#!/usr/bin/env ruby
# Verify what tools/lint_resource_map.py calls "unverifiable statically": the
# PROPERTY a stock mapping asserts on, and the columns of a plural resource that
# populates its table from the API response.
#
# Why this exists (issues #16, #17)
# ---------------------------------
# A stock inspec-aws resource answers an unknown property with NullResponse
# instead of raising. A mapping that names a property the resource does not
# have therefore renders a control that runs cleanly and FAILS every asset, and
# the failure reads exactly like a real finding. A live run reported all 14 KMS
# keys in an account as disabled this way; every one was enabled. `check` and
# `json` cannot see it, because neither evaluates a control body, and an
# account with none of that resource type never reaches the assert at all.
#
# The properties come from `create_resource_methods` over an API response, so
# they exist only when a response does. tools/stock_stub_support.rb supplies
# one without an account: the SDK's stub transport, with one element in every
# list and map, so every member of every response shape is present. A property
# that is still NullResponse there is one the resource does not expose.
#
# What a pass means: the name resolves on the resource. It does not mean the
# property carries the meaning the check wants; that is still a review question.
#
# Not every resource can be probed. Some validate the format of the id they are
# given, some parse a stubbed string as JSON, some select their subject out of a
# list by a name the stub does not carry. Those are listed as "could not be
# probed", so what was checked and what was not stays visible, and a mapping
# listed there in UNPROBEABLE_ALLOWED is the only kind that may stay unchecked:
# a mapping that newly becomes unprobeable fails the lint.
#
# Run in the auditor image, after `cinc-auditor vendor .`:
#
#   docker run --rm -v "$PWD:/work" -w /work --entrypoint ruby <image> \
#     tools/lint_stock_properties.rb
require 'timeout'
require 'yaml'
require_relative 'stock_stub_support'

# A resource that loops under stubs is reported as unprobeable, not waited on.
PROBE_SECONDS = 20
ALLOWED_PATH = File.join(__dir__, 'stock_unprobeable.yml')

def mappings
  merged = {}
  %w[resource_map.yml resource_map_derived.yml].each do |name|
    path = File.join(__dir__, name)
    next unless File.file?(path)

    (YAML.safe_load(File.read(path), aliases: true) || {}).fetch('checks', {}).each do |cid, spec|
      merged[cid] ||= spec # the authored file wins, as in render_controls.load
    end
  end
  merged
end

# A Hash member by symbol or string key; a NullResponse when it has neither.
def hash_member(hash, seg)
  return hash[seg.to_sym] if hash.key?(seg.to_sym)

  hash.key?(seg) ? hash[seg] : NullResponse.new
end

# One segment of a path: the value there, a NullResponse when the name is not
# there, or nil when nothing can be said.
def step_into(obj, seg)
  return hash_member(obj, seg) if obj.is_a?(Hash)

  obj.public_send(seg)
rescue NoMethodError => e
  # Raised ON this object FOR this name: the method is not public here, which
  # is the same answer as a NullResponse. Anything else is the method existing
  # and tripping over stub data, which says nothing about whether it is there.
  e.name.to_s == seg && e.receiver.equal?(obj) ? NullResponse.new : nil
rescue StandardError
  nil
end

# The value at a dotted path, or the first segment that is not there.
def resolve(resource, path)
  path.split('.').inject(resource) do |obj, seg|
    value = step_into(obj, seg)
    return [:missing, seg] if value.is_a?(NullResponse)
    # A scalar or an exhausted stub: nothing deeper can be confirmed or denied.
    return [:ok, nil] if value.nil?

    value.is_a?(Array) ? value.first : value
  end
  [:ok, nil]
end

def probe_plural(where, enum, problems, unprobeable)
  plural = Timeout.timeout(PROBE_SECONDS) { StockStub.resource(enum['resource']) }
  if plural.nil?
    problems << "#{where}: no resource named '#{enum['resource']}' in the pack"
    return
  end
  unless plural.respond_to?(enum['ids'].to_s)
    problems << "#{where}: #{enum['resource']} has no column '#{enum['ids']}' (ids)"
  end
  # `exclude:` is applied through the table's own schema, exactly as
  # libraries/_checkov_enumeration.rb applies it: the column must be a field on
  # the row. respond_to? is not enough, because a resource can answer to a name
  # that is not a column it can filter on.
  schema = plural.respond_to?(:where) ? plural.where({}).custom_properties_schema : {}
  (enum['exclude'] || {}).each_key do |col|
    property = schema[col.to_sym]
    if property.nil?
      problems << "#{where}: #{enum['resource']} has no column '#{col}' to exclude on. " \
                  "It has: #{schema.keys.sort.first(10).join(', ')}"
    elsif property.block
      problems << "#{where}: #{enum['resource']}.#{col} is a computed column and cannot scope an enumeration"
    end
  end
rescue StandardError, ScriptError => e
  unprobeable << ["#{where} enumerate", "#{enum['resource']} could not be built under stubs " \
                                         "(#{e.class}: #{e.message[0, 80]})"]
end

def probe_singular(where, assertion, problems, unprobeable)
  arg = assertion['arg']
  args = arg.nil? || arg == 'positional' ? nil : { arg.to_sym => 'stub' }
  singular = Timeout.timeout(PROBE_SECONDS) do
    args ? StockStub.resource(assertion['resource'], args) : StockStub.resource_class(assertion['resource'])&.new('stub')
  end
  if singular.nil?
    problems << "#{where}: no resource named '#{assertion['resource']}' in the pack"
    return false
  end
  state, seg = resolve(singular, assertion['property'].to_s)
  return true if state == :ok

  # A resource whose subject was not found has no response to derive properties
  # from, so a missing property there is not evidence. Several stock resources
  # decide `exists?` from the VALUE of a stubbed field (an ARN that starts with
  # "arn:"), so this is only consulted once the property has failed to resolve.
  exists = begin
    !singular.respond_to?(:exists?) || singular.exists?
  rescue StandardError
    false
  end
  # ...and only where the resource derives methods from the response at all. One
  # that does not has exactly the properties in its source, found or not.
  if !exists && StockStub.declared_properties(assertion['resource'])[:derived]
    unprobeable << ["#{where} assert", "#{assertion['resource']} does not come up under stubs (exists? is false)"]
    return false
  end
  problems << "#{where}: #{assertion['resource']} exposes no '#{seg}' " \
              "(asserted property: #{assertion['property']})"
  true
rescue StandardError, ScriptError => e
  # The resource would not build, so nothing can be asked of it. Its source can
  # still answer for a property it defines by name.
  first = assertion['property'].to_s.split('.').first
  return true if StockStub.declared_properties(assertion['resource'])[:names].include?(first)

  unprobeable << ["#{where} assert", "#{assertion['resource']} could not be built under stubs " \
                                     "(#{e.class}: #{e.message[0, 80]})"]
  false
end

StockStub.full = true
problems = []
unprobeable = []
checked = 0

mappings.sort.each do |cid, per_type|
  per_type.each do |tf_type, spec|
    next unless spec['reader'] == 'stock'

    where = "#{cid}/#{tf_type}"
    probe_plural(where, spec['enumerate'] || {}, problems, unprobeable)
    checked += 1 if probe_singular(where, spec['assert'] || {}, problems, unprobeable)
  end
end

allowed = File.file?(ALLOWED_PATH) ? (YAML.safe_load(File.read(ALLOWED_PATH)) || {}).fetch('unprobeable', {}) : {}
unprobeable.each do |key, why|
  next if allowed.key?(key)

  problems << "#{key}: #{why}. It is not listed in tools/stock_unprobeable.yml, so this " \
              'mapping would go unchecked without anyone having decided that it may'
end
stale = allowed.keys - unprobeable.map(&:first)
stale.each do |key|
  problems << "#{key}: listed in tools/stock_unprobeable.yml but it probes cleanly now. Remove the entry"
end

puts "stock properties resolved under stubs: #{checked}"
puts "could not be probed (listed, accepted) : #{unprobeable.size - (unprobeable.map(&:first) - allowed.keys).size}"

if problems.any?
  puts '::error::a stock mapping names a property or column the resource does not expose, ' \
       'or could not be checked. The control would fail every asset, or fail its ' \
       'enumeration, whatever the asset is.'
  problems.each { |p| puts "  #{p}" }
  exit 1
end

puts 'OK — every stock property and every enumeration column resolves on the resource it is ' \
     'read from, and every mapping that cannot be probed is one that was accepted by name.'
