#!/usr/bin/env ruby
# libraries/_checkov_enumeration.rb against REAL stock resources.
#
# Why real resources
# ------------------
# Every decision this library makes is a decision about how inspec-aws and
# FilterTable behave: what an empty table answers, which columns exist before a
# response has been seen, what a resource says when it found nothing. A fake
# collection encodes what the author believed about those, which is exactly
# what was wrong (#18): the helper asked an empty table for its `entries`,
# FilterTable raises there, and the rescue read that as "has rows, lacks the
# column". Four EKS controls failed on an account with no clusters.
#
# So the collections here are the vendored resources, built on the SDK's stub
# transport (tools/stock_stub_support.rb): an empty stub is an account with
# none of the resource, a full stub is one of everything.
#
# Run in the auditor image, after `cinc-auditor vendor .`:
#
#   docker run --rm -v "$PWD:/work" -w /work --entrypoint ruby <image> \
#     tests/enumeration_stub_test.rb
require_relative '../tools/stock_stub_support'

abort 'no vendored resource pack — run `cinc-auditor vendor .` first' unless StockStub.vendored?

require_relative '../libraries/_checkov_enumeration'

FAILURES = []
CHECKS = [0]
def assert(name, cond, detail = nil)
  CHECKS[0] += 1
  FAILURES << "#{name}#{detail ? " — #{detail}" : ''}" unless cond
end

SUBJECT = Class.new { include CheckovEnumeration }.new
EXCLUDE = { statuses: %w[CREATING DELETING] }.freeze

# --- an account with none of the resource is not a broken mapping (#18) ------
ids, problems = SUBJECT.checkov_enumerate(StockStub.resource('aws_eks_clusters'), :names, exclude: EXCLUDE)
assert('empty table, dynamic ids column: no ids', ids == [], ids.inspect)
assert('empty table, dynamic ids and exclude columns: no problems', problems == [], problems.inspect)

ids, problems = SUBJECT.checkov_enumerate(StockStub.resource('aws_kms_keys'), :key_ids)
assert('empty table, registered column: no ids, no problems', ids == [] && problems == [], [ids, problems].inspect)

# --- rows present: the same declarations enumerate ---------------------------
full = StockStub.resource('aws_eks_clusters', full: true)
ids, problems = SUBJECT.checkov_enumerate(full, :names, exclude: { statuses: %w[DELETING] })
assert('rows present: ids are read', ids.size == 1, ids.inspect)
assert('rows present: a real exclude column is not a problem', problems == [], problems.inspect)

# --- and a wrong declaration is still loud, which is what the guard is for ---
ids, problems = SUBJECT.checkov_enumerate(StockStub.resource('aws_eks_clusters', full: true), :cluster_identifiers)
assert('rows present, ids column that does not exist: nothing enumerated', ids == [], ids.inspect)
assert('rows present, ids column that does not exist: reported',
       problems.any? { |p| p.include?('is not a column this resource exposes') }, problems.inspect)

_, problems = SUBJECT.checkov_enumerate(StockStub.resource('aws_eks_clusters', full: true), :names,
                                        exclude: { no_such_column: %w[X] })
assert('rows present, exclude column that does not exist: reported',
       problems.any? { |p| p.include?("cannot narrow the population on 'no_such_column'") }, problems.inspect)

# --- reading an asset back: a value, an absent member, a resource that found nothing
key = StockStub.resource('aws_kms_key', { key_id: 'stub' }, full: true)
value, fault = SUBJECT.checkov_stock_value(key, 'enabled')
assert('a property the resource has: its value, no fault', value == false && fault.nil?, [value, fault].inspect)

value, fault = SUBJECT.checkov_stock_value(key, 'no_such_property')
assert('a member that is not there: nil, never a NullResponse', value.nil? && fault.nil?,
       [value.class, fault].inspect)

# Under the empty stub DescribeTrails returns no trail: the shape of a multi-region
# trail asked for by name outside its home region (#16).
trail = StockStub.resource('aws_cloudtrail_trail', { trail_name: 'stub' })
value, fault = SUBJECT.checkov_stock_value(trail, 'log_file_validation_enabled')
assert('a resource that found nothing: a fault, not a value',
       value.nil? && fault.to_s.include?('found nothing under this identifier'), [value, fault].inspect)

trail = StockStub.resource('aws_cloudtrail_trail', { trail_name: 'stub' }, full: true)
value, fault = SUBJECT.checkov_stock_value(trail, 'log_file_validation_enabled')
assert('the same resource when the trail is there: a value', value == false && fault.nil?, [value, fault].inspect)

if FAILURES.empty?
  puts "OK — #{CHECKS[0]} assertion(s): an empty account enumerates to nothing without a problem, " \
       'a wrong column is still reported, and an asset that cannot be read back is a fault, not a finding.'
else
  FAILURES.each { |f| puts "FAIL #{f}" }
  exit 1
end
