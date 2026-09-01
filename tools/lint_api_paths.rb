#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Resolve every dotted path in tools/api_specs.yml and every collection
# condition path in the resource maps against the AWS SDK's own response model.
#
#     docker run --rm -v "$PWD:/work" -w /work \
#       --entrypoint ruby risksentinel/sparc-auditor:v0.5.0 tools/lint_api_paths.rb
#
# Why this is a lint and not a runtime guard
# ------------------------------------------
# A misspelled path is the most expensive bug this profile can ship. It does not
# raise: `dig_path` and `dig_all` both answer "nothing reachable" for a member
# that does not exist, exactly as they do for a member the response omitted. For
# a collection roll-up the consequence is silent and total -- a condition that
# never resolves takes its `when_absent` verdict on every element, and the
# common `when_absent: false` case makes every element unmatchable, which makes
# `none_of` vacuously TRUE for every asset in the account. A security group open
# to the world then renders as a clean pass.
#
# The runtime alternative -- ask the population whether each path ever resolved
# -- was written first and then removed, because it cannot tell a typo from a
# tidy account. `ip_ranges.cidr_ip` reaches nothing in an account whose security
# group rules all reference peer groups rather than CIDRs, and that account is
# COMPLIANT: it would have been failed for being well configured. The
# distinction the guard actually wants is "does this member exist in the API's
# schema", which is static, exact, and known here.
#
# So this asks the SDK. `Aws::<Service>::Client.api` is the parsed service model
# that the client itself dispatches on, so the member names checked here are the
# same ones the parser will populate and `Aws::Structure#to_h` will emit as
# snake_case symbol keys -- the shape `dig_path`/`dig_all` walk.
#
# It also checks the two other things a spec can get wrong in the same silent
# way: a `list` operation that has REQUIRED input members (the reader calls it
# with none, so it would raise into unreadable_regions for every region), and a
# `collection` that is not a list of structures.
#
# Needs the aws-sdk gems, so it runs in the auditor image, not on a bare host.
# It has NO credential dependency: nothing here calls AWS, it only reads models.

require "yaml"
require "aws-sdk-core" # brings in Seahorse's shape classes; every spec gem depends on it

HERE  = File.expand_path(__dir__)
SPECS = File.join(HERE, "api_specs.yml")
MAPS  = %w[resource_map.yml resource_map_derived.yml].map { |f| File.join(HERE, f) }
COLLECTION_VERBS = %w[any_of all_of none_of].freeze

Shapes = Seahorse::Model::Shapes

def load_yaml(path)
  YAML.safe_load(File.read(path), aliases: true) || {}
end

# Walk a dotted path across the model the way dig_all walks the parsed response:
# a list is stepped THROUGH (its elements are what the next segment addresses),
# a structure is stepped INTO by member name.
#
# Returns the shape the path lands on, or raises with the segment that failed
# and the members that were actually available -- the message is the fix.
def resolve(shape, path)
  cursor = shape
  path.to_s.split(".").each do |segment|
    cursor = cursor.member.shape while cursor.is_a?(Shapes::ListShape)
    if cursor.is_a?(Shapes::MapShape)
      # A map's keys are data, not schema; nothing static can say whether a key
      # exists. Stop checking rather than pretend, and say so.
      return :map
    end
    unless cursor.is_a?(Shapes::StructureShape)
      raise "`#{segment}` continues past a #{cursor.class.name.split('::').last}, " \
            "which has no members to address"
    end
    unless cursor.member?(segment.to_sym)
      raise "`#{segment}` is not a member of #{cursor.name}. It has: " \
            "#{cursor.member_names.join(', ')}"
    end
    cursor = cursor.member(segment.to_sym).shape
  end
  cursor
end

def element_shape(shape)
  shape.is_a?(Shapes::ListShape) ? shape.member.shape : shape
end

specs   = load_yaml(SPECS)
errors  = []
notes   = []
checked = 0

# ---------------------------------------------------------------- api specs --
elements = {}
specs.each do |type, spec|
  begin
    require spec["gem"] unless Object.const_defined?(spec["client"])
  rescue LoadError
    errors << "#{type}: gem #{spec['gem']} is not installed in this image"
    next
  end

  client = Object.const_get(spec["client"])
  op_name = spec["list"].to_sym
  unless client.api.operation_names.include?(op_name)
    errors << "#{type}: #{spec['client']} has no operation ##{spec['list']}"
    next
  end
  operation = client.api.operation(op_name)

  # A two-step spec supplies the child call's parent id through `arg`, so that
  # one required member is satisfied. Without this the lint reported every
  # two-step spec as broken -- it was written before the parent shape existed,
  # and a lint that cries wolf on a working spec gets switched off.
  # .required yields Symbols and the spec holds Strings; subtracting the two
  # directly never matched, so a correct two-step spec still reported broken.
  required = operation.input.shape.required.to_a.map(&:to_s)
  satisfied = spec["parent"] ? [spec["arg"]].compact.map(&:to_s) : []
  outstanding = required - satisfied
  unless outstanding.empty?
    errors << "#{type}: #{spec['list']} REQUIRES #{outstanding.join(', ')}, but the reader " \
              "calls it with#{spec['parent'] ? ' only the parent id' : ' no arguments'} — " \
              "every region would raise into unreadable_regions"
  end

  # The parent leg must itself enumerate with no arguments, or there is nothing
  # to start the walk from.
  if spec["parent"]
    parent = spec["parent"]
    pop_name = parent["list"].to_sym
    if !client.api.operation_names.include?(pop_name)
      errors << "#{type}: parent list #{parent['list']} is not an operation on #{spec['client']}"
    else
      pop = client.api.operation(pop_name)
      preq = pop.input.shape.required.to_a.map(&:to_s)
      unless preq.empty?
        errors << "#{type}: parent list #{parent['list']} REQUIRES #{preq.join(', ')}; " \
                  "the parent leg is called with no arguments, so nothing would enumerate"
      end
      begin
        pcoll = resolve(pop.output.shape, parent["collection"])
        unless pcoll.is_a?(Shapes::ListShape)
          errors << "#{type}: parent `collection: #{parent['collection']}` is a " \
                    "#{pcoll.class.name.split('::').last}, not a list"
        end
      rescue RuntimeError => e
        errors << "#{type}: parent `collection: #{parent['collection']}` — #{e.message}"
      end
    end
  end

  begin
    collection = resolve(operation.output.shape, spec["collection"])
  rescue RuntimeError => e
    errors << "#{type}: `collection: #{spec['collection']}` — #{e.message}"
    next
  end
  if collection == :map
    errors << "#{type}: `collection: #{spec['collection']}` lands in a map, not a list of assets"
    next
  end
  unless collection.is_a?(Shapes::ListShape)
    errors << "#{type}: `collection: #{spec['collection']}` is a " \
              "#{collection.class.name.split('::').last}, not a list — the reader iterates it"
    next
  end
  element = collection.member.shape
  elements[type] = element

  paths = { "id" => spec["id"] }
  paths["arn"] = spec["arn"] if spec["arn"]
  (spec["fields"] || {}).each { |name, path| paths["fields.#{name}"] = path }
  paths.each do |label, path|
    checked += 1
    begin
      landed = resolve(element, path)
      notes << "#{type}: `#{label}: #{path}` crosses a map; the rest is unchecked" if landed == :map
    rescue RuntimeError => e
      errors << "#{type}: `#{label}: #{path}` — #{e.message}"
    end
  end
end

# ------------------------------------------------- collection condition paths --
MAPS.each do |file|
  (load_yaml(file)["checks"] || {}).each do |cid, by_type|
    (by_type || {}).each do |type, mapping|
      next unless COLLECTION_VERBS.include?(mapping["satisfies"])

      if mapping["reader"] != "api"
        errors << "#{cid}/#{type}: a `#{mapping['satisfies']}` roll-up on a " \
                  "`#{mapping['reader']}` reader cannot be path-checked here. Extend this " \
                  "lint to that reader before shipping it: an unchecked condition path is " \
                  "a control that cannot fail."
        next
      end

      element = elements[type]
      if element.nil?
        errors << "#{cid}/#{type}: no usable api spec, so its condition paths are unchecked"
        next
      end

      field_path = (specs[type]["fields"] || {})[mapping["field"]]
      if field_path.nil?
        errors << "#{cid}/#{type}: `field: #{mapping['field']}` is not declared in the " \
                  "api spec's fields, so the reader never populates it"
        next
      end

      begin
        collection_shape = resolve(element, field_path)
      rescue RuntimeError => e
        errors << "#{cid}/#{type}: `field: #{field_path}` — #{e.message}"
        next
      end
      if collection_shape == :map
        # Skipping here would leave the condition paths unchecked while the lint
        # still reported OK -- the exact silence this file exists to remove. A
        # map's keys are data, so nothing static can resolve past one; a roll-up
        # over a field behind a map has to wait for a guard that can.
        errors << "#{cid}/#{type}: `field: #{field_path}` crosses a map, so its condition " \
                  "paths CANNOT be resolved statically. A roll-up whose paths are unchecked " \
                  "is a control that may be unable to fail — do not ship it on this field."
        next
      end

      item = element_shape(collection_shape)
      if item.is_a?(Shapes::MapShape)
        errors << "#{cid}/#{type}: `field: #{field_path}` is a map, whose keys are data — no " \
                  "condition path over it can be resolved statically, and an unchecked " \
                  "roll-up path is a control that may be unable to fail."
        next
      end

      Array(mapping["conditions"]).each do |condition|
        Array(condition["path"]).each do |path|
          checked += 1
          begin
            landed = resolve(item, path)
            # A NOTE here would be the same silence one level down: the lint would
            # print OK having left this path unresolved, which is precisely the
            # state that makes `none_of` vacuously true for every asset. A scalar
            # `fields:` path crossing a map is only a nil the template filters;
            # a roll-up CONDITION path crossing one is a verdict nothing checked.
            if landed == :map
              errors << "#{cid}/#{type}: condition path `#{path}` crosses a map, so the rest " \
                        "of it CANNOT be resolved statically. Do not ship a roll-up on it."
            end
          rescue RuntimeError => e
            errors << "#{cid}/#{type}: condition path `#{path}` — #{e.message}"
          end
        end
      end
    end
  end
end

notes.each { |n| puts "note: #{n}" }
puts "api specs: #{specs.length}   paths resolved against the SDK model: #{checked}"

unless errors.empty?
  warn "::error::a declared path does not exist in the AWS SDK response model. " \
       "This does not raise at exec — the reader answers nil and a collection roll-up " \
       "then passes vacuously, so the control reports compliant having assessed nothing."
  errors.each { |e| warn "  #{e}" }
  exit 1
end
puts "OK — every declared path names a member the AWS SDK actually returns."
