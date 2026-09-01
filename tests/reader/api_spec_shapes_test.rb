# Checks every spec in libraries/_api_specs.rb against the SDK shapes actually
# shipped in the auditor image.
#
# Why this is a test and not one of the python linters: the answer lives in the
# gems, and only the image has them. tools/lint_api_specs.py can prove a spec
# matches the reader's SCHEMA; only this can prove it matches the API.
#
# What it is guarding against is the profile's recurring defect: a `fields:` path
# that names a member the response does not have is not an error and not a
# failure. dig_path answers nil, the generated control's nil filter removes the
# row, every row disappears, and the check renders Not Applicable — a rule that
# cannot fail, reported as one that does not apply. `check` and `json` never
# evaluate a control body, so nothing else in the proof set can see it.
#
# `list`, `collection` and `arg` typos are loud at exec (NoMethodError, or a
# recorded parent failure), but they are cheaper to catch here than in an
# account that happens to have the resource.
#
# Run:
#   docker run --rm -v "$PWD:/work" -w /work \
#     --entrypoint ruby risksentinel/sparc-auditor:v0.5.0 \
#     tests/reader/api_spec_shapes_test.rb
ROOT = File.expand_path("../..", __dir__)
load File.join(ROOT, "libraries", "_api_specs.rb")

PROBLEMS = []

def problem(msg)
  PROBLEMS << msg
end

# The shape one item of `collection` has. `_response` means the child response
# IS the item; a list member means its element shape; anything else is itself.
def item_shape(output, member, label, type)
  return output if member == "_response"

  ref = output.member(member.to_sym) if output.member?(member.to_sym)
  if ref.nil?
    problem("#{type}: #{label} '#{member}' is not a member of #{output.name}")
    return nil
  end
  shape = ref.shape
  shape.respond_to?(:member) && shape.is_a?(Seahorse::Model::Shapes::ListShape) ? shape.member.shape : shape
end

def structure?(shape)
  shape.is_a?(Seahorse::Model::Shapes::StructureShape)
end

# "resources_vpc_config.endpoint_public_access" walked through the shape tree.
def resolve_path(shape, path, type, label)
  node = shape
  path.to_s.split(".").each do |key|
    unless structure?(node)
      problem("#{type}: #{label} '#{path}' passes through #{node.name}, which has no members")
      return
    end
    unless node.member?(key.to_sym)
      problem("#{type}: #{label} '#{path}' — '#{key}' is not a member of #{node.name}. " \
              "dig_path answers nil, the control's nil filter removes the row, and the " \
              "check renders Not Applicable.")
      return
    end
    node = node.member(key.to_sym).shape
  end
end

def operation(client_class, name, type, label)
  client_class.api.operation(name.to_sym)
rescue Seahorse::Model::Api::NoSuchOperationError, ArgumentError, KeyError
  problem("#{type}: #{label} '#{name}' is not an operation on #{client_class}")
  nil
end

checked = 0
API_SPECS.each do |type, spec|
  begin
    require spec["gem"]
  rescue LoadError
    problem("#{type}: gem '#{spec['gem']}' is not in this runtime")
    next
  end

  begin
    client_class = Object.const_get(spec["client"])
  rescue NameError
    problem("#{type}: client '#{spec['client']}' does not resolve")
    next
  end
  checked += 1

  parent = spec["parent"]
  if parent
    op = operation(client_class, parent["list"], type, "parent.list")
    if op
      unless op.input.shape.required.to_a.empty?
        problem("#{type}: parent.list '#{parent['list']}' requires " \
                "#{op.input.shape.required.to_a.inspect}, but it is called with no arguments")
      end
      pshape = item_shape(op.output.shape, parent["collection"], "parent.collection", type)
      if pshape && parent["id"] != "_self"
        unless structure?(pshape) && pshape.member?(parent["id"].to_sym)
          problem("#{type}: parent.id '#{parent['id']}' is not a member of #{pshape.name}. " \
                  "Every parent id comes back blank and no child call is ever made.")
        end
      end
      if pshape && parent["id"] == "_self" && structure?(pshape)
        problem("#{type}: parent.id is `_self` but parent.collection holds #{pshape.name} " \
                "structures, not scalars")
      end
    end
  end

  op = operation(client_class, spec["list"], type, "list")
  next if op.nil?

  required = op.input.shape.required.to_a
  if parent
    unless op.input.shape.member?(spec["arg"].to_sym)
      problem("#{type}: arg '#{spec['arg']}' is not an input member of #{spec['list']}")
    end
    missing = required - [spec["arg"].to_s.to_sym]
    unless missing.empty?
      problem("#{type}: '#{spec['list']}' also requires #{missing.inspect}, which the reader " \
              "does not send (`args:` is not implemented)")
    end
  elsif !required.empty?
    problem("#{type}: one-step list '#{spec['list']}' requires #{required.inspect}")
  end

  ishape = item_shape(op.output.shape, spec["collection"], "collection", type)
  next if ishape.nil?

  unless structure?(ishape)
    problem("#{type}: collection '#{spec['collection']}' holds #{ishape.name}, which carries " \
            "no fields to read")
    next
  end

  if spec["id"] != "_parent" && !ishape.member?(spec["id"].to_sym)
    problem("#{type}: id '#{spec['id']}' is not a member of #{ishape.name}")
  end
  if spec["arn"] && !ishape.member?(spec["arn"].to_sym)
    problem("#{type}: arn '#{spec['arn']}' is not a member of #{ishape.name}")
  end
  (spec["fields"] || {}).each { |name, path| resolve_path(ishape, path, type, "field #{name}") }
end

puts "api spec shapes: #{checked} spec(s) checked against the SDK in this image"
if PROBLEMS.empty?
  puts "OK — every list call, collection, id, arn and field path resolves"
  exit 0
end
puts "#{PROBLEMS.length} problem(s):"
PROBLEMS.each { |p| puts "  #{p}" }
exit 1
