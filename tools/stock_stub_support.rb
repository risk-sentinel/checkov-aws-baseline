# Stock inspec-aws resources, built against the AWS SDK's own stub transport.
#
# Shared by tools/lint_stock_properties.rb and tests/enumeration_stub_test.rb.
# Both need the same thing: a real stock resource, the real FilterTable and the
# real SDK response shapes, with no account and no network.
#
# `stub_responses: true` gives that, and the stock resources accept it through
# `client_args:`. The SDK's default stub leaves every list and map EMPTY, which
# is the right model of an account that has none of a resource and the wrong one
# for asking what a resource exposes: a property read from `things.first` would
# never exist. FullStub puts one element in each list and map, so every member
# of every response shape is present. It is switched per call, because the two
# cases are both needed:
#
#   StockStub.resource('aws_eks_clusters')              # an account with none
#   StockStub.resource('aws_eks_clusters', full: true)  # one of everything
#
# Runs in the auditor image only (it needs inspec and the aws-sdk gems), after
# `cinc-auditor vendor .`.
Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8

# The vendored pack has to be on the load path before it can be required, and a
# run without it has nothing to check: it would pass by finding no resources. So
# both are settled here, before anything else is loaded.
VENDORED_LIBRARIES = Dir[File.join(File.expand_path('..', __dir__), 'vendor', '*', 'libraries')].first
unless VENDORED_LIBRARIES
  abort '::error::no vendored resource pack found. Run `cinc-auditor vendor .` first. ' \
        'Without it this would pass by having nothing to check.'
end
$LOAD_PATH.unshift(VENDORED_LIBRARIES)

require 'inspec'
require 'aws_backend'

module StockStub
  VENDOR = VENDORED_LIBRARIES
  CLIENT_ARGS = { stub_responses: true, region: 'us-east-1' }.freeze

  class << self
    attr_accessor :full

    # The class behind a resource name, or nil when the pack has no such file.
    #
    # Which file to load is known only by name, at run time, so the class is
    # registered for autoload and loaded on first use. A resource another one
    # already pulled in is defined and is left alone.
    def resource_class(name)
      path = File.join(VENDOR, "#{name}.rb")
      return nil unless File.file?(path)

      const = File.read(path)[/^class\s+(\w+)\s*</, 1].to_sym
      Object.autoload(const, path) unless Object.const_defined?(const)
      Object.const_get(const)
    end

    # A stock resource built under stubs. `args` are the resource's own
    # arguments; `full:` chooses one-of-everything over the SDK's empty default.
    # The setting is restored afterwards, so a caller that turned FullStub on
    # for a whole run keeps it for the lazy reads a resource makes later.
    def resource(name, args = {}, full: self.full)
      before = self.full
      klass = resource_class(name)
      return nil unless klass

      self.full = full
      klass.new(args.transform_values { |v| v == 'stub' ? nil : v }
                    .each_with_object({}) { |(k, v), h| h[k] = v || stub_id(k) }
                    .merge(client_args: CLIENT_ARGS))
    ensure
      self.full = before
    end

    # A stand-in identifier for an argument. Several stock resources validate
    # the FORMAT of the id they are given before making a call, so a bare
    # placeholder is rejected and the resource cannot be probed at all.
    STUB_IDS = {
      subnet_id: 'subnet-0123456789abcdef0',
      vpc_id: 'vpc-0123456789abcdef0',
      volume_id: 'vol-0123456789abcdef0',
      file_system_id: 'fs-0123456789abcdef0',
      arn: 'arn:aws:sns:us-east-1:123456789012:stub',
      queue_url: 'https://sqs.us-east-1.amazonaws.com/123456789012/stub',
    }.freeze

    def stub_id(arg)
      STUB_IDS.fetch(arg.to_sym, 'stub')
    end

    # What a resource's SOURCE says about its properties: the methods and
    # readers it defines by name, and whether it also derives methods from an
    # API response. A resource with no derived methods has exactly the
    # properties written in its file, whatever a stub does or does not return.
    def declared_properties(name)
      source = File.read(File.join(VENDOR, "#{name}.rb"))
      readers = source.scan(/attr_reader\s+((?::\w+[?!]?\s*,?\s*)+)/).flatten.join(' ').scan(/:(\w+[?!]?)/).flatten
      { names: (readers + source.scan(/^\s+def\s+(\w+[?!]?)/).flatten).uniq,
        derived: source.include?('create_resource_methods') }
    end
  end

  # One element in every list and map. Recursion is bounded by the generator's
  # own `visited` list.
  module FullStub
    # A resource that pages by hand loops until the token is nil. The SDK strips
    # the tokens of the paginators it knows; a stubbed string in any other token
    # member is a loop that never ends.
    PAGE_TOKEN = /\A(next_token|next_marker|marker|next_page_token|next_continuation_token|position|pagination_token)\z/

    private

    # A member a stock resource hands to JSON.parse: a stubbed shape name there
    # stops the resource being built, so it gets an empty document instead.
    JSON_MEMBER = /(\A|_)(policy|policy_document|security_configuration|document)\z/
    # Parses, and carries the one top-level key a stock resource indexes into
    # without checking (aws_emr_security_configuration).
    JSON_DOCUMENT = '{"EncryptionConfiguration":{}}'

    # A queue URL becomes the request ENDPOINT in the SQS client, so a stubbed
    # shape name there is rejected before the call is made.
    QUEUE_URL = 'https://sqs.us-east-1.amazonaws.com/123456789012/stub'

    def stub_structure(ref, visited)
      struct = super
      # The CLASS's members: an API shape can carry a field called `members`,
      # which shadows Struct#members on the instance and returns that field.
      struct.class.members.each do |m|
        name = m.to_s
        # A REQUIRED token (CloudFront's `marker`) cannot be nil: the stub would
        # fail the SDK's own validation. Empty is valid there and still ends a
        # hand-written paging loop that reads `next_marker`.
        if name.match?(PAGE_TOKEN)
          struct[m] = ref.shape.required.include?(m) ? '' : nil
        end
        next unless StockStub.full

        struct[m] = JSON_DOCUMENT if struct[m].is_a?(String) && name.match?(JSON_MEMBER)
        struct[m] = QUEUE_URL if name == 'queue_url'
        struct[m] = [QUEUE_URL] if name == 'queue_urls'
      end
      struct
    end

    def stub_ref(ref, visited = [])
      return super unless StockStub.full
      return nil if visited.include?(ref.shape)

      case ref.shape
      when Seahorse::Model::Shapes::ListShape
        [stub_ref(ref.shape.member, visited + [ref.shape])].compact
      when Seahorse::Model::Shapes::MapShape
        { 'stub' => stub_ref(ref.shape.value, visited + [ref.shape]) }
      else
        super
      end
    end
  end
end

Aws::Stubbing::EmptyStub.prepend(StockStub::FullStub)
