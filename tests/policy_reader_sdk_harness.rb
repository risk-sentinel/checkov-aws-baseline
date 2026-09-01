#!/usr/bin/env ruby
# The same reader as tests/policy_reader_harness.rb, driven through the REAL
# AWS SDK instead of hand-built fake clients.
#
# Why both harnesses exist
# ------------------------
# The sibling harness fakes the SDK, so it proves the reader's own logic and
# nothing about the SDK's behaviour. Every assumption the reader makes about the
# SDK is therefore unproven there:
#
#   * that a list response is PAGEABLE and `respond_to?(:each)` walks its pages
#     rather than iterating a Struct's values
#   * that `item.to_h` yields SYMBOL keys, which is what dig_path indexes with
#   * that `response.to_h` deep-converts, so `policy_version.document` resolves
#   * that RepositoryPolicyNotFoundException demodulizes to exactly the string
#     policy_specs.yml declares in `absent_when`
#   * that it, and AccessDeniedException, are both Aws::Errors::ServiceError, so
#     the rescues catch them
#   * that the argument names in policy_specs.yml are the ones the client
#     accepts -- a real client VALIDATES its params and raises on a wrong name,
#     where a fake happily accepts anything
#
# A wrong answer to any of those produces a reader that finds nothing, and a
# reader that finds nothing produces a control that cannot fail.
#
# `stub_responses: true` is the SDK's own test transport: the real client, the
# real API model, the real parameter validation, the real pagination and the
# real error classes, with the HTTP layer replaced. No credentials, no network.
#
# It is forced on with a prepended module rather than passed as an option,
# because the reader constructs its own clients per region (`client_for`) and
# there is no seam to pass options through -- which is itself the thing being
# tested.
#
# Run:  docker run --rm -v "$PWD:/work" -w /work \
#         --entrypoint sh risksentinel/sparc-auditor@sha256:b47711fe1e6177e937f17e24d2bd26cc0fea57852ec7546dac2b5146ed328ff8 \
#         -c 'ruby tests/policy_reader_sdk_harness.rb'
#
# It needs aws-sdk-iam and aws-sdk-ecr, which ship in the auditor image and are
# not installed on a laptop -- so unlike the other two test files this one runs
# in the image only. That is the cost of testing against the real SDK.

# The auditor image stopped shipping a UTF-8 locale at the v1.0.0 UBI rebase:
# v0.5.0 set LANG=en_US.UTF-8, v1.2.0 sets nothing, so Ruby's default external
# encoding is US-ASCII. Every source file in this repo is UTF-8 (em dashes
# throughout), so File.read then yields invalid byte sequences -- which surfaces
# as "invalid byte sequence in US-ASCII" from a regex, or, worse, as a SyntaxError
# from instance_eval on a library that is perfectly valid Ruby. Pinned here so the
# suite does not depend on the image's locale.
Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8

require "json"
require "aws-sdk-iam"
require "aws-sdk-ecr"

FAILURES = []
def assert(name, cond, detail = nil)
  FAILURES << "#{name}#{detail ? " — #{detail}" : ''}" unless cond
end

CRED = Aws::Credentials.new("stub-access-key-id", "stub-secret-access-key")
ACCOUNT = "111122223333".freeze

def encoded(doc)
  # IAM hands policy documents back percent-encoded (RFC 3986).
  JSON.generate(doc).gsub(/[^A-Za-z0-9\-_.~]/) { |c| format("%%%02X", c.ord) }
end

WILDCARD_TRUST = encoded(
  "Version" => "2012-10-17",
  "Statement" => [{ "Effect" => "Allow", "Principal" => { "AWS" => "*" },
                    "Action" => "sts:AssumeRole" }]
)
SERVICE_TRUST = encoded(
  "Version" => "2012-10-17",
  # A single object rather than an array, which is legal and which a parser that
  # assumes an array drops silently.
  "Statement" => { "Effect" => "Allow",
                   "Principal" => { "Service" => "ecs-tasks.amazonaws.com" },
                   "Action" => "sts:AssumeRole" }
)
ADMIN_POLICY = encoded(
  "Version" => "2012-10-17",
  "Statement" => [{ "Sid" => "Admin", "Effect" => "Allow", "Action" => "*", "Resource" => "*" }]
)

# ------------------------------------------------------- real clients, stubbed --

CALLS = []

# Prepended to the client's SINGLETON class, not the class.
#
# `Aws::IAM::Client.new(region: 'x')` is a class method that allocates and then
# calls `initialize(plugins, options)` -- TWO positional arguments. Overriding
# the instance `initialize(opts = {})` therefore raises
# "wrong number of arguments (given 2, expected 0..1)", which this harness did
# on its first run: the same positional-dispatch trap that
# `resource(id, aws_region: r)` hits elsewhere in this profile. Recorded here
# because the reader's `klass.new(region: region)` is the correct form and it
# would be easy to "simplify" it into the broken one.
module ForceStub
  def new(options = {})
    client = super(options.merge(stub_responses: true, credentials: CRED,
                                 region: options[:region] || "us-east-1"))
    client.canned_stubs
    client
  end
end

module StubIam
  def canned_stubs
    role = lambda do |name, doc|
      { path: "/", role_name: name, role_id: "AROA#{name}",
        arn: "arn:aws:iam::#{ACCOUNT}:role/#{name}", create_date: Time.now,
        assume_role_policy_document: doc }
    end
    # TWO pages: a reader that reads only the first would miss the finding, and
    # would report a clean estate while doing it.
    stub_responses(:list_roles, [
                     { roles: [role.call("public-trust", WILDCARD_TRUST)],
                       is_truncated: true, marker: "m1" },
                     { roles: [role.call("service-trust", SERVICE_TRUST),
                               role.call("broken-trust", "not a policy at all")],
                       is_truncated: false },
                   ])
    stub_responses(:list_policies, {
                     policies: [{ policy_name: "admin", policy_id: "ANPAADMIN",
                                  arn: "arn:aws:iam::#{ACCOUNT}:policy/admin", path: "/",
                                  default_version_id: "v3" }],
                     is_truncated: false,
                   })
    stub_responses(:get_policy_version, {
                     policy_version: { document: ADMIN_POLICY, version_id: "v3",
                                       is_default_version: true },
                   })
  end

  # The real client validates parameter NAMES, so recording the calls proves
  # policy_specs.yml spells them the way the API model does.
  def list_policies(params = {})
    CALLS << [:list_policies, params]
    super
  end

  def get_policy_version(params = {})
    CALLS << [:get_policy_version, params]
    super
  end
end

module StubEcr
  def canned_stubs
    stub_responses(:describe_repositories, lambda { |ctx|
      raise Aws::ECR::Errors::ServerException.new(ctx, "region opted out") if
        ctx.config.region == "eu-broken"

      { repositories: %w[public-repo no-policy denied].map do |n|
          { repository_name: n, registry_id: ACCOUNT,
            repository_arn: "arn:aws:ecr:#{ctx.config.region}:#{ACCOUNT}:repository/#{n}" }
        end }
    })
    stub_responses(:get_repository_policy, lambda { |ctx|
      case ctx.params[:repository_name]
      when "public-repo"
        { registry_id: ACCOUNT, repository_name: "public-repo",
          policy_text: JSON.generate(
            "Version" => "2012-10-17",
            "Statement" => [{ "Sid" => "Public", "Effect" => "Allow", "Principal" => "*",
                              "Action" => "ecr:BatchGetImage" }]
          ) }
      when "no-policy"
        # The declared absent_when: a real answer, and a passing one.
        Aws::ECR::Errors::RepositoryPolicyNotFoundException.new(ctx, "no policy")
      else
        # NOT declared: must be undecidable, never "no policy".
        Aws::ECR::Errors::AccessDeniedException.new(ctx, "not authorized")
      end
    })
  end

  def get_repository_policy(params = {})
    CALLS << [:get_repository_policy, params]
    super
  end
end

Aws::IAM::Client.prepend(StubIam)
Aws::ECR::Client.prepend(StubEcr)
Aws::IAM::Client.singleton_class.prepend(ForceStub)
Aws::ECR::Client.singleton_class.prepend(ForceStub)

# -------------------------------------------------- the vendored base, verbatim --

module Inspec
  class Rule; end
end

class FakeSts
  def get_caller_identity = Struct.new(:account).new(ACCOUNT)
end

STUB_REGIONS = ["us-east-1", "eu-broken"].freeze

class FakeRegions
  def initialize(regions) = @regions = regions
  def regions = @regions.map { |r| Struct.new(:region_name).new(r) }
end

class FakeEc2
  def initialize(regions) = @regions = regions
  def describe_regions = FakeRegions.new(@regions)
  def config = Struct.new(:region).new(@regions.first)
end

class FakeConnection
  def initialize(regions) = @regions = regions
  def sts_client = FakeSts.new
  def compute_client = FakeEc2.new(@regions)
  def aws_client(klass) = klass.new
end

# validate_parameters is transcribed from the vendored AwsResourceBase
# (aws_backend.rb:390-412), not paraphrased -- see the note in the sibling
# harness for the bug a paraphrase hid.
BACKEND = <<~'RUBY'
  class AwsResourceBase
    def initialize(opts = {})
      @opts = opts
      @aws = FakeConnection.new(STUB_REGIONS)
    end

    def self.name(value = nil) = value
    def self.desc(value = nil) = value
    def self.example(value = nil) = value

    def validate_parameters(allow: [], required: nil, require_any_of: nil)
      if required
        raise ArgumentError, "`#{required}` must be provided" unless @opts.is_a?(Hash) && required.all? { |req| @opts.key?(req) && !@opts[req].nil? && @opts[req] != "" }

        allow += required
      end
      allow += %i[client_args stub_data aws_region aws_endpoint aws_retry_limit aws_retry_backoff resource_data]
      raise ArgumentError, "Scalar arguments not supported" unless defined?(@opts.keys)
      raise ArgumentError, "Unexpected arguments found" unless @opts.keys.all? { |a| allow.include?(a) }
      raise ArgumentError, "Provided parameter should not be empty" unless @opts.values.all? do |a|
        return true if a.instance_of?(Integer)
        return true if [TrueClass, FalseClass].include?(a.class)

        !a.empty?
      end

      true
    end

    def catch_aws_errors
      yield
    rescue StandardError
      nil
    end
  end
RUBY

require "tmpdir"
dir = Dir.mktmpdir
File.write(File.join(dir, "aws_backend.rb"), BACKEND)
$LOAD_PATH.unshift(dir)

# Loaded exactly as InSpec loads library files: one shared eval context, so the
# cross-file constant resolution (PolicyDocument, POLICY_SPECS) is exercised.
ROOT = ARGV[0] || File.expand_path("..", __dir__)
class LibraryEvalContext; end
CTX = LibraryEvalContext.new
%w[_policy_specs.rb _policy_document.rb aws_policy_documents.rb].each do |f|
  CTX.instance_eval(File.read(File.join(ROOT, "libraries", f)), "libraries/#{f}", 1)
end
Reader = CTX.instance_eval("AwsPolicyDocuments")

# ---------------------------------------------------------------- IAM roles ----

roles = Reader.new(type: "aws_iam_role", predicate: "no_wildcard_principal", regions: [])
by_id = roles.assets.to_h { |r| [r[:id], r] }

assert "a PAGEABLE list is walked to the end, not truncated at page one",
       by_id.keys.sort == %w[public-trust service-trust],
       "got #{by_id.keys.inspect} (broken-trust is correctly undecidable)"
assert "a percent-encoded document from the real API is decoded and judged",
       by_id["public-trust"] && by_id["public-trust"][:offenders].length == 1
assert "the offender names the statement and the principal",
       by_id["public-trust"][:offenders].first
                                       .start_with?("Statement[0]: Effect Allow to Principal.AWS *")
assert "a single-object Statement is judged, not dropped",
       by_id["service-trust"] && by_id["service-trust"][:offenders] == [] &&
       by_id["service-trust"][:policy_present] == true
assert "an unparsable document is UNDECIDABLE, never clean",
       roles.undecidable.length == 1 && roles.undecidable.first.include?("broken-trust")
assert "a global source enumerates once and says so", by_id["public-trust"][:region] == "global"

# ------------------------------------------------------- IAM policy, 2 calls ---

CALLS.clear
policies = Reader.new(type: "aws_iam_policy", predicate: "no_admin_star_star", regions: [])
listed = CALLS.assoc(:list_policies)
assert "list_args reach the REAL client, which validates the name",
       listed && listed[1] == { scope: "Local" }, listed.inspect
fetched = CALLS.assoc(:get_policy_version)
assert "fetch args resolve `from: arn` and `from_item:` into validated params",
       fetched && fetched[1] == { policy_arn: "arn:aws:iam::#{ACCOUNT}:policy/admin",
                                  version_id: "v3" }, fetched.inspect
assert "a nested response path survives the real to_h and is judged",
       policies.assets.length == 1 && policies.assets.first[:offenders].length == 1
assert "the admin finding names both stars",
       policies.assets.first[:offenders].first.include?("Action * on Resource *")

# ---------------------------------------------------------- ECR, regional ------

CALLS.clear
ecr = Reader.new(type: "aws_ecr_repository_policy", predicate: "no_wildcard_principal",
                 regions: STUB_REGIONS)
ecr_by_id = ecr.assets.to_h { |r| [r[:id], r] }

assert "a region whose LIST call raised is unreadable, not empty",
       ecr.unreadable_regions.length == 1 &&
       ecr.unreadable_regions.first[:region] == "eu-broken",
       ecr.unreadable_regions.inspect
assert "the readable region still produced rows", ecr.assets.length == 2
assert "a public repository policy is a finding",
       ecr_by_id["public-repo"] && ecr_by_id["public-repo"][:offenders].length == 1
assert "the REAL RepositoryPolicyNotFoundException matches absent_when and PASSES",
       ecr_by_id["no-policy"] && ecr_by_id["no-policy"][:offenders] == [] &&
       ecr_by_id["no-policy"][:policy_present] == false
assert "a REAL AccessDeniedException is undecidable, never 'no policy'",
       ecr.undecidable.length == 1 && ecr.undecidable.first.include?("denied") &&
       ecr.undecidable.first.include?("AccessDeniedException"), ecr.undecidable.inspect
assert "the denied repository is excluded from assets", ecr_by_id["denied"].nil?
assert "fetch args resolve `from: id` into a validated param",
       CALLS.select { |c| c.first == :get_repository_policy }
            .map { |c| c[1] }.include?(repository_name: "public-repo")

# ------------------------------------------------------------------ report -----

if FAILURES.empty?
  puts "OK — the reader drives the real AWS SDK correctly: pagination, symbol-keyed "\
       "to_h, validated parameter names, and the real error classes."
  exit 0
end
puts "::error::#{FAILURES.length} SDK-backed assertion(s) failed:"
FAILURES.each { |f| puts "  #{f}" }
exit 1
