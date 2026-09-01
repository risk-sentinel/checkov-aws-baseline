#!/usr/bin/env ruby
# Integration test for libraries/aws_policy_documents.rb, with fake SDK clients.
#
# Why this exists, measured rather than assumed
# ---------------------------------------------
# `cinc-auditor check` and `json` cover NOTHING in libraries/. Verified against
# risksentinel/sparc-auditor:v0.5.0 by appending, in turn, a runtime NameError
# and then a syntax error to libraries/_policy_document.rb: both commands exited
# 0 and printed "Valid: true — No errors, warnings, or offenses". (A syntax error
# in a CONTROL file is barely better: `check` still says Valid: true and simply
# reports one fewer control.) So for a reader, the two commands in the proof
# checklist prove that the profile still parses, and nothing else.
#
# This test loads the three library files EXACTLY the way InSpec does --
# `context.instance_eval(content, source, line)` against one shared eval context,
# per inspec-core lib/inspec/profile_context.rb#load_with_context -- so the
# cross-file constant resolution the reader depends on (PolicyDocument and
# POLICY_SPECS are defined in other files) is exercised rather than assumed.
# Under instance_eval those constants are NOT on Object; they resolve only
# because every library file shares one cref. That is worth a test.
#
# What is faked, and the risk that carries
# ----------------------------------------
# AwsResourceBase is stubbed with the four things the reader uses -- @opts, @aws,
# validate_parameters and catch_aws_errors -- and the SDK clients are hand-built.
# A stub can drift from the vendored base class, so this proves the reader's OWN
# logic (region walk, second call, argument resolution, failure posture) and not
# its integration with inspec-aws. Say so rather than reading a pass here as
# proof the control works against AWS; only an exec does that.
#
# The failure posture is the point. Four ways to end up with no offending
# statements, and only two of them are a pass:
#
#   clean policy               -> PASS
#   no policy at all           -> PASS, policy_present: false
#   the read was DENIED        -> undecidable, excluded from assets, control FAILS
#   the document did not parse -> undecidable, excluded from assets, control FAILS
#
# Every one of those four is asserted below, because a reader that collapses the
# last two into the first turns the least-visible estate into the cleanest-
# looking one.
#
# Run:  ruby tests/policy_reader_harness.rb
# No gems, no network, no AWS credentials.

require "json"

FAILURES = []
def assert(name, cond, detail = nil)
  FAILURES << "#{name}#{detail ? " — #{detail}" : ''}" unless cond
end

# ---------------------------------------------------------------- SDK stubs --

module Seahorse
  module Client
    class NetworkingError < StandardError; end
  end
end

module Aws
  module Errors
    class ServiceError < StandardError; end
  end
  module ECR
    module Errors
      class RepositoryPolicyNotFoundException < ::Aws::Errors::ServiceError; end
      class AccessDeniedException < ::Aws::Errors::ServiceError; end
    end
  end
end

module Inspec
  class Rule; end
end

class Response
  def initialize(hash) = @hash = hash
  def to_h = @hash
end

class Page
  def initialize(name, items)
    @name = name
    @items = items
  end

  def respond_to_missing?(m, _ = false) = m == @name
  def method_missing(m, *args)
    m == @name ? @items : super
  end
end

CALLS = []

class FakeIam
  def initialize(region: nil) = @region = region

  def list_roles(_args = {})
    [Page.new(:roles, [
      { role_name: "public-trust", arn: "arn:aws:iam::111122223333:role/public-trust",
        assume_role_policy_document: encoded(
          "Version" => "2012-10-17",
          "Statement" => [{ "Effect" => "Allow", "Principal" => { "AWS" => "*" },
                            "Action" => "sts:AssumeRole" }]
        ) },
      { role_name: "service-trust", arn: "arn:aws:iam::111122223333:role/service-trust",
        assume_role_policy_document: encoded(
          "Version" => "2012-10-17",
          "Statement" => { "Effect" => "Allow",
                           "Principal" => { "Service" => "ecs-tasks.amazonaws.com" },
                           "Action" => "sts:AssumeRole" }
        ) },
      { role_name: "broken-trust", arn: "arn:aws:iam::111122223333:role/broken-trust",
        assume_role_policy_document: "not a policy at all" },
    ])]
  end

  def list_policies(args = {})
    CALLS << [:list_policies, args]
    [Page.new(:policies, [
      { policy_name: "admin", arn: "arn:aws:iam::111122223333:policy/admin",
        default_version_id: "v3" },
    ])]
  end

  def get_policy_version(args)
    CALLS << [:get_policy_version, args]
    Response.new(policy_version: {
      document: encoded("Version" => "2012-10-17",
                        "Statement" => [{ "Effect" => "Allow", "Action" => "*",
                                          "Resource" => "*" }]),
      version_id: args[:version_id],
    })
  end

  # IAM hands policy documents back URL-encoded (RFC 3986).
  def encoded(doc)
    JSON.generate(doc).gsub(/[^A-Za-z0-9\-_.~]/) { |c| format("%%%02X", c.ord) }
  end
end

class FakeEcr
  def initialize(region: nil) = @region = region

  def describe_repositories(_args = {})
    raise ::Aws::Errors::ServiceError, "region opted out" if @region == "eu-broken"

    [Page.new(:repositories, [
      { repository_name: "public-repo",
        repository_arn: "arn:aws:ecr:#{@region}:111122223333:repository/public-repo" },
      { repository_name: "no-policy",
        repository_arn: "arn:aws:ecr:#{@region}:111122223333:repository/no-policy" },
      { repository_name: "denied",
        repository_arn: "arn:aws:ecr:#{@region}:111122223333:repository/denied" },
    ])]
  end

  def get_repository_policy(args)
    CALLS << [:get_repository_policy, args]
    case args[:repository_name]
    when "public-repo"
      Response.new(policy_text: JSON.generate(
        "Version" => "2012-10-17",
        "Statement" => [{ "Sid" => "Public", "Effect" => "Allow", "Principal" => "*",
                          "Action" => "ecr:BatchGetImage" }]
      ))
    when "no-policy"
      raise ::Aws::ECR::Errors::RepositoryPolicyNotFoundException, "no policy"
    else
      raise ::Aws::ECR::Errors::AccessDeniedException, "not authorized"
    end
  end
end

Aws::IAM = Module.new unless defined?(Aws::IAM)
Aws::IAM.const_set(:Client, FakeIam)
Aws::ECR.const_set(:Client, FakeEcr)

class FakeRegions
  def initialize(regions) = @regions = regions
  def regions = @regions.map { |r| Struct.new(:region_name).new(r) }
end

class FakeEc2
  def initialize(regions) = @regions = regions
  def describe_regions = FakeRegions.new(@regions)
  def config = Struct.new(:region).new(@regions.first)
end

class FakeSts
  def get_caller_identity = Struct.new(:account).new("111122223333")
end

class FakeConnection
  def initialize(regions) = @regions = regions
  def sts_client = FakeSts.new
  def compute_client = FakeEc2.new(@regions)
  def aws_client(klass) = klass.new
end

# Stand-in for the vendored AwsResourceBase. Only the four things the reader
# actually uses: @opts, @aws, validate_parameters and catch_aws_errors.
STUB_REGIONS = ["us-east-1", "eu-broken"].freeze

BACKEND = <<~'RUBY'
  class AwsResourceBase
    def initialize(opts = {})
      @opts = opts
      @aws = FakeConnection.new(STUB_REGIONS)
    end

    def self.name(value = nil) = value
    def self.desc(value = nil) = value
    def self.example(value = nil) = value

    # Copied VERBATIM from the vendored AwsResourceBase (aws_backend.rb:390-412),
    # not paraphrased. The paraphrase this replaced was permissive where the real
    # one is strict, and it hid a live bug: the vendored version refuses ANY empty
    # value, an empty Array included, so `regions: []` -- which is what
    # `input('scan_regions')` returns on a default run -- raised
    # "Provided parameter should not be empty" out of the constructor before a
    # single policy was read. A stub that is kinder than the thing it stands in
    # for proves nothing, so this one is a transcription.
    def validate_parameters(allow: [], required: nil, require_any_of: nil)
      if required
        raise ArgumentError, "Expected required parameters as Array of Symbols, got #{required}" unless required.is_a?(Array) && required.all? { |r| r.is_a?(Symbol) }
        raise ArgumentError, "`#{required}` must be provided" unless @opts.is_a?(Hash) && required.all? { |req| @opts.key?(req) && !@opts[req].nil? && @opts[req] != "" }

        allow += required
      end
      if require_any_of
        raise ArgumentError, "One of `#{require_any_of}` must be provided." unless @opts.is_a?(Hash) && require_any_of.any? { |req| @opts.key?(req) && !@opts[req].nil? && @opts[req] != "" }

        allow += require_any_of
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

# ------------------------------------------------ load exactly as InSpec does --

ROOT = ARGV[0] || File.expand_path("..", __dir__)
class LibraryEvalContext; end
CTX = LibraryEvalContext.new
%w[_policy_specs.rb _policy_document.rb aws_policy_documents.rb].each do |f|
  path = File.join(ROOT, "libraries", f)
  CTX.instance_eval(File.read(path), "libraries/#{f}", 1)
end
Reader = CTX.instance_eval("AwsPolicyDocuments")

assert "the reader class loaded", !Reader.nil?
assert "PolicyDocument resolves across files", CTX.instance_eval("PolicyDocument::PREDICATES").length == 6

# ------------------------------------------------------------------- IAM roles

CALLS.clear
roles = Reader.new(type: "aws_iam_role", predicate: "no_wildcard_principal")
rows = roles.assets
by_id = rows.to_h { |r| [r[:id], r] }

assert "global scope enumerates once, not per region", rows.length == 2,
       "got #{rows.map { |r| r[:id] }.inspect}"
assert "the wildcard trust role has one offender",
       by_id["public-trust"] && by_id["public-trust"][:offenders].length == 1
assert "the offender names the statement",
       by_id["public-trust"][:offenders].first.start_with?("Statement[0]: Effect Allow to Principal.AWS *")
assert "the service-principal role is clean, not absent",
       by_id["service-trust"] && by_id["service-trust"][:offenders] == []
assert "a URL-encoded document was decoded", by_id["service-trust"][:policy_present] == true
assert "an unparsable document is UNDECIDABLE, not clean",
       roles.undecidable.length == 1 && roles.undecidable.first.include?("broken-trust")
assert "an undecidable asset is NOT in assets", by_id["broken-trust"].nil?
assert "a global source reports region 'global'", by_id["public-trust"][:region] == "global"
assert "the account id is carried", by_id["public-trust"][:account_id] == "111122223333"
assert "no region was reported unreadable", roles.unreadable_regions.empty?
assert "exemptions match on id",
       roles.assets(exempt: [{ "type" => "aws_iam_role", "ids" => ["public-trust"] }])
            .map { |r| r[:id] } == ["service-trust"]
assert "exemptions match on arn",
       roles.assets(exempt: [{ "type" => "aws_iam_role",
                               "arns" => ["arn:aws:iam::111122223333:role/public-trust"] }])
            .map { |r| r[:id] } == ["service-trust"]
assert "an exemption scoped to another type does not match",
       roles.assets(exempt: [{ "type" => "aws_s3_bucket", "ids" => ["public-trust"] }])
            .length == 2

# ------------------------------------------------------------ IAM policy fetch

CALLS.clear
policies = Reader.new(type: "aws_iam_policy", predicate: "no_admin_star_star")
listed = CALLS.select { |c| c.first == :list_policies }
assert "list_args reach the SDK call", listed.first[1] == { scope: "Local" },
       listed.first.inspect
fetched = CALLS.select { |c| c.first == :get_policy_version }
assert "fetch args resolve `from: arn` and `from_item:`",
       fetched.first[1] == { policy_arn: "arn:aws:iam::111122223333:policy/admin",
                             version_id: "v3" }, fetched.first.inspect
assert "a nested response path is dug out and judged",
       policies.assets.first[:offenders].length == 1
assert "the admin finding names both stars",
       policies.assets.first[:offenders].first.include?("Action * on Resource *")

# ------------------------------------------------------------ ECR, regional ---

CALLS.clear
ecr = Reader.new(type: "aws_ecr_repository_policy", predicate: "no_wildcard_principal",
                 regions: STUB_REGIONS)
ecr_by_id = ecr.assets.to_h { |r| [r[:id], r] }

assert "a region whose LIST call failed is unreadable, not empty",
       ecr.unreadable_regions.length == 1 &&
       ecr.unreadable_regions.first[:region] == "eu-broken"
assert "the readable region still produced rows", ecr.assets.length == 2
assert "a public repository policy is a finding",
       ecr_by_id["public-repo"] && ecr_by_id["public-repo"][:offenders].length == 1
assert "absent_when means no policy, which PASSES",
       ecr_by_id["no-policy"] && ecr_by_id["no-policy"][:offenders] == [] &&
       ecr_by_id["no-policy"][:policy_present] == false
assert "a DENIED read is undecidable, never 'no policy'",
       ecr.undecidable.length == 1 && ecr.undecidable.first.include?("denied") &&
       ecr.undecidable.first.include?("AccessDeniedException")
assert "the denied repository is not in assets", ecr_by_id["denied"].nil?
assert "a regional source carries its region",
       ecr_by_id["public-repo"][:region] == "us-east-1"
assert "fetch args resolve `from: id`",
       CALLS.select { |c| c.first == :get_repository_policy }
            .map { |c| c[1] }.include?(repository_name: "public-repo")

# --------------------------------------------------------------- refusals -----

# --------------------------------------------- the default-inputs region walk --
#
# `scan_regions` defaults to `[]` in inspec.yml, so a default run passes an empty
# array. The vendored validate_parameters refuses any empty value, so the reader
# drops the key before super. This asserts the DEFAULT invocation works at all --
# without it, every policy control errors on every run that does not name regions.
CALLS.clear
default_run = Reader.new(type: "aws_ecr_repository_policy",
                         predicate: "no_wildcard_principal", regions: [])
assert "an empty regions array does not raise, and still walks every region",
       default_run.assets.length == 2 && default_run.unreadable_regions.length == 1
assert "a regions array of blanks is treated as empty too",
       Reader.new(type: "aws_ecr_repository_policy", predicate: "no_wildcard_principal",
                  regions: ["", "  "]).assets.length == 2

begin
  Reader.new(type: "aws_iam_role", predicate: "no_such_thing")
  FAILURES << "an unimplemented predicate was accepted"
rescue ArgumentError => e
  assert "the refusal lists what IS implemented", e.message.include?("no_wildcard_principal")
end

begin
  Reader.new(type: "aws_nope", predicate: "no_wildcard_principal")
  FAILURES << "an unknown source was accepted"
rescue ArgumentError => e
  assert "the refusal names policy_specs.yml", e.message.include?("policy_specs.yml")
end

begin
  Reader.new(type: "aws_iam_role", predicate: "no_wildcard_principal", bogus: 1)
  FAILURES << "an unexpected parameter was accepted"
rescue ArgumentError
  nil
end

# ------------------------------------------------------------------ report ----

if FAILURES.empty?
  puts "OK — the policy reader walks regions, resolves fetch arguments, and keeps "\
       "an unreadable policy distinguishable from an absent one."
  exit 0
end
puts "::error::#{FAILURES.length} reader assertion(s) failed:"
FAILURES.each { |f| puts "  #{f}" }
exit 1
