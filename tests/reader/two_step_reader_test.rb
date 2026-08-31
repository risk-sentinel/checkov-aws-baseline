# Exercises libraries/aws_api_assets.rb's two-step (parent -> child) enumeration
# against stubbed AWS clients.
#
# Why this exists at all: `cinc-auditor check` and `cinc-auditor json` load
# control files without evaluating any control body, so they cannot see a reader
# bug. Every defect this shape can have — a structure flattened into its member
# values, a lost subtree that reads as an empty one, a wrong collection member
# that yields a green control — is invisible until exec, and exec needs an
# account that HAS the resource type. Stubbed clients close that gap statically.
#
# Run:
#   docker run --rm -v "$PWD:/work" -w /work \
#     --entrypoint ruby risksentinel/sparc-auditor:v0.5.0 \
#     tests/reader/two_step_reader_test.rb
$LOAD_PATH.unshift(__dir__)
require "aws_backend"
require "aws-sdk-apigateway"
require "aws-sdk-eks"
require "aws-sdk-guardduty"
require "aws-sdk-sns"

ROOT = File.expand_path("../..", __dir__)
load File.join(ROOT, "libraries", "_api_specs.rb")
load File.join(ROOT, "libraries", "aws_api_assets.rb")

# Everything except client construction runs for real: the region walk, the parent
# enumeration, pagination, the collection branch, dig_path and row assembly.
class StubbedAssets < AwsApiAssets
  private

  def client
    @opts[:stub_client]
  end

  def regional_client(_region)
    @opts[:stub_client]
  end
end

def stubbed(klass)
  klass.new(region: "us-east-1", stub_responses: true)
end

FAILURES = []

def check(what)
  ok, detail = yield
  if ok
    puts "  ok   #{what}"
  else
    puts "  FAIL #{what} — #{detail}"
    FAILURES << what
  end
rescue StandardError => e
  puts "  FAIL #{what} — raised #{e.class}: #{e.message}"
  FAILURES << what
end

def eq(actual, expected)
  [actual == expected, "expected #{expected.inspect}, got #{actual.inspect}"]
end

# --------------------------------------------------------------------------
puts "aws_api_gateway_stage — parent structures, child list in the singular `item`"

api = stubbed(Aws::APIGateway::Client)
# Two pages of parents, to prove the parent leg does not stop at page one. The
# GetRestApis paginator keys on `position`, so a page carrying one asks for
# another and a page without one ends the walk.
api.stub_responses(:get_rest_apis,
                   [{ items: [{ id: "a1" }, { id: "a2" }], position: "p1" },
                    { items: [{ id: "a3" }] }])
# One child response per parent, in enumeration order. a2 has no stages: that is
# a real answer, not an error and not a failure.
api.stub_responses(:get_stages,
                   [{ item: [{ stage_name: "prod", tracing_enabled: true }] },
                    { item: [] },
                    { item: [{ stage_name: "dev", tracing_enabled: false },
                             { stage_name: "qa", tracing_enabled: true }] }])

stages = StubbedAssets.new(type: "aws_api_gateway_stage", regions: ["us-east-1"],
                           stub_client: api)
rows = stages.assets

check("walks both pages of parents") { eq(stages.parents_seen, 3) }
check("flattens children of every parent") { eq(rows.map { |r| r[:id] }.sort, %w[dev prod qa]) }
check("a parent with no children is not a failure") { eq(stages.parent_failures, []) }
check("reads the child field") do
  eq(rows.find { |r| r[:id] == "dev" }[:tracing_enabled], false)
end
check("a child row carries its parent id") do
  eq(rows.find { |r| r[:id] == "prod" }[:parent_id], "a1")
end
check("a nested child field resolves through dig_path") do
  api2 = stubbed(Aws::APIGateway::Client)
  api2.stub_responses(:get_rest_apis, items: [{ id: "a1" }])
  api2.stub_responses(:get_stages,
                      item: [{ stage_name: "prod",
                               access_log_settings: { destination_arn: "arn:log" } }])
  a = StubbedAssets.new(type: "aws_api_gateway_stage", regions: ["us-east-1"],
                        stub_client: api2).assets
  eq(a.first[:access_log_destination_arn], "arn:log")
end

# --------------------------------------------------------------------------
puts "aws_api_gateway_stage — a failed child call is a LOST SUBTREE, not an empty one"

api_err = stubbed(Aws::APIGateway::Client)
api_err.stub_responses(:get_rest_apis, items: [{ id: "a1" }, { id: "a2" }, { id: "a3" }])
api_err.stub_responses(:get_stages,
                       [{ item: [{ stage_name: "prod" }] },
                        "AccessDeniedException",
                        { item: [{ stage_name: "dev" }] }])

lossy = StubbedAssets.new(type: "aws_api_gateway_stage", regions: ["us-east-1"],
                          stub_client: api_err)

check("the surviving subtrees are still read") { eq(lossy.assets.length, 2) }
check("the lost subtree is recorded, not dropped") { eq(lossy.parent_failures.length, 1) }
check("the record names the parent it lost") { eq(lossy.parent_failures.first[:parent_id], "a2") }
check("a lost subtree is not an unreadable region") { eq(lossy.unreadable_regions, []) }

# --------------------------------------------------------------------------
puts "aws_eks_cluster — parent.id: _self, and a child collection that is ONE STRUCTURE"

eks = stubbed(Aws::EKS::Client)
eks.stub_responses(:list_clusters, clusters: %w[app data])
eks.stub_responses(:describe_cluster,
                   [{ cluster: { name: "app", arn: "arn:app",
                                 resources_vpc_config: { endpoint_public_access: true } } },
                    { cluster: { name: "data", arn: "arn:data",
                                 resources_vpc_config: { endpoint_public_access: false } } }])

clusters = StubbedAssets.new(type: "aws_eks_cluster", regions: ["us-east-1"], stub_client: eks)
eks_rows = clusters.assets

# The regression this guards: Aws::EKS::Types::Cluster is a Struct subclass, so
# Array() on it returns its 28 MEMBER VALUES. Two clusters must be two rows.
check("one structure is one row, not its member values") { eq(eks_rows.length, 2) }
check("a scalar parent collection yields its items as ids") do
  eq(eks_rows.map { |r| r[:parent_id] }.sort, %w[app data])
end
check("the child's own id member is used") { eq(eks_rows.map { |r| r[:id] }.sort, %w[app data]) }
check("reads a nested boolean, including false") do
  eq(eks_rows.find { |r| r[:id] == "data" }[:endpoint_public_access], false)
end
check("carries the arn for exemption matching") do
  eq(eks_rows.find { |r| r[:id] == "app" }[:arn], "arn:app")
end

# --------------------------------------------------------------------------
puts "aws_guardduty_detector — collection: _response and id: _parent"

gd = stubbed(Aws::GuardDuty::Client)
gd.stub_responses(:list_detectors, detector_ids: ["d-1"])
# service_role is a REQUIRED member of GetDetectorResponse, so the stub is
# rejected without it — which the reader correctly records as a parent failure
# rather than as an empty detector. Leaving it out was how this test first ran.
gd.stub_responses(:get_detector, status: "ENABLED", service_role: "arn:role",
                                 finding_publishing_frequency: "FIFTEEN_MINUTES")

detectors = StubbedAssets.new(type: "aws_guardduty_detector", regions: ["us-east-1"],
                              stub_client: gd)
gd_rows = detectors.assets

check("a wrapperless response is one row") { eq(gd_rows.length, 1) }
check("id falls back to the parent id") { eq(gd_rows.first[:id], "d-1") }
check("top-level response members are readable fields") { eq(gd_rows.first[:status], "ENABLED") }

# --------------------------------------------------------------------------
puts "empty and broken accounts are told apart"

empty = stubbed(Aws::EKS::Client)
empty.stub_responses(:list_clusters, clusters: [])
none = StubbedAssets.new(type: "aws_eks_cluster", regions: ["us-east-1"], stub_client: empty)

check("no parents means no rows") { eq(none.assets, []) }
check("no parents is counted, so the control can say so") { eq(none.parents_seen, 0) }
check("no parents is not a failure") { eq(none.parent_failures, []) }
check("no parents is not an unreadable region") { eq(none.unreadable_regions, []) }

denied = stubbed(Aws::EKS::Client)
denied.stub_responses(:list_clusters, "AccessDeniedException")
blind = StubbedAssets.new(type: "aws_eks_cluster", regions: ["us-east-1"], stub_client: denied)

check("a failed PARENT leg is an unreadable region") { eq(blind.unreadable_regions.length, 1) }
check("a failed parent leg enumerates nothing") { eq(blind.parents_seen, 0) }

# --------------------------------------------------------------------------
puts "one-step specs are unchanged by the shared item/hash handling"

sns = stubbed(Aws::SNS::Client)
sns.stub_responses(:list_topics, topics: [{ topic_arn: "arn:t1" }, { topic_arn: "arn:t2" }])
topics = StubbedAssets.new(type: "aws_sns_topic", regions: ["us-east-1"], stub_client: sns)

check("a one-step spec still enumerates") { eq(topics.assets.map { |r| r[:id] }, %w[arn:t1 arn:t2]) }
check("a one-step spec reports no parents") { eq(topics.parents_seen, 0) }
check("a one-step row carries no parent_id") { eq(topics.assets.first.key?(:parent_id), false) }

# --------------------------------------------------------------------------
puts "a spec that names the wrong kind of member is a PROFILE ERROR, not zero rows"

broken = API_SPECS.dup
broken["aws_scalar_child_probe"] = {
  "gem" => "aws-sdk-eks", "client" => "Aws::EKS::Client", "scope" => "regional",
  "parent" => { "list" => "list_clusters", "collection" => "clusters", "id" => "_self" },
  # WRONG on purpose: `clusters` on a ListClusters response is a list of STRINGS,
  # which carry no fields. A spec pointing a CHILD collection at scalars would
  # otherwise produce rows of nils, which the nil filter removes, which renders
  # Not Applicable. `next_token` is used as the arg only because it is a real
  # String parameter of ListClusters, so the call itself succeeds.
  "arg" => "next_token", "list" => "list_clusters",
  "collection" => "clusters", "id" => "name", "fields" => {},
}
Object.send(:remove_const, :API_SPECS)
Object.const_set(:API_SPECS, broken.freeze)

scalar = stubbed(Aws::EKS::Client)
scalar.stub_responses(:list_clusters, clusters: %w[app])

check("a scalar child collection raises rather than yielding empty rows") do
  begin
    StubbedAssets.new(type: "aws_scalar_child_probe", regions: ["us-east-1"],
                      stub_client: scalar)
    [false, "no exception raised — a spec bug would have rendered Not Applicable"]
  rescue AwsApiAssets::SpecError => e
    [e.message.include?("collection"), "unexpected message: #{e.message}"]
  end
end

# --------------------------------------------------------------------------
puts ""
if FAILURES.empty?
  puts "OK — all reader assertions passed"
  exit 0
end
puts "#{FAILURES.length} assertion(s) failed:"
FAILURES.each { |f| puts "  #{f}" }
exit 1
