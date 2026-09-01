require "aws_backend"

# A declarative reader for resource types inspec-aws does not ship.
#
# Why this exists
# ---------------
# Checkov covers 217 AWS resource types. inspec-aws ships resources for 58 of
# them. Writing a bespoke InSpec resource for each of the rest would be ~130
# near-identical files whose only real content is "which client, which list call,
# which field" -- three facts that belong in data, not in Ruby.
#
# So the enumeration is described in tools/api_specs.yml, baked into
# libraries/_api_specs.rb, and read by this one resource. Adding a resource type
# becomes four lines of YAML that the linter can check, rather than a new library
# nobody reviews.
#
# What it deliberately does not do
# --------------------------------
# It does not interpret. It enumerates assets and extracts the named fields, and
# the control does the asserting. Anything needing real logic -- a policy
# document, a relationship between two resources -- is not expressible here and
# should not be forced into it.
#
# Failure posture
# ---------------
# A region that cannot be read is recorded in `unreadable_regions`, never
# flattened into "found nothing": absent renders as Not Applicable, which claims
# the rule does not apply here, and an unread region has not earned that. A
# service the account has never used answers with an empty list and that is a
# real answer; a denied call is not.
class AwsApiAssets < AwsResourceBase
  name "aws_api_assets"
  desc "Enumerates a resource type described in the baked API spec table."

  example "
    describe aws_api_assets(type: 'aws_lambda_function') do
      it { should exist }
    end
  "

  attr_reader :unreadable_regions, :account_id

  def initialize(opts = {})
    super(opts)
    validate_parameters(required: %i[type], allow: %i[type regions])
    @type = opts[:type].to_s
    @spec = API_SPECS[@type]
    raise ArgumentError, "aws_api_assets: no spec for #{@type}. Add it to tools/api_specs.yml." if @spec.nil?

    @unreadable_regions = []
    @account_id = fetch_account_id
    @rows = fetch_rows
  end

  # Rows as plain hashes with symbol keys, exemptions already removed. Controls
  # iterate these; see the note in aws_compute_assets on why not FilterTable.
  def assets(exempt: [])
    @rows.reject { |row| exempt?(row, exempt) }
  end

  def exists?
    !@rows.empty?
  end

  def to_s
    "#{@type} assets"
  end

  private

  def exempt?(asset, exemptions)
    Array(exemptions).any? do |rule|
      rule = rule.transform_keys(&:to_s) if rule.respond_to?(:transform_keys)
      next false unless rule.is_a?(Hash)
      next false if rule["type"] && rule["type"] != @type

      Array(rule["arns"]).include?(asset[:arn]) || Array(rule["ids"]).include?(asset[:id])
    end
  end

  def fetch_account_id
    id = nil
    catch_aws_errors { id = @aws.sts_client.get_caller_identity.account }
    id
  end

  # A missing SDK gem is NOT an unreadable region. The control cannot perform the
  # test as written at all, so it must surface as a profile error rather than as
  # a finding, a skip, or an empty result set. Raised, deliberately uncaught by
  # the region rescue below.
  class MissingGem < StandardError; end

  def load_sdk!
    require @spec["gem"] unless Object.const_defined?(@spec["client"])
  rescue LoadError
    raise MissingGem,
          "#{@spec['gem']} is not installed in this runtime, so #{@type} cannot be " \
          "enumerated. Add the gem to the auditor image (see tools/image_gems.txt " \
          "and tools/lint_api_specs.py); do not read this control's result as a pass, " \
          "a failure or a Not Applicable — nothing was assessed."
  end

  def client
    load_sdk!
    @aws.aws_client(Object.const_get(@spec["client"]))
  end

  # AwsConnection builds its clients for one region. A region walk needs one per
  # region, so the client class is instantiated directly rather than through the
  # connection's cached accessor.
  def regional_client(region)
    load_sdk!
    Object.const_get(@spec["client"]).new(region: region)
  end

  def regions
    return [nil] if @spec["scope"] == "global"

    declared = Array(@opts[:regions]).reject { |r| r.to_s.strip.empty? }
    return declared unless declared.empty?

    found = []
    catch_aws_errors { found = @aws.compute_client.describe_regions.regions.map(&:region_name) }
    found.empty? ? [@aws.compute_client.config.region].compact : found
  end

  def fetch_rows
    regions.flat_map { |region| rows_for(region) }
  end

  def rows_for(region)
    args = region ? { region: region } : {}
    api = region ? regional_client(region) : client
    collect(api, region)
  rescue MissingGem
    # Deliberately re-raised: filing this under unreadable_regions would turn
    # "the profile cannot run this test" into "this region had nothing in it".
    raise
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError, ArgumentError => e
    @unreadable_regions << { region: region || "global", error: e.message }
    []
  end

  def collect(api, region)
    rows = []
    response = api.public_send(@spec["list"])
    pages = response.respond_to?(:each) ? response : [response]
    pages.each do |page|
      Array(page.public_send(@spec["collection"])).each do |item|
        rows << row_for(item.to_h, region)
      end
    end
    rows
  end

  def row_for(item, region)
    row = { id: dig_path(item, @spec["id"]).to_s, region: region || "global",
            account_id: @account_id, type: @type }
    row[:arn] = dig_path(item, @spec["arn"]) if @spec["arn"]
    (@spec["fields"] || {}).each { |name, path| row[name.to_sym] = dig_path(item, path) }
    row
  end

  # "tracing_config.mode" -> item[:tracing_config][:mode], tolerating a missing
  # level. A field the API did not return is nil, and a control skips a nil
  # rather than reading it as a passing false.
  #
  # `false` is a VALUE and must survive, so the symbol key is tested for nil
  # explicitly rather than for truthiness. `node[key.to_sym] || node[key]` read a
  # member the API returned as `false` -- the FAILING state for every
  # `equals: true` mapping -- as nil, which the generated template then filters
  # out of scope as "does not express this setting". A boundary where every
  # asset failed rendered as Not Applicable, and one where some failed reported
  # 100% pass over the survivors. Same reason _checkov_collection.rb's `step`
  # tests nil explicitly; both walks have to.
  def dig_path(item, path)
    path.to_s.split(".").reduce(item) do |node, key|
      break nil unless node.is_a?(Hash)

      value = node[key.to_sym]
      value.nil? ? node[key] : value
    end
  end
end
