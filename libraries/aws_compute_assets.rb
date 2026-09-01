require "aws_backend"

# Every deployed asset a Checkov EC2-family check can apply to, as one row each.
#
# Why one resource for three Terraform types
# ------------------------------------------
# A Checkov check declares `supported_resources`, and for this family that is
# usually `aws_instance` + `aws_launch_template` + `aws_launch_configuration`.
# Those are three different APIs but one question: "does the thing that exists
# satisfy the rule". Keeping them in one table lets a control iterate the types
# its check actually declares, instead of every control re-deriving three
# enumerations and diverging in how it handles an empty one.
#
# Region walking
# --------------
# A single-region sweep reports "absent" for a workload that exists elsewhere,
# and absent renders as Not Applicable -- a claim that the rule does not apply
# here, which is not the same as not having looked. So the walk is explicit, and
# a region that could not be read is recorded in `unreadable_regions` rather
# than being flattened into "found nothing".
class AwsComputeAssets < AwsResourceBase
  name "aws_compute_assets"
  desc "EC2 instances, launch templates and launch configurations, with the "\
       "attributes the Checkov EC2-family checks assert on."

  example "
    describe aws_compute_assets(regions: ['us-east-1']).where(type: 'aws_instance') do
      its('public_ip') { should_not include true }
    end
  "

  attr_reader :table

  # Regions that could not be read -- INCLUDING the case where this resource
  # never got as far as walking one.
  #
  # catch_aws_errors raises Inspec::Exceptions::ResourceFailed on a 403, and
  # Inspec::Resource#supersuper_initialize rescues it around the whole
  # constructor, so a denied sts:GetCallerIdentity or ec2:DescribeRegions hands
  # the control a live object with @table never assigned. Answering [] here would
  # make `applicable` false and render the control Not Applicable having assessed
  # nothing, which is the failure this reader exists to prevent.
  def unreadable_regions
    failure = %i[resource_failed? failed_resource? resource_skipped?].find do |predicate|
      respond_to?(predicate) && public_send(predicate)
    end
    return Array(@unreadable_regions) unless failure

    Array(@unreadable_regions) + [{
      region: "(every region)",
      error: "the compute inventory could not be read at all (#{failure}): "\
             "#{(respond_to?(:resource_exception_message) && resource_exception_message) || 'the AWS call did not succeed'}. "\
             "NOTHING was assessed here",
    }]
  end

  FilterTable.create
             .register_column(:ids,                     field: :id)
             .register_column(:arns,                    field: :arn)
             .register_column(:types,                   field: :type)
             .register_column(:regions,                 field: :region)
             .register_column(:account_ids,             field: :account_id)
             .register_column(:imds_tokens_or_disabled, field: :imds_tokens_or_disabled)
             .register_column(:public_ip,               field: :public_ip)
             .register_column(:ebs_optimized,           field: :ebs_optimized)
             .register_column(:detailed_monitoring,     field: :detailed_monitoring)
             .register_column(:unencrypted_volumes,     field: :unencrypted_volumes)
             .register_column(:user_data_secrets,       field: :user_data_secrets)
             .register_column(:iam_roles,               field: :iam_roles)
             .install_filter_methods_on_resource(self, :table)

  # Patterns that make a user-data blob a finding rather than a config file.
  # Deliberately narrow: a scanner that flags every base64 blob trains its
  # reader to ignore it.
  SECRET_PATTERNS = [
    /\bAKIA[0-9A-Z]{16}\b/,                                   # long-term access key id
    /\bASIA[0-9A-Z]{16}\b/,                                   # temporary access key id
    /aws_secret_access_key\s*[:=]\s*\S{16,}/i,
    /\b(?:postgres|mysql|mongodb|redis):\/\/[^\s:@]+:[^\s@]+@/i, # credentials in a URI
    /(?:password|passwd|secret|token)\s*[:=]\s*['"][^'"]{8,}['"]/i,
  ].freeze

  def initialize(opts = {})
    opts = { regions: opts } if opts.is_a?(Array)
    super(opts)
    validate_parameters(allow: %i[regions])
    @unreadable_regions = []
    @account_id = fetch_account_id
    @table = fetch_data
  end

  attr_reader :account_id

  # Array(), not @table: a constructor that failed above never assigned it, and a
  # NoMethodError on nil reports as a control source-code error rather than as
  # the read failure that unreadable_regions is already carrying.
  def exists?
    !Array(@table).empty?
  end

  # Rows for the given Terraform resource types, as plain hashes.
  #
  # Controls iterate these rather than FilterTable entries: `entries` yields
  # Structs whose shape is FilterTable's business, not this profile's, and a
  # control that reaches into it breaks quietly when that changes. A hash with
  # symbol keys is the contract here.
  # Rows for the given Terraform resource types, with declared exemptions
  # already removed.
  #
  # Filtering happens here rather than in the control because the resource class
  # is NOT resolvable by constant from a control's eval context -- InSpec
  # registers a library resource under its DSL name, not as a constant the
  # control can reach. A control calling `AwsComputeAssets.exempt?` raises
  # `uninitialized constant` at exec, and neither `check` nor `json` sees it.
  #
  # Controls iterate plain hashes with symbol keys rather than FilterTable
  # entries: `entries` yields Structs whose shape is FilterTable's business, and
  # a control that reaches into it breaks quietly when that changes.
  def assets_of(types, exempt: [])
    wanted = Array(types)
    Array(@table).select { |row| wanted.include?(row[:type]) && !exempt?(row, exempt) }
  end

  # Does a declared exemption cover this asset?
  #
  # An exemption is scoped by resource TYPE and matched on ARN, because an id
  # alone is ambiguous across types and names neither the account nor the region
  # it lives in. A boundary that inherits assets from another account needs to
  # name them precisely, and an ARN is the only identifier that does.
  #
  #   exempt_assets:
  #     CKV_AWS_88:
  #       - type: aws_instance
  #         arns:
  #           - arn:aws:ec2:us-east-2:111122223333:instance/i-0123456789abcdef0
  #
  # `ids:` is accepted alongside `arns:` for the case where the console id is
  # what an operator has in hand and the asset is unambiguously in this account.
  def exempt?(asset, exemptions)
    Array(exemptions).any? do |rule|
      rule = rule.transform_keys(&:to_s) if rule.respond_to?(:transform_keys)
      next false unless rule.is_a?(Hash)
      next false if rule["type"] && rule["type"] != asset[:type]

      Array(rule["arns"]).include?(asset[:arn]) || Array(rule["ids"]).include?(asset[:id])
    end
  end

  private

  # The boundary this evidence is about. Carried on every row so a result names
  # the account it came from -- evidence that does not identify its subject is
  # not evidence, and a multi-account estate produces identical-looking rows
  # otherwise.
  def fetch_account_id
    id = nil
    catch_aws_errors do
      # Through @aws, not bare: the client accessors live on AwsConnection, and
      # a resource that calls `sts_client` directly raises NameError the moment
      # it runs -- which `check` and `json` never do.
      id = @aws.sts_client.get_caller_identity.account
    end
    id
  end

  # Derived from the region rather than read from an input: a resource cannot
  # read inputs (`input()` raises in resource scope), and the region already
  # carries the answer.
  def partition_for(region)
    case region.to_s
    when /\Aus-gov-/ then "aws-us-gov"
    when /\Acn-/     then "aws-cn"
    else                  "aws"
    end
  end

  def arn_for(region, service, resource)
    "arn:#{partition_for(region)}:#{service}:#{region}:#{@account_id}:#{resource}"
  end

  def fetch_data
    @scan_regions = resolve_regions
    @scan_regions.flat_map { |region| walk_region(region) }
  end

  def resolve_regions
    declared = Array(@opts[:regions]).reject { |r| r.to_s.strip.empty? }
    return declared unless declared.empty?

    regions = []
    catch_aws_errors do
      resp = @aws.compute_client.describe_regions
      regions = resp.regions.map(&:region_name)
    end
    # An empty list here means describe_regions itself failed. Returning [] would
    # scan nothing and report an account with no compute -- the exact silence
    # this resource exists to avoid -- so fall back to the configured region.
    regions.empty? ? [@aws.compute_client.config.region].compact : regions
  end

  def walk_region(region)
    rows = []
    begin
      client = ::Aws::EC2::Client.new(region: region)
      rows.concat(instances(client, region))
      rows.concat(launch_templates(client, region))
      rows.concat(launch_configurations(region))
    rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError => e
      # Recorded, not swallowed. A denied or unreachable region is undetermined,
      # and a control that treats it as "nothing here" passes vacuously.
      @unreadable_regions << { region: region, error: e.message }
    end
    rows
  end

  def instances(client, region)
    rows = []
    client.describe_instances.each do |page|
      page.reservations.each do |res|
        res.instances.each do |i|
          next if %w[terminated shutting-down].include?(i.state&.name)

          rows << {
            id:                     i.instance_id,
            arn:                    arn_for(region, "ec2", "instance/#{i.instance_id}"),
            account_id:             @account_id,
            type:                   "aws_instance",
            region:                 region,
            imds_tokens_or_disabled: imds_ok?(i.metadata_options),
            public_ip:              !i.public_ip_address.to_s.empty?,
            ebs_optimized:          !!i.ebs_optimized,
            detailed_monitoring:    i.monitoring&.state == "enabled",
            unencrypted_volumes:    unencrypted_volumes(client, i),
            user_data_secrets:      user_data_secrets(client, i.instance_id),
            iam_roles:              roles_in_profile(i.iam_instance_profile&.arn),
          }
        end
      end
    end
    rows
  end

  def launch_templates(client, region)
    rows = []
    client.describe_launch_templates.each do |page|
      page.launch_templates.each do |lt|
        data = latest_template_data(client, lt)
        next if data.nil?

        rows << {
          id:                     lt.launch_template_id,
          arn:                    arn_for(region, "ec2", "launch-template/#{lt.launch_template_id}"),
          account_id:             @account_id,
          type:                   "aws_launch_template",
          region:                 region,
          imds_tokens_or_disabled: imds_ok?(data.metadata_options),
          public_ip:              template_public_ip?(data),
          # Not expressed on a launch template: the API has no equivalent, and
          # nil says so rather than implying a passing value.
          ebs_optimized:          nil,
          detailed_monitoring:    nil,
          unencrypted_volumes:    nil,
          user_data_secrets:      secrets_in(decode(data.user_data)),
          iam_roles:              roles_in_profile(data.iam_instance_profile&.arn ||
                                                   data.iam_instance_profile&.name),
        }
      end
    end
    rows
  end

  def launch_configurations(region)
    rows = []
    asg = ::Aws::AutoScaling::Client.new(region: region)
    asg.describe_launch_configurations.each do |page|
      page.launch_configurations.each do |lc|
        rows << {
          id:                     lc.launch_configuration_name,
          # The API hands back the real ARN here, so use it rather than
          # reconstructing one -- a launch configuration ARN embeds a uuid that
          # cannot be derived from the name.
          arn:                    lc.launch_configuration_arn,
          account_id:             @account_id,
          type:                   "aws_launch_configuration",
          region:                 region,
          imds_tokens_or_disabled: imds_ok?(lc.metadata_options),
          public_ip:              !!lc.associate_public_ip_address,
          ebs_optimized:          !!lc.ebs_optimized,
          detailed_monitoring:    lc.instance_monitoring&.enabled,
          unencrypted_volumes:    lc_unencrypted_volumes(lc),
          user_data_secrets:      secrets_in(decode(lc.user_data)),
          iam_roles:              roles_in_profile(lc.iam_instance_profile),
        }
      end
    end
    rows
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError => e
    @unreadable_regions << { region: region, error: e.message }
    rows
  end

  # The IAM roles reachable through an instance profile, as names.
  #
  # Checkov's graph check follows aws_instance.iam_instance_profile to an
  # aws_iam_instance_profile to an aws_iam_role, so the deployed equivalent is
  # not "a profile is attached" -- an instance profile can exist with no role in
  # it, and an instance carrying one has exactly the credential-less posture the
  # rule is about. Answering with the ROLES makes an empty profile a failure
  # rather than a pass, which asserting on the profile ARN alone would not.
  #
  # A profile is named by ARN on an instance and by ARN *or* name on a launch
  # template or configuration; GetInstanceProfile takes the name, which is the
  # last path segment of the ARN either way.
  #
  # Answers are memoised: an estate typically shares a handful of profiles across
  # many instances, and this is one IAM call per distinct profile rather than one
  # per asset.
  def roles_in_profile(profile_ref)
    name = profile_ref.to_s.split("/").last
    return [] if name.nil? || name.empty?

    @profile_roles ||= {}
    return @profile_roles[name] if @profile_roles.key?(name)

    @profile_roles[name] = fetch_profile_roles(name)
  end

  # NoSuchEntity is answered, not raised: an instance pointing at a profile that
  # no longer exists really does reach nothing, and that is the finding. Every
  # other service error is left to propagate into walk_region, which records the
  # region as unreadable -- "we could not tell" must not be filed as "no roles".
  def fetch_profile_roles(name)
    @aws.iam_client.get_instance_profile(instance_profile_name: name)
        .instance_profile.roles.map(&:role_name)
  rescue ::Aws::Errors::ServiceError => e
    raise unless e.respond_to?(:code) && e.code.to_s == "NoSuchEntity"

    []
  end

  # Checkov accepts either http_tokens == required OR the endpoint disabled
  # outright; both remove the IMDSv1 credential path.
  def imds_ok?(options)
    return false if options.nil?

    options.http_tokens == "required" || options.http_endpoint == "disabled"
  end

  def template_public_ip?(data)
    Array(data.network_interfaces).any? { |ni| ni.associate_public_ip_address }
  end

  def latest_template_data(client, lt)
    resp = client.describe_launch_template_versions(
      launch_template_id: lt.launch_template_id, versions: ["$Latest"],
    )
    resp.launch_template_versions.first&.launch_template_data
  end

  # The volumes ACTUALLY attached, which is a superset of what the Terraform
  # check can see: a volume attached by hand after apply is invisible to HCL.
  def unencrypted_volumes(client, instance)
    ids = instance.block_device_mappings.map { |m| m.ebs&.volume_id }.compact
    return [] if ids.empty?

    client.describe_volumes(volume_ids: ids).volumes
          .reject(&:encrypted).map(&:volume_id)
  end

  def lc_unencrypted_volumes(lc)
    Array(lc.block_device_mappings).reject { |m| m.ebs.nil? || m.ebs.encrypted }
                                   .map(&:device_name)
  end

  def user_data_secrets(client, instance_id)
    attr = client.describe_instance_attribute(instance_id: instance_id, attribute: "userData")
    secrets_in(decode(attr.user_data&.value))
  end

  def decode(blob)
    return "" if blob.to_s.empty?

    require "base64"
    Base64.decode64(blob.to_s)
  rescue ArgumentError
    ""
  end

  def secrets_in(text)
    return [] if text.to_s.empty?

    SECRET_PATTERNS.select { |p| text.match?(p) }.map(&:source)
  end
end
