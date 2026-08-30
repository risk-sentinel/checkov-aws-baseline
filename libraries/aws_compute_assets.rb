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

  attr_reader :table, :unreadable_regions

  FilterTable.create
             .register_column(:ids,                     field: :id)
             .register_column(:types,                   field: :type)
             .register_column(:regions,                 field: :region)
             .register_column(:imds_tokens_or_disabled, field: :imds_tokens_or_disabled)
             .register_column(:public_ip,               field: :public_ip)
             .register_column(:ebs_optimized,           field: :ebs_optimized)
             .register_column(:detailed_monitoring,     field: :detailed_monitoring)
             .register_column(:unencrypted_volumes,     field: :unencrypted_volumes)
             .register_column(:user_data_secrets,       field: :user_data_secrets)
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
    @table = fetch_data
  end

  def exists?
    !@table.empty?
  end

  # Rows for the given Terraform resource types, as plain hashes.
  #
  # Controls iterate these rather than FilterTable entries: `entries` yields
  # Structs whose shape is FilterTable's business, not this profile's, and a
  # control that reaches into it breaks quietly when that changes. A hash with
  # symbol keys is the contract here.
  def assets_of(types)
    wanted = Array(types)
    @table.select { |row| wanted.include?(row[:type]) }
  end

  def to_s
    "Compute assets across #{@scan_regions.length} region(s)"
  end

  private

  def fetch_data
    @scan_regions = resolve_regions
    @scan_regions.flat_map { |region| walk_region(region) }
  end

  def resolve_regions
    declared = Array(@opts[:regions]).reject { |r| r.to_s.strip.empty? }
    return declared unless declared.empty?

    regions = []
    catch_aws_errors do
      resp = ec2_client.describe_regions
      regions = resp.regions.map(&:region_name)
    end
    # An empty list here means describe_regions itself failed. Returning [] would
    # scan nothing and report an account with no compute -- the exact silence
    # this resource exists to avoid -- so fall back to the configured region.
    regions.empty? ? [ec2_client.config.region].compact : regions
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
            type:                   "aws_instance",
            region:                 region,
            imds_tokens_or_disabled: imds_ok?(i.metadata_options),
            public_ip:              !i.public_ip_address.to_s.empty?,
            ebs_optimized:          !!i.ebs_optimized,
            detailed_monitoring:    i.monitoring&.state == "enabled",
            unencrypted_volumes:    unencrypted_volumes(client, i),
            user_data_secrets:      user_data_secrets(client, i.instance_id),
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
          type:                   "aws_launch_configuration",
          region:                 region,
          imds_tokens_or_disabled: imds_ok?(lc.metadata_options),
          public_ip:              !!lc.associate_public_ip_address,
          ebs_optimized:          !!lc.ebs_optimized,
          detailed_monitoring:    lc.instance_monitoring&.enabled,
          unencrypted_volumes:    lc_unencrypted_volumes(lc),
          user_data_secrets:      secrets_in(decode(lc.user_data)),
        }
      end
    end
    rows
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError => e
    @unreadable_regions << { region: region, error: e.message }
    rows
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
