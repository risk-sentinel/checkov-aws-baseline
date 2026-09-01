# Exemption matching for controls that read a stock inspec-aws resource.
#
# The custom readers in this profile carry an ARN on every row and match
# exemptions themselves. A stock inspec-aws resource hands back an id and
# nothing else, so the matching happens here instead -- one implementation, so
# the two paths cannot drift into answering the same declaration differently.
#
# An exemption is scoped by resource TYPE and matched on ARN where one is
# available, falling back to id:
#
#   exempt_assets:
#     CKV_AWS_18:
#       - type: aws_s3_bucket
#         arns: [arn:aws:s3:::example-bucket]
#         ids:  [example-bucket]
#
# Loaded into Inspec::Rule, so it is available at CONTROL scope. Calling it from
# inside a `subject`/`it` block raises NameError at exec -- the example is not
# the control -- which is what tools/lint_resource_scope.py checks for.
module CheckovScope
  # The regions a control should walk.
  #
  # Stock inspec-aws resources take `aws_region:` and otherwise read whatever
  # region the connection was built with. A control that does not pass one
  # assesses exactly one region and reports every other region's resources as
  # absent — which renders Not Applicable, a claim that the rule does not apply
  # here rather than an admission that nobody looked.
  #
  # An empty `scan_regions` input means "every enabled region", which is what
  # aws_regions answers. Resolved once at CONTROL scope and closed over: calling
  # this inside a describe block would defer it into the example, where the
  # helper does not exist.
  #
  # This method must never hand back an empty list in silence. A stock control's
  # whole population comes from `checkov_scan_regions(...).flat_map`, so [] means
  # `found` is empty, `problems` is empty, `applicable` is false, and the control
  # renders Not Applicable having assessed nothing -- across every region-walking
  # control at once. That was the previous behaviour on BOTH failure paths:
  #
  #   * aws_regions swallows its own error. AwsRegions#fetch_data wraps
  #     describe_regions in catch_aws_errors and then `return [] if !@regions`,
  #     so a denied, throttled or credential-less ec2:DescribeRegions produces an
  #     empty table and NO exception -- the rescue below never even fired.
  #   * When it does raise (a failed resource whose @table was never assigned),
  #     the rescue returned [] as well, despite a comment promising a fallback to
  #     the connection's own region that was never written.
  #
  # So: fall back to the connection's region, as aws_compute_assets#resolve_regions
  # and aws_api_assets#regions already do, AND record why. The control concatenates
  # `checkov_region_problems` into its `problems` list, which both keeps it
  # applicable and fails it with the reason, so a partial scan can never be read
  # as an account-wide pass.
  def checkov_scan_regions(declared)
    @checkov_region_problems = []

    listed = Array(declared).reject { |r| r.to_s.strip.empty? }
    return listed unless listed.empty?

    discovered = begin
                   Array(aws_regions.region_names).reject { |r| r.to_s.strip.empty? }
                 rescue StandardError => e
                   @checkov_region_problems << "listing the account's regions raised "\
                                               "#{e.class}: #{e.message}"
                   []
                 end
    return discovered unless discovered.empty?

    fallback = checkov_connection_region
    @checkov_region_problems <<
      "the account's regions could not be listed — ec2:DescribeRegions returned nothing, "\
      "and inspec-aws swallows the reason. #{fallback ? "Only #{fallback} was scanned" : 'NO region was scanned'}, "\
      "so NOTHING outside it was assessed. Do not read this control's result as an "\
      "account-wide pass: grant ec2:DescribeRegions, or name the regions explicitly in "\
      "the scan_regions input, and run it again"
    Array(fallback)
  end

  # Why the region list is not the account's, or [] when it is. Read by every
  # region-walking control and folded into the same `problems` list the
  # enumeration failures use.
  def checkov_region_problems
    @checkov_region_problems ||= []
  end

  # The region the SDK would resolve on its own — the same answer
  # `Aws::EC2::Client.new.config.region` gives, which is what
  # aws_compute_assets#resolve_regions falls back to.
  #
  # Read from the environment and the shared config rather than by building a
  # client, because CONSTRUCTING an Aws client also resolves CREDENTIALS: on a
  # runner with none it probes the instance-metadata endpoint at 169.254.169.254
  # and blocks until that times out. This runs once per control on the failure
  # path, so a broken credential chain would have added that stall to every one
  # of them. This is the SDK's own region chain, and it touches no network.
  def checkov_connection_region
    from_env = ENV["AWS_REGION"] || ENV["AMAZON_REGION"] || ENV["AWS_DEFAULT_REGION"]
    return from_env unless from_env.to_s.strip.empty?

    shared = ::Aws.shared_config.region if defined?(::Aws)
    shared unless shared.to_s.strip.empty?
  rescue StandardError
    nil
  end
end

::Inspec::Rule.include(CheckovScope)

module CheckovExemptions
  # An asset is exempt when a rule names its type and matches either identifier.
  # An ARN suffix match is deliberate: an S3 ARN has no account or region, so
  # `arn:aws:s3:::name` and the bare name are the same claim.
  def checkov_exempt?(id:, type:, rules:)
    Array(rules).any? do |rule|
      rule = rule.transform_keys(&:to_s) if rule.respond_to?(:transform_keys)
      next false unless rule.is_a?(Hash)
      next false if rule['type'] && rule['type'] != type

      Array(rule['ids']).include?(id) ||
        Array(rule['arns']).any? { |arn| arn.to_s == id || arn.to_s.end_with?(":#{id}", "/#{id}", ":::#{id}") }
    end
  end
end

::Inspec::Rule.include(CheckovExemptions)
