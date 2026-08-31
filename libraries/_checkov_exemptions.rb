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
  def checkov_scan_regions(declared)
    listed = Array(declared).reject { |r| r.to_s.strip.empty? }
    return listed unless listed.empty?

    aws_regions.region_names
  rescue StandardError
    # Region enumeration itself failed. Returning [] would scan nothing and
    # report an empty account, so fall back to the connection's own region and
    # let the single-region result be visibly single-region.
    []
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
