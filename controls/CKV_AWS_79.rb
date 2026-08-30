# Generated from tools/checkov_catalog.yml (checkov 3.3.16).
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {})['CKV_AWS_79'] || []
applies_to   = %w[aws_instance aws_launch_template aws_launch_configuration]

control 'CKV_AWS_79' do
  title 'Instance Metadata Service Version 1 is not enabled'

  desc <<~DESC
    Checkov asserts this against Terraform. This profile asserts it against the
    instances, launch templates, launch configurations that actually exist.
  DESC

  desc 'rationale', <<~RATIONALE
    IMDSv1 answers an unauthenticated GET, so any server-side request forgery in a
    workload on the instance reaches the credential endpoint. IMDSv2 requires a
    PUT-issued token, which SSRF cannot forge.
  RATIONALE

  desc 'check', <<~CHECK
    Checkov looks for: metadata_options[0].http_tokens is "required" -- or http_endpoint is "disabled", which
    Checkov also accepts, since either removes the IMDSv1 credential path.
  CHECK

  desc 'fix', <<~'FIX'
    Terraform (metadata_options.http_tokens):
      metadata_options {
      http_tokens   = "required"
      http_endpoint = "enabled"
    }

    Already deployed:
      aws ec2 modify-instance-metadata-options --instance-id <id> \
      --http-tokens required --http-endpoint enabled
  FIX

  tag checkov_id:       'CKV_AWS_79'
  tag checkov_category: 'GENERAL_SECURITY'
  tag checkov_version:  '3.3.16'
  tag tf_resources:     %w[aws_instance aws_launch_template aws_launch_configuration]
  tag tf_argument:      'metadata_options.http_tokens'
  tag tf_docs:          'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options'
  tag nist:             ['AC-3', 'AC-6']
  tag nist_r4:          ['AC-3', 'AC-6']
  tag cci:              ['CCI-000213', 'CCI-002233']
  tag ksi:              ['KSI-IAM-MFA']
  tag severity:         'high'
  tag severity_source:  'assessed'

  assets = aws_compute_assets(regions: scan_regions)

  # Only the asset types this check declares, only what the boundary has, and
  # only those that express the setting at all -- a launch template has no
  # ebs_optimized, and nil must not read as a passing false.
  in_scope = assets.assets_of(applies_to)
                   .reject { |a| exempt.include?(a[:id]) }
                   .reject { |a| a[:imds_tokens_or_disabled].nil? }

  applicable = !in_scope.empty?
  # Two statements, not a ternary: InSpec's AST impact collector calls
  # `.value` on the argument node, and a ternary is an IfNode, which has
  # none -- `impact applicable ? 0.7 : 0.0` aborts `check` for the whole
  # profile before a single control runs.
  impact 0.7
  impact 0.0 unless applicable
  only_if("no #{applies_to.join(', ')} in scope expressing this setting") { applicable }

  in_scope.each do |asset|
    describe "#{asset[:type]} #{asset[:id]} (#{asset[:region]})" do
      subject { asset[:imds_tokens_or_disabled] }
      it { should be true }
    end
  end
end
