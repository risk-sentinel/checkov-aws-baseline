# Generated from tools/checkov_catalog.yml (checkov 3.3.16).
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {})['CKV_AWS_46'] || []
applies_to   = %w[aws_instance aws_launch_template aws_launch_configuration]

control 'CKV_AWS_46' do
  title 'No hard-coded secrets in EC2 user data'

  desc <<~DESC
    Checkov asserts this against Terraform. This profile asserts it against the
    instances, launch templates, launch configurations that actually exist.
  DESC

  desc 'rationale', <<~RATIONALE
    User data is readable by anything that can reach the metadata service or call
    DescribeInstanceAttribute, and it is not encrypted at rest.
  RATIONALE

  desc 'check', <<~CHECK
    Checkov looks for: the user_data blob contains no recognisable secret.
  CHECK

  desc 'fix', <<~'FIX'
    Terraform (user_data):
      user_data = file("bootstrap.sh")   # fetch secrets at boot, never embed them

    Already deployed:
      Rotate anything found first, then move the value into Secrets Manager or
    Parameter Store and have user data fetch it at boot with the instance role.
  FIX

  tag checkov_id:       'CKV_AWS_46'
  tag checkov_category: 'SECRETS'
  tag checkov_version:  '3.3.16'
  tag tf_resources:     %w[aws_instance aws_launch_template aws_launch_configuration]
  tag tf_argument:      'user_data'
  tag tf_docs:          'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#user_data'
  tag nist:             ['IA-5 (7)', 'SC-28']
  tag nist_r4:          ['IA-5 (7)', 'SC-28']
  tag cci:              ['CCI-000196', 'CCI-002475']
  tag ksi:              ['KSI-SVC-KMG']
  tag severity:         'high'
  tag severity_source:  'assessed'

  assets = aws_compute_assets(regions: scan_regions)

  # Only the asset types this check declares, only what the boundary has, and
  # only those that express the setting at all -- a launch template has no
  # ebs_optimized, and nil must not read as a passing false.
  in_scope = assets.assets_of(applies_to)
                   .reject { |a| exempt.include?(a[:id]) }
                   .reject { |a| a[:user_data_secrets].nil? }

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
      subject { asset[:user_data_secrets] }
      it { should be_empty }
    end
  end
end
