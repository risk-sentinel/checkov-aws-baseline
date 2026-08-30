# Generated from tools/checkov_catalog.yml (checkov 3.3.16).
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {})['CKV_AWS_135'] || []
applies_to   = %w[aws_instance]

control 'CKV_AWS_135' do
  title 'EC2 instances are EBS optimized'

  desc <<~DESC
    Checkov asserts this against Terraform. This profile asserts it against the
    instances that actually exist.
  DESC

  desc 'rationale', <<~RATIONALE
    Dedicated EBS throughput keeps storage traffic off the shared network path, so
    a noisy neighbour cannot starve the instance of disk I/O.
  RATIONALE

  desc 'check', <<~CHECK
    Checkov looks for: ebs_optimized is true.
  CHECK

  desc 'fix', <<~'FIX'
    Terraform (ebs_optimized):
      ebs_optimized = true

    Already deployed:
      Stop the instance, then:
    aws ec2 modify-instance-attribute --instance-id <id> --ebs-optimized
  FIX

  tag checkov_id:       'CKV_AWS_135'
  tag checkov_category: 'GENERAL_SECURITY'
  tag checkov_version:  '3.3.16'
  tag tf_resources:     %w[aws_instance]
  tag tf_argument:      'ebs_optimized'
  tag tf_docs:          'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs_optimized'
  tag nist:             ['SC-5']
  tag nist_r4:          ['SC-5']
  tag cci:              ['CCI-002385']
  tag ksi:              ['KSI-CNA-CAP']
  tag severity:         'low'
  tag severity_source:  'assessed'

  assets = aws_compute_assets(regions: scan_regions)

  # Only the asset types this check declares, only what the boundary has, and
  # only those that express the setting at all -- a launch template has no
  # ebs_optimized, and nil must not read as a passing false.
  in_scope = assets.assets_of(applies_to)
                   .reject { |a| exempt.include?(a[:id]) }
                   .reject { |a| a[:ebs_optimized].nil? }

  applicable = !in_scope.empty?
  # Two statements, not a ternary: InSpec's AST impact collector calls
  # `.value` on the argument node, and a ternary is an IfNode, which has
  # none -- `impact applicable ? 0.3 : 0.0` aborts `check` for the whole
  # profile before a single control runs.
  impact 0.3
  impact 0.0 unless applicable
  only_if("no #{applies_to.join(', ')} in scope expressing this setting") { applicable }

  in_scope.each do |asset|
    describe "#{asset[:type]} #{asset[:id]} (#{asset[:region]})" do
      subject { asset[:ebs_optimized] }
      it { should be true }
    end
  end
end
