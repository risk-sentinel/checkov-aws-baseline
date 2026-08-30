# Generated from tools/checkov_catalog.yml (checkov 3.3.16).
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {})['CKV_AWS_8'] || []
applies_to   = %w[aws_instance aws_launch_configuration]

control 'CKV_AWS_8' do
  title 'Instance and launch configuration block storage is encrypted'

  desc <<~DESC
    Checkov asserts this against Terraform. This profile asserts it against the
    instances, launch configurations that actually exist.
  DESC

  desc 'rationale', <<~RATIONALE
    This assertion is STRONGER than the Checkov one it mirrors. Checkov reads the
    block devices declared in HCL; this reads DescribeVolumes, so a volume attached
    later, by hand, outside Terraform is assessed too -- and that is the volume most
    likely to be unencrypted.
  RATIONALE

  desc 'check', <<~CHECK
    Checkov looks for: every declared block device sets encrypted = true.
  CHECK

  desc 'fix', <<~'FIX'
    Terraform (root_block_device.encrypted):
      root_block_device {
      encrypted = true
    }

    Already deployed:
      Snapshot the volume, copy the snapshot with --encrypted, create a volume from
    the encrypted copy, and swap the attachment. A volume cannot be encrypted in
    place while attached.
  FIX

  tag checkov_id:       'CKV_AWS_8'
  tag checkov_category: 'ENCRYPTION'
  tag checkov_version:  '3.3.16'
  tag tf_resources:     %w[aws_instance aws_launch_configuration]
  tag tf_argument:      'root_block_device.encrypted'
  tag tf_docs:          'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#root-block-device'
  tag nist:             ['SC-28', 'SC-28 (1)']
  tag nist_r4:          ['SC-28', 'SC-28 (1)']
  tag cci:              ['CCI-001199', 'CCI-002475']
  tag ksi:              ['KSI-SVC-CER']
  tag severity:         'high'
  tag severity_source:  'assessed'

  assets = aws_compute_assets(regions: scan_regions)

  # Only the asset types this check declares, only what the boundary has, and
  # only those that express the setting at all -- a launch template has no
  # ebs_optimized, and nil must not read as a passing false.
  in_scope = assets.assets_of(applies_to)
                   .reject { |a| exempt.include?(a[:id]) }
                   .reject { |a| a[:unencrypted_volumes].nil? }

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
      subject { asset[:unencrypted_volumes] }
      it { should be_empty }
    end
  end
end
