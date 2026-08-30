# Generated from tools/checkov_catalog.yml (checkov 3.3.16).
#
# The rule id is the identity: file name, control id and `tag checkov_id` all
# carry it, and tools/lint_catalog_drift.py asserts the three agree.

scan_regions = input('scan_regions')
exempt       = (input('exempt_assets') || {})['CKV_AWS_88'] || []
applies_to   = %w[aws_instance aws_launch_template]

control 'CKV_AWS_88' do
  title 'EC2 instance does not have a public IP'

  desc <<~DESC
    Checkov asserts this against Terraform. This profile asserts it against the
    instances, launch templates that actually exist.
  DESC

  desc 'rationale', <<~RATIONALE
    A public IP puts the instance directly on the internet attack surface, rather
    than behind a load balancer or NAT where ingress can be reasoned about.
  RATIONALE

  desc 'check', <<~CHECK
    Checkov looks for: associate_public_ip_address is not true. On a launch template the same question
    is asked of network_interfaces[0].associate_public_ip_address -- the argument
    differs by resource type, the intent does not.
  CHECK

  desc 'fix', <<~'FIX'
    Terraform (associate_public_ip_address):
      associate_public_ip_address = false

    Already deployed:
      Recreate in a private subnet, or remove the public IP association from the
    network interface. A running instance cannot have its public IP detached.
  FIX

  tag checkov_id:       'CKV_AWS_88'
  tag checkov_category: 'NETWORKING'
  tag checkov_version:  '3.3.16'
  tag tf_resources:     %w[aws_instance aws_launch_template]
  tag tf_argument:      'associate_public_ip_address'
  tag tf_docs:          'https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#associate-public-ip-address'
  tag nist:             ['SC-7', 'SC-7 (5)']
  tag nist_r4:          ['SC-7', 'SC-7 (5)']
  tag cci:              ['CCI-001097', 'CCI-002080']
  tag ksi:              ['KSI-CNA-NDS']
  tag severity:         'medium'
  tag severity_source:  'assessed'

  assets = aws_compute_assets(regions: scan_regions)

  # Only the asset types this check declares, only what the boundary has, and
  # only those that express the setting at all -- a launch template has no
  # ebs_optimized, and nil must not read as a passing false.
  in_scope = assets.assets_of(applies_to)
                   .reject { |a| exempt.include?(a[:id]) }
                   .reject { |a| a[:public_ip].nil? }

  applicable = !in_scope.empty?
  # Two statements, not a ternary: InSpec's AST impact collector calls
  # `.value` on the argument node, and a ternary is an IfNode, which has
  # none -- `impact applicable ? 0.5 : 0.0` aborts `check` for the whole
  # profile before a single control runs.
  impact 0.5
  impact 0.0 unless applicable
  only_if("no #{applies_to.join(', ')} in scope expressing this setting") { applicable }

  in_scope.each do |asset|
    describe "#{asset[:type]} #{asset[:id]} (#{asset[:region]})" do
      subject { asset[:public_ip] }
      it { should be false }
    end
  end
end
