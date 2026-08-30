# Boundary inventory. Reports what the scan found, which account it landed in,
# and where it could not look.
#
# No compliance tags on purpose: this control asserts nothing about the estate's
# posture, it establishes what the rest of the profile was able to see. The tag
# lint skips a control with no `tag nist:` for exactly this shape.

scan_regions   = input('scan_regions')
declared_acct  = input('aws_account_id').to_s

control 'checkov-aws-inventory' do
  impact 0.0
  title 'Boundary inventory and scan target'
  desc 'Establishes the target this evidence is about -- account, regions, and '\
       'the assets found -- so a Not Applicable elsewhere in this profile reads '\
       'as "the boundary does not use this" rather than "nobody looked".'
  tag layer: 'inventory'

  assets = aws_compute_assets(regions: scan_regions)

  describe 'Scan target' do
    it 'resolved the account being scanned' do
      expect(assets.account_id.to_s).not_to be_empty,
        'sts:GetCallerIdentity returned nothing — every result would be unattributable'
    end

    # Evidence filed against the wrong account is worse than no evidence, and the
    # two are indistinguishable after the fact. Only asserted when declared.
    it "matches the declared boundary account" do
      skip 'aws_account_id not set in inputs' if declared_acct.empty?
      expect(assets.account_id.to_s).to eq(declared_acct)
    end
  end

  describe 'Region coverage' do
    it 'read every region it attempted' do
      failed = assets.unreadable_regions.map { |r| "#{r[:region]}: #{r[:error]}" }
      expect(failed).to be_empty, "regions that could not be read: #{failed.join('; ')}"
    end
  end

  %w[aws_instance aws_launch_template aws_launch_configuration].each do |type|
    found = assets.assets_of(type)
    describe "#{type} inventory" do
      it "found #{found.length} asset(s)" do
        expect(found.length).to be >= 0
      end
    end
  end
end
