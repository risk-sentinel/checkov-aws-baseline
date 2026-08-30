# Boundary inventory. Reports what the scan found and where it could not look.
#
# This control carries no compliance tags on purpose: it asserts nothing about
# the estate's posture, it establishes what the rest of the profile was able to
# see. The tag lint exempts a control with no `tag nist:` for exactly this shape.

scan_regions = input('scan_regions')

control 'checkov-aws-inventory' do
  impact 0.0
  title 'Compute assets discovered in the boundary'
  desc 'Enumerates the deployed assets the Checkov EC2-family checks apply to, '\
       'so a Not Applicable elsewhere in this profile can be read as "the '\
       'boundary does not use this" rather than "nobody looked".'
  tag layer: 'inventory'

  assets = aws_compute_assets(regions: scan_regions)

  describe 'Region coverage' do
    it 'read every region it attempted' do
      failed = assets.unreadable_regions.map { |r| "#{r[:region]}: #{r[:error]}" }
      expect(failed).to be_empty, "regions that could not be read: #{failed.join('; ')}"
    end
  end

  %w[aws_instance aws_launch_template aws_launch_configuration].each do |type|
    found = assets.where(type: type).ids
    describe "#{type} inventory" do
      it "found #{found.length} asset(s)" do
        expect(found.length).to be >= 0
      end
    end
  end
end
