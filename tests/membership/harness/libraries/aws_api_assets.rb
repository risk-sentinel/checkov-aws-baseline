# Stand-in for libraries/aws_api_assets.rb. Same surface -- `assets`,
# `assets(exempt:)`, `unreadable_regions` -- fabricated rows, chosen by
# $SCENARIO. It shadows the real reader by name, so the generated control under
# test is loaded and run UNMODIFIED.
#
# Deliberately not a mock framework and deliberately not clever: the thing being
# tested is the control body's join arithmetic and its guards, so the rows have
# to be plain data a reader can check by eye against the table in the README.
#
# `exempt:` is accepted and ignored. Exemption filtering belongs to the real
# reader and is not what these scenarios are about; honouring it here would only
# let a bug in the stub look like a bug in the control.
class AwsApiAssets < Inspec.resource(1)
  name "aws_api_assets"
  attr_reader :unreadable_regions
  VOL = "arn:aws:ec2:us-east-1:111122223333:volume/vol-covered".freeze
  def initialize(opts = {})
    @type = opts[:type].to_s
    @unreadable_regions = []
    s = ENV["SCENARIO"]
    @rows =
      case [@type, s]
      when ["aws_ebs_volume", "mixed"], ["aws_ebs_volume", "empty_right"],
           ["aws_ebs_volume", "broken_keys"], ["aws_ebs_volume", "bad_filter"]
        [{ id: "vol-covered", region: "us-east-1", account_id: "111122223333" },
         { id: "vol-orphan",  region: "us-east-1", account_id: "111122223333" }]
      when ["aws_ebs_volume", "unkeyable"]
        [{ id: "", region: "us-east-1", account_id: "111122223333" }]
      when ["aws_backup_protected_resource", "mixed"]
        [{ id: VOL, region: "us-east-1", resource_type: "EBS" }]
      when ["aws_backup_protected_resource", "broken_keys"]
        [{ id: "vol-covered", region: "us-west-2", resource_type: "EBS" }]
      when ["aws_backup_protected_resource", "bad_filter"]
        [{ id: VOL, region: "us-east-1", resource_type: "EBSVolume" }]
      when ["aws_backup_protected_resource", "unread_right"]
        @unreadable_regions = [{ region: "us-east-1", error: "AccessDenied" }]
        []
      else
        []
      end
  end
  def assets(exempt: []) = @rows
end
