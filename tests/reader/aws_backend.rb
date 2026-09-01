# A stand-in for inspec-aws's AwsResourceBase, so libraries/aws_api_assets.rb can
# be LOADED AND RUN outside InSpec.
#
# `cinc-auditor check` and `cinc-auditor json` parse control files without
# evaluating a single control body, so neither can tell whether the reader's Ruby
# is right. Without AWS credentials the only remaining way to find out is to run
# the reader against stubbed SDK clients, which is what tests/reader does.
#
# This file is named aws_backend.rb because the reader says `require "aws_backend"`.
# It lives under tests/ rather than libraries/ so InSpec never loads it.
require "aws-sdk-core"

class FakeConnection
  def sts_client
    @sts_client ||= Aws::STS::Client.new(region: "us-east-1", stub_responses: true).tap do |c|
      c.stub_responses(:get_caller_identity, account: "000000000000")
    end
  end

  # Only reached when a test declines to declare `regions:`. Most tests declare
  # them, so an unexpected call here is a test bug and should say so — unless the
  # test is deliberately exercising region DISCOVERY, which sets the stub.
  class << self
    attr_accessor :compute_client_stub
  end

  def compute_client
    FakeConnection.compute_client_stub ||
      raise("compute_client: a test reached the region walk; declare regions: instead")
  end

  def aws_client(_klass)
    raise "aws_client: the stubbed subclass should have overridden #client"
  end
end

class AwsResourceBase
  attr_reader :opts

  # `name`, `desc` and `example` are InSpec's resource DSL. `name` in particular
  # shadows Class#name, so it forwards when called with no argument — otherwise
  # anything that reads a class's name (including error reporting) breaks.
  def self.name(value = nil)
    value.nil? ? super() : nil
  end

  def self.desc(*); end

  def self.example(*); end

  def initialize(opts = {})
    @opts = opts
    @aws = FakeConnection.new
  end

  def validate_parameters(required: [], allow: [])
    missing = Array(required).reject { |k| @opts.key?(k) }
    raise ArgumentError, "missing #{missing.inspect}" unless missing.empty?
  end

  # inspec-aws swallows AWS errors here and leaves the caller with nil. The reader
  # only uses it for the account id, and matching that behaviour matters: a test
  # that let the error escape would be testing something the profile never does.
  def catch_aws_errors
    yield
  rescue StandardError
    nil
  end
end
