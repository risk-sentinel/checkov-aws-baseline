require "aws_backend"

# Fetches a resource-based or trust policy per asset and evaluates one named
# predicate over it.
#
# Why this is a reader and not a verb
# -----------------------------------
# Every other shape in this profile compares a FIELD. Seventeen of Checkov's AWS
# checks compare a policy document, where the unit of judgement is a statement
# and the verdict depends on Effect, Principal, Action, Resource and Condition
# together. That is not a matcher, and no `satisfies` verb will ever express it.
#
# The split is deliberate:
#
#   libraries/_policy_document.rb   the predicates. Pure functions of a parsed
#                                   document, no AWS, so tests/policy_document_test.rb
#                                   proves them without credentials.
#   tools/policy_specs.yml          where the document lives, per source. Data.
#   this file                       the region walk, the second call, and the
#                                   failure posture.
#
# How this file is proven without credentials
# -------------------------------------------
# `check` and `json` cover NOTHING in libraries/ -- measured, not assumed: a
# runtime NameError and then a syntax error were each appended to
# _policy_document.rb and both commands still exited 0 saying "Valid: true". So
# two harnesses stand in for the exec nobody can run on a laptop:
#
#   tests/policy_reader_harness.rb      fake SDK clients. Proves this file's own
#                                       logic -- region walk, second call,
#                                       argument resolution, failure posture.
#                                       Runs anywhere.
#   tests/policy_reader_sdk_harness.rb  the REAL aws-sdk with `stub_responses`.
#                                       Proves the assumptions this file makes
#                                       ABOUT the SDK: that a list response is
#                                       pageable, that `to_h` is symbol-keyed,
#                                       that the parameter names in
#                                       policy_specs.yml are the ones the client
#                                       validates, and that the error classes
#                                       are what `absent_when` spells. Needs the
#                                       SDK gems, so it runs in the image only.
#
# Neither is an exec. They prove the reader's mechanics, not its behaviour
# against a real account's data or IAM permissions.
#
# Failure posture -- the whole point of this class
# ------------------------------------------------
# There are four ways to end up with no offending statements, and only one of
# them is a pass:
#
#   the policy is clean                   -> offenders: [], a PASS
#   the asset has no policy at all        -> offenders: [], a PASS, and
#                                            policy_present: false records why
#   the policy could not be READ          -> UNDECIDABLE
#   the policy could not be PARSED        -> UNDECIDABLE
#
# The last two are separated out into `undecidable` and are NOT returned by
# `assets`, so a control's per-asset assertion never sees a nil offender list and
# never mistakes "nobody could look" for "nothing was found". The generated
# control asserts `undecidable` is empty as its own expectation, and keeps
# itself applicable when it is not -- a guard suppressed by only_if is no guard.
#
# An error that means "there is no policy here" is declared per source in
# `absent_when`, by error class name. Everything else -- AccessDenied above all
# -- is undecidable. A denied GetBucketPolicy that read as "no policy" would
# turn the least-visible estate into the cleanest-looking one.
#
# The same rule applies to a document member that is simply NOT THERE. `#{nil}`
# is `""` and `""` is the spelling of "no policy", so a `document:` path naming a
# member the API did not return handed every asset an empty offender list and
# rendered the control 100% compliant having read nothing. An absent member is
# UNDECIDABLE unless the source declares `document_absent_is_no_policy: true`,
# which is for the APIs that really do omit the member (sqs:GetQueueAttributes)
# and for nothing else. See resolve_document.
#
# And a region list that could not be DISCOVERED is not a one-region account:
# see `regions`.
class AwsPolicyDocuments < AwsResourceBase
  name "aws_policy_documents"
  desc "Fetches a policy document per asset and evaluates a named predicate over it."

  example "
    aws_policy_documents(type: 'aws_iam_role', predicate: 'no_wildcard_principal')
  "

  attr_reader :unreadable_regions, :undecidable, :account_id, :predicate, :source

  # A missing SDK gem is NOT an unreadable region and NOT an undecidable asset.
  # The profile cannot perform the test as written at all, so it surfaces as a
  # profile error rather than as a finding, a skip, or an empty result set.
  class MissingGem < StandardError; end

  # An EMPTY `regions:` is dropped before the base class ever sees it.
  #
  # The vendored AwsResourceBase#validate_parameters ends with
  #
  #     raise ArgumentError, "Provided parameter should not be empty" unless
  #       @opts.values.all? { |a| ... !a.empty? }
  #
  # so ANY empty value — including an empty Array — is refused. `scan_regions`
  # defaults to `[]` in inspec.yml, and `[]` is this profile's spelling of
  # "every region enabled for the account", so the generated control passes an
  # empty array on a default run and the constructor would raise before a single
  # policy was read. Dropping the key produces exactly the behaviour the empty
  # array was asking for: `regions` below finds no declared regions and falls
  # through to ec2:DescribeRegions.
  #
  # Reproduced against the vendored code, not inferred; see the commit message.
  # NOTE: libraries/aws_api_assets.rb and libraries/aws_compute_assets.rb take
  # `regions:` the same way and do NOT do this, so the 37 controls that call
  # them raise on a default run. That is a pre-existing defect in another
  # shape's reader and is reported rather than fixed here.
  def initialize(opts = {})
    opts = opts.dup if opts.is_a?(Hash)
    opts.delete(:regions) if opts.is_a?(Hash) && Array(opts[:regions]).reject { |r| r.to_s.strip.empty? }.empty?
    super(opts)
    validate_parameters(required: %i[type predicate], allow: %i[type predicate source regions])
    @type = opts[:type].to_s
    @source = (opts[:source] || opts[:type]).to_s
    @spec = POLICY_SPECS[@source]
    if @spec.nil?
      raise ArgumentError,
            "aws_policy_documents: no policy spec for '#{@source}'. " \
            "Add it to tools/policy_specs.yml and re-run tools/render_policy_specs.py."
    end

    @predicate = opts[:predicate].to_s
    unless PolicyDocument::PREDICATES.include?(@predicate)
      raise ArgumentError,
            "aws_policy_documents: '#{@predicate}' is not an implemented predicate. " \
            "Implemented: #{PolicyDocument::PREDICATES.join(', ')}. " \
            "Add it to libraries/_policy_document.rb rather than mapping onto a near-miss."
    end

    @unreadable_regions = []
    @undecidable = []
    @account_id = fetch_account_id
    @rows = fetch_rows
  end

  # Assets with a verdict, exemptions already removed. Rows are plain hashes
  # with symbol keys; see the note in aws_compute_assets on why not FilterTable.
  #
  # Every row here has an `offenders` array -- possibly empty, never nil. The
  # ones with no verdict are in `undecidable` instead.
  def assets(exempt: [])
    @rows.reject { |row| exempt?(row, exempt) }
  end

  def exists?
    !@rows.empty?
  end

  def to_s
    "#{@type} policy documents (#{@predicate})"
  end

  private

  def exempt?(asset, exemptions)
    Array(exemptions).any? do |rule|
      rule = rule.transform_keys(&:to_s) if rule.respond_to?(:transform_keys)
      next false unless rule.is_a?(Hash)
      next false if rule["type"] && rule["type"] != @type

      Array(rule["arns"]).include?(asset[:arn]) || Array(rule["ids"]).include?(asset[:id])
    end
  end

  # The boundary this evidence is about. Also what makes
  # `no_cross_account_principal_without_condition` mean anything: without it
  # every policy naming its own account's roles reads as cross-account.
  def fetch_account_id
    id = nil
    catch_aws_errors { id = @aws.sts_client.get_caller_identity.account }
    id
  end

  def load_sdk!
    require @spec["gem"] unless Object.const_defined?(@spec["client"])
  rescue LoadError
    raise MissingGem,
          "#{@spec['gem']} is not installed in this runtime, so #{@source} policies cannot " \
          "be read. Add the gem to the auditor image (see tools/image_gems.txt and " \
          "tools/lint_policy_specs.py); do not read this control's result as a pass, a " \
          "failure or a Not Applicable — nothing was assessed."
  end

  # AwsConnection builds its clients for one region, and its `<service>_client`
  # accessors are an explicitly enumerated closed list rather than a
  # method_missing dispatcher. `aws_client(klass)` is the public escape hatch;
  # a region walk needs one client per region, so those are built directly.
  def client_for(region)
    load_sdk!
    klass = Object.const_get(@spec["client"])
    region ? klass.new(region: region) : @aws.aws_client(klass)
  end

  def regions
    return [nil] if @spec["scope"] == "global"

    declared = Array(@opts[:regions]).reject { |r| r.to_s.strip.empty? }
    return declared unless declared.empty?

    found = []
    catch_aws_errors { found = @aws.compute_client.describe_regions.regions.map(&:region_name) }
    return found unless found.empty?

    # Region DISCOVERY failing is not the same as the account having one region.
    #
    # catch_aws_errors swallows a throttle or a transient 5xx on
    # ec2:DescribeRegions and leaves `found` empty, and the fallback then scans
    # ONE region. Without this record the control walks a single region, finds it
    # clean and reports a PASS over an estate it never looked at -- or finds it
    # empty and reports Not Applicable. The row makes the narrowed scope an
    # assertion the generated control already fails on.
    fallback = [@aws.compute_client.config.region].compact
    @unreadable_regions << {
      region: "region discovery",
      error: "ec2:DescribeRegions returned no regions, so only " \
             "#{fallback.empty? ? 'no region at all' : fallback.join(', ')} was scanned — " \
             "this control's scope is not the account. Pass `scan_regions` explicitly, or " \
             "grant ec2:DescribeRegions.",
    }
    fallback
  end

  def fetch_rows
    regions.flat_map { |region| rows_for(region) }
  end

  def rows_for(region)
    api = client_for(region)
    list_items(api).filter_map { |item| row_for(api, item, region) }
  rescue MissingGem
    # Deliberately re-raised: filing this under unreadable_regions would turn
    # "the profile cannot run this test" into "this region had nothing in it".
    raise
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError, ArgumentError => e
    @unreadable_regions << { region: region || "global", error: e.message }
    []
  end

  def list_items(api)
    items = []
    response = api.public_send(@spec["list"], list_args)
    pages = response.respond_to?(:each) ? response : [response]
    pages.each do |page|
      Array(page.public_send(@spec["collection"])).each { |item| items << item.to_h }
    end
    items
  end

  def list_args
    (@spec["list_args"] || {}).each_with_object({}) { |(k, v), out| out[k.to_sym] = v }
  end

  # nil when the asset has no verdict: it is recorded in `undecidable` instead,
  # so the caller's offender list is never nil.
  def row_for(api, item, region)
    # `.to_s` on a null response can itself answer nil (inspec-aws null objects
    # answer everything through method_missing), so the id is interpolated.
    id = "#{dig_path(item, @spec['id'])}"
    row = {
      id: id,
      arn: @spec["arn"] ? "#{dig_path(item, @spec['arn'])}" : nil,
      region: region || "global",
      account_id: @account_id,
      type: @type,
      source: @source,
      predicate: @predicate,
    }

    raw, failure = document_for(api, item, row)
    return undecided(row, failure) if failure

    row[:policy_present] = !raw.to_s.strip.empty?

    # The rescue spans the EVALUATION as well as the parse. A shape the
    # predicates do not expect -- `"Statement": "nonsense"`, a Principal that is
    # a number -- is raised by policy_document_statements/_principals/_flatten,
    # which run here and not in policy_document_parse. With the rescue around
    # the parse alone, one malformed document in one asset escaped the
    # constructor and errored the WHOLE control, taking every other asset's
    # verdict with it -- the opposite of the per-asset undecidable this class
    # documents. Reproduced before it was fixed; asserted in
    # tests/policy_reader_harness.rb.
    begin
      document = PolicyDocument.policy_document_parse(raw)
      row[:offenders] = if document.nil?
                          []
                        else
                          PolicyDocument.policy_document_offenders(
                            document, @predicate, account_id: @account_id
                          )
                        end
    rescue PolicyDocument::ParseError => e
      return undecided(row, "policy document did not parse: #{e.message}")
    end

    row
  end

  def undecided(row, reason)
    @undecidable << "#{@type} #{row[:id]} (#{row[:region]}): #{reason}"
    nil
  end

  # [raw document, failure reason]. A document already on the list item needs no
  # second call at all -- iam:ListRoles returns the trust policy inline.
  def document_for(api, item, row)
    if @spec["document"]
      return resolve_document(dig_path(item, @spec["document"]), @spec["document"], @spec["list"])
    end

    spec_fetch = @spec["fetch"]
    if spec_fetch.nil?
      return [nil, "the policy spec for #{@source} declares neither `document` nor `fetch`"]
    end

    call_fetch(api, item, row, spec_fetch)
  end

  # An ABSENT document member is not "there is no policy here".
  #
  # `#{nil}` is `""`, and `""` is the spelling of "no policy", which is a PASS.
  # So a `document:` path that names a member the API did not return -- a typo, a
  # renamed member, a shape that changed under us -- used to hand every asset an
  # empty offender list and render the control 100% compliant while assessing
  # nothing. iam:ListRoles ALWAYS returns AssumeRolePolicyDocument, so its
  # absence means the read was wrong, not that the role trusts nobody.
  #
  # Where a member really is optional and its absence really does mean "no
  # policy" -- sqs:GetQueueAttributes omits `Policy` entirely on a queue that has
  # none -- the source says so with `document_absent_is_no_policy: true`. It has
  # to be declared, because the default has to be the one that cannot pass by
  # accident. An EMPTY member (`""`) is a present answer and still passes.
  def resolve_document(value, path, call)
    return ["#{value}", nil] unless value.nil?
    return ["", nil] if @spec["document_absent_is_no_policy"]

    [nil,
     "#{call} returned no `#{path}` member, so no policy was read. That is not " \
     "evidence of an absent policy: check the `document` path in tools/policy_specs.yml " \
     "for #{@source}, or declare `document_absent_is_no_policy: true` if this API really " \
     "omits the member when there is no policy."]
  end

  def call_fetch(api, item, row, spec_fetch)
    response = api.public_send(spec_fetch["call"], fetch_args(spec_fetch["args"], item, row))
    resolve_document(dig_path(response.to_h, spec_fetch["document"]),
                     spec_fetch["document"], spec_fetch["call"])
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError => e
    error = e.class.name.to_s.split("::").last
    # A declared "there is no policy here" error is a real answer and a passing
    # one. Everything else -- AccessDenied above all -- is undecidable, because
    # a denied read that counted as "no policy" would make the least-visible
    # estate look like the cleanest one.
    return ["", nil] if Array(spec_fetch["absent_when"]).include?(error)

    [nil, "#{spec_fetch['call']} failed: #{error}: #{e.message}"]
  end

  def fetch_args(args, item, row)
    (args || {}).each_with_object({}) do |(key, value), out|
      out[key.to_sym] = value.is_a?(Hash) ? resolved_arg(value, item, row) : value
    end
  end

  def resolved_arg(reference, item, row)
    reference = reference.transform_keys(&:to_s)
    if reference.key?("from")
      source_key = reference["from"].to_s
      unless %w[id arn].include?(source_key)
        raise ArgumentError, "policy spec #{@source}: `from: #{source_key}` — only id and arn"
      end

      row[source_key.to_sym]
    elsif reference.key?("from_item")
      dig_path(item, reference["from_item"])
    else
      raise ArgumentError,
            "policy spec #{@source}: an argument object must carry `from` or `from_item`"
    end
  end

  # "policy_version.document" -> item[:policy_version][:document], tolerating a
  # missing level. A member the API did not return is nil, and nil reaches the
  # parser as "no policy", which is a stated state rather than a silent one.
  def dig_path(item, path)
    path.to_s.split(".").reduce(item) do |node, key|
      break nil unless node.respond_to?(:[])

      node.is_a?(Hash) ? (node[key.to_sym] || node[key]) : nil
    end
  end
end
