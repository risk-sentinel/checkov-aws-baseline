require "aws_backend"

# A declarative reader for resource types inspec-aws does not ship.
#
# Why this exists
# ---------------
# Checkov covers 217 AWS resource types. inspec-aws ships resources for 58 of
# them. Writing a bespoke InSpec resource for each of the rest would be ~130
# near-identical files whose only real content is "which client, which list call,
# which field" -- three facts that belong in data, not in Ruby.
#
# So the enumeration is described in tools/api_specs.yml, baked into
# libraries/_api_specs.rb, and read by this one resource. Adding a resource type
# becomes four lines of YAML that the linter can check, rather than a new library
# nobody reviews.
#
# What it deliberately does not do
# --------------------------------
# It does not interpret. It enumerates assets and extracts the named fields, and
# the control does the asserting. Anything needing real logic -- a policy
# document, a relationship between two resources -- is not expressible here and
# should not be forced into it.
#
# Two-step types
# --------------
# Many AWS list calls cannot enumerate an account at all: GetStages refuses to
# run without a restApiId, ListFunctionUrlConfigs without a FunctionName. The
# vendored pack signals this with `required:` / `require_any_of:`, and until now
# such a type was simply unmappable.
#
# A spec that declares `parent:` is read in two steps: a no-argument list call
# enumerates parent ids, then the child list call runs once per parent id, and
# the children flatten into ordinary rows that additionally carry `parent_id`.
# Both legs paginate. See tools/api_specs.yml for the schema and the sentinels.
#
# Cost: one child call per parent per region, on top of the parent walk. A
# 200-parent account is 201 calls per region, and nothing here bounds that --
# `regions:` is the only lever. Do not add a spec whose parent population is
# unbounded (ECS task definition REVISIONS are the known example) without
# reading tools/proposals/parentchild.yml's call_volume notes first.
#
# Failure posture
# ---------------
# A region that cannot be read is recorded in `unreadable_regions`, never
# flattened into "found nothing": absent renders as Not Applicable, which claims
# the rule does not apply here, and an unread region has not earned that. A
# service the account has never used answers with an empty list and that is a
# real answer; a denied call is not.
#
# Recording is only half of it. InSpec's only_if does not just mark a control
# skipped -- Inspec::Rule.prepare_checks DISCARDS every check and substitutes a
# no-op -- so an assertion written above the only_if never runs when the control
# turns out to be inapplicable. Every one of these three signals must therefore
# ALSO make the control applicable, and the generated control does that:
# `unreadable_regions`, `parent_failures`, and the rows themselves.
#
# The two-step shape adds a second way to lose data quietly, and it is worse: a
# child call that fails takes a whole SUBTREE with it, and returning [] for that
# parent is indistinguishable from "this parent has no children". Those failures
# are recorded per parent in `parent_failures`, which the generated control
# asserts on AND counts towards applicability, so only_if cannot suppress it.
#
# `parents_seen` exists for the other half of that distinction. Zero rows because
# the account has no parents at all is a truthful Not Applicable; zero rows with
# parents present is not the same claim, and a control that cannot tell them
# apart reports both as "does not apply here". It counts every parent the list
# call returned, including one whose id came back blank -- a count taken after
# that filter answers a different question while looking like this one.
class AwsApiAssets < AwsResourceBase
  name "aws_api_assets"
  desc "Enumerates a resource type described in the baked API spec table."

  example "
    describe aws_api_assets(type: 'aws_lambda_function') do
      it { should exist }
    end
  "

  attr_reader :account_id, :parent_failures, :parents_seen

  # Regions that could not be read -- INCLUDING the case where this resource
  # never got as far as walking one.
  #
  # catch_aws_errors raises Inspec::Exceptions::ResourceFailed on a 403, and
  # Inspec::Resource#supersuper_initialize rescues it around the whole
  # constructor. So a denied sts:GetCallerIdentity or ec2:DescribeRegions hands
  # the control a live object with @rows never assigned. Answering [] here would
  # make `applicable` false and render the control Not Applicable having assessed
  # nothing -- the exact failure this reader exists to prevent -- and answering
  # nil from `assets` below would raise NoMethodError inside the control body,
  # which reports as a source-code error rather than as "the read failed".
  def unreadable_regions
    failure = %i[resource_failed? failed_resource? resource_skipped?].find do |predicate|
      respond_to?(predicate) && public_send(predicate)
    end
    return Array(@unreadable_regions) unless failure

    Array(@unreadable_regions) + [{
      region: "(every region)",
      error: "#{@type} could not be read at all (#{failure}): "\
             "#{(respond_to?(:resource_exception_message) && resource_exception_message) || 'the AWS call did not succeed'}. "\
             "NOTHING was assessed here",
    }]
  end

  def initialize(opts = {})
    super(opts)
    validate_parameters(required: %i[type], allow: %i[type regions])
    @type = opts[:type].to_s
    @spec = API_SPECS[@type]
    raise ArgumentError, "aws_api_assets: no spec for #{@type}. Add it to tools/api_specs.yml." if @spec.nil?

    @unreadable_regions = []
    # Empty and 0 for a one-step spec, which is what the generated control expects:
    # the parent assertions render only for a spec that declares `parent:`.
    @parent_failures = []
    @parents_seen = 0
    @account_id = fetch_account_id
    @rows = fetch_rows
  end

  # Rows as plain hashes with symbol keys, exemptions already removed. Controls
  # iterate these; see the note in aws_compute_assets on why not FilterTable.
  def assets(exempt: [])
    @rows.reject { |row| exempt?(row, exempt) }
  end

  def exists?
    !@rows.empty?
  end

  def to_s
    "#{@type} assets"
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

  def fetch_account_id
    id = nil
    catch_aws_errors { id = @aws.sts_client.get_caller_identity.account }
    id
  end

  # A missing SDK gem is NOT an unreadable region. The control cannot perform the
  # test as written at all, so it must surface as a profile error rather than as
  # a finding, a skip, or an empty result set. Raised, deliberately uncaught by
  # the region rescue below.
  class MissingGem < StandardError; end

  # A spec that names something the API response does not have is a SPEC bug, not
  # an account condition. Absorbing it into unreadable_regions or into an empty
  # row set would turn "this spec is wrong" into "this rule does not apply here".
  # Raised, and deliberately re-raised past every rescue below.
  class SpecError < StandardError; end
  class CollectionPathError < StandardError; end

  def load_sdk!
    require @spec["gem"] unless Object.const_defined?(@spec["client"])
  rescue LoadError
    raise MissingGem,
          "#{@spec['gem']} is not installed in this runtime, so #{@type} cannot be " \
          "enumerated. Add the gem to the auditor image (see tools/image_gems.txt " \
          "and tools/lint_api_specs.py); do not read this control's result as a pass, " \
          "a failure or a Not Applicable — nothing was assessed."
  end

  def client
    load_sdk!
    @aws.aws_client(Object.const_get(@spec["client"]))
  end

  # AwsConnection builds its clients for one region. A region walk needs one per
  # region, so the client class is instantiated directly rather than through the
  # connection's cached accessor.
  def regional_client(region)
    load_sdk!
    Object.const_get(@spec["client"]).new(region: region)
  end

  def regions
    return [nil] if @spec["scope"] == "global"

    declared = Array(@opts[:regions]).reject { |r| r.to_s.strip.empty? }
    return declared unless declared.empty?

    found = discovered_regions
    found.empty? ? [@aws.compute_client.config.region].compact : found
  end

  # Region discovery that FAILED is not "the account has one region".
  #
  # This was written as `catch_aws_errors { found = ... }`, and catch_aws_errors
  # only raises for a permissions error: every other ServiceError (throttling,
  # OptInRequired, a 5xx) is logged, swallowed, and answered with nil. `found`
  # then stayed empty and the fallback narrowed the entire profile to the single
  # target region — every other region enumerated nothing, reported nothing, and
  # rendered Not Applicable. inspec.yml says exactly why that is unacceptable:
  # "a single-region sweep reports absent for a workload that exists elsewhere,
  # and absent renders as does not apply here, which is a claim."
  #
  # The fallback stays — one region read is better than none — but the failure is
  # recorded, which makes the control applicable and fails it. Nothing here can
  # tell how many regions it did not visit, so the only honest answer is to say
  # the sweep was not the sweep it claims to be.
  def discovered_regions
    @aws.compute_client.describe_regions.regions.map(&:region_name)
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError => e
    @unreadable_regions << {
      region: "(region discovery)",
      error: "#{e.class.name.split('::').last}: #{e.message}. Falling back to the " \
             "target region alone — every other region enabled for this account was " \
             "NOT enumerated, so nothing below is an account-wide answer.",
    }
    []
  end

  def fetch_rows
    regions.flat_map { |region| rows_for(region) }
  end

  def rows_for(region)
    api = region ? regional_client(region) : client
    @spec["parent"] ? collect_two_step(api, region) : collect(api, region)
  rescue MissingGem, SpecError, CollectionPathError
    # Deliberately re-raised: filing these under unreadable_regions would turn
    # "the profile cannot run this test" into "this region had nothing in it".
    raise
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError, ArgumentError => e
    @unreadable_regions << { region: region || "global", error: e.message }
    []
  end

  def collect(api, region)
    rows = []
    each_page(api.public_send(@spec["list"])) do |page|
      items_from(page, @spec["collection"]).each { |item| rows << row_for(hash_of(item), region) }
    end
    rows
  end

  # Enumerate parents, then call the child list once per parent id.
  #
  # A failure on the PARENT leg is a failure for the whole region and propagates
  # to rows_for's rescue, which is correct: nothing was enumerated. A failure on a
  # CHILD leg is one lost subtree, and is handled in children_of.
  def collect_two_step(api, region)
    parent = @spec["parent"]
    ids = []
    each_page(api.public_send(parent["list"])) do |page|
      items_from(page, parent["collection"]).each do |item|
        # Counted BEFORE the usability test. The census in the control's skip
        # message answers "did the account have any parents at all", and a count
        # taken after the filter answers a different question while looking like
        # that one.
        @parents_seen += 1
        id = parent_id_of(item, parent)
        next if record_unusable_parent(region, parent, id)

        ids << id
      end
    end
    ids.flat_map { |parent_id| children_of(api, region, parent_id) }
  end

  # A parent whose id member came back blank is a LOST SUBTREE and a silent one:
  # its children are never requested at all, so the region reads as empty. Left
  # as a bare `unless`, a `parent.id` naming the wrong member drops every parent,
  # enumerates zero rows and renders Not Applicable — the enumeration is broken
  # and the result says the rule does not apply here. It is recorded as a failure
  # instead, which the generated control asserts on and counts towards
  # applicability. Same guard as `unusable` in the stock control shape.
  def record_unusable_parent(region, parent, id)
    return false unless "#{id}".strip.empty?

    @parent_failures << { region: region || "global", parent_id: "(blank)",
                          error: "SpecError: parent.id '#{parent['id']}' yielded a blank id, " \
                                 "so this parent's children were never requested" }
    true
  end

  # `parent.id: _self` — the parent collection is a list of SCALARS (ARNs, names,
  # detector ids), so the item itself is the argument. Six of the drafted specs
  # are this shape, which is why it is a declared sentinel rather than a hack.
  def parent_id_of(item, parent)
    return item if parent["id"] == "_self"

    hash_of(item)[parent["id"].to_sym]
  end

  # One parent's children. A child call that raises takes a whole subtree with
  # it, and returning [] would make that indistinguishable from a parent that
  # legitimately has no children — the failure is recorded per parent instead,
  # and the generated control asserts the list is empty.
  #
  # Note what is NOT special-cased here: "the thing is not configured" errors
  # (S3's NoSuchPublicAccessBlockConfiguration, Route 53's DNSSECNotFound) are
  # recorded as failures like anything else. They are loud and self-describing
  # rather than silent, which is the safe direction; making them yield a row of
  # nils instead needs a declared `absent_errors:` AND a matching presence verb,
  # because a row of nils is filtered straight back out by a value check's nil
  # filter and renders Not Applicable. See tools/api_specs.yml.
  def children_of(api, region, parent_id)
    rows = []
    params = { @spec["arg"].to_sym => parent_id }
    each_page(api.public_send(@spec["list"], params)) do |page|
      items_from(page, @spec["collection"]).each do |item|
        rows << row_for(hash_of(item), region, parent_id)
      end
    end
    rows
  rescue MissingGem, SpecError, CollectionPathError
    raise
  rescue ::Aws::Errors::ServiceError, ::Seahorse::Client::NetworkingError, ArgumentError => e
    @parent_failures << { region: region || "global", parent_id: "#{parent_id}",
                          error: "#{e.class.name.split('::').last}: #{e.message}" }
    []
  end

  # Every page of a response, for a pageable operation and a non-pageable one
  # alike. aws-sdk-core wraps both in PageableResponse (a NullPager for the
  # latter), so `each` yields exactly one page when there is no paginator —
  # which is why both legs can use the same call and neither stops at page one.
  def each_page(response)
    pages = response.respond_to?(:each) ? response : [response]
    pages.each { |page| yield page }
  end

  # The items held by one named response member.
  #
  # `Array(value)` is wrong here and wrong SILENTLY. An Aws::Structure is a Struct
  # subclass, so Array() calls to_a and returns its MEMBER VALUES: one EKS cluster
  # comes back as 28 rows of garbage. Eleven of the drafted two-step specs point
  # `collection` at a single structure, so the three shapes are branched
  # explicitly instead of being left to Array()'s coercion.
  #
  # A member name the response does not have raises NoMethodError, which is not
  # rescued anywhere: a typo must abort the profile, not yield zero rows.
  # The items in a page, addressed by a member name or a DOTTED PATH.
  #
  # A single `page.public_send(member)` cannot reach a nested collection, and
  # several services only have a nested one: CloudFront's ListDistributions puts
  # its items under DistributionList.Items, so `collection: distribution_list.items`.
  #
  # A step that is nil stops the walk and yields no rows -- an optional structure
  # the API omitted is a real, empty answer. A step the response has no member
  # for is NOT: that is the spec naming something that does not exist, and it
  # raises rather than enumerating nothing, because enumerating nothing renders
  # Not Applicable and reads as "this rule does not apply here".
  def items_from(page, member)
    value = member == "_response" ? response_data(page) : walk_path(page, member)
    return [] if value.nil?
    return value if value.is_a?(Array)

    [value]
  end

  def walk_path(page, member)
    member.to_s.split(".").reduce(page) do |node, key|
      break nil if node.nil?
      unless node.respond_to?(key)
        raise CollectionPathError,
              "#{@type}: `collection: #{member}` — #{node.class} has no member " \
              "`#{key}`. Nothing was enumerated, so do not read this control's " \
              "result as a pass or a Not Applicable; fix the spec in tools/api_specs.yml."
      end

      node.public_send(key)
    end
  end

  # `collection: _response` — the child response has no wrapper member at all and
  # the fields are top-level members of the response itself (GuardDuty GetDetector,
  # CloudTrail GetEventDataStore).
  def response_data(page)
    page.respond_to?(:data) ? page.data : page
  end

  def hash_of(item)
    return item if item.is_a?(Hash)
    # `nil.respond_to?(:to_h)` is true and `nil.to_h` is `{}`, so a nil inside a
    # collection would pass the duck-type test below and become a row whose every
    # field is nil — which the control's nil filter removes again, leaving Not
    # Applicable. Refused explicitly rather than left to the duck type.
    if item.nil?
      raise SpecError,
            "#{@type}: `collection` yielded a nil item. A response member holding nils " \
            "cannot be read as assets; the row would carry no fields and disappear into " \
            "Not Applicable."
    end
    unless item.respond_to?(:to_h)
      raise SpecError,
            "#{@type}: `collection` names a member holding #{item.class} values, which " \
            "carry no fields to read. A list of scalars can only be a PARENT collection " \
            "(parent.id: _self)."
    end

    item.to_h
  end

  def row_for(item, region, parent_id = nil)
    # `id: _parent` — the child carries no identifier of its own (an S3 public
    # access block describes a bucket without ever naming it), so the parent id is
    # the row's identity. Interpolated rather than .to_s: to_s can answer nil for a
    # null response, and a nil id crashes the exemption match rather than failing.
    raw = @spec["id"] == "_parent" ? parent_id : item[@spec["id"].to_sym]
    row = { id: "#{raw}", region: region || "global",
            account_id: @account_id, type: @type }
    row[:parent_id] = "#{parent_id}" unless parent_id.nil?
    row[:arn] = item[@spec["arn"].to_sym] if @spec["arn"]
    (@spec["fields"] || {}).each { |name, path| row[name.to_sym] = dig_path(item, path) }
    row
  end

  # "tracing_config.mode" -> item[:tracing_config][:mode], tolerating a missing
  # level. A field the API did not return is nil, and a control skips a nil
  # rather than reading it as a passing false.
  #
  # The symbol/string fallback must test key PRESENCE, not truthiness. Written as
  # `node[key.to_sym] || node[key]` it returned nil for every field whose value
  # was legitimately `false` — which is precisely the failing population of every
  # `satisfies: equals, value: true` mapping. Those rows were then removed by the
  # control's nil filter and the check rendered Not Applicable: the failures
  # reported as "this rule does not apply here". Found by tests/reader.
  def dig_path(item, path)
    path.to_s.split(".").reduce(item) do |node, key|
      break nil unless node.is_a?(Hash)

      node.key?(key.to_sym) ? node[key.to_sym] : node[key]
    end
  end
end
