# Key normalisation for the "is every X covered by some Y" control shape.
#
# Why this is a shape and not a matcher
# -------------------------------------
# Every other reader in this profile answers a question about ONE asset: read a
# field, compare it to a value. A coverage question is different -- the answer
# for an EBS volume lives in a completely separate enumeration (AWS Backup's
# protected resources), and there is no per-volume call that returns it. So the
# control has to evaluate two populations and match them by key, which is the
# one thing the stock, api, custom and singleton shapes all cannot do.
#
# THE FAILURE MODE THIS FILE EXISTS TO PREVENT
# --------------------------------------------
# The two sides usually speak different identifier spaces. ec2 DescribeVolumes
# returns `vol-0abc...` and has NO Arn member at all -- confirmed against the
# aws-sdk-ec2 shape, `Aws::EC2::Types::Volume` has no `arn`. AWS Backup returns
# `arn:aws:ec2:us-east-1:111122223333:volume/vol-0abc...`. Comparing those two
# strings directly matches nothing, so EVERY volume reports as unprotected: a
# 100% finding that looks exactly like a real one and is invisible to `check`,
# to `json`, and to anyone reading the results.
#
# Inverting the mistake is worse. If the join were written so that a
# non-matching key counted as covered, every volume would pass and the control
# could not fail at all -- which, per this profile's standing rule, is worse
# than having no control.
#
# So the key space each side speaks is DECLARED in the mapping rather than
# inferred, both sides are reduced through the same two functions here, and the
# control carries a guard that fails when the two spaces do not intersect at
# all. There is exactly one implementation of the reduction so the two sides
# cannot drift into disagreeing about what a key is.
#
# Loaded into Inspec::Rule, so these are CONTROL-scope helpers. Calling one from
# inside an `it`/`subject` block raises NameError at exec -- the example is not
# the control -- which is what tools/lint_resource_scope.py checks for.
module CheckovMembership
  # The identifier spaces a mapping may declare.
  #
  #   verbatim          the field already IS the key. Use it when both sides
  #                     carry a full ARN, which is the only unambiguous match.
  #   terminal_segment  the field is an ARN or a path and the key is its last
  #                     component: everything after the final '/' or ':'.
  #                       arn:aws:ec2:us-east-1:1234:volume/vol-0abc -> vol-0abc
  #                       arn:aws:rds:us-east-1:1234:cluster:prod    -> prod
  #                       /hostedzone/Z1234                          -> Z1234
  #                     Reducing loses the account and the region, so it widens
  #                     what can collide. Prefer verbatim ARN-to-ARN and reach
  #                     for this only when one side has no ARN to offer.
  KEY_FORMS = %w[verbatim terminal_segment].freeze

  # One row -> its comparison key, or nil when the row cannot be keyed.
  #
  # nil is returned rather than a blank key on purpose: a row with no usable
  # identifier must be COUNTED and reported, not silently folded into the
  # population where it would match another blank and read as covered.
  #
  # `"#{...}"` rather than `.to_s`: an inspec-aws null response answers `to_s`
  # through method_missing and can hand back nil, and a nil key compares equal
  # to every other nil key.
  def checkov_membership_key(row, field:, key_form:, match_region: true)
    unless KEY_FORMS.include?(key_form.to_s)
      raise ArgumentError, "checkov_membership_key: unknown key_form #{key_form.inspect}; " \
                           "expected one of #{KEY_FORMS.join(', ')}"
    end

    raw = "#{row[field.to_sym]}".strip
    return nil if raw.empty?

    key = key_form.to_s == "terminal_segment" ? "#{raw.split(%r{[/:]}).last}".strip : raw
    return nil if key.empty?

    # Regions are paired by default. A backup entry in us-west-2 does not cover
    # a volume in us-east-1, and once terminal_segment has thrown the region
    # away the key alone cannot tell them apart -- two clusters with the same
    # identifier in two regions is an ordinary thing to do. Pairing risks a
    # false FAILURE if the two sides ever disagree about which region a resource
    # belongs to; not pairing risks a false PASS. A false failure is visible and
    # investigable, a false pass is not, so the strict side is the default.
    match_region ? ["#{row[:region]}", key] : ["*", key]
  end

  # The right-hand side's key set, as a Hash used as a set.
  #
  # A Hash rather than a Set so this file needs no `require "set"` inside
  # InSpec's library loader, and rather than an Array so the lookup does not go
  # quadratic across a few thousand rows.
  def checkov_membership_keys(rows, field:, key_form:, match_region: true)
    rows.each_with_object({}) do |row, set|
      key = checkov_membership_key(row, field: field, key_form: key_form, match_region: match_region)
      set[key] = true if key
    end
  end

  # Narrow a population by declared field values, compared as strings.
  #
  # Used on the RIGHT side: AWS Backup's ListProtectedResources answers for
  # every resource type in the account at once, and a coverage control for EBS
  # must not be satisfied by a protected RDS cluster that happens to reduce to
  # the same terminal segment.
  def checkov_membership_where(rows, filters)
    return rows if filters.nil? || filters.empty?

    rows.select do |row|
      filters.all? do |field, values|
        Array(values).map { |v| "#{v}" }.include?("#{row[field.to_sym]}")
      end
    end
  end

  # The distinct values a field actually took across a population.
  #
  # Reported by the control whenever a declared filter selects nothing. The
  # filter values are service strings that no SDK shape declares as an enum --
  # `Aws::Backup::Types::ProtectedResource#resource_type` is a bare string -- so
  # a wrong one cannot be caught statically. Printing what the API really
  # returned turns that from an invisible 100% finding into a one-line
  # diagnosis in the results.
  def checkov_membership_observed(rows, field)
    rows.map { |row| "#{row[field.to_sym]}" }.reject(&:empty?).uniq.sort
  end

  # A few keys from each side, for the message on the no-intersection guard.
  #
  # Rendered as "region/key" rather than just the key, because the region is
  # half of what a key IS when the join pairs on region, and a sample that hides
  # it makes a region mismatch look identical to a match. The first draft here
  # printed the key alone, and a cross-region test case then produced two
  # samples that read the same while nothing matched -- which is precisely the
  # confusion this guard exists to remove.
  #
  # Takes the [region, key] PAIRS -- `right_keys.keys` for the right-hand set,
  # not the hash itself, whose values are all `true`.
  def checkov_membership_sample(key_pairs, limit = 3)
    Array(key_pairs).map do |pair|
      region, key = Array(pair)
      "#{region}/#{key}"
    end.uniq.sort.first(limit)
  end
end

::Inspec::Rule.include(CheckovMembership)
