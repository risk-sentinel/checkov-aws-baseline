# Turning a stock inspec-aws plural resource into a list of identifiers.
#
# Why this is not `plural.column.to_a`
# ------------------------------------
# That is what the generated controls used to do, and a live exec found four
# separate ways it produces a WRONG result rather than an error:
#
#   1. A column that is not registered does not raise. AwsResourceBase#method_missing
#      answers with a NullResponse, whose `to_a` is itself and whose `map` is
#      itself, so `found` became one NullResponse per region. Those survived the
#      blank-id filter (NullResponse#to_s returns nil, and interpolating it
#      yields "#<NullResponse:0x...>", which is not blank) and were handed to the
#      singular resource as a cluster name. That removed CKV_AWS_37, _39, _58
#      and _339 from the map.
#
#   2. A column IS unregistered, legitimately, when the resource populates its
#      table from the API response (`populate_filter_table_from_response`) and
#      the account has none of that resource: there is no first row to derive
#      columns from. "no EKS clusters" and "the `ids:` column is wrong" reach the
#      control through the same NullResponse, and they must not be reported the
#      same way.
#
#   3. A column registered without `style: :simple` is NOT flattened by
#      FilterTable, so a field whose value is itself a list comes back nested.
#      aws_guardduty_detectors stores one row of {detector_ids: [...]}, so
#      `.detector_ids` is [[id]] and the singular rejects an Array where it wants
#      a String. That removed CKV_AWS_238.
#
#   4. A plural enumerates the whole API response, including objects in a
#      terminal or transitional state that no longer are the thing the check is
#      about — an EKS cluster mid-CREATE has no logging configuration yet, and
#      asserting on it produces a finding that disappears on its own.
#
# What this returns
# -----------------
#   [ids, problems]
#
# `ids` is what was enumerated. `problems` is what stopped it enumerating, as
# human-readable strings, and the control asserts it is EMPTY. That separation
# is the whole point: an enumeration that failed must be visible as a failure.
# Returning [] alone would render Not Applicable, which claims the rule does not
# apply to this account — indistinguishable, in the results people read, from a
# clean pass.
#
# Loaded into Inspec::Rule, so it is available at CONTROL scope. Calling it from
# inside a `subject`/`it` block raises NameError at exec; tools/lint_resource_scope.py
# checks for that.
module CheckovEnumeration
  # Identifiers for every asset a plural resource enumerated.
  #
  #   ids, problems = checkov_enumerate(aws_eks_clusters(aws_region: region), :names)
  #
  # `exclude` narrows the population before the ids are read, as
  # { column => [values] }: the rows whose column holds one of those values are
  # dropped. It is for objects the API keeps returning after they have stopped
  # being deployed assets — a terminated EC2 instance, a cluster mid-delete —
  # not for narrowing a check to the assets that would pass it.
  #
  # A row whose value is nil, or anything not in the list, is KEPT. Exclusion
  # defaults towards assessing the asset, because the failure mode of dropping
  # one is silent and the failure mode of keeping one is a visible result.
  def checkov_enumerate(collection, column, exclude: nil)
    problems = []
    scoped = collection

    (exclude || {}).each do |column, values|
      field = checkov_field_behind(scoped, column)
      if field.nil?
        # No such column. Harmless when nothing was enumerated -- a table built
        # from the API response registers nothing without a response -- and a
        # mapping bug otherwise.
        next if checkov_column_state(scoped, column) == :empty

        problems << "cannot narrow the population on '#{column}': the resource returned "\
                    "rows but exposes no such column, so `exclude:` in resource_map.yml "\
                    "names something that does not exist"
        next
      end

      begin
        scoped = scoped.where(field.to_sym => checkov_not_one_of(values))
      rescue ArgumentError => e
        problems << "cannot narrow the population on '#{column}': #{e.message}"
      end
    end

    case checkov_column_state(scoped, column)
    when :present
      [checkov_identifiers(scoped.public_send(column.to_sym)), problems]
    when :empty
      [[], problems]
    else
      problems << "'#{column}' is not a column this resource exposes, yet it returned "\
                  "rows — the `ids:` in resource_map.yml names a field that does not "\
                  "exist, so nothing was assessed"
      [[], problems]
    end
  end

  private

  # The FIELD a registered column reads, or nil if there is no such column.
  #
  # `where` does not take the column name. It validates its criteria against
  # `list_fields`, so `where(statuses: ...)` on a resource that registered
  # `register_column(:statuses, field: :status)` raises "':statuses' is not a
  # recognized criterion". A mapping names the COLUMN, because that is what the
  # `ids:` key names and what tools/lint_resource_map.py can check against the
  # vendored pack, so the translation happens here.
  #
  # `where({})` returns the FilterTable itself, which is where the column ->
  # field schema lives; the resource does not carry it.
  def checkov_field_behind(collection, column)
    return nil unless collection.respond_to?(:where)

    table = collection.where({})
    return nil unless table.respond_to?(:custom_properties_schema)

    property = table.custom_properties_schema[column.to_sym]
    property&.field_name
  end

  # :present — the column can be read.
  # :empty   — nothing was enumerated, so an absent column carries no information:
  #            a table populated from the API response registers no columns at all
  #            when there was no response to derive them from.
  # :missing — rows exist and the column does not. That is a mapping bug, and the
  #            only one of the three that must reach the results.
  #
  # `respond_to?` is honest here even though `method_missing` is not:
  # AwsResourceBase overrides method_missing but leaves respond_to_missing? as
  # super, so an unregistered column answers false rather than being masked.
  def checkov_column_state(collection, column)
    return :present if collection.respond_to?(column.to_sym)

    rows = begin
      collection.entries
    rescue StandardError
      nil
    end
    # Deliberately `is_a?(Array)`: FilterTable#entries returns one. A NullResponse
    # answers true to `empty?` as well, and treating that as "nothing here" would
    # reinstate exactly the silence this method exists to remove.
    return :empty if rows.is_a?(Array) && rows.empty?

    :missing
  end

  # A matcher for "not one of these values", as a Regexp.
  #
  # FilterTable's `where` compares with `desired === actual`, so an Array means
  # equality with that array, not membership — the only value type that can
  # express a set is a Regexp, which it matches against `value.to_s`. The
  # negative lookahead is anchored at both ends so a state named "deleting" does
  # not also exclude one named "deleting-failed", and an unset value ("") falls
  # through it and is kept.
  def checkov_not_one_of(values)
    alternatives = Array(values).map { |v| Regexp.escape(v.to_s) }.join("|")
    Regexp.new("\\A(?!(?:#{alternatives})\\z)", Regexp::IGNORECASE)
  end

  # The column's values as a flat list, with nothing coerced yet.
  #
  # Flattened because FilterTable only flattens columns registered with
  # `style: :simple`, and a hand-registered column whose field holds a list comes
  # back nested. Nil and blank entries are left in: the control counts them and
  # reports them, because "every id was blank" is a broken enumeration and must
  # not be quietly filtered into an empty, inapplicable control.
  def checkov_identifiers(raw)
    return [] if raw.nil? # NullResponse#nil? is true, which is the point
    return [] unless raw.respond_to?(:to_a)

    raw.to_a.flatten
  end
end

::Inspec::Rule.include(CheckovEnumeration)
