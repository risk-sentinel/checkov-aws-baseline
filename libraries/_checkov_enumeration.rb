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
  # A row whose value is nil, whose hash does not carry the field at all, or
  # whose value is anything not in the list, is KEPT. Exclusion defaults towards
  # assessing the asset, because the failure mode of dropping one is silent and
  # the failure mode of keeping one is a visible result.
  #
  # That last case is why the scoping below uses `where`'s BLOCK form rather than
  # its hash form. `where(field => matcher)` runs FilterTable#filter_raw_data,
  # which begins `next unless row.key?(field)` — a row whose hash does not carry
  # the key is dropped by any criterion, whatever the matcher says. Several
  # plurals in the pack build their rows with `response_struct.to_h`, and to_h
  # OMITS members the API did not return, so an `exclude:` on an optional member
  # would have silently deleted exactly the assets nobody could see. The block
  # form takes a different path: FilterTable builds a Struct per row with
  # `row_as_hash[field]` for each registered field, so an absent key arrives as
  # nil and the row survives. It is also the path that triggers population of a
  # lazily-loaded column, which the hash form only does for a named criterion.
  def checkov_enumerate(collection, column, exclude: nil)
    problems = []
    scoped = collection

    # Before anything is read off it, ask the resource whether the API call
    # behind it actually happened. This is the fifth silent-wrong-answer path
    # and the most common one in a real account: see checkov_read_failure.
    read_failure = checkov_read_failure(collection)
    return [[], [read_failure]] if read_failure

    # `excluded_column`, not `column`: a block parameter of the same name shadows
    # the method parameter, and the id column is read from it AFTER this loop.
    # Ruby's block-locals mean it happened to be harmless, which is exactly the
    # kind of thing that stops being harmless during an edit.
    (exclude || {}).each do |excluded_column, values|
      property = checkov_property_behind(scoped, excluded_column)
      if property.nil?
        # No such column. Harmless when nothing was enumerated -- a table built
        # from the API response registers nothing without a response -- and a
        # mapping bug otherwise.
        next if checkov_column_state(scoped, excluded_column) == :empty

        problems << "cannot narrow the population on '#{excluded_column}': the resource "\
                    "returned rows but exposes no such column, so `exclude:` in "\
                    "resource_map.yml names something that does not exist"
        next
      end

      # A column registered WITH an implementation block is computed from the
      # whole table rather than read off a row, so FilterTable leaves it out of
      # the per-row struct the block below is evaluated against and `send` on it
      # raises NoMethodError. Reported rather than rescued into an empty result.
      if property.block
        problems << "cannot narrow the population on '#{excluded_column}': it is a computed "\
                    "column, not a field on the row, so it cannot scope an enumeration"
        next
      end

      field    = property.field_name.to_sym
      unwanted = Array(values).map { |v| v.to_s.downcase }
      begin
        scoped = scoped.where { !unwanted.include?(send(field).to_s.downcase) }
      rescue StandardError => e
        problems << "cannot narrow the population on '#{excluded_column}': "\
                    "#{e.class}: #{e.message}"
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

  # Why the resource could not be read, or nil if it was read.
  #
  # An AWS call that fails does NOT reach the control as an exception. Two
  # layers swallow it:
  #
  #   * AwsResourceBase#catch_aws_errors turns Aws::Errors::MissingCredentialsError
  #     and NoSuchEndpointError into fail_resource + nil, and a non-403
  #     ServiceError -- throttling, RequestLimitExceeded, OptInRequired, a
  #     service that does not exist in the region -- into an Inspec::Log.warn,
  #     `@failed_resource = true` and nil.
  #   * Inspec::Resource#supersuper_initialize wraps EVERY resource constructor
  #     and rescues Inspec::Exceptions::ResourceFailed (which is what the 403 /
  #     AccessDenied branch of catch_aws_errors raises), ResourceSkipped and the
  #     NoMethodError a nil response produces one line later.
  #
  # Either way the control gets back a live object whose table is empty. Without
  # this check that empty table is `:empty` below -- an honest account with none
  # of this resource -- and the control renders Not Applicable having assessed
  # nothing. AccessDenied on one service, or one throttled region, would quietly
  # remove that check from the assessment while the run stayed green.
  #
  # `@failed_resource` (inspec-aws) and `@resource_failed` (InSpec core) are set
  # by different branches of the same rescue and neither implies the other, so
  # all three predicates are asked. No plural in the vendored pack calls
  # fail_resource for an empty result, so none of these fires on an account that
  # simply has nothing.
  def checkov_read_failure(collection)
    state = %i[resource_failed? failed_resource? resource_skipped?].find do |predicate|
      collection.respond_to?(predicate) && collection.public_send(predicate)
    end
    return nil unless state

    detail = if collection.respond_to?(:resource_exception_message)
               collection.resource_exception_message
             end
    "the resource could not be read (#{state}#{detail ? ": #{detail}" : ''}) — the AWS "\
    "call behind this enumeration did not succeed, so NOTHING was assessed here. "\
    "Do not read this control's result as a pass: fix the permission, the region "\
    "list or the throttling and run it again"
  end

  # The registered column's schema entry (field_name, block, opts), or nil if
  # there is no such column.
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
  def checkov_property_behind(collection, column)
    return nil unless collection.respond_to?(:where)

    table = collection.where({})
    return nil unless table.respond_to?(:custom_properties_schema)

    table.custom_properties_schema[column.to_sym]
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
