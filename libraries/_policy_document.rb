# Predicates over an AWS policy document.
#
# Why this is not a field comparison
# ----------------------------------
# Every other reader shape in this profile answers "what is the value of field
# X on asset Y", and a `satisfies` verb compares it. Seventeen of Checkov's AWS
# checks cannot be phrased that way. The unit of judgement in a policy document
# is a STATEMENT, and a statement's verdict depends on Effect, Principal,
# Action, Resource and Condition together:
#
#   {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
#     -> public, a finding
#   {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
#    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}}
#     -> the same Principal, the same Action, and not a finding
#
# No amount of field extraction distinguishes those two. So the mapping names a
# PREDICATE, and this file is the one place a predicate is defined -- shared by
# every check that needs it, so `no_wildcard_principal` cannot mean one thing on
# an ECR repository policy and another on a KMS key policy.
#
# What a predicate returns
# ------------------------
# A list of human-readable strings, one per offending statement, empty when the
# document is clean. Not a boolean: a control whose failure message is `false`
# tells the person reading the HDF nothing about which statement to go and fix.
# An empty list is the passing state and is directly comparable with `eq([])`.
#
# Shape tolerance is mandatory, silence is not
# --------------------------------------------
# `Statement` is a single object or an array of them. `Principal` is a string, a
# hash of type => value, or a hash of type => list. `Action`, `Resource` and a
# Condition value are each a string or a list. IAM element names are matched
# case-insensitively because IAM itself accepts either case.
#
# A shape this file does not expect raises ParseError. It deliberately does NOT
# return "no offending statements", because that is indistinguishable from a
# clean policy and turns a control that could not evaluate into a passing one.
# The caller (libraries/aws_policy_documents.rb) catches ParseError and files the
# asset as UNDECIDABLE, which the generated control asserts on and fails --
# visible, and neither a silent pass nor a Not Applicable.
#
# URL encoding
# ------------
# IAM returns policy documents URL-encoded (RFC 3986) -- `iam:ListRoles`
# AssumeRolePolicyDocument and `iam:GetPolicyVersion` Document both. Other
# services (ECR, KMS, S3, SNS, SQS, Lambda) return plain JSON. Rather than
# recording which is which, the parser tries JSON first and percent-decodes only
# when that fails, so neither convention needs to be declared per source.
#
# Scope
# -----
# Reached from two places: `PolicyDocument.<method>` from the reader resource,
# and bare from control scope via ::Inspec::Rule.include at the bottom of this
# file. The leading `::` is load-bearing -- a bare `Inspec::Rule.include` raises
# `uninitialized constant` at exec while passing `check`, which has bitten this
# fleet before.
module PolicyDocument
  # A document that could not be read as a policy. Never rescued into an empty
  # offender list; see the header.
  class ParseError < StandardError; end

  # The predicates a mapping may name. tools/lint_policy_specs.py reads this
  # list out of this file, so a mapping naming a predicate that does not exist
  # is refused before it renders rather than raising at exec.
  PREDICATES = %w[
    no_wildcard_principal
    no_wildcard_action
    no_admin_star_star
    no_cross_account_principal_without_condition
    no_account_root_principal
    gh_oidc_sub_safe
  ].freeze

  GH_OIDC_ISSUER = 'token.actions.githubusercontent.com'.freeze

  # A principal that is the account itself rather than a role or user in it:
  # either the bare 12-digit account number or its `:root` ARN. Partition-
  # agnostic, so a GovCloud (`arn:aws-us-gov:`) policy is judged the same way.
  ACCOUNT_ROOT = /\A(?:\d{12}|arn:aws[a-z0-9-]*:iam::\d{12}:root)\z/.freeze

  # A concrete IAM principal -- some specific account's user, role or root.
  ACCOUNT_PRINCIPAL = /\A(?:(\d{12})|arn:aws[a-z0-9-]*:iam::(\d{12}):\S*)\z/.freeze

  # `*` and `*:*` are the only two spellings of "every action in every service".
  # A prefix wildcard such as `s3:Get*` is NOT one of them: Checkov's rule is
  # about the bare star, and flagging every prefixed action would fire on almost
  # every policy in existence and train its reader to ignore the result.
  ALL_ACTIONS = %w[* *:*].freeze

  # A GitHub Actions OIDC `sub` claim that names a concrete repository.
  #
  #   repo:acme/widgets                       -> safe
  #   repo:acme/widgets:ref:refs/heads/main   -> safe
  #   repo:acme/widgets:*                     -> safe, the repo is still pinned
  #   repo:acme/*                             -> NOT safe, any repo in the org
  #   repo:*  /  *                            -> NOT safe
  #
  # The org and repository segments must carry no wildcard. Everything after
  # them may, because the repository is the trust boundary this rule is about.
  GH_SUB_SAFE = %r{\Arepo:[^/:*?\s]+/[^/:*?\s]+(?::.*)?\z}.freeze

  # Condition operators that CONSTRAIN a claim to a value. `Null`, `StringNotEquals`
  # and friends do not: `"Null": {"...:sub": "false"}` merely requires the claim to
  # be present, which every GitHub token satisfies.
  CONSTRAINING_OPERATORS = %w[stringequals stringequalsignorecase stringlike].freeze

  # Operators that pin a claim to an EXACT value. A StringLike can carry a
  # wildcard and therefore cannot pin an immutable id.
  EQUALITY_OPERATORS = %w[stringequals stringequalsignorecase].freeze

  # ---------------------------------------------------------------- parsing --

  # A raw policy string as a Hash, or nil when there is no policy at all.
  #
  # nil is NOT the same as an empty offender list to the caller: the reader
  # records `policy_present: false`, so "this bucket has no policy" is
  # distinguishable in the evidence from "this bucket's policy is clean".
  def policy_document_parse(raw)
    text = raw.to_s
    return nil if text.strip.empty?

    require 'json'
    parsed = policy_document_json(text)
    unless parsed.is_a?(Hash)
      raise ParseError, "policy document parsed to a #{parsed.class}, not an object"
    end

    parsed
  end

  # The statements, always as an array of Hashes.
  def policy_document_statements(document)
    return [] if document.nil?

    raw = policy_document_element(document, 'Statement')
    case raw
    when nil   then []
    when Hash  then [raw]
    when Array then policy_document_statement_array(raw)
    else
      raise ParseError, "Statement is a #{raw.class}; expected an object or an array of objects"
    end
  end

  # ------------------------------------------------------------- evaluation --

  # Offending statements for `predicate`, as readable strings. Empty is clean.
  #
  # `account_id` is the account the scan is running in. It is what makes
  # `no_cross_account_principal_without_condition` mean anything: without it,
  # every policy that names its own account's roles reads as cross-account.
  def policy_document_offenders(document, predicate, account_id: nil)
    name = predicate.to_s
    unless PREDICATES.include?(name)
      raise ArgumentError,
            "unknown policy predicate '#{name}'. Implemented: #{PREDICATES.join(', ')}. " \
            'Add it here rather than approximating it with a field comparison.'
    end

    policy_document_statements(document).each_with_index.map do |statement, index|
      reason = public_send("policy_offence_#{name}", statement, account_id)
      next nil if reason.nil?

      "#{policy_document_label(statement, index)}: #{reason}"
    end.compact
  end

  # ------------------------------------------------------------- predicates --

  # Allow, to everyone, unconditionally.
  #
  # A Condition -- ANY condition -- takes the statement out of scope, which is
  # what Checkov does too. Without that, every AWS-managed KMS key's default
  # policy and every VPC-endpoint-scoped bucket policy reads as public. It is
  # the coarse form of Checkov's condition allow-list (aws:PrincipalOrgID,
  # aws:SourceVpc, aws:PrincipalArn, ...) and errs towards NOT reporting a
  # statement somebody deliberately constrained.
  def policy_offence_no_wildcard_principal(statement, _account_id)
    return nil unless policy_document_allow?(statement)
    return nil if policy_document_conditioned?(statement)

    offending = policy_document_principals(statement, 'AWS').select { |p| p.include?('*') }
    return nil if offending.empty?

    "Effect Allow to Principal.AWS #{offending.join(', ')} with no Condition — " \
      'any AWS account, and an anonymous caller, matches this'
  end

  # Allow on every action in every service.
  def policy_offence_no_wildcard_action(statement, _account_id)
    return nil unless policy_document_allow?(statement)

    offending = policy_document_values(statement, 'Action').select { |a| ALL_ACTIONS.include?(a) }
    return nil if offending.empty?

    "Effect Allow with Action #{offending.join(', ')} — every action in every service"
  end

  # Allow on every action against every resource: administrative access.
  def policy_offence_no_admin_star_star(statement, _account_id)
    return nil unless policy_document_allow?(statement)

    actions = policy_document_values(statement, 'Action').select { |a| ALL_ACTIONS.include?(a) }
    return nil if actions.empty?

    resources = policy_document_values(statement, 'Resource').select { |r| r == '*' }
    return nil if resources.empty?

    "Effect Allow with Action #{actions.join(', ')} on Resource * — full administrative access"
  end

  # Allow to a named principal in ANOTHER account, with nothing constraining it.
  def policy_offence_no_cross_account_principal_without_condition(statement, account_id)
    return nil unless policy_document_allow?(statement)
    return nil if policy_document_conditioned?(statement)

    external = policy_document_principals(statement, 'AWS').select do |principal|
      owner = policy_document_principal_account(principal)
      !owner.nil? && owner != account_id.to_s
    end
    return nil if external.empty?

    unknown = account_id.to_s.strip.empty? ? ' (the scanning account could not be determined, ' \
                                             'so every named account is reported)' : ''
    "Effect Allow to Principal.AWS #{external.join(', ')} in another account, with no " \
      "Condition#{unknown}"
  end

  # Allow to an account root, which grants the whole account rather than a role.
  #
  # Any non-Deny statement, not only Allow: a root principal in a statement with
  # no Effect at all is still a malformed grant worth surfacing.
  def policy_offence_no_account_root_principal(statement, _account_id)
    return nil if policy_document_effect(statement) == 'deny'

    roots = policy_document_principals(statement, 'AWS').select { |p| ACCOUNT_ROOT.match?(p) }
    return nil if roots.empty?

    "Principal.AWS #{roots.join(', ')} is an account root — every identity in that " \
      'account inherits this grant, not a named role'
  end

  # A GitHub Actions OIDC trust that does not pin the repository.
  #
  # Statements with no GitHub federated principal are not this predicate's
  # business and return nil -- which is a PASS for that statement, not a skip:
  # the asset stays in scope and its other statements are still judged.
  def policy_offence_gh_oidc_sub_safe(statement, _account_id)
    return nil unless policy_document_allow?(statement)

    federated = policy_document_principals(statement, 'Federated')
    return nil unless federated.any? { |p| p.include?(GH_OIDC_ISSUER) }

    values = policy_document_sub_constraint(statement)
    if values.nil?
      return "trusts #{GH_OIDC_ISSUER} but no StringEquals/StringLike Condition constrains " \
             "#{GH_OIDC_ISSUER}:sub — any repository on GitHub can assume this role"
    end

    unsafe = values.reject { |v| GH_SUB_SAFE.match?(v) }
    return nil if unsafe.empty?

    # A wildcard `sub` is NOT a finding when the statement pins :repository_id
    # to an exact value. GitHub presents a RENAMED repository as
    # repo:<org>@<id>/<repo>@<id>, so a trust policy that pinned only the plain
    # name breaks on rename -- and the documented fix is to pin the numeric
    # repository_id, which is immutable, and to relax `sub` to match either
    # spelling. That combination is STRICTLY STRONGER than a `sub` pin: the id
    # identifies one repository for its whole life, where a name can be freed
    # and re-registered by somebody else.
    #
    # Without this, every role following AWS's own rename-safe guidance failed:
    # 24 of 24 failures on the first live run were this exact shape, and a
    # control that is wrong every time it fires is one its reader learns to skip.
    pinned = policy_document_claim_constraint(statement, 'repository_id',
                                              operators: EQUALITY_OPERATORS)
    if pinned && pinned.any? { |v| !v.to_s.strip.empty? && !v.to_s.include?('*') }
      return nil
    end

    "trusts #{GH_OIDC_ISSUER} with :sub constrained to #{unsafe.join(', ')} — that does not " \
      'pin a concrete repo:<org>/<repo>, and no :repository_id Condition pins it either, ' \
      'so repositories outside this one match'
  end

  # ------------------------------------------------------- shape tolerance ---

  # An IAM element by name, matched case-insensitively. IAM accepts either case
  # and real documents in the wild use both.
  def policy_document_element(node, name)
    return nil unless node.is_a?(Hash)

    key = node.keys.find { |k| k.to_s.casecmp(name).zero? }
    key.nil? ? nil : node[key]
  end

  def policy_document_effect(statement)
    policy_document_element(statement, 'Effect').to_s.downcase
  end

  def policy_document_allow?(statement)
    policy_document_effect(statement) == 'allow'
  end

  def policy_document_conditioned?(statement)
    condition = policy_document_element(statement, 'Condition')
    condition.is_a?(Hash) && !condition.empty?
  end

  # `Action`, `Resource`, `NotAction` ... as a flat array of strings.
  def policy_document_values(statement, name)
    policy_document_flatten(policy_document_element(statement, name), name)
  end

  # The principals of one type ('AWS', 'Service', 'Federated', 'CanonicalUser').
  #
  # `"Principal": "*"` is the bare-string form and is an AWS principal, so it is
  # normalised into the AWS bucket rather than being silently dropped -- dropping
  # it would make the single most common finding invisible.
  def policy_document_principals(statement, type)
    raw = policy_document_element(statement, 'Principal')
    case raw
    when nil    then []
    when String then type == 'AWS' ? [raw] : []
    when Array  then type == 'AWS' ? policy_document_flatten(raw, 'Principal') : []
    when Hash   then policy_document_flatten(policy_document_element(raw, type), 'Principal')
    else
      raise ParseError, "Principal is a #{raw.class}; expected a string, an array or an object"
    end
  end

  # The account a principal belongs to, or nil when it names no account.
  def policy_document_principal_account(principal)
    match = ACCOUNT_PRINCIPAL.match(principal.to_s)
    match.nil? ? nil : (match[1] || match[2])
  end

  # The values a Condition constrains the GitHub `sub` claim to, or nil when
  # nothing constrains it. An empty array is a real answer -- a constraint
  # present but valueless -- and is not the same as nil.
  def policy_document_sub_constraint(statement)
    policy_document_claim_constraint(statement, 'sub')
  end

  # The values a Condition constrains one OIDC claim to, or nil when nothing
  # constrains it. `operators:` narrows which Condition operators count --
  # :repository_id is only a pin under an EQUALITY operator, because a
  # StringLike on it could carry a wildcard and pin nothing.
  def policy_document_claim_constraint(statement, claim, operators: CONSTRAINING_OPERATORS)
    condition = policy_document_element(statement, 'Condition')
    return nil unless condition.is_a?(Hash)

    found = nil
    condition.each do |operator, clause|
      next unless clause.is_a?(Hash)
      next unless operators.include?(policy_document_base_operator(operator))

      value = policy_document_element(clause, "#{GH_OIDC_ISSUER}:#{claim}")
      next if value.nil?

      found = (found || []) + policy_document_flatten(value, 'Condition')
    end
    found
  end

  # `ForAllValues:StringLike` -> `stringlike`. The set-operator prefix does not
  # change whether the operator constrains, and every value is checked anyway.
  def policy_document_base_operator(operator)
    operator.to_s.sub(/\A(?:ForAllValues|ForAnyValue):/i, '').downcase
  end

  private

  def policy_document_json(text)
    JSON.parse(text)
  rescue JSON::ParserError
    decoded = policy_document_percent_decode(text)
    begin
      JSON.parse(decoded)
    rescue JSON::ParserError => e
      raise ParseError, "not JSON, before or after percent-decoding: #{e.message}"
    end
  end

  # RFC 3986 percent-decoding only. Deliberately not CGI.unescape, which also
  # turns `+` into a space: AWS encodes a literal plus as `%2B`, so a `+` that
  # survives into here belongs in the output as itself.
  def policy_document_percent_decode(text)
    text.gsub(/%([0-9A-Fa-f]{2})/) { [Regexp.last_match(1)].pack('H2') }
        .force_encoding(Encoding::UTF_8)
  end

  def policy_document_statement_array(raw)
    raw.each_with_index.map do |element, index|
      unless element.is_a?(Hash)
        raise ParseError, "Statement[#{index}] is a #{element.class}; expected an object"
      end

      element
    end
  end

  # A string, or a list of them, as a list of them. A nested list is flattened
  # because a hand-written document occasionally carries one, and a number or a
  # boolean is stringified rather than dropped.
  #
  # A `null` ELEMENT raises rather than being compacted away. `{"AWS": [null]}`
  # compacted to `[]`, and `[]` is indistinguishable from "this statement names
  # no principal", so the statement passed every predicate having been read by
  # nobody. An element this file cannot judge is the ParseError case, exactly as
  # a non-object Statement element is.
  def policy_document_flatten(value, name)
    case value
    when nil    then []
    when String then [value]
    when Array  then policy_document_flat_elements(value, name)
    when Numeric, TrueClass, FalseClass then [value.to_s]
    else
      raise ParseError, "#{name} is a #{value.class}; expected a string or an array of strings"
    end
  end

  # An element that is not a scalar raises for the same reason: `to_s` on a Hash
  # produces a string that is a valid principal to nobody and matches no
  # wildcard, so it reads as a clean statement.
  def policy_document_flat_elements(value, name)
    value.flatten.each_with_index.map do |element, index|
      unless element.is_a?(String) || element.is_a?(Numeric) ||
             [TrueClass, FalseClass].include?(element.class)
        raise ParseError, "#{name}[#{index}] is #{element.nil? ? 'null' : "a #{element.class}"}; " \
                          'expected a string'
      end

      element.to_s
    end
  end

  # The statement's own name where it has one, its index where it does not, so a
  # failure message points at something a person can find in the document.
  def policy_document_label(statement, index)
    sid = policy_document_element(statement, 'Sid').to_s
    sid.strip.empty? ? "Statement[#{index}]" : "Sid #{sid}"
  end

  public

  # Makes every public method above available both as
  # `PolicyDocument.policy_document_offenders(...)` (how the reader resource
  # calls them) and as a bare call at control scope.
  extend self
end

# Leading `::` is required. A bare `Inspec::Rule.include` resolves against the
# enclosing lexical scope, raises `uninitialized constant` at exec, and passes
# `check` -- which loads control files without evaluating one.
::Inspec::Rule.include(PolicyDocument)
