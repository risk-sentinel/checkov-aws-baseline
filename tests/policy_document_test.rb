#!/usr/bin/env ruby
# Unit tests for libraries/_policy_document.rb.
#
# Why these exist when nothing else in this profile has tests
# -----------------------------------------------------------
# `cinc-auditor check` and `json` load control files without evaluating a single
# control body, so neither can tell a correct predicate from one that returns an
# empty list for everything -- and a predicate that never returns an offender
# produces a control that structurally cannot fail, which reads exactly like a
# clean estate. Every other reader shape in this profile is a field comparison
# whose correctness is visible in the generated Ruby; a policy predicate's is
# not.
#
# The predicates are pure functions of a parsed document with no AWS dependency,
# so unlike the readers they can be proven without credentials. That is the whole
# reason the parsing and the fetching live in different files.
#
# Run:  ruby tests/policy_document_test.rb
# No gems, no bundler, no network -- so it runs in the auditor image and on a
# laptop identically.

# The library ends with `::Inspec::Rule.include(PolicyDocument)`. Outside InSpec
# that constant does not exist, so it is stubbed rather than the call being
# removed -- the point is to load the file EXACTLY as InSpec loads it, including
# the line that has historically been got wrong.
module Inspec
  class Rule
    def self.include(mod)
      @included ||= []
      @included << mod
      super
    end

    def self.included_modules_seen
      @included || []
    end
  end
end

require_relative '../libraries/_policy_document'

FAILURES = []
COUNT = [0]

def check(name)
  COUNT[0] += 1
  yield
rescue StandardError => e
  FAILURES << "#{name}: #{e.class}: #{e.message}"
end

def assert(name, condition, detail = nil)
  COUNT[0] += 1
  FAILURES << "#{name}#{detail ? " (#{detail})" : ''}" unless condition
end

def offenders(document, predicate, account_id: nil)
  PolicyDocument.policy_document_offenders(
    PolicyDocument.policy_document_parse(document), predicate, account_id: account_id
  )
end

def doc(statements)
  require 'json'
  JSON.generate('Version' => '2012-10-17', 'Statement' => statements)
end

# ---------------------------------------------------------------- wiring ----

assert 'included into ::Inspec::Rule',
       Inspec::Rule.included_modules_seen.include?(PolicyDocument)

assert 'PREDICATES has all six', PolicyDocument::PREDICATES.length == 6

check 'an unimplemented predicate raises rather than returning clean' do
  begin
    offenders(doc([]), 'no_such_predicate')
    FAILURES << 'an unknown predicate did not raise'
  rescue ArgumentError
    nil
  end
end

# ---------------------------------------------------------------- parsing ---

assert 'no policy at all parses to nil',
       PolicyDocument.policy_document_parse('').nil? &&
       PolicyDocument.policy_document_parse(nil).nil?

assert 'plain JSON parses',
       PolicyDocument.policy_document_parse(doc([]))['Version'] == '2012-10-17'

encoded = doc([{ 'Effect' => 'Allow', 'Principal' => '*', 'Action' => 's3:GetObject' }])
          .gsub('{', '%7B').gsub('}', '%7D').gsub('"', '%22').gsub(' ', '%20')
assert 'URL-encoded IAM document parses',
       offenders(encoded, 'no_wildcard_principal').length == 1

check 'a non-JSON document raises ParseError, not an empty offender list' do
  begin
    PolicyDocument.policy_document_parse('this is not a policy')
    FAILURES << 'garbage parsed without raising'
  rescue PolicyDocument::ParseError
    nil
  end
end

check 'a document that is a JSON array raises ParseError' do
  begin
    PolicyDocument.policy_document_parse('[]')
    FAILURES << 'a JSON array parsed as a policy'
  rescue PolicyDocument::ParseError
    nil
  end
end

check 'Statement of the wrong type raises ParseError' do
  begin
    PolicyDocument.policy_document_statements('Statement' => 'nonsense')
    FAILURES << 'a string Statement was accepted'
  rescue PolicyDocument::ParseError
    nil
  end
end

# A null inside a value list used to be compacted away, and `[]` is
# indistinguishable from "this statement names no principal at all" -- so the
# statement passed every predicate having been read by nobody. The whole point of
# ParseError is that a shape this file cannot judge is never a clean answer.
check 'a null element in a value list raises rather than being dropped' do
  begin
    offenders(doc([{ 'Effect' => 'Allow', 'Principal' => { 'AWS' => [nil] },
                     'Action' => 's3:GetObject' }]), 'no_wildcard_principal')
    FAILURES << 'a null principal was compacted into a clean statement'
  rescue PolicyDocument::ParseError
    nil
  end
end

check 'a non-scalar element in a value list raises rather than being stringified' do
  begin
    offenders(doc([{ 'Effect' => 'Allow', 'Action' => [{ 'oops' => true }],
                     'Resource' => '*' }]), 'no_admin_star_star')
    FAILURES << 'an object Action element was stringified into a clean statement'
  rescue PolicyDocument::ParseError
    nil
  end
end

assert 'a nested list of strings still flattens',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => { 'AWS' => [['*']] },
                        'Action' => 's3:GetObject' }]), 'no_wildcard_principal').length == 1

# ----------------------------------------------------------- shape variety --

single = { 'Effect' => 'Allow', 'Principal' => '*', 'Action' => 's3:*' }
assert 'Statement as a single object',
       PolicyDocument.policy_document_statements('Statement' => single).length == 1
assert 'Statement as an array',
       PolicyDocument.policy_document_statements('Statement' => [single, single]).length == 2
assert 'lowercase element names are matched',
       PolicyDocument.policy_document_statements('statement' => single).length == 1

assert 'Principal as a bare string',
       PolicyDocument.policy_document_principals({ 'Principal' => '*' }, 'AWS') == ['*']
assert 'Principal as a hash of string',
       PolicyDocument.policy_document_principals({ 'Principal' => { 'AWS' => '*' } }, 'AWS') == ['*']
assert 'Principal as a hash of list',
       PolicyDocument.policy_document_principals(
         { 'Principal' => { 'AWS' => %w[a b] } }, 'AWS'
       ) == %w[a b]
assert 'Principal as a bare list',
       PolicyDocument.policy_document_principals({ 'Principal' => ['*'] }, 'AWS') == ['*']
assert 'a Service principal is not an AWS principal',
       PolicyDocument.policy_document_principals(
         { 'Principal' => { 'Service' => 'ec2.amazonaws.com' } }, 'AWS'
       ).empty?

# ------------------------------------------------- no_wildcard_principal ----

assert 'bare "*" principal is a finding',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => '*',
                        'Action' => 'ecr:GetDownloadUrlForLayer' }]),
                 'no_wildcard_principal').length == 1

assert 'Principal.AWS "*" is a finding',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => { 'AWS' => '*' },
                        'Action' => 's3:GetObject' }]),
                 'no_wildcard_principal').length == 1

assert 'a Condition takes the statement out of scope',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => '*', 'Action' => 's3:GetObject',
                        'Condition' => { 'StringEquals' => { 'aws:PrincipalOrgID' => 'o-x' } } }]),
                 'no_wildcard_principal').empty?

assert 'a service principal is not a wildcard principal',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => { 'Service' => 'ec2.amazonaws.com' },
                        'Action' => 'sts:AssumeRole' }]),
                 'no_wildcard_principal').empty?

assert 'Deny to "*" is not a finding',
       offenders(doc([{ 'Effect' => 'Deny', 'Principal' => '*', 'Action' => '*' }]),
                 'no_wildcard_principal').empty?

assert 'a KMS default key policy is clean',
       offenders(doc([{ 'Sid' => 'Enable IAM User Permissions', 'Effect' => 'Allow',
                        'Principal' => { 'AWS' => 'arn:aws:iam::111122223333:root' },
                        'Action' => 'kms:*', 'Resource' => '*' }]),
                 'no_wildcard_principal').empty?

assert 'the failure message names the statement',
       offenders(doc([{ 'Sid' => 'PublicRead', 'Effect' => 'Allow', 'Principal' => '*',
                        'Action' => 's3:GetObject' }]),
                 'no_wildcard_principal').first.to_s.start_with?('Sid PublicRead:')

assert 'an unnamed statement is reported by index',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => '*', 'Action' => 's3:GetObject' }]),
                 'no_wildcard_principal').first.to_s.start_with?('Statement[0]:')

# ---------------------------------------------------- no_wildcard_action ----

assert 'Action "*" is a finding',
       offenders(doc([{ 'Effect' => 'Allow', 'Action' => '*', 'Resource' => 'arn:aws:s3:::b/*' }]),
                 'no_wildcard_action').length == 1

assert 'Action "*:*" is a finding',
       offenders(doc([{ 'Effect' => 'Allow', 'Action' => ['*:*'], 'Resource' => '*' }]),
                 'no_wildcard_action').length == 1

assert 'a prefixed wildcard action is NOT a finding',
       offenders(doc([{ 'Effect' => 'Allow', 'Action' => %w[s3:Get* s3:List*],
                        'Resource' => '*' }]),
                 'no_wildcard_action').empty?

assert 'Deny on "*" is not a finding',
       offenders(doc([{ 'Effect' => 'Deny', 'Action' => '*', 'Resource' => '*' }]),
                 'no_wildcard_action').empty?

# ----------------------------------------------------- no_admin_star_star ---

admin = doc([{ 'Effect' => 'Allow', 'Action' => '*', 'Resource' => '*' }])
assert 'Action * on Resource * is a finding',
       offenders(admin, 'no_admin_star_star').length == 1
assert 'Action * on a named resource is not',
       offenders(doc([{ 'Effect' => 'Allow', 'Action' => '*',
                        'Resource' => 'arn:aws:s3:::bucket/*' }]),
                 'no_admin_star_star').empty?
assert 'named actions on Resource * are not',
       offenders(doc([{ 'Effect' => 'Allow', 'Action' => 's3:GetObject', 'Resource' => '*' }]),
                 'no_admin_star_star').empty?
assert 'the star-star statement is found among several',
       offenders(doc([{ 'Effect' => 'Allow', 'Action' => 's3:GetObject', 'Resource' => '*' },
                      { 'Sid' => 'Admin', 'Effect' => 'Allow', 'Action' => ['*'],
                        'Resource' => ['*'] }]),
                 'no_admin_star_star') == ['Sid Admin: Effect Allow with Action * on ' \
                                           'Resource * — full administrative access']

# ------------------------- no_cross_account_principal_without_condition -----

cross = doc([{ 'Effect' => 'Allow', 'Principal' => { 'AWS' => 'arn:aws:iam::999988887777:root' },
               'Action' => 'sns:Publish' }])
assert 'another account with no condition is a finding',
       offenders(cross, 'no_cross_account_principal_without_condition',
                 account_id: '111122223333').length == 1
assert 'the scanning account itself is not cross-account',
       offenders(doc([{ 'Effect' => 'Allow',
                        'Principal' => { 'AWS' => 'arn:aws:iam::111122223333:role/app' },
                        'Action' => 'sns:Publish' }]),
                 'no_cross_account_principal_without_condition',
                 account_id: '111122223333').empty?
assert 'another account WITH a condition is not a finding',
       offenders(doc([{ 'Effect' => 'Allow',
                        'Principal' => { 'AWS' => 'arn:aws:iam::999988887777:root' },
                        'Action' => 'sns:Publish',
                        'Condition' => { 'StringEquals' => { 'aws:PrincipalOrgID' => 'o-x' } } }]),
                 'no_cross_account_principal_without_condition',
                 account_id: '111122223333').empty?
assert 'a bare 12-digit account principal counts',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => { 'AWS' => '999988887777' },
                        'Action' => 'sns:Publish' }]),
                 'no_cross_account_principal_without_condition',
                 account_id: '111122223333').length == 1
assert 'an unknown scanning account over-reports rather than under-reports',
       offenders(cross, 'no_cross_account_principal_without_condition').length == 1

# ------------------------------------------------ no_account_root_principal -

assert 'a root ARN is a finding',
       offenders(doc([{ 'Effect' => 'Allow',
                        'Principal' => { 'AWS' => 'arn:aws:iam::111122223333:root' },
                        'Action' => 'sts:AssumeRole' }]),
                 'no_account_root_principal').length == 1
assert 'a bare account number is a finding',
       offenders(doc([{ 'Effect' => 'Allow', 'Principal' => { 'AWS' => '111122223333' },
                        'Action' => 'sts:AssumeRole' }]),
                 'no_account_root_principal').length == 1
assert 'a GovCloud root ARN is a finding',
       offenders(doc([{ 'Effect' => 'Allow',
                        'Principal' => { 'AWS' => 'arn:aws-us-gov:iam::111122223333:root' },
                        'Action' => 'sts:AssumeRole' }]),
                 'no_account_root_principal').length == 1
assert 'a named role in the same account is not',
       offenders(doc([{ 'Effect' => 'Allow',
                        'Principal' => { 'AWS' => 'arn:aws:iam::111122223333:role/deploy' },
                        'Action' => 'sts:AssumeRole' }]),
                 'no_account_root_principal').empty?
assert 'a Deny on root is not',
       offenders(doc([{ 'Effect' => 'Deny',
                        'Principal' => { 'AWS' => 'arn:aws:iam::111122223333:root' },
                        'Action' => '*' }]),
                 'no_account_root_principal').empty?

# ------------------------------------------------------- gh_oidc_sub_safe ---

def gh(condition)
  statement = {
    'Effect' => 'Allow',
    'Principal' => {
      'Federated' => 'arn:aws:iam::111122223333:oidc-provider/' \
                     'token.actions.githubusercontent.com',
    },
    'Action' => 'sts:AssumeRoleWithWebIdentity',
  }
  statement['Condition'] = condition if condition
  doc([statement])
end

SUB = 'token.actions.githubusercontent.com:sub'.freeze

assert 'no condition at all is a finding',
       offenders(gh(nil), 'gh_oidc_sub_safe').length == 1
assert 'a condition that does not constrain :sub is a finding',
       offenders(gh('StringEquals' => { 'token.actions.githubusercontent.com:aud' =>
                                        'sts.amazonaws.com' }),
                 'gh_oidc_sub_safe').length == 1
assert 'a Null presence check on :sub is a finding',
       offenders(gh('Null' => { SUB => 'false' }), 'gh_oidc_sub_safe').length == 1
assert 'sub "*" is a finding',
       offenders(gh('StringLike' => { SUB => '*' }), 'gh_oidc_sub_safe').length == 1
assert 'sub "repo:acme/*" is a finding',
       offenders(gh('StringLike' => { SUB => 'repo:acme/*' }), 'gh_oidc_sub_safe').length == 1
assert 'a concrete repo passes',
       offenders(gh('StringEquals' => { SUB => 'repo:acme/widgets:ref:refs/heads/main' }),
                 'gh_oidc_sub_safe').empty?
assert 'a concrete repo with a wildcard ref passes',
       offenders(gh('StringLike' => { SUB => 'repo:acme/widgets:*' }),
                 'gh_oidc_sub_safe').empty?
assert 'ForAllValues:StringLike is recognised as constraining',
       offenders(gh('ForAllValues:StringLike' => { SUB => 'repo:acme/widgets:*' }),
                 'gh_oidc_sub_safe').empty?
assert 'a list of subs is safe only if every element is',
       offenders(gh('StringLike' => { SUB => ['repo:acme/widgets:*', 'repo:acme/*'] }),
                 'gh_oidc_sub_safe').length == 1
assert 'a role with no GitHub federated principal is clean, not skipped',
       offenders(doc([{ 'Effect' => 'Allow',
                        'Principal' => { 'Service' => 'ec2.amazonaws.com' },
                        'Action' => 'sts:AssumeRole' }]),
                 'gh_oidc_sub_safe').empty?

# --------------------------------------------------- the anti-silence test --
#
# The single most expensive failure mode here is a predicate that cannot return
# an offender. Every predicate is asserted to fire on at least one document
# above; this asserts the property directly, so a future predicate added without
# a positive case is caught.
firing = {
  'no_wildcard_principal' => doc([{ 'Effect' => 'Allow', 'Principal' => '*',
                                    'Action' => 's3:GetObject' }]),
  'no_wildcard_action' => doc([{ 'Effect' => 'Allow', 'Action' => '*', 'Resource' => 'x' }]),
  'no_admin_star_star' => admin,
  'no_cross_account_principal_without_condition' => cross,
  'no_account_root_principal' => doc([{ 'Effect' => 'Allow',
                                        'Principal' => { 'AWS' => '111122223333' },
                                        'Action' => '*' }]),
  'gh_oidc_sub_safe' => gh(nil),
}
PolicyDocument::PREDICATES.each do |name|
  assert "#{name} has a document it fires on",
         !firing[name].nil? && !offenders(firing[name], name, account_id: '000011112222').empty?
end

# ---------------------------------------------------------------- report ----

if FAILURES.empty?
  puts "OK — #{COUNT[0]} assertion(s), every predicate proven both to fire and to stay quiet."
  exit 0
end

puts "::error::#{FAILURES.length} of #{COUNT[0]} policy-predicate assertion(s) failed."
FAILURES.each { |f| puts "  #{f}" }
exit 1
