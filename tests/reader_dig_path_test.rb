#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Semantics fixture for the field walk in libraries/aws_api_assets.rb.
#
# Why this is a separate proof
# ---------------------------
# `dig_path` is where the api reader turns "encryption_configuration.encryption_type"
# into a value on the row, and it is the only place a BOOLEAN member is read.
# `node[key.to_sym] || node[key]` read a member the API returned as `false` as
# nil -- and `false` is the failing state of every `equals: true` mapping. The
# generated template then filters a nil field out of scope as "does not express
# this setting", so a non-compliant asset vanished from the population: a
# boundary where every asset failed rendered NOT APPLICABLE, and one where some
# failed reported 100% pass over the survivors. Ten mapped checks read a boolean
# this way.
#
# Nothing else in the pipeline sees it. `check` and `json` do not evaluate a
# control body; the roll-up fixture does not exercise the reader; and an exec
# against an account whose assets all happen to be compliant reports the same
# clean pass either way.
#
#     docker run --rm -v "$PWD:/work" -w /work --entrypoint ruby \
#       risksentinel/sparc-auditor:v0.5.0 tests/reader_dig_path_test.rb
#
# `--entrypoint ruby` is not optional: the image's entrypoint is cinc-auditor.
#
# The method is LIFTED from the reader's own source rather than copied, because
# a copy is a second authority that drifts. aws_api_assets.rb cannot simply be
# required here: it inherits AwsResourceBase from the vendored resource pack,
# which only loads inside a profile run.

SOURCE = File.expand_path("../libraries/aws_api_assets.rb", __dir__)

body = File.read(SOURCE)[/^  def dig_path\(item, path\)$.*?^  end$/m]
abort "could not lift dig_path out of #{SOURCE} — has it been renamed?" if body.nil?

Reader = Class.new { module_eval(body.gsub(/^  /, "")) }.new

def t(label, got, want)
  puts(format('%-58s %s  (got %p)', label, got == want ? 'ok  ' : 'FAIL', got))
  $bad = true if got != want
end

# The failing state of every `equals: true` mapping. This is the regression.
t('top-level false survives', Reader.dig_path({ encrypted: false }, 'encrypted'), false)
t('nested false survives',
  Reader.dig_path({ image_scanning_configuration: { scan_on_push: false } },
                  'image_scanning_configuration.scan_on_push'), false)
t('string-keyed false survives', Reader.dig_path({ 'encrypted' => false }, 'encrypted'), false)

# The states that must still read as nil, so the template's nil filter and the
# collection guard keep meaning what they say.
t('omitted member is nil', Reader.dig_path({ a: 1 }, 'b'), nil)
t('omitted level is nil', Reader.dig_path({ a: 1 }, 'b.c'), nil)
t('member explicitly nil is nil', Reader.dig_path({ a: nil }, 'a'), nil)
t('path continuing past a scalar is nil', Reader.dig_path({ a: 'x' }, 'a.b'), nil)
t('path continuing past a list is nil', Reader.dig_path({ a: [1] }, 'a.b'), nil)

# Ordinary reads, unchanged.
t('nested string', Reader.dig_path({ status: { state: 'RUNNING' } }, 'status.state'), 'RUNNING')
t('top-level true', Reader.dig_path({ encrypted: true }, 'encrypted'), true)
t('zero survives', Reader.dig_path({ retention_in_days: 0 }, 'retention_in_days'), 0)
t('empty string survives', Reader.dig_path({ kms_key_id: '' }, 'kms_key_id'), '')
t('a collection arrives whole',
  Reader.dig_path({ ip_permissions: [{ from_port: 22 }] }, 'ip_permissions'),
  [{ from_port: 22 }])

if $bad
  warn 'FAILED — the reader drops a value the mappings depend on.'
  exit 1
end
puts 'OK — dig_path reads false as false and an absent member as nil.'
