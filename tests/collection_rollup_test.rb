#!/usr/bin/env ruby
# frozen_string_literal: true
#
# Semantics fixture for libraries/_checkov_collection.rb.
#
# The collection roll-up is the one piece of this profile whose behaviour cannot
# be read off the generated Ruby: `none_of` and `all_of` are vacuously true over
# an empty collection, a condition is existential over its paths, and an omitted
# API member takes the condition's `when_absent` verdict. Each of those is a way
# to write a control that is structurally unable to fail, and neither
# `cinc-auditor check` nor `json` evaluates a control body, so none of them are
# visible before an exec against a real account.
#
# So the semantics are pinned here, against hand-built rows in the exact shape
# `Aws::Structure#to_h` produces -- symbol keys, nested hashes and arrays, and
# NO key at all for a member the response omitted.
#
#     docker run --rm -v "$PWD:/work" -w /work --entrypoint ruby \
#       risksentinel/sparc-auditor@sha256:a388fd08ebf64750d233f267a514d8bbd0bb3372f319b35f6098560026ee7f90 tests/collection_rollup_test.rb
#
# `--entrypoint ruby` is not optional: the image's entrypoint is cinc-auditor, so
# without it the command becomes `cinc-auditor ruby ...` and dies with "Could not
# find command ruby" — which is how the first version of this header was wrong.
#
# The lambdas below are copied from what tools/render_controls.py renders for
# CKV_AWS_24 and CKV_AWS_127; if predicate_for changes, they change with it.

require_relative "../libraries/_checkov_collection"

ANY_IPV4 = '0.0.0.0/0'.freeze


SSH = [
  { paths: ['from_port'], when_absent: true, test: ->(v) { v <= 22 } },
  { paths: ['to_port'],   when_absent: true, test: ->(v) { v >= 22 } },
  { paths: ['ip_ranges.cidr_ip', 'ipv_6_ranges.cidr_ipv_6'],
    test: ->(v) { [ANY_IPV4, '::/0'].include?(v) } },
].freeze

def t(label, got, want)
  puts(format('%-58s %s  (got %p)', label, got == want ? 'ok  ' : 'FAIL', got))
  $bad = true if got != want
end

open_ssh = [{ ip_protocol: 'tcp', from_port: 22, to_port: 22,
              ip_ranges: [{ cidr_ip: ANY_IPV4 }], ipv_6_ranges: [], user_id_group_pairs: [] }]
t('open tcp/22 to the world -> none_of false', CheckovCollection.none_of?(open_ssh, SSH), false)

wide = [{ ip_protocol: 'tcp', from_port: 0, to_port: 65535,
          ip_ranges: [{ cidr_ip: '10.0.0.0/8' }, { cidr_ip: ANY_IPV4 }] }]
t('wide range, second cidr open -> none_of false', CheckovCollection.none_of?(wide, SSH), false)

allproto = [{ ip_protocol: '-1', ip_ranges: [{ cidr_ip: ANY_IPV4 }] }]
t('protocol -1, ports omitted -> none_of false', CheckovCollection.none_of?(allproto, SSH), false)

v6 = [{ ip_protocol: 'tcp', from_port: 20, to_port: 25,
        ip_ranges: [], ipv_6_ranges: [{ cidr_ipv_6: '::/0' }] }]
t('ipv6 ::/0 over 20-25 -> none_of false', CheckovCollection.none_of?(v6, SSH), false)

icmp = [{ ip_protocol: 'icmp', from_port: -1, to_port: -1, ip_ranges: [{ cidr_ip: ANY_IPV4 }] }]
t('icmp -1/-1 (all types, not port 22) -> none_of true', CheckovCollection.none_of?(icmp, SSH), true)

corp = [{ ip_protocol: 'tcp', from_port: 22, to_port: 22, ip_ranges: [{ cidr_ip: '10.0.0.0/8' }] }]
t('tcp/22 from a private range -> none_of true', CheckovCollection.none_of?(corp, SSH), true)

peer = [{ ip_protocol: 'tcp', from_port: 22, to_port: 22, ip_ranges: [],
          user_id_group_pairs: [{ group_id: 'sg-0123456789abcdef0' }] }]
t('tcp/22 from a peer SG -> none_of true', CheckovCollection.none_of?(peer, SSH), true)

http = [{ ip_protocol: 'tcp', from_port: 443, to_port: 443, ip_ranges: [{ cidr_ip: ANY_IPV4 }] }]
t('tcp/443 open to the world -> none_of true', CheckovCollection.none_of?(http, SSH), true)

t('empty rule list -> none_of true (vacuous)', CheckovCollection.none_of?([], SSH), true)
t('nil field -> none_of true (vacuous)', CheckovCollection.none_of?(nil, SSH), true)

mixed = open_ssh + corp + http
t('one bad among three -> none_of false', CheckovCollection.none_of?(mixed, SSH), false)

# --- all_of, nested sub-path, not_empty -------------------------------------
CERT = [{ paths: ['listener.ssl_certificate_id'],
          test: ->(v) { !v.nil? && !(v.respond_to?(:empty?) && v.empty?) } }].freeze

both = [{ listener: { protocol: 'HTTPS', ssl_certificate_id: 'arn:aws:acm:1' } },
        { listener: { protocol: 'SSL', ssl_certificate_id: 'arn:aws:acm:2' } }]
t('every listener has a cert -> all_of true', CheckovCollection.all_of?(both, CERT), true)

one_bare = both + [{ listener: { protocol: 'HTTP', load_balancer_port: 80 } }]
t('one plain HTTP listener -> all_of false', CheckovCollection.all_of?(one_bare, CERT), false)

blank = [{ listener: { protocol: 'HTTPS', ssl_certificate_id: '' } }]
t('empty-string cert -> all_of false', CheckovCollection.all_of?(blank, CERT), false)

t('no listeners -> all_of true (vacuous)', CheckovCollection.all_of?([], CERT), true)
t('nil field -> all_of true (vacuous)', CheckovCollection.all_of?(nil, CERT), true)

# --- any_of, multi-path disjunction ------------------------------------------
LOGS = [{ paths: %w[cloud_watch_logs.enabled firehose.enabled s3.enabled],
          test: ->(v) { v == true } }].freeze
t('one of three destinations on -> any_of true',
  CheckovCollection.any_of?([{ cloud_watch_logs: { enabled: false }, firehose: { enabled: false },
                               s3: { enabled: true } }], LOGS), true)
t('all three off -> any_of false',
  CheckovCollection.any_of?([{ cloud_watch_logs: { enabled: false }, firehose: { enabled: false },
                               s3: { enabled: false } }], LOGS), false)
t('nil field -> any_of false (fails, no guard needed)', CheckovCollection.any_of?(nil, LOGS), false)

# --- shape edge cases --------------------------------------------------------
t('a Hash is ONE element, not its pairs',
  CheckovCollection.any_of?({ from_port: 22, to_port: 22, ip_ranges: [{ cidr_ip: ANY_IPV4 }] }, SSH), true)
t('false survives the nil filter',
  CheckovCollection.any_of?([{ a: false }], [{ paths: ['a'], test: ->(v) { v == false } }]), true)
t('leaf array arrives whole',
  CheckovCollection.dig_all({ ids: %w[a b] }, 'ids'), [%w[a b]])
t('mid-path array fans out',
  CheckovCollection.dig_all({ r: [{ c: 'x' }, { c: 'y' }] }, 'r.c'), %w[x y])
t('string keys work too',
  CheckovCollection.dig_all({ 'r' => [{ 'c' => 'x' }] }, 'r.c'), %w[x])
t('missing member reaches nothing', CheckovCollection.dig_all({ a: 1 }, 'b.c'), [])

# --- explain: a failure names the offending ELEMENTS, not the collection (#19) --
# The message used to be the whole collection inspected and truncated by RSpec:
# for a task definition, a slice of one container's command and the tail of
# another's secret references, with neither the failing container nor the tested
# field in it.
READ_ONLY = [{ paths: ['readonly_root_filesystem'], test: ->(v) { v == true }, when_absent: false }].freeze
CONTAINERS = [
  { name: 'web', readonly_root_filesystem: true, command: %w[sh -c run],
    secrets: [{ name: 'TOKEN', value_from: 'arn:aws:secretsmanager:region:acct:secret:x' }] },
  { name: 'sidecar', command: %w[tail -f] },
  { name: 'job', readonly_root_filesystem: false },
].freeze
why = CheckovCollection.explain(:all_of, CONTAINERS, READ_ONLY,
                                'have only elements where readonly_root_filesystem == True')
t('all_of: counts the elements and the offenders',
  why.include?('expected 3 element(s)') && why.include?('2 do not'), true)
t('all_of: names an offender whose member is absent',
  why.include?("'sidecar' (readonly_root_filesystem: (absent))"), true)
t('all_of: names an offender with the value it has',
  why.include?("'job' (readonly_root_filesystem: false)"), true)
t('all_of: does not name the compliant element', why.include?("'web'"), false)
t('all_of: shows nothing the conditions do not read',
  why.include?('secretsmanager') || why.include?('tail') || why.include?('command'), false)
t('none_of: names the elements that DO match',
  CheckovCollection.explain(:none_of, CONTAINERS, READ_ONLY, 'x').include?("1 do: 'web'"), true)
t('any_of: says none does, and lists what was looked at',
  CheckovCollection.explain(:any_of, [{ name: 'job', readonly_root_filesystem: false }], READ_ONLY, 'x')
                   .include?("at least one of 1 element(s) to x; none does: 'job'"), true)
t('an element with no name is identified by position',
  CheckovCollection.explain(:all_of, [{ a: 1 }], READ_ONLY, 'x').include?('element 0 ('), true)
t('more offenders than are shown are counted, not dropped',
  CheckovCollection.explain(:all_of, Array.new(7) { |i| { name: "c#{i}" } }, READ_ONLY, 'x')
                   .end_with?('and 2 more'), true)

if $bad
  warn 'FAILED — the roll-up does not mean what the generator says it means.'
  exit 1
end
puts 'OK — every roll-up case behaves as tools/render_controls.py documents.'
