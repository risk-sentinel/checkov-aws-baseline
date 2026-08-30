# Ensures the vendored inspec-aws `libraries/` directory is on $LOAD_PATH
# so `require "aws_backend"` resolves before any sibling local library
# file is parsed. Without this, `cinc-auditor exec` fails at library-load
# time with `cannot load such file -- aws_backend (LoadError)`.
#
# Why not `require_relative` from each sibling file: InSpec loads local
# library files via `instance_eval(content, source, line)` where `source`
# is a path *relative to the profile root* (e.g. "libraries/foo.rb"),
# not an absolute path. That makes `__FILE__` and `__dir__` relative too,
# and `Dir.pwd` is whatever the auditor's WORKDIR is (`/work` in our CI),
# not the profile directory — so neither `__dir__`-relative expansion nor
# `require_relative` can locate the vendor tree reliably.
#
# Instead: glob Dir.pwd for any vendored libraries directory, unshift
# onto $LOAD_PATH, and `require "aws_backend"` once. Ruby's require-once
# semantics means no duplicate load even if this file is somehow loaded
# twice.
#
# The leading underscore in the filename sorts us first in InSpec's
# alphabetical library-load order, so sibling files in this directory can
# inherit `AwsResourceBase` directly without any explicit require.

vendor_patterns = [
  File.join(Dir.pwd, "vendor", "*", "libraries"),
  File.join(Dir.pwd, "profiles", "*", "vendor", "*", "libraries"),
  File.join(Dir.pwd, "overlays", "*", "vendor", "*", "libraries"),
]
vendor_patterns.flat_map { |p| Dir.glob(p) }.uniq.each do |dir|
  $LOAD_PATH.unshift(dir) unless $LOAD_PATH.include?(dir)
end

require "aws_backend"
