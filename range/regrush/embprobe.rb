# embprobe.rb - stdin batch compile probe for embedded omnibus rubies.
# Reads JSONL {"i":n,"s":pattern} on STDIN; prints i= before compiling
# (plain + IGNORECASE); a native crash aborts at the last printed index.
require 'json'
$stdout.sync = true
until $stdin.eof?
  line = $stdin.gets
  rec = JSON.parse(line)
  puts "i=#{rec['i']}"
  begin
    Regexp.new(rec['s'])
    Regexp.new(rec['s'], Regexp::IGNORECASE)
  rescue Exception
    # Ruby-level error is fine; native crash aborts here
  end
end
puts 'PROBE_DONE'
