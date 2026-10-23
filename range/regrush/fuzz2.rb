# fuzz2.rb - batch-mode structured regex-compile fuzzer for CVE-2026-110264.
# Child prints "i=N" before compiling pattern N of a batch file (one JSON per
# line). A native crash kills the child mid-batch; parent re-runs the crasher
# pattern alone to confirm + capture signal. Ruby errors rescued in child.
require 'json'

LOG   = ARGV[0] || '/tmp/fuzz.log'
BATCH = (ARGV[1] || 500).to_i      # patterns per child
BATCHES = (ARGV[2] || 200).to_i    # total batches
SEED0 = (ARGV[3] || 1234).to_i

CHILD_SRC = <<~'RB'
  require 'json'
  patterns = File.readlines(ARGV[0]).map { |l| JSON.parse(l, symbolize_names: true) }
  patterns.each_with_index do |rec, i|
    $stdout.flush
    puts "i=#{rec[:i]}"
    $stdout.flush
    begin
      Regexp.new(rec[:s])
    rescue Exception
      # ruby-level error is fine; native crash aborts here
    end
  end
  puts "BATCH_DONE"
RB

rd = lambda { |max_len, giant_p|
  n = giant_p ? rand(10) + 8 : rand(1 + max_len) + 1
  s = (0...n).map { rand(10) }.join
  s.sub(/\A0+(?=\d)/, rand(1..9).to_s)
}

quant = lambda {
  giant = rand(6) == 0
  case rand(8)
  when 0 then "*"
  when 1 then "+"
  when 2 then "?"
  when 3 then "{#{rd.(6, giant)}}"
  when 4 then "{#{rd.(6, giant)},#{rd.(6, giant)}}"
  when 5 then "{#{rd.(6, giant)},}"
  when 6 then "{,#{rd.(6, giant)}}"
  else ["*?", "+?", "??", "*+", "?+", "{#{rd.(6, giant)}}?"].sample
  end
}

atom = ->(d) {
  case rand(24)
  when 0 then "a"
  when 1 then rand(32..126).chr
  when 2 then "\\x{#{rd.(7, rand(4).zero?)}}"
  when 3 then "\\#{rd.(4, rand(5).zero?)}}"
  when 4 then "[a-z#{rd.(4, false)}-#{rd.(4, false)}]"
  when 5 then "."
  when 6 then "[^\\x{#{rd.(7, rand(4).zero?)}}]"
  when 7 then "\\k<#{rd.(5, rand(4).zero?)}>"
  when 8 then "\\k<-#{rd.(5, rand(4).zero?)}>"
  when 9 then "\\g<#{rd.(5, rand(4).zero?)}>"
  when 10 then "(?<g#{d}>#{quant.()}a)"
  when 11 then "(?<n#{d % 30}>a)"
  when 12 then "(?<=#{atom.(d + 1)})"
  when 13 then "(?<!#{atom.(d + 1)})"
  when 14 then "(?>a)"
  when 15 then "(?i:a)"
  when 16 then "(?(#{rd.(5, rand(3).zero?)})a|b)"
  when 17 then "((?<x#{d % 10}>)\\g<x#{d % 10}>?)?"
  when 18 then "\\p{Alnum}"
  when 19 then "[[:alpha:][:digit:]]"
  when 20 then "\\M-\\C-#{rand(32..126).chr}"
  when 21 then ("a".."z").to_a.sample * (1 + rand(4))
  when 22 then "\\g<n#{rand(0...30)}>"
  when 23 then "(?~#{atom.(d + 1)})"
  end
}

pattern = ->(d) {
  return atom.(d) if d >= 5 || rand(3).zero?
  case rand(6)
  when 0 then "(?:#{pattern.(d + 1)})#{quant.()}"
  when 1 then "(#{pattern.(d + 1)})#{quant.()}"
  when 2 then "#{pattern.(d + 1)}|#{pattern.(d + 1)}"
  when 3 then "#{pattern.(d + 1)}#{pattern.(d + 1)}"
  when 4 then "(?:#{pattern.(d + 1)}#{quant.()})#{quant.()}"
  when 5 then "(?<k#{d}>#{pattern.(d + 1)})#{quant.()}"
  end
}

gen = lambda { |seed|
  srand(seed)
  { s: pattern.(0) }
}

f = File.open(LOG, 'a')
crashes = []
f.puts "START batches=#{BATCHES} batch=#{BATCH} seed0=#{SEED0}"

(BATCHES).times do |b|
  seed = SEED0 + b
  # generate batch deterministically from seed
  recs = []
  srand(seed)
  BATCH.times { |i| recs << { i: i, s: pattern.(0) } }
  tmp = "/tmp/fz_#{seed}.jsonl"
  File.write(tmp, recs.map { |r| JSON.generate(r) }.join("\n"))

  out = IO.popen(
    [{ 'RUBYOPT' => '' }, 'ruby', '-e', CHILD_SRC, tmp,
     err: [:child, :out]],
    &:read
  )
  st = $?
  unless st.success?
    # find last started index
    last = out[/i=(\d+)\s*\z/m, 1] || out.scan(/i=(\d+)/).map { |x| x[0].to_i }.last
    f.puts "BATCH CRASH seed=#{seed} status=#{st.exitstatus ? "exit#{st.exitstatus}" : "sig#{st.termsig}"} last_i=#{last} out_tail=#{out[-200..-1].inspect}"
    # confirm individually: run remaining candidates from last_i
    if last
      li = last.to_i
      (li..[li + 8, BATCH - 1].min).each do |j|
        rc = recs[j]
        one = IO.popen(['ruby', '-e', CHILD_SRC, '/dev/stdin', in: IO.popen? ? nil : nil] ) rescue nil
        # simpler: write single file
        File.write(tmp + ".1", JSON.generate(i: 0, s: rc[:s]))
        o2 = IO.popen(['ruby', '-e', CHILD_SRC, tmp + '.1'], &:read)
        s2 = $?
        unless s2.success?
          crashes << { seed: seed, i: j, s: rc[:s], sig: s2.termsig, exit: s2.exitstatus }
          f.puts "CONFIRMED CRASH seed=#{seed} i=#{j} sig=#{s2.termsig} src=#{rc[:s][0, 300].inspect}"
          f.flush
        end
      end
    end
  end
  File.delete(tmp) rescue nil
  File.delete(tmp + '.1') rescue nil
  f.puts "batch #{b} done (#{(b + 1) * BATCH} samples, #{crashes.size} confirmed)" if (b % 10).zero?
  f.flush
end
f.puts "DONE crashes=#{crashes.size}"
crashes.first(20).each { |c| f.puts "FINAL #{JSON.generate(c)[0, 400]}" }
f.close
