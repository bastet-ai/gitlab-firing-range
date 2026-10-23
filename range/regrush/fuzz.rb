# fuzz.rb - structured regex-compile fuzzer for CVE-2026-110264 shaping.
# Runs inside the regrush harness container. Each sample compiles in a forked
# child; Ruby-level errors are rescued so ONLY native crashes (signal exit)
# surface. Parent kills children after N sec (hang detection).
LOG = ARGV[0] || '/tmp/fuzz.log'
ITERS = (ARGV[1] || 30000).to_i
CHILD_TIMEOUT = 3.0

rand_digits = ->(max_len) {
  # sometimes wrap-prone giant digit strings
  n = rand(6) == 0 ? rand(10) + 6 : rand(1 + max_len) + 1
  (0...n).map { rand(10) }.join.sub(/^0+/, [rand(1..9)].join)
}

quant = -> {
  case rand(8)
  when 0 then "*"
  when 1 then "+"
  when 2 then "?"
  when 3 then "{#{rand_digits.call(6)}}"
  when 4 then "{#{rand_digits.call(6)},#{rand_digits.call(6)}}"
  when 5 then "{#{rand_digits.call(6)},}"
  when 6 then "{,#{rand_digits.call(6)}}"
  else "*?" + "?+"[rand(2)]
  end
}

atom = ->(d) {
  case rand(22)
  when 0 then "a"
  when 1 then rand(128).chr
  when 2 then "\\x{#{rand_digits.call(6)}}"
  when 3 then "\\#{rand(1..3999)}"
  when 4 then "[a-z#{rand_digits.call(4)}-#{rand_digits.call(4)}]"
  when 5 then "."
  when 6 then "[^\\x{#{rand_digits.call(7)}}]"
  when 7 then "\\k<#{rand(1..32770)}>"
  when 8 then "\\k<-#{rand(1..32770)}>"
  when 9 then "\\g<#{rand(1..32770)}>"
  when 10 then "(?<g#{d}>#{q = quant.call}a)"
  when 11 then "(?<n#{d % 20}>a)"
  when 12 then "(?<=#{atom.call(d + 1)})"
  when 13 then "(?<!#{atom.call(d + 1)})"
  when 14 then "(?>a)"
  when 15 then "(?i:a)"
  when 16 then "(?(#{rand(1..40000)})a|b)"
  when 17 then "((?<x#{d % 10}>)\\g<x#{d % 10}>?)?"
  when 18 then "\\p{Alpha}"
  when 19 then "[[:alpha:][:digit:]]"
  when 20 then "\\M-\\C-#{rand(128).chr}"
  when 21 then rand(97..122).chr * (1 + rand(3))
  end
}

depth = 0
pattern = ->(d) {
  return atom.call(d) if d >= 4 || rand(3) == 0
  case rand(5)
  when 0 then "(?:#{pattern.call(d + 1)})#{quant.call}"
  when 1 then "(#{pattern.call(d + 1)})#{quant.call}"
  when 2 then "#{pattern.call(d + 1)}|#{pattern.call(d + 1)}"
  when 3 then "#{pattern.call(d + 1)}#{pattern.call(d + 1)}"
  when 4 then "(?:#{pattern.call(d + 1)}#{quant.call})#{quant.call}"
  end
}

crashes = 0
hangs = 0
f = File.open(LOG, 'a')
t_start = Process.clock_gettime(Process::CLOCK_MONOTONIC)

ITERS.times do |i|
  src = pattern.call(0)
  pid = fork do
    begin
      Regexp.new(src)
    rescue Exception
      # Ruby-level failure: fine
    end
    Kernel.exit!(0)
  end
  status = nil
  deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + CHILD_TIMEOUT
  loop do
    _, status = Process.waitpid(pid, Process::WNOHANG)
    break unless status.nil?
    if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      Process.kill('KILL', pid)
      Process.waitpid(pid)
      hangs += 1
      f.puts "HANG #{src[0, 300].inspect}"
      f.flush
      break
    end
  end
  if status && !status.exited?
    crashes += 1
    f.puts "CRASH sig=#{status.termsig} #{src[0, 300].inspect}"
    f.flush
  end
  if (i % 5000).zero?
    f.puts "progress #{i}/#{ITERS} crashes=#{crashes} hangs=#{hangs}"
    f.flush
  end
end
el = Process.clock_gettime(Process::CLOCK_MONOTONIC) - t_start
f.puts "DONE iters=#{ITERS} crashes=#{crashes} hangs=#{hangs} secs=#{el.round(1)}"
f.close
