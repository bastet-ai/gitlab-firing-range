src = "a{30,31}" * 33000
re = Regexp.new(src)
puts "compiled"
$stdout.flush
t0 = Time.now
r = re.match("a" * 984_000)
puts "matched=#{!r.nil?} took=#{Time.now - t0}"
