src = "a{30,31}" * 65600
re = Regexp.new(src)
puts "compiled (len=#{src.size})"
$stdout.flush
t0 = Time.now
r = re.match("a" * 2_033_600)
puts "matched=#{!r.nil?} took=#{Time.now - t0}"
