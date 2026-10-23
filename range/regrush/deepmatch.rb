src = "(?:" + "a" * 25000 + "){100000}"
re = Regexp.new(src)
puts "compiled; program walk test:"
[250000, 500000, 1000000].each do |n|
  puts "match len=#{n}"
  $stdout.flush
  r = re.match("a" * n)
  puts "  => #{!r.nil?}"
  $stdout.flush
end
puts "DONE"
