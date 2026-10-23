begin
  Regexp.new("(?:" + "a" * 13000 + "|b){100000,}")
rescue Exception => e
  $stderr.puts "E #{e.class}"
end
