[10500, 12000, 13000, 15000, 17000, 21000, 25000].each do |c|
  lit = "a" * c
  [["inf", "(?:#{lit}){100000,}"], ["fin", "(?:#{lit}){100000}"]].each do |form, src|
    $stderr.puts "=== PAT form=#{form} chars=#{c}"
    begin; Regexp.new(src); rescue Exception; end
  end
end
