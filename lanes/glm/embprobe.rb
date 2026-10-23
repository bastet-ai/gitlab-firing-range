require "json"
$stdin.each_line do |l|
  l = l.strip
  next if l.empty?
  begin
    d = JSON.parse(l)
    Regexp.new(d["source"])
    puts "ok"
  rescue Exception => e
    puts "ERR:" + e.class.to_s
  end
end
