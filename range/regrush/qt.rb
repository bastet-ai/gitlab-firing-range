def t(src)
  $stderr.puts "@@T #{src.size}"
  begin
    Regexp.new(src)
    $stderr.puts "@@OK"
  rescue Exception => e
    $stderr.puts "@@E #{e.class}"
  end
end
lit = "a" * 13000
alt = ("ab" * 6500)   # alternation target, un-foldable
t("(?:#{lit}|b){100000,}")          # alt target, infinite, tlen~?
t("(a#{lit[0,1]}|b){100000,}")
t("(?:#{lit}|b){100000}")           # finite
t("(?:[a-z]#{lit[0,500]}|q){100000,}")
