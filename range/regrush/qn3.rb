def t(src, m = nil)
  $stderr.puts "### #{src[0, 30]}"
  begin
    re = Regexp.new(src)
    $stderr.puts "  compiled"
    re.match(m) if m
    $stderr.puts "  matched"
  rescue Exception => e
    $stderr.puts "  #{e.class}"
  end
end
t("(?:ab){3}", "ababab")
t("(?:abc|xy){100000,}", nil)
t("(?:" + "a" * 13000 + "){100000,}", nil)
