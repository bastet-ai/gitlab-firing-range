def t(src)
  $stderr.puts "### #{src[0, 40]}"
  begin
    Regexp.new(src)
    $stderr.puts "  ok"
  rescue Exception => e
    $stderr.puts "  #{e.class}"
  end
end
t("(?:ab){3}")
t("(?:a{5}){3}")
t("(?:abc){100000,}")
t("(?:abc|xy){100000,}")
