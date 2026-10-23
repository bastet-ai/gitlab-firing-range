begin; Regexp.new("(?:ab){3}").match("ababab"); rescue Exception; end; $stderr.puts "SCRIPT_END"
