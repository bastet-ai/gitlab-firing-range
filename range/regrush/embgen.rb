# embgen.rb - standalone pattern generator for embedded-ruby fuzzing.
# Emits JSONL {"i":n,"s":pattern} to stdout. Grammar v2 (matches fuzz2.rb).
BATCH = (ARGV[0] || 500).to_i
SEED  = (ARGV[1] || 1234).to_i

rd = lambda { |max_len, giant_p|
  n = giant_p ? rand(10) + 8 : rand(1 + max_len) + 1
  (0...n).map { rand(10) }.join.sub(/\A0+(?=\d)/, rand(1..9).to_s)
}

quant = lambda {
  giant = rand(6) == 0
  case rand(8)
  when 0 then "*"
  when 1 then "+"
  when 2 then "?"
  when 3 then "{#{rd.(6, giant)}}"
  when 4 then "{#{rd.(6, giant)},#{rd.(6, giant)}}"
  when 5 then "{#{rd.(6, giant)},}"
  when 6 then "{,#{rd.(6, giant)}}"
  else ["*?", "+?", "??", "*+", "?+", "{#{rd.(6, giant)}}?"].sample
  end
}

atom = ->(d) {
  case rand(30)
  when 0 then "a"
  when 1 then rand(32..126).chr
  when 2 then "\\x{#{rd.(7, rand(4).zero?)}}"
  when 3 then "\\#{rd.(4, rand(5).zero?)}"
  when 4 then "[a-z#{rd.(4, false)}-#{rd.(4, false)}]"
  when 5 then "."
  when 6 then "[^\\x{#{rd.(7, rand(4).zero?)}}]"
  when 7 then "\\k<#{rd.(5, rand(4).zero?)}>"
  when 8 then "\\k<-#{rd.(5, rand(4).zero?)}>"
  when 9 then "\\g<#{rd.(5, rand(4).zero?)}>"
  when 10 then "(?<g#{d}>#{quant.()}a)"
  when 11 then "(?<n#{d % 30}>a)"
  when 12 then "(?<=#{atom.(d + 1)})"
  when 13 then "(?<!#{atom.(d + 1)})"
  when 14 then "(?>a)"
  when 15 then "(?i:a)"
  when 16 then "(?(#{rd.(5, rand(3).zero?)})a|b)"
  when 17 then "((?<x#{d % 10}>)\\g<x#{d % 10}>?)?"
  when 18 then "\\p{Alnum}"
  when 19 then "[[:alpha:][:digit:]]"
  when 20 then "\\M-\\C-#{rand(32..126).chr}"
  when 21 then ["a", "k", "s", "ß", "ẞ", "ﬁ", "Σ", "σ", "ς", "ſ", "\u212A", "\u1F60", "ẛ", "ﬅ"].sample * (1 + rand(6))
  when 22 then "\\g<n#{rand(0...30)}>"
  when 23 then "(?~#{atom.(d + 1)})"
  when 24 then "[kſẞß\u212A]{#{rd.(3, false)}}"
  when 25 then "[a-#{["\\x{212A}", "\\x{1F600}", "\\x{10FFFF}", "\\x{7FFFFFFF}"].sample}]"
  when 26 then "(?i)#{["k", "ß", "ﬁ", "\u212A"].sample * (1 + rand(4))}"
  when 27 then "\\x{#{[0x212A, 0x1F82, 0x1F87, 0x104B3, 0x7FFFFFFF, rand(0x80..0x10FFFF)].sample}}"
  when 28 then "\\u{#{rd.(6, rand(3).zero?)}}"
  when 29 then "(?<=#{["k", "ß", "ﬁ", "\u212A", "a"].sample * (1 + rand(3))})"
  end
}

pattern = ->(d) {
  return atom.(d) if d >= 5 || rand(3).zero?
  case rand(6)
  when 0 then "(?:#{pattern.(d + 1)})#{quant.()}"
  when 1 then "(#{pattern.(d + 1)})#{quant.()}"
  when 2 then "#{pattern.(d + 1)}|#{pattern.(d + 1)}"
  when 3 then "#{pattern.(d + 1)}#{pattern.(d + 1)}"
  when 4 then "(?:#{pattern.(d + 1)}#{quant.()})#{quant.()}"
  when 5 then "(?<k#{d}>#{pattern.(d + 1)})#{quant.()}"
  end
}

require 'json'
srand(SEED)
(BATCH).times do |i|
  puts JSON.generate(i: i, s: pattern.(0))
end
