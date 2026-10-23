# embgen3.rb - grammar v3: escape-surviving / int-field shapes for the
# omnibus Onigmo (per R4/R6 conclusions). Emits JSONL {"i":n,"s":p}.
# Targets: char-class interiors (codepoint ranges, nested POSIX),
# repetition-of-repetition depth (fixed counts -> char_len int-cast),
# alternation-count x casefold expansion, (?(cond)) numbering,
# lookbehind distance wrap shapes.
require 'json'
N    = (ARGV[0] || 50_000).to_i
SEED = (ARGV[1] || 777).to_i

FOLD = ["ß", "ẞ", "ſ", "\u212A", "\u1F60", "Σ", "σ", "ς", "ﬁ", "ﬅ", "ẛ", "ᾀ", "ﬂ"]

def rnd(n) = (rand * n).to_i

cp = lambda { [1 + rnd(0x7FFFFFFF), rnd(0x110000), [0x212A, 0x1F82, 0x104B3, 0x7FFFFFFF, 0x10FFFF, 0x80].sample].sample }

cc = lambda {
  case rand(8)
  when 0 then "[a-\\x{#{cp.()}}]"
  when 1 then "[\\x{#{cp.()}}-\\x{#{cp.()}}]"
  when 2 then "[[:alpha:][:digit:][:alnum:][:space:][:punct:][:word:]]"
  when 3 then "[^\\x{#{cp.()}}-\\x{#{cp.()}}]"
  when 4 then "[#{FOLD.sample}#{FOLD.sample}#{FOLD.sample}]"
  when 5 then "[" + (1 + rnd(12)).times.map { "\\x{#{cp.()}}-\\x{#{cp.()}}" }.join + "]"
  when 6 then "[\\x{#{1 + rnd(0x7FFFFFFF)}}]"
  else "[" + (1 + rnd(30)).times.map { FOLD.sample }.uniq.join + "]"
  end
}

fixed = ->(lo = 1 + rnd(90_000)) { "{#{lo},#{lo}}" }  # lower==upper => char_len multiply path

def atom(d)
  case rand(10)
  when 0 then "a"
  when 1 then cc_safe
  when 2 then "\\x{#{cp_safe}}"
  when 3 then FOLD.sample * (1 + rnd(5))
  when 4 then "(?i)" + FOLD.sample * (1 + rnd(3))
  when 5 then "."
  when 6 then "\\p{Alpha}"
  when 7 then "(?>a)"
  when 8 then "[[:alpha:]]"
  else "ẛ" * (1 + rnd(3))
  end
end

def nesting(maxd = 30)  # repetition-of-repetition depth (fixed counts)
  d = 4 + rnd(maxd)
  s = "a{#{n = 1 + rnd(90_000)},#{n}}"
  d.times { s = "(?:#{s}){#{m = 1 + rnd(90_000)},#{m}}" }
  s
end

def altcount  # alternation count x fold chars
  n = [20, 200, 2000, 20000].sample
  members = (1..n).map { |i| i % 7 == 0 ? FOLD.sample : (i % 11 == 0 ? "\\x{#{cp_safe}}" : "a#{i % 10}") }
  "^(" + members.join("|") + ")$"   # org-ruby surface shape
end

def condnum
  "(?(#{1 + rnd(40_000)})a|b)"
end

def lbwrap  # lookbehind distance int-cast shapes
  inner = "(?:" + nesting(6 + rnd(12)) + ")"
  pre = ["(?<=", "(?<!", "(?<=" + FOLD.sample].sample
  "#{pre}#{inner})"
end

def fixed_safe = "{#{n = 1 + rnd(90_000)},#{n}}"

def cp_safe = [1 + rnd(0x7FFFFFFF), [0x212A, 0x1F82, 0x104B3, 0x7FFFFFFF].sample].sample
def cc_safe = ["[a-\\x{#{cp_safe}}]", "[[:alpha:][:digit:]]", "[#{FOLD.sample}]"].sample

def pattern
  case rand(12)
  when 0 then altcount
  when 1 then lbwrap
  when 2 then nesting
  when 3 then condnum
  when 4 then "(?i)" + nesting(8)
  when 5 then "^(" + (1 + rnd(5000)).times.map { FOLD.sample }.join("|") + ")$"
  when 6 then "(?<=" + ("x" * (1 + rnd(40_000))) + ")"
  when 7 then atom(0) + fixed_safe
  when 8 then "(?:#{atom(0)}|#{altcount})"
  when 9 then lbwrap + "|" + condnum
  when 10 then nesting(10) + "(?:#{cc_safe})" + fixed_safe
  else atom(0)
  end
end

srand(SEED)
N.times { |i| puts JSON.generate(i: i, s: pattern) }
