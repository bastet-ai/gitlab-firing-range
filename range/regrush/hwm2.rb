def hwm = File.read("/proc/self/status")[/VmHWM:\s+(\d+)/, 1]
[22000, 25000, 30000, 40000].each do |c|
  src = "(?:" + "a" * c + "){100000}"
  before = hwm
  begin
    re = Regexp.new(src)
    puts "chars=#{c}: hwm_before=#{before} hwm_after=#{hwm} compiled"
  rescue Exception => e
    puts "chars=#{c}: #{e.class} #{e.message[0,40]} (hwm=#{hwm})"
  end
end
