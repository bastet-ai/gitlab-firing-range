# regrush: harness for CVE-2026-110264 shaping research.
# Mimics the vulnerable GitLab pattern: server-side code COMPILES a
# user-supplied regex source (Onigmo) exactly like CI/CD regex settings /
# path rules do, then optionally matches it. No validation, no timeout:
# this is the vuln lab, not a safe service. Loopback-only by compose.
require 'webrick'
require 'json'

server = WEBrick::HTTPServer.new(
  Port: 80, BindAddress: '0.0.0.0',
  Logger: WEBrick::Log.new(File::NULL), AccessLog: []
)

# /compile  {source:, options?} -> compiles, reports class/length
# /match    {source:, subject:, options?} -> compiles + match, reports time
# /versions -> ruby/onigmo-relevant fingerprint for target ID
server.mount_proc '/compile' do |req, res|
  res['Content-Type'] = 'application/json'
  begin
    p = JSON.parse(req.body || '{}')
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    re = Regexp.new(p['source'].to_s, Regexp::IGNORECASE)
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    res.body = JSON.generate(ok: true, class: re.class.to_s, length: re.source.length,
                             compile_ms: ((t1 - t0) * 1000).round(3), pid: Process.pid)
  rescue Exception => e   # rubies differ on Exception vs StandardError; crash must be visible
    res.body = JSON.generate(ok: false, error: e.class.to_s, msg: e.message[0, 200])
  end
end

server.mount_proc '/match' do |req, res|
  res['Content-Type'] = 'application/json'
  begin
    p = JSON.parse(req.body || '{}')
    re = Regexp.new(p['source'].to_s)
    t0 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    m = re.match(p['subject'].to_s)
    t1 = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    res.body = JSON.generate(matched: !m.nil?, match_ms: ((t1 - t0) * 1000).round(3), pid: Process.pid)
  rescue Exception => e
    res.body = JSON.generate(ok: false, error: e.class.to_s, msg: e.message[0, 200])
  end
end

server.mount_proc '/versions' do |_req, res|
  res['Content-Type'] = 'application/json'
  res.body = JSON.generate(
    ruby: RUBY_VERSION, patchlevel: RUBY_PATCHLEVEL, platform: RUBY_PLATFORM,
    onigmo: Regexp.const_defined?(:ONIGMO_VERSION) ? Regexp::ONIGMO_VERSION : 'unknown',
    canary_flagged: (File.exist?('/CANARY') rescue false), pid: Process.pid
  )
end

# diagnostic: worker-crash oracle. A crashed worker here == same
# detection signature GitLab published ("Onigmo native worker crash").
server.mount_proc '/pid' do |_req, res|
  res['Content-Type'] = 'text/plain'
  res.body = "#{Process.pid}\n"
end

trap('INT') { server.shutdown }
trap('TERM') { server.shutdown }
server.start
