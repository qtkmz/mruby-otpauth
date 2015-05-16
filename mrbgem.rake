MRuby::Gem::Specification.new('mruby-otpauth') do |spec|
  spec.license = 'MIT'
  spec.author  = 'qtakamitsu'
  spec.summary = 'One time password class'
  spec.add_dependency 'mruby-sprintf'
  spec.add_dependency 'mruby-pack'
  spec.add_dependency 'mruby-digest'
  spec.add_dependency 'mruby-base32'
end
