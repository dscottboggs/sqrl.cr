abstract struct Sqrl::Key
  abstract def self.derive # won't compile
  abstract def domain_key(domain : String)
end
