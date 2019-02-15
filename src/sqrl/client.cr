require "uri"
require "./version"

struct Sqrl::Client
  class_property domain : String
  # A chainable setter for the domain class property, for convenience.
  #
  # Like:
  #
  # ```
  # Sqrl::Client.on(domain: "example.com").authenticate(...)
  # ```
  def self.on(@@domain : String)
    self
  end
  def authenticate(id : Identity, password : String, site_url : URI, options : Option) : HTTP::Request?
    # Get the private key for the domain
    if master_key = id.recover_master_key using: password
      key = master_key.domain_key domain
      # Build response URL options
      query = String.build do |q|
        # 1: add sqrlver
        q << "sqrlver=" << Version::SQRL_1
        # 2: add sqrlopt
        unless options.none?
          q << "sqrlopt=" << options.to_s
        end
        # 3: Add sqrlkey
        q << "sqrlkey=" << Base64.urlsafe_encode(key.public_key).rstrip('=')
        # 4: Add sqrlold... apparently not present in the Go version?

      end
      # Signed
      url = "#{site_url.host}#{port_for? site_url}/#{site_url.path}?#{query}"
      body = "sqrlsig=#{key.sign url}"
      HTTP::Request.new "POST", resource: url, body: body
    end
  end
  def authenticate(id : Identity, password : String, site_url : String, options : Option) : HTTP::Request?
    authenticate id, password, URI.parse(site_url), options
  end

  private def port_for?(url : URI)
    unless uri.port === URI.default_port url.scheme
      ":#{uri.port}"
    end
  end
end
