# encoding: utf-8
require "logstash/filters/base"

# Combine fingerprints of one field of consecutive messages.
class LogStash::Filters::Hashtree < LogStash::Filters::Base
  config_name "hashtree"

  # The name of the source field whose contents will be used
  # to create the fingerprint.
  config :source, :validate => :string, :default => 'message'

  # The name of the field where the generated fingerprint will be stored.
  # Any current contents of that field will be overwritten.
  config :target, :validate => :string, :default => 'fingerprint'

  # The name of the field where the fingerprint of the previous message will be stored.
  # Any current contents of that field will be overwritten.
  config :previous, :validate => :string, :default => 'fingerprint_previous'

  # Path of the file where the generated fingerprint will be stored.
  config :file, :validate => :string, :default => '/usr/share/logstash/data/filter-hashtree'

  # The fingerprint method to use.
  config :method, :validate => ['SHA1', 'SHA256', 'SHA384', 'SHA512', 'MD5'], :default => 'SHA1'

  public
  def register
    # convert to symbol for faster comparisons
    @method = @method.to_sym
  end

  public
  def filter(event)
    fingerprint = fingerprint(event.get(@source))
    File.open(@file, File::RDWR|File::CREAT, 0644) {|f|
      f.flock(File::LOCK_EX)
      event.set(@previous, previous = f.read)
      event.set(@target, combined = fingerprint(fingerprint + previous))
      f.rewind
      f.write(combined)
    }
    filter_matched(event)
  end

  def fingerprint(data)
    # since OpenSSL::Digest instances aren't thread safe, we must ensure that
    # each pipeline worker thread gets its own instance.
    # Also, since a logstash pipeline may contain multiple fingerprint filters
    # we must include the id in the thread local variable name, so that we can
    # store multiple digest instances
    digest_string = "digest-#{id}"
    Thread.current[digest_string] ||= select_digest(@method)
    digest = Thread.current[digest_string]
    # in JRuby 1.7.11 outputs as ASCII-8BIT
    digest.hexdigest(data.to_s).force_encoding(Encoding::UTF_8)
  end

  def select_digest(method)
    case method
    when :SHA1
      OpenSSL::Digest::SHA1.new
    when :SHA256
      OpenSSL::Digest::SHA256.new
    when :SHA384
      OpenSSL::Digest::SHA384.new
    when :SHA512
      OpenSSL::Digest::SHA512.new
    when :MD5
      OpenSSL::Digest::MD5.new
    else
      # we really should never get here
      raise(LogStash::ConfigurationError, "Unknown digest for method=#{method.to_s}")
    end
  end

end
