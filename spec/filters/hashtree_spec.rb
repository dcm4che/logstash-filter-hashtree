# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/hashtree"

describe LogStash::Filters::Hashtree do
  describe "Set to Hello World" do
    let(:config) do <<-CONFIG
      filter {
        hashtree {
          target => "current"
          previous => "previous"
          file => "filter-hashtree"
        }
      }
    CONFIG
    end

    sample("message" => "some text") do
      File.write('filter-hashtree','37aa63c77398d954473262e1a0057c1e632eda77')
      expect(subject).to include("message")
      expect(subject.get('previous')).to eq('37aa63c77398d954473262e1a0057c1e632eda77')
      expect(subject.get('current')).to eq('9c3a0b7800edb149bada08a999b16f7bdd9388db')
    end
  end
end
