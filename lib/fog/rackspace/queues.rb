require File.expand_path(File.join(File.dirname(__FILE__), '..', 'rackspace'))

module Fog
  module Rackspace
    class Queues < Fog::Service
      include Fog::Rackspace::Errors

      class ServiceError < Fog::Rackspace::Errors::ServiceError; end
      class InternalServerError < Fog::Rackspace::Errors::InternalServerError; end
      class BadRequest < Fog::Rackspace::Errors::BadRequest; end
      class MethodNotAllowed < Fog::Rackspace::Errors::BadRequest; end

      requires :rackspace_api_key, :rackspace_username
      recognizes :rackspace_auth_url
      recognizes :rackspace_auth_token
      recognizes :rackspace_region
      recognizes :rackspace_queues_url
      recognizes :rackspace_queues_client_id


      model_path 'fog/rackspace/models/queues'
      model :queue
      collection :queues
      model :message
      collection :messages
      model :claim
      collection :claims

      request_path 'fog/rackspace/requests/queues'
      request :list_queues
      request :get_queue
      request :create_queue
      request :delete_queue
      request :get_queue_stats

      request :list_messages
      request :get_message
      request :create_message
      request :delete_message
      request :create_claim
      request :get_claim
      request :update_claim
      request :delete_claim

      module Common
        def apply_options(options)
          @rackspace_api_key = options[:rackspace_api_key]
          @rackspace_username = options[:rackspace_username]
          @rackspace_queues_client_id = options[:rackspace_queues_client_id] || Fog::UUID.uuid
          @rackspace_auth_url = options[:rackspace_auth_url]
          @rackspace_must_reauthenticate = false
          @connection_options = options[:connection_options] || {}
          @rackspace_region = options[:rackspace_region] || :ord

          unless v2_authentication?
            raise Fog::Errors::NotImplemented.new("V2 authentication required for Queues")
          end
        end

        def service_name
          :cloudQueues
        end

        def region
          @rackspace_region
        end

        def endpoint_uri(service_endpoint_url=nil)
          @uri = super(@rackspace_endpoint || service_endpoint_url, :rackspace_queues_url)
        end

        def authenticate(options={})
          super({
            :rackspace_api_key  => @rackspace_api_key,
            :rackspace_username => @rackspace_username,
            :rackspace_auth_url => @rackspace_auth_url,
            :connection_options => @connection_options
          })
        end

        def client_id
          @rackspace_queues_client_id
        end

        def client_id=(client_id)
          @rackspace_queues_client_id = client_id
        end
      end

      class Mock < Fog::Rackspace::Service
        include Common

        # An in-memory Queue implementation.
        class MockQueue
          attr_accessor :name, :metadata, :messages
          attr_accessor :claimed, :free

          def initialize(name)
            @name = name
            @messages, @metadata = [], {}
            @claimed, @free = 0, 0
            @id_counter = Fog::Mock.random_hex(24).to_i(16)
          end

          # The total number of messages currently on the queue.
          #
          # @return [Integer]
          def total
            @messages.size
          end

          # Append a new message to the queue.
          #
          # @param client_id [String] UUID for the service object.
          # @param data [Hash] Message payload.
          # @param ttl [Integer] Number of seconds that the message should exist.
          # @return [MockMessage] The message object that was created.
          def add_message(client_id, data, ttl)
            id = @id_counter.to_s(16)
            @id_counter += 1
            message = MockMessage.new(id, self, client_id, data, ttl)
            @messages << message
            message
          end
        end

        # A single message posted to an in-memory MockQueue.
        class MockMessage
          attr_accessor :id, :queue, :data, :ttl, :producer_id
          attr_accessor :claim

          # Create a new message. Use {MockQueue#add_message} instead.
          def initialize(id, queue, client_id, data, ttl)
            @id, @queue, @producer_id = id, queue, client_id
            @data, @ttl = data, ttl
            @created = Time.now.to_i
            @claim = nil
          end

          # Determine how long ago this message was created, in seconds.
          #
          # @return [Integer]
          def age
            Time.now.to_i - @created
          end

          # Return true if this message has been claimed.
          #
          # @return [Boolean]
          def claimed?
            ! @claim.nil?
          end

          # Convert this message to a GET payload.
          #
          # @return [Hash]
          def to_h
            {
              "body" => @data,
              "age" => age,
              "ttl" => @ttl,
              "href" => "/v1/queues/#{@queue.name}/messages/#{@id}"
            }
          end
        end

        class MockClaim
          attr_reader :id, :ttl, :grace

          def initialize ttl, grace
            @id = Fog::Mock.random_hex(24)
            @ttl, @grace = ttl, grace
          end
        end

        def initialize(options = {})
          apply_options(options)
          authenticate
          endpoint_uri
        end

        # FIXME Refactor commonalities from Fog::Rackspace::Storage to... somewhere.
        def self.data
          @data ||= Hash.new do |hash, key|
            hash[key] = {}
          end
        end

        def data
          self.class.data[@rackspace_username]
        end
      end

      class Real < Fog::Rackspace::Service
        include Common

        def initialize(options = {})
          apply_options(options)

          authenticate

          @persistent = options[:persistent] || false
          @connection = Fog::Connection.new(endpoint_uri.to_s, @persistent, @connection_options)
        end

        def request(params, parse_json = true, &block)
          super(params, parse_json, &block)
        rescue Excon::Errors::NotFound => error
          raise NotFound.slurp(error, self)
        rescue Excon::Errors::BadRequest => error
          raise BadRequest.slurp(error, self)
        rescue Excon::Errors::InternalServerError => error
          raise InternalServerError.slurp(error, self)
        rescue Excon::Errors::MethodNotAllowed => error
          raise MethodNotAllowed.slurp(error, self)
        rescue Excon::Errors::HTTPStatusError => error
          raise ServiceError.slurp(error, self)
        end
      end

    end
  end
end
