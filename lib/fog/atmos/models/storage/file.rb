require 'fog/core/model'

module Fog
  module Storage
    class Atmos

      class File < Fog::Model

        identity  :key,             :aliases => :Filename

        attribute :content_length,  :aliases => ['bytes', 'Content-Length'], :type => :integer
        attribute :content_type,    :aliases => ['content_type', 'Content-Type']
        attribute :objectid,        :aliases => :ObjectID
        attribute :created_at,      :aliases => :ctime

        def body
          attributes[:body] ||= if objectid
            collection.get(identity).body
          else
            ''
          end
        end

        def body=(new_body)
          attributes[:body] = new_body
        end

        def directory
          @directory
        end

        def copy(target_directory_key, target_file_key, options={})
          target_directory = service.directories.new(:key => target_directory_key)
          target_directory.files.create(
            :key => target_file_key,
            :body => body
          )
        end

        def destroy
          requires :directory, :key
          service.delete_namespace([directory.key, key].join('/'))
          true
        end

        def meta_data
         requires :directory, :key
          service.get_namespace([directory.key, key].join('/') + "?metadata/system")
        end

        def file_size
          data = meta_data
          meta_data.headers["x-emc-meta"].match(/size=\d+/).to_s.gsub(/size=/,"")
        end

        def public=(new_public)
          # NOOP - we don't need to flag files as public, getting the public URL for a file handles it.
        end

        # By default, expire in 5 years
        def public_url(expires = (Time.now + 5 * 365 * 24 * 60 * 60))
          requires :objectid, :directory
          # TODO - more efficient method to get this?
          storage = connection
          
          #This is to get around the issue of square brackets in a file name, preventing download of the file.
          safe_key = key.gsub(/[\[]/,'%5B').gsub(/[\]]/,'%5D')
      
          Fog::Storage::Atmos
          # Build a public URL that will be sent such that the client's web browser can
          # retrieve the file directly using the NAMESPACE method (instead of Object ID):
          uri = URI::HTTPS.build(
            :scheme => Fog::Storage::Ninefold::STORAGE_SCHEME,
            :host => Fog::Storage::Ninefold::STORAGE_HOST,
            :port => Fog::Storage::Ninefold::STORAGE_PORT.to_i,
            :path => "/rest/namespace/#{directory.key}#{safe_key}"
          )
          connection.uid

          sb = "GET\n"
          sb += uri.path.downcase + "\n"
          sb += storage.uid + "\n"
          sb += String(expires.to_i())

          signature = storage.sign( URI.unescape(sb) )
          uri.query = "uid=#{CGI::escape(storage.uid)}&expires=#{expires.to_i()}&signature=#{CGI::escape(signature)}"
          uri.to_s
        end


        def save(options = {})
          requires :body, :directory, :key
          directory.kind_of?(Directory) ? ns = directory.key : ns = directory
          ns += key
          options[:headers] ||= {}
          options[:headers]['Content-Type'] = content_type if content_type
          options[:body] = body
          begin
            data = service.post_namespace(ns, options)
            self.objectid = data.headers['location'].split('/')[-1]
          rescue => error
            if error.message =~ /The resource you are trying to create already exists./
              data = service.put_namespace(ns, options)
            else
              raise error
            end
          end
          # merge_attributes(data.headers)
          true
        end

        private

        def directory=(new_directory)
          @directory = new_directory
        end

      end

    end
  end
end
