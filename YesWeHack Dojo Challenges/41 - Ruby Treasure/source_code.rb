require 'cgi'
require 'erb'

Dir.chdir("/tmp/app/views")

# Validate the given filename
# We use a super strict regex, so it can't be bypassed, right?
def validateFile(filename)
    return !!/^[a-zA-Z0-9_-]+$/.match(filename) || filename.length == 0
end

filename = CGI.unescape("")
content = ""

if validateFile(filename)
    begin
        content = IO.read("#{filename}.erb")
    rescue
        content = IO.read("collection.erb")
    end
    
end

# Render the given page for our web application
puts ERB.new(IO.read("index.erb")).result_with_hash({page: content})
