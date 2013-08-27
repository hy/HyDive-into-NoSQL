# TODO: 
# [X] Tidy up both forms of Mongo init
# [/] Add Neo4j
# [ ] Re-arrange config by prod / dev to allow remote / local db connections


###############################################################################
# Ruby Gem Core Requires  --  this first grouping is essential
#   (Deploy-to: Heroku Cedar Stack)
###############################################################################
require 'rubygems' if RUBY_VERSION < '1.9'

require 'sinatra/base'
 require 'erb'
require 'sinatra/graph'

require 'net/http'
require 'uri'
require 'json'

require 'pony'


###############################################################################
# Optional Requires (Not essential for base version)
###############################################################################
# require 'temporals'

# require 'ri_cal'   
# require 'tzinfo'

# If will be needed, Insert these into Gemfile:
# gem 'ri_cal'
# gem 'tzinfo'

# require 'yaml'


###############################################################################
#                 App Skeleton: General Implementation Comments
###############################################################################
#
# Here I do the 'Top-Level' Configuration, Options-Setting, etc.
#
# I enable static, logging, and sessions as Sinatra config. options
# (See http://www.sinatrarb.com/configuration.html re: enable/set)
#
# I am going to use MongoDB to log events, so I also proceed to declare
# all Mongo collections as universal resources at this point to make them
# generally available throughout the app, encouraging a paradigm treating
# them as if they were hooks into a filesystem akin to: stdin, stdout, etc.
#
# Redis provides fast cache; SendGrid: email; Google API --> calendar access
# 
# I am also going to include the Twilio REST Client for SMS ops and phone ops,
# and so I configure that as well.
#
###############################################################################

class TheApp < Sinatra::Base
  register Sinatra::Graph

  enable :static, :logging, :sessions
  set :public_folder, File.dirname(__FILE__) + '/static'

  configure :development do
    SITE = 'http://localhost:3000'
    puts '____________CONFIGURING FOR LOCAL SITE: ' + SITE + '____________'
  end
  configure :production do
    SITE = ENV['SITE']
    puts '____________CONFIGURING FOR REMOTE SITE: ' + SITE + '____________'
  end

  configure do
    begin
      ONE_HOUR = 60.0 * 60.0
      ONE_DAY = 24.0 * ONE_HOUR
      puts '[OK!]  Constants Initialized'
    end

    if ENV['NEO4J_URL']
      begin
        puts where = 'NEO4j CONFIG via ENV var set via heroku addons:add neo4j'
        require 'neography'

        neo4j_uri = URI ( ENV['NEO4J_URL'] )
        neo = Neography::Rest.new(neo4j_uri.to_s)

        http = Net::HTTP.new(neo4j_uri.host, new4j_uri.port)
        verification_req = Net::HTTP::Get.new(neo4j_uri.request_uri)
        
        if neo4j_uri.user
          verification_req.basic_auth(neo4j_uri.user, neo4j_uri.password)
        end #if

        puts response = http.request(verification_req)
        abort "Neo4j down" if response.code != '200' 

        # console access via: heroku addons:open neo4j

        puts("[OK!]  Neo4j Connection Configured and avail at #{neo4j_uri}")
      rescue Exception => e;  log_exception( e, where );  end
    end

    if ENV['MONGODB_URI']
      begin
        where = 'MONGO CONFIG via single ENV var containing the URI'
        require 'mongo'
        require 'bson'    #Do NOT 'require bson_ext' just put it in Gemfile!

        CN = Mongo::Connection.new
        DB = CN.db

        puts('[OK!]  Mongo URI Connection Configured via single env var')
      rescue Exception => e;  log_exception( e, where );  end 
    end

    if ENV['MONGO_URL'] and not ENV['MONGODB_URI']
      begin
        where = 'MONGO CONFIG via multiple separated ENV vars'
        require 'mongo'
        require 'bson'    #Do NOT 'require bson_ext' just put it in Gemfile!
        
        CN = Mongo::Connection.new(ENV['MONGO_URL'], ENV['MONGO_PORT'])
        DB = CN.db(ENV['MONGO_DB_NAME'])
        auth = DB.authenticate(ENV['MONGO_USER_ID'], ENV['MONGO_PASSWORD'])

        puts('[OK!]  Mongo Connection Configured via separated env vars')
      rescue Exception => e;  log_exception( e, where );  end
    end

    if ENV['REDISTOGO_URL']
      begin
        where = 'REDIS CONFIG'
        require 'hiredis'
        require 'redis'
        uri = URI.parse(ENV['REDISTOGO_URL'])
        REDIS = Redis.new(:host => uri.host, :port => uri.port,
                          :password => uri.password)
        REDIS.set('CacheStatus', '[OK!]  Redis Configured')
        puts REDIS.get('CacheStatus')
      rescue Exception => e;  log_exception( e, where );  end
    end

    if ENV['TWILIO_ACCOUNT_SID']&&ENV['TWILIO_AUTH_TOKEN']
      begin
        where = 'TWILIO CONFIG'
        require 'twilio-ruby'
        require 'builder'
        $t_client = Twilio::REST::Client.new(
          ENV['TWILIO_ACCOUNT_SID'], ENV['TWILIO_AUTH_TOKEN'] )
        $twilio_account = $t_client.account
        puts '[OK!]  Twilio Client Configured for: ' + ENV['TWILIO_CALLER_ID']
      rescue Exception => e;  log_exception( e, where );  end
    end

    if ENV['SENDGRID_USERNAME'] && ENV['SENDGRID_PASSWORD']
      begin
        where = 'SENDGRID CONFIG'
        Pony.options = {
          :via => :smtp,
          :via_options => {
          :address => 'smtp.sendgrid.net',
          :port => '587',
          :domain => 'heroku.com',
          :user_name => ENV['SENDGRID_USERNAME'],
          :password => ENV['SENDGRID_PASSWORD'],
          :authentication => :plain,
          :enable_starttls_auto => true
          }
        }
        puts "[OK!]  SendGrid Options Configured"
      rescue Exception => e;  log_exception( e, where );  end
    end


# Store the calling route in GClient.authorization.state 
# That way, if we have to redirect to authorize, we know how to get back
# to where we left off...

    if ENV['GOOGLE_ID'] && ENV['GOOGLE_SECRET']
      begin
        where = 'GOOGLE API CONFIG'
        require 'google/api_client'
        options = {:application_name => ENV['APP'],
                   :application_version => ENV['APP_BASE_VERSION']}
        GClient = Google::APIClient.new(options)
        GClient.authorization.client_id = ENV['GOOGLE_ID']
        GClient.authorization.client_secret = ENV['GOOGLE_SECRET']
        GClient.authorization.redirect_uri = SITE + 'oauth2callback'
        GClient.authorization.scope = [ 
          'https://www.googleapis.com/auth/calendar',
          'https://www.googleapis.com/auth/tasks'
        ]
        GClient.authorization.state = 'configuration'

        RedirectURL = GClient.authorization.authorization_uri.to_s
        GCal = GClient.discovered_api('calendar', 'v3')

        puts '[OK!]  Google API Configured with Scope Including:'
        puts GClient.authorization.scope

      rescue Exception => e;  log_exception( e, where );  end
    end

  end #configure


  # Since Mongo 'speaks' JSON, this makes many 3rd-party integrations
  # incredibly nice and simple, for example very simple graphing. . .   

  graph 'Temperature', :prefix => '/graphs' do
    cursor = DB['temp'].find({'temp' => {'$exists' => true}})
    temperature_a = Array.new
    cursor.each{ |d|
      temperature_a.push(d['temp'])
    }
    bar "Degrees (C)", temperature_a
  end

  graph 'Memcached', :prefix => '/graphs', :type => 'pie' do
    puts r_bytes = REDIS.get('bytes_read').to_f
    puts w_bytes = REDIS.get('bytes_written').to_f
    pie 'Memcached I/O', { 'Bytes Read' => r_bytes, 'Bytes Written' => w_bytes }
  end


  #############################################################################
  #                            Routing Code Filters
  #############################################################################
  #
  # It's generally safer to use custom helpers explicitly in each route. 
  # (Rather than overuse the default before and after filters. . .)
  #
  # This is especially true since there are many different kinds of routing
  # ops going on: Twilio routes, web routes, etc. and assumptions that are
  # valid for one type of route may be invalid for others . . .  
  #
  # So in the "before" filter, we just print diagnostics & set a timetamp
  # It is worth noting that @var's changed or set in the before filter are
  # available in the routes . . .  
  #
  # A stub for the "after" filter is also included
  # The after filter could possibly also be used to do command bifurcation
  #
  #############################################################################
  before do
    puts where = 'BEFORE FILTER'
    begin
      print_diagnostics_on_route_entry
      @these_variables_will_be_available_in_all_routes = true

      REDIS.set("Time", Time.now)

      @now_f = Time.now.to_f
    rescue Exception => e;  log_exception( e, where );  end
  end

  after do
    puts where = 'AFTER FILTER'
    begin

    puts "REDIS STORED THE TIME AS: "
    puts REDIS.get("Time")

    rescue Exception => e;  log_exception( e, where );  end
  end


  #############################################################################
  #                            Routing Code Notes
  #############################################################################
  # Some routes must "write" TwiML, which can be done in a number of ways.
  #
  # The cleanest-looking way is via erb, and Builder and raw XML in-line are
  # also options that have their uses.  Please note that these cannot be
  # readily combined -- if there is Builder XML in a route with erb at the
  # end, the erb will take precedence and the earlier functionality is voided
  #
  # In the case of TwiML erb, my convention is to list all of the instance
  # variables referenced in the erb directly before the erb call... this
  # serves as a sort of "parameter list" for the erb that is visible from
  # within the routing code
  #############################################################################


  # Look how easy Redis is to use. . . 
  # Let's give whatever we get as a (key, value) from the params to REDIS.set
  get '/redisify' do
    puts 'setting: ' + params['key']
    puts 'to: ' + params['value']
    REDIS.set(params['key'], params['value'])
  end

  get '/test' do
    'Server is up!'
  end


  #############################################################################
  #                         Google API routes
  #
  # Auth-Per-Transaction example:
  #
  # https://code.google.com/p/google-api-ruby-client/
  #          source/browse/calendar/calendar.rb?repo=samples
  # https://code.google.com/p/google-api-ruby-client/wiki/OAuth2
  #
  # Refresh Token example:
  #
  # http://pastebin.com/cWjqw9A6
  #
  #
  #############################################################################

  get '/insert' do
    where = 'ROUTE PATH: ' + request.path_info
    begin
      GClient.authorization.state = request.path_info
      ensure_session_has_GoogleAPI_refresh_token_else_redirect()

      puts cursor = DB['sample'].find({'location' => 'TestLand' })

      insert_into_gcal_from_mongo( cursor )
      GClient.authorization.state = '*route completed*'
    rescue Exception => e;  log_exception( e, where ); end
  end


  get '/quick_add' do
    where = 'ROUTE PATH: ' + request.path_info
    begin
      GClient.authorization.state = request.path_info
      ensure_session_has_GoogleAPI_refresh_token_else_redirect()

      puts cursor = DB['sample'].find({'location' => 'TestLand' })

      quick_add_into_gcal_from_mongo( cursor )
      GClient.authorization.state = '*route completed*'
    rescue Exception => e;  log_exception( e, where ); end
  end


  get '/delete_all_APP_events' do
    where = 'ROUTE PATH: ' + request.path_info
    begin
      GClient.authorization.state = request.path_info
      ensure_session_has_GoogleAPI_refresh_token_else_redirect()

      page_token = nil

      result = GClient.execute(:api_method => GCal.events.list,
       :parameters => {'calendarId' => 'primary', 'q' => 'APP_gen_event'})
      events = result.data.items
      puts events

      events.each { |e|
        GClient.execute(:api_method => GCal.events.delete,
         :parameters => {'calendarId' => 'primary', 'eventId' => e.id})
        puts 'DELETED EVENT wi. ID=' + e.id
      }
    rescue Exception => e;  log_exception( e, where ); end

  end #delete all APP-generated events


  get '/list' do
    ensure_session_has_GoogleAPI_refresh_token_else_redirect()
    
    calendar = GClient.execute(:api_method => GCal.calendars.get,
                               :parameters => {'calendarId' => 'primary' })

    print JSON.parse( calendar.body )
    return calendar.body
  end


  # Request authorization
  get '/oauth2authorize' do
    where = 'ROUTE PATH: ' + request.path_info
    begin

      redirect user_credentials.authorization_uri.to_s, 303
    rescue Exception => e;  log_exception( e, where ); end
  end

  get '/oauth2callback' do
    where = 'ROUTE PATH: ' + request.path_info
    begin
      GClient.authorization.code = params[:code]
      results = GClient.authorization.fetch_access_token!
      session[:refresh_token] = results['refresh_token']
      redirect GClient.authorization.state
    rescue Exception => e;  log_exception( e, where ); end
  end



  #############################################################################
  # SMS_request (via Twilio) 
  #############################################################################
  #
  # SMS routing essentially follows a command-line interface interaction model
  #
  # I get the SMS body, sender, and intended recipient (the intended recipient
  # should obviously be this app's own phone number).
  #
  # I first archive the SMS message in the db, regardless of what else is done
  #
  # I then use the command as a route in this app, prefixed by '/c/'
  #
  # At this point, I could just feed the content to the routes... that's a bit
  # dangerous, security-wise, though... so I will prepend with 'c' to keep
  # arbitrary interactions from routing right into the internals of the app!
  #
  # So, all-in-all: add protective wrapper, downcase the message content,
  # remove all of the whitespace from the content, . . .
  # and then prepend with the security tag and forward to the routing
  #
  #############################################################################
  get '/SMS_request' do
    puts where = 'SMS REQUEST ROUTE'
    begin

      puts info_about_this_SMS_to_log_in_db = {
        "Who" => params['From'],
        "utc" => @now_f,
        "When" => Time.now.strftime("%A %B %d at %I:%M %p"),
        "What" => params['Body']
      }
      puts DB['log'].insert(info_about_this_SMS_to_log_in_db, {:w => 1 })

# We would typically redirect to command handlers at this point. 
#      c_handler = '/c/'+(params['Body']).downcase.gsub(/\s+/, "")
# 
# But to just test things out, we'll inline a sample here. . . 

      incoming_msg = params['Body']
      regex_results = incoming_msg.match(/(?<digits>\d*)(?<words>.*)/) 

      insertion_string = ''
      puts regex_results['words']

      doc = {
        'ID' => params['From'], 
        'Numbers' => regex_results['digits'], 
        'Words' => regex_results['words'], 
        'utc' => Time.now.to_f 
      };DB['remarks'].insert(doc)

#      puts "SINATRA: Will try to use route handler for: "+c_handler
#      redirect to(c_handler)

    rescue Exception => e;  log_exception( e, where ); end

  end #do get




  #############################################################################
  # SMS Command routes are defined by their separators
  # Command routes are downcased before they come here, in SMS_request
  # Spaces are optional in SMS commands, and are removed before /c/ routing
  #
  # Un-caught routes fall through to default routing
  #
  # Roughly, detect all specific commands first
  # Then, detect more complex phrases
  # Then, detect numerical reporting
  # Finally, fall through to the default route
  # Exceptions can occur in: numerical matching
  # So, there must also be an exception route...
  #############################################################################
  get '/c/' do
    puts 'BLANK SMS ROUTE'
    send_SMS_to( params['From'], 'Received blank SMS, . . .  ?' )
  end #do get



  #############################################################################
  # Email a Report (From an array-of-hashes, right now randomly filled)
  #
  # To capture and parse emails, perhaps consider: 
  #
  # http://docs.cloudmailin.com/receiving_email/examples/ruby/
  #
  #############################################################################
  get /\/c\/(?<email_addy>[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,4})/ix do
  puts where = 'GMAIL REGEX ROUTE (uses Pony)'
  begin
    puts @email_to = params[:captures][0]
    puts @subject = 'Data'
    puts @words = 'Last data: \n'

    @array_of_hashes = Array.new
    @array_of_hashes.push( {'1key1'=>'1val1'}, {'1key2'=>'1val2'}  )
    @array_of_hashes.push( {'2key1'=>'2val1'}, {'2key2'=>'2val2'}  )
    @array_of_hashes.push( {'3key1'=>'3val1'}, {'3key2'=>'3val2'}  )
    @array_of_hashes.push( {'key4'=>'cow'} )

    if (@array_of_hashes == nil)
      @array_of_hashes = Array.new
      @array_of_hashes.push( {'Records'=>'None Yet'} )
    end #if

    puts @body = erb(:email)


    Pony.mail(:to=>@email_to,:via=>:smtp,:subject=>@subject,:body=>@body)

    register_email_in_db( @email_to )

    rescue Exception => e;  log_exception( e, where ); end

  end #do gmail



  #############################################################################
  # Final / "Trap" route: (should catch every SMS that is not a known command)
  #
  # Also:  Of course, if we do not know what the user meant, we should tell
  # them we could not understand their text message. 
  #
  #############################################################################
  get '/c/*' do |text|
  puts where = 'UNIVERSAL CATCH-ALL TRAPPING ROUTE'
  puts 'GOING TO THE COMMAND HASH IN THE DB TO ATTEMPT TO FIND: ' + text
  begin
    route = DB['routes'].find_one({'text' => text})

    if (route==nil)
      reply_via_SMS( 'Could not understand this command: '+text )
      doc = {
       'Who' => params['From'],
       'What' => text,
       'utc' => Time.now.to_f
      }
      DB['unrouted'].insert(doc)
    end #if

    redirect route if route != nil

    rescue Exception => e;  log_exception( e, where ); end

  end #do get


  #############################################################################
  #                  END OF THE ROUTING SECTION OF THE APP                    #
  #############################################################################



  #############################################################################
  # Helpers
  #############################################################################
  # Note: helpers are executed in the same context as routes and views
  # Note: helpers have the params[] hash available to them in this scope
  #       So, this gives us another option to send reply SMS, in addition
  #       to via-erb... etc.
  #
  # Primarily, I am using helpers as db-accessors and Twilio REST call
  # convenience functions.  Other uses include caller authenitcation or
  # caller blocking, and printing diagnostics, logging info, etc. 
  #
  #############################################################################
  helpers do


   ###########################################################################
   # Generic Sinatra Helpers
   ###########################################################################

    ###########################################################################
    # Define a handler for multiple http verbs at once (can be convenient!)
    ###########################################################################
    def any(url, verbs = %w(get post put delete), &block)
      verbs.each do |verb|
        send(verb, url, &block)
      end
    end


    ###########################################################################
    # Helper: Print Route Info Upon Entry (usu. called from the before filter) 
    ###########################################################################
    def print_diagnostics_on_route_entry
      # for the full url: puts request.url
      # for printing part of the url: puts request.fullpath
      # for printing just the path info: puts request.path_info

      puts "ENTERING ROUTE: "+ request.path_info
      params.each { |k, v| 
        puts request.path_info + ': ' + k.to_s + ' ====> ' + v.to_s
      }
    end #def


    ###########################################################################
    # Helper: Google API Refresh Token
    ###########################################################################
    def ensure_session_has_GoogleAPI_refresh_token_else_redirect()
      where = "HELPER: " + (__method__).to_s 
      begin
        redirect RedirectURL unless session[:refresh_token] 
        redirect RedirectURL if session[:refresh_token].length <= 3

        GClient.authorization.refresh_token = session[:refresh_token]
        GClient.authorization.fetch_access_token!
      rescue Exception => e;  log_exception( e, where ); end
    end #ensure_session_has_GoogleAPI_refresh_token_else_redirect()


    ###########################################################################
    # Helper: Google Calendar API Single-Event Insert
    ###########################################################################
    def insert_into_gcal( j )
      where = "HELPER: " + (__method__).to_s
      begin
        result = GClient.execute(:api_method => GCal.events.insert,
         :parameters => {'calendarId' => 'primary'},
         :body => JSON.dump( j ),
         :headers => {'Content-Type' => 'application/json'})
        puts "INSERTED event with id:" + result.data.id

        return result
      rescue Exception => e;  log_exception( e, where ); end
    end #insert_calendar_event


    ###########################################################################
    # Helper: Google Calendar API Multi-Event Insert from Mongo Cursor
    ###########################################################################
    def insert_into_gcal_from_mongo( cursor )
      where = "HELPER: " + (__method__).to_s
      begin
        cursor.each { |event|
          result = GClient.execute(:api_method => GCal.events.insert,
           :parameters => {'calendarId' => 'primary'},
           :body_object => event,
           :headers => {'Content-Type' => 'application/json'})
          puts "INSERTED event with result data id:" + result.data.id
        }
      rescue Exception => e;  log_exception( e, where ); end
    end #insert_calendar_event


    ###########################################################################
    # Helper: Google Calendar API Multi-Event Insert from Mongo Cursor
    ###########################################################################
    def insert_bg_checkins_into_gcal_from_mongo( cursor )
      where = "HELPER: " + (__method__).to_s
      begin
        cursor = DB['checkins'].find({'mg' => {'$exists' => true} })
        cursor.each { |checkin|
        event = Hash.new
        event['summary'] = (checkin['mg']).to_s
        event['color'] = Float(checkin['mg']) < 70 ?  2 : 3
        event['start']['dateTime'] = Time.at(checkin['utc']).strftime("%FT%T%z")
        event['start']['timeZone'] = 'America/Los_Angeles'
        event['end']['dateTime'] = Time.at(checkin['utc']+9).strftime("%FT%T%z")
        event['end']['timeZone'] = 'America/Los_Angeles'

        result = GClient.execute(:api_method => GCal.events.insert,
         :parameters => {'calendarId' => 'primary'},
         :body_object => event,
         :headers => {'Content-Type' => 'application/json'})
        puts "INSERTED event with result data id:" + result.data.id
        }
      rescue Exception => e;  log_exception( e, where ); end
    end #insert_calendar_event


    ###########################################################################
    # Helper: Speakble Time (usage: speakable_time_for( Time.now )
    ###########################################################################
    def speakable_time_for( time )
      return time.strftime("%A %B %d at %I:%M %p")
    end #def

    ###########################################################################
    # Helper: Speakable Time Interval given float (and optional preamble)
    ###########################################################################
    def speakable_interval_for( preamble=' ', float_representing_hours )
      where = "HELPER: " + (__method__).to_s
      begin
        msg_start = preamble

        whole_hours_i = float_representing_hours.to_i

        msg_start += whole_hours_i.to_s unless whole_hours_i==0

        h_f = float_representing_hours.floor
        h = float_representing_hours - h_f

        msg_mid = if    (h_f<=0)&&(h <= 0.2) then ' just a little while'
                  elsif (h_f<=0)&&(h <= 0.4) then ' a quarter hour'
                  elsif (h_f<=0)&&(h <= 0.6) then ' a half hour'
                  elsif (h_f<=0)&&(h <= 0.9) then ' three quarters of an hour'
                  elsif (h_f==1)&&(h <= 0.2) then ' hour'
                  elsif (h_f>=2)&&(h <= 0.2) then ' hours'
                  elsif (h_f>=1)&&(h <= 0.4) then ' and a quarter hours'   
                  elsif (h_f>=1)&&(h <= 0.6) then ' and a half hours'
                  elsif (h_f>=1)&&(h <= 1.0) then ' and three quarters hours'
                  else ' some time'
                  end

        msg_end = ' ago.'

        return msg = msg_start + msg_mid + msg_end
      rescue Exception => e;  log_exception( e, where );  end
    end #def


    ###########################################################################
    # Twilio-Specific 'Macro'-style Helper: Send SMS to a number
    ###########################################################################
    def send_SMS_to( number, msg )
      where = "HELPER: " + (__method__).to_s 
      begin
        puts "ATTEMPT TO SMS TO BAD NUMBER" if number.match(/\+1\d{10}\z/)==nil

        @message = $twilio_account.sms.messages.create({
              :from => ENV['TWILIO_CALLER_ID'],
              :to => number,
              :body => msg
        })
        puts "SENDING OUTGOING SMS: "+msg+" TO: "+number

      rescue Exception => e;  log_exception( e, where );  end
    end #def


    ###########################################################################
    # Twilio-Specific 'Macro'-style Helper: Send SMS back to caller
    ###########################################################################
    def reply_via_SMS( msg )
      where = "HELPER: " + (__method__).to_s
      begin
        @message = $twilio_account.sms.messages.create({
              :from => ENV['TWILIO_CALLER_ID'],
              :to => params['From'],
              :body => msg
        })
      puts "REPLYING WITH AN OUTGOING SMS: "+msg+" TO: "+params['From']

      rescue Exception => e;  log_exception( e, where );  end
    end #def


    ###########################################################################
    # Twilio-Specific 'Macro'-style Helper: Dial out to a number
    ###########################################################################
    def dial_out_to( number_to_call, route_to_execute )
      where = "HELPER: " + (__method__).to_s 
      begin
        @call = $twilio_account.calls.create({
              :from => ENV['TWILIO_CALLER_ID'],
              :to => number_to_call,
              :url => "#{SITE}" + route_to_execute
       })
       puts "DIALING OUT TO: "+number_to_call

      rescue Exception => e;  log_exception( e, where );  end
    end #def


    #
    # One key with Mongo is to minimize the size of stored keys and val's
    # because Mongo's performance suffers unless you have enough main 
    # system memory to hold about 30 - 40% of the total size of the 
    # collections you will want to access.  
    #
    # A straightforward way to help with this is to store an "abbreviation
    # dictionary" . . .  which we can also put in Mongo!
    #

    ###########################################################################
    # Helper: Map abbreviations to full text strings.  .  .
    ###########################################################################
    def full_string_from_abbrev( tag_abbrev_s )
      where = "HELPER: " + (__method__).to_s
 
      record = DB['abbrev'].find_one('abbreviation' => tag_abbrev_s)
      when_s = record['full'] if record != nil
      when_s = tag_abbrev_s if record == nil

      return when_s
    end #def


    # Suppose you want to introduce folks to your app by sending them 
    # an SMS . . .  can do!  We might then like to 'recognize' them as they
    # show up / call in . . .   

    def onboarding_helper
      where = "HELPER: " + (__method__).to_s 
      puts where = 'ONBOARDING HELPER'

      begin
        print_diagnostics_on_route_entry

        @this_user = DB['people'].find_one('_id' => params['From'])
        @now_f = Time.now.to_f

        if (@this_user == nil)
          doc = {
            '_id' => params['From'],
            'alerts' => 'None'
          }

          DB['people'].insert(doc)
          @this_user = DB['people'].find_one('_id' => params['From'])

          msg = 'Welcome to the experimental app!'
          msg += ' (All data sent or received is public.)'
          reply_via_SMS( msg )
        end #if

      puts @this_user

      rescue Exception => e;  log_exception( e, where );  end
    end



    ###########################################################################
    # Cross-Application Mongo DB Access Helpers (Twilio Case)  
    ###########################################################################
    # register_email_in_db finds the 'people' entry corresponding to the
    # phone number that is calling / texting us, and adds and/or updates
    # the email on file for that person.
    ###########################################################################
    def register_email_in_db(em)
      DB['people'].update({'_id' => params['From']},
                          {"$addToSet" => {'email' => em}}, :upsert => true)
    end #def


    ###########################################################################
    # Logging Helpers
    ###########################################################################
    def log_exception( e, where = 'unspecified' )
      here = "HELPER: " + (__method__).to_s 
      begin
        puts ' --> LOGGING AN EXCEPTION FROM: --> ' + where
        puts e.message
        puts e.backtrace.inspect

        current_time = Time.now
        doc = {
               'Who' => params['From'],
               'What' => e.message,
               'When' => current_time.strftime("%A %B %d at %I:%M %p"),
               'Where' => where,
               'Why' => request.url,
               'How' => e.backtrace,
               'utc' => current_time.to_f
        }
        DB['exceptions'].insert(doc)

      rescue Exception => e
        puts 'ERROR IN ERROR LOGGING HELPER'
        puts e.message
        puts e.backtrace.inspect
      end

    end #def log_exception


  end #helpers
  #############################################################################
  # END OF HELPERS
  #############################################################################



  #############################################################################
  # FALLBACKS AND CALLBACKS 
  #############################################################################

  #############################################################################
  # If voice_request route can't be reached or there is a runtime exception:
  #############################################################################
  get '/voice_fallback' do
    puts "VOICE FALLBACK ROUTE"
    response = Twilio::TwiML::Response.new do |r|
      r.Say 'Goodbye for now!'
    end #response

    response.text do |format|
      format.xml { render :xml => response.text }
    end #do
  end #get


  #############################################################################
  # If the SMS_request route can't be reached or there is a runtime exception
  #############################################################################
  get '/SMS_fallback' do
    puts where = 'SMS FALLBACK ROUTE'
    begin
      doc = Hash.new
      params.each { |key, val|
        puts ('KEY:'+key+'  VAL:'+val)
        doc[key.to_s] = val.to_s
      }
      doc['utc'] = Time.now.to_f

      if ( env['sinatra.error'] == nil )
        puts 'NO SINATRA ERROR MESSAGE'
        doc['sinatra.error'] = 'None'
      else
        puts 'SINATRA ERROR \n WITH MESSAGE= ' + env['sinatra.error'].message
        doc['sinatra.error'] = env['sinatra.error'].message
      end

      DB['fallbacks'].insert(doc)

    rescue Exception => e;  log_exception( e, where );  end

  end #get


  #############################################################################
  # Whenever a voice interaction completes:
  #############################################################################
  get '/status_callback' do
    begin
      puts where = "STATUS CALLBACK ROUTE"

      puts doc = {
         'What' => 'Voice Call completed',
         'Who' => params['From'],
         'utc' => @now_f
      }
      puts DB['log'].insert(doc)

    rescue Exception => e;  log_exception( e, where );  end
  end #get


end #class TheApp
###############################################################################
# END OF TheAPP
###############################################################################

 

###############################################################################
#                          Things to Keep in Mind
###############################################################################
#
# !: Google API scope can be a string or an array of strings
#
# !: If some but not all scopes are authorized, unauthed routes fail silently
#
# !: To list & revoke G-API: https://accounts.google.com/IssuedAuthSubTokens
#
# !: Keep in mind where the "/" is!!!  #{SITE} includes one already...
#
# !: When it's dialing OUT, the App's ph num appears as params['From'] !
#
# !: cURL does not handle Sinatra redirects - test only 1 level deep wi Curl!
#
# !: Curious fact: In local mode, Port num does not appear, triggering rescue.
#
# +: An excellent Reg-Ex tool can be found here:   http://rubular.com
#
# +: Capped collections store documents with natural order(disk order) equal
#     to insertion order
#
# +: Capped collections also have an  automatic expiry policy (roll-over)
#
# -: Capped collections are fast to write to, but cannot handle remove
#     operations or update operations that increase the size of the doc
#
# ?: http://redis.io/topics/memory-optimization
# 
# !: http://support.redistogo.com/kb/heroku/redis-to-go-on-heroku
#
# ?: logging options: https://addons.heroku.com/#logging
#
# *: To get a Mongo Shell on the MongoHQ instance: 
# /Mongo/mongodb-osx-x86_64-2.2.2/bin/mongo --host $MONGO_URL --port $MONGO_PORT -u $MONGO_USER_ID -p $MONGO_PASSWORD   $MONGO_DB_NAME
#
# http://net.tutsplus.com/tutorials/tools-and-tips/how-to-work-with-github-and-multiple-accounts/
# http://stackoverflow.com/questions/13103083/how-do-i-push-to-github-under-a-different-username
# http://stackoverflow.com/questions/3696938/git-how-do-you-commit-code-as-a-different-user
# http://stackoverflow.com/questions/15199262/managing-multiple-github-accounts-from-one-computer
# https://heroku-scheduler.herokuapp.com/dashboard
#
# http://stackoverflow.com/questions/10407638/how-do-i-pass-a-ruby-array-to-javascript-to-make-a-line-graph
# http://blog.crowdint.com/2011/03/31/make-your-sinatra-more-restful.html
#
###############################################################################


 #############################################################################
 #                                                                           #
 #                           OPEN SOURCE LICENSE                             #
 #                                                                           #
 #             Copyright (C) 2011-2013  Dr. Stephen A. Racunas               #
 #                                                                           #
 #                                                                           #
 #   Permission is hereby granted, free of charge, to any person obtaining   #
 #   a copy of this software and associated documentation files (the         #
 #   "Software"), to deal in the Software without restriction, including     #
 #   without limitation the rights to use, copy, modify, merge, publish,     #
 #   distribute, sublicense, and/or sell copies of the Software, and to      #
 #   permit persons to whom the Software is furnished to do so, subject to   # 
 #   the following conditions:                                               #
 #                                                                           #
 #   The above copyright notice and this permission notice shall be          #
 #   included in all copies or substantial portions of the Software.         #
 #                                                                           #
 #                                                                           #
 #   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,         #
 #   EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF      #
 #   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  #
 #   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY    # 
 #   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,    #
 #   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE       # 
 #   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                  #
 #                                                                           #
 #############################################################################


