ruleset io.picolabs.twilio.sms {
  meta {
    name "Twilio Module for SMS only"
    description "Utility methods for sending SMS with Twilio"
    author "Phil Windley"
    version "0.1.0"
    
    provides send_sms

    shares show_configuration

    configure using from_number = "801-555-1212"
                    account_sid = ""
                    auth_token = ""

  }

  global {
    
    show_configuration = function() {
      return {"account_sid": ent:account_sid,
              "auth_token": ent:auth_token,
              "from_number": ent:from_number}
    }

    // from_number =  from_number || show_configuration(){["from_number"]}
    // account_sid = account_sid || show_configuration(){["account_sid"]} 
    // auth_token = auth_token || show_configuration(["auth_token"] )
    
    base_url = <<https://#{account_sid}:#{auth_token}@api.twilio.com/2010-04-01/Accounts/#{account_sid}/>>
    
    
    //outgoing actions
    send_sms = defaction(message, to, from=from_number){ 
        http:post(base_url + "Messages.json", 
            form = {
                "From":from,
                "To":to,
                "Body":message
            });
    };
  }

  rule save_config {
    select when sensor configuration
    pre {
      auth_token = event:attr("twilio_auth_token")
      account_sid = event:attr("twilio_account_sid")
      from_number = event:attr("twilio_from_number") // number twilio gives you in E.164 format
    }
    if not (auth_token.isnull() 
          || account_sid.isnull() 
          || from_number.isnull()
           ) then noop()
    fired {
      log info "Configuring twilio";
      ent:account_sid := account_sid;
      ent:auth_token := auth_token;
      ent:from_number := from_number;
    }
  }

  // to use create a channel that allows the twilio domain; delete channel when done testing for security
  rule test_config {
    select when twilio test
    pre {
      msg = event:attr("msg")
    }
    send_sms(<<Test message:  msg>>, "+18013625611") setting(resp)
    always {
      log info "Test message sent: " + resp
    }
  }
  
}