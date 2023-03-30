ruleset io.picolabs.twilio.sms.krl {
  meta {
    name "Twilio Module for SMS only"
    description <<
      Utility methods for sending SMS with Twilio
    >>
    author "Phil Windley"
    
    configure using twiliokeys = {}
    
    provides 
        //actions
        send_sms

    shares show_configuration

  }

  global {
    
    from_number =  meta:rulesetConfig{["from_number"]} || ent:from_number 
  
    account_sid = meta:rulesetConfig{["account_sid"]} || ent:account_sid
    auth_token = meta:rulesetConfig{["auth_token"]} || ent:auth_token
    
    base_url = "https://#{account_sid}:#{auth_token}@api.twilio.com/2010-04-01/Accounts/#{account_sid}/"
    
    show_configuration = function() {
      return {"account_sid": ent:account_sid,
              "auth_token": ent:auth_token,
              "from_number": ent:from_number}
    }

    //outgoing actions
    send_sms = defaction(to, from, message){ 
        http:post(base_url + "SMS/Messages", 
            json = {
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
      from_number = event:attr("twilio_from_number")
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
  
}