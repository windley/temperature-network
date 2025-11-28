ruleset io.picolabs.sensor.community {
  meta {

    name "sensor_community"
    author "PJW"
    description "General rules for managing a community of Wovyn devices"
    version "draft"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.prowl alias prowl with apikey = meta:rulesetConfig{["prowl_apikey"]} 
                                                  providerkey = meta:rulesetConfig{["prowl_providerkey"]}
    use module io.picolabs.twilio.sms alias twilio with from_number = meta:rulesetConfig{["twilio_from_number"]}
                                                        account_sid = meta:rulesetConfig{["twilio_account_sid"]} 
                                                        auth_token = meta:rulesetConfig{["twilio_auth_token"]}
   
    shares
      children,
      temperatures
      
    //provides 
  }

  global {

    sms_notification_number = "8013625611"

    channels = [
      {"tags": ["sensor"],
       "eventPolicy": {
         "allow": [ { "domain": "sensor", "name": "*" }, ],
        "deny": []
        },
       "queryPolicy": {
         "allow": [ { "rid": "*", "name": "*" } ],
         "deny": []
       }
     }];

    children = function() {
      wrangler:children()
    }

    // don't add .krl extension
    rids_to_install = {"lht65":    ["io.picolabs.lht65.router"],
                       "lse01":    ["io.picolabs.lse01.router"],
                       "lsn50":    ["io.picolabs.lsn50.router"],
                       "wl03a_lb": ["io.picolabs.wl03a_lb.router"],
                       "all":      ["io.picolabs.sensor.thresholds",
                                    "io.picolabs.iotplotter",
                                    "io.picolabs.dragino"
                                   ]
                     };


    temperatures = function() {
      children = wrangler:children();
      children.map(function(child){
                     name = child.get("name").klog("Name")
                     temperature = wrangler:picoQuery(child.get("eci"),
                                                      "io.picolabs.lht65.router",
                                                      "lastInternalTemp").head()
                     reading = {"name": name,
                                "lastTemperature": temperature
                               }
                     reading
                   });
    };

  }

  // {
  //   "reading": 74.462,
  //   "name": "device_temperature",
  //   "sensor_id": "05951733-104c-45c5-99d5-1b646d061fce",
  //   "timestamp": 1679697222921,
  //   "pico_name": "lht65_test",
  //   "threshold": 60,
  //   "message": " threshold violation:  device_temperature is over threshold of 60 for dragino_lht65 "
  // }
  rule catch_threshold_violation {
    select when sensor threshold_violation
    pre {
      msg = <<Threshold violation on #{event:attr("pico_name")}: #{event:attr("message")}>>
    }
    //prowl:notify("Threshold Violatoin", msg, priority=1) setting(resp);
    twilio:send_sms(msg, sms_notification_number)
  }

  // sensor lifecycle management
  rule new_sensor {
    select when sensor initiation
    pre {
      sensor_color = (event:attr("color")|| "#ae85fa").klog("Color: ")
      sensor_name = (event:attr("name") || "sensor_"+random:word()).klog("Name: ")
      sensor_type = (event:attr("type") || "dht65").klog("Type: ")
      to_install = rids_to_install{"all"}.append(rids_to_install{sensor_type}.defaultsTo([]));
    }
    send_directive("new sensor pico initiated", {"sensor_name":sensor_name})
    always {
      ent:sensors := ent:sensors.defaultsTo([]).union([sensor_name]);
      raise wrangler event "new_child_request"
        attributes { "name": sensor_name, "backgroundColor": sensor_color,
                     "sensor_type": sensor_type,
                     "url_rids": to_install
                   }
    }
  }

rule sensor_initialization {
    select when wrangler new_child_created 
    foreach event:attr("url_rids") setting(rid)
      event:send(
        { "eci": event:attr("eci"), "eid": random:word(),
          "domain": "wrangler", "type": "install_ruleset_request",
          "attrs": {
            "absoluteURL":meta:rulesetURI,
            "rid":rid,
            "config":event:attr("config")
          }
        }
     )
  }

  rule initialize_temperatures {
    select when sensor temperature_initiation
    foreach ctx:children setting(eci)
      every {
        send_directive("initializing temperatures");
        event:send(
          { "eci": eci, "eid": random:word(),
            "domain": "sensor", "type": "temperature_initiation",
          }
        );
      }
  }

  // initialize this pico
  rule create_channels {
    select when wrangler ruleset_installed where event:attr("rids") >< ctx:rid
    foreach channels setting(channel)
     pre {
        existing_channels = wrangler:channels(channel{"tags"}.join(","));
      }
      if existing_channels.length() == 0 then 
         wrangler:createChannel(channel{"tags"},
                                channel{"eventPolicy"},
                                channel{"queryPolicy"}) setting(new_channel)
                             
  }

  rule inialize_ruleset {
    select when wrangler ruleset_installed where event:attr("rids") >< ctx:rid
    noop() // nothing to do right now
  }

    

  // this won't be needed once subscriptions are installed automatically 
  // rule install_subscription_ruleset {
  //   select when wrangler new_child_created
  //     event:send(
  //       { "eci": event:attr("eci"), "eid": random:word(),
  //         "domain": "wrangler", "type": "install_ruleset_request",
  //         "attrs": {
  //           "url" : "file:///usr/local/lib/node_modules/pico-engine/krl/io.picolabs.subscription.krl",
  //           "rid": "io.picolabs.subscription", 
  //           "config":{},
  //         }
  //       }
  //    )
  // }    

  // rule sensor_initialization {
  //   select when wrangler new_child_created
  //   foreach rids_to_install{"all"} setting(rid)
  //     event:send(
  //       { "eci": event:attr("eci"), "eid": random:word(),
  //         "domain": "wrangler", "type": "install_ruleset_request",
  //         "attrs": {
  //           "absoluteURL":meta:rulesetURI,
  //           "rid":rid,
  //           "config":{},
  //         }
  //       }
  //    )
  // }

}