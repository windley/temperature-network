ruleset io.picolabs.sensor.community {
  meta {

    name "sensor_community"
    author "PJW"
    description "General rules for managing a community of Wovyn devices"
    version "draft"

    use module io.picolabs.wrangler alias wrangler
   
    shares
      children,
      temperatures
      
    //provides 
  }

  global {

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
    rids_to_install = {"lht65": ["io.picolabs.lht65.router"],
                       "lse01": ["io.picolabs.lse01.router"],
                       "all":   ["io.picolabs.sensor.thresholds",
                                 "io.picolabs.iotplotter",
                                 //"io.picolabs.sensor.twilio",
                                ]
                     };


    temperatures = function() {
      children = wrangler:children();
      children.map(function(child){
                      wrangler:picoQuery(child.get("eci"),
                                         "io.picolabs.lht65.router",
                                         "lastTemperature")
                      .head()
                   });
    };

  }
 
  rule new_sensor {
    select when sensor initiation
    pre {
      sensor_color = (event:attr("color")|| "#ae85fa").klog("Color: ")
      sensor_name = (event:attr("name") || "sensor_"+random:word()).klog("Name: ")
      sensor_type = (event:attr("type") || "dht65").klog("Type: ")
      to_install = rids_to_install{"all"}.append(rids_to_install{event:attr(sensor_type)}.defaultsTo([]));
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
            "config":{},
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

  
  rule create_channels {
    select when wrangler ruleset_installed where event:attr("rids") >< ctx:rid
    foreach channels setting(channel)
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