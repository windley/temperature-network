ruleset io.picolabs.sensor.community {
  meta {

    name "sensor_community"
    author "PJW"
    description "General rules for managing a community of Wovyn devices"
    version "draft"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.subscription alias subscription
    use module io.picolabs.pds alias pds
     
    shares
      test_push,
      children, 
      readings,
      lastTemperatures
      
    //provides 
  }

  global {

    channels = [
      {"tags": ["sensor"],
       "eventPolicy": {
         "allow": [
           { "domain": "sensor", "name": "*" },
           { "domain": "community", "name": "add_thing" }
         ],
        "deny": []
        },
       "queryPolicy": {
         "allow": [ { "rid": "*", "name": "*" } ],
         "deny": []
       }
     },
      // Dedicated channel for Manifold's thing-creation delegation callback.
      // The subscription well-known channel cannot be used as callback_eci
      // because its event policy only allows engine_ui/wrangler events, not
      // the "community thing_created" callback Manifold sends.
      {"tags": ["manifold_callback"],
       "eventPolicy": {
         "allow": [ { "domain": "community", "name": "thing_created" } ],
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


    // Sensors are now Manifold "things" subscribed to this community rather than
    // child picos, so enumerate them via the community/thing subscriptions.
    sensorThings = function() {
      subscription:established().filter(function(sub){
        sub{"Tx_role"} == "thing"
      });
    };

    pdsProfileField = function(eci, field) {
      wrangler:picoQuery(eci, "io.picolabs.pds", "profile", field){"profile"}
    };

    thingDisplayName = function(sub) {
      sub{"name"}
        || pdsProfileField(sub{"Tx"}, "name")
        || wrangler:picoQuery(sub{"Tx"}, "io.picolabs.wrangler", "myself"){"name"}
    };

    lastTemperatures = function() {
      sensorThings().map(function(sub){
                     temperature = wrangler:picoQuery(sub{"Tx"},
                                                     "io.picolabs.lht65.router",
                                                     "lastInternalTemp");
                     {"name": thingDisplayName(sub),
                      "lastTemperature": temperature
                     }
                   });
    };

    push = function(array, new_element, len=10) {
      cur_len = array.length();
      new_array = cur_len >= len => array.splice(len-1, (cur_len - len) + 1)
                                  | array;
      new_element.append(new_array.klog("new array"))
    }

    test_push = function() {
      a_s = [0,1,2,3,4,5,6,7,8,9,10,11,12];
      new_a_s = a_s.push(15).klog("one item on 13 element array, should be [15,0,1,2,3,4,5,6,7,8]; is ")
      b_s = [0,1,2,3,4,5];
      new_b_s = b_s.push(10).klog("one iterm on short array, should be [10,0,1,2,3,4,5]; is ")
      c_s = [0,1,2,3,4,5,6,7,8,9];
      new_c_s = c_s.push(25).klog("one item on 10 element array with default, should be [25,0,1,2,3,4,5,6,7,8]; is ")
      new_c_s_2 = c_s.push(55, 5).klog("one item on 10 element array with length set to 5, should be [55,0,1,2,3]; is ")
      d_s = c_s.append(b_s)
      new_d_s = d_s.push(46, 15).klog("one item on a 16 element array with len = 15, should be [46.0,1,2,3,4,5,6,7,8,9,0,1,2,3]; is")
      "testing done, check logs"
    }

    readings = function(name) {
      name => ent:sensor_readings{name}
            | ent:sensor_readings
    }
    

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
  // Route threshold violations to the Manifold pico's notification platform
  // ("manifold add_notification") instead of calling Prowl/Twilio directly.
  // Manifold fans the notification out to Twilio/Prowl/Email/Text per the
  // thing's notification_settings. The manifold pico is the Tx of our
  // "manifold_pico"-role subscription.
  rule catch_threshold_violation {
    select when sensor threshold_violation
    pre {
      manifold_eci = subscription:established().filter(function(s){
        s{"Tx_role"} == "manifold_pico"
      }).head(){"Tx"};
      // The community is the notification SUBJECT for network-function alerts, so
      // we report our OWN picoId. The originating sensor's name/id ride along for
      // display only.
      sensor_id = event:attr("sender_id") || event:attr("sensor_id");
      pico_name = event:attr("pico_name") || event:attr("name");
      thing = pico_name;
      msg = <<Threshold violation on #{pico_name}: #{event:attr("message")}>>;
      community_name = pds:profile("name"){"profile"}
                         || wrangler:name().defaultsTo("Sensor Network");
      attrs = {
        "picoId"   : meta:picoId,
        "thing"    : thing,
        "sensor_id": sensor_id,
        "app"      : community_name,
        "message"  : msg,
        "ruleset"  : meta:rid
      };
    }
    if manifold_eci && thing then
      event:send({ "eci": manifold_eci,
                   "domain": "manifold",
                   "type": "add_notification",
                   "attrs": attrs });
  }

	  rule catch_new_readings {
    select when sensor new_readings
    pre {
      name = event:attr("sensor_name");
    }
    always {
      ent:sensor_readings{name} := ent:sensor_readings{name}.defaultsTo([]).push(event:attrs)
    }
  }

  // sensor lifecycle management
  //
  // Delegation step (initiate): rather than creating the sensor pico as our own
  // child, we ask the Manifold pico (our parent) to create a bare "thing" and
  // call us back. We mint a correlation id (rcn), stash the sensor-specific
  // context under it, and pass only {name, callback_eci, rcn} to Manifold.
  rule new_sensor {
    select when sensor initiation
    pre {
      sensor_color = (event:attr("color")|| "#ae85fa").klog("Color: ")
      sensor_name = (event:attr("name") || "sensor_"+random:word()).klog("Name: ")
      sensor_type = (event:attr("type") || "dht65").klog("Type: ")
      url_rids = rids_to_install{"all"}.append(rids_to_install{sensor_type}.defaultsTo([]));
      config = event:attr("config").defaultsTo({});
      rcn = "REQ-" + random:uuid();
      callback_eci = wrangler:channels("manifold_callback").head(){"id"};
      manifold_eci = wrangler:parent_eci();
    }
    if sensor_name && callback_eci && manifold_eci then
      every {
        send_directive("delegating sensor creation to Manifold",
                       {"sensor_name": sensor_name, "rcn": rcn});
        event:send({
          "eci": manifold_eci,
          "eid": "create_thing",
          "domain": "manifold",
          "type": "create_thing",
          "attrs": {
            "name": sensor_name,
            "callback_eci": callback_eci,
            "rcn": rcn
          }
        });
      }
    fired {
      ent:sensors := ent:sensors.defaultsTo([]).union([sensor_name]);
      ent:pending{rcn} := {
        "name": sensor_name,
        "sensor_type": sensor_type,
        "color": sensor_color,
        "url_rids": url_rids,
        "config": config
      };
    }
  }

  // Delegation step (finish): Manifold has created and subscribed the bare
  // thing and is calling us back with the correlation id. Reload our context,
  // join the thing to this community, and give it its sensor capabilities.
  rule finish_sensor {
    select when community thing_created
    pre {
      rcn = event:attr("rcn");
      info = ent:pending.defaultsTo({}){rcn};
      thing_eci = event:attr("thing_eci");
      thingPicoID = event:attr("thingPicoID");
      url_rids = info{"url_rids"}.defaultsTo([]);
      config = info{"config"}.defaultsTo({});
    }
    if info && thing_eci then
      send_directive("finishing sensor setup",
                     {"name": info{"name"}, "thing_eci": thing_eci})
    fired {
      // establish the community <-> thing subscription (io.picolabs.community)
      raise community event "add_thing"
        attributes { "eci": thing_eci };
      // install the specialized sensor rulesets on the thing
      raise sensor event "install_rulesets"
        attributes { "thing_eci": thing_eci,
                     "url_rids": url_rids,
                     "config": config };
      ent:sensor_things{thingPicoID} := info;
      ent:sensor_things{[thingPicoID, "thing_eci"]} := thing_eci;
      clear ent:pending{rcn};
    }
  }

  // Push the sensor-type rulesets to the newly created thing. These rulesets
  // live in this same (sensor network) repo, so meta:rulesetURI resolves them.
  rule install_sensor_rulesets {
    select when sensor install_rulesets
    foreach event:attr("url_rids") setting(rid)
      pre {
        thing_eci = event:attr("thing_eci");
        config = event:attr("config");
        absoluteURL = meta:rulesetURI;
      }
      if thing_eci && absoluteURL then
        event:send({
          "eci": thing_eci,
          "eid": "install",
          "domain": "wrangler",
          "type": "install_ruleset_request",
          "attrs": {
            "rid": rid,
            "absoluteURL": absoluteURL,
            "config": config
          }
        });
  }

  // Ingest sensor events arriving from member things (sensors report via
  // io.picolabs.thing's community_notify -> community thing_event_occurred)
  // and re-raise them into the sensor domain for the handlers below.
  rule ingest_thing_event {
    select when community thing_event_occurred where event:attr("domain") == "sensor"
    pre {
      evt_type = event:attr("type");
      // carry the originating thing's pico id (sender_id) so downstream
      // handlers (e.g. notifications) can identify the source thing
      evt_attrs = event:attr("attrs").defaultsTo({}).put("sender_id", event:attr("sender_id"));
    }
    if evt_type then
      send_directive("ingesting thing event", {"type": evt_type})
    fired {
      raise sensor event evt_type attributes evt_attrs
    }
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