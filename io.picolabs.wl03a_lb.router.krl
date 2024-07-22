ruleset io.picolabs.wl03a_lb.router {
  meta {
    name "WL03A-LB_device"
    
    description <<
Received and decodes heartbeat information from a Dragino WL03A-LB Leak Detector
>>

    author "PJW"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.dragino alias dragino

    share lastHeartbeat


  }

  global {

    channels = [
      {"tags": ["wl03a_lb", "sensor"],
       "eventPolicy": {
         "allow": [ { "domain": "wl03a_lb", "name": "*" }, ],
        "deny": []
        },
       "queryPolicy": {
         "allow": [ { "rid": "*", "name": "*" } ],
         "deny": []
       }
     },
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

    // API functions
    lastHeartbeat = function() {
      ent:lastHeartbeat.klog("Return value ")
    }

    lastLiquidLevel = function() {
      ent:lastLiquidLevel
    }

  }

  // mostly for debugging; see all data from last heartbeat
  rule receive_heartbeat {
    select when wl03a_lb heartbeat
    pre {

      heartbeat = event:attrs 

    }
    always {
      ent:lastHeartbeat := heartbeat;
    }
  }

// 10g propane tank full (and warm): 557mm
// after cooking steak (20 min): 537mm


  rule process_heartbeat {
      select when wl03a_lb heartbeat
      pre {
// Payload array for WL03A-LB
// Device Status (7 bytes)
// Array index    0       1           2           3         4            
// Size(bytes)    1       2           1           1         2
// Value          Mode     Firmware    Freq        Sub-band  Battery
//
// Leak Status (11 bytes)
// Array index    0       1           2           3             
// Size(bytes)    1       3           3           4 
// Value          Status  Total Leak  Last Leak   Unix 
//                Alarm   Evemts      Duration    Timestamp
//
        payload = event:attrs{["payload"]};
        payload_size = event:attrs{["payload_size"]}; 
        payload_array = (payload_size == 14) => dragino:get_payload("wl03a_lb_status", payload).klog("Payload status: ")
                      | (payload_size == 22) => dragino:get_payload("wl03a_lb_data", payload).klog("Payload data: ")
                      | [].klog("Payload size: #{payload_size} ");

        battery_status = dragino:get_battery_status("ldds20", payload_array)
        battery_voltage = dragino:get_battery_value("ldds20", payload_array)

        sensor_data = {"liquid_level": payload_array[1], // in mm
                       "battery_status": battery_status,
                       "battery_voltage": battery_voltage
                      };

        readings = {"readings":  sensor_data,
                    "sensor_type": "dragino_wl03a_lb",
	                  "sensor_id": event:attrs{["uuid"]},
                    "timestamp": event:attrs{["reported_at"]}
	                 }
      }
      always {
        ent:lastLiquidLevel := sensor_data{"liquid_level"}

      	raise sensor event "new_readings" attributes readings;       

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


}