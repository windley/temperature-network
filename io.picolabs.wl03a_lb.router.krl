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
// Manual: http://wiki.dragino.com/xwiki/bin/view/Main/User%20Manual%20for%20LoRaWAN%20End%20Nodes/WL03A-LB_LoRaWAN_None-Position_Rope_Type_Water_Leak_Controller_User_Manual/  
//
        payload = event:attrs{["payload"]};
        payload_size = event:attrs{["payload_size"]}.klog("Payload size: "); 
        payload_array = (payload_size == 7) => dragino:get_payload("wl03a_lb_status", payload).klog("Payload status: ")
                      | (payload_size == 11) => dragino:get_payload("wl03a_lb_data", payload).klog("Payload data: ")
                      | []

    }
    always {
       raise sensor event "new_status" attributes
             {"status": payload_array,
              "reported_at": event:attrs{["reported_at"]}} if payload_size == 7
       raise sensor event "new_data" attributes
             {"data": payload_array,
              "reported_at": event:attrs{["reported_at"]}} if payload_size == 11
    }
}

  rule process_leak_data {
      select when sensor new_data
      pre {

        data_array = event:attrs{["data"]}.klog("data array")
        status = data_array[0].as("Hex")
        
        sensor_data = { "leak": status.band("1").klog("Leak?"),
                        "alarm": status.band("2").klog("Alarm?"),
                        "tdc": status.band("4").klog("TDC?"),
                        "leak_events": data_array[1].klog("Leak events?"),
                        "leak_duration": data_array[2].klog("Duration") // sec
                      };

        readings = {"readings":  sensor_data,
                    "timestamp": event:attrs{["reported_at"]}
	                 }
      }
      always {

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