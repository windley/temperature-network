ruleset io.picolabs.lsn50.router {
  meta {
    name "LSN50_device"
    description <<
Received and decodes heartbeat information from a Dragino LSN50
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.dragino alias dragino

    share lastHeartbeat, lastTemperature_01, lastTemperature_02, lastTemperature_03

  }

  global {

    channels = [
      {"tags": ["lsn50", "sensor"],
       "eventPolicy": {
         "allow": [ { "domain": "lsn50", "name": "*" }, ],
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

    lastTemperature_01 = function() {
      ent:lastTemperature_01
    }
    
    lastTemperature_02 = function() {
      ent:lastTemperature_02
    }
    
    lastTemperature_03 = function() {
      ent:lastTemperature_03
    }

    expected_payload_size = 11

        
  }

  // mostly for debugging; see all data from last heartbeat
  rule receive_heartbeat {
    select when lsn50 heartbeat
    pre {

      heartbeat = event:attrs{"payload"} => event:attrs | {}

    }
    if(event:attrs{"payload_size"} == expected_payload_size) then noop()
    fired {
      ent:lastHeartbeat := heartbeat;
    }
  }

  rule process_heartbeat {
      select when lsn50 heartbeat
      pre {
// Payload array for LSN50
// Array index    0       1           2           3         4       5        
// Size(bytes)    2       2           2           1         2       2
// Value          BAT     Temp01      Ignore      Alarm     Temp02  Temp03
//                                                Flag
// http://wiki.dragino.com/xwiki/bin/view/Main/User%20Manual%20for%20LoRaWAN%20End%20Nodes/LSN50v2-D20-D22-D23%20LoRaWAN%20Temperature%20Sensor%20User%20Manual/

        payload_array = dragino:get_payload("lsn50", event:attrs{["payload"]})

        // lsn50 doesn't support battery status
        // battery_status = dragino:get_battery_status("lsn50", payload_array)
        battery_voltage = dragino:get_battery_value("lsn50", payload_array)
        
        temperature_01 = dragino:cToF(dragino:fix_temperatures(payload_array[1], "lsn50")).klog("Temperature (F)") // white
        temperature_02 = dragino:cToF(dragino:fix_temperatures(payload_array[4], "lsn50")).klog("Temperature (F)") // red
        temperature_03 = dragino:cToF(dragino:fix_temperatures(payload_array[5], "lsn50")).klog("Temperature (F)") // black

        sensor_data = {"white_probe": temperature_01,
                       "red_probe": temperature_02,
                       "black_probe": temperature_03,
                       "battery_voltage": battery_voltage
                      };

        readings = {"readings":  sensor_data,
                    "sensor_type": "dragino_lsn50",
	                  "sensor_id": event:attrs{["uuid"]},
                    "timestamp": event:attrs{["reported_at"]}
	                 }
      }
      if(event:attrs{"payload_size"} == expected_payload_size) then noop()
      fired {
        ent:lastTemperature_01 := temperature_01
        ent:lastTemperature_02 := temperature_02
        ent:lastTemperature_03 := temperature_03

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
