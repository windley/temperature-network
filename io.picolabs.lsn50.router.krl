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

        
  }

  // mostly for debugging; see all data from last heartbeat
  rule receive_heartbeat {
    select when lsn50 heartbeat
    pre {

      heartbeat = event:attrs{"payload"} => event:attrs | {}

    }
    always {
      ent:lastHeartbeat := heartbeat;
    }
  }

  rule process_heartbeat {
      select when lsn50 heartbeat
      pre {
// Payload array for LSN50
// Array index    0       1           2           3         4       5        
// Size(bytes)    2       2           2           1         2       2
// Value          BAT     Temp01      ADC         Digital   Temp02  Temp03
//                                                Input
//

        payload_array = dragino:get_payload("lsn50", event:attrs{["payload"]})

        battery_status = dragino:get_battery_status("lsn50", payload_array)
        battery_voltage = dragino:get_battery_value("lsn50", payload_array)
        
        temperature_01 = dragino:cToF(dragino:fix_temperatures(payload_array[1])).klog("Temperature (F)")
        temperature_02 = dragino:cToF(dragino:fix_temperatures(payload_array[4])).klog("Temperature (F)")
        temperature_03 = dragino:cToF(dragino:fix_temperatures(payload_array[5])).klog("Temperature (F)")

        sensor_data = {"temperature_01": temperature_01,
                       "temperature_02": temperature_02,
                       "temperature_03": temperature_03,
                       "battery_status": battery_status,
                       "battery_voltage": battery_voltage
                      };

        readings = {"readings":  sensor_data,
                    "sensor_type": "dragino_lsn50",
	                  "sensor_id": event:attrs{["uuid"]},
                    "timestamp": event:attrs{["reported_at"]}
	                 }
      }
      always {
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