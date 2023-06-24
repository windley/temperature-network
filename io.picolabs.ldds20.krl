ruleset io.picolabs.ldds20.router {
  meta {
    name "LDDS29_device"
    description <<
Received and decodes heartbeat information from a Dragino LDDS20 liquid level sensor
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.dragino alias dragino

    share lastHeartbeat, lastLiquidLevel


  }

  global {

    channels = [
      {"tags": ["ldds20", "sensor"],
       "eventPolicy": {
         "allow": [ { "domain": "ldds20", "name": "*" }, ],
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
    select when ldds20 heartbeat
    pre {

      heartbeat = event:attrs 

    }
    always {
      ent:lastHeartbeat := heartbeat;
    }
  }

// "payload":"DUcAAAAAAAE=" 3 in of water
// "payload":"DTwAAAAAAAE=" 0.75 in
// "payload":"DSwAAAAAAAE="


  rule process_heartbeat {
      select when ldds20 heartbeat
      pre {
// Payload array for LDDS20
// Array index    0       1           2           3         4            
// Size(bytes)    2       2           1           2         1
// Value          BAT     Distance    Int         Temp      Sensor Flag
//
        payload_array = dragino:get_payload("ldds20", event:attrs{["payload"]}).klog("Payload data: ")

        battery_status = dragino:get_battery_status("ldds20", payload_array)
        battery_voltage = dragino:get_battery_value("ldds20", payload_array)
        
        temperature = dragino:cToF(dragino:fix_temperatures(payload_array[1])).klog("Temperature (F)")
        humidity = (payload_array[2]/10).klog("Relative Humidity")
        external_sensor = ((payload_array[3] == 0) => "None" 
                          |(payload_array[3] == 1) => "Temperature" 
                          |                           "Something else").klog("External Sensor")
        probe_connected = (not (payload_array[4] == 32767)).klog("Probe connected?")
        external_temp = dragino:cToF(dragino:fix_temperatures(payload_array[4])).klog("Temperature Probe (F)");

        sensor_data = {"device_temperature": temperature,
                       "humidity": humidity,
                       "battery_status": battery_status,
                       "battery_voltage": battery_voltage
                      };

        readings = {"readings":  probe_connected => sensor_data.put({"probe_temperature": external_temp})
                                                  | sensor_data,
                    "probe_connected": probe_connected,
                    "sensor_type": "dragino_ldds20",
	                  "sensor_id": event:attrs{["uuid"]},
                    "timestamp": event:attrs{["reported_at"]}
	                 }
      }
      always {
        ent:lastInternalTemp := temperature
        ent:lastProbeTemp :=  external_temp
        clear ent:lastProbeTemp if not (probe_connected)
        ent:lastHumidity := humidity

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