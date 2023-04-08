ruleset io.picolabs.lse01.router {
  meta {
    name "LSE01_device"
    description <<
Received and decodes heartbeat information from a Dragino LSE01 (soil sensor)
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.dragino alias dragino

    share lastHeartbeat, lastMoisture, lastTemperature, lastConductivity

  }

  global {

    channels = [
      {"tags": ["lse01", "sensor"],
       "eventPolicy": {
         "allow": [ { "domain": "lse01", "name": "*" }, ],
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


    cToF = function(c){c*1.8+32};
    fix_temperatures = function(x){(x < 32768 => x | x-65536)/100}; 


    // API functions
    lastHeartbeat = function() {
      ent:lastHeartbeat.klog("Return value ")
    }

    lastMoisture = function() {
      ent:lastMoisture
    }
    
    lastTemperature = function() {
      ent:lastTemperature
    }

    lastConductivity = function() {
      ent:lastConductivity
    }
        
  }

  // mostly for debugging; see all data from last heartbeat
  rule receive_heartbeat {
    select when lse01 heartbeat
    pre {

      heartbeat = event:attrs{"payload"};

    }
    always {
      ent:lastHeartbeat := heartbeat;
    }
  }


  rule process_heartbeat {
      select when lse01 heartbeat
      pre {
        payload_array = dragino:get_payload("lse01", event:attrs{["payload"]})
        battery_status = dragino:get_battery_status("lse01", payload_array)
        battery_voltage = dragino:get_battery_value("lse01", payload_array)
        
        moisture = (payload_array[2]/100).klog("Moisture (%)")
        temperature = dragino:cToF(dragino:fix_temperatures(payload_array[3])).klog("Temperature (F)")
        conductivity = payload_array[4].klog("Conductivity (uS/cm)")
        
        sensor_data = {"moisture": moisture,
                       "temperature": temperature,
                       "conductivity": conductivity,
                       "battery_status": battery_status,
                       "battery_voltage": battery_voltage
                      };

        readings = {"readings":  sensor_data,
	                  "sensor_id": event:attrs{["uuid"]},
                    "sensor_type": "dragino_lse01",
                    "timestamp": event:attrs{["reported_at"]}
	                 }
      }
      always {
        ent:lastMoisture := moisture;
        ent:lastTemperature :=  temperature;
        ent:lastConductivity := conductivity;


        raise sensor event "new_readings" attributes readings;

      }
  }

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