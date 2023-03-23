ruleset io.picolabs.lse01.router {
  meta {
    name "LSE01_device"
    description <<
Received and decodes heartbeat information from a Dragino LSE01 (soil sensor)
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler

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
        payload = event:attrs{["payload"]};
        decoded = math:base64decode(payload.klog("Payload"),"hex").klog("Decoded")
        split_str = decoded.extract(re#(.{4})(.{4})(.{4})(.{4})(.{4})(.{2})#).klog("Split")
        payload_array = split_str.map(function(x){x.as("Number")}).klog("Values");
        moisture = (payload_array[2]/100).klog("Moisture (%)")
        temperature = cToF(fix_temperatures(payload_array[3])).klog("Temperature (F)")
        conductivity = payload_array[4].klog("Conductivity (uS/cm)")
        battery_status = payload_array[0].shiftRight(14).klog("Battery status")
        battery_voltage = payload_array[0].band("3FFF").klog("Battery voltage (mV)")

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