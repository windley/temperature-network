ruleset io.picolabs.lht65.router {
  meta {
    name "LHT65_device"
    description <<
Received and decodes heartbeat information from a Dragino LHT65
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.dragino alias dragino

    shares lastHeartbeat, lastHumidity, lastInternalTemp, lastProbeTemp

  }

  global {

    channels = [
      {"tags": ["lht65", "sensor"],
       "eventPolicy": {
         "allow": [ { "domain": "lht65", "name": "*" }, ],
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

    lastHumidity = function() {
      ent:lastHumidity
    }
    
    lastInternalTemp = function() {
      ent:lastInternalTemp
    }

    lastProbeTemp = function() {
      ent:lastProbeTemp
    }

    testHeartbeat = {
          "app_eui": "A840414391822BC8",
          "dc": {
            "balance": 999956,
            "nonce": 2
          },
          "dev_eui": "A84041CF21822BC8",
          "devaddr": "06000048",
          "downlink_url": "https://console.helium.com/api/v1/down/dcb82547-52ad-476b-a7e0-1d0999dcc8f3/VHooiGqfKQ6e4S7QWz7gZ7ttjnvV3P5i/629ddc75-8dc1-4eab-bc26-aec81b9909e9",
          "fcnt": 3,
          "hotspots": [
            {
              "channel": 15,
              "frequency": 905.2999877929688,
              "hold_time": 315,
              "id": "11G3PwHoWqb7NxmSaqQr91SudgpTULKu54g1awxWxY4Wzm2ZoMR",
              "lat": 44.28996071391308,
              "long": -111.45857325492528,
              "name": "dazzling-glass-puppy",
              "reported_at": 1649362146028,
              "rssi": -54,
              "snr": 13.5,
              "spreading": "SF10BW125",
              "status": "success"
            }
          ],
          "id": "629ddc75-8dc1-4eab-bc26-aec81b9909e9",
          "metadata": {
            "adr_allowed": false,
            "cf_list_enabled": false,
            "multi_buy": 1,
            "organization_id": "6cf8fa0a-e25d-42b0-8e83-be1d5cafaea2",
            "rx_delay": 1,
            "rx_delay_actual": 1,
            "rx_delay_state": "rx_delay_established"
          },
          "name": "First",
          "payload": "y7AJrwD2AQj1f/8=",
          "payload_size": 11,
          "port": 2,
          "raw_packet": "QAYAAEiAAwACUZiZ3UcCGh5ZjHdolaEB",
          "replay": false,
          "reported_at": 1649362146028,
          "type": "uplink",
          "uuid": "cb9f03ec-0544-44c8-b57d-26337d841c4d"
        };
        
  }

  // mostly for debugging; see all data from last heartbeat
  rule receive_heartbeat {
    select when lht65 heartbeat
    pre {

      heartbeat = event:attrs{"payload"} => event:attrs | testHeartbeat.klog("*** Using test data ***");

    }
    always {
      ent:lastHeartbeat := heartbeat;
    }
  }

  rule process_heartbeat {
      select when lht65 heartbeat
      pre {
// Payload array for LHT65
// Array index    0       1           2           3         4            
// Size(bytes)    2       2           2           1         4
// Value          BAT     Built-In    Built-in    Ext #     Ext value
//                        Temperature Humidity
//
// First 6 bytes: has fix meanings for every device.
// The 7th byte (EXT #): defines the external sensor model. (0 if missing, 1 for temperature)
        payload_array = dragino:get_payload("lht65", event:attrs{["payload"]}).klog("Payload array")

        battery_status = dragino:get_battery_status("lht65", payload_array)
        battery_voltage = dragino:get_battery_value("lht65", payload_array)
        
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
                    "sensor_type": "dragino_lht65",
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

    // meant to generally route events to sensor community. Extend eventex to choose what gets routed
    rule route_to_community {
      select when sensor new_readings
      pre {
        community = wrangler:parent_eci();
      }
      every {
        send_directive("Routing to community", community, event:attr())
        event:send({"eci": community, "domain":"sensor", "type": event:type(), "attrs": event:attr()});
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