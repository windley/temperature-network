ruleset io.picolabs.lht65.router {
  meta {
    name "LHT65_device"
    description <<
Received and decodes heartbeat information from a Dragino LHT65
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler

    share lastHeartbeat, lastHumidity, lastInternalTemp, lastProbeTemp

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


    cToF = function(c){c*1.8+32};
    fix_temperatures = function(x){(x < 32768 => x | x-65536)/100}; 


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
        payload = event:attrs{["payload"]} || testHeartbeat{"payload"};
        decoded = math:base64decode(payload.klog("Payload"),"hex").klog("Decoded")
        split_str = decoded.extract(re#(.{4})(.{4})(.{4})(.{2})(.{4})(.{4})#).klog("Split")
        payload_array = split_str.map(function(x){x.as("Number")}).klog("Values");
        temperature = cToF(fix_temperatures(payload_array[1])).klog("Temperature (F)")
        humidity = (payload_array[2]/10).klog("Relative Humidity")
        battery_status = payload_array[0].shiftRight(14).klog("Battery status")
        battery_voltage = payload_array[0].band("3FFF").klog("Battery voltage (mV)")
        external_sensor = (payload_array[3] == 1) => "Temperature" | "Something else"
        probe_connected = (not (payload_array[4] == 32767)).klog("Probe connected?")
        celsius_temp = fix_temperatures(payload_array[4]).klog("Temperature Probe (C)");
        external_temp = cToF(celsius_temp).klog("Temperature Probe (F)");

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