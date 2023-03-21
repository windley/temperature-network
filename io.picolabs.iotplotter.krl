ruleset io.picolabs.iotplotter {
  meta {

    name "iot_plotter"
    author "PJW"
    description "Sends data to IotPlotter API"
    version "0.2.0"

    use module io.picolabs.wrangler alias wrangler

  }

  global {

     name_map = {
       "internalTemp": "device_temperature",
       "probeTemp": "probe_temperature",
       };
       

  }

  rule send_temperature_data_to_IoTPlotter {
    select when lht65 new_readings

    pre {
      feed_id = meta:rulesetConfig{["feed_id"]};
      api_key = meta:rulesetConfig{["api_key"]};

      payload_data = event:attrs{["readings"]}.map(function(reading_val){
                         [
                          {"value": reading_val,
                           "epoch": event:attrs{["timestamp"]}
                          }
                         ]}).klog("New reading map");

      payload = {"data": {
                    "device_temperature": [
                      {"value": event:attrs{["readings", "internalTemp"]},
                       "epoch": event:attrs{["timestamp"]}}
                    ],
                    "probe_temperature": [
                      {"value": event:attrs{["readings", "probeTemp"]},
                       "epoch": event:attrs{["timestamp"]}}
                    ],
                    "humidity": [
                      {"value": event:attrs{["readings", "humidity"]},
                       "epoch": event:attrs{["timestamp"]}}
                    ],
                    "battery_voltage": [
                      {"value": event:attrs{["readings", "battery_voltage"]},
                       "epoch": event:attrs{["timestamp"]}}
                    ]}
                };
    }

    http:post("http://iotplotter.com/api/v2/feed/" + feed_id,
       headers = {"api-key": api_key},
       json = payload
    ) setting(resp);

    always {
      response =  resp.klog("POST response");
    }
  }
  

}