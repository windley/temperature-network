ruleset io.picolabs.iotplotter {
  meta {

    name "iot_plotter"
    author "PJW"
    description "Sends data to IotPlotter API"
    version "draft"

    use module io.picolabs.wrangler alias wrangler

  }

  global {

  }

  rule send_data_to_IoTPlotter {
    select when lht65 new_readings

    pre {
      feed_id = "367832564114515476";
      api_key = "43cd1f69ffad26cd06d9df3fb2613e32e5e54f87ce";
      payload = {"data": {
                    "device_temperature": [
                      {"value": event:attrs{["readings", "internal_temp"]},
                       "epoch": event:attrs{["timestamp"]}}
                    ],
                    "probe temperature": [
                      {"value": event:attrs{["readings", "probe_temp"]},
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