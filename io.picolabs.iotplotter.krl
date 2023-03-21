ruleset io.picolabs.iotplotter {
  meta {

    name "iot_plotter"
    author "PJW"
    description "Sends data to IotPlotter API"
    version "0.2.0"

    use module io.picolabs.wrangler alias wrangler

  }

  global {


 
    // map readings into format needed by IoTPlotter, removing any items with keys in `remove_these`
    format_payload = function(event_attrs) {
      remove_these = ["battery_status"];
      payload_data = event_attrs{["readings"]}
                         .map(function(reading_val){
                             [
                              {"value": reading_val,
                               "epoch": event_attrs{["timestamp"]}
                              }
                             ]})
                         .filter(function(v, k){not(remove_these >< k)}) 
                         //.klog("New reading map");
      payload_data
    };

  }

  rule send_temperature_data_to_IoTPlotter {
    select when lht65 new_readings

    pre {
      feed_id = meta:rulesetConfig{["feed_id"]};
      api_key = meta:rulesetConfig{["api_key"]};
 
    }

    http:post("http://iotplotter.com/api/v2/feed/" + feed_id,
       headers = {"api-key": api_key},
       json = {"data": format_payload(event:attrs)}
    ) setting(resp);

    always {
      response =  resp.klog("POST response");
    }
  }
  

}