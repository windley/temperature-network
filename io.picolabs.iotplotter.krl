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

    send_payload = defaction(feed_id, api_key, event_attrs) {
      http:post("http://iotplotter.com/api/v2/feed/" + feed_id,
         headers = {"api-key": api_key},
         json = {"data": format_payload(event_attrs)}
      ) setting(resp);
      return resp
    }

  }



  rule send_data_to_IoTPlotter {
    select when sensor new_readings

    send_payload(meta:rulesetConfig{["feed_id"]},
                 meta:rulesetConfig{["api_key"]},
                 event:attrs) setting(resp)
   
    always {
      response =  resp.klog("POST response");
    }
  }
  


  rule send_temperature_data_to_IoTPlotter {
    select when lht65 new_readings

    send_payload(meta:rulesetConfig{["feed_id"]},
                 meta:rulesetConfig{["api_key"]},
                 event:attrs) setting(resp)
   
    always {
      response =  resp.klog("POST response");
    }
  }
  
  rule send_soil_data_to_IoTPlotter {
    select when lse01 new_readings

    send_payload(meta:rulesetConfig{["feed_id"]},
                 meta:rulesetConfig{["api_key"]},
                 event:attrs) setting(resp)
   
    always {
      response =  resp.klog("POST response");
    }
  }
  

}