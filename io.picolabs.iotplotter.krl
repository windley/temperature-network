ruleset io.picolabs.iotplotter {
  meta {

    name "iot_plotter"
    author "PJW"
    description "Sends data to IotPlotter API"
    version "0.3.0"

    use module io.picolabs.wrangler alias wrangler

    shares show_configuration

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

    show_configuration = function() {
      return {"api_key": ent:api_key,
              "feed_id": ent:feed_id}
    }

  }

  rule send_data_to_IoTPlotter {
    select when sensor new_readings

    send_payload((meta:rulesetConfig{["feed_id"]} || ent:feed_id).klog("Feed id"),
                 (meta:rulesetConfig{["api_key"]} || ent:api_key).klog("API key"),
                 event:attrs) setting(resp)
   
    always {
      response =  resp.klog("POST response");
    }
  }

  rule save_config {
    select when sensor configuration
    pre {
      feed_id = event:attr("iotplotter_feed_id");
      api_key = event:attr("iotplotter_api_key");
    }
    if not feed_id && not api_key then noop()
    fired {
      log info "Configuring IoT Plotter";
      ent:feed_id := feed_id;
      ent:api_key := api_key;
    }
  }

}