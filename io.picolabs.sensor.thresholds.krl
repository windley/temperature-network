ruleset io.picolabs.sensor.thresholds {
  meta {

    name "Sensor_thresholds"
    author "PJW"
    description "Ruleset for tracking thresholds and notifying on violation"
    version "0.1.0"

    use module io.picolabs.wrangler alias wrangler
    
    
    shares thresholds
    provides thresholds
  }

  global {

    // public
    thresholds = function(threshold_type) {
      threshold_type => ent:thresholds{threshold_type}
                      | ent:thresholds
    }
  }

  // rule to save thresholds
  rule save_threshold {
    select when sensor new_threshold
    pre {
      threshold_type = event:attr("threshold_type").klog("Threshold type: ");
      threshold_value = {"limits": {"upper": event:attr("upper_limit"),
                                    "lower": event:attr("lower_limit")
				                }};
    }
    if(threshold_type.length() > 0) then send_directive(threshold_type);
    fired {
      log info << Setting threshold value for #{threshold_type} >>;
      ent:thresholds{threshold_type} := threshold_value;
    } else {
      log error "Missing threshold_type. Not saved";
    }
  }

  rule clear_threshold {
    select when sensor threshold_not_needed
    always {
      clear ent:thresholds{event:attr("threshold_type")}
    }
  }

  rule check_threshold {
    select when sensor new_readings

    foreach event:attr("readings") setting (reading, name)
      pre {
        // thresholds
		    threshold_map = thresholds(name)
	      lower_threshold = threshold_map{["limits","lower"]}
	      upper_threshold = threshold_map{["limits","upper"]}
	    }
      if(not threshold_map.isnull() ) then noop();
      fired {
        raise sensor event "threshold_exists" attributes
  	          {"reading": reading,
               "name": name,
 	             "sensor_id": event:attr("sensor_id"),
               "sensor_type": event:attr("sensor_type"),
               "timestamp": event:attr("timestamp"),
               "upper_threshold": upper_threshold,
               "lower_threshold": lower_threshold
             }
      }
  }

  rule check_violation {
    select when sensor threshold_exists
    pre {
      // decide
      upper_threshold = event:attr("upper_threshold")
      lower_threshold = event:attr("lower_threshold")
      reading = event:attr("reading")
      name = event:attr("name")
      sensor_type = event:attr("sensor_type")
      under = reading < lower_threshold;
      over = upper_threshold < reading;
      msg = under => <<#{name} is under threshold of #{lower_threshold}°F at #{reading}°F>>
          | over  => <<#{name} is over threshold of #{upper_threshold}°F at #{reading}°F>>
          |          <<#{name} is between #{lower_threshold}°F and #{upper_threshold}°F at #{reading}°F>>;
      attrs = {"reading": event:attr("reading"),
               "name": event:attr("name"),
               "sensor_id": event:attr("sensor_id"),
               "timestamp": event:attr("timestamp"),
               "pico_name": wrangler:myself(){"name"},
               "threshold": under => lower_threshold | upper_threshold,
               "message": <<#{sensor_type} #{msg}>>
              }	      

    }

    if( under || over ) then noop();
    fired {
          log warn << threshold: #{msg} for #{sensor_type} >>;
          raise sensor event "threshold_violation" attributes
            attrs.put(["threshold"], under => lower_threshold | upper_threshold)
    } else {
          log info << threshold: #{msg} for #{sensor_type} >> ;
          raise sensor event "within_threshold" attributes attrs;
    }
  }

  rule send_violation_to_parent {
    select when sensor threshold_violation
    event:send({"eci": wrangler:parent_eci().klog("Parent ECI"),
                "domain": "sensor",
                "type": "threshold_violation",
                "attrs": event:attrs
               })
   }
  
  rule inialize_ruleset {
    select when wrangler ruleset_installed where event:attr("rids") >< meta:rid
    pre {
      initial_thresholds = {
            "threshold_type" : "temperature",
            "upper_limit": 100,
            "lower_limit": 50
            };
    }
    if ( ent:thresholds.isnull() ) then send_directive("Initializing sensor pico thresholds");
    fired {
      raise sensor event "new_threshold" attributes initial_thresholds
    }
  }

}