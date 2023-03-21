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

  rule check_threshold {
    select when sensor new_readings

    foreach event:attr("readings") setting (reading, name)
      pre {


        // thresholds
		    threshold_map = thresholds(name).klog("Thresholds: ");
	      lower_threshold = threshold_map{["limits","lower"]}.klog("Lower threshold: ");
	      upper_threshold = threshold_map{["limits","upper"]};
  
	      sensor_type = event:attr{"sensor_type"}.klog("Type of sensor: ");

        // decide
	      under = reading < lower_threshold;
	      over = upper_threshold < reading;
	      msg = under => << #{name} is under threshold of #{lower_threshold}>>
	          | over  => << #{name} is over threshold of #{upper_threshold}>>
	          |          << #{name} is between #{lower_threshold} and #{upper_threshold}>>;
      }
      if(  under || over ) then noop();
      fired {
            log warn << threshold: #{msg} for #{sensor_type} >>;
	          raise sensor event "threshold_violation" attributes
  	          {"reading": reading,
 	             "sensor_id": event:attr("sensor_id"),
               "timestamp": event:attr("timestamp"),
	             "threshold": under => lower_threshold | upper_threshold,
	             "message": << threshold violation: #{msg} for #{sensor_type} >>
	            }	      
     } else { 
            log info << threshold: #{msg} for #{sensor_type} >>;
            raise sensor event "within_threshold" attributes
  	          {"reading": reading,
 	             "sensor_id": event:attr("sensor_id"),
               "timestamp": event:attr("timestamp"),
		           "message": << within threshold: #{msg} for #{sensor_type} >>
	            }	      
     }
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