ruleset io.picolabs.dragino {
    meta {
        name "Dragino Module"
        description "Provides functions for using Dragino devices"
        author "PJW"
        version "0.1.0"
        provides get_payload, cToF, fix_temperatures, get_battery_status, get_battery_value
    }

    global {

        cToF = function(c){math:int(c*180+3200)/100}; // two decimal places
        fix_temperatures = function(x){math:int(x < 32768 => x | x-65536)/100}; 

        get_payload = function(sensor, payload){
            decoded = math:base64decode(payload,"hex")
            split = (sensor == "lht65") => decoded.extract(re#(.{4})(.{4})(.{4})(.{2})(.{4})(.{4})#) 
                  | (sensor == "lse01") => decoded.extract(re#(.{4})(.{4})(.{4})(.{4})(.{4})(.{2})#)
                                         | []
            payload_array = split.map(function(x){x.as("Number")}) //.klog("Values")
            return payload_array
        }
        get_battery_status = function(sensor, payload){
          // sensor unused unless battery status is in different places on different sensor types
          status_value = payload[0].shiftRight(14)
          statuses = ["good", "ok", "low", "ultra_low"]
          statuses[status_value]
        }
        get_battery_value = function(sensor, payload){
          // sensor unused unless battery status is in different places on different sensor types
          payload[0].band("3FFF")
        }
    }
}