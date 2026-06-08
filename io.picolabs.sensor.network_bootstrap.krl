ruleset io.picolabs.sensor.network_bootstrap {
  meta {
    name "Sensor Network Bootstrap"
    description <<
Install on the Manifold pico to create sensor-network communities. manifold_pico
creates the child, installs io.picolabs.community, and subscribes it; this RS
installs io.picolabs.sensor.community and records ent:sensor_communities.

Send sensor create_community to the Manifold pico to create a new sensor community.
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler

    shares getSensorCommunities
  }

  global {
    default_community_name = "Sensors"
    sensor_community_rid = "io.picolabs.sensor.community"

    // Channels to enable on the Manifold pico for this community's picoId when
    // the community is created. Matches notifications default_settings(): Manifold
    // on, external channels off unless explicitly requested on create_community.
    default_notify_channels = ["Manifold"]

    getSensorCommunities = function() {
      ent:sensor_communities.defaultsTo({}).values()
    }
  }

  // Step 1: delegate community creation to manifold_pico (generic Manifold plumbing).
  // Stash context under rcn; manifold_pico creates the child and subscribes it
  // as a manifold_community. Step 2 installs sensor.community on the child.
  rule create_sensor_community {
    select when sensor create_community
    pre {
      name = event:attr("name").defaultsTo(default_community_name)
      description = event:attr("description")
                 .defaultsTo("Sensor network managed by io.picolabs.sensor.community")
      // Optional: comma-separated or array attr listing notification channels to
      // enable for this community subject, e.g. "Manifold,SMS,Prowl"
      notify_channels = event:attr("notify_channels").defaultsTo("Manifold").split(",")
      rcn = "SN-" + random:uuid()
    }
    if name then
      send_directive("creating sensor community",
                     {"name": name, "rcn": rcn})
    fired {
      ent:pending{rcn} := {
        "name": name,
        "description": description,
        "notify_channels": notify_channels
      };
      raise manifold event "new_community"
        attributes {
          "name": name,
          "description": description,
          "rcn": rcn,
          "sensor_bootstrap": true
        }
    }
  }

  // Step 2: Manifold has created the community child. Install sensor.community
  // (sensor-network) on the child, record it, and opt the community into
  // notifications. io.picolabs.community is installed by manifold_pico.
  rule finish_sensor_community {
    select when wrangler child_initialized
      where event:attr("event_name") == "manifold_new_community"
        && event:attr("sensor_bootstrap")
    pre {
      rcn = event:attr("rcn")
      child_eci = event:attr("eci")
      sensor_url = meta:rulesetURI
      name = ent:pending{rcn}{"name"} || event:attr("name")
      description = ent:pending{rcn}{"description"} || event:attr("description")
      notify_channels = ent:pending{rcn}{"notify_channels"} || default_notify_channels
    }
    if child_eci && sensor_url then every {
      send_directive("installing sensor.community",
                     {"name": name,
                      "picoID": child_eci,
                      "rcn": rcn,
                      "sensor_url": sensor_url})
      event:send({
        "eci": child_eci,
        "domain": "wrangler",
        "type": "install_ruleset_request",
        "attrs": {
          "rid": sensor_community_rid,
          "absoluteURL": sensor_url
        }
      })
    }
    fired {
      ent:sensor_communities := ent:sensor_communities.defaultsTo({});
      ent:sensor_communities{child_eci} := {
        "name": name,
        "description": description,
        "picoID": child_eci,
        "rcn": rcn,
        "created": time:now()
      };
      clear ent:pending{rcn} if rcn;
      raise sensor event "community_ready"
        attributes {"picoID": child_eci, "notify_channels": notify_channels}
    } else {
      error warn <<finish_sensor_community skipped: rcn=#{rcn} child_eci=#{child_eci} sensor_url=#{sensor_url}>>;
    }
  }

  // Step 3: opt the community into notifications on the Manifold pico. From unset,
  // change_notification_setting's first toggle sets the channel true.
  rule provision_community_notifications {
    select when sensor community_ready
    foreach event:attr("notify_channels") setting(option)
    pre {
      picoID = event:attr("picoID")
    }
    if picoID && option then noop()
    fired {
      raise manifold event "change_notification_setting"
        attributes {"id": picoID, "option": option}
    }
  }

}
