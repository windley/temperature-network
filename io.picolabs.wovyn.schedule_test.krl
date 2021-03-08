ruleset schedule_test {
  meta {
    name "schedule_test"
    description <<
Testing if schdules work
>>
    author "PJW"

    use module io.picolabs.wrangler alias wrangler
    use module io.picolabs.subscription alias subs

    shares gossip_schedule, gossip_period

    // provides 
  }

  global {
    gossip_schedule = function(){schedule:list()};
    gossip_period = function(){ent:gossip_period};
  }

  rule gossip {
    select when sensor gossip
    always {
      schedule sensor event "gossip"
        at time:add(time:now(), {"seconds": gossip_period()}) setting(id);
      ent:current_gossip_schedule := id.klog("Gossip schedule ID: ");
    }
  }

  rule stop_gossiping {
    select when sensor no_gossip
    schedule:remove(ent:current_gossip_schedule);
  }

  rule set_gossip_period {
    select when sensor gossip_period
    always {
      ent:gossip_period := event:attr("seconds").defaultsTo(20)
    }
  }

  rule inialize_ruleset {
    select when wrangler ruleset_installed where event:attr("rids") >< meta:rid
    pre {
      
    }
    if true then send_directive(<<Initializing #{meta:rid}>>)
    fired {
      ent:gossip_period := 20;
    }
  }


}