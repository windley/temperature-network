ruleset io.picolabs.prowl {
  meta {
    name "Prowl Module"
    description <<
      Provide a means of sending prowl notifications to an iPhone
    >>
    author "Phil Windley"
    

    configure using apikey = "nokey"
                    providerkey = "nokey"
                    application = "Pico Labs"
    provides notify
  }

  global {
   notify = defaction(title, description, url="", priority = 0) {
  
     http:post("https://api.prowlapp.com/publicapi/add", 
      form = {
       "apikey":apikey.klog("API Key: "),
       "providerkey":providerkey,
       "application":application,
       "priority": priority < -2 || priority > 2 => 0 | priority,
       "event": title.klog("Title: "),
       "description" : description.klog("Desc: "),
       "url": url
      }) setting (resp)

      return resp.klog("Response: ")
    } 
  }
}