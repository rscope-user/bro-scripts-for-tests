module Latency;

export {

    const poll_interval: interval = 1min &redef;
    redef enum Log::ID += { LOG };

    type Info: record {
        current_time: time &log;
        network_time: time &log;
        seconds_latency: interval &log;
    };

    global log_bro_latency: event(rec: Info);
    global poll_time: event();
}


event Latency::poll_time ()
{
    
    local latency = (current_time() - network_time());  
    local rec = [$network_time = network_time(), $seconds_latency = latency, $current_time = current_time() ];
    
    Log::write(Latency::LOG, rec);
    schedule poll_interval  { poll_time() };
    
}

event bro_init() {
    Log::create_stream(Latency::LOG, [$columns=Info, $ev=log_bro_latency]);
    schedule poll_interval { Latency::poll_time() };
}


