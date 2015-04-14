module TopOrigHosts;

export {
    
    global epoch: interval = 20min &redef;
    global top_k_size: count = 20 &redef;

    # Logging info
    redef enum Log::ID += { LOG };

    type Info: record {
        start_time: string &log;
        epoch: interval &log;
        top_orig_hosts: set[string]    &log;
    };

    global top_orig_session: set[string];
    global log_top_orig_hosts: event(rec: Info);
    
}

event bro_init()
    {
    local rec: TopOrigHosts::Info;
    Log::create_stream(TopOrigHosts::LOG, [$columns=Info, $ev=log_top_orig_hosts]);

    local r1 = SumStats::Reducer($stream="top.origh", $apply=set(SumStats::TOPK), $topk_size=top_k_size);
    SumStats::create([$name="top_top.origh",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["top.origh"];
                        
                        local s: vector of SumStats::Observation;
                        s = topk_get_top(r$topk, top_k_size);
         
                        for ( i in s )
                            {
                                add top_orig_session[s[i]$str];
                                
                            }
                            
                                
                        },
                        $epoch_finished(ts: time) =
                        {
                            rec = [$start_time=strftime("%c", (ts - epoch)), $epoch=epoch, $top_orig_hosts=top_orig_session];
                            top_orig_session = set();
                            Log::write(TopOrigHosts::LOG, rec);
                       
                        }]);
    }

event connection_state_remove(c: connection)
    {
        SumStats::observe("top.origh", [], [$str=fmt("%s", c$id$orig_h)]);
    }

