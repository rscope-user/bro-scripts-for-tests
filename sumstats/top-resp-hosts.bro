module TopRespHosts;

export {
    
    global epoch: interval = 20min &redef;
    global top_k_size: count = 20 &redef;

    # Logging info
    redef enum Log::ID += { LOG };

    type Info: record {
        start_time: string &log;
        epoch: interval &log;
        top_resp_hosts: set[string]    &log;
    };

    global top_resp_session: set[string];
    global log_top_resp_hosts: event(rec: Info);
    
}

event bro_init()
    {
    local rec: TopRespHosts::Info;
    Log::create_stream(TopRespHosts::LOG, [$columns=Info, $ev=log_top_resp_hosts]);

    local r1 = SumStats::Reducer($stream="top.resph", $apply=set(SumStats::TOPK), $topk_size=top_k_size);
    SumStats::create([$name="top_top.resph",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["top.resph"];
                        
                        local s: vector of SumStats::Observation;
                        s = topk_get_top(r$topk, top_k_size);
         
                        for ( i in s )
                            {
                                add top_resp_session[s[i]$str];
                                
                            }
                            
                                
                        },
                        $epoch_finished(ts: time) =
                        {
                            rec = [$start_time=strftime("%c", (ts - epoch)), $epoch=epoch, $top_resp_hosts=top_resp_session];
                            top_resp_session = set();
                            Log::write(TopRespHosts::LOG, rec);
                       
                        }]);
    }

event connection_state_remove(c: connection)
    {
        SumStats::observe("top.resph", [], [$str=fmt("%s", c$id$resp_h)]);
    }

