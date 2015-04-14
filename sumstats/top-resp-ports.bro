module TopRespPorts;

export {
    
    global epoch: interval = 20min &redef;
    global top_k_size: count = 20 &redef;

    # Logging info
    redef enum Log::ID += { LOG };

    type Info: record {
        start_time: string &log;
        epoch: interval &log;
        top_ports: set[string]    &log;
    };

    global top_port: set[string];
    global log_top_ports: event(rec: Info);
    
}

event bro_init()
    {
    local rec: TopRespPorts::Info;
    Log::create_stream(TopRespPorts::LOG, [$columns=Info, $ev=log_top_ports]);

    local r1 = SumStats::Reducer($stream="top.dports", $apply=set(SumStats::TOPK), $topk_size=top_k_size);
    SumStats::create([$name="top_top.dports",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["top.dports"];
                        
                        local s: vector of SumStats::Observation;
                        s = topk_get_top(r$topk, top_k_size);
         
                        for ( i in s )
                            {
                                add top_port[s[i]$str];
                            }
                            
                                
                        },
                        $epoch_finished(ts: time) =
                        {
                            rec = [$start_time=strftime("%c", (ts - epoch)), $epoch=epoch, $top_ports=top_port];
                            top_port = set();
                            Log::write(TopRespPorts::LOG, rec);
                       
                        }]);
    }

event connection_state_remove(c: connection)
    {
        SumStats::observe("top.dports", [], [$str=fmt("%s",c$id$resp_p)]);
    }


