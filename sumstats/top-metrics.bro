##! Find top metrics 

# Contributed by Reservoir Labs, Inc.

##!
##! top-metrics.bro is a script that tracks various top metrics in real-time. 
##! The current set of supported top metrics are:
##!
##!   - Top talkers: connections that carry the largest amount of data
##!   - Top URLs: URLs that are hit the most
##!

@load base/frameworks/sumstats
@load base/protocols/http

module TopMetrics;

export {
    
    ## The duration of the epoch, which defines the time between two consecutive reports
    const epoch_duration: interval = 10 sec &redef;
    ## The size of the top set to track
    const top_size: count = 20 &redef;

    # Logging info
    redef enum Log::ID += { URLS };
    redef enum Log::ID += { TALKERS };

    type Info: record {
        epoch_time: time &log;            ##< Time at the end of the epoch 
        top_list: vector of string &log;    ##< Ordered list of top URLs 
        top_counts: vector of string &log;  ##< Counters for each URL
    };

    # Logging event for tracking the top URLs 
    global log_top_urls: event(rec: Info);
    # Logging event for tracking the top talkers 
    global log_top_talkers: event(rec: Info);

}

event bro_init()
    {
    local rec: TopMetrics::Info;
    Log::create_stream(TopMetrics::URLS, [$columns=Info, $ev=log_top_urls]);
    Log::create_stream(TopMetrics::TALKERS, [$columns=Info, $ev=log_top_talkers]);

    # Define the reducers
    local r1 = SumStats::Reducer($stream="top.urls", $apply=set(SumStats::TOPK), $topk_size=top_size);
    local r2 = SumStats::Reducer($stream="top.talkers", $apply=set(SumStats::TOPK), $topk_size=top_size);

    # Define the SumStats
    SumStats::create([$name="tracking top URLs",
                      $epoch=epoch_duration,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                          {
                          local r = result["top.urls"];
                          local s: vector of SumStats::Observation;
                          local top_list = string_vec();
                          local top_counts = index_vec();
                          local i = 0;
                          s = topk_get_top(r$topk, top_size);
                          for ( element in s ) 
                              {
                              top_list[|top_list|] = s[element]$str;
                              top_counts[|top_counts|] = topk_count(r$topk, s[element]);
                              if ( ++i == top_size )
                                  break;
                              }

                          Log::write(TopMetrics::URLS, [$epoch_time=ts, 
                                                        $top_list=top_list, 
                                                        $top_counts=top_counts]);
                          }]);
    SumStats::create([$name="tracking top talkers",
                      $epoch=epoch_duration,
                      $reducers=set(r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                          {
                          local r = result["top.talkers"];
                          local s: vector of SumStats::Observation;
                          local top_list = string_vec();
                          local top_counts = index_vec();
                          local i = 0;
                          s = topk_get_top(r$topk, top_size);
                          for ( element in s ) 
                              {
                              top_list[|top_list|] = fmt("%s", s[element]$num);
                              top_counts[|top_counts|] = topk_count(r$topk, s[element]);
                              if ( ++i == top_size )
                                  break;
                              }

                          Log::write(TopMetrics::TALKERS, [$epoch_time=ts, 
                                                           $top_list=top_list, 
                                                           $top_counts=top_counts]);
                          }]);

    }

event DNS::log_dns(rec: DNS::Info)
    {
        # Define an observation
        if ( rec?$query )
            SumStats::observe("top.urls", [], [$str=fmt("%s", rec$query)]);
    }

event connection_state_remove(c: connection)
    {
        # Define an observation
        SumStats::observe("top.talkers", [], [$num=c$conn$orig_ip_bytes+c$conn$resp_ip_bytes]);
    } 

