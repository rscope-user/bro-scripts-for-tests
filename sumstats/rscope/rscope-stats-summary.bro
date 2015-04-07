module ThroughputSummary;

export {
    
    global epoch: interval = 1min &redef;
    redef enum Log::ID += { LOG };

    type Info: record {
        start_time: time &log;
        end_time: time &log;
        percent_shunted: double &log;
        percent_dropped: double &log;
    };

    global shunted: double = 0.0;
    global drop: double = 0.0;
    global received: double = 0.0;

    global log_rscope_stats_summary: event(rec: Info);
    
}

event bro_init()
    {
    local rec: ThroughputSummary::Info;
    Log::create_stream(ThroughputSummary::LOG, [$columns=Info, $ev=log_rscope_stats_summary]);

    local r1 = SumStats::Reducer($stream="avg.throughput.per.epoch", $apply=set(SumStats::SUM));
    SumStats::create([$name="top_avg.throughput.per.epoch",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["avg.throughput.per.epoch"];

                        if ( key$str == "shunt" )
                            shunted = r$sum;

                        if ( key$str == "drop" )
                            drop = r$sum;

                        if ( key$str == "received" )
                            received = r$sum;

                        },
                      $epoch_finished(ts: time) =
                        {
                            if ( received > 0.0 ){
                                local percent_shunted = (shunted / received ) * 100;
                                local percent_dropped = (drop / received ) * 100;
                            }


                            rec = [$start_time=ts-epoch, $end_time=ts, $percent_shunted=percent_shunted, $percent_dropped=percent_dropped];
                            Log::write(ThroughputSummary::LOG, rec);
                        }
                        ]);
    }

event RscopeStats::log_rscope_stats_pckt (recPckt: RscopeStats::InfoPckt)
    {

        local received_local: count  = recPckt$pckts_received_mcore;
        local shunted_local: count  = recPckt$pckts_shunted_mcore;
        local dropped_local: count = to_count(recPckt$pckts_dropped);

            SumStats::observe("avg.throughput.per.epoch", [$str="shunt"], [$num=shunted_local]);
            SumStats::observe("avg.throughput.per.epoch", [$str="drop"], [$num=dropped_local]);
            SumStats::observe("avg.throughput.per.epoch", [$str="received"], [$num=received_local]);

        }


