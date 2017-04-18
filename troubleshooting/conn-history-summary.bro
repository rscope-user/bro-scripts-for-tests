# Written by Bob Rotsted
# Copyright Reservoir Labs, 2014.
# 
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# TEST COMMENT

module HistorySummary;

export {
    
    global epoch: interval = 60min &redef;
    redef enum Log::ID += { LOG };

    type Info: record {
        start_time: time &log;
        end_time: time &log;
        history: string &log;
        cnt: double &log;
    };

    global log_history_summary: event(rec: Info);
 
}

event bro_init()
    {
    local rec: HistorySummary::Info;
    Log::create_stream(HistorySummary::LOG, [$columns=Info, $ev=log_history_summary]);

    local r1 = SumStats::Reducer($stream="history.summary", $apply=set(SumStats::SUM));
    SumStats::create([$name="top_history.summary",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["history.summary"];

                            rec = [$start_time=(ts - epoch), $end_time=ts, $history=key$str, $cnt=r$sum];
                            Log::write(HistorySummary::LOG, rec);

                        }
                        ]);
    }

event connection_state_remove (c: connection) {

    if ( ! c$conn?$history ) 
        return;
        
    SumStats::observe("history.summary", [$str=c$conn$history], [$num=1]);
}

