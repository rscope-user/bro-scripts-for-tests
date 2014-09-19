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

module TopByteCount;

export {
    
    global epoch: interval = 1min &redef;
    global top_k_size: count = 50 &redef;

    # Logging info
    redef enum Log::ID += { LOG };

    type Info: record {
        start_time: string &log;
        epoch: interval &log;
        role: string &log;
        host: addr     &log;
        reverse_dns: string &log &default="";
        cnt: count &log;
    };

    global log_conn_count: event(rec: Info);
    
}

event bro_init()
    {
    local rec: TopByteCount::Info;
    Log::create_stream(TopByteCount::LOG, [$columns=Info, $ev=log_conn_count]);

    local r1 = SumStats::Reducer($stream="src.byte.per.epoch", $apply=set(SumStats::TOPK), $topk_size=top_k_size);
    SumStats::create([$name="top_src.byte.per.epoch",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["src.byte.per.epoch"];
                        local s: vector of SumStats::Observation;
                        s = topk_get_top(r$topk, 10);
                        for ( i in s )
                            {

                                when ( local host = lookup_addr(key$host) ) { 
                                    rec = [$start_time= strftime("%c", r$begin), $epoch=epoch, $role=key$str, $host=key$host, 
                                           $reverse_dns=host, $cnt=topk_count(r$topk, s[i])];
    
                                    Log::write(TopByteCount::LOG, rec);
                                }
                                
                            }
                        }]);
    }

event connection_state_remove(c: connection)
    {
        SumStats::observe("src.byte.per.epoch", [$host=c$id$orig_h, $str="orig"], [$num=c$orig$size]);
        SumStats::observe("src.byte.per.epoch", [$host=c$id$resp_h, $str="resp"], [$num=c$resp$size]);
    }


