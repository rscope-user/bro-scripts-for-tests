# Written by Bob Rotsted
# Copyright Reservoir Labs, 2015.
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

module AvgByteCount;

export {
    
    global epoch: interval = 1min &redef;
    redef enum Log::ID += { LOG };

    type Info: record {
        start_time: string &log;
        role: string &log;
        epoch: interval &log;
        avg_bytes: double &log;
        std_dev_bytes: double &log;
    };

    global log_avg_bytes_per_flow: event(rec: Info);
    
}

event bro_init()
    {
    local rec: AvgByteCount::Info;
    Log::create_stream(AvgByteCount::LOG, [$columns=Info, $ev=log_avg_bytes_per_flow]);

    local r1 = SumStats::Reducer($stream="avg.byte.per.epoch", $apply=set(SumStats::AVERAGE, SumStats::STD_DEV));
    SumStats::create([$name="top_avg.byte.per.epoch",
                      $epoch=epoch,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local r = result["avg.byte.per.epoch"];
                        rec = [$start_time= strftime("%c", r$begin), $epoch=epoch, $role=key$str, $avg_bytes=r$average, $std_dev_bytes=r$std_dev];
                        Log::write(AvgByteCount::LOG, rec);
                        }
                        ]);
    }

event connection_state_remove(c: connection)
    {
        SumStats::observe("avg.byte.per.epoch", [$str="orig"], [$num=c$orig$size]);
        SumStats::observe("avg.byte.per.epoch", [$str="resp"], [$num=c$resp$size]);
        SumStats::observe("avg.byte.per.epoch", [$str="aggregate"], [$num=c$resp$size + c$orig$size]);

    }

