##! Benchmark HTTP 

# Contributed by Reservoir Labs, Inc.
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

redef dpd_reassemble_first_packets = F;
redef frag_timeout = 10000 sec;
redef skip_http_data = T;

redef tcp_inactivity_timeout = 5 sec;

module HttpTrack;

export {
        redef enum Log::ID += { LOG };

        type Info: record {
                timestamp: time              &log;        
                worker: string               &log;
                id: count                    &log;
                pkts_input: count            &log;
                pkts_shunted: count          &log;
                pkts_dropped: count          &log;
                pkts_pushed: count           &log;
                ted_threshold: count         &log;
                sel_cap: double              &log;
                av_sel_cap: double           &log;
                method: string               &log;
                uri: string                  &log;
                resp_code: count             &log;
                resp_msg: string             &log;
        };

        global log_http_track: event(rec: Info);
}

global http_track_numconns: count;
global http_track_numconns_last: count;
global http_track_time_last: time;
global http_track_time_first: time;        

const REPORTING_PERIOD = 100;

event bro_init() &priority=5
        {
        Log::create_stream(HttpTrack::LOG, [$columns=Info, $ev=log_http_track]);
        http_track_numconns = 0;
        http_track_numconns_last = 0;
        http_track_time_last = network_time();
        http_track_time_first = 0;
        }

type http_session_info: record
        {
        method: string &default="";
        uri: string &default="";
        status_code: count &default=0;
        status_msg: string &default="";
        };

global conn_info: table[conn_id] of http_session_info
        &read_expire=5mins
        &redef;

event http_request(c: connection, method: string, original_URI: string,
                       unescaped_URI: string, version: string)
        {
        if ( c$id !in conn_info )
                {
                local x: http_session_info;
                conn_info[c$id] = x;
                }

        local sess_ext = conn_info[c$id];
        sess_ext$method = method;
        sess_ext$uri = unescaped_URI;

        }
        
        
event http_reply(c: connection, version: string, code: count, reason: string)
        {
        local this_timestamp: time;        
        local this_sel_cap: double;
        local this_av_sel_cap: double;
        local id = c$id;
        if ( id !in conn_info )
                return;

        # this connection is no longer relevant to the analysis
#        mcore_shunt_conn(addr_to_count(id$orig_h),
#                         port_to_count(id$orig_p),
#                         addr_to_count(id$resp_h),
#                         port_to_count(id$resp_p));

        http_track_numconns = http_track_numconns + 1;

        if((http_track_numconns % REPORTING_PERIOD) == 0)
                {

                local sess_ext = conn_info[id];
                sess_ext$status_code = code;
                sess_ext$status_msg = reason;
                this_sel_cap = (http_track_numconns - http_track_numconns_last) / (time_to_double(network_time())-time_to_double(http_track_time_last));
                if(http_track_time_first != 0)
                        this_av_sel_cap = http_track_numconns / (time_to_double(network_time())-time_to_double(http_track_time_first));

                local this_worker : string;
                if(Cluster::node != "")
                        this_worker = Cluster::node;
                else
                        this_worker = "[Standalone worker]";

                this_timestamp = network_time();
                local rec: HttpTrack::Info = [$timestamp=this_timestamp,
                                              $worker=this_worker,
                                              $method=sess_ext$method,
                                              $uri=sess_ext$uri,
                                              $resp_code=sess_ext$status_code,
                                              $resp_msg=sess_ext$status_msg,
                                              $id=http_track_numconns,
                                              $pkts_input=mcore_get_stats_input_pkts(),
                                              $pkts_shunted=mcore_get_stats_shunted_pkts(),
                                              $pkts_dropped=mcore_get_stats_dropped_pkts(),
                                              $pkts_pushed=mcore_get_stats_pushed_pkts(),
                                              $ted_threshold=mcore_get_ted_flow_threshold(), 
                                              $sel_cap=this_sel_cap,
                                              $av_sel_cap=this_av_sel_cap];

                Log::write(HttpTrack::LOG, rec);
                http_track_time_last = network_time();
                if(http_track_time_first == 0)
	                http_track_time_first = network_time();
                http_track_numconns_last = http_track_numconns;

                }
        }
        
