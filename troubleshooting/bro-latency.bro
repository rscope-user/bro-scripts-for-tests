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


event Latency::poll_time () {
    
    local latency = (current_time() - network_time());  
    local rec = [$network_time = network_time(), $seconds_latency = latency, $current_time = current_time()];
    
    Log::write(Latency::LOG, rec);
    schedule poll_interval { Latency::poll_time() };
}

event bro_init() {

    Log::create_stream(Latency::LOG, [$columns=Info, $ev=log_bro_latency]);
    schedule poll_interval { Latency::poll_time() };
}


