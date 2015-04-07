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

module FileHash;

global watched_mime_types: set [string] = ["application/x-dosexec" ] &redef;

event file_new(f: fa_file) {

    if ( ! f?$mime_type || f?$mime_type && f$mime_type !in watched_mime_types )
        return;
        
    Files::add_analyzer(f, Files::ANALYZER_MD5);
    Files::add_analyzer(f, Files::ANALYZER_SHA1); 
 
 }
