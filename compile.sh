#! /bin/bash
#
# Copyright © 2019 Zoff <zoff@zoff.cc>
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
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

echo $_HOME_/
cd $_HOME_/

gcc -O3 -Wall -Wextra \
scan_bar_codes.c \
-fsanitize=address -fno-omit-frame-pointer \
-lasan \
-o scan_bar_codes || exit 1

echo "build OK"
