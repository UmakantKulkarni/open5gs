# Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

libpcs_sources = files('''
    pcs-thread-pool.h
    parson.h

    pcs-thread-pool.c
    parson.c
'''.split())

libpcs_inc = include_directories('.')

libpcs = library('pcsapp',
    sources : libpcs_sources,
    version : libogslib_version,
    include_directories : [libpcs_inc, libinc],
    install : true)

libpcs_dep = declare_dependency(
    link_with : libpcs,
    include_directories : [libpcs_inc, libinc]
)
