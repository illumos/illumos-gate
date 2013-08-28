#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2012 Nexenta Systems, Inc. All rights reserved.
#

file path=usr/share/man/man3kstat/kstat.3kstat
file path=usr/share/man/man3kstat/kstat_chain_update.3kstat
file path=usr/share/man/man3kstat/kstat_lookup.3kstat
file path=usr/share/man/man3kstat/kstat_open.3kstat
file path=usr/share/man/man3kstat/kstat_read.3kstat
link path=usr/share/man/man3kstat/kstat_close.3kstat target=kstat_open.3kstat
link path=usr/share/man/man3kstat/kstat_data_lookup.3kstat \
    target=kstat_lookup.3kstat
link path=usr/share/man/man3kstat/kstat_write.3kstat target=kstat_read.3kstat
