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

file path=usr/share/man/man3c_db/td_init.3c_db
file path=usr/share/man/man3c_db/td_log.3c_db
file path=usr/share/man/man3c_db/td_sync_get_info.3c_db
file path=usr/share/man/man3c_db/td_ta_enable_stats.3c_db
file path=usr/share/man/man3c_db/td_ta_event_addr.3c_db
file path=usr/share/man/man3c_db/td_ta_get_nthreads.3c_db
file path=usr/share/man/man3c_db/td_ta_map_addr2sync.3c_db
file path=usr/share/man/man3c_db/td_ta_map_id2thr.3c_db
file path=usr/share/man/man3c_db/td_ta_new.3c_db
file path=usr/share/man/man3c_db/td_ta_setconcurrency.3c_db
file path=usr/share/man/man3c_db/td_ta_sync_iter.3c_db
file path=usr/share/man/man3c_db/td_thr_dbsuspend.3c_db
file path=usr/share/man/man3c_db/td_thr_get_info.3c_db
file path=usr/share/man/man3c_db/td_thr_getgregs.3c_db
file path=usr/share/man/man3c_db/td_thr_lockowner.3c_db
file path=usr/share/man/man3c_db/td_thr_setprio.3c_db
file path=usr/share/man/man3c_db/td_thr_setsigpending.3c_db
file path=usr/share/man/man3c_db/td_thr_sleepinfo.3c_db
file path=usr/share/man/man3c_db/td_thr_tsd.3c_db
file path=usr/share/man/man3c_db/td_thr_validate.3c_db
link path=usr/share/man/man3c_db/td_event_addset.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_event_delset.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_event_emptyset.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_event_fillset.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_eventisempty.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_eventismember.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_sync_get_stats.3c_db \
    target=td_sync_get_info.3c_db
link path=usr/share/man/man3c_db/td_sync_setstate.3c_db \
    target=td_sync_get_info.3c_db
link path=usr/share/man/man3c_db/td_sync_waiters.3c_db \
    target=td_sync_get_info.3c_db
link path=usr/share/man/man3c_db/td_ta_clear_event.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_ta_delete.3c_db target=td_ta_new.3c_db
link path=usr/share/man/man3c_db/td_ta_event_getmsg.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_ta_get_ph.3c_db target=td_ta_new.3c_db
link path=usr/share/man/man3c_db/td_ta_get_stats.3c_db \
    target=td_ta_enable_stats.3c_db
link path=usr/share/man/man3c_db/td_ta_map_lwp2thr.3c_db \
    target=td_ta_map_id2thr.3c_db
link path=usr/share/man/man3c_db/td_ta_reset_stats.3c_db \
    target=td_ta_enable_stats.3c_db
link path=usr/share/man/man3c_db/td_ta_set_event.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_ta_sync_tracking_enable.3c_db \
    target=td_sync_get_info.3c_db
link path=usr/share/man/man3c_db/td_ta_thr_iter.3c_db \
    target=td_ta_sync_iter.3c_db
link path=usr/share/man/man3c_db/td_ta_tsd_iter.3c_db \
    target=td_ta_sync_iter.3c_db
link path=usr/share/man/man3c_db/td_thr_clear_event.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_thr_dbresume.3c_db \
    target=td_thr_dbsuspend.3c_db
link path=usr/share/man/man3c_db/td_thr_event_enable.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_thr_event_getmsg.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_thr_getfpregs.3c_db \
    target=td_thr_getgregs.3c_db
link path=usr/share/man/man3c_db/td_thr_getxregs.3c_db \
    target=td_thr_getgregs.3c_db
link path=usr/share/man/man3c_db/td_thr_getxregsize.3c_db \
    target=td_thr_getgregs.3c_db
link path=usr/share/man/man3c_db/td_thr_set_event.3c_db \
    target=td_ta_event_addr.3c_db
link path=usr/share/man/man3c_db/td_thr_setfpregs.3c_db \
    target=td_thr_getgregs.3c_db
link path=usr/share/man/man3c_db/td_thr_setgregs.3c_db \
    target=td_thr_getgregs.3c_db
link path=usr/share/man/man3c_db/td_thr_setxregs.3c_db \
    target=td_thr_getgregs.3c_db
link path=usr/share/man/man3c_db/td_thr_sigsetmask.3c_db \
    target=td_thr_setsigpending.3c_db
