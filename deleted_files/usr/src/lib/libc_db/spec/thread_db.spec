#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#

function	td_init
include		<thread_db.h>
declaration	td_err_e td_init(void)
version		SUNW_0.9
end

function	td_log
include		<thread_db.h>
declaration	void td_log(void)
version		SUNW_0.9
end

function	td_sync_get_info
include		<thread_db.h>
declaration	td_err_e td_sync_get_info(const td_synchandle_t *sh_p, \
			td_syncinfo_t *si_p)
version		SUNW_1.1
end

function	td_sync_get_stats
version		SUNWprivate_1.1
end

function	td_sync_setstate
include		<thread_db.h>
declaration	td_err_e td_sync_setstate(const td_synchandle_t *sh_p, \
			int value)
version		SUNW_1.1
end

function	td_sync_waiters
include		<thread_db.h>
declaration	td_err_e td_sync_waiters(const td_synchandle_t *sh_p, \
			td_thr_iter_f *cb, void *cb_data_p)
version		SUNW_1.1
end

function	td_thr_clear_event
include		<thread_db.h>
declaration	td_err_e td_thr_clear_event(const td_thrhandle_t *th_p, \
			td_thr_events_t *events)
version		SUNW_1.1
end

function	td_ta_delete
include		<thread_db.h>
declaration	td_err_e td_ta_delete(td_thragent_t *ta_p)
version		SUNW_0.9
end

function	td_ta_enable_stats
include		<thread_db.h>
declaration	td_err_e td_ta_enable_stats(const td_thragent_t *ta_p, \
			int on_off)
version		SUNW_1.1
end

function	td_ta_event_addr
include		<thread_db.h>
declaration	td_err_e td_ta_event_addr(const td_thragent_t *ta_p, \
			td_event_e event, td_notify_t *notify_p)
version		SUNW_1.1
end

function	td_ta_event_getmsg
include		<thread_db.h>
declaration	td_err_e td_ta_event_getmsg(const td_thragent_t *ta_p, \
			td_event_msg_t *msg)
version		SUNW_1.1
end

function	td_ta_get_nthreads
include		<thread_db.h>
declaration	td_err_e td_ta_get_nthreads(const  td_thragent_t *ta_p, \
			int *nthread_p)
version		SUNW_0.9
end

function	td_ta_get_ph
include		<thread_db.h>
declaration	td_err_e td_ta_get_ph(const td_thragent_t *ta_p, \
			struct ps_prochandle **ph_pp)
version		SUNW_0.9
end

function	td_ta_get_stats
include		<thread_db.h>
declaration	td_err_e td_ta_get_stats(const td_thragent_t *ta_p, \
			td_ta_stats_t *tstats)
version		SUNW_1.1
end

function	td_ta_map_addr2sync
include		<thread_db.h>
declaration	td_err_e td_ta_map_addr2sync(const td_thragent_t *ta_p, \
			psaddr_t addr, td_synchandle_t *sh_p)
version		SUNW_1.1
end

function	td_ta_map_id2thr
include		<thread_db.h>
declaration	td_err_e td_ta_map_id2thr(const td_thragent_t *ta_p, \
			thread_t tid, td_thrhandle_t *th_p)
version		SUNW_0.9
end

function	td_ta_map_lwp2thr
include		<thread_db.h>
declaration	td_err_e td_ta_map_lwp2thr(const td_thragent_t *ta_p, \
			lwpid_t lwpid, td_thrhandle_t *th_p)
version		SUNW_0.9
end

function	td_ta_new
include		<thread_db.h>
declaration	td_err_e td_ta_new(struct ps_prochandle *ph_p, \
			td_thragent_t **ta_pp)
version		SUNW_0.9
end

function	td_ta_reset_stats
include		<thread_db.h>
declaration	td_err_e td_ta_reset_stats(const td_thragent_t *ta_p)
version		SUNW_1.1
end

function	td_ta_set_event
include		<thread_db.h>
declaration	td_err_e td_ta_set_event(const td_thragent_t *th_p, \
			td_thr_events_t *events)
version		SUNW_1.1
end

function	td_ta_setconcurrency
include		<thread_db.h>
declaration	td_err_e td_ta_setconcurrency(const td_thragent_t *ta_p, \
			int level)
version		SUNW_1.1
end

function	td_ta_sync_tracking_enable
version		SUNWprivate_1.1
end

function	td_ta_sync_iter
include		<thread_db.h>
declaration	td_err_e td_ta_sync_iter(const td_thragent_t *ta_p, \
			td_sync_iter_f *cb, void *cbdata_p)
version		SUNW_1.1
end

function	td_ta_thr_iter
include		<thread_db.h>
declaration	td_err_e td_ta_thr_iter(const td_thragent_t *ta_p, \
			td_thr_iter_f *cb, void *cbdata_p, \
			td_thr_state_e, int, sigset_t *, unsigned)
version		SUNW_0.9
end

function	td_ta_tsd_iter
include		<thread_db.h>
declaration	td_err_e td_ta_tsd_iter(const td_thragent_t *ta_p, \
			td_key_iter_f *cb,  void *cbdata_p)
version		SUNW_0.9
end

function	td_ta_clear_event
include		<thread_db.h>
declaration	td_err_e td_ta_clear_event(const td_thragent_t *ta_p, \
			td_thr_events_t *events)
version		SUNW_1.1
end

function	td_thr_dbresume
include		<thread_db.h>
declaration	td_err_e td_thr_dbresume(const td_thrhandle_t *th_p)
version		SUNW_1.1
end

function	td_thr_dbsuspend
include		<thread_db.h>
declaration	td_err_e td_thr_dbsuspend(const td_thrhandle_t *th_p)
version		SUNW_1.1
end

function	td_thr_event_enable
include		<thread_db.h>
declaration	td_err_e td_thr_event_enable(const td_thrhandle_t *th_p, \
			int onoff)
version		SUNW_1.1
end

function	td_thr_event_getmsg
include		<thread_db.h>
declaration	td_err_e td_thr_event_getmsg(const td_thrhandle_t *th_p, \
			td_event_msg_t *msg)
version		SUNW_1.1
end

function	td_thr_get_info
include		<thread_db.h>
declaration	td_err_e td_thr_get_info(const td_thrhandle_t *th_p, \
			td_thrinfo_t *ti_p)
version		SUNW_0.9
end

function	td_thr_getfpregs
include		<thread_db.h>
declaration	td_err_e td_thr_getfpregs(const td_thrhandle_t *th_p, \
			prfpregset_t *fpregset)
version		SUNW_0.9
end

function	td_thr_getgregs
include		<thread_db.h>
declaration	td_err_e td_thr_getgregs(const td_thrhandle_t *th_p, \
			prgregset_t regset)
version		SUNW_0.9
end

function	td_thr_getxregs
include		<thread_db.h>
declaration	td_err_e td_thr_getxregs(const td_thrhandle_t *th_p, \
			void *xregset)
version		SUNW_0.9
end

function	td_thr_getxregsize
include		<thread_db.h>
declaration	td_err_e td_thr_getxregsize( const td_thrhandle_t *th_p, \
			int *xregsize)
version		SUNW_0.9
end

function	td_thr_lockowner
include		<thread_db.h>
declaration	td_err_e td_thr_lockowner(const td_thrhandle_t *th_p, \
			td_sync_iter_f *cb, void *cb_data_p)
version		SUNW_1.1
end

function	td_thr_set_event
include		<thread_db.h>
declaration	td_err_e td_thr_set_event(const td_thrhandle_t *th_p, \
			td_thr_events_t *events)
version		SUNW_1.1
end

function	td_thr_setfpregs
include		<thread_db.h>
declaration	td_err_e td_thr_setfpregs(const td_thrhandle_t *th_p, \
			const prfpregset_t *fpregset)
version		SUNW_0.9
end

function	td_thr_setgregs
include		<thread_db.h>
declaration	td_err_e td_thr_setgregs(const td_thrhandle_t *th_p, \
			const prgregset_t regset)
version		SUNW_0.9
end

function	td_thr_setprio
include		<thread_db.h>
declaration	td_err_e td_thr_setprio(const td_thrhandle_t *th_p, \
			int new_prio)
version		SUNW_0.9
end

function	td_thr_setsigpending
include		<thread_db.h>
declaration	td_err_e td_thr_setsigpending(const td_thrhandle_t *th_p, \
			uchar_t ti_pending_flag, \
			const sigset_t ti_pending)
version		SUNW_0.9
end

function	td_thr_setxregs
include		<thread_db.h>
declaration	td_err_e td_thr_setxregs(const td_thrhandle_t *th_p, \
			const void *xregset)
version		SUNW_0.9
end

function	td_thr_sigsetmask
include		<thread_db.h>
declaration	td_err_e td_thr_sigsetmask(const td_thrhandle_t *th_p, \
			const sigset_t ti_sigmask)
version		SUNW_0.9
end

function	td_thr_sleepinfo
include		<thread_db.h>
declaration	td_err_e td_thr_sleepinfo(const td_thrhandle_t *th_p, \
			td_synchandle_t *sh_p)
version		SUNW_1.1
end

function	td_thr_tsd
include		<thread_db.h>
declaration	td_err_e td_thr_tsd(const td_thrhandle_t *th_p, \
			thread_key_t key, void **data_pp)
version		SUNW_0.9
end

function	td_thr_tlsbase
include		<thread_db.h>
declaration	td_err_e td_thr_tlsbase(const td_thrhandle_t *th_p, \
			ulong_t moduleid, psaddr_t *base)
version		SUNW_1.3
end

function	td_thr_validate
include		<thread_db.h>
declaration	td_err_e td_thr_validate(const td_thrhandle_t *th_p)
version		SUNW_0.9
end

#
# Weak interfaces

function	__td_ta_new
weak		td_ta_new
version		SUNWprivate_1.1
end

function	__td_ta_delete
weak		td_ta_delete
version		SUNWprivate_1.1
end

function	__td_init
weak		td_init
version		SUNWprivate_1.1
end

function	__td_log
weak		td_log
version		SUNWprivate_1.1
end

function	__td_ta_get_ph
weak		td_ta_get_ph
version		SUNWprivate_1.1
end

function	__td_ta_setconcurrency
weak		td_ta_setconcurrency
version		SUNWprivate_1.1
end

function	__td_ta_sync_tracking_enable
weak		td_ta_sync_tracking_enable
version		SUNWprivate_1.1
end

function	__td_ta_sync_iter
weak		td_ta_sync_iter
version		SUNWprivate_1.1
end

function	__td_ta_enable_stats
weak		td_ta_enable_stats
version		SUNWprivate_1.1
end

function	__td_ta_event_addr
weak		td_ta_event_addr
version		SUNWprivate_1.1
end

function	__td_ta_event_getmsg
weak		td_ta_event_getmsg
version		SUNWprivate_1.1
end

function	__td_thr_event_enable
weak		td_thr_event_enable
version		SUNWprivate_1.1
end

function	__td_thr_set_event
weak		td_thr_set_event
version		SUNWprivate_1.1
end

function	__td_ta_reset_stats
weak		td_ta_reset_stats
version		SUNWprivate_1.1
end

function	__td_ta_set_event
weak		td_ta_set_event
version		SUNWprivate_1.1
end

function	__td_thr_clear_event
weak		td_thr_clear_event
version		SUNWprivate_1.1
end

function	__td_ta_clear_event
weak		td_ta_clear_event
version		SUNWprivate_1.1
end

function	__td_thr_event_getmsg
weak		td_thr_event_getmsg
version		SUNWprivate_1.1
end

function	__td_ta_get_stats
weak		td_ta_get_stats
version		SUNWprivate_1.1
end

function	__td_ta_get_nthreads
weak		td_ta_get_nthreads
version		SUNWprivate_1.1
end

function	__td_ta_tsd_iter
weak		td_ta_tsd_iter
version		SUNWprivate_1.1
end

function	__td_ta_thr_iter
weak		td_ta_thr_iter
version		SUNWprivate_1.1
end

function	__td_thr_validate
weak		td_thr_validate
version		SUNWprivate_1.1
end

function	__td_thr_tsd
weak		td_thr_tsd
version		SUNWprivate_1.1
end

function	__td_thr_tlsbase
weak		td_thr_tlsbase
version		SUNWprivate_1.1
end

function	__td_thr_get_info
weak		td_thr_get_info
version		SUNWprivate_1.1
end

function	__td_thr_sigsetmask
weak		td_thr_sigsetmask
version		SUNWprivate_1.1
end

function	__td_thr_setprio
weak		td_thr_setprio
version		SUNWprivate_1.1
end

function	__td_thr_setsigpending
weak		td_thr_setsigpending
version		SUNWprivate_1.1
end

function	__td_ta_map_addr2sync
weak		td_ta_map_addr2sync
version		SUNWprivate_1.1
end

function	__td_ta_map_id2thr
weak		td_ta_map_id2thr
version		SUNWprivate_1.1
end

function	__td_thr_lockowner
weak		td_thr_lockowner
version		SUNWprivate_1.1
end

function	__td_thr_sleepinfo
weak		td_thr_sleepinfo
version		SUNWprivate_1.1
end

function	__td_thr_dbsuspend
weak		td_thr_dbsuspend
version		SUNWprivate_1.1
end

function	__td_thr_dbresume
weak		td_thr_dbresume
version		SUNWprivate_1.1
end

function	__td_thr_getfpregs
weak		td_thr_getfpregs
version		SUNWprivate_1.1
end

function	__td_thr_setfpregs
weak		td_thr_setfpregs
version		SUNWprivate_1.1
end

function	__td_thr_setgregs
weak		td_thr_setgregs
version		SUNWprivate_1.1
end

function	__td_thr_getxregsize
weak		td_thr_getxregsize
version		SUNWprivate_1.1
end

function	__td_thr_setxregs
weak		td_thr_setxregs
version		SUNWprivate_1.1
end

function	__td_thr_getxregs
weak		td_thr_getxregs
version		SUNWprivate_1.1
end

function	__td_ta_map_lwp2thr
weak		td_ta_map_lwp2thr
version		SUNWprivate_1.1
end

function	__td_sync_get_info
weak		td_sync_get_info
version		SUNWprivate_1.1
end

function	__td_sync_get_stats
weak		td_sync_get_stats
version		SUNWprivate_1.1
end

function	__td_sync_setstate
weak		td_sync_setstate
version		SUNWprivate_1.1
end

function	__td_sync_waiters
weak		td_sync_waiters
version		SUNWprivate_1.1
end

function	__td_thr_getgregs
weak		td_thr_getgregs
version		SUNWprivate_1.1
end
