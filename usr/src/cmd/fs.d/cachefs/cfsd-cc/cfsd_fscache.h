/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
// ------------------------------------------------------------
//
//			fscache.h
//
// Include file for the fscache class.
//

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994 by Sun Microsystems, Inc.

#ifndef CFSD_FSCACHE
#define	CFSD_FSCACHE

class cfsd_fscache {
private:
	RWCString	i_name;			// fscache name
	RWCString	i_cachepath;		// cache pathname
	int		i_fscacheid;		// fscache identifier

	RWCString	i_mntpt;		// mount point
	RWCString	i_backfs;		// back file system
	RWCString	i_backpath;		// back file system path
	RWCString	i_backfstype;		// back file system type
	RWCString	i_cfsopt;		// cachefs mount options
	RWCString	i_bfsopt;		// backfs mount options

	mutex_t		i_lock;			// synchronizing lock
	int		i_refcnt;		// refs to object
	volatile int	i_disconnectable:1;	// 1 if okay to disconnect
	volatile int	i_mounted:1;		// 1 if fs is mounted
	volatile int	i_threaded:1;		// 1 if thread running
	volatile int	i_connected:1;		// 1 if connected
	volatile int	i_reconcile:1;		// 1 if reconciling
	volatile int	i_changes:1;		// 1 if changes to push back
	volatile int	i_simdis:1;		// 1 means simulate disconnect
	volatile int	i_tryunmount:1;		// 1 if should try unmount
	volatile int	i_backunmount:1;	// 1 if need to unmount backfs
	time_t		i_time_state;		// time of last dis/connect
	time_t		i_time_mnt;		// time of last u/mount
	int		i_modify;		// changed when modified

	int		i_ofd;			// message file descriptor

	thread_t	i_threadid;		// id of thread, if running
	cond_t		i_cvwait;		// cond var to wait on

	off_t		i_again_offset;		// offset to head modify op
	int		i_again_seq;		// seq number of head modify op

	void i_server_alive(cfsd_kmod *kmodp);
	int i_roll(cfsd_kmod *kmodp);
	int i_rollone(cfsd_kmod *kmodp, cfsd_maptbl *tblp, cfsd_logfile *lfp,
	    u_long seq);
	int i_addagain(cfsd_kmod *kmodp, cfsd_logfile *lfp, u_long seq);
	void i_fsproblem(cfsd_kmod *kmodp);
	int i_pingserver();

public:
	cfsd_fscache(const char *name, const char *cachepath, int fscacheid);
	~cfsd_fscache();

	void fscache_lock();
	void fscache_unlock();

	void fscache_refinc() { i_refcnt++; }
	void fscache_refdec() { i_refcnt--; }
	int fscache_refcnt() { return i_refcnt; }

	void fscache_setup();
	const char *fscache_name() { return i_name.data(); }
	int fscache_fscacheid() { return i_fscacheid; }
	const char *fscache_backfs() { return i_backfs.data(); }
	const char *fscache_mntpt() { return i_mntpt.data(); }
	const char *fscache_backfstype() { return i_backfstype.data(); }
	const char *fscache_cfsopt() { return i_cfsopt.data(); }
	int fscache_connected() { return i_connected; }
	int fscache_reconcile() { return i_reconcile; }
	int fscache_changes() { return i_changes; }
	void fscache_changes(int tt);
	time_t fscache_time_state() { return i_time_state; }
	time_t fscache_time_mnt() { return i_time_mnt; }
	void fscache_time_mnt(time_t tt) { i_time_mnt = tt; }
	int fscache_modify() { return i_modify; }

	void fscache_threaded(int yesno) { i_threaded = yesno; }
	int fscache_threaded() { return i_threaded; }

	void fscache_threadid(thread_t id) { i_threadid = id; }
	int fscache_threadid() { return i_threadid; }

	void fscache_mounted(int yesno) { i_mounted = yesno; }
	int fscache_mounted() { return i_mounted; }

	void fscache_disconnectable(int yesno) { i_disconnectable = yesno; }
	int fscache_disconnectable() { return i_disconnectable; }

	int fscache_simdisconnect(int disconnect);
	int fscache_unmount();

	void fscache_process();

	int operator==(const cfsd_fscache &fscache) const;
};

#endif /* CFSD_FSCACHE */
