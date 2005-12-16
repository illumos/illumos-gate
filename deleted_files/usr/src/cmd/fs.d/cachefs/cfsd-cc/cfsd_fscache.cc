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
// -----------------------------------------------------------------
//
//			fscache.cc
//
// Methods of the cfsd_fscache class.

#pragma ident	"%Z%%M%	%I%	%E% SMI"
// Copyright (c) 1994-2001 by Sun Microsystems, Inc.
// All rights reserved.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <limits.h>
#include <fcntl.h>
#include <nfs/nfs.h>
#include <sys/utsname.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <rw/cstring.h>
#include <rw/regexp.h>
#include <rw/rstream.h>
#include <rw/tpdlist.h>
#include <rpc/rpc.h>
#include <mdbug-cc/mdbug.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_dlog.h>
#include <sys/fs/cachefs_ioctl.h>
#include "cfsd_kmod.h"
#include "cfsd_maptbl.h"
#include "cfsd_logfile.h"
#include "cfsd_logelem.h"
#include "cfsd_fscache.h"

// forward reference
void mysleep(int sec);

// -----------------------------------------------------------------
//
//			cfsd_fscache::cfsd_fscache
//
// Description:
// Arguments:
//	name
//	cachepath
// Returns:
// Preconditions:
//	precond(name)
//	precond(cachepath)


cfsd_fscache::cfsd_fscache(const char *name, const char *cachepath,
    int fscacheid)
{
	dbug_enter("cfsd_fscache::cfsd_fscache");

	dbug_precond(name);
	dbug_precond(cachepath);

	i_name = name;
	i_cachepath = cachepath;
	i_fscacheid = fscacheid;
	i_refcnt = 0;
	i_disconnectable = 0;
	i_mounted = 0;
	i_threaded = 0;
	i_connected = 0;
	i_reconcile = 0;
	i_changes = 0;
	i_simdis = 0;
	i_tryunmount = 0;
	i_backunmount = 0;
	i_time_state = 0;
	i_time_mnt = 0;
	i_modify = 1;

	i_threadid = 0;
	i_ofd = -1;

	// initialize the locking mutex
	int xx = mutex_init(&i_lock, USYNC_THREAD, NULL);
	dbug_assert(xx == 0);

	xx = cond_init(&i_cvwait, USYNC_THREAD, 0);
	dbug_assert(xx == 0);
}

// -----------------------------------------------------------------
//
//			cfsd_fscache::~cfsd_fscache
//
// Description:
// Arguments:
// Returns:
// Preconditions:


cfsd_fscache::~cfsd_fscache()
{
	dbug_enter("cfsd_fscache::~cfsd_fscache");
	
	// close down the message file descriptor
	if (i_ofd >= 0) {
		close(i_ofd);
		i_ofd = -1;
	}

	// destroy the locking mutex
	int xx = mutex_destroy(&i_lock);
	dbug_assert(xx == 0);
}

// -----------------------------------------------------------------
//
//			cfsd_fscache::fscache_lock
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_fscache::fscache_lock()
{
	dbug_enter("cfsd_fscache::fscache_lock");

	mutex_lock(&i_lock);
}

// -----------------------------------------------------------------
//
//			cfsd_fscache::fscache_unlock
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_fscache::fscache_unlock()
{
	dbug_enter("cfsd_fscache::fscache_unlock");

	mutex_unlock(&i_lock);
}

// -----------------------------------------------------------------
//
//			cfsd_fscache::fscache_setup
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_fscache::fscache_setup()
{
	dbug_enter("cfsd_fscache::fscache_setup");

	i_modify++;
	i_disconnectable = 0;
	i_connected = 0;
	i_reconcile = 0;
	i_changes = 0;
	i_time_state = 0;
	i_time_mnt = 0;
	i_mntpt.resize(0);
	i_backfs.resize(0);
	i_backpath.resize(0);
	i_backfstype.resize(0);
	i_cfsopt.resize(0);
	i_bfsopt.resize(0);

	char buf[MAXPATHLEN*2];
	FILE *fin;
	time_t tval;

	tval = time(NULL);

	sprintf(buf, "%s/%s/%s", i_cachepath.data(), i_name.data(),
		CACHEFS_MNT_FILE);
	struct stat sinfo;

	// get the modify time of the mount file
	if (stat(buf, &sinfo) == -1) {
		dbug_print("err", ("could not stat %s, %d", buf, errno));
		return;
	}
	time_t mtime = sinfo.st_mtime;

	// open for reading the file with the mount information
	fin = fopen(buf, "r");
	if (fin == NULL) {
		dbug_print("err", ("could not open %s, %d", buf, errno));
		return;
	}

	// read the mount information from the file
	char type[50];
	int err = 0;
	int xx;
	while ((xx = fscanf(fin, "%s%s", type, buf)) == 2) {
		dbug_print("info", ("\"%s\" \"%s\"", type, buf));
		if (strcmp(type, "cachedir:") == 0) {
			if (i_cachepath.compareTo(buf) != 0) {
				err = 1;
				dbug_print("err", ("caches do not match %s, %s",
				    i_cachepath.data(), buf));
			}
		} else if (strcmp(type, "mnt_point:") == 0) {
			i_mntpt = buf;
		} else if (strcmp(type, "special:") == 0) {
			i_backfs = buf;
		} else if (strcmp(type, "backpath:") == 0) {
			i_backpath = buf;
		} else if (strcmp(type, "backfstype:") == 0) {
			i_backfstype = buf;
		} else if (strcmp(type, "cacheid:") == 0) {
			if (i_name.compareTo(buf) != 0) {
				err = 1;
				dbug_print("err", ("ids do not match %s, %s",
				    i_name.data(), buf));
			}
		} else if (strcmp(type, "cachefs_options:") == 0) {
			i_cfsopt = buf;
		} else if (strcmp(type, "backfs_options:") == 0) {
			i_bfsopt = buf;
		} else if (strcmp(type, "mount_time:") == 0) {
		} else {
			dbug_print("err", ("unknown keyword \"%s\"", type));
			err = 1;
		}
	}
	fclose(fin);

	// see if this is a file system that is disconnectable
	char *options[] = { "snr", "disconnectable", NULL };
	if ((err == 0) &&
	    !i_backfs.isNull() &&
	    !i_cfsopt.isNull()) {
		strcpy(buf, i_cfsopt.data());
		char *strp = buf;
		char *dummy;
		while (*strp != '\0') {
			xx = getsubopt(&strp, options, &dummy);
			if (xx != -1) {
				i_disconnectable = 1;
				break;
			}
		}
	}
	
	// open up a fd on the console so we have a place to write
	// log rolling errors
	if (i_disconnectable) {
		if (i_ofd < 0)
			i_ofd = open("/dev/console", O_WRONLY);
		if (i_ofd < 0) {
			fprintf(stderr,
			    "cachefsd: File system %s cannot"
			    " be disconnected.\n", i_mntpt.data());
			fprintf(stderr, "cachefsd: Cannot open /dev/console\n");
			i_disconnectable = 0;
		}
	}

	// see if the file system is mounted
	sprintf(buf, "%s/%s/%s", i_cachepath.data(), i_name.data(),
		CACHEFS_UNMNT_FILE);
	if (stat(buf, &sinfo) == 0) {
		i_mounted = 0;
		mtime = sinfo.st_mtime;
	} else
		i_mounted = 1;

	// save the time of the last mount or unmount
	i_time_mnt = mtime;

	dbug_print("info", ("disconnectable == %d, mounted == %d",
			    i_disconnectable, i_mounted));
}

// -----------------------------------------------------------------
//
//			cfsd_fscache::fscache_process
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_fscache::fscache_process()
{
	dbug_enter("cfsd_fscache::fscache_process");

	int xx;
	int changes;
	cfsd_kmod kmod;
	int setup = 1;

	int state;
	for (;;) {
		fscache_lock();
		i_time_state = time(NULL);
		i_modify++;

		// if we should try to unmount the file system
		if (i_tryunmount) {
			// shut down the interface to the kmod
			if (setup == 0) {
				kmod.kmod_shutdown();
				setup = 1;
			}

			// try to unmount the file system
			if (umount(i_mntpt.data()) == -1) {
				xx = errno;
				dbug_print("info", ("unmount failed %s",
						    strerror(xx)));
			} else {
				i_mounted = 0;
			}

			// wake up thread blocked in fscache_unmount
			i_tryunmount = 0;
			xx = cond_broadcast(&i_cvwait);
			dbug_assert(xx == 0);

			// all done if unmount succeeded
			if (i_mounted == 0) {
				fscache_unlock();
				break;
			}
		}

		if (setup) {
			setup = 0;
			// make an interface into the cachefs kmod for this fs
			xx = kmod.kmod_setup(i_mntpt.data());
			if (xx != 0) {
				dbug_print("err",
				    ("setup of kmod interface failed %d", xx));
				fscache_disconnectable(0);
				i_modify++;
				fscache_unlock();
				break;
			}

			// verify that we got the file system we expected
			// XXX
		}

		// get the current state of the file system
		state = kmod.kmod_stateget();

		if (i_simdis && (state == CFS_FS_CONNECTED)) {
			dbug_print("simdis", ("simulating disconnection on %s",
			    i_mntpt.data()));
			xx = kmod.kmod_stateset(CFS_FS_DISCONNECTED);
			dbug_assert(xx == 0);
			state = kmod.kmod_stateget();
			dbug_assert(state == CFS_FS_DISCONNECTED);
		}
		fscache_unlock();

		switch (state) {
		case CFS_FS_CONNECTED:
			fscache_lock();
			i_connected = 1;
			i_reconcile = 0;
			i_modify++;
			fscache_unlock();

			// wait for fs to switch to disconnecting
			xx = kmod.kmod_xwait();
			if (xx == EINTR) {
				dbug_print("info", ("a. EINTR from xwait"));
				continue;
			}
			dbug_assert(xx == 0);
			state = kmod.kmod_stateget();
			dbug_assert(state == CFS_FS_DISCONNECTED);
			break;

		case CFS_FS_DISCONNECTED:
			fscache_lock();
			i_connected = 0;
			i_reconcile = 0;
			i_modify++;
			fscache_unlock();

			// wait until we are reconnected
			i_server_alive(&kmod);
			if (i_tryunmount)
				continue;

			// switch to reconnecting mode
			xx = kmod.kmod_stateset(CFS_FS_RECONNECTING);
			dbug_assert(xx == 0);
			break;

		case CFS_FS_RECONNECTING:
			fscache_lock();
			i_connected = 1;
			i_reconcile = 1;
			i_modify++;
			changes = fscache_changes();
			fscache_unlock();

			// roll the log
			xx = i_roll(&kmod);
			if (xx) {
				dbug_assert(xx == ETIMEDOUT);
				// switch to disconnected
				xx = kmod.kmod_stateset(CFS_FS_DISCONNECTED);
				dbug_assert(xx == 0);
			} else {
				// switch to connected
				xx = kmod.kmod_stateset(CFS_FS_CONNECTED);
				dbug_assert(xx == 0);
				changes = 0;
			}

			fscache_lock();
			i_reconcile = 0;
			fscache_changes(changes);
			i_modify++;
			fscache_unlock();

			break;

		default:
			dbug_assert(0);
			break;
		}
	}
}

//
//			cfsd_fscache::fscache_simdisconnect
//
// Description:
//	Simulates disconnection or reconnects from a simulated disconnection.
// Arguments:
//	disconnect	1 means disconnect, !1 means connect
// Returns:
//	Returns 0 for success, !0 on an error
// Preconditions:

int
cfsd_fscache::fscache_simdisconnect(int disconnect)
{
	dbug_enter("cfsd_fscache::fscache_simdisconnect");

	int xx;
	int ret = 0;
	char *strp;

	strp = disconnect ? "disconnection" : "reconnection";

	dbug_print("simdis", ("About to simulate %s", strp));

	fscache_lock();

	if (disconnect) {
		// if file system cannot be disconnected
		if (fscache_disconnectable() == 0) {
			ret = 1;
			goto out;
		}

		// if file system is already disconnected
		if (i_connected == 0) {
			ret = 2;
			goto out;
		}
		i_simdis = 1;
	} else {
		// if file system is already connected
		if (i_connected) {
			ret = 1;
			goto out;
		}

		// if file system is not "simulated" disconnected
		if (i_simdis == 0) {
			ret = 2;
			goto out;
		}
		i_simdis = 0;
	}

	// if fs thread not running
	if (i_threaded == 0) {
		if (i_mounted) {
			dbug_print("simdis", ("thread not running"));
			ret = -1;
		} else {
			if (i_simdis)
				i_connected = 0;
			else
				i_connected = 1;
		}
		goto out;
	}

	// get the attention of the thread
	xx = thr_kill(i_threadid, SIGUSR1);
	if (xx) {
		dbug_print("simdis", ("thr_kill failed %d, threadid %d",
		    xx, i_threadid));
		ret = -1;
	}

out:
	fscache_unlock();
	
	if (ret == 0) {
		for (;;) {
			dbug_print("simdis", ("     waiting for simulated %s",
				strp));
			fscache_lock();
			int tcon = i_connected;
			int trec = i_reconcile;
			fscache_unlock();
			if (disconnect) {
				if (tcon == 0)
					break;
			} else {
				if ((tcon == 1) && (trec == 0))
					break;
			}
			mysleep(1);
		}
		dbug_print("simdis", ("DONE waiting for simulated %s", strp));
	} else {
		dbug_print("simdis", ("simulated %s failed %d", strp, ret));
	}

	return (ret);
}

//
//			cfsd_fscache::fscache_unmount
//
// Description:
//	Called to unmount the file system.
// Arguments:
// Returns:
//	Returns 0 if the unmount is successful
//		EIO if an error
//		EBUSY if did not unmount because busy
//		EAGAIN if umounted but should not unmount nfs mount
// Preconditions:

int
cfsd_fscache::fscache_unmount()
{
	dbug_enter("cfsd_fscache::fscache_unmount");

	int xx;
	int ret = 0;

	fscache_lock();

	// if there is a thread running
	if (i_threaded) {
		// do not bother unmounting if rolling the log
		if (i_reconcile) {
			ret = EBUSY;
			goto out;
		}

		// inform the thread to try the unmount
		i_tryunmount = 1;

		// get the attention of the thread
		xx = thr_kill(i_threadid, SIGUSR1);
		if (xx) {
			dbug_print("error", ("thr_kill failed %d, threadid %d",
			    xx, i_threadid));
			ret = EIO;
		}

		// wait for the thread to wake us up
		while (i_tryunmount) {
			xx = cond_wait(&i_cvwait, &i_lock);
			dbug_print("info", ("cond_wait woke up %d %d",
			    xx, i_tryunmount));
		}

		// if the file system is still mounted mounted
		if (fscache_mounted())
			ret = EBUSY;
	}

	// else if there is no thread running
	else {
		// try to unmount the file system
		if (umount(i_mntpt.data()) == -1) {
			xx = errno;
			dbug_print("info", ("unmount failed %s",
			    strerror(xx)));
			if (xx == EBUSY)
				ret = EBUSY;
			else
				ret = EIO;
		} else {
			i_mounted = 0;
		}
	}
out:
	fscache_unlock();
	return (ret);
}

// -----------------------------------------------------------------
//
//			cfsd_fscache::operator==
//
// Description:
// Arguments:
//	fscachep
// Returns:
//	Returns ...
// Preconditions:

int
cfsd_fscache::operator==(const cfsd_fscache &fscache) const
{
	dbug_enter("cfsd_fscache::operator==");
	int xx;
	xx = 0 == strcmp(i_name, fscache.i_name);
	return (xx);
}

// -----------------------------------------------------------------
//
//			cfsd_fscache::i_server_alive
//
// Description:
// Arguments:
// Returns:
// Preconditions:

void
cfsd_fscache::i_server_alive(cfsd_kmod *kmodp)
{
	dbug_enter("cfsd_fscache::i_server_alive");

	int ret;
	int xx;
	int result;

	for (;;) {
		// wait for a little while
		if (!i_simdis)
			mysleep(30);

		// if simulating disconnect
		fscache_lock();
		while (i_simdis && !i_tryunmount) {
			dbug_print("simdis", ("before calling cond_wait"));
			xx = cond_wait(&i_cvwait, &i_lock);
			dbug_print("simdis", ("cond_wait woke up %d %d",
			    xx, i_simdis));
		}
		fscache_unlock();

		if (i_tryunmount)
			break;

		// see if the server is alive
		if (i_pingserver() == -1) {
			// dead server
			continue;
		}

		// try to mount the back file system if needed
		if (i_backpath.isNull()) {
			RWCString tcmd("/usr/sbin/mount -F cachefs -o");
			tcmd += i_cfsopt;
			tcmd += ",slide,remount ";
			tcmd += i_backfs;
			tcmd += " ";
			tcmd += i_mntpt;
			dbug_print("info",
			    ("about to '%s'", tcmd.data()));
			system(tcmd.data());
		}

		// get the root fid of the file system
		cfs_fid_t rootfid;
		xx = kmodp->kmod_rootfid(&rootfid);
		if (xx) {
			dbug_print("info", ("could not mount back fs %s %d",
			    i_backfs.data(), xx));
			mysleep(5);
			continue;
		}

		// dummy up a fake kcred
		cred_t cr;
		memset(&cr, 0, sizeof (cred_t));

		// try to get attrs on the root
		cfs_vattr_t va;
		xx = kmodp->kmod_getattrfid(&rootfid, &cr, &va);
		if ((xx == ETIMEDOUT) || (xx == EIO)) {
			dbug_print("info", ("Bogus error %d", xx));
			mysleep(5);
			continue;
		}
		break;
	}
}

//
//			cfsd_fscache::i_pingserver
//
// Description:
//	Trys to ping the nfs server to see if it is alive.
// Arguments:
// Returns:
//	Returns 0 if it is alive, -1 if no answer.
// Preconditions:

int
cfsd_fscache::i_pingserver()
{
	dbug_enter("cfsd_fscache::i_pingserver");

	static struct timeval TIMEOUT = { 25, 0 };
	CLIENT *clnt;
	enum clnt_stat retval;
	int ret = 0;


	RWCString hostname = i_backfs;
	size_t index;
	index = hostname.first(':');
	dbug_assert(index != RW_NPOS);
	hostname.resize(index);
	dbug_print("info", ("remote host '%s'", hostname.data()));

	dbug_print("info", ("before clnt_create"));
	// XXX this takes 75 seconds to time out
	clnt = clnt_create(hostname.data(), NFS_PROGRAM, NFS_VERSION, "udp");
	if (clnt == NULL) {
		// XXX what if this fails other than TIMEDOUT
		clnt_pcreateerror(hostname.data());
		dbug_print("info", ("clnt_create failed"));
		ret = -1;
	} else {
		dbug_print("info", ("before null rpc"));
		// XXX this takes 45 seconds to time out
		retval = clnt_call(clnt, 0, xdr_void, NULL, xdr_void, NULL,
		    TIMEOUT);
		if (retval != RPC_SUCCESS) {
			// clnt_perror(clnt, "null rpc call failed");
			dbug_print("info", ("null rpc call failed %d", retval));
			ret = -1;
		}
		clnt_destroy(clnt);
	}
	return (ret);
}

//
//			cfsd_fscache::i_roll
//
// Description:
//	Rolls the contents of the log to the server.
// Arguments:
//	kmodp	interface to kernel functions
// Returns:
//	Returns 0 for success or ETIMEDOUT if a timeout error occurred.
// Preconditions:
//	precond(kmodp)

int
cfsd_fscache::i_roll(cfsd_kmod *kmodp)
{
	int error = 0;
	dbug_enter("cfsd_fscache::i_roll");

	dbug_precond(kmodp);

	cfsd_logelem *logp;
	char namebuf[MAXPATHLEN * 3];
	int xx;
	cfs_dlog_entry_t *entp;
	off_t next_offset;

	// map in the log file
	cfsd_logfile lf;
	sprintf(namebuf, "%s/%s/%s", i_cachepath.data(), i_name.data(),
		CACHEFS_DLOG_FILE);
	xx = lf.logfile_setup(namebuf, sizeof (cfs_dlog_entry_t));
	if (xx) {
		if (xx == ENOENT)
			return (0);
		i_fsproblem(kmodp);
		return (0);
	}

	fscache_lock();
	fscache_changes(1);
	fscache_unlock();

	// create a hashed mapping table for changes to cids
	cfsd_maptbl tbl;
	sprintf(namebuf, "%s/%s/%s", i_cachepath.data(), i_name.data(),
		CACHEFS_DMAP_FILE);
	xx = tbl.maptbl_setup(namebuf);
	if (xx) {
		i_fsproblem(kmodp);
		return (0);
	}

	i_again_offset = 0;
	i_again_seq = 0;

	// Pass 1: collect all cid to fid mappings
	next_offset = lf.logfile_entrystart();
	for (;;) {
		// get a pointer to the next record
		xx = lf.logfile_entry(next_offset, &entp);
		if (xx == 1)
			break;
		if (xx == -1) {
			i_fsproblem(kmodp);
			return (0);
		}
		next_offset += entp->dl_len;

		// skip record if not valid
		if (entp->dl_valid != CFS_DLOG_VAL_COMMITTED)
			continue;

		// create an object for the appropriate log type
		logp = NULL;
		switch (entp->dl_op) {
		case CFS_DLOG_CREATE:
		case CFS_DLOG_REMOVE:
		case CFS_DLOG_LINK:
		case CFS_DLOG_RENAME:
		case CFS_DLOG_MKDIR:
		case CFS_DLOG_RMDIR:
		case CFS_DLOG_SYMLINK:
		case CFS_DLOG_SETATTR:
		case CFS_DLOG_SETSECATTR:
		case CFS_DLOG_MODIFIED:
		case CFS_DLOG_TRAILER:
			break;

		case CFS_DLOG_MAPFID:
			dbug_print("info", ("mapfid"));
			logp = new cfsd_logelem_mapfid(&tbl, &lf, NULL);
			break;

		default:
			dbug_assert(0);
			i_fsproblem(kmodp);
			break;
		}

		// do not bother if ignoring the record
		if (logp == NULL)
			continue;

		// debuggging
		logp->logelem_dump();

		// roll the entry
		xx = logp->logelem_roll(NULL);
		if (xx) {
			i_fsproblem(kmodp);
			return (0);
		}

		// mark record as completed
		entp->dl_valid = CFS_DLOG_VAL_PROCESSED;
		xx = lf.logfile_sync();
		if (xx) {
			i_fsproblem(kmodp);
			return (0);
		}

		// destroy the object
		delete logp;
	}

	// Pass 2: modify the back file system
	next_offset = lf.logfile_entrystart();
	u_long curseq = 0;
	int eof = 0;
	for (;;) {
		// if we need the seq number of a deferred modify
		if (i_again_offset && (i_again_seq == 0)) {
			xx = lf.logfile_entry(i_again_offset, &entp);
			if (xx)
				break;
			dbug_assert(entp->dl_op == CFS_DLOG_MODIFIED);
			i_again_seq = entp->dl_seq;
			dbug_assert(i_again_seq != 0);
		}

		// get a pointer to the next record to process
		if (!eof) {
			xx = lf.logfile_entry(next_offset, &entp);
			if (xx == 1) {
				eof = 1;
				curseq = ULONG_MAX;
			} else if (xx)
				break;
			else
				curseq = entp->dl_seq;
		}

		// if its time to process a deferred modify entry
		if (i_again_seq && (eof || (i_again_seq < entp->dl_seq))) {
			xx = lf.logfile_entry(i_again_offset, &entp);
			if (xx)
				break;
			dbug_assert(entp->dl_op == CFS_DLOG_MODIFIED);
			i_again_offset = entp->dl_u.dl_modify.dl_next;
			i_again_seq = 0;
			entp->dl_u.dl_modify.dl_next = -1;
		} else if (eof) {
			xx = 0;
			break;
		}

		// else move the offset to the next record
		else {
			next_offset += entp->dl_len;
		}

		// skip record if not valid
		if (entp->dl_valid != CFS_DLOG_VAL_COMMITTED)
			continue;

		// process the record
		xx = i_rollone(kmodp, &tbl, &lf, curseq);
		if (xx == ETIMEDOUT) {
			// timeout error, back to disconnected
			dbug_print("info", ("timeout error occurred"));
			return (xx);
		} else if (xx == EIO) {
			break;
		} else if (xx == EAGAIN) {
		} else if (xx) {
			// should never happen
			dbug_assert(0);
			break;
		} else {
			// mark record as completed
			entp->dl_valid = CFS_DLOG_VAL_PROCESSED;
			xx = lf.logfile_sync();
			if (xx)
				break;
		}
	}

	// if an unrecoverable error occurred
	if (xx) {
		dbug_print("error", ("error processing log file"));
		i_fsproblem(kmodp);
	}

	// dump stats about the hash table
	tbl.maptbl_dumpstats();

	// dump stats about the log file
	lf.logfile_dumpstats();

	// XXX debugging hack, rename the log files
	char *xp;
	sprintf(namebuf, "%s/%s/%s", i_cachepath.data(), i_name.data(),
		CACHEFS_DLOG_FILE);
	xp = namebuf + strlen(namebuf) + 2;
	sprintf(xp, "%s/%s/%s.bak", i_cachepath.data(), i_name.data(),
		CACHEFS_DLOG_FILE);
	xx = rename(namebuf, xp);

	sprintf(namebuf, "%s/%s/%s", i_cachepath.data(), i_name.data(),
		CACHEFS_DMAP_FILE);
	xp = namebuf + strlen(namebuf) + 2;
	sprintf(xp, "%s/%s/%s.bak", i_cachepath.data(), i_name.data(),
		CACHEFS_DMAP_FILE);
	xx = rename(namebuf, xp);

	// delete the log file
	// XXX

	return (error);
}

//
//			cfsd_fscache::i_rollone
//
// Description:
// Arguments:
//	kmodp
//	tblp
//	lfp
// Returns:
//	Returns ...
// Preconditions:
//	precond(kmodp)
//	precond(tblp)
//	precond(lfp)

int
cfsd_fscache::i_rollone(cfsd_kmod *kmodp, cfsd_maptbl *tblp, cfsd_logfile *lfp,
    u_long seq)
{
	dbug_enter("cfsd_fscache::i_rollone");

	dbug_precond(kmodp);
	dbug_precond(tblp);
	dbug_precond(lfp);

	cfsd_logelem *logp = NULL;
	cfs_dlog_entry_t *entp = lfp->logfile_entry();

	// create an object for the appropriate log type
	switch (entp->dl_op) {
	case CFS_DLOG_CREATE:
		dbug_print("info", ("create"));
		logp = new cfsd_logelem_create(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_REMOVE:
		dbug_print("info", ("remove"));
		logp = new cfsd_logelem_remove(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_LINK:
		dbug_print("info", ("link"));
		logp = new cfsd_logelem_link(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_RENAME:
		dbug_print("info", ("rename"));
		logp = new cfsd_logelem_rename(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_MKDIR:
		dbug_print("info", ("mkdir"));
		logp = new cfsd_logelem_mkdir(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_RMDIR:
		dbug_print("info", ("rmdir"));
		logp = new cfsd_logelem_rmdir(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_SYMLINK:
		dbug_print("info", ("symlink"));
		logp = new cfsd_logelem_symlink(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_SETATTR:
		dbug_print("info", ("setattr"));
		logp = new cfsd_logelem_setattr(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_SETSECATTR:
		dbug_print("info", ("setsecattr"));
		logp = new cfsd_logelem_setsecattr(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_MODIFIED:
		dbug_print("info", ("modified"));
		logp = new cfsd_logelem_modified(tblp, lfp, kmodp);
		break;

	case CFS_DLOG_MAPFID:
		break;

	case CFS_DLOG_TRAILER:
		break;

	default:
		dbug_assert(0);
		return (EIO);
	}

	// do not bother if ignoring the record
	if (logp == NULL) {
		dbug_print("info", ("record ignored"));
		return (0);
	}

	// XXX debugging
	logp->logelem_dump();

	// roll the entry
	int xx = logp->logelem_roll(&seq);

	const char *strp = logp->logelem_message();
	if (strp) {
		write(i_ofd, strp, strlen(strp));
		dbug_print("conflict", ("%s", strp));
	}

	if (xx == EAGAIN) {
		dbug_assert(entp->dl_op == CFS_DLOG_MODIFIED);
		xx = i_addagain(kmodp, lfp, seq);
		if (xx == 0)
			xx = EAGAIN;
	}

	// destroy the object
	delete logp;

	return (xx);
}

//
//			cfsd_fscache::i_addagain
//
// Description:
// Arguments:
//	kmodp
//	lfp
// Returns:
//	Returns ...
// Preconditions:
//	precond(kmodp)
//	precond(lfp)

int
cfsd_fscache::i_addagain(cfsd_kmod *kmodp, cfsd_logfile *lfp, u_long nseq)
{
	dbug_enter("cfsd_fscache::i_addagain");

	dbug_precond(kmodp);
	dbug_precond(lfp);

	int xx;

	cfs_dlog_entry_t *entp = lfp->logfile_entry();
	off_t noffset = lfp->logfile_entry_off();
	dbug_assert(entp->dl_op == CFS_DLOG_MODIFIED);
	dbug_assert(nseq);

	// both set or both zero
	dbug_assert((!i_again_seq ^ !i_again_offset) == 0);

	// simple case, first one on list
	if ((i_again_seq == 0) || (nseq < i_again_seq)) {
		entp->dl_u.dl_modify.dl_next = i_again_offset;
		i_again_seq = nseq;
		i_again_offset = noffset;
		return (0);
	}

	// Search until we find the element on the list prior to the
	// insertion point.
	off_t prevoff = 0;
	off_t toff;
	for (toff = i_again_offset; toff != 0;
	    toff = entp->dl_u.dl_modify.dl_next) {
		// get pointer to next element on the list
		xx = lfp->logfile_entry(toff, &entp);
		if (xx) {
			return (xx);
		}
		dbug_assert(entp->dl_op == CFS_DLOG_MODIFIED);

		// done if we found the element after the insertion point
		if (nseq < entp->dl_seq)
			break;
		prevoff = toff;
	}
	dbug_assert(prevoff);

	// get pointer to element prior to the insertion point
	xx = lfp->logfile_entry(prevoff, &entp);
	if (xx) {
		return (xx);
	}
	dbug_assert(entp->dl_op == CFS_DLOG_MODIFIED);
	dbug_assert(entp->dl_u.dl_modify.dl_next == toff);

	// set element to point to our new element
	entp->dl_u.dl_modify.dl_next = noffset;

	// get pointer to our new element
	xx = lfp->logfile_entry(noffset, &entp);
	if (xx) {
		return (xx);
	}
	dbug_assert(entp->dl_op == CFS_DLOG_MODIFIED);

	// set it to point to next link or end of list
	entp->dl_u.dl_modify.dl_next = toff;

	// return success
	return (0);
}

//
//			cfsd_fscache::i_fsproblem
//
// Description:
// Arguments:
//	kmodp
// Returns:
// Preconditions:
//	precond(kmodp)

void
cfsd_fscache::i_fsproblem(cfsd_kmod *kmodp)
{
	dbug_enter("cfsd_fscache::i_fsproblem");

	dbug_precond(kmodp);

	int xx;

	// first try to put all modified files in lost+found
	xx = kmodp->kmod_lostfoundall();
	if (xx) {
		// if that failed, put file system in read-only mode
		kmodp->kmod_rofs();
		fscache_lock();
		fscache_disconnectable(0);
		i_modify++;
		fscache_unlock();
	}
}

//
//			cfsd_fscache::fscache_changes
//
// Description:
//	Used to specify whether or not there are changes to roll to the
//	server.
// Arguments:
//	tt
// Returns:
// Preconditions:

void
cfsd_fscache::fscache_changes(int tt)
{
	i_changes = tt;
	i_modify++;
}

//
//			mysleep
//
// Description:
//	A reimplemenation of the sleep(3c) function call using
//	cond_reltimedwait.
//	Problem withe sleep(3c) hanging.
//	May return early.
// Arguments:
//	sec	number of seconds to sleep for
// Returns:
// Preconditions:

void
mysleep(int sec)
{
#if 0
	sleep(sec);
#else
	cond_t cv;
	mutex_t mt;
	timestruc_t reltime;

	mutex_init(&mt, USYNC_THREAD, NULL);
	cond_init(&cv, USYNC_THREAD, 0);

	reltime.tv_sec = sec;
	reltime.tv_nsec = 0;

	cond_reltimedwait(&cv, &mt, &reltime);

	cond_destroy(&cv);
	mutex_destroy(&mt);
#endif
}
