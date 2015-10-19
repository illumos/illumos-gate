/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All rights reserved.  	*/


/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2015, Joyent, Inc.
 */

/*
 * FIFOFS file system vnode operations.  This file system
 * type supports STREAMS-based pipes and FIFOs.
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/kmem.h>
#include <sys/uio.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/pathname.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <sys/strsubr.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strredir.h>
#include <sys/fs/fifonode.h>
#include <sys/fs/namenode.h>
#include <sys/stropts.h>
#include <sys/proc.h>
#include <sys/unistd.h>
#include <sys/debug.h>
#include <fs/fs_subr.h>
#include <sys/filio.h>
#include <sys/termio.h>
#include <sys/ddi.h>
#include <sys/vtrace.h>
#include <sys/policy.h>
#include <sys/tsol/label.h>

/*
 * Define the routines/data structures used in this file.
 */
static int fifo_read(vnode_t *, uio_t *, int, cred_t *, caller_context_t *);
static int fifo_write(vnode_t *, uio_t *, int, cred_t *, caller_context_t *);
static int fifo_getattr(vnode_t *, vattr_t *, int, cred_t *,
	caller_context_t *);
static int fifo_setattr(vnode_t *, vattr_t *, int, cred_t *,
	caller_context_t *);
static int fifo_realvp(vnode_t *, vnode_t **, caller_context_t *);
static int fifo_access(vnode_t *, int, int, cred_t *, caller_context_t *);
static int fifo_create(struct vnode *, char *, vattr_t *, enum vcexcl,
    int, struct vnode **, struct cred *, int, caller_context_t *,
    vsecattr_t *);
static int fifo_fid(vnode_t *, fid_t *, caller_context_t *);
static int fifo_fsync(vnode_t *, int, cred_t *, caller_context_t *);
static int fifo_seek(vnode_t *, offset_t, offset_t *, caller_context_t *);
static int fifo_ioctl(vnode_t *, int, intptr_t, int, cred_t *, int *,
	caller_context_t *);
static int fifo_fastioctl(vnode_t *, int, intptr_t, int, cred_t *, int *);
static int fifo_strioctl(vnode_t *, int, intptr_t, int, cred_t *, int *);
static int fifo_poll(vnode_t *, short, int, short *, pollhead_t **,
	caller_context_t *);
static int fifo_pathconf(vnode_t *, int, ulong_t *, cred_t *,
	caller_context_t *);
static void fifo_inactive(vnode_t *, cred_t *, caller_context_t *);
static int fifo_rwlock(vnode_t *, int, caller_context_t *);
static void fifo_rwunlock(vnode_t *, int, caller_context_t *);
static int fifo_setsecattr(struct vnode *, vsecattr_t *, int, struct cred *,
	caller_context_t *);
static int fifo_getsecattr(struct vnode *, vsecattr_t *, int, struct cred *,
	caller_context_t *);

/* functions local to this file */
static boolean_t fifo_stayfast_enter(fifonode_t *);
static void fifo_stayfast_exit(fifonode_t *);

/*
 * Define the data structures external to this file.
 */
extern	dev_t	fifodev;
extern struct qinit fifo_stwdata;
extern struct qinit fifo_strdata;
extern kmutex_t ftable_lock;

struct  streamtab fifoinfo = { &fifo_strdata, &fifo_stwdata, NULL, NULL };

struct vnodeops *fifo_vnodeops;

const fs_operation_def_t fifo_vnodeops_template[] = {
	VOPNAME_OPEN,		{ .vop_open = fifo_open },
	VOPNAME_CLOSE,		{ .vop_close = fifo_close },
	VOPNAME_READ,		{ .vop_read = fifo_read },
	VOPNAME_WRITE,		{ .vop_write = fifo_write },
	VOPNAME_IOCTL,		{ .vop_ioctl = fifo_ioctl },
	VOPNAME_GETATTR,	{ .vop_getattr = fifo_getattr },
	VOPNAME_SETATTR,	{ .vop_setattr = fifo_setattr },
	VOPNAME_ACCESS,		{ .vop_access = fifo_access },
	VOPNAME_CREATE,		{ .vop_create = fifo_create },
	VOPNAME_FSYNC,		{ .vop_fsync = fifo_fsync },
	VOPNAME_INACTIVE,	{ .vop_inactive = fifo_inactive },
	VOPNAME_FID,		{ .vop_fid = fifo_fid },
	VOPNAME_RWLOCK,		{ .vop_rwlock = fifo_rwlock },
	VOPNAME_RWUNLOCK,	{ .vop_rwunlock = fifo_rwunlock },
	VOPNAME_SEEK,		{ .vop_seek = fifo_seek },
	VOPNAME_REALVP,		{ .vop_realvp = fifo_realvp },
	VOPNAME_POLL,		{ .vop_poll = fifo_poll },
	VOPNAME_PATHCONF,	{ .vop_pathconf = fifo_pathconf },
	VOPNAME_DISPOSE,	{ .error = fs_error },
	VOPNAME_SETSECATTR,	{ .vop_setsecattr = fifo_setsecattr },
	VOPNAME_GETSECATTR,	{ .vop_getsecattr = fifo_getsecattr },
	NULL,			NULL
};

/*
 * Return the fifoinfo structure.
 */
struct streamtab *
fifo_getinfo()
{
	return (&fifoinfo);
}

/*
 * Trusted Extensions enforces a restrictive policy for
 * writing via cross-zone named pipes. A privileged global
 * zone process may expose a named pipe by loopback mounting
 * it from a lower-level zone to a higher-level zone. The
 * kernel-enforced mount policy for lofs mounts ensures
 * that such mounts are read-only in the higher-level
 * zone. But this is not sufficient to prevent writing
 * down via fifos.  This function prevents writing down
 * by comparing the zone of the process which is requesting
 * write access with the zone owning the named pipe rendezvous.
 * For write access the zone of the named pipe must equal the
 * zone of the writing process. Writing up is possible since
 * the named pipe can be opened for read by a process in a
 * higher level zone.
 *
 * An exception is made for the global zone to support trusted
 * processes which enforce their own data flow policies.
 */
static boolean_t
tsol_fifo_access(vnode_t *vp, int flag, cred_t *crp)
{
	fifonode_t	*fnp = VTOF(vp);

	if (is_system_labeled() &&
	    (flag & FWRITE) &&
	    (!(fnp->fn_flag & ISPIPE))) {
		zone_t	*proc_zone;

		proc_zone = crgetzone(crp);
		if (proc_zone != global_zone) {
			char		vpath[MAXPATHLEN];
			zone_t		*fifo_zone;

			/*
			 * Get the pathname and use it to find
			 * the zone of the fifo.
			 */
			if (vnodetopath(rootdir, vp, vpath, sizeof (vpath),
			    kcred) == 0) {
				fifo_zone = zone_find_by_path(vpath);
				zone_rele(fifo_zone);

				if (fifo_zone != global_zone &&
				    fifo_zone != proc_zone) {
					return (B_FALSE);
				}
			} else {
				return (B_FALSE);
			}
		}
	}
	return (B_TRUE);
}

/*
 * Open and stream a FIFO.
 * If this is the first open of the file (FIFO is not streaming),
 * initialize the fifonode and attach a stream to the vnode.
 *
 * Each end of a fifo must be synchronized with the other end.
 * If not, the mated end may complete an open, I/O, close sequence
 * before the end waiting in open ever wakes up.
 * Note: namefs pipes come through this routine too.
 */
int
fifo_open(vnode_t **vpp, int flag, cred_t *crp, caller_context_t *ct)
{
	vnode_t		*vp		= *vpp;
	fifonode_t	*fnp		= VTOF(vp);
	fifolock_t	*fn_lock	= fnp->fn_lock;
	int		error;

	ASSERT(vp->v_type == VFIFO);
	ASSERT(vn_matchops(vp, fifo_vnodeops));

	if (!tsol_fifo_access(vp, flag, crp))
		return (EACCES);

	mutex_enter(&fn_lock->flk_lock);
	/*
	 * If we are the first reader, wake up any writers that
	 * may be waiting around.  wait for all of them to
	 * wake up before proceeding (i.e. fn_wsynccnt == 0)
	 */
	if (flag & FREAD) {
		fnp->fn_rcnt++;		/* record reader present */
		if (! (fnp->fn_flag & ISPIPE))
			fnp->fn_rsynccnt++;	/* record reader in open */
	}

	/*
	 * If we are the first writer, wake up any readers that
	 * may be waiting around.  wait for all of them to
	 * wake up before proceeding (i.e. fn_rsynccnt == 0)
	 */
	if (flag & FWRITE) {
		fnp->fn_wcnt++;		/* record writer present */
		if (! (fnp->fn_flag & ISPIPE))
			fnp->fn_wsynccnt++;	/* record writer in open */
	}
	/*
	 * fifo_stropen will take care of twisting the queues on the first
	 * open.  The 1 being passed in means twist the queues on the first
	 * open.
	 */
	error = fifo_stropen(vpp, flag, crp, 1, 1);
	/*
	 * fifo_stropen() could have replaced vpp
	 * since fifo's are the only thing we need to sync up,
	 * everything else just returns;
	 * Note: don't need to hold lock since ISPIPE can't change
	 * and both old and new vp need to be pipes
	 */
	ASSERT(MUTEX_HELD(&VTOF(*vpp)->fn_lock->flk_lock));
	if (fnp->fn_flag & ISPIPE) {
		ASSERT(VTOF(*vpp)->fn_flag & ISPIPE);
		ASSERT(VTOF(*vpp)->fn_rsynccnt == 0);
		ASSERT(VTOF(*vpp)->fn_rsynccnt == 0);
		/*
		 * XXX note: should probably hold locks, but
		 * These values should not be changing
		 */
		ASSERT(fnp->fn_rsynccnt == 0);
		ASSERT(fnp->fn_wsynccnt == 0);
		mutex_exit(&VTOF(*vpp)->fn_lock->flk_lock);
		return (error);
	}
	/*
	 * vp can't change for FIFOS
	 */
	ASSERT(vp == *vpp);
	/*
	 * If we are opening for read (or writer)
	 *   indicate that the reader (or writer) is done with open
	 *   if there is a writer (or reader) waiting for us, wake them up
	 *	and indicate that at least 1 read (or write) open has occurred
	 *	this is need in the event the read (or write) side closes
	 *	before the writer (or reader) has a chance to wake up
	 *	i.e. it sees that a reader (or writer) was once there
	 */
	if (flag & FREAD) {
		fnp->fn_rsynccnt--;	/* reader done with open */
		if (fnp->fn_flag & FIFOSYNC) {
			/*
			 * This indicates that a read open has occurred
			 * Only need to set if writer is actually asleep
			 * Flag will be consumed by writer.
			 */
			fnp->fn_flag |= FIFOROCR;
			cv_broadcast(&fnp->fn_wait_cv);
		}
	}
	if (flag & FWRITE) {
		fnp->fn_wsynccnt--;	/* writer done with open */
		if (fnp->fn_flag & FIFOSYNC) {
			/*
			 * This indicates that a write open has occurred
			 * Only need to set if reader is actually asleep
			 * Flag will be consumed by reader.
			 */
			fnp->fn_flag |= FIFOWOCR;
			cv_broadcast(&fnp->fn_wait_cv);
		}
	}

	fnp->fn_flag &= ~FIFOSYNC;

	/*
	 * errors don't wait around.. just return
	 * Note: XXX other end will wake up and continue despite error.
	 * There is no defined semantic on the correct course of option
	 * so we do what we've done in the past
	 */
	if (error != 0) {
		mutex_exit(&fnp->fn_lock->flk_lock);
		goto done;
	}
	ASSERT(fnp->fn_rsynccnt <= fnp->fn_rcnt);
	ASSERT(fnp->fn_wsynccnt <= fnp->fn_wcnt);
	/*
	 * FIFOWOCR (or FIFOROCR) indicates that the writer (or reader)
	 * has woken us up and is done with open (this way, if the other
	 * end has made it to close, we don't block forever in open)
	 * fn_wnct == fn_wsynccnt (or fn_rcnt == fn_rsynccnt) indicates
	 * that no writer (or reader) has yet made it through open
	 * This has the side benefit of that the first
	 * reader (or writer) will wait until the other end finishes open
	 */
	if (flag & FREAD) {
		while ((fnp->fn_flag & FIFOWOCR) == 0 &&
		    fnp->fn_wcnt == fnp->fn_wsynccnt) {
			if (flag & (FNDELAY|FNONBLOCK)) {
				mutex_exit(&fnp->fn_lock->flk_lock);
				goto done;
			}
			fnp->fn_insync++;
			fnp->fn_flag |= FIFOSYNC;
			if (!cv_wait_sig_swap(&fnp->fn_wait_cv,
			    &fnp->fn_lock->flk_lock)) {
				/*
				 * Last reader to wakeup clear writer
				 * Clear both writer and reader open
				 * occurred flag incase other end is O_RDWR
				 */
				if (--fnp->fn_insync == 0 &&
				    fnp->fn_flag & FIFOWOCR) {
					fnp->fn_flag &= ~(FIFOWOCR|FIFOROCR);
				}
				mutex_exit(&fnp->fn_lock->flk_lock);
				(void) fifo_close(*vpp, flag, 1, 0, crp, ct);
				error = EINTR;
				goto done;
			}
			/*
			 * Last reader to wakeup clear writer open occurred flag
			 * Clear both writer and reader open occurred flag
			 * incase other end is O_RDWR
			 */
			if (--fnp->fn_insync == 0 &&
			    fnp->fn_flag & FIFOWOCR) {
				fnp->fn_flag &= ~(FIFOWOCR|FIFOROCR);
				break;
			}
		}
	} else if (flag & FWRITE) {
		while ((fnp->fn_flag & FIFOROCR) == 0 &&
		    fnp->fn_rcnt == fnp->fn_rsynccnt) {
			if ((flag & (FNDELAY|FNONBLOCK)) && fnp->fn_rcnt == 0) {
				mutex_exit(&fnp->fn_lock->flk_lock);
				(void) fifo_close(*vpp, flag, 1, 0, crp, ct);
				error = ENXIO;
				goto done;
			}
			fnp->fn_flag |= FIFOSYNC;
			fnp->fn_insync++;
			if (!cv_wait_sig_swap(&fnp->fn_wait_cv,
			    &fnp->fn_lock->flk_lock)) {
				/*
				 * Last writer to wakeup clear
				 * Clear both writer and reader open
				 * occurred flag in case other end is O_RDWR
				 */
				if (--fnp->fn_insync == 0 &&
				    (fnp->fn_flag & FIFOROCR) != 0) {
					fnp->fn_flag &= ~(FIFOWOCR|FIFOROCR);
				}
				mutex_exit(&fnp->fn_lock->flk_lock);
				(void) fifo_close(*vpp, flag, 1, 0, crp, ct);
				error = EINTR;
				goto done;
			}
			/*
			 * Last writer to wakeup clear reader open occurred flag
			 * Clear both writer and reader open
			 * occurred flag in case other end is O_RDWR
			 */
			if (--fnp->fn_insync == 0 &&
			    (fnp->fn_flag & FIFOROCR) != 0) {
				fnp->fn_flag &= ~(FIFOWOCR|FIFOROCR);
				break;
			}
		}
	}
	mutex_exit(&fn_lock->flk_lock);
done:
	return (error);
}

/*
 * Close down a stream.
 * Call cleanlocks() and strclean() on every close.
 * For last close send hangup message and force
 * the other end of a named pipe to be unmounted.
 * Mount guarantees that the mounted end will only call fifo_close()
 * with a count of 1 when the unmount occurs.
 * This routine will close down one end of a pipe or FIFO
 * and free the stream head via strclose()
 */
/*ARGSUSED*/
int
fifo_close(vnode_t *vp, int flag, int count, offset_t offset, cred_t *crp,
	caller_context_t *ct)
{
	fifonode_t	*fnp		= VTOF(vp);
	fifonode_t	*fn_dest	= fnp->fn_dest;
	int		error		= 0;
	fifolock_t	*fn_lock	= fnp->fn_lock;
	queue_t		*sd_wrq;
	vnode_t		*fn_dest_vp;
	int		senthang = 0;

	ASSERT(vp->v_stream != NULL);
	/*
	 * clean locks and clear events.
	 */
	(void) cleanlocks(vp, ttoproc(curthread)->p_pid, 0);
	cleanshares(vp, ttoproc(curthread)->p_pid);
	strclean(vp);

	/*
	 * If a file still has the pipe/FIFO open, return.
	 */
	if (count > 1)
		return (0);


	sd_wrq = strvp2wq(vp);
	mutex_enter(&fn_lock->flk_lock);

	/*
	 * wait for pending opens to finish up
	 * note: this also has the side effect of single threading closes
	 */
	while (fn_lock->flk_ocsync)
		cv_wait(&fn_lock->flk_wait_cv, &fn_lock->flk_lock);

	fn_lock->flk_ocsync = 1;

	if (flag & FREAD) {
		fnp->fn_rcnt--;
	}
	/*
	 * If we are last writer wake up sleeping readers
	 * (They'll figure out that there are no more writers
	 * and do the right thing)
	 * send hangup down stream so that stream head will do the
	 * right thing.
	 */
	if (flag & FWRITE) {
		if (--fnp->fn_wcnt == 0 && fn_dest->fn_rcnt > 0) {
			if ((fn_dest->fn_flag & (FIFOFAST | FIFOWANTR)) ==
			    (FIFOFAST | FIFOWANTR)) {
				/*
				 * While we're at it, clear FIFOWANTW too
				 * Wake up any sleeping readers or
				 * writers.
				 */
				fn_dest->fn_flag &= ~(FIFOWANTR | FIFOWANTW);
				cv_broadcast(&fn_dest->fn_wait_cv);
			}
			/*
			 * This is needed incase the other side
			 * was opened non-blocking.  It is the
			 * only way we can tell that wcnt is 0 because
			 * of close instead of never having a writer
			 */
			if (!(fnp->fn_flag & ISPIPE))
				fnp->fn_flag |= FIFOCLOSE;
			/*
			 * Note: sending hangup effectively shuts down
			 * both reader and writer at other end.
			 */
			(void) putnextctl_wait(sd_wrq, M_HANGUP);
			senthang = 1;
		}
	}

	/*
	 * For FIFOs we need to indicate to stream head that last reader
	 * has gone away so that an error is generated
	 * Pipes just need to wake up the other end so that it can
	 * notice this end has gone away.
	 */

	if (fnp->fn_rcnt == 0 && fn_dest->fn_wcnt > 0) {
		if ((fn_dest->fn_flag & (FIFOFAST | FIFOWANTW)) ==
		    (FIFOFAST | FIFOWANTW)) {
			/*
			 * wake up any sleeping writers
			 */
			fn_dest->fn_flag &= ~FIFOWANTW;
			cv_broadcast(&fn_dest->fn_wait_cv);
		}
	}

	/*
	 * if there are still processes with this FIFO open
	 *	clear open/close sync flag
	 *	and just return;
	 */
	if (--fnp->fn_open > 0) {
		ASSERT((fnp->fn_rcnt + fnp->fn_wcnt) != 0);
		fn_lock->flk_ocsync = 0;
		cv_broadcast(&fn_lock->flk_wait_cv);
		mutex_exit(&fn_lock->flk_lock);
		return (0);
	}

	/*
	 * Need to send HANGUP if other side is still open
	 * (fnp->fn_rcnt or fnp->fn_wcnt may not be zero (some thread
	 * on this end of the pipe may still be in fifo_open())
	 *
	 * Note: we can get here with fn_rcnt and fn_wcnt != 0 if some
	 * thread is blocked somewhere in the fifo_open() path prior to
	 * fifo_stropen() incrementing fn_open.  This can occur for
	 * normal FIFOs as well as named pipes.  fn_rcnt and
	 * fn_wcnt only indicate attempts to open. fn_open indicates
	 * successful opens. Partially opened FIFOs should proceed
	 * normally; i.e. they will appear to be new opens.  Partially
	 * opened pipes will probably fail.
	 */

	if (fn_dest->fn_open && senthang == 0)
		(void) putnextctl_wait(sd_wrq, M_HANGUP);


	/*
	 * If this a pipe and this is the first end to close,
	 * then we have a bit of cleanup work to do.
	 * 	Mark both ends of pipe as closed.
	 * 	Wake up anybody blocked at the other end and for named pipes,
	 *	Close down this end of the stream
	 *	Allow other opens/closes to continue
	 * 	force an unmount of other end.
	 * Otherwise if this is last close,
	 *	flush messages,
	 *	close down the stream
	 *	allow other opens/closes to continue
	 */
	fnp->fn_flag &= ~FIFOISOPEN;
	if ((fnp->fn_flag & ISPIPE) && !(fnp->fn_flag & FIFOCLOSE)) {
		fnp->fn_flag |= FIFOCLOSE;
		fn_dest->fn_flag |= FIFOCLOSE;
		if (fnp->fn_flag & FIFOFAST)
			fifo_fastflush(fnp);
		if (vp->v_stream != NULL) {
			mutex_exit(&fn_lock->flk_lock);
			(void) strclose(vp, flag, crp);
			mutex_enter(&fn_lock->flk_lock);
		}
		cv_broadcast(&fn_dest->fn_wait_cv);
		/*
		 * allow opens and closes to proceed
		 * Since this end is now closed down, any attempt
		 * to do anything with this end will fail
		 */
		fn_lock->flk_ocsync = 0;
		cv_broadcast(&fn_lock->flk_wait_cv);
		fn_dest_vp = FTOV(fn_dest);
		/*
		 * if other end of pipe has been opened and it's
		 * a named pipe, unmount it
		 */
		if (fn_dest_vp->v_stream &&
		    (fn_dest_vp->v_stream->sd_flag & STRMOUNT)) {
			/*
			 * We must hold the destination vnode because
			 * nm_unmountall() causes close to be called
			 * for the other end of named pipe.  This
			 * could free the vnode before we are ready.
			 */
			VN_HOLD(fn_dest_vp);
			mutex_exit(&fn_lock->flk_lock);
			error = nm_unmountall(fn_dest_vp, crp);
			ASSERT(error == 0);
			VN_RELE(fn_dest_vp);
		} else {
			ASSERT(vp->v_count >= 1);
			mutex_exit(&fn_lock->flk_lock);
		}
	} else {
		if (fnp->fn_flag & FIFOFAST)
			fifo_fastflush(fnp);
#if DEBUG
		fn_dest_vp = FTOV(fn_dest);
		if (fn_dest_vp->v_stream)
			ASSERT((fn_dest_vp->v_stream->sd_flag & STRMOUNT) == 0);
#endif
		if (vp->v_stream != NULL) {
			mutex_exit(&fn_lock->flk_lock);
			(void) strclose(vp, flag, crp);
			mutex_enter(&fn_lock->flk_lock);
		}
		fn_lock->flk_ocsync = 0;
		cv_broadcast(&fn_lock->flk_wait_cv);
		cv_broadcast(&fn_dest->fn_wait_cv);
		mutex_exit(&fn_lock->flk_lock);
	}
	return (error);
}

/*
 * Read from a pipe or FIFO.
 * return 0 if....
 *    (1) user read request is 0 or no stream
 *    (2) broken pipe with no data
 *    (3) write-only FIFO with no data
 *    (4) no data and FNDELAY flag is set.
 * Otherwise return
 *	EAGAIN if FNONBLOCK is set and no data to read
 *	EINTR if signal received while waiting for data
 *
 * While there is no data to read....
 *   -  if the NDELAY/NONBLOCK flag is set, return 0/EAGAIN.
 *   -  wait for a write.
 *
 */
/*ARGSUSED*/

static int
fifo_read(struct vnode *vp, struct uio *uiop, int ioflag, struct cred *crp,
	caller_context_t *ct)
{
	fifonode_t	*fnp		= VTOF(vp);
	fifonode_t	*fn_dest;
	fifolock_t	*fn_lock	= fnp->fn_lock;
	int		error		= 0;
	mblk_t		*bp;

	ASSERT(vp->v_stream != NULL);
	if (uiop->uio_resid == 0)
		return (0);

	mutex_enter(&fn_lock->flk_lock);

	TRACE_2(TR_FAC_FIFO, TR_FIFOREAD_IN, "fifo_read in:%p fnp %p", vp, fnp);

	if (! (fnp->fn_flag & FIFOFAST))
		goto stream_mode;

	fn_dest	= fnp->fn_dest;
	/*
	 * Check for data on our input queue
	 */

	while (fnp->fn_count == 0) {
		/*
		 * No data on first attempt and no writer, then EOF
		 */
		if (fn_dest->fn_wcnt == 0 || fn_dest->fn_rcnt == 0) {
			mutex_exit(&fn_lock->flk_lock);
			return (0);
		}
		/*
		 * no data found.. if non-blocking, return EAGAIN
		 * otherwise 0.
		 */
		if (uiop->uio_fmode & (FNDELAY|FNONBLOCK)) {
			mutex_exit(&fn_lock->flk_lock);
			if (uiop->uio_fmode & FNONBLOCK)
				return (EAGAIN);
			return (0);
		}

		/*
		 * Note: FIFOs can get here with FIFOCLOSE set if
		 * write side is in the middle of opeining after
		 * it once closed. Pipes better not have FIFOCLOSE set
		 */
		ASSERT((fnp->fn_flag & (ISPIPE|FIFOCLOSE)) !=
		    (ISPIPE|FIFOCLOSE));
		/*
		 * wait for data
		 */
		fnp->fn_flag |= FIFOWANTR;

		TRACE_1(TR_FAC_FIFO, TR_FIFOREAD_WAIT, "fiforead wait: %p", vp);

		if (!cv_wait_sig_swap(&fnp->fn_wait_cv,
		    &fn_lock->flk_lock)) {
			error = EINTR;
			goto done;
		}

		TRACE_1(TR_FAC_FIFO, TR_FIFOREAD_WAKE,
		    "fiforead awake: %p", vp);

		/*
		 * check to make sure we are still in fast mode
		 */
		if (!(fnp->fn_flag & FIFOFAST))
			goto stream_mode;
	}

	ASSERT(fnp->fn_mp != NULL);

	/* For pipes copy should not bypass cache */
	uiop->uio_extflg |= UIO_COPY_CACHED;

	do {
		int bpsize = MBLKL(fnp->fn_mp);
		int uiosize = MIN(bpsize, uiop->uio_resid);

		error = uiomove(fnp->fn_mp->b_rptr, uiosize, UIO_READ, uiop);
		if (error != 0)
			break;

		fnp->fn_count -= uiosize;

		if (bpsize <= uiosize) {
			bp = fnp->fn_mp;
			fnp->fn_mp = fnp->fn_mp->b_cont;
			freeb(bp);

			if (uiop->uio_resid == 0)
				break;

			while (fnp->fn_mp == NULL && fn_dest->fn_wwaitcnt > 0) {
				ASSERT(fnp->fn_count == 0);

				if (uiop->uio_fmode & (FNDELAY|FNONBLOCK))
					goto trywake;

				/*
				 * We've consumed all available data but there
				 * are threads waiting to write more, let them
				 * proceed before bailing.
				 */

				fnp->fn_flag |= FIFOWANTR;
				fifo_wakewriter(fn_dest, fn_lock);

				if (!cv_wait_sig(&fnp->fn_wait_cv,
				    &fn_lock->flk_lock))
					goto trywake;

				if (!(fnp->fn_flag & FIFOFAST))
					goto stream_mode;
			}
		} else {
			fnp->fn_mp->b_rptr += uiosize;
			ASSERT(uiop->uio_resid == 0);
		}
	} while (uiop->uio_resid != 0 && fnp->fn_mp != NULL);

trywake:
	ASSERT(msgdsize(fnp->fn_mp) == fnp->fn_count);

	/*
	 * wake up any blocked writers, processes
	 * sleeping on POLLWRNORM, or processes waiting for SIGPOLL
	 * Note: checking for fn_count < Fifohiwat emulates
	 * STREAMS functionality when low water mark is 0
	 */
	if (fn_dest->fn_flag & (FIFOWANTW | FIFOHIWATW) &&
	    fnp->fn_count < Fifohiwat) {
		fifo_wakewriter(fn_dest, fn_lock);
	}
	goto done;

	/*
	 * FIFO is in streams mode.. let the stream head handle it
	 */
stream_mode:

	mutex_exit(&fn_lock->flk_lock);
	TRACE_1(TR_FAC_FIFO,
	    TR_FIFOREAD_STREAM, "fifo_read stream_mode:%p", vp);

	error = strread(vp, uiop, crp);

	mutex_enter(&fn_lock->flk_lock);

done:
	/*
	 * vnode update access time
	 */
	if (error == 0) {
		time_t now = gethrestime_sec();

		if (fnp->fn_flag & ISPIPE)
			fnp->fn_dest->fn_atime = now;
		fnp->fn_atime = now;
	}
	TRACE_2(TR_FAC_FIFO, TR_FIFOREAD_OUT,
	    "fifo_read out:%p error %d", vp, error);
	mutex_exit(&fn_lock->flk_lock);
	return (error);
}

/*
 * send SIGPIPE and return EPIPE if ...
 *   (1) broken pipe (essentially, reader is gone)
 *   (2) FIFO is not open for reading
 * return 0 if...
 *   (1) no stream
 *   (2) user write request is for 0 bytes and SW_SNDZERO is not set
 *	Note: SW_SNDZERO can't be set in fast mode
 * While the stream is flow controlled....
 *   -  if the NDELAY/NONBLOCK flag is set, return 0/EAGAIN.
 *   -  unlock the fifonode and sleep waiting for a reader.
 *   -  if a pipe and it has a mate, sleep waiting for its mate
 *	to read.
 */
/*ARGSUSED*/
static int
fifo_write(vnode_t *vp, uio_t *uiop, int ioflag, cred_t *crp,
	caller_context_t *ct)
{
	struct fifonode	*fnp, *fn_dest;
	fifolock_t	*fn_lock;
	struct stdata	*stp;
	int		error	= 0;
	int		write_size;
	int		size;
	int		fmode;
	mblk_t		*bp;
	boolean_t	hotread;

	ASSERT(vp->v_stream);
	uiop->uio_loffset = 0;
	stp	= vp->v_stream;

	/*
	 * remember original number of bytes requested. Used to determine if
	 * we actually have written anything at all
	 */
	write_size = uiop->uio_resid;

	/*
	 * only send zero-length messages if SW_SNDZERO is set
	 * Note: we will be in streams mode if SW_SNDZERO is set
	 * XXX this streams interface should not be exposed
	 */
	if ((write_size == 0) && !(stp->sd_wput_opt & SW_SNDZERO))
		return (0);

	fnp = VTOF(vp);
	fn_lock = fnp->fn_lock;
	fn_dest = fnp->fn_dest;

	mutex_enter(&fn_lock->flk_lock);

	TRACE_3(TR_FAC_FIFO, TR_FIFOWRITE_IN,
	    "fifo_write in:%p fnp %p size %d", vp, fnp, write_size);

	/*
	 * oops, no readers, error
	 */
	if (fn_dest->fn_rcnt == 0 || fn_dest->fn_wcnt == 0) {
		goto epipe;
	}

	/*
	 * if we are not in fast mode, let streams handle it
	 */
	if (!(fnp->fn_flag & FIFOFAST))
		goto stream_mode;

	fmode = uiop->uio_fmode & (FNDELAY|FNONBLOCK);

	/* For pipes copy should not bypass cache */
	uiop->uio_extflg |= UIO_COPY_CACHED;

	do  {
		/*
		 * check to make sure we are not over high water mark
		 */
		while (fn_dest->fn_count >= Fifohiwat) {
			/*
			 * Indicate that we have gone over high
			 * water mark
			 */
			/*
			 * if non-blocking, return
			 * only happens first time through loop
			 */
			if (fmode) {
				fnp->fn_flag |= FIFOHIWATW;
				if (uiop->uio_resid == write_size) {
					mutex_exit(&fn_lock->flk_lock);
					if (fmode & FNDELAY)
						return (0);
					else
						return (EAGAIN);
				}
				goto done;
			}

			/*
			 * wait for things to drain
			 */
			fnp->fn_flag |= FIFOWANTW;
			fnp->fn_wwaitcnt++;
			TRACE_1(TR_FAC_FIFO, TR_FIFOWRITE_WAIT,
			    "fifo_write wait: %p", vp);
			if (!cv_wait_sig_swap(&fnp->fn_wait_cv,
			    &fn_lock->flk_lock)) {
				error = EINTR;
				fnp->fn_wwaitcnt--;
				fifo_wakereader(fn_dest, fn_lock);
				goto done;
			}
			fnp->fn_wwaitcnt--;

			TRACE_1(TR_FAC_FIFO, TR_FIFOWRITE_WAKE,
			    "fifo_write wake: %p", vp);

			/*
			 * check to make sure we're still in fast mode
			 */
			if (!(fnp->fn_flag & FIFOFAST))
				goto stream_mode;

			/*
			 * make sure readers didn't go away
			 */
			if (fn_dest->fn_rcnt == 0 || fn_dest->fn_wcnt == 0) {
				goto epipe;
			}
		}
		/*
		 * If the write will put us over the high water mark,
		 * then we must break the message up into PIPE_BUF
		 * chunks to stay compliant with STREAMS
		 */
		if (uiop->uio_resid + fn_dest->fn_count > Fifohiwat)
			size = MIN(uiop->uio_resid, PIPE_BUF);
		else
			size = uiop->uio_resid;

		/*
		 * We don't need to hold flk_lock across the allocb() and
		 * uiomove().  However, on a multiprocessor machine where both
		 * the reader and writer thread are on cpu's, we must be
		 * careful to only drop the lock if there's data to be read.
		 * This forces threads entering fifo_read() to spin or block
		 * on flk_lock, rather than acquiring flk_lock only to
		 * discover there's no data to read and being forced to go
		 * back to sleep, only to be woken up microseconds later by
		 * this writer thread.
		 */
		hotread = fn_dest->fn_count > 0;
		if (hotread) {
			if (!fifo_stayfast_enter(fnp))
				goto stream_mode;
			mutex_exit(&fn_lock->flk_lock);
		}

		ASSERT(size != 0);
		/*
		 * Align the mblk with the user data so that
		 * copying in the data can take advantage of
		 * the double word alignment
		 */
		if ((bp = allocb(size + 8, BPRI_MED)) == NULL) {
			if (!hotread)
				mutex_exit(&fn_lock->flk_lock);

			error = strwaitbuf(size, BPRI_MED);

			mutex_enter(&fn_lock->flk_lock);

			if (hotread) {
				/*
				 * As we dropped the mutex for a moment, we
				 * need to wake up any thread waiting to be
				 * allowed to go from fast mode to stream mode.
				 */
				fifo_stayfast_exit(fnp);
			}
			if (error != 0) {
				goto done;
			}
			/*
			 * check to make sure we're still in fast mode
			 */
			if (!(fnp->fn_flag & FIFOFAST))
				goto stream_mode;

			/*
			 * make sure readers didn't go away
			 */
			if (fn_dest->fn_rcnt == 0 || fn_dest->fn_wcnt == 0) {
				goto epipe;
			}
			/*
			 * some other thread could have gotten in
			 * need to go back and check hi water mark
			 */
			continue;
		}
		bp->b_rptr += ((uintptr_t)uiop->uio_iov->iov_base & 0x7);
		bp->b_wptr = bp->b_rptr + size;
		error = uiomove((caddr_t)bp->b_rptr, size, UIO_WRITE, uiop);
		if (hotread) {
			mutex_enter(&fn_lock->flk_lock);
			/*
			 * As we dropped the mutex for a moment, we need to:
			 * - wake up any thread waiting to be allowed to go
			 *   from fast mode to stream mode,
			 * - make sure readers didn't go away.
			 */
			fifo_stayfast_exit(fnp);
			if (fn_dest->fn_rcnt == 0 || fn_dest->fn_wcnt == 0) {
				freeb(bp);
				goto epipe;
			}
		}

		if (error != 0) {
			freeb(bp);
			goto done;
		}

		fn_dest->fn_count += size;
		if (fn_dest->fn_mp != NULL) {
			fn_dest->fn_tail->b_cont = bp;
			fn_dest->fn_tail = bp;
		} else {
			fn_dest->fn_mp = fn_dest->fn_tail = bp;
			/*
			 * This is the first bit of data; wake up any sleeping
			 * readers, processes blocked in poll, and those
			 * expecting a SIGPOLL.
			 */
			fifo_wakereader(fn_dest, fn_lock);
		}
	} while (uiop->uio_resid != 0);

	goto done;

stream_mode:
	/*
	 * streams mode
	 *  let the stream head handle the write
	 */
	ASSERT(MUTEX_HELD(&fn_lock->flk_lock));

	mutex_exit(&fn_lock->flk_lock);
	TRACE_1(TR_FAC_FIFO,
	    TR_FIFOWRITE_STREAM, "fifo_write stream_mode:%p", vp);

	error = strwrite(vp, uiop, crp);

	mutex_enter(&fn_lock->flk_lock);

done:
	/*
	 * update vnode modification and change times
	 * make sure there were no errors and some data was transferred
	 */
	if (error == 0 && write_size != uiop->uio_resid) {
		time_t now = gethrestime_sec();

		if (fnp->fn_flag & ISPIPE) {
			fn_dest->fn_mtime = fn_dest->fn_ctime = now;
		}
		fnp->fn_mtime = fnp->fn_ctime = now;
	} else if (fn_dest->fn_rcnt == 0 || fn_dest->fn_wcnt == 0) {
		goto epipe;
	}
	TRACE_3(TR_FAC_FIFO, TR_FIFOWRITE_OUT,
	    "fifo_write out: vp %p error %d fnp %p", vp, error, fnp);
	mutex_exit(&fn_lock->flk_lock);
	return (error);
epipe:
	error = EPIPE;
	TRACE_3(TR_FAC_FIFO, TR_FIFOWRITE_OUT,
	    "fifo_write out: vp %p error %d fnp %p", vp, error, fnp);
	mutex_exit(&fn_lock->flk_lock);
	tsignal(curthread, SIGPIPE);
	return (error);
}

/*ARGSUSED6*/
static int
fifo_ioctl(vnode_t *vp, int cmd, intptr_t arg, int mode,
	cred_t *cr, int *rvalp, caller_context_t *ct)
{
	/*
	 * Just a quick check
	 * Once we go to streams mode we don't ever revert back
	 * So we do this quick check so as not to incur the overhead
	 * associated with acquiring the lock
	 */
	return ((VTOF(vp)->fn_flag & FIFOFAST) ?
	    fifo_fastioctl(vp, cmd, arg, mode, cr, rvalp) :
	    fifo_strioctl(vp, cmd, arg, mode, cr, rvalp));
}

static int
fifo_fastioctl(vnode_t *vp, int cmd, intptr_t arg, int mode,
	cred_t *cr, int *rvalp)
{
	fifonode_t	*fnp		= VTOF(vp);
	fifonode_t	*fn_dest;
	int		error		= 0;
	fifolock_t	*fn_lock	= fnp->fn_lock;
	int		cnt;

	/*
	 * tty operations not allowed
	 */
	if (((cmd & IOCTYPE) == LDIOC) ||
	    ((cmd & IOCTYPE) == tIOC) ||
	    ((cmd & IOCTYPE) == TIOC)) {
		return (EINVAL);
	}

	mutex_enter(&fn_lock->flk_lock);

	if (!(fnp->fn_flag & FIFOFAST)) {
		goto stream_mode;
	}

	switch (cmd) {

	/*
	 * Things we can't handle
	 * These will switch us to streams mode.
	 */
	default:
	case I_STR:
	case I_SRDOPT:
	case I_PUSH:
	case I_FDINSERT:
	case I_SENDFD:
	case I_RECVFD:
	case I_E_RECVFD:
	case I_ATMARK:
	case I_CKBAND:
	case I_GETBAND:
	case I_SWROPT:
		goto turn_fastoff;

	/*
	 * Things that don't do damage
	 * These things don't adjust the state of the
	 * stream head (i_setcltime does, but we don't care)
	 */
	case I_FIND:
	case I_GETSIG:
	case FIONBIO:
	case FIOASYNC:
	case I_GRDOPT:	/* probably should not get this, but no harm */
	case I_GWROPT:
	case I_LIST:
	case I_SETCLTIME:
	case I_GETCLTIME:
		mutex_exit(&fn_lock->flk_lock);
		return (strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp));

	case I_CANPUT:
		/*
		 * We can only handle normal band canputs.
		 * XXX : We could just always go to stream mode; after all
		 * canput is a streams semantics type thing
		 */
		if (arg != 0) {
			goto turn_fastoff;
		}
		*rvalp = (fnp->fn_dest->fn_count < Fifohiwat) ? 1 : 0;
		mutex_exit(&fn_lock->flk_lock);
		return (0);

	case I_NREAD:
		/*
		 * This may seem a bit silly for non-streams semantics,
		 * (After all, if they really want a message, they'll
		 * probably use getmsg() anyway). but it doesn't hurt
		 */
		error = copyout((caddr_t)&fnp->fn_count, (caddr_t)arg,
		    sizeof (cnt));
		if (error == 0) {
			*rvalp = (fnp->fn_count == 0) ? 0 : 1;
		}
		break;

	case FIORDCHK:
		*rvalp = fnp->fn_count;
		break;

	case I_PEEK:
	{
		STRUCT_DECL(strpeek, strpeek);
		struct uio	uio;
		struct iovec	iov;
		int		count;
		mblk_t		*bp;
		int		len;

		STRUCT_INIT(strpeek, mode);

		if (fnp->fn_count == 0) {
			*rvalp = 0;
			break;
		}

		error = copyin((caddr_t)arg, STRUCT_BUF(strpeek),
		    STRUCT_SIZE(strpeek));
		if (error)
			break;

		/*
		 * can't have any high priority message when in fast mode
		 */
		if (STRUCT_FGET(strpeek, flags) & RS_HIPRI) {
			*rvalp = 0;
			break;
		}

		len = STRUCT_FGET(strpeek, databuf.maxlen);
		if (len <= 0) {
			STRUCT_FSET(strpeek, databuf.len, len);
		} else {
			iov.iov_base = STRUCT_FGETP(strpeek, databuf.buf);
			iov.iov_len = len;
			uio.uio_iov = &iov;
			uio.uio_iovcnt = 1;
			uio.uio_loffset = 0;
			uio.uio_segflg = UIO_USERSPACE;
			uio.uio_fmode = 0;
			/* For pipes copy should not bypass cache */
			uio.uio_extflg = UIO_COPY_CACHED;
			uio.uio_resid = iov.iov_len;
			count = fnp->fn_count;
			bp = fnp->fn_mp;
			while (count > 0 && uio.uio_resid) {
				cnt = MIN(uio.uio_resid, MBLKL(bp));
				if ((error = uiomove((char *)bp->b_rptr, cnt,
				    UIO_READ, &uio)) != 0) {
					break;
				}
				count -= cnt;
				bp = bp->b_cont;
			}
			STRUCT_FSET(strpeek, databuf.len, len - uio.uio_resid);
		}
		STRUCT_FSET(strpeek, flags, 0);
		STRUCT_FSET(strpeek, ctlbuf.len, -1);

		error = copyout(STRUCT_BUF(strpeek), (caddr_t)arg,
		    STRUCT_SIZE(strpeek));
		if (error == 0 && len >= 0)
			*rvalp = 1;
		break;
	}

	case FIONREAD:
		/*
		 * let user know total number of bytes in message queue
		 */
		error = copyout((caddr_t)&fnp->fn_count, (caddr_t)arg,
		    sizeof (fnp->fn_count));
		if (error == 0)
			*rvalp = 0;
		break;

	case I_SETSIG:
		/*
		 * let streams set up the signal masking for us
		 * we just check to see if it's set
		 * XXX : this interface should not be visible
		 *  i.e. STREAM's framework is exposed.
		 */
		error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);
		if (vp->v_stream->sd_sigflags & (S_INPUT|S_RDNORM|S_WRNORM))
			fnp->fn_flag |= FIFOSETSIG;
		else
			fnp->fn_flag &= ~FIFOSETSIG;
		break;

	case I_FLUSH:
		/*
		 * flush them message queues
		 */
		if (arg & ~FLUSHRW) {
			error = EINVAL;
			break;
		}
		if (arg & FLUSHR) {
			fifo_fastflush(fnp);
		}
		fn_dest = fnp->fn_dest;
		if ((arg & FLUSHW)) {
			fifo_fastflush(fn_dest);
		}
		/*
		 * wake up any sleeping readers or writers
		 * (waking readers probably doesn't make sense, but it
		 *  doesn't hurt; i.e. we just got rid of all the data
		 *  what's to read ?)
		 */
		if (fn_dest->fn_flag & (FIFOWANTW | FIFOWANTR)) {
			fn_dest->fn_flag &= ~(FIFOWANTW | FIFOWANTR);
			cv_broadcast(&fn_dest->fn_wait_cv);
		}
		*rvalp = 0;
		break;

	/*
	 * Since no band data can ever get on a fifo in fast mode
	 * just return 0.
	 */
	case I_FLUSHBAND:
		error = 0;
		*rvalp = 0;
		break;

	/*
	 * invalid calls for stream head or fifos
	 */

	case I_POP:		/* shouldn't happen */
	case I_LOOK:
	case I_LINK:
	case I_PLINK:
	case I_UNLINK:
	case I_PUNLINK:

	/*
	 * more invalid tty type of ioctls
	 */

	case SRIOCSREDIR:
	case SRIOCISREDIR:
		error = EINVAL;
		break;

	}
	mutex_exit(&fn_lock->flk_lock);
	return (error);

turn_fastoff:
	fifo_fastoff(fnp);

stream_mode:
	/*
	 * streams mode
	 */
	mutex_exit(&fn_lock->flk_lock);
	return (fifo_strioctl(vp, cmd, arg, mode, cr, rvalp));

}

/*
 * FIFO is in STREAMS mode; STREAMS framework does most of the work.
 */
static int
fifo_strioctl(vnode_t *vp, int cmd, intptr_t arg, int mode,
	cred_t *cr, int *rvalp)
{
	fifonode_t	*fnp = VTOF(vp);
	int		error;
	fifolock_t	*fn_lock;

	if (cmd == _I_GETPEERCRED) {
		if (mode == FKIOCTL && fnp->fn_pcredp != NULL) {
			k_peercred_t *kp = (k_peercred_t *)arg;
			crhold(fnp->fn_pcredp);
			kp->pc_cr = fnp->fn_pcredp;
			kp->pc_cpid = fnp->fn_cpid;
			return (0);
		} else {
			return (ENOTSUP);
		}
	}

	error = strioctl(vp, cmd, arg, mode, U_TO_K, cr, rvalp);

	switch (cmd) {
	/*
	 * The FIFOSEND flag is set to inform other processes that a file
	 * descriptor is pending at the stream head of this pipe.
	 * The flag is cleared and the sending process is awoken when
	 * this process has completed receiving the file descriptor.
	 * XXX This could become out of sync if the process does I_SENDFDs
	 * and opens on connld attached to the same pipe.
	 */
	case I_RECVFD:
	case I_E_RECVFD:
		if (error == 0) {
			fn_lock = fnp->fn_lock;
			mutex_enter(&fn_lock->flk_lock);
			if (fnp->fn_flag & FIFOSEND) {
				fnp->fn_flag &= ~FIFOSEND;
				cv_broadcast(&fnp->fn_dest->fn_wait_cv);
			}
			mutex_exit(&fn_lock->flk_lock);
		}
		break;
	default:
		break;
	}

	return (error);
}

/*
 * If shadowing a vnode (FIFOs), apply the VOP_GETATTR to the shadowed
 * vnode to Obtain the node information. If not shadowing (pipes), obtain
 * the node information from the credentials structure.
 */
int
fifo_getattr(vnode_t *vp, vattr_t *vap, int flags, cred_t *crp,
	caller_context_t *ct)
{
	int		error		= 0;
	fifonode_t	*fnp		= VTOF(vp);
	queue_t		*qp;
	qband_t		*bandp;
	fifolock_t	*fn_lock	= fnp->fn_lock;

	if (fnp->fn_realvp) {
		/*
		 * for FIFOs or mounted pipes
		 */
		if (error = VOP_GETATTR(fnp->fn_realvp, vap, flags, crp, ct))
			return (error);
		mutex_enter(&fn_lock->flk_lock);
		/* set current times from fnode, even if older than vnode */
		vap->va_atime.tv_sec = fnp->fn_atime;
		vap->va_atime.tv_nsec = 0;
		vap->va_mtime.tv_sec = fnp->fn_mtime;
		vap->va_mtime.tv_nsec = 0;
		vap->va_ctime.tv_sec = fnp->fn_ctime;
		vap->va_ctime.tv_nsec = 0;
	} else {
		/*
		 * for non-attached/ordinary pipes
		 */
		vap->va_mode = 0;
		mutex_enter(&fn_lock->flk_lock);
		vap->va_atime.tv_sec = fnp->fn_atime;
		vap->va_atime.tv_nsec = 0;
		vap->va_mtime.tv_sec = fnp->fn_mtime;
		vap->va_mtime.tv_nsec = 0;
		vap->va_ctime.tv_sec = fnp->fn_ctime;
		vap->va_ctime.tv_nsec = 0;
		vap->va_uid = crgetuid(crp);
		vap->va_gid = crgetgid(crp);
		vap->va_nlink = 0;
		vap->va_fsid = fifodev;
		vap->va_nodeid = (ino64_t)fnp->fn_ino;
		vap->va_rdev = 0;
	}
	vap->va_type = VFIFO;
	vap->va_blksize = PIPE_BUF;
	/*
	 * Size is number of un-read bytes at the stream head and
	 * nblocks is the unread bytes expressed in blocks.
	 */
	if (vp->v_stream && (fnp->fn_flag & FIFOISOPEN)) {
		if ((fnp->fn_flag & FIFOFAST)) {
			vap->va_size = (u_offset_t)fnp->fn_count;
		} else {
			qp = RD((strvp2wq(vp)));
			vap->va_size = (u_offset_t)qp->q_count;
			if (qp->q_nband != 0) {
				mutex_enter(QLOCK(qp));
				for (bandp = qp->q_bandp; bandp;
				    bandp = bandp->qb_next)
					vap->va_size += bandp->qb_count;
				mutex_exit(QLOCK(qp));
			}
		}
		vap->va_nblocks = (fsblkcnt64_t)btod(vap->va_size);
	} else {
		vap->va_size = (u_offset_t)0;
		vap->va_nblocks = (fsblkcnt64_t)0;
	}
	mutex_exit(&fn_lock->flk_lock);
	vap->va_seq = 0;
	return (0);
}

/*
 * If shadowing a vnode, apply the VOP_SETATTR to it, and to the fnode.
 * Otherwise, set the time and return 0.
 */
int
fifo_setattr(
	vnode_t			*vp,
	vattr_t			*vap,
	int			flags,
	cred_t			*crp,
	caller_context_t	*ctp)
{
	fifonode_t	*fnp	= VTOF(vp);
	int		error	= 0;
	fifolock_t	*fn_lock;

	if (fnp->fn_realvp)
		error = VOP_SETATTR(fnp->fn_realvp, vap, flags, crp, ctp);
	if (error == 0) {
		fn_lock = fnp->fn_lock;
		mutex_enter(&fn_lock->flk_lock);
		if (vap->va_mask & AT_ATIME)
			fnp->fn_atime = vap->va_atime.tv_sec;
		if (vap->va_mask & AT_MTIME)
			fnp->fn_mtime = vap->va_mtime.tv_sec;
		fnp->fn_ctime = gethrestime_sec();
		mutex_exit(&fn_lock->flk_lock);
	}
	return (error);
}

/*
 * If shadowing a vnode, apply VOP_ACCESS to it.
 * Otherwise, return 0 (allow all access).
 */
int
fifo_access(vnode_t *vp, int mode, int flags, cred_t *crp, caller_context_t *ct)
{
	if (VTOF(vp)->fn_realvp)
		return (VOP_ACCESS(VTOF(vp)->fn_realvp, mode, flags, crp, ct));
	else
		return (0);
}

/*
 * This can be called if creat or an open with O_CREAT is done on the root
 * of a lofs mount where the mounted entity is a fifo.
 */
/*ARGSUSED*/
static int
fifo_create(struct vnode *dvp, char *name, vattr_t *vap, enum vcexcl excl,
    int mode, struct vnode **vpp, struct cred *cr, int flag,
    caller_context_t *ct, vsecattr_t *vsecp)
{
	int error;

	ASSERT(dvp && (dvp->v_flag & VROOT) && *name == '\0');
	if (excl == NONEXCL) {
		if (mode && (error = fifo_access(dvp, mode, 0, cr, ct)))
			return (error);
		VN_HOLD(dvp);
		return (0);
	}
	return (EEXIST);
}

/*
 * If shadowing a vnode, apply the VOP_FSYNC to it.
 * Otherwise, return 0.
 */
int
fifo_fsync(vnode_t *vp, int syncflag, cred_t *crp, caller_context_t *ct)
{
	fifonode_t	*fnp	= VTOF(vp);
	vattr_t		va;

	if (fnp->fn_realvp == NULL)
		return (0);

	bzero((caddr_t)&va, sizeof (va));
	va.va_mask = AT_MTIME | AT_ATIME;
	if (VOP_GETATTR(fnp->fn_realvp, &va, 0, crp, ct) == 0) {
		va.va_mask = 0;
		if (fnp->fn_mtime > va.va_mtime.tv_sec) {
			va.va_mtime.tv_sec = fnp->fn_mtime;
			va.va_mask = AT_MTIME;
		}
		if (fnp->fn_atime > va.va_atime.tv_sec) {
			va.va_atime.tv_sec = fnp->fn_atime;
			va.va_mask |= AT_ATIME;
		}
		if (va.va_mask != 0)
			(void) VOP_SETATTR(fnp->fn_realvp, &va, 0, crp, ct);
	}
	return (VOP_FSYNC(fnp->fn_realvp, syncflag, crp, ct));
}

/*
 * Called when the upper level no longer holds references to the
 * vnode. Sync the file system and free the fifonode.
 */
void
fifo_inactive(vnode_t *vp, cred_t *crp, caller_context_t *ct)
{
	fifonode_t	*fnp;
	fifolock_t	*fn_lock;

	mutex_enter(&ftable_lock);
	mutex_enter(&vp->v_lock);
	ASSERT(vp->v_count >= 1);
	if (--vp->v_count != 0) {
		/*
		 * Somebody accessed the fifo before we got a chance to
		 * remove it.  They will remove it when they do a vn_rele.
		 */
		mutex_exit(&vp->v_lock);
		mutex_exit(&ftable_lock);
		return;
	}
	mutex_exit(&vp->v_lock);

	fnp = VTOF(vp);

	/*
	 * remove fifo from fifo list so that no other process
	 * can grab it.
	 * Drop the reference count on the fifo node's
	 * underlying vfs.
	 */
	if (fnp->fn_realvp) {
		(void) fiforemove(fnp);
		mutex_exit(&ftable_lock);
		(void) fifo_fsync(vp, FSYNC, crp, ct);
		VN_RELE(fnp->fn_realvp);
		VFS_RELE(vp->v_vfsp);
		vp->v_vfsp = NULL;
	} else
		mutex_exit(&ftable_lock);

	fn_lock = fnp->fn_lock;

	mutex_enter(&fn_lock->flk_lock);
	ASSERT(vp->v_stream == NULL);
	ASSERT(vp->v_count == 0);
	/*
	 * if this is last reference to the lock, then we can
	 * free everything up.
	 */
	if (--fn_lock->flk_ref == 0) {
		mutex_exit(&fn_lock->flk_lock);
		ASSERT(fnp->fn_open == 0);
		ASSERT(fnp->fn_dest->fn_open == 0);
		if (fnp->fn_mp) {
			freemsg(fnp->fn_mp);
			fnp->fn_mp = NULL;
			fnp->fn_count = 0;
		}
		if (fnp->fn_pcredp != NULL) {
			crfree(fnp->fn_pcredp);
			fnp->fn_pcredp = NULL;
		}
		if (fnp->fn_flag & ISPIPE) {
			fifonode_t *fn_dest = fnp->fn_dest;

			vp = FTOV(fn_dest);
			if (fn_dest->fn_mp) {
				freemsg(fn_dest->fn_mp);
				fn_dest->fn_mp = NULL;
				fn_dest->fn_count = 0;
			}
			if (fn_dest->fn_pcredp != NULL) {
				crfree(fn_dest->fn_pcredp);
				fn_dest->fn_pcredp = NULL;
			}
			kmem_cache_free(pipe_cache, (fifodata_t *)fn_lock);
		} else
			kmem_cache_free(fnode_cache, (fifodata_t *)fn_lock);
	} else {
		mutex_exit(&fn_lock->flk_lock);
	}
}

/*
 * If shadowing a vnode, apply the VOP_FID to it.
 * Otherwise, return EINVAL.
 */
int
fifo_fid(vnode_t *vp, fid_t *fidfnp, caller_context_t *ct)
{
	if (VTOF(vp)->fn_realvp)
		return (VOP_FID(VTOF(vp)->fn_realvp, fidfnp, ct));
	else
		return (EINVAL);
}

/*
 * Lock a fifonode.
 */
/* ARGSUSED */
int
fifo_rwlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
	return (-1);
}

/*
 * Unlock a fifonode.
 */
/* ARGSUSED */
void
fifo_rwunlock(vnode_t *vp, int write_lock, caller_context_t *ctp)
{
}

/*
 * Return error since seeks are not allowed on pipes.
 */
/*ARGSUSED*/
int
fifo_seek(vnode_t *vp, offset_t ooff, offset_t *noffp, caller_context_t *ct)
{
	return (ESPIPE);
}

/*
 * If there is a realvp associated with vp, return it.
 */
int
fifo_realvp(vnode_t *vp, vnode_t **vpp, caller_context_t *ct)
{
	vnode_t *rvp;

	if ((rvp = VTOF(vp)->fn_realvp) != NULL) {
		vp = rvp;
		if (VOP_REALVP(vp, &rvp, ct) == 0)
			vp = rvp;
	}

	*vpp = vp;
	return (0);
}

/*
 * Poll for interesting events on a stream pipe
 */
/* ARGSUSED */
int
fifo_poll(vnode_t *vp, short events, int anyyet, short *reventsp,
	pollhead_t **phpp, caller_context_t *ct)
{
	fifonode_t	*fnp, *fn_dest;
	fifolock_t	*fn_lock;
	int		retevents;
	struct stdata	*stp;

	ASSERT(vp->v_stream != NULL);

	stp = vp->v_stream;
	retevents	= 0;
	fnp		= VTOF(vp);
	fn_dest		= fnp->fn_dest;
	fn_lock		= fnp->fn_lock;

	if (polllock(&stp->sd_pollist, &fn_lock->flk_lock) != 0) {
		*reventsp = POLLNVAL;
		return (0);
	}

	/*
	 * see if FIFO/pipe open
	 */
	if ((fnp->fn_flag & FIFOISOPEN) == 0) {
		if (((events & (POLLIN | POLLRDNORM | POLLPRI | POLLRDBAND)) &&
		    fnp->fn_rcnt == 0) ||
		    ((events & (POLLWRNORM | POLLWRBAND)) &&
		    fnp->fn_wcnt == 0)) {
			mutex_exit(&fnp->fn_lock->flk_lock);
			*reventsp = POLLERR;
			return (0);
		}
	}

	/*
	 * if not in fast mode, let the stream head take care of it
	 */
	if (!(fnp->fn_flag & FIFOFAST)) {
		mutex_exit(&fnp->fn_lock->flk_lock);
		goto stream_mode;
	}

	/*
	 * If this is a pipe.. check to see if the other
	 * end is gone.  If we are a fifo, check to see
	 * if write end is gone.
	 */

	if ((fnp->fn_flag & ISPIPE) && (fn_dest->fn_open == 0)) {
		retevents = POLLHUP;
	} else if ((fnp->fn_flag & (FIFOCLOSE | ISPIPE)) == FIFOCLOSE &&
	    (fn_dest->fn_wcnt == 0)) {
		/*
		 * no writer at other end.
		 * it was closed (versus yet to be opened)
		 */
			retevents = POLLHUP;
	} else if (events & (POLLWRNORM | POLLWRBAND)) {
		if (events & POLLWRNORM) {
			if (fn_dest->fn_count < Fifohiwat)
				retevents = POLLWRNORM;
			else
				fnp->fn_flag |= FIFOHIWATW;
		}
		/*
		 * This is always true for fast pipes
		 * (Note: will go to STREAMS mode if band data is written)
		 */
		if (events & POLLWRBAND)
			retevents |= POLLWRBAND;
	}
	if (events & (POLLIN | POLLRDNORM)) {
		if (fnp->fn_count)
			retevents |= (events & (POLLIN | POLLRDNORM));
	}

	/*
	 * if we happened to get something and we're not edge-triggered, return
	 */
	if ((*reventsp = (short)retevents) != 0 && !(events & POLLET)) {
		mutex_exit(&fnp->fn_lock->flk_lock);
		return (0);
	}

	/*
	 * If poll() has not found any events yet or we're edge-triggered, set
	 * up event cell to wake up the poll if a requested event occurs on this
	 * pipe/fifo.
	 */
	if (!anyyet) {
		if (events & POLLWRNORM)
			fnp->fn_flag |= FIFOPOLLW;
		if (events & (POLLIN | POLLRDNORM))
			fnp->fn_flag |= FIFOPOLLR;
		if (events & POLLRDBAND)
			fnp->fn_flag |= FIFOPOLLRBAND;
		/*
		 * XXX Don't like exposing this from streams
		 */
		*phpp = &stp->sd_pollist;
	}
	mutex_exit(&fnp->fn_lock->flk_lock);
	return (0);
stream_mode:
	return (strpoll(stp, events, anyyet, reventsp, phpp));
}

/*
 * POSIX pathconf() support.
 */
/* ARGSUSED */
int
fifo_pathconf(vnode_t *vp, int cmd, ulong_t *valp, cred_t *cr,
	caller_context_t *ct)
{
	ulong_t val;
	int error = 0;

	switch (cmd) {

	case _PC_LINK_MAX:
		val = MAXLINK;
		break;

	case _PC_MAX_CANON:
		val = MAX_CANON;
		break;

	case _PC_MAX_INPUT:
		val = MAX_INPUT;
		break;

	case _PC_NAME_MAX:
		error = EINVAL;
		break;

	case _PC_PATH_MAX:
	case _PC_SYMLINK_MAX:
		val = MAXPATHLEN;
		break;

	case _PC_PIPE_BUF:
		val = PIPE_BUF;
		break;

	case _PC_NO_TRUNC:
		if (vp->v_vfsp->vfs_flag & VFS_NOTRUNC)
			val = 1;	/* NOTRUNC is enabled for vp */
		else
			val = (ulong_t)-1;
		break;

	case _PC_VDISABLE:
		val = _POSIX_VDISABLE;
		break;

	case _PC_CHOWN_RESTRICTED:
		if (rstchown)
			val = rstchown;		/* chown restricted enabled */
		else
			val = (ulong_t)-1;
		break;

	case _PC_FILESIZEBITS:
		val = (ulong_t)-1;
		break;

	default:
		if (VTOF(vp)->fn_realvp)
			error = VOP_PATHCONF(VTOF(vp)->fn_realvp, cmd,
			    &val, cr, ct);
		else
			error = EINVAL;
		break;
	}

	if (error == 0)
		*valp = val;
	return (error);
}

/*
 * If shadowing a vnode, apply VOP_SETSECATTR to it.
 * Otherwise, return NOSYS.
 */
int
fifo_setsecattr(struct vnode *vp, vsecattr_t *vsap, int flag, struct cred *crp,
	caller_context_t *ct)
{
	int error;

	/*
	 * The acl(2) system call tries to grab the write lock on the
	 * file when setting an ACL, but fifofs does not implement
	 * VOP_RWLOCK or VOP_RWUNLOCK, so we do it here instead.
	 */
	if (VTOF(vp)->fn_realvp) {
		(void) VOP_RWLOCK(VTOF(vp)->fn_realvp, V_WRITELOCK_TRUE, ct);
		error = VOP_SETSECATTR(VTOF(vp)->fn_realvp, vsap, flag,
		    crp, ct);
		VOP_RWUNLOCK(VTOF(vp)->fn_realvp, V_WRITELOCK_TRUE, ct);
		return (error);
	} else
		return (fs_nosys());
}

/*
 * If shadowing a vnode, apply VOP_GETSECATTR to it. Otherwise, fabricate
 * an ACL from the permission bits that fifo_getattr() makes up.
 */
int
fifo_getsecattr(struct vnode *vp, vsecattr_t *vsap, int flag, struct cred *crp,
	caller_context_t *ct)
{
	if (VTOF(vp)->fn_realvp)
		return (VOP_GETSECATTR(VTOF(vp)->fn_realvp, vsap, flag,
		    crp, ct));
	else
		return (fs_fab_acl(vp, vsap, flag, crp, ct));
}


/*
 * Set the FIFOSTAYFAST flag so nobody can turn the fifo into stream mode.
 * If the flag is already set then wait until it is removed - releasing
 * the lock.
 * If the fifo switches into stream mode while we are waiting, return failure.
 */
static boolean_t
fifo_stayfast_enter(fifonode_t *fnp)
{
	ASSERT(MUTEX_HELD(&fnp->fn_lock->flk_lock));
	while (fnp->fn_flag & FIFOSTAYFAST) {
		fnp->fn_flag |= FIFOWAITMODE;
		cv_wait(&fnp->fn_wait_cv, &fnp->fn_lock->flk_lock);
		fnp->fn_flag &= ~FIFOWAITMODE;
	}
	if (!(fnp->fn_flag & FIFOFAST))
		return (B_FALSE);

	fnp->fn_flag |= FIFOSTAYFAST;
	return (B_TRUE);
}

/*
 * Unset the FIFOSTAYFAST flag and notify anybody waiting for this flag
 * to be removed:
 *	- threads wanting to turn into stream mode waiting in fifo_fastoff(),
 *	- other writers threads waiting in fifo_stayfast_enter().
 */
static void
fifo_stayfast_exit(fifonode_t *fnp)
{
	fifonode_t *fn_dest = fnp->fn_dest;

	ASSERT(MUTEX_HELD(&fnp->fn_lock->flk_lock));

	fnp->fn_flag &= ~FIFOSTAYFAST;

	if (fnp->fn_flag & FIFOWAITMODE)
		cv_broadcast(&fnp->fn_wait_cv);

	if ((fnp->fn_flag & ISPIPE) && (fn_dest->fn_flag & FIFOWAITMODE))
		cv_broadcast(&fn_dest->fn_wait_cv);
}
