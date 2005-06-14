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
/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Doors-daemon (dsvclockd) synchronization strategy: contacts a standalone
 * daemon to coordinate access to the shared resource across multiple
 * processes and multiple threads within a process.  Performance is slow
 * (about 1200 locks and unlocks per second on a Ultra 170E/167 MHz) but it
 * provides robust locks and scales well as the number of CPUs increase.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <unistd.h>
#include <dsvclockd.h>
#include <door.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <dhcp_svc_private.h>

static int dsvcd_lock(dsvc_synch_t *, dsvcd_locktype_t, void **);

/*
 * Our synchronization-private data which hangs off of sp->s_data; This
 * data is thus per-open-container-instance and (of course) per-process.
 */
typedef struct {
	int		s_lockfd;		/* door lock request fd */
	boolean_t	s_crosshost;		/* request crosshost synch */
} dsvcd_synch_t;

/*
 * Initialize the dsvclockd synchronization strategy for an open container,
 * whose synchronization information ("synchronization instance") is
 * pointed to by `sp', by opening the door to the dsvclockd.  On success,
 * hang our synchronization-private data off of `sp->s_data'.  Returns a
 * DSVC_* code.
 */
static int
dsvcd_init(dsvc_synch_t *sp, unsigned int synchflags)
{
	dsvcd_synch_t	*dsp;
	char		doorpath[MAXPATHLEN];
	door_info_t	info;
	unsigned int	tries;
	pid_t		dsvclockd_pid;
	int		fd;

	if (geteuid() != 0)
		return (DSVC_ACCESS);

	dsp = malloc(sizeof (dsvcd_synch_t));
	sp->s_data = dsp;
	if (dsp == NULL)
		return (DSVC_NO_MEMORY);

	(void) snprintf(doorpath, MAXPATHLEN, DSVCD_DOOR_FMT,
	    sp->s_datastore->d_resource);

	dsp->s_lockfd = -1;
	dsp->s_crosshost = (synchflags & DSVC_SYNCH_CROSSHOST) != 0;

	fd = open(doorpath, O_RDONLY);
	if (fd == -1) {
		if (errno == EACCES) {
			free(dsp);
			sp->s_data = NULL;
			return (DSVC_ACCESS);
		}
	} else {
		if (door_info(fd, &info) == 0 && info.di_target != -1) {
			dsp->s_lockfd = fd;
			return (DSVC_SUCCESS);
		}
		(void) close(fd);
	}

	switch (dsvclockd_pid = fork()) {
	case -1:
		break;
	case 0:
		/*
		 * Close all descriptors so messages don't leak through.
		 */
		(void) closefrom(0);

		/*
		 * It's okay if the exec fails; the `default' case below
		 * will give up and return DSVC_NO_LOCKMGR.
		 */
		(void) execl(DSVCD_PATH, DSVCD_PATH, (char *)0);
		_exit(EXIT_FAILURE);
	default:
		/*
		 * Make five attempts to open the dsvclockd door, each
		 * spaced a half second apart.
		 */
		for (tries = 0; tries < 5; tries++) {
			fd = open(doorpath, O_RDONLY);
			if (fd != -1) {
				if (door_info(fd, &info) == 0 &&
				    info.di_target != -1) {
					(void) waitpid(dsvclockd_pid, NULL, 0);
					dsp->s_lockfd = fd;
					return (DSVC_SUCCESS);
				}
				(void) close(fd);
			}
			(void) poll(NULL, 0, 500);
		}
		(void) waitpid(dsvclockd_pid, NULL, 0);
		break;
	}

	free(dsp);
	sp->s_data = NULL;
	return (DSVC_NO_LOCKMGR);
}

/*
 * Finish using the dsvclockd synchronization strategy on synchronization
 * instance `sp'.
 */
static void
dsvcd_fini(dsvc_synch_t *sp)
{
	dsvcd_synch_t *dsp = sp->s_data;

	sp->s_data = NULL;
	(void) close(dsp->s_lockfd);
	free(dsp);
}

/*
 * Obtain a shared lock on synchronization instance `sp'.  Upon success,
 * `unlock_cookiep' is set to a token to pass to `dsvcd_unlock' to unlock
 * the lock.  Returns a DSVC_* code.
 */
static int
dsvcd_rdlock(dsvc_synch_t *sp, void **unlock_cookiep)
{
	return (dsvcd_lock(sp, DSVCD_RDLOCK, unlock_cookiep));
}

/*
 * Obtain an exclusive lock on synchronization instance `sp'.  Upon
 * success, `unlock_cookiep' is set to a token to pass to `dsvcd_unlock' to
 * unlock the lock.  Returns a DSVC_* code.
 */
static int
dsvcd_wrlock(dsvc_synch_t *sp, void **unlock_cookiep)
{
	return (dsvcd_lock(sp, DSVCD_WRLOCK, unlock_cookiep));
}

/*
 * Lock the synchronization instance `sp' with a lock of type `locktype'.
 * Upon success, `unlock_cookiep' is set to point to a door descriptor
 * which is used to unlock the lock and to detect if the caller dies
 * holding the lock.  Returns a DSVC_* code.
 */
static int
dsvcd_lock(dsvc_synch_t *sp, dsvcd_locktype_t locktype, void **unlock_cookiep)
{
	door_arg_t		args;
	dsvcd_lock_request_t	request;
	dsvcd_reply_t		reply;
	door_desc_t		*descp;
	int			unlockfd;
	int			i;
	dsvcd_synch_t		*dsp = sp->s_data;

	if (dsp->s_lockfd == -1)
		return (DSVC_NO_LOCKMGR);

	request.lrq_request.rq_version	= DSVCD_DOOR_VERSION;
	request.lrq_request.rq_reqtype	= DSVCD_LOCK;
	request.lrq_locktype		= locktype;
	request.lrq_nonblock		= sp->s_nonblock;
	request.lrq_crosshost		= dsp->s_crosshost;
	request.lrq_conver		= sp->s_datastore->d_conver;

	(void) strlcpy(request.lrq_loctoken, sp->s_loctoken,
	    sizeof (request.lrq_loctoken));
	(void) strlcpy(request.lrq_conname, sp->s_conname,
	    sizeof (request.lrq_conname));

	args.data_ptr	= (char *)&request;
	args.data_size	= sizeof (dsvcd_lock_request_t);
	args.desc_ptr	= NULL;
	args.desc_num	= 0;
	args.rbuf	= (char *)&reply;
	args.rsize	= sizeof (dsvcd_reply_t);

	if (door_call(dsp->s_lockfd, &args) == -1) {
		/*
		 * If the lock manager went away, we'll get back EBADF.
		 */
		return (errno == EBADF ? DSVC_NO_LOCKMGR : DSVC_SYNCH_ERR);
	}

	descp = args.desc_ptr;
	if (args.desc_num == 0)
		unlockfd = -1;
	else {
		unlockfd = descp->d_data.d_desc.d_descriptor;

		/*
		 * There shouldn't be more than one descriptor, but close
		 * any extras to ease future compatibility.
		 */
		for (i = 1; i < args.desc_num; i++)
			(void) close(descp[i].d_data.d_desc.d_descriptor);
	}

	if (args.rbuf != (char *)&reply) {
		(void) memcpy(&reply, args.rbuf, sizeof (reply));
		(void) munmap(args.rbuf, args.rsize);
	}

	if (args.data_size != sizeof (dsvcd_reply_t) ||
	    reply.rp_version != DSVCD_DOOR_VERSION) {
		(void) close(unlockfd);
		return (DSVC_SYNCH_ERR);
	}

	if (reply.rp_retval == DSVC_SUCCESS && unlockfd == -1)
		return (DSVC_SYNCH_ERR);

	*unlock_cookiep = (void *)unlockfd;
	return (reply.rp_retval);
}

/*
 * Unlock the synchronization instance `sp' using the unlock token
 * `unlock_cookiep'.  Returns a DSVC_* code.
 */
/* ARGSUSED */
static int
dsvcd_unlock(dsvc_synch_t *sp, void *unlock_cookie)
{
	door_arg_t		args;
	dsvcd_unlock_request_t	request;
	dsvcd_reply_t		reply;
	int			unlockfd = (int)unlock_cookie;
	int			i;

	request.urq_request.rq_version = DSVCD_DOOR_VERSION;
	request.urq_request.rq_reqtype = DSVCD_UNLOCK;

	args.data_ptr	= (char *)&request;
	args.data_size	= sizeof (dsvcd_unlock_request_t);
	args.desc_ptr	= NULL;
	args.desc_num	= 0;
	args.rbuf	= (char *)&reply;
	args.rsize	= sizeof (dsvcd_reply_t);

	if (door_call(unlockfd, &args) == -1) {
		/*
		 * If the lock manager went away while we had a lock
		 * checked out, regard that as a synchronization error --
		 * it should never happen under correct operation.
		 */
		return (DSVC_SYNCH_ERR);
	}

	/*
	 * There shouldn't be any descriptors returned from the server
	 * here, but this may change in the future -- close any to ease
	 * future compatibility.
	 */
	for (i = 0; i < args.desc_num; i++)
		(void) close(args.desc_ptr[i].d_data.d_desc.d_descriptor);

	/*
	 * Close the unlock door even if the door_call() fails; this is so
	 * the container gets unlocked even if there's some screwup in the
	 * graceful unlocking protocol (in that case, this will generate
	 * a DOOR_UNREF_DATA call).
	 */
	(void) close(unlockfd);

	if (args.rbuf != (char *)&reply) {
		(void) memcpy(&reply, args.rbuf, sizeof (reply));
		(void) munmap(args.rbuf, args.rsize);
	}

	if (args.data_size != sizeof (dsvcd_reply_t) ||
	    reply.rp_version != DSVCD_DOOR_VERSION)
		return (DSVC_SYNCH_ERR);

	return (reply.rp_retval);
}

dsvc_synch_ops_t dsvcd_synch_ops = {
	dsvcd_init, dsvcd_fini, dsvcd_rdlock, dsvcd_wrlock, dsvcd_unlock
};
