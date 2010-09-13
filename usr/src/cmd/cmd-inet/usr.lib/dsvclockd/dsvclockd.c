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
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * #define _POSIX_PTHREAD_SEMANTICS before #including <signal.h> so that we
 * get the right (POSIX) version of sigwait(2).
 */
#define	_POSIX_PTHREAD_SEMANTICS

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <dhcp_svc_private.h>
#include <pthread.h>
#include <stdlib.h>
#include <dhcpmsg.h>
#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <locale.h>
#include <synch.h>
#include <sys/resource.h>

#include "datastore.h"
#include "dsvclockd.h"

/*
 * The DHCP service daemon synchronizes access to containers within a given
 * datastore.  Any datastore which is willing to accept the synchronization
 * constraints imposed by the DHCP service daemon can use this daemon in
 * lieu of rolling their own synchronization code.
 *
 * See $SRC/lib/libdhcpsvc/private/README.synch for more information.
 */

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN		"SYS_TEST"
#endif

#define	DSVCD_REAP_INTERVAL	(60 * 60 * 24)	/* seconds, thus once a day */
#define	DSVCD_REAP_THRESH	(60 * 60)	/* seconds, thus 1 hour stale */
#define	DSVCD_STACK_REDSIZE	(8 * 1024)	/* redzone size, in bytes */
#define	UD_RECLAIM_MAX		128		/* unlock door descriptors */

/*
 * Unlock descriptor -- one for each lock granted.  This descriptor is used
 * to subsequently unlock the granted lock (and to synchronize unlocking of
 * the lock; see svc_unlock() below for details).
 */
typedef struct dsvcd_unlock_desc {
	int			ud_fd;
	mutex_t			ud_lock;
	dsvcd_container_t	*ud_cn;
	struct dsvcd_unlock_desc *ud_next;
} dsvcd_unlock_desc_t;

static mutex_t			ud_reclaim_lock = DEFAULTMUTEX;
static unsigned int		ud_reclaim_count = 0;
static dsvcd_unlock_desc_t	*ud_reclaim_list = NULL;

static void			*reaper(void *);
static int			daemonize(void);
static void			*stack_create(unsigned int *);
static void			stack_destroy(void *, unsigned int);
static void			doorserv_create(door_info_t *);
static dsvcd_unlock_desc_t	*ud_create(dsvcd_container_t *, int *);
static void			ud_destroy(dsvcd_unlock_desc_t *, boolean_t);
static dsvcd_svc_t		svc_lock, svc_unlock;

int
main(int argc, char **argv)
{
	dsvcd_datastore_t	**ds_table;
	dsvc_datastore_t	dd;
	dsvc_synchtype_t	synchtype;
	char			**modules;
	unsigned int		i, j;
	int			debug_level = 0;
	boolean_t		is_daemon = B_TRUE;
	boolean_t		is_verbose = B_FALSE;
	int			sig, nmodules, nsynchmods, c;
	sigset_t		sigset;
	char			signame[SIG2STR_MAX];
	char			*progname;
	void			*stackbase;
	unsigned int		stacksize = 16 * 1024;
	struct rlimit		rl;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Mask all signals except SIGABRT; doing this here ensures that
	 * all threads created through door_create() have them masked too.
	 */
	(void) sigfillset(&sigset);
	(void) sigdelset(&sigset, SIGABRT);
	(void) thr_sigsetmask(SIG_BLOCK, &sigset, NULL);

	/*
	 * Figure out our program name; just keep the final piece so that
	 * our dhcpmsg() messages don't get too long.
	 */
	progname = strrchr(argv[0], '/');
	if (progname != NULL)
		progname++;
	else
		progname = argv[0];

	/*
	 * Set the door thread creation procedure so that all of our
	 * threads are created with thread stacks with backing store.
	 */
	(void) door_server_create(doorserv_create);

	while ((c = getopt(argc, argv, "d:fv")) != EOF) {
		switch (c) {

		case 'd':
			debug_level = atoi(optarg);
			break;

		case 'f':
			is_daemon = B_FALSE;
			break;

		case 'v':
			is_verbose = B_TRUE;
			break;

		case '?':
			(void) fprintf(stderr,
			    gettext("usage: %s [-dn] [-f] [-v]\n"), progname);
			return (EXIT_FAILURE);

		default:
			break;
		}
	}

	if (geteuid() != 0) {
		dhcpmsg_init(progname, B_FALSE, is_verbose, debug_level);
		dhcpmsg(MSG_ERROR, "must be super-user");
		dhcpmsg_fini();
		return (EXIT_FAILURE);
	}

	if (is_daemon && daemonize() == 0) {
		dhcpmsg_init(progname, B_FALSE, is_verbose, debug_level);
		dhcpmsg(MSG_ERROR, "cannot become daemon, exiting");
		dhcpmsg_fini();
		return (EXIT_FAILURE);
	}

	dhcpmsg_init(progname, is_daemon, is_verbose, debug_level);
	(void) atexit(dhcpmsg_fini);

	/*
	 * Max out the number available descriptors since we need to
	 * allocate two per held lock.
	 */
	rl.rlim_cur = RLIM_INFINITY;
	rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		dhcpmsg(MSG_ERR, "setrlimit failed");

	(void) enable_extended_FILE_stdio(-1, -1);

	if (enumerate_dd(&modules, &nmodules) != DSVC_SUCCESS) {
		dhcpmsg(MSG_ERROR, "cannot enumerate public modules, exiting");
		return (EXIT_FAILURE);
	}

	/*
	 * NOTE: this code assumes that a module that needs dsvclockd will
	 * always need it (even as the container version is ramped).  If
	 * this becomes bogus in a future release, we'll have to make this
	 * logic more sophisticated.
	 */
	nsynchmods = nmodules;
	for (i = 0; i < nmodules; i++) {
		dd.d_resource = modules[i];
		dd.d_conver = DSVC_CUR_CONVER;
		dd.d_location = "";
		if (module_synchtype(&dd, &synchtype) != DSVC_SUCCESS) {
			dhcpmsg(MSG_WARNING, "cannot determine synchronization "
			    "type for `%s', skipping", modules[i]);
			free(modules[i]);
			modules[i] = NULL;
			nsynchmods--;
			continue;
		}
		if ((synchtype & DSVC_SYNCH_STRATMASK) != DSVC_SYNCH_DSVCD) {
			free(modules[i]);
			modules[i] = NULL;
			nsynchmods--;
		}
	}

	if (nsynchmods == 0) {
		dhcpmsg(MSG_INFO, "no public modules need synchronization");
		return (EXIT_SUCCESS);
	}

	/*
	 * Allocate the datastore table; include one extra entry so that
	 * the table is NULL-terminated.
	 */
	ds_table = calloc(nsynchmods + 1, sizeof (dsvcd_datastore_t *));
	if (ds_table == NULL) {
		dhcpmsg(MSG_ERR, "cannot allocate datastore table, exiting");
		return (EXIT_FAILURE);
	}
	ds_table[nsynchmods] = NULL;

	/*
	 * Create the datastores (which implicitly creates the doors).
	 * then sit around and wait for requests to come in on the doors.
	 */
	for (i = 0, j = 0; i < nmodules; i++) {
		if (modules[i] != NULL) {
			ds_table[j] = ds_create(modules[i], svc_lock);
			if (ds_table[j] == NULL) {
				while (j-- > 0)
					ds_destroy(ds_table[j]);
				return (EXIT_FAILURE);
			}
			free(modules[i]);
			j++;
		}
	}
	free(modules);

	stackbase = stack_create(&stacksize);
	if (stackbase == NULL)
		dhcpmsg(MSG_ERR, "cannot create reaper stack; containers "
		    "will not be reaped");
	else {
		errno = thr_create(stackbase, stacksize, reaper, ds_table,
		    THR_DAEMON, NULL);
		if (errno != 0) {
			dhcpmsg(MSG_ERR, "cannot create reaper thread; "
			    "containers will not be reaped");
			stack_destroy(stackbase, stacksize);
		}
	}

	/*
	 * Synchronously wait for a QUIT, TERM, or INT, then shutdown.
	 */
	(void) sigemptyset(&sigset);
	(void) sigaddset(&sigset, SIGQUIT);
	(void) sigaddset(&sigset, SIGTERM);
	(void) sigaddset(&sigset, SIGINT);

	(void) sigwait(&sigset, &sig);
	if (sig != SIGTERM && sig != SIGQUIT && sig != SIGINT)
		dhcpmsg(MSG_WARNING, "received unexpected signal");

	if (sig2str(sig, signame) == -1)
		(void) strlcpy(signame, "???", sizeof (signame));

	dhcpmsg(MSG_INFO, "shutting down via SIG%s", signame);

	for (i = 0; i < nsynchmods; i++)
		ds_destroy(ds_table[i]);

	return (EXIT_SUCCESS);
}

/*
 * Sanity check that dsvcd_request_t `req' (which is `reqsize' bytes long)
 * is a correctly formed request; if not, return an error which will be
 * returned to the door caller.
 */
static int
check_door_req(dsvcd_request_t *req, size_t reqsize, size_t minsize)
{
	door_cred_t cred;

	if (req == NULL) {
		dhcpmsg(MSG_WARNING, "empty request, ignoring");
		return (DSVC_SYNCH_ERR);
	}

	/*
	 * Check credentials; we don't allow any non-super-user requests
	 * since this would open a denial-of-service hole (since a lock
	 * could be checked out indefinitely).
	 */
	if (door_cred(&cred) != 0) {
		dhcpmsg(MSG_WARNING, "request with unknown credentials");
		return (DSVC_ACCESS);
	}

	if (cred.dc_euid != 0) {
		dhcpmsg(MSG_WARNING, "request with non-super-user credentials");
		return (DSVC_ACCESS);
	}

	/*
	 * Check the version and size; we check this before checking the
	 * size of the request structure since an "incompatible version"
	 * message is more helpful than a "short request" message.
	 */
	if (reqsize > offsetof(dsvcd_request_t, rq_version) &&
	    req->rq_version != DSVCD_DOOR_VERSION) {
		dhcpmsg(MSG_WARNING, "request with unsupported version `%d'",
		    req->rq_version);
		return (DSVC_SYNCH_ERR);
	}

	if (reqsize < minsize) {
		dhcpmsg(MSG_VERBOSE, "short request (%d bytes, minimum %d "
		    "bytes)", reqsize, minsize);
		return (DSVC_SYNCH_ERR);
	}

	return (DSVC_SUCCESS);
}


/*
 * Service a lock request `req' passed across the door for datastore `ds'.
 * After verifying that the request is well-formed, locks the container and
 * creates an "unlock" door descriptor that the client uses to unlock the
 * door (either explicitly through door_call()) or implicitly through
 * terminating abnormally).
 */
/* ARGSUSED */
static void
svc_lock(void *cookie, dsvcd_request_t *req, size_t reqsize,
    door_desc_t *doorp, uint_t ndoors)
{
	dsvcd_reply_t		reply;
	door_desc_t		door_desc;
	dsvcd_lock_request_t	*lreq = (dsvcd_lock_request_t *)req;
	dsvcd_datastore_t	*ds = (dsvcd_datastore_t *)cookie;
	dsvcd_container_t	*cn;
	dsvcd_unlock_desc_t	*ud;
	char			conid[MAXPATHLEN];
	unsigned int		attempts = 0;

	reply.rp_version = DSVCD_DOOR_VERSION;
	reply.rp_retval  = check_door_req(req, reqsize,
	    sizeof (dsvcd_lock_request_t));
	if (reply.rp_retval != DSVC_SUCCESS) {
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	/*
	 * Verify that this is a lock request; if in the future we support
	 * other requests, we'll have to abstract this a bit.
	 */
	if (req->rq_reqtype != DSVCD_LOCK) {
		dhcpmsg(MSG_WARNING, "unsupported request `%d' on lock "
		    "request door", req->rq_reqtype);
		reply.rp_retval = DSVC_SYNCH_ERR;
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}
	if (lreq->lrq_locktype != DSVCD_RDLOCK &&
	    lreq->lrq_locktype != DSVCD_WRLOCK) {
		dhcpmsg(MSG_WARNING, "request for unsupported locktype `%d'",
		    lreq->lrq_locktype);
		reply.rp_retval = DSVC_SYNCH_ERR;
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	/*
	 * Find the container; create if it doesn't already exist.  We do
	 * this as a single operation to avoid race conditions.
	 */
	(void) snprintf(conid, sizeof (conid), "%s/%s%d_%s", lreq->lrq_loctoken,
	    ds->ds_name, lreq->lrq_conver, lreq->lrq_conname);
	cn = ds_get_container(ds, conid, lreq->lrq_crosshost);
	if (cn == NULL) {
		reply.rp_retval = DSVC_NO_MEMORY;
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	/*
	 * We need another door descriptor which is passed back with the
	 * request.  This descriptor is used when the caller wants to
	 * gracefully unlock or when the caller terminates abnormally.
	 */
	ud = ud_create(cn, &reply.rp_retval);
	if (ud == NULL) {
		ds_release_container(ds, cn);
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	/*
	 * We pass a duped door descriptor with the DOOR_RELEASE flag set
	 * instead of just passing the descriptor itself to handle the case
	 * where the client has gone away before we door_return().  Since
	 * we duped, the door descriptor itself will have a refcount of 2
	 * when we go to pass it to the client; if the client does not
	 * exist, the DOOR_RELEASE will drop the count from 2 to 1 which
	 * will cause a DOOR_UNREF_DATA call.
	 *
	 * In the regular (non-error) case, the door_return() will handoff
	 * the descriptor to the client, bumping the refcount to 3, and
	 * then the DOOR_RELEASE will drop the count to 2.  If the client
	 * terminates abnormally after this point, the count will drop from
	 * 2 to 1 which will cause a DOOR_UNREF_DATA call.  If the client
	 * unlocks gracefully, the refcount will still be 2 when the unlock
	 * door server procedure is called, and the unlock procedure will
	 * unlock the lock and note that the lock has been unlocked (so
	 * that we know the DOOR_UNREF_DATA call generated from the client
	 * subsequently closing the unlock descriptor is benign).
	 *
	 * Note that a DOOR_UNREF_DATA call will be generated *any time*
	 * the refcount goes from 2 to 1 -- even if *we* cause it to
	 * happen, which by default will happen in some of the error logic
	 * below (when we close the duped descriptor).  To prevent this
	 * scenario, we tell ud_destroy() *not* to cache the unlock
	 * descriptor, which forces it to blow away the descriptor using
	 * door_revoke(), making the close() that follows benign.
	 */
	door_desc.d_attributes = DOOR_DESCRIPTOR|DOOR_RELEASE;
	door_desc.d_data.d_desc.d_descriptor = dup(ud->ud_fd);
	if (door_desc.d_data.d_desc.d_descriptor == -1) {
		dhcpmsg(MSG_ERR, "cannot dup unlock door; denying %s "
		    "lock request", cn->cn_id);
		ud_destroy(ud, B_TRUE);
		ds_release_container(ds, cn);
		reply.rp_retval = DSVC_NO_RESOURCES;
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	/*
	 * Acquire the actual read or write lock on the container.
	 */
	dhcpmsg(MSG_DEBUG, "tid %d: %s locking %s", thr_self(),
	    lreq->lrq_locktype == DSVCD_RDLOCK ? "read" : "write", cn->cn_id);

	if (lreq->lrq_locktype == DSVCD_RDLOCK)
		reply.rp_retval = cn_rdlock(cn, lreq->lrq_nonblock);
	else if (lreq->lrq_locktype == DSVCD_WRLOCK)
		reply.rp_retval = cn_wrlock(cn, lreq->lrq_nonblock);

	dhcpmsg(MSG_DEBUG, "tid %d: %s %s lock operation: %s", thr_self(),
	    cn->cn_id, lreq->lrq_locktype == DSVCD_RDLOCK ? "read" : "write",
	    dhcpsvc_errmsg(reply.rp_retval));

	ds_release_container(ds, cn);
	if (reply.rp_retval != DSVC_SUCCESS) {
		ud_destroy(ud, B_FALSE);
		(void) close(door_desc.d_data.d_desc.d_descriptor);
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	while (door_return((char *)&reply, sizeof (reply), &door_desc, 1)
	    == -1 && errno == EMFILE) {
		if (lreq->lrq_nonblock) {
			dhcpmsg(MSG_WARNING, "unable to grant lock; client"
			    " is out of file descriptors");
			(void) cn_unlock(cn);
			ud_destroy(ud, B_FALSE);
			(void) close(door_desc.d_data.d_desc.d_descriptor);
			reply.rp_retval = DSVC_BUSY;
			(void) door_return((char *)&reply, sizeof (reply),
			    NULL, 0);
			return;
		}

		if (attempts++ == 0) {
			dhcpmsg(MSG_WARNING, "unable to grant lock; client"
			    " is out of file descriptors (retrying)");
		}
		(void) poll(NULL, 0, 100);
	}
}

/*
 * Service an unlock request `req' passed across the door associated with
 * the unlock token `cookie'.  We may be called explicitly (in which case
 * the request is a well-formed dsvcd_request_t) or implicitly (in which
 * case our request is set to the value DOOR_UNREF_DATA); this latter case
 * occurs when a process holding a lock terminates.  In either case, unlock
 * the lock; in the implicit case, log a message as well.
 */
/* ARGSUSED */
static void
svc_unlock(void *cookie, dsvcd_request_t *req, size_t reqsize,
    door_desc_t *doorp, uint_t ndoors)
{
	dsvcd_unlock_desc_t	*ud = cookie;
	dsvcd_container_t	*cn;
	dsvcd_reply_t		reply;

	/*
	 * Although unlock descriptors are handed out to only a single
	 * thread who has been granted a lock (ergo it seems that only one
	 * thread should be able to call us back), there's a potential race
	 * here if the process crashes while in this door_call(), since
	 * both this thread and the unref kernel upcall thread may run at
	 * the same time.  Protect against this case with a mutex.
	 */
	(void) mutex_lock(&ud->ud_lock);
	cn = ud->ud_cn;

	/*
	 * First handle the case where the lock owner has closed the unlock
	 * descriptor, either because they have unlocked the lock and are
	 * thus done using the descriptor, or because they crashed.  In the
	 * second case, print a message.
	 */
	if (req == DOOR_UNREF_DATA) {
		/*
		 * The last reference is ours; we can free the descriptor.
		 */
		(void) mutex_unlock(&ud->ud_lock);
		ud_destroy(ud, B_TRUE);

		/*
		 * Normal case: the caller is closing the unlock descriptor
		 * on a lock they've already unlocked -- just return.
		 */
		if (cn == NULL) {
			(void) door_return(NULL, 0, NULL, 0);
			return;
		}

		/*
		 * Error case: the caller has crashed while holding the
		 * unlock descriptor (or is otherwise in violation of
		 * protocol).  Since all datastores are required to be
		 * robust even if unexpected termination occurs, we assume
		 * the container is not corrupt, even if the process
		 * crashed with the write lock held.
		 */
		switch (cn_locktype(cn)) {
		case DSVCD_RDLOCK:
			dhcpmsg(MSG_WARNING, "process exited while reading "
			    "`%s'; unlocking", cn->cn_id);
			(void) cn_unlock(cn);
			break;

		case DSVCD_WRLOCK:
			dhcpmsg(MSG_WARNING, "process exited while writing "
			    "`%s'; unlocking", cn->cn_id);
			dhcpmsg(MSG_WARNING, "note that this write operation "
			    "may or may not have succeeded");
			(void) cn_unlock(cn);
			break;

		case DSVCD_NOLOCK:
			dhcpmsg(MSG_CRIT, "unreferenced unheld lock");
			break;
		}

		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	/*
	 * Verify that this is a unlock request; if in the future we support
	 * other requests, we'll have to abstract this a bit.
	 */
	reply.rp_version = DSVCD_DOOR_VERSION;
	reply.rp_retval = check_door_req(req, reqsize,
	    sizeof (dsvcd_unlock_request_t));
	if (reply.rp_retval != DSVC_SUCCESS) {
		(void) mutex_unlock(&ud->ud_lock);
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	if (req->rq_reqtype != DSVCD_UNLOCK) {
		dhcpmsg(MSG_WARNING, "unsupported request `%d' on unlock "
		    "request door", req->rq_reqtype);
		(void) mutex_unlock(&ud->ud_lock);
		reply.rp_retval = DSVC_SYNCH_ERR;
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}

	/*
	 * Attempt to unlock an already-unlocked container; log and return.
	 */
	if (cn == NULL) {
		dhcpmsg(MSG_WARNING, "process tried to re-unlock a lock");
		(void) mutex_unlock(&ud->ud_lock);
		reply.rp_retval = DSVC_SYNCH_ERR;
		(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
		return;
	}
	ud->ud_cn = NULL;

	/*
	 * Unlock the container; note that after cn_unlock() has been done
	 * cn->cn_id is no longer accessible.
	 */
	dhcpmsg(MSG_DEBUG, "tid %d: unlocking %s", thr_self(), cn->cn_id);
	reply.rp_retval = cn_unlock(cn);
	dhcpmsg(MSG_DEBUG, "tid %d: unlock operation: %s", thr_self(),
	    dhcpsvc_errmsg(reply.rp_retval));

	/*
	 * Even though we've unlocked the lock, we cannot yet destroy the
	 * unlock descriptor (even if we revoke the door) because it's
	 * possible the unref thread is already waiting on ud_lock.
	 */
	(void) mutex_unlock(&ud->ud_lock);
	(void) door_return((char *)&reply, sizeof (reply), NULL, 0);
}

/*
 * Reap containers that have not been recently used.
 */
static void *
reaper(void *ds_table_raw)
{
	dsvcd_datastore_t	**ds_table;
	unsigned int		i, nreaped;

	ds_table = (dsvcd_datastore_t **)ds_table_raw;
	for (;;) {
		(void) sleep(DSVCD_REAP_INTERVAL);
		for (i = 0; ds_table[i] != NULL; i++) {
			nreaped = ds_reap_containers(ds_table[i],
			    DSVCD_REAP_THRESH);
			if (nreaped > 0) {
				dhcpmsg(MSG_VERBOSE, "reaped %u container "
				    "synchpoints from %s", nreaped,
				    ds_table[i]->ds_name);
			}
		}
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Daemonize the process.
 */
static int
daemonize(void)
{
	switch (fork()) {

	case -1:
		return (0);

	case  0:
		/*
		 * Lose our controlling terminal, and become both a session
		 * leader and a process group leader.
		 */
		if (setsid() == -1)
			return (0);

		/*
		 * Under POSIX, a session leader can accidentally (through
		 * open(2)) acquire a controlling terminal if it does not
		 * have one.  Just to be safe, fork() again so we are not a
		 * session leader.
		 */
		switch (fork()) {

		case -1:
			return (0);

		case 0:
			(void) signal(SIGHUP, SIG_IGN);
			(void) chdir("/");
			(void) umask(022);
			closefrom(0);
			break;

		default:
			_exit(EXIT_SUCCESS);
		}
		break;

	default:
		_exit(EXIT_SUCCESS);
	}

	return (1);
}

/*
 * Create an unlock descriptor for container `cn' -- returns an unlock
 * descriptor on success, or NULL on failure; the reason for failure is in
 * `retvalp'.  Since creating door descriptors is expensive, we keep a few
 * cache a small list of old descriptors around on a reclaim list and only
 * allocate a new one if the list is empty.
 */
static dsvcd_unlock_desc_t *
ud_create(dsvcd_container_t *cn, int *retvalp)
{
	dsvcd_unlock_desc_t *ud;

	*retvalp = DSVC_SUCCESS;
	(void) mutex_lock(&ud_reclaim_lock);
	if (ud_reclaim_list != NULL) {
		ud = ud_reclaim_list;
		ud_reclaim_list = ud->ud_next;
		ud_reclaim_count--;
		(void) mutex_unlock(&ud_reclaim_lock);
	} else {
		(void) mutex_unlock(&ud_reclaim_lock);
		ud = malloc(sizeof (dsvcd_unlock_desc_t));
		if (ud == NULL) {
			dhcpmsg(MSG_WARNING, "cannot allocate unlock door "
			    "descriptor; denying %s lock request", cn->cn_id);
			*retvalp = DSVC_NO_MEMORY;
			return (NULL);
		}

		(void) mutex_init(&ud->ud_lock, USYNC_THREAD, NULL);
		ud->ud_fd = door_create((void (*)())svc_unlock, ud,
		    DOOR_UNREF_MULTI | DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
		if (ud->ud_fd == -1) {
			dhcpmsg(MSG_WARNING, "cannot create unlock door; "
			    "denying %s lock request", cn->cn_id);
			free(ud);
			*retvalp = DSVC_NO_RESOURCES;
			return (NULL);
		}
	}

	ud->ud_next = NULL;
	ud->ud_cn = cn;
	return (ud);
}

/*
 * Destroy the unlock descriptor `ud' -- `ud' must be unlocked on entry.
 * If there's room and `cacheable' is set, then, keep the unlock descriptor
 * on the reclaim list to lower future creation cost.
 */
static void
ud_destroy(dsvcd_unlock_desc_t *ud, boolean_t cacheable)
{
	assert(!MUTEX_HELD(&ud->ud_lock));

	ud->ud_cn = NULL;
	(void) mutex_lock(&ud_reclaim_lock);
	if (cacheable && ud_reclaim_count < UD_RECLAIM_MAX) {
		ud->ud_next = ud_reclaim_list;
		ud_reclaim_list = ud;
		ud_reclaim_count++;
		(void) mutex_unlock(&ud_reclaim_lock);
	} else {
		(void) mutex_unlock(&ud_reclaim_lock);
		(void) door_revoke(ud->ud_fd);
		(void) mutex_destroy(&ud->ud_lock);
		free(ud);
	}
}

/*
 * Create a stack of `*stacksizep' bytes (rounded up to the nearest page)
 * including a redzone for catching stack overflow.  Set `stacksizep' to
 * point to the actual usable size of the stack (i.e., everything but the
 * redzone).  Returns a pointer to the base of the stack (not including the
 * redzone).
 */
static void *
stack_create(unsigned int *stacksizep)
{
	caddr_t		stackbase;
	unsigned int	redzone = roundup(DSVCD_STACK_REDSIZE, PAGESIZE);
	unsigned int	stacksize = *stacksizep;

	if (stacksize < sysconf(_SC_THREAD_STACK_MIN))
		stacksize = sysconf(_SC_THREAD_STACK_MIN);

	stacksize = roundup(stacksize, PAGESIZE);
	stackbase = mmap(NULL, stacksize + redzone, PROT_READ | PROT_WRITE,
	    MAP_ANON | MAP_PRIVATE, -1, 0);
	if (stackbase == MAP_FAILED)
		return (NULL);

	*stacksizep = stacksize;
	(void) mprotect(stackbase, redzone, PROT_NONE);
	return (stackbase + redzone);
}

/*
 * Destroy the stack of `stacksize' bytes pointed to by `stackbase'.
 */
static void
stack_destroy(void *stackbase, unsigned int stacksize)
{
	unsigned int	redzone = roundup(DSVCD_STACK_REDSIZE, PAGESIZE);

	(void) munmap((caddr_t)stackbase - redzone, stacksize + redzone);
}

/*
 * Start function for door server threads; turns off thread cancellation
 * and then parks in the kernel via door_return().
 */
/* ARGSUSED */
static void *
doorserv_thread(void *arg)
{
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) door_return(NULL, 0, NULL, 0);
	return (NULL);
}

/*
 * Creation function for door server threads.  We require door threads to
 * have 32K of backed stack.  This is a guess but will be more than
 * sufficient for our uses, since door threads have a shallow call depth
 * and the functions use little automatic storage.
 */
/* ARGSUSED */
static void
doorserv_create(door_info_t *infop)
{
	void		*stackbase;
	unsigned int	stacksize = 32 * 1024;

	stackbase = stack_create(&stacksize);
	if (stackbase != NULL) {
		errno = thr_create(stackbase, stacksize, doorserv_thread, NULL,
		    THR_BOUND | THR_DETACHED, NULL);
		if (errno != 0) {
			dhcpmsg(MSG_ERR, "cannot create door server thread; "
			    "server thread pool will not be grown");
			stack_destroy(stackbase, stacksize);
		}
	}
}
