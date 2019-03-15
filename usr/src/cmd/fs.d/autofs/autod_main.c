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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <memory.h>
#include <stropts.h>
#include <netconfig.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/systeminfo.h>
#include <syslog.h>
#include <errno.h>
#include <sys/sockio.h>
#include <rpc/xdr.h>
#include <net/if.h>
#include <netdir.h>
#include <string.h>
#include <thread.h>
#include <locale.h>
#include <door.h>
#include <limits.h>
#include "automount.h"
#include <sys/vfs.h>
#include <sys/mnttab.h>
#include <arpa/inet.h>
#include <rpcsvc/daemon_utils.h>
#include <deflt.h>
#include <strings.h>
#include <priv.h>
#include <tsol/label.h>
#include <sys/utsname.h>
#include <sys/thread.h>
#include <nfs/rnode.h>
#include <nfs/nfs.h>
#include <wait.h>
#include <libshare.h>
#include <libscf.h>
#include "smfcfg.h"

static void autofs_doorfunc(void *, char *, size_t, door_desc_t *, uint_t);
static void autofs_setdoor(int);
static void autofs_mntinfo_1_r(autofs_lookupargs *, autofs_mountres *);
static void autofs_mount_1_free_r(struct autofs_mountres *);
static void autofs_lookup_1_r(autofs_lookupargs *, autofs_lookupres *);
static void autofs_lookup_1_free_args(autofs_lookupargs *);
static void autofs_unmount_1_r(umntrequest *, umntres *);
static void autofs_unmount_1_free_args(umntrequest *);
static void autofs_readdir_1_r(autofs_rddirargs *, autofs_rddirres *);
static void autofs_readdir_1_free_r(struct autofs_rddirres *);
static int decode_args(xdrproc_t, autofs_door_args_t *, caddr_t *, int);
static bool_t encode_res(xdrproc_t, autofs_door_res_t **, caddr_t, int *);
static void usage();
static void warn_hup(int);
static void free_action_list();
static int start_autofs_svcs();
static void automountd_wait_for_cleanup(pid_t);

/*
 * Private autofs system call
 */
extern int _autofssys(int, void *);

#define	CTIME_BUF_LEN 26

#define	RESOURCE_FACTOR 8
#ifdef DEBUG
#define	AUTOFS_DOOR	"/var/run/autofs_door"
#endif /* DEBUG */

static thread_key_t	s_thr_key;

struct autodir *dir_head;
struct autodir *dir_tail;
char self[64];

time_t timenow;
int verbose = 0;
int trace = 0;
int automountd_nobrowse = 0;

int
main(argc, argv)
	int argc;
	char *argv[];

{
	pid_t pid;
	int c, error;
	struct rlimit rlset;
	char defval[6];
	int ret = 0, bufsz;

	if (geteuid() != 0) {
		(void) fprintf(stderr, "%s must be run as root\n", argv[0]);
		exit(1);
	}

	/*
	 * Read in the values from SMF first before we check
	 * commandline options so the options override the file.
	 */
	bufsz = 6;
	ret = autofs_smf_get_prop("automountd_verbose", defval,
	    DEFAULT_INSTANCE, SCF_TYPE_BOOLEAN, AUTOMOUNTD, &bufsz);
	if (ret == SA_OK) {
		if (strncasecmp("true", defval, 4) == 0)
			verbose = TRUE;
		else
			verbose = FALSE;
	}
	bufsz = 6;
	ret = autofs_smf_get_prop("nobrowse", defval, DEFAULT_INSTANCE,
	    SCF_TYPE_BOOLEAN, AUTOMOUNTD, &bufsz);
	if (ret == SA_OK) {
		if (strncasecmp("true", defval, 4) == 0)
			automountd_nobrowse = TRUE;
		else
			automountd_nobrowse = FALSE;
	}
	bufsz = 6;
	ret = autofs_smf_get_prop("trace", defval, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, AUTOMOUNTD, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		trace = strtol(defval, (char **)NULL, 10);
		if (errno != 0)
			trace = 0;
	}
	put_automountd_env();

	while ((c = getopt(argc, argv, "vnTD:")) != EOF) {
		switch (c) {
		case 'v':
			verbose++;
			break;
		case 'n':
			automountd_nobrowse++;
			break;
		case 'T':
			trace++;
			break;
		case 'D':
			(void) putenv(optarg);
			break;
		default:
			usage();
		}
	}

	if (sysinfo(SI_HOSTNAME, self, sizeof (self)) == -1) {
		error = errno;
		(void) fprintf(stderr,
			"automountd: can't determine hostname, error: %d\n",
			error);
		exit(1);
	}

#ifndef DEBUG
	pid = fork();
	if (pid < 0) {
		perror("cannot fork");
		exit(1);
	}
	if (pid)
		exit(0);
#endif

	(void) setsid();
	openlog("automountd", LOG_PID, LOG_DAEMON);
	(void) setlocale(LC_ALL, "");

	/*
	 * Create the door_servers to manage fork/exec requests for
	 * mounts and executable automount maps
	 */
	if ((did_fork_exec = door_create(automountd_do_fork_exec,
	    NULL, 0)) == -1) {
		syslog(LOG_ERR, "door_create failed: %m, Exiting.");
		exit(errno);
	}
	if ((did_exec_map = door_create(automountd_do_exec_map,
	    NULL, 0)) == -1) {
		syslog(LOG_ERR, "door_create failed: %m, Exiting.");
		if (door_revoke(did_fork_exec) == -1) {
			syslog(LOG_ERR, "failed to door_revoke(%d) %m",
			    did_fork_exec);
		}
		exit(errno);
	}
	/*
	 * Before we become multithreaded we fork allowing the parent
	 * to become a door server to handle all mount and unmount
	 * requests. This works around a potential hang in using
	 * fork1() within a multithreaded environment
	 */

	pid = fork1();
	if (pid < 0) {
		syslog(LOG_ERR,
			"can't fork the automountd mount process %m");
		if (door_revoke(did_fork_exec) == -1) {
			syslog(LOG_ERR, "failed to door_revoke(%d) %m",
				did_fork_exec);
		}
		if (door_revoke(did_exec_map) == -1) {
			syslog(LOG_ERR, "failed to door_revoke(%d) %m",
				did_exec_map);
		}
		exit(1);
	} else if (pid > 0) {
		/* this is the door server process */
		automountd_wait_for_cleanup(pid);
	}


	(void) rwlock_init(&cache_lock, USYNC_THREAD, NULL);
	(void) rwlock_init(&autofs_rddir_cache_lock, USYNC_THREAD, NULL);

	/*
	 * initialize the name services, use NULL arguments to ensure
	 * we don't initialize the stack of files used in file service
	 */
	(void) ns_setup(NULL, NULL);

	/*
	 * we're using doors and its thread management now so we need to
	 * make sure we have more than the default of 256 file descriptors
	 * available.
	 */
	rlset.rlim_cur = RLIM_INFINITY;
	rlset.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rlset) == -1)
		syslog(LOG_ERR, "setrlimit failed for %s: %s", AUTOMOUNTD,
		    strerror(errno));

	(void) enable_extended_FILE_stdio(-1, -1);

	/*
	 * establish our lock on the lock file and write our pid to it.
	 * exit if some other process holds the lock, or if there's any
	 * error in writing/locking the file.
	 */
	pid = _enter_daemon_lock(AUTOMOUNTD);
	switch (pid) {
	case 0:
		break;
	case -1:
		syslog(LOG_ERR, "error locking for %s: %m", AUTOMOUNTD);
		exit(2);
	default:
		/* daemon was already running */
		exit(0);
	}

	/*
	 * If we coredump it'll be /core.
	 */
	if (chdir("/") < 0)
		syslog(LOG_ERR, "chdir /: %m");

	/*
	 * Create cache_cleanup thread
	 */
	if (thr_create(NULL, 0, (void *(*)(void *))cache_cleanup, NULL,
			THR_DETACHED | THR_DAEMON | THR_NEW_LWP, NULL)) {
		syslog(LOG_ERR, "unable to create cache_cleanup thread");
		exit(1);
	}

	/* other initializations */
	(void) rwlock_init(&portmap_cache_lock, USYNC_THREAD, NULL);

	/*
	 * On a labeled system, allow read-down nfs mounts if privileged
	 * (PRIV_NET_MAC_AWARE) to do so.  Otherwise, ignore the error
	 * and "mount equal label only" behavior will result.
	 */
	if (is_system_labeled()) {
		(void) setpflags(NET_MAC_AWARE, 1);
		(void) setpflags(NET_MAC_AWARE_INHERIT, 1);
	}

	(void) signal(SIGHUP, warn_hup);

	/* start services */
	return (start_autofs_svcs());

}

/*
 * The old automounter supported a SIGHUP
 * to allow it to resynchronize internal
 * state with the /etc/mnttab.
 * This is no longer relevant, but we
 * need to catch the signal and warn
 * the user.
 */
/* ARGSUSED */
static void
warn_hup(i)
	int i;
{
	syslog(LOG_ERR, "SIGHUP received: ignored");
	(void) signal(SIGHUP, warn_hup);
}

static void
usage()
{
	(void) fprintf(stderr, "Usage: automountd\n"
	    "\t[-T]\t\t(trace requests)\n"
	    "\t[-v]\t\t(verbose error msgs)\n"
	    "\t[-D n=s]\t(define env variable)\n");
	exit(1);
	/* NOTREACHED */
}

static void
autofs_readdir_1_r(
	autofs_rddirargs *req,
	autofs_rddirres *res)
{
	if (trace > 0)
		trace_prt(1, "READDIR REQUEST	: %s @ %ld\n",
		    req->rda_map, req->rda_offset);

	do_readdir(req, res);
	if (trace > 0)
		trace_prt(1, "READDIR REPLY	: status=%d\n", res->rd_status);
}

static void
autofs_readdir_1_free_r(struct autofs_rddirres *res)
{
	if (res->rd_status == AUTOFS_OK) {
		if (res->rd_rddir.rddir_entries)
			free(res->rd_rddir.rddir_entries);
	}
}


/* ARGSUSED */
static void
autofs_unmount_1_r(
	umntrequest *m,
	umntres *res)
{
	struct umntrequest *ul;

	if (trace > 0) {
		char ctime_buf[CTIME_BUF_LEN];
		if (ctime_r(&timenow, ctime_buf, CTIME_BUF_LEN) == NULL)
			ctime_buf[0] = '\0';

		trace_prt(1, "UNMOUNT REQUEST: %s", ctime_buf);
		for (ul = m; ul; ul = ul->next)
			trace_prt(1, " resource=%s fstype=%s mntpnt=%s"
			    " mntopts=%s %s\n",
			    ul->mntresource,
			    ul->fstype,
			    ul->mntpnt,
			    ul->mntopts,
			    ul->isdirect ? "direct" : "indirect");
	}


	res->status = do_unmount1(m);

	if (trace > 0)
		trace_prt(1, "UNMOUNT REPLY: status=%d\n", res->status);
}

static void
autofs_lookup_1_r(
	autofs_lookupargs *m,
	autofs_lookupres *res)
{
	autofs_action_t action;
	struct	linka link;
	int status;

	if (trace > 0) {
		char ctime_buf[CTIME_BUF_LEN];
		if (ctime_r(&timenow, ctime_buf, CTIME_BUF_LEN) == NULL)
			ctime_buf[0] = '\0';

		trace_prt(1, "LOOKUP REQUEST: %s", ctime_buf);
		trace_prt(1, "  name=%s[%s] map=%s opts=%s path=%s direct=%d\n",
		    m->name, m->subdir, m->map, m->opts, m->path, m->isdirect);
	}

	bzero(&link, sizeof (struct linka));

	status = do_lookup1(m->map, m->name, m->subdir, m->opts, m->path,
	    (uint_t)m->isdirect, m->uid, &action, &link);
	if (status == 0) {
		/*
		 * Return action list to kernel.
		 */
		res->lu_res = AUTOFS_OK;
		if ((res->lu_type.action = action) == AUTOFS_LINK_RQ) {
			res->lu_type.lookup_result_type_u.lt_linka = link;
		}
	} else {
		/*
		 * Entry not found
		 */
		res->lu_res = AUTOFS_NOENT;
	}
	res->lu_verbose = verbose;

	if (trace > 0)
		trace_prt(1, "LOOKUP REPLY    : status=%d\n", res->lu_res);
}

static void
autofs_mntinfo_1_r(
	autofs_lookupargs *m,
	autofs_mountres *res)
{
	int status;
	action_list		*alp = NULL;

	if (trace > 0) {
		char ctime_buf[CTIME_BUF_LEN];
		if (ctime_r(&timenow, ctime_buf, CTIME_BUF_LEN) == NULL)
			ctime_buf[0] = '\0';

		trace_prt(1, "MOUNT REQUEST:   %s", ctime_buf);
		trace_prt(1, "  name=%s[%s] map=%s opts=%s path=%s direct=%d\n",
		    m->name, m->subdir, m->map, m->opts, m->path, m->isdirect);
	}

	status = do_mount1(m->map, m->name, m->subdir, m->opts, m->path,
	    (uint_t)m->isdirect, m->uid, &alp, DOMOUNT_USER);
	if (status != 0) {
		/*
		 * An error occurred, free action list if allocated.
		 */
		if (alp != NULL) {
			free_action_list(alp);
			alp = NULL;
		}
	}
	if (alp != NULL) {
		/*
		 * Return action list to kernel.
		 */
		res->mr_type.status = AUTOFS_ACTION;
		res->mr_type.mount_result_type_u.list = alp;
	} else {
		/*
		 * No work to do left for the kernel
		 */
		res->mr_type.status = AUTOFS_DONE;
		res->mr_type.mount_result_type_u.error = status;
	}

	if (trace > 0) {
		switch (res->mr_type.status) {
		case AUTOFS_ACTION:
			trace_prt(1,
			    "MOUNT REPLY    : status=%d, AUTOFS_ACTION\n",
			    status);
			break;
		case AUTOFS_DONE:
			trace_prt(1,
			    "MOUNT REPLY    : status=%d, AUTOFS_DONE\n",
			    status);
			break;
		default:
			trace_prt(1, "MOUNT REPLY    : status=%d, UNKNOWN\n",
			    status);
		}
	}

	if (status && verbose) {
		if (m->isdirect) {
			/* direct mount */
			syslog(LOG_ERR, "mount of %s failed", m->path);
		} else {
			/* indirect mount */
			syslog(LOG_ERR,
			    "mount of %s/%s failed", m->path, m->name);
		}
	}
}

static void
autofs_mount_1_free_r(struct autofs_mountres *res)
{
	if (res->mr_type.status == AUTOFS_ACTION) {
		if (trace > 2)
			trace_prt(1, "freeing action list\n");
		free_action_list(res->mr_type.mount_result_type_u.list);
	}
}

/*
 * Used for reporting messages from code shared with automount command.
 * Formats message into a buffer and calls syslog.
 *
 * Print an error.  Works like printf (fmt string and variable args)
 * except that it will subsititute an error message for a "%m" string
 * (like syslog).
 */
void
pr_msg(const char *fmt, ...)
{
	va_list ap;
	char fmtbuff[BUFSIZ], buff[BUFSIZ];
	const char *p1;
	char *p2;

	p2 = fmtbuff;
	fmt = gettext(fmt);

	for (p1 = fmt; *p1; p1++) {
		if (*p1 == '%' && *(p1 + 1) == 'm') {
			(void) strcpy(p2, strerror(errno));
			p2 += strlen(p2);
			p1++;
		} else {
			*p2++ = *p1;
		}
	}
	if (p2 > fmtbuff && *(p2-1) != '\n')
		*p2++ = '\n';
	*p2 = '\0';

	va_start(ap, fmt);
	(void) vsprintf(buff, fmtbuff, ap);
	va_end(ap);
	syslog(LOG_ERR, buff);
}

static void
free_action_list(action_list *alp)
{
	action_list *p, *next = NULL;
	struct mounta *mp;

	for (p = alp; p != NULL; p = next) {
		switch (p->action.action) {
		case AUTOFS_MOUNT_RQ:
			mp = &(p->action.action_list_entry_u.mounta);
			/* LINTED pointer alignment */
			if (mp->fstype) {
				if (strcmp(mp->fstype, "autofs") == 0) {
					free_autofs_args((autofs_args *)
					    mp->dataptr);
				} else if (strncmp(mp->fstype, "nfs", 3) == 0) {
					free_nfs_args((struct nfs_args *)
					    mp->dataptr);
				}
			}
			mp->dataptr = NULL;
			mp->datalen = 0;
			free_mounta(mp);
			break;
		case AUTOFS_LINK_RQ:
			syslog(LOG_ERR,
			    "non AUTOFS_MOUNT_RQ requests not implemented\n");
			break;
		default:
			syslog(LOG_ERR,
			    "non AUTOFS_MOUNT_RQ requests not implemented\n");
			break;
		}
		next = p->next;
		free(p);
	}
}

static void
autofs_lookup_1_free_args(autofs_lookupargs *args)
{
	if (args->map)
		free(args->map);
	if (args->path)
		free(args->path);
	if (args->name)
		free(args->name);
	if (args->subdir)
		free(args->subdir);
	if (args->opts)
		free(args->opts);
}

static void
autofs_unmount_1_free_args(umntrequest *args)
{
	if (args->mntresource)
		free(args->mntresource);
	if (args->mntpnt)
		free(args->mntpnt);
	if (args->fstype)
		free(args->fstype);
	if (args->mntopts)
		free(args->mntopts);
	if (args->next)
		autofs_unmount_1_free_args(args->next);
}

static void
autofs_setdoor(int did)
{

	if (did < 0) {
		did = 0;
	}

	(void) _autofssys(AUTOFS_SETDOOR, &did);
}

void *
autofs_get_buffer(size_t size)
{
	autofs_tsd_t *tsd = NULL;

	/*
	 * Make sure the buffer size is aligned
	 */
	(void) thr_getspecific(s_thr_key, (void **)&tsd);
	if (tsd == NULL) {
		tsd = (autofs_tsd_t *)malloc(sizeof (autofs_tsd_t));
		if (tsd == NULL) {
			return (NULL);
		}
		tsd->atsd_buf = malloc(size);
		if (tsd->atsd_buf != NULL)
			tsd->atsd_len = size;
		else
			tsd->atsd_len = 0;
		(void) thr_setspecific(s_thr_key, tsd);
	} else {
		if (tsd->atsd_buf && (tsd->atsd_len < size)) {
			free(tsd->atsd_buf);
			tsd->atsd_buf = malloc(size);
			if (tsd->atsd_buf != NULL)
				tsd->atsd_len = size;
			else {
				tsd->atsd_len = 0;
			}
		}
	}
	if (tsd->atsd_buf) {
		bzero(tsd->atsd_buf, size);
		return (tsd->atsd_buf);
	} else {
		syslog(LOG_ERR,
		    gettext("Can't Allocate tsd buffer, size %d"), size);
		return (NULL);
	}
}

/*
 * Each request will automatically spawn a new thread with this
 * as its entry point.
 */
/* ARGUSED */
static void
autofs_doorfunc(
	void *cookie,
	char *argp,
	size_t arg_size,
	door_desc_t *dp,
	uint_t n_desc)
{
	char			*res;
	int			 res_size;
	int			 which;
	int			 error = 0;
	int			 srsz = 0;
	autofs_lookupargs	*xdrargs;
	autofs_lookupres	 lookup_res;
	autofs_rddirargs	*rddir_args;
	autofs_rddirres		 rddir_res;
	autofs_mountres		 mount_res;
	umntrequest		*umnt_args;
	umntres			 umount_res;
	autofs_door_res_t	*door_res;
	autofs_door_res_t	 failed_res;

	if (arg_size < sizeof (autofs_door_args_t)) {
		failed_res.res_status = EINVAL;
		error = door_return((char *)&failed_res,
		    sizeof (autofs_door_res_t), NULL, 0);
		/*
		 * If we got here the door_return() failed.
		 */
		syslog(LOG_ERR, "Bad argument, door_return failure %d", error);
		return;
	}

	timenow = time((time_t *)NULL);

	which = ((autofs_door_args_t *)argp)->cmd;
	switch (which) {
	case AUTOFS_LOOKUP:
		if (error = decode_args(xdr_autofs_lookupargs,
		    (autofs_door_args_t *)argp, (caddr_t *)&xdrargs,
		    sizeof (autofs_lookupargs))) {
			syslog(LOG_ERR,
			    "error allocating lookup arguments buffer");
			failed_res.res_status = error;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
			res_size = 0;
			break;
		}
		bzero(&lookup_res, sizeof (autofs_lookupres));

		autofs_lookup_1_r(xdrargs, &lookup_res);

		autofs_lookup_1_free_args(xdrargs);
		free(xdrargs);

		if (!encode_res(xdr_autofs_lookupres, &door_res,
		    (caddr_t)&lookup_res, &res_size)) {
			syslog(LOG_ERR,
			    "error allocating lookup results buffer");
			failed_res.res_status = EINVAL;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
		} else {
			door_res->res_status = 0;
			res = (caddr_t)door_res;
		}
		break;

	case AUTOFS_MNTINFO:
		if (error = decode_args(xdr_autofs_lookupargs,
		    (autofs_door_args_t *)argp, (caddr_t *)&xdrargs,
		    sizeof (autofs_lookupargs))) {
			syslog(LOG_ERR,
			    "error allocating lookup arguments buffer");
			failed_res.res_status = error;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
			res_size = 0;
			break;
		}

		autofs_mntinfo_1_r((autofs_lookupargs *)xdrargs, &mount_res);

		autofs_lookup_1_free_args(xdrargs);
		free(xdrargs);

		/*
		 * Only reason we would get a NULL res is because
		 * we could not allocate a results buffer.  Use
		 * a local one to return the error EAGAIN as has
		 * always been done when memory allocations fail.
		 */
		if (!encode_res(xdr_autofs_mountres, &door_res,
		    (caddr_t)&mount_res, &res_size)) {
			syslog(LOG_ERR,
			    "error allocating mount results buffer");
			failed_res.res_status = EAGAIN;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
		} else {
			door_res->res_status = 0;
			res = (caddr_t)door_res;
		}
		autofs_mount_1_free_r(&mount_res);
		break;

	case AUTOFS_UNMOUNT:
		if (error = decode_args(xdr_umntrequest,
		    (autofs_door_args_t *)argp,
		    (caddr_t *)&umnt_args, sizeof (umntrequest))) {
			syslog(LOG_ERR,
			    "error allocating unmount argument buffer");
			failed_res.res_status = error;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
			res_size = sizeof (autofs_door_res_t);
			break;
		}

		autofs_unmount_1_r(umnt_args, &umount_res);

		error = umount_res.status;

		autofs_unmount_1_free_args(umnt_args);
		free(umnt_args);

		if (!encode_res(xdr_umntres, &door_res, (caddr_t)&umount_res,
		    &res_size)) {
			syslog(LOG_ERR,
			    "error allocating unmount results buffer");
			failed_res.res_status = EINVAL;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
			res_size = sizeof (autofs_door_res_t);
		} else {
			door_res->res_status = 0;
			res = (caddr_t)door_res;
		}
		break;

	case AUTOFS_READDIR:
		if (error = decode_args(xdr_autofs_rddirargs,
		    (autofs_door_args_t *)argp,
		    (caddr_t *)&rddir_args,
		    sizeof (autofs_rddirargs))) {
			syslog(LOG_ERR,
			    "error allocating readdir argument buffer");
			failed_res.res_status = error;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
			res_size = sizeof (autofs_door_res_t);
			break;
		}

		autofs_readdir_1_r(rddir_args, &rddir_res);

		free(rddir_args->rda_map);
		free(rddir_args);

		if (!encode_res(xdr_autofs_rddirres, &door_res,
		    (caddr_t)&rddir_res, &res_size)) {
			syslog(LOG_ERR,
			    "error allocating readdir results buffer");
			failed_res.res_status = ENOMEM;
			failed_res.xdr_len = 0;
			res = (caddr_t)&failed_res;
			res_size = sizeof (autofs_door_res_t);
		} else {
			door_res->res_status = 0;
			res = (caddr_t)door_res;
		}
		autofs_readdir_1_free_r(&rddir_res);
		break;
#ifdef MALLOC_DEBUG
	case AUTOFS_DUMP_DEBUG:
			check_leaks("/var/tmp/automountd.leak");
			error = door_return(NULL, 0, NULL, 0);
			/*
			 * If we got here, door_return() failed
			 */
			syslog(LOG_ERR, "dump debug door_return failure %d",
			    error);
			return;
#endif
	case NULLPROC:
			res = NULL;
			res_size = 0;
			break;
	default:
			failed_res.res_status = EINVAL;
			res = (char *)&failed_res;
			res_size = sizeof (autofs_door_res_t);
			break;
	}

	srsz = res_size;
	errno = 0;
	error = door_return(res, res_size, NULL, 0);

	if (errno == E2BIG) {
		/*
		 * Failed due to encoded results being bigger than the
		 * kernel expected bufsize. Passing actual results size
		 * back down to kernel.
		 */
		failed_res.res_status = EOVERFLOW;
		failed_res.xdr_len = srsz;
		res = (caddr_t)&failed_res;
		res_size = sizeof (autofs_door_res_t);
	} else {
		syslog(LOG_ERR, "door_return failed %d, buffer %p, "
		    "buffer size %d", error, (void *)res, res_size);
		res = NULL;
		res_size = 0;
	}
	(void) door_return(res, res_size, NULL, 0);
	/* NOTREACHED */
}

static int
start_autofs_svcs(void)
{
	int doorfd;
#ifdef DEBUG
	int dfd;
#endif

	if ((doorfd = door_create(autofs_doorfunc, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1) {
		syslog(LOG_ERR, gettext("Unable to create door\n"));
		return (1);
	}

#ifdef DEBUG
	/*
	 * Create a file system path for the door
	 */
	if ((dfd = open(AUTOFS_DOOR, O_RDWR|O_CREAT|O_TRUNC,
	    S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)) == -1) {
		syslog(LOG_ERR, "Unable to open %s: %m\n", AUTOFS_DOOR);
		(void) close(doorfd);
		return (1);
	}

	/*
	 * stale associations clean up
	 */
	(void) fdetach(AUTOFS_DOOR);

	/*
	 * Register in the namespace to the kernel to door_ki_open.
	 */
	if (fattach(doorfd, AUTOFS_DOOR) == -1) {
		syslog(LOG_ERR, "Unable to fattach door %m\n", AUTOFS_DOOR);
		(void) close(dfd);
		(void) close(doorfd);
		return (1);
	}
#endif /* DEBUG */

	/*
	 * Pass door name to kernel for door_ki_open
	 */
	autofs_setdoor(doorfd);

	(void) thr_keycreate(&s_thr_key, NULL);

	/*
	 * Wait for incoming calls
	 */
	/*CONSTCOND*/
	while (1)
		(void) pause();

	/* NOTREACHED */
	syslog(LOG_ERR, gettext("Door server exited"));
	return (10);
}

static int
decode_args(
	xdrproc_t xdrfunc,
	autofs_door_args_t *argp,
	caddr_t *xdrargs,
	int size)
{
	XDR xdrs;

	caddr_t tmpargs = (caddr_t)&((autofs_door_args_t *)argp)->xdr_arg;
	size_t arg_size = ((autofs_door_args_t *)argp)->xdr_len;

	xdrmem_create(&xdrs, tmpargs, arg_size, XDR_DECODE);

	*xdrargs = malloc(size);
	if (*xdrargs == NULL) {
		syslog(LOG_ERR, "error allocating arguments buffer");
		return (ENOMEM);
	}

	bzero(*xdrargs, size);

	if (!(*xdrfunc)(&xdrs, *xdrargs)) {
		free(*xdrargs);
		*xdrargs = NULL;
		syslog(LOG_ERR, "error decoding arguments");
		return (EINVAL);
	}

	return (0);
}


static bool_t
encode_res(
	xdrproc_t xdrfunc,
	autofs_door_res_t **results,
	caddr_t resp,
	int *size)
{
	XDR xdrs;

	*size = xdr_sizeof((*xdrfunc), resp);
	*results = autofs_get_buffer(
	    sizeof (autofs_door_res_t) + *size);
	if (*results == NULL) {
		(*results)->res_status = ENOMEM;
		return (FALSE);
	}
	(*results)->xdr_len = *size;
	*size = sizeof (autofs_door_res_t) + (*results)->xdr_len;
	xdrmem_create(&xdrs, (caddr_t)((*results)->xdr_res),
	    (*results)->xdr_len, XDR_ENCODE);
	if (!(*xdrfunc)(&xdrs, resp)) {
		(*results)->res_status = EINVAL;
		syslog(LOG_ERR, "error encoding results");
		return (FALSE);
	}
	(*results)->res_status = 0;
	return (TRUE);
}

static void
automountd_wait_for_cleanup(pid_t pid)
{
	int status;
	int child_exitval;

	/*
	 * Wait for the main automountd process to exit so we cleanup
	 */
	(void) waitpid(pid, &status, 0);

	child_exitval = WEXITSTATUS(status);

	/*
	 * Shutdown the door server for mounting and unmounting
	 * filesystems
	 */
	if (door_revoke(did_fork_exec) == -1) {
		syslog(LOG_ERR, "failed to door_revoke(%d) %m", did_fork_exec);
	}
	if (door_revoke(did_exec_map) == -1) {
		syslog(LOG_ERR, "failed to door_revoke(%d) %m", did_exec_map);
	}
	exit(child_exitval);
}
