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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
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
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/nfs_prot.h>
#include <net/if.h>
#include <netdir.h>
#include <string.h>
#include <thread.h>
#include <locale.h>
#include "automount.h"
#include <sys/vfs.h>
#include <sys/mnttab.h>
#include <arpa/inet.h>
#include <rpc/svc.h>			/* for private dupcache routines */
#include <rpcsvc/daemon_utils.h>
#include <deflt.h>
#include <strings.h>


static void autofs_prog(struct svc_req *, SVCXPRT *);
static void autofs_mount_1_r(struct autofs_lookupargs *,
		struct autofs_mountres *, struct authunix_parms *);
static void autofs_mount_1_free_r(struct autofs_mountres *);
static void autofs_lookup_1_r(struct autofs_lookupargs *,
		struct autofs_lookupres *, struct authunix_parms *);
static void autofs_lookup_1_free_r(struct autofs_lookupres *);
static void autofs_unmount_1_r(struct umntrequest *, struct umntres *,
		struct authunix_parms *);
static void autofs_unmount_1_free_r(struct umntres *);
static void autofs_readdir_1_r(struct autofs_rddirargs *,
		struct autofs_rddirres *, struct authunix_parms *);
static void autofs_readdir_1_free_r(struct autofs_rddirres *);
static void usage();
static void warn_hup(int);
static void free_action_list();

static int dupreq_nonidemp(struct svc_req *, SVCXPRT *, int, bool_t (*)(),
		void (*)());
static int dupdonereq_nonidemp(struct svc_req *, caddr_t, bool_t (*)());
static int dupreq_idemp(struct svc_req *, SVCXPRT *, int, bool_t (*)(),
		void (*)());
static int dupdonereq_idemp(struct svc_req *, caddr_t, bool_t (*)());

#define	CTIME_BUF_LEN 26

/*
 * XXX - this limit was imposed due to resource problems - even though
 * we can and do try and set the rlimit to be able to handle more threads,
 * fopen() doesn't allow more than 256 fp's.
 */
#define	MAXTHREADS 64

#define	RESOURCE_FACTOR 8

static char str_arch[32];
static char str_cpu[32];

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
	int c, i, error;
	struct rlimit rlset;
	int rpc_svc_mode = RPC_SVC_MT_AUTO;
	int maxthreads = MAXTHREADS;
	int prevthreads = 0;
	char *defval;
	int defflags;

	if (geteuid() != 0) {
		(void) fprintf(stderr, "%s must be run as root\n", argv[0]);
		exit(1);
	}

	/*
	 * Read in the values from config file first before we check
	 * commandline options so the options override the file.
	 */
	if ((defopen(AUTOFSADMIN)) == 0) {
		if ((defval = defread("AUTOMOUNTD_VERBOSE=")) != NULL) {
			if (strncasecmp("true", defval, 4) == 0)
				verbose = TRUE;
			else
				verbose = FALSE;
		}
		if ((defval = defread("AUTOMOUNTD_NOBROWSE=")) != NULL) {
			if (strncasecmp("true", defval, 4) == 0)
				automountd_nobrowse = TRUE;
			else
				automountd_nobrowse = FALSE;
		}
		if ((defval = defread("AUTOMOUNTD_TRACE=")) != NULL) {
			errno = 0;
			trace = strtol(defval, (char **)NULL, 10);
			if (errno != 0)
				trace = 0;
		}
		if ((defval = defread("AUTOMOUNTD_ENV=")) != NULL) {
			(void) putenv(strdup(defval));
			defflags = defcntl(DC_GETFLAGS, 0);
			TURNON(defflags, DC_NOREWIND);
			defflags = defcntl(DC_SETFLAGS, defflags);
			while ((defval = defread("AUTOMOUNTD_ENV=")) != NULL)
				(void) putenv(strdup(defval));
			(void) defcntl(DC_SETFLAGS, defflags);
		}

		/* close defaults file */
		defopen(NULL);
	}

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
		fprintf(stderr,
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
	 * Since the "arch" command no longer exists we
	 * have to rely on sysinfo(SI_MACHINE) to return the closest
	 * approximation.  For backward compatibility we
	 * need to substitute "sun4" for "sun4m", "sun4c", ...
	 */
	if (getenv("ARCH") == NULL) {
		char buf[16];

		if (sysinfo(SI_MACHINE, buf, sizeof (buf)) != -1) {
			if (strncmp(buf, "sun4", 4) == 0)
				(void) strcpy(buf, "sun4");
			(void) sprintf(str_arch, "ARCH=%s", buf);
			(void) putenv(str_arch);
		} else {
			syslog(LOG_ERR,
				"can't determine machine type, error: %m");
		}
	}
	if (getenv("CPU") == NULL) {
		char buf[16];

		if (sysinfo(SI_ARCHITECTURE, buf, sizeof (buf)) != -1) {
			(void) sprintf(str_cpu, "CPU=%s", buf);
			(void) putenv(str_cpu);
		} else {
			syslog(LOG_ERR,
				"can't determine processor type, error: %m");
		}
	}

	(void) rwlock_init(&cache_lock, USYNC_THREAD, NULL);
	(void) rwlock_init(&rddir_cache_lock, USYNC_THREAD, NULL);

	/*
	 * initialize the name services, use NULL arguments to ensure
	 * we don't initialize the stack of files used in file service
	 */
	(void) ns_setup(NULL, NULL);

	/*
	 * set the maximum number of threads to be used. If it succeeds
	 * increase the number of resources the threads need. If the
	 * the resource allocation fails, return the threads value back
	 * to the default value
	 */
	if (((rpc_control(RPC_SVC_THRMAX_GET, &prevthreads)) == TRUE) &&
		((rpc_control(RPC_SVC_THRMAX_SET, &maxthreads)) == TRUE)) {
		rlset.rlim_max = RESOURCE_FACTOR * maxthreads;
		rlset.rlim_cur = RESOURCE_FACTOR * maxthreads;
		if ((setrlimit(RLIMIT_NOFILE, &rlset)) != 0) {
			syslog(LOG_ERR,
				"unable to increase system resource limit");

			/* back off changes to threads */
			if ((rpc_control(RPC_SVC_THRMAX_SET, &prevthreads))
				== FALSE) {
				/*
				 * Exit if we have more threads than resources.
				 */
				syslog(LOG_ERR,
				"unable to match threads to system resources");
				exit(1);
			}
			syslog(LOG_ERR,
				"decreased threads to match low resources");
		} else {
			/*
			 * Both are successful. Note that setrlimit
			 * allows a max setting of 1024
			 */
			if (trace > 3) {
				trace_prt(1,
				"  maxthreads: %d rlim_max: %d rlim_cur: %d\n",
				maxthreads, rlset.rlim_max, rlset.rlim_cur);
			}
			closefrom(3);
		}
	} else {
		syslog(LOG_ERR,
			"unable to increase threads - continue with default");
	}

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
		syslog(LOG_ERR, "error locking for %s: %s", AUTOMOUNTD,
		    strerror(errno));
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

	if (!rpc_control(RPC_SVC_MTMODE_SET, &rpc_svc_mode)) {
		syslog(LOG_ERR, "unable to set automatic MT mode");
		exit(1);
	}
	if (svc_create_local_service(autofs_prog,
		AUTOFS_PROG, AUTOFS_VERS, "netpath", "autofs") == 0) {
		syslog(LOG_ERR, "unable to create service");
		exit(1);
	}

	(void) signal(SIGHUP, warn_hup);

	svc_run();
	syslog(LOG_ERR, "svc_run returned");
	return (1);
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

/*
 * dupreq_nonidemp(struct svc_req *rqstp, SVCXPRT *transp, int res_sz,
 *		bool_t (*xdr_result)(), void (*local_free)())
 * check the status of nonidempotent requests in the duplicate request cache.
 * Get result of done requests and send a reply to the kernel. Return status.
 */
static int
dupreq_nonidemp(struct svc_req *rqstp, SVCXPRT *transp, int res_sz,
		bool_t (*xdr_result)(), void (*local_free)())
{
	caddr_t resp_buf;
	uint_t resp_bufsz;
	int dupstat;
	XDR xdrs;
	caddr_t res;

	dupstat = __svc_vc_dup(rqstp, &resp_buf, &resp_bufsz);
	switch (dupstat) {
	case DUP_NEW:
		break;
	case DUP_DONE:
		if (!resp_buf) {
			if (verbose) {
				syslog(LOG_ERR,
				"dupreq_nonidemp: done, no cached result");
			}
			break;
		}
		/* buffer contains xdr encoded results - decode and sendreply */
		if (verbose) {
			syslog(LOG_ERR,
			"dupreq_nonidemp: done, send reply to kernel");
		}

		memset((caddr_t)&xdrs, 0, sizeof (XDR));
		xdrmem_create(&xdrs, resp_buf, resp_bufsz, XDR_DECODE);

		if ((res = (caddr_t)malloc(res_sz)) == NULL) {
			syslog(LOG_ERR, "dupreq_nonidemp: out of memory");
			xdr_destroy(&xdrs);
			free(resp_buf);
			break;
		}
		memset(res, 0, res_sz);

		if ((*xdr_result)(&xdrs, res) == FALSE) {
			if (verbose)
				syslog(LOG_ERR,
				"dupreq_nonidemp: cannot xdr decode result");
			xdr_destroy(&xdrs);
			free(resp_buf);
			free(res);
			break;
		}

		if (!svc_sendreply(transp, xdr_result, (caddr_t)res)) {
			xdr_destroy(&xdrs);
			free(resp_buf);
			(void) (*local_free)(res);
			free(res);
			svcerr_systemerr(transp);
			return (DUP_ERROR);
		}
		xdr_destroy(&xdrs);
		free(resp_buf);
		(void) (*local_free)(res);
		free(res);
		break;

	/* all other cases log the case and drop the request */
	case DUP_INPROGRESS:
		if (verbose) {
			syslog(LOG_ERR,
			"dupreq_nonidemp: duplicate request in progress\n");
		}
		break;
	case DUP_DROP:	/* should never be called in automountd */
		if (verbose)
			syslog(LOG_ERR,
			"dupreq_nonidemp: dropped duplicate request error");
		break;
	case DUP_ERROR: /* fall through */
	default:
		if (verbose)
			syslog(LOG_ERR,
			"dupreq_nonidemp: duplicate request cache error");
		break;
	}
	return (dupstat);
}

/*
 * dupdonereq_nonidemp(struct svc_req *rqstp, caddr_t res,
 *		bool_t (*xdr_result)())
 * call the cache to indicate we are done with the nonidempotent request.
 * xdr_result will write the encoded xdr form of results into the buffer
 * provided in xdrmem_create. Makes a best effort to update the cache
 * first with a buffer containing the results, and then with a NULL buffer.
 * Return status.
 */
static int
dupdonereq_nonidemp(struct svc_req *rqstp, caddr_t res, bool_t (*xdr_result)())
{
	caddr_t resp_buf;
	ulong_t resp_bufsz;
	XDR xdrs;
	int dupstat;

	/*
	 * create a results buffer and write into the cache
	 * continue with a NULL buffer on errors.
	 */
	if ((resp_bufsz = xdr_sizeof(xdr_result, (void *)res)) == 0) {
		if (verbose)
			syslog(LOG_ERR, "dupdonereq_nonidemp: xdr error");
		resp_buf = NULL;
		resp_bufsz = 0;
	} else {
		if ((resp_buf = (caddr_t)malloc(resp_bufsz)) == NULL) {
			syslog(LOG_ERR, "dupdonereq_nonidemp: out of memory");
			resp_bufsz = 0;
		} else {
			memset(resp_buf, 0, resp_bufsz);
			memset((caddr_t)&xdrs, 0, sizeof (XDR));
			xdrmem_create(&xdrs, resp_buf, (uint_t)resp_bufsz,
					XDR_ENCODE);
			if ((*xdr_result)(&xdrs, res) == FALSE) {
				if (verbose)
					syslog(LOG_ERR,
					"cannot xdr encode results");
				xdr_destroy(&xdrs);
				free(resp_buf);
				resp_buf = NULL;
				resp_bufsz = 0;
			} else
				xdr_destroy(&xdrs);
		}
	}

	dupstat = __svc_vc_dupdone(rqstp, resp_buf, (uint_t)resp_bufsz,
				DUP_DONE);
	if (dupstat == DUP_ERROR) {
		if (verbose)
			syslog(LOG_ERR, "dupdonereq_nonidemp: cache error");
		if (resp_buf != NULL) {
			if (verbose)
				syslog(LOG_ERR, "dupdonereq_nonidemp: retry");
			dupstat = __svc_vc_dupdone(rqstp, NULL, 0, DUP_DONE);
			if ((dupstat == DUP_ERROR) && verbose)
				syslog(LOG_ERR,
				"dupdonereq_nonidemp: retry failed");
		}
	}
	if (resp_buf)
		free(resp_buf);
	return (dupstat);
}

/*
 * dupreq_idemp(struct svc_req *rqstp, SVCXPRT *transp, int res_sz;
 *		bool_t (*xdr_result)(), void (*local_free)())
 * check the status of idempotent requests in the duplicate request cache.
 * treat a idempotent request like a new one if its done, but do workavoids
 * if its a request in progress. Return status.
 */
static int
dupreq_idemp(struct svc_req *rqstp, SVCXPRT *transp, int res_sz,
		bool_t (*xdr_result)(), void (*local_free)())
{
	int dupstat;

#ifdef lint
	transp = transp;
	res_sz = res_sz;
	local_free = local_free;
	xdr_result = xdr_result;
#endif /* lint */

	/*
	 * call the cache to check the status of the request. don't care
	 * about results in the cache.
	 */
	dupstat = __svc_vc_dup(rqstp, NULL, NULL);
	switch (dupstat) {
	case DUP_NEW:
		break;
	case DUP_DONE:
		if (verbose)
			syslog(LOG_ERR, "dupreq_idemp: done request, redo");
		dupstat = DUP_NEW;
		break;

	/* all other cases log the case and drop the request */
	case DUP_INPROGRESS:
		if (verbose)
			syslog(LOG_ERR,
			"dupreq_idemp: duplicate request in progress\n");
		break;
	case DUP_DROP:	/* should never be called in automountd */
		if (verbose)
			syslog(LOG_ERR,
			"dupreq_idemp: dropped duplicate request error");
		break;
	case DUP_ERROR:	/* fall through */
	default:
		if (verbose)
			syslog(LOG_ERR,
			"dupreq_idemp: duplicate request cache error");
		break;
	}
	return (dupstat);
}

/*
 * dupdonereq_idemp(struct svc_req *rqstp, caddr_t res,	bool_t (*xdr_result)())
 * call the cache to indicate we are done with the idempotent request - we do
 * this to allow work avoids for in progress requests. don't bother to store
 * any results in the cache. Return status.
 */
static int
dupdonereq_idemp(struct svc_req *rqstp, caddr_t res, bool_t (*xdr_result)())
{
	int dupstat;

#ifdef lint
	res = res;
	xdr_result = xdr_result;
#endif /* lint */

	dupstat = __svc_vc_dupdone(rqstp, NULL, (uint_t)0, DUP_DONE);
	if ((dupstat == DUP_ERROR) && verbose)
		syslog(LOG_ERR, "dupdonereq_idemp: cannot cache result");
	return (dupstat);
}

/*
 * Returns the UID of the caller
 */
static uid_t
getowner(transp)
	SVCXPRT *transp;
{
	uid_t uid;

	if (__rpc_get_local_uid(transp, &uid) < 0) {
		char *err_msg = "Could not get local uid - request ignored\n";

		if (trace > 1)
			trace_prt(1, err_msg);
		if (verbose)
			pr_msg(err_msg);
		return (-1);
	}
	if (uid != 0) {
		char *err_msg =
			"Illegal access attempt by uid=%ld - request ignored\n";

		if (trace > 1)
			trace_prt(1, err_msg, uid);
		pr_msg(err_msg, uid);
	}
	return (uid);
}

/*
 * Each RPC request will automatically spawn a new thread with this
 * as its entry point.
 * XXX - the switch statement should be changed to a table of procedures
 * similar to that used by rfs_dispatch() in uts/common/fs/nfs/nfs_server.c.
 * duplicate request handling should also be synced with rfs_dispatch().
 */
static void
autofs_prog(rqstp, transp)
	struct svc_req *rqstp;
	register SVCXPRT *transp;
{
	union {
		autofs_lookupargs autofs_mount_1_arg;
		autofs_lookupargs autofs_lookup_1_arg;
		umntrequest autofs_umount_1_arg;
		autofs_rddirargs autofs_readdir_1_arg;
	} argument;

	union {
		autofs_mountres mount_res;
		autofs_lookupres lookup_res;
		umntres umount_res;
		autofs_rddirres readdir_res;
	} res;

	bool_t (*xdr_argument)();
	bool_t (*xdr_result)();
	void   (*local)();
	void   (*local_free)();
	int    (*dup_request)();
	int    (*dupdone_request)();

	timenow = time((time_t *)NULL);

	if (rqstp->rq_proc != NULLPROC && getowner(transp) != 0) {
		/*
		 * Drop request
		 */
		return;
	}

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void) svc_sendreply(transp, xdr_void, (char *)NULL);
		return;

#ifdef MALLOC_DEBUG
	case AUTOFS_DUMP_DEBUG:
		(void) svc_sendreply(transp, xdr_void, (char *)NULL);
		check_leaks("/var/tmp/automountd.leak");
		return;
#endif

	case AUTOFS_LOOKUP:
		xdr_argument = xdr_autofs_lookupargs;
		xdr_result = xdr_autofs_lookupres;
		local = autofs_lookup_1_r;
		local_free = autofs_lookup_1_free_r;
		dup_request = dupreq_nonidemp;
		dupdone_request = dupdonereq_nonidemp;
		break;

	case AUTOFS_MOUNT:
		xdr_argument = xdr_autofs_lookupargs;
		xdr_result = xdr_autofs_mountres;
		local = autofs_mount_1_r;
		local_free = autofs_mount_1_free_r;
		dup_request = dupreq_nonidemp;
		dupdone_request = dupdonereq_nonidemp;
		break;

	case AUTOFS_UNMOUNT:
		xdr_argument = xdr_umntrequest;
		xdr_result = xdr_umntres;
		local = autofs_unmount_1_r;
		local_free = autofs_unmount_1_free_r;
		dup_request = dupreq_nonidemp;
		dupdone_request = dupdonereq_nonidemp;
		break;

	case AUTOFS_READDIR:
		xdr_argument = xdr_autofs_rddirargs;
		xdr_result = xdr_autofs_rddirres;
		local = autofs_readdir_1_r;
		local_free = autofs_readdir_1_free_r;
		dup_request = dupreq_idemp;
		dupdone_request = dupdonereq_idemp;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}


	if ((*dup_request)(rqstp, transp, sizeof (res), xdr_result,
				local_free) != DUP_NEW)
		return;

	(void) memset((char *)&argument, 0, sizeof (argument));
	if (!svc_getargs(transp, xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		return;
	}

	(void) memset((char *)&res, 0, sizeof (res));
	(*local)(&argument, &res, rqstp->rq_clntcred);

	/* update cache with done request results */
	(void) (*dupdone_request)(rqstp, (caddr_t)&res, xdr_result);

	if (!svc_sendreply(transp, xdr_result, (caddr_t)&res)) {
		svcerr_systemerr(transp);
	}

	if (!svc_freeargs(transp, xdr_argument, (caddr_t)&argument)) {
		syslog(LOG_ERR, "unable to free arguments");
	}

	(*local_free)(&res);

}

static void
autofs_readdir_1_r(req, res, cred)
	struct autofs_rddirargs *req;
	struct autofs_rddirres *res;
	struct authunix_parms *cred;
{
	if (trace > 0)
		trace_prt(1, "READDIR REQUEST	: %s @ %ld\n",
		req->rda_map, req->rda_offset);

	(void) do_readdir(req, res, cred);

	if (trace > 0)
		trace_prt(1, "READDIR REPLY	: status=%d\n", res->rd_status);
}

static void
autofs_readdir_1_free_r(res)
	struct autofs_rddirres *res;
{
	if (res->rd_status == AUTOFS_OK) {
		if (res->rd_rddir.rddir_entries)
			free(res->rd_rddir.rddir_entries);
	}
}

/* ARGSUSED */
static void
autofs_unmount_1_r(m, res, cred)
	struct umntrequest *m;
	struct umntres *res;
	struct authunix_parms *cred;
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
autofs_unmount_1_free_r(res)
	struct umntres *res;
{
#ifdef lint
	res = res;
#endif /* lint */
}

static void
autofs_lookup_1_r(m, res, cred)
	struct autofs_lookupargs *m;
	struct autofs_lookupres *res;
	struct authunix_parms *cred;
{
	enum autofs_action action;
	struct linka link;
	int status;

	if (trace > 0) {
		char ctime_buf[CTIME_BUF_LEN];
		if (ctime_r(&timenow, ctime_buf, CTIME_BUF_LEN) == NULL)
			ctime_buf[0] = '\0';

		trace_prt(1, "LOOKUP REQUEST: %s", ctime_buf);
		trace_prt(1, "  name=%s[%s] map=%s opts=%s path=%s direct=%d\n",
			m->name, m->subdir, m->map, m->opts,
			m->path, m->isdirect);
	}

	status = do_lookup1(m->map, m->name, m->subdir, m->opts, m->path,
			(uint_t)m->isdirect, &action, &link, cred);
	if (status == 0) {
		/*
		 * Return action list to kernel.
		 */
		res->lu_res = AUTOFS_OK;
		if ((res->lu_type.action = action) == AUTOFS_LINK_RQ)
			res->lu_type.lookup_result_type_u.lt_linka = link;
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
autofs_lookup_1_free_r(res)
	struct autofs_lookupres *res;
{
	struct linka link;

	if ((res->lu_res == AUTOFS_OK) &&
	    (res->lu_type.action == AUTOFS_LINK_RQ)) {
		/*
		 * Free link information
		 */
		link = res->lu_type.lookup_result_type_u.lt_linka;
		if (link.dir)
			free(link.dir);
		if (link.link)
			free(link.link);
	}
}

static void
autofs_mount_1_r(m, res, cred)
	struct autofs_lookupargs *m;
	struct autofs_mountres *res;
	struct authunix_parms *cred;
{
	int status;
	action_list *alp = NULL;

	if (trace > 0) {
		char ctime_buf[CTIME_BUF_LEN];
		if (ctime_r(&timenow, ctime_buf, CTIME_BUF_LEN) == NULL)
			ctime_buf[0] = '\0';

		trace_prt(1, "MOUNT REQUEST:   %s", ctime_buf);
		trace_prt(1, "  name=%s[%s] map=%s opts=%s path=%s direct=%d\n",
			m->name, m->subdir, m->map, m->opts,
			m->path, m->isdirect);
	}

	status = do_mount1(m->map, m->name, m->subdir, m->opts, m->path,
			(uint_t)m->isdirect, &alp, cred);
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
	res->mr_verbose = verbose;

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
autofs_mount_1_free_r(res)
	struct autofs_mountres *res;
{
	if (res->mr_type.status == AUTOFS_ACTION) {
		if (trace > 2)
			trace_prt(1, "freeing action list\n");

		free_action_list(res->mr_type.mount_result_type_u.list);
	}
}

/*
 * Used for reporting messages from code
 * shared with automount command.
 * Formats message into a buffer and
 * calls syslog.
 *
 * Print an error.
 * Works like printf (fmt string and variable args)
 * except that it will subsititute an error message
 * for a "%m" string (like syslog).
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
		if (*p1 == '%' && *(p1+1) == 'm') {
			if (errno < sys_nerr) {
				(void) strcpy(p2, sys_errlist[errno]);
				p2 += strlen(p2);
			}
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
			free_autofs_args((autofs_args *)mp->dataptr);
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
