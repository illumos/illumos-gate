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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * nfs mount
 */

#define	NFSCLIENT
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <memory.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/param.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <nfs/nfs.h>
#include <nfs/mount.h>
#include <rpcsvc/mount.h>
#include <sys/pathconf.h>
#include <netdir.h>
#include <netconfig.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <syslog.h>
#include <fslib.h>
#include <deflt.h>
#include <sys/wait.h>
#include "replica.h"
#include <netinet/in.h>
#include <nfs/nfs_sec.h>
#include <rpcsvc/daemon_utils.h>
#include <priv.h>
#include <tsol/label.h>
#include "nfs_subr.h"
#include "webnfs.h"
#include <rpcsvc/nfs4_prot.h>
#include <limits.h>
#include <libscf.h>
#include <libshare.h>
#include "smfcfg.h"

#include <nfs/nfssys.h>
extern int _nfssys(enum nfssys_op, void *);

#ifndef	NFS_VERSMAX
#define	NFS_VERSMAX	4
#endif
#ifndef	NFS_VERSMIN
#define	NFS_VERSMIN	2
#endif

#define	RET_OK		0
#define	RET_RETRY	32
#define	RET_ERR		33
#define	RET_MNTERR	1000
#define	ERR_PROTO_NONE		0
#define	ERR_PROTO_INVALID	901
#define	ERR_PROTO_UNSUPP	902
#define	ERR_NETPATH		903
#define	ERR_NOHOST		904
#define	ERR_RPCERROR		905

typedef struct err_ret {
	int error_type;
	int error_value;
} err_ret_t;

#define	SET_ERR_RET(errst, etype, eval) \
	if (errst) { \
		(errst)->error_type = etype; \
		(errst)->error_value = eval; \
	}

/* number of transports to try */
#define	MNT_PREF_LISTLEN	2
#define	FIRST_TRY		1
#define	SECOND_TRY		2

#define	BIGRETRY	10000

/* maximum length of RPC header for NFS messages */
#define	NFS_RPC_HDR	432

#define	NFS_ARGS_EXTB_secdata(args, secdata) \
	{ (args)->nfs_args_ext = NFS_ARGS_EXTB, \
	(args)->nfs_ext_u.nfs_extB.secdata = secdata; }

extern int __clnt_bindresvport(CLIENT *);
extern char *nfs_get_qop_name();
extern AUTH * nfs_create_ah();
extern enum snego_stat nfs_sec_nego();

static void usage(void);
static int retry(struct mnttab *, int);
static int set_args(int *, struct nfs_args *, char *, struct mnttab *);
static int get_fh_via_pub(struct nfs_args *, char *, char *, bool_t, bool_t,
	int *, struct netconfig **, ushort_t);
static int get_fh(struct nfs_args *, char *, char *, int *, bool_t,
	struct netconfig **, ushort_t);
static int make_secure(struct nfs_args *, char *, struct netconfig *,
	bool_t, rpcvers_t);
static int mount_nfs(struct mnttab *, int, err_ret_t *);
static int getaddr_nfs(struct nfs_args *, char *, struct netconfig **,
		    bool_t, char *, ushort_t, err_ret_t *, bool_t);
static void pr_err(const char *fmt, ...);
static void usage(void);
static struct netbuf *get_addr(char *, rpcprog_t, rpcvers_t,
	struct netconfig **, char *, ushort_t, struct t_info *,
	caddr_t *, bool_t, char *, err_ret_t *);

static struct netbuf *get_the_addr(char *, rpcprog_t, rpcvers_t,
	struct netconfig *, ushort_t, struct t_info *, caddr_t *,
	bool_t, char *, err_ret_t *);

extern int self_check(char *);

static void read_default(void);

static char typename[64];

static int bg = 0;
static int backgrounded = 0;
static int posix = 0;
static int retries = BIGRETRY;
static ushort_t nfs_port = 0;
static char *nfs_proto = NULL;

static int mflg = 0;
static int Oflg = 0;	/* Overlay mounts */
static int qflg = 0;	/* quiet - don't print warnings on bad options */

static char *fstype = MNTTYPE_NFS;

static seconfig_t nfs_sec;
static int sec_opt = 0;	/* any security option ? */
static bool_t snego_done;
static void sigusr1(int);

extern void set_nfsv4_ephemeral_mount_to(void);

/*
 * list of support services needed
 */
static char	*service_list[] = { STATD, LOCKD, NULL };
static char	*service_list_v4[] = { STATD, LOCKD, NFS4CBD, NFSMAPID, NULL };

/*
 * These two variables control the NFS version number to be used.
 *
 * nfsvers defaults to 0 which means to use the highest number that
 * both the client and the server support.  It can also be set to
 * a particular value, either 2, 3, or 4 to indicate the version
 * number of choice.  If the server (or the client) do not support
 * the version indicated, then the mount attempt will be failed.
 *
 * nfsvers_to_use is the actual version number found to use.  It
 * is determined in get_fh by pinging the various versions of the
 * NFS service on the server to see which responds positively.
 *
 * nfsretry_vers is the version number set when we retry the mount
 * command with the version decremented from nfsvers_to_use.
 * nfsretry_vers is set from nfsvers_to_use when we retry the mount
 * for errors other than RPC errors; it helps un know why we are
 * retrying. It is an indication that the retry is due to
 * non-RPC errors.
 */
static rpcvers_t nfsvers = 0;
static rpcvers_t nfsvers_to_use = 0;
static rpcvers_t nfsretry_vers = 0;

/*
 * There are the defaults (range) for the client when determining
 * which NFS version to use when probing the server (see above).
 * These will only be used when the vers mount option is not used and
 * these may be reset if NFS SMF is configured to do so.
 */
static rpcvers_t vers_max_default = NFS_VERSMAX_DEFAULT;
static rpcvers_t vers_min_default = NFS_VERSMIN_DEFAULT;

/*
 * This variable controls whether to try the public file handle.
 */
static bool_t public_opt;

int
main(int argc, char *argv[])
{
	struct mnttab mnt;
	extern char *optarg;
	extern int optind;
	char optbuf[MAX_MNTOPT_STR];
	int ro = 0;
	int r;
	int c;
	char *myname;
	err_ret_t retry_error;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	myname = strrchr(argv[0], '/');
	myname = myname ? myname + 1 : argv[0];
	(void) snprintf(typename, sizeof (typename), "%s %s",
	    MNTTYPE_NFS, myname);
	argv[0] = typename;

	mnt.mnt_mntopts = optbuf;
	(void) strcpy(optbuf, "rw");

	/*
	 * Set options
	 */
	while ((c = getopt(argc, argv, "ro:mOq")) != EOF) {
		switch (c) {
		case 'r':
			ro++;
			break;
		case 'o':
			if (strlen(optarg) >= MAX_MNTOPT_STR) {
				pr_err(gettext("option string too long"));
				return (RET_ERR);
			}
			(void) strcpy(mnt.mnt_mntopts, optarg);
#ifdef LATER					/* XXX */
			if (strstr(optarg, MNTOPT_REMOUNT)) {
				/*
				 * If remount is specified, only rw is allowed.
				 */
				if ((strcmp(optarg, MNTOPT_REMOUNT) != 0) &&
				    (strcmp(optarg, "remount,rw") != 0) &&
				    (strcmp(optarg, "rw,remount") != 0)) {
					pr_err(gettext("Invalid options\n"));
					exit(RET_ERR);
				}
			}
#endif /* LATER */				/* XXX */
			break;
		case 'm':
			mflg++;
			break;
		case 'O':
			Oflg++;
			break;
		case 'q':
			qflg++;
			break;
		default:
			usage();
			exit(RET_ERR);
		}
	}
	if (argc - optind != 2) {
		usage();
		exit(RET_ERR);
	}

	mnt.mnt_special = argv[optind];
	mnt.mnt_mountp = argv[optind+1];

	if (!priv_ineffect(PRIV_SYS_MOUNT) ||
	    !priv_ineffect(PRIV_NET_PRIVADDR)) {
		pr_err(gettext("insufficient privileges\n"));
		exit(RET_ERR);
	}

	/*
	 * On a labeled system, allow read-down nfs mounts if privileged
	 * (PRIV_NET_MAC_AWARE) to do so.  Otherwise, ignore the error
	 * and "mount equal label only" behavior will result.
	 */
	if (is_system_labeled())
		(void) setpflags(NET_MAC_AWARE, 1);

	/*
	 * Read the NFS SMF defaults to see if the min/max versions have
	 * been set and therefore would override the encoded defaults.
	 * Then check to make sure that if they were set that the
	 * values are reasonable.
	 */
	read_default();
	if (vers_min_default > vers_max_default ||
	    vers_min_default < NFS_VERSMIN ||
	    vers_max_default > NFS_VERSMAX) {
		pr_err("%s\n%s %s\n",
		    gettext("Incorrect configuration of client\'s"),
		    gettext("client_versmin or client_versmax"),
		    gettext("is either out of range or overlaps."));
	}

	SET_ERR_RET(&retry_error, ERR_PROTO_NONE, 0);
	r = mount_nfs(&mnt, ro, &retry_error);
	if (r == RET_RETRY && retries) {
		/*
		 * Check the error code from the last mount attempt if it was
		 * an RPC error, then retry as is. Otherwise we retry with the
		 * nfsretry_vers set. It is set by decrementing nfsvers_to_use.
		 * If we are retrying with nfsretry_vers then we don't print any
		 * retry messages, since we are not retrying due to an RPC
		 * error.
		 */
		if (retry_error.error_type) {
			if (retry_error.error_type != ERR_RPCERROR) {
				nfsretry_vers = nfsvers_to_use =
				    nfsvers_to_use - 1;
				if (nfsretry_vers < NFS_VERSMIN)
					return (r);
			}
		}

		r = retry(&mnt, ro);
	}
	/*
	 * exit(r);
	 */
	return (r);
}

static void
pr_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (backgrounded != 0) {
		(void) vsyslog(LOG_ERR, fmt, ap);
	} else {
		(void) fprintf(stderr, "%s: ", typename);
		(void) vfprintf(stderr, fmt, ap);
		(void) fflush(stderr);
	}
	va_end(ap);
}

static void
usage()
{
	(void) fprintf(stderr,
	    gettext("Usage: nfs mount [-r] [-o opts] [server:]path dir\n"));
	exit(RET_ERR);
}

static int
mount_nfs(struct mnttab *mntp, int ro, err_ret_t *retry_error)
{
	struct nfs_args *args = NULL, *argp = NULL, *prev_argp = NULL;
	struct netconfig *nconf = NULL;
	struct replica *list = NULL;
	int mntflags = 0;
	int i, r, n;
	int oldvers = 0, vers = 0;
	int last_error = RET_OK;
	int replicated = 0;
	char *p;
	bool_t url;
	bool_t use_pubfh;
	char *special = NULL;
	char *oldpath = NULL;
	char *newpath = NULL;
	char *service;
	pid_t pi;
	struct flock f;
	char *saveopts = NULL;
	char **sl = NULL;

	mntp->mnt_fstype = MNTTYPE_NFS;

	if (ro) {
		mntflags |= MS_RDONLY;
		/* convert "rw"->"ro" */
		if (p = strstr(mntp->mnt_mntopts, "rw")) {
			if (*(p+2) == ',' || *(p+2) == '\0')
				*(p+1) = 'o';
		}
	}

	if (Oflg)
		mntflags |= MS_OVERLAY;

	list = parse_replica(mntp->mnt_special, &n);
	if (list == NULL) {
		if (n < 0)
			pr_err(gettext("nfs file system; use [host:]path\n"));
		else
			pr_err(gettext("no memory\n"));
		return (RET_ERR);
	}

	replicated = (n > 1);

	/*
	 * There are some free() calls at the bottom of this loop, so be
	 * careful about adding continue statements.
	 */
	for (i = 0; i < n; i++) {
		char *path;
		char *host;
		ushort_t port;

		argp = (struct nfs_args *)malloc(sizeof (*argp));
		if (argp == NULL) {
			pr_err(gettext("no memory\n"));
			last_error = RET_ERR;
			goto out;
		}
		memset(argp, 0, sizeof (*argp));

		memset(&nfs_sec, 0, sizeof (nfs_sec));
		sec_opt = 0;
		use_pubfh = FALSE;
		url = FALSE;
		port = 0;
		snego_done = FALSE;

		/*
		 * Looking for resources of the form
		 *	nfs://server_host[:port_number]/path_name
		 */
		if (strcmp(list[i].host, "nfs") == 0 && strncmp(list[i].path,
		    "//", 2) == 0) {
			char *sport, *cb;
			url = TRUE;
			oldpath = strdup(list[i].path);
			if (oldpath == NULL) {
				pr_err(gettext("memory allocation failure\n"));
				last_error = RET_ERR;
				goto out;
			}
			host = list[i].path+2;
			path = strchr(host, '/');

			if (path == NULL) {
				pr_err(gettext(
				    "illegal nfs url syntax\n"));
				last_error = RET_ERR;
				goto out;
			}

			*path = '\0';
			if (*host == '[') {
				cb = strchr(host, ']');
				if (cb == NULL) {
					pr_err(gettext(
					    "illegal nfs url syntax\n"));
					last_error = RET_ERR;
					goto out;
				} else {
					*cb = '\0';
					host++;
					cb++;
					if (*cb == ':')
						port = htons((ushort_t)
						    atoi(cb+1));
				}
			} else {
				sport = strchr(host, ':');

				if (sport != NULL && sport < path) {
					*sport = '\0';
					port = htons((ushort_t)atoi(sport+1));
				}
			}

			path++;
			if (*path == '\0')
				path = ".";

		} else {
			host = list[i].host;
			path = list[i].path;
		}

		if (r = set_args(&mntflags, argp, host, mntp)) {
			last_error = r;
			goto out;
		}

		if (public_opt == TRUE)
			use_pubfh = TRUE;

		if (port == 0) {
			port = nfs_port;
		} else if (nfs_port != 0 && nfs_port != port) {
			pr_err(gettext(
			    "port (%u) in nfs URL not the same"
			    " as port (%u) in port option\n"),
			    (unsigned int)ntohs(port),
			    (unsigned int)ntohs(nfs_port));
			last_error = RET_ERR;
			goto out;
		}


		if (replicated && !(mntflags & MS_RDONLY)) {
			pr_err(gettext(
			    "replicated mounts must be read-only\n"));
			last_error = RET_ERR;
			goto out;
		}

		if (replicated && (argp->flags & NFSMNT_SOFT)) {
			pr_err(gettext(
			    "replicated mounts must not be soft\n"));
			last_error = RET_ERR;
			goto out;
		}

		oldvers = vers;
		nconf = NULL;

		r = RET_ERR;

		/*
		 * If -o public was specified, and/or a URL was specified,
		 * then try the public file handle method.
		 */
		if ((use_pubfh == TRUE) || (url == TRUE)) {
			r = get_fh_via_pub(argp, host, path, url, use_pubfh,
			    &vers, &nconf, port);

			if (r != RET_OK) {
				/*
				 * If -o public was specified, then return the
				 * error now.
				 */
				if (use_pubfh == TRUE) {
					last_error = r;
					goto out;
				}
			} else
				use_pubfh = TRUE;
			argp->flags |= NFSMNT_PUBLIC;
		}

		if ((r != RET_OK) || (vers == NFS_V4)) {
			bool_t loud_on_mnt_err;

			/*
			 * This can happen if -o public is not specified,
			 * special is a URL, and server doesn't support
			 * public file handle.
			 */
			if (url) {
				URLparse(path);
			}

			/*
			 * If the path portion of the URL didn't have
			 * a leading / then there is good possibility
			 * that a mount without a leading slash will
			 * fail.
			 */
			if (url == TRUE && *path != '/')
				loud_on_mnt_err = FALSE;
			else
				loud_on_mnt_err = TRUE;

			r = get_fh(argp, host, path, &vers,
			    loud_on_mnt_err, &nconf, port);

			if (r != RET_OK) {

				/*
				 * If there was no leading / and the path was
				 * derived from a URL, then try again
				 * with a leading /.
				 */
				if ((r == RET_MNTERR) &&
				    (loud_on_mnt_err == FALSE)) {

					newpath = malloc(strlen(path)+2);

					if (newpath == NULL) {
						pr_err(gettext("memory "
						    "allocation failure\n"));
						last_error = RET_ERR;
						goto out;
					}

					strcpy(newpath, "/");
					strcat(newpath, path);

					r = get_fh(argp, host, newpath, &vers,
					    TRUE, &nconf, port);

					if (r == RET_OK)
						path = newpath;
				}

				/*
				 * map exit code back to RET_ERR.
				 */
				if (r == RET_MNTERR)
					r = RET_ERR;

				if (r != RET_OK) {

					if (replicated) {
						if (argp->fh)
							free(argp->fh);
						if (argp->pathconf)
							free(argp->pathconf);
						free(argp);
						goto cont;
					}

					last_error = r;
					goto out;
				}
			}
		}

		if (oldvers && vers != oldvers) {
			pr_err(
			    gettext("replicas must have the same version\n"));
			last_error = RET_ERR;
			goto out;
		}

		/*
		 * decide whether to use remote host's
		 * lockd or do local locking
		 */
		if (!(argp->flags & NFSMNT_LLOCK) && vers == NFS_VERSION &&
		    remote_lock(host, argp->fh)) {
			(void) fprintf(stderr, gettext(
			    "WARNING: No network locking on %s:%s:"),
			    host, path);
			(void) fprintf(stderr, gettext(
			    " contact admin to install server change\n"));
			argp->flags |= NFSMNT_LLOCK;
		}

		if (self_check(host))
			argp->flags |= NFSMNT_LOOPBACK;

		if (use_pubfh == FALSE) {
			/*
			 * Call to get_fh() above may have obtained the
			 * netconfig info and NULL proc'd the server.
			 * This would be the case with v4
			 */
			if (!(argp->flags & NFSMNT_KNCONF)) {
				nconf = NULL;
				if (r = getaddr_nfs(argp, host, &nconf,
				    FALSE, path, port, retry_error,
				    TRUE)) {
						last_error = r;
						goto out;
				}
			}
		}

		if (make_secure(argp, host, nconf, use_pubfh, vers) < 0) {
			last_error = RET_ERR;
			goto out;
		}

		if ((url == TRUE) && (use_pubfh == FALSE)) {
			/*
			 * Convert the special from
			 *	nfs://host/path
			 * to
			 *	host:path
			 */
			if (convert_special(&special, host, oldpath, path,
			    mntp->mnt_special) == -1) {
				(void) fprintf(stderr, gettext(
				    "could not convert URL nfs:%s to %s:%s\n"),
				    oldpath, host, path);
				last_error = RET_ERR;
				goto out;
			} else {
				mntp->mnt_special = special;
			}
		}

		if (prev_argp == NULL)
			args = argp;
		else
			prev_argp->nfs_ext_u.nfs_extB.next = argp;
		prev_argp = argp;

cont:
		if (oldpath != NULL) {
			free(oldpath);
			oldpath = NULL;
		}

		if (newpath != NULL) {
			free(newpath);
			newpath = NULL;
		}
	}

	argp = NULL;

	if (args == NULL) {
		last_error = RET_RETRY;
		goto out;
	}

	/* Determine which services are appropriate for the NFS version */
	if (strcmp(fstype, MNTTYPE_NFS4) == 0)
		sl = service_list_v4;
	else
		sl = service_list;

	/*
	 * enable services as needed.
	 */
	_check_services(sl);

	mntflags |= MS_DATA | MS_OPTIONSTR;

	if (mflg)
		mntflags |= MS_NOMNTTAB;

	if (!qflg)
		saveopts = strdup(mntp->mnt_mntopts);

	/*
	 * And make sure that we have the ephemeral mount_to
	 * set for this zone.
	 */
	set_nfsv4_ephemeral_mount_to();

	if (mount(mntp->mnt_special, mntp->mnt_mountp, mntflags, fstype, args,
	    sizeof (*args), mntp->mnt_mntopts, MAX_MNTOPT_STR) < 0) {
		if (errno != ENOENT) {
			pr_err(gettext("mount: %s: %s\n"),
			    mntp->mnt_mountp, strerror(errno));
		} else {
			struct stat sb;
			if (stat(mntp->mnt_mountp, &sb) < 0 && errno == ENOENT)
				pr_err(gettext("mount: %s: %s\n"),
				    mntp->mnt_mountp, strerror(ENOENT));
			else
				pr_err("%s: %s\n", mntp->mnt_special,
				    strerror(ENOENT));
		}

		last_error = RET_ERR;
		goto out;
	}

	if (!qflg && saveopts != NULL) {
		cmp_requested_to_actual_options(saveopts, mntp->mnt_mntopts,
		    mntp->mnt_special, mntp->mnt_mountp);
	}

out:
	if (saveopts != NULL)
		free(saveopts);
	if (special != NULL)
		free(special);
	if (oldpath != NULL)
		free(oldpath);
	if (newpath != NULL)
		free(newpath);

	free_replica(list, n);

	if (argp != NULL) {
		/*
		 * If we had a new entry which was not added to the
		 * list yet, then add it now that it can be freed.
		 */
		if (prev_argp == NULL)
			args = argp;
		else
			prev_argp->nfs_ext_u.nfs_extB.next = argp;
	}
	argp = args;
	while (argp != NULL) {
		if (argp->fh)
			free(argp->fh);
		if (argp->pathconf)
			free(argp->pathconf);
		if (argp->knconf)
			free(argp->knconf);
		if (argp->addr) {
			free(argp->addr->buf);
			free(argp->addr);
		}
		nfs_free_secdata(argp->nfs_ext_u.nfs_extB.secdata);
		if (argp->syncaddr) {
			free(argp->syncaddr->buf);
			free(argp->syncaddr);
		}
		if (argp->netname)
			free(argp->netname);
		prev_argp = argp;
		argp = argp->nfs_ext_u.nfs_extB.next;
		free(prev_argp);
	}

	return (last_error);
}

/*
 * These options are duplicated in uts/common/fs/nfs/nfs_dlinet.c
 * Changes must be made to both lists.
 */
static char *optlist[] = {
#define	OPT_RO		0
	MNTOPT_RO,
#define	OPT_RW		1
	MNTOPT_RW,
#define	OPT_QUOTA	2
	MNTOPT_QUOTA,
#define	OPT_NOQUOTA	3
	MNTOPT_NOQUOTA,
#define	OPT_SOFT	4
	MNTOPT_SOFT,
#define	OPT_HARD	5
	MNTOPT_HARD,
#define	OPT_SUID	6
	MNTOPT_SUID,
#define	OPT_NOSUID	7
	MNTOPT_NOSUID,
#define	OPT_GRPID	8
	MNTOPT_GRPID,
#define	OPT_REMOUNT	9
	MNTOPT_REMOUNT,
#define	OPT_NOSUB	10
	MNTOPT_NOSUB,
#define	OPT_INTR	11
	MNTOPT_INTR,
#define	OPT_NOINTR	12
	MNTOPT_NOINTR,
#define	OPT_PORT	13
	MNTOPT_PORT,
#define	OPT_SECURE	14
	MNTOPT_SECURE,
#define	OPT_RSIZE	15
	MNTOPT_RSIZE,
#define	OPT_WSIZE	16
	MNTOPT_WSIZE,
#define	OPT_TIMEO	17
	MNTOPT_TIMEO,
#define	OPT_RETRANS	18
	MNTOPT_RETRANS,
#define	OPT_ACTIMEO	19
	MNTOPT_ACTIMEO,
#define	OPT_ACREGMIN	20
	MNTOPT_ACREGMIN,
#define	OPT_ACREGMAX	21
	MNTOPT_ACREGMAX,
#define	OPT_ACDIRMIN	22
	MNTOPT_ACDIRMIN,
#define	OPT_ACDIRMAX	23
	MNTOPT_ACDIRMAX,
#define	OPT_BG		24
	MNTOPT_BG,
#define	OPT_FG		25
	MNTOPT_FG,
#define	OPT_RETRY	26
	MNTOPT_RETRY,
#define	OPT_NOAC	27
	MNTOPT_NOAC,
#define	OPT_NOCTO	28
	MNTOPT_NOCTO,
#define	OPT_LLOCK	29
	MNTOPT_LLOCK,
#define	OPT_POSIX	30
	MNTOPT_POSIX,
#define	OPT_VERS	31
	MNTOPT_VERS,
#define	OPT_PROTO	32
	MNTOPT_PROTO,
#define	OPT_SEMISOFT	33
	MNTOPT_SEMISOFT,
#define	OPT_NOPRINT	34
	MNTOPT_NOPRINT,
#define	OPT_SEC		35
	MNTOPT_SEC,
#define	OPT_LARGEFILES	36
	MNTOPT_LARGEFILES,
#define	OPT_NOLARGEFILES 37
	MNTOPT_NOLARGEFILES,
#define	OPT_PUBLIC	38
	MNTOPT_PUBLIC,
#define	OPT_DIRECTIO	39
	MNTOPT_FORCEDIRECTIO,
#define	OPT_NODIRECTIO	40
	MNTOPT_NOFORCEDIRECTIO,
#define	OPT_XATTR	41
	MNTOPT_XATTR,
#define	OPT_NOXATTR	42
	MNTOPT_NOXATTR,
#define	OPT_DEVICES	43
	MNTOPT_DEVICES,
#define	OPT_NODEVICES	44
	MNTOPT_NODEVICES,
#define	OPT_SETUID	45
	MNTOPT_SETUID,
#define	OPT_NOSETUID	46
	MNTOPT_NOSETUID,
#define	OPT_EXEC	47
	MNTOPT_EXEC,
#define	OPT_NOEXEC	48
	MNTOPT_NOEXEC,
	NULL
};

static int
convert_int(int *val, char *str)
{
	long lval;

	if (str == NULL || !isdigit(*str))
		return (-1);

	lval = strtol(str, &str, 10);
	if (*str != '\0' || lval > INT_MAX)
		return (-2);

	*val = (int)lval;
	return (0);
}

static int
set_args(int *mntflags, struct nfs_args *args, char *fshost, struct mnttab *mnt)
{
	char *saveopt, *optstr, *opts, *newopts, *val;
	int num;
	int largefiles = 0;
	int invalid = 0;
	int attrpref = 0;
	int optlen;

	args->flags = NFSMNT_INT;	/* default is "intr" */
	args->flags |= NFSMNT_HOSTNAME;
	args->flags |= NFSMNT_NEWARGS;	/* using extented nfs_args structure */
	args->hostname = fshost;

	optstr = opts = strdup(mnt->mnt_mntopts);
	/* sizeof (MNTOPT_XXX) includes one extra byte we may need for "," */
	optlen = strlen(mnt->mnt_mntopts) + sizeof (MNTOPT_XATTR) + 1;
	if (optlen > MAX_MNTOPT_STR) {
		pr_err(gettext("option string too long"));
		return (RET_ERR);
	}
	newopts = malloc(optlen);
	if (opts == NULL || newopts == NULL) {
		pr_err(gettext("no memory"));
		if (opts)
			free(opts);
		if (newopts)
			free(newopts);
		return (RET_ERR);
	}
	newopts[0] = '\0';

	while (*opts) {
		invalid = 0;
		saveopt = opts;
		switch (getsubopt(&opts, optlist, &val)) {
		case OPT_RO:
			*mntflags |= MS_RDONLY;
			break;
		case OPT_RW:
			*mntflags &= ~(MS_RDONLY);
			break;
		case OPT_QUOTA:
		case OPT_NOQUOTA:
			break;
		case OPT_SOFT:
			args->flags |= NFSMNT_SOFT;
			args->flags &= ~(NFSMNT_SEMISOFT);
			break;
		case OPT_SEMISOFT:
			args->flags |= NFSMNT_SOFT;
			args->flags |= NFSMNT_SEMISOFT;
			break;
		case OPT_HARD:
			args->flags &= ~(NFSMNT_SOFT);
			args->flags &= ~(NFSMNT_SEMISOFT);
			break;
		case OPT_SUID:
			*mntflags &= ~(MS_NOSUID);
			break;
		case OPT_NOSUID:
			*mntflags |= MS_NOSUID;
			break;
		case OPT_GRPID:
			args->flags |= NFSMNT_GRPID;
			break;
		case OPT_REMOUNT:
			*mntflags |= MS_REMOUNT;
			break;
		case OPT_INTR:
			args->flags |= NFSMNT_INT;
			break;
		case OPT_NOINTR:
			args->flags &= ~(NFSMNT_INT);
			break;
		case OPT_NOAC:
			args->flags |= NFSMNT_NOAC;
			break;
		case OPT_PORT:
			if (convert_int(&num, val) != 0)
				goto badopt;
			nfs_port = htons((ushort_t)num);
			break;

		case OPT_SECURE:
			if (nfs_getseconfig_byname("dh", &nfs_sec)) {
				pr_err(gettext("can not get \"dh\" from %s\n"),
				    NFSSEC_CONF);
				goto badopt;
			}
			sec_opt++;
			break;

		case OPT_NOCTO:
			args->flags |= NFSMNT_NOCTO;
			break;

		case OPT_RSIZE:
			if (convert_int(&args->rsize, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_RSIZE;
			break;
		case OPT_WSIZE:
			if (convert_int(&args->wsize, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_WSIZE;
			break;
		case OPT_TIMEO:
			if (convert_int(&args->timeo, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_TIMEO;
			break;
		case OPT_RETRANS:
			if (convert_int(&args->retrans, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_RETRANS;
			break;
		case OPT_ACTIMEO:
			if (convert_int(&args->acregmax, val) != 0)
				goto badopt;
			args->acdirmin = args->acregmin = args->acdirmax
			    = args->acregmax;
			args->flags |= NFSMNT_ACDIRMAX;
			args->flags |= NFSMNT_ACREGMAX;
			args->flags |= NFSMNT_ACDIRMIN;
			args->flags |= NFSMNT_ACREGMIN;
			break;
		case OPT_ACREGMIN:
			if (convert_int(&args->acregmin, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACREGMIN;
			break;
		case OPT_ACREGMAX:
			if (convert_int(&args->acregmax, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACREGMAX;
			break;
		case OPT_ACDIRMIN:
			if (convert_int(&args->acdirmin, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACDIRMIN;
			break;
		case OPT_ACDIRMAX:
			if (convert_int(&args->acdirmax, val) != 0)
				goto badopt;
			args->flags |= NFSMNT_ACDIRMAX;
			break;
		case OPT_BG:
			bg++;
			break;
		case OPT_FG:
			bg = 0;
			break;
		case OPT_RETRY:
			if (convert_int(&retries, val) != 0)
				goto badopt;
			break;
		case OPT_LLOCK:
			args->flags |= NFSMNT_LLOCK;
			break;
		case OPT_POSIX:
			posix = 1;
			break;
		case OPT_VERS:
			if (convert_int(&num, val) != 0)
				goto badopt;
			nfsvers = (rpcvers_t)num;
			break;
		case OPT_PROTO:
			if (val == NULL)
				goto badopt;

			nfs_proto = (char *)malloc(strlen(val)+1);
			if (!nfs_proto) {
				pr_err(gettext("no memory"));
				return (RET_ERR);
			}

			(void) strncpy(nfs_proto, val, strlen(val)+1);
			break;

		case OPT_NOPRINT:
			args->flags |= NFSMNT_NOPRINT;
			break;

		case OPT_LARGEFILES:
			largefiles = 1;
			break;

		case OPT_NOLARGEFILES:
			pr_err(gettext("NFS can't support \"nolargefiles\"\n"));
			free(optstr);
			return (RET_ERR);

		case OPT_SEC:
			if (val == NULL) {
				pr_err(gettext(
				    "\"sec\" option requires argument\n"));
				return (RET_ERR);
			}
			if (nfs_getseconfig_byname(val, &nfs_sec)) {
				pr_err(gettext("can not get \"%s\" from %s\n"),
				    val, NFSSEC_CONF);
				return (RET_ERR);
			}
			sec_opt++;
			break;

		case OPT_PUBLIC:
			public_opt = TRUE;
			break;

		case OPT_DIRECTIO:
			args->flags |= NFSMNT_DIRECTIO;
			break;

		case OPT_NODIRECTIO:
			args->flags &= ~(NFSMNT_DIRECTIO);
			break;

		case OPT_XATTR:
		case OPT_NOXATTR:
			/*
			 * VFS options; just need to get them into the
			 * new mount option string and note we've seen them
			 */
			attrpref = 1;
			break;
		default:
			/*
			 * Note that this could be a valid OPT_* option so
			 * we can't use "val" but need to use "saveopt".
			 */
			if (fsisstdopt(saveopt))
				break;
			invalid = 1;
			if (!qflg)
				(void) fprintf(stderr, gettext(
				    "mount: %s on %s - WARNING unknown option"
				    " \"%s\"\n"), mnt->mnt_special,
				    mnt->mnt_mountp, saveopt);
			break;
		}
		if (!invalid) {
			if (newopts[0])
				strcat(newopts, ",");
			strcat(newopts, saveopt);
		}
	}
	/* Default is to turn extended attrs on */
	if (!attrpref) {
		if (newopts[0])
			strcat(newopts, ",");
		strcat(newopts, MNTOPT_XATTR);
	}
	strcpy(mnt->mnt_mntopts, newopts);
	free(newopts);
	free(optstr);

	/* ensure that only one secure mode is requested */
	if (sec_opt > 1) {
		pr_err(gettext("Security options conflict\n"));
		return (RET_ERR);
	}

	/* ensure that the user isn't trying to get large files over V2 */
	if (nfsvers == NFS_VERSION && largefiles) {
		pr_err(gettext("NFS V2 can't support \"largefiles\"\n"));
		return (RET_ERR);
	}

	if (nfsvers == NFS_V4 &&
	    nfs_proto != NULL &&
	    strncasecmp(nfs_proto, NC_UDP, strlen(NC_UDP)) == 0) {
		pr_err(gettext("NFS V4 does not support %s\n"), nfs_proto);
		return (RET_ERR);
	}

	return (RET_OK);

badopt:
	pr_err(gettext("invalid option: \"%s\"\n"), saveopt);
	free(optstr);
	return (RET_ERR);
}

static int
make_secure(struct nfs_args *args, char *hostname, struct netconfig *nconf,
	bool_t use_pubfh, rpcvers_t vers)
{
	sec_data_t *secdata;
	int flags;
	struct netbuf *syncaddr = NULL;
	struct nd_addrlist *retaddrs = NULL;
	char netname[MAXNETNAMELEN+1];

	/*
	 * check to see if any secure mode is requested.
	 * if not, use default security mode.
	 */
	if (!snego_done && !sec_opt) {
		/*
		 * Get default security mode.
		 * AUTH_UNIX has been the default choice for a long time.
		 * The better NFS security service becomes, the better chance
		 * we will set stronger security service as the default NFS
		 * security mode.
		 */
		if (nfs_getseconfig_default(&nfs_sec)) {
			pr_err(gettext("error getting default"
			    " security entry\n"));
			return (-1);
		}
		args->flags |= NFSMNT_SECDEFAULT;
	}

	/*
	 * Get the network address for the time service on the server.
	 * If an RPC based time service is not available then try the
	 * IP time service.
	 *
	 * This is for AUTH_DH processing. We will also pass down syncaddr
	 * and netname for NFS V4 even if AUTH_DH is not requested right now.
	 * NFS V4 does security negotiation in the kernel via SECINFO.
	 * These information might be needed later in the kernel.
	 *
	 * Eventurally, we want to move this code to nfs_clnt_secdata()
	 * when autod_nfs.c and mount.c can share the same get_the_addr()
	 * routine.
	 */
	flags = 0;
	syncaddr = NULL;

	if (nfs_sec.sc_rpcnum == AUTH_DH || vers == NFS_V4) {
		/*
		 * If using the public fh or nfsv4, we will not contact the
		 * remote RPCBINDer, since it is possibly behind a firewall.
		 */
		if (use_pubfh == FALSE && vers != NFS_V4)
			syncaddr = get_the_addr(hostname, RPCBPROG, RPCBVERS,
			    nconf, 0, NULL, NULL, FALSE, NULL, NULL);

		if (syncaddr != NULL) {
			/* for flags in sec_data */
			flags |= AUTH_F_RPCTIMESYNC;
		} else {
			struct nd_hostserv hs;
			int error;

			hs.h_host = hostname;
			hs.h_serv = "timserver";

			error = netdir_getbyname(nconf, &hs, &retaddrs);

			if (error != ND_OK && (nfs_sec.sc_rpcnum == AUTH_DH)) {
				pr_err(gettext("%s: secure: no time service\n"),
				    hostname);
				return (-1);
			}

			if (error == ND_OK)
				syncaddr = retaddrs->n_addrs;

			/*
			 * For NFS_V4 if AUTH_DH is negotiated later in the
			 * kernel thru SECINFO, it will need syncaddr
			 * and netname data.
			 */
			if (vers == NFS_V4 && syncaddr &&
			    host2netname(netname, hostname, NULL)) {
				args->syncaddr = malloc(sizeof (struct netbuf));
				args->syncaddr->buf = malloc(syncaddr->len);
				(void) memcpy(args->syncaddr->buf,
				    syncaddr->buf, syncaddr->len);
				args->syncaddr->len = syncaddr->len;
				args->syncaddr->maxlen = syncaddr->maxlen;
				args->netname = strdup(netname);
				args->flags |= NFSMNT_SECURE;
			}
		}
	}

	/*
	 * For the initial chosen flavor (any flavor defined in nfssec.conf),
	 * the data will be stored in the sec_data structure via
	 * nfs_clnt_secdata() and be passed to the kernel via nfs_args_*
	 * extended data structure.
	 */
	if (!(secdata = nfs_clnt_secdata(&nfs_sec, hostname, args->knconf,
	    syncaddr, flags))) {
		pr_err(gettext("errors constructing security related data\n"));
		if (flags & AUTH_F_RPCTIMESYNC) {
			free(syncaddr->buf);
			free(syncaddr);
		} else if (retaddrs)
			netdir_free((void *)retaddrs, ND_ADDRLIST);
		return (-1);
	}

	NFS_ARGS_EXTB_secdata(args, secdata);
	if (flags & AUTH_F_RPCTIMESYNC) {
		free(syncaddr->buf);
		free(syncaddr);
	} else if (retaddrs)
		netdir_free((void *)retaddrs, ND_ADDRLIST);
	return (0);
}

/*
 * Get the network address on "hostname" for program "prog"
 * with version "vers" by using the nconf configuration data
 * passed in.
 *
 * If the address of a netconfig pointer is null then
 * information is not sufficient and no netbuf will be returned.
 *
 * Finally, ping the null procedure of that service.
 *
 * A similar routine is also defined in ../../autofs/autod_nfs.c.
 * This is a potential routine to move to ../lib for common usage.
 */
static struct netbuf *
get_the_addr(char *hostname, ulong_t prog, ulong_t vers,
	struct netconfig *nconf, ushort_t port, struct t_info *tinfo,
	caddr_t *fhp, bool_t get_pubfh, char *fspath, err_ret_t *error)
{
	struct netbuf *nb = NULL;
	struct t_bind *tbind = NULL;
	CLIENT *cl = NULL;
	struct timeval tv;
	int fd = -1;
	AUTH *ah = NULL;
	AUTH *new_ah = NULL;
	struct snego_t snego;

	if (nconf == NULL)
		return (NULL);

	if ((fd = t_open(nconf->nc_device, O_RDWR, tinfo)) == -1)
		goto done;

	/* LINTED pointer alignment */
	if ((tbind = (struct t_bind *)t_alloc(fd, T_BIND, T_ADDR))
	    == NULL)
		goto done;

	/*
	 * In the case of public filehandle usage or NFSv4 we want to
	 * avoid use of the rpcbind/portmap protocol
	 */
	if ((get_pubfh == TRUE) || (vers == NFS_V4)) {
		struct nd_hostserv hs;
		struct nd_addrlist *retaddrs;
		int retval;
		hs.h_host = hostname;

		/* NFS where vers==4 does not support UDP */
		if (vers == NFS_V4 &&
		    strncasecmp(nconf->nc_proto, NC_UDP,
		    strlen(NC_UDP)) == 0) {
			SET_ERR_RET(error, ERR_PROTO_UNSUPP, 0);
			goto done;
		}

		if (port == 0)
			hs.h_serv = "nfs";
		else
			hs.h_serv = NULL;

		if ((retval = netdir_getbyname(nconf, &hs, &retaddrs))
		    != ND_OK) {
			/*
			 * Carefully set the error value here. Want to signify
			 * that the error was an unknown host.
			 */
			if (retval == ND_NOHOST) {
				SET_ERR_RET(error, ERR_NOHOST, retval);
			}

			goto done;
		}
		memcpy(tbind->addr.buf, retaddrs->n_addrs->buf,
		    retaddrs->n_addrs->len);
		tbind->addr.len = retaddrs->n_addrs->len;
		netdir_free((void *)retaddrs, ND_ADDRLIST);
		(void) netdir_options(nconf, ND_SET_RESERVEDPORT, fd, NULL);

	} else {
		if (rpcb_getaddr(prog, vers, nconf, &tbind->addr,
		    hostname) == FALSE) {
			goto done;
		}
	}

	if (port) {
		/* LINTED pointer alignment */
		if (strcmp(nconf->nc_protofmly, NC_INET) == 0)
			((struct sockaddr_in *)tbind->addr.buf)->sin_port
			    = port;
		else if (strcmp(nconf->nc_protofmly, NC_INET6) == 0)
			((struct sockaddr_in6 *)tbind->addr.buf)->sin6_port
			    = port;

	}

	cl = clnt_tli_create(fd, nconf, &tbind->addr, prog, vers, 0, 0);
	if (cl == NULL) {
		/*
		 * clnt_tli_create() returns either RPC_SYSTEMERROR,
		 * RPC_UNKNOWNPROTO or RPC_TLIERROR. The RPC_TLIERROR translates
		 * to "Misc. TLI error". This is not too helpful. Most likely
		 * the connection to the remote server timed out, so this
		 * error is at least less perplexing.
		 * See: usr/src/cmd/rpcinfo/rpcinfo.c
		 */
		if (rpc_createerr.cf_stat == RPC_TLIERROR) {
			SET_ERR_RET(error, ERR_RPCERROR, RPC_PMAPFAILURE);
		} else {
			SET_ERR_RET(error, ERR_RPCERROR, rpc_createerr.cf_stat);
		}
		goto done;
	}

	ah = authsys_create_default();
	if (ah != NULL)
		cl->cl_auth = ah;

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	(void) clnt_control(cl, CLSET_TIMEOUT, (char *)&tv);

	if ((get_pubfh == TRUE) && (vers != NFS_V4)) {
		enum snego_stat sec;

		if (!snego_done) {
			/*
			 * negotiate sec flavor.
			 */
			snego.cnt = 0;
			if ((sec = nfs_sec_nego(vers, cl, fspath, &snego)) ==
			    SNEGO_SUCCESS) {
				int jj;

				/*
				 * check if server supports the one
				 * specified in the sec= option.
				 */
				if (sec_opt) {
					for (jj = 0; jj < snego.cnt; jj++) {
						if (snego.array[jj] ==
						    nfs_sec.sc_nfsnum) {
							snego_done = TRUE;
							break;
						}
					}
				}

				/*
				 * find a common sec flavor
				 */
				if (!snego_done) {
					if (sec_opt) {
						pr_err(gettext(
						    "Server does not support"
						    " the security flavor"
						    " specified.\n"));
					}

					for (jj = 0; jj < snego.cnt; jj++) {
						if (!nfs_getseconfig_bynumber(
						    snego.array[jj],
						    &nfs_sec)) {
							snego_done = TRUE;
#define	EMSG80SUX "Security flavor %d was negotiated and will be used.\n"
							if (sec_opt)
								pr_err(gettext(
								    EMSG80SUX),
								    nfs_sec.
								    sc_nfsnum);
							break;
						}
					}
				}

				if (!snego_done)
					return (NULL);

				/*
				 * Now that the flavor has been
				 * negotiated, get the fh.
				 *
				 * First, create an auth handle using the
				 * negotiated sec flavor in the next lookup to
				 * fetch the filehandle.
				 */
				new_ah = nfs_create_ah(cl, hostname, &nfs_sec);
				if (new_ah == NULL)
					goto done;
				cl->cl_auth = new_ah;
			} else if (sec == SNEGO_ARRAY_TOO_SMALL || sec ==
			    SNEGO_FAILURE) {
				goto done;
			}

			/*
			 * Note that if sec == SNEGO_DEF_VALID
			 * default sec flavor is acceptable.
			 * Use it to get the filehandle.
			 */
		}

		if (vers == NFS_VERSION) {
			wnl_diropargs arg;
			wnl_diropres res;

			memset((char *)&arg.dir, 0, sizeof (wnl_fh));
			arg.name = fspath;
			memset((char *)&res, 0, sizeof (wnl_diropres));
			if (wnlproc_lookup_2(&arg, &res, cl) !=
			    RPC_SUCCESS || res.status != WNL_OK)
				goto done;

			*fhp = malloc(sizeof (wnl_fh));

			if (*fhp == NULL) {
				pr_err(gettext("no memory\n"));
				goto done;
			}

			memcpy((char *)*fhp,
			    (char *)&res.wnl_diropres_u.wnl_diropres.file,
			    sizeof (wnl_fh));
		} else {
			WNL_LOOKUP3args arg;
			WNL_LOOKUP3res res;
			nfs_fh3 *fh3p;

			memset((char *)&arg.what.dir, 0, sizeof (wnl_fh3));
			arg.what.name = fspath;
			memset((char *)&res, 0, sizeof (WNL_LOOKUP3res));
			if (wnlproc3_lookup_3(&arg, &res, cl) !=
			    RPC_SUCCESS || res.status != WNL3_OK)
				goto done;

			fh3p = (nfs_fh3 *)malloc(sizeof (*fh3p));

			if (fh3p == NULL) {
				pr_err(gettext("no memory\n"));
				goto done;
			}

			fh3p->fh3_length =
			    res.WNL_LOOKUP3res_u.res_ok.object.data.data_len;
			memcpy(fh3p->fh3_u.data,
			    res.WNL_LOOKUP3res_u.res_ok.object.data.data_val,
			    fh3p->fh3_length);

			*fhp = (caddr_t)fh3p;
		}
	} else {
		struct rpc_err r_err;
		enum clnt_stat rc;

		/*
		 * NULL procedures need not have an argument or
		 * result param.
		 */
		if (vers == NFS_VERSION)
			rc = wnlproc_null_2(NULL, NULL, cl);
		else if (vers == NFS_V3)
			rc = wnlproc3_null_3(NULL, NULL, cl);
		else
			rc = wnlproc4_null_4(NULL, NULL, cl);

		if (rc != RPC_SUCCESS) {
			clnt_geterr(cl, &r_err);
			if (strcmp(nconf->nc_protofmly, NC_LOOPBACK) == 0) {
				switch (r_err.re_status) {
				case RPC_TLIERROR:
				case RPC_CANTRECV:
				case RPC_CANTSEND:
					r_err.re_status = RPC_PROGVERSMISMATCH;
				}
			}
			SET_ERR_RET(error, ERR_RPCERROR, r_err.re_status);
			goto done;
		}
	}

	/*
	 * Make a copy of the netbuf to return
	 */
	nb = (struct netbuf *)malloc(sizeof (*nb));
	if (nb == NULL) {
		pr_err(gettext("no memory\n"));
		goto done;
	}
	*nb = tbind->addr;
	nb->buf = (char *)malloc(nb->maxlen);
	if (nb->buf == NULL) {
		pr_err(gettext("no memory\n"));
		free(nb);
		nb = NULL;
		goto done;
	}
	(void) memcpy(nb->buf, tbind->addr.buf, tbind->addr.len);

done:
	if (cl) {
		if (ah != NULL) {
			if (new_ah != NULL)
				AUTH_DESTROY(ah);
			AUTH_DESTROY(cl->cl_auth);
			cl->cl_auth = NULL;
		}
		clnt_destroy(cl);
		cl = NULL;
	}
	if (tbind) {
		t_free((char *)tbind, T_BIND);
		tbind = NULL;
	}
	if (fd >= 0)
		(void) t_close(fd);
	return (nb);
}

static int
check_nconf(struct netconfig *nconf, int nthtry, int *valid_proto)
{
	int	try_test = 0;
	int	valid_family;
	char	*proto = NULL;


	if (nthtry == FIRST_TRY) {
		try_test = ((nconf->nc_semantics == NC_TPI_COTS_ORD) ||
		    (nconf->nc_semantics == NC_TPI_COTS));
		proto = NC_TCP;
	} else if (nthtry == SECOND_TRY) {
		try_test = (nconf->nc_semantics == NC_TPI_CLTS);
		proto = NC_UDP;
	}

	if (proto &&
	    (strcmp(nconf->nc_protofmly, NC_INET) == 0 ||
	    strcmp(nconf->nc_protofmly, NC_INET6) == 0) &&
	    (strcmp(nconf->nc_proto, proto) == 0))
		*valid_proto = TRUE;
	else
		*valid_proto = FALSE;

	return (try_test);
}

/*
 * Get a network address on "hostname" for program "prog"
 * with version "vers".  If the port number is specified (non zero)
 * then try for a TCP/UDP transport and set the port number of the
 * resulting IP address.
 *
 * If the address of a netconfig pointer was passed and
 * if it's not null, use it as the netconfig otherwise
 * assign the address of the netconfig that was used to
 * establish contact with the service.
 *
 * A similar routine is also defined in ../../autofs/autod_nfs.c.
 * This is a potential routine to move to ../lib for common usage.
 *
 * "error" refers to a more descriptive term when get_addr fails
 * and returns NULL: ERR_PROTO_NONE if no error introduced by
 * -o proto option, ERR_NETPATH if error found in NETPATH
 * environment variable, ERR_PROTO_INVALID if an unrecognized
 * protocol is specified by user, and ERR_PROTO_UNSUPP for a
 * recognized but invalid protocol (eg. ticlts, ticots, etc.).
 * "error" is ignored if get_addr returns non-NULL result.
 *
 */
static struct netbuf *
get_addr(char *hostname, ulong_t prog, ulong_t vers, struct netconfig **nconfp,
	char *proto, ushort_t port, struct t_info *tinfo, caddr_t *fhp,
	bool_t get_pubfh, char *fspath, err_ret_t *error)
{
	struct netbuf *nb = NULL;
	struct netconfig *nconf = NULL;
	NCONF_HANDLE *nc = NULL;
	int nthtry = FIRST_TRY;
	err_ret_t errsave_nohost, errsave_rpcerr;

	SET_ERR_RET(&errsave_nohost, ERR_PROTO_NONE, 0);
	SET_ERR_RET(&errsave_rpcerr, ERR_PROTO_NONE, 0);

	SET_ERR_RET(error, ERR_PROTO_NONE, 0);

	if (nconfp && *nconfp)
		return (get_the_addr(hostname, prog, vers, *nconfp, port,
		    tinfo, fhp, get_pubfh, fspath, error));
	/*
	 * No nconf passed in.
	 *
	 * Try to get a nconf from /etc/netconfig filtered by
	 * the NETPATH environment variable.
	 * First search for COTS, second for CLTS unless proto
	 * is specified.  When we retry, we reset the
	 * netconfig list so that we would search the whole list
	 * all over again.
	 */

	if ((nc = setnetpath()) == NULL) {
		/* should only return an error if problems with NETPATH */
		/* In which case you are hosed */
		SET_ERR_RET(error, ERR_NETPATH, 0);
		goto done;
	}

	/*
	 * If proto is specified, then only search for the match,
	 * otherwise try COTS first, if failed, try CLTS.
	 */
	if (proto) {
		/* no matching proto name */
		SET_ERR_RET(error, ERR_PROTO_INVALID, 0);

		while (nconf = getnetpath(nc)) {
			if (strcmp(nconf->nc_netid, proto))
				continue;

			/* may be unsupported */
			SET_ERR_RET(error, ERR_PROTO_UNSUPP, 0);

			if ((port != 0) &&
			    ((strcmp(nconf->nc_protofmly, NC_INET) == 0 ||
			    strcmp(nconf->nc_protofmly, NC_INET6) == 0) &&
			    (strcmp(nconf->nc_proto, NC_TCP) != 0 &&
			    strcmp(nconf->nc_proto, NC_UDP) != 0))) {
				continue;
			} else {
				nb = get_the_addr(hostname, prog,
				    vers, nconf, port, tinfo,
				    fhp, get_pubfh, fspath, error);

				if (nb != NULL)
					break;

				/* nb is NULL - deal with errors */
				if (error) {
					if (error->error_type == ERR_NOHOST)
						SET_ERR_RET(&errsave_nohost,
						    error->error_type,
						    error->error_value);
					if (error->error_type == ERR_RPCERROR)
						SET_ERR_RET(&errsave_rpcerr,
						    error->error_type,
						    error->error_value);
				}
				/*
				 * continue with same protocol
				 * selection
				 */
				continue;
			}
		} /* end of while */

		if (nconf == NULL)
			goto done;

		if ((nb = get_the_addr(hostname, prog, vers, nconf, port,
		    tinfo, fhp, get_pubfh, fspath, error)) == NULL)
			goto done;
	} else {
retry:
		SET_ERR_RET(error, ERR_NETPATH, 0);
		while (nconf = getnetpath(nc)) {
			SET_ERR_RET(error, ERR_PROTO_NONE, 0);

			if (nconf->nc_flag & NC_VISIBLE) {
				int	valid_proto;

				if (check_nconf(nconf,
				    nthtry, &valid_proto)) {
					if (port == 0)
						break;

					if (valid_proto == TRUE)
						break;
				}
			}
		} /* while */
		if (nconf == NULL) {
			if (++nthtry <= MNT_PREF_LISTLEN) {
				endnetpath(nc);
				if ((nc = setnetpath()) == NULL)
					goto done;
				goto retry;
			} else
				goto done;
		} else {
			if ((nb = get_the_addr(hostname, prog, vers, nconf,
			    port, tinfo, fhp, get_pubfh, fspath, error))
			    == NULL) {
				/* nb is NULL - deal with errors */
				if (error) {
					if (error->error_type == ERR_NOHOST)
						SET_ERR_RET(&errsave_nohost,
						    error->error_type,
						    error->error_value);
					if (error->error_type == ERR_RPCERROR)
						SET_ERR_RET(&errsave_rpcerr,
						    error->error_type,
						    error->error_value);
				}
				/*
				 * Continue the same search path in the
				 * netconfig db until no more matched
				 * nconf (nconf == NULL).
				 */
				goto retry;
			}
		}
	}
	SET_ERR_RET(error, ERR_PROTO_NONE, 0);

	/*
	 * Got nconf and nb.  Now dup the netconfig structure (nconf)
	 * and return it thru nconfp.
	 */
	*nconfp = getnetconfigent(nconf->nc_netid);
	if (*nconfp == NULL) {
		syslog(LOG_ERR, "no memory\n");
		free(nb);
		nb = NULL;
	}
done:
	if (nc)
		endnetpath(nc);

	if (nb == NULL) {
		/*
		 * Check the saved errors. The RPC error has *
		 * precedence over the no host error.
		 */
		if (errsave_nohost.error_type != ERR_PROTO_NONE)
			SET_ERR_RET(error, errsave_nohost.error_type,
			    errsave_nohost.error_value);

		if (errsave_rpcerr.error_type != ERR_PROTO_NONE)
			SET_ERR_RET(error, errsave_rpcerr.error_type,
			    errsave_rpcerr.error_value);
	}

	return (nb);
}

/*
 * Get a file handle usinging multi-component lookup with the public
 * file handle.
 */
static int
get_fh_via_pub(struct nfs_args *args, char *fshost, char *fspath, bool_t url,
	bool_t loud, int *versp, struct netconfig **nconfp, ushort_t port)
{
	uint_t vers_min;
	uint_t vers_max;
	int r;
	char *path;

	if (nfsvers != 0) {
		vers_max = vers_min = nfsvers;
	} else {
		vers_max = vers_max_default;
		vers_min = vers_min_default;
	}

	if (url == FALSE) {
		path = malloc(strlen(fspath) + 2);
		if (path == NULL) {
			if (loud == TRUE)
				pr_err(gettext("no memory\n"));
			return (RET_ERR);
		}

		path[0] = (char)WNL_NATIVEPATH;
		(void) strcpy(&path[1], fspath);

	} else  {
		path = fspath;
	}

	for (nfsvers_to_use = vers_max; nfsvers_to_use >= vers_min;
	    nfsvers_to_use--) {
		/*
		 * getaddr_nfs will also fill in the fh for us.
		 */
		r = getaddr_nfs(args, fshost, nconfp,
		    TRUE, path, port, NULL, FALSE);

		if (r == RET_OK) {
			/*
			 * Since we are using the public fh, and NLM is
			 * not firewall friendly, use local locking.
			 * Not the case for v4.
			 */
			*versp = nfsvers_to_use;
			switch (nfsvers_to_use) {
			case NFS_V4:
				fstype = MNTTYPE_NFS4;
				break;
			case NFS_V3:
				fstype = MNTTYPE_NFS3;
				/* FALLTHROUGH */
			default:
				args->flags |= NFSMNT_LLOCK;
				break;
			}
			if (fspath != path)
				free(path);

			return (r);
		}
	}

	if (fspath != path)
		free(path);

	if (loud == TRUE) {
		pr_err(gettext("Could not use public filehandle in request to"
		    " server %s\n"), fshost);
	}

	return (r);
}

/*
 * get fhandle of remote path from server's mountd
 */
static int
get_fh(struct nfs_args *args, char *fshost, char *fspath, int *versp,
	bool_t loud_on_mnt_err, struct netconfig **nconfp, ushort_t port)
{
	static struct fhstatus fhs;
	static struct mountres3 mountres3;
	static struct pathcnf p;
	nfs_fh3 *fh3p;
	struct timeval timeout = { 25, 0};
	CLIENT *cl;
	enum clnt_stat rpc_stat;
	rpcvers_t outvers = 0;
	rpcvers_t vers_to_try;
	rpcvers_t vers_min;
	static int printed = 0;
	int count, i, *auths;
	char *msg;

	switch (nfsvers) {
	case 2: /* version 2 specified try that only */
		vers_to_try = MOUNTVERS_POSIX;
		vers_min = MOUNTVERS;
		break;
	case 3: /* version 3 specified try that only */
		vers_to_try = MOUNTVERS3;
		vers_min = MOUNTVERS3;
		break;
	case 4: /* version 4 specified try that only */
		/*
		 * This assignment is in the wrong version sequence.
		 * The above are MOUNT program and this is NFS
		 * program.  However, it happens to work out since the
		 * two don't collide for NFSv4.
		 */
		vers_to_try = NFS_V4;
		vers_min = NFS_V4;
		break;
	default: /* no version specified, start with default */
		/*
		 * If the retry version is set, use that. This will
		 * be set if the last mount attempt returned any other
		 * besides an RPC error.
		 */
		if (nfsretry_vers)
			vers_to_try = nfsretry_vers;
		else {
			vers_to_try = vers_max_default;
			vers_min = vers_min_default;
		}

		break;
	}

	/*
	 * In the case of version 4, just NULL proc the server since
	 * there is no MOUNT program.  If this fails, then decrease
	 * vers_to_try and continue on with regular MOUNT program
	 * processing.
	 */
	if (vers_to_try == NFS_V4) {
		int savevers = nfsvers_to_use;
		err_ret_t error;
		int retval;
		SET_ERR_RET(&error, ERR_PROTO_NONE, 0);

		/* Let's hope for the best */
		nfsvers_to_use = NFS_V4;
		retval = getaddr_nfs(args, fshost, nconfp, FALSE,
		    fspath, port, &error, vers_min == NFS_V4);

		if (retval == RET_OK) {
			*versp = nfsvers_to_use = NFS_V4;
			fstype = MNTTYPE_NFS4;
			args->fh = strdup(fspath);
			if (args->fh == NULL) {
				pr_err(gettext("no memory\n"));
				*versp = nfsvers_to_use = savevers;
				return (RET_ERR);
			}
			return (RET_OK);
		}
		nfsvers_to_use = savevers;

		vers_to_try--;
		/* If no more versions to try, let the user know. */
		if (vers_to_try < vers_min)
			return (retval);

		/*
		 * If we are here, there are more versions to try but
		 * there has been an error of some sort.  If it is not
		 * an RPC error (e.g. host unknown), we just stop and
		 * return the error since the other versions would see
		 * the same error as well.
		 */
		if (retval == RET_ERR && error.error_type != ERR_RPCERROR)
			return (retval);
	}

	while ((cl = clnt_create_vers(fshost, MOUNTPROG, &outvers,
	    vers_min, vers_to_try, "datagram_v")) == NULL) {
		if (rpc_createerr.cf_stat == RPC_UNKNOWNHOST) {
			pr_err(gettext("%s: %s\n"), fshost,
			    clnt_spcreateerror(""));
			return (RET_ERR);
		}

		/*
		 * We don't want to downgrade version on lost packets
		 */
		if ((rpc_createerr.cf_stat == RPC_TIMEDOUT) ||
		    (rpc_createerr.cf_stat == RPC_PMAPFAILURE)) {
			pr_err(gettext("%s: %s\n"), fshost,
			    clnt_spcreateerror(""));
			return (RET_RETRY);
		}

		/*
		 * back off and try the previous version - patch to the
		 * problem of version numbers not being contigous and
		 * clnt_create_vers failing (SunOS4.1 clients & SGI servers)
		 * The problem happens with most non-Sun servers who
		 * don't support mountd protocol #2. So, in case the
		 * call fails, we re-try the call anyway.
		 */
		vers_to_try--;
		if (vers_to_try < vers_min) {
			if (rpc_createerr.cf_stat == RPC_PROGVERSMISMATCH) {
				if (nfsvers == 0) {
					pr_err(gettext(
			"%s:%s: no applicable versions of NFS supported\n"),
					    fshost, fspath);
				} else {
					pr_err(gettext(
			"%s:%s: NFS Version %d not supported\n"),
					    fshost, fspath, nfsvers);
				}
				return (RET_ERR);
			}
			if (!printed) {
				pr_err(gettext("%s: %s\n"), fshost,
				    clnt_spcreateerror(""));
				printed = 1;
			}
			return (RET_RETRY);
		}
	}
	if (posix && outvers < MOUNTVERS_POSIX) {
		pr_err(gettext("%s: %s: no pathconf info\n"),
		    fshost, clnt_sperror(cl, ""));
		clnt_destroy(cl);
		return (RET_ERR);
	}

	if (__clnt_bindresvport(cl) < 0) {
		pr_err(gettext("Couldn't bind to reserved port\n"));
		clnt_destroy(cl);
		return (RET_RETRY);
	}

	if ((cl->cl_auth = authsys_create_default()) == NULL) {
		pr_err(
		    gettext("Couldn't create default authentication handle\n"));
		clnt_destroy(cl);
		return (RET_RETRY);
	}

	switch (outvers) {
	case MOUNTVERS:
	case MOUNTVERS_POSIX:
		*versp = nfsvers_to_use = NFS_VERSION;
		rpc_stat = clnt_call(cl, MOUNTPROC_MNT, xdr_dirpath,
		    (caddr_t)&fspath, xdr_fhstatus, (caddr_t)&fhs, timeout);
		if (rpc_stat != RPC_SUCCESS) {
			pr_err(gettext("%s:%s: server not responding %s\n"),
			    fshost, fspath, clnt_sperror(cl, ""));
			clnt_destroy(cl);
			return (RET_RETRY);
		}

		if ((errno = fhs.fhs_status) != MNT_OK) {
			if (loud_on_mnt_err) {
				if (errno == EACCES) {
					pr_err(gettext(
					    "%s:%s: access denied\n"),
					    fshost, fspath);
				} else {
					pr_err(gettext("%s:%s: %s\n"), fshost,
					    fspath, errno >= 0 ?
					    strerror(errno) : "invalid error "
					    "returned by server");
				}
			}
			clnt_destroy(cl);
			return (RET_MNTERR);
		}
		args->fh = malloc(sizeof (fhs.fhstatus_u.fhs_fhandle));
		if (args->fh == NULL) {
			pr_err(gettext("no memory\n"));
			return (RET_ERR);
		}
		memcpy((caddr_t)args->fh, (caddr_t)&fhs.fhstatus_u.fhs_fhandle,
		    sizeof (fhs.fhstatus_u.fhs_fhandle));
		if (!errno && posix) {
			rpc_stat = clnt_call(cl, MOUNTPROC_PATHCONF,
			    xdr_dirpath, (caddr_t)&fspath, xdr_ppathcnf,
			    (caddr_t)&p, timeout);
			if (rpc_stat != RPC_SUCCESS) {
				pr_err(gettext(
				    "%s:%s: server not responding %s\n"),
				    fshost, fspath, clnt_sperror(cl, ""));
				free(args->fh);
				clnt_destroy(cl);
				return (RET_RETRY);
			}
			if (_PC_ISSET(_PC_ERROR, p.pc_mask)) {
				pr_err(gettext(
				    "%s:%s: no pathconf info\n"),
				    fshost, fspath);
				free(args->fh);
				clnt_destroy(cl);
				return (RET_ERR);
			}
			args->flags |= NFSMNT_POSIX;
			args->pathconf = malloc(sizeof (p));
			if (args->pathconf == NULL) {
				pr_err(gettext("no memory\n"));
				free(args->fh);
				clnt_destroy(cl);
				return (RET_ERR);
			}
			memcpy((caddr_t)args->pathconf, (caddr_t)&p,
			    sizeof (p));
		}
		break;

	case MOUNTVERS3:
		*versp = nfsvers_to_use = NFS_V3;
		rpc_stat = clnt_call(cl, MOUNTPROC_MNT, xdr_dirpath,
		    (caddr_t)&fspath, xdr_mountres3, (caddr_t)&mountres3,
		    timeout);
		if (rpc_stat != RPC_SUCCESS) {
			pr_err(gettext("%s:%s: server not responding %s\n"),
			    fshost, fspath, clnt_sperror(cl, ""));
			clnt_destroy(cl);
			return (RET_RETRY);
		}

		/*
		 * Assume here that most of the MNT3ERR_*
		 * codes map into E* errors.
		 */
		if ((errno = mountres3.fhs_status) != MNT_OK) {
			if (loud_on_mnt_err) {
				switch (errno) {
				case MNT3ERR_NAMETOOLONG:
					msg = "path name is too long";
					break;
				case MNT3ERR_NOTSUPP:
					msg = "operation not supported";
					break;
				case MNT3ERR_SERVERFAULT:
					msg = "server fault";
					break;
				default:
					if (errno >= 0)
						msg = strerror(errno);
					else
						msg = "invalid error returned "
						    "by server";
					break;
				}
				pr_err(gettext("%s:%s: %s\n"), fshost,
				    fspath, msg);
			}
			clnt_destroy(cl);
			return (RET_MNTERR);
		}

		fh3p = (nfs_fh3 *)malloc(sizeof (*fh3p));
		if (fh3p == NULL) {
			pr_err(gettext("no memory\n"));
			return (RET_ERR);
		}
		fh3p->fh3_length =
		    mountres3.mountres3_u.mountinfo.fhandle.fhandle3_len;
		(void) memcpy(fh3p->fh3_u.data,
		    mountres3.mountres3_u.mountinfo.fhandle.fhandle3_val,
		    fh3p->fh3_length);
		args->fh = (caddr_t)fh3p;
		fstype = MNTTYPE_NFS3;

		/*
		 * Check the security flavor to be used.
		 *
		 * If "secure" or "sec=flavor" is a mount
		 * option, check if the server supports the "flavor".
		 * If the server does not support the flavor, return
		 * error.
		 *
		 * If no mount option is given then look for default auth
		 * (default auth entry in /etc/nfssec.conf) in the auth list
		 * returned from server. If default auth not found, then use
		 * the first supported security flavor (by the client) in the
		 * auth list returned from the server.
		 *
		 */
		auths =
		    mountres3.mountres3_u.mountinfo.auth_flavors
		    .auth_flavors_val;
		count =
		    mountres3.mountres3_u.mountinfo.auth_flavors
		    .auth_flavors_len;

		if (count <= 0) {
			pr_err(gettext(
			    "server %s did not return any security mode\n"),
			    fshost);
			clnt_destroy(cl);
			return (RET_ERR);
		}

		if (sec_opt) {
			for (i = 0; i < count; i++) {
				if (auths[i] == nfs_sec.sc_nfsnum)
					break;
			}
			if (i == count)
				goto autherr;
		} else {
			seconfig_t default_sec;

			/*
			 * Get client configured default auth.
			 */
			nfs_sec.sc_nfsnum = -1;
			default_sec.sc_nfsnum = -1;
			(void) nfs_getseconfig_default(&default_sec);

			/*
			 * Look for clients default auth in servers list.
			 */
			if (default_sec.sc_nfsnum != -1) {
				for (i = 0; i < count; i++) {
					if (auths[i] == default_sec.sc_nfsnum) {
						sec_opt++;
						nfs_sec = default_sec;
						break;
					}
				}
			}

			/*
			 * Could not find clients default auth in servers list.
			 * Pick the first auth from servers list that is
			 * also supported on the client.
			 */
			if (nfs_sec.sc_nfsnum == -1) {
				for (i = 0; i < count; i++) {
					if (!nfs_getseconfig_bynumber(auths[i],
					    &nfs_sec)) {
						sec_opt++;
						break;

					}
				}
			}

			if (i == count)
				goto autherr;
		}
		break;
	default:
		pr_err(gettext("%s:%s: Unknown MOUNT version %d\n"),
		    fshost, fspath, outvers);
		clnt_destroy(cl);
		return (RET_ERR);
	}

	clnt_destroy(cl);
	return (RET_OK);

autherr:
	pr_err(gettext(
	    "security mode does not match the server exporting %s:%s\n"),
	    fshost, fspath);
	clnt_destroy(cl);
	return (RET_ERR);
}

/*
 * Fill in the address for the server's NFS service and
 * fill in a knetconfig structure for the transport that
 * the service is available on.
 */
static int
getaddr_nfs(struct nfs_args *args, char *fshost, struct netconfig **nconfp,
	    bool_t get_pubfh, char *fspath, ushort_t port, err_ret_t *error,
	    bool_t print_rpcerror)
{
	struct stat sb;
	struct netconfig *nconf;
	struct knetconfig *knconfp;
	static int printed = 0;
	struct t_info tinfo;
	err_ret_t addr_error;

	SET_ERR_RET(error, ERR_PROTO_NONE, 0);
	SET_ERR_RET(&addr_error, ERR_PROTO_NONE, 0);

	if (nfs_proto) {
		/*
		 * If a proto is specified and its rdma try this. The kernel
		 * will later do the reachablity test and fail form there
		 * if rdma transport is not available to kernel rpc
		 */
		if (strcmp(nfs_proto, "rdma") == 0) {
			args->addr = get_addr(fshost, NFS_PROGRAM,
			    nfsvers_to_use, nconfp, NULL, port, &tinfo,
			    &args->fh, get_pubfh, fspath, &addr_error);

			args->flags |= NFSMNT_DORDMA;
		} else {
			args->addr = get_addr(fshost, NFS_PROGRAM,
			    nfsvers_to_use, nconfp, nfs_proto, port, &tinfo,
			    &args->fh, get_pubfh, fspath, &addr_error);
		}
	} else {
		args->addr = get_addr(fshost, NFS_PROGRAM, nfsvers_to_use,
		    nconfp, nfs_proto, port, &tinfo, &args->fh, get_pubfh,
		    fspath, &addr_error);
		/*
		 * If no proto is specified set this flag.
		 * Kernel mount code will try to use RDMA if its on the
		 * system, otherwise it will keep on using the protocol
		 * selected here, through the above get_addr call.
		 */
		if (nfs_proto == NULL)
			args->flags |= NFSMNT_TRYRDMA;
	}

	if (args->addr == NULL) {
		/*
		 * We could have failed because the server had no public
		 * file handle support. So don't print a message and don't
		 * retry.
		 */
		if (get_pubfh == TRUE)
			return (RET_ERR);

		if (!printed) {
			switch (addr_error.error_type) {
			case 0:
				printed = 1;
				break;
			case ERR_RPCERROR:
				if (!print_rpcerror)
					/* no error print at this time */
					break;
				pr_err(gettext("%s NFS service not"
				    " available %s\n"), fshost,
				    clnt_sperrno(addr_error.error_value));
				printed = 1;
				break;
			case ERR_NETPATH:
				pr_err(gettext("%s: Error in NETPATH.\n"),
				    fshost);
				printed = 1;
				break;
			case ERR_PROTO_INVALID:
				pr_err(gettext("%s: NFS service does not"
				    " recognize protocol: %s.\n"), fshost,
				    nfs_proto);
				printed = 1;
				break;
			case ERR_PROTO_UNSUPP:
				if (nfsvers || nfsvers_to_use == NFS_VERSMIN) {
					/*
					 * Don't set "printed" here. Since we
					 * have to keep checking here till we
					 * exhaust transport errors on all vers.
					 *
					 * Print this message if:
					 * 1. After we have tried all versions
					 *    of NFS and none support the asked
					 *    transport.
					 *
					 * 2. If a version is specified and it
					 *    does'nt support the asked
					 *    transport.
					 *
					 * Otherwise we decrement the version
					 * and retry below.
					 */
					pr_err(gettext("%s: NFS service does"
					    " not support protocol: %s.\n"),
					    fshost, nfs_proto);
				}
				break;
			case ERR_NOHOST:
				pr_err("%s: %s\n", fshost, "Unknown host");
				printed = 1;
				break;
			default:
				/* case ERR_PROTO_NONE falls through */
				pr_err(gettext("%s: NFS service not responding"
				    "\n"), fshost);
				printed = 1;
				break;
			}
		}
		SET_ERR_RET(error,
		    addr_error.error_type, addr_error.error_value);
		if (addr_error.error_type == ERR_PROTO_NONE)
			return (RET_RETRY);
		else if (addr_error.error_type == ERR_RPCERROR &&
		    !IS_UNRECOVERABLE_RPC(addr_error.error_value)) {
			return (RET_RETRY);
		} else if (nfsvers == 0 && addr_error.error_type ==
		    ERR_PROTO_UNSUPP && nfsvers_to_use != NFS_VERSMIN) {
			/*
			 * If no version is specified, and the error is due
			 * to an unsupported transport, then decrement the
			 * version and retry.
			 */
			return (RET_RETRY);
		} else
			return (RET_ERR);
	}
	nconf = *nconfp;

	if (stat(nconf->nc_device, &sb) < 0) {
		pr_err(gettext("getaddr_nfs: couldn't stat: %s: %s\n"),
		    nconf->nc_device, strerror(errno));
		return (RET_ERR);
	}

	knconfp = (struct knetconfig *)malloc(sizeof (*knconfp));
	if (!knconfp) {
		pr_err(gettext("no memory\n"));
		return (RET_ERR);
	}
	knconfp->knc_semantics = nconf->nc_semantics;
	knconfp->knc_protofmly = nconf->nc_protofmly;
	knconfp->knc_proto = nconf->nc_proto;
	knconfp->knc_rdev = sb.st_rdev;

	/* make sure we don't overload the transport */
	if (tinfo.tsdu > 0 && tinfo.tsdu < NFS_MAXDATA + NFS_RPC_HDR) {
		args->flags |= (NFSMNT_RSIZE | NFSMNT_WSIZE);
		if (args->rsize == 0 || args->rsize > tinfo.tsdu - NFS_RPC_HDR)
			args->rsize = tinfo.tsdu - NFS_RPC_HDR;
		if (args->wsize == 0 || args->wsize > tinfo.tsdu - NFS_RPC_HDR)
			args->wsize = tinfo.tsdu - NFS_RPC_HDR;
	}

	args->flags |= NFSMNT_KNCONF;
	args->knconf = knconfp;
	return (RET_OK);
}

static int
retry(struct mnttab *mntp, int ro)
{
	int delay = 5;
	int count = retries;
	int r;

	/*
	 * Please see comments on nfsretry_vers in the beginning of this file
	 * and in main() routine.
	 */

	if (bg) {
		if (fork() > 0)
			return (RET_OK);
		backgrounded = 1;
		pr_err(gettext("backgrounding: %s\n"), mntp->mnt_mountp);
	} else {
		if (!nfsretry_vers)
			pr_err(gettext("retrying: %s\n"), mntp->mnt_mountp);
	}

	while (count--) {
		if ((r = mount_nfs(mntp, ro, NULL)) == RET_OK) {
			pr_err(gettext("%s: mounted OK\n"), mntp->mnt_mountp);
			return (RET_OK);
		}
		if (r != RET_RETRY)
			break;

		if (count > 0) {
			(void) sleep(delay);
			delay *= 2;
			if (delay > 120)
				delay = 120;
		}
	}

	if (!nfsretry_vers)
		pr_err(gettext("giving up on: %s\n"), mntp->mnt_mountp);

	return (RET_ERR);
}

/*
 * Read the NFS SMF Parameters  to determine if the
 * client has been configured for a new min/max for the NFS version to
 * use.
 */
static void
read_default(void)
{
	char value[4];
	int errno;
	int tmp = 0, bufsz = 0, ret = 0;

	/* Maximum number of bytes expected. */
	bufsz = 4;
	ret = nfs_smf_get_prop("client_versmin", value, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, SVC_NFS_CLIENT, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		tmp = strtol(value, (char **)NULL, 10);
		if (errno == 0) {
			vers_min_default = tmp;
		}
	}

	/* Maximum number of bytes expected. */
	bufsz = 4;
	ret = nfs_smf_get_prop("client_versmax", value, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, SVC_NFS_CLIENT, &bufsz);
	if (ret == SA_OK) {
		errno = 0;
		tmp = strtol(value, (char **)NULL, 10);
		if (errno == 0) {
			vers_max_default = tmp;
		}
	}
}

static void
sigusr1(int s)
{
}
