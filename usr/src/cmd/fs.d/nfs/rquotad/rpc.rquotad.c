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
 * Copyright 2017 Joyent Inc
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <stropts.h>
#include <errno.h>
#include <sys/netconfig.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/debug.h>
#ifdef notdef
#include <netconfig.h>
#endif
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/fs/ufs_quota.h>
#include <netdir.h>
#include <rpc/rpc.h>
#include <rpcsvc/rquota.h>
#include <tiuser.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libzfs.h>

#define	QFNAME		"quotas"	/* name of quota file */
#define	RPCSVC_CLOSEDOWN 120		/* 2 minutes */

struct fsquot {
	char *fsq_fstype;
	struct fsquot *fsq_next;
	char *fsq_dir;
	char *fsq_devname;
	dev_t fsq_dev;
};

struct fsquot *fsqlist = NULL;

typedef struct authunix_parms *authp;

static int request_pending;		/* Request in progress ? */

void closedown();
void dispatch();
struct fsquot *findfsq();
void freefs();
int  getdiskquota();
void getquota();
int  hasquota();
void log_cant_reply();
void setupfs();
static void zexit();

static libzfs_handle_t *(*_libzfs_init)(void);
static void (*_libzfs_fini)(libzfs_handle_t *);
static zfs_handle_t *(*_zfs_open)(libzfs_handle_t *, const char *, int);
static void (*_zfs_close)(zfs_handle_t *);
static int (*_zfs_prop_get_userquota_int)(zfs_handle_t *, const char *,
    uint64_t *);
static libzfs_handle_t *g_zfs = NULL;

/*
 * Dynamically check for libzfs, in case the user hasn't installed the SUNWzfs
 * packages.  'rquotad' supports zfs as an option.
 */
static void
load_libzfs(void)
{
	void *hdl;

	if (g_zfs != NULL)
		return;

	if ((hdl = dlopen("libzfs.so", RTLD_LAZY)) != NULL) {
		_libzfs_init = (libzfs_handle_t *(*)(void))dlsym(hdl,
		    "libzfs_init");
		_libzfs_fini = (void (*)())dlsym(hdl, "libzfs_fini");
		_zfs_open = (zfs_handle_t *(*)())dlsym(hdl, "zfs_open");
		_zfs_close = (void (*)())dlsym(hdl, "zfs_close");
		_zfs_prop_get_userquota_int = (int (*)())
		    dlsym(hdl, "zfs_prop_get_userquota_int");

		if (_libzfs_init && _libzfs_fini && _zfs_open &&
		    _zfs_close && _zfs_prop_get_userquota_int)
			g_zfs = _libzfs_init();
	}
}

/*ARGSUSED*/
int
main(int argc, char *argv[])
{
	register SVCXPRT *transp;

	load_libzfs();

	/*
	 * If stdin looks like a TLI endpoint, we assume
	 * that we were started by a port monitor. If
	 * t_getstate fails with TBADF, this is not a
	 * TLI endpoint.
	 */
	if (t_getstate(0) != -1 || t_errno != TBADF) {
		char *netid;
		struct netconfig *nconf = NULL;

		openlog("rquotad", LOG_PID, LOG_DAEMON);

		if ((netid = getenv("NLSPROVIDER")) == NULL) {
			struct t_info tinfo;

			if (t_sync(0) == -1) {
				syslog(LOG_ERR, "could not do t_sync");
				zexit(1);
			}
			if (t_getinfo(0, &tinfo) == -1) {
				syslog(LOG_ERR, "t_getinfo failed");
				zexit(1);
			}
			if (tinfo.servtype == T_CLTS) {
				if (tinfo.addr == INET_ADDRSTRLEN)
					netid = "udp";
				else
					netid = "udp6";
			} else {
				syslog(LOG_ERR, "wrong transport");
				zexit(1);
			}
		}
		if ((nconf = getnetconfigent(netid)) == NULL) {
			syslog(LOG_ERR, "cannot get transport info");
		}

		if ((transp = svc_tli_create(0, nconf, NULL, 0, 0)) == NULL) {
			syslog(LOG_ERR, "cannot create server handle");
			zexit(1);
		}
		if (nconf)
			freenetconfigent(nconf);

		if (!svc_reg(transp, RQUOTAPROG, RQUOTAVERS, dispatch, 0)) {
			syslog(LOG_ERR,
			    "unable to register (RQUOTAPROG, RQUOTAVERS).");
			zexit(1);
		}

		(void) sigset(SIGALRM, (void(*)(int)) closedown);
		(void) alarm(RPCSVC_CLOSEDOWN);

		svc_run();
		zexit(1);
		/* NOTREACHED */
	}

	/*
	 * Started from a shell - fork the daemon.
	 */

	switch (fork()) {
	case 0:		/* child */
		break;
	case -1:
		perror("rquotad: can't fork");
		zexit(1);
	default:	/* parent */
		zexit(0);
	}

	/*
	 * Close existing file descriptors, open "/dev/null" as
	 * standard input, output, and error, and detach from
	 * controlling terminal.
	 */
	closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();

	openlog("rquotad", LOG_PID, LOG_DAEMON);

	/*
	 * Create datagram service
	 */
	if (svc_create(dispatch, RQUOTAPROG, RQUOTAVERS, "datagram_v") == 0) {
		syslog(LOG_ERR, "couldn't register datagram_v service");
		zexit(1);
	}

	/*
	 * Start serving
	 */
	svc_run();
	syslog(LOG_ERR, "Error: svc_run shouldn't have returned");
	return (1);
}

void
dispatch(rqstp, transp)
	register struct svc_req *rqstp;
	register SVCXPRT *transp;
{

	request_pending = 1;

	switch (rqstp->rq_proc) {
	case NULLPROC:
		errno = 0;
		if (!svc_sendreply(transp, xdr_void, 0))
			log_cant_reply(transp);
		break;

	case RQUOTAPROC_GETQUOTA:
	case RQUOTAPROC_GETACTIVEQUOTA:
		getquota(rqstp, transp);
		break;

	default:
		svcerr_noproc(transp);
		break;
	}

	request_pending = 0;
}

void
closedown()
{
	if (!request_pending) {
		int i, openfd;
		struct t_info tinfo;

		if (!t_getinfo(0, &tinfo) && (tinfo.servtype == T_CLTS))
			zexit(0);

		for (i = 0, openfd = 0; i < svc_max_pollfd && openfd < 2; i++) {
			if (svc_pollfd[i].fd >= 0)
				openfd++;
		}

		if (openfd <= 1)
			zexit(0);
	}
	(void) alarm(RPCSVC_CLOSEDOWN);
}

static int
getzfsquota(uid_t user, char *dataset, struct dqblk *zq)
{
	zfs_handle_t *zhp = NULL;
	char propname[ZFS_MAXPROPLEN];
	uint64_t userquota, userused;

	if (g_zfs == NULL)
		return (1);

	if ((zhp = _zfs_open(g_zfs, dataset, ZFS_TYPE_DATASET)) == NULL) {
		syslog(LOG_ERR, "can not open zfs dataset %s", dataset);
		return (1);
	}

	(void) snprintf(propname, sizeof (propname), "userquota@%u", user);
	if (_zfs_prop_get_userquota_int(zhp, propname, &userquota) != 0) {
		_zfs_close(zhp);
		return (1);
	}

	(void) snprintf(propname, sizeof (propname), "userused@%u", user);
	if (_zfs_prop_get_userquota_int(zhp, propname, &userused) != 0) {
		_zfs_close(zhp);
		return (1);
	}

	zq->dqb_bhardlimit = userquota / DEV_BSIZE;
	zq->dqb_bsoftlimit = userquota / DEV_BSIZE;
	zq->dqb_curblocks = userused / DEV_BSIZE;
	_zfs_close(zhp);
	return (0);
}

void
getquota(rqstp, transp)
	register struct svc_req *rqstp;
	register SVCXPRT *transp;
{
	struct getquota_args gqa;
	struct getquota_rslt gqr;
	struct dqblk dqblk;
	struct fsquot *fsqp;
	struct timeval tv;
	bool_t qactive;

	gqa.gqa_pathp = NULL;		/* let xdr allocate the storage */
	if (!svc_getargs(transp, xdr_getquota_args, (caddr_t)&gqa)) {
		svcerr_decode(transp);
		return;
	}
	/*
	 * This authentication is really bogus with the current rpc
	 * authentication scheme. One day we will have something for real.
	 */
	CTASSERT(sizeof (authp) <= RQCRED_SIZE);
	if (rqstp->rq_cred.oa_flavor != AUTH_UNIX ||
	    (((authp) rqstp->rq_clntcred)->aup_uid != 0 &&
		((authp) rqstp->rq_clntcred)->aup_uid != (uid_t)gqa.gqa_uid)) {
		gqr.status = Q_EPERM;
		goto sendreply;
	}
	fsqp = findfsq(gqa.gqa_pathp);
	if (fsqp == NULL) {
		gqr.status = Q_NOQUOTA;
		goto sendreply;
	}

	bzero(&dqblk, sizeof (dqblk));
	if (strcmp(fsqp->fsq_fstype, MNTTYPE_ZFS) == 0) {
		if (getzfsquota(gqa.gqa_uid, fsqp->fsq_devname, &dqblk)) {
			gqr.status = Q_NOQUOTA;
			goto sendreply;
		}
		qactive = TRUE;
	} else {
		if (quotactl(Q_GETQUOTA, fsqp->fsq_dir,
		    (uid_t)gqa.gqa_uid, &dqblk) != 0) {
			qactive = FALSE;
			if ((errno == ENOENT) ||
			    (rqstp->rq_proc != RQUOTAPROC_GETQUOTA)) {
				gqr.status = Q_NOQUOTA;
				goto sendreply;
			}

			/*
			 * If there is no quotas file, don't bother to sync it.
			 */
			if (errno != ENOENT) {
				if (quotactl(Q_ALLSYNC, fsqp->fsq_dir,
				    (uid_t)gqa.gqa_uid, &dqblk) < 0 &&
				    errno == EINVAL)
					syslog(LOG_WARNING,
					    "Quotas are not compiled "
					    "into this kernel");
				if (getdiskquota(fsqp, (uid_t)gqa.gqa_uid,
				    &dqblk) == 0) {
					gqr.status = Q_NOQUOTA;
					goto sendreply;
				}
			}
		} else {
			qactive = TRUE;
		}
		/*
		 * We send the remaining time instead of the absolute time
		 * because clock skew between machines should be much greater
		 * than rpc delay.
		 */
#define	gqrslt getquota_rslt_u.gqr_rquota

		gettimeofday(&tv, NULL);
		gqr.gqrslt.rq_btimeleft	= dqblk.dqb_btimelimit - tv.tv_sec;
		gqr.gqrslt.rq_ftimeleft	= dqblk.dqb_ftimelimit - tv.tv_sec;
	}

	gqr.status = Q_OK;
	gqr.gqrslt.rq_active	= qactive;
	gqr.gqrslt.rq_bsize	= DEV_BSIZE;
	gqr.gqrslt.rq_bhardlimit = dqblk.dqb_bhardlimit;
	gqr.gqrslt.rq_bsoftlimit = dqblk.dqb_bsoftlimit;
	gqr.gqrslt.rq_curblocks = dqblk.dqb_curblocks;
	gqr.gqrslt.rq_fhardlimit = dqblk.dqb_fhardlimit;
	gqr.gqrslt.rq_fsoftlimit = dqblk.dqb_fsoftlimit;
	gqr.gqrslt.rq_curfiles	= dqblk.dqb_curfiles;
sendreply:
	errno = 0;
	if (!svc_sendreply(transp, xdr_getquota_rslt, (caddr_t)&gqr))
		log_cant_reply(transp);
}

int
quotactl(cmd, mountp, uid, dqp)
	int	cmd;
	char	*mountp;
	uid_t	uid;
	struct dqblk *dqp;
{
	int 		fd;
	int 		status;
	struct quotctl 	quota;
	char		mountpoint[256];
	FILE		*fstab;
	struct mnttab	mntp;

	if ((mountp == NULL) && (cmd == Q_ALLSYNC)) {
		/*
		 * Find the mount point of any ufs file system. this is
		 * because the ioctl that implements the quotactl call has
		 * to go to a real file, and not to the block device.
		 */
		if ((fstab = fopen(MNTTAB, "r")) == NULL) {
			syslog(LOG_ERR, "can not open %s: %m ", MNTTAB);
			return (-1);
		}
		fd = -1;
		while ((status = getmntent(fstab, &mntp)) == NULL) {
			if (strcmp(mntp.mnt_fstype, MNTTYPE_UFS) != 0 ||
				!(hasmntopt(&mntp, MNTOPT_RQ) ||
				hasmntopt(&mntp, MNTOPT_QUOTA)))
				continue;
			(void) strlcpy(mountpoint, mntp.mnt_mountp,
			    sizeof (mountpoint));
			strcat(mountpoint, "/quotas");
			if ((fd = open64(mountpoint, O_RDWR)) >= 0)
				break;
		}
		fclose(fstab);
		if (fd == -1) {
			errno = ENOENT;
			return (-1);
		}
	} else {
		if (mountp == NULL || mountp[0] == '\0') {
			errno = ENOENT;
			return (-1);
		}
		(void) strlcpy(mountpoint, mountp, sizeof (mountpoint));
		strcat(mountpoint, "/quotas");

		if ((fd = open64(mountpoint, O_RDONLY)) < 0) {
			errno = ENOENT;
			syslog(LOG_ERR, "can not open %s: %m ", mountpoint);
			return (-1);
		}
	}
	quota.op = cmd;
	quota.uid = uid;
	quota.addr = (caddr_t)dqp;

	status = ioctl(fd, Q_QUOTACTL, &quota);

	close(fd);
	return (status);
}

/*
 * Return the quota information for the given path.  Returns NULL if none
 * was found.
 */

struct fsquot *
findfsq(char *dir)
{
	struct stat sb;
	struct fsquot *fsqp;
	static time_t lastmtime = 0; 	/* mount table's previous mtime */

	/*
	 * If we've never looked at the mount table, or it has changed
	 * since the last time, rebuild the list of quota'd file systems
	 * and remember the current mod time for the mount table.
	 */

	if (stat(MNTTAB, &sb) < 0) {
		syslog(LOG_ERR, "can't stat %s: %m", MNTTAB);
		return (NULL);
	}
	if (lastmtime == 0 || sb.st_mtime != lastmtime) {
		freefs();
		setupfs();
		lastmtime = sb.st_mtime;
	}

	/*
	 * Try to find the given path in the list of file systems with
	 * quotas.
	 */

	if (fsqlist == NULL)
		return (NULL);
	if (stat(dir, &sb) < 0)
		return (NULL);

	for (fsqp = fsqlist; fsqp != NULL; fsqp = fsqp->fsq_next) {
		if (sb.st_dev == fsqp->fsq_dev)
			return (fsqp);
	}

	return (NULL);
}

static void
setup_zfs(struct mnttab *mp)
{
	struct fsquot *fsqp;
	struct stat sb;

	if (stat(mp->mnt_mountp, &sb) < 0)
		return;

	fsqp = malloc(sizeof (struct fsquot));
	if (fsqp == NULL) {
		syslog(LOG_ERR, "out of memory");
		zexit(1);
	}
	fsqp->fsq_dir = strdup(mp->mnt_mountp);
	fsqp->fsq_devname = strdup(mp->mnt_special);
	if (fsqp->fsq_dir == NULL || fsqp->fsq_devname == NULL) {
		syslog(LOG_ERR, "out of memory");
		zexit(1);
	}

	fsqp->fsq_fstype = MNTTYPE_ZFS;
	fsqp->fsq_dev = sb.st_dev;
	fsqp->fsq_next = fsqlist;
	fsqlist = fsqp;
}

void
setupfs()
{
	struct fsquot *fsqp;
	FILE *mt;
	struct mnttab m;
	struct stat sb;
	char qfilename[MAXPATHLEN];

	mt = fopen(MNTTAB, "r");
	if (mt == NULL) {
		syslog(LOG_ERR, "can't read %s: %m", MNTTAB);
		return;
	}

	while (getmntent(mt, &m) == 0) {
		if (strcmp(m.mnt_fstype, MNTTYPE_ZFS) == 0) {
			setup_zfs(&m);
			continue;
		}

		if (strcmp(m.mnt_fstype, MNTTYPE_UFS) != 0)
			continue;
		if (!hasquota(m.mnt_mntopts)) {
			snprintf(qfilename, sizeof (qfilename), "%s/%s",
			    m.mnt_mountp, QFNAME);
			if (access(qfilename, F_OK) < 0)
				continue;
		}
		if (stat(m.mnt_special, &sb) < 0 ||
		    (sb.st_mode & S_IFMT) != S_IFBLK)
			continue;
		fsqp = malloc(sizeof (struct fsquot));
		if (fsqp == NULL) {
			syslog(LOG_ERR, "out of memory");
			zexit(1);
		}
		fsqp->fsq_dir = strdup(m.mnt_mountp);
		fsqp->fsq_devname = strdup(m.mnt_special);
		if (fsqp->fsq_dir == NULL || fsqp->fsq_devname == NULL) {
			syslog(LOG_ERR, "out of memory");
			zexit(1);
		}
		fsqp->fsq_fstype = MNTTYPE_UFS;
		fsqp->fsq_dev = sb.st_rdev;
		fsqp->fsq_next = fsqlist;
		fsqlist = fsqp;
	}
	(void) fclose(mt);
}

/*
 * Free the memory used by the current list of quota'd file systems.  Nulls
 * out the list.
 */

void
freefs()
{
	register struct fsquot *fsqp;

	while ((fsqp = fsqlist) != NULL) {
		fsqlist = fsqp->fsq_next;
		free(fsqp->fsq_dir);
		free(fsqp->fsq_devname);
		free(fsqp);
	}
}

int
getdiskquota(fsqp, uid, dqp)
	struct fsquot *fsqp;
	uid_t uid;
	struct dqblk *dqp;
{
	int fd;
	char qfilename[MAXPATHLEN];

	snprintf(qfilename, sizeof (qfilename), "%s/%s", fsqp->fsq_dir, QFNAME);
	if ((fd = open64(qfilename, O_RDONLY)) < 0)
		return (0);
	(void) llseek(fd, (offset_t)dqoff(uid), L_SET);
	if (read(fd, dqp, sizeof (struct dqblk)) != sizeof (struct dqblk)) {
		close(fd);
		return (0);
	}
	close(fd);
	if (dqp->dqb_bhardlimit == 0 && dqp->dqb_bsoftlimit == 0 &&
	    dqp->dqb_fhardlimit == 0 && dqp->dqb_fsoftlimit == 0) {
		return (0);
	}
	return (1);
}

/*
 * Get the client's hostname from the transport handle
 * If the name is not available then return "(anon)".
 */
struct nd_hostservlist *
getclientsnames(transp)
	SVCXPRT *transp;
{
	struct netbuf *nbuf;
	struct netconfig *nconf;
	static struct nd_hostservlist	*serv;
	static struct nd_hostservlist	anon_hsl;
	static struct nd_hostserv	anon_hs;
	static char anon_hname[] = "(anon)";
	static char anon_sname[] = "";

	/* Set up anonymous client */
	anon_hs.h_host = anon_hname;
	anon_hs.h_serv = anon_sname;
	anon_hsl.h_cnt = 1;
	anon_hsl.h_hostservs = &anon_hs;

	if (serv) {
		netdir_free((char *)serv, ND_HOSTSERVLIST);
		serv = NULL;
	}
	nconf = getnetconfigent(transp->xp_netid);
	if (nconf == NULL) {
		syslog(LOG_ERR, "%s: getnetconfigent failed",
			transp->xp_netid);
		return (&anon_hsl);
	}

	nbuf = svc_getrpccaller(transp);
	if (nbuf == NULL) {
		freenetconfigent(nconf);
		return (&anon_hsl);
	}
	if (netdir_getbyaddr(nconf, &serv, nbuf)) {
		freenetconfigent(nconf);
		return (&anon_hsl);
	}
	freenetconfigent(nconf);
	return (serv);
}

void
log_cant_reply(transp)
	SVCXPRT *transp;
{
	int saverrno;
	struct nd_hostservlist *clnames;
	register char *name;

	saverrno = errno;	/* save error code */
	clnames = getclientsnames(transp);
	if (clnames == NULL)
		return;
	name = clnames->h_hostservs->h_host;

	errno = saverrno;
	if (errno == 0)
		syslog(LOG_ERR, "couldn't send reply to %s", name);
	else
		syslog(LOG_ERR, "couldn't send reply to %s: %m", name);
}

char *mntopts[] = { MNTOPT_QUOTA, NULL };
#define	QUOTA    0

/*
 * Return 1 if "quota" appears in the options string
 */
int
hasquota(opts)
	char *opts;
{
	char *value;

	if (opts == NULL)
		return (0);
	while (*opts != '\0') {
		if (getsubopt(&opts, mntopts, &value) == QUOTA)
			return (1);
	}

	return (0);
}

static void
zexit(int n)
{
	if (g_zfs != NULL)
		_libzfs_fini(g_zfs);
	exit(n);
}
