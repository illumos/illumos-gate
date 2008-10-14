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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/resource.h>
#include <sys/priocntl.h>
#include <sys/rtpriocntl.h>
#include <sys/tspriocntl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <strings.h>
#include <thread.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <locale.h>
#include <unistd.h>
#include <syslog.h>

#include <sys/nsctl/cfg.h>
#include <sys/nsctl/nsctl.h>
#include <sys/nsctl/nsc_ioctl.h>
#include <sys/nskernd.h>
#include <nsctl.h>

#include <sys/mkdev.h>
#include <sys/nsctl/sv_efi.h>

static const char *rdev = "/dev/nsctl";

/*
 * Define a minimal user stack size in bytes over and above the
 * libthread THR_STACK_MIN minimum value.
 *
 * This stack size needs to be sufficient to run _newlwp() and then
 * ioctl() down into the kernel.
 */
#define	NSK_STACK_SIZE	512

/*
 * LWP scheduling control switches.
 *
 * allow_pri	- set to non-zero to enable priocntl() manipulations of
 *		created LWPs.
 * allow_rt	- set to non-zero to use the RT rather than the TS
 *		scheduling class when manipulating the schduling
 *		parameters for an LWP.  Only used if allow_pri is
 *		non-zero.
 */
static int allow_pri = 1;
static int allow_rt = 0;	/* disallow - bad interactions with timeout() */

static int nsctl_fd = -1;
static int sigterm;

static int nthreads;		/* number of threads in the kernel */
static int exiting;		/* shutdown in progress flag */
static mutex_t thr_mutex = DEFAULTMUTEX;
static mutex_t cfg_mutex = DEFAULTMUTEX;

static int cl_nodeid = -1;

static int display_msg = 0;
static int delay_time = 30;

static void
usage(void)
{
	fprintf(stderr, gettext("usage: nskernd\n"));
	exit(255);
}


static void
sighand(int sig)
{
	if (sig == SIGTERM) {
		sigterm++;
	}
}


/*
 * Returns: 1 - can enter kernel; 0 - shutdown in progress, do not enter kernel
 */
int
nthread_inc(void)
{
	mutex_lock(&thr_mutex);
	if (exiting) {
		/* cannot enter kernel as nskernd is being shutdown - exit */
		mutex_unlock(&thr_mutex);
		return (0);
	}
	nthreads++;
	mutex_unlock(&thr_mutex);
	return (1);
}


void
nthread_dec(void)
{
	mutex_lock(&thr_mutex);
	nthreads--;
	mutex_unlock(&thr_mutex);
}


/*
 * returns: 1 - can shutdown; 0 - unable to shutdown
 */
int
canshutdown(void)
{
	int rc = 1;
	time_t	start_delay;

	mutex_lock(&thr_mutex);
	if (nthreads > 0) {
		if (display_msg) {
			fprintf(stderr,
			    gettext("nskernd: unable to shutdown: "
			    "%d kernel threads in use\n"), nthreads);
		}
		start_delay = time(0);
		while (nthreads > 0 && (time(0) - start_delay) < delay_time) {
			mutex_unlock(&thr_mutex);
			sleep(1);
			mutex_lock(&thr_mutex);
			fprintf(stderr,
			    gettext("nskernd:   delay shutdown: "
			    "%d kernel threads in use\n"), nthreads);
		}
		if (nthreads > 0) {
			rc = 0;
		} else {
			exiting = 1;
		}
	} else {
		/* flag shutdown in progress */
		exiting = 1;
	}
	mutex_unlock(&thr_mutex);

	return (rc);
}


/*
 * returns: 1 - shutdown successful; 0 - unable to shutdown
 */
int
shutdown(void)
{
	struct nskernd data;
	int rc;

	if (nsctl_fd < 0)
		return (1);

	bzero(&data, sizeof (data));
	data.command = NSKERND_STOP;

	if (!canshutdown()) {
		return (0);
	}

	rc = ioctl(nsctl_fd, NSCIOC_NSKERND, &data);
	if (rc < 0) {
		if (errno != EINTR || !sigterm) {
			fprintf(stderr,
			    gettext("nskernd: NSKERND_STOP failed\n"));
		}
	}

	return (1);
}


/*
 * First function run by a NSKERND_NEWLWP thread.
 *
 * Determines if it needs to change the scheduling priority of the LWP,
 * and then calls back into the kernel.
 */
static void *
_newlwp(void *arg)
{
	struct nskernd nsk;
	pcparms_t pcparms;
	pcinfo_t pcinfo;

	/* copy arguments onto stack and free heap memory */
	bcopy(arg, &nsk, sizeof (nsk));
	free(arg);

	if (nsk.data2 && allow_pri) {
		/* increase the scheduling priority of this LWP */

		bzero(&pcinfo, sizeof (pcinfo));
		strcpy(pcinfo.pc_clname, allow_rt ? "RT" : "TS");

		if (priocntl(0, 0, PC_GETCID, (char *)&pcinfo) < 0) {
			fprintf(stderr,
				gettext(
				"nskernd: priocntl(PC_GETCID) failed: %s\n"),
				strerror(errno));
			goto pri_done;
		}

		bzero(&pcparms, sizeof (pcparms));
		pcparms.pc_cid = pcinfo.pc_cid;

		if (allow_rt) {
			((rtparms_t *)pcparms.pc_clparms)->rt_pri =
				(pri_t)0; /* minimum RT priority */
			((rtparms_t *)pcparms.pc_clparms)->rt_tqsecs =
				(uint_t)RT_TQDEF;
			((rtparms_t *)pcparms.pc_clparms)->rt_tqnsecs =
				RT_TQDEF;
		} else {
			((tsparms_t *)pcparms.pc_clparms)->ts_uprilim =
				((tsinfo_t *)&pcinfo.pc_clinfo)->ts_maxupri;
			((tsparms_t *)pcparms.pc_clparms)->ts_upri =
				((tsinfo_t *)&pcinfo.pc_clinfo)->ts_maxupri;
		}

		if (priocntl(P_LWPID, P_MYID,
		    PC_SETPARMS, (char *)&pcparms) < 0) {
			fprintf(stderr,
				gettext(
				"nskernd: priocntl(PC_SETPARMS) failed: %s\n"),
				strerror(errno));
		}
	}

pri_done:
	if (nthread_inc()) {
		(void) ioctl(nsctl_fd, NSCIOC_NSKERND, &nsk);
		nthread_dec();
	}
	return (NULL);
}


/*
 * Start a new thread bound to an LWP.
 *
 * This is the user level side of nsc_create_process().
 */
static void
newlwp(struct nskernd *req)
{
	struct nskernd *nskp;
	thread_t tid;
	int rc;

	nskp = malloc(sizeof (*nskp));
	if (!nskp) {
#ifdef DEBUG
		fprintf(stderr, gettext("nskernd: malloc(%d) failed\n"),
			sizeof (*nskp));
#endif
		req->data1 = (uint64_t)ENOMEM;
		return;
	}

	/* copy args for child */
	bcopy(req, nskp, sizeof (*nskp));

	rc = thr_create(NULL, (THR_MIN_STACK + NSK_STACK_SIZE),
		_newlwp, nskp, THR_BOUND|THR_DETACHED, &tid);

	if (rc != 0) {
		/* thr_create failed */
#ifdef DEBUG
		fprintf(stderr, gettext("nskernd: thr_create failed: %s\n"),
			strerror(errno));
#endif
		req->data1 = (uint64_t)errno;
		free(nskp);
	} else {
		/* success - _newlwp() will free nskp */
		req->data1 = (uint64_t)0;
	}
}

static int
log_iibmp_err(char *set, int flags)
{
	CFGFILE *cfg;
	char key[CFG_MAX_KEY];
	char buf[CFG_MAX_BUF];
	char newflags[CFG_MAX_BUF];
	char outbuf[CFG_MAX_BUF];
	char *mst, *shd, *bmp, *mode, *ovr, *cnode, *opt, *grp;
	int setno, found = 0;
	int setlen;
	int rc = 0;
	pid_t pid = -1;

	if (set && *set) {
		setlen = strlen(set);
	} else {
		return (EINVAL);
	}

	mutex_lock(&cfg_mutex);
	cfg = cfg_open("");
	if (!cfg) {
		mutex_unlock(&cfg_mutex);
		return (ENXIO);
	}

	if (!cfg_lock(cfg, CFG_WRLOCK)) {

		mutex_unlock(&cfg_mutex);
		cfg_close(cfg);

		pid = fork();

		if (pid == -1) {
			fprintf(stderr, gettext(
			    "nskernd: Error forking\n"));
			return (errno);
		} else if (pid > 0) {
			fprintf(stdout, gettext(
			    "nskernd: Attempting deferred bitmap error\n"));
			return (0);
		}

		mutex_lock(&cfg_mutex);
		cfg = cfg_open("");
		if (!cfg) {
			mutex_unlock(&cfg_mutex);
			fprintf(stderr, gettext(
			    "nskernd: Failed cfg_open, deferred bitmap\n"));
			return (ENXIO);
		}

		/* Sooner or later, this lock will be free */
		while (!cfg_lock(cfg, CFG_WRLOCK))
			sleep(2);
	}

	/* find the proper set number */
	for (setno = 1; !found; setno++) {
		snprintf(key, CFG_MAX_KEY, "ii.set%d", setno);
		if (cfg_get_cstring(cfg, key, buf, CFG_MAX_BUF) < 0) {
			break;
		}

		mst = strtok(buf, " ");
		shd = strtok(NULL, " ");
		if (strncmp(shd, set, setlen) == 0) {
			found = 1;

			bmp = strtok(NULL, " ");
			mode = strtok(NULL, " ");
			ovr = strtok(NULL, " ");
			cnode = strtok(NULL, " ");
			opt = strtok(NULL, " ");
			grp = strtok(NULL, " ");
			break;
		}
	}

	if (found) {
		/* were there flags in the options field already? */
		snprintf(newflags, CFG_MAX_BUF, "%s=0x%x",
		    NSKERN_II_BMP_OPTION, flags);
		if (opt && strcmp(opt, "-") != 0) {
			bzero(newflags, CFG_MAX_BUF);
			opt = strtok(opt, ";");
			while (opt) {
				if (strncmp(opt, NSKERN_II_BMP_OPTION,
				    strlen(NSKERN_II_BMP_OPTION)) != 0) {
					strcat(newflags, ";");
					strcat(newflags, opt);
				}
			}
		}
		snprintf(key, CFG_MAX_KEY, "ii.set%d", setno);
		snprintf(outbuf, CFG_MAX_BUF, "%s %s %s %s %s %s %s %s",
			mst, shd, bmp, mode, ovr, cnode, newflags, grp);
		if (cfg_put_cstring(cfg, key, outbuf, CFG_MAX_BUF) < 0) {
			printf("Failed to put [%s]\n", outbuf);
			rc = ENXIO;
		} else {
			cfg_commit(cfg);
			rc = 0;
		}
	} else {
		fprintf(stderr, gettext(
			    "nskernd: Failed deferred bitmap [%s]\n"), set);
		rc = EINVAL;
	}
	cfg_unlock(cfg);
	cfg_close(cfg);
	mutex_unlock(&cfg_mutex);

	/*
	 * if we are the fork'ed client, just exit, if parent just return
	 */
	if (pid == 0) {
		exit(rc);
		/*NOTREACHED*/
	} else {
		return (rc);
	}
}

/*
 * First function run by a NSKERND_LOCK thread.
 *
 * Opens dscfg and locks it,
 * and then calls back into the kernel.
 *
 * Incoming:
 *	data1 is the kernel address of the sync structure.
 *	data2 is read(0)/write(1) lock mode.
 *
 * Returns:
 *	data1 as incoming.
 *	data2 errno.
 */
static void *
_dolock(void *arg)
{
	struct nskernd nsk;
	CFGFILE *cfg;
	int locked;
	int mode;
	int rc = 0;

	/* copy arguments onto stack and free heap memory */
	bcopy(arg, &nsk, sizeof (nsk));
	free(arg);

	mutex_lock(&cfg_mutex);
	cfg = cfg_open("");
	if (cfg == NULL) {
#ifdef DEBUG
		fprintf(stderr, gettext("nskernd: cfg_open failed: %s\n"),
		    strerror(errno));
#endif
		rc = ENXIO;
	}

	if (nsk.data2 == 0) {
		mode = CFG_RDLOCK;
	} else {
		mode = CFG_WRLOCK;
	}

	locked = 0;
	if (rc == 0) {
		if (cfg_lock(cfg, mode)) {
			locked = 1;
		} else {
#ifdef DEBUG
			fprintf(stderr,
			    gettext("nskernd: cfg_lock failed: %s\n"),
			    strerror(errno));
#endif
			rc = EINVAL;
		}
	}

	/* return to kernel */

	nsk.data2 = (uint64_t)rc;
	if (nthread_inc()) {
		(void) ioctl(nsctl_fd, NSCIOC_NSKERND, &nsk);
		nthread_dec();
	}

	/* cleanup */

	if (locked) {
		cfg_unlock(cfg);
		locked = 0;
	}

	if (cfg != NULL) {
		cfg_close(cfg);
		cfg = NULL;
	}
	mutex_unlock(&cfg_mutex);

	return (NULL);
}


/*
 * Inter-node lock thread.
 *
 * This is the user level side of nsc_rmlock().
 */
static void
dolock(struct nskernd *req)
{
	struct nskernd *nskp;
	thread_t tid;
	int rc;

	/* create a new thread to do the lock and return to kernel */

	nskp = malloc(sizeof (*nskp));
	if (!nskp) {
#ifdef DEBUG
		fprintf(stderr, gettext("nskernd:dolock: malloc(%d) failed\n"),
		    sizeof (*nskp));
#endif
		req->data1 = (uint64_t)ENOMEM;
		return;
	}

	/* copy args for child */
	bcopy(req, nskp, sizeof (*nskp));

	rc = thr_create(NULL, (THR_MIN_STACK + NSK_STACK_SIZE),
	    _dolock, nskp, THR_BOUND|THR_DETACHED, &tid);

	if (rc != 0) {
		/* thr_create failed */
#ifdef DEBUG
		fprintf(stderr, gettext("nskernd: thr_create failed: %s\n"),
		    strerror(errno));
#endif
		req->data1 = (uint64_t)errno;
		free(nskp);
	} else {
		/* success - _dolock() will free nskp */
		req->data1 = (uint64_t)0;
	}
}


/*
 * Convenience code for engineering test of multi-terabyte volumes.
 *
 * zvol (part of zfs) does not support DKIOCPARTITION but does use EFI
 * labels.  This code allocates a simple efi label structure and ioctls
 * to extract the size of a zvol.  It only handles the minimal EFI ioctl
 * implementation in zvol.
 */

static void
zvol_bsize(char *path, uint64_t *size, const int pnum)
{
	struct stat64 stb1, stb2;
	struct dk_minfo dkm;
	int fd = -1;
	int rc;

	if (cl_nodeid || pnum != 0)
		return;

	if ((fd = open(path, O_RDONLY)) < 0) {
		return;
	}

	if (stat64("/devices/pseudo/zfs@0:zfs", &stb1) != 0 ||
	    fstat64(fd, &stb2) != 0 ||
	    !S_ISCHR(stb1.st_mode) ||
	    !S_ISCHR(stb2.st_mode) ||
	    major(stb1.st_rdev) != major(stb2.st_rdev)) {
		(void) close(fd);
		return;
	}

	rc = ioctl(fd, DKIOCGMEDIAINFO, (void *)&dkm);
	if (rc >= 0) {
		*size = LE_64(dkm.dki_capacity) *
			(dkm.dki_lbsize) / 512;
	}

	(void) close(fd);
}

/* ARGSUSED */
static void
get_bsize(uint64_t raw_fd, uint64_t *size, int *partitionp, char *path)
{
	struct nscioc_bsize bsize;
#ifdef DKIOCPARTITION
	struct partition64 p64;
#endif
	struct dk_cinfo dki_info;
	struct vtoc vtoc;
	int fd;

	*partitionp = -1;
	*size = (uint64_t)0;

	dki_info.dki_partition = (ushort_t)-1;
	bsize.dki_info = (uint64_t)(unsigned long)&dki_info;
	bsize.vtoc = (uint64_t)(unsigned long)&vtoc;
	bsize.raw_fd = raw_fd;
	bsize.efi = 0;

	fd = open(rdev, O_RDONLY);
	if (fd < 0)
		return;

	if (ioctl(fd, NSCIOC_BSIZE, &bsize) < 0) {
		if (dki_info.dki_partition != (ushort_t)-1) {
			/* assume part# is ok and just the size failed */
			*partitionp = (int)dki_info.dki_partition;

#ifdef DKIOCPARTITION
			/* see if this is an EFI label */
			bzero(&p64, sizeof (p64));
			p64.p_partno = (uint_t)*partitionp;
			if ((ioctl(fd, DKIOCPARTITION, &p64)) > 0) {
				*size = (uint64_t)p64.p_size;
			} else {
				bsize.p64 = (uint64_t)(unsigned long)&p64;
				bsize.efi = 1;

				if (ioctl(fd, NSCIOC_BSIZE, &bsize) < 0) {
					/* see if this is a zvol */
					zvol_bsize(path, size, *partitionp);
				} else {
					*size = (uint64_t)p64.p_size;
				}
			}
#endif	/* DKIOCPARTITION */
		}

		close(fd);
		return;
	}

	close(fd);

	*partitionp = (int)dki_info.dki_partition;

	if (vtoc.v_sanity != VTOC_SANE)
		return;

	if (vtoc.v_version != V_VERSION && vtoc.v_version != 0)
		return;

	if (dki_info.dki_partition > V_NUMPAR)
		return;

	*size = (uint64_t)vtoc.v_part[(int)dki_info.dki_partition].p_size;
}


static int
iscluster(void)
{
	/*
	 * Find out if we are running in a cluster
	 */
	cl_nodeid = cfg_iscluster();
	if (cl_nodeid > 0) {
		return (TRUE);
	} else if (cl_nodeid == 0) {
		return (FALSE);
	}

	fprintf(stderr, "%s\n",
	    gettext("nskernd: unable to ascertain environment"));
	exit(1);
	/* NOTREACHED */
}

/*
 * Runtime Solaris release checking - build release == runtime release
 * is always considered success, so only keep entries in the map for
 * the special cases.
 */
static nsc_release_t nskernd_rel_map[] = {
/*	{ "5.10", "5.10" },			*/
	{ "5.11", "5.10" },
	{ NULL, NULL }
};


#ifdef lint
#define	main	nskernd_main
#endif
/* ARGSUSED1 */
int
main(int argc, char *argv[])
{
	const char *dir = "/";
	struct nskernd data;
	struct rlimit rl;
	int i, run, rc;
	int partition;
	char *reqd;
	int syncpipe[2];
	int startup;

	(void) setlocale(LC_ALL, "");
	(void) textdomain("nskernd");

	rc = nsc_check_release(BUILD_REV_STR, nskernd_rel_map, &reqd);
	if (rc < 0) {
		fprintf(stderr,
		    gettext("nskernd: unable to determine the current "
		    "Solaris release: %s\n"), strerror(errno));
		exit(1);
	} else if (rc == FALSE) {
		fprintf(stderr,
		    gettext("nskernd: incorrect Solaris release "
		    "(requires %s)\n"), reqd);
		exit(1);
	}

	rc = 0;

	if (argc != 1)
		usage();

	/*
	 * Usage: <progname> [-g] [-d <seconds to delay>]
	 */
	while ((i = getopt(argc, argv, "gd:")) != EOF) {
		switch (i) {
			case 'g':
				display_msg = 1;
				break;
			case 'd':
				delay_time = atoi(optarg);
				if (delay_time <= 0) {
					delay_time = 30;
				}
				break;
			default:
				syslog(LOG_ERR,
				"Usage: nskernd [-g] [-d <seconds to delay>]");
				exit(1);
				break;
		}
	}

	if (chroot(dir) < 0) {
		fprintf(stderr, gettext("nskernd: chroot failed: %s\n"),
			strerror(errno));
		exit(1);
	}

	if (chdir(dir) < 0) {
		fprintf(stderr, gettext("nskernd: chdir failed: %s\n"),
			strerror(errno));
		exit(1);
	}

	/*
	 * Determine if we are in a Sun Cluster or not, before fork'ing
	 */
	(void) iscluster();

	/*
	 * create a pipe to synchronise the parent with the
	 * child just before it enters its service loop.
	 */
	if (pipe(syncpipe) < 0) {
		fprintf(stderr, gettext("nskernd: cannot create pipe: %s\n"),
		    strerror(errno));
		exit(1);
	}
	/*
	 * Fork off a child that becomes the daemon.
	 */

	if ((rc = fork()) > 0) {
		char c;
		int n;
		(void) close(syncpipe[1]);
		/*
		 * wait for the close of the pipe.
		 * If we get a char back, indicates good
		 * status from child, so exit 0.
		 * If we get a zero length read, then the
		 * child has failed, so we do too.
		 */
		n = read(syncpipe[0], &c, 1);
		exit((n <= 0) ? 1 : 0);
	} else if (rc < 0) {
		fprintf(stderr, gettext("nskernd: cannot fork: %s\n"),
			strerror(errno));
		exit(1);
	}

	/*
	 * In child - become daemon.
	 */

	/* use closefrom(3C) from PSARC/2000/193 when possible */
	for (i = 0; i < syncpipe[1]; i++) {
		(void) close(i);
	}
	closefrom(syncpipe[1] + 1);

	(void) open("/dev/console", O_WRONLY|O_APPEND);
	(void) dup(0);
	(void) dup(0);
	(void) close(0);

	setpgrp();

	/*
	 * Ignore all signals apart from SIGTERM.
	 */

	for (i = 1; i < _sys_nsig; i++)
		(void) sigset(i, SIG_IGN);

	(void) sigset(SIGTERM, sighand);

	/*
	 * Increase the number of fd's that can be open.
	 */

	rl.rlim_cur = RLIM_INFINITY;
	rl.rlim_max = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
		fprintf(stderr,
		    gettext("nskernd: could not increase RLIMIT_NOFILE: %s\n"),
		    strerror(errno));
		fprintf(stderr,
		    gettext("nskernd: the maximum number of nsctl open "
		    "devices may be reduced\n"));
	}

	/*
	 * Open /dev/nsctl and startup.
	 */

	nsctl_fd = open(rdev, O_RDONLY);
	if (nsctl_fd < 0) {
		fprintf(stderr, gettext("nskernd: unable to open %s\n"), rdev);
		exit(1);
	}

	bzero(&data, sizeof (data));

	data.command = NSKERND_START;
	data.data1 = (uint64_t)cl_nodeid;
	run = 1;

	startup = 1;
	while (run) {
		rc = ioctl(nsctl_fd, NSCIOC_NSKERND, &data);
		if (rc < 0) {
			/* try and do kernel cleanup and exit */
			if (shutdown()) {
				run = 0;
			} else {
				sigterm = 0;
			}

			fprintf(stderr,
			    gettext("nskernd: NSCIOC_NSKERND failed: %s\n"),
			    strerror(errno));
			continue;
		} else if (sigterm) {
			/* SIGTERM received - terminate */
			if (data.command != NSKERND_START &&
			    (data.command != NSKERND_STOP ||
			    data.data1 != (uint64_t)1)) {
				/* need to do kernel cleanup */
				if (shutdown()) {
					run = 0;
				} else {
					sigterm = 0;
					data.command = NSKERND_START;
					data.data1 = (uint64_t)cl_nodeid;
				}
			} else {
				/* just quit */
				if (canshutdown()) {
					run = 0;
				} else {
					/* cannot shutdown - threads active */
					sigterm = 0;
					data.command = NSKERND_START;
					data.data1 = (uint64_t)cl_nodeid;
				}
			}
			continue;
		}
		if (startup) {
			char c = 0;
			(void) write(syncpipe[1], &c, 1);
			(void) close(syncpipe[1]);
			startup = 0;
		}
		switch (data.command) {
		case NSKERND_START:	/* (re)start completion */
			if (rc == 1) {
				fprintf(stderr,
				    gettext("nskernd: already started\n"));
				run = 0;
			} else if (rc == 2) {
				fprintf(stderr,
				    gettext("nskernd: stopped by kernel\n"));
				run = 0;
			}
			data.command = NSKERND_WAIT;
			break;

		case NSKERND_STOP:	/* kernel telling daemon to stop */
			if (data.data1 != (uint64_t)1) {
				(void) shutdown();
				run = 0;
			}
			break;

		case NSKERND_BSIZE:
			/*
			 * kernel requesting partsize
			 * data1 - size return
			 * data2 - raw_fd (entry)
			 *	 - partition number (return)
			 */
			partition = -1;
			get_bsize(data.data2, &data.data1,
			    &partition, data.char1);
			data.data2 = (uint64_t)partition;
			data.command = NSKERND_WAIT;
			break;

		case NSKERND_NEWLWP:	/* kernel requesting a new LWP */
			newlwp(&data);
			data.command = NSKERND_WAIT;
			break;

		case NSKERND_LOCK:  	/* kernel requesting lock */
			dolock(&data);
			data.command = NSKERND_WAIT;
			break;

		case NSKERND_WAIT:	/* kernel retrying wait */
			/*
			 * the kernel thread can be woken by the dr config
			 * utilities (ie cfgadm) therefore we just reissue
			 * the wait.
			 */
			break;

		case NSKERND_IIBITMAP:
			rc = log_iibmp_err(data.char1, (int)data.data1);
			data.data1 = (uint64_t)rc;
			data.command = NSKERND_WAIT;
			break;

		default:
			fprintf(stderr,
				gettext("nskernd: unknown command %d"),
				data.command);
			data.command = NSKERND_WAIT;
			break;
		}
	}

	(void) close(nsctl_fd);

	return (rc);
}
