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
 *	automount.c
 *
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <ctype.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <locale.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <signal.h>
#include <syslog.h>
#include <libshare.h>
#include <libscf.h>
#include <sys/param.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/tiuser.h>
#include <rpc/rpc.h>
#include <rpcsvc/nfs_prot.h>
#include <nsswitch.h>
#include <deflt.h>
#include <rpcsvc/daemon_utils.h>
#include "automount.h"
#include "smfcfg.h"

static int mkdir_r(char *);
struct autodir *dir_head;
struct autodir *dir_tail;
static struct extmnttab *find_mount();
int verbose = 0;
int trace = 0;

static void usage();
static int compare_opts(char *, char *);
static void do_unmounts();

static int mount_timeout = AUTOFS_MOUNT_TIMEOUT;

static char	*service_list[] = { AUTOMOUNTD, NULL };

/*
 * XXX
 * The following are needed because they're used in auto_subr.c and
 * we link with it. Should avoid this.
 */
mutex_t cleanup_lock;
cond_t cleanup_start_cv;
cond_t cleanup_done_cv;

int
main(int argc, char *argv[])
{
	int c;
	struct autofs_args ai;
	struct utsname utsname;
	char autofs_addr[MAXADDRLEN];
	struct autodir *dir, *d;
	struct stat stbuf;
	char *master_map = "auto_master";
	int null;
	struct extmnttab mnt, *mntp;
	struct mnttab *omntp;
	char mntopts[MAX_MNTOPT_STR];
	int mntflgs;
	int count = 0;
	char *stack[STACKSIZ];
	char **stkptr;
	char *defval;
	struct sigaction sigintact;
	int ret = 0, bufsz = 0;
	char valbuf[6];

	/*
	 * protect this command from session termination when run in background
	 * we test background by whether SIGINT is ignored
	 */
	(void) sigaction(SIGINT, NULL, &sigintact);
	if (sigintact.sa_handler == SIG_IGN) {
		(void) signal(SIGHUP, SIG_IGN);
		(void) setsid();
	}

	/*
	 * Read in the values from SMF first before we check
	 * commandline options so the options override the SMF values.
	 */
	bufsz = 6;
	ret = autofs_smf_get_prop("timeout", valbuf, DEFAULT_INSTANCE,
	    SCF_TYPE_INTEGER, AUTOMOUNTD, &bufsz);
	if (ret == SA_OK)
		/*
		 * Ignore errno.  In event of failure, mount_timeout is
		 * already initialized to the correct value.
		 */
		mount_timeout = strtol(valbuf, (char **)NULL, 10);

	bufsz = 6;
	ret = autofs_smf_get_prop("automount_verbose", valbuf, DEFAULT_INSTANCE,
	    SCF_TYPE_BOOLEAN, AUTOMOUNTD, &bufsz);
	if (ret == SA_OK) {
		if (strncasecmp("true", valbuf, 4) == 0)
			verbose = TRUE;
	}

	put_automountd_env();

	while ((c = getopt(argc, argv, "mM:D:f:t:v?")) != EOF) {
		switch (c) {
		case 'm':
			pr_msg("Warning: -m option not supported");
			break;
		case 'M':
			pr_msg("Warning: -M option not supported");
			break;
		case 'D':
			pr_msg("Warning: -D option not supported");
			break;
		case 'f':
			pr_msg("Error: -f option no longer supported");
			usage();
			break;
		case 't':
			if (strchr(optarg, '=')) {
				pr_msg("Error: invalid value for -t");
				usage();
			}
			mount_timeout = atoi(optarg);
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage();
			break;
		}
	}

	if (optind < argc) {
		pr_msg("%s: command line mountpoints/maps "
		    "no longer supported", argv[optind]);
		usage();
	}

	current_mounts = getmntlist();
	if (current_mounts == NULL) {
		pr_msg("Couldn't establish current mounts");
		exit(1);
	}

	(void) umask(0);
	ns_setup(stack, &stkptr);

	openlog("automount", LOG_PID, LOG_DAEMON);
	(void) loadmaster_map(master_map, "", stack, &stkptr);
	if (dir_head != NULL) {
		/*
		 * automount maps found. enable services as needed.
		 */
		_check_services(service_list);
	}

	closelog();

	if (uname(&utsname) < 0) {
		pr_msg("uname: %m");
		exit(1);
	}
	(void) strcpy(autofs_addr, utsname.nodename);
	(void) strcat(autofs_addr, ".autofs");
	ai.addr.buf	= autofs_addr;
	ai.addr.len	= strlen(ai.addr.buf);
	ai.addr.maxlen	= ai.addr.len;

	ai.mount_to	= mount_timeout;
	ai.rpc_to	= AUTOFS_RPC_TIMEOUT;

	/*
	 * Mount the daemon at its mount points.
	 */
	for (dir = dir_head; dir; dir = dir->dir_next) {

		/*
		 * Skip null entries
		 */
		if (strcmp(dir->dir_map, "-null") == 0)
			continue;

		/*
		 * Skip null'ed entries
		 */
		null = 0;
		for (d = dir->dir_prev; d; d = d->dir_prev) {
			if (strcmp(dir->dir_name, d->dir_name) == 0)
				null = 1;
		}
		if (null)
			continue;

		/*
		 * Check whether there's already an entry
		 * in the mnttab for this mountpoint.
		 */
		if (mntp = find_mount(dir->dir_name, 1)) {
			/*
			 * If it's not an autofs mount - don't
			 * mount over it.
			 */
			if (strcmp(mntp->mnt_fstype, MNTTYPE_AUTOFS) != 0) {
				pr_msg("%s: already mounted",
				    mntp->mnt_mountp);
				continue;
			}

			/*
			 * Compare the mnttab entry with the master map
			 * entry.  If the map or mount options are
			 * different, then update this information
			 * with a remount.
			 */
			if (strcmp(mntp->mnt_special, dir->dir_map) == 0 &&
			    compare_opts(dir->dir_opts,
			    mntp->mnt_mntopts) == 0) {
				continue;	/* no change */
			}

			/*
			 * Check for an overlaid direct autofs mount.
			 * Cannot remount since it's inaccessible.
			 */
			omntp = (struct mnttab *)mntp;
			if (hasmntopt(omntp, "direct") != NULL) {
				mntp = find_mount(dir->dir_name, 0);
				omntp = (struct mnttab *)mntp;
				if (hasmntopt(omntp, "direct") == NULL) {
					if (verbose)
						pr_msg("%s: cannot remount",
						    dir->dir_name);
					continue;
				}
			}

			dir->dir_remount = 1;
		}

		/*
		 * Create a mount point if necessary
		 * If the path refers to an existing symbolic
		 * link, refuse to mount on it.  This avoids
		 * future problems.
		 */
		if (lstat(dir->dir_name, &stbuf) == 0) {
			if ((stbuf.st_mode & S_IFMT) != S_IFDIR) {
				pr_msg("%s: Not a directory", dir->dir_name);
				continue;
			}
		} else {
			if (mkdir_r(dir->dir_name)) {
				pr_msg("%s: %m", dir->dir_name);
				continue;
			}
		}

		ai.path		= dir->dir_name;
		ai.opts		= dir->dir_opts;
		ai.map		= dir->dir_map;
		ai.subdir	= "";
		ai.direct	= dir->dir_direct;
		if (dir->dir_direct)
			ai.key = dir->dir_name;
		else
			ai.key = "";

		(void) sprintf(mntopts, "ignore,%s",
		    dir->dir_direct  ? "direct" : "indirect");
		if (dir->dir_opts && *dir->dir_opts) {
			(void) strcat(mntopts, ",");
			(void) strcat(mntopts, dir->dir_opts);
		}
		mntflgs = MS_OPTIONSTR | (dir->dir_remount ? MS_REMOUNT : 0);
		if (mount(dir->dir_map, dir->dir_name, MS_DATA | mntflgs,
		    MNTTYPE_AUTOFS, &ai, sizeof (ai), mntopts,
		    MAX_MNTOPT_STR) < 0) {
			pr_msg("mount %s: %m", dir->dir_name);
			continue;
		}

		count++;

		if (verbose) {
			if (dir->dir_remount)
				pr_msg("%s remounted", dir->dir_name);
			else
				pr_msg("%s mounted", dir->dir_name);
		}
	}

	if (verbose && count == 0)
		pr_msg("no mounts");

	/*
	 * Now compare the /etc/mnttab with the master
	 * map.  Any autofs mounts in the /etc/mnttab
	 * that are not in the master map must be
	 * unmounted
	 */
	do_unmounts();

	return (0);
}

/*
 * Find a mount entry given
 * the mountpoint path.
 * Optionally return the first
 * or last entry.
 */
static struct extmnttab *
find_mount(mntpnt, first)
	char *mntpnt;
	int first;
{
	struct mntlist *mntl;
	struct extmnttab *found = NULL;

	for (mntl = current_mounts; mntl; mntl = mntl->mntl_next) {

		if (strcmp(mntpnt, mntl->mntl_mnt->mnt_mountp) == 0) {
			found = mntl->mntl_mnt;
			if (first)
				break;
		}
	}

	return (found);
}

static char *ignore_opts[] = {"ignore", "direct", "indirect", "dev", NULL};

/*
 * Compare mount options
 * ignoring "ignore", "direct", "indirect"
 * and "dev=".
 */
static int
compare_opts(opts, mntopts)
	char *opts, *mntopts;
{
	char optbuf1[MAX_MNTOPT_STR], *s = optbuf1;
	char optbuf2[MAX_MNTOPT_STR];
	char **opttbl1, **opttbl2;
	int nopts1, nopts2;
	char *ostart, *optr, *valp;
	int j, i, notsame;

	opttbl1 = opttbl2 = NULL;
	/*
	 * Parse the two option strings to split them both into
	 * lists of individual options.
	 */
	if (mntopts != NULL)
		(void) strcpy(s, mntopts);
	else
		*s = '\0';
	if (*s != '\0')
		nopts1 = 1;
	else
		nopts1 = 0;
	for (s = strchr(s, ','); s != NULL; s = strchr(s, ',')) {
		nopts1++;
		s++;
	}
	if (nopts1)
		if ((opttbl1 = memalign(sizeof (char *),
			nopts1 * sizeof (char *))) == NULL)
			return (1);
	nopts1 = 0;
	s = optbuf1;
	for (ostart = optr = s; *optr != '\0'; ostart = optr) {
		if (getsubopt(&optr, ignore_opts, &valp) == -1) {
			opttbl1[nopts1++] = ostart;
		}
	}
	s = optbuf2;
	if (opts != NULL)
		(void) strcpy(s, opts);
	else
		*s = '\0';
	if (*s != '\0')
		nopts2 = 1;
	else
		nopts2 = 0;
	for (s = strchr(s, ','); s != NULL; s = strchr(s, ',')) {
		nopts2++;
		s++;
	}
	if (nopts2)
		if ((opttbl2 = memalign(sizeof (char *),
			nopts2 * sizeof (char *))) == NULL) {
			notsame = 1;
			goto done;
		}
	nopts2 = 0;
	s = optbuf2;
	for (ostart = optr = s; *optr != '\0'; ostart = optr) {
		if (getsubopt(&optr, ignore_opts, &valp) == -1) {
			opttbl2[nopts2++] = ostart;
		}
	}
	if (nopts2 != nopts1) {
		notsame = 1;
		goto done;
	}
	notsame = 0;
	for (i = 0; i < nopts1; i++) {
		notsame = 1;
		for (j = 0; j < nopts2; j++) {
			if (strcmp(opttbl1[i], opttbl2[j]) == 0) {
				notsame = 0;
				break;
			}
		}
		if (notsame)
			break;
	}

done:
	if (opttbl1 != NULL)
		free(opttbl1);
	if (opttbl2 != NULL)
		free(opttbl2);
	return (notsame);
}

static void
usage()
{
	pr_msg("Usage: automount  [ -v ]  [ -t duration ]");
	exit(1);
	/* NOTREACHED */
}

/*
 * Unmount any autofs mounts that
 * aren't in the master map
 */
static void
do_unmounts()
{
	struct mntlist *mntl;
	struct extmnttab *mnt;
	struct mnttab *omnt;
	struct autodir *dir;
	int current;
	int count = 0;
	struct zone_summary *zsp;

	zsp = fs_get_zone_summaries();
	if (zsp == NULL) {
		pr_msg("Couldn't establish active zones");
		exit(1);
	}
	for (mntl = current_mounts; mntl; mntl = mntl->mntl_next) {
		mnt = mntl->mntl_mnt;
		omnt = (struct mnttab *)mnt;
		if (strcmp(mnt->mnt_fstype, MNTTYPE_AUTOFS) != 0)
			continue;
		if (fs_mount_in_other_zone(zsp, mnt->mnt_mountp))
			continue;
		/*
		 * Don't unmount autofs mounts done
		 * from the autofs mount command.
		 * How do we tell them apart ?
		 * Autofs mounts not eligible for auto-unmount
		 * have the "nest" pseudo-option.
		 */
		if (hasmntopt(omnt, "nest") != NULL)
			continue;

		current = 0;
		for (dir = dir_head; dir; dir = dir->dir_next) {
			if (strcmp(dir->dir_name, mnt->mnt_mountp) == 0) {
				current = strcmp(dir->dir_map, "-null");
				break;
			}
		}
		if (current)
			continue;


		if (umount(mnt->mnt_mountp) == 0) {
			if (verbose) {
				pr_msg("%s unmounted",
				    mnt->mnt_mountp);
			}
			count++;
		}
	}
	if (verbose && count == 0)
		pr_msg("no unmounts");
}

static int
mkdir_r(dir)
	char *dir;
{
	int err;
	char *slash;

	if (mkdir(dir, 0555) == 0 || errno == EEXIST)
		return (0);
	if (errno != ENOENT)
		return (-1);
	slash = strrchr(dir, '/');
	if (slash == NULL)
		return (-1);
	*slash = '\0';
	err = mkdir_r(dir);
	*slash++ = '/';
	if (err || !*slash)
		return (err);
	return (mkdir(dir, 0555));
}

/*
 * Print an error.
 * Works like printf (fmt string and variable args)
 * except that it will subsititute an error message
 * for a "%m" string (like syslog).
 */
/* VARARGS1 */
void
pr_msg(const char *fmt, ...)
{
	va_list ap;
	char buf[BUFSIZ], *p2;
	char *p1;
	char *nfmt;

	(void) strcpy(buf, "automount: ");
	p2 = buf + strlen(buf);

	nfmt = gettext(fmt);

	for (p1 = nfmt; *p1; p1++) {
		if (*p1 == '%' && *(p1+1) == 'm') {
			(void) strcpy(p2, strerror(errno));
			p2 += strlen(p2);
			p1++;
		} else {
			*p2++ = *p1;
		}
	}
	if (p2 > buf && *(p2-1) != '\n')
		*p2++ = '\n';
	*p2 = '\0';

	va_start(ap, fmt);
	(void) vfprintf(stderr, buf, ap);
	va_end(ap);
}
