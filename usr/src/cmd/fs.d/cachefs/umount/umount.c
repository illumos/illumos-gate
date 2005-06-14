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
 * -----------------------------------------------------------------
 *
 *			umount.c
 *
 * CFS specific umount command.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <wait.h>
#include <ctype.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <sys/fs/cachefs_fs.h>
#include <fslib.h>
#include <sys/utsname.h>
#include <rpc/rpc.h>
#include "../common/subr.h"
#include "../common/cachefsd.h"

/* forward references */
void pr_err(char *fmt, ...);
void usage(char *msgp);
int daemon_unmount(char *mntptp, int);

/*
 *
 *			main
 *
 * Description:
 *	Main routine for the cfs umount program.
 * Arguments:
 *	argc	number of command line arguments
 *	argv	list of command line arguments
 * Returns:
 *	Returns 0 for success or 1 if an error occurs.
 * Preconditions:
 */

int
main(int argc, char **argv)
{
	char *strp;
	int xx;
	int ret;
	struct mnttab mget;
	struct mnttab mref;
	FILE *finp;
	char mnt_front[PATH_MAX];
	char mnt_back[PATH_MAX];
	char *p, mnt_frontns[PATH_MAX];
	pid_t pid;
	int stat_loc;
	char *cachedirp, *s;
	int ufd, c;
	int flag = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Set options
	 */
	while ((c = getopt(argc, argv, "f")) != EOF) {
		switch (c) {
		case 'f':
			flag |= MS_FORCE; /* forced unmount is desired */
			break;
		default:
			usage("Incorrect number of arguments specified");
			return (1);
		}
	}
	if (flag & MS_FORCE)
		strcpy(mnt_front, argv[2]);
	else
		strcpy(mnt_front, argv[1]);
	mnt_back[0] = '\0';

	if (strlen(argv[1]) >= (size_t)PATH_MAX) {
		pr_err(gettext("name too long"));
		return (1);
	}

	/*
	 * An unmount from autofs may have a
	 * space appended to the path.
	 * Trim it off before attempting to
	 * match the mountpoint in mnttab
	 */
	strcpy(mnt_frontns, mnt_front);
	p = &mnt_frontns[strlen(mnt_frontns) - 1];
	if (*p == ' ')
		*p = '\0';

	/* get the mount point and the back file system mount point */
	finp = fopen(MNTTAB, "r");
	if (finp) {
		mntnull(&mref);
		mref.mnt_mountp = mnt_frontns;
		mref.mnt_fstype = "cachefs";
		ret = getmntany(finp, &mget, &mref);

		cachedirp = (char *)malloc(strlen(mget.mnt_special) + 1);
		strcpy(cachedirp, mget.mnt_special);
		/*
		 * AutoClient mounts do not have .cfs_mnt_points string in
		 * them, so strstr would return NULL. So .cfs_unmnt file
		 * is not updated.
		 */
		if ((s = strstr(cachedirp, ".cfs_mnt_points")) != NULL) {
			time32_t btime;

			xx = -1;
			cachedirp[s-cachedirp] = '\0';
			strcat(cachedirp, CACHEFS_UNMNT_FILE);
			if ((ufd = open(cachedirp, O_WRONLY|O_CREAT|O_TRUNC,
					0600)) > 0) {
				if ((btime = get_boottime()) != -1)
				    xx = write(ufd, &btime, sizeof (time32_t));
				close(ufd);
			}
			if (xx < 0)
				pr_err(gettext(".cfs_unmnt error"));
		}

		if (ret != -1) {
			if (mget.mnt_special)
				strcpy(mnt_back, mget.mnt_special);
		} else {
			mref.mnt_special = mref.mnt_mountp;
			mref.mnt_mountp = NULL;
			rewind(finp);
			ret = getmntany(finp, &mget, &mref);
			if (ret != -1) {
				strcpy(mnt_front, mget.mnt_mountp);
				if (mget.mnt_special)
					strcpy(mnt_back, mget.mnt_special);
			} else {
				pr_err(gettext("warning: %s not in mnttab"),
				    mref.mnt_special);
			}
		}
		fclose(finp);
	}

	/* try to get the daemon to unmount this file system for us */
	xx = daemon_unmount(mnt_front, flag);
	if (xx == ENOTSUP)
		return (1);
	if (xx == EBUSY) {
		pr_err(gettext("%s %s"), mnt_front, strerror(xx));
		return (1);
	}
	if (xx == EIO) {
		/* try to unmount the file system directly */
		if (umount2(mnt_front, flag) == -1) {
			pr_err(gettext("%s %s"), mnt_front, strerror(errno));
			return (1);
		}
	}

	/* if we do not know the name of the back file system mount point */
	if (mnt_back[0] == '\0') {
		/* all done */
		return (0);
	}

	/*
	 * If the back file system was mounted on a directory with a
	 * parent name of BACKMNT_NAME then we assume that we
	 * mounted it and that it is okay to try to umount it.
	 */
	if (strstr(mnt_back, BACKMNT_NAME) == NULL)
		return (0);

	/* if no back file system mounted */
	if (strcmp(mnt_back, "nobackfs") == 0)
		return (0);

	/* fork */
	if ((pid = fork()) == -1) {
		pr_err(gettext("could not fork %s"), strerror(errno));
		return (1);
	}

	/* if the child */
	if (pid == 0) {
		/* invoke the umount command on the back file system */
		xx = execl("/sbin/umount", "/sbin/umount", mnt_back, NULL);
		pr_err(gettext("could not exec /sbin/umount"
		    " on back file system %s"), strerror(errno));
	}

	/* else if the parent */
	else {
		/* wait for the child to exit */
		if (wait(&stat_loc) == -1) {
			pr_err(gettext("wait failed %s"), strerror(errno));
			return (1);
		}

		if (!WIFEXITED(stat_loc)) {
			pr_err(gettext("back umount did not exit"));
			return (1);
		}

		xx = WEXITSTATUS(stat_loc);
		if (xx) {
			pr_err(gettext("back umount failed"));
			return (xx);
		}
	}

	/* delete the back file system mount point since we created it */
	rmdir(mnt_back);

	return (xx);
}

/*
 *
 *			pr_err
 *
 * Description:
 *	Prints an error message to stderr.
 * Arguments:
 *	fmt	printf style format
 *	...	arguments for fmt
 * Returns:
 * Preconditions:
 *	precond(fmt)
 */

void
pr_err(char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, gettext("umount -F cachefs: "));
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, "\n");
	va_end(ap);
}

/*
 *
 *			usage
 *
 * Description:
 *	Prints a usage message.
 * Arguments:
 *	An optional additional message to be displayed.
 * Returns:
 * Preconditions:
 */

void
usage(char *msgp)
{
	if (msgp)
		pr_err(gettext("%s"), msgp);
	fprintf(stderr, gettext("Usage: umount -F cachefs dir"));
}

/*
 *
 *			daemon_unmount
 *
 * Description:
 *	Notifies the cachefsd of an unmount request.
 * Arguments:
 *	Mount point to unmount.
 * Returns:
 *	Returns 0 if the cachefsd unmounted the file system
 *		EIO if should try unmount directly
 *		EBUSY if did not unmount because busy
 *		EAGAIN if umounted but should not unmount nfs mount
 *
 * Preconditions:
 *	precond(mntptp)
 */

int
daemon_unmount(char *mntptp, int flag)
{
	CLIENT *clnt;
	enum clnt_stat retval;
	int xx;
	int result;
	char *hostp;
	struct utsname info;
	static struct timeval TIMEOUT = { 60*60, 0 };
	static struct timeval create_timeout = { 5, 0};
	struct cachefsd_fs_unmounted uargs;

	/* get the host name */
	xx = uname(&info);
	if (xx == -1) {
		pr_err(gettext("cannot get host name, errno %d"), errno);
		return (EIO);
	}
	hostp = info.nodename;
	uargs.mntpt = mntptp;
	uargs.flag = flag;

	/* creat the connection to the daemon */
	clnt = clnt_create_timed(hostp, CACHEFSDPROG, CACHEFSDVERS, "local",
	    &create_timeout);
	if (clnt == NULL) {
		pr_err(gettext("cachefsd is not running"));
		return (EIO);
	}
	clnt_control(clnt, CLSET_TIMEOUT, (char *)&TIMEOUT);

	retval = cachefsd_fs_unmounted_1(&uargs, &result, clnt);
	if (retval != RPC_SUCCESS) {
		clnt_perror(clnt, gettext("cachefsd is not responding"));
		clnt_destroy(clnt);
		return (EIO);
	}

	clnt_destroy(clnt);

	return (result);
}
