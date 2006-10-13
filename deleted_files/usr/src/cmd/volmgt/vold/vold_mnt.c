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

#include	<stdio.h>
#include	<fcntl.h>
#include	<stdlib.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/stat.h>
#include	<sys/mnttab.h>
#include	<sys/mntent.h>
#include	<syslog.h>
#include	<sys/wait.h>
#include	<time.h>

#include	"vold.h"
#include	<errno.h>
#include	<sys/mount.h>


static struct 	mnttab *dupmnttab(struct mnttab *);
static void	freemnttab(struct mnttab *);
static int	readmnttab(void);


struct mntlist {
	struct mnttab	*mntl_mnt;
	struct mntlist	*mntl_next;
};

static struct mntlist	*mntl_head = NULL;	/* in-core mount table */

#ifndef TRUE
#define	TRUE	(-1)
#endif

#ifndef	FALSE
#define	FALSE	(0)
#endif

#define	UMOUNT_PATH	"/etc/umount"
#define	UMOUNT_PROG	"umount"
#define	FORCE_UMOUNT	"-f"

static int	call_umount(char *);

/*
 * Check to see if "path" is used as a special device in a mount.
 * Will match partial paths (e.g. / will match everything).  Returns
 * the first matched path.
 */
char *
mnt_special_test(char *path)
{
	struct mntlist	*mntl;
	char		*rval = NULL;
	int		len;

	if (!readmnttab())
		return (NULL);

	len = strlen(path);

	for (mntl = mntl_head; mntl; mntl = mntl->mntl_next) {
		if (strncmp(path, mntl->mntl_mnt->mnt_special, len) == 0) {
			rval = vold_strdup(mntl->mntl_mnt->mnt_special);
			break;
		}
	}
	return (rval);
}


struct mnttab *
mnt_mnttab(char *special)
{
	struct mntlist	*mntl;
	struct mnttab	*rval = NULL;

	if (!readmnttab())
		return (NULL);

	for (mntl = mntl_head; mntl; mntl = mntl->mntl_next) {
		if (strcmp(special, mntl->mntl_mnt->mnt_special) == 0) {
			rval = dupmnttab(mntl->mntl_mnt);
			break;
		}
	}
	return (rval);
}


void
mnt_free_mnttab(struct mnttab *mnt)
{
	freemnttab(mnt);
}

/*
 * rename a special device in /etc/mnttab
 * place holder that can probably go away.
 * probably need to trigger something here
 * but the original code wouldn't work in this
 * case.
 */
/*ARGSUSED*/
void
mnt_special_rename(char *from, char *to)
{
	;
}

/*
 * read the mount table into memory. caller must manage the lock.
 */
static int
readmnttab(void)
{
	FILE	*mnt_fp;
	struct mntlist	*mntl;
	struct mntlist	*mntl_prev, *mntl_next;
	struct mnttab	mnt;

	/* /etc/mnttab can only be opened for reading */
	if ((mnt_fp = fopen(MNTTAB, "r")) == NULL) {
		warning(gettext("can't open %s for r/w; %m\n"), MNTTAB);
		return (FALSE);
	}
	(void) fcntl(fileno(mnt_fp), F_SETFD, 1); /* close on exec */

	for (mntl = mntl_head; mntl != NULL; mntl = mntl_next) {
		mntl_next = mntl->mntl_next;
		freemnttab(mntl->mntl_mnt);
		free(mntl);
	}
	mntl_head = NULL;
	/*
	 * Read the mount table into memory.
	 */
	mntl_prev = NULL;
	while (getmntent(mnt_fp, &mnt) == 0) {
		mntl = vold_malloc(sizeof (*mntl));
		if (mntl_head == NULL) {
			mntl_head = mntl;
		} else {
			mntl_prev->mntl_next = mntl;
		}
		mntl_prev = mntl;
		mntl->mntl_next = NULL;
		mntl->mntl_mnt = dupmnttab(&mnt);
	}
	(void) fclose(mnt_fp);
	return (TRUE);
}

static struct mnttab *
dupmnttab(struct mnttab *mnt)
{
	struct mnttab *new;

	new = vold_calloc(1, sizeof (*new));
	/*
	 * work around problem where '-' in /etc/mnttab for
	 * special device turns to NULL which isn't expected
	 */
	if (mnt->mnt_special == NULL)
		mnt->mnt_special = "-";
	new->mnt_special = vold_strdup(mnt->mnt_special);
	new->mnt_mountp = vold_strdup(mnt->mnt_mountp);
	new->mnt_fstype = vold_strdup(mnt->mnt_fstype);
	/* mnt_mntopts and mnt_time can conceivably be null */
	if (mnt->mnt_mntopts != NULL)
		new->mnt_mntopts = vold_strdup(mnt->mnt_mntopts);
	if (mnt->mnt_time != NULL)
		new->mnt_time = vold_strdup(mnt->mnt_time);
	return (new);
}

static void
freemnttab(struct mnttab *mnt)
{
	free(mnt->mnt_special);
	free(mnt->mnt_mountp);
	free(mnt->mnt_fstype);
	if (mnt->mnt_mntopts != NULL) {
		free(mnt->mnt_mntopts);
	}
	if (mnt->mnt_time) {
		free(mnt->mnt_time);
	}
	free(mnt);
}

/*
 * call umount on each volume we've mounted, then umount our root dir
 *
 * if any of the umounts of managed volumes fails, ignore them, but return
 * the status of umounting our root dir
 *
 * return 0 for success, else non-zero
 *
 * ignore the return codes from truning to unmount managed mendia (it
 * may be busy), but return the status from trying to unmount our root dir
 */
int
umount_all(char *root_dir)
{
	uint_t		len = strlen(root_dir);
	struct mntlist	*mntl;
	int		res = 0;

	if (readmnttab() == FALSE)
		return (1);

	/* scan for mnt entries that use our root dir */
	for (mntl = mntl_head; mntl; mntl = mntl->mntl_next) {
		if (strncmp(root_dir, mntl->mntl_mnt->mnt_special, len) == 0)
			(void) call_umount(mntl->mntl_mnt->mnt_mountp);
	}
	if (umount2(root_dir, MS_FORCE) < 0) {
		switch (errno)	{
		case EINVAL:
			debug(10, "/vol is not mounted \n");
			break;
		default:
			debug(10, "umount2 failed to unmount /vol \n");
			res = errno;
			break;
		}
	}
	return (res);
}

/*
 * call the umount program for the specified directory
 *
 * called from child during program termination (e.g., so debug(), et. al.,
 *	can't be used)
 *
 * return 0 for success, else non-zero
 */
static int
call_umount(char *dir)
{
	pid_t	pid;
	int	stat;
	int	fd;
	int	ret_val = 1;

	if ((pid = fork1()) < 0) {
		goto dun;		/* no processes? */
	}

	if (pid == 0) {
		/* the child -- call umount */

		/* redirect stdout/stderr to the bit bucket */
		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			(void) dup2(fd, fileno(stdout));
			(void) dup2(fd, fileno(stderr));
		}

		/* now call umount to do the real work */
		(void) execl(UMOUNT_PATH, UMOUNT_PROG, dir, 0);

		/* oh oh -- shouldn't reach here! */
		syslog(LOG_ERR,
		    gettext("exec of \"%s\" on \"%s\" failed; %m\n"),
		    UMOUNT_PATH, dir);
		exit(1);
	}

	/* the parent -- wait for the child */
	if (waitpid(pid, &stat, 0) != pid) {
		/* couldn't get child status -- return error */
		goto dun;
	}

	/* get return value */
	if (WIFEXITED(stat) && (WEXITSTATUS(stat) == 0)) {
		ret_val = 0;		/* child met with success */
	}

	/* return status of child */
dun:
	return (ret_val);
}
