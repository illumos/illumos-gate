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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains functions that allow applications to roll the log.
 * It is intended for use by applications that open a raw device with the
 * understanding that it contains a Unix File System.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/filio.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fs/ufs_mount.h>
#include <sys/fs/ufs_log.h>
#include <libintl.h>
#include "roll_log.h"

/*
 * The following is the template string passed to mktemp(3C).  This
 * string is used as the name of a temporary mount point which is
 * used to roll the log.
 */
#define	RLG_TEMPLATE	".rlg.XXXXXX"

#define	SYSERR		(-1)

#define	RLM_RW		0
#define	RLM_RO		1

/*
 * Structure definitions:
 */

typedef struct log_info {
	char *li_blkname;	/* Path of block device. */
	char *li_mntpoint;	/* Path of mounted device. */
	char *li_tmpmp_parent;	/* Temporary parent directory of mount point */
	char *li_tmpmp;		/* Temporary mount point. */
} log_info_t;

/*
 * Static function declarations:
 */

static rl_result_t	is_mounted(log_info_t *lip, char *dev);
static void		cleanup(log_info_t *lip);
static rl_result_t	make_mp(log_info_t *lip);
static rl_result_t	rlflush(log_info_t *lip);
static rl_result_t	rlmount(log_info_t *lip, int mntopt);
static rl_result_t	rlumount(log_info_t *lip);

/*
 * NAME
 *	rl_roll_log
 *
 * SYNOPSIS
 *	rl_roll_log(block_dev)
 *
 * DESCRIPTION
 *	Roll the log for the block device "block_dev".
 */

rl_result_t
rl_roll_log(char *bdev)
{
	log_info_t		li;
	rl_result_t		rv = RL_SUCCESS;

	(void) memset((void *)&li, 0, (size_t)sizeof (li));
	if (is_mounted(&li, bdev) == RL_TRUE) {
		rv = rlflush(&li);
	} else {
		/*
		 * Device appears not to be mounted.
		 * We need to mount the device read only.
		 * This automatically causes the log to be rolled, then we can
		 * unmount the device again.  To do the mount, we need to
		 * create a temporary directory, and then remove it when we
		 * are done.
		 */
		rv = make_mp(&li);
		switch (rv) {
		case RL_CORRUPT:
			/* corrupt mnttab - the file sys really was mounted */
			rv = rlflush(&li);
			break;
		case RL_SUCCESS:
			rv = rlmount(&li, RLM_RO);
			if (rv == RL_SUCCESS) {
				rv = rlflush(&li);
				if (umount(li.li_blkname) == SYSERR) {
					(void) fprintf(stderr,
		"WARNING: rl_roll_log(): Can't unmount %s\n", li.li_blkname);
				}

			}
			break;
		}
	}
	cleanup(&li);
	return (rv);
}

/*
 * Static function definitions:
 */

/*
 * NAME
 *	cleanup
 *
 * SYNOPSIS
 *	cleanup(log_infop)
 *
 * DESCRIPTION
 *	Remove the temporary mount directroy and free the dynamically
 *	allocated memory that is pointed to by log_infop.
 */

static void
cleanup(log_info_t *lip)
{
	if (lip->li_blkname != (char *)NULL) {
		free(lip->li_blkname);
		lip->li_blkname = (char *)NULL;
	}
	if (lip->li_mntpoint != (char *)NULL) {
		free(lip->li_mntpoint);
		lip->li_mntpoint = (char *)NULL;
	}
	if (lip->li_tmpmp != (char *)NULL) {
		(void) rmdir(lip->li_tmpmp);
		free(lip->li_tmpmp);
		lip->li_tmpmp = (char *)NULL;
	}
	if (lip->li_tmpmp_parent != (char *)NULL) {
		(void) rmdir(lip->li_tmpmp_parent);
		free(lip->li_tmpmp_parent);
		lip->li_tmpmp_parent = (char *)NULL;
	}
}

/*
 * NAME
 *	is_mounted
 *
 * SYNOPSIS
 *	is_mounted(log_infop, dev)
 *
 * DESCRIPTION
 *	Determine if device dev is mounted, and return RL_TRUE if it is.
 *	As a side effect, li_blkname is set to point the the full path
 *	names of the block device.  Memory for this path is dynamically
 *	allocated and must be freed by the caller.
 */

extern char *getfullblkname(char *);

static rl_result_t
is_mounted(log_info_t *lip, char *dev)
{

	struct mnttab		mntbuf;
	FILE			*mnttable;
	rl_result_t		rv = RL_FALSE;

	/* Make sure that we have the full path name. */
	lip->li_blkname = getfullblkname(dev);
	if (lip->li_blkname == NULL)
		lip->li_blkname = strdup(dev);

	/* Search mnttab to see if it device is mounted. */
	if ((mnttable = fopen(MNTTAB, "r")) == NULL)
		return (rv);
	while (getmntent(mnttable, &mntbuf) == 0) {
		if (strcmp(mntbuf.mnt_fstype, MNTTYPE_UFS) == 0) {
			/* Entry is UFS */
			if ((strcmp(mntbuf.mnt_mountp, dev) == 0) ||
			    (strcmp(mntbuf.mnt_special, lip->li_blkname)
			    == 0) ||
			    (strcmp(mntbuf.mnt_special, dev) == 0)) {
				lip->li_mntpoint = strdup(mntbuf.mnt_mountp);
				rv = RL_TRUE;
				break;
			}
		}
	}
	(void) fclose(mnttable);


	return (rv);
}

/*
 * NAME
 *	make_mp
 *
 * SYNOPSIS
 *	make_mp(loginfop)
 *
 * DESCRIPTION
 *	Create a temporary directory to be used as a mount point.  li_tmpmp
 *	will be set to the path of the mount point. li_tmpmp_parent is the
 *	parent directory of the mount point.  The parent directory is
 *	created with restrictive permissions.   Memory pointed to by
 *	li_tmpmp and li_tmpmp_parent should be freed by the caller.
 */

static rl_result_t
make_mp(log_info_t *lip)
{
	size_t			i;
	rl_result_t		rv = RL_FAIL;
	/*
	 * Note tmp_dir_list[] should all be directories in the
	 * original root file system.
	 */
	static const char	*tmp_dir_list[] = {
							"/tmp/",
							"/var/tmp/",
							"/",
						};
	char			dirname[] = RLG_TEMPLATE;
	char			tmp_dir[MAXPATHLEN + 1];
	char			mountpt_dir[MAXPATHLEN + 1];
	static size_t		list_len = sizeof (tmp_dir_list) /
	    sizeof (const char *);
	int			merr = 0;

	/*
	 * Sequence of events:
	 * - Create a random name using mktemp(3C) (e.g., ".rlg.123456")
	 * - Cycle through tmp_dir_list to find a path where we can create
	 *   a temporary parent directory (e.g., /tmp/.rlg.123456) with
	 *   restrictive permissions.  This prevents any non-root processes,
	 *   such as a 'find', from wandering in where it doesn't belong.
	 * - Create the mount-point (/tmp/.rlg.123456/.rlg.123456).
	 */
	(void) mktemp(dirname);
	for (i = 0; i < list_len; i++) {
		/* Make the directory containing the mount-point */
		(void) snprintf(tmp_dir, sizeof (tmp_dir), "%s%s",
		    tmp_dir_list[i], dirname);
		if (mkdir(tmp_dir, 0) == SYSERR) {
			merr = errno;
			continue;
		}

		/* Now, make the mount-point */
		(void) snprintf(mountpt_dir, sizeof (mountpt_dir), "%s/%s",
		    tmp_dir, dirname);
		if (mkdir(mountpt_dir, 0) == SYSERR) {
			merr = errno;
			continue;
		}
		lip->li_tmpmp = strdup(mountpt_dir);
		lip->li_tmpmp_parent = strdup(tmp_dir);

		/* Make sure that the strdup()s both succeeded */
		if ((lip->li_tmpmp != NULL) && (lip->li_tmpmp_parent != NULL)) {
			rv = RL_SUCCESS;
		}
		break;
	}

	/* Get some help if we cannot make the directory. */
	if (rv != RL_SUCCESS) {
		/*
		 * If we get a read only filesystem failure (EROFS)
		 * to make a directory in "/", then we must be fsck'ing
		 * at boot with a incorrect mnttab.
		 *
		 * Just return RL_CORRUPT to indicate it really
		 * was mounted.
		 */
		if (merr == EROFS) {
			lip->li_mntpoint = strdup("/");
			return (RL_CORRUPT);
		}

		(void) fprintf(stderr, gettext(
		    "Unable to create temporary "
		    "directory in any of the directories listed "
		    "below:\n"));
		for (i = 0; i < list_len; i++) {
			(void) fprintf(stderr, "\t%s\n", tmp_dir_list[i]);
		}
		(void) fprintf(stderr, gettext(
		    "Please correct this problem "
		    "and rerun the program.\n"));
	}

	return (rv);
}

/*
 * NAME
 *	rlflush
 *
 * SYNOPSIS
 *	rlflush(log_infop)
 *
 * DESCRIPTION
 *	Open the mount point of the file system (li_mntpoint) to get a
 *	file descriptor.  Issue the _FIOFFS ioctl to flush the file system
 *	and then close the device.
 */

static rl_result_t
rlflush(log_info_t *lip)
{
	int			fd;	/* File descriptor. */
	rl_result_t		rv = RL_SUCCESS;

	if ((fd = open((lip->li_mntpoint ? lip->li_mntpoint : lip->li_tmpmp),
	    O_RDONLY)) == SYSERR) {
		return (RL_SYSERR);
	}
	if (ioctl(fd, _FIOFFS, NULL) == SYSERR) {
		rv = RL_SYSERR;
	}
	(void) close(fd);
	return (rv);
}

/*
 * NAME
 *	rlmount
 *
 * SYNOPSIS
 *	rlmount(log_infop, mntopt)
 *
 * DESCRIPTION
 *	Mount the device specified by li_blkname on li_tmpmp. mntopt specifies
 *	whether it's mounted RLM_RO or RLM_RW.
 */

static rl_result_t
rlmount(log_info_t *lip, int mntopt)
{
	struct ufs_args		args;
	rl_result_t		rv = RL_SUCCESS;
	char			opt[MAX_MNTOPT_STR];
	char			*optstr;
	int			optflg;

	args.flags = 0;	/* Initialize ufs_args */

	/*
	 * Use a minimal restrictive set of mount options.  Make sure
	 * to use "largefiles" option otherwise mount() can fail w/EFBIG.
	 * (Although "nosub" isn't a currently supported option on UFS,
	 * it would be a good one to have if it ever is implemented
	 * since submounts would prevent a umount.)
	 */
	args.flags |= UFSMNT_LARGEFILES;
	switch (mntopt) {
	case RLM_RO:
		optstr = MNTOPT_RO;
		optflg = MS_RDONLY;
		break;
	case RLM_RW:
		optstr = MNTOPT_RW;
		optflg = 0;
		break;
	default:
		return (RL_FAIL);
	}
	(void) snprintf(opt, sizeof (opt), "%s,%s,%s",
	    optstr, MNTOPT_NOSUID, MNTOPT_LARGEFILES);
	if (mount(lip->li_blkname, lip->li_tmpmp,
	    optflg | MS_DATA | MS_OPTIONSTR,
	    MNTTYPE_UFS, &args, sizeof (args),
	    opt, MAX_MNTOPT_STR) == SYSERR) {
		rv = RL_SYSERR;
	}
	return (rv);
}

/*
 * NAME
 *	rlumount
 *
 * SYNOPSIS
 *	rlumount(log_infop)
 *
 * DESCRIPTION
 *	Unmounts the device specified by li_blkname, printing an
 *	error message on failure.
 */

static rl_result_t
rlumount(log_info_t *lip)
{
	rl_result_t		rv = RL_SUCCESS;

	if (umount(lip->li_blkname) == SYSERR) {
		(void) fprintf(stderr, gettext(
		    "WARNING: rlumount(): Can't unmount %s\n"),
		    lip->li_blkname);
		rv = RL_SYSERR;
	}
	return (rv);
}

/*
 * NAME
 *	rl_log_control
 *
 * SYNOPSIS
 *	rl_log_control(block_dev, request)
 *
 * DESCRIPTION
 *	Enable/disable logging for the block device "block_dev".
 *	The request parameter should be set to _FIOLOGENABLE or
 *	_FIOLOGDISABLE.
 */

rl_result_t
rl_log_control(char *bdev, int request)
{
	log_info_t	li;
	rl_result_t	rv = RL_SUCCESS;
	rl_result_t	alreadymounted;
	int		fd;
	fiolog_t	fl;
	int		logenabled = 0;

	if ((request != _FIOLOGENABLE) && (request != _FIOLOGDISABLE))
		return (RL_FAIL);

	(void) memset((void *)&li, '\0', (size_t)sizeof (li));
	if ((alreadymounted = is_mounted(&li, bdev)) != RL_TRUE) {
		/*
		 * Device is not mounted. Need to mount it rw to allow
		 * the log to be enabled/disabled. To do the mount, we need
		 * to create a temporary directory, and then remove it when
		 * we are done.
		 */
		if (make_mp(&li) != RL_SUCCESS) {
			cleanup(&li);
			return (RL_FAIL);
		}
		if (rlmount(&li, RLM_RW) != RL_SUCCESS) {
			cleanup(&li);
			return (RL_FAIL);
		}
	}

	if (alreadymounted == RL_TRUE)
		fd = open(li.li_mntpoint, O_RDONLY);
	else
		fd = open(li.li_tmpmp, O_RDONLY);
	if (fd == SYSERR) {
		perror("open");
		rv = RL_SYSERR;
		goto out;
	}

	fl.nbytes_requested = 0;
	fl.nbytes_actual = 0;
	fl.error = FIOLOG_ENONE;

	if (ioctl(fd, request, &fl) == SYSERR) {
		perror("ioctl");
		(void) close(fd);
		rv = RL_SYSERR;
		goto out;
	}
	if (ioctl(fd, _FIOISLOG, &logenabled) == SYSERR) {
		perror("ioctl");
		(void) close(fd);
		rv = RL_SYSERR;
		goto out;
	}
	if (((request == _FIOLOGENABLE) && (!logenabled)) ||
	    ((request == _FIOLOGDISABLE) && logenabled))
		rv = RL_FAIL;

	(void) close(fd);
out:
	if (alreadymounted != RL_TRUE)
		(void) rlumount(&li);
	cleanup(&li);
	return (rv);
}
