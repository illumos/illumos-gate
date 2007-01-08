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

#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <synch.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfstab.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/fs/ufs_fs.h>

#include "libdiskmgt.h"
#include "disks_private.h"

/*
 * The list of filesystem heuristic programs.
 */
struct heuristic {
	struct heuristic	*next;
	char			*prog;
	char			*type;
};

struct vfstab_list {
	char	*special;
	char	*mountp;
	struct vfstab_list 	*next;
};

static struct vfstab_list	*vfstab_listp = NULL;
static	mutex_t	vfstab_lock = DEFAULTMUTEX;

static	time_t	timestamp = 0;

static struct heuristic	*hlist = NULL;
static int		initialized = 0;
static mutex_t		init_lock = DEFAULTMUTEX;

static int	has_fs(char *prog, char *slice);
static int	load_heuristics();
static int	add_use_record(struct vfstab *vp);
static int	load_vfstab();
static void	free_vfstab(struct vfstab_list *listp);

/*
 * Use the heuristics to check for a filesystem on the slice.
 */
int
inuse_fs(char *slice, nvlist_t *attrs, int *errp)
{
	struct 	heuristic	*hp;
	time_t	curr_time;
	int	found = 0;


	*errp = 0;

	if (slice == NULL) {
	    return (0);
	}

	/*
	 * We get the list of heuristic programs one time.
	 */
	(void) mutex_lock(&init_lock);
	if (!initialized) {
	    *errp = load_heuristics();

	    if (*errp == 0) {
		initialized = 1;
	    }
	}
	(void) mutex_unlock(&init_lock);

	/* Run each of the heuristics. */
	for (hp = hlist; hp; hp = hp->next) {
	    if (has_fs(hp->prog, slice)) {
		libdiskmgt_add_str(attrs, DM_USED_BY, DM_USE_FS, errp);
		libdiskmgt_add_str(attrs, DM_USED_NAME, hp->type, errp);
		found = 1;
	    }
	}

	if (*errp != 0)
		return (found);

	/*
	 * Second heuristic used is the check for an entry in vfstab
	 */

	(void) mutex_lock(&vfstab_lock);
	curr_time = time(NULL);

	if (timestamp < curr_time && (curr_time - timestamp) > 60) {
		free_vfstab(vfstab_listp);
		*errp = load_vfstab();
		timestamp = curr_time;
	}

	if (*errp == 0) {
	    struct vfstab_list	*listp;
	    listp = vfstab_listp;

	    while (listp != NULL) {
		if (strcmp(slice, listp->special) == 0) {
		    char *mountp = "";

		    if (listp->mountp != NULL)
			mountp = listp->mountp;

		    libdiskmgt_add_str(attrs, DM_USED_BY, DM_USE_VFSTAB, errp);
		    libdiskmgt_add_str(attrs, DM_USED_NAME, mountp, errp);
		    found = 1;
		}
		listp = listp->next;
	    }
	}
	(void) mutex_unlock(&vfstab_lock);
	return (found);
}

static int
has_fs(char *prog, char *slice)
{
	pid_t	pid;
	int	loc;
	mode_t	mode = S_IRUSR | S_IWUSR;

	switch ((pid = fork1())) {
	case 0:
	    /* child process */

	    closefrom(1);
	    (void) open("/dev/null", O_WRONLY, mode);
	    (void) open("/dev/null", O_WRONLY, mode);
	    (void) execl(prog, "fstyp", slice, NULL);
	    _exit(1);
	    break;

	case -1:
	    return (0);

	default:
	    /* parent process */
	    break;
	}

	(void) waitpid(pid, &loc, 0);

	if (WIFEXITED(loc) && WEXITSTATUS(loc) == 0) {
	    return (1);
	}

	return (0);
}

/*
 * Create a list of filesystem heuristic programs.
 */
static int
load_heuristics()
{
	DIR	*dirp;

	if ((dirp = opendir("/usr/lib/fs")) != NULL) {
	    struct dirent   *dp;

	    while ((dp = readdir(dirp)) != NULL) {
		char		path[MAXPATHLEN];
		struct stat	buf;
		DIR		*subdirp;

		/* skip known dirs */
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0) {
		    continue;
		}

		/*
		 * Skip checking for ZFS filesystems.  We know that
		 * inuse_zpool() will have already been called, which does a
		 * better job of checking anyway.  More importantly, an unused
		 * hot spare will still claim to have a ZFS filesystem because
		 * it doesn't do the same level of checks.
		 */
		if (strcmp(dp->d_name, "zfs") == 0)
			continue;

		(void) snprintf(path, sizeof (path), "/usr/lib/fs/%s",
		    dp->d_name);

		if (stat(path, &buf) != 0 || !S_ISDIR(buf.st_mode)) {
		    continue;
		}

		if ((subdirp = opendir(path)) != NULL) {
		    struct dirent   *sdp;

		    while ((sdp = readdir(subdirp)) != NULL) {

			if (strcmp(sdp->d_name, "fstyp") == 0) {
			    char progpath[MAXPATHLEN];

			    (void) snprintf(progpath, sizeof (progpath),
				"/usr/lib/fs/%s/fstyp", dp->d_name);

			    if (stat(progpath, &buf) == 0 &&
				S_ISREG(buf.st_mode)) {

				struct heuristic *hp;

				hp = (struct heuristic *)
				    malloc(sizeof (struct heuristic));

				if (hp == NULL) {
				    (void) closedir(subdirp);
				    (void) closedir(dirp);
				    return (ENOMEM);
				}

				if ((hp->prog = strdup(progpath)) == NULL) {
				    (void) closedir(subdirp);
				    (void) closedir(dirp);
				    return (ENOMEM);
				}

				if ((hp->type = strdup(dp->d_name)) == NULL) {
				    (void) closedir(subdirp);
				    (void) closedir(dirp);
				    return (ENOMEM);
				}

				hp->next = hlist;
				hlist = hp;
			    }

			    break;
			}
		    }

		    (void) closedir(subdirp);
		}
	    }

	    (void) closedir(dirp);
	}

	return (0);
}

static int
load_vfstab()
{
	FILE	*fp;
	struct	vfstab vp;
	int	status = 1;

	fp = fopen(VFSTAB, "r");
	if (fp != NULL) {
	    (void) memset(&vp, 0, sizeof (struct vfstab));
	    while (getvfsent(fp, &vp) == 0) {
		    status = add_use_record(&vp);
		    if (status != 0) {
			(void) fclose(fp);
			return (status);
		    }
		(void) memset(&vp, 0, sizeof (struct vfstab));
	    }
	    (void) fclose(fp);
	    status = 0;
	}

	return (status);
}

static int
add_use_record(struct vfstab *vp)
{
	struct 	vfstab_list	*vfsp;

	vfsp = (struct vfstab_list *)malloc(sizeof (struct vfstab_list));
	if (vfsp == NULL) {
	    return (ENOMEM);
	}

	vfsp->special = strdup(vp->vfs_special);
	if (vfsp->special == NULL) {
	    free(vfsp);
	    return (ENOMEM);
	}

	if (vp->vfs_mountp != NULL) {
	    vfsp->mountp = strdup(vp->vfs_mountp);
	    if (vfsp->mountp == NULL) {
		free(vfsp);
		return (ENOMEM);
	    }
	} else {
	    vfsp->mountp = NULL;
	}

	vfsp->next = vfstab_listp;
	vfstab_listp = vfsp;

	return (0);
}

static void
free_vfstab(struct vfstab_list *listp)
{
	struct vfstab_list	*nextp;

	while (listp != NULL) {
	    nextp = listp->next;
	    free((void *)listp->special);
	    free((void *)listp->mountp);
	    free((void *)listp);
	    listp = nextp;
	}

	vfstab_listp = NULL;
}
