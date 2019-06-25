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

/*
 *	Name:		getpathbylabel.c
 *
 *	Description:	Returns the global zone pathname corresponding
 *			to the specified label. The pathname does
 *			not need to match an existing file system object.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <tsol/label.h>
#include <stdlib.h>
#include <zone.h>
#include <sys/mntent.h>
#include <sys/mnttab.h>
#include <stdarg.h>

/*
 * This structure is used to chain mntent structures into a list
 * and to cache stat information for each member of the list.
 */
struct mntlist {
	struct mnttab	*mntl_mnt;
	struct mntlist	*mntl_next;
};


/*
 * Return a pointer to the trailing suffix of full that follows the prefix
 * given by pref.  If pref isn't a prefix of full, return NULL.  Apply
 * pathname semantics to the prefix test, so that pref must match at a
 * component boundary.
 */
static char *
pathsuffix(char *full, char *pref)
{
	int preflen;

	if (full == NULL || pref == NULL)
		return (NULL);

	preflen = strlen(pref);
	if (strncmp(pref, full, preflen) != 0)
		return (NULL);

	/*
	 * pref is a substring of full.  To be a subpath, it cannot cover a
	 * partial component of full.  The last clause of the test handles the
	 * special case of the root.
	 */
	if (full[preflen] != '\0' && full[preflen] != '/' && preflen > 1)
		return (NULL);

	if (preflen == 1 && full[0] == '/')
		return (full);
	else
		return (full + preflen);
}

/*
 * Return zero iff the path named by sub is a leading subpath
 * of the path named by full.
 *
 * Treat null paths as matching nothing.
 */
static int
subpath(char *full, char *sub)
{
	return (pathsuffix(full, sub) == NULL);
}

static void
tsol_mnt_free(struct mnttab *mnt)
{
	if (mnt->mnt_special)
		free(mnt->mnt_special);
	if (mnt->mnt_mountp)
		free(mnt->mnt_mountp);
	if (mnt->mnt_fstype)
		free(mnt->mnt_fstype);
	if (mnt->mnt_mntopts)
		free(mnt->mnt_mntopts);
	free(mnt);
}

static void
tsol_mlist_free(struct mntlist *mlist)
{
	struct mntlist *mlp;
	struct mntlist *oldmlp;

	mlp = mlist;
	while (mlp) {
		struct mnttab *mnt = mlp->mntl_mnt;

		if (mnt)
			tsol_mnt_free(mnt);
		oldmlp = mlp;
		mlp = mlp->mntl_next;
		free(oldmlp);
	}
}

static struct mnttab *
mntdup(struct mnttab *mnt)
{
	struct mnttab *new;

	new = (struct mnttab *)malloc(sizeof (*new));
	if (new == NULL)
		return (NULL);

	new->mnt_special = NULL;
	new->mnt_mountp = NULL;
	new->mnt_fstype = NULL;
	new->mnt_mntopts = NULL;

	new->mnt_special = strdup(mnt->mnt_special);
	if (new->mnt_special == NULL) {
		tsol_mnt_free(new);
		return (NULL);
	}
	new->mnt_mountp = strdup(mnt->mnt_mountp);
	if (new->mnt_mountp == NULL) {
		tsol_mnt_free(new);
		return (NULL);
	}
	new->mnt_fstype = strdup(mnt->mnt_fstype);
	if (new->mnt_fstype == NULL) {
		tsol_mnt_free(new);
		return (NULL);
	}
	new->mnt_mntopts = strdup(mnt->mnt_mntopts);
	if (new->mnt_mntopts == NULL) {
		tsol_mnt_free(new);
		return (NULL);
	}
	return (new);
}

static struct mntlist *
tsol_mkmntlist(void)
{
	FILE *mounted;
	struct mntlist *mntl;
	struct mntlist *mntst = NULL;
	struct mnttab mnt;

	if ((mounted = fopen(MNTTAB, "rF")) == NULL) {
		perror(MNTTAB);
		return (NULL);
	}
	resetmnttab(mounted);
	while (getmntent(mounted, &mnt) == 0) {
		mntl = (struct mntlist *)malloc(sizeof (*mntl));
		if (mntl == NULL) {
			tsol_mlist_free(mntst);
			mntst = NULL;
			break;
		}
		mntl->mntl_mnt = mntdup((struct mnttab *)(&mnt));
		if (mntl->mntl_mnt == NULL) {
			tsol_mlist_free(mntst);
			mntst = NULL;
			break;
		}
		mntl->mntl_next = mntst;
		mntst = mntl;
	}
	(void) fclose(mounted);
	return (mntst);
}

/*
 * This function attempts to convert local zone NFS mounted pathnames
 * into equivalent global zone NFS mounted pathnames. At present
 * it only works for automounted filesystems. It depends on the
 * assumption that both the local and global zone automounters
 * share the same nameservices. It also assumes that any automount
 * map used by a local zone is available to the global zone automounter.
 *
 * The algorithm used consists of three phases.
 *
 * 1. The local zone's mnttab is searched to find the automount map
 *    with the closest matching mountpath.
 *
 * 2. The matching autmount map name is looked up in the global zone's
 *    mnttab to determine the path where it should be mounted in the
 *    global zone.
 *
 * 3. A pathname covered by an appropiate autofs trigger mount in
 *    the global zone is generated as the resolved pathname
 *
 * Among the things that can go wrong is that global zone doesn't have
 * a matching automount map or the mount was not done via the automounter.
 * Either of these cases return a NULL path.
 */
#define	ZONE_OPT "zone="
static int
getnfspathbyautofs(struct mntlist *mlist, zoneid_t zoneid,
    struct mnttab *autofs_mnt, char *globalpath, char *zonepath, int global_len)
{
	struct mntlist *mlp;
	char zonematch[ZONENAME_MAX + 20];
	char zonename[ZONENAME_MAX];
	int  longestmatch;
	struct	mnttab	*mountmatch;

	if (autofs_mnt) {
		mountmatch = autofs_mnt;
		longestmatch = strlen(mountmatch->mnt_mountp);
	} else {
		/*
		 * First we need to get the zonename to look for
		 */
		if (zone_getattr(zoneid, ZONE_ATTR_NAME, zonename,
		    ZONENAME_MAX) == -1) {
			return (0);
		}

		(void) strncpy(zonematch, ZONE_OPT, sizeof (zonematch));
		(void) strlcat(zonematch, zonename, sizeof (zonematch));

		/*
		 * Find the best match for an automount map that
		 * corresponds to the local zone's pathname
		 */
		longestmatch = 0;
		for (mlp = mlist; mlp; mlp = mlp->mntl_next) {
			struct mnttab *mnt = mlp->mntl_mnt;
			int	len;
			int	matchfound;
			char	*token;
			char	*lasts;
			char	mntopts[MAXPATHLEN];

			if (subpath(globalpath, mnt->mnt_mountp) != 0)
				continue;
			if (strcmp(mnt->mnt_fstype, MNTTYPE_AUTOFS))
				continue;

			matchfound = 0;
			(void) strncpy(mntopts, mnt->mnt_mntopts, MAXPATHLEN);
			if ((token = strtok_r(mntopts, ",", &lasts)) != NULL) {
				if (strcmp(token, zonematch) == 0) {
					matchfound = 1;
				} else while ((token = strtok_r(NULL, ",",
				    &lasts)) != NULL) {
					if (strcmp(token, zonematch) == 0) {
						matchfound = 1;
						break;
					}
				}
			}
			if (matchfound) {
				len = strlen(mnt->mnt_mountp);
				if (len > longestmatch) {
					mountmatch = mnt;
					longestmatch = len;
				}
			}
		}
	}
	if (longestmatch == 0) {
		return (0);
	} else {
		/*
		 * Now we may have found the corresponding autofs mount
		 * Try to find the matching global zone autofs entry
		 */

		for (mlp = mlist; mlp; mlp = mlp->mntl_next) {
			char p[MAXPATHLEN];
			size_t zp_len;
			size_t mp_len;

			struct mnttab *mnt = mlp->mntl_mnt;

			if (strcmp(mountmatch->mnt_special,
			    mnt->mnt_special) != 0)
				continue;
			if (strcmp(mnt->mnt_fstype, MNTTYPE_AUTOFS))
				continue;
			if (strstr(mnt->mnt_mntopts, ZONE_OPT) != NULL)
				continue;
			/*
			 * OK, we have a matching global zone automap
			 * so adjust the path for the global zone.
			 */
			zp_len = strlen(zonepath);
			mp_len = strlen(mnt->mnt_mountp);
			(void) strncpy(p, globalpath + zp_len, MAXPATHLEN);
			/*
			 * If both global zone and zone-relative
			 * mountpoint match, just use the same pathname
			 */
			if (strncmp(mnt->mnt_mountp, p, mp_len) == 0) {
				(void) strncpy(globalpath, p, global_len);
				return (1);
			} else {
				(void) strncpy(p, globalpath, MAXPATHLEN);
				(void) strncpy(globalpath, mnt->mnt_mountp,
				    global_len);
				(void) strlcat(globalpath,
				    p + strlen(mountmatch->mnt_mountp),
				    global_len);
				return (1);
			}
		}
		return (0);
	}
}

/*
 * Find the pathname for the entry in mlist that corresponds to the
 * file named by path (i.e., that names a mount table entry for the
 * file system in which path lies).
 *
 * Return 0 is there an error.
 */
static int
getglobalpath(const char *path, zoneid_t zoneid, struct mntlist *mlist,
    char *globalpath)
{
	struct mntlist *mlp;
	char		lofspath[MAXPATHLEN];
	char		zonepath[MAXPATHLEN];
	int		longestmatch;
	struct	mnttab	*mountmatch;

	if (zoneid != GLOBAL_ZONEID) {
		char	*prefix;

		if ((prefix = getzonerootbyid(zoneid)) == NULL) {
			return (0);
		}
		(void) strncpy(zonepath, prefix, MAXPATHLEN);
		(void) strlcpy(globalpath, prefix, MAXPATHLEN);
		(void) strlcat(globalpath, path, MAXPATHLEN);
		free(prefix);
	} else {
		(void) strlcpy(globalpath, path, MAXPATHLEN);
	}

	for (;;) {
		longestmatch = 0;
		for (mlp = mlist; mlp; mlp = mlp->mntl_next) {
			struct mnttab *mnt = mlp->mntl_mnt;
			int	len;

			if (subpath(globalpath, mnt->mnt_mountp) != 0)
				continue;
			len = strlen(mnt->mnt_mountp);
			if (len > longestmatch) {
				mountmatch = mnt;
				longestmatch = len;
			}
		}
		/*
		 * Handle interesting mounts.
		 */
		if ((strcmp(mountmatch->mnt_fstype, MNTTYPE_NFS) == 0) ||
		    (strcmp(mountmatch->mnt_fstype, MNTTYPE_AUTOFS) == 0)) {
			if (zoneid > GLOBAL_ZONEID) {
				struct mnttab *m = NULL;

				if (strcmp(mountmatch->mnt_fstype,
				    MNTTYPE_AUTOFS) == 0)
					m = mountmatch;
				if (getnfspathbyautofs(mlist, zoneid, m,
				    globalpath, zonepath, MAXPATHLEN) == 0) {
					return (0);
				}
			}
			break;
		} else if (strcmp(mountmatch->mnt_fstype, MNTTYPE_LOFS) == 0) {
			/*
			 * count up what's left
			 */
			int	remainder;

			remainder = strlen(globalpath) - longestmatch;
			if (remainder > 0) {
				path = pathsuffix(globalpath,
				    mountmatch->mnt_mountp);
				(void) strlcpy(lofspath, path, MAXPATHLEN);
			}
			(void) strlcpy(globalpath, mountmatch->mnt_special,
			    MAXPATHLEN);
			if (remainder > 0) {
				(void) strlcat(globalpath, lofspath,
				    MAXPATHLEN);
			}
		} else {
			if ((zoneid > GLOBAL_ZONEID) &&
			    (strncmp(path, "/home/", strlen("/home/")) == 0)) {
				char zonename[ZONENAME_MAX];

				/*
				 * If this is a cross-zone reference to
				 * a home directory, it must be corrected.
				 * We should only get here if the zone's
				 * automounter hasn't yet mounted its
				 * autofs trigger on /home.
				 *
				 * Since it is likely to do so in the
				 * future, we will assume that the global
				 * zone already has an equivalent autofs
				 * mount established. By convention,
				 * this should be mounted at the
				 * /zone/<zonename>
				 */

				if (zone_getattr(zoneid, ZONE_ATTR_NAME,
				    zonename, ZONENAME_MAX) == -1) {
					return (0);
				} else {
					(void) snprintf(globalpath, MAXPATHLEN,
					    "/zone/%s%s", zonename, path);
				}
			}
			break;
		}
	}
	return (1);
}


/*
 * This function is only useful for global zone callers
 * It uses the global zone mnttab to translate local zone pathnames
 * into global zone pathnames.
 */
char *
getpathbylabel(const char *path_name, char *resolved_path, size_t bufsize,
    const bslabel_t *sl)
{
	char		ret_path[MAXPATHLEN];	/* pathname to return */
	zoneid_t	zoneid;
	struct mntlist *mlist;

	if (getzoneid() != GLOBAL_ZONEID) {
		errno = EINVAL;
		return (NULL);
	}

	if (path_name[0] != '/') {		/* need absolute pathname */
		errno = EINVAL;
		return (NULL);
	}

	if (resolved_path == NULL) {
		errno = EINVAL;
		return (NULL);
	}

	if ((zoneid = getzoneidbylabel(sl)) == -1)
		return (NULL);

	/*
	 * Construct the list of mounted file systems.
	 */

	if ((mlist = tsol_mkmntlist()) == NULL) {
		return (NULL);
	}
	if (getglobalpath(path_name, zoneid, mlist, ret_path) == 0) {
		tsol_mlist_free(mlist);
		return (NULL);
	}
	tsol_mlist_free(mlist);
	if (strlen(ret_path) >= bufsize) {
		errno = EFAULT;
		return (NULL);
	}
	return (strcpy(resolved_path, ret_path));
} /* end getpathbylabel() */
