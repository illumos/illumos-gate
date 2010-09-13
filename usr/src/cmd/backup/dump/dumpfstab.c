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
 * Copyright (c) 1996,1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dump.h"

/*
 * File system mount table input routines.  We handle a
 * a combination of BSD and SVR4 formats by coding functions
 * to explicitly read the SVR4 vfstab file and using
 * #define's to build a routine to read both BSD files
 * (fstab and mtab) and SVR4's mnttab file.  Internally
 * we keep everything in the common (mtab/mnttab) format.
 */
static struct pmntent {
	struct mntent	*pm_mnt;
	struct pmntent	*pm_next;
} *mnttable;

/* Note that nothing is ever free()'d, so this is safe */
#define	mntstrdup(s)	((s) ? strdup((s)) : "")

#ifdef __STDC__
static struct mntent *mygetmntent(FILE *, char *);
static struct pmntent *addmtab(char *, struct pmntent *);
static struct mntent *allocmntent(struct mntent *);
#else /* !__STDC__ */
static struct pmntent *addmtab();
static struct mntent *mygetmntent();
static struct mntent *allocmntent();
static int idatesort();
#endif

static struct mntent *
mygetmntent(f, name)
	FILE *f;
	char *name;
{
	static struct mntent mt;
	int status;

	if ((status = getmntent(f, &mt)) == 0)
		return (&mt);

	switch (status) {
	case EOF:	break;		/* normal exit condition */
	case MNT_TOOLONG:
		msg(gettext("%s has a line that is too long\n"), name);
		break;
	case MNT_TOOMANY:
		msg(gettext("%s has a line with too many entries\n"), name);
		break;
	case MNT_TOOFEW:
		msg(gettext("%s has a line with too few entries\n"), name);
		break;
	default:
		msg(gettext(
			"Unknown return code, %d, from getmntent() on %s\n"),
			status, name);
		break;
	}

	return (NULL);
}

/*
 * Read in SVR4 vfstab-format table.
 */
static struct pmntent *
addvfstab(tablename, pm)
	char	*tablename;
	struct pmntent *pm;
{
	struct mnttab *mnt;
	struct vfstab vfs;
	FILE	*tp;
	int status;

	assert(((mnttable == NULL) && (pm == NULL)) || (pm != NULL));

	/*
	 * No need to secure this, as tablename is hard-coded to VFSTAB,
	 * and that file is in /etc.  If random people have write-permission
	 * there, then there are more problems than any degree of paranoia
	 * on our part can fix.
	 */
	tp = fopen(tablename, "r");
	if (tp == (FILE *)0) {
		msg(gettext("Cannot open %s for dump table information.\n"),
			tablename);
		return ((struct pmntent *)0);
	}
	while ((status = getvfsent(tp, &vfs)) == 0) {
		if (vfs.vfs_fstype == (char *)0 ||
		    strcmp(vfs.vfs_fstype, MNTTYPE_42) != 0)
			continue;

		mnt = (struct mnttab *)xmalloc(sizeof (*mnt));
		mnt->mnt_fsname = mntstrdup(vfs.vfs_special);
		mnt->mnt_dir = mntstrdup(vfs.vfs_mountp);
		mnt->mnt_type = mntstrdup(vfs.vfs_fstype);
		mnt->mnt_opts = mntstrdup(vfs.vfs_mntopts);

		if (mnttable == (struct pmntent *)0)
			/*
			 * Guaranteed by caller that pm will also be NULL,
			 * so no memory leak to worry about.
			 */
			mnttable = pm = (struct pmntent *)xmalloc(sizeof (*pm));
		else {
			/* Guaranteed pm not NULL by caller and local logic */
			pm->pm_next = (struct pmntent *)xmalloc(sizeof (*pm));
			pm = pm->pm_next;
		}
		pm->pm_mnt = mnt;
		pm->pm_next = (struct pmntent *)0;
	}

	switch (status) {
	case EOF:	break;		/* normal exit condition */
	case VFS_TOOLONG:
		msg(gettext("%s has a line that is too long\n"), tablename);
		break;
	case VFS_TOOMANY:
		msg(gettext("%s has a line with too many entries\n"),
			tablename);
		break;
	case VFS_TOOFEW:
		msg(gettext("%s has a line with too few entries\n"), tablename);
		break;
	default:
		msg(gettext(
			"Unknown return code, %d, from getvfsent() on %s\n"),
			status, tablename);
		break;
	}
	(void) fclose(tp);
	return (pm);
}

static struct mntent *
allocmntent(mnt)
	struct mntent *mnt;
{
	struct mntent *new;

	new = (struct mntent *)xmalloc(sizeof (*mnt));
	new->mnt_fsname = mntstrdup(mnt->mnt_fsname);	/* mnt_special */
	new->mnt_dir = mntstrdup(mnt->mnt_dir);		/* mnt_mountp  */
	new->mnt_type = mntstrdup(mnt->mnt_type);	/* mnt_fstype  */
	new->mnt_opts = mntstrdup(mnt->mnt_opts);	/* mnt_mntopts */
	return (new);
}

void
mnttabread()
{
	struct pmntent *pm = (struct pmntent *)0;

	if (mnttable != (struct pmntent *)0)
		return;
	/*
	 * Read in the file system mount tables.  Order
	 * is important as the first matched entry is used
	 * if the target device/filesystem is not mounted.
	 * We try fstab or vfstab first, then mtab or mnttab.
	 */
	pm = addvfstab(VFSTAB, pm);
	(void) addmtab(MOUNTED, pm);
}

static struct pmntent *
addmtab(tablename, pm)
	char	*tablename;
	struct pmntent *pm;
{
	struct mntent *mnt;
	FILE	*tp;

	tp = setmntent(tablename, "r");
	if (tp == (FILE *)0) {
		msg(gettext("Cannot open %s for dump table information.\n"),
			tablename);
		return ((struct pmntent *)0);
	}
	while (mnt = mygetmntent(tp, tablename)) {
		if (mnt->mnt_type == (char *)0 ||
		    strcmp(mnt->mnt_type, MNTTYPE_42) != 0)
			continue;

		mnt = allocmntent(mnt);
		if (mnttable == (struct pmntent *)0)
			/*
			 * Guaranteed by caller that pm will also be NULL,
			 * so no memory leak to worry about.
			 */
			mnttable = pm = (struct pmntent *)xmalloc(sizeof (*pm));
		else {
			/* Guaranteed pm not NULL by caller and local logic */
			pm->pm_next = (struct pmntent *)xmalloc(sizeof (*pm));
			pm = pm->pm_next;
		}
		pm->pm_mnt = mnt;
		pm->pm_next = (struct pmntent *)0;
	}
	(void) endmntent(tp);
	return (pm);
}

/*
 * Search in fstab and potentially mtab for a file name.
 * If "mounted" is non-zero, the target file system must
 * be mounted in order for the search to succeed.
 * This file name can be either the special or the path file name.
 *
 * The entries in either fstab or mtab are the BLOCK special names,
 * not the character special names.
 * The caller of mnttabsearch assures that the character device
 * is dumped (that is much faster)
 *
 * The file name can omit the leading '/'.
 */
struct mntent *
mnttabsearch(key, mounted)
	char	*key;
	int	mounted;
{
	struct pmntent *pm;
	struct mntent *mnt;
	struct mntent *first = (struct mntent *)0;
	char *s;
	char *gotreal;
	char path[MAXPATHLEN];

	for (pm = mnttable; pm; pm = pm->pm_next) {
		s = NULL;
		mnt = pm->pm_mnt;
		if (strcmp(mnt->mnt_dir, key) == 0)
			goto found;
		if (strcmp(mnt->mnt_fsname, key) == 0)
			goto found;
		if ((s = rawname(mnt->mnt_fsname)) != NULL &&
		    strcmp(s, key) == 0)
			goto found;

		gotreal = realpath(mnt->mnt_dir, path);
		if (gotreal && strcmp(path, key) == 0)
			goto found;
		if (key[0] != '/') {
			if (*mnt->mnt_fsname == '/' &&
			    strcmp(mnt->mnt_fsname + 1, key) == 0)
				goto found;
			if (*mnt->mnt_dir == '/' &&
			    strcmp(mnt->mnt_dir + 1, key) == 0)
				goto found;
			if (gotreal && *path == '/' &&
			    strcmp(path + 1, key) == 0)
				goto found;
		}
		if (s != NULL && s != mnt->mnt_fsname)
			free(s);
		continue;
found:
		/* Pointer comparison, not string comparison */
		if (s != NULL && s != mnt->mnt_fsname)
			free(s);
		/*
		 * Found a match; return immediately if
		 * it is mounted (valid), otherwise just
		 * record if it's the first matched entry.
		 */
		if (lf_ismounted(mnt->mnt_fsname, mnt->mnt_dir) > 0)
			return (mnt);
		else if (first == (struct mntent *)0)
			first = mnt;
	}
	/*
	 * If we get here, there were either
	 * no matches, or no matched entries
	 * were mounted.  Return failure if
	 * we were supposed to find a mounted
	 * entry, otherwise return the first
	 * matched entry (or null).
	 */
	if (mounted)
		return ((struct mntent *)0);
	return (first);
}

static struct pmntent *current;
static int set;

void
#ifdef __STDC__
setmnttab(void)
#else
setmnttab()
#endif
{
	current = mnttable;
	set = 1;
}

struct mntent *
#ifdef __STDC__
getmnttab(void)
#else
getmnttab()
#endif
{
	struct pmntent *pm;

	if (!set)
		setmnttab();
	pm = current;
	if (current) {
		current = current->pm_next;
		return (pm->pm_mnt);
	}
	return ((struct mntent *)0);
}
