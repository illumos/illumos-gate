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

#include	<stdio.h>
#include	<stdarg.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<libintl.h>
#include	<string.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<syslog.h>
#include	<alloca.h>
#include	<sys/vfstab.h>
#include	<sys/mnttab.h>
#include	<sys/mntent.h>
#include	<sys/mount.h>
#include	<sys/filio.h>
#include	<sys/fs/ufs_filio.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<zone.h>
#include	<signal.h>
#include	<strings.h>
#include	"fslib.h"

/* LINTLIBRARY */

#define	BUFLEN		256

#define	TIME_MAX 16

/*
 * Reads all of the entries from the in-kernel mnttab, and returns the
 * linked list of the entries.
 */
mntlist_t *
fsgetmntlist(void)
{
	FILE *mfp;
	mntlist_t *mntl;
	char buf[BUFLEN];

	if ((mfp = fopen(MNTTAB, "r")) == NULL) {
		(void) snprintf(buf, BUFLEN, "fsgetmntlist: fopen %s", MNTTAB);
		perror(buf);
		return (NULL);
	}

	mntl = fsmkmntlist(mfp);

	(void) fclose(mfp);
	return (mntl);
}


static struct extmnttab zmnttab = { 0 };

struct extmnttab *
fsdupmnttab(struct extmnttab *mnt)
{
	struct extmnttab *new;

	new = (struct extmnttab *)malloc(sizeof (*new));
	if (new == NULL)
		goto alloc_failed;

	*new = zmnttab;
	/*
	 * Allocate an extra byte for the mountpoint
	 * name in case a space needs to be added.
	 */
	new->mnt_mountp = (char *)malloc(strlen(mnt->mnt_mountp) + 2);
	if (new->mnt_mountp == NULL)
		goto alloc_failed;
	(void) strcpy(new->mnt_mountp, mnt->mnt_mountp);

	if ((new->mnt_special = strdup(mnt->mnt_special)) == NULL)
		goto alloc_failed;

	if ((new->mnt_fstype = strdup(mnt->mnt_fstype)) == NULL)
		goto alloc_failed;

	if (mnt->mnt_mntopts != NULL)
		if ((new->mnt_mntopts = strdup(mnt->mnt_mntopts)) == NULL)
			goto alloc_failed;

	if (mnt->mnt_time != NULL)
		if ((new->mnt_time = strdup(mnt->mnt_time)) == NULL)
			goto alloc_failed;

	new->mnt_major = mnt->mnt_major;
	new->mnt_minor = mnt->mnt_minor;
	return (new);

alloc_failed:
	(void) fprintf(stderr, gettext("fsdupmnttab: Out of memory\n"));
	fsfreemnttab(new);
	return (NULL);
}

/*
 * Free a single mnttab structure
 */
void
fsfreemnttab(struct extmnttab *mnt)
{

	if (mnt) {
		if (mnt->mnt_special)
			free(mnt->mnt_special);
		if (mnt->mnt_mountp)
			free(mnt->mnt_mountp);
		if (mnt->mnt_fstype)
			free(mnt->mnt_fstype);
		if (mnt->mnt_mntopts)
			free(mnt->mnt_mntopts);
		if (mnt->mnt_time)
			free(mnt->mnt_time);
		free(mnt);
	}
}

void
fsfreemntlist(mntlist_t *mntl)
{
	mntlist_t *mntl_tmp;

	while (mntl) {
		fsfreemnttab(mntl->mntl_mnt);
		mntl_tmp = mntl;
		mntl = mntl->mntl_next;
		free(mntl_tmp);
	}
}

/*
 * Read the mnttab file and return it as a list of mnttab structs.
 * Returns NULL if there was a memory failure.
 */
mntlist_t *
fsmkmntlist(FILE *mfp)
{
	struct extmnttab	mnt;
	mntlist_t	*mhead, *mtail;
	int		ret;

	mhead = mtail = NULL;

	resetmnttab(mfp);
	while ((ret = getextmntent(mfp, &mnt, sizeof (struct extmnttab)))
	    != -1) {
		mntlist_t	*mp;

		if (ret != 0)		/* bad entry */
			continue;

		mp = (mntlist_t *)malloc(sizeof (*mp));
		if (mp == NULL)
			goto alloc_failed;
		if (mhead == NULL)
			mhead = mp;
		else
			mtail->mntl_next = mp;
		mtail = mp;
		mp->mntl_next = NULL;
		mp->mntl_flags = 0;
		if ((mp->mntl_mnt = fsdupmnttab(&mnt)) == NULL)
			goto alloc_failed;
	}
	return (mhead);

alloc_failed:
	fsfreemntlist(mhead);
	return (NULL);
}

/*
 * Return the last entry that matches mntin's special
 * device and/or mountpt.
 * Helps to be robust here, so we check for NULL pointers.
 */
mntlist_t *
fsgetmlast(mntlist_t *ml, struct mnttab *mntin)
{
	mntlist_t	*delete = NULL;

	for (; ml; ml = ml->mntl_next) {
		if (mntin->mnt_mountp && mntin->mnt_special) {
			/*
			 * match if and only if both are equal.
			 */
			if ((strcmp(ml->mntl_mnt->mnt_mountp,
			    mntin->mnt_mountp) == 0) &&
			    (strcmp(ml->mntl_mnt->mnt_special,
			    mntin->mnt_special) == 0))
				delete = ml;
		} else if (mntin->mnt_mountp) {
			if (strcmp(ml->mntl_mnt->mnt_mountp,
			    mntin->mnt_mountp) == 0)
				delete = ml;
		} else if (mntin->mnt_special) {
			if (strcmp(ml->mntl_mnt->mnt_special,
			    mntin->mnt_special) == 0)
				delete = ml;
		}
	}
	return (delete);
}


/*
 * Returns the mountlevel of the pathname in cp.  As examples,
 * / => 1, /bin => 2, /bin/ => 2, ////bin////ls => 3, sdf => 0, etc...
 */
int
fsgetmlevel(char *cp)
{
	int	mlevel;
	char	*cp1;

	if (cp == NULL || *cp == '\0' || *cp != '/')
		return (0);	/* this should never happen */

	mlevel = 1;			/* root (/) is the minimal case */

	for (cp1 = cp + 1; *cp1; cp++, cp1++)
		if (*cp == '/' && *cp1 != '/')	/* "///" counts as 1 */
			mlevel++;

	return (mlevel);
}

/*
 * Returns non-zero if string s is a member of the strings in ps.
 */
int
fsstrinlist(const char *s, const char **ps)
{
	const char *cp;
	cp = *ps;
	while (cp) {
		if (strcmp(s, cp) == 0)
			return (1);
		ps++;
		cp = *ps;
	}
	return (0);
}

static char *empty_opt_vector[] = {
	NULL
};
/*
 * Compare the mount options that were requested by the caller to
 * the options actually supported by the file system.  If any requested
 * options are not supported, print a warning message.
 *
 * WARNING: this function modifies the string pointed to by
 *	the requested_opts argument.
 *
 * Arguments:
 *	requested_opts - the string containing the requested options.
 *	actual_opts - the string returned by mount(2), which lists the
 *		options actually supported.  It is normal for this
 *		string to contain more options than the requested options.
 *		(The actual options may contain the default options, which
 *		may not have been included in the requested options.)
 *	special - device being mounted (only used in error messages).
 *	mountp - mount point (only used in error messages).
 */
void
cmp_requested_to_actual_options(char *requested_opts, char *actual_opts,
	char *special, char *mountp)
{
	char	*option_ptr, *actopt, *equalptr;
	int	found;
	char	*actual_opt_hold, *bufp;

	if (requested_opts == NULL)
		return;

	bufp = alloca(strlen(actual_opts) + 1);

	while (*requested_opts != '\0') {
		(void) getsubopt(&requested_opts, empty_opt_vector,
		    &option_ptr);

		/*
		 * Truncate any "=<value>" string from the end of
		 * the option.
		 */
		if ((equalptr = strchr(option_ptr, '=')) != NULL)
			*equalptr = '\0';

		if (*option_ptr == '\0')
			continue;

		/*
		 * Whilst we don't need this option to perform a lofi
		 * mount, let's not be mendacious enough to complain
		 * about it.
		 */
		if (strcmp(option_ptr, "loop") == 0)
			continue;

		/*
		 * Search for the requested option in the list of options
		 * actually supported.
		 */
		found = 0;

		/*
		 * Need to use a copy of actual_opts because getsubopt
		 * is destructive and we need to scan the actual_opts
		 * string more than once.
		 *
		 * We also need to reset actual_opt_hold to the
		 * beginning of the buffer because getsubopt changes
		 * actual_opt_hold (the pointer).
		 */
		actual_opt_hold = bufp;
		if (actual_opts != NULL)
			(void) strcpy(actual_opt_hold, actual_opts);
		else
			*actual_opt_hold = '\0';

		while (*actual_opt_hold != '\0') {
			(void) getsubopt(&actual_opt_hold, empty_opt_vector,
			    &actopt);

			/* Truncate the "=<value>", if any. */
			if ((equalptr = strchr(actopt, '=')) != NULL)
				*equalptr = '\0';

			if ((strcmp(option_ptr, actopt)) == 0) {
				found = 1;
				break;
			}
		}

		if (found == 0) {
			/*
			 * That we're ignoring the option is always
			 * truthful; the old message that the option
			 * was unknown is often not correct.
			 */
			(void) fprintf(stderr, gettext(
			    "mount: %s on %s - WARNING ignoring option "
			    "\"%s\"\n"), special, mountp, option_ptr);
		}
	}
}
/*
 * FUNCTION:	fsgetmaxphys(int *, int *)
 *
 * INPUT:	int *maxphys - a pointer to an integer that will hold
 *			the value for the system maxphys value.
 *		int *error - 0 means completed successfully
 *			     otherwise this indicates the errno value.
 *
 * RETURNS:	int	- 0 if maxphys not found
 *			- 1 if maxphys is found
 */
int
fsgetmaxphys(int *maxphys, int *error) {

	int	gotit = 0;
	int	fp = open("/", O_RDONLY);

	*error = 0;

	/*
	 * For some reason cannot open root as read only. Need a valid file
	 * descriptor to call the ufs private ioctl. If this open failes,
	 * just assume we cannot get maxphys in this case.
	 */
	if (fp == -1) {
		return (gotit);
	}

	if (ioctl(fp, _FIOGETMAXPHYS, maxphys) == -1) {
		*error = errno;
		(void) close(fp);
		return (gotit);
	}

	(void) close(fp);
	gotit = 1;
	return (gotit);

}

/*
 * The below is limited support for zone-aware commands.
 */
struct zone_summary {
	zoneid_t	zoneid;
	char		rootpath[MAXPATHLEN];
	size_t		rootpathlen;
};

struct zone_summary *
fs_get_zone_summaries(void)
{
	uint_t numzones = 0, oldnumzones = 0;
	uint_t i, j;
	zoneid_t *ids = NULL;
	struct zone_summary *summaries;
	zoneid_t myzoneid = getzoneid();

	for (;;) {
		if (zone_list(ids, &numzones) < 0) {
			perror("unable to retrieve list of zones");
			if (ids != NULL)
				free(ids);
			return (NULL);
		}
		if (numzones <= oldnumzones)
			break;
		if (ids != NULL)
			free(ids);
		ids = malloc(numzones * sizeof (*ids));
		if (ids == NULL) {
			perror("malloc failed");
			return (NULL);
		}
		oldnumzones = numzones;
	}

	summaries = malloc((numzones + 1) * sizeof (*summaries));
	if (summaries == NULL) {
		free(ids);
		perror("malloc failed");
		return (NULL);
	}


	for (i = 0, j = 0; i < numzones; i++) {
		ssize_t len;

		if (ids[i] == myzoneid)
			continue;
		len = zone_getattr(ids[i], ZONE_ATTR_ROOT,
		    summaries[j].rootpath, sizeof (summaries[j].rootpath));
		if (len < 0) {
			/*
			 * Zone must have gone away. Skip.
			 */
			continue;
		}
		/*
		 * Adding a trailing '/' to the zone's rootpath allows us to
		 * use strncmp() to see if a given path resides within that
		 * zone.
		 *
		 * As an example, if the zone's rootpath is "/foo/root",
		 * "/foo/root/usr" resides within the zone, while
		 * "/foo/rootpath" doesn't.
		 */
		(void) strlcat(summaries[j].rootpath, "/",
		    sizeof (summaries[j].rootpath));
		summaries[j].rootpathlen = len;
		summaries[j].zoneid = ids[i];
		j++;
	}
	summaries[j].zoneid = -1;
	free(ids);
	return (summaries);
}

static zoneid_t
fs_find_zone(const struct zone_summary *summaries, const char *mntpt)
{
	uint_t i;

	for (i = 0; summaries[i].zoneid != -1; i++) {
		if (strncmp(mntpt, summaries[i].rootpath,
		    summaries[i].rootpathlen) == 0)
			return (summaries[i].zoneid);
	}
	/*
	 * (-1) is the special token we return to the caller if the mount
	 * wasn't found in any other mounts on the system.  This means it's
	 * only visible to our zone.
	 *
	 * Odd choice of constant, I know, but it beats calling getzoneid() a
	 * million times.
	 */
	return (-1);
}

boolean_t
fs_mount_in_other_zone(const struct zone_summary *summaries, const char *mntpt)
{
	return (fs_find_zone(summaries, mntpt) != -1);
}

/*
 * List of standard options.
 */
static const char *stdopts[] = {
	MNTOPT_RO,			MNTOPT_RW,
	MNTOPT_SUID,			MNTOPT_NOSUID,
	MNTOPT_DEVICES,			MNTOPT_NODEVICES,
	MNTOPT_SETUID,			MNTOPT_NOSETUID,
	MNTOPT_NBMAND,			MNTOPT_NONBMAND,
	MNTOPT_EXEC,			MNTOPT_NOEXEC,
};

#define	NSTDOPT		(sizeof (stdopts) / sizeof (stdopts[0]))

static int
optindx(const char *opt)
{
	int i;

	for (i = 0; i < NSTDOPT; i++) {
		if (strcmp(opt, stdopts[i]) == 0)
			return (i);
	}
	return (-1);
}

/*
 * INPUT:	filesystem option not recognized by the fs specific option
 *		parsing code.
 * OUTPUT:	True if and only if the option is one of the standard VFS
 *		layer options.
 */
boolean_t
fsisstdopt(const char *opt)
{
	return (optindx(opt) != -1);
}
