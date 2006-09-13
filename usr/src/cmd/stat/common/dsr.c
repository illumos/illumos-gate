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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <sys/types.h>

/*
 * Dependent on types.h, but not including it...
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/dkio.h>
#include <sys/dktp/fdisk.h>
#include <sys/mnttab.h>
#include <sys/mntent.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#include <sys/vfs.h>
#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <kstat.h>
#include <ctype.h>
#include <dirent.h>
#include <libdevinfo.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <devid.h>

#include "dsr.h"
#include "statcommon.h"

/* disk/tape info */
static di_node_t	di_root;	/* for devid */
static di_dim_t		di_dim;		/* for /dev names */
typedef struct {
	char		*minor_name;
	int		minor_isdisk;
} minor_match_t;
static minor_match_t	mm_disk = {"a", 1};
static minor_match_t	mm_tape	= {"", 0};
static char		md_minor_name[MAXPATHLEN];
static minor_match_t	mm_md	= {md_minor_name, 0};
static minor_match_t	*mma_disk_tape[]	= {&mm_disk, &mm_tape, NULL};
static minor_match_t	*mma_md[]		= {&mm_md, NULL};
static char *mdsetno2name(int setno);
#define	DISKLIST_MOD	256		/* ^2 instunit mod hash */
static disk_list_t	*disklist[DISKLIST_MOD];

/* nfs info */
extern kstat_ctl_t	*kc;
extern mnt_t		*nfs;
static int		nfs_tried;
static char		*get_nfs_by_minor(uint_t);
static char		*cur_hostname(uint_t, kstat_ctl_t *);
static char		*cur_special(char *, char *);

/*
 * Clear the snapshot so a cache miss in lookup_ks_name() will cause a fresh
 * snapshot in drvinstunit2dev().
 */
void
cleanup_iodevs_snapshot()
{
	if (di_dim) {
		di_dim_fini(di_dim);
		di_dim = NULL;
	}

	if (di_root) {
		di_fini(di_root);
		di_root = DI_NODE_NIL;
	}

	nfs_tried = 0;
}

/*
 * Find information for (driver, instunit) device: return zero on failure.
 *
 * NOTE: Failure of drvinstunit2dev works out OK for the caller if the kstat
 * name is the same as public name: the caller will just use kstat name.
 */
static int
drvinstunit2dev(char *driver, int instunit,
    char **devpathp, char **adevpathp, char **devidp, int *isdiskp)
{
	int		instance;
	minor_match_t	**mma;
	minor_match_t	*mm;
	char		*devpath;
	char		*devid;
	char		*a, *s;
	int		mdsetno;
	char		*mdsetname = NULL;
	char		amdsetname[MAXPATHLEN];
	char		*devicespath;
	di_node_t	node;


	/* setup "no result" return values */
	if (devpathp)
		*devpathp = NULL;
	if (adevpathp)
		*adevpathp = NULL;
	if (devidp)
		*devidp = NULL;
	if (isdiskp)
		*isdiskp = 0;

	/* take <driver><instance><minor_name> snapshot if not established */
	if (di_dim == NULL) {
		di_dim = di_dim_init();
		if (di_dim == NULL)
			return (0);
	}

	/*
	 * Determine if 'instunit' is an 'instance' or 'unit' based on the
	 * 'driver'.  The current code only detects 'md' metadevice 'units',
	 * and defaults to 'instance' for everything else.
	 *
	 * For a metadevice, 'driver' is either "md" or "<setno>/md".
	 */
	s = strstr(driver, "/md");
	if ((strcmp(driver, "md") == 0) ||
	    (s && isdigit(*driver) && (strcmp(s, "/md") == 0))) {
		/*
		 * "md" unit: Special case translation of "md" kstat names.
		 * For the local set the kstat name is "md<unit>", and for
		 * a shared set the kstat name is "<setno>/md<unit>": we map
		 * these to the minor paths "/pseudo/md@0:<unit>,blk" and
		 * "/pseudo/md@0:<set>,<unit>,blk" respectively.
		 */
		if (isdigit(*driver)) {
			mdsetno = atoi(driver);

			/* convert setno to setname */
			mdsetname = mdsetno2name(mdsetno);
		} else
			mdsetno = 0;

		driver = "md";
		instance = 0;
		mma = mma_md;			/* metadevice dynamic minor */
		(void) snprintf(md_minor_name, sizeof (md_minor_name),
		    "%d,%d,blk", mdsetno, instunit);
	} else {
		instance = instunit;
		mma = mma_disk_tape;		/* disk/tape minors */
	}

	/* Try to find a minor_match that works */
	for (mm = *mma++; mm; mm = *mma++)  {
		if ((devpath = di_dim_path_dev(di_dim,
		    driver, instance, mm->minor_name)) != NULL)
			break;
	}
	if (devpath == NULL)
		return (0);

	/*
	 * At this point we have a devpath result. Return the information about
	 * the result that the caller is asking for.
	 */
	if (devpathp)			/* devpath */
		*devpathp = safe_strdup(devpath);

	if (adevpathp) {		/* abbreviated devpath */
		if (mm->minor_isdisk) {
			/*
			 * For disks we return the last component (with
			 * trailing "s#" or "p#" stripped  off for disks).
			 * For example for devpath of "/dev/dsk/c0t0d0s0" the
			 * abbreviated devpath would be "c0t0d0".
			 */
			a = strrchr(devpath, '/');
			if (a == NULL) {
				free(devpath);
				return (0);
			}
			a++;
			s = strrchr(a, 's');
			if (s == NULL) {
				s = strrchr(a, 'p');
				if (s == NULL) {
					free(devpath);
					return (0);
				}
			}
			/* don't include slice information in devpath */
			*s = '\0';
		} else {
			/*
			 * remove "/dev/", and "/dsk/", from 'devpath' (like
			 * "/dev/md/dsk/d0") to form the abbreviated devpath
			 * (like "md/d0").
			 */
			if ((s = strstr(devpath, "/dev/")) != NULL)
				(void) strcpy(s + 1, s + 5);
			if ((s = strstr(devpath, "/dsk/")) != NULL)
				(void) strcpy(s + 1, s + 5);

			/*
			 * If we have an mdsetname, convert abbreviated setno
			 * notation (like "md/shared/1/d0" to abbreviated
			 * setname notation (like "md/red/d0").
			 */
			if (mdsetname) {
				a = strrchr(devpath, '/');
				(void) snprintf(amdsetname, sizeof (amdsetname),
				    "md/%s%s", mdsetname, a);
				free(mdsetname);
				a = amdsetname;
			} else {
				if (*devpath == '/')
					a = devpath + 1;
				else
					a = devpath;
			}
		}
		*adevpathp = safe_strdup(a);
	}

	if (devidp) {			/* lookup the devid */
		/* take snapshots if not established */
		if (di_root == DI_NODE_NIL) {
			di_root = di_init("/", DINFOCACHE);
		}
		if (di_root) {
			/* get path to /devices devinfo node */
			devicespath = di_dim_path_devices(di_dim,
			    driver, instance, NULL);
			if (devicespath) {
				/* find the node in the snapshot */
				node = di_lookup_node(di_root, devicespath);
				free(devicespath);

				/* and lookup devid property on the node */
				if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
				    DEVID_PROP_NAME, &devid) != -1)
					*devidp = devid;
			}
		}
	}

	if (isdiskp)
		*isdiskp = mm->minor_isdisk;

	free(devpath);
	return (1);				/* success */
}

/*
 * Find/create a disk_list entry for "<driver><instunit>" given a kstat name.
 * The basic format of a kstat name is "<driver><instunit>,<partition>". The
 * <instunit> is a base10 number, and the ",<partition>" part is optional.
 *
 * NOTE: In the case of non-local metadevices, the format of "<driver>" in
 * a kstat name is acutally "<setno>/md".
 */
disk_list_t *
lookup_ks_name(char *ks_name, int want_devid)
{
	char		*p;
	int		len;
	char		driver[MAXNAMELEN];
	int		instunit;
	disk_list_t	**dlhp;		/* disklist head */
	disk_list_t	*entry;
	char		*devpath;
	char		*adevpath = NULL;
	char		*devid = NULL;
	int		isdisk;

	/*
	 * Extract <driver> and <instunit> from kstat name.
	 * Filter out illegal forms (like all digits).
	 */
	if ((ks_name == NULL) || (*ks_name == 0) ||
	    (strspn(ks_name, "0123456789") == strlen(ks_name)))
		return (NULL);
	p = strrchr(ks_name, ',');		/* start of ",partition" */
	if (p == NULL)
		p = &ks_name[strlen(ks_name) - 1];	/* last char */
	else
		p--;				/* before ",partition" */

	while ((p >= ks_name) && isdigit(*p))
		p--;				/* backwards over digits */
	p++;					/* start of instunit */
	if ((*p == '\0') || (*p == ','))
		return (NULL);			/* no <instunit> */
	len = p - ks_name;
	(void) strncpy(driver, ks_name, len);
	driver[len] = '\0';
	instunit = atoi(p);

	/* hash and search for existing disklist entry */
	dlhp = &disklist[instunit & (DISKLIST_MOD - 1)];
	for (entry = *dlhp; entry; entry = entry->next) {
		if ((strcmp(entry->dtype, driver) == 0) &&
		    (entry->dnum == instunit)) {
			return (entry);
		}
	}

	/* not found, try to get dev information */
	if (drvinstunit2dev(driver, instunit, &devpath, &adevpath,
	    want_devid ? &devid : NULL, &isdisk) == 0) {
		return (NULL);
	}

	/* and make a new disklist entry ... */
	entry = safe_alloc(sizeof (disk_list_t));
	entry->dtype = safe_strdup(driver);
	entry->dnum = instunit;
	entry->dname = devpath;
	entry->dsk = adevpath;
	entry->devidstr = devid;
	entry->flags = 0;
	if (isdisk) {
		entry->flags |= SLICES_OK;
#if defined(__i386)
		entry->flags |= PARTITIONS_OK;
#endif
	}
	entry->seen = 0;

	/* add new entry to head of instunit hashed list */
	entry->next = *dlhp;
	*dlhp = entry;
	return (entry);
}

/*
 * Convert metadevice setno to setname by looking in /dev/md for symlinks
 * that point to "shared/setno" - the name of such a symlink is the setname.
 * The caller is responsible for freeing the returned string.
 */
static char *
mdsetno2name(int setno)
{
	char		setlink[MAXPATHLEN + 1];
	char		link[MAXPATHLEN + 1];
	char		path[MAXPATHLEN + 1];
	char		*p;
	DIR		*dirp;
	struct dirent	*dp;
	size_t		len;
	char		*mdsetname = NULL;

	/* we are looking for a link to setlink */
	(void) snprintf(setlink, MAXPATHLEN, "shared/%d", setno);

	/* in the directory /dev/md */
	(void) strcpy(path, "/dev/md/");
	p = path + strlen(path);
	dirp = opendir(path);
	if (dirp == NULL)
		return (NULL);

	/* loop through /dev/md directory entries */
	while ((dp = readdir(dirp)) != NULL) {

		/* doing a readlink of entry (fails for non-symlinks) */
		*p = '\0';
		(void) strcpy(p, dp->d_name);
		if ((len = readlink(path, link, MAXPATHLEN)) == (size_t)-1)
			continue;

		/* and looking for a link to setlink */
		link[len] = '\0';
		if (strcmp(setlink, link))
			continue;

		/* found- name of link is the setname */
		mdsetname = safe_strdup(dp->d_name);
		break;
	}

	(void) closedir(dirp);
	return (mdsetname);
}

char *
lookup_nfs_name(char *ks, kstat_ctl_t *kc)
{
	uint_t minor;
	char *host, *path;
	char *cp;
	char *rstr = 0;
	size_t len;

	if (sscanf(ks, "nfs%u", &minor) == 1) {
retry:
		cp = get_nfs_by_minor(minor);
		if (cp) {
			if (strchr(cp, ',') == NULL) {
				rstr = safe_strdup(cp);
				return (rstr);
			}
			host = cur_hostname(minor, kc);
			if (host) {
				if (*host) {
					path = cur_special(host, cp);
					if (path) {
						len = strlen(host);
						len += strlen(path);
						len += 2;
						rstr = safe_alloc(len);
						(void) snprintf(rstr, len,
						    "%s:%s", host, path);
					} else {
						rstr = safe_strdup(cp);
					}
				} else {
					rstr = safe_strdup(ks);
				}
				free(host);
			} else {
				rstr = safe_strdup(cp);
			}
		} else if (nfs_tried == 0) {
			nfs_tried = 1;
			do_mnttab();
			goto retry;
		}
	}
	return (rstr);
}

static char *
get_nfs_by_minor(uint_t minor)
{
	mnt_t *localnfs;

	localnfs = nfs;
	while (localnfs) {
		if (localnfs->minor == minor) {
			return (localnfs->device_name);
		}
		localnfs = localnfs->next;
	}
	return (0);
}

/*
 * Read the cur_hostname from the mntinfo kstat
 */
static char *
cur_hostname(uint_t minor, kstat_ctl_t *kc)
{
	kstat_t *ksp;
	static struct mntinfo_kstat mik;
	char *rstr;

	for (ksp = kc->kc_chain; ksp; ksp = ksp->ks_next) {
		if (ksp->ks_type != KSTAT_TYPE_RAW)
			continue;
		if (ksp->ks_instance != minor)
			continue;
		if (strcmp(ksp->ks_module, "nfs"))
			continue;
		if (strcmp(ksp->ks_name, "mntinfo"))
			continue;
		if (ksp->ks_flags & KSTAT_FLAG_INVALID)
			return (NULL);
		if (kstat_read(kc, ksp, &mik) == -1)
			return (NULL);
		rstr = safe_strdup(mik.mik_curserver);
		return (rstr);
	}
	return (NULL);
}

/*
 * Given the hostname of the mounted server, extract the server
 * mount point from the mnttab string.
 *
 * Common forms:
 *	server1,server2,server3:/path
 *	server1:/path,server2:/path
 * or a hybrid of the two
 */
static char *
cur_special(char *hostname, char *special)
{
	char *cp;
	char *path;
	size_t hlen = strlen(hostname);

	/*
	 * find hostname in string
	 */
again:
	if ((cp = strstr(special, hostname)) == NULL)
		return (NULL);

	/*
	 * hostname must be followed by ',' or ':'
	 */
	if (cp[hlen] != ',' && cp[hlen] != ':') {
		special = &cp[hlen];
		goto again;
	}

	/*
	 * If hostname is followed by a ',' eat all characters until a ':'
	 */
	cp = &cp[hlen];
	if (*cp == ',') {
		cp++;
		while (*cp != ':') {
			if (*cp == NULL)
				return (NULL);
			cp++;
		}
	}
	path = ++cp;			/* skip ':' */

	/*
	 * path is terminated by either 0, or space or ','
	 */
	while (*cp) {
		if (isspace(*cp) || *cp == ',') {
			*cp = NULL;
			return (path);
		}
		cp++;
	}
	return (path);
}
