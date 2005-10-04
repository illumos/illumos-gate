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

static void rummage_dev(ldinfo_t *);
static void do_snm(char *, char *);
static int look_up_name(const char *, disk_list_t *);
static disk_list_t *make_an_entry(char *, char *,
    char *, dir_info_t *, int, ldinfo_t *);
static char *trim(char *, char *, int);
static ldinfo_t	*rummage_devinfo(void);
static void pline(char *, int, char *, char *, ldinfo_t **);
static void insert_dlist_ent(disk_list_t *, disk_list_t **);
static int str_is_digit(char *);
static ldinfo_t *find_ldinfo_match(char *, ldinfo_t *);

static void insert_into_dlist(dir_info_t *, disk_list_t *);
static void cleanup_dlist(dir_info_t *);
static void cleanup_ldinfo(ldinfo_t *);
static int devinfo_ident_disks(di_node_t, void *);
static int devinfo_ident_tapes(di_node_t, void *);
static void process_dir_ent(char *dent, int curr_type,
    char *last_snm, dir_info_t *, ldinfo_t *);

static char *get_nfs_by_minor(uint_t);
static char *cur_hostname(uint_t, kstat_ctl_t *);
static char *cur_special(char *, char *);

extern kstat_ctl_t *kc;
extern mnt_t *nfs;

/*
 * To do: add VXVM support: /dev/vx/dsk and ap support: /dev/ap/
 *
 * Note: Adding support for VxVM is *not* as simple as adding another
 * entry in the table and magically getting to see stuff related to
 * VxVM. The structure is radically different *AND* they don't produce
 * any IO kstats.
 */

#define	OSA_DISK	0
#define	DISK		1
#define	MD_DISK		2
#define	TAPE		3

#define	MAX_TYPES	4

#define	OSA_DISK_PATH	"/dev/osa/dev/dsk"
#define	MD_DISK_PATH	"/dev/md/dsk"
#define	DISK_PATH	"/dev/dsk"
#define	TAPE_PATH	"/dev/rmt"

#define	BASE_TRIM	"../../devices"
#define	MD_TRIM		"../../../devices"
#define	COLON		':'
#define	COMMA		','

#define	NAME_BUFLEN	256

static dir_info_t dlist[MAX_TYPES] = {
	OSA_DISK_PATH, 0, 0, 0, 0, "sd", BASE_TRIM, COLON,
	DISK_PATH, 0, 0, 0, 0, "sd", BASE_TRIM, COLON,
	MD_DISK_PATH, 0, 0, 0, 1, "md", MD_TRIM, COMMA,
	TAPE_PATH, 0, 0, 0, 0, "st", BASE_TRIM, COLON,
};

/*
 * Build a list of disks attached to the system.
 */
static void
build_disk_list(void)
{
	ldinfo_t *ptoi;

	/*
	 * Build the list of devices connected to the system.
	 */
	ptoi = rummage_devinfo();
	rummage_dev(ptoi);
	cleanup_ldinfo(ptoi);
}

/*
 * Walk the /dev/dsk and /dev/rmt directories building a
 * list of interesting devices. Interesting is everything in the
 * /dev/dsk directory. We skip some of the stuff in the /dev/rmt
 * directory.
 *
 * Note that not finding one or more of the directories is not an
 * error.
 */
static void
rummage_dev(ldinfo_t *ptoi)
{
	DIR		*dskp;
	int		i;
	struct stat 	buf;

	for (i = 0; i < MAX_TYPES; i++) {
		if (stat(dlist[i].name, &buf) == 0) {
			if (dlist[i].mtime != buf.st_mtime) {
				/*
				 * We've found a change. We need to cleanup
				 * old information and then rebuild the list
				 * for this device type.
				 */
				cleanup_dlist(&dlist[i]);
				dlist[i].mtime = buf.st_mtime;
				if ((dskp = opendir(dlist[i].name))) {
					struct dirent 	*bpt;
					char	last_snm[NAME_BUFLEN];

					last_snm[0] = NULL;
					while ((bpt = readdir(dskp)) != NULL) {
						if (bpt->d_name[0] != '.') {
							process_dir_ent(
							    bpt->d_name,
							    i, last_snm,
							    &dlist[i],
							    ptoi);
						}
					}
				}
				(void) closedir(dskp);
			}
		}
	}
}

/*
 * Walk the list of located devices and see if we've
 * seen this device before. We look at the short name.
 */
static int
look_up_name(const char *nm, disk_list_t *list)
{
	while (list) {
		if (strcmp(list->dsk, nm) != 0)
			list = list->next;
		else {
			return (1);
		}
	}
	return (0);
}

/*
 * Take a name of the form cNtNdNsN or cNtNdNpN
 * or /dev/dsk/CNtNdNsN or /dev/dsk/cNtNdNpN
 * remove the trailing sN or pN. Simply looking
 * for the first 's' or 'p' doesn't cut it.
 */
static void
do_snm(char *orig, char *shortnm)
{
	char *tmp;
	char *ptmp;
	int done = 0;
	char repl_char = 0;

	tmp = strrchr(orig, 's');
	if (tmp) {
		ptmp = tmp;
		ptmp++;
		done = str_is_digit(ptmp);
	}
	if (done == 0) {
		/*
		 * The string either has no 's' in it
		 * or the stuff trailing the s has a
		 * non-numeric in it. Look to see if
		 * we have an ending 'p' followed by
		 * numerics.
		 */
		tmp = strrchr(orig, 'p');
		if (tmp) {
			ptmp = tmp;
			ptmp++;
			if (str_is_digit(ptmp))
				repl_char = 'p';
			else
				tmp = 0;
		}
	} else {
		repl_char = 's';
	}
	if (tmp)
		*tmp = '\0';
	(void) strcpy(shortnm, orig);
	if (repl_char)
		*tmp = repl_char;
}

/*
 * Create and insert an entry into the device list.
 */
static disk_list_t *
make_an_entry(char *lname, char *shortnm, char *longnm,
	dir_info_t *drent, int devtype, ldinfo_t *ptoi)
{
	disk_list_t	*entry;
	char	*nlnm;
	char 	snm[NAME_BUFLEN];
	ldinfo_t *p;

	entry = safe_alloc(sizeof (disk_list_t));

	nlnm = trim(lname, drent->trimstr, drent->trimchr);
	entry->dsk = safe_strdup(shortnm);
	do_snm(longnm, snm);
	entry->dname = safe_strdup(snm);
	entry->devtype = devtype;
	entry->devidstr = NULL;
	if ((p = find_ldinfo_match(nlnm, ptoi))) {
		entry->dnum = p->dnum;
		entry->dtype = safe_strdup(p->dtype);
		if (p->devidstr)
			entry->devidstr = safe_strdup(p->devidstr);
	} else {
		entry->dtype = safe_strdup(drent->dtype);
		entry->dnum = -1;
		if (drent->dtype) {
			if (strcmp(drent->dtype, "md") == 0) {
				(void) sscanf(shortnm, "d%d", &entry->dnum);
			}
		}
	}
	entry->seen = 0;
	entry->next = 0;
	insert_dlist_ent(entry, &drent->list);
	return (entry);
}

/*
 * slice stuff off beginning and end of /devices directory names derived from
 * device links.
 */
static char *
trim(char *fnm, char *lname, int rchr)
{
	char	*ptr;

	while (*lname == *fnm) {
		lname++;
		fnm++;
	}
	if ((ptr = strrchr(fnm, rchr)))
		*ptr = NULL;
	return (fnm);
}

/*
 * Find an entry matching the name passed in
 */
static ldinfo_t *
find_ldinfo_match(char *name, ldinfo_t *ptoi)
{
	if (name) {
		while (ptoi) {
			if (strcmp(ptoi->name, name))
				ptoi = ptoi->next;
			else
				return (ptoi);
		}
	}
	return (NULL);
}

/*
 * Determine if a name is already in the list of disks. If not, insert the
 * name in the list.
 */
static void
insert_dlist_ent(disk_list_t *n, disk_list_t **hd)
{
	disk_list_t *tmp_ptr;

	if (n->dtype != NULL) {
		tmp_ptr = *hd;
		while (tmp_ptr) {
			if (strcmp(n->dsk, tmp_ptr->dsk) != 0)
				tmp_ptr = tmp_ptr->next;
			else
				break;
		}
		if (tmp_ptr == NULL) {
			/*
			 * We don't do anything with MD_DISK types here
			 * since they don't have partitions.
			 */
			if (n->devtype == DISK || n->devtype == OSA_DISK) {
				n->flags = SLICES_OK;
#if defined(__i386)
				n->flags |= PARTITIONS_OK;
#endif
			} else {
				n->flags = 0;
			}
			/*
			 * Figure out where to insert the name. The list is
			 * ostensibly in sorted order.
			 */
			if (*hd) {
				disk_list_t *follw;
				int	mv;

				tmp_ptr = *hd;

				/*
				 * Look through the list. While the strcmp
				 * value is less than the current value,
				 */
				while (tmp_ptr) {
					if ((mv = strcmp(n->dtype,
					    tmp_ptr->dtype)) < 0) {
						follw = tmp_ptr;
						tmp_ptr = tmp_ptr->next;
					} else
						break;
				}
				if (mv == 0) {
					/*
					 * We're now in the area where the
					 * leading chars of the kstat name
					 * match. We need to insert in numeric
					 * order after that.
					 */
					while (tmp_ptr) {
						if (strcmp(n->dtype,
						    tmp_ptr->dtype) != 0)
							break;
						if (n->dnum > tmp_ptr->dnum) {
							follw = tmp_ptr;
							tmp_ptr = tmp_ptr->next;
						} else
							break;
					}
				}
				/*
				 * We should now be ready to insert an
				 * entry...
				 */
				if (mv >= 0) {
					if (tmp_ptr == *hd) {
						n->next = tmp_ptr;
						*hd = n;
					} else {
						n->next = follw->next;
						follw->next = n;
					}
				} else {
					/*
					 * insert at the end of the
					 * list
					 */
					follw->next = n;
					n->next = 0;
				}
			} else {
				*hd = n;
				n->next = 0;
			}
		}
	}
}

/*
 * find an entry matching the given kstat name in the list
 * of disks, tapes and metadevices.
 */
disk_list_t *
lookup_ks_name(char *dev_nm)
{
	int tried = 0;
	int	dv;
	int	len;
	char	cmpbuf[PATH_MAX + 1];
	struct	list_of_disks *list;
	char	*nm;
	dev_name_t *tmp;
	uint_t	i;

	/*
	 * extract the device type from the kstat name. We expect the
	 * name to be one or more alphabetics followed by the device
	 * numeric id. We do this solely for speed purposes .
	 */
	len = 0;
	nm = dev_nm;
	while (*nm) {
		if (isalpha(*nm)) {
			nm++;
			len++;
		} else
			break;
	}

	if (!*nm)
		return (NULL);

	/*
	 * For each of the elements in the dlist array we keep
	 * an array of pointers to chains for each of the kstat
	 * prefixes found within that directory. This is typically
	 * 'sd' and 'ssd'. We walk the list in the directory and
	 * match on that type. Since the same prefixes can be
	 * in multiple places we keep checking if we don't find
	 * it in the first place.
	 */

	(void) strncpy(cmpbuf, dev_nm, len);
	cmpbuf[len] = NULL;
	dv = atoi(nm);

retry:
	for (i = 0; i < MAX_TYPES; i++) {
		tmp = dlist[i].nf;
		while (tmp) {
			if (strcmp(tmp->name, cmpbuf) == 0) {
				/*
				 * As an optimization we keep mins
				 * and maxes for the devices found.
				 * This helps chop the lists up and
				 * avoid some really long chains as
				 * we would get if we kept only prefix
				 * lists.
				 */
				if (dv >= tmp->min && dv <= tmp->max) {
					list = tmp->list_start;
					while (list) {
						if (list->dnum < dv)
							list = list->next;
						else
							break;
					}
					if (list && list->dnum == dv) {
						return (list);
					}
				}
			}
			tmp = tmp->next;
		}
	}

	if (!tried) {
		tried = 1;
		build_disk_list();
		goto retry;
	}

	return (0);
}

static int
str_is_digit(char *str)
{
	while (*str) {
		if (isdigit(*str))
		    str++;
		else
		    return (0);
	}
	return (1);
}

static void
insert_into_dlist(dir_info_t *d, disk_list_t *e)
{
	dev_name_t *tmp;

	tmp = d->nf;
	while (tmp) {
		if (strcmp(e->dtype, tmp->name) != 0) {
			tmp = tmp->next;
		} else {
			if (e->dnum < tmp->min) {
				tmp->min = e->dnum;
				tmp->list_start = e;
			} else if (e->dnum > tmp->max) {
				tmp->max = e->dnum;
				tmp->list_end = e;
			}
			break;
		}
	}
	if (tmp == NULL) {
		tmp = safe_alloc(sizeof (dev_name_t));
		tmp->name = e->dtype;
		tmp->min = e->dnum;
		tmp->max = e->dnum;
		tmp->list_start = e;
		tmp->list_end = e;
		tmp->next = d->nf;
		d->nf = tmp;
	}
}

/*
 * devinfo_ident_disks() and devinfo_ident_tapes() are the callback functions we
 * use while walking the device tree snapshot provided by devinfo.  If
 * devinfo_ident_disks() identifies that the device being considered has one or
 * more minor nodes _and_ is a block device, then it is a potential disk.
 * Similarly for devinfo_ident_tapes(), except that the second criterion is that
 * the minor_node be a character device.  (This is more inclusive than only
 * tape devices, but will match any entries in /dev/rmt/.)
 *
 * Note: if a driver was previously loaded but is now unloaded, the kstat may
 * still be around (e.g., st) but no information will be found in the
 * libdevinfo tree.
 */

static int
devinfo_ident_disks(di_node_t node, void *arg)
{
	di_minor_t minor = DI_MINOR_NIL;

	if ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		int spectype = di_minor_spectype(minor);

		if (S_ISBLK(spectype)) {
			char *physical_path = di_devfs_path(node);
			int instance = di_instance(node);
			char *driver_name = di_driver_name(node);
			char *devidstr;

			/* lookup the devid, devt specific first */
			if ((di_prop_lookup_strings(di_minor_devt(minor), node,
			    DEVID_PROP_NAME, &devidstr) == -1) &&
			    (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
			    DEVID_PROP_NAME, &devidstr) == -1))
				devidstr = NULL;

			if (driver_name == NULL)
				driver_name = "<nil>";

			pline(physical_path, instance,
				    driver_name, devidstr, arg);
			di_devfs_path_free(physical_path);
		}
	}
	return (DI_WALK_CONTINUE);
}

static int
devinfo_ident_tapes(di_node_t node, void *arg)
{
	di_minor_t minor = DI_MINOR_NIL;

	if ((minor = di_minor_next(node, minor)) != DI_MINOR_NIL) {
		int spectype = di_minor_spectype(minor);

		if (S_ISCHR(spectype)) {
			char *physical_path = di_devfs_path(node);
			int instance = di_instance(node);
			char *binding_name = di_binding_name(node);

			pline(physical_path, instance,
			    binding_name, NULL, arg);
			di_devfs_path_free(physical_path);
		}
	}
	return (DI_WALK_CONTINUE);
}

/*
 * rummage_devinfo() is the driver routine that walks the devinfo snapshot.
 */
static ldinfo_t *
rummage_devinfo(void)
{
	di_node_t root_node;
	ldinfo_t *rv = NULL;

	if ((root_node = di_init("/", DINFOCPYALL)) != DI_NODE_NIL) {
		(void) di_walk_node(root_node, DI_WALK_CLDFIRST, (void *)&rv,
			devinfo_ident_disks);
		(void) di_walk_node(root_node, DI_WALK_CLDFIRST, (void *)&rv,
			devinfo_ident_tapes);
		di_fini(root_node);
	}
	return (rv);
}

/*
 * pline() performs the lookup of the device path in the current list of disks,
 * and adds the appropriate information to the nms list in the case of a match.
 */
static void
pline(char *devfs_path, int instance,
	char *driver_name, char *devidstr, ldinfo_t **list)
{
	ldinfo_t *entry;

	entry = safe_alloc(sizeof (ldinfo_t));
	entry->dnum = instance;
	entry->name = safe_strdup(devfs_path);
	entry->dtype = safe_strdup(driver_name);
	entry->devidstr = safe_strdup(devidstr);
	entry->next = *list;
	*list = entry;
}

/*
 * Cleanup space allocated in dlist processing.
 * We're only interested in cleaning up the list and nf
 * fields in the structure. Everything else is static
 * data.
 */
static void
cleanup_dlist(dir_info_t *d)
{
	dev_name_t *tmp;
	dev_name_t *t1;
	disk_list_t *t2;
	disk_list_t *t3;

	/*
	 * All of the entries in a dev_name_t use information
	 * from a disk_list_t structure that is freed later.
	 * All we need do here is free the dev_name_t
	 * structure itself.
	 */
	tmp = d->nf;
	while (tmp) {
		t1 = tmp->next;
		free(tmp);
		tmp = t1;
	}
	d->nf = 0;
	/*
	 * "Later". Free the disk_list_t structures and their
	 * data attached to this portion of the dir_info
	 * structure.
	 */
	t2 = d->list;
	while (t2) {
		if (t2->dtype) {
			free(t2->dtype);
			t2->dtype = NULL;
		}
		if (t2->dsk) {
			free(t2->dsk);
			t2->dsk = NULL;
		}
		if (t2->dname) {
			free(t2->dname);
			t2->dname = NULL;
		}
		t3 = t2->next;
		free(t2);
		t2 = t3;
	}
	d->list = 0;
}

static void
process_dir_ent(char *dent, int curr_type, char *last_snm,
    dir_info_t *dp, ldinfo_t *ptoi)
{
	struct stat	sbuf;
	char	dnmbuf[PATH_MAX + 1];
	char	lnm[NAME_BUFLEN];
	char	snm[NAME_BUFLEN];
	char	*npt;

	snm[0] = NULL;
	if (curr_type == DISK || curr_type == OSA_DISK) {
		/*
		 * get the short name - omitting
		 * the trailing sN or PN
		 */
		(void) strcpy(lnm, dent);
		do_snm(dent, snm);
	} else if (curr_type == MD_DISK) {
		(void) strcpy(lnm, dent);
		(void) strcpy(snm, dent);
	} else {
		/*
		 * don't want all rewind/etc
		 * devices for a tape
		 */
		if (!str_is_digit(dent))
			return;
		(void) snprintf(snm, sizeof (snm), "rmt/%s", dent);
		(void) snprintf(lnm, sizeof (snm), "rmt/%s", dent);
	}
	/*
	 * See if we've already processed an entry for this device.
	 * If so, we're just another partition so we get another
	 * entry.
	 *
	 * last_snm is an optimization to avoid the function call
	 * and lookup since we'll often see partition records
	 * immediately after the disk record.
	 */
	if (dp->skip_lookup == 0) {
		if (strcmp(snm, last_snm) != 0) {
			/*
			 * a zero return means that
			 * no record was found. We'd
			 * return a pointer otherwise.
			 */
			if (look_up_name(snm,
				dp->list) == 0) {
				(void) strcpy(last_snm, snm);
			} else
				return;
		} else
			return;
	}
	/*
	 * Get the real device name for this beast
	 * by following the link into /devices.
	 */
	(void) snprintf(dnmbuf, sizeof (dnmbuf), "%s/%s", dp->name, dent);
	if (lstat(dnmbuf, &sbuf) != -1) {
		if ((sbuf.st_mode & S_IFMT) == S_IFLNK) {
			/*
			 * It's a link. Get the real name.
			 */
			char	nmbuf[PATH_MAX + 1];
			int	nbyr;

			if ((nbyr = readlink(dnmbuf, nmbuf,
			    sizeof (nmbuf))) != 1) {
				npt = nmbuf;
				/*
				 * readlink does not terminate
				 * the string so we have to
				 * do it.
				 */
				nmbuf[nbyr] = NULL;
			} else
				npt = NULL;
		} else
			npt = lnm;
		/*
		 * make an entry in the device list
		 */
		if (npt) {
			disk_list_t *d;

			d = make_an_entry(npt, snm,
			    dnmbuf, dp,
			    curr_type, ptoi);
			insert_into_dlist(dp, d);
		}
	}
}
static void
cleanup_ldinfo(ldinfo_t *list)
{
	ldinfo_t *tmp;
	while (list) {
		tmp = list;
		list = list->next;
		free(tmp->name);
		free(tmp->dtype);
		if (tmp->devidstr)
			free(tmp->devidstr);
		free(tmp);
	}
}

char *
lookup_nfs_name(char *ks, kstat_ctl_t *kc)
{
	int tried = 0;
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
		} else if (!tried) {
			tried = 1;
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
