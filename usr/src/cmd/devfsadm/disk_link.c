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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <devfsadm.h>
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <bsm/devalloc.h>

#define	DISK_SUBPATH_MAX 100
#define	RM_STALE 0x01
#define	DISK_LINK_RE	"^r?dsk/c[0-9]+(t[0-9A-F]+)?d[0-9]+(((s|p))[0-9]+)?$"
#define	DISK_LINK_TO_UPPER(ch)\
	(((ch) >= 'a' && (ch) <= 'z') ? (ch - 'a' + 'A') : ch)

#define	SLICE_SMI	"s7"
#define	SLICE_EFI	""

#define	MN_SMI		"h"
#define	MN_EFI		"wd"
#define	ASCIIWWNSIZE	255

extern int system_labeled;

static int disk_callback_chan(di_minor_t minor, di_node_t node);
static int disk_callback_nchan(di_minor_t minor, di_node_t node);
static int disk_callback_wwn(di_minor_t minor, di_node_t node);
static int disk_callback_fabric(di_minor_t minor, di_node_t node);
static void disk_common(di_minor_t minor, di_node_t node, char *disk,
				int flags);
static char *diskctrl(di_node_t node, di_minor_t minor);
static int reserved_links_exist(di_node_t node, di_minor_t minor, int nflags);


static devfsadm_create_t disk_cbt[] = {
	{ "disk", "ddi_block", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_nchan
	},
	{ "disk", "ddi_block:channel", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_chan
	},
	{ "disk", "ddi_block:fabric", NULL,
		TYPE_EXACT, ILEVEL_0, disk_callback_fabric
	},
	{ "disk", "ddi_block:wwn", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_wwn
	},
	{ "disk", "ddi_block:cdrom", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_nchan
	},
	{ "disk", "ddi_block:cdrom:channel", NULL,
	    TYPE_EXACT, ILEVEL_0, disk_callback_chan
	},
};

DEVFSADM_CREATE_INIT_V0(disk_cbt);

/*
 * HOT auto cleanup of disks not desired.
 */
static devfsadm_remove_t disk_remove_cbt[] = {
	{ "disk", DISK_LINK_RE, RM_POST,
		ILEVEL_0, devfsadm_rm_all
	}
};

DEVFSADM_REMOVE_INIT_V0(disk_remove_cbt);

static devlink_re_t disks_re_array[] = {
	{"^r?dsk/c([0-9]+)", 1},
	{"^cfg/c([0-9]+)$", 1},
	{"^scsi/.+/c([0-9]+)", 1},
	{NULL}
};

static char *disk_mid = "disk_mid";
static char *modname = "disk_link";

int
minor_init()
{
	devfsadm_print(disk_mid,
	    "%s: minor_init(): Creating disks reserved ID cache\n",
	    modname);
	return (devfsadm_reserve_id_cache(disks_re_array, NULL));
}

static int
disk_callback_chan(di_minor_t minor, di_node_t node)
{
	char *addr;
	char disk[20];
	uint_t targ;
	uint_t lun;

	addr = di_bus_addr(node);
	(void) sscanf(addr, "%X,%X", &targ, &lun);
	(void) sprintf(disk, "t%dd%d", targ, lun);
	disk_common(minor, node, disk, 0);
	return (DEVFSADM_CONTINUE);

}

static int
disk_callback_nchan(di_minor_t minor, di_node_t node)
{
	char *addr;
	char disk[10];
	uint_t lun;

	addr = di_bus_addr(node);
	(void) sscanf(addr, "%X", &lun);
	(void) sprintf(disk, "d%d", lun);
	disk_common(minor, node, disk, 0);
	return (DEVFSADM_CONTINUE);

}

static int
disk_callback_wwn(di_minor_t minor, di_node_t node)
{
	char disk[10];
	int lun;
	int targ;
	int *intp;

	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "target", &intp) <= 0) {
		return (DEVFSADM_CONTINUE);
	}
	targ = *intp;
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "lun", &intp) <= 0) {
		lun = 0;
	} else {
		lun = *intp;
	}
	(void) sprintf(disk, "t%dd%d", targ, lun);

	disk_common(minor, node, disk, RM_STALE);

	return (DEVFSADM_CONTINUE);
}

static int
disk_callback_fabric(di_minor_t minor, di_node_t node)
{
	char disk[DISK_SUBPATH_MAX];
	int lun;
	int count;
	int *intp;
	uchar_t *str;
	uchar_t *wwn;
	uchar_t ascii_wwn[ASCIIWWNSIZE];

	if (di_prop_lookup_strings(DDI_DEV_T_ANY, node,
	    "client-guid", (char **)&wwn) > 0) {
		if (strlcpy((char *)ascii_wwn, (char *)wwn,
		    sizeof (ascii_wwn)) >= sizeof (ascii_wwn)) {
			devfsadm_errprint("SUNW_disk_link: GUID too long:%d",
			    strlen((char *)wwn));
			return (DEVFSADM_CONTINUE);
		}
		lun = 0;
	} else if (di_prop_lookup_bytes(DDI_DEV_T_ANY, node,
	    "port-wwn", &wwn) > 0) {
		if (di_prop_lookup_ints(DDI_DEV_T_ANY, node,
		    "lun", &intp) > 0) {
			lun = *intp;
		} else {
			lun = 0;
		}

		for (count = 0, str = ascii_wwn; count < 8; count++, str += 2) {
			(void) sprintf((caddr_t)str, "%02x", wwn[count]);
		}
		*str = '\0';
	} else {
		return (DEVFSADM_CONTINUE);
	}

	for (str = ascii_wwn; *str != '\0'; str++) {
		*str = DISK_LINK_TO_UPPER(*str);
	}

	(void) snprintf(disk, DISK_SUBPATH_MAX, "t%sd%d", ascii_wwn, lun);

	disk_common(minor, node, disk, RM_STALE);

	return (DEVFSADM_CONTINUE);
}

/*
 * This function is called for every disk minor node.
 * Calls enumerate to assign a logical controller number, and
 * then devfsadm_mklink to make the link.
 */
static void
disk_common(di_minor_t minor, di_node_t node, char *disk, int flags)
{
	char l_path[PATH_MAX + 1];
	char sec_path[PATH_MAX + 1];
	char stale_re[DISK_SUBPATH_MAX];
	char *dir;
	char slice[4];
	char *mn;
	char *ctrl;
	char *nt = NULL;
	int *int_prop;
	int  nflags = 0;

	if (strstr(mn = di_minor_name(minor), ",raw")) {
		dir = "rdsk";
	} else {
		dir = "dsk";
	}

	if (mn[0] < 113) {
		(void) sprintf(slice, "s%d", mn[0] - 'a');
	} else if (strncmp(mn, MN_EFI, 2) != 0) {
		(void) sprintf(slice, "p%d", mn[0] - 'q');
	} else {
		/* For EFI label */
		(void) sprintf(slice, SLICE_EFI);
	}

	nflags = 0;
	if (system_labeled) {
		nt = di_minor_nodetype(minor);
		if ((nt != NULL) &&
		    ((strcmp(nt, DDI_NT_CD) == 0) ||
		    (strcmp(nt, DDI_NT_CD_CHAN) == 0) ||
		    (strcmp(nt, DDI_NT_BLOCK_CHAN) == 0))) {
			nflags = DA_ADD|DA_CD;
		}
	}

	if (reserved_links_exist(node, minor, nflags) == DEVFSADM_SUCCESS) {
		devfsadm_print(disk_mid, "Reserved link exists. Not "
		    "creating links for slice %s\n", slice);
		return;
	}

	if (NULL == (ctrl = diskctrl(node, minor)))
		return;

	(void) strcpy(l_path, dir);
	(void) strcat(l_path, "/c");
	(void) strcat(l_path, ctrl);
	(void) strcat(l_path, disk);

	/*
	 * If switching between SMI and EFI label or vice versa
	 * cleanup the previous label's devlinks.
	 */
	if (*mn == *(MN_SMI) || (strncmp(mn, MN_EFI, 2) == 0)) {
		char *s, tpath[PATH_MAX + 1];
		struct stat sb;

		s = l_path + strlen(l_path);
		(void) strcat(l_path, (*mn == *(MN_SMI))
		    ? SLICE_EFI : SLICE_SMI);
		/*
		 * Attempt the remove only if the stale link exists
		 */
		(void) snprintf(tpath, sizeof (tpath), "%s/dev/%s",
		    devfsadm_root_path(), l_path);
		if (lstat(tpath, &sb) != -1)
			devfsadm_rm_all(l_path);
		*s = '\0';
	}
	(void) strcat(l_path, slice);

	(void) devfsadm_mklink(l_path, node, minor, nflags);

	/* secondary links for removable and hotpluggable devices */
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "removable-media",
	    &int_prop) >= 0) {
		(void) strcpy(sec_path, "removable-media/");
		(void) strcat(sec_path, l_path);
		(void) devfsadm_secondary_link(sec_path, l_path, 0);
	}
	if (di_prop_lookup_ints(DDI_DEV_T_ANY, node, "hotpluggable",
	    &int_prop) >= 0) {
		(void) strcpy(sec_path, "hotpluggable/");
		(void) strcat(sec_path, l_path);
		(void) devfsadm_secondary_link(sec_path, l_path, 0);
	}

	if ((flags & RM_STALE) == RM_STALE) {
		(void) strcpy(stale_re, "^");
		(void) strcat(stale_re, dir);
		(void) strcat(stale_re, "/c");
		(void) strcat(stale_re, ctrl);
		(void) strcat(stale_re, "t[0-9A-F]+d[0-9]+(s[0-9]+)?$");
		/*
		 * optimizations are made inside of devfsadm_rm_stale_links
		 * instead of before calling the function, as it always
		 * needs to add the valid link to the cache.
		 */
		devfsadm_rm_stale_links(stale_re, l_path, node, minor);
	}

	free(ctrl);
}


/* index of enumeration rule applicable to this module */
#define	RULE_INDEX	0

static char *
diskctrl(di_node_t node, di_minor_t minor)
{
	char path[PATH_MAX + 1];
	char *devfspath;
	char *buf, *mn;

	devfsadm_enumerate_t rules[3] = {
	    {"^r?dsk$/^c([0-9]+)", 1, MATCH_PARENT},
	    {"^cfg$/^c([0-9]+)$", 1, MATCH_ADDR},
	    {"^scsi$/^.+$/^c([0-9]+)", 1, MATCH_PARENT}
	};

	mn = di_minor_name(minor);

	if ((devfspath = di_devfs_path(node)) == NULL) {
		return (NULL);
	}
	(void) strcpy(path, devfspath);
	(void) strcat(path, ":");
	(void) strcat(path, mn);
	di_devfs_path_free(devfspath);

	/*
	 * Use controller component of disk path
	 */
	if (disk_enumerate_int(path, RULE_INDEX, &buf, rules, 3) ==
	    DEVFSADM_MULTIPLE) {

		/*
		 * We failed because there are multiple logical controller
		 * numbers for a single physical controller.  If we use node
		 * name also in the match it should fix this and only find one
		 * logical controller. (See 4045879).
		 * NOTE: Rules for controllers are not changed, as there is
		 * no unique controller number for them in this case.
		 *
		 * MATCH_UNCACHED flag is private to the "disks" and "sgen"
		 * modules. NOT to be used by other modules.
		 */

		rules[0].flags = MATCH_NODE | MATCH_UNCACHED; /* disks */
		rules[2].flags = MATCH_NODE | MATCH_UNCACHED; /* generic scsi */
		if (devfsadm_enumerate_int(path, RULE_INDEX, &buf, rules, 3)) {
			return (NULL);
		}
	}

	return (buf);
}

typedef struct dvlist {
	char *dv_link;
	struct dvlist *dv_next;
} dvlist_t;

static void
free_dvlist(dvlist_t **pp)
{
	dvlist_t *entry;

	while (*pp) {
		entry = *pp;
		*pp = entry->dv_next;
		assert(entry->dv_link);
		free(entry->dv_link);
		free(entry);
	}
}
static int
dvlink_cb(di_devlink_t devlink, void *arg)
{
	char *path;
	char *can_path;
	dvlist_t **pp = (dvlist_t **)arg;
	dvlist_t *entry = NULL;

	entry = calloc(1, sizeof (dvlist_t));
	if (entry == NULL) {
		devfsadm_errprint("%s: calloc failed\n", modname);
		goto error;
	}

	path = (char *)di_devlink_path(devlink);
	assert(path);
	if (path == NULL) {
		devfsadm_errprint("%s: di_devlink_path() returned NULL\n",
		    modname);
		goto error;
	}

	devfsadm_print(disk_mid, "%s: found link %s in reverse link cache\n",
	    modname, path);

	/*
	 * Return linkname in canonical form i.e. without the
	 * "/dev/" prefix
	 */
	can_path = strstr(path, "/dev/");
	if (can_path == NULL) {
		devfsadm_errprint("%s: devlink path %s has no /dev/\n",
		    modname, path);
		goto error;
	}

	entry->dv_link = s_strdup(can_path + strlen("/dev/"));
	entry->dv_next = *pp;
	*pp = entry;

	return (DI_WALK_CONTINUE);

error:
	free(entry);
	free_dvlist(pp);
	*pp = NULL;
	return (DI_WALK_TERMINATE);
}

/*
 * Returns success only if all goes well. If there is no matching reserved link
 * or if there is an error, we assume no match. It is better to err on the side
 * of caution by creating extra links than to miss out creating a required link.
 */
static int
reserved_links_exist(di_node_t node, di_minor_t minor, int nflags)
{
	di_devlink_handle_t dvlink_cache = devfsadm_devlink_cache();
	char phys_path[PATH_MAX];
	char *minor_path;
	dvlist_t *head;
	dvlist_t *entry;
	char *s;
	char l[PATH_MAX];
	int switch_link = 0;
	char *mn = di_minor_name(minor);

	if (dvlink_cache == NULL || mn == NULL) {
		devfsadm_errprint("%s: No minor or devlink cache\n", modname);
		return (DEVFSADM_FAILURE);
	}

	if (!devfsadm_have_reserved()) {
		devfsadm_print(disk_mid, "%s: No reserved links\n", modname);
		return (DEVFSADM_FAILURE);
	}

	minor_path = di_devfs_minor_path(minor);
	if (minor_path == NULL) {
		devfsadm_errprint("%s: di_devfs_minor_path failed\n", modname);
		return (DEVFSADM_FAILURE);
	}

	(void) strlcpy(phys_path, minor_path, sizeof (phys_path));

	di_devfs_path_free(minor_path);

	head = NULL;
	(void) di_devlink_cache_walk(dvlink_cache, DISK_LINK_RE, phys_path,
	    DI_PRIMARY_LINK, &head, dvlink_cb);

	/*
	 * We may be switching between EFI label and SMI label in which case
	 * we only have minors of the other type.
	 */
	if (head == NULL && (*mn == *(MN_SMI) ||
	    (strncmp(mn, MN_EFI, 2) == 0))) {
		devfsadm_print(disk_mid, "%s: No links for minor %s in /dev. "
		    "Trying another label\n", modname, mn);
		s = strrchr(phys_path, ':');
		if (s == NULL) {
			devfsadm_errprint("%s: invalid minor path: %s\n",
			    modname, phys_path);
			return (DEVFSADM_FAILURE);
		}
		(void) snprintf(s+1, sizeof (phys_path) - (s + 1 - phys_path),
		    "%s%s", *mn == *(MN_SMI) ? MN_EFI : MN_SMI,
		    strstr(s, ",raw") ? ",raw" : "");
		(void) di_devlink_cache_walk(dvlink_cache, DISK_LINK_RE,
		    phys_path, DI_PRIMARY_LINK, &head, dvlink_cb);
	}

	if (head == NULL) {
		devfsadm_print(disk_mid, "%s: minor %s has no links in /dev\n",
		    modname, phys_path);
		/* no links on disk */
		return (DEVFSADM_FAILURE);
	}

	/*
	 * It suffices to use 1 link to this minor, since
	 * we are matching with reserved IDs on the basis of
	 * the controller number which will be the same for
	 * all links to this minor.
	 */
	if (!devfsadm_is_reserved(disks_re_array, head->dv_link)) {
		/* not reserved links */
		devfsadm_print(disk_mid, "%s: devlink %s and its minor "
		    "are NOT reserved\n", modname, head->dv_link);
		free_dvlist(&head);
		return (DEVFSADM_FAILURE);
	}

	devfsadm_print(disk_mid, "%s: devlink %s and its minor are on "
	    "reserved list\n", modname, head->dv_link);

	/*
	 * Switch between SMI and EFI labels if required
	 */
	switch_link = 0;
	if (*mn == *(MN_SMI) || (strncmp(mn, MN_EFI, 2) == 0)) {
		for (entry = head; entry; entry = entry->dv_next) {
			s = strrchr(entry->dv_link, '/');
			assert(s);
			if (s == NULL) {
				devfsadm_errprint("%s: disk link %s has no "
				    "directory\n", modname, entry->dv_link);
				continue;
			}
			if (*mn == *(MN_SMI) && strchr(s, 's') == NULL) {
				(void) snprintf(l, sizeof (l), "%s%s",
				    entry->dv_link, SLICE_SMI);
				switch_link = 1;
				devfsadm_print(disk_mid, "%s: switching "
				    "reserved link from EFI to SMI label. "
				    "New link is %s\n", modname, l);
			} else if (strncmp(mn, MN_EFI, 2) == 0 &&
			    (s = strchr(s, 's'))) {
				*s = '\0';
				(void) snprintf(l, sizeof (l), "%s",
				    entry->dv_link);
				*s = 's';
				switch_link = 1;
				devfsadm_print(disk_mid, "%s: switching "
				    "reserved link from SMI to EFI label. "
				    "New link is %s\n", modname, l);
			}
			if (switch_link) {
				devfsadm_print(disk_mid, "%s: switching "
				    "link: deleting %s and creating %s\n",
				    modname, entry->dv_link, l);
				devfsadm_rm_link(entry->dv_link);
				(void) devfsadm_mklink(l, node, minor, nflags);
			}
		}
	}
	free_dvlist(&head);

	/*
	 * return SUCCESS to indicate that new links to this minor should not
	 * be created so that only compatibility links to this minor remain.
	 */
	return (DEVFSADM_SUCCESS);
}
