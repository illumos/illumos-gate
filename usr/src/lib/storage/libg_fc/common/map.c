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


/*LINTLIBRARY*/

/*
 * I18N message number ranges
 *  This file: 12000 - 12499
 *  Shared common messages: 1 - 1999
 */

/*
 *	This module is part of the Fibre Channel Interface library.
 */

/* #define		_POSIX_SOURCE 1 */


/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/mkdev.h>
#include	<sys/param.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<string.h>
#include	<sys/scsi/scsi.h>
#include	<dirent.h>		/* for DIR */
#include	<sys/vtoc.h>
#include	<nl_types.h>
#include	<strings.h>
#include	<errno.h>
#include	<sys/ddi.h>		/* for max */
#include	<fnmatch.h>
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<g_state.h>
#include	<g_scsi.h>
#include	<sys/fibre-channel/ulp/fcp_util.h>
#include	<sys/fibre-channel/impl/fc_error.h>
#include	<sys/fibre-channel/impl/fcph.h>
#include	<sys/socalio.h>
#include	<libdevinfo.h>
#include	<ctype.h>
#include	<devid.h>

/* Some forward declarations of static functions */
/*
 * becomes extern interface for Tapestry.
 * static int g_get_inq_dtype(char *, la_wwn_t, uchar_t *);
 * static int g_get_dev_list(char *, fc_port_dev_t **, int *, int);
 */
static int	g_issue_fcp_ioctl(int, struct fcp_ioctl *, int);
static int	g_set_port_state(char *, int);
static int	g_dev_log_in_out(char *, la_wwn_t, uint16_t);
static int	g_get_dev_port_state(char *, la_wwn_t, uint32_t *);
static void	g_free_rls(AL_rls *);
static int	g_scsi_inquiry_cmd80(int, uchar_t *, int);
static int	get_fca_inq_dtype(char *, la_wwn_t, uchar_t *);
static int	g_find_supported_inq_page(int, int);
static int	wwn_list_name_compare(const void *, const void *);
static int	devid_get_all(ddi_devid_t, di_node_t, char *,
			struct mplist_struct **);
static int	get_multipath(char *, struct dlist **,
			struct wwn_list_struct *);
static int	get_multipath_disk(char *, struct dlist **,
			struct wwn_list_struct *);
static void	mplist_free(struct mplist_struct *);
static int	get_wwn_data(di_node_t, uchar_t **, uchar_t **);
static int	get_dev_path(struct wwn_list_struct **, char *, char *);
static int	insert_missing_pwwn(char *, struct wwn_list_struct **);
static int	get_scsi_vhci_port_wwn(char *, uchar_t *);
static int	search_wwn_entry(struct wwn_list_found_struct *, uchar_t *,
		uchar_t *);
static int	add_wwn_entry(struct wwn_list_found_struct **, uchar_t *,
		uchar_t *);
static int	string_to_wwn(uchar_t *, uchar_t *);
static int	get_wwns(char *, uchar_t *, uchar_t *, int *,
		struct wwn_list_found_struct **);

/* type for g_dev_map_init related routines */

#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)

typedef struct impl_map_dev_prop {
	char	prop_name[MAXNAMELEN];
	int	prop_type;
	int	prop_size;
	void 	*prop_data;
	int 	prop_error;
	struct impl_map_dev_prop	*next;
} impl_map_dev_prop_t;

typedef struct impl_map_dev {
	int			flag;
	uint_t			topo;
	impl_map_dev_prop_t	*prop_list;
	struct impl_map_dev	*parent;
	struct impl_map_dev	*child;
	struct impl_map_dev 	*next;
} impl_map_dev_t;

/*	Defines 	*/
#define	VERBPRINT	if (verbose) (void) printf

#define	DIR_MATCH_ST		"*[0-9+]n"
#define	DIR_MATCH_SSD		"*s2"

#define	PROP_NOEXIST		0
#define	PROP_EXIST		1

/*	Prototypes	*/
static int create_map(char *, gfc_map_t *, int, int);
static char ctoi(char);
static int	lilp_map_cmp(const void*, const void*);
static int	devices_get_all(di_node_t, char *, char *,
			struct wwn_list_struct **);
static char	*my_devfs_path(di_node_t);
static void	my_devfs_path_free(char *path);
static void	copy_wwn_data_to_str(char *, const uchar_t *);
static void	init_drv(char *, char *, char *);

/* static for g_dev_map_init related routines */

static int update_map_dev_fc_prop(impl_map_dev_prop_t **, uint32_t,
	uchar_t *, uchar_t *, int, int);
static int update_map_dev_FCP_prop(impl_map_dev_prop_t **, uchar_t *, int, int);
static int handle_map_dev_FCP_prop(minor_t, la_wwn_t, impl_map_dev_prop_t **);
static void free_prop_list(impl_map_dev_prop_t **);
static void free_child_list(impl_map_dev_t **);
static u_longlong_t wwnConversion(uchar_t *wwn);

uchar_t g_switch_to_alpa[] = {
	0xef, 0xe8, 0xe4, 0xe2, 0xe1, 0xe0, 0xdc, 0xda, 0xd9, 0xd6,
	0xd5, 0xd4, 0xd3, 0xd2, 0xd1, 0xce, 0xcd, 0xcc, 0xcb, 0xca,
	0xc9, 0xc7, 0xc6, 0xc5, 0xc3, 0xbc, 0xba, 0xb9, 0xb6, 0xb5,
	0xb4, 0xb3, 0xb2, 0xb1, 0xae, 0xad, 0xac, 0xab, 0xaa, 0xa9,
	0xa7, 0xa6, 0xa5, 0xa3, 0x9f, 0x9e, 0x9d, 0x9b, 0x98, 0x97,
	0x90, 0x8f, 0x88, 0x84, 0x82, 0x81, 0x80, 0x7c, 0x7a, 0x79,
	0x76, 0x75, 0x74, 0x73, 0x72, 0x71, 0x6e, 0x6d, 0x6c, 0x6b,
	0x6a, 0x69, 0x67, 0x66, 0x65, 0x63, 0x5c, 0x5a, 0x59, 0x56,
	0x55, 0x54, 0x53, 0x52, 0x51, 0x4e, 0x4d, 0x4c, 0x4b, 0x4a,
	0x49, 0x47, 0x46, 0x45, 0x43, 0x3c, 0x3a, 0x39, 0x36, 0x35,
	0x34, 0x33, 0x32, 0x31, 0x2e, 0x2d, 0x2c, 0x2b, 0x2a, 0x29,
	0x27, 0x26, 0x25, 0x23, 0x1f, 0x1e, 0x1d, 0x1b, 0x18, 0x17,
	0x10, 0x0f, 0x08, 0x04, 0x02, 0x01
};

uchar_t g_sf_alpa_to_switch[] = {
	0x00, 0x7d, 0x7c, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x7a, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x78, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x77, 0x76, 0x00, 0x00, 0x75, 0x00, 0x74,
	0x73, 0x72, 0x00, 0x00, 0x00, 0x71, 0x00, 0x70, 0x6f, 0x6e,
	0x00, 0x6d, 0x6c, 0x6b, 0x6a, 0x69, 0x68, 0x00, 0x00, 0x67,
	0x66, 0x65, 0x64, 0x63, 0x62, 0x00, 0x00, 0x61, 0x60, 0x00,
	0x5f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x5e, 0x00, 0x5d,
	0x5c, 0x5b, 0x00, 0x5a, 0x59, 0x58, 0x57, 0x56, 0x55, 0x00,
	0x00, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4f, 0x00, 0x00, 0x4e,
	0x4d, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4b,
	0x00, 0x4a, 0x49, 0x48, 0x00, 0x47, 0x46, 0x45, 0x44, 0x43,
	0x42, 0x00, 0x00, 0x41, 0x40, 0x3f, 0x3e, 0x3d, 0x3c, 0x00,
	0x00, 0x3b, 0x3a, 0x00, 0x39, 0x00, 0x00, 0x00, 0x38, 0x37,
	0x36, 0x00, 0x35, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x33, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x31, 0x30, 0x00, 0x00, 0x2f, 0x00, 0x2e, 0x2d, 0x2c,
	0x00, 0x00, 0x00, 0x2b, 0x00, 0x2a, 0x29, 0x28, 0x00, 0x27,
	0x26, 0x25, 0x24, 0x23, 0x22, 0x00, 0x00, 0x21, 0x20, 0x1f,
	0x1e, 0x1d, 0x1c, 0x00, 0x00, 0x1b, 0x1a, 0x00, 0x19, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x17, 0x16, 0x15,
	0x00, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0f, 0x00, 0x00, 0x0e,
	0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x00, 0x00, 0x08, 0x07, 0x00,
	0x06, 0x00, 0x00, 0x00, 0x05, 0x04, 0x03, 0x00, 0x02, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};



/*
 * Check if device is in the map.
 *
 * PARAMS:
 *	map - loop map returned from fc port
 *	tid - device ID for private map or 24-bit alpa for fabric map
 *
 * RETURNS:
 *	 1 if device present in the map.
 *	 0 otherwise.
 *
 */
int
g_device_in_map(gfc_map_t *map, int tid)
{
	int i, j;
	gfc_port_dev_info_t	*dev_ptr;

	dev_ptr = map->dev_addr;
	if ((map->hba_addr.port_topology == FC_TOP_PUBLIC_LOOP) ||
		(map->hba_addr.port_topology == FC_TOP_FABRIC)) {
		for (i = 0; i < map->count; i++, dev_ptr++) {
			if (dev_ptr->
				gfc_port_dev.pub_port.dev_did.port_id == tid) {
				/* Does not count if WWN == 0 */
				for (j = 0; j < FC_WWN_SIZE; j++)
					if (dev_ptr->gfc_port_dev.pub_port.
						dev_pwwn.raw_wwn[j] != 0)
						return (1);
			}
		}
	} else {
		for (i = 0; i < map->count; i++, dev_ptr++) {
			if (dev_ptr->gfc_port_dev.priv_port.sf_al_pa ==
				(int)g_switch_to_alpa[tid]) {
				/* Does not count if WWN == 0 */
				for (j = 0; j < WWN_SIZE; j++)
					if (dev_ptr->gfc_port_dev.priv_port.
						sf_port_wwn[j] != 0)
						return (1);
			}
		}
	}
	return (0);
}

/*
 * Inserts any missing port wwns for mpxio device paths
 * which are in ONLINE or STANDBY state.
 */
static int
insert_missing_pwwn(char *phys_path, struct wwn_list_struct **wwn_list_ptr)
{
mp_pathlist_t	pathlist;
int	i, pathcnt, match;
struct	wwn_list_struct *new_wwn, *wwn_list_s, *wwn_list_found;
char	pwwn1[WWN_S_LEN];

	/*
	 * Now check each scsi_vhci device path to find any missed
	 * port wwns and insert a new wwn list entry for the missed
	 * port wwn
	 */
	if (g_get_pathlist(phys_path, &pathlist)) {
		/* Free memory for pathlist before return */
		S_FREE(pathlist.path_info);
		return (L_INVALID_PATH);
	}

	pathcnt = pathlist.path_count;
	for (i = 0; i < pathcnt; i++) {
		/*
		 * Just search for ONLINE and STANDBY paths as
		 * those should be the only missing wwn entries.
		 * There is a very small window for an offline
		 * to have occurred between the time we retrieved
		 * the device list and a call to this function.
		 * If that happens, we just won't add it to
		 * the list which is probably a good thing.
		 */
		if (pathlist.path_info[i].path_state ==
		    MDI_PATHINFO_STATE_ONLINE ||
		    pathlist.path_info[i].path_state ==
		    MDI_PATHINFO_STATE_STANDBY) {
			(void) strncpy(pwwn1, pathlist.path_info[i].path_addr,
				WWN_S_LEN - 1);
			pwwn1[WWN_S_LEN - 1] = '\0';
			/*
			 * Now search through wwn list for matching
			 * device path AND pwwn
			 * If it's found, continue to next path.
			 * If it's not found, add it the wwn list.
			 */
			match = 0;

			for (wwn_list_s = *wwn_list_ptr; wwn_list_s != NULL;
			    wwn_list_s = wwn_list_s->wwn_next) {
				if (strncmp(phys_path,
					    wwn_list_s->physical_path,
					    strlen(phys_path)) == 0) {
					wwn_list_found = wwn_list_s;
					if (strncmp(pwwn1,
						    wwn_list_s->port_wwn_s,
						    WWN_S_LEN) == 0) {
						match++;
						break;
					}
				}
			}
			if (match) {
				continue;
			} else {
				/*
				 * didn't find a match but the mpxio
				 * device is in the list. Retrieve
				 * the info from the wwn_list_found
				 * and add it to the list.
				 */
				if ((new_wwn = (struct  wwn_list_struct *)
					calloc(1,
					sizeof (struct  wwn_list_struct)))
					== NULL) {
				    S_FREE(pathlist.path_info);
				    return (L_MALLOC_FAILED);
				}
				if ((new_wwn->physical_path = (char *)
					calloc(1,
					strlen(wwn_list_found->physical_path)
					+1)) == NULL) {
				    S_FREE(pathlist.path_info);
				    return (L_MALLOC_FAILED);
				}
				if ((new_wwn->logical_path = (char *)
					calloc(1,
					strlen(wwn_list_found->logical_path)
					+ 1)) == NULL) {
				    S_FREE(pathlist.path_info);
				    return (L_MALLOC_FAILED);
				}

				/*
				 * Insert new_wwn at the beginning of the list.
				 */
				new_wwn->wwn_next = *wwn_list_ptr;
				(*wwn_list_ptr)->wwn_prev = new_wwn;

				/* set new starting ptr */
				*wwn_list_ptr = new_wwn;

				memcpy(new_wwn->physical_path,
				    wwn_list_found->physical_path,
					strlen(wwn_list_found->physical_path));
				memcpy(new_wwn->logical_path,
				    wwn_list_found->logical_path,
					strlen(wwn_list_found->logical_path));
				/*
				 * Copy found node wwn data to this new entry
				 * Node wwn is required for the wwn_list
				 * however for mpxio devices it is not
				 * relevant as it may apply to multiple
				 * target controllers, so just use what
				 * we already have in wwn_list_found.
				 */
				memcpy(new_wwn->node_wwn_s,
				    wwn_list_found->node_wwn_s, WWN_S_LEN);
				memcpy(new_wwn->w_node_wwn,
				    wwn_list_found->w_node_wwn, WWN_SIZE);
				new_wwn->device_type =
				    wwn_list_found->device_type;
				memcpy(new_wwn->port_wwn_s, pwwn1, WWN_S_LEN);
			}
		}
	}
	S_FREE(pathlist.path_info);
	return (0);
}

/*
 * gets the port wwn for a scsi_vhci device using ONLINE path priority
 */
static int
get_scsi_vhci_port_wwn(char *phys_path, uchar_t *port_wwn)
{
mp_pathlist_t	pathlist;
int	i, pathcnt, found;
char	pwwn1[WWN_S_LEN];

	if (g_get_pathlist(phys_path, &pathlist)) {
		return (L_INVALID_PATH);
	}

	found = 0;
	pathcnt = pathlist.path_count;
	/*
	 * Look for an ONLINE path first.
	 * If that fails, get the STANDBY path port WWN
	 * If that fails, give up
	 */
	for (i = 0; found == 0 && i < pathcnt; i++) {
		if (pathlist.path_info[i].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			(void) strncpy(pwwn1, pathlist.path_info[i].path_addr,
				WWN_S_LEN - 1);
			pwwn1[WWN_S_LEN - 1] = '\0';
			found++;
		}
	}

	for (i = 0; found == 0 && i < pathcnt; i++) {
		if (pathlist.path_info[i].path_state ==
		    MDI_PATHINFO_STATE_STANDBY) {
			(void) strncpy(pwwn1, pathlist.path_info[i].path_addr,
				WWN_S_LEN - 1);
			pwwn1[WWN_S_LEN - 1] = '\0';
			found++;
		}
	}

	S_FREE(pathlist.path_info);
	if (found) {
		return (string_to_wwn((uchar_t *)pwwn1, port_wwn));
	} else {
		return (-1);
	}
}

/*
 * searches wwn_list_found for the pwwn passed in
 * and sets the corresponding nwwn on return.
 * If no match is found, -1 is returned and nwwn is not set.
 */
static int
search_wwn_entry(struct wwn_list_found_struct *wwn_list_found, uchar_t *pwwn,
		uchar_t *nwwn)
{
struct	wwn_list_found_struct *wwn_list_s;

	for (wwn_list_s = wwn_list_found; wwn_list_s != NULL;
	    wwn_list_s = wwn_list_s->wwn_next) {
		if (memcmp(pwwn,
			    wwn_list_s->port_wwn, WWN_SIZE) == 0) {
			memcpy(nwwn, wwn_list_s->node_wwn, WWN_SIZE);
			return (0);
		}
	}
	return (-1);
}

/*
 * adds a nwwn, pwwn entry to the next entry in wwn_list_found list
 */
static int
add_wwn_entry(struct wwn_list_found_struct **wwn_list_found, uchar_t *pwwn,
		uchar_t *nwwn)
{
struct wwn_list_found_struct *new_wwn, *temp_wwn_list_found = NULL;

	/* Got wwns, load data in list */
	if ((new_wwn = (struct  wwn_list_found_struct *)
		calloc(1, sizeof (struct  wwn_list_found_struct)))
			== NULL) {
		return (L_MALLOC_FAILED);
	}

	memcpy(new_wwn->node_wwn, nwwn, WWN_SIZE);
	memcpy(new_wwn->port_wwn, pwwn, WWN_SIZE);

	/*
	 * Insert new_wwn in the list
	 */
	if (*wwn_list_found != NULL) {
		temp_wwn_list_found = (*wwn_list_found)->wwn_next;
		(*wwn_list_found)->wwn_next = new_wwn;
	} else {
		*wwn_list_found = new_wwn;
	}
	new_wwn->wwn_next = temp_wwn_list_found;

	return (0);
}


/*
 * Create a linked list of all the WWN's for all FC_AL disks and
 * tapes that are attached to this host.
 *
 * RETURN VALUES: 0 O.K.
 *
 * wwn_list pointer:
 *			NULL: No devices found.
 *			!NULL: Devices found
 *                      wwn_list points to a linked list of wwn's.
 */
int
g_get_wwn_list(struct wwn_list_struct **wwn_list_ptr, int verbose)
{
struct wwn_list_struct *wwn_list_p = NULL, *wwn_list_tmp_p = NULL;
struct wwn_list_found_struct *wwn_list_found = NULL;
int err;
int al_pa;
uchar_t node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
hrtime_t	start_time, end_time;
char *env = NULL;

	/* return L_NULL_WWN_LIST if wwn_list_ptr is NULL */
	if (wwn_list_ptr == NULL) {
		return (L_NULL_WWN_LIST);
	}

	if ((env = getenv("_LUX_T_DEBUG")) != NULL) {
		start_time = gethrtime();
	}

	if ((err = g_devices_get_all(wwn_list_ptr))
		!= 0) {
		return (err);
	}

	/*
	 * retain backward compatibility with g_get_wwn_list
	 * and retrieve the WWN for scsi_vhci devices in the
	 * same fashion
	 * Note that for scsi_vhci devices, the wwn fields are
	 * not relevant but in the previous versions
	 * we loaded the wwns so...
	 */
	wwn_list_p = *wwn_list_ptr;
	while (wwn_list_p != NULL) {
	    if (strstr(wwn_list_p->physical_path, SCSI_VHCI) != NULL) {
		/* get port wwn of first ONLINE, STANDBY */
		if ((get_scsi_vhci_port_wwn(wwn_list_p->physical_path,
			port_wwn)) == 0) {
		    if ((search_wwn_entry(wwn_list_found, port_wwn,
			node_wwn)) != 0) {
			if ((err = get_wwns(wwn_list_p->physical_path, port_wwn,
				node_wwn, &al_pa, &wwn_list_found)) != 0) {
				g_free_wwn_list_found(&wwn_list_found);
				return (err);
			}
		    }
		} else {
		    /* Use g_get_wwn as a last resort */
		    if ((err = g_get_wwn(wwn_list_p->physical_path, port_wwn,
			node_wwn, &al_pa, 0)) != 0) {
			/*
			 * this is a bad WWN.  remove it from the
			 * wwn_list.
			 *
			 * After removing the bad WWN, wwn_list_p
			 * should point to the next node in the list
			 */
			if ((wwn_list_p->wwn_prev == NULL) &&
			    (wwn_list_p->wwn_next == NULL)) {
			    *wwn_list_ptr = NULL;
			    free(wwn_list_p);
			    g_free_wwn_list_found(&wwn_list_found);
			    return (L_NO_DEVICES_FOUND);
			} else if (wwn_list_p->wwn_prev == NULL) {
			    *wwn_list_ptr = wwn_list_p->wwn_next;
			    free(wwn_list_p);
			    wwn_list_p = *wwn_list_ptr;
			    wwn_list_p->wwn_prev = NULL;
			} else if (wwn_list_p->wwn_next == NULL) {
			    wwn_list_p->wwn_prev->wwn_next = NULL;
			    free(wwn_list_p);
			    wwn_list_p = NULL;
			} else {
			    wwn_list_tmp_p = wwn_list_p->wwn_next;
			    wwn_list_p->wwn_prev->wwn_next =
				wwn_list_p->wwn_next;
			    wwn_list_p->wwn_next->wwn_prev =
				wwn_list_p->wwn_prev;
			    free(wwn_list_p);
			    wwn_list_p = wwn_list_tmp_p;
			}
			continue;
		    }
		}
		copy_wwn_data_to_str(wwn_list_p->node_wwn_s, node_wwn);
		copy_wwn_data_to_str(wwn_list_p->port_wwn_s, port_wwn);
		memcpy(wwn_list_p->w_node_wwn, node_wwn, WWN_SIZE);
	    }
	    wwn_list_p = wwn_list_p->wwn_next;
	}
	g_free_wwn_list_found(&wwn_list_found);

	/*
	 * Now go through the list one more time to add entries for
	 * any missing port wwns.
	 * This allows a search on port wwn for any paths which are
	 * ONLINE or STANDBY. We don't care about OFFLINE as those won't
	 * and should not show up in the list
	 */
	for (wwn_list_p = *wwn_list_ptr; wwn_list_p != NULL;
	    wwn_list_p = wwn_list_p->wwn_next) {
	    if (strstr(wwn_list_p->physical_path, SCSI_VHCI) != NULL) {
		if ((err = insert_missing_pwwn(wwn_list_p->physical_path,
				    wwn_list_ptr)) != 0)
			return (err);
	    }
	}

	if (env != NULL) {
		end_time = gethrtime();
		fprintf(stdout, "      g_get_wwn_list: "
		"\t\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}
	return (0);

}

int
g_devices_get_all(struct wwn_list_struct **wwn_list_ptr)
{
struct wwn_list_struct *tape_ptr = NULL;
struct wwn_list_struct *tmp;
int err;
di_node_t root;
hrtime_t	start_time, end_time;
char *env = NULL;

	if ((env = getenv("_LUX_T_DEBUG")) != NULL) {
		start_time = gethrtime();
	}

	/*
	 * Try to prime di_drv_first_node()
	 * If there are no nodes bound, di_drv_first_node()
	 * will return nothing.
	 */
	init_drv(DEV_TAPE_DIR, DIR_MATCH_ST, SLSH_DRV_NAME_ST);
	init_drv(DEV_RDIR, DIR_MATCH_SSD, SLSH_DRV_NAME_SSD);

	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		return (L_DEV_SNAPSHOT_FAILED);
	}

	if (env != NULL) {
		end_time = gethrtime();
		fprintf(stdout, "      di_init - /:  "
		"\t\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}

	if (env != NULL) {
		start_time = gethrtime();
	}

	if ((err = devices_get_all(root, SSD_DRVR_NAME, SSD_MINOR_NAME,
			wwn_list_ptr)) != 0) {
		if (err != L_NO_DEVICES_FOUND) {
			di_fini(root);
			g_free_wwn_list(&tape_ptr);
			g_free_wwn_list(wwn_list_ptr);
			return (err);
		}
	}

	if (env != NULL) {
		end_time = gethrtime();
		fprintf(stdout, "      devices_get_all - ssd:  "
		"\t\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}

	if (env != NULL) {
		start_time = gethrtime();
	}

	if ((err = devices_get_all(root, ST_DRVR_NAME, ST_MINOR_NAME,
			&tape_ptr)) != 0) {
		di_fini(root);
		if (err != L_NO_DEVICES_FOUND) {
			g_free_wwn_list(&tape_ptr);
			g_free_wwn_list(wwn_list_ptr);
			return (err);
		} else {
			/*
			 * if *wwn_list_ptr == NULL
			 * we have disks but no tapes
			 * Just return
			 */
			if (*wwn_list_ptr != NULL) {
				return (0);
			} else {
				/*
				 * No disks or tapes
				 */
				g_free_wwn_list(&tape_ptr);
				g_free_wwn_list(wwn_list_ptr);
				return (err);
			}
		}
	}

	if (env != NULL) {
		end_time = gethrtime();
		fprintf(stdout, "      devices_get_all - st: "
		"\t\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}

	/* Now link the two together */
	if (*wwn_list_ptr != NULL) { /* We have both disks and tapes */
		/* Walk to the end of it */
		for (tmp = *wwn_list_ptr; tmp->wwn_next != NULL;
			tmp = tmp->wwn_next);
		tmp->wwn_next = tape_ptr;
		tape_ptr->wwn_prev = tmp;
		di_fini(root);
		return (0);
	}

	/* else we have no disks */
	*wwn_list_ptr = tape_ptr;
	di_fini(root);
	return (0);
}

void
g_free_wwn_list_found(struct wwn_list_found_struct **wwn_list_found) {
	WWN_list_found	    *next = NULL;

	/* return if wwn_list_found is NULL */
	if (wwn_list_found == NULL) {
		return;
	}
	for (; *wwn_list_found != NULL; *wwn_list_found = next) {
		next = (*wwn_list_found)->wwn_next;
		g_destroy_data(*wwn_list_found);
		*wwn_list_found = NULL;
	}
}

void
g_free_wwn_list(struct wwn_list_struct **wwn_list)
{
WWN_list	*next = NULL;

	/* return if wwn_list is NULL */
	if (wwn_list == NULL) {
		return;
	}

	for (; *wwn_list != NULL; *wwn_list = next) {
		next = (*wwn_list)->wwn_next;
		if ((*wwn_list)->physical_path != NULL)
			(void) g_destroy_data((*wwn_list)->physical_path);
		if ((*wwn_list)->logical_path != NULL)
			(void) g_destroy_data((*wwn_list)->logical_path);
		(void) g_destroy_data(*wwn_list);
	}
	wwn_list = NULL;
}




void
g_sort_wwn_list(struct wwn_list_struct **wwn_list)
{
	int			i, n;
	struct wwn_list_struct	**wwn_list_array;
	struct wwn_list_struct	*wwn_list_ptr;
	struct wwn_list_struct	**wwn_list_array_ptr1;
	struct wwn_list_struct	**wwn_list_array_ptr2;

	/*
	 * Count the number of wwn_list in the list
	 */
	for (n = 0,  wwn_list_ptr = *wwn_list;
	    wwn_list_ptr != NULL;
	    wwn_list_ptr = wwn_list_ptr->wwn_next) {
		n++;
	}
	if (n <= 1) {
		return;
	}

	/*
	 * Allocate a simple wwn_list array and fill it in
	 */
	wwn_list_array = (struct wwn_list_struct **)
	    g_zalloc((n+1) * sizeof (struct wwn_list_struct *));

	wwn_list_array_ptr1 = wwn_list_array;
	for (wwn_list_ptr = *wwn_list;
	    wwn_list_ptr != NULL;
	    wwn_list_ptr = wwn_list_ptr->wwn_next) {
		*wwn_list_array_ptr1++ = wwn_list_ptr;
	}
	*wwn_list_array_ptr1 = NULL;

	/*
	 * Sort the wwn_list array
	 */
	qsort((void *) wwn_list_array, n,
	    sizeof (struct wwn_list_struct *), wwn_list_name_compare);

	/*
	 * Rebuild the linked list wwn_list structure
	 */
	wwn_list_array_ptr1 = wwn_list_array;
	*wwn_list = *wwn_list_array_ptr1;
	wwn_list_array_ptr2 = wwn_list_array_ptr1 + 1;
	(*wwn_list_array_ptr1)->wwn_prev = NULL;
	for (i = 0; i < n - 1; i++) {
	    (*wwn_list_array_ptr2)->wwn_prev = *wwn_list_array_ptr1;
	    (*wwn_list_array_ptr1++)->wwn_next = *wwn_list_array_ptr2++;
	}
	(*wwn_list_array_ptr1)->wwn_next = NULL;

	/*
	 * Clean up
	 */
	(void) g_destroy_data((void *)wwn_list_array);
}

int
wwn_list_name_compare(const void *arg1, const void *arg2)
{
	char	*s1, *s2;
	int	n1, n2;
	char	*p1, *p2;

	s1 = (*((struct wwn_list_struct **)arg1))->logical_path;
	s2 = (*((struct wwn_list_struct **)arg2))->logical_path;
	for (;;) {
		if (*s1 == 0 || *s2 == 0)
			break;
		if ((isdigit(*s1) && isdigit(*s2))) {
			n1 = strtol(s1, &p1, 10);
			n2 = strtol(s2, &p2, 10);
			if (n1 != n2) {
				return (n1 - n2);
			}
			s1 = p1;
			s2 = p2;
		} else if (*s1 != *s2) {
			break;
		} else {
			s1++;
			s2++;
		}
	}
	return (*s1 - *s2);
}

/*
 * Get the limited map for FC4 devices.
 * This function is specific to FC4
 * devices and doesn't work for FC (leadville) devices.
 *
 * RETURN VALUES:
 *	0	 O.K.
 *	non-zero otherwise
 *
 * lilpmap *map_ptr:
 *		NULL: No devices found
 *		!NULL: if devices found
 */
int
g_get_limited_map(char *path, struct lilpmap *map_ptr, int verbose)
{
int	fd, i;
char	drvr_path[MAXPATHLEN];
struct	stat	stbuf;


	/* initialize map */
	(void) memset(map_ptr, 0, sizeof (struct lilpmap));

	(void) strcpy(drvr_path, path);
	/*
	 * Get the path to the :devctl driver
	 *
	 * This assumes the path looks something like this:
	 * /devices/sbus@1f,0/SUNW,socal@1,0:1
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0
	 * or
	 * a 1 level PCI type driver
	 */
	if (stat(drvr_path, &stbuf) < 0) {
		return (L_LSTAT_ERROR);
	}
	if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
		/* append a port. Just try 0 since they did not give us one */
		(void) strcat(drvr_path, ":0");
	}

	P_DPRINTF("  g_get_limited_map: Geting drive map from:"
		" %s\n", drvr_path);

	/* open controller */
	if ((fd = g_object_open(drvr_path, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);

	if (ioctl(fd, FCIO_GETMAP, map_ptr) != 0) {
		I_DPRINTF("  FCIO_GETMAP ioctl failed\n");
		(void) close(fd);
		return (L_FCIO_GETMAP_IOCTL_FAIL);
	}
	(void) close(fd);

	/*
	 * Check for reasonableness.
	 */
	if ((map_ptr->lilp_length > 126) || (map_ptr->lilp_magic != 0x1107)) {
		return (L_INVALID_LOOP_MAP);
	}
	for (i = 0; i < (uint_t)map_ptr->lilp_length; i++) {
		if (map_ptr->lilp_list[i] > 0xef) {
			return (L_INVALID_LOOP_MAP);
		}
	}

	return (0);
}


/*
 * For leadville specific HBA's ONLY.
 * Get the host specific parameters,
 * al_pa, hard address, node/port WWN etc.
 *
 * OUTPUT:
 *	fc_port_dev_t structure.
 *
 * RETURNS:
 *	0	if  OK
 *	non-zero in case of error.
 */
int
g_get_host_params(char *host_path, fc_port_dev_t *host_val, int verbose)
{
int		err;
int		fd;
int		dev_type;
fcio_t		fcio;

	/* return invalid path if host_path is NULL */
	if (host_path == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if host_val is NULL */
	if (host_val == NULL) {
		return (L_INVALID_ARG);
	}

	dev_type = g_get_path_type(host_path);
	if ((dev_type == 0) || !(dev_type & FC_GEN_XPORT)) {
		return (L_INVALID_PATH_TYPE);
	}
	if ((fd = g_object_open(host_path, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}

	/* initialize structure */
	(void) memset(host_val, 0, sizeof (struct fc_port_dev));

	fcio.fcio_cmd = FCIO_GET_HOST_PARAMS;
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)host_val;
	fcio.fcio_olen = sizeof (fc_port_dev_t);

	if (g_issue_fcio_ioctl(fd, &fcio, verbose) != 0) {
		I_DPRINTF(" FCIO_GET_HOST_PARAMS ioctl failed.\n");
		(void) close(fd);
		return (L_FCIO_GET_HOST_PARAMS_FAIL);
	}
	(void) close(fd);

	/* get the inquiry information for the leadville HBA. */
	if ((err = get_fca_inq_dtype(host_path, host_val->dev_pwwn,
				&host_val->dev_dtype)) != 0) {
		return (err);
	}
	return (0);
}



/*
 * Issue FCIO ioctls to the port(fp) driver.
 * FCIO ioctl needs to be retried when it
 * is returned with an EINVAL error, wait
 * time between retries should be atleast
 * WAIT_FCIO_IOCTL (too much of a time to wait!!)
 *
 * OUTPUT:
 *	fcio_t structure
 *
 * RETURNS:
 *	0	 if O.K.
 *	non-zero otherwise.
 */
int
g_issue_fcio_ioctl(int fd, fcio_t *fcio, int verbose)
{
int	ntries;

	for (ntries = 0; ntries < RETRY_FCIO_IOCTL; ntries++) {
		if (ioctl(fd, FCIO_CMD, fcio) != 0) {
			if ((errno == EAGAIN) &&
				(ntries+1 < RETRY_FCIO_IOCTL)) {
				/* wait WAIT_FCIO_IOCTL */
				(void) usleep(WAIT_FCIO_IOCTL);
				continue;
			}
			I_DPRINTF("FCIO ioctl failed.\n"
				"Error: %s. fc_error = %d (0x%x)\n",
			strerror(errno), fcio->fcio_errno, fcio->fcio_errno);
			if (errno == EINVAL) {
				if (fcio->fcio_errno == FC_TOOMANY) {
					return (L_INVALID_DEVICE_COUNT);
				} else {
					return (errno);
				}
			}
			/*
			 * When port is offlined, qlc
			 * returns the FC_OFFLINE error and errno
			 * is set to EIO.
			 * We do want to ignore this error,
			 * especially when an enclosure is
			 * removed from the loop.
			 */
			if (fcio->fcio_errno == FC_OFFLINE)
				break;
			return (-1);
		}
		break;
	}

	return (0);
}

/*
 * This function issues the FCP_TGT_INQUIRY ioctl to
 * the fcp module
 *
 * OUTPUT:
 *	fcp_ioctl structure in fcp_data is filled in by fcp
 *
 * RETURN VALUES :
 *	0 on Success
 *	Non-zero otherwise
 */
static int
g_issue_fcp_ioctl(int fd, struct fcp_ioctl *fcp_data, int verbose)
{
	int 			num_tries = 0;
	struct device_data	*dev_data = NULL;

	/*
	 * Issue the ioctl to FCP
	 * The retries are required because the driver may
	 * need some time to respond at times.
	 */
	while (num_tries++ < RETRY_FCP_IOCTL) {
		/* if ioctl fails it is an error from Solaris operation. */
		if (ioctl(fd, FCP_TGT_INQUIRY, fcp_data) == -1) {
			if (errno == EAGAIN) {
				(void) usleep(WAIT_FCP_IOCTL);
				continue;
			} else {
				break;
			}
		}
		dev_data = (struct device_data *)((void *)(fcp_data->list));
		if (dev_data->dev_status == 0) {
			return (0);
		}

		if (dev_data->dev_status == EAGAIN) {
			(void) usleep(WAIT_FCP_IOCTL);
			continue;
		} else {
			dev_data->dev0_type = DTYPE_UNKNOWN;
			return (0);
		}
	}

	return (L_FCP_TGT_INQUIRY_FAIL);
}

/*
 * Get the number of devices and also
 * a list of devices accessible through
 * the device's port as specified by path.
 * The calling function * is responsible for freeing the dev_list.
 *
 * Acquires inq_dtype from g_get_inq_dtype() and
 * stores into dev_dtype field of fc_port_dev.
 *
 * For fabric devices call FCIO_DEV_LOGIN (if necessary) to execute port login
 * and get inq dtype.
 *
 * dev_list:
 *	NULL:	  No devices found, in case of an error
 *	Non-NULL: Devices found.
 * ndevs:
 *	set to the number of devices
 *	accessible through the port.
 *
 * RETURNS:
 *	0	 if O.K.
 *	non-zero otherwise
 */
int
g_get_dev_list(char *path, fc_port_dev_t **dev_list, int *ndevs)
{
int		num_devices = 0;
int		i, err, ulp_failure = 0, new_count = 0;
int		dev_type;
int		fd;
char		fcapath[MAXPATHLEN];
char		*char_ptr;
struct	stat	stbuf;
fcio_t		fcio;
uint32_t	port_top;
fc_port_dev_t	*dlist;

	*dev_list = dlist = NULL;
	(void) strcpy(fcapath, path);
	/*
	 * Get the path to the :devctl driver
	 *
	 * This assumes the path looks something like this:
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0:devctl
	 * or
	 * a 1 level PCI type driver but still :devctl
	 */
	if (strstr(fcapath, DRV_NAME_SSD) || strstr(fcapath, SES_NAME)) {
		if ((char_ptr = strrchr(fcapath, '/')) == NULL) {
			return (L_INVALID_PATH);
		}
		*char_ptr = '\0';   /* Terminate sting  */
		/* append controller */
		(void) strcat(fcapath, FC_CTLR);
	} else {
		if (stat(fcapath, &stbuf) < 0) {
			return (L_LSTAT_ERROR);
		}
		if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
			/* append controller */
			(void) strcat(fcapath, FC_CTLR);
		}
	}
	dev_type = g_get_path_type(fcapath);
	if ((dev_type == 0) || !(dev_type & FC_GEN_XPORT)) {
		return (L_INVALID_PATH_TYPE);
	}
	if ((fd = g_object_open(fcapath, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}

	/*
	 * Get the device list from port driver
	 */
	fcio.fcio_cmd = FCIO_GET_NUM_DEVS;
	fcio.fcio_olen = sizeof (num_devices);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)&num_devices;
	if (g_issue_fcio_ioctl(fd, &fcio, 0) != 0) {
		I_DPRINTF(" FCIO_GET_NUM_DEVS ioctl failed.\n");
		(void) close(fd);
		return (L_FCIO_GET_NUM_DEVS_FAIL);
	}
	if (num_devices == 0) {
		*ndevs = 0;
		(void) close(fd);
		return (L_NO_DEVICES_FOUND);
	}

	if ((dlist = (fc_port_dev_t *)calloc(num_devices,
				sizeof (fc_port_dev_t))) == NULL) {
		(void) close(fd);
		return (L_MALLOC_FAILED);
	}
	bzero((caddr_t)&fcio, sizeof (fcio));
	/* Get the device list */
	fcio.fcio_cmd = FCIO_GET_DEV_LIST;
	/* Information read operation */
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_olen = num_devices * sizeof (fc_port_dev_t);
	fcio.fcio_obuf = (caddr_t)dlist;
	/* new device count */
	fcio.fcio_alen = sizeof (new_count);
	fcio.fcio_abuf = (caddr_t)&new_count;
	if ((err = g_issue_fcio_ioctl(fd, &fcio, 0)) != 0) {
	    if (err == L_INVALID_DEVICE_COUNT) {
		/*
		 * original buffer was small so allocate buffer
		 * with a new count and retry.
		 */
		free(dlist);
		num_devices = new_count;
		new_count = 0;
		if ((dlist = (fc_port_dev_t *)calloc(num_devices,
				sizeof (fc_port_dev_t))) == NULL) {
			(void) close(fd);
			return (L_MALLOC_FAILED);
		}
		fcio.fcio_cmd = FCIO_GET_DEV_LIST;
		/* Information read operation */
		fcio.fcio_xfer = FCIO_XFER_READ;
		fcio.fcio_obuf = (caddr_t)dlist;
		fcio.fcio_olen = num_devices * sizeof (fc_port_dev_t);
		/* new device count */
		fcio.fcio_alen = sizeof (new_count);
		fcio.fcio_abuf = (caddr_t)&new_count;
		if ((err = g_issue_fcio_ioctl(fd, &fcio, 0)) != 0) {
		    if (err == L_INVALID_DEVICE_COUNT) {
			/*
			 * No more retry. There may be severe hardware
			 * problem so return error here.
			 */
			I_DPRINTF(" Device count was %d"
			" should have been %d\n",
			num_devices, new_count);
		    } else {
			I_DPRINTF(" FCIO_GET_DEV_LIST ioctl failed.");
			err = L_FCIO_GET_DEV_LIST_FAIL;
		    }
		    free(dlist);
		    (void) close(fd);
		    return (err);
		}
	    } else {
		I_DPRINTF(" FCIO_GET_DEV_LIST ioctl failed.");
		free(dlist);
		(void) close(fd);
		return (L_FCIO_GET_DEV_LIST_FAIL);
	    }
	}

	/*
	 * if new count is smaller than the original number from
	 * FCIO_GET_NUM_DEVS, adjust new count and buffer size
	 * and continue.
	 */
	if (new_count < num_devices) {
		if (new_count == 0) {
			*ndevs = 0;
			(void) close(fd);
			S_FREE(dlist);
			return (L_NO_DEVICES_FOUND);
		}
		num_devices = new_count;
		if ((dlist = (fc_port_dev_t *)realloc(dlist,
				(new_count * sizeof (fc_port_dev_t))))
				== NULL) {
			S_FREE(dlist);
			(void) close(fd);
			return (L_MALLOC_FAILED);
		}
	}

	*dev_list = dlist;
	*ndevs = num_devices;

	/* close here since fcapath will be passed to other routines. */
	(void) close(fd);

	if ((err = g_get_fca_port_topology(fcapath, &port_top, 0)) != 0) {
		free(*dev_list);
		*dev_list = NULL;
		return (err);
	}

	/* Get the inq_dtype for each device on dev list. */
	for (i = 0; i < num_devices; i++, dlist++) {
		/* Get the inq_dtype for each device. */
		if ((err = g_get_inq_dtype(fcapath, dlist->dev_pwwn,
				&dlist->dev_dtype)) != 0) {
			/*
			 * if g_get_inq_dtype failed on g_dev_login
			 * or g_issue_fcp_ioctl, continue to the next
			 * dev on dlist.
			 * L_GET_DEV_LIST_ULP_FAILURE is returned
			 * after processing the whole dlist.
			 */
			if ((err == L_FCIO_DEV_LOGIN_FAIL) ||
				(err == L_FCP_TGT_INQUIRY_FAIL)) {
				ulp_failure = 1;
				dlist->dev_dtype = GFC_ERR_INQ_DTYPE;
			} else {
				(void) free(*dev_list);
				*dev_list = NULL;
				return (err);
			}
		}
	}

	if (ulp_failure) {
		return (L_GET_DEV_LIST_ULP_FAILURE);
	} else {
		return (0);
	}
}


/* Constant used by g_get_inq_dtype() */
#define	FCP_PATH	"/devices/pseudo/fcp@0:fcp"

/*
 * Gets the inq_dtype for devices on the fabric FC driver
 * through an ioctl to the FCP module.
 *
 * OUTPUT:
 *	inq_dtype is set to the dtype on success
 *
 * RETURN VALUES:
 *	0 on Success
 *	Non-zero on error
 */
int
g_get_inq_dtype(char *fcapath, la_wwn_t pwwn, uchar_t *inq_dtype)
{
	int			dev_type, fd;
	int			err, fcp_fd;
	uint32_t		state;
	uint32_t		port_top = 0;
	struct fcp_ioctl	fcp_data;
	struct device_data	inq_data;
	struct stat		sbuf;

	dev_type = g_get_path_type(fcapath);
	if ((dev_type == 0) || !(dev_type & FC_GEN_XPORT)) {
		return (L_INVALID_PATH_TYPE);
	}

	if ((err = g_get_fca_port_topology(fcapath, &port_top, 0)) != 0) {
		return (err);
	}

	if ((port_top == FC_TOP_FABRIC) || (port_top == FC_TOP_PUBLIC_LOOP)) {
		/*
		 * if there is an error on getting port state we will
		 * continue to login.
		 * state can be either of
		 * PORT_DEVICE_INVALID, PORT_DEVICE_VALID,
		 * PORT_DEVICE_LOGGED_IN.  Trying port login
		 * unless already logged in.
		 * It will be examined if there is an adverse
		 * effect on invalid state device.
		 */
		if (((err = g_get_dev_port_state(fcapath, pwwn, &state))
				!= 0) || (state != PORT_DEVICE_LOGGED_IN)) {
			/* do port login to fabric device.  */
			if ((err = g_dev_login(fcapath, pwwn)) != 0) {
				return (err);
			}
		}
	}

	if ((fd = g_object_open(fcapath, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);

	if (fstat(fd, &sbuf) == -1) {
		(void) close(fd);
		return (L_FSTAT_ERROR);
	}

	if ((fcp_fd = g_object_open(FCP_PATH, O_RDONLY)) == -1) {
		(void) close(fd);
		return (L_OPEN_PATH_FAIL);
	}

	/* Get the minor number for an fp instance */
	fcp_data.fp_minor = minor(sbuf.st_rdev);

	fcp_data.listlen = 1;
	inq_data.dev_pwwn = pwwn;	/* The port WWN as passed */
	fcp_data.list = (caddr_t)&inq_data;

	if (err = g_issue_fcp_ioctl(fcp_fd, &fcp_data, 0)) {
		close(fd);
		close(fcp_fd);
		return (err);
	}
	*inq_dtype = inq_data.dev0_type;

	close(fd);
	close(fcp_fd);

	return (err);
}

/*
 * Gets the inq_dtype for devices on the fabric FC driver
 * through an ioctl to the FCP module.
 *
 * This is exactly same as g_get_inq_dtype except that it does not do
 * g_dev_login(). That is for the case when the FCA tries to get its own
 * inq_dtype and in such a case, it cannot PLOGI into itself.
 *
 * OUTPUT:
 *	inq_dtype is set to the dtype on success
 *
 * RETURN VALUES:
 *	0 on Success
 *	Non-zero on error
 */
static int
get_fca_inq_dtype(char *fcapath, la_wwn_t pwwn, uchar_t *inq_dtype)
{
	int			dev_type, fd;
	int			err, fcp_fd;
	struct fcp_ioctl	fcp_data;
	struct device_data	inq_data;
	struct stat		sbuf;

	dev_type = g_get_path_type(fcapath);
	if ((dev_type == 0) || !(dev_type & FC_GEN_XPORT)) {
		return (L_INVALID_PATH_TYPE);
	}

	if ((fd = g_object_open(fcapath, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}

	if (fstat(fd, &sbuf) == -1) {
		(void) close(fd);
		return (L_FSTAT_ERROR);
	}

	if ((fcp_fd = g_object_open(FCP_PATH, O_RDONLY)) == -1) {
		(void) close(fd);
		return (L_OPEN_PATH_FAIL);
	}

	/* Get the minor number for an fp instance */
	fcp_data.fp_minor = minor(sbuf.st_rdev);

	fcp_data.listlen = 1;
	inq_data.dev_pwwn = pwwn;	/* The port WWN as passed */
	fcp_data.list = (caddr_t)&inq_data;

	if (err = g_issue_fcp_ioctl(fcp_fd, &fcp_data, 0)) {
		close(fd);
		close(fcp_fd);
		return (err);
	}
	*inq_dtype = inq_data.dev0_type;

	close(fd);
	close(fcp_fd);

	return (0);
}

/*
 * This function returns the traditional g_get_dev_map. Device list
 * and local hba seperate.
 */
int
g_get_dev_map(char *path, gfc_map_t *map_ptr, int verbose)
{
	return (create_map(path, map_ptr, verbose, MAP_FORMAT_STANDARD));
}

/*
 * This function returns the device map with local hba in physical
 * order.  Note: Physical order is only returned properly for
 * private loop. local hba is also included seperate
 */
int
g_get_lilp_map(char *path, gfc_map_t *map_ptr, int verbose)
{
	return (create_map(path, map_ptr, verbose, MAP_FORMAT_LILP));
}

/*
 * Gets device map from nexus driver
 *
 * PARAMS:
 *	path -	must be the physical path to a device
 *	map  -	loop map returned from fc port.
 *	verbose - options.
 *
 * LOGIC:
 *	1. check the validity of path via g_get_path_type.
 *	2. If FC path, get the topology of the path via
 *		g_get_fca_port_topology.
 *
 *	3. If FC type(Leadville statck)
 *		g_get_dev_list to get the device node list of fc_port_dev_t.
 *		g_get_host_params to get the fca port node of fc_port_dev_t.
 *
 *		Case of fabric or public loop topology
 *			Check if the port id > 0xffff.
 *			Move device node and fca port node to
 *			gfc_map structure via gfc_port_dev_info_t
 *			pub_port union.
 *			Issue g_get_inq_dtype to get FCP inquiry data
 *			and store it into gfc_port_dev_info_t.
 *
 *		Case of private loop topology
 *			Check if the port id < 0xff.
 *			Move device node and fca port node to
 *			gfc_map structure via gfc_port_dev_info_t
 *			priv_port union.
 *			Issue g_get_inq_dtype to get FCP inquiry data
 *			and store it into gfc_port_dev_info_t.
 *
 *	   else FC4 type(socal/sf or ifp stack)
 *		SFIOCGMAP ioctl to get the device and hba nodes of
 *			sf_addr_pair_t.
 *
 *
 * RETURNS:
 *	0	: if OK
 *	non-zero: otherwise
 */
int
create_map(char *path, gfc_map_t *map_ptr, int verbose, int map_type)
{
int		fd, i, j, num_devices = 0, err, pathcnt = 1;
char		drvr_path[MAXPATHLEN], drvr_path0[MAXPATHLEN];
char		*char_ptr;
struct stat	stbuf;
fc_port_dev_t	*dev_list, *dlistptr;
uint32_t	hba_port_top = 0;
uint_t		dev_type;
sf_al_map_t	sf_map;
gfc_port_dev_info_t	*dev_ptr;
fc_port_dev_t	fp_hba_port;
mp_pathlist_t	pathlist;
int		p_on = 0, p_st = 0;

	/* return invalid path if path is NULL */
	if (path == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if map_ptr is NULL */
	if (map_ptr == NULL) {
		return (L_INVALID_ARG);
	}

	map_ptr->dev_addr = NULL;
	map_ptr->count = 0;
	(void) strcpy(drvr_path, path);
	/*
	 * Get the path to the :devctl driver
	 *
	 * This assumes the path looks something like this:
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0:devctl
	 * or
	 * a 1 level PCI type driver but still :devctl
	 */
	if (strstr(path, SCSI_VHCI)) {
		(void) strcpy(drvr_path0, path);
		if (g_get_pathlist(drvr_path0, &pathlist)) {
			return (L_INVALID_PATH);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (pathlist.path_info[p_on].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			/* on_line path */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_on].path_hba);
		} else {
			/* standby or path0 */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_st].path_hba);
		}
		free(pathlist.path_info);
		(void) strcat(drvr_path, FC_CTLR);
	} else {
		(void) strcpy(drvr_path, path);
		if (strstr(drvr_path, DRV_NAME_SSD) ||
			strstr(drvr_path, SES_NAME) ||
			strstr(drvr_path, DRV_NAME_ST)) {
			if ((char_ptr = strrchr(drvr_path, '/')) == NULL) {
				return (L_INVALID_PATH);
			}
			*char_ptr = '\0';   /* Terminate sting  */
			/* append controller */
			(void) strcat(drvr_path, FC_CTLR);
		} else {
			if (stat(drvr_path, &stbuf) < 0) {
				return (L_LSTAT_ERROR);
			}
			if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
				/* append controller */
				(void) strcat(drvr_path, FC_CTLR);
			}
		}
	}

	P_DPRINTF("  g_get_dev_map: Geting drive map from:"
		" %s\n", drvr_path);

	dev_type = g_get_path_type(drvr_path);
	if ((dev_type == 0) || !(dev_type & XPORT_MASK)) {
		return (L_INVALID_PATH_TYPE);
	}

	/* get fiber topology */
	if ((err = g_get_fca_port_topology(drvr_path,
			&hba_port_top, verbose)) != 0) {
		return (err);
	}

	/* for FC devices. */
	if (dev_type & FC_FCA_MASK) {
		/*
		 * if g_get_dev_list fails with L_NO_DEVICES_FOUND
		 * we still want to call g_get_host_params to try to find the
		 * HBA.  If we do not see any HBAs on the loop, the
		 * g_get_host_params will fail when it trys to issue the target
		 * inquiry ioctl.  In this case, we would still like to return
		 * L_NO_DEVICES_FOUND.
		 *
		 * If g_get_dev_list fails with L_NO_DEVICES_FOUND and
		 * g_get_host_params fails, the function returns
		 * L_NO_DEVICES_FOUND
		 */
		if ((err = g_get_dev_list(drvr_path, &dev_list,
				&num_devices)) != 0) {
			/*
			 * g_get_dev_map doesn't allow ulp failure
			 * to continue thus we need to free dev_list
			 * here.
			 */
			if (err == L_GET_DEV_LIST_ULP_FAILURE) {
				(void) free(dev_list);
			}
			if (err != L_NO_DEVICES_FOUND) {
				return (err);
			}
		}

		/* Get local HBA information */
		if ((err = g_get_host_params(drvr_path, &fp_hba_port,
				verbose)) != 0) {
			(void) free(dev_list);
			if (num_devices == 0)
				return (L_NO_DEVICES_FOUND);
			else
				return (err);
		}

		/* If devices, other than local HBA are found	*/
		/* allocate space for them in the gfc_map.	*/
		if (num_devices > 0) {

			/* If map type is on MAP_FORMAT_LILP we need	*/
			/* to add space for the local HBA		*/
			if (map_type == MAP_FORMAT_LILP) {
				map_ptr->count = ++num_devices;
			} else {
				map_ptr->count = num_devices;
			}

			if ((map_ptr->dev_addr = (gfc_port_dev_info_t *)
			    calloc(map_ptr->count,
				sizeof (gfc_port_dev_info_t))) == NULL) {
			    (void) free(dev_list);
			    return (L_MALLOC_FAILED);
			}
		}

		/* If we want the lilp map then we need to do a little	*/
		/* work here.  The lilp map contains the local hba in	*/
		/* the dev_addr.  Once this has been added qsort the	*/
		/* dev_addr array so it's in physical order.		*/
		/* The lilp map will contain the local hba in the	*/
		/* dev_addr array only when num_devices > 0		*/
		if (map_type == MAP_FORMAT_LILP && num_devices > 0) {

			/* First we need to allocate one additional	*/
			/* device to the dev_addr structure, for the 	*/
			/* local hba					*/
			if ((dev_list = (fc_port_dev_t *)realloc(dev_list,
				(num_devices * sizeof (fc_port_dev_t))))
				== NULL) {
				S_FREE(dev_list);
				(void) free(map_ptr->dev_addr);
				map_ptr->dev_addr = NULL;
				return (L_MALLOC_FAILED);
			}

			/* Next, copy the local hba into this new loc.	*/
			if (memcpy(dev_list+(num_devices-1), &fp_hba_port,
					sizeof (fc_port_dev_t)) == NULL) {
				(void) free(dev_list);
				(void) free(map_ptr->dev_addr);
				map_ptr->dev_addr = NULL;
				return (L_MEMCPY_FAILED);
			}

			/* Now sort by physical location		*/
			qsort((void*)dev_list, num_devices,
				sizeof (fc_port_dev_t), lilp_map_cmp);
		}

		dlistptr = dev_list;
		dev_ptr = map_ptr->dev_addr;

		switch (hba_port_top) {
		case FC_TOP_FABRIC:
		case FC_TOP_PUBLIC_LOOP:
			if (fp_hba_port.dev_did.port_id <= 0xffff) {
				(void) free(dlistptr);
				(void) free(map_ptr->dev_addr);
				map_ptr->dev_addr = NULL;
				return (L_INVALID_FABRIC_ADDRESS);
			} else {
				map_ptr->hba_addr.port_topology = hba_port_top;
				map_ptr->hba_addr.gfc_port_dev.pub_port =
					fp_hba_port;
			}
			for (i = 0; i < num_devices; i++, dev_ptr++,
					dev_list++) {
				if (dev_list->dev_did.port_id <= 0xffff) {
					(void) free(dlistptr);
					(void) free(map_ptr->dev_addr);
					map_ptr->dev_addr = NULL;
					return (L_INVALID_FABRIC_ADDRESS);
				} else {
					dev_ptr->port_topology = hba_port_top;
					dev_ptr->gfc_port_dev.pub_port =
						*dev_list;
				}
			}
			break;
		case FC_TOP_PRIVATE_LOOP:
			/*
			 * Map the (new->old) structures here.
			 * Checking (i < SF_NUM_ENTRIES_IN_MAP) just to
			 * make sure that we don't overrun the map structure
			 * since it can hold data for upto 126 devices.
			 */
			if (fp_hba_port.dev_did.port_id > 0xff) {
				(void) free(dlistptr);
				(void) free(map_ptr->dev_addr);
				map_ptr->dev_addr = NULL;
				return (L_INVALID_PRIVATE_LOOP_ADDRESS);
			} else {
				map_ptr->hba_addr.port_topology = hba_port_top;
				map_ptr->hba_addr.gfc_port_dev.
					priv_port.sf_al_pa =
					(uchar_t)fp_hba_port.dev_did.port_id;
				map_ptr->hba_addr.gfc_port_dev.
					priv_port.sf_hard_address = (uchar_t)
					fp_hba_port.dev_hard_addr.hard_addr;
				for (j = 0; j < FC_WWN_SIZE; j++) {
					map_ptr->hba_addr.gfc_port_dev.
						priv_port.sf_node_wwn[j] =
					fp_hba_port.dev_nwwn.raw_wwn[j];
					map_ptr->hba_addr.gfc_port_dev.
						priv_port.sf_port_wwn[j] =
					fp_hba_port.dev_pwwn.raw_wwn[j];
				}
				map_ptr->hba_addr.gfc_port_dev.
					priv_port.sf_inq_dtype =
					fp_hba_port.dev_dtype;
			}

			for (i = 0; (i < num_devices &&
					i < SF_NUM_ENTRIES_IN_MAP);
					i++, dev_ptr++, dev_list++) {
				/*
				 * Out of 24 bits of port_id, copy only
				 * 8 bits to al_pa. This works okay for
				 * devices that're on a private loop.
				 */
				if (dev_list->dev_did.port_id > 0xff) {
					(void) free(dlistptr);
					(void) free(map_ptr->dev_addr);
					map_ptr->dev_addr = NULL;
					return (L_INVALID_PRIVATE_LOOP_ADDRESS);
				}
				dev_ptr->port_topology = hba_port_top;
				dev_ptr->gfc_port_dev.priv_port.sf_al_pa
					= (uchar_t)dev_list->dev_did.port_id;
				dev_ptr->gfc_port_dev.priv_port.sf_hard_address
					= (uchar_t)dev_list->dev_hard_addr.
						hard_addr;
				for (j = 0; j < FC_WWN_SIZE; j++) {
					dev_ptr->
					gfc_port_dev.priv_port.sf_node_wwn[j] =
						dev_list->dev_nwwn.raw_wwn[j];
					dev_ptr->
					gfc_port_dev.priv_port.sf_port_wwn[j] =
						dev_list->dev_pwwn.raw_wwn[j];
				}
				dev_ptr->gfc_port_dev.priv_port.sf_inq_dtype =
					dev_list->dev_dtype;
			}
			break;
		case FC_TOP_PT_PT:
			(void) free(dlistptr);
			(void) free(map_ptr->dev_addr);
			map_ptr->dev_addr = NULL;
			return (L_PT_PT_FC_TOP_NOT_SUPPORTED);
		default:
			(void) free(dlistptr);
			(void) free(map_ptr->dev_addr);
			map_ptr->dev_addr = NULL;
			return (L_UNEXPECTED_FC_TOPOLOGY);
		}	/* End of switch on port_topology */
		(void) free(dlistptr);

	} else {	/* sf and fc4/pci devices */
		if ((fd = g_object_open(drvr_path, O_NDELAY | O_RDONLY)) == -1)
			return (errno);
		/* initialize map */
		(void) memset(&sf_map, 0, sizeof (struct sf_al_map));
		if (ioctl(fd, SFIOCGMAP, &sf_map) != 0) {
			I_DPRINTF("  SFIOCGMAP ioctl failed.\n");
			(void) close(fd);
			return (L_SFIOCGMAP_IOCTL_FAIL);
		}
		/* Check for reasonableness. */
		if ((sf_map.sf_count > 126) || (sf_map.sf_count < 0)) {
			(void) close(fd);
			return (L_INVALID_LOOP_MAP);
		}
		if (sf_map.sf_count == 0) {
			(void) close(fd);
			return (L_NO_DEVICES_FOUND);
		}

		map_ptr->count = sf_map.sf_count;
		if ((map_ptr->dev_addr =
			(gfc_port_dev_info_t *)calloc(map_ptr->count,
			sizeof (gfc_port_dev_info_t))) == NULL) {
			(void) close(fd);
			return (L_MALLOC_FAILED);
		}
		dev_ptr = map_ptr->dev_addr;
		for (i = 0; i < sf_map.sf_count; i++, dev_ptr++) {
			if (sf_map.sf_addr_pair[i].sf_al_pa > 0xef) {
				(void) free(map_ptr->dev_addr);
				map_ptr->dev_addr = NULL;
				(void) close(fd);
				return (L_INVALID_LOOP_MAP);
			}
			dev_ptr->port_topology = hba_port_top;
			dev_ptr->gfc_port_dev.priv_port =
				sf_map.sf_addr_pair[i];
		}
		map_ptr->hba_addr.port_topology = hba_port_top;
		map_ptr->hba_addr.gfc_port_dev.priv_port =
				sf_map.sf_hba_addr;
		(void) close(fd);
	}

	return (0);
}

/*
 * This function consturct FC proerty list using map_dev_fc_prop_list.
 *
 * port WWN, node WWN, port addr and hard addr properties is constructed.
 *
 * return 0 if OK.
 * otherwise returns error code.
 */
static int
update_map_dev_fc_prop(
	impl_map_dev_prop_t **prop_list, uint32_t map_topo,
	uchar_t *port_wwn, uchar_t *node_wwn, int port_addr,
	int hard_addr)
{
	impl_map_dev_prop_t	*prop_ptr, *pl_start = NULL, *pl_end = NULL;
	uchar_t *port_wwn_data, *node_wwn_data;
	int *port_addr_data, *hard_addr_data;

	/* consrtruct port addr property. */
	if ((map_topo == FC_TOP_FABRIC) ||
		(map_topo == FC_TOP_PUBLIC_LOOP)) {
		if (port_addr <= 0xffff) {
		    return (L_INVALID_FABRIC_ADDRESS);
		}
	} else if (map_topo == FC_TOP_PRIVATE_LOOP) {
		if (port_addr > 0xff) {
		    return (L_INVALID_PRIVATE_LOOP_ADDRESS);
		}
	}

	if ((prop_ptr = (impl_map_dev_prop_t *)calloc(
		1, sizeof (impl_map_dev_prop_t))) == NULL) {
		return (L_MALLOC_FAILED);
	}
	(void) strncpy(prop_ptr->prop_name, PORT_ADDR_PROP,
			strlen(PORT_ADDR_PROP));
	prop_ptr->prop_type = GFC_PROP_TYPE_INT;

	if ((port_addr_data = (int *)calloc(1, sizeof (int))) == NULL) {
		free(prop_ptr);
		return (L_MALLOC_FAILED);
	}
	*port_addr_data = port_addr;
	prop_ptr->prop_data = port_addr_data;

	pl_start = pl_end = prop_ptr;

	/* consrtruct port WWN property. */
	if ((prop_ptr = (impl_map_dev_prop_t *)calloc(
		1, sizeof (impl_map_dev_prop_t))) == NULL) {
		free_prop_list(&pl_start);
		return (L_MALLOC_FAILED);
	}
	(void) strncpy(prop_ptr->prop_name, PORT_WWN_PROP,
			strlen(PORT_WWN_PROP));
	prop_ptr->prop_type = GFC_PROP_TYPE_BYTES;

	if ((port_wwn_data = (uchar_t *)calloc(
		1, FC_WWN_SIZE)) == NULL) {
		free_prop_list(&pl_start);
		return (L_MALLOC_FAILED);
	}
	memcpy(port_wwn_data, port_wwn, FC_WWN_SIZE);
	prop_ptr->prop_data = port_wwn_data;
	prop_ptr->prop_size = FC_WWN_SIZE;
	pl_end->next = prop_ptr;
	pl_end = prop_ptr;

	/* consrtruct node WWN property. */
	if ((prop_ptr = (impl_map_dev_prop_t *)calloc(
		1, sizeof (impl_map_dev_prop_t))) == NULL) {
		free_prop_list(&pl_start);
		return (L_MALLOC_FAILED);
	}
	(void) strncpy(prop_ptr->prop_name, NODE_WWN_PROP,
			strlen(NODE_WWN_PROP));
	prop_ptr->prop_type = GFC_PROP_TYPE_BYTES;

	if ((node_wwn_data = (uchar_t *)calloc(
		1, FC_WWN_SIZE)) == NULL) {
		free_prop_list(&pl_start);
		return (L_MALLOC_FAILED);
	}
	memcpy(node_wwn_data, node_wwn, FC_WWN_SIZE);
	prop_ptr->prop_data = node_wwn_data;
	prop_ptr->prop_size = FC_WWN_SIZE;
	pl_end->next = prop_ptr;
	pl_end = prop_ptr;

	/* consrtruct hard addr property. */
	if ((prop_ptr = (impl_map_dev_prop_t *)calloc(
		1, sizeof (impl_map_dev_prop_t))) == NULL) {
		free_prop_list(&pl_start);
		return (L_MALLOC_FAILED);
	}
	(void) strncpy(prop_ptr->prop_name, HARD_ADDR_PROP,
			strlen(HARD_ADDR_PROP));
	prop_ptr->prop_type = GFC_PROP_TYPE_INT;

	if ((hard_addr_data = (int *)calloc(
		1, sizeof (int))) == NULL) {
		free_prop_list(&pl_start);
		return (L_MALLOC_FAILED);
	}
	*hard_addr_data = hard_addr;
	prop_ptr->prop_data = hard_addr_data;
	pl_end->next = prop_ptr;
	pl_end = prop_ptr;

	if (*prop_list == NULL) {
		*prop_list = pl_start;
	} else {
		pl_end->next = (*prop_list)->next;
		*prop_list = pl_start;
	}

	return (0);
}

/*
 * This function consturct FCP inq dtype propery.
 * if inq_dtype is null the property is constrcted with err info.
 *
 * L_MALLOC_FAILED is the only possible error.
 */
static int
update_map_dev_FCP_prop(
	impl_map_dev_prop_t **prop_list,
	uchar_t *inq_dtype, int err, int exist)
{
	impl_map_dev_prop_t	*prop_ptr, *old_prop_ptr;
	uchar_t *inq_dtype_data;

	if ((prop_ptr = (impl_map_dev_prop_t *)calloc(
		1, sizeof (impl_map_dev_prop_t))) == NULL) {
		return (L_MALLOC_FAILED);
	}

	(void) strncpy(prop_ptr->prop_name, INQ_DTYPE_PROP,
		strlen(INQ_DTYPE_PROP));

	if (inq_dtype == NULL) {
		prop_ptr->prop_data = NULL;
		prop_ptr->prop_error = err;
	} else {
		if ((inq_dtype_data = (uchar_t *)calloc(
			1, sizeof (uchar_t))) == NULL) {
			free(prop_ptr);
			return (L_MALLOC_FAILED);
		}
		memcpy(inq_dtype_data, inq_dtype, sizeof (uchar_t));
		prop_ptr->prop_data = inq_dtype_data;
		prop_ptr->prop_type = GFC_PROP_TYPE_BYTES;
		prop_ptr->prop_size = sizeof (uchar_t);
	}

	if (*prop_list == NULL) {
		*prop_list = prop_ptr;
	} else {
		if (exist == PROP_EXIST) {
			prop_ptr->next = (*prop_list)->next;
			old_prop_ptr = *prop_list;
			*prop_list = prop_ptr;
			free((uchar_t *)(old_prop_ptr->prop_data));
			old_prop_ptr->prop_data = NULL;
			S_FREE(old_prop_ptr);
		} else {
			prop_ptr->next = *prop_list;
			*prop_list = prop_ptr;
		}
	}

	return (0);
}

/*
 * This function calls FCP_TGT_INQUIRY via g_issue_fcp_ioctl()
 * to get the inq_dtype of input device and calls update_map_dev_FCP_prop().
 * inq_dtype is set to NULL and pass error code if inq_dtype data is not
 * requried.
 *
 * return error from update_map_dev_FCP_prop().
 */
static int
handle_map_dev_FCP_prop(
	minor_t fp_xport_minor,
	la_wwn_t port_wwn,
	impl_map_dev_prop_t **prop_list)
{
	struct device_data	inq_data;
	int 			fcp_fd, err;
	struct fcp_ioctl	fcp_data;
	uchar_t			inq_dtype;

	if ((fcp_fd = g_object_open(FCP_PATH, O_RDONLY)) == -1) {
		update_map_dev_FCP_prop(prop_list, NULL,
			L_OPEN_PATH_FAIL, PROP_NOEXIST);
	}

	/* Get the minor number for an fp instance */
	fcp_data.fp_minor = fp_xport_minor;

	/* Get FCP prop for the hba first. */
	fcp_data.listlen = 1;
	inq_data.dev_pwwn = port_wwn;
	fcp_data.list = (caddr_t)&inq_data;

	if (err = g_issue_fcp_ioctl(fcp_fd, &fcp_data, 0)) {
		/* if ioctl error then set the prop_error.	*/
	    if ((err = update_map_dev_FCP_prop(
		prop_list, NULL, err, PROP_NOEXIST)) != 0) {
		return (err);
	    }
	} else {
	    inq_dtype = inq_data.dev0_type;
	    if ((err = update_map_dev_FCP_prop(
		prop_list, &inq_dtype, 0, PROP_NOEXIST)) != 0) {
		return (err);
	    }
	}

	return (0);
}

/*
 * Construct device map tree from nexus driver
 *
 * PARAMS:
 *	path -	must be the physical path to a device
 *	l_err  - ptr to an error code.  Set when NULL is returned.
 *	flag -  device map fomat and property type.
 *
 * LOGIC:
 *	1. check the validity of path via g_get_path_type.
 *	2. If FC path, get the topology of the path via
 *		g_get_fca_port_topology.
 *
 *	3. If FC type(Leadville statck)
 *		FCIO_GET_DEV_LIST to get the device node list of fc_port_dev_t.
 *		FCIO_GET_HOST_PARAMS to get the fca port node of fc_port_dev_t.
 *
 *		root of tree is set with host_params info
 *			FC propery is set.
 *			FCP property is set if reqyested through flag.
 *				Issue g_issue_fcp_ioctl to get FCP inquiry data
 *		consruruct list of children via dev_list.
 *			FC property is set.
 *			FCP property is set if reqyested through flag.
 *				Issue FCIO_DEV_LOGIN if it is fabric device.
 *				Issue g_issue_fcp_ioctl to get FCP inquiry data.
 *
 *	   else FC4 type(socal/sf or ifp stack)
 *		SFIOCGMAP ioctl to get the device and hba nodes of
 *			sf_addr_pair_t.
 *		FCIO_GETMAP ioctl to get hba port info.
 *		consturct map and child tree list and
 *		set the properties as private loop devices.
 *
 * RETURNS:
 *	ptr to map is returned if OK.
 *	NULL and l_err is set otherwise.
 */
gfc_dev_t
g_dev_map_init(char *path, int *l_err, int flag)
{
int		fd, i, num_devices = 0, err, pathcnt = 1, new_count = 0;
char		drvr_path[MAXPATHLEN], drvr_path0[MAXPATHLEN];
char		*char_ptr, *nexus_path;
struct stat	stbuf;
fc_port_dev_t	*dev_list = NULL, *dlist;
uint32_t	hba_port_top, state;
uint_t		path_type;
sf_al_map_t	sf_map;
fc_port_dev_t	fp_hba_port;
mp_pathlist_t	pathlist;
int		p_on = 0, p_st = 0, hba_alpa_found = 0, nexus_fd;
fcio_t		fcio;
struct lilpmap	limited_map;
impl_map_dev_t	*impl_map, *impl_dev, *mdl_start = NULL, *mdl_end = NULL;
struct stat	sbuf;

	if (l_err == NULL) {
		return (NULL);
	}

	if (path == NULL) {
		*l_err = L_INVALID_PATH;
		return (NULL);
	}

	*l_err = 0;

	(void) strcpy(drvr_path, path);
	/*
	 * Get the path to the :devctl driver
	 *
	 * This assumes the path looks something like this:
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0:devctl
	 * or
	 * a 1 level PCI type driver but still :devctl
	 */
	if (strstr(path, SCSI_VHCI)) {
		(void) strcpy(drvr_path0, path);
		if (g_get_pathlist(drvr_path0, &pathlist)) {
			*l_err = L_INVALID_PATH;
			return (NULL);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (pathlist.path_info[p_on].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			/* on_line path */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_on].path_hba);
		} else {
			/* standby or path0 */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_st].path_hba);
		}
		free(pathlist.path_info);
		(void) strcat(drvr_path, FC_CTLR);
	} else {
		(void) strcpy(drvr_path, path);
		if (strstr(drvr_path, DRV_NAME_SSD) ||
			strstr(drvr_path, SES_NAME) ||
			strstr(drvr_path, DRV_NAME_ST)) {
			if ((char_ptr = strrchr(drvr_path, '/')) == NULL) {
				*l_err = L_INVALID_PATH;
				return (NULL);
			}
			*char_ptr = '\0';   /* Terminate sting  */
			/* append controller */
			(void) strcat(drvr_path, FC_CTLR);
		} else {
			if (stat(drvr_path, &stbuf) < 0) {
				*l_err = L_LSTAT_ERROR;
				return (NULL);
			}
			if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
				/* append controller */
				(void) strcat(drvr_path, FC_CTLR);
			}
		}
	}

	P_DPRINTF("  g_dev_map_init: Geting drive map from:"
		" %s\n", drvr_path);

	path_type = g_get_path_type(drvr_path);
	if ((path_type == 0) || !(path_type & XPORT_MASK)) {
		*l_err = L_INVALID_PATH_TYPE;
		return (NULL);
	}

	/* get fiber topology */
	if ((err = g_get_fca_port_topology(drvr_path,
			&hba_port_top, 0)) != 0) {
		*l_err = err;
		return (NULL);
	}

	if ((fd = g_object_open(drvr_path, O_NDELAY | O_RDONLY)) == -1) {
		*l_err = errno;
		return (NULL);
	}

	/* for FC devices. */
	if (path_type & FC_FCA_MASK) {
		/* get the number of device first. */
	    fcio.fcio_cmd = FCIO_GET_NUM_DEVS;
	    fcio.fcio_olen = sizeof (num_devices);
	    fcio.fcio_xfer = FCIO_XFER_READ;
	    fcio.fcio_obuf = (caddr_t)&num_devices;
	    if (g_issue_fcio_ioctl(fd, &fcio, 0) != 0) {
		I_DPRINTF(" FCIO_GET_NUM_DEVS ioctl failed.\n");
		(void) close(fd);
		*l_err = L_FCIO_GET_NUM_DEVS_FAIL;
		return (NULL);
	    }
	    if (num_devices != 0) {
		if ((dev_list = (fc_port_dev_t *)calloc(num_devices,
			sizeof (fc_port_dev_t))) == NULL) {
		    (void) close(fd);
		    *l_err = L_MALLOC_FAILED;
		    return (NULL);
		}

		bzero((caddr_t)&fcio, sizeof (fcio));
		/* Get the device list */
		fcio.fcio_cmd = FCIO_GET_DEV_LIST;
		/* Information read operation */
		fcio.fcio_xfer = FCIO_XFER_READ;
		fcio.fcio_olen = num_devices * sizeof (fc_port_dev_t);
		fcio.fcio_obuf = (caddr_t)dev_list;
		/* new device count */
		fcio.fcio_alen = sizeof (new_count);
		fcio.fcio_abuf = (caddr_t)&new_count;
		if ((err = g_issue_fcio_ioctl(fd, &fcio, 0)) != 0) {
		    if (err == L_INVALID_DEVICE_COUNT) {
			/*
			 * original buffer was small so allocate buffer
			 * with a new count and retry.
			 */
			free(dev_list);
			num_devices = new_count;
			new_count = 0;
			if ((dev_list = (fc_port_dev_t *)calloc(num_devices,
				sizeof (fc_port_dev_t))) == NULL) {
			    (void) close(fd);
			    *l_err = L_MALLOC_FAILED;
			    return (NULL);
			}
			fcio.fcio_cmd = FCIO_GET_DEV_LIST;
			/* Information read operation */
			fcio.fcio_xfer = FCIO_XFER_READ;
			fcio.fcio_obuf = (caddr_t)dev_list;
			fcio.fcio_olen = num_devices * sizeof (fc_port_dev_t);
			/* new device count */
			fcio.fcio_alen = sizeof (new_count);
			fcio.fcio_abuf = (caddr_t)&new_count;
			if ((err = g_issue_fcio_ioctl(fd, &fcio, 0)) != 0) {
			    if (err == L_INVALID_DEVICE_COUNT) {
				/*
				 * No more retry. There may be severe hardware
				 * problem so return error here.
				 */
				I_DPRINTF(" Device count was %d"
				" should have been %d\n",
				num_devices, new_count);
				free(dev_list);
				(void) close(fd);
				*l_err = L_INVALID_DEVICE_COUNT;
				return (NULL);
			    } else {
				I_DPRINTF(" FCIO_GET_DEV_LIST ioctl failed.");
				free(dev_list);
				(void) close(fd);
				*l_err = L_FCIO_GET_DEV_LIST_FAIL;
				return (NULL);
			    }
			}
		    }
		}
	    }

		/*
		 * if new count is smaller than the original number from
		 * FCIO_GET_NUM_DEVS, adjust new count and buffer size
		 * and continue.
		 */
	    if (new_count < num_devices) {
		num_devices = new_count;
		if (new_count > 0) {
		    if ((dev_list = (fc_port_dev_t *)realloc(dev_list,
			(new_count * sizeof (fc_port_dev_t))))
				== NULL) {
			S_FREE(dev_list);
			(void) close(fd);
			*l_err = L_MALLOC_FAILED;
			return (NULL);
		    }
		}
	    }

		/* get the host param info */
	    (void) memset(&fp_hba_port, 0, sizeof (struct fc_port_dev));
	    fcio.fcio_cmd = FCIO_GET_HOST_PARAMS;
	    fcio.fcio_xfer = FCIO_XFER_READ;
	    fcio.fcio_obuf = (caddr_t)&fp_hba_port;
	    fcio.fcio_olen = sizeof (fc_port_dev_t);

	    if (g_issue_fcio_ioctl(fd, &fcio, 0) != 0) {
		I_DPRINTF(" FCIO_GET_HOST_PARAMS ioctl failed.\n");
		(void) close(fd);
		if (num_devices == 0) {
			*l_err = L_NO_DEVICES_FOUND;
		} else {
			free(dev_list);
			*l_err = L_FCIO_GET_HOST_PARAMS_FAIL;
		}
		(void) close(fd);
		return (NULL);
	    }

		/* If we want the lilp map then we need to do a little	*/
		/* work here.  The lilp map contains the local hba in	*/
		/* the dev_addr.  Once this has been added qsort the	*/
		/* dev_addr array so it's in physical order.		*/
	    if ((flag & MAP_FORMAT_LILP) == MAP_FORMAT_LILP) {
		/* First we need to allocate one additional	*/
		/* device to the dev_addr structure, for the 	*/
		/* local hba					*/
		if (num_devices > 0) {
		    if ((dev_list = (fc_port_dev_t *)realloc(dev_list,
			(++num_devices * sizeof (fc_port_dev_t)))) == NULL) {
			(void) close(fd);
			/* in case dev_list is not null free it. */
			S_FREE(dev_list);
			*l_err =  L_MALLOC_FAILED;
			return (NULL);
		    }

		    /* Next, copy the local hba into this new loc.	*/
		    if (memcpy(dev_list+(num_devices-1), &fp_hba_port,
				sizeof (fc_port_dev_t)) == NULL) {
			(void) free(dev_list);
			(void) close(fd);
			*l_err =  L_MEMCPY_FAILED;
			return (NULL);
		    }

			/* Now sort by physical location		*/
		    qsort((void*)dev_list, num_devices,
			sizeof (fc_port_dev_t), lilp_map_cmp);
		}
	    }


		/* We have dev list info and host param info.	*/
		/* Now constructs map tree with these info.	*/
		/* First consturct the root of the map tree	*/
		/* with host param.				*/
	    if ((impl_map = (impl_map_dev_t *)calloc(
			1, sizeof (impl_map_dev_t))) == NULL) {
		(void) free(dev_list);
		(void) close(fd);
		*l_err = L_MALLOC_FAILED;
		return (NULL);
	    }
	    impl_map->flag = flag;
	    impl_map->topo = hba_port_top;

		/* consturct hba property list.	*/
	    if ((err = update_map_dev_fc_prop(&impl_map->prop_list,
		    hba_port_top, fp_hba_port.dev_pwwn.raw_wwn,
		    fp_hba_port.dev_nwwn.raw_wwn, fp_hba_port.dev_did.port_id,
		    fp_hba_port.dev_hard_addr.hard_addr)) != 0) {
		(void) free(dev_list);
		(void) close(fd);
		g_dev_map_fini(impl_map);
		*l_err = err;
		return (NULL);
	    }

	    if ((flag & MAP_XPORT_PROP_ONLY) != MAP_XPORT_PROP_ONLY) {
		if (fstat(fd, &sbuf) == -1) {
		    (void) free(dev_list);
		    (void) close(fd);
		    g_dev_map_fini(impl_map);
		    *l_err = L_FSTAT_ERROR;
		    return (NULL);
		}
		if ((err = handle_map_dev_FCP_prop(minor(sbuf.st_rdev),
			fp_hba_port.dev_pwwn, &impl_map->prop_list)) != 0) {
		    (void) free(dev_list);
		    (void) close(fd);
		    g_dev_map_fini(impl_map);
		    *l_err = err;
		    return (NULL);
		}
	    }

		/* consturct child for each device and	*/
		/* set device property list.		*/
	    dlist = dev_list;
	    for (i = 0; i < num_devices; i++, dlist++) {
		if ((impl_dev = (impl_map_dev_t *)calloc(
			1, sizeof (impl_map_dev_t))) == NULL) {
		    (void) free(dev_list);
		    (void) close(fd);
		    g_dev_map_fini(impl_map);
		    *l_err = L_MALLOC_FAILED;
		    return (NULL);
		}
		/* set the map as parent */
		impl_dev->parent = impl_map;
		if ((err = update_map_dev_fc_prop(&impl_dev->prop_list,
		    hba_port_top, dlist->dev_pwwn.raw_wwn,
		    dlist->dev_nwwn.raw_wwn, dlist->dev_did.port_id,
		    dlist->dev_hard_addr.hard_addr)) != 0) {
		    (void) free(dev_list);
		    (void) close(fd);
		    g_dev_map_fini(impl_map);
		    *l_err = err;
		    return (NULL);
		}
		if (i == 0) {
		    mdl_start = mdl_end = impl_dev;
		} else {
		    mdl_end->next = impl_dev;
		    mdl_end = impl_dev;
		}
		if ((flag & MAP_XPORT_PROP_ONLY) != MAP_XPORT_PROP_ONLY) {
		    if (((hba_port_top == FC_TOP_PUBLIC_LOOP) ||
			(hba_port_top == FC_TOP_FABRIC)) &&
			(memcmp(fp_hba_port.dev_pwwn.raw_wwn,
			dlist->dev_pwwn.raw_wwn, FC_WWN_SIZE) != 0)) {
			(void) memset(&fcio, 0, sizeof (fcio_t));
			fcio.fcio_cmd = FCIO_GET_STATE;
			fcio.fcio_ilen = sizeof (dlist->dev_pwwn);
			fcio.fcio_ibuf = (caddr_t)&dlist->dev_pwwn;
			fcio.fcio_xfer = FCIO_XFER_READ | FCIO_XFER_WRITE;
			fcio.fcio_olen = sizeof (uint32_t);
			fcio.fcio_obuf = (caddr_t)&state;
			fcio.fcio_alen = 0;
			fcio.fcio_abuf = NULL;
			if (g_issue_fcio_ioctl(fd, &fcio, 0) != 0) {
			    I_DPRINTF(" FCIO_GET_STATE ioctl failed.\n");
			    if ((err = update_map_dev_FCP_prop(
				&impl_dev->prop_list, NULL,
				L_FCIO_GET_STATE_FAIL, PROP_NOEXIST)) != 0) {
				(void) free(dev_list);
				(void) close(fd);
				g_dev_map_fini(impl_map);
				*l_err = err;
				return (NULL);
			    }
			}
			if (state != PORT_DEVICE_LOGGED_IN) {
			    (void) close(fd);
			    if ((fd = g_object_open(drvr_path,
				O_NDELAY | O_RDONLY | O_EXCL)) == -1) {
				(void) free(dev_list);
				g_dev_map_fini(impl_map);
				*l_err = L_OPEN_PATH_FAIL;
				return (NULL);
			    }
			    (void) memset(&fcio, 0, sizeof (fcio_t));
			    fcio.fcio_cmd = FCIO_DEV_LOGIN;
			    fcio.fcio_ilen = sizeof (dlist->dev_pwwn);
			    fcio.fcio_ibuf = (caddr_t)&dlist->dev_pwwn;
			    fcio.fcio_xfer = FCIO_XFER_WRITE;
			    fcio.fcio_olen = fcio.fcio_alen = 0;
			    fcio.fcio_obuf = fcio.fcio_abuf = NULL;
			    if (g_issue_fcio_ioctl(fd, &fcio, 0) != 0) {
				I_DPRINTF(" FCIO_DEV_LOGIN ioctl failed.\n");
				if ((err = update_map_dev_FCP_prop(
				    &impl_dev->prop_list, NULL,
				    L_FCIO_DEV_LOGIN_FAIL,
				    PROP_NOEXIST)) != 0) {
				    (void) free(dev_list);
				    (void) close(fd);
				    g_dev_map_fini(impl_map);
				    *l_err = err;
				    return (NULL);
				}
				/* plogi failed continue to next dev */
				continue;
			    }
			}
		    }
			/* sbuf should be set from hba_port handling. */
		    if ((err = handle_map_dev_FCP_prop(minor(sbuf.st_rdev),
			dlist->dev_pwwn, &impl_dev->prop_list)) != 0) {
			(void) free(dev_list);
			(void) close(fd);
			g_dev_map_fini(impl_map);
			*l_err = err;
			return (NULL);
		    }
		}
	    }
		/* connect the children to to map.	*/
	    impl_map->child = mdl_start;
	    S_FREE(dev_list);

	} else {	/* sf and fc4/pci devices */
	    /* initialize map */
	    (void) memset(&sf_map, 0, sizeof (struct sf_al_map));
	    if (ioctl(fd, SFIOCGMAP, &sf_map) != 0) {
		I_DPRINTF("  SFIOCGMAP ioctl failed.\n");
		(void) close(fd);
		*l_err = L_SFIOCGMAP_IOCTL_FAIL;
		return (NULL);
	    }
		/* Check for reasonableness. */
	    if ((sf_map.sf_count > 126) || (sf_map.sf_count < 0)) {
		(void) close(fd);
		*l_err = L_INVALID_LOOP_MAP;
		return (NULL);
	    }

	    if (sf_map.sf_count == 0) {
		(void) close(fd);
		*l_err = L_NO_DEVICES_FOUND;
		return (NULL);
	    }

	    if ((err = g_get_nexus_path(drvr_path, &nexus_path)) != 0) {
		(void) close(fd);
		*l_err = err;
		return (NULL);
	    }

	    if ((nexus_fd = g_object_open(nexus_path, O_NDELAY | O_RDONLY)) ==
			-1) {
		(void) close(fd);
		S_FREE(nexus_path);
		*l_err = errno;
		return (NULL);
	    }

		/* get limited map to get hba param info */
	    if (ioctl(nexus_fd, FCIO_GETMAP, &limited_map) != 0) {
		I_DPRINTF("  FCIO_GETMAP ioctl failed\n");
		(void) close(fd);
		(void) close(nexus_fd);
		S_FREE(nexus_path);
		*l_err = L_FCIO_GETMAP_IOCTL_FAIL;
		return (NULL);
	    }
	    (void) close(nexus_fd);
	    S_FREE(nexus_path);

	    for (i = 0; i < sf_map.sf_count; i++) {
		if (sf_map.sf_addr_pair[i].sf_al_pa ==
			limited_map.lilp_myalpa) {
			sf_map.sf_hba_addr = sf_map.sf_addr_pair[i];
			hba_alpa_found = 1;
		}
	    }

	    if (!(hba_alpa_found)) {
		(void) close(fd);
		*l_err = L_INVALID_LOOP_MAP;
		return (NULL);
	    }

		/* We have dev list info and host param info.	*/
		/* Now constructs map tree with these info.	*/
		/* First consturct the root of the map tree	*/
		/* with host param.				*/
	    if ((impl_map = (impl_map_dev_t *)calloc(
			1, sizeof (impl_map_dev_t))) == NULL) {
		(void) close(fd);
		*l_err = L_MALLOC_FAILED;
		return (NULL);
	    }
	    impl_map->flag = flag;
	    impl_map->topo = hba_port_top;

		/* consturct hba property list.	*/
	    if ((err = update_map_dev_fc_prop(&impl_map->prop_list,
		    hba_port_top, sf_map.sf_hba_addr.sf_port_wwn,
		    sf_map.sf_hba_addr.sf_node_wwn,
		    (int)sf_map.sf_hba_addr.sf_al_pa,
		    (int)sf_map.sf_hba_addr.sf_hard_address)) != 0) {
		(void) close(fd);
		g_dev_map_fini(impl_map);
		*l_err = err;
		return (NULL);
	    }

	    if ((flag & MAP_XPORT_PROP_ONLY) != MAP_XPORT_PROP_ONLY) {
		if ((err = update_map_dev_FCP_prop(&impl_map->prop_list,
		    &sf_map.sf_hba_addr.sf_inq_dtype, 0, PROP_NOEXIST)) != 0) {
		    (void) close(fd);
		    g_dev_map_fini(impl_map);
		    *l_err = err;
		    return (NULL);
		}
	    }

	    for (i = 0; i < sf_map.sf_count; i++) {
		if ((impl_dev = (impl_map_dev_t *)calloc(
			1, sizeof (impl_map_dev_t))) == NULL) {
		    (void) close(fd);
		    g_dev_map_fini(impl_map);
		    *l_err = L_MALLOC_FAILED;
		    return (NULL);
		}
		/* set the map as parent */
		impl_dev->parent = impl_map;
		if ((err = update_map_dev_fc_prop(&impl_dev->prop_list,
		    hba_port_top, sf_map.sf_addr_pair[i].sf_port_wwn,
		    sf_map.sf_addr_pair[i].sf_node_wwn,
		    (int)(sf_map.sf_addr_pair[i].sf_al_pa),
		    (int)(sf_map.sf_addr_pair[i].sf_hard_address))) != 0) {
		    (void) close(fd);
		    g_dev_map_fini(impl_map);
		    *l_err = err;
		    return (NULL);
		}
		if (i == 0) {
		    mdl_start = mdl_end = impl_dev;
		} else {
		    mdl_end->next = impl_dev;
		    mdl_end = impl_dev;
		}
		if ((flag & MAP_XPORT_PROP_ONLY) != MAP_XPORT_PROP_ONLY) {
		    if ((err = update_map_dev_FCP_prop(&impl_dev->prop_list,
			&sf_map.sf_addr_pair[i].sf_inq_dtype, 0,
			PROP_NOEXIST)) != 0) {
			(void) close(fd);
			g_dev_map_fini(impl_map);
			*l_err = err;
			return (NULL);
		    }
		}
	    } /* end of for loop */

	    impl_map->child = mdl_start;
	} /* end of else */

	close(fd);
	return ((gfc_dev_t)(impl_map));
}

/*
 * This function deallocates memory for propery list.
 */
static void
free_prop_list(impl_map_dev_prop_t **prop_list)
{
	impl_map_dev_prop_t *lp, *olp;

	lp = *prop_list;
	while (lp != NULL) {
		switch (lp->prop_type) {
		case GFC_PROP_TYPE_BYTES:
			free((uchar_t *)(lp->prop_data));
			break;
		case GFC_PROP_TYPE_INT:
			free((int *)(lp->prop_data));
			break;
		case GFC_PROP_TYPE_STRING:
			free((char *)(lp->prop_data));
			break;
		default:
			break;
		}
		lp->prop_data = NULL;
		olp = lp;
		lp = olp->next;
		S_FREE(olp);
	}

	*prop_list = NULL;
}

/*
 * This function deallocates memory for children list.
 */
static void
free_child_list(impl_map_dev_t **dev_list)
{
	impl_map_dev_t *lp, *olp;

	lp = *dev_list;
	while (lp != NULL) {
		free_prop_list(&lp->prop_list);
		olp = lp;
		lp = olp->next;
		S_FREE(olp);
	}

	*dev_list = NULL;
}

/*
 * This function deallocates memory for the whole map.
 */
void
g_dev_map_fini(gfc_dev_t map)
{
	impl_map_dev_t *impl_map;

	impl_map = (impl_map_dev_t *)map;

	if (impl_map != NULL) {
	    free_prop_list(&impl_map->prop_list);
	    free_child_list(&impl_map->child);
	    S_FREE(impl_map);
	}
}

/*
 * This function passes back topology of the input map.
 * input should be a handle form g_dev_map_init().
 *
 * return 0 if OK.
 * return error code otherwise.
 */
int
g_get_map_topology(
	gfc_dev_t map,
	uint_t *topology)
{
	impl_map_dev_t	*impl_map;

	if (map == NULL) {
		return (L_INVALID_MAP_DEV_ADDR);
	}

	if (topology == NULL) {
		return (L_INVALID_ARG);
	}

	impl_map = (impl_map_dev_t *)map;

	*topology = impl_map->topo;

	return (0);
}

/*
 * This function returns the first device handle of the input map.
 * map input should be a handle form g_dev_map_init().
 *
 * l_err set to 0 if OK.
 * l_err set to error code otherwise.
 */
gfc_dev_t
g_get_first_dev(
	gfc_dev_t map,
	int *l_err)
{
	impl_map_dev_t	*impl_map;

	if (l_err == NULL) {
		return (NULL);
	}

	*l_err = 0;

	if (map == NULL) {
		*l_err = L_INVALID_MAP_DEV_ADDR;
		return (NULL);
	}

	impl_map = (impl_map_dev_t *)map;

	if (impl_map->child == NULL) {
		*l_err = L_NO_SUCH_DEV_FOUND;
	}

	return ((gfc_dev_t)(impl_map->child));
}

/*
 * This function returns the next device handle of the input map.
 * map_dev input should be a handle for device.
 *
 * l_err set to 0 if OK.
 * l_err set to error code otherwise.
 */
gfc_dev_t
g_get_next_dev(
	gfc_dev_t map_dev,
	int *l_err)
{
	impl_map_dev_t	*impl_dev;

	if (l_err == NULL) {
		return (NULL);
	}

	*l_err = 0;

	if (map_dev == NULL) {
		*l_err = L_INVALID_MAP_DEV_ADDR;
		return (NULL);
	}

	impl_dev = (impl_map_dev_t *)map_dev;

	if (impl_dev->next == NULL) {
		*l_err = L_NO_SUCH_DEV_FOUND;
	}

	return ((gfc_dev_t)(impl_dev->next));
}

/*
 * This function passes back uchar_t type property and its count.
 * map_dev input should be a handle for device.
 *
 * return 0 if OK.
 * return error code otherwise.
 */
int
g_dev_prop_lookup_bytes(
	gfc_dev_t map_dev,
	const char *prop_name,
	int *prop_data_count,
	uchar_t **prop_data)
{
	impl_map_dev_t *impl_dev;
	impl_map_dev_prop_t *impl_prop;
	int err;

	if (map_dev == NULL) {
		return (L_INVALID_MAP_DEV_ADDR);
	}

	if ((prop_name == NULL) || (prop_data == NULL) ||
		(prop_data_count == NULL)) {
		return (L_INVALID_ARG);
	}

	impl_dev = (impl_map_dev_t *)map_dev;
	impl_prop = impl_dev->prop_list;

	err = L_INVALID_MAP_DEV_PROP_NAME;

	while (impl_prop) {
	    if (strncmp(impl_prop->prop_name, prop_name,
		strlen(prop_name)) == 0) {
		if (impl_prop->prop_type != GFC_PROP_TYPE_BYTES) {
		    err = L_INVALID_MAP_DEV_PROP_TYPE;
		    break;
		}
		if (impl_prop->prop_data) {
		    *prop_data = (uchar_t *)(impl_prop->prop_data);
		    *prop_data_count = impl_prop->prop_size;
		    return (0);
		} else {
		    err = impl_prop->prop_error;
		}
		break;
	    }
	    impl_prop = impl_prop->next;
	}

	return (err);
}

/*
 * This function passes back int type property.
 * map_dev input should be a handle for device.
 *
 * return 0 if OK.
 * return error code otherwise.
 */
int
g_dev_prop_lookup_ints(
	gfc_dev_t map_dev,
	const char *prop_name,
	int **prop_data)
{
	impl_map_dev_t *impl_dev;
	impl_map_dev_prop_t *impl_prop;
	int err;

	if (map_dev == NULL) {
		return (L_INVALID_MAP_DEV_ADDR);
	}

	if ((prop_name == NULL) || (prop_data == NULL)) {
		return (L_INVALID_ARG);
	}

	impl_dev = (impl_map_dev_t *)map_dev;
	impl_prop = impl_dev->prop_list;

	err = L_INVALID_MAP_DEV_PROP_NAME;

	while (impl_prop) {
	    if (strncmp(impl_prop->prop_name, prop_name,
		strlen(prop_name)) == 0) {
		if (impl_prop->prop_type != GFC_PROP_TYPE_INT) {
		    err = L_INVALID_MAP_DEV_PROP_TYPE;
		    break;
		}
		if (impl_prop->prop_data) {
		    *prop_data = (int *)(impl_prop->prop_data);
		    return (0);
		} else {
		    err = impl_prop->prop_error;
		}
		break;
	    }
	    impl_prop = impl_prop->next;
	}

	return (err);
}

/*
 * This function passes back int type property.
 * map_dev input should be a handle for device.
 *
 * return 0 if OK.
 * return error code otherwise.
 */
int
g_dev_prop_lookup_strings(
	gfc_dev_t map_dev,
	const char *prop_name,
	char **prop_data)
{
	impl_map_dev_t *impl_dev;
	impl_map_dev_prop_t *impl_prop;
	int err;

	if (map_dev == NULL) {
		return (L_INVALID_MAP_DEV_ADDR);
	}

	if ((prop_name == NULL) || (prop_data == NULL)) {
		return (L_INVALID_ARG);
	}

	impl_dev = (impl_map_dev_t *)map_dev;
	impl_prop = impl_dev->prop_list;

	err = L_INVALID_MAP_DEV_PROP_NAME;

	while (impl_prop) {
	    if (strncmp(impl_prop->prop_name, prop_name,
		strlen(prop_name)) == 0) {
		if (impl_prop->prop_type != GFC_PROP_TYPE_STRING) {
		    err = L_INVALID_MAP_DEV_PROP_TYPE;
		    break;
		}
		if (impl_prop->prop_data) {
		    *prop_data = (char *)(impl_prop->prop_data);
		    return (0);
		} else {
		    err = impl_prop->prop_error;
		}
		break;
	    }
	    impl_prop = impl_prop->next;
	}

	return (err);
}

/*
 * This function returns the handle for the first property of the input device.
 * map_dev input should be a handle form a device.
 *
 * l_err set to 0 if OK.
 * l_err set to error code otherwise.
 */
gfc_prop_t
g_get_first_dev_prop(
	gfc_dev_t map_dev,
	int *l_err)
{
	impl_map_dev_t	*impl_dev;

	if (l_err == NULL) {
		return (NULL);
	}

	*l_err = 0;

	if (map_dev == NULL) {
		*l_err = L_INVALID_MAP_DEV_ADDR;
		return (NULL);
	}

	impl_dev = (impl_map_dev_t *)map_dev;

	if (impl_dev->prop_list == NULL) {
		*l_err = L_NO_SUCH_PROP_FOUND;
	}

	return ((gfc_prop_t)(impl_dev->prop_list));
}

/*
 * This function returns the handle for next property handle of the input prop.
 * map_prop input should be a handle for property.
 *
 * l_err set to 0 if OK.
 * l_err set to error code otherwise.
 */
gfc_prop_t
g_get_next_dev_prop(
	gfc_prop_t map_prop,
	int *l_err)
{
	impl_map_dev_prop_t	*impl_prop;

	if (l_err == NULL) {
		return (NULL);
	}

	*l_err = 0;

	if (map_prop == NULL) {
		*l_err = L_INVALID_MAP_DEV_PROP;
		return (NULL);
	}

	impl_prop = (impl_map_dev_prop_t *)map_prop;

	if (impl_prop->next == NULL) {
		*l_err = L_NO_SUCH_PROP_FOUND;
	}

	return ((gfc_prop_t)(impl_prop->next));
}

/*
 * This function returns the name of the property of the input prop.
 * map_prop input should be a handle for property.
 *
 * return name string if OK.
 * returns NULL and l_err set to error code otherwise.
 */
char *
g_get_dev_prop_name(
	gfc_prop_t map_prop,
	int *l_err)
{
	impl_map_dev_prop_t	*impl_prop;

	if (l_err == NULL) {
		return (NULL);
	}

	*l_err = 0;

	if (map_prop == NULL) {
		*l_err = L_INVALID_MAP_DEV_PROP;
		return (NULL);
	}

	impl_prop = (impl_map_dev_prop_t *)map_prop;

	return (impl_prop->prop_name);
}

/*
 * This function returns the type of the property of the input prop.
 * map_prop input should be a handle for property.
 *
 * return type if OK.
 * returns GFC_PROP_TYPE_UNKNOWN and l_err set to error code otherwise.
 */
int
g_get_dev_prop_type(
	gfc_prop_t map_prop,
	int *l_err)
{
	impl_map_dev_prop_t	*impl_prop;

	if (l_err != NULL) {
		*l_err = 0;
	} else {
		return (L_INVALID_ARG);
	}

	if (map_prop == NULL) {
		*l_err = L_INVALID_MAP_DEV_PROP;
		return (GFC_PROP_TYPE_UNKNOWN);
	}

	impl_prop = (impl_map_dev_prop_t *)map_prop;

	return (impl_prop->prop_type);
}

/*
 * This function passes back uchar_t type property and its count.
 * map_prop input should be a handle for property.
 *
 * return 0 if OK.
 * return error code otherwise.
 */
int
g_get_dev_prop_bytes(
	gfc_prop_t map_prop,
	int *prop_data_count,
	uchar_t **prop_data)
{
	impl_map_dev_prop_t *impl_prop;

	if (map_prop == NULL) {
		return (L_INVALID_MAP_DEV_ADDR);
	}

	if ((prop_data == NULL) || (prop_data_count == NULL)) {
		return (L_INVALID_ARG);
	}

	impl_prop = (impl_map_dev_prop_t *)map_prop;

	if (impl_prop->prop_type != GFC_PROP_TYPE_BYTES) {
		    return (L_INVALID_MAP_DEV_PROP_TYPE);
	}
	if (impl_prop->prop_data) {
	    *prop_data = (uchar_t *)(impl_prop->prop_data);
	    *prop_data_count = impl_prop->prop_size;
	} else {
	    return (impl_prop->prop_error);
	}

	return (0);
}

/*
 * This function passes back int type property.
 * map_prop input should be a handle for property.
 *
 * return 0 if OK.
 * return error code otherwise.
 */
int
g_get_dev_prop_ints(
	gfc_prop_t map_prop,
	int **prop_data)
{
	impl_map_dev_prop_t *impl_prop;

	if (map_prop == NULL) {
		return (L_INVALID_MAP_DEV_ADDR);
	}

	if (prop_data == NULL) {
		return (L_INVALID_ARG);
	}

	impl_prop = (impl_map_dev_prop_t *)map_prop;

	if (impl_prop->prop_type != GFC_PROP_TYPE_INT) {
		    return (L_INVALID_MAP_DEV_PROP_TYPE);
	}
	if (impl_prop->prop_data) {
	    *prop_data = (int *)(impl_prop->prop_data);
	} else {
	    return (impl_prop->prop_error);
	}

	return (0);
}

/*
 * This function passes back string type property.
 * map_prop input should be a handle for property.
 *
 * return 0 if OK.
 * return error code otherwise.
 */
int
g_get_dev_prop_strings(
	gfc_prop_t map_prop,
	char **prop_data)
{
	impl_map_dev_prop_t *impl_prop;

	if (map_prop == NULL) {
		return (L_INVALID_MAP_DEV_ADDR);
	}

	if (prop_data == NULL) {
		return (L_INVALID_ARG);
	}

	impl_prop = (impl_map_dev_prop_t *)map_prop;

	if (impl_prop->prop_type != GFC_PROP_TYPE_STRING) {
		    return (L_INVALID_MAP_DEV_PROP_TYPE);
	}
	if (impl_prop->prop_data) {
	    *prop_data = (char *)(impl_prop->prop_data);
	} else {
	    return (impl_prop->prop_error);
	}

	return (0);
}

/*
 * Free the linked list allocated by g_rdls()
 */
static void
g_free_rls(AL_rls *rlsptr)
{
	AL_rls *trlsptr;

	while (rlsptr != NULL) {
		trlsptr = rlsptr->next;
		free(rlsptr);
		rlsptr = trlsptr;
	}
}

/*
 * Read the extended link error status block
 * from the specified device and Host Adapter.
 *
 * PARAMS:
 *	path_phys - physical path to an FC device
 *	rls_ptr   - pointer to read link state structure
 *
 * RETURNS:
 *	0	: if OK
 *	non-zero: otherwise
 */
int
g_rdls(char *path_phys, struct al_rls **rls_ptr, int verbose)
{
char		nexus_path[MAXPATHLEN], *nexus_path_ptr;
int		fd, fp_fd, err, length, exp_map_flag = 0, *port_addr;
struct lilpmap	map;
AL_rls		*rls, *c1 = NULL, *c2 = NULL;
uchar_t		i, *port_wwn_byte;
la_wwn_t	port_wwn;
sf_al_map_t	exp_map;
char		*charPtr, fp_path[MAXPATHLEN];
uint_t		dev_type;
struct stat	stbuf;
fcio_t		fcio;
fc_portid_t	rls_req;
fc_rls_acc_t	rls_payload;
gfc_dev_t	map_root, map_dev;
uint32_t	hba_port_top, state;
int		pathcnt = 1, count;
mp_pathlist_t	pathlist;
int		p_on = 0, p_st = 0;

	/* return invalid path if path_phys is NULL */
	if (path_phys == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if rls_ptr is NULL */
	if (rls_ptr == NULL) {
		return (L_INVALID_ARG);
	}

	*rls_ptr = rls = NULL;

	if (strstr(path_phys, SCSI_VHCI) != NULL) {
		(void) strcpy(fp_path, path_phys);
		if (g_get_pathlist(fp_path, &pathlist)) {
			return (L_INVALID_PATH);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (pathlist.path_info[p_on].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			/* on_line path */
			(void) strcpy(fp_path,
				pathlist.path_info[p_on].path_hba);
		} else {
			/* standby or path0 */
			(void) strcpy(fp_path,
				pathlist.path_info[p_st].path_hba);
		}
		free(pathlist.path_info);
	} else {
		(void) strcpy(fp_path, path_phys);
	}

	/* Get map of devices on this loop. */
	if ((dev_type = g_get_path_type(fp_path)) == 0) {
		return (L_INVALID_PATH);
	}
	if (dev_type & FC_FCA_MASK) {
		if (strstr(path_phys, SCSI_VHCI) != NULL) {
			(void) strcat(fp_path, FC_CTLR);
		} else if (strstr(fp_path, DRV_NAME_SSD) ||
		    strstr(fp_path, DRV_NAME_ST) ||
				strstr(fp_path, SES_NAME)) {
			if ((charPtr = strrchr(fp_path, '/')) == NULL) {
				return (L_INVALID_PATH);
			}
			*charPtr = '\0';
			/* append devctl to the path */
			(void) strcat(fp_path, FC_CTLR);
		} else {
			if (stat(fp_path, &stbuf) < 0) {
				return (L_LSTAT_ERROR);
			}
			if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
				/* append devctl to the path */
				(void) strcat(fp_path, FC_CTLR);
			}
		}

		if ((map_root = g_dev_map_init(fp_path, &err,
			MAP_XPORT_PROP_ONLY)) == NULL) {
			return (err);
		}

	} else { /* FC4_FCA_MASK type path */
	    (void) memset(&map, 0, sizeof (struct lilpmap));

	    if ((err = g_get_nexus_path(path_phys,
		    &nexus_path_ptr)) != 0) {
		return (err);
	    }
	    (void) strcpy(nexus_path, nexus_path_ptr);
	    g_destroy_data(nexus_path_ptr);

		/* open driver */
	    if ((fd = g_object_open(nexus_path,
			O_NDELAY | O_RDONLY)) == -1)
		return (errno);

		/*
		 * First try using the socal version of the map.
		 * If that fails get the expanded vesion.
		 */
	    if (ioctl(fd, FCIO_GETMAP, &map) != 0) {
		I_DPRINTF("  FCIO_GETMAP ioctl failed.\n");
		if (ioctl(fd, SFIOCGMAP, &exp_map) != 0) {
			I_DPRINTF("  SFIOCGMAP ioctl failed.\n");
			(void) close(fd);
			return (L_SFIOCGMAP_IOCTL_FAIL);
		}
		/* Check for reasonableness. */
		if ((exp_map.sf_count > 126) ||
				(exp_map.sf_count < 0)) {
			(void) close(fd);
			return (L_INVALID_LOOP_MAP);
		}
		for (i = 0; i < exp_map.sf_count; i++) {
			if (exp_map.sf_addr_pair[i].sf_al_pa > 0xef) {
				(void) close(fd);
				return (L_INVALID_LOOP_MAP);
			}
		}
		length = exp_map.sf_count;
		exp_map_flag++;
	    } else {
		I_DPRINTF("  g_rdls:"
			" FCIO_GETMAP ioctl returned %d entries.\n",
			map.lilp_length);
		/* Check for reasonableness. */
		if (map.lilp_length > sizeof (map.lilp_list)) {
			(void) close(fd);
			return (L_FCIOGETMAP_INVLD_LEN);
		}
		length = map.lilp_length;
	    }
	    for (i = 0; i < length; i++) {
		if ((c2 = (struct al_rls *)
			g_zalloc(sizeof (struct al_rls))) == NULL) {
			close(fd);
			return (L_MALLOC_FAILED);
		}
		if (rls == NULL) {
			c1 = rls = c2;
		} else {
			for (c1 = rls; c1->next; c1 =  c1->next) {};
			c1 = c1->next = c2;
		}
		(void) strcpy(c1->driver_path, nexus_path);
		if (exp_map_flag) {
			c1->payload.rls_portno = c1->al_ha =
				exp_map.sf_addr_pair[i].sf_al_pa;
		} else {
			c1->payload.rls_portno = c1->al_ha = map.lilp_list[i];
		}
		c1->payload.rls_linkfail =
				(uint_t)0xff000000; /* get LESB for this port */
		I_DPRINTF("  g_rdls:" " al_pa 0x%x\n", c1->payload.rls_portno);

		if (ioctl(fd, FCIO_LINKSTATUS, &c1->payload) != 0) {
			/*
			 * The ifp driver will return ENXIO when rls
			 * is issued for same initiator on loop when
			 * there is more than one on the loop.
			 * Rather than completely fail, continue on.
			 * Set values in the payload struct to -1 as
			 * this is what socal is currently doing for
			 * the case of same initiator rls.
			 */
			if ((dev_type & FC4_PCI_FCA) && (errno == ENXIO)) {
				c1->payload.rls_linkfail =
				c1->payload.rls_syncfail =
				c1->payload.rls_sigfail =
				c1->payload.rls_primitiverr =
				c1->payload.rls_invalidword =
				c1->payload.rls_invalidcrc = (uint_t)0xffffffff;
			} else {
				I_DPRINTF("  FCIO_LINKSTATUS ioctl"
				" failed with errno %d.\n", errno);
				g_free_rls(rls);
				(void) close(fd);
				return (L_FCIO_LINKSTATUS_FAILED);
			}
		}
		I_DPRINTF("  g_rdls: al_pa returned by ioctl 0x%x\n",
			c1->payload.rls_portno);
	    }
	    *rls_ptr = rls; /* Pass back pointer */

	    (void) close(fd);
	    return (0);
	}

	/* Now we need to take care of FC_FCA_MASK case.	*/
	/* we have map created already via g_dev_map_init.	*/
	if ((err = g_get_map_topology(map_root, &hba_port_top)) != 0) {
		g_dev_map_fini(map_root);
		return (err);
	}

	if ((map_dev = g_get_first_dev(map_root, &err)) == NULL) {
		g_dev_map_fini(map_root);
		if (err != L_NO_SUCH_DEV_FOUND) {
			return (err);
		} else {
			return (L_NO_DEVICES_FOUND);
		}
	}

	while (map_dev) {
	    if ((err = g_dev_prop_lookup_ints(
		map_dev, PORT_ADDR_PROP, &port_addr)) != 0) {
		g_dev_map_fini(map_root);
		g_free_rls(rls);
		return (err);
	    }

	    if ((c2 = (struct al_rls *)
		g_zalloc(sizeof (struct al_rls))) == NULL) {
		g_dev_map_fini(map_root);
		g_free_rls(rls);
		close(fd);
		return (L_MALLOC_FAILED);
	    }
	    if (rls == NULL) {
		c1 = rls = c2;
	    } else {
		for (c1 = rls; c1->next; c1 =  c1->next) {};
		c1 = c1->next = c2;
	    }
	    /* Set the al_ha here */
	    c1->al_ha = rls_req.port_id = *port_addr;

		/*
		 * fp uses different input/output structures for
		 * rls. Load the values returned for the fp ioctl
		 * into the structure passed back to the caller
		 * Note: There is no reason for the path
		 * to be loaded into AL_rls as is done for socal/ifp
		 * above.
		 */
	    if ((hba_port_top == FC_TOP_FABRIC) ||
		(hba_port_top == FC_TOP_PUBLIC_LOOP)) {
		if ((err = g_dev_prop_lookup_bytes(
			map_dev, PORT_WWN_PROP, &count, &port_wwn_byte)) != 0) {
			g_dev_map_fini(map_root);
			g_free_rls(rls);
			return (err);
		}
		memcpy(port_wwn.raw_wwn, port_wwn_byte, FC_WWN_SIZE);
		if ((err = g_get_dev_port_state(
			fp_path, port_wwn, &state)) == 0) {
		    if (state != PORT_DEVICE_LOGGED_IN) {
			if ((err = g_dev_login(fp_path, port_wwn)) != 0) {
				c1->payload.rls_linkfail =
				c1->payload.rls_syncfail =
				c1->payload.rls_sigfail =
				c1->payload.rls_primitiverr =
				c1->payload.rls_invalidword =
				c1->payload.rls_invalidcrc = (uint_t)0xffffffff;
				if (((map_dev =
					g_get_next_dev(map_dev, &err))
					== NULL) &&
					(err != L_NO_SUCH_DEV_FOUND)) {
					g_dev_map_fini(map_root);
					g_free_rls(rls);
					return (err);
				}
				continue;
			}
		    }
		} /* if g_get_dev_port_state fails proceed. */
	    }

	    fcio.fcio_cmd_flags = FCIO_CFLAGS_RLS_DEST_NPORT;
	    if ((fp_fd = g_object_open(fp_path, O_RDONLY | O_EXCL)) < 0) {
		g_dev_map_fini(map_root);
		g_free_rls(rls);
		return (L_OPEN_PATH_FAIL);
	    }
	    fcio.fcio_cmd = FCIO_LINK_STATUS;
	    fcio.fcio_ibuf = (caddr_t)&rls_req;
	    fcio.fcio_ilen = sizeof (rls_req);
	    fcio.fcio_xfer = FCIO_XFER_RW;
	    fcio.fcio_flags = 0;
	    fcio.fcio_obuf = (caddr_t)&rls_payload;
	    fcio.fcio_olen = sizeof (rls_payload);
	    if (g_issue_fcio_ioctl(fp_fd, &fcio, verbose) != 0) {
		c1->payload.rls_linkfail =
		c1->payload.rls_syncfail =
		c1->payload.rls_sigfail =
		c1->payload.rls_primitiverr =
		c1->payload.rls_invalidword =
		c1->payload.rls_invalidcrc = (uint_t)0xffffffff;
	    } else {
		/*
		 * Load the values into the struct passed
		 * back to the caller
		 */
		c1->payload.rls_linkfail = rls_payload.rls_link_fail;
		c1->payload.rls_syncfail = rls_payload.rls_sync_loss;
		c1->payload.rls_sigfail = rls_payload.rls_sig_loss;
		c1->payload.rls_primitiverr = rls_payload.rls_prim_seq_err;
		c1->payload.rls_invalidword = rls_payload.rls_invalid_word;
		c1->payload.rls_invalidcrc = rls_payload.rls_invalid_crc;
	    }
	    (void) close(fp_fd);

	    if (((map_dev = g_get_next_dev(map_dev, &err)) == NULL) &&
		(err != L_NO_SUCH_DEV_FOUND)) {
		g_dev_map_fini(map_root);
		g_free_rls(rls);
		return (err);
	    }
	}

	/* for Leadville issue a final call for the initiator */

	if ((err = g_dev_prop_lookup_ints(
		map_root, PORT_ADDR_PROP, &port_addr)) != 0) {
		g_dev_map_fini(map_root);
		g_free_rls(rls);
		return (err);
	}

	if ((c2 = (struct al_rls *)
		g_zalloc(sizeof (struct al_rls))) == NULL) {
		g_dev_map_fini(map_root);
		g_free_rls(rls);
		return (L_MALLOC_FAILED);
	}
	if (rls == NULL) {
		c1 = rls = c2;
	} else {
		for (c1 = rls; c1->next; c1 =  c1->next) {};
		c1 = c1->next = c2;
	}

	c1->al_ha = rls_req.port_id = *port_addr;

	if ((fp_fd = g_object_open(fp_path, O_RDONLY | O_EXCL)) < 0) {
		g_dev_map_fini(map_root);
		g_free_rls(rls);
		return (L_OPEN_PATH_FAIL);
	}

	fcio.fcio_cmd = FCIO_LINK_STATUS;
	fcio.fcio_ibuf = (caddr_t)&rls_req;
	fcio.fcio_ilen = sizeof (rls_req);
	fcio.fcio_xfer = FCIO_XFER_RW;
	fcio.fcio_flags = 0;
	fcio.fcio_cmd_flags = FCIO_CFLAGS_RLS_DEST_NPORT;
	fcio.fcio_obuf = (caddr_t)&rls_payload;
	fcio.fcio_olen = sizeof (rls_payload);

	if (g_issue_fcio_ioctl(fp_fd, &fcio, verbose) != 0) {
		c1->payload.rls_linkfail =
		c1->payload.rls_syncfail =
		c1->payload.rls_sigfail =
		c1->payload.rls_primitiverr =
		c1->payload.rls_invalidword =
		c1->payload.rls_invalidcrc = (uint_t)0xffffffff;
	} else {
		/*
		 * Load the values into the struct passed
		 * back to the caller
		 */
		c1->payload.rls_linkfail = rls_payload.rls_link_fail;
		c1->payload.rls_syncfail = rls_payload.rls_sync_loss;
		c1->payload.rls_sigfail = rls_payload.rls_sig_loss;
		c1->payload.rls_primitiverr = rls_payload.rls_prim_seq_err;
		c1->payload.rls_invalidword = rls_payload.rls_invalid_word;
		c1->payload.rls_invalidcrc = rls_payload.rls_invalid_crc;
		(void) close(fp_fd);
	}
	(void) close(fp_fd);

	*rls_ptr = rls;	/* Pass back pointer */

	g_dev_map_fini(map_root);
	return (0);
}

static u_longlong_t wwnConversion(uchar_t *wwn)
{
	u_longlong_t tmp;
	memcpy(&tmp, wwn, sizeof (u_longlong_t));
	return (tmp);
}

/*
 * Get device World Wide Name (port and node) for device at path
 * and add all WWNs to the wwn_list_found list.
 *
 * RETURN: 0 O.K.
 *
 * INPUTS:
 *	- path_phys must be of a device, either an IB or disk.
 */
static int
get_wwns(char *path_phys, uchar_t port_wwn[], uchar_t node_wwn[], int *al_pa,
	struct wwn_list_found_struct **wwn_list_found)
{
uint32_t	hba_port_top;
int		i, err, count;
char		*char_ptr, *ptr;
int		found = 0, pathcnt, *port_addr;
unsigned long long 	pwwn;
uchar_t			*port_wwn_byte, *node_wwn_byte;
char		drvr_path[MAXPATHLEN];
int		p_on = 0, p_st = 0;
mp_pathlist_t	pathlist;
char		pwwn1[WWN_S_LEN];
gfc_dev_t	map_root, map_dev;
hrtime_t	start_time, end_time;
char *env = NULL;

	P_DPRINTF("  g_get_wwn: Getting device WWN"
			" and al_pa for device: %s\n",
			path_phys);

	if ((env = getenv("_LUX_T_DEBUG")) != NULL) {
		start_time = gethrtime();
	}

	/*
	 * Get the loop identifier (switch setting) from the path.
	 *
	 * This assumes the path looks something like this:
	 * /devices/.../SUNW,socal@3,0/SUNW,sf@0,0/SUNW,ssd@x,0
	 * or
	 * /devices/.../SUNW,qlc@5/SUNW,fp@0,0/SUNW,ssd@x,0
	 */
	if ((char_ptr = strrchr(path_phys, '@')) == NULL) {
		return (L_INVLD_PATH_NO_ATSIGN_FND);
	}
	char_ptr++;	/* point to the loop identifier or WWN */

	(void) strcpy(drvr_path, path_phys);
	/* This function allocs mem for map.dev_addr on success */
	if (strstr(drvr_path, SCSI_VHCI)) {
		if (g_get_pathlist(drvr_path, &pathlist)) {
			return (L_INVALID_PATH);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (p_on == i) {
			/* on_line path */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_on].path_hba);
			(void) strncpy(pwwn1,
				pathlist.path_info[p_on].path_addr,
				WWN_S_LEN - 1);
			pwwn1[WWN_S_LEN - 1] = '\0';
		} else {
			/* standby or path0 */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_st].path_hba);
			(void) strncpy(pwwn1,
				pathlist.path_info[p_st].path_addr,
				WWN_S_LEN - 1);
			pwwn1[WWN_S_LEN - 1] = '\0';
		}
		free(pathlist.path_info);
		(void) strcat(drvr_path, FC_CTLR);
	}
	if ((map_root = g_dev_map_init(drvr_path, &err,
		MAP_XPORT_PROP_ONLY)) == NULL) {
		return (err);
	}

	if ((err = g_get_map_topology(map_root, &hba_port_top)) != 0) {
		g_dev_map_fini(map_root);
		return (err);
	}

	if (strstr(path_phys, SCSI_VHCI)) {
		char_ptr = pwwn1;
	} else {
		/*
		 * Format of WWN is
		 * ssd@w2200002037000f96,0:a,raw
		 */
		if (*char_ptr != 'w') {
			g_dev_map_fini(map_root);
			return (L_INVLD_WWN_FORMAT);
		}
		char_ptr++;
	}
	pwwn = strtoull(char_ptr, &ptr, 16);
	if (ptr == char_ptr) {
		g_dev_map_fini(map_root);
		return (L_NO_WWN_FOUND_IN_PATH);
	}
	P_DPRINTF("  g_get_wwn:  Looking for WWN "
	    "0x%llx\n", pwwn);

	if (((map_dev = g_get_first_dev(map_root, &err)) == NULL) &&
	    (err != L_NO_SUCH_DEV_FOUND)) {
		g_dev_map_fini(map_root);
		return (err);
	}

	while (map_dev) {
		if ((err = g_dev_prop_lookup_bytes(map_dev,
			PORT_WWN_PROP, &count, &port_wwn_byte)) != 0) {
			g_dev_map_fini(map_root);
			return (err);
		}
		if ((err = g_dev_prop_lookup_bytes(map_dev,
			NODE_WWN_PROP, &count, &node_wwn_byte)) != 0) {
			g_dev_map_fini(map_root);
			return (err);
		}

		if (pwwn == wwnConversion(port_wwn_byte) && found != 1) {
			found = 1;
			memcpy(port_wwn, port_wwn_byte, FC_WWN_SIZE);
			memcpy(node_wwn, node_wwn_byte, FC_WWN_SIZE);
			if ((err = g_dev_prop_lookup_ints(
				map_dev, PORT_ADDR_PROP, &port_addr)) != 0) {
				g_dev_map_fini(map_root);
				return (err);
			}
			*al_pa = *port_addr;
		}
		add_wwn_entry(wwn_list_found, port_wwn_byte,
		    node_wwn_byte);

		if (((map_dev = g_get_next_dev(map_dev, &err)) == NULL) &&
		    (err != L_NO_SUCH_DEV_FOUND)) {
			g_dev_map_fini(map_root);
			return (err);
		}
	}
	if (!found) {
		g_dev_map_fini(map_root);
		return (L_NO_LOOP_ADDRS_FOUND);
	}

	g_dev_map_fini(map_root);
	if (env != NULL) {
		end_time = gethrtime();
		fprintf(stdout, "      get_wwns: "
		"\t\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}
	return (0);
}

/*
 * Get device World Wide Name and AL_PA for device at path
 *
 * RETURN: 0 O.K.
 *
 * INPUTS:
 *	- path_phys must be of a device, either an IB or disk.
 */
int
g_get_wwn(char *path_phys, uchar_t port_wwn[], uchar_t node_wwn[],
	int *al_pa, int verbose)
{
	struct wwn_list_found_struct *wwn_list_found = NULL;
	int ret;

	/* return invalid path if the argument is NULL */
	if (path_phys == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if the argument is NULL */
	if ((port_wwn == NULL) ||
		(node_wwn == NULL) || (al_pa == NULL)) {
		return (L_INVALID_ARG);
	}

	ret = get_wwns(path_phys, port_wwn, node_wwn, al_pa, &wwn_list_found);
	g_free_wwn_list_found(&wwn_list_found);
	return (ret);
}

int
g_get_serial_number(char *path, uchar_t *serial_number,
    size_t *serial_number_len)
{
int	    fd, status = 0;
L_inquiry80 inq80;

	/* return invalid path if path is NULL */
	if (path == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if serial_number is NULL */
	if (serial_number == NULL) {
		return (L_INVALID_ARG);
	}

	P_DPRINTF("  g_get_serial_number: path: %s\n", path);
	if ((fd = g_object_open(path, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}
	/*
	 * Call the inquiry cmd on page 0x80 only if the vendor
	 * supports page 0x80.
	 */
	if ((g_find_supported_inq_page(fd, 0x80))) {
		/*
		 * Let's retrieve the serial number from page 0x80
		 * and store it in the inquiry structure
		 */
		status = g_scsi_inquiry_cmd80(fd,
		    (uchar_t *)&inq80,
		    sizeof (struct l_inquiry80_struct));
		if (status == 0) {
			if (*serial_number_len > inq80.inq_page_len)
				*serial_number_len = inq80.inq_page_len;
			strncpy((char *)serial_number, (char *)inq80.inq_serial,
			    *serial_number_len);
		} else {
			char unavail[] = "Unavailable";
			status = 0;
			if (*serial_number_len > strlen(unavail))
				*serial_number_len = strlen(unavail);
			strncpy((char *)serial_number, unavail,
			    *serial_number_len);
		}
	} else {
		/*
		 * page 0x80 is not supported, so print the
		 * appropriate message.
		 */
		char unsupp[] = "Unsupported";
		if (*serial_number_len > strlen(unsupp))
			*serial_number_len = strlen(unsupp);
		strncpy((char *)serial_number, unsupp,
		    *serial_number_len);
	}
	(void) close(fd);
	return (status);
}

int
g_get_inquiry(char *path, L_inquiry *l_inquiry)
{
int	    fd, status;

	/* return invalid path if path is NULL */
	if (path == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if l_inquiry is NULL */
	if (l_inquiry == NULL) {
		return (L_INVALID_ARG);
	}

	P_DPRINTF("  g_get_inquiry: path: %s\n", path);
	if ((fd = g_object_open(path, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);
	status = g_scsi_inquiry_cmd(fd,
		(uchar_t *)l_inquiry, sizeof (struct l_inquiry_struct));

	(void) close(fd);
	return (status);
}

/*
 * Function to retrieve inquiry page 0x80 from the device
 */
static int
g_scsi_inquiry_cmd80(int fd, uchar_t *buf_ptr, int buf_len)
{
struct uscsi_cmd	ucmd;
my_cdb_g0	cdb = {SCMD_INQUIRY, 0x1, 0x80, 0, 0x10, 0};
struct	scsi_extended_sense	sense;

	(void) memset(buf_ptr, 0, buf_len);
	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.count = (uchar_t)buf_len;
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)buf_ptr;
	ucmd.uscsi_buflen = buf_len;
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct  scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	return (cmd(fd, &ucmd, USCSI_READ | USCSI_SILENT));
}

/*
 * Function to determine if the given page is supported by vendor.
 */
static int
g_find_supported_inq_page(int fd, int page_num)
{
struct	uscsi_cmd	ucmd;
my_cdb_g0	cdb = {SCMD_INQUIRY, 0x1, 0, 0, 0xff, 0};
struct	scsi_extended_sense	sense;
L_inquiry00			inq00;
uchar_t				*data;
int				status = 0;
int				index;

	(void) memset((char *)&ucmd, 0, sizeof (ucmd));
	cdb.count = (uchar_t)(sizeof (L_inquiry00));
	ucmd.uscsi_cdb = (caddr_t)&cdb;
	ucmd.uscsi_cdblen = CDB_GROUP0;
	ucmd.uscsi_bufaddr = (caddr_t)&inq00;
	ucmd.uscsi_buflen = sizeof (inq00);
	ucmd.uscsi_rqbuf = (caddr_t)&sense;
	ucmd.uscsi_rqlen = sizeof (struct scsi_extended_sense);
	ucmd.uscsi_timeout = 60;
	status = cmd(fd, &ucmd, USCSI_READ | USCSI_SILENT);
	if (status) {
		return (0);
	}
	data = (uchar_t *)&inq00;
	for (index = 4; (index <= inq00.len+3)&&
	    (data[index] <= page_num); index ++) {
		if (data[index] == page_num) {
			return (1);
		}
	}
	return (0);
}

int
g_get_perf_statistics(char *path, uchar_t *perf_ptr)
{
int	fd;

	P_DPRINTF("  g_get_perf_statistics: Get Performance Statistics:"
		"\n  Path:%s\n",
		path);

	/* initialize tables */
	(void) memset(perf_ptr, 0, sizeof (int));

	/* open controller */
	if ((fd = g_object_open(path, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);


	/* update parameters in the performance table */

	/* get the period in seconds */


	(void) close(fd);

	return (0);
}


int
g_start(char *path)
{
int	status;
int	fd;

	P_DPRINTF("  g_start: Start: Path %s\n", path);
	if ((fd = g_object_open(path, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);
	status = g_scsi_start_cmd(fd);
	(void) close(fd);
	return (status);
}

int
g_stop(char *path, int immediate_flag)
{
int	status, fd;

	P_DPRINTF("  g_stop: Stop: Path %s\n", path);
	if ((fd = g_object_open(path, O_NDELAY | O_RDONLY)) == -1)
		return (errno);
	status = g_scsi_stop_cmd(fd, immediate_flag);
	(void) close(fd);
	return (status);
}

int
g_reserve(char *path)
{
int 	fd, status;

	P_DPRINTF("  g_reserve: Reserve: Path %s\n", path);
	if ((fd = g_object_open(path, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);
	status = g_scsi_reserve_cmd(fd);
	(void) close(fd);
	return (status);
}

int
g_release(char *path)
{
int 	fd, status;

	P_DPRINTF("  g_release: Release: Path %s\n", path);
	if ((fd = g_object_open(path, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);
	status = g_scsi_release_cmd(fd);
	(void) close(fd);
	return (status);
}

static char
ctoi(char c)
{
	if ((c >= '0') && (c <= '9'))
		c -= '0';
	else if ((c >= 'A') && (c <= 'F'))
		c = c - 'A' + 10;
	else if ((c >= 'a') && (c <= 'f'))
		c = c - 'a' + 10;
	else
		c = -1;
	return (c);
}

int
g_string_to_wwn(uchar_t *wwn, uchar_t *wwnp)
{
	int	i;
	char	c, c1;

	*wwnp++ = 0;
	*wwnp++ = 0;
	for (i = 0; i < WWN_SIZE - 2; i++, wwnp++) {
		c = ctoi(*wwn++);
		c1 = ctoi(*wwn++);
		if (c == -1 || c1 == -1)
			return (-1);
		*wwnp = ((c << 4) + c1);
	}

	return (0);

}

/*
 * Converts a string of WWN ASCII characters to a
 * binary representation.
 *
 * Input: string - pointer to uchar_t array
 *		WWN in ASCII
 *		length: 16 bytes
 * Output: wwn - pointer to uchar_t array
 *		containing WWN result
 *		length: 8 bytes
 * Returns:
 *	non-zero on error
 *	zero on success
 */
int
string_to_wwn(uchar_t *string, uchar_t *wwn)
{
	int	i;
	char	c, c1;
	uchar_t *wwnp;

	wwnp = wwn;

	for (i = 0; i < WWN_SIZE; i++, wwnp++) {

		c = ctoi(*string++);
		c1 = ctoi(*string++);
		if (c == -1 || c1 == -1)
			return (-1);
		*wwnp = ((c << 4) + c1);
	}

	return (0);

}


/*
 * Get multiple paths to a given device port.
 * INPUTS:
 *	port WWN string.
 */
int
g_get_port_multipath(char *port_wwn_s, struct dlist **dlh, int verbose)
{
int		err;
WWN_list	*wwn_list, *wwn_list_ptr;
struct dlist	*dlt, *dl;


	/* Initialize list structures. */
	dl = *dlh  = dlt = (struct dlist *)NULL;
	wwn_list = wwn_list_ptr = NULL;

	H_DPRINTF("  g_get_port_multipath: Looking for multiple paths for"
		" device with\n    port WWW:"
		"%s\n", port_wwn_s);

	if (err = g_get_wwn_list(&wwn_list, verbose)) {
		return (err);
	}

	for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
				wwn_list_ptr = wwn_list_ptr->wwn_next) {
		if (strcmp(port_wwn_s, wwn_list_ptr->port_wwn_s) == 0) {
			if ((dl = (struct dlist *)
				g_zalloc(sizeof (struct dlist))) == NULL) {
				while (*dlh != NULL) {
					dl = (*dlh)->next;
					(void) g_destroy_data(*dlh);
					*dlh = dl;
				}
				(void) g_free_wwn_list(&wwn_list);
				return (L_MALLOC_FAILED);
			}
			H_DPRINTF("  g_get_port_multipath:"
				" Found multipath:\n    %s\n",
				wwn_list_ptr->physical_path);
			dl->dev_path = strdup(wwn_list_ptr->physical_path);
			dl->logical_path = strdup(wwn_list_ptr->logical_path);
			if (*dlh == NULL) {
				*dlh = dlt = dl;
			} else {
				dlt->next = dl;
				dl->prev = dlt;
				dlt = dl;
			}
		}
	}
	(void) g_free_wwn_list(&wwn_list);
	return (0);
}



/*
 * Get multiple paths to a given disk/tape device.
 * The arg: devpath should be the physical path to device.
 *
 * OUTPUT:
 *	multipath_list	points to a list of multiple paths to the device.
 *	NOTE: The caller must free the allocated list (dlist).
 *
 * RETURNS:
 *	0	 if O.K.
 *	non-zero otherwise
 */
int
g_get_multipath(char *devpath, struct dlist **multipath_list,
	struct wwn_list_struct *wwn_list, int verbose)
{
int	err;

	H_DPRINTF("  g_get_multipath: Looking for multiple paths for"
		" device at path: %s\n", devpath);

	/* return invalid path if devpath is NULL */
	if (devpath == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if argument is NULL */
	if ((multipath_list == NULL) || (wwn_list == NULL)) {
		return (L_INVALID_ARG);
	}

	if (strstr(devpath, DRV_NAME_SSD) != NULL) {
		err = get_multipath_disk(devpath, multipath_list, wwn_list);
	} else {
		err = get_multipath(devpath, multipath_list, wwn_list);
	}

	return (err);
}


/*
 * Returns multipath information for a ssd device.
 * Inputs:
 *	devpath: device path to for requested multipath info
 *	wwn_list: returned from g_get_wwn_list or devices_get_all
 * Output:
 *	multipath_list: dlist list of paths
 * Returns:
 *	0 on success
 *	non-zero on failure
 */
int
get_multipath_disk(char *devpath, struct dlist **multipath_list,
	struct wwn_list_struct *wwn_list)
{
WWN_list	*wwn_list_ptr;
struct dlist	*dl = NULL, *dlt = NULL;
ddi_devid_t	devid = NULL;
int		err;
di_node_t	root;
struct mplist_struct	*mplistp = NULL, *mplisth = NULL;

	if (wwn_list == NULL || multipath_list == NULL || devpath == NULL) {
		return (L_NULL_WWN_LIST);
	}

	if ((root = di_init("/", DINFOCPYALL)) == DI_NODE_NIL) {
		return (L_DEV_SNAPSHOT_FAILED);
	}

	if ((err = g_devid_get(devpath, &devid, root, SSD_DRVR_NAME)) != 0) {
		di_fini(root);
		return (err);
	}

	*multipath_list = (struct dlist *)NULL;
	if ((err = devid_get_all(devid, root, SSD_DRVR_NAME, &mplisth)) != 0) {
		di_fini(root);
		return (err);
	}

	if (mplisth == NULL) {
		di_fini(root);
		return (L_NULL_WWN_LIST);
	}

	for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
				wwn_list_ptr = wwn_list_ptr->wwn_next) {
		/*
		 * When a path is found from the list, load the logical
		 * and physical dev path
		 */
		for (mplistp = mplisth; mplistp != NULL;
				mplistp = mplistp->next) {
		    if (strncmp(mplistp->devpath, wwn_list_ptr->physical_path,
			strlen(mplistp->devpath)) == 0) {

			/* Load multipath list */
			if ((dl = (struct dlist *)
				calloc(1, sizeof (struct dlist))) == NULL) {
				while (*multipath_list != NULL) {
					dl = dlt->next;
					g_destroy_data(dlt);
					dlt = dl;
				}
				di_fini(root);
				return (L_MALLOC_FAILED);
			}
			H_DPRINTF("  g_get_multipath: Found multipath=%s\n",
					wwn_list_ptr->physical_path);
			dl->logical_path = strdup(wwn_list_ptr->logical_path);
			dl->dev_path = strdup(wwn_list_ptr->physical_path);
			if (*multipath_list == NULL) {
				*multipath_list = dlt = dl;
			} else {
				dlt->next = dl;
				dl->prev = dlt;
				dlt = dl;
			}
		    }
		}
	}
	di_fini(root);
	mplist_free(mplisth);
	return (0);
}

int
get_multipath(char *devpath, struct dlist **multipath_list,
	struct wwn_list_struct *wwn_list)
{
WWN_list	*wwn_list_ptr;
struct dlist	*dl, *dlt;
char		path[MAXPATHLEN], m_phys_path[MAXPATHLEN], *ptr;
int		len;
int		lun_a = -1;
char		node_wwn_s[WWN_S_LEN];

	if (devpath == NULL) {
		return (L_INVALID_PATH);
	}

	/* Strip partition information. */
	if ((ptr = strrchr(devpath, ':')) != NULL) {
		len = strlen(devpath) - strlen(ptr);
		(void) strncpy(path, devpath, len);
		path[len] = '\0';
	} else {
		(void) strcpy(path, devpath);
	}

	*multipath_list = dl = dlt = (struct dlist *)NULL;


	if (wwn_list == NULL) {
		return (L_NULL_WWN_LIST);
	}

	for (*node_wwn_s = NULL, wwn_list_ptr = wwn_list;
				wwn_list_ptr != NULL;
				wwn_list_ptr = wwn_list_ptr->wwn_next) {

		if ((ptr = strrchr(wwn_list_ptr->physical_path, ':')) != NULL) {
			len = strlen(wwn_list_ptr->physical_path) - strlen(ptr);
			(void) strncpy(m_phys_path, wwn_list_ptr->physical_path,
					len);
			m_phys_path[len] = '\0';
		} else {
			(void) strcpy(m_phys_path, wwn_list_ptr->physical_path);
		}

		if (strcasecmp(m_phys_path, path) == 0) {
			(void) strcpy(node_wwn_s, wwn_list_ptr->node_wwn_s);
			break;
		}
	}

	if (*node_wwn_s == NULL) {
		H_DPRINTF("node_wwn_s is NULL!\n");
		return (L_NO_NODE_WWN_IN_WWNLIST);
	}

	lun_a = g_get_lun_number(wwn_list_ptr->physical_path);

	for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
				wwn_list_ptr = wwn_list_ptr->wwn_next) {
		if ((strcmp(node_wwn_s, wwn_list_ptr->node_wwn_s) == 0) &&
			((lun_a < 0) || (lun_a ==
			g_get_lun_number(wwn_list_ptr->physical_path)))) {

			if ((dl = (struct dlist *)
				g_zalloc(sizeof (struct dlist))) == NULL) {
				while (*multipath_list != NULL) {
					dl = dlt->next;
					(void) g_destroy_data(dlt);
					dlt = dl;
				}
				return (L_MALLOC_FAILED);
			}
			H_DPRINTF("  g_get_multipath: Found multipath=%s\n",
					wwn_list_ptr->physical_path);
			dl->dev_path = strdup(wwn_list_ptr->physical_path);
			dl->logical_path = strdup(wwn_list_ptr->logical_path);
			if (*multipath_list == NULL) {
				*multipath_list = dlt = dl;
			} else {
				dlt->next = dl;
				dl->prev = dlt;
				dlt = dl;
			}
		}
	}
	return (0);
}

/*
 * Free a multipath list
 *
 */
void
g_free_multipath(struct dlist *dlh)
{
struct dlist	*dl;

	while (dlh != NULL) {
		dl = dlh->next;
		if (dlh->dev_path != NULL)
			(void) g_destroy_data(dlh->dev_path);
		if (dlh->logical_path != NULL)
			(void) g_destroy_data(dlh->logical_path);
		(void) g_destroy_data(dlh);
		dlh = dl;
	}
}



/*
 * Get the path to the nexus (HBA) driver.
 * This assumes the path looks something like this:
 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
 * or maybe this
 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@1,0
 * or
 * /devices/sbus@1f,0/SUNW,socal@1,0
 * or
 * /devices/sbus@1f,0/SUNW,socal@1,0:1
 * or
 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0:devctl
 * (or "qlc" instead of "socal" and "fp" for "sf")
 *
 * Which should resolve to a path like this:
 * /devices/sbus@1f,0/SUNW,socal@1,0:1
 * or
 * /devices/pci@6,2000/pci@2/SUNW,qlc@5
 *
 * or
 * /devices/pci@4,2000/scsi@1/ses@w50800200000000d2,0:0
 * which should resolve to
 * /devices/pci@4,2000/scsi@1:devctl
 */
int
g_get_nexus_path(char *path_phys, char **nexus_path)
{
uchar_t		port = 0;
int		port_flag = 0, i = 0, pathcnt = 1;
char		*char_ptr;
char		drvr_path[MAXPATHLEN];
char		buf[MAXPATHLEN];
char		temp_buf[MAXPATHLEN];
struct stat	stbuf;
uint_t		path_type;
mp_pathlist_t	pathlist;
int		p_on = 0, p_st = 0;

	/* return invalid path if the path_phys is NULL */
	if (path_phys == NULL) {
		return (L_INVALID_PATH);
	}

	*nexus_path = NULL;
	(void) strcpy(drvr_path, path_phys);

	if (strstr(path_phys, SCSI_VHCI)) {
		if (g_get_pathlist(drvr_path, &pathlist)) {
			return (L_INVALID_PATH);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (pathlist.path_info[p_on].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			/* on_line path */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_on].path_hba);
		} else {
			/* standby or path0 */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_st].path_hba);
		}
		free(pathlist.path_info);
		(void) strcat(drvr_path, FC_CTLR);
	} else {
		if (strstr(drvr_path, DRV_NAME_SSD) || strstr(drvr_path,
			DRV_NAME_ST) || strstr(drvr_path, SES_NAME)) {
			if ((char_ptr = strrchr(drvr_path, '/')) == NULL) {
				return (L_INVALID_PATH);
			}
			*char_ptr = '\0';   /* Terminate string  */
		}

	path_type = g_get_path_type(drvr_path);

	if (path_type & FC4_SF_XPORT) {

		/* sf driver in path so capture the port # */
		if ((char_ptr = strstr(drvr_path, "sf@")) == NULL) {
				return (L_INVALID_PATH);
		}
		port = atoi(char_ptr + 3);
		if (port > 1) {
			return (L_INVLD_PORT_IN_PATH);
		}

		if ((char_ptr = strrchr(drvr_path, '/')) == NULL) {
			return (L_INVALID_PATH);
		}
		*char_ptr = '\0';   /* Terminate string  */
		port_flag++;

		L_DPRINTF("  g_get_nexus_path:"
			" sf driver in path so use port #%d.\n",
			port);
	} else if (path_type & FC_GEN_XPORT) {
		/*
		 * check to see if it 3rd party vendor FCA.
		 * if it is return error for this operation since
		 * we don't know how they creates FCA port related minor node.
		 *
		 * As of now there is no supported operation on FCA node so
		 * this should be okay.
		 */
		if ((path_type & FC_FCA_MASK) == FC_FCA_MASK) {
			return (L_INVALID_PATH_TYPE);
		}
		/*
		 * For current Sun FCA driver, appending
		 * port # doesn't work. Just remove transport layer from
		 * input path.
		 */
		if ((char_ptr = strstr(drvr_path, "/fp@")) == NULL) {
			return (L_INVALID_PATH);
		}
		*char_ptr = '\0';   /* Terminate string  */
	}

	if (stat(drvr_path, &stbuf) != 0) {
		return (L_LSTAT_ERROR);
	}

	if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
		/*
		 * Found a directory.
		 * Now append a port number or devctl to the path.
		 */
		if (port_flag) {
			/* append port */
			(void) sprintf(buf, ":%d", port);
		} else {
			/* Try adding port 0 and see if node exists. */
			(void) sprintf(temp_buf, "%s:0", drvr_path);
			if (stat(temp_buf, &stbuf) != 0) {
				/*
				 * Path we guessed at does not
				 * exist so it may be a driver
				 * that ends in :devctl.
				 */
				(void) sprintf(buf, ":devctl");
			} else {
				/*
				 * The path that was entered
				 * did not include a port number
				 * so the port was set to zero, and
				 * then checked. The default path
				 * did exist.
				 */
				ER_DPRINTF("Since a complete path"
					" was not supplied "
					"a default path is being"
					" used:\n  %s\n",
					temp_buf);
				(void) sprintf(buf, ":0");
			}
		}

		(void) strcat(drvr_path, buf);
	}

	}
	*nexus_path = g_alloc_string(drvr_path);
	L_DPRINTF("  g_get_nexus_path: Nexus path = %s\n", drvr_path);
	return (0);
}


/*
 * Get the FC topology for the input device or nexus(HBA) path.
 *
 * The routine calls g_get_path_type to determine the stack of
 * the input path.
 *
 * 	If it a socal path
 *		it returns FC_TOP_PRIVATE_LOOP
 *	else
 *		calls fc_get_topology ioctl to
 *		get the fp topolgy from the driver.
 *
 * INPUTS:
 *	path - a string of device path, transport path.
 *		NOTE:  "path" SHOULD NOT BE OPEN BEFORE CALLING
 *			THIS FUNCTION BECAUSE THIS FUNCTION DOES
 *			AN "O_EXCL" OPEN.
 *	port_top - a pointer to the toplogy type.
 *
 * RETURNS:
 *	0 if there is no error.
 *	error code.
 *
 * The input path is expected to be something like below:
 * 	1)
 * 	/devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
 * 	/devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ssd@..
 * 	/devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@1,0
 * 	/devices/sbus@1f,0/SUNW,socal@1,0
 * 	/devices/sbus@1f,0/SUNW,socal@1,0:1
 * 	/devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0:devctl
 * 	(or "qlc" instead of "socal" and "fp" for "sf")
 *
 * 	Which should resolve to a path like this:
 * 	/devices/sbus@1f,0/SUNW,socal@1,0:1
 * 	/devices/pci@6,2000/pci@2/SUNW,qlc@5
 *
 * 	2)
 * 	/devices/pci@4,2000/scsi@1/ses@w50800200000000d2,0:0
 * 	which should resolve to
 * 	/devices/pci@4,2000/scsi@1:devctl
 *
 *      3) The nexus(hba or nexus) path will get an error only for qlc
 *	since the routine need to open fp :devctl node for fcio ioctl.
 * 	/devices/sbus@1f,0/SUNW,socal@1,0
 * 	/devices/sbus@1f,0/SUNW,socal@1,0:1
 * 	/devices/pci@6,2000/pci@2/SUNW,qlc@5 => error
 */
int
g_get_fca_port_topology(char *path, uint32_t *port_top, int verbose)
{
fcio_t		fcio;
int		fd, i = 0, pathcnt = 1;
char		drvr_path[MAXPATHLEN];
char		*char_ptr;
struct stat	stbuf;
uint_t		dev_type;
mp_pathlist_t	pathlist;
int		p_on = 0, p_st = 0;

	/* return invalid path if the path is NULL */
	if (path == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if the argument is NULL */
	if (port_top == NULL) {
		return (L_INVALID_ARG);
	}

	(void) strcpy(drvr_path, path);
	if (strstr(path, SCSI_VHCI)) {
		if (g_get_pathlist(drvr_path, &pathlist)) {
			return (L_INVALID_PATH);
		}
		pathcnt = pathlist.path_count;
		p_on = p_st = 0;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) {
					p_on = i;
					break;
				} else if (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY) {
					p_st = i;
				}
			}
		}
		if (pathlist.path_info[p_on].path_state ==
		    MDI_PATHINFO_STATE_ONLINE) {
			/* on_line path */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_on].path_hba);
		} else {
			/* standby or path0 */
			(void) strcpy(drvr_path,
				pathlist.path_info[p_st].path_hba);
		}
		free(pathlist.path_info);
		(void) strcat(drvr_path, FC_CTLR);
	} else {
	/*
	 * Get the path to the :devctl driver
	 *
	 * This assumes the path looks something like this:
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0
	 * or
	 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0:devctl
	 * or
	 * a 1 level PCI type driver but still :devctl
	 * (or "qlc" in the place of "socal" and "fp" for "sf")
	 *
	 * The dir below doesn't have corresponding :devctl node.
	 * /devices/pci@6,2000/pci@2/SUNW,qlc@5
	 * /devices/sbus@2,0/SUNW,socal@1,0
	 *
	 */
		if ((strstr(drvr_path, DRV_NAME_SSD) ||
			strstr(drvr_path, SES_NAME)) ||
			strstr(drvr_path, DRV_NAME_ST)) {
			if ((char_ptr = strrchr(drvr_path, '/')) == NULL) {
				return (L_INVALID_PATH);
			}
			*char_ptr = '\0';   /* Terminate sting  */
			/* append controller */
			(void) strcat(drvr_path, FC_CTLR);
		} else {
			if (stat(drvr_path, &stbuf) < 0) {
				return (L_LSTAT_ERROR);
			}
			if ((stbuf.st_mode & S_IFMT) == S_IFDIR) {
				/* append controller */
				(void) strcat(drvr_path, FC_CTLR);
			}
		}
	}

	if ((dev_type = g_get_path_type(drvr_path)) == 0) {
		return (L_INVALID_PATH);
	}

	if ((dev_type & FC4_XPORT_MASK) || (dev_type & FC4_FCA_MASK)) {
		*port_top = FC_TOP_PRIVATE_LOOP;
		return (0);
	}

	/* To contiue the path type should be fp :devctl node */
	if (!(dev_type & FC_XPORT_MASK)) {
		return (L_INVALID_PATH);
	}

	if ((fd = g_object_open(drvr_path, O_NDELAY | O_RDONLY)) == -1)
		return (errno);

	P_DPRINTF("  g_get_fca_port_topology: Geting topology from:"
		" %s\n", drvr_path);

	fcio.fcio_cmd = FCIO_GET_TOPOLOGY;
	fcio.fcio_olen = sizeof (uint32_t);
	fcio.fcio_xfer = FCIO_XFER_READ;
	fcio.fcio_obuf = (caddr_t)port_top;
	if (g_issue_fcio_ioctl(fd, &fcio, verbose) != 0) {
		I_DPRINTF(" FCIO_GET_TOPOLOGY ioctl failed.\n");
		close(fd);
		return (L_FCIO_GET_TOPOLOGY_FAIL);
	}
	close(fd);
	return (0);
}


/*
 * This functions enables or disables a FCA port depending on the
 * argument, cmd, passed to it. If cmd is PORT_OFFLINE, the function
 * tries to disable the port specified by the argument 'phys_path'. If
 * cmd is PORT_ONLINE, the function tries to enable the port specified
 * by the argument 'phys_path'.
 * INPUTS :
 *	nexus_port_ptr - Pointer to the nexus path of the FCA port to
 *			operate on
 *	cmd       - PORT_OFFLINE or PORT_ONLINE
 * RETURNS :
 *	0 on success and non-zero otherwise
 */
static int
g_set_port_state(char *nexus_port_ptr, int cmd)
{
	int	path_type, fd;

	if ((path_type = g_get_path_type(nexus_port_ptr)) == 0) {
		return (L_INVALID_PATH);
	}

	if ((fd = g_object_open(nexus_port_ptr, O_NDELAY|O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}

	switch (cmd) {
		case PORT_OFFLINE:
			if (path_type & FC4_SOCAL_FCA) {
				/*
				 * Socal/sf drivers -
				 * The socal driver currently returns EFAULT
				 * even if the ioctl has completed successfully.
				 */
				if (ioctl(fd, FCIO_LOOPBACK_INTERNAL,
							NULL) == -1) {
					close(fd);
					return (L_PORT_OFFLINE_FAIL);
				}
			} else {
				/*
				 * QLogic card -
				 * Can't do much here since the driver currently
				 * doesn't support this feature. We'll just fail
				 * for now. Support can be added when the driver
				 * is enabled with the feature at a later date.
				 */
				close(fd);
				return (L_PORT_OFFLINE_UNSUPPORTED);
			}
			break;
		case PORT_ONLINE:
			if (path_type & FC4_SOCAL_FCA) {
				/*
				 * Socal/sf drivers
				 * The socal driver currently returns EFAULT
				 * even if the ioctl has completed successfully.
				 */
				if (ioctl(fd, FCIO_NO_LOOPBACK, NULL) == -1) {
					close(fd);
					return (L_PORT_ONLINE_FAIL);
				}
			} else {
				/*
				 * QLogic card -
				 * Can't do much here since the driver currently
				 * doesn't support this feature. We'll just fail
				 * for now. Support can be added when the driver
				 * is enabled with the feature at a later date.
				 */
				close(fd);
				return (L_PORT_ONLINE_UNSUPPORTED);
			}
			break;
		default:
			close(fd);
			return (-1);
	}
	close(fd);
	return (0);
}

/*
 * The interfaces defined below (g_port_offline() and g_port_online())
 * are what will be exposed to applications. We will hide g_set_port_state().
 * They have to be functions (as against macros) because making them
 * macros will mean exposing g_set_port_state() and we dont want to do that
 */

int
g_port_offline(char *path)
{
	return (g_set_port_state(path, PORT_OFFLINE));
}

int
g_port_online(char *path)
{
	return (g_set_port_state(path, PORT_ONLINE));
}

/*
 * This function sets the loopback mode for a port on a HBA
 * INPUTS :
 *	portpath	- Pointer to the path of the FCA port on which to
 *			set the loopback mode
 *	cmd       	- EXT_LPBACK
 *			  INT_LPBACK
 *			  NO_LPBACK
 * RETURNS :
 *	0 on success and non-zero otherwise
 */
int
g_loopback_mode(char *portpath, int cmd)
{
	int	path_type, fd;

	if ((path_type = g_get_path_type(portpath)) == 0) {
		return (L_INVALID_PATH);
	}

	if ((fd = g_object_open(portpath, O_NDELAY|O_RDONLY|O_EXCL)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}

	/*
	 * The loopback calls are currently not fully supported
	 * via fp.
	 *
	 * A fp based general solution is required to support Leadville FCAs
	 * including Qlgc and 3rd party FCA. As of now qlgc provides
	 * some diag functions like echo through qlc private ioctl
	 * which is not supproted by luxadm and libraries.
	 */
	switch (cmd) {
		case EXT_LPBACK:
			if (path_type & FC4_SOCAL_FCA) {
				if (ioctl(fd, FCIO_LOOPBACK_MANUAL,
							NULL) == -1) {
					/* Check for previous mode set */
					if (errno != EALREADY) {
						close(fd);
						return (L_LOOPBACK_FAILED);
					}
				}
			} else {
				/*
				 * Well, it wasn't one of the above cards so..
				 */
				close(fd);
				return (L_LOOPBACK_UNSUPPORTED);
			}
			break;
		case NO_LPBACK:
			if (path_type & FC4_SOCAL_FCA) {
				if (ioctl(fd, FCIO_NO_LOOPBACK, NULL) == -1) {
					close(fd);
					return (L_LOOPBACK_FAILED);
				}
			} else {
				/*
				 * Well, it wasn't one of the above cards so..
				 */
				close(fd);
				return (L_LOOPBACK_UNSUPPORTED);
			}
			break;
		case INT_LPBACK:
			if (path_type & FC4_SOCAL_FCA) {
				if (ioctl(fd, FCIO_LOOPBACK_INTERNAL,
					NULL) == -1) {
					/* Check for previous mode set */
					if (errno != EALREADY) {
						close(fd);
						return (L_LOOPBACK_FAILED);
					}
				}
			} else {
				/*
				 * Well, it wasn't one of the above cards so..
				 */
				close(fd);
				return (L_LOOPBACK_UNSUPPORTED);
			}
			break;
		default:
			close(fd);
			return (L_LOOPBACK_UNSUPPORTED);
	}
	close(fd);
	return (0);
}

/*
 * g_get_port_state(char *portpath, int port_state)
 * Purpose: Get port state for a path
 * Input:   portpath
 *		set to path of port
 * Output:  port_state
 *	Set to one of the following:
 *		PORT_CONNECTED
 *		PORT_NOTCONNECTED
 * Returns: 0 on success
 *	    non-zero on failure
 */
int
g_get_port_state(char *portpath, int *portstate, int verbose)
{
	int	fd, err, num_devices = 0;
	struct lilpmap	map;
	uint_t	dev_type;
	gfc_dev_t	map_root;


	(void) memset(&map, 0, sizeof (struct lilpmap));

	/* return invalid path if portpath is NULL */
	if (portpath == NULL) {
		return (L_INVALID_PATH);
	}
	/* return invalid arg if argument is NULL */
	if ((portpath == NULL) || (portstate == NULL)) {
		return (L_INVALID_ARG);
	}

	if ((dev_type = g_get_path_type(portpath)) == 0) {
		return (L_INVALID_PATH);
	}

	/*
	 * FCIO_GETMAP returns error when there are * no devices attached.
	 * ENOMEM is returned when no devices are attached.
	 * g_get_first_dev returns NULL without error when there is no
	 * devices are attached.
	 */
	if (dev_type & FC_FCA_MASK) {
		if ((map_root = g_dev_map_init(portpath, &err,
			MAP_XPORT_PROP_ONLY)) == NULL) {
			return (err);
		}

		if (g_get_first_dev(map_root, &err) == NULL) {
			/* no device is found if err == 0 */
			if (err == L_NO_SUCH_DEV_FOUND) {
				*portstate = PORT_NOTCONNECTED;
			}
			g_dev_map_fini(map_root);
			return (0);
		} else {
			/* Device found okay */
			*portstate = PORT_CONNECTED;
			g_dev_map_fini(map_root);
		}

	} else {
		/* open controller */
		if ((fd = g_object_open(portpath, O_NDELAY | O_RDONLY)) == -1) {
			return (errno);
		}

		/*
		 * Note: There is only one error returned by this ioctl. ENOMEM.
		 * Hence the lack of return on error.
		 */
		if (ioctl(fd, FCIO_GETMAP, &map) != 0) {
			map.lilp_length = 0;
		}
		num_devices = map.lilp_length;

		/* Non-Leadville stacks report the FCA in the count */
		*portstate = (num_devices > 1) ? PORT_CONNECTED :
							PORT_NOTCONNECTED;
		(void) close(fd);
	}
	return (0);
}

/*
 * g_dev_login(char *port_path, la_wwn_t port_wwn)
 * Purpose: port login via g_dev_log_in_out()
 * Input:   port_path
 *		fc transport port with fabric/public loop topology
 *	    port_wwn
 *		port wwn of device node to login
 *
 * Returns: return code from g_dev_log_in_out()
 */
int
g_dev_login(char *port_path, la_wwn_t port_wwn)
{
	return (g_dev_log_in_out(port_path, port_wwn, FCIO_DEV_LOGIN));
}


/*
 * g_dev_logout(char *port_path, la_wwn_t port_wwn)
 * Purpose: port login via g_dev_log_in_out()
 * Input:   port_path
 *		fc transport port with fabric/public loop topology
 *	    port_wwn
 *		port wwn of device node to logout
 *
 * Returns: return code from g_dev_log_in_out()
 */
int
g_dev_logout(char *port_path, la_wwn_t port_wwn)
{
	return (g_dev_log_in_out(port_path, port_wwn, FCIO_DEV_LOGOUT));
}


/*
 * g_dev_log_in_out(char *port_path, la_wwn_t port_wwn, uint16_t cmd)
 * Purpose: port login via FCIO_DEV_LOGOUT and port logout via FCIO_DEV_LOGOUT
 *	    IOCTL requires EXCLUSIVE open.
 * Input:   port_path
 *		fc transport port with fabric/public loop topology
 *	    port_wwn
 *		port wwn of device node to logout
 *	    cmd
 *		FCIO_DEV_LOGON or FCIO_DEV_LOGOUT
 *
 * Returns: 0 on success
 *	    non-zero on failure
 */
static int
g_dev_log_in_out(char *port_path, la_wwn_t port_wwn, uint16_t cmd)
{
int		fd, err;
uint32_t	hba_port_top;
fcio_t		fcio;
int		verbose = 0;

	if ((err = g_get_fca_port_topology(port_path,
		&hba_port_top, verbose)) != 0) {
		return (err);
	}

	if (!((hba_port_top == FC_TOP_PUBLIC_LOOP) ||
		(hba_port_top == FC_TOP_FABRIC))) {
		return (L_OPNOSUPP_ON_TOPOLOGY);
	}

	/* open controller */
	if ((fd = g_object_open(port_path, O_NDELAY | O_RDONLY | O_EXCL)) == -1)
		return (L_OPEN_PATH_FAIL);

	/*
	 * stores port_wwn to la_wwn_t raw_wwn field
	 * and construct fcio structures for FCIO_DEV_LOGIN.
	 */
	fcio.fcio_cmd = cmd;
	fcio.fcio_ilen = sizeof (port_wwn);
	fcio.fcio_ibuf = (caddr_t)&port_wwn;
	fcio.fcio_xfer = FCIO_XFER_WRITE;
	fcio.fcio_olen = fcio.fcio_alen = 0;
	fcio.fcio_obuf = fcio.fcio_abuf = NULL;
	if (g_issue_fcio_ioctl(fd, &fcio, verbose) != 0) {
		I_DPRINTF((cmd == FCIO_DEV_LOGIN) ?
			" FCIO_DEV_LOGIN ioctl failed.\n"
			: " FCIO_DEV_LOGOUT ioctl failed.\n");
		(void) close(fd);
		return ((cmd == FCIO_DEV_LOGIN) ?
			L_FCIO_DEV_LOGIN_FAIL
			: L_FCIO_DEV_LOGOUT_FAIL);
	} else {
		(void) close(fd);
		return (0);
	}
}

/*
 * This function will verify if a FC device (represented by input WWN
 * is connected on a FCA port by searching the device list from
 * g_get_dev_list() for a WWN match.
 *
 * input:
 *   fca_path: pointer to the physical path string, path to a fp node.
 *             possible forms are
 *		/devices/pci@1f,2000/pci@1/SUNW,qlc@5/fp@0,0:devctl
 *   dev_wwn: WWN string
 *   flag: indicate that the input WWN is node or port
 *
 * returned values
 *   0: if a match is found.
 *   L_WWN_NOT_FOUND_IN_DEV_LIST: if no match found
 *   L_UNEXPECTED_FC_TOPOLOGY: existing error code for an error
 *	from the topology checking of the input fca path.
 *   L_MALLOC_FAILED: existing error code for allocation eror from the
 *	g_get_dev_list().
 *   L_FCIO_GETMAP_IOCTL_FAIL: existing error code for an error from the
 *	FCIO ioctl called by the g_get_dev_list()
 *   -1: other failure
 *
 */
int
g_wwn_in_dev_list(char *fca_path, la_wwn_t dev_wwn, int flag)
{
uint_t		dev_type;
int		i, err;
fc_port_dev_t	*dev_list;
fc_port_dev_t	*dev_list_save;
int		num_devices = 0;

	if ((dev_type = g_get_path_type(fca_path)) == 0) {
		return (L_INVALID_PATH);
	}

	if (!(dev_type & FC_XPORT_MASK)) {
		return (L_INVALID_PATH_TYPE);
	}

	if (((err = g_get_dev_list(fca_path, &dev_list, &num_devices))
		!= 0) && (err != L_GET_DEV_LIST_ULP_FAILURE)) {
		return (err);
	}

	dev_list_save = dev_list;

	switch (flag) {
	case MATCH_NODE_WWN:
		for (i = 0; i < num_devices; i++, dev_list++) {
			if (memcmp(dev_list->dev_nwwn.raw_wwn,
					dev_wwn.raw_wwn, FC_WWN_SIZE) == 0) {
				(void) free(dev_list_save);
				return (0);
			}
		}
		(void) free(dev_list_save);
		/* consider a new error code for not found. */
		return (L_WWN_NOT_FOUND_IN_DEV_LIST);

	case MATCH_PORT_WWN:
		for (i = 0; i < num_devices; i++, dev_list++) {
			if (memcmp(dev_list->dev_pwwn.raw_wwn,
					dev_wwn.raw_wwn, FC_WWN_SIZE) == 0) {
				(void) free(dev_list_save);
				return (0);
			}
		}
		(void) free(dev_list_save);
		/* consider a new error code for not found. */
		return (L_WWN_NOT_FOUND_IN_DEV_LIST);
	}
	(void) free(dev_list_save);
	return (-1);
}


/*
 * g_get_dev_port_state(char *fca_path, la_wwn_t port_wwn, uint32_t *state)
 * Purpose: get the state of device port login via FCIO_GET_STATE ioctl.
 *
 * Input:   fca_path
 *		fc transport port with fabric/public loop topology
 *	    port_wwn
 *		port wwn of device node to logout
 *	    state
 *		port login or not
 *
 * Returns: 0 on success
 *	    non-zero on failure
 */
static int
g_get_dev_port_state(char *fca_path, la_wwn_t port_wwn, uint32_t *state)
{
int		fd;
int		dev_type;
fcio_t		fcio;
int		verbose = 0;

	if ((dev_type = g_get_path_type(fca_path)) == 0) {
		return (L_INVALID_PATH);
	}

	if (!(dev_type & FC_XPORT_MASK)) {
		return (L_INVALID_PATH_TYPE);
	}

	/* open controller */
	if ((fd = g_object_open(fca_path, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);

	/*
	 * stores port_wwn to la_wwn_t raw_wwn field
	 * and construct fcio structures for FCIO_DEV_LOGIN.
	 */
	fcio.fcio_cmd = FCIO_GET_STATE;
	fcio.fcio_ilen = sizeof (port_wwn);
	fcio.fcio_ibuf = (caddr_t)&port_wwn;
	fcio.fcio_xfer = FCIO_XFER_READ | FCIO_XFER_WRITE;
	fcio.fcio_olen = sizeof (uint32_t);
	fcio.fcio_obuf = (caddr_t)state;
	fcio.fcio_alen = 0;
	fcio.fcio_abuf = NULL;
	if (g_issue_fcio_ioctl(fd, &fcio, verbose) != 0) {
		I_DPRINTF(" FCIO_GET_STATE ioctl failed.\n");
		(void) close(fd);
		return (L_FCIO_GET_STATE_FAIL);
	} else {
		(void) close(fd);
		return (0);
	}
}

/*
 * Name: lilp_map_cmp
 *
 * Description: This function is used to compare the physical location
 *              of to fc devices in a gfc_map_t.dev_addr arrary.
 *
 * Params:
 *	First device to compare
 *	Second device to compare
 *
 * Return:
 *   0 = Devices at equal phyiscal location, How did this happen?
 *  >0 = First device have a higher physical location than second
 *  <0 = Second device have a higher physical location than first
 */
static int lilp_map_cmp(const void* dev1, const void* dev2) {
	int i_dev1 = ((fc_port_dev_t *)dev1)->dev_did.priv_lilp_posit;
	int i_dev2 = ((fc_port_dev_t *)dev2)->dev_did.priv_lilp_posit;

	if (i_dev1 > i_dev2)
		return (1);
	if (i_dev1 < i_dev2)
		return (-1);
	return (0);
}

/*
 * Description:
 *    Retrieves multiple paths to a device based on devid
 *    Caller must use mplist_free to free mplist structure
 *    This currently only supports ssd devices.
 *    The st driver does not register a device id.
 *
 * Input Values:
 *
 *    devid: ptr to valid ddi_devid_t struct
 *    root: root handle to device tree snapshot
 *    drvr_name: driver name to start the node tree search
 *
 * Return Value:
 *    0 on success
 *    non-zero on failure
 */

static int
devid_get_all(ddi_devid_t devid, di_node_t root, char *drvr_name,
		struct mplist_struct **mplistp)
{
ddi_devid_t mydevid;
di_node_t node;
char *devfs_path = NULL;
struct mplist_struct *mpl, *mpln;

	if (devid == NULL || root == NULL || drvr_name == NULL ||
		mplistp == NULL ||
		(strncmp(drvr_name, SSD_DRVR_NAME, strlen(SSD_DRVR_NAME))
			!= 0)) {
		return (EINVAL);
	}

	*mplistp = mpl = mpln = (struct mplist_struct *)NULL;

	/* point to first node which matches portdrvr */
	node = di_drv_first_node(drvr_name, root);
	if (node == DI_NODE_NIL) {
		return (L_NO_DRIVER_NODES_FOUND);
	}

	while (node != DI_NODE_NIL) {
		if ((mydevid = di_devid(node)) != NULL) {
			if (((devid_compare(mydevid, devid)) == 0)) {
			    /* Load multipath list */
			    if ((mpl = (struct mplist_struct *)
				calloc(1, sizeof (struct mplist_struct)))
					== NULL) {
				mplist_free(*mplistp);
				return (L_MALLOC_FAILED);
			    }
			    if ((devfs_path = my_devfs_path(node)) == NULL) {
				node = di_drv_next_node(node);
				S_FREE(mpl);
				continue;
			    }
			    mpl->devpath = (char *)calloc(1,
					strlen(devfs_path) +
					strlen(SSD_MINOR_NAME) + 1);
			    if (mpl->devpath == NULL) {
				S_FREE(mpl);
				mplist_free(*mplistp);
				my_devfs_path_free(devfs_path);
				return (L_MALLOC_FAILED);
			    }
			    sprintf(mpl->devpath, "%s%s", devfs_path,
					SSD_MINOR_NAME);
			    if (*mplistp == NULL) {
				*mplistp = mpln = mpl;
			    } else {
				mpln->next = mpl;
				mpln = mpl;
			    }
			    my_devfs_path_free(devfs_path);
			}
		}
	node = di_drv_next_node(node);
	}
	return (0);
}

/*
 * Frees a previously allocated mplist_struct
 */
static void
mplist_free(struct mplist_struct *mplistp)
{
struct mplist_struct *mplistn;

	while (mplistp != NULL) {
		mplistn = mplistp->next;
		if (mplistp->devpath != NULL) {
			free(mplistp->devpath);
			mplistp->devpath = NULL;
		}
		free(mplistp);
		mplistp = mplistn;
	}
}

/*
 * Description
 *	Retrieves all device nodes based on drvr_name
 *	Currently supports SSD_DRVR_NAME, ST_DRVR_NAME
 *	There will be a device node in the libdevinfo
 *	snapshot only if there is at least one node bound.
 *
 * Input values:
 *	root		valid snapshot handle from di_init(3DEVINFO)
 *	drvr_name	name of driver to start node search
 *	wwn_list_ptr	ptr to ptr to WWN_list struct
 *
 *
 */
static int
devices_get_all(di_node_t root, char *drvr_name, char *minor_name,
	struct wwn_list_struct **wwn_list_ptr)
{
di_node_t node;
char *devfs_path;
char devicepath[MAXPATHLEN];
uchar_t *nwwn = NULL, *pwwn = NULL;
uchar_t node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
WWN_list *wwn_list, *l1, *l2;
int scsi_vhci = 0;
int err, devtype;

	if (root == DI_NODE_NIL || drvr_name == NULL ||
		wwn_list_ptr == NULL) {
		return (EINVAL);
	}

	wwn_list = *wwn_list_ptr = NULL;

	memset(port_wwn, 0, sizeof (port_wwn));
	memset(node_wwn, 0, sizeof (node_wwn));

	if (strcmp(drvr_name, SSD_DRVR_NAME) == 0) {
		devtype = DTYPE_DIRECT;
	} else if (strcmp(drvr_name, ST_DRVR_NAME) == 0) {
		devtype = DTYPE_SEQUENTIAL;
	} else {
		/*
		 * An unsupported driver name was passed in
		 */
		return (L_DRIVER_NOTSUPP);
	}

	/* point to first node which matches portdrvr */
	node = di_drv_first_node(drvr_name, root);
	if (node == DI_NODE_NIL) {
		return (L_NO_DEVICES_FOUND);
	}

	while (node != DI_NODE_NIL) {

	    if ((devfs_path = my_devfs_path(node)) != NULL) {

		/*
		 * Check for offline state
		 */
		if ((di_state(node) & DI_DEVICE_OFFLINE) == DI_DEVICE_OFFLINE) {
			my_devfs_path_free(devfs_path);
			node = di_drv_next_node(node);
			continue;
		}

		/*
		 * Only support st, ssd nodes
		 */
		if (!strstr(devfs_path, SLSH_DRV_NAME_SSD) &&
			!strstr(devfs_path, SLSH_DRV_NAME_ST)) {
			my_devfs_path_free(devfs_path);
			node = di_drv_next_node(node);
			continue;
		}

		devicepath[0] = '\0';

		/*
		 * form device path
		 */
		sprintf(devicepath, "%s%s", devfs_path, minor_name);

		if ((strstr(devicepath, SCSI_VHCI) == NULL)) {
			if ((err = get_wwn_data(node, &nwwn, &pwwn)) != 0) {
				my_devfs_path_free(devfs_path);
				return (err);
			} else {
				memcpy(node_wwn, nwwn, sizeof (node_wwn));
				memcpy(port_wwn, pwwn, sizeof (port_wwn));
			}
		} else {
			/*
			 * Clear values for SCSI VHCI devices.
			 * node wwn, port wwn are irrevelant at
			 * the SCSI VHCI level
			 */
			scsi_vhci++;
			memset(port_wwn, 0, sizeof (port_wwn));
			memset(node_wwn, 0, sizeof (node_wwn));
		}

		/* Got wwns, load data in list */
		if ((l2 = (struct  wwn_list_struct *)
			calloc(1, sizeof (struct  wwn_list_struct))) == NULL) {
			my_devfs_path_free(devfs_path);
			return (L_MALLOC_FAILED);
		}
		if ((l2->physical_path = (char *)
			calloc(1, strlen(devicepath) +1)) == NULL) {
			my_devfs_path_free(devfs_path);
			return (L_MALLOC_FAILED);
		}

		memcpy(l2->w_node_wwn, node_wwn, WWN_SIZE);

		if (scsi_vhci) {
		    strcpy(l2->node_wwn_s, MSGSTR(12000, "N/A"));
		} else {
		    copy_wwn_data_to_str(l2->node_wwn_s, node_wwn);
		    copy_wwn_data_to_str(l2->port_wwn_s, port_wwn);
		}

		strcpy(l2->physical_path, devicepath);

		l2->device_type = devtype;
		if (wwn_list == NULL) {
			l1 = wwn_list = l2;
		} else {
			l2->wwn_prev = l1;
			l1 = l1->wwn_next = l2;
		}
		my_devfs_path_free(devfs_path);
		scsi_vhci = 0;
	    }
	    node = di_drv_next_node(node);
	}

	*wwn_list_ptr = wwn_list; /* pass back ptr to list */

	if (*wwn_list_ptr == NULL) {
		return (L_NO_DEVICES_FOUND);
	} else {
		/*
		 * Now load the /dev/ paths
		 */
		if (strcmp(drvr_name, SSD_DRVR_NAME) == 0) {
			if ((err = get_dev_path(wwn_list_ptr, DEV_RDIR,
					DIR_MATCH_SSD)) != 0) {
				g_free_wwn_list(wwn_list_ptr);
				return (err);
			}
		} else if (strcmp(drvr_name, ST_DRVR_NAME) == 0) {
			if ((err = get_dev_path(wwn_list_ptr, DEV_TAPE_DIR,
					DIR_MATCH_ST)) != 0) {
				g_free_wwn_list(wwn_list_ptr);
				return (err);
			}
		}
		return (0);
	}
}


/*
 * Access the properties for the node to get the node-wwn, port-wwn property
 * On error, contents of nwwn, pwwn are unspecified.
 * On successful return nwwn and pwwn are WWN_SIZE bytes.
 */
static int
get_wwn_data(di_node_t node, uchar_t **nwwn, uchar_t **pwwn)
{
	if (di_prop_lookup_bytes(DDI_DEV_T_ANY, node, NODE_WWN_PROP,
			nwwn) != WWN_SIZE) {
	/* If we didn't get back the right count, return error */
		return (L_NO_WWN_PROP_FOUND);
	}
	if (di_prop_lookup_bytes(DDI_DEV_T_ANY, node, PORT_WWN_PROP,
			pwwn) != WWN_SIZE) {
	/* If we didn't get back the right count, return error */
		return (L_NO_WWN_PROP_FOUND);
	}
	return (0);
}

/*
 * Description
 *	retrieves the /dev logical path for a WWN_list of devices.
 * Input values
 *	wwn_list_ptr	ptr to list returned by devices_get_all
 *	dir_name	/dev/ directory to search
 *
 */
static int
get_dev_path(struct wwn_list_struct **wwn_list_ptr, char *dir_name,
	char *pattern_match)
{
DIR		*dirp;
struct dirent	*entp;
char		namebuf[MAXPATHLEN];
char		*result = NULL;
WWN_list	*wwn_list, *wwn_list_save;
char		*env;
hrtime_t	start_time, end_time;

	if (wwn_list_ptr == NULL || *wwn_list_ptr == NULL ||
		dir_name == NULL || pattern_match == NULL) {
		return (EINVAL);
	}

	if ((env = getenv("_LUX_T_DEBUG")) != NULL) {
		start_time = gethrtime();
	}

	wwn_list = *wwn_list_ptr;

	if ((dirp = opendir(dir_name)) == NULL) {
		P_DPRINTF("  get_dev_path: No devices found\n");
		return (L_NO_DEVICES_FOUND);
	}

	while ((entp = readdir(dirp)) != NULL) {
		/*
		 * Ignore current directory and parent directory
		 * entries.
		 */
		if ((strcmp(entp->d_name, ".") == 0) ||
		    (strcmp(entp->d_name, "..") == 0) ||
		    (fnmatch(pattern_match, entp->d_name, 0) != 0))
			continue;

		memset(namebuf, 0, sizeof (namebuf));
		sprintf(namebuf, "%s/%s", dir_name, entp->d_name);

		if ((result = g_get_physical_name_from_link(namebuf)) == NULL) {
			ER_DPRINTF("  Warning: Get physical name from"
				" link failed. Link=%s\n", namebuf);
			continue;
		}
		for (wwn_list = *wwn_list_ptr; wwn_list != NULL;
		    wwn_list = wwn_list->wwn_next) {
		    if (strcmp(wwn_list->physical_path, result) == 0) {
			/*
			 * Add information to the list.
			 */
			if ((wwn_list->logical_path = (char *)
				calloc(1, strlen(namebuf) + 1)) == NULL) {
				free(result);
				return (L_MALLOC_FAILED);
			}
			strcpy(wwn_list->logical_path, namebuf);
			break;
		    }
		}
		free(result);
	}
	closedir(dirp);

	/*
	 * Did we load all of the paths?
	 * Note: if there is a missing entry in /dev then
	 * the user probably did a cleanup of /dev.
	 * Whatever the case, remove the entry as it
	 * is invalid.
	 */
	wwn_list = *wwn_list_ptr;
	while (wwn_list != NULL) {
		if (wwn_list->logical_path == NULL) {
			free(wwn_list->physical_path);
			wwn_list_save = wwn_list;
			if (wwn_list->wwn_prev != NULL) {
				wwn_list->wwn_prev->wwn_next =
					wwn_list->wwn_next;
			} else {
				/*
				 * No previous entries
				 */
				*wwn_list_ptr = wwn_list->wwn_next;
			}
			if (wwn_list->wwn_next != NULL) {
				wwn_list->wwn_next->wwn_prev =
					wwn_list->wwn_prev;
			}
			wwn_list = wwn_list->wwn_next;
			free(wwn_list_save);
		} else {
			wwn_list = wwn_list->wwn_next;
		}
	}

	if (env != NULL) {
		end_time = gethrtime();
		fprintf(stdout,
		"      get_dev_path %s:  "
		"\t\tTime = %lld millisec\n",
		dir_name, (end_time - start_time)/1000000);
	}

	if (*wwn_list_ptr == NULL) {
		return (L_NO_DEVICES_FOUND);
	} else {
		return (0);
	}
}

/*
 * This functions calls di_devfs_path and gets the path associated with a
 * given devinfo node. If the path returned does not have a '@' in it, it
 * checks if the driver is detached and creates a path after looking at the
 * driver properties.
 *
 * di_devfs_path_free is called internally.
 *
 * The argument 'path' points to the final value upon return.
 * Caller must use my_devfs_path_free on returned char *
 * Note: Only support FC/SCSI_VHCI devices,
 *       for FC check for node-wwn prop
 *
 */
static char *
my_devfs_path(di_node_t node)
{
	uchar_t	*pwwn = NULL;
	char	pwwns[WWN_SIZE*2+1];
	char	*mypath;
	int	scsi_vhci = 0;
	char	*tptr = NULL, *lun_guid = NULL;
	int	*lunnump = NULL;

	/* sanity check */
	if (node == DI_NODE_NIL) {
		return (NULL);
	}

	/* Now go get the path for this node */
	if ((tptr = di_devfs_path(node)) == NULL) {
		return (NULL);
	}

	if ((mypath = (char *)calloc(1, MAXPATHLEN + 1)) == NULL) {
		di_devfs_path_free(tptr);
		return (NULL);
	}

	/* Prepend "/devices" to libdevinfo-returned paths */
	sprintf(mypath, "%s%s", DEVICES_DIR, tptr);

	di_devfs_path_free(tptr);


	/*
	 * Is this a FC device?
	 * Check the pwwn property
	 */
	if (strstr(mypath, SCSI_VHCI) == NULL) {
		if (di_prop_lookup_bytes(DDI_DEV_T_ANY, node, PORT_WWN_PROP,
				&pwwn) < 0) {
			/* Not a FC device. Free path and return */
			free(mypath);
			return (NULL);
		}
	} else {
		scsi_vhci++;
	}

	if ((tptr = strrchr(mypath, '/')) == NULL) {
		free(mypath);
		return (NULL);
	}

	if (strchr(tptr, '@') != NULL) {
		return (mypath);
	}

	/*
	 * No '@' in path. This can happen when driver is detached.
	 * We'll check if the state is detached and if it is, we'll construct
	 * the path by looking at the properties.
	 */

	if ((di_state(node) & DI_DRIVER_DETACHED) != DI_DRIVER_DETACHED) {
		/*
		 * Driver is not detached and no '@' in path.
		 * Can't handle it.
		 */
		free(mypath);
		return (NULL);
	}

	if (!scsi_vhci) {
		copy_wwn_data_to_str(pwwns, pwwn);
		di_prop_lookup_ints(DDI_DEV_T_ANY, node, LUN_PROP, &lunnump);
		sprintf(&mypath[strlen(mypath)], "@w%s,%x", pwwn, *lunnump);
	} else {
		di_prop_lookup_strings(DDI_DEV_T_ANY, node,
			LUN_GUID_PROP, &lun_guid);
		sprintf(&mypath[strlen(mypath)], "@g%s", lun_guid);
	}
	return (mypath);
}

static void
my_devfs_path_free(char *path)
{
	if (path != NULL) {
		free(path);
	}
}

/*
 * from_ptr: ptr to uchar_t array of size WWN_SIZE
 * to_ptr: char ptr to string of size WWN_SIZE*2+1
 */
static void
copy_wwn_data_to_str(char *to_ptr, const uchar_t *from_ptr)
{
	if ((to_ptr == NULL) || (from_ptr == NULL))
		return;

	sprintf(to_ptr, "%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
	from_ptr[0], from_ptr[1], from_ptr[2], from_ptr[3],
	from_ptr[4], from_ptr[5], from_ptr[6], from_ptr[7]);
}

/*
 * Open the requested directory and get one valid open.
 * If a device is busy, return.
 * Only need to open one device since
 * that implies there will be a node returned from
 * di_drv_first_node()
 * dir_name: logical device name directory
 *	(DEV_TAPE_DIR, DEV_RDIR)
 * pattern_match: used by fnmatch on directory entry
 *	(DIR_MATCH_SSD, DIR_MATCH_ST)
 * drvr_path: path type to verify ("/ssd@", "/st@")
 *	(SLSH_DRV_NAME_ST, SLSH_DRV_NAME_SSD)
 *
 * Returns: None
 */
static void
init_drv(char *dir_name, char *pattern_match, char *drvr_path)
{
DIR		*dirp;
struct dirent	*entp;
char		namebuf[MAXPATHLEN];
char		*result = NULL;
int		fd;

	if ((dirp = opendir(dir_name)) == NULL) {
		return;
	}

	while ((entp = readdir(dirp)) != NULL) {
		/*
		 * Ignore current directory and parent directory
		 * entries.
		 */
		if ((strcmp(entp->d_name, ".") == 0) ||
		    (strcmp(entp->d_name, "..") == 0) ||
		    (fnmatch(pattern_match, entp->d_name, 0) != 0)) {
			continue;
		}

		memset(namebuf, 0, sizeof (namebuf));
		sprintf(namebuf, "%s/%s", dir_name, entp->d_name);

		if ((result = g_get_physical_name_from_link(namebuf)) == NULL) {
			ER_DPRINTF("  Warning: Get physical name from"
				" link failed. Link=%s\n", namebuf);
			continue;
		}

		if (strstr(result, drvr_path) == NULL) {
			free(result);
			result = NULL;
			continue;
		}

		if ((fd = g_object_open(result, O_NDELAY | O_RDONLY)) != -1) {
			close(fd);
			break;
		} else if (errno != EBUSY) {
			free(result);
			result = NULL;
			continue;
		} else {
			break;
		}
	}
	free(result);
	closedir(dirp);
}
