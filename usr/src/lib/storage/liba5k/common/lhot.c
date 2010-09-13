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
 *	This module is part of the photon library
 */

/*
 * I18N message number ranges
 *  This file: 8500 - 8999
 *  Shared common messages: 1 - 1999
 */

/* #define		_POSIX_SOURCE 1 */

/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<sys/param.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<time.h>
#include	<sys/scsi/scsi.h>
#include	<sys/vtoc.h>
#include	<nl_types.h>
#include	<strings.h>
#include	<sys/ddi.h>		/* for max */
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<rom.h>
#include	<a_state.h>
#include	<a5k.h>


/*	Global variables	*/
extern	uchar_t		g_switch_to_alpa[];
extern	uchar_t		g_sf_alpa_to_switch[];


/*
 * This function checks if the passed char pointer has WWN_SIZE nulls (zeroes).
 *
 * This is only a convenience function.
 *
 * INPUT:
 * wwn_ptr -	pointer to a character string of length WWN_SIZE
 *		It is expected to be holding the WWN
 *		Ex: A WWN like 508002000000ddc1 is expected to be stored as
 *		the following 8 bytes -
 *		0x50, 0x80, 0x00, 0x20, ... etc
 *
 * RETURNS:
 * 0 - if there is atleast one of WWN_SIZE bytes is != '\0'
 * non-zero - if all WWN_SIZE bytes are '\0'
 */
int
is_null_wwn(uchar_t *wwn_ptr)
{
	int i;

	for (i = 0; i < WWN_SIZE; i++) {
		if (wwn_ptr[i] != '\0' || wwn_ptr[i] != '0')
			return (0);
	}
	return (1);
}


/*
 * This functions constructs a device path of the device/enclosure with the
 * given tid and, for public/fabric cases, on the same area and domain as
 * the given ses_path.
 *
 * INPUT:
 * ses_path	- pointer to the ses_path
 * tid		- tid of the device/enclosure whose path is to be constructed
 * map		- pointer to the map
 * dtype	- dtype of the device whose path is to be constructed
 *
 * OUTPUT:
 * dev_path	- pointer to the device path of type dtype and with tid
 *		- Caller has to free this after use
 *
 * RETURNS:
 * 0 - on success
 * non-zero - otherwise
 */
int
l_make_node(char *ses_path, int tid, char *dev_path,
			gfc_map_t *map, int dtype)
{
int			len, i, err;
int			this_pid, ses_pid;
char			ssd[40], wwn[20];
gfc_port_dev_info_t	*dev_addr_ptr;
struct stat		stat_buf;
WWN_list		*wwnlp, *wwn_list;
int			found = 0;

	if ((ses_path == NULL) || (dev_path == NULL) || (map == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	switch (map->hba_addr.port_topology) {
	case FC_TOP_PRIVATE_LOOP:
		for (i = 0, dev_addr_ptr = map->dev_addr;
			i < map->count; i++, dev_addr_ptr++) {
			if (dev_addr_ptr->gfc_port_dev.priv_port.
				sf_al_pa == g_switch_to_alpa[tid])
				break;
		}
		if (i >= map->count) {
			*dev_path = '\0';
			return (L_INVALID_LOOP_MAP);
		}

		/* Make sure that the port WWN is valid */
		if (is_null_wwn(dev_addr_ptr->gfc_port_dev.
			priv_port.sf_port_wwn)) {
			*dev_path = '\0';
			return (L_INVLD_WWN_FORMAT);
		}

		(void) g_ll_to_str(dev_addr_ptr->gfc_port_dev.
			priv_port.sf_port_wwn, wwn);

		if (strstr(ses_path, SCSI_VHCI) != NULL) {
			if (err = g_get_wwn_list(&wwn_list, 0)) {
				return (err);
			}
			for (wwnlp = wwn_list, found = 0;
				wwnlp != NULL;
				wwnlp = wwnlp->wwn_next) {
				if (strcmp(wwnlp->port_wwn_s,
					wwn) == 0) {
					found = 1;
					break;
				}
			}
			if (found) {
				(void) strcpy(dev_path,
					wwnlp->physical_path);
			} else {
				return (L_INVALID_PATH);
			}
		} else {

			len = strlen(ses_path) -
			strlen(strrchr(ses_path, '/'));

			if (dtype != DTYPE_ESI) {
				(void) sprintf(ssd,
					"/ssd@w%s,0:c", wwn);
			} else {
				(void) sprintf(ssd,
					"/ses@w%s,0:c", wwn);
			}

			/* TBD: Must find path, not just use :c */
			(void) strncpy(dev_path, ses_path, len);
			dev_path[len] = '\0';
			(void) strcat(dev_path, ssd);
		}
		break;
	case FC_TOP_FABRIC:
	case FC_TOP_PUBLIC_LOOP:
		/* First lets get the PA from the ses path passed in */
		if (err = l_get_pid_from_path(ses_path, map, &ses_pid)) {
			return (err);
		}

		/*
		 * Now we go through every entry in the map and match the
		 * area and domain ids with the PA of the passed ses path.
		 * If we find a match, we then match the low order byte
		 */
		for (i = 0, dev_addr_ptr = map->dev_addr; i < map->count;
							i++, dev_addr_ptr++) {
			this_pid = dev_addr_ptr->gfc_port_dev.pub_port.
								dev_did.port_id;
			if ((this_pid & AREA_DOMAIN_ID) ==
						(ses_pid & AREA_DOMAIN_ID)) {
			    if ((uchar_t)(this_pid & 0xFF) ==
							g_switch_to_alpa[tid])
				break;
			}
		}
		if (i >= map->count) {
			*dev_path = '\0';
			return (L_INVALID_LOOP_MAP);
		}
		/* Make sure that the port WWN is valid */
		if (is_null_wwn(dev_addr_ptr->gfc_port_dev.pub_port.
							dev_pwwn.raw_wwn)) {
			*dev_path = '\0';
			return (L_INVLD_WWN_FORMAT);
		}
		(void) g_ll_to_str(dev_addr_ptr->gfc_port_dev.
						pub_port.dev_pwwn.raw_wwn, wwn);



		if (strstr(ses_path, SCSI_VHCI) != NULL) {
			if (err = g_get_wwn_list(&wwn_list, 0)) {
				return (err);
			}
			for (wwnlp = wwn_list, found = 0; wwnlp != NULL;
				wwnlp = wwnlp->wwn_next) {
				if (strcmp(wwnlp->port_wwn_s,
					wwn) == 0) {
						found = 1;
				}
			}
			if (found) {
				(void) strcpy(dev_path,
					wwnlp->physical_path);
			} else {
				return (L_INVALID_PATH);
			}
		} else {
			len = strlen(ses_path) -
				strlen(strrchr(ses_path, '/'));

			if (dtype != DTYPE_ESI) {
				(void) sprintf(ssd, "/ssd@w%s,0:c", wwn);
			} else {
				(void) sprintf(ssd, "/ses@w%s,0:c", wwn);
			}

			/* TBD: Must find path, not just use :c */
			(void) strncpy(dev_path, ses_path, len);
			dev_path[len] = '\0';
			(void) strcat(dev_path, ssd);
		}

		if (stat(dev_path, &stat_buf) == -1) {
			return (errno);
		}

		break;
	case FC_TOP_PT_PT:
		return (L_PT_PT_FC_TOP_NOT_SUPPORTED);
	default:
		return (L_UNEXPECTED_FC_TOPOLOGY);
	}	/* End of switch on port_topology */
	return (0);
}



/*
 * checks for null wwn to a disk.
 * and returns -1 if found, 0
 * otherwise.
 *
 * OUTPUT:
 *	char	*ses_path
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
int
l_chk_null_wwn(Path_struct *path_struct, char *ses_path,
				L_state *l_state, int verbose)
{
char		*ptr, boxname[MAXPATHLEN];
char		node_wwn_s[WWN_SIZE * 2 + 1];
Box_list	*boxlist;


	if ((path_struct == NULL) || (ses_path == NULL) ||
	    (l_state == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	/*
	 * verify and continue only if the argv
	 * has a format like box,{f/r}<slot #>.
	 * Otherwise, return to the caller.
	 * The only way to address null wwn disk
	 * is using the box,{f/r}<slot#> format.
	 */
/* add support for new {f/r/s}<slot#> support for DPM */
	(void) strcpy(boxname, path_struct->argv);
	if (((ptr = strstr(boxname, ",")) != NULL) &&
	    ((*(ptr + 1) == 'f') || (*(ptr + 1) == 'r') ||
	    (*(ptr + 1) == 's'))) {
		*ptr = NULL;
	} else {
		return (0);
	}


	/*
	 * Get the list of enclosures
	 * connected to the system.
	 */
	if (l_get_box_list(&boxlist, verbose) != 0) {
		return (L_NO_ENCL_LIST_FOUND);
	}

	*ses_path = NULL;

	/*
	 * The following method is safer to get an ses path
	 * to the enclosure than calling l_get_ses_path(),
	 * with physical path to null WWN disk.
	 * Because, l_get_ses_path uses the disk's
	 * al_pa to get the box id and then ses path
	 * to the box. When a disk has null wwn, it may
	 * not have a valid al_pa, and hard address.
	 * There is a possibility that l_get_ses_path()
	 * not returning ses path to the correct enclosure.
	 */
	while (boxlist != NULL) {
		if ((strcmp(boxname, (char *)boxlist->b_name) == 0)) {
			(void) strcpy(ses_path, boxlist->b_physical_path);
			break;
		}
		boxlist = boxlist->box_next;
	}

	/* free the box list */
	(void) l_free_box_list(&boxlist);

	if ((ses_path != NULL) && (strstr(ses_path, "ses") != NULL)) {
		if (l_get_status(ses_path, l_state,
				verbose) != 0) {
			return (L_GET_STATUS_FAILED);
		}
		if (path_struct->f_flag) {
			(void) strcpy(node_wwn_s,
		l_state->drv_front[path_struct->slot].g_disk_state.node_wwn_s);
		} else {
			(void) strcpy(node_wwn_s,
		l_state->drv_rear[path_struct->slot].g_disk_state.node_wwn_s);
		}

		W_DPRINTF("Found ses path: %s\n"
			"and Node WWN: %s\n", ses_path, node_wwn_s);

		/* check for null WWN */
		if (is_null_wwn((uchar_t *)node_wwn_s) == 0) {
			return (0);	/* Non-null wwn */
		}
		W_DPRINTF("Found NULL WWN: %s\n", node_wwn_s);
		return (1);
	}

	return (0);

}



/*
 * If OVERALL_STATUS is sent as the "func",
 *	the code pointer must be valid (non NULL).
 * Otherwise NULL is a valid input for the code pointer.
 *
 * RETURNS:
 *	0	 if OK
 *	non-zero otherwise
 */
int
l_encl_status_page_funcs(int func, char *code, int todo, char *ses_path,
					struct l_state_struct  *l_state,
				int f_flag, int slot, int verbose_flag)
{
uchar_t	*page_buf;
int 	fd, front_index, rear_index, offset, err;
unsigned short	page_len;
struct	device_element *elem;

	if ((ses_path == NULL) || (l_state == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	if ((page_buf = (uchar_t *)g_zalloc(MAX_REC_DIAG_LENGTH)) == NULL) {
		return (L_MALLOC_FAILED);
	}

	if ((fd = g_object_open(ses_path, O_NDELAY | O_RDWR)) == -1) {
		(void) g_destroy_data(page_buf);
		return (L_OPEN_PATH_FAIL);
	}

	if ((err = l_get_envsen_page(fd, page_buf, MAX_REC_DIAG_LENGTH,
					L_PAGE_2, verbose_flag)) != 0) {
		(void) g_destroy_data(page_buf);
		(void) close(fd);
		return (err);
	}

	page_len = (page_buf[2] << 8 | page_buf[3]) + HEADER_LEN;

	if ((err = l_get_disk_element_index(l_state, &front_index,
							&rear_index)) != 0) {
		(void) g_destroy_data(page_buf);
		(void) close(fd);
		return (err);
	}
	/* Skip global element */
	front_index++;
	if ((strncmp((char *)l_state->ib_tbl.config.prod_id, DAK_OFF_NAME,
						strlen(DAK_OFF_NAME)) == 0) ||
		(strncmp((char *)l_state->ib_tbl.config.prod_id, DAK_PROD_STR,
						strlen(DAK_OFF_NAME)) == 0)) {
		rear_index += l_state->total_num_drv/2 + 1;
	} else
		rear_index++;

	if (f_flag) {
		offset = (8 + (front_index + slot)*4);
	} else {
		offset = (8 + (rear_index  + slot)*4);
	}

	elem = (struct device_element *)(page_buf + offset);

	switch (func) {
		case OVERALL_STATUS:
		    if (code == NULL) {
			return (L_INVALID_ARG);
		    }
		    switch (todo) {
			case INSERT_DEVICE:
				*code = (elem->code != S_OK) ? elem->code : 0;
				(void) g_destroy_data(page_buf);
				(void) close(fd);
				return (0);
			case REMOVE_DEVICE:
				*code = (elem->code != S_NOT_INSTALLED) ?
					elem->code : 0;
				(void) g_destroy_data(page_buf);
				(void) close(fd);
				return (0);
		    }
		    /* NOTREACHED */
		case SET_RQST_INSRT:
			bzero(elem, sizeof (struct device_element));
			elem->select = 1;
			elem->rdy_to_ins = 1;
			break;
		case SET_RQST_RMV:
			bzero(elem, sizeof (struct device_element));
			elem->select = 1;
			elem->rmv = 1;
			elem->dev_off = 1;
			elem->en_bypass_a = 1;
			elem->en_bypass_b = 1;
			break;
		case SET_FAULT:
			bzero(elem, sizeof (struct device_element));
			elem->select = 1;
			elem->fault_req = 1;
			elem->dev_off = 1;
			elem->en_bypass_a = 1;
			elem->en_bypass_b = 1;
			break;
		case SET_DRV_ON:
			bzero(elem, sizeof (struct device_element));
			elem->select = 1;
			break;
	}

	err = g_scsi_send_diag_cmd(fd, (uchar_t *)page_buf, page_len);
	(void) g_destroy_data(page_buf);
	(void) close(fd);
	return (err);
}



/*
 * Finds whether device id (tid) exists in the
 * Arbitrated loop map or not.
 *
 * INPUT:
 * ses_path	- pointer to a ses path
 * tid		- the target id of the device we want to check on
 *		- only the low order 8 bits has the tid
 * map		- pointer to a map of the system
 * verbose_flag - self explanatory
 *
 * OUTPUT:
 * dev_path	- the device path of the device with "tid".
 *                Caller is responsible for freeing it
 *
 * RETURNS:
 *	1	 if device present
 *	0	 otherwise
 */
int
l_device_present(char *ses_path, int tid, gfc_map_t *map,
				int verbose_flag, char **dev_path)
{
char			sf_path[MAXPATHLEN];
uchar_t			wwn[40], c;
int			len, i, j, k, fnib, snib, this_pid;
int			fd, ses_pid, al_pa, err;
char			ssd[30];
gfc_port_dev_info_t	*dev_addr_ptr;
WWN_list		*wwnlp, *wwn_list;


	if (dev_path == NULL)
		return (0);

	if ((ses_path == NULL) || (map == NULL)) {
		return (L_NO_SES_PATH);
	}

	*dev_path = NULL;

	switch (map->hba_addr.port_topology) {
	case FC_TOP_PRIVATE_LOOP:
		for (i = 0, dev_addr_ptr = map->dev_addr; i < map->count;
						i++, dev_addr_ptr++) {
			if (dev_addr_ptr->gfc_port_dev.
				priv_port.sf_inq_dtype != DTYPE_ESI) {
				al_pa = dev_addr_ptr->gfc_port_dev.
						priv_port.sf_al_pa;
				if (tid == g_sf_alpa_to_switch[al_pa]) {
					break;
				}
			}
		}
		if (i >= map->count)
			return (0);
		/*
		 * Make sure that the port WWN is valid
		 */
		if (is_null_wwn(dev_addr_ptr->gfc_port_dev.
						priv_port.sf_port_wwn)) {
			return (0);
		}
		for (j = 0, k = 0; j < WWN_SIZE; j++) {
			c = dev_addr_ptr->gfc_port_dev.priv_port.sf_port_wwn[j];
			fnib = (((int)(c & 0xf0)) >> 4);
			snib = (c & 0x0f);
			if (fnib >= 0 && fnib <= 9)
				wwn[k++] = '0' + fnib;
			else if (fnib >= 10 && fnib <= 15)
				wwn[k++] = 'a' + fnib - 10;
			if (snib >= 0 && snib <= 9)
				wwn[k++] = '0' + snib;
			else if (snib >= 10 && snib <= 15)
				wwn[k++] = 'a' + snib - 10;
		}
		wwn[k] = '\0';
		break;
	case FC_TOP_PUBLIC_LOOP:
	case FC_TOP_FABRIC:
		/*
		 * Get the phys address (port id) of this ses device
		 */
		if (err = l_get_pid_from_path(ses_path, map, &ses_pid))
			return (err);

		for (i = 0, dev_addr_ptr = map->dev_addr; i < map->count;
							i++, dev_addr_ptr++) {
			if (dev_addr_ptr->gfc_port_dev.pub_port.dev_dtype !=
								DTYPE_ESI) {
				/*
				 * We have a device. First match the area and
				 * domain ids and if they match, then see if
				 * the 8bit tid matches the last 8 bits of
				 * 'this_pid'
				 */
				this_pid = dev_addr_ptr->gfc_port_dev.
						pub_port.dev_did.port_id;
				if ((this_pid & AREA_DOMAIN_ID) ==
						(ses_pid & AREA_DOMAIN_ID)) {
					if (tid == g_sf_alpa_to_switch[
							this_pid & 0xFF])
						break;
				}
			}
		}

		if (i >= map->count)
			return (0);
		/*
		 * Make sure that the port WWN is valid
		 */
		if (is_null_wwn(dev_addr_ptr->gfc_port_dev.
						pub_port.dev_pwwn.raw_wwn)) {
			return (0);
		}
		for (j = 0, k = 0; j < WWN_SIZE; j++) {
			c = dev_addr_ptr->gfc_port_dev.pub_port.
							dev_pwwn.raw_wwn[j];
			fnib = (((int)(c & 0xf0)) >> 4);
			snib = (c & 0x0f);
			if (fnib >= 0 && fnib <= 9)
				wwn[k++] = '0' + fnib;
			else if (fnib >= 10 && fnib <= 15)
				wwn[k++] = 'a' + fnib - 10;
			if (snib >= 0 && snib <= 9)
				wwn[k++] = '0' + snib;
			else if (snib >= 10 && snib <= 15)
				wwn[k++] = 'a' + snib - 10;
		}
		wwn[k] = '\0';
		break;
	case FC_TOP_PT_PT:
		return (L_PT_PT_FC_TOP_NOT_SUPPORTED);
	default:
		return (L_UNEXPECTED_FC_TOPOLOGY);
	}	/* End of switch on port_topology */

	if (strstr(ses_path, SCSI_VHCI) != NULL) {
		if (err = g_get_wwn_list(&wwn_list, 0)) {
			return (err);
		}
		for (wwnlp = wwn_list; wwnlp != NULL;
						wwnlp = wwnlp->wwn_next) {
			if (memcmp(wwnlp->port_wwn_s, wwn, WWN_S_LEN) == 0) {
				break;
			}
		}
		if (wwnlp != NULL) {
			if ((*dev_path = g_zalloc(MAXPATHLEN)) == NULL) {
				g_free_wwn_list(&wwn_list);
				return (L_MALLOC_FAILED);
			}
			(void) strcpy(*dev_path, wwnlp->physical_path);
		} else {
			g_free_wwn_list(&wwn_list);
			return (0);
		}
	} else {

		len = strlen(ses_path) - strlen(strrchr(ses_path, '/'));

		(void) sprintf(ssd, "ssd@w%s,0", wwn);

		(void) strncpy(sf_path, ses_path, len);
		sf_path[len] = '\0';
		P_DPRINTF("  l_device_present: wwn=%s, sf_path=%s\n",
			wwn, sf_path);

		if ((*dev_path = g_zalloc(MAXPATHLEN)) == NULL) {
			return (L_MALLOC_FAILED);
		}
		(void) sprintf(*dev_path, "%s/%s", sf_path, ssd);
		P_DPRINTF("  l_device_present: dev_path=%s\n", *dev_path);

		(void) strcat(*dev_path, ":c");
	}
	if ((fd = open(*dev_path, O_RDONLY)) == -1) {
		free(*dev_path);
		*dev_path = NULL;
		return (0);
	}
	(void) close(fd);
	return (1);
}



/*
 * onlines the given list of devices
 * and free up the allocated memory.
 *
 * RETURNS:
 *	N/A
 */
static void
online_dev(struct dlist *dl_head, int force_flag)
{
struct dlist	*dl, *dl1;

	for (dl = dl_head; dl != NULL; ) {
		(void) g_online_drive(dl->multipath, force_flag);
		(void) g_free_multipath(dl->multipath);
		dl1 = dl;
		dl = dl->next;
		(void) g_destroy_data(dl1);
	}
}



/*
 * offlines all the disks in a
 * SENA enclosure.
 *
 * RETURNS:
 *	0	 if O.K.
 *	non-zero otherwise
 */
int
l_offline_photon(struct hotplug_disk_list *hotplug_sena,
				struct wwn_list_struct *wwn_list,
				int force_flag, int verbose_flag)
{
int		i, err;
struct dlist	*dl_head, *dl_tail, *dl, *dl_ses;
char		*dev_path, ses_path[MAXPATHLEN];
L_state		*l_state = NULL;

	if (hotplug_sena == NULL) {
		return (L_INVALID_PATH_FORMAT);
	}

	dl_head = dl_tail = NULL;
	if ((l_state = (L_state *)calloc(1, sizeof (L_state))) == NULL) {
		return (L_MALLOC_FAILED);
	}

	/* Get global status for this Photon */
	dl_ses = hotplug_sena->seslist;
	while (dl_ses) {
		(void) strcpy(ses_path, dl_ses->dev_path);
		if (l_get_status(ses_path, l_state, verbose_flag) == 0)
			break;
		dl_ses = dl_ses->next;
	}

	if (dl_ses == NULL) {
		(void) l_free_lstate(&l_state);
		return (L_ENCL_INVALID_PATH);
	}

	for (i = 0; i < l_state->total_num_drv/2; i++) {
		if (*l_state->drv_front[i].g_disk_state.physical_path) {
			if ((dev_path = g_zalloc(MAXPATHLEN)) == NULL) {
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (L_MALLOC_FAILED);
			}
			(void) strcpy(dev_path,
		(char *)&l_state->drv_front[i].g_disk_state.physical_path);
			if ((dl = g_zalloc(sizeof (struct dlist))) == NULL) {
				(void) g_destroy_data(dev_path);
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (L_MALLOC_FAILED);
			}
			dl->dev_path = dev_path;
			if ((err = g_get_multipath(dev_path,
					&(dl->multipath), wwn_list,  0)) != 0) {
				(void) g_destroy_data(dev_path);
				if (dl->multipath != NULL) {
					(void) g_free_multipath(dl->multipath);
				}
				(void) g_destroy_data(dl);
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (err);
			}
			if ((err = g_offline_drive(dl->multipath,
					force_flag)) != 0) {
				(void) g_destroy_data(dev_path);
				(void) g_free_multipath(dl->multipath);
				(void) g_destroy_data(dl);
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (err);
			}
			if (dl_head == NULL) {
				dl_head = dl_tail = dl;
			} else {
				dl_tail->next = dl;
				dl->prev = dl_tail;
				dl_tail = dl;
			}
			(void) g_destroy_data(dev_path);
		}
		if (*l_state->drv_rear[i].g_disk_state.physical_path) {
			if ((dev_path = g_zalloc(MAXPATHLEN)) == NULL) {
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (L_MALLOC_FAILED);
			}
			(void) strcpy(dev_path,
		(char *)&l_state->drv_rear[i].g_disk_state.physical_path);
			if ((dl = g_zalloc(sizeof (struct dlist))) == NULL) {
				(void) g_destroy_data(dev_path);
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (L_MALLOC_FAILED);
			}
			dl->dev_path = dev_path;
			if ((err = g_get_multipath(dev_path,
					&(dl->multipath), wwn_list, 0)) != 0) {
				(void) g_destroy_data(dev_path);
				if (dl->multipath != NULL) {
					(void) g_free_multipath(dl->multipath);
				}
				(void) g_destroy_data(dl);
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (err);
			}
			if ((err = g_offline_drive(dl->multipath,
				force_flag)) != 0) {
				(void) g_destroy_data(dev_path);
				(void) g_free_multipath(dl->multipath);
				(void) g_destroy_data(dl);
				(void) online_dev(dl_head, force_flag);
				(void) l_free_lstate(&l_state);
				return (err);
			}
			if (dl_head == NULL) {
				dl_head = dl_tail = dl;
			} else {
				dl_tail->next = dl;
				dl->prev = dl_tail;
				dl_tail = dl;
			}
			(void) g_destroy_data(dev_path);
		}
	}
	hotplug_sena->dlhead = dl_head;
	(void) l_free_lstate(&l_state);
	return (0);

}



/*
 * prepares a char string
 * containing the name of the
 * device which will be hotplugged.
 *
 * RETURNS:
 *	N/A
 */
void
l_get_drive_name(char *drive_name, int slot, int f_flag, char *box_name)
{
int	    enc_type = 0;
L_inquiry   inq;
char	    *physpath;
Path_struct *p_pathstruct;

	if ((drive_name == NULL) || (box_name == NULL)) {
		return;
	}

	if (!l_convert_name(box_name, &physpath, &p_pathstruct, 0)) {
	    if (!g_get_inquiry(physpath, &inq)) {
		enc_type = l_get_enc_type(inq);
	    }
	}
	/* If either of the above fail, we use the default value of 0 */
	free(physpath);
	free(p_pathstruct);
	switch (enc_type) {
	case DAK_ENC_TYPE:
	    if (f_flag != NULL) {
		(void) sprintf(drive_name, MSGSTR(8502,
			"Drive in \"%s\" slot %d"), box_name, slot);
	    } else {
		(void) sprintf(drive_name, MSGSTR(8502,
			"Drive in \"%s\" slot %d"), box_name,
			slot + (MAX_DRIVES_DAK/2));
	    }
	    break;
	default:
	    if (f_flag != NULL) {
		(void) sprintf(drive_name, MSGSTR(8500,
		    "Drive in \"%s\" front slot %d"), box_name, slot);
	    } else {
		(void) sprintf(drive_name, MSGSTR(8501,
		    "Drive in \"%s\" rear slot %d"), box_name, slot);
	    }
	    break;
	}
}
