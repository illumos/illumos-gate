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
 *  This file: 8000 - 8499
 *  Shared common messages: 1 - 1999
 */

/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/types.h>
#include	<sys/param.h>
#include	<fcntl.h>
#include	<unistd.h>
#include	<errno.h>
#include	<string.h>
#include	<sys/scsi/scsi.h>
#include	<nl_types.h>
#include	<strings.h>
#include	<sys/ddi.h>	/* for max */
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<a_state.h>
#include	<a5k.h>



/*	Defines		*/
#define	VERBPRINT	if (verbose) (void) printf


/*
 * take all paths supplied by dl offline.
 *
 * RETURNS:
 *	0 = No error.
 *	*bsy_res_flag_p: 1 = The device is "busy".
 *
 * In pre-2.6 we just return success
 */
static int
d_offline_drive(struct dlist *dl, int *bsy_res_flag_p, int verbose)
{
char			dev_path1[MAXPATHLEN];
devctl_hdl_t		devhdl;


	/* for each path attempt to take it offline */
	for (; dl != NULL; dl = dl->next) {

		/* save a copy of the pathname */
		(void) strcpy(dev_path1, dl->dev_path);

		/* attempt to acquire the device */
		if ((devhdl = devctl_device_acquire(dev_path1,
			DC_EXCL)) == NULL) {
			if (errno != EBUSY) {
				return (L_ACQUIRE_FAIL);
			}
		}

		/* attempt to offline the drive */
		if (devctl_device_offline(devhdl) != 0) {
			*bsy_res_flag_p = 1;
			(void) devctl_release(devhdl);
			return (0);
		}

		E_DPRINTF("  d_offline_drive: Offline succeeded:/n    "
			"%s\n", dev_path1);
		/* offline succeeded -- release handle acquired above */
		(void) devctl_release(devhdl);
	}
	return (0);
}




/*
 * Check to see if any of the disks that are attached
 * to the selected port on this backplane are reserved or busy.
 *
 * INPUTS:
 * RETURNS:
 *	0 = No error.
 *	*bsy_res_flag_p: 1 = The device is "busy".
 */

int
l_check_busy_reserv_bp(char *ses_path, int front_flag,
	int port_a_flag, int *bsy_res_flag_p, int verbose)
{
int	err, i;
L_state		*l_state = NULL;
struct dlist	*p_list;

	if ((l_state = (L_state *)calloc(1, sizeof (L_state))) == NULL) {
		return (L_MALLOC_FAILED);
	}

	if (err = l_get_status(ses_path, l_state, verbose)) {
		(void) l_free_lstate(&l_state);
		return (err);
	}
	for (i = 0; i < (int)l_state->total_num_drv/2; i++) {
		if ((front_flag &&
	(l_state->drv_front[i].g_disk_state.d_state_flags[port_a_flag] &
			L_RESERVED)) || (!front_flag &&
	(l_state->drv_rear[i].g_disk_state.d_state_flags[port_a_flag] &
			L_RESERVED))) {
			*bsy_res_flag_p = 1;
			(void) l_free_lstate(&l_state);
			return (0);
		}
	}

	for (i = 0; i < (int)l_state->total_num_drv/2; i++) {
		/* Get list of all paths to the requested port. */
		if (front_flag) {
			if (port_a_flag) {
				if ((err = g_get_port_multipath(
				l_state->drv_front[i].g_disk_state.port_a_wwn_s,
					&p_list, verbose)) != 0) {
					(void) l_free_lstate(&l_state);
					return (err);
				}
			} else {
				if ((err = g_get_port_multipath(
				l_state->drv_front[i].g_disk_state.port_b_wwn_s,
					&p_list, verbose)) != 0) {
					(void) l_free_lstate(&l_state);
					return (err);
				}
			}
		} else {
			if (port_a_flag) {
				if ((err = g_get_port_multipath(
				l_state->drv_rear[i].g_disk_state.port_a_wwn_s,
					&p_list, verbose)) != 0) {
					(void) l_free_lstate(&l_state);
					return (err);
				}
			} else {
				if ((err = g_get_port_multipath(
				l_state->drv_rear[i].g_disk_state.port_b_wwn_s,
					&p_list, verbose)) != 0) {
					(void) l_free_lstate(&l_state);
					return (err);
				}
			}
		}
		if (err = d_offline_drive(p_list,
			bsy_res_flag_p, verbose)) {
			(void) g_free_multipath(p_list);
			(void) l_free_lstate(&l_state);
			return (err);
		}
		(void) g_free_multipath(p_list);
	}
	(void) l_free_lstate(&l_state);
	return (0);
}



/*
 * Request the enclosure services controller (IB)
 * to set the LRC (Loop Redundancy Circuit) to the
 * bypassed/enabled state for the backplane specified by
 * the a and f flag and the enclosure or pathname.
 */
int
l_bp_bypass_enable(char *ses_path, int bypass_flag, int port_a_flag,
	int front_flag, int force_flag, int verbose)
{

int		fd, i;
int		nobj = 0;
ses_objarg	obj;
ses_object	*all_objp = NULL, *all_objp_save = NULL;
int		found = 0;
Bp_elem_st	*bp;
char		msg[MAXPATHLEN];
int		bsy_res_flag = 0;
int		err;

	if (ses_path == NULL) {
		return (L_NO_SES_PATH);
	}

	/*
	 * Check for reservation and busy for all disks on this
	 * backplane.
	 */

	if (!force_flag && bypass_flag) {
		if (err = l_check_busy_reserv_bp(ses_path,
			front_flag, port_a_flag, &bsy_res_flag, verbose)) {
			return (err);
		}
		if (bsy_res_flag) {
				return (L_BP_BUSY_RESERVED);
		}
	}


	if ((fd = g_object_open(ses_path, O_NDELAY | O_RDWR)) == -1) {
		return (errno);
	}

	if (ioctl(fd, SESIOC_GETNOBJ, (caddr_t)&nobj) < 0) {
		(void) close(fd);
		return (errno);
	}
	if (nobj == 0) {
		(void) close(fd);
		return (L_IB_NO_ELEM_FOUND);
	}

	E_DPRINTF("  l_ib_bypass_bp: Number of SES objects: 0x%x\n",
		nobj);

	/* alloc some memory for the objmap */
	if ((all_objp = g_zalloc((nobj + 1) * sizeof (ses_object))) == NULL) {
		(void) close(fd);
		return (errno);
	}

	all_objp_save = all_objp;

	if (ioctl(fd, SESIOC_GETOBJMAP, (caddr_t)all_objp) < 0) {
		(void) close(fd);
		(void) g_destroy_data(all_objp_save);
		return (errno);
	}

	for (i = 0; i < nobj; i++, all_objp++) {
			E_DPRINTF("  ID 0x%x\t Element type 0x%x\n",
			all_objp->obj_id, all_objp->elem_type);
		if (all_objp->elem_type == ELM_TYP_BP) {
			found++;
			break;
		}
	}

	if (found == 0) {
		(void) close(fd);
		(void) g_destroy_data(all_objp_save);
		return (L_NO_BP_ELEM_FOUND);
	}

	/*
	 * We found the backplane element.
	 */


	if (verbose) {
		/* Get the status for backplane #0 */
		obj.obj_id = all_objp->obj_id;
		if (ioctl(fd, SESIOC_GETOBJSTAT, (caddr_t)&obj) < 0) {
			(void) close(fd);
			(void) g_destroy_data(all_objp_save);
			return (errno);
		}
		(void) fprintf(stdout, MSGSTR(8000,
			"  Front backplane status: "));
		bp = (struct  bp_element_status *)&obj.cstat[0];
		l_element_msg_string(bp->code, msg);
		(void) fprintf(stdout, "%s\n", msg);
		if (bp->byp_a_enabled || bp->en_bypass_a) {
			(void) fprintf(stdout, "    ");
			(void) fprintf(stdout,
			MSGSTR(130, "Bypass A enabled"));
			(void) fprintf(stdout, ".\n");
		}
		if (bp->byp_b_enabled || bp->en_bypass_b) {
			(void) fprintf(stdout, "    ");
			(void) fprintf(stdout,
			MSGSTR(129, "Bypass B enabled"));
			(void) fprintf(stdout, ".\n");
		}

		all_objp++;
		obj.obj_id = all_objp->obj_id;
		all_objp--;
		if (ioctl(fd, SESIOC_GETOBJSTAT, (caddr_t)&obj) < 0) {
			(void) close(fd);
			(void) g_destroy_data(all_objp_save);
			return (errno);
		}
		(void) fprintf(stdout, MSGSTR(8001,
			"  Rear backplane status: "));
		bp = (struct  bp_element_status *)&obj.cstat[0];
		l_element_msg_string(bp->code, msg);
		(void) fprintf(stdout, "%s\n", msg);
		if (bp->byp_a_enabled || bp->en_bypass_a) {
			(void) fprintf(stdout, "    ");
			(void) fprintf(stdout,
			MSGSTR(130, "Bypass A enabled"));
			(void) fprintf(stdout, ".\n");
		}
		if (bp->byp_b_enabled || bp->en_bypass_b) {
			(void) fprintf(stdout, "    ");
			(void) fprintf(stdout,
			MSGSTR(129, "Bypass B enabled"));
			(void) fprintf(stdout, ".\n");
		}
	}

	/* Get the current status */
	if (!front_flag) {
		all_objp++;
	}
	obj.obj_id = all_objp->obj_id;
	if (ioctl(fd, SESIOC_GETOBJSTAT, (caddr_t)&obj) < 0) {
		(void) close(fd);
		(void) g_destroy_data(all_objp_save);
		return (errno);
	}
	/* Do the requested action. */
	bp = (struct  bp_element_status *)&obj.cstat[0];
	bp->select = 1;
	bp->code = 0;
	if (port_a_flag) {
		bp->en_bypass_a = bypass_flag;
	} else {
		bp->en_bypass_b = bypass_flag;
	}
	if (getenv("_LUX_E_DEBUG") != NULL) {
		(void) printf("  Sending this structure to ID 0x%x"
			" of type 0x%x\n",
			obj.obj_id, all_objp->elem_type);
		for (i = 0; i < 4; i++) {
			(void) printf("    Byte %d  0x%x\n", i,
			obj.cstat[i]);
		}
	}

	if (ioctl(fd, SESIOC_SETOBJSTAT, (caddr_t)&obj) < 0) {
		(void) close(fd);
		(void) g_destroy_data(all_objp_save);
		return (errno);
	}

	(void) g_destroy_data(all_objp_save);
	(void) close(fd);

	return (0);
}




/*
 * This function will request the enclosure services
 * controller (IB) to set the LRC (Loop Redundancy Circuit) to the
 * bypassed/enabled state for the device specified by the
 * enclosure,dev or pathname and the port specified by the a
 * flag.
 */

int
l_dev_bypass_enable(struct path_struct *path_struct, int bypass_flag,
	int force_flag, int port_a_flag, int verbose)
{
gfc_map_t		map;
char			ses_path[MAXPATHLEN];
uchar_t			*page_buf;
int 			err, fd, front_index, rear_index, offset;
int			pathcnt = 1;
unsigned short		page_len;
struct	device_element 	*elem;
L_state			*l_state = NULL;
struct device_element 	status;
int			bsy_flag = 0, i, f_flag;
struct dlist		*p_list;
char			temppath[MAXPATHLEN];
mp_pathlist_t		pathlist;
int			p_pw = 0, p_on = 0, p_st = 0;
L_inquiry		inq;

	if (path_struct == NULL) {
		return (L_INVALID_PATH_FORMAT);
	}

	if ((l_state = (L_state *)calloc(1, sizeof (L_state))) == NULL) {
		return (L_MALLOC_FAILED);
	}
	map.dev_addr = (gfc_port_dev_info_t *)NULL;
	(void) strcpy(temppath, path_struct->p_physical_path);
	if ((strstr(path_struct->p_physical_path, SCSI_VHCI) != NULL) &&
		(!g_get_pathlist(temppath, &pathlist))) {
			pathcnt = pathlist.path_count;
			p_pw = p_on = p_st = 0;
			for (i = 0; i < pathcnt; i++) {
				if (pathlist.path_info[i].path_state <
					MAXPATHSTATE) {
					if (strstr(pathlist.path_info[i].
						path_addr,
						path_struct->argv) != NULL) {
						p_pw = i;
						break;
					}
					if (pathlist.path_info[i].path_state ==
						MDI_PATHINFO_STATE_ONLINE) {
						p_on = i;
					}
					if (pathlist.path_info[i].path_state ==
						MDI_PATHINFO_STATE_STANDBY) {
						p_st = i;
					}
				}
			}
			if (strstr(pathlist.path_info[p_pw].path_addr,
				path_struct->argv) != NULL) {
				/* matching input pwwn */
				(void) strcpy(temppath,
					pathlist.path_info[p_pw].path_hba);
			} else if (pathlist.path_info[p_on].path_state ==
				MDI_PATHINFO_STATE_ONLINE) {
				/* on_line path */
				(void) strcpy(temppath,
					pathlist.path_info[p_on].path_hba);
			} else {
				/* standby or path0 */
				(void) strcpy(temppath,
					pathlist.path_info[p_st].path_hba);
			}
			free(pathlist.path_info);
			(void) strcat(temppath, FC_CTLR);
	}

	/*
	 * Need to get a valid location, front/rear & slot.
	 *
	 * The path_struct will return a valid slot
	 * and the IB path or a disk path.
	 */

	if (!path_struct->ib_path_flag) {
		if (err = g_get_dev_map(temppath, &map, verbose)) {
			(void) l_free_lstate(&l_state);
			return (err);
		}
		if (err = l_get_ses_path(path_struct->p_physical_path,
			ses_path, &map, verbose)) {
			(void) l_free_lstate(&l_state);
			free((void *)map.dev_addr);
			return (err);
		}
	} else {
		(void) strcpy(ses_path, path_struct->p_physical_path);
	}
	if (!path_struct->slot_valid) {
		if ((map.dev_addr == (gfc_port_dev_info_t *)NULL) &&
			((err = g_get_dev_map(temppath,
						&map, verbose)) != 0)) {
			(void) l_free_lstate(&l_state);
			return (err);
		}
		if ((err = l_get_ses_path(path_struct->p_physical_path,
			ses_path, &map, verbose)) != 0) {
			(void) l_free_lstate(&l_state);
			free((void *)map.dev_addr);
			return (err);
		}
		if ((err = l_get_status(ses_path, l_state, verbose)) != 0) {
			(void) l_free_lstate(&l_state);
			free((void *)map.dev_addr);
			return (err);
		}

		/* We are passing the disks path */
		if ((err = l_get_slot(path_struct, l_state, verbose)) != 0) {
			(void) l_free_lstate(&l_state);
			free((void *)map.dev_addr);
			return (err);
		}
	}

	if (map.dev_addr != (gfc_port_dev_info_t *)NULL) {
		free((void *)map.dev_addr);
	}

	if ((page_buf = (uchar_t *)malloc(MAX_REC_DIAG_LENGTH)) == NULL) {
		(void) l_free_lstate(&l_state);
		return (errno);
	}

	if ((fd = g_object_open(ses_path, O_NDELAY | O_RDWR)) == -1) {
		(void) g_destroy_data(page_buf);
		(void) l_free_lstate(&l_state);
		return (errno);
	}

	if (err = l_get_envsen_page(fd, page_buf, MAX_REC_DIAG_LENGTH,
				L_PAGE_2, verbose)) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		(void) l_free_lstate(&l_state);
		return (err);
	}

	page_len = (page_buf[2] << 8 | page_buf[3]) + HEADER_LEN;

	/* Get index to the disk we are interested in */
	if (err = l_get_status(ses_path, l_state, verbose)) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		(void) l_free_lstate(&l_state);
		return (err);
	}
	/*
	 * Now that we have the status check to see if
	 * busy or reserved, if bypassing.
	 */
	if ((!(force_flag | path_struct->ib_path_flag)) &&
						bypass_flag) {
		i = path_struct->slot;
		f_flag = path_struct->f_flag;

		/*
		 * Check for reservation and busy
		 */
		if ((f_flag &&
		(l_state->drv_front[i].g_disk_state.d_state_flags[port_a_flag] &
			L_RESERVED)) || (!f_flag &&
		(l_state->drv_rear[i].g_disk_state.d_state_flags[port_a_flag] &
			L_RESERVED))) {
			(void) close(fd);
			(void) g_destroy_data(page_buf);
			(void) l_free_lstate(&l_state);
			return (L_BP_RESERVED);
		}
		if (f_flag) {
			if (port_a_flag) {
				if ((err = g_get_port_multipath(
				l_state->drv_front[i].g_disk_state.port_a_wwn_s,
					&p_list, verbose)) != 0) {
					(void) close(fd);
					(void) g_destroy_data(page_buf);
					(void) l_free_lstate(&l_state);
					return (err);
				}
			} else {
				if ((err = g_get_port_multipath(
				l_state->drv_front[i].g_disk_state.port_b_wwn_s,
					&p_list, verbose)) != 0) {
					(void) close(fd);
					(void) g_destroy_data(page_buf);
					(void) l_free_lstate(&l_state);
					return (err);
				}
			}
		} else {
			if (port_a_flag) {
				if ((err = g_get_port_multipath(
				l_state->drv_rear[i].g_disk_state.port_a_wwn_s,
					&p_list, verbose)) != 0) {
					(void) close(fd);
					(void) g_destroy_data(page_buf);
					(void) l_free_lstate(&l_state);
					return (err);
				}
			} else {
				if ((err = g_get_port_multipath(
				l_state->drv_rear[i].g_disk_state.port_b_wwn_s,
					&p_list, verbose)) != 0) {
					(void) close(fd);
					(void) g_destroy_data(page_buf);
					(void) l_free_lstate(&l_state);
					return (err);
				}
			}
		}
		if (err = d_offline_drive(p_list,
			&bsy_flag, verbose)) {
			(void) g_free_multipath(p_list);
			(void) close(fd);
			(void) g_destroy_data(page_buf);
			(void) l_free_lstate(&l_state);
			return (err);
		}
		(void) g_free_multipath(p_list);
		if (bsy_flag) {
			(void) close(fd);
			(void) g_destroy_data(page_buf);
			(void) l_free_lstate(&l_state);
			return (L_BP_BUSY);
		}
	}

	if (err = l_get_disk_element_index(l_state, &front_index,
		&rear_index)) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		(void) l_free_lstate(&l_state);
		return (err);
	}

	if (g_get_inquiry(ses_path, &inq)) {
		return (L_SCSI_ERROR);
	}

	/* Skip global element */
	front_index++;
	if ((strncmp((char *)&inq.inq_pid[0], DAK_OFF_NAME,
						strlen(DAK_OFF_NAME)) == 0) ||
			(strncmp((char *)&inq.inq_pid[0], DAK_PROD_STR,
						strlen(DAK_PROD_STR)) == 0)) {
		rear_index += (MAX_DRIVES_DAK/2) + 1;
	} else {
		rear_index++;
	}

	if (path_struct->f_flag) {
		offset = (8 + (front_index + path_struct->slot)*4);
	} else {
		offset = (8 + (rear_index + path_struct->slot)*4);
	}

	elem = (struct device_element *)(page_buf + offset);
	/*
	 * now do requested action.
	 */
	bcopy((const void *)elem, (void *)&status,
		sizeof (struct device_element));	/* save status */
	bzero(elem, sizeof (struct device_element));
	elem->select = 1;
	elem->dev_off = status.dev_off;
	elem->en_bypass_a = status.en_bypass_a;
	elem->en_bypass_b = status.en_bypass_b;

	/* Do requested action */
	if (port_a_flag) {
		elem->en_bypass_a = bypass_flag;
	} else {
		elem->en_bypass_b = bypass_flag;
	}

	if (getenv("_LUX_E_DEBUG") != NULL) {
		g_dump("  l_dev_bypass_enable: Updating LRC circuit state:\n"
		"    Device Status Element ",
		(uchar_t *)elem, sizeof (struct device_element),
		HEX_ONLY);
		(void) fprintf(stdout, "    for device at location:"
			" enclosure:%s slot:%d %s\n",
			l_state->ib_tbl.enclosure_name,
			path_struct->slot,
			path_struct->f_flag ? "front" : "rear");
	}
	if (err = g_scsi_send_diag_cmd(fd,
		(uchar_t *)page_buf, page_len)) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		(void) l_free_lstate(&l_state);
		return (err);
	}

	(void) close(fd);
	(void) g_destroy_data(page_buf);
	(void) l_free_lstate(&l_state);
	return (0);
}



/*
 * Issue a Loop Port enable Primitive sequence
 * to the device specified by the pathname.
 */
int
d_p_enable(char *path, int verbose)
/*ARGSUSED*/
{

	return (0);
}

/*
 * Issue a Loop Port Bypass Primitive sequence
 * to the device specified by the pathname. This requests the
 * device to set its L_Port into the bypass mode.
 */
int
d_p_bypass(char *path, int verbose)
/*ARGSUSED*/
{

	return (0);
}
