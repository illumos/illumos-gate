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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */


/*LINTLIBRARY*/

/*
 * I18N message number ranges
 *  This file: 9000 - 9499
 *  Shared common messages: 1 - 1999
 */

/*
 *	This module is part of the photon library
 */
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
#include	<assert.h>
#include	<sys/scsi/scsi.h>
#include	<dirent.h>		/* for DIR */
#include	<sys/vtoc.h>
#include	<sys/dkio.h>
#include	<nl_types.h>
#include	<strings.h>
#include	<sys/ddi.h>		/* for max */
#include	<l_common.h>
#include	<stgcom.h>
#include	<l_error.h>
#include	<rom.h>
#include	<exec.h>
#include	<a_state.h>
#include	<a5k.h>


/*	Defines 	*/
#define	PLNDEF		"SUNW,pln"	/* check if box name starts with 'c' */
#define	DOWNLOAD_RETRIES	60*5	/* 5 minutes */
#define	IBFIRMWARE_FILE		"/usr/lib/locale/C/LC_MESSAGES/ibfirmware"

/*	Global variables	*/
extern	uchar_t		g_switch_to_alpa[];
extern	uchar_t		g_sf_alpa_to_switch[];

/*	Forward declarations	*/
static	int pwr_up_down(char *, L_state *, int, int, int, int);
static	int load_flds_if_enc_disk(char *, struct path_struct **);
static	int copy_config_page(struct l_state_struct *, uchar_t *);
static	void copy_page_7(struct l_state_struct *, uchar_t *);
static	int l_get_node_status(char *, struct l_disk_state_struct *,
	int *, WWN_list *, int);
static	int check_file(int, int, uchar_t **, int);
static	int check_dpm_file(int);
static	int ib_download_code_cmd(int, int, int, uchar_t *, int, int);
static	int dak_download_code_cmd(int, uchar_t *, int);
static	void free_mp_dev_map(struct gfc_map_mp **);
static	int get_mp_dev_map(char *, struct gfc_map_mp **, int);

/*
 * l_get_mode_pg() - Read all mode pages.
 *
 * RETURNS:
 *	0        O.K.
 *	non-zero otherwise
 *
 * INPUTS:
 *	path     pointer to device path
 *	pg_buf   ptr to mode pages
 *
 */
/*ARGSUSED*/
int
l_get_mode_pg(char *path, uchar_t **pg_buf, int verbose)
{
Mode_header_10	*mode_header_ptr;
int		status, size, fd;

	P_DPRINTF("  l_get_mode_pg: Reading Mode Sense pages.\n");

	/* do not do mode sense if this is a tape device */
	/* mode sense will rewind the tape */
	if (strstr(path, SLSH_DRV_NAME_ST)) {
		return (-1);
	}

	/* open controller */
	if ((fd = g_object_open(path, O_NDELAY | O_RDWR)) == -1)
		return (L_OPEN_PATH_FAIL);

	/*
	 * Read the first part of the page to get the page size
	 */
	size = 20;
	if ((*pg_buf = (uchar_t *)g_zalloc(size)) == NULL) {
	    (void) close(fd);
	    return (L_MALLOC_FAILED);
	}
	/* read page */
	if (status = g_scsi_mode_sense_cmd(fd, *pg_buf, size,
	    0, MODEPAGE_ALLPAGES)) {
	    (void) close(fd);
	    (void) g_destroy_data((char *)*pg_buf);
	    return (status);
	}
	/* Now get the size for all pages */
	mode_header_ptr = (struct mode_header_10_struct *)(void *)*pg_buf;
	size = mode_header_ptr->length + sizeof (mode_header_ptr->length);
	(void) g_destroy_data((char *)*pg_buf);
	if ((*pg_buf = (uchar_t *)g_zalloc(size)) == NULL) {
	    (void) close(fd);
	    return (L_MALLOC_FAILED);
	}
	/* read all pages */
	if (status = g_scsi_mode_sense_cmd(fd, *pg_buf, size,
					0, MODEPAGE_ALLPAGES)) {
	    (void) close(fd);
	    (void) g_destroy_data((char *)*pg_buf);
	    return (status);
	}
	(void) close(fd);
	return (0);
}



/*
 * Format QLA21xx status
 *
 * INPUTS: message buffer
 *         Count
 *         status
 *
 * OUTPUT: Message of this format in message buffer
 *         "status type:            0xstatus        count"
 */
int
l_format_ifp_status_msg(char *status_msg_buf, int count, int status)
{
	if (status_msg_buf == NULL) {
		return (0);
	}

	switch (status) {
	case IFP_CMD_CMPLT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9000, "O.K.                          0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_INCOMPLETE:
		(void) sprintf(status_msg_buf,
			MSGSTR(9001, "Cmd incomplete                0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_DMA_DERR:
		(void) sprintf(status_msg_buf,
			MSGSTR(9002, "DMA direction error           0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_TRAN_ERR:
		(void) sprintf(status_msg_buf,
			MSGSTR(9003, "Unspecified transport error   0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_RESET:
		(void) sprintf(status_msg_buf,
			MSGSTR(9004, "Reset aborted transport       0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_ABORTED:
		(void) sprintf(status_msg_buf,
			MSGSTR(9005, "Cmd aborted                   0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_TIMEOUT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9006, "Cmd Timeout                   0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_DATA_OVR:
		(void) sprintf(status_msg_buf,
			MSGSTR(9007, "Data Overrun                  0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_ABORT_REJECTED:
		(void) sprintf(status_msg_buf,
			MSGSTR(9008, "Target rejected abort msg     0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_RESET_REJECTED:
		(void) sprintf(status_msg_buf,
			MSGSTR(9009, "Target rejected reset msg     0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_DATA_UNDER:
		(void) sprintf(status_msg_buf,
			MSGSTR(9010, "Data underrun                 0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_QUEUE_FULL:
		(void) sprintf(status_msg_buf,
			MSGSTR(9011, "Queue full SCSI status        0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_PORT_UNAVAIL:
		(void) sprintf(status_msg_buf,
			MSGSTR(9012, "Port unavailable              0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_PORT_LOGGED_OUT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9013, "Port loged out                0x%-2x"
			"            %d"), status, count);
		break;
	case IFP_CMD_PORT_CONFIG_CHANGED:
		/* Not enough packets for given request */
		(void) sprintf(status_msg_buf,
			MSGSTR(9014, "Port name changed             0x%-2x"
			"            %d"), status, count);
		break;
	default:
		(void) sprintf(status_msg_buf,
			"%s                0x%-2x"
			"            %d", MSGSTR(4, "Unknown status"),
			status, count);

	} /* End of switch() */

	return (0);

}



/*
 * Format Fibre Channel status
 *
 * INPUTS: message buffer
 *         Count
 *         status
 *
 * OUTPUT: Message of this format in message buffer
 *         "status type:            0xstatus        count"
 */
int
l_format_fc_status_msg(char *status_msg_buf, int count, int status)
{
	if (status_msg_buf == NULL) {
		return (0);
	}

	switch (status) {
	case FCAL_STATUS_OK:
		(void) sprintf(status_msg_buf,
			MSGSTR(9015, "O.K.                          0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_P_RJT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9016, "P_RJT (Frame Rejected)        0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_F_RJT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9017, "F_RJT (Frame Rejected)        0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_P_BSY:
		(void) sprintf(status_msg_buf,
			MSGSTR(9018, "P_BSY (Port Busy)             0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_F_BSY:
		(void) sprintf(status_msg_buf,
			MSGSTR(9019, "F_BSY (Port Busy)             0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_OLDPORT_ONLINE:
		/* Should not happen. */
		(void) sprintf(status_msg_buf,
			MSGSTR(9020, "Old port Online               0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_ERR_OFFLINE:
		(void) sprintf(status_msg_buf,
			MSGSTR(9021, "Link Offline                  0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_TIMEOUT:
		/* Should not happen. */
		(void) sprintf(status_msg_buf,
			MSGSTR(9022, "Sequence Timeout              0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_ERR_OVERRUN:
		(void) sprintf(status_msg_buf,
			MSGSTR(9023, "Sequence Payload Overrun      0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_LOOP_ONLINE:
		(void) sprintf(status_msg_buf,
			MSGSTR(9060, "Loop Online                   0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_OLD_PORT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9061, "Old port                      0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_AL_PORT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9062, "AL port                       0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_UNKNOWN_CQ_TYPE:
		(void) sprintf(status_msg_buf,
			MSGSTR(9024, "Unknown request type          0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_BAD_SEG_CNT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9025, "Bad segment count             0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_MAX_XCHG_EXCEEDED:
		(void) sprintf(status_msg_buf,
			MSGSTR(9026, "Maximum exchanges exceeded    0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_BAD_XID:
		(void) sprintf(status_msg_buf,
			MSGSTR(9027, "Bad exchange identifier       0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_XCHG_BUSY:
		(void) sprintf(status_msg_buf,
			MSGSTR(9028, "Duplicate exchange request    0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_BAD_POOL_ID:
		(void) sprintf(status_msg_buf,
			MSGSTR(9029, "Bad memory pool ID            0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_INSUFFICIENT_CQES:
		/* Not enough packets for given request */
		(void) sprintf(status_msg_buf,
			MSGSTR(9030, "Invalid # of segments for req 0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_ALLOC_FAIL:
		(void) sprintf(status_msg_buf,
			MSGSTR(9031, "Resource allocation failure   0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_BAD_SID:
		(void) sprintf(status_msg_buf,
			MSGSTR(9032, "Bad Source Identifier(S_ID)   0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_NO_SEQ_INIT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9033, "No sequence initiative        0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_BAD_DID:
		(void) sprintf(status_msg_buf,
			MSGSTR(9034, "Bad Destination ID(D_ID)      0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_ABORTED:
		(void) sprintf(status_msg_buf,
			MSGSTR(9035, "Received BA_ACC from abort    0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_ABORT_FAILED:
		(void) sprintf(status_msg_buf,
			MSGSTR(9036, "Received BA_RJT from abort    0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_DIAG_BUSY:
		(void) sprintf(status_msg_buf,
			MSGSTR(9037, "Diagnostics currently busy    0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_DIAG_INVALID:
		(void) sprintf(status_msg_buf,
			MSGSTR(9038, "Diagnostics illegal request   0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_INCOMPLETE_DMA_ERR:
		(void) sprintf(status_msg_buf,
			MSGSTR(9039, "SBus DMA did not complete     0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_CRC_ERR:
		(void) sprintf(status_msg_buf,
			MSGSTR(9040, "CRC error detected            0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_OPEN_FAIL:
		(void) sprintf(status_msg_buf,
			MSGSTR(9063, "Open failure                  0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_ERROR:
		(void) sprintf(status_msg_buf,
			MSGSTR(9041, "Invalid status error          0x%-2x"
			"            %d"), status, count);
		break;
	case FCAL_STATUS_ONLINE_TIMEOUT:
		(void) sprintf(status_msg_buf,
			MSGSTR(9042, "Timed out before ONLINE       0x%-2x"
			"            %d"), status, count);
		break;
	default:
		(void) sprintf(status_msg_buf,
			"%s                0x%-2x"
			"            %d", MSGSTR(4, "Unknown status"),
			status, count);

	} /* End of switch() */

	return (0);

}



/*
 * Get the indexes to the disk device elements in page 2,
 * based on the locations found in page 1.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_disk_element_index(struct l_state_struct *l_state, int *front_index,
						int *rear_index)
{
int	index = 0, front_flag = 0, local_front = 0, local_rear = 0;
int	i, rear_flag = 0;

	if ((l_state == NULL) || (front_index == NULL) ||
	    (rear_index == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	*front_index = *rear_index = 0;
	/* Get the indexes to the disk device elements */
	for (i = 0; i < (int)l_state->ib_tbl.config.enc_num_elem; i++) {
		if (l_state->ib_tbl.config.type_hdr[i].type == ELM_TYP_DD) {
			if (front_flag) {
				local_rear = index;
				rear_flag = 1;
				break;
			} else {
				local_front = index;
				front_flag = 1;
			}
		}
		index += l_state->ib_tbl.config.type_hdr[i].num;
		index++;		/* for global element */
	}

	D_DPRINTF("  l_get_disk_element_index:"
		" Index to front disk elements 0x%x\n"
		"  l_get_disk_element_index:"
		" Index to rear disk elements 0x%x\n",
		local_front, local_rear);

	if (!front_flag && !rear_flag) {    /* neither is found */
		return (L_RD_NO_DISK_ELEM);
	}
	*front_index = local_front;
	*rear_index = local_rear;
	return (0);
}



/*
 * l_led() manage the device led's
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_led(struct path_struct *path_struct, int led_action,
	struct device_element *status,
	int verbose)
{
gfc_map_t		map;
char			ses_path[MAXPATHLEN];
uchar_t			*page_buf;
int 			err, write, fd, front_index, rear_index, offset;
unsigned short		page_len;
struct	device_element 	*elem;
L_state			*l_state;
int			enc_type;

	if ((path_struct == NULL) || (status == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	/*
	 * Need to get a valid location, front/rear & slot.
	 *
	 * The path_struct will return a valid slot
	 * and the IB path or a disk path.
	 */

	map.dev_addr = (gfc_port_dev_info_t *)NULL;
	if (!path_struct->ib_path_flag) {
		if ((err = g_get_dev_map(path_struct->p_physical_path,
							&map, verbose)) != 0)
			return (err);
		if ((err = l_get_ses_path(path_struct->p_physical_path,
					ses_path, &map, verbose)) != 0) {
			free((void *)map.dev_addr);
			return (err);
		}
	} else {
		(void) strcpy(ses_path, path_struct->p_physical_path);
	}

	if ((l_state = (L_state *)calloc(1, sizeof (L_state))) == NULL) {
		free((void *)map.dev_addr);
		return (L_MALLOC_FAILED);
	}

	if (!path_struct->slot_valid) {
		if ((map.dev_addr != NULL) &&
			(err = g_get_dev_map(path_struct->p_physical_path,
							&map, verbose)) != 0) {
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
		if (err = l_get_slot(path_struct, l_state, verbose)) {
			(void) l_free_lstate(&l_state);
			free((void *)map.dev_addr);
			return (err);
		}
	}
	if (map.dev_addr != NULL)
		free((void *)map.dev_addr);	/* Not used anymore */

	if ((page_buf = (uchar_t *)calloc(1,
				MAX_REC_DIAG_LENGTH)) == NULL) {
		(void) l_free_lstate(&l_state);
		return (L_MALLOC_FAILED);
	}

	if ((fd = g_object_open(ses_path, O_NDELAY | O_RDWR)) == -1) {
		(void) l_free_lstate(&l_state);
		(void) g_destroy_data(page_buf);
		return (L_OPEN_PATH_FAIL);
	}

	if (err = l_get_envsen_page(fd, page_buf, MAX_REC_DIAG_LENGTH,
						L_PAGE_2, verbose)) {
		(void) l_free_lstate(&l_state);
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		return (err);
	}

	page_len = (page_buf[2] << 8 | page_buf[3]) + HEADER_LEN;

	/* Get index to the disk we are interested in */
	if (err = l_get_status(ses_path, l_state, verbose)) {
		(void) l_free_lstate(&l_state);
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		return (err);
	}

	/* find enclosure type */
	if ((strncmp((char *)l_state->ib_tbl.config.prod_id, DAK_OFF_NAME,
						strlen(DAK_OFF_NAME)) == 0) ||
		(strncmp((char *)l_state->ib_tbl.config.prod_id, DAK_PROD_STR,
						strlen(DAK_PROD_STR)) == 0)) {
		enc_type = DAK_ENC_TYPE;
	} else {
		enc_type = SENA_ENC_TYPE;
	}

	/* Double check slot. */
	if (path_struct->slot >= l_state->total_num_drv/2) {
		(void) l_free_lstate(&l_state);
		return (L_INVALID_SLOT);
	}

	if (err = l_get_disk_element_index(l_state, &front_index,
	    &rear_index)) {
		(void) l_free_lstate(&l_state);
		return (err);
	}

	/* Skip global element */
	front_index++;
	if (enc_type == DAK_ENC_TYPE) {
		rear_index += l_state->total_num_drv/2 + 1;
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
	bcopy((const void *)elem, (void *)status,
		sizeof (struct device_element));	/* save status */
	bzero(elem, sizeof (struct device_element));
	elem->select = 1;
	elem->dev_off = status->dev_off;
	elem->en_bypass_a = status->en_bypass_a;
	elem->en_bypass_b = status->en_bypass_b;
	write = 1;

	switch (led_action) {
	case	L_LED_STATUS:
		write = 0;
		break;
	case	L_LED_RQST_IDENTIFY:
		elem->ident = 1;
		if (verbose) {
		    if (enc_type == DAK_ENC_TYPE) {
			(void) fprintf(stdout,
			MSGSTR(9043, "  Blinking LED for slot %d in enclosure"
			" %s\n"), path_struct->f_flag ? path_struct->slot :
			path_struct->slot + (MAX_DRIVES_DAK/2),
			l_state->ib_tbl.enclosure_name);
		    } else {
			(void) fprintf(stdout,
			MSGSTR(9043, "  Blinking LED for slot %d in enclosure"
			" %s\n"), path_struct->slot,
			l_state->ib_tbl.enclosure_name);
		    }
		}
		break;
	case	L_LED_OFF:
		if (verbose) {
		    if (enc_type == DAK_ENC_TYPE) {
			(void) fprintf(stdout,
			MSGSTR(9044,
			"  Turning off LED for slot %d in enclosure"
			" %s\n"), path_struct->f_flag ? path_struct->slot
			: path_struct->slot + (MAX_DRIVES_DAK/2),
			l_state->ib_tbl.enclosure_name);
		    } else {
			(void) fprintf(stdout,
			MSGSTR(9044,
			"  Turning off LED for slot %d in enclosure"
			" %s\n"), path_struct->slot,
			l_state->ib_tbl.enclosure_name);
		    }
		}
		break;
	default:
		(void) l_free_lstate(&l_state);
		return (L_INVALID_LED_RQST);
	} /* End of switch */

	if (write) {
		if (getenv("_LUX_D_DEBUG") != NULL) {
			g_dump("  l_led: Updating led state: "
			"Device Status Element ",
			(uchar_t *)elem, sizeof (struct device_element),
			HEX_ONLY);
		}
		if (err = g_scsi_send_diag_cmd(fd,
			(uchar_t *)page_buf, page_len)) {
			(void) close(fd);
			(void) g_destroy_data(page_buf);
			(void) l_free_lstate(&l_state);
			return (err);
		}

		bzero(page_buf, MAX_REC_DIAG_LENGTH);
		if (err = l_get_envsen_page(fd, page_buf, MAX_REC_DIAG_LENGTH,
					L_PAGE_2, verbose)) {
			(void) g_destroy_data(page_buf);
			(void) close(fd);
			(void) l_free_lstate(&l_state);
			return (err);
		}
		elem = (struct device_element *)(page_buf + offset);
		bcopy((const void *)elem, (void *)status,
			sizeof (struct device_element));
	}
	if (getenv("_LUX_D_DEBUG") != NULL) {
		g_dump("  l_led: Device Status Element ",
		(uchar_t *)status, sizeof (struct device_element),
		HEX_ONLY);
	}

	(void) l_free_lstate(&l_state);
	(void) close(fd);
	(void) g_destroy_data(page_buf);
	return (0);
}


/*
 * frees the previously alloced l_state
 * structure.
 *
 * RETURNS:
 *	0	O.K.
 *	non-zero otherwise
 */
int
l_free_lstate(L_state **l_state)
{
int	i;

	if ((l_state == NULL) || (*l_state == NULL))
		return (0);

	for (i = 0; i < (int)(*l_state)->total_num_drv/2; i++) {
	if ((*l_state)->drv_front[i].g_disk_state.multipath_list != NULL)
		(void) g_free_multipath(
		(*l_state)->drv_front[i].g_disk_state.multipath_list);
	if ((*l_state)->drv_rear[i].g_disk_state.multipath_list != NULL)
		(void) g_free_multipath(
		(*l_state)->drv_rear[i].g_disk_state.multipath_list);
	}
	(void) g_destroy_data (*l_state);
	l_state = NULL;

	return (0);
}



/*
 * Set the state of an individual disk
 * in the Photon enclosure the powered
 * up/down mode. The path must point to
 * a disk or the ib_path_flag must be set.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_dev_pwr_up_down(char *path_phys, struct path_struct *path_struct,
		int power_off_flag, int verbose, int force_flag)
/*ARGSUSED*/
{
gfc_map_t		map;
char			ses_path[MAXPATHLEN], dev_path[MAXPATHLEN];
int			slot, err = 0;
L_state			*l_state = NULL;
struct l_disk_state_struct	*drive;
struct dlist		*dl, *dl1;
devctl_hdl_t		devhdl;
WWN_list		*wwn_list = NULL;
L_inquiry		inq;

	if (path_struct == NULL) {
		return (L_INVALID_PATH_FORMAT);
	}

	dl = (struct dlist *)NULL;
	map.dev_addr = (gfc_port_dev_info_t *)NULL;

	if (err = g_get_dev_map(path_struct->p_physical_path,
					&map, verbose))
		return (err);

	if (err = l_get_ses_path(path_struct->p_physical_path,
				ses_path, &map, verbose)) {
		free((void *)map.dev_addr);
		return (err);
	}
	free((void *)map.dev_addr);	/* Not used anymore */

	/*
	 * Check to see if we have a photon, and if not, don't allow
	 * this operation
	 */
	if (err = g_get_inquiry(ses_path, &inq)) {
	    return (err);
	}
	if (l_get_enc_type(inq) != SENA_ENC_TYPE) {
	    return (L_ENCL_INVALID_PATH);
	}
	/*
	 * OK, so we have a photon... we can continue
	 */


	if ((l_state = (L_state *)calloc(1, sizeof (L_state))) == NULL) {
		return (L_MALLOC_FAILED);
	}

	if (err = l_get_status(ses_path, l_state, verbose)) {
		(void) l_free_lstate(&l_state);
		return (err);
	}

	if (!path_struct->slot_valid) {
		/* We are passing the disks path */
		if (err = l_get_slot(path_struct, l_state, verbose)) {
			(void) l_free_lstate(&l_state);
			return (err);
		}
	}

	slot = path_struct->slot;
	(void) strcpy(dev_path, path_struct->p_physical_path);

	/*
	 * Either front or rear drive
	 */
	if (path_struct->f_flag) {
		drive = &l_state->drv_front[slot];
	} else {
		drive = &l_state->drv_rear[slot];
	}

	/*
	 * Check for drive presence always
	 */
	if (drive->ib_status.code == S_NOT_INSTALLED) {
		(void) l_free_lstate(&l_state);
		return (L_SLOT_EMPTY);
	}

	/*
	 * Check disk state
	 * before the power off.
	 *
	 */
	if (power_off_flag && !force_flag) {
		goto pre_pwr_dwn;
	} else {
		goto pwr_up_dwn;
	}

pre_pwr_dwn:

	/*
	 * Check whether disk
	 * is reserved by another
	 * host
	 */
	if ((drive->g_disk_state.d_state_flags[PORT_A] & L_RESERVED) ||
		(drive->g_disk_state.d_state_flags[PORT_B] &
		L_RESERVED)) {
		(void) l_free_lstate(&l_state);
		return (L_DEVICE_RESERVED);
	}


	if ((dl = (struct dlist *)g_zalloc(sizeof (struct dlist))) == NULL) {
		(void) l_free_lstate(&l_state);
		return (L_MALLOC_FAILED);
	}

	/*
	 * NOTE: It is not necessary to get the multipath list here as ------
	 * we alread have it after getting the status earlier.
	 * - REWRITE -
	 */

	/*
	 * Get path to all the FC disk and tape devices.
	 *
	 * I get this now and pass down for performance
	 * reasons.
	 * If for some reason the list can become invalid,
	 * i.e. device being offlined, then the list
	 * must be re-gotten.
	 */
	if (err = g_get_wwn_list(&wwn_list, verbose)) {
		(void) g_destroy_data(dl);
		(void) l_free_lstate(&l_state);
		return (err);   /* Failure */
	}

	dl->dev_path = dev_path;
	if ((err = g_get_multipath(dev_path,
			&(dl->multipath), wwn_list, verbose)) != 0) {
		(void) g_destroy_data(dl);
		(void) g_free_wwn_list(&wwn_list);
		(void) l_free_lstate(&l_state);
		return (err);
	}

	for (dl1 = dl->multipath; dl1 != NULL; dl1 = dl1->next) {
		if ((devhdl = devctl_device_acquire(dl1->dev_path,
						DC_EXCL)) == NULL) {
			if (errno != EBUSY) {
				ER_DPRINTF("%s could not acquire"
				" the device: %s\n\n",
				strerror(errno), dl1->dev_path);
				continue;
			}
		}
		if (devctl_device_offline(devhdl) != 0) {
			(void) devctl_release(devhdl);
			(void) g_free_multipath(dl->multipath);
			(void) g_destroy_data(dl);
			(void) g_free_wwn_list(&wwn_list);
			(void) l_free_lstate(&l_state);
			return (L_POWER_OFF_FAIL_BUSY);
		}
		(void) devctl_release(devhdl);
	}

pwr_up_dwn:
	err = pwr_up_down(ses_path, l_state, path_struct->f_flag,
			path_struct->slot, power_off_flag, verbose);

	if (dl != NULL) {
		(void) g_free_multipath(dl->multipath);
		(void) g_destroy_data(dl);
	}
	(void) g_free_wwn_list(&wwn_list);
	(void) l_free_lstate(&l_state);
	if (err) {
		return (err);
	}
	return (0);
}



/*
 * l_pho_pwr_up_down() Set the state of the Photon enclosure
 * the powered up/down mode.
 * The path must point to an IB.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_pho_pwr_up_down(char *dev_name, char *path_phys, int power_off_flag,
	int verbose, int force_flag)
{
L_state		*l_state = NULL;
int		i, err = 0;
struct dlist	*dl, *dl1;
char		dev_path[MAXPATHLEN];
devctl_hdl_t	devhdl;
WWN_list	*wwn_list = NULL;

	if (path_phys == NULL) {
		return (L_INVALID_PATH_FORMAT);
	}

	dl = (struct dlist *)NULL;
	if ((l_state = (L_state *)calloc(1, sizeof (L_state))) == NULL) {
		return (L_MALLOC_FAILED);
	}
	if (err = l_get_status(path_phys, l_state, verbose)) {
		(void) l_free_lstate(&l_state);
		return (err);
	}
	if (power_off_flag && !force_flag) {
		goto pre_pwr_dwn;
	} else {
		goto pwr_up_dwn;
	}

pre_pwr_dwn:

	/*
	 * Check if any disk in this enclosure
	 * is reserved by another host before
	 * the power off.
	 */
	for (i = 0; i < l_state->total_num_drv/2; i++) {
		if ((l_state->drv_front[i].g_disk_state.d_state_flags[PORT_A] &
						L_RESERVED) ||
		(l_state->drv_front[i].g_disk_state.d_state_flags[PORT_B] &
						L_RESERVED) ||
		(l_state->drv_rear[i].g_disk_state.d_state_flags[PORT_A] &
						L_RESERVED) ||
		(l_state->drv_rear[i].g_disk_state.d_state_flags[PORT_B] &
						L_RESERVED)) {
				return (L_DISKS_RESERVED);
		}
	}

	/*
	 * Check if any disk in this enclosure
	 * Get path to all the FC disk and tape devices.
	 *
	 * I get this now and pass down for performance
	 * reasons.
	 * If for some reason the list can become invalid,
	 * i.e. device being offlined, then the list
	 * must be re-gotten.
	 */
	if (err = g_get_wwn_list(&wwn_list, verbose)) {
		(void) l_free_lstate(&l_state);
		return (err);   /* Failure */
	}
	for (i = 0; i < l_state->total_num_drv/2; i++) {
		if (*l_state->drv_front[i].g_disk_state.physical_path) {
			(void) memset(dev_path, 0, MAXPATHLEN);
			(void) strcpy(dev_path,
		(char *)&l_state->drv_front[i].g_disk_state.physical_path);

			if ((dl = (struct dlist *)
				g_zalloc(sizeof (struct dlist))) == NULL) {
				(void) g_free_wwn_list(&wwn_list);
				(void) l_free_lstate(&l_state);
				return (L_MALLOC_FAILED);
			}
			dl->dev_path = dev_path;
			if (g_get_multipath(dev_path, &(dl->multipath),
				wwn_list, verbose) != 0) {
				(void) g_destroy_data(dl);
				continue;
			}

			for (dl1 = dl->multipath;
			    dl1 != NULL;
			    dl1 = dl1->next) {

				/* attempt to acquire the device */
				if ((devhdl = devctl_device_acquire(
					dl1->dev_path, DC_EXCL)) == NULL) {
					if (errno != EBUSY) {
						ER_DPRINTF("%s: Could not "
						"acquire the device: %s\n\n",
						strerror(errno),
						dl1->dev_path);
						continue;
					}
				}

				/* attempt to offline the device */
				if (devctl_device_offline(devhdl) != 0) {
					(void) devctl_release(devhdl);
					(void) g_free_multipath(
						dl->multipath);
					(void) g_destroy_data(dl);
					(void) g_free_wwn_list(&wwn_list);
					(void) l_free_lstate(&l_state);
					return (L_POWER_OFF_FAIL_BUSY);
				}

				/* release handle acquired above */
				(void) devctl_release(devhdl);
			}
			(void) g_free_multipath(dl->multipath);
			(void) g_destroy_data(dl);

		}
		if (*l_state->drv_rear[i].g_disk_state.physical_path) {
			(void) memset(dev_path, 0, MAXPATHLEN);
			(void) strcpy(dev_path,
		(char *)&l_state->drv_rear[i].g_disk_state.physical_path);

			if ((dl = (struct dlist *)
				g_zalloc(sizeof (struct dlist))) == NULL) {
				(void) g_free_wwn_list(&wwn_list);
				(void) l_free_lstate(&l_state);
				return (L_MALLOC_FAILED);
			}
			dl->dev_path = dev_path;
			if (g_get_multipath(dev_path, &(dl->multipath),
				wwn_list, verbose) != 0) {
				(void) g_destroy_data(dl);
				continue;
			}


			for (dl1 = dl->multipath;
			    dl1 != NULL;
			    dl1 = dl1->next) {

				/* attempt to acquire the device */
				if ((devhdl = devctl_device_acquire(
					dl1->dev_path, DC_EXCL)) == NULL) {
					if (errno != EBUSY) {
						ER_DPRINTF("%s: Could not "
						"acquire the device: %s\n\n",
						strerror(errno),
						dl1->dev_path);
						continue;
					}
				}
				/* attempt to offline the device */
				if (devctl_device_offline(devhdl) != 0) {
					(void) devctl_release(devhdl);
					(void) g_free_multipath(
							dl->multipath);
					(void) g_destroy_data(dl);
					(void) g_free_wwn_list(&wwn_list);
					(void) l_free_lstate(&l_state);
					return (L_POWER_OFF_FAIL_BUSY);
				}

				/* release handle acquired above */
				(void) devctl_release(devhdl);
			}
			(void) g_free_multipath(dl->multipath);
			(void) g_destroy_data(dl);

		}
	}

pwr_up_dwn:

	(void) g_free_wwn_list(&wwn_list);
	if ((err = pwr_up_down(path_phys, l_state, 0, -1,
		power_off_flag, verbose)) != 0) {
		(void) l_free_lstate(&l_state);
		return (err);
	}
	(void) l_free_lstate(&l_state);
	return (0);
}


/*
 * Set the state of the Photon enclosure or disk
 * powered up/down mode.
 * The path must point to an IB.
 * slot == -1 implies entire enclosure.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
static int
pwr_up_down(char *path_phys, L_state *l_state, int front, int slot,
		int power_off_flag, int verbose)
{
L_inquiry		inq;
int			fd, status, err;
uchar_t			*page_buf;
int 			front_index, rear_index, front_offset, rear_offset;
unsigned short		page_len;
struct	device_element	*front_elem, *rear_elem;

	(void) memset(&inq, 0, sizeof (inq));
	if ((fd = g_object_open(path_phys, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}
	/* Verify it is a Photon */
	if (status = g_scsi_inquiry_cmd(fd,
		(uchar_t *)&inq, sizeof (struct l_inquiry_struct))) {
		(void) close(fd);
		return (status);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) &&
		(!(strncmp((char *)inq.inq_vid, "SUN     ",
		sizeof (inq.inq_vid)) &&
		((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)))) {
		(void) close(fd);
		return (L_ENCL_INVALID_PATH);
	}

	/*
	 * To power up/down a Photon we use the Driver Off
	 * bit in the global device control element.
	 */
	if ((page_buf = (uchar_t *)malloc(MAX_REC_DIAG_LENGTH)) == NULL) {
		return (L_MALLOC_FAILED);
	}
	if (err = l_get_envsen_page(fd, page_buf, MAX_REC_DIAG_LENGTH,
				L_PAGE_2, verbose)) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		return (err);
	}

	page_len = (page_buf[2] << 8 | page_buf[3]) + HEADER_LEN;

	/* Double check slot as convert_name only does gross check */
	if (slot >= l_state->total_num_drv/2) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		return (L_INVALID_SLOT);
	}

	if (err = l_get_disk_element_index(l_state, &front_index,
		&rear_index)) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		return (err);
	}
	/* Skip global element */
	front_index++;
	rear_index++;

	front_offset = (8 + (front_index + slot)*4);
	rear_offset = (8 + (rear_index + slot)*4);

	front_elem = (struct device_element *)(page_buf + front_offset);
	rear_elem = (struct device_element *)(page_buf + rear_offset);

	if (front || slot == -1) {
		/*
		 * now do requested action.
		 */
		bzero(front_elem, sizeof (struct device_element));
		/* Set/reset power off bit */
		front_elem->dev_off = power_off_flag;
		front_elem->select = 1;
	}
	if (!front || slot == -1) {
		/* Now do rear */
		bzero(rear_elem, sizeof (struct device_element));
		/* Set/reset power off bit */
		rear_elem->dev_off = power_off_flag;
		rear_elem->select = 1;
	}

	if (getenv("_LUX_D_DEBUG") != NULL) {
		if (front || slot == -1) {
			g_dump("  pwr_up_down: "
				"Front Device Status Element ",
				(uchar_t *)front_elem,
				sizeof (struct device_element),
				HEX_ONLY);
		}
		if (!front || slot == -1) {
			g_dump("  pwr_up_down: "
				"Rear Device Status Element ",
				(uchar_t *)rear_elem,
				sizeof (struct device_element),
				HEX_ONLY);
		}
	}
	if (err = g_scsi_send_diag_cmd(fd,
		(uchar_t *)page_buf, page_len)) {
		(void) close(fd);
		(void) g_destroy_data(page_buf);
		return (err);
	}
	(void) close(fd);
	(void) g_destroy_data(page_buf);
	return (0);
}

/*
 * Set the password of the FPM by sending the password
 * in page 4 of the Send Diagnostic command.
 *
 * The path must point to an IB.
 *
 * The size of the password string must be <= 8 bytes.
 * The string can also be NULL. This is the way the user
 * chooses to not have a password.
 *
 * I then tell the photon by giving it 4 NULL bytes.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_new_password(char *path_phys, char *password)
{
Page4_name	page4;
L_inquiry	inq;
int		fd, status;

	(void) memset(&inq, 0, sizeof (inq));
	(void) memset(&page4, 0, sizeof (page4));

	if ((fd = g_object_open(path_phys, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}
	/* Verify it is a Photon */
	if (status = g_scsi_inquiry_cmd(fd,
		(uchar_t *)&inq, sizeof (struct l_inquiry_struct))) {
		(void) close(fd);
		return (status);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) &&
		(!(strncmp((char *)inq.inq_vid, "SUN     ",
		sizeof (inq.inq_vid)) &&
		((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)))) {
		(void) close(fd);
		return (L_ENCL_INVALID_PATH);
	}

	page4.page_code = L_PAGE_4;
	page4.page_len = (ushort_t)max((strlen(password) + 4), 8);
	/* Double check */
	if (strlen(password) > 8) {
		return (L_INVALID_PASSWORD_LEN);
	}
	page4.string_code = L_PASSWORD;
	page4.enable = 1;
	(void) strcpy((char *)page4.name, password);

	if (status = g_scsi_send_diag_cmd(fd, (uchar_t *)&page4,
		page4.page_len + HEADER_LEN)) {
		(void) close(fd);
		return (status);
	}

	(void) close(fd);
	return (0);
}



/*
 * Set the name of the enclosure by sending the name
 * in page 4 of the Send Diagnostic command.
 *
 * The path must point to an IB.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_new_name(char *path_phys, char *name)
{
Page4_name	page4;
L_inquiry	inq;
int		fd, status;

	if ((path_phys == NULL) || (name == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	(void) memset(&inq, 0, sizeof (inq));
	(void) memset(&page4, 0, sizeof (page4));

	if ((fd = g_object_open(path_phys, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}
	/* Verify it is a Photon */
	if (status = g_scsi_inquiry_cmd(fd,
		(uchar_t *)&inq, sizeof (struct l_inquiry_struct))) {
		(void) close(fd);
		return (status);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) &&
		(!(strncmp((char *)inq.inq_vid, "SUN     ",
		sizeof (inq.inq_vid)) &&
		((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)))) {
		(void) close(fd);
		return (L_ENCL_INVALID_PATH);
	}

	page4.page_code = L_PAGE_4;
	page4.page_len = (ushort_t)((sizeof (struct page4_name) - 4));
	page4.string_code = L_ENCL_NAME;
	page4.enable = 1;
	strncpy((char *)page4.name, name, sizeof (page4.name));

	if (status = g_scsi_send_diag_cmd(fd, (uchar_t *)&page4,
		sizeof (page4))) {
		(void) close(fd);
		return (status);
	}

	/*
	 * Check the name really changed.
	 */
	if (status = g_scsi_inquiry_cmd(fd,
		(uchar_t *)&inq, sizeof (struct l_inquiry_struct))) {
		(void) close(fd);
		return (status);
	}
	if (strncmp((char *)inq.inq_box_name, name, sizeof (page4.name)) != 0) {
		char	name_buf[MAXNAMELEN];
		(void) close(fd);
		strncpy((char *)name_buf, (char *)inq.inq_box_name,
			sizeof (inq.inq_box_name));
		return (L_ENCL_NAME_CHANGE_FAIL);
	}

	(void) close(fd);
	return (0);
}



/*
 * Issue a Loop Port enable Primitive sequence
 * to the device specified by the pathname.
 */
int
l_enable(char *path, int verbose)
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
l_bypass(char *path, int verbose)
/*ARGSUSED*/
{

	return (0);
}



/*
 * Create a linked list of all the Photon enclosures that
 * are attached to this host.
 *
 * RETURN VALUES: 0 O.K.
 *
 * box_list pointer:
 *			NULL: No enclosures found.
 *			!NULL: Enclosures found
 *                      box_list points to a linked list of boxes.
 */
int
l_get_box_list(struct box_list_struct **box_list_ptr, int verbose)
{
char		*dev_name;
DIR		*dirp;
struct dirent	*entp;
char		namebuf[MAXPATHLEN];
struct stat	sb;
char		*result = NULL;
int		fd, status;
L_inquiry	inq;
Box_list	*box_list, *l1, *l2;
IB_page_config	page1;
uchar_t		node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
int		al_pa;

	if (box_list_ptr == NULL) {
		return (L_INVALID_PATH_FORMAT);
	}

	box_list = *box_list_ptr = NULL;
	if ((dev_name = (char *)g_zalloc(sizeof ("/dev/es"))) == NULL) {
		return (L_MALLOC_FAILED);
	}
	(void) sprintf((char *)dev_name, "/dev/es");

	if (verbose) {
		(void) fprintf(stdout,
		MSGSTR(9045,
			"  Searching directory %s for links to enclosures\n"),
			dev_name);
	}

	if ((dirp = opendir(dev_name)) == NULL) {
		(void) g_destroy_data(dev_name);
		/* No Photons found */
		B_DPRINTF("  l_get_box_list: No Photons found\n");
		return (0);
	}


	while ((entp = readdir(dirp)) != NULL) {
		if (strcmp(entp->d_name, ".") == 0 ||
			strcmp(entp->d_name, "..") == 0)
			continue;

		(void) sprintf(namebuf, "%s/%s", dev_name, entp->d_name);

		if ((lstat(namebuf, &sb)) < 0) {
			ER_DPRINTF("Warning: Cannot stat %s\n",
							namebuf);
			continue;
		}

		if (!S_ISLNK(sb.st_mode)) {
			ER_DPRINTF("Warning: %s is not a symbolic link\n",
								namebuf);
			continue;
		}
		if ((result = g_get_physical_name_from_link(namebuf)) == NULL) {
			ER_DPRINTF("  Warning: Get physical name from"
			" link failed. Link=%s\n", namebuf);
			continue;
		}

		/* Found a SES card. */
		B_DPRINTF("  l_get_box_list: Link to SES Card found: %s/%s\n",
			dev_name, entp->d_name);
		if ((fd = g_object_open(result, O_NDELAY | O_RDONLY)) == -1) {
			g_destroy_data(result);
			continue;	/* Ignore errors */
		}
		/* Get the box name */
		if (status = g_scsi_inquiry_cmd(fd,
			(uchar_t *)&inq, sizeof (struct l_inquiry_struct))) {
			(void) close(fd);
			g_destroy_data(result);
			continue;	/* Ignore errors */
		}

		if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) != NULL) ||
			(((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI) &&
				(l_get_enc_type(inq) == DAK_ENC_TYPE))) {
			/*
			 * Found Photon/Daktari
			 */

			/* Get the port WWN from the IB, page 1 */
			if ((status = l_get_envsen_page(fd, (uchar_t *)&page1,
				sizeof (page1), 1, 0)) != NULL) {
				(void) close(fd);
				g_destroy_data(result);
				(void) g_destroy_data(dev_name);
				closedir(dirp);
				return (status);
			}

			/*
			 * Build list of names.
			 */
			if ((l2 = (struct  box_list_struct *)
				g_zalloc(sizeof (struct  box_list_struct)))
				== NULL) {
				(void) close(fd);
				g_destroy_data(result);
				g_destroy_data(dev_name);
				closedir(dirp);
				return (L_MALLOC_FAILED);
			}

			/* Fill in structure */
			(void) strcpy((char *)l2->b_physical_path,
				(char *)result);
			(void) strcpy((char *)l2->logical_path,
				(char *)namebuf);
			bcopy((void *)page1.enc_node_wwn,
				(void *)l2->b_node_wwn, WWN_SIZE);
			(void) sprintf(l2->b_node_wwn_s,
			"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
				page1.enc_node_wwn[0],
				page1.enc_node_wwn[1],
				page1.enc_node_wwn[2],
				page1.enc_node_wwn[3],
				page1.enc_node_wwn[4],
				page1.enc_node_wwn[5],
				page1.enc_node_wwn[6],
				page1.enc_node_wwn[7]);
			strncpy((char *)l2->prod_id_s,
				(char *)inq.inq_pid,
				sizeof (inq.inq_pid));
			strncpy((char *)l2->b_name,
				(char *)inq.inq_box_name,
				sizeof (inq.inq_box_name));
			/* make sure null terminated */
			l2->b_name[sizeof (l2->b_name) - 1] = NULL;

			/*
			 * Now get the port WWN for the port
			 * we are connected to.
			 */
			status = g_get_wwn(result, port_wwn, node_wwn,
					&al_pa, verbose);
			if (status == 0) {
				(void) sprintf(l2->b_port_wwn_s,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
				port_wwn[0], port_wwn[1], port_wwn[2],
				port_wwn[3], port_wwn[4], port_wwn[5],
				port_wwn[6], port_wwn[7]);
				bcopy((void *)port_wwn,
					(void *)l2->b_port_wwn, WWN_SIZE);

				B_DPRINTF("  l_get_box_list:"
				" Found enclosure named:%s\n", l2->b_name);

				if (box_list == NULL) {
					l1 = box_list = l2;
				} else {
					l2->box_prev = l1;
					l1 = l1->box_next = l2;
				}
			} else {
				(void) close(fd);
				g_destroy_data(result);
				(void) g_destroy_data(dev_name);
				(void) g_destroy_data(l2);
				closedir(dirp);
				return (status);
			}

		}
		g_destroy_data(result);
		(void) close(fd);
		*box_list_ptr = box_list; /* pass back ptr to list */
	}
	(void) g_destroy_data(dev_name);
	closedir(dirp);
	return (0);
}

void
l_free_box_list(struct box_list_struct **box_list)
{
Box_list	*next = NULL;

	if (box_list == NULL) {
		return;
	}

	for (; *box_list != NULL; *box_list = next) {
		next = (*box_list)->box_next;
		(void) g_destroy_data(*box_list);
	}

	*box_list = NULL;
}



/*
 * Finds out if there are any other boxes
 * with the same name as "name".
 *
 * RETURNS:
 *	0   There are no other boxes with the same name.
 *	>0  if duplicate names found
 */
/*ARGSUSED*/
int
l_duplicate_names(Box_list *b_list, char wwn[], char *name, int verbose)
{
int		dup_flag = 0;
Box_list	*box_list_ptr = NULL;

	if ((name == NULL) || (wwn == NULL))
		return (0);

	box_list_ptr = b_list;
	while (box_list_ptr != NULL) {
		if ((strcmp(name, (const char *)box_list_ptr->b_name) == 0) &&
			(strcmp(box_list_ptr->b_node_wwn_s, wwn) != 0)) {
			dup_flag++;
			break;
		}
		box_list_ptr = box_list_ptr->box_next;
	}
	return (dup_flag);
}



/*
 * Checks for a name conflict with an SSA cN type name.
 */
int
l_get_conflict(char *name, char **result, int verbose)
{
char		s[MAXPATHLEN];
char		*p = NULL;
char		*pp = NULL;
Box_list	*box_list = NULL;
int		found_box = 0, err = 0;

	(void) strcpy(s, name);
	if ((*result = g_get_physical_name(s)) == NULL) {
		return (0);
	}
	if ((strstr((const char *)*result, PLNDEF)) == NULL) {
		(void) g_destroy_data(*result);
		*result = NULL;
		return (0);
	}
	P_DPRINTF("  l_get_conflict: Found "
		"SSA path using %s\n", s);
	/* Find path to IB */
	if ((err = l_get_box_list(&box_list, verbose)) != 0) {
		return (err);	/* Failure */
	}
	/*
	 * Valid cN type name found.
	 */
	while (box_list != NULL) {
		if ((strcmp((char *)s,
			(char *)box_list->b_name)) == 0) {
			found_box = 1;
			if (p == NULL) {
				if ((p = g_zalloc(strlen(
				box_list->b_physical_path)
				+ 2)) == NULL) {
				(void) l_free_box_list(&box_list);
				return (errno);
				}
			} else {
				if ((pp = g_zalloc(strlen(
				box_list->b_physical_path)
				+ strlen(p)
				+ 2)) == NULL) {
				(void) l_free_box_list(&box_list);
				return (errno);
				}
				(void) strcpy(pp, p);
				(void) g_destroy_data(p);
				p = pp;
			}
			(void) strcat(p, box_list->b_physical_path);
			(void) strcat(p, "\n");
		}
		box_list = box_list->box_next;
	}
	if (found_box) {
		D_DPRINTF("There is a conflict between the "
			"enclosure\nwith this name, %s, "
			"and a SSA name of the same form.\n"
			"Please use one of the following physical "
			"pathnames:\n%s\n%s\n",
			s, *result, p);

		(void) l_free_box_list(&box_list);
		(void) g_destroy_data(p);
		return (L_SSA_CONFLICT);	/* failure */
	}
	(void) l_free_box_list(&box_list);
	return (0);
}

/*
 * This function sets the "slot", "slot_valid" and "f_flag" fields of the
 * path_struct that is passed in IFF the device path passed in ("phys_path")
 * is a disk in an A5K or a Daktari. This is achieved by calling l_get_slot().
 *
 * INPUT  :
 *	phys_path - physical path to a device
 *	path_sturct - Pointer to pointer to a path_struct data structure
 *
 * OUTPUT :
 *	if phys_path is that of an A5K/Daktari disk
 *		path_struct->slot is set to the slot position in enclosure
 *		path_struct->slot_valid is set to 1
 *		path_struct->f_flag is set to 1 if in the front of an A5k
 *			    or if among the first 6 disks on a Daktari
 *	else
 *		they are left as they were
 * RETURNS:
 *	0 on SUCCESS
 *	non-zero otherwise
 */
static int
load_flds_if_enc_disk(char *phys_path, struct path_struct **path_struct)
{
	int		err = 0, verbose = 0;
	char		ses_path[MAXPATHLEN];
	gfc_map_t	map;
	L_inquiry	inq;
	L_state		*l_state = NULL;

	if ((path_struct == NULL) || (*path_struct == NULL) ||
				(phys_path == NULL) || (*phys_path == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	if ((strstr(phys_path, SLSH_DRV_NAME_SSD) == NULL) ||
	    (g_get_path_type(phys_path) == 0)) {
		/*
		 * Don't proceed when not a disk device or if it is not a
		 * valid FC device on which g_get_dev_map() can be done
		 * (for example, g_get_dev_map() will fail on SSAs).
		 *
		 * Just return success
		 */
		return (0);
	}

	if ((*path_struct)->ib_path_flag) {
		/*
		 * If this flag is set, l_get_slot() should not be called
		 * So, no point in proceeding. Just return success.
		 */
		return (0);
	}

	if ((err = g_get_dev_map(phys_path, &map, verbose)) != 0) {
		return (err);
	}

	if ((err = l_get_ses_path(phys_path, ses_path, &map, verbose)) != 0) {
		(void) free(map.dev_addr);
		if (err == L_NO_SES_PATH) {
			/*
			 * This is not an error since this could be a device
			 * which does not have SES nodes
			 */
			return (0);
		}
		return (err);
	}

	/*
	 * There is a SES path on the same FCA as the given disk. But if the
	 * SES node is not of a photon/Daktari, we dont proceed
	 */
	if ((err = g_get_inquiry(ses_path, &inq)) != 0) {
		(void) free(map.dev_addr);
		return (err);
	}

	/*
	 * only want to continue if this is a photon or a Daktari
	 *
	 * if product ID is not SENA or VID is not "SUN" (checks for photon)
	 * and if enclosure type is not a Daktari, then I return
	 */
	if (((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) ||
		    (strncmp((char *)inq.inq_vid, "SUN     ",
			sizeof (inq.inq_vid)) != 0)) &&
	    ((l_get_enc_type(inq) != DAK_ENC_TYPE))) {
		/* Not a photon/Daktari */
		(void) free(map.dev_addr);
		return (0);
	}

	/* Now, set some fields that l_get_slot() uses and then call it */
	if ((l_state = (L_state *)g_zalloc(sizeof (L_state))) == NULL) {
		(void) free(map.dev_addr);
		return (L_MALLOC_FAILED);
	}

	if ((err = l_get_ib_status(ses_path, l_state, verbose)) != 0) {
		(void) free(map.dev_addr);
		(void) l_free_lstate(&l_state);
		return (err);
	}

	if ((err = l_get_slot(*path_struct, l_state, verbose)) != 0) {
		(void) free(map.dev_addr);
		(void) l_free_lstate(&l_state);
		return (err);
	}

	(void) free(map.dev_addr);
	(void) l_free_lstate(&l_state);
	return (0);
}

/*
 * convert box name or WWN or logical path to physical path.
 *
 *	OUTPUT:
 *		path_struct:
 *		- This structure is used to return more detailed
 *		  information about the path.
 *		- *p_physical_path
 *		  Normally this is the requested physical path.
 *		  If the requested path is not found then iff the
 *		  ib_path_flag is set this is the IB path.
 *		- *argv
 *		This is the argument variable input. e.g. Bob,f1
 *              - slot_valid
 *              - slot
 *		This is the slot number that was entered when using
 *		  the box,[fr]slot format. It is only valid if the
 *		  slot_valid flag is set.
 *		- f_flag
 *		  Front flag - If set, the requested device is located in the
 *		  front of the enclosure.
 *		- ib_path_flag
 *		  If this flag is set it means a devices path was requested
 *		  but could not be found but an IB's path was found and
 *		  the p_physical_path points to that path.
 *		- **phys_path
 *		  physical path to the device.
 *	RETURNS:
 *		- 0  if O.K.
 *		- error otherwise.
 */
int
l_convert_name(char *name, char **phys_path,
		struct path_struct **path_struct, int verbose)
{
char		tmp_name[MAXPATHLEN], ses_path[MAXPATHLEN];
char		*char_ptr, *ptr = NULL;
char		*result = NULL;
char		*env = NULL;
char		save_frd;	    /* which designator was it? */
int		slot = 0, slot_flag = 0, found_box = 0, found_comma = 0;
int		err = 0, enc_type = 0;
hrtime_t	start_time, end_time;
Box_list	*box_list = NULL, *box_list_ptr = NULL;
L_inquiry	inq;
L_state		*l_state = NULL;
Path_struct	*path_ptr = NULL;
WWN_list	*wwn_list, *wwn_list_ptr;

	if ((name == NULL) || (phys_path == NULL) ||
	    (path_struct == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	if ((env = getenv("_LUX_T_DEBUG")) != NULL) {
		start_time = gethrtime();
	}

	if ((*path_struct = path_ptr = (struct path_struct *)
		g_zalloc(sizeof (struct path_struct))) == NULL) {
		return (L_MALLOC_FAILED);
	}

	*phys_path = NULL;
	/*
	 * If the path contains a "/" then assume
	 * it is a logical or physical path as the
	 * box name or wwn can not contain "/"s.
	 */
	if (strchr(name, '/') != NULL) {
		if ((result = g_get_physical_name(name)) == NULL) {
			return (L_NO_PHYS_PATH);
		}

		path_ptr->p_physical_path = result;
		/*
		 * Make sure it's a disk or tape path
		 */
		if (strstr(name, DEV_RDIR) || strstr(name, SLSH_DRV_NAME_SSD) ||
			strstr(name, DEV_TAPE_DIR) ||
			strstr(name, SLSH_DRV_NAME_ST)) {
			if ((err = g_get_inquiry(result, &inq)) != 0) {
				(void) free(result);
				return (L_SCSI_ERROR);
			}
			/*
			 * Check to see if it is not a
			 * A5K/v880/v890 disk
			 *
			 */
			if (!g_enclDiskChk((char *)inq.inq_vid,
				    (char *)inq.inq_pid)) {
				path_ptr->argv = name;
				*phys_path = result;
				return (0);
			}
		}

		if (err = load_flds_if_enc_disk(result, path_struct)) {
			(void) free(result);
			return (err);
		}
		goto done;
	}

	(void) strcpy(tmp_name, name);
	if ((tmp_name[0] == 'c') &&
		((int)strlen(tmp_name) > 1) && ((int)strlen(tmp_name) < 5)) {
		if ((err = l_get_conflict(tmp_name, &result, verbose)) != 0) {
			if (result != NULL) {
				(void) g_destroy_data(result);
			}
			return (err);
		}
		if (result != NULL) {
			path_ptr->p_physical_path = result;
			if ((err = g_get_inquiry(result, &inq)) != 0) {
				(void) free(result);
				return (L_SCSI_ERROR);
			}
			/*
			 * Check to see if it is a supported
			 * A5K/v880/v890 storage subsystem disk
			 */
			if (g_enclDiskChk((char *)inq.inq_vid,
				    (char *)inq.inq_pid)) {
				if (err = load_flds_if_enc_disk(
					    result, path_struct)) {
					(void) free(result);
					return (err);
				}
			}
			goto done;
		}
	}

	/*
	 * Check to see if we have a box or WWN name.
	 *
	 * If it contains a , then the format must be
	 *    box_name,f1 where f is front and 1 is the slot number
	 * or it is a format like
	 * ssd@w2200002037049adf,0:h,raw
	 * or
	 * SUNW,pln@a0000000,77791d:ctlr
	 */
	if (((char_ptr = strstr(tmp_name, ",")) != NULL) &&
		((*(char_ptr + 1) == 'f') || (*(char_ptr + 1) == 'r') ||
		    (*(char_ptr + 1) == 's'))) {
		char_ptr++;	/* point to f/r */
		if ((*char_ptr == 'f') || (*char_ptr == 's')) {
			path_ptr->f_flag = 1;
		} else if (*char_ptr != 'r') {
			return (L_INVALID_PATH_FORMAT);
		}
		save_frd = (char)*char_ptr;	/* save it */
		char_ptr++;
		slot = strtol(char_ptr, &ptr, 10);
		/*
		 * NOTE: Need to double check the slot when we get
		 * the number of the devices actually in the box.
		 */
		if ((slot < 0) || (ptr == char_ptr) ||
		    ((save_frd == 's' && slot >= MAX_DRIVES_DAK) ||
		    ((save_frd != 's' && slot >= (MAX_DRIVES_PER_BOX/2))))) {
			return (L_INVALID_SLOT);
		}
		/* Say slot valid. */
		slot_flag = path_ptr->slot_valid = 1;
		if (save_frd == 's' && slot >= (MAX_DRIVES_DAK/2)) {
			path_ptr->slot = slot = slot % (MAX_DRIVES_DAK/2);
			path_ptr->f_flag = 0;
		} else
			path_ptr->slot = slot;
	}

	if (((char_ptr = strstr(tmp_name, ",")) != NULL) &&
		((*(char_ptr + 1) == 'f') || (*(char_ptr + 1) == 'r') ||
		    (*(char_ptr + 1) == 's'))) {
		*char_ptr = NULL; /* make just box name */
		found_comma = 1;
	}
	/* Find path to IB */
	if ((err = l_get_box_list(&box_list, verbose)) != 0) {
		(void) l_free_box_list(&box_list);
		return (err);
	}
	box_list_ptr = box_list;
	/* Look for box name. */
	while (box_list != NULL) {
	    if ((strcmp((char *)tmp_name, (char *)box_list->b_name)) == 0) {
			result =
				g_alloc_string(box_list->b_physical_path);
			L_DPRINTF("  l_convert_name:"
			" Found subsystem: name %s  WWN %s\n",
			box_list->b_name, box_list->b_node_wwn_s);
			/*
			 * Check for another box with this name.
			 */
			if (l_duplicate_names(box_list_ptr,
				box_list->b_node_wwn_s,
				(char *)box_list->b_name,
				verbose)) {
				(void) l_free_box_list(&box_list_ptr);
				(void) g_destroy_data(result);
				return (L_DUPLICATE_ENCLOSURES);
			}
			found_box = 1;
			break;
		}
		box_list = box_list->box_next;
	}
	/*
	 * Check to see if we must get individual disks path.
	 */

	if (found_box && slot_flag) {
		if ((l_state = (L_state *)g_zalloc(sizeof (L_state))) == NULL) {
			(void) g_destroy_data(result);
			(void) l_free_box_list(&box_list_ptr);
			return (L_MALLOC_FAILED);
		}
		(void) strcpy(ses_path, result);
		if ((err = l_get_status(ses_path, l_state,
			verbose)) != 0) {
			(void) g_destroy_data(result);
			(void) g_destroy_data(l_state);
			(void) l_free_box_list(&box_list_ptr);
			return (err);
		}
		/*
		 * Now double check the slot number.
		 */
		if (slot >= l_state->total_num_drv/2) {
			path_ptr->slot_valid = 0;
			(void) g_destroy_data(result);
			(void) l_free_box_list(&box_list_ptr);
			(void) l_free_lstate(&l_state);
			return (L_INVALID_SLOT);
		}

		/* Only allow the single slot version for Daktari */
		if (g_get_inquiry(ses_path, &inq)) {
		    return (L_SCSI_ERROR);
		}
		enc_type = l_get_enc_type(inq);
		if (((enc_type == DAK_ENC_TYPE) && (save_frd != 's')) ||
			((enc_type != DAK_ENC_TYPE) && (save_frd == 's'))) {
			path_ptr->slot_valid = 0;
			(void) g_destroy_data(result);
			(void) l_free_box_list(&box_list_ptr);
			(void) l_free_lstate(&l_state);
			return (L_INVALID_SLOT);
		}

		if (path_ptr->f_flag) {
		if (*l_state->drv_front[slot].g_disk_state.physical_path) {
				result =
	g_alloc_string(l_state->drv_front[slot].g_disk_state.physical_path);
			} else {
				/* Result is the IB path */
				path_ptr->ib_path_flag = 1;
				path_ptr->p_physical_path =
					g_alloc_string(result);
				(void) g_destroy_data(result);
				result = NULL;
			}
		} else {
		if (*l_state->drv_rear[slot].g_disk_state.physical_path) {
				result =
	g_alloc_string(l_state->drv_rear[slot].g_disk_state.physical_path);
			} else {
				/* Result is the IB path */
				path_ptr->ib_path_flag = 1;
				path_ptr->p_physical_path =
					g_alloc_string(result);
				(void) g_destroy_data(result);
				result = NULL;
			}
		}
		(void) l_free_lstate(&l_state);
		goto done;
	}
	if (found_box || found_comma) {
		goto done;
	}
	/*
	 * No luck with the box name.
	 *
	 * Try WWN's
	 */
	/* Look for the SES's WWN */
	box_list = box_list_ptr;
	while (box_list != NULL) {
		if (((strcasecmp((char *)tmp_name,
			(char *)box_list->b_port_wwn_s)) == 0) ||
			((strcasecmp((char *)tmp_name,
			(char *)box_list->b_node_wwn_s)) == 0)) {
				result =
				g_alloc_string(box_list->b_physical_path);
				L_DPRINTF("  l_convert_name:"
				" Found subsystem using the WWN"
				": name %s  WWN %s\n",
				box_list->b_name, box_list->b_node_wwn_s);
				goto done;
		}
		box_list = box_list->box_next;
	}
	/* Look for a device's WWN */
	if (strlen(tmp_name) <= L_WWN_LENGTH) {
		if ((err = g_get_wwn_list(&wwn_list, verbose)) != 0) {
			(void) l_free_box_list(&box_list_ptr);
			return (err);
		}
		for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
				wwn_list_ptr = wwn_list_ptr->wwn_next) {
			if (((strcasecmp((char *)tmp_name,
				(char *)wwn_list_ptr->node_wwn_s)) == 0) ||
				((strcasecmp((char *)tmp_name,
				(char *)wwn_list_ptr->port_wwn_s)) == 0)) {
			/*
			 * Found the device's WWN in the global WWN list.
			 * It MAY be in a photon/Daktari. If it is, we'll set
			 * additional fields in path_struct.
			 */
			result = g_alloc_string(wwn_list_ptr->physical_path);
			L_DPRINTF("  l_convert_name:"
					"  Found device: WWN %s Path %s\n",
					tmp_name, wwn_list_ptr->logical_path);

			(void) g_free_wwn_list(&wwn_list);

			/*
			 * Now check if it is a disk in an A5K and set
			 * path_struct fields
			 */
			path_ptr->p_physical_path = result;
			if ((err = g_get_inquiry(result, &inq)) != 0) {
				(void) free(result);
				return (L_SCSI_ERROR);
			}
			/*
			 * Check to see if it is a supported
			 * A5K/v880/v890 storage subsystem disk
			 */
			if (g_enclDiskChk((char *)inq.inq_vid,
				    (char *)inq.inq_pid)) {
				if (err = load_flds_if_enc_disk(
					    result, path_struct)) {
					(void) free(result);
					return (err);
				}
			}
			goto done;
		    }
		}
	}

	/*
	 * Try again in case we were in the /dev
	 * or /devices directory.
	 */
	result = g_get_physical_name(name);

done:
	(void) l_free_box_list(&box_list_ptr);
	path_ptr->argv = name;
	if (result == NULL) {
		if (!path_ptr->ib_path_flag)
			return (-1);
	} else {
		path_ptr->p_physical_path = result;
	}

	L_DPRINTF("  l_convert_name: path_struct:\n\tphysical_path:\n\t %s\n"
		"\targv:\t\t%s"
		"\n\tslot_valid\t%d"
		"\n\tslot\t\t%d"
		"\n\tf_flag\t\t%d"
		"\n\tib_path_flag\t%d\n",
		path_ptr->p_physical_path,
		path_ptr->argv,
		path_ptr->slot_valid,
		path_ptr->slot,
		path_ptr->f_flag,
		path_ptr->ib_path_flag);
	if (env != NULL) {
		end_time = gethrtime();
		(void) fprintf(stdout, "  l_convert_name: "
		"Time = %lld millisec\n",
		(end_time - start_time)/1000000);
	}

	if (path_ptr->ib_path_flag)
		return (-1);
	*phys_path = result;
	return (0);
}


/*
 * Gets envsen information of an enclosure from IB
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_envsen_page(int fd, uchar_t *buf, int buf_size, uchar_t page_code,
	int verbose)
{
Rec_diag_hdr	hdr;
uchar_t	*pg;
int	size, new_size, status;

	if (buf == NULL) {
		return (L_INVALID_BUF_LEN);
	}

	if (verbose) {
		(void) fprintf(stdout,
		MSGSTR(9046, "  Reading SES page %x\n"), page_code);
	}

	(void) memset(&hdr, 0, sizeof (struct rec_diag_hdr));
	if (status = g_scsi_rec_diag_cmd(fd, (uchar_t *)&hdr,
		sizeof (struct rec_diag_hdr), page_code)) {
		return (status);
	}

	/* Check */
	if ((hdr.page_code != page_code) || (hdr.page_len == 0)) {
		return (L_RD_PG_INVLD_CODE);
	}
	size = HEADER_LEN + hdr.page_len;
	/*
	 * Because of a hardware restriction in the soc+ chip
	 * the transfers must be word aligned.
	 */
	while (size & 0x03) {
		size++;
		if (size > buf_size) {
			return (L_RD_PG_MIN_BUFF);
		}
		P_DPRINTF("  l_get_envsen_page: Adjusting size of the "
			"g_scsi_rec_diag_cmd buffer.\n");
	}

	if ((pg = (uchar_t *)g_zalloc(size)) == NULL) {
		return (L_MALLOC_FAILED);
	}

	P_DPRINTF("  l_get_envsen_page: Reading page %x of size 0x%x\n",
		page_code, size);
	if (status = g_scsi_rec_diag_cmd(fd, pg, size, page_code)) {
		(void) g_destroy_data((char *)pg);
		return (status);
	}

	new_size = MIN(size, buf_size);
	bcopy((const void *)pg, (void *)buf, (size_t)new_size);

	(void) g_destroy_data(pg);
	return (0);
}



/*
 * Get consolidated copy of all environmental information
 * into buf structure.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */

int
l_get_envsen(char *path_phys, uchar_t *buf, int size, int verbose)
{
int		fd, rval;
uchar_t		*page_list_ptr, page_code, *local_buf_ptr = buf;
Rec_diag_hdr	*hdr = (struct rec_diag_hdr *)(void *)buf;
ushort_t	num_pages;

	if ((path_phys == NULL) || (buf == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	page_code = L_PAGE_PAGE_LIST;

	/* open IB */
	if ((fd = g_object_open(path_phys, O_NDELAY | O_RDONLY)) == -1)
		return (L_OPEN_PATH_FAIL);

	P_DPRINTF("  l_get_envsen: Getting list of supported"
		" pages from IB\n");
	if (verbose) {
		(void) fprintf(stdout,
		MSGSTR(9047, "  Getting list of supported pages from IB\n"));
	}

	/* Get page 0 */
	if ((rval = l_get_envsen_page(fd, local_buf_ptr,
		size, page_code, verbose)) != NULL) {
		(void) close(fd);
		return (rval);
	}

	page_list_ptr = buf + HEADER_LEN + 1; /* +1 to skip page 0 */

	num_pages = hdr->page_len - 1;

	/*
	 * check whether the number of pages received
	 * from IB are valid. SENA enclosure
	 * supports only 8 pages of sense information.
	 * According to SES specification dpANS X3.xxx-1997
	 * X3T10/Project 1212-D/Rev 8a, the enclosure supported
	 * pages can go upto L_MAX_POSSIBLE_PAGES (0xFF).
	 * Return an error if no. of pages exceeds L_MAX_POSSIBLE_PAGES.
	 * See if (num_pages >= L_MAX_POSSIBLE_PAGES) since 1 page (page 0)
	 * was already subtracted from the total number of pages before.
	 */
	if (num_pages < 1 || num_pages >= L_MAX_POSSIBLE_PAGES) {
		return (L_INVALID_NO_OF_ENVSEN_PAGES);
	}
	/*
	 * Buffer size of MAX_REC_DIAG_LENGTH can be small if the
	 * number of pages exceed more than L_MAX_SENAIB_PAGES
	 * but less than L_MAX_POSSIBLE_PAGES.
	 */
	if (size == MAX_REC_DIAG_LENGTH &&
			num_pages >= L_MAX_SENAIB_PAGES) {
		return (L_INVALID_BUF_LEN);
	}
	/* Align buffer */
	while (hdr->page_len & 0x03) {
		hdr->page_len++;
	}
	local_buf_ptr += HEADER_LEN + hdr->page_len;

	/*
	 * Getting all pages and appending to buf
	 */
	for (; num_pages--; page_list_ptr++) {
		/*
		 * The fifth byte of page 0 is the start
		 * of the list of pages not including page 0.
		 */
		page_code = *page_list_ptr;

		if ((rval = l_get_envsen_page(fd, local_buf_ptr,
			size, page_code, verbose)) != NULL) {
			(void) close(fd);
			return (rval);
		}
		hdr = (struct rec_diag_hdr *)(void *)local_buf_ptr;
		local_buf_ptr += HEADER_LEN + hdr->page_len;
	}

	(void) close(fd);
	return (0);
}



/*
 * Get the individual disk status.
 * Path must be physical and point to a disk.
 *
 * This function updates the d_state_flags, port WWN's
 * and num_blocks for all accessiable ports
 * in l_disk_state->g_disk_state structure.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_disk_status(char *path, struct l_disk_state_struct *l_disk_state,
	WWN_list *wwn_list, int verbose)
{
struct dlist	*ml;
char		path_a[MAXPATHLEN], path_b[MAXPATHLEN], ses_path[MAXPATHLEN];
gfc_map_t	map;
int		path_a_found = 0, path_b_found = 0, local_port_a_flag;
uchar_t		node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
int		al_pa, err, pathcnt = 1;
int		i = 0;
char		temppath[MAXPATHLEN];
mp_pathlist_t	pathlist;
char		pwwn[WWN_S_LEN];
struct		stat sbuf;

	if ((path == NULL) || (l_disk_state == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	/* Check device name */
	if (stat(path, &sbuf) || (sbuf.st_rdev == NODEV)) {
		G_DPRINTF("  l_get_disk_status: invalid device %s\n", path);
		return (L_INVALID_PATH);
	}

	/* Initialize */
	*path_a = *path_b = NULL;
	l_disk_state->g_disk_state.num_blocks = 0;

	/* Get paths. */
	g_get_multipath(path,
		&(l_disk_state->g_disk_state.multipath_list),
		wwn_list, verbose);
	ml = l_disk_state->g_disk_state.multipath_list;
	if (ml == NULL) {
		l_disk_state->l_state_flag = L_NO_PATH_FOUND;
		G_DPRINTF("  l_get_disk_status: Error finding a "
			"multipath to the disk.\n");
		return (0);
	}

	if (strstr(path, SCSI_VHCI) != NULL) {
		/*
		 * It is an MPXIO Path
		 */
		(void) strcpy(temppath, path);
		if (g_get_pathlist(temppath, &pathlist)) {
			return (0);
		}
		pathcnt = pathlist.path_count;
		for (i = 0; i < pathcnt; i++) {
			/*
			 * Skip inactive paths.
			 * A path that is not in either
			 * MDI_PATHINFO_STATE_ONLINE or
			 * MDI_PATHINFO_STATE_STANDBY state is not
			 * an active path.
			 *
			 * When a disk port is bypassed and mpxio is
			 * enabled, the path_state for that path goes to the
			 * offline state
			 */
			if (pathlist.path_info[i].path_state !=
			    MDI_PATHINFO_STATE_ONLINE &&
			    pathlist.path_info[i].path_state !=
			    MDI_PATHINFO_STATE_STANDBY) {
				continue;
			}
			(void) strncpy(pwwn, pathlist.path_info[i].path_addr,
								L_WWN_LENGTH);
			pwwn[L_WWN_LENGTH] = '\0';
			if (!(path_a_found || path_b_found)) {
				if (pwwn[1] == '1') {
					local_port_a_flag = 1;
				} else {
					local_port_a_flag = 0;
				}
			} else if (path_a_found &&
				(strstr(l_disk_state->g_disk_state.port_a_wwn_s,
							pwwn) == NULL)) {
				/* do port b */
				local_port_a_flag = 0;
			} else if (path_b_found &&
				(strstr(l_disk_state->g_disk_state.port_b_wwn_s,
							pwwn) == NULL)) {
				/* do port a */
				local_port_a_flag = 1;
			}

			if (err = l_get_disk_port_status(path,
				l_disk_state, local_port_a_flag, verbose)) {
				return (err);
			}

			if (local_port_a_flag && (!path_a_found)) {
				(void) strcpy(l_disk_state->
					g_disk_state.port_a_wwn_s, pwwn);
				l_disk_state->g_disk_state.port_a_valid++;
				path_a_found++;
			}

			if ((!local_port_a_flag) && (!path_b_found)) {
				(void) strcpy(l_disk_state->
					g_disk_state.port_b_wwn_s, pwwn);
				l_disk_state->g_disk_state.port_b_valid++;
				path_b_found++;
			}
		}
		free(pathlist.path_info);
		return (0);
	}

	while (ml && (!(path_a_found && path_b_found))) {
		if (err = g_get_dev_map(ml->dev_path, &map, verbose)) {
			(void) g_free_multipath(ml);
			return (err);
		}
		if ((err = l_get_ses_path(ml->dev_path, ses_path,
			&map, verbose)) != 0) {
			(void) g_free_multipath(ml);
			free((void *)map.dev_addr);
			return (err);
		}
		free((void *)map.dev_addr);	/* Not used anymore */

		/*
		 * Get the port, A or B, of the disk,
		 * by passing the IB path.
		 */
		if (err = l_get_port(ses_path, &local_port_a_flag, verbose)) {
			(void) g_free_multipath(ml);
			return (err);
		}
		if (local_port_a_flag && (!path_a_found)) {
			G_DPRINTF("  l_get_disk_status: Path to Port A "
				"found: %s\n", ml->dev_path);
			if (err = l_get_disk_port_status(ml->dev_path,
				l_disk_state, local_port_a_flag, verbose)) {
				(void) g_free_multipath(ml);
				return (err);
			}
			if (err = g_get_wwn(ml->dev_path,
				port_wwn, node_wwn,
				&al_pa, verbose)) {
				(void) g_free_multipath(ml);
				return (err);
			}
			(void) sprintf(l_disk_state->g_disk_state.port_a_wwn_s,
			"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
			port_wwn[0], port_wwn[1], port_wwn[2], port_wwn[3],
			port_wwn[4], port_wwn[5], port_wwn[6], port_wwn[7]);

			l_disk_state->g_disk_state.port_a_valid++;
			path_a_found++;
		}
		if ((!local_port_a_flag) && (!path_b_found)) {
			G_DPRINTF("  l_get_disk_status: Path to Port B "
				"found: %s\n", ml->dev_path);
			if (err = l_get_disk_port_status(ml->dev_path,
				l_disk_state, local_port_a_flag, verbose)) {
				return (err);
			}
			if (err = g_get_wwn(ml->dev_path,
				port_wwn, node_wwn,
				&al_pa, verbose)) {
				(void) g_free_multipath(ml);
				return (err);
			}
			(void) sprintf(l_disk_state->g_disk_state.port_b_wwn_s,
			"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
			port_wwn[0], port_wwn[1], port_wwn[2], port_wwn[3],
			port_wwn[4], port_wwn[5], port_wwn[6], port_wwn[7]);

			l_disk_state->g_disk_state.port_b_valid++;
			path_b_found++;
		}
		ml = ml->next;
	}
	return (0);


}



/*
 * Check for Persistent Reservations.
 */
int
l_persistent_check(int fd, struct l_disk_state_struct *l_disk_state,
	int verbose)
{
int	status;
Read_keys	read_key_buf;
Read_reserv	read_reserv_buf;

	(void) memset(&read_key_buf, 0, sizeof (struct  read_keys_struct));
	if ((status = g_scsi_persistent_reserve_in_cmd(fd,
		(uchar_t *)&read_key_buf, sizeof (struct  read_keys_struct),
		ACTION_READ_KEYS))) {
		return (status);
	}
	/* This means persistent reservations are supported by the disk. */
	l_disk_state->g_disk_state.persistent_reserv_flag = 1;

	if (read_key_buf.rk_length) {
		l_disk_state->g_disk_state.persistent_registered = 1;
	}

	(void) memset(&read_reserv_buf, 0,
			sizeof (struct  read_reserv_struct));
	if ((status = g_scsi_persistent_reserve_in_cmd(fd,
		(uchar_t *)&read_reserv_buf,
		sizeof (struct  read_reserv_struct),
		ACTION_READ_RESERV))) {
		return (status);
	}
	if (read_reserv_buf.rr_length) {
		l_disk_state->g_disk_state.persistent_active = 1;
	}
	if (verbose) {
		(void) fprintf(stdout,
		MSGSTR(9048, "  Checking for Persistent "
			"Reservations:"));
		if (l_disk_state->g_disk_state.persistent_reserv_flag) {
		    if (l_disk_state->g_disk_state.persistent_active != NULL) {
			(void) fprintf(stdout, MSGSTR(39, "Active"));
		    } else {
			(void) fprintf(stdout, MSGSTR(9049, "Registered"));
		    }
		} else {
			(void) fprintf(stdout,
			MSGSTR(87,
			"Not being used"));
		}
		(void) fprintf(stdout, "\n");
	}
	return (0);
}



/*
 * Gets the disk status and
 * updates the l_disk_state_struct structure.
 * Checks for open fail, Reservation Conflicts,
 * Not Ready and so on.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_disk_port_status(char *path, struct l_disk_state_struct *l_disk_state,
	int port_a_flag, int verbose)
{
int		fd, status = 0, local_state = 0;
Read_capacity_data	capacity;	/* local read capacity buffer */
struct vtoc	vtoc;

	if ((path == NULL) || (l_disk_state == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	/*
	 * Try to open drive.
	 */
	if ((fd = g_object_open(path, O_RDONLY)) == -1) {
	    if ((fd = g_object_open(path,
		O_RDONLY | O_NDELAY)) == -1) {
		G_DPRINTF("  l_get_disk_port_status: Error "
			"opening drive %s\n", path);
		local_state = L_OPEN_FAIL;
	    } else {
		/* See if drive ready */
		if (status = g_scsi_tur(fd)) {
			if ((status & L_SCSI_ERROR) &&
				((status & ~L_SCSI_ERROR) == STATUS_CHECK)) {
				/*
				 * TBD
				 * This is where I should figure out
				 * if the device is Not Ready or whatever.
				 */
				local_state = L_NOT_READY;
			} else if ((status & L_SCSI_ERROR) &&
			    ((status & ~L_SCSI_ERROR) ==
			    STATUS_RESERVATION_CONFLICT)) {
			    /* mark reserved */
			    local_state = L_RESERVED;
			} else {
				local_state = L_SCSI_ERR;
			}

		/*
		 * There may not be a label on the drive - check
		 */
		} else if (ioctl(fd, DKIOCGVTOC, &vtoc) == 0) {
			/*
			 * Sanity-check the vtoc
			 */
		    if (vtoc.v_sanity != VTOC_SANE ||
			vtoc.v_sectorsz != DEV_BSIZE) {
			local_state = L_NO_LABEL;
			G_DPRINTF("  l_get_disk_port_status: "
				"Checking vtoc - No Label found.\n");
		    }
		} else if (errno != ENOTSUP) {
		    I_DPRINTF("\t- DKIOCGVTOC ioctl failed: "
		    " invalid geometry\n");
		    local_state = L_NO_LABEL;
		}
	    }
	}
	/*
	 * Need an extra check for tape devices
	 * read capacity should not be run on tape devices.
	 * It will always return Not Readable
	 */
	if (((local_state == 0) || (local_state == L_NO_LABEL)) &&
		! (strstr(path, SLSH_DRV_NAME_ST))) {

	    if (status = g_scsi_read_capacity_cmd(fd, (uchar_t *)&capacity,
		sizeof (capacity))) {
			G_DPRINTF("  l_get_disk_port_status: "
				"Read Capacity failed.\n");
		if (status & L_SCSI_ERROR) {
		    if ((status & ~L_SCSI_ERROR) ==
			STATUS_RESERVATION_CONFLICT) {
			/* mark reserved */
			local_state |= L_RESERVED;
		    } else
			/* mark bad */
			local_state |= L_NOT_READABLE;
		} else {
			/*
			 * TBD
			 * Need a more complete state definition here.
			 */
			l_disk_state->g_disk_state.d_state_flags[port_a_flag] =
								L_SCSI_ERR;
			(void) close(fd);
			return (0);
		}
	    } else {
		/* save capacity */
		l_disk_state->g_disk_state.num_blocks =
					capacity.last_block_addr + 1;
	    }

	}
	(void) close(fd);

	l_disk_state->g_disk_state.d_state_flags[port_a_flag] = local_state;
	G_DPRINTF("  l_get_disk_port_status: Individual Disk"
		" Status: 0x%x for"
		" port %s for path:"
		" %s\n", local_state,
		port_a_flag ? "A" : "B", path);

	return (0);
}



/*
 * Copy and format page 1 from big buffer to state structure.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */

static int
copy_config_page(struct l_state_struct *l_state, uchar_t *from_ptr)
{
IB_page_config	*encl_ptr;
int		size, i;


	encl_ptr = (struct ib_page_config *)(void *)from_ptr;

	/* Sanity check. */
	if ((encl_ptr->enc_len > MAX_VEND_SPECIFIC_ENC) ||
		(encl_ptr->enc_len == 0)) {
		return (L_REC_DIAG_PG1);
	}
	if ((encl_ptr->enc_num_elem > MAX_IB_ELEMENTS) ||
		(encl_ptr->enc_num_elem == 0)) {
		return (L_REC_DIAG_PG1);
	}

	size = HEADER_LEN + 4 + HEADER_LEN + encl_ptr->enc_len;
	bcopy((void *)(from_ptr),
		(void *)&l_state->ib_tbl.config, (size_t)size);
	/*
	 * Copy Type Descriptors seperately to get aligned.
	 */
	from_ptr += size;
	size = (sizeof (struct	type_desc_hdr))*encl_ptr->enc_num_elem;
	bcopy((void *)(from_ptr),
		(void *)&l_state->ib_tbl.config.type_hdr, (size_t)size);

	/*
	 * Copy Text Descriptors seperately to get aligned.
	 *
	 * Must use the text size from the Type Descriptors.
	 */
	from_ptr += size;
	for (i = 0; i < (int)l_state->ib_tbl.config.enc_num_elem; i++) {
		size = l_state->ib_tbl.config.type_hdr[i].text_len;
		bcopy((void *)(from_ptr),
			(void *)&l_state->ib_tbl.config.text[i], (size_t)size);
		from_ptr += size;
	}
	return (0);
}



/*
 * Copy page 7 (Element Descriptor page) to state structure.
 * Copy header then copy each element descriptor
 * seperately.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
static void
copy_page_7(struct l_state_struct *l_state, uchar_t *from_ptr)
{
uchar_t	*my_from_ptr;
int	size, j, k, p7_index;

	size = HEADER_LEN +
		sizeof (l_state->ib_tbl.p7_s.gen_code);
	bcopy((void *)(from_ptr),
		(void *)&l_state->ib_tbl.p7_s, (size_t)size);
	my_from_ptr = from_ptr + size;
	if (getenv("_LUX_D_DEBUG") != NULL) {
		g_dump("  copy_page_7: Page 7 header:  ",
		(uchar_t *)&l_state->ib_tbl.p7_s, size,
		HEX_ASCII);
		(void) fprintf(stdout,
			"  copy_page_7: Elements being stored "
			"in state table\n"
			"              ");
	}
	/* I am assuming page 1 has been read. */
	for (j = 0, p7_index = 0;
		j < (int)l_state->ib_tbl.config.enc_num_elem; j++) {
		/* Copy global element */
		size = HEADER_LEN +
			((*(my_from_ptr + 2) << 8) | *(my_from_ptr + 3));
		bcopy((void *)(my_from_ptr),
		(void *)&l_state->ib_tbl.p7_s.element_desc[p7_index++],
			(size_t)size);
		my_from_ptr += size;
		for (k = 0; k < (int)l_state->ib_tbl.config.type_hdr[j].num;
			k++) {
			/* Copy individual elements */
			size = HEADER_LEN +
				((*(my_from_ptr + 2) << 8) |
					*(my_from_ptr + 3));
			bcopy((void *)(my_from_ptr),
			(void *)&l_state->ib_tbl.p7_s.element_desc[p7_index++],
				(size_t)size);
			my_from_ptr += size;
			D_DPRINTF(".");
		}
	}
	D_DPRINTF("\n");
}


/*
 * Gets IB diagnostic pages on a given pathname from l_get_envsen().
 * It also fills up the individual device element of l_state_struct using
 * diagnostics pages.
 * Gets IB diagnostic pages on a given pathname from l_get_envsen().
 * It also fills up the individual device element of l_state_struct using
 * diagnostics pages.
 *
 * The path must be of the ses driver.
 * e.g.
 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
 * or
 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@WWN,0:0
 *
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_ib_status(char *path, struct l_state_struct *l_state,
	int verbose)
{
L_inquiry	inq;
uchar_t		*ib_buf, *from_ptr;
int		num_pages, i, size, err;
IB_page_2	*encl_ptr;
int		front_index, rear_index;
int		enc_type = 0;

	if ((path == NULL) || (l_state == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	/*
	 * get big buffer
	 */
	if ((ib_buf = (uchar_t *)calloc(1,
				MAX_REC_DIAG_LENGTH)) == NULL) {
		return (L_MALLOC_FAILED);
	}

	/*
	 * Get IB information
	 * Even if there are 2 IB's in this box on this loop don't bother
	 * talking to the other one as both IB's in a box
	 * are supposed to report the same information.
	 */
	if (err = l_get_envsen(path, ib_buf, MAX_REC_DIAG_LENGTH,
		verbose)) {
		(void) g_destroy_data(ib_buf);
		return (err);
	}

	/*
	 * Set up state structure
	 */
	bcopy((void *)ib_buf, (void *)&l_state->ib_tbl.p0,
		(size_t)sizeof (struct  ib_page_0));

	num_pages = l_state->ib_tbl.p0.page_len;
	from_ptr = ib_buf + HEADER_LEN + l_state->ib_tbl.p0.page_len;

	for (i = 1; i < num_pages; i++) {
		if (l_state->ib_tbl.p0.sup_page_codes[i] == L_PAGE_1) {
			if (err = copy_config_page(l_state, from_ptr)) {
				return (err);
			}
		} else if (l_state->ib_tbl.p0.sup_page_codes[i] ==
								L_PAGE_2) {
			encl_ptr = (struct ib_page_2 *)(void *)from_ptr;
			size = HEADER_LEN + encl_ptr->page_len;
			bcopy((void *)(from_ptr),
				(void *)&l_state->ib_tbl.p2_s, (size_t)size);
			if (getenv("_LUX_D_DEBUG") != NULL) {
				g_dump("  l_get_ib_status: Page 2:  ",
				(uchar_t *)&l_state->ib_tbl.p2_s, size,
				HEX_ONLY);
			}

		} else if (l_state->ib_tbl.p0.sup_page_codes[i] ==
								L_PAGE_7) {
			(void) copy_page_7(l_state, from_ptr);
		}
		from_ptr += ((*(from_ptr + 2) << 8) | *(from_ptr + 3));
		from_ptr += HEADER_LEN;
	}
	(void) g_destroy_data(ib_buf);
	G_DPRINTF("  l_get_ib_status: Read %d Receive Diagnostic pages "
		"from the IB.\n", num_pages);

	if (err = g_get_inquiry(path, &inq)) {
		return (err);
	}
	enc_type = l_get_enc_type(inq);
	/*
	 * Get the total number of drives per box.
	 * This assumes front & rear are the same.
	 */
	l_state->total_num_drv = 0; /* default to use as a flag */
	for (i = 0; i < (int)l_state->ib_tbl.config.enc_num_elem; i++) {
		if (l_state->ib_tbl.config.type_hdr[i].type == ELM_TYP_DD) {
			if (l_state->total_num_drv) {
				if (l_state->total_num_drv !=
				(l_state->ib_tbl.config.type_hdr[i].num * 2)) {
					return (L_INVALID_NUM_DISKS_ENCL);
				}
			} else {
				if (enc_type == DAK_ENC_TYPE) {
				    l_state->total_num_drv =
				    l_state->ib_tbl.config.type_hdr[i].num;
				} else {
				    l_state->total_num_drv =
				    l_state->ib_tbl.config.type_hdr[i].num * 2;
				}
			}
		}
	}

	/*
	 * transfer the individual drive Device Element information
	 * from IB state to drive state.
	 */
	if (err = l_get_disk_element_index(l_state, &front_index,
		&rear_index)) {
		return (err);
	}
	/* Skip global element */
	front_index++;
	if (enc_type == DAK_ENC_TYPE) {
		rear_index += l_state->total_num_drv/2 + 1;
	} else {
		rear_index++;
	}

	for (i = 0; i < l_state->total_num_drv/2; i++) {
		bcopy((void *)&l_state->ib_tbl.p2_s.element[front_index + i],
			(void *)&l_state->drv_front[i].ib_status,
			(size_t)sizeof (struct device_element));
		bcopy((void *)&l_state->ib_tbl.p2_s.element[rear_index + i],
			(void *)&l_state->drv_rear[i].ib_status,
			(size_t)sizeof (struct device_element));
	}
	if (getenv("_LUX_G_DEBUG") != NULL) {
		g_dump("  l_get_ib_status: disk elements:  ",
		(uchar_t *)&l_state->ib_tbl.p2_s.element[front_index],
		((sizeof (struct device_element)) * (l_state->total_num_drv)),
		HEX_ONLY);
	}

	return (0);
}



/*
 * Given an IB path get the port, A or B.
 *
 * OUTPUT:
 *	port_a:	sets to 1 for port A
 *		and 0 for port B.
 * RETURNS:
 *	err:	0 O.k.
 *		non-zero otherwise
 */
int
l_get_port(char *ses_path, int *port_a, int verbose)
{
L_state	*ib_state = NULL;
Ctlr_elem_st	ctlr;
int	i, err, elem_index = 0;

	if ((ses_path == NULL) || (port_a == NULL)) {
		return (L_NO_SES_PATH);
	}

	if ((ib_state = (L_state *)calloc(1, sizeof (L_state))) == NULL) {
		return (L_MALLOC_FAILED);
	}

	bzero(&ctlr, sizeof (ctlr));
	if (err = l_get_ib_status(ses_path, ib_state, verbose)) {
		(void) l_free_lstate(&ib_state);
		return (err);
	}

	for (i = 0; i < (int)ib_state->ib_tbl.config.enc_num_elem; i++) {
	    elem_index++;		/* skip global */
	    if (ib_state->ib_tbl.config.type_hdr[i].type == ELM_TYP_IB) {
		bcopy((const void *)
			&ib_state->ib_tbl.p2_s.element[elem_index],
			(void *)&ctlr, sizeof (ctlr));
		break;
	    }
	    elem_index += ib_state->ib_tbl.config.type_hdr[i].num;
	}
	*port_a = ctlr.report;
	G_DPRINTF("  l_get_port: Found ses is the %s card.\n",
		ctlr.report ? "A" : "B");
	(void) l_free_lstate(&ib_state);
	return (0);
}

/*
 * This function expects a pointer to a device path ending in the form
 * .../ses@w<NODEWWN>,<something> or .../ssd@w<NODEWWN>,<something>
 *
 * No validity checking of the path is done by the function.
 *
 * It gets the wwn (node wwn) out of the passed string, searches the passed
 * map for a match, gets the corresponding phys addr (port id) for that entry
 * and stores in the pointer the caller has passed as an argument (pid)
 *
 * This function is to be called only for public/fabric topologies
 *
 * If this interface is going to get exported, one point to be
 * considered is if a call to g_get_path_type() has to be made.
 *
 * INPUT:
 * path - pointer to the enclosure/disk device path
 * map - pointer to the map
 *
 * OUTPUT:
 * pid - the physical address associated for the node WWN that was found
 *       in the map
 *
 * RETURNS:
 * 0 - on success
 * non-zero - otherwise
 */
int
l_get_pid_from_path(const char *path, const gfc_map_t *map, int *pid)
{
int			i;
unsigned long long	ll_wwn;
char			*char_ptr, wwn_str[WWN_SIZE * 2 + 1];
char			*byte_ptr, *temp_ptr;
gfc_port_dev_info_t	*dev_addr_ptr;
mp_pathlist_t		pathlist;
char			path0[MAXPATHLEN], pwwn0[WWN_S_LEN];

	/* if mpxio device */
	if (strstr(path, SCSI_VHCI) != NULL) {
		(void) strcpy(path0, path);
		if (g_get_pathlist(path0, &pathlist)) {
			return (L_INVALID_PATH);
		} else {
			(void) strncpy(pwwn0, pathlist.path_info[0].
				path_addr, L_WWN_LENGTH);
			pwwn0[L_WWN_LENGTH] = '\0';
			free(pathlist.path_info);
			char_ptr = pwwn0;
		}
	} else {
		/* First a quick check on the path */
		if (((char_ptr = strrchr(path, '@')) == NULL) ||
					(*++char_ptr != 'w')) {
			return (L_INVALID_PATH);
		} else {
			char_ptr++;
		}
	}

	if (strlen(char_ptr) < (WWN_SIZE * 2)) {
		return (L_INVALID_PATH);
	}
	(void) strncpy(wwn_str, char_ptr, WWN_SIZE * 2);
	wwn_str[WWN_SIZE * 2] = '\0';
	errno = 0;	/* For error checking */
	ll_wwn = strtoull(wwn_str, &temp_ptr, L_WWN_LENGTH);

	if (errno || (temp_ptr != (wwn_str + (WWN_SIZE * 2)))) {
		return (L_INVALID_PATH);
	}

	byte_ptr = (char *)&ll_wwn;

	/*
	 * Search for the ses's node wwn in map to get the area and
	 * domain ids from the corresponding port id (phys address).
	 */
	for (dev_addr_ptr = map->dev_addr, i = 0; i < map->count;
						dev_addr_ptr++, i++) {
		if (bcmp((char *)dev_addr_ptr->gfc_port_dev.
			pub_port.dev_nwwn.raw_wwn, byte_ptr, WWN_SIZE) == 0)
			break;
	}
	if (i >= map->count)
		return (L_INVALID_PATH);
	*pid = dev_addr_ptr->gfc_port_dev.pub_port.dev_did.port_id;
	return (0);
}


/*
 * Finds the disk's node wwn string, and
 * port A and B's WWNs and their port status.
 *
 * INPUT:
 * path		- pointer to a ses path
 * wwn_list	- pointer to the wwn_list
 *
 * OUTPUT:
 * state	- node_wwn and wwn of ports A & B of disk, etc are inited
 *		- by l_get_disk_status()
 * found_flag	- incremented after each examined element in the map
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise.
 */
static int
l_get_node_status(char *path, struct l_disk_state_struct *state,
	int *found_flag, WWN_list *wwn_list, int verbose)
{
int		j, select_id, err;
int		path_pid;
char		temp_path[MAXPATHLEN];
char		sbuf[MAXPATHLEN], *char_ptr;
gfc_map_mp_t	*map_mp, *map_ptr;
struct stat	stat_buf;
WWN_list	*wwnlp;
char		wwnp[WWN_S_LEN];

	/*
	 * Get a new map.
	 */
	map_mp = NULL;
	if (err = get_mp_dev_map(path, &map_mp, verbose))
		return (err);

	for (map_ptr = map_mp; map_ptr != NULL; map_ptr = map_ptr->map_next) {
	    switch (map_ptr->map.hba_addr.port_topology) {
		case FC_TOP_PRIVATE_LOOP:
		    for (j = 0; j < map_ptr->map.count; j++) {
			/*
			 * Get a generic path to a device
			 *
			 * This assumes the path looks something like this
			 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/...
			 *					...ses@x,0:0
			 * then creates a path that looks like
			 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ssd@
			 */
			(void) strcpy(temp_path, path);
			if ((char_ptr = strrchr(temp_path, '/')) == NULL) {
				free_mp_dev_map(&map_mp);
				return (L_INVALID_PATH);
			}
			*char_ptr = '\0';   /* Terminate sting  */
			(void) strcat(temp_path, SLSH_DRV_NAME_SSD);
			/*
			 * Create complete path.
			 *
			 * Build entry ssd@xx,0:c,raw
			 * where xx is the WWN.
			 */
			select_id = g_sf_alpa_to_switch[map_ptr->map.
			    dev_addr[j].gfc_port_dev.priv_port.sf_al_pa];
			G_DPRINTF("  l_get_node_status: Searching loop map "
				"to find disk: ID:0x%x"
				" AL_PA:0x%x\n", select_id,
				state->ib_status.sel_id);

		if (strstr(path, SCSI_VHCI) == NULL) {

			(void) sprintf(sbuf,
			"w%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x,0:c,raw",
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[0],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[1],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[2],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[3],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[4],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[5],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[6],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_port_wwn[7]);
			(void) strcat(temp_path, sbuf);

		}
			/*
			 * If we find a device on this loop in this box
			 * update its status.
			 */
			if (state->ib_status.sel_id == select_id) {
				/*
				 * Found a device on this loop in this box.
				 *
				 * Update state.
				 */
				(void) sprintf(state->g_disk_state.node_wwn_s,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[0],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[1],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[2],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[3],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[4],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[5],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[6],
				map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
								sf_node_wwn[7]);

	if (strstr(path, SCSI_VHCI) != NULL) {
		(void) g_ll_to_str(map_ptr->map.dev_addr[j].gfc_port_dev.
			priv_port.sf_node_wwn, wwnp);
		for (wwnlp = wwn_list; wwnlp != NULL;
			wwnlp = wwnlp->wwn_next) {
			if (strcmp(wwnlp->node_wwn_s, wwnp) == 0) {
			(void) strcpy(temp_path, wwnlp->physical_path);
				break;
			}
		}
		if (wwnlp == NULL) {
			(void) sprintf(sbuf,
		"g%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x:c,raw",
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[0],
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[1],
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[2],
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[3],
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[4],
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[5],
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[6],
			map_ptr->map.dev_addr[j].gfc_port_dev.priv_port.
							sf_node_wwn[7]);
			(void) strcat(temp_path, sbuf);
			/*
			 * check to make sure this is a valid path.
			 * Paths may not always be created on the
			 * host. So, we make a quick check.
			 */
			if (stat(temp_path, &stat_buf) == -1) {
				free_mp_dev_map(&map_mp);
				return (errno);
			}

		}
	}
		(void) strcpy(state->g_disk_state.physical_path,
			temp_path);


				/* Bad if WWN is all zeros. */
				if (is_null_wwn(map_ptr->map.dev_addr[j].
					    gfc_port_dev.priv_port.
					    sf_node_wwn)) {
					state->l_state_flag = L_INVALID_WWN;
					G_DPRINTF("  l_get_node_status: "
						"Disk state was "
						" Invalid WWN.\n");
					(*found_flag)++;
					free_mp_dev_map(&map_mp);
					return (0);
				}

				/* get device status */
				if (err = l_get_disk_status(temp_path, state,
							wwn_list, verbose)) {
					free_mp_dev_map(&map_mp);
					return (err);
				}
				/*
				 * found device in map.  Don't need to look
				 * any further
				 */
				(*found_flag)++;
				free_mp_dev_map(&map_mp);
				return (0);
			}
		    }	/* for loop */
		break;
	case FC_TOP_PUBLIC_LOOP:
	case FC_TOP_FABRIC:
		/*
		 * Get a generic path to a device
		 * This assumes the path looks something like this
		 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@wWWN,0:0
		 * then creates a path that looks like
		 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ssd@
		 */
		(void) strcpy(temp_path, path);
		if ((char_ptr = strrchr(temp_path, '/')) == NULL) {
			free_mp_dev_map(&map_mp);
			return (L_INVALID_PATH);
		}
		*char_ptr = '\0';   /* Terminate sting  */

		if (err = l_get_pid_from_path(path, &map_ptr->map, &path_pid)) {
			free_mp_dev_map(&map_mp);
			return (err);
		}

		/* Now append the ssd string */
		(void) strcat(temp_path, SLSH_DRV_NAME_SSD);

		/*
		 * Create complete path.
		 *
		 * Build entry ssd@WWN,0:c,raw
		 *
		 * First, search the map for a device with the area code and
		 * domain as in 'path_pid'.
		 */
		for (j = 0; j < map_ptr->map.count; j++) {
			if (map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
			    dev_dtype != DTYPE_ESI) {
				select_id = g_sf_alpa_to_switch[map_ptr->map.
				    dev_addr[j].gfc_port_dev.pub_port.dev_did.
				    port_id & 0xFF];

				if (((map_ptr->map.dev_addr[j].gfc_port_dev.
						    pub_port.dev_did.port_id &
						    AREA_DOMAIN_ID) ==
					    (path_pid & AREA_DOMAIN_ID)) &&
				    (state->ib_status.sel_id == select_id)) {
					/*
					 * Found the device. Update state.
					 */
		if (strstr(temp_path, SCSI_VHCI) == NULL) {
					(void) sprintf(sbuf,
			"w%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x,0:c,raw",
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[0],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[1],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[2],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[3],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[4],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[5],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[6],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_pwwn.raw_wwn[7]);
					(void) strcat(temp_path, sbuf);

					/*
					 * Paths for fabric cases may not always
					 * be created on the host. So, we make a
					 * quick check.
					 */
					if (stat(temp_path, &stat_buf) == -1) {
						free_mp_dev_map(&map_mp);
						return (errno);
					}

					(void) sprintf(state->
							g_disk_state.node_wwn_s,
				"%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x",
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[0],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[1],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[2],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[3],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[4],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[5],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[6],
					map_ptr->map.dev_addr[j].gfc_port_dev.
					pub_port.dev_nwwn.raw_wwn[7]);

		} else {
		(void) g_ll_to_str(map_ptr->map.dev_addr[j].gfc_port_dev.
			priv_port.sf_node_wwn, wwnp);
		for (wwnlp = wwn_list; wwnlp != NULL;
		wwnlp = wwnlp->wwn_next) {
			if (strcmp(wwnlp->node_wwn_s, wwnp) == 0) {
			(void) strcpy(temp_path, wwnlp->physical_path);
			break;
			}
		}
		if (wwnlp == NULL) {
			(void) sprintf(sbuf,
		"w%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x%1.2x,0:c,raw",
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[0],
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[1],
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[2],
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[3],
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[4],
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[5],
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[6],
			map_ptr->map.dev_addr[j].gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn[7]);
				(void) strcat(temp_path, sbuf);
		}
		}
		(void) strcpy(state->g_disk_state.physical_path,
		temp_path);

					/* Bad if WWN is all zeros. */
					if (is_null_wwn(map_ptr->map.
						    dev_addr[j].gfc_port_dev.
						    pub_port.dev_nwwn.
						    raw_wwn)) {
						state->l_state_flag =
								L_INVALID_WWN;
						G_DPRINTF(
						"  l_get_node_status: "
						"Disk state was "
						" Invalid WWN.\n");
						(*found_flag)++;
						free_mp_dev_map(&map_mp);
						return (0);
					}

					/* get device status */
					if (err = l_get_disk_status(temp_path,
						state, wwn_list, verbose)) {
						free_mp_dev_map(&map_mp);
						return (err);
					}

					(*found_flag)++;
					free_mp_dev_map(&map_mp);
					return (0);
				}	/* if select_id match */
			}	/* if !DTYPE_ESI */
		}		/* for loop */
		break;
	case FC_TOP_PT_PT:
		free_mp_dev_map(&map_mp);
		return (L_PT_PT_FC_TOP_NOT_SUPPORTED);
	default:
		free_mp_dev_map(&map_mp);
		return (L_UNEXPECTED_FC_TOPOLOGY);
	    }	/* End of switch on port_topology */

	}
	free_mp_dev_map(&map_mp);
	return (0);
}


/*
 * Get the individual drives status for the device specified by the index.
 * device at the path where the path is of the IB and updates the
 * g_disk_state_struct structure.
 *
 * If the disk's port is bypassed,  it gets the
 * drive status such as node WWN from the second port.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_individual_state(char *path,
	struct l_disk_state_struct *state, Ib_state *ib_state,
	int front_flag, struct box_list_struct *box_list,
	struct wwn_list_struct *wwn_list, int verbose)
{
int		found_flag = 0, elem_index = 0;
int		port_a_flag, err, j;
struct dlist	*seslist = NULL;
Bp_elem_st	bpf, bpr;
hrtime_t	start_time, end_time;

	if ((path == NULL) || (state == NULL) ||
	    (ib_state == NULL) || (box_list == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	start_time = gethrtime();


	if ((state->ib_status.code != S_NOT_INSTALLED) &&
		(state->ib_status.code != S_NOT_AVAILABLE)) {

		/*
		 * Disk could have been bypassed on this loop.
		 * Check the port state before l_state_flag
		 * is set to L_INVALID_MAP.
		 */
		for (j = 0;
		j < (int)ib_state->config.enc_num_elem;
		j++) {
			elem_index++;
			if (ib_state->config.type_hdr[j].type ==
							ELM_TYP_BP)
				break;
			elem_index +=
				ib_state->config.type_hdr[j].num;
		}

		/*
		 * check if port A & B of backplane are bypassed.
		 * If so, do not bother.
		 */
		if (front_flag) {
			bcopy((const void *)
			&(ib_state->p2_s.element[elem_index]),
			(void *)&bpf, sizeof (bpf));

			if ((bpf.byp_a_enabled || bpf.en_bypass_a) &&
				(bpf.byp_b_enabled || bpf.en_bypass_b))
				return (0);
		} else {
			/* if disk is in rear slot */
			bcopy((const void *)
			&(ib_state->p2_s.element[elem_index+1]),
			(void *)&bpr, sizeof (bpr));

			if ((bpr.byp_b_enabled || bpr.en_bypass_b) &&
				(bpr.byp_a_enabled || bpr.en_bypass_a))
				return (0);
		}

		if ((err = l_get_node_status(path, state,
				&found_flag, wwn_list, verbose)) != 0)
			return (err);

		if (!found_flag) {
			if ((err = l_get_allses(path, box_list,
						&seslist, 0)) != 0) {
				return (err);
			}

			if (err = l_get_port(path, &port_a_flag, verbose))
				goto done;

			if (port_a_flag) {
				if ((state->ib_status.bypass_a_en &&
					!(state->ib_status.bypass_b_en)) ||
					!(state->ib_status.bypass_b_en)) {
					while (seslist != NULL && !found_flag) {
						if (err = l_get_port(
							seslist->dev_path,
						&port_a_flag, verbose)) {
							goto done;
						}
						if ((strcmp(seslist->dev_path,
							path) != 0) &&
							!port_a_flag) {
							*path = NULL;
							(void) strcpy(path,
							seslist->dev_path);
							if (err =
							l_get_node_status(path,
							state, &found_flag,
							wwn_list, verbose)) {
								goto done;
							}
						}
						seslist = seslist->next;
					}
				}
			} else {
				if ((state->ib_status.bypass_b_en &&
					!(state->ib_status.bypass_a_en)) ||
					!(state->ib_status.bypass_a_en)) {
					while (seslist != NULL && !found_flag) {
						if (err = l_get_port(
							seslist->dev_path,
						&port_a_flag, verbose)) {
							goto done;
						}
						if ((strcmp(seslist->dev_path,
						path) != 0) && port_a_flag) {
							*path = NULL;
							(void) strcpy(path,
							seslist->dev_path);
							if (err =
							l_get_node_status(path,
							state, &found_flag,
							wwn_list, verbose)) {
								goto done;
							}
						}
						seslist = seslist->next;
					}
				}
			}
			if (!found_flag) {
				state->l_state_flag = L_INVALID_MAP;
				G_DPRINTF("  l_get_individual_state: "
					"Disk state was "
					"Not in map.\n");
			} else {
				G_DPRINTF("  l_get_individual_state: "
					"Disk was found in the map.\n");
			}

			if (seslist != NULL)
				(void) g_free_multipath(seslist);

		}

	} else {
		G_DPRINTF("  l_get_individual_state: Disk state was %s.\n",
			(state->ib_status.code == S_NOT_INSTALLED) ?
			"Not Installed" : "Not Available");
	}

	if (getenv("_LUX_T_DEBUG") != NULL) {
		end_time = gethrtime();
		(void) fprintf(stdout, "    l_get_individual_state:"
		"\tTime = %lld millisec\n",
		(end_time - start_time)/1000000);
	}

	return (0);
done:
	(void) g_free_multipath(seslist);
	return (err);
}



/*
 * Get the global state of the photon.
 *
 * INPUT:
 * path and verbose flag
 *
 * "path" must be of the ses driver.
 * e.g.
 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@e,0:0
 * or
 * /devices/sbus@1f,0/SUNW,socal@1,0/SUNW,sf@0,0/ses@WWN,0:0
 *
 * OUTPUT:
 * The struct l_state (which was passed in) has the status info
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_status(char *path, struct l_state_struct *l_state, int verbose)
{
int		err = 0, i, count;
L_inquiry	inq;
uchar_t		node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
int		al_pa, found_front, found_rear, front_flag, enc_type;
char		ses_path_front[MAXPATHLEN];
char		ses_path_rear[MAXPATHLEN];
Box_list	*b_list = NULL;
Box_list	*o_list = NULL;
char		node_wwn_s[(WWN_SIZE*2)+1];
uint_t		select_id;
hrtime_t	start_time, end_time;
WWN_list		*wwn_list = NULL;

	if ((path == NULL) || (l_state == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	start_time = gethrtime();

	G_DPRINTF("  l_get_status: Get Status for enclosure at: "
		" %s\n", path);

	/* initialization */
	(void) memset(l_state, 0, sizeof (struct l_state_struct));

	if (err = g_get_inquiry(path, &inq)) {
		return (err);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) &&
		(!(strncmp((char *)inq.inq_vid, "SUN     ",
		sizeof (inq.inq_vid)) &&
		((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)))) {
		return (L_ENCL_INVALID_PATH);
	}

	(void) strncpy((char *)l_state->ib_tbl.enclosure_name,
		(char *)inq.inq_box_name, sizeof (inq.inq_box_name));

	/*
	 * Get all of the IB Receive Diagnostic pages.
	 */
	if (err = l_get_ib_status(path, l_state, verbose)) {
		return (err);
	}

	/*
	 * Now get the individual devices information from
	 * the device itself.
	 *
	 * May need to use multiple paths to get to the
	 * front and rear drives in the box.
	 * If the loop is split some drives may not even be available
	 * from this host.
	 *
	 * The way this works is in the select ID the front disks
	 * are accessed via the IB with the bit 4 = 0
	 * and the rear disks by the IB with bit 4 = 1.
	 *
	 * First get device map from fc nexus driver for this loop.
	 */
	/*
	 * Get the boxes node WWN & al_pa for this path.
	 */
	if (err = g_get_wwn(path, port_wwn, node_wwn, &al_pa, verbose)) {
		return (err);
	}
	if (err = l_get_box_list(&o_list, verbose)) {
		(void) l_free_box_list(&o_list);
		return (err);	/* Failure */
	}

	found_front = found_rear = 0;
	for (i = 0; i < WWN_SIZE; i++) {
		(void) sprintf(&node_wwn_s[i << 1], "%02x", node_wwn[i]);
	}

	/*
	 * The al_pa (or pa) can be 24 bits in size for fabric loops.
	 * But we will take only the low order byte to get the select_id.
	 * Private loops have al_pa which is only a byte in size.
	 */
	select_id = g_sf_alpa_to_switch[al_pa & 0xFF];
	l_state->ib_tbl.box_id = (select_id & BOX_ID_MASK) >> 5;

	G_DPRINTF("  l_get_status: Using this select_id 0x%x "
		"and node WWN %s\n",
		select_id, node_wwn_s);

	if (strstr(path, SCSI_VHCI) != NULL) {
		/* there is no way to obtain all the al_pa with */
		/*  current implementation. assume both front   */
		/*  and rear. need changes later on. */
		found_rear = 1;
		found_front = 1;
		(void) strcpy(ses_path_rear, path);
		(void) strcpy(ses_path_front, path);
	} else {

	if (select_id & ALT_BOX_ID) {
		found_rear = 1;
		(void) strcpy(ses_path_rear, path);
		b_list = o_list;
		while (b_list) {
			if (strcmp(b_list->b_node_wwn_s, node_wwn_s) == 0) {
				if (err = g_get_wwn(b_list->b_physical_path,
					port_wwn, node_wwn,
					&al_pa, verbose)) {
					(void) l_free_box_list(&o_list);
					return (err);
				}

				/* Take the low order byte of al_pa */
				select_id = g_sf_alpa_to_switch[al_pa & 0xFF];
				if (!(select_id & ALT_BOX_ID)) {
					(void) strcpy(ses_path_front,
					b_list->b_physical_path);
					found_front = 1;
					break;
				}
			}
			b_list = b_list->box_next;
		}
	} else {
		(void) strcpy(ses_path_front, path);
		found_front = 1;
		b_list = o_list;
		while (b_list) {
			if (strcmp(b_list->b_node_wwn_s, node_wwn_s) == 0) {
				if (err = g_get_wwn(b_list->b_physical_path,
					port_wwn, node_wwn,
					&al_pa, verbose)) {
					(void) l_free_box_list(&o_list);
					return (err);
				}
				select_id = g_sf_alpa_to_switch[al_pa & 0xFF];
				if (select_id & ALT_BOX_ID) {
					(void) strcpy(ses_path_rear,
					b_list->b_physical_path);
					found_rear = 1;
					break;
				}
			}
			b_list = b_list->box_next;
		}
	}
	}

	if (getenv("_LUX_G_DEBUG") != NULL) {
		if (!found_front) {
		(void) printf("l_get_status: Loop to front disks not found.\n");
		}
		if (!found_rear) {
		(void) printf("l_get_status: Loop to rear disks not found.\n");
		}
	}

	/*
	 * Get path to all the FC disk and tape devices.
	 *
	 * I get this now and pass down for performance
	 * reasons.
	 * If for some reason the list can become invalid,
	 * i.e. device being offlined, then the list
	 * must be re-gotten.
	 */
	if (err = g_get_wwn_list(&wwn_list, verbose)) {
		return (err);   /* Failure */
	}

	enc_type = l_get_enc_type(inq);
	if (found_front) {
		front_flag = 1;
		for (i = 0, count = 0; i < l_state->total_num_drv/2;
							count++, i++) {
			if (enc_type == DAK_ENC_TYPE) {
				G_DPRINTF("  l_get_status: Getting individual"
				    " State for disk in slot %d\n", count);
			} else {
				G_DPRINTF("  l_get_status: Getting individual"
				    " State for front disk in slot %d\n", i);
			}
			if (err = l_get_individual_state(ses_path_front,
			(struct l_disk_state_struct *)&l_state->drv_front[i],
					&l_state->ib_tbl, front_flag, o_list,
					wwn_list, verbose)) {
				(void) l_free_box_list(&o_list);
				(void) g_free_wwn_list(&wwn_list);
				return (err);
			}
		}
	} else {
		/* Set to loop not accessable. */
		for (i = 0; i < l_state->total_num_drv/2; i++) {
			l_state->drv_front[i].l_state_flag = L_NO_LOOP;
		}
	}
	/*
	 * For Daktari's, disk 0-5 information are located in the
	 * l_state->drv_front array
	 * For Daktari's, disk 6-11 information are located in the
	 * l_state->drv_rear array
	 *
	 * For this reason, on daktari's, I ignore the found_front and
	 * found_rear flags and check both the drv_front and drv_rear
	 */

	if (enc_type == DAK_ENC_TYPE && found_front) {
		front_flag = 1;
		for (i = 0; i < l_state->total_num_drv/2; i++, count++) {
			G_DPRINTF("  l_get_status: Getting individual"
				    " State for disk in slot %d\n", count);
			if (err = l_get_individual_state(ses_path_front,
			(struct l_disk_state_struct *)&l_state->drv_rear[i],
					&l_state->ib_tbl, front_flag, o_list,
					wwn_list, verbose)) {
				(void) l_free_box_list(&o_list);
				(void) g_free_wwn_list(&wwn_list);
				return (err);
			}
		}
	} else if (enc_type != DAK_ENC_TYPE && found_rear) {
		for (i = 0; i < l_state->total_num_drv/2; i++, count++) {
				G_DPRINTF("  l_get_status: Getting individual"
					" State for rear disk in slot %d\n", i);
			if (err = l_get_individual_state(ses_path_rear,
			    (struct l_disk_state_struct *)&l_state->drv_rear[i],
			    &l_state->ib_tbl, front_flag, o_list,
			    wwn_list, verbose)) {
				(void) l_free_box_list(&o_list);
				(void) g_free_wwn_list(&wwn_list);
				return (err);
			}
		}
	} else if (enc_type != DAK_ENC_TYPE) {
		/* Set to loop not accessable. */
		for (i = 0; i < l_state->total_num_drv/2; i++) {
			l_state->drv_rear[i].l_state_flag = L_NO_LOOP;
		}
	}

	(void) l_free_box_list(&o_list);
	(void) g_free_wwn_list(&wwn_list);
	if (getenv("_LUX_T_DEBUG") != NULL) {
		end_time = gethrtime();
		(void) fprintf(stdout, "  l_get_status:   "
		"Time = %lld millisec\n",
		(end_time - start_time)/1000000);
	}

	return (0);
}



/*
 * Check the SENA file for validity:
 *	- verify the size is that of 3 proms worth of text.
 *	- verify PROM_MAGIC.
 *	- verify (and print) the date.
 *	- verify the checksum.
 *	- verify the WWN == 0.
 * Since this requires reading the entire file, do it now and pass a pointer
 * to the allocated buffer back to the calling routine (which is responsible
 * for freeing it).  If the buffer is not allocated it will be NULL.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */

static int
check_file(int fd, int verbose, uchar_t **buf_ptr, int dl_info_offset)
{
struct	exec	the_exec;
int		temp, i, j, *p, size, *start;
uchar_t		*buf;
char		*date_str;
struct	dl_info	*dl_info;

	*buf_ptr = NULL;

	/* read exec header */
	if (lseek(fd, 0, SEEK_SET) == -1)
		return (errno);
	if ((temp = read(fd, (char *)&the_exec, sizeof (the_exec))) == -1) {
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	if (temp != sizeof (the_exec)) {
	    return (L_DWNLD_READ_INCORRECT_BYTES);
	}

	if (the_exec.a_text != PROMSIZE) {
	    return (L_DWNLD_INVALID_TEXT_SIZE);
	}

	if (!(buf = (uchar_t *)g_zalloc(PROMSIZE)))
	    return (L_MALLOC_FAILED);

	if ((temp = read(fd, buf, PROMSIZE)) == -1) {
	    return (L_DWNLD_READ_ERROR);
	}

	if (temp != PROMSIZE) {
	    return (L_DWNLD_READ_INCORRECT_BYTES);
	}



	/* check the IB firmware MAGIC */
	dl_info = (struct dl_info *)(unsigned long)(buf + dl_info_offset);
	if (dl_info->magic != PROM_MAGIC) {
		return (L_DWNLD_BAD_FRMWARE);
	}

	/*
	 * Get the date
	 */

	date_str = ctime(&dl_info->datecode);

	if (verbose) {
		(void) fprintf(stdout,
		MSGSTR(9050, "  IB Prom Date: %s"),
		date_str);
	}

	/*
	 * verify checksum
	 */

	if (dl_info_offset == FPM_DL_INFO) {
		start = (int *)(long)(buf + FPM_OFFSET);
		size = FPM_SZ;
	} else {
		start = (int *)(long)buf;
		size = TEXT_SZ + IDATA_SZ;
	}

	for (j = 0, p = start, i = 0; i < (size/ 4); i++, j ^= *p++);

	if (j != 0) {
		return (L_DWNLD_CHKSUM_FAILED);
	}

	/* file verified */
	*buf_ptr = buf;

	return (0);
}

/*
 * Check the DPM file for validity:
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
#define	dakstring	"64616B74617269"
#define	dakoffs		"BFC00000"

static int
check_dpm_file(int fd)
{
	struct s3hdr {
	    char	rtype[2];
	    char	rlen[2];
	    char	data[255];
	} theRec;
	int nread;
	int reclen;

	if (fd < 0) {
	    return (L_DWNLD_READ_ERROR);
	}
	lseek(fd, 0, SEEK_SET);

	/* First record */
	memset((void*)&theRec, 0, sizeof (struct s3hdr));
	nread = read(fd, (void *)&theRec, 4);
	if (nread != 4) {
	    /* error reading first record/length */
	    return (L_DWNLD_READ_ERROR);
	}
	if (strncmp((char *)&theRec.rtype[0], "S0", 2) != 0) {
	    /* error in first record type */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	reclen = strtol(&theRec.rlen[0], (char **)NULL, 16);
	if (reclen == 0) {
	    /* error in length == 0 */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	nread = read(fd, (void *)&theRec.data[0], ((reclen*2) +1));
	if (nread != ((reclen*2) +1)) {
	    /* error in trying to read data */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	if (strncmp(&theRec.data[4], dakstring, 14) != 0) {
	    /* error in compiled file name */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}

	/* Second record */
	memset((void*)&theRec, 0, sizeof (struct s3hdr));
	nread = read(fd, (void *)&theRec, 4);
	if (nread != 4) {
	    /* error reading second record/length */
	    return (L_DWNLD_READ_ERROR);
	}
	if (strncmp((char *)&theRec.rtype[0], "S3", 2) != 0) {
	    /* error in second record type */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	reclen = strtol(&theRec.rlen[0], (char **)NULL, 16);
	if (reclen == 0) {
	    /* error in length == 0 */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	nread = read(fd, (void *)&theRec.data[0], ((reclen*2) +1));
	if (nread != ((reclen*2) +1)) {
	    /* error in trying to read data */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	if (strncmp(&theRec.data[0], dakoffs, 8) != 0) {
	    /* error in SSC100 offset pointer */
	    return (L_DWNLD_READ_HEADER_FAIL);
	}
	lseek(fd, 0, SEEK_SET);
	return (0);
}



int
l_check_file(char *file, int verbose)
{
int	file_fd;
int	err;
uchar_t	*buf;

	if ((file_fd = g_object_open(file, O_RDONLY)) == -1) {
	    return (L_OPEN_PATH_FAIL);
	}
	err = check_file(file_fd, verbose, &buf, FW_DL_INFO);
	if (buf)
		(void) g_destroy_data((char *)buf);
	return (err);
}



/*
 * Write buffer command set up to download
 * firmware to the Photon IB.
 *
 * RETURNS:
 *	status
 */
static int
ib_download_code_cmd(int fd, int promid, int off, uchar_t *buf_ptr,
						int buf_len, int sp)
{
int	status, sz;

	while (buf_len) {
		sz = MIN(256, buf_len);
		buf_len -= sz;
		status = g_scsi_writebuffer_cmd(fd, off, buf_ptr, sz,
						(sp) ? 3 : 2, promid);
		if (status)
			return (status);
		buf_ptr += sz;
		off += sz;
	}

	return (status);
}

/*
 *
 * Downloads the code to the DAKTARI/DPM with the hdr set correctly
 *
 *
 * Inputs:
 *	fd - int for the file descriptor
 *	buf_ptr - uchar_t pointer to the firmware itself
 *	buf_len - int for the length of the data
 *
 * Returns:
 *	status:  0 indicates success, != 0 failure, returned from writebuffer
 *
 */

static int
dak_download_code_cmd(int fd, uchar_t *buf_ptr, int buf_len)
{
	int 	status = 0;
	int	sz = 0;
	int	offs = 0;

	while (buf_len > 0) {
		sz = MIN(256, buf_len);
		buf_len -= sz;
		status = g_scsi_writebuffer_cmd(fd, offs, buf_ptr, sz, 0x07, 0);
		if (status != 0) {
		    return (status);
		}
		buf_ptr += sz;
		offs += sz;
	}
	return (status);
}




/*
 * Downloads the new prom image to IB.
 *
 * INPUTS:
 * 	path		- physical path of Photon SES card
 * 	file		- input file for new code (may be NULL)
 * 	ps		- whether the "save" bit should be set
 * 	verbose		- to be verbose or not
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_download(char *path_phys, char *file, int ps, int verbose)
{
int		file_fd, controller_fd;
int		err, status;
uchar_t		*buf_ptr;
char		printbuf[MAXPATHLEN];
int		retry;
char		file_path[MAXPATHLEN];
struct stat	statbuf;
int		enc_type;
L_inquiry	inq;

	if (path_phys == NULL) {
		return (L_INVALID_PATH_FORMAT);
	}

	if (!file) {
		(void) strcpy(file_path, IBFIRMWARE_FILE);
	} else {
		(void) strncpy(file_path, file, sizeof (file_path));
	}
	if (verbose)
		(void) fprintf(stdout, "%s\n",
			MSGSTR(9051, "  Opening the IB for I/O."));

	if ((controller_fd = g_object_open(path_phys, O_NDELAY | O_RDWR)) == -1)
		return (L_OPEN_PATH_FAIL);

	(void) sprintf(printbuf, MSGSTR(9052, "  Doing download to:"
			"\n\t%s.\n  From file: %s."), path_phys, file_path);

	if (verbose)
		(void) fprintf(stdout, "%s\n", printbuf);
	P_DPRINTF("  Doing download to:"
			"\n\t%s\n  From file: %s\n", path_phys, file_path);

	if ((file_fd = g_object_open(file_path, O_NDELAY | O_RDONLY)) == -1) {
		/*
		 * Return a different error code here to differentiate between
		 * this failure in g_object_open() and the one above.
		 */
		return (L_INVALID_PATH);
	}

	if (g_scsi_inquiry_cmd(controller_fd, (uchar_t *)&inq, sizeof (inq))) {
	    return (L_SCSI_ERROR);
	}
	enc_type = l_get_enc_type(inq);
	switch (enc_type) {
	case DAK_ENC_TYPE:
	/*
	 * We don't have a default daktari file location, so
	 * the user must specify the firmware file on the command line
	 */
	    if (!file) {
		return (L_REQUIRE_FILE);
	    }
	    /* Validate the file */
	    if ((err = check_dpm_file(file_fd))) {
		return (err);
	    }
	    /* Now go ahead and load up the data */
	    if (fstat(file_fd, &statbuf) == -1) {
		err = errno;
		(void) fprintf(stdout, "%s  %s\n",
		    MSGSTR(9101, "  Stat'ing the F/W file:"), strerror(err));
		return (L_OPEN_PATH_FAIL);
	    }
	    buf_ptr = (uchar_t *)g_zalloc(statbuf.st_size);
	    if (buf_ptr == NULL) {
		err = errno;
		(void) fprintf(stdout, "%s  %s\n",
		    MSGSTR(9102, "  Cannot alloc mem to read F/W file:"),
		    strerror(err));
		return (L_MALLOC_FAILED);
	    }
	    if (read(file_fd, buf_ptr, statbuf.st_size) == -1) {
		err = errno;
		(void) fprintf(stdout, "%s  %s\n",
		    MSGSTR(9103, "  Reading F/W file:"), strerror(err));
		g_destroy_data((char *)buf_ptr);
		return (L_DWNLD_READ_ERROR);
	    }
	    break;
	default:
	    if (err = check_file(file_fd, verbose, &buf_ptr, FW_DL_INFO)) {
		if (buf_ptr) {
		    (void) g_destroy_data((char *)buf_ptr);
		    return (err);
		}
	    }
	    break;
	}

	if (verbose) {
		(void) fprintf(stdout, "  ");
		(void) fprintf(stdout, MSGSTR(127, "Checkfile O.K."));
		(void) fprintf(stdout, "\n");
	}
	P_DPRINTF("  Checkfile OK.\n");
	(void) close(file_fd);

	if (verbose) {
		(void) fprintf(stdout, MSGSTR(9053,
			"  Verifying the IB is available.\n"));
	}

	retry = DOWNLOAD_RETRIES;
	while (retry) {
		if ((status = g_scsi_tur(controller_fd)) == 0) {
			break;
		} else {
			if ((retry % 30) == 0) {
				ER_DPRINTF(" Waiting for the IB to be"
						" available.\n");
			}
			(void) sleep(1);
		}
	}
	if (!retry) {
		if (buf_ptr)
			(void) g_destroy_data((char *)buf_ptr);
		(void) close(controller_fd);
		return (status);
	}

	if (verbose)
		(void) fprintf(stdout, "%s\n",
			MSGSTR(9054, "  Writing new text image to IB."));
	P_DPRINTF("  Writing new image to IB\n");
	switch (enc_type) {
	case DAK_ENC_TYPE:
	    status = dak_download_code_cmd(controller_fd, buf_ptr,
		statbuf.st_size);
	    if (status != 0) {
		if (buf_ptr != NULL) {
		    g_destroy_data((char *)buf_ptr);
		}
		(void) close(controller_fd);
		return (status);
	    }
	    break;
	default:
	    status = ib_download_code_cmd(controller_fd, IBEEPROM, TEXT_OFFSET,
		(uchar_t *)(buf_ptr + TEXT_OFFSET), TEXT_SZ, ps);
	    if (status) {
		(void) close(controller_fd);
		(void) g_destroy_data((char *)buf_ptr);
		return (status);
	    }
	    if (verbose) {
		(void) fprintf(stdout, "%s\n",
		    MSGSTR(9055, "  Writing new data image to IB."));
	    }
	    status = ib_download_code_cmd(controller_fd, IBEEPROM, IDATA_OFFSET,
		(uchar_t *)(buf_ptr + IDATA_OFFSET), IDATA_SZ, ps);
	    if (status) {
		(void) close(controller_fd);
		(void) g_destroy_data((char *)buf_ptr);
		return (status);
	    }
	    break;
	}


	if (verbose) {
		(void) fprintf(stdout, MSGSTR(9056,
			"  Re-verifying the IB is available.\n"));
	}

	retry = DOWNLOAD_RETRIES;
	while (retry) {
		if ((status = g_scsi_tur(controller_fd)) == 0) {
			break;
		} else {
			if ((retry % 30) == 0) {
				ER_DPRINTF("  Waiting for the IB to be"
					" available.\n");
			}
			(void) sleep(1);
		}
		retry--;
	}
	if (!retry) {
		(void) close(controller_fd);
		(void) g_destroy_data((char *)buf_ptr);
		return (L_DWNLD_TIMED_OUT);
	}

	switch (enc_type) {
	case DAK_ENC_TYPE:
	    break;
	default:
	    if (verbose) {
		(void) fprintf(stdout, "%s\n",
		    MSGSTR(9057, "  Writing new image to FPM."));
	    }
	    status = ib_download_code_cmd(controller_fd, MBEEPROM, FPM_OFFSET,
	    (uchar_t *)(buf_ptr + FPM_OFFSET), FPM_SZ, ps);
	    break;
	}

	if ((!status) && ps) {
		/*
		 * Reset the IB
		 */
		status = g_scsi_reset(controller_fd);
	}

	(void) close(controller_fd);
	return (status);
}

/*
 * Set the World Wide Name
 * in page 4 of the Send Diagnostic command.
 *
 * Is it allowed to change the wwn ???
 * The path must point to an IB.
 *
 */
int
l_set_wwn(char *path_phys, char *wwn)
{
Page4_name	page4;
L_inquiry	inq;
int		fd, status;
char		wwnp[WWN_SIZE];

	(void) memset(&inq, 0, sizeof (inq));
	(void) memset(&page4, 0, sizeof (page4));

	if ((fd = g_object_open(path_phys, O_NDELAY | O_RDONLY)) == -1) {
		return (L_OPEN_PATH_FAIL);
	}
	/* Verify it is a Photon */
	if (status = g_scsi_inquiry_cmd(fd,
		(uchar_t *)&inq, sizeof (struct l_inquiry_struct))) {
		(void) close(fd);
		return (status);
	}
	if ((strstr((char *)inq.inq_pid, ENCLOSURE_PROD_ID) == 0) &&
		(!(strncmp((char *)inq.inq_vid, "SUN     ",
		sizeof (inq.inq_vid)) &&
		((inq.inq_dtype & DTYPE_MASK) == DTYPE_ESI)))) {
		(void) close(fd);
		return (L_ENCL_INVALID_PATH);
	}

	page4.page_code = L_PAGE_4;
	page4.page_len = (ushort_t)((sizeof (struct page4_name) - 4));
	page4.string_code = L_WWN;
	page4.enable = 1;
	if (g_string_to_wwn((uchar_t *)wwn, (uchar_t *)&page4.name)) {
		close(fd);
		return (EINVAL);
	}
	bcopy((void *)wwnp, (void *)page4.name, (size_t)WWN_SIZE);

	if (status = g_scsi_send_diag_cmd(fd, (uchar_t *)&page4,
		sizeof (page4))) {
		(void) close(fd);
		return (status);
	}

	/*
	 * Check the wwn really changed.
	 */
	bzero((char *)page4.name, 32);
	if (status = g_scsi_rec_diag_cmd(fd, (uchar_t *)&page4,
				sizeof (page4), L_PAGE_4)) {
		(void) close(fd);
		return (status);
	}
	if (bcmp((char *)page4.name, wwnp, WWN_SIZE)) {
		(void) close(fd);
		return (L_WARNING);
	}

	(void) close(fd);
	return (0);
}



/*
 * Use a physical path to a disk in a Photon box
 * as the base to genererate a path to a SES
 * card in this box.
 *
 * path_phys: Physical path to a Photon disk.
 * ses_path:  This must be a pointer to an already allocated path string.
 *
 * RETURNS:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_ses_path(char *path_phys, char *ses_path, gfc_map_t *map,
	int verbose)
{
char	*char_ptr, id_buf[MAXPATHLEN], wwn[20];
uchar_t	t_wwn[20], *ses_wwn, *ses_wwn1, *ses_nwwn;
int	j, al_pa, al_pa1, box_id, fd, disk_flag = 0;
int	err, found = 0;
gfc_port_dev_info_t	*dev_addr_ptr;

	if ((path_phys == NULL) || (ses_path == NULL) || (map == NULL)) {
		return (L_NO_SES_PATH);
	}

	(void) strcpy(ses_path, path_phys);
	if ((char_ptr = strrchr(ses_path, '/')) == NULL) {
			return (L_INVLD_PATH_NO_SLASH_FND);
	}
	disk_flag++;
	*char_ptr = '\0';   /* Terminate sting  */
	(void) strcat(ses_path, SLSH_SES_NAME);

	/*
	 * Figure out and create the boxes pathname.
	 *
	 * NOTE: This uses the fact that the disks's
	 * AL_PA and the boxes AL_PA must match
	 * the assigned hard address in the current
	 * implementations. This may not be true in the
	 * future.
	 */
	if ((char_ptr = strrchr(path_phys, '@')) == NULL) {
		return (L_INVLD_PATH_NO_ATSIGN_FND);
	}
	char_ptr++;	/* point to the loop identifier */

	if ((err = g_get_wwn(path_phys, t_wwn, t_wwn,
		&al_pa, verbose)) != 0) {
		return (err);
	}
	box_id = g_sf_alpa_to_switch[al_pa & 0xFF] & BOX_ID_MASK;

	switch (map->hba_addr.port_topology) {
	case FC_TOP_PRIVATE_LOOP:
		for (j = 0, dev_addr_ptr = map->dev_addr;
			j < map->count; j++, dev_addr_ptr++) {
		    if (dev_addr_ptr->gfc_port_dev.priv_port.
			sf_inq_dtype == DTYPE_ESI) {
			al_pa1 = dev_addr_ptr->gfc_port_dev.
				priv_port.sf_al_pa;
			if (box_id == (g_sf_alpa_to_switch[al_pa1] &
				BOX_ID_MASK)) {
			    if (!found) {
				ses_wwn = dev_addr_ptr->
					gfc_port_dev.priv_port.sf_port_wwn;
				ses_nwwn = dev_addr_ptr->
					gfc_port_dev.priv_port.sf_node_wwn;
				if (getenv("_LUX_P_DEBUG")) {
					(void) g_ll_to_str(ses_wwn,
						(char *)t_wwn);
					(void) printf(
					"  l_get_ses_path: "
					"Found ses wwn = %s "
					"al_pa 0x%x\n", t_wwn, al_pa1);
				}
			} else {
				ses_wwn1 = dev_addr_ptr->
				    gfc_port_dev.priv_port.sf_port_wwn;
				if (getenv("_LUX_P_DEBUG")) {
					(void) g_ll_to_str(ses_wwn1,
							(char *)t_wwn);
					(void) printf(
						"  l_get_ses_path: "
						"Found second ses " "wwn = %s "
						"al_pa 0x%x\n", t_wwn, al_pa1);
				}
			    }
			    found++;
			}
		    }
		}
		break;
	case FC_TOP_FABRIC:
	case FC_TOP_PUBLIC_LOOP:
		for (j = 0, dev_addr_ptr = map->dev_addr;
			j < map->count; j++, dev_addr_ptr++) {
		    if (dev_addr_ptr->gfc_port_dev.pub_port.dev_dtype ==
				DTYPE_ESI) {
			/*
			 * We found an enclosure, lets match the
			 * area and domain codes for this enclosure with
			 * that of the ses path since there may be
			 * multiple enclosures with same box id on a
			 * fabric
			 */
			al_pa1 = dev_addr_ptr->gfc_port_dev.
				pub_port.dev_did.port_id;
			if ((al_pa & AREA_DOMAIN_ID) ==
				(al_pa1 & AREA_DOMAIN_ID)) {
				/*
				 * The area and domain matched. Now, we
				 * match the box id of the disk with
				 * this enclosure
				 */
				if (box_id ==
				    (g_sf_alpa_to_switch[al_pa1 &
					0xFF] & BOX_ID_MASK)) {
				    if (!found) {
					ses_wwn = dev_addr_ptr->
						gfc_port_dev.pub_port.
						    dev_pwwn.raw_wwn;
					ses_nwwn = dev_addr_ptr->
						gfc_port_dev.pub_port.
						dev_nwwn.raw_wwn;
					if (getenv("_LUX_P_DEBUG")) {
					    (void) g_ll_to_str(ses_wwn,
							(char *)t_wwn);
					    (void) printf(
						    "  l_get_ses_path: "
						    "Found ses wwn = %s "
						    "al_pa 0x%x\n", t_wwn,
						    al_pa1);
					}
				    } else {
					ses_wwn1 = dev_addr_ptr->
						gfc_port_dev.pub_port.
						    dev_pwwn.raw_wwn;
					if (getenv("_LUX_P_DEBUG")) {
					    (void) g_ll_to_str(ses_wwn1,
						(char *)t_wwn);
					    (void) printf(
						"  l_get_ses_path: "
						"Found second ses "
						"wwn = %s "
						"al_pa 0x%x\n", t_wwn,
						al_pa1);
					}
				    }
				    found++;
				}
			    }
			}
		    }
		    break;
	case FC_TOP_PT_PT:
		return (L_PT_PT_FC_TOP_NOT_SUPPORTED);
	default:
		return (L_UNEXPECTED_FC_TOPOLOGY);
	}	/* End of switch on port_topology */

	if (!found) {
		return (L_NO_SES_PATH);
	}

	if (strstr(path_phys, SCSI_VHCI) != NULL) {
		(void) g_ll_to_str(ses_nwwn, wwn);
		(void) sprintf(id_buf, "g%s:0", wwn);
	} else {
		(void) g_ll_to_str(ses_wwn, wwn);
		(void) sprintf(id_buf, "w%s,0:0", wwn);
	}
	(void) strcat(ses_path, id_buf);
	if (verbose) {
		(void) fprintf(stdout,
			MSGSTR(9058, "  Creating enclosure path:\n    %s\n"),
			ses_path);
	}

	/*
	 * see if these paths exist.
	 */
	if ((fd = g_object_open(ses_path, O_NDELAY | O_RDONLY)) == -1) {

		if (strstr(path_phys, SCSI_VHCI) != NULL) {
			return (L_INVALID_PATH);
		}

		char_ptr = strrchr(ses_path, '/');
		*char_ptr = '\0';
		(void) strcat(ses_path, SLSH_SES_NAME);
		if (found > 1) {
			(void) g_ll_to_str(ses_wwn1, wwn);
			P_DPRINTF("  l_get_ses_path: "
				"Using second path, ses wwn1 = %s\n",
				wwn);
			(void) sprintf(id_buf, "w%s,0:0", wwn);
			strcat(ses_path, id_buf);
			return (0);
		} else {
			return (L_NO_SES_PATH);
		}
	}
	close(fd);
	return (0);
}



/*
 * Get a valid location, front/rear & slot.
 *
 * path_struct->p_physical_path must be of a disk.
 *
 * OUTPUT: path_struct->slot_valid
 *	path_struct->slot
 *	path_struct->f_flag
 *
 * RETURN:
 *	0	 O.K.
 *	non-zero otherwise
 */
int
l_get_slot(struct path_struct *path_struct, L_state *l_state, int verbose)
{
int		err, al_pa, slot, found = 0;
uchar_t		node_wwn[WWN_SIZE], port_wwn[WWN_SIZE];
uint_t		select_id;

	if ((path_struct == NULL) || (l_state == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	/* Double check to see if we need to calculate. */
	if (path_struct->slot_valid)
		return (0);

	/* Programming error if this occures */
	assert(path_struct->ib_path_flag == 0);

	if (strstr(path_struct->p_physical_path, "ssd") == NULL) {
		return (L_INVLD_PHYS_PATH_TO_DISK);
	}
	if (err = g_get_wwn(path_struct->p_physical_path, port_wwn, node_wwn,
		&al_pa, verbose)) {
		return (err);
	}

	/*
	 * Find the slot by searching for the matching hard address.
	 * Take only the low order byte ignoring area and domain code in
	 * fabric devices' 24 bit al_pa
	 */
	select_id = g_sf_alpa_to_switch[al_pa & 0xFF];
	P_DPRINTF("  l_get_slot: Searching Receive Diagnostic page 2, "
		"to find the slot number with this ID:0x%x\n",
		select_id);

	for (slot = 0; slot < l_state->total_num_drv/2; slot++) {
		if (l_state->drv_front[slot].ib_status.sel_id ==
			select_id) {
			path_struct->f_flag = 1;
			found = 1;
			break;
		} else if (l_state->drv_rear[slot].ib_status.sel_id ==
			select_id) {
			path_struct->f_flag = 0;
			found = 1;
			break;
		}
	}
	if (!found) {
		return (L_INVALID_SLOT);	/* Failure */
	}
	if ((strncmp((char *)l_state->ib_tbl.config.prod_id, DAK_OFF_NAME,
						strlen(DAK_OFF_NAME)) == 0) ||
		(strncmp((char *)l_state->ib_tbl.config.prod_id, DAK_PROD_STR,
						strlen(DAK_OFF_NAME)) == 0)) {
		P_DPRINTF("  l_get_slot: Found slot %d.\n",
			path_struct->f_flag ? slot : slot + (MAX_DRIVES_DAK/2));
	} else {
		P_DPRINTF("  l_get_slot: Found slot %d %s.\n", slot,
			path_struct->f_flag ? "Front" : "Rear");
	}
	path_struct->slot = slot;
	path_struct->slot_valid = 1;
	return (0);
}


void
l_element_msg_string(uchar_t code, char *es)
{
	if (code == S_OK) {
		(void) sprintf(es, MSGSTR(29, "O.K."));
	} else if (code == S_NOT_AVAILABLE) {
		(void) sprintf(es, MSGSTR(34, "Disabled"));
	} else if (code == S_NOT_INSTALLED) {
		(void) sprintf(es, MSGSTR(30, "Not Installed"));
	} else if (code == S_NONCRITICAL) {
		(void) sprintf(es, MSGSTR(9059, "Noncritical failure"));
	} else if (code == S_CRITICAL) {
		(void) sprintf(es, MSGSTR(122, "Critical failure"));
	} else {
		(void) sprintf(es, MSGSTR(4, "Unknown status"));
	}
}


/*
 * Get all ses paths paths to a given box.
 * The arg should be the physical path to one of the box's IB.
 * NOTE: The caller must free the allocated lists.
 *
 * OUTPUT:
 *	a pointer to a list of ses paths if found
 *	NULL on error.
 *
 * RETURNS:
 *	0	 if O.K.
 *	non-zero otherwise
 */
int
l_get_allses(char *path, struct box_list_struct *box_list,
			struct dlist **ses_list, int verbose)
{
struct box_list_struct 	*box_list_ptr;
char			node_wwn_s[WWN_S_LEN];
struct dlist		*dlt, *dl;

	if ((path == NULL) || (box_list == NULL) || (ses_list == NULL)) {
		return (L_INVALID_PATH_FORMAT);
	}

	/* Initialize lists/arrays */
	*ses_list = dlt = dl = (struct dlist *)NULL;
	node_wwn_s[0] = '\0';

	H_DPRINTF("  l_get_allses: Looking for all ses paths for"
		" box at path: %s\n", path);

	for (box_list_ptr = box_list; box_list_ptr != NULL;
				box_list_ptr = box_list_ptr->box_next) {
		H_DPRINTF("  l_get_allses: physical_path= %s\n",
				box_list_ptr->b_physical_path);
		if (strcmp(path, box_list_ptr->b_physical_path) == 0) {
			(void) strcpy(node_wwn_s, box_list_ptr->b_node_wwn_s);
			break;
		}
	}
	if (node_wwn_s[0] == '\0') {
		H_DPRINTF("node_wwn_s is NULL!\n");
		return (L_NO_NODE_WWN_IN_BOXLIST);
	}
	H_DPRINTF("  l_get_allses: node_wwn=%s\n", node_wwn_s);
	for (box_list_ptr = box_list; box_list_ptr != NULL;
				box_list_ptr = box_list_ptr->box_next) {
		if (strcmp(node_wwn_s, box_list_ptr->b_node_wwn_s) == 0) {
			if ((dl = (struct dlist *)
				g_zalloc(sizeof (struct dlist))) == NULL) {
				while (*ses_list != NULL) {
					dl = dlt->next;
					(void) g_destroy_data(dlt);
					dlt = dl;
				}
				return (L_MALLOC_FAILED);
			}
			H_DPRINTF("  l_get_allses: Found ses=%s\n",
					box_list_ptr->b_physical_path);
			dl->dev_path = strdup(box_list_ptr->b_physical_path);
			dl->logical_path = strdup(box_list_ptr->logical_path);
			if (*ses_list == NULL) {
				*ses_list = dlt = dl;
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
 *	Routine to return the enclosure type pointed to by the path.
 *	Inputs:	The inquiry data for the device in question
 *
 *	Return:  >= 0 is the type:
 *
 *	Types are defined in storage/libg_fc/common/hdrs/g_state.h:
 *
 *		0 -> default (SENA)
 *		1 -> Daktari
 *		2 -> Other Enclosures
 *
 */
int
l_get_enc_type(L_inquiry inq)
{
	if (strncmp((char *)&inq.inq_pid[0], ENCLOSURE_PROD_ID,
		    strlen(ENCLOSURE_PROD_ID)) == 0) {
		return (SENA_ENC_TYPE);
	}
	if (strncmp((char *)&inq.inq_pid[0], DAK_OFF_NAME,
		strlen(DAK_OFF_NAME)) == 0) {
	    return (DAK_ENC_TYPE);
	}
	if (strncmp((char *)&inq.inq_pid[0], DAK_PROD_STR,
		strlen(DAK_PROD_STR)) == 0) {
	    return (DAK_ENC_TYPE);
	}
	/*
	 *  ADD OTHERS here if ever needed/wanted, and add to def's
	 * 	as noted above
	 */
	return (UNDEF_ENC_TYPE);
}

void
free_mp_dev_map(gfc_map_mp_t **map_mp_ptr) {
	gfc_map_mp_t	    *next = NULL;

	for (; *map_mp_ptr != NULL; *map_mp_ptr = next) {
		next = (*map_mp_ptr)->map_next;
		(void) g_destroy_data((*map_mp_ptr)->map.dev_addr);
		(void) g_destroy_data(*map_mp_ptr);
	}
	*map_mp_ptr = NULL;
}
/*
 * This function will return a linked list of device maps
 * An example of when this will be used is when we want to return the device
 * map of a vhci path.
 */

int
get_mp_dev_map(char *path, gfc_map_mp_t **map_mp_ptr, int verbose) {

	int		pathcnt, i, err;
	mp_pathlist_t	pathlist;
	gfc_map_mp_t	*new_map_mp_ptr;
	char		drvr_path[MAXPATHLEN];
	if (strstr(path, SCSI_VHCI)) {
		if (g_get_pathlist(path, &pathlist)) {
			return (L_INVALID_PATH);
		}
		pathcnt = pathlist.path_count;
		for (i = 0; i < pathcnt; i++) {
			if (pathlist.path_info[i].path_state < MAXPATHSTATE) {
				/*
				 * only pay attention to paths that are either
				 * ONLINE or STANDBY
				 */
				if ((pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_ONLINE) ||
				    (pathlist.path_info[i].path_state ==
					MDI_PATHINFO_STATE_STANDBY)) {
					if ((new_map_mp_ptr = (gfc_map_mp_t *)
					    g_zalloc(sizeof (gfc_map_mp_t)))
								== NULL) {
						free(pathlist.path_info);
						free_mp_dev_map(map_mp_ptr);
						return (L_MALLOC_FAILED);
					}
					(void) strcpy(drvr_path,
						pathlist.path_info[i].path_hba);
					(void) strcat(drvr_path, FC_CTLR);
					if (err = g_get_dev_map(drvr_path,
					    &(new_map_mp_ptr->map),
					    verbose)) {
						free(pathlist.path_info);
						free_mp_dev_map(map_mp_ptr);
						return (err);
					}
					/* add newly created map onto list */
					if (*map_mp_ptr == NULL) {
						new_map_mp_ptr->map_next = NULL;
						*map_mp_ptr = new_map_mp_ptr;
					} else {
						new_map_mp_ptr->map_next =
						    *map_mp_ptr;
						*map_mp_ptr = new_map_mp_ptr;
					}
				}
			}
		}
		free(pathlist.path_info);
	} else {
		if ((new_map_mp_ptr = (gfc_map_mp_t *)g_zalloc
			    (sizeof (gfc_map_mp_t))) == NULL) {
			return (L_MALLOC_FAILED);
		}
		g_get_dev_map(path, &(new_map_mp_ptr->map), verbose);
		*map_mp_ptr = new_map_mp_ptr;
	}
	return (0);
}
