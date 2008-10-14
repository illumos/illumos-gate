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
 *  This file: 3500 - 3999
 *  Shared common messages: 1 - 1999
 */

/*	Includes	*/
#include	<stdlib.h>
#include	<stdio.h>
#include	<sys/file.h>
#include	<sys/errno.h>
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
#include	<libdevice.h>
#include	<sys/fibre-channel/fcio.h>
#define	_SYS_FC4_FCAL_LINKAPP_H
#include	<sys/fc4/fcio.h>
#include	<sys/devctl.h>
#include	<sys/scsi/targets/sesio.h>
#include	<l_common.h>
#include	<l_error.h>
#include	<a_state.h>
#include	<a5k.h>
#include	<stgcom.h>
#include	"luxadm.h"


/*	Defines		*/
#define	VERBPRINT	if (verbose) (void) printf



static int
print_ssd_in_box(char *ses_path, uchar_t *box_name, int verbose)
{
L_state		l_state;
int		err, i;
struct	dlist	*ml;
WWN_list	*wwn_list, *wwn_list_ptr;
char		*s;
L_inquiry	inq;
int		enc_type = 0;

	wwn_list = wwn_list_ptr = NULL;
	if (err = l_get_status(ses_path, &l_state, verbose)) {
		return (err);
	}

	if (err = g_get_wwn_list(&wwn_list, verbose)) {
		return (err);

	}

	/* Need to find out whether this device is a daktari */
	if (g_get_inquiry(ses_path, &inq)) {
		return (L_SCSI_ERROR);
	}
	if ((strncmp((char *)&inq.inq_pid[0], DAK_OFF_NAME,
						strlen(DAK_OFF_NAME)) == 0) ||
			(strncmp((char *)&inq.inq_pid[0], DAK_PROD_STR,
						strlen(DAK_PROD_STR)) == 0)) {
		enc_type = DAK_ENC_TYPE;
	}
	for (i = 0; i < (int)l_state.total_num_drv/2; i++) {
		if (l_state.drv_front[i].ib_status.code != S_NOT_INSTALLED) {

		ml = l_state.drv_front[i].g_disk_state.multipath_list;
		while (ml) {
			for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
					wwn_list_ptr = wwn_list_ptr->wwn_next) {
				s = wwn_list_ptr->physical_path;
				if (strcmp((char *)s,
					ml->dev_path) == 0) {
				(void) fprintf(stdout, MSGSTR(3500,
					"%-80.80s %-17.17s %-17.17s %-22.22s "),
					wwn_list_ptr->physical_path,
					wwn_list_ptr->node_wwn_s,
					wwn_list_ptr->port_wwn_s,
					wwn_list_ptr->logical_path);
					if (enc_type == DAK_ENC_TYPE) {
						(void) fprintf(stdout,
						MSGSTR(3513, "%s,s%d\n"),
						box_name, i);
					} else {
						(void) fprintf(stdout,
						MSGSTR(3501, "%s,f%d\n"),
						box_name, i);
					}
				}
			}
			ml = ml->next;
		}

		}
	}
	for (i = 0; i < (int)l_state.total_num_drv/2; i++) {
		if (l_state.drv_rear[i].ib_status.code != S_NOT_INSTALLED) {

		ml = l_state.drv_rear[i].g_disk_state.multipath_list;
		while (ml) {
			wwn_list_ptr = wwn_list;
			for (wwn_list_ptr = wwn_list; wwn_list_ptr != NULL;
					wwn_list_ptr = wwn_list_ptr->wwn_next) {
				s = wwn_list_ptr->physical_path;
				if (strcmp((char *)s,
					ml->dev_path) == 0) {
				(void) fprintf(stdout, MSGSTR(3502,
					"%-80.80s %-17.17s %-17.17s %-22.22s "),
					wwn_list_ptr->physical_path,
					wwn_list_ptr->node_wwn_s,
					wwn_list_ptr->port_wwn_s,
					wwn_list_ptr->logical_path);
					if (enc_type == DAK_ENC_TYPE) {
						(void) fprintf(stdout,
						MSGSTR(3513, "%s,s%d\n"),
							box_name,
						(int)l_state.total_num_drv/2+i);
					} else {
						(void) fprintf(stdout,
						MSGSTR(3503, "%s,r%d\n"),
								box_name, i);
					}
				}
			}
			ml = ml->next;
		}

		}
	}
	g_free_wwn_list(&wwn_list);
	return (0);
}



int
sysdump(int verbose)
{
int		err;

Box_list	*b_list = NULL;
Box_list	*o_list = NULL;
Box_list	*c_list = NULL;
int		multi_print_flag;

	if (err = l_get_box_list(&b_list, verbose)) {
		return (err);
	}
	if (b_list == NULL) {
		(void) fprintf(stdout,
			MSGSTR(93, "No %s enclosures found "
			"in /dev/es\n"), ENCLOSURE_PROD_NAME);
	} else {
		o_list = b_list;
		while (b_list != NULL) {
			/* Don't re-print multiple paths */
			c_list = o_list;
			multi_print_flag = 0;
			while (c_list != b_list) {
				if (strcmp(c_list->b_node_wwn_s,
					b_list->b_node_wwn_s) == 0) {
					multi_print_flag = 1;
					break;
				}
				c_list = c_list->box_next;
			}
			if (multi_print_flag) {
				b_list = b_list->box_next;
				continue;
			}
			/* Found enclosure */

			(void) fprintf(stdout,
			MSGSTR(3504, "Enclosure name:%s   Node WWN:%s\n"),
			b_list->b_name, b_list->b_node_wwn_s);

			(void) fprintf(stdout, MSGSTR(3505,
			"%-80.80s %-17.17s %-17.17s %-22.22s %-20.20s \n"),
			MSGSTR(3506, "Physical"),
			MSGSTR(3507, "Node_WWN"),
			MSGSTR(3508, "Port_WWN"),
			MSGSTR(3509, "Logical"),
			MSGSTR(3510, "Name"));

			(void) fprintf(stdout, MSGSTR(3511,
			"%-80.80s %-17.17s %-17.17s %-22.22s %-20.20s\n"),
			b_list->b_physical_path,
			b_list->b_node_wwn_s,
			b_list->b_port_wwn_s,
			b_list->logical_path,
			b_list->b_name);

			c_list = o_list;
			while (c_list != NULL) {
				if ((c_list != b_list) &&
				(strcmp(c_list->b_node_wwn_s,
					b_list->b_node_wwn_s) == 0)) {
					(void) fprintf(stdout, MSGSTR(3512,
			"%-80.80s %-17.17s %-17.17s %-22.22s %-20.20s\n"),
					c_list->b_physical_path,
					c_list->b_node_wwn_s,
					c_list->b_port_wwn_s,
					c_list->logical_path,
					c_list->b_name);
				}
				c_list = c_list->box_next;
			}
			/*
			 * Print the individual disk information for each box.
			 */
			if (err = print_ssd_in_box(b_list->b_physical_path,
				b_list->b_name, verbose)) {
				return (err);
			}
			b_list = b_list->box_next;
		}
	}
	(void) l_free_box_list(&b_list);
	return (0);
}
