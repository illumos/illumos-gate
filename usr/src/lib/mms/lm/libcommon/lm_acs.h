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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __LM_ACS_H
#define	__LM_ACS_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <lm.h>
#include <lm_proto.h>
#include <acssys.h>
#include <acsapi.h>
#include <identifier.h>

			/* The following define the ACSLS sequence numbers */
			/* that are used by the different ACSLS commands */
			/* These cannot overlap because of the use of */
			/* threads within the LM. They should be 50 between */
			/* the different numbers. These are in acs_common.c  */
#define	ACS_ENTER_SEQ		100
#define	ACS_EJECT_SEQ		150
#define	ACS_MOUNT_SEQ		200
#define	ACS_DISMOUNT_SEQ	250
#define	ACS_Q_DRIVE_SEQ		300
#define	ACS_Q_MOUNT_SEQ		350
#define	ACS_Q_VOL_SEQ		400
#define	ACS_Q_CAP_SEQ		450
#define	ACS_Q_SERVER_SEQ	500
#define	ACS_DISPLAY_SEQ		550

			/* The following are ACSLS sequence numbers used */
			/* in lm_lcom.c */
#define	LM_EVENT_SEQ		1000
#define	LM_Q_SERVER_SEQ		1050
#define	LM_Q_LSM_SEQ		1100
#define	LM_Q_VOL_SEQ		1150
#define	LM_Q_VOL2_SEQ		1200
#define	LM_Q_DRIVE_SEQ		1250

#define	SLOT_CFG_SIZE 75	/* The number of bytes in one slot */
				/* definition of a config slot LMPL */
				/* command */
#define	MAX_CONFIG_CARTS 420	/* Max number of cartridges that can */
				/* be processed into one config slot */
				/* LMPL command */
#define	DRIVE_CFG_SIZE 75	/* The number of bytes in one drive */
				/* definition of a config drive LMPL */
				/* command */
#define	MAX_CONFIG_DRIVES 400	/* Max number of drives that can */
				/* be processed into one config slot */
				/* LMPL command */
#define	ACS_RESPONSE 42		/* The number of cartridges or drives */
				/* that can be part of a acs response */
				/* This is the MAX_ID in the ACSLS api */
				/* code */

#define	MAX_BAD_ACS_PKT 100

#define	MAX_CAP_SIZE		10
#define	MAX_L180_CAPS		1
#define	MAX_L180_CAP_SIZE	10
#define	MAX_L500_CAPS		1
#define	MAX_L500_CAP_SIZE	5
#define	MAX_L700_CAPS		2
#define	MAX_L700_CAP_SIZE	20

typedef struct acs_rsp_ele {
	mms_list_node_t		acs_rsp_next;
	SEQ_NO			acs_seq_nmbr;
	STATUS			acs_status;
	ACS_RESPONSE_TYPE	acs_type;
	REQ_ID			acs_req_id;
	ALIGNED_BYTES		acs_rbuf[MAX_MESSAGE_SIZE /
						sizeof (ALIGNED_BYTES)];
} acs_rsp_ele_t;

typedef struct acs_rsp {
	mms_list_t			acs_queue;
	pthread_mutex_t		acs_mutex;
	pthread_cond_t		acs_cv;
	int			acs_reading;
} acs_rsp_t;

typedef struct acs_cap {
	int	cap_config;
	int	cap_size;
	int	cap_capid;
	char	cap_name[MAX_CAP_SIZE + 1];
} acs_cap_t;

typedef struct acs_drive {
	int	acs_max_drive;
	int	acs_cnt_drive;
} acs_drive_t;

int lm_acs_init();
acs_rsp_ele_t *lm_obtain_acs_response(SEQ_NO, char *, char *, char *);
void lm_handle_acs_cmd_error(STATUS, char *, char *, char *);
void lm_handle_acsls_error(STATUS, char *, char *, char *, char *);
void lm_handle_acsls_state(STATE, char *, char *, char *, char *);
void lm_handle_query_vol_error(STATUS, char *, char *, char *);
void lm_handle_query_mount_error(STATUS, char *, char *, char *);
void lm_handle_mount_error(STATUS, char *, char *, char *, int, int, char *,
    char *, char *);
void lm_handle_dismount_error(STATUS, char *, char *, char *, char *, int, int,
    char *, char *, char *);
void lm_handle_enter_error(STATUS, char *, int, char *, char *, char *);
void lm_handle_eject_error(STATUS, char *, int, char *, char *, char *);

int lm_validate_private(mms_par_node_t *, char *, char *);
int lm_library_config_non_comm(int, char *, char *, char *);

int lm_drive_serial_num(char *, char *, char *);
int lm_obtain_serial_num(char *, char **, char *, char *, char *);
int lm_obtain_geometry(char *, char **, char *, char *, char *);
int lm_lib_type(int, char *, char *);
int lm_num_panels(int, char *, char *);
int lm_num_vols(int *, int, char *, char *);
void lm_set_drive_disabled(char *, char *);
int lm_acs_mount(acs_rsp_ele_t **, VOLID, DRIVEID, char *, char *, char *);
int lm_acs_dismount(acs_rsp_ele_t **, VOLID, DRIVEID, char *, char *, char *);
int lm_acs_query_volume(acs_rsp_ele_t **, VOLID [], int, char *, char *,
									char *);
int lm_acs_query_drive(acs_rsp_ele_t **, DRIVEID [], int, char *, char *,
									char *);
int lm_acs_query_mount(acs_rsp_ele_t **, VOLID [], int, char *, char *,
									char *);
int lm_acs_display(acs_rsp_ele_t **, DISPLAY_XML_DATA, char *, char *, char *);
int lm_acs_enter(acs_rsp_ele_t **, CAPID, char *, char *, char *);
int lm_acs_eject(acs_rsp_ele_t **, CAPID, VOLID [], int, char *, char *,
									char *);
int lm_acs_query_server(acs_rsp_ele_t **, char *, char *, char *);
int lm_acs_query_cap(acs_rsp_ele_t **, CAPID [], char *, char *, char *);

#ifdef	__cplusplus
}
#endif

#endif /* __LM_ACS_H */
