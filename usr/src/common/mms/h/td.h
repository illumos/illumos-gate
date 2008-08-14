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

#ifndef _TD_
#define	_TD_


#include "csi_structs.h"
#include "csi_rpc_header.h"
#include "csi_adi_header.h"
#include "cl_pub.h"


typedef struct {
	CSI_HEADER_RPC		csi_header;
	MESSAGE_HEADER		message_header;
	char message_content;
} CSI_REQUEST_HEADER_RPC;

typedef struct {
	CSI_HEADER_ADI		csi_header;
	MESSAGE_HEADER		message_header;
	char message_content;
} CSI_REQUEST_HEADER_ADI;

#define	SIZEOFIDBUF		100
typedef enum {
	LONG,
	SHORT
} FORMAT;

typedef enum {
	PACKET_REQUEST,
	PACKET_RESPONSE,
	PACKET_ACK
} PACKET_TYPE;

typedef void (*FUNC)(VERSION);

extern char td_msg_buf[];
extern char td_ascii_buf[];
extern PACKET_TYPE td_packet_type;
extern unsigned char td_mopts;
extern unsigned long td_xopts;
extern char *td_msg_ptr;
extern char *td_fix_portion;
extern char *td_var_portion;
extern int		td_adi_protocol;

void td_get_packet(void);
VERSION td_msg_header(MESSAGE_HEADER *);
void td_csi_header_rpc(CSI_HEADER_RPC *);
void td_csi_header_adi(CSI_HEADER_ADI *);
void td_critical_info(MESSAGE_HEADER *, unsigned);
char *td_net_addr(unsigned char *);
char *td_utoa(unsigned int);
char *td_ltoa(long);
char *td_ultoa(unsigned long);
char *td_stoa(short);
char *td_ustoa(unsigned short);
char *td_ctoa(SIGNED char);
char *td_htoa(SIGNED char id);
char *td_rm_space(char *);
void td_print(char *, void *, size_t, char *);
void td_print_header(void);
void td_hex_dump(void);

void td_print_volid(VOLID *);
void td_print_volrange(VOLRANGE *);
void td_print_driveid(DRIVEID *);
void td_print_msgid(MESSAGE_ID *);
void td_print_acs(ACS *);
void td_print_v0_capid(V0_CAPID *);
void td_print_capid(CAPID *);
void td_print_cellid(CELLID *);
void td_print_lsmid(LSMID *);
void td_print_portid(PORTID *);
void td_print_poolid(POOLID*);
void td_print_panelid(PANELID *);
void td_print_subpanelid(SUBPANELID *);
void td_print_lockid(LOCKID *);
void td_print_userid(USERID *);

void td_print_acs_list(ACS *, unsigned short);
void td_print_lsmid_list(LSMID *, unsigned short);
void td_print_capid_list(CAPID *, unsigned short);
void td_print_v0_capid_list(V0_CAPID *, unsigned short);
void td_print_portid_list(PORTID *, unsigned short);
void td_print_poolid_list(POOLID *, unsigned short);
void td_print_panelid_list(PANELID *, unsigned short);
void td_print_subpanelid_list(SUBPANELID *, unsigned short);
void td_print_volid_list(VOLID *, unsigned short);
void td_print_volrange_list(VOLRANGE *, unsigned short);
void td_print_driveid_list(DRIVEID *, unsigned short);

void td_print_msgid_list(MESSAGE_ID *, unsigned short);
void td_print_id_list(IDENTIFIER *, TYPE, unsigned short, VERSION);

void td_decode_req(VERSION, COMMAND);
void td_decode_resp(VERSION, COMMAND);
void td_decode_ack(VERSION);

void td_print_command(COMMAND *);
void td_print_type(TYPE *);
void td_print_count(unsigned short *);
void td_print_state(STATE *);
void td_print_status(STATUS *);
void td_print_freecells(FREECELLS *);
void td_print_low_water_mark(unsigned long *);
void td_print_high_water_mark(unsigned long *);
void td_print_pool_attr(unsigned long *);
void td_print_max_use(unsigned short *);
void td_print_cur_use(unsigned short *);
void td_print_location(LOCATION *);
void td_print_cap_mode(CAP_MODE *);
void td_print_cap_priority(CAP_PRIORITY *);
void td_decode_resp_status(RESPONSE_STATUS *);
void td_decode_vol_status(VOLUME_STATUS *);
void td_decode_vol_status_list(VOLUME_STATUS *, unsigned short);
void td_print_media_type(MEDIA_TYPE *);
void td_print_media_type_list(MEDIA_TYPE *, unsigned short);
void td_print_drive_type(DRIVE_TYPE *);
void td_print_drive_type_list(DRIVE_TYPE *, unsigned short);
void td_print_clean_cart_cap(CLN_CART_CAPABILITY *);

void td_print_reply_type(EVENT_REPLY_TYPE *event_reply_type);
void td_print_volume_event_type(VOL_EVENT_TYPE *vol_event_type);
void td_print_resource_type(TYPE *type);
void td_print_resource_identifier(TYPE type, IDENTIFIER *identifier);
void td_print_resource_event(RESOURCE_EVENT *resource_event);
void td_print_resource_data_type(RESOURCE_DATA_TYPE *resource_data_type);
void td_print_category(int *catetory);
void td_print_code(int *code);
void td_print_type_hli(SENSE_HLI *sense_hli);
void td_print_sense_key(unsigned char *sense_key);
void td_print_asc(unsigned char *asc);
void td_print_ascq(unsigned char *ascq);
void td_print_type_scsi(SENSE_SCSI *sense_scsi);
void td_print_type_fsc(SENSE_FSC *sense_fsc);
void td_print_type_serial_num(SERIAL_NUM *serial_num);
void td_print_type_lsm(LSM_TYPE *lsm_type);
void td_show_register_status(EVENT_REGISTER_STATUS *event_register_status);
void td_print_eventClass_list(EVENT_CLASS_TYPE *event_class,
    unsigned short count);

void td_print_register_return(EVENT_CLASS_REGISTER_RETURN
	*event_class_register_return);
void td_show_resource_status(EVENT_RESOURCE_STATUS *event_resource_status);
void td_print_registration_id(REGISTRATION_ID *registration_id);
void td_print_event_sequence(EVENT_SEQUENCE *event_sequence);
void td_print_register_status(EVENT_REGISTER_STATUS *event_register_status,
    unsigned short count);
void td_print_xml_data(DISPLAY_XML_DATA *display_xml_data);
void td_print_xml_data_length(unsigned short *length);
void td_print_xml_data_data(char *data, unsigned short length);


void td_invalid_command(VERSION);
void td_idle_command(VERSION);
void td_start_command(VERSION);

void td_audit_req(VERSION);
void td_cancel_req(VERSION);
void td_define_pool_req(VERSION);
void td_delete_pool_req(VERSION);
void td_dismount_req(VERSION);
void td_eject_req(VERSION);
void td_enter_req(VERSION);
void td_venter_req(VERSION);
void td_lock_req(VERSION);
void td_mount_req(VERSION);
void td_mount_scratch_req(VERSION);
void td_query_req(VERSION);
void td_set_cap_req(VERSION);
void td_set_clean_req(VERSION);
void td_set_scratch_req(VERSION);
void td_vary_req(VERSION);
void td_register_req(VERSION);
void td_unregister_req(VERSION);
void td_check_registration_req(VERSION);
void td_display_req(VERSION);

void td_audit_resp(VERSION);
void td_cancel_resp(VERSION);
void td_define_pool_resp(VERSION);
void td_delete_pool_resp(VERSION);
void td_dismount_resp(VERSION);
void td_eject_enter(VERSION);
void td_lock_resp(VERSION);
void td_mount_resp(VERSION);
void td_mount_scratch_resp(VERSION);
void td_query_resp(VERSION);
void td_query_lock_resp(VERSION);
void td_set_cap_resp(VERSION);
void td_set_clean_resp(VERSION);
void td_set_scratch_resp(VERSION);
void td_vary_resp(VERSION);
void td_register_resp(VERSION);
void td_unregister_resp(VERSION);
void td_check_registration_resp(VERSION);
void td_display_resp(VERSION);


void td_mount_pinfo_resp(VERSION);
void td_mount_pinfo_req(VERSION);
void td_print_mgmt_clas(MGMT_CLAS *mgmt_clas);
void td_print_dataset_name(DATASET_NAME *dataset_name);
void td_print_step_name(STEP_NAME *step_name);
void td_print_job_name(JOB_NAME *job_name);
void td_print_subpool_name(SUBPOOL_NAME *subpool_name);
void td_print_drive_addr(unsigned short *drive_addr);
void td_print_group_type(GROUP_TYPE *group_type);
void td_print_group_id(GROUPID		*group_id);
void td_print_group_info(unsigned short count, GROUPID		*group_id);
void td_print_subpool_info(unsigned short count, SUBPOOL_NAME	*subpool_name);

void td_print_drive_activity_type(TYPE *type);
void td_print_drive_activity_data(DRIVE_ACTIVITY_DATA *drive_activity_data);
void td_print_volume_type(VOLUME_TYPE *volume_type);
void td_show_drive_activity_status(EVENT_DRIVE_STATUS *event_drive_status);

#endif /* _TD_ */
