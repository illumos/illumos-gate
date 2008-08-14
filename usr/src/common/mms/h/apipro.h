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


#ifndef _APIPRO_H_
#define	_APIPRO_H_

STATUS acs_audit_acs(
    SEQ_NO		seqNumber,
    ACS		acs[MAX_ID],
    CAPID		capId,
    unsigned short		count);

STATUS acs_audit_lsm(
    SEQ_NO		seqNumber,
    LSMID		lsmId[MAX_ID],
    CAPID		capId,
    unsigned short		count);

STATUS acs_audit_panel(
    SEQ_NO		seqNumber,
    PANELID		panelId[MAX_ID],
    CAPID		capId,
    unsigned short		count);

STATUS acs_audit_subpanel(
    SEQ_NO		seqNumber,
    SUBPANELID		subpanelId[MAX_ID],
    CAPID		capId,
    unsigned short		count);

STATUS acs_audit_server
(
    SEQ_NO seqNumber,
    CAPID capId);

STATUS acs_cancel(
    SEQ_NO		seqNumber,
    REQ_ID		reqId);

STATUS acs_idle(
    SEQ_NO		seqNumber,
    BOOLEAN		force);

STATUS acs_start(
    SEQ_NO		seqNumber);

STATUS acs_set_access(
    char *user_id);


STATUS acs_enter(
    SEQ_NO		seqNumber,
    CAPID		capId,
    BOOLEAN		continuous);

STATUS acs_eject(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    CAPID		capId,
    unsigned short		count,
    VOLID		volumes[MAX_ID]);

STATUS acs_venter(
    SEQ_NO		seqNumber,
    CAPID		capId,
    unsigned short		count,
    VOLID		volId[MAX_ID]);

STATUS acs_xeject(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    CAPID		capId,
    VOLRANGE		volRange[MAX_ID],
    unsigned short count);

STATUS acs_clear_lock_drive(
    SEQ_NO		seqNumber,
    DRIVEID		driveId[MAX_ID],
    unsigned short		count);

STATUS acs_clear_lock_volume(
    SEQ_NO		seqNumber,
    VOLID		volId[MAX_ID],
    unsigned short		count);

STATUS acs_lock_drive(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    USERID		userId,
    DRIVEID		driveId[MAX_ID],
    BOOLEAN		wait,
    unsigned short		count);

STATUS acs_lock_volume(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    USERID		userId,
    VOLID		volId[MAX_ID],
    BOOLEAN		wait,
    unsigned short		count);

STATUS acs_unlock_drive(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    DRIVEID		driveId[MAX_ID],
    unsigned short		count);

STATUS acs_unlock_volume(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    VOLID		volId[MAX_ID],
    unsigned short		count);

STATUS acs_dismount(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    VOLID		volId,
    DRIVEID		driveId,
    BOOLEAN		force);

STATUS acs_mount(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    VOLID		volId,
    DRIVEID		driveId,
    BOOLEAN		readonly,
    BOOLEAN		bypass);

STATUS acs_mount_scratch(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    POOL		pool,
    DRIVEID		driveId,
    MEDIA_TYPE mtype);

STATUS acs_query_mount_scratch_pinfo(
    SEQ_NO		seqNumber,
    POOL		pool[MAX_ID],
    unsigned short		count,
    MEDIA_TYPE		media_type,
    MGMT_CLAS		mgmt_clas);

STATUS acs_query_acs(
    SEQ_NO		seqNumber,
    ACS		acs[MAX_ID],
    unsigned short		count);

STATUS acs_query_cap(
    SEQ_NO		seqNumber,
    CAPID		capId[MAX_ID],
    unsigned short		count);

STATUS acs_query_clean(
    SEQ_NO		seqNumber,
    VOLID		volId[MAX_ID],
    unsigned short		count);

STATUS acs_query_drive(
    SEQ_NO		seqNumber,
    DRIVEID		driveId[MAX_ID],
    unsigned short		count);

STATUS acs_query_lock_drive(
    SEQ_NO		seqNumber,
    DRIVEID		driveId[MAX_ID],
    LOCKID		lockId,
    unsigned short		count);

STATUS acs_query_lock_volume(
    SEQ_NO		seqNumber,
    VOLID		volId[MAX_ID],
    LOCKID		lockId,
    unsigned short		count);

STATUS acs_query_lsm(
    SEQ_NO		seqNumber,
    LSMID		lsmId[MAX_ID],
    unsigned short		count);

STATUS acs_query_mm_info(SEQ_NO seqNumber);

STATUS acs_query_mount(
    SEQ_NO		seqNumber,
    VOLID		volId[MAX_ID],
    unsigned short		count);

STATUS acs_query_mount_scratch(
    SEQ_NO		seqNumber,
    POOL		pool[MAX_ID],
    unsigned short		count,
    MEDIA_TYPE		media_type);

STATUS acs_query_pool(
    SEQ_NO		seqNumber,
    POOL		pool[MAX_ID],
    unsigned short		count);

STATUS acs_query_port(
    SEQ_NO		seqNumber,
    PORTID		portId[MAX_ID],
    unsigned short		count);

STATUS acs_query_request(
    SEQ_NO		seqNumber,
    REQ_ID		reqId[MAX_ID],
    unsigned short		count);

STATUS acs_query_scratch(
    SEQ_NO		seqNumber,
    POOL		pool[MAX_ID],
    unsigned short		count);

STATUS acs_query_server(
    SEQ_NO		seqNumber);

STATUS acs_query_subpool_name(
    SEQ_NO		seqNumber,
    unsigned short		count,
    SUBPOOL_NAME		subpoolName[MAX_SPN]);

STATUS acs_query_volume(
    SEQ_NO		seqNumber,
    VOLID		volId[MAX_ID],
    unsigned short		count);

STATUS acs_response(
    int		timeout,
    SEQ_NO *	seqNumber,
    REQ_ID *	reqId,
    ACS_RESPONSE_TYPE *	type,
    ALIGNED_BYTES	buffer);

STATUS acs_set_cap(
    SEQ_NO		seqNumber,
    CAP_PRIORITY		capPriority,
    CAP_MODE		capMode,
    CAPID		capId[MAX_ID],
    unsigned		short count);

STATUS acs_set_clean(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    unsigned short		maxUse,
    VOLRANGE		volRange[MAX_ID],
    BOOLEAN		on,
    unsigned short		count);

STATUS acs_set_scratch(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    POOL		pool,
    VOLRANGE		volRange[MAX_ID],
    BOOLEAN		on,
    unsigned short		count);

STATUS acs_define_pool(
    SEQ_NO		seqNumber,
    unsigned long		lwm,
    unsigned long		hwm,
    unsigned long		attributes,
    POOL		pool[MAX_ID],
    unsigned short		count);

STATUS acs_delete_pool(
    SEQ_NO		seqNumber,
    POOL		pool[MAX_ID],
    unsigned short		count);

STATUS acs_vary_acs(
    SEQ_NO		seqNumber,
    ACS		acs[MAX_ID],
    STATE		state,
    BOOLEAN		force,
    unsigned short		count);

STATUS acs_vary_cap(
    SEQ_NO		seqNumber,
    CAPID		capId[MAX_ID],
    STATE		state,
    unsigned short		count);

STATUS acs_vary_drive(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    DRIVEID		driveId[MAX_ID],
    STATE		state,
    unsigned short		count);

STATUS acs_vary_lsm(
    SEQ_NO		seqNumber,
    LSMID		lsmId[MAX_ID],
    STATE		state,
    BOOLEAN		force,
    unsigned short		count);

STATUS acs_vary_port(
    SEQ_NO		seqNumber,
    PORTID		portId[MAX_ID],
    STATE		state,
    unsigned short count);

STATUS acs_register(
    SEQ_NO		seqNumber,
    REGISTRATION_ID		registration_id,
    EVENT_CLASS_TYPE		eventClass[MAX_EVENT_CLASS_TYPE],
    unsigned short		count);

STATUS acs_unregister(
    SEQ_NO		seqNumber,
    REGISTRATION_ID		registration_id,
    EVENT_CLASS_TYPE		eventClass[MAX_EVENT_CLASS_TYPE],
    unsigned short		count);

STATUS acs_check_registration(
    SEQ_NO		seqNumber,
    REGISTRATION_ID		registration_id);

STATUS acs_display(
    SEQ_NO		seqNumber,
    TYPE		display_type,
    DISPLAY_XML_DATA		display_xml_data);

char *acs_type_response(
    ACS_RESPONSE_TYPE rtype);

STATUS acs_virtual_mount(
    SEQ_NO		seqNumber,
    LOCKID		lockId,
    VOLID		volId,
    POOLID		pool_id,
    MGMT_CLAS		mgmtClas,
    MEDIA_TYPE		mtype,
    BOOLEAN		scratch,
    BOOLEAN		readonly,
    BOOLEAN		bypass,
    JOB_NAME		jobName,
    DATASET_NAME datasetName,
    STEP_NAME		stepName,
    DRIVEID		driveId);

STATUS acs_virtual_query_drive(
    SEQ_NO		seqNumber,
    DRIVEID		driveId[MAX_ID],
    unsigned short		count,
    BOOLEAN		virt_aware);

char *acs_type(
    TYPE type);

char *acs_status(
    STATUS status);

char *acs_state(
    STATE state);

char *acs_command(
    COMMAND cmd);

VERSION acs_get_packet_version(
    void);

#endif /* _APIPRO_H_ */
