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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SRPT_STP_H
#define	_SRPT_STP_H

/*
 * Prototypes and data structures providing the SRP SCSI
 * target port COMSTAR port provider function.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Prototypes
 */
int srpt_stp_start_srp(srpt_target_port_t *tgt);
void srpt_stp_stop_srp(srpt_target_port_t *tgt);
srpt_target_port_t *srpt_stp_alloc_port(srpt_ioc_t *ioc, ib_guid_t guid);
stmf_status_t srpt_stp_free_port(srpt_target_port_t *tgt);
stmf_status_t srpt_stp_destroy_port(srpt_target_port_t *tgt);

srpt_session_t *srpt_stp_alloc_session(srpt_target_port_t *tgt,
	uint8_t *i_id, uint8_t *t_id, uint8_t port,
	char *local_gid, char *remote_gid);
void srpt_stp_free_session(srpt_session_t *session);

srpt_channel_t *srpt_stp_login(srpt_target_port_t *tgt,
	srp_login_req_t *login, srp_login_rsp_t *login_rsp,
	srp_login_rej_t *login_rej, uint8_t login_port,
	char *local_gid, char *remote_gid);

void srpt_stp_logout(srpt_channel_t *ch);

stmf_status_t srpt_stp_send_status(struct scsi_task *task,
	uint32_t ioflags);

ibt_status_t srpt_stp_send_response(srpt_iu_t *iu, uint8_t scsi_status,
	uint8_t flags, uint32_t resid, uint16_t sense_length,
	uint8_t *sense_data, uint_t fence);
ibt_status_t srpt_stp_send_mgmt_response(srpt_iu_t *iu, uint8_t srp_rsp,
	uint_t fence);
void srpt_stp_add_task(srpt_session_t *session, srpt_iu_t *iu);
void srpt_stp_remove_task(srpt_session_t *session, srpt_iu_t *iu);

uint64_t srpt_stp_u8array2u64(uint8_t *array);

#ifdef	__cplusplus
}
#endif

#endif /* _SRPT_STP_H */
