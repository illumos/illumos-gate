/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__SMCLIB_H__
#define	__SMCLIB_H__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <smc_if.h>
#include <smc_commands.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SMC error codes
 */
typedef enum {
	SMC_SUCCESS 		= 0x0,
	SMC_FAILURE		= 0x1,
	SMC_REQ_FAILURE		= 0x2,
	SMC_ACK_TIMEOUT		= 0x3,
	SMC_ACK_FAILURE		= 0x4,
	SMC_RSP_FAILURE		= 0x5,
	SMC_RSP_TIMEOUT		= 0x6,
	SMC_INVALID_SEQ		= 0x7,
	SMC_RSP_ERROR		= 0x8
} smc_errno_t;

extern smc_errno_t smc_init_smc_msg(sc_reqmsg_t *req_msg, smc_app_command_t cmd,
	uint8_t msg_id, uint8_t msg_data_size);

extern smc_errno_t smc_init_ipmi_msg(sc_reqmsg_t *req_msg, uint8_t cmd,
	uint8_t msg_id, uint8_t msg_data_size, uint8_t *msg_data_buf,
	int8_t seq_num, int ipmb_addr, smc_netfn_t netfn, smc_lun_t lun);

extern smc_errno_t smc_send_msg(int fd, sc_reqmsg_t *req_pkt,
	sc_rspmsg_t *rsp_pkt, int poll_time);

#ifdef	__cplusplus
}
#endif

#endif	/* __SMCLIB_H__ */
