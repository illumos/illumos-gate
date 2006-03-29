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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_RMCADM_IMPL_H
#define	_SYS_RMCADM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	RMCADM_REQUEST_RESPONSE		0
#define	RMCADM_RESET_SP			1
#define	RMCADM_REQUEST_RESPONSE_BP	2
#define	RMCADM_SEND_SRECORD_BP		3

typedef struct rmcadm_msg {
	uint8_t		msg_type;	/* message type */
	uint16_t	msg_len;	/* size of the message buffer */
	uint16_t	msg_bytes;	/* number of bytes returned */
	caddr_t		msg_buf;	/* message buffer */
} rmcadm_msg_t;

typedef struct rmcadm_request_response {
	rmcadm_msg_t	req;
	rmcadm_msg_t	resp;
	uint_t		wait_time;
	int		status;
} rmcadm_request_response_t;

typedef struct rmcadm_send_srecord_bp {
	uint_t		data_len;
	caddr_t		data_buf;	/* message buffer */
	rmcadm_msg_t	resp_bp;	/* BP message returned */
	uint32_t	wait_time;	/* max waiting time for a BP message */
					/* (millisec) */
	int		status;
} rmcadm_send_srecord_bp_t;

#if defined(_SYSCALL32)
typedef struct rmcadm_msg32 {
	uint8_t		msg_type;	/* message type */
	uint16_t	msg_len;	/* size of the message buffer */
	uint16_t	msg_bytes;	/* number of bytes returned */
	caddr32_t	msg_buf;	/* message buffer */
} rmcadm_msg32_t;

typedef struct rmcadm_request_response32 {
	rmcadm_msg32_t	req;
	rmcadm_msg32_t	resp;
	uint32_t	wait_time;
	int		status;
} rmcadm_request_response32_t;

typedef struct rmcadm_send_srecord_bp32 {
	uint_t		data_len;
	caddr32_t	data_buf;	/* message buffer */
	rmcadm_msg32_t	resp_bp;
	uint32_t	wait_time;
	int		status;
} rmcadm_send_srecord_bp32_t;

#endif /* _SYSCALL32 */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RMCADM_IMPL_H */
