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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBPCP_H
#define	_LIBPCP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCPL_MAX_TRY_CNT	5
#define	PCP_CLEANUP_TIMEOUT	3

#define	PCPL_DEF_MTU_SZ		100


#define	PCPL_IO_OP_READ		(1)
#define	PCPL_IO_OP_WRITE	(2)
#define	PCPL_IO_OP_PEEK		(3)

/*
 * sleep (seconds) for glvc call failures before
 * retrying.
 */
#define	PCPL_GLVC_SLEEP		(5)

/*
 * Error codes for pcp library that are
 * returned to users applications.
 */
#define	PCPL_OK			0
#define	PCPL_ERROR		(-1)
#define	PCPL_INVALID_ARGS 	(-2)
#define	PCPL_GLVC_ERROR		(-3)
#define	PCPL_XPORT_ERROR	(-4)
#define	PCPL_MALLOC_FAIL	(-5)
#define	PCPL_GLVC_TIMEOUT	(-6)
#define	PCPL_FRAME_ERROR	(-7)
#define	PCPL_CKSUM_ERROR	(-8)
#define	PCPL_PROT_ERROR		(-9)

/* common defines */
#ifndef	MIN
#define	MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
#ifndef	MAX
#define	MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef	ABS
#define	ABS(x)	((x) < (0) ? (-(x)) : (x))
#endif

/*
 * PCP user apps message format
 */
typedef struct pcp_msg {
	uint8_t	msg_type;
	uint8_t	sub_type;
	uint16_t rsvd_pad;
	uint32_t msg_len;
	void *msg_data;
} pcp_msg_t;

int pcp_init(char *channel_name);
int pcp_send_recv(int channel_fd, pcp_msg_t *req_msg, pcp_msg_t *resp_msg,
			uint32_t timeout);
int pcp_close(int channel_fd);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBPCP_H */
