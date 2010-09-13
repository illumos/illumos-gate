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

#ifndef _ISNS_FUNC_H
#define	_ISNS_FUNC_H

#include	<isns_protocol.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct conn_arg {
	int so;
	int lock;
	int (*handler)(struct conn_arg *);
	struct {
		isns_pdu_t *pdu;
		isns_tlv_t *source;
		isns_tlv_t *key;
		size_t key_len;
		isns_tlv_t *op;
		size_t op_len;
	} in_packet;
	struct {
		isns_pdu_t *pdu;
		size_t pl;
		size_t sz;
	} out_packet;
	struct sockaddr_storage ss;
	int ec;
} conn_arg_t;

int packet_split_verify(conn_arg_t *);
isns_pdu_t *make_dummy_rsp(isns_pdu_t *, int);
int isns_response(conn_arg_t *);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_FUNC_H */
