/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _BNXSND_H
#define	_BNXSND_H

#include "bnx.h"

#ifdef __cplusplus
extern "C" {
#endif

int  bnx_txpkts_init(um_device_t *const);
void bnx_txpkts_flush(um_device_t *const);
void bnx_txpkts_fini(um_device_t *const);

#define	BNX_SEND_GOODXMIT  0
#define	BNX_SEND_LINKDOWN  1
#define	BNX_SEND_DEFERPKT  2
#define	BNX_SEND_HDWRFULL  3

int  bnx_xmit_pkt_map(um_txpacket_t *const, mblk_t *);

int bnx_xmit_ring_xmit_qpkt(um_device_t *const, const unsigned int);

int bnx_xmit_ring_xmit_mblk(um_device_t *const, const unsigned int, mblk_t *);

void bnx_xmit_ring_reclaim(um_device_t *const, const unsigned int, s_list_t *);

void bnx_xmit_ring_intr(um_device_t *const, const unsigned int);

void bnx_txpkts_intr(um_device_t *const);

void bnx_xmit_ring_post(um_device_t *const, const unsigned int);

#ifdef __cplusplus
}
#endif

#endif /* _BNXSND_H */
