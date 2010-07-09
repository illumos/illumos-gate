/*
 * This file contains definitions used in OFED defined user/kernel
 * interfaces. These are imported from the OFED header ib_user_sa.h. Oracle
 * elects to have and use the contents of ib_user_sa.h under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _SYS_IB_CLIENTS_OF_RDMA_IB_USER_SA_H
#define	_SYS_IB_CLIENTS_OF_RDMA_IB_USER_SA_H

#ifdef __cplusplus
extern "C" {
#endif

struct ib_user_path_rec {
	uint8_t		dgid[16];
	uint8_t		sgid[16];
	uint16_t	dlid;
	uint16_t	slid;
	uint32_t	raw_traffic;
	uint32_t	flow_label;
	uint32_t	reversible;
	uint32_t	mtu;
	uint16_t	pkey;
	uint8_t		hop_limit;
	uint8_t		traffic_class;
	uint8_t		numb_path;
	uint8_t		sl;
	uint8_t		mtu_selector;
	uint8_t		rate_selector;
	uint8_t		rate;
	uint8_t		packet_life_time_selector;
	uint8_t		packet_life_time;
	uint8_t		preference;
};

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_CLIENTS_OF_RDMA_IB_USER_SA_H */
