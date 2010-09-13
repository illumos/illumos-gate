/*
 * This file contains definitions used in OFED defined user/kernel
 * interfaces. These are imported from the OFED header ib_user_mad.h. Oracle
 * elects to have and use the contents of ib_user_mad.h under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Voltaire, Inc. All rights reserved.
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
 *
 */

#ifndef _SYS_IB_CLIENTS_OF_RDMA_IB_USER_MAD_H
#define	_SYS_IB_CLIENTS_OF_RDMA_IB_USER_MAD_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Increment this value if any changes that break userspace ABI
 * compatibility are made.
 */
#define	IB_USER_MAD_ABI_VERSION	5

/*
 * Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 */

/*
 * ib_user_mad_hdr_old - Old version of MAD packet header without pkey_index
 * @id - ID of agent MAD received with/to be sent with
 * @status - 0 on successful receive, ETIMEDOUT if no response
 *   received (transaction ID in data[] will be set to TID of original
 *   request) (ignored on send)
 * @timeout_ms - Milliseconds to wait for response (unset on receive)
 * @retries - Number of automatic retries to attempt
 * @qpn - Remote QP number received from/to be sent to
 * @qkey - Remote Q_Key to be sent with (unset on receive)
 * @lid - Remote lid received from/to be sent to
 * @sl - Service level received with/to be sent with
 * @path_bits - Local path bits received with/to be sent with
 * @grh_present - If set, GRH was received/should be sent
 * @gid_index - Local GID index to send with (unset on receive)
 * @hop_limit - Hop limit in GRH
 * @traffic_class - Traffic class in GRH
 * @gid - Remote GID in GRH
 * @flow_label - Flow label in GRH
 *
 */

/*
 * ib_user_mad_hdr - MAD packet header
 *   This layout allows specifying/receiving the P_Key index.  To use
 *   this capability, an application must call the
 *   IB_USER_MAD_ENABLE_PKEY ioctl on the user MAD file handle before
 *   any other actions with the file handle.
 * @id - ID of agent MAD received with/to be sent with
 * @status - 0 on successful receive, ETIMEDOUT if no response
 *   received (transaction ID in data[] will be set to TID of original
 *   request) (ignored on send)
 * @timeout_ms - Milliseconds to wait for response (unset on receive)
 * @retries - Number of automatic retries to attempt
 * @qpn - Remote QP number received from/to be sent to
 * @qkey - Remote Q_Key to be sent with (unset on receive)
 * @lid - Remote lid received from/to be sent to
 * @sl - Service level received with/to be sent with
 * @path_bits - Local path bits received with/to be sent with
 * @grh_present - If set, GRH was received/should be sent
 * @gid_index - Local GID index to send with (unset on receive)
 * @hop_limit - Hop limit in GRH
 * @traffic_class - Traffic class in GRH
 * @gid - Remote GID in GRH
 * @flow_label - Flow label in GRH
 *
 */
struct ib_user_mad_hdr {
	uint32_t	id;
	uint32_t	status;
	uint32_t	timeout_ms;
	uint32_t	retries;
	uint32_t	length;
	uint32_t	qpn;
	uint32_t	qkey;
	uint16_t	lid;
	uint8_t		sl;
	uint8_t		path_bits;
	uint8_t		grh_present;
	uint8_t		gid_index;
	uint8_t		hop_limit;
	uint8_t		traffic_class;
	uint8_t		gid[16];
	uint32_t	flow_label;
	uint16_t	pkey_index;
	uint8_t		reserved[6];
};

/*
 * ib_user_mad - MAD packet
 * @hdr - MAD packet header
 * @data - Contents of MAD
 *
 */
struct ib_user_mad {
	struct ib_user_mad_hdr hdr;
	uint64_t	data[];
};

/*
 * ib_user_mad_reg_req - MAD registration request
 * @id - Set by the kernel; used to identify agent in future requests.
 * @qpn - Queue pair number; must be 0 or 1.
 * @method_mask - The caller will receive unsolicited MADs for any method
 *   where @method_mask = 1.
 * @mgmt_class - Indicates which management class of MADs should be receive
 *   by the caller.  This field is only required if the user wishes to
 *   receive unsolicited MADs, otherwise it should be 0.
 * @mgmt_class_version - Indicates which version of MADs for the given
 *   management class to receive.
 * @oui: Indicates IEEE OUI when mgmt_class is a vendor class
 *   in the range from 0x30 to 0x4f. Otherwise not used.
 * @rmpp_version: If set, indicates the RMPP version used.
 *
 */
struct ib_user_mad_reg_req {
	uint32_t	id;
	uint32_t	method_mask[4];
	uint8_t		qpn;
	uint8_t		mgmt_class;
	uint8_t		mgmt_class_version;
	uint8_t		oui[3];
	uint8_t		rmpp_version;
};

#define	IB_IOCTL_MAGIC		0x1b

#define	IB_USER_MAD_REGISTER_AGENT	_IOWR(IB_IOCTL_MAGIC, 1, \
						struct ib_user_mad_reg_req)

#define	IB_USER_MAD_UNREGISTER_AGENT	_IOW(IB_IOCTL_MAGIC, 2, uint32_t)

#define	IB_USER_MAD_ENABLE_PKEY		_IO(IB_IOCTL_MAGIC, 3)

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_RDMA_IB_USER_MAD_H */
