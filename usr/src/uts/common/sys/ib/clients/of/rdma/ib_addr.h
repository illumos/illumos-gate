/*
 * This file contains definitions used in OFED defined user/kernel
 * interfaces. These are imported from the OFED header ib_addr.h. Oracle
 * elects to have and use the contents of ib_addr.h under and governed
 * by the OpenIB.org BSD license (see below for details). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 * This Software is licensed under one of the following licenses:
 *
 * 1) under the terms of the "Common Public License 1.0" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/cpl.php.
 *
 * 2) under the terms of the "The BSD License" a copy of which is
 *    available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/bsd-license.php.
 *
 * 3) under the terms of the "GNU General Public License (GPL) Version 2" a
 *    copy of which is available from the Open Source Initiative, see
 *    http://www.opensource.org/licenses/gpl-license.php.
 *
 * Licensee has the right to choose one of the above licenses.
 *
 * Redistributions of source code must retain the above copyright
 * notice and one of the license notices.
 *
 * Redistributions in binary form must reproduce both the above copyright
 * notice, one of the license notices in the documentation
 * and/or other materials provided with the distribution.
 *
 */

#ifndef _SYS_IB_CLIENTS_OF_RDMA_IB_ADDR_H
#define	_SYS_IB_CLIENTS_OF_RDMA_IB_ADDR_H

#ifdef __cplusplus
extern "C" {
#endif


#include <sys/socket.h>
#include <sys/ib/clients/of/rdma/ib_verbs.h>

#define	MAX_ADDR_LEN	32	/* Maximim hardware length */

struct rdma_dev_addr {
	unsigned char src_dev_addr[MAX_ADDR_LEN];
	unsigned char dst_dev_addr[MAX_ADDR_LEN];
	unsigned char broadcast[MAX_ADDR_LEN];
	enum rdma_node_type dev_type;
};

static inline int ip_addr_size(struct sockaddr *addr)
{
	return addr->sa_family == AF_INET6 ?
	    sizeof (struct sockaddr_in6) :
	    sizeof (struct sockaddr_in);
}

static inline uint16_t ib_addr_get_pkey(struct rdma_dev_addr *dev_addr)
{
	return (((uint16_t)dev_addr->broadcast[8] << 8) |
	    (uint16_t)dev_addr->broadcast[9]);
}

static inline void ib_addr_set_pkey(struct rdma_dev_addr *dev_addr,
    uint16_t pkey)
{
	dev_addr->broadcast[8] = pkey >> 8;
	dev_addr->broadcast[9] = (unsigned char) pkey;
}

static inline void ib_addr_get_mgid(struct rdma_dev_addr *dev_addr,
    union ib_gid *gid)
{
	(void) memcpy(gid, dev_addr->broadcast + 4, sizeof (*gid));
}

static inline void ib_addr_get_sgid(struct rdma_dev_addr *dev_addr,
    union ib_gid *gid)
{
	(void) memcpy(gid, dev_addr->src_dev_addr + 4, sizeof (*gid));
}

static inline void ib_addr_set_sgid(struct rdma_dev_addr *dev_addr,
    union ib_gid *gid)
{
	(void) memcpy(dev_addr->src_dev_addr + 4, gid, sizeof (*gid));
}

static inline void ib_addr_get_dgid(struct rdma_dev_addr *dev_addr,
    union ib_gid *gid)
{
	(void) memcpy(gid, dev_addr->dst_dev_addr + 4, sizeof (*gid));
}

static inline void ib_addr_set_dgid(struct rdma_dev_addr *dev_addr,
    union ib_gid *gid)
{
	(void) memcpy(dev_addr->dst_dev_addr + 4, gid, sizeof (*gid));
}


#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_RDMA_IB_ADDR_H */
