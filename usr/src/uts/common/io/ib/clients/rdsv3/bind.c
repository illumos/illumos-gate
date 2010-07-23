/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file bind.c
 * Oracle elects to have and use the contents of bind.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
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
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/random.h>
#include <sys/rds.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

kmutex_t	rdsv3_bind_lock;
avl_tree_t	rdsv3_bind_tree;

/*
 * Each node in the rdsv3_bind_tree is of this type.
 */
struct rdsv3_ip_bucket {
	ipaddr_t		ip;
	zoneid_t		zone;
	avl_node_t		ip_avl_node;
	krwlock_t		rwlock;
	uint_t			nsockets;
	struct rdsv3_sock	*port[65536];
};

static int
rdsv3_bind_node_compare(const void *a, const void *b)
{
	struct rdsv3_ip_bucket *bp = (struct rdsv3_ip_bucket *)b;

	if (*(uint64_t *)a > (((uint64_t)bp->ip << 32) | bp->zone))
		return (+1);
	else if (*(uint64_t *)a < (((uint64_t)bp->ip << 32) | bp->zone))
		return (-1);

	return (0);
}

void
rdsv3_bind_init()
{
	RDSV3_DPRINTF4("rdsv3_bind_tree_init", "Enter");

	mutex_init(&rdsv3_bind_lock, NULL, MUTEX_DRIVER, NULL);
	avl_create(&rdsv3_bind_tree, rdsv3_bind_node_compare,
	    sizeof (struct rdsv3_ip_bucket),
	    offsetof(struct rdsv3_ip_bucket, ip_avl_node));

	RDSV3_DPRINTF4("rdsv3_bind_tree_init", "Return");
}

/* called on detach */
void
rdsv3_bind_exit()
{
	struct rdsv3_ip_bucket	*bucketp;
	void			*cookie = NULL;

	RDSV3_DPRINTF2("rdsv3_bind_tree_exit", "Enter");

	while ((bucketp =
	    avl_destroy_nodes(&rdsv3_bind_tree, &cookie)) != NULL) {
		rw_destroy(&bucketp->rwlock);
		kmem_free(bucketp, sizeof (struct rdsv3_ip_bucket));
	}

	avl_destroy(&rdsv3_bind_tree);
	mutex_destroy(&rdsv3_bind_lock);

	RDSV3_DPRINTF2("rdsv3_bind_tree_exit", "Return");
}

struct rdsv3_ip_bucket *
rdsv3_find_ip_bucket(ipaddr_t ipaddr, zoneid_t zoneid)
{
	struct rdsv3_ip_bucket	*bucketp;
	avl_index_t		where;
	uint64_t		needle = ((uint64_t)ipaddr << 32) | zoneid;

	mutex_enter(&rdsv3_bind_lock);
	bucketp = avl_find(&rdsv3_bind_tree, &needle, &where);
	if (bucketp == NULL) {
		/* allocate a new bucket for this IP & zone */
		bucketp =
		    kmem_zalloc(sizeof (struct rdsv3_ip_bucket), KM_SLEEP);
		rw_init(&bucketp->rwlock, NULL, RW_DRIVER, NULL);
		bucketp->ip = ipaddr;
		bucketp->zone = zoneid;
		avl_insert(&rdsv3_bind_tree, bucketp, where);
	}
	mutex_exit(&rdsv3_bind_lock);

	return (bucketp);
}

/*
 * Return the rdsv3_sock bound at the given local address.
 *
 * The rx path can race with rdsv3_release.  We notice if rdsv3_release() has
 * marked this socket and don't return a rs ref to the rx path.
 */
struct rdsv3_sock *
rdsv3_find_bound(struct rdsv3_connection *conn, uint16_be_t port)
{
	struct rdsv3_sock *rs;

	RDSV3_DPRINTF4("rdsv3_find_bound", "Enter(ip:port: %u.%u.%u.%u:%d)",
	    NIPQUAD(conn->c_laddr), ntohs(port));

	rw_enter(&conn->c_bucketp->rwlock, RW_READER);
	ASSERT(ntohl(conn->c_laddr) == conn->c_bucketp->ip);
	rs = conn->c_bucketp->port[ntohs(port)];
	if (rs && !rdsv3_sk_sock_flag(rdsv3_rs_to_sk(rs), SOCK_DEAD))
		rdsv3_sk_sock_hold(rdsv3_rs_to_sk(rs));
	else
		rs = NULL;
	rw_exit(&conn->c_bucketp->rwlock);

	RDSV3_DPRINTF5("rdsv3_find_bound", "returning rs %p for %u.%u.%u.%u:%d",
	    rs, NIPQUAD(conn->c_laddr), ntohs(port));

	return (rs);
}

/* returns -ve errno or +ve port */
static int
rdsv3_add_bound(struct rdsv3_sock *rs, uint32_be_t addr, uint16_be_t *port)
{
	int ret = -EADDRINUSE;
	uint16_t rover, last;
	struct rdsv3_ip_bucket *bucketp;

	RDSV3_DPRINTF4("rdsv3_add_bound", "Enter(addr:port: %x:%x)",
	    ntohl(addr), ntohs(*port));

	if (*port != 0) {
		rover = ntohs(*port);
		last = rover;
	} else {
		(void) random_get_pseudo_bytes((uint8_t *)&rover,
		    sizeof (uint16_t));
		rover = MAX(rover, 2);
		last = rover - 1;
	}

	bucketp = rdsv3_find_ip_bucket(ntohl(addr), rs->rs_zoneid);

	/* leave the bind lock and get the bucket lock */
	rw_enter(&bucketp->rwlock, RW_WRITER);

	do {
		if (rover == 0)
			rover++;

		if (bucketp->port[rover] == NULL) {
			*port = htons(rover);
			ret = 0;
			break;
		}
	} while (rover++ != last);

	if (ret == 0)  {
		rs->rs_bound_addr = addr;
		rs->rs_bound_port = *port;
		bucketp->port[rover] = rs;
		bucketp->nsockets++;
		rdsv3_sock_addref(rs);

		RDSV3_DPRINTF5("rdsv3_add_bound",
		    "rs %p binding to %u.%u.%u.%u:%d",
		    rs, NIPQUAD(addr), rover);
	}

	rw_exit(&bucketp->rwlock);

	RDSV3_DPRINTF4("rdsv3_add_bound", "Return(ret: %d port: %d)",
	    ret, rover);


	return (ret);
}

void
rdsv3_remove_bound(struct rdsv3_sock *rs)
{
	RDSV3_DPRINTF4("rdsv3_remove_bound", "Enter(rs: %p)", rs);

	if (rs->rs_bound_addr) {
		struct rdsv3_ip_bucket *bucketp;

		RDSV3_DPRINTF5("rdsv3_remove_bound",
		    "rs %p unbinding from %u.%u.%u.%u:%x",
		    rs, NIPQUAD(htonl(rs->rs_bound_addr)), rs->rs_bound_port);

		bucketp = rdsv3_find_ip_bucket(ntohl(rs->rs_bound_addr),
		    rs->rs_zoneid);

		rw_enter(&bucketp->rwlock, RW_WRITER);
		bucketp->port[ntohs(rs->rs_bound_port)] = NULL;
		bucketp->nsockets--;
		rs->rs_bound_addr = 0;
		rw_exit(&bucketp->rwlock);

		rdsv3_sock_put(rs);
	}

	RDSV3_DPRINTF4("rdsv3_remove_bound", "Return(rs: %p)", rs);
}

/* ARGSUSED */
int
rdsv3_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr)
{
	struct rsock	*sk = (struct rsock *)proto_handle;
	sin_t		*sin = (sin_t *)sa;
	struct rdsv3_sock	*rs = rdsv3_sk_to_rs(sk);
	int		ret;

	if (len != sizeof (sin_t) || (sin == NULL) ||
	    !OK_32PTR((char *)sin)) {
		RDSV3_DPRINTF2("rdsv3_bind", "address to bind not specified");
		return (EINVAL);
	}

	RDSV3_DPRINTF4("rdsv3_bind", "Enter(rs: %p, addr: 0x%x, port: %x)",
	    rs, ntohl(sin->sin_addr.s_addr), htons(sin->sin_port));

	if (sin->sin_addr.s_addr == INADDR_ANY) {
		RDSV3_DPRINTF2("rdsv3_bind", "Invalid address");
		return (EINVAL);
	}

	/* We don't allow multiple binds */
	if (rs->rs_bound_addr) {
		RDSV3_DPRINTF2("rdsv3_bind", "Multiple binds not allowed");
		return (EINVAL);
	}

	ret = rdsv3_add_bound(rs, sin->sin_addr.s_addr, &sin->sin_port);
	if (ret) {
		return (ret);
	}

	rs->rs_transport = rdsv3_trans_get_preferred(sin->sin_addr.s_addr);
	if (!rs->rs_transport) {
		rdsv3_remove_bound(rs);
		if (rdsv3_printk_ratelimit()) {
			RDSV3_DPRINTF1("rdsv3_bind",
			    "RDS: rdsv3_bind() could not find a transport.\n");
		}
		return (EADDRNOTAVAIL);
	}

	RDSV3_DPRINTF4("rdsv3_bind", "Return: Assigned port: %x to sock: %p",
	    sin->sin_port, rs);

	return (0);
}
