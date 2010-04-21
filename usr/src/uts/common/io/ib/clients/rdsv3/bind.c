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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/random.h>
#include <sys/rds.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

/*
 * XXX this probably still needs more work.. no INADDR_ANY, and rbtrees aren't
 * particularly zippy.
 *
 * This is now called for every incoming frame so we arguably care much more
 * about it than we used to.
 */
kmutex_t	rdsv3_bind_lock;
avl_tree_t	rdsv3_bind_tree;

static struct rdsv3_sock *
rdsv3_bind_tree_walk(uint32_be_t addr, uint16_be_t port,
    struct rdsv3_sock *insert)
{
	struct rdsv3_sock *rs;
	avl_index_t	where;

	rs = avl_find(&rdsv3_bind_tree, &port, &where);
	if ((rs == NULL) && (insert != NULL)) {
		insert->rs_bound_addr = addr;
		insert->rs_bound_port = port;
		avl_insert(&rdsv3_bind_tree, insert, where);
	}

	return (rs);
}

/*
 * Return the rdsv3_sock bound at the given local address.
 *
 * The rx path can race with rdsv3_release.  We notice if rdsv3_release() has
 * marked this socket and don't return a rs ref to the rx path.
 */
struct rdsv3_sock *
rdsv3_find_bound(uint32_be_t addr, uint16_be_t port)
{
	struct rdsv3_sock *rs;

	RDSV3_DPRINTF4("rdsv3_find_bound", "Enter(port: %x)", port);

	mutex_enter(&rdsv3_bind_lock);
	rs = rdsv3_bind_tree_walk(addr, port, NULL);
	if (rs && !rdsv3_sk_sock_flag(rdsv3_rs_to_sk(rs), SOCK_DEAD))
		rdsv3_sock_addref(rs);
	else
		rs = NULL;
	mutex_exit(&rdsv3_bind_lock);

	RDSV3_DPRINTF5("rdsv3_find_bound", "returning rs %p for %u.%u.%u.%u:%x",
	    rs, NIPQUAD(addr), port);
	return (rs);
}

/* returns -ve errno or +ve port */
static int
rdsv3_add_bound(struct rdsv3_sock *rs, uint32_be_t addr, uint16_be_t *port)
{
	int ret = -EADDRINUSE;
	uint16_t rover, last;

	RDSV3_DPRINTF4("rdsv3_add_bound", "Enter(port: %x)", *port);

	if (*port != 0) {
		rover = ntohs(*port);
		last = rover;
	} else {
		(void) random_get_pseudo_bytes((uint8_t *)&rover,
		    sizeof (uint16_t));
		rover = MAX(rover, 2);
		last = rover - 1;
	}

	mutex_enter(&rdsv3_bind_lock);

	do {
		if (rover == 0)
			rover++;
		if (rdsv3_bind_tree_walk(addr, htons(rover), rs) == NULL) {
			*port = htons(rover);
			ret = 0;
			break;
		}
	} while (rover++ != last);

	if (ret == 0)  {
		rs->rs_bound_addr = addr;
		rs->rs_bound_port = *port;
		rdsv3_sock_addref(rs);

		RDSV3_DPRINTF5("rdsv3_add_bound",
		    "rs %p binding to %u.%u.%u.%u:%x",
		    rs, NIPQUAD(addr), *port);

	}

	mutex_exit(&rdsv3_bind_lock);

	RDSV3_DPRINTF4("rdsv3_add_bound", "Return(port: %x)", *port);

	return (ret);
}

void
rdsv3_remove_bound(struct rdsv3_sock *rs)
{
	RDSV3_DPRINTF4("rdsv3_remove_bound", "Enter(rs: %p)", rs);

	mutex_enter(&rdsv3_bind_lock);

	if (rs->rs_bound_addr) {
		RDSV3_DPRINTF5("rdsv3_remove_bound",
		    "rs %p unbinding from %u.%u.%u.%u:%x",
		    rs, NIPQUAD(rs->rs_bound_addr), rs->rs_bound_port);

		avl_remove(&rdsv3_bind_tree, rs);
		rdsv3_sock_put(rs);
		rs->rs_bound_addr = 0;
	}

	mutex_exit(&rdsv3_bind_lock);

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
	if (rs->rs_transport == NULL) {
		rdsv3_remove_bound(rs);
		return (EADDRNOTAVAIL);
	}

	RDSV3_DPRINTF4("rdsv3_bind", "Return: Assigned port: %x to sock: %p",
	    sin->sin_port, rs);

	return (0);
}
