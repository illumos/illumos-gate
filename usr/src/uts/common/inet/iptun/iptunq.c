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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The sole purpose of this module is to provide a STREAMS queue to the iptun
 * module so that it can call ip module functions which require one.  Once the
 * ip module no longer requires a STREAMS queue for bind processing, all of
 * this complexity can be removed.
 */

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ipclassifier.h>
#include <sys/stream.h>
#include "iptun_impl.h"

static int	iptunq_open(queue_t *, dev_t *, int, int, cred_t *);
static int	iptunq_close(queue_t *);

static struct module_info iptunq_modinfo = {
	0, "iptunq", 0, INFPSZ, 1, 0
};

static struct qinit iptunq_rinit = {
	NULL, NULL, iptunq_open, iptunq_close, NULL, &iptunq_modinfo, NULL
};

static struct qinit iptunq_winit = {
	(pfi_t)putq, (pfi_t)ip_wsrv, iptunq_open, iptunq_close, NULL,
	&iptunq_modinfo, NULL
};

struct streamtab iptunq_info = {
	&iptunq_rinit, &iptunq_winit, NULL, NULL
};

/* ARGSUSED */
static int
iptunq_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	netstack_t	*ns;
	conn_t		*connp;
	major_t		maj;
	dev_t		conn_dev;

	if (q->q_ptr != NULL)
		return (EBUSY);

	if ((conn_dev = inet_minor_alloc(ip_minor_arena_sa)) == 0)
		return (ENOMEM);

	ns = netstack_find_by_cred(credp);
	iptun_set_g_q(ns, q);
	connp = ipcl_conn_create(IPCL_IPCCONN, KM_NOSLEEP, ns);
	netstack_rele(ns);
	if (connp == NULL) {
		inet_minor_free(ip_minor_arena_sa, conn_dev);
		return (ENOMEM);
	}

	connp->conn_flags |= IPCL_IPTUN;
	connp->conn_zoneid = (ns->netstack_stackid == GLOBAL_NETSTACKID) ?
	    crgetzoneid(credp) : GLOBAL_ZONEID;
	connp->conn_dev = conn_dev;
	connp->conn_minor_arena = ip_minor_arena_sa;

	maj = getmajor(*devp);
	*devp = makedevice(maj, (minor_t)connp->conn_dev);
	connp->conn_cred = credp;
	crhold(connp->conn_cred);

	q->q_ptr = WR(q)->q_ptr = connp;
	connp->conn_rq = q;
	connp->conn_wq = WR(q);

	ASSERT(connp->conn_ref == 1);
	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);

	qprocson(q);
	return (0);
}

static int
iptunq_close(queue_t *q)
{
	conn_t *connp = q->q_ptr;

	iptun_clear_g_q(connp->conn_netstack);
	ip_quiesce_conn(connp);
	qprocsoff(q);
	inet_minor_free(connp->conn_minor_arena, connp->conn_dev);
	connp->conn_ref--;
	ipcl_conn_destroy(connp);
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}
