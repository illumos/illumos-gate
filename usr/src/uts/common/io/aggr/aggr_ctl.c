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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEEE 802.3ad Link Aggregation -- IOCTL processing.
 */

#include <sys/ddi.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>
#include <sys/strsun.h>

static int aggr_ioc_create(mblk_t *, int);
static int aggr_ioc_delete(mblk_t *, int);
static int aggr_ioc_info(mblk_t *, int);
static int aggr_ioc_add(mblk_t *, int);
static int aggr_ioc_remove(mblk_t *, int);
static int aggr_ioc_modify(mblk_t *, int);

typedef struct ioc_cmd_s {
	int ic_cmd;
	int (*ic_func)(mblk_t *, int);
} ioc_cmd_t;

static ioc_cmd_t ioc_cmd[] = {
	{LAIOC_CREATE, aggr_ioc_create},
	{LAIOC_DELETE, aggr_ioc_delete},
	{LAIOC_INFO, aggr_ioc_info},
	{LAIOC_ADD, aggr_ioc_add},
	{LAIOC_REMOVE, aggr_ioc_remove},
	{LAIOC_MODIFY, aggr_ioc_modify}};

#define	IOC_CMD_SZ	(sizeof (ioc_cmd) / sizeof (ioc_cmd_t))

/*
 * Process a LAIOC_MODIFY request.
 */
static int
aggr_ioc_modify(mblk_t *mp, int mode)
{
	STRUCT_HANDLE(laioc_modify, modify_arg);
	uint32_t policy;
	boolean_t mac_fixed;
	uchar_t mac_addr[ETHERADDRL];
	uint8_t modify_mask_arg, modify_mask = 0;
	datalink_id_t linkid;
	uint32_t rc;
	aggr_lacp_mode_t lacp_mode;
	aggr_lacp_timer_t lacp_timer;

	STRUCT_SET_HANDLE(modify_arg, mode, (void *)mp->b_cont->b_rptr);
	if (MBLKL(mp->b_cont) < STRUCT_SIZE(modify_arg))
		return (EINVAL);

	linkid = STRUCT_FGET(modify_arg, lu_linkid);
	modify_mask_arg = STRUCT_FGET(modify_arg, lu_modify_mask);

	if (modify_mask_arg & LAIOC_MODIFY_POLICY) {
		modify_mask |= AGGR_MODIFY_POLICY;
		policy = STRUCT_FGET(modify_arg, lu_policy);
	}

	if (modify_mask_arg & LAIOC_MODIFY_MAC) {
		modify_mask |= AGGR_MODIFY_MAC;
		bcopy(STRUCT_FGET(modify_arg, lu_mac), mac_addr, ETHERADDRL);
		mac_fixed = STRUCT_FGET(modify_arg, lu_mac_fixed);
	}

	if (modify_mask_arg & LAIOC_MODIFY_LACP_MODE) {
		modify_mask |= AGGR_MODIFY_LACP_MODE;
		lacp_mode = STRUCT_FGET(modify_arg, lu_lacp_mode);
	}

	if (modify_mask_arg & LAIOC_MODIFY_LACP_TIMER) {
		modify_mask |= AGGR_MODIFY_LACP_TIMER;
		lacp_timer = STRUCT_FGET(modify_arg, lu_lacp_timer);
	}

	rc = aggr_grp_modify(linkid, NULL, modify_mask, policy, mac_fixed,
	    mac_addr, lacp_mode, lacp_timer);

	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	return (rc);
}

/*
 * Process a LAIOC_CREATE request.
 */
static int
aggr_ioc_create(mblk_t *mp, int mode)
{
	STRUCT_HANDLE(laioc_create, create_arg);
	uint16_t nports;
	laioc_port_t *ports = NULL;
	uint32_t policy;
	boolean_t mac_fixed;
	boolean_t force;
	uchar_t mac_addr[ETHERADDRL];
	aggr_lacp_mode_t lacp_mode;
	aggr_lacp_timer_t lacp_timer;
	int rc, len;

	STRUCT_SET_HANDLE(create_arg, mode, (void *)mp->b_cont->b_rptr);
	if ((len = MBLKL(mp->b_cont)) < STRUCT_SIZE(create_arg))
		return (EINVAL);

	nports = STRUCT_FGET(create_arg, lc_nports);
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	policy = STRUCT_FGET(create_arg, lc_policy);
	lacp_mode = STRUCT_FGET(create_arg, lc_lacp_mode);
	lacp_timer = STRUCT_FGET(create_arg, lc_lacp_timer);

	if (len < STRUCT_SIZE(create_arg) + (nports * sizeof (laioc_port_t)))
		return (EINVAL);

	ports = (laioc_port_t *)(STRUCT_BUF(create_arg) + 1);

	bcopy(STRUCT_FGET(create_arg, lc_mac), mac_addr, ETHERADDRL);
	mac_fixed = STRUCT_FGET(create_arg, lc_mac_fixed);
	force = STRUCT_FGET(create_arg, lc_force);

	rc = aggr_grp_create(STRUCT_FGET(create_arg, lc_linkid),
	    STRUCT_FGET(create_arg, lc_key), nports, ports, policy,
	    mac_fixed, force, mac_addr, lacp_mode, lacp_timer);

	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	return (rc);
}

static int
aggr_ioc_delete(mblk_t *mp, int mode)
{
	STRUCT_HANDLE(laioc_delete, delete_arg);
	int rc;

	STRUCT_SET_HANDLE(delete_arg, mode, (void *)mp->b_cont->b_rptr);
	if (STRUCT_SIZE(delete_arg) > MBLKL(mp))
		return (EINVAL);

	rc = aggr_grp_delete(STRUCT_FGET(delete_arg, ld_linkid));

	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	return (rc);
}

typedef struct aggr_ioc_info_state {
	uint32_t bytes_left;
	uchar_t *where;
} aggr_ioc_info_state_t;

static int
aggr_ioc_info_new_grp(void *arg, datalink_id_t linkid, uint32_t key,
    uchar_t *mac, boolean_t mac_fixed, boolean_t force, uint32_t policy,
    uint32_t nports, aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer)
{
	aggr_ioc_info_state_t *state = arg;
	laioc_info_group_t grp;

	if (state->bytes_left < sizeof (grp))
		return (ENOSPC);

	grp.lg_linkid = linkid;
	grp.lg_key = key;
	bcopy(mac, grp.lg_mac, ETHERADDRL);
	grp.lg_mac_fixed = mac_fixed;
	grp.lg_force = force;
	grp.lg_policy = policy;
	grp.lg_nports = nports;
	grp.lg_lacp_mode = lacp_mode;
	grp.lg_lacp_timer = lacp_timer;

	bcopy(&grp, state->where, sizeof (grp));
	state->where += sizeof (grp);
	state->bytes_left -= sizeof (grp);

	return (0);
}

static int
aggr_ioc_info_new_port(void *arg, datalink_id_t linkid, uchar_t *mac,
    aggr_port_state_t portstate, aggr_lacp_state_t *lacp_state)
{
	aggr_ioc_info_state_t *state = arg;
	laioc_info_port_t port;

	if (state->bytes_left < sizeof (port))
		return (ENOSPC);

	port.lp_linkid = linkid;
	bcopy(mac, port.lp_mac, ETHERADDRL);
	port.lp_state = portstate;
	port.lp_lacp_state = *lacp_state;

	bcopy(&port, state->where, sizeof (port));
	state->where += sizeof (port);
	state->bytes_left -= sizeof (port);

	return (0);
}

/*ARGSUSED*/
static int
aggr_ioc_info(mblk_t *mp, int mode)
{
	laioc_info_t *info_argp;
	datalink_id_t linkid;
	int rc, len;
	aggr_ioc_info_state_t state;

	if ((len = MBLKL(mp->b_cont)) < sizeof (*info_argp))
		return (EINVAL);

	info_argp = (laioc_info_t *)mp->b_cont->b_rptr;

	/*
	 * linkid of the group to return. Must not be DATALINK_INVALID_LINKID.
	 */
	if ((linkid = info_argp->li_group_linkid) == DATALINK_INVALID_LINKID)
		return (EINVAL);

	state.bytes_left = len - sizeof (laioc_info_t);
	state.where = (uchar_t *)(info_argp + 1);

	rc = aggr_grp_info(linkid, &state,
	    aggr_ioc_info_new_grp, aggr_ioc_info_new_port);

	return (rc);
}

static int
aggr_ioc_add(mblk_t *mp, int mode)
{
	STRUCT_HANDLE(laioc_add_rem, add_arg);
	uint32_t nports;
	laioc_port_t *ports = NULL;
	boolean_t force;
	int rc, len;

	STRUCT_SET_HANDLE(add_arg, mode, (void *)mp->b_cont->b_rptr);
	if ((len = MBLKL(mp->b_cont)) < STRUCT_SIZE(add_arg))
		return (EINVAL);

	nports = STRUCT_FGET(add_arg, la_nports);
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	if (len < STRUCT_SIZE(add_arg) + (nports * sizeof (laioc_port_t)))
		return (EINVAL);

	ports = (laioc_port_t *)(STRUCT_BUF(add_arg) + 1);
	force = STRUCT_FGET(add_arg, la_force);

	rc = aggr_grp_add_ports(STRUCT_FGET(add_arg, la_linkid),
	    nports, force, ports);

	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	return (rc);
}

static int
aggr_ioc_remove(mblk_t *mp, int mode)
{
	STRUCT_HANDLE(laioc_add_rem, rem_arg);
	uint32_t nports;
	laioc_port_t *ports = NULL;
	int rc, len;

	STRUCT_SET_HANDLE(rem_arg, mode, (void *)mp->b_cont->b_rptr);
	if ((len = MBLKL(mp->b_cont)) < STRUCT_SIZE(rem_arg))
		return (EINVAL);

	nports = STRUCT_FGET(rem_arg, la_nports);
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	if (len < STRUCT_SIZE(rem_arg) + (nports * sizeof (laioc_port_t)))
		return (EINVAL);

	ports = (laioc_port_t *)(STRUCT_BUF(rem_arg) + 1);

	rc = aggr_grp_rem_ports(STRUCT_FGET(rem_arg, la_linkid),
	    nports, ports);

	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	return (rc);
}

void
aggr_ioctl(queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	int i, err = EINVAL;
	mblk_t *nmp;

	if (mp->b_cont == NULL)
		goto done;

	/*
	 * Construct contiguous message
	 */
	if ((nmp = msgpullup(mp->b_cont, -1)) == NULL) {
		err = ENOMEM;
		goto done;
	}

	freemsg(mp->b_cont);
	mp->b_cont = nmp;

	for (i = 0; i < IOC_CMD_SZ; i++) {
		if (iocp->ioc_cmd == ioc_cmd[i].ic_cmd) {
			err = ioc_cmd[i].ic_func(mp, (int)iocp->ioc_flag);
			break;
		}
	}

	if (err == 0) {
		int len = 0;

		if (mp->b_cont != NULL) {
			len = MBLKL(mp->b_cont);
		}
		miocack(wq, mp, len, 0);
		return;
	}

done:
	miocnak(wq, mp, 0, err);
}
