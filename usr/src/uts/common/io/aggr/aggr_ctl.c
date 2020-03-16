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
 * IEEE 802.3ad Link Aggregation -- IOCTL processing.
 */

#include <sys/aggr.h>
#include <sys/aggr_impl.h>
#include <sys/policy.h>

/*
 * Process a LAIOC_MODIFY request.
 */
/* ARGSUSED */
static int
aggr_ioc_modify(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	laioc_modify_t *modify_arg = karg;
	uint32_t policy;
	boolean_t mac_fixed;
	uchar_t mac_addr[ETHERADDRL];
	uint8_t modify_mask_arg, modify_mask = 0;
	aggr_lacp_mode_t lacp_mode;
	aggr_lacp_timer_t lacp_timer;

	policy = 0;
	mac_fixed = B_FALSE;
	lacp_mode = AGGR_LACP_OFF;
	lacp_timer = AGGR_LACP_TIMER_LONG;

	modify_mask_arg = modify_arg->lu_modify_mask;

	if (modify_mask_arg & LAIOC_MODIFY_POLICY) {
		modify_mask |= AGGR_MODIFY_POLICY;
		policy = modify_arg->lu_policy;
	}

	if (modify_mask_arg & LAIOC_MODIFY_MAC) {
		modify_mask |= AGGR_MODIFY_MAC;
		bcopy(modify_arg->lu_mac, mac_addr, ETHERADDRL);
		mac_fixed = modify_arg->lu_mac_fixed;
	}

	if (modify_mask_arg & LAIOC_MODIFY_LACP_MODE) {
		modify_mask |= AGGR_MODIFY_LACP_MODE;
		lacp_mode = modify_arg->lu_lacp_mode;
	}

	if (modify_mask_arg & LAIOC_MODIFY_LACP_TIMER) {
		modify_mask |= AGGR_MODIFY_LACP_TIMER;
		lacp_timer = modify_arg->lu_lacp_timer;
	}

	return (aggr_grp_modify(modify_arg->lu_linkid, modify_mask, policy,
	    mac_fixed, mac_addr, lacp_mode, lacp_timer));
}

/*
 * Process a LAIOC_CREATE request.
 */
/* ARGSUSED */
static int
aggr_ioc_create(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	laioc_create_t *create_arg = karg;
	uint16_t nports;
	laioc_port_t *ports = NULL;
	size_t ports_size;
	uint32_t policy;
	boolean_t mac_fixed;
	boolean_t force;
	uchar_t mac_addr[ETHERADDRL];
	aggr_lacp_mode_t lacp_mode;
	aggr_lacp_timer_t lacp_timer;
	int rc;

	nports = create_arg->lc_nports;
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	policy = create_arg->lc_policy;
	lacp_mode = create_arg->lc_lacp_mode;
	lacp_timer = create_arg->lc_lacp_timer;

	ports_size = nports * sizeof (laioc_port_t);
	ports = kmem_alloc(ports_size, KM_SLEEP);

	if (ddi_copyin((uchar_t *)arg + sizeof (*create_arg), ports,
	    ports_size, mode) != 0) {
		rc = EFAULT;
		goto done;
	}

	bcopy(create_arg->lc_mac, mac_addr, ETHERADDRL);
	mac_fixed = create_arg->lc_mac_fixed;
	force = create_arg->lc_force;

	rc = aggr_grp_create(create_arg->lc_linkid, create_arg->lc_key, nports,
	    ports, policy, mac_fixed, force, mac_addr, lacp_mode, lacp_timer,
	    cred);

done:
	kmem_free(ports, ports_size);
	return (rc);
}

/* ARGSUSED */
static int
aggr_ioc_delete(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	laioc_delete_t *delete_arg = karg;

	return (aggr_grp_delete(delete_arg->ld_linkid, cred));
}

typedef struct aggr_ioc_info_state {
	uint32_t	bytes_left;
	uchar_t		*where;		/* in user buffer */
	int		mode;
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

	if (ddi_copyout(&grp, state->where, sizeof (grp), state->mode) != 0)
		return (EFAULT);

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

	if (ddi_copyout(&port, state->where, sizeof (port), state->mode) != 0)
		return (EFAULT);

	state->where += sizeof (port);
	state->bytes_left -= sizeof (port);

	return (0);
}

/*ARGSUSED*/
static int
aggr_ioc_info(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	laioc_info_t *info_argp = karg;
	aggr_ioc_info_state_t state;

	state.bytes_left = info_argp->li_bufsize - sizeof (laioc_info_t);
	state.where = (uchar_t *)arg + sizeof (laioc_info_t);
	state.mode = mode;

	return (aggr_grp_info(info_argp->li_group_linkid, &state,
	    aggr_ioc_info_new_grp, aggr_ioc_info_new_port, cred));
}

static int
aggr_ioc_add_remove(laioc_add_rem_t *add_rem_arg, intptr_t arg, int cmd,
    int mode)
{
	uint16_t nports;
	laioc_port_t *ports = NULL;
	size_t ports_size;
	int rc;

	nports = add_rem_arg->la_nports;
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	ports_size = nports * sizeof (laioc_port_t);
	ports = kmem_alloc(ports_size, KM_SLEEP);
	if (ddi_copyin((uchar_t *)arg + sizeof (*add_rem_arg), ports,
	    ports_size, mode) != 0) {
		rc = EFAULT;
		goto done;
	}

	switch (cmd) {
	case LAIOC_ADD:
		rc = aggr_grp_add_ports(add_rem_arg->la_linkid, nports,
		    add_rem_arg->la_force, ports);
		break;
	case LAIOC_REMOVE:
		rc = aggr_grp_rem_ports(add_rem_arg->la_linkid, nports, ports);
		break;
	default:
		rc = 0;
		break;
	}

done:
	kmem_free(ports, ports_size);
	return (rc);
}

/* ARGSUSED */
static int
aggr_ioc_add(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	return (aggr_ioc_add_remove(karg, arg, LAIOC_ADD, mode));
}

/* ARGSUSED */
static int
aggr_ioc_remove(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	return (aggr_ioc_add_remove(karg, arg, LAIOC_REMOVE, mode));
}

static dld_ioc_info_t aggr_ioc_list[] = {
	{LAIOC_CREATE, DLDCOPYIN, sizeof (laioc_create_t), aggr_ioc_create,
	    secpolicy_dl_config},
	{LAIOC_DELETE, DLDCOPYIN, sizeof (laioc_delete_t), aggr_ioc_delete,
	    secpolicy_dl_config},
	{LAIOC_INFO, DLDCOPYINOUT, sizeof (laioc_info_t), aggr_ioc_info, NULL},
	{LAIOC_ADD, DLDCOPYIN, sizeof (laioc_add_rem_t), aggr_ioc_add,
	    secpolicy_dl_config},
	{LAIOC_REMOVE, DLDCOPYIN, sizeof (laioc_add_rem_t), aggr_ioc_remove,
	    secpolicy_dl_config},
	{LAIOC_MODIFY, DLDCOPYIN, sizeof (laioc_modify_t), aggr_ioc_modify,
	    secpolicy_dl_config}
};

int
aggr_ioc_init(void)
{
	return (dld_ioc_register(AGGR_IOC, aggr_ioc_list,
	    DLDIOCCNT(aggr_ioc_list)));
}

void
aggr_ioc_fini(void)
{
	dld_ioc_unregister(AGGR_IOC);
}
