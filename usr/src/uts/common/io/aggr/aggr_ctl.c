/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IEEE 802.3ad Link Aggregation -- IOCTL processing.
 */

#include <sys/ddi.h>
#include <sys/aggr.h>
#include <sys/aggr_impl.h>

static int aggr_ioc_create(int, void *, int);
static int aggr_ioc_delete(int, void *, int);
static int aggr_ioc_info(int, void *, int);
static int aggr_ioc_add_remove(int, void *, int);
static int aggr_ioc_status(int, void *, int);
static int aggr_ioc_modify(int, void *, int);

typedef struct ioc_cmd_s {
	int ic_cmd;
	int (*ic_func)(int, void *, int);
} ioc_cmd_t;

static ioc_cmd_t ioc_cmd[] = {
	{LAIOC_CREATE, aggr_ioc_create},
	{LAIOC_DELETE, aggr_ioc_delete},
	{LAIOC_INFO, aggr_ioc_info},
	{LAIOC_ADD, aggr_ioc_add_remove},
	{LAIOC_REMOVE, aggr_ioc_add_remove},
	{LAIOC_MODIFY, aggr_ioc_modify}};

/*ARGSUSED*/
int
aggr_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	/* only the control interface can be opened */
	if (getminor(*devp) != AGGR_MINOR_CTL)
		return (ENOSYS);
	return (0);
}

/*ARGSUSED*/
int
aggr_close(dev_t dev, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

/*
 * Process a LAIOC_MODIFY request.
 */
/* ARGSUSED */
static int
aggr_ioc_modify(int cmd, void *arg, int mode)
{
	STRUCT_DECL(laioc_modify, modify_arg);
	uint32_t policy;
	boolean_t mac_fixed;
	uchar_t mac_addr[ETHERADDRL];
	uint8_t modify_mask_arg, modify_mask = 0;
	uint32_t key;
	aggr_lacp_mode_t lacp_mode;
	aggr_lacp_timer_t lacp_timer;

	STRUCT_INIT(modify_arg, mode);

	if (copyin(arg, STRUCT_BUF(modify_arg), STRUCT_SIZE(modify_arg)) != 0)
		return (EFAULT);

	key = STRUCT_FGET(modify_arg, lu_key);
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

	return (aggr_grp_modify(key, NULL, modify_mask, policy, mac_fixed,
	    mac_addr, lacp_mode, lacp_timer));
}

/*
 * Process a LAIOC_CREATE request.
 */
/* ARGSUSED */
static int
aggr_ioc_create(int cmd, void *arg, int mode)
{
	STRUCT_DECL(laioc_create, create_arg);
	uint16_t nports;
	laioc_port_t *ports = NULL;
	uint32_t policy;
	boolean_t mac_fixed;
	uchar_t mac_addr[ETHERADDRL];
	aggr_lacp_mode_t lacp_mode;
	aggr_lacp_timer_t lacp_timer;
	int rc;

	STRUCT_INIT(create_arg, mode);

	if (copyin(arg, STRUCT_BUF(create_arg), STRUCT_SIZE(create_arg)) != 0)
		return (EFAULT);

	nports = STRUCT_FGET(create_arg, lc_nports);
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	policy = STRUCT_FGET(create_arg, lc_policy);
	lacp_mode = STRUCT_FGET(create_arg, lc_lacp_mode);
	lacp_timer = STRUCT_FGET(create_arg, lc_lacp_timer);

	ports = kmem_alloc(nports * sizeof (laioc_port_t), KM_SLEEP);

	if (copyin(STRUCT_FGETP(create_arg, lc_ports), ports,
	    nports * sizeof (laioc_port_t)) != 0) {
		rc = EFAULT;
		goto bail;
	}

	bcopy(STRUCT_FGET(create_arg, lc_mac), mac_addr, ETHERADDRL);
	mac_fixed = STRUCT_FGET(create_arg, lc_mac_fixed);

	rc = aggr_grp_create(STRUCT_FGET(create_arg, lc_key),
	    nports, ports, policy, mac_fixed, mac_addr, lacp_mode, lacp_timer);

bail:
	kmem_free(ports, nports * sizeof (laioc_port_t));
	return (rc);
}

/* ARGSUSED */
static int
aggr_ioc_delete(int cmd, void *arg, int mode)
{
	STRUCT_DECL(laioc_delete, delete_arg);

	STRUCT_INIT(delete_arg, mode);

	if (copyin(arg, STRUCT_BUF(delete_arg), STRUCT_SIZE(delete_arg)) != 0)
		return (EFAULT);

	return (aggr_grp_delete(STRUCT_FGET(delete_arg, ld_key)));
}

typedef struct aggr_ioc_info_state {
	uint32_t bytes_left;
	uchar_t *where;			/* in user buffer */
} aggr_ioc_info_state_t;

static int
aggr_ioc_info_new_grp(void *arg, uint32_t key, uchar_t *mac,
    boolean_t mac_fixed, uint32_t policy, uint32_t nports,
    aggr_lacp_mode_t lacp_mode, aggr_lacp_timer_t lacp_timer)
{
	aggr_ioc_info_state_t *state = arg;
	laioc_info_group_t grp;

	if (state->bytes_left < sizeof (grp))
		return (ENOSPC);

	grp.lg_key = key;
	bcopy(mac, grp.lg_mac, ETHERADDRL);
	grp.lg_mac_fixed = mac_fixed;
	grp.lg_policy = policy;
	grp.lg_nports = nports;
	grp.lg_lacp_mode = lacp_mode;
	grp.lg_lacp_timer = lacp_timer;

	if (copyout(&grp, state->where, sizeof (grp)) != 0)
		return (EFAULT);

	state->where += sizeof (grp);
	state->bytes_left -= sizeof (grp);

	return (0);
}

static int
aggr_ioc_info_new_port(void *arg, char *devname, uint32_t portnum,
    uchar_t *mac, aggr_port_state_t portstate, aggr_lacp_state_t *lacp_state)
{
	aggr_ioc_info_state_t *state = arg;
	laioc_info_port_t port;

	if (state->bytes_left < sizeof (port))
		return (ENOSPC);

	bcopy(devname, port.lp_devname, MAXNAMELEN + 1);
	port.lp_port = portnum;
	bcopy(mac, port.lp_mac, ETHERADDRL);
	port.lp_state = portstate;
	port.lp_lacp_state = *lacp_state;

	if (copyout(&port, state->where, sizeof (port)) != 0)
		return (EFAULT);

	state->where += sizeof (port);
	state->bytes_left -= sizeof (port);

	return (0);
}

/*ARGSUSED*/
static int
aggr_ioc_info(int cmd, void *arg, int mode)
{
	laioc_info_t info_arg;
	uint32_t ngroups, group_key;
	int rc;
	aggr_ioc_info_state_t state;

	if (copyin(arg, &info_arg, sizeof (info_arg)) != 0)
		return (EFAULT);

	/*
	 * Key of the group to return. If zero, the call returns information
	 * regarding all groups currently defined.
	 */
	group_key = info_arg.li_group_key;

	state.bytes_left = info_arg.li_bufsize - sizeof (laioc_info_t);
	state.where = (uchar_t *)arg + sizeof (laioc_info_t);

	rc = aggr_grp_info(&ngroups, group_key, &state, aggr_ioc_info_new_grp,
	    aggr_ioc_info_new_port);
	if (rc == 0) {
		info_arg.li_ngroups = ngroups;
		if (copyout(&info_arg, arg, sizeof (info_arg)) != 0)
			return (EFAULT);
	}
	return (rc);
}

/*ARGSUSED*/
static int
aggr_ioc_add_remove(int cmd, void *arg, int mode)
{
	STRUCT_DECL(laioc_add_rem, add_rem_arg);
	uint16_t nports;
	laioc_port_t *ports = NULL;
	int rc;

	STRUCT_INIT(add_rem_arg, mode);

	if (copyin(arg, STRUCT_BUF(add_rem_arg), STRUCT_SIZE(add_rem_arg)) != 0)
		return (EFAULT);

	nports = STRUCT_FGET(add_rem_arg, la_nports);
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	ports = kmem_alloc(nports * sizeof (laioc_port_t), KM_SLEEP);

	if (copyin(STRUCT_FGETP(add_rem_arg, la_ports), ports,
	    nports * sizeof (laioc_port_t)) != 0) {
		rc = EFAULT;
		goto bail;
	}

	switch (cmd) {
	case LAIOC_ADD:
		rc = aggr_grp_add_ports(STRUCT_FGET(add_rem_arg, la_key),
		    nports, ports);
		break;
	case LAIOC_REMOVE:
		rc = aggr_grp_rem_ports(STRUCT_FGET(add_rem_arg, la_key),
		    nports, ports);
		break;
	default:
		rc = EINVAL;
	}

bail:
	if (ports != NULL)
		kmem_free(ports, nports * sizeof (laioc_port_t));
	return (rc);
}

/*ARGSUSED*/
static int
aggr_ioc_remove(void *arg, int mode)
{
	STRUCT_DECL(laioc_add_rem, rem_arg);
	uint16_t nports;
	laioc_port_t *ports = NULL;
	int rc;

	STRUCT_INIT(rem_arg, mode);

	if (copyin(arg, STRUCT_BUF(rem_arg), STRUCT_SIZE(rem_arg)) != 0)
		return (EFAULT);

	nports = STRUCT_FGET(rem_arg, la_nports);
	if (nports > AGGR_MAX_PORTS)
		return (EINVAL);

	ports = kmem_alloc(nports * sizeof (laioc_port_t), KM_SLEEP);

	if (copyin(STRUCT_FGETP(rem_arg, la_ports), ports,
	    nports * sizeof (laioc_port_t)) != 0) {
		rc = EFAULT;
		goto bail;
	}

	rc = aggr_grp_rem_ports(STRUCT_FGET(rem_arg, la_key),
	    nports, ports);

bail:
	if (ports != NULL)
		kmem_free(ports, nports * sizeof (laioc_port_t));
	return (rc);
}

/*ARGSUSED*/
int
aggr_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr, int *rv)
{
	int i;

	for (i = 0; i < sizeof (ioc_cmd) / sizeof (ioc_cmd_t); i++) {
		if (cmd == ioc_cmd[i].ic_cmd)
			return (ioc_cmd[i].ic_func(cmd, (void *)arg, mode));
	}

	return (EINVAL);
}
