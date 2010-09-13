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
 * This file implements the ioctl control path for the iptun driver.  The
 * GLDv3 dld_ioc_register() mechanism is used to register iptun ioctls with
 * the dld module.
 */

#include <sys/dld_ioc.h>
#include <sys/policy.h>
#include <inet/iptun.h>
#include "iptun_impl.h"

/* ARGSUSED */
static int
iptun_ioc_create(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	return (iptun_create(karg, cred));
}

/* ARGSUSED */
static int
iptun_ioc_delete(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	return (iptun_delete(*(datalink_id_t *)karg, cred));
}

/* ARGSUSED */
static int
iptun_ioc_modify(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	return (iptun_modify(karg, cred));
}

/* ARGSUSED */
static int
iptun_ioc_info(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	return (iptun_info(karg, cred));
}

/* ARGSUSED */
static int
iptun_ioc_set_6to4relay(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	ipaddr_t	*relay = karg;
	netstack_t	*ns = netstack_find_by_cred(cred);
	int		err;

	err = iptun_set_6to4relay(ns, *relay);
	netstack_rele(ns);
	return (err);
}

/* ARGSUSED */
static int
iptun_ioc_get_6to4relay(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	ipaddr_t	*relay = karg;
	netstack_t	*ns = netstack_find_by_cred(cred);

	iptun_get_6to4relay(ns, relay);
	netstack_rele(ns);
	return (0);
}

static dld_ioc_info_t	iptun_ioc_list[] = {
	{ IPTUN_CREATE,		DLDCOPYIN,	sizeof (iptun_kparams_t),
	    iptun_ioc_create,		secpolicy_iptun_config},
	{ IPTUN_DELETE,		DLDCOPYIN,	sizeof (datalink_id_t),
	    iptun_ioc_delete,		secpolicy_iptun_config},
	{ IPTUN_MODIFY,		DLDCOPYIN,	sizeof (iptun_kparams_t),
	    iptun_ioc_modify,		secpolicy_iptun_config},
	{ IPTUN_INFO,		DLDCOPYINOUT,	sizeof (iptun_kparams_t),
	    iptun_ioc_info,		NULL},
	{ IPTUN_SET_6TO4RELAY,	DLDCOPYIN,	sizeof (struct in_addr),
	    iptun_ioc_set_6to4relay,	secpolicy_iptun_config},
	{ IPTUN_GET_6TO4RELAY,	DLDCOPYINOUT,	sizeof (struct in_addr),
	    iptun_ioc_get_6to4relay,	NULL}
};

int
iptun_ioc_init(void)
{
	return (dld_ioc_register(IPTUN_IOC, iptun_ioc_list,
	    DLDIOCCNT(iptun_ioc_list)));
}

void
iptun_ioc_fini(void)
{
	dld_ioc_unregister(IPTUN_IOC);
}
