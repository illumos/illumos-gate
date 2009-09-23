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
 * DL_6TO4 MAC Type plugin for the Nemo mac module
 */

#include <sys/modctl.h>
#include <sys/dlpi.h>
#include <inet/ip.h>
#include <sys/mac.h>
#include <sys/mac_6to4.h>
#include <sys/mac_ipv4_impl.h>

static struct modlmisc mac_6to4_modlmisc = {
	&mod_miscops,
	"6to4 tunneling MAC plugin"
};

static struct modlinkage mac_6to4_modlinkage = {
	MODREV_1,
	&mac_6to4_modlmisc,
	NULL
};

static mactype_ops_t mac_6to4_type_ops;

int
_init(void)
{
	mactype_register_t *mtrp;
	int	err;

	if ((mtrp = mactype_alloc(MACTYPE_VERSION)) == NULL)
		return (ENOTSUP);
	mtrp->mtr_ident = MAC_PLUGIN_IDENT_6TO4;
	mtrp->mtr_ops = &mac_6to4_type_ops;
	mtrp->mtr_mactype = DL_6TO4;
	mtrp->mtr_nativetype = DL_6TO4;
	mtrp->mtr_addrlen = sizeof (ipaddr_t);
	if ((err = mactype_register(mtrp)) == 0) {
		if ((err = mod_install(&mac_6to4_modlinkage)) != 0)
			(void) mactype_unregister(MAC_PLUGIN_IDENT_6TO4);
	}
	mactype_free(mtrp);
	return (err);
}

int
_fini(void)
{
	int	err;
	if ((err = mactype_unregister(MAC_PLUGIN_IDENT_6TO4)) != 0)
		return (err);
	return (mod_remove(&mac_6to4_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&mac_6to4_modlinkage, modinfop));
}

/*
 * MAC Type plugin operations.  Note that because 6to4 is a form of
 * tunneling over IPv4, this plugin is able to steal most of its operations
 * from the IPv4 plugin.
 */

/*
 * Check the legality of a 6to4 tunnel SAP value.  The only acceptable
 * values are IPPROTO_IPV6 (IPv6 in IPv4 tunneling) and 0 (for snoop).
 */
/* ARGSUSED */
boolean_t
mac_6to4_sap_verify(uint32_t sap, uint32_t *bind_sap, void *pdata)
{
	if (sap == IPPROTO_IPV6 || sap == 0) {
		if (bind_sap != NULL)
			*bind_sap = sap;
		return (B_TRUE);
	}
	return (B_FALSE);
}

static mactype_ops_t	mac_6to4_type_ops = {
	MTOPS_PDATA_VERIFY,
	mac_ipv4_unicst_verify,
	mac_ipv4_multicst_verify,
	mac_6to4_sap_verify,
	mac_ipv4_header,
	mac_ipv4_header_info,
	mac_ipv4_pdata_verify,
	NULL,
	NULL,
	NULL
};
