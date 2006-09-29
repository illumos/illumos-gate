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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nss_common.h>
#include <nss_dbdefs.h>
#include "nscd_common.h"
#include "nscd_switch.h"

void
_nss_initf_passwd(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PASSWD;
	p->default_config = NSS_DEFCONF_PASSWD;
}

void
_nss_initf_hosts(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_HOSTS;
	p->default_config = NSS_DEFCONF_HOSTS;
}

void
_nss_initf_group(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_GROUP;
	p->default_config = NSS_DEFCONF_GROUP;
}

void
_nss_initf_ipnodes(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_IPNODES;
	p->default_config = NSS_DEFCONF_IPNODES;
}

void
_nss_initf_net(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_NETWORKS;
	p->default_config = NSS_DEFCONF_NETWORKS;
}

void
_nss_initf_proto(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PROTOCOLS;
	p->default_config = NSS_DEFCONF_PROTOCOLS;
}

void
_nss_initf_rpc(p)
	nss_db_params_t	*p;
{
	p->name	= NSS_DBNAM_RPC;
	p->default_config = NSS_DEFCONF_RPC;
}

void
_nss_initf_ethers(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_ETHERS;
	p->default_config = NSS_DEFCONF_ETHERS;
}

void
_nss_initf_netmasks(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_NETMASKS;
	p->default_config = NSS_DEFCONF_NETMASKS;
}

void
_nss_initf_bootparams(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_BOOTPARAMS;
	p->default_config = NSS_DEFCONF_BOOTPARAMS;
}

void
_nss_initf_publickey(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PUBLICKEY;
	p->default_config = NSS_DEFCONF_PUBLICKEY;
}

void
_nss_initf_netgroup(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_NETGROUP;
	p->default_config = NSS_DEFCONF_NETGROUP;
}

void
_nss_initf_services(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_SERVICES;
	p->default_config = NSS_DEFCONF_SERVICES;
}

void
_nss_initf_printers(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PRINTERS;
	p->default_config = NSS_DEFCONF_PRINTERS;
}

void
_nss_initf_authattr(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_AUTHATTR;
	p->default_config = NSS_DEFCONF_AUTHATTR;
}

void
_nss_initf_profattr(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PROFATTR;
	p->default_config = NSS_DEFCONF_PROFATTR;
}

void
_nss_initf_execattr(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_EXECATTR;
	p->default_config = NSS_DEFCONF_PROFATTR;
	p->config_name    = NSS_DBNAM_PROFATTR; /* use config for "prof_attr" */
}

void
_nss_initf_userattr(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_USERATTR;
	p->config_name = NSS_DBNAM_PASSWD;
	p->default_config = NSS_DEFCONF_USERATTR;
}

void
_nss_initf_project(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PROJECT;
	p->default_config = NSS_DEFCONF_PROJECT;
}

void
_nss_initf_auuser(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_AUDITUSER;
	p->config_name	= NSS_DBNAM_PASSWD;
	p->default_config = NSS_DEFCONF_AUDITUSER;
}

void
_nss_initf_shadow(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_SHADOW;
	p->config_name	= NSS_DBNAM_PASSWD;
	p->default_config = NSS_DEFCONF_PASSWD;
}

void
_nss_initf_passwd_compat(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_PASSWD;
	p->config_name	= NSS_DBNAM_PASSWD_COMPAT;
	p->default_config = NSS_DEFCONF_PASSWD_COMPAT;
}

void
_nss_initf_group_compat(nss_db_params_t *p)
{
	p->name	= NSS_DBNAM_GROUP;
	p->config_name	= NSS_DBNAM_GROUP_COMPAT;
	p->default_config = NSS_DEFCONF_GROUP_COMPAT;
}

void
_nss_initf_tsol_rh(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_TSOL_RH;
	p->default_config = NSS_DEFCONF_TSOL_RH;
}

void
_nss_initf_tsol_tp(nss_db_params_t *p)
{
	p->name = NSS_DBNAM_TSOL_TP;
	p->default_config = NSS_DEFCONF_TSOL_TP;
}

nss_db_initf_t	nscd_nss_db_initf[] = {
	_nss_initf_passwd,
	_nss_initf_hosts,
	_nss_initf_group,
	_nss_initf_ipnodes,
	_nss_initf_net,
	_nss_initf_proto,
	_nss_initf_rpc,
	_nss_initf_ethers,
	_nss_initf_netmasks,
	_nss_initf_bootparams,
	_nss_initf_publickey,
	_nss_initf_netgroup,
	_nss_initf_services,
	_nss_initf_printers,
	_nss_initf_authattr,
	_nss_initf_profattr,
	_nss_initf_execattr,
	_nss_initf_userattr,
	_nss_initf_project,
	_nss_initf_shadow,
	_nss_initf_auuser,
	_nss_initf_tsol_rh,
	_nss_initf_tsol_tp,
	_nss_initf_passwd_compat,
	_nss_initf_group_compat,
	/*
	 * no initf() for pseudo-databases: passwd, shadow,
	 * audit_user, user_attr, and group (when called from
	 * the compat backend)
	 */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL};
