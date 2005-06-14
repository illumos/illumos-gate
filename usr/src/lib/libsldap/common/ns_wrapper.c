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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ns_sldap.h"
#include "ns_internal.h"

/* ARGSUSED */
static LDAP *
__s_api_getLDAPconn(int flags)
{
	return (NULL);
}

/*
 * Abandon functions
 */
/* ARGSUSED */
int _ns_ldap_abandon_ext(char *service, int flags,
	int msgid, LDAPControl **serverctrls,
	LDAPControl ** clientctrls)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_abandon_ext(ld, msgid, serverctrls, clientctrls));
}

/* ARGSUSED */
int _ns_ldap_abandon(char *service, int flags,
	int msgid)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_abandon(ld, msgid));
}

/*
 * Add functions
 */
/* ARGSUSED */
int _ns_ldap_add_ext(char *service, int flags,
	char *dn, LDAPMod **attrs,
	LDAPControl ** serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_add_ext(ld, dn, attrs,
				serverctrls, clientctrls, msgidp));
}

/* ARGSUSED */
int _ns_ldap_add_ext_s(char *service, int flags,
	char *dn, LDAPMod **attrs,
	LDAPControl ** serverctrls, LDAPControl **clientctrls)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_add_ext_s(ld, dn, attrs, serverctrls, clientctrls));
}

/* ARGSUSED */
int _ns_ldap_add(char *service, int flags,
	char *dn, LDAPMod **attrs)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_add(ld, dn, attrs));
}

/* ARGSUSED */
int _ns_ldap_add_s(char *service, int flags,
	char *dn, LDAPMod **attrs)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_add_s(ld, dn, attrs));
}

/*
 * Compare functions
 */
/* ARGSUSED */
int _ns_ldap_compare_ext(char *service, int flags,
	char *dn, char *attr, struct berval *bvalue,
	LDAPControl ** serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_compare_ext(ld, dn, attr, bvalue,
				    serverctrls, clientctrls, msgidp));
}

/* ARGSUSED */
int _ns_ldap_compare_ext_s(char *service, int flags,
	char *dn, char *attr, struct berval *bvalue,
	LDAPControl ** serverctrls, LDAPControl **clientctrls)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_compare_ext_s(ld, dn, attr, bvalue,
		serverctrls, clientctrls));
}

/* ARGSUSED */
int _ns_ldap_compare(char *service, int flags,
	char *dn, char *attr, char *value)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_compare(ld, dn, attr, value));
}

/* ARGSUSED */
int _ns_ldap_compare_s(char *service, int flags,
	char *dn, char *attr, char *value)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_compare_s(ld, dn, attr, value));
}

/*
 * Delete functions
 */
/* ARGSUSED */
int _ns_ldap_delete_ext(char *service, int flags,
	char *dn, LDAPControl **serverctrls,
	LDAPControl **clientctrls, int *msgidp)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_delete_ext(ld, dn, serverctrls, clientctrls, msgidp));
}

/* ARGSUSED */
int _ns_ldap_delete_ext_s(char *service, int flags,
	char *dn, LDAPControl **serverctrls,
	LDAPControl **clientctrls)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_delete_ext_s(ld, dn, serverctrls, clientctrls));
}

/* ARGSUSED */
int _ns_ldap_delete(char *service, int flags,
	char *dn)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_delete(ld, dn));
}

/* ARGSUSED */
int _ns_ldap_delete_s(char *service, int flags,
	char *dn)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_delete_s(ld, dn));
}

/*
 * Modify functions
 */
/* ARGSUSED */
int _ns_ldap_modify_ext(char *service, int flags,
	char *dn, LDAPMod **mods,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modify_ext(ld, dn, mods, serverctrls,
		clientctrls, msgidp));
}

/* ARGSUSED */
int _ns_ldap_modify_ext_s(char *service, int flags,
	char *dn, LDAPMod **mods,
	LDAPControl **serverctrls, LDAPControl **clientctrls)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modify_ext_s(ld, dn, mods, serverctrls, clientctrls));
}

/* ARGSUSED */
int _ns_ldap_modify(char *service, int flags,
	char *dn, LDAPMod **mods)
/* ARGSUSED */
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modify(ld, dn, mods));
}

/* ARGSUSED */
int _ns_ldap_modify_s(char *service, int flags,
	char *dn, LDAPMod **mods)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modify_s(ld, dn, mods));
}

/*
 * Modrdn functions
 */

/* ARGSUSED */
int _ns_ldap_modrdn(char *service, int flags,
	char *dn, char *newrdn, int deleteoldrdn)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modrdn(ld, dn, newrdn));
}

/* ARGSUSED */
int _ns_ldap_modrdn_s(char *service, int flags,
	char *dn, char *newrdn, int deleteoldrdn)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modrdn_s(ld, dn, newrdn));
}

/* ARGSUSED */
int _ns_ldap_modrdn2(char *service, int flags,
	char *dn, char *newrdn, int deleteoldrdn)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modrdn2(ld, dn, newrdn, deleteoldrdn));
}

/* ARGSUSED */
int _ns_ldap_modrdn2_s(char *service, int flags,
	char *dn, char *newrdn, int deleteoldrdn)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_modrdn2_s(ld, dn, newrdn, deleteoldrdn));
}

/*
 * Rename functions
 */
/* ARGSUSED */
int _ns_ldap_rename(char *service, int flags,
	char *dn, char *newrdn, char *newparent,
	int deleteoldrdn, LDAPControl ** serverctrls,
	LDAPControl **clientctrls, int *msgidp)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_rename(ld, dn, newrdn, newparent,
				deleteoldrdn, serverctrls,
				clientctrls, msgidp));
}

/* ARGSUSED */
int _ns_ldap_rename_s(char *service, int flags,
	char *dn, char *newrdn, char *newparent,
	int deleteoldrdn, LDAPControl ** serverctrls,
	LDAPControl **clientctrls)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_rename_s(ld, dn, newrdn, newparent,
		deleteoldrdn, serverctrls, clientctrls));
}

/*
 * Result functions
 */
/* ARGSUSED */
int _ns_ldap_result(char *service, int flags,
	int msgid, int all,
	struct timeval *timeout, LDAPMessage **result)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_result(ld, msgid, all, timeout, result));
}

/*
 * Search functions
 */
/* ARGSUSED */
int _ns_ldap_search_ext(char *service, int flags,
	char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeoutp,
	int sizelimit, int *msgidp)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_search_ext(ld, base, scope, filter,
		attrs, attrsonly, serverctrls,
		clientctrls, timeoutp, sizelimit, msgidp));
}

/* ARGSUSED */
int _ns_ldap_search_ext_s(char *service, int flags,
	char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeoutp, int sizelimit,
	LDAPMessage **res)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_search_ext_s(ld, base, scope, filter,
		attrs, attrsonly, serverctrls,
		clientctrls, timeoutp, sizelimit, res));
}

/* ARGSUSED */
int _ns_ldap_search(char *service, int flags,
	char *base, int scope, char *filter,
	char **attrs, int attrsonly)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_search(ld, base, scope, filter, attrs, attrsonly));
}

/* ARGSUSED */
int _ns_ldap_search_s(char *service, int flags,
	char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPMessage **res)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_search_s(ld, base, scope, filter,
		attrs, attrsonly, res));
}

/* ARGSUSED */
int _ns_ldap_search_st(char *service, int flags,
	char *base, int scope, char *filter,
	char **attrs, int attrsonly,
	struct timeval *timeout, LDAPMessage **res)
{
	LDAP *ld = __s_api_getLDAPconn(flags);

	return (ldap_search_st(ld, base, scope, filter,
		attrs, attrsonly, timeout, res));
}
