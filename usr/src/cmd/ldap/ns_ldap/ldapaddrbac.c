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

/*
 * ldapaddrbac.c
 *
 * Routines to add RBAC /etc files into LDAP.
 * Can also be used to dump entries from a ldap container in /etc format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <strings.h>
#include <sys/param.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <locale.h>
#include <syslog.h>
#include "ldapaddent.h"

#undef opaque
#undef	GROUP
#include <bsm/libbsm.h>

extern	char	*_strtok_escape(char *, char *, char **); /* from libnsl */

#include <user_attr.h>
#include <prof_attr.h>
#include <exec_attr.h>
#include <auth_attr.h>

/*
 * The parsing routines for RBAC and audit_user databases
 */

/*
 * genent_attr:
 *   Generic function for generating entries for all of the *_attr databases.
 */
int
genent_attr(
	char	*line,		/* entry to parse */
	int	ncol,		/* number of columns in the database */
	entry_col	**ecolret)	/* return entry array */
{
	int		i;
	char		(*buf)[BUFSIZ + 1];
	char		*s;
	char		*sep = KV_TOKEN_DELIMIT;
	char		*lasts;
	entry_col	*ecol;

	/*
	 * check input length
	 */
	if (strlen(line) >= sizeof (*buf)) {
		(void) strcpy(parse_err_msg, "line too long");
		return (GENENT_PARSEERR);
	}

	/*
	 * setup and clear column data
	 */
	if ((ecol = (entry_col *)malloc(ncol * sizeof (entry_col) +
	    sizeof (*buf))) == NULL)
		return (GENENT_ERR);
	(void) memset((char *)ecol, 0, ncol * sizeof (ecol));

	/* don't scribble over input */
	buf = (char (*)[sizeof (*buf)]) (ecol + ncol);
	(void) strncpy((char *)buf, line, sizeof (*buf));

	/* Split up columns */
	for (i = 0; i < ncol; i++, buf = NULL) {
		s = _strtok_escape((char *)buf, sep, &lasts);
		if (s == NULL) {
			ecol[i].ec_value.ec_value_val = "";
			ecol[i].ec_value.ec_value_len = 0;
		} else {
			ecol[i].ec_value.ec_value_val = s;
			ecol[i].ec_value.ec_value_len = strlen(s)+1;
		}
	}

	*ecolret = ecol;
	return (GENENT_OK);
}

int
genent_user_attr(char *line, int (*cback)())
{
	entry_col	*ecol;
	userstr_t	data;
	int		res, retval;

	/*
	 * parse entry into columns
	 */
	res = genent_attr(line, USERATTR_DB_NCOL, &ecol);
	if (res != GENENT_OK)
		return (res);

	data.name = ecol[0].ec_value.ec_value_val;
	data.qualifier = ecol[1].ec_value.ec_value_val;
	data.res1 = NULL;
	data.res2 = NULL;
	data.attr = ecol[4].ec_value.ec_value_val;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.name);

	retval = (*cback)(&data, 1);
	if (retval != NS_LDAP_SUCCESS) {
		if (retval == LDAP_NO_SUCH_OBJECT)
			(void) fprintf(stdout,
			gettext("Cannot add user_attr entry (%s), "
			"add passwd entry first\n"), data.name);
		if (continue_onerror == 0) res = GENENT_CBERR;
	}

	free(ecol);

	return (res);
}

void
dump_user_attr(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "uid");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	else
		return;

	(void) fprintf(stdout, "::::");
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrKeyValue");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, "\n");
}

int
genent_prof_attr(char *line, int (*cback)())
{
	entry_col	*ecol;
	profstr_t	data;
	int		res, retval;

	/*
	 * parse entry into columns
	 */
	res = genent_attr(line, PROFATTR_DB_NCOL, &ecol);
	if (res != GENENT_OK)
		return (res);

	data.name = ecol[0].ec_value.ec_value_val;
	data.res1 = NULL;
	data.res2 = NULL;
	data.desc = ecol[3].ec_value.ec_value_val;
	data.attr = ecol[4].ec_value.ec_value_val;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.name);

	retval = (*cback)(&data, 0);
	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"),
			    data.name);
		else {
			res = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.name);
		}
	} else if (retval)
		res = GENENT_CBERR;

	free(ecol);

	return (res);
}

void
dump_prof_attr(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "cn");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	else
		return;

	(void) fprintf(stdout, ":::");
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrLongDesc");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, ":");
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrKeyValue");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, "\n");
}

int
genent_exec_attr(char *line, int (*cback)())
{
	entry_col	*ecol;
	execstr_t	data;
	int		res, retval;

	/*
	 * parse entry into columns
	 */
	res = genent_attr(line, EXECATTR_DB_NCOL, &ecol);
	if (res != GENENT_OK)
		return (res);

	data.name = ecol[0].ec_value.ec_value_val;
	data.policy = ecol[1].ec_value.ec_value_val;
	data.type = ecol[2].ec_value.ec_value_val;
	data.res1 = NULL;
	data.res2 = NULL;
	data.id = ecol[5].ec_value.ec_value_val;
	data.attr = ecol[6].ec_value.ec_value_val;
	data.next = NULL;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s+%s+%s+%s\n"),
		    data.name, data.policy, data.type, data.id);

	retval = (*cback)(&data, 0);
	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s+%s+%s+%s - already Exists,"
			    " skipping it.\n"),
			    data.name, data.policy, data.type, data.id);
		else {
			res = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s+%s+%s+%s - already Exists\n"),
			    data.name, data.policy, data.type, data.id);
		}
	} else if (retval)
		res = GENENT_CBERR;

	free(ecol);

	return (res);
}

void
dump_exec_attr(ns_ldap_result_t *res)
{
	char	**profile;
	char	**policy;
	char	**type;
	char	**id;
	char	**value;

	profile = __ns_ldap_getAttr(res->entry, "cn");
	policy = __ns_ldap_getAttr(res->entry, "SolarisKernelSecurityPolicy");
	type = __ns_ldap_getAttr(res->entry, "SolarisProfileType");
	id = __ns_ldap_getAttr(res->entry, "SolarisProfileId");

	if (profile == NULL || profile[0] == NULL ||
	    policy == NULL || policy[0] == NULL ||
	    type == NULL || type[0] == NULL ||
	    id == NULL || id[0] == NULL)
		return;

	(void) fprintf(stdout, "%s", profile[0]);
	(void) fprintf(stdout, ":");
	(void) fprintf(stdout, "%s", policy[0]);
	(void) fprintf(stdout, ":");
	(void) fprintf(stdout, "%s", type[0]);
	(void) fprintf(stdout, ":::");
	(void) fprintf(stdout, "%s", id[0]);
	(void) fprintf(stdout, ":");
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrKeyValue");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, "\n");
}

int
genent_auth_attr(char *line, int (*cback)())
{
	entry_col	*ecol;
	authstr_t	data;
	int		res, retval;

	/*
	 * parse entry into columns
	 */
	res = genent_attr(line, AUTHATTR_DB_NCOL, &ecol);
	if (res != GENENT_OK)
		return (res);

	data.name = ecol[0].ec_value.ec_value_val;
	data.res1 = NULL;
	data.res2 = NULL;
	data.short_desc = ecol[3].ec_value.ec_value_val;
	data.long_desc = ecol[4].ec_value.ec_value_val;
	data.attr = ecol[5].ec_value.ec_value_val;

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.name);

	retval = (*cback)(&data, 0);
	if (retval == LDAP_ALREADY_EXISTS) {
		if (continue_onerror)
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists,"
			    " skipping it.\n"), data.name);
		else {
			res = GENENT_CBERR;
			(void) fprintf(stderr,
			    gettext("Entry: %s - already Exists\n"),
			    data.name);
		}
	} else if (retval)
		res = GENENT_CBERR;

	free(ecol);

	return (res);
}

void
dump_auth_attr(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "cn");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	else
		return;

	(void) fprintf(stdout, ":::");
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrShortDesc");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, ":");
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrLongDesc");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, ":");
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrKeyValue");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, "\n");
}

int
genent_audit_user(char *line, int (*cback)())
{
	entry_col	*ecol;
	au_user_str_t	data;
	int		res, retval;

	/*
	 * parse entry into columns
	 */
	res = genent_attr(line, AUDITUSER_DB_NCOL, &ecol);
	if (res != GENENT_OK)
		return (res);

	data.au_name = strdup(ecol[0].ec_value.ec_value_val);
	data.au_always = strdup(ecol[1].ec_value.ec_value_val);
	data.au_never = strdup(ecol[2].ec_value.ec_value_val);

	if (flags & F_VERBOSE)
		(void) fprintf(stdout,
		    gettext("Adding entry : %s\n"), data.au_name);

	retval = (*cback)(&data, 1);
	if (retval != NS_LDAP_SUCCESS) {
		if (retval == LDAP_NO_SUCH_OBJECT)
			(void) fprintf(stdout,
			gettext("Cannot add audit_user entry (%s), "
			"add passwd entry first\n"), data.au_name);
		if (continue_onerror == 0) res = GENENT_CBERR;
	}

	free(ecol);

	return (res);
}

void
dump_audit_user(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "uid");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	else
		return;

	(void) fprintf(stdout, ":");
	value = __ns_ldap_getAttr(res->entry, "SolarisAuditAlways");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, ":");
	value = __ns_ldap_getAttr(res->entry, "SolarisAuditNever");
	if (value && value[0])
		(void) fprintf(stdout, "%s", value[0]);
	(void) fprintf(stdout, "\n");
}
