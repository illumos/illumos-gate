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
 * ldapaddtsol.c
 *
 * Routines to add tnrhdb and tnrhtp from /etc/security/tsol into LDAP.
 * Can also be used to dump entries from a ldap container in /etc format.
 */

#include <stdio.h>
#include <stdlib.h>
#include <libintl.h>
#include <string.h>
#include <nss.h>
#include <secdb.h>
#include <sys/tsol/tndb.h>
#include "ldapaddent.h"

extern  int	genent_attr(char *, int, entry_col **);

int
genent_tnrhdb(char *line, int (*cback)())
{
	entry_col	*ecol;
	tsol_rhstr_t	data;
	int		res, retval;

	/*
	 * parse entry into columns
	 */
	res = genent_attr(line, TNRHDB_NCOL, &ecol);
	if (res != GENENT_OK)
		return (res);

	data.address = _do_unescape(ecol[0].ec_value.ec_value_val);
	data.template = ecol[1].ec_value.ec_value_val;
	if (strchr(data.address, ':') == NULL)
		data.family = AF_INET;
	else
		data.family = AF_INET6;

	if (flags & F_VERBOSE)
		(void) printf(gettext("Adding entry : %s\n"), data.address);

	retval = (*cback)(&data, 1);
	if (retval)
		res = GENENT_CBERR;

	free(ecol);

	return (res);
}

void
dump_tnrhdb(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "ipTnetNumber");
	if (value && value[0])
		(void) printf("%s", value[0]);
	else
		return;

	(void) putchar(':');
	value = __ns_ldap_getAttr(res->entry, "ipTnetTemplateName");
	if (value && value[0])
		(void) printf("%s", value[0]);
	(void) putchar('\n');
}

int
genent_tnrhtp(char *line, int (*cback)())
{
	entry_col	*ecol;
	tsol_tpstr_t	data;
	int		res, retval;

	/*
	 * parse entry into columns
	 */
	res = genent_attr(line, TNRHTP_NCOL, &ecol);
	if (res != GENENT_OK)
		return (res);

	data.template = ecol[0].ec_value.ec_value_val;
	data.attrs = ecol[1].ec_value.ec_value_val;

	if (flags & F_VERBOSE)
		(void) printf(gettext("Adding entry : %s\n"), data.template);

	retval = (*cback)(&data, 1);
	if (retval)
		res = GENENT_CBERR;

	free(ecol);

	return (res);
}

void
dump_tnrhtp(ns_ldap_result_t *res)
{
	char	**value = NULL;

	value = __ns_ldap_getAttr(res->entry, "ipTnetTemplateName");
	if (value && value[0])
		(void) printf("%s", value[0]);
	else
		return;

	(void) putchar(':');
	value = __ns_ldap_getAttr(res->entry, "SolarisAttrKeyValue");
	if (value && value[0])
		(void) printf("%s", value[0]);
	(void) putchar('\n');
}
