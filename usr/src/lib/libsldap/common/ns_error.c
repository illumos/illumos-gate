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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <libintl.h>
#include "ns_sldap.h"
#include "ns_internal.h"

struct ns_ldaperror {
	int	e_code;
	char	*e_reason;
};

static mutex_t		ns_error_lock = DEFAULTMUTEX;
static boolean_t	error_inited = B_FALSE;

static struct ns_ldaperror ns_ldap_errlist[] = {
	{NS_LDAP_SUCCESS,	NULL},
	{NS_LDAP_OP_FAILED,	NULL},
	{NS_LDAP_NOTFOUND,	NULL},
	{NS_LDAP_MEMORY,	NULL},
	{NS_LDAP_CONFIG,	NULL},
	{NS_LDAP_PARTIAL,	NULL},
	{NS_LDAP_INTERNAL,	NULL},
	{NS_LDAP_INVALID_PARAM,	NULL},
	{-1,			NULL}
};


static void
ns_ldaperror_init()
{
	int 	i = 0;

	(void) mutex_lock(&ns_error_lock);
	if (!error_inited) {
		ns_ldap_errlist[i++].e_reason = gettext("Success");
		ns_ldap_errlist[i++].e_reason = gettext("Operation failed");
		ns_ldap_errlist[i++].e_reason = gettext("Object not found");
		ns_ldap_errlist[i++].e_reason = gettext("Memory failure");
		ns_ldap_errlist[i++].e_reason =
			gettext("LDAP configuration problem");
		ns_ldap_errlist[i++].e_reason = gettext("Partial result");
		ns_ldap_errlist[i++].e_reason = gettext("LDAP error");
		ns_ldap_errlist[i++].e_reason = gettext("Invalid parameter");
		ns_ldap_errlist[i++].e_reason = gettext("Unknown error");
		error_inited = B_TRUE;
	}
	(void) mutex_unlock(&ns_error_lock);
}


int
__ns_ldap_err2str(int err, char **strmsg)
{
	int	i;

	if (!error_inited)
		ns_ldaperror_init();

	for (i = 0; (ns_ldap_errlist[i].e_code != err) &&
			(ns_ldap_errlist[i].e_code != -1); i++) {
		/* empty for loop */
	}
	*strmsg = ns_ldap_errlist[i].e_reason;
	return (NS_LDAP_SUCCESS);
}


int
__ns_ldap_freeError(ns_ldap_error_t **errorp)
{
	ns_ldap_error_t *err = *errorp;
	if (err) {
		if (err->message)
			free(err->message);
		free(err);
	}
	*errorp = NULL;
	return (NS_LDAP_SUCCESS);
}
