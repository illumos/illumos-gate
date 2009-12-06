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
 * ns_fnutils.c
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <synch.h>
#include <rpc/rpc.h>
#include <xfn/xfn.h>
#include "automount.h"
#include "ns_fnutils.h"


/*
 * FNS file system reference and address types.  Each array is indexed
 * using the corresponding enumeration (reftype_t or addrtype_t).
 */
const char *reftypes[] = {
	"onc_fn_fs",
};

const char *addrtypes[] = {
	"onc_fn_fs_mount",
	"onc_fn_fs_host",
	"onc_fn_fs_user",
};


FN_string_t		*empty_string = NULL;
FN_composite_name_t	*empty_cname = NULL;
FN_composite_name_t	*slash_cname = NULL;


int
init_fn(void)
{
	static mutex_t	init_lock = DEFAULTMUTEX;

	if (slash_cname != NULL) {
		return (0);
	}

	mutex_lock(&init_lock);

	if (empty_string == NULL) {
		if ((empty_string = fn_string_create()) == NULL) {
			log_mem_failure();
			goto unlock;
		}
	}
	if (empty_cname == NULL) {
		if ((empty_cname = new_cname("")) == NULL) {
			goto unlock;
		}
	}
	if (slash_cname == NULL) {
		if ((slash_cname = new_cname("/")) == NULL) {
			goto unlock;
		}
	}
unlock:
	mutex_unlock(&init_lock);
	return ((slash_cname != NULL) ? 0 : -1);
}


FN_composite_name_t *
new_cname(const char *str)
{
	FN_string_t		*string;
	FN_composite_name_t	*cname;

	string = fn_string_from_str((unsigned char *)str);
	if (string == NULL) {
		if (verbose) {
			syslog(LOG_ERR, "Could not create FNS string object");
		}
		return (NULL);
	}
	cname = fn_composite_name_from_string(string);
	fn_string_destroy(string);
	if ((cname == NULL) && verbose) {
		syslog(LOG_ERR, "Could not create FNS composite name object");
	}
	return (cname);
}


reftype_t
reftype(const FN_ref_t *ref)
{
	reftype_t	rtype;

	for (rtype = 0; rtype < NUM_REFTYPES; rtype++) {
		if (ident_str_equal(fn_ref_type(ref), reftypes[rtype])) {
			break;
		}
	}
	return (rtype);
}


addrtype_t
addrtype(const FN_ref_addr_t *addr)
{
	addrtype_t		atype;
	const FN_identifier_t	*ident = fn_ref_addr_type(addr);

	for (atype = 0; atype < NUM_ADDRTYPES; atype++) {
		if (ident_str_equal(ident, addrtypes[atype])) {
			break;
		}
	}
	return (atype);
}


bool_t
ident_equal(const FN_identifier_t *id1, const FN_identifier_t *id2)
{
	return ((id1->format == id2->format) &&
	    (id1->length == id2->length) &&
	    (memcmp(id1->contents, id2->contents, id1->length) == 0));
}


bool_t
ident_str_equal(const FN_identifier_t *id, const char *str)
{
	return ((id->format == FN_ID_STRING) &&
	    (id->length == strlen(str)) &&
	    (strncmp(str, id->contents, id->length) == 0));
}


void
logstat(const FN_status_t *status, const char *msg1, const char *msg2)
{
	FN_string_t	*desc_string;
	const char	*desc = NULL;

	if (verbose) {
		desc_string = fn_status_description(status, DETAIL, NULL);
		if (desc_string != NULL) {
			desc = (const char *)fn_string_str(desc_string, NULL);
		}
		if (desc == NULL) {
			desc = "(no status description)";
		}
		syslog(LOG_ERR, "FNS %s %s: %s (%u)",
		    msg1, msg2, desc, fn_status_code(status));
		fn_string_destroy(desc_string);
	}
}


bool_t
transient(const FN_status_t *status)
{
	unsigned int statcode;

	statcode = fn_status_code(status);
	if (statcode == FN_E_LINK_ERROR) {
		statcode = fn_status_link_code(status);
	}
	switch (statcode) {
	case FN_E_COMMUNICATION_FAILURE:
	case FN_E_CTX_UNAVAILABLE:
	case FN_E_INSUFFICIENT_RESOURCES:
	case FN_E_INVALID_ENUM_HANDLE:
	case FN_E_PARTIAL_RESULT:
	case FN_E_UNSPECIFIED_ERROR:
		return (TRUE);
	default:
		return (FALSE);
	}
}


void
log_mem_failure(void)
{
	if (verbose) {
		syslog(LOG_ERR, "Memory allocation failed");
	}
}
