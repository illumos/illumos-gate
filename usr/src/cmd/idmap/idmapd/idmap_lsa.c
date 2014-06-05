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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * LSA lookups
 */

#include <stdio.h>
#include <note.h>
#include <assert.h>

#include "idmapd.h"
#include "libsmb.h"

idmap_retcode
idmap_lsa_xlate_sid_type(const lsa_account_t *acct, idmap_id_type *ret_type)
{
	switch (acct->a_sidtype) {
	case SidTypeUser:
	case SidTypeComputer:
	case SidTypeDomain:
	case SidTypeDeletedAccount:
	case SidTypeUnknown:
	case SidTypeLabel:
		*ret_type = IDMAP_USID;
		return (IDMAP_SUCCESS);
	case SidTypeGroup:
	case SidTypeAlias:
	case SidTypeWellKnownGroup:
		*ret_type = IDMAP_GSID;
		return (IDMAP_SUCCESS);
	case SidTypeNull:
	case SidTypeInvalid:
	default:
		idmapdlog(LOG_WARNING,
		    "LSA lookup:  bad type %d for %s@%s",
		    acct->a_sidtype, acct->a_name, acct->a_domain);
		return (IDMAP_ERR_OTHER);
	}
	NOTE(NOTREACHED)
}

/* Given SID, look up name and type */
idmap_retcode
lookup_lsa_by_sid(
    const char *sidprefix,
    uint32_t rid,
    char **ret_name,
    char **ret_domain,
    idmap_id_type *ret_type)
{
	lsa_account_t acct;
	char sid[SMB_SID_STRSZ + 1];
	idmap_retcode ret;
	int rc;

	(void) memset(&acct, 0, sizeof (acct));
	*ret_name = NULL;
	*ret_domain = NULL;

	(void) snprintf(sid, sizeof (sid), "%s-%u", sidprefix, rid);

	rc = smb_lookup_sid(sid, &acct);
	if (rc != 0) {
		idmapdlog(LOG_ERR, "Error:  smb_lookup_sid failed.");
		idmapdlog(LOG_ERR,
		    "Check SMB service (svc:/network/smb/server).");
		idmapdlog(LOG_ERR,
		    "Check connectivity to Active Directory.");

		ret = IDMAP_ERR_OTHER;
		goto out;
	}
	if (acct.a_status == NT_STATUS_NONE_MAPPED) {
		ret = IDMAP_ERR_NOTFOUND;
		goto out;
	}
	if (acct.a_status != NT_STATUS_SUCCESS) {
		idmapdlog(LOG_WARNING,
		    "Warning:  smb_lookup_sid(%s) failed (0x%x)",
		    sid, acct.a_status);
		/* Fail soft */
		ret = IDMAP_ERR_NOTFOUND;
		goto out;
	}

	ret = idmap_lsa_xlate_sid_type(&acct, ret_type);
	if (ret != IDMAP_SUCCESS)
		goto out;

	*ret_name = strdup(acct.a_name);
	if (*ret_name == NULL) {
		ret = IDMAP_ERR_MEMORY;
		goto out;
	}

	*ret_domain = strdup(acct.a_domain);
	if (*ret_domain == NULL) {
		ret = IDMAP_ERR_MEMORY;
		goto out;
	}

	ret = IDMAP_SUCCESS;

out:
	if (ret != IDMAP_SUCCESS) {
		free(*ret_name);
		*ret_name = NULL;
		free(*ret_domain);
		*ret_domain = NULL;
	}
	return (ret);
}

/* Given name and optional domain, look up SID, type, and canonical name */
idmap_retcode
lookup_lsa_by_name(
    const char *name,
    const char *domain,
    char **ret_sidprefix,
    uint32_t *ret_rid,
    char **ret_name,
    char **ret_domain,
    idmap_id_type *ret_type)
{
	lsa_account_t acct;
	char *namedom = NULL;
	idmap_retcode ret;
	int rc;

	(void) memset(&acct, 0, sizeof (acct));
	*ret_sidprefix = NULL;
	if (ret_name != NULL)
		*ret_name = NULL;
	if (ret_domain != NULL)
		*ret_domain = NULL;

	if (domain != NULL)
		(void) asprintf(&namedom, "%s@%s", name, domain);
	else
		namedom = strdup(name);
	if (namedom == NULL) {
		ret = IDMAP_ERR_MEMORY;
		goto out;
	}

	rc = smb_lookup_name(namedom, SidTypeUnknown, &acct);
	if (rc != 0) {
		idmapdlog(LOG_ERR, "Error:  smb_lookup_name failed.");
		idmapdlog(LOG_ERR,
		    "Check SMB service (svc:/network/smb/server).");
		idmapdlog(LOG_ERR,
		    "Check connectivity to Active Directory.");
		ret = IDMAP_ERR_OTHER;
		goto out;
	}
	if (acct.a_status == NT_STATUS_NONE_MAPPED) {
		ret = IDMAP_ERR_NOTFOUND;
		goto out;
	}
	if (acct.a_status != NT_STATUS_SUCCESS) {
		idmapdlog(LOG_WARNING,
		    "Warning:  smb_lookup_name(%s) failed (0x%x)",
		    namedom, acct.a_status);
		/* Fail soft */
		ret = IDMAP_ERR_NOTFOUND;
		goto out;
	}

	rc = smb_sid_splitstr(acct.a_sid, ret_rid);
	assert(rc == 0);
	*ret_sidprefix = strdup(acct.a_sid);
	if (*ret_sidprefix == NULL) {
		ret = IDMAP_ERR_MEMORY;
		goto out;
	}

	ret = idmap_lsa_xlate_sid_type(&acct, ret_type);
	if (ret != IDMAP_SUCCESS)
		goto out;

	if (ret_name != NULL) {
		*ret_name = strdup(acct.a_name);
		if (*ret_name == NULL) {
			ret = IDMAP_ERR_MEMORY;
			goto out;
		}
	}

	if (ret_domain != NULL) {
		*ret_domain = strdup(acct.a_domain);
		if (*ret_domain == NULL) {
			ret = IDMAP_ERR_MEMORY;
			goto out;
		}
	}

	ret = IDMAP_SUCCESS;

out:
	free(namedom);
	if (ret != IDMAP_SUCCESS) {
		if (ret_name != NULL) {
			free(*ret_name);
			*ret_name = NULL;
		}
		if (ret_domain != NULL) {
			free(*ret_domain);
			*ret_domain = NULL;
		}
		free(*ret_sidprefix);
		*ret_sidprefix = NULL;
	}
	return (ret);
}

/*
 * This exists just so we can avoid exposing all of idmapd to libsmb.h.
 * Like the above functions, it's a door call over to smbd.
 */
void
notify_dc_changed(void)
{
	smb_notify_dc_changed();
}
