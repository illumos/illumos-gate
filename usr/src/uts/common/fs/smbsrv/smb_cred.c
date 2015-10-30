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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Authentication helpers for building credentials
 */

#include <sys/types.h>
#include <sys/sid.h>
#include <sys/priv_names.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <smbsrv/smb_idmap.h>
#include <smbsrv/smb_kproto.h>
#include <smbsrv/smb_token.h>

static void smb_cred_set_sid(smb_id_t *id, ksid_t *ksid);
static ksidlist_t *smb_cred_set_sidlist(smb_ids_t *token_grps);

/*
 * Allocate a Solaris cred and initialize it based on the access token.
 *
 * If the user can be mapped to a non-ephemeral ID, the cred gid is set
 * to the Solaris user's primary group.
 *
 * If the mapped UID is ephemeral, or the primary group could not be
 * obtained, the cred gid is set to whatever Solaris group is mapped
 * to the token's primary group.
 */
cred_t *
smb_cred_create(smb_token_t *token)
{
	ksid_t			ksid;
	ksidlist_t		*ksidlist = NULL;
	smb_posix_grps_t	*posix_grps;
	cred_t			*cr;
	gid_t			gid;

	ASSERT(token);
	ASSERT(token->tkn_posix_grps);
	posix_grps = token->tkn_posix_grps;

	cr = crget();
	ASSERT(cr != NULL);

	if (!IDMAP_ID_IS_EPHEMERAL(token->tkn_user.i_id) &&
	    (posix_grps->pg_ngrps != 0)) {
		gid = posix_grps->pg_grps[0];
	} else {
		gid = token->tkn_primary_grp.i_id;
	}

	if (crsetugid(cr, token->tkn_user.i_id, gid) != 0) {
		crfree(cr);
		return (NULL);
	}

	if (crsetgroups(cr, posix_grps->pg_ngrps, posix_grps->pg_grps) != 0) {
		crfree(cr);
		return (NULL);
	}

	smb_cred_set_sid(&token->tkn_user, &ksid);
	crsetsid(cr, &ksid, KSID_USER);
	smb_cred_set_sid(&token->tkn_primary_grp, &ksid);
	crsetsid(cr, &ksid, KSID_GROUP);
	smb_cred_set_sid(&token->tkn_owner, &ksid);
	crsetsid(cr, &ksid, KSID_OWNER);
	ksidlist = smb_cred_set_sidlist(&token->tkn_win_grps);
	crsetsidlist(cr, ksidlist);

	/*
	 * In the AD world, "take ownership privilege" is very much
	 * like having Unix "root" privileges.  It's normally given
	 * to members of the "Administrators" group, which normally
	 * includes the the local Administrator (like root) and when
	 * joined to a domain, "Domain Admins".
	 */
	if (smb_token_query_privilege(token, SE_TAKE_OWNERSHIP_LUID)) {
		(void) crsetpriv(cr,
		    PRIV_FILE_CHOWN,
		    PRIV_FILE_DAC_READ,
		    PRIV_FILE_DAC_SEARCH,
		    PRIV_FILE_DAC_WRITE,
		    PRIV_FILE_OWNER,
		    NULL);
	}

	return (cr);
}

/*
 * Initialize the ksid based on the given smb_id_t.
 */
static void
smb_cred_set_sid(smb_id_t *id, ksid_t *ksid)
{
	char sidstr[SMB_SID_STRSZ];
	int rc;

	ASSERT(id);
	ASSERT(id->i_sid);

	ksid->ks_id = id->i_id;
	smb_sid_tostr(id->i_sid, sidstr);
	rc = smb_sid_splitstr(sidstr, &ksid->ks_rid);
	ASSERT(rc == 0);

	ksid->ks_attr = id->i_attrs;
	ksid->ks_domain = ksid_lookupdomain(sidstr);
}

/*
 * Allocate and initialize the ksidlist based on the access token group list.
 */
static ksidlist_t *
smb_cred_set_sidlist(smb_ids_t *token_grps)
{
	int i;
	ksidlist_t *lp;

	lp = kmem_zalloc(KSIDLIST_MEM(token_grps->i_cnt), KM_SLEEP);
	lp->ksl_ref = 1;
	lp->ksl_nsid = token_grps->i_cnt;
	lp->ksl_neid = 0;

	for (i = 0; i < lp->ksl_nsid; i++) {
		smb_cred_set_sid(&token_grps->i_ids[i], &lp->ksl_sids[i]);
		if (lp->ksl_sids[i].ks_id > IDMAP_WK__MAX_GID)
			lp->ksl_neid++;
	}

	return (lp);
}
