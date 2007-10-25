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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains functions which destruct SMB session, tree, file,
 * user and xa structures.
 */

#include <smbsrv/smb_incl.h>
#include <smbsrv/smb_door_svc.h>
#include <smbsrv/smb_kproto.h>

/*
 * If this user is found in the user list,
 * return 1 on the first occurrence
 * else return 0 if end of list is reached
 */

/*
 * Return # of users
 */
uint32_t
smb_user_get_num(void)
{
	smb_session_t	*sn = NULL;
	smb_llist_t	*ulist;
	uint32_t cnt = 0;

	smb_svcstate_lock_read(&smb_info.si_svc_sm_ctx);
	while ((sn = smb_svcstate_session_getnext(&smb_info.si_svc_sm_ctx, sn))
	    != NULL) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		ulist = &sn->s_user_list;
		cnt += smb_llist_get_count(ulist);
	}
	smb_svcstate_unlock(&smb_info.si_svc_sm_ctx);
	return (cnt);
}

static int
smb_dr_user_create(smb_dr_user_ctx_t *uinfo, uint64_t sess_id, uint16_t uid,
    char *domain, char *acct, char *workstation, uint32_t ipaddr,
    int32_t native_os, time_t logon_time, uint32_t flags)
{
	if (!domain || !acct || !workstation)
		return (-1);

	uinfo->du_session_id = sess_id;
	uinfo->du_uid = uid;

	uinfo->du_domain_len = strlen(domain) + 1;
	uinfo->du_domain = smb_kstrdup(domain, uinfo->du_domain_len);

	uinfo->du_account_len = strlen(acct) + 1;
	uinfo->du_account = smb_kstrdup(acct, uinfo->du_account_len);

	uinfo->du_workstation_len = strlen(workstation) + 1;
	uinfo->du_workstation = smb_kstrdup(workstation,
	    uinfo->du_workstation_len);

	uinfo->du_native_os = native_os;
	uinfo->du_ipaddr = ipaddr;
	uinfo->du_logon_time = (int64_t)logon_time;
	uinfo->du_flags = flags;

	return (0);
}

void
smb_dr_user_free(smb_dr_user_ctx_t *uinfo)
{
	if (!uinfo)
		return;

	if (uinfo->du_domain)
		kmem_free(uinfo->du_domain, uinfo->du_domain_len);

	if (uinfo->du_account)
		kmem_free(uinfo->du_account, uinfo->du_account_len);

	if (uinfo->du_workstation)
		kmem_free(uinfo->du_workstation, uinfo->du_workstation_len);
}

void
smb_dr_ulist_free(smb_dr_ulist_t *ulist)
{
	int i;

	if (!ulist)
		return;

	for (i = 0; i < ulist->dul_cnt; i++) {
		smb_dr_user_free(&ulist->dul_users[i]);
	}
}

int
smb_dr_ulist_get(int offset, smb_dr_ulist_t *dr_ulist)
{
	smb_session_t	*sn = NULL;
	smb_user_t	*user;
	smb_llist_t	*ulist;
	smb_dr_user_ctx_t *uinfo;
	int cnt = 0, skip = 0;

	if (!dr_ulist)
		return (-1);

	smb_svcstate_lock_read(&smb_info.si_svc_sm_ctx);
	while ((sn = smb_svcstate_session_getnext(&smb_info.si_svc_sm_ctx, sn))
	    != NULL && cnt < SMB_DR_MAX_USERS) {
		ASSERT(sn->s_magic == SMB_SESSION_MAGIC);
		ulist = &sn->s_user_list;
		smb_llist_enter(ulist, RW_READER);
		user = smb_llist_head(ulist);
		while (user && cnt < SMB_DR_MAX_USERS) {
			ASSERT(user->u_magic == SMB_USER_MAGIC);
			mutex_enter(&user->u_mutex);
			if (user->u_state == SMB_USER_STATE_LOGGED_IN) {
				if (skip++ < offset) {
					mutex_exit(&user->u_mutex);
					user = smb_llist_next(ulist, user);
					continue;
				}

				uinfo = &dr_ulist->dul_users[cnt++];
				if (smb_dr_user_create(uinfo, sn->s_kid,
				    user->u_uid, user->u_domain, user->u_name,
				    sn->workstation, sn->ipaddr, sn->native_os,
				    user->u_logon_time, user->u_flags) != 0) {
					cnt--;
					mutex_exit(&user->u_mutex);
					user = smb_llist_next(ulist, user);
					continue;
				}
			}
			mutex_exit(&user->u_mutex);
			user = smb_llist_next(ulist, user);
		}
		smb_llist_exit(ulist);
	}
	smb_svcstate_unlock(&smb_info.si_svc_sm_ctx);
	dr_ulist->dul_cnt = cnt;
	return (cnt);
}
