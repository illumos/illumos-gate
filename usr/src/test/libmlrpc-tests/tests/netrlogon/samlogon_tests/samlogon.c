/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Test NetrSamLogon and NetrSamLogonEx, uses for NTLM pass-thru auth.
 */

#include <smbsrv/libmlsvc.h>
#include <smbsrv/netrauth.h>
#include <stdio.h>
#include <stdlib.h>

#include <util_common.h>

extern void netr_initialize(void);
extern uint32_t netlogon_logon(smb_logon_t *, smb_token_t *, smb_domainex_t *);

boolean_t
compare_tokens(const smb_token_t *src, const smb_token_t *dst)
{
	int i;
	const smb_ids_t *src_wgrps, *dst_wgrps;
	smb_id_t *src_grp, *dst_grp;
	char src_sid[SMB_SID_STRSZ] = "NULL", dst_sid[SMB_SID_STRSZ] = "NULL";

	if (strcmp(src->tkn_domain_name, dst->tkn_domain_name) != 0) {
		fprintf(stderr, "src domain %s does not match dst %s\n",
		    src->tkn_domain_name, dst->tkn_domain_name);
		return (B_FALSE);
	}

	if (strcmp(src->tkn_account_name, dst->tkn_account_name) != 0) {
		fprintf(stderr, "src account %s does not match dst %s\n",
		    src->tkn_account_name, dst->tkn_account_name);
		return (B_FALSE);
	}

	if (src->tkn_user.i_attrs != dst->tkn_user.i_attrs) {
		fprintf(stderr, "src attrs 0x%x does not match dst 0x%x\n",
		    src->tkn_user.i_attrs, dst->tkn_user.i_attrs);
		return (B_FALSE);
	}

	if (!smb_sid_cmp(src->tkn_user.i_sid, dst->tkn_user.i_sid)) {
		smb_sid_tostr(src->tkn_user.i_sid, src_sid);
		smb_sid_tostr(dst->tkn_user.i_sid, dst_sid);
		fprintf(stderr, "src usersid %s does not match dst %s\n",
		    src_sid, dst_sid);
		return (B_FALSE);
	}

	/* tkn_owner can be NULL if we haven't called smb_token_setup_common */
	if (src->tkn_owner.i_sid != dst->tkn_owner.i_sid &&
	    !smb_sid_cmp(src->tkn_owner.i_sid, dst->tkn_owner.i_sid)) {
		smb_sid_tostr(src->tkn_owner.i_sid, src_sid);
		smb_sid_tostr(dst->tkn_owner.i_sid, dst_sid);
		fprintf(stderr, "src ownersid %s does not match dst %s\n",
		    src_sid, dst_sid);
		return (B_FALSE);
	}

	if (!smb_sid_cmp(src->tkn_primary_grp.i_sid,
	    dst->tkn_primary_grp.i_sid)) {
		smb_sid_tostr(src->tkn_primary_grp.i_sid, src_sid);
		smb_sid_tostr(dst->tkn_primary_grp.i_sid, dst_sid);
		fprintf(stderr, "src primarysid %s does not match dst %s\n",
		    src_sid, dst_sid);
		return (B_FALSE);
	}

	src_wgrps = &src->tkn_win_grps;
	dst_wgrps = &dst->tkn_win_grps;

	if ((src_wgrps->i_ids == NULL && dst_wgrps->i_ids != NULL) ||
	    (src_wgrps->i_ids != NULL && dst_wgrps->i_ids == NULL)) {
		fprintf(stderr,
		    "src wingrp nullness 0x%p does not match dst 0x%p\n",
		    src_wgrps->i_ids, dst_wgrps->i_ids);
		return (B_FALSE);
	}

	if (src_wgrps->i_ids != NULL) {
		src_grp = &src_wgrps->i_ids[0];
		dst_grp = &dst_wgrps->i_ids[0];
		if (src_wgrps->i_cnt != dst_wgrps->i_cnt) {
			fprintf(stderr,
			    "src wingrp count %d does not match dst %d\n",
			    src_wgrps->i_cnt, dst_wgrps->i_cnt);
			return (B_FALSE);
		}

		for (i = 0; i < src_wgrps->i_cnt; i++, src_grp++, dst_grp++) {
			if ((src_grp->i_sid == NULL &&
			    dst_grp->i_sid != NULL) ||
			    (src_grp->i_sid != NULL &&
			    dst_grp->i_sid == NULL)) {
				fprintf(stderr,
				    "src wgrp %d nullness 0x%p does not "
				    "match dst 0x%p\n",
				    i, src_grp->i_sid, dst_grp->i_sid);
				return (B_FALSE);
			}


			if (src_grp->i_sid != NULL &&
			    !smb_sid_cmp(src_grp->i_sid, dst_grp->i_sid)) {
				smb_sid_tostr(src_grp->i_sid, src_sid);
				smb_sid_tostr(dst_grp->i_sid, dst_sid);
				fprintf(stderr, "src wingrp %d sid %s "
				    "does not match dst %s\n",
				    i, src_sid, dst_sid);
				return (B_FALSE);
			}
		}
	}

	if ((src->tkn_posix_grps == NULL && dst->tkn_posix_grps != NULL) ||
	    (src->tkn_posix_grps != NULL && dst->tkn_posix_grps == NULL)) {
		fprintf(stderr, "src pgrp nullness 0x%p does not match "
		    "dst 0x%p\n",
		    src->tkn_posix_grps, dst->tkn_posix_grps);
		return (B_FALSE);
	}

	if (src->tkn_posix_grps != NULL) {
		if (src->tkn_posix_grps->pg_ngrps !=
		    dst->tkn_posix_grps->pg_ngrps) {
			fprintf(stderr,
			    "src pgrp count %d does not match dst %d\n",
			    src->tkn_posix_grps->pg_ngrps,
			    dst->tkn_posix_grps->pg_ngrps);
			return (B_FALSE);
		}

		for (i = 0; i < src->tkn_posix_grps->pg_ngrps; i++) {
			if (src->tkn_posix_grps->pg_grps[i] !=
			    dst->tkn_posix_grps->pg_grps[i]) {
				fprintf(stderr,
				    "src pgrp num %d %d does not match "
				    "dst %d\n", i,
				    src->tkn_posix_grps->pg_grps[i],
				    dst->tkn_posix_grps->pg_grps[i]);
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

enum SAMLOGON_RC {
	SL_SUCCESS = 0,
	SL_ARGC,
	SL_DC_FQDN,
	SL_NB_DOMAIN,
	SL_CHALLENGE,
	SL_NT_PASS,
	SL_LM_PASS,
	SL_TOKEN_ALLOC,
	SL_NETLOGON,
	SL_TOKEN_COMP,
	SL_NETLOGON_LOOP,
	SL_NETLOGON_SAMLOGON,
	SL_NETLOGON_NOVERIFY
};

int
main(int argc, char *argv[])
{
	smb_logon_t user_info = {
		.lg_secmode = SMB_SECMODE_DOMAIN,
		.lg_domain_type = SMB_DOMAIN_PRIMARY,
		.lg_level = NETR_NETWORK_LOGON
	};
	smb_token_t *token = NULL;
	smb_token_t cmp_token;
	smb_domainex_t di = {0};
	char *nb_domain, *dc_name, *user_name, *workstation, *chall_file;
	char *nt_file, *lm_file;
	uint32_t status;
	int i;

	if (argc < 8) {
		fprintf(stderr, "usage: %s <NETBIOS domain> <DC FQDN> "
		    "<user name> "
		    "<client computer name> <Binary Challenge File> "
		    "<Binary NT response file> <Binary LM response file>\n",
		    argv[0]);
		return (-SL_ARGC);
	}

	nb_domain = argv[1];
	dc_name = argv[2];
	user_name = argv[3];
	workstation = argv[4];
	chall_file = argv[5];
	nt_file = argv[6];
	lm_file = argv[7];

	if (strlcpy(di.d_dci.dc_name, dc_name, sizeof (di.d_dci.dc_name)) >=
	    sizeof (di.d_dci.dc_name)) {
		fprintf(stderr, "DC FQDN %s is too long\n", dc_name);
		return (-SL_DC_FQDN);
	}
	if (strlcpy(di.d_primary.di_nbname, nb_domain,
	    sizeof (di.d_primary.di_nbname)) >=
	    sizeof (di.d_primary.di_nbname)) {
		fprintf(stderr, "Netbios Domain %s is too long\n", nb_domain);
		return (-SL_NB_DOMAIN);
	}

	user_info.lg_domain = nb_domain;
	user_info.lg_e_domain = user_info.lg_domain;
	user_info.lg_username = user_name;
	user_info.lg_workstation = workstation;

	user_info.lg_challenge_key.val =
	    read_buf_from_file(chall_file, &user_info.lg_challenge_key.len);
	if (user_info.lg_challenge_key.val == NULL) {
		fprintf(stderr, "failed to get challenge\n");
		return (-SL_CHALLENGE);
	}

	user_info.lg_nt_password.val =
	    read_buf_from_file(nt_file, &user_info.lg_nt_password.len);
	if (user_info.lg_nt_password.val == NULL) {
		fprintf(stderr, "failed to get NT pass\n");
		return (-SL_NT_PASS);
	}

	user_info.lg_lm_password.val =
	    read_buf_from_file(lm_file, &user_info.lg_lm_password.len);
	if (user_info.lg_lm_password.val == NULL) {
		fprintf(stderr, "failed to get LM pass\n");
		return (-SL_LM_PASS);
	}

	/* Initialize only those bits on which netlogon_logon depends */
	(void) smb_lgrp_start();
	smb_ipc_init();
	netr_initialize();

	token = calloc(1, sizeof (*token));
	if (token == NULL) {
		fprintf(stderr, "failed to allocate token\n");
		return (-SL_TOKEN_ALLOC);
	}
	status = netlogon_logon(&user_info, token, &di);

	if (status != NT_STATUS_SUCCESS) {
		fprintf(stderr, "netlogon_logon failed: 0x%x\n", status);
		return (-SL_NETLOGON);
	}
	smb_token_log(token);

	/* struct copy */
	cmp_token = *token;

	for (i = 0; i < 10; i++) {
		token = calloc(1, sizeof (*token));
		if (token == NULL) {
			fprintf(stderr, "iter %d: failed to allocate token\n",
			    i);
			return (-SL_TOKEN_ALLOC);
		}
		status = netlogon_logon(&user_info, token, &di);

		if (status != NT_STATUS_SUCCESS) {
			fprintf(stderr,
			    "iter %d: netlogon_logon failed: 0x%x\n",
			    i, status);
			return (-SL_NETLOGON_LOOP);
		}
		if (!compare_tokens(&cmp_token, token)) {
			fprintf(stderr, "iter %d: tokens didn't match\n", i);
			smb_token_log(token);
			return (-SL_TOKEN_COMP);
		}
		if (i != 9)
			smb_token_destroy(token);
	}
	smb_token_log(token);
	smb_token_destroy(token);

	token = calloc(1, sizeof (*token));
	if (token == NULL) {
		fprintf(stderr, "failed to allocate token\n");
		return (-SL_TOKEN_ALLOC);
	}

	/* Turn off SamLogonEx */
	netlogon_init_global(0x00000004);
	status = netlogon_logon(&user_info, token, &di);
	if (status != NT_STATUS_SUCCESS) {
		fprintf(stderr, "NoSamLogonEx: netlogon_logon failed: 0x%x\n",
		    status);
		return (-SL_NETLOGON_SAMLOGON);
	}
	smb_token_log(token);
	if (!compare_tokens(&cmp_token, token)) {
		fprintf(stderr, "tokens didn't match\n");
		return (-SL_TOKEN_COMP);
	}
	smb_token_destroy(token);

	token = calloc(1, sizeof (*token));
	if (token == NULL) {
		fprintf(stderr, "failed to allocate token\n");
		return (-SL_TOKEN_ALLOC);
	}

	/* Don't verify responses */
	netlogon_init_global(0x00000002);
	status = netlogon_logon(&user_info, token, &di);

	if (status != NT_STATUS_SUCCESS) {
		fprintf(stderr, "NoVerify: netlogon_logon failed: 0x%x\n",
		    status);
		return (-SL_NETLOGON_NOVERIFY);
	}
	smb_token_log(token);

	if (!compare_tokens(&cmp_token, token)) {
		fprintf(stderr, "tokens didn't match\n");
		return (-SL_TOKEN_COMP);
	}
	smb_token_destroy(token);
	return (SL_SUCCESS);
}
