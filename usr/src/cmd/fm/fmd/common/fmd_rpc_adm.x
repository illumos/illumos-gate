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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

%#include <fm/fmd_api.h>

enum fmd_adm_error {
	FMD_ADM_ERR_NOMEM = 1,
	FMD_ADM_ERR_PERM,
	FMD_ADM_ERR_MODSRCH,
	FMD_ADM_ERR_MODBUSY,
	FMD_ADM_ERR_MODFAIL,
	FMD_ADM_ERR_MODNOENT,
	FMD_ADM_ERR_MODEXIST,
	FMD_ADM_ERR_MODINIT,
	FMD_ADM_ERR_MODLOAD,
	FMD_ADM_ERR_RSRCSRCH,
	FMD_ADM_ERR_RSRCNOTF,
	FMD_ADM_ERR_SERDSRCH,
	FMD_ADM_ERR_SERDFIRED,
	FMD_ADM_ERR_ROTSRCH,
	FMD_ADM_ERR_ROTFAIL,
	FMD_ADM_ERR_ROTBUSY,
	FMD_ADM_ERR_CASESRCH,
	FMD_ADM_ERR_CASEOPEN,
	FMD_ADM_ERR_XPRTSRCH,
	FMD_ADM_ERR_CASEXPRT
};

struct fmd_rpc_modstat {
	struct fmd_stat rms_buf<>;
	enum fmd_adm_error rms_err;
};

struct fmd_rpc_modinfo {
	string rmi_name<>;
	string rmi_desc<>;
	string rmi_vers<>;
	bool rmi_faulty;
	struct fmd_rpc_modinfo *rmi_next;
};

struct fmd_rpc_modlist {
	enum fmd_adm_error rml_err;
	struct fmd_rpc_modinfo *rml_list;
	uint32_t rml_len;
};

struct fmd_rpc_rsrcinfo {
	string rri_fmri<>;
	string rri_uuid<>;
	string rri_case<>;
	bool rri_faulty;
	bool rri_unusable;
	bool rri_invisible;
	enum fmd_adm_error rri_err;
};

struct fmd_rpc_rsrclist {
	opaque rrl_buf<>;
	uint32_t rrl_len;
	uint32_t rrl_cnt;
	enum fmd_adm_error rrl_err;
	bool rrl_all;
};

struct fmd_rpc_serdinfo {
	string rsi_name<>;
	uint64_t rsi_delta;
	uint32_t rsi_count;
	bool rsi_fired;
	uint64_t rsi_n;
	uint64_t rsi_t;
	struct fmd_rpc_serdinfo *rsi_next;
};

struct fmd_rpc_serdlist {
	enum fmd_adm_error rsl_err;
	struct fmd_rpc_serdinfo *rsl_list;
	uint32_t rsl_len;
};

struct fmd_rpc_xprtlist {
	int32_t rxl_buf<>;
	uint32_t rxl_len;
	enum fmd_adm_error rxl_err;
};

struct fmd_rpc_caseinfo {
	opaque rci_evbuf<>;
	enum fmd_adm_error rci_err;
};

struct fmd_rpc_caselist {
	opaque rcl_buf<>;
	uint32_t rcl_len;
	uint32_t rcl_cnt;
	enum fmd_adm_error rcl_err;
};

program FMD_ADM {
	version FMD_ADM_VERSION_1 {
		struct fmd_rpc_modlist FMD_ADM_MODINFO(void) = 1;
		struct fmd_rpc_modstat FMD_ADM_MODCSTAT(string) = 2;
		struct fmd_rpc_modstat FMD_ADM_MODDSTAT(string) = 3;
		struct fmd_rpc_modstat FMD_ADM_MODGSTAT(void) = 4;
		int FMD_ADM_MODLOAD(string) = 5;
		int FMD_ADM_MODUNLOAD(string) = 6;
		int FMD_ADM_MODRESET(string) = 7;
		int FMD_ADM_MODGC(string) = 8;
		struct fmd_rpc_rsrclist FMD_ADM_RSRCLIST(bool) = 9;
		struct fmd_rpc_rsrcinfo FMD_ADM_RSRCINFO(string) = 10;
		int FMD_ADM_RSRCFLUSH(string) = 11;
		int FMD_ADM_RSRCREPAIRED(string) = 12;
		struct fmd_rpc_serdlist FMD_ADM_SERDINFO(string) = 13;
		int FMD_ADM_SERDRESET(string, string) = 14;
		int FMD_ADM_LOGROTATE(string) = 15;
		int FMD_ADM_CASEREPAIR(string) = 16;
		struct fmd_rpc_xprtlist FMD_ADM_XPRTLIST(void) = 17;
		struct fmd_rpc_modstat FMD_ADM_XPRTSTAT(int32_t) = 18;
		struct fmd_rpc_caselist FMD_ADM_CASELIST(void) = 19;
		struct fmd_rpc_caseinfo FMD_ADM_CASEINFO(string) = 20;
		int FMD_ADM_RSRCREPLACED(string) = 21;
		int FMD_ADM_RSRCACQUIT(string, string) = 22;
		int FMD_ADM_CASEACQUIT(string) = 23;
	} = 1;
} = 100169;

%extern void fmd_adm_1(struct svc_req *, SVCXPRT *);
%extern bool_t xdr_fmd_stat(XDR *, struct fmd_stat *);

%#undef	RW_READ_HELD
%#undef	RW_WRITE_HELD
%#undef	RW_LOCK_HELD
%#undef	MUTEX_HELD
