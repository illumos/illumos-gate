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
 * Server Service RPC (SRVSVC) server-side interface definition.
 * The server service provides a remote administration interface.
 *
 * This service uses NERR/Win32 error codes rather than NT status
 * values.
 */

#include <sys/errno.h>
#include <unistd.h>
#include <netdb.h>
#include <strings.h>
#include <time.h>
#include <tzfile.h>
#include <time.h>
#include <thread.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <smbsrv/smb_fsd.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/nterror.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/cifs.h>
#include <smbsrv/netrauth.h>
#include <smbsrv/mlsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/ndl/srvsvc.ndl>
#include <smbsrv/smb_common_door.h>

#define	SV_TYPE_SENT_BY_ME (SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_NT)

static DWORD mlsvc_NetSessionEnumLevel0(struct mslm_infonres *, DWORD,
    struct mlrpc_xaction *);
static DWORD mlsvc_NetSessionEnumLevel1(struct mslm_infonres *, DWORD,
    struct mlrpc_xaction *);
static DWORD mlsvc_NetShareEnumLevel0(struct mslm_infonres *, DWORD,
    struct mlrpc_xaction *, char);
static DWORD mlsvc_NetShareEnumLevel1(struct mslm_infonres *, DWORD,
    struct mlrpc_xaction *, char);
static DWORD mlsvc_NetShareEnumLevel2(struct mslm_infonres *, DWORD,
    struct mlrpc_xaction *, char);
static DWORD mlsvc_NetShareEnumLevel502(struct mslm_infonres *, DWORD,
    struct mlrpc_xaction *, char);
static DWORD mlsvc_NetShareEnumCommon(struct mlrpc_xaction *, DWORD,
    int, lmshare_info_t *, void *);
static int srvsvc_is_poweruser(struct mlrpc_xaction *);

static char empty_string[1];

static mlrpc_stub_table_t srvsvc_stub_table[];

static mlrpc_service_t srvsvc_service = {
	"SRVSVC",			/* name */
	"Server services",		/* desc */
	"\\srvsvc",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"4b324fc8-1670-01d3-12785a47bf6ee188", 3,	/* abstract */
	"8a885d04-1ceb-11c9-9fe808002b104860", 2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(srvsvc_interface),	/* interface ti */
	srvsvc_stub_table		/* stub_table */
};

/*
 * srvsvc_fix_comment
 *
 * The parser sometimes has problems with empty strings so we
 * need to ensure that the comment field has something in it.
 */
static inline char *
srvsvc_fix_comment(char *original, char *alternative)
{
	if (original == 0 || strlen(original) == 0)
		return (alternative);

	return (original);
}

/*
 * srvsvc_share_mkpath
 *
 * Create the share path required by the share enum calls. This function
 * creates the path in a MLRPC heap buffer ready for use by the caller.
 *
 * Some Windows over-the-wire backup applications do not work unless a
 * drive letter is present in the share path. We don't care about the
 * drive letter since the path is fully qualified with the volume name.
 * We can try using drive B since by default that letter isn't assigned
 * and even if it conflicts, we should still be okay with the fully
 * qualified path.
 *
 * Windows clients seem to be mostly okay with the forward slash in
 * share paths but they cannot handle one immediately after the drive
 * letter, i.e. D:/. For consistency we convert all the slashes in
 * the path.
 *
 * Returns a pointer to a heap buffer containing the share path, which
 * could be a null pointer if the heap allocation fails.
 */
static char *
srvsvc_share_mkpath(struct mlrpc_xaction *mxa, char *path)
{
	char tmpbuf[MAXPATHLEN];
	char *p;

	if (strlen(path) == 0)
		return (MLRPC_HEAP_STRSAVE(mxa, path));

	/* strip the volume from the path (/vol1/home -> /home) */
	p = strchr(path[0] == '/' ? &path[1] : path, '/');

	(void) snprintf(tmpbuf, MAXPATHLEN, "%c:%s", 'B'
	    /* vattr.drive_letter */, p == NULL ? "/": p);
	(void) strsubst(tmpbuf, '/', '\\');

	return (MLRPC_HEAP_STRSAVE(mxa, tmpbuf));
}

/*
 * srvsvc_add_autohome
 *
 * Add the autohome share for the user to the shares' list
 * if autohome is enabled the share is not a permanent share.
 */
static int
srvsvc_add_autohome(struct mlrpc_xaction *mxa, char *username, DWORD i,
    int level, char *infop)
{
	lmshare_info_t si;
	DWORD status;

	if ((lmshare_getinfo(username, &si) == NERR_Success) &&
	    (si.mode & LMSHRM_TRANS)) {
		status = mlsvc_NetShareEnumCommon(mxa, i, level, &si,
		    (void *)infop);
		if (status == ERROR_SUCCESS)
			i++;
	}

	return (i);
}

/*
 * srvsvc_initialize
 *
 * This function registers the SRVSVC RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
srvsvc_initialize(void)
{
	(void) mlrpc_register_service(&srvsvc_service);
}

/*
 * srvsvc_s_NetConnectEnum
 *
 * Under construction. This is just enough to get the interface working.
 * Current level 0 and level 1 connection info are supported.
 *
 * Level 1 request is made by 'srvmgr' (Server Manager)
 * utility of NT Server part of NT Domain to MLRPC server
 * while double click of share info icon. These values
 * are currectly virtual to MLRPC client and does't
 * reflect the real state of server.
 */
static int
srvsvc_s_NetConnectEnum(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetConnectEnum *param = arg;
	struct mslm_NetConnectInfoBuf0 *ci0;
	struct mslm_NetConnectInfoBuf1 *ci1;
	DWORD status;

	status = ERROR_SUCCESS;
	switch (param->info.level) {
	case 0:
		ci0 = MLRPC_HEAP_NEW(mxa, struct mslm_NetConnectInfoBuf0);
		if (ci0 == 0) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		ci0->coni0_id = 0x17;

		param->info.ru.info0
		    = MLRPC_HEAP_NEW(mxa, struct mslm_NetConnectInfo0);

		if (param->info.ru.info0 == 0) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		param->info.ru.info0->ci0 = ci0;
		param->info.ru.info0->entries_read = 1;

		param->total_entries = 1;
		param->resume_handle = 0;
		break;

	case 1:
		ci1 = MLRPC_HEAP_NEW(mxa, struct mslm_NetConnectInfoBuf1);
		if (ci1 == 0) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		ci1->coni1_id = 0x17;
		ci1->coni1_type = STYPE_IPC;
		ci1->coni1_num_opens = 1;
		ci1->coni1_num_users = 1;
		ci1->coni1_time = 16;
		ci1->coni1_username =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, "Administrator");

		ci1->coni1_netname =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, "IPC$");

		param->info.ru.info1 = MLRPC_HEAP_NEW(mxa,
		    struct mslm_NetConnectInfo1);

		if (param->info.ru.info1 == 0) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		param->info.ru.info1->ci1 = ci1;
		param->info.ru.info1->entries_read = 1;

		param->total_entries = 1;
		param->resume_handle = 0;
		break;

	default:
		status = ERROR_ACCESS_DENIED;
		break;
	}

	if (status != ERROR_SUCCESS)
		bzero(param, sizeof (struct mslm_NetConnectEnum));

	param->status = status;
	return (MLRPC_DRC_OK);
}


/*
 * srvsvc_s_NetFileEnum
 *
 * Under construction. The values used here are fictional values and
 * bear no relation to any real values, living or otherwise. I just
 * made them up to get the interface working.
 */
static int
srvsvc_s_NetFileEnum(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetFileEnum *param = arg;
	struct mslm_NetFileInfoBuf3 *fi3;

	if (param->info.switch_value != 3) {
		bzero(param, sizeof (struct mslm_NetFileEnum));
		param->status = ERROR_INVALID_LEVEL;
		return (MLRPC_DRC_OK);
	}

	fi3 = MLRPC_HEAP_NEW(mxa, struct mslm_NetFileInfoBuf3);
	if (fi3 == 0) {
		bzero(param, sizeof (struct mslm_NetFileEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (MLRPC_DRC_OK);
	}

	fi3->fi3_id = 0xF5;
	fi3->fi3_permissions = 0x23;
	fi3->fi3_num_locks = 0;
	fi3->fi3_pathname =
	    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, "\\PIPE\\srvsvc");

	fi3->fi3_username =
	    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, "Administrator");

	param->info.ru.info3 = MLRPC_HEAP_NEW(mxa, struct mslm_NetFileInfo3);
	if (param->info.ru.info3 == 0) {
		bzero(param, sizeof (struct mslm_NetFileEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (MLRPC_DRC_OK);
	}

	param->info.ru.info3->fi3 = fi3;
	param->info.ru.info3->entries_read = 1;
	param->total_entries = 1;

	if (param->resume_handle)
		*param->resume_handle = 0x5F;

	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}


/*
 * srvsvc_s_NetFileClose
 *
 * Under construction. This is just enough to get the interface working.
 */
/*ARGSUSED*/
static int
srvsvc_s_NetFileClose(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetFileClose *param = arg;

	bzero(param, sizeof (struct mslm_NetFileClose));
	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}


/*
 * srvsvc_s_NetShareGetInfo
 *
 * This call is made by Windows2000 to get share information. There are
 * probably other information levels but these are the only ones I've
 * seen so far.
 *
 * Returns Win32 error codes.
 */
static int
srvsvc_s_NetShareGetInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct mlsm_NetShareGetInfo *param = arg;
	struct mslm_NetShareGetInfo0 *info0;
	struct mslm_NetShareGetInfo1 *info1;
	struct mslm_NetShareGetInfo2 *info2;
	struct mslm_NetShareGetInfo502 *info502;
	struct mslm_NetShareGetInfo1005 *info1005;
	struct lmshare_info si;
	char shr_comment[LMSHR_COMMENT_MAX];
	DWORD status;

	status = lmshare_getinfo((char *)param->netname, &si);
	if (status != NERR_Success) {
		if (strcasecmp((const char *)param->netname, "IPC$") == 0) {
			/*
			 * Windows clients don't send the \\PIPE path for IPC$.
			 */
			(void) memset(&si, 0, sizeof (lmshare_info_t));
			(void) strcpy(si.share_name, "IPC$");
			(void) strcpy(si.comment, "Remote IPC");
			si.stype = (int)(STYPE_IPC | STYPE_SPECIAL);
		} else {
			bzero(param, sizeof (struct mlsm_NetShareGetInfo));
			param->status = status;
			return (MLRPC_DRC_OK);
		}
	}

	if (si.comment && strlen(si.comment))
		(void) snprintf(shr_comment, sizeof (shr_comment), "%s %s",
		    si.directory, si.comment);
	else
		(void) strcpy(shr_comment, si.directory);

	status = ERROR_SUCCESS;

	switch (param->level) {
	case 0:
		info0 = MLRPC_HEAP_NEW(mxa, struct mslm_NetShareGetInfo0);
		if (info0 == 0) {

			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		info0->shi0_netname
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si.share_name);

		param->result.ru.info0 = info0;
		break;

	case 1:
		info1 = MLRPC_HEAP_NEW(mxa, struct mslm_NetShareGetInfo1);
		if (info1 == 0) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		info1->shi1_netname =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si.share_name);
		info1->shi1_comment =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, shr_comment);
		info1->shi1_type = si.stype;
		param->result.ru.info1 = info1;
		break;

	case 2:
		info2 = MLRPC_HEAP_NEW(mxa, struct mslm_NetShareGetInfo2);
		if (info2 == 0) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		info2->shi2_netname =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si.share_name);
		info2->shi2_comment =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, shr_comment);
		info2->shi2_path =
		    (unsigned char *)srvsvc_share_mkpath(mxa, si.directory);
		info2->shi2_passwd = 0;
		info2->shi2_type = si.stype;
		info2->shi2_permissions = 0;
		info2->shi2_max_uses = SHI_USES_UNLIMITED;
		info2->shi2_current_uses = 0;
		param->result.ru.info2 = info2;
		break;

	case 1005:
		info1005 = MLRPC_HEAP_NEW(mxa, struct mslm_NetShareGetInfo1005);
		if (info1005 == 0) {

			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		info1005->shi1005_flags = 0;
		param->result.ru.info1005 = info1005;
		break;

	case 502:
		/*
		 * Level 502 provides level 2 information plus a
		 * security descriptor. We don't support security
		 * descriptors on shares yet.
		 */
		info502 = MLRPC_HEAP_NEW(mxa, struct mslm_NetShareGetInfo502);
		if (info502 == 0) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}
		info502->shi502_netname =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si.share_name);
		info502->shi502_comment =
		    (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, shr_comment);
		info502->shi502_path =
		    (unsigned char *)srvsvc_share_mkpath(mxa, si.directory);
		info502->shi502_passwd = 0;
		info502->shi502_type = si.stype;
		info502->shi502_permissions = 0;
		info502->shi502_max_uses = SHI_USES_UNLIMITED;
		info502->shi502_current_uses = 0;
		info502->shi502_reserved = 0;
		info502->shi502_security_descriptor = 0;
		param->result.ru.info502 = info502;
		break;

	default:
		status = ERROR_ACCESS_DENIED;
		break;
	}

	if (status != ERROR_SUCCESS)
		bzero(param, sizeof (struct mlsm_NetShareGetInfo));
	else
		param->result.switch_value = param->level;

	param->status = status;
	return (MLRPC_DRC_OK);
}


/*
 * srvsvc_s_NetShareSetInfo
 *
 * This call is made by SrvMgr to set share information.
 * Always returns ERROR_ACCESS_DENIED for now.
 *
 * Returns Win32 error codes.
 */
static int
srvsvc_s_NetShareSetInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct mlsm_NetShareSetInfo *param = arg;

	(void) memset(param, 0, sizeof (struct mlsm_NetShareSetInfo));
	param->parm_err_ptr = (DWORD)(uintptr_t)MLRPC_HEAP_MALLOC(mxa,
	    sizeof (DWORD));
	param->parm_err = 0;

	smb_config_rdlock();
	if (smb_config_getyorn(SMB_CI_SRVSVC_SHRSET_ENABLE) != 0)
		param->status = ERROR_SUCCESS;
	else
		param->status = ERROR_ACCESS_DENIED;
	smb_config_unlock();

	return (MLRPC_DRC_OK);
}

/*
 * srvsvc_s_NetSessionEnum
 *
 * Level 1 request is made by the 'srvmgr' (Server Manager) utility on
 * NT Server when the user info icon is selected.
 *
 * Return Values
 * If the function succeeds, the return value is NERR_Success.
 * If the function fails, the return value can be one of the following
 * error codes:
 *
 * ERROR_ACCESS_DENIED      The user does not have access to the requested
 *                          information.
 * ERROR_INVALID_LEVEL      The value specified for the level parameter is
 *                          invalid.
 * ERROR_INVALID_PARAMETER  The specified parameter is invalid.
 * ERROR_MORE_DATA	    More entries are available. Specify a large
 *                          enough buffer to receive all entries.
 * ERROR_NOT_ENOUGH_MEMORY  Insufficient memory is available.
 * NERR_ClientNameNotFound  A session does not exist with the computer
 *                          name.
 * NERR_InvalidComputer     The computer name is invalid.
 * NERR_UserNotFound        The user name could not be found.
 */
static int
srvsvc_s_NetSessionEnum(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetSessionEnum *param = arg;
	struct mslm_infonres *infonres;
	DWORD status;
	DWORD n_sessions;

	infonres = MLRPC_HEAP_NEW(mxa, struct mslm_infonres);
	if (infonres == 0) {
		bzero(param, sizeof (struct mslm_NetSessionEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (MLRPC_DRC_OK);
	}

	infonres->entriesread = 0;
	infonres->entries = 0;
	param->result.level = param->level;
	param->result.bufptr.p = infonres;
	param->total_entries = 1;
	param->status = ERROR_SUCCESS;

	n_sessions = (DWORD) smb_dwncall_user_num();

	switch (param->level) {
	case 0:
		status = mlsvc_NetSessionEnumLevel0(infonres, n_sessions, mxa);
		break;

	case 1:
		status = mlsvc_NetSessionEnumLevel1(infonres, n_sessions, mxa);
		break;

	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != 0) {
		bzero(param, sizeof (struct mslm_NetSessionEnum));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	param->resume_handle = 0;
	param->total_entries = infonres->entriesread;
	param->status = status;
	return (MLRPC_DRC_OK);
}

/*
 * mlsvc_NetSessionEnumLevel0
 *
 * Build the level 0 session information.
 */
/*ARGSUSED*/
static DWORD
mlsvc_NetSessionEnumLevel0(struct mslm_infonres *infonres, DWORD n_sessions,
    struct mlrpc_xaction *mxa)
{
	struct mslm_SESSION_INFO_0 *info0;
	smb_dr_ulist_t *ulist;
	smb_dr_user_ctx_t *user;
	char *workstation;
	char ipaddr_buf[INET_ADDRSTRLEN];
	int i, offset, cnt, total;

	info0 = MLRPC_HEAP_NEWN(mxa, struct mslm_SESSION_INFO_0, n_sessions);
	if (info0 == 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	ulist = malloc(sizeof (smb_dr_ulist_t));
	if (!ulist)
		return (ERROR_NOT_ENOUGH_MEMORY);

	for (total = 0, offset = 0;
	    (cnt = smb_dwncall_get_users(offset, ulist)) > 0;
	    offset += cnt) {
		for (i = 0; i < cnt && total < n_sessions; i++, total++) {
			user = &ulist->dul_users[i];
			/*
			 * Ignore local tokens (IP address is zero).
			 */
			if (user->du_ipaddr == 0) {
				total--;
				smb_dr_ulist_free(ulist);
				ulist = malloc(sizeof (smb_dr_ulist_t));
				if (!ulist)
					return (ERROR_NOT_ENOUGH_MEMORY);
				continue;
			}

			if ((workstation = user->du_workstation) == 0) {
				(void) inet_ntop(AF_INET,
				    (char *)&user->du_ipaddr, ipaddr_buf,
				    sizeof (ipaddr_buf));
				workstation = ipaddr_buf;
			}

			info0[total].sesi0_cname = MLRPC_HEAP_STRSAVE(mxa,
			    workstation);
			if (info0[total].sesi0_cname == 0) {
				smb_dr_ulist_free(ulist);
				return (ERROR_NOT_ENOUGH_MEMORY);
			}

		}
		smb_dr_ulist_free(ulist);
		ulist = malloc(sizeof (smb_dr_ulist_t));
		if (!ulist)
			return (ERROR_NOT_ENOUGH_MEMORY);

	}

	infonres->entriesread = total;
	infonres->entries = info0;
	return (ERROR_SUCCESS);
}


/*
 * mlsvc_NetSessionEnumLevel1
 *
 * Build the level 1 session information.
 */
/*ARGSUSED*/
static DWORD
mlsvc_NetSessionEnumLevel1(struct mslm_infonres *infonres, DWORD n_sessions,
    struct mlrpc_xaction *mxa)
{
	struct mslm_SESSION_INFO_1 *info1;
	smb_dr_ulist_t *ulist;
	smb_dr_user_ctx_t *user;
	char *workstation;
	char *account;
	char ipaddr_buf[INET_ADDRSTRLEN];
	int i, offset, cnt, total;

	info1 = MLRPC_HEAP_NEWN(mxa, struct mslm_SESSION_INFO_1, n_sessions);
	if (info1 == 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	ulist = malloc(sizeof (smb_dr_ulist_t));
	if (!ulist)
		return (ERROR_NOT_ENOUGH_MEMORY);

	for (total = 0, offset = 0;
	    (cnt = smb_dwncall_get_users(offset, ulist)) > 0;
	    offset += cnt) {
		for (i = 0; i < cnt && total < n_sessions; i++, total++) {
			user = &ulist->dul_users[i];
			/*
			 * Ignore local user_ctxs (IP address is zero).
			 */
			if (user->du_ipaddr == 0) {
				total--;
				smb_dr_ulist_free(ulist);
				ulist = malloc(sizeof (smb_dr_ulist_t));
				if (!ulist)
					return (ERROR_NOT_ENOUGH_MEMORY);
				continue;
			}

			if ((workstation = user->du_workstation) == 0) {
				(void) inet_ntop(AF_INET,
				    (char *)&user->du_ipaddr,
				    ipaddr_buf, sizeof (ipaddr_buf));
				workstation = ipaddr_buf;
			}

			if ((account = user->du_account) == 0)
				account = "Unknown";

			info1[total].sesi1_cname = MLRPC_HEAP_STRSAVE(mxa,
			    workstation);
			info1[total].sesi1_uname = MLRPC_HEAP_STRSAVE(mxa,
			    account);

			if (info1[total].sesi1_cname == 0 ||
			    info1[total].sesi1_uname == 0) {
				smb_dr_ulist_free(ulist);
				return (ERROR_NOT_ENOUGH_MEMORY);
			}

			info1[total].sesi1_nopens = 1;
			info1[total].sesi1_time = time(0) -
			    user->du_logon_time;
			info1[total].sesi1_itime = 0;
			info1[total].sesi1_uflags =
			    (user->du_flags & SMB_ATF_GUEST) ? SESS_GUEST : 0;
		}
		smb_dr_ulist_free(ulist);
		ulist = malloc(sizeof (smb_dr_ulist_t));
		if (!ulist)
			return (ERROR_NOT_ENOUGH_MEMORY);
	}

	infonres->entriesread = total;
	infonres->entries = info1;
	return (ERROR_SUCCESS);
}

/*
 * srvsvc_s_NetSessionDel
 *
 * Ends a network session between a server and a workstation.
 * On NT only members of the Administrators or Account Operators
 * local groups are permitted to use NetSessionDel.
 *
 * Return Values
 * If the function succeeds, the return value is NERR_Success/
 * ERROR_SUCCESS. If the function fails, the return value can be
 * one of the following error codes:
 *
 * ERROR_ACCESS_DENIED 		The user does not have access to the
 * 							requested information.
 * ERROR_INVALID_PARAMETER	The specified parameter is invalid.
 * ERROR_NOT_ENOUGH_MEMORY	Insufficient memory is available.
 * NERR_ClientNameNotFound	A session does not exist with that
 *                          computer name.
 */
static int
srvsvc_s_NetSessionDel(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetSessionDel *param = arg;

	if (srvsvc_is_poweruser(mxa) == 0) {
		param->status = ERROR_ACCESS_DENIED;
		return (MLRPC_DRC_OK);
	}

	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * SRVSVC NetServerGetInfo
 *
 *	IN	LPTSTR servername,
 *	IN	DWORD level,
 *	OUT	union switch(level) {
 *		case 100:	mslm_SERVER_INFO_100 *p100;
 *		case 101:	mslm_SERVER_INFO_101 *p101;
 *		case 102:	mslm_SERVER_INFO_102 *p102;
 *		default:	char *nullptr;
 *		} bufptr,
 *	OUT	DWORD status
 */
static int
srvsvc_s_NetServerGetInfo(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetServerGetInfo *param = arg;
	struct mslm_SERVER_INFO_100 *info100;
	struct mslm_SERVER_INFO_101 *info101;
	struct mslm_SERVER_INFO_102 *info102;
	char *sys_comment;
	char hostname[MAXHOSTNAMELEN];

	if (smb_gethostname(hostname, MAXHOSTNAMELEN, 1) != 0) {
netservergetinfo_no_memory:
		bzero(param, sizeof (struct mslm_NetServerGetInfo));
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	smb_config_rdlock();
	sys_comment = smb_config_getstr(SMB_CI_SYS_CMNT);
	sys_comment = srvsvc_fix_comment(sys_comment, " ");
	smb_config_unlock();

	switch (param->level) {
	case 100:
		info100 = MLRPC_HEAP_NEW(mxa, struct mslm_SERVER_INFO_100);
		if (info100 == 0)
			goto netservergetinfo_no_memory;

		bzero(info100, sizeof (struct mslm_SERVER_INFO_100));
		info100->sv100_platform_id = SV_PLATFORM_ID_NT;
		info100->sv100_name
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, hostname);

		if (info100->sv100_name == 0)
			goto netservergetinfo_no_memory;

		param->result.bufptr.bufptr100 = info100;
		break;

	case 101:
		info101 = MLRPC_HEAP_NEW(mxa, struct mslm_SERVER_INFO_101);
		if (info101 == 0)
			goto netservergetinfo_no_memory;

		bzero(info101, sizeof (struct mslm_SERVER_INFO_101));
		info101->sv101_platform_id = SV_PLATFORM_ID_NT;
		info101->sv101_version_major = 4;
		info101->sv101_version_minor = 0;
		info101->sv101_type = SV_TYPE_SENT_BY_ME;
		info101->sv101_name
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, hostname);

		info101->sv101_comment
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, sys_comment);

		if (info101->sv101_name == 0 || info101->sv101_comment == 0)
			goto netservergetinfo_no_memory;

		param->result.bufptr.bufptr101 = info101;
		break;

	case 102:
		info102 = MLRPC_HEAP_NEW(mxa, struct mslm_SERVER_INFO_102);
		if (info102 == 0)
			goto netservergetinfo_no_memory;

		bzero(info102, sizeof (struct mslm_SERVER_INFO_102));
		info102->sv102_platform_id = SV_PLATFORM_ID_NT;
		info102->sv102_version_major = 4;
		info102->sv102_version_minor = 0;
		info102->sv102_type = SV_TYPE_SENT_BY_ME;
		info102->sv102_name
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, hostname);

		info102->sv102_comment
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, sys_comment);

		/*
		 * The following level 102 fields are defaulted to zero
		 * by virtue of the call to bzero above.
		 *
		 * sv102_users
		 * sv102_disc
		 * sv102_hidden
		 * sv102_announce
		 * sv102_anndelta
		 * sv102_licenses
		 * sv102_userpath
		 */
		if (info102->sv102_name == 0 || info102->sv102_comment == 0)
			goto netservergetinfo_no_memory;

		param->result.bufptr.bufptr102 = info102;
		break;

	default:
		bzero(&param->result,
		    sizeof (struct mslm_NetServerGetInfo_result));
		param->status = ERROR_ACCESS_DENIED;
		return (MLRPC_DRC_OK);
	}

	param->result.level = param->level;
	param->status = (ERROR_SUCCESS);
	return (MLRPC_DRC_OK);
}

/*
 * NetRemoteTOD
 *
 * Returns information about the time of day on this server.
 *
 * typedef struct _TIME_OF_DAY_INFO {
 *	DWORD tod_elapsedt;  // seconds since 00:00:00 January 1 1970 GMT
 *	DWORD tod_msecs;     // arbitrary milliseconds (since reset)
 *	DWORD tod_hours;     // current hour [0-23]
 *	DWORD tod_mins;      // current minute [0-59]
 *	DWORD tod_secs;      // current second [0-59]
 *	DWORD tod_hunds;     // current hundredth (0.01) second [0-99]
 *	LONG tod_timezone;   // time zone of the server
 *	DWORD tod_tinterval; // clock tick time interval
 *	DWORD tod_day;       // day of the month [1-31]
 *	DWORD tod_month;     // month of the year [1-12]
 *	DWORD tod_year;      // current year
 *	DWORD tod_weekday;   // day of the week since sunday [0-6]
 * } TIME_OF_DAY_INFO;
 *
 * The time zone of the server is calculated in minutes from Greenwich
 * Mean Time (GMT). For time zones west of Greenwich, the value is
 * positive; for time zones east of Greenwich, the value is negative.
 * A value of -1 indicates that the time zone is undefined.
 *
 * The clock tick value represents a resolution of one ten-thousandth
 * (0.0001) second.
 */
static int
srvsvc_s_NetRemoteTOD(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetRemoteTOD *param = arg;
	struct mslm_TIME_OF_DAY_INFO *tod;
	struct timeval		time_val;
	struct tm		tm;

	(void) gettimeofday(&time_val, 0);
	(void) gmtime_r(&time_val.tv_sec, &tm);

	tod = MLRPC_HEAP_NEW(mxa, struct mslm_TIME_OF_DAY_INFO);
	if (tod == NULL) {
		bzero(param, sizeof (struct mslm_NetRemoteTOD));
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	tod->tod_elapsedt = time_val.tv_sec;
	tod->tod_msecs = time_val.tv_usec;
	tod->tod_hours = tm.tm_hour;
	tod->tod_mins = tm.tm_min;
	tod->tod_secs = tm.tm_sec;
	tod->tod_hunds = 0;
	tod->tod_tinterval = 1000;
	tod->tod_day = tm.tm_mday;
	tod->tod_month = tm.tm_mon+1;
	tod->tod_year = tm.tm_year+1900;
	tod->tod_weekday = tm.tm_wday;

	(void) localtime_r(&time_val.tv_sec, &tm);

	param->bufptr = tod;
	param->status = ERROR_SUCCESS;
	return (MLRPC_DRC_OK);
}

/*
 * srvsvc_s_NetNameValidate
 *
 * Perform name validation.
 * I've observed that the Computer Management Windows Application
 * always send this request with type=0x09 and the flags=0 when
 * attempting to validate a share name.
 *
 * The share name is consider invalid if it contains any of the
 * following character (as mentioned in MSDN article #236388).
 *
 * " / \ [ ] : | < > + ; , ? * =
 *
 *
 * For now, if the type is other than 0x09, return access denied.
 *
 * Returns Win32 error codes.
 */
/*ARGSUSED*/
static int
srvsvc_s_NetNameValidate(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetNameValidate *param = arg;

	switch (param->type) {
	case 0x09:
		param->status = lmshare_is_valid((char *)param->pathname) ?
		    ERROR_SUCCESS : ERROR_INVALID_NAME;
		break;

	default:
		param->status = ERROR_ACCESS_DENIED;
		break;
	}

	return (MLRPC_DRC_OK);
}

/*
 * srvsvc_s_NetShareAdd
 *
 * Add a new share. We support info levels 2 and 502 but ignore the
 * security descriptor in level 502 requests. Only the administrator,
 * or a member of the domain administrators group, is allowed to add
 * shares.
 *
 * This interface is used by the rmtshare command from the NT resource
 * kit. Rmtshare allows a client to add or remove shares on a server
 * from the client's command line.
 *
 * Note that we don't support security descriptors on a share. If the
 * /grant is used, the share will be created but the subsequent attempt
 * to manipulate the security descriptor (NetShareGetInfo) will fail.
 * Similarly for the /remove option.
 *
 * Returns Win32 error codes.
 */
static int
srvsvc_s_NetShareAdd(void *arg, struct mlrpc_xaction *mxa)
{
	static DWORD parm_err = 0;
	DWORD parm_stat;
	struct mslm_NetShareAdd *param = arg;
	smb_dr_user_ctx_t *user_ctx;
	struct mslm_SHARE_INFO_2 *info2;
	struct lmshare_info si;
	char realpath[MAXPATHLEN];

	user_ctx = mxa->context->user_ctx;

	if (srvsvc_is_poweruser(mxa) == 0) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = ERROR_ACCESS_DENIED;
		return (MLRPC_DRC_OK);
	}

	switch (param->level) {
	case 2:
		info2 = param->info.un.info2;
		break;

	case 502:
		info2 = (struct mslm_SHARE_INFO_2 *)param->info.un.info502;
		break;

	default:
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = ERROR_ACCESS_DENIED;
		return (MLRPC_DRC_OK);
	}

	if (info2->shi2_netname == 0 || info2->shi2_path == 0) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = NERR_NetNameNotFound;
		return (MLRPC_DRC_OK);
	}

	if (lmshare_is_restricted((char *)info2->shi2_netname)) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = ERROR_ACCESS_DENIED;
		return (MLRPC_DRC_OK);
	}

	if (info2->shi2_remark == 0)
		info2->shi2_remark = (unsigned char *)"";

	/*
	 * Derive the real path which will be stored in the
	 * directory field of the lmshare_info_t structure
	 * from the path field in this RPC request.
	 */
	parm_stat = lmshare_get_realpath((const char *)info2->shi2_path,
	    realpath, MAXPATHLEN);

	if (parm_stat != NERR_Success) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = parm_stat;
		param->parm_err
		    = (user_ctx->du_native_os == NATIVE_OS_WIN95) ?
		    0 : &parm_err;
		return (MLRPC_DRC_OK);
	}

	(void) memset(&si, 0, sizeof (lmshare_info_t));
	(void) strlcpy(si.share_name, (const char *)info2->shi2_netname,
	    MAXNAMELEN);

	(void) strlcpy(si.directory, realpath, MAXPATHLEN);
	(void) strlcpy(si.comment, (const char *)info2->shi2_remark,
	    LMSHR_COMMENT_MAX);

	si.mode = LMSHRM_PERM;

	param->status = lmshare_add(&si, 1);
	param->parm_err = (user_ctx->du_native_os == NATIVE_OS_WIN95) ?
	    0 : &parm_err;
	return (MLRPC_DRC_OK);
}

/*
 * srvsvc_is_poweruser
 *
 * Check whether or not the specified user has power-user privileges,
 * i.e. is a member of the Domain Admins, Administrators or Power
 * Users groups. This is typically required for operations such as
 * adding/deleting shares.
 *
 * Returns 1 if the user is a power user, otherwise returns 0.
 */
static int
srvsvc_is_poweruser(struct mlrpc_xaction *mxa)
{
	smb_dr_user_ctx_t *user = mxa->context->user_ctx;

	return ((user->du_flags & SMB_ATF_ADMIN) ||
	    (user->du_flags & SMB_ATF_POWERUSER));
}

/*
 * srvsvc_s_NetShareEnum
 *
 * Request for various levels of information about our shares.
 * Level 0: just the share names.
 * Level 1: the share name, the share type and the comment field.
 * Level 2: everything that we know about the shares.
 */
static int
srvsvc_s_NetShareEnum(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetShareEnum *param = arg;
	struct mslm_infonres *infonres;
	DWORD status;
	DWORD n_shares;

	infonres = MLRPC_HEAP_NEW(mxa, struct mslm_infonres);
	if (infonres == 0) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (MLRPC_DRC_OK);
	}

	infonres->entriesread = 0;
	infonres->entries = 0;
	param->result.level = param->level;
	param->result.bufptr.p = infonres;
	param->totalentries = 1; /* NT stream hint value: prefmaxlen? */
	param->status = ERROR_SUCCESS;

	n_shares = lmshare_num_shares();

	switch (param->level) {
	case 0:
		status = mlsvc_NetShareEnumLevel0(infonres, n_shares, mxa, 0);
		break;

	case 1:
		status = mlsvc_NetShareEnumLevel1(infonres, n_shares, mxa, 0);
		break;

	case 2:
		status = mlsvc_NetShareEnumLevel2(infonres, n_shares, mxa, 0);
		break;

	case 502:
		status = mlsvc_NetShareEnumLevel502(infonres, n_shares, mxa, 0);
		break;

	default:
		status = ERROR_INVALID_PARAMETER;
		break;
	}

	if (status != 0) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	param->resume_handle = 0;
	param->totalentries = infonres->entriesread;
	param->status = status;
	return (MLRPC_DRC_OK);
}


/*
 * srvsvc_s_NetShareEnumSticky
 *
 * Request for various levels of information about our shares.
 * Level 0: just the share names.
 * Level 1: the share name, the share type and the comment field.
 * Level 2: everything that we know about the shares.
 *
 * NetShareEnumSticky is the same as NetShareEnum except that hidden
 * shares are not returned. This call was apparently added due to a
 * bug in the NT implementation of NetShareEnum - it didn't process
 * the resume handle correctly so that attempts to enumerate large
 * share lists resulted in an infinite loop.
 */
static int
srvsvc_s_NetShareEnumSticky(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetShareEnum *param = arg;
	struct mslm_infonres *infonres;
	DWORD resume_handle;
	DWORD status;
	DWORD n_shares;

	infonres = MLRPC_HEAP_NEW(mxa, struct mslm_infonres);
	if (infonres == 0) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (MLRPC_DRC_OK);
	}

	infonres->entriesread = 0;
	infonres->entries = 0;
	param->result.level = param->level;
	param->result.bufptr.p = infonres;
	param->totalentries = 1; /* NT stream hint value: prefmaxlen? */
	param->status = ERROR_SUCCESS;

	n_shares = lmshare_num_shares();

	if (param->resume_handle)
		resume_handle = *param->resume_handle;
	else
		resume_handle = 0;

	switch (param->level) {
	case 0:
		status = mlsvc_NetShareEnumLevel0(infonres, n_shares, mxa, 1);
		break;

	case 1:
		status = mlsvc_NetShareEnumLevel1(infonres, n_shares, mxa, 1);
		break;

	case 2:
		status = mlsvc_NetShareEnumLevel2(infonres, n_shares, mxa, 1);
		break;

	case 502:
		status = mlsvc_NetShareEnumLevel502(infonres, n_shares, mxa, 1);
		break;

	default:
		status = ERROR_INVALID_PARAMETER;
		break;
	}

	if (status != 0) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = status;
		return (MLRPC_DRC_OK);
	}

	if (param->resume_handle)
		*param->resume_handle = resume_handle;
	param->totalentries = infonres->entriesread;
	param->status = status;
	return (MLRPC_DRC_OK);
}



/*
 * mlsvc_NetShareEnumLevel0
 *
 * Build the level 0 share information. The list should have been built
 * before we got here so all we have to do is copy the share names to
 * the response heap and setup the infonres values.
 */
static DWORD
mlsvc_NetShareEnumLevel0(struct mslm_infonres *infonres, DWORD n_shares,
    struct mlrpc_xaction *mxa, char sticky)
{
	struct mslm_SHARE_INFO_0 *info0;
	lmshare_iterator_t *iterator;
	lmshare_info_t *si;
	DWORD i;
	DWORD status;
	smb_dr_user_ctx_t *user_ctx = mxa->context->user_ctx;

	info0 = MLRPC_HEAP_NEWN(mxa, struct mslm_SHARE_INFO_0, n_shares);
	if (info0 == 0) {
		status = ERROR_NOT_ENOUGH_MEMORY;
		return (status);
	}

	iterator = lmshare_open_iterator(LMSHRM_ALL);
	if (iterator == NULL) {
		status = ERROR_NOT_ENOUGH_MEMORY;
		return (status);
	}

	i = 0;
	while ((si = lmshare_iterate(iterator)) != 0) {
		if (sticky && (si->stype & STYPE_SPECIAL))
			continue;

		if (smb_is_autohome(si))
			continue;

		status = mlsvc_NetShareEnumCommon(mxa, i, 0, si,
		    (void *)info0);

		if (status != ERROR_SUCCESS)
			break;

		i++;
	}

	i = srvsvc_add_autohome(mxa, user_ctx->du_account, i, 0, (char *)info0);

	lmshare_close_iterator(iterator);

	infonres->entriesread = i;
	infonres->entries = info0;
	return (ERROR_SUCCESS);
}


/*
 * mlsvc_NetShareEnumLevel1
 *
 * Build the level 1 share information. The list should have been built
 * before we arrived here so all we have to do is copy the share info
 * to the response heap and setup the infonres values. The only thing
 * to be aware of here is that there are minor difference between the
 * various share types.
 */
static DWORD
mlsvc_NetShareEnumLevel1(struct mslm_infonres *infonres, DWORD n_shares,
    struct mlrpc_xaction *mxa, char sticky)
{
	struct mslm_SHARE_INFO_1 *info1;
	lmshare_iterator_t *iterator;
	lmshare_info_t *si;
	DWORD i;
	smb_dr_user_ctx_t *user_ctx = mxa->context->user_ctx;

	info1 = MLRPC_HEAP_NEWN(mxa, struct mslm_SHARE_INFO_1, n_shares);
	if (info1 == 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	iterator = lmshare_open_iterator(LMSHRM_ALL);
	if (iterator == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	i = 0;
	while ((si = lmshare_iterate(iterator)) != 0) {
		if (sticky && (si->stype & STYPE_SPECIAL))
			continue;

		if (smb_is_autohome(si))
			continue;

		if (mlsvc_NetShareEnumCommon(mxa, i, 1, si,
		    (void *)info1) != ERROR_SUCCESS)
			break;
		i++;
	}

	i = srvsvc_add_autohome(mxa, user_ctx->du_account, i, 1, (char *)info1);

	lmshare_close_iterator(iterator);

	infonres->entriesread = i;
	infonres->entries = info1;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetShareEnumLevel2
 *
 * Build the level 2 share information. The list should have been built
 * before we arrived here so all we have to do is copy the share info
 * to the response heap and setup the infonres values. The only thing
 * to be aware of here is that there are minor difference between the
 * various share types.
 */
static DWORD
mlsvc_NetShareEnumLevel2(struct mslm_infonres *infonres, DWORD n_shares,
    struct mlrpc_xaction *mxa, char sticky)
{
	struct mslm_SHARE_INFO_2 *info2;
	lmshare_iterator_t *iterator;
	lmshare_info_t *si;
	DWORD i;
	smb_dr_user_ctx_t *user_ctx = mxa->context->user_ctx;

	info2 = MLRPC_HEAP_NEWN(mxa, struct mslm_SHARE_INFO_2, n_shares);
	if (info2 == 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	iterator = lmshare_open_iterator(LMSHRM_ALL);
	if (iterator == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	i = 0;
	while ((si = lmshare_iterate(iterator)) != 0) {
		if (sticky && (si->stype & STYPE_SPECIAL))
			continue;

		if (smb_is_autohome(si))
			continue;

		if (mlsvc_NetShareEnumCommon(mxa, i, 2, si,
		    (void *)info2) != ERROR_SUCCESS)
			break;
		i++;
	}

	i = srvsvc_add_autohome(mxa, user_ctx->du_account, i, 2, (char *)info2);

	lmshare_close_iterator(iterator);
	infonres->entriesread = i;
	infonres->entries = info2;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetShareEnumLevel502
 *
 * Build the level 502 share information. This is the same as level 2
 * but with a security descriptor in the share structure. We don't
 * support SD's on shares so we can just set that field to zero. See
 * mlsvc_NetShareEnumLevel2 for more information.
 */
static DWORD
mlsvc_NetShareEnumLevel502(struct mslm_infonres *infonres, DWORD n_shares,
    struct mlrpc_xaction *mxa, char sticky)
{
	struct mslm_SHARE_INFO_502 *info502;
	lmshare_iterator_t *iterator;
	lmshare_info_t *si;
	DWORD i;
	smb_dr_user_ctx_t *user_ctx = mxa->context->user_ctx;

	info502 = MLRPC_HEAP_NEWN(mxa, struct mslm_SHARE_INFO_502, n_shares);

	if (info502 == 0)
		return (ERROR_NOT_ENOUGH_MEMORY);

	iterator = lmshare_open_iterator(LMSHRM_ALL);
	if (iterator == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	i = 0;
	while ((si = lmshare_iterate(iterator)) != 0) {
		if (sticky && (si->stype & STYPE_SPECIAL))
			continue;

		if (smb_is_autohome(si))
			continue;

		if (mlsvc_NetShareEnumCommon(
		    mxa, i, 502, si, (void *)info502) != ERROR_SUCCESS)
			break;
		i++;
	}

	i = srvsvc_add_autohome(mxa, user_ctx->du_account, i, 502,
	    (char *)info502);

	lmshare_close_iterator(iterator);
	infonres->entriesread = i;
	infonres->entries = info502;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetShareEnumCommon
 *
 * Build the levels 0, 1, 2 and 502 share information. This function
 * is called by the various NetShareEnum levels for each share. If
 * we cannot build the share data for some reason, we return an error
 * but the actual value of the error is not important to the caller.
 * The caller just needs to know not to include this info in the RPC
 * response.
 *
 * Returns:
 *	ERROR_SUCCESS
 *	ERROR_NOT_ENOUGH_MEMORY
 *	ERROR_INVALID_LEVEL
 */
static DWORD
mlsvc_NetShareEnumCommon(struct mlrpc_xaction *mxa, DWORD i, int level,
    lmshare_info_t *si, void *infop)
{
	struct mslm_SHARE_INFO_0 *info0;
	struct mslm_SHARE_INFO_1 *info1;
	struct mslm_SHARE_INFO_2 *info2;
	struct mslm_SHARE_INFO_502 *info502;
	char shr_comment[LMSHR_COMMENT_MAX];

	if ((si->stype & STYPE_MASK) == STYPE_IPC) {
		/*
		 * Windows clients don't send the \\PIPE path for IPC$.
		 */
		si->directory[0] = '\0';
		(void) strcpy(si->comment, "Remote IPC");
	}

	if (si->comment && strlen(si->comment))
		(void) snprintf(shr_comment, sizeof (shr_comment), "%s (%s)",
		    si->directory, si->comment);
	else
		(void) strcpy(shr_comment, si->directory);

	switch (level) {
	case 0:
		info0 = (struct mslm_SHARE_INFO_0 *)infop;
		info0[i].shi0_netname
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si->share_name);

		if (info0[i].shi0_netname == 0)
			return (ERROR_NOT_ENOUGH_MEMORY);
		break;

	case 1:
		info1 = (struct mslm_SHARE_INFO_1 *)infop;
		info1[i].shi1_netname
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si->share_name);

		info1[i].shi1_remark
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, shr_comment);

		info1[i].shi1_type = si->stype;

		if (!info1[i].shi1_netname || !info1[i].shi1_remark)
			return (ERROR_NOT_ENOUGH_MEMORY);
		break;

	case 2:
		info2 = (struct mslm_SHARE_INFO_2 *)infop;
		info2[i].shi2_netname
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si->share_name);

		info2[i].shi2_remark
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, shr_comment);

		info2[i].shi2_path
		    = (unsigned char *)srvsvc_share_mkpath(mxa, si->directory);

		info2[i].shi2_type = si->stype;
		info2[i].shi2_permissions = 0;
		info2[i].shi2_max_uses = SHI_USES_UNLIMITED;
		info2[i].shi2_current_uses = 0;
		info2[i].shi2_passwd
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, empty_string);

		if (!info2[i].shi2_netname || !info2[i].shi2_remark ||
		    !info2[i].shi2_passwd || !info2[i].shi2_path)
			return (ERROR_NOT_ENOUGH_MEMORY);

		break;

	case 502:
		info502 = (struct mslm_SHARE_INFO_502 *)infop;
		info502[i].shi502_netname
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, si->share_name);

		info502[i].shi502_remark
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, shr_comment);

		info502[i].shi502_path
		    = (unsigned char *)srvsvc_share_mkpath(mxa, si->directory);

		info502[i].shi502_type = si->stype;
		info502[i].shi502_permissions = 0;
		info502[i].shi502_max_uses = SHI_USES_UNLIMITED;
		info502[i].shi502_current_uses = 0;
		info502[i].shi502_passwd
		    = (unsigned char *)MLRPC_HEAP_STRSAVE(mxa, empty_string);

		info502[i].shi502_reserved = 0;
		info502[i].shi502_security_descriptor = 0;

		if (!info502[i].shi502_netname || !info502[i].shi502_remark ||
		    !info502[i].shi502_passwd || !info502[i].shi502_path)
			return (ERROR_NOT_ENOUGH_MEMORY);
		break;

	default:
		return (ERROR_INVALID_LEVEL);
	}

	return (ERROR_SUCCESS);
}

/*
 * srvsvc_s_NetShareDel
 *
 * Delete a share. Only the administrator, or a member of the domain
 * administrators group, is allowed to delete shares.
 *
 * This interface is used by the rmtshare command from the NT resource
 * kit. Rmtshare allows a client to add or remove shares on a server
 * from the client's command line.
 *
 * Returns Win32 error codes.
 */
static int
srvsvc_s_NetShareDel(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetShareDel *param = arg;

	if (srvsvc_is_poweruser(mxa) == 0 ||
	    lmshare_is_restricted((char *)param->netname)) {
		param->status = ERROR_ACCESS_DENIED;
		return (MLRPC_DRC_OK);
	}

	param->status = lmshare_delete((char *)param->netname, 1);
	return (MLRPC_DRC_OK);
}

/*
 * srvsvc_s_NetGetFileSecurity
 *
 * Get security descriptor of the requested file/folder
 *
 * Right now, just returns ERROR_ACCESS_DENIED, because we cannot
 * get the requested SD here in MLRPC code.
 */
/*ARGSUSED*/
static int
srvsvc_s_NetGetFileSecurity(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetGetFileSecurity *param = arg;

	param->length = 0;
	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

/*
 * srvsvc_s_NetSetFileSecurity
 *
 * Set the given security descriptor for the requested file/folder
 *
 * Right now, just returns ERROR_ACCESS_DENIED, because we cannot
 * set the requested SD here in MLRPC code.
 */
/*ARGSUSED*/
static int
srvsvc_s_NetSetFileSecurity(void *arg, struct mlrpc_xaction *mxa)
{
	struct mslm_NetSetFileSecurity *param = arg;

	param->status = ERROR_ACCESS_DENIED;
	return (MLRPC_DRC_OK);
}

static mlrpc_stub_table_t srvsvc_stub_table[] = {
	{ srvsvc_s_NetConnectEnum,	SRVSVC_OPNUM_NetConnectEnum },
	{ srvsvc_s_NetFileEnum,		SRVSVC_OPNUM_NetFileEnum },
	{ srvsvc_s_NetFileClose,	SRVSVC_OPNUM_NetFileClose },
	{ srvsvc_s_NetShareGetInfo,	SRVSVC_OPNUM_NetShareGetInfo },
	{ srvsvc_s_NetShareSetInfo,	SRVSVC_OPNUM_NetShareSetInfo },
	{ srvsvc_s_NetSessionEnum,	SRVSVC_OPNUM_NetSessionEnum },
	{ srvsvc_s_NetSessionDel,	SRVSVC_OPNUM_NetSessionDel },
	{ srvsvc_s_NetServerGetInfo,	SRVSVC_OPNUM_NetServerGetInfo },
	{ srvsvc_s_NetRemoteTOD,	SRVSVC_OPNUM_NetRemoteTOD },
	{ srvsvc_s_NetNameValidate,	SRVSVC_OPNUM_NetNameValidate },
	{ srvsvc_s_NetShareAdd,		SRVSVC_OPNUM_NetShareAdd },
	{ srvsvc_s_NetShareDel,		SRVSVC_OPNUM_NetShareDel },
	{ srvsvc_s_NetShareEnum,	SRVSVC_OPNUM_NetShareEnum },
	{ srvsvc_s_NetShareEnumSticky,	SRVSVC_OPNUM_NetShareEnumSticky },
	{ srvsvc_s_NetGetFileSecurity,	SRVSVC_OPNUM_NetGetFileSecurity },
	{ srvsvc_s_NetSetFileSecurity,	SRVSVC_OPNUM_NetSetFileSecurity },
	{0}
};
