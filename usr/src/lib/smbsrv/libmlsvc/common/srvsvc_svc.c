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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <thread.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libshare.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/lmerr.h>
#include <smbsrv/nterror.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/cifs.h>
#include <smbsrv/netrauth.h>
#include <smbsrv/ndl/srvsvc.ndl>
#include <smbsrv/smb_common_door.h>
#include "mlsvc.h"

#define	SV_TYPE_SENT_BY_ME (SV_TYPE_WORKSTATION | SV_TYPE_SERVER | SV_TYPE_NT)

/*
 * Qualifier types for NetConnectEnum.
 */
#define	SRVSVC_CONNECT_ENUM_NULL	0
#define	SRVSVC_CONNECT_ENUM_SHARE	1
#define	SRVSVC_CONNECT_ENUM_WKSTN	2

#define	SMB_SRVSVC_MAXBUFLEN	(8 * 1024 * 1024)
#define	SMB_SRVSVC_MAXPREFLEN	((uint32_t)(-1))

/*
 * prefmaxlen:    Client specified response buffer limit.
 * resume_handle: Cookie used to track enumeration across multiple calls.
 * n_total:       Total number of entries.
 * n_enum:        Number of entries to enumerate (derived from prefmaxlen).
 * n_skip:        Number of entries to skip (from incoming resume handle).
 * n_read:        Number of objects returned for current enumeration request.
 */
typedef struct srvsvc_enum {
	uint32_t se_level;
	uint32_t se_prefmaxlen;
	uint32_t se_resume_handle;
	uint32_t se_n_total;
	uint32_t se_n_enum;
	uint32_t se_n_skip;
	uint32_t se_n_read;
} srvsvc_enum_t;

typedef struct srvsvc_sd {
	uint8_t *sd_buf;
	uint32_t sd_size;
} srvsvc_sd_t;

typedef struct srvsvc_netshare_setinfo {
	char *nss_netname;
	char *nss_comment;
	char *nss_path;
	uint32_t nss_type;
	srvsvc_sd_t nss_sd;
} srvsvc_netshare_setinfo_t;

typedef union srvsvc_netshare_getinfo {
	struct mslm_NetShareInfo_0 nsg_info0;
	struct mslm_NetShareInfo_1 nsg_info1;
	struct mslm_NetShareInfo_2 nsg_info2;
	struct mslm_NetShareInfo_501 nsg_info501;
	struct mslm_NetShareInfo_502 nsg_info502;
	struct mslm_NetShareInfo_503 nsg_info503;
	struct mslm_NetShareInfo_1004 nsg_info1004;
	struct mslm_NetShareInfo_1005 nsg_info1005;
	struct mslm_NetShareInfo_1006 nsg_info1006;
	struct mslm_NetShareInfo_1501 nsg_info1501;
} srvsvc_netshare_getinfo_t;

static DWORD srvsvc_s_NetConnectEnumLevel0(ndr_xa_t *,
    srvsvc_NetConnectInfo0_t *);
static DWORD srvsvc_s_NetConnectEnumLevel1(ndr_xa_t *,
    srvsvc_NetConnectInfo1_t *);

static DWORD srvsvc_NetFileEnum2(ndr_xa_t *,
    struct mslm_NetFileEnum *);
static DWORD srvsvc_NetFileEnum3(ndr_xa_t *,
    struct mslm_NetFileEnum *);

static DWORD mlsvc_NetSessionEnumLevel0(struct mslm_infonres *, DWORD,
    ndr_xa_t *);
static DWORD mlsvc_NetSessionEnumLevel1(struct mslm_infonres *, DWORD,
    ndr_xa_t *);
static DWORD mlsvc_NetSessionEnumLevel2(struct mslm_infonres *, DWORD,
    ndr_xa_t *);
static DWORD mlsvc_NetSessionEnumLevel10(struct mslm_infonres *, DWORD,
    ndr_xa_t *);
static DWORD mlsvc_NetSessionEnumLevel502(struct mslm_infonres *, DWORD,
    ndr_xa_t *);

static DWORD mlsvc_NetShareEnumLevel0(ndr_xa_t *,
    struct mslm_infonres *, srvsvc_enum_t *, int);
static DWORD mlsvc_NetShareEnumLevel1(ndr_xa_t *,
    struct mslm_infonres *, srvsvc_enum_t *, int);
static DWORD mlsvc_NetShareEnumLevel2(ndr_xa_t *,
    struct mslm_infonres *, srvsvc_enum_t *, int);
static DWORD mlsvc_NetShareEnumLevel501(ndr_xa_t *,
    struct mslm_infonres *, srvsvc_enum_t *, int);
static DWORD mlsvc_NetShareEnumLevel502(ndr_xa_t *,
    struct mslm_infonres *, srvsvc_enum_t *, int);
static DWORD mlsvc_NetShareEnumCommon(ndr_xa_t *,
    srvsvc_enum_t *, smb_share_t *, void *);
static boolean_t srvsvc_add_autohome(ndr_xa_t *, srvsvc_enum_t *,
    void *);
static char *srvsvc_share_mkpath(ndr_xa_t *, char *);
static uint32_t srvsvc_share_getsd(ndr_xa_t *, smb_share_t *, srvsvc_sd_t *);

static int srvsvc_netconnect_qualifier(const char *);
static uint32_t srvsvc_estimate_objcnt(uint32_t, uint32_t, uint32_t);

static uint32_t srvsvc_modify_share(smb_share_t *,
    srvsvc_netshare_setinfo_t *);
static uint32_t srvsvc_modify_transient_share(smb_share_t *,
    srvsvc_netshare_setinfo_t *);
static uint32_t srvsvc_update_share_flags(smb_share_t *, uint32_t);

static uint32_t srvsvc_sa_add(char *, char *, char *);
static uint32_t srvsvc_sa_delete(char *);
static uint32_t srvsvc_sa_modify(smb_share_t *, srvsvc_netshare_setinfo_t *);
static uint32_t srvsvc_sa_setattr(smb_share_t *);

static char empty_string[1];

static ndr_stub_table_t srvsvc_stub_table[];

static ndr_service_t srvsvc_service = {
	"SRVSVC",			/* name */
	"Server services",		/* desc */
	"\\srvsvc",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"4b324fc8-1670-01d3-1278-5a47bf6ee188", 3,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(srvsvc_interface),	/* interface ti */
	srvsvc_stub_table		/* stub_table */
};

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
	(void) ndr_svc_register(&srvsvc_service);
}

/*
 * srvsvc_s_NetConnectEnum
 *
 * List tree connections made to a share on this server or all tree
 * connections established from a specific client.  Administrator,
 * Server Operator, Print Operator or Power User group membership
 * is required to use this interface.
 *
 * There are three information levels:  0, 1, and 50.  We don't support
 * level 50, which is only used by Windows 9x clients.
 *
 * It seems Server Manger (srvmgr) only sends workstation as the qualifier
 * and the Computer Management Interface on Windows 2000 doesn't request
 * a list of connections.
 *
 * Return Values:
 * ERROR_SUCCESS            Success
 * ERROR_ACCESS_DENIED      Caller does not have access to this call.
 * ERROR_INVALID_PARAMETER  One of the parameters is invalid.
 * ERROR_INVALID_LEVEL      Unknown information level specified.
 * ERROR_MORE_DATA          Partial date returned, more entries available.
 * ERROR_NOT_ENOUGH_MEMORY  Insufficient memory is available.
 * NERR_NetNameNotFound     The share qualifier cannot be found.
 * NERR_BufTooSmall         The supplied buffer is too small.
 */
static int
srvsvc_s_NetConnectEnum(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetConnectEnum *param = arg;
	srvsvc_NetConnectInfo0_t *info0;
	srvsvc_NetConnectInfo1_t *info1;
	char *qualifier;
	int qualtype;
	DWORD status = ERROR_SUCCESS;

	if (!ndr_is_poweruser(mxa)) {
		bzero(param, sizeof (struct mslm_NetConnectEnum));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	qualifier = (char *)param->qualifier;
	qualtype = srvsvc_netconnect_qualifier(qualifier);

	if (qualtype == SRVSVC_CONNECT_ENUM_NULL) {
		bzero(param, sizeof (struct mslm_NetConnectEnum));
		param->status = NERR_NetNameNotFound;
		return (NDR_DRC_OK);
	}

	switch (param->info.level) {
	case 0:
		info0 = NDR_NEW(mxa, srvsvc_NetConnectInfo0_t);
		if (info0 == NULL) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		bzero(info0, sizeof (srvsvc_NetConnectInfo0_t));
		param->info.ru.info0 = info0;

		status = srvsvc_s_NetConnectEnumLevel0(mxa, info0);

		param->total_entries = info0->entries_read;
		param->resume_handle = NULL;
		break;

	case 1:
		info1 = NDR_NEW(mxa, srvsvc_NetConnectInfo1_t);
		if (info1 == NULL) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		bzero(info1, sizeof (srvsvc_NetConnectInfo1_t));
		param->info.ru.info1 = info1;

		status = srvsvc_s_NetConnectEnumLevel1(mxa, info1);

		param->total_entries = info1->entries_read;
		param->resume_handle = NULL;
		break;

	case 50:
		status = ERROR_NOT_SUPPORTED;
		break;

	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != ERROR_SUCCESS)
		bzero(param, sizeof (struct mslm_NetConnectEnum));

	param->status = status;
	return (NDR_DRC_OK);
}

static DWORD
srvsvc_s_NetConnectEnumLevel0(ndr_xa_t *mxa, srvsvc_NetConnectInfo0_t *info0)
{
	srvsvc_NetConnectInfoBuf0_t *ci0;

	ci0 = NDR_NEW(mxa, srvsvc_NetConnectInfoBuf0_t);
	if (ci0 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	ci0->coni0_id = 0x17;

	info0->ci0 = ci0;
	info0->entries_read = 1;
	return (ERROR_SUCCESS);
}

static DWORD
srvsvc_s_NetConnectEnumLevel1(ndr_xa_t *mxa, srvsvc_NetConnectInfo1_t *info1)
{
	srvsvc_NetConnectInfoBuf1_t *ci1;

	ci1 = NDR_NEW(mxa, srvsvc_NetConnectInfoBuf1_t);
	if (ci1 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	ci1->coni1_id = 0x17;
	ci1->coni1_type = STYPE_IPC;
	ci1->coni1_num_opens = 1;
	ci1->coni1_num_users = 1;
	ci1->coni1_time = 16;
	ci1->coni1_username = (uint8_t *)NDR_STRDUP(mxa, "Administrator");
	ci1->coni1_netname = (uint8_t *)NDR_STRDUP(mxa, "IPC$");

	info1->ci1 = ci1;
	info1->entries_read = 1;
	return (ERROR_SUCCESS);
}

/*
 * srvsvc_netconnect_qualifier
 *
 * The qualifier is a string that specifies a share name or computer name
 * for the connections of interest.  If it is a share name then all the
 * connections made to that share name are listed.  If it is a computer
 * name (it starts with two backslash characters), then NetConnectEnum
 * lists all connections made from that computer to the specified server.
 */
static int
srvsvc_netconnect_qualifier(const char *qualifier)
{
	if (qualifier == NULL || *qualifier == '\0')
		return (SRVSVC_CONNECT_ENUM_NULL);

	if (strlen(qualifier) > MAXHOSTNAMELEN)
		return (SRVSVC_CONNECT_ENUM_NULL);

	if (qualifier[0] == '\\' && qualifier[1] == '\\') {
		return (SRVSVC_CONNECT_ENUM_WKSTN);
	} else {
		if (!smb_shr_exists((char *)qualifier))
			return (SRVSVC_CONNECT_ENUM_NULL);

		return (SRVSVC_CONNECT_ENUM_SHARE);
	}
}

/*
 * srvsvc_s_NetFileEnum
 *
 * Return information on open files or named pipes. Only members of the
 * Administrators or Server Operators local groups are allowed to make
 * this call. Currently, we only support Administrators.
 *
 * If basepath is null, all open resources are enumerated. If basepath
 * is non-null, only resources that have basepath as a prefix should
 * be returned.
 *
 * If username is specified (non-null), only files opened by username
 * should be returned.
 *
 * Notes:
 * 1. We don't validate the servername because we would have to check
 * all primary IPs and the ROI seems unlikely to be worth it.
 * 2. Both basepath and username are currently ignored because both
 * Server Manger (NT 4.0) and CMI (Windows 2000) always set them to null.
 *
 * The level of information requested may be one of:
 *
 *  2   Return the file identification number.
 *      This level is not supported on Windows Me/98/95.
 *
 *  3   Return information about the file.
 *      This level is not supported on Windows Me/98/95.
 *
 *  50  Windows Me/98/95:  Return information about the file.
 *
 * Note:
 * If pref_max_len is unlimited and resume_handle is null, the client
 * expects to receive all data in a single call.
 * If we are unable to do fit all data in a single response, we would
 * normally return ERROR_MORE_DATA with a partial list.
 *
 * Unfortunately, when both of these conditions occur, Server Manager
 * pops up an error box with the message "more data available" and
 * doesn't display any of the returned data. In this case, it is
 * probably better to return ERROR_SUCCESS with the partial list.
 * Windows 2000 doesn't have this problem because it always sends a
 * non-null resume_handle.
 *
 * Return Values:
 * ERROR_SUCCESS            Success
 * ERROR_ACCESS_DENIED      Caller does not have access to this call.
 * ERROR_INVALID_PARAMETER  One of the parameters is invalid.
 * ERROR_INVALID_LEVEL      Unknown information level specified.
 * ERROR_MORE_DATA          Partial date returned, more entries available.
 * ERROR_NOT_ENOUGH_MEMORY  Insufficient memory is available.
 * NERR_BufTooSmall         The supplied buffer is too small.
 */
static int
srvsvc_s_NetFileEnum(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetFileEnum *param = arg;
	DWORD status;

	if (!ndr_is_admin(mxa)) {
		bzero(param, sizeof (struct mslm_NetFileEnum));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	switch (param->info.switch_value) {
	case 2:
		status = srvsvc_NetFileEnum2(mxa, param);
		break;

	case 3:
		status = srvsvc_NetFileEnum3(mxa, param);
		break;

	case 50:
		status = ERROR_NOT_SUPPORTED;
		break;

	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct mslm_NetFileEnum));
		param->status = status;
		return (NDR_DRC_OK);
	}

	if (param->resume_handle)
		*param->resume_handle = 0;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * Build level 2 file information.
 *
 * On success, the caller expects that the info2, fi2 and entries_read
 * fields have been set up.
 */
static DWORD
srvsvc_NetFileEnum2(ndr_xa_t *mxa, struct mslm_NetFileEnum *param)
{
	struct mslm_NetFileInfoBuf2 *fi2;
	ndr_pipe_info_t pi;
	uint32_t entries_read = 0;
	int i;

	param->info.ru.info2 = NDR_NEW(mxa, struct mslm_NetFileInfo2);
	if (param->info.ru.info2 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	fi2 = NDR_NEWN(mxa, struct mslm_NetFileInfoBuf2, 128);
	if (fi2 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	param->info.ru.info2->fi2 = fi2;

	for (i = 0; i < 128; ++i) {
		if (ndr_pipe_getinfo(i, &pi) == -1)
			continue;

		fi2->fi2_id = pi.npi_fid;

		++entries_read;
		++fi2;
	}

	param->info.ru.info2->entries_read = entries_read;
	param->total_entries = entries_read;
	return (ERROR_SUCCESS);
}

/*
 * Build level 3 file information.
 *
 * On success, the caller expects that the info3, fi3 and entries_read
 * fields have been set up.
 */
static DWORD
srvsvc_NetFileEnum3(ndr_xa_t *mxa, struct mslm_NetFileEnum *param)
{
	struct mslm_NetFileInfoBuf3 *fi3;
	ndr_pipe_info_t pi;
	uint32_t entries_read = 0;
	int i;

	param->info.ru.info3 = NDR_NEW(mxa, struct mslm_NetFileInfo3);
	if (param->info.ru.info3 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	fi3 = NDR_NEWN(mxa, struct mslm_NetFileInfoBuf3, 128);
	if (fi3 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	param->info.ru.info3->fi3 = fi3;

	for (i = 0; i < 128; ++i) {
		if (ndr_pipe_getinfo(i, &pi) == -1)
			continue;

		fi3->fi3_id = pi.npi_fid;
		fi3->fi3_permissions = pi.npi_permissions;
		fi3->fi3_num_locks = pi.npi_num_locks;
		fi3->fi3_pathname = (uint8_t *)
		    NDR_STRDUP(mxa, pi.npi_pathname);
		fi3->fi3_username = (uint8_t *)
		    NDR_STRDUP(mxa, pi.npi_username);

		++entries_read;
		++fi3;
	}

	param->info.ru.info3->entries_read = entries_read;
	param->total_entries = entries_read;
	return (ERROR_SUCCESS);
}

/*
 * srvsvc_s_NetFileClose
 *
 * NetFileClose forces a file to close. This function can be used when
 * an error prevents closure by any other means.  Use NetFileClose with
 * caution because it does not flush data, cached on a client, to the
 * file before closing the file.
 *
 * Return Values
 * ERROR_SUCCESS            Operation succeeded.
 * ERROR_ACCESS_DENIED      Operation denied.
 * NERR_FileIdNotFound      No open file with the specified id.
 *
 * Note: MSDN suggests that the error code should be ERROR_FILE_NOT_FOUND
 * but network captures using NT show NERR_FileIdNotFound.
 * The NetFileClose2 MSDN page has the right error code.
 */
static int
srvsvc_s_NetFileClose(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetFileClose *param = arg;

	if (!ndr_is_admin(mxa)) {
		bzero(param, sizeof (struct mslm_NetFileClose));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	bzero(param, sizeof (struct mslm_NetFileClose));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * srvsvc_s_NetShareGetInfo
 *
 * Returns Win32 error codes.
 */
static int
srvsvc_s_NetShareGetInfo(void *arg, ndr_xa_t *mxa)
{
	struct mlsm_NetShareGetInfo *param = arg;
	struct mslm_NetShareInfo_0 *info0;
	struct mslm_NetShareInfo_1 *info1;
	struct mslm_NetShareInfo_2 *info2;
	struct mslm_NetShareInfo_501 *info501;
	struct mslm_NetShareInfo_502 *info502;
	struct mslm_NetShareInfo_503 *info503;
	struct mslm_NetShareInfo_1004 *info1004;
	struct mslm_NetShareInfo_1005 *info1005;
	struct mslm_NetShareInfo_1006 *info1006;
	struct mslm_NetShareInfo_1501 *info1501;
	srvsvc_netshare_getinfo_t *info;
	uint8_t *netname;
	uint8_t *comment;
	smb_share_t si;
	srvsvc_sd_t sd;
	DWORD status;

	status = smb_shr_get((char *)param->netname, &si);
	if (status != NERR_Success) {
		bzero(param, sizeof (struct mlsm_NetShareGetInfo));
		param->status = status;
		return (NDR_DRC_OK);
	}

	netname = (uint8_t *)NDR_STRDUP(mxa, si.shr_name);
	comment = (uint8_t *)NDR_STRDUP(mxa, si.shr_cmnt);
	info = NDR_NEW(mxa, srvsvc_netshare_getinfo_t);

	if (netname == NULL || comment == NULL || info == NULL) {
		bzero(param, sizeof (struct mlsm_NetShareGetInfo));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	switch (param->level) {
	case 0:
		info0 = &info->nsg_info0;
		info0->shi0_netname = netname;
		param->result.ru.info0 = info0;
		break;

	case 1:
		info1 = &info->nsg_info1;
		info1->shi1_netname = netname;
		info1->shi1_comment = comment;
		info1->shi1_type = si.shr_type;
		param->result.ru.info1 = info1;
		break;

	case 2:
		info2 = &info->nsg_info2;
		info2->shi2_netname = netname;
		info2->shi2_comment = comment;
		info2->shi2_path =
		    (uint8_t *)srvsvc_share_mkpath(mxa, si.shr_path);
		info2->shi2_passwd = 0;
		info2->shi2_type = si.shr_type;
		info2->shi2_permissions = 0;
		info2->shi2_max_uses = SHI_USES_UNLIMITED;
		info2->shi2_current_uses = 0;
		param->result.ru.info2 = info2;
		break;

	case 501:
		info501 = &info->nsg_info501;
		info501->shi501_netname = netname;
		info501->shi501_comment = comment;
		info501->shi501_type = si.shr_type;
		info501->shi501_reserved = 0;
		param->result.ru.info501 = info501;
		break;

	case 502:
		info502 = &info->nsg_info502;
		info502->shi502_netname = netname;
		info502->shi502_comment = comment;
		info502->shi502_path =
		    (uint8_t *)srvsvc_share_mkpath(mxa, si.shr_path);
		info502->shi502_passwd = 0;
		info502->shi502_type = si.shr_type;
		info502->shi502_permissions = 0;
		info502->shi502_max_uses = SHI_USES_UNLIMITED;
		info502->shi502_current_uses = 0;

		status = srvsvc_share_getsd(mxa, &si, &sd);
		if (status == ERROR_SUCCESS) {
			info502->shi502_reserved = sd.sd_size;
			info502->shi502_security_descriptor = sd.sd_buf;
		} else {
			info502->shi502_reserved = 0;
			info502->shi502_security_descriptor = NULL;
		}

		param->result.ru.info502 = info502;
		break;

	case 503:
		info503 = &info->nsg_info503;
		info503->shi503_netname = netname;
		info503->shi503_comment = comment;
		info503->shi503_path =
		    (uint8_t *)srvsvc_share_mkpath(mxa, si.shr_path);
		info503->shi503_passwd = NULL;
		info503->shi503_type = si.shr_type;
		info503->shi503_permissions = 0;
		info503->shi503_max_uses = SHI_USES_UNLIMITED;
		info503->shi503_current_uses = 0;
		info503->shi503_servername = NULL;

		status = srvsvc_share_getsd(mxa, &si, &sd);
		if (status == ERROR_SUCCESS) {
			info503->shi503_reserved = sd.sd_size;
			info503->shi503_security_descriptor = sd.sd_buf;
		} else {
			info503->shi503_reserved = 0;
			info503->shi503_security_descriptor = NULL;
		}

		param->result.ru.info503 = info503;
		break;

	case 1004:
		info1004 = &info->nsg_info1004;
		info1004->shi1004_comment = comment;
		param->result.ru.info1004 = info1004;
		break;

	case 1005:
		info1005 = &info->nsg_info1005;
		info1005->shi1005_flags = 0;

		switch (si.shr_flags & SMB_SHRF_CSC_MASK) {
		case SMB_SHRF_CSC_DISABLED:
			info1005->shi1005_flags |= CSC_CACHE_NONE;
			break;
		case SMB_SHRF_CSC_AUTO:
			info1005->shi1005_flags |= CSC_CACHE_AUTO_REINT;
			break;
		case SMB_SHRF_CSC_VDO:
			info1005->shi1005_flags |= CSC_CACHE_VDO;
			break;
		case SMB_SHRF_CSC_MANUAL:
		default:
			/*
			 * Default to CSC_CACHE_MANUAL_REINT.
			 */
			break;
		}

		param->result.ru.info1005 = info1005;
		break;

	case 1006:
		info1006 = &info->nsg_info1006;
		info1006->shi1006_max_uses = SHI_USES_UNLIMITED;
		param->result.ru.info1006 = info1006;
		break;

	case 1501:
		info1501 = &info->nsg_info1501;

		status = srvsvc_share_getsd(mxa, &si, &sd);
		if (status == ERROR_SUCCESS) {
			info503->shi503_reserved = sd.sd_size;
			info503->shi503_security_descriptor = sd.sd_buf;
		} else {
			info503->shi503_reserved = 0;
			info503->shi503_security_descriptor = NULL;
		}

		param->result.ru.info1501 = info1501;
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
	return (NDR_DRC_OK);
}

static uint32_t
srvsvc_share_getsd(ndr_xa_t *mxa, smb_share_t *si, srvsvc_sd_t *sd)
{
	uint32_t status;

	status = srvsvc_sd_get(si, NULL, &sd->sd_size);
	if (status != ERROR_SUCCESS) {
		if (status == ERROR_PATH_NOT_FOUND) {
			bzero(sd, sizeof (srvsvc_sd_t));
			status = ERROR_SUCCESS;
		}

		return (status);
	}

	if ((sd->sd_buf = NDR_MALLOC(mxa, sd->sd_size)) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	status = srvsvc_sd_get(si, sd->sd_buf, NULL);
	if (status == ERROR_PATH_NOT_FOUND) {
		bzero(sd, sizeof (srvsvc_sd_t));
		status = ERROR_SUCCESS;
	}

	return (status);
}

/*
 * srvsvc_s_NetShareSetInfo
 *
 * This call is made by SrvMgr to set share information.
 * Only power users groups can manage shares.
 *
 * To avoid misleading errors, we don't report an error
 * when a FS doesn't support ACLs on shares.
 *
 * Returns Win32 error codes.
 */
static int
srvsvc_s_NetShareSetInfo(void *arg, ndr_xa_t *mxa)
{
	struct mlsm_NetShareSetInfo *param = arg;
	struct mslm_NetShareInfo_0 *info0;
	struct mslm_NetShareInfo_1 *info1;
	struct mslm_NetShareInfo_2 *info2;
	struct mslm_NetShareInfo_501 *info501;
	struct mslm_NetShareInfo_502 *info502;
	struct mslm_NetShareInfo_503 *info503;
	struct mslm_NetShareInfo_1004 *info1004;
	struct mslm_NetShareInfo_1005 *info1005;
	struct mslm_NetShareInfo_1501 *info1501;
	static DWORD parm_err = 0;
	srvsvc_netshare_setinfo_t info;
	smb_share_t si;
	uint8_t *sdbuf;
	int32_t native_os;
	DWORD status;

	native_os = ndr_native_os(mxa);

	if (!ndr_is_poweruser(mxa)) {
		status = ERROR_ACCESS_DENIED;
		goto netsharesetinfo_exit;
	}

	if (smb_shr_get((char *)param->netname, &si) != NERR_Success) {
		status = ERROR_INVALID_NETNAME;
		goto netsharesetinfo_exit;
	}

	if (param->result.ru.nullptr == NULL) {
		status = ERROR_INVALID_PARAMETER;
		goto netsharesetinfo_exit;
	}

	bzero(&info, sizeof (srvsvc_netshare_setinfo_t));

	switch (param->level) {
	case 0:
		info0 = (struct mslm_NetShareInfo_0 *)param->result.ru.info0;
		info.nss_netname = (char *)info0->shi0_netname;
		status = srvsvc_modify_share(&si, &info);
		break;

	case 1:
		info1 = (struct mslm_NetShareInfo_1 *)param->result.ru.info1;
		info.nss_netname = (char *)info1->shi1_netname;
		info.nss_comment = (char *)info1->shi1_comment;
		info.nss_type = info1->shi1_type;
		status = srvsvc_modify_share(&si, &info);
		break;

	case 2:
		info2 = (struct mslm_NetShareInfo_2 *)param->result.ru.info2;
		info.nss_netname = (char *)info2->shi2_netname;
		info.nss_comment = (char *)info2->shi2_comment;
		info.nss_path = (char *)info2->shi2_path;
		info.nss_type = info2->shi2_type;
		status = srvsvc_modify_share(&si, &info);
		break;

	case 501:
		info501 = (struct mslm_NetShareInfo_501 *)
		    param->result.ru.info501;
		info.nss_netname = (char *)info501->shi501_netname;
		info.nss_comment = (char *)info501->shi501_comment;
		info.nss_type = info501->shi501_type;
		status = srvsvc_modify_share(&si, &info);
		break;

	case 502:
		info502 = (struct mslm_NetShareInfo_502 *)
		    param->result.ru.info502;
		info.nss_netname = (char *)info502->shi502_netname;
		info.nss_comment = (char *)info502->shi502_comment;
		info.nss_path = (char *)info502->shi502_path;
		info.nss_type = info502->shi502_type;
		info.nss_sd.sd_buf = info502->shi502_security_descriptor;
		status = srvsvc_modify_share(&si, &info);
		break;

	case 503:
		info503 = (struct mslm_NetShareInfo_503 *)
		    param->result.ru.info503;
		info.nss_netname = (char *)info503->shi503_netname;
		info.nss_comment = (char *)info503->shi503_comment;
		info.nss_path = (char *)info503->shi503_path;
		info.nss_type = info503->shi503_type;
		info.nss_sd.sd_buf = info503->shi503_security_descriptor;
		status = srvsvc_modify_share(&si, &info);
		break;

	case 1004:
		info1004 = (struct mslm_NetShareInfo_1004 *)
		    param->result.ru.info1004;
		info.nss_comment = (char *)info1004->shi1004_comment;
		status = srvsvc_modify_share(&si, &info);
		break;

	case 1005:
		info1005 = (struct mslm_NetShareInfo_1005 *)
		    param->result.ru.info1005;
		status = srvsvc_update_share_flags(&si,
		    info1005->shi1005_flags);
		break;

	case 1006:
		/*
		 * We don't limit the maximum number of concurrent
		 * connections to a share.
		 */
		status = ERROR_SUCCESS;
		break;

	case 1501:
		info1501 = (struct mslm_NetShareInfo_1501 *)
		    param->result.ru.info1501;
		sdbuf = info1501->shi1501_security_descriptor;
		status = ERROR_SUCCESS;

		if (sdbuf != NULL) {
			status = srvsvc_sd_set(&si, sdbuf);
			if (status == ERROR_PATH_NOT_FOUND)
				status = ERROR_SUCCESS;
		}
		break;

	default:
		status = ERROR_ACCESS_DENIED;
		break;
	}

netsharesetinfo_exit:
	if (status != ERROR_SUCCESS)
		bzero(param, sizeof (struct mlsm_NetShareSetInfo));

	param->parm_err = (native_os == NATIVE_OS_WIN95) ? 0 : &parm_err;
	param->status = status;
	return (NDR_DRC_OK);
}

static uint32_t
srvsvc_modify_share(smb_share_t *si, srvsvc_netshare_setinfo_t *info)
{
	uint32_t nerr = NERR_Success;

	if (si->shr_flags & SMB_SHRF_TRANS)
		return (srvsvc_modify_transient_share(si, info));

	if (info->nss_sd.sd_buf != NULL) {
		nerr = srvsvc_sd_set(si, info->nss_sd.sd_buf);
		if (nerr == ERROR_PATH_NOT_FOUND)
			nerr = NERR_Success;
	}

	if ((nerr = srvsvc_sa_modify(si, info)) == NERR_Success)
		nerr = smb_shr_modify(si);

	return (nerr);
}

/*
 * Update transient shares.  This includes autohome shares.
 */
static uint32_t
srvsvc_modify_transient_share(smb_share_t *si, srvsvc_netshare_setinfo_t *info)
{
	uint32_t nerr;

	if (info->nss_netname != NULL && info->nss_netname[0] != '\0' &&
	    utf8_strcasecmp(info->nss_netname, si->shr_name) != 0) {
		nerr = smb_shr_rename(si->shr_name, info->nss_netname);
		if (nerr != NERR_Success)
			return (nerr);

		(void) strlcpy(si->shr_name, info->nss_netname, MAXNAMELEN);
	}

	if ((info->nss_comment != NULL) &&
	    (strcmp(info->nss_comment, si->shr_cmnt) != 0)) {
		(void) strlcpy(si->shr_cmnt, info->nss_comment,
		    SMB_SHARE_CMNT_MAX);

		if ((nerr = smb_shr_modify(si)) != NERR_Success)
			return (nerr);
	}

	return (NERR_Success);
}

static uint32_t
srvsvc_update_share_flags(smb_share_t *si, uint32_t shi_flags)
{
	uint32_t cscflg = 0;
	uint32_t nerr = NERR_Success;

	switch ((shi_flags & CSC_MASK)) {
	case CSC_CACHE_AUTO_REINT:
		cscflg = SMB_SHRF_CSC_AUTO;
		break;
	case CSC_CACHE_VDO:
		cscflg = SMB_SHRF_CSC_VDO;
		break;
	case CSC_CACHE_NONE:
		cscflg = SMB_SHRF_CSC_DISABLED;
		break;
	case CSC_CACHE_MANUAL_REINT:
		cscflg = SMB_SHRF_CSC_MANUAL;
		break;
	default:
		return (NERR_Success);
	}

	if (cscflg == (si->shr_flags & SMB_SHRF_CSC_MASK))
		return (NERR_Success);

	si->shr_flags &= ~SMB_SHRF_CSC_MASK;
	si->shr_flags |= cscflg;

	if ((si->shr_flags & SMB_SHRF_TRANS) == 0) {
		if ((nerr = srvsvc_sa_setattr(si)) != NERR_Success)
			return (nerr);
	}

	return (smb_shr_modify(si));
}

/*
 * srvsvc_s_NetSessionEnum
 *
 * Level 1 request is made by (Server Manager (srvmgr) on NT Server when
 * the user info icon is selected.
 *
 * On success, the return value is NERR_Success.
 * On error, the return value can be one of the following error codes:
 *
 * ERROR_ACCESS_DENIED      The user does not have access to the requested
 *                          information.
 * ERROR_INVALID_LEVEL      The value specified for the level is invalid.
 * ERROR_INVALID_PARAMETER  The specified parameter is invalid.
 * ERROR_MORE_DATA          More entries are available. Specify a large
 *                          enough buffer to receive all entries.
 * ERROR_NOT_ENOUGH_MEMORY  Insufficient memory is available.
 * NERR_ClientNameNotFound  A session does not exist with the computer name.
 * NERR_InvalidComputer     The computer name is invalid.
 * NERR_UserNotFound        The user name could not be found.
 */
static int
srvsvc_s_NetSessionEnum(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetSessionEnum *param = arg;
	struct mslm_infonres *infonres;
	DWORD status;
	DWORD n_sessions;

	infonres = NDR_NEW(mxa, struct mslm_infonres);
	if (infonres == NULL) {
		bzero(param, sizeof (struct mslm_NetSessionEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	infonres->entriesread = 0;
	infonres->entries = NULL;
	param->result.level = param->level;
	param->result.bufptr.p = infonres;
	param->total_entries = 0;
	param->resume_handle = NULL;
	param->status = ERROR_SUCCESS;

	if ((n_sessions = (DWORD) mlsvc_get_num_users()) == 0)
		return (NDR_DRC_OK);

	switch (param->level) {
	case 0:
		status = mlsvc_NetSessionEnumLevel0(infonres, n_sessions, mxa);
		break;

	case 1:
		status = mlsvc_NetSessionEnumLevel1(infonres, n_sessions, mxa);
		break;

	case 2:
		status = mlsvc_NetSessionEnumLevel2(infonres, n_sessions, mxa);
		break;

	case 10:
		status = mlsvc_NetSessionEnumLevel10(infonres, n_sessions, mxa);
		break;

	case 502:
		status = mlsvc_NetSessionEnumLevel502(infonres, n_sessions,
		    mxa);
		break;

	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != 0) {
		bzero(param, sizeof (struct mslm_NetSessionEnum));
		param->status = status;
		return (NDR_DRC_OK);
	}

	param->total_entries = infonres->entriesread;
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * mlsvc_NetSessionEnumLevel0
 *
 * Build the level 0 session information.
 */
static DWORD
mlsvc_NetSessionEnumLevel0(struct mslm_infonres *infonres, DWORD n_sessions,
    ndr_xa_t *mxa)
{
	struct mslm_SESSION_INFO_0 *info0;
	smb_ulist_t *ulist;
	smb_opipe_context_t *user;
	char *workstation;
	char ipaddr_buf[INET6_ADDRSTRLEN];
	int i;

	ulist = smb_ulist_alloc();
	if (ulist == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (mlsvc_get_user_list(ulist) != 0) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	if (ulist->ul_cnt < n_sessions)
		n_sessions = ulist->ul_cnt;

	info0 = NDR_NEWN(mxa, struct mslm_SESSION_INFO_0, n_sessions);
	if (info0 == NULL) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	user = ulist->ul_users;
	for (i = 0; i < n_sessions; ++i, user++) {
		workstation = user->oc_workstation;
		if (workstation == NULL || *workstation == '\0') {
			(void) smb_inet_ntop(&user->oc_ipaddr,
			    ipaddr_buf, SMB_IPSTRLEN(user->oc_ipaddr.a_family));
			workstation = ipaddr_buf;
		}

		info0[i].sesi0_cname = NDR_STRDUP(mxa, workstation);
		if (info0[i].sesi0_cname == NULL) {
			smb_ulist_free(ulist);
			return (ERROR_NOT_ENOUGH_MEMORY);
		}
	}

	smb_ulist_free(ulist);
	infonres->entriesread = n_sessions;
	infonres->entries = info0;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetSessionEnumLevel1
 *
 * Build the level 1 session information.
 */
static DWORD
mlsvc_NetSessionEnumLevel1(struct mslm_infonres *infonres, DWORD n_sessions,
    ndr_xa_t *mxa)
{
	struct mslm_SESSION_INFO_1 *info1;
	smb_ulist_t *ulist;
	smb_opipe_context_t *user;
	char *workstation;
	char account[MAXNAMELEN];
	char ipaddr_buf[INET6_ADDRSTRLEN];
	int i;

	ulist = smb_ulist_alloc();
	if (ulist == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (mlsvc_get_user_list(ulist) != 0) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	if (ulist->ul_cnt < n_sessions)
		n_sessions = ulist->ul_cnt;

	info1 = NDR_NEWN(mxa, struct mslm_SESSION_INFO_1, n_sessions);
	if (info1 == NULL) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	user = ulist->ul_users;
	for (i = 0; i < n_sessions; ++i, user++) {
		workstation = user->oc_workstation;
		if (workstation == NULL || *workstation == '\0') {
			(void) smb_inet_ntop(&user->oc_ipaddr,
			    ipaddr_buf, SMB_IPSTRLEN(user->oc_ipaddr.a_family));
			workstation = ipaddr_buf;
		}

		(void) snprintf(account, MAXNAMELEN, "%s\\%s",
		    user->oc_domain, user->oc_account);

		info1[i].sesi1_cname = NDR_STRDUP(mxa, workstation);
		info1[i].sesi1_uname = NDR_STRDUP(mxa, account);

		if (info1[i].sesi1_cname == NULL ||
		    info1[i].sesi1_uname == NULL) {
			smb_ulist_free(ulist);
			return (ERROR_NOT_ENOUGH_MEMORY);
		}

		info1[i].sesi1_nopens = 1;
		info1[i].sesi1_time = time(0) - user->oc_logon_time;
		info1[i].sesi1_itime = 0;
		info1[i].sesi1_uflags =
		    (user->oc_flags & SMB_ATF_GUEST) ? SESS_GUEST : 0;
	}

	smb_ulist_free(ulist);
	infonres->entriesread = n_sessions;
	infonres->entries = info1;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetSessionEnumLevel2
 *
 * Build the level 2 session information.
 */
static DWORD
mlsvc_NetSessionEnumLevel2(struct mslm_infonres *infonres, DWORD n_sessions,
    ndr_xa_t *mxa)
{
	struct mslm_SESSION_INFO_2 *info2;
	smb_ulist_t *ulist;
	smb_opipe_context_t *user;
	char *workstation;
	char account[MAXNAMELEN];
	char ipaddr_buf[INET6_ADDRSTRLEN];
	int i;

	if ((ulist = smb_ulist_alloc()) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (mlsvc_get_user_list(ulist) != 0) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	if (ulist->ul_cnt < n_sessions)
		n_sessions = ulist->ul_cnt;

	info2 = NDR_NEWN(mxa, struct mslm_SESSION_INFO_2, n_sessions);
	if (info2 == NULL) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	user = ulist->ul_users;
	for (i = 0; i < n_sessions; ++i, user++) {
		workstation = user->oc_workstation;
		if (workstation == NULL || *workstation == '\0') {
			(void) smb_inet_ntop(&user->oc_ipaddr,
			    ipaddr_buf, SMB_IPSTRLEN(user->oc_ipaddr.a_family));
			workstation = ipaddr_buf;
		}

		(void) snprintf(account, MAXNAMELEN, "%s\\%s",
		    user->oc_domain, user->oc_account);

		info2[i].sesi2_cname = NDR_STRDUP(mxa, workstation);
		info2[i].sesi2_uname = NDR_STRDUP(mxa, account);

		if (info2[i].sesi2_cname == NULL ||
		    info2[i].sesi2_uname == NULL) {
			smb_ulist_free(ulist);
			return (ERROR_NOT_ENOUGH_MEMORY);
		}

		info2[i].sesi2_nopens = 1;
		info2[i].sesi2_time = time(0) - user->oc_logon_time;
		info2[i].sesi2_itime = 0;
		info2[i].sesi2_uflags =
		    (user->oc_flags & SMB_ATF_GUEST) ? SESS_GUEST : 0;
		info2[i].sesi2_cltype_name = (uint8_t *)"";
	}

	smb_ulist_free(ulist);
	infonres->entriesread = n_sessions;
	infonres->entries = info2;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetSessionEnumLevel10
 *
 * Build the level 10 session information.
 */
static DWORD
mlsvc_NetSessionEnumLevel10(struct mslm_infonres *infonres, DWORD n_sessions,
    ndr_xa_t *mxa)
{
	struct mslm_SESSION_INFO_10 *info10;
	smb_ulist_t *ulist;
	smb_opipe_context_t *user;
	char *workstation;
	char account[MAXNAMELEN];
	char ipaddr_buf[INET6_ADDRSTRLEN];
	int i;

	if ((ulist = smb_ulist_alloc()) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (mlsvc_get_user_list(ulist) != 0) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	if (ulist->ul_cnt < n_sessions)
		n_sessions = ulist->ul_cnt;

	info10 = NDR_NEWN(mxa, struct mslm_SESSION_INFO_10, n_sessions);
	if (info10 == NULL) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	user = ulist->ul_users;
	for (i = 0; i < n_sessions; ++i, user++) {
		workstation = user->oc_workstation;
		if (workstation == NULL || *workstation == '\0') {
			(void) smb_inet_ntop(&user->oc_ipaddr,
			    ipaddr_buf, SMB_IPSTRLEN(user->oc_ipaddr.a_family));
			workstation = ipaddr_buf;
		}

		(void) snprintf(account, MAXNAMELEN, "%s\\%s",
		    user->oc_domain, user->oc_account);

		info10[i].sesi10_cname = NDR_STRDUP(mxa, workstation);
		info10[i].sesi10_uname = NDR_STRDUP(mxa, account);

		if (info10[i].sesi10_cname == NULL ||
		    info10[i].sesi10_uname == NULL) {
			smb_ulist_free(ulist);
			return (ERROR_NOT_ENOUGH_MEMORY);
		}

		info10[i].sesi10_time = time(0) - user->oc_logon_time;
		info10[i].sesi10_itime = 0;
	}

	smb_ulist_free(ulist);
	infonres->entriesread = n_sessions;
	infonres->entries = info10;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetSessionEnumLevel502
 *
 * Build the level 502 session information.
 */
static DWORD
mlsvc_NetSessionEnumLevel502(struct mslm_infonres *infonres, DWORD n_sessions,
    ndr_xa_t *mxa)
{
	struct mslm_SESSION_INFO_502 *info502;
	smb_ulist_t *ulist;
	smb_opipe_context_t *user;
	char *workstation;
	char account[MAXNAMELEN];
	char ipaddr_buf[INET6_ADDRSTRLEN];
	int i;

	if ((ulist = smb_ulist_alloc()) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	if (mlsvc_get_user_list(ulist) != 0) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	if (ulist->ul_cnt < n_sessions)
		n_sessions = ulist->ul_cnt;

	info502 = NDR_NEWN(mxa, struct mslm_SESSION_INFO_502, n_sessions);
	if (info502 == NULL) {
		smb_ulist_free(ulist);
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	user = ulist->ul_users;
	for (i = 0; i < n_sessions; ++i, user++) {
		workstation = user->oc_workstation;
		if (workstation == NULL || *workstation == '\0') {
			(void) smb_inet_ntop(&user->oc_ipaddr,
			    ipaddr_buf, SMB_IPSTRLEN(user->oc_ipaddr.a_family));
			workstation = ipaddr_buf;
		}

		(void) snprintf(account, MAXNAMELEN, "%s\\%s",
		    user->oc_domain, user->oc_account);

		info502[i].sesi502_cname = NDR_STRDUP(mxa, workstation);
		info502[i].sesi502_uname = NDR_STRDUP(mxa, account);

		if (info502[i].sesi502_cname == NULL ||
		    info502[i].sesi502_uname == NULL) {
			smb_ulist_free(ulist);
			return (ERROR_NOT_ENOUGH_MEMORY);
		}

		info502[i].sesi502_nopens = 1;
		info502[i].sesi502_time = time(0) - user->oc_logon_time;
		info502[i].sesi502_itime = 0;
		info502[i].sesi502_uflags =
		    (user->oc_flags & SMB_ATF_GUEST) ? SESS_GUEST : 0;
		info502[i].sesi502_cltype_name = (uint8_t *)"";
		info502[i].sesi502_transport = (uint8_t *)"";
	}

	smb_ulist_free(ulist);
	infonres->entriesread = n_sessions;
	infonres->entries = info502;
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
srvsvc_s_NetSessionDel(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetSessionDel *param = arg;

	if (!ndr_is_poweruser(mxa)) {
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
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
 *		...
 *		default:	char *nullptr;
 *		} bufptr,
 *	OUT	DWORD status
 */
static int
srvsvc_s_NetServerGetInfo(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetServerGetInfo *param = arg;
	struct mslm_SERVER_INFO_100 *info100;
	struct mslm_SERVER_INFO_101 *info101;
	struct mslm_SERVER_INFO_102 *info102;
	struct mslm_SERVER_INFO_502 *info502;
	struct mslm_SERVER_INFO_503 *info503;
	char sys_comment[SMB_PI_MAX_COMMENT];
	char hostname[NETBIOS_NAME_SZ];

	if (smb_getnetbiosname(hostname, sizeof (hostname)) != 0) {
netservergetinfo_no_memory:
		bzero(param, sizeof (struct mslm_NetServerGetInfo));
		return (ERROR_NOT_ENOUGH_MEMORY);
	}

	(void) smb_config_getstr(SMB_CI_SYS_CMNT, sys_comment,
	    sizeof (sys_comment));
	if (*sys_comment == '\0')
		(void) strcpy(sys_comment, " ");

	switch (param->level) {
	case 100:
		info100 = NDR_NEW(mxa, struct mslm_SERVER_INFO_100);
		if (info100 == NULL)
			goto netservergetinfo_no_memory;

		bzero(info100, sizeof (struct mslm_SERVER_INFO_100));
		info100->sv100_platform_id = SV_PLATFORM_ID_NT;
		info100->sv100_name = (uint8_t *)NDR_STRDUP(mxa, hostname);
		if (info100->sv100_name == NULL)
			goto netservergetinfo_no_memory;

		param->result.bufptr.bufptr100 = info100;
		break;

	case 101:
		info101 = NDR_NEW(mxa, struct mslm_SERVER_INFO_101);
		if (info101 == NULL)
			goto netservergetinfo_no_memory;

		bzero(info101, sizeof (struct mslm_SERVER_INFO_101));
		info101->sv101_platform_id = SV_PLATFORM_ID_NT;
		info101->sv101_version_major = 4;
		info101->sv101_version_minor = 0;
		info101->sv101_type = SV_TYPE_SENT_BY_ME;
		info101->sv101_name = (uint8_t *)NDR_STRDUP(mxa, hostname);
		info101->sv101_comment
		    = (uint8_t *)NDR_STRDUP(mxa, sys_comment);

		if (info101->sv101_name == NULL ||
		    info101->sv101_comment == NULL)
			goto netservergetinfo_no_memory;

		param->result.bufptr.bufptr101 = info101;
		break;

	case 102:
		info102 = NDR_NEW(mxa, struct mslm_SERVER_INFO_102);
		if (info102 == NULL)
			goto netservergetinfo_no_memory;

		bzero(info102, sizeof (struct mslm_SERVER_INFO_102));
		info102->sv102_platform_id = SV_PLATFORM_ID_NT;
		info102->sv102_version_major = 4;
		info102->sv102_version_minor = 0;
		info102->sv102_type = SV_TYPE_SENT_BY_ME;
		info102->sv102_name = (uint8_t *)NDR_STRDUP(mxa, hostname);
		info102->sv102_comment
		    = (uint8_t *)NDR_STRDUP(mxa, sys_comment);

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
		if (info102->sv102_name == NULL ||
		    info102->sv102_comment == NULL)
			goto netservergetinfo_no_memory;

		param->result.bufptr.bufptr102 = info102;
		break;

	case 502:
		info502 = NDR_NEW(mxa, struct mslm_SERVER_INFO_502);
		if (info502 == NULL)
			goto netservergetinfo_no_memory;

		bzero(info502, sizeof (struct mslm_SERVER_INFO_502));
		param->result.bufptr.bufptr502 = info502;
#ifdef SRVSVC_SATISFY_SMBTORTURE
		break;
#else
		param->result.level = param->level;
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
#endif /* SRVSVC_SATISFY_SMBTORTURE */

	case 503:
		info503 = NDR_NEW(mxa, struct mslm_SERVER_INFO_503);
		if (info503 == NULL)
			goto netservergetinfo_no_memory;

		bzero(info503, sizeof (struct mslm_SERVER_INFO_503));
		param->result.bufptr.bufptr503 = info503;
#ifdef SRVSVC_SATISFY_SMBTORTURE
		break;
#else
		param->result.level = param->level;
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
#endif /* SRVSVC_SATISFY_SMBTORTURE */

	default:
		bzero(&param->result,
		    sizeof (struct mslm_NetServerGetInfo_result));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	param->result.level = param->level;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
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
 *	DWORD tod_weekday;   // day of the week since Sunday [0-6]
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
srvsvc_s_NetRemoteTOD(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetRemoteTOD *param = arg;
	struct mslm_TIME_OF_DAY_INFO *tod;
	struct timeval		time_val;
	struct tm		tm;

	(void) gettimeofday(&time_val, 0);
	(void) gmtime_r(&time_val.tv_sec, &tm);

	tod = NDR_NEW(mxa, struct mslm_TIME_OF_DAY_INFO);
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
	return (NDR_DRC_OK);
}

/*
 * srvsvc_s_NetNameValidate
 *
 * Perform name validation.
 *
 * The share name is considered invalid if it contains any of the
 * following character (MSDN 236388).
 *
 * " / \ [ ] : | < > + ; , ? * =
 *
 * Returns Win32 error codes.
 */
/*ARGSUSED*/
static int
srvsvc_s_NetNameValidate(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetNameValidate *param = arg;
	char *name;
	int len;

	if ((name = (char *)param->pathname) == NULL) {
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	len = strlen(name);

	if ((param->flags == 0 && len > 81) ||
	    (param->flags == 0x80000000 && len > 13)) {
		param->status = ERROR_INVALID_NAME;
		return (NDR_DRC_OK);
	}

	switch (param->type) {
	case NAMETYPE_SHARE:
		if (smb_shr_chkname(name))
			param->status = ERROR_SUCCESS;
		else
			param->status = ERROR_INVALID_NAME;
		break;

	case NAMETYPE_USER:
	case NAMETYPE_PASSWORD:
	case NAMETYPE_GROUP:
	case NAMETYPE_COMPUTER:
	case NAMETYPE_EVENT:
	case NAMETYPE_DOMAIN:
	case NAMETYPE_SERVICE:
	case NAMETYPE_NET:
	case NAMETYPE_MESSAGE:
	case NAMETYPE_MESSAGEDEST:
	case NAMETYPE_SHAREPASSWORD:
	case NAMETYPE_WORKGROUP:
		param->status = ERROR_NOT_SUPPORTED;
		break;

	default:
		param->status = ERROR_INVALID_PARAMETER;
		break;
	}

	return (NDR_DRC_OK);
}

/*
 * srvsvc_s_NetShareAdd
 *
 * Add a new share. Only power users groups can manage shares.
 *
 * This interface is used by the rmtshare command from the NT resource
 * kit. Rmtshare allows a client to add or remove shares on a server
 * from the client's command line.
 *
 * Returns Win32 error codes.
 */
static int
srvsvc_s_NetShareAdd(void *arg, ndr_xa_t *mxa)
{
	static DWORD parm_err = 0;
	DWORD parm_stat;
	struct mslm_NetShareAdd *param = arg;
	struct mslm_NetShareInfo_2 *info2;
	struct mslm_NetShareInfo_502 *info502;
	char realpath[MAXPATHLEN];
	int32_t native_os;
	uint8_t *sdbuf = NULL;
	uint32_t status;
	smb_share_t si;

	native_os = ndr_native_os(mxa);

	if (!ndr_is_poweruser(mxa)) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	switch (param->level) {
	case 2:
		info2 = (struct mslm_NetShareInfo_2 *)param->info.un.info2;
		break;

	case 502:
		info502 = (struct mslm_NetShareInfo_502 *)
		    param->info.un.info502;
		sdbuf = info502->shi502_security_descriptor;
		info2 = (struct mslm_NetShareInfo_2 *)info502;
		break;

	default:
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	if (info2->shi2_netname == NULL || info2->shi2_path == NULL) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = NERR_NetNameNotFound;
		return (NDR_DRC_OK);
	}

	if (smb_shr_is_restricted((char *)info2->shi2_netname)) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	if (info2->shi2_comment == NULL)
		info2->shi2_comment = (uint8_t *)"";

	/*
	 * Derive the real path which will be stored in the
	 * directory field of the smb_share_t structure
	 * from the path field in this RPC request.
	 */
	parm_stat = smb_shr_get_realpath((const char *)info2->shi2_path,
	    realpath, MAXPATHLEN);

	if (parm_stat != NERR_Success) {
		bzero(param, sizeof (struct mslm_NetShareAdd));
		param->status = parm_stat;
		param->parm_err
		    = (native_os == NATIVE_OS_WIN95) ? 0 : &parm_err;
		return (NDR_DRC_OK);
	}

	param->status = srvsvc_sa_add((char *)info2->shi2_netname, realpath,
	    (char *)info2->shi2_comment);
	if (param->status == NERR_Success) {
		status = smb_shr_get((char *)info2->shi2_netname, &si);

		if ((sdbuf != NULL) && (status == NERR_Success))
			(void) srvsvc_sd_set(&si, sdbuf);
	}
	param->parm_err = (native_os == NATIVE_OS_WIN95) ? 0 : &parm_err;
	return (NDR_DRC_OK);
}

/*
 * srvsvc_estimate_objcnt
 *
 * Estimate the number of objects that will fit in prefmaxlen.
 */
static uint32_t
srvsvc_estimate_objcnt(uint32_t prefmaxlen, uint32_t n_obj, uint32_t obj_size)
{
	DWORD max_cnt;

	if (obj_size == 0)
		return (0);

	if ((max_cnt = (prefmaxlen / obj_size)) == 0)
		return (0);

	if (n_obj > max_cnt)
		n_obj = max_cnt;

	return (n_obj);
}

/*
 * srvsvc_s_NetShareEnum
 *
 * Enumerate all shares (see also NetShareEnumSticky).
 *
 * Request for various levels of information about our shares.
 * Level 0: share names.
 * Level 1: share name, share type and comment field.
 * Level 2: everything that we know about the shares.
 * Level 501: level 1 + flags (flags must be zero).
 * Level 502: level 2 + security descriptor.
 */
static int
srvsvc_s_NetShareEnum(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetShareEnum *param = arg;
	struct mslm_infonres *infonres;
	srvsvc_enum_t se;
	DWORD status;

	infonres = NDR_NEW(mxa, struct mslm_infonres);
	if (infonres == NULL) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	infonres->entriesread = 0;
	infonres->entries = NULL;
	param->result.level = param->level;
	param->result.bufptr.p = infonres;

	bzero(&se, sizeof (srvsvc_enum_t));
	se.se_level = param->level;
	se.se_n_total = smb_shr_count();

	if (param->prefmaxlen == SMB_SRVSVC_MAXPREFLEN ||
	    param->prefmaxlen > SMB_SRVSVC_MAXBUFLEN)
		se.se_prefmaxlen = SMB_SRVSVC_MAXBUFLEN;
	else
		se.se_prefmaxlen = param->prefmaxlen;

	if (param->resume_handle) {
		se.se_resume_handle = *param->resume_handle;
		se.se_n_skip = se.se_resume_handle;
	}

	switch (param->level) {
	case 0:
		status = mlsvc_NetShareEnumLevel0(mxa, infonres, &se, 0);
		break;

	case 1:
		status = mlsvc_NetShareEnumLevel1(mxa, infonres, &se, 0);
		break;

	case 2:
		status = mlsvc_NetShareEnumLevel2(mxa, infonres, &se, 0);
		break;

	case 501:
		status = mlsvc_NetShareEnumLevel501(mxa, infonres, &se, 0);
		break;

	case 502:
		status = mlsvc_NetShareEnumLevel502(mxa, infonres, &se, 0);
		break;

	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != 0) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = status;
		return (NDR_DRC_OK);
	}

	if (se.se_n_enum == 0) {
		if (param->resume_handle)
			*param->resume_handle = 0;
		param->status = ERROR_SUCCESS;
		return (NDR_DRC_OK);
	}

	if (param->resume_handle &&
	    param->prefmaxlen != SMB_SRVSVC_MAXPREFLEN) {
		if (se.se_resume_handle < se.se_n_total) {
			*param->resume_handle = se.se_resume_handle;
			status = ERROR_MORE_DATA;
		} else {
			*param->resume_handle = 0;
		}
	}

	param->totalentries = se.se_n_total;
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * srvsvc_s_NetShareEnumSticky
 *
 * Enumerate sticky shares: all shares except those marked STYPE_SPECIAL.
 * Except for excluding STYPE_SPECIAL shares, NetShareEnumSticky is the
 * same as NetShareEnum.
 *
 * Request for various levels of information about our shares.
 * Level 0: share names.
 * Level 1: share name, share type and comment field.
 * Level 2: everything that we know about the shares.
 * Level 501: not valid for this request.
 * Level 502: level 2 + security descriptor.
 *
 * We set n_skip to resume_handle, which is used to find the appropriate
 * place to resume.  The resume_handle is similar to the readdir cookie.
 */
static int
srvsvc_s_NetShareEnumSticky(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetShareEnum *param = arg;
	struct mslm_infonres *infonres;
	srvsvc_enum_t se;
	DWORD status;

	infonres = NDR_NEW(mxa, struct mslm_infonres);
	if (infonres == NULL) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	infonres->entriesread = 0;
	infonres->entries = NULL;
	param->result.level = param->level;
	param->result.bufptr.p = infonres;

	bzero(&se, sizeof (srvsvc_enum_t));
	se.se_level = param->level;
	se.se_n_total = smb_shr_count();

	if (param->prefmaxlen == SMB_SRVSVC_MAXPREFLEN ||
	    param->prefmaxlen > SMB_SRVSVC_MAXBUFLEN)
		se.se_prefmaxlen = SMB_SRVSVC_MAXBUFLEN;
	else
		se.se_prefmaxlen = param->prefmaxlen;

	if (param->resume_handle) {
		se.se_resume_handle = *param->resume_handle;
		se.se_n_skip = se.se_resume_handle;
	}

	switch (param->level) {
	case 0:
		status = mlsvc_NetShareEnumLevel0(mxa, infonres, &se, 1);
		break;

	case 1:
		status = mlsvc_NetShareEnumLevel1(mxa, infonres, &se, 1);
		break;

	case 2:
		status = mlsvc_NetShareEnumLevel2(mxa, infonres, &se, 1);
		break;

	case 502:
		status = mlsvc_NetShareEnumLevel502(mxa, infonres, &se, 1);
		break;

	case 501:
	default:
		status = ERROR_INVALID_LEVEL;
		break;
	}

	if (status != ERROR_SUCCESS) {
		bzero(param, sizeof (struct mslm_NetShareEnum));
		param->status = status;
		return (NDR_DRC_OK);
	}

	if (se.se_n_enum == 0) {
		if (param->resume_handle)
			*param->resume_handle = 0;
		param->status = ERROR_SUCCESS;
		return (NDR_DRC_OK);
	}

	if (param->resume_handle &&
	    param->prefmaxlen != SMB_SRVSVC_MAXPREFLEN) {
		if (se.se_resume_handle < se.se_n_total) {
			*param->resume_handle = se.se_resume_handle;
			status = ERROR_MORE_DATA;
		} else {
			*param->resume_handle = 0;
		}
	}

	param->totalentries = se.se_n_total;
	param->status = status;
	return (NDR_DRC_OK);
}

/*
 * NetShareEnum Level 0
 */
static DWORD
mlsvc_NetShareEnumLevel0(ndr_xa_t *mxa,
    struct mslm_infonres *infonres, srvsvc_enum_t *se, int sticky)
{
	struct mslm_NetShareInfo_0 *info0;
	smb_shriter_t iterator;
	smb_share_t *si;
	DWORD status;

	se->se_n_enum = srvsvc_estimate_objcnt(se->se_prefmaxlen,
	    se->se_n_total, sizeof (struct mslm_NetShareInfo_0) + MAXNAMELEN);
	if (se->se_n_enum == 0)
		return (ERROR_SUCCESS);

	info0 = NDR_NEWN(mxa, struct mslm_NetShareInfo_0, se->se_n_enum);
	if (info0 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	smb_shr_iterinit(&iterator);

	se->se_n_read = 0;
	while ((si = smb_shr_iterate(&iterator)) != NULL) {
		if (se->se_n_skip > 0) {
			--se->se_n_skip;
			continue;
		}

		++se->se_resume_handle;

		if (sticky && (si->shr_flags & SMB_SHRF_TRANS))
			continue;

		if (si->shr_flags & SMB_SHRF_AUTOHOME)
			continue;

		if (se->se_n_read >= se->se_n_enum) {
			se->se_n_read = se->se_n_enum;
			break;
		}

		status = mlsvc_NetShareEnumCommon(mxa, se, si, (void *)info0);
		if (status != ERROR_SUCCESS)
			break;

		++se->se_n_read;
	}

	if (se->se_n_read < se->se_n_enum) {
		if (srvsvc_add_autohome(mxa, se, (void *)info0))
			++se->se_n_read;
	}

	infonres->entriesread = se->se_n_read;
	infonres->entries = info0;
	return (ERROR_SUCCESS);
}

/*
 * NetShareEnum Level 1
 */
static DWORD
mlsvc_NetShareEnumLevel1(ndr_xa_t *mxa,
    struct mslm_infonres *infonres, srvsvc_enum_t *se, int sticky)
{
	struct mslm_NetShareInfo_1 *info1;
	smb_shriter_t iterator;
	smb_share_t *si;
	DWORD status;

	se->se_n_enum = srvsvc_estimate_objcnt(se->se_prefmaxlen,
	    se->se_n_total, sizeof (struct mslm_NetShareInfo_1) + MAXNAMELEN);
	if (se->se_n_enum == 0)
		return (ERROR_SUCCESS);

	info1 = NDR_NEWN(mxa, struct mslm_NetShareInfo_1, se->se_n_enum);
	if (info1 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	smb_shr_iterinit(&iterator);

	se->se_n_read = 0;
	while ((si = smb_shr_iterate(&iterator)) != 0) {
		if (se->se_n_skip > 0) {
			--se->se_n_skip;
			continue;
		}

		++se->se_resume_handle;

		if (sticky && (si->shr_flags & SMB_SHRF_TRANS))
			continue;

		if (si->shr_flags & SMB_SHRF_AUTOHOME)
			continue;

		if (se->se_n_read >= se->se_n_enum) {
			se->se_n_read = se->se_n_enum;
			break;
		}

		status = mlsvc_NetShareEnumCommon(mxa, se, si, (void *)info1);
		if (status != ERROR_SUCCESS)
			break;

		++se->se_n_read;
	}

	if (se->se_n_read < se->se_n_enum) {
		if (srvsvc_add_autohome(mxa, se, (void *)info1))
			++se->se_n_read;
	}

	infonres->entriesread = se->se_n_read;
	infonres->entries = info1;
	return (ERROR_SUCCESS);
}

/*
 * NetShareEnum Level 2
 */
static DWORD
mlsvc_NetShareEnumLevel2(ndr_xa_t *mxa,
    struct mslm_infonres *infonres, srvsvc_enum_t *se, int sticky)
{
	struct mslm_NetShareInfo_2 *info2;
	smb_shriter_t iterator;
	smb_share_t *si;
	DWORD status;

	se->se_n_enum = srvsvc_estimate_objcnt(se->se_prefmaxlen,
	    se->se_n_total, sizeof (struct mslm_NetShareInfo_2) + MAXNAMELEN);
	if (se->se_n_enum == 0)
		return (ERROR_SUCCESS);

	info2 = NDR_NEWN(mxa, struct mslm_NetShareInfo_2, se->se_n_enum);
	if (info2 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	smb_shr_iterinit(&iterator);

	se->se_n_read = 0;
	while ((si = smb_shr_iterate(&iterator)) != 0) {
		if (se->se_n_skip > 0) {
			--se->se_n_skip;
			continue;
		}

		++se->se_resume_handle;

		if (sticky && (si->shr_flags & SMB_SHRF_TRANS))
			continue;

		if (si->shr_flags & SMB_SHRF_AUTOHOME)
			continue;

		if (se->se_n_read >= se->se_n_enum) {
			se->se_n_read = se->se_n_enum;
			break;
		}

		status = mlsvc_NetShareEnumCommon(mxa, se, si, (void *)info2);
		if (status != ERROR_SUCCESS)
			break;

		++se->se_n_read;
	}

	if (se->se_n_read < se->se_n_enum) {
		if (srvsvc_add_autohome(mxa, se, (void *)info2))
			++se->se_n_read;
	}

	infonres->entriesread = se->se_n_read;
	infonres->entries = info2;
	return (ERROR_SUCCESS);
}

/*
 * NetShareEnum Level 501
 */
static DWORD
mlsvc_NetShareEnumLevel501(ndr_xa_t *mxa,
    struct mslm_infonres *infonres, srvsvc_enum_t *se, int sticky)
{
	struct mslm_NetShareInfo_501 *info501;
	smb_shriter_t iterator;
	smb_share_t *si;
	DWORD status;

	se->se_n_enum = srvsvc_estimate_objcnt(se->se_prefmaxlen,
	    se->se_n_total, sizeof (struct mslm_NetShareInfo_501) + MAXNAMELEN);
	if (se->se_n_enum == 0)
		return (ERROR_SUCCESS);

	info501 = NDR_NEWN(mxa, struct mslm_NetShareInfo_501,
	    se->se_n_enum);
	if (info501 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	smb_shr_iterinit(&iterator);

	se->se_n_read = 0;
	while ((si = smb_shr_iterate(&iterator)) != 0) {
		if (se->se_n_skip > 0) {
			--se->se_n_skip;
			continue;
		}

		++se->se_resume_handle;

		if (sticky && (si->shr_flags & SMB_SHRF_TRANS))
			continue;

		if (si->shr_flags & SMB_SHRF_AUTOHOME)
			continue;

		if (se->se_n_read >= se->se_n_enum) {
			se->se_n_read = se->se_n_enum;
			break;
		}

		status = mlsvc_NetShareEnumCommon(mxa, se, si, (void *)info501);
		if (status != ERROR_SUCCESS)
			break;

		++se->se_n_read;
	}

	if (se->se_n_read < se->se_n_enum) {
		if (srvsvc_add_autohome(mxa, se, (void *)info501))
			++se->se_n_read;
	}

	infonres->entriesread = se->se_n_read;
	infonres->entries = info501;
	return (ERROR_SUCCESS);
}

/*
 * NetShareEnum Level 502
 */
static DWORD
mlsvc_NetShareEnumLevel502(ndr_xa_t *mxa,
    struct mslm_infonres *infonres, srvsvc_enum_t *se, int sticky)
{
	struct mslm_NetShareInfo_502 *info502;
	smb_shriter_t iterator;
	smb_share_t *si;
	DWORD status;

	se->se_n_enum = srvsvc_estimate_objcnt(se->se_prefmaxlen,
	    se->se_n_total, sizeof (struct mslm_NetShareInfo_502) + MAXNAMELEN);
	if (se->se_n_enum == 0)
		return (ERROR_SUCCESS);

	info502 = NDR_NEWN(mxa, struct mslm_NetShareInfo_502,
	    se->se_n_enum);
	if (info502 == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	smb_shr_iterinit(&iterator);

	se->se_n_read = 0;
	while ((si = smb_shr_iterate(&iterator)) != NULL) {
		if (se->se_n_skip > 0) {
			--se->se_n_skip;
			continue;
		}

		++se->se_resume_handle;

		if (sticky && (si->shr_flags & SMB_SHRF_TRANS))
			continue;

		if (si->shr_flags & SMB_SHRF_AUTOHOME)
			continue;

		if (se->se_n_read >= se->se_n_enum) {
			se->se_n_read = se->se_n_enum;
			break;
		}

		status = mlsvc_NetShareEnumCommon(mxa, se, si, (void *)info502);
		if (status != ERROR_SUCCESS)
			break;

		++se->se_n_read;
	}

	if (se->se_n_read < se->se_n_enum) {
		if (srvsvc_add_autohome(mxa, se, (void *)info502))
			++se->se_n_read;
	}

	infonres->entriesread = se->se_n_read;
	infonres->entries = info502;
	return (ERROR_SUCCESS);
}

/*
 * mlsvc_NetShareEnumCommon
 *
 * Build the levels 0, 1, 2, 501 and 502 share information. This function
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
mlsvc_NetShareEnumCommon(ndr_xa_t *mxa, srvsvc_enum_t *se,
    smb_share_t *si, void *infop)
{
	struct mslm_NetShareInfo_0 *info0;
	struct mslm_NetShareInfo_1 *info1;
	struct mslm_NetShareInfo_2 *info2;
	struct mslm_NetShareInfo_501 *info501;
	struct mslm_NetShareInfo_502 *info502;
	srvsvc_sd_t sd;
	uint8_t *netname;
	uint8_t *comment;
	uint8_t *passwd;
	uint8_t *path;
	int i = se->se_n_read;

	netname = (uint8_t *)NDR_STRDUP(mxa, si->shr_name);
	comment = (uint8_t *)NDR_STRDUP(mxa, si->shr_cmnt);
	passwd = (uint8_t *)NDR_STRDUP(mxa, empty_string);
	path = (uint8_t *)srvsvc_share_mkpath(mxa, si->shr_path);

	if (!netname || !comment || !passwd || !path)
		return (ERROR_NOT_ENOUGH_MEMORY);

	switch (se->se_level) {
	case 0:
		info0 = (struct mslm_NetShareInfo_0 *)infop;
		info0[i].shi0_netname = netname;
		break;

	case 1:
		info1 = (struct mslm_NetShareInfo_1 *)infop;
		info1[i].shi1_netname = netname;
		info1[i].shi1_comment = comment;
		info1[i].shi1_type = si->shr_type;
		break;

	case 2:
		info2 = (struct mslm_NetShareInfo_2 *)infop;
		info2[i].shi2_netname = netname;
		info2[i].shi2_comment = comment;
		info2[i].shi2_path = path;
		info2[i].shi2_type = si->shr_type;
		info2[i].shi2_permissions = 0;
		info2[i].shi2_max_uses = SHI_USES_UNLIMITED;
		info2[i].shi2_current_uses = 0;
		info2[i].shi2_passwd = passwd;
		break;

	case 501:
		info501 = (struct mslm_NetShareInfo_501 *)infop;
		info501[i].shi501_netname = netname;
		info501[i].shi501_comment = comment;
		info501[i].shi501_type = si->shr_type;
		info501[i].shi501_reserved = 0;
		break;

	case 502:
		info502 = (struct mslm_NetShareInfo_502 *)infop;
		info502[i].shi502_netname = netname;
		info502[i].shi502_comment = comment;
		info502[i].shi502_path = path;
		info502[i].shi502_type = si->shr_type;
		info502[i].shi502_permissions = 0;
		info502[i].shi502_max_uses = SHI_USES_UNLIMITED;
		info502[i].shi502_current_uses = 0;
		info502[i].shi502_passwd = passwd;

		if (srvsvc_share_getsd(mxa, si, &sd) == ERROR_SUCCESS) {
			info502[i].shi502_reserved = sd.sd_size;
			info502[i].shi502_security_descriptor = sd.sd_buf;
		} else {
			info502[i].shi502_reserved = 0;
			info502[i].shi502_security_descriptor = NULL;
		}

		break;

	default:
		return (ERROR_INVALID_LEVEL);
	}

	return (ERROR_SUCCESS);
}

/*
 * srvsvc_add_autohome
 *
 * Add the autohome share for the user. The share must not be a permanent
 * share to avoid duplicates.
 */
static boolean_t
srvsvc_add_autohome(ndr_xa_t *mxa, srvsvc_enum_t *se, void *infop)
{
	smb_opipe_context_t *ctx = &mxa->pipe->np_ctx;
	char *username = ctx->oc_account;
	smb_share_t si;
	DWORD status;

	if (smb_shr_get(username, &si) != NERR_Success)
		return (B_FALSE);

	if ((si.shr_flags & SMB_SHRF_AUTOHOME) == 0)
		return (B_FALSE);

	status = mlsvc_NetShareEnumCommon(mxa, se, &si, infop);
	return (status == ERROR_SUCCESS);
}

/*
 * srvsvc_share_mkpath
 *
 * Create the share path required by the share enum calls. The path
 * is created in a heap buffer ready for use by the caller.
 *
 * Some Windows over-the-wire backup applications do not work unless a
 * drive letter is present in the share path.  We don't care about the
 * drive letter since the path is fully qualified with the volume name.
 *
 * Windows clients seem to be mostly okay with forward slashes in
 * share paths but they cannot handle one immediately after the drive
 * letter, i.e. B:/.  For consistency we convert all the slashes in
 * the path.
 *
 * Returns a pointer to a heap buffer containing the share path, which
 * could be a null pointer if the heap allocation fails.
 */
static char *
srvsvc_share_mkpath(ndr_xa_t *mxa, char *path)
{
	char tmpbuf[MAXPATHLEN];
	char *p;

	if (strlen(path) == 0)
		return (NDR_STRDUP(mxa, path));

	/*
	 * Strip the volume name from the path (/vol1/home -> /home).
	 */
	p = path;
	p += strspn(p, "/");
	p += strcspn(p, "/");
	p += strspn(p, "/");
	(void) snprintf(tmpbuf, MAXPATHLEN, "%c:/%s", 'B', p);
	(void) strsubst(tmpbuf, '/', '\\');

	return (NDR_STRDUP(mxa, tmpbuf));
}

static int
srvsvc_s_NetShareCheck(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetShareCheck *param = arg;
	smb_shriter_t iterator;
	smb_share_t *si;
	char *path;

	if (param->path == NULL) {
		param->stype = STYPE_DISKTREE;
		param->status = NERR_NetNameNotFound;
		return (NDR_DRC_OK);
	}

	(void) strsubst((char *)param->path, '/', '\\');

	smb_shr_iterinit(&iterator);

	while ((si = smb_shr_iterate(&iterator)) != NULL) {
		path = srvsvc_share_mkpath(mxa, si->shr_path);

		if (utf8_strcasecmp(path, (char *)param->path) == 0) {
			param->stype = (si->shr_type & STYPE_MASK);
			param->status = NERR_Success;
			return (NDR_DRC_OK);
		}
	}

	param->stype = STYPE_DISKTREE;
	param->status = NERR_NetNameNotFound;
	return (NDR_DRC_OK);
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
srvsvc_s_NetShareDel(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetShareDel *param = arg;

	if (!ndr_is_poweruser(mxa) ||
	    smb_shr_is_restricted((char *)param->netname)) {
		param->status = ERROR_ACCESS_DENIED;
		return (NDR_DRC_OK);
	}

	param->status = srvsvc_sa_delete((char *)param->netname);
	return (NDR_DRC_OK);
}

/*
 * srvsvc_s_NetGetFileSecurity
 *
 * Get security descriptor of the requested file/folder
 *
 * Right now, just returns ERROR_ACCESS_DENIED, because we cannot
 * get the requested SD here in RPC code.
 */
/*ARGSUSED*/
static int
srvsvc_s_NetGetFileSecurity(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetGetFileSecurity *param = arg;

	param->length = 0;
	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

/*
 * srvsvc_s_NetSetFileSecurity
 *
 * Set the given security descriptor for the requested file/folder
 *
 * Right now, just returns ERROR_ACCESS_DENIED, because we cannot
 * set the requested SD here in RPC code.
 */
/*ARGSUSED*/
static int
srvsvc_s_NetSetFileSecurity(void *arg, ndr_xa_t *mxa)
{
	struct mslm_NetSetFileSecurity *param = arg;

	param->status = ERROR_ACCESS_DENIED;
	return (NDR_DRC_OK);
}

/*
 * If the default "smb" share group exists then return the group
 * handle, otherwise create the group and return the handle.
 *
 * All shares created via the srvsvc will be added to the "smb"
 * group.
 */
static sa_group_t
srvsvc_sa_get_smbgrp(sa_handle_t handle)
{
	sa_group_t group = NULL;
	int err;

	group = sa_get_group(handle, SMB_DEFAULT_SHARE_GROUP);
	if (group != NULL)
		return (group);

	group = sa_create_group(handle, SMB_DEFAULT_SHARE_GROUP, &err);
	if (group == NULL)
		return (NULL);

	if (sa_create_optionset(group, SMB_DEFAULT_SHARE_GROUP) == NULL) {
		(void) sa_remove_group(group);
		group = NULL;
	}

	return (group);
}

/*
 * Stores the given share in sharemgr
 */
static uint32_t
srvsvc_sa_add(char *sharename, char *path, char *cmnt)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_group_t group;
	sa_resource_t resource;
	boolean_t new_share = B_FALSE;
	uint32_t status = NERR_Success;
	int err;

	if ((handle = smb_shr_sa_enter()) == NULL)
		return (NERR_InternalError);

	share = sa_find_share(handle, path);
	if (share == NULL) {
		group = srvsvc_sa_get_smbgrp(handle);
		if (group == NULL) {
			smb_shr_sa_exit();
			return (NERR_InternalError);
		}

		share = sa_add_share(group, path, SA_SHARE_PERMANENT, &err);
		if (share == NULL) {
			smb_shr_sa_exit();
			return (NERR_InternalError);
		}
		new_share = B_TRUE;
	}

	resource = sa_get_share_resource(share, sharename);
	if (resource == NULL) {
		resource = sa_add_resource(share, sharename,
		    SA_SHARE_PERMANENT, &err);
		if (resource == NULL) {
			if (new_share)
				(void) sa_remove_share(share);
			smb_shr_sa_exit();
			return (NERR_InternalError);
		}
	}

	(void) sa_set_resource_description(resource, cmnt);

	smb_shr_sa_exit();
	return (status);
}

/*
 * Removes the share from sharemgr
 */
static uint32_t
srvsvc_sa_delete(char *sharename)
{
	sa_handle_t handle;
	sa_resource_t resource;
	uint32_t status;

	if ((handle = smb_shr_sa_enter()) == NULL)
		return (NERR_InternalError);

	status = NERR_InternalError;
	if ((resource = sa_find_resource(handle, sharename)) != NULL) {
		if (sa_remove_resource(resource) == SA_OK)
			status = NERR_Success;
	}

	smb_shr_sa_exit();
	return (status);
}

/*
 * Update the share information.
 */
static uint32_t
srvsvc_sa_modify(smb_share_t *si, srvsvc_netshare_setinfo_t *info)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_resource_t resource;
	boolean_t renamed = B_FALSE;
	uint32_t nerr = NERR_Success;

	if ((handle = smb_shr_sa_enter()) == NULL)
		return (NERR_InternalError);

	if ((share = sa_find_share(handle, si->shr_path)) == NULL) {
		smb_shr_sa_exit();
		return (NERR_InternalError);
	}

	if ((resource = sa_get_share_resource(share, si->shr_name)) == NULL) {
		smb_shr_sa_exit();
		return (NERR_InternalError);
	}

	if (info->nss_netname != NULL && info->nss_netname[0] != '\0' &&
	    utf8_strcasecmp(info->nss_netname, si->shr_name) != 0) {
		(void) sa_set_resource_attr(resource, SHOPT_NAME,
		    info->nss_netname);
		renamed = B_TRUE;
	}

	if ((info->nss_comment != NULL) &&
	    (strcmp(info->nss_comment, si->shr_cmnt) != 0)) {
		(void) sa_set_resource_description(resource, info->nss_comment);
		(void) strlcpy(si->shr_cmnt, info->nss_comment,
		    SMB_SHARE_CMNT_MAX);
	}

	smb_shr_sa_exit();

	if (renamed) {
		nerr = smb_shr_rename(si->shr_name, info->nss_netname);
		if (nerr != NERR_Success)
			return (nerr);

		(void) strlcpy(si->shr_name, info->nss_netname, MAXNAMELEN);
	}

	return (nerr);
}

/*
 * Update the share flags.
 */
static uint32_t
srvsvc_sa_setattr(smb_share_t *si)
{
	sa_handle_t handle;
	sa_share_t share;
	sa_resource_t resource;
	char *value;

	if ((handle = smb_shr_sa_enter()) == NULL)
		return (NERR_InternalError);

	if ((share = sa_find_share(handle, si->shr_path)) == NULL) {
		smb_shr_sa_exit();
		return (NERR_InternalError);
	}

	if ((resource = sa_get_share_resource(share, si->shr_name)) == NULL) {
		smb_shr_sa_exit();
		return (NERR_InternalError);
	}

	if ((value = smb_shr_sa_csc_name(si)) == NULL) {
		smb_shr_sa_exit();
		return (NERR_InternalError);
	}

	(void) sa_set_resource_attr(resource, SHOPT_CSC, value);
	smb_shr_sa_exit();
	return (NERR_Success);
}

static ndr_stub_table_t srvsvc_stub_table[] = {
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
	{ srvsvc_s_NetShareCheck,	SRVSVC_OPNUM_NetShareCheck },
	{ srvsvc_s_NetGetFileSecurity,	SRVSVC_OPNUM_NetGetFileSecurity },
	{ srvsvc_s_NetSetFileSecurity,	SRVSVC_OPNUM_NetSetFileSecurity },
	{0}
};
