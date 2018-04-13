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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Printing and Spooling RPC service.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/atomic.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <fcntl.h>
#include <errno.h>
#include <libmlrpc/libmlrpc.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smb.h>
#include <smbsrv/ndl/spoolss.ndl>
#include <smbsrv/ndl/winreg.ndl>
#include <smb/nterror.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>
#include <mlsvc.h>

#ifdef	HAVE_CUPS

#define	SPOOLSS_PRINTER		"Postscript"

typedef struct smb_spool {
	list_t		sp_list;
	int		sp_cnt;
	rwlock_t	sp_rwl;
	int		sp_initialized;
} smb_spool_t;

typedef struct smb_spooldoc {
	uint32_t	sd_magic;
	list_node_t	sd_lnd;
	smb_inaddr_t	sd_ipaddr;
	int		sd_spool_num;
	char		sd_username[MAXNAMELEN];
	char		sd_path[MAXPATHLEN];
	char		sd_doc_name[MAXNAMELEN];
	char		sd_printer_name[MAXPATHLEN];
	int32_t		sd_fd;
	ndr_hdid_t	sd_handle;
} smb_spooldoc_t;

typedef struct {
	char		*name;
	uint32_t	value;
} spoolss_winreg_t;

typedef struct {
	uint8_t		*sd_buf;
	uint32_t	sd_size;
} spoolss_sd_t;

static uint32_t spoolss_cnt;
static smb_spool_t spoolss_splist;

void (*spoolss_copyfile_callback)(smb_inaddr_t *, char *, char *, char *);

DECL_FIXUP_STRUCT(spoolss_GetPrinter_result_u);
DECL_FIXUP_STRUCT(spoolss_GetPrinter_result);
DECL_FIXUP_STRUCT(spoolss_GetPrinter);

DECL_FIXUP_STRUCT(spoolss_RPC_V2_NOTIFY_INFO_DATA_DATA);
DECL_FIXUP_STRUCT(spoolss_RPC_V2_NOTIFY_INFO_DATA);
DECL_FIXUP_STRUCT(spoolss_RPC_V2_NOTIFY_INFO);
DECL_FIXUP_STRUCT(spoolss_RFNPCNEX);

uint32_t srvsvc_sd_set_relative(smb_sd_t *, uint8_t *);
static int spoolss_getservername(char *, size_t);
static uint32_t spoolss_make_sd(ndr_xa_t *, spoolss_sd_t *);
static uint32_t spoolss_format_sd(smb_sd_t *);
static int spoolss_find_document(ndr_hdid_t *);

static int spoolss_s_OpenPrinter(void *, ndr_xa_t *);
static int spoolss_s_ClosePrinter(void *, ndr_xa_t *);
static int spoolss_s_AbortPrinter(void *, ndr_xa_t *);
static int spoolss_s_ResetPrinter(void *, ndr_xa_t *);
static int spoolss_s_GetPrinter(void *, ndr_xa_t *);
static int spoolss_s_GetPrinterData(void *, ndr_xa_t *);
static int spoolss_s_AddJob(void *, ndr_xa_t *);
static int spoolss_s_GetJob(void *, ndr_xa_t *);
static int spoolss_s_EnumJobs(void *, ndr_xa_t *);
static int spoolss_s_ScheduleJob(void *, ndr_xa_t *);
static int spoolss_s_StartDocPrinter(void *, ndr_xa_t *);
static int spoolss_s_EndDocPrinter(void *, ndr_xa_t *);
static int spoolss_s_StartPagePrinter(void *, ndr_xa_t *);
static int spoolss_s_EndPagePrinter(void *, ndr_xa_t *);
static int spoolss_s_rfnpcnex(void *, ndr_xa_t *);
static int spoolss_s_WritePrinter(void *, ndr_xa_t *);
static int spoolss_s_AddForm(void *, ndr_xa_t *);
static int spoolss_s_DeleteForm(void *, ndr_xa_t *);
static int spoolss_s_EnumForms(void *, ndr_xa_t *);
static int spoolss_s_AddMonitor(void *, ndr_xa_t *);
static int spoolss_s_DeleteMonitor(void *, ndr_xa_t *);
static int spoolss_s_DeletePort(void *, ndr_xa_t *);
static int spoolss_s_AddPortEx(void *, ndr_xa_t *);
static int spoolss_s_SetPort(void *, ndr_xa_t *);
static int spoolss_s_stub(void *, ndr_xa_t *);

static ndr_stub_table_t spoolss_stub_table[] = {
	{ spoolss_s_GetJob,		SPOOLSS_OPNUM_GetJob },
	{ spoolss_s_EnumJobs,		SPOOLSS_OPNUM_EnumJobs },
	{ spoolss_s_stub, SPOOLSS_OPNUM_DeletePrinter },
	{ spoolss_s_GetPrinter,		SPOOLSS_OPNUM_GetPrinter },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_GetPrinterDriver },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_DeletePrinterDriver },
	{ spoolss_s_OpenPrinter,	SPOOLSS_OPNUM_OpenPrinter },
	{ spoolss_s_StartDocPrinter,	SPOOLSS_OPNUM_StartDocPrinter },
	{ spoolss_s_WritePrinter,	SPOOLSS_OPNUM_WritePrinter },
	{ spoolss_s_EndDocPrinter,	SPOOLSS_OPNUM_EndDocPrinter },
	{ spoolss_s_StartPagePrinter,	SPOOLSS_OPNUM_StartPagePrinter },
	{ spoolss_s_EndPagePrinter,	SPOOLSS_OPNUM_EndPagePrinter },
	{ spoolss_s_AbortPrinter,	SPOOLSS_OPNUM_AbortPrinter },
	{ spoolss_s_ResetPrinter,	SPOOLSS_OPNUM_ResetPrinter },
	{ spoolss_s_AddJob,		SPOOLSS_OPNUM_AddJob },
	{ spoolss_s_ScheduleJob,    	SPOOLSS_OPNUM_ScheduleJob },
	{ spoolss_s_GetPrinterData,	SPOOLSS_OPNUM_GetPrinterData },
	{ spoolss_s_ClosePrinter,	SPOOLSS_OPNUM_ClosePrinter },
	{ spoolss_s_AddForm,		SPOOLSS_OPNUM_AddForm },
	{ spoolss_s_DeleteForm,		SPOOLSS_OPNUM_DeleteForm },
	{ spoolss_s_EnumForms,		SPOOLSS_OPNUM_EnumForms },
	{ spoolss_s_AddMonitor,		SPOOLSS_OPNUM_AddMonitor },
	{ spoolss_s_DeleteMonitor,	SPOOLSS_OPNUM_DeleteMonitor },
	{ spoolss_s_DeletePort,		SPOOLSS_OPNUM_DeletePort },
	{ spoolss_s_AddPortEx,		SPOOLSS_OPNUM_AddPortEx },
	{ spoolss_s_SetPort,		SPOOLSS_OPNUM_SetPort },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_GetPrinterDriver2 },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_FCPN },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_ReplyOpenPrinter },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_ReplyClosePrinter },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_RFFPCNEX },
	{ spoolss_s_rfnpcnex,		SPOOLSS_OPNUM_RFNPCNEX },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_RRPCN },
	{ spoolss_s_OpenPrinter,	SPOOLSS_OPNUM_OpenPrinterEx },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_EnumPrinterData },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_EnumPrinterDataEx },
	{ spoolss_s_stub,		SPOOLSS_OPNUM_EnumPrinterKey },
	{0}
};

static ndr_service_t spoolss_service = {
	"SPOOLSS",			/* name */
	"Print Spool Service",		/* desc */
	"\\spoolss",			/* endpoint */
	PIPE_SPOOLSS,			/* sec_addr_port */
	"12345678-1234-abcd-ef00-0123456789ab",	1,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(spoolss_interface),	/* interface ti */
	spoolss_stub_table		/* stub_table */
};

void
spoolss_initialize(void)
{
	if (!spoolss_splist.sp_initialized) {
		list_create(&spoolss_splist.sp_list,
		    sizeof (smb_spooldoc_t),
		    offsetof(smb_spooldoc_t, sd_lnd));
		spoolss_splist.sp_initialized = 1;
	}

	spoolss_copyfile_callback = NULL;

	(void) ndr_svc_register(&spoolss_service);
}

void
spoolss_finalize(void)
{
	spoolss_copyfile_callback = NULL;
}

/*
 * Register a copyfile callback that the spoolss service can use to
 * copy files to the spool directory.
 *
 * Set a null pointer to disable the copying of files to the spool
 * directory.
 */
void
spoolss_register_copyfile(spoolss_copyfile_t copyfile)
{
	spoolss_copyfile_callback = copyfile;
}

static void
spoolss_copyfile(smb_inaddr_t *ipaddr, char *username, char *path,
    char *docname)
{
	if (spoolss_copyfile_callback != NULL)
		(*spoolss_copyfile_callback)(ipaddr, username, path, docname);
}

static int
spoolss_s_OpenPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_OpenPrinter *param = arg;
	char		*name = (char *)param->printer_name;
	ndr_hdid_t	*id;

	if (name != NULL && *name != '\0') {
		if (strspn(name, "\\") > 2) {
			bzero(&param->handle, sizeof (spoolss_handle_t));
			param->status = ERROR_INVALID_PRINTER_NAME;
			return (NDR_DRC_OK);
		}

		smb_tracef("spoolss_s_OpenPrinter: %s", name);
	}

	if ((id = ndr_hdalloc(mxa, NULL)) == NULL) {
		bzero(&param->handle, sizeof (spoolss_handle_t));
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	bcopy(id, &param->handle, sizeof (spoolss_handle_t));
	param->status = 0;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_StartPagePrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_StartPagePrinter *param = arg;

	param->status = ERROR_SUCCESS;

	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_EndPagePrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_EndPagePrinter *param = arg;

	param->status = ERROR_SUCCESS;

	return (NDR_DRC_OK);
}

/*
 * Windows XP and 2000 use this mechanism to write spool files.
 * Create a spool file fd to be used by spoolss_s_WritePrinter
 * and add it to the tail of the spool list.
 */
static int
spoolss_s_StartDocPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_StartDocPrinter *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	smb_spooldoc_t *spfile;
	spoolss_DocInfo_t *docinfo;
	char g_path[MAXPATHLEN];
	smb_share_t si;
	int rc;
	int fd;

	if (ndr_hdlookup(mxa, id) == NULL) {
		smb_tracef("spoolss_s_StartDocPrinter: invalid handle");
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	if ((docinfo = param->dinfo.DocInfoContainer) == NULL) {
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	if ((rc = smb_shr_get(SMB_SHARE_PRINT, &si)) != NERR_Success) {
		smb_tracef("spoolss_s_StartDocPrinter: %s error=%d",
		    SMB_SHARE_PRINT, rc);
		param->status = rc;
		return (NDR_DRC_OK);
	}

	if ((spfile = calloc(1, sizeof (smb_spooldoc_t))) == NULL) {
		param->status = ERROR_NOT_ENOUGH_MEMORY;
		return (NDR_DRC_OK);
	}

	if (docinfo->doc_name != NULL)
		(void) strlcpy(spfile->sd_doc_name,
		    (char *)docinfo->doc_name, MAXNAMELEN);
	else
		(void) strlcpy(spfile->sd_doc_name, "document", MAXNAMELEN);

	if (docinfo->printer_name != NULL)
		(void) strlcpy(spfile->sd_printer_name,
		    (char *)docinfo->printer_name, MAXPATHLEN);
	else
		(void) strlcpy(spfile->sd_printer_name, "printer", MAXPATHLEN);

	spfile->sd_ipaddr = mxa->pipe->np_user->ui_ipaddr;
	(void) strlcpy((char *)spfile->sd_username,
	    mxa->pipe->np_user->ui_account, MAXNAMELEN);
	(void) memcpy(&spfile->sd_handle, &param->handle, sizeof (ndr_hdid_t));

	/*
	 *	write temporary spool file to print$
	 */
	(void) snprintf(g_path, MAXPATHLEN, "%s/%s%d", si.shr_path,
	    spfile->sd_username, spoolss_cnt);
	atomic_inc_32(&spoolss_cnt);

	fd = open(g_path, O_CREAT | O_RDWR, 0600);
	if (fd == -1) {
		smb_tracef("spoolss_s_StartDocPrinter: %s: %s",
		    g_path, strerror(errno));
		param->status = ERROR_OPEN_FAILED;
		free(spfile);
	} else {
		(void) strlcpy((char *)spfile->sd_path, g_path, MAXPATHLEN);
		spfile->sd_fd = (uint16_t)fd;

		/*
		 * Add the document to the spool list.
		 */
		(void) rw_wrlock(&spoolss_splist.sp_rwl);
		list_insert_tail(&spoolss_splist.sp_list, spfile);
		spoolss_splist.sp_cnt++;
		(void) rw_unlock(&spoolss_splist.sp_rwl);

		/*
		 * JobId isn't used now, but if printQ management is added
		 * this will have to be incremented per job submitted.
		 */
		param->JobId = 46;
		param->status = ERROR_SUCCESS;
	}
	return (NDR_DRC_OK);
}

/*
 * Windows XP and 2000 use this mechanism to write spool files
 * Search the spooldoc list for a matching RPC handle and pass
 * the spool the file for printing.
 */
static int
spoolss_s_EndDocPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_EndDocPrinter *param = arg;
	ndr_hdid_t	*id = (ndr_hdid_t *)&param->handle;
	smb_spooldoc_t	*sp;

	if (ndr_hdlookup(mxa, id) == NULL) {
		smb_tracef("spoolss_s_EndDocPrinter: invalid handle");
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	param->status = ERROR_INVALID_HANDLE;
	(void) rw_wrlock(&spoolss_splist.sp_rwl);

	sp = list_head(&spoolss_splist.sp_list);
	while (sp != NULL) {
		if (!memcmp(id, &(sp->sd_handle), sizeof (ndr_hdid_t))) {
			spoolss_copyfile(&sp->sd_ipaddr,
			    sp->sd_username, sp->sd_path, sp->sd_doc_name);
			(void) close(sp->sd_fd);
			list_remove(&spoolss_splist.sp_list, sp);
			free(sp);
			param->status = ERROR_SUCCESS;
			break;
		}

		sp = list_next(&spoolss_splist.sp_list, sp);
	}

	(void) rw_unlock(&spoolss_splist.sp_rwl);

	if (param->status != ERROR_SUCCESS)
		smb_tracef("spoolss_s_EndDocPrinter: document not found");
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_AbortPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_AbortPrinter *param = arg;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_ResetPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_AbortPrinter *param = arg;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

static int
spoolss_s_ClosePrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_ClosePrinter *param = arg;
	ndr_hdid_t	*id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t	*hd;

	if ((hd = ndr_hdlookup(mxa, id)) != NULL) {
		free(hd->nh_data);
		hd->nh_data = NULL;
	}

	ndr_hdfree(mxa, id);
	bzero(&param->result_handle, sizeof (spoolss_handle_t));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

static int
spoolss_s_AddForm(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_AddForm *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	if (ndr_hdlookup(mxa, id) == NULL) {
		bzero(param, sizeof (struct spoolss_AddForm));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	bzero(param, sizeof (struct spoolss_AddForm));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

static int
spoolss_s_DeleteForm(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_DeleteForm *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	if (ndr_hdlookup(mxa, id) == NULL) {
		bzero(param, sizeof (struct spoolss_DeleteForm));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	bzero(param, sizeof (struct spoolss_DeleteForm));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

static int
spoolss_s_EnumForms(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_EnumForms *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;

	if (ndr_hdlookup(mxa, id) == NULL) {
		bzero(param, sizeof (struct spoolss_EnumForms));
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	bzero(param, sizeof (struct spoolss_EnumForms));
	param->status = ERROR_SUCCESS;
	param->needed = 0;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_AddMonitor(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_AddMonitor *param = arg;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_DeleteMonitor(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_DeleteMonitor *param = arg;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_DeletePort(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_DeletePort *param = arg;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_AddPortEx(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_AddPortEx *param = arg;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_SetPort(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_SetPort *param = arg;

	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_EnumJobs(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_EnumJobs *param = arg;
	DWORD status = ERROR_SUCCESS;

	switch (param->level) {
	case 1:
	case 2:
	case 3:
	case 4:
	default:
		break;
	}

	param->status = status;
	param->needed = 0;
	param->needed2 = 0;
	return (NDR_DRC_OK);
}


/*ARGSUSED*/
static int
spoolss_s_GetJob(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_GetJob *param = arg;
	DWORD status = ERROR_SUCCESS;

	if (param->BufCount == 0)
		param->status = ERROR_INSUFFICIENT_BUFFER;
	else
		param->status = status;
	param->needed = 0;
	return (NDR_DRC_OK);
}


/*ARGSUSED*/
static int
spoolss_s_ScheduleJob(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_ScheduleJob *param = arg;
	DWORD status = ERROR_SPL_NO_ADDJOB;

	param->status = status;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_AddJob(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_AddJob *param = arg;

	param->status = ERROR_SUCCESS;
	param->needed = 0;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
static int
spoolss_s_rfnpcnex(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_RFNPCNEX *param = arg;

	param->ppinfo = 0;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * Use the RPC context handle to find the fd and write the document content.
 */
static int
spoolss_s_WritePrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_WritePrinter *param = arg;
	int written = 0;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	int spfd;

	if (ndr_hdlookup(mxa, id) == NULL) {
		param->written = 0;
		param->status = ERROR_INVALID_HANDLE;
		smb_tracef("spoolss_s_WritePrinter: invalid handle");
		return (NDR_DRC_OK);
	}

	if ((spfd = spoolss_find_document(id)) < 0) {
		param->written = 0;
		param->status = ERROR_INVALID_HANDLE;
		smb_tracef("spoolss_s_WritePrinter: document not found");
		return (NDR_DRC_OK);
	}

	written = write(spfd, param->pBuf, param->BufCount);
	if (written < param->BufCount) {
		smb_tracef("spoolss_s_WritePrinter: write failed");
		param->written = 0;
		param->status = ERROR_CANTWRITE;
		return (NDR_DRC_OK);
	}

	param->written = written;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * Find a document by RPC handle in the spool list and return the fd.
 */
static int
spoolss_find_document(ndr_hdid_t *handle)
{
	smb_spooldoc_t *sp;

	(void) rw_rdlock(&spoolss_splist.sp_rwl);

	sp = list_head(&spoolss_splist.sp_list);
	while (sp != NULL) {
		if (!memcmp(handle, &(sp->sd_handle), sizeof (ndr_hdid_t))) {
			(void) rw_unlock(&spoolss_splist.sp_rwl);
			return (sp->sd_fd);
		}
		sp = list_next(&spoolss_splist.sp_list, sp);
	}

	(void) rw_unlock(&spoolss_splist.sp_rwl);
	return (-1);
}

/*
 * GetPrinterData is used t obtain values from the registry for a
 * printer or a print server.  See [MS-RPRN] for value descriptions.
 * The registry returns ERROR_FILE_NOT_FOUND for unknown keys.
 */
static int
spoolss_s_GetPrinterData(void *arg, ndr_xa_t *mxa)
{
	static spoolss_winreg_t	reg[] = {
		{ "ChangeId",			0x0050acf2 },
		{ "W3SvcInstalled",		0x00000000 },
		{ "BeepEnabled",		0x00000000 },
		{ "EventLog",			0x0000001f },
		{ "NetPopup",			0x00000000 },
		{ "NetPopupToComputer",		0x00000000 },
		{ "MajorVersion",		0x00000003 },
		{ "MinorVersion",		0x00000000 },
		{ "DsPresent",			0x00000000 }
	};

	struct spoolss_GetPrinterData *param = arg;
	char			*name = (char *)param->pValueName;
	char			buf[MAXPATHLEN];
	static uint8_t		reserved_buf[4];
	spoolss_winreg_t	*rp;
	smb_share_t		si;
	smb_version_t		*osversion;
	struct utsname		sysname;
	smb_wchar_t		*wcs;
	uint32_t		value;
	uint32_t		status;
	int			wcslen;
	int			i;

	if (name == NULL || *name == '\0') {
		status = ERROR_FILE_NOT_FOUND;
		goto report_error;
	}

	for (i = 0; i < sizeof (reg) / sizeof (reg[0]); ++i) {
		param->pType = WINREG_DWORD;
		param->Needed = sizeof (uint32_t);
		rp = &reg[i];

		if (strcasecmp(name, rp->name) != 0)
			continue;

		if (param->Size < sizeof (uint32_t)) {
			param->Size = 0;
			goto need_more_data;
		}

		if ((param->Buf = NDR_NEW(mxa, uint32_t)) == NULL) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			goto report_error;
		}

		value = rp->value;

		if ((strcasecmp(name, "DsPresent") == 0) &&
		    (smb_config_get_secmode() == SMB_SECMODE_DOMAIN))
			value = 0x00000001;

		bcopy(&value, param->Buf, sizeof (uint32_t));
		param->Size = sizeof (uint32_t);
		param->status = ERROR_SUCCESS;
		return (NDR_DRC_OK);
	}

	if (strcasecmp(name, "OSVersion") == 0) {
		param->pType = WINREG_BINARY;
		param->Needed = sizeof (smb_version_t);

		if (param->Size < sizeof (smb_version_t)) {
			param->Size = sizeof (smb_version_t);
			goto need_more_data;
		}

		if ((osversion = NDR_NEW(mxa, smb_version_t)) == NULL) {
			status = ERROR_NOT_ENOUGH_MEMORY;
			goto report_error;
		}

		smb_config_get_version(osversion);
		param->Buf = (uint8_t *)osversion;
		param->status = ERROR_SUCCESS;
		return (NDR_DRC_OK);
	}

	if (strcasecmp(name, "DNSMachineName") == 0) {
		param->pType = WINREG_SZ;
		buf[0] = '\0';
		(void) smb_getfqhostname(buf, MAXHOSTNAMELEN);
		goto encode_string;
	}

	if (strcasecmp(name, "DefaultSpoolDirectory") == 0) {
		param->pType = WINREG_SZ;
		buf[0] = '\0';

		if (smb_shr_get(SMB_SHARE_PRINT, &si) != NERR_Success) {
			status = ERROR_FILE_NOT_FOUND;
			goto report_error;
		}

		(void) snprintf(buf, MAXPATHLEN, "C:/%s", si.shr_path);
		(void) strcanon(buf, "/\\");
		(void) strsubst(buf, '/', '\\');
		goto encode_string;
	}

	if (strcasecmp(name, "Architecture") == 0) {
		param->pType = WINREG_SZ;

		if (uname(&sysname) < 0)
			(void) strlcpy(buf, "Solaris", MAXPATHLEN);
		else
			(void) snprintf(buf, MAXPATHLEN, "%s %s",
			    sysname.sysname, sysname.machine);

		goto encode_string;
	}

	status = ERROR_FILE_NOT_FOUND;

report_error:
	bzero(param, sizeof (struct spoolss_GetPrinterData));
	param->Buf = reserved_buf;
	param->status = status;
	return (NDR_DRC_OK);

encode_string:
	wcslen = smb_wcequiv_strlen(buf) + sizeof (smb_wchar_t);
	if (param->Size < wcslen) {
		param->Needed = wcslen;
		goto need_more_data;
	}

	if ((wcs = NDR_MALLOC(mxa, wcslen)) == NULL) {
		status = ERROR_NOT_ENOUGH_MEMORY;
		goto report_error;
	}

	(void) ndr_mbstowcs(NULL, wcs, buf, wcslen);
	param->Buf = (uint8_t *)wcs;
	param->Needed = wcslen;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);

need_more_data:
	param->Size = 0;
	param->Buf = reserved_buf;
	param->status = ERROR_MORE_DATA;
	return (NDR_DRC_OK);
}

void
smb_rpc_off(char *dst, char *src, uint32_t *offset, uint32_t *outoffset)
{
	int nwchars;
	int bytes;

	bytes = smb_wcequiv_strlen(src) + 2;
	nwchars = strlen(src) + 1;
	*offset -= bytes;
	*outoffset = *offset;
	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	(void) smb_mbstowcs(((smb_wchar_t *)(dst + *offset)), src, nwchars);
}

int
spoolss_s_GetPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_GetPrinter	*param = arg;
	struct spoolss_GetPrinter0	*pinfo0;
	struct spoolss_GetPrinter1	*pinfo1;
	struct spoolss_GetPrinter2	*pinfo2;
	struct spoolss_DeviceMode	*devmode2;
	ndr_hdid_t	*id = (ndr_hdid_t *)&param->handle;
	spoolss_sd_t	secdesc;
	char		server[MAXNAMELEN];
	char		printer[MAXNAMELEN];
	DWORD		status = ERROR_SUCCESS;
	char		*wname;
	uint32_t	offset;
	uint8_t		*tmpbuf;

	if (ndr_hdlookup(mxa, id) == NULL) {
		status = ERROR_INVALID_HANDLE;
		goto error_out;
	}

	if (spoolss_getservername(server, MAXNAMELEN) != 0) {
		status = ERROR_INTERNAL_ERROR;
		goto error_out;
	}

	(void) snprintf(printer, MAXNAMELEN, "%s\\%s", server, SPOOLSS_PRINTER);

	switch (param->switch_value) {
	case 0:
	case 1:
		param->needed = 460;
		break;
	case 2:
		param->needed = 712;
		break;
	default:
		status = ERROR_INVALID_LEVEL;
		goto error_out;
	}

	if (param->BufCount < param->needed) {
		param->BufCount = 0;
		param->Buf = NULL;
		param->status = ERROR_INSUFFICIENT_BUFFER;
		return (NDR_DRC_OK);
	}

	if ((param->Buf = NDR_MALLOC(mxa, param->BufCount)) == NULL) {
		status = ERROR_NOT_ENOUGH_MEMORY;
		goto error_out;
	}

	bzero(param->Buf, param->BufCount);
	wname = (char *)param->Buf;
	offset = param->needed;

	switch (param->switch_value) {
	case 0:
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		pinfo0 = (struct spoolss_GetPrinter0 *)param->Buf;

		smb_rpc_off(wname, server, &offset, &pinfo0->servername);
		smb_rpc_off(wname, printer, &offset, &pinfo0->printername);
		pinfo0->cjobs = 0;
		pinfo0->total_jobs = 6;
		pinfo0->total_bytes = 1040771;
		pinfo0->time0 = 0;
		pinfo0->time1 = 0;
		pinfo0->time2 = 3;
		pinfo0->time3 = 0;
		pinfo0->global_counter = 2162710;
		pinfo0->total_pages = 21495865;
		pinfo0->version = 10;
		pinfo0->session_counter = 1;
		pinfo0->job_error = 0x6;
		pinfo0->change_id  = 0x1;
		pinfo0->status = 0;
		pinfo0->c_setprinter = 0;
		break;
	case 1:
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		pinfo1 = (struct spoolss_GetPrinter1 *)param->Buf;

		pinfo1->flags = PRINTER_ENUM_ICON8;
		smb_rpc_off(wname, printer, &offset, &pinfo1->flags);
		smb_rpc_off(wname, printer, &offset, &pinfo1->description);
		smb_rpc_off(wname, printer, &offset, &pinfo1->comment);
		break;
	case 2:
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		pinfo2 = (struct spoolss_GetPrinter2 *)param->Buf;

		smb_rpc_off(wname, server, &offset, &pinfo2->servername);
		smb_rpc_off(wname, printer, &offset, &pinfo2->printername);
		smb_rpc_off(wname, SPOOLSS_PRINTER, &offset,
		    &pinfo2->sharename);
		smb_rpc_off(wname, "CIFS Printer Port", &offset,
		    &pinfo2->portname);
		smb_rpc_off(wname, "", &offset, &pinfo2->drivername);
		smb_rpc_off(wname, SPOOLSS_PRINTER, &offset,
		    &pinfo2->comment);
		smb_rpc_off(wname, "farside", &offset, &pinfo2->location);

		offset -= sizeof (struct spoolss_DeviceMode);
		pinfo2->devmode = offset;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		devmode2 = (struct spoolss_DeviceMode *)(param->Buf + offset);

		smb_rpc_off(wname, "farside", &offset, &pinfo2->sepfile);
		smb_rpc_off(wname, "winprint", &offset,
		    &pinfo2->printprocessor);
		smb_rpc_off(wname, "RAW", &offset, &pinfo2->datatype);
		smb_rpc_off(wname, "", &offset, &pinfo2->parameters);

		status = spoolss_make_sd(mxa, &secdesc);
		if (status == ERROR_SUCCESS) {
			offset -= secdesc.sd_size;
			pinfo2->secdesc = offset;
			tmpbuf = (uint8_t *)(param->Buf + offset);
			bcopy(secdesc.sd_buf, tmpbuf, secdesc.sd_size);
		}

		pinfo2->attributes = 0x00001048;
		pinfo2->status = 0x00000000;
		pinfo2->starttime = 0;
		pinfo2->untiltime = 0;
		pinfo2->cjobs = 0;
		pinfo2->averageppm = 0;
		pinfo2->defaultpriority = 0;

		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		(void) smb_mbstowcs((smb_wchar_t *)devmode2->devicename,
		    printer, 32);
		devmode2->specversion = 0x0401;
		devmode2->driverversion = 1024;
		devmode2->size = 220;
		devmode2->driverextra_length = 0;
		devmode2->fields = 0x00014713;
		devmode2->orientation = 1;
		devmode2->papersize = 1;
		devmode2->paperlength = 0;
		devmode2->paperwidth = 0;
		devmode2->scale = 100;
		devmode2->copies = 1;
		devmode2->defaultsource = 15;
		devmode2->printquality = 65532;
		devmode2->color = 1;
		devmode2->duplex = 1;
		devmode2->yresolution = 1;
		devmode2->ttoption = 1;
		devmode2->collate = 0;
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		(void) smb_mbstowcs((smb_wchar_t *)devmode2->formname,
		    "Letter", 32);
		devmode2->logpixels = 0;
		devmode2->bitsperpel = 0;
		devmode2->pelswidth = 0;
		devmode2->pelsheight = 0;
		devmode2->displayflags = 0;
		devmode2->displayfrequency = 0;
		devmode2->icmmethod = 0;
		devmode2->icmintent = 0;
		devmode2->mediatype = 0;
		devmode2->dithertype = 0;
		devmode2->reserved1 = 0;
		devmode2->reserved2 = 0;
		devmode2->panningwidth = 0;
		devmode2->panningheight = 0;
		break;

	default:
		break;
	}

	param->status = status;
	return (NDR_DRC_OK);

error_out:
	smb_tracef("spoolss_s_GetPrinter: error %u", status);
	bzero(param, sizeof (struct spoolss_GetPrinter));
	param->status = status;
	return (NDR_DRC_OK);
}

static int
spoolss_getservername(char *name, size_t namelen)
{
	char		hostname[MAXHOSTNAMELEN];
	char		ipstr[INET6_ADDRSTRLEN];
	smb_inaddr_t	ipaddr;
	struct hostent	*h;
	const char	*p;
	int		error;

	if (smb_gethostname(hostname, MAXHOSTNAMELEN, 0) != 0) {
		smb_tracef("spoolss_s_GetPrinter: gethostname failed");
		return (-1);
	}

	if ((h = smb_gethostbyname(hostname, &error)) == NULL) {
		smb_tracef("spoolss_s_GetPrinter: gethostbyname failed: %d",
		    error);
		return (-1);
	}

	bcopy(h->h_addr, &ipaddr, h->h_length);
	ipaddr.a_family = h->h_addrtype;
	freehostent(h);

	p = smb_inet_ntop(&ipaddr, ipstr, SMB_IPSTRLEN(ipaddr.a_family));
	if (p == NULL) {
		smb_tracef("spoolss_s_GetPrinter: inet_ntop failed");
		return (-1);
	}

	(void) snprintf(name, namelen, "\\\\%s", ipstr);
	return (0);
}

static uint32_t
spoolss_make_sd(ndr_xa_t *mxa, spoolss_sd_t *secdesc)
{
	smb_sd_t	sd;
	uint8_t		*sd_buf;
	uint32_t	sd_len;
	uint32_t	status;

	bzero(&sd, sizeof (smb_sd_t));

	if ((status = spoolss_format_sd(&sd)) != ERROR_SUCCESS)
		return (status);

	sd_len = smb_sd_len(&sd, SMB_ALL_SECINFO);

	if ((sd_buf = NDR_MALLOC(mxa, sd_len)) == NULL)
		return (ERROR_NOT_ENOUGH_MEMORY);

	secdesc->sd_buf = sd_buf;
	secdesc->sd_size = sd_len;

	status = srvsvc_sd_set_relative(&sd, sd_buf);
	smb_sd_term(&sd);
	return (status);
}

static uint32_t
spoolss_format_sd(smb_sd_t *sd)
{
	smb_fssd_t	fs_sd;
	acl_t		*acl;
	uint32_t	status = ERROR_SUCCESS;

	if (acl_fromtext("everyone@:full_set::allow", &acl) != 0) {
		smb_tracef("spoolss_format_sd: NOT_ENOUGH_MEMORY");
		return (ERROR_NOT_ENOUGH_MEMORY);
	}
	smb_fssd_init(&fs_sd, SMB_ALL_SECINFO, SMB_FSSD_FLAGS_DIR);
	fs_sd.sd_uid = 0;
	fs_sd.sd_gid = 0;
	fs_sd.sd_zdacl = acl;
	fs_sd.sd_zsacl = NULL;

	status = smb_sd_fromfs(&fs_sd, sd);
	if (status != NT_STATUS_SUCCESS) {
		smb_tracef("spoolss_format_sd: %u", status);
		status = ERROR_ACCESS_DENIED;
	}
	smb_fssd_term(&fs_sd);
	return (status);
}

/*ARGSUSED*/
static int
spoolss_s_stub(void *arg, ndr_xa_t *mxa)
{
	return (NDR_DRC_FAULT_PARAM_0_UNIMPLEMENTED);
}

void
fixup_spoolss_RFNPCNEX(struct spoolss_RFNPCNEX *val)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;
	struct spoolss_RPC_V2_NOTIFY_INFO *pinfo;

	pinfo = val->ppinfo->pinfo;
	switch (pinfo->aData->Reserved) {
	case TABLE_STRING:
		size1 = sizeof (struct STRING_CONTAINER);
		break;
	case TABLE_DWORD:
		size1 = sizeof (DWORD) * 2;
		break;
	case TABLE_TIME:
		size1 = sizeof (struct SYSTEMTIME_CONTAINER);
		break;
	case TABLE_DEVMODE:
		size1 = sizeof (struct spoolssDevmodeContainer);
		break;
	case TABLE_SECURITY_DESCRIPTOR:
		size1 = sizeof (struct SECURITY_CONTAINER);
		break;
	default:
		return;
	}
	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (ndr_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(spoolss_RPC_V2_NOTIFY_INFO_DATA_DATA, size1);
	FIXUP_PDU_SIZE(spoolss_RPC_V2_NOTIFY_INFO_DATA, size2);
	FIXUP_PDU_SIZE(spoolss_RPC_V2_NOTIFY_INFO, size3);
	FIXUP_PDU_SIZE(spoolss_RFNPCNEX, size3);
}

void
fixup_spoolss_GetPrinter(struct spoolss_GetPrinter *val)
{
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;

	switch (val->switch_value) {
	CASE_INFO_ENT(spoolss_GetPrinter, 0);
	CASE_INFO_ENT(spoolss_GetPrinter, 1);
	CASE_INFO_ENT(spoolss_GetPrinter, 2);
	CASE_INFO_ENT(spoolss_GetPrinter, 3);
	CASE_INFO_ENT(spoolss_GetPrinter, 4);
	CASE_INFO_ENT(spoolss_GetPrinter, 5);
	CASE_INFO_ENT(spoolss_GetPrinter, 6);
	CASE_INFO_ENT(spoolss_GetPrinter, 7);
	CASE_INFO_ENT(spoolss_GetPrinter, 8);

	default:
		return;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (ndr_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(spoolss_GetPrinter_result_u, size1);
	FIXUP_PDU_SIZE(spoolss_GetPrinter_result, size2);
	FIXUP_PDU_SIZE(spoolss_GetPrinter, size3);
}

#else	/* HAVE_CUPS */

/*
 * If not HAVE_CUPS, just provide a few "stubs".
 */

void
spoolss_initialize(void)
{
}

void
spoolss_finalize(void)
{
}

/*ARGSUSED*/
void
spoolss_register_copyfile(spoolss_copyfile_t copyfile)
{
}

#endif 	/* HAVE_CUPS */
