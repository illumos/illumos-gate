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
 */

/*
 * Printing and Spooling RPC service.
 */
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <pthread.h>
#include <synch.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/ndrtypes.ndl>
#include <smbsrv/ndl/spoolss.ndl>
#include <smb/nterror.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/nmpipes.h>
#include <wchar.h>
#include <cups/cups.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <dlfcn.h>
#include <mlsvc.h>

typedef struct smb_spool {
	list_t sp_list;
	int sp_cnt;
	rwlock_t sp_rwl;
	int sp_initialized;
} smb_spool_t;

static uint32_t spoolss_cnt;
static uint32_t spoolss_jobnum = 1;
static smb_spool_t spoolss_splist;
static smb_cups_ops_t smb_cups;
static mutex_t spoolss_cups_mutex;

#define	SPOOLSS_PJOBLEN		256
#define	SPOOLSS_JOB_NOT_ISSUED	3004
#define	SPOOLSS_PRINTER		"Postscript"
#define	SPOOLSS_FN_PREFIX	"cifsprintjob-"
#define	SPOOLSS_CUPS_SPOOL_DIR	"//var//spool//cups"

struct spoolss_printjob {
	pid_t pj_pid;
	int pj_sysjob;
	int pj_fd;
	time_t pj_start_time;
	int pj_status;
	size_t pj_size;
	int pj_page_count;
	boolean_t pj_isspooled;
	boolean_t pj_jobnum;
	char pj_filename[SPOOLSS_PJOBLEN];
	char pj_jobname[SPOOLSS_PJOBLEN];
	char pj_username[SPOOLSS_PJOBLEN];
	char pj_queuename[SPOOLSS_PJOBLEN];
};

DECL_FIXUP_STRUCT(spoolss_GetPrinter_result_u);
DECL_FIXUP_STRUCT(spoolss_GetPrinter_result);
DECL_FIXUP_STRUCT(spoolss_GetPrinter);

DECL_FIXUP_STRUCT(spoolss_RPC_V2_NOTIFY_INFO_DATA_DATA);
DECL_FIXUP_STRUCT(spoolss_RPC_V2_NOTIFY_INFO_DATA);
DECL_FIXUP_STRUCT(spoolss_RPC_V2_NOTIFY_INFO);
DECL_FIXUP_STRUCT(spoolss_RFNPCNEX);

uint32_t srvsvc_sd_set_relative(smb_sd_t *, uint8_t *);
static int spoolss_s_make_sd(uint8_t *);
static uint32_t spoolss_sd_format(smb_sd_t *);
static int spoolss_find_fd(ndr_hdid_t *);
static void spoolss_find_doc_and_print(ndr_hdid_t *);
static void spoolss_add_spool_doc(smb_spooldoc_t *);
static int spoolss_cups_init(void);
static void spoolss_cups_fini(void);

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
static int spoolss_s_EnumForms(void *, ndr_xa_t *);
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
	{ spoolss_s_EnumForms,		SPOOLSS_OPNUM_EnumForms },
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
	(void) ndr_svc_register(&spoolss_service);
	(void) spoolss_cups_init();
}

void
spoolss_finalize(void)
{
	spoolss_cups_fini();
}

static int
spoolss_s_OpenPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_OpenPrinter *param = arg;
	ndr_hdid_t *id;

	if ((id = ndr_hdalloc(mxa, 0)) == NULL) {
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
 *
 * adds new spool doc to the tail.  used by windows
 * XP and 2000 only
 *
 * Return values
 *      smb_spooldoc_t - NULL if not found
 */

static void
spoolss_add_spool_doc(smb_spooldoc_t *sp)
{
	(void) rw_wrlock(&spoolss_splist.sp_rwl);
	if (!spoolss_splist.sp_initialized) {
		list_create(&spoolss_splist.sp_list,
		    sizeof (smb_spooldoc_t),
		    offsetof(smb_spooldoc_t, sd_lnd));
		spoolss_splist.sp_initialized = 1;
	}
	list_insert_tail(&spoolss_splist.sp_list, sp);
	spoolss_splist.sp_cnt++;
	(void) rw_unlock(&spoolss_splist.sp_rwl);
}

/*
 *
 * finds a completed spool doc using the RPC handle
 * as the key, then prints the doc
 *
 * XP and 2000 only
 *
 */

static void
spoolss_find_doc_and_print(ndr_hdid_t *handle)
{
	smb_spooldoc_t *sp;

	if (!spoolss_splist.sp_initialized) {
		syslog(LOG_ERR, "spoolss_find_doc_and_print: not initialized");
		return;
	}
	(void) rw_wrlock(&spoolss_splist.sp_rwl);
	sp = list_head(&spoolss_splist.sp_list);
	while (sp != NULL) {
		/*
		 * search the spooldoc list for a matching RPC handle
		 * and use the info to pass to cups for printing
		 */
		if (!memcmp(handle, &(sp->sd_handle), sizeof (ndr_hdid_t))) {
			spoolss_copy_spool_file(&sp->sd_ipaddr,
			    sp->sd_username, sp->sd_path, sp->sd_doc_name);
			(void) close(sp->sd_fd);
			list_remove(&spoolss_splist.sp_list, sp);
			free(sp);
			(void) rw_unlock(&spoolss_splist.sp_rwl);
			return;
		}
		sp = list_next(&spoolss_splist.sp_list, sp);
	}
	syslog(LOG_ERR, "spoolss_find_doc_and_print: handle not found");
	(void) rw_unlock(&spoolss_splist.sp_rwl);
}

static int
spoolss_find_fd(ndr_hdid_t *handle)
{
	smb_spooldoc_t *sp;

	if (!spoolss_splist.sp_initialized) {
		syslog(LOG_ERR, "spoolss_find_fd: not initialized");
		return (-1);
	}
	(void) rw_rdlock(&spoolss_splist.sp_rwl);
	sp = list_head(&spoolss_splist.sp_list);
	while (sp != NULL) {
		/*
		 * check for a matching rpc handle in the
		 * spooldoc list
		 */
		if (!memcmp(handle, &(sp->sd_handle), sizeof (ndr_hdid_t))) {
			(void) rw_unlock(&spoolss_splist.sp_rwl);
			return (sp->sd_fd);
		}
		sp = list_next(&spoolss_splist.sp_list, sp);
	}
	syslog(LOG_ERR, "spoolss_find_fd: handle not found");
	(void) rw_unlock(&spoolss_splist.sp_rwl);
	return (-1);
}

/*
 * Windows XP and 2000 use this mechanism to write spool files.
 * Creates a spool file fd to be used by spoolss_s_WritePrinter.
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
		syslog(LOG_ERR, "spoolss_s_StartDocPrinter: invalid handle");
		param->status = ERROR_INVALID_HANDLE;
		return (NDR_DRC_OK);
	}

	if ((docinfo = param->dinfo.DocInfoContainer) == NULL) {
		param->status = ERROR_INVALID_PARAMETER;
		return (NDR_DRC_OK);
	}

	if ((rc = smb_shr_get(SMB_SHARE_PRINT, &si)) != NERR_Success) {
		syslog(LOG_INFO, "spoolss_s_StartDocPrinter: %s error=%d",
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

	spfile->sd_ipaddr = mxa->pipe->np_user.ui_ipaddr;
	(void) strlcpy((char *)spfile->sd_username,
	    mxa->pipe->np_user.ui_account, MAXNAMELEN);
	(void) memcpy(&spfile->sd_handle, &param->handle,
	    sizeof (rpc_handle_t));
	/*
	 *	write temporary spool file to print$
	 */
	(void) snprintf(g_path, MAXPATHLEN, "%s/%s%d", si.shr_path,
	    spfile->sd_username, spoolss_cnt);
	atomic_inc_32(&spoolss_cnt);

	fd = open(g_path, O_CREAT | O_RDWR, 0600);
	if (fd == -1) {
		syslog(LOG_INFO, "spoolss_s_StartDocPrinter: %s: %s",
		    g_path, strerror(errno));
		param->status = ERROR_OPEN_FAILED;
		free(spfile);
	} else {
		(void) strlcpy((char *)spfile->sd_path, g_path, MAXPATHLEN);
		spfile->sd_fd = (uint16_t)fd;
		spoolss_add_spool_doc(spfile);
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
 */

/*ARGSUSED*/
static int
spoolss_s_EndDocPrinter(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_EndDocPrinter *param = arg;

	spoolss_find_doc_and_print((ndr_hdid_t *)&param->handle);
	param->status = ERROR_SUCCESS;
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
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	if ((hd = ndr_hdlookup(mxa, id)) != NULL) {
		free(hd->nh_data);
		hd->nh_data = NULL;
	}

	ndr_hdfree(mxa, id);
	bzero(&param->result_handle, sizeof (spoolss_handle_t));
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
int
spoolss_s_EnumForms(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_EnumForms *param = arg;
	DWORD status = ERROR_SUCCESS;

	param->status = status;
	param->needed = 0;
	return (NDR_DRC_OK);
}

/*ARGSUSED*/
int
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
	DWORD status = SPOOLSS_JOB_NOT_ISSUED;

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
		syslog(LOG_ERR, "spoolss_s_WritePrinter: invalid handle");
		return (NDR_DRC_OK);
	}

	if ((spfd = spoolss_find_fd(id)) < 0) {
		param->written = 0;
		param->status = ERROR_INVALID_HANDLE;
		syslog(LOG_ERR, "spoolss_s_WritePrinter: cannot find fd");
		return (NDR_DRC_OK);
	}

	written = write(spfd, param->pBuf, param->BufCount);
	if (written < param->BufCount) {
		syslog(LOG_ERR, "spoolss_s_WritePrinter: write failed");
		param->written = 0;
		param->status = ERROR_CANTWRITE;
		return (NDR_DRC_OK);
	}

	param->written = written;
	param->status = ERROR_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * All versions of windows use this function to print
 * spool files via the cups interface
 */

void
spoolss_copy_spool_file(smb_inaddr_t *ipaddr, char *username,
    char *path, char *doc_name)
{
	smb_cups_ops_t	*cups;
	int		ret = 1;		/* Return value */
	http_t		*http = NULL;		/* HTTP connection to server */
	ipp_t		*request = NULL;	/* IPP Request */
	ipp_t		*response = NULL;	/* IPP Response */
	cups_lang_t	*language = NULL;	/* Default language */
	char		uri[HTTP_MAX_URI];	/* printer-uri attribute */
	char		new_jobname[SPOOLSS_PJOBLEN];
	struct		spoolss_printjob pjob;
	char 		clientname[INET6_ADDRSTRLEN];
	struct stat 	sbuf;

	if (stat(path, &sbuf)) {
		syslog(LOG_INFO, "spoolss_copy_spool_file: %s: %s",
		    path, strerror(errno));
		return;
	}

	/*
	 * Remove zero size files and return; these were inadvertantly
	 * created by XP or 2000.
	 */
	if (sbuf.st_blocks == 0) {
		if (remove(path))
			syslog(LOG_INFO,
			    "spoolss_copy_spool_file: cannot remove %s", path);
		return;
	}

	if ((cups = spoolss_cups_ops()) == NULL)
		return;

	if ((http = cups->httpConnect("localhost", 631)) == NULL) {
		syslog(LOG_INFO, "spoolss_copy_spool_file: cupsd not running");
		return;
	}

	if ((request = cups->ippNew()) == NULL) {
		syslog(LOG_INFO, "spoolss_copy_spool_file: ipp not running");
		return;
	}
	request->request.op.operation_id = IPP_PRINT_JOB;
	request->request.op.request_id = 1;
	language = cups->cupsLangDefault();

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_CHARSET,
	    "attributes-charset", NULL, cups->cupsLangEncoding(language));

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_LANGUAGE,
	    "attributes-natural-language", NULL, language->language);

	(void) snprintf(uri, sizeof (uri), "ipp://localhost/printers/%s",
	    SPOOLSS_PRINTER);
	pjob.pj_pid = pthread_self();
	pjob.pj_sysjob = 10;
	(void) strlcpy(pjob.pj_filename, path, SPOOLSS_PJOBLEN);
	pjob.pj_start_time = time(NULL);
	pjob.pj_status = 2;
	pjob.pj_size = sbuf.st_blocks * 512;
	pjob.pj_page_count = 1;
	pjob.pj_isspooled = B_TRUE;
	pjob.pj_jobnum = spoolss_jobnum;

	(void) strlcpy(pjob.pj_jobname, doc_name, SPOOLSS_PJOBLEN);
	(void) strlcpy(pjob.pj_username, username, SPOOLSS_PJOBLEN);
	(void) strlcpy(pjob.pj_queuename, SPOOLSS_CUPS_SPOOL_DIR,
	    SPOOLSS_PJOBLEN);
	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_URI,
	    "printer-uri", NULL, uri);

	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	    "requesting-user-name", NULL, pjob.pj_username);

	if (smb_inet_ntop(ipaddr, clientname,
	    SMB_IPSTRLEN(ipaddr->a_family)) == NULL) {
		syslog(LOG_INFO, "spoolss_copy_spool_file: %s: unknown client",
		    clientname);
		goto out;
	}
	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	    "job-originating-host-name", NULL, clientname);

	(void) snprintf(new_jobname, SPOOLSS_PJOBLEN, "%s%d",
	    SPOOLSS_FN_PREFIX, pjob.pj_jobnum);
	cups->ippAddString(request, IPP_TAG_OPERATION, IPP_TAG_NAME,
	    "job-name", NULL, new_jobname);

	(void) snprintf(uri, sizeof (uri) - 1, "/printers/%s", SPOOLSS_PRINTER);

	response = cups->cupsDoFileRequest(http, request, uri,
	    pjob.pj_filename);
	if (response != NULL) {
		if (response->request.status.status_code >= IPP_OK_CONFLICT) {
			syslog(LOG_ERR,
			    "spoolss_copy_spool_file: file print %s: %s",
			    SPOOLSS_PRINTER,
			    cups->ippErrorString(cups->cupsLastError()));
		} else {
			atomic_inc_32(&spoolss_jobnum);
			ret = 0;
		}
	} else {
		syslog(LOG_ERR,
		    "spoolss_copy_spool_file: unable to print file to %s",
		    cups->ippErrorString(cups->cupsLastError()));
	}

	if (ret == 0)
		(void) unlink(pjob.pj_filename);

out:
	if (response)
		cups->ippDelete(response);

	if (language)
		cups->cupsLangFree(language);

	if (http)
		cups->httpClose(http);
}

static int
spoolss_s_GetPrinterData(void *arg, ndr_xa_t *mxa)
{
	struct spoolss_GetPrinterData *param = arg;
	DWORD status = ERROR_SUCCESS;

	if (param->Size > 0) {
		param->Buf = NDR_NEWN(mxa, char, param->Size);
		bzero(param->Buf, param->Size);
	} else {
		param->Buf = NDR_NEWN(mxa, uint32_t, 1);
		param->Buf[0] = 1;
		param->Buf[1] = 1;
		param->Buf[2] = 2;
		param->Buf[3] = 2;
	}

	/*
	 * Increment pType if the Printer Data changes
	 * as specified by Microsoft documentation
	 */
	param->pType = 1;
	if (strcasecmp((char *)param->pValueName, "ChangeId") == 0) {
		param->pType = 4;
		param->Buf[3] = 0x00;
		param->Buf[2] = 0x50;
		param->Buf[1] = 0xac;
		param->Buf[0] = 0xf2;
	} else if (strcasecmp((char *)param->pValueName,
	    "UISingleJobStatusString") == 0) {
		status = ERROR_FILE_NOT_FOUND;
	} else if (strcasecmp((char *)param->pValueName,
	    "W3SvcInstalled") == 0) {
		status = ERROR_FILE_NOT_FOUND;
	} else if (strcasecmp((char *)param->pValueName,
	    "PrintProcCaps_NT EMF 1.008") == 0) {
		status = ERROR_FILE_NOT_FOUND;
	} else if (strcasecmp((char *)param->pValueName, "OSVersion") == 0) {
		param->Buf = NDR_NEWN(mxa, char, param->Size);
		bzero(param->Buf, param->Size);
		param->Buf[0] = 0x14;
		param->Buf[1] = 0x01;
		param->Buf[4] = 0x05;
		param->Buf[12] = 0x93;
		param->Buf[13] = 0x08;
	}
	param->status = status;
	param->Needed = param->Size;
	return (NDR_DRC_OK);
}

smb_cups_ops_t *
spoolss_cups_ops(void)
{
	if (spoolss_cups_init() != 0)
		return (NULL);

	return (&smb_cups);
}

static int
spoolss_cups_init(void)
{
	(void) mutex_lock(&spoolss_cups_mutex);

	if (smb_cups.cups_hdl != NULL) {
		(void) mutex_unlock(&spoolss_cups_mutex);
		return (0);
	}

	if ((smb_cups.cups_hdl = dlopen("libcups.so.2", RTLD_NOW)) == NULL) {
		(void) mutex_unlock(&spoolss_cups_mutex);
		syslog(LOG_DEBUG, "spoolss_cups_init: cannot open libcups");
		return (ENOENT);
	}

	smb_cups.cupsLangDefault =
	    (cups_lang_t *(*)())dlsym(smb_cups.cups_hdl, "cupsLangDefault");
	smb_cups.cupsLangEncoding = (const char *(*)(cups_lang_t *))
	    dlsym(smb_cups.cups_hdl, "cupsLangEncoding");
	smb_cups.cupsDoFileRequest =
	    (ipp_t *(*)(http_t *, ipp_t *, const char *, const char *))
	    dlsym(smb_cups.cups_hdl, "cupsDoFileRequest");
	smb_cups.cupsLastError = (ipp_status_t (*)())
	    dlsym(smb_cups.cups_hdl, "cupsLastError");
	smb_cups.cupsLangFree = (void (*)(cups_lang_t *))
	    dlsym(smb_cups.cups_hdl, "cupsLangFree");
	smb_cups.cupsGetDests = (int (*)(cups_dest_t **))
	    dlsym(smb_cups.cups_hdl, "cupsGetDests");
	smb_cups.cupsFreeDests = (void (*)(int, cups_dest_t *))
	    dlsym(smb_cups.cups_hdl, "cupsFreeDests");

	smb_cups.httpClose = (void (*)(http_t *))
	    dlsym(smb_cups.cups_hdl, "httpClose");
	smb_cups.httpConnect = (http_t *(*)(const char *, int))
	    dlsym(smb_cups.cups_hdl, "httpConnect");

	smb_cups.ippNew = (ipp_t *(*)())dlsym(smb_cups.cups_hdl, "ippNew");
	smb_cups.ippDelete = (void (*)())dlsym(smb_cups.cups_hdl, "ippDelete");
	smb_cups.ippErrorString = (char *(*)())
	    dlsym(smb_cups.cups_hdl, "ippErrorString");
	smb_cups.ippAddString = (ipp_attribute_t *(*)())
	    dlsym(smb_cups.cups_hdl, "ippAddString");

	if (smb_cups.cupsLangDefault == NULL ||
	    smb_cups.cupsLangEncoding == NULL ||
	    smb_cups.cupsDoFileRequest == NULL ||
	    smb_cups.cupsLastError == NULL ||
	    smb_cups.cupsLangFree == NULL ||
	    smb_cups.cupsGetDests == NULL ||
	    smb_cups.cupsFreeDests == NULL ||
	    smb_cups.ippNew == NULL ||
	    smb_cups.httpClose == NULL ||
	    smb_cups.httpConnect == NULL ||
	    smb_cups.ippDelete == NULL ||
	    smb_cups.ippErrorString == NULL ||
	    smb_cups.ippAddString == NULL) {
		smb_dlclose(smb_cups.cups_hdl);
		smb_cups.cups_hdl = NULL;
		(void) mutex_unlock(&spoolss_cups_mutex);
		syslog(LOG_DEBUG, "spoolss_cups_init: cannot load libcups");
		return (ENOENT);
	}

	(void) mutex_unlock(&spoolss_cups_mutex);
	return (0);
}

static void
spoolss_cups_fini(void)
{
	(void) mutex_lock(&spoolss_cups_mutex);

	if (smb_cups.cups_hdl != NULL) {
		smb_dlclose(smb_cups.cups_hdl);
		smb_cups.cups_hdl = NULL;
	}

	(void) mutex_unlock(&spoolss_cups_mutex);
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
	struct spoolss_GetPrinter *param = arg;
	struct spoolss_GetPrinter0 *pinfo0;
	struct spoolss_GetPrinter1 *pinfo1;
	struct spoolss_GetPrinter2 *pinfo2;
	struct spoolss_DeviceMode *devmode2;
	DWORD status = ERROR_SUCCESS;
	char *wname;
	uint32_t offset;
	smb_inaddr_t ipaddr;
	struct hostent *h;
	char hname[MAXHOSTNAMELEN];
	char soutbuf[MAXNAMELEN];
	char poutbuf[MAXNAMELEN];
	char ipstr[INET6_ADDRSTRLEN];
	int error;
	uint8_t *tmpbuf;

	if (param->BufCount == 0) {
		status = ERROR_INSUFFICIENT_BUFFER;
		goto error_out;
	}
	param->Buf = NDR_NEWN(mxa, char, param->BufCount);
	bzero(param->Buf, param->BufCount);
	switch (param->switch_value) {
	case 0:
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		pinfo0 = (struct spoolss_GetPrinter0 *)param->Buf;
		break;
	case 1:
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		pinfo1 = (struct spoolss_GetPrinter1 *)param->Buf;
		break;
	case 2:
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		pinfo2 = (struct spoolss_GetPrinter2 *)param->Buf;
		break;
	}
	wname = (char *)param->Buf;

	status = ERROR_INVALID_PARAMETER;
	if (smb_gethostname(hname, MAXHOSTNAMELEN, 0) != 0) {
		syslog(LOG_NOTICE, "spoolss_s_GetPrinter: gethostname failed");
		goto error_out;
	}
	if ((h = smb_gethostbyname(hname, &error)) == NULL) {
		syslog(LOG_NOTICE,
		    "spoolss_s_GetPrinter: gethostbyname failed");
		goto error_out;
	}
	bcopy(h->h_addr, &ipaddr, h->h_length);
	ipaddr.a_family = h->h_addrtype;
	freehostent(h);
	if (smb_inet_ntop(&ipaddr, ipstr, SMB_IPSTRLEN(ipaddr.a_family))
	    == NULL) {
		syslog(LOG_NOTICE, "spoolss_s_GetPrinter: inet_ntop failed");
		goto error_out;
	}
	status = ERROR_SUCCESS;
	(void) snprintf(poutbuf, MAXNAMELEN, "\\\\%s\\%s",
	    ipstr, SPOOLSS_PRINTER);
	(void) snprintf(soutbuf, MAXNAMELEN, "\\\\%s", ipstr);
	param->needed = 0;
	switch (param->switch_value) {
	case 0:
		offset = 460;
		smb_rpc_off(wname, "", &offset, &pinfo0->servername);
		smb_rpc_off(wname, poutbuf, &offset, &pinfo0->printername);
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
		pinfo1->flags = PRINTER_ENUM_ICON8;
		offset = 460;
		smb_rpc_off(wname, poutbuf, &offset, &pinfo1->flags);
		smb_rpc_off(wname, poutbuf, &offset, &pinfo1->description);
		smb_rpc_off(wname, poutbuf, &offset, &pinfo1->comment);
		break;
	case 2:
		offset = param->BufCount;
		smb_rpc_off(wname, soutbuf, &offset, &pinfo2->servername);
		smb_rpc_off(wname, poutbuf, &offset, &pinfo2->printername);
		smb_rpc_off(wname, SPOOLSS_PRINTER, &offset,
		    &pinfo2->sharename);
		smb_rpc_off(wname, "CIFS Printer Port", &offset,
		    &pinfo2->portname);
		smb_rpc_off(wname, "", &offset, &pinfo2->drivername);
		smb_rpc_off(wname, SPOOLSS_PRINTER, &offset,
		    &pinfo2->comment);
		smb_rpc_off(wname, "farside", &offset, &pinfo2->location);
		smb_rpc_off(wname, "farside", &offset, &pinfo2->sepfile);
		smb_rpc_off(wname, "winprint", &offset,
		    &pinfo2->printprocessor);
		smb_rpc_off(wname, "RAW", &offset, &pinfo2->datatype);
		smb_rpc_off(wname, "", &offset, &pinfo2->datatype);
		pinfo2->attributes = 0x00001048;
		pinfo2->status = 0x00000000;
		pinfo2->starttime = 0;
		pinfo2->untiltime = 0;
		pinfo2->cjobs = 0;
		pinfo2->averageppm = 0;
		pinfo2->defaultpriority = 0;
		pinfo2->devmode = 568; // offset
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		devmode2 = (struct spoolss_DeviceMode *)(param->Buf
		    + pinfo2->devmode);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		(void) smb_mbstowcs(((smb_wchar_t *)
		    (devmode2->devicename)), (const char *)poutbuf, 25);
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
		(void) smb_mbstowcs(((smb_wchar_t *)
		    (devmode2->formname)), (const char *)"Letter", 6);
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

		pinfo2->secdesc = 84;
		tmpbuf = (uint8_t *)(pinfo2->secdesc + (uint8_t *)param->Buf);
		error = spoolss_s_make_sd(tmpbuf);
		param->needed = 712;
		break;

	default:
		syslog(LOG_NOTICE, "spoolss_s_GetPrinter: INVALID_LEVEL");
		status = ERROR_INVALID_LEVEL;
		break;

	}
error_out:
	param->status = status;
	return (NDR_DRC_OK);
}

int
spoolss_s_make_sd(uint8_t *sd_buf)
{
	smb_sd_t			sd;
	uint32_t			status;

	bzero(&sd, sizeof (smb_sd_t));

	if ((status = spoolss_sd_format(&sd)) == ERROR_SUCCESS) {
		status = srvsvc_sd_set_relative(&sd, sd_buf);
		smb_sd_term(&sd);
		return (NDR_DRC_OK);
	}
	syslog(LOG_NOTICE, "spoolss_s_make_sd: error status=%d", status);
	smb_sd_term(&sd);
	return (NDR_DRC_OK);
}

static uint32_t
spoolss_sd_format(smb_sd_t *sd)
{
	smb_fssd_t	fs_sd;
	acl_t		*acl;
	uint32_t	status = ERROR_SUCCESS;

	if (acl_fromtext("everyone@:full_set::allow", &acl) != 0) {
		syslog(LOG_ERR, "spoolss_sd_format: NOT_ENOUGH_MEMORY");
		return (ERROR_NOT_ENOUGH_MEMORY);
	}
	smb_fssd_init(&fs_sd, SMB_ALL_SECINFO, SMB_FSSD_FLAGS_DIR);
	fs_sd.sd_uid = 0;
	fs_sd.sd_gid = 0;
	fs_sd.sd_zdacl = acl;
	fs_sd.sd_zsacl = NULL;

	if (smb_sd_fromfs(&fs_sd, sd) != NT_STATUS_SUCCESS) {
		syslog(LOG_NOTICE, "spoolss_sd_format: ACCESS_DENIED");
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

/*ARGSUSED*/
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
