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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Event Log Service RPC (LOGR) interface definition.
 */
#include <sys/utsname.h>
#include <unistd.h>
#include <strings.h>
#include <libmlrpc/libmlrpc.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/eventlog.ndl>


#define	LOGR_FWD		+1
#define	LOGR_REW		-1
#define	LOGR_RECORD_SIGNATURE	0x654C664C

#define	LOGR_PRI(p)		((p) & LOG_PRIMASK)
#define	LOGR_WNSTRLEN(S)	((strlen((S)) + 1) * sizeof (smb_wchar_t))

#define	LOGR_MSG_DWORD_OFFSET	12
#define	LOGR_MSG_WORD_OFFSET	4

/*
 * READ flags for EventLogRead
 *
 * EVENTLOG_SEEK_READ
 * The read operation proceeds from the record specified by the
 * dwRecordOffset parameter. This flag cannot be used with
 * EVENTLOG_SEQUENTIAL_READ.
 *
 * EVENTLOG_SEQUENTIAL_READ
 * The read operation proceeds sequentially from the last call to the
 * ReadEventLog function using this handle. This flag cannot be used
 * with EVENTLOG_SEEK_READ.
 *
 * If the buffer is large enough, more than one record can be read at
 * the specified seek position; you must specify one of the following
 * flags to indicate the direction for successive read operations.
 *
 * EVENTLOG_FORWARDS_READ
 * The log is read in chronological order. This flag cannot be used
 * with EVENTLOG_BACKWARDS_READ.
 *
 * EVENTLOG_BACKWARDS_READ
 * The log is read in reverse chronological order. This flag cannot be
 * used with EVENTLOG_FORWARDS_READ.
 */
#define	EVENTLOG_SEQUENTIAL_READ	0x0001
#define	EVENTLOG_SEEK_READ		0x0002
#define	EVENTLOG_FORWARDS_READ		0x0004
#define	EVENTLOG_BACKWARDS_READ		0x0008

/*
 * The types of events that can be logged.
 */
#define	EVENTLOG_SUCCESS		0x0000
#define	EVENTLOG_ERROR_TYPE		0x0001
#define	EVENTLOG_WARNING_TYPE		0x0002
#define	EVENTLOG_INFORMATION_TYPE	0x0004
#define	EVENTLOG_AUDIT_SUCCESS		0x0008
#define	EVENTLOG_AUDIT_FAILURE		0x0010

/*
 * Event Identifiers
 *
 * Event identifiers uniquely identify a particular event. Each event
 * source can define its own numbered events and the description strings
 * to which they are mapped. Event viewers can present these strings to
 * the user. They should help the user understand what went wrong and
 * suggest what actions to take. Direct the description at users solving
 * their own problems, not at administrators or support technicians.
 * Make the description clear and concise and avoid culture-specific
 * phrases.
 *
 * The following diagram illustrates the format of an event identifier.
 *
 *   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *  +---+-+-+-----------------------+-------------------------------+
 *  |Sev|C|R|     Facility          |               Code            |
 *  +---+-+-+-----------------------+-------------------------------+
 *
 *  Sev
 *        Indicates the severity. This is one of the following values:
 *        00 - Success
 *        01 - Informational
 *        10 - Warning
 *        11 - Error
 *
 *  C
 *        Indicates a customer code (1) or a system code (0).
 *  R
 *        Reserved bit.
 *  Facility
 *        Facility code.
 *  Code
 *        Status code for the facility.
 */
#define	EVENTID_SEVERITY_SUCCESS	0x00000000
#define	EVENTID_SEVERITY_INFO		0x40000000
#define	EVENTID_SEVERITY_WARNING	0x80000000
#define	EVENTID_SEVERITY_ERROR		0xC0000000

#define	EVENTID_SYSTEM_CODE		0x00000000
#define	EVENTID_CUSTOMER_CODE		0x20000000

static int logr_s_EventLogClose(void *, ndr_xa_t *);
static int logr_s_EventLogQueryCount(void *, ndr_xa_t *);
static int logr_s_EventLogGetOldestRec(void *, ndr_xa_t *);
static int logr_s_EventLogOpen(void *, ndr_xa_t *);
static int logr_s_EventLogRead(void *, ndr_xa_t *);

static ndr_stub_table_t logr_stub_table[] = {
	{ logr_s_EventLogClose,		LOGR_OPNUM_EventLogClose },
	{ logr_s_EventLogQueryCount,	LOGR_OPNUM_EventLogQueryCount },
	{ logr_s_EventLogGetOldestRec,	LOGR_OPNUM_EventLogGetOldestRec },
	{ logr_s_EventLogOpen,		LOGR_OPNUM_EventLogOpen },
	{ logr_s_EventLogRead,		LOGR_OPNUM_EventLogRead },
	{0}
};

static ndr_service_t logr_service = {
	"LOGR",				/* name */
	"Event Log Service",		/* desc */
	"\\eventlog",			/* endpoint */
	PIPE_NTSVCS,			/* sec_addr_port */
	"82273fdc-e32a-18c3-3f78-827929dc23ea", 0,	/* abstract */
	NDR_TRANSFER_SYNTAX_UUID,		2,	/* transfer */
	0,				/* no bind_instance_size */
	0,				/* no bind_req() */
	0,				/* no unbind_and_close() */
	0,				/* use generic_call_stub() */
	&TYPEINFO(logr_interface),	/* interface ti */
	logr_stub_table			/* stub_table */
};

/*
 * logr_initialize
 *
 * This function registers the LOGR RPC interface with the RPC runtime
 * library. It must be called in order to use either the client side
 * or the server side functions.
 */
void
logr_initialize(void)
{
	(void) ndr_svc_register(&logr_service);
	logr_init();
}

void
logr_finalize(void)
{
	logr_fini();
}

/*
 * logr_hdlookup
 *
 * Handle lookup wrapper to validate the local service and/or manager context.
 */
static ndr_handle_t *
logr_hdlookup(ndr_xa_t *mxa, ndr_hdid_t *id)
{
	ndr_handle_t *hd;
	logr_context_t *ctx;

	if ((hd = ndr_hdlookup(mxa, id)) == NULL)
		return (NULL);

	if ((ctx = (logr_context_t *)hd->nh_data) == NULL)
		return (NULL);

	if (ctx->lc_source_name == NULL)
		return (NULL);

	return (hd);
}

/*
 * logr_context_data_free
 *
 * Callback to free the context data associated with local service
 * and/or manager context.
 */
static void
logr_context_data_free(void *ctxp)
{
	logr_context_t *ctx = (logr_context_t *)ctxp;

	if (ctx == NULL)
		return;

	free(ctx->lc_source_name);
	free(ctx->lc_cached_read_data->rd_log);
	free(ctx->lc_cached_read_data);
	free(ctx);
	ctx = NULL;
}

/*
 * logr_hdalloc
 *
 * Handle allocation wrapper to setup the local manager context.
 */
static ndr_hdid_t *
logr_hdalloc(ndr_xa_t *mxa, char *logname)
{
	logr_context_t *ctx;

	if ((ctx = malloc(sizeof (logr_context_t))) == NULL)
		return (NULL);
	bzero(ctx, sizeof (logr_context_t));

	ctx->lc_source_name = strdup(logname);
	if (ctx->lc_source_name == NULL) {
		free(ctx);
		return (NULL);
	}

	if (logr_get_snapshot(ctx) != 0) {
		free(ctx->lc_source_name);
		free(ctx);
		return (NULL);
	}

	return (ndr_hdalloc(mxa, ctx));
}

/*
 * logr_s_EventLogClose
 *
 * This is a request to close the LOGR interface specified by handle.
 * Free the handle and associated resources, and zero out the result
 * handle for the client.
 */
static int
logr_s_EventLogClose(void *arg, ndr_xa_t *mxa)
{
	struct logr_EventLogClose *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;

	if ((hd = ndr_hdlookup(mxa, id)) == NULL) {
		bzero(&param->result_handle, sizeof (logr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}
	logr_context_data_free(hd->nh_data);
	ndr_hdfree(mxa, id);

	bzero(&param->result_handle, sizeof (logr_handle_t));
	param->status = NT_STATUS_SUCCESS;

	return (NDR_DRC_OK);
}

/*
 * logr_s_EventLogOpen
 *
 * Open the event log. Not supported yet.
 */
/*ARGSUSED*/
static int
logr_s_EventLogOpen(void *arg, ndr_xa_t *mxa)
{
	struct logr_EventLogOpen *param = arg;
	ndr_hdid_t *id = NULL;
	ndr_handle_t *hd;
	char *log_name = NULL;

	if (!ndr_is_admin(mxa)) {
		bzero(&param->handle, sizeof (logr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (NDR_DRC_OK);
	}

	if (param->log_name.length != 0)
		log_name = (char *)param->log_name.str;

	if (!logr_is_supported(log_name)) {
		bzero(&param->handle, sizeof (logr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
		return (NDR_DRC_OK);
	}

	id = logr_hdalloc(mxa, log_name);
	if (id && ((hd = logr_hdlookup(mxa, id)) != NULL)) {
		hd->nh_data_free = logr_context_data_free;
		bcopy(id, &param->handle, sizeof (logr_handle_t));
		param->status = NT_STATUS_SUCCESS;
	} else {
		bzero(&param->handle, sizeof (logr_handle_t));
		param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	}

	return (NDR_DRC_OK);
}

/*
 * logr_s_EventLogQueryCount
 *
 * take a snapshot from system log, assign it to the given handle.
 * return number of log entries in the snapshot as result of RPC
 * call.
 */
static int
logr_s_EventLogQueryCount(void *arg, ndr_xa_t *mxa)
{
	struct logr_EventLogQueryCount *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	logr_context_t *ctx;
	logr_read_data_t *data;

	if ((hd = logr_hdlookup(mxa, id)) == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	ctx = (logr_context_t *)hd->nh_data;
	data = ctx->lc_cached_read_data;

	param->rec_num = data->rd_tot_recnum;
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * logr_s_EventLogGetOldestRec
 *
 * Return oldest record number in the snapshot as result of RPC call.
 */
static int
logr_s_EventLogGetOldestRec(void *arg, ndr_xa_t *mxa)
{
	struct logr_EventLogGetOldestRec *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	logr_context_t *ctx;
	logr_read_data_t *data;

	if ((hd = logr_hdlookup(mxa, id)) == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	ctx = (logr_context_t *)hd->nh_data;
	data = ctx->lc_cached_read_data;

	param->oldest_rec = data->rd_log->li_idx - data->rd_tot_recnum + 1;

	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * logr_set_event_typeid
 *
 * Map the local system log priority to the event type and event ID
 * for Windows events.
 */
void
logr_set_event_typeid(int le_pri, WORD *etype, DWORD *eid)
{
	switch (LOGR_PRI(le_pri)) {
	case LOG_EMERG:
	case LOG_ALERT:
	case LOG_CRIT:
	case LOG_ERR:
		*eid   = EVENTID_SEVERITY_ERROR;
		*etype = EVENTLOG_ERROR_TYPE;
		break;
	case LOG_WARNING:
		*eid   = EVENTID_SEVERITY_WARNING;
		*etype = EVENTLOG_WARNING_TYPE;
		break;
	case LOG_NOTICE:
	case LOG_INFO:
	case LOG_DEBUG:
		*eid   = EVENTID_SEVERITY_INFO;
		*etype = EVENTLOG_INFORMATION_TYPE;
		break;
	default:
		*eid   = EVENTID_SEVERITY_SUCCESS;
		*etype = EVENTLOG_SUCCESS;
	}
}

/*
 * logr_get_entry
 *
 * Gets a log entry.
 */
static logr_entry_t *
logr_get_entry(logr_info_t *linfo, int entno)
{
	return (&linfo->li_entry[entno]);
}

/*
 * logr_set_logrecord
 *
 * Fill a Windows event record based on a local system log record.
 */
static void
logr_set_logrecord(char *src_name, logr_entry_t *le,
    DWORD recno, logr_record_t *rec)
{
	int srcname_len = 0, hostname_len = 0, len;
	int str_offs, sh_len;
	smb_wchar_t wcs_hostname[MAXHOSTNAMELEN];
	smb_wchar_t wcs_srcname[SYS_NMLN * 2];

	(void) smb_mbstowcs(wcs_srcname, src_name,
	    strlen(src_name) + 1);
	srcname_len = LOGR_WNSTRLEN(src_name);

	/* Because, Solaris allows remote logging, need to get hostname here */
	(void) smb_mbstowcs(wcs_hostname, le->le_hostname,
	    strlen(le->le_hostname) + 1);
	hostname_len = LOGR_WNSTRLEN(le->le_hostname);

	sh_len = srcname_len + hostname_len;
	str_offs = LOGR_MSG_DWORD_OFFSET * sizeof (DWORD) +
	    LOGR_MSG_WORD_OFFSET * sizeof (WORD) + sh_len;

	rec->Length1 = sizeof (logr_record_t);
	rec->Reserved = LOGR_RECORD_SIGNATURE;
	rec->RecordNumber = recno;
	rec->TimeGenerated = le->le_timestamp.tv_sec;
	rec->TimeWritten = le->le_timestamp.tv_sec;
	logr_set_event_typeid(le->le_pri, &rec->EventType, &rec->EventID);
	rec->NumStrings = 1;
	rec->EventCategory = 0;
	rec->ReservedFlags = 0;
	rec->ClosingRecordNumber = 0;
	rec->StringOffset = str_offs;
	rec->UserSidLength = 0;
	rec->UserSidOffset = 0;
	rec->DataLength = 0;
	rec->DataOffset = 0;

	bzero(rec->info, LOGR_MAXENTRYLEN);
	(void) memcpy(rec->info, wcs_srcname, srcname_len);
	(void) memcpy(rec->info + srcname_len, wcs_hostname, hostname_len);

	len = strlen(le->le_msg) + 1;
	if (len > 0)
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		(void) smb_mbstowcs((smb_wchar_t *)(rec->info + sh_len),
		    le->le_msg, len);

	rec->Length2 = sizeof (logr_record_t);
}

/*
 * logr_s_EventLogRead
 *
 * Reads a whole number of entries from system log. The function can
 * read log entries in chronological or reverse chronological order.
 */
static int
logr_s_EventLogRead(void *arg, ndr_xa_t *mxa)
{
	struct logr_EventLogRead *param = arg;
	ndr_hdid_t *id = (ndr_hdid_t *)&param->handle;
	ndr_handle_t *hd;
	logr_read_data_t *rdata;
	logr_entry_t *le;
	DWORD ent_no, ent_num, ent_remain;
	logr_record_t *rec;
	BYTE *buf;
	int dir, ent_per_req, iter;
	logr_context_t *ctx;

	if ((hd = logr_hdlookup(mxa, id)) == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	ctx = (logr_context_t *)hd->nh_data;
	rdata = ctx->lc_cached_read_data;
	if (rdata == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	dir = (param->read_flags & EVENTLOG_FORWARDS_READ) ?
	    LOGR_FWD : LOGR_REW;

	if (param->read_flags & EVENTLOG_SEEK_READ)
		rdata->rd_last_sentrec = param->rec_offset;
	else if (rdata->rd_first_read)
		/*
		 * set last record number which is read for
		 * the first iteration of sequential read.
		 */
		rdata->rd_last_sentrec = (dir == LOGR_FWD)
		    ? (rdata->rd_log->li_idx - rdata->rd_tot_recnum)
		    : rdata->rd_log->li_idx;

	ent_remain = (dir == LOGR_FWD)
	    ? (rdata->rd_tot_recnum - rdata->rd_last_sentrec)
	    : rdata->rd_last_sentrec;

	/*
	 * function should return as many whole log entries as
	 * will fit in the buffer; it should not return partial
	 * entries, even if there is room in the buffer.
	 */
	ent_per_req = param->nbytes_to_read / sizeof (logr_record_t);
	if (ent_remain > ent_per_req)
		ent_remain = ent_per_req;

	if (ent_remain == 0) {
		/*
		 * Send this error to Windows client so that it
		 * can figure out that there is no more record
		 * to read.
		 */
		param->buf = NDR_STRDUP(mxa, "");
		param->sent_size = 0;
		param->status = NT_SC_ERROR(NT_STATUS_END_OF_FILE);
		return (NDR_DRC_OK);
	}

	param->buf = NDR_MALLOC(mxa, param->nbytes_to_read);
	buf = (BYTE *)param->buf;

	for (ent_num = 0, ent_no = rdata->rd_last_sentrec;
	    ent_num < ent_remain; ent_num++, ent_no += dir) {

		iter = ent_no & LOGR_NMSGMASK;
		if (dir == LOGR_REW)
			iter = (ent_no - 1) & LOGR_NMSGMASK;

		le = logr_get_entry(rdata->rd_log, iter);

		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		rec = (logr_record_t *)buf;
		logr_set_logrecord(ctx->lc_source_name, le, ent_no, rec);
		buf += sizeof (logr_record_t);
	}

	rdata->rd_last_sentrec = ent_no;
	rdata->rd_first_read = 0;

	param->sent_size = sizeof (logr_record_t) * ent_remain;
	param->status = NT_STATUS_SUCCESS;

	return (NDR_DRC_OK);
}
