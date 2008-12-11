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

/*
 * Event Log Service RPC (LOGR) interface definition.
 */

#include <sys/utsname.h>
#include <unistd.h>
#include <strings.h>
#include <netdb.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlrpc.h>
#include <smbsrv/ntstatus.h>
#include <smbsrv/nmpipes.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/ndl/eventlog.ndl>

#define	FWD	+1
#define	REW	-1

/* define the logging structs here - from syslog.h */
#define	NMSGMASK	1023
#define	MAXMSGLEN	223
#define	LOGBUFSIZE	(MAXMSGLEN + 1)

#define	LOG_PRI(p)	((p) & LOG_PRIMASK)

typedef struct log_entry {
	struct timeval	timestamp;	    /* time of log entry */
	int		pri;		    /* message priority */
	char		msg[LOGBUFSIZE];    /* log message text */
	int		thread_id;	    /* calling function thread ID */
	char		thread_name[12];    /* calling function thread name */
	unsigned long	caller_adr;	    /* calling function address */
} log_entry_t;

typedef struct log_info {
	log_entry_t	entry[NMSGMASK+1];
	int		ix;
	int		alarm_on;
	int		alarm_disable;
	int		timestamp_level;
	int		disp_msg_len;
	int		prefix_len;
} log_info_t;

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

#define	MAX_SRCNAME_LEN			20
#define	LOGR_KEY			"LogrOpen"


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

typedef struct {
	DWORD tot_recnum;
	DWORD last_sentrec;
	char first_read;
	struct log_info log;
} read_data_t;

static char logr_sysname[SYS_NMLN];
static mts_wchar_t wcs_hostname[MAXHOSTNAMELEN];
static int hostname_len = 0;
static mts_wchar_t wcs_srcname[MAX_SRCNAME_LEN];
static int srcname_len = 0;

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
	struct utsname name;
	char *sysname;
	int len;

	if (uname(&name) < 0)
		sysname = "Solaris";
	else
		sysname = name.sysname;

	(void) strlcpy(logr_sysname, sysname, SYS_NMLN);
	len = strlen(logr_sysname) + 1;
	(void) mts_mbstowcs(wcs_srcname, logr_sysname, len);
	srcname_len = len * sizeof (mts_wchar_t);

	(void) ndr_svc_register(&logr_service);
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

	free(hd->nh_data);
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

	bzero(&param->handle, sizeof (logr_handle_t));
	param->status = NT_SC_ERROR(NT_STATUS_ACCESS_DENIED);
	return (NDR_DRC_OK);
}

/*
 * logr_get_snapshot
 *
 * Allocate memory and make a copy, as a snapshot, from system log.
 */
static read_data_t *
logr_get_snapshot(void)
{
	read_data_t *data = NULL;
	return (data);
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
	read_data_t *data;

	if ((hd = ndr_hdlookup(mxa, id)) == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	if ((data = logr_get_snapshot()) == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
		return (NDR_DRC_OK);
	}

	hd->nh_data = data;
	param->rec_num = data->tot_recnum;
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
	read_data_t *data;

	if ((hd = ndr_hdlookup(mxa, id)) == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	data = (read_data_t *)hd->nh_data;
	param->oldest_rec = data->log.ix - data->tot_recnum;
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * set_event_typeid
 *
 * Map the local system log priority to the event type and event ID
 * for Windows events.
 */
void
set_event_typeid(int le_pri, WORD *etype, DWORD *eid)
{
	switch (LOG_PRI(le_pri)) {
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

static log_entry_t *
log_get_entry(struct log_info *linfo, int entno)
{
	return (&linfo->entry[entno]);
}

/*
 * Fill a Windows event record based on a local system log record.
 */
static void
set_logrec(log_entry_t *le, DWORD recno, logr_record_t *rec)
{
	int str_offs;
	int sh_len;
	int len;

	sh_len = srcname_len + hostname_len;
	str_offs = 12 * sizeof (DWORD) + 4 * sizeof (WORD) + sh_len;

	rec->Length1 = sizeof (logr_record_t);
	rec->Reserved = 0x654C664C;
	rec->RecordNumber = recno;
	rec->TimeGenerated = le->timestamp.tv_sec;
	rec->TimeWritten = le->timestamp.tv_sec;
	set_event_typeid(le->pri, &rec->EventType, &rec->EventID);
	rec->NumStrings = 1;
	rec->EventCategory = 0;
	rec->ReservedFlags = 0;
	rec->ClosingRecordNumber = 0;
	rec->StringOffset = str_offs;
	rec->UserSidLength = 0;
	rec->UserSidOffset = sizeof (logr_record_t) - sizeof (DWORD);
	rec->DataLength = 0;
	rec->DataOffset = sizeof (logr_record_t) - sizeof (DWORD);
	bzero(rec->info, LOGR_INFOLEN);
	(void) memcpy(rec->info, wcs_srcname, srcname_len);
	(void) memcpy(rec->info + srcname_len, wcs_hostname, hostname_len);

	len = (LOGR_INFOLEN - sh_len) / 2;

	if ((strlen(le->msg) + 1) < len)
		len = strlen(le->msg) + 1;

	/*LINTED E_BAD_PTR_CAST_ALIGN*/
	(void) mts_mbstowcs((mts_wchar_t *)(rec->info+sh_len), le->msg, len);
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
	read_data_t *rdata;
	log_entry_t *le;
	DWORD ent_no, ent_num, ent_remain;
	logr_record_t *rec;
	BYTE *buf;
	int dir, ent_per_req;

	if ((hd = ndr_hdlookup(mxa, id)) == NULL) {
		param->status = NT_SC_ERROR(NT_STATUS_INVALID_HANDLE);
		return (NDR_DRC_OK);
	}

	rdata = (read_data_t *)hd->nh_data;
	if (rdata == NULL) {
		if ((rdata = logr_get_snapshot()) == NULL) {
			param->status = NT_SC_ERROR(NT_STATUS_NO_MEMORY);
			return (NDR_DRC_OK);
		}

		hd->nh_data = rdata;
	}

	dir = (param->read_flags & EVENTLOG_FORWARDS_READ) ? FWD : REW;

	if (param->read_flags & EVENTLOG_SEEK_READ) {
		rdata->last_sentrec = param->rec_offset;
	} else if (rdata->first_read) {
		/*
		 * set last record number which is read for
		 * the first iteration of sequential read.
		 */
		rdata->last_sentrec = (dir == FWD)
		    ? (rdata->log.ix - rdata->tot_recnum) : rdata->log.ix;
	}

	ent_remain = (dir == FWD)
	    ? (rdata->tot_recnum - rdata->last_sentrec) : rdata->last_sentrec;

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
		param->sent_size = 0;
		param->unknown = 0;
		param->status = NT_SC_ERROR(NT_STATUS_END_OF_FILE);
		return (NDR_DRC_OK);
	}

	buf = (param->read_flags & EVENTLOG_SEEK_READ)
	    ? param->ru.rec : param->ru.recs;

	for (ent_num = 0, ent_no = rdata->last_sentrec;
	    ent_num < ent_remain; ent_num++, ent_no += dir) {
		le = log_get_entry(&rdata->log, ent_no & NMSGMASK);
		/*LINTED E_BAD_PTR_CAST_ALIGN*/
		rec = (logr_record_t *)buf;
		set_logrec(le, ent_no, rec);
		buf += sizeof (logr_record_t);
	}
	rdata->last_sentrec = ent_no;
	rdata->first_read = 0;

	param->sent_size = sizeof (logr_record_t) * ent_remain;
	param->unknown = 0;
	param->status = NT_STATUS_SUCCESS;
	return (NDR_DRC_OK);
}

/*
 * Declare extern references.
 */
DECL_FIXUP_STRUCT(logr_read_u);
DECL_FIXUP_STRUCT(logr_read_info);
DECL_FIXUP_STRUCT(logr_EventLogRead);

/*
 * Patch the logr_EventLogRead union.
 * This function is called from mlsvc_logr_ndr.c
 */
void
fixup_logr_EventLogRead(void *xarg)
{
	struct logr_EventLogRead *arg = (struct logr_EventLogRead *)xarg;
	unsigned short size1 = 0;
	unsigned short size2 = 0;
	unsigned short size3 = 0;
	DWORD nbr = arg->nbytes_to_read;

	switch (nbr) {
	case 0:
		size1 = 0;
		break;
	default:
		size1 = nbr;
		break;
	};

	size2 = size1 + (2 * sizeof (DWORD));
	size3 = size2 + sizeof (ndr_request_hdr_t) + sizeof (DWORD);

	FIXUP_PDU_SIZE(logr_read_u, size1);
	FIXUP_PDU_SIZE(logr_read_info, size2);
	FIXUP_PDU_SIZE(logr_EventLogRead, size3);
}
