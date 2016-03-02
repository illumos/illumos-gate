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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/fm/protocol.h>
#include <sys/strlog.h>
#include <sys/log.h>
#include <libscf.h>

#include <fm/fmd_api.h>
#include <fm/fmd_msg.h>

#include <stropts.h>
#include <strings.h>
#include <syslog.h>
#include <alloca.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>

static struct stats {
	fmd_stat_t bad_vers;
	fmd_stat_t bad_code;
	fmd_stat_t log_err;
	fmd_stat_t msg_err;
	fmd_stat_t no_msg;
} syslog_stats = {
	{ "bad_vers", FMD_TYPE_UINT64, "event version is missing or invalid" },
	{ "bad_code", FMD_TYPE_UINT64, "event code has no dictionary name" },
	{ "log_err", FMD_TYPE_UINT64, "failed to log message to log(7D)" },
	{ "msg_err", FMD_TYPE_UINT64, "failed to log message to sysmsg(7D)" },
	{ "no_msg", FMD_TYPE_UINT64, "message logging suppressed" }
};

static const struct facility {
	const char *fac_name;
	int fac_value;
} syslog_facs[] = {
	{ "LOG_DAEMON", LOG_DAEMON },
	{ "LOG_LOCAL0", LOG_LOCAL0 },
	{ "LOG_LOCAL1", LOG_LOCAL1 },
	{ "LOG_LOCAL2", LOG_LOCAL2 },
	{ "LOG_LOCAL3", LOG_LOCAL3 },
	{ "LOG_LOCAL4", LOG_LOCAL4 },
	{ "LOG_LOCAL5", LOG_LOCAL5 },
	{ "LOG_LOCAL6", LOG_LOCAL6 },
	{ "LOG_LOCAL7", LOG_LOCAL7 },
	{ NULL, 0 }
};

static fmd_msg_hdl_t *syslog_msghdl; /* handle for libfmd_msg calls */
static int syslog_msgall;	/* set to message all faults */
static log_ctl_t syslog_ctl;	/* log(7D) meta-data for each msg */
static int syslog_logfd = -1;	/* log(7D) file descriptor */
static int syslog_msgfd = -1;	/* sysmsg(7D) file descriptor */
static int syslog_file;		/* log to syslog_logfd */
static int syslog_cons;		/* log to syslog_msgfd */
static const char SYSLOG_POINTER[] = "syslog-msgs-pointer";

/*
 * Ideally we would just use syslog(3C) for outputting our messages, but our
 * messaging standard defines a nice multi-line format and syslogd(1M) is very
 * inflexible and stupid when it comes to multi-line messages.  It pulls data
 * out of log(7D) and splits it up by \n, printing each line to the console
 * with its usual prefix of date and sender; it uses the same behavior for the
 * messages file as well.  Further, syslog(3C) provides no CE_CONT equivalent
 * for userland callers (which at least works around repeated file prefixing).
 * So with a multi-line message format, your file and console end up like this:
 *
 * Dec 02 18:08:40 hostname this is my nicely formatted
 * Dec 02 18:08:40 hostname message designed for 80 cols
 * ...
 *
 * To resolve these issues, we use our own syslog_emit() wrapper to emit
 * messages and some knowledge of how the Solaris log drivers work.  We first
 * construct an enlarged format string containing the appropriate msgid(1).
 * We then format the caller's message using the provided format and buffer.
 * We send this message to log(7D) using putmsg() with SL_CONSOLE | SL_LOGONLY
 * set in the log_ctl_t.  The log driver allows us to set SL_LOGONLY when we
 * construct messages ourself, indicating that syslogd should only emit the
 * message to /var/adm/messages and any remote hosts, and skip the console.
 * Then we emit the message a second time, without the special prefix, to the
 * sysmsg(7D) device, which handles console redirection and also permits us
 * to output any characters we like to the console, including \n and \r.
 */
static void
syslog_emit(fmd_hdl_t *hdl, const char *msg)
{
	struct strbuf ctl, dat;
	uint32_t msgid;

	char *buf;
	size_t buflen;

	const char *format = "fmd: [ID %u FACILITY_AND_PRIORITY] %s";
	STRLOG_MAKE_MSGID(format, msgid);

	buflen = snprintf(NULL, 0, format, msgid, msg);
	buf = alloca(buflen + 1);
	(void) snprintf(buf, buflen + 1, format, msgid, msg);

	ctl.buf = (void *)&syslog_ctl;
	ctl.len = sizeof (syslog_ctl);

	dat.buf = buf;
	dat.len = buflen + 1;

	/*
	 * The underlying log driver won't accept messages longer than
	 * LOG_MAXPS bytes.  Therefore, messages which exceed this limit will
	 * be truncated and appended with a pointer to the full message.
	 */
	if (dat.len > LOG_MAXPS) {
		char *syslog_pointer, *p;
		size_t plen;

		if ((syslog_pointer = fmd_msg_gettext_id(syslog_msghdl, NULL,
		    SYSLOG_POINTER)) == NULL) {
			/*
			 * This shouldn't happen, but if it does we'll just
			 * truncate the message.
			 */
			buf[LOG_MAXPS - 1] = '\0';
			dat.len = LOG_MAXPS;
		} else {
			plen = strlen(syslog_pointer) + 1;
			buf[LOG_MAXPS - plen] = '\0';
			/*
			 * If possible, the pointer is appended after a newline
			 */
			if ((p = strrchr(buf, '\n')) == NULL)
				p = &buf[LOG_MAXPS - plen];

			(void) strcpy(p, syslog_pointer);
			free(syslog_pointer);
			dat.len = strlen(buf) + 1;
		}
	}
	if (syslog_file && putmsg(syslog_logfd, &ctl, &dat, 0) != 0) {
		fmd_hdl_debug(hdl, "putmsg failed: %s\n", strerror(errno));
		syslog_stats.log_err.fmds_value.ui64++;
	}

	dat.buf = strchr(buf, ']');
	dat.len -= (size_t)(dat.buf - buf);

	dat.buf[0] = '\r'; /* overwrite ']' with carriage return */
	dat.buf[1] = '\n'; /* overwrite ' ' with newline */

	if (syslog_cons && write(syslog_msgfd, dat.buf, dat.len) != dat.len) {
		fmd_hdl_debug(hdl, "write failed: %s\n", strerror(errno));
		syslog_stats.msg_err.fmds_value.ui64++;
	}
}

static void
free_notify_prefs(fmd_hdl_t *hdl, nvlist_t **prefs, uint_t nprefs)
{
	int i;

	for (i = 0; i < nprefs; i++) {
		nvlist_free(prefs[i]);
	}

	fmd_hdl_free(hdl, prefs, sizeof (nvlist_t *) * nprefs);
}

static int
get_notify_prefs(fmd_hdl_t *hdl, nvlist_t *ev_nvl, nvlist_t ***pref_nvl,
    uint_t *nprefs)
{
	nvlist_t *top_nvl, **np_nvlarr, *mech_nvl;
	nvlist_t **tmparr;
	int ret, i;
	uint_t nelem, nslelem;

	if ((ret = smf_notify_get_params(&top_nvl, ev_nvl)) != SCF_SUCCESS) {
		ret = scf_error();
		if (ret != SCF_ERROR_NOT_FOUND) {
			fmd_hdl_debug(hdl, "Error looking up notification "
			    "preferences (%s)", scf_strerror(ret));
			return (ret);
		}
		return (ret);
	}

	if (nvlist_lookup_nvlist_array(top_nvl, SCF_NOTIFY_PARAMS, &np_nvlarr,
	    &nelem) != 0) {
		fmd_hdl_debug(hdl, "Malformed preference nvlist\n");
		ret = SCF_ERROR_INVALID_ARGUMENT;
		goto pref_done;
	}

	tmparr = fmd_hdl_alloc(hdl, nelem * sizeof (nvlist_t *), FMD_SLEEP);
	nslelem = 0;

	for (i = 0; i < nelem; i++) {
		if (nvlist_lookup_nvlist(np_nvlarr[i], "syslog", &mech_nvl)
		    == 0)
			tmparr[nslelem++] = fmd_nvl_dup(hdl, mech_nvl,
			    FMD_SLEEP);
	}

	if (nslelem != 0) {
		size_t sz = nslelem * sizeof (nvlist_t *);

		*pref_nvl = fmd_hdl_zalloc(hdl, sz, FMD_SLEEP);
		*nprefs = nslelem;
		bcopy(tmparr, *pref_nvl, sz);
		ret = 0;
	} else {
		*pref_nvl = NULL;
		*nprefs = 0;
		ret = SCF_ERROR_NOT_FOUND;
	}

	fmd_hdl_free(hdl, tmparr, nelem * sizeof (nvlist_t *));
pref_done:
	nvlist_free(top_nvl);
	return (ret);
}

/*ARGSUSED*/
static void
syslog_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	uint8_t version;
	boolean_t domsg, *active;
	char *msg;
	nvlist_t **prefs;
	uint_t nprefs, nelems;
	int ret;

	if (nvlist_lookup_uint8(nvl, FM_VERSION, &version) != 0 ||
	    version > FM_SUSPECT_VERSION) {
		fmd_hdl_debug(hdl, "invalid event version: %u\n", version);
		syslog_stats.bad_vers.fmds_value.ui64++;
		return; /* invalid event version */
	}

	if (!syslog_msgall && nvlist_lookup_boolean_value(nvl,
	    FM_SUSPECT_MESSAGE, &domsg) == 0 && !domsg) {
		fmd_hdl_debug(hdl, "%s requested no message\n", class);
		syslog_stats.no_msg.fmds_value.ui64++;
		return; /* event is not to be messaged */
	}

	ret = get_notify_prefs(hdl, nvl, &prefs, &nprefs);
	if (ret == SCF_ERROR_NOT_FOUND) {
		/*
		 * No syslog notification preferences specified for this type of
		 * event, so we're done
		 */
		fmd_hdl_debug(hdl, "No syslog notification preferences "
		    "configured for class %s\n", class);
		syslog_stats.no_msg.fmds_value.ui64++;
		return;
	} else if (ret != 0 || nvlist_lookup_boolean_array(prefs[0], "active",
	    &active, &nelems)) {
		fmd_hdl_debug(hdl, "Failed to retrieve notification "
		    "preferences for class %s\n", class);
		if (ret == 0)
			free_notify_prefs(hdl, prefs, nprefs);
		return;
	} else if (!active[0]) {
		fmd_hdl_debug(hdl, "Syslog notifications disabled for "
		    "class %s\n", class);
		syslog_stats.no_msg.fmds_value.ui64++;
		free_notify_prefs(hdl, prefs, nprefs);
		return;
	}
	free_notify_prefs(hdl, prefs, nprefs);

	if ((msg = fmd_msg_gettext_nv(syslog_msghdl, NULL, nvl)) == NULL) {
		fmd_hdl_debug(hdl, "failed to format message");
		syslog_stats.bad_code.fmds_value.ui64++;
		return; /* libfmd_msg error */
	}

	syslog_ctl.pri &= LOG_FACMASK;
	if (strcmp(class, FM_LIST_ISOLATED_CLASS) == 0 ||
	    strcmp(class, FM_LIST_RESOLVED_CLASS) == 0 ||
	    strcmp(class, FM_LIST_REPAIRED_CLASS) == 0 ||
	    strcmp(class, FM_LIST_UPDATED_CLASS) == 0)
		syslog_ctl.pri |= LOG_NOTICE;
	else
		syslog_ctl.pri |= LOG_ERR;

	syslog_emit(hdl, msg);
	free(msg);
}

static const fmd_prop_t fmd_props[] = {
	{ "console", FMD_TYPE_BOOL, "true" },
	{ "facility", FMD_TYPE_STRING, "LOG_DAEMON" },
	{ "gmt", FMD_TYPE_BOOL, "false" },
	{ "syslogd", FMD_TYPE_BOOL, "true" },
	{ "url", FMD_TYPE_STRING, "http://illumos.org/msg/" },
	{ "message_all", FMD_TYPE_BOOL, "false" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	syslog_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_hdl_info_t fmd_info = {
	"Syslog Messaging Agent", "1.1", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	const struct facility *fp;
	char *facname, *tz, *rootdir, *urlbase;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* invalid data in configuration file */

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (syslog_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&syslog_stats);

	if ((syslog_logfd = open("/dev/conslog", O_WRONLY | O_NOCTTY)) == -1)
		fmd_hdl_abort(hdl, "syslog-msgs failed to open /dev/conslog");

	if ((syslog_msgfd = open("/dev/sysmsg", O_WRONLY | O_NOCTTY)) == -1)
		fmd_hdl_abort(hdl, "syslog-msgs failed to open /dev/sysmsg");

	/*
	 * If the "gmt" property is set to true, force our EVENT-TIME to be
	 * reported in GMT time; otherwise we use localtime.  tzset() affects
	 * the results of subsequent calls to strftime(3C) above.
	 */
	if (fmd_prop_get_int32(hdl, "gmt") == FMD_B_TRUE &&
	    ((tz = getenv("TZ")) == NULL || strcmp(tz, "GMT") != 0)) {
		(void) putenv(fmd_hdl_strdup(hdl, "TZ=GMT", FMD_SLEEP));
		tzset(); /* reload env */
	}

	/*
	 * Look up the value of the "facility" property and use it to determine
	 * what syslog LOG_* facility value we use to fill in our log_ctl_t.
	 * The details of our logging method are described above syslog_emit().
	 */
	facname = fmd_prop_get_string(hdl, "facility");

	for (fp = syslog_facs; fp->fac_name != NULL; fp++) {
		if (strcmp(fp->fac_name, facname) == 0)
			break;
	}

	if (fp->fac_name == NULL)
		fmd_hdl_abort(hdl, "invalid 'facility' setting: %s\n", facname);

	fmd_prop_free_string(hdl, facname);
	syslog_ctl.pri = fp->fac_value;
	syslog_ctl.flags = SL_CONSOLE | SL_LOGONLY;

	/*
	 * Cache any properties we use every time we receive an event and
	 * subscribe to list.suspect events regardless of the .conf file.
	 */
	syslog_file = fmd_prop_get_int32(hdl, "syslogd");
	syslog_cons = fmd_prop_get_int32(hdl, "console");
	syslog_msgall = fmd_prop_get_int32(hdl, "message_all");

	rootdir = fmd_prop_get_string(hdl, "fmd.rootdir");
	syslog_msghdl = fmd_msg_init(rootdir, FMD_MSG_VERSION);
	fmd_prop_free_string(hdl, rootdir);

	if (syslog_msghdl == NULL)
		fmd_hdl_abort(hdl, "failed to initialize libfmd_msg");

	urlbase = fmd_prop_get_string(hdl, "url");
	(void) fmd_msg_url_set(syslog_msghdl, urlbase);
	fmd_prop_free_string(hdl, urlbase);

	/*
	 * We subscribe to all FM events and then consult the notification
	 * preferences in the serice configuration repo to determine whether
	 * or not to emit a console message.
	 */
	fmd_hdl_subscribe(hdl, FM_LIST_SUSPECT_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_REPAIRED_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_RESOLVED_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_ISOLATED_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_UPDATED_CLASS);
}

/*ARGSUSED*/
void
_fmd_fini(fmd_hdl_t *hdl)
{
	fmd_msg_fini(syslog_msghdl);
	(void) close(syslog_logfd);
	(void) close(syslog_msgfd);
}
