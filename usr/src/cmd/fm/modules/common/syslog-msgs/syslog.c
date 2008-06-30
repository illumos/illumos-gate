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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fm/protocol.h>
#include <sys/strlog.h>
#include <sys/log.h>
#include <fm/fmd_api.h>
#include <fm/fmd_msg.h>

#include <stropts.h>
#include <syslog.h>
#include <locale.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

/*
 * SYSLOG_DOMAIN and SYSLOG_TEMPLATE define the dgettext() parameters the agent
 * can use to retrieve the localized format string for diagnosis messages.
 * The format string retrieved from SYSLOG_DOMAIN is the default format
 * string, but when processing each suspect list, dgettext() is also called
 * for the domain that matches the diagcode dictname and if SYSLOG_TEMPLATE
 * is defined, it overrides the default for that suspect list only.
 *
 * Similarly, SYSLOG_URL is also checked to see if syslog_url
 * should be overridden for each suspect list.
 *
 * The net effect of all this is that for a given diagcode DICT-1234-56:
 *
 *	- If DICT.mo defines syslog-msgs-message-template, it is used
 *	  as the format string for the diagnosis message.
 *
 *	- Otherwise, syslog-msgs-message-template from FMD.mo is used.
 *
 *	- If DICT.mo defines syslog-url, it is used when filling
 *	  in the %s in the "description" message.
 *
 *	- Otherwise, if syslog-msgs.conf defines a "url" property, that
 *	  value is used.
 *
 *	- Otherwise, the default "http://sun.com/msg/" is used (via the
 *	  fmd_props[] table defined in this file).
 */
static const char SYSLOG_DOMAIN[] = "FMD";
static const char SYSLOG_TEMPLATE[] = "syslog-msgs-message-template";
static const char SYSLOG_URL[] = "syslog-url";

static struct stats {
	fmd_stat_t bad_vers;
	fmd_stat_t bad_fmri;
	fmd_stat_t bad_code;
	fmd_stat_t bad_time;
	fmd_stat_t log_err;
	fmd_stat_t msg_err;
	fmd_stat_t no_msg;
} syslog_stats = {
	{ "bad_vers", FMD_TYPE_UINT64, "event version is missing or invalid" },
	{ "bad_fmri", FMD_TYPE_UINT64, "event fmri is missing or invalid" },
	{ "bad_code", FMD_TYPE_UINT64, "event code has no dictionary name" },
	{ "bad_time", FMD_TYPE_UINT64, "event time is not properly encoded" },
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

static char *syslog_locdir;	/* l10n messages directory (if alternate) */
static char *syslog_url;	/* current value of "url" property */
static int syslog_msgall;	/* set to message all faults */
static log_ctl_t syslog_ctl;	/* log(7D) meta-data for each msg */
static int syslog_logfd = -1;	/* log(7D) file descriptor */
static int syslog_msgfd = -1;	/* sysmsg(7D) file descriptor */
static int syslog_file;		/* log to syslog_logfd */
static int syslog_cons;		/* log to syslog_msgfd */

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
 * Note: the log driver packet size limit for output via putmsg is LOGMAX_PS.
 * Then we emit the message a second time, without the special prefix, to the
 * sysmsg(7D) device, which handles console redirection and also permits us
 * to output any characters we like to the console, including \n and \r.
 */
/*PRINTFLIKE2*/
static void
syslog_emit(fmd_hdl_t *hdl, const char *msgformat, ...)
{
	struct strbuf ctl, dat;
	uint32_t msgid;

	char *format, c;
	char *buf = NULL;
	size_t formatlen, logmsglen;
	int len;
	va_list ap;

	formatlen = strlen(msgformat) + 64; /* +64 for prefix and \0 */
	format = alloca(formatlen);

	STRLOG_MAKE_MSGID(msgformat, msgid);
	(void) snprintf(format, formatlen,
	    "fmd: [ID %u FACILITY_AND_PRIORITY] %s", msgid, msgformat);

	/*
	 * Figure out the length of the message then allocate a buffer
	 * of adequate size.
	 */
	va_start(ap, msgformat);
	if ((len = vsnprintf(&c, 1, format, ap)) >= 0 &&
	    (buf = fmd_hdl_alloc(hdl, len + 1, FMD_SLEEP)) != NULL)
		(void) vsnprintf(buf, len + 1, format, ap);
	va_end(ap);

	if (buf == NULL)
		return;

	ctl.buf = (void *)&syslog_ctl;
	ctl.len = sizeof (syslog_ctl);

	dat.buf = buf;
	logmsglen = strlen(buf) + 1;

	/*
	 * The underlying log driver won't accept (ERANGE) messages
	 * longer than LOG_MAXPS bytes so don't putmsg more than that.
	 */
	if (logmsglen > LOG_MAXPS)
		dat.len = LOG_MAXPS;
	else
		dat.len = logmsglen;

	if (syslog_file && putmsg(syslog_logfd, &ctl, &dat, 0) != 0) {
		fmd_hdl_debug(hdl, "putmsg failed: %s\n", strerror(errno));
		syslog_stats.log_err.fmds_value.ui64++;
	}

	dat.buf = strchr(buf, ']');
	dat.len = (size_t)(logmsglen - (dat.buf - buf));

	dat.buf[0] = '\r'; /* overwrite ']' with carriage return */
	dat.buf[1] = '\n'; /* overwrite ' ' with newline */

	if (syslog_cons && write(syslog_msgfd, dat.buf, dat.len) != dat.len) {
		fmd_hdl_debug(hdl, "write failed: %s\n", strerror(errno));
		syslog_stats.msg_err.fmds_value.ui64++;
	}

	fmd_hdl_free(hdl, buf, len + 1);
}

/*ARGSUSED*/
static void
syslog_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	char *uuid, *code, *dict, *url, *urlcode, *template, *p;
	char *src_name, *src_vers, *platform, *chassis, *server;
	char *typ, *sev, *fmt, *trfmt, *rsp, *imp, *act, *locdir;
	char desc[1024], date[64];
	boolean_t domsg;

	nvlist_t *fmri, *auth;
	uint8_t version;
	struct tm tm, *tmp;
	int64_t *tv;
	time_t sec;
	uint_t tn = 0;
	char *olang = NULL;
	int locale_c = 0;
	size_t len;

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

	/*
	 * Extract the DE element, which is an FMRI for the diagnosis engine
	 * that made this event, and validate its meta-data before continuing.
	 */
	if (nvlist_lookup_nvlist(nvl, FM_SUSPECT_DE, &fmri) != 0 ||
	    nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &p) != 0 ||
	    strcmp(p, FM_FMRI_SCHEME_FMD) != 0 ||
	    nvlist_lookup_uint8(fmri, FM_VERSION, &version) != 0 ||
	    version > FM_FMD_SCHEME_VERSION ||
	    nvlist_lookup_nvlist(fmri, FM_FMRI_AUTHORITY, &auth) != 0 ||
	    nvlist_lookup_uint8(auth, FM_VERSION, &version) != 0 ||
	    version > FM_FMRI_AUTH_VERSION) {
		syslog_stats.bad_fmri.fmds_value.ui64++;
		return; /* invalid de fmri */
	}

	/*
	 * Extract the relevant identifying elements of the FMRI and authority.
	 * Note: for now, we ignore FM_FMRI_AUTH_DOMAIN (only for SPs).
	 */
	(void) nvlist_lookup_string(fmri, FM_FMRI_FMD_NAME, &src_name);
	(void) nvlist_lookup_string(fmri, FM_FMRI_FMD_VERSION, &src_vers);
	(void) nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT, &platform);
	(void) nvlist_lookup_string(auth, FM_FMRI_AUTH_SERVER, &server);

	if (nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS, &chassis) != 0)
		chassis = "-"; /* chassis serial number may not be present */

	/*
	 * Extract the uuid and diagcode dictionary from the event code.  The
	 * dictionary name is the text preceding the first "-" in the code.
	 */
	(void) nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid);
	(void) nvlist_lookup_string(nvl, FM_SUSPECT_DIAG_CODE, &code);

	if ((p = strchr(code, '-')) == NULL || p == code) {
		fmd_hdl_debug(hdl, "invalid diagnosis code: %s\n", code);
		syslog_stats.bad_code.fmds_value.ui64++;
		return; /* invalid diagnosis code */
	}

	dict = alloca((size_t)(p - code) + 1);
	(void) strncpy(dict, code, (size_t)(p - code));
	dict[(size_t)(p - code)] = '\0';

	/*
	 * Alloca a hunk of memory and use it to create the msgid strings
	 * <code>.type, <code>.severity, <code>.description, and so forth.
	 * These form the msgids we will use to look up the localized text.
	 * Since we've allocated things to be of the right size, we know
	 * than snprintf() can't overflow: INT_MAX is used shut lint up and
	 * avoid code to needlessly recompute the remaining buffer space.
	 */
	typ = alloca(6 * (strlen(code) + 16));
	sev = typ + snprintf(typ, INT_MAX, "%s.type", code) + 1;
	fmt = sev + snprintf(sev, INT_MAX, "%s.severity", code) + 1;
	rsp = fmt + snprintf(fmt, INT_MAX, "%s.description", code) + 1;
	imp = rsp + snprintf(rsp, INT_MAX, "%s.response", code) + 1;
	act = imp + snprintf(imp, INT_MAX, "%s.impact", code) + 1;
	(void) snprintf(act, INT_MAX, "%s.action", code);

	fmd_msg_lock();

	if (syslog_locdir != NULL)
		locdir =  bindtextdomain(dict, syslog_locdir);

	if ((trfmt = dgettext(dict, fmt)) == fmt) {
		/*
		 * We didn't find a translation in the dictionary for the
		 * current language.  The string we passed to gettext is merely
		 * an index - it isn't sufficient, on its own, to be used as the
		 * message.  Fall back to C and try again.
		 */
		olang = setlocale(LC_MESSAGES, NULL);
		if (olang) {
			p = alloca(strlen(olang) + 1);
			olang = strcpy(p, olang);
		}
		locale_c = 1;
		(void) setlocale(LC_MESSAGES, "C");
		trfmt = dgettext(dict, fmt);
	}

	if ((url = dgettext(dict, SYSLOG_URL)) == SYSLOG_URL)
		url = syslog_url;

	/*
	 * If the URL ends with a slash, that indicates the code should be
	 * appended to it.  After formatting the URL, reformat the DESC
	 * text using the URL as an snprintf argument.
	 */
	len = strlen(url);
	if (url[len - 1] == '/') {
		urlcode = alloca(len + strlen(code) + 1);
		(void) snprintf(urlcode, INT_MAX, "%s%s", url, code);
	} else {
		urlcode = url;
	}
	/* LINTED - variable format specifier to snprintf() */
	(void) snprintf(desc, sizeof (desc), trfmt, urlcode);

	/*
	 * Extract the diagnosis time and format it using the locale's default.
	 * strftime() will use GMT or local time based on our "gmt" setting.
	 */
	if (nvlist_lookup_int64_array(nvl, FM_SUSPECT_DIAG_TIME,
	    &tv, &tn) == 0 && tn == 2 && (sec = (time_t)tv[0]) != (time_t)-1 &&
	    (tmp = localtime_r(&sec, &tm)) != NULL)
		(void) strftime(date, sizeof (date), "%C", tmp);
	else {
		syslog_stats.bad_time.fmds_value.ui64++;
		(void) strcpy(date, "-");
	}

	/*
	 * Create and log the final string by filling in the template with the
	 * strings we've created and the strings from the message dictionary.
	 * If a template is provided for this dictionary, use it, otherwise
	 * fall back to the default template.
	 */
	if ((template = dgettext(dict, SYSLOG_TEMPLATE)) == SYSLOG_TEMPLATE)
		template = dgettext(SYSLOG_DOMAIN, SYSLOG_TEMPLATE);

	syslog_ctl.pri &= LOG_FACMASK;
	if (strcmp(class, FM_LIST_REPAIRED_CLASS) == 0)
		syslog_ctl.pri |= LOG_NOTICE;
	else
		syslog_ctl.pri |= LOG_ERR;
	syslog_emit(hdl, template, code, dgettext(dict, typ),
	    dgettext(dict, sev), date, platform, chassis, server, src_name,
	    src_vers, uuid, desc, dgettext(dict, rsp), dgettext(dict, imp),
	    dgettext(dict, act));

	/*
	 * Switch back to our original language if we had to fall back to C.
	 */
	if (olang != NULL)
		(void) setlocale(LC_MESSAGES, olang);

	if (syslog_locdir != NULL)
		(void) bindtextdomain(dict, locdir);

	fmd_msg_unlock();

	if (locale_c) {
		fmd_hdl_debug(hdl,
		    trfmt == fmt ?
		    "dgettext(%s, %s) in %s and C failed\n" :
		    "dgettext(%s, %s) in %s failed; C used\n",
		    dict, fmt, olang ? olang : "<null>");
	}
}

static const fmd_prop_t fmd_props[] = {
	{ "console", FMD_TYPE_BOOL, "true" },
	{ "facility", FMD_TYPE_STRING, "LOG_DAEMON" },
	{ "gmt", FMD_TYPE_BOOL, "false" },
	{ "syslogd", FMD_TYPE_BOOL, "true" },
	{ "url", FMD_TYPE_STRING, "http://sun.com/msg/" },
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
	"Syslog Messaging Agent", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	const struct facility *fp;
	char *facname, *tz, *rootdir, *locdir, *locale, *p;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* invalid data in configuration file */

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (syslog_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&syslog_stats);

	if ((syslog_logfd = open("/dev/conslog", O_WRONLY | O_NOCTTY)) == -1)
		fmd_hdl_abort(hdl, "syslog-msgs failed to open /dev/conslog");

	if ((syslog_msgfd = open("/dev/sysmsg", O_WRONLY | O_NOCTTY)) == -1)
		fmd_hdl_abort(hdl, "syslog-msgs failed to open /dev/sysmsg");

	/*
	 * All FMA event dictionaries use msgfmt(1) message objects to produce
	 * messages, even for the C locale.  We therefore want to use dgettext
	 * for all message lookups, but its defined behavior in the C locale is
	 * to return the input string.  Since our input strings are event codes
	 * and not format strings, this doesn't help us.  We resolve this nit
	 * by setting NLSPATH to a non-existent file: the presence of NLSPATH
	 * is defined to force dgettext(3C) to do a full lookup even for C.
	 */
	if (getenv("NLSPATH") == NULL && putenv(fmd_hdl_strdup(hdl,
	    "NLSPATH=/usr/lib/fm/fmd/fmd.cat", FMD_SLEEP)) != 0)
		fmd_hdl_abort(hdl, "syslog-msgs failed to set NLSPATH");

	fmd_msg_lock();
	(void) setlocale(LC_MESSAGES, "");
	locale = setlocale(LC_MESSAGES, NULL);
	if (locale) {
		p = alloca(strlen(locale) + 1);
		locale = strcpy(p, locale);
	} else {
		locale = "<null>";
	}
	fmd_msg_unlock();
	fmd_hdl_debug(hdl, "locale=%s\n", locale);

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
	syslog_url = fmd_prop_get_string(hdl, "url");
	syslog_msgall = fmd_prop_get_int32(hdl, "message_all");

	/*
	 * If fmd's rootdir property is set to a non-default root, then we are
	 * going to need to rebind the text domains we use for dgettext() as
	 * we go.  Look up the default l10n messages directory and make
	 * syslog_locdir be this path with fmd.rootdir prepended to it.
	 */
	rootdir = fmd_prop_get_string(hdl, "fmd.rootdir");

	if (*rootdir != '\0' && strcmp(rootdir, "/") != 0) {
		fmd_msg_lock();
		locdir = bindtextdomain(SYSLOG_DOMAIN, NULL);
		fmd_msg_unlock();
		if (locdir != NULL) {
			size_t len = strlen(rootdir) + strlen(locdir) + 1;
			syslog_locdir = fmd_hdl_alloc(hdl, len, FMD_SLEEP);
			(void) snprintf(syslog_locdir, len, "%s%s", rootdir,
			    locdir);
			fmd_hdl_debug(hdl,
			    "binding textdomain to %s for syslog\n",
			    syslog_locdir);
		}
	}

	fmd_prop_free_string(hdl, rootdir);
	fmd_hdl_subscribe(hdl, FM_LIST_SUSPECT_CLASS);
	fmd_hdl_subscribe(hdl, FM_LIST_REPAIRED_CLASS);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	fmd_hdl_strfree(hdl, syslog_locdir);
	fmd_prop_free_string(hdl, syslog_url);

	(void) close(syslog_logfd);
	(void) close(syslog_msgfd);
}
