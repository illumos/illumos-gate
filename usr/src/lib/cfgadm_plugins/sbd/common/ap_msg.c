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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <macros.h>
#include <errno.h>
#include <locale.h>
#include <libdevinfo.h>
#include <librcm.h>
#define	CFGA_PLUGIN_LIB
#include <config_admin.h>
#include "ap.h"

#ifdef	SBD_DEBUG

static FILE *debug_fp;

int
debugging(void)
{
	char *ep;
	static int inited;

	if (inited)
		return (debug_fp != NULL);
	inited = 1;

	if ((ep = getenv("SBD_DEBUG")) == NULL)
		return (0);

	if (*ep == '\0')
		debug_fp = stderr;
	else {
		if ((debug_fp = fopen(ep, "a")) == NULL)
			return (0);
	}
	(void) fprintf(debug_fp, "\nDebug started, pid=%d\n", (int)getpid());
	return (1);
}

/*PRINTFLIKE1*/
void
dbg(char *fmt, ...)
{
	va_list ap;

	if (!debugging())
		return;

	va_start(ap, fmt);
	(void) vfprintf(debug_fp, fmt, ap);
	va_end(ap);
}
#endif

static char *
ap_err_fmts[] = {
	"command invalid: %s",
	"%s %s: %s%s%s",			/* command failed */
	"%s %s",				/* command nacked */
	"command not supported: %s %s",
	"command aborted: %s %s",
	"option invalid: %s",
	"option requires value: %s",
	"option requires no value: %s",
	"option value invalid: %s %s",
	"attachment point invalid: %s",
	"component invalid: %s",
	"sequence invalid: %s (%s %s) %s",
	"change signal disposition failed",
	"cannot get RCM handle",
	"RCM %s failed for %s",
	"\n%-30s %-10s %s",
	"cannot open %s%s%s",
	"cannot find symbol %s in %s",
	"cannot stat %s: %s",
	"not enough memory",
	"%s plugin: %s",
	"unknown error",
	NULL
};

#define	ap_err_fmt(i)		ap_err_fmts[min((uint_t)(i), ERR_NONE)]

static char *
ap_msg_fmts[] = {
	"%s %s\n",
	"%s %s skipped\n",
	"System may be temporarily suspended, proceed",
	"%s %s aborted\n",
	"%s %s done\n",
	"%s %s failed\n",
	"RCM library not found, feature will be disabled\n",
	"Unknown message\n",
	NULL
};

#define	ap_msg_fmt(i)		ap_msg_fmts[min((uint_t)(i), MSG_NONE)]

#define	STR_BD			"board"
#define	STR_SEP			": "
#define	STR_NULL		"NULL"
#define	STR_CMD_UNKNOWN		"unknown command"
#define	STR_ERR_UNKNOWN		"unknown error"
#define	STR_MSG_UNKNOWN		"unknown message\n"
#define	STR_TGT_UNKNOWN		"unknown target"

#define	get_cmd(c, ap, v) \
{ \
	(v) = va_arg((ap), int); \
	if (((c) = ap_cmd_name((v))) == NULL) \
		(c) = STR_CMD_UNKNOWN; \
}
#define	get_tgt(t, ap) {\
	(t) = va_arg((ap), char *); \
	if (!str_valid((t))) \
		(t) = STR_TGT_UNKNOWN; \
}
#define	check_tgt(tgt, t) {\
	if (str_valid((tgt))) \
		(t) = (tgt); \
	else \
		(t) = STR_TGT_UNKNOWN; \
}
#define	get_str(v, ap, d) \
{ \
	(v) = va_arg((ap), char *); \
	if ((v) == NULL) \
		(v) = (d); \
}

static char *
ap_stnames[] = {
	"unknown state",
	"empty",
	"disconnected",
	"connected",
	"unconfigured",
	"configured"
};

/*
 * ap_err() accepts a variable number of message IDs and constructs
 * a corresponding error string.  ap_err() calls dgettext() to
 * internationalize the proper portions of a message.  If a system
 * error was encountered (errno set), ap_err() looks for the error
 * string corresponding to the returned error code if one is available.
 * If not, the standard libc error string is fetched.
 */
void
ap_err(apd_t *a, ...)
{
	int v;
	int err;
	int len;
	char *p;
	char *sep;
	char *rsep;
	const char *fmt;
	char *cmd;
	char *value;
	char *target;
	char *serr;
	char *syserr;
	char *rstate;
	char *ostate;
	char *srsrc;
	char *sysrsrc;
	char *option;
	char *path;
	char *sym;
	char *msg;
	const char *error;
	char **errstring;
	char *rinfostr = NULL;
	va_list ap;

	DBG("ap_err(%p)\n", (void *)a);

	/*
	 * If there is no descriptor or string pointer or if
	 * there is an outstanding error, just return.
	 */
	if (a == NULL || (errstring = a->errstring) == NULL ||
	    *errstring != NULL)
		return;

	va_start(ap, a);

	err = va_arg(ap, int);

	if ((fmt = ap_err_fmt(err)) == NULL)
		fmt = STR_ERR_UNKNOWN;
	fmt = dgettext(TEXT_DOMAIN, fmt);
	len = strlen(fmt);

	sep = "";
	serr = NULL;
	srsrc = NULL;
	error = NULL;

	/*
	 * Get the proper arguments for the error.
	 */
	switch (err) {
	case ERR_CMD_ABORT:
	case ERR_CMD_FAIL:
	case ERR_CMD_NACK:
		get_cmd(cmd, ap, v);
		check_tgt(a->target, target);
		len += strlen(cmd) + strlen(target);
		DBG("<%s><%s>", cmd, target);
		break;
	case ERR_CMD_NOTSUPP:
		get_cmd(cmd, ap, v);
		if (a->tgt == AP_BOARD)
			target = STR_BD;
		else
			check_tgt(a->cname, target);
		len += strlen(cmd) + strlen(target);
		DBG("<%s><%s>", cmd, target);
		break;
	case ERR_AP_INVAL:
		check_tgt((char *)a->apid, target);
		len += strlen(target);
		DBG("<%s>", target);
		break;
	case ERR_CMD_INVAL:
	case ERR_CM_INVAL:
	case ERR_OPT_INVAL:
	case ERR_OPT_NOVAL:
	case ERR_OPT_VAL:
	case ERR_OPT_BADVAL:
		get_str(option, ap, STR_NULL);
		len += strlen(option);
		DBG("<%s>", option);
		if (err != ERR_OPT_BADVAL)
			break;
		get_str(value, ap, STR_NULL);
		len += strlen(value);
		DBG("<%s>", value);
		break;
	case ERR_TRANS_INVAL: {
		cfga_stat_t rs, os;

		get_cmd(cmd, ap, v);
		check_tgt(a->target, target);
		len += strlen(cmd) + strlen(target);
		ap_state(a, &rs, &os);
		rstate = ap_stnames[rs];
		ostate = ap_stnames[os];
		len += strlen(rstate) + strlen(ostate);
		DBG("<%s><%s><%s><%s>", cmd, target, rstate, ostate);
		break;
	}
	case ERR_RCM_CMD: {

		get_cmd(cmd, ap, v);
		check_tgt(a->target, target);
		len += strlen(cmd) + strlen(target);
		DBG("<%s><%s>", cmd, target);

		if ((ap_rcm_info(a, &rinfostr) == 0) && (rinfostr != NULL)) {
			len += strlen(rinfostr);
		}

		break;
	}
	case ERR_LIB_OPEN:
		get_str(path, ap, STR_NULL);
		get_str(error, ap, "");
		if (str_valid(error))
			sep = STR_SEP;
		DBG("<%s><%s>", path, error);
		break;
	case ERR_LIB_SYM:
		get_str(path, ap, STR_NULL);
		get_str(sym, ap, STR_NULL);
		DBG("<%s><%s>", path, sym);
		break;
	case ERR_STAT:
		get_str(path, ap, STR_NULL);
		break;
	case ERR_PLUGIN:
		get_str(msg, ap, STR_NULL);
		break;
	default:
		DBG("<NOARGS>");
		break;
	}

	va_end(ap);

	/*
	 * In case of a system error, get the reason for
	 * the failure as well as the resource if availbale.
	 * If we already got some error info (e.g. from RCM)
	 * don't bother looking.
	 */
	if (!str_valid(error) && errno) {
		sep = STR_SEP;
		sysrsrc = NULL;
		if ((syserr = ap_sys_err(a, &sysrsrc)) == NULL)
			syserr = STR_ERR_UNKNOWN;
		else
			serr = syserr;

		syserr = dgettext(TEXT_DOMAIN, syserr);

		if (sysrsrc == NULL)
			sysrsrc = "";
		else
			srsrc = sysrsrc;

		len += strlen(syserr) + strlen(sysrsrc);

		if (str_valid(sysrsrc)) {
			rsep = STR_SEP;
			len += strlen(rsep);
		} else
			rsep = "";

		DBG("<%s><%s><%s>", syserr, rsep, sysrsrc);

	} else
		syserr = rsep = sysrsrc = "";

	DBG("\n");

	if ((p = (char *)calloc(len, 1)) != NULL)
		*errstring = p;

	/*
	 * Print the string with appropriate arguments.
	 */
	switch (err) {
	case ERR_CMD_FAIL:
		(void) snprintf(p, len, fmt, cmd, target,
		    syserr, rsep, sysrsrc);
		break;
	case ERR_CMD_ABORT:
	case ERR_CMD_NACK:
	case ERR_CMD_NOTSUPP:
		(void) snprintf(p, len, fmt, cmd, target);
		break;
	case ERR_AP_INVAL:
		(void) snprintf(p, len, fmt, target);
		break;
	case ERR_CMD_INVAL:
	case ERR_CM_INVAL:
	case ERR_OPT_INVAL:
	case ERR_OPT_NOVAL:
	case ERR_OPT_VAL:
		(void) snprintf(p, len, fmt, option);
		break;
	case ERR_OPT_BADVAL:
		(void) snprintf(p, len, fmt, option, value);
		break;
	case ERR_TRANS_INVAL:
		(void) snprintf(p, len, fmt, cmd, rstate, ostate, target);
		break;
	case ERR_SIG_CHANGE:
	case ERR_RCM_HANDLE:
		(void) snprintf(p, len, fmt);
		break;
	case ERR_RCM_CMD:
		/*
		 * If the rinfostr has a string, then the librcm has returned
		 * us a text field of its reasons why the command failed.
		 *
		 * If the rinfostr is not returning data, we will use
		 * the standard ap_err_fmts[] for the rcm error.
		 */
		if (rinfostr != NULL)
			(void) snprintf(p, len, "%s", rinfostr);
		else
			(void) snprintf(p, len, fmt, cmd, target);
		break;
	case ERR_LIB_OPEN:
		(void) snprintf(p, len, fmt, path, sep, error);
		break;
	case ERR_LIB_SYM:
		(void) snprintf(p, len, fmt, sym, path);
		break;
	case ERR_STAT:
		(void) snprintf(p, len, fmt, path, syserr);
		break;
	case ERR_NOMEM:
		(void) snprintf(p, len, fmt);
		break;
	case ERR_PLUGIN:
		(void) snprintf(p, len, fmt, a->class, msg);
		break;
	default:
		break;
	}

	if (serr)
		free(serr);
	if (srsrc)
		free(srsrc);
}

/*
 * ap_msg() accepts a variable number of message IDs and constructs
 * a corresponding message string which is printed via the message print
 * routine argument.  ap_msg() internationalizes the appropriate portion
 * of the message.
 */
void
ap_msg(apd_t *a, ...)
{
	int v;
	int len;
	char *p;
	const char *fmt;
	char *cmd;
	char *target;
	struct cfga_msg *msgp;
	va_list ap;

	DBG("ap_msg(%p)\n", (void *)a);

	if (a == NULL || ap_getopt(a, OPT_VERBOSE) == 0)
		return;

	msgp = a->msgp;

	if (msgp == NULL || msgp->message_routine == NULL)
		return;

	va_start(ap, a);

	v = va_arg(ap, int);

	if ((fmt = ap_msg_fmt(v)) == NULL)
		fmt = STR_MSG_UNKNOWN;
	fmt = dgettext(TEXT_DOMAIN, fmt);
	len = strlen(fmt) + 128;	/* slop */

	DBG("<%d>", v);

	switch (v) {
	case MSG_ISSUE:
	case MSG_SKIP:
	case MSG_ABORT:
	case MSG_FAIL:
	case MSG_DONE:
		get_cmd(cmd, ap, v);
		get_tgt(target, ap);
		DBG("<%s><%s>\n", cmd, target);
		len += strlen(cmd) + strlen(target);
		break;
	default:
		break;
	}

	va_end(ap);

	if ((p = (char *)calloc(len, 1)) == NULL)
		return;

	(void) snprintf(p, len, fmt, cmd, target);

	(*msgp->message_routine)(msgp->appdata_ptr, p);
	free(p);
}

int
ap_confirm(apd_t *a)
{
	int rc;
	char *msg;
	struct cfga_confirm *confp;

	if (a == NULL)
		return (0);

	confp = a->confp;

	if (confp == NULL || confp->confirm == NULL)
		return (0);

	msg = dgettext(TEXT_DOMAIN, ap_msg_fmt(MSG_SUSPEND));

	rc = (*confp->confirm)(confp->appdata_ptr, msg);

	return (rc);
}
