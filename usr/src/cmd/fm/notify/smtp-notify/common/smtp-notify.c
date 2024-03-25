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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <fcntl.h>
#include <libscf.h>
#include <priv_utils.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <zone.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fm/fmd_msg.h>
#include <fm/libfmevent.h>
#include "libfmnotify.h"

#define	SENDMAIL	"/usr/sbin/sendmail"
#define	SVCNAME		"system/fm/smtp-notify"

#define	XHDR_HOSTNAME		"X-FMEV-HOSTNAME"
#define	XHDR_CLASS		"X-FMEV-CLASS"
#define	XHDR_UUID		"X-FMEV-UUID"
#define	XHDR_MSGID		"X-FMEV-CODE"
#define	XHDR_SEVERITY		"X-FMEV-SEVERITY"
#define	XHDR_FMRI		"X-FMEV-FMRI"
#define	XHDR_FROM_STATE		"X-FMEV-FROM-STATE"
#define	XHDR_TO_STATE		"X-FMEV-TO-STATE"

/*
 * Debug messages can be enabled by setting the debug property to true
 *
 * # svccfg -s svc:/system/fm/smtp-notify setprop config/debug=true
 *
 * Debug messages will be spooled to the service log at:
 * <root>/var/svc/log/system-fm-smtp-notify:default.log
 */
#define	PP_SCRIPT "usr/lib/fm/notify/process_msg_template.sh"

typedef struct email_pref
{
	int ep_num_recips;
	char **ep_recips;
	char *ep_reply_to;
	char *ep_template_path;
	char *ep_template;
} email_pref_t;

static nd_hdl_t *nhdl;
static char hostname[MAXHOSTNAMELEN + 1];
static const char optstr[] = "dfR:";
static const char DEF_SUBJ_TEMPLATE[] = "smtp-notify-subject-template";
static const char SMF_SUBJ_TEMPLATE[] = "smtp-notify-smf-subject-template";
static const char FM_SUBJ_TEMPLATE[] = "smtp-notify-fm-subject-template";
static const char IREPORT_MSG_TEMPLATE[] = "ireport-msg-template";
static const char SMF_MSG_TEMPLATE[] = "ireport.os.smf-msg-template";

static int
usage(const char *pname)
{
	(void) fprintf(stderr, "Usage: %s [-df] [-R <altroot>]\n", pname);

	(void) fprintf(stderr,
	    "\t-d  enable debug mode\n"
	    "\t-f  stay in foreground\n"
	    "\t-R  specify alternate root\n");

	return (1);
}

/*
 * This function simply reads the file specified by "template" into a buffer
 * and returns a pointer to that buffer (or NULL on failure).  The caller is
 * responsible for free'ing the returned buffer.
 */
static char *
read_template(const char *template)
{
	int fd;
	struct stat statb;
	char *buf;

	if (stat(template, &statb) != 0) {
		nd_error(nhdl, "Failed to stat %s (%s)", template,
		    strerror(errno));
		return (NULL);
	}
	if ((fd = open(template, O_RDONLY)) < 0) {
		nd_error(nhdl, "Failed to open %s (%s)", template,
		    strerror(errno));
		return (NULL);
	}
	if ((buf = malloc(statb.st_size + 1)) == NULL) {
		nd_error(nhdl, "Failed to allocate %d bytes", statb.st_size);
		(void) close(fd);
		return (NULL);
	}
	if (read(fd, buf, statb.st_size) < 0) {
		nd_error(nhdl, "Failed to read in template (%s)",
		    strerror(errno));
		free(buf);
		(void) close(fd);
		return (NULL);
	}
	buf[statb.st_size] = '\0';
	(void) close(fd);
	return (buf);
}

/*
 * This function runs a user-supplied message body template through a script
 * which replaces the "committed" expansion macros with actual libfmd_msg
 * expansion macros.
 */
static int
process_template(nd_ev_info_t *ev_info, email_pref_t *eprefs)
{
	char pp_script[PATH_MAX], tmpfile[PATH_MAX], pp_cli[PATH_MAX];
	int ret = -1;

	(void) snprintf(pp_script, sizeof (pp_script), "%s%s",
	    nhdl->nh_rootdir, PP_SCRIPT);
	(void) snprintf(tmpfile, sizeof (tmpfile), "%s%s",
	    nhdl->nh_rootdir, tmpnam(NULL));

	/*
	 * If it's an SMF event, then the diagcode and severity won't be part
	 * of the event payload and so libfmd_msg won't be able to expand them.
	 * Therefore we pass the code and severity into the script and let the
	 * script do the expansion.
	 */
	/* LINTED: E_SEC_SPRINTF_UNBOUNDED_COPY */
	(void) sprintf(pp_cli, "%s %s %s %s %s", pp_script,
	    eprefs->ep_template_path, tmpfile, ev_info->ei_diagcode,
	    ev_info->ei_severity);

	nd_debug(nhdl, "Executing %s", pp_cli);
	if (system(pp_cli) != -1)
		if ((eprefs->ep_template = read_template(tmpfile)) != NULL)
			ret = 0;

	(void) unlink(tmpfile);
	return (ret);
}

/*
 * If someone does an "svcadm refresh" on us, then this function gets called,
 * which rereads our service configuration.
 */
static void
get_svc_config()
{
	int s = 0;
	uint8_t val;

	s = nd_get_boolean_prop(nhdl, SVCNAME, "config", "debug", &val);
	nhdl->nh_debug = val;

	s += nd_get_astring_prop(nhdl, SVCNAME, "config", "rootdir",
	    &(nhdl->nh_rootdir));

	if (s != 0)
		nd_error(nhdl, "Failed to read retrieve service "
		    "properties\n");
}

static void
nd_sighandler(int sig)
{
	if (sig == SIGHUP)
		get_svc_config();
	else
		nd_cleanup(nhdl);
}

/*
 * This function constructs all the email headers and puts them into the
 * "headers" buffer handle.  The caller is responsible for free'ing this
 * buffer.
 */
static int
build_headers(nd_hdl_t *nhdl, nd_ev_info_t *ev_info, email_pref_t *eprefs,
    char **headers)
{
	const char *subj_key;
	char *subj_fmt, *subj = NULL;
	size_t len;
	boolean_t is_smf_event = B_FALSE, is_fm_event = B_FALSE;

	/*
	 * Fetch and format the email subject.
	 */
	if (strncmp(ev_info->ei_class, "list.", 5) == 0) {
		is_fm_event = B_TRUE;
		subj_key = FM_SUBJ_TEMPLATE;
	} else if (strncmp(ev_info->ei_class, "ireport.os.smf", 14) == 0) {
		is_smf_event = B_TRUE;
		subj_key = SMF_SUBJ_TEMPLATE;
	} else {
		subj_key = DEF_SUBJ_TEMPLATE;
	}

	if ((subj_fmt = fmd_msg_gettext_key(nhdl->nh_msghdl, NULL,
	    FMNOTIFY_MSG_DOMAIN, subj_key)) == NULL) {
		nd_error(nhdl, "Failed to contruct subject format");
		return (-1); /* libfmd_msg error */
	}

	if (is_fm_event) {
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		len = snprintf(NULL, 0, subj_fmt, hostname,
		    ev_info->ei_diagcode);
		subj = alloca(len + 1);
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(subj, len + 1, subj_fmt, hostname,
		    ev_info->ei_diagcode);
	} else if (is_smf_event) {
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		len = snprintf(NULL, 0, subj_fmt, hostname, ev_info->ei_fmri,
		    ev_info->ei_from_state, ev_info->ei_to_state);
		subj = alloca(len + 1);
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(subj, len + 1, subj_fmt, hostname,
		    ev_info->ei_fmri, ev_info->ei_from_state,
		    ev_info->ei_to_state);
	} else {
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		len = snprintf(NULL, 0, subj_fmt, hostname);
		subj = alloca(len + 1);
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(subj, len + 1, subj_fmt, hostname);
	}

	/*
	 * Here we add some X-headers to our mail message for use by mail
	 * filtering agents.  We add headers for the following bits of event
	 * data for all events
	 *
	 * hostname
	 * msg id (diagcode)
	 * event class
	 * event severity
	 * event uuid
	 *
	 * For SMF transition events, we'll have the following add'l X-headers
	 *
	 * from-state
	 * to-state
	 * service fmri
	 *
	 * We follow the X-headers with standard Reply-To and Subject headers.
	 */
	if (is_fm_event) {
		len = snprintf(NULL, 0, "%s: %s\n%s: %s\n%s: %s\n%s: %s\n"
		    "%s: %s\nReply-To: %s\nSubject: %s\n\n", XHDR_HOSTNAME,
		    hostname, XHDR_CLASS, ev_info->ei_class, XHDR_UUID,
		    ev_info->ei_uuid, XHDR_MSGID, ev_info->ei_diagcode,
		    XHDR_SEVERITY, ev_info->ei_severity, eprefs->ep_reply_to,
		    subj);

		*headers = calloc(len + 1, sizeof (char));

		(void) snprintf(*headers, len + 1, "%s: %s\n%s: %s\n%s: %s\n"
		    "%s: %s\n%s: %s\nReply-To: %s\nSubject: %s\n\n",
		    XHDR_HOSTNAME, hostname, XHDR_CLASS, ev_info->ei_class,
		    XHDR_UUID, ev_info->ei_uuid, XHDR_MSGID,
		    ev_info->ei_diagcode, XHDR_SEVERITY, ev_info->ei_severity,
		    eprefs->ep_reply_to, subj);
	} else if (is_smf_event) {
		len = snprintf(NULL, 0, "%s: %s\n%s: %s\n%s: %s\n%s: %s\n"
		    "%s: %s\n%s: %s\n%s: %s\nReply-To: %s\n"
		    "Subject: %s\n\n", XHDR_HOSTNAME, hostname, XHDR_CLASS,
		    ev_info->ei_class, XHDR_MSGID, ev_info->ei_diagcode,
		    XHDR_SEVERITY, ev_info->ei_severity, XHDR_FMRI,
		    ev_info->ei_fmri, XHDR_FROM_STATE, ev_info->ei_from_state,
		    XHDR_TO_STATE, ev_info->ei_to_state, eprefs->ep_reply_to,
		    subj);

		*headers = calloc(len + 1, sizeof (char));

		(void) snprintf(*headers, len + 1, "%s: %s\n%s: %s\n%s: %s\n"
		    "%s: %s\n%s: %s\n%s: %s\n%s: %s\nReply-To: %s\n"
		    "Subject: %s\n\n", XHDR_HOSTNAME, hostname, XHDR_CLASS,
		    ev_info->ei_class, XHDR_MSGID, ev_info->ei_diagcode,
		    XHDR_SEVERITY, ev_info->ei_severity, XHDR_FMRI,
		    ev_info->ei_fmri, XHDR_FROM_STATE, ev_info->ei_from_state,
		    XHDR_TO_STATE, ev_info->ei_to_state, eprefs->ep_reply_to,
		    subj);
	} else {
		len = snprintf(NULL, 0, "%s: %s\n%s: %s\n%s: %s\n%s: %s\n"
		    "Reply-To: %s\nSubject: %s\n\n", XHDR_HOSTNAME,
		    hostname, XHDR_CLASS, ev_info->ei_class, XHDR_MSGID,
		    ev_info->ei_diagcode, XHDR_SEVERITY, ev_info->ei_severity,
		    eprefs->ep_reply_to, subj);

		*headers = calloc(len + 1, sizeof (char));

		(void) snprintf(*headers, len + 1, "%s: %s\n%s: %s\n%s: %s\n"
		    "%s: %s\nReply-To: %s\nSubject: %s\n\n",
		    XHDR_HOSTNAME, hostname, XHDR_CLASS, ev_info->ei_class,
		    XHDR_MSGID, ev_info->ei_diagcode, XHDR_SEVERITY,
		    ev_info->ei_severity, eprefs->ep_reply_to, subj);
	}
	return (0);
}

static void
send_email(nd_hdl_t *nhdl, const char *headers, const char *body,
    const char *recip)
{
	FILE *mp;
	char sm_cli[PATH_MAX];

	/*
	 * Open a pipe to sendmail and pump out the email message
	 */
	(void) snprintf(sm_cli, PATH_MAX, "%s -t %s", SENDMAIL, recip);

	nd_debug(nhdl, "Sending email notification to %s", recip);
	if ((mp = popen(sm_cli, "w")) == NULL) {
		nd_error(nhdl, "Failed to open pipe to %s (%s)", SENDMAIL,
		    strerror(errno));
		return;
	}
	if (fprintf(mp, "%s", headers) < 0)
		nd_error(nhdl, "Failed to write to pipe (%s)", strerror(errno));

	if (fprintf(mp, "%s\n.\n", body) < 0)
		nd_error(nhdl, "Failed to write to pipe (%s)",
		    strerror(errno));

	(void) pclose(mp);
}

static void
send_email_template(nd_hdl_t *nhdl, nd_ev_info_t *ev_info, email_pref_t *eprefs)
{
	char *msg, *headers;

	if (build_headers(nhdl, ev_info, eprefs, &headers) != 0)
		return;

	/*
	 * If the user specified a message body template, then we pass it
	 * through a private interface in libfmd_msg, which will return a string
	 * with any expansion tokens decoded.
	 */
	if ((msg = fmd_msg_decode_tokens(ev_info->ei_payload,
	    eprefs->ep_template, ev_info->ei_url)) == NULL) {
		nd_error(nhdl, "Failed to parse msg template");
		free(headers);
		return;
	}
	for (int i = 0; i < eprefs->ep_num_recips; i++)
		send_email(nhdl, headers, msg, eprefs->ep_recips[i]);

	free(msg);
	free(headers);
}

static int
get_email_prefs(nd_hdl_t *nhdl, fmev_t ev, email_pref_t **eprefs)
{
	nvlist_t **p_nvl = NULL;
	email_pref_t *ep;
	uint_t npref, tn1 = 0, tn2 = 0;
	char **tmparr1, **tmparr2;
	int r, ret = -1;

	r = nd_get_notify_prefs(nhdl, "smtp", ev, &p_nvl, &npref);
	if (r == SCF_ERROR_NOT_FOUND) {
		/*
		 * No email notification preferences specified for this type of
		 * event, so we're done
		 */
		return (-1);
	} else if (r != 0) {
		nd_error(nhdl, "Failed to retrieve notification preferences "
		    "for this event");
		return (-1);
	}

	if ((ep = malloc(sizeof (email_pref_t))) == NULL) {
		nd_error(nhdl, "Failed to allocate space for email preferences "
		    "(%s)", strerror(errno));
		goto eprefs_done;
	}
	(void) memset(ep, 0, sizeof (email_pref_t));

	/*
	 * For SMF state transition events, pref_nvl may contain two sets of
	 * preferences, which will have to be merged.
	 *
	 * The "smtp" nvlist can contain up to four members:
	 *
	 * "active"	- boolean - used to toggle notfications
	 * "to"		- a string array of email recipients
	 * "reply-to"	- a string array containing the reply-to addresses
	 *		- this is optional and defaults to root@localhost
	 * "msg_template" - the pathname of a user-supplied message body
	 *		template
	 *
	 * In the case that we have two sets of preferences, we will merge them
	 * using the following rules:
	 *
	 * "active" will be set to true, if it is true in either set
	 *
	 * The "reply-to" and "to" lists will be merged, with duplicate email
	 * addresses removed.
	 */
	if (npref == 2) {
		boolean_t *act1, *act2;
		char **arr1, **arr2, **strarr, **reparr1, **reparr2;
		uint_t n1, n2, arrsz, repsz;

		r = nvlist_lookup_boolean_array(p_nvl[0], "active", &act1, &n1);
		r += nvlist_lookup_boolean_array(p_nvl[1], "active", &act2,
		    &n2);
		r += nvlist_lookup_string_array(p_nvl[0], "to", &arr1, &n1);
		r += nvlist_lookup_string_array(p_nvl[1], "to", &arr2, &n2);

		if (r != 0) {
			nd_error(nhdl, "Malformed email notification "
			    "preferences");
			nd_dump_nvlist(nhdl, p_nvl[0]);
			nd_dump_nvlist(nhdl, p_nvl[1]);
			goto eprefs_done;
		} else if (!act1[0] && !act2[0]) {
			nd_debug(nhdl, "Email notification is disabled");
			goto eprefs_done;
		}

		if (nd_split_list(nhdl, arr1[0], ",", &tmparr1, &tn1) != 0 ||
		    nd_split_list(nhdl, arr2[0], ",", &tmparr2, &tn2) != 0) {
			nd_error(nhdl, "Error parsing \"to\" lists");
			nd_dump_nvlist(nhdl, p_nvl[0]);
			nd_dump_nvlist(nhdl, p_nvl[1]);
			goto eprefs_done;
		}

		if ((ep->ep_num_recips = nd_merge_strarray(nhdl, tmparr1, tn1,
		    tmparr2, tn2, &ep->ep_recips)) < 0) {
			nd_error(nhdl, "Error merging email recipient lists");
			goto eprefs_done;
		}

		r = nvlist_lookup_string_array(p_nvl[0], "reply-to", &arr1,
		    &n1);
		r += nvlist_lookup_string_array(p_nvl[1], "reply-to", &arr2,
		    &n2);
		repsz = n1 = n2 = 0;
		if (!r &&
		    nd_split_list(nhdl, arr1[0], ",", &reparr1, &n1) != 0 ||
		    nd_split_list(nhdl, arr2[0], ",", &reparr2, &n2) != 0 ||
		    (repsz = nd_merge_strarray(nhdl, tmparr1, n1, tmparr2, n2,
		    &strarr)) != 0 ||
		    nd_join_strarray(nhdl, strarr, repsz, &ep->ep_reply_to)
		    != 0) {

			ep->ep_reply_to = strdup("root@localhost");
		}
		if (n1)
			nd_free_strarray(reparr1, n1);
		if (n2)
			nd_free_strarray(reparr2, n2);
		if (repsz > 0)
			nd_free_strarray(strarr, repsz);

		if (nvlist_lookup_string_array(p_nvl[0], "msg_template",
		    &strarr, &arrsz) == 0)
			ep->ep_template_path = strdup(strarr[0]);
	} else {
		char **strarr, **tmparr;
		uint_t arrsz;
		boolean_t *active;

		/*
		 * Both the "active" and "to" notification preferences are
		 * required, so if we have trouble looking either of these up
		 * we return an error.  We will also return an error if "active"
		 * is set to false.  Returning an error will cause us to not
		 * send a notification for this event.
		 */
		r = nvlist_lookup_boolean_array(p_nvl[0], "active", &active,
		    &arrsz);
		r += nvlist_lookup_string_array(p_nvl[0], "to", &strarr,
		    &arrsz);

		if (r != 0) {
			nd_error(nhdl, "Malformed email notification "
			    "preferences");
			nd_dump_nvlist(nhdl, p_nvl[0]);
			goto eprefs_done;
		} else if (!active[0]) {
			nd_debug(nhdl, "Email notification is disabled");
			goto eprefs_done;
		}

		if (nd_split_list(nhdl, strarr[0], ",", &tmparr, &arrsz)
		    != 0) {
			nd_error(nhdl, "Error parsing \"to\" list");
			goto eprefs_done;
		}
		ep->ep_num_recips = arrsz;
		ep->ep_recips = tmparr;

		if (nvlist_lookup_string_array(p_nvl[0], "msg_template",
		    &strarr, &arrsz) == 0)
			ep->ep_template_path = strdup(strarr[0]);

		if (nvlist_lookup_string_array(p_nvl[0], "reply-to", &strarr,
		    &arrsz) == 0)
			ep->ep_reply_to = strdup(strarr[0]);
		else
			ep->ep_reply_to = strdup("root@localhost");
	}
	ret = 0;
	*eprefs = ep;
eprefs_done:
	if (ret != 0) {
		if (ep->ep_recips)
			nd_free_strarray(ep->ep_recips, ep->ep_num_recips);
		if (ep->ep_reply_to)
			free(ep->ep_reply_to);
		free(ep);
	}
	if (tn1)
		nd_free_strarray(tmparr1, tn1);
	if (tn2)
		nd_free_strarray(tmparr2, tn2);
	nd_free_nvlarray(p_nvl, npref);

	return (ret);
}

/*ARGSUSED*/
static void
irpt_cbfunc(fmev_t ev, const char *class, nvlist_t *nvl, void *arg)
{
	char *body_fmt, *headers = NULL, *body = NULL, tstamp[32];
	struct tm ts;
	size_t len;
	nd_ev_info_t *ev_info = NULL;
	email_pref_t *eprefs;

	nd_debug(nhdl, "Received event of class %s", class);

	if (get_email_prefs(nhdl, ev, &eprefs) < 0)
		return;

	if (nd_get_event_info(nhdl, class, ev, &ev_info) != 0)
		goto irpt_done;

	/*
	 * If the user specified a template, then we pass it through a script,
	 * which post-processes any expansion macros.  Then we attempt to read
	 * it in and then send the message.  Otherwise we carry on with the rest
	 * of this function which will contruct the message body from one of the
	 * default templates.
	 */
	if (eprefs->ep_template != NULL)
		free(eprefs->ep_template);

	if (eprefs->ep_template_path != NULL &&
	    process_template(ev_info, eprefs) == 0) {
		send_email_template(nhdl, ev_info, eprefs);
		goto irpt_done;
	}

	/*
	 * Fetch and format the event timestamp
	 */
	if (fmev_localtime(ev, &ts) == NULL) {
		nd_error(nhdl, "Malformed event: failed to retrieve "
		    "timestamp");
		goto irpt_done;
	}
	(void) strftime(tstamp, sizeof (tstamp), NULL, &ts);

	/*
	 * We have two message body templates to choose from.  One for SMF
	 * service transition events and a generic one for any other
	 * uncommitted ireport.
	 */
	if (strncmp(class, "ireport.os.smf", 14) == 0) {
		/*
		 * For SMF state transition events we have a standard message
		 * template that we fill in based on the payload of the event.
		 */
		if ((body_fmt = fmd_msg_gettext_key(nhdl->nh_msghdl, NULL,
		    FMNOTIFY_MSG_DOMAIN, SMF_MSG_TEMPLATE)) == NULL) {
			nd_error(nhdl, "Failed to format message body");
			goto irpt_done;
		}

		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		len = snprintf(NULL, 0, body_fmt, hostname, tstamp,
		    ev_info->ei_fmri, ev_info->ei_from_state,
		    ev_info->ei_to_state, ev_info->ei_descr,
		    ev_info->ei_reason);
		body = calloc(len, sizeof (char));
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(body, len, body_fmt, hostname, tstamp,
		    ev_info->ei_fmri, ev_info->ei_from_state,
		    ev_info->ei_to_state, ev_info->ei_descr,
		    ev_info->ei_reason);
	} else {
		if ((body_fmt = fmd_msg_gettext_key(nhdl->nh_msghdl, NULL,
		    FMNOTIFY_MSG_DOMAIN, IREPORT_MSG_TEMPLATE)) == NULL) {
			nd_error(nhdl, "Failed to format message body");
			goto irpt_done;
		}
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		len = snprintf(NULL, 0, body_fmt, hostname, tstamp, class);
		body = calloc(len, sizeof (char));
		/* LINTED: E_SEC_PRINTF_VAR_FMT */
		(void) snprintf(body, len, body_fmt, hostname, tstamp, class);
	}

	if (build_headers(nhdl, ev_info, eprefs, &headers) != 0)
		goto irpt_done;

	/*
	 * Everything is ready, so now we just iterate through the list of
	 * recipents, sending an email notification to each one.
	 */
	for (int i = 0; i < eprefs->ep_num_recips; i++)
		send_email(nhdl, headers, body, eprefs->ep_recips[i]);

irpt_done:
	free(headers);
	free(body);
	if (ev_info)
		nd_free_event_info(ev_info);
	if (eprefs->ep_recips)
		nd_free_strarray(eprefs->ep_recips, eprefs->ep_num_recips);
	if (eprefs->ep_reply_to)
		free(eprefs->ep_reply_to);
	free(eprefs);
}

/*
 * There is a lack of uniformity in how the various entries in our diagnosis
 * are terminated.  Some end with one newline, others with two.  This makes the
 * output look a bit ugly.  Therefore we postprocess the message before sending
 * it, removing consecutive occurences of newlines.
 */
static void
postprocess_msg(char *msg)
{
	int i = 0, j = 0;
	char *buf;

	if ((buf = malloc(strlen(msg) + 1)) == NULL)
		return;

	buf[j++] = msg[i++];
	for (i = 1; i < strlen(msg); i++) {
		if (!(msg[i] == '\n' && msg[i - 1] == '\n'))
			buf[j++] = msg[i];
	}
	buf[j] = '\0';
	(void) strncpy(msg, buf, j+1);
	free(buf);
}

/*ARGSUSED*/
static void
listev_cb(fmev_t ev, const char *class, nvlist_t *nvl, void *arg)
{
	char *body = NULL, *headers = NULL;
	nd_ev_info_t *ev_info = NULL;
	boolean_t domsg;
	email_pref_t *eprefs;

	nd_debug(nhdl, "Received event of class %s", class);

	if (get_email_prefs(nhdl, ev, &eprefs) < 0)
		return;

	if (nd_get_event_info(nhdl, class, ev, &ev_info) != 0)
		goto listcb_done;

	/*
	 * If the message payload member is set to 0, then it's an event we
	 * typically suppress messaging on, so we won't send an email for it.
	 */
	if (nvlist_lookup_boolean_value(ev_info->ei_payload, FM_SUSPECT_MESSAGE,
	    &domsg) == 0 && !domsg) {
		nd_debug(nhdl, "Messaging suppressed for this event");
		goto listcb_done;
	}

	/*
	 * If the user specified a template, then we pass it through a script,
	 * which post-processes any expansion macros.  Then we attempt to read
	 * it in and then send the message.  Otherwise we carry on with the rest
	 * of this function which will contruct the message body from one of the
	 * default templates.
	 */
	if (eprefs->ep_template != NULL)
		free(eprefs->ep_template);

	if (eprefs->ep_template_path != NULL &&
	    process_template(ev_info, eprefs) == 0) {
		send_email_template(nhdl, ev_info, eprefs);
		goto listcb_done;
	}

	/*
	 * Format the message body
	 *
	 * For FMA list.* events we use the same message that the
	 * syslog-msgs agent would emit as the message body
	 *
	 */
	if ((body = fmd_msg_gettext_nv(nhdl->nh_msghdl, NULL,
	    ev_info->ei_payload)) == NULL) {
		nd_error(nhdl, "Failed to format message body");
		nd_dump_nvlist(nhdl, ev_info->ei_payload);
		goto listcb_done;
	}
	postprocess_msg(body);

	if (build_headers(nhdl, ev_info, eprefs, &headers) != 0)
		goto listcb_done;

	/*
	 * Everything is ready, so now we just iterate through the list of
	 * recipents, sending an email notification to each one.
	 */
	for (int i = 0; i < eprefs->ep_num_recips; i++)
		send_email(nhdl, headers, body, eprefs->ep_recips[i]);

listcb_done:
	free(headers);
	free(body);
	if (ev_info)
		nd_free_event_info(ev_info);
	if (eprefs->ep_recips)
		nd_free_strarray(eprefs->ep_recips, eprefs->ep_num_recips);
	if (eprefs->ep_reply_to)
		free(eprefs->ep_reply_to);
	free(eprefs);
}

int
main(int argc, char *argv[])
{
	struct rlimit rlim;
	struct sigaction act;
	sigset_t set;
	int c;
	boolean_t run_fg = B_FALSE;

	if ((nhdl = malloc(sizeof (nd_hdl_t))) == NULL) {
		(void) fprintf(stderr, "Failed to allocate space for notifyd "
		    "handle (%s)", strerror(errno));
		return (1);
	}
	(void) memset(nhdl, 0, sizeof (nd_hdl_t));

	nhdl->nh_keep_running = B_TRUE;
	nhdl->nh_log_fd = stderr;
	nhdl->nh_pname = argv[0];

	get_svc_config();

	/*
	 * In the case where we get started outside of SMF, args passed on the
	 * command line override SMF property setting
	 */
	while (optind < argc) {
		while ((c = getopt(argc, argv, optstr)) != -1) {
			switch (c) {
			case 'd':
				nhdl->nh_debug = B_TRUE;
				break;
			case 'f':
				run_fg = B_TRUE;
				break;
			case 'R':
				nhdl->nh_rootdir = strdup(optarg);
				break;
			default:
				free(nhdl);
				return (usage(argv[0]));
			}
		}
	}

	/*
	 * Set up a signal handler for SIGTERM (and SIGINT if we'll
	 * be running in the foreground) to ensure sure we get a chance to exit
	 * in an orderly fashion.  We also catch SIGHUP, which will be sent to
	 * us by SMF if the service is refreshed.
	 */
	(void) sigfillset(&set);
	(void) sigfillset(&act.sa_mask);
	act.sa_handler = nd_sighandler;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);
	(void) sigdelset(&set, SIGTERM);
	(void) sigaction(SIGHUP, &act, NULL);
	(void) sigdelset(&set, SIGHUP);

	if (run_fg) {
		(void) sigaction(SIGINT, &act, NULL);
		(void) sigdelset(&set, SIGINT);
	} else
		nd_daemonize(nhdl);

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_CORE, &rlim);

	/*
	 * We need to be root to initialize our libfmevent handle (because that
	 * involves reading/writing to /dev/sysevent), so we do this before
	 * calling __init_daemon_priv.
	 */
	nhdl->nh_evhdl = fmev_shdl_init(LIBFMEVENT_VERSION_2, NULL, NULL, NULL);
	if (nhdl->nh_evhdl == NULL) {
		(void) sleep(5);
		nd_abort(nhdl, "failed to initialize libfmevent: %s",
		    fmev_strerror(fmev_errno));
	}

	/*
	 * If we're in the global zone, reset all of our privilege sets to
	 * the minimum set of required privileges.  Since we've already
	 * initialized our libmevent handle, we no no longer need to run as
	 * root, so we change our uid/gid to noaccess (60002).
	 *
	 * __init_daemon_priv will also set the process core path for us
	 *
	 */
	if (getzoneid() == GLOBAL_ZONEID)
		if (__init_daemon_priv(
		    PU_RESETGROUPS | PU_LIMITPRIVS | PU_INHERITPRIVS,
		    60002, 60002, PRIV_PROC_SETID, NULL) != 0)
			nd_abort(nhdl, "additional privileges required to run");

	nhdl->nh_msghdl = fmd_msg_init(nhdl->nh_rootdir, FMD_MSG_VERSION);
	if (nhdl->nh_msghdl == NULL)
		nd_abort(nhdl, "failed to initialize libfmd_msg");

	(void) gethostname(hostname, MAXHOSTNAMELEN + 1);
	/*
	 * Set up our event subscriptions.  We subscribe to everything and then
	 * consult libscf when we receive an event to determine whether to send
	 * an email notification.
	 */
	nd_debug(nhdl, "Subscribing to ireport.* events");
	if (fmev_shdl_subscribe(nhdl->nh_evhdl, "ireport.*", irpt_cbfunc,
	    NULL) != FMEV_SUCCESS) {
		nd_abort(nhdl, "fmev_shdl_subscribe failed: %s",
		    fmev_strerror(fmev_errno));
	}

	nd_debug(nhdl, "Subscribing to list.* events");
	if (fmev_shdl_subscribe(nhdl->nh_evhdl, "list.*", listev_cb,
	    NULL) != FMEV_SUCCESS) {
		nd_abort(nhdl, "fmev_shdl_subscribe failed: %s",
		    fmev_strerror(fmev_errno));
	}

	/*
	 * We run until someone kills us
	 */
	while (nhdl->nh_keep_running)
		(void) sigsuspend(&set);

	free(nhdl->nh_rootdir);
	free(nhdl);

	return (0);
}
