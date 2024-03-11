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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/list.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <ofmt.h>
#include <libilb.h>
#include "ilbadm.h"

extern int	optind, optopt, opterr;
extern char	*optarg;

typedef struct hc_export_arg {
	FILE	*fp;
} hc_export_arg_t;

/* Maximum columns for printing hc output. */
#define	SHOW_HC_COLS	80

/* OFMT call back to print out a hc server result field. */
static boolean_t print_hc_result(ofmt_arg_t *, char *, uint_t);

/* ID to indicate which field to be printed. */
enum hc_print_id {
	hc_of_rname, hc_of_hname, hc_of_sname, hc_of_status, hc_of_fail_cnt,
	hc_of_lasttime, hc_of_nexttime, hc_of_rtt,
	hc_of_name, hc_of_timeout, hc_of_count, hc_of_interval, hc_of_def_ping,
	hc_of_test
};

/*
 * Fields of a hc server result.  The sum of all fields' width is SHOW_HC_COLS.
 */
static ofmt_field_t hc_results[] = {
	{"RULENAME",	14,	hc_of_rname,	print_hc_result},
	{"HCNAME",	14,	hc_of_hname,	print_hc_result},
	{"SERVERID",	14,	hc_of_sname,	print_hc_result},
	{"STATUS",	9,	hc_of_status,	print_hc_result},
	{"FAIL",	5,	hc_of_fail_cnt,	print_hc_result},
	{"LAST",	9,	hc_of_lasttime,	print_hc_result},
	{"NEXT",	9,	hc_of_nexttime,	print_hc_result},
	{"RTT",		6,	hc_of_rtt,	print_hc_result},
	{NULL,		0,	0,		NULL}
};

/* OFMT call back to print out a hc info field. */
static boolean_t print_hc(ofmt_arg_t *, char *, uint_t);

/*
 * Fields of a hc info.  The sume of all fields' width is SHOW_HC_COLS.
 */
static ofmt_field_t hc_fields[] = {
	{"HCNAME",	14,	hc_of_name,	print_hc},
	{"TIMEOUT",	8,	hc_of_timeout,	print_hc},
	{"COUNT",	8,	hc_of_count,	print_hc},
	{"INTERVAL",	9,	hc_of_interval,	print_hc},
	{"DEF_PING",	9,	hc_of_def_ping,	print_hc},
	{"TEST",	32,	hc_of_test,	print_hc},
	{NULL,		0,	0,		NULL}
};

static boolean_t
print_hc(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	enum hc_print_id id = of_arg->ofmt_id;
	ilb_hc_info_t *info = (ilb_hc_info_t *)of_arg->ofmt_cbarg;

	switch (id) {
	case hc_of_name:
		(void) strlcpy(buf, info->hci_name, bufsize);
		break;
	case hc_of_timeout:
		(void) snprintf(buf, bufsize, "%d", info->hci_timeout);
		break;
	case hc_of_count:
		(void) snprintf(buf, bufsize, "%d", info->hci_count);
		break;
	case hc_of_interval:
		(void) snprintf(buf, bufsize, "%d", info->hci_interval);
		break;
	case hc_of_def_ping:
		(void) snprintf(buf, bufsize, "%c",
		    info->hci_def_ping ? 'Y' : 'N');
		break;
	case hc_of_test:
		(void) snprintf(buf, bufsize, "%s", info->hci_test);
		break;
	}
	return (B_TRUE);
}

/* Call back to ilb_walk_hc(). */
/* ARGSUSED */
static ilb_status_t
ilbadm_print_hc(ilb_handle_t h, ilb_hc_info_t *hc_info, void *arg)
{
	ofmt_handle_t	ofmt_h = arg;

	ofmt_print(ofmt_h, hc_info);
	return (ILB_STATUS_OK);
}

/*
 * Print out health check objects given their name.
 * Or print out all health check objects if no name given.
 */
/* ARGSUSED */
ilbadm_status_t
ilbadm_show_hc(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib;
	ofmt_handle_t	ofmt_h;
	ofmt_status_t	ofmt_ret;

	if ((ofmt_ret = ofmt_open("all", hc_fields, 0, SHOW_HC_COLS,
	    &ofmt_h)) != OFMT_SUCCESS) {
		char err_buf[SHOW_HC_COLS];

		ilbadm_err(gettext("ofmt_open failed: %s"),
		    ofmt_strerror(ofmt_h, ofmt_ret, err_buf, SHOW_HC_COLS));
		return (ILBADM_LIBERR);
	}
	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	if (argc == 1) {
		rclib = ilb_walk_hc(h, ilbadm_print_hc, ofmt_h);
	} else {
		ilb_hc_info_t hc_info;
		int i;

		for (i = 1; i < argc; i++) {
			rclib = ilb_get_hc_info(h, argv[i], &hc_info);
			if (rclib == ILB_STATUS_OK)
				ofmt_print(ofmt_h, &hc_info);
			else
				break;
		}
	}
out:
	ofmt_close(ofmt_h);

	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		return (ILBADM_LIBERR);
	}

	return (ILBADM_OK);
}

static boolean_t
print_hc_result(ofmt_arg_t *of_arg, char *buf, uint_t bufsize)
{
	enum hc_print_id id = of_arg->ofmt_id;
	ilb_hc_srv_t *srv = (ilb_hc_srv_t *)of_arg->ofmt_cbarg;
	struct tm tv;

	switch (id) {
	case hc_of_rname:
		(void) strlcpy(buf, srv->hcs_rule_name, bufsize);
		break;
	case hc_of_hname:
		(void) strlcpy(buf, srv->hcs_hc_name, bufsize);
		break;
	case hc_of_sname:
		(void) strlcpy(buf, srv->hcs_ID, bufsize);
		break;
	case hc_of_status:
		switch (srv->hcs_status) {
		case ILB_HCS_UNINIT:
			(void) strlcpy(buf, "un-init", bufsize);
			break;
		case ILB_HCS_UNREACH:
			(void) strlcpy(buf, "unreach", bufsize);
			break;
		case ILB_HCS_ALIVE:
			(void) strlcpy(buf, "alive", bufsize);
			break;
		case ILB_HCS_DEAD:
			(void) strlcpy(buf, "dead", bufsize);
			break;
		case ILB_HCS_DISABLED:
			(void) strlcpy(buf, "disabled", bufsize);
			break;
		}
		break;
	case hc_of_fail_cnt:
		(void) snprintf(buf, bufsize, "%u", srv->hcs_fail_cnt);
		break;
	case hc_of_lasttime:
		if (localtime_r(&srv->hcs_lasttime, &tv) == NULL)
			return (B_FALSE);
		(void) snprintf(buf, bufsize, "%02d:%02d:%02d", tv.tm_hour,
		    tv.tm_min, tv.tm_sec);
		break;
	case hc_of_nexttime:
		if (srv->hcs_status == ILB_HCS_DISABLED)
			break;
		if (localtime_r(&srv->hcs_nexttime, &tv) == NULL)
			return (B_FALSE);
		(void) snprintf(buf, bufsize, "%02d:%02d:%02d", tv.tm_hour,
		    tv.tm_min, tv.tm_sec);
		break;
	case hc_of_rtt:
		(void) snprintf(buf, bufsize, "%u", srv->hcs_rtt);
		break;
	}
	return (B_TRUE);
}

/* Call back to ilbd_walk_hc_srvs(). */
/* ARGSUSED */
static ilb_status_t
ilbadm_print_hc_result(ilb_handle_t h, ilb_hc_srv_t *srv, void *arg)
{
	ofmt_handle_t	ofmt_h = arg;

	ofmt_print(ofmt_h, srv);
	return (ILB_STATUS_OK);
}

/*
 * Output hc result of a specified rule or all rules.
 */
ilbadm_status_t
ilbadm_show_hc_result(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t 	rclib = ILB_STATUS_OK;
	int		i;
	ofmt_handle_t	ofmt_h;
	ofmt_status_t	ofmt_ret;

	/* ilbadm show-hc-result [rule-name] */
	if (argc < 1) {
		ilbadm_err(gettext("usage: ilbadm show-hc-result"
		    " [rule-name]"));
		return (ILBADM_LIBERR);
	}

	if ((ofmt_ret = ofmt_open("all", hc_results, 0, SHOW_HC_COLS,
	    &ofmt_h)) != OFMT_SUCCESS) {
		char err_buf[SHOW_HC_COLS];

		ilbadm_err(gettext("ofmt_open failed: %s"),
		    ofmt_strerror(ofmt_h, ofmt_ret, err_buf, SHOW_HC_COLS));
		return (ILBADM_LIBERR);
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	/* If no rule name is given, show results for all rules. */
	if (argc == 1) {
		rclib = ilb_walk_hc_srvs(h, ilbadm_print_hc_result, NULL,
		    ofmt_h);
	} else {
		for (i = 1; i < argc; i++) {
			rclib = ilb_walk_hc_srvs(h, ilbadm_print_hc_result,
			    argv[i], ofmt_h);
			if (rclib != ILB_STATUS_OK)
				break;
		}
	}
out:
	ofmt_close(ofmt_h);

	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		return (ILBADM_LIBERR);
	}
	return (ILBADM_OK);
}

#define	ILBADM_DEF_HC_COUNT	3
#define	ILBADM_DEF_HC_INTERVAL	30	/* in sec */
#define	ILBADM_DEF_HC_TIMEOUT	5	/* in sec */

static ilbadm_key_name_t hc_parse_keys[] = {
	{ILB_KEY_HC_TEST, "hc-test", "hc-test"},
	{ILB_KEY_HC_COUNT, "hc-count", "hc-count"},
	{ILB_KEY_HC_TIMEOUT, "hc-timeout", "hc-tout"},
	{ILB_KEY_HC_INTERVAL, "hc-interval", "hc-intl"},
	{ILB_KEY_BAD, "", ""}
};

static ilbadm_status_t
ilbadm_hc_parse_arg(char *arg, ilb_hc_info_t *hc)
{
	ilbadm_status_t ret;

	/* set default value for count, interval, timeout */
	hc->hci_count = ILBADM_DEF_HC_COUNT;
	hc->hci_interval = ILBADM_DEF_HC_INTERVAL;
	hc->hci_timeout = ILBADM_DEF_HC_TIMEOUT;
	hc->hci_test[0] = '\0';

	ret = i_parse_optstring(arg, hc, hc_parse_keys, 0, NULL);
	if (ret != ILBADM_OK && ret != ILBADM_LIBERR) {
		ilbadm_err(ilbadm_errstr(ret));
		return (ILBADM_LIBERR);
	}
	if (hc->hci_test[0] == '\0' && ret != ILBADM_LIBERR) {
		ilbadm_err("hc-test: missing");
		return (ILBADM_LIBERR);
	}
	return (ret);
}

/* ARGSUSED */
ilbadm_status_t
ilbadm_create_hc(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_hc_info_t	hc_info;
	ilbadm_status_t	ret = ILBADM_OK;
	ilb_status_t	rclib;
	int		c;


	hc_info.hci_def_ping = B_TRUE;
	while ((c = getopt(argc, argv, ":h:n")) != -1) {
		if (c == 'h') {
			ret = ilbadm_hc_parse_arg(optarg, &hc_info);
			if (ret != ILBADM_OK)
				return (ret);
		} else if (c == 'n') {
			hc_info.hci_def_ping = B_FALSE;
		} else {
			ilbadm_err(gettext("bad argument %c"), c);
			return (ILBADM_LIBERR);
		}
	}

	if (optind >= argc) {
		ilbadm_err(gettext("usage: ilbadm"
		    " create-healthcheck [-n] -h"
		    " hc-test=val[,hc-timeout=val][,hc-count=va]"
		    "[,hc-interval=val]  hc-name"));
		return (ILBADM_FAIL);
	}

	if (strlen(argv[optind]) > ILBD_NAMESZ - 1) {
		ilbadm_err(gettext("health check object name %s is too long - "
		    "must not exceed %d chars"), argv[optind],
		    ILBD_NAMESZ - 1);
		return (ILBADM_FAIL);
	}

	if (((strcasecmp(hc_info.hci_test, ILB_HC_STR_UDP) == 0) ||
	    (strcasecmp(hc_info.hci_test, ILB_HC_STR_PING) == 0)) &&
	    !(hc_info.hci_def_ping)) {
		ilbadm_err(gettext("cannot disable default PING"
		    " for this test"));
		return (ILBADM_LIBERR);
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	(void) strlcpy(hc_info.hci_name, argv[optind],
	    sizeof (hc_info.hci_name));
	rclib = ilb_create_hc(h, &hc_info);
out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		ret = ILBADM_LIBERR;
	}
	return (ret);
}

ilbadm_status_t
ilbadm_destroy_hc(int argc, char *argv[])
{
	ilb_handle_t	h = ILB_INVALID_HANDLE;
	ilb_status_t	rclib;
	ilbadm_status_t ret = ILBADM_OK;
	int		i;

	if (argc < 2) {
		ilbadm_err(gettext("usage: ilbadm"
		    " delete-healthcheck hc-name ..."));
		return (ILBADM_LIBERR);
	}

	rclib = ilb_open(&h);
	if (rclib != ILB_STATUS_OK)
		goto out;

	for (i = 1; i < argc; i++) {
		rclib = ilb_destroy_hc(h, argv[i]);
		if (rclib != ILB_STATUS_OK)
			break;
	}
out:
	if (h != ILB_INVALID_HANDLE)
		(void) ilb_close(h);

	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		ret = ILBADM_LIBERR;
	}
	return (ret);
}

/*
 * Since this function is used by libilb function, it
 * must return libilb errors
 */
/* ARGSUSED */
ilb_status_t
ilbadm_export_hcinfo(ilb_handle_t h, ilb_hc_info_t *hc_info, void *arg)
{
	FILE 		*fp = ((hc_export_arg_t *)arg)->fp;
	int		count = 0;
	int		ret;

	/*
	 * a test name "PING" implies "no default ping", so we only
	 * print -n if the test is NOT "PING"
	 */
	if (hc_info->hci_def_ping == B_FALSE &&
	    strncasecmp(hc_info->hci_test, "PING", 5) != 0)
		(void) fprintf(fp, "create-healthcheck -n -h ");
	else
		(void) fprintf(fp, "create-healthcheck -h ");

	if (*hc_info->hci_test != '\0') {
		(void) fprintf(fp, "hc-test=%s", hc_info->hci_test);
		count++;
	}
	if (hc_info->hci_timeout != 0) {
		if (count++ > 0)
			(void) fprintf(fp, ",");
		(void) fprintf(fp, "hc-timeout=%d", hc_info->hci_timeout);
	}
	if (hc_info->hci_count != 0) {
		if (count++ > 0)
			(void) fprintf(fp, ",");
		(void) fprintf(fp, "hc-count=%d", hc_info->hci_count);
	}
	if (hc_info->hci_interval != 0) {
		if (count > 0)
			(void) fprintf(fp, ",");
		(void) fprintf(fp, "hc-interval=%d", hc_info->hci_interval);
	}

	/*
	 * if any of the above writes fails, then, we assume, so will
	 * this one; so it's sufficient to test once
	 */
	ret = fprintf(fp, " %s\n", hc_info->hci_name);
	if (ret < 0)
		goto out_fail;
	ret = fflush(fp);

out_fail:
	if (ret < 0)
		return (ILB_STATUS_WRITE);
	return (ILB_STATUS_OK);
}

ilbadm_status_t
ilbadm_export_hc(ilb_handle_t h, FILE *fp)
{
	ilb_status_t	rclib;
	ilbadm_status_t	ret = ILBADM_OK;
	hc_export_arg_t	arg;

	arg.fp = fp;
	rclib = ilb_walk_hc(h, ilbadm_export_hcinfo, (void *)&arg);
	if (rclib != ILB_STATUS_OK) {
		ilbadm_err(ilb_errstr(rclib));
		ret = ILBADM_LIBERR;
	}
	return (ret);
}
