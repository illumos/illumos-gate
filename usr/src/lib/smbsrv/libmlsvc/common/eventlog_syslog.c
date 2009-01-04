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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <syslog.h>
#include <thread.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <sys/synch.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <ctype.h>
#include "eventlog.h"

#define	LOGR_SYSLOG_PARSE_ENTRY_SUCCESS	0
#define	LOGR_SYSLOG_PARSE_ENTRY_ERR	-1
#define	LOGR_SYSLOG_PARSE_NOPRI_ERR	-2

#define	LOGR_SYSLOG_PARSE_IDTOKEN_PFX	"[ID"

typedef enum {
	LOGR_SYSLOG_MONTH = 0,
	LOGR_SYSLOG_DAY,
	LOGR_SYSLOG_TIME,
	LOGR_SYSLOG_MACHINENAME,
	LOGR_SYSLOG_SOURCE,
	LOGR_SYSLOG_ID,
	LOGR_SYSLOG_PRI_FAC,
	LOGR_SYSLOG_NARG
} logr_syslog_tokens;

typedef enum {
	LOGR_SYSLOG_FACILITY = 0,
	LOGR_SYSLOG_PRIORITY,
	LOGR_SYSLOG_PRI_FAC_NARG
} logr_syslog_pri_fac_tokens;

/*
 * Event code translation struct for use in processing config file
 */
typedef struct logr_code_tbl {
	char	*c_name;
	int	c_val;
} logr_code_tbl_t;

static logr_code_tbl_t	logr_syslog_pri_names[] = {
	"panic",	LOG_EMERG,
	"emerg",	LOG_EMERG,
	"alert",	LOG_ALERT,
	"crit",		LOG_CRIT,
	"err",		LOG_ERR,
	"error",	LOG_ERR,
	"warn",		LOG_WARNING,
	"warning",	LOG_WARNING,
	"notice",	LOG_NOTICE,
	"info",		LOG_INFO,
	"debug",	LOG_DEBUG
};

static logr_code_tbl_t	logr_syslog_fac_names[] = {
	"kern",		LOG_KERN,
	"user",		LOG_USER,
	"mail",		LOG_MAIL,
	"daemon",	LOG_DAEMON,
	"auth",		LOG_AUTH,
	"security",	LOG_AUTH,
	"syslog",	LOG_SYSLOG,
	"lpr",		LOG_LPR,
	"news",		LOG_NEWS,
	"uucp",		LOG_UUCP,
	"audit",	LOG_AUDIT,
	"cron",		LOG_CRON,
	"local0",	LOG_LOCAL0,
	"local1",	LOG_LOCAL1,
	"local2",	LOG_LOCAL2,
	"local3",	LOG_LOCAL3,
	"local4",	LOG_LOCAL4,
	"local5",	LOG_LOCAL5,
	"local6",	LOG_LOCAL6,
	"local7",	LOG_LOCAL7
};

typedef struct logr_syslog_node {
	list_node_t	ln_node;
	char		ln_logline[LOGR_MAXENTRYLEN];
} logr_syslog_node_t;

/*
 * Sets the loghost of an syslog entry.
 * Returns 0 on success, -1 on failure.
 */
static int
logr_syslog_set_loghost(char *log_host, logr_entry_t *le)
{
	if (log_host == NULL)
		return (-1);

	(void) strlcpy(le->le_hostname, log_host, MAXHOSTNAMELEN);

	return (0);
}

/*
 * Sets the timestamp of an syslog entry.
 * Returns 0 on success, -1 on failure.
 */
static int
logr_syslog_set_timestamp(char *month, char *day, char *time, logr_entry_t *le)
{
	struct timeval	now;
	struct tm tm, cur_tm;
	char buf[30];

	if ((month == NULL) || (day == NULL) || (time == NULL))
		return (-1);

	bzero(&tm, sizeof (tm));
	(void) snprintf(buf, 30, "%s %s %s", month, day, time);
	if (strptime(buf, "%b" "%d" "%H:%M:%S", &tm) == NULL)
		return (-1);

	/* get the current dst, year and apply it. */
	if (gettimeofday(&now, NULL) != 0)
		return (-1);

	if (localtime_r(&now.tv_sec, &cur_tm) == NULL)
		return (-1);

	tm.tm_isdst = cur_tm.tm_isdst;
	tm.tm_year = cur_tm.tm_year;
	if (tm.tm_mon > cur_tm.tm_mon)
		tm.tm_year = tm.tm_year - 1;

	if ((le->le_timestamp.tv_sec = mktime(&tm)) == -1)
		return (-1);

	return (0);
}

/*
 * Sets the Priority and Facility of an syslog entry.
 * Returns 0 on success, -1 on failure.
 */
static int
logr_syslog_set_pri_fac(char *pf_tkn, logr_entry_t *le)
{
	int pri_fac[LOGR_SYSLOG_PRI_FAC_NARG];
	int j, sz = 0;

	le->le_pri = LOG_INFO;

	if (pf_tkn == NULL)
		return (-1);

	/* Defaults */
	pri_fac[LOGR_SYSLOG_FACILITY] = LOG_USER;
	pri_fac[LOGR_SYSLOG_PRIORITY] = LOG_INFO;

	sz = sizeof (logr_syslog_fac_names) / sizeof (logr_syslog_fac_names[0]);
	for (j = 0; j < sz; j++) {
		if (strstr(pf_tkn, logr_syslog_fac_names[j].c_name) != NULL) {
			pri_fac[LOGR_SYSLOG_FACILITY] =
			    logr_syslog_fac_names[j].c_val;
			break;
		}
	}

	sz = sizeof (logr_syslog_pri_names) / sizeof (logr_syslog_pri_names[0]);
	for (j = 0; j < sz; j++) {
		if (strstr(pf_tkn, logr_syslog_pri_names[j].c_name) != NULL) {
			pri_fac[LOGR_SYSLOG_PRIORITY] =
			    logr_syslog_pri_names[j].c_val;
			break;
		}
	}

	le->le_pri = pri_fac[LOGR_SYSLOG_PRIORITY];

	return (0);
}

/*
 * Sets the messages of an syslog entry.
 */
static void
logr_syslog_set_message(char *logline, logr_entry_t *le)
{
	char *p;

	if ((p = strchr(logline, '\n')) != NULL)
		*p = '\0';

	(void) strlcpy(le->le_msg, logline, LOGR_MAXENTRYLEN);
}

/*
 * Parses the tokens from an syslog entry. A typical syslog entry is of the
 * following standard format,
 *
 *  <month> <day> <time> <loghost> <source>: [ID <ID> <facility.priority>] <msg>
 * For Example:
 *  Oct 29 09:49:20 pbgalaxy1 smbd[104039]: [ID 702911 daemon.info] init done.
 *
 * This method parses the above syslog entry and populates the log_entry_t
 * structure from the parsed tokens. It returns the following return codes.
 *
 * Returns,
 *   LOGR_SYSLOG_PARSE_ENTRY_ERR:	If the syslog entry is NULL, or there is
 *					error in parsing the entry or entry is
 *					not in the standard format.
 *   LOGR_SYSLOG_PARSE_NOPRI_ERR:	If the priority of the message cannot be
 *					obtained from the parsed tokens.
 *   LOGR_SYSLOG_PARSE_ENTRY_SUCCESS:	If the syslog entry is sucessfully
 *					parsed.
 */
static int
logr_syslog_parse_tokens(char *logline, logr_entry_t *le)
{
	char *argv[LOGR_SYSLOG_NARG];
	int i;
	boolean_t no_pri = B_TRUE;

	for (i = 0; i < LOGR_SYSLOG_NARG; ++i) {
		if ((argv[i] = strsep(&logline, " ")) == NULL)
			return (LOGR_SYSLOG_PARSE_ENTRY_ERR);

		(void) trim_whitespace(logline);

		if ((i == LOGR_SYSLOG_ID) &&
		    (strcmp(argv[i], LOGR_SYSLOG_PARSE_IDTOKEN_PFX) == 0)) {
			i--;
			no_pri = B_FALSE;
		}
	}

	if (logr_syslog_set_timestamp(argv[LOGR_SYSLOG_MONTH],
	    argv[LOGR_SYSLOG_DAY], argv[LOGR_SYSLOG_TIME], le) < 0)
		return (LOGR_SYSLOG_PARSE_ENTRY_ERR);

	if (logr_syslog_set_loghost(argv[LOGR_SYSLOG_MACHINENAME], le) < 0)
		return (LOGR_SYSLOG_PARSE_ENTRY_ERR);

	if (no_pri)
		return (LOGR_SYSLOG_PARSE_NOPRI_ERR);

	if (logr_syslog_set_pri_fac(argv[LOGR_SYSLOG_PRI_FAC], le) < 0)
		return (LOGR_SYSLOG_PARSE_NOPRI_ERR);

	logr_syslog_set_message(logline, le);

	return (LOGR_SYSLOG_PARSE_ENTRY_SUCCESS);
}

/*
 * log_syslog_parse_entry
 *
 * Parse the given syslog entry into a log_entry_t structure.
 *
 * Returns,
 *   LOGR_SYSLOG_PARSE_ENTRY_SUCCESS:	If the parsing is successful.
 *   An error code less than zero, if parsing fails.
 */
static int
logr_syslog_parse_entry(char *logline, logr_entry_t *le)
{
	char *dup_logline;
	int ret = LOGR_SYSLOG_PARSE_ENTRY_SUCCESS;

	if (logline == NULL)
		return (LOGR_SYSLOG_PARSE_ENTRY_ERR);

	dup_logline = strdup(logline);
	ret = logr_syslog_parse_tokens(dup_logline, le);
	free(dup_logline);

	switch (ret) {
	case LOGR_SYSLOG_PARSE_NOPRI_ERR:
		le->le_pri = LOG_INFO;
		logr_syslog_set_message(logline, le);
		ret = LOGR_SYSLOG_PARSE_ENTRY_SUCCESS;
		break;
	default:
		break;
	}

	return (ret);
}

static void
logr_syslog_destroy_queue(list_t *queue)
{
	logr_syslog_node_t *head;

	while ((head = list_head(queue)) != NULL) {
		list_remove(queue, head);
		free(head);
	}
	list_destroy(queue);
}

static int
logr_syslog_construct_queue(FILE *fp, list_t *queue)
{
	logr_syslog_node_t *node, *head;
	int line_num = 0;
	char logline[LOGR_MAXENTRYLEN];

	list_create(queue, sizeof (logr_syslog_node_t),
	    offsetof(logr_syslog_node_t, ln_node));

	bzero(logline, LOGR_MAXENTRYLEN);
	while (fgets(logline, LOGR_MAXENTRYLEN, fp) != NULL) {
		/* Read the last 1024 entries in the queue */
		if (line_num > LOGR_NMSGMASK) {
			head = list_head(queue);
			list_remove(queue, head);
			free(head);
		}

		if ((node = malloc(sizeof (logr_syslog_node_t))) == NULL) {
			logr_syslog_destroy_queue(queue);
			return (-1);
		}
		bzero(node->ln_logline, LOGR_MAXENTRYLEN);

		(void) strlcpy(node->ln_logline, logline, LOGR_MAXENTRYLEN);
		list_insert_tail(queue, node);
		bzero(logline, LOGR_MAXENTRYLEN);
		line_num++;
	}

	return (0);
}

/*
 * logr_syslog_load
 *
 * Loads the given log file into log_info_t structure format.
 *
 * Returns pointer to the allocated log structure on success.
 * Note that the caller is responsible for freeing the allocated
 * memory for returned log_info_t structure.
 */
static int
logr_syslog_load(FILE *fp, logr_info_t *log)
{
	logr_entry_t *entry;
	int i = 0;

	list_t queue;
	logr_syslog_node_t *node;

	if (logr_syslog_construct_queue(fp, &queue) < 0)
		return (-1);

	node = list_head(&queue);
	while (node) {
		entry = &log->li_entry[i];

		if (logr_syslog_parse_entry(node->ln_logline, entry) !=
		    LOGR_SYSLOG_PARSE_ENTRY_SUCCESS) {
			node = list_next(&queue, node);
			continue;
		}

		if (++i > LOGR_NMSGMASK)
			break;

		node = list_next(&queue, node);
	}

	logr_syslog_destroy_queue(&queue);
	log->li_idx = i;

	return (0);
}

/*
 * logr_syslog_snapshot
 *
 * Return a snapshot of the given log in the buffer
 * provided by the caller. Returns the number of entries in
 * the log.
 */
int
logr_syslog_snapshot(logr_info_t *loginfo)
{
	FILE *fp;

	if (loginfo == NULL)
		return (-1);

	if ((fp = fopen("/var/adm/messages", "r")) == 0)
		return (-1);

	if (logr_syslog_load(fp, loginfo) < 0) {
		(void) fclose(fp);
		return (-1);
	}
	(void) fclose(fp);

	if (loginfo->li_idx <= LOGR_NMSGMASK)
		return (loginfo->li_idx);

	return (LOGR_NMSGMASK+1);
}
