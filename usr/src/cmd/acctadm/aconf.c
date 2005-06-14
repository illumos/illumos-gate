/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/acctctl.h>

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "aconf.h"
#include "utils.h"
#include "res.h"

#define	BUFSZ	(PATH_MAX + 80)

typedef struct ac_token {
	char *tok_name;
	int tok_type;
	int (*tok_parse)(acctconf_t *, char *, int);
	int (*tok_print)(acctconf_t *, FILE *, int);
} ac_token_t;

static int print_enable(acctconf_t *, FILE *, int);
static int print_file(acctconf_t *, FILE *, int);
static int print_tracked(acctconf_t *, FILE *, int);
static int print_untracked(acctconf_t *, FILE *, int);

static ac_token_t tokens[] = {
	{ "ACCTADM_PROC_ENABLE",
		AC_PROC, aconf_str2enable, print_enable },
	{ "ACCTADM_PROC_FILE",
		AC_PROC, aconf_str2file, print_file },
	{ "ACCTADM_PROC_TRACKED",
		AC_PROC, aconf_str2tracked, print_tracked },
	{ "ACCTADM_PROC_UNTRACKED",
		AC_PROC, aconf_str2untracked, print_untracked },
	{ "ACCTADM_TASK_ENABLE",
		AC_TASK, aconf_str2enable, print_enable },
	{ "ACCTADM_TASK_FILE",
		AC_TASK, aconf_str2file, print_file },
	{ "ACCTADM_TASK_TRACKED",
		AC_TASK, aconf_str2tracked, print_tracked },
	{ "ACCTADM_TASK_UNTRACKED",
		AC_TASK, aconf_str2untracked, print_untracked },
	{ "ACCTADM_FLOW_ENABLE",
		AC_FLOW, aconf_str2enable, print_enable },
	{ "ACCTADM_FLOW_FILE",
		AC_FLOW, aconf_str2file, print_file },
	{ "ACCTADM_FLOW_TRACKED",
		AC_FLOW, aconf_str2tracked, print_tracked },
	{ "ACCTADM_FLOW_UNTRACKED",
		AC_FLOW, aconf_str2untracked, print_untracked },
	{ NULL,
		AC_NONE, NULL, NULL }
};

void
aconf_init(acctconf_t *acp)
{
	void *buf;
	void *pathname;
	char *tracked, *untracked;
	int state;

	if ((buf = malloc(AC_BUFSIZE)) == NULL ||
	    (pathname = malloc(MAXPATHLEN)) == NULL)
		die(gettext("not enough memory\n"));

	/*
	 * Initialize process accounting settings
	 */
	(void) memset(pathname, 0, MAXPATHLEN);
	if (acctctl(AC_PROC | AC_STATE_GET, &state, sizeof (int)) == -1)
		die(gettext("cannot get process accounting state\n"));
	acp->ac_proc_state = state;
	if (acctctl(AC_PROC | AC_FILE_GET, pathname, MAXPATHLEN) == -1) {
		if (errno == ENOTACTIVE)
			(void) strlcpy(acp->ac_proc_file,
			    AC_STR_NONE, MAXPATHLEN);
		else
			die(gettext("cannot get process accounting file name"));
	} else {
		(void) strlcpy(acp->ac_proc_file, pathname, MAXPATHLEN);
	}
	(void) memset(buf, 0, AC_BUFSIZE);
	if (acctctl(AC_PROC | AC_RES_GET, buf, AC_BUFSIZE) == -1)
		die(gettext("cannot obtain the list of enabled resources\n"));
	tracked = buf2str(buf, AC_BUFSIZE, AC_ON, AC_PROC);
	untracked = buf2str(buf, AC_BUFSIZE, AC_OFF, AC_PROC);
	(void) strlcpy(acp->ac_proc_tracked, tracked, MAXRESLEN);
	(void) strlcpy(acp->ac_proc_untracked, untracked, MAXRESLEN);
	free(tracked);
	free(untracked);

	/*
	 * Initialize flow accounting settings
	 */
	(void) memset(pathname, 0, MAXPATHLEN);
	if (acctctl(AC_FLOW | AC_STATE_GET, &state, sizeof (int)) == -1)
		die(gettext("cannot get flow accounting state\n"));
	acp->ac_flow_state = state;
	if (acctctl(AC_FLOW | AC_FILE_GET, pathname, MAXPATHLEN) == -1) {
		if (errno == ENOTACTIVE)
			(void) strlcpy(acp->ac_flow_file,
			    AC_STR_NONE, MAXPATHLEN);
		else
			die(gettext("cannot get flow accounting file name"));
	} else {
		(void) strlcpy(acp->ac_flow_file, pathname, MAXPATHLEN);
	}
	(void) memset(buf, 0, AC_BUFSIZE);
	if (acctctl(AC_FLOW | AC_RES_GET, buf, AC_BUFSIZE) == -1)
		die(gettext("cannot obtain the list of enabled resources\n"));
	tracked = buf2str(buf, AC_BUFSIZE, AC_ON, AC_FLOW);
	untracked = buf2str(buf, AC_BUFSIZE, AC_OFF, AC_FLOW);
	(void) strlcpy(acp->ac_flow_tracked, tracked, MAXRESLEN);
	(void) strlcpy(acp->ac_flow_untracked, untracked, MAXRESLEN);
	free(tracked);
	free(untracked);

	/*
	 * Initialize task accounting settings
	 */
	(void) memset(pathname, 0, MAXPATHLEN);
	if (acctctl(AC_TASK | AC_STATE_GET, &state, sizeof (int)) == -1)
		die(gettext("cannot get task accounting state\n"));
	acp->ac_task_state = state;
	if (acctctl(AC_TASK | AC_FILE_GET, pathname, MAXPATHLEN) == -1) {
		if (errno == ENOTACTIVE)
			(void) strlcpy(acp->ac_task_file,
			    AC_STR_NONE, MAXPATHLEN);
		else
			die(gettext("cannot get task accounting file name"));
	} else {
		(void) strlcpy(acp->ac_task_file, pathname, MAXPATHLEN);
	}
	(void) memset(buf, 0, AC_BUFSIZE);
	if (acctctl(AC_TASK | AC_RES_GET, buf, AC_BUFSIZE) == -1)
		die(gettext("cannot obtain the list of enabled resources\n"));
	tracked = buf2str(buf, AC_BUFSIZE, AC_ON, AC_TASK);
	untracked = buf2str(buf, AC_BUFSIZE, AC_OFF, AC_TASK);
	(void) strlcpy(acp->ac_task_tracked, tracked, MAXRESLEN);
	(void) strlcpy(acp->ac_task_untracked, untracked, MAXRESLEN);
	free(pathname);
	free(buf);
	free(tracked);
	free(untracked);
}

int
aconf_create(acctconf_t *acp, const char *fpath)
{
	if ((acp->ac_conf_fd = open(fpath, O_RDWR | O_CREAT, AC_PERM)) == -1) {
		warn(gettext("failed to open %s"), fpath);
		return (-1);
	}
	if ((acp->ac_conf_fp = fdopen(acp->ac_conf_fd, "r+")) == NULL) {
		warn(gettext("failed to open stream for %s"), fpath);
		return (-1);
	}
	return (0);
}

int
aconf_open(acctconf_t *acp, const char *fpath)
{
	char buf[BUFSZ];
	int line;
	int ret = 0;

	if ((acp->ac_conf_fd = open(fpath, O_RDONLY, AC_PERM)) == -1) {
		warn(gettext("failed to open %s"), fpath);
		return (-1);
	}
	if ((acp->ac_conf_fp = fdopen(acp->ac_conf_fd, "r")) == NULL) {
		warn(gettext("failed to open stream for %s"), fpath);
		return (-1);
	}
	for (line = 1; fgets(buf, BUFSZ, acp->ac_conf_fp) != NULL; line++) {
		char name[BUFSZ], value[BUFSZ];
		ac_token_t *tokp;
		int len;

		if (buf[0] == '#' || buf[0] == '\n')
			continue;
		/*
		 * Look for "name=value", with optional whitespace on either
		 * side, terminated by a newline, and consuming the whole line.
		 */
		/* LINTED - unbounded string specifier */
		if (sscanf(buf, " %[^=]=%s \n%n", name, value, &len) == 2 &&
		    name[0] != '\0' && value[0] != '\0' && len == strlen(buf)) {
			/*
			 * Locate a matching token in the tokens[] table,
			 * and invoke its parsing function.
			 */
			for (tokp = tokens; tokp->tok_name != NULL; tokp++) {
				if (strcmp(name, tokp->tok_name) == 0) {
					if (tokp->tok_parse(acp, value,
					    tokp->tok_type) == -1) {
						warn(gettext("\"%s\", line %d: "
						    "warning: invalid %s\n"),
						    fpath, line, name);
						ret = -1;
					}
					break;
				}
			}
			/*
			 * If we hit the end of the tokens[] table,
			 * no matching token was found.
			 */
			if (tokp->tok_name == NULL) {
				warn(gettext("\"%s\", line %d: warning: "
				    "invalid token: %s\n"), fpath, line, name);
				ret = -1;
			}
		} else {
			warn(gettext("\"%s\", line %d: syntax error\n"),
			    fpath, line);
			ret = -1;
		}
	}
	if (line == 1) {
		warn(gettext("cannot read settings from %s\n"), fpath);
		ret = -1;
	}
	return (ret);
}

int
aconf_setup(acctconf_t *acp)
{
	void *buf;

	if ((buf = malloc(AC_BUFSIZE)) == NULL)
		die(gettext("not enough memory\n"));

	/*
	 * Setup process accounting
	 */
	(void) memset(buf, 0, AC_BUFSIZE);
	str2buf(buf, acp->ac_proc_untracked, AC_OFF, AC_PROC);
	str2buf(buf, acp->ac_proc_tracked, AC_ON, AC_PROC);
	if (acctctl(AC_PROC | AC_RES_SET, buf, AC_BUFSIZE) == -1) {
		warn(gettext("cannot enable or disable resources\n"));
		return (-1);
	}
	if (strcmp(acp->ac_proc_file, AC_STR_NONE) != 0) {
		if (acctctl(AC_PROC | AC_FILE_SET,
		    acp->ac_proc_file, strlen(acp->ac_proc_file) + 1) == -1) {
			warn(gettext("cannot open accounting file"));
			return (-1);
		}
	} else {
		if (acctctl(AC_PROC | AC_FILE_SET, NULL, 0) == -1) {
			warn(gettext("cannot close accounting file\n"));
			return (-1);
		}
	}
	if (acctctl(AC_PROC | AC_STATE_SET, &acp->ac_proc_state,
	    sizeof (int)) == -1) {
		warn(gettext("cannot enable/disable process accounting"));
		return (-1);
	}

	/*
	 * Setup flow accounting
	 */
	(void) memset(buf, 0, AC_BUFSIZE);
	str2buf(buf, acp->ac_flow_untracked, AC_OFF, AC_FLOW);
	str2buf(buf, acp->ac_flow_tracked, AC_ON, AC_FLOW);
	if (acctctl(AC_FLOW | AC_RES_SET, buf, AC_BUFSIZE) == -1) {
		warn(gettext("cannot enable or disable resources\n"));
		return (-1);
	}
	if (strcmp(acp->ac_flow_file, AC_STR_NONE) != 0) {
		if (acctctl(AC_FLOW | AC_FILE_SET,
		    acp->ac_flow_file, strlen(acp->ac_flow_file) + 1) == -1) {
			warn(gettext("cannot open accounting file"));
			return (-1);
		}
	} else {
		if (acctctl(AC_FLOW | AC_FILE_SET, NULL, 0) == -1) {
			warn(gettext("cannot close accounting file\n"));
			return (-1);
		}
	}
	if (acctctl(AC_FLOW | AC_STATE_SET, &acp->ac_flow_state,
	    sizeof (int)) == -1) {
		warn(gettext("cannot enable/disable flow accounting"));
		return (-1);
	}


	/*
	 * Setup task accounting
	 */
	(void) memset(buf, 0, AC_BUFSIZE);
	str2buf(buf, acp->ac_task_untracked, AC_OFF, AC_TASK);
	str2buf(buf, acp->ac_task_tracked, AC_ON, AC_TASK);
	if (acctctl(AC_TASK | AC_RES_SET, buf, AC_BUFSIZE) == -1) {
		warn(gettext("cannot enable or disable resources\n"));
		return (-1);
	}
	if (strcmp(acp->ac_task_file, AC_STR_NONE) != 0) {
		if (acctctl(AC_TASK | AC_FILE_SET,
		    acp->ac_task_file, strlen(acp->ac_task_file) + 1) == -1) {
			warn(gettext("cannot set accounting file"));
			return (-1);
		}
	} else {
		if (acctctl(AC_TASK | AC_FILE_SET, NULL, 0) == -1) {
			warn(gettext("cannot close accounting file\n"));
			return (-1);
		}
	}
	if (acctctl(AC_TASK | AC_STATE_SET, &acp->ac_task_state,
	    sizeof (int)) == -1) {
		warn(gettext("cannot enable/disable task accounting"));
		return (-1);
	}

	free(buf);
	return (0);
}

int
aconf_close(acctconf_t *acp)
{
	if (acp->ac_conf_fp != NULL && fclose(acp->ac_conf_fp) != 0)
		return (-1);
	else
		return (0);
}

int
aconf_write(acctconf_t *acp)
{
	ac_token_t *tokp;

	if (fseeko(acp->ac_conf_fp, (off_t)0, SEEK_SET) == -1) {
		warn(gettext("failed to seek config file"));
		return (-1);
	}
	if (ftruncate(acp->ac_conf_fd, (off_t)0) == -1) {
		warn(gettext("failed to truncate config file"));
		return (-1);
	}
	(void) fputs("#\n# acctadm.conf\n#\n"
	    "# Configuration parameters for extended accounting.\n"
	    "# Do NOT edit this file by hand -- use acctadm(1m) instead.\n"
	    "#\n", acp->ac_conf_fp);
	for (tokp = tokens; tokp->tok_name != NULL; tokp++) {
		if (fprintf(acp->ac_conf_fp, "%s=", tokp->tok_name) == -1 ||
		    tokp->tok_print(acp, acp->ac_conf_fp,
		    tokp->tok_type) == -1) {
			warn(gettext("failed to write token"));
			return (-1);
		}
	}
	if (fflush(acp->ac_conf_fp) != 0)
		warn(gettext("warning: failed to flush config file"));
	if (fsync(acp->ac_conf_fd) == -1)
		warn(gettext("warning: failed to sync config file to disk"));
	if (fchmod(acp->ac_conf_fd, AC_PERM) == -1)
		warn(gettext("warning: failed to reset mode on config file"));
	if (fchown(acp->ac_conf_fd, AC_OWNER, AC_GROUP) == -1)
		warn(gettext("warning: failed to reset owner on config file"));
	return (0);
}

void
aconf_print(acctconf_t *acp, FILE *fp, int type)
{
	if (type & AC_TASK) {
		(void) fprintf(fp,
		    gettext("            Task accounting: %s\n"),
		    acp->ac_task_state ?
		    gettext("active") : gettext("inactive"));
		(void) fprintf(fp,
		    gettext("       Task accounting file: %s\n"),
		    acp->ac_task_file);
		(void) fprintf(fp,
		    gettext("     Tracked task resources: %s\n"),
		    acp->ac_task_tracked);
		(void) fprintf(fp,
		    gettext("   Untracked task resources: %s\n"),
		    acp->ac_task_untracked);
	}
	if (type & AC_PROC) {
		(void) fprintf(fp,
		    gettext("         Process accounting: %s\n"),
		    acp->ac_proc_state ?
		    gettext("active") : gettext("inactive"));
		(void) fprintf(fp,
		    gettext("    Process accounting file: %s\n"),
		    acp->ac_proc_file);
		(void) fprintf(fp,
		    gettext("  Tracked process resources: %s\n"),
		    acp->ac_proc_tracked);
		(void) fprintf(fp,
		    gettext("Untracked process resources: %s\n"),
		    acp->ac_proc_untracked);
	}
	if (type & AC_FLOW) {
		(void) fprintf(fp,
		    gettext("            Flow accounting: %s\n"),
		    acp->ac_flow_state ?
		    gettext("active") : gettext("inactive"));
		(void) fprintf(fp,
		    gettext("       Flow accounting file: %s\n"),
		    acp->ac_flow_file);
		(void) fprintf(fp,
		    gettext("     Tracked flow resources: %s\n"),
		    acp->ac_flow_tracked);
		(void) fprintf(fp,
		    gettext("   Untracked flow resources: %s\n"),
		    acp->ac_flow_untracked);
	}
}

int
aconf_str2enable(acctconf_t *acp, char *buf, int type)
{
	int state;

	if (strcasecmp(buf, AC_STR_YES) == 0)
		state = AC_ON;
	else if (strcasecmp(buf, AC_STR_NO) == 0)
		state = AC_OFF;
	else
		return (-1);
	if (type == AC_PROC)
		acp->ac_proc_state = state;
	else if (type == AC_TASK)
		acp->ac_task_state = state;
	else if (type == AC_FLOW)
		acp->ac_flow_state = state;
	else
		return (-1);
	return (0);
}

int
aconf_str2file(acctconf_t *acp, char *buf, int type)
{
	if (strcmp(buf, AC_STR_NONE) != 0 && !valid_abspath(buf))
		return (-1);
	if (type == AC_PROC)
		(void) strlcpy(acp->ac_proc_file, buf, MAXPATHLEN);
	else if (type == AC_TASK)
		(void) strlcpy(acp->ac_task_file, buf, MAXPATHLEN);
	else if (type == AC_FLOW)
		(void) strlcpy(acp->ac_flow_file, buf, MAXPATHLEN);
	return (0);
}

int
aconf_str2tracked(acctconf_t *acp, char *buf, int type)
{
	if (type == AC_PROC)
		(void) strlcpy(acp->ac_proc_tracked, buf, MAXRESLEN);
	else if (type == AC_TASK)
		(void) strlcpy(acp->ac_task_tracked, buf, MAXRESLEN);
	else if (type == AC_FLOW)
		(void) strlcpy(acp->ac_flow_tracked, buf, MAXRESLEN);
	else
		return (-1);
	return (0);
}

int
aconf_str2untracked(acctconf_t *acp, char *buf, int type)
{
	if (type == AC_PROC)
		(void) strlcpy(acp->ac_proc_untracked, buf, MAXRESLEN);
	else if (type == AC_TASK)
		(void) strlcpy(acp->ac_task_untracked, buf, MAXRESLEN);
	else if (type == AC_FLOW)
		(void) strlcpy(acp->ac_flow_untracked, buf, MAXRESLEN);
	else
		return (-1);
	return (0);
}

static int
print_enable(acctconf_t *acp, FILE *fp, int type)
{
	if (type == AC_PROC)
		return (fprintf(fp, "%s\n", (acp->ac_proc_state == AC_OFF) ?
		    AC_STR_NO : AC_STR_YES));
	else if (type == AC_TASK)
		return (fprintf(fp, "%s\n", (acp->ac_task_state == AC_OFF) ?
		    AC_STR_NO : AC_STR_YES));
	else if (type == AC_FLOW)
		return (fprintf(fp, "%s\n", (acp->ac_flow_state == AC_OFF) ?
		    AC_STR_NO : AC_STR_YES));
	else
		return (-1);
}

static int
print_file(acctconf_t *acp, FILE *fp, int type)
{
	if (type == AC_PROC)
		return (fprintf(fp, "%s\n", acp->ac_proc_file));
	else if (type == AC_TASK)
		return (fprintf(fp, "%s\n", acp->ac_task_file));
	else if (type == AC_FLOW)
		return (fprintf(fp, "%s\n", acp->ac_flow_file));
	else
		return (-1);
}

static int
print_tracked(acctconf_t *acp, FILE *fp, int type)
{
	if (type == AC_PROC)
		return (fprintf(fp, "%s\n", acp->ac_proc_tracked));
	else if (type == AC_TASK)
		return (fprintf(fp, "%s\n", acp->ac_task_tracked));
	else if (type == AC_FLOW)
		return (fprintf(fp, "%s\n", acp->ac_flow_tracked));
	else
		return (-1);
}

static int
print_untracked(acctconf_t *acp, FILE *fp, int type)
{
	if (type == AC_PROC)
		return (fprintf(fp, "%s\n", acp->ac_proc_untracked));
	else if (type == AC_TASK)
		return (fprintf(fp, "%s\n", acp->ac_task_untracked));
	else if (type == AC_FLOW)
		return (fprintf(fp, "%s\n", acp->ac_flow_untracked));
	else
		return (-1);
}
