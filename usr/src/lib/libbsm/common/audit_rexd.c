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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <pwd.h>
#include <netinet/in.h>
#include <tsol/label.h>
#include <locale.h>
#include "generic.h"

#ifdef C2_DEBUG
#define	dprintf(x) { (void) printf x; }
#else
#define	dprintf(x)
#endif

#define	UNKNOWN_CMD	"???"

static au_event_t	event;
static int		audit_rexd_status = 0;

static char *
build_cmd(char **cmd)
{
	int i, l;
	char *r;

	if (cmd == NULL)
		return (NULL);
	/* count the total length of command line */
	for (i = 0, l = 0; cmd[i] != NULL; i++)
		l += strlen(cmd[i]) + 1;

	if (l == 0)
		return (NULL);
	r = malloc(l);
	if (r != NULL) {
		for (i = 0; cmd[i] != NULL; i++) {
			(void) strcat(r, cmd[i]);
			if (cmd[i + 1] != NULL)
				(void) strcat(r, " ");
		}
	}
	return (r);
}

static int
selected(uid, user, event, sf)
uid_t uid;
char	*user;
au_event_t	event;
int	sf;
{
	int		sorf;
	struct au_mask	mask;

	mask.am_success = mask.am_failure = 0;
	if (uid > MAXEPHUID) {
		/* get non-attrib flags */
		(void) auditon(A_GETKMASK, (caddr_t)&mask, sizeof (mask));
	} else {
		(void) au_user_mask(user, &mask);
	}

	if (sf == 0) {
		sorf = AU_PRS_SUCCESS;
	} else if (sf == -1) {
		sorf = AU_PRS_FAILURE;
	} else {
		sorf = AU_PRS_BOTH;
	}

	return (au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}

void
audit_rexd_setup()
{
	dprintf(("audit_rexd_setup()\n"));

	event = AUE_rexd;
}

/* ARGSUSED */
static void
audit_rexd_session_setup(char *name, char *mach, uid_t uid)
{
	int			rc;
	au_mask_t		mask;
	struct auditinfo_addr	info;

	if (getaudit_addr(&info, sizeof (info)) < 0) {
		perror("getaudit_addr");
		exit(1);
	}

	info.ai_auid = uid;
	info.ai_asid = getpid();

	mask.am_success = 0;
	mask.am_failure = 0;

	(void) au_user_mask(name, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	rc = setaudit_addr(&info, sizeof (info));
	if (rc < 0) {
		perror("setaudit_addr");
	}
}

void
audit_rexd_fail(msg, hostname, user, uid, gid, shell, cmd)
	char	*msg;		/* message containing failure information */
	char	*hostname;	/* hostname of machine requesting service */
	char	*user;		/* username of user requesting service */
	uid_t 	uid;		/* user id of user requesting service */
	gid_t	gid;		/* group of user requesting service */
	char	*shell;		/* login shell of user requesting service */
	char	**cmd;		/* argv to be executed locally */
{
	int	rd;		/* audit record descriptor */
	char	buf[256];	/* temporary buffer */
	char	*tbuf;		/* temporary buffer */
	int	tlen;
	const char *gtxt;	/* gettext return value */
	pid_t	pid;
	char	*cmdbuf;
	char	*audit_cmd[2] = {NULL, NULL};
	int	dont_free = 0;
	struct auditinfo_addr info;

	dprintf(("audit_rexd_fail()\n"));

	/*
	 * check if audit_rexd_fail() or audit_rexd_success()
	 * have been called already.
	 */
	if (audit_rexd_status == 1) {
		return;
	}

	if (cannot_audit(0)) {
		return;
	}

	/*
	 * set status to prevent multiple calls
	 * to audit_rexd_fail() and audit_rexd_success()
	 */
	audit_rexd_status = 1;

	/* determine if we're preselected */
	if (!selected(uid, user, event, -1))
		return;

	pid = getpid();

	if (getaudit_addr(&info, sizeof (info)) < 0) {
		perror("getaudit_addr");
		exit(1);
	}

	rd = au_open();

	/* add subject token */
	(void) au_write(rd,
		au_to_subject_ex(uid, uid, gid, uid, gid, pid, pid,
			&info.ai_termid));
	if (is_system_labeled())
		(void) au_write(rd, au_to_mylabel());

	/* add reason for failure */
	(void) au_write(rd, au_to_text(msg));

	/* add hostname of machine requesting service */
	(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
		"Remote execution requested by: %s"), hostname);
	(void) au_write(rd, au_to_text(buf));

	/* add username of user requesting service */
	if (user == NULL)
		user = "???";
	(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
	    "Username: %s"), user);
	(void) au_write(rd, au_to_text(buf));

	(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
	    "User id: %d"), uid);
	(void) au_write(rd, au_to_text(buf));

	if (cmd == NULL) {
		audit_cmd[0] = shell;
		cmd = audit_cmd;
	}

	cmdbuf = build_cmd(cmd);
	if (cmdbuf == NULL) {
		cmdbuf = UNKNOWN_CMD;
		dont_free = 1;
	}

	gtxt = dgettext(bsm_dom, "Command line: %s");
	/* over estimate of size of buffer needed (%s is replaced) */
	tlen = strlen(cmdbuf) + strlen(gtxt) + 1;

	if ((tbuf = malloc(tlen)) == NULL) {
		(void) au_close(rd, 0, 0);
		return;
	}
	(void) snprintf(tbuf, tlen, gtxt, cmdbuf);
	(void) au_write(rd, au_to_text(tbuf));
	(void) free(tbuf);
	if (!dont_free)
		(void) free(cmdbuf);

	/* add return token */
#ifdef _LP64
	(void) au_write(rd, au_to_return64(-1, (int64_t)0));
#else
	(void) au_write(rd, au_to_return32(-1, (int32_t)0));
#endif

	/* write audit record */
	if (au_close(rd, 1, event) < 0) {
		(void) au_close(rd, 0, 0);
		return;
	}
}

void
audit_rexd_success(hostname, user, uid, gid, shell, cmd)
char	*hostname;	/* hostname of machine requesting service */
char	*user;		/* username of user requesting service, may be NULL */
uid_t 	uid;		/* user id of user requesting service */
gid_t	gid;		/* group of user requesting service */
char	*shell;		/* login shell of user requesting service */
char	**cmd;		/* argv to be executed locally, may be NULL */
{
	int	rd;			/* audit record descriptor */
	char	buf[256];	/* temporary buffer */
	char	*tbuf;		/* temporary buffer */
	int	tlen;
	const char *gtxt;
	pid_t	pid;
	char	*cmdbuf;
	char	*audit_cmd[2] = {NULL, NULL};
	int	dont_free = 0;
	struct auditinfo_addr info;
	char	*empty = "";

	dprintf(("audit_rexd_success()\n"));

	/*
	 * check if audit_rexd_fail() or audit_rexd_success()
	 * have been called already.
	 */
	if (audit_rexd_status == 1) {
		return;
	}

	if (cannot_audit(0)) {
		return;
	}

	/* a little bullet proofing... */

	if (hostname == NULL)
		hostname = empty;
	if (shell == NULL)
		shell = empty;

	/*
	 * set status to prevent multiple calls
	 * to audit_rexd_fail() and audit_rexd_success()
	 */
	audit_rexd_status = 1;

	/* determine if we're preselected */
	if (!selected(uid, user, event, 0))
		goto rexd_audit_session;

	pid = getpid();

	if (getaudit_addr(&info, sizeof (info)) < 0) {
		perror("getaudit_addr");
		exit(1);
	}

	rd = au_open();

	/* add subject token */
	(void) au_write(rd,
		au_to_subject_ex(uid, uid, gid, uid, gid, pid, pid,
			&info.ai_termid));
	if (is_system_labeled())
		(void) au_write(rd, au_to_mylabel());

	/* add hostname of machine requesting service */

	(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
		"Remote execution requested by: %s"), hostname);
	(void) au_write(rd, au_to_text(buf));

	/* add username at machine requesting service */
	(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
	    "Username: %s"), user);
	(void) au_write(rd, au_to_text(buf));

	if (cmd == NULL) {
		audit_cmd[0] = shell;
		cmd = audit_cmd;
	}

	cmdbuf = build_cmd(cmd);
	if (cmdbuf == NULL) {
		cmdbuf = UNKNOWN_CMD;
		dont_free = 1;
	}

	gtxt = dgettext(bsm_dom, "Command line: %s");
	tlen = strlen(cmdbuf) + strlen(gtxt) + 1;

	if ((tbuf = malloc(tlen)) == NULL) {
		(void) au_close(rd, 0, 0);
		goto rexd_audit_session;
	}

	(void) snprintf(tbuf, tlen, gtxt, cmdbuf);
	(void) au_write(rd, au_to_text(tbuf));
	(void) free(tbuf);
	if (!dont_free)
		(void) free(cmdbuf);

	/* add return token */
#ifdef _LP64
	(void) au_write(rd, au_to_return64(0, (int64_t)0));
#else
	(void) au_write(rd, au_to_return32(0, (int32_t)0));
#endif

	/* write audit record */
	if (au_close(rd, 1, event) < 0) {
		(void) au_close(rd, 0, 0);
	}

rexd_audit_session:
	audit_rexd_session_setup(user, hostname, uid);
}
