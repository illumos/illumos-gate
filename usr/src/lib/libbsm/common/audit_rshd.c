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
#include <sys/fcntl.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <tsol/label.h>
#include <locale.h>
#include <unistd.h>
#include <generic.h>

static au_event_t	rshd_event;	/* audit event number */
static uint32_t		rshd_addr[4];	/* peer address */

static void generate_record(char *, char *, char *, int, char *);
static void setup_session(char *);
static int selected(uid_t, char *, au_event_t, int);

int
audit_rshd_setup()
{
	rshd_event = AUE_rshd;
	return (0);
}

/* ARGSUSED */
int
audit_rshd_fail(msg, hostname, remuser, locuser, cmdbuf)
char	*msg;		/* message containing failure information */
char	*hostname;		/* hostname of machine requesting service */
char	*remuser;		/* username at machine requesting service */
char	*locuser;		/* username of local machine */
char	*cmdbuf;		/* command line to be executed locally */
{
	if (cannot_audit(0)) {
		return (0);
	}
	generate_record(remuser, locuser, cmdbuf, -1, msg);
	return (0);
}

/* ARGSUSED */
int
audit_rshd_success(hostname, remuser, locuser, cmdbuf)
char	*hostname;		/* hostname of machine requesting service */
char	*remuser;		/* username at machine requesting service */
char	*locuser;		/* username at local machine */
char	*cmdbuf;		/* command line to be executed locally */
{
	if (cannot_audit(0)) {
		return (0);
	}
	generate_record(remuser, locuser, cmdbuf, 0, "");
	setup_session(locuser);
	return (0);
}


#include <pwd.h>

static void
generate_record(char *remuser,	/* username at machine requesting service */
		char *locuser,	/* username of local machine */
		char *cmdbuf,	/* command line to be executed locally */
		int sf_flag,	/* success (0) or failure (-1) flag */
		char *msg)	/* message containing failure information */
{
	int	rd;		/* audit record descriptor */
	char	buf[256];	/* temporary buffer */
	char	*tbuf;		/* temporary buffer */
	int	tlen;
	const char *gtxt;
	uid_t	uid;
	gid_t	gid;
	pid_t	pid;
	struct passwd *pwd;
	struct auditinfo_addr info;

	if (cannot_audit(0)) {
		return;
	}

	pwd = getpwnam(locuser);
	if (pwd == NULL) {
		uid = (uid_t)-1;
		gid = (gid_t)-1;
	} else {
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
	}

	if (!selected(uid, locuser, rshd_event, sf_flag))
		return;

	pid = getpid();

	/* see if terminal id already set */
	if (getaudit_addr(&info, sizeof (info)) < 0) {
		perror("getaudit");
	}
	rd = au_open();

	(void) au_write(rd, au_to_subject_ex(uid, uid, gid, uid, gid, pid, pid,
	    &info.ai_termid));
	if (is_system_labeled())
		(void) au_write(rd, au_to_mylabel());

	gtxt = dgettext(bsm_dom, "cmd %s");
	tlen = strlen(gtxt) + strlen(cmdbuf) + 1;
	if ((tbuf = malloc(tlen)) == NULL) {
		(void) au_close(rd, 0, 0);
		return;
	}
	(void) snprintf(tbuf, tlen, gtxt, cmdbuf);
	(void) au_write(rd, au_to_text(tbuf));
	(void) free(tbuf);

	if (strcmp(remuser, locuser) != 0) {
		(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
		    "remote user %s"), remuser);
		(void) au_write(rd, au_to_text(buf));
	}

	if (sf_flag == -1) {
		(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
		    "local user %s"), locuser);
		(void) au_write(rd, au_to_text(buf));
		(void) au_write(rd, au_to_text(msg));
	}

#ifdef _LP64
	(void) au_write(rd, au_to_return64(sf_flag, (int64_t)0));
#else
	(void) au_write(rd, au_to_return32(sf_flag, (int32_t)0));
#endif

	if (au_close(rd, 1, rshd_event) < 0) {
		(void) au_close(rd, 0, 0);
	}
}

static int
selected(uid_t uid, char *locuser, au_event_t event, int sf)
{
	int		sorf;
	struct au_mask	mask;

	mask.am_success = mask.am_failure = 0;
	if (uid > MAXEPHUID) {
		/* get non-attrib flags */
		(void) auditon(A_GETKMASK, (caddr_t)&mask, sizeof (mask));
	} else {
		(void) au_user_mask(locuser, &mask);
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

static void
setup_session(char *locuser)
{
	int	rc;
	struct auditinfo_addr info;
	au_mask_t		mask;
	uid_t			uid;
	struct passwd *pwd;

	pwd = getpwnam(locuser);
	if (pwd == NULL)
		uid = (uid_t)-1;
	else
		uid = pwd->pw_uid;

	/* see if terminal id already set */
	if (getaudit_addr(&info, sizeof (info)) < 0) {
		perror("getaudit");
	}

	info.ai_auid = uid;
	info.ai_asid = getpid();

	mask.am_success = 0;
	mask.am_failure = 0;
	(void) au_user_mask(locuser, &mask);

	info.ai_mask.am_success = mask.am_success;
	info.ai_mask.am_failure = mask.am_failure;

	rshd_addr[0] = info.ai_termid.at_addr[0];
	rshd_addr[1] = info.ai_termid.at_addr[1];
	rshd_addr[2] = info.ai_termid.at_addr[2];
	rshd_addr[3] = info.ai_termid.at_addr[3];

	rc = setaudit_addr(&info, sizeof (info));
	if (rc < 0) {
		perror("setaudit");
	}
}
