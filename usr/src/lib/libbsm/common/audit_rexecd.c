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

static au_event_t	event;
static int		audit_rexecd_status = 0;

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
audit_rexecd_setup()
{
	dprintf(("audit_rexecd_setup()\n"));

	event = AUE_rexecd;
}


static void
audit_rexecd_session_setup(char *name, char *mach, uid_t uid)
{
	int			rc;
	au_mask_t		mask;
	struct auditinfo_addr	info;
	uint32_t addr[4], type;

	info.ai_auid = uid;
	info.ai_asid = getpid();

	mask.am_success = 0;
	mask.am_failure = 0;

	(void) au_user_mask(name, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	rc = aug_get_machine(mach, addr, &type);
	if (rc < 0) {
		perror("get address");
	}
	info.ai_termid.at_port = aug_get_port();
	info.ai_termid.at_type    = type;
	info.ai_termid.at_addr[0] = addr[0];
	info.ai_termid.at_addr[1] = addr[1];
	info.ai_termid.at_addr[2] = addr[2];
	info.ai_termid.at_addr[3] = addr[3];

	rc = setaudit_addr(&info, sizeof (info));
	if (rc < 0) {
		perror("setaudit");
	}
}

void
audit_rexecd_fail(msg, hostname, user, cmdbuf)
char	*msg;		/* message containing failure information */
char	*hostname;	/* hostname of machine requesting service */
char	*user;		/* username of user requesting service */
char	*cmdbuf;	/* command line to be executed locally */
{
	int	rd;		/* audit record descriptor */
	char	buf[256];	/* temporary buffer */
	char	*tbuf;		/* temporary buffer */
	int	tlen;
	const char *gtxt;
	uid_t 	uid;
	gid_t	gid;
	pid_t	pid;
	au_tid_addr_t	tid;
	struct passwd	*pwd;
	uint32_t addr[4], type;
	int rc;

	dprintf(("audit_rexecd_fail()\n"));

	/*
	 * check if audit_rexecd_fail() or audit_rexecd_success()
	 * have been called already.
	 */
	if (audit_rexecd_status == 1) {
		return;
	}

	if (cannot_audit(0)) {
		return;
	}

	/*
	 * set status to prevent multiple calls
	 * to audit_rexecd_fail() and audit_rexecd_success()
	 */
	audit_rexecd_status = 1;

	pwd = getpwnam(user);
	if (pwd == NULL) {
		uid = (uid_t)-1;
		gid = (gid_t)-1;
	} else {
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
	}

	/* determine if we're preselected */
	if (!selected(uid, user, event, -1))
		return;

	pid = getpid();
	rc = aug_get_machine(hostname, addr, &type);
	if (rc < 0) {
		perror("get address");
	}

	tid.at_port    = aug_get_port();
	tid.at_addr[0] = addr[0];
	tid.at_addr[1] = addr[1];
	tid.at_addr[2] = addr[2];
	tid.at_addr[3] = addr[3];
	tid.at_type    = type;

	rd = au_open();

	/* add subject token */
	(void) au_write(rd,
		au_to_subject_ex(uid, uid, gid, uid, gid, pid, pid, &tid));
	if (is_system_labeled())
		(void) au_write(rd, au_to_mylabel());

	/* add reason for failure */
	(void) au_write(rd, au_to_text(msg));

	/* add hostname of machine requesting service */
	(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
		"Remote execution requested by: %s"), hostname);
	(void) au_write(rd, au_to_text(buf));

	/* add username of user requesting service */
	(void) snprintf(buf, sizeof (buf), dgettext(bsm_dom,
		"Username: %s"), user);
	(void) au_write(rd, au_to_text(buf));

	/* add command line to be executed locally */
	gtxt = dgettext(bsm_dom, "Command line: %s");
	tlen = strlen(gtxt) + strlen(cmdbuf) + 1;
	if ((tbuf = malloc(tlen)) == NULL) {
		(void) au_close(rd, 0, 0);
		return;
	}
	(void) snprintf(tbuf, tlen, gtxt, cmdbuf);
	(void) au_write(rd, au_to_text(tbuf));
	(void) free(tbuf);

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
audit_rexecd_success(hostname, user, cmdbuf)
char	*hostname;	/* hostname of machine requesting service */
char	*user;		/* username of user requesting service */
char	*cmdbuf;	/* command line to be executed locally */
{
	int	rd;		/* audit record descriptor */
	char	buf[256];	/* temporary buffer */
	char	*tbuf;		/* temporary buffer */
	int	tlen;
	const char *gtxt;
	uid_t 	uid;
	gid_t	gid;
	pid_t	pid;
	au_tid_addr_t	tid;
	struct passwd	*pwd;
	uint32_t addr[4], type;
	int rc;

	dprintf(("audit_rexecd_success()\n"));

	/*
	 * check if audit_rexecd_fail() or audit_rexecd_success()
	 * have been called already.
	 */
	if (audit_rexecd_status == 1) {
		return;
	}

	if (cannot_audit(0)) {
		return;
	}

	/*
	 * set status to prevent multiple calls
	 * to audit_rexecd_fail() and audit_rexecd_success()
	 */
	audit_rexecd_status = 1;

	pwd = getpwnam(user);
	if (pwd == NULL) {
		uid = (uid_t)-1;
		gid = (gid_t)-1;
	} else {
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
	}

	/* determine if we're preselected */
	if (!selected(uid, user, event, 0))
		goto rexecd_audit_session;

	pid = getpid();
	rc = aug_get_machine(hostname, addr, &type);
	if (rc < 0) {
		perror("get address");
	}

	tid.at_port    = aug_get_port();
	tid.at_addr[0] = addr[0];
	tid.at_addr[1] = addr[1];
	tid.at_addr[2] = addr[2];
	tid.at_addr[3] = addr[3];
	tid.at_type    = type;

	rd = au_open();

	/* add subject token */
	(void) au_write(rd,
		au_to_subject_ex(uid, uid, gid, uid, gid, pid, pid, &tid));
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

	/* add command line to be executed locally */
	gtxt = dgettext(bsm_dom, "Command line: %s");
	tlen = strlen(gtxt) + strlen(cmdbuf) + 1;
	if ((tbuf = malloc(tlen)) == NULL) {
		(void) au_close(rd, 0, 0);
	} else {
		(void) snprintf(tbuf, tlen, gtxt, cmdbuf);
		(void) au_write(rd, au_to_text(tbuf));
		(void) free(tbuf);

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
	}

rexecd_audit_session:
	audit_rexecd_session_setup(user, hostname, uid);
}
