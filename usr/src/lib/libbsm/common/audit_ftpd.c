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
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>
#include <tsol/label.h>

#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/audit_uevents.h>
#include <bsm/libbsm.h>
#include <bsm/audit_private.h>

#include <locale.h>
#include <pwd.h>
#include <generic.h>

#define	BAD_PASSWD	(1)
#define	UNKNOWN_USER	(2)
#define	EXCLUDED_USER	(3)
#define	NO_ANONYMOUS	(4)
#define	MISC_FAILURE	(5)

static char		luser[LOGNAME_MAX + 1];

static void generate_record(char *, int, char *);
static int selected(uid_t, char *, au_event_t, int);

void
audit_ftpd_bad_pw(char *uname)
{
	if (cannot_audit(0)) {
		return;
	}
	(void) strncpy(luser, uname, LOGNAME_MAX);
	generate_record(luser, BAD_PASSWD, dgettext(bsm_dom, "bad password"));
}


void
audit_ftpd_unknown(char	*uname)
{
	if (cannot_audit(0)) {
		return;
	}
	(void) strncpy(luser, uname, LOGNAME_MAX);
	generate_record(luser, UNKNOWN_USER, dgettext(bsm_dom, "unknown user"));
}


void
audit_ftpd_excluded(char *uname)
{
	if (cannot_audit(0)) {
		return;
	}
	(void) strncpy(luser, uname, LOGNAME_MAX);
	generate_record(luser, EXCLUDED_USER, dgettext(bsm_dom,
	    "excluded user"));
}


void
audit_ftpd_no_anon(void)
{
	if (cannot_audit(0)) {
		return;
	}
	generate_record("", NO_ANONYMOUS, dgettext(bsm_dom, "no anonymous"));
}

void
audit_ftpd_failure(char *uname)
{
	if (cannot_audit(0)) {
		return;
	}
	generate_record(uname, MISC_FAILURE, dgettext(bsm_dom, "misc failure"));
}

void
audit_ftpd_success(char	*uname)
{
	if (cannot_audit(0)) {
		return;
	}
	(void) strncpy(luser, uname, LOGNAME_MAX);
	generate_record(luser, 0, "");
}



static void
generate_record(
		char	*locuser,	/* username of local user */
		int	err,		/* error status */
					/* (=0 success, >0 error code) */
		char	*msg)		/* error message */
{
	int	rd;		/* audit record descriptor */
	char	buf[256];	/* temporary buffer */
	uid_t	uid;
	gid_t	gid;
	uid_t	ruid;		/* real uid */
	gid_t	rgid;		/* real gid */
	pid_t	pid;
	struct passwd *pwd;
	uid_t	ceuid;		/* current effective uid */
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

	ceuid = geteuid();	/* save current euid */
	(void) seteuid(0);	/* change to root so you can audit */

	/* determine if we're preselected */
	if (!selected(uid, locuser, AUE_ftpd, err)) {
		(void) seteuid(ceuid);
		return;
	}

	ruid = getuid();	/* get real uid */
	rgid = getgid();	/* get real gid */

	pid = getpid();

	/* see if terminal id already set */
	if (getaudit_addr(&info, sizeof (info)) < 0) {
		perror("getaudit");
	}

	rd = au_open();

	/* add subject token */
	(void) au_write(rd, au_to_subject_ex(uid, uid, gid,
	    ruid, rgid, pid, pid, &info.ai_termid));

	if (is_system_labeled())
		(void) au_write(rd, au_to_mylabel());

	/* add return token */
	errno = 0;
	if (err) {
		/* add reason for failure */
		if (err == UNKNOWN_USER)
			(void) snprintf(buf, sizeof (buf),
			    "%s %s", msg, locuser);
		else
			(void) snprintf(buf, sizeof (buf), "%s", msg);
		(void) au_write(rd, au_to_text(buf));
#ifdef _LP64
		(void) au_write(rd, au_to_return64(-1, (int64_t)err));
#else
		(void) au_write(rd, au_to_return32(-1, (int32_t)err));
#endif
	} else {
#ifdef _LP64
		(void) au_write(rd, au_to_return64(0, (int64_t)0));
#else
		(void) au_write(rd, au_to_return32(0, (int32_t)0));
#endif
	}

	/* write audit record */
	if (au_close(rd, 1, AUE_ftpd) < 0) {
		(void) au_close(rd, 0, 0);
	}
	(void) seteuid(ceuid);
}


static int
selected(
	uid_t		uid,
	char		*locuser,
	au_event_t	event,
	int	err)
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

	if (err == 0) {
		sorf = AU_PRS_SUCCESS;
	} else if (err >= 1) {
		sorf = AU_PRS_FAILURE;
	} else {
		sorf = AU_PRS_BOTH;
	}

	return (au_preselect(event, &mask, sorf, AU_PRS_REREAD));
}


void
audit_ftpd_logout(void)
{
	int	rd;		/* audit record descriptor */
	uid_t	euid;
	gid_t	egid;
	uid_t	uid;
	gid_t	gid;
	pid_t	pid;
	struct auditinfo_addr info;

	if (cannot_audit(0)) {
		return;
	}

	(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_PROC_AUDIT, NULL);

	/* see if terminal id already set */
	if (getaudit_addr(&info, sizeof (info)) < 0) {
		perror("getaudit");
	}

	/* determine if we're preselected */
	if (au_preselect(AUE_ftpd_logout, &info.ai_mask, AU_PRS_SUCCESS,
	    AU_PRS_USECACHE) == 0) {
		(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_AUDIT,
		    NULL);
		return;
	}

	euid = geteuid();
	egid = getegid();
	uid = getuid();
	gid = getgid();
	pid = getpid();

	rd = au_open();

	/* add subject token */
	(void) au_write(rd, au_to_subject_ex(info.ai_auid, euid,
	    egid, uid, gid, pid, pid, &info.ai_termid));

	if (is_system_labeled())
		(void) au_write(rd, au_to_mylabel());

	/* add return token */
	errno = 0;
#ifdef _LP64
	(void) au_write(rd, au_to_return64(0, (int64_t)0));
#else
	(void) au_write(rd, au_to_return32(0, (int32_t)0));
#endif

	/* write audit record */
	if (au_close(rd, 1, AUE_ftpd_logout) < 0) {
		(void) au_close(rd, 0, 0);
	}
	(void) priv_set(PRIV_OFF, PRIV_EFFECTIVE, PRIV_PROC_AUDIT, NULL);
}
