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

#include <sys/systeminfo.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/systeminfo.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#include <pwd.h>
#include <stdlib.h>
#include <shadow.h>
#include <utmpx.h>
#include <unistd.h>
#include <string.h>

#include <bsm/audit.h>
#include <bsm/libbsm.h>
#include <bsm/audit_uevents.h>
#include <bsm/audit_record.h>
#include <bsm/audit_private.h>
#include <generic.h>

#include <locale.h>

static void audit_login_record();
static void audit_login_session_setup();

static void get_terminal_id();
static void audit_login_logout();
static int get_machine(uint32_t *, uint32_t *);
static int selected();

static char	sav_ttyn[512];
static int	sav_rflag;
static int	sav_hflag;
static char	sav_name[512];
static uid_t	sav_uid;
static gid_t	sav_gid;
static dev_t	sav_port;
static uint32_t	sav_machine[4];
static uint32_t	sav_iptype;
static char	sav_host[512];

int
audit_login_save_flags(rflag, hflag)
	int rflag, hflag;
{

	if (cannot_audit(0)) {
		return (0);
	}
	sav_rflag = rflag;
	sav_hflag = hflag;
	return (0);
}

int
audit_login_save_host(host)
	char *host;
{
	int rv;

	if (cannot_audit(0)) {
		return (0);
	}
	(void) strncpy(sav_host, host, 511);
	sav_host[511] = '\0';
	rv = audit_login_save_machine();
	return (rv);
}

int
audit_login_save_ttyn(ttyn)
	char *ttyn;
{
	if (cannot_audit(0)) {
		return (0);
	}
	(void) strncpy(sav_ttyn, ttyn, 511);
	sav_ttyn[511] = '\0';
	return (0);
}

int
audit_login_save_port()
{
	if (cannot_audit(0)) {
		return (0);
	}
	sav_port = aug_get_port();
	return (0);
}

int
audit_login_save_machine()
{
	int rv;

	if (cannot_audit(0)) {
		return (0);
	}
	rv = get_machine(&sav_machine[0], &sav_iptype);

	return (rv);
}

int
audit_login_save_pw(pwd)
	struct passwd *pwd;
{
	if (cannot_audit(0)) {
		return (0);
	}
	if (pwd == NULL) {
		sav_name[0] = '\0';
		sav_uid = -1;
		sav_gid = -1;
	} else {
		(void) strncpy(sav_name, pwd->pw_name, 511);
		sav_name[511] = '\0';
		sav_uid = pwd->pw_uid;
		sav_gid = pwd->pw_gid;
	}
	return (0);
}

int
audit_login_maxtrys()
{
	if (cannot_audit(0)) {
		return (0);
	}
	audit_login_record(1, dgettext(bsm_dom, "maxtrys"),
		AUE_login);
	return (0);
}

int
audit_login_not_console()
{
	if (cannot_audit(0)) {
		return (0);
	}
	audit_login_record(2, dgettext(bsm_dom, "not_console"),
		AUE_login);
	return (0);
}

int
audit_login_bad_pw()
{
	if (cannot_audit(0)) {
		return (0);
	}
	if (sav_uid == -1) {
		audit_login_record(3, dgettext(bsm_dom,
			"invalid user name"), AUE_login);
	} else {
		audit_login_record(4, dgettext(bsm_dom,
			"invalid password"), AUE_login);
	}
	return (0);
}

int
audit_login_bad_dialup()
{
	if (cannot_audit(0)) {
		return (0);
	}
	audit_login_record(5, dgettext(bsm_dom,
		"invalid dialup password"), AUE_login);
	return (0);
}

int
audit_login_success()
{
	if (cannot_audit(0)) {
		return (0);
	}
	audit_login_session_setup();
	audit_login_record(0, dgettext(bsm_dom,
		"successful login"), AUE_login);
	audit_login_logout();
	return (0);
}

static void
audit_login_record(typ, string, event_no)
int	typ;
char	*string;
au_event_t event_no;
{
	int		ad, rc;
	uid_t		uid;
	gid_t		gid;
	pid_t		pid;
	au_tid_addr_t	tid;

	uid = sav_uid;
	gid = sav_gid;
	pid = getpid();

	get_terminal_id(&tid);

	if (typ == 0) {
		rc = 0;
	} else {
		rc = -1;
	}

	if (event_no == AUE_login) {
		if (sav_hflag)  {
			event_no = AUE_telnet;
		}
		if (sav_rflag) {
			event_no = AUE_rlogin;
		}
	}

	if (!selected(sav_name, uid, event_no, rc))
		return;

	ad = au_open();

	(void) au_write(ad, au_to_subject_ex(uid, uid,
		gid, uid, gid, pid, pid, &tid));
	(void) au_write(ad, au_to_text(string));
#ifdef _LP64
	(void) au_write(ad, au_to_return64(typ, (int64_t)rc));
#else
	(void) au_write(ad, au_to_return32(typ, (int32_t)rc));
#endif

	rc = au_close(ad, AU_TO_WRITE, event_no);
	if (rc < 0) {
		perror("audit");
	}
}

static void
audit_login_session_setup()
{
	int	rc;
	struct auditinfo_addr info;
	au_mask_t mask;
	struct auditinfo_addr now;

	info.ai_auid = sav_uid;
	info.ai_asid = getpid();
	mask.am_success = 0;
	mask.am_failure = 0;

	(void) au_user_mask(sav_name, &mask);

	info.ai_mask.am_success  = mask.am_success;
	info.ai_mask.am_failure  = mask.am_failure;

	/* see if terminal id already set */
	if (getaudit_addr(&now, sizeof (now)) < 0) {
		perror("getaudit");
	}
	/*
	 * Don't allow even a privileged process to change terminal
	 * info once it has been set
	 */
	if (now.ai_termid.at_port ||
	    now.ai_termid.at_addr[0] ||
	    now.ai_termid.at_addr[1] ||
	    now.ai_termid.at_addr[2] ||
	    now.ai_termid.at_addr[3]) {
		info.ai_termid = now.ai_termid;
		/* update terminal ID with real values */
		sav_port   = now.ai_termid.at_port;
		sav_iptype = now.ai_termid.at_type;
		sav_machine[0] = now.ai_termid.at_addr[0];
		sav_machine[1] = now.ai_termid.at_addr[1];
		sav_machine[2] = now.ai_termid.at_addr[2];
		sav_machine[3] = now.ai_termid.at_addr[3];
	} else
		get_terminal_id(&(info.ai_termid));

	rc = setaudit_addr(&info, sizeof (info));
	if (rc < 0) {
		perror("setaudit");
	}
}


static void
get_terminal_id(tid)
au_tid_addr_t *tid;
{
	tid->at_port = sav_port;
	tid->at_type = sav_iptype;
	tid->at_addr[0] = sav_machine[0];
	tid->at_addr[1] = sav_machine[1];
	tid->at_addr[2] = sav_machine[2];
	tid->at_addr[3] = sav_machine[3];
}

static void
audit_login_logout()
{
	int	ret; /* return value of wait() */
	int	status; /* wait status */
	pid_t pid; /* process id */

	if ((pid = fork()) == 0) {
		return;
	} else if (pid == -1) {
		(void) fputs(dgettext(bsm_dom,
			"login: could not fork\n"), stderr);
		exit(1);
	} else {
		char	textbuf[BSM_TEXTBUFSZ];

		/*
		 * When this routine is called, the current working
		 * directory is the user's home directory. Change it
		 * to root for the waiting process so that the user's
		 * home directory can be unmounted if necessary.
		 */
		if (chdir("/") != 0) {
			(void) fputs(dgettext(bsm_dom,
				"login: could not chdir\n"), stderr);
			/* since we let the child finish we just bail */
			exit(0);
		}

		(void) sigset(SIGCHLD, SIG_DFL);
		while ((ret = (int)wait(&status)) != pid && ret != -1);
			/* keep waiting */
		(void) snprintf(textbuf, sizeof (textbuf),
			dgettext(bsm_dom, "logout %s"), sav_name);
		audit_login_record(0, textbuf, AUE_logout);
		exit(0);
	}
}

static int
get_machine(uint32_t *buf, uint32_t *iptype)
{
	int	rc;
	char	hostname[256];
	int stat;

	if (sav_rflag || sav_hflag) {
		stat = aug_get_machine(sav_host, buf, iptype);
	} else {
		rc = sysinfo(SI_HOSTNAME, hostname, 256);
		if (rc < 0) {
			perror("sysinfo");
			return (0);
		}
		stat = aug_get_machine(hostname, buf, iptype);
	}
	return (stat);
}


static int
selected(nam, uid, event, sf)
char	*nam;
uid_t uid;
au_event_t event;
int	sf;
{
	int	rc, sorf;
	char	naflags[512];
	struct au_mask mask;

	mask.am_success = mask.am_failure = 0;
	if (uid < 0) {
		rc = getacna(naflags, 256); /* get non-attrib flags */
		if (rc == 0)
			(void) getauditflagsbin(naflags, &mask);
	} else {
		rc = au_user_mask(nam, &mask);
	}

	if (sf == 0) {
		sorf = AU_PRS_SUCCESS;
	} else {
		sorf = AU_PRS_FAILURE;
	}
	rc = au_preselect(event, &mask, sorf, AU_PRS_REREAD);

	return (rc);
}
