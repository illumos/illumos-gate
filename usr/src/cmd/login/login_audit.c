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

#include <assert.h>
#include <priv.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/wait.h>

#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include "login_audit.h"

/*
 * Key assumption:  login is single threaded.
 */
static void audit_logout(adt_session_data_t *);

/*
 * if audit is not enabled, the adt_*() functions simply return without
 * doing anything.  In the success case, the credential has already been
 * setup with audit data by PAM.
 */

/*
 * There is no information passed to login.c from rlogin or telnet
 * about the terminal id.  They both set the tid before they
 * exec login; the value is picked up by adt_start_session() and is
 * carefully *not* overwritten by adt_load_hostname().
 */

void
audit_success(uint_t event_id, struct passwd *pwd, char *optional_text)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	int			rc;

	assert(pwd != NULL);

	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA)) {
		syslog(LOG_AUTH | LOG_ALERT, "login adt_start_session(): %m");
		return;
	}
	if (adt_set_user(ah, pwd->pw_uid,  pwd->pw_gid,
	    pwd->pw_uid,  pwd->pw_gid, NULL, ADT_USER)) {
		syslog(LOG_AUTH | LOG_ALERT, "login adt_set_user(): %m");
		(void) adt_end_session(ah);
		return;
	}
	event = adt_alloc_event(ah, event_id);

	if (event == NULL)
		return;

	switch (event_id) {
	case ADT_zlogin:
		event->adt_zlogin.message = optional_text;
		break;
	default:
		break;
	}
	rc = adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS);

	(void) adt_free_event(event);
	if (rc) {
		(void) adt_end_session(ah);
		syslog(LOG_AUTH | LOG_ALERT, "login adt_put_event(): %m");
		return;
	}
	/*
	 * The code above executes whether or not audit is enabled.
	 * However audit_logout must only execute if audit is
	 * enabled so we don't fork unnecessarily.
	 */
	if (adt_audit_enabled()) {
		switch (event_id) {
		case ADT_login:
		case ADT_rlogin:
		case ADT_telnet:
		case ADT_zlogin:
			audit_logout(ah);	/* fork to catch logout */
			break;
		}
	}
	(void) adt_end_session(ah);
}

/*
 * errors are ignored since there is no action to take on error
 */
static void
audit_logout(adt_session_data_t *ah)
{
	adt_event_data_t	*logout;
	int			status;		/* wait status */
	pid_t			pid;
	priv_set_t		*priv;		/* waiting process privs */

	if ((logout = adt_alloc_event(ah, ADT_logout)) == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "adt_alloc_event(ADT_logout): %m");
		return;
	}
	if ((priv = priv_allocset())  == NULL) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "login audit_logout: could not alloc basic privs: %m");
		adt_free_event(logout);
		return;
	}

	/*
	 * The child returns and continues the login processing.
	 * The parent's sole job is to wait for child exit, write the
	 * logout audit record, and replay the child's exit code.
	 */

	if ((pid = fork()) == 0) {
		/* child */

		adt_free_event(logout);
		priv_freeset(priv);
		return;
	}
	if (pid == -1) {
		/* failure */

		syslog(LOG_AUTH | LOG_ALERT,
		    "login audit_logout: could not fork: %m");
		adt_free_event(logout);
		priv_freeset(priv);
		return;
	}

	/* parent process */

	/*
	 * When this routine is called, the current working
	 * directory is the user's home directory and there are
	 * unknown open files. For the waiting process, change the
	 * current directory to root and close files so that the
	 * user's home directory and anything else can be unmounted
	 * if necessary.
	 */
	if (chdir("/") != 0) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "login audit_logut: could not chdir /: %m");
	}
	/*
	 * Reduce privileges to just those needed.
	 */
	priv_basicset(priv);
	(void) priv_delset(priv, PRIV_PROC_EXEC);
	(void) priv_delset(priv, PRIV_PROC_FORK);
	(void) priv_delset(priv, PRIV_PROC_INFO);
	(void) priv_delset(priv, PRIV_PROC_SESSION);
	(void) priv_delset(priv, PRIV_FILE_LINK_ANY);
	if ((priv_addset(priv, PRIV_PROC_AUDIT) != 0) ||
	    (setppriv(PRIV_SET, PRIV_PERMITTED, priv) != 0)) {
		syslog(LOG_AUTH | LOG_ALERT,
		    "login audit_logout: could not reduce privs: %m");
	}
	closefrom(0);
	priv_freeset(priv);
	while (pid != waitpid(pid, &status, 0))
		continue;

	(void) adt_put_event(logout, ADT_SUCCESS, ADT_SUCCESS);
	adt_free_event(logout);
	(void) adt_end_session(ah);
	exit(WEXITSTATUS(status));
}

/*
 * errors are ignored since there is no action to take on error.
 *
 * If the user id is invalid, pwd is NULL.
 */
void
audit_failure(uint_t event_id, int failure_code, struct passwd *pwd,
    const char *hostname, const char *ttyname, char *optional_text)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;
	uid_t			uid;
	gid_t			gid;
	adt_termid_t		*p_tid;

	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA))
		return;

	uid = ADT_NO_ATTRIB;
	gid = ADT_NO_ATTRIB;
	if (pwd != NULL) {
		uid = pwd->pw_uid;
		gid = pwd->pw_gid;
	}
	/*
	 * If this is a remote login, in.rlogind or in.telnetd has
	 * already set the terminal id, in which case
	 * adt_load_hostname() will use the preset terminal id and
	 * ignore hostname.  (If no remote host and ttyname is NULL,
	 * let adt_load_ttyname() figure out what to do.)
	 */
	if (*hostname == '\0')
		(void) adt_load_ttyname(ttyname, &p_tid);
	else
		(void) adt_load_hostname(hostname, &p_tid);

	if (adt_set_user(ah, uid, gid, uid, gid, p_tid, ADT_NEW)) {
		(void) adt_end_session(ah);
		if (p_tid != NULL)
			free(p_tid);
		return;
	}
	if (p_tid != NULL)
		free(p_tid);

	event = adt_alloc_event(ah, event_id);
	if (event == NULL) {
		return;
	}
	switch (event_id) {
	case ADT_zlogin:
		event->adt_zlogin.message = optional_text;
		break;
	}
	(void) adt_put_event(event, ADT_FAILURE, failure_code);

	adt_free_event(event);
	(void) adt_end_session(ah);
}
