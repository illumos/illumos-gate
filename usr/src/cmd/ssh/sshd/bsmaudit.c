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
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * usr/src/cmd/ssh/sshd/bsmaudit.c
 *
 * Taken from the on81 usr/src/lib/libbsm/common/audit_login.c
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "includes.h"

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

#include <stdarg.h>
#include <pwd.h>
#include <shadow.h>
#include <utmpx.h>
#include <unistd.h>
#include <string.h>

#include <locale.h>

#include "log.h"
#include "packet.h"
#include "canohost.h"
#include "servconf.h"
#include <errno.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>

extern uint_t utmp_len; /* XXX - Yuck; we'll keep this for now */
extern ServerOptions options;
	/*
	 * XXX - Yuck; we should have a
	 * get_client_name_or_ip that does the
	 * right thing wrt reverse lookups
	 */

void
audit_sshd_chauthtok(int pam_retval, uid_t uid, gid_t gid)
{
	adt_session_data_t	*ah	= NULL;
	adt_event_data_t	*event	= NULL;
	const char		*how = "couldn't start adt session";
	int			saved_errno = 0;

	if (adt_start_session(&ah, NULL, 0) != 0) {
		saved_errno = errno;
		goto fail;
	}
	if (adt_set_user(ah, uid, gid, uid, gid, NULL, ADT_NEW) != 0) {
		saved_errno = errno;
		how = "couldn't set adt user";
		goto fail;
	}

	if ((event = adt_alloc_event(ah, ADT_passwd)) == NULL) {
		saved_errno = errno;
		how = "couldn't allocate adt event";
		goto fail;
	}

	if (pam_retval == PAM_SUCCESS) {
		if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
			saved_errno = errno;
			how = "couldn't put adt event";
			goto fail;
		}
	} else if (adt_put_event(event, ADT_FAILURE,
	    ADT_FAIL_PAM + pam_retval) != 0) {
		saved_errno = errno;
		how = "couldn't put adt event";
		goto fail;
	}

	adt_free_event(event);
	(void) adt_end_session(ah);
	return;

fail:
	adt_free_event(event);
	(void) adt_end_session(ah);

	fatal("Auditing of password change failed: %s (%s)",
	    strerror(saved_errno), how);
}

void
audit_sshd_login(adt_session_data_t **ah, uid_t uid, gid_t gid)
{
	adt_event_data_t	*event	= NULL;
	const char		*how = "couldn't start adt session";
	int			saved_errno = 0;

	if (ah == NULL) {
		how = "programmer error";
		saved_errno = EINVAL;
		goto fail;
	}

	if (adt_start_session(ah, NULL, ADT_USE_PROC_DATA) != 0) {
		saved_errno = errno;
		how = "couldn't start adt session";
		goto fail;
	}
	if (adt_set_user(*ah, uid, gid, uid, gid,
		    NULL, ADT_USER) != 0) {
		saved_errno = errno;
		how = "couldn't set adt user";
		goto fail;
	}
	if ((event = adt_alloc_event(*ah, ADT_ssh)) == NULL) {
		saved_errno = errno;
		how = "couldn't allocate adt event";
		goto fail;
	}
	if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
		saved_errno = errno;
		how = "couldn't put adt event";
		goto fail;
	}

	adt_free_event(event);
	/* Don't end adt session - leave for when logging out */
	return;

fail:
	adt_free_event(event);
	(void) adt_end_session(*ah);

	fatal("Auditing of login failed: %s (%s)",
	    strerror(saved_errno), how);
}

void
audit_sshd_login_failure(adt_session_data_t **ah, int pam_retval)
{
	adt_event_data_t	*event	= NULL;
	const char		*how = "couldn't start adt session";
	int			saved_errno = 0;

	if (ah == NULL) {
		how = "programmer error";
		saved_errno = EINVAL;
		goto fail;
	}

	if (adt_start_session(ah, NULL, ADT_USE_PROC_DATA) != 0) {
		saved_errno = errno;
		how = "couldn't start adt session";
		goto fail;
	}

	if (adt_set_user(*ah, ADT_NO_ATTRIB, ADT_NO_ATTRIB,
	    ADT_NO_ATTRIB, ADT_NO_ATTRIB,
	    NULL, ADT_NEW) != 0) {
		saved_errno = errno;
		how = "couldn't set adt user";
		goto fail;
	}
	if ((event = adt_alloc_event(*ah, ADT_ssh)) == NULL) {
		saved_errno = errno;
		how = "couldn't allocate adt event";
		goto fail;
	}
	if (adt_put_event(event, ADT_FAILURE, ADT_FAIL_PAM + pam_retval) != 0) {
		saved_errno = errno;
		how = "couldn't put adt event";
		goto fail;
	}

	adt_free_event(event);
	(void) adt_end_session(*ah);
	*ah = NULL;
	return;

fail:
	adt_free_event(event);
	(void) adt_end_session(*ah);

	fatal("Auditing of login failed: %s (%s)",
	    strerror(saved_errno), how);
}

void
audit_sshd_logout(adt_session_data_t **ah)
{
	adt_event_data_t	*event	= NULL;
	const char		*how = "programmer error";
	int			saved_errno = 0;

	if (!ah) {
		saved_errno = EINVAL;
		goto fail;
	}

	if ((event = adt_alloc_event(*ah, ADT_logout)) == NULL) {
		saved_errno = errno;
		how = "couldn't allocate adt event";
		goto fail;
	}

	if (adt_put_event(event, ADT_SUCCESS, ADT_SUCCESS) != 0) {
		saved_errno = errno;
		how = "couldn't put adt event";
		goto fail;
	}

	adt_free_event(event);
	(void) adt_end_session(*ah);
	*ah = NULL;
	return;

fail:
	adt_free_event(event);
	(void) adt_end_session(*ah);

	fatal("Auditing of logout failed: %s (%s)",
	    how, strerror(saved_errno));
}

/*
 * audit_sshd_settid stores the terminal id while it is still
 * available.
 *
 * The failure cases are lack of resources or incorrect permissions.
 * libbsm generates syslog messages, so there's no value doing more
 * here.  ADT_NO_AUDIT leaves the auid at AU_NOAUDITID and will be
 * replaced when one of the above functions is called.
 */
void
audit_sshd_settid(int sock)
{
	adt_session_data_t	*ah;
	adt_termid_t		*termid;

	if (adt_start_session(&ah, NULL, 0) == 0) {
		if (adt_load_termid(sock, &termid) == 0) {
			if (adt_set_user(ah, ADT_NO_AUDIT,
			    ADT_NO_AUDIT, 0, ADT_NO_AUDIT,
			    termid, ADT_SETTID) == 0)
				(void) adt_set_proc(ah);
			free(termid);
		}
		(void) adt_end_session(ah);
	}
}
