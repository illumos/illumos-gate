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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_BSMAUDIT_H
#define	_BSMAUDIT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <bsm/adt.h>
#include <bsm/adt_event.h>
#include <pwd.h>

void audit_sshd_chauthtok(int pam_retval, uid_t uid, gid_t gid);
void audit_sshd_login(adt_session_data_t **ah, pid_t pid);
void audit_sshd_login_failure(adt_session_data_t **ah, int pam_retval,
	char *user);
void audit_sshd_logout(adt_session_data_t **ah);
void audit_sshd_settid(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _BSMAUDIT_H */
