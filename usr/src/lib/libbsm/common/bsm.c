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

#include <sys/syscall.h>
#include <sys/types.h>
#include <bsm/audit.h>
#include <sys/socket.h>
#include <sys/param.h>

const char *bsm_dom = TEXT_DOMAIN;

int
auditdoor(int fd)
{
	return (syscall(SYS_auditsys, BSM_AUDITDOOR, fd));
}


int
audit(char *record, int length)
{
	return (syscall(SYS_auditsys, BSM_AUDIT, record, length));
}


int
getauid(au_id_t *auid)
{
	return (syscall(SYS_auditsys, BSM_GETAUID, auid));
}


int
setauid(au_id_t *auid)
{
	return (syscall(SYS_auditsys, BSM_SETAUID, auid));
}


int
getaudit(auditinfo_t *ai)
{
	return (syscall(SYS_auditsys, BSM_GETAUDIT, ai));
}

int
getaudit_addr(auditinfo_addr_t *ai, int len)
{
	return (syscall(SYS_auditsys, BSM_GETAUDIT_ADDR, ai, len));
}


int
setaudit(auditinfo_t *ai)
{
	return (syscall(SYS_auditsys, BSM_SETAUDIT, ai));
}


int
setaudit_addr(auditinfo_addr_t *ai, int len)
{
	return (syscall(SYS_auditsys, BSM_SETAUDIT_ADDR, ai, len));
}


int
auditon(int cmd, caddr_t data, int length)
{
	return (syscall(SYS_auditsys, BSM_AUDITCTL, cmd, data, length));
}
