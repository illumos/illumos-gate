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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SCSI_RESET_NOTIFY_H
#define	_SYS_SCSI_RESET_NOTIFY_H

#include <sys/note.h>
#include <sys/scsi/scsi_types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI Control Information for Reset Notification.
 */

/*
 * adapter drivers use the following structure to record the notification
 * requests from target drivers.
 */
struct scsi_reset_notify_entry {
	struct scsi_address		*ap;
	void				(*callback)(caddr_t);
	caddr_t				arg;
	struct scsi_reset_notify_entry	*next;
};

#ifdef __lock_lint
_NOTE(SCHEME_PROTECTS_DATA("protected by lock passed as arg",
	scsi_reset_notify_entry::ap
	scsi_reset_notify_entry::callback
	scsi_reset_notify_entry::arg
	scsi_reset_notify_entry::next))
#endif

#ifdef	_KERNEL
extern int scsi_hba_reset_notify_setup(struct scsi_address *, int,
	void (*)(caddr_t), caddr_t, kmutex_t *,
	struct scsi_reset_notify_entry **);
extern void scsi_hba_reset_notify_tear_down(
	struct scsi_reset_notify_entry *listp);
extern void scsi_hba_reset_notify_callback(kmutex_t *mutex,
	struct scsi_reset_notify_entry **listp);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_RESET_NOTIFY_H */
