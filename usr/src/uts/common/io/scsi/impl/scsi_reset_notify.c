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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * support functions for hba drivers to handle scsi reset notifications.
 */

#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>

/*
 * routine for reset notification setup.
 * The function is entered without adapter driver mutex being held.
 */

int
scsi_hba_reset_notify_setup(struct scsi_address *ap, int flag,
	void (*callback)(caddr_t), caddr_t arg, kmutex_t *mutex,
	struct scsi_reset_notify_entry **listp)
{
	struct scsi_reset_notify_entry	*p, *beforep;
	int				rval = DDI_FAILURE;

	mutex_enter(mutex);
	p = *listp;
	beforep = NULL;
	while (p) {
		if (p->ap == ap)
			break;		/* An entry exist for this target */
		beforep = p;
		p = p->next;
	}

	if ((flag & SCSI_RESET_CANCEL) && (p != NULL)) {
		if (beforep == NULL) {
			*listp = p->next;
		} else {
			beforep->next = p->next;
		}
		kmem_free(p, sizeof (struct scsi_reset_notify_entry));
		rval = DDI_SUCCESS;

	} else if ((flag & SCSI_RESET_NOTIFY) && (p == NULL)) {
		p = kmem_zalloc(sizeof (struct scsi_reset_notify_entry),
		    KM_SLEEP);
		p->ap = ap;
		p->callback = callback;
		p->arg = arg;
		p->next = *listp;
		*listp = p;
		rval = DDI_SUCCESS;
	}
	mutex_exit(mutex);
	return (rval);
}

/*
 * routine to deallocate the callback list
 */
void
scsi_hba_reset_notify_tear_down(struct scsi_reset_notify_entry *listp)
{
	struct scsi_reset_notify_entry	*p, *next;

	p = listp;
	while (p) {
		next = p->next;
		kmem_free(p, sizeof (struct scsi_reset_notify_entry));
		p = next;
	}
}


/*
 * routine to perform the notification callbacks after a reset.
 * The function is entered with adapter driver mutex being held.
 */
void
scsi_hba_reset_notify_callback(kmutex_t *mutex,
	struct scsi_reset_notify_entry **listp)
{
	int	i, count;
	struct	scsi_reset_notify_entry	*p;
	struct	notify_entry {
		void	(*callback)(caddr_t);
		caddr_t	arg;
	} *list;

	if ((p = *listp) == NULL)
		return;

	count = 0;
	while (p != NULL) {
		count++;
		p = p->next;
	}

	list = kmem_alloc(count * sizeof (struct notify_entry), KM_NOSLEEP);
	if (list == NULL) {
		cmn_err(CE_WARN, "scsi_reset_notify: kmem_alloc failed");
		return;
	}

	for (i = 0, p = *listp; i < count; i++, p = p->next) {
		list[i].callback = p->callback;
		list[i].arg = p->arg;
	}

	mutex_exit(mutex);
	for (i = 0; i < count; i++) {
		if (list[i].callback != NULL)
			(void) (*list[i].callback)(list[i].arg);
	}
	kmem_free(list, count * sizeof (struct notify_entry));
	mutex_enter(mutex);
}
