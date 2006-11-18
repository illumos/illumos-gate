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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * scsi.c - Warlock versions of DDI/DKI routines associated with scsi
 *
 * These renditions of the scsi-related DDI/DKI routines give warlock
 * info about control flow which warlock needs in order to do a good
 * job of analysis.
 */
#include <sys/note.h>
#include <sys/scsi/scsi.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/scsi/impl/transport.h>

void
scsi_init()
{
	struct scsi_hba_tran *p;

	p->tran_tgt_init(0, 0, 0, 0);
	p->tran_tgt_probe(0, 0);
	p->tran_tgt_free(0, 0, 0, 0);
	p->tran_add_eventcall(0, 0, 0, 0, 0, 0);
	p->tran_get_eventcookie(0, 0, 0, 0);
	p->tran_post_event(0, 0, 0, 0);
	p->tran_remove_eventcall(0, 0);
}
