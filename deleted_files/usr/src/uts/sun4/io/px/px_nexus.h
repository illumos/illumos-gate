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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PX_NEXUS_H
#define	_SYS_PX_NEXUS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

enum px_fault_ops { FAULT_LOG, FAULT_RESET, FAULT_POKEFLT, FAULT_POKEFINI };

struct px_fault_handle {
	dev_info_t *fh_dip;		/* device registered fault handler */
	int (*fh_f)();			/* fault handler function */
	void *fh_arg;			/* argument for fault handler */
	struct px_fault_handle *fh_next;
};

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_NEXUS_H */
