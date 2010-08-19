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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _PANIC_H
#define	_PANIC_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	SW_SUNOS_PANIC_DETECTED	"ireport.os.sunos.panic.dump_pending_on_device"
#define	SW_SUNOS_PANIC_FAILURE	"ireport.os.sunos.panic.savecore_failure"
#define	SW_SUNOS_PANIC_AVAIL	"ireport.os.sunos.panic.dump_available"

#define	SW_SUNOS_PANIC_DEFECT	"defect.sunos.kernel.panic"

extern char *sw_panic_fmri2str(fmd_hdl_t *, nvlist_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PANIC_H */
