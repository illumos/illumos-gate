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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_1394_ADAPTERS_HCI1394_TNF_H
#define	_SYS_1394_ADAPTERS_HCI1394_TNF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * hci1394_tnf.h
 *    Keys used for TNF_PROBE_* routines
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/tnf_probe.h>


#define	HCI1394_TNF_HAL			" 1394 hci1394 "
#define	HCI1394_TNF_HAL_STACK		" 1394 hci1394 stacktrace "
#define	HCI1394_TNF_HAL_STACK_ISOCH	" 1394 hci1394 stacktrace isoch"
#define	HCI1394_TNF_HAL_ERROR		" 1394 hci1394 error "
#define	HCI1394_TNF_HAL_ERROR_ISOCH	" 1394 hci1394 error isoch"
#define	HCI1394_TNF_HAL_INFO		" 1394 hci1394 info "
#define	HCI1394_TNF_HAL_INFO_ISOCH	" 1394 hci1394 info isoch"
#define	HCI1394_TNF_HAL_TLABEL		" 1394 hci1394 tlabel "

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_1394_ADAPTERS_HCI1394_TNF_H */
