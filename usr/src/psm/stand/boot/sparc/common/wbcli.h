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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* wanboot booter specific definitions */

#ifndef	_WBCLI_H
#define	_WBCLI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/wanboot_impl.h>
#include <dhcp_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	WB_MAX_CID_LEN	DHCP_MAX_CID_LEN

extern boolean_t wanboot_init_interface(char *);
extern boolean_t wanboot_verify_config(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _WBCLI_H */
