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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dat_init.h
 *
 * PURPOSE: DAT registry global data
 *
 * $Id: dat_init.h,v 1.8 2003/06/16 17:53:35 sjs2 Exp $
 */

#ifndef _DAT_INIT_H_
#define	_DAT_INIT_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *
 * Enumerations
 *
 */

typedef enum
{
    DAT_MODULE_STATE_UNINITIALIZED,
    DAT_MODULE_STATE_INITIALIZING,
    DAT_MODULE_STATE_INITIALIZED,
    DAT_MODULE_STATE_DEINITIALIZING,
    DAT_MODULE_STATE_DEINITIALIZED
} DAT_MODULE_STATE;

/*
 *
 * Function Prototypes
 *
 */

DAT_MODULE_STATE
dat_module_get_state(void);

void
dat_init(void);

void
dat_fini(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _DAT_INIT_H_ */
