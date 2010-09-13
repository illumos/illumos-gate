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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_init.h
 *
 * PURPOSE: Prototypes for library-interface init and fini functions
 *
 * $Id: dapl_init.h,v 1.4 2003/07/31 14:04:17 jlentini Exp $
 *
 */


#ifndef _DAPL_INIT_H_
#define	_DAPL_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

extern void
DAT_PROVIDER_INIT_FUNC_NAME(
	IN const DAT_PROVIDER_INFO *,
	IN const char *);		/* instance data */

extern void
DAT_PROVIDER_FINI_FUNC_NAME(
    IN const DAT_PROVIDER_INFO *);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_INIT_H_ */
