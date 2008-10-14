
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * Description
 *  mpapi-sun.h - general header file for Sun extension to the Multipath
 *  Management API Version 1.0 client
 *
 */

#ifndef _MPAPI_SUN_H
#define _MPAPI_SUN_H

#include <sys/scsi/impl/uscsi.h>

#ifdef __cplusplus
extern "C" {
#endif


#ifndef MPAPI_SUN_H
#define MPAPI_SUN_H

/**
 ******************************************************************************
 *
 * The APIs for path management.
 *
 * - Sun_MP_SendScsiCmd
 *
 ******************************************************************************
 */


MP_STATUS Sun_MP_SendScsiCmd(
   MP_OID		pathOid,
   struct uscsi_cmd	*cmd
);


#endif

#ifdef __cplusplus
};
#endif

#endif /* _MPAPI_SUN_H */
