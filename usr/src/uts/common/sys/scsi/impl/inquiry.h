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
 * Copyright (c) 1996, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SCSI_IMPL_INQUIRY_H
#define	_SYS_SCSI_IMPL_INQUIRY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Implementation inquiry data that is not within
 * the scope of any released SCSI standard.
 */

/*
 * Minimum inquiry data length (includes up through RDF field)
 */

#define	SUN_MIN_INQLEN	4

/*
 * Inquiry data size definition
 */
#define	SUN_INQSIZE	(sizeof (struct scsi_inquiry))

/*
 * SCSI inquiry properties
 */
#define	INQUIRY_PRODUCT_ID	"inquiry-product-id"
#define	INQUIRY_VENDOR_ID	"inquiry-vendor-id"
#define	INQUIRY_REVISION_ID	"inquiry-revision-id"
#define	INQUIRY_DEVICE_TYPE	"inquiry-device-type"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_INQUIRY_H */
