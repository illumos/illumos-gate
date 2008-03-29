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

#ifndef	_FRAMEWORK_LIBSES_H
#define	_FRAMEWORK_LIBSES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These are properties attached to the root target node of the enclosure, and
 * represent the SCSI inquiry data.
 */
#define	SCSI_PROP_VENDOR		"scsi-inquiry-vendor"
#define	SCSI_PROP_PRODUCT		"scsi-inquiry-product"
#define	SCSI_PROP_REVISION		"scsi-inquiry-revision"

/*
 * This property provides a human-readable name for the element type.  This is
 * constant, and not derived from the enclosure data.
 */
#define	LIBSES_PROP_ELEMENT_TYPE_NAME	"libses-element-type-name"

/*
 * The following properties can be added to any node.  There is no provision in
 * the specification for these properties, but they can be derived from vendor
 * specific data for some enclosures.
 */
#define	LIBSES_PROP_PART		"libses-part-number"
#define	LIBSES_PROP_SERIAL		"libses-serial-number"

/*
 * The chassis serial number is a pseudo property that doesn't exist in SES
 * spec.  A single physical chassis may present several logically different SES
 * targets that are connected to the same or different elements.  These targets
 * can extract the chassis serial number in a vendor-specific way so that
 * consumers know these SES targets refer to the same device.  This defaults to
 * to the logical-id, and is always present.
 */
#define	LIBSES_EN_PROP_CSN		"libses-chassis-serial"

#ifdef	__cplusplus
}
#endif

#endif	/* _FRAMEWORK_LIBSES_H */
