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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SCSI_IMPL_INQUIRY_H
#define	_SYS_SCSI_IMPL_INQUIRY_H

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
 * SCSI inquiry properties.  The following properties figuratively
 * represent 'inquiry' data.  Some of the values may be more detailed
 * (longer in length) than the basic 'struct scsi_inquiry' fields. For
 * example the INQUIRY_REVISION_ID field in 'struct scsi_inquiry' is
 * four bytes long, but SATA's 'Identify Device Data' is eight bytes.
 * In situations like this an HBA driver's tran_tgt_init(9E)
 * implementation may establish different, more detailed, values than
 * those returned by 'struct scsi_inquiry'.  In addition some
 * properties like 'serial number' and 'capacity' are never derived
 * from 'struct scsi_inquiry'.  Instead, the information is obtained
 * from an INQUIRY command to another page (page 0x80 for serial
 * number), by some other SCSI commands (like READ_CAPACITY for
 * capacity), or by some HBA driver specific mechanism.
 */
#define	INQUIRY_DEVICE_TYPE	"inquiry-device-type"	/* int */
#define	INQUIRY_VENDOR_ID	"inquiry-vendor-id"	/* string */
#define	INQUIRY_PRODUCT_ID	"inquiry-product-id"	/* string */
#define	INQUIRY_REVISION_ID	"inquiry-revision-id"	/* string */
#define	INQUIRY_SERIAL_NO	"inquiry-serial-no"	/* string */

#ifdef	_KERNEL
int	scsi_ascii_inquiry_len(char *field, size_t length);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_INQUIRY_H */
