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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_SCSI_IMPL_SENSE_H
#define	_SYS_SCSI_IMPL_SENSE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Implementation Variant defines
 * for SCSI Sense Information
 */

/*
 * These are 'pseudo' sense keys for common Sun implementation driver
 * detected errors. Note that they start out as being higher than the
 * legal key numbers for standard SCSI.
 */

#define	SUN_KEY_FATAL		0x10	/* driver, scsi handshake failure */
#define	SUN_KEY_TIMEOUT		0x11	/* driver, command timeout */
#define	SUN_KEY_EOF		0x12	/* driver, eof hit */
#define	SUN_KEY_EOT		0x13	/* driver, eot hit */
#define	SUN_KEY_LENGTH		0x14	/* driver, length error */
#define	SUN_KEY_BOT		0x15	/* driver, bot hit */
#define	SUN_KEY_WRONGMEDIA	0x16	/* driver, wrong tape media */

#define	NUM_IMPL_SENSE_KEYS	7	/* seven extra keys */

/*
 * Common sense length allocation sufficient for this implementation.
 */

#define	SENSE_LENGTH	\
	(roundup(sizeof (struct scsi_extended_sense), sizeof (int)))

/*
 * Minimum useful Sense Length value
 */

#define	SUN_MIN_SENSE_LENGTH	4

/*
 * Specific variants to the Extended Sense structure.
 *
 * Defines for:
 *	Emulex MD21 SCSI/ESDI Controller
 *	Emulex MT02 SCSI/QIC-36 Controller.
 *
 * 1) The Emulex controllers put error class and error code into the byte
 * right after the 'additional sense length' field in Extended Sense.
 *
 * 2) Except that some people state that this isn't so for the MD21- only
 * the MT02.
 */

#define	emulex_ercl_ercd	es_cmd_info[0]

/*
 * 2) These are valid on Extended Sense for the MD21, FORMAT command only:
 */

#define	emulex_cyl_msb		es_info_1
#define	emulex_cyl_lsb		es_info_2
#define	emulex_head_num		es_info_3
#define	emulex_sect_num		es_info_4

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_SENSE_H */
