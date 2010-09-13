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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MD_CRC_H
#define	_SYS_MD_CRC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* md_crc.c */
/*
 * Structure to hold fields to be skipped when calculating the checksum
 */
typedef struct crc_skip {
	struct crc_skip	*skip_next;
	int		skip_offset;
	int		skip_size;
} crc_skip_t;

extern uint_t			crcfunc(uint_t check,
				    uchar_t *record,
				    uint_t *result,
				    size_t size,
				    crc_skip_t *skip);
extern void			crcfreetab(void);

/*
 * The following crc defines allow for a number of areas to be skipped
 * (not be included in the data being crc'd) in the record
 * block (mddb_rb_32). These areas are the 12 byte area covering
 *	rb_checksum_fiddle, rb_private and rb_userdata
 *
 * In addition the skipped areas include the timestamps in the crc for
 * MN disksets.
 */
#ifndef DEBUG
#define	crcgen(record, result, size, skip) \
	(void) crcfunc(0, (uchar_t *)(record), (uint_t *)(result), \
	    (size_t)(size), (crc_skip_t *)(skip))

#else /* DEBUG */

#ifdef	_KERNEL
#define	crcgen(record, result, size, skip)		{\
	uint_t b = crcfunc(0, (uchar_t *)(record), (uint_t *)(result), \
	    (size_t)(size), (crc_skip_t *)(skip)); \
	(void) crcfunc(0, (uchar_t *)(record), (uint_t *)(result), \
	    (size_t)(size), (crc_skip_t *)(skip)); \
	ASSERT (*((uint_t *)(result)) == b); \
}
#else	/* !_KERNEL */
#define	crcgen(record, result, size, skip)		{\
	uint_t b = crcfunc(0, (uchar_t *)(record), (uint_t *)(result), \
	    (size_t)(size), (crc_skip_t *)(skip)); \
	(void) crcfunc(0, (uchar_t *)(record), (uint_t *)(result), \
	    (size_t)(size), (crc_skip_t *)(skip)); \
	assert (*((uint_t *)(result)) == b); \
}
#endif	/* _KERNEL */
#endif	/* DEBUG */

#define	crcchk(record, result, size, skip) crcfunc(1, (uchar_t *)(record), \
	(uint_t *)(result), (size_t)(size), (crc_skip_t *)(skip))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_CRC_H */
