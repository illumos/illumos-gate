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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SGSRTCID_H
#define	_SGSRTCID_H

#include <sys/debug.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * This file defines the Rtc_id structure that is found at the beginning
 * of linker configuration files. It resides at this level so that
 * it can be accessed by file(1) as well as by crle(1) and the
 * runtime linker (ld.so.1). The rest of the data structures for
 * config files are found in usr/src/cmd/sgs/include/rtc.h
 *
 * The use of sizeof(char) data (no byte order issue) and explicit
 * padding in the definition of Rtc_id ensures that it will have
 * exactly the same layout on all systems, and will have a
 * size of 16 bytes. The same layout means all systems can read it.
 * the same size means that any data can be safely placed immediately
 * following it, without the need for alignment.
 */

/*
 * Identification header.
 */
typedef struct {
	uchar_t	id_magic0;	/* RTC_ID_MAG0 */
	uchar_t	id_magic1;	/* RTC_ID_MAG1 */
	uchar_t	id_magic2;	/* RTC_ID_MAG2 */
	uchar_t	id_magic3;	/* RTC_ID_MAG3 */
	uchar_t	id_class;	/* File class/capacity (ELFCLASS constant) */
	uchar_t	id_data;	/* Data encoding (ELFDATA constant) */
	uchar_t	id_machine;	/* Architecture (ELF EM_ constant) */
	uchar_t	id_pad[9];	/* Ensure size is 16 bytes */
} Rtc_id;

/*
 * This structure is a raw file header structured to be platform agnostic, it
 * must always be precisely 16 bytes
 */
CTASSERT(sizeof (Rtc_id) == 16);

#define	RTC_ID_MAG0 '\077'	/* ? */
#define	RTC_ID_MAG1 'R'		/* Runtime */
#define	RTC_ID_MAG2 'L'		/* Linker */
#define	RTC_ID_MAG3 'C'		/* Configuration */

/*
 * Ensure that the largest relevant machine constant will not grow beyond
 * maximum value representable by an unsigned byte without our
 * being alerted to it.
 *
 * This is a cop out because while e_machine has grown beyond this limit, the
 * machines illumos needs to describe have not and are unlikely to.
 *
 * A more complete implementation would introduce an id_machinehi into the
 * padding, to hold the high byte.
 */
#if !defined(__x86) && !defined(__sparc__)
#error "Ensure machine constant fits in a byte. Format may require revision."
#endif

/*
 * Check the 4 bytes starting at the given address to see if
 * they contain the Rtc_id magic number. The type of the address
 * is unimportant as long as it is valid, because RTC_ID_TEST()
 * will cast it to (uchar_t *).
 */
#define	RTC_ID_TEST(addr) \
	((RTC_ID_MAG0 == *((uchar_t *)addr)) && \
	(RTC_ID_MAG1 == *(((uchar_t *)addr) + 1)) && \
	(RTC_ID_MAG2 == *(((uchar_t *)addr) + 2)) && \
	(RTC_ID_MAG3 == *(((uchar_t *)addr) + 3)))

#ifdef	__cplusplus
}
#endif

#endif	/* _SGSRTCID_H */
