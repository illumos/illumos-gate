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

#ifndef	_SV_EFI_H
#define	_SV_EFI_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This header hides the differences between the header files and
 * macros needed for EFI vtocs in the various Solaris releases.
 *
 * <sys/dkio.h> and <sys/vtoc.h> must have already been included.
 */

#if !defined(_SYS_DKIO_H) || !defined(_SYS_VTOC_H)
#error	sys/dkio.h or sys/vtoc.h has not been included
#endif

#ifdef DS_DDICT
#undef	DKIOCPARTITION
#endif

#ifdef DKIOCPARTITION

#include <sys/efi_partition.h>
#include <sys/byteorder.h>

/*
 * Solaris 10 has all the support we need in the header files,
 * just include <sys/crc32.h>.
 */
#include <sys/crc32.h>

#endif  /* DKIOCPARTITION */

#ifdef	__cplusplus
}
#endif

#endif	/* _SV_EFI_H */
