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
 * Copyright (c) 1993 by Sun Microsystems, Inc.
 */

#ifndef _SYS_ELF_NOTES_H
#define	_SYS_ELF_NOTES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Sun defined names for elf note sections.
 */
#define	ELF_NOTE_SOLARIS		"SUNW Solaris"

/*
 * Describes the desired pagesize of elf PT_LOAD segments.
 * Descriptor is 1 word in length, and contains the desired pagesize.
 */
#define	ELF_NOTE_PAGESIZE_HINT		1

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ELF_NOTES_H */
