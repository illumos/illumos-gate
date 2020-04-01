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

#include <xen/public/elfnote.h>

/*
 * A note is a name/value pair that belongs to some class.
 */
#define NOTE(class, id, type, value)	\
	.align	4;			\
	.4byte	2f - 1f;		\
	.4byte	4f - 3f;		\
	.4byte	id;			\
1: ;					\
	.string class;			\
2: ;					\
	.align	4;			\
3: ;					\
	type	value;			\
4: ;

	.section .note
	NOTE("Xen", XEN_ELFNOTE_LOADER, .string, "generic")
	NOTE("Xen", XEN_ELFNOTE_XEN_VERSION, .string, "xen-3.0")
	NOTE("Xen", XEN_ELFNOTE_GUEST_OS, .string, "Solaris")
	NOTE("Xen", XEN_ELFNOTE_VIRT_BASE, .4byte, 0x40000000)
	NOTE("Xen", XEN_ELFNOTE_PADDR_OFFSET, .4byte, 0x40000000)
#if defined(__i386)
	NOTE("Xen", XEN_ELFNOTE_PAE_MODE, .string, "yes,bimodal")
#endif

