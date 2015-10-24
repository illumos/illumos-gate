/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Toomas Soome <tsoome@me.com>
 */

	.file	"multiboot.s"

/*
 * Provide fake multiboot header to support versioning and partition
 * start.
 */

#define	ASM_FILE
#include <multiboot.h>

		.globl mb_header, start_sector
		.text

		.align 4
mb_header:
		.long	MULTIBOOT_HEADER_MAGIC
		.long	MULTIBOOT_AOUT_KLUDGE
		.long	-(MULTIBOOT_HEADER_MAGIC + MULTIBOOT_AOUT_KLUDGE)
		.long	0                       /* header_addr */
		.long	0                       /* load_addr */
		.long	0                       /* load_end_addr */
start_sector:	.long	0			/* partition LBA */
		.long	0

