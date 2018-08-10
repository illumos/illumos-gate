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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Support routines for the unix kmdb module
 */

#if defined(__lint)

#include <sys/types.h>

#else

#include <sys/asm_linkage.h>

	.file	"unix_sup.s"

	ENTRY(kmdb_unix_getcr0)
	movq %cr0, %rax
	ret
	SET_SIZE(kmdb_unix_getcr0)

	ENTRY(kmdb_unix_getcr2)
	movq %cr2, %rax
	ret
	SET_SIZE(kmdb_unix_getcr2)

	ENTRY(kmdb_unix_getcr3)
	movq %cr3, %rax
	ret
	SET_SIZE(kmdb_unix_getcr3)

	ENTRY(kmdb_unix_getcr4)
	movq %cr4, %rax
	ret
	SET_SIZE(kmdb_unix_getcr4)

	ENTRY(kmdb_unix_getgdtr)
	sgdt (%rdi)
	ret
	SET_SIZE(kmdb_unix_getgdtr)

#endif /* !__lint */
