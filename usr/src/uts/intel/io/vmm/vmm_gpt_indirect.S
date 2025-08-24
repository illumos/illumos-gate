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
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/asm_linkage.h>

/*
 * Function stubs for GPT indirection.
 *
 * These default to calling a simple panic function prior to being hot-patched
 * with a jump to the proper implementation.
 */

ENTRY_NP(vmm_gpti_map_table)
	jmp	vmm_gpt_impl_panic
SET_SIZE(vmm_gpti_map_table)

ENTRY_NP(vmm_gpti_map_page)
	jmp	vmm_gpt_impl_panic
SET_SIZE(vmm_gpti_map_page)

ENTRY_NP(vmm_gpti_parse)
	jmp	vmm_gpt_impl_panic
SET_SIZE(vmm_gpti_parse)
