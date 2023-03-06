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
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 */

	.file	"unwind_wrap.s"
	.global	__Unwind_RaiseException_Backend

#include "SYS.h"

	ANSI_PRAGMA_WEAK2(_SUNW_Unwind_RaiseException,_Unwind_RaiseException,
	    function)

	ENTRY(_Unwind_RaiseException)
	pushq	%rbp
	movq	%rsp,%rbp
	andq	$-STACK_ALIGN, %rsp	/* adjust stack alignment */
	call	__Unwind_RaiseException_Backend
	leave
	ret
	SET_SIZE(_Unwind_RaiseException)
