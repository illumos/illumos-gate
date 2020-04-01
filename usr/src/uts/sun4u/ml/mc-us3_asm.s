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
 * Copyright 2000,2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Assembly code support for Memory Control driver
 */

#include "assym.h"
#include <sys/mc-us3.h>

#include <sys/asm_linkage.h>

 	! This routine is to get content of Memory Control Registers
 	ENTRY(get_mcr)
 	! input
 	! %i0 is the VA for Memory Control Registers
 	!
 	ldxa	[%o0]ASI_MCU_CTRL,	%o0
 	retl
 	  nop
 	SET_SIZE(get_mcr)
 
