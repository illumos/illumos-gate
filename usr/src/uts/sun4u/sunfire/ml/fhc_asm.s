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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/asi.h>
#include <sys/privregs.h>
#include <sys/spitregs.h>

#include "assym.h"

/*
 * fhc_shutdown_asm(u_longlong_t base, int size)
 *
 * Flush cpu E$ then shutdown.
 * This function is special in that it really sets the D-tags to
 * a known state.  And this is the behavior we're looking for.
 *
 * The flush address is known to be a cpu-unique non-existent
 * cacheable address.  We write to non-existent memory, using
 * the side effect of d-tag invalidation.
 *
 * Also, note that this function is never run from main memory.
 * Rather it is copied to non-cacheable SRAM (hence the ..._end
 * label at the bottom of the function).  This implies that the
 * function must be position independent code that doesn't reference 
 * cacheable real memory.
 */

	ENTRY(fhc_shutdown_asm)
	! turn off errors (we'll be writing to non-existent memory)
	stxa	%g0, [%g0]ASI_ESTATE_ERR
	membar	#Sync			! SYNC

	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o3
	wrpr	%o3, %g0, %pstate
1:
	brlez,pn %o1, 2f		! if (len <= 0) exit loop
	  dec	64, %o1			! size -= 64
        sta     %g0, [%o0]ASI_MEM	! store (unpopulated) word
	ba	1b
	  inc	64, %o0			! addr += 64
2:
	membar  #Sync			! SYNC
	shutdown			! SHUTDOWN
	/*NOTREACHED*/

	! if, for some reason, this cpu doesn't shutdown, just sit here
3:
	ba	3b
	  nop				! eventually the master will notice
	SET_SIZE(fhc_shutdown_asm)

	.global	fhc_shutdown_asm_end
fhc_shutdown_asm_end:

