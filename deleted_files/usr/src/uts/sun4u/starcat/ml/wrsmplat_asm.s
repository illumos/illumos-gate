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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"


#if defined(lint)
#include <sys/types.h>
#else
#include "assym.h"
#endif /* lint */

#include <sys/asm_linkage.h>
#include <sys/asi.h>
#include <sys/cmpregs.h>
#include <sys/cheetahregs.h>
#include <sys/wrsmplat.h>

#if defined(lint)

/* ARGSUSED */
	
/*
 * This function sets the ASI_CESR_ID per core register and
 * is only used by wrsmplat on StarCat
 */
void
asi_cesr_id_wr(uint64_t cesr_id)
{}

#else	/* lint */
	!jaguar: write cesr id
	ENTRY(asi_cesr_id_wr) 
        set	ASI_CESR_ID_VA, %o1
        stxa    %o0, [%o1]ASI_CMP_PER_CORE
	membar #Sync
	retl
	nop
	SET_SIZE(asi_cesr_id_wr)
#endif	/* lint */
