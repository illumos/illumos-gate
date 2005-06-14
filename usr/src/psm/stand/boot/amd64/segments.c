/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1992 Terrence R. Lambert.
 * Copyright (c) 1982, 1987, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)machdep.c	7.4 (Berkeley) 6/3/91
 */

#include <sys/types.h>

#include <amd64/boothooks.h>
#include <amd64/types.h>
#include <amd64/debug.h>
#include <amd64/tss.h>
#include <amd64/segments.h>

/*
 * Routines for loading segment descriptors in a format the hardware
 * understands.
 */

/*
 * Install user segment descriptor for code and data.
 */
void
set_usegd(user_desc_t *dp, void *base, size_t size, uint_t type,
    uint_t dpl, uint_t gran, uint_t defopsz)
{
	bzero(dp, sizeof (*dp));

	dp->usd_lolimit = size;
	dp->usd_hilimit = (uintptr_t)size >> 16;

	dp->usd_lobase = (uintptr_t)base;
	dp->usd_midbase = (uintptr_t)base >> 16;
	dp->usd_hibase = (uintptr_t)base >> (16 + 8);

	dp->usd_type = type;
	dp->usd_dpl = dpl;
	dp->usd_p = 1;
	dp->usd_def32 = defopsz;	/* 0 = 16, 1 = 32 bit operands */
	dp->usd_gran = gran;		/* 0 = bytes, 1 = pages */
}

/*
 * In long mode we have the new L or long mode attribute bit
 * for code segments. Only the conforming bit in type is used along
 * with descriptor priority and present bits. Default operand size must
 * be zero when in long mode. In 32-bit compatibility mode all fields
 * are treated as in legacy mode. For data segments while in long mode
 * only the present bit is loaded.
 */
void
set_usegd64(user_desc64_t *dp, uint_t lmode, void *base, size_t size,
    uint_t type, uint_t dpl, uint_t gran, uint_t defopsz)
{
	bzero(dp, sizeof (*dp));

	ASSERT(lmode == 0 || lmode == 1);

	/*
	 * 64-bit long mode.
	 */
	if (lmode == LONG) {
		dp->usd_type = type;
		dp->usd_dpl = dpl;
		dp->usd_p = 1;
		dp->usd_long = 1;	/* 64-bit mode */
		dp->usd_def32 = 0;	/* must be zero for 32-bit operands */
		dp->usd_gran = gran;	/* 0 = bytes, 1 = pages */
	} else {

		/*
		 * 32-bit compatibility mode.
		 */
		dp->usd_lolimit = size;
		dp->usd_hilimit = (uintptr_t)size >> 16;

		dp->usd_lobase = (uintptr_t)base;
		dp->usd_midbase = (uintptr_t)base >> 16;
		dp->usd_hibase = (uintptr_t)base >> (16 + 8);

		dp->usd_type = type;
		dp->usd_dpl = dpl;
		dp->usd_p = 1;
		dp->usd_long = 0;		/* 32-bit mode */
		dp->usd_def32 = defopsz;	/* 0 = 16, 1 = 32-bit ops */
		dp->usd_gran = gran;		/* 0 = bytes, 1 = pages */
	}
}

/*
 * Install system segment descriptor for LDT and TSS segments.
 */
void
set_syssegd(system_desc_t *dp, void *base, size_t size, uint_t type,
    uint_t dpl)
{
	bzero(dp, sizeof (*dp));

	dp->ssd_lolimit = size;
	dp->ssd_hilimit = (uintptr_t)size >> 16;

	dp->ssd_lobase = (uintptr_t)base;
	dp->ssd_midbase = (uintptr_t)base >> 16;
	dp->ssd_hibase = (uintptr_t)base >> (16 + 8);

	dp->ssd_type = type;
	dp->ssd_zero = 0;	/* must be zero */
	dp->ssd_dpl = dpl;
	dp->ssd_p = 1;

	/*
	 * XXX why would anyone care to use page units for
	 * ldt or tss sizes? Force it to be bytes.
	 */
	dp->ssd_gran = 0;
}

void
set_syssegd64(system_desc64_t *dp, void *base, size_t size, uint_t type,
    uint_t dpl)
{
	bzero(dp, sizeof (*dp));

	dp->ssd_lolimit = size;
	dp->ssd_hilimit = (uintptr_t)size >> 16;

	dp->ssd_lobase = (uint32_t)base;
	dp->ssd_midbase = (uint64_t)(uint32_t)base >> 16;
	dp->ssd_hibase = (uint64_t)(uint32_t)base >> (16 + 8);
	dp->ssd_hi64base = (uint64_t)(uint32_t)base >> (16 + 8 + 8);

	dp->ssd_type = type;
	dp->ssd_zero1 = 0;	/* must be zero */
	dp->ssd_zero2 = 0;
	dp->ssd_dpl = dpl;
	dp->ssd_p = 1;
	dp->ssd_gran = 0;	/* force byte units */
}

/*
 * Install gate segment descriptor for interrupt, trap, call and task gates.
 */
void
set_gatesegd(gate_desc_t *dp, void (*func)(void), selector_t sel,
    uint_t wcount, uint_t type, uint_t dpl)
{
	bzero(dp, sizeof (*dp));

	dp->sgd_looffset = (uintptr_t)func;
	dp->sgd_hioffset = (uintptr_t)func >> 16;

	dp->sgd_selector =  (uint16_t)sel;
	dp->sgd_stkcpy = wcount;
	dp->sgd_type = type;
	dp->sgd_dpl = dpl;
	dp->sgd_p = 1;
}

/*
 * Note stkcpy is replaced with ist. Read the PRM for details on this.
 */
void
set_gatesegd64(gate_desc64_t *dp, void (*func)(void), selector_t sel,
    uint_t ist, uint_t type, uint_t dpl)
{
	bzero(dp, sizeof (*dp));

	dp->sgd_looffset = (uint64_t)(uint32_t)func;
	dp->sgd_hioffset = (uint64_t)(uint32_t)func >> 16;
	dp->sgd_hi64offset = (uint64_t)(uint32_t)func >> (16 + 16);

	dp->sgd_selector =  (uint16_t)sel;
	dp->sgd_ist = ist;
	dp->sgd_type = type;
	dp->sgd_dpl = dpl;
	dp->sgd_p = 1;
}
