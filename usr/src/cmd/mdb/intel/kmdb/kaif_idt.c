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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * kmdb's IDT
 */

#include <sys/types.h>
#include <sys/segments.h>
#include <sys/trap.h>
#include <strings.h>

#include <kmdb/kaif.h>
#include <mdb/mdb_debug.h>
#include <kmdb/kaif_asmutil.h>

#if defined(__amd64)
#define	KMDBCODE_SEL	B64CODE_SEL
#else
#define	KMDBCODE_SEL	BOOTCODE_SEL
#endif

typedef void idt_hdlr_f(void);

extern idt_hdlr_f kaif_trap0, kaif_trap1, kaif_int2, kaif_trap3, kaif_trap4;
extern idt_hdlr_f kaif_trap5, kaif_trap6, kaif_trap7, kaif_traperr8, kaif_trap9;
extern idt_hdlr_f kaif_traperr10, kaif_traperr11, kaif_traperr12;
extern idt_hdlr_f kaif_traperr13, kaif_traperr14, kaif_trap16, kaif_trap17;
extern idt_hdlr_f kaif_trap18, kaif_trap19, kaif_trap20, kaif_ivct32;
extern idt_hdlr_f kaif_invaltrap;

gate_desc_t kaif_idt[NIDT];
desctbr_t kaif_idtr;

struct idt_description {
	uint_t id_low;
	uint_t id_high;
	idt_hdlr_f *id_basehdlr;
	size_t *id_incrp;
	uint_t id_type;
} idt_description[] = {
	{ T_ZERODIV, 0,		kaif_trap0, NULL,		SDT_SYSIGT },
	{ T_SGLSTP, 0,		kaif_trap1, NULL,		SDT_SYSIGT },
	{ T_NMIFLT, 0,		kaif_int2, NULL,		SDT_SYSIGT },
	{ T_BPTFLT, 0,		kaif_trap3, NULL,		SDT_SYSIGT },
	{ T_OVFLW, 0,		kaif_trap4, NULL,		SDT_SYSIGT },
	{ T_BOUNDFLT, 0,	kaif_trap5, NULL,		SDT_SYSIGT },
	{ T_ILLINST, 0,		kaif_trap6, NULL,		SDT_SYSIGT },
	{ T_NOEXTFLT, 0,	kaif_trap7, NULL,		SDT_SYSIGT },
	{ T_DBLFLT, 0,		kaif_traperr8, NULL,		SDT_SYSIGT },
	{ T_EXTOVRFLT, 0,	kaif_trap9, NULL,		SDT_SYSIGT },
	{ T_TSSFLT, 0,		kaif_traperr10, NULL,		SDT_SYSIGT },
	{ T_SEGFLT, 0,		kaif_traperr11, NULL,		SDT_SYSIGT },
	{ T_STKFLT, 0,		kaif_traperr12, NULL,		SDT_SYSIGT },
	{ T_GPFLT, 0,		kaif_traperr13, NULL,		SDT_SYSIGT },
	{ T_PGFLT, 0,		kaif_traperr14, NULL,		SDT_SYSIGT },
	{ 15, 0,		kaif_invaltrap, NULL,		SDT_SYSIGT },
	{ T_EXTERRFLT, 0, 	kaif_trap16, NULL,		SDT_SYSIGT },
	{ T_ALIGNMENT, 0, 	kaif_trap17, NULL,		SDT_SYSIGT },
	{ T_MCE, 0,		kaif_trap18, NULL,		SDT_SYSIGT },
	{ T_SIMDFPE, 0,		kaif_trap19, NULL,		SDT_SYSIGT },
	{ T_DBGENTR, 0,		kaif_trap20, NULL,		SDT_SYSIGT },
	{ 21, 31,		kaif_invaltrap, NULL,		SDT_SYSIGT },
	{ 32, 255,		kaif_ivct32, &kaif_ivct_size,	SDT_SYSIGT },
	{ 0, 0, NULL },
};

static void
kaif_set_gatesegd(gate_desc_t *dp, void (*func)(void), selector_t sel,
    uint_t type)
{
	bzero(dp, sizeof (gate_desc_t));

	dp->sgd_looffset = ((uintptr_t)func) & 0xffff;
	dp->sgd_hioffset = ((uintptr_t)func >> 16) & 0xffff;
#ifdef __amd64
	dp->sgd_hi64offset = (uintptr_t)func >> 32;
#endif

	dp->sgd_selector =  (uint16_t)sel;
	dp->sgd_type = type;
	dp->sgd_dpl = SEL_KPL;
	dp->sgd_p = 1;

#ifdef __amd64
	dp->sgd_ist = 0;
#else
	dp->sgd_stkcpy = 0;
#endif
}

void
kaif_idt_init(void)
{
	struct idt_description *id;
	int i;

	for (id = idt_description; id->id_basehdlr != NULL; id++) {
		uint_t high = id->id_high != 0 ? id->id_high : id->id_low;
		size_t incr = id->id_incrp != NULL ? *id->id_incrp : 0;

		for (i = id->id_low; i <= high; i++) {
			caddr_t hdlr = (caddr_t)id->id_basehdlr +
			    incr * (i - id->id_low);
			kaif_set_gatesegd(&kaif_idt[i], (void (*)(void))hdlr,
			    KMDBCODE_SEL, id->id_type);
		}
	}

	kaif_idtr.dtr_limit = sizeof (kaif_idt) - 1;
	kaif_idtr.dtr_base = (uint64_t)kaif_idt;
}

/*
 * Patch caller-provided code into the debugger's IDT handlers.  This code is
 * used to save MSRs that must be saved before the first branch.  All handlers
 * are essentially the same, and end with a branch to kaif_cmnint.  To save the
 * MSR, we need to patch in before the branch.  The handlers have the following
 * structure: KAIF_MSR_PATCHOFF bytes of code, KAIF_MSR_PATCHSZ bytes of
 * patchable space, followed by more code.
 */
void
kaif_idt_patch(caddr_t code, size_t sz)
{
	int i;

	ASSERT(sz <= KAIF_MSR_PATCHSZ);

	for (i = 0; i < sizeof (kaif_idt) / sizeof (struct gate_desc); i++) {
		gate_desc_t *gd;
		uchar_t *patch;

		if (i == T_DBLFLT)
			continue;	/* uses kernel's handler */

		gd = &kaif_idt[i];
		patch = (uchar_t *)GATESEG_GETOFFSET(gd) + KAIF_MSR_PATCHOFF;

		/*
		 * We can't ASSERT that there's a nop here, because this may be
		 * a debugger restart.  In that case, we're copying the new
		 * patch point over the old one.
		 */
		bcopy(code, patch, sz);

		/* Fill the rest with nops to be sure */
		while (sz < KAIF_MSR_PATCHSZ)
			patch[sz++] = 0x90; /* nop */
	}
}

void
kaif_idt_write(gate_desc_t *gate, uint_t vec)
{
	kaif_idt[vec] = *gate;
}
