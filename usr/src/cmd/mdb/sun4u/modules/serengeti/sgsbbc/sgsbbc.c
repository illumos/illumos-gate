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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mutex.h>
#include <sys/mdb_modapi.h>
#include <sys/sgsbbc_priv.h>

/*
 * Given the address of a soft state pointer for the SGSBBC driver,
 * this function displays the values of selected fields.
 *
 * You have to specify the address of the soft state structure you
 * want to decode. This dcmd does not automatically work that out
 * for you. The contents of <sbbcp> points to the variable pointing
 * to the soft state pointers.
 *
 * (ie. typing "**sbbcp/10J" at the mdb prompt will list the addresses
 * of the first 10 soft state structures (if they exist).
 *
 * It can also be obtained using mdb's softstate dcmd.
 * "*sbbcp::softstate 0 | ::sgsbbc_softstate"
 */
/* ARGSUSED */
int
display_sbbc_softstate_t(uintptr_t addr, uint_t flags, int argc,
	const mdb_arg_t *argv)
{
	sbbc_softstate_t	softp;

	uint_t	offset = 0;	/* offset into soft state structure */
	int	rv;		/* return value from mdb function */

	/*
	 * You have to specify the address of the soft state structure you
	 * want to decode. This dcmd does not automatically work that out.
	 */
	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_ERR);

	rv = mdb_vread(&softp, sizeof (sbbc_softstate_t), addr);
	if (rv != sizeof (sbbc_softstate_t)) {
		mdb_warn("sgsbbc soft_state: Failed read on %ll#r", addr);
		return (DCMD_ERR);
	}

	mdb_printf("---------- sbbc_softstate_t @ %#lr ----------\n", addr);

	offset = (int)(uintptr_t)&softp.dip - (int)(uintptr_t)&softp;
	mdb_printf("%p: dip: %31ll#r\n", addr + offset, softp.dip);

	offset = (int)(uintptr_t)&softp.sram - (int)(uintptr_t)&softp;
	mdb_printf("%p: sram: %30ll#r\n", addr + offset, softp.sram);

	offset = (int)(uintptr_t)&softp.sbbc_regs - (int)(uintptr_t)&softp;
	mdb_printf("%p: sbbc_regs: %25ll#r\n", addr + offset,  softp.sbbc_regs);

	offset = (int)(uintptr_t)&softp.port_int_regs - (int)(uintptr_t)&softp;
	mdb_printf("%p: port_int_regs: %21ll#r\n", addr + offset,
		softp.port_int_regs);

	offset = (int)(uintptr_t)&softp.epld_regs - (int)(uintptr_t)&softp;
	mdb_printf("%p: epld_regs: %25p\n", addr + offset, softp.epld_regs);

	offset = (int)(uintptr_t)&softp.sram_toc - (int)(uintptr_t)&softp;
	mdb_printf("%p: sram_toc: %26d\n", addr + offset,  softp.sram_toc);

	offset = (int)(uintptr_t)&softp.sbbc_reg_handle1 -
		(int)(uintptr_t)&softp;
	mdb_printf("%p: sbbc_reg_handle1: %18ll#r\n", addr + offset,
		softp.sbbc_reg_handle1);

	offset = (int)(uintptr_t)&softp.sbbc_reg_handle2 -
		(int)(uintptr_t)&softp;
	mdb_printf("%p: sbbc_reg_handle2: %18ll#r\n", addr + offset,
		softp.sbbc_reg_handle2);

	offset = (int)(uintptr_t)&softp.inumber - (int)(uintptr_t)&softp;
	mdb_printf("%p: inumber: %27ll#r\n", addr + offset,  softp.inumber);

	offset = (int)(uintptr_t)&softp.intr_hdlrs - (int)(uintptr_t)&softp;
	mdb_printf("%p: intr_hdlrs: %24ll#r\n", addr + offset,
		softp.intr_hdlrs);

	offset = (int)(uintptr_t)&softp.suspended - (int)(uintptr_t)&softp;
	mdb_printf("%p: suspended: %25ll#r\n", addr + offset,  softp.suspended);

	offset = (int)(uintptr_t)&softp.chosen - (int)(uintptr_t)&softp;
	mdb_printf("%p: chosen: %28ll#r\n", addr + offset,  softp.chosen);

	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {{
		"sgsbbc_softstate",
		NULL,
		"print SGSBBC mailbox driver softstate fields",
		display_sbbc_softstate_t
	}, { NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, NULL
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
