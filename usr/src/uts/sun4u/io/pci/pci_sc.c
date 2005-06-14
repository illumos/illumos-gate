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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PCI Streaming Cache operations: initialization and configuration
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <vm/seg_kmem.h>
#include <sys/async.h>
#include <sys/spl.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci/pci_obj.h>
#include <sys/x_call.h>		/* XCALL_PIL */

/*LINTLIBRARY*/

void
sc_create(pci_t *pci_p)
{
	dev_info_t *dip = pci_p->pci_dip;
	sc_t *sc_p;
	uint64_t paddr;

#ifdef lint
	dip = dip;
#endif

	if (!pci_stream_buf_exists)
		return;

	/*
	 * Allocate streaming cache state structure and link it to
	 * the pci state structure.
	 */
	sc_p = (sc_t *)kmem_zalloc(sizeof (sc_t), KM_SLEEP);
	pci_p->pci_sc_p = sc_p;
	sc_p->sc_pci_p = pci_p;

	pci_sc_setup(sc_p);
	sc_p->sc_sync_reg_pa = va_to_pa((char *)sc_p->sc_sync_reg);

	DEBUG3(DBG_ATTACH, dip, "sc_create: ctrl=%x, invl=%x, sync=%x\n",
		sc_p->sc_ctrl_reg, sc_p->sc_invl_reg,
		sc_p->sc_sync_reg);
	DEBUG2(DBG_ATTACH, dip, "sc_create: ctx_invl=%x ctx_match=%x\n",
		sc_p->sc_ctx_invl_reg, sc_p->sc_ctx_match_reg);
	DEBUG3(DBG_ATTACH, dip,
		"sc_create: data_diag=%x, tag_diag=%x, ltag_diag=%x\n",
		sc_p->sc_data_diag_acc, sc_p->sc_tag_diag_acc,
		sc_p->sc_ltag_diag_acc);

	/*
	 * Allocate the flush/sync buffer.  Make sure it's properly
	 * aligned.
	 */
	sc_p->sc_sync_flag_base =
	    vmem_xalloc(static_alloc_arena, PCI_SYNC_FLAG_SIZE,
		PCI_SYNC_FLAG_SIZE, 0, 0, NULL, NULL, VM_SLEEP);
	sc_p->sc_sync_flag_vaddr = (uint64_t *)sc_p->sc_sync_flag_base;
	paddr = (uint64_t)hat_getpfnum(kas.a_hat,
	    (caddr_t)sc_p->sc_sync_flag_vaddr);
	paddr <<= MMU_PAGESHIFT;
	paddr += (uint64_t)
	    ((uintptr_t)sc_p->sc_sync_flag_vaddr & ~MMU_PAGEMASK);
	sc_p->sc_sync_flag_pa = paddr;
	DEBUG2(DBG_ATTACH, dip, "sc_create: sync buffer - vaddr=%x paddr=%x\n",
	    sc_p->sc_sync_flag_vaddr, sc_p->sc_sync_flag_pa);

	/*
	 * Create a mutex to go along with it.  While the mutex is held,
	 * all interrupts should be blocked.  This will prevent driver
	 * interrupt routines from attempting to acquire the mutex while
	 * held by a lower priority interrupt routine.  Note also that
	 * we now block cross calls as well, to prevent issues with
	 * relocation.
	 */
	mutex_init(&sc_p->sc_sync_mutex, NULL, MUTEX_DRIVER,
	    (void *)ipltospl(XCALL_PIL));

	sc_configure(sc_p);
}

void
sc_destroy(pci_t *pci_p)
{
	sc_t *sc_p;

	if (!pci_stream_buf_exists)
		return;

	sc_p = pci_p->pci_sc_p;

	DEBUG0(DBG_DETACH, pci_p->pci_dip, "sc_destroy:\n");

	vmem_xfree(static_alloc_arena, sc_p->sc_sync_flag_base,
	    PCI_SYNC_FLAG_SIZE);

	/*
	 * Free the streaming cache state structure.
	 */
	kmem_free(sc_p, sizeof (sc_t));
	pci_p->pci_sc_p = NULL;
}

void
sc_configure(sc_t *sc_p)
{
	int i, instance;
	uint64_t l;
	dev_info_t *dip;

	if (!sc_p)
		return;

	dip = sc_p->sc_pci_p->pci_dip;

	/*
	 * Invalidate all streaming cache entries via the diagnostic
	 * access registers.
	 */
	DEBUG0(DBG_ATTACH, dip, "sc_configure:\n");
	*sc_p->sc_ctrl_reg |= COMMON_SC_CTRL_DIAG_ENABLE;
	for (i = 0; i < PCI_SBUF_ENTRIES; i++) {
		sc_p->sc_tag_diag_acc[i] = 0x0ull;
		sc_p->sc_ltag_diag_acc[i] = 0x0ull;
	}

	/*
	 * Configure the streaming cache:
	 */
	l = 0;
	instance = ddi_get_instance(dip);
	if (pci_stream_buf_enable & (1 << instance))
		l |= COMMON_SC_CTRL_ENABLE;
	if (pci_rerun_disable & (1 << instance))
		l |= COMMON_SC_CTRL_RR__DISABLE;
	if (pci_lock_sbuf & (1 << instance))
		l |= COMMON_SC_CTRL_LRU_LE;

	/*
	 * Get any SC configuration changes specific to the chip.
	 */
	l |= pci_sc_configure(sc_p->sc_pci_p);

	DEBUG1(DBG_ATTACH, dip,
	    "sc_configure: writing %x to sc csr\n", l);
	*sc_p->sc_ctrl_reg = l;
}
