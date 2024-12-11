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

#ifndef	_SYS_PCI_SC_H
#define	_SYS_PCI_SC_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * streaming cache (sc) block soft state structure:
 *
 * Each pci node contains has its own private sc block structure.
 */
typedef struct sc sc_t;
struct sc {

	pci_t *sc_pci_p;	/* link back to pci soft state */

	/*
	 * control registers (psycho and schizo):
	 */
	volatile uint64_t *sc_ctrl_reg;
	volatile uint64_t *sc_invl_reg;
	volatile uint64_t *sc_sync_reg;
	uint64_t sc_sync_reg_pa;

	/*
	 * control registers (schizo only):
	 */
	volatile uint64_t *sc_ctx_invl_reg;
	volatile uint64_t *sc_ctx_match_reg;

	/*
	 * diagnostic access registers:
	 */
	volatile uint64_t *sc_data_diag_acc;
	volatile uint64_t *sc_tag_diag_acc;
	volatile uint64_t *sc_ltag_diag_acc;

	/*
	 * Sync flag and its associated buffer.
	 */
	caddr_t sc_sync_flag_base;
	volatile uint64_t *sc_sync_flag_vaddr;
	uint64_t sc_sync_flag_pa;

	kmutex_t sc_sync_mutex;		/* mutex for flush/sync register */
};

#define	PCI_SBUF_ENTRIES	16	/* number of i/o cache lines */
#define	PCI_SBUF_LINE_SIZE	64	/* size of i/o cache line */

#define	PCI_CACHE_LINE_SIZE	(PCI_SBUF_LINE_SIZE / 4)

extern void sc_create(pci_t *pci_p);
extern void sc_destroy(pci_t *pci_p);
extern void sc_configure(sc_t *sc_p);

/*
 * The most significant bit (63) of each context match register.
 */
#define	SC_CMR_DIRTY_BIT	1
#define	SC_ENTRIES		16
#define	SC_ENT_SHIFT		(64 - SC_ENTRIES)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCI_SC_H */
