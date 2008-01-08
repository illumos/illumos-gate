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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCIEX_PCIE_ERROR_H
#define	_PCIEX_PCIE_ERROR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 *	PCI Error related library header file
 */


/*
 * Error related library functions
 */

int		pcie_error_enable(dev_info_t *cdip, ddi_acc_handle_t cfg_hdl);
void		pcie_error_disable(dev_info_t *cdip, ddi_acc_handle_t cfg_hdl);


/*
 * PCIE bridge interfaces
 */

typedef struct {
	dev_info_t *dip;
	ddi_acc_handle_t cfghdl;
	void *datap;

	int pcie_loc;
	int aer_loc;
	int port_type;
	int inband_hpc;

	int iflags;
	int itype;
	int iwant;
	int igot;
	uint_t ipri;

	ddi_intr_handle_t *ihdl_tab;	/* length: iwant */

	/* isrc_tab[ <inum> ] = interrupt sources on <inum> */
	int *isrc_tab;			/* length: igot */

	kmutex_t ilock;
} pcie_bridge_intr_state_t;


/* bridge interrupt state flags (pcie_bridge_intr_state_t.iflags) */
#define	PCIE_BRIDGE_INTR_INIT_HTABLE	0x01	/* htable kmem_alloced */
#define	PCIE_BRIDGE_INTR_INIT_ALLOC	0x02	/* ddi_intr_alloc called */
#define	PCIE_BRIDGE_INTR_INIT_HANDLER	0x04	/* ddi_intr_add_handler done */
#define	PCIE_BRIDGE_INTR_INIT_ENABLE	0x08	/* ddi_intr_enable called */
#define	PCIE_BRIDGE_INTR_INIT_BLOCK	0x10	/* ddi_intr_block_enable done */
#define	PCIE_BRIDGE_INTR_INIT_MUTEX	0x20	/* mutex initialized */
#define	PCIE_BRIDGE_INTR_INIT_ISRCTAB	0x40	/* isrc table allocated */

/* default interrupt priority for all interrupts (hotplug or non-hotplug) */
#define	PCIE_BRIDGE_INTR_PRI	1

/* bit flags for identifying interrupt sources */
#define	PCIE_BRIDGE_INTR_SRC_UNKNOWN	0x0	/* must be 0 */
#define	PCIE_BRIDGE_INTR_SRC_HP		0x1
#define	PCIE_BRIDGE_INTR_SRC_PME	0x2
#define	PCIE_BRIDGE_INTR_SRC_AER	0x4


int pcie_bridge_intr_type(pcie_bridge_intr_state_t *, int *);
void pcie_bridge_pme_intr_disable(ddi_acc_handle_t, int);
void pcie_bridge_pme_intr_enable(ddi_acc_handle_t, int);
void pcie_bridge_pme_disable(pcie_bridge_intr_state_t *);
int pcie_bridge_intr_init(pcie_bridge_intr_state_t *, ddi_intr_handler_t);
int pcie_bridge_intr_reinit(pcie_bridge_intr_state_t *);
void pcie_bridge_intr_fini(pcie_bridge_intr_state_t *);
int pcie_bridge_is_link_disabled(dev_info_t *, ddi_acc_handle_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _PCIEX_PCIE_ERROR_H */
