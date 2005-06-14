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

#ifndef	_TOPO_PCI_H
#define	_TOPO_PCI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/libtopo_enum.h>
#include <libdevinfo.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCI_BUS		"pcibus"
#define	PCI_DEVICE	"pcidev"
#define	PCI_FUNCTION	"pcifn"

extern struct tenumr *Pci_enumr;

#define	PLAINPCI "pci"
#define	SCHIZO "pcisch"
#define	PSYCHO "pcipsy"

#define	REGPROP "reg"
#define	SLOTPROP "slot-names"
#define	CLASSPROP "class-code"
#define	VENDIDPROP	"vendor-id"
#define	DEVIDPROP	"device-id"

#define	VENDIDTPROP	"VENDOR-ID"
#define	DEVIDTPROP	"DEVICE-ID"

#define	GETCLASS(x) (((x) & 0xff0000) >> 16)
#define	GETSUBCLASS(x) (((x) & 0xff00) >> 8)
#define	GETPROGIF(x) ((x) & 0xff)

void examine_children(di_node_t n, di_prom_handle_t ph);

int topo_pci_init(void);
void topo_pci_fini(void);
void topo_pci_enum(tnode_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_PCI_H */
