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

#ifndef _PCI_STRINGS_H
#define	_PCI_STRINGS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>

typedef struct pci_class_strings_s {
	uint8_t	base_class;	/* Base class of the PCI/PCI-X/PCIe function */
	uint8_t sub_class;	/* Sub-class of the PCI/PCI-X/PCIe function */
	uint8_t prog_class;	/* Programming class of PCI/X, PCIe function */
	char	*actual_desc;	/* PCI/PCI-X/PCIe function's description */
	char	*short_desc;	/* Cfgadm based original short description */
} pci_class_strings_t;

#ifdef __cplusplus
}
#endif

#endif /* _PCI_STRINGS_H */
