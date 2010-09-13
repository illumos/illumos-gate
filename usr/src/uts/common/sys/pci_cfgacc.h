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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCI_CFGACC_H
#define	_PCI_CFGACC_H

#include <sys/dditypes.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

#define	PCI_GETBDF(b, d, f)	\
	((d != 0) ?		\
	((((uint16_t)b & 0xff) << 8) + (((uint8_t)d & 0x1f) << 3) + \
	((uint8_t)f & 0x7)) :	\
	((((uint16_t)b & 0xff) << 8) + ((uint8_t)f & 0xff)))

typedef union pci_cfg_data {
	uint8_t b;
	uint16_t w;
	uint32_t dw;
	uint64_t qw;
} pci_cfg_data_t;

typedef enum pci_config_size {
	PCI_CFG_SIZE_BYTE = 1,
	PCI_CFG_SIZE_WORD = 2,
	PCI_CFG_SIZE_DWORD = 4,
	PCI_CFG_SIZE_QWORD = 8
} pci_config_size_t;

typedef struct pci_cfgacc_req {
	dev_info_t	*rcdip;
	uint16_t	bdf;
	uint16_t	offset;
	uint8_t		size;
	boolean_t	write;
	pci_cfg_data_t	value;
	boolean_t	ioacc;
} pci_cfgacc_req_t;
#define	VAL8(req)	((req)->value.b)
#define	VAL16(req)	((req)->value.w)
#define	VAL32(req)	((req)->value.dw)
#define	VAL64(req)	((req)->value.qw)

extern uint8_t	pci_cfgacc_get8(dev_info_t *, uint16_t, uint16_t);
extern uint16_t	pci_cfgacc_get16(dev_info_t *, uint16_t, uint16_t);
extern uint32_t	pci_cfgacc_get32(dev_info_t *, uint16_t, uint16_t);
extern uint64_t	pci_cfgacc_get64(dev_info_t *, uint16_t, uint16_t);
extern void	pci_cfgacc_put8(dev_info_t *, uint16_t, uint16_t, uint8_t);
extern void	pci_cfgacc_put16(dev_info_t *, uint16_t, uint16_t, uint16_t);
extern void	pci_cfgacc_put32(dev_info_t *, uint16_t, uint16_t, uint32_t);
extern void	pci_cfgacc_put64(dev_info_t *, uint16_t, uint16_t, uint64_t);
extern void	pci_cfgacc_acc(pci_cfgacc_req_t *);

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _PCI_CFGACC_H */
