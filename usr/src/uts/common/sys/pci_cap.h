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

#ifndef	_SYS_PCI_CAP_H
#define	_SYS_PCI_CAP_H

#ifdef __cplusplus
extern "C" {
#endif

#define	PCI_CAP_XCFG_FLAG_SHIFT	31
#define	PCI_CAP_XCFG_FLAG	(1u << PCI_CAP_XCFG_FLAG_SHIFT)

/* Function Prototypes */
int pci_xcap_locate(ddi_acc_handle_t h, uint16_t id, uint16_t *base_p);
int pci_lcap_locate(ddi_acc_handle_t h, uint8_t id, uint16_t *base_p);
int pci_htcap_locate(ddi_acc_handle_t h, uint16_t reg_mask, uint16_t reg_val,
    uint16_t *base_p);


/* Extract the lower 16 bits Extended CFG SPACE */
#define	PCI_CAP_XID_MASK		0xffff

/* Extract the lower 8 bits Extended CFG SPACE */
#define	PCI_CAP_ID_MASK		0xff

#define	PCI_CAP_XCFG_SPC(i) 	((i) ? (i) | PCI_CAP_XCFG_FLAG : 0)

#ifdef DEBUG
#define	PCI_CAP_DBG		if (pci_cap_debug) printf
#else
#define PCI_CAP_DBG		_NOTE(CONSTANTCONDITION) if (0) printf
#endif /* DEBUG */

/* 2's complement of -1, added here to ameliorate testing for invalid data */
#define	PCI_CAP_EINVAL8		0xff
#define	PCI_CAP_EINVAL16	0xffff
#define	PCI_CAP_EINVAL32	0xffffffff

/*
 * Supported Config Size Reads/Writes
 */

typedef enum {
	PCI_CAP_CFGSZ_8 	= 0,
	PCI_CAP_CFGSZ_16	= 1,
	PCI_CAP_CFGSZ_32	= 2
} pci_cap_config_size_t;

/* Define Macros */

#define	PCI_CAP_LOCATE(h, id, base_p) ((id) & PCI_CAP_XCFG_FLAG ? \
	pci_xcap_locate(h, (uint16_t)((id) & PCI_CAP_XID_MASK), base_p) : \
	pci_lcap_locate(h, (uint8_t)((id) & PCI_CAP_ID_MASK), base_p))

#define	PCI_CAP_GET8(h, i, b, o) ((uint8_t) \
	pci_cap_get(h, PCI_CAP_CFGSZ_8, i, b, o))
#define	PCI_CAP_GET16(h, i, b, o) ((uint16_t) \
	pci_cap_get(h, PCI_CAP_CFGSZ_16, i, b, o))
#define	PCI_CAP_GET32(h, i, b, o) ((uint32_t) \
	pci_cap_get(h, PCI_CAP_CFGSZ_32, i, b, o))

#define	PCI_CAP_PUT8(h, i, b, o, d) ((uint8_t) \
	pci_cap_put(h, PCI_CAP_CFGSZ_8, i, b, o, d))
#define	PCI_CAP_PUT16(h, i, b, o, d) ((uint16_t) \
	pci_cap_put(h, PCI_CAP_CFGSZ_16, i, b, o, d))
#define	PCI_CAP_PUT32(h, i, b, o, d) ((uint32_t) \
	pci_cap_put(h, PCI_CAP_CFGSZ_32, i, b, o, d))

#define	PCI_XCAP_GET8(h, i, b, o) ((uint8_t) \
	pci_cap_get(h, PCI_CAP_CFGSZ_8, PCI_CAP_XCFG_SPC(i), b, o))
#define	PCI_XCAP_GET16(h, i, b, o) ((uint16_t) \
	pci_cap_get(h, PCI_CAP_CFGSZ_16, PCI_CAP_XCFG_SPC(i), b, o))
#define	PCI_XCAP_GET32(h, i, b, o) ((uint32_t) \
	pci_cap_get(h, PCI_CAP_CFGSZ_32, PCI_CAP_XCFG_SPC(i), b, o))

#define	PCI_XCAP_PUT8(h, i, b, o, d) ((uint8_t) \
	pci_cap_put(h, PCI_CAP_CFGSZ_8, PCI_CAP_XCFG_SPC(i), b, o, d))
#define	PCI_XCAP_PUT16(h, i, b, o, d) ((uint16_t) \
	pci_cap_put(h, PCI_CAP_CFGSZ_16, PCI_CAP_XCFG_SPC(i), b, o, d))
#define	PCI_XCAP_PUT32(h, i, b, o, d) ((uint32_t) \
	pci_cap_put(h, PCI_CAP_CFGSZ_32, PCI_CAP_XCFG_SPC(i), b, o, d))


extern int pci_cap_probe(ddi_acc_handle_t h, uint16_t index,
		uint32_t *id_p, uint16_t *base_p);

extern uint32_t pci_cap_get(ddi_acc_handle_t h, pci_cap_config_size_t size,
		uint32_t id, uint16_t base, uint16_t offset);

extern int pci_cap_put(ddi_acc_handle_t h, pci_cap_config_size_t size,
		uint32_t id, uint16_t base, uint16_t offset, uint32_t data);

extern int pci_cap_read(ddi_acc_handle_t h, uint32_t id, uint16_t base,
		uint32_t *buf_p, uint32_t nwords);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_PCI_CAP_H */
