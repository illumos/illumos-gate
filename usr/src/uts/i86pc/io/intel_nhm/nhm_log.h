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

#ifndef _NHM_LOG_H
#define	_NHM_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/cpu_module.h>

typedef struct nhm_dimm {
	uint64_t dimm_size;
	uint8_t nranks;
	uint8_t nbanks;
	uint8_t ncolumn;
	uint8_t nrow;
	uint8_t width;
	char manufacturer[64];
	char serial_number[64];
	char part_number[16];
	char revision[2];
	char label[64];
} nhm_dimm_t;

extern nhm_dimm_t **nhm_dimms;
extern uint32_t nhm_chipset;

extern errorq_t *nhm_queue;
extern kmutex_t nhm_mutex;

extern void nhm_drain(void *, const void *, const errorq_elem_t *);

extern int nhm_init(void);
extern int nhm_dev_init(void);
extern void nhm_dev_reinit(void);
extern void nhm_unload(void);
extern void nhm_dev_unload(void);

extern int inhm_mc_register(cmi_hdl_t, void *, void *, void *);
extern void nhm_scrubber_enable(void);
extern void nhm_error_trap(cmi_hdl_t, boolean_t, boolean_t);

extern void nhm_pci_cfg_setup(dev_info_t *);
extern void nhm_pci_cfg_free(void);

extern uint8_t nhm_pci_getb(int, int, int, int, int *);
extern uint16_t nhm_pci_getw(int, int, int, int, int *);
extern uint32_t nhm_pci_getl(int, int, int, int, int *);
extern void nhm_pci_putb(int, int, int, int, uint8_t);
extern void nhm_pci_putw(int, int, int, int, uint16_t);
extern void nhm_pci_putl(int, int, int, int, uint32_t);

extern uint64_t dimm_to_addr(int, int, int, uint64_t, uint64_t *, uint64_t *,
    uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *, uint32_t *);

#ifdef __cplusplus
}
#endif

#endif /* _NHM_LOG_H */
