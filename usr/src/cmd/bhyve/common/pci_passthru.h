/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin K<C3><B6>hne <c.koehne@beckhoff.com>
 */

#ifndef _PCI_PASSTHRU_H_
#define _PCI_PASSTHRU_H_

#include <vmmapi.h>

#include "pci_emul.h"

struct passthru_softc;

typedef int (*cfgread_handler)(struct passthru_softc *sc,
    struct pci_devinst *pi, int coff, int bytes, uint32_t *rv);
typedef int (*cfgwrite_handler)(struct passthru_softc *sc,
    struct pci_devinst *pi, int coff, int bytes, uint32_t val);

uint32_t pci_host_read_config(const struct pcisel *sel, long reg, int width);
void pci_host_write_config(const struct pcisel *sel, long reg, int width,
    uint32_t data);

int passthru_cfgread_emulate(struct passthru_softc *sc, struct pci_devinst *pi,
    int coff, int bytes, uint32_t *rv);
int passthru_cfgwrite_emulate(struct passthru_softc *sc, struct pci_devinst *pi,
    int coff, int bytes, uint32_t val);
int set_pcir_handler(struct passthru_softc *sc, int reg, int len,
    cfgread_handler rhandler, cfgwrite_handler whandler);

#endif /* _PCI_PASSTHRU_H_ */
