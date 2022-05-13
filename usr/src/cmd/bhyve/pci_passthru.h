/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Beckhoff Automation GmbH & Co. KG
 * Author: Corvin K<C3><B6>hne <c.koehne@beckhoff.com>
 */

#ifndef _PCI_PASSTHRU_H_
#define _PCI_PASSTHRU_H_

#include <vmmapi.h>

#include "pci_emul.h"

uint32_t read_config(struct pci_devinst *pi, long reg, int width);
void write_config(struct pci_devinst *pi, long reg, int width, uint32_t data);

#endif /* _PCI_PASSTHRU_H_ */
