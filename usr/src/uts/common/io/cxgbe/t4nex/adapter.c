/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2011-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "common.h"

uint32_t
t4_read_reg(struct adapter *sc, uint32_t reg)
{
	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	return (ddi_get32(sc->regh, (uint32_t *)(sc->regp + reg)));
}

void
t4_write_reg(struct adapter *sc, uint32_t reg, uint32_t val)
{
	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	ddi_put32(sc->regh, (uint32_t *)(sc->regp + reg), val);
}

void
t4_os_pci_read_cfg1(struct adapter *sc, int reg, uint8_t *val)
{
	*val = pci_config_get8(sc->pci_regh, reg);
}

void
t4_os_pci_write_cfg1(struct adapter *sc, int reg, uint8_t val)
{
	pci_config_put8(sc->pci_regh, reg, val);
}

void
t4_os_pci_read_cfg2(struct adapter *sc, int reg, uint16_t *val)
{
	*val = pci_config_get16(sc->pci_regh, reg);
}

void
t4_os_pci_write_cfg2(struct adapter *sc, int reg, uint16_t val)
{
	pci_config_put16(sc->pci_regh, reg, val);
}

void
t4_os_pci_read_cfg4(struct adapter *sc, int reg, uint32_t *val)
{
	*val = pci_config_get32(sc->pci_regh, reg);
}

void
t4_os_pci_write_cfg4(struct adapter *sc, int reg, uint32_t val)
{
	pci_config_put32(sc->pci_regh, reg, val);
}

uint64_t
t4_read_reg64(struct adapter *sc, uint32_t reg)
{
	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	return (ddi_get64(sc->regh, (uint64_t *)(sc->regp + reg)));
}

void
t4_write_reg64(struct adapter *sc, uint32_t reg, uint64_t val)
{
	/* LINTED: E_BAD_PTR_CAST_ALIGN */
	ddi_put64(sc->regh, (uint64_t *)(sc->regp + reg), val);
}

struct port_info *
adap2pinfo(struct adapter *sc, int idx)
{
	return (sc->port[idx]);
}

void
t4_os_set_hw_addr(struct adapter *sc, int idx, uint8_t hw_addr[])
{
	bcopy(hw_addr, sc->port[idx]->hw_addr, ETHERADDRL);
}

bool
is_10G_port(const struct port_info *pi)
{
	return ((pi->link_cfg.supported & FW_PORT_CAP_SPEED_10G) != 0);
}

struct sge_rxq *
iq_to_rxq(struct sge_iq *iq)
{
	return (container_of(iq, struct sge_rxq, iq));
}

bool
is_40G_port(const struct port_info *pi)
{
	return ((pi->link_cfg.supported & FW_PORT_CAP_SPEED_40G) != 0);
}

#ifndef TCP_OFFLOAD_DISABLE
int
t4_wrq_tx(struct adapter *sc, struct sge_wrq *wrq, mblk_t *m)
{
	int rc;

	TXQ_LOCK(wrq);
	rc = t4_wrq_tx_locked(sc, wrq, m);
	TXQ_UNLOCK(wrq);
	return (rc);
}
#endif
