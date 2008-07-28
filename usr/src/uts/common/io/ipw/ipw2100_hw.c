/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004
 *	Damien Bergamini <damien.bergamini@free.fr>. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Intel Wireless PRO/2100 mini-PCI adapter driver
 * ipw2100_hw.c is used to handle hardware operation and firmware operations.
 */
#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/stream.h>
#include <sys/strsun.h>

#include "ipw2100.h"
#include "ipw2100_impl.h"

/*
 * Hardware related operations
 */
#define	IPW2100_EEPROM_SHIFT_D	(2)
#define	IPW2100_EEPROM_SHIFT_Q	(4)

#define	IPW2100_EEPROM_C	(1 << 0)
#define	IPW2100_EEPROM_S	(1 << 1)
#define	IPW2100_EEPROM_D	(1 << IPW2100_EEPROM_SHIFT_D)
#define	IPW2100_EEPROM_Q	(1 << IPW2100_EEPROM_SHIFT_Q)

uint8_t
ipw2100_csr_get8(struct ipw2100_softc *sc, uint32_t off)
{
	return (ddi_get8(sc->sc_ioh, (uint8_t *)(sc->sc_regs + off)));
}

uint16_t
ipw2100_csr_get16(struct ipw2100_softc *sc, uint32_t off)
{
	return (ddi_get16(sc->sc_ioh,
	    (uint16_t *)((uintptr_t)sc->sc_regs + off)));
}

uint32_t
ipw2100_csr_get32(struct ipw2100_softc *sc, uint32_t off)
{
	return (ddi_get32(sc->sc_ioh,
	    (uint32_t *)((uintptr_t)sc->sc_regs + off)));
}

void
ipw2100_csr_rep_get16(struct ipw2100_softc *sc,
	uint32_t off, uint16_t *buf, size_t cnt)
{
	ddi_rep_get16(sc->sc_ioh, buf,
	    (uint16_t *)((uintptr_t)sc->sc_regs + off),
	    cnt, DDI_DEV_NO_AUTOINCR);
}

void
ipw2100_csr_put8(struct ipw2100_softc *sc, uint32_t off, uint8_t val)
{
	ddi_put8(sc->sc_ioh, (uint8_t *)(sc->sc_regs + off), val);
}

void
ipw2100_csr_put16(struct ipw2100_softc *sc, uint32_t off, uint16_t val)
{
	ddi_put16(sc->sc_ioh,
	    (uint16_t *)((uintptr_t)sc->sc_regs + off), val);
}

void
ipw2100_csr_put32(struct ipw2100_softc *sc, uint32_t off, uint32_t val)
{
	ddi_put32(sc->sc_ioh,
	    (uint32_t *)((uintptr_t)sc->sc_regs + off), val);
}

void
ipw2100_csr_rep_put8(struct ipw2100_softc *sc,
	uint32_t off, uint8_t *buf, size_t cnt)
{
	ddi_rep_put8(sc->sc_ioh, buf, (uint8_t *)(sc->sc_regs + off),
	    cnt, DDI_DEV_NO_AUTOINCR);
}

uint8_t
ipw2100_imem_get8(struct ipw2100_softc *sc, int32_t addr)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);

	return (ipw2100_csr_get8(sc, IPW2100_CSR_INDIRECT_DATA));
}

uint16_t
ipw2100_imem_get16(struct ipw2100_softc *sc, uint32_t addr)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);

	return (ipw2100_csr_get16(sc, IPW2100_CSR_INDIRECT_DATA));
}

uint32_t
ipw2100_imem_get32(struct ipw2100_softc *sc, uint32_t addr)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);

	return (ipw2100_csr_get32(sc, IPW2100_CSR_INDIRECT_DATA));
}

void
ipw2100_imem_rep_get16(struct ipw2100_softc *sc,
	uint32_t addr, uint16_t *buf, size_t cnt)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);
	ipw2100_csr_rep_get16(sc, IPW2100_CSR_INDIRECT_DATA, buf, cnt);
}

void
ipw2100_imem_put8(struct ipw2100_softc *sc, uint32_t addr, uint8_t val)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);
	ipw2100_csr_put8(sc, IPW2100_CSR_INDIRECT_DATA, val);
}

void
ipw2100_imem_put16(struct ipw2100_softc *sc, uint32_t addr, uint16_t val)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);
	ipw2100_csr_put16(sc, IPW2100_CSR_INDIRECT_DATA, val);
}

void
ipw2100_imem_put32(struct ipw2100_softc *sc, uint32_t addr, uint32_t val)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_DATA, val);
}

void
ipw2100_imem_rep_put8(struct ipw2100_softc *sc,
	uint32_t addr, uint8_t *buf, size_t cnt)
{
	ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr);
	ipw2100_csr_rep_put8(sc, IPW2100_CSR_INDIRECT_DATA, buf, cnt);
}

void
ipw2100_imem_getbuf(struct ipw2100_softc *sc,
	uint32_t addr, uint8_t *buf, size_t cnt)
{
	for (; cnt > 0; addr++, buf++, cnt--) {
		ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr & ~3);
		*buf = ipw2100_csr_get8(sc,
		    IPW2100_CSR_INDIRECT_DATA +(addr & 3));
	}
}

void
ipw2100_imem_putbuf(struct ipw2100_softc *sc,
	uint32_t addr, uint8_t *buf, size_t cnt)
{
	for (; cnt > 0; addr++, buf++, cnt--) {
		ipw2100_csr_put32(sc, IPW2100_CSR_INDIRECT_ADDR, addr & ~3);
		ipw2100_csr_put8(sc,
		    IPW2100_CSR_INDIRECT_DATA +(addr & 3), *buf);
	}
}

void
ipw2100_rom_control(struct ipw2100_softc *sc, uint32_t val)
{
	ipw2100_imem_put32(sc, IPW2100_IMEM_EEPROM_CTL, val);
	drv_usecwait(IPW2100_EEPROM_DELAY);
}


uint8_t
ipw2100_table1_get8(struct ipw2100_softc *sc, uint32_t off)
{
	uint32_t addr = ipw2100_imem_get32(sc, sc->sc_table1_base + off);
	return (ipw2100_imem_get8(sc, addr));
}

uint32_t
ipw2100_table1_get32(struct ipw2100_softc *sc, uint32_t off)
{
	uint32_t addr = ipw2100_imem_get32(sc, sc->sc_table1_base + off);
	return (ipw2100_imem_get32(sc, addr));
}

void
ipw2100_table1_put32(struct ipw2100_softc *sc, uint32_t off, uint32_t val)
{
	uint32_t addr = ipw2100_imem_get32(sc, sc->sc_table1_base + off);
	ipw2100_imem_put32(sc, addr, val);
}

int
ipw2100_table2_getbuf(struct ipw2100_softc *sc,
	uint32_t off, uint8_t *buf, uint32_t *len)
{
	uint32_t	addr, info;
	uint16_t	cnt, size;
	uint32_t	total;

	addr = ipw2100_imem_get32(sc, sc->sc_table2_base + off);
	info = ipw2100_imem_get32(sc,
	    sc->sc_table2_base + off + sizeof (uint32_t));

	cnt = info >> 16;
	size = info & 0xffff;
	total = cnt * size;

	if (total > *len) {
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_table2_getbuf(): invalid table offset = 0x%08x\n",
		    off));
		return (DDI_FAILURE);
	}

	*len = total;
	ipw2100_imem_getbuf(sc, addr, buf, total);

	return (DDI_SUCCESS);
}

uint16_t
ipw2100_rom_get16(struct ipw2100_softc *sc, uint8_t addr)
{
	uint32_t	tmp;
	uint16_t	val;
	int		n;

	/*
	 * According to i2c bus protocol to set them.
	 */
	/* clock */
	ipw2100_rom_control(sc, 0);
	ipw2100_rom_control(sc, IPW2100_EEPROM_S);
	ipw2100_rom_control(sc, IPW2100_EEPROM_S | IPW2100_EEPROM_C);
	ipw2100_rom_control(sc, IPW2100_EEPROM_S);
	/* start bit */
	ipw2100_rom_control(sc, IPW2100_EEPROM_S | IPW2100_EEPROM_D);
	ipw2100_rom_control(sc, IPW2100_EEPROM_S
	    | IPW2100_EEPROM_D | IPW2100_EEPROM_C);
	/* read opcode */
	ipw2100_rom_control(sc, IPW2100_EEPROM_S | IPW2100_EEPROM_D);
	ipw2100_rom_control(sc, IPW2100_EEPROM_S
	    | IPW2100_EEPROM_D | IPW2100_EEPROM_C);
	ipw2100_rom_control(sc, IPW2100_EEPROM_S);
	ipw2100_rom_control(sc, IPW2100_EEPROM_S | IPW2100_EEPROM_C);
	/*
	 * address, totally 8 bits, defined by hardware, push from MSB to LSB
	 */
	for (n = 7; n >= 0; n--) {
		ipw2100_rom_control(sc, IPW2100_EEPROM_S
		    |(((addr >> n) & 1) << IPW2100_EEPROM_SHIFT_D));
		ipw2100_rom_control(sc, IPW2100_EEPROM_S
		    |(((addr >> n) & 1) << IPW2100_EEPROM_SHIFT_D)
		    | IPW2100_EEPROM_C);
	}

	ipw2100_rom_control(sc, IPW2100_EEPROM_S);

	/*
	 * data, totally 16 bits, defined by hardware, push from MSB to LSB
	 */
	val = 0;
	for (n = 15; n >= 0; n--) {
		ipw2100_rom_control(sc, IPW2100_EEPROM_S | IPW2100_EEPROM_C);
		ipw2100_rom_control(sc, IPW2100_EEPROM_S);
		tmp = ipw2100_imem_get32(sc, IPW2100_IMEM_EEPROM_CTL);
		val |= ((tmp & IPW2100_EEPROM_Q)
		    >> IPW2100_EEPROM_SHIFT_Q) << n;
	}

	ipw2100_rom_control(sc, 0);

	/* clear chip select and clock */
	ipw2100_rom_control(sc, IPW2100_EEPROM_S);
	ipw2100_rom_control(sc, 0);
	ipw2100_rom_control(sc, IPW2100_EEPROM_C);

	return (LE_16(val));
}


/*
 * Firmware related operations
 */
#define	IPW2100_FW_MAJOR_VERSION (1)
#define	IPW2100_FW_MINOR_VERSION (3)

#define	IPW2100_FW_MAJOR(x)((x) & 0xff)
#define	IPW2100_FW_MINOR(x)(((x) & 0xff) >> 8)

/*
 * The firware was issued by Intel as binary which need to be loaded
 * to hardware when card is initiated, or when fatal error happened,
 * or when the chip need be reset.
 */
static uint8_t ipw2100_firmware_bin [] = {
#include "fw-ipw2100/ipw2100-1.3.fw.hex"
};

int
ipw2100_cache_firmware(struct ipw2100_softc *sc)
{
	uint8_t				*bin = ipw2100_firmware_bin;
	struct ipw2100_firmware_hdr	*h = (struct ipw2100_firmware_hdr *)bin;

	IPW2100_DBG(IPW2100_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2100_cache_firmwares(): enter\n"));

	sc->sc_fw.bin_base  = bin;
	sc->sc_fw.bin_size  = sizeof (ipw2100_firmware_bin);

	if (IPW2100_FW_MAJOR(h->version) != IPW2100_FW_MAJOR_VERSION) {
		IPW2100_WARN((sc->sc_dip, CE_WARN,
		    "ipw2100_cache_firmware(): image not compatible, %u\n",
		    h->version));
		return (DDI_FAILURE);
	}

	sc->sc_fw.fw_base = bin + sizeof (struct ipw2100_firmware_hdr);
	sc->sc_fw.fw_size = LE_32(h->fw_size);
	sc->sc_fw.uc_base = sc->sc_fw.fw_base + sc->sc_fw.fw_size;
	sc->sc_fw.uc_size = LE_32(h->uc_size);

	sc->sc_flags |= IPW2100_FLAG_FW_CACHED;

	IPW2100_DBG(IPW2100_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2100_cache_firmware(): exit\n"));

	return (DDI_SUCCESS);
}

/*
 * If user-land firmware loading is supported, this routine
 * free kmemory if sc->sc_fw.bin_base & sc->sc_fw.bin_size are
 * not empty.
 */
int
ipw2100_free_firmware(struct ipw2100_softc *sc)
{
	sc->sc_flags &= ~IPW2100_FLAG_FW_CACHED;

	return (DDI_SUCCESS);
}

/*
 * the following routines load code onto ipw2100 hardware
 */
int
ipw2100_load_uc(struct ipw2100_softc *sc)
{
	int	ntries;

	ipw2100_imem_put32(sc, 0x3000e0, 0x80000000);
	ipw2100_csr_put32(sc, IPW2100_CSR_RST, 0);

	ipw2100_imem_put16(sc, 0x220000, 0x0703);
	ipw2100_imem_put16(sc, 0x220000, 0x0707);

	ipw2100_imem_put8(sc, 0x210014, 0x72);
	ipw2100_imem_put8(sc, 0x210014, 0x72);

	ipw2100_imem_put8(sc, 0x210000, 0x40);
	ipw2100_imem_put8(sc, 0x210000, 0x00);
	ipw2100_imem_put8(sc, 0x210000, 0x40);

	ipw2100_imem_rep_put8(sc, 0x210010,
	    sc->sc_fw.uc_base, sc->sc_fw.uc_size);

	ipw2100_imem_put8(sc, 0x210000, 0x00);
	ipw2100_imem_put8(sc, 0x210000, 0x00);
	ipw2100_imem_put8(sc, 0x210000, 0x80);

	ipw2100_imem_put16(sc, 0x220000, 0x0703);
	ipw2100_imem_put16(sc, 0x220000, 0x0707);

	ipw2100_imem_put8(sc, 0x210014, 0x72);
	ipw2100_imem_put8(sc, 0x210014, 0x72);

	ipw2100_imem_put8(sc, 0x210000, 0x00);
	ipw2100_imem_put8(sc, 0x210000, 0x80);

	/* try many times */
	for (ntries = 0; ntries < 5000; ntries++) {
		if (ipw2100_imem_get8(sc, 0x210000) & 1)
			break;
		drv_usecwait(1000); /* wait for a while */
	}
	if (ntries == 5000)
		return (DDI_FAILURE);

	ipw2100_imem_put32(sc, 0x3000e0, 0);

	return (DDI_SUCCESS);
}

int
ipw2100_load_fw(struct ipw2100_softc *sc)
{
	uint8_t		*p, *e;
	uint32_t	dst;
	uint16_t	len;
	clock_t		clk;

	IPW2100_DBG(IPW2100_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2100_load_fw(): enter\n"));

	p = sc->sc_fw.fw_base;
	e = sc->sc_fw.fw_base + sc->sc_fw.fw_size;
	while (p < e) {
		/*
		 * each block is organized as <DST,LEN,DATA>
		 */
		if ((p + sizeof (dst) + sizeof (len)) > e) {
			IPW2100_WARN((sc->sc_dip, CE_CONT,
			    "ipw2100_load_fw(): invalid firmware image\n"));
			return (DDI_FAILURE);
		}
		dst = LE_32(*((uint32_t *)(uintptr_t)p)); p += sizeof (dst);
		len = LE_16(*((uint16_t *)(uintptr_t)p)); p += sizeof (len);
		if ((p + len) > e) {
			IPW2100_WARN((sc->sc_dip, CE_CONT,
			    "ipw2100_load_fw(): invalid firmware image\n"));
			return (DDI_FAILURE);
		}

		ipw2100_imem_putbuf(sc, dst, p, len);
		p += len;
	}

	ipw2100_csr_put32(sc, IPW2100_CSR_IO,
	    IPW2100_IO_GPIO1_ENABLE | IPW2100_IO_GPIO3_MASK |
	    IPW2100_IO_LED_OFF);

	mutex_enter(&sc->sc_ilock);

	/*
	 * enable all interrupts
	 */
	ipw2100_csr_put32(sc, IPW2100_CSR_INTR_MASK, IPW2100_INTR_MASK_ALL);

	ipw2100_csr_put32(sc, IPW2100_CSR_RST, 0);
	ipw2100_csr_put32(sc, IPW2100_CSR_CTL,
	    ipw2100_csr_get32(sc, IPW2100_CSR_CTL) | IPW2100_CTL_ALLOW_STANDBY);

	/*
	 * wait for interrupt to notify fw initialization is done
	 */
	while (!(sc->sc_flags & IPW2100_FLAG_FW_INITED)) {
		/*
		 * wait longer for the fw  initialized
		 */
		clk = ddi_get_lbolt() + drv_usectohz(5000000);  /* 5 second */
		if (cv_timedwait(&sc->sc_fw_cond, &sc->sc_ilock, clk) < 0)
			break;
	}
	mutex_exit(&sc->sc_ilock);

	ipw2100_csr_put32(sc, IPW2100_CSR_IO,
	    ipw2100_csr_get32(sc, IPW2100_CSR_IO) |
	    IPW2100_IO_GPIO1_MASK | IPW2100_IO_GPIO3_MASK);

	if (!(sc->sc_flags & IPW2100_FLAG_FW_INITED)) {
		IPW2100_DBG(IPW2100_DBG_FW, (sc->sc_dip, CE_CONT,
		    "ipw2100_load_fw(): exit, init failed\n"));
		return (DDI_FAILURE);
	}

	IPW2100_DBG(IPW2100_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2100_load_fw(): exit\n"));
	return (DDI_SUCCESS);
}
