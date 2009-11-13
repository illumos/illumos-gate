/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2004, 2005
 *      Damien Bergamini <damien.bergamini@free.fr>. All rights reserved.
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

/*
 * Intel Wireless PRO/2200 mini-PCI adapter driver
 * ipw2200_hw.c is used t handle hardware operations and firmware operations.
 */
#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/stream.h>
#include <sys/strsun.h>

#include "ipw2200.h"
#include "ipw2200_impl.h"

/*
 * Hardware related operations
 */
#define	IPW2200_EEPROM_SHIFT_D		(2)
#define	IPW2200_EEPROM_SHIFT_Q		(4)

#define	IPW2200_EEPROM_C		(1 << 0)
#define	IPW2200_EEPROM_S		(1 << 1)
#define	IPW2200_EEPROM_D		(1 << IPW2200_EEPROM_SHIFT_D)
#define	IPW2200_EEPROM_Q		(1 << IPW2200_EEPROM_SHIFT_Q)

uint8_t
ipw2200_csr_get8(struct ipw2200_softc *sc, uint32_t off)
{
	return (ddi_get8(sc->sc_ioh, (uint8_t *)(sc->sc_regs + off)));
}

uint16_t
ipw2200_csr_get16(struct ipw2200_softc *sc, uint32_t off)
{
	return (ddi_get16(sc->sc_ioh,
	    (uint16_t *)((uintptr_t)sc->sc_regs + off)));
}

uint32_t
ipw2200_csr_get32(struct ipw2200_softc *sc, uint32_t off)
{
	return (ddi_get32(sc->sc_ioh,
	    (uint32_t *)((uintptr_t)sc->sc_regs + off)));
}

void
ipw2200_csr_getbuf32(struct ipw2200_softc *sc, uint32_t off,
	uint32_t *buf, size_t cnt)
{
	ddi_rep_get32(sc->sc_ioh, buf,
	    (uint32_t *)((uintptr_t)sc->sc_regs + off),
	    cnt, DDI_DEV_AUTOINCR);
}

void
ipw2200_csr_put8(struct ipw2200_softc *sc, uint32_t off,
	uint8_t val)
{
	ddi_put8(sc->sc_ioh, (uint8_t *)(sc->sc_regs + off), val);
}

void
ipw2200_csr_put16(struct ipw2200_softc *sc, uint32_t off,
	uint16_t val)
{
	ddi_put16(sc->sc_ioh,
	    (uint16_t *)((uintptr_t)sc->sc_regs + off), val);
}

void
ipw2200_csr_put32(struct ipw2200_softc *sc, uint32_t off,
	uint32_t val)
{
	ddi_put32(sc->sc_ioh,
	    (uint32_t *)((uintptr_t)sc->sc_regs + off), val);
}

uint8_t
ipw2200_imem_get8(struct ipw2200_softc *sc, uint32_t addr)
{
	ipw2200_csr_put32(sc, IPW2200_CSR_INDIRECT_ADDR, addr);
	return (ipw2200_csr_get8(sc, IPW2200_CSR_INDIRECT_DATA));
}

uint16_t
ipw2200_imem_get16(struct ipw2200_softc *sc,
	uint32_t addr)
{
	ipw2200_csr_put32(sc, IPW2200_CSR_INDIRECT_ADDR, addr);
	return (ipw2200_csr_get16(sc, IPW2200_CSR_INDIRECT_DATA));
}

uint32_t
ipw2200_imem_get32(struct ipw2200_softc *sc, uint32_t addr)
{
	ipw2200_csr_put32(sc, IPW2200_CSR_INDIRECT_ADDR, addr);
	return (ipw2200_csr_get32(sc, IPW2200_CSR_INDIRECT_DATA));
}

void
ipw2200_imem_put8(struct ipw2200_softc *sc, uint32_t addr, uint8_t val)
{
	ipw2200_csr_put32(sc, IPW2200_CSR_INDIRECT_ADDR, addr);
	ipw2200_csr_put8(sc, IPW2200_CSR_INDIRECT_DATA, val);
}

void
ipw2200_imem_put16(struct ipw2200_softc *sc, uint32_t addr,
	uint16_t val)
{
	ipw2200_csr_put32(sc, IPW2200_CSR_INDIRECT_ADDR, addr);
	ipw2200_csr_put16(sc, IPW2200_CSR_INDIRECT_DATA, val);
}

void
ipw2200_imem_put32(struct ipw2200_softc *sc, uint32_t addr,
	uint32_t val)
{
	ipw2200_csr_put32(sc, IPW2200_CSR_INDIRECT_ADDR, addr);
	ipw2200_csr_put32(sc, IPW2200_CSR_INDIRECT_DATA, val);
}

void
ipw2200_rom_control(struct ipw2200_softc *sc, uint32_t val)
{
	ipw2200_imem_put32(sc, IPW2200_IMEM_EEPROM_CTL, val);
	drv_usecwait(IPW2200_EEPROM_DELAY);
}

uint16_t
ipw2200_rom_get16(struct ipw2200_softc *sc, uint8_t addr)
{
	uint32_t	tmp;
	uint16_t	val;
	int		n;

	/*
	 * According to i2c bus protocol
	 */
	/* clock */
	ipw2200_rom_control(sc, 0);
	ipw2200_rom_control(sc, IPW2200_EEPROM_S);
	ipw2200_rom_control(sc, IPW2200_EEPROM_S | IPW2200_EEPROM_C);
	ipw2200_rom_control(sc, IPW2200_EEPROM_S);
	/* start bit */
	ipw2200_rom_control(sc, IPW2200_EEPROM_S | IPW2200_EEPROM_D);
	ipw2200_rom_control(sc, IPW2200_EEPROM_S | IPW2200_EEPROM_D |
	    IPW2200_EEPROM_C);
	/* read opcode */
	ipw2200_rom_control(sc, IPW2200_EEPROM_S | IPW2200_EEPROM_D);
	ipw2200_rom_control(sc, IPW2200_EEPROM_S | IPW2200_EEPROM_D |
	    IPW2200_EEPROM_C);
	ipw2200_rom_control(sc, IPW2200_EEPROM_S);
	ipw2200_rom_control(sc, IPW2200_EEPROM_S | IPW2200_EEPROM_C);
	/*
	 * address, totally 8 bits, defined by hardware, push from MSB to LSB
	 */
	for (n = 7; n >= 0; n--) {
		ipw2200_rom_control(sc, IPW2200_EEPROM_S |
		    (((addr >> n) & 1) << IPW2200_EEPROM_SHIFT_D));
		ipw2200_rom_control(sc, IPW2200_EEPROM_S |
		    (((addr >> n) & 1) << IPW2200_EEPROM_SHIFT_D) |
		    IPW2200_EEPROM_C);
	}

	ipw2200_rom_control(sc, IPW2200_EEPROM_S);

	/*
	 * data, totally 16 bits, defined by hardware, push from MSB to LSB
	 */
	val = 0;
	for (n = 15; n >= 0; n--) {
		ipw2200_rom_control(sc, IPW2200_EEPROM_S | IPW2200_EEPROM_C);
		ipw2200_rom_control(sc, IPW2200_EEPROM_S);
		tmp = ipw2200_imem_get32(sc, IPW2200_IMEM_EEPROM_CTL);
		val |= ((tmp & IPW2200_EEPROM_Q) >> IPW2200_EEPROM_SHIFT_Q)
		    << n;
	}

	ipw2200_rom_control(sc, 0);

	/* clear chip select and clock */
	ipw2200_rom_control(sc, IPW2200_EEPROM_S);
	ipw2200_rom_control(sc, 0);
	ipw2200_rom_control(sc, IPW2200_EEPROM_C);

	return (BE_16(val));
}

/*
 * Firmware related operations
 */
#define	IPW2200_FW_MAJOR_VERSION	(2)
#define	IPW2200_FW_MINOR_VERSION	(4)

#define	IPW2200_FW_MAJOR(x)((x) & 0xff)
#define	IPW2200_FW_MINOR(x)(((x) & 0xff) >> 8)

/*
 * These firwares were issued by Intel as binaries which need to be
 * loaded to hardware when card is initiated, or when fatal error
 * happened, or when the chip need be reset.
 */
static uint8_t ipw2200_boot_bin [] = {
#include "fw-ipw2200/ipw-2.4-boot.hex"
};
static uint8_t ipw2200_ucode_bin [] = {
#include "fw-ipw2200/ipw-2.4-bss_ucode.hex"
};
static uint8_t ipw2200_fw_bin [] = {
#include "fw-ipw2200/ipw-2.4-bss.hex"
};

#pragma pack(1)
struct header {
	uint32_t	version;
	uint32_t	mode;
};
#pragma pack()

int
ipw2200_cache_firmware(struct ipw2200_softc *sc)
{
	IPW2200_DBG(IPW2200_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2200_cache_firmware(): enter\n"));

	/* boot code */
	sc->sc_fw.boot_base = ipw2200_boot_bin + sizeof (struct header);
	sc->sc_fw.boot_size =
	    sizeof (ipw2200_boot_bin) - sizeof (struct header);
	/* ucode */
	sc->sc_fw.uc_base = ipw2200_ucode_bin + sizeof (struct header);
	sc->sc_fw.uc_size = sizeof (ipw2200_ucode_bin) - sizeof (struct header);
	/* firmware */
	sc->sc_fw.fw_base = ipw2200_fw_bin + sizeof (struct header);
	sc->sc_fw.fw_size = sizeof (ipw2200_fw_bin) - sizeof (struct header);

	sc->sc_flags |= IPW2200_FLAG_FW_CACHED;

	IPW2200_DBG(IPW2200_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2200_cache_firmware(): boot=%u,uc=%u,fw=%u\n",
	    sc->sc_fw.boot_size, sc->sc_fw.uc_size, sc->sc_fw.fw_size));
	IPW2200_DBG(IPW2200_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2200_cache_firmware(): exit\n"));

	return (DDI_SUCCESS);
}

/*
 * If user-land firmware loading is supported, this routine will
 * free kernel memory, when sc->sc_fw.bin_base & sc->sc_fw.bin_size
 * are not empty
 */
int
ipw2200_free_firmware(struct ipw2200_softc *sc)
{
	sc->sc_flags &= ~IPW2200_FLAG_FW_CACHED;

	return (DDI_SUCCESS);
}

/*
 * the following routines load code onto ipw2200 hardware
 */
int
ipw2200_load_uc(struct ipw2200_softc *sc, uint8_t *buf, size_t size)
{
	int		ntries, i;
	uint16_t	*w;

	ipw2200_csr_put32(sc, IPW2200_CSR_RST,
	    IPW2200_RST_STOP_MASTER | ipw2200_csr_get32(sc, IPW2200_CSR_RST));
	for (ntries = 0; ntries < 5; ntries++) {
		if (ipw2200_csr_get32(sc, IPW2200_CSR_RST) &
		    IPW2200_RST_MASTER_DISABLED)
			break;
		drv_usecwait(10);
	}
	if (ntries == 5) {
		IPW2200_WARN((sc->sc_dip, CE_CONT,
		    "ipw2200_load_uc(): timeout waiting for master"));
		return (DDI_FAILURE);
	}

	ipw2200_imem_put32(sc, 0x3000e0, 0x80000000);
	drv_usecwait(5000);
	ipw2200_csr_put32(sc, IPW2200_CSR_RST,
	    ~IPW2200_RST_PRINCETON_RESET &
	    ipw2200_csr_get32(sc, IPW2200_CSR_RST));
	drv_usecwait(5000);
	ipw2200_imem_put32(sc, 0x3000e0, 0);
	drv_usecwait(1000);
	ipw2200_imem_put32(sc, IPW2200_IMEM_EVENT_CTL, 1);
	drv_usecwait(1000);
	ipw2200_imem_put32(sc, IPW2200_IMEM_EVENT_CTL, 0);
	drv_usecwait(1000);
	ipw2200_imem_put8(sc, 0x200000, 0x00);
	ipw2200_imem_put8(sc, 0x200000, 0x40);
	drv_usecwait(1000);

	for (w = (uint16_t *)(uintptr_t)buf; size > 0; w++, size -= 2)
		ipw2200_imem_put16(sc, 0x200010, LE_16(*w));

	ipw2200_imem_put8(sc, 0x200000, 0x00);
	ipw2200_imem_put8(sc, 0x200000, 0x80);

	/*
	 * try many times to wait the upload is ready, 2000times
	 */
	for (ntries = 0; ntries < 2000; ntries++) {
		uint8_t val;

		val = ipw2200_imem_get8(sc, 0x200000);
		if (val & 1)
			break;
		drv_usecwait(1000); /* wait for a while */
	}
	if (ntries == 2000) {
		IPW2200_WARN((sc->sc_dip, CE_WARN,
		    "ipw2200_load_uc(): timeout waiting for ucode init.\n"));
		return (DDI_FAILURE);
	}

	for (i = 0; i < 7; i++)
		(void) ipw2200_imem_get32(sc, 0x200004);

	ipw2200_imem_put8(sc, 0x200000, 0x00);

	return (DDI_SUCCESS);
}

#define	MAX_DR_NUM	(64)
#define	MAX_DR_SIZE	(4096)

int
ipw2200_load_fw(struct ipw2200_softc *sc, uint8_t *buf, size_t size)
{
	struct dma_region	dr[MAX_DR_NUM]; /* maximal, 64 * 4KB = 256KB */
	uint8_t			*p, *end, *v;
	uint32_t		mlen;
	uint32_t		src, dst, ctl, len, sum, off;
	uint32_t		sentinel;
	int			ntries, err, cnt, i;
	clock_t			clk = drv_usectohz(5000000);  /* 5 second */

	ipw2200_imem_put32(sc, 0x3000a0, 0x27000);

	p   = buf;
	end = p + size;

	cnt = 0;
	err = ipw2200_dma_region_alloc(sc, &dr[cnt], MAX_DR_SIZE, DDI_DMA_READ,
	    DDI_DMA_STREAMING);
	if (err != DDI_SUCCESS)
		goto fail0;
	off = 0;
	src = dr[cnt].dr_pbase;

	ipw2200_csr_put32(sc, IPW2200_CSR_AUTOINC_ADDR, 0x27000);

	while (p < end) {
		dst = LE_32(*((uint32_t *)(uintptr_t)p)); p += 4;
		len = LE_32(*((uint32_t *)(uintptr_t)p)); p += 4;
		v = p;
		p += len;
		IPW2200_DBG(IPW2200_DBG_FW, (sc->sc_dip, CE_CONT,
		    "ipw2200_load_fw(): dst=0x%x,len=%u\n", dst, len));

		while (len > 0) {
			/*
			 * if no DMA region is available, allocate a new one
			 */
			if (off == dr[cnt].dr_size) {
				cnt++;
				if (cnt >= MAX_DR_NUM) {
					IPW2200_WARN((sc->sc_dip, CE_WARN,
					    "ipw2200_load_fw(): "
					    "maximum %d DRs is reached\n",
					    cnt));
					cnt--; /* only free alloced DMA */
					goto fail1;
				}
				err = ipw2200_dma_region_alloc(sc, &dr[cnt],
				    MAX_DR_SIZE, DDI_DMA_WRITE,
				    DDI_DMA_STREAMING);
				if (err != DDI_SUCCESS) {
					cnt--; /* only free alloced DMA */
					goto fail1;
				}
				off = 0;
				src = dr[cnt].dr_pbase;
			}
			mlen = min(IPW2200_CB_MAXDATALEN, len);
			mlen = min(mlen, dr[cnt].dr_size - off);

			(void) memcpy(dr[cnt].dr_base + off, v, mlen);
			(void) ddi_dma_sync(dr[cnt].dr_hnd, off, mlen,
			    DDI_DMA_SYNC_FORDEV);

			ctl = IPW2200_CB_DEFAULT_CTL | mlen;
			sum = ctl ^ src ^ dst;
			/*
			 * write a command
			 */
			ipw2200_csr_put32(sc, IPW2200_CSR_AUTOINC_DATA, ctl);
			ipw2200_csr_put32(sc, IPW2200_CSR_AUTOINC_DATA, src);
			ipw2200_csr_put32(sc, IPW2200_CSR_AUTOINC_DATA, dst);
			ipw2200_csr_put32(sc, IPW2200_CSR_AUTOINC_DATA, sum);

			off += mlen;
			src += mlen;
			dst += mlen;
			v   += mlen;
			len -= mlen;
		}
	}

	sentinel = ipw2200_csr_get32(sc, IPW2200_CSR_AUTOINC_ADDR);
	ipw2200_csr_put32(sc, IPW2200_CSR_AUTOINC_DATA, 0);

	IPW2200_DBG(IPW2200_DBG_FW, (sc->sc_dip, CE_CONT,
	    "ipw2200_load_fw(): sentinel=%x\n", sentinel));

	ipw2200_csr_put32(sc, IPW2200_CSR_RST,
	    ~(IPW2200_RST_MASTER_DISABLED | IPW2200_RST_STOP_MASTER)
	    & ipw2200_csr_get32(sc, IPW2200_CSR_RST));

	ipw2200_imem_put32(sc, 0x3000a4, 0x540100);
	for (ntries = 0; ntries < 400; ntries++) {
		uint32_t val;
		val = ipw2200_imem_get32(sc, 0x3000d0);
		if (val >= sentinel)
			break;
		drv_usecwait(100);
	}
	if (ntries == 400) {
		IPW2200_WARN((sc->sc_dip, CE_WARN,
		    "ipw2200_load_fw(): timeout processing command blocks\n"));
		goto fail1;
	}

	mutex_enter(&sc->sc_ilock);

	ipw2200_imem_put32(sc, 0x3000a4, 0x540c00);

	/*
	 * enable all interrupts
	 */
	ipw2200_csr_put32(sc, IPW2200_CSR_INTR_MASK, IPW2200_INTR_MASK_ALL);

	/*
	 * tell the adapter to initialize the firmware,
	 * just simply set it to 0
	 */
	ipw2200_csr_put32(sc, IPW2200_CSR_RST, 0);
	ipw2200_csr_put32(sc, IPW2200_CSR_CTL,
	    ipw2200_csr_get32(sc, IPW2200_CSR_CTL) |
	    IPW2200_CTL_ALLOW_STANDBY);

	/*
	 * wait for interrupt to notify fw initialization is done
	 */
	sc->sc_fw_ok = 0;
	while (!sc->sc_fw_ok) {
		/*
		 * There is an enhancement! we just change from 1s to 5s
		 */
		if (cv_reltimedwait(&sc->sc_fw_cond, &sc->sc_ilock, clk,
		    TR_CLOCK_TICK) < 0)
			break;
	}
	mutex_exit(&sc->sc_ilock);

	if (!sc->sc_fw_ok) {
		IPW2200_WARN((sc->sc_dip, CE_WARN,
		    "ipw2200_load_fw(): firmware(%u) load failed!", size));
		goto fail1;
	}

	for (i = 0; i <= cnt; i++)
		ipw2200_dma_region_free(&dr[i]);

	return (DDI_SUCCESS);

fail1:
	IPW2200_WARN((sc->sc_dip, CE_WARN,
	    "ipw2200_load_fw(): DMA allocation failed, cnt=%d\n", cnt));
	for (i = 0; i <= cnt; i++)
		ipw2200_dma_region_free(&dr[i]);
fail0:
	return (DDI_FAILURE);
}
