/*-
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/pciio.h>
#include <sys/ioctl.h>

#include <sys/pci.h>
#include <sys/pci_tools.h>
#include <libdevinfo.h>

#include <dev/io/iodev.h>
#include <dev/pci/pcireg.h>

#include <machine/iodev.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sysexits.h>
#include <unistd.h>

#include <machine/vmm.h>
#include <vmmapi.h>
#include "pci_emul.h"
#include "mem.h"

#ifdef __FreeBSD__
#ifndef _PATH_DEVPCI
#define	_PATH_DEVPCI	"/dev/pci"
#endif

#ifndef	_PATH_DEVIO
#define	_PATH_DEVIO	"/dev/io"
#endif
#endif

#ifndef _PATH_MEM
#define	_PATH_MEM	"/dev/mem"
#endif

#define	LEGACY_SUPPORT	1

#define MSIX_TABLE_COUNT(ctrl) (((ctrl) & PCIM_MSIXCTRL_TABLE_SIZE) + 1)
#define MSIX_CAPLEN 12

#ifdef __FreeBSD__
static int pcifd = -1;
static int iofd = -1;
#endif
static int memfd = -1;

struct passthru_softc {
	struct pci_devinst *psc_pi;
	struct pcibar psc_bar[PCI_BARMAX + 1];
	struct {
		int		capoff;
		int		msgctrl;
		int		emulated;
	} psc_msi;
	struct {
		int		capoff;
	} psc_msix;
	struct pcisel psc_sel;
	di_node_t devnode;
	int nexfd;
	int msi_limit;
	int msix_limit;
};

static int
msi_caplen(int msgctrl)
{
	int len;
	
	len = 10;		/* minimum length of msi capability */

	if (msgctrl & PCIM_MSICTRL_64BIT)
		len += 4;

#if 0
	/*
	 * Ignore the 'mask' and 'pending' bits in the MSI capability.
	 * We'll let the guest manipulate them directly.
	 */
	if (msgctrl & PCIM_MSICTRL_VECTOR)
		len += 10;
#endif

	return (len);
}

static uint32_t
pcitool_reg_rw(const struct passthru_softc *sc, int bar, uint64_t reg, int width,
    uint64_t data, int req)
{
	struct pcitool_reg pr = { 0 };

	pr.user_version = PCITOOL_VERSION;
	pr.acc_attr = PCITOOL_ACC_ATTR_ENDN_LTL;
	pr.barnum = bar;
	pr.bus_no = sc->psc_sel.pc_bus;
	pr.dev_no = sc->psc_sel.pc_dev;
	pr.func_no = sc->psc_sel.pc_func;
	pr.offset = reg;
	pr.data = data;

	switch (width) {
	case 1:
		pr.acc_attr += PCITOOL_ACC_ATTR_SIZE_1;
		break;
	case 2:
		pr.acc_attr += PCITOOL_ACC_ATTR_SIZE_2;
		break;
	case 4:
		pr.acc_attr += PCITOOL_ACC_ATTR_SIZE_4;
		break;
	case 8:
		pr.acc_attr += PCITOOL_ACC_ATTR_SIZE_8;
		break;
	default:
		return (0);
	}

	if (ioctl(sc->nexfd, req, &pr) != 0)
		return (0);
	else
		return (pr.data);
}

static uint32_t
read_config(const struct passthru_softc *sc, long reg, int width)
{
#ifdef __FreeBSD__
	struct pci_io pi;

	bzero(&pi, sizeof(pi));
	pi.pi_sel = sc->sel;
	pi.pi_reg = reg;
	pi.pi_width = width;

	if (ioctl(pcifd, PCIOCREAD, &pi) < 0)
		return (0);				/* XXX */
	else
		return (pi.pi_data);
#else
	return (pcitool_reg_rw(sc, PCITOOL_CONFIG, reg, width, 0,
	    PCITOOL_DEVICE_GET_REG));
#endif
}

static void
write_config(const struct passthru_softc *sc, long reg, int width, uint32_t data)
{
#ifdef __FreeBSD__
	struct pci_io pi;

	bzero(&pi, sizeof(pi));
	pi.pi_sel = sc->sel;
	pi.pi_reg = reg;
	pi.pi_width = width;
	pi.pi_data = data;

	(void)ioctl(pcifd, PCIOCWRITE, &pi);		/* XXX */
#else
	(void) pcitool_reg_rw(sc, PCITOOL_CONFIG, reg, width, data,
	    PCITOOL_DEVICE_SET_REG);
#endif
}

#ifdef LEGACY_SUPPORT
static int
passthru_add_msicap(struct pci_devinst *pi, int msgnum, int nextptr)
{
	int capoff, i;
	struct msicap msicap;
	u_char *capdata;

	pci_populate_msicap(&msicap, msgnum, nextptr);

	/*
	 * XXX
	 * Copy the msi capability structure in the last 16 bytes of the
	 * config space. This is wrong because it could shadow something
	 * useful to the device.
	 */
	capoff = 256 - roundup(sizeof(msicap), 4);
	capdata = (u_char *)&msicap;
	for (i = 0; i < sizeof(msicap); i++)
		pci_set_cfgdata8(pi, capoff + i, capdata[i]);

	return (capoff);
}
#endif	/* LEGACY_SUPPORT */

static int
cfginitmsi(struct passthru_softc *sc)
{
	int i, ptr, capptr, cap, sts, caplen, table_size, mmc;
	uint32_t u32;
	struct pcisel sel;
	struct pci_devinst *pi;
	struct msixcap msixcap;
	uint32_t *msixcap_ptr;
	int msi_limit;

	pi = sc->psc_pi;
	sel = sc->psc_sel;

	/*
	 * Parse the capabilities and cache the location of the MSI
	 * and MSI-X capabilities.
	 */
	sts = read_config(sc, PCIR_STATUS, 2);
	if (sts & PCIM_STATUS_CAPPRESENT) {
		ptr = read_config(sc, PCIR_CAP_PTR, 1);
		while (ptr != 0 && ptr != 0xff) {
			cap = read_config(sc, ptr + PCICAP_ID, 1);
			if (cap == PCIY_MSI) {
				/*
				 * Copy the MSI capability into the config
				 * space of the emulated pci device
				 */
				sc->psc_msi.capoff = ptr;
				sc->psc_msi.msgctrl = read_config(sc,
								  ptr + 2, 2);
				sc->psc_msi.emulated = 0;
				caplen = msi_caplen(sc->psc_msi.msgctrl);
				capptr = ptr;
				while (caplen > 0) {
					u32 = read_config(sc, capptr, 4);
					pci_set_cfgdata32(pi, capptr, u32);
					caplen -= 4;
					capptr += 4;
				}

				/*
				 * Reduce the number of MSI vectors if higher
				 * than the limit imposed by the OS.
				 */
				msi_limit =
				    sc->msi_limit > 16 ? PCIM_MSICTRL_MMC_32 :
				    sc->msi_limit > 8 ? PCIM_MSICTRL_MMC_16 :
				    sc->msi_limit > 4 ? PCIM_MSICTRL_MMC_8 :
				    sc->msi_limit > 2 ? PCIM_MSICTRL_MMC_4 :
				    sc->msi_limit > 1 ? PCIM_MSICTRL_MMC_2 :
				    PCIM_MSICTRL_MMC_1;

				mmc = sc->psc_msi.msgctrl &
				    PCIM_MSICTRL_MMC_MASK;
				if (sc->msi_limit != -1 && mmc > msi_limit) {
					sc->psc_msi.msgctrl &=
					    ~PCIM_MSICTRL_MMC_MASK;
					sc->psc_msi.msgctrl |= msi_limit;
					pci_set_cfgdata16(pi, ptr + 2,
					    sc->psc_msi.msgctrl);
				}
			} else if (cap == PCIY_MSIX) {
				/*
				 * Copy the MSI-X capability 
				 */
				sc->psc_msix.capoff = ptr;
				caplen = 12;
				msixcap_ptr = (uint32_t*) &msixcap;
				capptr = ptr;
				while (caplen > 0) {
					u32 = read_config(sc, capptr, 4);
					*msixcap_ptr = u32;
					pci_set_cfgdata32(pi, capptr, u32);
					caplen -= 4;
					capptr += 4;
					msixcap_ptr++;
				}

				/*
				 * Reduce the number of MSI vectors if higher
				 * than the limit imposed by the OS.
				 */
				if (sc->msix_limit != -1 &&
				    MSIX_TABLE_COUNT(msixcap.msgctrl) >
				    sc->msix_limit) {
					msixcap.msgctrl &=
					    ~PCIM_MSIXCTRL_TABLE_SIZE;
					msixcap.msgctrl |= sc->msix_limit - 1;
					pci_set_cfgdata16(pi, ptr + 2,
					    msixcap.msgctrl);
				}
			}
			ptr = read_config(sc, ptr + PCICAP_NEXTPTR, 1);
		}
	}

	if (sc->psc_msix.capoff != 0) {
		pi->pi_msix.pba_bar =
		    msixcap.pba_info & PCIM_MSIX_BIR_MASK;
		pi->pi_msix.pba_offset =
		    msixcap.pba_info & ~PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_bar =
		    msixcap.table_info & PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_offset =
		    msixcap.table_info & ~PCIM_MSIX_BIR_MASK;
		pi->pi_msix.table_count = MSIX_TABLE_COUNT(msixcap.msgctrl);
		pi->pi_msix.pba_size = PBA_SIZE(pi->pi_msix.table_count);

		/* Allocate the emulated MSI-X table array */
		table_size = pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
		pi->pi_msix.table = calloc(1, table_size);

		/* Mask all table entries */
		for (i = 0; i < pi->pi_msix.table_count; i++) {
			pi->pi_msix.table[i].vector_control |=
						PCIM_MSIX_VCTRL_MASK;
		}
	}

#ifdef LEGACY_SUPPORT
	/*
	 * If the passthrough device does not support MSI then craft a
	 * MSI capability for it. We link the new MSI capability at the
	 * head of the list of capabilities.
	 */
	if ((sts & PCIM_STATUS_CAPPRESENT) != 0 && sc->psc_msi.capoff == 0) {
		int origptr, msiptr;
		origptr = read_config(sc, PCIR_CAP_PTR, 1);
		msiptr = passthru_add_msicap(pi, 1, origptr);
		sc->psc_msi.capoff = msiptr;
		sc->psc_msi.msgctrl = pci_get_cfgdata16(pi, msiptr + 2);
		sc->psc_msi.emulated = 1;
		pci_set_cfgdata8(pi, PCIR_CAP_PTR, msiptr);
	}
#endif

	/* Make sure one of the capabilities is present */
	if (sc->psc_msi.capoff == 0 && sc->psc_msix.capoff == 0) 
		return (-1);
	else
		return (0);
}

static uint64_t
msix_table_read(struct passthru_softc *sc, uint64_t offset, int size)
{
	struct pci_devinst *pi;
	struct msix_table_entry *entry;
	uint8_t *src8;
	uint16_t *src16;
	uint32_t *src32;
	uint64_t *src64;
	uint64_t data;
	size_t entry_offset;
	int index;

	pi = sc->psc_pi;
	if (offset >= pi->pi_msix.pba_offset &&
	    offset < pi->pi_msix.pba_offset + pi->pi_msix.pba_size) {
		switch(size) {
		case 1:
			src8 = (uint8_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src8;
			break;
		case 2:
			src16 = (uint16_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src16;
			break;
		case 4:
			src32 = (uint32_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src32;
			break;
		case 8:
			src64 = (uint64_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			data = *src64;
			break;
		default:
			return (-1);
		}
		return (data);
	}

	if (offset < pi->pi_msix.table_offset)
		return (-1);

	offset -= pi->pi_msix.table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	if (index >= pi->pi_msix.table_count)
		return (-1);

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	switch(size) {
	case 1:
		src8 = (uint8_t *)((void *)entry + entry_offset);
		data = *src8;
		break;
	case 2:
		src16 = (uint16_t *)((void *)entry + entry_offset);
		data = *src16;
		break;
	case 4:
		src32 = (uint32_t *)((void *)entry + entry_offset);
		data = *src32;
		break;
	case 8:
		src64 = (uint64_t *)((void *)entry + entry_offset);
		data = *src64;
		break;
	default:
		return (-1);
	}

	return (data);
}

static void
msix_table_write(struct vmctx *ctx, int vcpu, struct passthru_softc *sc,
		 uint64_t offset, int size, uint64_t data)
{
	struct pci_devinst *pi;
	struct msix_table_entry *entry;
	uint8_t *dest8;
	uint16_t *dest16;
	uint32_t *dest32;
	uint64_t *dest64;
	size_t entry_offset;
	uint32_t vector_control;
	int index;

	pi = sc->psc_pi;
	if (offset >= pi->pi_msix.pba_offset &&
	    offset < pi->pi_msix.pba_offset + pi->pi_msix.pba_size) {
		switch(size) {
		case 1:
			dest8 = (uint8_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest8 = data;
			break;
		case 2:
			dest16 = (uint16_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest16 = data;
			break;
		case 4:
			dest32 = (uint32_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest32 = data;
			break;
		case 8:
			dest64 = (uint64_t *)(pi->pi_msix.pba_page + offset -
			    pi->pi_msix.pba_page_offset);
			*dest64 = data;
			break;
		default:
			break;
		}
		return;
	}

	if (offset < pi->pi_msix.table_offset)
		return;

	offset -= pi->pi_msix.table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	if (index >= pi->pi_msix.table_count)
		return;

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	/* Only 4 byte naturally-aligned writes are supported */
	assert(size == 4);
	assert(entry_offset % 4 == 0);

	vector_control = entry->vector_control;
	dest32 = (uint32_t *)((void *)entry + entry_offset);
	*dest32 = data;
	/* If MSI-X hasn't been enabled, do nothing */
	if (pi->pi_msix.enabled) {
		/* If the entry is masked, don't set it up */
		if ((entry->vector_control & PCIM_MSIX_VCTRL_MASK) == 0 ||
		    (vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
			(void)vm_setup_pptdev_msix(ctx, vcpu,
			    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
			    sc->psc_sel.pc_func, index, entry->addr,
			    entry->msg_data, entry->vector_control);
		}
	}
}

static int
init_msix_table(struct vmctx *ctx, struct passthru_softc *sc, uint64_t base)
{
	int b, s, f;
	int error, idx;
	size_t len, remaining;
	uint32_t table_size, table_offset;
	uint32_t pba_size, pba_offset;
	vm_paddr_t start;
	struct pci_devinst *pi = sc->psc_pi;

	assert(pci_msix_table_bar(pi) >= 0 && pci_msix_pba_bar(pi) >= 0);

	b = sc->psc_sel.pc_bus;
	s = sc->psc_sel.pc_dev;
	f = sc->psc_sel.pc_func;

	/* 
	 * If the MSI-X table BAR maps memory intended for
	 * other uses, it is at least assured that the table 
	 * either resides in its own page within the region, 
	 * or it resides in a page shared with only the PBA.
	 */
	table_offset = rounddown2(pi->pi_msix.table_offset, 4096);

	table_size = pi->pi_msix.table_offset - table_offset;
	table_size += pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
	table_size = roundup2(table_size, 4096);

	idx = pi->pi_msix.table_bar;
	start = pi->pi_bar[idx].addr;
	remaining = pi->pi_bar[idx].size;

	if (pi->pi_msix.pba_bar == pi->pi_msix.table_bar) {
		pba_offset = pi->pi_msix.pba_offset;
		pba_size = pi->pi_msix.pba_size;
		if (pba_offset >= table_offset + table_size ||
		    table_offset >= pba_offset + pba_size) {
			/*
			 * If the PBA does not share a page with the MSI-x
			 * tables, no PBA emulation is required.
			 */
			pi->pi_msix.pba_page = NULL;
			pi->pi_msix.pba_page_offset = 0;
		} else {
			/*
			 * The PBA overlaps with either the first or last
			 * page of the MSI-X table region.  Map the
			 * appropriate page.
			 */
			if (pba_offset <= table_offset)
				pi->pi_msix.pba_page_offset = table_offset;
			else
				pi->pi_msix.pba_page_offset = table_offset +
				    table_size - 4096;
			pi->pi_msix.pba_page = mmap(NULL, 4096, PROT_READ |
			    PROT_WRITE, MAP_SHARED, memfd, start +
			    pi->pi_msix.pba_page_offset);
			if (pi->pi_msix.pba_page == MAP_FAILED) {
				warn(
			    "Failed to map PBA page for MSI-X on %d/%d/%d",
				    b, s, f);
				return (-1);
			}
		}
	}

	/* Map everything before the MSI-X table */
	if (table_offset > 0) {
		len = table_offset;
		error = vm_map_pptdev_mmio(ctx, b, s, f, start, len, base);
		if (error)
			return (error);

		base += len;
		start += len;
		remaining -= len;
	}

	/* Skip the MSI-X table */
	base += table_size;
	start += table_size;
	remaining -= table_size;

	/* Map everything beyond the end of the MSI-X table */
	if (remaining > 0) {
		len = remaining;
		error = vm_map_pptdev_mmio(ctx, b, s, f, start, len, base);
		if (error)
			return (error);
	}

	return (0);
}

static int
devinfo_getbar(di_node_t node, int bar, enum pcibar_type *type, uint64_t *base,
    uint64_t *size)
{
	int len, i;
	int *regbuf;
	int num;

	len = di_prop_lookup_ints(DDI_DEV_T_ANY, node,
	    "assigned-addresses", &regbuf);

	for (i = 0; i < len;
	     i += sizeof (pci_regspec_t) / sizeof (uint_t)) {
		pci_regspec_t *reg = (pci_regspec_t *)&regbuf[i];

		if (PCI_REG_REG_G(reg->pci_phys_hi) < PCI_CONF_BASE0 ||
		    PCI_REG_REG_G(reg->pci_phys_hi) > PCI_CONF_BASE5)
			continue;
		num = (PCI_REG_REG_G(reg->pci_phys_hi) - PCI_CONF_BASE0) >> 2;
		if (num != bar)
			continue;

		*base = ((uint64_t)reg->pci_phys_mid << 32) | reg->pci_phys_low;
		*size = ((uint64_t)reg->pci_size_hi << 32) | reg->pci_size_low;
		switch (reg->pci_phys_hi & PCI_REG_ADDR_M) {
		case PCI_ADDR_IO:
			*type = PCIBAR_IO;
			break;
		case PCI_ADDR_MEM32:
			*type = PCIBAR_MEM32;
			break;
		case PCI_ADDR_MEM64:
			*type = PCIBAR_MEM64;
			break;
		}

		return (0);
	}

	return (-1);
}

static int
cfginitbar(struct vmctx *ctx, struct passthru_softc *sc)
{
	int i, error;
	struct pci_devinst *pi;
#ifdef __FreeBSD__
	struct pci_bar_io bar;
#endif
	enum pcibar_type bartype;
	uint64_t base, size;

	pi = sc->psc_pi;

	/*
	 * Initialize BAR registers
	 */
	for (i = 0; i <= PCI_BARMAX; i++) {
#ifdef __FreeBSD__
		bzero(&bar, sizeof(bar));
		bar.pbi_sel = sc->psc_sel;
		bar.pbi_reg = PCIR_BAR(i);

		if (ioctl(pcifd, PCIOCGETBAR, &bar) < 0)
			continue;

		if (PCI_BAR_IO(bar.pbi_base)) {
			bartype = PCIBAR_IO;
			base = bar.pbi_base & PCIM_BAR_IO_BASE;
		} else {
			switch (bar.pbi_base & PCIM_BAR_MEM_TYPE) {
			case PCIM_BAR_MEM_64:
				bartype = PCIBAR_MEM64;
				break;
			default:
				bartype = PCIBAR_MEM32;
				break;
			}
			base = bar.pbi_base & PCIM_BAR_MEM_BASE;
		}
		size = bar.pbi_length;
#else
		if (devinfo_getbar(sc->devnode, i, &bartype, &base, &size) != 0)
			continue;
#endif

		if (bartype != PCIBAR_IO) {
			if (((base | size) & PAGE_MASK) != 0) {
				warnx("passthru device %d/%d/%d BAR %d: "
				    "base %#lx or size %#lx not page aligned\n",
				    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev,
				    sc->psc_sel.pc_func, i, base, size);
				return (-1);
			}
		}

		/* Cache information about the "real" BAR */
		sc->psc_bar[i].type = bartype;
		sc->psc_bar[i].size = size;
		sc->psc_bar[i].addr = base;

		/* Allocate the BAR in the guest I/O or MMIO space */
		error = pci_emul_alloc_pbar(pi, i, base, bartype, size);
		if (error)
			return (-1);

		/* The MSI-X table needs special handling */
		if (i == pci_msix_table_bar(pi)) {
			error = init_msix_table(ctx, sc, base);
			if (error) 
				return (-1);
		} else if (bartype != PCIBAR_IO) {
			/* Map the physical BAR in the guest MMIO space */
			error = vm_map_pptdev_mmio(ctx, sc->psc_sel.pc_bus,
				sc->psc_sel.pc_dev, sc->psc_sel.pc_func,
				pi->pi_bar[i].addr, pi->pi_bar[i].size, base);
			if (error)
				return (-1);
		}

		/*
		 * 64-bit BAR takes up two slots so skip the next one.
		 */
		if (bartype == PCIBAR_MEM64) {
			i++;
			assert(i <= PCI_BARMAX);
			sc->psc_bar[i].type = PCIBAR_MEMHI64;
		}
	}
	return (0);
}

static int
cfginit(struct vmctx *ctx, struct pci_devinst *pi, int bus, int slot, int func)
{
	int error;
	struct passthru_softc *sc;

	error = 1;
	sc = pi->pi_arg;

	bzero(&sc->psc_sel, sizeof(struct pcisel));
	sc->psc_sel.pc_bus = bus;
	sc->psc_sel.pc_dev = slot;
	sc->psc_sel.pc_func = func;

	if (cfginitmsi(sc) != 0) {
		warnx("failed to initialize MSI for PCI %d/%d/%d",
		    bus, slot, func);
		goto done;
	}

	if (cfginitbar(ctx, sc) != 0) {
		warnx("failed to initialize BARs for PCI %d/%d/%d",
		    bus, slot, func);
		goto done;
	}

	error = 0;				/* success */
done:
	return (error);
}

static int
devinfo_open(char *path, di_node_t *devnode, int *bus, int *slot, int *func)
{
	di_node_t rootnode, nexnode, node;
	char *devfspath, *tmp;
	int nexfd;
	int len, *regbuf;
	pci_regspec_t *reg;

	nexnode = rootnode = di_init("/", DINFOCPYALL);

	if (rootnode == DI_NODE_NIL)
		return (-1);

	for (*devnode = di_drv_first_node("ppt", rootnode);
	     *devnode != DI_NODE_NIL;
	     *devnode = di_drv_next_node(*devnode)) {
		devfspath = di_devfs_path(*devnode);
		if (strcmp(devfspath, path) == 0) {
			/*
			 * Walk up device path. Last node before the root node
			 * is the nexus node.
			 */
			node = di_parent_node(*devnode);
			while (node != rootnode) {
				nexnode = node;
				node = di_parent_node(node);
			}

			di_devfs_path_free(devfspath);
			break;
		}
		di_devfs_path_free(devfspath);
	}

	if (*devnode == DI_NODE_NIL || nexnode == rootnode)
		return (-1);

	devfspath = di_devfs_path(nexnode);
	(void) asprintf(&tmp, "/devices%s:reg", devfspath);
	nexfd = open(tmp, O_RDWR);
	free(tmp);
	di_devfs_path_free(devfspath);

	len = di_prop_lookup_ints(DDI_DEV_T_ANY, *devnode, "reg", &regbuf);
	reg = (pci_regspec_t *)regbuf;

	*bus = (uchar_t)PCI_REG_BUS_G(reg->pci_phys_hi);
	*slot = (uchar_t)PCI_REG_DEV_G(reg->pci_phys_hi);
	*func = (uchar_t)PCI_REG_FUNC_G(reg->pci_phys_hi);

	return (nexfd);
}

static int
passthru_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	int bus, slot, func, error, memflags;
	struct passthru_softc *sc;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t pci_ioctls[] = { PCIOCREAD, PCIOCWRITE, PCIOCGETBAR };
	cap_ioctl_t io_ioctls[] = { IODEV_PIO };
#endif
	di_node_t devnode;
	int nexfd;

	sc = NULL;
	error = 1;

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_IOCTL, CAP_READ, CAP_WRITE);
#endif

	memflags = vm_get_memflags(ctx);
	if (!(memflags & VM_MEM_F_WIRED)) {
		warnx("passthru requires guest memory to be wired");
		goto done;
	}

#ifdef __FreeBSD__
	if (pcifd < 0) {
		pcifd = open(_PATH_DEVPCI, O_RDWR, 0);
		if (pcifd < 0) {
			warn("failed to open %s", _PATH_DEVPCI);
			goto done;
		}
	}
#endif

#ifndef WITHOUT_CAPSICUM
	if (cap_rights_limit(pcifd, &rights) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (cap_ioctls_limit(pcifd, pci_ioctls, nitems(pci_ioctls)) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

#ifdef __FreeBSD__
	if (iofd < 0) {
		iofd = open(_PATH_DEVIO, O_RDWR, 0);
		if (iofd < 0) {
			warn("failed to open %s", _PATH_DEVIO);
			goto done;
		}
	}
#endif

#ifndef WITHOUT_CAPSICUM
	if (cap_rights_limit(iofd, &rights) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (cap_ioctls_limit(iofd, io_ioctls, nitems(io_ioctls)) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	if (memfd < 0) {
		memfd = open(_PATH_MEM, O_RDWR, 0);
		if (memfd < 0) {
			warn("failed to open %s", _PATH_MEM);
			goto done;
		}
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_clear(&rights, CAP_IOCTL);
	cap_rights_set(&rights, CAP_MMAP_RW);
	if (cap_rights_limit(memfd, &rights) == -1 && errno != ENOSYS)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

#ifdef __FreeBSD__
	if (opts == NULL ||
	    sscanf(opts, "%d/%d/%d", &bus, &slot, &func) != 3) {
		warnx("invalid passthru options");
		goto done;
	}
#else
	if (opts == NULL ||
	    (nexfd = devinfo_open(opts, &devnode, &bus, &slot, &func)) == -1) {
		warnx("invalid passthru options");
		goto done;
	}
#endif

	if (vm_assign_pptdev(ctx, bus, slot, func) != 0) {
		warnx("PCI device at %d/%d/%d is not using the ppt(4) driver",
		    bus, slot, func);
		goto done;
	}

	sc = calloc(1, sizeof(struct passthru_softc));

	pi->pi_arg = sc;
	sc->psc_pi = pi;
	sc->devnode = devnode;
	sc->nexfd = nexfd;

	if ((error = vm_get_pptdev_limits(ctx, bus, slot, func, &sc->msi_limit,
	    &sc->msix_limit)) != 0)
		goto done;

	/* initialize config space */
	if ((error = cfginit(ctx, pi, bus, slot, func)) != 0)
		goto done;
	
	error = 0;		/* success */
done:
	if (error) {
		free(sc);
		vm_unassign_pptdev(ctx, bus, slot, func);
	}
	return (error);
}

static int
bar_access(int coff)
{
	if (coff >= PCIR_BAR(0) && coff < PCIR_BAR(PCI_BARMAX + 1))
		return (1);
	else
		return (0);
}

static int
msicap_access(struct passthru_softc *sc, int coff)
{
	int caplen;

	if (sc->psc_msi.capoff == 0)
		return (0);

	caplen = msi_caplen(sc->psc_msi.msgctrl);

	if (coff >= sc->psc_msi.capoff && coff < sc->psc_msi.capoff + caplen)
		return (1);
	else
		return (0);
}

static int 
msixcap_access(struct passthru_softc *sc, int coff)
{
	if (sc->psc_msix.capoff == 0) 
		return (0);

	return (coff >= sc->psc_msix.capoff && 
	        coff < sc->psc_msix.capoff + MSIX_CAPLEN);
}

static int
passthru_cfgread(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
		 int coff, int bytes, uint32_t *rv)
{
	struct passthru_softc *sc;

	sc = pi->pi_arg;

	/*
	 * PCI BARs and MSI capability is emulated.
	 */
	if (bar_access(coff) || msicap_access(sc, coff))
		return (-1);

#ifdef LEGACY_SUPPORT
	/*
	 * Emulate PCIR_CAP_PTR if this device does not support MSI capability
	 * natively.
	 */
	if (sc->psc_msi.emulated) {
		if (coff >= PCIR_CAP_PTR && coff < PCIR_CAP_PTR + 4)
			return (-1);
	}
#endif

	/* Everything else just read from the device's config space */
	*rv = read_config(sc, coff, bytes);

	return (0);
}

static int
passthru_cfgwrite(struct vmctx *ctx, int vcpu, struct pci_devinst *pi,
		  int coff, int bytes, uint32_t val)
{
	int error, msix_table_entries, i;
	struct passthru_softc *sc;

	sc = pi->pi_arg;

	/*
	 * PCI BARs are emulated
	 */
	if (bar_access(coff))
		return (-1);

	/*
	 * MSI capability is emulated
	 */
	if (msicap_access(sc, coff)) {
		msicap_cfgwrite(pi, sc->psc_msi.capoff, coff, bytes, val);

		error = vm_setup_pptdev_msi(ctx, vcpu, sc->psc_sel.pc_bus,
			sc->psc_sel.pc_dev, sc->psc_sel.pc_func,
			pi->pi_msi.addr, pi->pi_msi.msg_data,
			pi->pi_msi.maxmsgnum);
		if (error != 0)
			err(1, "vm_setup_pptdev_msi");
		return (0);
	}

	if (msixcap_access(sc, coff)) {
		msixcap_cfgwrite(pi, sc->psc_msix.capoff, coff, bytes, val);
		if (pi->pi_msix.enabled) {
			msix_table_entries = pi->pi_msix.table_count;
			for (i = 0; i < msix_table_entries; i++) {
				error = vm_setup_pptdev_msix(ctx, vcpu,
				    sc->psc_sel.pc_bus, sc->psc_sel.pc_dev, 
				    sc->psc_sel.pc_func, i, 
				    pi->pi_msix.table[i].addr,
				    pi->pi_msix.table[i].msg_data,
				    pi->pi_msix.table[i].vector_control);
		
				if (error)
					err(1, "vm_setup_pptdev_msix");
			}
		}
		return (0);
	}

#ifdef LEGACY_SUPPORT
	/*
	 * If this device does not support MSI natively then we cannot let
	 * the guest disable legacy interrupts from the device. It is the
	 * legacy interrupt that is triggering the virtual MSI to the guest.
	 */
	if (sc->psc_msi.emulated && pci_msi_enabled(pi)) {
		if (coff == PCIR_COMMAND && bytes == 2)
			val &= ~PCIM_CMD_INTxDIS;
	}
#endif

	write_config(sc, coff, bytes, val);

	return (0);
}

static void
passthru_write(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int baridx,
	       uint64_t offset, int size, uint64_t value)
{
	struct passthru_softc *sc;
#ifdef __FreeBSD__
	struct iodev_pio_req pio;
#endif

	sc = pi->pi_arg;

	if (baridx == pci_msix_table_bar(pi)) {
		msix_table_write(ctx, vcpu, sc, offset, size, value);
	} else {
		assert(pi->pi_bar[baridx].type == PCIBAR_IO);
#ifdef __FreeBSD__
		bzero(&pio, sizeof(struct iodev_pio_req));
		pio.access = IODEV_PIO_WRITE;
		pio.port = sc->psc_bar[baridx].addr + offset;
		pio.width = size;
		pio.val = value;
		
		(void)ioctl(iofd, IODEV_PIO, &pio);
#else
		(void) pcitool_reg_rw(sc, baridx, offset, size, value,
		    PCITOOL_DEVICE_SET_REG);
#endif
	}
}

static uint64_t
passthru_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int baridx,
	      uint64_t offset, int size)
{
	struct passthru_softc *sc;
#ifdef __FreeBSD__
	struct iodev_pio_req pio;
#endif
	uint64_t val;

	sc = pi->pi_arg;

	if (baridx == pci_msix_table_bar(pi)) {
		val = msix_table_read(sc, offset, size);
	} else {
		assert(pi->pi_bar[baridx].type == PCIBAR_IO);
#ifdef __FreeBSD__
		bzero(&pio, sizeof(struct iodev_pio_req));
		pio.access = IODEV_PIO_READ;
		pio.port = sc->psc_bar[baridx].addr + offset;
		pio.width = size;
		pio.val = 0;

		(void)ioctl(iofd, IODEV_PIO, &pio);

		val = pio.val;
#else
		val = pcitool_reg_rw(sc, baridx, offset, size, 0,
		    PCITOOL_DEVICE_GET_REG);
#endif
	}

	return (val);
}

struct pci_devemu passthru = {
	.pe_emu		= "passthru",
	.pe_init	= passthru_init,
	.pe_cfgwrite	= passthru_cfgwrite,
	.pe_cfgread	= passthru_cfgread,
	.pe_barwrite 	= passthru_write,
	.pe_barread    	= passthru_read,
};
PCI_EMUL_SET(passthru);
