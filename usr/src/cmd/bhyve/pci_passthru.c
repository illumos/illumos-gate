/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
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
#include <sys/ppt_dev.h>
#include "pci_emul.h"
#include "mem.h"

#ifndef _PATH_MEM
#define	_PATH_MEM	"/dev/mem"
#endif

#define	LEGACY_SUPPORT	1

#define MSIX_TABLE_COUNT(ctrl) (((ctrl) & PCIM_MSIXCTRL_TABLE_SIZE) + 1)
#define MSIX_CAPLEN 12

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
	int pptfd;
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
read_config(const struct passthru_softc *sc, long reg, int width)
{
	struct ppt_cfg_io pi;

	pi.pci_off = reg;
	pi.pci_width = width;

	if (ioctl(sc->pptfd, PPT_CFG_READ, &pi) != 0) {
		return (0);
	}
	return (pi.pci_data);
}

static void
write_config(const struct passthru_softc *sc, long reg, int width,
    uint32_t data)
{
	struct ppt_cfg_io pi;

	pi.pci_off = reg;
	pi.pci_width = width;
	pi.pci_data = data;

	(void) ioctl(sc->pptfd, PPT_CFG_WRITE, &pi);
}

static int
passthru_get_bar(struct passthru_softc *sc, int bar, enum pcibar_type *type,
    uint64_t *base, uint64_t *size)
{
	struct ppt_bar_query pb;

	pb.pbq_baridx = bar;

	if (ioctl(sc->pptfd, PPT_BAR_QUERY, &pb) != 0) {
		return (-1);
	}

	switch (pb.pbq_type) {
	case PCI_ADDR_IO:
		*type = PCIBAR_IO;
		break;
	case PCI_ADDR_MEM32:
		*type = PCIBAR_MEM32;
		break;
	case PCI_ADDR_MEM64:
		*type = PCIBAR_MEM64;
		break;
	default:
		err(1, "unrecognized BAR type: %u\n", pb.pbq_type);
		break;
	}

	*base = pb.pbq_base;
	*size = pb.pbq_size;
	return (0);
}

static int
passthru_dev_open(const char *path, int *pptfdp)
{
	int pptfd;

	if ((pptfd = open(path, O_RDWR)) < 0) {
		return (errno);
	}

	/* XXX: verify fd with ioctl? */
	*pptfdp = pptfd;
	return (0);
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

static void
passthru_intr_limit(struct passthru_softc *sc, struct msixcap *msixcap)
{
	struct pci_devinst *pi = sc->psc_pi;
	int off;

	/* Reduce the number of MSI vectors if higher than OS limit */
	if ((off = sc->psc_msi.capoff) != 0 && sc->msi_limit != -1) {
		int msi_limit, mmc;

		msi_limit =
		    sc->msi_limit > 16 ? PCIM_MSICTRL_MMC_32 :
		    sc->msi_limit > 8 ? PCIM_MSICTRL_MMC_16 :
		    sc->msi_limit > 4 ? PCIM_MSICTRL_MMC_8 :
		    sc->msi_limit > 2 ? PCIM_MSICTRL_MMC_4 :
		    sc->msi_limit > 1 ? PCIM_MSICTRL_MMC_2 :
		    PCIM_MSICTRL_MMC_1;
		mmc = sc->psc_msi.msgctrl & PCIM_MSICTRL_MMC_MASK;

		if (mmc > msi_limit) {
			sc->psc_msi.msgctrl &= ~PCIM_MSICTRL_MMC_MASK;
			sc->psc_msi.msgctrl |= msi_limit;
			pci_set_cfgdata16(pi, off + 2, sc->psc_msi.msgctrl);
		}
	}

	/* Reduce the number of MSI-X vectors if higher than OS limit */
	if ((off = sc->psc_msix.capoff) != 0 && sc->msix_limit != -1) {
		if (MSIX_TABLE_COUNT(msixcap->msgctrl) > sc->msix_limit) {
			msixcap->msgctrl &= ~PCIM_MSIXCTRL_TABLE_SIZE;
			msixcap->msgctrl |= sc->msix_limit - 1;
			pci_set_cfgdata16(pi, off + 2, msixcap->msgctrl);
		}
	}
}

static int
cfginitmsi(struct passthru_softc *sc)
{
	int i, ptr, capptr, cap, sts, caplen, table_size;
	uint32_t u32;
	struct pci_devinst *pi = sc->psc_pi;
	struct msixcap msixcap;
	uint32_t *msixcap_ptr;

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
			}
			ptr = read_config(sc, ptr + PCICAP_NEXTPTR, 1);
		}
	}

	passthru_intr_limit(sc, &msixcap);

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
	if (sc->psc_msi.capoff == 0 && sc->psc_msix.capoff == 0) {
		return (-1);
	} else {
		return (0);
	}
}

static uint64_t
passthru_msix_table_read(struct passthru_softc *sc, uint64_t offset, int size)
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
passthru_msix_table_write(struct vmctx *ctx, int vcpu,
    struct passthru_softc *sc, uint64_t offset, int size, uint64_t data)
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
			(void) vm_setup_pptdev_msix(ctx, vcpu, sc->pptfd,
			    index, entry->addr, entry->msg_data,
			    entry->vector_control);
		}
	}
}

static int
init_msix_table(struct vmctx *ctx, struct passthru_softc *sc, uint64_t base)
{
	int error, idx;
	size_t len, remaining;
	uint32_t table_size, table_offset;
	uint32_t pba_size, pba_offset;
	vm_paddr_t start;
	struct pci_devinst *pi = sc->psc_pi;

	assert(pci_msix_table_bar(pi) >= 0 && pci_msix_pba_bar(pi) >= 0);

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
			int memfd;

			/*
			 * This cannot work in a zone and should be replaced
			 * with a better interface offered by the ppt driver.
			 */
			memfd = open(_PATH_MEM, O_RDWR, 0);
			if (memfd < 0) {
				warn("failed to open %s", _PATH_MEM);
				return (-1);
			}

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
			(void) close(memfd);
			if (pi->pi_msix.pba_page == MAP_FAILED) {
				warn("Failed to map PBA page for MSI-X on %d",
				    sc->pptfd);
				return (-1);
			}
		}
	}

	/* Map everything before the MSI-X table */
	if (table_offset > 0) {
		len = table_offset;
		error = vm_map_pptdev_mmio(ctx, sc->pptfd, start, len, base);
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
		error = vm_map_pptdev_mmio(ctx, sc->pptfd, start, len, base);
		if (error)
			return (error);
	}

	return (0);
}

static int
cfginitbar(struct vmctx *ctx, struct passthru_softc *sc)
{
	struct pci_devinst *pi = sc->psc_pi;
	uint_t i;

	/*
	 * Initialize BAR registers
	 */
	for (i = 0; i <= PCI_BARMAX; i++) {
		enum pcibar_type bartype;
		uint64_t base, size;
		int error;

		if (passthru_get_bar(sc, i, &bartype, &base, &size) != 0) {
			continue;
		}

		if (bartype != PCIBAR_IO) {
			if (((base | size) & PAGE_MASK) != 0) {
				warnx("passthru device %d BAR %d: "
				    "base %#lx or size %#lx not page aligned\n",
				    sc->pptfd, i, base, size);
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
			error = vm_map_pptdev_mmio(ctx, sc->pptfd,
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
cfginit(struct vmctx *ctx, struct passthru_softc *sc)
{
	if (cfginitmsi(sc) != 0) {
		warnx("failed to initialize MSI for PCI %d", sc->pptfd);
		return (-1);
	}

	if (cfginitbar(ctx, sc) != 0) {
		warnx("failed to initialize BARs for PCI %d", sc->pptfd);
		return (-1);
	}

	return (0);
}

static int
passthru_init(struct vmctx *ctx, struct pci_devinst *pi, char *opts)
{
	int error, memflags, pptfd;
	struct passthru_softc *sc;

	sc = NULL;
	error = 1;

	memflags = vm_get_memflags(ctx);
	if (!(memflags & VM_MEM_F_WIRED)) {
		warnx("passthru requires guest memory to be wired");
		goto done;
	}

	if (opts == NULL || passthru_dev_open(opts, &pptfd) != 0) {
		warnx("invalid passthru options");
		goto done;
	}

	if (vm_assign_pptdev(ctx, pptfd) != 0) {
		warnx("PCI device at %d is not using the ppt driver", pptfd);
		goto done;
	}

	sc = calloc(1, sizeof(struct passthru_softc));

	pi->pi_arg = sc;
	sc->psc_pi = pi;
	sc->pptfd = pptfd;

	if ((error = vm_get_pptdev_limits(ctx, pptfd, &sc->msi_limit,
	    &sc->msix_limit)) != 0)
		goto done;

	/* initialize config space */
	if ((error = cfginit(ctx, sc)) != 0)
		goto done;

	error = 0;		/* success */
done:
	if (error) {
		free(sc);
		vm_unassign_pptdev(ctx, pptfd);
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

	/*
	 * MSI-X is also emulated since a limit on interrupts may be imposed by
	 * the OS, altering the perceived register state.
	 */
	if (msixcap_access(sc, coff))
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

		error = vm_setup_pptdev_msi(ctx, vcpu, sc->pptfd,
		    pi->pi_msi.addr, pi->pi_msi.msg_data, pi->pi_msi.maxmsgnum);
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
				    sc->pptfd, i,
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
	struct passthru_softc *sc = pi->pi_arg;

	if (baridx == pci_msix_table_bar(pi)) {
		passthru_msix_table_write(ctx, vcpu, sc, offset, size, value);
	} else {
		struct ppt_bar_io pbi;

		assert(pi->pi_bar[baridx].type == PCIBAR_IO);

		pbi.pbi_bar = baridx;
		pbi.pbi_width = size;
		pbi.pbi_off = offset;
		pbi.pbi_data = value;
		(void) ioctl(sc->pptfd, PPT_BAR_WRITE, &pbi);
	}
}

static uint64_t
passthru_read(struct vmctx *ctx, int vcpu, struct pci_devinst *pi, int baridx,
    uint64_t offset, int size)
{
	struct passthru_softc *sc = pi->pi_arg;
	uint64_t val;

	if (baridx == pci_msix_table_bar(pi)) {
		val = passthru_msix_table_read(sc, offset, size);
	} else {
		struct ppt_bar_io pbi;

		assert(pi->pi_bar[baridx].type == PCIBAR_IO);

		pbi.pbi_bar = baridx;
		pbi.pbi_width = size;
		pbi.pbi_off = offset;
		if (ioctl(sc->pptfd, PPT_BAR_READ, &pbi) == 0) {
			val = pbi.pbi_data;
		} else {
			val = 0;
		}
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
