/*-
 * SPDX-License-Identifier: BSD-2-Clause
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
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/pciio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

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

#include "config.h"
#include "debug.h"
#include "pci_passthru.h"
#include "mem.h"

#define	LEGACY_SUPPORT	1

#define MSIX_TABLE_COUNT(ctrl) (((ctrl) & PCIM_MSIXCTRL_TABLE_SIZE) + 1)
#define MSIX_CAPLEN 12

struct passthru_softc {
	struct pci_devinst *psc_pi;
	/* ROM is handled like a BAR */
	struct pcibar psc_bar[PCI_BARMAX_WITH_ROM + 1];
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

	cfgread_handler psc_pcir_rhandler[PCI_REGMAX + 1];
	cfgwrite_handler psc_pcir_whandler[PCI_REGMAX + 1];
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
passthru_read_config(const struct passthru_softc *sc, long reg, int width)
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
passthru_write_config(const struct passthru_softc *sc, long reg, int width,
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
	int capoff;
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
	for (size_t i = 0; i < sizeof(msicap); i++)
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
	char *msixcap_ptr;

	/*
	 * Parse the capabilities and cache the location of the MSI
	 * and MSI-X capabilities.
	 */
	sts = passthru_read_config(sc, PCIR_STATUS, 2);
	if (sts & PCIM_STATUS_CAPPRESENT) {
		ptr = passthru_read_config(sc, PCIR_CAP_PTR, 1);
		while (ptr != 0 && ptr != 0xff) {
			cap = passthru_read_config(sc, ptr + PCICAP_ID, 1);
			if (cap == PCIY_MSI) {
				/*
				 * Copy the MSI capability into the config
				 * space of the emulated pci device
				 */
				sc->psc_msi.capoff = ptr;
				sc->psc_msi.msgctrl = passthru_read_config(sc,
				    ptr + 2, 2);
				sc->psc_msi.emulated = 0;
				caplen = msi_caplen(sc->psc_msi.msgctrl);
				capptr = ptr;
				while (caplen > 0) {
					u32 = passthru_read_config(sc,
					    capptr, 4);
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
				msixcap_ptr = (char *)&msixcap;
				capptr = ptr;
				while (caplen > 0) {
					u32 = passthru_read_config(sc,
					    capptr, 4);
					memcpy(msixcap_ptr, &u32, 4);
					pci_set_cfgdata32(pi, capptr, u32);
					caplen -= 4;
					capptr += 4;
					msixcap_ptr += 4;
				}
			}
			ptr = passthru_read_config(sc, ptr + PCICAP_NEXTPTR, 1);
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
		origptr = passthru_read_config(sc, PCIR_CAP_PTR, 1);
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
	uint32_t table_offset;
	int index, table_count;

	pi = sc->psc_pi;

	table_offset = pi->pi_msix.table_offset;
	table_count = pi->pi_msix.table_count;
	if (offset < table_offset ||
	    offset >= table_offset + table_count * MSIX_TABLE_ENTRY_SIZE) {
		switch (size) {
		case 1:
			src8 = (uint8_t *)(pi->pi_msix.mapped_addr + offset);
			data = *src8;
			break;
		case 2:
			src16 = (uint16_t *)(pi->pi_msix.mapped_addr + offset);
			data = *src16;
			break;
		case 4:
			src32 = (uint32_t *)(pi->pi_msix.mapped_addr + offset);
			data = *src32;
			break;
		case 8:
			src64 = (uint64_t *)(pi->pi_msix.mapped_addr + offset);
			data = *src64;
			break;
		default:
			return (-1);
		}
		return (data);
	}

	offset -= table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	assert(index < table_count);

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	switch (size) {
	case 1:
		src8 = (uint8_t *)((uint8_t *)entry + entry_offset);
		data = *src8;
		break;
	case 2:
		src16 = (uint16_t *)((uint8_t *)entry + entry_offset);
		data = *src16;
		break;
	case 4:
		src32 = (uint32_t *)((uint8_t *)entry + entry_offset);
		data = *src32;
		break;
	case 8:
		src64 = (uint64_t *)((uint8_t *)entry + entry_offset);
		data = *src64;
		break;
	default:
		return (-1);
	}

	return (data);
}

static void
msix_table_write(struct vmctx *ctx, struct passthru_softc *sc,
		 uint64_t offset, int size, uint64_t data)
{
	struct pci_devinst *pi;
	struct msix_table_entry *entry;
	uint8_t *dest8;
	uint16_t *dest16;
	uint32_t *dest32;
	uint64_t *dest64;
	size_t entry_offset;
	uint32_t table_offset, vector_control;
	int index, table_count;

	pi = sc->psc_pi;

	table_offset = pi->pi_msix.table_offset;
	table_count = pi->pi_msix.table_count;
	if (offset < table_offset ||
	    offset >= table_offset + table_count * MSIX_TABLE_ENTRY_SIZE) {
		switch (size) {
		case 1:
			dest8 = (uint8_t *)(pi->pi_msix.mapped_addr + offset);
			*dest8 = data;
			break;
		case 2:
			dest16 = (uint16_t *)(pi->pi_msix.mapped_addr + offset);
			*dest16 = data;
			break;
		case 4:
			dest32 = (uint32_t *)(pi->pi_msix.mapped_addr + offset);
			*dest32 = data;
			break;
		case 8:
			dest64 = (uint64_t *)(pi->pi_msix.mapped_addr + offset);
			*dest64 = data;
			break;
		}
		return;
	}

	offset -= table_offset;
	index = offset / MSIX_TABLE_ENTRY_SIZE;
	assert(index < table_count);

	entry = &pi->pi_msix.table[index];
	entry_offset = offset % MSIX_TABLE_ENTRY_SIZE;

	/* Only 4 byte naturally-aligned writes are supported */
	assert(size == 4);
	assert(entry_offset % 4 == 0);

	vector_control = entry->vector_control;
	dest32 = (uint32_t *)((uint8_t *)entry + entry_offset);
	*dest32 = data;
	/* If MSI-X hasn't been enabled, do nothing */
	if (pi->pi_msix.enabled) {
		/* If the entry is masked, don't set it up */
		if ((entry->vector_control & PCIM_MSIX_VCTRL_MASK) == 0 ||
		    (vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
			(void) vm_setup_pptdev_msix(ctx, sc->pptfd,
			    index, entry->addr, entry->msg_data,
			    entry->vector_control);
		}
	}
}

static int
init_msix_table(struct vmctx *ctx __unused, struct passthru_softc *sc)
{
	struct pci_devinst *pi = sc->psc_pi;
	uint32_t table_size, table_offset;
	int i;

	i = pci_msix_table_bar(pi);
	assert(i >= 0);

        /*
         * Map the region of the BAR containing the MSI-X table.  This is
         * necessary for two reasons:
         * 1. The PBA may reside in the first or last page containing the MSI-X
         *    table.
         * 2. While PCI devices are not supposed to use the page(s) containing
         *    the MSI-X table for other purposes, some do in practice.
         */

	/*
	 * Mapping pptfd provides access to the BAR containing the MSI-X
	 * table. See ppt_devmap() in usr/src/uts/intel/io/vmm/io/ppt.c
	 *
	 * This maps the whole BAR and then mprotect(PROT_NONE) is used below
	 * to prevent access to pages that don't contain the MSI-X table.
	 * When porting this, it was tempting to just map the MSI-X table pages
	 * but that would mean updating everywhere that assumes that
	 * pi->pi_msix.mapped_addr points to the start of the BAR. For now,
	 * keep closer to upstream.
	 */
	pi->pi_msix.mapped_size = sc->psc_bar[i].size;
	pi->pi_msix.mapped_addr = (uint8_t *)mmap(NULL, pi->pi_msix.mapped_size,
	    PROT_READ | PROT_WRITE, MAP_SHARED, sc->pptfd, 0);
	if (pi->pi_msix.mapped_addr == MAP_FAILED) {
		warn("Failed to map MSI-X table BAR on %d", sc->pptfd);
		return (-1);
	}

	table_offset = rounddown2(pi->pi_msix.table_offset, 4096);

	table_size = pi->pi_msix.table_offset - table_offset;
	table_size += pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
	table_size = roundup2(table_size, 4096);

	/*
	 * Unmap any pages not containing the table, we do not need to emulate
	 * accesses to them.  Avoid releasing address space to help ensure that
	 * a buggy out-of-bounds access causes a crash.
	 */
	if (table_offset != 0)
		if (mprotect((caddr_t)pi->pi_msix.mapped_addr, table_offset,
		    PROT_NONE) != 0)
			warn("Failed to unmap MSI-X table BAR region");
	if (table_offset + table_size != pi->pi_msix.mapped_size)
		if (mprotect((caddr_t)
		    pi->pi_msix.mapped_addr + table_offset + table_size,
		    pi->pi_msix.mapped_size - (table_offset + table_size),
		    PROT_NONE) != 0)
			warn("Failed to unmap MSI-X table BAR region");

	return (0);
}

static int
cfginitbar(struct vmctx *ctx __unused, struct passthru_softc *sc)
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
		sc->psc_bar[i].lobits = 0;

		/* Allocate the BAR in the guest I/O or MMIO space */
		error = pci_emul_alloc_bar(pi, i, bartype, size);
		if (error)
			return (-1);

		/* Use same lobits as physical bar */
		uint8_t lobits = passthru_read_config(sc, PCIR_BAR(i), 0x01);
		if (bartype == PCIBAR_MEM32 || bartype == PCIBAR_MEM64) {
			lobits &= ~PCIM_BAR_MEM_BASE;
		} else {
			lobits &= ~PCIM_BAR_IO_BASE;
		}
		sc->psc_bar[i].lobits = lobits;
		pi->pi_bar[i].lobits = lobits;

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
	int error;
	struct pci_devinst *pi = sc->psc_pi;
	uint8_t intline, intpin;

	/*
	 * Copy physical PCI header to virtual config space. INTLINE and INTPIN
	 * shouldn't be aligned with their physical value and they are already
	 * set by pci_emul_init().
	 */
	intline = pci_get_cfgdata8(pi, PCIR_INTLINE);
	intpin = pci_get_cfgdata8(pi, PCIR_INTPIN);
	for (int i = 0; i <= PCIR_MAXLAT; i += 4) {
#ifdef	__FreeBSD__
		pci_set_cfgdata32(pi, i, read_config(&sc->psc_sel, i, 4));
#else
		pci_set_cfgdata32(pi, i, passthru_read_config(sc, i, 4));
#endif
	}

	pci_set_cfgdata8(pi, PCIR_INTLINE, intline);
	pci_set_cfgdata8(pi, PCIR_INTPIN, intpin);

	if (cfginitmsi(sc) != 0) {
		warnx("failed to initialize MSI for PCI %d", sc->pptfd);
		return (-1);
	}

	if (cfginitbar(ctx, sc) != 0) {
		warnx("failed to initialize BARs for PCI %d", sc->pptfd);
		return (-1);
	}

	passthru_write_config(sc, PCIR_COMMAND, 2,
	    pci_get_cfgdata16(pi, PCIR_COMMAND));

	/*
	* We need to do this after PCIR_COMMAND got possibly updated, e.g.,
	* a BAR was enabled.
	*/
	if (pci_msix_table_bar(pi) >= 0) {
		error = init_msix_table(ctx, sc);
		if (error != 0) {
			warnx("failed to initialize MSI-X table for PCI %d",
			    sc->pptfd);
			goto done;
		}
	}

	/* Emulate most PCI header register. */
	if ((error = set_pcir_handler(sc, 0, PCIR_MAXLAT + 1,
	    passthru_cfgread_emulate, passthru_cfgwrite_emulate)) != 0)
		goto done;

	/* Allow access to the physical command and status register. */
	if ((error = set_pcir_handler(sc, PCIR_COMMAND, 0x04, NULL, NULL)) != 0)
		goto done;

	error = 0;				/* success */
done:
	return (error);
}

int
set_pcir_handler(struct passthru_softc *sc, int reg, int len,
    cfgread_handler rhandler, cfgwrite_handler whandler)
{
	if (reg > PCI_REGMAX || reg + len > PCI_REGMAX + 1)
		return (-1);

	for (int i = reg; i < reg + len; ++i) {
		assert(sc->psc_pcir_rhandler[i] == NULL || rhandler == NULL);
		assert(sc->psc_pcir_whandler[i] == NULL || whandler == NULL);
		sc->psc_pcir_rhandler[i] = rhandler;
		sc->psc_pcir_whandler[i] = whandler;
	}

	return (0);
}

static int
passthru_legacy_config(nvlist_t *nvl, const char *opt)
{
	char *config, *name, *tofree, *value;

	if (opt == NULL)
		return (0);

	config = tofree = strdup(opt);
	while ((name = strsep(&config, ",")) != NULL) {
		value = strchr(name, '=');
		if (value != NULL) {
			*value++ = '\0';
			set_config_value_node(nvl, name, value);
		} else {
			if (strncmp(name, "/dev/ppt", 8) != 0) {
				EPRINTLN("passthru: invalid path \"%s\"", name);
				free(tofree);
				return (-1);
			}
			set_config_value_node(nvl, "path", name);
		}
	}
	free(tofree);
	return (0);
}

static int
passthru_init_rom(struct vmctx *const ctx __unused,
    struct passthru_softc *const sc, const char *const romfile)
{
	if (romfile == NULL) {
		return (0);
	}

	const int fd = open(romfile, O_RDONLY);
	if (fd < 0) {
		warnx("%s: can't open romfile \"%s\"", __func__, romfile);
		return (-1);
	}

	struct stat sbuf;
	if (fstat(fd, &sbuf) < 0) {
		warnx("%s: can't fstat romfile \"%s\"", __func__, romfile);
		close(fd);
		return (-1);
	}
	const uint64_t rom_size = sbuf.st_size;

	void *const rom_data = mmap(NULL, rom_size, PROT_READ, MAP_SHARED, fd,
	    0);
	if (rom_data == MAP_FAILED) {
		warnx("%s: unable to mmap romfile \"%s\" (%d)", __func__,
		    romfile, errno);
		close(fd);
		return (-1);
	}

	void *rom_addr;
	int error = pci_emul_alloc_rom(sc->psc_pi, rom_size, &rom_addr);
	if (error) {
		warnx("%s: failed to alloc rom segment", __func__);
		munmap(rom_data, rom_size);
		close(fd);
		return (error);
	}
	memcpy(rom_addr, rom_data, rom_size);

	sc->psc_bar[PCI_ROM_IDX].type = PCIBAR_ROM;
	sc->psc_bar[PCI_ROM_IDX].addr = (uint64_t)rom_addr;
	sc->psc_bar[PCI_ROM_IDX].size = rom_size;

	munmap(rom_data, rom_size);
	close(fd);

 	return (0);
 }

static int
passthru_init(struct pci_devinst *pi, nvlist_t *nvl)
{
	int error, memflags, pptfd;
	struct passthru_softc *sc;
	const char *path;
	struct vmctx *ctx = pi->pi_vmctx;

	pptfd = -1;
	sc = NULL;
	error = 1;

	memflags = vm_get_memflags(ctx);
	if (!(memflags & VM_MEM_F_WIRED)) {
		warnx("passthru requires guest memory to be wired");
		goto done;
	}

	path = get_config_value_node(nvl, "path");
	if (path == NULL || passthru_dev_open(path, &pptfd) != 0) {
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

#ifndef	__FreeBSD__
	/*
	 * If this function uses legacy interrupt messages, then request one for
	 * the guest in case drivers expect to see it. Note that nothing in the
	 * hypervisor is currently wired up do deliver such an interrupt should
	 * the guest actually rely upon it.
	 */
	uint8_t intpin = passthru_read_config(sc, PCIR_INTPIN, 1);
	if (intpin > 0 && intpin < 5)
		pci_lintr_request(sc->psc_pi);
#endif

	/* initialize config space */
	if ((error = cfginit(ctx, sc)) != 0)
		goto done;

	/* initialize ROM */
	if ((error = passthru_init_rom(ctx, sc,
	    get_config_value_node(nvl, "rom"))) != 0) {
		goto done;
	}

done:
	if (error) {
		free(sc);
		if (pptfd != -1)
			vm_unassign_pptdev(ctx, pptfd);
	}
	return (error);
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
passthru_cfgread_default(struct passthru_softc *sc,
    struct pci_devinst *pi __unused, int coff, int bytes, uint32_t *rv)
{
	/*
	 * MSI capability is emulated.
	 */
	if (msicap_access(sc, coff) || msixcap_access(sc, coff))
		return (-1);

	/*
	 * MSI-X is also emulated since a limit on interrupts may be imposed by
	 * the OS, altering the perceived register state.
	 */
	if (msixcap_access(sc, coff))
		return (-1);

	/*
	 * Emulate the command register.  If a single read reads both the
	 * command and status registers, read the status register from the
	 * device's config space.
	 */
	if (coff == PCIR_COMMAND) {
		if (bytes <= 2)
			return (-1);
		*rv = passthru_read_config(sc, PCIR_STATUS, 2) << 16 |
		    pci_get_cfgdata16(pi, PCIR_COMMAND);
		return (0);
	}

	/* Everything else just read from the device's config space */
	*rv = passthru_read_config(sc, coff, bytes);

	return (0);
}

int
passthru_cfgread_emulate(struct passthru_softc *sc __unused,
    struct pci_devinst *pi __unused, int coff __unused, int bytes __unused,
    uint32_t *rv __unused)
{
	return (-1);
}

static int
passthru_cfgread(struct pci_devinst *pi, int coff, int bytes, uint32_t *rv)
{
	struct passthru_softc *sc;

	sc = pi->pi_arg;

	if (sc->psc_pcir_rhandler[coff] != NULL)
		return (sc->psc_pcir_rhandler[coff](sc, pi, coff, bytes, rv));

	return (passthru_cfgread_default(sc, pi, coff, bytes, rv));
}

static int
passthru_cfgwrite_default(struct passthru_softc *sc, struct pci_devinst *pi,
    int coff, int bytes, uint32_t val)
{
	int error, msix_table_entries, i;
	uint16_t cmd_old;
	struct vmctx *ctx = pi->pi_vmctx;

	/*
	 * MSI capability is emulated
	 */
	if (msicap_access(sc, coff)) {
		pci_emul_capwrite(pi, coff, bytes, val, sc->psc_msi.capoff,
		    PCIY_MSI);
		error = vm_setup_pptdev_msi(ctx, sc->pptfd,
		    pi->pi_msi.addr, pi->pi_msi.msg_data, pi->pi_msi.maxmsgnum);
		if (error != 0)
			err(1, "vm_setup_pptdev_msi");
		return (0);
	}

	if (msixcap_access(sc, coff)) {
		pci_emul_capwrite(pi, coff, bytes, val, sc->psc_msix.capoff,
		    PCIY_MSIX);
		if (pi->pi_msix.enabled) {
			msix_table_entries = pi->pi_msix.table_count;
			for (i = 0; i < msix_table_entries; i++) {
				error = vm_setup_pptdev_msix(ctx,
				    sc->pptfd, i,
				    pi->pi_msix.table[i].addr,
				    pi->pi_msix.table[i].msg_data,
				    pi->pi_msix.table[i].vector_control);

				if (error)
					err(1, "vm_setup_pptdev_msix");
			}
		} else {
			error = vm_disable_pptdev_msix(ctx, sc->pptfd);
			if (error)
				err(1, "vm_disable_pptdev_msix");
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

	passthru_write_config(sc, coff, bytes, val);
	if (coff == PCIR_COMMAND) {
		cmd_old = pci_get_cfgdata16(pi, PCIR_COMMAND);
		if (bytes == 1)
			pci_set_cfgdata8(pi, PCIR_COMMAND, val);
		else if (bytes == 2)
			pci_set_cfgdata16(pi, PCIR_COMMAND, val);
		pci_emul_cmd_changed(pi, cmd_old);
	}

	return (0);
}

int
passthru_cfgwrite_emulate(struct passthru_softc *sc __unused,
    struct pci_devinst *pi __unused, int coff __unused, int bytes __unused,
    uint32_t val __unused)
{
	return (-1);
}

static int
passthru_cfgwrite(struct pci_devinst *pi, int coff, int bytes, uint32_t val)
{
	struct passthru_softc *sc;

	sc = pi->pi_arg;

	if (sc->psc_pcir_whandler[coff] != NULL)
		return (sc->psc_pcir_whandler[coff](sc, pi, coff, bytes, val));

	return (passthru_cfgwrite_default(sc, pi, coff, bytes, val));
}

static void
passthru_write(struct pci_devinst *pi, int baridx, uint64_t offset, int size,
    uint64_t value)
{
	struct passthru_softc *sc = pi->pi_arg;
	struct vmctx *ctx = pi->pi_vmctx;

	if (baridx == pci_msix_table_bar(pi)) {
		msix_table_write(ctx, sc, offset, size, value);
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
passthru_read(struct pci_devinst *pi, int baridx, uint64_t offset, int size)
{
	struct passthru_softc *sc = pi->pi_arg;
	uint64_t val;

	if (baridx == pci_msix_table_bar(pi)) {
		val = msix_table_read(sc, offset, size);
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

static void
passthru_msix_addr(struct vmctx *ctx, struct pci_devinst *pi, int baridx,
		   int enabled, uint64_t address)
{
	struct passthru_softc *sc;
	size_t remaining;
	uint32_t table_size, table_offset;

	sc = pi->pi_arg;
	table_offset = rounddown2(pi->pi_msix.table_offset, 4096);
	if (table_offset > 0) {
		if (!enabled) {
			if (vm_unmap_pptdev_mmio(ctx, sc->pptfd, address,
			    table_offset) != 0)
				warnx("pci_passthru: unmap_pptdev_mmio failed");
		} else {
			if (vm_map_pptdev_mmio(ctx, sc->pptfd, address,
			    table_offset, sc->psc_bar[baridx].addr) != 0)
				warnx("pci_passthru: map_pptdev_mmio failed");
		}
	}
	table_size = pi->pi_msix.table_offset - table_offset;
	table_size += pi->pi_msix.table_count * MSIX_TABLE_ENTRY_SIZE;
	table_size = roundup2(table_size, 4096);
	remaining = pi->pi_bar[baridx].size - table_offset - table_size;
	if (remaining > 0) {
		address += table_offset + table_size;
		if (!enabled) {
			if (vm_unmap_pptdev_mmio(ctx, sc->pptfd, address,
			    remaining) != 0)
				warnx("pci_passthru: unmap_pptdev_mmio failed");
		} else {
			if (vm_map_pptdev_mmio(ctx, sc->pptfd, address,
			    remaining, sc->psc_bar[baridx].addr +
			    table_offset + table_size) != 0)
				warnx("pci_passthru: map_pptdev_mmio failed");
		}
	}
}

static void
passthru_mmio_addr(struct vmctx *ctx, struct pci_devinst *pi, int baridx,
		   int enabled, uint64_t address)
{
	struct passthru_softc *sc;

	sc = pi->pi_arg;
	if (!enabled) {
		if (vm_unmap_pptdev_mmio(ctx, sc->pptfd, address,
		    sc->psc_bar[baridx].size) != 0)
			warnx("pci_passthru: unmap_pptdev_mmio failed");
	} else {
		if (vm_map_pptdev_mmio(ctx, sc->pptfd, address,
		    sc->psc_bar[baridx].size, sc->psc_bar[baridx].addr) != 0)
			warnx("pci_passthru: map_pptdev_mmio failed");
	}
}

static void
passthru_addr_rom(struct pci_devinst *const pi, const int idx,
    const int enabled)
{
	const uint64_t addr = pi->pi_bar[idx].addr;
	const uint64_t size = pi->pi_bar[idx].size;

	if (!enabled) {
		if (vm_munmap_memseg(pi->pi_vmctx, addr, size) != 0) {
			errx(4, "%s: munmap_memseg @ [%016lx - %016lx] failed",
			    __func__, addr, addr + size);
		}

	} else {
		if (vm_mmap_memseg(pi->pi_vmctx, addr, VM_PCIROM,
			pi->pi_romoffset, size, PROT_READ | PROT_EXEC) != 0) {
			errx(4, "%s: mmap_memseg @ [%016lx - %016lx]  failed",
			    __func__, addr, addr + size);
		}
	}
}

static void
passthru_addr(struct pci_devinst *pi, int baridx,
    int enabled, uint64_t address)
{
	struct vmctx *ctx = pi->pi_vmctx;

	switch (pi->pi_bar[baridx].type) {
	case PCIBAR_IO:
		/* IO BARs are emulated */
		break;
	case PCIBAR_ROM:
		passthru_addr_rom(pi, baridx, enabled);
		break;
	case PCIBAR_MEM32:
	case PCIBAR_MEM64:
		if (baridx == pci_msix_table_bar(pi))
			passthru_msix_addr(ctx, pi, baridx, enabled, address);
		else
			passthru_mmio_addr(ctx, pi, baridx, enabled, address);
		break;
	default:
		errx(4, "%s: invalid BAR type %d", __func__,
		    pi->pi_bar[baridx].type);
	}
}

static const struct pci_devemu passthru = {
	.pe_emu		= "passthru",
	.pe_init	= passthru_init,
	.pe_legacy_config = passthru_legacy_config,
	.pe_cfgwrite	= passthru_cfgwrite,
	.pe_cfgread	= passthru_cfgread,
	.pe_barwrite 	= passthru_write,
	.pe_barread    	= passthru_read,
	.pe_baraddr	= passthru_addr,
};
PCI_EMUL_SET(passthru);

/*
 * This isn't the right place for these functions which, on FreeBSD, can
 * read or write from arbitrary devices. They are not supported on illumos;
 * not least because bhyve is generally run in a non-global zone which doesn't
 * have access to the devinfo tree.
 */
uint32_t
read_config(const struct pcisel *sel __unused, long reg __unused,
    int width __unused)
{
	return (-1);
}

void
write_config(const struct pcisel *sel __unused, long reg __unused,
    int width __unused, uint32_t data __unused)
{
       errx(4, "write_config() unimplemented on illumos");
}
