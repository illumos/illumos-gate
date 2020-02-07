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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/mdb_modapi.h>
#include <mdb/mdb_ks.h>
#include <sys/async.h>		/* ecc_flt for pci_ecc.h */
#include <sys/ddi_subrdefs.h>
#include <sys/pci/pci_obj.h>
#include "niumx_var.h"
#include "px_obj.h"

static int intr_pci_walk_step(mdb_walk_state_t *);
static int intr_px_walk_step(mdb_walk_state_t *);
static int intr_niumx_walk_step(mdb_walk_state_t *);
static void intr_pci_print_items(mdb_walk_state_t *);
static void intr_px_print_items(mdb_walk_state_t *);
static char *intr_get_intr_type(uint16_t type);
static void intr_print_banner(void);

typedef struct intr_info {
	uint32_t	cpuid;
	uint32_t	inum;
	uint32_t	num;
	uint32_t	pil;
	uint16_t	intr_type;
	uint16_t	mondo;
	uint8_t		ino_ino;
	uint_t		intr_state;
	int		instance;
	int		shared;
	char		driver_name[12];
	char		pathname[MAXNAMELEN];
}
intr_info_t;

#define	PX_MAX_ENTRIES		32

static void intr_print_elements(intr_info_t);
static int detailed = 0; /* Print detailed view */


static int
intr_walk_init(mdb_walk_state_t *wsp)
{
	wsp->walk_addr = (uintptr_t)NULL;

	return (WALK_NEXT);
}

static int
intr_walk_step(mdb_walk_state_t *wsp)
{
	pci_t		*pci_per_p;
	px_t		*px_state_p;
	niumx_devstate_t *niumx_state_p;

	/* read globally declared structures in the pci driver */
	if (mdb_readvar(&pci_per_p, "per_pci_state") != -1) {
		wsp->walk_addr = (uintptr_t)pci_per_p;
		intr_pci_walk_step(wsp);
	}

	/* read globally declared structures in the px driver */
	if (mdb_readvar(&px_state_p, "px_state_p") != -1) {
		wsp->walk_addr = (uintptr_t)px_state_p;
		intr_px_walk_step(wsp);
	}

	/* read globally declared structures in the niumx driver */
	if (mdb_readvar(&niumx_state_p, "niumx_state") != -1) {
		wsp->walk_addr = (uintptr_t)niumx_state_p;
		intr_niumx_walk_step(wsp);
	}

	return (WALK_DONE);
}

static int
intr_pci_walk_step(mdb_walk_state_t *wsp)
{
	pci_t		*pci_per_p;
	pci_t		pci_per;
	uintptr_t	start_addr;

	/* Read start of state structure array */
	if (mdb_vread(&pci_per_p, sizeof (uintptr_t),
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("intr: failed to read the initial pci_per_p "
		    "structure\n");
		return (WALK_ERR);
	}

	/* Figure out how many items are here */
	start_addr = (uintptr_t)pci_per_p;

	intr_print_banner();

	while (mdb_vread(&pci_per_p, sizeof (uintptr_t),
	    (uintptr_t)start_addr) != -1) {
		/* Read until nothing is left */
		if (mdb_vread(&pci_per, sizeof (pci_t),
		    (uintptr_t)pci_per_p) == -1) {
			return (WALK_DONE);
		}

		wsp->walk_addr = (uintptr_t)pci_per.pci_ib_p;
		intr_pci_print_items(wsp);

		start_addr += sizeof (uintptr_t);
	}

	return (WALK_DONE);
}

static int
intr_px_walk_step(mdb_walk_state_t *wsp)
{
	px_t		*px_state_p;
	px_t		px_state;
	uintptr_t	start_addr;
	int		x;

	/* Read start of state structure array */
	if (mdb_vread(&px_state_p, sizeof (uintptr_t),
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("intr: failed to read the initial px_per_p "
		    "structure\n");
		return (WALK_ERR);
	}

	/* Figure out how many items are here */
	start_addr = (uintptr_t)px_state_p;

	intr_print_banner();

	for (x = 0; x < PX_MAX_ENTRIES; x++) {
		(void) mdb_vread(&px_state_p, sizeof (uintptr_t),
		    (uintptr_t)start_addr);

		start_addr += sizeof (uintptr_t);

		/* Read if anything is there */
		if (mdb_vread(&px_state, sizeof (px_t),
		    (uintptr_t)px_state_p) == -1) {
			continue;
		}

		wsp->walk_addr = (uintptr_t)px_state.px_ib_p;
		intr_px_print_items(wsp);
	}

	return (WALK_DONE);
}

static int
intr_niumx_walk_step(mdb_walk_state_t *wsp)
{
	niumx_devstate_t *niumx_state_p;
	niumx_devstate_t niumx_state;
	uintptr_t	start_addr;
	char		name[MODMAXNAMELEN + 1];
	struct dev_info	dev;
	intr_info_t	info;
	int		i;

	/* Read start of state structure array */
	if (mdb_vread(&niumx_state_p, sizeof (uintptr_t),
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("intr: failed to read the initial niumx_state_p "
		    "structure\n");
		return (WALK_ERR);
	}

	/* Figure out how many items are here */
	start_addr = (uintptr_t)niumx_state_p;

	while (mdb_vread(&niumx_state_p, sizeof (uintptr_t),
	    (uintptr_t)start_addr) >= 0) {

		start_addr += sizeof (uintptr_t);

		/* Read if anything is there */
		if (mdb_vread(&niumx_state, sizeof (niumx_devstate_t),
		    (uintptr_t)niumx_state_p) == -1) {
			return (WALK_DONE);
		}

		for (i = 0; i < NIUMX_MAX_INTRS; i++) {
			if (niumx_state.niumx_ihtable[i].ih_sysino == 0)
				continue;

			if (niumx_state.niumx_ihtable[i].ih_dip == 0)
				continue;

			bzero((void *)&info, sizeof (intr_info_t));

			info.shared = 0;

			(void) mdb_devinfo2driver(
			    (uintptr_t)niumx_state.niumx_ihtable[i].ih_dip,
			    name, sizeof (name));

			(void) mdb_ddi_pathname(
			    (uintptr_t)niumx_state.niumx_ihtable[i].ih_dip,
			    info.pathname, sizeof (info.pathname));

			/* Get instance */
			if (mdb_vread(&dev, sizeof (struct dev_info),
			    (uintptr_t)niumx_state.niumx_ihtable[i].ih_dip) ==
			    -1) {
				mdb_warn("intr: failed to read DIP "
				    "structure\n");

				return (WALK_DONE);
			}

			/* Make sure the name doesn't over run */
			(void) mdb_snprintf(info.driver_name,
			    sizeof (info.driver_name), "%s", name);

			info.instance = dev.devi_instance;
			info.inum = niumx_state.niumx_ihtable[i].ih_inum;
			info.intr_type = DDI_INTR_TYPE_FIXED;
			info.num = 0;
			info.intr_state = niumx_state.niumx_ihtable[i].ih_state;
			info.ino_ino = i;
			info.mondo = niumx_state.niumx_ihtable[i].ih_sysino;
			info.pil = niumx_state.niumx_ihtable[i].ih_pri;
			info.cpuid = niumx_state.niumx_ihtable[i].ih_cpuid;

			intr_print_elements(info);
		}
	}

	return (WALK_DONE);
}

static void
intr_pci_print_items(mdb_walk_state_t *wsp)
{
	ib_t			ib;
	ib_ino_info_t		ino;
	ib_ino_pil_t		ipil;
	ih_t			ih;
	int			count;
	char			name[MODMAXNAMELEN + 1];
	struct dev_info		dev;
	intr_info_t		info;

	if (mdb_vread(&ib, sizeof (ib_t),
	    (uintptr_t)wsp->walk_addr) == -1) {
		mdb_warn("intr: failed to read pci interrupt block "
		    "structure\n");
		return;
	}

	/* Read in ib_ino_info_t structure at address */
	if (mdb_vread(&ino, sizeof (ib_ino_info_t),
	    (uintptr_t)ib.ib_ino_lst) == -1) {
		/* Nothing here to read from */
		return;
	}

	do {
		if (mdb_vread(&ipil, sizeof (ib_ino_pil_t),
		    (uintptr_t)ino.ino_ipil_p) == -1) {
			mdb_warn("intr: failed to read pci interrupt "
			    "ib_ino_pil_t structure\n");
			return;
		}

		do {
			if (mdb_vread(&ih, sizeof (ih_t),
			    (uintptr_t)ipil.ipil_ih_start) == -1) {
				mdb_warn("intr: failed to read pci interrupt "
				    "ih_t structure\n");
				return;
			}

			count = 0;

			do {
				bzero((void *)&info, sizeof (intr_info_t));

				if ((ino.ino_ipil_size > 1) ||
				    (ipil.ipil_ih_size > 1)) {
					info.shared = 1;
				}

				(void) mdb_devinfo2driver((uintptr_t)ih.ih_dip,
				    name, sizeof (name));

				(void) mdb_ddi_pathname((uintptr_t)ih.ih_dip,
				    info.pathname, sizeof (info.pathname));

				/* Get instance */
				if (mdb_vread(&dev, sizeof (struct dev_info),
				    (uintptr_t)ih.ih_dip) == -1) {
					mdb_warn("intr: failed to read DIP "
					    "structure\n");
					return;
				}

				/* Make sure the name doesn't over run */
				(void) mdb_snprintf(info.driver_name,
				    sizeof (info.driver_name), "%s", name);

				info.instance = dev.devi_instance;
				info.inum = ih.ih_inum;
				info.intr_type = DDI_INTR_TYPE_FIXED;
				info.num = 0;
				info.intr_state = ih.ih_intr_state;
				info.ino_ino = ino.ino_ino;
				info.mondo = ino.ino_mondo;
				info.pil = ipil.ipil_pil;
				info.cpuid = ino.ino_cpuid;

				intr_print_elements(info);
				count++;

				(void) mdb_vread(&ih, sizeof (ih_t),
				    (uintptr_t)ih.ih_next);

			} while (count < ipil.ipil_ih_size);

		} while (mdb_vread(&ipil, sizeof (ib_ino_pil_t),
		    (uintptr_t)ipil.ipil_next_p) != -1);

	} while (mdb_vread(&ino, sizeof (ib_ino_info_t),
	    (uintptr_t)ino.ino_next_p) != -1);
}

static void
intr_px_print_items(mdb_walk_state_t *wsp)
{
	px_ib_t		ib;
	px_ino_t	ino;
	px_ino_pil_t	ipil;
	px_ih_t		ih;
	int		count;
	char		name[MODMAXNAMELEN + 1];
	struct dev_info	dev;
	intr_info_t	info;
	devinfo_intr_t	intr_p;

	if (mdb_vread(&ib, sizeof (px_ib_t), wsp->walk_addr) == -1) {
		return;
	}

	/* Read in px_ino_t structure at address */
	if (mdb_vread(&ino, sizeof (px_ino_t),
	    (uintptr_t)ib.ib_ino_lst) == -1) {
		/* Nothing here to read from */
		return;
	}

	do { /* ino_next_p loop */
		if (mdb_vread(&ipil, sizeof (px_ino_pil_t),
		    (uintptr_t)ino.ino_ipil_p) == -1) {
			continue;
		}

		do { /* ipil_next_p loop */
			if (mdb_vread(&ih, sizeof (px_ih_t),
			    (uintptr_t)ipil.ipil_ih_start) == -1) {
				continue;
			}

			count = 0;

			do { /* ipil_ih_size loop */
				bzero((void *)&info, sizeof (intr_info_t));

				(void) mdb_devinfo2driver((uintptr_t)ih.ih_dip,
				    name, sizeof (name));

				(void) mdb_ddi_pathname((uintptr_t)ih.ih_dip,
				    info.pathname, sizeof (info.pathname));

				/* Get instance */
				if (mdb_vread(&dev, sizeof (struct dev_info),
				    (uintptr_t)ih.ih_dip) == -1) {
					mdb_warn("intr: failed to read DIP "
					    "structure\n");
					return;
				}

				/* Make sure the name doesn't over run */
				(void) mdb_snprintf(info.driver_name,
				    sizeof (info.driver_name), "%s", name);

				info.instance = dev.devi_instance;
				info.inum = ih.ih_inum;

				/*
				 * Read the type used, keep PCIe messages
				 * separate.
				 */
				(void) mdb_vread(&intr_p,
				    sizeof (devinfo_intr_t),
				    (uintptr_t)dev.devi_intr_p);

				if (ih.ih_rec_type != MSG_REC) {
					info.intr_type =
					    intr_p.devi_intr_curr_type;
				}

				if ((ino.ino_ipil_size > 1) ||
				    (ipil.ipil_ih_size > 1)) {
					info.shared = 1;
				}

				info.num = ih.ih_msg_code;
				info.intr_state = ih.ih_intr_state;
				info.ino_ino = ino.ino_ino;
				info.mondo = ino.ino_sysino;
				info.pil = ipil.ipil_pil;
				info.cpuid = ino.ino_cpuid;

				intr_print_elements(info);
				count++;

				(void) mdb_vread(&ih, sizeof (px_ih_t),
				    (uintptr_t)ih.ih_next);

			} while (count < ipil.ipil_ih_size);

		} while ((ipil.ipil_next_p != NULL) &&
		    (mdb_vread(&ipil, sizeof (px_ino_pil_t),
		    (uintptr_t)ipil.ipil_next_p) != -1));

	} while ((ino.ino_next_p != NULL) && (mdb_vread(&ino, sizeof (px_ino_t),
	    (uintptr_t)ino.ino_next_p) != -1));
}

static char *
intr_get_intr_type(uint16_t type)
{
	switch (type) {
		case	DDI_INTR_TYPE_FIXED:
			return ("Fixed");
		case	DDI_INTR_TYPE_MSI:
			return ("MSI");
		case	DDI_INTR_TYPE_MSIX:
			return ("MSI-X");
		default:
			return ("PCIe");
	}
}

static void
intr_print_banner(void)
{
	if (!detailed) {
		mdb_printf("\n%<u>\tDevice\t"
		    " Type\t"
		    " MSG #\t"
		    " State\t"
		    " INO\t"
		    " Mondo\t"
		    " Shared\t"
		    "  Pil\t"
		    " CPU   %</u>"
		    "\n");
	}
}

static void
intr_print_elements(intr_info_t info)
{
	if (!detailed) {
		mdb_printf(" %11s#%d\t", info.driver_name, info.instance);
		mdb_printf(" %s\t", intr_get_intr_type(info.intr_type));
		if (info.intr_type == DDI_INTR_TYPE_FIXED) {
			mdb_printf("  --- \t");
		} else {
			mdb_printf(" %4d\t", info.num);
		}
		mdb_printf(" %2s\t",
		    info.intr_state ? "enbl" : "disbl");
		mdb_printf(" 0x%x\t", info.ino_ino);
		mdb_printf(" 0x%x\t", info.mondo);
		mdb_printf(" %5s\t",
		    info.shared ? "yes" : "no");
		mdb_printf(" %4d\t", info.pil);
		mdb_printf(" %3d \n", info.cpuid);
	} else {
		mdb_printf("\n-------------------------------------------\n");
		mdb_printf("Device:\t\t%s\n", info.driver_name);
		mdb_printf("Instance:\t%d\n", info.instance);
		mdb_printf("Path:\t\t%s\n", info.pathname);
		mdb_printf("Inum:\t\t%d\n", info.inum);
		mdb_printf("Interrupt Type:\t%s\n",
		    intr_get_intr_type(info.intr_type));
		if (info.intr_type == DDI_INTR_TYPE_MSI) {
			mdb_printf("MSI Number:\t%d\n", info.num);
		} else if (info.intr_type == DDI_INTR_TYPE_MSIX) {
			mdb_printf("MSI-X Number:\t%d\n", info.num);
		} else if (!info.intr_type) {
			mdb_printf("PCIe Message #:\t%d\n", info.num);
		}

		mdb_printf("Shared Intr:\t%s\n",
		    info.shared ? "yes" : "no");
		mdb_printf("State:\t\t%d (%s)\n", info.intr_state,
		    info.intr_state ? "Enabled" : "Disabled");
		mdb_printf("INO:\t\t0x%x\n", info.ino_ino);
		mdb_printf("Mondo:\t\t0x%x\n", info.mondo);
		mdb_printf("Pil:\t\t%d\n", info.pil);
		mdb_printf("CPU:\t\t%d\n", info.cpuid);
	}
}

/*ARGSUSED*/
static void
intr_walk_fini(mdb_walk_state_t *wsp)
{
	/* Nothing to do here */
}

/*ARGSUSED*/
static int
intr_intr(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	detailed = 0;

	if (mdb_getopts(argc, argv, 'd', MDB_OPT_SETBITS, TRUE, &detailed,
	    NULL) != argc)
		return (DCMD_USAGE);

	if (!(flags & DCMD_ADDRSPEC)) {
		if (mdb_walk_dcmd("interrupts", "interrupts", argc, argv)
		    == -1) {
			mdb_warn("can't walk pci/px buffer entries\n");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	return (DCMD_OK);
}

/*
 * MDB module linkage information:
 */

static const mdb_dcmd_t dcmds[] = {
	{ "interrupts", "[-d]", "display the interrupt info registered with "
	    "the PCI/PX nexus drivers", intr_intr },
	{ NULL }
};

static const mdb_walker_t walkers[] = {
	{ "interrupts", "walk PCI/PX interrupt structures",
		intr_walk_init, intr_walk_step, intr_walk_fini },
	{ NULL }
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION, dcmds, walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
