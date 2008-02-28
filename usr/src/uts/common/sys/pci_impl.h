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

#ifndef _SYS_PCI_IMPL_H
#define	_SYS_PCI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dditypes.h>
#include <sys/memlist.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__i386) || defined(__amd64)

/*
 * There are two ways to access the PCI configuration space on X86
 * 	Access method 2 is the older method
 *	Access method 1 is the newer method and is preferred because
 *	  of the problems in trying to lock the configuration space
 *	  for MP machines using method 2.  See PCI Local BUS Specification
 *	  Revision 2.0 section 3.6.4.1 for more details.
 *
 * In addition, on IBM Sandalfoot and a few related machines there's
 * still another mechanism.  See PReP 1.1 section 6.1.7.
 */

#define	PCI_MECHANISM_UNKNOWN		-1
#define	PCI_MECHANISM_NONE		0
#if defined(__i386) || defined(__amd64)
#define	PCI_MECHANISM_1 		1
#define	PCI_MECHANISM_2			2
#else
#error "Unknown processor type"
#endif


#ifndef FALSE
#define	FALSE   0
#endif

#ifndef TRUE
#define	TRUE    1
#endif

#define	PCI_FUNC_MASK			0x07

/* these macros apply to Configuration Mechanism #1 */
#define	PCI_CONFADD		0xcf8
#define	PCI_PMC			0xcfb
#define	PCI_CONFDATA		0xcfc
#define	PCI_CONE		0x80000000
#define	PCI_CADDR1(bus, device, function, reg) \
		(PCI_CONE | (((bus) & 0xff) << 16) | (((device & 0x1f)) << 11) \
			    | (((function) & 0x7) << 8) | ((reg) & 0xfc))

/* these macros apply to Configuration Mechanism #2 */
#define	PCI_CSE_PORT		0xcf8
#define	PCI_FORW_PORT		0xcfa
#define	PCI_CADDR2(device, indx) \
		(0xc000 | (((device) & 0xf) <<  8) | (indx))

typedef struct 	pci_acc_cfblk {
	uchar_t	c_busnum;		/* bus number */
	uchar_t c_devnum;		/* device number */
	uchar_t c_funcnum;		/* function number */
	uchar_t c_fill;			/* reserve field */
} pci_acc_cfblk_t;

struct pci_bus_resource {
	struct memlist *io_ports;	/* available free io res */
	struct memlist *io_ports_used;	/* used io res */
	struct memlist *mem_space;	/* available free mem res */
	struct memlist *mem_space_used;	/* used mem res */
	struct memlist *pmem_space; /* available free prefetchable mem res */
	struct memlist *pmem_space_used; /* used prefetchable mem res */
	struct memlist *bus_space;	/* available free bus res */
			/* bus_space_used not needed; can read from regs */
	dev_info_t *dip;	/* devinfo node */
	void *privdata;		/* private data for configuration */
	uchar_t par_bus;	/* parent bus number */
	uchar_t sub_bus;	/* highest bus number beyond this bridge */
	uchar_t root_addr;	/* legacy peer bus address assignment */
	uchar_t num_cbb;	/* # of CardBus Bridges on the bus */
	boolean_t io_reprogram;	/* need io reprog on this bus */
	boolean_t mem_reprogram;	/* need mem reprog on this bus */
	boolean_t subtractive;	/* subtractive PPB */
};

extern struct pci_bus_resource *pci_bus_res;

/*
 * For now, x86-only to avoid conflicts with <sys/memlist_impl.h>
 */
extern struct memlist *memlist_alloc(void);
extern void memlist_free(struct memlist *);
extern void memlist_free_all(struct memlist **);
extern void memlist_insert(struct memlist **, uint64_t, uint64_t);
extern int memlist_remove(struct memlist **, uint64_t, uint64_t);
extern uint64_t memlist_find(struct memlist **, uint64_t, int);
extern uint64_t memlist_find_with_startaddr(struct memlist **, uint64_t,
    uint64_t, int);
extern void memlist_dump(struct memlist *);
extern void memlist_merge(struct memlist **, struct memlist **);
extern struct memlist *memlist_dup(struct memlist *);
extern int memlist_count(struct memlist *);

#endif /* __i386 || __amd64 */

/*
 * PCI capability related definitions.
 */

/*
 * Minimum number of dwords to be saved.
 */
#define	PCI_MSI_MIN_WORDS	3
#define	PCI_PCIX_MIN_WORDS	2
#define	PCI_PCIE_MIN_WORDS	5

/*
 * Total number of dwords to be saved.
 */
#define	PCI_PMCAP_NDWORDS	2
#define	PCI_AGP_NDWORDS		3
#define	PCI_SLOTID_NDWORDS	1
#define	PCI_MSIX_NDWORDS	3
#define	PCI_CAP_SZUNKNOWN	0

#define	CAP_ID(confhdl, cap_ptr, xspace)		\
	((xspace) ? 0 : pci_config_get8((confhdl), (cap_ptr) + PCI_CAP_ID))

#define	NEXT_CAP(confhdl, cap_ptr, xspace)	\
	((xspace) ? 0 :				\
	pci_config_get8((confhdl), (cap_ptr) + PCI_CAP_NEXT_PTR))

extern int pci_resource_setup(dev_info_t *);
extern void pci_resource_destroy(dev_info_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PCI_IMPL_H */
