/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1988-1989,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_CG6REG_H
#define	_SYS_CG6REG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * CG6 frame buffer hardware definitions.
 */


/* Physical frame buffer and color map addresses */
/*
 * The base address is defined in the configuration file, e.g. GENERIC.
 * These constants are the offset from that address.
 */

#define	CG6_P4BASE		0xFB000000L

#define	CG6_ADDR_ROM_SBUS	0L
#define	CG6_ADDR_ROM_P4		0x380000L


#define	CG6_ADDR_CMAP		0x200000L
#define	CG6_ADDR_DHC		0x240000L
#define	CG6_ADDR_ALT		0x280000L
#define	CG6_ADDR_FBC		0x700000L
#define	CG6_ADDR_TEC		0x701000L
#define	CG6_ADDR_P4REG		0x300000L
#define	CG6_ADDR_OVERLAY	0x400000L	/* FAKE */
#define	CG6_ADDR_FHC		0x300000L
#define	CG6_ADDR_THC		0x301000L
#define	CG6_ADDR_ENABLE		0x600000L
#define	CG6_ADDR_COLOR		0x800000L

#define	CG6_ADDR_FBCTEC		CG6_ADDR_FBC
#define	CG6_ADDR_FHCTHC		CG6_ADDR_FHC

#define	CG6_CMAP_SZ		8192
#define	CG6_FBCTEC_SZ		8192
#define	CG6_FHCTHC_SZ		8192
#define	CG6_ROM_SZ		(64*1024)
#define	CG6_FB_SZ		(1024*1024)
#define	CG6_DHC_SZ		8192
#define	CG6_ALT_SZ		8192

/*
 * Offsets of TEC/FHC into page
 */
#define	CG6_TEC_POFF		0x1000
#define	CG6_THC_POFF		0x1000

/*
 * Virtual (mmap offsets) addresses
 */
#define	CG6_VBASE		0x70000000L	/* nobody knows where */
						/* this comes from */
#define	CG6_VADDR(x)		(CG6_VBASE + (x) * 8192)

/*
 * CG6 Virtual object addresses
 */
#define	CG6_VADDR_FBC		CG6_VADDR(0)
#define	CG6_VADDR_TEC		(CG6_VADDR_FBC + CG6_TEC_POFF)
#define	CG6_VADDR_CMAP		CG6_VADDR(1)
#define	CG6_VADDR_FHC		CG6_VADDR(2)
#define	CG6_VADDR_THC		(CG6_VADDR_FHC + CG6_THC_POFF)
#define	CG6_VADDR_ROM		CG6_VADDR(3)
#define	CG6_VADDR_COLOR		(CG6_VADDR_ROM + CG6_ROM_SZ)
	/* KLUDGE: BIG gap here, to accomodate potential future framebuffers */
#define	CG6_VADDR_DHC		CG6_VADDR(16384)
#define	CG6_VADDR_ALT		CG6_VADDR(16385)
#define	CG6_VADDR_UART		CG6_VADDR(16386)
#define	CG6_VADDR_VRT		CG6_VADDR(16387) /* vertical retrace page */

#define	CG6_VADDR_FBCTEC	CG6_VADDR_FBC
#define	CG6_VADDR_FHCTHC	CG6_VADDR_FHC
/*
 * to map in all of lego, use mmapsize below, and offset CG6_VBASE
 */
#define	MMAPSIZE(dfbsize)	(CG6_VADDR_COLOR-CG6_VBASE+dfbsize)

/*
 * convert from address returned by pr_makefromfd (eg. mmap)
 * to CG6 register set.
 */
#define	CG6VA_TO_FBC(base) \
	((struct fbc *)(((char *)base)+(CG6_VADDR_FBC-CG6_VBASE)))
#define	CG6VA_TO_TEC(base)  \
	((struct tec *)(((char *)base)+(CG6_VADDR_TEC-CG6_VBASE)))
#define	CG6VA_TO_FHC(base)  \
	((uint_t *)(((char *)base)+(CG6_VADDR_FHC-CG6_VBASE)))
#define	CG6VA_TO_THC(base)  \
	((struct thc *)(((char *)base)+(CG6_VADDR_THC-CG6_VBASE)))
#define	CG6VA_TO_DFB(base)  \
	((short *)(((char *)base)+(CG6_VADDR_COLOR-CG6_VBASE)))
#define	CG6VA_TO_ROM(base)  \
	((uint_t *)(((char *)base)+(CG6_VADDR_ROM-CG6_VBASE)))
#define	CG6VA_TO_CMAP(base) \
	((struct cg6_cmap *)(((char *)base)+(CG6_VADDR_CMAP-CG6_VBASE)))


/* (Brooktree DAC) definitions */

/* number of colormap entries */
#define	CG6_CMAP_ENTRIES	256

struct cg6_cmap {
	uint32_t	addr;		/* address register */
	uint32_t	cmap;		/* color map data register */
	uint32_t	ctrl;		/* control register */
	uint32_t	omap;		/* overlay map data register */
};

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CG6REG_H */
