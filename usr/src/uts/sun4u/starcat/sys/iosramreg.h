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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IOSRAMREG_H
#define	_SYS_IOSRAMREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif



/*
 * iosram_reg_t property  (an array of following tuple/data)
 *	address format
 *	  hi  npt000ss  bbbbbbbb  dddddfff  rrrrrrrr
 *	 mid  hhhhhhhh  hhhhhhhh  hhhhhhhh  hhhhhhhh
 *	 low  llllllll  llllllll  llllllll  llllllll
 *
 *	size format
 *	  hi  hhhhhhhh  hhhhhhhh  hhhhhhhh  hhhhhhhh
 *	 low  llllllll  llllllll  llllllll  llllllll
 *	 n=0 if relocatable
 *	 p=1 if addressable region is prefetchable
 *	 t=1 if address region is aliased
 *	 ss=00 Config. space also n,p,t must be 0
 *	   =01 I/O space p must be 0
 *	   =10 32 bit address memory space
 *	   =11 64 bit address memory space
 *	 bbbbbbbb 8 bit bus number
 *	 ddddd 5 bit device number
 *	 fff 3 bit function number
 *	 rrrrrrrr 8 bit register number
 *	 hhhhhhhh 32 bit unsigned number
 *	 llllllll 32 bit unsigned number
 *
 *	 address: 64 bits memory space
 *	  hi 00000011  00000000  00000000  00000000
 *	     0x03000000
 *	 mid 00000000  00000000  00000000  00000000
 *	     0x00000000
 *	 low 00000000  00010000  00000000  00000000
 *	     0x00100000
 *	 size
 *	  hi 00000000  00000000  00000000  00000000
 *	 low 00000000  00000011  11111111  11111111
 */

typedef struct {
	uint32_t	addr_hi;
	uint32_t	addr_lo;
	uint32_t	size;
} iosram_reg_t;


/*
 * SBBC access structures.  Each SBBC register is 32 bits aligned on a 16
 * byte boundary.  The iosram_sbbc_region structure should be mapped onto
 * the SBBC register space starting at 0x1000 to achieve correct alignment
 * between structure fields and SBBC registers.
 */
typedef struct iosram_sbbcr {
	uint32_t	reg;		/* 32-bit register */
	uint32_t	pad[3];		/* padding to fill out 16 bytes */
} iosram_sbbcr_t;

typedef struct iosram_sbbc_region {
	iosram_sbbcr_t	synch[16];	/* 0x1000 - 10ff - semaphore region */
	iosram_sbbcr_t	pad0[240];	/* 0x1100 - 1fff - padding */
	iosram_sbbcr_t	p0_int_gen;	/* 0x2000 - 200f - PCI port 0 */
					/*    interrupt generation */
	iosram_sbbcr_t	p1_int_gen;	/* 0x2010 - 201f - PCI port 1 */
					/*    interrupt generation */
	iosram_sbbcr_t	pad1[48];	/* 0x2020 - 231f - padding */
	iosram_sbbcr_t	int_status;	/* 0x2320 - 232f - interrupt status */
	iosram_sbbcr_t	int_enable;	/* 0x2330 - 233f - interrupt enables */
} iosram_sbbc_region_t;

#define	IOSRAM_SBBC_MAP_OFFSET	0x1000	/* offset of SBBC regs to be mapped */
#define	IOSRAM_SBBC_MAP_INDEX   0x1	/* address space set # for SBBC regs */
#define	IOSRAM_SBBC_INT0	0x01
#define	IOSRAM_SBBC_INT1	0x10

/*
 * SBBC hardware semaphore access
 */

/* indices into sbbc_region->synch array */
#define	IOSRAM_SEMA_SMS_IDX	0x1	/* when accessed by SMS */
#define	IOSRAM_SEMA_DOM_IDX	0x8	/* when accessed by domain */
#define	IOSRAM_SEMA_OBP_IDX	0xf	/* when accessed by OBP */

/* mask for bits used to encode how semaphore was acquired (bits 1-4) */
#define	IOSRAM_SEMA_MASK	0x1e

/* read an write semaphore values using domain assigned register */
#define	IOSRAM_SEMA_RD(softp)	ddi_get32((softp)->sbbc_handle, \
	&(softp->sbbc_region->synch[IOSRAM_SEMA_DOM_IDX].reg));
#define	IOSRAM_SEMA_WR(softp, v) ddi_put32((softp)->sbbc_handle, \
	&(softp->sbbc_region->synch[IOSRAM_SEMA_DOM_IDX].reg), v);

#define	IOSRAM_SEMA_IS_HELD(v)	((v) & 0x1)
#define	IOSRAM_SEMA_GET_IDX(v)	(((v) & IOSRAM_SEMA_MASK) >> 1)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOSRAMREG_H */
