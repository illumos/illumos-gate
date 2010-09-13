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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Inter-Domain Network - Xfire specifics.
 */

#ifndef	_SYS_IDN_XF_H
#define	_SYS_IDN_XF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/pda.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/idn_sigb.h>
#include <sys/starfire.h>

#include <sys/idn.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * These address bits fit into PA[17:9].
 */
#define	CIC_CONFIG0_ADDR	0x002
#define	CIC_CONFIG1_ADDR	0x003
#define	CIC_DOMAIN_MASK_ADDR	0x004
#define	CIC_SM_MASK_ADDR	0x005
#define	CIC_SM_BAR_LSB_ADDR	0x006
#define	CIC_SM_BAR_MSB_ADDR	0x007
#define	CIC_SM_LAR_LSB_ADDR	0x008
#define	CIC_SM_LAR_MSB_ADDR	0x009

#define	CIC_CONFIG0_BUSMODE_MASK	0x3
#define	CIC_CONFIG0_BUSMODE_SHIFT	2
#define	CIC_CONFIG0_BUSMODE(c) \
	(((c) >> CIC_CONFIG0_BUSMODE_SHIFT) & CIC_CONFIG0_BUSMODE_MASK)
#define	CIC_CONFIG1_SMMASK_MASK		0x1
#define	CIC_CONFIG1_SMMASK_SHIFT	1
#define	CIC_CONFIG1_SMMASK_BIT(c) \
	(((c) >> CIC_CONFIG1_SMMASK_SHIFT) & CIC_CONFIG1_SMMASK_MASK)

#define	CIC_CSR_ADDR_MASK	0x1ff
#define	CIC_CSR_ADDR_SHIFT	9
#define	CSR_TYPE_CIC		0xe

#define	CSR_BOARD_MASK		0xf	/* PA[39:36] */
#define	CSR_BOARD_SHIFT		36

#define	CSR_TYPE_MASK		0xf	/* PA[35:32] */
#define	CSR_TYPE_SHIFT		32

#define	CSR_BUS_MASK		0x3
#define	CSR_BUS_SHIFT		6    /* XXX - depends on config/shuffle */

				/* bd=board, t=type, a=addr, bs=bus */
#define	MAKE_CIC_CSR_PA(bd, t, a, bs) \
		(((u_longlong_t)1 << 40) \
		    | ((u_longlong_t)((bd) & CSR_BOARD_MASK) \
			<< CSR_BOARD_SHIFT) \
		    | ((u_longlong_t)((t) & CSR_TYPE_MASK) \
			<< CSR_TYPE_SHIFT) \
		    | ((u_longlong_t)((a) & CIC_CSR_ADDR_MASK) \
			<< CIC_CSR_ADDR_SHIFT) \
		    | ((u_longlong_t)((bs) & CSR_BUS_MASK) \
			<< CSR_BUS_SHIFT))

#define	STARFIRE_PC_MADR_VALIDBIT	0x80000000

/*
 * Macro to calculate address of CIC prep buffer
 * that resides in PC.
 * This macro really belongs in <sys/starfire.h>
 */
#define	STARFIRE_PC_CICBUF_ADDR(bb, p) \
		(STARFIRE_BRD_TO_PSI(bb) | \
		((uint64_t)(p) << STARFIRE_UPS_MID_SHIFT) | \
		STARFIRE_PSI_PCREG_OFF | \
		STARFIRE_PC_CIC_WRITE_DATA)

/*
 * ---------------------------------------------------------------------
 */

extern cpu_t		cpu0;

extern int	get_hw_config(struct hwconfig *loc_hw);
extern int	update_local_hw_config(idn_domain_t *ldp,
				struct hwconfig *loc_hw);
extern boardset_t	cic_read_domain_mask(int board, int bus);
extern boardset_t	cic_read_sm_mask(int board, int bus);
extern uint_t	cic_read_sm_bar(int board, int bus);
extern uint_t	cic_read_sm_lar(int board, int bus);
extern void	pc_read_madr(pda_handle_t ph, int lboard,
				uint_t mc_adr[], int  local_only);
extern void	mc_get_adr_all(pda_handle_t ph, uint_t mc_adr[],
				int *nmcadr);
extern int	post2obp_valid(post2obp_info_t *p2o);

extern uint_t	xf_physio_rdword(u_longlong_t physaddr);
extern void	xf_physio_wrword(u_longlong_t physaddr, uint_t value);
extern ushort_t	xf_physio_rdhword(u_longlong_t physaddr);
extern void	xf_physio_wrhword(u_longlong_t physaddr, ushort_t value);


#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IDN_XF_H */
