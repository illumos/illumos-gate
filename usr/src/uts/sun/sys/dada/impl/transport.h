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
 * Copyright (c) 1996, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_DADA_IMPL_TRANSPORT_H
#define	_SYS_DADA_IMPL_TRANSPORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Include loadable module wrapper.
 */
#include <sys/modctl.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
/*
 * DCD transport structure
 *	As each host adapter makes itself known to the system,
 * 	It will create and register with the library the structure
 * 	describe below. This is so that the library knows how to route
 *	packets, resource control requests, and capability requests
 * 	for any  particular host adapter. The 'a_hba_tran' field of a
 *	dcd_address structure made known to a target driver will point to
 *	one of these transport structures.
 */

typedef	struct dcd_hba_tran	dcd_hba_tran_t;

struct dcd_hba_tran {
	uint_t		version;
	/*
	 * Ptr to the device info structure for thsi particular HBA
	 */
	dev_info_t	*tran_hba_dip;

	/*
	 * Private fields for use by the HBA itself
	 */
	void		*tran_hba_private; /* HBA Softstate */
	void		*tran_tgt_private; /* Target specific info */

	/*
	 * Only used to refer to a particular dcd device
	 * if the entire dcd_hba_tran_structure is cloned
	 * per target device, otherwise NULL.
	 */

	struct	dcd_device	*tran_sd;

	/*
	 * vectors to point to specific HBA entry points.
	 */
	int 		(*tran_tgt_init)(
				dev_info_t	*hba_dip,
				dev_info_t	*tgt_dip,
				dcd_hba_tran_t	*hba_tran,
				struct	dcd_device	*dcd);

	int		(*tran_tgt_probe)(
				struct dcd_device	*dcd,
				int		(*callback)(void));
	int		(*tran_tgt_free)(
				dev_info_t	*hba_dip,
				dev_info_t	*tgt_dip,
				dcd_hba_tran_t	*hba_tran,
				struct	dcd_device	*dcd);

	int		(*tran_start)(
				struct	dcd_address *ap,
				struct	dcd_pkt	*pkt);

	int		(*tran_reset)(
				struct dcd_address *ap,
				int		level);

	int		(*tran_abort)(
				struct	dcd_address *ap,
				struct  dcd_pkt	 *pkt);

	struct dcd_pkt *(*tran_init_pkt)(
				struct dcd_address	*ap,
				struct	dcd_pkt		*pkt,
				struct	buf		*bp,
				int			cmdlen,
				int			statuslen,
				int			tgtlen,
				int			flags,
				int			(*callback)(
							caddr_t arg),
				caddr_t			callback_arg);

	void		(*tran_destroy_pkt)(
				struct dcd_address *ap,
				struct	dcd_pkt		*pkt);

	void		(*tran_dmafree)(
				struct dcd_address	*ap,
				struct	dcd_pkt		*pkt);
	void		(*tran_sync_pkt)(
				struct dcd_address	*ap,
				struct dcd_pkt		*pkt);


	/*
	 * Implementation private specifics.
	 */
	int		tran_hba_flags;		/* flag option */

	/*
	 * min xfer and min/max burst sizes for DDI_CTLOPS_IOMIN
	 */
	uint_t		tran_min_xfer;
	uchar_t		tran_min_burst_size;
	uchar_t		tran_max_burst_size;
};


/*
 * Prototypes for DCD HBA interface function.
 */

extern void	dcd_initialize_hba_interface(void);

#ifdef	NO_DADA_FINI_YET
extern	void	dcd_uninitialize_hba_interface(void);
#endif

extern	int	dcd_hba_init(struct modlinkage	*modlp);

extern	void	dcd_hab_fini(struct modlinkage	*modlp);

#ifdef NOTNEEDED
extern	int	dcd_hba_attach(
			dev_info_t	*dip,
			ddi_dma_lim_t	*hba_lim,
			dcd_hba_tran_t	*hba_tran,
			int		flags,
			void		*hba_options);
#endif

extern int	dcd_hba_attach(
			dev_info_t	*dip,
			ddi_dma_attr_t	*hba_dma_attr,
			dcd_hba_tran_t	*hba_tran,
			int		flags);

extern int	dcd_hba_detach(
			dev_info_t	*dip);

extern	dcd_hba_tran_t	*dcd_hba_tran_alloc(
			dev_info_t	*dip,
			int		flags);

extern	void	dcd_hba_tran_free(
			dcd_hba_tran_t	*hba_tran);

extern int	dcd_hba_probe(
			struct	dcd_device  *dcd,
			int	(*callback)(void));

extern	struct	dcd_pkt	*dcd_hba_pkt_alloc(
			struct	dcd_address	*ap,
			int		cmdlen,
			int		statuslen,
			int		tgtlen,
			int		hbalen,
			int 		(*callback)(caddr_t),
			caddr_t		arg);

extern	void 	dcd_hba_pkt_free(
		struct dcd_address 	*ap,
		struct dcd_pkt		*pkt);

extern	int	dcd_hba_lookup_capstr(
			char	*capstr);
extern	int	dcd_hba_in_panic(void);

/*
 * Flags for dcd_hba_attach
 */
#define	 DCD_HBA_TRAN_CLONE	0x01

/*
 * Flags for scsi_hab alloaction functions
 */
#define	DCD_HBA_CANSLEEP 0x01

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DADA_IMPL_TRANSPORT_H */
