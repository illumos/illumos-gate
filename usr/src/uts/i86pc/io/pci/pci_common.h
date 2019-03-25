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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 Joyent, Inc.
 */

#ifndef	_PCI_PCI_COMMON_H
#define	_PCI_PCI_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Common header file with definitions shared between
 *	pci(7D) and npe(7D)
 */

/* State structure. */
typedef struct pci_state {
	dev_info_t *pci_dip;
	int pci_fmcap;
	uint_t pci_soft_state;
	ddi_iblock_cookie_t pci_fm_ibc;
	kmutex_t pci_mutex;
	kmutex_t pci_peek_poke_mutex;
	kmutex_t pci_err_mutex;

	/*
	 * The following members are only used by npe(7D).
	 * See uts/i86pc/io/pciex/npe.c for more information.
	 */
	ndi_event_hdl_t pci_ndi_event_hdl;
} pci_state_t;

/*
 * These are the access routines.
 * The pci_bus_map sets the handle to point to these in pci(7D).
 * The npe_bus_map sets the handle to point to these in npe(7D).
 */
uint8_t		pci_config_rd8(ddi_acc_impl_t *hdlp, uint8_t *addr);
uint16_t	pci_config_rd16(ddi_acc_impl_t *hdlp, uint16_t *addr);
uint32_t	pci_config_rd32(ddi_acc_impl_t *hdlp, uint32_t *addr);
uint64_t	pci_config_rd64(ddi_acc_impl_t *hdlp, uint64_t *addr);

void		pci_config_wr8(ddi_acc_impl_t *hdlp, uint8_t *addr,
		    uint8_t value);
void		pci_config_wr16(ddi_acc_impl_t *hdlp, uint16_t *addr,
		    uint16_t value);
void		pci_config_wr32(ddi_acc_impl_t *hdlp, uint32_t *addr,
		    uint32_t value);
void		pci_config_wr64(ddi_acc_impl_t *hdlp, uint64_t *addr,
		    uint64_t value);

void		pci_config_rep_rd8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
		    uint8_t *dev_addr, size_t repcount, uint_t flags);
void		pci_config_rep_rd16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
		    uint16_t *dev_addr, size_t repcount, uint_t flags);
void		pci_config_rep_rd32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
		    uint32_t *dev_addr, size_t repcount, uint_t flags);
void		pci_config_rep_rd64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
		    uint64_t *dev_addr, size_t repcount, uint_t flags);

void		pci_config_rep_wr8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
		    uint8_t *dev_addr, size_t repcount, uint_t flags);
void		pci_config_rep_wr16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
		    uint16_t *dev_addr, size_t repcount, uint_t flags);
void		pci_config_rep_wr32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
		    uint32_t *dev_addr, size_t repcount, uint_t flags);
void		pci_config_rep_wr64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
		    uint64_t *dev_addr, size_t repcount, uint_t flags);

/*
 * PCI tool related declarations
 */
int	pci_common_ioctl(dev_info_t *dip, dev_t dev, int cmd,
	    intptr_t arg, int mode, cred_t *credp, int *rvalp);

/*
 * Interrupt related declaration
 */
int	pci_common_intr_ops(dev_info_t *, dev_info_t *, ddi_intr_op_t,
	    ddi_intr_handle_impl_t *, void *);
void	pci_common_set_parent_private_data(dev_info_t *);

/*
 * Miscellaneous library functions
 */
int	pci_common_get_reg_prop(dev_info_t *dip, pci_regspec_t *pci_rp);
int	pci_common_name_child(dev_info_t *child, char *name, int namelen);
int	pci_common_peekpoke(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t ctlop, void *arg, void *result);
int	pci_fm_acc_setup(ddi_acc_hdl_t *hp, off_t offset, off_t len);

#ifdef	__cplusplus
}
#endif

#endif	/* _PCI_PCI_COMMON_H */
