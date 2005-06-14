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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PCI nexus driver interface
 */
#include <sys/types.h>
#include <sys/conf.h>		/* nulldev */
#include <sys/stat.h>		/* devctl */
#include <sys/kmem.h>
#include <sys/async.h>		/* ecc_flt for pci_ecc.h */
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ontrap.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_subrdefs.h>
#include <sys/epm.h>
#include <sys/membar.h>
#include <sys/modctl.h>
#include <sys/hotplug/pci/pcihp.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

static uint8_t	pci_axq_hack_get8(ddi_acc_impl_t *handle, uint8_t *addr);
static uint16_t	pci_axq_hack_get16(ddi_acc_impl_t *handle, uint16_t *addr);
static uint32_t	pci_axq_hack_get32(ddi_acc_impl_t *handle, uint32_t *addr);
static uint64_t	pci_axq_hack_get64(ddi_acc_impl_t *handle, uint64_t *addr);
static void	pci_axq_hack_put8(ddi_acc_impl_t *handle, uint8_t *addr,
			uint8_t data);
static void	pci_axq_hack_put16(ddi_acc_impl_t *handle, uint16_t *addr,
			uint16_t data);
static void	pci_axq_hack_put32(ddi_acc_impl_t *handle, uint32_t *addr,
			uint32_t data);
static void	pci_axq_hack_put64(ddi_acc_impl_t *handle, uint64_t *addr,
			uint64_t data);
static void	pci_axq_hack_rep_get8(ddi_acc_impl_t *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
static void	pci_axq_hack_rep_get16(ddi_acc_impl_t *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
static void	pci_axq_hack_rep_get32(ddi_acc_impl_t *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
static void	pci_axq_hack_rep_get64(ddi_acc_impl_t *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);
static void	pci_axq_hack_rep_put8(ddi_acc_impl_t *handle,
			uint8_t *host_addr, uint8_t *dev_addr,
			size_t repcount, uint_t flags);
static void	pci_axq_hack_rep_put16(ddi_acc_impl_t *handle,
			uint16_t *host_addr, uint16_t *dev_addr,
			size_t repcount, uint_t flags);
static void	pci_axq_hack_rep_put32(ddi_acc_impl_t *handle,
			uint32_t *host_addr, uint32_t *dev_addr,
			size_t repcount, uint_t flags);
static void	pci_axq_hack_rep_put64(ddi_acc_impl_t *handle,
			uint64_t *host_addr, uint64_t *dev_addr,
			size_t repcount, uint_t flags);

/*
 * On Sunfire 15k systems with AXQs less than 6.1
 * we have to use special PIO routines that limit
 * the number of outstanding PIOs.  We setup the
 * handle with pointers to our special functions
 * after it has been succesfully mapped by our
 * parent.
 */

void
pci_axq_pio_limit(pbm_t *pbm_p)
{
	pci_t *pci_p = pbm_p->pbm_pci_p;
	dev_info_t *dip = pci_p->pci_dip;
	int (*axq_pio_workaround)(dev_info_t *) = NULL;

	axq_pio_workaround =
	    (int (*)(dev_info_t *)) modgetsymvalue(
	    "starcat_axq_pio_workaround", 0);

	if (axq_pio_workaround) {
		pbm_p->pbm_pio_limit = (axq_pio_workaround)(dip);
		pbm_p->pbm_pio_counter = pbm_p->pbm_pio_limit;
	} else
		pbm_p->pbm_pio_limit = 0;
}

void
pci_axq_setup(ddi_map_req_t *mp, pbm_t *pbm_p)
{
	ddi_acc_hdl_t *hp;
	ddi_acc_impl_t *ap;

	if (mp->map_op != DDI_MO_MAP_LOCKED)
		return;
	if (!pbm_p->pbm_pio_limit)
		return;

	hp = (ddi_acc_hdl_t *)mp->map_handlep;
	ap = (ddi_acc_impl_t *)hp->ah_platform_private;

	ap->ahi_get8 = pci_axq_hack_get8;
	ap->ahi_get16 = pci_axq_hack_get16;
	ap->ahi_get32 = pci_axq_hack_get32;
	ap->ahi_get64 = pci_axq_hack_get64;
	ap->ahi_put8 = pci_axq_hack_put8;
	ap->ahi_put16 = pci_axq_hack_put16;
	ap->ahi_put32 = pci_axq_hack_put32;
	ap->ahi_put64 = pci_axq_hack_put64;
	ap->ahi_rep_get8 = pci_axq_hack_rep_get8;
	ap->ahi_rep_get16 = pci_axq_hack_rep_get16;
	ap->ahi_rep_get32 = pci_axq_hack_rep_get32;
	ap->ahi_rep_get64 = pci_axq_hack_rep_get64;
	ap->ahi_rep_put8 = pci_axq_hack_rep_put8;
	ap->ahi_rep_put16 = pci_axq_hack_rep_put16;
	ap->ahi_rep_put32 = pci_axq_hack_rep_put32;
	ap->ahi_rep_put64 = pci_axq_hack_rep_put64;

	hp->ah_bus_private = (void *)pbm_p;
}

/*
 * get/put routines for SunFire 15K systems that have AXQ versions
 * less than 6.1.  These routines limit the number of outsanding
 * PIOs issues across a PCI Bus.
 */
static uint8_t
pci_axq_hack_get8(ddi_acc_impl_t *handle, uint8_t *addr)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint8_t data;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	data = i_ddi_get8(handle, addr);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);

	return (data);
}

static uint16_t
pci_axq_hack_get16(ddi_acc_impl_t *handle, uint16_t *addr)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint16_t data;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	data = i_ddi_swap_get16(handle, addr);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);

	return (data);
}

static uint32_t
pci_axq_hack_get32(ddi_acc_impl_t *handle, uint32_t *addr)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t data;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	data = i_ddi_swap_get32(handle, addr);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);

	return (data);
}

static uint64_t
pci_axq_hack_get64(ddi_acc_impl_t *handle, uint64_t *addr)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint64_t data;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	data = i_ddi_swap_get64(handle, addr);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);

	return (data);
}

static void
pci_axq_hack_put8(ddi_acc_impl_t *handle, uint8_t *addr, uint8_t data)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_put8(handle, addr, data);
	membar_sync();
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_put16(ddi_acc_impl_t *handle, uint16_t *addr, uint16_t data)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_swap_put16(handle, addr, data);
	membar_sync();
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_put32(ddi_acc_impl_t *handle, uint32_t *addr, uint32_t data)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_swap_put32(handle, addr, data);
	membar_sync();
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_put64(ddi_acc_impl_t *handle, uint64_t *addr, uint64_t data)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_swap_put64(handle, addr, data);
	membar_sync();
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_rep_get8(ddi_acc_impl_t *handle, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_rep_get8(handle, host_addr, dev_addr, repcount, flags);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_rep_get16(ddi_acc_impl_t *handle, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_swap_rep_get16(handle, host_addr, dev_addr, repcount, flags);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_rep_get32(ddi_acc_impl_t *handle, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_swap_rep_get32(handle, host_addr, dev_addr, repcount, flags);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_rep_get64(ddi_acc_impl_t *handle, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	i_ddi_swap_rep_get64(handle, host_addr, dev_addr, repcount, flags);
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_rep_put8(ddi_acc_impl_t *handle, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	while (repcount--) {
		i_ddi_put8(handle, dev_addr, *host_addr);
		membar_sync();
		if (flags == DDI_DEV_AUTOINCR)
			dev_addr++;
		host_addr++;
	}
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_rep_put16(ddi_acc_impl_t *handle, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	while (repcount--) {
		i_ddi_put16(handle, dev_addr, *host_addr);
		membar_sync();
		if (flags == DDI_DEV_AUTOINCR)
			dev_addr++;
		host_addr++;
	}
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}

static void
pci_axq_hack_rep_put32(ddi_acc_impl_t *handle, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	while (repcount--) {
		i_ddi_put32(handle, dev_addr, *host_addr);
		membar_sync();
		if (flags == DDI_DEV_AUTOINCR)
			dev_addr++;
		host_addr++;
	}
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}
static void
pci_axq_hack_rep_put64(ddi_acc_impl_t *handle, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	pbm_t *pbm_p = (pbm_t *)handle->ahi_common.ah_bus_private;
	uint32_t spl;

	spl = ddi_enter_critical();
	PIO_LIMIT_ENTER(pbm_p);
	while (repcount--) {
		i_ddi_put64(handle, dev_addr, *host_addr);
		membar_sync();
		if (flags == DDI_DEV_AUTOINCR)
			dev_addr++;
		host_addr++;
	}
	PIO_LIMIT_EXIT(pbm_p);
	ddi_exit_critical(spl);
}
