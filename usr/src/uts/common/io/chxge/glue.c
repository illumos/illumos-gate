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

/*
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

/*
 * Solaris support routines for common code part of
 * Chelsio PCI Ethernet Driver.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strlog.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/kstat.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/varargs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include "ostypes.h"
#undef OFFSET
#include "common.h"
#include <sys/gld.h>
#include "oschtoe.h"
#include "ch.h"			/* Chelsio Driver specific parameters */
#include "sge.h"
#include "regs.h"

/*
 * Device specific.
 */
struct pe_reg {
	uint32_t cmd;
	uint32_t addr;
	union {
		uint32_t v32;
		uint64_t v64;
	}vv;
	union {
		uint32_t m32;
		uint64_t m64;
	}mm;
};
#define	pe_reg_val vv.v32
#define	pe_opt_val vv.v64
#define	pe_mask32  mm.m32
#define	pe_mask64  mm.m64

struct toetool_reg {
	uint32_t cmd;
	uint32_t addr;
	uint32_t val;
};

uint32_t
t1_read_reg_4(ch_t *obj, uint32_t reg_val)
{
	return (ddi_get32(obj->ch_hbar0, (uint32_t *)(obj->ch_bar0 + reg_val)));
}

void
t1_write_reg_4(ch_t *obj, uint32_t reg_val, uint32_t write_val)
{
	ddi_put32(obj->ch_hbar0, (uint32_t *)(obj->ch_bar0+reg_val), write_val);
}

uint32_t
t1_os_pci_read_config_2(ch_t *obj, uint32_t reg, uint16_t *val)
{
	*val = pci_config_get16(obj->ch_hpci, reg);
	return (0);
}

int
t1_os_pci_write_config_2(ch_t *obj, uint32_t reg, uint16_t val)
{
	pci_config_put16(obj->ch_hpci, reg, val);
	return (0);
}

uint32_t
t1_os_pci_read_config_4(ch_t *obj, uint32_t reg, uint32_t *val)
{
	*val = pci_config_get32(obj->ch_hpci, reg);
	return (0);
}

int
t1_os_pci_write_config_4(ch_t *obj, uint32_t reg, uint32_t val)
{
	pci_config_put32(obj->ch_hpci, reg, val);
	return (0);
}

void *
t1_os_malloc_wait_zero(size_t len)
{
	return (kmem_zalloc(len, KM_SLEEP));
}

void
t1_os_free(void *adr, size_t len)
{
	kmem_free(adr, len);
}

int
t1_num_of_ports(ch_t *obj)
{
	return (obj->config_data.num_of_ports);
}

/* ARGSUSED */
int
pe_os_mem_copy(ch_t *obj, void *dst, void *src, size_t len)
{
	bcopy(src, dst, len);
	return (0);
}

int
pe_is_ring_buffer_enabled(ch_t *obj)
{
	return (obj->config & CFGMD_RINGB);
}

#define	PE_READ_REG  _IOR('i', 0xAB, 0x18)
#define	PE_WRITE_REG _IOW('i', 0xAB, 0x18)
#define	PE_READ_PCI  _IOR('i', 0xAC, 0x18)
#define	PE_WRITE_PCI _IOW('i', 0xAC, 0x18)
#define	PE_READ_INTR _IOR('i', 0xAD, 0x20)
#define	TOETOOL_GETTPI _IOR('i', 0xAE, 0xc)
#define	TOETOOL_SETTPI _IOW('i', 0xAE, 0xc)

void
pe_ioctl(ch_t *chp, queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	mblk_t *dmp;
	struct pe_reg *pe;
	struct toetool_reg *te;
	uint32_t reg;
	struct sge_intr_counts *se, *sep;

	iocp = (struct iocblk *)mp->b_rptr;

	/* don't support TRASPARENT ioctls */
	if (iocp->ioc_count == TRANSPARENT) {
		iocp->ioc_error = ENOTTY;
		goto bad;
	}

	/*
	 * sanity checks. There should be a M_DATA mblk following
	 * the initial M_IOCTL mblk
	 */
	if ((dmp = mp->b_cont) == NULL) {
		iocp->ioc_error = ENOTTY;
		goto bad;
	}

	if (dmp->b_datap->db_type != M_DATA) {
		iocp->ioc_error = ENOTTY;
		goto bad;
	}

	pe = (struct pe_reg *)dmp->b_rptr;
	se = (struct sge_intr_counts *)dmp->b_rptr;
	te = (struct toetool_reg *)dmp->b_rptr;

	/* now process the ioctl */
	switch (iocp->ioc_cmd) {
	case PE_READ_REG:

		if ((dmp->b_wptr - dmp->b_rptr) != sizeof (*pe)) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		/* protect against bad addr values */
		pe->addr &= (uint32_t)~3;

		pe->pe_mask32 = 0xFFFFFFFF;

		if (pe->addr == 0x950)
			pe->pe_reg_val = reg = t1_sge_get_ptimeout(chp);
		else
			pe->pe_reg_val = reg = t1_read_reg_4(chp, pe->addr);

		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = sizeof (*pe);

		break;

	case PE_WRITE_REG:

		if ((dmp->b_wptr - dmp->b_rptr) != sizeof (*pe)) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		if (pe->addr == 0x950)
			t1_sge_set_ptimeout(chp, pe->pe_reg_val);
		else {
			if (pe->pe_mask32 != 0xffffffff) {
				reg = t1_read_reg_4(chp, pe->addr);
				pe->pe_reg_val |= (reg & ~pe->pe_mask32);
			}

			t1_write_reg_4(chp, pe->addr,  pe->pe_reg_val);
		}

		if (mp->b_cont)
			freemsg(mp->b_cont);
		mp->b_cont = NULL;
		mp->b_datap->db_type = M_IOCACK;
		break;

	case PE_READ_PCI:

		if ((dmp->b_wptr - dmp->b_rptr) != sizeof (*pe)) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		/* protect against bad addr values */
		pe->addr &= (uint32_t)~3;

		pe->pe_mask32 = 0xFFFFFFFF;
		pe->pe_reg_val = reg = pci_config_get32(chp->ch_hpci, pe->addr);
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = sizeof (*pe);

		break;

	case PE_WRITE_PCI:

		if ((dmp->b_wptr - dmp->b_rptr) != sizeof (*pe)) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		if (pe->pe_mask32 != 0xffffffff) {
			reg = pci_config_get32(chp->ch_hpci, pe->addr);
			pe->pe_reg_val |= (reg & ~pe->pe_mask32);
		}

		pci_config_put32(chp->ch_hpci, pe->addr,  pe->pe_reg_val);

		if (mp->b_cont)
			freemsg(mp->b_cont);
		mp->b_cont = NULL;
		mp->b_datap->db_type = M_IOCACK;
		break;

	case PE_READ_INTR:

		if ((dmp->b_wptr - dmp->b_rptr) != sizeof (*se)) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		sep = sge_get_stat(chp->sge);
		bcopy(sep, se, sizeof (*se));
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = sizeof (*se);
		break;

	case TOETOOL_GETTPI:

		if ((dmp->b_wptr - dmp->b_rptr) != sizeof (*te)) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		/* protect against bad addr values */
		if ((te->addr & 3) != 0) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		(void) t1_tpi_read(chp, te->addr, &te->val);
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = sizeof (*te);

		break;

	case TOETOOL_SETTPI:

		if ((dmp->b_wptr - dmp->b_rptr) != sizeof (*te)) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		/* protect against bad addr values */
		if ((te->addr & 3) != 0) {
			iocp->ioc_error = ENOTTY;
			goto bad;
		}

		(void) t1_tpi_write(chp, te->addr, te->val);

		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_count = sizeof (*te);

		break;

	default:
		iocp->ioc_error = ENOTTY;
		goto bad;
	}

	qreply(q, mp);

	return;

bad:
	if (mp->b_cont)
		freemsg(mp->b_cont);
	mp->b_cont = NULL;
	mp->b_datap->db_type = M_IOCNAK;

	qreply(q, mp);
}

/*
 * Can't wait for memory here, since we have to use the Solaris dma
 * mechanisms to determine the physical address.
 * flg is either 0 (read) or DMA_OUT (write).
 */
void *
pe_os_malloc_contig_wait_zero(ch_t *chp, size_t len, uint64_t *dma_addr,
	ulong_t *dh, ulong_t *ah, uint32_t flg)
{
	void *mem = NULL;
	uint64_t pa;

	/*
	 * byte swap, consistant mapping & 4k aligned
	 */
	mem = ch_alloc_dma_mem(chp, 1, DMA_4KALN|flg, len, &pa, dh, ah);
	if (mem == NULL) {
		return (0);
	}

	if (dma_addr)
		*dma_addr = pa;

	bzero(mem, len);

	return ((void *)mem);
}

/* ARGSUSED */
void
pe_os_free_contig(ch_t *obj, size_t len, void *addr, uint64_t dma_addr,
			ulong_t dh, ulong_t ah)
{
	ch_free_dma_mem(dh, ah);
}

void
t1_fatal_err(ch_t *adapter)
{
	if (adapter->ch_flags & PEINITDONE) {
		(void) sge_stop(adapter->sge);
		t1_interrupts_disable(adapter);
	}
	CH_ALERT("%s: encountered fatal error, operation suspended\n",
	    adapter_name(adapter));
}

void
CH_ALERT(const char *fmt, ...)
{
	va_list	ap;
	char	buf[128];

	/* format buf using fmt and arguments contained in ap */

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	/* pass formatted string to cmn_err(9F) */
	cmn_err(CE_WARN, "%s", buf);
}

void
CH_WARN(const char *fmt, ...)
{
	va_list	ap;
	char	buf[128];

	/* format buf using fmt and arguments contained in ap */

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	/* pass formatted string to cmn_err(9F) */
	cmn_err(CE_WARN, "%s", buf);
}

void
CH_ERR(const char *fmt, ...)
{
	va_list	ap;
	char	buf[128];

	/* format buf using fmt and arguments contained in ap */

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	/* pass formatted string to cmn_err(9F) */
	cmn_err(CE_WARN, "%s", buf);
}

u32
le32_to_cpu(u32 data)
{
#if BYTE_ORDER == BIG_ENDIAN
	uint8_t *in, t;
	in = (uint8_t *)&data;
	t = in[0];
	in[0] = in[3];
	in[3] = t;
	t = in[1];
	in[1] = in[2];
	in[2] = t;
#endif
	return (data);
}

/*
 * This function initializes a polling routine, Poll_func
 * which will be polled ever N Microsecond, where N is
 * provided in the cyclic start routine.
 */
/* ARGSUSED */
void
ch_init_cyclic(void *adapter, p_ch_cyclic_t cyclic,
		void (*poll_func)(void *), void *arg)
{
	cyclic->func = poll_func;
	cyclic->arg = arg;
	cyclic->timer = 0;
}

/*
 * Cyclic function which provides a periodic polling
 * capability to Solaris. The poll function provided by
 * the 'ch_init_cyclic' function is called from this
 * here, and this routine launches a new one-shot
 * timer to bring it back in some period later.
 */
void
ch_cyclic(p_ch_cyclic_t cyclic)
{
	if (cyclic->timer != 0) {
		cyclic->func(cyclic->arg);
		cyclic->timer = timeout((void(*)(void  *))ch_cyclic,
		    (void *)cyclic, cyclic->period);
	}
}

/*
 * The 'ch_start_cyclic' starts the polling.
 */
void
ch_start_cyclic(p_ch_cyclic_t cyclic, unsigned long period)
{
	cyclic->period = drv_usectohz(period * 1000);
	if (cyclic->timer == 0) {
		cyclic->timer = timeout((void(*)(void  *))ch_cyclic,
		    (void *)cyclic, cyclic->period);
	}
}

/*
 * The 'ch_stop_cyclic' stops the polling.
 */
void
ch_stop_cyclic(p_ch_cyclic_t cyclic)
{
	timeout_id_t timer;
	clock_t value;

	do {
		timer = cyclic->timer;
		cyclic->timer = 0;
		value = untimeout(timer);
		if (value == 0)
			drv_usecwait(drv_hztousec(2 * cyclic->period));
	} while ((timer != 0) && (value == 0));
}
