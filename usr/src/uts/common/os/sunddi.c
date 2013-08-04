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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 */

#include <sys/note.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/cred.h>
#include <sys/poll.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <sys/model.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/open.h>
#include <sys/user.h>
#include <sys/t_lock.h>
#include <sys/vm.h>
#include <sys/stat.h>
#include <vm/hat.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <vm/seg_dev.h>
#include <vm/as.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/debug.h>
#include <sys/autoconf.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/sunndi.h>
#include <sys/kstat.h>
#include <sys/conf.h>
#include <sys/ddi_impldefs.h>	/* include implementation structure defs */
#include <sys/ndi_impldefs.h>	/* include prototypes */
#include <sys/ddi_periodic.h>
#include <sys/hwconf.h>
#include <sys/pathname.h>
#include <sys/modctl.h>
#include <sys/epm.h>
#include <sys/devctl.h>
#include <sys/callb.h>
#include <sys/cladm.h>
#include <sys/sysevent.h>
#include <sys/dacf_impl.h>
#include <sys/ddidevmap.h>
#include <sys/bootconf.h>
#include <sys/disp.h>
#include <sys/atomic.h>
#include <sys/promif.h>
#include <sys/instance.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/taskq.h>
#include <sys/devpolicy.h>
#include <sys/ctype.h>
#include <net/if.h>
#include <sys/rctl.h>
#include <sys/zone.h>
#include <sys/clock_impl.h>
#include <sys/ddi.h>
#include <sys/modhash.h>
#include <sys/sunldi_impl.h>
#include <sys/fs/dv_node.h>
#include <sys/fs/snode.h>

extern	pri_t	minclsyspri;

extern	rctl_hndl_t rc_project_locked_mem;
extern	rctl_hndl_t rc_zone_locked_mem;

#ifdef DEBUG
static int sunddi_debug = 0;
#endif /* DEBUG */

/* ddi_umem_unlock miscellaneous */

static	void	i_ddi_umem_unlock_thread_start(void);

static	kmutex_t	ddi_umem_unlock_mutex; /* unlock list mutex */
static	kcondvar_t	ddi_umem_unlock_cv; /* unlock list block/unblock */
static	kthread_t	*ddi_umem_unlock_thread;
/*
 * The ddi_umem_unlock FIFO list.  NULL head pointer indicates empty list.
 */
static	struct	ddi_umem_cookie *ddi_umem_unlock_head = NULL;
static	struct	ddi_umem_cookie *ddi_umem_unlock_tail = NULL;

/*
 * DDI(Sun) Function and flag definitions:
 */

#if defined(__x86)
/*
 * Used to indicate which entries were chosen from a range.
 */
char	*chosen_reg = "chosen-reg";
#endif

/*
 * Function used to ring system console bell
 */
void (*ddi_console_bell_func)(clock_t duration);

/*
 * Creating register mappings and handling interrupts:
 */

/*
 * Generic ddi_map: Call parent to fulfill request...
 */

int
ddi_map(dev_info_t *dp, ddi_map_req_t *mp, off_t offset,
    off_t len, caddr_t *addrp)
{
	dev_info_t *pdip;

	ASSERT(dp);
	pdip = (dev_info_t *)DEVI(dp)->devi_parent;
	return ((DEVI(pdip)->devi_ops->devo_bus_ops->bus_map)(pdip,
	    dp, mp, offset, len, addrp));
}

/*
 * ddi_apply_range: (Called by nexi only.)
 * Apply ranges in parent node dp, to child regspec rp...
 */

int
ddi_apply_range(dev_info_t *dp, dev_info_t *rdip, struct regspec *rp)
{
	return (i_ddi_apply_range(dp, rdip, rp));
}

int
ddi_map_regs(dev_info_t *dip, uint_t rnumber, caddr_t *kaddrp, off_t offset,
    off_t len)
{
	ddi_map_req_t mr;
#if defined(__x86)
	struct {
		int	bus;
		int	addr;
		int	size;
	} reg, *reglist;
	uint_t	length;
	int	rc;

	/*
	 * get the 'registers' or the 'reg' property.
	 * We look up the reg property as an array of
	 * int's.
	 */
	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "registers", (int **)&reglist, &length);
	if (rc != DDI_PROP_SUCCESS)
		rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "reg", (int **)&reglist, &length);
	if (rc == DDI_PROP_SUCCESS) {
		/*
		 * point to the required entry.
		 */
		reg = reglist[rnumber];
		reg.addr += offset;
		if (len != 0)
			reg.size = len;
		/*
		 * make a new property containing ONLY the required tuple.
		 */
		if (ddi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		    chosen_reg, (int *)&reg, (sizeof (reg)/sizeof (int)))
		    != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: cannot create '%s' "
			    "property", DEVI(dip)->devi_name,
			    DEVI(dip)->devi_instance, chosen_reg);
		}
		/*
		 * free the memory allocated by
		 * ddi_prop_lookup_int_array ().
		 */
		ddi_prop_free((void *)reglist);
	}
#endif
	mr.map_op = DDI_MO_MAP_LOCKED;
	mr.map_type = DDI_MT_RNUMBER;
	mr.map_obj.rnumber = rnumber;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = NULL;
	mr.map_vers = DDI_MAP_VERSION;

	/*
	 * Call my parent to map in my regs.
	 */

	return (ddi_map(dip, &mr, offset, len, kaddrp));
}

void
ddi_unmap_regs(dev_info_t *dip, uint_t rnumber, caddr_t *kaddrp, off_t offset,
    off_t len)
{
	ddi_map_req_t mr;

	mr.map_op = DDI_MO_UNMAP;
	mr.map_type = DDI_MT_RNUMBER;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_prot = PROT_READ | PROT_WRITE;	/* who cares? */
	mr.map_obj.rnumber = rnumber;
	mr.map_handlep = NULL;
	mr.map_vers = DDI_MAP_VERSION;

	/*
	 * Call my parent to unmap my regs.
	 */

	(void) ddi_map(dip, &mr, offset, len, kaddrp);
	*kaddrp = (caddr_t)0;
#if defined(__x86)
	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, chosen_reg);
#endif
}

int
ddi_bus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *vaddrp)
{
	return (i_ddi_bus_map(dip, rdip, mp, offset, len, vaddrp));
}

/*
 * nullbusmap:	The/DDI default bus_map entry point for nexi
 *		not conforming to the reg/range paradigm (i.e. scsi, etc.)
 *		with no HAT/MMU layer to be programmed at this level.
 *
 *		If the call is to map by rnumber, return an error,
 *		otherwise pass anything else up the tree to my parent.
 */
int
nullbusmap(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *vaddrp)
{
	_NOTE(ARGUNUSED(rdip))
	if (mp->map_type == DDI_MT_RNUMBER)
		return (DDI_ME_UNSUPPORTED);

	return (ddi_map(dip, mp, offset, len, vaddrp));
}

/*
 * ddi_rnumber_to_regspec: Not for use by leaf drivers.
 *			   Only for use by nexi using the reg/range paradigm.
 */
struct regspec *
ddi_rnumber_to_regspec(dev_info_t *dip, int rnumber)
{
	return (i_ddi_rnumber_to_regspec(dip, rnumber));
}


/*
 * Note that we allow the dip to be nil because we may be called
 * prior even to the instantiation of the devinfo tree itself - all
 * regular leaf and nexus drivers should always use a non-nil dip!
 *
 * We treat peek in a somewhat cavalier fashion .. assuming that we'll
 * simply get a synchronous fault as soon as we touch a missing address.
 *
 * Poke is rather more carefully handled because we might poke to a write
 * buffer, "succeed", then only find some time later that we got an
 * asynchronous fault that indicated that the address we were writing to
 * was not really backed by hardware.
 */

static int
i_ddi_peekpoke(dev_info_t *devi, ddi_ctl_enum_t cmd, size_t size,
    void *addr, void *value_p)
{
	union {
		uint64_t	u64;
		uint32_t	u32;
		uint16_t	u16;
		uint8_t		u8;
	} peekpoke_value;

	peekpoke_ctlops_t peekpoke_args;
	uint64_t dummy_result;
	int rval;

	/* Note: size is assumed to be correct;  it is not checked. */
	peekpoke_args.size = size;
	peekpoke_args.dev_addr = (uintptr_t)addr;
	peekpoke_args.handle = NULL;
	peekpoke_args.repcount = 1;
	peekpoke_args.flags = 0;

	if (cmd == DDI_CTLOPS_POKE) {
		switch (size) {
		case sizeof (uint8_t):
			peekpoke_value.u8 = *(uint8_t *)value_p;
			break;
		case sizeof (uint16_t):
			peekpoke_value.u16 = *(uint16_t *)value_p;
			break;
		case sizeof (uint32_t):
			peekpoke_value.u32 = *(uint32_t *)value_p;
			break;
		case sizeof (uint64_t):
			peekpoke_value.u64 = *(uint64_t *)value_p;
			break;
		}
	}

	peekpoke_args.host_addr = (uintptr_t)&peekpoke_value.u64;

	if (devi != NULL)
		rval = ddi_ctlops(devi, devi, cmd, &peekpoke_args,
		    &dummy_result);
	else
		rval = peekpoke_mem(cmd, &peekpoke_args);

	/*
	 * A NULL value_p is permitted by ddi_peek(9F); discard the result.
	 */
	if ((cmd == DDI_CTLOPS_PEEK) & (value_p != NULL)) {
		switch (size) {
		case sizeof (uint8_t):
			*(uint8_t *)value_p = peekpoke_value.u8;
			break;
		case sizeof (uint16_t):
			*(uint16_t *)value_p = peekpoke_value.u16;
			break;
		case sizeof (uint32_t):
			*(uint32_t *)value_p = peekpoke_value.u32;
			break;
		case sizeof (uint64_t):
			*(uint64_t *)value_p = peekpoke_value.u64;
			break;
		}
	}

	return (rval);
}

/*
 * Keep ddi_peek() and ddi_poke() in case 3rd parties are calling this.
 * they shouldn't be, but the 9f manpage kind of pseudo exposes it.
 */
int
ddi_peek(dev_info_t *devi, size_t size, void *addr, void *value_p)
{
	switch (size) {
	case sizeof (uint8_t):
	case sizeof (uint16_t):
	case sizeof (uint32_t):
	case sizeof (uint64_t):
		break;
	default:
		return (DDI_FAILURE);
	}

	return (i_ddi_peekpoke(devi, DDI_CTLOPS_PEEK, size, addr, value_p));
}

int
ddi_poke(dev_info_t *devi, size_t size, void *addr, void *value_p)
{
	switch (size) {
	case sizeof (uint8_t):
	case sizeof (uint16_t):
	case sizeof (uint32_t):
	case sizeof (uint64_t):
		break;
	default:
		return (DDI_FAILURE);
	}

	return (i_ddi_peekpoke(devi, DDI_CTLOPS_POKE, size, addr, value_p));
}

int
ddi_peek8(dev_info_t *dip, int8_t *addr, int8_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}

int
ddi_peek16(dev_info_t *dip, int16_t *addr, int16_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}

int
ddi_peek32(dev_info_t *dip, int32_t *addr, int32_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}

int
ddi_peek64(dev_info_t *dip, int64_t *addr, int64_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}


/*
 * We need to separate the old interfaces from the new ones and leave them
 * in here for a while. Previous versions of the OS defined the new interfaces
 * to the old interfaces. This way we can fix things up so that we can
 * eventually remove these interfaces.
 * e.g. A 3rd party module/driver using ddi_peek8 and built against S10
 * or earlier will actually have a reference to ddi_peekc in the binary.
 */
#ifdef _ILP32
int
ddi_peekc(dev_info_t *dip, int8_t *addr, int8_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}

int
ddi_peeks(dev_info_t *dip, int16_t *addr, int16_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}

int
ddi_peekl(dev_info_t *dip, int32_t *addr, int32_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}

int
ddi_peekd(dev_info_t *dip, int64_t *addr, int64_t *val_p)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_PEEK, sizeof (*val_p), addr,
	    val_p));
}
#endif /* _ILP32 */

int
ddi_poke8(dev_info_t *dip, int8_t *addr, int8_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}

int
ddi_poke16(dev_info_t *dip, int16_t *addr, int16_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}

int
ddi_poke32(dev_info_t *dip, int32_t *addr, int32_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}

int
ddi_poke64(dev_info_t *dip, int64_t *addr, int64_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}

/*
 * We need to separate the old interfaces from the new ones and leave them
 * in here for a while. Previous versions of the OS defined the new interfaces
 * to the old interfaces. This way we can fix things up so that we can
 * eventually remove these interfaces.
 * e.g. A 3rd party module/driver using ddi_poke8 and built against S10
 * or earlier will actually have a reference to ddi_pokec in the binary.
 */
#ifdef _ILP32
int
ddi_pokec(dev_info_t *dip, int8_t *addr, int8_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}

int
ddi_pokes(dev_info_t *dip, int16_t *addr, int16_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}

int
ddi_pokel(dev_info_t *dip, int32_t *addr, int32_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}

int
ddi_poked(dev_info_t *dip, int64_t *addr, int64_t val)
{
	return (i_ddi_peekpoke(dip, DDI_CTLOPS_POKE, sizeof (val), addr, &val));
}
#endif /* _ILP32 */

/*
 * ddi_peekpokeio() is used primarily by the mem drivers for moving
 * data to and from uio structures via peek and poke.  Note that we
 * use "internal" routines ddi_peek and ddi_poke to make this go
 * slightly faster, avoiding the call overhead ..
 */
int
ddi_peekpokeio(dev_info_t *devi, struct uio *uio, enum uio_rw rw,
    caddr_t addr, size_t len, uint_t xfersize)
{
	int64_t	ibuffer;
	int8_t w8;
	size_t sz;
	int o;

	if (xfersize > sizeof (long))
		xfersize = sizeof (long);

	while (len != 0) {
		if ((len | (uintptr_t)addr) & 1) {
			sz = sizeof (int8_t);
			if (rw == UIO_WRITE) {
				if ((o = uwritec(uio)) == -1)
					return (DDI_FAILURE);
				if (ddi_poke8(devi, (int8_t *)addr,
				    (int8_t)o) != DDI_SUCCESS)
					return (DDI_FAILURE);
			} else {
				if (i_ddi_peekpoke(devi, DDI_CTLOPS_PEEK, sz,
				    (int8_t *)addr, &w8) != DDI_SUCCESS)
					return (DDI_FAILURE);
				if (ureadc(w8, uio))
					return (DDI_FAILURE);
			}
		} else {
			switch (xfersize) {
			case sizeof (int64_t):
				if (((len | (uintptr_t)addr) &
				    (sizeof (int64_t) - 1)) == 0) {
					sz = xfersize;
					break;
				}
				/*FALLTHROUGH*/
			case sizeof (int32_t):
				if (((len | (uintptr_t)addr) &
				    (sizeof (int32_t) - 1)) == 0) {
					sz = xfersize;
					break;
				}
				/*FALLTHROUGH*/
			default:
				/*
				 * This still assumes that we might have an
				 * I/O bus out there that permits 16-bit
				 * transfers (and that it would be upset by
				 * 32-bit transfers from such locations).
				 */
				sz = sizeof (int16_t);
				break;
			}

			if (rw == UIO_READ) {
				if (i_ddi_peekpoke(devi, DDI_CTLOPS_PEEK, sz,
				    addr, &ibuffer) != DDI_SUCCESS)
					return (DDI_FAILURE);
			}

			if (uiomove(&ibuffer, sz, rw, uio))
				return (DDI_FAILURE);

			if (rw == UIO_WRITE) {
				if (i_ddi_peekpoke(devi, DDI_CTLOPS_POKE, sz,
				    addr, &ibuffer) != DDI_SUCCESS)
					return (DDI_FAILURE);
			}
		}
		addr += sz;
		len -= sz;
	}
	return (DDI_SUCCESS);
}

/*
 * These routines are used by drivers that do layered ioctls
 * On sparc, they're implemented in assembler to avoid spilling
 * register windows in the common (copyin) case ..
 */
#if !defined(__sparc)
int
ddi_copyin(const void *buf, void *kernbuf, size_t size, int flags)
{
	if (flags & FKIOCTL)
		return (kcopy(buf, kernbuf, size) ? -1 : 0);
	return (copyin(buf, kernbuf, size));
}

int
ddi_copyout(const void *buf, void *kernbuf, size_t size, int flags)
{
	if (flags & FKIOCTL)
		return (kcopy(buf, kernbuf, size) ? -1 : 0);
	return (copyout(buf, kernbuf, size));
}
#endif	/* !__sparc */

/*
 * Conversions in nexus pagesize units.  We don't duplicate the
 * 'nil dip' semantics of peek/poke because btopr/btop/ptob are DDI/DKI
 * routines anyway.
 */
unsigned long
ddi_btop(dev_info_t *dip, unsigned long bytes)
{
	unsigned long pages;

	(void) ddi_ctlops(dip, dip, DDI_CTLOPS_BTOP, &bytes, &pages);
	return (pages);
}

unsigned long
ddi_btopr(dev_info_t *dip, unsigned long bytes)
{
	unsigned long pages;

	(void) ddi_ctlops(dip, dip, DDI_CTLOPS_BTOPR, &bytes, &pages);
	return (pages);
}

unsigned long
ddi_ptob(dev_info_t *dip, unsigned long pages)
{
	unsigned long bytes;

	(void) ddi_ctlops(dip, dip, DDI_CTLOPS_PTOB, &pages, &bytes);
	return (bytes);
}

unsigned int
ddi_enter_critical(void)
{
	return ((uint_t)spl7());
}

void
ddi_exit_critical(unsigned int spl)
{
	splx((int)spl);
}

/*
 * Nexus ctlops punter
 */

#if !defined(__sparc)
/*
 * Request bus_ctl parent to handle a bus_ctl request
 *
 * (The sparc version is in sparc_ddi.s)
 */
int
ddi_ctlops(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t op, void *a, void *v)
{
	int (*fp)();

	if (!d || !r)
		return (DDI_FAILURE);

	if ((d = (dev_info_t *)DEVI(d)->devi_bus_ctl) == NULL)
		return (DDI_FAILURE);

	fp = DEVI(d)->devi_ops->devo_bus_ops->bus_ctl;
	return ((*fp)(d, r, op, a, v));
}

#endif

/*
 * DMA/DVMA setup
 */

#if defined(__sparc)
static ddi_dma_lim_t standard_limits = {
	(uint_t)0,	/* addr_t dlim_addr_lo */
	(uint_t)-1,	/* addr_t dlim_addr_hi */
	(uint_t)-1,	/* uint_t dlim_cntr_max */
	(uint_t)1,	/* uint_t dlim_burstsizes */
	(uint_t)1,	/* uint_t dlim_minxfer */
	0		/* uint_t dlim_dmaspeed */
};
#elif defined(__x86)
static ddi_dma_lim_t standard_limits = {
	(uint_t)0,		/* addr_t dlim_addr_lo */
	(uint_t)0xffffff,	/* addr_t dlim_addr_hi */
	(uint_t)0,		/* uint_t dlim_cntr_max */
	(uint_t)0x00000001,	/* uint_t dlim_burstsizes */
	(uint_t)DMA_UNIT_8,	/* uint_t dlim_minxfer */
	(uint_t)0,		/* uint_t dlim_dmaspeed */
	(uint_t)0x86<<24+0,	/* uint_t dlim_version */
	(uint_t)0xffff,		/* uint_t dlim_adreg_max */
	(uint_t)0xffff,		/* uint_t dlim_ctreg_max */
	(uint_t)512,		/* uint_t dlim_granular */
	(int)1,			/* int dlim_sgllen */
	(uint_t)0xffffffff	/* uint_t dlim_reqsizes */
};

#endif

#if !defined(__sparc)
/*
 * Request bus_dma_ctl parent to fiddle with a dma request.
 *
 * (The sparc version is in sparc_subr.s)
 */
int
ddi_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objp, uint_t flags)
{
	int (*fp)();

	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_ctl;
	fp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_ctl;
	return ((*fp) (dip, rdip, handle, request, offp, lenp, objp, flags));
}
#endif

/*
 * For all DMA control functions, call the DMA control
 * routine and return status.
 *
 * Just plain assume that the parent is to be called.
 * If a nexus driver or a thread outside the framework
 * of a nexus driver or a leaf driver calls these functions,
 * it is up to them to deal with the fact that the parent's
 * bus_dma_ctl function will be the first one called.
 */

#define	HD	((ddi_dma_impl_t *)h)->dmai_rdip

/*
 * This routine is left in place to satisfy link dependencies
 * for any 3rd party nexus drivers that rely on it.  It is never
 * called, though.
 */
/*ARGSUSED*/
int
ddi_dma_map(dev_info_t *dip, dev_info_t *rdip,
	struct ddi_dma_req *dmareqp, ddi_dma_handle_t *handlep)
{
	return (DDI_FAILURE);
}

#if !defined(__sparc)

/*
 * The SPARC versions of these routines are done in assembler to
 * save register windows, so they're in sparc_subr.s.
 */

int
ddi_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_attr_t *,
	    int (*)(caddr_t), caddr_t, ddi_dma_handle_t *);

	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_allochdl;

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_allochdl;
	return ((*funcp)(dip, rdip, attr, waitfp, arg, handlep));
}

int
ddi_dma_freehdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t handlep)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t);

	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_allochdl;

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_freehdl;
	return ((*funcp)(dip, rdip, handlep));
}

int
ddi_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cp, uint_t *ccountp)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t,
	    struct ddi_dma_req *, ddi_dma_cookie_t *, uint_t *);

	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_bindhdl;

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_bindhdl;
	return ((*funcp)(dip, rdip, handle, dmareq, cp, ccountp));
}

int
ddi_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t);

	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_unbindhdl;

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_unbindhdl;
	return ((*funcp)(dip, rdip, handle));
}


int
ddi_dma_flush(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len,
    uint_t cache_flags)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t,
	    off_t, size_t, uint_t);

	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_flush;

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_flush;
	return ((*funcp)(dip, rdip, handle, off, len, cache_flags));
}

int
ddi_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp,
    size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t,
	    uint_t, off_t *, size_t *, ddi_dma_cookie_t *, uint_t *);

	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_win;

	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_win;
	return ((*funcp)(dip, rdip, handle, win, offp, lenp,
	    cookiep, ccountp));
}

int
ddi_dma_sync(ddi_dma_handle_t h, off_t o, size_t l, uint_t whom)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)h;
	dev_info_t *dip, *rdip;
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t, off_t,
	    size_t, uint_t);

	/*
	 * the DMA nexus driver will set DMP_NOSYNC if the
	 * platform does not require any sync operation. For
	 * example if the memory is uncached or consistent
	 * and without any I/O write buffers involved.
	 */
	if ((hp->dmai_rflags & DMP_NOSYNC) == DMP_NOSYNC)
		return (DDI_SUCCESS);

	dip = rdip = hp->dmai_rdip;
	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_flush;
	funcp = DEVI(dip)->devi_ops->devo_bus_ops->bus_dma_flush;
	return ((*funcp)(dip, rdip, h, o, l, whom));
}

int
ddi_dma_unbind_handle(ddi_dma_handle_t h)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)h;
	dev_info_t *dip, *rdip;
	int (*funcp)(dev_info_t *, dev_info_t *, ddi_dma_handle_t);

	dip = rdip = hp->dmai_rdip;
	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_unbindhdl;
	funcp = DEVI(rdip)->devi_bus_dma_unbindfunc;
	return ((*funcp)(dip, rdip, h));
}

#endif	/* !__sparc */

/*
 * DMA burst sizes, and transfer minimums
 */

int
ddi_dma_burstsizes(ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *dimp = (ddi_dma_impl_t *)handle;

	if (!dimp)
		return (0);
	else
		return (dimp->dmai_burstsizes);
}

int
ddi_iomin(dev_info_t *a, int i, int stream)
{
	int r;

	/*
	 * Make sure that the initial value is sane
	 */
	if (i & (i - 1))
		return (0);
	if (i == 0)
		i = (stream) ? 4 : 1;

	r = ddi_ctlops(a, a,
	    DDI_CTLOPS_IOMIN, (void *)(uintptr_t)stream, (void *)&i);
	if (r != DDI_SUCCESS || (i & (i - 1)))
		return (0);
	return (i);
}

/*
 * Given two DMA attribute structures, apply the attributes
 * of one to the other, following the rules of attributes
 * and the wishes of the caller.
 *
 * The rules of DMA attribute structures are that you cannot
 * make things *less* restrictive as you apply one set
 * of attributes to another.
 *
 */
void
ddi_dma_attr_merge(ddi_dma_attr_t *attr, ddi_dma_attr_t *mod)
{
	attr->dma_attr_addr_lo =
	    MAX(attr->dma_attr_addr_lo, mod->dma_attr_addr_lo);
	attr->dma_attr_addr_hi =
	    MIN(attr->dma_attr_addr_hi, mod->dma_attr_addr_hi);
	attr->dma_attr_count_max =
	    MIN(attr->dma_attr_count_max, mod->dma_attr_count_max);
	attr->dma_attr_align =
	    MAX(attr->dma_attr_align,  mod->dma_attr_align);
	attr->dma_attr_burstsizes =
	    (uint_t)(attr->dma_attr_burstsizes & mod->dma_attr_burstsizes);
	attr->dma_attr_minxfer =
	    maxbit(attr->dma_attr_minxfer, mod->dma_attr_minxfer);
	attr->dma_attr_maxxfer =
	    MIN(attr->dma_attr_maxxfer, mod->dma_attr_maxxfer);
	attr->dma_attr_seg = MIN(attr->dma_attr_seg, mod->dma_attr_seg);
	attr->dma_attr_sgllen = MIN((uint_t)attr->dma_attr_sgllen,
	    (uint_t)mod->dma_attr_sgllen);
	attr->dma_attr_granular =
	    MAX(attr->dma_attr_granular, mod->dma_attr_granular);
}

/*
 * mmap/segmap interface:
 */

/*
 * ddi_segmap:		setup the default segment driver. Calls the drivers
 *			XXmmap routine to validate the range to be mapped.
 *			Return ENXIO of the range is not valid.  Create
 *			a seg_dev segment that contains all of the
 *			necessary information and will reference the
 *			default segment driver routines. It returns zero
 *			on success or non-zero on failure.
 */
int
ddi_segmap(dev_t dev, off_t offset, struct as *asp, caddr_t *addrp, off_t len,
    uint_t prot, uint_t maxprot, uint_t flags, cred_t *credp)
{
	extern int spec_segmap(dev_t, off_t, struct as *, caddr_t *,
	    off_t, uint_t, uint_t, uint_t, struct cred *);

	return (spec_segmap(dev, offset, asp, addrp, len,
	    prot, maxprot, flags, credp));
}

/*
 * ddi_map_fault:	Resolve mappings at fault time.  Used by segment
 *			drivers. Allows each successive parent to resolve
 *			address translations and add its mappings to the
 *			mapping list supplied in the page structure. It
 *			returns zero on success	or non-zero on failure.
 */

int
ddi_map_fault(dev_info_t *dip, struct hat *hat, struct seg *seg,
    caddr_t addr, struct devpage *dp, pfn_t pfn, uint_t prot, uint_t lock)
{
	return (i_ddi_map_fault(dip, dip, hat, seg, addr, dp, pfn, prot, lock));
}

/*
 * ddi_device_mapping_check:	Called from ddi_segmap_setup.
 *	Invokes platform specific DDI to determine whether attributes specified
 *	in attr(9s) are	valid for the region of memory that will be made
 *	available for direct access to user process via the mmap(2) system call.
 */
int
ddi_device_mapping_check(dev_t dev, ddi_device_acc_attr_t *accattrp,
    uint_t rnumber, uint_t *hat_flags)
{
	ddi_acc_handle_t handle;
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int result;
	dev_info_t *dip;

	/*
	 * we use e_ddi_hold_devi_by_dev to search for the devi.  We
	 * release it immediately since it should already be held by
	 * a devfs vnode.
	 */
	if ((dip =
	    e_ddi_hold_devi_by_dev(dev, E_DDI_HOLD_DEVI_NOATTACH)) == NULL)
		return (-1);
	ddi_release_devi(dip);		/* for e_ddi_hold_devi_by_dev() */

	/*
	 * Allocate and initialize the common elements of data
	 * access handle.
	 */
	handle = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	if (handle == NULL)
		return (-1);

	hp = impl_acc_hdl_get(handle);
	hp->ah_vers = VERS_ACCHDL;
	hp->ah_dip = dip;
	hp->ah_rnumber = rnumber;
	hp->ah_offset = 0;
	hp->ah_len = 0;
	hp->ah_acc = *accattrp;

	/*
	 * Set up the mapping request and call to parent.
	 */
	mr.map_op = DDI_MO_MAP_HANDLE;
	mr.map_type = DDI_MT_RNUMBER;
	mr.map_obj.rnumber = rnumber;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;
	result = ddi_map(dip, &mr, 0, 0, NULL);

	/*
	 * Region must be mappable, pick up flags from the framework.
	 */
	*hat_flags = hp->ah_hat_flags;

	impl_acc_hdl_free(handle);

	/*
	 * check for end result.
	 */
	if (result != DDI_SUCCESS)
		return (-1);
	return (0);
}


/*
 * Property functions:	 See also, ddipropdefs.h.
 *
 * These functions are the framework for the property functions,
 * i.e. they support software defined properties.  All implementation
 * specific property handling (i.e.: self-identifying devices and
 * PROM defined properties are handled in the implementation specific
 * functions (defined in ddi_implfuncs.h).
 */

/*
 * nopropop:	Shouldn't be called, right?
 */
int
nopropop(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	_NOTE(ARGUNUSED(dev, dip, prop_op, mod_flags, name, valuep, lengthp))
	return (DDI_PROP_NOT_FOUND);
}

#ifdef	DDI_PROP_DEBUG
int ddi_prop_debug_flag = 0;

int
ddi_prop_debug(int enable)
{
	int prev = ddi_prop_debug_flag;

	if ((enable != 0) || (prev != 0))
		printf("ddi_prop_debug: debugging %s\n",
		    enable ? "enabled" : "disabled");
	ddi_prop_debug_flag = enable;
	return (prev);
}

#endif	/* DDI_PROP_DEBUG */

/*
 * Search a property list for a match, if found return pointer
 * to matching prop struct, else return NULL.
 */

ddi_prop_t *
i_ddi_prop_search(dev_t dev, char *name, uint_t flags, ddi_prop_t **list_head)
{
	ddi_prop_t	*propp;

	/*
	 * find the property in child's devinfo:
	 * Search order defined by this search function is first matching
	 * property with input dev == DDI_DEV_T_ANY matching any dev or
	 * dev == propp->prop_dev, name == propp->name, and the correct
	 * data type as specified in the flags.  If a DDI_DEV_T_NONE dev
	 * value made it this far then it implies a DDI_DEV_T_ANY search.
	 */
	if (dev == DDI_DEV_T_NONE)
		dev = DDI_DEV_T_ANY;

	for (propp = *list_head; propp != NULL; propp = propp->prop_next)  {

		if (!DDI_STRSAME(propp->prop_name, name))
			continue;

		if ((dev != DDI_DEV_T_ANY) && (propp->prop_dev != dev))
			continue;

		if (((propp->prop_flags & flags) & DDI_PROP_TYPE_MASK) == 0)
			continue;

		return (propp);
	}

	return ((ddi_prop_t *)0);
}

/*
 * Search for property within devnames structures
 */
ddi_prop_t *
i_ddi_search_global_prop(dev_t dev, char *name, uint_t flags)
{
	major_t		major;
	struct devnames	*dnp;
	ddi_prop_t	*propp;

	/*
	 * Valid dev_t value is needed to index into the
	 * correct devnames entry, therefore a dev_t
	 * value of DDI_DEV_T_ANY is not appropriate.
	 */
	ASSERT(dev != DDI_DEV_T_ANY);
	if (dev == DDI_DEV_T_ANY) {
		return ((ddi_prop_t *)0);
	}

	major = getmajor(dev);
	dnp = &(devnamesp[major]);

	if (dnp->dn_global_prop_ptr == NULL)
		return ((ddi_prop_t *)0);

	LOCK_DEV_OPS(&dnp->dn_lock);

	for (propp = dnp->dn_global_prop_ptr->prop_list;
	    propp != NULL;
	    propp = (ddi_prop_t *)propp->prop_next) {

		if (!DDI_STRSAME(propp->prop_name, name))
			continue;

		if ((!(flags & DDI_PROP_ROOTNEX_GLOBAL)) &&
		    (!(flags & LDI_DEV_T_ANY)) && (propp->prop_dev != dev))
			continue;

		if (((propp->prop_flags & flags) & DDI_PROP_TYPE_MASK) == 0)
			continue;

		/* Property found, return it */
		UNLOCK_DEV_OPS(&dnp->dn_lock);
		return (propp);
	}

	UNLOCK_DEV_OPS(&dnp->dn_lock);
	return ((ddi_prop_t *)0);
}

static char prop_no_mem_msg[] = "can't allocate memory for ddi property <%s>";

/*
 * ddi_prop_search_global:
 *	Search the global property list within devnames
 *	for the named property.  Return the encoded value.
 */
static int
i_ddi_prop_search_global(dev_t dev, uint_t flags, char *name,
    void *valuep, uint_t *lengthp)
{
	ddi_prop_t	*propp;
	caddr_t		buffer;

	propp =  i_ddi_search_global_prop(dev, name, flags);

	/* Property NOT found, bail */
	if (propp == (ddi_prop_t *)0)
		return (DDI_PROP_NOT_FOUND);

	if (propp->prop_flags & DDI_PROP_UNDEF_IT)
		return (DDI_PROP_UNDEFINED);

	if ((buffer = kmem_alloc(propp->prop_len,
	    (flags & DDI_PROP_CANSLEEP) ? KM_SLEEP : KM_NOSLEEP)) == NULL) {
		cmn_err(CE_CONT, prop_no_mem_msg, name);
		return (DDI_PROP_NO_MEMORY);
	}

	/*
	 * Return the encoded data
	 */
	*(caddr_t *)valuep = buffer;
	*lengthp = propp->prop_len;
	bcopy(propp->prop_val, buffer, propp->prop_len);

	return (DDI_PROP_SUCCESS);
}

/*
 * ddi_prop_search_common:	Lookup and return the encoded value
 */
int
ddi_prop_search_common(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    uint_t flags, char *name, void *valuep, uint_t *lengthp)
{
	ddi_prop_t	*propp;
	int		i;
	caddr_t		buffer;
	caddr_t		prealloc = NULL;
	int		plength = 0;
	dev_info_t	*pdip;
	int		(*bop)();

	/*CONSTANTCONDITION*/
	while (1)  {

		mutex_enter(&(DEVI(dip)->devi_lock));


		/*
		 * find the property in child's devinfo:
		 * Search order is:
		 *	1. driver defined properties
		 *	2. system defined properties
		 *	3. driver global properties
		 *	4. boot defined properties
		 */

		propp = i_ddi_prop_search(dev, name, flags,
		    &(DEVI(dip)->devi_drv_prop_ptr));
		if (propp == NULL)  {
			propp = i_ddi_prop_search(dev, name, flags,
			    &(DEVI(dip)->devi_sys_prop_ptr));
		}
		if ((propp == NULL) && DEVI(dip)->devi_global_prop_list) {
			propp = i_ddi_prop_search(dev, name, flags,
			    &DEVI(dip)->devi_global_prop_list->prop_list);
		}

		if (propp == NULL)  {
			propp = i_ddi_prop_search(dev, name, flags,
			    &(DEVI(dip)->devi_hw_prop_ptr));
		}

		/*
		 * Software property found?
		 */
		if (propp != (ddi_prop_t *)0)	{

			/*
			 * If explicit undefine, return now.
			 */
			if (propp->prop_flags & DDI_PROP_UNDEF_IT) {
				mutex_exit(&(DEVI(dip)->devi_lock));
				if (prealloc)
					kmem_free(prealloc, plength);
				return (DDI_PROP_UNDEFINED);
			}

			/*
			 * If we only want to know if it exists, return now
			 */
			if (prop_op == PROP_EXISTS) {
				mutex_exit(&(DEVI(dip)->devi_lock));
				ASSERT(prealloc == NULL);
				return (DDI_PROP_SUCCESS);
			}

			/*
			 * If length only request or prop length == 0,
			 * service request and return now.
			 */
			if ((prop_op == PROP_LEN) ||(propp->prop_len == 0)) {
				*lengthp = propp->prop_len;

				/*
				 * if prop_op is PROP_LEN_AND_VAL_ALLOC
				 * that means prop_len is 0, so set valuep
				 * also to NULL
				 */
				if (prop_op == PROP_LEN_AND_VAL_ALLOC)
					*(caddr_t *)valuep = NULL;

				mutex_exit(&(DEVI(dip)->devi_lock));
				if (prealloc)
					kmem_free(prealloc, plength);
				return (DDI_PROP_SUCCESS);
			}

			/*
			 * If LEN_AND_VAL_ALLOC and the request can sleep,
			 * drop the mutex, allocate the buffer, and go
			 * through the loop again.  If we already allocated
			 * the buffer, and the size of the property changed,
			 * keep trying...
			 */
			if ((prop_op == PROP_LEN_AND_VAL_ALLOC) &&
			    (flags & DDI_PROP_CANSLEEP))  {
				if (prealloc && (propp->prop_len != plength)) {
					kmem_free(prealloc, plength);
					prealloc = NULL;
				}
				if (prealloc == NULL)  {
					plength = propp->prop_len;
					mutex_exit(&(DEVI(dip)->devi_lock));
					prealloc = kmem_alloc(plength,
					    KM_SLEEP);
					continue;
				}
			}

			/*
			 * Allocate buffer, if required.  Either way,
			 * set `buffer' variable.
			 */
			i = *lengthp;			/* Get callers length */
			*lengthp = propp->prop_len;	/* Set callers length */

			switch (prop_op) {

			case PROP_LEN_AND_VAL_ALLOC:

				if (prealloc == NULL) {
					buffer = kmem_alloc(propp->prop_len,
					    KM_NOSLEEP);
				} else {
					buffer = prealloc;
				}

				if (buffer == NULL)  {
					mutex_exit(&(DEVI(dip)->devi_lock));
					cmn_err(CE_CONT, prop_no_mem_msg, name);
					return (DDI_PROP_NO_MEMORY);
				}
				/* Set callers buf ptr */
				*(caddr_t *)valuep = buffer;
				break;

			case PROP_LEN_AND_VAL_BUF:

				if (propp->prop_len > (i)) {
					mutex_exit(&(DEVI(dip)->devi_lock));
					return (DDI_PROP_BUF_TOO_SMALL);
				}

				buffer = valuep;  /* Get callers buf ptr */
				break;

			default:
				break;
			}

			/*
			 * Do the copy.
			 */
			bcopy(propp->prop_val, buffer, propp->prop_len);
			mutex_exit(&(DEVI(dip)->devi_lock));
			return (DDI_PROP_SUCCESS);
		}

		mutex_exit(&(DEVI(dip)->devi_lock));
		if (prealloc)
			kmem_free(prealloc, plength);
		prealloc = NULL;

		/*
		 * Prop not found, call parent bus_ops to deal with possible
		 * h/w layer (possible PROM defined props, etc.) and to
		 * possibly ascend the hierarchy, if allowed by flags.
		 */
		pdip = (dev_info_t *)DEVI(dip)->devi_parent;

		/*
		 * One last call for the root driver PROM props?
		 */
		if (dip == ddi_root_node())  {
			return (ddi_bus_prop_op(dev, dip, dip, prop_op,
			    flags, name, valuep, (int *)lengthp));
		}

		/*
		 * We may have been called to check for properties
		 * within a single devinfo node that has no parent -
		 * see make_prop()
		 */
		if (pdip == NULL) {
			ASSERT((flags &
			    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM)) ==
			    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM));
			return (DDI_PROP_NOT_FOUND);
		}

		/*
		 * Instead of recursing, we do iterative calls up the tree.
		 * As a bit of optimization, skip the bus_op level if the
		 * node is a s/w node and if the parent's bus_prop_op function
		 * is `ddi_bus_prop_op', because we know that in this case,
		 * this function does nothing.
		 *
		 * 4225415: If the parent isn't attached, or the child
		 * hasn't been named by the parent yet, use the default
		 * ddi_bus_prop_op as a proxy for the parent.  This
		 * allows property lookups in any child/parent state to
		 * include 'prom' and inherited properties, even when
		 * there are no drivers attached to the child or parent.
		 */

		bop = ddi_bus_prop_op;
		if (i_ddi_devi_attached(pdip) &&
		    (i_ddi_node_state(dip) >= DS_INITIALIZED))
			bop = DEVI(pdip)->devi_ops->devo_bus_ops->bus_prop_op;

		i = DDI_PROP_NOT_FOUND;

		if ((bop != ddi_bus_prop_op) || ndi_dev_is_prom_node(dip)) {
			i = (*bop)(dev, pdip, dip, prop_op,
			    flags | DDI_PROP_DONTPASS,
			    name, valuep, lengthp);
		}

		if ((flags & DDI_PROP_DONTPASS) ||
		    (i != DDI_PROP_NOT_FOUND))
			return (i);

		dip = pdip;
	}
	/*NOTREACHED*/
}


/*
 * ddi_prop_op: The basic property operator for drivers.
 *
 * In ddi_prop_op, the type of valuep is interpreted based on prop_op:
 *
 *	prop_op			valuep
 *	------			------
 *
 *	PROP_LEN		<unused>
 *
 *	PROP_LEN_AND_VAL_BUF	Pointer to callers buffer
 *
 *	PROP_LEN_AND_VAL_ALLOC	Address of callers pointer (will be set to
 *				address of allocated buffer, if successful)
 */
int
ddi_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int	i;

	ASSERT((mod_flags & DDI_PROP_TYPE_MASK) == 0);

	/*
	 * If this was originally an LDI prop lookup then we bail here.
	 * The reason is that the LDI property lookup interfaces first call
	 * a drivers prop_op() entry point to allow it to override
	 * properties.  But if we've made it here, then the driver hasn't
	 * overriden any properties.  We don't want to continue with the
	 * property search here because we don't have any type inforamtion.
	 * When we return failure, the LDI interfaces will then proceed to
	 * call the typed property interfaces to look up the property.
	 */
	if (mod_flags & DDI_PROP_DYNAMIC)
		return (DDI_PROP_NOT_FOUND);

	/*
	 * check for pre-typed property consumer asking for typed property:
	 * see e_ddi_getprop_int64.
	 */
	if (mod_flags & DDI_PROP_CONSUMER_TYPED)
		mod_flags |= DDI_PROP_TYPE_INT64;
	mod_flags |= DDI_PROP_TYPE_ANY;

	i = ddi_prop_search_common(dev, dip, prop_op,
	    mod_flags, name, valuep, (uint_t *)lengthp);
	if (i == DDI_PROP_FOUND_1275)
		return (DDI_PROP_SUCCESS);
	return (i);
}

/*
 * ddi_prop_op_nblocks_blksize: The basic property operator for drivers that
 * maintain size in number of blksize blocks.  Provides a dynamic property
 * implementation for size oriented properties based on nblocks64 and blksize
 * values passed in by the driver.  Fallback to ddi_prop_op if the nblocks64
 * is too large.  This interface should not be used with a nblocks64 that
 * represents the driver's idea of how to represent unknown, if nblocks is
 * unknown use ddi_prop_op.
 */
int
ddi_prop_op_nblocks_blksize(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp,
    uint64_t nblocks64, uint_t blksize)
{
	uint64_t size64;
	int	blkshift;

	/* convert block size to shift value */
	ASSERT(BIT_ONLYONESET(blksize));
	blkshift = highbit(blksize) - 1;

	/*
	 * There is no point in supporting nblocks64 values that don't have
	 * an accurate uint64_t byte count representation.
	 */
	if (nblocks64 >= (UINT64_MAX >> blkshift))
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));

	size64 = nblocks64 << blkshift;
	return (ddi_prop_op_size_blksize(dev, dip, prop_op, mod_flags,
	    name, valuep, lengthp, size64, blksize));
}

/*
 * ddi_prop_op_nblocks: ddi_prop_op_nblocks_blksize with DEV_BSIZE blksize.
 */
int
ddi_prop_op_nblocks(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp, uint64_t nblocks64)
{
	return (ddi_prop_op_nblocks_blksize(dev, dip, prop_op,
	    mod_flags, name, valuep, lengthp, nblocks64, DEV_BSIZE));
}

/*
 * ddi_prop_op_size_blksize: The basic property operator for block drivers that
 * maintain size in bytes. Provides a of dynamic property implementation for
 * size oriented properties based on size64 value and blksize passed in by the
 * driver.  Fallback to ddi_prop_op if the size64 is too large. This interface
 * should not be used with a size64 that represents the driver's idea of how
 * to represent unknown, if size is unknown use ddi_prop_op.
 *
 * NOTE: the legacy "nblocks"/"size" properties are treated as 32-bit unsigned
 * integers. While the most likely interface to request them ([bc]devi_size)
 * is declared int (signed) there is no enforcement of this, which means we
 * can't enforce limitations here without risking regression.
 */
int
ddi_prop_op_size_blksize(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp, uint64_t size64,
    uint_t blksize)
{
	uint64_t nblocks64;
	int	callers_length;
	caddr_t	buffer;
	int	blkshift;

	/*
	 * This is a kludge to support capture of size(9P) pure dynamic
	 * properties in snapshots for non-cmlb code (without exposing
	 * i_ddi_prop_dyn changes). When everyone uses cmlb, this code
	 * should be removed.
	 */
	if (i_ddi_prop_dyn_driver_get(dip) == NULL) {
		static i_ddi_prop_dyn_t prop_dyn_size[] = {
		    {"Size",		DDI_PROP_TYPE_INT64,	S_IFCHR},
		    {"Nblocks",		DDI_PROP_TYPE_INT64,	S_IFBLK},
		    {NULL}
		};
		i_ddi_prop_dyn_driver_set(dip, prop_dyn_size);
	}

	/* convert block size to shift value */
	ASSERT(BIT_ONLYONESET(blksize));
	blkshift = highbit(blksize) - 1;

	/* compute DEV_BSIZE nblocks value */
	nblocks64 = size64 >> blkshift;

	/* get callers length, establish length of our dynamic properties */
	callers_length = *lengthp;

	if (strcmp(name, "Nblocks") == 0)
		*lengthp = sizeof (uint64_t);
	else if (strcmp(name, "Size") == 0)
		*lengthp = sizeof (uint64_t);
	else if ((strcmp(name, "nblocks") == 0) && (nblocks64 < UINT_MAX))
		*lengthp = sizeof (uint32_t);
	else if ((strcmp(name, "size") == 0) && (size64 < UINT_MAX))
		*lengthp = sizeof (uint32_t);
	else if ((strcmp(name, "blksize") == 0) && (blksize < UINT_MAX))
		*lengthp = sizeof (uint32_t);
	else {
		/* fallback to ddi_prop_op */
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	}

	/* service request for the length of the property */
	if (prop_op == PROP_LEN)
		return (DDI_PROP_SUCCESS);

	switch (prop_op) {
	case PROP_LEN_AND_VAL_ALLOC:
		if ((buffer = kmem_alloc(*lengthp,
		    (mod_flags & DDI_PROP_CANSLEEP) ?
		    KM_SLEEP : KM_NOSLEEP)) == NULL)
			return (DDI_PROP_NO_MEMORY);

		*(caddr_t *)valuep = buffer;	/* set callers buf ptr */
		break;

	case PROP_LEN_AND_VAL_BUF:
		/* the length of the property and the request must match */
		if (callers_length != *lengthp)
			return (DDI_PROP_INVAL_ARG);

		buffer = valuep;		/* get callers buf ptr */
		break;

	default:
		return (DDI_PROP_INVAL_ARG);
	}

	/* transfer the value into the buffer */
	if (strcmp(name, "Nblocks") == 0)
		*((uint64_t *)buffer) = nblocks64;
	else if (strcmp(name, "Size") == 0)
		*((uint64_t *)buffer) = size64;
	else if (strcmp(name, "nblocks") == 0)
		*((uint32_t *)buffer) = (uint32_t)nblocks64;
	else if (strcmp(name, "size") == 0)
		*((uint32_t *)buffer) = (uint32_t)size64;
	else if (strcmp(name, "blksize") == 0)
		*((uint32_t *)buffer) = (uint32_t)blksize;
	return (DDI_PROP_SUCCESS);
}

/*
 * ddi_prop_op_size: ddi_prop_op_size_blksize with DEV_BSIZE block size.
 */
int
ddi_prop_op_size(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
    int mod_flags, char *name, caddr_t valuep, int *lengthp, uint64_t size64)
{
	return (ddi_prop_op_size_blksize(dev, dip, prop_op,
	    mod_flags, name, valuep, lengthp, size64, DEV_BSIZE));
}

/*
 * Variable length props...
 */

/*
 * ddi_getlongprop:	Get variable length property len+val into a buffer
 *		allocated by property provider via kmem_alloc. Requester
 *		is responsible for freeing returned property via kmem_free.
 *
 *	Arguments:
 *
 *	dev_t:	Input:	dev_t of property.
 *	dip:	Input:	dev_info_t pointer of child.
 *	flags:	Input:	Possible flag modifiers are:
 *		DDI_PROP_DONTPASS:	Don't pass to parent if prop not found.
 *		DDI_PROP_CANSLEEP:	Memory allocation may sleep.
 *	name:	Input:	name of property.
 *	valuep:	Output:	Addr of callers buffer pointer.
 *	lengthp:Output:	*lengthp will contain prop length on exit.
 *
 *	Possible Returns:
 *
 *		DDI_PROP_SUCCESS:	Prop found and returned.
 *		DDI_PROP_NOT_FOUND:	Prop not found
 *		DDI_PROP_UNDEFINED:	Prop explicitly undefined.
 *		DDI_PROP_NO_MEMORY:	Prop found, but unable to alloc mem.
 */

int
ddi_getlongprop(dev_t dev, dev_info_t *dip, int flags,
    char *name, caddr_t valuep, int *lengthp)
{
	return (ddi_prop_op(dev, dip, PROP_LEN_AND_VAL_ALLOC,
	    flags, name, valuep, lengthp));
}

/*
 *
 * ddi_getlongprop_buf:		Get long prop into pre-allocated callers
 *				buffer. (no memory allocation by provider).
 *
 *	dev_t:	Input:	dev_t of property.
 *	dip:	Input:	dev_info_t pointer of child.
 *	flags:	Input:	DDI_PROP_DONTPASS or NULL
 *	name:	Input:	name of property
 *	valuep:	Input:	ptr to callers buffer.
 *	lengthp:I/O:	ptr to length of callers buffer on entry,
 *			actual length of property on exit.
 *
 *	Possible returns:
 *
 *		DDI_PROP_SUCCESS	Prop found and returned
 *		DDI_PROP_NOT_FOUND	Prop not found
 *		DDI_PROP_UNDEFINED	Prop explicitly undefined.
 *		DDI_PROP_BUF_TOO_SMALL	Prop found, callers buf too small,
 *					no value returned, but actual prop
 *					length returned in *lengthp
 *
 */

int
ddi_getlongprop_buf(dev_t dev, dev_info_t *dip, int flags,
    char *name, caddr_t valuep, int *lengthp)
{
	return (ddi_prop_op(dev, dip, PROP_LEN_AND_VAL_BUF,
	    flags, name, valuep, lengthp));
}

/*
 * Integer/boolean sized props.
 *
 * Call is value only... returns found boolean or int sized prop value or
 * defvalue if prop not found or is wrong length or is explicitly undefined.
 * Only flag is DDI_PROP_DONTPASS...
 *
 * By convention, this interface returns boolean (0) sized properties
 * as value (int)1.
 *
 * This never returns an error, if property not found or specifically
 * undefined, the input `defvalue' is returned.
 */

int
ddi_getprop(dev_t dev, dev_info_t *dip, int flags, char *name, int defvalue)
{
	int	propvalue = defvalue;
	int	proplength = sizeof (int);
	int	error;

	error = ddi_prop_op(dev, dip, PROP_LEN_AND_VAL_BUF,
	    flags, name, (caddr_t)&propvalue, &proplength);

	if ((error == DDI_PROP_SUCCESS) && (proplength == 0))
		propvalue = 1;

	return (propvalue);
}

/*
 * Get prop length interface: flags are 0 or DDI_PROP_DONTPASS
 * if returns DDI_PROP_SUCCESS, length returned in *lengthp.
 */

int
ddi_getproplen(dev_t dev, dev_info_t *dip, int flags, char *name, int *lengthp)
{
	return (ddi_prop_op(dev, dip, PROP_LEN, flags, name, NULL, lengthp));
}

/*
 * Allocate a struct prop_driver_data, along with 'size' bytes
 * for decoded property data.  This structure is freed by
 * calling ddi_prop_free(9F).
 */
static void *
ddi_prop_decode_alloc(size_t size, void (*prop_free)(struct prop_driver_data *))
{
	struct prop_driver_data *pdd;

	/*
	 * Allocate a structure with enough memory to store the decoded data.
	 */
	pdd = kmem_zalloc(sizeof (struct prop_driver_data) + size, KM_SLEEP);
	pdd->pdd_size = (sizeof (struct prop_driver_data) + size);
	pdd->pdd_prop_free = prop_free;

	/*
	 * Return a pointer to the location to put the decoded data.
	 */
	return ((void *)((caddr_t)pdd + sizeof (struct prop_driver_data)));
}

/*
 * Allocated the memory needed to store the encoded data in the property
 * handle.
 */
static int
ddi_prop_encode_alloc(prop_handle_t *ph, size_t size)
{
	/*
	 * If size is zero, then set data to NULL and size to 0.  This
	 * is a boolean property.
	 */
	if (size == 0) {
		ph->ph_size = 0;
		ph->ph_data = NULL;
		ph->ph_cur_pos = NULL;
		ph->ph_save_pos = NULL;
	} else {
		if (ph->ph_flags == DDI_PROP_DONTSLEEP) {
			ph->ph_data = kmem_zalloc(size, KM_NOSLEEP);
			if (ph->ph_data == NULL)
				return (DDI_PROP_NO_MEMORY);
		} else
			ph->ph_data = kmem_zalloc(size, KM_SLEEP);
		ph->ph_size = size;
		ph->ph_cur_pos = ph->ph_data;
		ph->ph_save_pos = ph->ph_data;
	}
	return (DDI_PROP_SUCCESS);
}

/*
 * Free the space allocated by the lookup routines.  Each lookup routine
 * returns a pointer to the decoded data to the driver.  The driver then
 * passes this pointer back to us.  This data actually lives in a struct
 * prop_driver_data.  We use negative indexing to find the beginning of
 * the structure and then free the entire structure using the size and
 * the free routine stored in the structure.
 */
void
ddi_prop_free(void *datap)
{
	struct prop_driver_data *pdd;

	/*
	 * Get the structure
	 */
	pdd = (struct prop_driver_data *)
	    ((caddr_t)datap - sizeof (struct prop_driver_data));
	/*
	 * Call the free routine to free it
	 */
	(*pdd->pdd_prop_free)(pdd);
}

/*
 * Free the data associated with an array of ints,
 * allocated with ddi_prop_decode_alloc().
 */
static void
ddi_prop_free_ints(struct prop_driver_data *pdd)
{
	kmem_free(pdd, pdd->pdd_size);
}

/*
 * Free a single string property or a single string contained within
 * the argv style return value of an array of strings.
 */
static void
ddi_prop_free_string(struct prop_driver_data *pdd)
{
	kmem_free(pdd, pdd->pdd_size);

}

/*
 * Free an array of strings.
 */
static void
ddi_prop_free_strings(struct prop_driver_data *pdd)
{
	kmem_free(pdd, pdd->pdd_size);
}

/*
 * Free the data associated with an array of bytes.
 */
static void
ddi_prop_free_bytes(struct prop_driver_data *pdd)
{
	kmem_free(pdd, pdd->pdd_size);
}

/*
 * Reset the current location pointer in the property handle to the
 * beginning of the data.
 */
void
ddi_prop_reset_pos(prop_handle_t *ph)
{
	ph->ph_cur_pos = ph->ph_data;
	ph->ph_save_pos = ph->ph_data;
}

/*
 * Restore the current location pointer in the property handle to the
 * saved position.
 */
void
ddi_prop_save_pos(prop_handle_t *ph)
{
	ph->ph_save_pos = ph->ph_cur_pos;
}

/*
 * Save the location that the current location pointer is pointing to..
 */
void
ddi_prop_restore_pos(prop_handle_t *ph)
{
	ph->ph_cur_pos = ph->ph_save_pos;
}

/*
 * Property encode/decode functions
 */

/*
 * Decode a single integer property
 */
static int
ddi_prop_fm_decode_int(prop_handle_t *ph, void *data, uint_t *nelements)
{
	int	i;
	int	tmp;

	/*
	 * If there is nothing to decode return an error
	 */
	if (ph->ph_size == 0)
		return (DDI_PROP_END_OF_DATA);

	/*
	 * Decode the property as a single integer and return it
	 * in data if we were able to decode it.
	 */
	i = DDI_PROP_INT(ph, DDI_PROP_CMD_DECODE, &tmp);
	if (i < DDI_PROP_RESULT_OK) {
		switch (i) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_DECODE);
		}
	}

	*(int *)data = tmp;
	*nelements = 1;
	return (DDI_PROP_SUCCESS);
}

/*
 * Decode a single 64 bit integer property
 */
static int
ddi_prop_fm_decode_int64(prop_handle_t *ph, void *data, uint_t *nelements)
{
	int	i;
	int64_t	tmp;

	/*
	 * If there is nothing to decode return an error
	 */
	if (ph->ph_size == 0)
		return (DDI_PROP_END_OF_DATA);

	/*
	 * Decode the property as a single integer and return it
	 * in data if we were able to decode it.
	 */
	i = DDI_PROP_INT64(ph, DDI_PROP_CMD_DECODE, &tmp);
	if (i < DDI_PROP_RESULT_OK) {
		switch (i) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_DECODE);
		}
	}

	*(int64_t *)data = tmp;
	*nelements = 1;
	return (DDI_PROP_SUCCESS);
}

/*
 * Decode an array of integers property
 */
static int
ddi_prop_fm_decode_ints(prop_handle_t *ph, void *data, uint_t *nelements)
{
	int	i;
	int	cnt = 0;
	int	*tmp;
	int	*intp;
	int	n;

	/*
	 * Figure out how many array elements there are by going through the
	 * data without decoding it first and counting.
	 */
	for (;;) {
		i = DDI_PROP_INT(ph, DDI_PROP_CMD_SKIP, NULL);
		if (i < 0)
			break;
		cnt++;
	}

	/*
	 * If there are no elements return an error
	 */
	if (cnt == 0)
		return (DDI_PROP_END_OF_DATA);

	/*
	 * If we cannot skip through the data, we cannot decode it
	 */
	if (i == DDI_PROP_RESULT_ERROR)
		return (DDI_PROP_CANNOT_DECODE);

	/*
	 * Reset the data pointer to the beginning of the encoded data
	 */
	ddi_prop_reset_pos(ph);

	/*
	 * Allocated memory to store the decoded value in.
	 */
	intp = ddi_prop_decode_alloc((cnt * sizeof (int)),
	    ddi_prop_free_ints);

	/*
	 * Decode each element and place it in the space we just allocated
	 */
	tmp = intp;
	for (n = 0; n < cnt; n++, tmp++) {
		i = DDI_PROP_INT(ph, DDI_PROP_CMD_DECODE, tmp);
		if (i < DDI_PROP_RESULT_OK) {
			/*
			 * Free the space we just allocated
			 * and return an error.
			 */
			ddi_prop_free(intp);
			switch (i) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_DECODE);
			}
		}
	}

	*nelements = cnt;
	*(int **)data = intp;

	return (DDI_PROP_SUCCESS);
}

/*
 * Decode a 64 bit integer array property
 */
static int
ddi_prop_fm_decode_int64_array(prop_handle_t *ph, void *data, uint_t *nelements)
{
	int	i;
	int	n;
	int	cnt = 0;
	int64_t	*tmp;
	int64_t	*intp;

	/*
	 * Count the number of array elements by going
	 * through the data without decoding it.
	 */
	for (;;) {
		i = DDI_PROP_INT64(ph, DDI_PROP_CMD_SKIP, NULL);
		if (i < 0)
			break;
		cnt++;
	}

	/*
	 * If there are no elements return an error
	 */
	if (cnt == 0)
		return (DDI_PROP_END_OF_DATA);

	/*
	 * If we cannot skip through the data, we cannot decode it
	 */
	if (i == DDI_PROP_RESULT_ERROR)
		return (DDI_PROP_CANNOT_DECODE);

	/*
	 * Reset the data pointer to the beginning of the encoded data
	 */
	ddi_prop_reset_pos(ph);

	/*
	 * Allocate memory to store the decoded value.
	 */
	intp = ddi_prop_decode_alloc((cnt * sizeof (int64_t)),
	    ddi_prop_free_ints);

	/*
	 * Decode each element and place it in the space allocated
	 */
	tmp = intp;
	for (n = 0; n < cnt; n++, tmp++) {
		i = DDI_PROP_INT64(ph, DDI_PROP_CMD_DECODE, tmp);
		if (i < DDI_PROP_RESULT_OK) {
			/*
			 * Free the space we just allocated
			 * and return an error.
			 */
			ddi_prop_free(intp);
			switch (i) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_DECODE);
			}
		}
	}

	*nelements = cnt;
	*(int64_t **)data = intp;

	return (DDI_PROP_SUCCESS);
}

/*
 * Encode an array of integers property (Can be one element)
 */
int
ddi_prop_fm_encode_ints(prop_handle_t *ph, void *data, uint_t nelements)
{
	int	i;
	int	*tmp;
	int	cnt;
	int	size;

	/*
	 * If there is no data, we cannot do anything
	 */
	if (nelements == 0)
		return (DDI_PROP_CANNOT_ENCODE);

	/*
	 * Get the size of an encoded int.
	 */
	size = DDI_PROP_INT(ph, DDI_PROP_CMD_GET_ESIZE, NULL);

	if (size < DDI_PROP_RESULT_OK) {
		switch (size) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_ENCODE);
		}
	}

	/*
	 * Allocate space in the handle to store the encoded int.
	 */
	if (ddi_prop_encode_alloc(ph, size * nelements) !=
	    DDI_PROP_SUCCESS)
		return (DDI_PROP_NO_MEMORY);

	/*
	 * Encode the array of ints.
	 */
	tmp = (int *)data;
	for (cnt = 0; cnt < nelements; cnt++, tmp++) {
		i = DDI_PROP_INT(ph, DDI_PROP_CMD_ENCODE, tmp);
		if (i < DDI_PROP_RESULT_OK) {
			switch (i) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_ENCODE);
			}
		}
	}

	return (DDI_PROP_SUCCESS);
}


/*
 * Encode a 64 bit integer array property
 */
int
ddi_prop_fm_encode_int64(prop_handle_t *ph, void *data, uint_t nelements)
{
	int i;
	int cnt;
	int size;
	int64_t *tmp;

	/*
	 * If there is no data, we cannot do anything
	 */
	if (nelements == 0)
		return (DDI_PROP_CANNOT_ENCODE);

	/*
	 * Get the size of an encoded 64 bit int.
	 */
	size = DDI_PROP_INT64(ph, DDI_PROP_CMD_GET_ESIZE, NULL);

	if (size < DDI_PROP_RESULT_OK) {
		switch (size) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_ENCODE);
		}
	}

	/*
	 * Allocate space in the handle to store the encoded int.
	 */
	if (ddi_prop_encode_alloc(ph, size * nelements) !=
	    DDI_PROP_SUCCESS)
		return (DDI_PROP_NO_MEMORY);

	/*
	 * Encode the array of ints.
	 */
	tmp = (int64_t *)data;
	for (cnt = 0; cnt < nelements; cnt++, tmp++) {
		i = DDI_PROP_INT64(ph, DDI_PROP_CMD_ENCODE, tmp);
		if (i < DDI_PROP_RESULT_OK) {
			switch (i) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_ENCODE);
			}
		}
	}

	return (DDI_PROP_SUCCESS);
}

/*
 * Decode a single string property
 */
static int
ddi_prop_fm_decode_string(prop_handle_t *ph, void *data, uint_t *nelements)
{
	char		*tmp;
	char		*str;
	int		i;
	int		size;

	/*
	 * If there is nothing to decode return an error
	 */
	if (ph->ph_size == 0)
		return (DDI_PROP_END_OF_DATA);

	/*
	 * Get the decoded size of the encoded string.
	 */
	size = DDI_PROP_STR(ph, DDI_PROP_CMD_GET_DSIZE, NULL);
	if (size < DDI_PROP_RESULT_OK) {
		switch (size) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_DECODE);
		}
	}

	/*
	 * Allocated memory to store the decoded value in.
	 */
	str = ddi_prop_decode_alloc((size_t)size, ddi_prop_free_string);

	ddi_prop_reset_pos(ph);

	/*
	 * Decode the str and place it in the space we just allocated
	 */
	tmp = str;
	i = DDI_PROP_STR(ph, DDI_PROP_CMD_DECODE, tmp);
	if (i < DDI_PROP_RESULT_OK) {
		/*
		 * Free the space we just allocated
		 * and return an error.
		 */
		ddi_prop_free(str);
		switch (i) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_DECODE);
		}
	}

	*(char **)data = str;
	*nelements = 1;

	return (DDI_PROP_SUCCESS);
}

/*
 * Decode an array of strings.
 */
int
ddi_prop_fm_decode_strings(prop_handle_t *ph, void *data, uint_t *nelements)
{
	int		cnt = 0;
	char		**strs;
	char		**tmp;
	char		*ptr;
	int		i;
	int		n;
	int		size;
	size_t		nbytes;

	/*
	 * Figure out how many array elements there are by going through the
	 * data without decoding it first and counting.
	 */
	for (;;) {
		i = DDI_PROP_STR(ph, DDI_PROP_CMD_SKIP, NULL);
		if (i < 0)
			break;
		cnt++;
	}

	/*
	 * If there are no elements return an error
	 */
	if (cnt == 0)
		return (DDI_PROP_END_OF_DATA);

	/*
	 * If we cannot skip through the data, we cannot decode it
	 */
	if (i == DDI_PROP_RESULT_ERROR)
		return (DDI_PROP_CANNOT_DECODE);

	/*
	 * Reset the data pointer to the beginning of the encoded data
	 */
	ddi_prop_reset_pos(ph);

	/*
	 * Figure out how much memory we need for the sum total
	 */
	nbytes = (cnt + 1) * sizeof (char *);

	for (n = 0; n < cnt; n++) {
		/*
		 * Get the decoded size of the current encoded string.
		 */
		size = DDI_PROP_STR(ph, DDI_PROP_CMD_GET_DSIZE, NULL);
		if (size < DDI_PROP_RESULT_OK) {
			switch (size) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_DECODE);
			}
		}

		nbytes += size;
	}

	/*
	 * Allocate memory in which to store the decoded strings.
	 */
	strs = ddi_prop_decode_alloc(nbytes, ddi_prop_free_strings);

	/*
	 * Set up pointers for each string by figuring out yet
	 * again how long each string is.
	 */
	ddi_prop_reset_pos(ph);
	ptr = (caddr_t)strs + ((cnt + 1) * sizeof (char *));
	for (tmp = strs, n = 0; n < cnt; n++, tmp++) {
		/*
		 * Get the decoded size of the current encoded string.
		 */
		size = DDI_PROP_STR(ph, DDI_PROP_CMD_GET_DSIZE, NULL);
		if (size < DDI_PROP_RESULT_OK) {
			ddi_prop_free(strs);
			switch (size) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_DECODE);
			}
		}

		*tmp = ptr;
		ptr += size;
	}

	/*
	 * String array is terminated by a NULL
	 */
	*tmp = NULL;

	/*
	 * Finally, we can decode each string
	 */
	ddi_prop_reset_pos(ph);
	for (tmp = strs, n = 0; n < cnt; n++, tmp++) {
		i = DDI_PROP_STR(ph, DDI_PROP_CMD_DECODE, *tmp);
		if (i < DDI_PROP_RESULT_OK) {
			/*
			 * Free the space we just allocated
			 * and return an error
			 */
			ddi_prop_free(strs);
			switch (i) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_DECODE);
			}
		}
	}

	*(char ***)data = strs;
	*nelements = cnt;

	return (DDI_PROP_SUCCESS);
}

/*
 * Encode a string.
 */
int
ddi_prop_fm_encode_string(prop_handle_t *ph, void *data, uint_t nelements)
{
	char		**tmp;
	int		size;
	int		i;

	/*
	 * If there is no data, we cannot do anything
	 */
	if (nelements == 0)
		return (DDI_PROP_CANNOT_ENCODE);

	/*
	 * Get the size of the encoded string.
	 */
	tmp = (char **)data;
	size = DDI_PROP_STR(ph, DDI_PROP_CMD_GET_ESIZE, *tmp);
	if (size < DDI_PROP_RESULT_OK) {
		switch (size) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_ENCODE);
		}
	}

	/*
	 * Allocate space in the handle to store the encoded string.
	 */
	if (ddi_prop_encode_alloc(ph, size) != DDI_PROP_SUCCESS)
		return (DDI_PROP_NO_MEMORY);

	ddi_prop_reset_pos(ph);

	/*
	 * Encode the string.
	 */
	tmp = (char **)data;
	i = DDI_PROP_STR(ph, DDI_PROP_CMD_ENCODE, *tmp);
	if (i < DDI_PROP_RESULT_OK) {
		switch (i) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_ENCODE);
		}
	}

	return (DDI_PROP_SUCCESS);
}


/*
 * Encode an array of strings.
 */
int
ddi_prop_fm_encode_strings(prop_handle_t *ph, void *data, uint_t nelements)
{
	int		cnt = 0;
	char		**tmp;
	int		size;
	uint_t		total_size;
	int		i;

	/*
	 * If there is no data, we cannot do anything
	 */
	if (nelements == 0)
		return (DDI_PROP_CANNOT_ENCODE);

	/*
	 * Get the total size required to encode all the strings.
	 */
	total_size = 0;
	tmp = (char **)data;
	for (cnt = 0; cnt < nelements; cnt++, tmp++) {
		size = DDI_PROP_STR(ph, DDI_PROP_CMD_GET_ESIZE, *tmp);
		if (size < DDI_PROP_RESULT_OK) {
			switch (size) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_ENCODE);
			}
		}
		total_size += (uint_t)size;
	}

	/*
	 * Allocate space in the handle to store the encoded strings.
	 */
	if (ddi_prop_encode_alloc(ph, total_size) != DDI_PROP_SUCCESS)
		return (DDI_PROP_NO_MEMORY);

	ddi_prop_reset_pos(ph);

	/*
	 * Encode the array of strings.
	 */
	tmp = (char **)data;
	for (cnt = 0; cnt < nelements; cnt++, tmp++) {
		i = DDI_PROP_STR(ph, DDI_PROP_CMD_ENCODE, *tmp);
		if (i < DDI_PROP_RESULT_OK) {
			switch (i) {
			case DDI_PROP_RESULT_EOF:
				return (DDI_PROP_END_OF_DATA);

			case DDI_PROP_RESULT_ERROR:
				return (DDI_PROP_CANNOT_ENCODE);
			}
		}
	}

	return (DDI_PROP_SUCCESS);
}


/*
 * Decode an array of bytes.
 */
static int
ddi_prop_fm_decode_bytes(prop_handle_t *ph, void *data, uint_t *nelements)
{
	uchar_t		*tmp;
	int		nbytes;
	int		i;

	/*
	 * If there are no elements return an error
	 */
	if (ph->ph_size == 0)
		return (DDI_PROP_END_OF_DATA);

	/*
	 * Get the size of the encoded array of bytes.
	 */
	nbytes = DDI_PROP_BYTES(ph, DDI_PROP_CMD_GET_DSIZE,
	    data, ph->ph_size);
	if (nbytes < DDI_PROP_RESULT_OK) {
		switch (nbytes) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_DECODE);
		}
	}

	/*
	 * Allocated memory to store the decoded value in.
	 */
	tmp = ddi_prop_decode_alloc(nbytes, ddi_prop_free_bytes);

	/*
	 * Decode each element and place it in the space we just allocated
	 */
	i = DDI_PROP_BYTES(ph, DDI_PROP_CMD_DECODE, tmp, nbytes);
	if (i < DDI_PROP_RESULT_OK) {
		/*
		 * Free the space we just allocated
		 * and return an error
		 */
		ddi_prop_free(tmp);
		switch (i) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_DECODE);
		}
	}

	*(uchar_t **)data = tmp;
	*nelements = nbytes;

	return (DDI_PROP_SUCCESS);
}

/*
 * Encode an array of bytes.
 */
int
ddi_prop_fm_encode_bytes(prop_handle_t *ph, void *data, uint_t nelements)
{
	int		size;
	int		i;

	/*
	 * If there are no elements, then this is a boolean property,
	 * so just create a property handle with no data and return.
	 */
	if (nelements == 0) {
		(void) ddi_prop_encode_alloc(ph, 0);
		return (DDI_PROP_SUCCESS);
	}

	/*
	 * Get the size of the encoded array of bytes.
	 */
	size = DDI_PROP_BYTES(ph, DDI_PROP_CMD_GET_ESIZE, (uchar_t *)data,
	    nelements);
	if (size < DDI_PROP_RESULT_OK) {
		switch (size) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_DECODE);
		}
	}

	/*
	 * Allocate space in the handle to store the encoded bytes.
	 */
	if (ddi_prop_encode_alloc(ph, (uint_t)size) != DDI_PROP_SUCCESS)
		return (DDI_PROP_NO_MEMORY);

	/*
	 * Encode the array of bytes.
	 */
	i = DDI_PROP_BYTES(ph, DDI_PROP_CMD_ENCODE, (uchar_t *)data,
	    nelements);
	if (i < DDI_PROP_RESULT_OK) {
		switch (i) {
		case DDI_PROP_RESULT_EOF:
			return (DDI_PROP_END_OF_DATA);

		case DDI_PROP_RESULT_ERROR:
			return (DDI_PROP_CANNOT_ENCODE);
		}
	}

	return (DDI_PROP_SUCCESS);
}

/*
 * OBP 1275 integer, string and byte operators.
 *
 * DDI_PROP_CMD_DECODE:
 *
 *	DDI_PROP_RESULT_ERROR:		cannot decode the data
 *	DDI_PROP_RESULT_EOF:		end of data
 *	DDI_PROP_OK:			data was decoded
 *
 * DDI_PROP_CMD_ENCODE:
 *
 *	DDI_PROP_RESULT_ERROR:		cannot encode the data
 *	DDI_PROP_RESULT_EOF:		end of data
 *	DDI_PROP_OK:			data was encoded
 *
 * DDI_PROP_CMD_SKIP:
 *
 *	DDI_PROP_RESULT_ERROR:		cannot skip the data
 *	DDI_PROP_RESULT_EOF:		end of data
 *	DDI_PROP_OK:			data was skipped
 *
 * DDI_PROP_CMD_GET_ESIZE:
 *
 *	DDI_PROP_RESULT_ERROR:		cannot get encoded size
 *	DDI_PROP_RESULT_EOF:		end of data
 *	> 0:				the encoded size
 *
 * DDI_PROP_CMD_GET_DSIZE:
 *
 *	DDI_PROP_RESULT_ERROR:		cannot get decoded size
 *	DDI_PROP_RESULT_EOF:		end of data
 *	> 0:				the decoded size
 */

/*
 * OBP 1275 integer operator
 *
 * OBP properties are a byte stream of data, so integers may not be
 * properly aligned.  Therefore we need to copy them one byte at a time.
 */
int
ddi_prop_1275_int(prop_handle_t *ph, uint_t cmd, int *data)
{
	int	i;

	switch (cmd) {
	case DDI_PROP_CMD_DECODE:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0)
			return (DDI_PROP_RESULT_ERROR);
		if (ph->ph_flags & PH_FROM_PROM) {
			i = MIN(ph->ph_size, PROP_1275_INT_SIZE);
			if ((int *)ph->ph_cur_pos > ((int *)ph->ph_data +
			    ph->ph_size - i))
				return (DDI_PROP_RESULT_ERROR);
		} else {
			if (ph->ph_size < sizeof (int) ||
			    ((int *)ph->ph_cur_pos > ((int *)ph->ph_data +
			    ph->ph_size - sizeof (int))))
				return (DDI_PROP_RESULT_ERROR);
		}

		/*
		 * Copy the integer, using the implementation-specific
		 * copy function if the property is coming from the PROM.
		 */
		if (ph->ph_flags & PH_FROM_PROM) {
			*data = impl_ddi_prop_int_from_prom(
			    (uchar_t *)ph->ph_cur_pos,
			    (ph->ph_size < PROP_1275_INT_SIZE) ?
			    ph->ph_size : PROP_1275_INT_SIZE);
		} else {
			bcopy(ph->ph_cur_pos, data, sizeof (int));
		}

		/*
		 * Move the current location to the start of the next
		 * bit of undecoded data.
		 */
		ph->ph_cur_pos = (uchar_t *)ph->ph_cur_pos +
		    PROP_1275_INT_SIZE;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_ENCODE:
		/*
		 * Check that there is room to encoded the data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0 ||
		    ph->ph_size < PROP_1275_INT_SIZE ||
		    ((int *)ph->ph_cur_pos > ((int *)ph->ph_data +
		    ph->ph_size - sizeof (int))))
			return (DDI_PROP_RESULT_ERROR);

		/*
		 * Encode the integer into the byte stream one byte at a
		 * time.
		 */
		bcopy(data, ph->ph_cur_pos, sizeof (int));

		/*
		 * Move the current location to the start of the next bit of
		 * space where we can store encoded data.
		 */
		ph->ph_cur_pos = (uchar_t *)ph->ph_cur_pos + PROP_1275_INT_SIZE;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_SKIP:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0 ||
		    ph->ph_size < PROP_1275_INT_SIZE)
			return (DDI_PROP_RESULT_ERROR);


		if ((caddr_t)ph->ph_cur_pos ==
		    (caddr_t)ph->ph_data + ph->ph_size) {
			return (DDI_PROP_RESULT_EOF);
		} else if ((caddr_t)ph->ph_cur_pos >
		    (caddr_t)ph->ph_data + ph->ph_size) {
			return (DDI_PROP_RESULT_EOF);
		}

		/*
		 * Move the current location to the start of the next bit of
		 * undecoded data.
		 */
		ph->ph_cur_pos = (uchar_t *)ph->ph_cur_pos + PROP_1275_INT_SIZE;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_GET_ESIZE:
		/*
		 * Return the size of an encoded integer on OBP
		 */
		return (PROP_1275_INT_SIZE);

	case DDI_PROP_CMD_GET_DSIZE:
		/*
		 * Return the size of a decoded integer on the system.
		 */
		return (sizeof (int));

	default:
#ifdef DEBUG
		panic("ddi_prop_1275_int: %x impossible", cmd);
		/*NOTREACHED*/
#else
		return (DDI_PROP_RESULT_ERROR);
#endif	/* DEBUG */
	}
}

/*
 * 64 bit integer operator.
 *
 * This is an extension, defined by Sun, to the 1275 integer
 * operator.  This routine handles the encoding/decoding of
 * 64 bit integer properties.
 */
int
ddi_prop_int64_op(prop_handle_t *ph, uint_t cmd, int64_t *data)
{

	switch (cmd) {
	case DDI_PROP_CMD_DECODE:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0)
			return (DDI_PROP_RESULT_ERROR);
		if (ph->ph_flags & PH_FROM_PROM) {
			return (DDI_PROP_RESULT_ERROR);
		} else {
			if (ph->ph_size < sizeof (int64_t) ||
			    ((int64_t *)ph->ph_cur_pos >
			    ((int64_t *)ph->ph_data +
			    ph->ph_size - sizeof (int64_t))))
				return (DDI_PROP_RESULT_ERROR);
		}
		/*
		 * Copy the integer, using the implementation-specific
		 * copy function if the property is coming from the PROM.
		 */
		if (ph->ph_flags & PH_FROM_PROM) {
			return (DDI_PROP_RESULT_ERROR);
		} else {
			bcopy(ph->ph_cur_pos, data, sizeof (int64_t));
		}

		/*
		 * Move the current location to the start of the next
		 * bit of undecoded data.
		 */
		ph->ph_cur_pos = (uchar_t *)ph->ph_cur_pos +
		    sizeof (int64_t);
			return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_ENCODE:
		/*
		 * Check that there is room to encoded the data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0 ||
		    ph->ph_size < sizeof (int64_t) ||
		    ((int64_t *)ph->ph_cur_pos > ((int64_t *)ph->ph_data +
		    ph->ph_size - sizeof (int64_t))))
			return (DDI_PROP_RESULT_ERROR);

		/*
		 * Encode the integer into the byte stream one byte at a
		 * time.
		 */
		bcopy(data, ph->ph_cur_pos, sizeof (int64_t));

		/*
		 * Move the current location to the start of the next bit of
		 * space where we can store encoded data.
		 */
		ph->ph_cur_pos = (uchar_t *)ph->ph_cur_pos +
		    sizeof (int64_t);
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_SKIP:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0 ||
		    ph->ph_size < sizeof (int64_t))
			return (DDI_PROP_RESULT_ERROR);

		if ((caddr_t)ph->ph_cur_pos ==
		    (caddr_t)ph->ph_data + ph->ph_size) {
			return (DDI_PROP_RESULT_EOF);
		} else if ((caddr_t)ph->ph_cur_pos >
		    (caddr_t)ph->ph_data + ph->ph_size) {
			return (DDI_PROP_RESULT_EOF);
		}

		/*
		 * Move the current location to the start of
		 * the next bit of undecoded data.
		 */
		ph->ph_cur_pos = (uchar_t *)ph->ph_cur_pos +
		    sizeof (int64_t);
			return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_GET_ESIZE:
		/*
		 * Return the size of an encoded integer on OBP
		 */
		return (sizeof (int64_t));

	case DDI_PROP_CMD_GET_DSIZE:
		/*
		 * Return the size of a decoded integer on the system.
		 */
		return (sizeof (int64_t));

	default:
#ifdef DEBUG
		panic("ddi_prop_int64_op: %x impossible", cmd);
		/*NOTREACHED*/
#else
		return (DDI_PROP_RESULT_ERROR);
#endif  /* DEBUG */
	}
}

/*
 * OBP 1275 string operator.
 *
 * OBP strings are NULL terminated.
 */
int
ddi_prop_1275_string(prop_handle_t *ph, uint_t cmd, char *data)
{
	int	n;
	char	*p;
	char	*end;

	switch (cmd) {
	case DDI_PROP_CMD_DECODE:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0) {
			return (DDI_PROP_RESULT_ERROR);
		}

		/*
		 * Match DDI_PROP_CMD_GET_DSIZE logic for when to stop and
		 * how to NULL terminate result.
		 */
		p = (char *)ph->ph_cur_pos;
		end = (char *)ph->ph_data + ph->ph_size;
		if (p >= end)
			return (DDI_PROP_RESULT_EOF);

		while (p < end) {
			*data++ = *p;
			if (*p++ == 0) {	/* NULL from OBP */
				ph->ph_cur_pos = p;
				return (DDI_PROP_RESULT_OK);
			}
		}

		/*
		 * If OBP did not NULL terminate string, which happens
		 * (at least) for 'true'/'false' boolean values, account for
		 * the space and store null termination on decode.
		 */
		ph->ph_cur_pos = p;
		*data = 0;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_ENCODE:
		/*
		 * Check that there is room to encoded the data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0) {
			return (DDI_PROP_RESULT_ERROR);
		}

		n = strlen(data) + 1;
		if ((char *)ph->ph_cur_pos > ((char *)ph->ph_data +
		    ph->ph_size - n)) {
			return (DDI_PROP_RESULT_ERROR);
		}

		/*
		 * Copy the NULL terminated string
		 */
		bcopy(data, ph->ph_cur_pos, n);

		/*
		 * Move the current location to the start of the next bit of
		 * space where we can store encoded data.
		 */
		ph->ph_cur_pos = (char *)ph->ph_cur_pos + n;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_SKIP:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0) {
			return (DDI_PROP_RESULT_ERROR);
		}

		/*
		 * Return the string length plus one for the NULL
		 * We know the size of the property, we need to
		 * ensure that the string is properly formatted,
		 * since we may be looking up random OBP data.
		 */
		p = (char *)ph->ph_cur_pos;
		end = (char *)ph->ph_data + ph->ph_size;
		if (p >= end)
			return (DDI_PROP_RESULT_EOF);

		while (p < end) {
			if (*p++ == 0) {	/* NULL from OBP */
				ph->ph_cur_pos = p;
				return (DDI_PROP_RESULT_OK);
			}
		}

		/*
		 * Accommodate the fact that OBP does not always NULL
		 * terminate strings.
		 */
		ph->ph_cur_pos = p;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_GET_ESIZE:
		/*
		 * Return the size of the encoded string on OBP.
		 */
		return (strlen(data) + 1);

	case DDI_PROP_CMD_GET_DSIZE:
		/*
		 * Return the string length plus one for the NULL.
		 * We know the size of the property, we need to
		 * ensure that the string is properly formatted,
		 * since we may be looking up random OBP data.
		 */
		p = (char *)ph->ph_cur_pos;
		end = (char *)ph->ph_data + ph->ph_size;
		if (p >= end)
			return (DDI_PROP_RESULT_EOF);

		for (n = 0; p < end; n++) {
			if (*p++ == 0) {	/* NULL from OBP */
				ph->ph_cur_pos = p;
				return (n + 1);
			}
		}

		/*
		 * If OBP did not NULL terminate string, which happens for
		 * 'true'/'false' boolean values, account for the space
		 * to store null termination here.
		 */
		ph->ph_cur_pos = p;
		return (n + 1);

	default:
#ifdef DEBUG
		panic("ddi_prop_1275_string: %x impossible", cmd);
		/*NOTREACHED*/
#else
		return (DDI_PROP_RESULT_ERROR);
#endif	/* DEBUG */
	}
}

/*
 * OBP 1275 byte operator
 *
 * Caller must specify the number of bytes to get.  OBP encodes bytes
 * as a byte so there is a 1-to-1 translation.
 */
int
ddi_prop_1275_bytes(prop_handle_t *ph, uint_t cmd, uchar_t *data,
	uint_t nelements)
{
	switch (cmd) {
	case DDI_PROP_CMD_DECODE:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0 ||
		    ph->ph_size < nelements ||
		    ((char *)ph->ph_cur_pos > ((char *)ph->ph_data +
		    ph->ph_size - nelements)))
			return (DDI_PROP_RESULT_ERROR);

		/*
		 * Copy out the bytes
		 */
		bcopy(ph->ph_cur_pos, data, nelements);

		/*
		 * Move the current location
		 */
		ph->ph_cur_pos = (char *)ph->ph_cur_pos + nelements;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_ENCODE:
		/*
		 * Check that there is room to encode the data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0 ||
		    ph->ph_size < nelements ||
		    ((char *)ph->ph_cur_pos > ((char *)ph->ph_data +
		    ph->ph_size - nelements)))
			return (DDI_PROP_RESULT_ERROR);

		/*
		 * Copy in the bytes
		 */
		bcopy(data, ph->ph_cur_pos, nelements);

		/*
		 * Move the current location to the start of the next bit of
		 * space where we can store encoded data.
		 */
		ph->ph_cur_pos = (char *)ph->ph_cur_pos + nelements;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_SKIP:
		/*
		 * Check that there is encoded data
		 */
		if (ph->ph_cur_pos == NULL || ph->ph_size == 0 ||
		    ph->ph_size < nelements)
			return (DDI_PROP_RESULT_ERROR);

		if ((char *)ph->ph_cur_pos > ((char *)ph->ph_data +
		    ph->ph_size - nelements))
			return (DDI_PROP_RESULT_EOF);

		/*
		 * Move the current location
		 */
		ph->ph_cur_pos = (char *)ph->ph_cur_pos + nelements;
		return (DDI_PROP_RESULT_OK);

	case DDI_PROP_CMD_GET_ESIZE:
		/*
		 * The size in bytes of the encoded size is the
		 * same as the decoded size provided by the caller.
		 */
		return (nelements);

	case DDI_PROP_CMD_GET_DSIZE:
		/*
		 * Just return the number of bytes specified by the caller.
		 */
		return (nelements);

	default:
#ifdef DEBUG
		panic("ddi_prop_1275_bytes: %x impossible", cmd);
		/*NOTREACHED*/
#else
		return (DDI_PROP_RESULT_ERROR);
#endif	/* DEBUG */
	}
}

/*
 * Used for properties that come from the OBP, hardware configuration files,
 * or that are created by calls to ddi_prop_update(9F).
 */
static struct prop_handle_ops prop_1275_ops = {
	ddi_prop_1275_int,
	ddi_prop_1275_string,
	ddi_prop_1275_bytes,
	ddi_prop_int64_op
};


/*
 * Interface to create/modify a managed property on child's behalf...
 * Flags interpreted are:
 *	DDI_PROP_CANSLEEP:	Allow memory allocation to sleep.
 *	DDI_PROP_SYSTEM_DEF:	Manipulate system list rather than driver list.
 *
 * Use same dev_t when modifying or undefining a property.
 * Search for properties with DDI_DEV_T_ANY to match first named
 * property on the list.
 *
 * Properties are stored LIFO and subsequently will match the first
 * `matching' instance.
 */

/*
 * ddi_prop_add:	Add a software defined property
 */

/*
 * define to get a new ddi_prop_t.
 * km_flags are KM_SLEEP or KM_NOSLEEP.
 */

#define	DDI_NEW_PROP_T(km_flags)	\
	(kmem_zalloc(sizeof (ddi_prop_t), km_flags))

static int
ddi_prop_add(dev_t dev, dev_info_t *dip, int flags,
    char *name, caddr_t value, int length)
{
	ddi_prop_t	*new_propp, *propp;
	ddi_prop_t	**list_head = &(DEVI(dip)->devi_drv_prop_ptr);
	int		km_flags = KM_NOSLEEP;
	int		name_buf_len;

	/*
	 * If dev_t is DDI_DEV_T_ANY or name's length is zero return error.
	 */

	if (dev == DDI_DEV_T_ANY || name == (char *)0 || strlen(name) == 0)
		return (DDI_PROP_INVAL_ARG);

	if (flags & DDI_PROP_CANSLEEP)
		km_flags = KM_SLEEP;

	if (flags & DDI_PROP_SYSTEM_DEF)
		list_head = &(DEVI(dip)->devi_sys_prop_ptr);
	else if (flags & DDI_PROP_HW_DEF)
		list_head = &(DEVI(dip)->devi_hw_prop_ptr);

	if ((new_propp = DDI_NEW_PROP_T(km_flags)) == NULL)  {
		cmn_err(CE_CONT, prop_no_mem_msg, name);
		return (DDI_PROP_NO_MEMORY);
	}

	/*
	 * If dev is major number 0, then we need to do a ddi_name_to_major
	 * to get the real major number for the device.  This needs to be
	 * done because some drivers need to call ddi_prop_create in their
	 * attach routines but they don't have a dev.  By creating the dev
	 * ourself if the major number is 0, drivers will not have to know what
	 * their major number.	They can just create a dev with major number
	 * 0 and pass it in.  For device 0, we will be doing a little extra
	 * work by recreating the same dev that we already have, but its the
	 * price you pay :-).
	 *
	 * This fixes bug #1098060.
	 */
	if (getmajor(dev) == DDI_MAJOR_T_UNKNOWN) {
		new_propp->prop_dev =
		    makedevice(ddi_name_to_major(DEVI(dip)->devi_binding_name),
		    getminor(dev));
	} else
		new_propp->prop_dev = dev;

	/*
	 * Allocate space for property name and copy it in...
	 */

	name_buf_len = strlen(name) + 1;
	new_propp->prop_name = kmem_alloc(name_buf_len, km_flags);
	if (new_propp->prop_name == 0)	{
		kmem_free(new_propp, sizeof (ddi_prop_t));
		cmn_err(CE_CONT, prop_no_mem_msg, name);
		return (DDI_PROP_NO_MEMORY);
	}
	bcopy(name, new_propp->prop_name, name_buf_len);

	/*
	 * Set the property type
	 */
	new_propp->prop_flags = flags & DDI_PROP_TYPE_MASK;

	/*
	 * Set length and value ONLY if not an explicit property undefine:
	 * NOTE: value and length are zero for explicit undefines.
	 */

	if (flags & DDI_PROP_UNDEF_IT) {
		new_propp->prop_flags |= DDI_PROP_UNDEF_IT;
	} else {
		if ((new_propp->prop_len = length) != 0) {
			new_propp->prop_val = kmem_alloc(length, km_flags);
			if (new_propp->prop_val == 0)  {
				kmem_free(new_propp->prop_name, name_buf_len);
				kmem_free(new_propp, sizeof (ddi_prop_t));
				cmn_err(CE_CONT, prop_no_mem_msg, name);
				return (DDI_PROP_NO_MEMORY);
			}
			bcopy(value, new_propp->prop_val, length);
		}
	}

	/*
	 * Link property into beginning of list. (Properties are LIFO order.)
	 */

	mutex_enter(&(DEVI(dip)->devi_lock));
	propp = *list_head;
	new_propp->prop_next = propp;
	*list_head = new_propp;
	mutex_exit(&(DEVI(dip)->devi_lock));
	return (DDI_PROP_SUCCESS);
}


/*
 * ddi_prop_change:	Modify a software managed property value
 *
 *			Set new length and value if found.
 *			returns DDI_PROP_INVAL_ARG if dev is DDI_DEV_T_ANY or
 *			input name is the NULL string.
 *			returns DDI_PROP_NO_MEMORY if unable to allocate memory
 *
 *			Note: an undef can be modified to be a define,
 *			(you can't go the other way.)
 */

static int
ddi_prop_change(dev_t dev, dev_info_t *dip, int flags,
    char *name, caddr_t value, int length)
{
	ddi_prop_t	*propp;
	ddi_prop_t	**ppropp;
	caddr_t		p = NULL;

	if ((dev == DDI_DEV_T_ANY) || (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	/*
	 * Preallocate buffer, even if we don't need it...
	 */
	if (length != 0)  {
		p = kmem_alloc(length, (flags & DDI_PROP_CANSLEEP) ?
		    KM_SLEEP : KM_NOSLEEP);
		if (p == NULL)	{
			cmn_err(CE_CONT, prop_no_mem_msg, name);
			return (DDI_PROP_NO_MEMORY);
		}
	}

	/*
	 * If the dev_t value contains DDI_MAJOR_T_UNKNOWN for the major
	 * number, a real dev_t value should be created based upon the dip's
	 * binding driver.  See ddi_prop_add...
	 */
	if (getmajor(dev) == DDI_MAJOR_T_UNKNOWN)
		dev = makedevice(
		    ddi_name_to_major(DEVI(dip)->devi_binding_name),
		    getminor(dev));

	/*
	 * Check to see if the property exists.  If so we modify it.
	 * Else we create it by calling ddi_prop_add().
	 */
	mutex_enter(&(DEVI(dip)->devi_lock));
	ppropp = &DEVI(dip)->devi_drv_prop_ptr;
	if (flags & DDI_PROP_SYSTEM_DEF)
		ppropp = &DEVI(dip)->devi_sys_prop_ptr;
	else if (flags & DDI_PROP_HW_DEF)
		ppropp = &DEVI(dip)->devi_hw_prop_ptr;

	if ((propp = i_ddi_prop_search(dev, name, flags, ppropp)) != NULL) {
		/*
		 * Need to reallocate buffer?  If so, do it
		 * carefully (reuse same space if new prop
		 * is same size and non-NULL sized).
		 */
		if (length != 0)
			bcopy(value, p, length);

		if (propp->prop_len != 0)
			kmem_free(propp->prop_val, propp->prop_len);

		propp->prop_len = length;
		propp->prop_val = p;
		propp->prop_flags &= ~DDI_PROP_UNDEF_IT;
		mutex_exit(&(DEVI(dip)->devi_lock));
		return (DDI_PROP_SUCCESS);
	}

	mutex_exit(&(DEVI(dip)->devi_lock));
	if (length != 0)
		kmem_free(p, length);

	return (ddi_prop_add(dev, dip, flags, name, value, length));
}

/*
 * Common update routine used to update and encode a property.	Creates
 * a property handle, calls the property encode routine, figures out if
 * the property already exists and updates if it does.	Otherwise it
 * creates if it does not exist.
 */
int
ddi_prop_update_common(dev_t match_dev, dev_info_t *dip, int flags,
    char *name, void *data, uint_t nelements,
    int (*prop_create)(prop_handle_t *, void *data, uint_t nelements))
{
	prop_handle_t	ph;
	int		rval;
	uint_t		ourflags;

	/*
	 * If dev_t is DDI_DEV_T_ANY or name's length is zero,
	 * return error.
	 */
	if (match_dev == DDI_DEV_T_ANY || name == NULL || strlen(name) == 0)
		return (DDI_PROP_INVAL_ARG);

	/*
	 * Create the handle
	 */
	ph.ph_data = NULL;
	ph.ph_cur_pos = NULL;
	ph.ph_save_pos = NULL;
	ph.ph_size = 0;
	ph.ph_ops = &prop_1275_ops;

	/*
	 * ourflags:
	 * For compatibility with the old interfaces.  The old interfaces
	 * didn't sleep by default and slept when the flag was set.  These
	 * interfaces to the opposite.	So the old interfaces now set the
	 * DDI_PROP_DONTSLEEP flag by default which tells us not to sleep.
	 *
	 * ph.ph_flags:
	 * Blocked data or unblocked data allocation
	 * for ph.ph_data in ddi_prop_encode_alloc()
	 */
	if (flags & DDI_PROP_DONTSLEEP) {
		ourflags = flags;
		ph.ph_flags = DDI_PROP_DONTSLEEP;
	} else {
		ourflags = flags | DDI_PROP_CANSLEEP;
		ph.ph_flags = DDI_PROP_CANSLEEP;
	}

	/*
	 * Encode the data and store it in the property handle by
	 * calling the prop_encode routine.
	 */
	if ((rval = (*prop_create)(&ph, data, nelements)) !=
	    DDI_PROP_SUCCESS) {
		if (rval == DDI_PROP_NO_MEMORY)
			cmn_err(CE_CONT, prop_no_mem_msg, name);
		if (ph.ph_size != 0)
			kmem_free(ph.ph_data, ph.ph_size);
		return (rval);
	}

	/*
	 * The old interfaces use a stacking approach to creating
	 * properties.	If we are being called from the old interfaces,
	 * the DDI_PROP_STACK_CREATE flag will be set, so we just do a
	 * create without checking.
	 */
	if (flags & DDI_PROP_STACK_CREATE) {
		rval = ddi_prop_add(match_dev, dip,
		    ourflags, name, ph.ph_data, ph.ph_size);
	} else {
		rval = ddi_prop_change(match_dev, dip,
		    ourflags, name, ph.ph_data, ph.ph_size);
	}

	/*
	 * Free the encoded data allocated in the prop_encode routine.
	 */
	if (ph.ph_size != 0)
		kmem_free(ph.ph_data, ph.ph_size);

	return (rval);
}


/*
 * ddi_prop_create:	Define a managed property:
 *			See above for details.
 */

int
ddi_prop_create(dev_t dev, dev_info_t *dip, int flag,
    char *name, caddr_t value, int length)
{
	if (!(flag & DDI_PROP_CANSLEEP)) {
		flag |= DDI_PROP_DONTSLEEP;
#ifdef DDI_PROP_DEBUG
		if (length != 0)
			cmn_err(CE_NOTE, "!ddi_prop_create: interface obsolete,"
			    "use ddi_prop_update (prop = %s, node = %s%d)",
			    name, ddi_driver_name(dip), ddi_get_instance(dip));
#endif /* DDI_PROP_DEBUG */
	}
	flag &= ~DDI_PROP_SYSTEM_DEF;
	flag |= DDI_PROP_STACK_CREATE | DDI_PROP_TYPE_ANY;
	return (ddi_prop_update_common(dev, dip, flag, name,
	    value, length, ddi_prop_fm_encode_bytes));
}

int
e_ddi_prop_create(dev_t dev, dev_info_t *dip, int flag,
    char *name, caddr_t value, int length)
{
	if (!(flag & DDI_PROP_CANSLEEP))
		flag |= DDI_PROP_DONTSLEEP;
	flag |= DDI_PROP_SYSTEM_DEF | DDI_PROP_STACK_CREATE | DDI_PROP_TYPE_ANY;
	return (ddi_prop_update_common(dev, dip, flag,
	    name, value, length, ddi_prop_fm_encode_bytes));
}

int
ddi_prop_modify(dev_t dev, dev_info_t *dip, int flag,
    char *name, caddr_t value, int length)
{
	ASSERT((flag & DDI_PROP_TYPE_MASK) == 0);

	/*
	 * If dev_t is DDI_DEV_T_ANY or name's length is zero,
	 * return error.
	 */
	if (dev == DDI_DEV_T_ANY || name == NULL || strlen(name) == 0)
		return (DDI_PROP_INVAL_ARG);

	if (!(flag & DDI_PROP_CANSLEEP))
		flag |= DDI_PROP_DONTSLEEP;
	flag &= ~DDI_PROP_SYSTEM_DEF;
	if (ddi_prop_exists(dev, dip, (flag | DDI_PROP_NOTPROM), name) == 0)
		return (DDI_PROP_NOT_FOUND);

	return (ddi_prop_update_common(dev, dip,
	    (flag | DDI_PROP_TYPE_BYTE), name,
	    value, length, ddi_prop_fm_encode_bytes));
}

int
e_ddi_prop_modify(dev_t dev, dev_info_t *dip, int flag,
    char *name, caddr_t value, int length)
{
	ASSERT((flag & DDI_PROP_TYPE_MASK) == 0);

	/*
	 * If dev_t is DDI_DEV_T_ANY or name's length is zero,
	 * return error.
	 */
	if (dev == DDI_DEV_T_ANY || name == NULL || strlen(name) == 0)
		return (DDI_PROP_INVAL_ARG);

	if (ddi_prop_exists(dev, dip, (flag | DDI_PROP_SYSTEM_DEF), name) == 0)
		return (DDI_PROP_NOT_FOUND);

	if (!(flag & DDI_PROP_CANSLEEP))
		flag |= DDI_PROP_DONTSLEEP;
	return (ddi_prop_update_common(dev, dip,
	    (flag | DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_BYTE),
	    name, value, length, ddi_prop_fm_encode_bytes));
}


/*
 * Common lookup routine used to lookup and decode a property.
 * Creates a property handle, searches for the raw encoded data,
 * fills in the handle, and calls the property decode functions
 * passed in.
 *
 * This routine is not static because ddi_bus_prop_op() which lives in
 * ddi_impl.c calls it.  No driver should be calling this routine.
 */
int
ddi_prop_lookup_common(dev_t match_dev, dev_info_t *dip,
    uint_t flags, char *name, void *data, uint_t *nelements,
    int (*prop_decoder)(prop_handle_t *, void *data, uint_t *nelements))
{
	int		rval;
	uint_t		ourflags;
	prop_handle_t	ph;

	if ((match_dev == DDI_DEV_T_NONE) ||
	    (name == NULL) || (strlen(name) == 0))
		return (DDI_PROP_INVAL_ARG);

	ourflags = (flags & DDI_PROP_DONTSLEEP) ? flags :
	    flags | DDI_PROP_CANSLEEP;

	/*
	 * Get the encoded data
	 */
	bzero(&ph, sizeof (prop_handle_t));

	if ((flags & DDI_UNBND_DLPI2) || (flags & DDI_PROP_ROOTNEX_GLOBAL)) {
		/*
		 * For rootnex and unbound dlpi style-2 devices, index into
		 * the devnames' array and search the global
		 * property list.
		 */
		ourflags &= ~DDI_UNBND_DLPI2;
		rval = i_ddi_prop_search_global(match_dev,
		    ourflags, name, &ph.ph_data, &ph.ph_size);
	} else {
		rval = ddi_prop_search_common(match_dev, dip,
		    PROP_LEN_AND_VAL_ALLOC, ourflags, name,
		    &ph.ph_data, &ph.ph_size);

	}

	if (rval != DDI_PROP_SUCCESS && rval != DDI_PROP_FOUND_1275) {
		ASSERT(ph.ph_data == NULL);
		ASSERT(ph.ph_size == 0);
		return (rval);
	}

	/*
	 * If the encoded data came from a OBP or software
	 * use the 1275 OBP decode/encode routines.
	 */
	ph.ph_cur_pos = ph.ph_data;
	ph.ph_save_pos = ph.ph_data;
	ph.ph_ops = &prop_1275_ops;
	ph.ph_flags = (rval == DDI_PROP_FOUND_1275) ? PH_FROM_PROM : 0;

	rval = (*prop_decoder)(&ph, data, nelements);

	/*
	 * Free the encoded data
	 */
	if (ph.ph_size != 0)
		kmem_free(ph.ph_data, ph.ph_size);

	return (rval);
}

/*
 * Lookup and return an array of composite properties.  The driver must
 * provide the decode routine.
 */
int
ddi_prop_lookup(dev_t match_dev, dev_info_t *dip,
    uint_t flags, char *name, void *data, uint_t *nelements,
    int (*prop_decoder)(prop_handle_t *, void *data, uint_t *nelements))
{
	return (ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_COMPOSITE), name,
	    data, nelements, prop_decoder));
}

/*
 * Return 1 if a property exists (no type checking done).
 * Return 0 if it does not exist.
 */
int
ddi_prop_exists(dev_t match_dev, dev_info_t *dip, uint_t flags, char *name)
{
	int	i;
	uint_t	x = 0;

	i = ddi_prop_search_common(match_dev, dip, PROP_EXISTS,
	    flags | DDI_PROP_TYPE_MASK, name, NULL, &x);
	return (i == DDI_PROP_SUCCESS || i == DDI_PROP_FOUND_1275);
}


/*
 * Update an array of composite properties.  The driver must
 * provide the encode routine.
 */
int
ddi_prop_update(dev_t match_dev, dev_info_t *dip,
    char *name, void *data, uint_t nelements,
    int (*prop_create)(prop_handle_t *, void *data, uint_t nelements))
{
	return (ddi_prop_update_common(match_dev, dip, DDI_PROP_TYPE_COMPOSITE,
	    name, data, nelements, prop_create));
}

/*
 * Get a single integer or boolean property and return it.
 * If the property does not exists, or cannot be decoded,
 * then return the defvalue passed in.
 *
 * This routine always succeeds.
 */
int
ddi_prop_get_int(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int defvalue)
{
	int	data;
	uint_t	nelements;
	int	rval;

	if (flags & ~(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
	    LDI_DEV_T_ANY | DDI_UNBND_DLPI2 | DDI_PROP_ROOTNEX_GLOBAL)) {
#ifdef DEBUG
		if (dip != NULL) {
			cmn_err(CE_WARN, "ddi_prop_get_int: invalid flag"
			    " 0x%x (prop = %s, node = %s%d)", flags,
			    name, ddi_driver_name(dip), ddi_get_instance(dip));
		}
#endif /* DEBUG */
		flags &= DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
		    LDI_DEV_T_ANY | DDI_UNBND_DLPI2;
	}

	if ((rval = ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_INT), name, &data, &nelements,
	    ddi_prop_fm_decode_int)) != DDI_PROP_SUCCESS) {
		if (rval == DDI_PROP_END_OF_DATA)
			data = 1;
		else
			data = defvalue;
	}
	return (data);
}

/*
 * Get a single 64 bit integer or boolean property and return it.
 * If the property does not exists, or cannot be decoded,
 * then return the defvalue passed in.
 *
 * This routine always succeeds.
 */
int64_t
ddi_prop_get_int64(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int64_t defvalue)
{
	int64_t	data;
	uint_t	nelements;
	int	rval;

	if (flags & ~(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
	    LDI_DEV_T_ANY | DDI_UNBND_DLPI2 | DDI_PROP_ROOTNEX_GLOBAL)) {
#ifdef DEBUG
		if (dip != NULL) {
			cmn_err(CE_WARN, "ddi_prop_get_int64: invalid flag"
			    " 0x%x (prop = %s, node = %s%d)", flags,
			    name, ddi_driver_name(dip), ddi_get_instance(dip));
		}
#endif /* DEBUG */
		return (DDI_PROP_INVAL_ARG);
	}

	if ((rval = ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_INT64 | DDI_PROP_NOTPROM),
	    name, &data, &nelements, ddi_prop_fm_decode_int64))
	    != DDI_PROP_SUCCESS) {
		if (rval == DDI_PROP_END_OF_DATA)
			data = 1;
		else
			data = defvalue;
	}
	return (data);
}

/*
 * Get an array of integer property
 */
int
ddi_prop_lookup_int_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int **data, uint_t *nelements)
{
	if (flags & ~(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
	    LDI_DEV_T_ANY | DDI_UNBND_DLPI2 | DDI_PROP_ROOTNEX_GLOBAL)) {
#ifdef DEBUG
		if (dip != NULL) {
			cmn_err(CE_WARN, "ddi_prop_lookup_int_array: "
			    "invalid flag 0x%x (prop = %s, node = %s%d)",
			    flags, name, ddi_driver_name(dip),
			    ddi_get_instance(dip));
		}
#endif /* DEBUG */
		flags &= DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
		    LDI_DEV_T_ANY | DDI_UNBND_DLPI2;
	}

	return (ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_INT), name, data,
	    nelements, ddi_prop_fm_decode_ints));
}

/*
 * Get an array of 64 bit integer properties
 */
int
ddi_prop_lookup_int64_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, int64_t **data, uint_t *nelements)
{
	if (flags & ~(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
	    LDI_DEV_T_ANY | DDI_UNBND_DLPI2 | DDI_PROP_ROOTNEX_GLOBAL)) {
#ifdef DEBUG
		if (dip != NULL) {
			cmn_err(CE_WARN, "ddi_prop_lookup_int64_array: "
			    "invalid flag 0x%x (prop = %s, node = %s%d)",
			    flags, name, ddi_driver_name(dip),
			    ddi_get_instance(dip));
		}
#endif /* DEBUG */
		return (DDI_PROP_INVAL_ARG);
	}

	return (ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_INT64 | DDI_PROP_NOTPROM),
	    name, data, nelements, ddi_prop_fm_decode_int64_array));
}

/*
 * Update a single integer property.  If the property exists on the drivers
 * property list it updates, else it creates it.
 */
int
ddi_prop_update_int(dev_t match_dev, dev_info_t *dip,
    char *name, int data)
{
	return (ddi_prop_update_common(match_dev, dip, DDI_PROP_TYPE_INT,
	    name, &data, 1, ddi_prop_fm_encode_ints));
}

/*
 * Update a single 64 bit integer property.
 * Update the driver property list if it exists, else create it.
 */
int
ddi_prop_update_int64(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t data)
{
	return (ddi_prop_update_common(match_dev, dip, DDI_PROP_TYPE_INT64,
	    name, &data, 1, ddi_prop_fm_encode_int64));
}

int
e_ddi_prop_update_int(dev_t match_dev, dev_info_t *dip,
    char *name, int data)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_INT,
	    name, &data, 1, ddi_prop_fm_encode_ints));
}

int
e_ddi_prop_update_int64(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t data)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_INT64,
	    name, &data, 1, ddi_prop_fm_encode_int64));
}

/*
 * Update an array of integer property.  If the property exists on the drivers
 * property list it updates, else it creates it.
 */
int
ddi_prop_update_int_array(dev_t match_dev, dev_info_t *dip,
    char *name, int *data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip, DDI_PROP_TYPE_INT,
	    name, data, nelements, ddi_prop_fm_encode_ints));
}

/*
 * Update an array of 64 bit integer properties.
 * Update the driver property list if it exists, else create it.
 */
int
ddi_prop_update_int64_array(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t *data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip, DDI_PROP_TYPE_INT64,
	    name, data, nelements, ddi_prop_fm_encode_int64));
}

int
e_ddi_prop_update_int64_array(dev_t match_dev, dev_info_t *dip,
    char *name, int64_t *data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_INT64,
	    name, data, nelements, ddi_prop_fm_encode_int64));
}

int
e_ddi_prop_update_int_array(dev_t match_dev, dev_info_t *dip,
    char *name, int *data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_INT,
	    name, data, nelements, ddi_prop_fm_encode_ints));
}

/*
 * Get a single string property.
 */
int
ddi_prop_lookup_string(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, char **data)
{
	uint_t x;

	if (flags & ~(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
	    LDI_DEV_T_ANY | DDI_UNBND_DLPI2 | DDI_PROP_ROOTNEX_GLOBAL)) {
#ifdef DEBUG
		if (dip != NULL) {
			cmn_err(CE_WARN, "%s: invalid flag 0x%x "
			    "(prop = %s, node = %s%d); invalid bits ignored",
			    "ddi_prop_lookup_string", flags, name,
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
#endif /* DEBUG */
		flags &= DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
		    LDI_DEV_T_ANY | DDI_UNBND_DLPI2;
	}

	return (ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_STRING), name, data,
	    &x, ddi_prop_fm_decode_string));
}

/*
 * Get an array of strings property.
 */
int
ddi_prop_lookup_string_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, char ***data, uint_t *nelements)
{
	if (flags & ~(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
	    LDI_DEV_T_ANY | DDI_UNBND_DLPI2 | DDI_PROP_ROOTNEX_GLOBAL)) {
#ifdef DEBUG
		if (dip != NULL) {
			cmn_err(CE_WARN, "ddi_prop_lookup_string_array: "
			    "invalid flag 0x%x (prop = %s, node = %s%d)",
			    flags, name, ddi_driver_name(dip),
			    ddi_get_instance(dip));
		}
#endif /* DEBUG */
		flags &= DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
		    LDI_DEV_T_ANY | DDI_UNBND_DLPI2;
	}

	return (ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_STRING), name, data,
	    nelements, ddi_prop_fm_decode_strings));
}

/*
 * Update a single string property.
 */
int
ddi_prop_update_string(dev_t match_dev, dev_info_t *dip,
    char *name, char *data)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_TYPE_STRING, name, &data, 1,
	    ddi_prop_fm_encode_string));
}

int
e_ddi_prop_update_string(dev_t match_dev, dev_info_t *dip,
    char *name, char *data)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_STRING,
	    name, &data, 1, ddi_prop_fm_encode_string));
}


/*
 * Update an array of strings property.
 */
int
ddi_prop_update_string_array(dev_t match_dev, dev_info_t *dip,
    char *name, char **data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_TYPE_STRING, name, data, nelements,
	    ddi_prop_fm_encode_strings));
}

int
e_ddi_prop_update_string_array(dev_t match_dev, dev_info_t *dip,
    char *name, char **data, uint_t nelements)
{
	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_STRING,
	    name, data, nelements,
	    ddi_prop_fm_encode_strings));
}


/*
 * Get an array of bytes property.
 */
int
ddi_prop_lookup_byte_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    char *name, uchar_t **data, uint_t *nelements)
{
	if (flags & ~(DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
	    LDI_DEV_T_ANY | DDI_UNBND_DLPI2 | DDI_PROP_ROOTNEX_GLOBAL)) {
#ifdef DEBUG
		if (dip != NULL) {
			cmn_err(CE_WARN, "ddi_prop_lookup_byte_array: "
			    " invalid flag 0x%x (prop = %s, node = %s%d)",
			    flags, name, ddi_driver_name(dip),
			    ddi_get_instance(dip));
		}
#endif /* DEBUG */
		flags &= DDI_PROP_DONTPASS | DDI_PROP_NOTPROM |
		    LDI_DEV_T_ANY | DDI_UNBND_DLPI2;
	}

	return (ddi_prop_lookup_common(match_dev, dip,
	    (flags | DDI_PROP_TYPE_BYTE), name, data,
	    nelements, ddi_prop_fm_decode_bytes));
}

/*
 * Update an array of bytes property.
 */
int
ddi_prop_update_byte_array(dev_t match_dev, dev_info_t *dip,
    char *name, uchar_t *data, uint_t nelements)
{
	if (nelements == 0)
		return (DDI_PROP_INVAL_ARG);

	return (ddi_prop_update_common(match_dev, dip, DDI_PROP_TYPE_BYTE,
	    name, data, nelements, ddi_prop_fm_encode_bytes));
}


int
e_ddi_prop_update_byte_array(dev_t match_dev, dev_info_t *dip,
    char *name, uchar_t *data, uint_t nelements)
{
	if (nelements == 0)
		return (DDI_PROP_INVAL_ARG);

	return (ddi_prop_update_common(match_dev, dip,
	    DDI_PROP_SYSTEM_DEF | DDI_PROP_TYPE_BYTE,
	    name, data, nelements, ddi_prop_fm_encode_bytes));
}


/*
 * ddi_prop_remove_common:	Undefine a managed property:
 *			Input dev_t must match dev_t when defined.
 *			Returns DDI_PROP_NOT_FOUND, possibly.
 *			DDI_PROP_INVAL_ARG is also possible if dev is
 *			DDI_DEV_T_ANY or incoming name is the NULL string.
 */
int
ddi_prop_remove_common(dev_t dev, dev_info_t *dip, char *name, int flag)
{
	ddi_prop_t	**list_head = &(DEVI(dip)->devi_drv_prop_ptr);
	ddi_prop_t	*propp;
	ddi_prop_t	*lastpropp = NULL;

	if ((dev == DDI_DEV_T_ANY) || (name == (char *)0) ||
	    (strlen(name) == 0)) {
		return (DDI_PROP_INVAL_ARG);
	}

	if (flag & DDI_PROP_SYSTEM_DEF)
		list_head = &(DEVI(dip)->devi_sys_prop_ptr);
	else if (flag & DDI_PROP_HW_DEF)
		list_head = &(DEVI(dip)->devi_hw_prop_ptr);

	mutex_enter(&(DEVI(dip)->devi_lock));

	for (propp = *list_head; propp != NULL; propp = propp->prop_next)  {
		if (DDI_STRSAME(propp->prop_name, name) &&
		    (dev == propp->prop_dev)) {
			/*
			 * Unlink this propp allowing for it to
			 * be first in the list:
			 */

			if (lastpropp == NULL)
				*list_head = propp->prop_next;
			else
				lastpropp->prop_next = propp->prop_next;

			mutex_exit(&(DEVI(dip)->devi_lock));

			/*
			 * Free memory and return...
			 */
			kmem_free(propp->prop_name,
			    strlen(propp->prop_name) + 1);
			if (propp->prop_len != 0)
				kmem_free(propp->prop_val, propp->prop_len);
			kmem_free(propp, sizeof (ddi_prop_t));
			return (DDI_PROP_SUCCESS);
		}
		lastpropp = propp;
	}
	mutex_exit(&(DEVI(dip)->devi_lock));
	return (DDI_PROP_NOT_FOUND);
}

int
ddi_prop_remove(dev_t dev, dev_info_t *dip, char *name)
{
	return (ddi_prop_remove_common(dev, dip, name, 0));
}

int
e_ddi_prop_remove(dev_t dev, dev_info_t *dip, char *name)
{
	return (ddi_prop_remove_common(dev, dip, name, DDI_PROP_SYSTEM_DEF));
}

/*
 * e_ddi_prop_list_delete: remove a list of properties
 *	Note that the caller needs to provide the required protection
 *	(eg. devi_lock if these properties are still attached to a devi)
 */
void
e_ddi_prop_list_delete(ddi_prop_t *props)
{
	i_ddi_prop_list_delete(props);
}

/*
 * ddi_prop_remove_all_common:
 *	Used before unloading a driver to remove
 *	all properties. (undefines all dev_t's props.)
 *	Also removes `explicitly undefined' props.
 *	No errors possible.
 */
void
ddi_prop_remove_all_common(dev_info_t *dip, int flag)
{
	ddi_prop_t	**list_head;

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (flag & DDI_PROP_SYSTEM_DEF) {
		list_head = &(DEVI(dip)->devi_sys_prop_ptr);
	} else if (flag & DDI_PROP_HW_DEF) {
		list_head = &(DEVI(dip)->devi_hw_prop_ptr);
	} else {
		list_head = &(DEVI(dip)->devi_drv_prop_ptr);
	}
	i_ddi_prop_list_delete(*list_head);
	*list_head = NULL;
	mutex_exit(&(DEVI(dip)->devi_lock));
}


/*
 * ddi_prop_remove_all:		Remove all driver prop definitions.
 */

void
ddi_prop_remove_all(dev_info_t *dip)
{
	i_ddi_prop_dyn_driver_set(dip, NULL);
	ddi_prop_remove_all_common(dip, 0);
}

/*
 * e_ddi_prop_remove_all:	Remove all system prop definitions.
 */

void
e_ddi_prop_remove_all(dev_info_t *dip)
{
	ddi_prop_remove_all_common(dip, (int)DDI_PROP_SYSTEM_DEF);
}


/*
 * ddi_prop_undefine:	Explicitly undefine a property.  Property
 *			searches which match this property return
 *			the error code DDI_PROP_UNDEFINED.
 *
 *			Use ddi_prop_remove to negate effect of
 *			ddi_prop_undefine
 *
 *			See above for error returns.
 */

int
ddi_prop_undefine(dev_t dev, dev_info_t *dip, int flag, char *name)
{
	if (!(flag & DDI_PROP_CANSLEEP))
		flag |= DDI_PROP_DONTSLEEP;
	flag |= DDI_PROP_STACK_CREATE | DDI_PROP_UNDEF_IT | DDI_PROP_TYPE_ANY;
	return (ddi_prop_update_common(dev, dip, flag,
	    name, NULL, 0, ddi_prop_fm_encode_bytes));
}

int
e_ddi_prop_undefine(dev_t dev, dev_info_t *dip, int flag, char *name)
{
	if (!(flag & DDI_PROP_CANSLEEP))
		flag |= DDI_PROP_DONTSLEEP;
	flag |= DDI_PROP_SYSTEM_DEF | DDI_PROP_STACK_CREATE |
	    DDI_PROP_UNDEF_IT | DDI_PROP_TYPE_ANY;
	return (ddi_prop_update_common(dev, dip, flag,
	    name, NULL, 0, ddi_prop_fm_encode_bytes));
}

/*
 * Support for gathering dynamic properties in devinfo snapshot.
 */
void
i_ddi_prop_dyn_driver_set(dev_info_t *dip, i_ddi_prop_dyn_t *dp)
{
	DEVI(dip)->devi_prop_dyn_driver = dp;
}

i_ddi_prop_dyn_t *
i_ddi_prop_dyn_driver_get(dev_info_t *dip)
{
	return (DEVI(dip)->devi_prop_dyn_driver);
}

void
i_ddi_prop_dyn_parent_set(dev_info_t *dip, i_ddi_prop_dyn_t *dp)
{
	DEVI(dip)->devi_prop_dyn_parent = dp;
}

i_ddi_prop_dyn_t *
i_ddi_prop_dyn_parent_get(dev_info_t *dip)
{
	return (DEVI(dip)->devi_prop_dyn_parent);
}

void
i_ddi_prop_dyn_cache_invalidate(dev_info_t *dip, i_ddi_prop_dyn_t *dp)
{
	/* for now we invalidate the entire cached snapshot */
	if (dip && dp)
		i_ddi_di_cache_invalidate();
}

/* ARGSUSED */
void
ddi_prop_cache_invalidate(dev_t dev, dev_info_t *dip, char *name, int flags)
{
	/* for now we invalidate the entire cached snapshot */
	i_ddi_di_cache_invalidate();
}


/*
 * Code to search hardware layer (PROM), if it exists, on behalf of child.
 *
 * if input dip != child_dip, then call is on behalf of child
 * to search PROM, do it via ddi_prop_search_common() and ascend only
 * if allowed.
 *
 * if input dip == ch_dip (child_dip), call is on behalf of root driver,
 * to search for PROM defined props only.
 *
 * Note that the PROM search is done only if the requested dev
 * is either DDI_DEV_T_ANY or DDI_DEV_T_NONE. PROM properties
 * have no associated dev, thus are automatically associated with
 * DDI_DEV_T_NONE.
 *
 * Modifying flag DDI_PROP_NOTPROM inhibits the search in the h/w layer.
 *
 * Returns DDI_PROP_FOUND_1275 if found to indicate to framework
 * that the property resides in the prom.
 */
int
impl_ddi_bus_prop_op(dev_t dev, dev_info_t *dip, dev_info_t *ch_dip,
    ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int	len;
	caddr_t buffer;

	/*
	 * If requested dev is DDI_DEV_T_NONE or DDI_DEV_T_ANY, then
	 * look in caller's PROM if it's a self identifying device...
	 *
	 * Note that this is very similar to ddi_prop_op, but we
	 * search the PROM instead of the s/w defined properties,
	 * and we are called on by the parent driver to do this for
	 * the child.
	 */

	if (((dev == DDI_DEV_T_NONE) || (dev == DDI_DEV_T_ANY)) &&
	    ndi_dev_is_prom_node(ch_dip) &&
	    ((mod_flags & DDI_PROP_NOTPROM) == 0)) {
		len = prom_getproplen((pnode_t)DEVI(ch_dip)->devi_nodeid, name);
		if (len == -1) {
			return (DDI_PROP_NOT_FOUND);
		}

		/*
		 * If exists only request, we're done
		 */
		if (prop_op == PROP_EXISTS) {
			return (DDI_PROP_FOUND_1275);
		}

		/*
		 * If length only request or prop length == 0, get out
		 */
		if ((prop_op == PROP_LEN) || (len == 0)) {
			*lengthp = len;
			return (DDI_PROP_FOUND_1275);
		}

		/*
		 * Allocate buffer if required... (either way `buffer'
		 * is receiving address).
		 */

		switch (prop_op) {

		case PROP_LEN_AND_VAL_ALLOC:

			buffer = kmem_alloc((size_t)len,
			    mod_flags & DDI_PROP_CANSLEEP ?
			    KM_SLEEP : KM_NOSLEEP);
			if (buffer == NULL) {
				return (DDI_PROP_NO_MEMORY);
			}
			*(caddr_t *)valuep = buffer;
			break;

		case PROP_LEN_AND_VAL_BUF:

			if (len > (*lengthp)) {
				*lengthp = len;
				return (DDI_PROP_BUF_TOO_SMALL);
			}

			buffer = valuep;
			break;

		default:
			break;
		}

		/*
		 * Call the PROM function to do the copy.
		 */
		(void) prom_getprop((pnode_t)DEVI(ch_dip)->devi_nodeid,
		    name, buffer);

		*lengthp = len; /* return the actual length to the caller */
		(void) impl_fix_props(dip, ch_dip, name, len, buffer);
		return (DDI_PROP_FOUND_1275);
	}

	return (DDI_PROP_NOT_FOUND);
}

/*
 * The ddi_bus_prop_op default bus nexus prop op function.
 *
 * Code to search hardware layer (PROM), if it exists,
 * on behalf of child, then, if appropriate, ascend and check
 * my own software defined properties...
 */
int
ddi_bus_prop_op(dev_t dev, dev_info_t *dip, dev_info_t *ch_dip,
    ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int	error;

	error = impl_ddi_bus_prop_op(dev, dip, ch_dip, prop_op, mod_flags,
	    name, valuep, lengthp);

	if (error == DDI_PROP_SUCCESS || error == DDI_PROP_FOUND_1275 ||
	    error == DDI_PROP_BUF_TOO_SMALL)
		return (error);

	if (error == DDI_PROP_NO_MEMORY) {
		cmn_err(CE_CONT, prop_no_mem_msg, name);
		return (DDI_PROP_NO_MEMORY);
	}

	/*
	 * Check the 'options' node as a last resort
	 */
	if ((mod_flags & DDI_PROP_DONTPASS) != 0)
		return (DDI_PROP_NOT_FOUND);

	if (ch_dip == ddi_root_node())	{
		/*
		 * As a last resort, when we've reached
		 * the top and still haven't found the
		 * property, see if the desired property
		 * is attached to the options node.
		 *
		 * The options dip is attached right after boot.
		 */
		ASSERT(options_dip != NULL);
		/*
		 * Force the "don't pass" flag to *just* see
		 * what the options node has to offer.
		 */
		return (ddi_prop_search_common(dev, options_dip, prop_op,
		    mod_flags|DDI_PROP_DONTPASS, name, valuep,
		    (uint_t *)lengthp));
	}

	/*
	 * Otherwise, continue search with parent's s/w defined properties...
	 * NOTE: Using `dip' in following call increments the level.
	 */

	return (ddi_prop_search_common(dev, dip, prop_op, mod_flags,
	    name, valuep, (uint_t *)lengthp));
}

/*
 * External property functions used by other parts of the kernel...
 */

/*
 * e_ddi_getlongprop: See comments for ddi_get_longprop.
 */

int
e_ddi_getlongprop(dev_t dev, vtype_t type, char *name, int flags,
    caddr_t valuep, int *lengthp)
{
	_NOTE(ARGUNUSED(type))
	dev_info_t *devi;
	ddi_prop_op_t prop_op = PROP_LEN_AND_VAL_ALLOC;
	int error;

	if ((devi = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (DDI_PROP_NOT_FOUND);

	error = cdev_prop_op(dev, devi, prop_op, flags, name, valuep, lengthp);
	ddi_release_devi(devi);
	return (error);
}

/*
 * e_ddi_getlongprop_buf:	See comments for ddi_getlongprop_buf.
 */

int
e_ddi_getlongprop_buf(dev_t dev, vtype_t type, char *name, int flags,
    caddr_t valuep, int *lengthp)
{
	_NOTE(ARGUNUSED(type))
	dev_info_t *devi;
	ddi_prop_op_t prop_op = PROP_LEN_AND_VAL_BUF;
	int error;

	if ((devi = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (DDI_PROP_NOT_FOUND);

	error = cdev_prop_op(dev, devi, prop_op, flags, name, valuep, lengthp);
	ddi_release_devi(devi);
	return (error);
}

/*
 * e_ddi_getprop:	See comments for ddi_getprop.
 */
int
e_ddi_getprop(dev_t dev, vtype_t type, char *name, int flags, int defvalue)
{
	_NOTE(ARGUNUSED(type))
	dev_info_t *devi;
	ddi_prop_op_t prop_op = PROP_LEN_AND_VAL_BUF;
	int	propvalue = defvalue;
	int	proplength = sizeof (int);
	int	error;

	if ((devi = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (defvalue);

	error = cdev_prop_op(dev, devi, prop_op,
	    flags, name, (caddr_t)&propvalue, &proplength);
	ddi_release_devi(devi);

	if ((error == DDI_PROP_SUCCESS) && (proplength == 0))
		propvalue = 1;

	return (propvalue);
}

/*
 * e_ddi_getprop_int64:
 *
 * This is a typed interfaces, but predates typed properties. With the
 * introduction of typed properties the framework tries to ensure
 * consistent use of typed interfaces. This is why TYPE_INT64 is not
 * part of TYPE_ANY.  E_ddi_getprop_int64 is a special case where a
 * typed interface invokes legacy (non-typed) interfaces:
 * cdev_prop_op(), prop_op(9E), ddi_prop_op(9F)).  In this case the
 * fact that TYPE_INT64 is not part of TYPE_ANY matters.  To support
 * this type of lookup as a single operation we invoke the legacy
 * non-typed interfaces with the special CONSUMER_TYPED bit set. The
 * framework ddi_prop_op(9F) implementation is expected to check for
 * CONSUMER_TYPED and, if set, expand type bits beyond TYPE_ANY
 * (currently TYPE_INT64).
 */
int64_t
e_ddi_getprop_int64(dev_t dev, vtype_t type, char *name,
    int flags, int64_t defvalue)
{
	_NOTE(ARGUNUSED(type))
	dev_info_t	*devi;
	ddi_prop_op_t	prop_op = PROP_LEN_AND_VAL_BUF;
	int64_t		propvalue = defvalue;
	int		proplength = sizeof (propvalue);
	int		error;

	if ((devi = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (defvalue);

	error = cdev_prop_op(dev, devi, prop_op, flags |
	    DDI_PROP_CONSUMER_TYPED, name, (caddr_t)&propvalue, &proplength);
	ddi_release_devi(devi);

	if ((error == DDI_PROP_SUCCESS) && (proplength == 0))
		propvalue = 1;

	return (propvalue);
}

/*
 * e_ddi_getproplen:	See comments for ddi_getproplen.
 */
int
e_ddi_getproplen(dev_t dev, vtype_t type, char *name, int flags, int *lengthp)
{
	_NOTE(ARGUNUSED(type))
	dev_info_t *devi;
	ddi_prop_op_t prop_op = PROP_LEN;
	int error;

	if ((devi = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (DDI_PROP_NOT_FOUND);

	error = cdev_prop_op(dev, devi, prop_op, flags, name, NULL, lengthp);
	ddi_release_devi(devi);
	return (error);
}

/*
 * Routines to get at elements of the dev_info structure
 */

/*
 * ddi_binding_name: Return the driver binding name of the devinfo node
 *		This is the name the OS used to bind the node to a driver.
 */
char *
ddi_binding_name(dev_info_t *dip)
{
	return (DEVI(dip)->devi_binding_name);
}

/*
 * ddi_driver_major: Return the major number of the driver that
 *	the supplied devinfo is bound to.  If not yet bound,
 *	DDI_MAJOR_T_NONE.
 *
 * When used by the driver bound to 'devi', this
 * function will reliably return the driver major number.
 * Other ways of determining the driver major number, such as
 *	major = ddi_name_to_major(ddi_get_name(devi));
 *	major = ddi_name_to_major(ddi_binding_name(devi));
 * can return a different result as the driver/alias binding
 * can change dynamically, and thus should be avoided.
 */
major_t
ddi_driver_major(dev_info_t *devi)
{
	return (DEVI(devi)->devi_major);
}

/*
 * ddi_driver_name: Return the normalized driver name. this is the
 *		actual driver name
 */
const char *
ddi_driver_name(dev_info_t *devi)
{
	major_t major;

	if ((major = ddi_driver_major(devi)) != DDI_MAJOR_T_NONE)
		return (ddi_major_to_name(major));

	return (ddi_node_name(devi));
}

/*
 * i_ddi_set_binding_name:	Set binding name.
 *
 *	Set the binding name to the given name.
 *	This routine is for use by the ddi implementation, not by drivers.
 */
void
i_ddi_set_binding_name(dev_info_t *dip, char *name)
{
	DEVI(dip)->devi_binding_name = name;

}

/*
 * ddi_get_name: A synonym of ddi_binding_name() ... returns a name
 * the implementation has used to bind the node to a driver.
 */
char *
ddi_get_name(dev_info_t *dip)
{
	return (DEVI(dip)->devi_binding_name);
}

/*
 * ddi_node_name: Return the name property of the devinfo node
 *		This may differ from ddi_binding_name if the node name
 *		does not define a binding to a driver (i.e. generic names).
 */
char *
ddi_node_name(dev_info_t *dip)
{
	return (DEVI(dip)->devi_node_name);
}


/*
 * ddi_get_nodeid:	Get nodeid stored in dev_info structure.
 */
int
ddi_get_nodeid(dev_info_t *dip)
{
	return (DEVI(dip)->devi_nodeid);
}

int
ddi_get_instance(dev_info_t *dip)
{
	return (DEVI(dip)->devi_instance);
}

struct dev_ops *
ddi_get_driver(dev_info_t *dip)
{
	return (DEVI(dip)->devi_ops);
}

void
ddi_set_driver(dev_info_t *dip, struct dev_ops *devo)
{
	DEVI(dip)->devi_ops = devo;
}

/*
 * ddi_set_driver_private/ddi_get_driver_private:
 * Get/set device driver private data in devinfo.
 */
void
ddi_set_driver_private(dev_info_t *dip, void *data)
{
	DEVI(dip)->devi_driver_data = data;
}

void *
ddi_get_driver_private(dev_info_t *dip)
{
	return (DEVI(dip)->devi_driver_data);
}

/*
 * ddi_get_parent, ddi_get_child, ddi_get_next_sibling
 */

dev_info_t *
ddi_get_parent(dev_info_t *dip)
{
	return ((dev_info_t *)DEVI(dip)->devi_parent);
}

dev_info_t *
ddi_get_child(dev_info_t *dip)
{
	return ((dev_info_t *)DEVI(dip)->devi_child);
}

dev_info_t *
ddi_get_next_sibling(dev_info_t *dip)
{
	return ((dev_info_t *)DEVI(dip)->devi_sibling);
}

dev_info_t *
ddi_get_next(dev_info_t *dip)
{
	return ((dev_info_t *)DEVI(dip)->devi_next);
}

void
ddi_set_next(dev_info_t *dip, dev_info_t *nextdip)
{
	DEVI(dip)->devi_next = DEVI(nextdip);
}

/*
 * ddi_root_node:		Return root node of devinfo tree
 */

dev_info_t *
ddi_root_node(void)
{
	extern dev_info_t *top_devinfo;

	return (top_devinfo);
}

/*
 * Miscellaneous functions:
 */

/*
 * Implementation specific hooks
 */

void
ddi_report_dev(dev_info_t *d)
{
	char *b;

	(void) ddi_ctlops(d, d, DDI_CTLOPS_REPORTDEV, (void *)0, (void *)0);

	/*
	 * If this devinfo node has cb_ops, it's implicitly accessible from
	 * userland, so we print its full name together with the instance
	 * number 'abbreviation' that the driver may use internally.
	 */
	if (DEVI(d)->devi_ops->devo_cb_ops != (struct cb_ops *)0 &&
	    (b = kmem_zalloc(MAXPATHLEN, KM_NOSLEEP))) {
		cmn_err(CE_CONT, "?%s%d is %s\n",
		    ddi_driver_name(d), ddi_get_instance(d),
		    ddi_pathname(d, b));
		kmem_free(b, MAXPATHLEN);
	}
}

/*
 * ddi_ctlops() is described in the assembler not to buy a new register
 * window when it's called and can reduce cost in climbing the device tree
 * without using the tail call optimization.
 */
int
ddi_dev_regsize(dev_info_t *dev, uint_t rnumber, off_t *result)
{
	int ret;

	ret = ddi_ctlops(dev, dev, DDI_CTLOPS_REGSIZE,
	    (void *)&rnumber, (void *)result);

	return (ret == DDI_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
}

int
ddi_dev_nregs(dev_info_t *dev, int *result)
{
	return (ddi_ctlops(dev, dev, DDI_CTLOPS_NREGS, 0, (void *)result));
}

int
ddi_dev_is_sid(dev_info_t *d)
{
	return (ddi_ctlops(d, d, DDI_CTLOPS_SIDDEV, (void *)0, (void *)0));
}

int
ddi_slaveonly(dev_info_t *d)
{
	return (ddi_ctlops(d, d, DDI_CTLOPS_SLAVEONLY, (void *)0, (void *)0));
}

int
ddi_dev_affinity(dev_info_t *a, dev_info_t *b)
{
	return (ddi_ctlops(a, a, DDI_CTLOPS_AFFINITY, (void *)b, (void *)0));
}

int
ddi_streams_driver(dev_info_t *dip)
{
	if (i_ddi_devi_attached(dip) &&
	    (DEVI(dip)->devi_ops->devo_cb_ops != NULL) &&
	    (DEVI(dip)->devi_ops->devo_cb_ops->cb_str != NULL))
		return (DDI_SUCCESS);
	return (DDI_FAILURE);
}

/*
 * callback free list
 */

static int ncallbacks;
static int nc_low = 170;
static int nc_med = 512;
static int nc_high = 2048;
static struct ddi_callback *callbackq;
static struct ddi_callback *callbackqfree;

/*
 * set/run callback lists
 */
struct	cbstats	{
	kstat_named_t	cb_asked;
	kstat_named_t	cb_new;
	kstat_named_t	cb_run;
	kstat_named_t	cb_delete;
	kstat_named_t	cb_maxreq;
	kstat_named_t	cb_maxlist;
	kstat_named_t	cb_alloc;
	kstat_named_t	cb_runouts;
	kstat_named_t	cb_L2;
	kstat_named_t	cb_grow;
} cbstats = {
	{"asked",	KSTAT_DATA_UINT32},
	{"new",		KSTAT_DATA_UINT32},
	{"run",		KSTAT_DATA_UINT32},
	{"delete",	KSTAT_DATA_UINT32},
	{"maxreq",	KSTAT_DATA_UINT32},
	{"maxlist",	KSTAT_DATA_UINT32},
	{"alloc",	KSTAT_DATA_UINT32},
	{"runouts",	KSTAT_DATA_UINT32},
	{"L2",		KSTAT_DATA_UINT32},
	{"grow",	KSTAT_DATA_UINT32},
};

#define	nc_asked	cb_asked.value.ui32
#define	nc_new		cb_new.value.ui32
#define	nc_run		cb_run.value.ui32
#define	nc_delete	cb_delete.value.ui32
#define	nc_maxreq	cb_maxreq.value.ui32
#define	nc_maxlist	cb_maxlist.value.ui32
#define	nc_alloc	cb_alloc.value.ui32
#define	nc_runouts	cb_runouts.value.ui32
#define	nc_L2		cb_L2.value.ui32
#define	nc_grow		cb_grow.value.ui32

static kmutex_t ddi_callback_mutex;

/*
 * callbacks are handled using a L1/L2 cache. The L1 cache
 * comes out of kmem_cache_alloc and can expand/shrink dynamically. If
 * we can't get callbacks from the L1 cache [because pageout is doing
 * I/O at the time freemem is 0], we allocate callbacks out of the
 * L2 cache. The L2 cache is static and depends on the memory size.
 * [We might also count the number of devices at probe time and
 * allocate one structure per device and adjust for deferred attach]
 */
void
impl_ddi_callback_init(void)
{
	int	i;
	uint_t	physmegs;
	kstat_t	*ksp;

	physmegs = physmem >> (20 - PAGESHIFT);
	if (physmegs < 48) {
		ncallbacks = nc_low;
	} else if (physmegs < 128) {
		ncallbacks = nc_med;
	} else {
		ncallbacks = nc_high;
	}

	/*
	 * init free list
	 */
	callbackq = kmem_zalloc(
	    ncallbacks * sizeof (struct ddi_callback), KM_SLEEP);
	for (i = 0; i < ncallbacks-1; i++)
		callbackq[i].c_nfree = &callbackq[i+1];
	callbackqfree = callbackq;

	/* init kstats */
	if (ksp = kstat_create("unix", 0, "cbstats", "misc", KSTAT_TYPE_NAMED,
	    sizeof (cbstats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL)) {
		ksp->ks_data = (void *) &cbstats;
		kstat_install(ksp);
	}

}

static void
callback_insert(int (*funcp)(caddr_t), caddr_t arg, uintptr_t *listid,
	int count)
{
	struct ddi_callback *list, *marker, *new;
	size_t size = sizeof (struct ddi_callback);

	list = marker = (struct ddi_callback *)*listid;
	while (list != NULL) {
		if (list->c_call == funcp && list->c_arg == arg) {
			list->c_count += count;
			return;
		}
		marker = list;
		list = list->c_nlist;
	}
	new = kmem_alloc(size, KM_NOSLEEP);
	if (new == NULL) {
		new = callbackqfree;
		if (new == NULL) {
			new = kmem_alloc_tryhard(sizeof (struct ddi_callback),
			    &size, KM_NOSLEEP | KM_PANIC);
			cbstats.nc_grow++;
		} else {
			callbackqfree = new->c_nfree;
			cbstats.nc_L2++;
		}
	}
	if (marker != NULL) {
		marker->c_nlist = new;
	} else {
		*listid = (uintptr_t)new;
	}
	new->c_size = size;
	new->c_nlist = NULL;
	new->c_call = funcp;
	new->c_arg = arg;
	new->c_count = count;
	cbstats.nc_new++;
	cbstats.nc_alloc++;
	if (cbstats.nc_alloc > cbstats.nc_maxlist)
		cbstats.nc_maxlist = cbstats.nc_alloc;
}

void
ddi_set_callback(int (*funcp)(caddr_t), caddr_t arg, uintptr_t *listid)
{
	mutex_enter(&ddi_callback_mutex);
	cbstats.nc_asked++;
	if ((cbstats.nc_asked - cbstats.nc_run) > cbstats.nc_maxreq)
		cbstats.nc_maxreq = (cbstats.nc_asked - cbstats.nc_run);
	(void) callback_insert(funcp, arg, listid, 1);
	mutex_exit(&ddi_callback_mutex);
}

static void
real_callback_run(void *Queue)
{
	int (*funcp)(caddr_t);
	caddr_t arg;
	int count, rval;
	uintptr_t *listid;
	struct ddi_callback *list, *marker;
	int check_pending = 1;
	int pending = 0;

	do {
		mutex_enter(&ddi_callback_mutex);
		listid = Queue;
		list = (struct ddi_callback *)*listid;
		if (list == NULL) {
			mutex_exit(&ddi_callback_mutex);
			return;
		}
		if (check_pending) {
			marker = list;
			while (marker != NULL) {
				pending += marker->c_count;
				marker = marker->c_nlist;
			}
			check_pending = 0;
		}
		ASSERT(pending > 0);
		ASSERT(list->c_count > 0);
		funcp = list->c_call;
		arg = list->c_arg;
		count = list->c_count;
		*(uintptr_t *)Queue = (uintptr_t)list->c_nlist;
		if (list >= &callbackq[0] &&
		    list <= &callbackq[ncallbacks-1]) {
			list->c_nfree = callbackqfree;
			callbackqfree = list;
		} else
			kmem_free(list, list->c_size);

		cbstats.nc_delete++;
		cbstats.nc_alloc--;
		mutex_exit(&ddi_callback_mutex);

		do {
			if ((rval = (*funcp)(arg)) == 0) {
				pending -= count;
				mutex_enter(&ddi_callback_mutex);
				(void) callback_insert(funcp, arg, listid,
				    count);
				cbstats.nc_runouts++;
			} else {
				pending--;
				mutex_enter(&ddi_callback_mutex);
				cbstats.nc_run++;
			}
			mutex_exit(&ddi_callback_mutex);
		} while (rval != 0 && (--count > 0));
	} while (pending > 0);
}

void
ddi_run_callback(uintptr_t *listid)
{
	softcall(real_callback_run, listid);
}

/*
 * ddi_periodic_t
 * ddi_periodic_add(void (*func)(void *), void *arg, hrtime_t interval,
 *     int level)
 *
 * INTERFACE LEVEL
 *      Solaris DDI specific (Solaris DDI)
 *
 * PARAMETERS
 *      func: the callback function
 *
 *            The callback function will be invoked. The function is invoked
 *            in kernel context if the argument level passed is the zero.
 *            Otherwise it's invoked in interrupt context at the specified
 *            level.
 *
 *       arg: the argument passed to the callback function
 *
 *  interval: interval time
 *
 *    level : callback interrupt level
 *
 *            If the value is the zero, the callback function is invoked
 *            in kernel context. If the value is more than the zero, but
 *            less than or equal to ten, the callback function is invoked in
 *            interrupt context at the specified interrupt level, which may
 *            be used for real time applications.
 *
 *            This value must be in range of 0-10, which can be a numeric
 *            number or a pre-defined macro (DDI_IPL_0, ... , DDI_IPL_10).
 *
 * DESCRIPTION
 *      ddi_periodic_add(9F) schedules the specified function to be
 *      periodically invoked in the interval time.
 *
 *      As well as timeout(9F), the exact time interval over which the function
 *      takes effect cannot be guaranteed, but the value given is a close
 *      approximation.
 *
 *      Drivers waiting on behalf of processes with real-time constraints must
 *      pass non-zero value with the level argument to ddi_periodic_add(9F).
 *
 * RETURN VALUES
 *      ddi_periodic_add(9F) returns a non-zero opaque value (ddi_periodic_t),
 *      which must be used for ddi_periodic_delete(9F) to specify the request.
 *
 * CONTEXT
 *      ddi_periodic_add(9F) can be called in user or kernel context, but
 *      it cannot be called in interrupt context, which is different from
 *      timeout(9F).
 */
ddi_periodic_t
ddi_periodic_add(void (*func)(void *), void *arg, hrtime_t interval, int level)
{
	/*
	 * Sanity check of the argument level.
	 */
	if (level < DDI_IPL_0 || level > DDI_IPL_10)
		cmn_err(CE_PANIC,
		    "ddi_periodic_add: invalid interrupt level (%d).", level);

	/*
	 * Sanity check of the context. ddi_periodic_add() cannot be
	 * called in either interrupt context or high interrupt context.
	 */
	if (servicing_interrupt())
		cmn_err(CE_PANIC,
		    "ddi_periodic_add: called in (high) interrupt context.");

	return ((ddi_periodic_t)i_timeout(func, arg, interval, level));
}

/*
 * void
 * ddi_periodic_delete(ddi_periodic_t req)
 *
 * INTERFACE LEVEL
 *     Solaris DDI specific (Solaris DDI)
 *
 * PARAMETERS
 *     req: ddi_periodic_t opaque value ddi_periodic_add(9F) returned
 *     previously.
 *
 * DESCRIPTION
 *     ddi_periodic_delete(9F) cancels the ddi_periodic_add(9F) request
 *     previously requested.
 *
 *     ddi_periodic_delete(9F) will not return until the pending request
 *     is canceled or executed.
 *
 *     As well as untimeout(9F), calling ddi_periodic_delete(9F) for a
 *     timeout which is either running on another CPU, or has already
 *     completed causes no problems. However, unlike untimeout(9F), there is
 *     no restrictions on the lock which might be held across the call to
 *     ddi_periodic_delete(9F).
 *
 *     Drivers should be structured with the understanding that the arrival of
 *     both an interrupt and a timeout for that interrupt can occasionally
 *     occur, in either order.
 *
 * CONTEXT
 *     ddi_periodic_delete(9F) can be called in user or kernel context, but
 *     it cannot be called in interrupt context, which is different from
 *     untimeout(9F).
 */
void
ddi_periodic_delete(ddi_periodic_t req)
{
	/*
	 * Sanity check of the context. ddi_periodic_delete() cannot be
	 * called in either interrupt context or high interrupt context.
	 */
	if (servicing_interrupt())
		cmn_err(CE_PANIC,
		    "ddi_periodic_delete: called in (high) interrupt context.");

	i_untimeout((timeout_t)req);
}

dev_info_t *
nodevinfo(dev_t dev, int otyp)
{
	_NOTE(ARGUNUSED(dev, otyp))
	return ((dev_info_t *)0);
}

/*
 * A driver should support its own getinfo(9E) entry point. This function
 * is provided as a convenience for ON drivers that don't expect their
 * getinfo(9E) entry point to be called. A driver that uses this must not
 * call ddi_create_minor_node.
 */
int
ddi_no_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip, infocmd, arg, result))
	return (DDI_FAILURE);
}

/*
 * A driver should support its own getinfo(9E) entry point. This function
 * is provided as a convenience for ON drivers that where the minor number
 * is the instance. Drivers that do not have 1:1 mapping must implement
 * their own getinfo(9E) function.
 */
int
ddi_getinfo_1to1(dev_info_t *dip, ddi_info_cmd_t infocmd,
    void *arg, void **result)
{
	_NOTE(ARGUNUSED(dip))
	int	instance;

	if (infocmd != DDI_INFO_DEVT2INSTANCE)
		return (DDI_FAILURE);

	instance = getminor((dev_t)(uintptr_t)arg);
	*result = (void *)(uintptr_t)instance;
	return (DDI_SUCCESS);
}

int
ddifail(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	_NOTE(ARGUNUSED(devi, cmd))
	return (DDI_FAILURE);
}

int
ddi_no_dma_map(dev_info_t *dip, dev_info_t *rdip,
    struct ddi_dma_req *dmareqp, ddi_dma_handle_t *handlep)
{
	_NOTE(ARGUNUSED(dip, rdip, dmareqp, handlep))
	return (DDI_DMA_NOMAPPING);
}

int
ddi_no_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	_NOTE(ARGUNUSED(dip, rdip, attr, waitfp, arg, handlep))
	return (DDI_DMA_BADATTR);
}

int
ddi_no_dma_freehdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	_NOTE(ARGUNUSED(dip, rdip, handle))
	return (DDI_FAILURE);
}

int
ddi_no_dma_bindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, struct ddi_dma_req *dmareq,
    ddi_dma_cookie_t *cp, uint_t *ccountp)
{
	_NOTE(ARGUNUSED(dip, rdip, handle, dmareq, cp, ccountp))
	return (DDI_DMA_NOMAPPING);
}

int
ddi_no_dma_unbindhdl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle)
{
	_NOTE(ARGUNUSED(dip, rdip, handle))
	return (DDI_FAILURE);
}

int
ddi_no_dma_flush(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, off_t off, size_t len,
    uint_t cache_flags)
{
	_NOTE(ARGUNUSED(dip, rdip, handle, off, len, cache_flags))
	return (DDI_FAILURE);
}

int
ddi_no_dma_win(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, uint_t win, off_t *offp,
    size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	_NOTE(ARGUNUSED(dip, rdip, handle, win, offp, lenp, cookiep, ccountp))
	return (DDI_FAILURE);
}

int
ddi_no_dma_mctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_dma_handle_t handle, enum ddi_dma_ctlops request,
    off_t *offp, size_t *lenp, caddr_t *objp, uint_t flags)
{
	_NOTE(ARGUNUSED(dip, rdip, handle, request, offp, lenp, objp, flags))
	return (DDI_FAILURE);
}

void
ddivoid(void)
{}

int
nochpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **pollhdrp)
{
	_NOTE(ARGUNUSED(dev, events, anyyet, reventsp, pollhdrp))
	return (ENXIO);
}

cred_t *
ddi_get_cred(void)
{
	return (CRED());
}

clock_t
ddi_get_lbolt(void)
{
	return ((clock_t)lbolt_hybrid());
}

int64_t
ddi_get_lbolt64(void)
{
	return (lbolt_hybrid());
}

time_t
ddi_get_time(void)
{
	time_t	now;

	if ((now = gethrestime_sec()) == 0) {
		timestruc_t ts;
		mutex_enter(&tod_lock);
		ts = tod_get();
		mutex_exit(&tod_lock);
		return (ts.tv_sec);
	} else {
		return (now);
	}
}

pid_t
ddi_get_pid(void)
{
	return (ttoproc(curthread)->p_pid);
}

kt_did_t
ddi_get_kt_did(void)
{
	return (curthread->t_did);
}

/*
 * This function returns B_TRUE if the caller can reasonably expect that a call
 * to cv_wait_sig(9F), cv_timedwait_sig(9F), or qwait_sig(9F) could be awakened
 * by user-level signal.  If it returns B_FALSE, then the caller should use
 * other means to make certain that the wait will not hang "forever."
 *
 * It does not check the signal mask, nor for reception of any particular
 * signal.
 *
 * Currently, a thread can receive a signal if it's not a kernel thread and it
 * is not in the middle of exit(2) tear-down.  Threads that are in that
 * tear-down effectively convert cv_wait_sig to cv_wait, cv_timedwait_sig to
 * cv_timedwait, and qwait_sig to qwait.
 */
boolean_t
ddi_can_receive_sig(void)
{
	proc_t *pp;

	if (curthread->t_proc_flag & TP_LWPEXIT)
		return (B_FALSE);
	if ((pp = ttoproc(curthread)) == NULL)
		return (B_FALSE);
	return (pp->p_as != &kas);
}

/*
 * Swap bytes in 16-bit [half-]words
 */
void
swab(void *src, void *dst, size_t nbytes)
{
	uchar_t *pf = (uchar_t *)src;
	uchar_t *pt = (uchar_t *)dst;
	uchar_t tmp;
	int nshorts;

	nshorts = nbytes >> 1;

	while (--nshorts >= 0) {
		tmp = *pf++;
		*pt++ = *pf++;
		*pt++ = tmp;
	}
}

static void
ddi_append_minor_node(dev_info_t *ddip, struct ddi_minor_data *dmdp)
{
	int			circ;
	struct ddi_minor_data	*dp;

	ndi_devi_enter(ddip, &circ);
	if ((dp = DEVI(ddip)->devi_minor) == (struct ddi_minor_data *)NULL) {
		DEVI(ddip)->devi_minor = dmdp;
	} else {
		while (dp->next != (struct ddi_minor_data *)NULL)
			dp = dp->next;
		dp->next = dmdp;
	}
	ndi_devi_exit(ddip, circ);
}

/*
 * Part of the obsolete SunCluster DDI Hooks.
 * Keep for binary compatibility
 */
minor_t
ddi_getiminor(dev_t dev)
{
	return (getminor(dev));
}

static int
i_log_devfs_minor_create(dev_info_t *dip, char *minor_name)
{
	int se_flag;
	int kmem_flag;
	int se_err;
	char *pathname, *class_name;
	sysevent_t *ev = NULL;
	sysevent_id_t eid;
	sysevent_value_t se_val;
	sysevent_attr_list_t *ev_attr_list = NULL;

	/* determine interrupt context */
	se_flag = (servicing_interrupt()) ? SE_NOSLEEP : SE_SLEEP;
	kmem_flag = (se_flag == SE_SLEEP) ? KM_SLEEP : KM_NOSLEEP;

	i_ddi_di_cache_invalidate();

#ifdef DEBUG
	if ((se_flag == SE_NOSLEEP) && sunddi_debug) {
		cmn_err(CE_CONT, "ddi_create_minor_node: called from "
		    "interrupt level by driver %s",
		    ddi_driver_name(dip));
	}
#endif /* DEBUG */

	ev = sysevent_alloc(EC_DEVFS, ESC_DEVFS_MINOR_CREATE, EP_DDI, se_flag);
	if (ev == NULL) {
		goto fail;
	}

	pathname = kmem_alloc(MAXPATHLEN, kmem_flag);
	if (pathname == NULL) {
		sysevent_free(ev);
		goto fail;
	}

	(void) ddi_pathname(dip, pathname);
	ASSERT(strlen(pathname));
	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = pathname;
	if (sysevent_add_attr(&ev_attr_list, DEVFS_PATHNAME,
	    &se_val, se_flag) != 0) {
		kmem_free(pathname, MAXPATHLEN);
		sysevent_free(ev);
		goto fail;
	}
	kmem_free(pathname, MAXPATHLEN);

	/* add the device class attribute */
	if ((class_name = i_ddi_devi_class(dip)) != NULL) {
		se_val.value_type = SE_DATA_TYPE_STRING;
		se_val.value.sv_string = class_name;
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_DEVI_CLASS, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}
	}

	/*
	 * allow for NULL minor names
	 */
	if (minor_name != NULL) {
		se_val.value.sv_string = minor_name;
		if (sysevent_add_attr(&ev_attr_list, DEVFS_MINOR_NAME,
		    &se_val, se_flag) != 0) {
			sysevent_free_attr(ev_attr_list);
			sysevent_free(ev);
			goto fail;
		}
	}

	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		sysevent_free_attr(ev_attr_list);
		sysevent_free(ev);
		goto fail;
	}

	if ((se_err = log_sysevent(ev, se_flag, &eid)) != 0) {
		if (se_err == SE_NO_TRANSPORT) {
			cmn_err(CE_WARN, "/devices or /dev may not be current "
			    "for driver %s (%s). Run devfsadm -i %s",
			    ddi_driver_name(dip), "syseventd not responding",
			    ddi_driver_name(dip));
		} else {
			sysevent_free(ev);
			goto fail;
		}
	}

	sysevent_free(ev);
	return (DDI_SUCCESS);
fail:
	cmn_err(CE_WARN, "/devices or /dev may not be current "
	    "for driver %s. Run devfsadm -i %s",
	    ddi_driver_name(dip), ddi_driver_name(dip));
	return (DDI_SUCCESS);
}

/*
 * failing to remove a minor node is not of interest
 * therefore we do not generate an error message
 */
static int
i_log_devfs_minor_remove(dev_info_t *dip, char *minor_name)
{
	char *pathname, *class_name;
	sysevent_t *ev;
	sysevent_id_t eid;
	sysevent_value_t se_val;
	sysevent_attr_list_t *ev_attr_list = NULL;

	/*
	 * only log ddi_remove_minor_node() calls outside the scope
	 * of attach/detach reconfigurations and when the dip is
	 * still initialized.
	 */
	if (DEVI_IS_ATTACHING(dip) || DEVI_IS_DETACHING(dip) ||
	    (i_ddi_node_state(dip) < DS_INITIALIZED)) {
		return (DDI_SUCCESS);
	}

	i_ddi_di_cache_invalidate();

	ev = sysevent_alloc(EC_DEVFS, ESC_DEVFS_MINOR_REMOVE, EP_DDI, SE_SLEEP);
	if (ev == NULL) {
		return (DDI_SUCCESS);
	}

	pathname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	if (pathname == NULL) {
		sysevent_free(ev);
		return (DDI_SUCCESS);
	}

	(void) ddi_pathname(dip, pathname);
	ASSERT(strlen(pathname));
	se_val.value_type = SE_DATA_TYPE_STRING;
	se_val.value.sv_string = pathname;
	if (sysevent_add_attr(&ev_attr_list, DEVFS_PATHNAME,
	    &se_val, SE_SLEEP) != 0) {
		kmem_free(pathname, MAXPATHLEN);
		sysevent_free(ev);
		return (DDI_SUCCESS);
	}

	kmem_free(pathname, MAXPATHLEN);

	/*
	 * allow for NULL minor names
	 */
	if (minor_name != NULL) {
		se_val.value.sv_string = minor_name;
		if (sysevent_add_attr(&ev_attr_list, DEVFS_MINOR_NAME,
		    &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}
	}

	if ((class_name = i_ddi_devi_class(dip)) != NULL) {
		/* add the device class, driver name and instance attributes */

		se_val.value_type = SE_DATA_TYPE_STRING;
		se_val.value.sv_string = class_name;
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_DEVI_CLASS, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}

		se_val.value_type = SE_DATA_TYPE_STRING;
		se_val.value.sv_string = (char *)ddi_driver_name(dip);
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_DRIVER_NAME, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}

		se_val.value_type = SE_DATA_TYPE_INT32;
		se_val.value.sv_int32 = ddi_get_instance(dip);
		if (sysevent_add_attr(&ev_attr_list,
		    DEVFS_INSTANCE, &se_val, SE_SLEEP) != 0) {
			sysevent_free_attr(ev_attr_list);
			goto fail;
		}

	}

	if (sysevent_attach_attributes(ev, ev_attr_list) != 0) {
		sysevent_free_attr(ev_attr_list);
	} else {
		(void) log_sysevent(ev, SE_SLEEP, &eid);
	}
fail:
	sysevent_free(ev);
	return (DDI_SUCCESS);
}

/*
 * Derive the device class of the node.
 * Device class names aren't defined yet. Until this is done we use
 * devfs event subclass names as device class names.
 */
static int
derive_devi_class(dev_info_t *dip, char *node_type, int flag)
{
	int rv = DDI_SUCCESS;

	if (i_ddi_devi_class(dip) == NULL) {
		if (strncmp(node_type, DDI_NT_BLOCK,
		    sizeof (DDI_NT_BLOCK) - 1) == 0 &&
		    (node_type[sizeof (DDI_NT_BLOCK) - 1] == '\0' ||
		    node_type[sizeof (DDI_NT_BLOCK) - 1] == ':') &&
		    strcmp(node_type, DDI_NT_FD) != 0) {

			rv = i_ddi_set_devi_class(dip, ESC_DISK, flag);

		} else if (strncmp(node_type, DDI_NT_NET,
		    sizeof (DDI_NT_NET) - 1) == 0 &&
		    (node_type[sizeof (DDI_NT_NET) - 1] == '\0' ||
		    node_type[sizeof (DDI_NT_NET) - 1] == ':')) {

			rv = i_ddi_set_devi_class(dip, ESC_NETWORK, flag);

		} else if (strncmp(node_type, DDI_NT_PRINTER,
		    sizeof (DDI_NT_PRINTER) - 1) == 0 &&
		    (node_type[sizeof (DDI_NT_PRINTER) - 1] == '\0' ||
		    node_type[sizeof (DDI_NT_PRINTER) - 1] == ':')) {

			rv = i_ddi_set_devi_class(dip, ESC_PRINTER, flag);

		} else if (strncmp(node_type, DDI_PSEUDO,
		    sizeof (DDI_PSEUDO) -1) == 0 &&
		    (strncmp(ESC_LOFI, ddi_node_name(dip),
		    sizeof (ESC_LOFI) -1) == 0)) {
			rv = i_ddi_set_devi_class(dip, ESC_LOFI, flag);
		}
	}

	return (rv);
}

/*
 * Check compliance with PSARC 2003/375:
 *
 * The name must contain only characters a-z, A-Z, 0-9 or _ and it must not
 * exceed IFNAMSIZ (16) characters in length.
 */
static boolean_t
verify_name(char *name)
{
	size_t	len = strlen(name);
	char	*cp;

	if (len == 0 || len > IFNAMSIZ)
		return (B_FALSE);

	for (cp = name; *cp != '\0'; cp++) {
		if (!isalnum(*cp) && *cp != '_')
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * ddi_create_minor_common:	Create a  ddi_minor_data structure and
 *				attach it to the given devinfo node.
 */

int
ddi_create_minor_common(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag, ddi_minor_type mtype,
    const char *read_priv, const char *write_priv, mode_t priv_mode)
{
	struct ddi_minor_data *dmdp;
	major_t major;

	if (spec_type != S_IFCHR && spec_type != S_IFBLK)
		return (DDI_FAILURE);

	if (name == NULL)
		return (DDI_FAILURE);

	/*
	 * Log a message if the minor number the driver is creating
	 * is not expressible on the on-disk filesystem (currently
	 * this is limited to 18 bits both by UFS). The device can
	 * be opened via devfs, but not by device special files created
	 * via mknod().
	 */
	if (minor_num > L_MAXMIN32) {
		cmn_err(CE_WARN,
		    "%s%d:%s minor 0x%x too big for 32-bit applications",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    name, minor_num);
		return (DDI_FAILURE);
	}

	/* dip must be bound and attached */
	major = ddi_driver_major(dip);
	ASSERT(major != DDI_MAJOR_T_NONE);

	/*
	 * Default node_type to DDI_PSEUDO and issue notice in debug mode
	 */
	if (node_type == NULL) {
		node_type = DDI_PSEUDO;
		NDI_CONFIG_DEBUG((CE_NOTE, "!illegal node_type NULL for %s%d "
		    " minor node %s; default to DDI_PSEUDO",
		    ddi_driver_name(dip), ddi_get_instance(dip), name));
	}

	/*
	 * If the driver is a network driver, ensure that the name falls within
	 * the interface naming constraints specified by PSARC/2003/375.
	 */
	if (strcmp(node_type, DDI_NT_NET) == 0) {
		if (!verify_name(name))
			return (DDI_FAILURE);

		if (mtype == DDM_MINOR) {
			struct devnames *dnp = &devnamesp[major];

			/* Mark driver as a network driver */
			LOCK_DEV_OPS(&dnp->dn_lock);
			dnp->dn_flags |= DN_NETWORK_DRIVER;

			/*
			 * If this minor node is created during the device
			 * attachment, this is a physical network device.
			 * Mark the driver as a physical network driver.
			 */
			if (DEVI_IS_ATTACHING(dip))
				dnp->dn_flags |= DN_NETWORK_PHYSDRIVER;
			UNLOCK_DEV_OPS(&dnp->dn_lock);
		}
	}

	if (mtype == DDM_MINOR) {
		if (derive_devi_class(dip,  node_type, KM_NOSLEEP) !=
		    DDI_SUCCESS)
			return (DDI_FAILURE);
	}

	/*
	 * Take care of minor number information for the node.
	 */

	if ((dmdp = kmem_zalloc(sizeof (struct ddi_minor_data),
	    KM_NOSLEEP)) == NULL) {
		return (DDI_FAILURE);
	}
	if ((dmdp->ddm_name = i_ddi_strdup(name, KM_NOSLEEP)) == NULL) {
		kmem_free(dmdp, sizeof (struct ddi_minor_data));
		return (DDI_FAILURE);
	}
	dmdp->dip = dip;
	dmdp->ddm_dev = makedevice(major, minor_num);
	dmdp->ddm_spec_type = spec_type;
	dmdp->ddm_node_type = node_type;
	dmdp->type = mtype;
	if (flag & CLONE_DEV) {
		dmdp->type = DDM_ALIAS;
		dmdp->ddm_dev = makedevice(ddi_driver_major(clone_dip), major);
	}
	if (flag & PRIVONLY_DEV) {
		dmdp->ddm_flags |= DM_NO_FSPERM;
	}
	if (read_priv || write_priv) {
		dmdp->ddm_node_priv =
		    devpolicy_priv_by_name(read_priv, write_priv);
	}
	dmdp->ddm_priv_mode = priv_mode;

	ddi_append_minor_node(dip, dmdp);

	/*
	 * only log ddi_create_minor_node() calls which occur
	 * outside the scope of attach(9e)/detach(9e) reconfigurations
	 */
	if (!(DEVI_IS_ATTACHING(dip) || DEVI_IS_DETACHING(dip)) &&
	    mtype != DDM_INTERNAL_PATH) {
		(void) i_log_devfs_minor_create(dip, name);
	}

	/*
	 * Check if any dacf rules match the creation of this minor node
	 */
	dacfc_match_create_minor(name, node_type, dip, dmdp, flag);
	return (DDI_SUCCESS);
}

int
ddi_create_minor_node(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag)
{
	return (ddi_create_minor_common(dip, name, spec_type, minor_num,
	    node_type, flag, DDM_MINOR, NULL, NULL, 0));
}

int
ddi_create_priv_minor_node(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag,
    const char *rdpriv, const char *wrpriv, mode_t priv_mode)
{
	return (ddi_create_minor_common(dip, name, spec_type, minor_num,
	    node_type, flag, DDM_MINOR, rdpriv, wrpriv, priv_mode));
}

int
ddi_create_default_minor_node(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag)
{
	return (ddi_create_minor_common(dip, name, spec_type, minor_num,
	    node_type, flag, DDM_DEFAULT, NULL, NULL, 0));
}

/*
 * Internal (non-ddi) routine for drivers to export names known
 * to the kernel (especially ddi_pathname_to_dev_t and friends)
 * but not exported externally to /dev
 */
int
ddi_create_internal_pathname(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num)
{
	return (ddi_create_minor_common(dip, name, spec_type, minor_num,
	    "internal", 0, DDM_INTERNAL_PATH, NULL, NULL, 0));
}

void
ddi_remove_minor_node(dev_info_t *dip, char *name)
{
	int			circ;
	struct ddi_minor_data	*dmdp, *dmdp1;
	struct ddi_minor_data	**dmdp_prev;

	ndi_devi_enter(dip, &circ);
	dmdp_prev = &DEVI(dip)->devi_minor;
	dmdp = DEVI(dip)->devi_minor;
	while (dmdp != NULL) {
		dmdp1 = dmdp->next;
		if ((name == NULL || (dmdp->ddm_name != NULL &&
		    strcmp(name, dmdp->ddm_name) == 0))) {
			if (dmdp->ddm_name != NULL) {
				if (dmdp->type != DDM_INTERNAL_PATH)
					(void) i_log_devfs_minor_remove(dip,
					    dmdp->ddm_name);
				kmem_free(dmdp->ddm_name,
				    strlen(dmdp->ddm_name) + 1);
			}
			/*
			 * Release device privilege, if any.
			 * Release dacf client data associated with this minor
			 * node by storing NULL.
			 */
			if (dmdp->ddm_node_priv)
				dpfree(dmdp->ddm_node_priv);
			dacf_store_info((dacf_infohdl_t)dmdp, NULL);
			kmem_free(dmdp, sizeof (struct ddi_minor_data));
			*dmdp_prev = dmdp1;
			/*
			 * OK, we found it, so get out now -- if we drive on,
			 * we will strcmp against garbage.  See 1139209.
			 */
			if (name != NULL)
				break;
		} else {
			dmdp_prev = &dmdp->next;
		}
		dmdp = dmdp1;
	}
	ndi_devi_exit(dip, circ);
}


int
ddi_in_panic()
{
	return (panicstr != NULL);
}


/*
 * Find first bit set in a mask (returned counting from 1 up)
 */

int
ddi_ffs(long mask)
{
	return (ffs(mask));
}

/*
 * Find last bit set. Take mask and clear
 * all but the most significant bit, and
 * then let ffs do the rest of the work.
 *
 * Algorithm courtesy of Steve Chessin.
 */

int
ddi_fls(long mask)
{
	while (mask) {
		long nx;

		if ((nx = (mask & (mask - 1))) == 0)
			break;
		mask = nx;
	}
	return (ffs(mask));
}

/*
 * The ddi_soft_state_* routines comprise generic storage management utilities
 * for driver soft state structures (in "the old days," this was done with
 * statically sized array - big systems and dynamic loading and unloading
 * make heap allocation more attractive).
 */

/*
 * Allocate a set of pointers to 'n_items' objects of size 'size'
 * bytes.  Each pointer is initialized to nil.
 *
 * The 'size' and 'n_items' values are stashed in the opaque
 * handle returned to the caller.
 *
 * This implementation interprets 'set of pointers' to mean 'array
 * of pointers' but note that nothing in the interface definition
 * precludes an implementation that uses, for example, a linked list.
 * However there should be a small efficiency gain from using an array
 * at lookup time.
 *
 * NOTE	As an optimization, we make our growable array allocations in
 *	powers of two (bytes), since that's how much kmem_alloc (currently)
 *	gives us anyway.  It should save us some free/realloc's ..
 *
 *	As a further optimization, we make the growable array start out
 *	with MIN_N_ITEMS in it.
 */

#define	MIN_N_ITEMS	8	/* 8 void *'s == 32 bytes */

int
ddi_soft_state_init(void **state_p, size_t size, size_t n_items)
{
	i_ddi_soft_state	*ss;

	if (state_p == NULL || size == 0)
		return (EINVAL);

	ss = kmem_zalloc(sizeof (*ss), KM_SLEEP);
	mutex_init(&ss->lock, NULL, MUTEX_DRIVER, NULL);
	ss->size = size;

	if (n_items < MIN_N_ITEMS)
		ss->n_items = MIN_N_ITEMS;
	else {
		int bitlog;

		if ((bitlog = ddi_fls(n_items)) == ddi_ffs(n_items))
			bitlog--;
		ss->n_items = 1 << bitlog;
	}

	ASSERT(ss->n_items >= n_items);

	ss->array = kmem_zalloc(ss->n_items * sizeof (void *), KM_SLEEP);

	*state_p = ss;
	return (0);
}

/*
 * Allocate a state structure of size 'size' to be associated
 * with item 'item'.
 *
 * In this implementation, the array is extended to
 * allow the requested offset, if needed.
 */
int
ddi_soft_state_zalloc(void *state, int item)
{
	i_ddi_soft_state	*ss = (i_ddi_soft_state *)state;
	void			**array;
	void			*new_element;

	if ((state == NULL) || (item < 0))
		return (DDI_FAILURE);

	mutex_enter(&ss->lock);
	if (ss->size == 0) {
		mutex_exit(&ss->lock);
		cmn_err(CE_WARN, "ddi_soft_state_zalloc: bad handle: %s",
		    mod_containing_pc(caller()));
		return (DDI_FAILURE);
	}

	array = ss->array;	/* NULL if ss->n_items == 0 */
	ASSERT(ss->n_items != 0 && array != NULL);

	/*
	 * refuse to tread on an existing element
	 */
	if (item < ss->n_items && array[item] != NULL) {
		mutex_exit(&ss->lock);
		return (DDI_FAILURE);
	}

	/*
	 * Allocate a new element to plug in
	 */
	new_element = kmem_zalloc(ss->size, KM_SLEEP);

	/*
	 * Check if the array is big enough, if not, grow it.
	 */
	if (item >= ss->n_items) {
		void			**new_array;
		size_t			new_n_items;
		struct i_ddi_soft_state	*dirty;

		/*
		 * Allocate a new array of the right length, copy
		 * all the old pointers to the new array, then
		 * if it exists at all, put the old array on the
		 * dirty list.
		 *
		 * Note that we can't kmem_free() the old array.
		 *
		 * Why -- well the 'get' operation is 'mutex-free', so we
		 * can't easily catch a suspended thread that is just about
		 * to dereference the array we just grew out of.  So we
		 * cons up a header and put it on a list of 'dirty'
		 * pointer arrays.  (Dirty in the sense that there may
		 * be suspended threads somewhere that are in the middle
		 * of referencing them).  Fortunately, we -can- garbage
		 * collect it all at ddi_soft_state_fini time.
		 */
		new_n_items = ss->n_items;
		while (new_n_items < (1 + item))
			new_n_items <<= 1;	/* double array size .. */

		ASSERT(new_n_items >= (1 + item));	/* sanity check! */

		new_array = kmem_zalloc(new_n_items * sizeof (void *),
		    KM_SLEEP);
		/*
		 * Copy the pointers into the new array
		 */
		bcopy(array, new_array, ss->n_items * sizeof (void *));

		/*
		 * Save the old array on the dirty list
		 */
		dirty = kmem_zalloc(sizeof (*dirty), KM_SLEEP);
		dirty->array = ss->array;
		dirty->n_items = ss->n_items;
		dirty->next = ss->next;
		ss->next = dirty;

		ss->array = (array = new_array);
		ss->n_items = new_n_items;
	}

	ASSERT(array != NULL && item < ss->n_items && array[item] == NULL);

	array[item] = new_element;

	mutex_exit(&ss->lock);
	return (DDI_SUCCESS);
}

/*
 * Fetch a pointer to the allocated soft state structure.
 *
 * This is designed to be cheap.
 *
 * There's an argument that there should be more checking for
 * nil pointers and out of bounds on the array.. but we do a lot
 * of that in the alloc/free routines.
 *
 * An array has the convenience that we don't need to lock read-access
 * to it c.f. a linked list.  However our "expanding array" strategy
 * means that we should hold a readers lock on the i_ddi_soft_state
 * structure.
 *
 * However, from a performance viewpoint, we need to do it without
 * any locks at all -- this also makes it a leaf routine.  The algorithm
 * is 'lock-free' because we only discard the pointer arrays at
 * ddi_soft_state_fini() time.
 */
void *
ddi_get_soft_state(void *state, int item)
{
	i_ddi_soft_state	*ss = (i_ddi_soft_state *)state;

	ASSERT((ss != NULL) && (item >= 0));

	if (item < ss->n_items && ss->array != NULL)
		return (ss->array[item]);
	return (NULL);
}

/*
 * Free the state structure corresponding to 'item.'   Freeing an
 * element that has either gone or was never allocated is not
 * considered an error.  Note that we free the state structure, but
 * we don't shrink our pointer array, or discard 'dirty' arrays,
 * since even a few pointers don't really waste too much memory.
 *
 * Passing an item number that is out of bounds, or a null pointer will
 * provoke an error message.
 */
void
ddi_soft_state_free(void *state, int item)
{
	i_ddi_soft_state	*ss = (i_ddi_soft_state *)state;
	void			**array;
	void			*element;
	static char		msg[] = "ddi_soft_state_free:";

	if (ss == NULL) {
		cmn_err(CE_WARN, "%s null handle: %s",
		    msg, mod_containing_pc(caller()));
		return;
	}

	element = NULL;

	mutex_enter(&ss->lock);

	if ((array = ss->array) == NULL || ss->size == 0) {
		cmn_err(CE_WARN, "%s bad handle: %s",
		    msg, mod_containing_pc(caller()));
	} else if (item < 0 || item >= ss->n_items) {
		cmn_err(CE_WARN, "%s item %d not in range [0..%lu]: %s",
		    msg, item, ss->n_items - 1, mod_containing_pc(caller()));
	} else if (array[item] != NULL) {
		element = array[item];
		array[item] = NULL;
	}

	mutex_exit(&ss->lock);

	if (element)
		kmem_free(element, ss->size);
}

/*
 * Free the entire set of pointers, and any
 * soft state structures contained therein.
 *
 * Note that we don't grab the ss->lock mutex, even though
 * we're inspecting the various fields of the data structure.
 *
 * There is an implicit assumption that this routine will
 * never run concurrently with any of the above on this
 * particular state structure i.e. by the time the driver
 * calls this routine, there should be no other threads
 * running in the driver.
 */
void
ddi_soft_state_fini(void **state_p)
{
	i_ddi_soft_state	*ss, *dirty;
	int			item;
	static char		msg[] = "ddi_soft_state_fini:";

	if (state_p == NULL ||
	    (ss = (i_ddi_soft_state *)(*state_p)) == NULL) {
		cmn_err(CE_WARN, "%s null handle: %s",
		    msg, mod_containing_pc(caller()));
		return;
	}

	if (ss->size == 0) {
		cmn_err(CE_WARN, "%s bad handle: %s",
		    msg, mod_containing_pc(caller()));
		return;
	}

	if (ss->n_items > 0) {
		for (item = 0; item < ss->n_items; item++)
			ddi_soft_state_free(ss, item);
		kmem_free(ss->array, ss->n_items * sizeof (void *));
	}

	/*
	 * Now delete any dirty arrays from previous 'grow' operations
	 */
	for (dirty = ss->next; dirty; dirty = ss->next) {
		ss->next = dirty->next;
		kmem_free(dirty->array, dirty->n_items * sizeof (void *));
		kmem_free(dirty, sizeof (*dirty));
	}

	mutex_destroy(&ss->lock);
	kmem_free(ss, sizeof (*ss));

	*state_p = NULL;
}

#define	SS_N_ITEMS_PER_HASH	16
#define	SS_MIN_HASH_SZ		16
#define	SS_MAX_HASH_SZ		4096

int
ddi_soft_state_bystr_init(ddi_soft_state_bystr **state_p, size_t size,
    int n_items)
{
	i_ddi_soft_state_bystr	*sss;
	int			hash_sz;

	ASSERT(state_p && size && n_items);
	if ((state_p == NULL) || (size == 0) || (n_items == 0))
		return (EINVAL);

	/* current implementation is based on hash, convert n_items to hash */
	hash_sz = n_items / SS_N_ITEMS_PER_HASH;
	if (hash_sz < SS_MIN_HASH_SZ)
		hash_sz = SS_MIN_HASH_SZ;
	else if (hash_sz > SS_MAX_HASH_SZ)
		hash_sz = SS_MAX_HASH_SZ;

	/* allocate soft_state pool */
	sss = kmem_zalloc(sizeof (*sss), KM_SLEEP);
	sss->ss_size = size;
	sss->ss_mod_hash = mod_hash_create_strhash("soft_state_bystr",
	    hash_sz, mod_hash_null_valdtor);
	*state_p = (ddi_soft_state_bystr *)sss;
	return (0);
}

int
ddi_soft_state_bystr_zalloc(ddi_soft_state_bystr *state, const char *str)
{
	i_ddi_soft_state_bystr	*sss = (i_ddi_soft_state_bystr *)state;
	void			*sso;
	char			*dup_str;

	ASSERT(sss && str && sss->ss_mod_hash);
	if ((sss == NULL) || (str == NULL) || (sss->ss_mod_hash == NULL))
		return (DDI_FAILURE);
	sso = kmem_zalloc(sss->ss_size, KM_SLEEP);
	dup_str = i_ddi_strdup((char *)str, KM_SLEEP);
	if (mod_hash_insert(sss->ss_mod_hash,
	    (mod_hash_key_t)dup_str, (mod_hash_val_t)sso) == 0)
		return (DDI_SUCCESS);

	/*
	 * The only error from an strhash insert is caused by a duplicate key.
	 * We refuse to tread on an existing elements, so free and fail.
	 */
	kmem_free(dup_str, strlen(dup_str) + 1);
	kmem_free(sso, sss->ss_size);
	return (DDI_FAILURE);
}

void *
ddi_soft_state_bystr_get(ddi_soft_state_bystr *state, const char *str)
{
	i_ddi_soft_state_bystr	*sss = (i_ddi_soft_state_bystr *)state;
	void			*sso;

	ASSERT(sss && str && sss->ss_mod_hash);
	if ((sss == NULL) || (str == NULL) || (sss->ss_mod_hash == NULL))
		return (NULL);

	if (mod_hash_find(sss->ss_mod_hash,
	    (mod_hash_key_t)str, (mod_hash_val_t *)&sso) == 0)
		return (sso);
	return (NULL);
}

void
ddi_soft_state_bystr_free(ddi_soft_state_bystr *state, const char *str)
{
	i_ddi_soft_state_bystr	*sss = (i_ddi_soft_state_bystr *)state;
	void			*sso;

	ASSERT(sss && str && sss->ss_mod_hash);
	if ((sss == NULL) || (str == NULL) || (sss->ss_mod_hash == NULL))
		return;

	(void) mod_hash_remove(sss->ss_mod_hash,
	    (mod_hash_key_t)str, (mod_hash_val_t *)&sso);
	kmem_free(sso, sss->ss_size);
}

void
ddi_soft_state_bystr_fini(ddi_soft_state_bystr **state_p)
{
	i_ddi_soft_state_bystr	*sss;

	ASSERT(state_p);
	if (state_p == NULL)
		return;

	sss = (i_ddi_soft_state_bystr *)(*state_p);
	if (sss == NULL)
		return;

	ASSERT(sss->ss_mod_hash);
	if (sss->ss_mod_hash) {
		mod_hash_destroy_strhash(sss->ss_mod_hash);
		sss->ss_mod_hash = NULL;
	}

	kmem_free(sss, sizeof (*sss));
	*state_p = NULL;
}

/*
 * The ddi_strid_* routines provide string-to-index management utilities.
 */
/* allocate and initialize an strid set */
int
ddi_strid_init(ddi_strid **strid_p, int n_items)
{
	i_ddi_strid	*ss;
	int		hash_sz;

	if (strid_p == NULL)
		return (DDI_FAILURE);

	/* current implementation is based on hash, convert n_items to hash */
	hash_sz = n_items / SS_N_ITEMS_PER_HASH;
	if (hash_sz < SS_MIN_HASH_SZ)
		hash_sz = SS_MIN_HASH_SZ;
	else if (hash_sz > SS_MAX_HASH_SZ)
		hash_sz = SS_MAX_HASH_SZ;

	ss = kmem_alloc(sizeof (*ss), KM_SLEEP);
	ss->strid_chunksz = n_items;
	ss->strid_spacesz = n_items;
	ss->strid_space = id_space_create("strid", 1, n_items);
	ss->strid_bystr = mod_hash_create_strhash("strid_bystr", hash_sz,
	    mod_hash_null_valdtor);
	ss->strid_byid = mod_hash_create_idhash("strid_byid", hash_sz,
	    mod_hash_null_valdtor);
	*strid_p = (ddi_strid *)ss;
	return (DDI_SUCCESS);
}

/* allocate an id mapping within the specified set for str, return id */
static id_t
i_ddi_strid_alloc(ddi_strid *strid, char *str)
{
	i_ddi_strid	*ss = (i_ddi_strid *)strid;
	id_t		id;
	char		*s;

	ASSERT(ss && str);
	if ((ss == NULL) || (str == NULL))
		return (0);

	/*
	 * Allocate an id using VM_FIRSTFIT in order to keep allocated id
	 * range as compressed as possible.  This is important to minimize
	 * the amount of space used when the id is used as a ddi_soft_state
	 * index by the caller.
	 *
	 * If the id list is exhausted, increase the size of the list
	 * by the chuck size specified in ddi_strid_init and reattempt
	 * the allocation
	 */
	if ((id = id_allocff_nosleep(ss->strid_space)) == (id_t)-1) {
		id_space_extend(ss->strid_space, ss->strid_spacesz,
		    ss->strid_spacesz + ss->strid_chunksz);
		ss->strid_spacesz += ss->strid_chunksz;
		if ((id = id_allocff_nosleep(ss->strid_space)) == (id_t)-1)
			return (0);
	}

	/*
	 * NOTE: since we create and destroy in unison we can save space by
	 * using bystr key as the byid value.  This means destroy must occur
	 * in (byid, bystr) order.
	 */
	s = i_ddi_strdup(str, KM_SLEEP);
	if (mod_hash_insert(ss->strid_bystr, (mod_hash_key_t)s,
	    (mod_hash_val_t)(intptr_t)id) != 0) {
		ddi_strid_free(strid, id);
		return (0);
	}
	if (mod_hash_insert(ss->strid_byid, (mod_hash_key_t)(intptr_t)id,
	    (mod_hash_val_t)s) != 0) {
		ddi_strid_free(strid, id);
		return (0);
	}

	/* NOTE: s if freed on mod_hash_destroy by mod_hash_strval_dtor */
	return (id);
}

/* allocate an id mapping within the specified set for str, return id */
id_t
ddi_strid_alloc(ddi_strid *strid, char *str)
{
	return (i_ddi_strid_alloc(strid, str));
}

/* return the id within the specified strid given the str */
id_t
ddi_strid_str2id(ddi_strid *strid, char *str)
{
	i_ddi_strid	*ss = (i_ddi_strid *)strid;
	id_t		id = 0;
	mod_hash_val_t	hv;

	ASSERT(ss && str);
	if (ss && str && (mod_hash_find(ss->strid_bystr,
	    (mod_hash_key_t)str, &hv) == 0))
		id = (int)(intptr_t)hv;
	return (id);
}

/* return str within the specified strid given the id */
char *
ddi_strid_id2str(ddi_strid *strid, id_t id)
{
	i_ddi_strid	*ss = (i_ddi_strid *)strid;
	char		*str = NULL;
	mod_hash_val_t	hv;

	ASSERT(ss && id > 0);
	if (ss && (id > 0) && (mod_hash_find(ss->strid_byid,
	    (mod_hash_key_t)(uintptr_t)id, &hv) == 0))
		str = (char *)hv;
	return (str);
}

/* free the id mapping within the specified strid */
void
ddi_strid_free(ddi_strid *strid, id_t id)
{
	i_ddi_strid	*ss = (i_ddi_strid *)strid;
	char		*str;

	ASSERT(ss && id > 0);
	if ((ss == NULL) || (id <= 0))
		return;

	/* bystr key is byid value: destroy order must be (byid, bystr) */
	str = ddi_strid_id2str(strid, id);
	(void) mod_hash_destroy(ss->strid_byid, (mod_hash_key_t)(uintptr_t)id);
	id_free(ss->strid_space, id);

	if (str)
		(void) mod_hash_destroy(ss->strid_bystr, (mod_hash_key_t)str);
}

/* destroy the strid set */
void
ddi_strid_fini(ddi_strid **strid_p)
{
	i_ddi_strid	*ss;

	ASSERT(strid_p);
	if (strid_p == NULL)
		return;

	ss = (i_ddi_strid *)(*strid_p);
	if (ss == NULL)
		return;

	/* bystr key is byid value: destroy order must be (byid, bystr) */
	if (ss->strid_byid)
		mod_hash_destroy_hash(ss->strid_byid);
	if (ss->strid_byid)
		mod_hash_destroy_hash(ss->strid_bystr);
	if (ss->strid_space)
		id_space_destroy(ss->strid_space);
	kmem_free(ss, sizeof (*ss));
	*strid_p = NULL;
}

/*
 * This sets the devi_addr entry in the dev_info structure 'dip' to 'name'.
 * Storage is double buffered to prevent updates during devi_addr use -
 * double buffering is adaquate for reliable ddi_deviname() consumption.
 * The double buffer is not freed until dev_info structure destruction
 * (by i_ddi_free_node).
 */
void
ddi_set_name_addr(dev_info_t *dip, char *name)
{
	char	*buf = DEVI(dip)->devi_addr_buf;
	char	*newaddr;

	if (buf == NULL) {
		buf = kmem_zalloc(2 * MAXNAMELEN, KM_SLEEP);
		DEVI(dip)->devi_addr_buf = buf;
	}

	if (name) {
		ASSERT(strlen(name) < MAXNAMELEN);
		newaddr = (DEVI(dip)->devi_addr == buf) ?
		    (buf + MAXNAMELEN) : buf;
		(void) strlcpy(newaddr, name, MAXNAMELEN);
	} else
		newaddr = NULL;

	DEVI(dip)->devi_addr = newaddr;
}

char *
ddi_get_name_addr(dev_info_t *dip)
{
	return (DEVI(dip)->devi_addr);
}

void
ddi_set_parent_data(dev_info_t *dip, void *pd)
{
	DEVI(dip)->devi_parent_data = pd;
}

void *
ddi_get_parent_data(dev_info_t *dip)
{
	return (DEVI(dip)->devi_parent_data);
}

/*
 * ddi_name_to_major: returns the major number of a named module,
 * derived from the current driver alias binding.
 *
 * Caveat: drivers should avoid the use of this function, in particular
 * together with ddi_get_name/ddi_binding name, as per
 *	major = ddi_name_to_major(ddi_get_name(devi));
 * ddi_name_to_major() relies on the state of the device/alias binding,
 * which can and does change dynamically as aliases are administered
 * over time.  An attached device instance cannot rely on the major
 * number returned by ddi_name_to_major() to match its own major number.
 *
 * For driver use, ddi_driver_major() reliably returns the major number
 * for the module to which the device was bound at attach time over
 * the life of the instance.
 *	major = ddi_driver_major(dev_info_t *)
 */
major_t
ddi_name_to_major(char *name)
{
	return (mod_name_to_major(name));
}

/*
 * ddi_major_to_name: Returns the module name bound to a major number.
 */
char *
ddi_major_to_name(major_t major)
{
	return (mod_major_to_name(major));
}

/*
 * Return the name of the devinfo node pointed at by 'dip' in the buffer
 * pointed at by 'name.'  A devinfo node is named as a result of calling
 * ddi_initchild().
 *
 * Note: the driver must be held before calling this function!
 */
char *
ddi_deviname(dev_info_t *dip, char *name)
{
	char *addrname;
	char none = '\0';

	if (dip == ddi_root_node()) {
		*name = '\0';
		return (name);
	}

	if (i_ddi_node_state(dip) < DS_BOUND) {
		addrname = &none;
	} else {
		/*
		 * Use ddi_get_name_addr() without checking state so we get
		 * a unit-address if we are called after ddi_set_name_addr()
		 * by nexus DDI_CTL_INITCHILD code, but before completing
		 * node promotion to DS_INITIALIZED.  We currently have
		 * two situations where we are called in this state:
		 *   o  For framework processing of a path-oriented alias.
		 *   o  If a SCSA nexus driver calls ddi_devid_register()
		 *	from it's tran_tgt_init(9E) implementation.
		 */
		addrname = ddi_get_name_addr(dip);
		if (addrname == NULL)
			addrname = &none;
	}

	if (*addrname == '\0') {
		(void) sprintf(name, "/%s", ddi_node_name(dip));
	} else {
		(void) sprintf(name, "/%s@%s", ddi_node_name(dip), addrname);
	}

	return (name);
}

/*
 * Spits out the name of device node, typically name@addr, for a given node,
 * using the driver name, not the nodename.
 *
 * Used by match_parent. Not to be used elsewhere.
 */
char *
i_ddi_parname(dev_info_t *dip, char *name)
{
	char *addrname;

	if (dip == ddi_root_node()) {
		*name = '\0';
		return (name);
	}

	ASSERT(i_ddi_node_state(dip) >= DS_INITIALIZED);

	if (*(addrname = ddi_get_name_addr(dip)) == '\0')
		(void) sprintf(name, "%s", ddi_binding_name(dip));
	else
		(void) sprintf(name, "%s@%s", ddi_binding_name(dip), addrname);
	return (name);
}

static char *
pathname_work(dev_info_t *dip, char *path)
{
	char *bp;

	if (dip == ddi_root_node()) {
		*path = '\0';
		return (path);
	}
	(void) pathname_work(ddi_get_parent(dip), path);
	bp = path + strlen(path);
	(void) ddi_deviname(dip, bp);
	return (path);
}

char *
ddi_pathname(dev_info_t *dip, char *path)
{
	return (pathname_work(dip, path));
}

char *
ddi_pathname_minor(struct ddi_minor_data *dmdp, char *path)
{
	if (dmdp->dip == NULL)
		*path = '\0';
	else {
		(void) ddi_pathname(dmdp->dip, path);
		if (dmdp->ddm_name) {
			(void) strcat(path, ":");
			(void) strcat(path, dmdp->ddm_name);
		}
	}
	return (path);
}

static char *
pathname_work_obp(dev_info_t *dip, char *path)
{
	char *bp;
	char *obp_path;

	/*
	 * look up the "obp-path" property, return the path if it exists
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "obp-path", &obp_path) == DDI_PROP_SUCCESS) {
		(void) strcpy(path, obp_path);
		ddi_prop_free(obp_path);
		return (path);
	}

	/*
	 * stop at root, no obp path
	 */
	if (dip == ddi_root_node()) {
		return (NULL);
	}

	obp_path = pathname_work_obp(ddi_get_parent(dip), path);
	if (obp_path == NULL)
		return (NULL);

	/*
	 * append our component to parent's obp path
	 */
	bp = path + strlen(path);
	if (*(bp - 1) != '/')
		(void) strcat(bp++, "/");
	(void) ddi_deviname(dip, bp);
	return (path);
}

/*
 * return the 'obp-path' based path for the given node, or NULL if the node
 * does not have a different obp path. NOTE: Unlike ddi_pathname, this
 * function can't be called from interrupt context (since we need to
 * lookup a string property).
 */
char *
ddi_pathname_obp(dev_info_t *dip, char *path)
{
	ASSERT(!servicing_interrupt());
	if (dip == NULL || path == NULL)
		return (NULL);

	/* split work into a separate function to aid debugging */
	return (pathname_work_obp(dip, path));
}

int
ddi_pathname_obp_set(dev_info_t *dip, char *component)
{
	dev_info_t *pdip;
	char *obp_path = NULL;
	int rc = DDI_FAILURE;

	if (dip == NULL)
		return (DDI_FAILURE);

	obp_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);

	pdip = ddi_get_parent(dip);

	if (ddi_pathname_obp(pdip, obp_path) == NULL) {
		(void) ddi_pathname(pdip, obp_path);
	}

	if (component) {
		(void) strncat(obp_path, "/", MAXPATHLEN);
		(void) strncat(obp_path, component, MAXPATHLEN);
	}
	rc = ndi_prop_update_string(DDI_DEV_T_NONE, dip, "obp-path",
	    obp_path);

	if (obp_path)
		kmem_free(obp_path, MAXPATHLEN);

	return (rc);
}

/*
 * Given a dev_t, return the pathname of the corresponding device in the
 * buffer pointed at by "path."  The buffer is assumed to be large enough
 * to hold the pathname of the device (MAXPATHLEN).
 *
 * The pathname of a device is the pathname of the devinfo node to which
 * the device "belongs," concatenated with the character ':' and the name
 * of the minor node corresponding to the dev_t.  If spec_type is 0 then
 * just the pathname of the devinfo node is returned without driving attach
 * of that node.  For a non-zero spec_type, an attach is performed and a
 * search of the minor list occurs.
 *
 * It is possible that the path associated with the dev_t is not
 * currently available in the devinfo tree.  In order to have a
 * dev_t, a device must have been discovered before, which means
 * that the path is always in the instance tree.  The one exception
 * to this is if the dev_t is associated with a pseudo driver, in
 * which case the device must exist on the pseudo branch of the
 * devinfo tree as a result of parsing .conf files.
 */
int
ddi_dev_pathname(dev_t devt, int spec_type, char *path)
{
	int		circ;
	major_t		major = getmajor(devt);
	int		instance;
	dev_info_t	*dip;
	char		*minorname;
	char		*drvname;

	if (major >= devcnt)
		goto fail;
	if (major == clone_major) {
		/* clone has no minor nodes, manufacture the path here */
		if ((drvname = ddi_major_to_name(getminor(devt))) == NULL)
			goto fail;

		(void) snprintf(path, MAXPATHLEN, "%s:%s", CLONE_PATH, drvname);
		return (DDI_SUCCESS);
	}

	/* extract instance from devt (getinfo(9E) DDI_INFO_DEVT2INSTANCE). */
	if ((instance = dev_to_instance(devt)) == -1)
		goto fail;

	/* reconstruct the path given the major/instance */
	if (e_ddi_majorinstance_to_path(major, instance, path) != DDI_SUCCESS)
		goto fail;

	/* if spec_type given we must drive attach and search minor nodes */
	if ((spec_type == S_IFCHR) || (spec_type == S_IFBLK)) {
		/* attach the path so we can search minors */
		if ((dip = e_ddi_hold_devi_by_path(path, 0)) == NULL)
			goto fail;

		/* Add minorname to path. */
		ndi_devi_enter(dip, &circ);
		minorname = i_ddi_devtspectype_to_minorname(dip,
		    devt, spec_type);
		if (minorname) {
			(void) strcat(path, ":");
			(void) strcat(path, minorname);
		}
		ndi_devi_exit(dip, circ);
		ddi_release_devi(dip);
		if (minorname == NULL)
			goto fail;
	}
	ASSERT(strlen(path) < MAXPATHLEN);
	return (DDI_SUCCESS);

fail:	*path = 0;
	return (DDI_FAILURE);
}

/*
 * Given a major number and an instance, return the path.
 * This interface does NOT drive attach.
 */
int
e_ddi_majorinstance_to_path(major_t major, int instance, char *path)
{
	struct devnames *dnp;
	dev_info_t	*dip;

	if ((major >= devcnt) || (instance == -1)) {
		*path = 0;
		return (DDI_FAILURE);
	}

	/* look for the major/instance in the instance tree */
	if (e_ddi_instance_majorinstance_to_path(major, instance,
	    path) == DDI_SUCCESS) {
		ASSERT(strlen(path) < MAXPATHLEN);
		return (DDI_SUCCESS);
	}

	/*
	 * Not in instance tree, find the instance on the per driver list and
	 * construct path to instance via ddi_pathname(). This is how paths
	 * down the 'pseudo' branch are constructed.
	 */
	dnp = &(devnamesp[major]);
	LOCK_DEV_OPS(&(dnp->dn_lock));
	for (dip = dnp->dn_head; dip;
	    dip = (dev_info_t *)DEVI(dip)->devi_next) {
		/* Skip if instance does not match. */
		if (DEVI(dip)->devi_instance != instance)
			continue;

		/*
		 * An ndi_hold_devi() does not prevent DS_INITIALIZED->DS_BOUND
		 * node demotion, so it is not an effective way of ensuring
		 * that the ddi_pathname result has a unit-address.  Instead,
		 * we reverify the node state after calling ddi_pathname().
		 */
		if (i_ddi_node_state(dip) >= DS_INITIALIZED) {
			(void) ddi_pathname(dip, path);
			if (i_ddi_node_state(dip) < DS_INITIALIZED)
				continue;
			UNLOCK_DEV_OPS(&(dnp->dn_lock));
			ASSERT(strlen(path) < MAXPATHLEN);
			return (DDI_SUCCESS);
		}
	}
	UNLOCK_DEV_OPS(&(dnp->dn_lock));

	/* can't reconstruct the path */
	*path = 0;
	return (DDI_FAILURE);
}

#define	GLD_DRIVER_PPA "SUNW,gld_v0_ppa"

/*
 * Given the dip for a network interface return the ppa for that interface.
 *
 * In all cases except GLD v0 drivers, the ppa == instance.
 * In the case of GLD v0 drivers, the ppa is equal to the attach order.
 * So for these drivers when the attach routine calls gld_register(),
 * the GLD framework creates an integer property called "gld_driver_ppa"
 * that can be queried here.
 *
 * The only time this function is used is when a system is booting over nfs.
 * In this case the system has to resolve the pathname of the boot device
 * to it's ppa.
 */
int
i_ddi_devi_get_ppa(dev_info_t *dip)
{
	return (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    GLD_DRIVER_PPA, ddi_get_instance(dip)));
}

/*
 * i_ddi_devi_set_ppa() should only be called from gld_register()
 * and only for GLD v0 drivers
 */
void
i_ddi_devi_set_ppa(dev_info_t *dip, int ppa)
{
	(void) e_ddi_prop_update_int(DDI_DEV_T_NONE, dip, GLD_DRIVER_PPA, ppa);
}


/*
 * Private DDI Console bell functions.
 */
void
ddi_ring_console_bell(clock_t duration)
{
	if (ddi_console_bell_func != NULL)
		(*ddi_console_bell_func)(duration);
}

void
ddi_set_console_bell(void (*bellfunc)(clock_t duration))
{
	ddi_console_bell_func = bellfunc;
}

int
ddi_dma_alloc_handle(dev_info_t *dip, ddi_dma_attr_t *attr,
	int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	int (*funcp)() = ddi_dma_allochdl;
	ddi_dma_attr_t dma_attr;
	struct bus_ops *bop;

	if (attr == (ddi_dma_attr_t *)0)
		return (DDI_DMA_BADATTR);

	dma_attr = *attr;

	bop = DEVI(dip)->devi_ops->devo_bus_ops;
	if (bop && bop->bus_dma_allochdl)
		funcp = bop->bus_dma_allochdl;

	return ((*funcp)(dip, dip, &dma_attr, waitfp, arg, handlep));
}

void
ddi_dma_free_handle(ddi_dma_handle_t *handlep)
{
	ddi_dma_handle_t h = *handlep;
	(void) ddi_dma_freehdl(HD, HD, h);
}

static uintptr_t dma_mem_list_id = 0;


int
ddi_dma_mem_alloc(ddi_dma_handle_t handle, size_t length,
	ddi_device_acc_attr_t *accattrp, uint_t flags,
	int (*waitfp)(caddr_t), caddr_t arg, caddr_t *kaddrp,
	size_t *real_length, ddi_acc_handle_t *handlep)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	dev_info_t *dip = hp->dmai_rdip;
	ddi_acc_hdl_t *ap;
	ddi_dma_attr_t *attrp = &hp->dmai_attr;
	uint_t sleepflag, xfermodes;
	int (*fp)(caddr_t);
	int rval;

	if (waitfp == DDI_DMA_SLEEP)
		fp = (int (*)())KM_SLEEP;
	else if (waitfp == DDI_DMA_DONTWAIT)
		fp = (int (*)())KM_NOSLEEP;
	else
		fp = waitfp;
	*handlep = impl_acc_hdl_alloc(fp, arg);
	if (*handlep == NULL)
		return (DDI_FAILURE);

	/* check if the cache attributes are supported */
	if (i_ddi_check_cache_attr(flags) == B_FALSE)
		return (DDI_FAILURE);

	/*
	 * Transfer the meaningful bits to xfermodes.
	 * Double-check if the 3rd party driver correctly sets the bits.
	 * If not, set DDI_DMA_STREAMING to keep compatibility.
	 */
	xfermodes = flags & (DDI_DMA_CONSISTENT | DDI_DMA_STREAMING);
	if (xfermodes == 0) {
		xfermodes = DDI_DMA_STREAMING;
	}

	/*
	 * initialize the common elements of data access handle
	 */
	ap = impl_acc_hdl_get(*handlep);
	ap->ah_vers = VERS_ACCHDL;
	ap->ah_dip = dip;
	ap->ah_offset = 0;
	ap->ah_len = 0;
	ap->ah_xfermodes = flags;
	ap->ah_acc = *accattrp;

	sleepflag = ((waitfp == DDI_DMA_SLEEP) ? 1 : 0);
	if (xfermodes == DDI_DMA_CONSISTENT) {
		rval = i_ddi_mem_alloc(dip, attrp, length, sleepflag,
		    flags, accattrp, kaddrp, NULL, ap);
		*real_length = length;
	} else {
		rval = i_ddi_mem_alloc(dip, attrp, length, sleepflag,
		    flags, accattrp, kaddrp, real_length, ap);
	}
	if (rval == DDI_SUCCESS) {
		ap->ah_len = (off_t)(*real_length);
		ap->ah_addr = *kaddrp;
	} else {
		impl_acc_hdl_free(*handlep);
		*handlep = (ddi_acc_handle_t)NULL;
		if (waitfp != DDI_DMA_SLEEP && waitfp != DDI_DMA_DONTWAIT) {
			ddi_set_callback(waitfp, arg, &dma_mem_list_id);
		}
		rval = DDI_FAILURE;
	}
	return (rval);
}

void
ddi_dma_mem_free(ddi_acc_handle_t *handlep)
{
	ddi_acc_hdl_t *ap;

	ap = impl_acc_hdl_get(*handlep);
	ASSERT(ap);

	i_ddi_mem_free((caddr_t)ap->ah_addr, ap);

	/*
	 * free the handle
	 */
	impl_acc_hdl_free(*handlep);
	*handlep = (ddi_acc_handle_t)NULL;

	if (dma_mem_list_id != 0) {
		ddi_run_callback(&dma_mem_list_id);
	}
}

int
ddi_dma_buf_bind_handle(ddi_dma_handle_t handle, struct buf *bp,
	uint_t flags, int (*waitfp)(caddr_t), caddr_t arg,
	ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	dev_info_t *dip, *rdip;
	struct ddi_dma_req dmareq;
	int (*funcp)();

	dmareq.dmar_flags = flags;
	dmareq.dmar_fp = waitfp;
	dmareq.dmar_arg = arg;
	dmareq.dmar_object.dmao_size = (uint_t)bp->b_bcount;

	if (bp->b_flags & B_PAGEIO) {
		dmareq.dmar_object.dmao_type = DMA_OTYP_PAGES;
		dmareq.dmar_object.dmao_obj.pp_obj.pp_pp = bp->b_pages;
		dmareq.dmar_object.dmao_obj.pp_obj.pp_offset =
		    (uint_t)(((uintptr_t)bp->b_un.b_addr) & MMU_PAGEOFFSET);
	} else {
		dmareq.dmar_object.dmao_obj.virt_obj.v_addr = bp->b_un.b_addr;
		if (bp->b_flags & B_SHADOW) {
			dmareq.dmar_object.dmao_obj.virt_obj.v_priv =
			    bp->b_shadow;
			dmareq.dmar_object.dmao_type = DMA_OTYP_BUFVADDR;
		} else {
			dmareq.dmar_object.dmao_type =
			    (bp->b_flags & (B_PHYS | B_REMAPPED)) ?
			    DMA_OTYP_BUFVADDR : DMA_OTYP_VADDR;
			dmareq.dmar_object.dmao_obj.virt_obj.v_priv = NULL;
		}

		/*
		 * If the buffer has no proc pointer, or the proc
		 * struct has the kernel address space, or the buffer has
		 * been marked B_REMAPPED (meaning that it is now
		 * mapped into the kernel's address space), then
		 * the address space is kas (kernel address space).
		 */
		if ((bp->b_proc == NULL) || (bp->b_proc->p_as == &kas) ||
		    (bp->b_flags & B_REMAPPED)) {
			dmareq.dmar_object.dmao_obj.virt_obj.v_as = 0;
		} else {
			dmareq.dmar_object.dmao_obj.virt_obj.v_as =
			    bp->b_proc->p_as;
		}
	}

	dip = rdip = hp->dmai_rdip;
	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_bindhdl;
	funcp = DEVI(rdip)->devi_bus_dma_bindfunc;
	return ((*funcp)(dip, rdip, handle, &dmareq, cookiep, ccountp));
}

int
ddi_dma_addr_bind_handle(ddi_dma_handle_t handle, struct as *as,
	caddr_t addr, size_t len, uint_t flags, int (*waitfp)(caddr_t),
	caddr_t arg, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	dev_info_t *dip, *rdip;
	struct ddi_dma_req dmareq;
	int (*funcp)();

	if (len == (uint_t)0) {
		return (DDI_DMA_NOMAPPING);
	}
	dmareq.dmar_flags = flags;
	dmareq.dmar_fp = waitfp;
	dmareq.dmar_arg = arg;
	dmareq.dmar_object.dmao_size = len;
	dmareq.dmar_object.dmao_type = DMA_OTYP_VADDR;
	dmareq.dmar_object.dmao_obj.virt_obj.v_as = as;
	dmareq.dmar_object.dmao_obj.virt_obj.v_addr = addr;
	dmareq.dmar_object.dmao_obj.virt_obj.v_priv = NULL;

	dip = rdip = hp->dmai_rdip;
	if (dip != ddi_root_node())
		dip = (dev_info_t *)DEVI(dip)->devi_bus_dma_bindhdl;
	funcp = DEVI(rdip)->devi_bus_dma_bindfunc;
	return ((*funcp)(dip, rdip, handle, &dmareq, cookiep, ccountp));
}

void
ddi_dma_nextcookie(ddi_dma_handle_t handle, ddi_dma_cookie_t *cookiep)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	ddi_dma_cookie_t *cp;

	cp = hp->dmai_cookie;
	ASSERT(cp);

	cookiep->dmac_notused = cp->dmac_notused;
	cookiep->dmac_type = cp->dmac_type;
	cookiep->dmac_address = cp->dmac_address;
	cookiep->dmac_size = cp->dmac_size;
	hp->dmai_cookie++;
}

int
ddi_dma_numwin(ddi_dma_handle_t handle, uint_t *nwinp)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	if ((hp->dmai_rflags & DDI_DMA_PARTIAL) == 0) {
		return (DDI_FAILURE);
	} else {
		*nwinp = hp->dmai_nwin;
		return (DDI_SUCCESS);
	}
}

int
ddi_dma_getwin(ddi_dma_handle_t h, uint_t win, off_t *offp,
	size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp)
{
	int (*funcp)() = ddi_dma_win;
	struct bus_ops *bop;

	bop = DEVI(HD)->devi_ops->devo_bus_ops;
	if (bop && bop->bus_dma_win)
		funcp = bop->bus_dma_win;

	return ((*funcp)(HD, HD, h, win, offp, lenp, cookiep, ccountp));
}

int
ddi_dma_set_sbus64(ddi_dma_handle_t h, ulong_t burstsizes)
{
	return (ddi_dma_mctl(HD, HD, h, DDI_DMA_SET_SBUS64, 0,
	    &burstsizes, 0, 0));
}

int
i_ddi_dma_fault_check(ddi_dma_impl_t *hp)
{
	return (hp->dmai_fault);
}

int
ddi_check_dma_handle(ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	int (*check)(ddi_dma_impl_t *);

	if ((check = hp->dmai_fault_check) == NULL)
		check = i_ddi_dma_fault_check;

	return (((*check)(hp) == DDI_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}

void
i_ddi_dma_set_fault(ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	void (*notify)(ddi_dma_impl_t *);

	if (!hp->dmai_fault) {
		hp->dmai_fault = 1;
		if ((notify = hp->dmai_fault_notify) != NULL)
			(*notify)(hp);
	}
}

void
i_ddi_dma_clr_fault(ddi_dma_handle_t handle)
{
	ddi_dma_impl_t *hp = (ddi_dma_impl_t *)handle;
	void (*notify)(ddi_dma_impl_t *);

	if (hp->dmai_fault) {
		hp->dmai_fault = 0;
		if ((notify = hp->dmai_fault_notify) != NULL)
			(*notify)(hp);
	}
}

/*
 * register mapping routines.
 */
int
ddi_regs_map_setup(dev_info_t *dip, uint_t rnumber, caddr_t *addrp,
	offset_t offset, offset_t len, ddi_device_acc_attr_t *accattrp,
	ddi_acc_handle_t *handle)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;
	int result;

	/*
	 * Allocate and initialize the common elements of data access handle.
	 */
	*handle = impl_acc_hdl_alloc(KM_SLEEP, NULL);
	hp = impl_acc_hdl_get(*handle);
	hp->ah_vers = VERS_ACCHDL;
	hp->ah_dip = dip;
	hp->ah_rnumber = rnumber;
	hp->ah_offset = offset;
	hp->ah_len = len;
	hp->ah_acc = *accattrp;

	/*
	 * Set up the mapping request and call to parent.
	 */
	mr.map_op = DDI_MO_MAP_LOCKED;
	mr.map_type = DDI_MT_RNUMBER;
	mr.map_obj.rnumber = rnumber;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;
	result = ddi_map(dip, &mr, offset, len, addrp);

	/*
	 * check for end result
	 */
	if (result != DDI_SUCCESS) {
		impl_acc_hdl_free(*handle);
		*handle = (ddi_acc_handle_t)NULL;
	} else {
		hp->ah_addr = *addrp;
	}

	return (result);
}

void
ddi_regs_map_free(ddi_acc_handle_t *handlep)
{
	ddi_map_req_t mr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(*handlep);
	ASSERT(hp);

	mr.map_op = DDI_MO_UNMAP;
	mr.map_type = DDI_MT_RNUMBER;
	mr.map_obj.rnumber = hp->ah_rnumber;
	mr.map_prot = PROT_READ | PROT_WRITE;
	mr.map_flags = DDI_MF_KERNEL_MAPPING;
	mr.map_handlep = hp;
	mr.map_vers = DDI_MAP_VERSION;

	/*
	 * Call my parent to unmap my regs.
	 */
	(void) ddi_map(hp->ah_dip, &mr, hp->ah_offset,
	    hp->ah_len, &hp->ah_addr);
	/*
	 * free the handle
	 */
	impl_acc_hdl_free(*handlep);
	*handlep = (ddi_acc_handle_t)NULL;
}

int
ddi_device_zero(ddi_acc_handle_t handle, caddr_t dev_addr, size_t bytecount,
	ssize_t dev_advcnt, uint_t dev_datasz)
{
	uint8_t *b;
	uint16_t *w;
	uint32_t *l;
	uint64_t *ll;

	/* check for total byte count is multiple of data transfer size */
	if (bytecount != ((bytecount / dev_datasz) * dev_datasz))
		return (DDI_FAILURE);

	switch (dev_datasz) {
	case DDI_DATA_SZ01_ACC:
		for (b = (uint8_t *)dev_addr;
		    bytecount != 0; bytecount -= 1, b += dev_advcnt)
			ddi_put8(handle, b, 0);
		break;
	case DDI_DATA_SZ02_ACC:
		for (w = (uint16_t *)dev_addr;
		    bytecount != 0; bytecount -= 2, w += dev_advcnt)
			ddi_put16(handle, w, 0);
		break;
	case DDI_DATA_SZ04_ACC:
		for (l = (uint32_t *)dev_addr;
		    bytecount != 0; bytecount -= 4, l += dev_advcnt)
			ddi_put32(handle, l, 0);
		break;
	case DDI_DATA_SZ08_ACC:
		for (ll = (uint64_t *)dev_addr;
		    bytecount != 0; bytecount -= 8, ll += dev_advcnt)
			ddi_put64(handle, ll, 0x0ll);
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

int
ddi_device_copy(
	ddi_acc_handle_t src_handle, caddr_t src_addr, ssize_t src_advcnt,
	ddi_acc_handle_t dest_handle, caddr_t dest_addr, ssize_t dest_advcnt,
	size_t bytecount, uint_t dev_datasz)
{
	uint8_t *b_src, *b_dst;
	uint16_t *w_src, *w_dst;
	uint32_t *l_src, *l_dst;
	uint64_t *ll_src, *ll_dst;

	/* check for total byte count is multiple of data transfer size */
	if (bytecount != ((bytecount / dev_datasz) * dev_datasz))
		return (DDI_FAILURE);

	switch (dev_datasz) {
	case DDI_DATA_SZ01_ACC:
		b_src = (uint8_t *)src_addr;
		b_dst = (uint8_t *)dest_addr;

		for (; bytecount != 0; bytecount -= 1) {
			ddi_put8(dest_handle, b_dst,
			    ddi_get8(src_handle, b_src));
			b_dst += dest_advcnt;
			b_src += src_advcnt;
		}
		break;
	case DDI_DATA_SZ02_ACC:
		w_src = (uint16_t *)src_addr;
		w_dst = (uint16_t *)dest_addr;

		for (; bytecount != 0; bytecount -= 2) {
			ddi_put16(dest_handle, w_dst,
			    ddi_get16(src_handle, w_src));
			w_dst += dest_advcnt;
			w_src += src_advcnt;
		}
		break;
	case DDI_DATA_SZ04_ACC:
		l_src = (uint32_t *)src_addr;
		l_dst = (uint32_t *)dest_addr;

		for (; bytecount != 0; bytecount -= 4) {
			ddi_put32(dest_handle, l_dst,
			    ddi_get32(src_handle, l_src));
			l_dst += dest_advcnt;
			l_src += src_advcnt;
		}
		break;
	case DDI_DATA_SZ08_ACC:
		ll_src = (uint64_t *)src_addr;
		ll_dst = (uint64_t *)dest_addr;

		for (; bytecount != 0; bytecount -= 8) {
			ddi_put64(dest_handle, ll_dst,
			    ddi_get64(src_handle, ll_src));
			ll_dst += dest_advcnt;
			ll_src += src_advcnt;
		}
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

#define	swap16(value)  \
	((((value) & 0xff) << 8) | ((value) >> 8))

#define	swap32(value)	\
	(((uint32_t)swap16((uint16_t)((value) & 0xffff)) << 16) | \
	(uint32_t)swap16((uint16_t)((value) >> 16)))

#define	swap64(value)	\
	(((uint64_t)swap32((uint32_t)((value) & 0xffffffff)) \
	    << 32) | \
	(uint64_t)swap32((uint32_t)((value) >> 32)))

uint16_t
ddi_swap16(uint16_t value)
{
	return (swap16(value));
}

uint32_t
ddi_swap32(uint32_t value)
{
	return (swap32(value));
}

uint64_t
ddi_swap64(uint64_t value)
{
	return (swap64(value));
}

/*
 * Convert a binding name to a driver name.
 * A binding name is the name used to determine the driver for a
 * device - it may be either an alias for the driver or the name
 * of the driver itself.
 */
char *
i_binding_to_drv_name(char *bname)
{
	major_t major_no;

	ASSERT(bname != NULL);

	if ((major_no = ddi_name_to_major(bname)) == -1)
		return (NULL);
	return (ddi_major_to_name(major_no));
}

/*
 * Search for minor name that has specified dev_t and spec_type.
 * If spec_type is zero then any dev_t match works.  Since we
 * are returning a pointer to the minor name string, we require the
 * caller to do the locking.
 */
char *
i_ddi_devtspectype_to_minorname(dev_info_t *dip, dev_t dev, int spec_type)
{
	struct ddi_minor_data	*dmdp;

	/*
	 * The did layered driver currently intentionally returns a
	 * devinfo ptr for an underlying sd instance based on a did
	 * dev_t. In this case it is not an error.
	 *
	 * The did layered driver is associated with Sun Cluster.
	 */
	ASSERT((ddi_driver_major(dip) == getmajor(dev)) ||
	    (strcmp(ddi_major_to_name(getmajor(dev)), "did") == 0));

	ASSERT(DEVI_BUSY_OWNED(dip));
	for (dmdp = DEVI(dip)->devi_minor; dmdp; dmdp = dmdp->next) {
		if (((dmdp->type == DDM_MINOR) ||
		    (dmdp->type == DDM_INTERNAL_PATH) ||
		    (dmdp->type == DDM_DEFAULT)) &&
		    (dmdp->ddm_dev == dev) &&
		    ((((spec_type & (S_IFCHR|S_IFBLK))) == 0) ||
		    (dmdp->ddm_spec_type == spec_type)))
			return (dmdp->ddm_name);
	}

	return (NULL);
}

/*
 * Find the devt and spectype of the specified minor_name.
 * Return DDI_FAILURE if minor_name not found. Since we are
 * returning everything via arguments we can do the locking.
 */
int
i_ddi_minorname_to_devtspectype(dev_info_t *dip, char *minor_name,
	dev_t *devtp, int *spectypep)
{
	int			circ;
	struct ddi_minor_data	*dmdp;

	/* deal with clone minor nodes */
	if (dip == clone_dip) {
		major_t	major;
		/*
		 * Make sure minor_name is a STREAMS driver.
		 * We load the driver but don't attach to any instances.
		 */

		major = ddi_name_to_major(minor_name);
		if (major == DDI_MAJOR_T_NONE)
			return (DDI_FAILURE);

		if (ddi_hold_driver(major) == NULL)
			return (DDI_FAILURE);

		if (STREAMSTAB(major) == NULL) {
			ddi_rele_driver(major);
			return (DDI_FAILURE);
		}
		ddi_rele_driver(major);

		if (devtp)
			*devtp = makedevice(clone_major, (minor_t)major);

		if (spectypep)
			*spectypep = S_IFCHR;

		return (DDI_SUCCESS);
	}

	ndi_devi_enter(dip, &circ);
	for (dmdp = DEVI(dip)->devi_minor; dmdp; dmdp = dmdp->next) {
		if (((dmdp->type != DDM_MINOR) &&
		    (dmdp->type != DDM_INTERNAL_PATH) &&
		    (dmdp->type != DDM_DEFAULT)) ||
		    strcmp(minor_name, dmdp->ddm_name))
			continue;

		if (devtp)
			*devtp = dmdp->ddm_dev;

		if (spectypep)
			*spectypep = dmdp->ddm_spec_type;

		ndi_devi_exit(dip, circ);
		return (DDI_SUCCESS);
	}
	ndi_devi_exit(dip, circ);

	return (DDI_FAILURE);
}

static kmutex_t devid_gen_mutex;
static short	devid_gen_number;

#ifdef DEBUG

static int	devid_register_corrupt = 0;
static int	devid_register_corrupt_major = 0;
static int	devid_register_corrupt_hint = 0;
static int	devid_register_corrupt_hint_major = 0;

static int devid_lyr_debug = 0;

#define	DDI_DEBUG_DEVID_DEVTS(msg, ndevs, devs)		\
	if (devid_lyr_debug)					\
		ddi_debug_devid_devts(msg, ndevs, devs)

#else

#define	DDI_DEBUG_DEVID_DEVTS(msg, ndevs, devs)

#endif /* DEBUG */


#ifdef	DEBUG

static void
ddi_debug_devid_devts(char *msg, int ndevs, dev_t *devs)
{
	int i;

	cmn_err(CE_CONT, "%s:\n", msg);
	for (i = 0; i < ndevs; i++) {
		cmn_err(CE_CONT, "    0x%lx\n", devs[i]);
	}
}

static void
ddi_debug_devid_paths(char *msg, int npaths, char **paths)
{
	int i;

	cmn_err(CE_CONT, "%s:\n", msg);
	for (i = 0; i < npaths; i++) {
		cmn_err(CE_CONT, "    %s\n", paths[i]);
	}
}

static void
ddi_debug_devid_devts_per_path(char *path, int ndevs, dev_t *devs)
{
	int i;

	cmn_err(CE_CONT, "dev_ts per path %s\n", path);
	for (i = 0; i < ndevs; i++) {
		cmn_err(CE_CONT, "    0x%lx\n", devs[i]);
	}
}

#endif	/* DEBUG */

/*
 * Register device id into DDI framework.
 * Must be called when the driver is bound.
 */
static int
i_ddi_devid_register(dev_info_t *dip, ddi_devid_t devid)
{
	impl_devid_t	*i_devid = (impl_devid_t *)devid;
	size_t		driver_len;
	const char	*driver_name;
	char		*devid_str;
	major_t		major;

	if ((dip == NULL) ||
	    ((major = ddi_driver_major(dip)) == DDI_MAJOR_T_NONE))
		return (DDI_FAILURE);

	/* verify that the devid is valid */
	if (ddi_devid_valid(devid) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* Updating driver name hint in devid */
	driver_name = ddi_driver_name(dip);
	driver_len = strlen(driver_name);
	if (driver_len > DEVID_HINT_SIZE) {
		/* Pick up last four characters of driver name */
		driver_name += driver_len - DEVID_HINT_SIZE;
		driver_len = DEVID_HINT_SIZE;
	}
	bzero(i_devid->did_driver, DEVID_HINT_SIZE);
	bcopy(driver_name, i_devid->did_driver, driver_len);

#ifdef DEBUG
	/* Corrupt the devid for testing. */
	if (devid_register_corrupt)
		i_devid->did_id[0] += devid_register_corrupt;
	if (devid_register_corrupt_major &&
	    (major == devid_register_corrupt_major))
		i_devid->did_id[0] += 1;
	if (devid_register_corrupt_hint)
		i_devid->did_driver[0] += devid_register_corrupt_hint;
	if (devid_register_corrupt_hint_major &&
	    (major == devid_register_corrupt_hint_major))
		i_devid->did_driver[0] += 1;
#endif /* DEBUG */

	/* encode the devid as a string */
	if ((devid_str = ddi_devid_str_encode(devid, NULL)) == NULL)
		return (DDI_FAILURE);

	/* add string as a string property */
	if (ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    DEVID_PROP_NAME, devid_str) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: devid property update failed",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		ddi_devid_str_free(devid_str);
		return (DDI_FAILURE);
	}

	/* keep pointer to devid string for interrupt context fma code */
	if (DEVI(dip)->devi_devid_str)
		ddi_devid_str_free(DEVI(dip)->devi_devid_str);
	DEVI(dip)->devi_devid_str = devid_str;
	return (DDI_SUCCESS);
}

int
ddi_devid_register(dev_info_t *dip, ddi_devid_t devid)
{
	int rval;

	rval = i_ddi_devid_register(dip, devid);
	if (rval == DDI_SUCCESS) {
		/*
		 * Register devid in devid-to-path cache
		 */
		if (e_devid_cache_register(dip, devid) == DDI_SUCCESS) {
			mutex_enter(&DEVI(dip)->devi_lock);
			DEVI(dip)->devi_flags |= DEVI_CACHED_DEVID;
			mutex_exit(&DEVI(dip)->devi_lock);
		} else if (ddi_get_name_addr(dip)) {
			/*
			 * We only expect cache_register DDI_FAILURE when we
			 * can't form the full path because of NULL devi_addr.
			 */
			cmn_err(CE_WARN, "%s%d: failed to cache devid",
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
	} else {
		cmn_err(CE_WARN, "%s%d: failed to register devid",
		    ddi_driver_name(dip), ddi_get_instance(dip));
	}
	return (rval);
}

/*
 * Remove (unregister) device id from DDI framework.
 * Must be called when device is detached.
 */
static void
i_ddi_devid_unregister(dev_info_t *dip)
{
	if (DEVI(dip)->devi_devid_str) {
		ddi_devid_str_free(DEVI(dip)->devi_devid_str);
		DEVI(dip)->devi_devid_str = NULL;
	}

	/* remove the devid property */
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, DEVID_PROP_NAME);
}

void
ddi_devid_unregister(dev_info_t *dip)
{
	mutex_enter(&DEVI(dip)->devi_lock);
	DEVI(dip)->devi_flags &= ~DEVI_CACHED_DEVID;
	mutex_exit(&DEVI(dip)->devi_lock);
	e_devid_cache_unregister(dip);
	i_ddi_devid_unregister(dip);
}

/*
 * Allocate and initialize a device id.
 */
int
ddi_devid_init(
	dev_info_t	*dip,
	ushort_t	devid_type,
	ushort_t	nbytes,
	void		*id,
	ddi_devid_t	*ret_devid)
{
	impl_devid_t	*i_devid;
	int		sz = sizeof (*i_devid) + nbytes - sizeof (char);
	int		driver_len;
	const char	*driver_name;

	switch (devid_type) {
	case DEVID_SCSI3_WWN:
		/*FALLTHRU*/
	case DEVID_SCSI_SERIAL:
		/*FALLTHRU*/
	case DEVID_ATA_SERIAL:
		/*FALLTHRU*/
	case DEVID_ENCAP:
		if (nbytes == 0)
			return (DDI_FAILURE);
		if (id == NULL)
			return (DDI_FAILURE);
		break;
	case DEVID_FAB:
		if (nbytes != 0)
			return (DDI_FAILURE);
		if (id != NULL)
			return (DDI_FAILURE);
		nbytes = sizeof (int) +
		    sizeof (struct timeval32) + sizeof (short);
		sz += nbytes;
		break;
	default:
		return (DDI_FAILURE);
	}

	if ((i_devid = kmem_zalloc(sz, KM_SLEEP)) == NULL)
		return (DDI_FAILURE);

	i_devid->did_magic_hi = DEVID_MAGIC_MSB;
	i_devid->did_magic_lo = DEVID_MAGIC_LSB;
	i_devid->did_rev_hi = DEVID_REV_MSB;
	i_devid->did_rev_lo = DEVID_REV_LSB;
	DEVID_FORMTYPE(i_devid, devid_type);
	DEVID_FORMLEN(i_devid, nbytes);

	/* Fill in driver name hint */
	driver_name = ddi_driver_name(dip);
	driver_len = strlen(driver_name);
	if (driver_len > DEVID_HINT_SIZE) {
		/* Pick up last four characters of driver name */
		driver_name += driver_len - DEVID_HINT_SIZE;
		driver_len = DEVID_HINT_SIZE;
	}

	bcopy(driver_name, i_devid->did_driver, driver_len);

	/* Fill in id field */
	if (devid_type == DEVID_FAB) {
		char		*cp;
		uint32_t	hostid;
		struct timeval32 timestamp32;
		int		i;
		int		*ip;
		short		gen;

		/* increase the generation number */
		mutex_enter(&devid_gen_mutex);
		gen = devid_gen_number++;
		mutex_exit(&devid_gen_mutex);

		cp = i_devid->did_id;

		/* Fill in host id (big-endian byte ordering) */
		hostid = zone_get_hostid(NULL);
		*cp++ = hibyte(hiword(hostid));
		*cp++ = lobyte(hiword(hostid));
		*cp++ = hibyte(loword(hostid));
		*cp++ = lobyte(loword(hostid));

		/*
		 * Fill in timestamp (big-endian byte ordering)
		 *
		 * (Note that the format may have to be changed
		 * before 2038 comes around, though it's arguably
		 * unique enough as it is..)
		 */
		uniqtime32(&timestamp32);
		ip = (int *)&timestamp32;
		for (i = 0;
		    i < sizeof (timestamp32) / sizeof (int); i++, ip++) {
			int	val;
			val = *ip;
			*cp++ = hibyte(hiword(val));
			*cp++ = lobyte(hiword(val));
			*cp++ = hibyte(loword(val));
			*cp++ = lobyte(loword(val));
		}

		/* fill in the generation number */
		*cp++ = hibyte(gen);
		*cp++ = lobyte(gen);
	} else
		bcopy(id, i_devid->did_id, nbytes);

	/* return device id */
	*ret_devid = (ddi_devid_t)i_devid;
	return (DDI_SUCCESS);
}

int
ddi_devid_get(dev_info_t *dip, ddi_devid_t *ret_devid)
{
	return (i_ddi_devi_get_devid(DDI_DEV_T_ANY, dip, ret_devid));
}

int
i_ddi_devi_get_devid(dev_t dev, dev_info_t *dip, ddi_devid_t *ret_devid)
{
	char		*devidstr;

	ASSERT(dev != DDI_DEV_T_NONE);

	/* look up the property, devt specific first */
	if (ddi_prop_lookup_string(dev, dip, DDI_PROP_DONTPASS,
	    DEVID_PROP_NAME, &devidstr) != DDI_PROP_SUCCESS) {
		if ((dev == DDI_DEV_T_ANY) ||
		    (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, DEVID_PROP_NAME, &devidstr) !=
		    DDI_PROP_SUCCESS)) {
			return (DDI_FAILURE);
		}
	}

	/* convert to binary form */
	if (ddi_devid_str_decode(devidstr, ret_devid, NULL) == -1) {
		ddi_prop_free(devidstr);
		return (DDI_FAILURE);
	}
	ddi_prop_free(devidstr);
	return (DDI_SUCCESS);
}

/*
 * Return a copy of the device id for dev_t
 */
int
ddi_lyr_get_devid(dev_t dev, ddi_devid_t *ret_devid)
{
	dev_info_t	*dip;
	int		rval;

	/* get the dip */
	if ((dip = e_ddi_hold_devi_by_dev(dev, 0)) == NULL)
		return (DDI_FAILURE);

	rval = i_ddi_devi_get_devid(dev, dip, ret_devid);

	ddi_release_devi(dip);		/* e_ddi_hold_devi_by_dev() */
	return (rval);
}

/*
 * Return a copy of the minor name for dev_t and spec_type
 */
int
ddi_lyr_get_minor_name(dev_t dev, int spec_type, char **minor_name)
{
	char		*buf;
	int		circ;
	dev_info_t	*dip;
	char		*nm;
	int		rval;

	if ((dip = e_ddi_hold_devi_by_dev(dev, 0)) == NULL) {
		*minor_name = NULL;
		return (DDI_FAILURE);
	}

	/* Find the minor name and copy into max size buf */
	buf = kmem_alloc(MAXNAMELEN, KM_SLEEP);
	ndi_devi_enter(dip, &circ);
	nm = i_ddi_devtspectype_to_minorname(dip, dev, spec_type);
	if (nm)
		(void) strcpy(buf, nm);
	ndi_devi_exit(dip, circ);
	ddi_release_devi(dip);	/* e_ddi_hold_devi_by_dev() */

	if (nm) {
		/* duplicate into min size buf for return result */
		*minor_name = i_ddi_strdup(buf, KM_SLEEP);
		rval = DDI_SUCCESS;
	} else {
		*minor_name = NULL;
		rval = DDI_FAILURE;
	}

	/* free max size buf and return */
	kmem_free(buf, MAXNAMELEN);
	return (rval);
}

int
ddi_lyr_devid_to_devlist(
	ddi_devid_t	devid,
	char		*minor_name,
	int		*retndevs,
	dev_t		**retdevs)
{
	ASSERT(ddi_devid_valid(devid) == DDI_SUCCESS);

	if (e_devid_cache_to_devt_list(devid, minor_name,
	    retndevs, retdevs) == DDI_SUCCESS) {
		ASSERT(*retndevs > 0);
		DDI_DEBUG_DEVID_DEVTS("ddi_lyr_devid_to_devlist",
		    *retndevs, *retdevs);
		return (DDI_SUCCESS);
	}

	if (e_ddi_devid_discovery(devid) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	if (e_devid_cache_to_devt_list(devid, minor_name,
	    retndevs, retdevs) == DDI_SUCCESS) {
		ASSERT(*retndevs > 0);
		DDI_DEBUG_DEVID_DEVTS("ddi_lyr_devid_to_devlist",
		    *retndevs, *retdevs);
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

void
ddi_lyr_free_devlist(dev_t *devlist, int ndevs)
{
	kmem_free(devlist, sizeof (dev_t) * ndevs);
}

/*
 * Note: This will need to be fixed if we ever allow processes to
 * have more than one data model per exec.
 */
model_t
ddi_mmap_get_model(void)
{
	return (get_udatamodel());
}

model_t
ddi_model_convert_from(model_t model)
{
	return ((model & DDI_MODEL_MASK) & ~DDI_MODEL_NATIVE);
}

/*
 * ddi interfaces managing storage and retrieval of eventcookies.
 */

/*
 * Invoke bus nexus driver's implementation of the
 * (*bus_remove_eventcall)() interface to remove a registered
 * callback handler for "event".
 */
int
ddi_remove_event_handler(ddi_callback_id_t id)
{
	ndi_event_callbacks_t *cb = (ndi_event_callbacks_t *)id;
	dev_info_t *ddip;

	ASSERT(cb);
	if (!cb) {
		return (DDI_FAILURE);
	}

	ddip = NDI_EVENT_DDIP(cb->ndi_evtcb_cookie);
	return (ndi_busop_remove_eventcall(ddip, id));
}

/*
 * Invoke bus nexus driver's implementation of the
 * (*bus_add_eventcall)() interface to register a callback handler
 * for "event".
 */
int
ddi_add_event_handler(dev_info_t *dip, ddi_eventcookie_t event,
    void (*handler)(dev_info_t *, ddi_eventcookie_t, void *, void *),
    void *arg, ddi_callback_id_t *id)
{
	return (ndi_busop_add_eventcall(dip, dip, event, handler, arg, id));
}


/*
 * Return a handle for event "name" by calling up the device tree
 * hierarchy via  (*bus_get_eventcookie)() interface until claimed
 * by a bus nexus or top of dev_info tree is reached.
 */
int
ddi_get_eventcookie(dev_info_t *dip, char *name,
    ddi_eventcookie_t *event_cookiep)
{
	return (ndi_busop_get_eventcookie(dip, dip,
	    name, event_cookiep));
}

/*
 * This procedure is provided as the general callback function when
 * umem_lockmemory calls as_add_callback for long term memory locking.
 * When as_unmap, as_setprot, or as_free encounter segments which have
 * locked memory, this callback will be invoked.
 */
void
umem_lock_undo(struct as *as, void *arg, uint_t event)
{
	_NOTE(ARGUNUSED(as, event))
	struct ddi_umem_cookie *cp = (struct ddi_umem_cookie *)arg;

	/*
	 * Call the cleanup function.  Decrement the cookie reference
	 * count, if it goes to zero, return the memory for the cookie.
	 * The i_ddi_umem_unlock for this cookie may or may not have been
	 * called already.  It is the responsibility of the caller of
	 * umem_lockmemory to handle the case of the cleanup routine
	 * being called after a ddi_umem_unlock for the cookie
	 * was called.
	 */

	(*cp->callbacks.cbo_umem_lock_cleanup)((ddi_umem_cookie_t)cp);

	/* remove the cookie if reference goes to zero */
	if (atomic_add_long_nv((ulong_t *)(&(cp->cook_refcnt)), -1) == 0) {
		kmem_free(cp, sizeof (struct ddi_umem_cookie));
	}
}

/*
 * The following two Consolidation Private routines provide generic
 * interfaces to increase/decrease the amount of device-locked memory.
 *
 * To keep project_rele and project_hold consistent, i_ddi_decr_locked_memory()
 * must be called every time i_ddi_incr_locked_memory() is called.
 */
int
/* ARGSUSED */
i_ddi_incr_locked_memory(proc_t *procp, rctl_qty_t inc)
{
	ASSERT(procp != NULL);
	mutex_enter(&procp->p_lock);
	if (rctl_incr_locked_mem(procp, NULL, inc, 1)) {
		mutex_exit(&procp->p_lock);
		return (ENOMEM);
	}
	mutex_exit(&procp->p_lock);
	return (0);
}

/*
 * To keep project_rele and project_hold consistent, i_ddi_incr_locked_memory()
 * must be called every time i_ddi_decr_locked_memory() is called.
 */
/* ARGSUSED */
void
i_ddi_decr_locked_memory(proc_t *procp, rctl_qty_t dec)
{
	ASSERT(procp != NULL);
	mutex_enter(&procp->p_lock);
	rctl_decr_locked_mem(procp, NULL, dec, 1);
	mutex_exit(&procp->p_lock);
}

/*
 * The cookie->upd_max_lock_rctl flag is used to determine if we should
 * charge device locked memory to the max-locked-memory rctl.  Tracking
 * device locked memory causes the rctl locks to get hot under high-speed
 * I/O such as RDSv3 over IB.  If there is no max-locked-memory rctl limit,
 * we bypass charging the locked memory to the rctl altogether.  The cookie's
 * flag tells us if the rctl value should be updated when unlocking the memory,
 * in case the rctl gets changed after the memory was locked.  Any device
 * locked memory in that rare case will not be counted toward the rctl limit.
 *
 * When tracking the locked memory, the kproject_t parameter is always NULL
 * in the code paths:
 *	i_ddi_incr_locked_memory -> rctl_incr_locked_mem
 *	i_ddi_decr_locked_memory -> rctl_decr_locked_mem
 * Thus, we always use the tk_proj member to check the projp setting.
 */
static void
init_lockedmem_rctl_flag(struct ddi_umem_cookie *cookie)
{
	proc_t		*p;
	kproject_t	*projp;
	zone_t		*zonep;

	ASSERT(cookie);
	p = cookie->procp;
	ASSERT(p);

	zonep = p->p_zone;
	projp = p->p_task->tk_proj;

	ASSERT(zonep);
	ASSERT(projp);

	if (zonep->zone_locked_mem_ctl == UINT64_MAX &&
	    projp->kpj_data.kpd_locked_mem_ctl == UINT64_MAX)
		cookie->upd_max_lock_rctl = 0;
	else
		cookie->upd_max_lock_rctl = 1;
}

/*
 * This routine checks if the max-locked-memory resource ctl is
 * exceeded, if not increments it, grabs a hold on the project.
 * Returns 0 if successful otherwise returns error code
 */
static int
umem_incr_devlockmem(struct ddi_umem_cookie *cookie)
{
	proc_t		*procp;
	int		ret;

	ASSERT(cookie);
	if (cookie->upd_max_lock_rctl == 0)
		return (0);

	procp = cookie->procp;
	ASSERT(procp);

	if ((ret = i_ddi_incr_locked_memory(procp,
	    cookie->size)) != 0) {
		return (ret);
	}
	return (0);
}

/*
 * Decrements the max-locked-memory resource ctl and releases
 * the hold on the project that was acquired during umem_incr_devlockmem
 */
static void
umem_decr_devlockmem(struct ddi_umem_cookie *cookie)
{
	proc_t		*proc;

	if (cookie->upd_max_lock_rctl == 0)
		return;

	proc = (proc_t *)cookie->procp;
	if (!proc)
		return;

	i_ddi_decr_locked_memory(proc, cookie->size);
}

/*
 * A consolidation private function which is essentially equivalent to
 * ddi_umem_lock but with the addition of arguments ops_vector and procp.
 * A call to as_add_callback is done if DDI_UMEMLOCK_LONGTERM is set, and
 * the ops_vector is valid.
 *
 * Lock the virtual address range in the current process and create a
 * ddi_umem_cookie (of type UMEM_LOCKED). This can be used to pass to
 * ddi_umem_iosetup to create a buf or do devmap_umem_setup/remap to export
 * to user space.
 *
 * Note: The resource control accounting currently uses a full charge model
 * in other words attempts to lock the same/overlapping areas of memory
 * will deduct the full size of the buffer from the projects running
 * counter for the device locked memory.
 *
 * addr, size should be PAGESIZE aligned
 *
 * flags - DDI_UMEMLOCK_READ, DDI_UMEMLOCK_WRITE or both
 *	identifies whether the locked memory will be read or written or both
 *      DDI_UMEMLOCK_LONGTERM  must be set when the locking will
 * be maintained for an indefinitely long period (essentially permanent),
 * rather than for what would be required for a typical I/O completion.
 * When DDI_UMEMLOCK_LONGTERM is set, umem_lockmemory will return EFAULT
 * if the memory pertains to a regular file which is mapped MAP_SHARED.
 * This is to prevent a deadlock if a file truncation is attempted after
 * after the locking is done.
 *
 * Returns 0 on success
 *	EINVAL - for invalid parameters
 *	EPERM, ENOMEM and other error codes returned by as_pagelock
 *	ENOMEM - is returned if the current request to lock memory exceeds
 *		*.max-locked-memory resource control value.
 *      EFAULT - memory pertains to a regular file mapped shared and
 *		and DDI_UMEMLOCK_LONGTERM flag is set
 *	EAGAIN - could not start the ddi_umem_unlock list processing thread
 */
int
umem_lockmemory(caddr_t addr, size_t len, int flags, ddi_umem_cookie_t *cookie,
		struct umem_callback_ops *ops_vector,
		proc_t *procp)
{
	int	error;
	struct ddi_umem_cookie *p;
	void	(*driver_callback)() = NULL;
	struct as *as;
	struct seg		*seg;
	vnode_t			*vp;

	/* Allow device drivers to not have to reference "curproc" */
	if (procp == NULL)
		procp = curproc;
	as = procp->p_as;
	*cookie = NULL;		/* in case of any error return */

	/* These are the only three valid flags */
	if ((flags & ~(DDI_UMEMLOCK_READ | DDI_UMEMLOCK_WRITE |
	    DDI_UMEMLOCK_LONGTERM)) != 0)
		return (EINVAL);

	/* At least one (can be both) of the two access flags must be set */
	if ((flags & (DDI_UMEMLOCK_READ | DDI_UMEMLOCK_WRITE)) == 0)
		return (EINVAL);

	/* addr and len must be page-aligned */
	if (((uintptr_t)addr & PAGEOFFSET) != 0)
		return (EINVAL);

	if ((len & PAGEOFFSET) != 0)
		return (EINVAL);

	/*
	 * For longterm locking a driver callback must be specified; if
	 * not longterm then a callback is optional.
	 */
	if (ops_vector != NULL) {
		if (ops_vector->cbo_umem_callback_version !=
		    UMEM_CALLBACK_VERSION)
			return (EINVAL);
		else
			driver_callback = ops_vector->cbo_umem_lock_cleanup;
	}
	if ((driver_callback == NULL) && (flags & DDI_UMEMLOCK_LONGTERM))
		return (EINVAL);

	/*
	 * Call i_ddi_umem_unlock_thread_start if necessary.  It will
	 * be called on first ddi_umem_lock or umem_lockmemory call.
	 */
	if (ddi_umem_unlock_thread == NULL)
		i_ddi_umem_unlock_thread_start();

	/* Allocate memory for the cookie */
	p = kmem_zalloc(sizeof (struct ddi_umem_cookie), KM_SLEEP);

	/* Convert the flags to seg_rw type */
	if (flags & DDI_UMEMLOCK_WRITE) {
		p->s_flags = S_WRITE;
	} else {
		p->s_flags = S_READ;
	}

	/* Store procp in cookie for later iosetup/unlock */
	p->procp = (void *)procp;

	/*
	 * Store the struct as pointer in cookie for later use by
	 * ddi_umem_unlock.  The proc->p_as will be stale if ddi_umem_unlock
	 * is called after relvm is called.
	 */
	p->asp = as;

	/*
	 * The size field is needed for lockmem accounting.
	 */
	p->size = len;
	init_lockedmem_rctl_flag(p);

	if (umem_incr_devlockmem(p) != 0) {
		/*
		 * The requested memory cannot be locked
		 */
		kmem_free(p, sizeof (struct ddi_umem_cookie));
		*cookie = (ddi_umem_cookie_t)NULL;
		return (ENOMEM);
	}

	/* Lock the pages corresponding to addr, len in memory */
	error = as_pagelock(as, &(p->pparray), addr, len, p->s_flags);
	if (error != 0) {
		umem_decr_devlockmem(p);
		kmem_free(p, sizeof (struct ddi_umem_cookie));
		*cookie = (ddi_umem_cookie_t)NULL;
		return (error);
	}

	/*
	 * For longterm locking the addr must pertain to a seg_vn segment or
	 * or a seg_spt segment.
	 * If the segment pertains to a regular file, it cannot be
	 * mapped MAP_SHARED.
	 * This is to prevent a deadlock if a file truncation is attempted
	 * after the locking is done.
	 * Doing this after as_pagelock guarantees persistence of the as; if
	 * an unacceptable segment is found, the cleanup includes calling
	 * as_pageunlock before returning EFAULT.
	 *
	 * segdev is allowed here as it is already locked.  This allows
	 * for memory exported by drivers through mmap() (which is already
	 * locked) to be allowed for LONGTERM.
	 */
	if (flags & DDI_UMEMLOCK_LONGTERM) {
		extern  struct seg_ops segspt_shmops;
		extern	struct seg_ops segdev_ops;
		AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
		for (seg = as_segat(as, addr); ; seg = AS_SEGNEXT(as, seg)) {
			if (seg == NULL || seg->s_base > addr + len)
				break;
			if (seg->s_ops == &segdev_ops)
				continue;
			if (((seg->s_ops != &segvn_ops) &&
			    (seg->s_ops != &segspt_shmops)) ||
			    ((SEGOP_GETVP(seg, addr, &vp) == 0 &&
			    vp != NULL && vp->v_type == VREG) &&
			    (SEGOP_GETTYPE(seg, addr) & MAP_SHARED))) {
				as_pageunlock(as, p->pparray,
				    addr, len, p->s_flags);
				AS_LOCK_EXIT(as, &as->a_lock);
				umem_decr_devlockmem(p);
				kmem_free(p, sizeof (struct ddi_umem_cookie));
				*cookie = (ddi_umem_cookie_t)NULL;
				return (EFAULT);
			}
		}
		AS_LOCK_EXIT(as, &as->a_lock);
	}


	/* Initialize the fields in the ddi_umem_cookie */
	p->cvaddr = addr;
	p->type = UMEM_LOCKED;
	if (driver_callback != NULL) {
		/* i_ddi_umem_unlock and umem_lock_undo may need the cookie */
		p->cook_refcnt = 2;
		p->callbacks = *ops_vector;
	} else {
		/* only i_ddi_umme_unlock needs the cookie */
		p->cook_refcnt = 1;
	}

	*cookie = (ddi_umem_cookie_t)p;

	/*
	 * If a driver callback was specified, add an entry to the
	 * as struct callback list. The as_pagelock above guarantees
	 * the persistence of as.
	 */
	if (driver_callback) {
		error = as_add_callback(as, umem_lock_undo, p, AS_ALL_EVENT,
		    addr, len, KM_SLEEP);
		if (error != 0) {
			as_pageunlock(as, p->pparray,
			    addr, len, p->s_flags);
			umem_decr_devlockmem(p);
			kmem_free(p, sizeof (struct ddi_umem_cookie));
			*cookie = (ddi_umem_cookie_t)NULL;
		}
	}
	return (error);
}

/*
 * Unlock the pages locked by ddi_umem_lock or umem_lockmemory and free
 * the cookie.  Called from i_ddi_umem_unlock_thread.
 */

static void
i_ddi_umem_unlock(struct ddi_umem_cookie *p)
{
	uint_t	rc;

	/*
	 * There is no way to determine whether a callback to
	 * umem_lock_undo was registered via as_add_callback.
	 * (i.e. umem_lockmemory was called with DDI_MEMLOCK_LONGTERM and
	 * a valid callback function structure.)  as_delete_callback
	 * is called to delete a possible registered callback.  If the
	 * return from as_delete_callbacks is AS_CALLBACK_DELETED, it
	 * indicates that there was a callback registered, and that is was
	 * successfully deleted.  Thus, the cookie reference count
	 * will never be decremented by umem_lock_undo.  Just return the
	 * memory for the cookie, since both users of the cookie are done.
	 * A return of AS_CALLBACK_NOTFOUND indicates a callback was
	 * never registered.  A return of AS_CALLBACK_DELETE_DEFERRED
	 * indicates that callback processing is taking place and, and
	 * umem_lock_undo is, or will be, executing, and thus decrementing
	 * the cookie reference count when it is complete.
	 *
	 * This needs to be done before as_pageunlock so that the
	 * persistence of as is guaranteed because of the locked pages.
	 *
	 */
	rc = as_delete_callback(p->asp, p);


	/*
	 * The proc->p_as will be stale if i_ddi_umem_unlock is called
	 * after relvm is called so use p->asp.
	 */
	as_pageunlock(p->asp, p->pparray, p->cvaddr, p->size, p->s_flags);

	/*
	 * Now that we have unlocked the memory decrement the
	 * *.max-locked-memory rctl
	 */
	umem_decr_devlockmem(p);

	if (rc == AS_CALLBACK_DELETED) {
		/* umem_lock_undo will not happen, return the cookie memory */
		ASSERT(p->cook_refcnt == 2);
		kmem_free(p, sizeof (struct ddi_umem_cookie));
	} else {
		/*
		 * umem_undo_lock may happen if as_delete_callback returned
		 * AS_CALLBACK_DELETE_DEFERRED.  In that case, decrement the
		 * reference count, atomically, and return the cookie
		 * memory if the reference count goes to zero.  The only
		 * other value for rc is AS_CALLBACK_NOTFOUND.  In that
		 * case, just return the cookie memory.
		 */
		if ((rc != AS_CALLBACK_DELETE_DEFERRED) ||
		    (atomic_add_long_nv((ulong_t *)(&(p->cook_refcnt)), -1)
		    == 0)) {
			kmem_free(p, sizeof (struct ddi_umem_cookie));
		}
	}
}

/*
 * i_ddi_umem_unlock_thread - deferred ddi_umem_unlock list handler.
 *
 * Call i_ddi_umem_unlock for entries in the ddi_umem_unlock list
 * until it is empty.  Then, wait for more to be added.  This thread is awoken
 * via calls to ddi_umem_unlock.
 */

static void
i_ddi_umem_unlock_thread(void)
{
	struct ddi_umem_cookie	*ret_cookie;
	callb_cpr_t	cprinfo;

	/* process the ddi_umem_unlock list */
	CALLB_CPR_INIT(&cprinfo, &ddi_umem_unlock_mutex,
	    callb_generic_cpr, "unlock_thread");
	for (;;) {
		mutex_enter(&ddi_umem_unlock_mutex);
		if (ddi_umem_unlock_head != NULL) {	/* list not empty */
			ret_cookie = ddi_umem_unlock_head;
			/* take if off the list */
			if ((ddi_umem_unlock_head =
			    ddi_umem_unlock_head->unl_forw) == NULL) {
				ddi_umem_unlock_tail = NULL;
			}
			mutex_exit(&ddi_umem_unlock_mutex);
			/* unlock the pages in this cookie */
			(void) i_ddi_umem_unlock(ret_cookie);
		} else {   /* list is empty, wait for next ddi_umem_unlock */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&ddi_umem_unlock_cv, &ddi_umem_unlock_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &ddi_umem_unlock_mutex);
			mutex_exit(&ddi_umem_unlock_mutex);
		}
	}
	/* ddi_umem_unlock_thread does not exit */
	/* NOTREACHED */
}

/*
 * Start the thread that will process the ddi_umem_unlock list if it is
 * not already started (i_ddi_umem_unlock_thread).
 */
static void
i_ddi_umem_unlock_thread_start(void)
{
	mutex_enter(&ddi_umem_unlock_mutex);
	if (ddi_umem_unlock_thread == NULL) {
		ddi_umem_unlock_thread = thread_create(NULL, 0,
		    i_ddi_umem_unlock_thread, NULL, 0, &p0,
		    TS_RUN, minclsyspri);
	}
	mutex_exit(&ddi_umem_unlock_mutex);
}

/*
 * Lock the virtual address range in the current process and create a
 * ddi_umem_cookie (of type UMEM_LOCKED). This can be used to pass to
 * ddi_umem_iosetup to create a buf or do devmap_umem_setup/remap to export
 * to user space.
 *
 * Note: The resource control accounting currently uses a full charge model
 * in other words attempts to lock the same/overlapping areas of memory
 * will deduct the full size of the buffer from the projects running
 * counter for the device locked memory. This applies to umem_lockmemory too.
 *
 * addr, size should be PAGESIZE aligned
 * flags - DDI_UMEMLOCK_READ, DDI_UMEMLOCK_WRITE or both
 *	identifies whether the locked memory will be read or written or both
 *
 * Returns 0 on success
 *	EINVAL - for invalid parameters
 *	EPERM, ENOMEM and other error codes returned by as_pagelock
 *	ENOMEM - is returned if the current request to lock memory exceeds
 *		*.max-locked-memory resource control value.
 *	EAGAIN - could not start the ddi_umem_unlock list processing thread
 */
int
ddi_umem_lock(caddr_t addr, size_t len, int flags, ddi_umem_cookie_t *cookie)
{
	int	error;
	struct ddi_umem_cookie *p;

	*cookie = NULL;		/* in case of any error return */

	/* These are the only two valid flags */
	if ((flags & ~(DDI_UMEMLOCK_READ | DDI_UMEMLOCK_WRITE)) != 0) {
		return (EINVAL);
	}

	/* At least one of the two flags (or both) must be set */
	if ((flags & (DDI_UMEMLOCK_READ | DDI_UMEMLOCK_WRITE)) == 0) {
		return (EINVAL);
	}

	/* addr and len must be page-aligned */
	if (((uintptr_t)addr & PAGEOFFSET) != 0) {
		return (EINVAL);
	}

	if ((len & PAGEOFFSET) != 0) {
		return (EINVAL);
	}

	/*
	 * Call i_ddi_umem_unlock_thread_start if necessary.  It will
	 * be called on first ddi_umem_lock or umem_lockmemory call.
	 */
	if (ddi_umem_unlock_thread == NULL)
		i_ddi_umem_unlock_thread_start();

	/* Allocate memory for the cookie */
	p = kmem_zalloc(sizeof (struct ddi_umem_cookie), KM_SLEEP);

	/* Convert the flags to seg_rw type */
	if (flags & DDI_UMEMLOCK_WRITE) {
		p->s_flags = S_WRITE;
	} else {
		p->s_flags = S_READ;
	}

	/* Store curproc in cookie for later iosetup/unlock */
	p->procp = (void *)curproc;

	/*
	 * Store the struct as pointer in cookie for later use by
	 * ddi_umem_unlock.  The proc->p_as will be stale if ddi_umem_unlock
	 * is called after relvm is called.
	 */
	p->asp = curproc->p_as;
	/*
	 * The size field is needed for lockmem accounting.
	 */
	p->size = len;
	init_lockedmem_rctl_flag(p);

	if (umem_incr_devlockmem(p) != 0) {
		/*
		 * The requested memory cannot be locked
		 */
		kmem_free(p, sizeof (struct ddi_umem_cookie));
		*cookie = (ddi_umem_cookie_t)NULL;
		return (ENOMEM);
	}

	/* Lock the pages corresponding to addr, len in memory */
	error = as_pagelock(((proc_t *)p->procp)->p_as, &(p->pparray),
	    addr, len, p->s_flags);
	if (error != 0) {
		umem_decr_devlockmem(p);
		kmem_free(p, sizeof (struct ddi_umem_cookie));
		*cookie = (ddi_umem_cookie_t)NULL;
		return (error);
	}

	/* Initialize the fields in the ddi_umem_cookie */
	p->cvaddr = addr;
	p->type = UMEM_LOCKED;
	p->cook_refcnt = 1;

	*cookie = (ddi_umem_cookie_t)p;
	return (error);
}

/*
 * Add the cookie to the ddi_umem_unlock list.  Pages will be
 * unlocked by i_ddi_umem_unlock_thread.
 */

void
ddi_umem_unlock(ddi_umem_cookie_t cookie)
{
	struct ddi_umem_cookie	*p = (struct ddi_umem_cookie *)cookie;

	ASSERT(p->type == UMEM_LOCKED);
	ASSERT(CPU_ON_INTR(CPU) == 0); /* cannot be high level */
	ASSERT(ddi_umem_unlock_thread != NULL);

	p->unl_forw = (struct ddi_umem_cookie *)NULL;	/* end of list */
	/*
	 * Queue the unlock request and notify i_ddi_umem_unlock thread
	 * if it's called in the interrupt context. Otherwise, unlock pages
	 * immediately.
	 */
	if (servicing_interrupt()) {
		/* queue the unlock request and notify the thread */
		mutex_enter(&ddi_umem_unlock_mutex);
		if (ddi_umem_unlock_head == NULL) {
			ddi_umem_unlock_head = ddi_umem_unlock_tail = p;
			cv_broadcast(&ddi_umem_unlock_cv);
		} else {
			ddi_umem_unlock_tail->unl_forw = p;
			ddi_umem_unlock_tail = p;
		}
		mutex_exit(&ddi_umem_unlock_mutex);
	} else {
		/* unlock the pages right away */
		(void) i_ddi_umem_unlock(p);
	}
}

/*
 * Create a buf structure from a ddi_umem_cookie
 * cookie - is a ddi_umem_cookie for from ddi_umem_lock and ddi_umem_alloc
 *		(only UMEM_LOCKED & KMEM_NON_PAGEABLE types supported)
 * off, len - identifies the portion of the memory represented by the cookie
 *		that the buf points to.
 *	NOTE: off, len need to follow the alignment/size restrictions of the
 *		device (dev) that this buf will be passed to. Some devices
 *		will accept unrestricted alignment/size, whereas others (such as
 *		st) require some block-size alignment/size. It is the caller's
 *		responsibility to ensure that the alignment/size restrictions
 *		are met (we cannot assert as we do not know the restrictions)
 *
 * direction - is one of B_READ or B_WRITE and needs to be compatible with
 *		the flags used in ddi_umem_lock
 *
 * The following three arguments are used to initialize fields in the
 * buf structure and are uninterpreted by this routine.
 *
 * dev
 * blkno
 * iodone
 *
 * sleepflag - is one of DDI_UMEM_SLEEP or DDI_UMEM_NOSLEEP
 *
 * Returns a buf structure pointer on success (to be freed by freerbuf)
 *	NULL on any parameter error or memory alloc failure
 *
 */
struct buf *
ddi_umem_iosetup(ddi_umem_cookie_t cookie, off_t off, size_t len,
	int direction, dev_t dev, daddr_t blkno,
	int (*iodone)(struct buf *), int sleepflag)
{
	struct ddi_umem_cookie *p = (struct ddi_umem_cookie *)cookie;
	struct buf *bp;

	/*
	 * check for valid cookie offset, len
	 */
	if ((off + len) > p->size) {
		return (NULL);
	}

	if (len > p->size) {
		return (NULL);
	}

	/* direction has to be one of B_READ or B_WRITE */
	if ((direction != B_READ) && (direction != B_WRITE)) {
		return (NULL);
	}

	/* These are the only two valid sleepflags */
	if ((sleepflag != DDI_UMEM_SLEEP) && (sleepflag != DDI_UMEM_NOSLEEP)) {
		return (NULL);
	}

	/*
	 * Only cookies of type UMEM_LOCKED and KMEM_NON_PAGEABLE are supported
	 */
	if ((p->type != UMEM_LOCKED) && (p->type != KMEM_NON_PAGEABLE)) {
		return (NULL);
	}

	/* If type is KMEM_NON_PAGEABLE procp is NULL */
	ASSERT((p->type == KMEM_NON_PAGEABLE) ?
	    (p->procp == NULL) : (p->procp != NULL));

	bp = kmem_alloc(sizeof (struct buf), sleepflag);
	if (bp == NULL) {
		return (NULL);
	}
	bioinit(bp);

	bp->b_flags = B_BUSY | B_PHYS | direction;
	bp->b_edev = dev;
	bp->b_lblkno = blkno;
	bp->b_iodone = iodone;
	bp->b_bcount = len;
	bp->b_proc = (proc_t *)p->procp;
	ASSERT(((uintptr_t)(p->cvaddr) & PAGEOFFSET) == 0);
	bp->b_un.b_addr = (caddr_t)((uintptr_t)(p->cvaddr) + off);
	if (p->pparray != NULL) {
		bp->b_flags |= B_SHADOW;
		ASSERT(((uintptr_t)(p->cvaddr) & PAGEOFFSET) == 0);
		bp->b_shadow = p->pparray + btop(off);
	}
	return (bp);
}

/*
 * Fault-handling and related routines
 */

ddi_devstate_t
ddi_get_devstate(dev_info_t *dip)
{
	if (DEVI_IS_DEVICE_OFFLINE(dip))
		return (DDI_DEVSTATE_OFFLINE);
	else if (DEVI_IS_DEVICE_DOWN(dip) || DEVI_IS_BUS_DOWN(dip))
		return (DDI_DEVSTATE_DOWN);
	else if (DEVI_IS_BUS_QUIESCED(dip))
		return (DDI_DEVSTATE_QUIESCED);
	else if (DEVI_IS_DEVICE_DEGRADED(dip))
		return (DDI_DEVSTATE_DEGRADED);
	else
		return (DDI_DEVSTATE_UP);
}

void
ddi_dev_report_fault(dev_info_t *dip, ddi_fault_impact_t impact,
	ddi_fault_location_t location, const char *message)
{
	struct ddi_fault_event_data fd;
	ddi_eventcookie_t ec;

	/*
	 * Assemble all the information into a fault-event-data structure
	 */
	fd.f_dip = dip;
	fd.f_impact = impact;
	fd.f_location = location;
	fd.f_message = message;
	fd.f_oldstate = ddi_get_devstate(dip);

	/*
	 * Get eventcookie from defining parent.
	 */
	if (ddi_get_eventcookie(dip, DDI_DEVI_FAULT_EVENT, &ec) !=
	    DDI_SUCCESS)
		return;

	(void) ndi_post_event(dip, dip, ec, &fd);
}

char *
i_ddi_devi_class(dev_info_t *dip)
{
	return (DEVI(dip)->devi_device_class);
}

int
i_ddi_set_devi_class(dev_info_t *dip, char *devi_class, int flag)
{
	struct dev_info *devi = DEVI(dip);

	mutex_enter(&devi->devi_lock);

	if (devi->devi_device_class)
		kmem_free(devi->devi_device_class,
		    strlen(devi->devi_device_class) + 1);

	if ((devi->devi_device_class = i_ddi_strdup(devi_class, flag))
	    != NULL) {
		mutex_exit(&devi->devi_lock);
		return (DDI_SUCCESS);
	}

	mutex_exit(&devi->devi_lock);

	return (DDI_FAILURE);
}


/*
 * Task Queues DDI interfaces.
 */

/* ARGSUSED */
ddi_taskq_t *
ddi_taskq_create(dev_info_t *dip, const char *name, int nthreads,
    pri_t pri, uint_t cflags)
{
	char full_name[TASKQ_NAMELEN];
	const char *tq_name;
	int nodeid = 0;

	if (dip == NULL)
		tq_name = name;
	else {
		nodeid = ddi_get_instance(dip);

		if (name == NULL)
			name = "tq";

		(void) snprintf(full_name, sizeof (full_name), "%s_%s",
		    ddi_driver_name(dip), name);

		tq_name = full_name;
	}

	return ((ddi_taskq_t *)taskq_create_instance(tq_name, nodeid, nthreads,
	    pri == TASKQ_DEFAULTPRI ? minclsyspri : pri,
	    nthreads, INT_MAX, TASKQ_PREPOPULATE));
}

void
ddi_taskq_destroy(ddi_taskq_t *tq)
{
	taskq_destroy((taskq_t *)tq);
}

int
ddi_taskq_dispatch(ddi_taskq_t *tq, void (* func)(void *),
    void *arg, uint_t dflags)
{
	taskqid_t id = taskq_dispatch((taskq_t *)tq, func, arg,
	    dflags == DDI_SLEEP ? TQ_SLEEP : TQ_NOSLEEP);

	return (id != 0 ? DDI_SUCCESS : DDI_FAILURE);
}

void
ddi_taskq_wait(ddi_taskq_t *tq)
{
	taskq_wait((taskq_t *)tq);
}

void
ddi_taskq_suspend(ddi_taskq_t *tq)
{
	taskq_suspend((taskq_t *)tq);
}

boolean_t
ddi_taskq_suspended(ddi_taskq_t *tq)
{
	return (taskq_suspended((taskq_t *)tq));
}

void
ddi_taskq_resume(ddi_taskq_t *tq)
{
	taskq_resume((taskq_t *)tq);
}

int
ddi_parse(
	const char	*ifname,
	char		*alnum,
	uint_t		*nump)
{
	const char	*p;
	int		l;
	ulong_t		num;
	boolean_t	nonum = B_TRUE;
	char		c;

	l = strlen(ifname);
	for (p = ifname + l; p != ifname; l--) {
		c = *--p;
		if (!isdigit(c)) {
			(void) strlcpy(alnum, ifname, l + 1);
			if (ddi_strtoul(p + 1, NULL, 10, &num) != 0)
				return (DDI_FAILURE);
			break;
		}
		nonum = B_FALSE;
	}
	if (l == 0 || nonum)
		return (DDI_FAILURE);

	*nump = num;
	return (DDI_SUCCESS);
}

/*
 * Default initialization function for drivers that don't need to quiesce.
 */
/* ARGSUSED */
int
ddi_quiesce_not_needed(dev_info_t *dip)
{
	return (DDI_SUCCESS);
}

/*
 * Initialization function for drivers that should implement quiesce()
 * but haven't yet.
 */
/* ARGSUSED */
int
ddi_quiesce_not_supported(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

char *
ddi_strdup(const char *str, int flag)
{
	int	n;
	char	*ptr;

	ASSERT(str != NULL);
	ASSERT((flag == KM_SLEEP) || (flag == KM_NOSLEEP));

	n = strlen(str);
	if ((ptr = kmem_alloc(n + 1, flag)) == NULL)
		return (NULL);
	bcopy(str, ptr, n + 1);
	return (ptr);
}

char *
strdup(const char *str)
{
	return (ddi_strdup(str, KM_SLEEP));
}

void
strfree(char *str)
{
	ASSERT(str != NULL);
	kmem_free(str, strlen(str) + 1);
}

/*
 * Generic DDI callback interfaces.
 */

int
ddi_cb_register(dev_info_t *dip, ddi_cb_flags_t flags, ddi_cb_func_t cbfunc,
    void *arg1, void *arg2, ddi_cb_handle_t *ret_hdlp)
{
	ddi_cb_t	*cbp;

	ASSERT(dip != NULL);
	ASSERT(DDI_CB_FLAG_VALID(flags));
	ASSERT(cbfunc != NULL);
	ASSERT(ret_hdlp != NULL);

	/* Sanity check the context */
	ASSERT(!servicing_interrupt());
	if (servicing_interrupt())
		return (DDI_FAILURE);

	/* Validate parameters */
	if ((dip == NULL) || !DDI_CB_FLAG_VALID(flags) ||
	    (cbfunc == NULL) || (ret_hdlp == NULL))
		return (DDI_EINVAL);

	/* Check for previous registration */
	if (DEVI(dip)->devi_cb_p != NULL)
		return (DDI_EALREADY);

	/* Allocate and initialize callback */
	cbp = kmem_zalloc(sizeof (ddi_cb_t), KM_SLEEP);
	cbp->cb_dip = dip;
	cbp->cb_func = cbfunc;
	cbp->cb_arg1 = arg1;
	cbp->cb_arg2 = arg2;
	cbp->cb_flags = flags;
	DEVI(dip)->devi_cb_p = cbp;

	/* If adding an IRM callback, notify IRM */
	if (flags & DDI_CB_FLAG_INTR)
		i_ddi_irm_set_cb(dip, B_TRUE);

	*ret_hdlp = (ddi_cb_handle_t)&(DEVI(dip)->devi_cb_p);
	return (DDI_SUCCESS);
}

int
ddi_cb_unregister(ddi_cb_handle_t hdl)
{
	ddi_cb_t	*cbp;
	dev_info_t	*dip;

	ASSERT(hdl != NULL);

	/* Sanity check the context */
	ASSERT(!servicing_interrupt());
	if (servicing_interrupt())
		return (DDI_FAILURE);

	/* Validate parameters */
	if ((hdl == NULL) || ((cbp = *(ddi_cb_t **)hdl) == NULL) ||
	    ((dip = cbp->cb_dip) == NULL))
		return (DDI_EINVAL);

	/* If removing an IRM callback, notify IRM */
	if (cbp->cb_flags & DDI_CB_FLAG_INTR)
		i_ddi_irm_set_cb(dip, B_FALSE);

	/* Destroy the callback */
	kmem_free(cbp, sizeof (ddi_cb_t));
	DEVI(dip)->devi_cb_p = NULL;

	return (DDI_SUCCESS);
}

/*
 * Platform independent DR routines
 */

static int
ndi2errno(int n)
{
	int err = 0;

	switch (n) {
		case NDI_NOMEM:
			err = ENOMEM;
			break;
		case NDI_BUSY:
			err = EBUSY;
			break;
		case NDI_FAULT:
			err = EFAULT;
			break;
		case NDI_FAILURE:
			err = EIO;
			break;
		case NDI_SUCCESS:
			break;
		case NDI_BADHANDLE:
		default:
			err = EINVAL;
			break;
	}
	return (err);
}

/*
 * Prom tree node list
 */
struct ptnode {
	pnode_t		nodeid;
	struct ptnode	*next;
};

/*
 * Prom tree walk arg
 */
struct pta {
	dev_info_t	*pdip;
	devi_branch_t	*bp;
	uint_t		flags;
	dev_info_t	*fdip;
	struct ptnode	*head;
};

static void
visit_node(pnode_t nodeid, struct pta *ap)
{
	struct ptnode	**nextp;
	int		(*select)(pnode_t, void *, uint_t);

	ASSERT(nodeid != OBP_NONODE && nodeid != OBP_BADNODE);

	select = ap->bp->create.prom_branch_select;

	ASSERT(select);

	if (select(nodeid, ap->bp->arg, 0) == DDI_SUCCESS) {

		for (nextp = &ap->head; *nextp; nextp = &(*nextp)->next)
			;

		*nextp = kmem_zalloc(sizeof (struct ptnode), KM_SLEEP);

		(*nextp)->nodeid = nodeid;
	}

	if ((ap->flags & DEVI_BRANCH_CHILD) == DEVI_BRANCH_CHILD)
		return;

	nodeid = prom_childnode(nodeid);
	while (nodeid != OBP_NONODE && nodeid != OBP_BADNODE) {
		visit_node(nodeid, ap);
		nodeid = prom_nextnode(nodeid);
	}
}

/*
 * NOTE: The caller of this function must check for device contracts
 * or LDI callbacks against this dip before setting the dip offline.
 */
static int
set_infant_dip_offline(dev_info_t *dip, void *arg)
{
	char	*path = (char *)arg;

	ASSERT(dip);
	ASSERT(arg);

	if (i_ddi_node_state(dip) >= DS_ATTACHED) {
		(void) ddi_pathname(dip, path);
		cmn_err(CE_WARN, "Attempt to set offline flag on attached "
		    "node: %s", path);
		return (DDI_FAILURE);
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (!DEVI_IS_DEVICE_OFFLINE(dip))
		DEVI_SET_DEVICE_OFFLINE(dip);
	mutex_exit(&(DEVI(dip)->devi_lock));

	return (DDI_SUCCESS);
}

typedef struct result {
	char	*path;
	int	result;
} result_t;

static int
dip_set_offline(dev_info_t *dip, void *arg)
{
	int end;
	result_t *resp = (result_t *)arg;

	ASSERT(dip);
	ASSERT(resp);

	/*
	 * We stop the walk if e_ddi_offline_notify() returns
	 * failure, because this implies that one or more consumers
	 * (either LDI or contract based) has blocked the offline.
	 * So there is no point in conitnuing the walk
	 */
	if (e_ddi_offline_notify(dip) == DDI_FAILURE) {
		resp->result = DDI_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * If set_infant_dip_offline() returns failure, it implies
	 * that we failed to set a particular dip offline. This
	 * does not imply that the offline as a whole should fail.
	 * We want to do the best we can, so we continue the walk.
	 */
	if (set_infant_dip_offline(dip, resp->path) == DDI_SUCCESS)
		end = DDI_SUCCESS;
	else
		end = DDI_FAILURE;

	e_ddi_offline_finalize(dip, end);

	return (DDI_WALK_CONTINUE);
}

/*
 * The call to e_ddi_offline_notify() exists for the
 * unlikely error case that a branch we are trying to
 * create already exists and has device contracts or LDI
 * event callbacks against it.
 *
 * We allow create to succeed for such branches only if
 * no constraints block the offline.
 */
static int
branch_set_offline(dev_info_t *dip, char *path)
{
	int		circ;
	int		end;
	result_t	res;


	if (e_ddi_offline_notify(dip) == DDI_FAILURE) {
		return (DDI_FAILURE);
	}

	if (set_infant_dip_offline(dip, path) == DDI_SUCCESS)
		end = DDI_SUCCESS;
	else
		end = DDI_FAILURE;

	e_ddi_offline_finalize(dip, end);

	if (end == DDI_FAILURE)
		return (DDI_FAILURE);

	res.result = DDI_SUCCESS;
	res.path = path;

	ndi_devi_enter(dip, &circ);
	ddi_walk_devs(ddi_get_child(dip), dip_set_offline, &res);
	ndi_devi_exit(dip, circ);

	return (res.result);
}

/*ARGSUSED*/
static int
create_prom_branch(void *arg, int has_changed)
{
	int		circ;
	int		exists, rv;
	pnode_t		nodeid;
	struct ptnode	*tnp;
	dev_info_t	*dip;
	struct pta	*ap = arg;
	devi_branch_t	*bp;
	char		*path;

	ASSERT(ap);
	ASSERT(ap->fdip == NULL);
	ASSERT(ap->pdip && ndi_dev_is_prom_node(ap->pdip));

	bp = ap->bp;

	nodeid = ddi_get_nodeid(ap->pdip);
	if (nodeid == OBP_NONODE || nodeid == OBP_BADNODE) {
		cmn_err(CE_WARN, "create_prom_branch: invalid "
		    "nodeid: 0x%x", nodeid);
		return (EINVAL);
	}

	ap->head = NULL;

	nodeid = prom_childnode(nodeid);
	while (nodeid != OBP_NONODE && nodeid != OBP_BADNODE) {
		visit_node(nodeid, ap);
		nodeid = prom_nextnode(nodeid);
	}

	if (ap->head == NULL)
		return (ENODEV);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	rv = 0;
	while ((tnp = ap->head) != NULL) {
		ap->head = tnp->next;

		ndi_devi_enter(ap->pdip, &circ);

		/*
		 * Check if the branch already exists.
		 */
		exists = 0;
		dip = e_ddi_nodeid_to_dip(tnp->nodeid);
		if (dip != NULL) {
			exists = 1;

			/* Parent is held busy, so release hold */
			ndi_rele_devi(dip);
#ifdef	DEBUG
			cmn_err(CE_WARN, "create_prom_branch: dip(%p) exists"
			    " for nodeid 0x%x", (void *)dip, tnp->nodeid);
#endif
		} else {
			dip = i_ddi_create_branch(ap->pdip, tnp->nodeid);
		}

		kmem_free(tnp, sizeof (struct ptnode));

		/*
		 * Hold the branch if it is not already held
		 */
		if (dip && !exists) {
			e_ddi_branch_hold(dip);
		}

		ASSERT(dip == NULL || e_ddi_branch_held(dip));

		/*
		 * Set all dips in the newly created branch offline so that
		 * only a "configure" operation can attach
		 * the branch
		 */
		if (dip == NULL || branch_set_offline(dip, path)
		    == DDI_FAILURE) {
			ndi_devi_exit(ap->pdip, circ);
			rv = EIO;
			continue;
		}

		ASSERT(ddi_get_parent(dip) == ap->pdip);

		ndi_devi_exit(ap->pdip, circ);

		if (ap->flags & DEVI_BRANCH_CONFIGURE) {
			int error = e_ddi_branch_configure(dip, &ap->fdip, 0);
			if (error && rv == 0)
				rv = error;
		}

		/*
		 * Invoke devi_branch_callback() (if it exists) only for
		 * newly created branches
		 */
		if (bp->devi_branch_callback && !exists)
			bp->devi_branch_callback(dip, bp->arg, 0);
	}

	kmem_free(path, MAXPATHLEN);

	return (rv);
}

static int
sid_node_create(dev_info_t *pdip, devi_branch_t *bp, dev_info_t **rdipp)
{
	int			rv, circ, len;
	int			i, flags, ret;
	dev_info_t		*dip;
	char			*nbuf;
	char			*path;
	static const char	*noname = "<none>";

	ASSERT(pdip);
	ASSERT(DEVI_BUSY_OWNED(pdip));

	flags = 0;

	/*
	 * Creating the root of a branch ?
	 */
	if (rdipp) {
		*rdipp = NULL;
		flags = DEVI_BRANCH_ROOT;
	}

	ndi_devi_alloc_sleep(pdip, (char *)noname, DEVI_SID_NODEID, &dip);
	rv = bp->create.sid_branch_create(dip, bp->arg, flags);

	nbuf = kmem_alloc(OBP_MAXDRVNAME, KM_SLEEP);

	if (rv == DDI_WALK_ERROR) {
		cmn_err(CE_WARN, "e_ddi_branch_create: Error setting"
		    " properties on devinfo node %p",  (void *)dip);
		goto fail;
	}

	len = OBP_MAXDRVNAME;
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, "name", nbuf, &len)
	    != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "e_ddi_branch_create: devinfo node %p has"
		    "no name property", (void *)dip);
		goto fail;
	}

	ASSERT(i_ddi_node_state(dip) == DS_PROTO);
	if (ndi_devi_set_nodename(dip, nbuf, 0) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "e_ddi_branch_create: cannot set name (%s)"
		    " for devinfo node %p", nbuf, (void *)dip);
		goto fail;
	}

	kmem_free(nbuf, OBP_MAXDRVNAME);

	/*
	 * Ignore bind failures just like boot does
	 */
	(void) ndi_devi_bind_driver(dip, 0);

	switch (rv) {
	case DDI_WALK_CONTINUE:
	case DDI_WALK_PRUNESIB:
		ndi_devi_enter(dip, &circ);

		i = DDI_WALK_CONTINUE;
		for (; i == DDI_WALK_CONTINUE; ) {
			i = sid_node_create(dip, bp, NULL);
		}

		ASSERT(i == DDI_WALK_ERROR || i == DDI_WALK_PRUNESIB);
		if (i == DDI_WALK_ERROR)
			rv = i;
		/*
		 * If PRUNESIB stop creating siblings
		 * of dip's child. Subsequent walk behavior
		 * is determined by rv returned by dip.
		 */

		ndi_devi_exit(dip, circ);
		break;
	case DDI_WALK_TERMINATE:
		/*
		 * Don't create children and ask our parent
		 * to not create siblings either.
		 */
		rv = DDI_WALK_PRUNESIB;
		break;
	case DDI_WALK_PRUNECHILD:
		/*
		 * Don't create children, but ask parent to continue
		 * with siblings.
		 */
		rv = DDI_WALK_CONTINUE;
		break;
	default:
		ASSERT(0);
		break;
	}

	if (rdipp)
		*rdipp = dip;

	/*
	 * Set device offline - only the "configure" op should cause an attach.
	 * Note that it is safe to set the dip offline without checking
	 * for either device contract or layered driver (LDI) based constraints
	 * since there cannot be any contracts or LDI opens of this device.
	 * This is because this node is a newly created dip with the parent busy
	 * held, so no other thread can come in and attach this dip. A dip that
	 * has never been attached cannot have contracts since by definition
	 * a device contract (an agreement between a process and a device minor
	 * node) can only be created against a device that has minor nodes
	 * i.e is attached. Similarly an LDI open will only succeed if the
	 * dip is attached. We assert below that the dip is not attached.
	 */
	ASSERT(i_ddi_node_state(dip) < DS_ATTACHED);
	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	ret = set_infant_dip_offline(dip, path);
	ASSERT(ret == DDI_SUCCESS);
	kmem_free(path, MAXPATHLEN);

	return (rv);
fail:
	(void) ndi_devi_free(dip);
	kmem_free(nbuf, OBP_MAXDRVNAME);
	return (DDI_WALK_ERROR);
}

static int
create_sid_branch(
	dev_info_t	*pdip,
	devi_branch_t	*bp,
	dev_info_t	**dipp,
	uint_t		flags)
{
	int		rv = 0, state = DDI_WALK_CONTINUE;
	dev_info_t	*rdip;

	while (state == DDI_WALK_CONTINUE) {
		int	circ;

		ndi_devi_enter(pdip, &circ);

		state = sid_node_create(pdip, bp, &rdip);
		if (rdip == NULL) {
			ndi_devi_exit(pdip, circ);
			ASSERT(state == DDI_WALK_ERROR);
			break;
		}

		e_ddi_branch_hold(rdip);

		ndi_devi_exit(pdip, circ);

		if (flags & DEVI_BRANCH_CONFIGURE) {
			int error = e_ddi_branch_configure(rdip, dipp, 0);
			if (error && rv == 0)
				rv = error;
		}

		/*
		 * devi_branch_callback() is optional
		 */
		if (bp->devi_branch_callback)
			bp->devi_branch_callback(rdip, bp->arg, 0);
	}

	ASSERT(state == DDI_WALK_ERROR || state == DDI_WALK_PRUNESIB);

	return (state == DDI_WALK_ERROR ? EIO : rv);
}

int
e_ddi_branch_create(
	dev_info_t	*pdip,
	devi_branch_t	*bp,
	dev_info_t	**dipp,
	uint_t		flags)
{
	int prom_devi, sid_devi, error;

	if (pdip == NULL || bp == NULL || bp->type == 0)
		return (EINVAL);

	prom_devi = (bp->type == DEVI_BRANCH_PROM) ? 1 : 0;
	sid_devi = (bp->type == DEVI_BRANCH_SID) ? 1 : 0;

	if (prom_devi && bp->create.prom_branch_select == NULL)
		return (EINVAL);
	else if (sid_devi && bp->create.sid_branch_create == NULL)
		return (EINVAL);
	else if (!prom_devi && !sid_devi)
		return (EINVAL);

	if (flags & DEVI_BRANCH_EVENT)
		return (EINVAL);

	if (prom_devi) {
		struct pta pta = {0};

		pta.pdip = pdip;
		pta.bp = bp;
		pta.flags = flags;

		error = prom_tree_access(create_prom_branch, &pta, NULL);

		if (dipp)
			*dipp = pta.fdip;
		else if (pta.fdip)
			ndi_rele_devi(pta.fdip);
	} else {
		error = create_sid_branch(pdip, bp, dipp, flags);
	}

	return (error);
}

int
e_ddi_branch_configure(dev_info_t *rdip, dev_info_t **dipp, uint_t flags)
{
	int		rv;
	char		*devnm;
	dev_info_t	*pdip;

	if (dipp)
		*dipp = NULL;

	if (rdip == NULL || flags != 0 || (flags & DEVI_BRANCH_EVENT))
		return (EINVAL);

	pdip = ddi_get_parent(rdip);

	ndi_hold_devi(pdip);

	if (!e_ddi_branch_held(rdip)) {
		ndi_rele_devi(pdip);
		cmn_err(CE_WARN, "e_ddi_branch_configure: "
		    "dip(%p) not held", (void *)rdip);
		return (EINVAL);
	}

	if (i_ddi_node_state(rdip) < DS_INITIALIZED) {
		/*
		 * First attempt to bind a driver. If we fail, return
		 * success (On some platforms, dips for some device
		 * types (CPUs) may not have a driver)
		 */
		if (ndi_devi_bind_driver(rdip, 0) != NDI_SUCCESS) {
			ndi_rele_devi(pdip);
			return (0);
		}

		if (ddi_initchild(pdip, rdip) != DDI_SUCCESS) {
			rv = NDI_FAILURE;
			goto out;
		}
	}

	ASSERT(i_ddi_node_state(rdip) >= DS_INITIALIZED);

	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);

	(void) ddi_deviname(rdip, devnm);

	if ((rv = ndi_devi_config_one(pdip, devnm+1, &rdip,
	    NDI_DEVI_ONLINE | NDI_CONFIG)) == NDI_SUCCESS) {
		/* release hold from ndi_devi_config_one() */
		ndi_rele_devi(rdip);
	}

	kmem_free(devnm, MAXNAMELEN + 1);
out:
	if (rv != NDI_SUCCESS && dipp && rdip) {
		ndi_hold_devi(rdip);
		*dipp = rdip;
	}
	ndi_rele_devi(pdip);
	return (ndi2errno(rv));
}

void
e_ddi_branch_hold(dev_info_t *rdip)
{
	if (e_ddi_branch_held(rdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_hold: branch already held");
		return;
	}

	mutex_enter(&DEVI(rdip)->devi_lock);
	if ((DEVI(rdip)->devi_flags & DEVI_BRANCH_HELD) == 0) {
		DEVI(rdip)->devi_flags |= DEVI_BRANCH_HELD;
		DEVI(rdip)->devi_ref++;
	}
	ASSERT(DEVI(rdip)->devi_ref > 0);
	mutex_exit(&DEVI(rdip)->devi_lock);
}

int
e_ddi_branch_held(dev_info_t *rdip)
{
	int rv = 0;

	mutex_enter(&DEVI(rdip)->devi_lock);
	if ((DEVI(rdip)->devi_flags & DEVI_BRANCH_HELD) &&
	    DEVI(rdip)->devi_ref > 0) {
		rv = 1;
	}
	mutex_exit(&DEVI(rdip)->devi_lock);

	return (rv);
}

void
e_ddi_branch_rele(dev_info_t *rdip)
{
	mutex_enter(&DEVI(rdip)->devi_lock);
	DEVI(rdip)->devi_flags &= ~DEVI_BRANCH_HELD;
	DEVI(rdip)->devi_ref--;
	mutex_exit(&DEVI(rdip)->devi_lock);
}

int
e_ddi_branch_unconfigure(
	dev_info_t *rdip,
	dev_info_t **dipp,
	uint_t flags)
{
	int	circ, rv;
	int	destroy;
	char	*devnm;
	uint_t	nflags;
	dev_info_t *pdip;

	if (dipp)
		*dipp = NULL;

	if (rdip == NULL)
		return (EINVAL);

	pdip = ddi_get_parent(rdip);

	ASSERT(pdip);

	/*
	 * Check if caller holds pdip busy - can cause deadlocks during
	 * devfs_clean()
	 */
	if (DEVI_BUSY_OWNED(pdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_unconfigure: failed: parent"
		    " devinfo node(%p) is busy held", (void *)pdip);
		return (EINVAL);
	}

	destroy = (flags & DEVI_BRANCH_DESTROY) ? 1 : 0;

	devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);

	ndi_devi_enter(pdip, &circ);
	(void) ddi_deviname(rdip, devnm);
	ndi_devi_exit(pdip, circ);

	/*
	 * ddi_deviname() returns a component name with / prepended.
	 */
	(void) devfs_clean(pdip, devnm + 1, DV_CLEAN_FORCE);

	ndi_devi_enter(pdip, &circ);

	/*
	 * Recreate device name as it may have changed state (init/uninit)
	 * when parent busy lock was dropped for devfs_clean()
	 */
	(void) ddi_deviname(rdip, devnm);

	if (!e_ddi_branch_held(rdip)) {
		kmem_free(devnm, MAXNAMELEN + 1);
		ndi_devi_exit(pdip, circ);
		cmn_err(CE_WARN, "e_ddi_%s_branch: dip(%p) not held",
		    destroy ? "destroy" : "unconfigure", (void *)rdip);
		return (EINVAL);
	}

	/*
	 * Release hold on the branch. This is ok since we are holding the
	 * parent busy. If rdip is not removed, we must do a hold on the
	 * branch before returning.
	 */
	e_ddi_branch_rele(rdip);

	nflags = NDI_DEVI_OFFLINE;
	if (destroy || (flags & DEVI_BRANCH_DESTROY)) {
		nflags |= NDI_DEVI_REMOVE;
		destroy = 1;
	} else {
		nflags |= NDI_UNCONFIG;		/* uninit but don't remove */
	}

	if (flags & DEVI_BRANCH_EVENT)
		nflags |= NDI_POST_EVENT;

	if (i_ddi_devi_attached(pdip) &&
	    (i_ddi_node_state(rdip) >= DS_INITIALIZED)) {
		rv = ndi_devi_unconfig_one(pdip, devnm+1, dipp, nflags);
	} else {
		rv = e_ddi_devi_unconfig(rdip, dipp, nflags);
		if (rv == NDI_SUCCESS) {
			ASSERT(!destroy || ddi_get_child(rdip) == NULL);
			rv = ndi_devi_offline(rdip, nflags);
		}
	}

	if (!destroy || rv != NDI_SUCCESS) {
		/* The dip still exists, so do a hold */
		e_ddi_branch_hold(rdip);
	}
out:
	kmem_free(devnm, MAXNAMELEN + 1);
	ndi_devi_exit(pdip, circ);
	return (ndi2errno(rv));
}

int
e_ddi_branch_destroy(dev_info_t *rdip, dev_info_t **dipp, uint_t flag)
{
	return (e_ddi_branch_unconfigure(rdip, dipp,
	    flag|DEVI_BRANCH_DESTROY));
}

/*
 * Number of chains for hash table
 */
#define	NUMCHAINS	17

/*
 * Devinfo busy arg
 */
struct devi_busy {
	int dv_total;
	int s_total;
	mod_hash_t *dv_hash;
	mod_hash_t *s_hash;
	int (*callback)(dev_info_t *, void *, uint_t);
	void *arg;
};

static int
visit_dip(dev_info_t *dip, void *arg)
{
	uintptr_t sbusy, dvbusy, ref;
	struct devi_busy *bsp = arg;

	ASSERT(bsp->callback);

	/*
	 * A dip cannot be busy if its reference count is 0
	 */
	if ((ref = e_ddi_devi_holdcnt(dip)) == 0) {
		return (bsp->callback(dip, bsp->arg, 0));
	}

	if (mod_hash_find(bsp->dv_hash, dip, (mod_hash_val_t *)&dvbusy))
		dvbusy = 0;

	/*
	 * To catch device opens currently maintained on specfs common snodes.
	 */
	if (mod_hash_find(bsp->s_hash, dip, (mod_hash_val_t *)&sbusy))
		sbusy = 0;

#ifdef	DEBUG
	if (ref < sbusy || ref < dvbusy) {
		cmn_err(CE_WARN, "dip(%p): sopen = %lu, dvopen = %lu "
		    "dip ref = %lu\n", (void *)dip, sbusy, dvbusy, ref);
	}
#endif

	dvbusy = (sbusy > dvbusy) ? sbusy : dvbusy;

	return (bsp->callback(dip, bsp->arg, dvbusy));
}

static int
visit_snode(struct snode *sp, void *arg)
{
	uintptr_t sbusy;
	dev_info_t *dip;
	int count;
	struct devi_busy *bsp = arg;

	ASSERT(sp);

	/*
	 * The stable lock is held. This prevents
	 * the snode and its associated dip from
	 * going away.
	 */
	dip = NULL;
	count = spec_devi_open_count(sp, &dip);

	if (count <= 0)
		return (DDI_WALK_CONTINUE);

	ASSERT(dip);

	if (mod_hash_remove(bsp->s_hash, dip, (mod_hash_val_t *)&sbusy))
		sbusy = count;
	else
		sbusy += count;

	if (mod_hash_insert(bsp->s_hash, dip, (mod_hash_val_t)sbusy)) {
		cmn_err(CE_WARN, "%s: s_hash insert failed: dip=0x%p, "
		    "sbusy = %lu", "e_ddi_branch_referenced",
		    (void *)dip, sbusy);
	}

	bsp->s_total += count;

	return (DDI_WALK_CONTINUE);
}

static void
visit_dvnode(struct dv_node *dv, void *arg)
{
	uintptr_t dvbusy;
	uint_t count;
	struct vnode *vp;
	struct devi_busy *bsp = arg;

	ASSERT(dv && dv->dv_devi);

	vp = DVTOV(dv);

	mutex_enter(&vp->v_lock);
	count = vp->v_count;
	mutex_exit(&vp->v_lock);

	if (!count)
		return;

	if (mod_hash_remove(bsp->dv_hash, dv->dv_devi,
	    (mod_hash_val_t *)&dvbusy))
		dvbusy = count;
	else
		dvbusy += count;

	if (mod_hash_insert(bsp->dv_hash, dv->dv_devi,
	    (mod_hash_val_t)dvbusy)) {
		cmn_err(CE_WARN, "%s: dv_hash insert failed: dip=0x%p, "
		    "dvbusy=%lu", "e_ddi_branch_referenced",
		    (void *)dv->dv_devi, dvbusy);
	}

	bsp->dv_total += count;
}

/*
 * Returns reference count on success or -1 on failure.
 */
int
e_ddi_branch_referenced(
	dev_info_t *rdip,
	int (*callback)(dev_info_t *dip, void *arg, uint_t ref),
	void *arg)
{
	int circ;
	char *path;
	dev_info_t *pdip;
	struct devi_busy bsa = {0};

	ASSERT(rdip);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	ndi_hold_devi(rdip);

	pdip = ddi_get_parent(rdip);

	ASSERT(pdip);

	/*
	 * Check if caller holds pdip busy - can cause deadlocks during
	 * devfs_walk()
	 */
	if (!e_ddi_branch_held(rdip) || DEVI_BUSY_OWNED(pdip)) {
		cmn_err(CE_WARN, "e_ddi_branch_referenced: failed: "
		    "devinfo branch(%p) not held or parent busy held",
		    (void *)rdip);
		ndi_rele_devi(rdip);
		kmem_free(path, MAXPATHLEN);
		return (-1);
	}

	ndi_devi_enter(pdip, &circ);
	(void) ddi_pathname(rdip, path);
	ndi_devi_exit(pdip, circ);

	bsa.dv_hash = mod_hash_create_ptrhash("dv_node busy hash", NUMCHAINS,
	    mod_hash_null_valdtor, sizeof (struct dev_info));

	bsa.s_hash = mod_hash_create_ptrhash("snode busy hash", NUMCHAINS,
	    mod_hash_null_valdtor, sizeof (struct snode));

	if (devfs_walk(path, visit_dvnode, &bsa)) {
		cmn_err(CE_WARN, "e_ddi_branch_referenced: "
		    "devfs walk failed for: %s", path);
		kmem_free(path, MAXPATHLEN);
		bsa.s_total = bsa.dv_total = -1;
		goto out;
	}

	kmem_free(path, MAXPATHLEN);

	/*
	 * Walk the snode table to detect device opens, which are currently
	 * maintained on specfs common snodes.
	 */
	spec_snode_walk(visit_snode, &bsa);

	if (callback == NULL)
		goto out;

	bsa.callback = callback;
	bsa.arg = arg;

	if (visit_dip(rdip, &bsa) == DDI_WALK_CONTINUE) {
		ndi_devi_enter(rdip, &circ);
		ddi_walk_devs(ddi_get_child(rdip), visit_dip, &bsa);
		ndi_devi_exit(rdip, circ);
	}

out:
	ndi_rele_devi(rdip);
	mod_hash_destroy_ptrhash(bsa.s_hash);
	mod_hash_destroy_ptrhash(bsa.dv_hash);
	return (bsa.s_total > bsa.dv_total ? bsa.s_total : bsa.dv_total);
}
