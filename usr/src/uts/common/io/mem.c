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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * Copyright 2017 Joyent, Inc.
 * Copyright 2017 James S Blachly, MD <james.blachly@gmail.com>
 */

/*
 * Memory special file
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/vm.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/kmem.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <sys/stat.h>
#include <sys/vmem.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>

#include <vm/seg_vn.h>
#include <vm/seg_dev.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <vm/seg_kpm.h>
#include <vm/hat.h>

#include <sys/conf.h>
#include <sys/mem.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/memlist.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/fm/protocol.h>

#if defined(__sparc)
extern int cpu_get_mem_name(uint64_t, uint64_t *, uint64_t, char *, int, int *);
extern int cpu_get_mem_info(uint64_t, uint64_t, uint64_t *, uint64_t *,
    uint64_t *, int *, int *, int *);
extern size_t cpu_get_name_bufsize(void);
extern int cpu_get_mem_sid(char *, char *, int, int *);
extern int cpu_get_mem_addr(char *, char *, uint64_t, uint64_t *);
#elif defined(__x86)
#include <sys/cpu_module.h>
#endif	/* __sparc */

/*
 * Turn a byte length into a pagecount.  The DDI btop takes a
 * 32-bit size on 32-bit machines, this handles 64-bit sizes for
 * large physical-memory 32-bit machines.
 */
#define	BTOP(x)	((pgcnt_t)((x) >> _pageshift))

static kmutex_t mm_lock;
static caddr_t mm_map;

static dev_info_t *mm_dip;	/* private copy of devinfo pointer */

static int mm_kmem_io_access;

static int mm_kstat_update(kstat_t *ksp, int rw);
static int mm_kstat_snapshot(kstat_t *ksp, void *buf, int rw);

static int mm_read_mem_name(intptr_t data, mem_name_t *mem_name);

#define	MM_KMEMLOG_NENTRIES	64

static int mm_kmemlogent;
static mm_logentry_t mm_kmemlog[MM_KMEMLOG_NENTRIES];

/*
 * On kmem/allmem writes, we log information that might be useful in the event
 * that a write is errant (that is, due to operator error) and induces a later
 * problem.  Note that (in particular) in the event of such operator-induced
 * corruption, a search over the kernel address space for the corrupted
 * address will yield the ring buffer entry that recorded the write.  And
 * should it seem baroque or otherwise unnecessary, yes, we need this kind of
 * auditing facility and yes, we learned that the hard way: disturbingly,
 * there exist recommendations for "tuning" the system that involve writing to
 * kernel memory addresses via the kernel debugger, and -- as we discovered --
 * these can easily be applied incorrectly or unsafely, yielding an entirely
 * undebuggable "can't happen" kind of panic.
 */
static void
mm_logkmem(struct uio *uio)
{
	mm_logentry_t *ent;
	proc_t *p = curthread->t_procp;

	mutex_enter(&mm_lock);

	ent = &mm_kmemlog[mm_kmemlogent++];

	if (mm_kmemlogent == MM_KMEMLOG_NENTRIES)
		mm_kmemlogent = 0;

	ent->mle_vaddr = (uintptr_t)uio->uio_loffset;
	ent->mle_len = uio->uio_resid;
	gethrestime(&ent->mle_hrestime);
	ent->mle_hrtime = gethrtime();
	ent->mle_pid = p->p_pidp->pid_id;

	(void) strncpy(ent->mle_psargs,
	    p->p_user.u_psargs, sizeof (ent->mle_psargs));

	mutex_exit(&mm_lock);
}

/*ARGSUSED1*/
static int
mm_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int i;
	struct mem_minor {
		char *name;
		minor_t minor;
		int privonly;
		const char *rdpriv;
		const char *wrpriv;
		mode_t priv_mode;
	} mm[] = {
		{ "mem",	M_MEM,		0,	NULL,	"all",	0640 },
		{ "kmem",	M_KMEM,		0,	NULL,	"all",	0640 },
		{ "allkmem",	M_ALLKMEM,	0,	"all",	"all",	0600 },
		{ "null",	M_NULL,	PRIVONLY_DEV,	NULL,	NULL,	0666 },
		{ "zero",	M_ZERO, PRIVONLY_DEV,	NULL,	NULL,	0666 },
		{ "full",	M_FULL, PRIVONLY_DEV,	NULL,	NULL,	0666 },
	};
	kstat_t *ksp;

	mutex_init(&mm_lock, NULL, MUTEX_DEFAULT, NULL);
	mm_map = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);

	for (i = 0; i < (sizeof (mm) / sizeof (mm[0])); i++) {
		if (ddi_create_priv_minor_node(devi, mm[i].name, S_IFCHR,
		    mm[i].minor, DDI_PSEUDO, mm[i].privonly,
		    mm[i].rdpriv, mm[i].wrpriv, mm[i].priv_mode) ==
		    DDI_FAILURE) {
			ddi_remove_minor_node(devi, NULL);
			return (DDI_FAILURE);
		}
	}

	mm_dip = devi;

	ksp = kstat_create("mm", 0, "phys_installed", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VAR_SIZE | KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_update = mm_kstat_update;
		ksp->ks_snapshot = mm_kstat_snapshot;
		ksp->ks_lock = &mm_lock; /* XXX - not really needed */
		kstat_install(ksp);
	}

	mm_kmem_io_access = ddi_getprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "kmem_io_access", 0);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
mm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	register int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)mm_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED1*/
static int
mmopen(dev_t *devp, int flag, int typ, struct cred *cred)
{
	switch (getminor(*devp)) {
	case M_NULL:
	case M_ZERO:
	case M_FULL:
	case M_MEM:
	case M_KMEM:
	case M_ALLKMEM:
		/* standard devices */
		break;

	default:
		/* Unsupported or unknown type */
		return (EINVAL);
	}
	/* must be character device */
	if (typ != OTYP_CHR)
		return (EINVAL);
	return (0);
}

struct pollhead	mm_pollhd;

/*ARGSUSED*/
static int
mmchpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	switch (getminor(dev)) {
	case M_NULL:
	case M_ZERO:
	case M_FULL:
	case M_MEM:
	case M_KMEM:
	case M_ALLKMEM:
		*reventsp = events & (POLLIN | POLLOUT | POLLPRI | POLLRDNORM |
		    POLLWRNORM | POLLRDBAND | POLLWRBAND);
		/*
		 * A non NULL pollhead pointer should be returned in case
		 * user polls for 0 events or is doing an edge-triggerd poll.
		 */
		if ((!*reventsp && !anyyet) || (events & POLLET)) {
			*phpp = &mm_pollhd;
		}
		return (0);
	default:
		/* no other devices currently support polling */
		return (ENXIO);
	}
}

static int
mmpropop(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int flags,
    char *name, caddr_t valuep, int *lengthp)
{
	/*
	 * implement zero size to reduce overhead (avoid two failing
	 * property lookups per stat).
	 */
	return (ddi_prop_op_size(dev, dip, prop_op,
	    flags, name, valuep, lengthp, 0));
}

static int
mmio(struct uio *uio, enum uio_rw rw, pfn_t pfn, off_t pageoff, int allowio,
    page_t *pp)
{
	int error = 0;
	int devload = 0;
	int is_memory = pf_is_memory(pfn);
	size_t nbytes = MIN((size_t)(PAGESIZE - pageoff),
	    (size_t)uio->uio_iov->iov_len);
	caddr_t va = NULL;

	mutex_enter(&mm_lock);

	if (is_memory && kpm_enable) {
		if (pp)
			va = hat_kpm_mapin(pp, NULL);
		else
			va = hat_kpm_mapin_pfn(pfn);
	}

	if (va == NULL) {
		hat_devload(kas.a_hat, mm_map, PAGESIZE, pfn,
		    (uint_t)(rw == UIO_READ ? PROT_READ : PROT_READ|PROT_WRITE),
		    HAT_LOAD_NOCONSIST|HAT_LOAD_LOCK);
		va = mm_map;
		devload = 1;
	}

	if (!is_memory) {
		if (allowio) {
			size_t c = uio->uio_iov->iov_len;

			if (ddi_peekpokeio(NULL, uio, rw,
			    (caddr_t)(uintptr_t)uio->uio_loffset, c,
			    sizeof (int32_t)) != DDI_SUCCESS)
				error = EFAULT;
		} else
			error = EIO;
	} else
		error = uiomove(va + pageoff, nbytes, rw, uio);

	if (devload)
		hat_unload(kas.a_hat, mm_map, PAGESIZE, HAT_UNLOAD_UNLOCK);
	else if (pp)
		hat_kpm_mapout(pp, NULL, va);
	else
		hat_kpm_mapout_pfn(pfn);

	mutex_exit(&mm_lock);
	return (error);
}

static int
mmpagelock(struct as *as, caddr_t va)
{
	struct seg *seg;
	int i;

	AS_LOCK_ENTER(as, RW_READER);
	seg = as_segat(as, va);
	i = (seg != NULL)? SEGOP_CAPABLE(seg, S_CAPABILITY_NOMINFLT) : 0;
	AS_LOCK_EXIT(as);

	return (i);
}

#ifdef	__sparc

#define	NEED_LOCK_KVADDR(kva)	mmpagelock(&kas, kva)

#else	/* __i386, __amd64 */

#define	NEED_LOCK_KVADDR(va)	0

#endif	/* __sparc */

/*ARGSUSED3*/
static int
mmrw(dev_t dev, struct uio *uio, enum uio_rw rw, cred_t *cred)
{
	pfn_t v;
	struct iovec *iov;
	int error = 0;
	size_t c;
	ssize_t oresid = uio->uio_resid;
	minor_t minor = getminor(dev);

	while (uio->uio_resid > 0 && error == 0) {
		iov = uio->uio_iov;
		if (iov->iov_len == 0) {
			uio->uio_iov++;
			uio->uio_iovcnt--;
			if (uio->uio_iovcnt < 0)
				panic("mmrw");
			continue;
		}
		switch (minor) {

		case M_MEM:
			memlist_read_lock();
			if (!address_in_memlist(phys_install,
			    (uint64_t)uio->uio_loffset, 1)) {
				memlist_read_unlock();
				error = EFAULT;
				break;
			}
			memlist_read_unlock();

			v = BTOP((u_offset_t)uio->uio_loffset);
			error = mmio(uio, rw, v,
			    uio->uio_loffset & PAGEOFFSET, 0, NULL);
			break;

		case M_KMEM:
		case M_ALLKMEM:
			{
			page_t **ppp = NULL;
			caddr_t vaddr = (caddr_t)uio->uio_offset;
			int try_lock = NEED_LOCK_KVADDR(vaddr);
			int locked = 0;

			if ((error = plat_mem_do_mmio(uio, rw)) != ENOTSUP)
				break;

			if (rw == UIO_WRITE)
				mm_logkmem(uio);

			/*
			 * If vaddr does not map a valid page, as_pagelock()
			 * will return failure. Hence we can't check the
			 * return value and return EFAULT here as we'd like.
			 * seg_kp and seg_kpm do not properly support
			 * as_pagelock() for this context so we avoid it
			 * using the try_lock set check above.  Some day when
			 * the kernel page locking gets redesigned all this
			 * muck can be cleaned up.
			 */
			if (try_lock)
				locked = (as_pagelock(&kas, &ppp, vaddr,
				    PAGESIZE, S_WRITE) == 0);

			v = hat_getpfnum(kas.a_hat,
			    (caddr_t)(uintptr_t)uio->uio_loffset);
			if (v == PFN_INVALID) {
				if (locked)
					as_pageunlock(&kas, ppp, vaddr,
					    PAGESIZE, S_WRITE);
				error = EFAULT;
				break;
			}

			error = mmio(uio, rw, v, uio->uio_loffset & PAGEOFFSET,
			    minor == M_ALLKMEM || mm_kmem_io_access,
			    (locked && ppp) ? *ppp : NULL);
			if (locked)
				as_pageunlock(&kas, ppp, vaddr, PAGESIZE,
				    S_WRITE);
			}

			break;

		case M_FULL:
			if (rw == UIO_WRITE) {
				error = ENOSPC;
				break;
			}
			/* else it's a read, fall through to zero case */
			/*FALLTHROUGH*/

		case M_ZERO:
			if (rw == UIO_READ) {
				label_t ljb;

				if (on_fault(&ljb)) {
					no_fault();
					error = EFAULT;
					break;
				}
				uzero(iov->iov_base, iov->iov_len);
				no_fault();
				uio->uio_resid -= iov->iov_len;
				uio->uio_loffset += iov->iov_len;
				break;
			}
			/* else it's a write, fall through to NULL case */
			/*FALLTHROUGH*/

		case M_NULL:
			if (rw == UIO_READ)
				return (0);
			c = iov->iov_len;
			iov->iov_base += c;
			iov->iov_len -= c;
			uio->uio_loffset += c;
			uio->uio_resid -= c;
			break;

		}
	}
	return (uio->uio_resid == oresid ? error : 0);
}

static int
mmread(dev_t dev, struct uio *uio, cred_t *cred)
{
	return (mmrw(dev, uio, UIO_READ, cred));
}

static int
mmwrite(dev_t dev, struct uio *uio, cred_t *cred)
{
	return (mmrw(dev, uio, UIO_WRITE, cred));
}

/*
 * Private ioctl for libkvm to support kvm_physaddr().
 * Given an address space and a VA, compute the PA.
 */
static int
mmioctl_vtop(intptr_t data)
{
#ifdef _SYSCALL32
	mem_vtop32_t vtop32;
#endif
	mem_vtop_t mem_vtop;
	proc_t *p;
	pfn_t pfn = (pfn_t)PFN_INVALID;
	pid_t pid = 0;
	struct as *as;
	struct seg *seg;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin((void *)data, &mem_vtop, sizeof (mem_vtop_t)))
			return (EFAULT);
	}
#ifdef _SYSCALL32
	else {
		if (copyin((void *)data, &vtop32, sizeof (mem_vtop32_t)))
			return (EFAULT);
		mem_vtop.m_as = (struct as *)(uintptr_t)vtop32.m_as;
		mem_vtop.m_va = (void *)(uintptr_t)vtop32.m_va;

		if (mem_vtop.m_as != NULL)
			return (EINVAL);
	}
#endif

	if (mem_vtop.m_as == &kas) {
		pfn = hat_getpfnum(kas.a_hat, mem_vtop.m_va);
	} else {
		if (mem_vtop.m_as == NULL) {
			/*
			 * Assume the calling process's address space if the
			 * caller didn't specify one.
			 */
			p = curthread->t_procp;
			if (p == NULL)
				return (EIO);
			mem_vtop.m_as = p->p_as;
		}

		mutex_enter(&pidlock);
		for (p = practive; p != NULL; p = p->p_next) {
			if (p->p_as == mem_vtop.m_as) {
				pid = p->p_pid;
				break;
			}
		}
		mutex_exit(&pidlock);
		if (p == NULL)
			return (EIO);
		p = sprlock(pid);
		if (p == NULL)
			return (EIO);
		as = p->p_as;
		if (as == mem_vtop.m_as) {
			mutex_exit(&p->p_lock);
			AS_LOCK_ENTER(as, RW_READER);
			for (seg = AS_SEGFIRST(as); seg != NULL;
			    seg = AS_SEGNEXT(as, seg))
				if ((uintptr_t)mem_vtop.m_va -
				    (uintptr_t)seg->s_base < seg->s_size)
					break;
			if (seg != NULL)
				pfn = hat_getpfnum(as->a_hat, mem_vtop.m_va);
			AS_LOCK_EXIT(as);
			mutex_enter(&p->p_lock);
		}
		sprunlock(p);
	}
	mem_vtop.m_pfn = pfn;
	if (pfn == PFN_INVALID)
		return (EIO);

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&mem_vtop, (void *)data, sizeof (mem_vtop_t)))
			return (EFAULT);
	}
#ifdef _SYSCALL32
	else {
		vtop32.m_pfn = mem_vtop.m_pfn;
		if (copyout(&vtop32, (void *)data, sizeof (mem_vtop32_t)))
			return (EFAULT);
	}
#endif

	return (0);
}

/*
 * Given a PA, execute the given page retire command on it.
 */
static int
mmioctl_page_retire(int cmd, intptr_t data)
{
	extern int page_retire_test(void);
	uint64_t pa;

	if (copyin((void *)data, &pa, sizeof (uint64_t))) {
		return (EFAULT);
	}

	switch (cmd) {
	case MEM_PAGE_ISRETIRED:
		return (page_retire_check(pa, NULL));

	case MEM_PAGE_UNRETIRE:
		return (page_unretire(pa));

	case MEM_PAGE_RETIRE:
		return (page_retire(pa, PR_FMA));

	case MEM_PAGE_RETIRE_MCE:
		return (page_retire(pa, PR_MCE));

	case MEM_PAGE_RETIRE_UE:
		return (page_retire(pa, PR_UE));

	case MEM_PAGE_GETERRORS:
		{
			uint64_t page_errors;
			int rc = page_retire_check(pa, &page_errors);
			if (copyout(&page_errors, (void *)data,
			    sizeof (uint64_t))) {
				return (EFAULT);
			}
			return (rc);
		}

	case MEM_PAGE_RETIRE_TEST:
		return (page_retire_test());

	}

	return (EINVAL);
}

#ifdef __sparc
/*
 * Given a syndrome, syndrome type, and address return the
 * associated memory name in the provided data buffer.
 */
static int
mmioctl_get_mem_name(intptr_t data)
{
	mem_name_t mem_name;
	void *buf;
	size_t bufsize;
	int len, err;

	if ((bufsize = cpu_get_name_bufsize()) == 0)
		return (ENOTSUP);

	if ((err = mm_read_mem_name(data, &mem_name)) < 0)
		return (err);

	buf = kmem_alloc(bufsize, KM_SLEEP);

	/*
	 * Call into cpu specific code to do the lookup.
	 */
	if ((err = cpu_get_mem_name(mem_name.m_synd, mem_name.m_type,
	    mem_name.m_addr, buf, bufsize, &len)) != 0) {
		kmem_free(buf, bufsize);
		return (err);
	}

	if (len >= mem_name.m_namelen) {
		kmem_free(buf, bufsize);
		return (ENOSPC);
	}

	if (copyoutstr(buf, (char *)mem_name.m_name,
	    mem_name.m_namelen, NULL) != 0) {
		kmem_free(buf, bufsize);
		return (EFAULT);
	}

	kmem_free(buf, bufsize);
	return (0);
}

/*
 * Given a syndrome and address return information about the associated memory.
 */
static int
mmioctl_get_mem_info(intptr_t data)
{
	mem_info_t mem_info;
	int err;

	if (copyin((void *)data, &mem_info, sizeof (mem_info_t)))
		return (EFAULT);

	if ((err = cpu_get_mem_info(mem_info.m_synd, mem_info.m_addr,
	    &mem_info.m_mem_size, &mem_info.m_seg_size, &mem_info.m_bank_size,
	    &mem_info.m_segments, &mem_info.m_banks, &mem_info.m_mcid)) != 0)
		return (err);

	if (copyout(&mem_info, (void *)data, sizeof (mem_info_t)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Given a memory name, return its associated serial id
 */
static int
mmioctl_get_mem_sid(intptr_t data)
{
	mem_name_t mem_name;
	void *buf;
	void *name;
	size_t	name_len;
	size_t bufsize;
	int len, err;

	if ((bufsize = cpu_get_name_bufsize()) == 0)
		return (ENOTSUP);

	if ((err = mm_read_mem_name(data, &mem_name)) < 0)
		return (err);

	buf = kmem_alloc(bufsize, KM_SLEEP);

	if (mem_name.m_namelen > 1024)
		mem_name.m_namelen = 1024; /* cap at 1024 bytes */

	name = kmem_alloc(mem_name.m_namelen, KM_SLEEP);

	if ((err = copyinstr((char *)mem_name.m_name, (char *)name,
	    mem_name.m_namelen, &name_len)) != 0) {
		kmem_free(buf, bufsize);
		kmem_free(name, mem_name.m_namelen);
		return (err);
	}

	/*
	 * Call into cpu specific code to do the lookup.
	 */
	if ((err = cpu_get_mem_sid(name, buf, bufsize, &len)) != 0) {
		kmem_free(buf, bufsize);
		kmem_free(name, mem_name.m_namelen);
		return (err);
	}

	if (len > mem_name.m_sidlen) {
		kmem_free(buf, bufsize);
		kmem_free(name, mem_name.m_namelen);
		return (ENAMETOOLONG);
	}

	if (copyoutstr(buf, (char *)mem_name.m_sid,
	    mem_name.m_sidlen, NULL) != 0) {
		kmem_free(buf, bufsize);
		kmem_free(name, mem_name.m_namelen);
		return (EFAULT);
	}

	kmem_free(buf, bufsize);
	kmem_free(name, mem_name.m_namelen);
	return (0);
}
#endif	/* __sparc */

/*
 * Private ioctls for
 *	libkvm to support kvm_physaddr().
 *	FMA support for page_retire() and memory attribute information.
 */
/*ARGSUSED*/
static int
mmioctl(dev_t dev, int cmd, intptr_t data, int flag, cred_t *cred, int *rvalp)
{
	if ((cmd == MEM_VTOP && getminor(dev) != M_KMEM) ||
	    (cmd != MEM_VTOP && getminor(dev) != M_MEM))
		return (ENXIO);

	switch (cmd) {
	case MEM_VTOP:
		return (mmioctl_vtop(data));

	case MEM_PAGE_RETIRE:
	case MEM_PAGE_ISRETIRED:
	case MEM_PAGE_UNRETIRE:
	case MEM_PAGE_RETIRE_MCE:
	case MEM_PAGE_RETIRE_UE:
	case MEM_PAGE_GETERRORS:
	case MEM_PAGE_RETIRE_TEST:
		return (mmioctl_page_retire(cmd, data));

#ifdef __sparc
	case MEM_NAME:
		return (mmioctl_get_mem_name(data));

	case MEM_INFO:
		return (mmioctl_get_mem_info(data));

	case MEM_SID:
		return (mmioctl_get_mem_sid(data));
#else
	case MEM_NAME:
	case MEM_INFO:
	case MEM_SID:
		return (ENOTSUP);
#endif	/* __sparc */
	}
	return (ENXIO);
}

/*ARGSUSED2*/
static int
mmmmap(dev_t dev, off_t off, int prot)
{
	pfn_t pf;
	struct memlist *pmem;
	minor_t minor = getminor(dev);

	switch (minor) {
	case M_MEM:
		pf = btop(off);
		memlist_read_lock();
		for (pmem = phys_install; pmem != NULL; pmem = pmem->ml_next) {
			if (pf >= BTOP(pmem->ml_address) &&
			    pf < BTOP(pmem->ml_address + pmem->ml_size)) {
				memlist_read_unlock();
				return (impl_obmem_pfnum(pf));
			}
		}
		memlist_read_unlock();
		break;

	case M_KMEM:
	case M_ALLKMEM:
		/* no longer supported with KPR */
		return (-1);

	case M_FULL:
	case M_ZERO:
		/*
		 * We shouldn't be mmap'ing to /dev/zero here as
		 * mmsegmap() should have already converted
		 * a mapping request for this device to a mapping
		 * using seg_vn for anonymous memory.
		 */
		break;

	}
	return (-1);
}

/*
 * This function is called when a memory device is mmap'ed.
 * Set up the mapping to the correct device driver.
 */
static int
mmsegmap(dev_t dev, off_t off, struct as *as, caddr_t *addrp, off_t len,
    uint_t prot, uint_t maxprot, uint_t flags, struct cred *cred)
{
	struct segvn_crargs vn_a;
	struct segdev_crargs dev_a;
	int error;
	minor_t minor;
	off_t i;

	minor = getminor(dev);

	as_rangelock(as);
	/*
	 * No need to worry about vac alignment on /dev/zero
	 * since this is a "clone" object that doesn't yet exist.
	 */
	error = choose_addr(as, addrp, len, off,
	    (minor == M_MEM) || (minor == M_KMEM), flags);
	if (error != 0) {
		as_rangeunlock(as);
		return (error);
	}

	switch (minor) {
	case M_MEM:
		/* /dev/mem cannot be mmap'ed with MAP_PRIVATE */
		if ((flags & MAP_TYPE) != MAP_SHARED) {
			as_rangeunlock(as);
			return (EINVAL);
		}

		/*
		 * Check to ensure that the entire range is
		 * legal and we are not trying to map in
		 * more than the device will let us.
		 */
		for (i = 0; i < len; i += PAGESIZE) {
			if (mmmmap(dev, off + i, maxprot) == -1) {
				as_rangeunlock(as);
				return (ENXIO);
			}
		}

		/*
		 * Use seg_dev segment driver for /dev/mem mapping.
		 */
		dev_a.mapfunc = mmmmap;
		dev_a.dev = dev;
		dev_a.offset = off;
		dev_a.type = (flags & MAP_TYPE);
		dev_a.prot = (uchar_t)prot;
		dev_a.maxprot = (uchar_t)maxprot;
		dev_a.hat_attr = 0;

		/*
		 * Make /dev/mem mappings non-consistent since we can't
		 * alias pages that don't have page structs behind them,
		 * such as kernel stack pages. If someone mmap()s a kernel
		 * stack page and if we give them a tte with cv, a line from
		 * that page can get into both pages of the spitfire d$.
		 * But snoop from another processor will only invalidate
		 * the first page. This later caused kernel (xc_attention)
		 * to go into an infinite loop at pil 13 and no interrupts
		 * could come in. See 1203630.
		 *
		 */
		dev_a.hat_flags = HAT_LOAD_NOCONSIST;
		dev_a.devmap_data = NULL;

		error = as_map(as, *addrp, len, segdev_create, &dev_a);
		break;

	case M_ZERO:
		/*
		 * Use seg_vn segment driver for /dev/zero mapping.
		 * Passing in a NULL amp gives us the "cloning" effect.
		 */
		vn_a.vp = NULL;
		vn_a.offset = 0;
		vn_a.type = (flags & MAP_TYPE);
		vn_a.prot = prot;
		vn_a.maxprot = maxprot;
		vn_a.flags = flags & ~MAP_TYPE;
		vn_a.cred = cred;
		vn_a.amp = NULL;
		vn_a.szc = 0;
		vn_a.lgrp_mem_policy_flags = 0;
		error = as_map(as, *addrp, len, segvn_create, &vn_a);
		break;

	case M_KMEM:
	case M_ALLKMEM:
		/* No longer supported with KPR. */
		error = ENXIO;
		break;

	case M_NULL:
		/*
		 * Use seg_dev segment driver for /dev/null mapping.
		 */
		dev_a.mapfunc = mmmmap;
		dev_a.dev = dev;
		dev_a.offset = off;
		dev_a.type = 0;		/* neither PRIVATE nor SHARED */
		dev_a.prot = dev_a.maxprot = (uchar_t)PROT_NONE;
		dev_a.hat_attr = 0;
		dev_a.hat_flags = 0;
		error = as_map(as, *addrp, len, segdev_create, &dev_a);
		break;

	default:
		error = ENXIO;
	}

	as_rangeunlock(as);
	return (error);
}

static struct cb_ops mm_cb_ops = {
	mmopen,			/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	mmread,			/* read */
	mmwrite,		/* write */
	mmioctl,		/* ioctl */
	nodev,			/* devmap */
	mmmmap,			/* mmap */
	mmsegmap,		/* segmap */
	mmchpoll,		/* poll */
	mmpropop,		/* prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP | D_64BIT | D_U64BIT
};

static struct dev_ops mm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	mm_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	mm_attach,		/* attach */
	nodev,			/* detach */
	nodev,			/* reset */
	&mm_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops, "memory driver", &mm_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

static int
mm_kstat_update(kstat_t *ksp, int rw)
{
	struct memlist *pmem;
	uint_t count;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	count = 0;
	memlist_read_lock();
	for (pmem = phys_install; pmem != NULL; pmem = pmem->ml_next) {
		count++;
	}
	memlist_read_unlock();

	ksp->ks_ndata = count;
	ksp->ks_data_size = count * 2 * sizeof (uint64_t);

	return (0);
}

static int
mm_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	struct memlist *pmem;
	struct memunit {
		uint64_t address;
		uint64_t size;
	} *kspmem;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ksp->ks_snaptime = gethrtime();

	kspmem = (struct memunit *)buf;
	memlist_read_lock();
	for (pmem = phys_install; pmem != NULL;
	    pmem = pmem->ml_next, kspmem++) {
		if ((caddr_t)kspmem >= (caddr_t)buf + ksp->ks_data_size)
			break;
		kspmem->address = pmem->ml_address;
		kspmem->size = pmem->ml_size;
	}
	memlist_read_unlock();

	return (0);
}

/*
 * Read a mem_name_t from user-space and store it in the mem_name_t
 * pointed to by the mem_name argument.
 */
static int
mm_read_mem_name(intptr_t data, mem_name_t *mem_name)
{
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin((void *)data, mem_name, sizeof (mem_name_t)))
			return (EFAULT);
	}
#ifdef	_SYSCALL32
	else {
		mem_name32_t mem_name32;

		if (copyin((void *)data, &mem_name32, sizeof (mem_name32_t)))
			return (EFAULT);
		mem_name->m_addr = mem_name32.m_addr;
		mem_name->m_synd = mem_name32.m_synd;
		mem_name->m_type[0] = mem_name32.m_type[0];
		mem_name->m_type[1] = mem_name32.m_type[1];
		mem_name->m_name = (caddr_t)(uintptr_t)mem_name32.m_name;
		mem_name->m_namelen = (size_t)mem_name32.m_namelen;
		mem_name->m_sid = (caddr_t)(uintptr_t)mem_name32.m_sid;
		mem_name->m_sidlen = (size_t)mem_name32.m_sidlen;
	}
#endif	/* _SYSCALL32 */

	return (0);
}
