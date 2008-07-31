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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * CPU Performance Counter system calls and device driver.
 *
 * This module uses a combination of thread context operators, and
 * thread-specific data to export CPU performance counters
 * via both a system call and a driver interface.
 *
 * There are three access methods exported - the 'shared' device
 * and the 'private' and 'agent' variants of the system call.
 *
 * The shared device treats the performance counter registers as
 * a processor metric, regardless of the work scheduled on them.
 * The private system call treats the performance counter registers
 * as a property of a single lwp.  This is achieved by using the
 * thread context operators to virtualize the contents of the
 * performance counter registers between lwps.
 *
 * The agent method is like the private method, except that it must
 * be accessed via /proc's agent lwp to allow the counter context of
 * other threads to be examined safely.
 *
 * The shared usage fundamentally conflicts with the agent and private usage;
 * almost all of the complexity of the module is needed to allow these two
 * models to co-exist in a reasonable way.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/nvpair.h>
#include <sys/policy.h>
#include <sys/machsystm.h>
#include <sys/cpc_impl.h>
#include <sys/cpc_pcbe.h>
#include <sys/kcpc.h>

static int kcpc_copyin_set(kcpc_set_t **set, void *ubuf, size_t len);
static int kcpc_verify_set(kcpc_set_t *set);
static uint32_t kcpc_nvlist_npairs(nvlist_t *list);

/*
 * Generic attributes supported regardless of processor.
 */

#define	ATTRLIST "picnum"
#define	SEPARATOR ","

/*
 * System call to access CPU performance counters.
 */
static int
cpc(int cmd, id_t lwpid, void *udata1, void *udata2, void *udata3)
{
	kthread_t	*t;
	int		error;
	int		size;
	const char	*str;
	int		code;

	/*
	 * This CPC syscall should only be loaded if it found a PCBE to use.
	 */
	ASSERT(pcbe_ops != NULL);

	if (curproc->p_agenttp == curthread) {
		/*
		 * Only if /proc is invoking this system call from
		 * the agent thread do we allow the caller to examine
		 * the contexts of other lwps in the process.  And
		 * because we know we're the agent, we know we don't
		 * have to grab p_lock because no-one else can change
		 * the state of the process.
		 */
		if ((t = idtot(curproc, lwpid)) == NULL || t == curthread)
			return (set_errno(ESRCH));
		ASSERT(t->t_tid == lwpid && ttolwp(t) != NULL);
	} else
		t = curthread;

	if (t->t_cpc_set == NULL && (cmd == CPC_SAMPLE || cmd == CPC_RELE))
		return (set_errno(EINVAL));

	switch (cmd) {
	case CPC_BIND:
		/*
		 * udata1 = pointer to packed nvlist buffer
		 * udata2 = size of packed nvlist buffer
		 * udata3 = User addr to return error subcode in.
		 */

		rw_enter(&kcpc_cpuctx_lock, RW_READER);
		if (kcpc_cpuctx) {
			rw_exit(&kcpc_cpuctx_lock);
			return (set_errno(EAGAIN));
		}

		if (kcpc_hw_lwp_hook() != 0) {
			rw_exit(&kcpc_cpuctx_lock);
			return (set_errno(EACCES));
		}

		/*
		 * An LWP may only have one set bound to it at a time; if there
		 * is a set bound to this LWP already, we unbind it here.
		 */
		if (t->t_cpc_set != NULL)
			(void) kcpc_unbind(t->t_cpc_set);
		ASSERT(t->t_cpc_set == NULL);

		if ((error = kcpc_copyin_set(&t->t_cpc_set, udata1,
		    (size_t)udata2)) != 0) {
			rw_exit(&kcpc_cpuctx_lock);
			return (set_errno(error));
		}

		if ((error = kcpc_verify_set(t->t_cpc_set)) != 0) {
			rw_exit(&kcpc_cpuctx_lock);
			kcpc_free_set(t->t_cpc_set);
			t->t_cpc_set = NULL;
			if (copyout(&error, udata3, sizeof (error)) == -1)
				return (set_errno(EFAULT));
			return (set_errno(EINVAL));
		}

		if ((error = kcpc_bind_thread(t->t_cpc_set, t, &code)) != 0) {
			rw_exit(&kcpc_cpuctx_lock);
			kcpc_free_set(t->t_cpc_set);
			t->t_cpc_set = NULL;
			/*
			 * EINVAL and EACCES are the only errors with more
			 * specific subcodes.
			 */
			if ((error == EINVAL || error == EACCES) &&
			    copyout(&code, udata3, sizeof (code)) == -1)
				return (set_errno(EFAULT));
			return (set_errno(error));
		}

		rw_exit(&kcpc_cpuctx_lock);
		return (0);
	case CPC_SAMPLE:
		/*
		 * udata1 = pointer to user's buffer
		 * udata2 = pointer to user's hrtime
		 * udata3 = pointer to user's tick
		 */
		/*
		 * We only allow thread-bound sets to be sampled via the
		 * syscall, so if this set has a CPU-bound context, return an
		 * error.
		 */
		if (t->t_cpc_set->ks_ctx->kc_cpuid != -1)
			return (set_errno(EINVAL));
		if ((error = kcpc_sample(t->t_cpc_set, udata1, udata2,
		    udata3)) != 0)
			return (set_errno(error));

		return (0);
	case CPC_PRESET:
	case CPC_RESTART:
		/*
		 * These are valid only if this lwp has a bound set.
		 */
		if (t->t_cpc_set == NULL)
			return (set_errno(EINVAL));
		if (cmd == CPC_PRESET) {
			/*
			 * The preset is shipped up to us from userland in two
			 * parts. This lets us handle 64-bit values from 32-bit
			 * and 64-bit applications in the same manner.
			 *
			 * udata1 = index of request to preset
			 * udata2 = new 64-bit preset (most sig. 32 bits)
			 * udata3 = new 64-bit preset (least sig. 32 bits)
			 */
			if ((error = kcpc_preset(t->t_cpc_set, (intptr_t)udata1,
			    ((uint64_t)(uintptr_t)udata2 << 32ULL) |
			    (uint64_t)(uintptr_t)udata3)) != 0)
				return (set_errno(error));
		} else {
			/*
			 * udata[1-3] = unused
			 */
			if ((error = kcpc_restart(t->t_cpc_set)) != 0)
				return (set_errno(error));
		}
		return (0);
	case CPC_ENABLE:
	case CPC_DISABLE:
		udata1 = 0;
		/*FALLTHROUGH*/
	case CPC_USR_EVENTS:
	case CPC_SYS_EVENTS:
		if (t != curthread || t->t_cpc_set == NULL)
			return (set_errno(EINVAL));
		/*
		 * Provided for backwards compatibility with CPCv1.
		 *
		 * Stop the counters and record the current counts. Use the
		 * counts as the preset to rebind a new set with the requests
		 * reconfigured as requested.
		 *
		 * udata1: 1 == enable; 0 == disable
		 * udata{2,3}: unused
		 */
		rw_enter(&kcpc_cpuctx_lock, RW_READER);
		if ((error = kcpc_enable(t,
		    cmd, (int)(uintptr_t)udata1)) != 0) {
			rw_exit(&kcpc_cpuctx_lock);
			return (set_errno(error));
		}
		rw_exit(&kcpc_cpuctx_lock);
		return (0);
	case CPC_NPIC:
		return (cpc_ncounters);
	case CPC_CAPS:
		return (pcbe_ops->pcbe_caps);
	case CPC_EVLIST_SIZE:
	case CPC_LIST_EVENTS:
		/*
		 * udata1 = pointer to user's int or buffer
		 * udata2 = picnum
		 * udata3 = unused
		 */
		if ((uintptr_t)udata2 >= cpc_ncounters)
			return (set_errno(EINVAL));

		size = strlen(
		    pcbe_ops->pcbe_list_events((uintptr_t)udata2)) + 1;

		if (cmd == CPC_EVLIST_SIZE) {
			if (suword32(udata1, size) == -1)
				return (set_errno(EFAULT));
		} else {
			if (copyout(
			    pcbe_ops->pcbe_list_events((uintptr_t)udata2),
			    udata1, size) == -1)
				return (set_errno(EFAULT));
		}
		return (0);
	case CPC_ATTRLIST_SIZE:
	case CPC_LIST_ATTRS:
		/*
		 * udata1 = pointer to user's int or buffer
		 * udata2 = unused
		 * udata3 = unused
		 *
		 * attrlist size is length of PCBE-supported attributes, plus
		 * room for "picnum\0" plus an optional ',' separator char.
		 */
		str = pcbe_ops->pcbe_list_attrs();
		size = strlen(str) + sizeof (SEPARATOR ATTRLIST) + 1;
		if (str[0] != '\0')
			/*
			 * A ',' separator character is necessary.
			 */
			size += 1;

		if (cmd == CPC_ATTRLIST_SIZE) {
			if (suword32(udata1, size) == -1)
				return (set_errno(EFAULT));
		} else {
			/*
			 * Copyout the PCBE attributes, and then append the
			 * generic attribute list (with separator if necessary).
			 */
			if (copyout(str, udata1, strlen(str)) == -1)
				return (set_errno(EFAULT));
			if (str[0] != '\0') {
				if (copyout(SEPARATOR ATTRLIST,
				    ((char *)udata1) + strlen(str),
				    strlen(SEPARATOR ATTRLIST) + 1)
				    == -1)
					return (set_errno(EFAULT));
			} else
				if (copyout(ATTRLIST,
				    (char *)udata1 + strlen(str),
				    strlen(ATTRLIST) + 1) == -1)
					return (set_errno(EFAULT));
		}
		return (0);
	case CPC_IMPL_NAME:
	case CPC_CPUREF:
		/*
		 * udata1 = pointer to user's buffer
		 * udata2 = unused
		 * udata3 = unused
		 */
		if (cmd == CPC_IMPL_NAME) {
			str = pcbe_ops->pcbe_impl_name();
			ASSERT(strlen(str) < CPC_MAX_IMPL_NAME);
		} else {
			str = pcbe_ops->pcbe_cpuref();
			ASSERT(strlen(str) < CPC_MAX_CPUREF);
		}

		if (copyout(str, udata1, strlen(str) + 1) != 0)
			return (set_errno(EFAULT));
		return (0);
	case CPC_INVALIDATE:
		kcpc_invalidate(t);
		return (0);
	case CPC_RELE:
		if ((error = kcpc_unbind(t->t_cpc_set)) != 0)
			return (set_errno(error));
		return (0);
	default:
		return (set_errno(EINVAL));
	}
}

/*
 * The 'shared' device allows direct access to the
 * performance counter control register of the current CPU.
 * The major difference between the contexts created here and those
 * above is that the context handlers are -not- installed, thus
 * no context switching behaviour occurs.
 *
 * Because they manipulate per-cpu state, these ioctls can
 * only be invoked from a bound lwp, by a caller with the cpc_cpu privilege
 * who can open the relevant entry in /devices (the act of holding it open
 * causes other uses of the counters to be suspended).
 *
 * Note that for correct results, the caller -must- ensure that
 * all existing per-lwp contexts are either inactive or marked invalid;
 * that's what the open routine does.
 */
/*ARGSUSED*/
static int
kcpc_ioctl(dev_t dev, int cmd, intptr_t data, int flags, cred_t *cr, int *rvp)
{
	kthread_t	*t = curthread;
	processorid_t	cpuid;
	void		*udata1 = NULL;
	void		*udata2 = NULL;
	void		*udata3 = NULL;
	int		error;
	int		code;

	STRUCT_DECL(__cpc_args, args);

	STRUCT_INIT(args, flags);

	if (curthread->t_bind_cpu != getminor(dev))
		return (EAGAIN);  /* someone unbound it? */

	cpuid = getminor(dev);

	if (cmd == CPCIO_BIND || cmd == CPCIO_SAMPLE) {
		if (copyin((void *)data, STRUCT_BUF(args),
		    STRUCT_SIZE(args)) == -1)
			return (EFAULT);

		udata1 = STRUCT_FGETP(args, udata1);
		udata2 = STRUCT_FGETP(args, udata2);
		udata3 = STRUCT_FGETP(args, udata3);
	}

	switch (cmd) {
	case CPCIO_BIND:
		/*
		 * udata1 = pointer to packed nvlist buffer
		 * udata2 = size of packed nvlist buffer
		 * udata3 = User addr to return error subcode in.
		 */
		if (t->t_cpc_set != NULL) {
			(void) kcpc_unbind(t->t_cpc_set);
			ASSERT(t->t_cpc_set == NULL);
		}

		if ((error = kcpc_copyin_set(&t->t_cpc_set, udata1,
		    (size_t)udata2)) != 0) {
			return (error);
		}

		if ((error = kcpc_verify_set(t->t_cpc_set)) != 0) {
			kcpc_free_set(t->t_cpc_set);
			t->t_cpc_set = NULL;
			if (copyout(&error, udata3, sizeof (error)) == -1)
				return (EFAULT);
			return (EINVAL);
		}

		if ((error = kcpc_bind_cpu(t->t_cpc_set, cpuid, &code)) != 0) {
			kcpc_free_set(t->t_cpc_set);
			t->t_cpc_set = NULL;
			/*
			 * Subcodes are only returned for EINVAL and EACCESS.
			 */
			if ((error == EINVAL || error == EACCES) &&
			    copyout(&code, udata3, sizeof (code)) == -1)
				return (EFAULT);
			return (error);
		}

		return (0);
	case CPCIO_SAMPLE:
		/*
		 * udata1 = pointer to user's buffer
		 * udata2 = pointer to user's hrtime
		 * udata3 = pointer to user's tick
		 */
		/*
		 * Only CPU-bound sets may be sampled via the ioctl(). If this
		 * set has no CPU-bound context, return an error.
		 */
		if (t->t_cpc_set == NULL)
			return (EINVAL);
		if ((error = kcpc_sample(t->t_cpc_set, udata1, udata2,
		    udata3)) != 0)
			return (error);
		return (0);
	case CPCIO_RELE:
		if (t->t_cpc_set == NULL)
			return (EINVAL);
		return (kcpc_unbind(t->t_cpc_set));
	default:
		return (EINVAL);
	}
}

/*
 * The device supports multiple opens, but only one open
 * is allowed per processor.  This is to enable multiple
 * instances of tools looking at different processors.
 */
#define	KCPC_MINOR_SHARED		((minor_t)0x3fffful)

static ulong_t *kcpc_cpumap;		/* bitmap of cpus */

/*ARGSUSED1*/
static int
kcpc_open(dev_t *dev, int flags, int otyp, cred_t *cr)
{
	processorid_t	cpuid;
	int		error;

	ASSERT(pcbe_ops != NULL);

	if ((error = secpolicy_cpc_cpu(cr)) != 0)
		return (error);
	if (getminor(*dev) != KCPC_MINOR_SHARED)
		return (ENXIO);
	if ((cpuid = curthread->t_bind_cpu) == PBIND_NONE)
		return (EINVAL);
	if (cpuid > max_cpuid)
		return (EINVAL);

	rw_enter(&kcpc_cpuctx_lock, RW_WRITER);
	if (++kcpc_cpuctx == 1) {
		ASSERT(kcpc_cpumap == NULL);
		kcpc_cpumap = kmem_zalloc(BT_SIZEOFMAP(max_cpuid + 1),
		    KM_SLEEP);
		/*
		 * When this device is open for processor-based contexts,
		 * no further lwp-based contexts can be created.
		 *
		 * Since this is the first open, ensure that all existing
		 * contexts are invalidated.
		 */
		kcpc_invalidate_all();
	} else if (BT_TEST(kcpc_cpumap, cpuid)) {
		kcpc_cpuctx--;
		rw_exit(&kcpc_cpuctx_lock);
		return (EAGAIN);
	} else if (kcpc_hw_cpu_hook(cpuid, kcpc_cpumap) != 0) {
		kcpc_cpuctx--;
		rw_exit(&kcpc_cpuctx_lock);
		return (EACCES);
	}
	BT_SET(kcpc_cpumap, cpuid);
	rw_exit(&kcpc_cpuctx_lock);

	*dev = makedevice(getmajor(*dev), (minor_t)cpuid);

	return (0);
}

/*ARGSUSED1*/
static int
kcpc_close(dev_t dev, int flags, int otyp, cred_t *cr)
{
	rw_enter(&kcpc_cpuctx_lock, RW_WRITER);
	BT_CLEAR(kcpc_cpumap, getminor(dev));
	if (--kcpc_cpuctx == 0) {
		kmem_free(kcpc_cpumap, BT_SIZEOFMAP(max_cpuid + 1));
		kcpc_cpumap = NULL;
	}
	ASSERT(kcpc_cpuctx >= 0);
	rw_exit(&kcpc_cpuctx_lock);

	return (0);
}

/*
 * Sane boundaries on the size of packed lists. In bytes.
 */
#define	CPC_MIN_PACKSIZE 4
#define	CPC_MAX_PACKSIZE 10000

/*
 * Sane boundary on the number of requests a set can contain.
 */
#define	CPC_MAX_NREQS 100

/*
 * Sane boundary on the number of attributes a request can contain.
 */
#define	CPC_MAX_ATTRS 50

/*
 * Copy in a packed nvlist from the user and create a request set out of it.
 * If successful, return 0 and store a pointer to the set we've created. Returns
 * error code on error.
 */
int
kcpc_copyin_set(kcpc_set_t **inset, void *ubuf, size_t len)
{
	kcpc_set_t	*set;
	int		i;
	int		j;
	char		*packbuf;

	nvlist_t	*nvl;
	nvpair_t	*nvp = NULL;

	nvlist_t	*attrs;
	nvpair_t	*nvp_attr;
	kcpc_attr_t	*attrp;

	nvlist_t	**reqlist;
	uint_t		nreqs;
	uint64_t	uint64;
	uint32_t	uint32;
	uint32_t	setflags = (uint32_t)-1;
	char		*string;
	char		*name;

	if (len < CPC_MIN_PACKSIZE || len > CPC_MAX_PACKSIZE)
		return (EINVAL);

	packbuf = kmem_alloc(len, KM_SLEEP);

	if (copyin(ubuf, packbuf, len) == -1) {
		kmem_free(packbuf, len);
		return (EFAULT);
	}

	if (nvlist_unpack(packbuf, len, &nvl, KM_SLEEP) != 0) {
		kmem_free(packbuf, len);
		return (EINVAL);
	}

	/*
	 * The nvlist has been unpacked so there is no need for the packed
	 * representation from this point on.
	 */
	kmem_free(packbuf, len);

	i = 0;
	while ((nvp = nvlist_next_nvpair(nvl, nvp)) != NULL) {
		switch (nvpair_type(nvp)) {
		case DATA_TYPE_UINT32:
			if (strcmp(nvpair_name(nvp), "flags") != 0 ||
			    nvpair_value_uint32(nvp, &setflags) != 0) {
				nvlist_free(nvl);
				return (EINVAL);
			}
			break;
		case DATA_TYPE_NVLIST_ARRAY:
			if (strcmp(nvpair_name(nvp), "reqs") != 0 ||
			    nvpair_value_nvlist_array(nvp, &reqlist,
			    &nreqs) != 0) {
				nvlist_free(nvl);
				return (EINVAL);
			}
			break;
		default:
			nvlist_free(nvl);
			return (EINVAL);
		}
		i++;
	}

	/*
	 * There should be two members in the top-level nvlist:
	 * an array of nvlists consisting of the requests, and flags.
	 * Anything else is an invalid set.
	 */
	if (i != 2) {
		nvlist_free(nvl);
		return (EINVAL);
	}

	if (nreqs > CPC_MAX_NREQS) {
		nvlist_free(nvl);
		return (EINVAL);
	}

	/*
	 * The requests are now stored in the nvlist array at reqlist.
	 * Note that the use of kmem_zalloc() to alloc the kcpc_set_t means
	 * we don't need to call the init routines for ks_lock and ks_condv.
	 */
	set = kmem_zalloc(sizeof (kcpc_set_t), KM_SLEEP);
	set->ks_req = (kcpc_request_t *)kmem_zalloc(sizeof (kcpc_request_t) *
	    nreqs, KM_SLEEP);
	set->ks_nreqs = nreqs;
	/*
	 * If the nvlist didn't contain a flags member, setflags was initialized
	 * with an illegal value and this set will fail sanity checks later on.
	 */
	set->ks_flags = setflags;
	/*
	 * Initialize bind/unbind set synchronization.
	 */
	set->ks_state &= ~KCPC_SET_BOUND;

	/*
	 * Build the set up one request at a time, always keeping it self-
	 * consistent so we can give it to kcpc_free_set() if we need to back
	 * out and return and error.
	 */
	for (i = 0; i < nreqs; i++) {
		nvp = NULL;
		set->ks_req[i].kr_picnum = -1;
		while ((nvp = nvlist_next_nvpair(reqlist[i], nvp)) != NULL) {
			name = nvpair_name(nvp);
			switch (nvpair_type(nvp)) {
			case DATA_TYPE_UINT32:
				if (nvpair_value_uint32(nvp, &uint32) == EINVAL)
					goto inval;
				if (strcmp(name, "cr_flags") == 0)
					set->ks_req[i].kr_flags = uint32;
				if (strcmp(name, "cr_index") == 0)
					set->ks_req[i].kr_index = uint32;
				break;
			case DATA_TYPE_UINT64:
				if (nvpair_value_uint64(nvp, &uint64) == EINVAL)
					goto inval;
				if (strcmp(name, "cr_preset") == 0)
					set->ks_req[i].kr_preset = uint64;
				break;
			case DATA_TYPE_STRING:
				if (nvpair_value_string(nvp, &string) == EINVAL)
					goto inval;
				if (strcmp(name, "cr_event") == 0)
					(void) strncpy(set->ks_req[i].kr_event,
					    string, CPC_MAX_EVENT_LEN);
				break;
			case DATA_TYPE_NVLIST:
				if (strcmp(name, "cr_attr") != 0)
					goto inval;
				if (nvpair_value_nvlist(nvp, &attrs) == EINVAL)
					goto inval;
				nvp_attr = NULL;
				/*
				 * If the picnum has been specified as an
				 * attribute, consume that attribute here and
				 * remove it from the list of attributes.
				 */
				if (nvlist_lookup_uint64(attrs, "picnum",
				    &uint64) == 0) {
					if (nvlist_remove(attrs, "picnum",
					    DATA_TYPE_UINT64) != 0)
						panic("nvlist %p faulty",
						    (void *)attrs);
					set->ks_req[i].kr_picnum = uint64;
				}

				if ((set->ks_req[i].kr_nattrs =
				    kcpc_nvlist_npairs(attrs)) == 0)
					break;

				if (set->ks_req[i].kr_nattrs > CPC_MAX_ATTRS)
					goto inval;

				set->ks_req[i].kr_attr =
				    kmem_alloc(set->ks_req[i].kr_nattrs *
				    sizeof (kcpc_attr_t), KM_SLEEP);
				j = 0;

				while ((nvp_attr = nvlist_next_nvpair(attrs,
				    nvp_attr)) != NULL) {
					attrp = &set->ks_req[i].kr_attr[j];

					if (nvpair_type(nvp_attr) !=
					    DATA_TYPE_UINT64)
						goto inval;

					(void) strncpy(attrp->ka_name,
					    nvpair_name(nvp_attr),
					    CPC_MAX_ATTR_LEN);

					if (nvpair_value_uint64(nvp_attr,
					    &(attrp->ka_val)) == EINVAL)
						goto inval;
					j++;
				}
				ASSERT(j == set->ks_req[i].kr_nattrs);
			default:
				break;
			}
		}
	}

	nvlist_free(nvl);
	*inset = set;
	return (0);

inval:
	nvlist_free(nvl);
	kcpc_free_set(set);
	return (EINVAL);
}

/*
 * Count the number of nvpairs in the supplied nvlist.
 */
static uint32_t
kcpc_nvlist_npairs(nvlist_t *list)
{
	nvpair_t *nvp = NULL;
	uint32_t n = 0;

	while ((nvp = nvlist_next_nvpair(list, nvp)) != NULL)
		n++;

	return (n);
}

/*
 * Performs sanity checks on the given set.
 * Returns 0 if the set checks out OK.
 * Returns a detailed error subcode, or -1 if there is no applicable subcode.
 */
static int
kcpc_verify_set(kcpc_set_t *set)
{
	kcpc_request_t	*rp;
	int		i;
	uint64_t	bitmap = 0;
	int		n;

	if (set->ks_nreqs > cpc_ncounters)
		return (-1);

	if (CPC_SET_VALID_FLAGS(set->ks_flags) == 0)
		return (-1);

	for (i = 0; i < set->ks_nreqs; i++) {
		rp = &set->ks_req[i];

		/*
		 * The following comparison must cast cpc_ncounters to an int,
		 * because kr_picnum will be -1 if the request didn't explicitly
		 * choose a PIC.
		 */
		if (rp->kr_picnum >= (int)cpc_ncounters)
			return (CPC_INVALID_PICNUM);

		/*
		 * Of the pics whose physical picnum has been specified, make
		 * sure each PIC appears only once in set.
		 */
		if ((n = set->ks_req[i].kr_picnum) != -1) {
			if ((bitmap & (1 << n)) != 0)
				return (-1);
			bitmap |= (1 << n);
		}

		/*
		 * Make sure the requested index falls within the range of all
		 * requests.
		 */
		if (rp->kr_index < 0 || rp->kr_index >= set->ks_nreqs)
			return (-1);

		/*
		 * Make sure there are no unknown flags.
		 */
		if (KCPC_REQ_VALID_FLAGS(rp->kr_flags) == 0)
			return (CPC_REQ_INVALID_FLAGS);
	}

	return (0);
}

static struct cb_ops cb_ops = {
	kcpc_open,
	kcpc_close,
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	kcpc_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_NEW | D_MP
};

/*ARGSUSED*/
static int
kcpc_probe(dev_info_t *devi)
{
	return (DDI_PROBE_SUCCESS);
}

static dev_info_t *kcpc_devi;

static int
kcpc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	kcpc_devi = devi;
	return (ddi_create_minor_node(devi, "shared", S_IFCHR,
	    KCPC_MINOR_SHARED, DDI_PSEUDO, 0));
}

/*ARGSUSED*/
static int
kcpc_getinfo(dev_info_t *devi, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		switch (getminor((dev_t)arg)) {
		case KCPC_MINOR_SHARED:
			*result = kcpc_devi;
			return (DDI_SUCCESS);
		default:
			break;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		return (DDI_SUCCESS);
	default:
		break;
	}

	return (DDI_FAILURE);
}

static struct dev_ops dev_ops = {
	DEVO_REV,
	0,
	kcpc_getinfo,
	nulldev,		/* identify */
	kcpc_probe,
	kcpc_attach,
	nodev,			/* detach */
	nodev,			/* reset */
	&cb_ops,
	(struct bus_ops *)0
};

static struct modldrv modldrv = {
	&mod_driverops,
	"cpc sampling driver",
	&dev_ops
};

static struct sysent cpc_sysent = {
	5,
	SE_NOUNLOAD | SE_ARGC | SE_32RVAL1,
	cpc
};

static struct modlsys modlsys = {
	&mod_syscallops,
	"cpc sampling system call",
	&cpc_sysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"32-bit cpc sampling system call",
	&cpc_sysent
};
#endif

static struct modlinkage modl = {
	MODREV_1,
	&modldrv,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
};

static void
kcpc_init(void)
{
	long hash;

	rw_init(&kcpc_cpuctx_lock, NULL, RW_DEFAULT, NULL);
	for (hash = 0; hash < CPC_HASH_BUCKETS; hash++)
		mutex_init(&kcpc_ctx_llock[hash],
		    NULL, MUTEX_DRIVER, (void *)(uintptr_t)15);
}

static void
kcpc_fini(void)
{
	long hash;

	for (hash = 0; hash < CPC_HASH_BUCKETS; hash++)
		mutex_destroy(&kcpc_ctx_llock[hash]);
	rw_destroy(&kcpc_cpuctx_lock);
}

int
_init(void)
{
	int ret;

	if (kcpc_hw_load_pcbe() != 0)
		return (ENOTSUP);

	kcpc_init();
	if ((ret = mod_install(&modl)) != 0)
		kcpc_fini();
	return (ret);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modl)) == 0)
		kcpc_fini();
	return (ret);
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&modl, mi));
}
