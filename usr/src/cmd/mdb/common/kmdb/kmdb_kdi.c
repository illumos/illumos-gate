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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The KDI, or kernel/debugger interface, is used to allow the kernel and the
 * debugger to communicate.  These communications take two forms:
 *
 *  1. kernel to debugger.  Interfaces of this type are used by the kernel to
 *     inform the debugger of changes in the state of the system that need to
 *     be noted by the debugger.  For example, the kernel uses one of these
 *     interfaces to tell debugger that the set of currently-loaded modules
 *     has changed.
 *
 *  2. debugger to kernel.  Interfaces of this type are used by the debugger
 *     to extract information from the kernel that would otherwise be difficult
 *     to get, or to perform services that are specific to the machine being
 *     used.  An example of the former is the module iterator, which is needed
 *     to allow symbol resolution, but which needs to resolve symbols prior
 *     to the iteration.  The latter class include machine-specific or
 *     cpu-type-specific functions, such as the I-cache flusher.  By directly
 *     using the kernel versions of these functions, we avoid the need to
 *     include multiple versions of each function - one per cpu and/or machine -
 *     in kmdb.
 */

#include <sys/kdi_impl.h>

#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_kvm.h>
#include <kmdb/kmdb_promif.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

static int kdi_unload_request;

typedef struct mod_interp_data {
	int	(*mid_usercb)(struct modctl *, void *);
	void	*mid_userarg;
	jmp_buf mid_pcb;
	jmp_buf *mid_oldpcb;
} mod_interp_data_t;

static kmdb_auxv_t *kdi_auxv;

int
kmdb_kdi_mods_changed(void)
{
	return (mdb.m_kdi->kdi_mods_changed());
}

static int
kmdb_kdi_mod_interp(struct modctl *mp, void *arg)
{
	mod_interp_data_t *mid = arg;
	int rc;

	kmdb_dpi_restore_fault_hdlr(mid->mid_oldpcb);
	rc = mid->mid_usercb(mp, mid->mid_userarg);
	mid->mid_oldpcb = kmdb_dpi_set_fault_hdlr(&mid->mid_pcb);

	return (rc);
}

/*
 * We need to protect ourselves against any problems that may occur while
 * executing the module iterator, currently located in krtld.  If, for
 * example, one of the next pointers in the module list points to an invalid
 * address, we don't want kmdb to explode.  As such, we protect ourselves
 * with the DPI fault-protection routines.  We don't want our fault-protection
 * callback to protect the callback that the kmdb consumer provided, so we
 * provide our own interposition callback that removes our fault-protector
 * before invoking the user's callback.
 */
int
kmdb_kdi_mod_iter(int (*cb)(struct modctl *, void *), void *arg)
{
	mod_interp_data_t mid;
	int rc;

	if (setjmp(mid.mid_pcb) != 0) {
		/* We took a fault while iterating through the modules */
		kmdb_dpi_restore_fault_hdlr(mid.mid_oldpcb);
		return (-1);
	}

	mid.mid_usercb = cb;
	mid.mid_userarg = arg;
	mid.mid_oldpcb = kmdb_dpi_set_fault_hdlr(&mid.mid_pcb);

	rc = mdb.m_kdi->kdi_mod_iter(kmdb_kdi_mod_interp, &mid);

	kmdb_dpi_restore_fault_hdlr(mid.mid_oldpcb);

	return (rc);
}

int
kmdb_kdi_mod_isloaded(struct modctl *modp)
{
	return (mdb.m_kdi->kdi_mod_isloaded(modp));
}

int
kmdb_kdi_mod_haschanged(struct modctl *mc1, struct module *mp1,
    struct modctl *mc2, struct module *mp2)
{
	return (mdb.m_kdi->kdi_mod_haschanged(mc1, mp1, mc2, mp2));
}

static ssize_t
kdi_prw(void *buf, size_t nbytes, physaddr_t addr, int (*rw)(caddr_t, size_t,
    physaddr_t, size_t *))
{
	size_t sz;
	int rc;

	kmdb_dpi_flush_slave_caches();
	if ((rc = rw(buf, nbytes, addr, &sz)) != 0)
		return (set_errno(rc));

	return (sz);
}

ssize_t
kmdb_kdi_pread(void *buf, size_t nbytes, physaddr_t addr)
{
	return (kdi_prw(buf, nbytes, addr, mdb.m_kdi->kdi_pread));
}

ssize_t
kmdb_kdi_pwrite(void *buf, size_t nbytes, physaddr_t addr)
{
	return (kdi_prw(buf, nbytes, addr, mdb.m_kdi->kdi_pwrite));
}

void
kmdb_kdi_flush_caches(void)
{
	mdb.m_kdi->kdi_flush_caches();
}

int
kmdb_kdi_get_unload_request(void)
{
	return (kdi_unload_request);
}

void
kmdb_kdi_set_unload_request(void)
{
	kdi_unload_request = 1;
}

int
kmdb_kdi_get_flags(void)
{
	uint_t flags = 0;

	if (mdb.m_flags & MDB_FL_NOCTF)
		flags |= KMDB_KDI_FL_NOCTF;
	if (mdb.m_flags & MDB_FL_NOMODS)
		flags |= KMDB_KDI_FL_NOMODS;

	return (flags);
}

size_t
kmdb_kdi_range_is_nontoxic(uintptr_t va, size_t sz, int write)
{
	return (mdb.m_kdi->kdi_range_is_nontoxic(va, sz, write));
}

void
kmdb_kdi_system_claim(void)
{
	(void) kmdb_dpi_call((uintptr_t)mdb.m_kdi->kdi_system_claim, 0, NULL);
	kmdb_prom_debugger_entry();
}

void
kmdb_kdi_system_release(void)
{
	kmdb_prom_debugger_exit();

	if (mdb.m_kdi->kdi_system_release != NULL) {
		(void) kmdb_dpi_call((uintptr_t)mdb.m_kdi->kdi_system_release,
		    0, NULL);
	}
}

struct cons_polledio *
kmdb_kdi_get_polled_io(void)
{
	return (mdb.m_kdi->kdi_get_polled_io());
}

void
kmdb_kdi_kmdb_enter(void)
{
	mdb.m_kdi->kdi_kmdb_enter();
}

int
kmdb_kdi_vtop(uintptr_t va, physaddr_t *pap)
{
	jmp_buf pcb, *oldpcb;
	int rc = 0;

	if (setjmp(pcb) == 0) {
		int err;

		oldpcb = kmdb_dpi_set_fault_hdlr(&pcb);

		if ((err = mdb.m_kdi->kdi_vtop(va, pap)) != 0)
			rc = set_errno(err == ENOENT ? EMDB_NOMAP : err);
	} else {
		/* We faulted during the translation */
		rc = set_errno(EMDB_NOMAP);
	}

	kmdb_dpi_restore_fault_hdlr(oldpcb);

	return (rc);
}

kdi_dtrace_state_t
kmdb_kdi_dtrace_get_state(void)
{
	return (mdb.m_kdi->kdi_dtrace_get_state());
}

int
kmdb_kdi_dtrace_set(int state)
{
	int err;

	if ((err = mdb.m_kdi->kdi_dtrace_set(state)) != 0)
		return (set_errno(err));

	return (0);
}

/*
 * This function is to be called only during kmdb initialization, as it
 * uses the running kernel for symbol translation facilities.
 */
uintptr_t
kmdb_kdi_lookup_by_name(char *modname, char *symname)
{
	ASSERT(kmdb_dpi_get_state(NULL) == DPI_STATE_INIT);

	return (kdi_auxv->kav_lookup_by_name(modname, symname));
}

void
kmdb_kdi_init(kdi_t *kdi, kmdb_auxv_t *kav)
{
	mdb.m_kdi = kdi;
	mdb.m_pagesize = kav->kav_pagesize;

	kdi_unload_request = 0;

	kdi_auxv = kav;

	kmdb_kdi_init_isadep(kdi, kav);
}

void
kmdb_kdi_end_init(void)
{
	kdi_auxv = NULL;
}
