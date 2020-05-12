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

/*
 * SPARC-specific portions of the KDI
 */

#include <sys/types.h>
#include <sys/kdi_impl.h>

#include <kmdb/kaif.h>
#include <kmdb/kmdb_dpi.h>
#include <kmdb/kmdb_promif.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb.h>

#define	KDI_XC_RETRIES			10

static size_t kdi_dcache_size;
static size_t kdi_dcache_linesize;
static size_t kdi_icache_size;
static size_t kdi_icache_linesize;

static uint_t kdi_max_cpu_freq;
static uint_t kdi_sticks_per_usec;

/* XXX	needs to go into a header */

void
kdi_usecwait(clock_t n)
{
	mdb.m_kdi->mkdi_tickwait(n * kdi_sticks_per_usec);
}

static int
kdi_cpu_ready_iter(int (*cb)(int, void *), void *arg)
{
	return (mdb.m_kdi->mkdi_cpu_ready_iter(cb, arg));
}

static int
kdi_xc_one(int cpuid, void (*cb)(void))
{
	return (mdb.m_kdi->mkdi_xc_one(cpuid, (void (*)())cb, (uintptr_t)NULL,
	    (uintptr_t)NULL));
}

/*ARGSUSED1*/
static int
kdi_init_cpus_cb(pnode_t node, void *arg, void *result)
{
	/*
	 * Sun4v dosen't support virtual address cache
	 */
#ifndef	sun4v
	int dcache_size, dcache_linesize;
	int icache_size, icache_linesize;
#endif
	int cpu_freq;

#ifndef	sun4v
	/* Get the real cpu property node if needed */
	node = kmdb_prom_getcpu_propnode(node);

	/*
	 * data cache
	 */

	if (kmdb_prom_getprop(node, "dcache-size",
	    (caddr_t)&dcache_size) == -1 &&
	    kmdb_prom_getprop(node, "l1-dcache-size",
	    (caddr_t)&dcache_size) == -1)
		fail("can't get dcache size for node %x\n", node);

	if (kdi_dcache_size == 0 || dcache_size > kdi_dcache_size)
		kdi_dcache_size = dcache_size;

	if (kmdb_prom_getprop(node, "dcache-line-size",
	    (caddr_t)&dcache_linesize) == -1 &&
	    kmdb_prom_getprop(node, "l1-dcache-line-size",
	    (caddr_t)&dcache_linesize) == -1)
		fail("can't get dcache line size for node %x\n", node);

	if (kdi_dcache_linesize == 0 || dcache_linesize < kdi_dcache_linesize)
		kdi_dcache_linesize = dcache_linesize;

	/*
	 * instruction cache
	 */

	if (kmdb_prom_getprop(node, "icache-size",
	    (caddr_t)&icache_size) == -1 &&
	    kmdb_prom_getprop(node, "l1-icache-size",
	    (caddr_t)&icache_size) == -1)
		fail("can't get icache size for node %x\n", node);

	if (kdi_icache_size == 0 || icache_size > kdi_icache_size)
		kdi_icache_size = icache_size;

	if (kmdb_prom_getprop(node, "icache-line-size",
	    (caddr_t)&icache_linesize) == -1 &&
	    kmdb_prom_getprop(node, "l1-icache-line-size",
	    (caddr_t)&icache_linesize) == -1)
		fail("can't get icache size for node %x\n", node);

	if (kdi_icache_linesize == 0 || icache_linesize < kdi_icache_linesize)
		kdi_icache_linesize = icache_linesize;
#endif

	if (kmdb_prom_getprop(node, "clock-frequency",
	    (caddr_t)&cpu_freq) == -1) {
		fail("can't get cpu frequency for node %x\n", node);
	}

	kdi_max_cpu_freq = MAX(kdi_max_cpu_freq, cpu_freq);

	return (0);
}

/*
 * Called on an individual CPU.  Tries to send it off to the state saver if it
 * hasn't already entered the debugger.  Returns non-zero if it *fails* to stop
 * the CPU.
 */
static int
kdi_halt_cpu(int cpuid, void *state_saverp)
{
	void (*state_saver)(void) = (void (*)(void))state_saverp;
	int state = kmdb_dpi_get_cpu_state(cpuid);
	const char *msg;
	int rc = 0;
	int res;

	if (state != DPI_CPU_STATE_MASTER && state != DPI_CPU_STATE_SLAVE) {
		res = kdi_xc_one(cpuid, state_saver);
		rc = 1;

		if (res == KDI_XC_RES_OK)
			msg = "accepted the";
		else {
			if (res == KDI_XC_RES_BUSY)
				msg = "too busy for";
			else if (res == KDI_XC_RES_NACK)
				msg = "NACKED the";
			else
				msg = "errored the";
		}
		mdb_dprintf(MDB_DBG_KDI, "CPU %d %s halt\n", cpuid, msg);
	}

	return (rc);
}

/*ARGSUSED1*/
static int
kdi_report_unhalted(int cpuid, void *junk)
{
	int state = kmdb_dpi_get_cpu_state(cpuid);

	if (state != DPI_CPU_STATE_MASTER && state != DPI_CPU_STATE_SLAVE)
		mdb_warn("CPU %d: stop failed\n", cpuid);

	return (0);
}

/*ARGSUSED*/
void
kmdb_kdi_stop_slaves(int my_cpuid, int doxc)
{
	int i;

	for (i = 0; i < KDI_XC_RETRIES; i++) {
		if (kdi_cpu_ready_iter(kdi_halt_cpu,
		    (void *)kaif_slave_entry) == 0)
			break;

		kdi_usecwait(2000);
	}
	(void) kdi_cpu_ready_iter(kdi_report_unhalted, NULL);
}

void
kmdb_kdi_start_slaves(void)
{
}

void
kmdb_kdi_slave_wait(void)
{
}

int
kmdb_kdi_get_stick(uint64_t *stickp)
{
	return (mdb.m_kdi->mkdi_get_stick(stickp));
}

caddr_t
kmdb_kdi_get_trap_vatotte(void)
{
	return ((caddr_t)mdb.m_kdi->mkdi_trap_vatotte);
}

void
kmdb_kdi_kernpanic(struct regs *regs, uint_t tt)
{
	uintptr_t args[2];

	args[0] = (uintptr_t)regs;
	args[1] = tt;

	(void) kmdb_dpi_call((uintptr_t)mdb.m_kdi->mkdi_kernpanic, 2, args);
}

/*ARGSUSED*/
void
kmdb_kdi_init_isadep(kdi_t *kdi, kmdb_auxv_t *kav)
{
	kdi_dcache_size = kdi_dcache_linesize =
	    kdi_icache_size = kdi_icache_linesize = 0;

	kdi_max_cpu_freq = kdi_sticks_per_usec = 0;

	mdb_dprintf(MDB_DBG_KDI, "Initializing CPUs\n");

	kmdb_prom_walk_cpus(kdi_init_cpus_cb, NULL, NULL);

	/*
	 * If we can't find one, guess high.  The CPU frequency is going to be
	 * used to determine the length of various delays, such as the mondo
	 * interrupt retry delay.  Too long is generally better than too short.
	 */
	if (kdi_max_cpu_freq == 0) {
		mdb_dprintf(MDB_DBG_KDI, "No CPU freq found - assuming "
		    "500MHz\n");
		kdi_max_cpu_freq = 500 * MICROSEC;
	}

	kdi_sticks_per_usec =
	    MAX((kdi_max_cpu_freq + (MICROSEC - 1)) / MICROSEC, 1);

	mdb.m_kdi->mkdi_cpu_init(kdi_dcache_size, kdi_dcache_linesize,
	    kdi_icache_size, kdi_icache_linesize);

#ifndef sun4v
	kmdb_prom_preserve_kctx_init();
#endif /* sun4v */

}
