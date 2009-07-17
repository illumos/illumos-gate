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
 */

#include <sys/cpu_module.h>
#include <sys/lockstat.h>

/*
 * This is a dummy file that provides the default cpu module
 * that is linked to unix.
 */

uint_t	root_phys_addr_lo_mask;
int64_t timedelta;
hrtime_t hres_last_tick;
volatile timestruc_t hrestime;
int64_t hrestime_adj;
volatile int hres_lock;
uint_t nsec_scale;
uint_t nsec_shift;
uint_t adj_shift;
hrtime_t hrtime_base;
int traptrace_use_stick;
uint_t cpu_impl_dual_pgsz;

void
cpu_setup(void)
{}

void
cpu_init_tick_freq(void)
{}

/*ARGSUSED*/
void
vtag_flushpage(caddr_t addr, uint64_t sfmmup)
{}

void
vtag_flushall(void)
{}

void
vtag_flushall_uctxs(void)
{}

/*ARGSUSED*/
void
vtag_flushpage_tl1(uint64_t addr, uint64_t sfmmup)
{}

/*ARGSUSED*/
void
vtag_flush_pgcnt_tl1(uint64_t addr, uint64_t sfmmup_pgcnt)
{}

/*ARGSUSED*/
void
vtag_flushall_tl1(uint64_t dummy1, uint64_t dummy2)
{}

/*ARGSUSED*/
void
vtag_unmap_perm_tl1(uint64_t addr, uint64_t ctx)
{}

/*ARGSUSED*/
void
vac_flushpage(pfn_t pf, int color)
{}

/*ARGSUSED*/
void
vac_flushpage_tl1(uint64_t pf, uint64_t color)
{}

/*ARGSUSED*/
void
vac_flushcolor(int color, pfn_t pf)
{}

/*ARGSUSED*/
void
vac_flushcolor_tl1(uint64_t color, uint64_t dummy)
{}

/*ARGSUSED*/
void
init_mondo(xcfunc_t func, uint64_t arg1, uint64_t arg2)
{}

/*ARGSUSED*/
void
send_one_mondo(int cpuid)
{}

/*ARGSUSED*/
void
send_mondo_set(cpuset_t set)
{}

/*ARGSUSED*/
void
flush_instr_mem(caddr_t addr, size_t len)
{}

void
syncfpu(void)
{}

/*ARGSUSED*/
void
cpu_change_speed(uint64_t divisor, uint64_t arg2)
{}

u_longlong_t
gettick(void)
{ return (0); }

uint64_t
gettick_counter(void)
{ return (0); }

/*ARGSUSED*/
void
gethrestime(timespec_t *tp)
{}

time_t
gethrestime_sec(void)
{ return (0); }

/*ARGSUSED*/
void
gethrestime_lasttick(timespec_t *tp)
{}

hrtime_t
gethrtime(void)
{ return (0); }

hrtime_t
gethrtime_unscaled(void)
{ return (0); }

hrtime_t
gethrtime_waitfree(void)
{ return (0); }

hrtime_t
dtrace_gethrtime(void)
{ return (0); }

uint_t
get_impl(void)
{ return (0); }

hrtime_t
get_hrestime(void)
{ return (0); }

ulong_t
get_timestamp(void)
{ return (0); }

ulong_t
get_virtime(void)
{ return (0); }

hrtime_t
gethrtime_max(void)
{ return (0); }

/*ARGSUSED*/
void
scalehrtime(hrtime_t *hrt)
{}

void
hres_tick(void)
{}

/*ARGSUSED*/
void
tickcmpr_set(uint64_t clock_cycles)
{}

void
tickcmpr_disable(void)
{}

/*ARGSUSED*/
void
tick_write_delta(uint64_t delta)
{}

int
tickcmpr_disabled(void)
{ return (0); }

/*ARGSUSED*/
void
drv_usecwait(clock_t n)
{}

/*
 * Processor-optimized memory routines
 */
/*ARGSUSED*/
int
kcopy(const void *from, void *to, size_t count)
{ return (0); }

/*ARGSUSED*/
int
kcopy_nta(const void *from, void *to, size_t count, int dummy)
{ return (0); }

/*ARGSUSED*/
void
bcopy(const void *from, void *to, size_t count)
{}

/*ARGSUSED*/
void
ovbcopy(const void *from, void *to, size_t count)
{}

/*ARGSUSED*/
int
copyin(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

/*ARGSUSED*/
int
xcopyin(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

/*ARGSUSED*/
int
xcopyin_nta(const void *uaddr, void *kaddr, size_t count, int dummy)
{ return (0); }

/*ARGSUSED*/
int
copyout(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

/*ARGSUSED*/
int
xcopyout(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

/*ARGSUSED*/
int
xcopyout_nta(const void *kaddr, void *uaddr, size_t count, int dummy)
{ return (0); }

/*ARGSUSED*/
void
copyout_noerr(const void *kfrom, void *uto, size_t count)
{}

/*ARGSUSED*/
void
copyin_noerr(const void *kfrom, void *uto, size_t count)
{}

/*ARGSUSED*/
int
xcopyin_little(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

/*ARGSUSED*/
int
xcopyout_little(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

/*ARGSUSED*/
void
hwblkpagecopy(const void *src, void *dst)
{}

/*ARGSUSED*/
void
hw_pa_bcopy32(uint64_t src, uint64_t dst)
{}

/*ARGSUSED*/
int
hwblkclr(void *addr, size_t len)
{ return (0); }

int use_hw_bzero;
int use_hw_bcopy;
uint_t hw_copy_limit_1;
uint_t hw_copy_limit_2;
uint_t hw_copy_limit_4;
uint_t hw_copy_limit_8;

/*
 * tick operations
 */

void
tick_rtt(void)
{ }

void
pil14_interrupt(void)
{ }

void
pil15_interrupt(void)
{ }

/* ARGSUSED */
void
cpu_init_private(struct cpu *cp)
{}

/* ARGSUSED */
void
cpu_uninit_private(struct cpu *cp)
{}

void
sticksync_slave(void)
{}

void
sticksync_master(void)
{}

/*ARGSUSED*/
int
dtrace_blksuword32(uintptr_t addr, uint32_t *data, int tryagain)
{ return (-1); }
