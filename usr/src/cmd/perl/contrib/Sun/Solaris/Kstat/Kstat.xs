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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014 Racktop Systems.
 */

/*
 * Kstat.xs is a Perl XS (eXStension module) that makes the Solaris
 * kstat(3KSTAT) facility available to Perl scripts.  Kstat is a general-purpose
 * mechanism  for  providing kernel statistics to users.  The Solaris API is
 * function-based (see the manpage for details), but for ease of use in Perl
 * scripts this module presents the information as a nested hash data structure.
 * It would be too inefficient to read every kstat in the system, so this module
 * uses the Perl TIEHASH mechanism to implement a read-on-demand semantic, which
 * only reads and updates kstats as and when they are actually accessed.
 */

/*
 * Ignored raw kstats.
 *
 * Some raw kstats are ignored by this module, these are listed below.  The
 * most common reason is that the kstats are stored as arrays and the ks_ndata
 * and/or ks_data_size fields are invalid.  In this case it is impossible to
 * know how many records are in the array, so they can't be read.
 *
 * unix:*:sfmmu_percpu_stat
 * This is stored as an array with one entry per cpu.  Each element is of type
 * struct sfmmu_percpu_stat.  The ks_ndata and ks_data_size fields are bogus.
 *
 * ufs directio:*:UFS DirectIO Stats
 * The structure definition used for these kstats (ufs_directio_kstats) is in a
 * C file (uts/common/fs/ufs/ufs_directio.c) rather than a header file, so it
 * isn't accessible.
 *
 * qlc:*:statistics
 * This is a third-party driver for which we don't have source.
 *
 * mm:*:phys_installed
 * This is stored as an array of uint64_t, with each pair of values being the
 * (address, size) of a memory segment.  The ks_ndata and ks_data_size fields
 * are both zero.
 *
 * sockfs:*:sock_unix_list
 * This is stored as an array with one entry per active socket.  Each element
 * is of type struct k_sockinfo.  The ks_ndata and ks_data_size fields are both
 * zero.
 *
 * Note that the ks_ndata and ks_data_size of many non-array raw kstats are
 * also incorrect.  The relevant assertions are therefore commented out in the
 * appropriate raw kstat read routines.
 */

/* Kstat related includes */
#include <libgen.h>
#include <kstat.h>
#include <sys/var.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <sys/flock.h>
#include <sys/dnlc.h>
#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>

/* Ultra-specific kstat includes */
#ifdef __sparc
#include <vm/hat_sfmmu.h>	/* from /usr/platform/sun4u/include */
#include <sys/simmstat.h>	/* from /usr/platform/sun4u/include */
#include <sys/sysctrl.h>	/* from /usr/platform/sun4u/include */
#include <sys/fhc.h>		/* from /usr/include */
#endif

/*
 * Solaris #defines SP, which conflicts with the perl definition of SP
 * We don't need the Solaris one, so get rid of it to avoid warnings
 */
#undef SP

/* Perl XS includes */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/* Debug macros */
#define	DEBUG_ID "Sun::Solaris::Kstat"
#ifdef KSTAT_DEBUG
#define	PERL_ASSERT(EXP) \
    ((void)((EXP) || (croak("%s: assertion failed at %s:%d: %s", \
    DEBUG_ID, __FILE__, __LINE__, #EXP), 0), 0))
#define	PERL_ASSERTMSG(EXP, MSG) \
    ((void)((EXP) || (croak(DEBUG_ID ": " MSG), 0), 0))
#else
#define	PERL_ASSERT(EXP)		((void)0)
#define	PERL_ASSERTMSG(EXP, MSG)	((void)0)
#endif

/* Macros for saving the contents of KSTAT_RAW structures */
#if defined(HAS_QUAD) && defined(USE_64_BIT_INT)
#define NEW_IV(V) \
    (newSViv((IVTYPE) V))
#define NEW_UV(V) \
    (newSVuv((UVTYPE) V))
#else
#define NEW_IV(V) \
    (V >= IV_MIN && V <= IV_MAX ? newSViv((IVTYPE) V) : newSVnv((NVTYPE) V))
#if defined(UVTYPE)
#define NEW_UV(V) \
    (V <= UV_MAX ? newSVuv((UVTYPE) V) : newSVnv((NVTYPE) V))
# else
#define NEW_UV(V) \
    (V <= IV_MAX ? newSViv((IVTYPE) V) : newSVnv((NVTYPE) V))
#endif
#endif
#define	NEW_HRTIME(V) \
    newSVnv((NVTYPE) (V / 1000000000.0))

#define	SAVE_FNP(H, F, K) \
    hv_store(H, K, sizeof (K) - 1, newSViv((IVTYPE)(uintptr_t)&F), 0)
#define	SAVE_STRING(H, S, K, SS) \
    hv_store(H, #K, sizeof (#K) - 1, \
    newSVpvn(S->K, SS ? strlen(S->K) : sizeof(S->K)), 0)
#define	SAVE_INT32(H, S, K) \
    hv_store(H, #K, sizeof (#K) - 1, NEW_IV(S->K), 0)
#define	SAVE_UINT32(H, S, K) \
    hv_store(H, #K, sizeof (#K) - 1, NEW_UV(S->K), 0)
#define	SAVE_INT64(H, S, K) \
    hv_store(H, #K, sizeof (#K) - 1, NEW_IV(S->K), 0)
#define	SAVE_UINT64(H, S, K) \
    hv_store(H, #K, sizeof (#K) - 1, NEW_UV(S->K), 0)
#define	SAVE_HRTIME(H, S, K) \
    hv_store(H, #K, sizeof (#K) - 1, NEW_HRTIME(S->K), 0)

/* Private structure used for saving kstat info in the tied hashes */
typedef struct {
	char		read;		/* Kstat block has been read before */
	char		valid;		/* Kstat still exists in kstat chain */
	char		strip_str;	/* Strip KSTAT_DATA_CHAR fields */
	kstat_ctl_t	*kstat_ctl;	/* Handle returned by kstat_open */
	kstat_t		*kstat;		/* Handle used by kstat_read */
} KstatInfo_t;

/* typedef for apply_to_ties callback functions */
typedef int (*ATTCb_t)(HV *, void *);

/* typedef for raw kstat reader functions */
typedef void (*kstat_raw_reader_t)(HV *, kstat_t *, int);

/* Hash of "module:name" to KSTAT_RAW read functions */
static HV *raw_kstat_lookup;

/*
 * Kstats come in two flavours, named and raw.  Raw kstats are just C structs,
 * so we need a function per raw kstat to convert the C struct into the
 * corresponding perl hash.  All such conversion functions are in the following
 * section.
 */

/*
 * Definitions in /usr/include/sys/cpuvar.h and /usr/include/sys/sysinfo.h
 */

static void
save_cpu_stat(HV *self, kstat_t *kp, int strip_str)
{
	cpu_stat_t    *statp;
	cpu_sysinfo_t *sysinfop;
	cpu_syswait_t *syswaitp;
	cpu_vminfo_t  *vminfop;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (cpu_stat_t));
	statp = (cpu_stat_t *)(kp->ks_data);
	sysinfop = &statp->cpu_sysinfo;
	syswaitp = &statp->cpu_syswait;
	vminfop  = &statp->cpu_vminfo;

	hv_store(self, "idle", 4, NEW_UV(sysinfop->cpu[CPU_IDLE]), 0);
	hv_store(self, "user", 4, NEW_UV(sysinfop->cpu[CPU_USER]), 0);
	hv_store(self, "kernel", 6, NEW_UV(sysinfop->cpu[CPU_KERNEL]), 0);
	hv_store(self, "wait", 4, NEW_UV(sysinfop->cpu[CPU_WAIT]), 0);
	hv_store(self, "wait_io", 7, NEW_UV(sysinfop->wait[W_IO]), 0);
	hv_store(self, "wait_swap", 9, NEW_UV(sysinfop->wait[W_SWAP]), 0);
	hv_store(self, "wait_pio",  8, NEW_UV(sysinfop->wait[W_PIO]), 0);
	SAVE_UINT32(self, sysinfop, bread);
	SAVE_UINT32(self, sysinfop, bwrite);
	SAVE_UINT32(self, sysinfop, lread);
	SAVE_UINT32(self, sysinfop, lwrite);
	SAVE_UINT32(self, sysinfop, phread);
	SAVE_UINT32(self, sysinfop, phwrite);
	SAVE_UINT32(self, sysinfop, pswitch);
	SAVE_UINT32(self, sysinfop, trap);
	SAVE_UINT32(self, sysinfop, intr);
	SAVE_UINT32(self, sysinfop, syscall);
	SAVE_UINT32(self, sysinfop, sysread);
	SAVE_UINT32(self, sysinfop, syswrite);
	SAVE_UINT32(self, sysinfop, sysfork);
	SAVE_UINT32(self, sysinfop, sysvfork);
	SAVE_UINT32(self, sysinfop, sysexec);
	SAVE_UINT32(self, sysinfop, readch);
	SAVE_UINT32(self, sysinfop, writech);
	SAVE_UINT32(self, sysinfop, rcvint);
	SAVE_UINT32(self, sysinfop, xmtint);
	SAVE_UINT32(self, sysinfop, mdmint);
	SAVE_UINT32(self, sysinfop, rawch);
	SAVE_UINT32(self, sysinfop, canch);
	SAVE_UINT32(self, sysinfop, outch);
	SAVE_UINT32(self, sysinfop, msg);
	SAVE_UINT32(self, sysinfop, sema);
	SAVE_UINT32(self, sysinfop, namei);
	SAVE_UINT32(self, sysinfop, ufsiget);
	SAVE_UINT32(self, sysinfop, ufsdirblk);
	SAVE_UINT32(self, sysinfop, ufsipage);
	SAVE_UINT32(self, sysinfop, ufsinopage);
	SAVE_UINT32(self, sysinfop, inodeovf);
	SAVE_UINT32(self, sysinfop, fileovf);
	SAVE_UINT32(self, sysinfop, procovf);
	SAVE_UINT32(self, sysinfop, intrthread);
	SAVE_UINT32(self, sysinfop, intrblk);
	SAVE_UINT32(self, sysinfop, idlethread);
	SAVE_UINT32(self, sysinfop, inv_swtch);
	SAVE_UINT32(self, sysinfop, nthreads);
	SAVE_UINT32(self, sysinfop, cpumigrate);
	SAVE_UINT32(self, sysinfop, xcalls);
	SAVE_UINT32(self, sysinfop, mutex_adenters);
	SAVE_UINT32(self, sysinfop, rw_rdfails);
	SAVE_UINT32(self, sysinfop, rw_wrfails);
	SAVE_UINT32(self, sysinfop, modload);
	SAVE_UINT32(self, sysinfop, modunload);
	SAVE_UINT32(self, sysinfop, bawrite);
#ifdef STATISTICS	/* see header file */
	SAVE_UINT32(self, sysinfop, rw_enters);
	SAVE_UINT32(self, sysinfop, win_uo_cnt);
	SAVE_UINT32(self, sysinfop, win_uu_cnt);
	SAVE_UINT32(self, sysinfop, win_so_cnt);
	SAVE_UINT32(self, sysinfop, win_su_cnt);
	SAVE_UINT32(self, sysinfop, win_suo_cnt);
#endif

	SAVE_INT32(self, syswaitp, iowait);
	SAVE_INT32(self, syswaitp, swap);
	SAVE_INT32(self, syswaitp, physio);

	SAVE_UINT32(self, vminfop, pgrec);
	SAVE_UINT32(self, vminfop, pgfrec);
	SAVE_UINT32(self, vminfop, pgin);
	SAVE_UINT32(self, vminfop, pgpgin);
	SAVE_UINT32(self, vminfop, pgout);
	SAVE_UINT32(self, vminfop, pgpgout);
	SAVE_UINT32(self, vminfop, swapin);
	SAVE_UINT32(self, vminfop, pgswapin);
	SAVE_UINT32(self, vminfop, swapout);
	SAVE_UINT32(self, vminfop, pgswapout);
	SAVE_UINT32(self, vminfop, zfod);
	SAVE_UINT32(self, vminfop, dfree);
	SAVE_UINT32(self, vminfop, scan);
	SAVE_UINT32(self, vminfop, rev);
	SAVE_UINT32(self, vminfop, hat_fault);
	SAVE_UINT32(self, vminfop, as_fault);
	SAVE_UINT32(self, vminfop, maj_fault);
	SAVE_UINT32(self, vminfop, cow_fault);
	SAVE_UINT32(self, vminfop, prot_fault);
	SAVE_UINT32(self, vminfop, softlock);
	SAVE_UINT32(self, vminfop, kernel_asflt);
	SAVE_UINT32(self, vminfop, pgrrun);
	SAVE_UINT32(self, vminfop, execpgin);
	SAVE_UINT32(self, vminfop, execpgout);
	SAVE_UINT32(self, vminfop, execfree);
	SAVE_UINT32(self, vminfop, anonpgin);
	SAVE_UINT32(self, vminfop, anonpgout);
	SAVE_UINT32(self, vminfop, anonfree);
	SAVE_UINT32(self, vminfop, fspgin);
	SAVE_UINT32(self, vminfop, fspgout);
	SAVE_UINT32(self, vminfop, fsfree);
}

/*
 * Definitions in /usr/include/sys/var.h
 */

static void
save_var(HV *self, kstat_t *kp, int strip_str)
{
	struct var *varp;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (struct var));
	varp = (struct var *)(kp->ks_data);

	SAVE_INT32(self, varp, v_buf);
	SAVE_INT32(self, varp, v_call);
	SAVE_INT32(self, varp, v_proc);
	SAVE_INT32(self, varp, v_maxupttl);
	SAVE_INT32(self, varp, v_nglobpris);
	SAVE_INT32(self, varp, v_maxsyspri);
	SAVE_INT32(self, varp, v_clist);
	SAVE_INT32(self, varp, v_maxup);
	SAVE_INT32(self, varp, v_hbuf);
	SAVE_INT32(self, varp, v_hmask);
	SAVE_INT32(self, varp, v_pbuf);
	SAVE_INT32(self, varp, v_sptmap);
	SAVE_INT32(self, varp, v_maxpmem);
	SAVE_INT32(self, varp, v_autoup);
	SAVE_INT32(self, varp, v_bufhwm);
}

/*
 * Definition in /usr/include/sys/dnlc.h
 */

static void
save_ncstats(HV *self, kstat_t *kp, int strip_str)
{
	struct ncstats *ncstatsp;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (struct ncstats));
	ncstatsp = (struct ncstats *)(kp->ks_data);

	SAVE_INT32(self, ncstatsp, hits);
	SAVE_INT32(self, ncstatsp, misses);
	SAVE_INT32(self, ncstatsp, enters);
	SAVE_INT32(self, ncstatsp, dbl_enters);
	SAVE_INT32(self, ncstatsp, long_enter);
	SAVE_INT32(self, ncstatsp, long_look);
	SAVE_INT32(self, ncstatsp, move_to_front);
	SAVE_INT32(self, ncstatsp, purges);
}

/*
 * Definition in  /usr/include/sys/sysinfo.h
 */

static void
save_sysinfo(HV *self, kstat_t *kp, int strip_str)
{
	sysinfo_t *sysinfop;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (sysinfo_t));
	sysinfop = (sysinfo_t *)(kp->ks_data);

	SAVE_UINT32(self, sysinfop, updates);
	SAVE_UINT32(self, sysinfop, runque);
	SAVE_UINT32(self, sysinfop, runocc);
	SAVE_UINT32(self, sysinfop, swpque);
	SAVE_UINT32(self, sysinfop, swpocc);
	SAVE_UINT32(self, sysinfop, waiting);
}

/*
 * Definition in  /usr/include/sys/sysinfo.h
 */

static void
save_vminfo(HV *self, kstat_t *kp, int strip_str)
{
	vminfo_t *vminfop;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (vminfo_t));
	vminfop = (vminfo_t *)(kp->ks_data);

	SAVE_UINT64(self, vminfop, freemem);
	SAVE_UINT64(self, vminfop, swap_resv);
	SAVE_UINT64(self, vminfop, swap_alloc);
	SAVE_UINT64(self, vminfop, swap_avail);
	SAVE_UINT64(self, vminfop, swap_free);
	SAVE_UINT64(self, vminfop, updates);
}

/*
 * Definition in /usr/include/nfs/nfs_clnt.h
 */

static void
save_nfs(HV *self, kstat_t *kp, int strip_str)
{
	struct mntinfo_kstat *mntinfop;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (struct mntinfo_kstat));
	mntinfop = (struct mntinfo_kstat *)(kp->ks_data);

	SAVE_STRING(self, mntinfop, mik_proto, strip_str);
	SAVE_UINT32(self, mntinfop, mik_vers);
	SAVE_UINT32(self, mntinfop, mik_flags);
	SAVE_UINT32(self, mntinfop, mik_secmod);
	SAVE_UINT32(self, mntinfop, mik_curread);
	SAVE_UINT32(self, mntinfop, mik_curwrite);
	SAVE_INT32(self, mntinfop, mik_timeo);
	SAVE_INT32(self, mntinfop, mik_retrans);
	SAVE_UINT32(self, mntinfop, mik_acregmin);
	SAVE_UINT32(self, mntinfop, mik_acregmax);
	SAVE_UINT32(self, mntinfop, mik_acdirmin);
	SAVE_UINT32(self, mntinfop, mik_acdirmax);
	hv_store(self, "lookup_srtt", 11,
	    NEW_UV(mntinfop->mik_timers[0].srtt), 0);
	hv_store(self, "lookup_deviate", 14,
	    NEW_UV(mntinfop->mik_timers[0].deviate), 0);
	hv_store(self, "lookup_rtxcur", 13,
	    NEW_UV(mntinfop->mik_timers[0].rtxcur), 0);
	hv_store(self, "read_srtt", 9,
	    NEW_UV(mntinfop->mik_timers[1].srtt), 0);
	hv_store(self, "read_deviate", 12,
	    NEW_UV(mntinfop->mik_timers[1].deviate), 0);
	hv_store(self, "read_rtxcur", 11,
	    NEW_UV(mntinfop->mik_timers[1].rtxcur), 0);
	hv_store(self, "write_srtt", 10,
	    NEW_UV(mntinfop->mik_timers[2].srtt), 0);
	hv_store(self, "write_deviate", 13,
	    NEW_UV(mntinfop->mik_timers[2].deviate), 0);
	hv_store(self, "write_rtxcur", 12,
	    NEW_UV(mntinfop->mik_timers[2].rtxcur), 0);
	SAVE_UINT32(self, mntinfop, mik_noresponse);
	SAVE_UINT32(self, mntinfop, mik_failover);
	SAVE_UINT32(self, mntinfop, mik_remap);
	SAVE_STRING(self, mntinfop, mik_curserver, strip_str);
}

/*
 * The following struct => hash functions are all only present on the sparc
 * platform, so they are all conditionally compiled depending on __sparc
 */

/*
 * Definition in /usr/platform/sun4u/include/vm/hat_sfmmu.h
 */

#ifdef __sparc
static void
save_sfmmu_global_stat(HV *self, kstat_t *kp, int strip_str)
{
	struct sfmmu_global_stat *sfmmugp;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (struct sfmmu_global_stat));
	sfmmugp = (struct sfmmu_global_stat *)(kp->ks_data);

	SAVE_INT32(self, sfmmugp, sf_tsb_exceptions);
	SAVE_INT32(self, sfmmugp, sf_tsb_raise_exception);
	SAVE_INT32(self, sfmmugp, sf_pagefaults);
	SAVE_INT32(self, sfmmugp, sf_uhash_searches);
	SAVE_INT32(self, sfmmugp, sf_uhash_links);
	SAVE_INT32(self, sfmmugp, sf_khash_searches);
	SAVE_INT32(self, sfmmugp, sf_khash_links);
	SAVE_INT32(self, sfmmugp, sf_swapout);
	SAVE_INT32(self, sfmmugp, sf_tsb_alloc);
	SAVE_INT32(self, sfmmugp, sf_tsb_allocfail);
	SAVE_INT32(self, sfmmugp, sf_tsb_sectsb_create);
	SAVE_INT32(self, sfmmugp, sf_scd_1sttsb_alloc);
	SAVE_INT32(self, sfmmugp, sf_scd_2ndtsb_alloc);
	SAVE_INT32(self, sfmmugp, sf_scd_1sttsb_allocfail);
	SAVE_INT32(self, sfmmugp, sf_scd_2ndtsb_allocfail);
	SAVE_INT32(self, sfmmugp, sf_tteload8k);
	SAVE_INT32(self, sfmmugp, sf_tteload64k);
	SAVE_INT32(self, sfmmugp, sf_tteload512k);
	SAVE_INT32(self, sfmmugp, sf_tteload4m);
	SAVE_INT32(self, sfmmugp, sf_tteload32m);
	SAVE_INT32(self, sfmmugp, sf_tteload256m);
	SAVE_INT32(self, sfmmugp, sf_tsb_load8k);
	SAVE_INT32(self, sfmmugp, sf_tsb_load4m);
	SAVE_INT32(self, sfmmugp, sf_hblk_hit);
	SAVE_INT32(self, sfmmugp, sf_hblk8_ncreate);
	SAVE_INT32(self, sfmmugp, sf_hblk8_nalloc);
	SAVE_INT32(self, sfmmugp, sf_hblk1_ncreate);
	SAVE_INT32(self, sfmmugp, sf_hblk1_nalloc);
	SAVE_INT32(self, sfmmugp, sf_hblk_slab_cnt);
	SAVE_INT32(self, sfmmugp, sf_hblk_reserve_cnt);
	SAVE_INT32(self, sfmmugp, sf_hblk_recurse_cnt);
	SAVE_INT32(self, sfmmugp, sf_hblk_reserve_hit);
	SAVE_INT32(self, sfmmugp, sf_get_free_success);
	SAVE_INT32(self, sfmmugp, sf_get_free_throttle);
	SAVE_INT32(self, sfmmugp, sf_get_free_fail);
	SAVE_INT32(self, sfmmugp, sf_put_free_success);
	SAVE_INT32(self, sfmmugp, sf_put_free_fail);
	SAVE_INT32(self, sfmmugp, sf_pgcolor_conflict);
	SAVE_INT32(self, sfmmugp, sf_uncache_conflict);
	SAVE_INT32(self, sfmmugp, sf_unload_conflict);
	SAVE_INT32(self, sfmmugp, sf_ism_uncache);
	SAVE_INT32(self, sfmmugp, sf_ism_recache);
	SAVE_INT32(self, sfmmugp, sf_recache);
	SAVE_INT32(self, sfmmugp, sf_steal_count);
	SAVE_INT32(self, sfmmugp, sf_pagesync);
	SAVE_INT32(self, sfmmugp, sf_clrwrt);
	SAVE_INT32(self, sfmmugp, sf_pagesync_invalid);
	SAVE_INT32(self, sfmmugp, sf_kernel_xcalls);
	SAVE_INT32(self, sfmmugp, sf_user_xcalls);
	SAVE_INT32(self, sfmmugp, sf_tsb_grow);
	SAVE_INT32(self, sfmmugp, sf_tsb_shrink);
	SAVE_INT32(self, sfmmugp, sf_tsb_resize_failures);
	SAVE_INT32(self, sfmmugp, sf_tsb_reloc);
	SAVE_INT32(self, sfmmugp, sf_user_vtop);
	SAVE_INT32(self, sfmmugp, sf_ctx_inv);
	SAVE_INT32(self, sfmmugp, sf_tlb_reprog_pgsz);
	SAVE_INT32(self, sfmmugp, sf_region_remap_demap);
	SAVE_INT32(self, sfmmugp, sf_create_scd);
	SAVE_INT32(self, sfmmugp, sf_join_scd);
	SAVE_INT32(self, sfmmugp, sf_leave_scd);
	SAVE_INT32(self, sfmmugp, sf_destroy_scd);
}
#endif

/*
 * Definition in /usr/platform/sun4u/include/vm/hat_sfmmu.h
 */

#ifdef __sparc
static void
save_sfmmu_tsbsize_stat(HV *self, kstat_t *kp, int strip_str)
{
	struct sfmmu_tsbsize_stat *sfmmutp;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (struct sfmmu_tsbsize_stat));
	sfmmutp = (struct sfmmu_tsbsize_stat *)(kp->ks_data);

	SAVE_INT32(self, sfmmutp, sf_tsbsz_8k);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_16k);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_32k);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_64k);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_128k);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_256k);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_512k);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_1m);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_2m);
	SAVE_INT32(self, sfmmutp, sf_tsbsz_4m);
}
#endif

/*
 * Definition in /usr/platform/sun4u/include/sys/simmstat.h
 */

#ifdef __sparc
static void
save_simmstat(HV *self, kstat_t *kp, int strip_str)
{
	uchar_t	*simmstatp;
	SV	*list;
	int	i;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (uchar_t) * SIMM_COUNT);

	list = newSVpv("", 0);
	for (i = 0, simmstatp = (uchar_t *)(kp->ks_data);
	i < SIMM_COUNT - 1; i++, simmstatp++) {
		sv_catpvf(list, "%d,", *simmstatp);
	}
	sv_catpvf(list, "%d", *simmstatp);
	hv_store(self, "status", 6, list, 0);
}
#endif

/*
 * Used by save_temperature to make CSV lists from arrays of
 * short temperature values
 */

#ifdef __sparc
static SV *
short_array_to_SV(short *shortp, int len)
{
	SV  *list;

	list = newSVpv("", 0);
	for (; len > 1; len--, shortp++) {
		sv_catpvf(list, "%d,", *shortp);
	}
	sv_catpvf(list, "%d", *shortp);
	return (list);
}

/*
 * Definition in /usr/platform/sun4u/include/sys/fhc.h
 */

static void
save_temperature(HV *self, kstat_t *kp, int strip_str)
{
	struct temp_stats *tempsp;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (struct temp_stats));
	tempsp = (struct temp_stats *)(kp->ks_data);

	SAVE_UINT32(self, tempsp, index);
	hv_store(self, "l1", 2, short_array_to_SV(tempsp->l1, L1_SZ), 0);
	hv_store(self, "l2", 2, short_array_to_SV(tempsp->l2, L2_SZ), 0);
	hv_store(self, "l3", 2, short_array_to_SV(tempsp->l3, L3_SZ), 0);
	hv_store(self, "l4", 2, short_array_to_SV(tempsp->l4, L4_SZ), 0);
	hv_store(self, "l5", 2, short_array_to_SV(tempsp->l5, L5_SZ), 0);
	SAVE_INT32(self, tempsp, max);
	SAVE_INT32(self, tempsp, min);
	SAVE_INT32(self, tempsp, state);
	SAVE_INT32(self, tempsp, temp_cnt);
	SAVE_INT32(self, tempsp, shutdown_cnt);
	SAVE_INT32(self, tempsp, version);
	SAVE_INT32(self, tempsp, trend);
	SAVE_INT32(self, tempsp, override);
}
#endif

/*
 * Not actually defined anywhere - just a short.  Yuck.
 */

#ifdef __sparc
static void
save_temp_over(HV *self, kstat_t *kp, int strip_str)
{
	short *shortp;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == sizeof (short));

	shortp = (short *)(kp->ks_data);
	hv_store(self, "override", 8, newSViv(*shortp), 0);
}
#endif

/*
 * Defined in /usr/platform/sun4u/include/sys/sysctrl.h
 * (Well, sort of.  Actually there's no structure, just a list of #defines
 * enumerating *some* of the array indexes.)
 */

#ifdef __sparc
static void
save_ps_shadow(HV *self, kstat_t *kp, int strip_str)
{
	uchar_t *ucharp;

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	PERL_ASSERT(kp->ks_data_size == SYS_PS_COUNT);

	ucharp = (uchar_t *)(kp->ks_data);
	hv_store(self, "core_0", 6, newSViv(*ucharp++), 0);
	hv_store(self, "core_1", 6, newSViv(*ucharp++), 0);
	hv_store(self, "core_2", 6, newSViv(*ucharp++), 0);
	hv_store(self, "core_3", 6, newSViv(*ucharp++), 0);
	hv_store(self, "core_4", 6, newSViv(*ucharp++), 0);
	hv_store(self, "core_5", 6, newSViv(*ucharp++), 0);
	hv_store(self, "core_6", 6, newSViv(*ucharp++), 0);
	hv_store(self, "core_7", 6, newSViv(*ucharp++), 0);
	hv_store(self, "pps_0", 5, newSViv(*ucharp++), 0);
	hv_store(self, "clk_33", 6, newSViv(*ucharp++), 0);
	hv_store(self, "clk_50", 6, newSViv(*ucharp++), 0);
	hv_store(self, "v5_p", 4, newSViv(*ucharp++), 0);
	hv_store(self, "v12_p", 5, newSViv(*ucharp++), 0);
	hv_store(self, "v5_aux", 6, newSViv(*ucharp++), 0);
	hv_store(self, "v5_p_pch", 8, newSViv(*ucharp++), 0);
	hv_store(self, "v12_p_pch", 9, newSViv(*ucharp++), 0);
	hv_store(self, "v3_pch", 6, newSViv(*ucharp++), 0);
	hv_store(self, "v5_pch", 6, newSViv(*ucharp++), 0);
	hv_store(self, "p_fan", 5, newSViv(*ucharp++), 0);
}
#endif

/*
 * Definition in /usr/platform/sun4u/include/sys/fhc.h
 */

#ifdef __sparc
static void
save_fault_list(HV *self, kstat_t *kp, int strip_str)
{
	struct ft_list	*faultp;
	int		i;
	char		name[KSTAT_STRLEN + 7];	/* room for 999999 faults */

	/* PERL_ASSERT(kp->ks_ndata == 1); */
	/* PERL_ASSERT(kp->ks_data_size == sizeof (struct ft_list)); */

	for (i = 1, faultp = (struct ft_list *)(kp->ks_data);
	    i <= 999999 && i <= kp->ks_data_size / sizeof (struct ft_list);
	    i++, faultp++) {
		(void) snprintf(name, sizeof (name), "unit_%d", i);
		hv_store(self, name, strlen(name), newSViv(faultp->unit), 0);
		(void) snprintf(name, sizeof (name), "type_%d", i);
		hv_store(self, name, strlen(name), newSViv(faultp->type), 0);
		(void) snprintf(name, sizeof (name), "fclass_%d", i);
		hv_store(self, name, strlen(name), newSViv(faultp->fclass), 0);
		(void) snprintf(name, sizeof (name), "create_time_%d", i);
		hv_store(self, name, strlen(name),
		    NEW_UV(faultp->create_time), 0);
		(void) snprintf(name, sizeof (name), "msg_%d", i);
		hv_store(self, name, strlen(name), newSVpv(faultp->msg, 0), 0);
	}
}
#endif

/*
 * We need to be able to find the function corresponding to a particular raw
 * kstat.  To do this we ignore the instance and glue the module and name
 * together to form a composite key.  We can then use the data in the kstat
 * structure to find the appropriate function.  We use a perl hash to manage the
 * lookup, where the key is "module:name" and the value is a pointer to the
 * appropriate C function.
 *
 * Note that some kstats include the instance number as part of the module
 * and/or name.  This could be construed as a bug.  However, to work around this
 * we omit any digits from the module and name as we build the table in
 * build_raw_kstat_loopup(), and we remove any digits from the module and name
 * when we look up the functions in lookup_raw_kstat_fn()
 */

/*
 * This function is called when the XS is first dlopen()ed, and builds the
 * lookup table as described above.
 */

static void
build_raw_kstat_lookup()
	{
	/* Create new hash */
	raw_kstat_lookup = newHV();

	SAVE_FNP(raw_kstat_lookup, save_cpu_stat, "cpu_stat:cpu_stat");
	SAVE_FNP(raw_kstat_lookup, save_var, "unix:var");
	SAVE_FNP(raw_kstat_lookup, save_ncstats, "unix:ncstats");
	SAVE_FNP(raw_kstat_lookup, save_sysinfo, "unix:sysinfo");
	SAVE_FNP(raw_kstat_lookup, save_vminfo, "unix:vminfo");
	SAVE_FNP(raw_kstat_lookup, save_nfs, "nfs:mntinfo");
#ifdef __sparc
	SAVE_FNP(raw_kstat_lookup, save_sfmmu_global_stat,
	    "unix:sfmmu_global_stat");
	SAVE_FNP(raw_kstat_lookup, save_sfmmu_tsbsize_stat,
	    "unix:sfmmu_tsbsize_stat");
	SAVE_FNP(raw_kstat_lookup, save_simmstat, "unix:simm-status");
	SAVE_FNP(raw_kstat_lookup, save_temperature, "unix:temperature");
	SAVE_FNP(raw_kstat_lookup, save_temp_over, "unix:temperature override");
	SAVE_FNP(raw_kstat_lookup, save_ps_shadow, "unix:ps_shadow");
	SAVE_FNP(raw_kstat_lookup, save_fault_list, "unix:fault_list");
#endif
}

/*
 * This finds and returns the raw kstat reader function corresponding to the
 * supplied module and name.  If no matching function exists, 0 is returned.
 */

static kstat_raw_reader_t lookup_raw_kstat_fn(char *module, char *name)
	{
	char			key[KSTAT_STRLEN * 2];
	register char		*f, *t;
	SV			**entry;
	kstat_raw_reader_t	fnp;

	/* Copy across module & name, removing any digits - see comment above */
	for (f = module, t = key; *f != '\0'; f++, t++) {
		while (*f != '\0' && isdigit(*f)) { f++; }
		*t = *f;
	}
	*t++ = ':';
	for (f = name; *f != '\0'; f++, t++) {
		while (*f != '\0' && isdigit(*f)) {
			f++;
		}
	*t = *f;
	}
	*t = '\0';

	/* look up & return the function, or teturn 0 if not found */
	if ((entry = hv_fetch(raw_kstat_lookup, key, strlen(key), FALSE)) == 0)
	{
		fnp = 0;
	} else {
		fnp = (kstat_raw_reader_t)(uintptr_t)SvIV(*entry);
	}
	return (fnp);
}

/*
 * This module converts the flat list returned by kstat_read() into a perl hash
 * tree keyed on module, instance, name and statistic.  The following functions
 * provide code to create the nested hashes, and to iterate over them.
 */

/*
 * Given module, instance and name keys return a pointer to the hash tied to
 * the bottommost hash.  If the hash already exists, we just return a pointer
 * to it, otherwise we create the hash and any others also required above it in
 * the hierarchy.  The returned tiehash is blessed into the
 * Sun::Solaris::Kstat::_Stat class, so that the appropriate TIEHASH methods are
 * called when the bottommost hash is accessed.  If the is_new parameter is
 * non-null it will be set to TRUE if a new tie has been created, and FALSE if
 * the tie already existed.
 */

static HV *
get_tie(SV *self, char *module, int instance, char *name, int *is_new)
{
	char str_inst[11];	/* big enough for up to 10^10 instances */
	char *key[3];		/* 3 part key: module, instance, name */
	int  k;
	int  new;
	HV   *hash;
	HV   *tie;

	/* Create the keys */
	(void) snprintf(str_inst, sizeof (str_inst), "%d", instance);
	key[0] = module;
	key[1] = str_inst;
	key[2] = name;

	/* Iteratively descend the tree, creating new hashes as required */
	hash = (HV *)SvRV(self);
	for (k = 0; k < 3; k++) {
		SV **entry;

		SvREADONLY_off(hash);
		entry = hv_fetch(hash, key[k], strlen(key[k]), TRUE);

		/* If the entry doesn't exist, create it */
		if (! SvOK(*entry)) {
			HV *newhash;
			SV *rv;

			newhash = newHV();
			rv = newRV_noinc((SV *)newhash);
			sv_setsv(*entry, rv);
			SvREFCNT_dec(rv);
			if (k < 2) {
				SvREADONLY_on(newhash);
			}
			SvREADONLY_on(*entry);
			SvREADONLY_on(hash);
			hash = newhash;
			new = 1;

		/* Otherwise it already existed */
		} else {
			SvREADONLY_on(hash);
			hash = (HV *)SvRV(*entry);
			new = 0;
		}
	}

	/* Create and bless a hash for the tie, if necessary */
	if (new) {
		SV *tieref;
		HV *stash;

		tie = newHV();
		tieref = newRV_noinc((SV *)tie);
		stash = gv_stashpv("Sun::Solaris::Kstat::_Stat", TRUE);
		sv_bless(tieref, stash);

		/* Add TIEHASH magic */
		hv_magic(hash, (GV *)tieref, 'P');
		SvREADONLY_on(hash);

	/* Otherwise, just find the existing tied hash */
	} else {
		MAGIC *mg;

		mg = mg_find((SV *)hash, 'P');
		PERL_ASSERTMSG(mg != 0, "get_tie: lost P magic");
		tie = (HV *)SvRV(mg->mg_obj);
	}
	if (is_new) {
		*is_new = new;
	}
	return (tie);
}

/*
 * This is an iterator function used to traverse the hash hierarchy and apply
 * the passed function to the tied hashes at the bottom of the hierarchy.  If
 * any of the callback functions return 0, 0 is returned, otherwise 1
 */

static int
apply_to_ties(SV *self, ATTCb_t cb, void *arg)
{
	HV	*hash1;
	HE	*entry1;
	int	ret;

	hash1 = (HV *)SvRV(self);
	hv_iterinit(hash1);
	ret = 1;

	/* Iterate over each module */
	while ((entry1 = hv_iternext(hash1))) {
		HV *hash2;
		HE *entry2;

		hash2 = (HV *)SvRV(hv_iterval(hash1, entry1));
		hv_iterinit(hash2);

		/* Iterate over each module:instance */
		while ((entry2 = hv_iternext(hash2))) {
			HV *hash3;
			HE *entry3;

			hash3 = (HV *)SvRV(hv_iterval(hash2, entry2));
			hv_iterinit(hash3);

			/* Iterate over each module:instance:name */
			while ((entry3 = hv_iternext(hash3))) {
				HV    *hash4;
				MAGIC *mg;

				/* Get the tie */
				hash4 = (HV *)SvRV(hv_iterval(hash3, entry3));
				mg = mg_find((SV *)hash4, 'P');
				PERL_ASSERTMSG(mg != 0,
				    "apply_to_ties: lost P magic");

				/* Apply the callback */
				if (! cb((HV *)SvRV(mg->mg_obj), arg)) {
					ret = 0;
				}
			}
		}
	}
	return (ret);
}

/*
 * Mark this HV as valid - used by update() when pruning deleted kstat nodes
 */

static int
set_valid(HV *self, void *arg)
{
	MAGIC *mg;

	mg = mg_find((SV *)self, '~');
	PERL_ASSERTMSG(mg != 0, "set_valid: lost ~ magic");
	((KstatInfo_t *)SvPVX(mg->mg_obj))->valid = (int)(intptr_t)arg;
	return (1);
}

/*
 * Prune invalid kstat nodes. This is called when kstat_chain_update() detects
 * that the kstat chain has been updated.  This removes any hash tree entries
 * that no longer have a corresponding kstat.  If del is non-null it will be
 * set to the keys of the deleted kstat nodes, if any.  If any entries are
 * deleted 1 will be retured, otherwise 0
 */

static int
prune_invalid(SV *self, AV *del)
{
	HV	*hash1;
	HE	*entry1;
	STRLEN	klen;
	char	*module, *instance, *name, *key;
	int	ret;

	hash1 = (HV *)SvRV(self);
	hv_iterinit(hash1);
	ret = 0;

	/* Iterate over each module */
	while ((entry1 = hv_iternext(hash1))) {
		HV *hash2;
		HE *entry2;

		module = HePV(entry1, PL_na);
		hash2 = (HV *)SvRV(hv_iterval(hash1, entry1));
		hv_iterinit(hash2);

		/* Iterate over each module:instance */
		while ((entry2 = hv_iternext(hash2))) {
			HV *hash3;
			HE *entry3;

			instance = HePV(entry2, PL_na);
			hash3 = (HV *)SvRV(hv_iterval(hash2, entry2));
			hv_iterinit(hash3);

			/* Iterate over each module:instance:name */
			while ((entry3 = hv_iternext(hash3))) {
				HV    *hash4;
				MAGIC *mg;
				HV    *tie;

				name = HePV(entry3, PL_na);
				hash4 = (HV *)SvRV(hv_iterval(hash3, entry3));
				mg = mg_find((SV *)hash4, 'P');
				PERL_ASSERTMSG(mg != 0,
				    "prune_invalid: lost P magic");
				tie = (HV *)SvRV(mg->mg_obj);
				mg = mg_find((SV *)tie, '~');
				PERL_ASSERTMSG(mg != 0,
				    "prune_invalid: lost ~ magic");

				/* If this is marked as invalid, prune it */
				if (((KstatInfo_t *)SvPVX(
				    (SV *)mg->mg_obj))->valid == FALSE) {
					SvREADONLY_off(hash3);
					key = HePV(entry3, klen);
					hv_delete(hash3, key, klen, G_DISCARD);
					SvREADONLY_on(hash3);
					if (del) {
						av_push(del,
						    newSVpvf("%s:%s:%s",
						    module, instance, name));
					}
					ret = 1;
				}
			}

			/* If the module:instance:name hash is empty prune it */
			if (HvKEYS(hash3) == 0) {
				SvREADONLY_off(hash2);
				key = HePV(entry2, klen);
				hv_delete(hash2, key, klen, G_DISCARD);
				SvREADONLY_on(hash2);
			}
		}
		/* If the module:instance hash is empty prune it */
		if (HvKEYS(hash2) == 0) {
			SvREADONLY_off(hash1);
			key = HePV(entry1, klen);
			hv_delete(hash1, key, klen, G_DISCARD);
			SvREADONLY_on(hash1);
		}
	}
	return (ret);
}

/*
 * Named kstats are returned as a list of key/values.  This function converts
 * such a list into the equivalent perl datatypes, and stores them in the passed
 * hash.
 */

static void
save_named(HV *self, kstat_t *kp, int strip_str)
{
	kstat_named_t	*knp;
	int		n;
	SV*		value;

	for (n = kp->ks_ndata, knp = KSTAT_NAMED_PTR(kp); n > 0; n--, knp++) {
		switch (knp->data_type) {
		case KSTAT_DATA_CHAR:
			value = newSVpv(knp->value.c, strip_str ?
			    strlen(knp->value.c) : sizeof (knp->value.c));
			break;
		case KSTAT_DATA_INT32:
			value = newSViv(knp->value.i32);
			break;
		case KSTAT_DATA_UINT32:
			value = NEW_UV(knp->value.ui32);
			break;
		case KSTAT_DATA_INT64:
			value = NEW_UV(knp->value.i64);
			break;
		case KSTAT_DATA_UINT64:
			value = NEW_UV(knp->value.ui64);
			break;
		case KSTAT_DATA_STRING:
			if (KSTAT_NAMED_STR_PTR(knp) == NULL)
				value = newSVpv("null", sizeof ("null") - 1);
			else
				value = newSVpv(KSTAT_NAMED_STR_PTR(knp),
						KSTAT_NAMED_STR_BUFLEN(knp) -1);
			break;
		default:
			PERL_ASSERTMSG(0, "kstat_read: invalid data type");
			continue;
		}
		hv_store(self, knp->name, strlen(knp->name), value, 0);
	}
}

/*
 * Save kstat interrupt statistics
 */

static void
save_intr(HV *self, kstat_t *kp, int strip_str)
{
	kstat_intr_t	*kintrp;
	int		i;
	static char	*intr_names[] =
	    { "hard", "soft", "watchdog", "spurious", "multiple_service" };

	PERL_ASSERT(kp->ks_ndata == 1);
	PERL_ASSERT(kp->ks_data_size == sizeof (kstat_intr_t));
	kintrp = KSTAT_INTR_PTR(kp);

	for (i = 0; i < KSTAT_NUM_INTRS; i++) {
		hv_store(self, intr_names[i], strlen(intr_names[i]),
		    NEW_UV(kintrp->intrs[i]), 0);
	}
}

/*
 * Save IO statistics
 */

static void
save_io(HV *self, kstat_t *kp, int strip_str)
{
	kstat_io_t *kiop;

	PERL_ASSERT(kp->ks_ndata == 1);
	PERL_ASSERT(kp->ks_data_size == sizeof (kstat_io_t));
	kiop = KSTAT_IO_PTR(kp);
	SAVE_UINT64(self, kiop, nread);
	SAVE_UINT64(self, kiop, nwritten);
	SAVE_UINT32(self, kiop, reads);
	SAVE_UINT32(self, kiop, writes);
	SAVE_HRTIME(self, kiop, wtime);
	SAVE_HRTIME(self, kiop, wlentime);
	SAVE_HRTIME(self, kiop, wlastupdate);
	SAVE_HRTIME(self, kiop, rtime);
	SAVE_HRTIME(self, kiop, rlentime);
	SAVE_HRTIME(self, kiop, rlastupdate);
	SAVE_UINT32(self, kiop, wcnt);
	SAVE_UINT32(self, kiop, rcnt);
}

/*
 * Save timer statistics
 */

static void
save_timer(HV *self, kstat_t *kp, int strip_str)
{
	kstat_timer_t *ktimerp;

	PERL_ASSERT(kp->ks_ndata == 1);
	PERL_ASSERT(kp->ks_data_size == sizeof (kstat_timer_t));
	ktimerp = KSTAT_TIMER_PTR(kp);
	SAVE_STRING(self, ktimerp, name, strip_str);
	SAVE_UINT64(self, ktimerp, num_events);
	SAVE_HRTIME(self, ktimerp, elapsed_time);
	SAVE_HRTIME(self, ktimerp, min_time);
	SAVE_HRTIME(self, ktimerp, max_time);
	SAVE_HRTIME(self, ktimerp, start_time);
	SAVE_HRTIME(self, ktimerp, stop_time);
}

/*
 * Read kstats and copy into the supplied perl hash structure.  If refresh is
 * true, this function is being called as part of the update() method.  In this
 * case it is only necessary to read the kstats if they have previously been
 * accessed (kip->read == TRUE).  If refresh is false, this function is being
 * called prior to returning a value to the caller. In this case, it is only
 * necessary to read the kstats if they have not previously been read.  If the
 * kstat_read() fails, 0 is returned, otherwise 1
 */

static int
read_kstats(HV *self, int refresh)
{
	MAGIC			*mg;
	KstatInfo_t		*kip;
	kstat_raw_reader_t	fnp;

	/* Find the MAGIC KstatInfo_t data structure */
	mg = mg_find((SV *)self, '~');
	PERL_ASSERTMSG(mg != 0, "read_kstats: lost ~ magic");
	kip = (KstatInfo_t *)SvPVX(mg->mg_obj);

	/* Return early if we don't need to actually read the kstats */
	if ((refresh && ! kip->read) || (! refresh && kip->read)) {
		return (1);
	}

	/* Read the kstats and return 0 if this fails */
	if (kstat_read(kip->kstat_ctl, kip->kstat, NULL) < 0) {
		return (0);
	}

	/* Save the read data */
	hv_store(self, "snaptime", 8, NEW_HRTIME(kip->kstat->ks_snaptime), 0);
	switch (kip->kstat->ks_type) {
		case KSTAT_TYPE_RAW:
			if ((fnp = lookup_raw_kstat_fn(kip->kstat->ks_module,
			    kip->kstat->ks_name)) != 0) {
				fnp(self, kip->kstat, kip->strip_str);
			}
			break;
		case KSTAT_TYPE_NAMED:
			save_named(self, kip->kstat, kip->strip_str);
			break;
		case KSTAT_TYPE_INTR:
			save_intr(self, kip->kstat, kip->strip_str);
			break;
		case KSTAT_TYPE_IO:
			save_io(self, kip->kstat, kip->strip_str);
			break;
		case KSTAT_TYPE_TIMER:
			save_timer(self, kip->kstat, kip->strip_str);
			break;
		default:
			PERL_ASSERTMSG(0, "read_kstats: illegal kstat type");
			break;
	}
	kip->read = TRUE;
	return (1);
}

/*
 * The XS code exported to perl is below here.  Note that the XS preprocessor
 * has its own commenting syntax, so all comments from this point on are in
 * that form.
 */

/* The following XS methods are the ABI of the Sun::Solaris::Kstat package */

MODULE = Sun::Solaris::Kstat PACKAGE = Sun::Solaris::Kstat
PROTOTYPES: ENABLE

 # Create the raw kstat to store function lookup table on load
BOOT:
	build_raw_kstat_lookup();

 #
 # The Sun::Solaris::Kstat constructor.  This builds the nested
 # name::instance::module hash structure, but doesn't actually read the
 # underlying kstats.  This is done on demand by the TIEHASH methods in
 # Sun::Solaris::Kstat::_Stat
 #

SV*
new(class, ...)
	char *class;
PREINIT:
	HV		*stash;
	kstat_ctl_t	*kc;
	SV		*kcsv;
	kstat_t		*kp;
	KstatInfo_t	kstatinfo;
	int		sp, strip_str;
CODE:
	/* Check we have an even number of arguments, excluding the class */
	sp = 1;
	if (((items - sp) % 2) != 0) {
		croak(DEBUG_ID ": new: invalid number of arguments");
	}

	/* Process any (name => value) arguments */
	strip_str = 0;
	while (sp < items) {
		SV *name, *value;

		name = ST(sp);
		sp++;
		value = ST(sp);
		sp++;
		if (strcmp(SvPVX(name), "strip_strings") == 0) {
			strip_str = SvTRUE(value);
		} else {
			croak(DEBUG_ID ": new: invalid parameter name '%s'",
			    SvPVX(name));
		}
	}

	/* Open the kstats handle */
	if ((kc = kstat_open()) == 0) {
		XSRETURN_UNDEF;
	}

	/* Create a blessed hash ref */
	RETVAL = (SV *)newRV_noinc((SV *)newHV());
	stash = gv_stashpv(class, TRUE);
	sv_bless(RETVAL, stash);

	/* Create a place to save the KstatInfo_t structure */
	kcsv = newSVpv((char *)&kc, sizeof (kc));
	sv_magic(SvRV(RETVAL), kcsv, '~', 0, 0);
	SvREFCNT_dec(kcsv);

	/* Initialise the KstatsInfo_t structure */
	kstatinfo.read = FALSE;
	kstatinfo.valid = TRUE;
	kstatinfo.strip_str = strip_str;
	kstatinfo.kstat_ctl = kc;

	/* Scan the kstat chain, building hash entries for the kstats */
	for (kp = kc->kc_chain; kp != 0; kp = kp->ks_next) {
		HV *tie;
		SV *kstatsv;

		/* Don't bother storing the kstat headers */
		if (strncmp(kp->ks_name, "kstat_", 6) == 0) {
			continue;
		}

		/* Don't bother storing raw stats we don't understand */
		if (kp->ks_type == KSTAT_TYPE_RAW &&
		    lookup_raw_kstat_fn(kp->ks_module, kp->ks_name) == 0) {
#ifdef REPORT_UNKNOWN
			(void) fprintf(stderr,
			    "Unknown kstat type %s:%d:%s - %d of size %d\n",
			    kp->ks_module, kp->ks_instance, kp->ks_name,
			    kp->ks_ndata, kp->ks_data_size);
#endif
			continue;
		}

		/* Create a 3-layer hash hierarchy - module.instance.name */
		tie = get_tie(RETVAL, kp->ks_module, kp->ks_instance,
		    kp->ks_name, 0);

		/* Save the data necessary to read the kstat info on demand */
		hv_store(tie, "class", 5, newSVpv(kp->ks_class, 0), 0);
		hv_store(tie, "crtime", 6, NEW_HRTIME(kp->ks_crtime), 0);
		kstatinfo.kstat = kp;
		kstatsv = newSVpv((char *)&kstatinfo, sizeof (kstatinfo));
		sv_magic((SV *)tie, kstatsv, '~', 0, 0);
		SvREFCNT_dec(kstatsv);
	}
	SvREADONLY_on(SvRV(RETVAL));
	/* SvREADONLY_on(RETVAL); */
OUTPUT:
	RETVAL

 #
 # Update the perl hash structure so that it is in line with the kernel kstats
 # data.  Only kstats athat have previously been accessed are read,
 #

 # Scalar context: true/false
 # Array context: (\@added, \@deleted)
void
update(self)
	SV* self;
PREINIT:
	MAGIC		*mg;
	kstat_ctl_t	*kc;
	kstat_t		*kp;
	int		ret;
	AV		*add, *del;
PPCODE:
	/* Find the hidden KstatInfo_t structure */
	mg = mg_find(SvRV(self), '~');
	PERL_ASSERTMSG(mg != 0, "update: lost ~ magic");
	kc = *(kstat_ctl_t **)SvPVX(mg->mg_obj);

	/* Update the kstat chain, and return immediately on error. */
	if ((ret = kstat_chain_update(kc)) == -1) {
		if (GIMME_V == G_ARRAY) {
			EXTEND(SP, 2);
			PUSHs(sv_newmortal());
			PUSHs(sv_newmortal());
		} else {
			EXTEND(SP, 1);
			PUSHs(sv_2mortal(newSViv(ret)));
		}
	}

	/* Create the arrays to be returned if in an array context */
	if (GIMME_V == G_ARRAY) {
		add = newAV();
		del = newAV();
	} else {
		add = 0;
		del = 0;
	}

	/*
	 * If the kstat chain hasn't changed we can just reread any stats
	 * that have already been read
	 */
	if (ret == 0) {
		if (! apply_to_ties(self, (ATTCb_t)read_kstats, (void *)TRUE)) {
			if (GIMME_V == G_ARRAY) {
				EXTEND(SP, 2);
				PUSHs(sv_2mortal(newRV_noinc((SV *)add)));
				PUSHs(sv_2mortal(newRV_noinc((SV *)del)));
			} else {
				EXTEND(SP, 1);
				PUSHs(sv_2mortal(newSViv(-1)));
			}
		}

	/*
	 * Otherwise we have to update the Perl structure so that it is in
	 * agreement with the new kstat chain.  We do this in such a way as to
	 * retain all the existing structures, just adding or deleting the
	 * bare minimum.
	 */
	} else {
		KstatInfo_t	kstatinfo;

		/*
		 * Step 1: set the 'invalid' flag on each entry
		 */
		apply_to_ties(self, &set_valid, (void *)FALSE);

		/*
		 * Step 2: Set the 'valid' flag on all entries still in the
		 * kernel kstat chain
		 */
		kstatinfo.read		= FALSE;
		kstatinfo.valid		= TRUE;
		kstatinfo.kstat_ctl	= kc;
		for (kp = kc->kc_chain; kp != 0; kp = kp->ks_next) {
			int	new;
			HV	*tie;

			/* Don't bother storing the kstat headers or types */
			if (strncmp(kp->ks_name, "kstat_", 6) == 0) {
				continue;
			}

			/* Don't bother storing raw stats we don't understand */
			if (kp->ks_type == KSTAT_TYPE_RAW &&
			    lookup_raw_kstat_fn(kp->ks_module, kp->ks_name)
			    == 0) {
#ifdef REPORT_UNKNOWN
				(void) printf("Unknown kstat type %s:%d:%s "
				    "- %d of size %d\n", kp->ks_module,
				    kp->ks_instance, kp->ks_name,
				    kp->ks_ndata, kp->ks_data_size);
#endif
				continue;
			}

			/* Find the tied hash associated with the kstat entry */
			tie = get_tie(self, kp->ks_module, kp->ks_instance,
			    kp->ks_name, &new);

			/* If newly created store the associated kstat info */
			if (new) {
				SV *kstatsv;

				/*
				 * Save the data necessary to read the kstat
				 * info on demand
				 */
				hv_store(tie, "class", 5,
				    newSVpv(kp->ks_class, 0), 0);
				hv_store(tie, "crtime", 6,
				    NEW_HRTIME(kp->ks_crtime), 0);
				kstatinfo.kstat = kp;
				kstatsv = newSVpv((char *)&kstatinfo,
				    sizeof (kstatinfo));
				sv_magic((SV *)tie, kstatsv, '~', 0, 0);
				SvREFCNT_dec(kstatsv);

				/* Save the key on the add list, if required */
				if (GIMME_V == G_ARRAY) {
					av_push(add, newSVpvf("%s:%d:%s",
					    kp->ks_module, kp->ks_instance,
					    kp->ks_name));
				}

			/* If the stats already exist, just update them */
			} else {
				MAGIC *mg;
				KstatInfo_t *kip;

				/* Find the hidden KstatInfo_t */
				mg = mg_find((SV *)tie, '~');
				PERL_ASSERTMSG(mg != 0, "update: lost ~ magic");
				kip = (KstatInfo_t *)SvPVX(mg->mg_obj);

				/* Mark the tie as valid */
				kip->valid = TRUE;

				/* Re-save the kstat_t pointer.  If the kstat
				 * has been deleted and re-added since the last
				 * update, the address of the kstat structure
				 * will have changed, even though the kstat will
				 * still live at the same place in the perl
				 * hash tree structure.
				 */
				kip->kstat = kp;

				/* Reread the stats, if read previously */
				read_kstats(tie, TRUE);
			}
		}

		/*
		 *Step 3: Delete any entries still marked as 'invalid'
		 */
		ret = prune_invalid(self, del);

	}
	if (GIMME_V == G_ARRAY) {
		EXTEND(SP, 2);
		PUSHs(sv_2mortal(newRV_noinc((SV *)add)));
		PUSHs(sv_2mortal(newRV_noinc((SV *)del)));
	} else {
		EXTEND(SP, 1);
		PUSHs(sv_2mortal(newSViv(ret)));
	}


 #
 # Destructor.  Closes the kstat connection
 #

void
DESTROY(self)
	SV *self;
PREINIT:
	MAGIC		*mg;
	kstat_ctl_t	*kc;
CODE:
	mg = mg_find(SvRV(self), '~');
	PERL_ASSERTMSG(mg != 0, "DESTROY: lost ~ magic");
	kc = *(kstat_ctl_t **)SvPVX(mg->mg_obj);
	if (kstat_close(kc) != 0) {
		croak(DEBUG_ID ": kstat_close: failed");
	}

 #
 # The following XS methods implement the TIEHASH mechanism used to update the
 # kstats hash structure.  These are blessed into a package that isn't
 # visible to callers of the Sun::Solaris::Kstat module
 #

MODULE = Sun::Solaris::Kstat PACKAGE = Sun::Solaris::Kstat::_Stat
PROTOTYPES: ENABLE

 #
 # If a value has already been read, return it.  Otherwise read the appropriate
 # kstat and then return the value
 #

SV*
FETCH(self, key)
	SV* self;
	SV* key;
PREINIT:
	char	*k;
	STRLEN	klen;
	SV	**value;
CODE:
	self = SvRV(self);
	k = SvPV(key, klen);
	if (strNE(k, "class") && strNE(k, "crtime")) {
		read_kstats((HV *)self, FALSE);
	}
	value = hv_fetch((HV *)self, k, klen, FALSE);
	if (value) {
		RETVAL = *value; SvREFCNT_inc(RETVAL);
	} else {
		RETVAL = &PL_sv_undef;
	}
OUTPUT:
	RETVAL

 #
 # Save the passed value into the kstat hash.  Read the appropriate kstat first,
 # if necessary.  Note that this DOES NOT update the underlying kernel kstat
 # structure.
 #

SV*
STORE(self, key, value)
	SV* self;
	SV* key;
	SV* value;
PREINIT:
	char	*k;
	STRLEN	klen;
CODE:
	self = SvRV(self);
	k = SvPV(key, klen);
	if (strNE(k, "class") && strNE(k, "crtime")) {
		read_kstats((HV *)self, FALSE);
	}
	SvREFCNT_inc(value);
	RETVAL = *(hv_store((HV *)self, k, klen, value, 0));
	SvREFCNT_inc(RETVAL);
OUTPUT:
	RETVAL

 #
 # Check for the existence of the passed key.  Read the kstat first if necessary
 #

bool
EXISTS(self, key)
	SV* self;
	SV* key;
PREINIT:
	char *k;
CODE:
	self = SvRV(self);
	k = SvPV(key, PL_na);
	if (strNE(k, "class") && strNE(k, "crtime")) {
		read_kstats((HV *)self, FALSE);
	}
	RETVAL = hv_exists_ent((HV *)self, key, 0);
OUTPUT:
	RETVAL


 #
 # Hash iterator initialisation.  Read the kstats if necessary.
 #

SV*
FIRSTKEY(self)
	SV* self;
PREINIT:
	HE *he;
PPCODE:
	self = SvRV(self);
	read_kstats((HV *)self, FALSE);
	hv_iterinit((HV *)self);
	if ((he = hv_iternext((HV *)self))) {
		EXTEND(SP, 1);
		PUSHs(hv_iterkeysv(he));
	}

 #
 # Return hash iterator next value.  Read the kstats if necessary.
 #

SV*
NEXTKEY(self, lastkey)
	SV* self;
	SV* lastkey;
PREINIT:
	HE *he;
PPCODE:
	self = SvRV(self);
	if ((he = hv_iternext((HV *)self))) {
		EXTEND(SP, 1);
		PUSHs(hv_iterkeysv(he));
	}


 #
 # Delete the specified hash entry.
 #

SV*
DELETE(self, key)
	SV *self;
	SV *key;
CODE:
	self = SvRV(self);
	RETVAL = hv_delete_ent((HV *)self, key, 0, 0);
	if (RETVAL) {
		SvREFCNT_inc(RETVAL);
	} else {
		RETVAL = &PL_sv_undef;
	}
OUTPUT:
	RETVAL

 #
 # Clear the entire hash.  This will stop any update() calls rereading this
 # kstat until it is accessed again.
 #

void
CLEAR(self)
	SV* self;
PREINIT:
	MAGIC   *mg;
	KstatInfo_t *kip;
CODE:
	self = SvRV(self);
	hv_clear((HV *)self);
	mg = mg_find(self, '~');
	PERL_ASSERTMSG(mg != 0, "CLEAR: lost ~ magic");
	kip = (KstatInfo_t *)SvPVX(mg->mg_obj);
	kip->read  = FALSE;
	kip->valid = TRUE;
	hv_store((HV *)self, "class", 5, newSVpv(kip->kstat->ks_class, 0), 0);
	hv_store((HV *)self, "crtime", 6, NEW_HRTIME(kip->kstat->ks_crtime), 0);
