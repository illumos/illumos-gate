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

#ifndef	_SYS_N2RNG_H
#define	_SYS_N2RNG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* skip following stuff when included in n2rng_hcall.s */
#ifndef _ASM
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/ksynch.h>
#include <sys/sunddi.h>
#include <sys/param.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/mdesc.h>

#endif /* !_ASM */

#ifdef	__cplusplus
extern "C" {
#endif

#define	HV_RNG_GET_DIAG_CONTROL	0x130
#define	HV_RNG_CTL_READ		0x131
#define	HV_RNG_CTL_WRITE	0x132
#define	HV_RNG_DATA_READ_DIAG	0x133
#define	HV_RNG_DATA_READ	0x134

#define	CTL_STATE_UNCONFIGURED	0
#define	CTL_STATE_CONFIGURED	1
#define	CTL_STATE_HEALTHCHECK	2
#define	CTL_STATE_ERROR		3

#define	NRNGCTL			4
#define	N2RNG_MAX_READ		(128 * 1024)	/* 128K bytes */

#define	DRIVER			"n2rng"
#define	N2RNG_MANUFACTURER_ID	"SUNWn2rng"

#define	N2RNG_BINDNAME_N2	"SUNW,n2-rng"
#define	N2RNG_BINDNAME_VF	"SUNW,vf-rng"

#define	N2RNG_MAX_RNGS		4
#define	N2RNG_INVALID_ID	(-1)

#ifndef _ASM

typedef enum {
	N2RNG_CPU_UNKNOWN,
	N2RNG_CPU_N2,
	N2RNG_CPU_VF
} n2rng_binding_t;

typedef union n2rngctl {
	uint64_t	word;
	struct {
		uint64_t rnc_res : 39;
		uint64_t rnc_cnt : 16;
		uint64_t rnc_bypass : 1;
		uint64_t rnc_vcoctl : 2;
		uint64_t rnc_anlg_sel : 2;
		uint64_t rnc_mode : 1;
		uint64_t rnc_selbits : 3;
	} fields;
} n2rng_ctl_t;

typedef struct {
	n2rng_ctl_t ctlwds[NRNGCTL];
} n2rng_setup_t;

#if defined(_KERNEL)

/*
 * Our contiguous memory alignment requirement is
 * only for 8 bytes, however contig mem allocation
 * routines requirement minimum of 64.
 */
#define	CONTIG_ALIGNMENT	64

/*
 * Returns 1 only if the address range of a variable of type type at
 * ptr falls entirely on one page.  Based on page size of 4K.  May
 * give some false negatives on larger page sizes.
 */
#define	CONTIGUOUS(ptr, type)	\
	(((((uint64_t)(ptr)) ^ ((uint64_t)(ptr) + sizeof (type) -1))	\
	& PAGEMASK) == 0)

/*
 * The RNG hardware can send certain internal analog signals to an
 * external pin on the chip.  Setting the rnc_anlg_sel bit to
 * N2RNG_NOANALOGOUT deselects all analog signals (perhaps selects
 * ground).  Choosing any other value would aid an attacker with
 * physical access to the chip.
 */
#define	N2RNG_NOANALOGOUT	0x2

/*
 * There can only be N2_RNG_FIPS_INSTANCES concurrent RNG requsts from
 * the framework.  Making this value large helps benchmarks.  It
 * should probably come from a conf file, but for now it is hard
 * coded.  The code computes i % N2RNG_FIPS_INSTANCES, which is more
 * efficient when N2RNG_FIPS_INSTANCES is a power of 2.
 */
#define	N2RNG_FIPS_INSTANCES 8

typedef struct fipsrandomstruct fipsrandomstruct_t;
struct fipsrandomstruct {
	kmutex_t	mtx;
	uint64_t	entropyhunger;  /* RNGs generated with no entropy */
	uint32_t	XKEY[6]; /* one extra word for getentropy */
};

typedef struct {
	/*
	 * volatile, since it is not protected by a mutex.  (That is
	 * okay since it is operated on and accessed via atomic ops.)
	 */
	volatile unsigned int	fips_round_robin_j;
	fipsrandomstruct_t	fipsarray[N2RNG_FIPS_INSTANCES];
} fips_ensemble_t;

/*
 * Device flags (n2rng_t.n_flags)
 */
#define	N2RNG_CONTROL		0x00000001
#define	N2RNG_FAILED		0x00000002
#define	N2RNG_CONFIGURED	0x00000004
#define	N2RNG_INITIALIZED	0x00000008
#define	N2RNG_REGISTERED	0x00000010

#define	n2rng_setcontrol(n2rng)		((n2rng)->n_flags |= N2RNG_CONTROL)
#define	n2rng_clrcontrol(n2rng)		((n2rng)->n_flags &= ~N2RNG_CONTROL)
#define	n2rng_iscontrol(n2rng)		((n2rng)->n_flags & N2RNG_CONTROL)

#define	n2rng_setfailed(n2rng)		((n2rng)->n_flags |= N2RNG_FAILED)
#define	n2rng_clrfailed(n2rng)		((n2rng)->n_flags &= ~N2RNG_FAILED)
#define	n2rng_isfailed(n2rng)		((n2rng)->n_flags & N2RNG_FAILED)

#define	n2rng_setconfigured(n2rng)	((n2rng)->n_flags |= N2RNG_CONFIGURED)
#define	n2rng_clrconfigured(n2rng)	((n2rng)->n_flags &= ~N2RNG_CONFIGURED)
#define	n2rng_isconfigured(n2rng)	((n2rng)->n_flags & N2RNG_CONFIGURED)

#define	n2rng_setinitialized(n2rng)	((n2rng)->n_flags |= N2RNG_INITIALIZED)
#define	n2rng_clrinitialized(n2rng)	((n2rng)->n_flags &= ~N2RNG_INITIALIZED)
#define	n2rng_isinitialized(n2rng)	((n2rng)->n_flags & N2RNG_INITIALIZED)

#define	n2rng_setregistered(n2rng)	((n2rng)->n_flags |= N2RNG_REGISTERED)
#define	n2rng_clrregistered(n2rng)	((n2rng)->n_flags &= ~N2RNG_REGISTERED)
#define	n2rng_isregistered(n2rng)	((n2rng)->n_flags & N2RNG_REGISTERED)

#define	DS_RNGBYTES		0
#define	DS_RNGJOBS		1
#define	DS_RNGHEALTHCHECKS	2
#define	DS_MAX			3

#define	N2RNG_NOSC		3
#define	N2RNG_BIASBITS		2
#define	N2RNG_NBIASES		(1 << N2RNG_BIASBITS)
#define	N2RNG_CTLOPS		(N2RNG_OSC + 1)

#define	N2RNG_PROP_NUM_UNITS	"rng-#units"
#define	SECOND			1000000		/* micro seconds */

typedef struct {
	uint64_t	numvals;
	uint64_t	H1;	/* in bits per bit << LOG_VAL_SCALE */
	uint64_t	H2;
	uint64_t	Hinf;
} n2rng_osc_perf_t;

typedef n2rng_osc_perf_t n2rng_osc_perf_table_t[N2RNG_NOSC][N2RNG_NBIASES];

typedef struct {
	uint64_t	bias;
	uint64_t	entropy;
} n2rng_bias_info_t;

typedef struct {
	n2rng_bias_info_t	n_bias_info[N2RNG_NOSC];
	n2rng_osc_perf_table_t	n_perftable;
	n2rng_setup_t		n_preferred_config;
	uint64_t		n_rng_state; /* as last known in this drvr. */
} rng_entry_t;

typedef struct {
	int			n_num_rngs;
	int			n_num_rngs_online;
	rng_entry_t		*n_rngs;
	clock_t			n_hc_secs;
	uint64_t		n_watchdog_cycles;
	uint64_t		n_accumulate_cycles;
} rng_ctl_data_t;

typedef struct n2rng {
	kmutex_t		n_lock;
	dev_info_t		*n_dip;
	unsigned		n_flags;	/* dev state flags */
	uint_t			n_hvapi_major_version;
	uint_t			n_hvapi_minor_version;
	n2rng_binding_t		n_binding;
	char			*n_binding_name;
	rng_ctl_data_t		*n_ctl_data;	/* Only valid in ctl domain */
	kstat_t			*n_ksp;
	uint64_t		n_stats[DS_MAX];
	crypto_kcf_provider_handle_t	n_prov;
	fips_ensemble_t		n_frs;
	timeout_id_t		n_timeout_id;
	md_t			*n_mdp;
	uint64_t		n_sticks_per_usec;
	ddi_taskq_t		*n_taskq;
} n2rng_t;

typedef kstat_named_t n2rng_kstat_bias_t[N2RNG_NOSC][N2RNG_NBIASES];

typedef struct n2rng_stat n2rng_stat_t;
struct n2rng_stat {
	kstat_named_t		ns_status;
	kstat_named_t		ns_algs[DS_MAX];
	kstat_named_t		ns_rngstate[N2RNG_MAX_RNGS];
	n2rng_kstat_bias_t	ns_rngbias;
	n2rng_kstat_bias_t	ns_rngentropy;
};

#define	RNG_MODE_NORMAL			1
#define	RNG_MODE_DIAGNOSTIC		0

#define	RNG_DIAG_CHUNK_SIZE		(N2RNG_MAX_READ / 8) /* as words */
#define	RNG_MAX_DATA_READ_ATTEMPTS	100
#define	RNG_RETRY_HLCHK_USECS		100000	/* retry every .1 seconds */

#define	RNG_MAX_LOGIC_TEST_ATTEMPTS	3
#define	RNG_MAX_BUSY_ATTEMPTS		100
#define	RNG_MAX_BLOCK_ATTEMPTS		50000
#define	RNG_RETRY_BUSY_DELAY		1

#define	RNG_DEFAULT_ACCUMULATE_CYCLES	2048
#define	RNG_CFG_RETRY_SECS		60 /* seconds between cfg retries */

#define	RNG_DEFAULT_HC_SECS		0  /* seconds between health checks */
#define	RNG_EXTRA_WATCHDOG_SECS		60 /* added to hc time for watchdog */

#define	LOG_ARG_SCALE			49
#define	LOG_VAL_SCALE			32

void n2rng_sort(uint64_t *data, int log2_size);
int n2rng_noise_gen_preferred(n2rng_t *n2rng, int rngid);
int n2rng_config_test(n2rng_t *n2rng);
int n2rng_collect_diag_bits(n2rng_t *n2rng, int rngid,
    n2rng_setup_t *collect_setupp, void *buffer, int numbytes,
    n2rng_setup_t *exit_setupp, uint64_t exitstate);
int n2rng_getentropy(n2rng_t *n2rng, void *buffer, size_t size);
int n2rng_fips_random_init(n2rng_t *n2rng, fipsrandomstruct_t *frsp);
void n2rng_fips_random_fini(fipsrandomstruct_t *frsp);
int n2rng_do_health_check(n2rng_t *n2rng, int rngid);
void n2rng_renyi_entropy(uint64_t *buffer, int log2samples,
    n2rng_osc_perf_t *metricp);
uint64_t n2rng_read_ctl(n2rng_t *n2rng, int rngid, uint64_t ctlregs_pa,
    uint64_t *state, uint64_t *tdelta, uint64_t *wdelta);
uint64_t n2rng_ctl_wait(n2rng_t *n2rng, int rngid);
uint64_t n2rng_ctl_write(n2rng_t *n2rng, int rngid, uint64_t ctlregs_pa,
    uint64_t newstate, uint64_t wtimeout, uint64_t *tdelta);
uint64_t n2rng_data_read_diag(n2rng_t *n2rng, int rngid, uint64_t data_pa,
    size_t  datalen, uint64_t *tdelta);
uint64_t n2rng_check_ctl_access(n2rng_t *n2rng);
void n2rng_config_retry(n2rng_t *n2rng, clock_t seconds);

#if defined(DEBUG)

#define	DWARN		0x00000001
#define	DMA_ARGS	0x00000002
#define	DMA_LDST	0x00000004
#define	DNCS_QTAIL	0x00000008
#define	DATTACH		0x00000010
#define	DCFG		0x00000020
#define	DMOD		0x00000040  /* _init/_fini/_info/attach/detach */
#define	DENTRY		0x00000080  /* crypto routine entry/exit points */
#define	DHEALTH		0x00000100
#define	DCHATTY		0x00000200
#define	DKCF		0x00000400
#define	DALL		0xFFFFFFFF

#define	DBG0	n2rng_dprintf
#define	DBG1	n2rng_dprintf
#define	DBG2	n2rng_dprintf
#define	DBG3	n2rng_dprintf
#define	DBG4	n2rng_dprintf
#define	DBG5	n2rng_dprintf
#define	DBG6	n2rng_dprintf
#define	DBGCALL(flag, func)	{ if (n2rng_dflagset(flag)) (void) func; }

void	n2rng_dprintf(n2rng_t *, int, const char *, ...);
void	n2rng_dumphex(void *, int);
int	n2rng_dflagset(int);

#else	/* !defined(DEBUG) */

#define	DBG0(vca, lvl, fmt)
#define	DBG1(vca, lvl, fmt, arg1)
#define	DBG2(vca, lvl, fmt, arg1, arg2)
#define	DBG3(vca, lvl, fmt, arg1, arg2, arg3)
#define	DBG4(vca, lvl, fmt, arg1, arg2, arg3, arg4)
#define	DBG5(vca, lvl, fmt, arg1, arg2, arg3, arg4, arg5)
#define	DBG6(vca, lvl, fmt, arg1, arg2, arg3, arg4, arg5, arg6)
#define	DBGCALL(flag, func)

#endif	/* !defined(DEBUG) */

/*
 * n2rng_kcf.c
 */
int n2rng_herr2kerr(uint64_t);
int n2rng_logic_test(n2rng_t *, int);
int n2rng_noise_gen_test_set(void);
int n2rng_init(n2rng_t *n2rng);
int n2rng_uninit(n2rng_t *n2rng);
int n2rng_register_provider(n2rng_t *n2rng);
int n2rng_unregister_provider(n2rng_t *n2rng);
void n2rng_failure(n2rng_t *n2rng);
void n2rng_unconfigured(n2rng_t *n2rng);

/*
 * n2rng_debug.c
 */
void n2rng_error(n2rng_t *, const char *, ...);
void n2rng_diperror(dev_info_t *, const char *, ...);
void n2rng_dipverror(dev_info_t *, const char *, va_list);

uint64_t hv_rng_get_diag_control(void);
uint64_t hv_rng_ctl_read(uint64_t ctlregs_pa, uint64_t *state,
    uint64_t *tdelta);
uint64_t hv_rng_ctl_read_v2(uint64_t ctlregs_pa, uint64_t rngid,
    uint64_t *state, uint64_t *tdelta, uint64_t *wdelta, uint64_t *wstate);
uint64_t hv_rng_ctl_write(uint64_t ctlregs_pa,
    uint64_t newstate, uint64_t wtimeout, uint64_t *tdelta);
uint64_t hv_rng_ctl_write_v2(uint64_t ctlregs_pa,
    uint64_t newstate, uint64_t wtimeout, uint64_t rngid);
uint64_t hv_rng_data_read_diag(uint64_t data_pa,
    size_t  datalen, uint64_t *tdelta);
uint64_t hv_rng_data_read_diag_v2(uint64_t data_pa,
    size_t  datalen, uint64_t rngid, uint64_t *tdelta);
uint64_t hv_rng_data_read(uint64_t data_pa, uint64_t *tdelta);

#endif /* _KERNEL */
#endif /* !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_N2RNG_H */
