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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 1983, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/project.h>
#include <sys/klwp.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/var.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/conf.h>
#include <sys/class.h>
#include <sys/ts.h>
#include <sys/rt.h>
#include <sys/exec.h>
#include <sys/exechdr.h>
#include <sys/buf.h>
#include <sys/resource.h>
#include <vm/seg.h>
#include <vm/pvn.h>
#include <vm/seg_kmem.h>
#include <sys/vmparam.h>
#include <sys/machparam.h>
#include <sys/utsname.h>
#include <sys/kmem.h>
#include <sys/stack.h>
#include <sys/modctl.h>
#include <sys/fdbuffer.h>
#include <sys/cyclic_impl.h>
#include <sys/disp.h>
#include <sys/tuneable.h>
#include <sys/systeminfo.h>

#include <sys/vmem.h>
#include <sys/clock.h>
#include <sys/clock_impl.h>
#include <sys/serializer.h>

/*
 * The following few lines describe generic things that must be compiled
 * into the booted executable (unix) rather than genunix or any other
 * module because they're required by crash dump readers, etc.
 */
struct modctl modules;		/* head of linked list of modules */
char *default_path;		/* default module loading path */
struct swapinfo *swapinfo;	/* protected by the swapinfo_lock */
proc_t *practive;		/* active process list */
uint_t nproc;			/* current number of processes */
proc_t p0;			/* process 0 */
struct plock p0lock;		/* p0's p_lock */
klwp_t lwp0;			/* t0's lwp */
task_t *task0p;			/* task 0 */
kproject_t *proj0p;		/* location of project 0 */

/*
 * The following are "implementation architecture" dependent constants made
 * available here in the form of initialized data for use by "implementation
 * architecture" independent modules. See machparam.h.
 */
const unsigned long	_pagesize	= (unsigned long)PAGESIZE;
const unsigned int	_pageshift	= (unsigned int)PAGESHIFT;
const unsigned long	_pageoffset	= (unsigned long)PAGEOFFSET;
/*
 * XXX - This value pagemask has to be a 64bit size because
 * large file support uses this mask on offsets which are 64 bit size.
 * using unsigned leaves the higher 32 bits value as zero thus
 * corrupting offset calculations in the file system and VM.
 */
const u_longlong_t	_pagemask	= (u_longlong_t)PAGEMASK;
const unsigned long	_mmu_pagesize	= (unsigned long)MMU_PAGESIZE;
const unsigned int	_mmu_pageshift	= (unsigned int)MMU_PAGESHIFT;
const unsigned long	_mmu_pageoffset	= (unsigned long)MMU_PAGEOFFSET;
const unsigned long	_mmu_pagemask	= (unsigned long)MMU_PAGEMASK;
uintptr_t		_kernelbase	= (uintptr_t)KERNELBASE;
uintptr_t		_userlimit	= (uintptr_t)USERLIMIT;
uintptr_t		_userlimit32	= (uintptr_t)USERLIMIT32;
const uintptr_t		_argsbase	= (uintptr_t)ARGSBASE;
const unsigned int	_diskrpm	= (unsigned int)DISKRPM;
const unsigned long	_pgthresh	= (unsigned long)PGTHRESH;
const unsigned int	_maxslp		= (unsigned int)MAXSLP;
const unsigned long	_maxhandspreadpages = (unsigned long)MAXHANDSPREADPAGES;
const int		_ncpu 		= (int)NCPU;
const int		_ncpu_log2	= (int)NCPU_LOG2;
const int		_ncpu_p2	= (int)NCPU_P2;
const unsigned long	_defaultstksz	= (unsigned long)DEFAULTSTKSZ;
const unsigned int	_nbpg		= (unsigned int)MMU_PAGESIZE;

/*
 * System parameter formulae.
 *
 * This file is copied into each directory where we compile
 * the kernel; it should be modified there to suit local taste
 * if necessary.
 */

/*
 * Default hz is 100, but if we set hires_tick we get higher resolution
 * clock behavior (currently defined to be 1000 hz).  Higher values seem
 * to work, but are not supported.
 *
 * If we do decide to play with higher values, remember that hz should
 * satisfy the following constraints to avoid integer round-off problems:
 *
 * (1) hz should be in the range 100 <= hz <= MICROSEC.  If hz exceeds
 *     MICROSEC, usec_per_tick will be zero and lots of stuff will break.
 *     Similarly, if hz < 100 then hz / 100 == 0 and stuff will break.
 *
 * (2) If hz <= 1000, it should be both a multiple of 100 and a
 *	divisor of 1000.
 *
 * (3) If hz > 1000, it should be both a multiple of 1000 and a
 *	divisor of MICROSEC.
 *
 * Thus the only reasonable values of hz (i.e. the values that won't
 * cause roundoff error) are: 100, 200, 500, 1000, 2000, 4000, 5000,
 * 8000, 10000, 20000, 25000, 40000, 50000, 100000, 125000, 200000,
 * 250000, 500000, 1000000.  As of this writing (1996) a clock rate
 * of more than about 10 kHz seems utterly ridiculous, although
 * this observation will no doubt seem quaintly amusing one day.
 */
#define	HIRES_HZ_DEFAULT	1000

int hz = HZ_DEFAULT;
int hires_hz = HIRES_HZ_DEFAULT;

int hires_tick = 0;
int cpu_decay_factor = 10;	/* this is no longer tied to clock */
int max_hres_adj;	/* maximum adjustment of hrtime per tick */
int tick_per_msec;	/* clock ticks per millisecond (zero if hz < 1000) */

/*
 * Milliseconds, Microseconds, and Nanoseconds per clock tick
 *
 * Note:
 *  msec_per_tick is zero if hz > 1000
 */
int msec_per_tick;
int usec_per_tick;
int nsec_per_tick;

/*
 * Time Resolution values. These are defined in condvar.h and initialized in
 * param_init(). Consumers of cv_reltimedwait() and cv_reltimedwait_sig()
 * need to specify how accurate the timeout argument should be through
 * one of these values. The intention is to allow the underlying implementation
 * to anticipate or defer the expiration of timeouts, preventing unnecessary
 * wakeups by batch processing similarly expiring events.
 */
time_res_t time_res[TR_COUNT];

/*
 * Setting "snooping" to a non-zero value will cause a deadman panic if
 * snoop_interval microseconds elapse without lbolt increasing.  The default
 * snoop_interval is 50 seconds.
 */
#define	SNOOP_INTERVAL_MIN	(MICROSEC)
#define	SNOOP_INTERVAL_DEFAULT	(50 * MICROSEC)

int snooping = 0;
uint_t snoop_interval = SNOOP_INTERVAL_DEFAULT;

/*
 * Tables of initialization functions, called from main().
 */

extern void system_taskq_init(void);
extern void binit(void);
extern void space_init(void);
extern void dnlc_init(void);
extern void vfsinit(void);
extern void finit(void);
extern void strinit(void);
extern void flk_init(void);
extern void ftrace_init(void);
extern void softcall_init(void);
extern void ttyinit(void);
extern void schedctl_init(void);
extern void deadman_init(void);
extern void clock_timer_init(void);
extern void clock_realtime_init(void);
extern void clock_highres_init(void);
extern void clock_tick_mp_init(void);
extern void cu_init(void);
extern void callout_mp_init(void);
extern void cpu_seq_tbl_init(void);

void	(*init_tbl[])(void) = {
	system_taskq_init,
	binit,
	space_init,
	dnlc_init,
	vfsinit,
	finit,
	strinit,
	serializer_init,
	softcall_init,
	ttyinit,
	as_init,
	pvn_init,
	anon_init,
	segvn_init,
	flk_init,
	cpu_seq_tbl_init,
	schedctl_init,
	fdb_init,
	deadman_init,
	clock_timer_init,
	clock_realtime_init,
	clock_highres_init,
	0
};


#if defined(__sparc)
	extern void siron_mp_init();
#endif

/*
 * Any per cpu resources should be initialized via
 * an entry in mp_init_tbl().
 */
void	(*mp_init_tbl[])(void) = {
	ftrace_init,
	cyclic_mp_init,
#if defined(__sparc)
	siron_mp_init,
#endif
	clock_tick_mp_init,
	cu_init,
	callout_mp_init,
	0
};

int maxusers;		/* kitchen-sink knob for dynamic configuration */

/*
 * pidmax -- highest pid value assigned by the system
 * Settable in /etc/system
 */
int pidmax = DEFAULT_MAXPID;

/*
 * jump_pid - if set, this value is where pid numbers should start
 * after the first few system pids (0-3) are used.  If 0, pids are
 * chosen in the usual way. This variable can be used to quickly
 * create large pids (by setting it to 100000, for example). pids
 * less than this value will never be chosen.
 */
pid_t jump_pid = DEFAULT_JUMPPID;

/*
 * autoup -- used in struct var for dynamic config of the age a delayed-write
 * buffer must be in seconds before bdflush will write it out.
 */
#define	DEFAULT_AUTOUP	30
int autoup = DEFAULT_AUTOUP;

/*
 * bufhwm -- tuneable variable for struct var for v_bufhwm.
 * high water mark for buffer cache mem usage in units of K bytes.
 *
 * bufhwm_pct -- ditto, but given in % of physmem.
 */
int bufhwm = 0;
int bufhwm_pct = 0;

/*
 * Process table.
 */
int maxpid;
int max_nprocs;		/* set in param_init() */
int maxuprc;		/* set in param_init() */
int reserved_procs;
int nthread = 1;

/*
 * UFS tunables
 */
int ufs_ninode;		/* declared here due to backwards compatibility */
int ndquot;		/* declared here due to backwards compatibility */

/*
 * Exec switch table. This is used by the generic exec module
 * to switch out to the desired executable type, based on the
 * magic number. The currently supported types are ELF, a.out
 * (both NMAGIC and ZMAGIC), interpreter (#!) files,
 * and Java executables.
 */
/*
 * Magic numbers
 */
short elfmagic = 0x7f45;
short intpmagic = 0x2321;
short jmagic = 0x504b;

#if defined(__sparc)
short aout_nmagic = NMAGIC;
short aout_zmagic = ZMAGIC;
short aout_omagic = OMAGIC;
#endif
short nomagic = 0;

/*
 * Magic strings
 */
#define	ELF32MAGIC_STRING	"\x7f""ELF\x1"
#define	ELF64MAGIC_STRING	"\x7f""ELF\x2"
#define	INTPMAGIC_STRING	"#!"
#define	JAVAMAGIC_STRING	"PK\003\004"
#define	AOUT_OMAGIC_STRING	"\x1""\x07"	/* 0407 */
#define	AOUT_NMAGIC_STRING	"\x1""\x08"	/* 0410 */
#define	AOUT_ZMAGIC_STRING	"\x1""\x0b"	/* 0413 */
#define	NOMAGIC_STRING		""

#define	SHBIN_CNTL(x)	((x)&037)
#define	SHBINMAGIC_STRING {SHBIN_CNTL('k'), SHBIN_CNTL('s'), SHBIN_CNTL('h'), 0}
#define	SHBINMAGIC_LEN	4

char elf32magicstr[] = ELF32MAGIC_STRING;
char elf64magicstr[] = ELF64MAGIC_STRING;
char intpmagicstr[] = INTPMAGIC_STRING;
char shbinmagicstr[] = SHBINMAGIC_STRING;
char javamagicstr[] = JAVAMAGIC_STRING;
#if defined(__sparc)
char aout_nmagicstr[] = AOUT_NMAGIC_STRING;
char aout_zmagicstr[] = AOUT_ZMAGIC_STRING;
char aout_omagicstr[] = AOUT_OMAGIC_STRING;
#endif
char nomagicstr[] = NOMAGIC_STRING;

char *execswnames[] = {
	"elfexec",	/* Elf32 */
#ifdef _LP64
	"elfexec",	/* Elf64 */
#endif
	"intpexec",
	"shbinexec",
	"javaexec",
#if defined(__sparc)
	"aoutexec",
	"aoutexec",
	"aoutexec",
#endif
	NULL,
	NULL,
	NULL
};

struct execsw execsw[] = {
	{ elf32magicstr, 0, 5, NULL, NULL, NULL },
#ifdef _LP64
	{ elf64magicstr, 0, 5, NULL, NULL, NULL },
#endif
	{ intpmagicstr, 0, 2, NULL, NULL, NULL },
	{ shbinmagicstr, 0, SHBINMAGIC_LEN, NULL, NULL, NULL },
	{ javamagicstr, 0, 4, NULL, NULL, NULL },
#if defined(__sparc)
	{ aout_zmagicstr, 2, 2, NULL, NULL, NULL },
	{ aout_nmagicstr, 2, 2, NULL, NULL, NULL },
	{ aout_omagicstr, 2, 2, NULL, NULL, NULL },
#endif
	{ nomagicstr, 0, 0, NULL, NULL, NULL },
	{ nomagicstr, 0, 0, NULL, NULL, NULL },
	{ nomagicstr, 0, 0, NULL, NULL, NULL },
	{ nomagicstr, 0, 0, NULL, NULL, NULL }
};
int nexectype = sizeof (execsw) / sizeof (execsw[0]);	/* # of exec types */
kmutex_t execsw_lock;	/* Used for allocation of execsw entries */

/*
 * symbols added to make changing max-file-descriptors
 * simple via /etc/system
 */
#define	RLIM_FD_CUR 0x100
#define	RLIM_FD_MAX 0x10000

uint_t rlim_fd_cur = RLIM_FD_CUR;
uint_t rlim_fd_max = RLIM_FD_MAX;

/*
 * (Default resource limits were formerly declared here, but are now provided by
 * the more general resource controls framework.)
 */

/*
 * STREAMS tunables
 */
int	nstrpush = 9;		/* maximum # of modules/drivers on a stream */
ssize_t	strctlsz = 1024;	/* maximum size of user-generated M_PROTO */
ssize_t	strmsgsz = 0x10000;	/* maximum size of user-generated M_DATA */
				/* for `strmsgsz', zero means unlimited */
/*
 * Filesystem tunables
 */
int	rstchown = 1;		/* POSIX_CHOWN_RESTRICTED is enabled */
int	ngroups_max = NGROUPS_MAX_DEFAULT;

/*
 * generic scheduling stuff
 *
 * Configurable parameters for RT and TS are in the respective
 * scheduling class modules.
 */

pri_t maxclsyspri = MAXCLSYSPRI;
pri_t minclsyspri = MINCLSYSPRI;
char sys_name[] = "SYS";

extern pri_t sys_init(id_t, int, classfuncs_t **);
extern classfuncs_t sys_classfuncs;

sclass_t sclass[] = {
	{ "SYS",	sys_init,	&sys_classfuncs, STATIC_SCHED, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 },
	{ "",	NULL,	NULL,	NULL, 0 }
};

int loaded_classes = 1;		/* for loaded classes */
kmutex_t class_lock;		/* lock for class[] */

int nclass = sizeof (sclass) / sizeof (sclass_t);
char initcls[] = "TS";
char *defaultclass = initcls;

/*
 * Tunable system parameters.
 */

/*
 * The integers tune_* are done this way so that the tune
 * data structure may be "tuned" if necessary from the /etc/system
 * file. The tune data structure is initialized in param_init();
 */

tune_t tune;

/*
 * If freemem < t_getpgslow, then start to steal pages from processes.
 */
int tune_t_gpgslo = 25;

/*
 * Rate at which fsflush is run, in seconds.
 */
#define	DEFAULT_TUNE_T_FSFLUSHR	1
int tune_t_fsflushr = DEFAULT_TUNE_T_FSFLUSHR;

/*
 * The minimum available resident (not swappable) memory to maintain
 * in order to avoid deadlock.  In pages.
 */
int tune_t_minarmem = 25;

/*
 * The minimum available swappable memory to maintain in order to avoid
 * deadlock.  In pages.
 */
int tune_t_minasmem = 25;

int tune_t_flckrec = 512;	/* max # of active frlocks */

/*
 * Number of currently available pages that cannot be 'locked'
 * This is set in init_pages_pp_maximum, and must be initialized
 * to zero here to detect an override in /etc/system
 */
pgcnt_t pages_pp_maximum = 0;

int boothowto;			/* boot flags passed to kernel */
struct var v;			/* System Configuration Information */

/*
 * System Configuration Information
 */

/*
 * The physical system's host identifier, expressed as a decimal string.
 * Code should only directly access this value when writing to it (setting the
 * physical system's host identifier).  Code that reads the physical system's
 * host identifier should use zone_get_hostid(NULL) instead.
 */
char hw_serial[HW_HOSTID_LEN] = "0";

#if defined(__sparc)

/*
 * On sparc machines, read hw_serial from the firmware at boot time
 * and simply assert Oracle is the hardware provider.
 */
char architecture[] = "sparcv9";
char architecture_32[] = "sparc";
char hw_provider[] = "Oracle Corporation";

#elif defined(__i386)

char architecture[] = "i386";
char architecture_32[] = "i386";
char hw_provider[SYS_NMLN] = "";

#elif defined(__amd64)

char architecture[] = "amd64";
char architecture_32[] = "i386";
char hw_provider[SYS_NMLN] = "";

#else
#error "unknown processor architecture"
#endif

char srpc_domain[SYS_NMLN] = "";
char platform[SYS_NMLN] = "";	/* read from the devinfo root node */

/* Initialize isa_list */
char *isa_list = architecture;

static pgcnt_t original_physmem = 0;

#define	MIN_DEFAULT_MAXUSERS	8u
#define	MAX_DEFAULT_MAXUSERS	10000u
#define	MAX_MAXUSERS		20000u

void
param_preset(void)
{
	original_physmem = physmem;
}

void
param_calc(int platform_max_nprocs)
{
	/*
	 * Default to about one "user" per 8MB, taking into
	 * account both physical and virtual constraints.
	 * Note: 2^20 is a meg; shifting right by (20 - PAGESHIFT)
	 * converts pages to megs without integer overflow.
	 */
#if defined(__sparc)
	if (physmem > original_physmem) {
		physmem = original_physmem;
		cmn_err(CE_NOTE, "physmem limited to %ld", physmem);
	}
#endif
	if (maxusers == 0) {
		pgcnt_t physmegs = physmem >> (20 - PAGESHIFT);
		pgcnt_t virtmegs = vmem_size(heap_arena, VMEM_FREE) >> 20;
		maxusers = MIN(physmegs, virtmegs) >> 3; /* divide by 8 */
		maxusers = MAX(maxusers, MIN_DEFAULT_MAXUSERS);
		maxusers = MIN(maxusers, MAX_DEFAULT_MAXUSERS);
	}
	if (maxusers > MAX_MAXUSERS) {
		maxusers = MAX_MAXUSERS;
		cmn_err(CE_NOTE, "maxusers limited to %d", MAX_MAXUSERS);
	}

#ifdef DEBUG
	/*
	 * The purpose of maxusers is to prevent memory overcommit.
	 * DEBUG kernels take more space, so reduce maxusers a bit.
	 */
	maxusers = (3 * maxusers) / 4;
#endif

	/*
	 * We need to dynamically change any variables now so that
	 * the setting of maxusers and pidmax propagate to the other
	 * variables that are dependent on them.
	 */
	if (reserved_procs == 0)
		reserved_procs = 5;
	if (pidmax < reserved_procs || pidmax > MAX_MAXPID)
		maxpid = MAX_MAXPID;
	else
		maxpid = pidmax;

	/*
	 * This allows platform-dependent code to constrain the maximum
	 * number of processes allowed in case there are e.g. VM limitations
	 * with how many contexts are available.
	 */
	if (max_nprocs == 0)
		max_nprocs = (10 + 16 * maxusers);
	if (platform_max_nprocs > 0 && max_nprocs > platform_max_nprocs)
		max_nprocs = platform_max_nprocs;
	if (max_nprocs > maxpid)
		max_nprocs = maxpid;

	if (maxuprc == 0)
		maxuprc = (max_nprocs - reserved_procs);
}

void
param_init(void)
{
	/*
	 * Set each individual element of struct var v to be the
	 * default value. This is done this way
	 * so that a user can set the assigned integer value in the
	 * /etc/system file *IF* tuning is needed.
	 */
	v.v_proc = max_nprocs;	/* v_proc - max # of processes system wide */
	v.v_maxupttl = max_nprocs - reserved_procs;
	v.v_maxsyspri = (int)maxclsyspri;  /* max global pri for sysclass */
	v.v_maxup = MIN(maxuprc, v.v_maxupttl); /* max procs per user */
	v.v_autoup = autoup;	/* v_autoup - delay for delayed writes */

	/*
	 * Set each individual element of struct tune to be the
	 * default value. Each struct element This is done this way
	 *  so that a user can set the assigned integer value in the
	 * /etc/system file *IF* tuning is needed.
	 */
	tune.t_gpgslo = tune_t_gpgslo;
	tune.t_fsflushr = tune_t_fsflushr;
	tune.t_minarmem = tune_t_minarmem;
	tune.t_minasmem = tune_t_minasmem;
	tune.t_flckrec = tune_t_flckrec;

	/*
	 * Initialization for file descriptors to correct mistaken settings in
	 * /etc/system.  Initialization of limits performed by resource control
	 * system.
	 */
	if (rlim_fd_cur > rlim_fd_max)
		rlim_fd_cur = rlim_fd_max;

	/*
	 * calculations needed if hz was set in /etc/system
	 */
	if (hires_tick)
		hz = hires_hz;

	tick_per_msec = hz / MILLISEC;
	msec_per_tick = MILLISEC / hz;
	usec_per_tick = MICROSEC / hz;
	nsec_per_tick = NANOSEC / hz;
	max_hres_adj = nsec_per_tick >> ADJ_SHIFT;

	/*
	 * Consumers of relative timedwait functions must specify how accurately
	 * the given timeout must expire. This is currently TR_CLOCK_TICK for
	 * the vast majority of consumers, but nsec_per_tick becomes an
	 * artificial value in a tickless world. Each caller of such routines
	 * should re-evaluate their usage and specify the appropriate
	 * resolution.
	 */
	time_res[TR_NANOSEC] = NANOSEC / NANOSEC;
	time_res[TR_MICROSEC] = NANOSEC / MICROSEC;
	time_res[TR_MILLISEC] = NANOSEC / MILLISEC;
	time_res[TR_SEC] = NANOSEC / SEC;
	time_res[TR_CLOCK_TICK] = nsec_per_tick;
}

/*
 * Validate tuneable parameters following /etc/system processing,
 * but prior to param_init().
 */
void
param_check(void)
{
#if defined(__x86)
	if (physmem != original_physmem) {
		cmn_err(CE_NOTE, "physmem cannot be modified to 0x%lx"
		    " via /etc/system. Please use eeprom(1M) instead.",
		    physmem);
		physmem = original_physmem;
	}
#endif
	if (ngroups_max < NGROUPS_UMIN)
		ngroups_max = NGROUPS_UMIN;
	if (ngroups_max > NGROUPS_UMAX)
		ngroups_max = NGROUPS_UMAX;

	/* If we have many groups then the ucred proto message also grows. */
	if (ngroups_max > NGROUPS_OLDMAX &&
	    strctlsz < (ngroups_max - NGROUPS_OLDMAX) * sizeof (gid_t) + 1024) {
		strctlsz = (ngroups_max - NGROUPS_OLDMAX) * sizeof (gid_t) +
		    1024;
	}

	if (autoup <= 0) {
		autoup = DEFAULT_AUTOUP;
		cmn_err(CE_WARN, "autoup <= 0; defaulting to %d", autoup);
	}

	if (tune_t_fsflushr <= 0) {
		tune_t_fsflushr = DEFAULT_TUNE_T_FSFLUSHR;
		cmn_err(CE_WARN, "tune_t_fsflushr <= 0; defaulting to %d",
		    tune_t_fsflushr);
	}

	if (jump_pid < 0 || jump_pid >= pidmax) {
		jump_pid = 0;
		cmn_err(CE_WARN, "jump_pid < 0 or >= pidmax; ignored");
	}

	if (snoop_interval < SNOOP_INTERVAL_MIN) {
		snoop_interval = SNOOP_INTERVAL_DEFAULT;
		cmn_err(CE_WARN, "snoop_interval < minimum (%d); defaulting"
		    " to %d", SNOOP_INTERVAL_MIN, SNOOP_INTERVAL_DEFAULT);
	}
}
