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
 */

#ifndef _SYS_CPR_H
#define	_SYS_CPR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/obpdefs.h>
#include <sys/param.h>
#include <sys/mutex.h>
#include <sys/uadmin.h>
#include <sys/compress.h>
#include <sys/archsystm.h>

/*
 * definitions for kernel, cprboot, pmconfig
 */
#define	CPR_VERSION		6
#define	CPR_CONFIG		"/etc/.cpr_config"


/*
 * magic numbers for cpr files
 */
#define	CPR_CONFIG_MAGIC	0x436E4667	/* 'CnFg' */
#define	CPR_DEFAULT_MAGIC	0x44664C74	/* 'DfLt' */

/*
 * max(strlen("true"), strlen("false")) + 1
 */
#define	PROP_BOOL_LEN		6
#define	PROP_MOD		'Y'
#define	PROP_NOMOD		'N'

/*
 * max property name length used
 * max property count
 */
#define	CPR_MAXPLEN		15
#define	CPR_MAXPROP		5

/*
 * name/value of nvram properties
 */
struct cpr_prop_info {
	char	mod;
	char	name[CPR_MAXPLEN];
	char	value[OBP_MAXPATHLEN];
};
typedef struct cpr_prop_info cprop_t;

struct cpr_default_mini {
	int	magic;				/* magic word for booter */
	int	reusable;			/* true if resuable statefile */
};
typedef struct cpr_default_mini cmini_t;

struct cpr_default_info {
	cmini_t	mini;
	cprop_t	props[CPR_MAXPROP];		/* nvram property info */
};
typedef struct cpr_default_info cdef_t;


/*
 * Configuration info provided by user via pmconfig.
 *
 * The first part (cf_type, cf_path, cf_fs, cf_devfs, cf_dev_prom)
 * is used by both the cpr kernel module and cpr booter program
 * to locate the statefile.
 *
 * cf_type	CFT_UFS
 * cf_path	(path within file system) ".CPR"
 * cf_fs	(mount point for the statefile's filesystem) "/export/home"
 * cf_devfs	(devfs path of disk parition mounted there) "/dev/dsk/c0t0d0s7"
 * cf_dev_prom	(prom device path of the above disk partition)
 *			"/sbus/espdma/dma/sd@0:h"
 *
 * If the statefile were on a character special device (/dev//rdsk/c0t1d0s7),
 * the fields would have the typical values shown below:
 *
 * cf_type	CFT_SPEC
 * cf_path	ignored
 * cf_fs	ignored
 * cf_devfs	/dev/rdsk/c1t0d0s7
 * cf_dev_prom	(prom device path of the above special file)
 *			"/sbus/espdma/dma/sd@1:h"
 *
 * If the statefile is on a zvol, the fields would have these values:
 *
 * cf_type	CFT_ZVOL
 * cf_path	ignored
 * cf_fs	(the zvol name e.g. "dump" portion of rootpool/dump)
 * cf_devfs	(devfs path) "/dev/zvol/dsk/<pool>/<zvol>"
 * cf_dev_prom	(prom device path of the above special file)
 *		e.g. "/sbus/espdma/dma/sd@1:h"
 *
 * The rest of the fields are autoshutdown and autopm configuration related.
 * They are updated by pmconfig and consumed by both powerd and dtpower.
 */

struct cprconfig {
	int	cf_magic;			/* magic word for	*/
						/* booter to verify	*/
	int	cf_type;			/* CFT_UFS or CFT_SPEC	*/
	char	cf_path[MAXNAMELEN];		/* fs-relative path	*/
						/* for the state file	*/
	char	cf_fs[MAXNAMELEN];		/* mount point for fs	*/
						/* holding state file	*/
	char	cf_devfs[MAXNAMELEN];		/* path to device node	*/
						/* for above mount pt.	*/
	char	cf_dev_prom[OBP_MAXPATHLEN];	/* full device path of	*/
						/* above filesystem	*/
	/*
	 * autoshutdown configuration fields
	 */
	int	is_cpr_capable;			/* 0 - False, 1 - True */
	int	is_cpr_default;			/* 0 - False, 1 - True */
	int	is_autowakeup_capable;		/* 0 - False, 1 - True */
	int	as_idle;			/* idle time in min */
	int	as_sh;				/* Start_time hour */
	int	as_sm;				/* Start_time minutes */
	int	as_fh;				/* Finish_time hour */
	int	as_fm;				/* Finish_time minute */
	char	as_behavior[64];		/* "default","unconfigured", */
						/* "shutdown", "autowakeup" */
						/*  or "noshutdown" */
	int	ttychars_thold;			/* default = 0 */
	float	loadaverage_thold;		/* default = 0.04  */
	int	diskreads_thold;		/* default = 0 */
	int	nfsreqs_thold;			/* default = 0 */
	char	idlecheck_path[MAXPATHLEN];	/* default = "" */

	/*
	 * autopm behavior field
	 */
	int	is_autopm_default;		/* 0 - False, 1 - True */
	char	apm_behavior[64];		/* "enable","disable" or */
						/* "default" */
};


/*
 * values for cf_type
 */
#define	CFT_UFS		1		/* statefile is ufs file	*/
#define	CFT_SPEC	2		/* statefile is special file	*/
#define	CFT_ZVOL	3		/* statefile is a zvol		*/


/*
 * definitions for kernel, cprboot
 */
#ifdef _KERNEL

#include <sys/promif.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/vnode.h>
#include <sys/cpr_impl.h>

extern int	cpr_debug;

#define	errp	prom_printf
#define	DPRINT

/*
 * CPR_DEBUG1 displays the main flow of CPR. Use it to identify which
 * sub-module of CPR causes problems.
 * CPR_DEBUG2 displays minor stuff that normally won't matter.
 * CPR_DEBUG3 displays some big loops (cpr_dump); requires much longer runtime.
 * CPR_DEBUG4 displays lots of cprboot output, cpr_read and page handling.
 * CPR_DEBUG5 various, mostly unique stuff
 * CPR_DEBUG9 displays statistical data for CPR on console (by using printf),
 *	such as num page invalidated, etc.
 */
#define	CPR_DEBUG1	0x1
#define	CPR_DEBUG2	0x2
#define	CPR_DEBUG3	0x4
#define	CPR_DEBUG4	0x8
#define	CPR_DEBUG5	0x10
#define	CPR_DEBUG6	0x20
#define	CPR_DEBUG7	0x40
#define	CPR_DEBUG8	0x80
#define	CPR_DEBUG9	CPR_DEBUG6

#define	CPR_DEBUG(level, ...) if (cpr_debug & level) cpr_dprintf(__VA_ARGS__)

#define	CPR_DEBUG_BIT(dval)	(1 << (dval - AD_CPR_DEBUG0 - 1))
#define	DBG_DONTSHOWRANGE	0
#define	DBG_SHOWRANGE		1

/*
 * CPR FILE FORMAT:
 *
 * 	Dump Header: general dump data:
 *		cpr_dump_desc
 *
 *	Machdep descriptor: cpr_machdep_desc
 *	Machdep data: sun4m/sun4u machine dependent info:
 *		cpr_sun4m_machdep
 *		cpr_sun4u_machdep, var length prom words
 *
 * 	Page Map: bitmap record consisting of a descriptor and data:
 *		cpr_bitmap_desc
 *		(char) bitmap[cpr_bitmap_desc.cbd_size]
 *
 * 	Page data: Contains one or more physical page records,
 *		each record consists of a descriptor and data:
 *		cpr_page_desc
 *		(char) page_data[cpr_page_desc.cpd_offset]
 *
 *	Terminator: end marker
 *		cpr_terminator
 *
 *	NOTE: cprboot now supports both ILP32 and LP64 kernels;
 *	the size of these structures written to a cpr statefile
 *	must be the same for ILP32 and LP64.  For details, see
 *	sun4u/sys/cpr_impl.h
 */

#define	CPR_DUMP_MAGIC		0x44754d70	/* 'DuMp' */
#define	CPR_BITMAP_MAGIC	0x42744d70	/* 'BtMp' */
#define	CPR_PAGE_MAGIC		0x50614765	/* 'PaGe' */
#define	CPR_MACHDEP_MAGIC	0x4d614470	/* 'MaDp' */
#define	CPR_TERM_MAGIC		0x5465526d	/* 'TeRm' */

/*
 * header at the begining of the dump data section
 */
struct cpr_dump_desc {
	uint_t		cdd_magic;	/* paranoia check */
	ushort_t	cdd_version;	/* version number */
	ushort_t	cdd_machine;	/* sun4m, sun4u */
	int		cdd_bitmaprec;	/* number of bitmap records */
	int		cdd_dumppgsize;	/* total # of frames dumped, in pages */
	int		cdd_test_mode;	/* true if called by uadmin test mode */
	int		cdd_debug;	/* turn on debug in cprboot */
	cpr_ext		cdd_filesize;	/* statefile size in bytes */
};
typedef struct cpr_dump_desc cdd_t;

/*
 * physical memory bitmap descriptor, preceeds the actual bitmap.
 */
struct cpr_bitmap_desc {
	uint_t		cbd_magic;	/* so we can spot it better */
	pfn_t		cbd_spfn;   	/* starting pfn */
	pfn_t		cbd_epfn;	/* ending pfn */
	size_t		cbd_size;	/* size of this bitmap, in bytes */
	cpr_ptr		cbd_reg_bitmap;	/* regular bitmap */
	cpr_ptr		cbd_vlt_bitmap; /* volatile bitmap */
	cpr_ptr		cbd_auxmap; 	/* aux bitmap used during thaw */
};
typedef struct cpr_bitmap_desc cbd_t;

/*
 * Maximum supported bitmap descriptors; 1-2 + null-terminator is common
 */
#define	CPR_MAX_BMDESC	(16 + 1)

/*
 * Describes the contiguous pages saved in the storage area.
 * To save space data will be compressed before saved.
 * However some data end up bigger after compression.
 * In that case, we save the raw data and make a note
 * of it in the csd_clean_compress field.
 */
struct cpr_storage_desc {
	pfn_t		csd_dirty_spfn;		/* starting dirty pfn */
	pgcnt_t		csd_dirty_npages;
	cpr_ptr		csd_clean_sva;		/* starting clean va */
	size_t		csd_clean_sz;
	int		csd_clean_compressed;
#ifdef DEBUG
	uint_t		csd_usum;
	uint_t		csd_csum;
#endif
};
typedef struct cpr_storage_desc csd_t;

/*
 * Describes saved pages, preceeds page data;
 * cpd_lenth len is important when pages are compressed.
 */
struct cpr_page_desc {
	uint_t	cpd_magic;	/* so we can spot it better */
	pfn_t	cpd_pfn;   	/* kern physical address page # */
	pgcnt_t	cpd_pages;	/* number of contiguous pages */
	size_t	cpd_length;	/* data segment size in bytes */
	uint_t	cpd_flag;	/* see below */
	uint_t	cpd_csum;	/* "after compression" checksum */
	uint_t	cpd_usum;	/* "before compression" checksum */
};
typedef struct cpr_page_desc cpd_t;

/*
 * cpd_flag values
 */
#define	CPD_COMPRESS	0x0001	/* set if compressed */
#define	CPD_CSUM	0x0002	/* set if "after compression" checsum valid */
#define	CPD_USUM	0x0004	/* set if "before compression" checsum valid */

/*
 * machdep header stores the length of the platform specific information
 * that are used by resume.
 *
 * Note: the md_size field is the total length of the machine dependent
 * information.  This always includes a fixed length section and may
 * include a variable length section following it on some platforms.
 */
struct cpr_machdep_desc {
	uint_t md_magic;	/* paranoia check */
	uint_t md_size;		/* the size of the "opaque" data following */
};
typedef struct cpr_machdep_desc cmd_t;

typedef struct timespec32 cpr_time_t;

struct cpr_terminator {
	uint_t	magic;			/* paranoia check */
	size_t	real_statef_size;	/* ...in bytes */
	cpr_ptr	va;			/* virtual addr of this struct */
	cpr_ext	pfn;			/* phys addr of this struct */
	cpr_time_t tm_shutdown;		/* time in milisec when shutdown */
	cpr_time_t tm_cprboot_start;	/* time when cprboot starts to run */
	cpr_time_t tm_cprboot_end;	/* time before jumping to kernel */
};
typedef struct cpr_terminator ctrm_t;


#define	REGULAR_BITMAP		1
#define	VOLATILE_BITMAP		0

/*
 * reference the right bitmap based on the arg descriptor and flag
 */
#define	DESC_TO_MAP(desc, flag)	(flag == REGULAR_BITMAP) ? \
	(char *)desc->cbd_reg_bitmap : (char *)desc->cbd_vlt_bitmap
/*
 * checks if a phys page is within the range covered by a bitmap
 */
#define	PPN_IN_RANGE(ppn, desc) \
	(ppn <= desc->cbd_epfn && ppn >= desc->cbd_spfn)

#define	WRITE_TO_STATEFILE	0
#define	SAVE_TO_STORAGE		1
#define	STORAGE_DESC_ALLOC	2


/*
 * prom_read() max is 32k
 * for sun4m, page size is 4k, CPR_MAXCONTIG is 8
 * for sun4u, page size is 8k, CPR_MAXCONTIG is 4
 */
#define	PROM_MAX_READ	0x8000
#define	CPR_MAX_BLOCK	0x8000
#define	CPR_MAXCONTIG	(CPR_MAX_BLOCK / MMU_PAGESIZE)

#define	PAGE_ROUNDUP(val)	(((val) + MMU_PAGEOFFSET) & MMU_PAGEMASK)

/*
 * converts byte size to bitmap size; 1 bit represents one phys page
 */
#define	BITMAP_BYTES(size)	((size) >> (MMU_PAGESHIFT + 3))


/*
 * redefinitions of uadmin subcommands for A_FREEZE
 */
#define	AD_CPR_COMPRESS		AD_COMPRESS /* store state file compressed */
#define	AD_CPR_FORCE		AD_FORCE /* force to do AD_CPR_COMPRESS */
#define	AD_CPR_CHECK		AD_CHECK /* test if CPR module is there */
#define	AD_CPR_REUSEINIT	AD_REUSEINIT /* write cprinfo file */
#define	AD_CPR_REUSABLE		AD_REUSABLE /* create reusable statefile */
#define	AD_CPR_REUSEFINI	AD_REUSEFINI /* revert to non-reusable CPR */
#define	AD_CPR_TESTHALT		6	/* test mode, halt */
#define	AD_CPR_TESTNOZ		7	/* test mode, auto-restart uncompress */
#define	AD_CPR_TESTZ		8	/* test mode, auto-restart compress */
#define	AD_CPR_PRINT		9	/* print out stats */
#define	AD_CPR_NOCOMPRESS	10	/* store state file uncompressed */
#define	AD_CPR_SUSP_DEVICES	11	/* Only suspend resume devices */
#define	AD_CPR_DEBUG0		100	/* clear debug flag */
#define	AD_CPR_DEBUG1		101	/* display CPR main flow via prom */
#define	AD_CPR_DEBUG2		102	/* misc small/mid size loops */
#define	AD_CPR_DEBUG3		103	/* exhaustive big loops */
#define	AD_CPR_DEBUG4		104	/* debug cprboot */
#define	AD_CPR_DEBUG5		105	/* debug machdep part of resume */
#define	AD_CPR_DEBUG7		107	/* debug bitmap code */
#define	AD_CPR_DEBUG8		108
#define	AD_CPR_DEBUG9		109	/* display stat data on console */

/*
 * Suspend to RAM test points.
 * Probably belong above, but are placed here for now.
 */
/* S3 leave hardware on and return success */
#define	AD_LOOPBACK_SUSPEND_TO_RAM_PASS	22

/* S3 leave hardware on and return failure */
#define	AD_LOOPBACK_SUSPEND_TO_RAM_FAIL	23

/* S3 ignored devices that fail to suspend */
#define	AD_FORCE_SUSPEND_TO_RAM		24

/* S3 on a specified device */
#define	AD_DEVICE_SUSPEND_TO_RAM	25



/*
 * Temporary definition of the Suspend to RAM development subcommands
 * so that non-ON apps will work after initial integration.
 */
#define	DEV_SUSPEND_TO_RAM	200
#define	DEV_CHECK_SUSPEND_TO_RAM	201

/*
 * cprboot related information and definitions.
 * The statefile names are hardcoded for now.
 */
#define	CPR_DEFAULT		"/.cpr_default"
#define	CPR_STATE_FILE		"/.CPR"


/*
 * definitions for CPR statistics
 */
#define	CPR_E_NAMELEN		64
#define	CPR_E_MAX_EVENTNUM	64

struct cpr_tdata {
	time_t	mtime;		/* mean time on this event */
	time_t	stime;		/* start time on this event */
	time_t	etime;		/* end time on this event */
	time_t	ltime;		/* time duration of the last event */
};
typedef struct cpr_tdata ctd_t;

struct cpr_event {
	struct	cpr_event *ce_next;	/* next event in the list */
	long	ce_ntests;		/* num of the events since loaded */
	ctd_t	ce_sec;			/* cpr time in sec on this event */
	ctd_t	ce_msec;		/* cpr time in 100*millisec */
	char 	ce_name[CPR_E_NAMELEN];
};

struct cpr_stat {
	int	cs_ntests;		/* num of cpr's since loaded */
	int	cs_mclustsz;		/* average cluster size: all in bytes */
	int	cs_upage2statef;	/* actual # of upages gone to statef */
	int	cs_min_comprate;	/* minimum compression ratio * 100 */
	pgcnt_t	cs_nosw_pages;		/* # of pages of no backing store */
	size_t	cs_nocomp_statefsz;	/* statefile size without compression */
	size_t	cs_est_statefsz;	/* estimated statefile size */
	size_t	cs_real_statefsz;	/* real statefile size */
	size_t	cs_dumped_statefsz;	/* how much has been dumped out */
	struct cpr_event *cs_event_head; /* The 1st one in stat event list */
	struct cpr_event *cs_event_tail; /* The last one in stat event list */
};

/*
 * macros for CPR statistics evaluation
 */
#define	CPR_STAT_EVENT_START(s)		cpr_stat_event_start(s, 0)
#define	CPR_STAT_EVENT_END(s)		cpr_stat_event_end(s, 0)
/*
 * use the following is other time zone is required
 */
#define	CPR_STAT_EVENT_START_TMZ(s, t)	cpr_stat_event_start(s, t)
#define	CPR_STAT_EVENT_END_TMZ(s, t)	cpr_stat_event_end(s, t)

#define	CPR_STAT_EVENT_PRINT		cpr_stat_event_print


/*
 * State Structure for CPR
 */
typedef struct cpr {
	uint_t		c_cprboot_magic;
	uint_t		c_flags;
	int		c_substate;	/* tracking suspend progress */
	int		c_fcn;		/* uadmin subcommand */
	vnode_t		*c_vp;		/* vnode for statefile */
	cbd_t  		*c_bmda;	/* bitmap descriptor array */
	caddr_t		c_mapping_area;	/* reserve for dumping kas phys pages */
	struct cpr_stat	c_stat;
	char		c_alloc_cnt;	/* # of statefile alloc retries */
} cpr_t;

/*
 * c_flags definitions
 */
#define	C_SUSPENDING		0x01
#define	C_RESUMING		0x02
#define	C_COMPRESSING		0x04
#define	C_REUSABLE		0x08
#define	C_ERROR			0x10

extern cpr_t cpr_state;
#define	CPR	(&cpr_state)
#define	STAT	(&cpr_state.c_stat)

/*
 * definitions for c_substate. It works together w/ c_flags to determine which
 * stages the CPR is at.
 */
#define	C_ST_SUSPEND_BEGIN		0
#define	C_ST_MP_OFFLINE			1
#define	C_ST_STOP_USER_THREADS		2
#define	C_ST_PM_REATTACH_NOINVOL	3
#define	C_ST_DISABLE_UFS_LOGGING	4
#define	C_ST_STATEF_ALLOC		5
#define	C_ST_SUSPEND_DEVICES		6
#define	C_ST_STOP_KERNEL_THREADS	7
#define	C_ST_SETPROPS_1			8
#define	C_ST_DUMP			9
#define	C_ST_SETPROPS_0			10
#define	C_ST_DUMP_NOSPC			11
#define	C_ST_REUSABLE			12
#define	C_ST_NODUMP			13
#define	C_ST_MP_PAUSED			14

#define	cpr_set_substate(a)	(CPR->c_substate = (a))

#define	C_VP		(CPR->c_vp)

#define	C_MAX_ALLOC_RETRY	4

#define	CPR_PROM_SAVE		0
#define	CPR_PROM_RESTORE	1
#define	CPR_PROM_FREE		2

/*
 * default/historic size for cpr write buffer
 */
#define	CPRBUFSZ		0x20000

/*
 * cpr statefile I/O on a block device begins after the disk label
 * and bootblock (primarily for disk slices that start at cyl 0);
 * the offset should be at least (label size + bootblock size = 8k)
 */
#define	CPR_SPEC_OFFSET		16384

typedef int (*bitfunc_t)(pfn_t, int);

/*
 * arena scan info
 */
struct cpr_walkinfo {
	int mapflag;
	bitfunc_t bitfunc;
	pgcnt_t pages;
	size_t size;
	int ranges;
};

/*
 * Value used by cpr, found in devi_cpr_flags
 */
#define	DCF_CPR_SUSPENDED	0x1	/* device went through cpr_suspend */

/*
 * Values used to differentiate between suspend to disk and suspend to ram
 * in cpr_suspend and cpr_resume
 */

#define	CPR_TORAM	3
#define	CPR_TODISK	4

#ifndef _ASM

extern char *cpr_build_statefile_path(void);
extern char *cpr_enumerate_promprops(char **, size_t *);
extern char *cpr_get_statefile_prom_path(void);
extern int cpr_contig_pages(vnode_t *, int);
extern int cpr_default_setup(int);
extern int cpr_dump(vnode_t *);
extern int cpr_get_reusable_mode(void);
extern int cpr_isset(pfn_t, int);
extern int cpr_main(int);
extern int cpr_mp_offline(void);
extern int cpr_mp_online(void);
extern int cpr_nobit(pfn_t, int);
extern int cpr_open_deffile(int, vnode_t **);
extern int cpr_read_cdump(int, cdd_t *, ushort_t);
extern int cpr_read_cprinfo(int, char *, char *);
extern int cpr_read_machdep(int, caddr_t, size_t);
extern int cpr_read_phys_page(int, uint_t, int *);
extern int cpr_read_terminator(int, ctrm_t *, caddr_t);
extern int cpr_resume_devices(dev_info_t *, int);
extern int cpr_set_properties(int);
extern int cpr_statefile_is_spec(void);
extern int cpr_statefile_offset(void);
extern int cpr_stop_kernel_threads(void);
extern int cpr_threads_are_stopped(void);
extern int cpr_stop_user_threads(void);
extern int cpr_suspend_devices(dev_info_t *);
extern int cpr_validate_definfo(int);
extern int cpr_write(vnode_t *, caddr_t, size_t);
extern int cpr_update_nvram(cprop_t *);
extern int cpr_write_deffile(cdef_t *);
extern int i_cpr_alloc_bitmaps(void);
extern int i_cpr_dump_sensitive_kpages(vnode_t *);
extern int i_cpr_save_sensitive_kpages(void);
extern pgcnt_t cpr_count_kpages(int, bitfunc_t);
extern pgcnt_t cpr_count_pages(caddr_t, size_t, int, bitfunc_t, int);
extern pgcnt_t cpr_count_volatile_pages(int, bitfunc_t);
extern pgcnt_t i_cpr_count_sensitive_kpages(int, bitfunc_t);
extern pgcnt_t i_cpr_count_special_kpages(int, bitfunc_t);
extern pgcnt_t i_cpr_count_storage_pages(int, bitfunc_t);
extern ssize_t cpr_get_machdep_len(int);
extern void cpr_clear_definfo(void);
extern void cpr_restore_time(void);
extern void cpr_save_time(void);
extern void cpr_show_range(char *, size_t, int, bitfunc_t, pgcnt_t);
extern void cpr_signal_user(int sig);
extern void cpr_spinning_bar(void);
extern void cpr_start_user_threads(void);
extern void cpr_stat_cleanup(void);
extern void cpr_stat_event_end(char *, cpr_time_t *);
extern void cpr_stat_event_print(void);
extern void cpr_stat_event_start(char *, cpr_time_t *);
extern void cpr_stat_record_events(void);
extern void cpr_tod_get(cpr_time_t *ctp);
extern void cpr_tod_status_set(int);
extern void i_cpr_bitmap_cleanup(void);
extern void i_cpr_stop_other_cpus(void);
extern void i_cpr_alloc_cpus(void);
extern void i_cpr_free_cpus(void);

/*PRINTFLIKE2*/
extern void cpr_err(int, const char *, ...) __KPRINTFLIKE(2);

extern cpr_time_t wholecycle_tv;
extern int cpr_reusable_mode;

#endif	/* _ASM */
#endif	/* _KERNEL */


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CPR_H */
