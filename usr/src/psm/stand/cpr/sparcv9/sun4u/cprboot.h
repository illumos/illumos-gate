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

#ifndef _CPRBOOT_H
#define	_CPRBOOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * defs for sun4u cprboot
 */

/*
 * select virt ranges well past _end;
 * these ranges are used for tmp tlb entries
 *
 *     CB_SRC_VIRT	source statefile buffer pages
 *     CB_DST_VIRT	destination kernel pages
 *     CB_STACK_VIRT	new stack
 *     CB_HIGH_VIRT	...and above for the bitmap and co.
 */

#define	CB_SRC_VIRT	0x200000
#define	CB_DST_VIRT	0x300000
#define	CB_STACK_VIRT	0x400000
#define	CB_HIGH_VIRT	0x500000

/*
 * master cpu and slave cpu stack sizes
 * their sum should be (n * MMU_PAGESIZE)
 */
#define	CB_MSS		0x009000
#define	CB_SSS		0x001000
#define	CB_STACK_SIZE	(CB_MSS + CB_SSS)


/*
 * max number of tlb entries and tmp pages for
 * src statefile buf pages and dst kernel pages
 */
#define	CB_MAX_KPAGES	mmu_btop(CPR_MAX_BLOCK)
#define	CB_MAX_BPAGES	(CB_MAX_KPAGES + 1)

#define	ERR		-1


#ifndef _ASM

#define	CB_VPRINTF(args) \
	if (verbose) prom_printf args

#define	CB_VENTRY(name) \
	CB_VPRINTF((ent_fmt, #name, entry))

#define	NULLP (char *)0

#define	CPR_DBG(n)	(cpr_debug & CPR_DEBUG##n)


/*
 * info for handling statefile data
 */
struct statefile {
	int	fd;			/* prom file handle */
	int	kpages;			/* total number of kernel pages */
	size_t	size;			/* file size, rounded for alloc */
	caddr_t	buf;			/* allocated file buffer */
	size_t	buf_offset;		/* byte offset from buf */
	uint_t	*buf_map;		/* map of buf phys page numbers */
	pfn_t	low_ppn;		/* lowest buf ppn */
	pfn_t	high_ppn;		/* highest buf ppn */
	int	npages;			/* nubmer of pages restored */
	int	ngroups;		/* number of page groups restored */
	int	outside;		/* kpage is outside of buf range */
	int	precede;		/* kpage preceeds buf offset */
	int	move;			/* number of buf pages moved */
	int	recycle;		/* free tmp page for reuse */
};

/*
 * convert a statefile buffer byte-offset into a buffer ppn;
 * buf_map starts out as an identity map, and gets updated as
 * pages are moved; the original ppn can always be derived
 * from the ORIG macro:
 */
#define	SF_BUF_PPN(off)		*(sfile.buf_map + mmu_btop(off))
#define	SF_ORIG_PPN(off)	sfile.low_ppn + mmu_btop(off)
#define	SF_SAME_PPN(off)	(SF_BUF_PPN(off) == SF_ORIG_PPN(off))
#define	SF_DIFF_PPN(off)	(SF_BUF_PPN(off) != SF_ORIG_PPN(off))

#define	SF_STAT_INC(field)	sfile.field++


/*
 * next data in statefile buffer
 */
#define	SF_DATA()	sfile.buf + sfile.buf_offset

/*
 * advance statefile buffer offset
 */
#define	SF_ADV(len)	sfile.buf_offset += len

/*
 * struct data is written to the statefile without any alignment
 * handling; for easy access, struct data gets copied to aligned
 * space and the buf data pointer is advanced
 */
#define	SF_DCOPY(space) \
	bcopy(SF_DATA(), &space, sizeof (space)); \
	SF_ADV(sizeof (space))


/*
 * structure of "available" property from /memory node
 */
struct prom_physavail {
	physaddr_t base;		/* start of phys range */
	size_t size;			/* size of phys range */
};

struct avail_range {
	pfn_t low;
	pfn_t high;
	pgcnt_t nfree;
};

typedef struct prom_physavail pphav_t;
typedef struct avail_range arange_t;


/*
 * prom properties and data
 */
struct cb_props {
	caddr_t prop;
	uint_t *datap;
};


/*
 * ../../common/support.c
 */
extern int cpr_reset_properties(void);
extern int cpr_locate_statefile(char *, char *);
extern void cpr_update_terminator(ctrm_t *, caddr_t);

/*
 * cprboot.c
 */
extern struct statefile sfile;
extern char prog[];
extern char rsvp[];
extern char entry[];
extern char ent_fmt[];
extern int verbose;
extern uint_t cb_dents;
extern uint_t cb_msec;
extern char *volname;

/*
 * machdep.c
 */
extern int cpr_test_mode;
extern csu_md_t mdinfo;
extern uint_t cpu_delay;
extern uint_t cb_mid;
extern uint_t cb_clock_freq;
extern int cb_check_machdep(void);
extern int cb_interpret(void);
extern int cb_ksetup(void);
extern int cb_mpsetup(void);
extern void slave_init(int);

/*
 * pages.c
 */
extern int cb_restore_kpages(void);
extern int cb_terminator(void);

/*
 * bitmap.c
 */
extern int cb_nbitmaps;
extern pfn_t find_apage(void);
extern int cb_set_bitmap(void);
extern int cb_get_newstack(void);
extern int cb_tracking_setup(void);
extern int cb_get_physavail(void);
extern int cb_relocate(void);

/*
 * util.c
 */
extern int cpr_statefile_open(char *, char *);
extern int cpr_statefile_close(int);
extern int cpr_read(int, caddr_t, size_t);
extern void cb_spin(void);
extern pfn_t cpr_vatopfn(caddr_t);
extern int prom_remap(size_t, caddr_t, physaddr_t);
extern void install_remap(void);
extern int cb_alloc(size_t, uint_t, caddr_t *, physaddr_t *);
extern int cb_mountroot(void);
extern int cb_unmountroot(void);
extern int cb_get_props(void);
extern void cb_mapin(caddr_t, pfn_t, uint_t, uint_t, uint_t);
extern int cb_usb_setup(void);
extern void cb_enter_mon(void);
extern void cb_exit_to_mon(void);
extern int cpr_fs_close(int);
extern int cpr_fs_volopen(char *);
extern int cpr_fs_open(char *);
extern int cpr_fs_read(int, char *, int);
extern int cpr_fs_seek(int, offset_t);
extern int cpr_read(int, char *, size_t);

/*
 * cb_srt0.s
 */
extern caddr_t _end[];
extern void *estack;
extern void _start(void *, ...);
extern void exit_to_kernel(void *, csu_md_t *);
extern void bzero(void *, size_t);
extern void phys_xcopy(physaddr_t, physaddr_t, size_t);
extern void ptov_bcopy(physaddr_t, void *, size_t);
extern void get_dtlb_entry(int, caddr_t *, tte_t *);
extern void set_dtlb_entry(int, caddr_t, tte_t *);
extern void set_itlb_entry(int, caddr_t, tte_t *);
extern void cpu_launch(int);
extern void cb_usec_wait(int);
extern void membar_stld(void);
extern uint_t getmid(void);

#endif /* !_ASM */

#ifdef __cplusplus
}
#endif

#endif	/* _CPRBOOT_H */
