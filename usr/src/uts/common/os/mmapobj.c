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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/mman.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/vmsystm.h>
#include <sys/machsystm.h>
#include <sys/debug.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <sys/vmparam.h>
#include <sys/vfs.h>
#include <sys/elf.h>
#include <sys/machelf.h>
#include <sys/corectl.h>
#include <sys/exec.h>
#include <sys/exechdr.h>
#include <sys/autoconf.h>
#include <sys/mem.h>
#include <vm/seg_dev.h>
#include <sys/vmparam.h>
#include <sys/mmapobj.h>
#include <sys/atomic.h>

/*
 * Theory statement:
 *
 * The main driving force behind mmapobj is to interpret and map ELF files
 * inside of the kernel instead of having the linker be responsible for this.
 *
 * mmapobj also supports the AOUT 4.x binary format as well as flat files in
 * a read only manner.
 *
 * When interpreting and mapping an ELF file, mmapobj will map each PT_LOAD
 * or PT_SUNWBSS segment according to the ELF standard.  Refer to the "Linker
 * and Libraries Guide" for more information about the standard and mapping
 * rules.
 *
 * Having mmapobj interpret and map objects will allow the kernel to make the
 * best decision for where to place the mappings for said objects.  Thus, we
 * can make optimizations inside of the kernel for specific platforms or
 * cache mapping information to make mapping objects faster.
 *
 * The lib_va_hash will be one such optimization.  For each ELF object that
 * mmapobj is asked to interpret, we will attempt to cache the information
 * about the PT_LOAD and PT_SUNWBSS sections to speed up future mappings of
 * the same objects.  We will cache up to LIBVA_CACHED_SEGS (see below) program
 * headers which should cover a majority of the libraries out there without
 * wasting space.  In order to make sure that the cached information is valid,
 * we check the passed in vnode's mtime and ctime to make sure the vnode
 * has not been modified since the last time we used it.
 *
 * In addition, the lib_va_hash may contain a preferred starting VA for the
 * object which can be useful for platforms which support a shared context.
 * This will increase the likelyhood that library text can be shared among
 * many different processes.  We limit the reserved VA space for 32 bit objects
 * in order to minimize fragmenting the processes address space.
 *
 * In addition to the above, the mmapobj interface allows for padding to be
 * requested before the first mapping and after the last mapping created.
 * When padding is requested, no additional optimizations will be made for
 * that request.
 */

/*
 * Threshold to prevent allocating too much kernel memory to read in the
 * program headers for an object.  If it requires more than below,
 * we will use a KM_NOSLEEP allocation to allocate memory to hold all of the
 * program headers which could possibly fail.  If less memory than below is
 * needed, then we use a KM_SLEEP allocation and are willing to wait for the
 * memory if we need to.
 */
size_t mmapobj_alloc_threshold = 65536;

/* Debug stats for test coverage */
#ifdef DEBUG
struct mobj_stats {
	uint_t	mobjs_unmap_called;
	uint_t	mobjs_remap_devnull;
	uint_t	mobjs_lookup_start;
	uint_t	mobjs_alloc_start;
	uint_t	mobjs_alloc_vmem;
	uint_t	mobjs_add_collision;
	uint_t	mobjs_get_addr;
	uint_t	mobjs_map_flat_no_padding;
	uint_t	mobjs_map_flat_padding;
	uint_t	mobjs_map_ptload_text;
	uint_t	mobjs_map_ptload_initdata;
	uint_t	mobjs_map_ptload_preread;
	uint_t	mobjs_map_ptload_unaligned_text;
	uint_t	mobjs_map_ptload_unaligned_map_fail;
	uint_t	mobjs_map_ptload_unaligned_read_fail;
	uint_t	mobjs_zfoddiff;
	uint_t	mobjs_zfoddiff_nowrite;
	uint_t	mobjs_zfodextra;
	uint_t	mobjs_ptload_failed;
	uint_t	mobjs_map_elf_no_holes;
	uint_t	mobjs_unmap_hole;
	uint_t	mobjs_nomem_header;
	uint_t	mobjs_inval_header;
	uint_t	mobjs_overlap_header;
	uint_t	mobjs_np2_align;
	uint_t	mobjs_np2_align_overflow;
	uint_t	mobjs_exec_padding;
	uint_t	mobjs_exec_addr_mapped;
	uint_t	mobjs_exec_addr_devnull;
	uint_t	mobjs_exec_addr_in_use;
	uint_t	mobjs_lvp_found;
	uint_t	mobjs_no_loadable_yet;
	uint_t	mobjs_nothing_to_map;
	uint_t	mobjs_e2big;
	uint_t	mobjs_dyn_pad_align;
	uint_t	mobjs_dyn_pad_noalign;
	uint_t	mobjs_alloc_start_fail;
	uint_t	mobjs_lvp_nocache;
	uint_t	mobjs_extra_padding;
	uint_t	mobjs_lvp_not_needed;
	uint_t	mobjs_no_mem_map_sz;
	uint_t	mobjs_check_exec_failed;
	uint_t	mobjs_lvp_used;
	uint_t	mobjs_wrong_model;
	uint_t	mobjs_noexec_fs;
	uint_t	mobjs_e2big_et_rel;
	uint_t	mobjs_et_rel_mapped;
	uint_t	mobjs_unknown_elf_type;
	uint_t	mobjs_phent32_too_small;
	uint_t	mobjs_phent64_too_small;
	uint_t	mobjs_inval_elf_class;
	uint_t	mobjs_too_many_phdrs;
	uint_t	mobjs_no_phsize;
	uint_t	mobjs_phsize_large;
	uint_t	mobjs_phsize_xtralarge;
	uint_t	mobjs_fast_wrong_model;
	uint_t	mobjs_fast_e2big;
	uint_t	mobjs_fast;
	uint_t	mobjs_fast_success;
	uint_t	mobjs_fast_not_now;
	uint_t	mobjs_small_file;
	uint_t	mobjs_read_error;
	uint_t	mobjs_unsupported;
	uint_t	mobjs_flat_e2big;
	uint_t	mobjs_phent_align32;
	uint_t	mobjs_phent_align64;
	uint_t	mobjs_lib_va_find_hit;
	uint_t	mobjs_lib_va_find_delay_delete;
	uint_t	mobjs_lib_va_find_delete;
	uint_t	mobjs_lib_va_add_delay_delete;
	uint_t	mobjs_lib_va_add_delete;
	uint_t	mobjs_lib_va_create_failure;
	uint_t	mobjs_min_align;
#if defined(__sparc)
	uint_t	mobjs_aout_uzero_fault;
	uint_t	mobjs_aout_64bit_try;
	uint_t	mobjs_aout_noexec;
	uint_t	mobjs_aout_e2big;
	uint_t	mobjs_aout_lib;
	uint_t	mobjs_aout_fixed;
	uint_t	mobjs_aout_zfoddiff;
	uint_t	mobjs_aout_map_bss;
	uint_t	mobjs_aout_bss_fail;
	uint_t	mobjs_aout_nlist;
	uint_t	mobjs_aout_addr_in_use;
#endif
} mobj_stats;

#define	MOBJ_STAT_ADD(stat)		((mobj_stats.mobjs_##stat)++)
#else
#define	MOBJ_STAT_ADD(stat)
#endif

/*
 * Check if addr is at or above the address space reserved for the stack.
 * The stack is at the top of the address space for all sparc processes
 * and 64 bit x86 processes.  For 32 bit x86, the stack is not at the top
 * of the address space and thus this check wil always return false for
 * 32 bit x86 processes.
 */
#if defined(__sparc)
#define	OVERLAPS_STACK(addr, p)						\
	(addr >= (p->p_usrstack - ((p->p_stk_ctl + PAGEOFFSET) & PAGEMASK)))
#elif defined(__amd64)
#define	OVERLAPS_STACK(addr, p)						\
	((p->p_model == DATAMODEL_LP64) &&				\
	(addr >= (p->p_usrstack - ((p->p_stk_ctl + PAGEOFFSET) & PAGEMASK))))
#elif defined(__i386)
#define	OVERLAPS_STACK(addr, p)	0
#endif

/* lv_flags values - bitmap */
#define	LV_ELF32	0x1		/* 32 bit ELF file */
#define	LV_ELF64	0x2		/* 64 bit ELF file */
#define	LV_DEL		0x4		/* delete when lv_refcnt hits zero */

/*
 * Note: lv_num_segs will denote how many segments this file has and will
 * only be set after the lv_mps array has been filled out.
 * lv_mps can only be valid if lv_num_segs is non-zero.
 */
struct lib_va {
	struct lib_va		*lv_next;
	caddr_t			lv_base_va;	/* start va for library */
	ssize_t			lv_len;		/* total va span of library */
	size_t			lv_align;	/* minimum alignment */
	uint64_t		lv_nodeid;	/* filesystem node id */
	uint64_t		lv_fsid;	/* filesystem id */
	timestruc_t		lv_ctime;	/* last time file was changed */
	timestruc_t		lv_mtime;	/* or modified */
	mmapobj_result_t	lv_mps[LIBVA_CACHED_SEGS]; /* cached pheaders */
	int			lv_num_segs;	/* # segs for this file */
	int			lv_flags;
	uint_t			lv_refcnt;	/* number of holds on struct */
};

#define	LIB_VA_SIZE	1024
#define	LIB_VA_MASK	(LIB_VA_SIZE - 1)
#define	LIB_VA_MUTEX_SHIFT	3

#if (LIB_VA_SIZE & (LIB_VA_SIZE - 1))
#error	"LIB_VA_SIZE is not a power of 2"
#endif

static struct lib_va *lib_va_hash[LIB_VA_SIZE];
static kmutex_t lib_va_hash_mutex[LIB_VA_SIZE >> LIB_VA_MUTEX_SHIFT];

#define	LIB_VA_HASH_MUTEX(index)					\
	(&lib_va_hash_mutex[index >> LIB_VA_MUTEX_SHIFT])

#define	LIB_VA_HASH(nodeid)						\
	(((nodeid) ^ ((nodeid) << 7) ^ ((nodeid) << 13)) & LIB_VA_MASK)

#define	LIB_VA_MATCH_ID(arg1, arg2)					\
	((arg1)->lv_nodeid == (arg2)->va_nodeid &&			\
	(arg1)->lv_fsid == (arg2)->va_fsid)

#define	LIB_VA_MATCH_TIME(arg1, arg2)					\
	((arg1)->lv_ctime.tv_sec == (arg2)->va_ctime.tv_sec &&		\
	(arg1)->lv_mtime.tv_sec == (arg2)->va_mtime.tv_sec &&		\
	(arg1)->lv_ctime.tv_nsec == (arg2)->va_ctime.tv_nsec &&		\
	(arg1)->lv_mtime.tv_nsec == (arg2)->va_mtime.tv_nsec)

#define	LIB_VA_MATCH(arg1, arg2)					\
	(LIB_VA_MATCH_ID(arg1, arg2) && LIB_VA_MATCH_TIME(arg1, arg2))

/*
 * lib_va will be used for optimized allocation of address ranges for
 * libraries, such that subsequent mappings of the same library will attempt
 * to use the same VA as previous mappings of that library.
 * In order to map libraries at the same VA in many processes, we need to carve
 * out our own address space for them which is unique across many processes.
 * We use different arenas for 32 bit and 64 bit libraries.
 *
 * Since the 32 bit address space is relatively small, we limit the number of
 * libraries which try to use consistent virtual addresses to lib_threshold.
 * For 64 bit libraries there is no such limit since the address space is large.
 */
static vmem_t *lib_va_32_arena;
static vmem_t *lib_va_64_arena;
uint_t lib_threshold = 20;	/* modifiable via /etc/system */

static kmutex_t lib_va_init_mutex;	/* no need to initialize */

/*
 * Number of 32 bit and 64 bit libraries in lib_va hash.
 */
static uint_t libs_mapped_32 = 0;
static uint_t libs_mapped_64 = 0;

/*
 * Free up the resources associated with lvp as well as lvp itself.
 * We also decrement the number of libraries mapped via a lib_va
 * cached virtual address.
 */
void
lib_va_free(struct lib_va *lvp)
{
	int is_64bit = lvp->lv_flags & LV_ELF64;
	ASSERT(lvp->lv_refcnt == 0);

	if (lvp->lv_base_va != NULL) {
		vmem_xfree(is_64bit ? lib_va_64_arena : lib_va_32_arena,
		    lvp->lv_base_va, lvp->lv_len);
		if (is_64bit) {
			atomic_dec_32(&libs_mapped_64);
		} else {
			atomic_dec_32(&libs_mapped_32);
		}
	}
	kmem_free(lvp, sizeof (struct lib_va));
}

/*
 * See if the file associated with the vap passed in is in the lib_va hash.
 * If it is and the file has not been modified since last use, then
 * return a pointer to that data.  Otherwise, return NULL if the file has
 * changed or the file was not found in the hash.
 */
static struct lib_va *
lib_va_find(vattr_t *vap)
{
	struct lib_va *lvp;
	struct lib_va *del = NULL;
	struct lib_va **tmp;
	uint_t index;
	index = LIB_VA_HASH(vap->va_nodeid);

	mutex_enter(LIB_VA_HASH_MUTEX(index));
	tmp = &lib_va_hash[index];
	while (*tmp != NULL) {
		lvp = *tmp;
		if (LIB_VA_MATCH_ID(lvp, vap)) {
			if (LIB_VA_MATCH_TIME(lvp, vap)) {
				ASSERT((lvp->lv_flags & LV_DEL) == 0);
				lvp->lv_refcnt++;
				MOBJ_STAT_ADD(lib_va_find_hit);
			} else {
				/*
				 * file was updated since last use.
				 * need to remove it from list.
				 */
				del = lvp;
				*tmp = del->lv_next;
				del->lv_next = NULL;
				/*
				 * If we can't delete it now, mark it for later
				 */
				if (del->lv_refcnt) {
					MOBJ_STAT_ADD(lib_va_find_delay_delete);
					del->lv_flags |= LV_DEL;
					del = NULL;
				}
				lvp = NULL;
			}
			mutex_exit(LIB_VA_HASH_MUTEX(index));
			if (del) {
				ASSERT(del->lv_refcnt == 0);
				MOBJ_STAT_ADD(lib_va_find_delete);
				lib_va_free(del);
			}
			return (lvp);
		}
		tmp = &lvp->lv_next;
	}
	mutex_exit(LIB_VA_HASH_MUTEX(index));
	return (NULL);
}

/*
 * Add a new entry to the lib_va hash.
 * Search the hash while holding the appropriate mutex to make sure that the
 * data is not already in the cache.  If we find data that is in the cache
 * already and has not been modified since last use, we return NULL.  If it
 * has been modified since last use, we will remove that entry from
 * the hash and it will be deleted once it's reference count reaches zero.
 * If there is no current entry in the hash we will add the new entry and
 * return it to the caller who is responsible for calling lib_va_release to
 * drop their reference count on it.
 *
 * lv_num_segs will be set to zero since the caller needs to add that
 * information to the data structure.
 */
static struct lib_va *
lib_va_add_hash(caddr_t base_va, ssize_t len, size_t align, vattr_t *vap)
{
	struct lib_va *lvp;
	uint_t index;
	model_t model;
	struct lib_va **tmp;
	struct lib_va *del = NULL;

	model = get_udatamodel();
	index = LIB_VA_HASH(vap->va_nodeid);

	lvp = kmem_alloc(sizeof (struct lib_va), KM_SLEEP);

	mutex_enter(LIB_VA_HASH_MUTEX(index));

	/*
	 * Make sure not adding same data a second time.
	 * The hash chains should be relatively short and adding
	 * is a relatively rare event, so it's worth the check.
	 */
	tmp = &lib_va_hash[index];
	while (*tmp != NULL) {
		if (LIB_VA_MATCH_ID(*tmp, vap)) {
			if (LIB_VA_MATCH_TIME(*tmp, vap)) {
				mutex_exit(LIB_VA_HASH_MUTEX(index));
				kmem_free(lvp, sizeof (struct lib_va));
				return (NULL);
			}

			/*
			 * We have the same nodeid and fsid but the file has
			 * been modified since we last saw it.
			 * Need to remove the old node and add this new
			 * one.
			 * Could probably use a callback mechanism to make
			 * this cleaner.
			 */
			ASSERT(del == NULL);
			del = *tmp;
			*tmp = del->lv_next;
			del->lv_next = NULL;

			/*
			 * Check to see if we can free it.  If lv_refcnt
			 * is greater than zero, than some other thread
			 * has a reference to the one we want to delete
			 * and we can not delete it.  All of this is done
			 * under the lib_va_hash_mutex lock so it is atomic.
			 */
			if (del->lv_refcnt) {
				MOBJ_STAT_ADD(lib_va_add_delay_delete);
				del->lv_flags |= LV_DEL;
				del = NULL;
			}
			/* tmp is already advanced */
			continue;
		}
		tmp = &((*tmp)->lv_next);
	}

	lvp->lv_base_va = base_va;
	lvp->lv_len = len;
	lvp->lv_align = align;
	lvp->lv_nodeid = vap->va_nodeid;
	lvp->lv_fsid = vap->va_fsid;
	lvp->lv_ctime.tv_sec = vap->va_ctime.tv_sec;
	lvp->lv_ctime.tv_nsec = vap->va_ctime.tv_nsec;
	lvp->lv_mtime.tv_sec = vap->va_mtime.tv_sec;
	lvp->lv_mtime.tv_nsec = vap->va_mtime.tv_nsec;
	lvp->lv_next = NULL;
	lvp->lv_refcnt = 1;

	/* Caller responsible for filling this and lv_mps out */
	lvp->lv_num_segs = 0;

	if (model == DATAMODEL_LP64) {
		lvp->lv_flags = LV_ELF64;
	} else {
		ASSERT(model == DATAMODEL_ILP32);
		lvp->lv_flags = LV_ELF32;
	}

	if (base_va != NULL) {
		if (model == DATAMODEL_LP64) {
			atomic_inc_32(&libs_mapped_64);
		} else {
			ASSERT(model == DATAMODEL_ILP32);
			atomic_inc_32(&libs_mapped_32);
		}
	}
	ASSERT(*tmp == NULL);
	*tmp = lvp;
	mutex_exit(LIB_VA_HASH_MUTEX(index));
	if (del) {
		ASSERT(del->lv_refcnt == 0);
		MOBJ_STAT_ADD(lib_va_add_delete);
		lib_va_free(del);
	}
	return (lvp);
}

/*
 * Release the hold on lvp which was acquired by lib_va_find or lib_va_add_hash.
 * In addition, if this is the last hold and lvp is marked for deletion,
 * free up it's reserved address space and free the structure.
 */
static void
lib_va_release(struct lib_va *lvp)
{
	uint_t index;
	int to_del = 0;

	ASSERT(lvp->lv_refcnt > 0);

	index = LIB_VA_HASH(lvp->lv_nodeid);
	mutex_enter(LIB_VA_HASH_MUTEX(index));
	if (--lvp->lv_refcnt == 0 && (lvp->lv_flags & LV_DEL)) {
		to_del = 1;
	}
	mutex_exit(LIB_VA_HASH_MUTEX(index));
	if (to_del) {
		ASSERT(lvp->lv_next == 0);
		lib_va_free(lvp);
	}
}

/*
 * Dummy function for mapping through /dev/null
 * Normally I would have used mmmmap in common/io/mem.c
 * but that is a static function, and for /dev/null, it
 * just returns -1.
 */
/* ARGSUSED */
static int
mmapobj_dummy(dev_t dev, off_t off, int prot)
{
	return (-1);
}

/*
 * Called when an error occurred which requires mmapobj to return failure.
 * All mapped objects will be unmapped and /dev/null mappings will be
 * reclaimed if necessary.
 * num_mapped is the number of elements of mrp which have been mapped, and
 * num_segs is the total number of elements in mrp.
 * For e_type ET_EXEC, we need to unmap all of the elements in mrp since
 * we had already made reservations for them.
 * If num_mapped equals num_segs, then we know that we had fully mapped
 * the file and only need to clean up the segments described.
 * If they are not equal, then for ET_DYN we will unmap the range from the
 * end of the last mapped segment to the end of the last segment in mrp
 * since we would have made a reservation for that memory earlier.
 * If e_type is passed in as zero, num_mapped must equal num_segs.
 */
void
mmapobj_unmap(mmapobj_result_t *mrp, int num_mapped, int num_segs,
    ushort_t e_type)
{
	int i;
	struct as *as = curproc->p_as;
	caddr_t addr;
	size_t size;

	if (e_type == ET_EXEC) {
		num_mapped = num_segs;
	}
#ifdef DEBUG
	if (e_type == 0) {
		ASSERT(num_mapped == num_segs);
	}
#endif

	MOBJ_STAT_ADD(unmap_called);
	for (i = 0; i < num_mapped; i++) {

		/*
		 * If we are going to have to create a mapping we need to
		 * make sure that no one else will use the address we
		 * need to remap between the time it is unmapped and
		 * mapped below.
		 */
		if (mrp[i].mr_flags & MR_RESV) {
			as_rangelock(as);
		}
		/* Always need to unmap what we mapped */
		(void) as_unmap(as, mrp[i].mr_addr, mrp[i].mr_msize);

		/* Need to reclaim /dev/null reservation from earlier */
		if (mrp[i].mr_flags & MR_RESV) {
			struct segdev_crargs dev_a;

			ASSERT(e_type != ET_DYN);
			/*
			 * Use seg_dev segment driver for /dev/null mapping.
			 */
			dev_a.mapfunc = mmapobj_dummy;
			dev_a.dev = makedevice(mm_major, M_NULL);
			dev_a.offset = 0;
			dev_a.type = 0;		/* neither PRIVATE nor SHARED */
			dev_a.prot = dev_a.maxprot = (uchar_t)PROT_NONE;
			dev_a.hat_attr = 0;
			dev_a.hat_flags = 0;

			(void) as_map(as, mrp[i].mr_addr, mrp[i].mr_msize,
			    segdev_create, &dev_a);
			MOBJ_STAT_ADD(remap_devnull);
			as_rangeunlock(as);
		}
	}

	if (num_mapped != num_segs) {
		ASSERT(e_type == ET_DYN);
		/* Need to unmap any reservation made after last mapped seg */
		if (num_mapped == 0) {
			addr = mrp[0].mr_addr;
		} else {
			addr = mrp[num_mapped - 1].mr_addr +
			    mrp[num_mapped - 1].mr_msize;
		}
		size = (size_t)mrp[num_segs - 1].mr_addr +
		    mrp[num_segs - 1].mr_msize - (size_t)addr;
		(void) as_unmap(as, addr, size);

		/*
		 * Now we need to unmap the holes between mapped segs.
		 * Note that we have not mapped all of the segments and thus
		 * the holes between segments would not have been unmapped
		 * yet.  If num_mapped == num_segs, then all of the holes
		 * between segments would have already been unmapped.
		 */

		for (i = 1; i < num_mapped; i++) {
			addr = mrp[i - 1].mr_addr + mrp[i - 1].mr_msize;
			size = mrp[i].mr_addr - addr;
			(void) as_unmap(as, addr, size);
		}
	}
}

/*
 * We need to add the start address into mrp so that the unmap function
 * has absolute addresses to use.
 */
static void
mmapobj_unmap_exec(mmapobj_result_t *mrp, int num_mapped, caddr_t start_addr)
{
	int i;

	for (i = 0; i < num_mapped; i++) {
		mrp[i].mr_addr += (size_t)start_addr;
	}
	mmapobj_unmap(mrp, num_mapped, num_mapped, ET_EXEC);
}

static caddr_t
mmapobj_lookup_start_addr(struct lib_va *lvp)
{
	proc_t *p = curproc;
	struct as *as = p->p_as;
	struct segvn_crargs crargs = SEGVN_ZFOD_ARGS(PROT_USER, PROT_ALL);
	int error;
	uint_t ma_flags = _MAP_LOW32;
	caddr_t base = NULL;
	size_t len;
	size_t align;

	ASSERT(lvp != NULL);
	MOBJ_STAT_ADD(lookup_start);

	as_rangelock(as);

	base = lvp->lv_base_va;
	len = lvp->lv_len;

	/*
	 * If we don't have an expected base address, or the one that we want
	 * to use is not available or acceptable, go get an acceptable
	 * address range.
	 */
	if (base == NULL || as_gap(as, len, &base, &len, 0, NULL) ||
	    valid_usr_range(base, len, PROT_ALL, as, as->a_userlimit) !=
	    RANGE_OKAY || OVERLAPS_STACK(base + len, p)) {
		if (lvp->lv_flags & LV_ELF64) {
			ma_flags = 0;
		}

		align = lvp->lv_align;
		if (align > 1) {
			ma_flags |= MAP_ALIGN;
		}

		base = (caddr_t)align;
		map_addr(&base, len, 0, 1, ma_flags);
	}

	/*
	 * Need to reserve the address space we're going to use.
	 * Don't reserve swap space since we'll be mapping over this.
	 */
	if (base != NULL) {
		crargs.flags |= MAP_NORESERVE;
		error = as_map(as, base, len, segvn_create, &crargs);
		if (error) {
			base = NULL;
		}
	}

	as_rangeunlock(as);
	return (base);
}

/*
 * Get the starting address for a given file to be mapped and return it
 * to the caller.  If we're using lib_va and we need to allocate an address,
 * we will attempt to allocate it from the global reserved pool such that the
 * same address can be used in the future for this file.  If we can't use the
 * reserved address then we just get one that will fit in our address space.
 *
 * Returns the starting virtual address for the range to be mapped or NULL
 * if an error is encountered. If we successfully insert the requested info
 * into the lib_va hash, then *lvpp will be set to point to this lib_va
 * structure.  The structure will have a hold on it and thus lib_va_release
 * needs to be called on it by the caller.  This function will not fill out
 * lv_mps or lv_num_segs since it does not have enough information to do so.
 * The caller is responsible for doing this making sure that any modifications
 * to lv_mps are visible before setting lv_num_segs.
 */
static caddr_t
mmapobj_alloc_start_addr(struct lib_va **lvpp, size_t len, int use_lib_va,
    size_t align, vattr_t *vap)
{
	proc_t *p = curproc;
	struct as *as = p->p_as;
	struct segvn_crargs crargs = SEGVN_ZFOD_ARGS(PROT_USER, PROT_ALL);
	int error;
	model_t model;
	uint_t ma_flags = _MAP_LOW32;
	caddr_t base = NULL;
	vmem_t *model_vmem;
	size_t lib_va_start;
	size_t lib_va_end;
	size_t lib_va_len;

	ASSERT(lvpp != NULL);

	MOBJ_STAT_ADD(alloc_start);
	model = get_udatamodel();

	if (model == DATAMODEL_LP64) {
		ma_flags = 0;
		model_vmem = lib_va_64_arena;
	} else {
		ASSERT(model == DATAMODEL_ILP32);
		model_vmem = lib_va_32_arena;
	}

	if (align > 1) {
		ma_flags |= MAP_ALIGN;
	}
	if (use_lib_va) {
		/*
		 * The first time through, we need to setup the lib_va arenas.
		 * We call map_addr to find a suitable range of memory to map
		 * the given library, and we will set the highest address
		 * in our vmem arena to the end of this adddress range.
		 * We allow up to half of the address space to be used
		 * for lib_va addresses but we do not prevent any allocations
		 * in this range from other allocation paths.
		 */
		if (lib_va_64_arena == NULL && model == DATAMODEL_LP64) {
			mutex_enter(&lib_va_init_mutex);
			if (lib_va_64_arena == NULL) {
				base = (caddr_t)align;
				as_rangelock(as);
				map_addr(&base, len, 0, 1, ma_flags);
				as_rangeunlock(as);
				if (base == NULL) {
					mutex_exit(&lib_va_init_mutex);
					MOBJ_STAT_ADD(lib_va_create_failure);
					goto nolibva;
				}
				lib_va_end = (size_t)base + len;
				lib_va_len = lib_va_end >> 1;
				lib_va_len = P2ROUNDUP(lib_va_len, PAGESIZE);
				lib_va_start = lib_va_end - lib_va_len;

				/*
				 * Need to make sure we avoid the address hole.
				 * We know lib_va_end is valid but we need to
				 * make sure lib_va_start is as well.
				 */
				if ((lib_va_end > (size_t)hole_end) &&
				    (lib_va_start < (size_t)hole_end)) {
					lib_va_start = P2ROUNDUP(
					    (size_t)hole_end, PAGESIZE);
					lib_va_len = lib_va_end - lib_va_start;
				}
				lib_va_64_arena = vmem_create("lib_va_64",
				    (void *)lib_va_start, lib_va_len, PAGESIZE,
				    NULL, NULL, NULL, 0,
				    VM_NOSLEEP | VMC_IDENTIFIER);
				if (lib_va_64_arena == NULL) {
					mutex_exit(&lib_va_init_mutex);
					goto nolibva;
				}
			}
			model_vmem = lib_va_64_arena;
			mutex_exit(&lib_va_init_mutex);
		} else if (lib_va_32_arena == NULL &&
		    model == DATAMODEL_ILP32) {
			mutex_enter(&lib_va_init_mutex);
			if (lib_va_32_arena == NULL) {
				base = (caddr_t)align;
				as_rangelock(as);
				map_addr(&base, len, 0, 1, ma_flags);
				as_rangeunlock(as);
				if (base == NULL) {
					mutex_exit(&lib_va_init_mutex);
					MOBJ_STAT_ADD(lib_va_create_failure);
					goto nolibva;
				}
				lib_va_end = (size_t)base + len;
				lib_va_len = lib_va_end >> 1;
				lib_va_len = P2ROUNDUP(lib_va_len, PAGESIZE);
				lib_va_start = lib_va_end - lib_va_len;
				lib_va_32_arena = vmem_create("lib_va_32",
				    (void *)lib_va_start, lib_va_len, PAGESIZE,
				    NULL, NULL, NULL, 0,
				    VM_NOSLEEP | VMC_IDENTIFIER);
				if (lib_va_32_arena == NULL) {
					mutex_exit(&lib_va_init_mutex);
					goto nolibva;
				}
			}
			model_vmem = lib_va_32_arena;
			mutex_exit(&lib_va_init_mutex);
		}

		if (model == DATAMODEL_LP64 || libs_mapped_32 < lib_threshold) {
			base = vmem_xalloc(model_vmem, len, align, 0, 0, NULL,
			    NULL, VM_NOSLEEP | VM_ENDALLOC);
			MOBJ_STAT_ADD(alloc_vmem);
		}

		/*
		 * Even if the address fails to fit in our address space,
		 * or we can't use a reserved address,
		 * we should still save it off in lib_va_hash.
		 */
		*lvpp = lib_va_add_hash(base, len, align, vap);

		/*
		 * Check for collision on insertion and free up our VA space.
		 * This is expected to be rare, so we'll just reset base to
		 * NULL instead of looking it up in the lib_va hash.
		 */
		if (*lvpp == NULL) {
			if (base != NULL) {
				vmem_xfree(model_vmem, base, len);
				base = NULL;
				MOBJ_STAT_ADD(add_collision);
			}
		}
	}

nolibva:
	as_rangelock(as);

	/*
	 * If we don't have an expected base address, or the one that we want
	 * to use is not available or acceptable, go get an acceptable
	 * address range.
	 */
	if (base == NULL || as_gap(as, len, &base, &len, 0, NULL) ||
	    valid_usr_range(base, len, PROT_ALL, as, as->a_userlimit) !=
	    RANGE_OKAY || OVERLAPS_STACK(base + len, p)) {
		MOBJ_STAT_ADD(get_addr);
		base = (caddr_t)align;
		map_addr(&base, len, 0, 1, ma_flags);
	}

	/*
	 * Need to reserve the address space we're going to use.
	 * Don't reserve swap space since we'll be mapping over this.
	 */
	if (base != NULL) {
		/* Don't reserve swap space since we'll be mapping over this */
		crargs.flags |= MAP_NORESERVE;
		error = as_map(as, base, len, segvn_create, &crargs);
		if (error) {
			base = NULL;
		}
	}

	as_rangeunlock(as);
	return (base);
}

/*
 * Map the file associated with vp into the address space as a single
 * read only private mapping.
 * Returns 0 for success, and non-zero for failure to map the file.
 */
static int
mmapobj_map_flat(vnode_t *vp, mmapobj_result_t *mrp, size_t padding,
    cred_t *fcred)
{
	int error = 0;
	struct as *as = curproc->p_as;
	caddr_t addr = NULL;
	caddr_t start_addr;
	size_t len;
	size_t pad_len;
	int prot = PROT_USER | PROT_READ;
	uint_t ma_flags = _MAP_LOW32;
	vattr_t vattr;
	struct segvn_crargs crargs = SEGVN_ZFOD_ARGS(PROT_USER, PROT_ALL);

	if (get_udatamodel() == DATAMODEL_LP64) {
		ma_flags = 0;
	}

	vattr.va_mask = AT_SIZE;
	error = VOP_GETATTR(vp, &vattr, 0, fcred, NULL);
	if (error) {
		return (error);
	}

	len = vattr.va_size;

	ma_flags |= MAP_PRIVATE;
	if (padding == 0) {
		MOBJ_STAT_ADD(map_flat_no_padding);
		error = VOP_MAP(vp, 0, as, &addr, len, prot, PROT_ALL,
		    ma_flags, fcred, NULL);
		if (error == 0) {
			mrp[0].mr_addr = addr;
			mrp[0].mr_msize = len;
			mrp[0].mr_fsize = len;
			mrp[0].mr_offset = 0;
			mrp[0].mr_prot = prot;
			mrp[0].mr_flags = 0;
		}
		return (error);
	}

	/* padding was requested so there's more work to be done */
	MOBJ_STAT_ADD(map_flat_padding);

	/* No need to reserve swap space now since it will be reserved later */
	crargs.flags |= MAP_NORESERVE;

	/* Need to setup padding which can only be in PAGESIZE increments. */
	ASSERT((padding & PAGEOFFSET) == 0);
	pad_len = len + (2 * padding);

	as_rangelock(as);
	map_addr(&addr, pad_len, 0, 1, ma_flags);
	error = as_map(as, addr, pad_len, segvn_create, &crargs);
	as_rangeunlock(as);
	if (error) {
		return (error);
	}
	start_addr = addr;
	addr += padding;
	ma_flags |= MAP_FIXED;
	error = VOP_MAP(vp, 0, as, &addr, len, prot, PROT_ALL, ma_flags,
	    fcred, NULL);
	if (error == 0) {
		mrp[0].mr_addr = start_addr;
		mrp[0].mr_msize = padding;
		mrp[0].mr_fsize = 0;
		mrp[0].mr_offset = 0;
		mrp[0].mr_prot = 0;
		mrp[0].mr_flags = MR_PADDING;

		mrp[1].mr_addr = addr;
		mrp[1].mr_msize = len;
		mrp[1].mr_fsize = len;
		mrp[1].mr_offset = 0;
		mrp[1].mr_prot = prot;
		mrp[1].mr_flags = 0;

		mrp[2].mr_addr = addr + P2ROUNDUP(len, PAGESIZE);
		mrp[2].mr_msize = padding;
		mrp[2].mr_fsize = 0;
		mrp[2].mr_offset = 0;
		mrp[2].mr_prot = 0;
		mrp[2].mr_flags = MR_PADDING;
	} else {
		/* Need to cleanup the as_map from earlier */
		(void) as_unmap(as, start_addr, pad_len);
	}
	return (error);
}

/*
 * Map a PT_LOAD or PT_SUNWBSS section of an executable file into the user's
 * address space.
 * vp - vnode to be mapped in
 * addr - start address
 * len - length of vp to be mapped
 * zfodlen - length of zero filled memory after len above
 * offset - offset into file where mapping should start
 * prot - protections for this mapping
 * fcred - credentials for the file associated with vp at open time.
 */
static int
mmapobj_map_ptload(struct vnode *vp, caddr_t addr, size_t len, size_t zfodlen,
    off_t offset, int prot, cred_t *fcred)
{
	int error = 0;
	caddr_t zfodbase, oldaddr;
	size_t oldlen;
	size_t end;
	size_t zfoddiff;
	label_t ljb;
	struct as *as = curproc->p_as;
	model_t model;
	int full_page;

	/*
	 * See if addr and offset are aligned such that we can map in
	 * full pages instead of partial pages.
	 */
	full_page = (((uintptr_t)addr & PAGEOFFSET) ==
	    ((uintptr_t)offset & PAGEOFFSET));

	model = get_udatamodel();

	oldaddr = addr;
	addr = (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);
	if (len) {
		spgcnt_t availm, npages;
		int preread;
		uint_t mflag = MAP_PRIVATE | MAP_FIXED;

		if (model == DATAMODEL_ILP32) {
			mflag |= _MAP_LOW32;
		}
		/* We may need to map in extra bytes */
		oldlen = len;
		len += ((size_t)oldaddr & PAGEOFFSET);

		if (full_page) {
			offset = (off_t)((uintptr_t)offset & PAGEMASK);
			if ((prot & (PROT_WRITE | PROT_EXEC)) == PROT_EXEC) {
				mflag |= MAP_TEXT;
				MOBJ_STAT_ADD(map_ptload_text);
			} else {
				mflag |= MAP_INITDATA;
				MOBJ_STAT_ADD(map_ptload_initdata);
			}

			/*
			 * maxprot is passed as PROT_ALL so that mdb can
			 * write to this segment.
			 */
			if (error = VOP_MAP(vp, (offset_t)offset, as, &addr,
			    len, prot, PROT_ALL, mflag, fcred, NULL)) {
				return (error);
			}

			/*
			 * If the segment can fit and is relatively small, then
			 * we prefault the entire segment in.  This is based
			 * on the model that says the best working set of a
			 * small program is all of its pages.
			 * We only do this if freemem will not drop below
			 * lotsfree since we don't want to induce paging.
			 */
			npages = (spgcnt_t)btopr(len);
			availm = freemem - lotsfree;
			preread = (npages < availm && len < PGTHRESH) ? 1 : 0;

			/*
			 * If we aren't prefaulting the segment,
			 * increment "deficit", if necessary to ensure
			 * that pages will become available when this
			 * process starts executing.
			 */
			if (preread == 0 && npages > availm &&
			    deficit < lotsfree) {
				deficit += MIN((pgcnt_t)(npages - availm),
				    lotsfree - deficit);
			}

			if (preread) {
				(void) as_faulta(as, addr, len);
				MOBJ_STAT_ADD(map_ptload_preread);
			}
		} else {
			/*
			 * addr and offset were not aligned such that we could
			 * use VOP_MAP, thus we need to as_map the memory we
			 * need and then read the data in from disk.
			 * This code path is a corner case which should never
			 * be taken, but hand crafted binaries could trigger
			 * this logic and it needs to work correctly.
			 */
			MOBJ_STAT_ADD(map_ptload_unaligned_text);
			as_rangelock(as);
			(void) as_unmap(as, addr, len);

			/*
			 * We use zfod_argsp because we need to be able to
			 * write to the mapping and then we'll change the
			 * protections later if they are incorrect.
			 */
			error = as_map(as, addr, len, segvn_create, zfod_argsp);
			as_rangeunlock(as);
			if (error) {
				MOBJ_STAT_ADD(map_ptload_unaligned_map_fail);
				return (error);
			}

			/* Now read in the data from disk */
			error = vn_rdwr(UIO_READ, vp, oldaddr, oldlen, offset,
			    UIO_USERSPACE, 0, (rlim64_t)0, fcred, NULL);
			if (error) {
				MOBJ_STAT_ADD(map_ptload_unaligned_read_fail);
				return (error);
			}

			/*
			 * Now set protections.
			 */
			if (prot != PROT_ZFOD) {
				(void) as_setprot(as, addr, len, prot);
			}
		}
	}

	if (zfodlen) {
		end = (size_t)addr + len;
		zfodbase = (caddr_t)P2ROUNDUP(end, PAGESIZE);
		zfoddiff = (uintptr_t)zfodbase - end;
		if (zfoddiff) {
			/*
			 * Before we go to zero the remaining space on the last
			 * page, make sure we have write permission.
			 *
			 * We need to be careful how we zero-fill the last page
			 * if the protection does not include PROT_WRITE. Using
			 * as_setprot() can cause the VM segment code to call
			 * segvn_vpage(), which must allocate a page struct for
			 * each page in the segment. If we have a very large
			 * segment, this may fail, so we check for that, even
			 * though we ignore other return values from as_setprot.
			 */
			MOBJ_STAT_ADD(zfoddiff);
			if ((prot & PROT_WRITE) == 0) {
				if (as_setprot(as, (caddr_t)end, zfoddiff,
				    prot | PROT_WRITE) == ENOMEM)
					return (ENOMEM);
				MOBJ_STAT_ADD(zfoddiff_nowrite);
			}
			if (on_fault(&ljb)) {
				no_fault();
				if ((prot & PROT_WRITE) == 0) {
					(void) as_setprot(as, (caddr_t)end,
					    zfoddiff, prot);
				}
				return (EFAULT);
			}
			uzero((void *)end, zfoddiff);
			no_fault();

			/*
			 * Remove write protection to return to original state
			 */
			if ((prot & PROT_WRITE) == 0) {
				(void) as_setprot(as, (caddr_t)end,
				    zfoddiff, prot);
			}
		}
		if (zfodlen > zfoddiff) {
			struct segvn_crargs crargs =
			    SEGVN_ZFOD_ARGS(prot, PROT_ALL);

			MOBJ_STAT_ADD(zfodextra);
			zfodlen -= zfoddiff;
			crargs.szc = AS_MAP_NO_LPOOB;


			as_rangelock(as);
			(void) as_unmap(as, (caddr_t)zfodbase, zfodlen);
			error = as_map(as, (caddr_t)zfodbase,
			    zfodlen, segvn_create, &crargs);
			as_rangeunlock(as);
			if (error) {
				return (error);
			}
		}
	}
	return (0);
}

/*
 * Map the ELF file represented by vp into the users address space.  The
 * first mapping will start at start_addr and there will be num_elements
 * mappings.  The mappings are described by the data in mrp which may be
 * modified upon returning from this function.
 * Returns 0 for success or errno for failure.
 */
static int
mmapobj_map_elf(struct vnode *vp, caddr_t start_addr, mmapobj_result_t *mrp,
    int num_elements, cred_t *fcred, ushort_t e_type)
{
	int i;
	int ret;
	caddr_t lo;
	caddr_t hi;
	struct as *as = curproc->p_as;

	for (i = 0; i < num_elements; i++) {
		caddr_t addr;
		size_t p_memsz;
		size_t p_filesz;
		size_t zfodlen;
		offset_t p_offset;
		size_t dif;
		int prot;

		/* Always need to adjust mr_addr */
		addr = start_addr + (size_t)(mrp[i].mr_addr);
		mrp[i].mr_addr =
		    (caddr_t)((uintptr_t)addr & (uintptr_t)PAGEMASK);

		/* Padding has already been mapped */
		if (MR_GET_TYPE(mrp[i].mr_flags) == MR_PADDING) {
			continue;
		}
		p_memsz = mrp[i].mr_msize;
		p_filesz = mrp[i].mr_fsize;
		zfodlen = p_memsz - p_filesz;
		p_offset = mrp[i].mr_offset;
		dif = (uintptr_t)(addr) & PAGEOFFSET;
		prot = mrp[i].mr_prot | PROT_USER;
		ret = mmapobj_map_ptload(vp, addr, p_filesz, zfodlen,
		    p_offset, prot, fcred);
		if (ret != 0) {
			MOBJ_STAT_ADD(ptload_failed);
			mmapobj_unmap(mrp, i, num_elements, e_type);
			return (ret);
		}

		/* Need to cleanup mrp to reflect the actual values used */
		mrp[i].mr_msize += dif;
		mrp[i].mr_offset = (size_t)addr & PAGEOFFSET;
	}

	/* Also need to unmap any holes created above */
	if (num_elements == 1) {
		MOBJ_STAT_ADD(map_elf_no_holes);
		return (0);
	}
	if (e_type == ET_EXEC) {
		return (0);
	}

	as_rangelock(as);
	lo = start_addr;
	hi = mrp[0].mr_addr;

	/* Remove holes made by the rest of the segments */
	for (i = 0; i < num_elements - 1; i++) {
		lo = (caddr_t)P2ROUNDUP((size_t)(mrp[i].mr_addr) +
		    mrp[i].mr_msize, PAGESIZE);
		hi = mrp[i + 1].mr_addr;
		if (lo < hi) {
			/*
			 * If as_unmap fails we just use up a bit of extra
			 * space
			 */
			(void) as_unmap(as, (caddr_t)lo,
			    (size_t)hi - (size_t)lo);
			MOBJ_STAT_ADD(unmap_hole);
		}
	}
	as_rangeunlock(as);

	return (0);
}

/* Ugly hack to get STRUCT_* macros to work below */
struct myphdr {
	Phdr		x;	/* native version */
};

struct myphdr32 {
	Elf32_Phdr	x;
};

/*
 * Calculate and return the number of loadable segments in the ELF Phdr
 * represented by phdrbase as well as the len of the total mapping and
 * the max alignment that is needed for a given segment.  On success,
 * 0 is returned, and *len, *loadable and *align have been filled out.
 * On failure, errno will be returned, which in this case is ENOTSUP
 * if we were passed an ELF file with overlapping segments.
 */
static int
calc_loadable(Ehdr *ehdrp, caddr_t phdrbase, int nphdrs, size_t *len,
    int *loadable, size_t *align)
{
	int i;
	int hsize;
	model_t model;
	ushort_t e_type = ehdrp->e_type;	/* same offset 32 and 64 bit */
	uint_t p_type;
	offset_t p_offset;
	size_t p_memsz;
	size_t p_align;
	caddr_t vaddr;
	int num_segs = 0;
	caddr_t start_addr = NULL;
	caddr_t p_end = NULL;
	size_t max_align = 0;
	size_t min_align = PAGESIZE;	/* needed for vmem_xalloc */
	STRUCT_HANDLE(myphdr, mph);
#if defined(__sparc)
	extern int vac_size;

	/*
	 * Want to prevent aliasing by making the start address at least be
	 * aligned to vac_size.
	 */
	min_align = MAX(PAGESIZE, vac_size);
#endif

	model = get_udatamodel();
	STRUCT_SET_HANDLE(mph, model, (struct myphdr *)phdrbase);

	/* hsize alignment should have been checked before calling this func */
	if (model == DATAMODEL_LP64) {
		hsize = ehdrp->e_phentsize;
		if (hsize & 7) {
			return (ENOTSUP);
		}
	} else {
		ASSERT(model == DATAMODEL_ILP32);
		hsize = ((Elf32_Ehdr *)ehdrp)->e_phentsize;
		if (hsize & 3) {
			return (ENOTSUP);
		}
	}

	/*
	 * Determine the span of all loadable segments and calculate the
	 * number of loadable segments.
	 */
	for (i = 0; i < nphdrs; i++) {
		p_type = STRUCT_FGET(mph, x.p_type);
		if (p_type == PT_LOAD || p_type == PT_SUNWBSS) {
			vaddr = (caddr_t)(uintptr_t)STRUCT_FGET(mph, x.p_vaddr);
			p_memsz = STRUCT_FGET(mph, x.p_memsz);

			/*
			 * Skip this header if it requests no memory to be
			 * mapped.
			 */
			if (p_memsz == 0) {
				STRUCT_SET_HANDLE(mph, model,
				    (struct myphdr *)((size_t)STRUCT_BUF(mph) +
				    hsize));
				MOBJ_STAT_ADD(nomem_header);
				continue;
			}
			if (num_segs++ == 0) {
				/*
				 * The p_vaddr of the first PT_LOAD segment
				 * must either be NULL or within the first
				 * page in order to be interpreted.
				 * Otherwise, its an invalid file.
				 */
				if (e_type == ET_DYN &&
				    ((caddr_t)((uintptr_t)vaddr &
				    (uintptr_t)PAGEMASK) != NULL)) {
					MOBJ_STAT_ADD(inval_header);
					return (ENOTSUP);
				}
				start_addr = vaddr;
				/*
				 * For the first segment, we need to map from
				 * the beginning of the file, so we will
				 * adjust the size of the mapping to include
				 * this memory.
				 */
				p_offset = STRUCT_FGET(mph, x.p_offset);
			} else {
				p_offset = 0;
			}
			/*
			 * Check to make sure that this mapping wouldn't
			 * overlap a previous mapping.
			 */
			if (vaddr < p_end) {
				MOBJ_STAT_ADD(overlap_header);
				return (ENOTSUP);
			}

			p_end = vaddr + p_memsz + p_offset;
			p_end = (caddr_t)P2ROUNDUP((size_t)p_end, PAGESIZE);

			p_align = STRUCT_FGET(mph, x.p_align);
			if (p_align > 1 && p_align > max_align) {
				max_align = p_align;
				if (max_align < min_align) {
					max_align = min_align;
					MOBJ_STAT_ADD(min_align);
				}
			}
		}
		STRUCT_SET_HANDLE(mph, model,
		    (struct myphdr *)((size_t)STRUCT_BUF(mph) + hsize));
	}

	/*
	 * The alignment should be a power of 2, if it isn't we forgive it
	 * and round up.  On overflow, we'll set the alignment to max_align
	 * rounded down to the nearest power of 2.
	 */
	if (max_align > 0 && !ISP2(max_align)) {
		MOBJ_STAT_ADD(np2_align);
		*align = 2 * (1L << (highbit(max_align) - 1));
		if (*align < max_align ||
		    (*align > UINT_MAX && model == DATAMODEL_ILP32)) {
			MOBJ_STAT_ADD(np2_align_overflow);
			*align = 1L << (highbit(max_align) - 1);
		}
	} else {
		*align = max_align;
	}

	ASSERT(*align >= PAGESIZE || *align == 0);

	*loadable = num_segs;
	*len = p_end - start_addr;
	return (0);
}

/*
 * Check the address space to see if the virtual addresses to be used are
 * available.  If they are not, return errno for failure.  On success, 0
 * will be returned, and the virtual addresses for each mmapobj_result_t
 * will be reserved.  Note that a reservation could have earlier been made
 * for a given segment via a /dev/null mapping.  If that is the case, then
 * we can use that VA space for our mappings.
 * Note: this function will only be used for ET_EXEC binaries.
 */
int
check_exec_addrs(int loadable, mmapobj_result_t *mrp, caddr_t start_addr)
{
	int i;
	struct as *as = curproc->p_as;
	struct segvn_crargs crargs = SEGVN_ZFOD_ARGS(PROT_ZFOD, PROT_ALL);
	int ret;
	caddr_t myaddr;
	size_t mylen;
	struct seg *seg;

	/* No need to reserve swap space now since it will be reserved later */
	crargs.flags |= MAP_NORESERVE;
	as_rangelock(as);
	for (i = 0; i < loadable; i++) {

		myaddr = start_addr + (size_t)mrp[i].mr_addr;
		mylen = mrp[i].mr_msize;

		/* See if there is a hole in the as for this range */
		if (as_gap(as, mylen, &myaddr, &mylen, 0, NULL) == 0) {
			ASSERT(myaddr == start_addr + (size_t)mrp[i].mr_addr);
			ASSERT(mylen == mrp[i].mr_msize);

#ifdef DEBUG
			if (MR_GET_TYPE(mrp[i].mr_flags) == MR_PADDING) {
				MOBJ_STAT_ADD(exec_padding);
			}
#endif
			ret = as_map(as, myaddr, mylen, segvn_create, &crargs);
			if (ret) {
				as_rangeunlock(as);
				mmapobj_unmap_exec(mrp, i, start_addr);
				return (ret);
			}
		} else {
			/*
			 * There is a mapping that exists in the range
			 * so check to see if it was a "reservation"
			 * from /dev/null.  The mapping is from
			 * /dev/null if the mapping comes from
			 * segdev and the type is neither MAP_SHARED
			 * nor MAP_PRIVATE.
			 */
			AS_LOCK_ENTER(as, &as->a_lock, RW_READER);
			seg = as_findseg(as, myaddr, 0);
			MOBJ_STAT_ADD(exec_addr_mapped);
			if (seg && seg->s_ops == &segdev_ops &&
			    ((SEGOP_GETTYPE(seg, myaddr) &
			    (MAP_SHARED | MAP_PRIVATE)) == 0) &&
			    myaddr >= seg->s_base &&
			    myaddr + mylen <=
			    seg->s_base + seg->s_size) {
				MOBJ_STAT_ADD(exec_addr_devnull);
				AS_LOCK_EXIT(as, &as->a_lock);
				(void) as_unmap(as, myaddr, mylen);
				ret = as_map(as, myaddr, mylen, segvn_create,
				    &crargs);
				mrp[i].mr_flags |= MR_RESV;
				if (ret) {
					as_rangeunlock(as);
					/* Need to remap what we unmapped */
					mmapobj_unmap_exec(mrp, i + 1,
					    start_addr);
					return (ret);
				}
			} else {
				AS_LOCK_EXIT(as, &as->a_lock);
				as_rangeunlock(as);
				mmapobj_unmap_exec(mrp, i, start_addr);
				MOBJ_STAT_ADD(exec_addr_in_use);
				return (EADDRINUSE);
			}
		}
	}
	as_rangeunlock(as);
	return (0);
}

/*
 * Walk through the ELF program headers and extract all useful information
 * for PT_LOAD and PT_SUNWBSS segments into mrp.
 * Return 0 on success or error on failure.
 */
static int
process_phdr(Ehdr *ehdrp, caddr_t phdrbase, int nphdrs, mmapobj_result_t *mrp,
    vnode_t *vp, uint_t *num_mapped, size_t padding, cred_t *fcred)
{
	int i;
	caddr_t start_addr = NULL;
	caddr_t vaddr;
	size_t len = 0;
	size_t lib_len = 0;
	int ret;
	int prot;
	struct lib_va *lvp = NULL;
	vattr_t vattr;
	struct as *as = curproc->p_as;
	int error;
	int loadable = 0;
	int current = 0;
	int use_lib_va = 1;
	size_t align = 0;
	size_t add_pad = 0;
	int hdr_seen = 0;
	ushort_t e_type = ehdrp->e_type;	/* same offset 32 and 64 bit */
	uint_t p_type;
	offset_t p_offset;
	size_t p_memsz;
	size_t p_filesz;
	uint_t p_flags;
	int hsize;
	model_t model;
	STRUCT_HANDLE(myphdr, mph);

	model = get_udatamodel();
	STRUCT_SET_HANDLE(mph, model, (struct myphdr *)phdrbase);

	/*
	 * Need to make sure that hsize is aligned properly.
	 * For 32bit processes, 4 byte alignment is required.
	 * For 64bit processes, 8 byte alignment is required.
	 * If the alignment isn't correct, we need to return failure
	 * since it could cause an alignment error panic while walking
	 * the phdr array.
	 */
	if (model == DATAMODEL_LP64) {
		hsize = ehdrp->e_phentsize;
		if (hsize & 7) {
			MOBJ_STAT_ADD(phent_align64);
			return (ENOTSUP);
		}
	} else {
		ASSERT(model == DATAMODEL_ILP32);
		hsize = ((Elf32_Ehdr *)ehdrp)->e_phentsize;
		if (hsize & 3) {
			MOBJ_STAT_ADD(phent_align32);
			return (ENOTSUP);
		}
	}

	if (padding != 0) {
		use_lib_va = 0;
	}
	if (e_type == ET_DYN) {
		vattr.va_mask = AT_FSID | AT_NODEID | AT_CTIME | AT_MTIME;
		error = VOP_GETATTR(vp, &vattr, 0, fcred, NULL);
		if (error) {
			return (error);
		}
		/* Check to see if we already have a description for this lib */
		lvp = lib_va_find(&vattr);

		if (lvp != NULL) {
			MOBJ_STAT_ADD(lvp_found);
			if (use_lib_va) {
				start_addr = mmapobj_lookup_start_addr(lvp);
				if (start_addr == NULL) {
					lib_va_release(lvp);
					return (ENOMEM);
				}
			}

			/*
			 * loadable may be zero if the original allocator
			 * of lvp hasn't finished setting it up but the rest
			 * of the fields will be accurate.
			 */
			loadable = lvp->lv_num_segs;
			len = lvp->lv_len;
			align = lvp->lv_align;
		}
	}

	/*
	 * Determine the span of all loadable segments and calculate the
	 * number of loadable segments, the total len spanned by the mappings
	 * and the max alignment, if we didn't get them above.
	 */
	if (loadable == 0) {
		MOBJ_STAT_ADD(no_loadable_yet);
		ret = calc_loadable(ehdrp, phdrbase, nphdrs, &len,
		    &loadable, &align);
		if (ret != 0) {
			/*
			 * Since it'd be an invalid file, we shouldn't have
			 * cached it previously.
			 */
			ASSERT(lvp == NULL);
			return (ret);
		}
#ifdef DEBUG
		if (lvp) {
			ASSERT(len == lvp->lv_len);
			ASSERT(align == lvp->lv_align);
		}
#endif
	}

	/* Make sure there's something to map. */
	if (len == 0 || loadable == 0) {
		/*
		 * Since it'd be an invalid file, we shouldn't have
		 * cached it previously.
		 */
		ASSERT(lvp == NULL);
		MOBJ_STAT_ADD(nothing_to_map);
		return (ENOTSUP);
	}

	lib_len = len;
	if (padding != 0) {
		loadable += 2;
	}
	if (loadable > *num_mapped) {
		*num_mapped = loadable;
		/* cleanup previous reservation */
		if (start_addr) {
			(void) as_unmap(as, start_addr, lib_len);
		}
		MOBJ_STAT_ADD(e2big);
		if (lvp) {
			lib_va_release(lvp);
		}
		return (E2BIG);
	}

	/*
	 * We now know the size of the object to map and now we need to
	 * get the start address to map it at.  It's possible we already
	 * have it if we found all the info we need in the lib_va cache.
	 */
	if (e_type == ET_DYN && start_addr == NULL) {
		/*
		 * Need to make sure padding does not throw off
		 * required alignment.  We can only specify an
		 * alignment for the starting address to be mapped,
		 * so we round padding up to the alignment and map
		 * from there and then throw out the extra later.
		 */
		if (padding != 0) {
			if (align > 1) {
				add_pad = P2ROUNDUP(padding, align);
				len += add_pad;
				MOBJ_STAT_ADD(dyn_pad_align);
			} else {
				MOBJ_STAT_ADD(dyn_pad_noalign);
				len += padding;	/* at beginning */
			}
			len += padding;	/* at end of mapping */
		}
		/*
		 * At this point, if lvp is non-NULL, then above we
		 * already found it in the cache but did not get
		 * the start address since we were not going to use lib_va.
		 * Since we know that lib_va will not be used, it's safe
		 * to call mmapobj_alloc_start_addr and know that lvp
		 * will not be modified.
		 */
		ASSERT(lvp ? use_lib_va == 0 : 1);
		start_addr = mmapobj_alloc_start_addr(&lvp, len,
		    use_lib_va, align, &vattr);
		if (start_addr == NULL) {
			if (lvp) {
				lib_va_release(lvp);
			}
			MOBJ_STAT_ADD(alloc_start_fail);
			return (ENOMEM);
		}
		/*
		 * If we can't cache it, no need to hang on to it.
		 * Setting lv_num_segs to non-zero will make that
		 * field active and since there are too many segments
		 * to cache, all future users will not try to use lv_mps.
		 */
		if (lvp != NULL && loadable > LIBVA_CACHED_SEGS && use_lib_va) {
			lvp->lv_num_segs = loadable;
			lib_va_release(lvp);
			lvp = NULL;
			MOBJ_STAT_ADD(lvp_nocache);
		}
		/*
		 * Free the beginning of the mapping if the padding
		 * was not aligned correctly.
		 */
		if (padding != 0 && add_pad != padding) {
			(void) as_unmap(as, start_addr,
			    add_pad - padding);
			start_addr += (add_pad - padding);
			MOBJ_STAT_ADD(extra_padding);
		}
	}

	/*
	 * At this point, we have reserved the virtual address space
	 * for our mappings.  Now we need to start filling out the mrp
	 * array to describe all of the individual mappings we are going
	 * to return.
	 * For ET_EXEC there has been no memory reservation since we are
	 * using fixed addresses.  While filling in the mrp array below,
	 * we will have the first segment biased to start at addr 0
	 * and the rest will be biased by this same amount.  Thus if there
	 * is padding, the first padding will start at addr 0, and the next
	 * segment will start at the value of padding.
	 */

	/* We'll fill out padding later, so start filling in mrp at index 1 */
	if (padding != 0) {
		current = 1;
	}

	/* If we have no more need for lvp let it go now */
	if (lvp != NULL && use_lib_va == 0) {
		lib_va_release(lvp);
		MOBJ_STAT_ADD(lvp_not_needed);
		lvp = NULL;
	}

	/* Now fill out the mrp structs from the program headers */
	STRUCT_SET_HANDLE(mph, model, (struct myphdr *)phdrbase);
	for (i = 0; i < nphdrs; i++) {
		p_type = STRUCT_FGET(mph, x.p_type);
		if (p_type == PT_LOAD || p_type == PT_SUNWBSS) {
			vaddr = (caddr_t)(uintptr_t)STRUCT_FGET(mph, x.p_vaddr);
			p_memsz = STRUCT_FGET(mph, x.p_memsz);
			p_filesz = STRUCT_FGET(mph, x.p_filesz);
			p_offset = STRUCT_FGET(mph, x.p_offset);
			p_flags = STRUCT_FGET(mph, x.p_flags);

			/*
			 * Skip this header if it requests no memory to be
			 * mapped.
			 */
			if (p_memsz == 0) {
				STRUCT_SET_HANDLE(mph, model,
				    (struct myphdr *)((size_t)STRUCT_BUF(mph) +
				    hsize));
				MOBJ_STAT_ADD(no_mem_map_sz);
				continue;
			}

			prot = 0;
			if (p_flags & PF_R)
				prot |= PROT_READ;
			if (p_flags & PF_W)
				prot |= PROT_WRITE;
			if (p_flags & PF_X)
				prot |= PROT_EXEC;

			ASSERT(current < loadable);
			mrp[current].mr_msize = p_memsz;
			mrp[current].mr_fsize = p_filesz;
			mrp[current].mr_offset = p_offset;
			mrp[current].mr_prot = prot;

			if (hdr_seen == 0 && p_filesz != 0) {
				mrp[current].mr_flags = MR_HDR_ELF;
				/*
				 * We modify mr_offset because we
				 * need to map the ELF header as well, and if
				 * we didn't then the header could be left out
				 * of the mapping that we will create later.
				 * Since we're removing the offset, we need to
				 * account for that in the other fields as well
				 * since we will be mapping the memory from 0
				 * to p_offset.
				 */
				if (e_type == ET_DYN) {
					mrp[current].mr_offset = 0;
					mrp[current].mr_msize += p_offset;
					mrp[current].mr_fsize += p_offset;
				} else {
					ASSERT(e_type == ET_EXEC);
					/*
					 * Save off the start addr which will be
					 * our bias for the rest of the
					 * ET_EXEC mappings.
					 */
					start_addr = vaddr - padding;
				}
				mrp[current].mr_addr = (caddr_t)padding;
				hdr_seen = 1;
			} else {
				if (e_type == ET_EXEC) {
					/* bias mr_addr */
					mrp[current].mr_addr =
					    vaddr - (size_t)start_addr;
				} else {
					mrp[current].mr_addr = vaddr + padding;
				}
				mrp[current].mr_flags = 0;
			}
			current++;
		}

		/* Move to next phdr */
		STRUCT_SET_HANDLE(mph, model,
		    (struct myphdr *)((size_t)STRUCT_BUF(mph) +
		    hsize));
	}

	/* Now fill out the padding segments */
	if (padding != 0) {
		mrp[0].mr_addr = NULL;
		mrp[0].mr_msize = padding;
		mrp[0].mr_fsize = 0;
		mrp[0].mr_offset = 0;
		mrp[0].mr_prot = 0;
		mrp[0].mr_flags = MR_PADDING;

		/* Setup padding for the last segment */
		ASSERT(current == loadable - 1);
		mrp[current].mr_addr = (caddr_t)lib_len + padding;
		mrp[current].mr_msize = padding;
		mrp[current].mr_fsize = 0;
		mrp[current].mr_offset = 0;
		mrp[current].mr_prot = 0;
		mrp[current].mr_flags = MR_PADDING;
	}

	/*
	 * Need to make sure address ranges desired are not in use or
	 * are previously allocated reservations from /dev/null.  For
	 * ET_DYN, we already made sure our address range was free.
	 */
	if (e_type == ET_EXEC) {
		ret = check_exec_addrs(loadable, mrp, start_addr);
		if (ret != 0) {
			ASSERT(lvp == NULL);
			MOBJ_STAT_ADD(check_exec_failed);
			return (ret);
		}
	}

	/* Finish up our business with lvp. */
	if (lvp) {
		ASSERT(e_type == ET_DYN);
		if (lvp->lv_num_segs == 0 && loadable <= LIBVA_CACHED_SEGS) {
			bcopy(mrp, lvp->lv_mps,
			    loadable * sizeof (mmapobj_result_t));
			membar_producer();
		}
		/*
		 * Setting lv_num_segs to a non-zero value indicates that
		 * lv_mps is now valid and can be used by other threads.
		 * So, the above stores need to finish before lv_num_segs
		 * is updated. lv_mps is only valid if lv_num_segs is
		 * greater than LIBVA_CACHED_SEGS.
		 */
		lvp->lv_num_segs = loadable;
		lib_va_release(lvp);
		MOBJ_STAT_ADD(lvp_used);
	}

	/* Now that we have mrp completely filled out go map it */
	ret = mmapobj_map_elf(vp, start_addr, mrp, loadable, fcred, e_type);
	if (ret == 0) {
		*num_mapped = loadable;
	}

	return (ret);
}

/*
 * Take the ELF file passed in, and do the work of mapping it.
 * num_mapped in - # elements in user buffer
 * num_mapped out - # sections mapped and length of mrp array if
 *			no errors.
 */
static int
doelfwork(Ehdr *ehdrp, vnode_t *vp, mmapobj_result_t *mrp,
    uint_t *num_mapped, size_t padding, cred_t *fcred)
{
	int error;
	offset_t phoff;
	int nphdrs;
	unsigned char ei_class;
	unsigned short phentsize;
	ssize_t phsizep;
	caddr_t phbasep;
	int to_map;
	model_t model;

	ei_class = ehdrp->e_ident[EI_CLASS];
	model = get_udatamodel();
	if ((model == DATAMODEL_ILP32 && ei_class == ELFCLASS64) ||
	    (model == DATAMODEL_LP64 && ei_class == ELFCLASS32)) {
		MOBJ_STAT_ADD(wrong_model);
		return (ENOTSUP);
	}

	/* Can't execute code from "noexec" mounted filesystem. */
	if (ehdrp->e_type == ET_EXEC &&
	    (vp->v_vfsp->vfs_flag & VFS_NOEXEC) != 0) {
		MOBJ_STAT_ADD(noexec_fs);
		return (EACCES);
	}

	/*
	 * Relocatable and core files are mapped as a single flat file
	 * since no interpretation is done on them by mmapobj.
	 */
	if (ehdrp->e_type == ET_REL || ehdrp->e_type == ET_CORE) {
		to_map = padding ? 3 : 1;
		if (*num_mapped < to_map) {
			*num_mapped = to_map;
			MOBJ_STAT_ADD(e2big_et_rel);
			return (E2BIG);
		}
		error = mmapobj_map_flat(vp, mrp, padding, fcred);
		if (error == 0) {
			*num_mapped = to_map;
			mrp[padding ? 1 : 0].mr_flags = MR_HDR_ELF;
			MOBJ_STAT_ADD(et_rel_mapped);
		}
		return (error);
	}

	/* Check for an unknown ELF type */
	if (ehdrp->e_type != ET_EXEC && ehdrp->e_type != ET_DYN) {
		MOBJ_STAT_ADD(unknown_elf_type);
		return (ENOTSUP);
	}

	if (ei_class == ELFCLASS32) {
		Elf32_Ehdr *e32hdr = (Elf32_Ehdr *)ehdrp;
		ASSERT(model == DATAMODEL_ILP32);
		nphdrs = e32hdr->e_phnum;
		phentsize = e32hdr->e_phentsize;
		if (phentsize < sizeof (Elf32_Phdr)) {
			MOBJ_STAT_ADD(phent32_too_small);
			return (ENOTSUP);
		}
		phoff = e32hdr->e_phoff;
	} else if (ei_class == ELFCLASS64) {
		Elf64_Ehdr *e64hdr = (Elf64_Ehdr *)ehdrp;
		ASSERT(model == DATAMODEL_LP64);
		nphdrs = e64hdr->e_phnum;
		phentsize = e64hdr->e_phentsize;
		if (phentsize < sizeof (Elf64_Phdr)) {
			MOBJ_STAT_ADD(phent64_too_small);
			return (ENOTSUP);
		}
		phoff = e64hdr->e_phoff;
	} else {
		/* fallthrough case for an invalid ELF class */
		MOBJ_STAT_ADD(inval_elf_class);
		return (ENOTSUP);
	}

	/*
	 * nphdrs should only have this value for core files which are handled
	 * above as a single mapping.  If other file types ever use this
	 * sentinel, then we'll add the support needed to handle this here.
	 */
	if (nphdrs == PN_XNUM) {
		MOBJ_STAT_ADD(too_many_phdrs);
		return (ENOTSUP);
	}

	phsizep = nphdrs * phentsize;

	if (phsizep == 0) {
		MOBJ_STAT_ADD(no_phsize);
		return (ENOTSUP);
	}

	/* Make sure we only wait for memory if it's a reasonable request */
	if (phsizep > mmapobj_alloc_threshold) {
		MOBJ_STAT_ADD(phsize_large);
		if ((phbasep = kmem_alloc(phsizep, KM_NOSLEEP)) == NULL) {
			MOBJ_STAT_ADD(phsize_xtralarge);
			return (ENOMEM);
		}
	} else {
		phbasep = kmem_alloc(phsizep, KM_SLEEP);
	}

	if ((error = vn_rdwr(UIO_READ, vp, phbasep, phsizep,
	    (offset_t)phoff, UIO_SYSSPACE, 0, (rlim64_t)0,
	    fcred, NULL)) != 0) {
		kmem_free(phbasep, phsizep);
		return (error);
	}

	/* Now process the phdr's */
	error = process_phdr(ehdrp, phbasep, nphdrs, mrp, vp, num_mapped,
	    padding, fcred);
	kmem_free(phbasep, phsizep);
	return (error);
}

#if defined(__sparc)
/*
 * Hack to support 64 bit kernels running AOUT 4.x programs.
 * This is the sizeof (struct nlist) for a 32 bit kernel.
 * Since AOUT programs are 32 bit only, they will never use the 64 bit
 * sizeof (struct nlist) and thus creating a #define is the simplest
 * way around this since this is a format which is not being updated.
 * This will be used in the place of sizeof (struct nlist) below.
 */
#define	NLIST_SIZE	(0xC)

static int
doaoutwork(vnode_t *vp, mmapobj_result_t *mrp,
    uint_t *num_mapped, struct exec *hdr, cred_t *fcred)
{
	int error;
	size_t size;
	size_t osize;
	size_t nsize;	/* nlist size */
	size_t msize;
	size_t zfoddiff;
	caddr_t addr;
	caddr_t start_addr;
	struct as *as = curproc->p_as;
	int prot = PROT_USER | PROT_READ | PROT_EXEC;
	uint_t mflag = MAP_PRIVATE | _MAP_LOW32;
	offset_t off = 0;
	int segnum = 0;
	uint_t to_map;
	int is_library = 0;
	struct segvn_crargs crargs = SEGVN_ZFOD_ARGS(PROT_ZFOD, PROT_ALL);

	/* Only 32bit apps supported by this file format */
	if (get_udatamodel() != DATAMODEL_ILP32) {
		MOBJ_STAT_ADD(aout_64bit_try);
		return (ENOTSUP);
	}

	/* Check to see if this is a library */
	if (hdr->a_magic == ZMAGIC && hdr->a_entry < PAGESIZE) {
		is_library = 1;
	}

	/* Can't execute code from "noexec" mounted filesystem. */
	if (((vp->v_vfsp->vfs_flag & VFS_NOEXEC) != 0) && (is_library == 0)) {
		MOBJ_STAT_ADD(aout_noexec);
		return (EACCES);
	}

	/*
	 * There are 2 ways to calculate the mapped size of executable:
	 * 1) rounded text size + data size + bss size.
	 * 2) starting offset for text + text size + data size + text relocation
	 *    size + data relocation size + room for nlist data structure.
	 *
	 * The larger of the two sizes will be used to map this binary.
	 */
	osize = P2ROUNDUP(hdr->a_text, PAGESIZE) + hdr->a_data + hdr->a_bss;

	off = hdr->a_magic == ZMAGIC ? 0 : sizeof (struct exec);

	nsize = off + hdr->a_text + hdr->a_data + hdr->a_trsize +
	    hdr->a_drsize + NLIST_SIZE;

	size = MAX(osize, nsize);
	if (size != nsize) {
		nsize = 0;
	}

	/*
	 * 1 seg for text and 1 seg for initialized data.
	 * 1 seg for bss (if can't fit in leftover space of init data)
	 * 1 seg for nlist if needed.
	 */
	to_map = 2 + (nsize ? 1 : 0) +
	    (hdr->a_bss > PAGESIZE - P2PHASE(hdr->a_data, PAGESIZE) ? 1 : 0);
	if (*num_mapped < to_map) {
		*num_mapped = to_map;
		MOBJ_STAT_ADD(aout_e2big);
		return (E2BIG);
	}

	/* Reserve address space for the whole mapping */
	if (is_library) {
		/* We'll let VOP_MAP below pick our address for us */
		addr = NULL;
		MOBJ_STAT_ADD(aout_lib);
	} else {
		/*
		 * default start address for fixed binaries from AOUT 4.x
		 * standard.
		 */
		MOBJ_STAT_ADD(aout_fixed);
		mflag |= MAP_FIXED;
		addr = (caddr_t)0x2000;
		as_rangelock(as);
		if (as_gap(as, size, &addr, &size, 0, NULL) != 0) {
			as_rangeunlock(as);
			MOBJ_STAT_ADD(aout_addr_in_use);
			return (EADDRINUSE);
		}
		crargs.flags |= MAP_NORESERVE;
		error = as_map(as, addr, size, segvn_create, &crargs);
		ASSERT(addr == (caddr_t)0x2000);
		as_rangeunlock(as);
	}

	start_addr = addr;
	osize = size;

	/*
	 * Map as large as we need, backed by file, this will be text, and
	 * possibly the nlist segment.  We map over this mapping for bss and
	 * initialized data segments.
	 */
	error = VOP_MAP(vp, off, as, &addr, size, prot, PROT_ALL,
	    mflag, fcred, NULL);
	if (error) {
		if (!is_library) {
			(void) as_unmap(as, start_addr, osize);
		}
		return (error);
	}

	/* pickup the value of start_addr and osize for libraries */
	start_addr = addr;
	osize = size;

	/*
	 * We have our initial reservation/allocation so we need to use fixed
	 * addresses from now on.
	 */
	mflag |= MAP_FIXED;

	mrp[0].mr_addr = addr;
	mrp[0].mr_msize = hdr->a_text;
	mrp[0].mr_fsize = hdr->a_text;
	mrp[0].mr_offset = 0;
	mrp[0].mr_prot = PROT_READ | PROT_EXEC;
	mrp[0].mr_flags = MR_HDR_AOUT;


	/*
	 * Map initialized data. We are mapping over a portion of the
	 * previous mapping which will be unmapped in VOP_MAP below.
	 */
	off = P2ROUNDUP((offset_t)(hdr->a_text), PAGESIZE);
	msize = off;
	addr += off;
	size = hdr->a_data;
	error = VOP_MAP(vp, off, as, &addr, size, PROT_ALL, PROT_ALL,
	    mflag, fcred, NULL);
	if (error) {
		(void) as_unmap(as, start_addr, osize);
		return (error);
	}
	msize += size;
	mrp[1].mr_addr = addr;
	mrp[1].mr_msize = size;
	mrp[1].mr_fsize = size;
	mrp[1].mr_offset = 0;
	mrp[1].mr_prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	mrp[1].mr_flags = 0;

	/* Need to zero out remainder of page */
	addr += hdr->a_data;
	zfoddiff = P2PHASE((size_t)addr, PAGESIZE);
	if (zfoddiff) {
		label_t ljb;

		MOBJ_STAT_ADD(aout_zfoddiff);
		zfoddiff = PAGESIZE - zfoddiff;
		if (on_fault(&ljb)) {
			no_fault();
			MOBJ_STAT_ADD(aout_uzero_fault);
			(void) as_unmap(as, start_addr, osize);
			return (EFAULT);
		}
		uzero(addr, zfoddiff);
		no_fault();
	}
	msize += zfoddiff;
	segnum = 2;

	/* Map bss */
	if (hdr->a_bss > zfoddiff) {
		struct segvn_crargs crargs =
		    SEGVN_ZFOD_ARGS(PROT_ZFOD, PROT_ALL);
		MOBJ_STAT_ADD(aout_map_bss);
		addr += zfoddiff;
		size = hdr->a_bss - zfoddiff;
		as_rangelock(as);
		(void) as_unmap(as, addr, size);
		error = as_map(as, addr, size, segvn_create, &crargs);
		as_rangeunlock(as);
		msize += size;

		if (error) {
			MOBJ_STAT_ADD(aout_bss_fail);
			(void) as_unmap(as, start_addr, osize);
			return (error);
		}
		mrp[2].mr_addr = addr;
		mrp[2].mr_msize = size;
		mrp[2].mr_fsize = 0;
		mrp[2].mr_offset = 0;
		mrp[2].mr_prot = PROT_READ | PROT_WRITE | PROT_EXEC;
		mrp[2].mr_flags = 0;

		addr += size;
		segnum = 3;
	}

	/*
	 * If we have extra bits left over, we need to include that in how
	 * much we mapped to make sure the nlist logic is correct
	 */
	msize = P2ROUNDUP(msize, PAGESIZE);

	if (nsize && msize < nsize) {
		MOBJ_STAT_ADD(aout_nlist);
		mrp[segnum].mr_addr = addr;
		mrp[segnum].mr_msize = nsize - msize;
		mrp[segnum].mr_fsize = 0;
		mrp[segnum].mr_offset = 0;
		mrp[segnum].mr_prot = PROT_READ | PROT_EXEC;
		mrp[segnum].mr_flags = 0;
	}

	*num_mapped = to_map;
	return (0);
}
#endif

/*
 * These are the two types of files that we can interpret and we want to read
 * in enough info to cover both types when looking at the initial header.
 */
#define	MAX_HEADER_SIZE	(MAX(sizeof (Ehdr), sizeof (struct exec)))

/*
 * Map vp passed in in an interpreted manner.  ELF and AOUT files will be
 * interpreted and mapped appropriately for execution.
 * num_mapped in - # elements in mrp
 * num_mapped out - # sections mapped and length of mrp array if
 *		    no errors or E2BIG returned.
 *
 * Returns 0 on success, errno value on failure.
 */
static int
mmapobj_map_interpret(vnode_t *vp, mmapobj_result_t *mrp,
    uint_t *num_mapped, size_t padding, cred_t *fcred)
{
	int error = 0;
	vattr_t vattr;
	struct lib_va *lvp;
	caddr_t start_addr;
	model_t model;

	/*
	 * header has to be aligned to the native size of ulong_t in order
	 * to avoid an unaligned access when dereferencing the header as
	 * a ulong_t.  Thus we allocate our array on the stack of type
	 * ulong_t and then have header, which we dereference later as a char
	 * array point at lheader.
	 */
	ulong_t lheader[(MAX_HEADER_SIZE / (sizeof (ulong_t))) + 1];
	caddr_t header = (caddr_t)&lheader;

	vattr.va_mask = AT_FSID | AT_NODEID | AT_CTIME | AT_MTIME | AT_SIZE;
	error = VOP_GETATTR(vp, &vattr, 0, fcred, NULL);
	if (error) {
		return (error);
	}

	/*
	 * Check lib_va to see if we already have a full description
	 * for this library.  This is the fast path and only used for
	 * ET_DYN ELF files (dynamic libraries).
	 */
	if (padding == 0 && (lvp = lib_va_find(&vattr)) != NULL) {
		int num_segs;

		model = get_udatamodel();
		if ((model == DATAMODEL_ILP32 &&
		    lvp->lv_flags & LV_ELF64) ||
		    (model == DATAMODEL_LP64 &&
		    lvp->lv_flags & LV_ELF32)) {
			lib_va_release(lvp);
			MOBJ_STAT_ADD(fast_wrong_model);
			return (ENOTSUP);
		}
		num_segs = lvp->lv_num_segs;
		if (*num_mapped < num_segs) {
			*num_mapped = num_segs;
			lib_va_release(lvp);
			MOBJ_STAT_ADD(fast_e2big);
			return (E2BIG);
		}

		/*
		 * Check to see if we have all the mappable program headers
		 * cached.
		 */
		if (num_segs <= LIBVA_CACHED_SEGS && num_segs != 0) {
			MOBJ_STAT_ADD(fast);
			start_addr = mmapobj_lookup_start_addr(lvp);
			if (start_addr == NULL) {
				lib_va_release(lvp);
				return (ENOMEM);
			}

			bcopy(lvp->lv_mps, mrp,
			    num_segs * sizeof (mmapobj_result_t));

			error = mmapobj_map_elf(vp, start_addr, mrp,
			    num_segs, fcred, ET_DYN);

			lib_va_release(lvp);
			if (error == 0) {
				*num_mapped = num_segs;
				MOBJ_STAT_ADD(fast_success);
			}
			return (error);
		}
		MOBJ_STAT_ADD(fast_not_now);

		/* Release it for now since we'll look it up below */
		lib_va_release(lvp);
	}

	/*
	 * Time to see if this is a file we can interpret.  If it's smaller
	 * than this, then we can't interpret it.
	 */
	if (vattr.va_size < MAX_HEADER_SIZE) {
		MOBJ_STAT_ADD(small_file);
		return (ENOTSUP);
	}

	if ((error = vn_rdwr(UIO_READ, vp, header, MAX_HEADER_SIZE, 0,
	    UIO_SYSSPACE, 0, (rlim64_t)0, fcred, NULL)) != 0) {
		MOBJ_STAT_ADD(read_error);
		return (error);
	}

	/* Verify file type */
	if (header[EI_MAG0] == ELFMAG0 && header[EI_MAG1] == ELFMAG1 &&
	    header[EI_MAG2] == ELFMAG2 && header[EI_MAG3] == ELFMAG3) {
		return (doelfwork((Ehdr *)lheader, vp, mrp, num_mapped,
		    padding, fcred));
	}

#if defined(__sparc)
	/* On sparc, check for 4.X AOUT format */
	switch (((struct exec *)header)->a_magic) {
	case OMAGIC:
	case ZMAGIC:
	case NMAGIC:
		return (doaoutwork(vp, mrp, num_mapped,
		    (struct exec *)lheader, fcred));
	}
#endif

	/* Unsupported type */
	MOBJ_STAT_ADD(unsupported);
	return (ENOTSUP);
}

/*
 * Given a vnode, map it as either a flat file or interpret it and map
 * it according to the rules of the file type.
 * *num_mapped will contain the size of the mmapobj_result_t array passed in.
 * If padding is non-zero, the mappings will be padded by that amount
 * rounded up to the nearest pagesize.
 * If the mapping is successful, *num_mapped will contain the number of
 * distinct mappings created, and mrp will point to the array of
 * mmapobj_result_t's which describe these mappings.
 *
 * On error, -1 is returned and errno is set appropriately.
 * A special error case will set errno to E2BIG when there are more than
 * *num_mapped mappings to be created and *num_mapped will be set to the
 * number of mappings needed.
 */
int
mmapobj(vnode_t *vp, uint_t flags, mmapobj_result_t *mrp,
    uint_t *num_mapped, size_t padding, cred_t *fcred)
{
	int to_map;
	int error = 0;

	ASSERT((padding & PAGEOFFSET) == 0);
	ASSERT((flags & ~MMOBJ_ALL_FLAGS) == 0);
	ASSERT(num_mapped != NULL);
	ASSERT((flags & MMOBJ_PADDING) ? padding != 0 : padding == 0);

	if ((flags & MMOBJ_INTERPRET) == 0) {
		to_map = padding ? 3 : 1;
		if (*num_mapped < to_map) {
			*num_mapped = to_map;
			MOBJ_STAT_ADD(flat_e2big);
			return (E2BIG);
		}
		error = mmapobj_map_flat(vp, mrp, padding, fcred);

		if (error) {
			return (error);
		}
		*num_mapped = to_map;
		return (0);
	}

	error = mmapobj_map_interpret(vp, mrp, num_mapped, padding, fcred);
	return (error);
}
