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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DDIDMAREQ_H
#define	_SYS_DDIDMAREQ_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Memory Objects
 *
 * Definitions of structures that can describe
 * an object that can be mapped for DMA.
 */

/*
 * Structure describing a virtual address
 */
struct v_address {
	caddr_t		v_addr;		/* base virtual address */
	struct	as	*v_as;		/* pointer to address space */
	void 		*v_priv;	/* priv data for shadow I/O */
};

/*
 * Structure describing a page-based address
 */
struct pp_address {
	/*
	 * A pointer to a circularly linked list of page structures.
	 */
	struct page *pp_pp;
	uint_t pp_offset;	/* offset within first page */
};

/*
 * Structure to describe a physical memory address.
 */
struct phy_address {
	ulong_t	p_addr;		/* base physical address */
	ulong_t	p_memtype;	/* memory type */
};

/*
 * Structure to describe an array DVMA addresses.
 * Under normal circumstances, dv_nseg will be 1.
 * dvs_start is always page aligned.
 */
struct dvma_address {
	size_t dv_off;
	size_t dv_nseg;
	struct dvmaseg {
		uint64_t dvs_start;
		size_t dvs_len;
	} *dv_seg;
};

/*
 * A union of all of the above structures.
 *
 * This union describes the relationship between
 * the kind of an address description and an object.
 */
typedef union {
	struct v_address virt_obj;	/* Some virtual address		*/
	struct pp_address pp_obj;	/* Some page-based address	*/
	struct phy_address phys_obj;	/* Some physical address	*/
	struct dvma_address dvma_obj;
} ddi_dma_aobj_t;

/*
 * DMA object types - used to select how the object
 * being mapped is being addressed by the IU.
 */
typedef enum {
	DMA_OTYP_VADDR = 0,	/* enforce starting value of zero */
	DMA_OTYP_PAGES,
	DMA_OTYP_PADDR,
	DMA_OTYP_BUFVADDR,
	DMA_OTYP_DVADDR
} ddi_dma_atyp_t;

/*
 * A compact package to describe an object that is to be mapped for DMA.
 */
typedef struct {
	uint_t		dmao_size;	/* size, in bytes, of the object */
	ddi_dma_atyp_t	dmao_type;	/* type of object */
	ddi_dma_aobj_t	dmao_obj;	/* the object described */
} ddi_dma_obj_t;

/*
 * DMA addressing limits.
 *
 * This structure describes the constraints that a particular device's
 * DMA engine has to its parent so that the parent may correctly set
 * things up for a DMA mapping. Each parent may in turn modify the
 * constraints listed in a DMA request structure in order to describe
 * to its parent any changed or additional constraints. The rules
 * are that each parent may modify a constraint in order to further
 * constrain things (e.g., picking a more limited address range than
 * that permitted by the child), but that the parent may not ignore
 * a child's constraints.
 *
 * A particular constraint that we do *not* address is whether or not
 * a requested mapping is too large for a DMA engine's counter to
 * correctly track. It is still up to each driver to explicitly handle
 * transfers that are too large for its own hardware to deal with directly.
 *
 * The mapping routines that are cognizant of this structure will
 * copy any user defined limits structure if they need to modify
 * the fields (as alluded to above).
 *
 * A note as to how to define constraints:
 *
 * How you define the constraints for your device depends on how you
 * define your device. For example, you may have an SBus card with a
 * device on it that address only the bottom 16mb of virtual DMA space.
 * However, if the card also has ancillary circuitry that pulls the high 8
 * bits of address lines high, the more correct expression for your device
 * is that it address [0xff000000..0xffffffff] rather than [0..0x00ffffff].
 */
#if defined(__sparc)
typedef struct ddi_dma_lim {

	/*
	 * Low range of 32 bit addressing capability.
	 */
	uint_t	dlim_addr_lo;

	/*
	 * Upper inclusive bound of addressing capability. It is an
	 * inclusive boundary limit to allow for the addressing range
	 * [0..0xffffffff] to be specified in preference to [0..0].
	 */
	uint_t	dlim_addr_hi;

	/*
	 * Inclusive upper bound with which The DMA engine's counter acts as
	 * a register.
	 *
	 * This handles the case where an upper portion of a DMA address
	 * register is a latch instead of being a full 32 bit register
	 * (e.g., the upper 8 bits may remain constant while the lower
	 * 24 bits are the real address register).
	 *
	 * This essentially gives a hint about segment limitations
	 * to the mapping routines.
	 */
	uint_t	dlim_cntr_max;

	/*
	 * DMA burst sizes.
	 *
	 * At the time of a mapping request, this tag defines the possible
	 * DMA burst cycle sizes that the requestor's DMA engine can
	 * emit. The format of the data is binary encoding of burst sizes
	 * assumed to be powers of two. That is, if a DMA engine is capable
	 * of doing 1, 2, 4 and 16 byte transfers, the encoding would be 0x17.
	 *
	 * As the mapping request is handled by intervening nexi, the
	 * burstsizes value may be modified. Prior to enabling DMA for
	 * the specific device, the driver that owns the DMA engine should
	 * check (via ddi_dma_burstsizes(9F)) what the allowed burstsizes
	 * have become and program their DMA engine appropriately.
	 */
	uint_t	dlim_burstsizes;

	/*
	 * Minimum effective DMA transfer size, in units of bytes.
	 *
	 * This value specifies the minimum effective granularity of the
	 * DMA engine. It is distinct from dlim_burtsizes in that it
	 * describes the minimum amount of access a DMA transfer will
	 * effect. dlim_burtsizes describes in what electrical fashion
	 * the DMA engine might perform its accesses, while dlim_minxfer
	 * describes the minimum amount of memory that can be touched by
	 * the DMA transfer.
	 *
	 * As the mapping request is handled by intervening nexi, the
	 * dlim_minxfer value may be modifed contingent upon the presence
	 * (and use) of I/O caches and DMA write buffers in between the
	 * DMA engine and the object that DMA is being performed on.
	 *
	 */
	uint_t	dlim_minxfer;

	/*
	 * Expected average data rate for this DMA engine
	 * while transferring data.
	 *
	 * This is used as a hint for a number of operations that might
	 * want to know the possible optimal latency requirements of this
	 * device. A value of zero will be interpreted as a 'do not care'.
	 */
	uint_t	dlim_dmaspeed;

} ddi_dma_lim_t;

#elif defined(__x86)

/*
 * values for dlim_minxfer
 */
#define	DMA_UNIT_8  1
#define	DMA_UNIT_16 2
#define	DMA_UNIT_32 4

/*
 * Version number
 */
#define	DMALIM_VER0	((0x86000000) + 0)

typedef struct ddi_dma_lim {

	/*
	 * Low range of 32 bit addressing capability.
	 */
	uint_t	dlim_addr_lo;

	/*
	 * Upper Inclusive bound of 32 bit addressing capability.
	 *
	 * The ISA nexus restricts this to 0x00ffffff, since this bus has
	 * only 24 address lines.  This enforces the 16 Mb address limitation.
	 * The EISA nexus restricts this to 0xffffffff.
	 */
	uint_t	dlim_addr_hi;

	/*
	 * DMA engine counter not used; set to 0
	 */
	uint_t	dlim_cntr_max;

	/*
	 *  DMA burst sizes not used; set to 1
	 */
	uint_t	dlim_burstsizes;

	/*
	 * Minimum effective DMA transfer size.
	 *
	 * This value specifies the minimum effective granularity of the
	 * DMA engine. It is distinct from dlim_burstsizes in that it
	 * describes the minimum amount of access a DMA transfer will
	 * effect. dlim_burstsizes describes in what electrical fashion
	 * the DMA engine might perform its accesses, while dlim_minxfer
	 * describes the minimum amount of memory that can be touched by
	 * the DMA transfer.
	 *
	 * This value also implies the required address alignment.
	 * The number of bytes transferred is assumed to be
	 * 	dlim_minxfer * (DMA engine count)
	 *
	 * It should be set to DMA_UNIT_8, DMA_UNIT_16, or DMA_UNIT_32.
	 */
	uint_t	dlim_minxfer;

	/*
	 * Expected average data rate for this DMA engine
	 * while transferring data.
	 *
	 * This is used as a hint for a number of operations that might
	 * want to know the possible optimal latency requirements of this
	 * device. A value of zero will be interpreted as a 'do not care'.
	 */
	uint_t	dlim_dmaspeed;


	/*
	 * Version number of this structure
	 */
	uint_t	dlim_version;	/* = 0x86 << 24 + 0 */

	/*
	 * Inclusive upper bound with which the DMA engine's Address acts as
	 * a register.
	 * This handles the case where an upper portion of a DMA address
	 * register is a latch instead of being a full 32 bit register
	 * (e.g., the upper 16 bits remain constant while the lower 16 bits
	 * are incremented for each DMA transfer).
	 *
	 * The ISA nexus restricts only 3rd-party DMA requests to 0x0000ffff,
	 * since the ISA DMA engine has a 16-bit register for low address and
	 * an 8-bit latch for high address.  This enforces the first 64 Kb
	 * limitation (address boundary).
	 * The EISA nexus restricts only 3rd-party DMA requests to 0xffffffff.
	 */
	uint_t	dlim_adreg_max;

	/*
	 * Maximum transfer count that the DMA engine can handle.
	 *
	 * The ISA nexus restricts only 3rd-party DMA requests to 0x0000ffff,
	 * since the ISA DMA engine has a 16-bit register for counting.
	 * This enforces the other 64 Kb limitation (count size).
	 * The EISA nexus restricts only 3rd-party DMA requests to 0x00ffffff,
	 * since the EISA DMA engine has a 24-bit register for counting.
	 *
	 * This transfer count limitation is a per segment limitation.
	 * It can also be used to restrict the size of segments.
	 *
	 * This is used as a bit mask, so it must be a power of 2, minus 1.
	 */
	uint_t	dlim_ctreg_max;

	/*
	 * Granularity of DMA transfer, in units of bytes.
	 *
	 * Breakup sizes must be multiples of this value.
	 * If no scatter/gather capabilty is specified, then the size of
	 * each DMA transfer must be a multiple of this value.
	 *
	 * If there is scatter/gather capability, then a single cookie cannot
	 * be smaller in size than the minimum xfer value, and may be less
	 * than the granularity value.  The total transfer length of the
	 * scatter/gather list should be a multiple of the granularity value;
	 * use dlim_sgllen to specify the length of the scatter/gather list.
	 *
	 * This value should be equal to the sector size of the device.
	 */
	uint_t	dlim_granular;

	/*
	 * Length of scatter/gather list
	 *
	 * This value specifies the number of segments or cookies that a DMA
	 * engine can consume in one i/o request to the device.  For 3rd-party
	 * DMA that uses the bus nexus this should be set to 1.  Devices with
	 * 1st-party DMA capability should specify the number of entries in
	 * its scatter/gather list.  The breakup routine will ensure that each
	 * group of dlim_sgllen cookies (within a DMA window) will have a
	 * total transfer length that is a multiple of dlim_granular.
	 *
	 *	< 0  :  tbd
	 *	= 0  :  breakup is for PIO.
	 *	= 1  :  breakup is for DMA engine with no scatter/gather
	 *		capability.
	 *	>= 2 :  breakup is for DMA engine with scatter/gather
	 *		capability; value is max number of entries in list.
	 *
	 * Note that this list length is not dependent on the DMA window
	 * size.  The size of the DMA window is based on resources consumed,
	 * such as intermediate buffers.  Several s/g lists may exist within
	 * a window.  But the end of a window does imply the end of the s/g
	 * list.
	 */
	short	dlim_sgllen;

	/*
	 * Size of device i/o request
	 *
	 * This value indicates the maximum number of bytes the device
	 * can transmit/receive for one i/o command.  This limitation is
	 * significant ony if it is less than (dlim_ctreg_max * dlim_sgllen).
	 */
	uint_t	dlim_reqsize;

} ddi_dma_lim_t;

#else
#error "struct ddi_dma_lim not defined for this architecture"
#endif	/* defined(__sparc) */

/*
 * Flags definition for dma_attr_flags
 */

/*
 * return physical DMA address on platforms
 * which support DVMA
 */
#define	DDI_DMA_FORCE_PHYSICAL		0x0100

/*
 * An error will be flagged for DMA data path errors
 */
#define	DDI_DMA_FLAGERR			0x200

/*
 * Enable relaxed ordering
 */
#define	DDI_DMA_RELAXED_ORDERING	0x400


/*
 * Consolidation private x86 only flag which will cause a bounce buffer
 * (paddr < dma_attr_seg) to be used if the buffer passed to the bind
 * operation contains pages both above and below dma_attr_seg. If this flag
 * is set, dma_attr_seg must be <= dma_attr_addr_hi.
 */
#define	_DDI_DMA_BOUNCE_ON_SEG		0x8000

#define	DMA_ATTR_V0		0
#define	DMA_ATTR_VERSION	DMA_ATTR_V0

typedef struct ddi_dma_attr {
	uint_t		dma_attr_version;	/* version number */
	uint64_t	dma_attr_addr_lo;	/* low DMA address range */
	uint64_t	dma_attr_addr_hi;	/* high DMA address range */
	uint64_t	dma_attr_count_max;	/* DMA counter register */
	uint64_t	dma_attr_align;		/* DMA address alignment */
	uint_t		dma_attr_burstsizes;	/* DMA burstsizes */
	uint32_t	dma_attr_minxfer;	/* min effective DMA size */
	uint64_t 	dma_attr_maxxfer;	/* max DMA xfer size */
	uint64_t 	dma_attr_seg;		/* segment boundary */
	int		dma_attr_sgllen;	/* s/g length */
	uint32_t	dma_attr_granular;	/* granularity of device */
	uint_t		dma_attr_flags;		/* Bus specific DMA flags */
} ddi_dma_attr_t;

/*
 * Handy macro to set a maximum bit value (should be elsewhere)
 *
 * Clear off all bits lower then 'mybit' in val; if there are no
 * bits higher than or equal to mybit in val then set mybit. Assumes
 * mybit equals some power of 2 and is not zero.
 */
#define	maxbit(val, mybit)	\
	((val) & ~((mybit)-1)) | ((((val) & ~((mybit)-1)) == 0) ? (mybit) : 0)

/*
 * Handy macro to set a minimum bit value (should be elsewhere)
 *
 * Clear off all bits higher then 'mybit' in val; if there are no
 * bits lower than or equal to mybit in val then set mybit. Assumes
 * mybit equals some pow2 and is not zero.
 */
#define	minbit(val, mybit)	\
	(((val)&((mybit)|((mybit)-1))) | \
	((((val) & ((mybit)-1)) == 0) ? (mybit) : 0))

/*
 * Structure of a request to map an object for DMA.
 */
typedef struct ddi_dma_req {
	/*
	 * Caller's DMA engine constraints.
	 *
	 * If there are no particular constraints to the caller's DMA
	 * engine, this field may be set to NULL. The implementation DMA
	 * setup functions will then select a set of standard beginning
	 * constraints.
	 *
	 * In either case, as the mapping proceeds, the initial DMA
	 * constraints may become more restrictive as each intervening
	 * nexus might add further restrictions.
	 */
	ddi_dma_lim_t	*dmar_limits;

	/*
	 * Contains the information passed to the DMA mapping allocation
	 * routine(s).
	 */
	uint_t		dmar_flags;

	/*
	 * Callback function. A caller of the DMA mapping functions must
	 * specify by filling in this field whether the allocation routines
	 * can sleep awaiting mapping resources, must *not* sleep awaiting
	 * resources, or may *not* sleep awaiting any resources and must
	 * call the function specified by dmar_fp with the the argument
	 * dmar_arg when resources might have become available at a future
	 * time.
	 */
	int		(*dmar_fp)();

	caddr_t		dmar_arg;	/* Callback function argument */

	/*
	 * Description of the object to be mapped for DMA.
	 * Must be last in this structure in case that the
	 * union ddi_dma_obj_t changes in the future.
	 */
	ddi_dma_obj_t	dmar_object;

} ddi_dma_req_t;

/*
 * Defines for the DMA mapping allocation functions
 *
 * If a DMA callback funtion is set to anything other than the following
 * defines then it is assumed that one wishes a callback and is providing
 * a function address.
 */
#define	DDI_DMA_DONTWAIT	((int (*)(caddr_t))0)
#define	DDI_DMA_SLEEP		((int (*)(caddr_t))1)

/*
 * Return values from callback functions.
 */
#define	DDI_DMA_CALLBACK_RUNOUT	0
#define	DDI_DMA_CALLBACK_DONE	1

/*
 * Flag definitions for the allocation functions.
 */
#define	DDI_DMA_WRITE		0x0001	/* Direction memory --> IO 	*/
#define	DDI_DMA_READ		0x0002	/* Direction IO --> memory	*/
#define	DDI_DMA_RDWR		(DDI_DMA_READ | DDI_DMA_WRITE)

/*
 * If possible, establish a MMU redzone after the mapping (to protect
 * against cheap DMA hardware that might get out of control).
 */
#define	DDI_DMA_REDZONE		0x0004

/*
 * A partial allocation is allowed. That is, if the size of the object
 * exceeds the mapping resources available, only map a portion of the
 * object and return status indicating that this took place. The caller
 * can use the functions ddi_dma_numwin(9F) and ddi_dma_getwin(9F) to
 * change, at a later point, the actual mapped portion of the object.
 *
 * The mapped portion begins at offset 0 of the object.
 *
 */
#define	DDI_DMA_PARTIAL		0x0008

/*
 * Map the object for byte consistent access. Note that explicit
 * synchronization (via ddi_dma_sync(9F)) will still be required.
 * Consider this flag to be a hint to the mapping routines as to
 * the intended use of the mapping.
 *
 * Normal data transfers can be usually consider to use 'streaming'
 * modes of operations. They start at a specific point, transfer a
 * fairly large amount of data sequentially, and then stop (usually
 * on a well aligned boundary).
 *
 * Control mode data transfers (for memory resident device control blocks,
 * e.g., ethernet message descriptors) do not access memory in such
 * a streaming sequential fashion. Instead, they tend to modify a few
 * words or bytes, move around and maybe modify a few more.
 *
 * There are many machine implementations that make this difficult to
 * control in a generic and seamless fashion. Therefore, explicit synch-
 * ronization steps (via ddi_dma_sync(9F)) are still required (even if you
 * ask for a byte-consistent mapping) in order to make the view of the
 * memory object shared between a CPU and a DMA master in consistent.
 * However, judicious use of this flag can give sufficient hints to
 * the mapping routines to attempt to pick the most efficacious mapping
 * such that the synchronization steps are as efficient as possible.
 *
 */
#define	DDI_DMA_CONSISTENT	0x0010

/*
 * Some DMA mappings have to be 'exclusive' access.
 */
#define	DDI_DMA_EXCLUSIVE	0x0020

/*
 * Sequential, unidirectional, block-sized and block aligned transfers
 */
#define	DDI_DMA_STREAMING	0x0040

/*
 * Support for 64-bit SBus devices
 */
#define	DDI_DMA_SBUS_64BIT	0x2000

/*
 * Return values from the mapping allocation functions.
 */

/*
 * succeeded in satisfying request
 */
#define	DDI_DMA_MAPPED		0

/*
 * Mapping is legitimate (for advisory calls).
 */
#define	DDI_DMA_MAPOK		0

/*
 * Succeeded in mapping a portion of the request.
 */
#define	DDI_DMA_PARTIAL_MAP	1

/*
 * indicates end of window/segment list
 */
#define	DDI_DMA_DONE		2

/*
 * No resources to map request.
 */
#define	DDI_DMA_NORESOURCES	-1

/*
 * Can't establish a mapping to the specified object
 * (no specific reason).
 */
#define	DDI_DMA_NOMAPPING	-2

/*
 * The request is too big to be mapped.
 */
#define	DDI_DMA_TOOBIG		-3

/*
 * The request is too small to be mapped.
 */
#define	DDI_DMA_TOOSMALL	-4

/*
 * The request cannot be mapped because the object
 * is locked against mapping by another DMA master.
 */
#define	DDI_DMA_LOCKED		-5

/*
 * The request cannot be mapped because the limits
 * structure has bogus values.
 */
#define	DDI_DMA_BADLIMITS	-6

/*
 * the segment/window pointer is stale
 */
#define	DDI_DMA_STALE		-7

/*
 * The system can't allocate DMA resources using
 * the given DMA attributes
 */
#define	DDI_DMA_BADATTR		-8

/*
 * A DMA handle is already used for a DMA
 */
#define	DDI_DMA_INUSE		-9


/*
 * DVMA disabled or not supported. use physical DMA
 */
#define	DDI_DMA_USE_PHYSICAL		-10


/*
 * In order for the access to a memory object to be consistent
 * between a device and a CPU, the function ddi_dma_sync(9F)
 * must be called upon the DMA handle. The following flags
 * define whose view of the object should be made consistent.
 * There are different flags here because on different machines
 * there are definite performance implications of how long
 * such synchronization takes.
 *
 * DDI_DMA_SYNC_FORDEV makes all device references to the object
 * mapped by the DMA handle up to date. It should be used by a
 * driver after a cpu modifies the memory object (over the range
 * specified by the other arguments to the ddi_dma_sync(9F) call).
 *
 * DDI_DMA_SYNC_FORCPU makes all cpu references to the object
 * mapped by the DMA handle up to date. It should be used
 * by a driver after the receipt of data from the device to
 * the memory object is done (over the range specified by
 * the other arguments to the ddi_dma_sync(9F) call).
 *
 * If the only mapping that concerns the driver is one for the
 * kernel (such as memory allocated by ddi_iopb_alloc(9F)), the
 * flag DDI_DMA_SYNC_FORKERNEL can be used. This is a hint to the
 * system that if it can synchronize the kernel's view faster
 * that the CPU's view, it can do so, otherwise it acts the
 * same as DDI_DMA_SYNC_FORCPU. DDI_DMA_SYNC_FORKERNEL might
 * speed up the synchronization of kernel mappings in case of
 * non IO-coherent CPU caches.
 */
#define	DDI_DMA_SYNC_FORDEV	0x0
#define	DDI_DMA_SYNC_FORCPU	0x1
#define	DDI_DMA_SYNC_FORKERNEL	0x2

/*
 * Bus nexus control functions for DMA
 */

/*
 * Control operations, defined here so that devops.h can be included
 * by drivers without having to include a specific SYSDDI implementation
 * header file.
 */

enum ddi_dma_ctlops {
	DDI_DMA_FREE,		/* obsolete - do not use		*/
	DDI_DMA_SYNC,		/* obsolete - do not use		*/
	DDI_DMA_HTOC,		/* obsolete - do not use		*/
	DDI_DMA_KVADDR,		/* obsolete - do not use		*/
	DDI_DMA_MOVWIN,		/* obsolete - do not use		*/
	DDI_DMA_REPWIN,		/* obsolete - do not use		*/
	DDI_DMA_GETERR,		/* obsolete - do not use		*/
	DDI_DMA_COFF,		/* obsolete - do not use		*/
	DDI_DMA_NEXTWIN,	/* obsolete - do not use		*/
	DDI_DMA_NEXTSEG,	/* obsolete - do not use		*/
	DDI_DMA_SEGTOC,		/* obsolete - do not use		*/
	DDI_DMA_RESERVE,	/* reserve some DVMA range		*/
	DDI_DMA_RELEASE,	/* free preallocated DVMA range		*/
	DDI_DMA_RESETH,		/* obsolete - do not use		*/
	DDI_DMA_CKSYNC,		/* obsolete - do not use		*/
	DDI_DMA_IOPB_ALLOC,	/* obsolete - do not use		*/
	DDI_DMA_IOPB_FREE,	/* obsolete - do not use		*/
	DDI_DMA_SMEM_ALLOC,	/* obsolete - do not use		*/
	DDI_DMA_SMEM_FREE,	/* obsolete - do not use		*/
	DDI_DMA_SET_SBUS64,	/* 64 bit SBus support			*/
	DDI_DMA_REMAP,		/* remap DVMA buffers after relocation	*/

		/*
		 * control ops for DMA engine on motherboard
		 */
	DDI_DMA_E_ACQUIRE,	/* get channel for exclusive use	*/
	DDI_DMA_E_FREE,		/* release channel			*/
	DDI_DMA_E_1STPTY,	/* setup channel for 1st party DMA	*/
	DDI_DMA_E_GETCB,	/* get control block for DMA engine	*/
	DDI_DMA_E_FREECB,	/* free control blk for DMA engine	*/
	DDI_DMA_E_PROG,		/* program channel of DMA engine	*/
	DDI_DMA_E_SWSETUP,	/* setup channel for software control	*/
	DDI_DMA_E_SWSTART,	/* software operation of DMA channel	*/
	DDI_DMA_E_ENABLE,	/* enable channel of DMA engine		*/
	DDI_DMA_E_STOP,		/* stop a channel of DMA engine		*/
	DDI_DMA_E_DISABLE,	/* disable channel of DMA engine	*/
	DDI_DMA_E_GETCNT,	/* get remaining xfer count		*/
	DDI_DMA_E_GETLIM,	/* obsolete - do not use		*/
	DDI_DMA_E_GETATTR	/* get DMA engine attributes		*/
};

/*
 * Cache attribute flags:
 *
 * IOMEM_DATA_CACHED
 *   The CPU can cache the data it fetches and push it to memory at a later
 *   time. This is the default attribute and used if no cache attributes is
 *   specified.
 *
 * IOMEM_DATA_UC_WR_COMBINE
 *   The CPU never caches the data but writes may occur out of order or be
 *   combined. It implies re-ordering.
 *
 * IOMEM_DATA_UNCACHED
 *   The CPU never caches the data and has uncacheable access to memory.
 *   It also implies strict ordering.
 *
 * The cache attributes are mutually exclusive, and any combination of the
 * values leads to a failure. On the sparc architecture, only IOMEM_DATA_CACHED
 * is meaningful, but others lead to a failure.
 */
#define	IOMEM_DATA_CACHED		0x10000 /* data is cached */
#define	IOMEM_DATA_UC_WR_COMBINE	0x20000 /* data is not cached, but */
						/* writes might be combined */
#define	IOMEM_DATA_UNCACHED		0x40000 /* data is not cached. */
#define	IOMEM_DATA_MASK			0xF0000	/* cache attrs mask */

/*
 * Check if either uncacheable or write-combining specified. (those flags are
 * mutually exclusive) This macro is used to override hat attributes if either
 * one is set.
 */
#define	OVERRIDE_CACHE_ATTR(attr)	\
	(attr & (IOMEM_DATA_UNCACHED | IOMEM_DATA_UC_WR_COMBINE))

/*
 * Get the cache attribute from flags. If there is no attributes,
 * return IOMEM_DATA_CACHED (default attribute).
 */
#define	IOMEM_CACHE_ATTR(flags)	\
	((flags & IOMEM_DATA_MASK) ? (flags & IOMEM_DATA_MASK) : \
	    IOMEM_DATA_CACHED)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDIDMAREQ_H */
