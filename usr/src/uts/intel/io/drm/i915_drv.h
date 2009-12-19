/* BEGIN CSTYLED */

/* i915_drv.h -- Private header for the I915 driver -*- linux-c -*-
 */
/*
 *
 * Copyright 2003 Tungsten Graphics, Inc., Cedar Park, Texas.
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.
 * IN NO EVENT SHALL TUNGSTEN GRAPHICS AND/OR ITS SUPPLIERS BE LIABLE FOR
 * ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _I915_DRV_H
#define _I915_DRV_H

/* General customization:
 */

#define DRIVER_AUTHOR		"Tungsten Graphics, Inc."

#define DRIVER_NAME		"i915"
#define DRIVER_DESC		"Intel Graphics"
#define DRIVER_DATE		"20080730"

#if defined(__SVR4) && defined(__sun)
#define spinlock_t kmutex_t 
#endif

#define I915_NUM_PIPE	2

#define I915_NUM_PIPE  2

/* Interface history:
 *
 * 1.1: Original.
 * 1.2: Add Power Management
 * 1.3: Add vblank support
 * 1.4: Fix cmdbuffer path, add heap destroy
 * 1.5: Add vblank pipe configuration
 * 1.6: - New ioctl for scheduling buffer swaps on vertical blank
 * 	    - Support vertical blank on secondary display pipe
 */
#define DRIVER_MAJOR		1
#define DRIVER_MINOR		6	
#define DRIVER_PATCHLEVEL	0

#if defined(__linux__)
#define I915_HAVE_FENCE
#define I915_HAVE_BUFFER
#endif
#define	I915_HAVE_GEM	1

typedef struct _drm_i915_ring_buffer {
	int tail_mask;
	unsigned long Size;
	u8 *virtual_start;
	int head;
	int tail;
	int space;
	drm_local_map_t map;
	struct drm_gem_object *ring_obj;
} drm_i915_ring_buffer_t;

struct mem_block {
	struct mem_block *next;
	struct mem_block *prev;
	int start;
	int size;
	drm_file_t *filp;		/* 0: free, -1: heap, other: real files */
};

typedef struct _drm_i915_vbl_swap {
	struct list_head head;
	drm_drawable_t drw_id;
	unsigned int plane;
	unsigned int sequence;
	int flip;
} drm_i915_vbl_swap_t;

typedef struct s3_i915_private {
	ddi_acc_handle_t saveHandle;
	caddr_t saveAddr;
	uint32_t pgtbl_ctl;
	uint8_t saveLBB;
	uint32_t saveDSPACNTR;
	uint32_t saveDSPBCNTR;
	uint32_t saveDSPARB;
	uint32_t saveRENDERSTANDBY;
	uint32_t saveHWS;
	uint32_t savePIPEACONF;
	uint32_t savePIPEBCONF;
	uint32_t savePIPEASRC;
	uint32_t savePIPEBSRC;
	uint32_t saveFPA0;
	uint32_t saveFPA1;
	uint32_t saveDPLL_A;
	uint32_t saveDPLL_A_MD;
	uint32_t saveHTOTAL_A;
	uint32_t saveHBLANK_A;
	uint32_t saveHSYNC_A;
	uint32_t saveVTOTAL_A;
	uint32_t saveVBLANK_A;
	uint32_t saveVSYNC_A;
	uint32_t saveBCLRPAT_A;
	uint32_t saveDSPASTRIDE;
	uint32_t saveDSPASIZE;
	uint32_t saveDSPAPOS;
	uint32_t saveDSPABASE;
	uint32_t saveDSPASURF;
	uint32_t saveDSPATILEOFF;
	uint32_t savePFIT_PGM_RATIOS;
	uint32_t saveBLC_PWM_CTL;
	uint32_t saveBLC_PWM_CTL2;
	uint32_t saveFPB0;
	uint32_t saveFPB1;
	uint32_t saveDPLL_B;
	uint32_t saveDPLL_B_MD;
	uint32_t saveHTOTAL_B;
	uint32_t saveHBLANK_B;
	uint32_t saveHSYNC_B;
	uint32_t saveVTOTAL_B;
	uint32_t saveVBLANK_B;
	uint32_t saveVSYNC_B;
	uint32_t saveBCLRPAT_B;
 	uint32_t saveDSPBSTRIDE;
	uint32_t saveDSPBSIZE;
	uint32_t saveDSPBPOS;
	uint32_t saveDSPBBASE;
	uint32_t saveDSPBSURF;
	uint32_t saveDSPBTILEOFF;
	uint32_t saveVCLK_DIVISOR_VGA0;
	uint32_t saveVCLK_DIVISOR_VGA1;
	uint32_t saveVCLK_POST_DIV;
	uint32_t saveVGACNTRL;
	uint32_t saveADPA;
	uint32_t saveLVDS;
	uint32_t saveLVDSPP_ON;
	uint32_t saveLVDSPP_OFF;
	uint32_t saveDVOA;
	uint32_t saveDVOB;
	uint32_t saveDVOC;
	uint32_t savePP_ON;
	uint32_t savePP_OFF;
	uint32_t savePP_CONTROL;
	uint32_t savePP_CYCLE;
	uint32_t savePFIT_CONTROL;
	uint32_t save_palette_a[256];
	uint32_t save_palette_b[256];
	uint32_t saveFBC_CFB_BASE;
	uint32_t saveFBC_LL_BASE;
	uint32_t saveFBC_CONTROL;
	uint32_t saveFBC_CONTROL2;
	uint32_t saveIER;
	uint32_t saveIIR;
	uint32_t saveIMR;
	uint32_t saveD_STATE;
	uint32_t saveCG_2D_DIS;
	uint32_t saveMI_ARB_STATE;
	uint32_t savePIPEASTAT;
	uint32_t savePIPEBSTAT;
	uint32_t saveCACHE_MODE_0;
	uint32_t saveSWF0[16];
	uint32_t saveSWF1[16];
	uint32_t saveSWF2[3];
	uint8_t saveMSR;
	uint8_t saveSR[8];
	uint8_t saveGR[25];
	uint8_t saveAR_INDEX;
	uint8_t saveAR[21];
	uint8_t saveDACMASK;
	uint8_t saveDACDATA[256*3]; /* 256 3-byte colors */
	uint8_t saveCR[37];
} s3_i915_private_t;

struct drm_i915_error_state {
	u32 eir;
	u32 pgtbl_er;
	u32 pipeastat;
	u32 pipebstat;
	u32 ipeir;
	u32 ipehr;
	u32 instdone;
	u32 acthd;
	u32 instpm;
	u32 instps;
	u32 instdone1;
	u32 seqno;
	struct timeval time;
};

typedef struct drm_i915_private {
	struct drm_device *dev;

	drm_local_map_t *sarea;
	drm_local_map_t *mmio_map;

	drm_i915_sarea_t *sarea_priv;
	drm_i915_ring_buffer_t ring;

 	drm_dma_handle_t *status_page_dmah;
	void *hw_status_page;
	dma_addr_t dma_status_page;
	uint32_t counter;
	unsigned int status_gfx_addr;
	drm_local_map_t hws_map;
	struct drm_gem_object *hws_obj;
	
	unsigned int cpp;
	int back_offset;
	int front_offset;
	int current_page;
	int page_flipping;

	wait_queue_head_t irq_queue;
	atomic_t irq_received;
        /** Protects user_irq_refcount and irq_mask_reg */
        spinlock_t user_irq_lock;
        /** Refcount for i915_user_irq_get() versus i915_user_irq_put(). */
        int user_irq_refcount;
        /** Cached value of IMR to avoid reads in updating the bitfield */
        int irq_mask_reg;
	uint32_t pipestat[2];
	/** splitted irq regs for graphics and display engine on IGDNG,
	irq_mask_reg is still used for display irq. */
	u32 gt_irq_mask_reg;
	u32 gt_irq_enable_reg;
	u32 de_irq_enable_reg;

	int tex_lru_log_granularity;
	int allow_batchbuffer;
	struct mem_block *agp_heap;
	unsigned int sr01, adpa, ppcr, dvob, dvoc, lvds;
	int vblank_pipe;

	spinlock_t error_lock;
	struct drm_i915_error_state *first_error;

	struct {
		struct drm_mm gtt_space;

		drm_local_map_t gtt_mapping;
		/**
		 * List of objects currently involved in rendering from the
		 * ringbuffer.
		 *
		 * A reference is held on the buffer while on this list.
		 */
		struct list_head active_list;

		/**
		 * List of objects which are not in the ringbuffer but which
		 * still have a write_domain which needs to be flushed before
		 * unbinding.
		 *
		 * A reference is held on the buffer while on this list.
		 */
		struct list_head flushing_list;

		/**
		 * LRU list of objects which are not in the ringbuffer and
		 * are ready to unbind, but are still in the GTT.
		 *
		 * A reference is not held on the buffer while on this list,
		 * as merely being GTT-bound shouldn't prevent its being
		 * freed, and we'll pull it off the list in the free path.
		 */
		struct list_head inactive_list;

		/**
		 * List of breadcrumbs associated with GPU requests currently
		 * outstanding.
		 */
		struct list_head request_list;

		uint32_t next_gem_seqno;

		/**
		 * Waiting sequence number, if any
		 */
		uint32_t waiting_gem_seqno;

		/**
		 * Last seq seen at irq time
		 */
		uint32_t irq_gem_seqno;

		/**
		 * Flag if the X Server, and thus DRM, is not currently in
		 * control of the device.
		 *
		 * This is set between LeaveVT and EnterVT.  It needs to be
		 * replaced with a semaphore.  It also needs to be
		 * transitioned away from for kernel modesetting.
		 */
		int suspended;

		/**
		 * Flag if the hardware appears to be wedged.
		 *
		 * This is set when attempts to idle the device timeout.
		 * It prevents command submission from occuring and makes
		 * every pending request fail
		 */
		int wedged;

		/** Bit 6 swizzling required for X tiling */
		uint32_t bit_6_swizzle_x;
		/** Bit 6 swizzling required for Y tiling */
		uint32_t bit_6_swizzle_y;
	} mm;

} drm_i915_private_t;

struct drm_track {
	struct drm_track *next, *prev;
	caddr_t contain_ptr;
	struct drm_gem_object *obj;
	uint32_t name;
	uint64_t offset;
	
};

/** driver private structure attached to each drm_gem_object */
struct drm_i915_gem_object {
	/** This object's place on the active/flushing/inactive lists */
	struct list_head list;

	struct drm_gem_object *obj;

	/** Current space allocated to this object in the GTT, if any. */
	struct drm_mm_node *gtt_space;


	/**
	 * This is set if the object is on the active or flushing lists
	 * (has pending rendering), and is not set if it's on inactive (ready
	 * to be unbound).
	 */
	int active;

	/**
	 * This is set if the object has been written to since last bound
	 * to the GTT
	 */
	int dirty;

	/** AGP memory structure for our GTT binding. */
	int	agp_mem;

	caddr_t *page_list;

	pfn_t	*pfnarray;
	/**
	 * Current offset of the object in GTT space.
	 *
	 * This is the same as gtt_space->start
	 */
	uint32_t gtt_offset;

	/** Boolean whether this object has a valid gtt offset. */
	int gtt_bound;

	/** How many users have pinned this object in GTT space */
	int pin_count;

	/** Breadcrumb of last rendering to the buffer. */
	uint32_t last_rendering_seqno;

	/** Current tiling mode for the object. */
	uint32_t tiling_mode;
	uint32_t stride;
	/**
	 * Flagging of which individual pages are valid in GEM_DOMAIN_CPU when
	 * GEM_DOMAIN_CPU is not in the object's read domain.
	 */
	uint8_t *page_cpu_valid;
	/** User space pin count and filp owning the pin */
	uint32_t user_pin_count;
	struct drm_file *pin_filp;
	/**
	 * Used for checking the object doesn't appear more than once
	 * in an execbuffer object list.
	 */
	int in_execbuffer;
};

/**
 * Request queue structure.
 *
 * The request queue allows us to note sequence numbers that have been emitted
 * and may be associated with active buffers to be retired.
 *
 * By keeping this list, we can avoid having to do questionable
 * sequence-number comparisons on buffer last_rendering_seqnos, and associate
 * an emission time with seqnos for tracking how far ahead of the GPU we are.
 */
struct drm_i915_gem_request {
	struct list_head list;

	/** GEM sequence number associated with this request. */
	uint32_t seqno;

	/** Time at which this request was emitted, in jiffies. */
	unsigned long emitted_jiffies;

	/** Cache domains that were flushed at the start of the request. */
	uint32_t flush_domains;

};

struct drm_i915_file_private {
	struct {
		uint32_t last_gem_seqno;
		uint32_t last_gem_throttle_seqno;
	} mm;
};


enum intel_chip_family {
	CHIP_I8XX = 0x01,
	CHIP_I9XX = 0x02,
	CHIP_I915 = 0x04,
	CHIP_I965 = 0x08,
};

extern drm_ioctl_desc_t i915_ioctls[];
extern int i915_max_ioctl;
extern void i915_save_display(struct drm_device *dev);
extern void i915_restore_display(struct drm_device *dev);

				/* i915_dma.c */
extern void i915_kernel_lost_context(drm_device_t * dev);
extern int i915_driver_load(struct drm_device *, unsigned long flags);
extern int i915_driver_unload(struct drm_device *dev);
extern int i915_driver_open(drm_device_t * dev, drm_file_t *file_priv);
extern void i915_driver_lastclose(drm_device_t * dev);
extern void i915_driver_preclose(drm_device_t * dev, drm_file_t *filp);
extern void i915_driver_postclose(drm_device_t * dev,
		    struct drm_file *file_priv);
extern int i915_driver_device_is_agp(drm_device_t * dev);
extern long i915_compat_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg);
extern int i915_emit_box(struct drm_device *dev,
			struct drm_clip_rect __user *boxes,
			int i, int DR1, int DR4);
extern void i915_emit_breadcrumb(struct drm_device *dev);
extern void i915_emit_mi_flush(drm_device_t *dev, uint32_t flush);
extern void i915_handle_error(struct drm_device *dev);

/* i915_irq.c */
extern int i915_irq_emit(DRM_IOCTL_ARGS);
extern int i915_irq_wait(DRM_IOCTL_ARGS);

extern int i915_enable_vblank(struct drm_device *dev, int crtc);
extern void i915_disable_vblank(struct drm_device *dev, int crtc);
extern u32 i915_get_vblank_counter(struct drm_device *dev, int crtc);
extern u32 gm45_get_vblank_counter(struct drm_device *dev, int crtc);
extern irqreturn_t i915_driver_irq_handler(DRM_IRQ_ARGS);
extern int i915_driver_irq_preinstall(drm_device_t * dev);
extern void i915_driver_irq_postinstall(drm_device_t * dev);
extern void i915_driver_irq_uninstall(drm_device_t * dev);
extern int i915_emit_irq(drm_device_t * dev);
extern int i915_vblank_swap(DRM_IOCTL_ARGS);
extern void i915_user_irq_on(drm_device_t * dev);
extern void i915_user_irq_off(drm_device_t * dev);
extern int i915_vblank_pipe_set(DRM_IOCTL_ARGS);
extern int i915_vblank_pipe_get(DRM_IOCTL_ARGS);

/* i915_mem.c */
extern int i915_mem_alloc(DRM_IOCTL_ARGS);
extern int i915_mem_free(DRM_IOCTL_ARGS);
extern int i915_mem_init_heap(DRM_IOCTL_ARGS);
extern int i915_mem_destroy_heap(DRM_IOCTL_ARGS);
extern void i915_mem_takedown(struct mem_block **heap);
extern void i915_mem_release(drm_device_t * dev,
			     drm_file_t *filp, struct mem_block *heap);
extern struct mem_block **get_heap(drm_i915_private_t *, int);
extern struct mem_block *find_block_by_proc(struct mem_block *, drm_file_t *);
extern void mark_block(drm_device_t *, struct mem_block *, int);
extern void free_block(struct mem_block *);

/* i915_gem.c */
int i915_gem_init_ioctl(DRM_IOCTL_ARGS);
int i915_gem_create_ioctl(DRM_IOCTL_ARGS);
int i915_gem_pread_ioctl(DRM_IOCTL_ARGS);
int i915_gem_pwrite_ioctl(DRM_IOCTL_ARGS);
int i915_gem_mmap_ioctl(DRM_IOCTL_ARGS);
int i915_gem_set_domain_ioctl(DRM_IOCTL_ARGS);
int i915_gem_sw_finish_ioctl(DRM_IOCTL_ARGS);
int i915_gem_execbuffer(DRM_IOCTL_ARGS);
int i915_gem_pin_ioctl(DRM_IOCTL_ARGS);
int i915_gem_unpin_ioctl(DRM_IOCTL_ARGS);
int i915_gem_busy_ioctl(DRM_IOCTL_ARGS);
int i915_gem_throttle_ioctl(DRM_IOCTL_ARGS);
int i915_gem_entervt_ioctl(DRM_IOCTL_ARGS);
int i915_gem_leavevt_ioctl(DRM_IOCTL_ARGS);
int i915_gem_set_tiling(DRM_IOCTL_ARGS);
int i915_gem_get_tiling(DRM_IOCTL_ARGS);
int i915_gem_get_aperture_ioctl(DRM_IOCTL_ARGS);
void i915_gem_load(struct drm_device *dev);
int i915_gem_init_object(struct drm_gem_object *obj);
void i915_gem_free_object(struct drm_gem_object *obj);
int i915_gem_object_pin(struct drm_gem_object *obj, uint32_t alignment);
void i915_gem_object_unpin(struct drm_gem_object *obj);
int i915_gem_object_unbind(struct drm_gem_object *obj, uint32_t type);
void i915_gem_lastclose(struct drm_device *dev);
uint32_t i915_get_gem_seqno(struct drm_device *dev);
void i915_gem_retire_requests(struct drm_device *dev);
void i915_gem_retire_work_handler(void *dev);
void i915_gem_clflush_object(struct drm_gem_object *obj);
int i915_gem_init_ringbuffer(struct drm_device *dev);

/* i915_gem_tiling.c */
void i915_gem_detect_bit_6_swizzle(struct drm_device *dev);

/* i915_gem_debug.c */
void i915_gem_command_decode(uint32_t *data, int count, 
				uint32_t hw_offset, struct drm_device *dev);
/* i915_gem_regdump.c */
int i915_reg_dump_show(struct drm_device *dev, void *v);
#ifdef I915_HAVE_FENCE
/* i915_fence.c */


extern void i915_fence_handler(drm_device_t *dev);
extern int i915_fence_emit_sequence(drm_device_t *dev, uint32_t class,
				    uint32_t flags,
				    uint32_t *sequence, 
				    uint32_t *native_type);
extern void i915_poke_flush(drm_device_t *dev, uint32_t class);
extern int i915_fence_has_irq(drm_device_t *dev, uint32_t class, uint32_t flags);
#endif

#ifdef I915_HAVE_BUFFER
/* i915_buffer.c */
extern drm_ttm_backend_t *i915_create_ttm_backend_entry(drm_device_t *dev);
extern int i915_fence_types(drm_buffer_object_t *bo, uint32_t *class, uint32_t *type);
extern int i915_invalidate_caches(drm_device_t *dev, uint32_t buffer_flags);
extern int i915_init_mem_type(drm_device_t *dev, uint32_t type,
			       drm_mem_type_manager_t *man);
extern uint32_t i915_evict_mask(drm_buffer_object_t *bo);
extern int i915_move(drm_buffer_object_t *bo, int evict,
	      	int no_wait, drm_bo_mem_reg_t *new_mem);

#endif

#define I915_READ(reg)          DRM_READ32(dev_priv->mmio_map, (reg))
#define I915_WRITE(reg,val)     DRM_WRITE32(dev_priv->mmio_map, (reg), (val))
#define I915_READ16(reg) 	DRM_READ16(dev_priv->mmio_map, (reg))
#define I915_WRITE16(reg,val)	DRM_WRITE16(dev_priv->mmio_map, (reg), (val))
#define	S3_READ(reg)	\
	*(uint32_t volatile *)((uintptr_t)s3_priv->saveAddr + (reg))
#define	S3_WRITE(reg, val) \
	*(uint32_t volatile *)((uintptr_t)s3_priv->saveAddr + (reg)) = (val)

#define I915_VERBOSE 0 
#define I915_RING_VALIDATE 0

#if I915_RING_VALIDATE
void i915_ring_validate(struct drm_device *dev, const char *func, int line);
#define I915_RING_DO_VALIDATE(dev) i915_ring_validate(dev, __FUNCTION__, __LINE__)
#else
#define I915_RING_DO_VALIDATE(dev)
#endif

#define RING_LOCALS	unsigned int outring, ringmask, outcount; \
                        volatile unsigned char *virt;


#define I915_RING_VALIDATE 0

#if I915_RING_VALIDATE
void i915_ring_validate(struct drm_device *dev, const char *func, int line);
#define I915_RING_DO_VALIDATE(dev) i915_ring_validate(dev, __FUNCTION__, __LINE__)
#else
#define I915_RING_DO_VALIDATE(dev)
#endif

#if I915_VERBOSE
#define BEGIN_LP_RING(n) do {				\
	DRM_DEBUG("BEGIN_LP_RING(%d)\n", (n));		\
	DRM_DEBUG("dev_priv->ring.virtual_start (%lx)\n", (dev_priv->ring.virtual_start));		\
	I915_RING_DO_VALIDATE(dev);			\
	if (dev_priv->ring.space < (n)*4)			\
		(void) i915_wait_ring(dev, (n)*4, __FUNCTION__);		\
	outcount = 0;					\
	outring = dev_priv->ring.tail;			\
	ringmask = dev_priv->ring.tail_mask;		\
	virt = dev_priv->ring.virtual_start;		\
} while (*"\0")
#else
#define BEGIN_LP_RING(n) do {				\
	I915_RING_DO_VALIDATE(dev);			\
	if (dev_priv->ring.space < (n)*4)			\
		(void) i915_wait_ring(dev, (n)*4, __FUNCTION__);		\
	outcount = 0;					\
	outring = dev_priv->ring.tail;			\
	ringmask = dev_priv->ring.tail_mask;		\
	virt = dev_priv->ring.virtual_start;		\
} while (*"\0")
#endif

#if I915_VERBOSE
#define OUT_RING(n) do {					\
	DRM_DEBUG("   OUT_RING %x\n", (int)(n));	\
	*(volatile unsigned int *)(void *)(virt + outring) = (n);		\
        outcount++;						\
	outring += 4;						\
	outring &= ringmask;					\
} while (*"\0")
#else
#define OUT_RING(n) do {					\
	*(volatile unsigned int *)(void *)(virt + outring) = (n);		\
        outcount++;						\
	outring += 4;						\
	outring &= ringmask;					\
} while (*"\0")
#endif

#if I915_VERBOSE
#define ADVANCE_LP_RING() do {						\
	DRM_DEBUG("ADVANCE_LP_RING %x\n", outring);	\
	I915_RING_DO_VALIDATE(dev);					\
	dev_priv->ring.tail = outring;					\
	dev_priv->ring.space -= outcount * 4;				\
	I915_WRITE(PRB0_TAIL, outring);			\
} while (*"\0")
#else
#define ADVANCE_LP_RING() do {						\
	I915_RING_DO_VALIDATE(dev);					\
	dev_priv->ring.tail = outring;					\
	dev_priv->ring.space -= outcount * 4;				\
	I915_WRITE(PRB0_TAIL, outring);			\
} while (*"\0")
#endif

extern int i915_wait_ring(drm_device_t * dev, int n, const char *caller);

/* Extended config space */
#define LBB 0xf4
#define GDRST 0xc0
#define GDRST_FULL	(0<<2)
#define GDRST_RENDER	(1<<2)
#define GDRST_MEDIA	(3<<2)

/* VGA stuff */

#define VGA_ST01_MDA 0x3ba
#define VGA_ST01_CGA 0x3da

#define VGA_MSR_WRITE 0x3c2
#define VGA_MSR_READ 0x3cc
#define   VGA_MSR_MEM_EN (1<<1)
#define   VGA_MSR_CGA_MODE (1<<0)

#define VGA_SR_INDEX 0x3c4
#define VGA_SR_DATA 0x3c5

#define VGA_AR_INDEX 0x3c0
#define   VGA_AR_VID_EN (1<<5)
#define VGA_AR_DATA_WRITE 0x3c0
#define VGA_AR_DATA_READ 0x3c1

#define VGA_GR_INDEX 0x3ce
#define VGA_GR_DATA 0x3cf
/* GR05 */
#define   VGA_GR_MEM_READ_MODE_SHIFT 3
#define     VGA_GR_MEM_READ_MODE_PLANE 1
/* GR06 */
#define   VGA_GR_MEM_MODE_MASK 0xc
#define   VGA_GR_MEM_MODE_SHIFT 2
#define   VGA_GR_MEM_A0000_AFFFF 0
#define   VGA_GR_MEM_A0000_BFFFF 1
#define   VGA_GR_MEM_B0000_B7FFF 2
#define   VGA_GR_MEM_B0000_BFFFF 3

#define VGA_DACMASK 0x3c6
#define VGA_DACRX 0x3c7
#define VGA_DACWX 0x3c8
#define VGA_DACDATA 0x3c9

#define VGA_CR_INDEX_MDA 0x3b4
#define VGA_CR_DATA_MDA 0x3b5
#define VGA_CR_INDEX_CGA 0x3d4
#define VGA_CR_DATA_CGA 0x3d5


#define GFX_OP_USER_INTERRUPT 		((0<<29)|(2<<23))
#define GFX_OP_BREAKPOINT_INTERRUPT	((0<<29)|(1<<23))
#define CMD_REPORT_HEAD			(7<<23)
#define CMD_STORE_DWORD_IDX		((0x21<<23) | 0x1)
#define CMD_OP_BATCH_BUFFER  ((0x0<<29)|(0x30<<23)|0x1)

#define INST_PARSER_CLIENT   0x00000000
#define INST_OP_FLUSH        0x02000000
#define INST_FLUSH_MAP_CACHE 0x00000001

#define MI_INSTR(opcode, flags) (((opcode) << 23) | (flags))
#define MI_USER_INTERRUPT       MI_INSTR(2, (0 << 29))
#define MI_FLUSH         (0x04 << 23)
#define MI_NO_WRITE_FLUSH    (1 << 2)
#define MI_READ_FLUSH        (1 << 0)
#define MI_EXE_FLUSH         (1 << 1)
#define MI_STORE_DWORD_INDEX   MI_INSTR(0x21, 1)
#define	MI_STORE_DWORD_INDEX_SHIFT 2

#define BB1_START_ADDR_MASK   (~0x7)
#define BB1_PROTECTED         (1<<0)
#define BB1_UNPROTECTED       (0<<0)
#define BB2_END_ADDR_MASK     (~0x7)

#define	I915REG_PGTBL_CTRL	0x2020
#define IPEIR			0x02088
#define HWSTAM			0x02098
#define IIR			0x020a4
#define IMR		 	0x020a8
#define IER			0x020a0
#define INSTPM	      		0x020c0
#define ACTHD			0x020c8
#define PIPEASTAT		0x70024
#define PIPEBSTAT		0x71024
#define ACTHD_I965		0x02074
#define HWS_PGA			0x02080
#define IPEIR_I965	0x02064
#define IPEHR_I965	0x02068
#define INSTDONE_I965	0x0206c
#define INSTPS		0x02070 /* 965+ only */
#define INSTDONE1	0x0207c /* 965+ only */
#define IPEHR		0x0208c
#define INSTDONE	0x02090
#define EIR		0x020b0
#define EMR		0x020b4
#define ESR		0x020b8
#define   GM45_ERROR_PAGE_TABLE				(1<<5)
#define   GM45_ERROR_MEM_PRIV				(1<<4)
#define   I915_ERROR_PAGE_TABLE				(1<<4)
#define   GM45_ERROR_CP_PRIV				(1<<3)
#define   I915_ERROR_MEMORY_REFRESH			(1<<1)
#define   I915_ERROR_INSTRUCTION			(1<<0)

#define PIPEA_FRMCOUNT_GM45    0x70040
#define PIPEA_FLIPCOUNT_GM45   0x70044
#define PIPEB_FRMCOUNT_GM45    0x71040
#define PIPEB_FLIPCOUNT_GM45   0x71044

#define PIPE_VBLANK_INTERRUPT_ENABLE	(1UL<<17)
#define I915_VBLANK_CLEAR		(1UL<<1)

#define SRX_INDEX		0x3c4
#define SRX_DATA		0x3c5
#define SR01			1
#define SR01_SCREEN_OFF 	(1<<5)

#define PPCR			0x61204
#define PPCR_ON			(1<<0)

#define DVOB			0x61140
#define DVOB_ON			(1<<31)
#define DVOC			0x61160
#define DVOC_ON			(1<<31)
#define LVDS			0x61180
#define LVDS_ON			(1<<31)

#define ADPA			0x61100
#define ADPA_DPMS_MASK		(~(3<<10))
#define ADPA_DPMS_ON		(0<<10)
#define ADPA_DPMS_SUSPEND	(1<<10)
#define ADPA_DPMS_STANDBY	(2<<10)
#define ADPA_DPMS_OFF		(3<<10)

#ifdef NOPID
#undef NOPID
#endif
#define NOPID                   0x2094
#define LP_RING     		0x2030
#define HP_RING     		0x2040
#define TAIL_ADDR		0x001FFFF8
#define HEAD_WRAP_COUNT     	0xFFE00000
#define HEAD_WRAP_ONE       	0x00200000
#define HEAD_ADDR           	0x001FFFFC
#define RING_START     		0x08
#define START_ADDR          	0x0xFFFFF000
#define RING_LEN       		0x0C
#define RING_NR_PAGES       	0x001FF000
#define RING_REPORT_MASK    	0x00000006
#define RING_REPORT_64K     	0x00000002
#define RING_REPORT_128K    	0x00000004
#define RING_NO_REPORT      	0x00000000
#define RING_VALID_MASK     	0x00000001
#define RING_VALID          	0x00000001
#define RING_INVALID        	0x00000000
#define PGTBL_ER		0x02024
#define PRB0_TAIL              0x02030
#define PRB0_HEAD              0x02034
#define PRB0_START		0x02038
#define PRB0_CTL               0x0203c
#define GFX_OP_SCISSOR         ((0x3<<29)|(0x1c<<24)|(0x10<<19))
#define SC_UPDATE_SCISSOR       (0x1<<1)
#define SC_ENABLE_MASK          (0x1<<0)
#define SC_ENABLE               (0x1<<0)

#define GFX_OP_SCISSOR_INFO    ((0x3<<29)|(0x1d<<24)|(0x81<<16)|(0x1))
#define SCI_YMIN_MASK      (0xffff<<16)
#define SCI_XMIN_MASK      (0xffff<<0)
#define SCI_YMAX_MASK      (0xffff<<16)
#define SCI_XMAX_MASK      (0xffff<<0)

#define GFX_OP_SCISSOR_ENABLE	 ((0x3<<29)|(0x1c<<24)|(0x10<<19))
#define GFX_OP_SCISSOR_RECT	 ((0x3<<29)|(0x1d<<24)|(0x81<<16)|1)
#define GFX_OP_COLOR_FACTOR      ((0x3<<29)|(0x1d<<24)|(0x1<<16)|0x0)
#define GFX_OP_STIPPLE           ((0x3<<29)|(0x1d<<24)|(0x83<<16))
#define GFX_OP_MAP_INFO          ((0x3<<29)|(0x1d<<24)|0x4)
#define GFX_OP_DESTBUFFER_VARS   ((0x3<<29)|(0x1d<<24)|(0x85<<16)|0x0)
#define GFX_OP_DRAWRECT_INFO     ((0x3<<29)|(0x1d<<24)|(0x80<<16)|(0x3))

#define GFX_OP_DRAWRECT_INFO_I965  ((0x7900<<16)|0x2)

#define SRC_COPY_BLT_CMD                ((2<<29)|(0x43<<22)|4)
#define XY_SRC_COPY_BLT_CMD		((2<<29)|(0x53<<22)|6)
#define XY_SRC_COPY_BLT_WRITE_ALPHA	(1<<21)
#define XY_SRC_COPY_BLT_WRITE_RGB	(1<<20)
#define XY_SRC_COPY_BLT_SRC_TILED	(1<<15)
#define XY_SRC_COPY_BLT_DST_TILED	(1<<11)

#define MI_BATCH_BUFFER 	((0x30<<23)|1)
#define MI_BATCH_BUFFER_START 	(0x31<<23)
#define MI_BATCH_BUFFER_END 	(0xA<<23)
#define MI_BATCH_NON_SECURE	(1)

#define MI_BATCH_NON_SECURE_I965 (1<<8)

#define MI_WAIT_FOR_EVENT       ((0x3<<23))
#define MI_WAIT_FOR_PLANE_B_FLIP      (1<<6)
#define MI_WAIT_FOR_PLANE_A_FLIP      (1<<2)
#define MI_WAIT_FOR_PLANE_A_SCANLINES (1<<1)

#define MI_LOAD_SCAN_LINES_INCL  ((0x12<<23))

#define CMD_OP_DISPLAYBUFFER_INFO ((0x0<<29)|(0x14<<23)|2)
#define ASYNC_FLIP                (1<<22)
#define DISPLAY_PLANE_A           (0<<20)
#define DISPLAY_PLANE_B           (1<<20)

#define CMD_OP_DESTBUFFER_INFO	 ((0x3<<29)|(0x1d<<24)|(0x8e<<16)|1)

/**
 * Reads a dword out of the status page, which is written to from the command
 * queue by automatic updates, MI_REPORT_HEAD, MI_STORE_DATA_INDEX, or
 * MI_STORE_DATA_IMM.
 *
 * The following dwords have a reserved meaning:
 * 0x00: ISR copy, updated when an ISR bit not set in the HWSTAM changes.
 * 0x04: ring 0 head pointer
 * 0x05: ring 1 head pointer (915-class)
 * 0x06: ring 2 head pointer (915-class)
 * 0x10-0x1b: Context status DWords (GM45)
 * 0x1f: Last written status offset. (GM45)
 *
 * The area from dword 0x20 to 0x3ff is available for driver usage.
 */
#define READ_HWSP(dev_priv, reg)  (((volatile u32*)(dev_priv->hw_status_page))[reg])
#define READ_BREADCRUMB(dev_priv) READ_HWSP(dev_priv, I915_BREADCRUMB_INDEX)
#define I915_GEM_HWS_INDEX		0x20
#define I915_BREADCRUMB_INDEX		0x21

/*
 * add here for S3 support
 */
#define DPLL_A          0x06014
#define DPLL_B          0x06018
# define DPLL_VCO_ENABLE                        0x80000000 /* (1 << 31) */
# define DPLL_DVO_HIGH_SPEED                    (1 << 30)
# define DPLL_SYNCLOCK_ENABLE                   (1 << 29)
# define DPLL_VGA_MODE_DIS                      (1 << 28)
# define DPLLB_MODE_DAC_SERIAL                  (1 << 26) /* i915 */
# define DPLLB_MODE_LVDS                        (2 << 26) /* i915 */
# define DPLL_MODE_MASK                         (3 << 26)
# define DPLL_DAC_SERIAL_P2_CLOCK_DIV_10        (0 << 24) /* i915 */
# define DPLL_DAC_SERIAL_P2_CLOCK_DIV_5         (1 << 24) /* i915 */
# define DPLLB_LVDS_P2_CLOCK_DIV_14             (0 << 24) /* i915 */
# define DPLLB_LVDS_P2_CLOCK_DIV_7              (1 << 24) /* i915 */
# define DPLL_P2_CLOCK_DIV_MASK                 0x03000000 /* i915 */
# define DPLL_FPA01_P1_POST_DIV_MASK            0x00ff0000 /* i915 */

/**
 *  The i830 generation, in DAC/serial mode, defines p1 as two plus this
 * bitfield, or just 2 if PLL_P1_DIVIDE_BY_TWO is set.
 */
# define DPLL_FPA01_P1_POST_DIV_MASK_I830       0x001f0000
/**
 * The i830 generation, in LVDS mode, defines P1 as the bit number set within
 * this field (only one bit may be set).
 */
# define DPLL_FPA01_P1_POST_DIV_MASK_I830_LVDS  0x003f0000
# define DPLL_FPA01_P1_POST_DIV_SHIFT           16
# define PLL_P2_DIVIDE_BY_4                     (1 << 23) /* i830, required in DVO non-gang */
# define PLL_P1_DIVIDE_BY_TWO                   (1 << 21) /* i830 */
# define PLL_REF_INPUT_DREFCLK                  (0 << 13)
# define PLL_REF_INPUT_TVCLKINA                 (1 << 13) /* i830 */
# define PLL_REF_INPUT_TVCLKINBC                (2 << 13) /* SDVO TVCLKIN */
# define PLLB_REF_INPUT_SPREADSPECTRUMIN        (3 << 13)
# define PLL_REF_INPUT_MASK                     (3 << 13)
# define PLL_LOAD_PULSE_PHASE_SHIFT             9

/* IGDNG */
#define PLL_REF_SDVO_HDMI_MULTIPLIER_SHIFT	9
#define PLL_REF_SDVO_HDMI_MULTIPLIER_MASK	(7 << 9)
#define PLL_REF_SDVO_HDMI_MULTIPLIER(x)		(((x)-1) << 9)
#define DPLL_FPA1_P1_POST_DIV_SHIFT		0
#define DPLL_FPA1_P1_POST_DIV_MASK		0xff

/*
 * Parallel to Serial Load Pulse phase selection.
 * Selects the phase for the 10X DPLL clock for the PCIe
 * digital display port. The range is 4 to 13; 10 or more
 * is just a flip delay. The default is 6
 */
# define PLL_LOAD_PULSE_PHASE_MASK              (0xf << PLL_LOAD_PULSE_PHASE_SHIFT)
# define DISPLAY_RATE_SELECT_FPA1               (1 << 8)

/**
 * SDVO multiplier for 945G/GM. Not used on 965.
 *
 * \sa DPLL_MD_UDI_MULTIPLIER_MASK
 */
# define SDVO_MULTIPLIER_MASK                   0x000000ff
# define SDVO_MULTIPLIER_SHIFT_HIRES            4
# define SDVO_MULTIPLIER_SHIFT_VGA              0

/** @defgroup DPLL_MD
 * @{
 */
/** Pipe A SDVO/UDI clock multiplier/divider register for G965. */
#define DPLL_A_MD               0x0601c
/** Pipe B SDVO/UDI clock multiplier/divider register for G965. */
#define DPLL_B_MD               0x06020
/**
 * UDI pixel divider, controlling how many pixels are stuffed into a packet.
 *
 * Value is pixels minus 1.  Must be set to 1 pixel for SDVO.
 */
# define DPLL_MD_UDI_DIVIDER_MASK               0x3f000000
# define DPLL_MD_UDI_DIVIDER_SHIFT              24
/** UDI pixel divider for VGA, same as DPLL_MD_UDI_DIVIDER_MASK. */
# define DPLL_MD_VGA_UDI_DIVIDER_MASK           0x003f0000
# define DPLL_MD_VGA_UDI_DIVIDER_SHIFT          16
/**
 * SDVO/UDI pixel multiplier.
 *
 * SDVO requires that the bus clock rate be between 1 and 2 Ghz, and the bus
 * clock rate is 10 times the DPLL clock.  At low resolution/refresh rate
 * modes, the bus rate would be below the limits, so SDVO allows for stuffing
 * dummy bytes in the datastream at an increased clock rate, with both sides of
 * the link knowing how many bytes are fill.
 *
 * So, for a mode with a dotclock of 65Mhz, we would want to double the clock
 * rate to 130Mhz to get a bus rate of 1.30Ghz.  The DPLL clock rate would be
 * set to 130Mhz, and the SDVO multiplier set to 2x in this register and
 * through an SDVO command.
 *
 * This register field has values of multiplication factor minus 1, with
 * a maximum multiplier of 5 for SDVO.
 */
# define DPLL_MD_UDI_MULTIPLIER_MASK            0x00003f00
# define DPLL_MD_UDI_MULTIPLIER_SHIFT           8
/** SDVO/UDI pixel multiplier for VGA, same as DPLL_MD_UDI_MULTIPLIER_MASK.
 * This best be set to the default value (3) or the CRT won't work. No,
 * I don't entirely understand what this does...
 */
# define DPLL_MD_VGA_UDI_MULTIPLIER_MASK        0x0000003f
# define DPLL_MD_VGA_UDI_MULTIPLIER_SHIFT       0
/** @} */

#define DPLL_TEST               0x606c
# define DPLLB_TEST_SDVO_DIV_1                  (0 << 22)
# define DPLLB_TEST_SDVO_DIV_2                  (1 << 22)
# define DPLLB_TEST_SDVO_DIV_4                  (2 << 22)
# define DPLLB_TEST_SDVO_DIV_MASK               (3 << 22)
# define DPLLB_TEST_N_BYPASS                    (1 << 19)
# define DPLLB_TEST_M_BYPASS                    (1 << 18)
# define DPLLB_INPUT_BUFFER_ENABLE              (1 << 16)
# define DPLLA_TEST_N_BYPASS                    (1 << 3)
# define DPLLA_TEST_M_BYPASS                    (1 << 2)
# define DPLLA_INPUT_BUFFER_ENABLE              (1 << 0)

/*
 * Palette registers
 */
#define PALETTE_A               0x0a000
#define PALETTE_B               0x0a800

/* MCH MMIO space */

/*
 * MCHBAR mirror.
 *
 * This mirrors the MCHBAR MMIO space whose location is determined by
 * device 0 function 0's pci config register 0x44 or 0x48 and matches it in
 * every way.  It is not accessible from the CP register read instructions.
 *
 */
#define MCHBAR_MIRROR_BASE	0x10000

/** 915-945 and GM965 MCH register controlling DRAM channel access */
#define DCC			0x10200
#define DCC_ADDRESSING_MODE_SINGLE_CHANNEL		(0 << 0)
#define DCC_ADDRESSING_MODE_DUAL_CHANNEL_ASYMMETRIC	(1 << 0)
#define DCC_ADDRESSING_MODE_DUAL_CHANNEL_INTERLEAVED	(2 << 0)
#define DCC_ADDRESSING_MODE_MASK			(3 << 0)
#define DCC_CHANNEL_XOR_DISABLE				(1 << 10)
#define DCC_CHANNEL_XOR_BIT_17				(1 << 9)

/** 965 MCH register controlling DRAM channel configuration */
#define C0DRB3			0x10206
#define C1DRB3			0x10606

/** GM965 GM45 render standby register */
#define MCHBAR_RENDER_STANDBY	0x111B8

#define FPA0            0x06040
#define FPA1            0x06044
#define FPB0            0x06048
#define FPB1            0x0604c

#define D_STATE         0x6104
#define CG_2D_DIS       0x6200
#define CG_3D_DIS       0x6204

#define MI_ARB_STATE    0x20e4

/*
 * Cache mode 0 reg.
 *  - Manipulating render cache behaviour is central
 *    to the concept of zone rendering, tuning this reg can help avoid
 *    unnecessary render cache reads and even writes (for z/stencil)
 *    at beginning and end of scene.
 *
 * - To change a bit, write to this reg with a mask bit set and the
 * bit of interest either set or cleared.  EG: (BIT<<16) | BIT to set.
 */
#define CACHE_MODE_0   0x2120

/* I830 CRTC registers */
#define HTOTAL_A        0x60000
#define HBLANK_A        0x60004
#define HSYNC_A         0x60008
#define VTOTAL_A        0x6000c
#define VBLANK_A        0x60010
#define VSYNC_A         0x60014
#define PIPEASRC        0x6001c
#define BCLRPAT_A       0x60020
#define VSYNCSHIFT_A    0x60028

#define HTOTAL_B        0x61000
#define HBLANK_B        0x61004
#define HSYNC_B         0x61008
#define VTOTAL_B        0x6100c
#define VBLANK_B        0x61010
#define VSYNC_B         0x61014
#define PIPEBSRC        0x6101c
#define BCLRPAT_B       0x61020
#define VSYNCSHIFT_B    0x61028

#define DSPACNTR                0x70180
#define DSPBCNTR                0x71180
#define DISPLAY_PLANE_ENABLE                    (1<<31)
#define DISPLAY_PLANE_DISABLE                   0
#define DISPPLANE_GAMMA_ENABLE                  (1<<30)
#define DISPPLANE_GAMMA_DISABLE                 0
#define DISPPLANE_PIXFORMAT_MASK                (0xf<<26)
#define DISPPLANE_8BPP                          (0x2<<26)
#define DISPPLANE_15_16BPP                      (0x4<<26)
#define DISPPLANE_16BPP                         (0x5<<26)
#define DISPPLANE_32BPP_NO_ALPHA                (0x6<<26)
#define DISPPLANE_32BPP                         (0x7<<26)
#define DISPPLANE_STEREO_ENABLE                 (1<<25)
#define DISPPLANE_STEREO_DISABLE                0
#define DISPPLANE_SEL_PIPE_MASK                 (1<<24)
#define DISPPLANE_SEL_PIPE_A                    0
#define DISPPLANE_SEL_PIPE_B                    (1<<24)
#define DISPPLANE_SRC_KEY_ENABLE                (1<<22)
#define DISPPLANE_SRC_KEY_DISABLE               0
#define DISPPLANE_LINE_DOUBLE                   (1<<20)
#define DISPPLANE_NO_LINE_DOUBLE                0
#define DISPPLANE_STEREO_POLARITY_FIRST         0
#define DISPPLANE_STEREO_POLARITY_SECOND        (1<<18)
/* plane B only */
#define DISPPLANE_ALPHA_TRANS_ENABLE            (1<<15)
#define DISPPLANE_ALPHA_TRANS_DISABLE           0
#define DISPPLANE_SPRITE_ABOVE_DISPLAYA         0
#define DISPPLANE_SPRITE_ABOVE_OVERLAY          (1)

#define DSPABASE                0x70184
#define DSPASTRIDE              0x70188

#define DSPBBASE                0x71184
#define DSPBADDR                DSPBBASE
#define DSPBSTRIDE              0x71188

#define DSPAKEYVAL              0x70194
#define DSPAKEYMASK             0x70198

#define DSPAPOS                 0x7018C /* reserved */
#define DSPASIZE                0x70190
#define DSPBPOS                 0x7118C
#define DSPBSIZE                0x71190

#define DSPASURF                0x7019C
#define DSPATILEOFF             0x701A4

#define DSPBSURF                0x7119C
#define DSPBTILEOFF             0x711A4

#define PIPEACONF 0x70008
#define PIPEACONF_ENABLE        (1UL<<31)
#define PIPEACONF_DISABLE       0
#define PIPEACONF_DOUBLE_WIDE   (1<<30)
#define I965_PIPECONF_ACTIVE    (1<<30)
#define PIPEACONF_SINGLE_WIDE   0
#define PIPEACONF_PIPE_UNLOCKED 0
#define PIPEACONF_PIPE_LOCKED   (1<<25)
#define PIPEACONF_PALETTE       0
#define PIPEACONF_GAMMA         (1<<24)
#define PIPECONF_FORCE_BORDER   (1<<25)
#define PIPECONF_PROGRESSIVE    (0 << 21)
#define PIPECONF_INTERLACE_W_FIELD_INDICATION   (6 << 21)
#define PIPECONF_INTERLACE_FIELD_0_ONLY         (7 << 21)

#define PIPEBCONF 0x71008
#define PIPEBCONF_ENABLE        (1UL<<31)
#define PIPEBCONF_DISABLE       0
#define PIPEBCONF_DOUBLE_WIDE   (1<<30)
#define PIPEBCONF_DISABLE       0
#define PIPEBCONF_GAMMA         (1<<24)
#define PIPEBCONF_PALETTE       0

#define BLC_PWM_CTL             0x61254
#define BACKLIGHT_MODULATION_FREQ_SHIFT         (17)

#define BLC_PWM_CTL2            0x61250

#define PFIT_CONTROL    0x61230
#define PFIT_PGM_RATIOS 0x61234

/**
 * Indicates that all dependencies of the panel are on:
 *
 * - PLL enabled
 * - pipe enabled
 * - LVDS/DVOB/DVOC on
 */
#define PP_READY                               (1 << 30)
#define PP_SEQUENCE_NONE                       (0 << 28)
#define PP_SEQUENCE_ON                         (1 << 28)
#define PP_SEQUENCE_OFF                        (2 << 28)
#define PP_SEQUENCE_MASK                       0x30000000
#define PP_CONTROL      0x61204
#define POWER_TARGET_ON                        (1 << 0)

#define LVDSPP_ON       0x61208
#define LVDSPP_OFF      0x6120c
#define PP_CYCLE        0x61210

/* Framebuffer compression */
#define FBC_CFB_BASE            0x03200 /* 4k page aligned */
#define FBC_LL_BASE             0x03204 /* 4k page aligned */
#define FBC_CONTROL             0x03208

#define VGACNTRL                0x71400

#define VCLK_DIVISOR_VGA0   0x6000
#define VCLK_DIVISOR_VGA1   0x6004
#define VCLK_POST_DIV       0x6010

/* Framebuffer compression */
#define FBC_CFB_BASE            0x03200 /* 4k page aligned */
#define FBC_LL_BASE             0x03204 /* 4k page aligned */
#define FBC_CONTROL             0x03208
#define   FBC_CTL_EN            (1<<31)
#define   FBC_CTL_PERIODIC      (1<<30)
#define   FBC_CTL_INTERVAL_SHIFT (16)
#define   FBC_CTL_UNCOMPRESSIBLE (1<<14)
#define   FBC_CTL_STRIDE_SHIFT  (5)
#define   FBC_CTL_FENCENO       (1<<0)
#define	FBC_COMMAND             0x0320c
#define   FBC_CMD_COMPRESS      (1<<0)
#define FBC_STATUS              0x03210
#define   FBC_STAT_COMPRESSING  (1<<31)
#define   FBC_STAT_COMPRESSED   (1<<30)
#define   FBC_STAT_MODIFIED     (1<<29)
#define   FBC_STAT_CURRENT_LINE (1<<0)
#define FBC_CONTROL2            0x03214
#define   FBC_CTL_FENCE_DBL     (0<<4)
#define   FBC_CTL_IDLE_IMM      (0<<2)
#define   FBC_CTL_IDLE_FULL     (1<<2)
#define   FBC_CTL_IDLE_LINE     (2<<2)
#define   FBC_CTL_IDLE_DEBUG    (3<<2)
#define   FBC_CTL_CPU_FENCE     (1<<1)
#define   FBC_CTL_PLANEA        (0<<0)
#define   FBC_CTL_PLANEB        (1<<0)
#define FBC_FENCE_OFF           0x0321b

#define FBC_LL_SIZE             (1536)
#define FBC_LL_PAD              (32)

#define	DSPARB                  0x70030

#define PIPEAFRAMEHIGH          0x70040
#define PIPEBFRAMEHIGH		0x71040
#define PIPE_FRAME_HIGH_MASK    0x0000ffff
#define PIPE_FRAME_HIGH_SHIFT   0
#define PIPEAFRAMEPIXEL         0x70044
#define PIPEBFRAMEPIXEL		0x71044

#define PIPE_FRAME_LOW_MASK     0xff000000
#define PIPE_FRAME_LOW_SHIFT    24

/* Interrupt bits:
 */
#define I915_PIPE_CONTROL_NOTIFY_INTERRUPT		(1<<18)
#define I915_DISPLAY_PORT_INTERRUPT			(1<<17)
#define I915_RENDER_COMMAND_PARSER_ERROR_INTERRUPT	(1<<15)
#define I915_GMCH_THERMAL_SENSOR_EVENT_INTERRUPT	(1<<14)
#define I915_HWB_OOM_INTERRUPT				(1<<13) /* binner out of memory */
#define I915_SYNC_STATUS_INTERRUPT			(1<<12)
#define I915_DISPLAY_PLANE_A_FLIP_PENDING_INTERRUPT	(1<<11)
#define I915_DISPLAY_PLANE_B_FLIP_PENDING_INTERRUPT	(1<<10)
#define I915_OVERLAY_PLANE_FLIP_PENDING_INTERRUPT	(1<<9)
#define I915_DISPLAY_PLANE_C_FLIP_PENDING_INTERRUPT	(1<<8)
#define I915_DISPLAY_PIPE_A_VBLANK_INTERRUPT		(1<<7)
#define I915_DISPLAY_PIPE_A_EVENT_INTERRUPT		(1<<6)
#define I915_DISPLAY_PIPE_B_VBLANK_INTERRUPT		(1<<5)
#define I915_DISPLAY_PIPE_B_EVENT_INTERRUPT		(1<<4)
#define I915_DEBUG_INTERRUPT				(1<<2)
#define I915_USER_INTERRUPT				(1<<1)
#define	I915_ASLE_INTERRUPT				(1<<0)

#define I915_FIFO_UNDERRUN_STATUS		(1UL<<31)
#define I915_CRC_ERROR_ENABLE			(1UL<<29)
#define I915_CRC_DONE_ENABLE			(1UL<<28)
#define I915_GMBUS_EVENT_ENABLE			(1UL<<27)
#define I915_VSYNC_INTERRUPT_ENABLE		(1UL<<25)
#define I915_DISPLAY_LINE_COMPARE_ENABLE	(1UL<<24)
#define I915_DPST_EVENT_ENABLE			(1UL<<23)
#define I915_LEGACY_BLC_EVENT_ENABLE		(1UL<<22)
#define I915_ODD_FIELD_INTERRUPT_ENABLE		(1UL<<21)
#define I915_EVEN_FIELD_INTERRUPT_ENABLE	(1UL<<20)
#define PIPE_START_VBLANK_INTERRUPT_ENABLE	(1UL<<18)	/* 965 or later */
#define I915_VBLANK_INTERRUPT_ENABLE		(1UL<<17)
#define I915_OVERLAY_UPDATED_ENABLE		(1UL<<16)
#define I915_CRC_ERROR_INTERRUPT_STATUS		(1UL<<13)
#define I915_CRC_DONE_INTERRUPT_STATUS		(1UL<<12)
#define I915_GMBUS_INTERRUPT_STATUS		(1UL<<11)
#define I915_VSYNC_INTERRUPT_STATUS		(1UL<<9)
#define I915_DISPLAY_LINE_COMPARE_STATUS	(1UL<<8)
#define I915_DPST_EVENT_STATUS			(1UL<<7)
#define I915_LEGACY_BLC_EVENT_STATUS		(1UL<<6)
#define I915_ODD_FIELD_INTERRUPT_STATUS		(1UL<<5)
#define I915_EVEN_FIELD_INTERRUPT_STATUS	(1UL<<4)
#define PIPE_START_VBLANK_INTERRUPT_STATUS	(1UL<<2)	/* 965 or later */
#define PIPE_VBLANK_INTERRUPT_STATUS		(1UL<<1)
#define I915_OVERLAY_UPDATED_STATUS		(1UL<<0)

/* GM45+ just has to be different */
#define PIPEA_FRMCOUNT_GM45    0x70040
#define PIPEA_FLIPCOUNT_GM45   0x70044
#define PIPEB_FRMCOUNT_GM45    0x71040
#define PIPEB_FLIPCOUNT_GM45   0x71044

/*
 * Some BIOS scratch area registers.  The 845 (and 830?) store the amount
 * of video memory available to the BIOS in SWF1.
 */

#define SWF0                    0x71410

/*
 * 855 scratch registers.
 */
#define SWF10                   0x70410

#define SWF30                   0x72414

/* IGDNG */

#define CPU_VGACNTRL	0x41000

#define DIGITAL_PORT_HOTPLUG_CNTRL      0x44030
#define  DIGITAL_PORTA_HOTPLUG_ENABLE           (1 << 4)
#define  DIGITAL_PORTA_SHORT_PULSE_2MS          (0 << 2)
#define  DIGITAL_PORTA_SHORT_PULSE_4_5MS        (1 << 2)
#define  DIGITAL_PORTA_SHORT_PULSE_6MS          (2 << 2)
#define  DIGITAL_PORTA_SHORT_PULSE_100MS        (3 << 2)
#define  DIGITAL_PORTA_NO_DETECT                (0 << 0)
#define  DIGITAL_PORTA_LONG_PULSE_DETECT_MASK   (1 << 1)
#define  DIGITAL_PORTA_SHORT_PULSE_DETECT_MASK  (1 << 0)

/* refresh rate hardware control */
#define RR_HW_CTL       0x45300
#define  RR_HW_LOW_POWER_FRAMES_MASK    0xff
#define  RR_HW_HIGH_POWER_FRAMES_MASK   0xff00

#define FDI_PLL_BIOS_0  0x46000
#define FDI_PLL_BIOS_1  0x46004
#define FDI_PLL_BIOS_2  0x46008
#define DISPLAY_PORT_PLL_BIOS_0         0x4600c
#define DISPLAY_PORT_PLL_BIOS_1         0x46010
#define DISPLAY_PORT_PLL_BIOS_2         0x46014

#define FDI_PLL_FREQ_CTL        0x46030
#define  FDI_PLL_FREQ_CHANGE_REQUEST    (1<<24)
#define  FDI_PLL_FREQ_LOCK_LIMIT_MASK   0xfff00
#define  FDI_PLL_FREQ_DISABLE_COUNT_LIMIT_MASK  0xff


#define PIPEA_DATA_M1           0x60030
#define  TU_SIZE(x)             (((x)-1) << 25) /* default size 64 */
#define  TU_SIZE_MASK           0x7e000000
#define  PIPEA_DATA_M1_OFFSET   0
#define PIPEA_DATA_N1           0x60034
#define  PIPEA_DATA_N1_OFFSET   0

#define PIPEA_DATA_M2           0x60038
#define  PIPEA_DATA_M2_OFFSET   0
#define PIPEA_DATA_N2           0x6003c
#define  PIPEA_DATA_N2_OFFSET   0

#define PIPEA_LINK_M1           0x60040
#define  PIPEA_LINK_M1_OFFSET   0
#define PIPEA_LINK_N1           0x60044
#define  PIPEA_LINK_N1_OFFSET   0

#define PIPEA_LINK_M2           0x60048
#define  PIPEA_LINK_M2_OFFSET   0
#define PIPEA_LINK_N2           0x6004c
#define  PIPEA_LINK_N2_OFFSET   0

/* PIPEB timing regs are same start from 0x61000 */

#define PIPEB_DATA_M1           0x61030
#define  PIPEB_DATA_M1_OFFSET   0
#define PIPEB_DATA_N1           0x61034
#define  PIPEB_DATA_N1_OFFSET   0

#define PIPEB_DATA_M2           0x61038
#define  PIPEB_DATA_M2_OFFSET   0
#define PIPEB_DATA_N2           0x6103c
#define  PIPEB_DATA_N2_OFFSET   0

#define PIPEB_LINK_M1           0x61040
#define  PIPEB_LINK_M1_OFFSET   0
#define PIPEB_LINK_N1           0x61044
#define  PIPEB_LINK_N1_OFFSET   0

#define PIPEB_LINK_M2           0x61048
#define  PIPEB_LINK_M2_OFFSET   0
#define PIPEB_LINK_N2           0x6104c
#define  PIPEB_LINK_N2_OFFSET   0

/* CPU panel fitter */
#define PFA_CTL_1               0x68080
#define PFB_CTL_1               0x68880
#define  PF_ENABLE              (1<<31)

/* legacy palette */
#define LGC_PALETTE_A           0x4a000
#define LGC_PALETTE_B           0x4a800

/* interrupts */
#define DE_MASTER_IRQ_CONTROL   (0x80000000)
#define DE_SPRITEB_FLIP_DONE    (1 << 29)
#define DE_SPRITEA_FLIP_DONE    (1 << 28)
#define DE_PLANEB_FLIP_DONE     (1 << 27)
#define DE_PLANEA_FLIP_DONE     (1 << 26)
#define DE_PCU_EVENT            (1 << 25)
#define DE_GTT_FAULT            (1 << 24)
#define DE_POISON               (1 << 23)
#define DE_PERFORM_COUNTER      (1 << 22)
#define DE_PCH_EVENT            (1 << 21)
#define DE_AUX_CHANNEL_A        (1 << 20)
#define DE_DP_A_HOTPLUG         (1 << 19)
#define DE_GSE                  (1 << 18)
#define DE_PIPEB_VBLANK         (1 << 15)
#define DE_PIPEB_EVEN_FIELD     (1 << 14)
#define DE_PIPEB_ODD_FIELD      (1 << 13)
#define DE_PIPEB_LINE_COMPARE   (1 << 12)
#define DE_PIPEB_VSYNC          (1 << 11)
#define DE_PIPEB_FIFO_UNDERRUN  (1 << 8)
#define DE_PIPEA_VBLANK         (1 << 7)
#define DE_PIPEA_EVEN_FIELD     (1 << 6)
#define DE_PIPEA_ODD_FIELD      (1 << 5)
#define DE_PIPEA_LINE_COMPARE   (1 << 4)
#define DE_PIPEA_VSYNC          (1 << 3)
#define DE_PIPEA_FIFO_UNDERRUN  (1 << 0)

#define DEISR   0x44000
#define DEIMR   0x44004
#define DEIIR   0x44008
#define DEIER   0x4400c

/* GT interrupt */
#define GT_SYNC_STATUS          (1 << 2)
#define GT_USER_INTERRUPT       (1 << 0)

#define GTISR   0x44010
#define GTIMR   0x44014
#define GTIIR   0x44018
#define GTIER   0x4401c

/* PCH */

/* south display engine interrupt */
#define SDE_CRT_HOTPLUG         (1 << 11)
#define SDE_PORTD_HOTPLUG       (1 << 10)
#define SDE_PORTC_HOTPLUG       (1 << 9)
#define SDE_PORTB_HOTPLUG       (1 << 8)
#define SDE_SDVOB_HOTPLUG       (1 << 6)

#define SDEISR  0xc4000
#define SDEIMR  0xc4004
#define SDEIIR  0xc4008
#define SDEIER  0xc400c

/* digital port hotplug */
#define PCH_PORT_HOTPLUG        0xc4030
#define PORTD_HOTPLUG_ENABLE            (1 << 20)
#define PORTD_PULSE_DURATION_2ms        (0)
#define PORTD_PULSE_DURATION_4_5ms      (1 << 18)
#define PORTD_PULSE_DURATION_6ms        (2 << 18)
#define PORTD_PULSE_DURATION_100ms      (3 << 18)
#define PORTD_HOTPLUG_NO_DETECT         (0)
#define PORTD_HOTPLUG_SHORT_DETECT      (1 << 16)
#define PORTD_HOTPLUG_LONG_DETECT       (1 << 17)
#define PORTC_HOTPLUG_ENABLE            (1 << 12)
#define PORTC_PULSE_DURATION_2ms        (0)
#define PORTC_PULSE_DURATION_4_5ms      (1 << 10)
#define PORTC_PULSE_DURATION_6ms        (2 << 10)
#define PORTC_PULSE_DURATION_100ms      (3 << 10)
#define PORTC_HOTPLUG_NO_DETECT         (0)
#define PORTC_HOTPLUG_SHORT_DETECT      (1 << 8)
#define PORTC_HOTPLUG_LONG_DETECT       (1 << 9)
#define PORTB_HOTPLUG_ENABLE            (1 << 4)
#define PORTB_PULSE_DURATION_2ms        (0)
#define PORTB_PULSE_DURATION_4_5ms      (1 << 2)
#define PORTB_PULSE_DURATION_6ms        (2 << 2)
#define PORTB_PULSE_DURATION_100ms      (3 << 2)
#define PORTB_HOTPLUG_NO_DETECT         (0)
#define PORTB_HOTPLUG_SHORT_DETECT      (1 << 0)
#define PORTB_HOTPLUG_LONG_DETECT       (1 << 1)

#define PCH_GPIOA               0xc5010
#define PCH_GPIOB               0xc5014
#define PCH_GPIOC               0xc5018
#define PCH_GPIOD               0xc501c
#define PCH_GPIOE               0xc5020
#define PCH_GPIOF               0xc5024

#define PCH_DPLL_A              0xc6014
#define PCH_DPLL_B              0xc6018

#define PCH_FPA0                0xc6040
#define PCH_FPA1                0xc6044
#define PCH_FPB0                0xc6048
#define PCH_FPB1                0xc604c

#define PCH_DPLL_TEST           0xc606c

#define PCH_DREF_CONTROL        0xC6200
#define  DREF_CONTROL_MASK      0x7fc3
#define  DREF_CPU_SOURCE_OUTPUT_DISABLE         (0<<13)
#define  DREF_CPU_SOURCE_OUTPUT_DOWNSPREAD      (2<<13)
#define  DREF_CPU_SOURCE_OUTPUT_NONSPREAD       (3<<13)
#define  DREF_CPU_SOURCE_OUTPUT_MASK		(3<<13)
#define  DREF_SSC_SOURCE_DISABLE                (0<<11)
#define  DREF_SSC_SOURCE_ENABLE                 (2<<11)
#define  DREF_SSC_SOURCE_MASK			(2<<11)
#define  DREF_NONSPREAD_SOURCE_DISABLE          (0<<9)
#define  DREF_NONSPREAD_CK505_ENABLE		(1<<9)
#define  DREF_NONSPREAD_SOURCE_ENABLE           (2<<9)
#define  DREF_NONSPREAD_SOURCE_MASK		(2<<9)
#define  DREF_SUPERSPREAD_SOURCE_DISABLE        (0<<7)
#define  DREF_SUPERSPREAD_SOURCE_ENABLE         (2<<7)
#define  DREF_SSC4_DOWNSPREAD                   (0<<6)
#define  DREF_SSC4_CENTERSPREAD                 (1<<6)
#define  DREF_SSC1_DISABLE                      (0<<1)
#define  DREF_SSC1_ENABLE                       (1<<1)
#define  DREF_SSC4_DISABLE                      (0)
#define  DREF_SSC4_ENABLE                       (1)

#define PCH_RAWCLK_FREQ         0xc6204
#define  FDL_TP1_TIMER_SHIFT    12
#define  FDL_TP1_TIMER_MASK     (3<<12)
#define  FDL_TP2_TIMER_SHIFT    10
#define  FDL_TP2_TIMER_MASK     (3<<10)
#define  RAWCLK_FREQ_MASK       0x3ff

#define PCH_DPLL_TMR_CFG        0xc6208

#define PCH_SSC4_PARMS          0xc6210
#define PCH_SSC4_AUX_PARMS      0xc6214

/* transcoder */

#define TRANS_HTOTAL_A          0xe0000
#define  TRANS_HTOTAL_SHIFT     16
#define  TRANS_HACTIVE_SHIFT    0
#define TRANS_HBLANK_A          0xe0004
#define  TRANS_HBLANK_END_SHIFT 16
#define  TRANS_HBLANK_START_SHIFT 0
#define TRANS_HSYNC_A           0xe0008
#define  TRANS_HSYNC_END_SHIFT  16
#define  TRANS_HSYNC_START_SHIFT 0
#define TRANS_VTOTAL_A          0xe000c
#define  TRANS_VTOTAL_SHIFT     16
#define  TRANS_VACTIVE_SHIFT    0
#define TRANS_VBLANK_A          0xe0010
#define  TRANS_VBLANK_END_SHIFT 16
#define  TRANS_VBLANK_START_SHIFT 0
#define TRANS_VSYNC_A           0xe0014
#define  TRANS_VSYNC_END_SHIFT  16
#define  TRANS_VSYNC_START_SHIFT 0

#define TRANSA_DATA_M1          0xe0030
#define TRANSA_DATA_N1          0xe0034
#define TRANSA_DATA_M2          0xe0038
#define TRANSA_DATA_N2          0xe003c
#define TRANSA_DP_LINK_M1       0xe0040
#define TRANSA_DP_LINK_N1       0xe0044
#define TRANSA_DP_LINK_M2       0xe0048
#define TRANSA_DP_LINK_N2       0xe004c

#define TRANS_HTOTAL_B          0xe1000
#define TRANS_HBLANK_B          0xe1004
#define TRANS_HSYNC_B           0xe1008
#define TRANS_VTOTAL_B          0xe100c
#define TRANS_VBLANK_B          0xe1010
#define TRANS_VSYNC_B           0xe1014

#define TRANSB_DATA_M1          0xe1030
#define TRANSB_DATA_N1          0xe1034
#define TRANSB_DATA_M2          0xe1038
#define TRANSB_DATA_N2          0xe103c
#define TRANSB_DP_LINK_M1       0xe1040
#define TRANSB_DP_LINK_N1       0xe1044
#define TRANSB_DP_LINK_M2       0xe1048
#define TRANSB_DP_LINK_N2       0xe104c

#define TRANSACONF              0xf0008
#define TRANSBCONF              0xf1008
#define  TRANS_DISABLE          (0<<31)
#define  TRANS_ENABLE           (1<<31)
#define  TRANS_STATE_MASK       (1<<30)
#define  TRANS_STATE_DISABLE    (0<<30)
#define  TRANS_STATE_ENABLE     (1<<30)
#define  TRANS_FSYNC_DELAY_HB1  (0<<27)
#define  TRANS_FSYNC_DELAY_HB2  (1<<27)
#define  TRANS_FSYNC_DELAY_HB3  (2<<27)
#define  TRANS_FSYNC_DELAY_HB4  (3<<27)
#define  TRANS_DP_AUDIO_ONLY    (1<<26)
#define  TRANS_DP_VIDEO_AUDIO   (0<<26)
#define  TRANS_PROGRESSIVE      (0<<21)
#define  TRANS_8BPC             (0<<5)
#define  TRANS_10BPC            (1<<5)
#define  TRANS_6BPC             (2<<5)
#define  TRANS_12BPC            (3<<5)

#define FDI_RXA_CHICKEN         0xc200c
#define FDI_RXB_CHICKEN         0xc2010
#define  FDI_RX_PHASE_SYNC_POINTER_ENABLE       (1)

/* CPU: FDI_TX */
#define FDI_TXA_CTL             0x60100
#define FDI_TXB_CTL             0x61100
#define  FDI_TX_DISABLE         (0<<31)
#define  FDI_TX_ENABLE          (1<<31)
#define  FDI_LINK_TRAIN_PATTERN_1       (0<<28)
#define  FDI_LINK_TRAIN_PATTERN_2       (1<<28)
#define  FDI_LINK_TRAIN_PATTERN_IDLE    (2<<28)
#define  FDI_LINK_TRAIN_NONE            (3<<28)
#define  FDI_LINK_TRAIN_VOLTAGE_0_4V    (0<<25)
#define  FDI_LINK_TRAIN_VOLTAGE_0_6V    (1<<25)
#define  FDI_LINK_TRAIN_VOLTAGE_0_8V    (2<<25)
#define  FDI_LINK_TRAIN_VOLTAGE_1_2V    (3<<25)
#define  FDI_LINK_TRAIN_PRE_EMPHASIS_NONE (0<<22)
#define  FDI_LINK_TRAIN_PRE_EMPHASIS_1_5X (1<<22)
#define  FDI_LINK_TRAIN_PRE_EMPHASIS_2X   (2<<22)
#define  FDI_LINK_TRAIN_PRE_EMPHASIS_3X   (3<<22)
#define  FDI_DP_PORT_WIDTH_X1           (0<<19)
#define  FDI_DP_PORT_WIDTH_X2           (1<<19)
#define  FDI_DP_PORT_WIDTH_X3           (2<<19)
#define  FDI_DP_PORT_WIDTH_X4           (3<<19)
#define  FDI_TX_ENHANCE_FRAME_ENABLE    (1<<18)
/* IGDNG: hardwired to 1 */
#define  FDI_TX_PLL_ENABLE              (1<<14)
/* both Tx and Rx */
#define  FDI_SCRAMBLING_ENABLE          (0<<7)
#define  FDI_SCRAMBLING_DISABLE         (1<<7)

/* FDI_RX, FDI_X is hard-wired to Transcoder_X */
#define FDI_RXA_CTL             0xf000c
#define FDI_RXB_CTL             0xf100c
#define  FDI_RX_ENABLE          (1<<31)
#define  FDI_RX_DISABLE         (0<<31)
/* train, dp width same as FDI_TX */
#define  FDI_DP_PORT_WIDTH_X8           (7<<19)
#define  FDI_8BPC                       (0<<16)
#define  FDI_10BPC                      (1<<16)
#define  FDI_6BPC                       (2<<16)
#define  FDI_12BPC                      (3<<16)
#define  FDI_LINK_REVERSE_OVERWRITE     (1<<15)
#define  FDI_DMI_LINK_REVERSE_MASK      (1<<14)
#define  FDI_RX_PLL_ENABLE              (1<<13)
#define  FDI_FS_ERR_CORRECT_ENABLE      (1<<11)
#define  FDI_FE_ERR_CORRECT_ENABLE      (1<<10)
#define  FDI_FS_ERR_REPORT_ENABLE       (1<<9)
#define  FDI_FE_ERR_REPORT_ENABLE       (1<<8)
#define  FDI_RX_ENHANCE_FRAME_ENABLE    (1<<6)
#define  FDI_SEL_RAWCLK                 (0<<4)
#define  FDI_SEL_PCDCLK                 (1<<4)

#define FDI_RXA_MISC            0xf0010
#define FDI_RXB_MISC            0xf1010
#define FDI_RXA_TUSIZE1         0xf0030
#define FDI_RXA_TUSIZE2         0xf0038
#define FDI_RXB_TUSIZE1         0xf1030
#define FDI_RXB_TUSIZE2         0xf1038

/* FDI_RX interrupt register format */
#define FDI_RX_INTER_LANE_ALIGN         (1<<10)
#define FDI_RX_SYMBOL_LOCK              (1<<9) /* train 2 */
#define FDI_RX_BIT_LOCK                 (1<<8) /* train 1 */
#define FDI_RX_TRAIN_PATTERN_2_FAIL     (1<<7)
#define FDI_RX_FS_CODE_ERR              (1<<6)
#define FDI_RX_FE_CODE_ERR              (1<<5)
#define FDI_RX_SYMBOL_ERR_RATE_ABOVE    (1<<4)
#define FDI_RX_HDCP_LINK_FAIL           (1<<3)
#define FDI_RX_PIXEL_FIFO_OVERFLOW      (1<<2)
#define FDI_RX_CROSS_CLOCK_OVERFLOW     (1<<1)
#define FDI_RX_SYMBOL_QUEUE_OVERFLOW    (1<<0)

#define FDI_RXA_IIR             0xf0014
#define FDI_RXA_IMR             0xf0018
#define FDI_RXB_IIR             0xf1014
#define FDI_RXB_IMR             0xf1018

#define FDI_PLL_CTL_1           0xfe000
#define FDI_PLL_CTL_2           0xfe004

/* CRT */
#define PCH_ADPA                0xe1100
#define  ADPA_TRANS_SELECT_MASK (1<<30)
#define  ADPA_TRANS_A_SELECT    0
#define  ADPA_TRANS_B_SELECT    (1<<30)
#define  ADPA_CRT_HOTPLUG_MASK  0x03ff0000 /* bit 25-16 */
#define  ADPA_CRT_HOTPLUG_MONITOR_NONE  (0<<24)
#define  ADPA_CRT_HOTPLUG_MONITOR_MASK  (3<<24)
#define  ADPA_CRT_HOTPLUG_MONITOR_COLOR (3<<24)
#define  ADPA_CRT_HOTPLUG_MONITOR_MONO  (2<<24)
#define  ADPA_CRT_HOTPLUG_ENABLE        (1<<23)
#define  ADPA_CRT_HOTPLUG_PERIOD_64     (0<<22)
#define  ADPA_CRT_HOTPLUG_PERIOD_128    (1<<22)
#define  ADPA_CRT_HOTPLUG_WARMUP_5MS    (0<<21)
#define  ADPA_CRT_HOTPLUG_WARMUP_10MS   (1<<21)
#define  ADPA_CRT_HOTPLUG_SAMPLE_2S     (0<<20)
#define  ADPA_CRT_HOTPLUG_SAMPLE_4S     (1<<20)
#define  ADPA_CRT_HOTPLUG_VOLTAGE_40    (0<<18)
#define  ADPA_CRT_HOTPLUG_VOLTAGE_50    (1<<18)
#define  ADPA_CRT_HOTPLUG_VOLTAGE_60    (2<<18)
#define  ADPA_CRT_HOTPLUG_VOLTAGE_70    (3<<18)
#define  ADPA_CRT_HOTPLUG_VOLREF_325MV  (0<<17)
#define  ADPA_CRT_HOTPLUG_VOLREF_475MV  (1<<17)
#define  ADPA_CRT_HOTPLUG_FORCE_TRIGGER (1<<16)

/* or SDVOB */
#define HDMIB   0xe1140
#define  PORT_ENABLE    (1 << 31)
#define  TRANSCODER_A   (0)
#define  TRANSCODER_B   (1 << 30)
#define  COLOR_FORMAT_8bpc      (0)
#define  COLOR_FORMAT_12bpc     (3 << 26)
#define  SDVOB_HOTPLUG_ENABLE   (1 << 23)
#define  SDVO_ENCODING          (0)
#define  TMDS_ENCODING          (2 << 10)
#define  NULL_PACKET_VSYNC_ENABLE       (1 << 9)
#define  SDVOB_BORDER_ENABLE    (1 << 7)
#define  AUDIO_ENABLE           (1 << 6)
#define  VSYNC_ACTIVE_HIGH      (1 << 4)
#define  HSYNC_ACTIVE_HIGH      (1 << 3)
#define  PORT_DETECTED          (1 << 2)

#define HDMIC   0xe1150
#define HDMID   0xe1160

#define PCH_LVDS	0xe1180
#define  LVDS_DETECTED	(1 << 1)

#define BLC_PWM_CPU_CTL2	0x48250
#define  PWM_ENABLE		(1 << 31)
#define  PWM_PIPE_A		(0 << 29)
#define  PWM_PIPE_B		(1 << 29)
#define BLC_PWM_CPU_CTL		0x48254

#define BLC_PWM_PCH_CTL1	0xc8250
#define  PWM_PCH_ENABLE		(1 << 31)
#define  PWM_POLARITY_ACTIVE_LOW	(1 << 29)
#define  PWM_POLARITY_ACTIVE_HIGH	(0 << 29)
#define  PWM_POLARITY_ACTIVE_LOW2	(1 << 28)
#define  PWM_POLARITY_ACTIVE_HIGH2	(0 << 28)

#define BLC_PWM_PCH_CTL2	0xc8254

#define PCH_PP_STATUS		0xc7200
#define PCH_PP_CONTROL		0xc7204
#define  EDP_FORCE_VDD		(1 << 3)
#define  EDP_BLC_ENABLE		(1 << 2)
#define  PANEL_POWER_RESET	(1 << 1)
#define  PANEL_POWER_OFF	(0 << 0)
#define  PANEL_POWER_ON		(1 << 0)
#define PCH_PP_ON_DELAYS	0xc7208
#define  EDP_PANEL		(1 << 30)
#define PCH_PP_OFF_DELAYS	0xc720c
#define PCH_PP_DIVISOR		0xc7210

#define	PCI_DEVICE_ID_INTEL_82830_CGC 0x3577
#define PCI_DEVICE_ID_INTEL_82845G_IG   0x2562
#define PCI_DEVICE_ID_INTEL_82855GM_IG  0x3582
#define PCI_DEVICE_ID_INTEL_82865_IG    0x2572
#define PCI_DEVICE_ID_INTEL_82915G_IG   0x2582
#define PCI_DEVICE_ID_INTEL_82915GM_IG  0x2592
#define PCI_DEVICE_ID_INTEL_82945G_IG   0x2772
#define PCI_DEVICE_ID_INTEL_82945GM_IG  0x27A2
#define PCI_DEVICE_ID_INTEL_82945GME_IG 0x27AE
#define	PCI_DEVICE_ID_INTEL_82946_GZ	0x2972	
#define	PCI_DEVICE_ID_INTEL_82G35_IG	0x2982
#define	PCI_DEVICE_ID_INTEL_82Q963_IG	0x2992
#define	PCI_DEVICE_ID_INTEL_82G965_IG	0x29a2
#define	PCI_DEVICE_ID_INTEL_GM965_IG	0x2a02
#define	PCI_DEVICE_ID_INTEL_GME965_IG	0x2a12
#define	PCI_DEVICE_ID_INTEL_82G33_IG	0x29c2
#define	PCI_DEVICE_ID_INTEL_82Q35_IG	0x29b2
#define	PCI_DEVICE_ID_INTEL_82Q33_IG	0x29d2
#define	PCI_DEVICE_ID_INTEL_CANTIGA_IG	0x2a42
#define	PCI_DEVICE_ID_INTEL_EL_IG	0x2e02
#define	PCI_DEVICE_ID_INTEL_82Q45_IG	0x2e12
#define	PCI_DEVICE_ID_INTEL_82G45_IG	0x2e22
#define	PCI_DEVICE_ID_INTEL_82G41_IG	0x2e32
#define	PCI_DEVICE_ID_INTEL_IGDNG_D_IG	0x42
#define	PCI_DEVICE_ID_INTEL_IGDNG_M_IG	0x46
#define	PCI_DEVICE_ID_INTEL_82B43_IG	0x2e42


#define IS_I830(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82830_CGC)
#define IS_845G(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82845G_IG)
#define IS_I85X(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82855GM_IG)
#define IS_I855(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82855GM_IG)
#define IS_I865G(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82865_IG) 

#define IS_I915G(dev) (dev->pci_device == PCI_DEVICE_ID_INTEL_82915G_IG)
#define IS_I915GM(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82915GM_IG)
#define IS_I945G(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82945G_IG)
#define IS_I945GM(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82945GM_IG || \
                        (dev)->pci_device == PCI_DEVICE_ID_INTEL_82945GME_IG)

#define IS_IGDNG_D(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_IGDNG_D_IG)
#define IS_IGDNG_M(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_IGDNG_M_IG)
#define IS_IGDNG(dev) (IS_IGDNG_D(dev) || IS_IGDNG_M(dev))

#define IS_I965G(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82946_GZ || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G35_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q963_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G965_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_GM965_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_GME965_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_CANTIGA_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_EL_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q45_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G45_IG || \
			(dev)->pci_device == PCI_DEVICE_ID_INTEL_82B43_IG || \
			(dev)->pci_device == PCI_DEVICE_ID_INTEL_IGDNG_D_IG || \
			(dev)->pci_device == PCI_DEVICE_ID_INTEL_IGDNG_M_IG || \
			(dev)->pci_device == PCI_DEVICE_ID_INTEL_82G41_IG)

#define IS_I965GM(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_GM965_IG)

#define IS_GM45(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_CANTIGA_IG)

#define IS_G4X(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_EL_IG || \
                     (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q45_IG || \
                     (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G45_IG || \
                     (dev)->pci_device == PCI_DEVICE_ID_INTEL_82B43_IG || \
                     (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G41_IG)

#define IS_G33(dev)    ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82G33_IG ||  \
                        (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q35_IG || \
                        (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q33_IG)

#define IS_I9XX(dev) (IS_I915G(dev) || IS_I915GM(dev) || IS_I945G(dev) || \
                      IS_I945GM(dev) || IS_I965G(dev) || IS_G33(dev) || \
			IS_IGDNG(dev))

#define IS_MOBILE(dev) (IS_I830(dev) || IS_I85X(dev) || IS_I915GM(dev) || \
                        IS_I945GM(dev) || IS_I965GM(dev) || IS_GM45(dev) || \
			IS_IGDNG_M(dev))

#define IS_IGDG(dev) ((dev)->pci_device == 0xa001)
#define IS_IGDGM(dev) ((dev)->pci_device == 0xa011)
#define IS_IGD(dev) (IS_IGDG(dev) || IS_IGDGM(dev))

#define I915_NEED_GFX_HWS(dev) (IS_G33(dev) || IS_GM45(dev) || IS_G4X(dev) || \
				IS_IGDNG(dev))
/* With the 945 and later, Y tiling got adjusted so that it was 32 128-byte
 * rows, which changed the alignment requirements and fence programming.
 */
#define HAS_128_BYTE_Y_TILING(dev) (IS_I9XX(dev) && !(IS_I915G(dev) || \
						      IS_I915GM(dev)))

#endif /* _I915_DRV_H */
