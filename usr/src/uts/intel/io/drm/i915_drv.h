/* BEGIN CSTYLED */

/* i915_drv.h -- Private header for the I915 driver -*- linux-c -*-
 */
/*
 *
 * Copyright 2003 Tungsten Graphics, Inc., Cedar Park, Texas.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _I915_DRV_H
#define _I915_DRV_H

/* General customization:
 */

#define DRIVER_AUTHOR		"Tungsten Graphics, Inc."

#define DRIVER_NAME		"i915"
#define DRIVER_DESC		"Intel Graphics"
#define DRIVER_DATE		"20060929"

#if defined(__SVR4) && defined(__sun)
#define spinlock_t kmutex_t 
#endif

/* Interface history:
 *
 * 1.1: Original.
 * 1.2: Add Power Management
 * 1.3: Add vblank support
 * 1.4: Fix cmdbuffer path, add heap destroy
 */
#define DRIVER_MAJOR		1
#define DRIVER_MINOR		4
#define DRIVER_PATCHLEVEL	0

#if defined(__linux__)
#define I915_HAVE_FENCE
#define I915_HAVE_BUFFER
#endif

typedef struct _drm_i915_ring_buffer {
	int tail_mask;
	unsigned long Start;
	unsigned long End;
	unsigned long Size;
	u8 *virtual_start;
	int head;
	int tail;
	int space;
	drm_local_map_t map;
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
	unsigned int pipe;
	unsigned int sequence;
} drm_i915_vbl_swap_t;

typedef struct s3_i915_private {
	ddi_acc_handle_t saveHandle;
	caddr_t saveAddr;
	uint32_t pgtbl_ctl;
	uint8_t saveLBB;
	uint32_t saveDSPACNTR;
	uint32_t saveDSPBCNTR;
	uint32_t saveDSPARB;
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

typedef struct drm_i915_private {
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

	unsigned int cpp;
	int back_offset;
	int front_offset;
	int current_page;
	int page_flipping;
	int use_mi_batchbuffer_start;

	wait_queue_head_t irq_queue;
	atomic_t irq_received;
	atomic_t irq_emitted;

	int tex_lru_log_granularity;
	int allow_batchbuffer;
	struct mem_block *agp_heap;
	unsigned int sr01, adpa, ppcr, dvob, dvoc, lvds;
	int vblank_pipe;
	spinlock_t user_irq_lock;
        int user_irq_refcount;
        int fence_irq_on;
        uint32_t irq_enable_reg;
        int irq_enabled;

#ifdef I915_HAVE_FENCE
        uint32_t flush_sequence;
	uint32_t flush_flags;
	uint32_t flush_pending;
	uint32_t saved_flush_status;
#endif
#ifdef I915_HAVE_BUFFER
	void *agp_iomap;
#endif
	spinlock_t swaps_lock;
	drm_i915_vbl_swap_t vbl_swaps;
	unsigned int swaps_pending;

} drm_i915_private_t;

enum intel_chip_family {
	CHIP_I8XX = 0x01,
	CHIP_I9XX = 0x02,
	CHIP_I915 = 0x04,
	CHIP_I965 = 0x08,
};

extern drm_ioctl_desc_t i915_ioctls[];
extern int i915_max_ioctl;

				/* i915_dma.c */
extern void i915_kernel_lost_context(drm_device_t * dev);
extern int i915_driver_load(struct drm_device *, unsigned long flags);
extern int i915_driver_unload(struct drm_device *dev);
extern void i915_driver_lastclose(drm_device_t * dev);
extern void i915_driver_preclose(drm_device_t * dev, drm_file_t *filp);
extern int i915_driver_device_is_agp(drm_device_t * dev);
extern long i915_compat_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg);
extern int i915_emit_mi_flush(drm_device_t *dev, uint32_t flush);


/* i915_irq.c */
extern int i915_irq_emit(DRM_IOCTL_ARGS);
extern int i915_irq_wait(DRM_IOCTL_ARGS);

extern int i915_driver_vblank_wait(drm_device_t *dev, unsigned int *sequence);
extern int i915_driver_vblank_wait2(drm_device_t *dev, unsigned int *sequence);
extern irqreturn_t i915_driver_irq_handler(DRM_IRQ_ARGS);
extern void i915_driver_irq_preinstall(drm_device_t * dev);
extern void i915_driver_irq_postinstall(drm_device_t * dev);
extern void i915_driver_irq_uninstall(drm_device_t * dev);
extern int i915_emit_irq(drm_device_t * dev);
extern void i915_user_irq_on(drm_i915_private_t *dev_priv);
extern void i915_user_irq_off(drm_i915_private_t *dev_priv);

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

#define RING_LOCALS	unsigned int outring, ringmask, outcount; \
                        volatile unsigned char *virt;

#define BEGIN_LP_RING(n) do {				\
	if (dev_priv->ring.space < (n)*4)			\
		(void) i915_wait_ring(dev, (n)*4, __FUNCTION__);		\
	outcount = 0;					\
	outring = dev_priv->ring.tail;			\
	ringmask = dev_priv->ring.tail_mask;		\
	virt = dev_priv->ring.virtual_start;		\
} while (*"\0")

#define OUT_RING(n) do {					\
	*(volatile unsigned int *)(void *)(virt + outring) = (n);		\
        outcount++;						\
	outring += 4;						\
	outring &= ringmask;					\
} while (*"\0")

#define ADVANCE_LP_RING() do {						\
	dev_priv->ring.tail = outring;					\
	dev_priv->ring.space -= outcount * 4;				\
	I915_WRITE(LP_RING + RING_TAIL, outring);			\
} while (*"\0")

extern int i915_wait_ring(drm_device_t * dev, int n, const char *caller);

/* Extended config space */
#define LBB 0xf4

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

#define CMD_MI_FLUSH         (0x04 << 23)
#define MI_NO_WRITE_FLUSH    (1 << 2)
#define MI_READ_FLUSH        (1 << 0)
#define MI_EXE_FLUSH         (1 << 1)

#define BB1_START_ADDR_MASK   (~0x7)
#define BB1_PROTECTED         (1<<0)
#define BB1_UNPROTECTED       (0<<0)
#define BB2_END_ADDR_MASK     (~0x7)

#define	I915REG_PGTBL_CTRL	0x2020
#define I915REG_HWSTAM		0x02098
#define I915REG_INT_IDENTITY_R	0x020a4
#define I915REG_INT_MASK_R 	0x020a8
#define I915REG_INT_ENABLE_R	0x020a0
#define I915REG_INSTPM	        0x020c0

#define I915REG_PIPEASTAT	0x70024
#define I915REG_PIPEBSTAT	0x71024

#define I915_VBLANK_INTERRUPT_ENABLE	(1UL<<17)
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
#define RING_TAIL      		0x00
#define TAIL_ADDR		0x001FFFF8
#define RING_HEAD      		0x04
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

#define MI_BATCH_BUFFER 	((0x30<<23)|1)
#define MI_BATCH_BUFFER_START 	(0x31<<23)
#define MI_BATCH_BUFFER_END 	(0xA<<23)
#define MI_BATCH_NON_SECURE	(1)

#define MI_WAIT_FOR_EVENT       ((0x3<<23))
#define MI_WAIT_FOR_PLANE_A_FLIP      (1<<2)
#define MI_WAIT_FOR_PLANE_A_SCANLINES (1<<1)

#define MI_LOAD_SCAN_LINES_INCL  ((0x12<<23))

#define CMD_OP_DISPLAYBUFFER_INFO ((0x0<<29)|(0x14<<23)|2)
#define ASYNC_FLIP                (1<<22)

#define CMD_OP_DESTBUFFER_INFO	 ((0x3<<29)|(0x1d<<24)|(0x8e<<16)|1)

#define BREADCRUMB_OFFSET          32  /* dword offset 20h */
#define READ_BREADCRUMB(dev_priv)  (((volatile u32*)(dev_priv->hw_status_page))[BREADCRUMB_OFFSET])
#define READ_HWSP(dev_priv, reg)  (((volatile u32*)(dev_priv->hw_status_page))[reg])

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
#define PIPEACONF_ENABLE        (1<<31)
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
#define PIPEBCONF_ENABLE        (1<<31)
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
# define PP_READY                               (1 << 30) # define PP_SEQUENCE_NONE                       (0 << 28)
# define PP_SEQUENCE_ON                         (1 << 28) # define PP_SEQUENCE_OFF                        (2 << 28)
# define PP_SEQUENCE_MASK                       0x30000000
#define PP_CONTROL      0x61204
# define POWER_TARGET_ON                        (1 << 0)

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
#define   FBC_CTL_FENCENO       (1<<0) #define FBC_COMMAND             0x0320c
#define   FBC_CMD_COMPRESS      (1<<0) #define FBC_STATUS              0x03210
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

#define IS_I965G(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82946_GZ || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G35_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q963_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G965_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_GM965_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_GME965_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_CANTIGA_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_EL_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q45_IG || \
                       (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G45_IG)

#define IS_I965GM(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_GM965_IG)

#define IS_GM45(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_CANTIGA_IG)

#define IS_G4X(dev) ((dev)->pci_device == PCI_DEVICE_ID_INTEL_EL_IG || \
                     (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q45_IG || \
                     (dev)->pci_device == PCI_DEVICE_ID_INTEL_82G45_IG)

#define IS_G33(dev)    ((dev)->pci_device == PCI_DEVICE_ID_INTEL_82G33_IG ||  \
                        (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q35_IG || \
                        (dev)->pci_device == PCI_DEVICE_ID_INTEL_82Q33_IG)

#define IS_I9XX(dev) (IS_I915G(dev) || IS_I915GM(dev) || IS_I945G(dev) || \
                      IS_I945GM(dev) || IS_I965G(dev) || IS_G33(dev))

#define IS_MOBILE(dev) (IS_I830(dev) || IS_I85X(dev) || IS_I915GM(dev) || \
                        IS_I945GM(dev) || IS_I965GM(dev) || IS_GM45(dev))

#define I915_NEED_GFX_HWS(dev) (IS_G33(dev) || IS_GM45(dev) || IS_G4X(dev))

#endif /* _I915_DRV_H */
