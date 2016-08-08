/* BEGIN CSTYLED */

/*
 * i915_drv.c -- Intel i915 driver -*- linux-c -*-
 * Created: Wed Feb 14 17:10:04 2001 by gareth@valinux.com
 */

/*
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * Copyright (c) 2009, Intel Corporation.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2014 RackTop Systems.
 */

/*
 * I915 DRM Driver for Solaris
 *
 * This driver provides the hardware 3D acceleration support for Intel
 * integrated video devices (e.g. i8xx/i915/i945 series chipsets), under the
 * DRI (Direct Rendering Infrastructure). DRM (Direct Rendering Manager) here
 * means the kernel device driver in DRI.
 *
 * I915 driver is a device dependent driver only, it depends on a misc module
 * named drm for generic DRM operations.
 */

#include "drmP.h"
#include "i915_drm.h"
#include "i915_drv.h"
#include "drm_pciids.h"

/*
 * copied from vgasubr.h
 */

struct vgaregmap {
	uint8_t			*addr;
	ddi_acc_handle_t	handle;
	boolean_t		mapped;
};

enum pipe {
	PIPE_A = 0,
	PIPE_B,
};


/*
 * cb_ops entrypoint
 */
extern struct cb_ops drm_cb_ops;

/*
 * module entrypoint
 */
static int i915_info(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int i915_attach(dev_info_t *, ddi_attach_cmd_t);
static int i915_detach(dev_info_t *, ddi_detach_cmd_t);


/* drv_PCI_IDs comes from drm_pciids.h */
static drm_pci_id_list_t i915_pciidlist[] = {
	i915_PCI_IDS
};

/*
 * Local routines
 */
static void i915_configure(drm_driver_t *);
static int i915_quiesce(dev_info_t *dip);

/*
 * DRM driver
 */
static drm_driver_t	i915_driver = {0};


static struct dev_ops i915_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	i915_info,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	i915_attach,			/* devo_attach */
	i915_detach,			/* devo_detach */
	nodev,				/* devo_reset */
	&drm_cb_ops,			/* devo_cb_ops */
	NULL,				/* devo_bus_ops */
	NULL,				/* power */
	i915_quiesce,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,			/* drv_modops */
	"I915 DRM driver",	/* drv_linkinfo */
	&i915_dev_ops,			/* drv_dev_ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &modldrv, NULL
};

static ddi_device_acc_attr_t s3_attr = {                              
        DDI_DEVICE_ATTR_V0,                                                     
        DDI_NEVERSWAP_ACC,                                                      
        DDI_STRICTORDER_ACC     /* must be DDI_STRICTORDER_ACC */               
}; 

/*
 * softstate head
 */
static void 	*i915_statep;

int
_init(void)
{
	int error;

	i915_configure(&i915_driver);

	if ((error = ddi_soft_state_init(&i915_statep,
	    sizeof (drm_device_t), DRM_MAX_INSTANCES)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&i915_statep);
		return (error);
	}

	return (error);

}	/* _init() */

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	(void) ddi_soft_state_fini(&i915_statep);
	
	return (0);

}	/* _fini() */

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));

}	/* _info() */

/*
 * off range: 0x3b0 ~ 0x3ff
 */

static void
vga_reg_put8(struct vgaregmap *regmap, uint16_t off, uint8_t val)
{
	ASSERT((off >= 0x3b0) && (off <= 0x3ff));

	ddi_put8(regmap->handle, regmap->addr + off, val);
}

/*
 * off range: 0x3b0 ~ 0x3ff
 */
static uint8_t
vga_reg_get8(struct vgaregmap *regmap, uint16_t off)
{

	ASSERT((off >= 0x3b0) && (off <= 0x3ff));

	return (ddi_get8(regmap->handle, regmap->addr + off));
}

static void
i915_write_indexed(struct vgaregmap *regmap,
    uint16_t index_port, uint16_t data_port, uint8_t index, uint8_t val)
{
	vga_reg_put8(regmap, index_port, index);
	vga_reg_put8(regmap, data_port, val);
}

static uint8_t
i915_read_indexed(struct vgaregmap *regmap,
    uint16_t index_port, uint16_t data_port, uint8_t index)
{
	vga_reg_put8(regmap, index_port, index);
	return (vga_reg_get8(regmap, data_port));
}

static void
i915_write_ar(struct vgaregmap *regmap, uint16_t st01,
    uint8_t reg, uint8_t val, uint8_t palette_enable)
{
	(void) vga_reg_get8(regmap, st01);
	vga_reg_put8(regmap, VGA_AR_INDEX, palette_enable | reg);
	vga_reg_put8(regmap, VGA_AR_DATA_WRITE, val);
}

static uint8_t
i915_read_ar(struct vgaregmap *regmap, uint16_t st01,
    uint8_t index, uint8_t palette_enable)
{
	(void) vga_reg_get8(regmap, st01);
	vga_reg_put8(regmap, VGA_AR_INDEX, index | palette_enable);
	return (vga_reg_get8(regmap, VGA_AR_DATA_READ));
}

static int
i915_pipe_enabled(struct drm_device *dev, enum pipe pipe)
{
	struct s3_i915_private *s3_priv = dev->s3_private;

	if (pipe == PIPE_A)
		return (S3_READ(DPLL_A) & DPLL_VCO_ENABLE);
	else
		return (S3_READ(DPLL_B) & DPLL_VCO_ENABLE);
}

static void
i915_save_palette(struct drm_device *dev, enum pipe pipe)
{
	struct s3_i915_private *s3_priv = dev->s3_private;
	unsigned long reg = (pipe == PIPE_A ? PALETTE_A : PALETTE_B);
	uint32_t *array;
	int i;

	if (!i915_pipe_enabled(dev, pipe))
		return;

	if (pipe == PIPE_A)
		array = s3_priv->save_palette_a;
	else
		array = s3_priv->save_palette_b;

	for(i = 0; i < 256; i++)
		array[i] = S3_READ(reg + (i << 2));

}

static void
i915_restore_palette(struct drm_device *dev, enum pipe pipe)
{
	struct s3_i915_private *s3_priv = dev->s3_private;
	unsigned long reg = (pipe == PIPE_A ? PALETTE_A : PALETTE_B);
	uint32_t *array;
	int i;

	if (!i915_pipe_enabled(dev, pipe))
		return;

	if (pipe == PIPE_A)
		array = s3_priv->save_palette_a;
	else
		array = s3_priv->save_palette_b;

	for(i = 0; i < 256; i++)
		S3_WRITE(reg + (i << 2), array[i]);
}

static void
i915_save_vga(struct drm_device *dev)
{
	struct s3_i915_private *s3_priv = dev->s3_private;
	int i;
	uint16_t cr_index, cr_data, st01;
	struct vgaregmap regmap;

	regmap.addr = (uint8_t *)s3_priv->saveAddr;
	regmap.handle = s3_priv->saveHandle;

	/* VGA color palette registers */
        s3_priv->saveDACMASK = vga_reg_get8(&regmap, VGA_DACMASK);
	/* DACCRX automatically increments during read */
	vga_reg_put8(&regmap, VGA_DACRX, 0);
	/* Read 3 bytes of color data from each index */
	for (i = 0; i < 256 * 3; i++)
		s3_priv->saveDACDATA[i] = vga_reg_get8(&regmap, VGA_DACDATA);

	/* MSR bits */
	s3_priv->saveMSR = vga_reg_get8(&regmap, VGA_MSR_READ);
	if (s3_priv->saveMSR & VGA_MSR_CGA_MODE) {
		cr_index = VGA_CR_INDEX_CGA;
		cr_data = VGA_CR_DATA_CGA;
		st01 = VGA_ST01_CGA;
	} else {
		cr_index = VGA_CR_INDEX_MDA;
		cr_data = VGA_CR_DATA_MDA;
		st01 = VGA_ST01_MDA;
	}

	/* CRT controller regs */
	i915_write_indexed(&regmap, cr_index, cr_data, 0x11,
	    i915_read_indexed(&regmap, cr_index, cr_data, 0x11) & (~0x80));
	for (i = 0; i <= 0x24; i++)
		s3_priv->saveCR[i] =
		    i915_read_indexed(&regmap, cr_index, cr_data, i);
	/* Make sure we don't turn off CR group 0 writes */
	s3_priv->saveCR[0x11] &= ~0x80;

	/* Attribute controller registers */
	(void) vga_reg_get8(&regmap, st01);
	s3_priv->saveAR_INDEX = vga_reg_get8(&regmap, VGA_AR_INDEX);
	for (i = 0; i <= 0x14; i++)
		s3_priv->saveAR[i] = i915_read_ar(&regmap, st01, i, 0);
	(void) vga_reg_get8(&regmap, st01);
	vga_reg_put8(&regmap, VGA_AR_INDEX, s3_priv->saveAR_INDEX);
	(void) vga_reg_get8(&regmap, st01);

	/* Graphics controller registers */
	for (i = 0; i < 9; i++)
		s3_priv->saveGR[i] =
		    i915_read_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, i);

	s3_priv->saveGR[0x10] =
		i915_read_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, 0x10);
	s3_priv->saveGR[0x11] =
		i915_read_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, 0x11);
	s3_priv->saveGR[0x18] =
		i915_read_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, 0x18);

	/* Sequencer registers */
	for (i = 0; i < 8; i++)
		s3_priv->saveSR[i] =
		    i915_read_indexed(&regmap, VGA_SR_INDEX, VGA_SR_DATA, i);
}

static void
i915_restore_vga(struct drm_device *dev)
{
	struct s3_i915_private *s3_priv = dev->s3_private;
	int i;
	uint16_t cr_index, cr_data, st01;
	struct vgaregmap regmap;

	regmap.addr = (uint8_t *)s3_priv->saveAddr;
	regmap.handle = s3_priv->saveHandle;

	/*
	 * I/O Address Select. This bit selects 3Bxh or 3Dxh as the
	 * I/O address for the CRT Controller registers,
	 * the Feature Control Register (FCR), and Input Status Register
	 * 1 (ST01). Presently ignored (whole range is claimed), but
	 * will "ignore" 3Bx for color configuration or 3Dx for monochrome.
	 * Note that it is typical in AGP chipsets to shadow this bit
	 * and properly steer I/O cycles to the proper bus for operation
	 * where a MDA exists on another bus such as ISA.
	 * 0 = Select 3Bxh I/O address (MDA emulation) (default).
	 * 1 = Select 3Dxh I/O address (CGA emulation).
	 */
	vga_reg_put8(&regmap, VGA_MSR_WRITE, s3_priv->saveMSR);

	if (s3_priv->saveMSR & VGA_MSR_CGA_MODE) {
		cr_index = VGA_CR_INDEX_CGA;
		cr_data = VGA_CR_DATA_CGA;
		st01 = VGA_ST01_CGA;
        } else {
		cr_index = VGA_CR_INDEX_MDA;
		cr_data = VGA_CR_DATA_MDA;
		st01 = VGA_ST01_MDA;
        }
	
	/* Sequencer registers, don't write SR07 */
        for (i = 0; i < 7; i++)
		i915_write_indexed(&regmap, VGA_SR_INDEX, VGA_SR_DATA, i,
		    s3_priv->saveSR[i]);
	/* CRT controller regs */
	/* Enable CR group 0 writes */
	i915_write_indexed(&regmap, cr_index, cr_data,
	    0x11, s3_priv->saveCR[0x11]);
	for (i = 0; i <= 0x24; i++)
		i915_write_indexed(&regmap, cr_index,
		    cr_data, i, s3_priv->saveCR[i]);

	/* Graphics controller regs */
	for (i = 0; i < 9; i++)
		i915_write_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, i,
		    s3_priv->saveGR[i]);

	i915_write_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, 0x10,
	    s3_priv->saveGR[0x10]);
	i915_write_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, 0x11,
	    s3_priv->saveGR[0x11]);
	i915_write_indexed(&regmap, VGA_GR_INDEX, VGA_GR_DATA, 0x18,
	    s3_priv->saveGR[0x18]);

	/* Attribute controller registers */
	(void) vga_reg_get8(&regmap, st01); /* switch back to index mode */
	for (i = 0; i <= 0x14; i++)
	    i915_write_ar(&regmap, st01, i, s3_priv->saveAR[i], 0);
	(void) vga_reg_get8(&regmap, st01); /* switch back to index mode */
	vga_reg_put8(&regmap, VGA_AR_INDEX, s3_priv->saveAR_INDEX | 0x20);
	(void) vga_reg_get8(&regmap, st01); /* switch back to index mode */

	/* VGA color palette registers */
	vga_reg_put8(&regmap, VGA_DACMASK, s3_priv->saveDACMASK);
	/* DACCRX automatically increments during read */
	vga_reg_put8(&regmap, VGA_DACWX, 0);
	/* Read 3 bytes of color data from each index */
	for (i = 0; i < 256 * 3; i++)
		vga_reg_put8(&regmap, VGA_DACDATA, s3_priv->saveDACDATA[i]);
}

/**
 * i915_save_display - save display & mode info
 * @dev: DRM device
 *
 * Save mode timings and display info.
 */
void i915_save_display(struct drm_device *dev)
{
	struct s3_i915_private *s3_priv = dev->s3_private;

	/* Display arbitration control */
	s3_priv->saveDSPARB = S3_READ(DSPARB);

	/*
	 * Pipe & plane A info.
	 */
	s3_priv->savePIPEACONF = S3_READ(PIPEACONF);
	s3_priv->savePIPEASRC = S3_READ(PIPEASRC);
	s3_priv->saveFPA0 = S3_READ(FPA0);
	s3_priv->saveFPA1 = S3_READ(FPA1);
	s3_priv->saveDPLL_A = S3_READ(DPLL_A);
	if (IS_I965G(dev))
		s3_priv->saveDPLL_A_MD = S3_READ(DPLL_A_MD);
	s3_priv->saveHTOTAL_A = S3_READ(HTOTAL_A);
	s3_priv->saveHBLANK_A = S3_READ(HBLANK_A);
	s3_priv->saveHSYNC_A = S3_READ(HSYNC_A);
	s3_priv->saveVTOTAL_A = S3_READ(VTOTAL_A);
	s3_priv->saveVBLANK_A = S3_READ(VBLANK_A);
	s3_priv->saveVSYNC_A = S3_READ(VSYNC_A);
	s3_priv->saveBCLRPAT_A = S3_READ(BCLRPAT_A);

	s3_priv->saveDSPACNTR = S3_READ(DSPACNTR);
	s3_priv->saveDSPASTRIDE = S3_READ(DSPASTRIDE);
	s3_priv->saveDSPASIZE = S3_READ(DSPASIZE);
	s3_priv->saveDSPAPOS = S3_READ(DSPAPOS);
	s3_priv->saveDSPABASE = S3_READ(DSPABASE);
	if (IS_I965G(dev)) {
		s3_priv->saveDSPASURF = S3_READ(DSPASURF);
		s3_priv->saveDSPATILEOFF = S3_READ(DSPATILEOFF);
	}
	i915_save_palette(dev, PIPE_A);
	s3_priv->savePIPEASTAT = S3_READ(PIPEASTAT);

	/*
	 * Pipe & plane B info
	 */
	s3_priv->savePIPEBCONF = S3_READ(PIPEBCONF);
	s3_priv->savePIPEBSRC = S3_READ(PIPEBSRC);
	s3_priv->saveFPB0 = S3_READ(FPB0);
	s3_priv->saveFPB1 = S3_READ(FPB1);
	s3_priv->saveDPLL_B = S3_READ(DPLL_B);
	if (IS_I965G(dev))
		s3_priv->saveDPLL_B_MD = S3_READ(DPLL_B_MD);
	s3_priv->saveHTOTAL_B = S3_READ(HTOTAL_B);
	s3_priv->saveHBLANK_B = S3_READ(HBLANK_B);
	s3_priv->saveHSYNC_B = S3_READ(HSYNC_B);
	s3_priv->saveVTOTAL_B = S3_READ(VTOTAL_B);
	s3_priv->saveVBLANK_B = S3_READ(VBLANK_B);
	s3_priv->saveVSYNC_B = S3_READ(VSYNC_B);
	s3_priv->saveBCLRPAT_A = S3_READ(BCLRPAT_A);

	s3_priv->saveDSPBCNTR = S3_READ(DSPBCNTR);
	s3_priv->saveDSPBSTRIDE = S3_READ(DSPBSTRIDE);
	s3_priv->saveDSPBSIZE = S3_READ(DSPBSIZE);
	s3_priv->saveDSPBPOS = S3_READ(DSPBPOS);
	s3_priv->saveDSPBBASE = S3_READ(DSPBBASE);
	if (IS_I965GM(dev) || IS_GM45(dev)) {
		s3_priv->saveDSPBSURF = S3_READ(DSPBSURF);
		s3_priv->saveDSPBTILEOFF = S3_READ(DSPBTILEOFF);
	}
	i915_save_palette(dev, PIPE_B);
	s3_priv->savePIPEBSTAT = S3_READ(PIPEBSTAT);

	/*
	 * CRT state
	 */
	s3_priv->saveADPA = S3_READ(ADPA);

	/*
	 * LVDS state
	 */
	s3_priv->savePP_CONTROL = S3_READ(PP_CONTROL);
	s3_priv->savePFIT_PGM_RATIOS = S3_READ(PFIT_PGM_RATIOS);
	s3_priv->saveBLC_PWM_CTL = S3_READ(BLC_PWM_CTL);
	if (IS_I965G(dev))
		s3_priv->saveBLC_PWM_CTL2 = S3_READ(BLC_PWM_CTL2);
	if (IS_MOBILE(dev) && !IS_I830(dev))
		s3_priv->saveLVDS = S3_READ(LVDS);
	if (!IS_I830(dev) && !IS_845G(dev))
		s3_priv->savePFIT_CONTROL = S3_READ(PFIT_CONTROL);
	s3_priv->saveLVDSPP_ON = S3_READ(LVDSPP_ON);
	s3_priv->saveLVDSPP_OFF = S3_READ(LVDSPP_OFF);
	s3_priv->savePP_CYCLE = S3_READ(PP_CYCLE);

	/* FIXME: save TV & SDVO state */

	/* FBC state */
	s3_priv->saveFBC_CFB_BASE = S3_READ(FBC_CFB_BASE);
	s3_priv->saveFBC_LL_BASE = S3_READ(FBC_LL_BASE);
	s3_priv->saveFBC_CONTROL2 = S3_READ(FBC_CONTROL2);
	s3_priv->saveFBC_CONTROL = S3_READ(FBC_CONTROL);

	/* VGA state */
	s3_priv->saveVCLK_DIVISOR_VGA0 = S3_READ(VCLK_DIVISOR_VGA0);
	s3_priv->saveVCLK_DIVISOR_VGA1 = S3_READ(VCLK_DIVISOR_VGA1);
	s3_priv->saveVCLK_POST_DIV = S3_READ(VCLK_POST_DIV);
	s3_priv->saveVGACNTRL = S3_READ(VGACNTRL);

	i915_save_vga(dev);
}

void i915_restore_display(struct drm_device *dev)
{
        struct s3_i915_private *s3_priv = dev->s3_private;

	S3_WRITE(DSPARB, s3_priv->saveDSPARB);

	/* 
	 * Pipe & plane A info
	 * Prime the clock
	 */
	if (s3_priv->saveDPLL_A & DPLL_VCO_ENABLE) {
		S3_WRITE(DPLL_A, s3_priv->saveDPLL_A &
		    ~DPLL_VCO_ENABLE);
		drv_usecwait(150);
        }
	S3_WRITE(FPA0, s3_priv->saveFPA0);
	S3_WRITE(FPA1, s3_priv->saveFPA1);
	/* Actually enable it */
	S3_WRITE(DPLL_A, s3_priv->saveDPLL_A);
	drv_usecwait(150);
	if (IS_I965G(dev))
		S3_WRITE(DPLL_A_MD, s3_priv->saveDPLL_A_MD);
	drv_usecwait(150);

	/* Restore mode */
	S3_WRITE(HTOTAL_A, s3_priv->saveHTOTAL_A);
	S3_WRITE(HBLANK_A, s3_priv->saveHBLANK_A);
	S3_WRITE(HSYNC_A, s3_priv->saveHSYNC_A);
	S3_WRITE(VTOTAL_A, s3_priv->saveVTOTAL_A);
	S3_WRITE(VBLANK_A, s3_priv->saveVBLANK_A);
	S3_WRITE(VSYNC_A, s3_priv->saveVSYNC_A);
	S3_WRITE(BCLRPAT_A, s3_priv->saveBCLRPAT_A);

	/* Restore plane info */
	S3_WRITE(DSPASIZE, s3_priv->saveDSPASIZE);
	S3_WRITE(DSPAPOS, s3_priv->saveDSPAPOS);
	S3_WRITE(PIPEASRC, s3_priv->savePIPEASRC);
	S3_WRITE(DSPABASE, s3_priv->saveDSPABASE);
	S3_WRITE(DSPASTRIDE, s3_priv->saveDSPASTRIDE);
	if (IS_I965G(dev)) {
		S3_WRITE(DSPASURF, s3_priv->saveDSPASURF);
		S3_WRITE(DSPATILEOFF, s3_priv->saveDSPATILEOFF);
	}
	S3_WRITE(PIPEACONF, s3_priv->savePIPEACONF);
	i915_restore_palette(dev, PIPE_A);
	/* Enable the plane */
	S3_WRITE(DSPACNTR, s3_priv->saveDSPACNTR);
	S3_WRITE(DSPABASE, S3_READ(DSPABASE));
	
	/* Pipe & plane B info */
	if (s3_priv->saveDPLL_B & DPLL_VCO_ENABLE) {
		S3_WRITE(DPLL_B, s3_priv->saveDPLL_B &
		    ~DPLL_VCO_ENABLE);
		drv_usecwait(150);
	}
	S3_WRITE(FPB0, s3_priv->saveFPB0);
	S3_WRITE(FPB1, s3_priv->saveFPB1);
	/* Actually enable it */
	S3_WRITE(DPLL_B, s3_priv->saveDPLL_B);
	drv_usecwait(150);
	if (IS_I965G(dev))
		S3_WRITE(DPLL_B_MD, s3_priv->saveDPLL_B_MD);
	drv_usecwait(150);

	/* Restore mode */
	S3_WRITE(HTOTAL_B, s3_priv->saveHTOTAL_B);
	S3_WRITE(HBLANK_B, s3_priv->saveHBLANK_B);
	S3_WRITE(HSYNC_B, s3_priv->saveHSYNC_B);
	S3_WRITE(VTOTAL_B, s3_priv->saveVTOTAL_B);
	S3_WRITE(VBLANK_B, s3_priv->saveVBLANK_B);
	S3_WRITE(VSYNC_B, s3_priv->saveVSYNC_B);
	S3_WRITE(BCLRPAT_B, s3_priv->saveBCLRPAT_B);

	/* Restore plane info */
	S3_WRITE(DSPBSIZE, s3_priv->saveDSPBSIZE);
	S3_WRITE(DSPBPOS, s3_priv->saveDSPBPOS);
	S3_WRITE(PIPEBSRC, s3_priv->savePIPEBSRC);
	S3_WRITE(DSPBBASE, s3_priv->saveDSPBBASE);
	S3_WRITE(DSPBSTRIDE, s3_priv->saveDSPBSTRIDE);
	if (IS_I965G(dev)) {
		S3_WRITE(DSPBSURF, s3_priv->saveDSPBSURF);
		S3_WRITE(DSPBTILEOFF, s3_priv->saveDSPBTILEOFF);
        }
	S3_WRITE(PIPEBCONF, s3_priv->savePIPEBCONF);
	i915_restore_palette(dev, PIPE_B);
	/* Enable the plane */
	S3_WRITE(DSPBCNTR, s3_priv->saveDSPBCNTR);
        S3_WRITE(DSPBBASE, S3_READ(DSPBBASE));

	/* CRT state */
	S3_WRITE(ADPA, s3_priv->saveADPA);

	/* LVDS state */
	if (IS_I965G(dev))
		S3_WRITE(BLC_PWM_CTL2, s3_priv->saveBLC_PWM_CTL2);
	if (IS_MOBILE(dev) && !IS_I830(dev))
		S3_WRITE(LVDS, s3_priv->saveLVDS);
	if (!IS_I830(dev) && !IS_845G(dev))
		S3_WRITE(PFIT_CONTROL, s3_priv->savePFIT_CONTROL);

	S3_WRITE(PFIT_PGM_RATIOS, s3_priv->savePFIT_PGM_RATIOS);
	S3_WRITE(BLC_PWM_CTL, s3_priv->saveBLC_PWM_CTL);
        S3_WRITE(LVDSPP_ON, s3_priv->saveLVDSPP_ON);
        S3_WRITE(LVDSPP_OFF, s3_priv->saveLVDSPP_OFF);
        S3_WRITE(PP_CYCLE, s3_priv->savePP_CYCLE);
        S3_WRITE(PP_CONTROL, s3_priv->savePP_CONTROL);

	/* FIXME: restore TV & SDVO state */

	/* FBC info */
	S3_WRITE(FBC_CFB_BASE, s3_priv->saveFBC_CFB_BASE);
	S3_WRITE(FBC_LL_BASE, s3_priv->saveFBC_LL_BASE);
	S3_WRITE(FBC_CONTROL2, s3_priv->saveFBC_CONTROL2);
	S3_WRITE(FBC_CONTROL, s3_priv->saveFBC_CONTROL);

	/* VGA state */
	S3_WRITE(VGACNTRL, s3_priv->saveVGACNTRL);
	S3_WRITE(VCLK_DIVISOR_VGA0, s3_priv->saveVCLK_DIVISOR_VGA0);
	S3_WRITE(VCLK_DIVISOR_VGA1, s3_priv->saveVCLK_DIVISOR_VGA1);
	S3_WRITE(VCLK_POST_DIV, s3_priv->saveVCLK_POST_DIV);
	drv_usecwait(150);
	
	i915_restore_vga(dev);
}
static int
i915_resume(struct drm_device *dev)
{
	ddi_acc_handle_t conf_hdl;
	struct s3_i915_private *s3_priv = dev->s3_private;
	int i;

	if (pci_config_setup(dev->dip, &conf_hdl) != DDI_SUCCESS) {
		DRM_ERROR(("i915_resume: pci_config_setup fail"));
		return (DDI_FAILURE);
	}
	/*
	 * Nexus driver will resume pci config space and set the power state
	 * for its children. So we needn't resume them explicitly here.
	 * see pci_pre_resume for detail.
	 */
	pci_config_put8(conf_hdl, LBB, s3_priv->saveLBB);

	if (IS_I965G(dev) && IS_MOBILE(dev))
		S3_WRITE(MCHBAR_RENDER_STANDBY, s3_priv->saveRENDERSTANDBY);
	if (IS_I965GM(dev))
		(void) S3_READ(MCHBAR_RENDER_STANDBY);

	S3_WRITE(HWS_PGA, s3_priv->saveHWS);
	if (IS_I965GM(dev))
		(void) S3_READ(HWS_PGA);

	i915_restore_display(dev);

	 /* Clock gating state */
	S3_WRITE (D_STATE, s3_priv->saveD_STATE);
	S3_WRITE (CG_2D_DIS, s3_priv->saveCG_2D_DIS);

	/* Cache mode state */
	S3_WRITE (CACHE_MODE_0, s3_priv->saveCACHE_MODE_0 | 0xffff0000);

	/* Memory arbitration state */
	S3_WRITE (MI_ARB_STATE, s3_priv->saveMI_ARB_STATE | 0xffff0000);
	
	for (i = 0; i < 16; i++) {
		S3_WRITE(SWF0 + (i << 2), s3_priv->saveSWF0[i]);
		S3_WRITE(SWF10 + (i << 2), s3_priv->saveSWF1[i]);
        }
	for (i = 0; i < 3; i++)
		S3_WRITE(SWF30 + (i << 2), s3_priv->saveSWF2[i]);

	S3_WRITE(I915REG_PGTBL_CTRL, s3_priv->pgtbl_ctl);

	(void) pci_config_teardown(&conf_hdl);

	drm_agp_rebind(dev);

	return (DDI_SUCCESS);
}

static int
i915_suspend(struct drm_device *dev)
{
	ddi_acc_handle_t conf_hdl;
	struct s3_i915_private *s3_priv = dev->s3_private;
	int i;

	if (pci_config_setup(dev->dip, &conf_hdl) != DDI_SUCCESS) {
		DRM_ERROR(("i915_suspend: pci_config_setup fail"));
		return (DDI_FAILURE);
	}

	/*
	 * Nexus driver will resume pci config space for its children.
	 * So pci config registers are not saved here.
	 */
	s3_priv->saveLBB = pci_config_get8(conf_hdl, LBB);

	if (IS_I965G(dev) && IS_MOBILE(dev))
		s3_priv->saveRENDERSTANDBY = S3_READ(MCHBAR_RENDER_STANDBY);

	/* Hardware status page */
	s3_priv->saveHWS = S3_READ(HWS_PGA);

	i915_save_display(dev);

	/* Interrupt state */
	s3_priv->saveIIR = S3_READ(IIR);
	s3_priv->saveIER = S3_READ(IER);
	s3_priv->saveIMR = S3_READ(IMR);

	/* Clock gating state */
	s3_priv->saveD_STATE = S3_READ(D_STATE);
	s3_priv->saveCG_2D_DIS = S3_READ(CG_2D_DIS);

	/* Cache mode state */
	s3_priv->saveCACHE_MODE_0 = S3_READ(CACHE_MODE_0);

	/* Memory Arbitration state */
	s3_priv->saveMI_ARB_STATE = S3_READ(MI_ARB_STATE);

	/* Scratch space */
	for (i = 0; i < 16; i++) {
		s3_priv->saveSWF0[i] = S3_READ(SWF0 + (i << 2));
		s3_priv->saveSWF1[i] = S3_READ(SWF10 + (i << 2));
	}
	for (i = 0; i < 3; i++)
		s3_priv->saveSWF2[i] = S3_READ(SWF30 + (i << 2));

	/*
	 * Save page table control register
	 */
	s3_priv->pgtbl_ctl = S3_READ(I915REG_PGTBL_CTRL);

	(void) pci_config_teardown(&conf_hdl);

	return (DDI_SUCCESS);
}

/*
 * This funtion check the length of memory mapped IO space to get the right bar. * And There are two possibilities here.
 * 1. The MMIO registers is in memory map IO bar with 1M size. The bottom half
 *    of the 1M space is the MMIO registers.
 * 2. The MMIO register is in memory map IO with 512K size. The whole 512K
 *    space is the MMIO registers.
 */
static int
i915_map_regs(dev_info_t *dip, caddr_t *save_addr, ddi_acc_handle_t *handlep)
{
	int	rnumber;
	int	nregs;
	off_t	size = 0;

	if (ddi_dev_nregs(dip, &nregs)) {
		cmn_err(CE_WARN, "i915_map_regs: failed to get nregs");
		return (DDI_FAILURE);
	}
	
	for (rnumber = 1; rnumber < nregs; rnumber++) {
		(void) ddi_dev_regsize(dip, rnumber, &size);
		if ((size == 0x80000) ||
		    (size == 0x100000) ||
		    (size == 0x400000))
			break;
	}

	if (rnumber >= nregs) {
		cmn_err(CE_WARN,
		    "i915_map_regs: failed to find MMIO registers");
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(dip, rnumber, save_addr,
	    0, 0x80000, &s3_attr, handlep)) {
		cmn_err(CE_WARN,
		    "i915_map_regs: failed to map bar %d", rnumber);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}
static void
i915_unmap_regs(ddi_acc_handle_t *handlep)
{
	ddi_regs_map_free(handlep);
}
static int
i915_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{	
	drm_device_t		*statep;
	s3_i915_private_t	*s3_private;
	void		*handle;
	int			unit;

	unit =  ddi_get_instance(dip);
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		statep = ddi_get_soft_state(i915_statep, unit);
		return (i915_resume(statep));
	default:
		DRM_ERROR("i915_attach: attach and resume ops are supported");
		return (DDI_FAILURE);
		
	}

	if (ddi_soft_state_zalloc(i915_statep, unit) != DDI_SUCCESS) {
			cmn_err(CE_WARN,
			    "i915_attach: failed to alloc softstate");
			return (DDI_FAILURE);
	}
	statep = ddi_get_soft_state(i915_statep, unit);
	statep->dip = dip;
	statep->driver = &i915_driver;

	statep->s3_private = drm_alloc(sizeof(s3_i915_private_t),
	    DRM_MEM_DRIVER);

	if (statep->s3_private == NULL) {
		cmn_err(CE_WARN, "i915_attach: failed to allocate s3 priv");
		goto err_exit1;
	}	

	/*
	 * Map in the mmio register space for s3.
	 */
	s3_private = (s3_i915_private_t *)statep->s3_private;
	
	if (i915_map_regs(dip, &s3_private->saveAddr,
	    &s3_private->saveHandle)) {
		cmn_err(CE_WARN, "i915_attach: failed to map MMIO");
		goto err_exit2;
	}

	/*
	 * Call drm_supp_register to create minor nodes for us
	 */
	handle = drm_supp_register(dip, statep);
	if ( handle == NULL) {
		DRM_ERROR("i915_attach: drm_supp_register failed");
		goto err_exit3;
	}
	statep->drm_handle = handle;

	/*
	 * After drm_supp_register, we can call drm_xxx routine
	 */
	statep->drm_supported = DRM_UNSUPPORT;
	if (
		    drm_probe(statep, i915_pciidlist) != DDI_SUCCESS) {
		DRM_ERROR("i915_open: "
		    "DRM current don't support this graphics card");
		goto err_exit4;
	}
	statep->drm_supported = DRM_SUPPORT;

	/* call common attach code */
	if (drm_attach(statep) != DDI_SUCCESS) {
		DRM_ERROR("i915_attach: drm_attach failed");
		goto err_exit4;
	}
	return (DDI_SUCCESS);
err_exit4:
	(void) drm_supp_unregister(handle);
err_exit3:
	i915_unmap_regs(&s3_private->saveHandle);
err_exit2:
	drm_free(statep->s3_private, sizeof(s3_i915_private_t),
	    DRM_MEM_DRIVER);
err_exit1:
	(void) ddi_soft_state_free(i915_statep, unit);

	return (DDI_FAILURE);

}	/* i915_attach() */

static int
i915_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)    
{
	drm_device_t		*statep;
	int		unit;
	s3_i915_private_t	*s3_private;

	if ((cmd != DDI_SUSPEND) && (cmd != DDI_DETACH)) {
			DRM_ERROR("i915_detach: "
			    "only detach and resume ops are supported");
			return (DDI_FAILURE);
	}

	unit =  ddi_get_instance(dip);
	statep = ddi_get_soft_state(i915_statep, unit);
	if (statep == NULL) {
		DRM_ERROR("i915_detach: can not get soft state");
		return (DDI_FAILURE);
	}

	if (cmd == DDI_SUSPEND)
			return (i915_suspend(statep));

	s3_private = (s3_i915_private_t *)statep->s3_private;
	ddi_regs_map_free(&s3_private->saveHandle);

	/*
	 * Free the struct for context saving in S3
	 */
	drm_free(statep->s3_private, sizeof(s3_i915_private_t),
	    DRM_MEM_DRIVER);

	(void) drm_detach(statep);
	(void) drm_supp_unregister(statep->drm_handle);
	(void) ddi_soft_state_free(i915_statep, unit);

	return (DDI_SUCCESS);

}	/* i915_detach() */


/*ARGSUSED*/
static int
i915_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	drm_device_t		*statep;
	int 	error = DDI_SUCCESS;
	int 	unit;

	unit = drm_dev_to_instance((dev_t)arg);
	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		statep = ddi_get_soft_state(i915_statep, unit);
		if (statep == NULL || statep->dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) statep->dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)unit;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);

}	/* i915_info() */


static void i915_configure(drm_driver_t *driver)
{
	driver->buf_priv_size	=	1;	/* No dev_priv */
	driver->load	=	i915_driver_load;
	driver->unload	=	i915_driver_unload;
	driver->open	=	i915_driver_open;
	driver->preclose	=	i915_driver_preclose;
	driver->postclose	=	i915_driver_postclose;
	driver->lastclose	=	i915_driver_lastclose;
	driver->device_is_agp	=	i915_driver_device_is_agp;
	driver->enable_vblank	= 	i915_enable_vblank;
	driver->disable_vblank	= 	i915_disable_vblank;
	driver->irq_preinstall	=	i915_driver_irq_preinstall;
	driver->irq_postinstall	=	i915_driver_irq_postinstall;
	driver->irq_uninstall	=	i915_driver_irq_uninstall;
	driver->irq_handler 	=	i915_driver_irq_handler;

	driver->gem_init_object = 	i915_gem_init_object;
	driver->gem_free_object = 	i915_gem_free_object;

	driver->driver_ioctls	=	i915_ioctls;
	driver->max_driver_ioctl	=	i915_max_ioctl;

	driver->driver_name	=	DRIVER_NAME;
	driver->driver_desc	=	DRIVER_DESC;
	driver->driver_date	=	DRIVER_DATE;
	driver->driver_major	=	DRIVER_MAJOR;
	driver->driver_minor	=	DRIVER_MINOR;
	driver->driver_patchlevel	=	DRIVER_PATCHLEVEL;

	driver->use_agp	=	1;
	driver->require_agp	=	1;
	driver->use_irq	=	1;
}

static int i915_quiesce(dev_info_t *dip)
{	
	drm_device_t		*statep;
	int		unit;

	unit =  ddi_get_instance(dip);
	statep = ddi_get_soft_state(i915_statep, unit);
	if (statep == NULL) {
		return (DDI_FAILURE);
	}
	i915_driver_irq_uninstall(statep);

	return (DDI_SUCCESS);
}
