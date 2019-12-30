/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 */

/*
 * Generic framebuffer interface. Implementing common interfaces
 * for bitmapped frame buffer and vgatext.
 */
#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/visual_io.h>
#include <sys/vgareg.h>
#include <sys/vgasubr.h>
#include <sys/pci.h>
#include <sys/boot_console.h>
#include <sys/kd.h>
#include <sys/fbio.h>
#include <sys/gfx_private.h>
#include "gfxp_fb.h"

#define	MYNAME	"gfxp_fb"

/* need to keep vgatext symbols for compatibility */
#pragma weak gfxp_vgatext_softc_alloc = gfxp_fb_softc_alloc
#pragma weak gfxp_vgatext_softc_free = gfxp_fb_softc_free
#pragma weak gfxp_vgatext_attach = gfxp_fb_attach
#pragma weak gfxp_vgatext_detach = gfxp_fb_detach
#pragma weak gfxp_vgatext_open = gfxp_fb_open
#pragma weak gfxp_vgatext_close = gfxp_fb_close
#pragma weak gfxp_vgatext_ioctl = gfxp_fb_ioctl
#pragma weak gfxp_vgatext_devmap = gfxp_fb_devmap

/*
 * NOTE: this function is duplicated here and in consplat/vgatext while
 *       we work on a set of commitable interfaces to sunpci.c.
 *
 * Use the class code to determine if the device is a PCI-to-PCI bridge.
 * Returns:  B_TRUE  if the device is a bridge.
 *           B_FALSE if the device is not a bridge or the property cannot be
 *		     retrieved.
 */
static boolean_t
is_pci_bridge(dev_info_t *dip)
{
	uint32_t class_code;

	class_code = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "class-code", 0xffffffff);

	if (class_code == 0xffffffff || class_code == DDI_PROP_NOT_FOUND)
		return (B_FALSE);

	class_code &= 0x00ffff00;
	if (class_code == ((PCI_CLASS_BRIDGE << 16) | (PCI_BRIDGE_PCI << 8)))
		return (B_TRUE);

	return (B_FALSE);
}

#define	STREQ(a, b)	(strcmp((a), (b)) == 0)

static void
gfxp_check_for_console(dev_info_t *devi, struct gfxp_fb_softc *softc,
    int pci_pcie_bus)
{
	ddi_acc_handle_t pci_conf;
	dev_info_t *pdevi;
	uint16_t data16;

	/*
	 * Based on Section 11.3, "PCI Display Subsystem Initialization",
	 * of the 1.1 PCI-to-PCI Bridge Architecture Specification
	 * determine if this is the boot console device.  First, see
	 * if the SBIOS has turned on PCI I/O for this device.  Then if
	 * this is PCI/PCI-E, verify the parent bridge has VGAEnable set.
	 */

	if (pci_config_setup(devi, &pci_conf) != DDI_SUCCESS) {
		cmn_err(CE_WARN, MYNAME ": can't get PCI conf handle");
		return;
	}

	data16 = pci_config_get16(pci_conf, PCI_CONF_COMM);
	if (data16 & PCI_COMM_IO)
		softc->flags |= GFXP_FLAG_CONSOLE;

	pci_config_teardown(&pci_conf);

	/* If IO not enabled or ISA/EISA, just return */
	if (!(softc->flags & GFXP_FLAG_CONSOLE) || !pci_pcie_bus)
		return;

	/*
	 * Check for VGA Enable in the Bridge Control register for all
	 * PCI/PCIEX parents.  If not set all the way up the chain,
	 * this cannot be the boot console.
	 */

	pdevi = devi;
	while (pdevi = ddi_get_parent(pdevi)) {
		int	error;
		ddi_acc_handle_t ppci_conf;
		char	*parent_type = NULL;

		error = ddi_prop_lookup_string(DDI_DEV_T_ANY, pdevi,
		    DDI_PROP_DONTPASS, "device_type", &parent_type);
		if (error != DDI_SUCCESS) {
			return;
		}

		/* Verify still on the PCI/PCIEX parent tree */
		if (!STREQ(parent_type, "pci") &&
		    !STREQ(parent_type, "pciex")) {
			ddi_prop_free(parent_type);
			return;
		}

		ddi_prop_free(parent_type);
		parent_type = NULL;

		/* VGAEnable is set only for PCI-to-PCI bridges. */
		if (is_pci_bridge(pdevi) == B_FALSE)
			continue;

		if (pci_config_setup(pdevi, &ppci_conf) != DDI_SUCCESS)
			continue;

		data16 = pci_config_get16(ppci_conf, PCI_BCNF_BCNTRL);
		pci_config_teardown(&ppci_conf);

		if (!(data16 & PCI_BCNF_BCNTRL_VGA_ENABLE)) {
			softc->flags &= ~GFXP_FLAG_CONSOLE;
			return;
		}
	}
}

gfxp_fb_softc_ptr_t
gfxp_fb_softc_alloc(void)
{
	return (kmem_zalloc(sizeof (struct gfxp_fb_softc), KM_SLEEP));
}

void
gfxp_fb_softc_free(gfxp_fb_softc_ptr_t ptr)
{
	kmem_free(ptr, sizeof (struct gfxp_fb_softc));
}

void
gfxp_fb_resume(struct gfxp_fb_softc *softc)
{
	if (softc->gfxp_ops->resume != NULL)
		softc->gfxp_ops->resume(softc);
}

int
gfxp_fb_suspend(struct gfxp_fb_softc *softc)
{
	if (softc->gfxp_ops->suspend != NULL)
		return (softc->gfxp_ops->suspend(softc));
	return (DDI_FAILURE);
}

int
gfxp_fb_attach(dev_info_t *devi, ddi_attach_cmd_t cmd, gfxp_fb_softc_ptr_t ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;
	int	error;
	char	*parent_type = NULL;
	int pci_pcie_bus = 0;
	int value;

	if (softc == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		gfxp_fb_resume(softc);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	/* DDI_ATTACH */
	softc->devi = devi; /* Copy and init DEVI */
	softc->polledio.arg = (struct vis_polledio_arg *)softc;
	softc->mode = -1;	/* the actual value will be set by tem */
	mutex_init(&(softc->lock), NULL, MUTEX_DRIVER, NULL);

	error = ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_get_parent(devi),
	    DDI_PROP_DONTPASS, "device_type", &parent_type);
	if (error != DDI_SUCCESS) {
		cmn_err(CE_WARN, MYNAME ": can't determine parent type.");
		goto fail;
	}

	if (STREQ(parent_type, "pci") || STREQ(parent_type, "pciex")) {
		pci_pcie_bus = 1;
	}
	ddi_prop_free(parent_type);
	gfxp_check_for_console(devi, softc, pci_pcie_bus);

	value = GFXP_IS_CONSOLE(softc) ? 1 : 0;
	if (ddi_prop_update_int(DDI_DEV_T_NONE, devi,
	    "primary-controller", value) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
		    "Cannot %s primary-controller "
		    "property for driver", value ? "set" : "clear");
	}

	switch (fb_info.fb_type) {
	case FB_TYPE_UNINITIALIZED:
		/*
		 * While booting from MB1, we do not have FB.
		 * Fall through.
		 */
	case FB_TYPE_EGA_TEXT:
		softc->fb_type = GFXP_VGATEXT;
		error = gfxp_vga_attach(devi, softc);
		break;

	case FB_TYPE_INDEXED:	/* FB types */
	case FB_TYPE_RGB:
		softc->fb_type = GFXP_BITMAP;
		error = gfxp_bm_attach(devi, softc);
		break;

	default:
		error = DDI_FAILURE;
	}

	if (error == DDI_SUCCESS)
		return (error);

	(void) ddi_prop_remove(DDI_DEV_T_ANY, devi, "primary-controller");
fail:
	(void) gfxp_fb_detach(devi, DDI_DETACH, (void *)softc);
	return (error);
}

int
gfxp_fb_detach(dev_info_t *devi, ddi_detach_cmd_t cmd, gfxp_fb_softc_ptr_t ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;
	int error;

	if (softc == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_SUSPEND:
		return (gfxp_fb_suspend(softc));

	case DDI_DETACH:
		(void) ddi_prop_remove(DDI_DEV_T_ANY, devi,
		    "primary-controller");
		error = DDI_SUCCESS;
		switch (softc->fb_type) {
		case GFXP_BITMAP:
			error = gfxp_bm_detach(devi, softc);
			break;
		case GFXP_VGATEXT:
			error = gfxp_vga_detach(devi, softc);
			break;
		}
		mutex_destroy(&(softc->lock));
		return (error);

	default:
		cmn_err(CE_WARN, "gfxp_fb_detach: unknown cmd 0x%x\n",
		    cmd);
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
int
gfxp_fb_open(dev_t *devp, int flag, int otyp, cred_t *cred,
    gfxp_fb_softc_ptr_t ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;

	if (softc == NULL || otyp == OTYP_BLK)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
int
gfxp_fb_close(dev_t devp, int flag, int otyp, cred_t *cred,
    gfxp_fb_softc_ptr_t ptr)
{
	return (0);
}

static int
do_gfx_ioctl(int cmd, intptr_t data, int mode, struct gfxp_fb_softc *softc)
{
	static char kernel_only[] =
	    "gfxp_fb_ioctl: %s is a kernel only ioctl";
	int err;
	int kd_mode;

	switch (cmd) {
	case KDSETMODE:
		kd_mode = (int)data;
		if ((kd_mode == softc->mode) || (!GFXP_IS_CONSOLE(softc)))
			break;
		return (softc->gfxp_ops->kdsetmode(softc, kd_mode));

	case KDGETMODE:
		kd_mode = softc->mode;
		if (ddi_copyout(&kd_mode, (void *)data, sizeof (int), mode))
			return (EFAULT);
		break;

	case VIS_GETIDENTIFIER:
		if (ddi_copyout(softc->gfxp_ops->ident, (void *)data,
		    sizeof (struct vis_identifier), mode))
			return (EFAULT);
		break;

	case VIS_DEVINIT:

		if (!(mode & FKIOCTL)) {
			cmn_err(CE_CONT, kernel_only, "VIS_DEVINIT");
			return (ENXIO);
		}

		err = softc->gfxp_ops->devinit(softc,
		    (struct vis_devinit *)data);
		if (err != 0) {
			cmn_err(CE_WARN,
			    "gfxp_fb_ioctl:  could not initialize console");
			return (err);
		}
		break;

	case VIS_CONSCLEAR:	/* clear screen */
	{
		struct vis_consclear pma;

		if (ddi_copyin((void *)data, &pma,
		    sizeof (struct vis_consclear), mode))
			return (EFAULT);

		return (softc->gfxp_ops->cons_clear(softc, &pma));
	}

	case VIS_CONSCOPY:	/* move */
	{
		struct vis_conscopy pma;

		if (ddi_copyin((void *)data, &pma,
		    sizeof (struct vis_conscopy), mode))
			return (EFAULT);

		softc->gfxp_ops->cons_copy(softc, &pma);
		break;
	}

	case VIS_CONSDISPLAY:	/* display */
	{
		struct vis_consdisplay display_request;

		if (ddi_copyin((void *)data, &display_request,
		    sizeof (display_request), mode))
			return (EFAULT);

		softc->gfxp_ops->cons_display(softc, &display_request);
		break;
	}

	case VIS_CONSCURSOR:
	{
		struct vis_conscursor cursor_request;

		if (ddi_copyin((void *)data, &cursor_request,
		    sizeof (cursor_request), mode))
			return (EFAULT);

		softc->gfxp_ops->cons_cursor(softc, &cursor_request);

		if (cursor_request.action == VIS_GET_CURSOR &&
		    ddi_copyout(&cursor_request, (void *)data,
		    sizeof (cursor_request), mode))
			return (EFAULT);
		break;
	}

	case VIS_GETCMAP:
	case VIS_PUTCMAP:
	case FBIOPUTCMAP:
	case FBIOGETCMAP:
		/*
		 * At the moment, text mode is not considered to have
		 * a color map.
		 */
		return (EINVAL);

	case FBIOGATTR:
		if (copyout(softc->fbgattr, (void *)data,
		    sizeof (struct fbgattr)))
			return (EFAULT);
		break;

	case FBIOGTYPE:
		if (copyout(&softc->fbgattr->fbtype, (void *)data,
		    sizeof (struct fbtype)))
			return (EFAULT);
		break;

	default:
		cmn_err(CE_CONT, "!unimplemented cmd: 0x%x\n", cmd);
		return (ENXIO);
	}
	return (0);
}

/*ARGSUSED*/
int
gfxp_fb_ioctl(dev_t dev, int cmd, intptr_t data, int mode,
    cred_t *cred, int *rval, gfxp_fb_softc_ptr_t ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;
	int error = DDI_FAILURE;

	if (softc == NULL)
		return (error);
	mutex_enter(&(softc->lock));
	error = do_gfx_ioctl(cmd, data, mode, softc);
	mutex_exit(&(softc->lock));
	return (error);
}

int
gfxp_fb_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off,
    size_t len, size_t *maplen, uint_t model, void *ptr)
{
	struct gfxp_fb_softc *softc = (struct gfxp_fb_softc *)ptr;

	if (softc == NULL)
		return (DDI_FAILURE);

	return (softc->gfxp_ops->devmap(dev, dhp, off, len, maplen,
	    model, ptr));
}
