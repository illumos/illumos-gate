/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This module provides support for labeling operations for target
 * drivers.
 */

#include <sys/scsi/scsi.h>
#include <sys/sunddi.h>
#include <sys/dklabel.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/dktp/fdisk.h>
#include <sys/vtrace.h>
#include <sys/efi_partition.h>
#include <sys/cmlb.h>
#include <sys/cmlb_impl.h>


/*
 * Driver minor node structure and data table
 */
struct driver_minor_data {
	char	*name;
	minor_t	minor;
	int	type;
};

static struct driver_minor_data dk_minor_data[] = {
	{"a", 0, S_IFBLK},
	{"b", 1, S_IFBLK},
	{"c", 2, S_IFBLK},
	{"d", 3, S_IFBLK},
	{"e", 4, S_IFBLK},
	{"f", 5, S_IFBLK},
	{"g", 6, S_IFBLK},
	{"h", 7, S_IFBLK},
#if defined(_SUNOS_VTOC_16)
	{"i", 8, S_IFBLK},
	{"j", 9, S_IFBLK},
	{"k", 10, S_IFBLK},
	{"l", 11, S_IFBLK},
	{"m", 12, S_IFBLK},
	{"n", 13, S_IFBLK},
	{"o", 14, S_IFBLK},
	{"p", 15, S_IFBLK},
#endif			/* defined(_SUNOS_VTOC_16) */
#if defined(_FIRMWARE_NEEDS_FDISK)
	{"q", 16, S_IFBLK},
	{"r", 17, S_IFBLK},
	{"s", 18, S_IFBLK},
	{"t", 19, S_IFBLK},
	{"u", 20, S_IFBLK},
#endif			/* defined(_FIRMWARE_NEEDS_FDISK) */
	{"a,raw", 0, S_IFCHR},
	{"b,raw", 1, S_IFCHR},
	{"c,raw", 2, S_IFCHR},
	{"d,raw", 3, S_IFCHR},
	{"e,raw", 4, S_IFCHR},
	{"f,raw", 5, S_IFCHR},
	{"g,raw", 6, S_IFCHR},
	{"h,raw", 7, S_IFCHR},
#if defined(_SUNOS_VTOC_16)
	{"i,raw", 8, S_IFCHR},
	{"j,raw", 9, S_IFCHR},
	{"k,raw", 10, S_IFCHR},
	{"l,raw", 11, S_IFCHR},
	{"m,raw", 12, S_IFCHR},
	{"n,raw", 13, S_IFCHR},
	{"o,raw", 14, S_IFCHR},
	{"p,raw", 15, S_IFCHR},
#endif			/* defined(_SUNOS_VTOC_16) */
#if defined(_FIRMWARE_NEEDS_FDISK)
	{"q,raw", 16, S_IFCHR},
	{"r,raw", 17, S_IFCHR},
	{"s,raw", 18, S_IFCHR},
	{"t,raw", 19, S_IFCHR},
	{"u,raw", 20, S_IFCHR},
#endif			/* defined(_FIRMWARE_NEEDS_FDISK) */
	{0}
};

static struct driver_minor_data dk_minor_data_efi[] = {
	{"a", 0, S_IFBLK},
	{"b", 1, S_IFBLK},
	{"c", 2, S_IFBLK},
	{"d", 3, S_IFBLK},
	{"e", 4, S_IFBLK},
	{"f", 5, S_IFBLK},
	{"g", 6, S_IFBLK},
	{"wd", 7, S_IFBLK},
#if defined(_FIRMWARE_NEEDS_FDISK)
	{"q", 16, S_IFBLK},
	{"r", 17, S_IFBLK},
	{"s", 18, S_IFBLK},
	{"t", 19, S_IFBLK},
	{"u", 20, S_IFBLK},
#endif			/* defined(_FIRMWARE_NEEDS_FDISK) */
	{"a,raw", 0, S_IFCHR},
	{"b,raw", 1, S_IFCHR},
	{"c,raw", 2, S_IFCHR},
	{"d,raw", 3, S_IFCHR},
	{"e,raw", 4, S_IFCHR},
	{"f,raw", 5, S_IFCHR},
	{"g,raw", 6, S_IFCHR},
	{"wd,raw", 7, S_IFCHR},
#if defined(_FIRMWARE_NEEDS_FDISK)
	{"q,raw", 16, S_IFCHR},
	{"r,raw", 17, S_IFCHR},
	{"s,raw", 18, S_IFCHR},
	{"t,raw", 19, S_IFCHR},
	{"u,raw", 20, S_IFCHR},
#endif			/* defined(_FIRMWARE_NEEDS_FDISK) */
	{0}
};



extern struct mod_ops mod_miscops;

/*
 * Global buffer and mutex for debug logging
 */
static char	cmlb_log_buffer[1024];
static kmutex_t	cmlb_log_mutex;


struct cmlb_lun *cmlb_debug_un = NULL;
uint_t cmlb_level_mask = 0x0;

int cmlb_rot_delay = 4;	/* default rotational delay */

static struct modlmisc modlmisc = {
	&mod_miscops,   /* Type of module */
	"Common Labeling module %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

/* Local function prototypes */
static dev_t cmlb_make_device(struct cmlb_lun *un);
static int cmlb_validate_geometry(struct cmlb_lun *un, int forcerevalid);
static void cmlb_resync_geom_caches(struct cmlb_lun *un, diskaddr_t capacity);
static int cmlb_read_fdisk(struct cmlb_lun *un, diskaddr_t capacity);
static void cmlb_swap_efi_gpt(efi_gpt_t *e);
static void cmlb_swap_efi_gpe(int nparts, efi_gpe_t *p);
static int cmlb_validate_efi(efi_gpt_t *labp);
static int cmlb_use_efi(struct cmlb_lun *un, diskaddr_t capacity);
static void cmlb_build_default_label(struct cmlb_lun *un);
static int  cmlb_uselabel(struct cmlb_lun *un,  struct dk_label *l);
static void cmlb_build_user_vtoc(struct cmlb_lun *un, struct vtoc *user_vtoc);
static int cmlb_build_label_vtoc(struct cmlb_lun *un, struct vtoc *user_vtoc);
static int cmlb_write_label(struct cmlb_lun *un);
static int cmlb_set_vtoc(struct cmlb_lun *un, struct dk_label *dkl);
static void cmlb_clear_efi(struct cmlb_lun *un);
static void cmlb_clear_vtoc(struct cmlb_lun *un);
static void cmlb_setup_default_geometry(struct cmlb_lun *un);
static int cmlb_create_minor_nodes(struct cmlb_lun *un);
static int cmlb_check_update_blockcount(struct cmlb_lun *un);

#if defined(__i386) || defined(__amd64)
static int cmlb_update_fdisk_and_vtoc(struct cmlb_lun *un);
#endif

#if defined(_FIRMWARE_NEEDS_FDISK)
static int  cmlb_has_max_chs_vals(struct ipart *fdp);
#endif

#if defined(_SUNOS_VTOC_16)
static void cmlb_convert_geometry(diskaddr_t capacity, struct dk_geom *un_g);
#endif

static int cmlb_dkio_get_geometry(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_set_geometry(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_get_partition(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_set_partition(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_get_efi(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_set_efi(struct cmlb_lun *un, dev_t dev, caddr_t arg,
    int flag);
static int cmlb_dkio_get_vtoc(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_set_vtoc(struct cmlb_lun *un, dev_t dev, caddr_t arg,
    int flag);
static int cmlb_dkio_get_mboot(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_set_mboot(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_partition(struct cmlb_lun *un, caddr_t arg, int flag);

#if defined(__i386) || defined(__amd64)
static int cmlb_dkio_get_virtgeom(struct cmlb_lun *un, caddr_t arg, int flag);
static int cmlb_dkio_get_phygeom(struct cmlb_lun *un, caddr_t  arg, int flag);
static int cmlb_dkio_partinfo(struct cmlb_lun *un, dev_t dev, caddr_t arg,
    int flag);
#endif

static void cmlb_dbg(uint_t comp, struct cmlb_lun *un, const char *fmt, ...);
static void cmlb_v_log(dev_info_t *dev, char *label, uint_t level,
    const char *fmt, va_list ap);
static void cmlb_log(dev_info_t *dev, char *label, uint_t level,
    const char *fmt, ...);

int
_init(void)
{
	mutex_init(&cmlb_log_mutex, NULL, MUTEX_DRIVER, NULL);
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0) {
		return (err);
	}

	mutex_destroy(&cmlb_log_mutex);
	return (err);
}

/*
 * cmlb_dbg is used for debugging to log additional info
 * Level of output is controlled via cmlb_level_mask setting.
 */
static void
cmlb_dbg(uint_t comp, struct cmlb_lun *un, const char *fmt, ...)
{
	va_list		ap;
	dev_info_t	*dev;
	uint_t		level_mask = 0;

	ASSERT(un != NULL);
	dev = CMLB_DEVINFO(un);
	ASSERT(dev != NULL);
	/*
	 * Filter messages based on the global component and level masks,
	 * also print if un matches the value of cmlb_debug_un, or if
	 * cmlb_debug_un is set to NULL.
	 */
	if (comp & CMLB_TRACE)
		level_mask |= CMLB_LOGMASK_TRACE;

	if (comp & CMLB_INFO)
		level_mask |= CMLB_LOGMASK_INFO;

	if (comp & CMLB_ERROR)
		level_mask |= CMLB_LOGMASK_ERROR;

	if ((cmlb_level_mask & level_mask) &&
	    ((cmlb_debug_un == NULL) || (cmlb_debug_un == un))) {
		va_start(ap, fmt);
		cmlb_v_log(dev, CMLB_LABEL(un), CE_CONT, fmt, ap);
		va_end(ap);
	}
}

/*
 * cmlb_log is basically a duplicate of scsi_log. It is redefined here
 * so that this module does not depend on scsi module.
 */
static void
cmlb_log(dev_info_t *dev, char *label, uint_t level, const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	cmlb_v_log(dev, label, level, fmt, ap);
	va_end(ap);
}

static void
cmlb_v_log(dev_info_t *dev, char *label, uint_t level, const char *fmt,
    va_list ap)
{
	static char 	name[256];
	int 		log_only = 0;
	int 		boot_only = 0;
	int 		console_only = 0;

	mutex_enter(&cmlb_log_mutex);

	if (dev) {
		if (level == CE_PANIC || level == CE_WARN ||
		    level == CE_NOTE) {
			(void) sprintf(name, "%s (%s%d):\n",
			    ddi_pathname(dev, cmlb_log_buffer),
			    label, ddi_get_instance(dev));
		} else {
			name[0] = '\0';
		}
	} else {
		(void) sprintf(name, "%s:", label);
	}

	(void) vsprintf(cmlb_log_buffer, fmt, ap);

	switch (cmlb_log_buffer[0]) {
	case '!':
		log_only = 1;
		break;
	case '?':
		boot_only = 1;
		break;
	case '^':
		console_only = 1;
		break;
	}

	switch (level) {
	case CE_NOTE:
		level = CE_CONT;
		/* FALLTHROUGH */
	case CE_CONT:
	case CE_WARN:
	case CE_PANIC:
		if (boot_only) {
			cmn_err(level, "?%s\t%s", name, &cmlb_log_buffer[1]);
		} else if (console_only) {
			cmn_err(level, "^%s\t%s", name, &cmlb_log_buffer[1]);
		} else if (log_only) {
			cmn_err(level, "!%s\t%s", name, &cmlb_log_buffer[1]);
		} else {
			cmn_err(level, "%s\t%s", name, cmlb_log_buffer);
		}
		break;
	case CE_IGNORE:
		break;
	default:
		cmn_err(CE_CONT, "^DEBUG: %s\t%s", name, cmlb_log_buffer);
		break;
	}
	mutex_exit(&cmlb_log_mutex);
}


/*
 * cmlb_alloc_handle:
 *
 *	Allocates a handle.
 *
 * Arguments:
 *	cmlbhandlep	pointer to handle
 *
 * Notes:
 *	Allocates a handle and stores the allocated handle in the area
 *	pointed to by cmlbhandlep
 *
 * Context:
 *	Kernel thread only (can sleep).
 */
void
cmlb_alloc_handle(cmlb_handle_t *cmlbhandlep)
{
	struct cmlb_lun 	*un;

	un = kmem_zalloc(sizeof (struct cmlb_lun), KM_SLEEP);
	ASSERT(cmlbhandlep != NULL);

	un->un_state = CMLB_INITED;
	un->un_def_labeltype = CMLB_LABEL_UNDEF;
	mutex_init(CMLB_MUTEX(un), NULL, MUTEX_DRIVER, NULL);

	*cmlbhandlep = (cmlb_handle_t)(un);
}

/*
 * cmlb_free_handle
 *
 *	Frees handle.
 *
 * Arguments:
 *	cmlbhandlep	pointer to handle
 */
void
cmlb_free_handle(cmlb_handle_t *cmlbhandlep)
{
	struct cmlb_lun 	*un;

	un = (struct cmlb_lun *)*cmlbhandlep;
	if (un != NULL) {
		mutex_destroy(CMLB_MUTEX(un));
		kmem_free(un, sizeof (struct cmlb_lun));
	}

}

/*
 * cmlb_attach:
 *
 *	Attach handle to device, create minor nodes for device.
 *
 * Arguments:
 * 	devi		pointer to device's dev_info structure.
 * 	tgopsp		pointer to array of functions cmlb can use to callback
 *			to target driver.
 *
 *	device_type	Peripheral device type as defined in
 *			scsi/generic/inquiry.h
 *
 *	is_removable	whether or not device is removable.
 *			0 non-removable, 1 removable.
 *
 *	node_type	minor node type (as used by ddi_create_minor_node)
 *
 *	alter_behavior
 *			bit flags:
 *
 *			CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT: create
 *			an alternate slice for the default label, if
 *			device type is DTYPE_DIRECT an architectures default
 *			label type is VTOC16.
 *			Otherwise alternate slice will no be created.
 *
 *
 *			CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8: report a default
 *			geometry and label for DKIOCGGEOM and DKIOCGVTOC
 *			on architecture with VTOC8 label types.
 *
 *
 *	cmlbhandle	cmlb handle associated with device
 *
 * Notes:
 *	Assumes a default label based on capacity for non-removable devices.
 *	If capacity > 1TB, EFI is assumed otherwise VTOC (default VTOC
 *	for the architecture).
 *
 *	For removable devices, default label type is assumed to be VTOC
 *	type. Create minor nodes based on a default label type.
 *	Label on the media is not validated.
 *	minor number consists of:
 *		if _SUNOS_VTOC_8 is defined
 *			lowest 3 bits is taken as partition number
 *			the rest is instance number
 *		if _SUNOS_VTOC_16 is defined
 *			lowest 6 bits is taken as partition number
 *			the rest is instance number
 *
 *
 * Return values:
 *	0 	Success
 * 	ENXIO 	creating minor nodes failed.
 */
int
cmlb_attach(dev_info_t *devi, cmlb_tg_ops_t *tgopsp, int device_type,
    int is_removable, char *node_type, int alter_behavior,
    cmlb_handle_t cmlbhandle)
{

	struct cmlb_lun	*un = (struct cmlb_lun *)cmlbhandle;
	diskaddr_t	cap;
	int		status;

	mutex_enter(CMLB_MUTEX(un));

	CMLB_DEVINFO(un) = devi;
	un->cmlb_tg_ops = tgopsp;
	un->un_device_type = device_type;
	un->un_is_removable = is_removable;
	un->un_node_type = node_type;
	un->un_sys_blocksize = DEV_BSIZE;
	un->un_f_geometry_is_valid = FALSE;
	un->un_def_labeltype = CMLB_LABEL_VTOC;
	un->un_alter_behavior = alter_behavior;

	if (is_removable != 0) {
		mutex_exit(CMLB_MUTEX(un));
		status = DK_TG_GETCAP(un, &cap);
		mutex_enter(CMLB_MUTEX(un));
		if (status == 0 && cap > DK_MAX_BLOCKS) {
			/* set default EFI if > 1TB */
			un->un_def_labeltype = CMLB_LABEL_EFI;
		}
	}

	/* create minor nodes based on default label type */
	un->un_last_labeltype = CMLB_LABEL_UNDEF;
	un->un_cur_labeltype = CMLB_LABEL_UNDEF;

	if (cmlb_create_minor_nodes(un) != 0) {
		mutex_exit(CMLB_MUTEX(un));
		return (ENXIO);
	}

	un->un_state = CMLB_ATTACHED;

	mutex_exit(CMLB_MUTEX(un));
	return (0);
}

/*
 * cmlb_detach:
 *
 * Invalidate in-core labeling data and remove all minor nodes for
 * the device associate with handle.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *
 */
void
cmlb_detach(cmlb_handle_t cmlbhandle)
{
	struct cmlb_lun *un = (struct cmlb_lun *)cmlbhandle;

	mutex_enter(CMLB_MUTEX(un));
	un->un_def_labeltype = CMLB_LABEL_UNDEF;
	un->un_f_geometry_is_valid = FALSE;
	ddi_remove_minor_node(CMLB_DEVINFO(un), NULL);
	un->un_state = CMLB_INITED;
	mutex_exit(CMLB_MUTEX(un));
}

/*
 * cmlb_validate:
 *
 *	Validates label.
 *
 * Arguments
 *	cmlbhandle	cmlb handle associated with device.
 *
 * Notes:
 *	If new label type is different from the current, adjust minor nodes
 *	accordingly.
 *
 * Return values:
 *	0		success
 *			Note: having fdisk but no solaris partition is assumed
 *			success.
 *
 *	ENOMEM		memory allocation failed
 *	EIO		i/o errors during read or get capacity
 * 	EACCESS		reservation conflicts
 * 	EINVAL		label was corrupt, or no default label was assumed
 *	ENXIO		invalid handle
 */
int
cmlb_validate(cmlb_handle_t cmlbhandle)
{
	struct cmlb_lun *un = (struct cmlb_lun *)cmlbhandle;
	int 		rval;
	int  		ret = 0;

	/*
	 * Temp work-around checking un for NULL since there is a bug
	 * in sd_detach calling this routine from taskq_dispatch
	 * inited function.
	 */
	if (un == NULL)
		return (ENXIO);

	ASSERT(un != NULL);

	mutex_enter(CMLB_MUTEX(un));
	if (un->un_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(un));
		return (ENXIO);
	}

	rval = cmlb_validate_geometry((struct cmlb_lun *)cmlbhandle, 1);

	if (rval == ENOTSUP) {
		if (un->un_f_geometry_is_valid == TRUE) {
			un->un_cur_labeltype = CMLB_LABEL_EFI;
			ret = 0;
		} else {
			ret = EINVAL;
		}
	} else {
		ret = rval;
		if (ret == 0)
			un->un_cur_labeltype = CMLB_LABEL_VTOC;
	}

	if (ret == 0)
		(void) cmlb_create_minor_nodes(un);

	mutex_exit(CMLB_MUTEX(un));
	return (ret);
}

/*
 * cmlb_invalidate:
 *	Invalidate in core label data
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 */
void
cmlb_invalidate(cmlb_handle_t cmlbhandle)
{
	struct cmlb_lun *un = (struct cmlb_lun *)cmlbhandle;

	if (un == NULL)
		return;

	mutex_enter(CMLB_MUTEX(un));
	un->un_f_geometry_is_valid = FALSE;
	mutex_exit(CMLB_MUTEX(un));
}

/*
 * cmlb_close:
 *
 * Close the device, revert to a default label minor node for the device,
 * if it is removable.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *
 * Return values:
 *	0	Success
 * 	ENXIO	Re-creating minor node failed.
 */
int
cmlb_close(cmlb_handle_t cmlbhandle)
{
	struct cmlb_lun *un = (struct cmlb_lun *)cmlbhandle;

	mutex_enter(CMLB_MUTEX(un));
	un->un_f_geometry_is_valid = FALSE;

	/* revert to default minor node for this device */
	if (ISREMOVABLE(un)) {
		un->un_cur_labeltype = CMLB_LABEL_UNDEF;
		(void) cmlb_create_minor_nodes(un);
	}

	mutex_exit(CMLB_MUTEX(un));
	return (0);
}

/*
 * cmlb_get_devid_block:
 *	 get the block number where device id is stored.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	devidblockp	pointer to block number.
 *
 * Notes:
 *	It stores the block number of device id in the area pointed to
 *	by devidblockp.
 * 	with the block number of device id.
 *
 * Return values:
 *	0	success
 *	EINVAL 	device id does not apply to current label type.
 */
int
cmlb_get_devid_block(cmlb_handle_t cmlbhandle, diskaddr_t *devidblockp)
{
	daddr_t			spc, blk, head, cyl;
	struct cmlb_lun *un = (struct cmlb_lun *)cmlbhandle;

	mutex_enter(CMLB_MUTEX(un));
	if (un->un_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(un));
		return (EINVAL);
	}

	if (un->un_blockcount <= DK_MAX_BLOCKS) {
		/* this geometry doesn't allow us to write a devid */
		if (un->un_g.dkg_acyl < 2) {
			mutex_exit(CMLB_MUTEX(un));
			return (EINVAL);
		}

		/*
		 * Subtract 2 guarantees that the next to last cylinder
		 * is used
		 */
		cyl  = un->un_g.dkg_ncyl  + un->un_g.dkg_acyl - 2;
		spc  = un->un_g.dkg_nhead * un->un_g.dkg_nsect;
		head = un->un_g.dkg_nhead - 1;
		blk  = (cyl * (spc - un->un_g.dkg_apc)) +
		    (head * un->un_g.dkg_nsect) + 1;
	} else {
		mutex_exit(CMLB_MUTEX(un));
		return (EINVAL);
	}
	*devidblockp = blk;
	mutex_exit(CMLB_MUTEX(un));
	return (0);
}

/*
 * cmlb_partinfo:
 *	Get partition info for specified partition number.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	part		partition number
 *	nblocksp	pointer to number of blocks
 *	startblockp	pointer to starting block
 *	partnamep	pointer to name of partition
 *	tagp		pointer to tag info
 *
 *
 * Notes:
 *	If in-core label is not valid, this functions tries to revalidate
 *	the label. If label is valid, it stores the total number of blocks
 *	in this partition in the area pointed to by nblocksp, starting
 *	block number in area pointed to by startblockp,  pointer to partition
 *	name in area pointed to by partnamep, and tag value in area
 *	pointed by tagp.
 *	For EFI labels, tag value will be set to 0.
 *
 *	For all nblocksp, startblockp and partnamep, tagp, a value of NULL
 *	indicates the corresponding info is not requested.
 *
 *
 * Return values:
 *	0	success
 *	EINVAL  no valid label or requested partition number is invalid.
 *
 */
int
cmlb_partinfo(cmlb_handle_t cmlbhandle, int part, diskaddr_t *nblocksp,
    diskaddr_t *startblockp, char **partnamep, uint16_t *tagp)
{

	struct cmlb_lun *un = (struct cmlb_lun *)cmlbhandle;
	int rval;

	ASSERT(un != NULL);
	mutex_enter(CMLB_MUTEX(un));
	if (un->un_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(un));
		return (EINVAL);
	}

	if (part  < 0 || part >= MAXPART) {
		rval = EINVAL;
	} else {
		(void) cmlb_validate_geometry((struct cmlb_lun *)un, 0);
		if ((un->un_f_geometry_is_valid == FALSE) ||
		    (part < NDKMAP && un->un_solaris_size == 0)) {
			rval = EINVAL;
		} else {
			if (startblockp != NULL)
				*startblockp = (diskaddr_t)un->un_offset[part];

			if (nblocksp != NULL)
				*nblocksp = (diskaddr_t)
				    un->un_map[part].dkl_nblk;

			if (tagp != NULL)
				if (un->un_cur_labeltype == CMLB_LABEL_EFI)
					*tagp = V_UNASSIGNED;
				else
					*tagp = un->un_vtoc.v_part[part].p_tag;
			rval = 0;
		}

		/* consistent with behavior of sd for getting minor name */
		if (partnamep != NULL)
			*partnamep = dk_minor_data[part].name;

	}

	mutex_exit(CMLB_MUTEX(un));
	return (rval);
}

/* ARGSUSED */
int
cmlb_ioctl(cmlb_handle_t cmlbhandle, dev_t dev, int cmd, intptr_t arg,
    int flag, cred_t *cred_p, int *rval_p)
{

	int err;
	struct cmlb_lun *un;

	un = (struct cmlb_lun *)cmlbhandle;

	ASSERT(un != NULL);

	mutex_enter(CMLB_MUTEX(un));
	if (un->un_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(un));
		return (EIO);
	}


	if ((cmlb_check_update_blockcount(un) == 0) &&
	    (un->un_blockcount > DK_MAX_BLOCKS)) {
		switch (cmd) {
		case DKIOCGAPART:
		case DKIOCGGEOM:
		case DKIOCSGEOM:
		case DKIOCGVTOC:
		case DKIOCSVTOC:
		case DKIOCSAPART:
		case DKIOCG_PHYGEOM:
		case DKIOCG_VIRTGEOM:
			mutex_exit(CMLB_MUTEX(un));
			return (ENOTSUP);
		}
	}

	switch (cmd) {
		case DKIOCSVTOC:
		case DKIOCSETEFI:
		case DKIOCSMBOOT:
			break;
		default:
			(void) cmlb_validate_geometry(un, 0);
			if ((un->un_f_geometry_is_valid == TRUE) &&
			    (un->un_solaris_size > 0)) {
			/*
			 * the "geometry_is_valid" flag could be true if we
			 * have an fdisk table but no Solaris partition
			 */
			if (un->un_vtoc.v_sanity != VTOC_SANE) {
				/* it is EFI, so return ENOTSUP for these */
				switch (cmd) {
				case DKIOCGAPART:
				case DKIOCGGEOM:
				case DKIOCGVTOC:
				case DKIOCSVTOC:
				case DKIOCSAPART:
					mutex_exit(CMLB_MUTEX(un));
					return (ENOTSUP);
				}
			}
		}
	}

	mutex_exit(CMLB_MUTEX(un));

	switch (cmd) {
	case DKIOCGGEOM:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCGGEOM\n");
		err = cmlb_dkio_get_geometry(un, (caddr_t)arg, flag);
		break;

	case DKIOCSGEOM:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCSGEOM\n");
		err = cmlb_dkio_set_geometry(un, (caddr_t)arg, flag);
		break;

	case DKIOCGAPART:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCGAPART\n");
		err = cmlb_dkio_get_partition(un, (caddr_t)arg, flag);
		break;

	case DKIOCSAPART:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCSAPART\n");
		err = cmlb_dkio_set_partition(un, (caddr_t)arg, flag);
		break;

	case DKIOCGVTOC:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCGVTOC\n");
		err = cmlb_dkio_get_vtoc(un, (caddr_t)arg, flag);
		break;

	case DKIOCGETEFI:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCGETEFI\n");
		err = cmlb_dkio_get_efi(un, (caddr_t)arg, flag);
		break;

	case DKIOCPARTITION:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCPARTITION\n");
		err = cmlb_dkio_partition(un, (caddr_t)arg, flag);
		break;

	case DKIOCSVTOC:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCSVTOC\n");
		err = cmlb_dkio_set_vtoc(un, dev, (caddr_t)arg, flag);
		break;

	case DKIOCSETEFI:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCSETEFI\n");
		err = cmlb_dkio_set_efi(un, dev, (caddr_t)arg, flag);
		break;

	case DKIOCGMBOOT:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCGMBOOT\n");
		err = cmlb_dkio_get_mboot(un, (caddr_t)arg, flag);
		break;

	case DKIOCSMBOOT:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCSMBOOT\n");
		err = cmlb_dkio_set_mboot(un, (caddr_t)arg, flag);
		break;
	case DKIOCG_PHYGEOM:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCG_PHYGEOM\n");
#if defined(__i386) || defined(__amd64)
		err = cmlb_dkio_get_phygeom(un, (caddr_t)arg, flag);
#else
		err = ENOTTY;
#endif
		break;
	case DKIOCG_VIRTGEOM:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCG_VIRTGEOM\n");
#if defined(__i386) || defined(__amd64)
		err = cmlb_dkio_get_virtgeom(un, (caddr_t)arg, flag);
#else
		err = ENOTTY;
#endif
		break;
	case DKIOCPARTINFO:
		cmlb_dbg(CMLB_TRACE, un, "DKIOCPARTINFO");
#if defined(__i386) || defined(__amd64)
		err = cmlb_dkio_partinfo(un, dev, (caddr_t)arg, flag);
#else
		err = ENOTTY;
#endif
		break;

	default:
		err = ENOTTY;

	}
	return (err);
}

dev_t
cmlb_make_device(struct cmlb_lun *un)
{
	return (makedevice(ddi_name_to_major(ddi_get_name(CMLB_DEVINFO(un))),
	    ddi_get_instance(CMLB_DEVINFO(un)) << CMLBUNIT_SHIFT));
}

/*
 * Function: cmlb_check_update_blockcount
 *
 * Description: If current capacity value is invalid, obtains the
 *		current capacity from target driver.
 *
 * Return Code: 0	success
 *		EIO	failure
 */
static int
cmlb_check_update_blockcount(struct cmlb_lun *un)
{
	int status;
	diskaddr_t capacity;

	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	if (un->un_f_geometry_is_valid == FALSE)  {
		mutex_exit(CMLB_MUTEX(un));
		status = DK_TG_GETCAP(un, &capacity);
		mutex_enter(CMLB_MUTEX(un));
		if (status == 0 && capacity != 0) {
			un->un_blockcount = capacity;
			return (0);
		} else
			return (EIO);
	} else
		return (0);
}

/*
 *    Function: cmlb_create_minor_nodes
 *
 * Description: Create or adjust the minor device nodes for the instance.
 * 		Minor nodes are created based on default label type,
 *		current label type and last label type we created
 *		minor nodes based on.
 *
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: 0 success
 *		ENXIO	failure.
 *
 *     Context: Kernel thread context
 */
static int
cmlb_create_minor_nodes(struct cmlb_lun *un)
{
	struct driver_minor_data	*dmdp;
	int				instance;
	char				name[48];
	cmlb_label_t			newlabeltype;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(un)));


	/* check the most common case */
	if (un->un_cur_labeltype != CMLB_LABEL_UNDEF &&
	    un->un_last_labeltype == un->un_cur_labeltype) {
		/* do nothing */
		return (0);
	}

	if (un->un_def_labeltype == CMLB_LABEL_UNDEF) {
		/* we should never get here */
		return (ENXIO);
	}

	if (un->un_last_labeltype == CMLB_LABEL_UNDEF) {
		/* first time during attach */
		newlabeltype = un->un_def_labeltype;

		instance = ddi_get_instance(CMLB_DEVINFO(un));

		/* Create all the minor nodes for this target. */
		dmdp = (newlabeltype == CMLB_LABEL_EFI) ? dk_minor_data_efi :
		    dk_minor_data;
		while (dmdp->name != NULL) {

			(void) sprintf(name, "%s", dmdp->name);

			if (ddi_create_minor_node(CMLB_DEVINFO(un), name,
			    dmdp->type,
			    (instance << CMLBUNIT_SHIFT) | dmdp->minor,
			    un->un_node_type, NULL) == DDI_FAILURE) {
				/*
				 * Clean up any nodes that may have been
				 * created, in case this fails in the middle
				 * of the loop.
				 */
				ddi_remove_minor_node(CMLB_DEVINFO(un), NULL);
				return (ENXIO);
			}
			dmdp++;
		}
		un->un_last_labeltype = newlabeltype;
		return (0);
	}

	/* Not first time  */
	if (un->un_cur_labeltype == CMLB_LABEL_UNDEF) {
		if (un->un_last_labeltype != un->un_def_labeltype) {
			/* close time, revert to default. */
			newlabeltype = un->un_def_labeltype;
		} else {
			/*
			 * do nothing since the type for which we last created
			 * nodes matches the default
			 */
			return (0);
		}
	} else {
		if (un->un_cur_labeltype != un->un_last_labeltype) {
			/* We are not closing, use current label type */
			newlabeltype = un->un_cur_labeltype;
		} else {
			/*
			 * do nothing since the type for which we last created
			 * nodes matches the current label type
			 */
			return (0);
		}
	}

	instance = ddi_get_instance(CMLB_DEVINFO(un));

	/*
	 * Currently we only fix up the s7 node when we are switching
	 * label types from or to EFI. This is consistent with
	 * current behavior of sd.
	 */
	if (newlabeltype == CMLB_LABEL_EFI &&
	    un->un_last_labeltype != CMLB_LABEL_EFI) {
		/* from vtoc to EFI */
		ddi_remove_minor_node(CMLB_DEVINFO(un), "h");
		ddi_remove_minor_node(CMLB_DEVINFO(un), "h,raw");
		(void) ddi_create_minor_node(CMLB_DEVINFO(un), "wd",
		    S_IFBLK, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    un->un_node_type, NULL);
		(void) ddi_create_minor_node(CMLB_DEVINFO(un), "wd,raw",
		    S_IFCHR, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    un->un_node_type, NULL);
	} else {
		/* from efi to vtoc */
		ddi_remove_minor_node(CMLB_DEVINFO(un), "wd");
		ddi_remove_minor_node(CMLB_DEVINFO(un), "wd,raw");
		(void) ddi_create_minor_node(CMLB_DEVINFO(un), "h",
		    S_IFBLK, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    un->un_node_type, NULL);
		(void) ddi_create_minor_node(CMLB_DEVINFO(un), "h,raw",
		    S_IFCHR, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    un->un_node_type, NULL);
	}

	un->un_last_labeltype = newlabeltype;
	return (0);
}

/*
 *    Function: cmlb_validate_geometry
 *
 * Description: Read the label from the disk (if present). Update the unit's
 *		geometry and vtoc information from the data in the label.
 *		Verify that the label is valid.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: 0 - Successful completion
 *		EINVAL  - Invalid value in un->un_tgt_blocksize or
 *			  un->un_blockcount; or label on disk is corrupted
 *			  or unreadable.
 *		EACCES  - Reservation conflict at the device.
 *		ENOMEM  - Resource allocation error
 *		ENOTSUP - geometry not applicable
 *
 *     Context: Kernel thread only (can sleep).
 */
static int
cmlb_validate_geometry(struct cmlb_lun *un, int forcerevalid)
{
	int		label_error = 0;
	diskaddr_t	capacity;
	int		count;

	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	if ((un->un_f_geometry_is_valid == TRUE) && (forcerevalid == 0)) {
		if (un->un_cur_labeltype == CMLB_LABEL_EFI)
			return (ENOTSUP);
		return (0);
	}

	if (cmlb_check_update_blockcount(un) != 0)
		return (EIO);

	capacity = un->un_blockcount;

#if defined(_SUNOS_VTOC_16)
	/*
	 * Set up the "whole disk" fdisk partition; this should always
	 * exist, regardless of whether the disk contains an fdisk table
	 * or vtoc.
	 */
	un->un_map[P0_RAW_DISK].dkl_cylno = 0;
	/*
	 * note if capacity > uint32_max we should be using efi,
	 * and not use p0, so the truncation does not matter.
	 */
	un->un_map[P0_RAW_DISK].dkl_nblk  = capacity;
#endif
	/*
	 * Refresh the logical and physical geometry caches.
	 * (data from MODE SENSE format/rigid disk geometry pages,
	 * and scsi_ifgetcap("geometry").
	 */
	cmlb_resync_geom_caches(un, capacity);

	label_error = cmlb_use_efi(un, capacity);
	if (label_error == 0) {

		/* found a valid EFI label */
		cmlb_dbg(CMLB_TRACE, un,
		    "cmlb_validate_geometry: found EFI label\n");
		/*
		 * solaris_size and geometry_is_valid are set in
		 * cmlb_use_efi
		 */
		return (ENOTSUP);
	} else {
		if ((label_error != ESRCH) && (label_error != EINVAL)) {
			cmlb_dbg(CMLB_ERROR,  un, "cmlb_use_efi failed %d\n",
			    label_error);
			return (label_error);
		}
	}

	/* NO EFI label found */

	if (capacity > DK_MAX_BLOCKS) {
		if (label_error == ESRCH) {
			/*
			 * they've configured a LUN over 1TB, but used
			 * format.dat to restrict format's view of the
			 * capacity to be under 1TB
			 */
			/* i.e > 1Tb with a VTOC < 1TB */

			cmlb_log(CMLB_DEVINFO(un), CMLB_LABEL(un), CE_WARN,
			    "is >1TB and has a VTOC label: use format(1M) to "
			    "either decrease the");
			cmlb_log(CMLB_DEVINFO(un), CMLB_LABEL(un), CE_CONT,
			    "size to be < 1TB or relabel the disk with an EFI "
			    "label");
		} else {
			/* unlabeled disk over 1TB */
			return (ENOTSUP);
		}
	}

	label_error = 0;

	/*
	 * at this point it is either labeled with a VTOC or it is
	 * under 1TB
	 */

	/*
	 * Only DIRECT ACCESS devices will have Sun labels.
	 * CD's supposedly have a Sun label, too
	 */
	if (un->un_device_type == DTYPE_DIRECT || ISREMOVABLE(un)) {
		struct	dk_label *dkl;
		offset_t label_addr;
		int	rval;
		size_t	buffer_size;

		/*
		 * Note: This will set up un->un_solaris_size and
		 * un->un_solaris_offset.
		 */
		rval = cmlb_read_fdisk(un, capacity);
		if (rval != 0) {
			ASSERT(mutex_owned(CMLB_MUTEX(un)));
			return (rval);
		}

		if (un->un_solaris_size <= DK_LABEL_LOC) {
			/*
			 * Found fdisk table but no Solaris partition entry,
			 * so don't call cmlb_uselabel() and don't create
			 * a default label.
			 */
			label_error = 0;
			un->un_f_geometry_is_valid = TRUE;
			goto no_solaris_partition;
		}

		label_addr = (daddr_t)(un->un_solaris_offset + DK_LABEL_LOC);

		buffer_size = sizeof (struct dk_label);

		cmlb_dbg(CMLB_TRACE, un, "cmlb_validate_geometry: "
		    "label_addr: 0x%x allocation size: 0x%x\n",
		    label_addr, buffer_size);

		if ((dkl = kmem_zalloc(buffer_size, KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		mutex_exit(CMLB_MUTEX(un));
		rval = DK_TG_READ(un, dkl, label_addr, buffer_size);
		mutex_enter(CMLB_MUTEX(un));

		switch (rval) {
		case 0:
			/*
			 * cmlb_uselabel will establish that the geometry
			 * is valid.
			 */
			if (cmlb_uselabel(un,
			    (struct dk_label *)(uintptr_t)dkl) !=
			    CMLB_LABEL_IS_VALID) {
				label_error = EINVAL;
			} else
				un->un_vtoc_label_is_from_media = 1;
			break;
		case EACCES:
			label_error = EACCES;
			break;
		default:
			label_error = EINVAL;
			break;
		}

		kmem_free(dkl, buffer_size);
	}

	/*
	 * If a valid label was not found, AND if no reservation conflict
	 * was detected, then go ahead and create a default label (4069506).
	 *
	 * Note: currently, for VTOC_8 devices, the default label is created
	 * for removables only.  For VTOC_16 devices, the default label will
	 * be created for both removables and non-removables alike.
	 * (see cmlb_build_default_label)
	 */
#if defined(_SUNOS_VTOC_8)
	if (ISREMOVABLE(un) && (label_error != EACCES)) {
#elif defined(_SUNOS_VTOC_16)
	if (label_error != EACCES) {
#endif
		if (un->un_f_geometry_is_valid == FALSE) {
			cmlb_build_default_label(un);
		}
		label_error = 0;
	}

no_solaris_partition:

#if defined(_SUNOS_VTOC_16)
	/*
	 * If we have valid geometry, set up the remaining fdisk partitions.
	 * Note that dkl_cylno is not used for the fdisk map entries, so
	 * we set it to an entirely bogus value.
	 */
	for (count = 0; count < FD_NUMPART; count++) {
		un->un_map[FDISK_P1 + count].dkl_cylno = -1;
		un->un_map[FDISK_P1 + count].dkl_nblk =
		    un->un_fmap[count].fmap_nblk;

		un->un_offset[FDISK_P1 + count] =
		    un->un_fmap[count].fmap_start;
	}
#endif

	for (count = 0; count < NDKMAP; count++) {
#if defined(_SUNOS_VTOC_8)
		struct dk_map *lp  = &un->un_map[count];
		un->un_offset[count] =
		    un->un_g.dkg_nhead * un->un_g.dkg_nsect * lp->dkl_cylno;
#elif defined(_SUNOS_VTOC_16)
		struct dkl_partition *vp = &un->un_vtoc.v_part[count];

		un->un_offset[count] = vp->p_start + un->un_solaris_offset;
#else
#error "No VTOC format defined."
#endif
	}

	return (label_error);
}

#if defined(_SUNOS_VTOC_16)
/*
 * Macro: MAX_BLKS
 *
 *	This macro is used for table entries where we need to have the largest
 *	possible sector value for that head & SPT (sectors per track)
 *	combination.  Other entries for some smaller disk sizes are set by
 *	convention to match those used by X86 BIOS usage.
 */
#define	MAX_BLKS(heads, spt)	UINT16_MAX * heads * spt, heads, spt

/*
 *    Function: cmlb_convert_geometry
 *
 * Description: Convert physical geometry into a dk_geom structure. In
 *		other words, make sure we don't wrap 16-bit values.
 *		e.g. converting from geom_cache to dk_geom
 *
 *     Context: Kernel thread only
 */
static void
cmlb_convert_geometry(diskaddr_t capacity, struct dk_geom *un_g)
{
	int i;
	static const struct chs_values {
		uint_t max_cap;		/* Max Capacity for this HS. */
		uint_t nhead;		/* Heads to use. */
		uint_t nsect;		/* SPT to use. */
	} CHS_values[] = {
		{0x00200000,  64, 32},		/* 1GB or smaller disk. */
		{0x01000000, 128, 32},		/* 8GB or smaller disk. */
		{MAX_BLKS(255,  63)},		/* 502.02GB or smaller disk. */
		{MAX_BLKS(255, 126)},		/* .98TB or smaller disk. */
		{DK_MAX_BLOCKS, 255, 189}	/* Max size is just under 1TB */
	};

	/* Unlabeled SCSI floppy device */
	if (capacity <= 0x1000) {
		un_g->dkg_nhead = 2;
		un_g->dkg_ncyl = 80;
		un_g->dkg_nsect = capacity / (un_g->dkg_nhead * un_g->dkg_ncyl);
		return;
	}

	/*
	 * For all devices we calculate cylinders using the
	 * heads and sectors we assign based on capacity of the
	 * device.  The table is designed to be compatible with the
	 * way other operating systems lay out fdisk tables for X86
	 * and to insure that the cylinders never exceed 65535 to
	 * prevent problems with X86 ioctls that report geometry.
	 * We use SPT that are multiples of 63, since other OSes that
	 * are not limited to 16-bits for cylinders stop at 63 SPT
	 * we make do by using multiples of 63 SPT.
	 *
	 * Note than capacities greater than or equal to 1TB will simply
	 * get the largest geometry from the table. This should be okay
	 * since disks this large shouldn't be using CHS values anyway.
	 */
	for (i = 0; CHS_values[i].max_cap < capacity &&
	    CHS_values[i].max_cap != DK_MAX_BLOCKS; i++)
		;

	un_g->dkg_nhead = CHS_values[i].nhead;
	un_g->dkg_nsect = CHS_values[i].nsect;
}
#endif

/*
 *    Function: cmlb_resync_geom_caches
 *
 * Description: (Re)initialize both geometry caches: the virtual geometry
 *            information is extracted from the HBA (the "geometry"
 *            capability), and the physical geometry cache data is
 *            generated by issuing MODE SENSE commands.
 *
 *   Arguments: un - driver soft state (unit) structure
 *		capacity - disk capacity in #blocks
 *
 *     Context: Kernel thread only (can sleep).
 */
static void
cmlb_resync_geom_caches(struct cmlb_lun *un, diskaddr_t capacity)
{
	struct	cmlb_geom 	pgeom;
	struct	cmlb_geom	lgeom;
	struct 	cmlb_geom	*pgeomp = &pgeom;
	unsigned short 		nhead;
	unsigned short 		nsect;
	int 			spc;
	int			ret;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	/*
	 * Ask the controller for its logical geometry.
	 * Note: if the HBA does not support scsi_ifgetcap("geometry"),
	 * then the lgeom cache will be invalid.
	 */
	mutex_exit(CMLB_MUTEX(un));
	bzero(&lgeom, sizeof (struct cmlb_geom));
	ret = DK_TG_GETVIRTGEOM(un, &lgeom);
	mutex_enter(CMLB_MUTEX(un));

	bcopy(&lgeom, &un->un_lgeom, sizeof (un->un_lgeom));

	/*
	 * Initialize the pgeom cache from lgeom, so that if MODE SENSE
	 * doesn't work, DKIOCG_PHYSGEOM can return reasonable values.
	 */
	if (ret != 0 || un->un_lgeom.g_nsect == 0 ||
	    un->un_lgeom.g_nhead == 0) {
		/*
		 * Note: Perhaps this needs to be more adaptive? The rationale
		 * is that, if there's no HBA geometry from the HBA driver, any
		 * guess is good, since this is the physical geometry. If MODE
		 * SENSE fails this gives a max cylinder size for non-LBA access
		 */
		nhead = 255;
		nsect = 63;
	} else {
		nhead = un->un_lgeom.g_nhead;
		nsect = un->un_lgeom.g_nsect;
	}

	if (ISCD(un)) {
		pgeomp->g_nhead = 1;
		pgeomp->g_nsect = nsect * nhead;
	} else {
		pgeomp->g_nhead = nhead;
		pgeomp->g_nsect = nsect;
	}

	spc = pgeomp->g_nhead * pgeomp->g_nsect;
	pgeomp->g_capacity = capacity;
	pgeomp->g_ncyl = pgeomp->g_capacity / spc;
	pgeomp->g_acyl = 0;

	/*
	 * Retrieve fresh geometry data from the hardware, stash it
	 * here temporarily before we rebuild the incore label.
	 *
	 * We want to use the MODE SENSE commands to derive the
	 * physical geometry of the device, but if either command
	 * fails, the logical geometry is used as the fallback for
	 * disk label geometry.
	 */

	mutex_exit(CMLB_MUTEX(un));
	(void) DK_TG_GETPHYGEOM(un,  pgeomp);
	mutex_enter(CMLB_MUTEX(un));

	/*
	 * Now update the real copy while holding the mutex. This
	 * way the global copy is never in an inconsistent state.
	 */
	bcopy(pgeomp, &un->un_pgeom,  sizeof (un->un_pgeom));

	cmlb_dbg(CMLB_INFO, un, "cmlb_resync_geom_caches: "
	    "(cached from lgeom)\n");
	cmlb_dbg(CMLB_INFO,  un,
	    "   ncyl: %ld; acyl: %d; nhead: %d; nsect: %d\n",
	    un->un_pgeom.g_ncyl, un->un_pgeom.g_acyl,
	    un->un_pgeom.g_nhead, un->un_pgeom.g_nsect);
	cmlb_dbg(CMLB_INFO,  un, "   lbasize: %d; capacity: %ld; "
	    "intrlv: %d; rpm: %d\n", un->un_pgeom.g_secsize,
	    un->un_pgeom.g_capacity, un->un_pgeom.g_intrlv,
	    un->un_pgeom.g_rpm);
}


/*
 *    Function: cmlb_read_fdisk
 *
 * Description: utility routine to read the fdisk table.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: 0 for success (includes not reading for no_fdisk_present case
 *		errnos from tg_rw if failed to read the first block.
 *
 *     Context: Kernel thread only (can sleep).
 */
/* ARGSUSED */
static int
cmlb_read_fdisk(struct cmlb_lun *un, diskaddr_t capacity)
{
#if defined(_NO_FDISK_PRESENT)

	un->un_solaris_offset = 0;
	un->un_solaris_size = capacity;
	bzero(un->un_fmap, sizeof (struct fmap) * FD_NUMPART);
	return (0);

#elif defined(_FIRMWARE_NEEDS_FDISK)

	struct ipart	*fdp;
	struct mboot	*mbp;
	struct ipart	fdisk[FD_NUMPART];
	int		i;
	char		sigbuf[2];
	caddr_t		bufp;
	int		uidx;
	int 		rval;
	int		lba = 0;
	uint_t		solaris_offset;	/* offset to solaris part. */
	daddr_t		solaris_size;	/* size of solaris partition */
	uint32_t	blocksize;

	ASSERT(un != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	/*
	 * Start off assuming no fdisk table
	 */
	solaris_offset = 0;
	solaris_size   = capacity;

	blocksize = 512;

	bufp = kmem_zalloc(blocksize, KM_SLEEP);

	mutex_exit(CMLB_MUTEX(un));
	rval = DK_TG_READ(un,  bufp, 0, blocksize);
	mutex_enter(CMLB_MUTEX(un));

	if (rval != 0) {
		cmlb_dbg(CMLB_ERROR,  un,
		    "cmlb_read_fdisk: fdisk read err\n");
		kmem_free(bufp, blocksize);
		return (rval);
	}

	mbp = (struct mboot *)bufp;

	/*
	 * The fdisk table does not begin on a 4-byte boundary within the
	 * master boot record, so we copy it to an aligned structure to avoid
	 * alignment exceptions on some processors.
	 */
	bcopy(&mbp->parts[0], fdisk, sizeof (fdisk));

	/*
	 * Check for lba support before verifying sig; sig might not be
	 * there, say on a blank disk, but the max_chs mark may still
	 * be present.
	 *
	 * Note: LBA support and BEFs are an x86-only concept but this
	 * code should work OK on SPARC as well.
	 */

	/*
	 * First, check for lba-access-ok on root node (or prom root node)
	 * if present there, don't need to search fdisk table.
	 */
	if (ddi_getprop(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    "lba-access-ok", 0) != 0) {
		/* All drives do LBA; don't search fdisk table */
		lba = 1;
	} else {
		/* Okay, look for mark in fdisk table */
		for (fdp = fdisk, i = 0; i < FD_NUMPART; i++, fdp++) {
			/* accumulate "lba" value from all partitions */
			lba = (lba || cmlb_has_max_chs_vals(fdp));
		}
	}

	/*
	 * Next, look for 'no-bef-lba-access' prop on parent.
	 * Its presence means the realmode driver doesn't support
	 * LBA, so the target driver shouldn't advertise it as ok.
	 * This should be a temporary condition; one day all
	 * BEFs should support the LBA access functions.
	 */
	if ((lba != 0) && (ddi_getprop(DDI_DEV_T_ANY,
	    ddi_get_parent(CMLB_DEVINFO(un)), DDI_PROP_DONTPASS,
	    "no-bef-lba-access", 0) != 0)) {
		/* BEF doesn't support LBA; don't advertise it as ok */
		lba = 0;
	}

	if (lba != 0) {
		dev_t dev = cmlb_make_device(un);

		if (ddi_getprop(dev, CMLB_DEVINFO(un), DDI_PROP_DONTPASS,
		    "lba-access-ok", 0) == 0) {
			/* not found; create it */
			if (ddi_prop_create(dev, CMLB_DEVINFO(un), 0,
			    "lba-access-ok", (caddr_t)NULL, 0) !=
			    DDI_PROP_SUCCESS) {
				cmlb_dbg(CMLB_ERROR,  un,
				    "cmlb_read_fdisk: Can't create lba "
				    "property for instance %d\n",
				    ddi_get_instance(CMLB_DEVINFO(un)));
			}
		}
	}

	bcopy(&mbp->signature, sigbuf, sizeof (sigbuf));

	/*
	 * Endian-independent signature check
	 */
	if (((sigbuf[1] & 0xFF) != ((MBB_MAGIC >> 8) & 0xFF)) ||
	    (sigbuf[0] != (MBB_MAGIC & 0xFF))) {
		cmlb_dbg(CMLB_ERROR,  un,
		    "cmlb_read_fdisk: no fdisk\n");
		bzero(un->un_fmap, sizeof (struct fmap) * FD_NUMPART);
		goto done;
	}

#ifdef CMLBDEBUG
	if (cmlb_level_mask & SD_LOGMASK_INFO) {
		fdp = fdisk;
		cmlb_dbg(CMLB_INFO,  un, "cmlb_read_fdisk:\n");
		cmlb_dbg(CMLB_INFO,  un, "         relsect    "
		    "numsect         sysid       bootid\n");
		for (i = 0; i < FD_NUMPART; i++, fdp++) {
			cmlb_dbg(CMLB_INFO,  un,
			    "    %d:  %8d   %8d     0x%08x     0x%08x\n",
			    i, fdp->relsect, fdp->numsect,
			    fdp->systid, fdp->bootid);
		}
	}
#endif

	/*
	 * Try to find the unix partition
	 */
	uidx = -1;
	solaris_offset = 0;
	solaris_size   = 0;

	for (fdp = fdisk, i = 0; i < FD_NUMPART; i++, fdp++) {
		int	relsect;
		int	numsect;

		if (fdp->numsect == 0) {
			un->un_fmap[i].fmap_start = 0;
			un->un_fmap[i].fmap_nblk  = 0;
			continue;
		}

		/*
		 * Data in the fdisk table is little-endian.
		 */
		relsect = LE_32(fdp->relsect);
		numsect = LE_32(fdp->numsect);

		un->un_fmap[i].fmap_start = relsect;
		un->un_fmap[i].fmap_nblk  = numsect;

		if (fdp->systid != SUNIXOS &&
		    fdp->systid != SUNIXOS2 &&
		    fdp->systid != EFI_PMBR) {
			continue;
		}

		/*
		 * use the last active solaris partition id found
		 * (there should only be 1 active partition id)
		 *
		 * if there are no active solaris partition id
		 * then use the first inactive solaris partition id
		 */
		if ((uidx == -1) || (fdp->bootid == ACTIVE)) {
			uidx = i;
			solaris_offset = relsect;
			solaris_size   = numsect;
		}
	}

	cmlb_dbg(CMLB_INFO,  un, "fdisk 0x%x 0x%lx",
	    un->un_solaris_offset, un->un_solaris_size);
done:

	/*
	 * Clear the VTOC info, only if the Solaris partition entry
	 * has moved, changed size, been deleted, or if the size of
	 * the partition is too small to even fit the label sector.
	 */
	if ((un->un_solaris_offset != solaris_offset) ||
	    (un->un_solaris_size != solaris_size) ||
	    solaris_size <= DK_LABEL_LOC) {
		cmlb_dbg(CMLB_INFO,  un, "fdisk moved 0x%x 0x%lx",
			solaris_offset, solaris_size);
		bzero(&un->un_g, sizeof (struct dk_geom));
		bzero(&un->un_vtoc, sizeof (struct dk_vtoc));
		bzero(&un->un_map, NDKMAP * (sizeof (struct dk_map)));
		un->un_f_geometry_is_valid = FALSE;
	}
	un->un_solaris_offset = solaris_offset;
	un->un_solaris_size = solaris_size;
	kmem_free(bufp, blocksize);
	return (rval);

#else	/* #elif defined(_FIRMWARE_NEEDS_FDISK) */
#error "fdisk table presence undetermined for this platform."
#endif	/* #if defined(_NO_FDISK_PRESENT) */
}

static void
cmlb_swap_efi_gpt(efi_gpt_t *e)
{
	_NOTE(ASSUMING_PROTECTED(*e))
	e->efi_gpt_Signature = LE_64(e->efi_gpt_Signature);
	e->efi_gpt_Revision = LE_32(e->efi_gpt_Revision);
	e->efi_gpt_HeaderSize = LE_32(e->efi_gpt_HeaderSize);
	e->efi_gpt_HeaderCRC32 = LE_32(e->efi_gpt_HeaderCRC32);
	e->efi_gpt_MyLBA = LE_64(e->efi_gpt_MyLBA);
	e->efi_gpt_AlternateLBA = LE_64(e->efi_gpt_AlternateLBA);
	e->efi_gpt_FirstUsableLBA = LE_64(e->efi_gpt_FirstUsableLBA);
	e->efi_gpt_LastUsableLBA = LE_64(e->efi_gpt_LastUsableLBA);
	UUID_LE_CONVERT(e->efi_gpt_DiskGUID, e->efi_gpt_DiskGUID);
	e->efi_gpt_PartitionEntryLBA = LE_64(e->efi_gpt_PartitionEntryLBA);
	e->efi_gpt_NumberOfPartitionEntries =
	    LE_32(e->efi_gpt_NumberOfPartitionEntries);
	e->efi_gpt_SizeOfPartitionEntry =
	    LE_32(e->efi_gpt_SizeOfPartitionEntry);
	e->efi_gpt_PartitionEntryArrayCRC32 =
	    LE_32(e->efi_gpt_PartitionEntryArrayCRC32);
}

static void
cmlb_swap_efi_gpe(int nparts, efi_gpe_t *p)
{
	int i;

	_NOTE(ASSUMING_PROTECTED(*p))
	for (i = 0; i < nparts; i++) {
		UUID_LE_CONVERT(p[i].efi_gpe_PartitionTypeGUID,
		    p[i].efi_gpe_PartitionTypeGUID);
		p[i].efi_gpe_StartingLBA = LE_64(p[i].efi_gpe_StartingLBA);
		p[i].efi_gpe_EndingLBA = LE_64(p[i].efi_gpe_EndingLBA);
		/* PartitionAttrs */
	}
}

static int
cmlb_validate_efi(efi_gpt_t *labp)
{
	if (labp->efi_gpt_Signature != EFI_SIGNATURE)
		return (EINVAL);
	/* at least 96 bytes in this version of the spec. */
	if (sizeof (efi_gpt_t) - sizeof (labp->efi_gpt_Reserved2) >
	    labp->efi_gpt_HeaderSize)
		return (EINVAL);
	/* this should be 128 bytes */
	if (labp->efi_gpt_SizeOfPartitionEntry != sizeof (efi_gpe_t))
		return (EINVAL);
	return (0);
}

static int
cmlb_use_efi(struct cmlb_lun *un, diskaddr_t capacity)
{
	int		i;
	int		rval = 0;
	efi_gpe_t	*partitions;
	uchar_t		*buf;
	uint_t		lbasize;	/* is really how much to read */
	diskaddr_t	cap;
	uint_t		nparts;
	diskaddr_t	gpe_lba;
	int		iofailed = 0;

	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	lbasize = un->un_sys_blocksize;

	buf = kmem_zalloc(EFI_MIN_ARRAY_SIZE, KM_SLEEP);
	mutex_exit(CMLB_MUTEX(un));

	rval = DK_TG_READ(un, buf, 0, lbasize);
	if (rval) {
		iofailed = 1;
		goto done_err;
	}
	if (((struct dk_label *)buf)->dkl_magic == DKL_MAGIC) {
		/* not ours */
		rval = ESRCH;
		goto done_err;
	}

	rval = DK_TG_READ(un, buf, 1, lbasize);
	if (rval) {
		iofailed = 1;
		goto done_err;
	}
	cmlb_swap_efi_gpt((efi_gpt_t *)buf);

	if ((rval = cmlb_validate_efi((efi_gpt_t *)buf)) != 0) {
		/*
		 * Couldn't read the primary, try the backup.  Our
		 * capacity at this point could be based on CHS, so
		 * check what the device reports.
		 */
		rval = DK_TG_GETCAP(un, &cap);

		if (rval) {
			iofailed = 1;
			goto done_err;
		}
		if ((rval = DK_TG_READ(un, buf, cap - 1, lbasize)) != 0) {
			iofailed = 1;
			goto done_err;
		}
		cmlb_swap_efi_gpt((efi_gpt_t *)buf);
		if ((rval = cmlb_validate_efi((efi_gpt_t *)buf)) != 0)
			goto done_err;
		cmlb_log(CMLB_DEVINFO(un), CMLB_LABEL(un), CE_WARN,
		    "primary label corrupt; using backup\n");
	}

	nparts = ((efi_gpt_t *)buf)->efi_gpt_NumberOfPartitionEntries;
	gpe_lba = ((efi_gpt_t *)buf)->efi_gpt_PartitionEntryLBA;

	rval = DK_TG_READ(un, buf, gpe_lba, EFI_MIN_ARRAY_SIZE);
	if (rval) {
		iofailed = 1;
		goto done_err;
	}
	partitions = (efi_gpe_t *)buf;

	if (nparts > MAXPART) {
		nparts = MAXPART;
	}
	cmlb_swap_efi_gpe(nparts, partitions);

	mutex_enter(CMLB_MUTEX(un));

	/* Fill in partition table. */
	for (i = 0; i < nparts; i++) {
		if (partitions->efi_gpe_StartingLBA != 0 ||
		    partitions->efi_gpe_EndingLBA != 0) {
			un->un_map[i].dkl_cylno =
			    partitions->efi_gpe_StartingLBA;
			un->un_map[i].dkl_nblk =
			    partitions->efi_gpe_EndingLBA -
			    partitions->efi_gpe_StartingLBA + 1;
			un->un_offset[i] =
			    partitions->efi_gpe_StartingLBA;
		}
		if (i == WD_NODE) {
			/*
			 * minor number 7 corresponds to the whole disk
			 */
			un->un_map[i].dkl_cylno = 0;
			un->un_map[i].dkl_nblk = capacity;
			un->un_offset[i] = 0;
		}
		partitions++;
	}
	un->un_solaris_offset = 0;
	un->un_solaris_size = capacity;
	un->un_f_geometry_is_valid = TRUE;
	kmem_free(buf, EFI_MIN_ARRAY_SIZE);
	return (0);

done_err:
	kmem_free(buf, EFI_MIN_ARRAY_SIZE);
	mutex_enter(CMLB_MUTEX(un));
	/*
	 * if we didn't find something that could look like a VTOC
	 * and the disk is over 1TB, we know there isn't a valid label.
	 * Otherwise let cmlb_uselabel decide what to do.  We only
	 * want to invalidate this if we're certain the label isn't
	 * valid because cmlb_prop_op will now fail, which in turn
	 * causes things like opens and stats on the partition to fail.
	 */
	if ((capacity > DK_MAX_BLOCKS) && (rval != ESRCH) && !iofailed) {
		un->un_f_geometry_is_valid = FALSE;
	}
	return (rval);
}


/*
 *    Function: cmlb_uselabel
 *
 * Description: Validate the disk label and update the relevant data (geometry,
 *		partition, vtoc, and capacity data) in the cmlb_lun struct.
 *		Marks the geometry of the unit as being valid.
 *
 *   Arguments: un: unit struct.
 *		dk_label: disk label
 *
 * Return Code: CMLB_LABEL_IS_VALID: Label read from disk is OK; geometry,
 *		partition, vtoc, and capacity data are good.
 *
 *		CMLB_LABEL_IS_INVALID: Magic number or checksum error in the
 *		label; or computed capacity does not jibe with capacity
 *		reported from the READ CAPACITY command.
 *
 *     Context: Kernel thread only (can sleep).
 */
static int
cmlb_uselabel(struct cmlb_lun *un, struct dk_label *labp)
{
	short		*sp;
	short		sum;
	short		count;
	int		label_error = CMLB_LABEL_IS_VALID;
	int		i;
	diskaddr_t	label_capacity;
	int		part_end;
	diskaddr_t	track_capacity;
#if defined(_SUNOS_VTOC_16)
	struct	dkl_partition	*vpartp;
#endif
	ASSERT(un != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	/* Validate the magic number of the label. */
	if (labp->dkl_magic != DKL_MAGIC) {
#if defined(__sparc)
		if (!ISREMOVABLE(un)) {
			cmlb_log(CMLB_DEVINFO(un), CMLB_LABEL(un), CE_WARN,
			    "Corrupt label; wrong magic number\n");
		}
#endif
		return (CMLB_LABEL_IS_INVALID);
	}

	/* Validate the checksum of the label. */
	sp  = (short *)labp;
	sum = 0;
	count = sizeof (struct dk_label) / sizeof (short);
	while (count--)	 {
		sum ^= *sp++;
	}

	if (sum != 0) {
#if defined(_SUNOS_VTOC_16)
		if (!ISCD(un)) {
#elif defined(_SUNOS_VTOC_8)
		if (!ISREMOVABLE(un)) {
#endif
			cmlb_log(CMLB_DEVINFO(un), CMLB_LABEL(un), CE_WARN,
			    "Corrupt label - label checksum failed\n");
		}
		return (CMLB_LABEL_IS_INVALID);
	}


	/*
	 * Fill in geometry structure with data from label.
	 */
	bzero(&un->un_g, sizeof (struct dk_geom));
	un->un_g.dkg_ncyl   = labp->dkl_ncyl;
	un->un_g.dkg_acyl   = labp->dkl_acyl;
	un->un_g.dkg_bcyl   = 0;
	un->un_g.dkg_nhead  = labp->dkl_nhead;
	un->un_g.dkg_nsect  = labp->dkl_nsect;
	un->un_g.dkg_intrlv = labp->dkl_intrlv;

#if defined(_SUNOS_VTOC_8)
	un->un_g.dkg_gap1   = labp->dkl_gap1;
	un->un_g.dkg_gap2   = labp->dkl_gap2;
	un->un_g.dkg_bhead  = labp->dkl_bhead;
#endif
#if defined(_SUNOS_VTOC_16)
	un->un_dkg_skew = labp->dkl_skew;
#endif

#if defined(__i386) || defined(__amd64)
	un->un_g.dkg_apc = labp->dkl_apc;
#endif

	/*
	 * Currently we rely on the values in the label being accurate. If
	 * dkl_rpm or dkl_pcly are zero in the label, use a default value.
	 *
	 * Note: In the future a MODE SENSE may be used to retrieve this data,
	 * although this command is optional in SCSI-2.
	 */
	un->un_g.dkg_rpm  = (labp->dkl_rpm  != 0) ? labp->dkl_rpm  : 3600;
	un->un_g.dkg_pcyl = (labp->dkl_pcyl != 0) ? labp->dkl_pcyl :
	    (un->un_g.dkg_ncyl + un->un_g.dkg_acyl);

	/*
	 * The Read and Write reinstruct values may not be valid
	 * for older disks.
	 */
	un->un_g.dkg_read_reinstruct  = labp->dkl_read_reinstruct;
	un->un_g.dkg_write_reinstruct = labp->dkl_write_reinstruct;

	/* Fill in partition table. */
#if defined(_SUNOS_VTOC_8)
	for (i = 0; i < NDKMAP; i++) {
		un->un_map[i].dkl_cylno = labp->dkl_map[i].dkl_cylno;
		un->un_map[i].dkl_nblk  = labp->dkl_map[i].dkl_nblk;
	}
#endif
#if  defined(_SUNOS_VTOC_16)
	vpartp		= labp->dkl_vtoc.v_part;
	track_capacity	= labp->dkl_nhead * labp->dkl_nsect;

	for (i = 0; i < NDKMAP; i++, vpartp++) {
		un->un_map[i].dkl_cylno = vpartp->p_start / track_capacity;
		un->un_map[i].dkl_nblk  = vpartp->p_size;
	}
#endif

	/* Fill in VTOC Structure. */
	bcopy(&labp->dkl_vtoc, &un->un_vtoc, sizeof (struct dk_vtoc));
#if defined(_SUNOS_VTOC_8)
	/*
	 * The 8-slice vtoc does not include the ascii label; save it into
	 * the device's soft state structure here.
	 */
	bcopy(labp->dkl_asciilabel, un->un_asciilabel, LEN_DKL_ASCII);
#endif

	/* Mark the geometry as valid. */
	un->un_f_geometry_is_valid = TRUE;

	/* Now look for a valid capacity. */
	track_capacity	= (un->un_g.dkg_nhead * un->un_g.dkg_nsect);
	label_capacity	= (un->un_g.dkg_ncyl  * track_capacity);

	if (un->un_g.dkg_acyl) {
#if defined(__i386) || defined(__amd64)
		/* we may have > 1 alts cylinder */
		label_capacity += (track_capacity * un->un_g.dkg_acyl);
#else
		label_capacity += track_capacity;
#endif
	}

	/*
	 * if we got invalidated when mutex exit and entered again,
	 * if blockcount different than when we came in, need to
	 * retry from beginning of cmlb_validate_geometry.
	 * revisit this on next phase of utilizing this for
	 * sd.
	 */

	if (label_capacity <= un->un_blockcount) {
#if defined(_SUNOS_VTOC_8)
		/*
		 * We can't let this happen on drives that are subdivided
		 * into logical disks (i.e., that have an fdisk table).
		 * The un_blockcount field should always hold the full media
		 * size in sectors, period.  This code would overwrite
		 * un_blockcount with the size of the Solaris fdisk partition.
		 */
		cmlb_dbg(CMLB_ERROR,  un,
		    "cmlb_uselabel: Label %d blocks; Drive %d blocks\n",
		    label_capacity, un->un_blockcount);
		un->un_solaris_size = label_capacity;

#endif	/* defined(_SUNOS_VTOC_8) */
		goto done;
	}

	if (ISCD(un)) {
		/* For CDROMs, we trust that the data in the label is OK. */
#if defined(_SUNOS_VTOC_8)
		for (i = 0; i < NDKMAP; i++) {
			part_end = labp->dkl_nhead * labp->dkl_nsect *
			    labp->dkl_map[i].dkl_cylno +
			    labp->dkl_map[i].dkl_nblk  - 1;

			if ((labp->dkl_map[i].dkl_nblk) &&
			    (part_end > un->un_blockcount)) {
				un->un_f_geometry_is_valid = FALSE;
				break;
			}
		}
#endif
#if defined(_SUNOS_VTOC_16)
		vpartp = &(labp->dkl_vtoc.v_part[0]);
		for (i = 0; i < NDKMAP; i++, vpartp++) {
			part_end = vpartp->p_start + vpartp->p_size;
			if ((vpartp->p_size > 0) &&
			    (part_end > un->un_blockcount)) {
				un->un_f_geometry_is_valid = FALSE;
				break;
			}
		}
#endif
	} else {
		/* label_capacity > un->un_blockcount */
		cmlb_log(CMLB_DEVINFO(un), CMLB_LABEL(un), CE_WARN,
		    "Corrupt label - bad geometry\n");
		cmlb_log(CMLB_DEVINFO(un), CMLB_LABEL(un), CE_CONT,
		    "Label says %llu blocks; Drive says %llu blocks\n",
		    label_capacity, un->un_blockcount);
		un->un_f_geometry_is_valid = FALSE;
		label_error = CMLB_LABEL_IS_INVALID;
	}

done:

	cmlb_dbg(CMLB_INFO,  un, "cmlb_uselabel: (label geometry)\n");
	cmlb_dbg(CMLB_INFO,  un,
	    "   ncyl: %d; acyl: %d; nhead: %d; nsect: %d\n",
	    un->un_g.dkg_ncyl,  un->un_g.dkg_acyl,
	    un->un_g.dkg_nhead, un->un_g.dkg_nsect);

	cmlb_dbg(CMLB_INFO,  un,
	    "   label_capacity: %d; intrlv: %d; rpm: %d\n",
	    un->un_blockcount, un->un_g.dkg_intrlv, un->un_g.dkg_rpm);
	cmlb_dbg(CMLB_INFO,  un, "   wrt_reinstr: %d; rd_reinstr: %d\n",
	    un->un_g.dkg_write_reinstruct, un->un_g.dkg_read_reinstruct);

	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	return (label_error);
}


/*
 *    Function: cmlb_build_default_label
 *
 * Description: Generate a default label for those devices that do not have
 *		one, e.g., new media, removable cartridges, etc..
 *
 *     Context: Kernel thread only
 */
static void
cmlb_build_default_label(struct cmlb_lun *un)
{
#if defined(_SUNOS_VTOC_16)
	uint_t	phys_spc;
	uint_t	disksize;
	struct  dk_geom un_g;
#endif

	ASSERT(un != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(un)));

#if defined(_SUNOS_VTOC_8)
	/*
	 * Note: This is a legacy check for non-removable devices on VTOC_8
	 * only. This may be a valid check for VTOC_16 as well.
	 */
	if (!ISREMOVABLE(un)) {
		return;
	}
#endif

	bzero(&un->un_g, sizeof (struct dk_geom));
	bzero(&un->un_vtoc, sizeof (struct dk_vtoc));
	bzero(&un->un_map, NDKMAP * (sizeof (struct dk_map)));

#if defined(_SUNOS_VTOC_8)

	/*
	 * It's a REMOVABLE media, therefore no label (on sparc, anyway).
	 * But it is still necessary to set up various geometry information,
	 * and we are doing this here.
	 */

	/*
	 * For the rpm, we use the minimum for the disk.  For the head, cyl,
	 * and number of sector per track, if the capacity <= 1GB, head = 64,
	 * sect = 32.  else head = 255, sect 63 Note: the capacity should be
	 * equal to C*H*S values.  This will cause some truncation of size due
	 * to round off errors. For CD-ROMs, this truncation can have adverse
	 * side effects, so returning ncyl and nhead as 1. The nsect will
	 * overflow for most of CD-ROMs as nsect is of type ushort. (4190569)
	 */
	un->un_solaris_size = un->un_blockcount;
	if (ISCD(un)) {
		tg_attribute_t tgattribute;
		int is_writable;
		/*
		 * Preserve the old behavior for non-writable
		 * medias. Since dkg_nsect is a ushort, it
		 * will lose bits as cdroms have more than
		 * 65536 sectors. So if we recalculate
		 * capacity, it will become much shorter.
		 * But the dkg_* information is not
		 * used for CDROMs so it is OK. But for
		 * Writable CDs we need this information
		 * to be valid (for newfs say). So we
		 * make nsect and nhead > 1 that way
		 * nsect can still stay within ushort limit
		 * without losing any bits.
		 */

		bzero(&tgattribute, sizeof (tg_attribute_t));

		mutex_exit(CMLB_MUTEX(un));
		is_writable = (DK_TG_GETATTRIBUTE(un, &tgattribute) == 0) ?
		    tgattribute.media_is_writable : 1;
		mutex_enter(CMLB_MUTEX(un));

		if (is_writable) {
			un->un_g.dkg_nhead = 64;
			un->un_g.dkg_nsect = 32;
			un->un_g.dkg_ncyl = un->un_blockcount / (64 * 32);
			un->un_solaris_size = un->un_g.dkg_ncyl *
			    un->un_g.dkg_nhead * un->un_g.dkg_nsect;
		} else {
			un->un_g.dkg_ncyl  = 1;
			un->un_g.dkg_nhead = 1;
			un->un_g.dkg_nsect = un->un_blockcount;
		}
	} else {
		if (un->un_blockcount <= 0x1000) {
			/* unlabeled SCSI floppy device */
			un->un_g.dkg_nhead = 2;
			un->un_g.dkg_ncyl = 80;
			un->un_g.dkg_nsect = un->un_blockcount / (2 * 80);
		} else if (un->un_blockcount <= 0x200000) {
			un->un_g.dkg_nhead = 64;
			un->un_g.dkg_nsect = 32;
			un->un_g.dkg_ncyl  = un->un_blockcount / (64 * 32);
		} else {
			un->un_g.dkg_nhead = 255;
			un->un_g.dkg_nsect = 63;
			un->un_g.dkg_ncyl  = un->un_blockcount / (255 * 63);
		}
		un->un_solaris_size =
		    un->un_g.dkg_ncyl * un->un_g.dkg_nhead * un->un_g.dkg_nsect;

	}

	un->un_g.dkg_acyl	= 0;
	un->un_g.dkg_bcyl	= 0;
	un->un_g.dkg_rpm	= 200;
	un->un_asciilabel[0]	= '\0';
	un->un_g.dkg_pcyl	= un->un_g.dkg_ncyl;

	un->un_map[0].dkl_cylno = 0;
	un->un_map[0].dkl_nblk  = un->un_solaris_size;

	un->un_map[2].dkl_cylno = 0;
	un->un_map[2].dkl_nblk  = un->un_solaris_size;

#elif defined(_SUNOS_VTOC_16)

	if (un->un_solaris_size == 0) {
		/*
		 * Got fdisk table but no solaris entry therefore
		 * don't create a default label
		 */
		un->un_f_geometry_is_valid = TRUE;
		return;
	}

	/*
	 * For CDs we continue to use the physical geometry to calculate
	 * number of cylinders. All other devices must convert the
	 * physical geometry (cmlb_geom) to values that will fit
	 * in a dk_geom structure.
	 */
	if (ISCD(un)) {
		phys_spc = un->un_pgeom.g_nhead * un->un_pgeom.g_nsect;
	} else {
		/* Convert physical geometry to disk geometry */
		bzero(&un_g, sizeof (struct dk_geom));
		cmlb_convert_geometry(un->un_blockcount, &un_g);
		bcopy(&un_g, &un->un_g, sizeof (un->un_g));
		phys_spc = un->un_g.dkg_nhead * un->un_g.dkg_nsect;
	}

	un->un_g.dkg_pcyl = un->un_solaris_size / phys_spc;
	un->un_g.dkg_acyl = DK_ACYL;
	un->un_g.dkg_ncyl = un->un_g.dkg_pcyl - DK_ACYL;
	disksize = un->un_g.dkg_ncyl * phys_spc;

	if (ISCD(un)) {
		/*
		 * CD's don't use the "heads * sectors * cyls"-type of
		 * geometry, but instead use the entire capacity of the media.
		 */
		disksize = un->un_solaris_size;
		un->un_g.dkg_nhead = 1;
		un->un_g.dkg_nsect = 1;
		un->un_g.dkg_rpm =
		    (un->un_pgeom.g_rpm == 0) ? 200 : un->un_pgeom.g_rpm;

		un->un_vtoc.v_part[0].p_start = 0;
		un->un_vtoc.v_part[0].p_size  = disksize;
		un->un_vtoc.v_part[0].p_tag   = V_BACKUP;
		un->un_vtoc.v_part[0].p_flag  = V_UNMNT;

		un->un_map[0].dkl_cylno = 0;
		un->un_map[0].dkl_nblk  = disksize;
		un->un_offset[0] = 0;

	} else {
		/*
		 * Hard disks and removable media cartridges
		 */
		un->un_g.dkg_rpm =
		    (un->un_pgeom.g_rpm == 0) ? 3600: un->un_pgeom.g_rpm;
		un->un_vtoc.v_sectorsz = un->un_sys_blocksize;

		/* Add boot slice */
		un->un_vtoc.v_part[8].p_start = 0;
		un->un_vtoc.v_part[8].p_size  = phys_spc;
		un->un_vtoc.v_part[8].p_tag   = V_BOOT;
		un->un_vtoc.v_part[8].p_flag  = V_UNMNT;

		un->un_map[8].dkl_cylno = 0;
		un->un_map[8].dkl_nblk  = phys_spc;
		un->un_offset[8] = 0;

		if ((un->un_alter_behavior &
		    CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT) &&
		    un->un_device_type == DTYPE_DIRECT) {
			un->un_vtoc.v_part[9].p_start = phys_spc;
			un->un_vtoc.v_part[9].p_size  = 2 * phys_spc;
			un->un_vtoc.v_part[9].p_tag   = V_ALTSCTR;
			un->un_vtoc.v_part[9].p_flag  = 0;

			un->un_map[9].dkl_cylno = 1;
			un->un_map[9].dkl_nblk  = 2 * phys_spc;
			un->un_offset[9] = phys_spc;
		}
	}

	un->un_g.dkg_apc = 0;
	un->un_vtoc.v_nparts = V_NUMPAR;
	un->un_vtoc.v_version = V_VERSION;

	/* Add backup slice */
	un->un_vtoc.v_part[2].p_start = 0;
	un->un_vtoc.v_part[2].p_size  = disksize;
	un->un_vtoc.v_part[2].p_tag   = V_BACKUP;
	un->un_vtoc.v_part[2].p_flag  = V_UNMNT;

	un->un_map[2].dkl_cylno = 0;
	un->un_map[2].dkl_nblk  = disksize;
	un->un_offset[2] = 0;

	(void) sprintf(un->un_vtoc.v_asciilabel, "DEFAULT cyl %d alt %d"
	    " hd %d sec %d", un->un_g.dkg_ncyl, un->un_g.dkg_acyl,
	    un->un_g.dkg_nhead, un->un_g.dkg_nsect);

#else
#error "No VTOC format defined."
#endif

	un->un_g.dkg_read_reinstruct  = 0;
	un->un_g.dkg_write_reinstruct = 0;

	un->un_g.dkg_intrlv = 1;

	un->un_vtoc.v_sanity  = VTOC_SANE;

	un->un_f_geometry_is_valid = TRUE;
	un->un_vtoc_label_is_from_media = 0;

	cmlb_dbg(CMLB_INFO,  un,
	    "cmlb_build_default_label: Default label created: "
	    "cyl: %d\tacyl: %d\tnhead: %d\tnsect: %d\tcap: %d\n",
	    un->un_g.dkg_ncyl, un->un_g.dkg_acyl, un->un_g.dkg_nhead,
	    un->un_g.dkg_nsect, un->un_blockcount);
}


#if defined(_FIRMWARE_NEEDS_FDISK)
/*
 * Max CHS values, as they are encoded into bytes, for 1022/254/63
 */
#define	LBA_MAX_SECT	(63 | ((1022 & 0x300) >> 2))
#define	LBA_MAX_CYL	(1022 & 0xFF)
#define	LBA_MAX_HEAD	(254)


/*
 *    Function: cmlb_has_max_chs_vals
 *
 * Description: Return TRUE if Cylinder-Head-Sector values are all at maximum.
 *
 *   Arguments: fdp - ptr to CHS info
 *
 * Return Code: True or false
 *
 *     Context: Any.
 */
static int
cmlb_has_max_chs_vals(struct ipart *fdp)
{
	return ((fdp->begcyl  == LBA_MAX_CYL)	&&
	    (fdp->beghead == LBA_MAX_HEAD)	&&
	    (fdp->begsect == LBA_MAX_SECT)	&&
	    (fdp->endcyl  == LBA_MAX_CYL)	&&
	    (fdp->endhead == LBA_MAX_HEAD)	&&
	    (fdp->endsect == LBA_MAX_SECT));
}
#endif

/*
 *    Function: cmlb_dkio_get_geometry
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to get the device geometry (DKIOCGGEOM).
 *
 *   Arguments:
 *		arg  - pointer to user provided dk_geom structure specifying
 *			the controller's notion of the current geometry.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_get_geometry(struct cmlb_lun *un, caddr_t arg, int flag)
{
	struct dk_geom	*tmp_geom = NULL;
	int		rval = 0;

	/*
	 * cmlb_validate_geometry does not spin a disk up
	 * if it was spun down. We need to make sure it
	 * is ready.
	 */
	mutex_enter(CMLB_MUTEX(un));
	rval = cmlb_validate_geometry(un, 1);
#if defined(_SUNOS_VTOC_8)
	if (rval == EINVAL &&
	    un->un_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8) {
		/*
		 * This is to return a default label geometry even when we
		 * do not really assume a default label for the device.
		 * dad driver utilizes this.
		 */
		if (un->un_blockcount <= DK_MAX_BLOCKS) {
			cmlb_setup_default_geometry(un);
			rval = 0;
		}
	}
#endif
	if (rval) {
		mutex_exit(CMLB_MUTEX(un));
		return (rval);
	}

#if defined(__i386) || defined(__amd64)
	if (un->un_solaris_size == 0) {
		mutex_exit(CMLB_MUTEX(un));
		return (EIO);
	}
#endif

	/*
	 * Make a local copy of the soft state geometry to avoid some potential
	 * race conditions associated with holding the mutex and updating the
	 * write_reinstruct value
	 */
	tmp_geom = kmem_zalloc(sizeof (struct dk_geom), KM_SLEEP);
	bcopy(&un->un_g, tmp_geom, sizeof (struct dk_geom));

	if (tmp_geom->dkg_write_reinstruct == 0) {
		tmp_geom->dkg_write_reinstruct =
		    (int)((int)(tmp_geom->dkg_nsect * tmp_geom->dkg_rpm *
		    cmlb_rot_delay) / (int)60000);
	}
	mutex_exit(CMLB_MUTEX(un));

	rval = ddi_copyout(tmp_geom, (void *)arg, sizeof (struct dk_geom),
	    flag);
	if (rval != 0) {
		rval = EFAULT;
	}

	kmem_free(tmp_geom, sizeof (struct dk_geom));
	return (rval);

}


/*
 *    Function: cmlb_dkio_set_geometry
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to set the device geometry (DKIOCSGEOM). The actual
 *		device geometry is not updated, just the driver "notion" of it.
 *
 *   Arguments:
 *		arg  - pointer to user provided dk_geom structure used to set
 *			the controller's notion of the current geometry.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_set_geometry(struct cmlb_lun *un, caddr_t arg, int flag)
{
	struct dk_geom	*tmp_geom;
	struct dk_map	*lp;
	int		rval = 0;
	int		i;


#if defined(__i386) || defined(__amd64)
	if (un->un_solaris_size == 0) {
		return (EIO);
	}
#endif
	/*
	 * We need to copy the user specified geometry into local
	 * storage and then update the softstate. We don't want to hold
	 * the mutex and copyin directly from the user to the soft state
	 */
	tmp_geom = (struct dk_geom *)
	    kmem_zalloc(sizeof (struct dk_geom), KM_SLEEP);
	rval = ddi_copyin(arg, tmp_geom, sizeof (struct dk_geom), flag);
	if (rval != 0) {
		kmem_free(tmp_geom, sizeof (struct dk_geom));
		return (EFAULT);
	}

	mutex_enter(CMLB_MUTEX(un));
	bcopy(tmp_geom, &un->un_g, sizeof (struct dk_geom));
	for (i = 0; i < NDKMAP; i++) {
		lp  = &un->un_map[i];
		un->un_offset[i] =
		    un->un_g.dkg_nhead * un->un_g.dkg_nsect * lp->dkl_cylno;
#if defined(__i386) || defined(__amd64)
		un->un_offset[i] += un->un_solaris_offset;
#endif
	}
	un->un_f_geometry_is_valid = FALSE;
	mutex_exit(CMLB_MUTEX(un));
	kmem_free(tmp_geom, sizeof (struct dk_geom));

	return (rval);
}

/*
 *    Function: cmlb_dkio_get_partition
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to get the partition table (DKIOCGAPART).
 *
 *   Arguments:
 *		arg  - pointer to user provided dk_allmap structure specifying
 *			the controller's notion of the current partition table.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_get_partition(struct cmlb_lun *un, caddr_t arg, int flag)
{
	int		rval = 0;
	int		size;

	/*
	 * Make sure the geometry is valid before getting the partition
	 * information.
	 */
	mutex_enter(CMLB_MUTEX(un));
	if ((rval = cmlb_validate_geometry(un, 1)) != 0) {
		mutex_exit(CMLB_MUTEX(un));
		return (rval);
	}
	mutex_exit(CMLB_MUTEX(un));

#if defined(__i386) || defined(__amd64)
	if (un->un_solaris_size == 0) {
		return (EIO);
	}
#endif

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct dk_map32 dk_map32[NDKMAP];
		int		i;

		for (i = 0; i < NDKMAP; i++) {
			dk_map32[i].dkl_cylno = un->un_map[i].dkl_cylno;
			dk_map32[i].dkl_nblk  = un->un_map[i].dkl_nblk;
		}
		size = NDKMAP * sizeof (struct dk_map32);
		rval = ddi_copyout(dk_map32, (void *)arg, size, flag);
		if (rval != 0) {
			rval = EFAULT;
		}
		break;
	}
	case DDI_MODEL_NONE:
		size = NDKMAP * sizeof (struct dk_map);
		rval = ddi_copyout(un->un_map, (void *)arg, size, flag);
		if (rval != 0) {
			rval = EFAULT;
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	size = NDKMAP * sizeof (struct dk_map);
	rval = ddi_copyout(un->un_map, (void *)arg, size, flag);
	if (rval != 0) {
		rval = EFAULT;
	}
#endif /* _MULTI_DATAMODEL */
	return (rval);
}

/*
 *    Function: cmlb_dkio_set_partition
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to set the partition table (DKIOCSAPART). The actual
 *		device partition is not updated.
 *
 *   Arguments:
 *		arg  - pointer to user provided dk_allmap structure used to set
 *			the controller's notion of the partition table.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EINVAL
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_set_partition(struct cmlb_lun *un, caddr_t arg, int flag)
{
	struct dk_map	dk_map[NDKMAP];
	struct dk_map	*lp;
	int		rval = 0;
	int		size;
	int		i;
#if defined(_SUNOS_VTOC_16)
	struct dkl_partition	*vp;
#endif

	/*
	 * Set the map for all logical partitions.  We lock
	 * the priority just to make sure an interrupt doesn't
	 * come in while the map is half updated.
	 */
	_NOTE(DATA_READABLE_WITHOUT_LOCK(cmlb_lun::un_solaris_size))
	mutex_enter(CMLB_MUTEX(un));

	if (un->un_blockcount > DK_MAX_BLOCKS) {
		mutex_exit(CMLB_MUTEX(un));
		return (ENOTSUP);
	}
	mutex_exit(CMLB_MUTEX(un));
	if (un->un_solaris_size == 0) {
		return (EIO);
	}

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct dk_map32 dk_map32[NDKMAP];

		size = NDKMAP * sizeof (struct dk_map32);
		rval = ddi_copyin((void *)arg, dk_map32, size, flag);
		if (rval != 0) {
			return (EFAULT);
		}
		for (i = 0; i < NDKMAP; i++) {
			dk_map[i].dkl_cylno = dk_map32[i].dkl_cylno;
			dk_map[i].dkl_nblk  = dk_map32[i].dkl_nblk;
		}
		break;
	}
	case DDI_MODEL_NONE:
		size = NDKMAP * sizeof (struct dk_map);
		rval = ddi_copyin((void *)arg, dk_map, size, flag);
		if (rval != 0) {
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	size = NDKMAP * sizeof (struct dk_map);
	rval = ddi_copyin((void *)arg, dk_map, size, flag);
	if (rval != 0) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	mutex_enter(CMLB_MUTEX(un));
	/* Note: The size used in this bcopy is set based upon the data model */
	bcopy(dk_map, un->un_map, size);
#if defined(_SUNOS_VTOC_16)
	vp = (struct dkl_partition *)&(un->un_vtoc);
#endif	/* defined(_SUNOS_VTOC_16) */
	for (i = 0; i < NDKMAP; i++) {
		lp  = &un->un_map[i];
		un->un_offset[i] =
		    un->un_g.dkg_nhead * un->un_g.dkg_nsect * lp->dkl_cylno;
#if defined(_SUNOS_VTOC_16)
		vp->p_start = un->un_offset[i];
		vp->p_size = lp->dkl_nblk;
		vp++;
#endif	/* defined(_SUNOS_VTOC_16) */
#if defined(__i386) || defined(__amd64)
		un->un_offset[i] += un->un_solaris_offset;
#endif
	}
	mutex_exit(CMLB_MUTEX(un));
	return (rval);
}


/*
 *    Function: cmlb_dkio_get_vtoc
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to get the current volume table of contents
 *		(DKIOCGVTOC).
 *
 *   Arguments:
 *		arg  - pointer to user provided vtoc structure specifying
 *			the current vtoc.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_get_vtoc(struct cmlb_lun *un, caddr_t arg, int flag)
{
#if defined(_SUNOS_VTOC_8)
	struct vtoc	user_vtoc;
#endif	/* defined(_SUNOS_VTOC_8) */
	int		rval = 0;

	mutex_enter(CMLB_MUTEX(un));
	rval = cmlb_validate_geometry(un, 1);

#if defined(_SUNOS_VTOC_8)
	if (rval == EINVAL &&
	    (un->un_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8)) {
		/*
		 * This is to return a default label even when we do not
		 * really assume a default label for the device.
		 * dad driver utilizes this.
		 */
		if (un->un_blockcount <= DK_MAX_BLOCKS) {
			cmlb_setup_default_geometry(un);
			rval = 0;
		}
	}
#endif
	if (rval) {
		mutex_exit(CMLB_MUTEX(un));
		return (rval);
	}

#if defined(_SUNOS_VTOC_8)
	cmlb_build_user_vtoc(un, &user_vtoc);
	mutex_exit(CMLB_MUTEX(un));

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct vtoc32 user_vtoc32;

		vtoctovtoc32(user_vtoc, user_vtoc32);
		if (ddi_copyout(&user_vtoc32, (void *)arg,
		    sizeof (struct vtoc32), flag)) {
			return (EFAULT);
		}
		break;
	}

	case DDI_MODEL_NONE:
		if (ddi_copyout(&user_vtoc, (void *)arg,
		    sizeof (struct vtoc), flag)) {
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyout(&user_vtoc, (void *)arg, sizeof (struct vtoc), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

#elif defined(_SUNOS_VTOC_16)
	mutex_exit(CMLB_MUTEX(un));

#ifdef _MULTI_DATAMODEL
	/*
	 * The un_vtoc structure is a "struct dk_vtoc"  which is always
	 * 32-bit to maintain compatibility with existing on-disk
	 * structures.  Thus, we need to convert the structure when copying
	 * it out to a datamodel-dependent "struct vtoc" in a 64-bit
	 * program.  If the target is a 32-bit program, then no conversion
	 * is necessary.
	 */
	/* LINTED: logical expression always true: op "||" */
	ASSERT(sizeof (un->un_vtoc) == sizeof (struct vtoc32));
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyout(&(un->un_vtoc), (void *)arg,
		    sizeof (un->un_vtoc), flag)) {
			return (EFAULT);
		}
		break;

	case DDI_MODEL_NONE: {
		struct vtoc user_vtoc;

		vtoc32tovtoc(un->un_vtoc, user_vtoc);
		if (ddi_copyout(&user_vtoc, (void *)arg,
		    sizeof (struct vtoc), flag)) {
			return (EFAULT);
		}
		break;
	}
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyout(&(un->un_vtoc), (void *)arg, sizeof (un->un_vtoc),
	    flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */
#else
#error "No VTOC format defined."
#endif

	return (rval);
}

static int
cmlb_dkio_get_efi(struct cmlb_lun *un, caddr_t arg, int flag)
{
	dk_efi_t	user_efi;
	int		rval = 0;
	void		*buffer;

	if (ddi_copyin(arg, &user_efi, sizeof (dk_efi_t), flag))
		return (EFAULT);

	user_efi.dki_data = (void *)(uintptr_t)user_efi.dki_data_64;

	buffer = kmem_alloc(user_efi.dki_length, KM_SLEEP);
	rval = DK_TG_READ(un, buffer, user_efi.dki_lba, user_efi.dki_length);
	if (rval == 0 && ddi_copyout(buffer, user_efi.dki_data,
	    user_efi.dki_length, flag) != 0)
		rval = EFAULT;

	kmem_free(buffer, user_efi.dki_length);
	return (rval);
}

/*
 *    Function: cmlb_build_user_vtoc
 *
 * Description: This routine populates a pass by reference variable with the
 *		current volume table of contents.
 *
 *   Arguments: un - driver soft state (unit) structure
 *		user_vtoc - pointer to vtoc structure to be populated
 */
static void
cmlb_build_user_vtoc(struct cmlb_lun *un, struct vtoc *user_vtoc)
{
	struct dk_map2		*lpart;
	struct dk_map		*lmap;
	struct partition	*vpart;
	int			nblks;
	int			i;

	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	/*
	 * Return vtoc structure fields in the provided VTOC area, addressed
	 * by *vtoc.
	 */
	bzero(user_vtoc, sizeof (struct vtoc));
	user_vtoc->v_bootinfo[0] = un->un_vtoc.v_bootinfo[0];
	user_vtoc->v_bootinfo[1] = un->un_vtoc.v_bootinfo[1];
	user_vtoc->v_bootinfo[2] = un->un_vtoc.v_bootinfo[2];
	user_vtoc->v_sanity	= VTOC_SANE;
	user_vtoc->v_version	= un->un_vtoc.v_version;
	bcopy(un->un_vtoc.v_volume, user_vtoc->v_volume, LEN_DKL_VVOL);
	user_vtoc->v_sectorsz = un->un_sys_blocksize;
	user_vtoc->v_nparts = un->un_vtoc.v_nparts;

	for (i = 0; i < 10; i++)
		user_vtoc->v_reserved[i] = un->un_vtoc.v_reserved[i];

	/*
	 * Convert partitioning information.
	 *
	 * Note the conversion from starting cylinder number
	 * to starting sector number.
	 */
	lmap = un->un_map;
	lpart = (struct dk_map2 *)un->un_vtoc.v_part;
	vpart = user_vtoc->v_part;

	nblks = un->un_g.dkg_nsect * un->un_g.dkg_nhead;

	for (i = 0; i < V_NUMPAR; i++) {
		vpart->p_tag	= lpart->p_tag;
		vpart->p_flag	= lpart->p_flag;
		vpart->p_start	= lmap->dkl_cylno * nblks;
		vpart->p_size	= lmap->dkl_nblk;
		lmap++;
		lpart++;
		vpart++;

		/* (4364927) */
		user_vtoc->timestamp[i] = (time_t)un->un_vtoc.v_timestamp[i];
	}

	bcopy(un->un_asciilabel, user_vtoc->v_asciilabel, LEN_DKL_ASCII);
}

static int
cmlb_dkio_partition(struct cmlb_lun *un, caddr_t arg, int flag)
{
	struct partition64	p64;
	int			rval = 0;
	uint_t			nparts;
	efi_gpe_t		*partitions;
	efi_gpt_t		*buffer;
	diskaddr_t		gpe_lba;

	if (ddi_copyin((const void *)arg, &p64,
	    sizeof (struct partition64), flag)) {
		return (EFAULT);
	}

	buffer = kmem_alloc(EFI_MIN_ARRAY_SIZE, KM_SLEEP);
	rval = DK_TG_READ(un, buffer, 1, DEV_BSIZE);
	if (rval != 0)
		goto done_error;

	cmlb_swap_efi_gpt(buffer);

	if ((rval = cmlb_validate_efi(buffer)) != 0)
		goto done_error;

	nparts = buffer->efi_gpt_NumberOfPartitionEntries;
	gpe_lba = buffer->efi_gpt_PartitionEntryLBA;
	if (p64.p_partno > nparts) {
		/* couldn't find it */
		rval = ESRCH;
		goto done_error;
	}
	/*
	 * if we're dealing with a partition that's out of the normal
	 * 16K block, adjust accordingly
	 */
	gpe_lba += p64.p_partno / sizeof (efi_gpe_t);
	rval = DK_TG_READ(un, buffer, gpe_lba, EFI_MIN_ARRAY_SIZE);

	if (rval) {
		goto done_error;
	}
	partitions = (efi_gpe_t *)buffer;

	cmlb_swap_efi_gpe(nparts, partitions);

	partitions += p64.p_partno;
	bcopy(&partitions->efi_gpe_PartitionTypeGUID, &p64.p_type,
	    sizeof (struct uuid));
	p64.p_start = partitions->efi_gpe_StartingLBA;
	p64.p_size = partitions->efi_gpe_EndingLBA -
			p64.p_start + 1;

	if (ddi_copyout(&p64, (void *)arg, sizeof (struct partition64), flag))
		rval = EFAULT;

done_error:
	kmem_free(buffer, EFI_MIN_ARRAY_SIZE);
	return (rval);
}


/*
 *    Function: cmlb_dkio_set_vtoc
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to set the current volume table of contents
 *		(DKIOCSVTOC).
 *
 *   Arguments: dev  - the device number
 *		arg  - pointer to user provided vtoc structure used to set the
 *			current vtoc.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EINVAL
 *		ENOTSUP
 */
static int
cmlb_dkio_set_vtoc(struct cmlb_lun *un, dev_t dev, caddr_t arg, int flag)
{
	struct vtoc	user_vtoc;
	int		rval = 0;

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct vtoc32 user_vtoc32;

		if (ddi_copyin((const void *)arg, &user_vtoc32,
		    sizeof (struct vtoc32), flag)) {
			return (EFAULT);
		}
		vtoc32tovtoc(user_vtoc32, user_vtoc);
		break;
	}

	case DDI_MODEL_NONE:
		if (ddi_copyin((const void *)arg, &user_vtoc,
		    sizeof (struct vtoc), flag)) {
			return (EFAULT);
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyin((const void *)arg, &user_vtoc,
	    sizeof (struct vtoc), flag)) {
		return (EFAULT);
	}
#endif /* _MULTI_DATAMODEL */

	mutex_enter(CMLB_MUTEX(un));
	if (un->un_blockcount > DK_MAX_BLOCKS) {
		mutex_exit(CMLB_MUTEX(un));
		return (ENOTSUP);
	}
	if (un->un_g.dkg_ncyl == 0) {
		mutex_exit(CMLB_MUTEX(un));
		return (EINVAL);
	}

	mutex_exit(CMLB_MUTEX(un));
	cmlb_clear_efi(un);
	ddi_remove_minor_node(CMLB_DEVINFO(un), "wd");
	ddi_remove_minor_node(CMLB_DEVINFO(un), "wd,raw");
	(void) ddi_create_minor_node(CMLB_DEVINFO(un), "h",
	    S_IFBLK, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    un->un_node_type, NULL);
	(void) ddi_create_minor_node(CMLB_DEVINFO(un), "h,raw",
	    S_IFCHR, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    un->un_node_type, NULL);
	mutex_enter(CMLB_MUTEX(un));

	if ((rval = cmlb_build_label_vtoc(un, &user_vtoc)) == 0) {
		if ((rval = cmlb_write_label(un)) == 0) {
			if (cmlb_validate_geometry(un, 1) != 0) {
				cmlb_dbg(CMLB_ERROR, un,
				    "cmlb_dkio_set_vtoc: "
				    "Failed validate geometry\n");
			}
		}
	}
	mutex_exit(CMLB_MUTEX(un));
	return (rval);
}


/*
 *    Function: cmlb_build_label_vtoc
 *
 * Description: This routine updates the driver soft state current volume table
 *		of contents based on a user specified vtoc.
 *
 *   Arguments: un - driver soft state (unit) structure
 *		user_vtoc - pointer to vtoc structure specifying vtoc to be used
 *			    to update the driver soft state.
 *
 * Return Code: 0
 *		EINVAL
 */
static int
cmlb_build_label_vtoc(struct cmlb_lun *un, struct vtoc *user_vtoc)
{
	struct dk_map		*lmap;
	struct partition	*vpart;
	int			nblks;
#if defined(_SUNOS_VTOC_8)
	int			ncyl;
	struct dk_map2		*lpart;
#endif	/* defined(_SUNOS_VTOC_8) */
	int			i;

	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	/* Sanity-check the vtoc */
	if (user_vtoc->v_sanity != VTOC_SANE ||
	    user_vtoc->v_sectorsz != un->un_sys_blocksize ||
	    user_vtoc->v_nparts != V_NUMPAR) {
		cmlb_dbg(CMLB_INFO,  un,
		    "cmlb_build_label_vtoc: vtoc not valid\n");
		return (EINVAL);
	}

	nblks = un->un_g.dkg_nsect * un->un_g.dkg_nhead;
	if (nblks == 0) {
		cmlb_dbg(CMLB_INFO,  un,
		    "cmlb_build_label_vtoc: geom nblks is 0\n");
		return (EINVAL);
	}

#if defined(_SUNOS_VTOC_8)
	vpart = user_vtoc->v_part;
	for (i = 0; i < V_NUMPAR; i++) {
		if ((vpart->p_start % nblks) != 0) {
			cmlb_dbg(CMLB_INFO,  un,
			    "cmlb_build_label_vtoc: p_start not multiply of"
			    "nblks part %d p_start %d nblks %d\n", i,
			    vpart->p_start, nblks);
			return (EINVAL);
		}
		ncyl = vpart->p_start / nblks;
		ncyl += vpart->p_size / nblks;
		if ((vpart->p_size % nblks) != 0) {
			ncyl++;
		}
		if (ncyl > (int)un->un_g.dkg_ncyl) {
			cmlb_dbg(CMLB_INFO,  un,
			    "cmlb_build_label_vtoc: ncyl %d  > dkg_ncyl %d"
			    "p_size %ld p_start %ld nblks %d  part number %d"
			    "tag %d\n",
			    ncyl, un->un_g.dkg_ncyl, vpart->p_size,
			    vpart->p_start, nblks,
			    i, vpart->p_tag);

			return (EINVAL);
		}
		vpart++;
	}
#endif	/* defined(_SUNOS_VTOC_8) */

	/* Put appropriate vtoc structure fields into the disk label */
#if defined(_SUNOS_VTOC_16)
	/*
	 * The vtoc is always a 32bit data structure to maintain the
	 * on-disk format. Convert "in place" instead of doing bcopy.
	 */
	vtoctovtoc32((*user_vtoc), (*((struct vtoc32 *)&(un->un_vtoc))));

	/*
	 * in the 16-slice vtoc, starting sectors are expressed in
	 * numbers *relative* to the start of the Solaris fdisk partition.
	 */
	lmap = un->un_map;
	vpart = user_vtoc->v_part;

	for (i = 0; i < (int)user_vtoc->v_nparts; i++, lmap++, vpart++) {
		lmap->dkl_cylno = vpart->p_start / nblks;
		lmap->dkl_nblk = vpart->p_size;
	}

#elif defined(_SUNOS_VTOC_8)

	un->un_vtoc.v_bootinfo[0] = (uint32_t)user_vtoc->v_bootinfo[0];
	un->un_vtoc.v_bootinfo[1] = (uint32_t)user_vtoc->v_bootinfo[1];
	un->un_vtoc.v_bootinfo[2] = (uint32_t)user_vtoc->v_bootinfo[2];

	un->un_vtoc.v_sanity = (uint32_t)user_vtoc->v_sanity;
	un->un_vtoc.v_version = (uint32_t)user_vtoc->v_version;

	bcopy(user_vtoc->v_volume, un->un_vtoc.v_volume, LEN_DKL_VVOL);

	un->un_vtoc.v_nparts = user_vtoc->v_nparts;

	for (i = 0; i < 10; i++)
		un->un_vtoc.v_reserved[i] =  user_vtoc->v_reserved[i];

	/*
	 * Note the conversion from starting sector number
	 * to starting cylinder number.
	 * Return error if division results in a remainder.
	 */
	lmap = un->un_map;
	lpart = un->un_vtoc.v_part;
	vpart = user_vtoc->v_part;

	for (i = 0; i < (int)user_vtoc->v_nparts; i++) {
		lpart->p_tag  = vpart->p_tag;
		lpart->p_flag = vpart->p_flag;
		lmap->dkl_cylno = vpart->p_start / nblks;
		lmap->dkl_nblk = vpart->p_size;

		lmap++;
		lpart++;
		vpart++;

		/* (4387723) */
#ifdef _LP64
		if (user_vtoc->timestamp[i] > TIME32_MAX) {
			un->un_vtoc.v_timestamp[i] = TIME32_MAX;
		} else {
			un->un_vtoc.v_timestamp[i] = user_vtoc->timestamp[i];
		}
#else
		un->un_vtoc.v_timestamp[i] = user_vtoc->timestamp[i];
#endif
	}

	bcopy(user_vtoc->v_asciilabel, un->un_asciilabel, LEN_DKL_ASCII);
#else
#error "No VTOC format defined."
#endif
	return (0);
}

/*
 *    Function: cmlb_clear_efi
 *
 * Description: This routine clears all EFI labels.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: void
 */
static void
cmlb_clear_efi(struct cmlb_lun *un)
{
	efi_gpt_t	*gpt;
	diskaddr_t	cap;
	int		rval;

	ASSERT(!mutex_owned(CMLB_MUTEX(un)));

	gpt = kmem_alloc(sizeof (efi_gpt_t), KM_SLEEP);

	if (DK_TG_READ(un, gpt, 1, DEV_BSIZE) != 0) {
		goto done;
	}

	cmlb_swap_efi_gpt(gpt);
	rval = cmlb_validate_efi(gpt);
	if (rval == 0) {
		/* clear primary */
		bzero(gpt, sizeof (efi_gpt_t));
		if (rval = DK_TG_WRITE(un, gpt, 1, EFI_LABEL_SIZE)) {
			cmlb_dbg(CMLB_INFO,  un,
				"cmlb_clear_efi: clear primary label failed\n");
		}
	}
	/* the backup */
	rval = DK_TG_GETCAP(un, &cap);
	if (rval) {
		goto done;
	}

	if ((rval = DK_TG_READ(un, gpt, cap - 1, EFI_LABEL_SIZE)) != 0) {
		goto done;
	}
	cmlb_swap_efi_gpt(gpt);
	rval = cmlb_validate_efi(gpt);
	if (rval == 0) {
		/* clear backup */
		cmlb_dbg(CMLB_TRACE,  un,
		    "cmlb_clear_efi clear backup@%lu\n", cap - 1);
		bzero(gpt, sizeof (efi_gpt_t));
		if ((rval = DK_TG_WRITE(un, gpt, cap - 1, EFI_LABEL_SIZE))) {
			cmlb_dbg(CMLB_INFO,  un,
				"cmlb_clear_efi: clear backup label failed\n");
		}
	}

done:
	kmem_free(gpt, sizeof (efi_gpt_t));
}

/*
 *    Function: cmlb_set_vtoc
 *
 * Description: This routine writes data to the appropriate positions
 *
 *   Arguments: un - driver soft state (unit) structure
 *              dkl  - the data to be written
 *
 * Return: void
 */
static int
cmlb_set_vtoc(struct cmlb_lun *un, struct dk_label *dkl)
{
	uint_t	label_addr;
	int	sec;
	int	blk;
	int	head;
	int	cyl;
	int	rval;

#if defined(__i386) || defined(__amd64)
	label_addr = un->un_solaris_offset + DK_LABEL_LOC;
#else
	/* Write the primary label at block 0 of the solaris partition. */
	label_addr = 0;
#endif

	rval = DK_TG_WRITE(un, dkl, label_addr, un->un_sys_blocksize);

	if (rval != 0) {
		return (rval);
	}

	/*
	 * Calculate where the backup labels go.  They are always on
	 * the last alternate cylinder, but some older drives put them
	 * on head 2 instead of the last head.	They are always on the
	 * first 5 odd sectors of the appropriate track.
	 *
	 * We have no choice at this point, but to believe that the
	 * disk label is valid.	 Use the geometry of the disk
	 * as described in the label.
	 */
	cyl  = dkl->dkl_ncyl  + dkl->dkl_acyl - 1;
	head = dkl->dkl_nhead - 1;

	/*
	 * Write and verify the backup labels. Make sure we don't try to
	 * write past the last cylinder.
	 */
	for (sec = 1; ((sec < 5 * 2 + 1) && (sec < dkl->dkl_nsect)); sec += 2) {
		blk = (daddr_t)(
		    (cyl * ((dkl->dkl_nhead * dkl->dkl_nsect) - dkl->dkl_apc)) +
		    (head * dkl->dkl_nsect) + sec);
#if defined(__i386) || defined(__amd64)
		blk += un->un_solaris_offset;
#endif
		rval = DK_TG_WRITE(un, dkl, blk, un->un_sys_blocksize);
		cmlb_dbg(CMLB_INFO,  un,
		"cmlb_set_vtoc: wrote backup label %d\n", blk);
		if (rval != 0) {
			goto exit;
		}
	}
exit:
	return (rval);
}

/*
 *    Function: cmlb_clear_vtoc
 *
 * Description: This routine clears out the VTOC labels.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return: void
 */
static void
cmlb_clear_vtoc(struct cmlb_lun *un)
{
	struct dk_label		*dkl;

	mutex_exit(CMLB_MUTEX(un));
	dkl = kmem_zalloc(sizeof (struct dk_label), KM_SLEEP);
	mutex_enter(CMLB_MUTEX(un));
	/*
	 * cmlb_set_vtoc uses these fields in order to figure out
	 * where to overwrite the backup labels
	 */
	dkl->dkl_apc    = un->un_g.dkg_apc;
	dkl->dkl_ncyl   = un->un_g.dkg_ncyl;
	dkl->dkl_acyl   = un->un_g.dkg_acyl;
	dkl->dkl_nhead  = un->un_g.dkg_nhead;
	dkl->dkl_nsect  = un->un_g.dkg_nsect;
	mutex_exit(CMLB_MUTEX(un));
	(void) cmlb_set_vtoc(un, dkl);
	kmem_free(dkl, sizeof (struct dk_label));

	mutex_enter(CMLB_MUTEX(un));
}

/*
 *    Function: cmlb_write_label
 *
 * Description: This routine will validate and write the driver soft state vtoc
 *		contents to the device.
 *
 *   Arguments: un	cmlb handle
 *
 * Return Code: the code returned by cmlb_send_scsi_cmd()
 *		0
 *		EINVAL
 *		ENXIO
 *		ENOMEM
 */
static int
cmlb_write_label(struct cmlb_lun *un)
{
	struct dk_label	*dkl;
	short		sum;
	short		*sp;
	int		i;
	int		rval;

	ASSERT(mutex_owned(CMLB_MUTEX(un)));
	mutex_exit(CMLB_MUTEX(un));
	dkl = kmem_zalloc(sizeof (struct dk_label), KM_SLEEP);
	mutex_enter(CMLB_MUTEX(un));

	bcopy(&un->un_vtoc, &dkl->dkl_vtoc, sizeof (struct dk_vtoc));
	dkl->dkl_rpm	= un->un_g.dkg_rpm;
	dkl->dkl_pcyl	= un->un_g.dkg_pcyl;
	dkl->dkl_apc	= un->un_g.dkg_apc;
	dkl->dkl_intrlv = un->un_g.dkg_intrlv;
	dkl->dkl_ncyl	= un->un_g.dkg_ncyl;
	dkl->dkl_acyl	= un->un_g.dkg_acyl;
	dkl->dkl_nhead	= un->un_g.dkg_nhead;
	dkl->dkl_nsect	= un->un_g.dkg_nsect;

#if defined(_SUNOS_VTOC_8)
	dkl->dkl_obs1	= un->un_g.dkg_obs1;
	dkl->dkl_obs2	= un->un_g.dkg_obs2;
	dkl->dkl_obs3	= un->un_g.dkg_obs3;
	for (i = 0; i < NDKMAP; i++) {
		dkl->dkl_map[i].dkl_cylno = un->un_map[i].dkl_cylno;
		dkl->dkl_map[i].dkl_nblk  = un->un_map[i].dkl_nblk;
	}
	bcopy(un->un_asciilabel, dkl->dkl_asciilabel, LEN_DKL_ASCII);
#elif defined(_SUNOS_VTOC_16)
	dkl->dkl_skew	= un->un_dkg_skew;
#else
#error "No VTOC format defined."
#endif

	dkl->dkl_magic			= DKL_MAGIC;
	dkl->dkl_write_reinstruct	= un->un_g.dkg_write_reinstruct;
	dkl->dkl_read_reinstruct	= un->un_g.dkg_read_reinstruct;

	/* Construct checksum for the new disk label */
	sum = 0;
	sp = (short *)dkl;
	i = sizeof (struct dk_label) / sizeof (short);
	while (i--) {
		sum ^= *sp++;
	}
	dkl->dkl_cksum = sum;

	mutex_exit(CMLB_MUTEX(un));

	rval = cmlb_set_vtoc(un, dkl);
exit:
	kmem_free(dkl, sizeof (struct dk_label));
	mutex_enter(CMLB_MUTEX(un));
	return (rval);
}

static int
cmlb_dkio_set_efi(struct cmlb_lun *un, dev_t dev, caddr_t arg, int flag)
{
	dk_efi_t	user_efi;
	int		rval = 0;
	void		*buffer;

	if (ddi_copyin(arg, &user_efi, sizeof (dk_efi_t), flag))
		return (EFAULT);

	user_efi.dki_data = (void *)(uintptr_t)user_efi.dki_data_64;

	buffer = kmem_alloc(user_efi.dki_length, KM_SLEEP);
	if (ddi_copyin(user_efi.dki_data, buffer, user_efi.dki_length, flag)) {
		rval = EFAULT;
	} else {
		/*
		 * let's clear the vtoc labels and clear the softstate
		 * vtoc.
		 */
		mutex_enter(CMLB_MUTEX(un));
		if (un->un_vtoc.v_sanity == VTOC_SANE) {
			cmlb_dbg(CMLB_TRACE,  un,
				"cmlb_dkio_set_efi: CLEAR VTOC\n");
			if (un->un_vtoc_label_is_from_media)
				cmlb_clear_vtoc(un);
			bzero(&un->un_vtoc, sizeof (struct dk_vtoc));
			mutex_exit(CMLB_MUTEX(un));
			ddi_remove_minor_node(CMLB_DEVINFO(un), "h");
			ddi_remove_minor_node(CMLB_DEVINFO(un), "h,raw");
			(void) ddi_create_minor_node(CMLB_DEVINFO(un), "wd",
			    S_IFBLK,
			    (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
			    un->un_node_type, NULL);
			(void) ddi_create_minor_node(CMLB_DEVINFO(un), "wd,raw",
			    S_IFCHR,
			    (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
			    un->un_node_type, NULL);
		} else
			mutex_exit(CMLB_MUTEX(un));
		rval = DK_TG_WRITE(un, buffer, user_efi.dki_lba,
		    user_efi.dki_length);
		if (rval == 0) {
			mutex_enter(CMLB_MUTEX(un));
			un->un_f_geometry_is_valid = FALSE;
			mutex_exit(CMLB_MUTEX(un));
		}
	}
	kmem_free(buffer, user_efi.dki_length);
	return (rval);
}

/*
 *    Function: cmlb_dkio_get_mboot
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to get the current device mboot (DKIOCGMBOOT)
 *
 *   Arguments:
 *		arg  - pointer to user provided mboot structure specifying
 *			the current mboot.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EINVAL
 *		EFAULT
 *		ENXIO
 */
static int
cmlb_dkio_get_mboot(struct cmlb_lun *un, caddr_t arg, int flag)
{
	struct mboot	*mboot;
	int		rval;
	size_t		buffer_size;


#if defined(_SUNOS_VTOC_8)
	if ((!ISREMOVABLE(un)) || (arg == NULL)) {
#elif defined(_SUNOS_VTOC_16)
	if (arg == NULL) {
#endif
		return (EINVAL);
	}

	/*
	 * Read the mboot block, located at absolute block 0 on the target.
	 */
	buffer_size = sizeof (struct mboot);

	cmlb_dbg(CMLB_TRACE,  un,
	    "cmlb_dkio_get_mboot: allocation size: 0x%x\n", buffer_size);

	mboot = kmem_zalloc(buffer_size, KM_SLEEP);
	if ((rval = DK_TG_READ(un, mboot, 0, buffer_size)) == 0) {
		if (ddi_copyout(mboot, (void *)arg,
		    sizeof (struct mboot), flag) != 0) {
			rval = EFAULT;
		}
	}
	kmem_free(mboot, buffer_size);
	return (rval);
}


/*
 *    Function: cmlb_dkio_set_mboot
 *
 * Description: This routine is the driver entry point for handling user
 *		requests to validate and set the device master boot
 *		(DKIOCSMBOOT).
 *
 *   Arguments:
 *		arg  - pointer to user provided mboot structure used to set the
 *			master boot.
 *		flag - this argument is a pass through to ddi_copyxxx()
 *		       directly from the mode argument of ioctl().
 *
 * Return Code: 0
 *		EINVAL
 *		EFAULT
 *		ENXIO
 */
static int
cmlb_dkio_set_mboot(struct cmlb_lun *un, caddr_t arg, int flag)
{
	struct mboot	*mboot = NULL;
	int		rval;
	ushort_t	magic;


	ASSERT(!mutex_owned(CMLB_MUTEX(un)));

#if defined(_SUNOS_VTOC_8)
	if (!ISREMOVABLE(un)) {
		return (EINVAL);
	}
#endif

	if (arg == NULL) {
		return (EINVAL);
	}

	mboot = kmem_zalloc(sizeof (struct mboot), KM_SLEEP);

	if (ddi_copyin((const void *)arg, mboot,
	    sizeof (struct mboot), flag) != 0) {
		kmem_free(mboot, (size_t)(sizeof (struct mboot)));
		return (EFAULT);
	}

	/* Is this really a master boot record? */
	magic = LE_16(mboot->signature);
	if (magic != MBB_MAGIC) {
		kmem_free(mboot, (size_t)(sizeof (struct mboot)));
		return (EINVAL);
	}

	rval = DK_TG_WRITE(un, mboot, 0, un->un_sys_blocksize);

	mutex_enter(CMLB_MUTEX(un));
#if defined(__i386) || defined(__amd64)
	if (rval == 0) {
		/*
		 * mboot has been written successfully.
		 * update the fdisk and vtoc tables in memory
		 */
		rval = cmlb_update_fdisk_and_vtoc(un);
		if ((un->un_f_geometry_is_valid == FALSE) || (rval != 0)) {
			mutex_exit(CMLB_MUTEX(un));
			kmem_free(mboot, (size_t)(sizeof (struct mboot)));
			return (rval);
		}
	}
#else
	if (rval == 0) {
		/*
		 * mboot has been written successfully.
		 * set up the default geometry and VTOC
		 */
		if (un->un_blockcount <= DK_MAX_BLOCKS)
			cmlb_setup_default_geometry(un);
	}
#endif
	mutex_exit(CMLB_MUTEX(un));
	kmem_free(mboot, (size_t)(sizeof (struct mboot)));
	return (rval);
}


/*
 *    Function: cmlb_setup_default_geometry
 *
 * Description: This local utility routine sets the default geometry as part of
 *		setting the device mboot.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Note: This may be redundant with cmlb_build_default_label.
 */
static void
cmlb_setup_default_geometry(struct cmlb_lun *un)
{
	struct cmlb_geom	pgeom;
	struct cmlb_geom	*pgeomp = &pgeom;
	int			ret;
	int			geom_base_cap = 1;


	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	/* zero out the soft state geometry and partition table. */
	bzero(&un->un_g, sizeof (struct dk_geom));
	bzero(&un->un_vtoc, sizeof (struct dk_vtoc));
	bzero(un->un_map, NDKMAP * (sizeof (struct dk_map)));

	/*
	 * For the rpm, we use the minimum for the disk.
	 * For the head, cyl and number of sector per track,
	 * if the capacity <= 1GB, head = 64, sect = 32.
	 * else head = 255, sect 63
	 * Note: the capacity should be equal to C*H*S values.
	 * This will cause some truncation of size due to
	 * round off errors. For CD-ROMs, this truncation can
	 * have adverse side effects, so returning ncyl and
	 * nhead as 1. The nsect will overflow for most of
	 * CD-ROMs as nsect is of type ushort.
	 */
	if (un->un_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8) {
		/*
		 * newfs currently can not handle 255 ntracks for SPARC
		 * so get the geometry from target driver instead of coming up
		 * with one based on capacity.
		 */
		mutex_exit(CMLB_MUTEX(un));
		ret = DK_TG_GETPHYGEOM(un, pgeomp);
		mutex_enter(CMLB_MUTEX(un));

		if (ret  == 0) {
			geom_base_cap = 0;
		} else {
			cmlb_dbg(CMLB_ERROR,  un,
			    "cmlb_setup_default_geometry: "
			    "tg_getphygeom failed %d\n", ret);

			/* do default setting, geometry based on capacity */
		}
	}

	if (geom_base_cap) {
		if (ISCD(un)) {
			un->un_g.dkg_ncyl = 1;
			un->un_g.dkg_nhead = 1;
			un->un_g.dkg_nsect = un->un_blockcount;
		} else if (un->un_blockcount <= 0x1000) {
			/* Needed for unlabeled SCSI floppies. */
			un->un_g.dkg_nhead = 2;
			un->un_g.dkg_ncyl = 80;
			un->un_g.dkg_pcyl = 80;
			un->un_g.dkg_nsect = un->un_blockcount / (2 * 80);
		} else if (un->un_blockcount <= 0x200000) {
			un->un_g.dkg_nhead = 64;
			un->un_g.dkg_nsect = 32;
			un->un_g.dkg_ncyl = un->un_blockcount / (64 * 32);
		} else {
			un->un_g.dkg_nhead = 255;
			un->un_g.dkg_nsect = 63;
			un->un_g.dkg_ncyl = un->un_blockcount / (255 * 63);
		}

		un->un_g.dkg_acyl = 0;
		un->un_g.dkg_bcyl = 0;
		un->un_g.dkg_intrlv = 1;
		un->un_g.dkg_rpm = 200;
		if (un->un_g.dkg_pcyl == 0)
			un->un_g.dkg_pcyl = un->un_g.dkg_ncyl +
			    un->un_g.dkg_acyl;
	} else {
		un->un_g.dkg_ncyl = (short)pgeomp->g_ncyl;
		un->un_g.dkg_acyl = pgeomp->g_acyl;
		un->un_g.dkg_nhead = pgeomp->g_nhead;
		un->un_g.dkg_nsect = pgeomp->g_nsect;
		un->un_g.dkg_intrlv = pgeomp->g_intrlv;
		un->un_g.dkg_rpm = pgeomp->g_rpm;
		un->un_g.dkg_pcyl = un->un_g.dkg_ncyl + un->un_g.dkg_acyl;
	}

	un->un_g.dkg_read_reinstruct = 0;
	un->un_g.dkg_write_reinstruct = 0;
	un->un_solaris_size = un->un_g.dkg_ncyl *
	    un->un_g.dkg_nhead * un->un_g.dkg_nsect;

	un->un_map['a'-'a'].dkl_cylno = 0;
	un->un_map['a'-'a'].dkl_nblk = un->un_solaris_size;

	un->un_map['c'-'a'].dkl_cylno = 0;
	un->un_map['c'-'a'].dkl_nblk = un->un_solaris_size;

	un->un_vtoc.v_part[2].p_tag   = V_BACKUP;
	un->un_vtoc.v_part[2].p_flag  = V_UNMNT;
	un->un_vtoc.v_nparts = V_NUMPAR;
	un->un_vtoc.v_version = V_VERSION;
	(void) sprintf((char *)un->un_asciilabel, "DEFAULT cyl %d alt %d"
	    " hd %d sec %d", un->un_g.dkg_ncyl, un->un_g.dkg_acyl,
	    un->un_g.dkg_nhead, un->un_g.dkg_nsect);

	un->un_f_geometry_is_valid = FALSE;
}


#if defined(__i386) || defined(__amd64)
/*
 *    Function: cmlb_update_fdisk_and_vtoc
 *
 * Description: This local utility routine updates the device fdisk and vtoc
 *		as part of setting the device mboot.
 *
 *   Arguments: un - driver soft state (unit) structure
 *
 * Return Code: 0 for success or errno-type return code.
 *
 *    Note:x86: This looks like a duplicate of cmlb_validate_geometry(), but
 *		these did exist separately in x86 sd.c.
 */
static int
cmlb_update_fdisk_and_vtoc(struct cmlb_lun *un)
{
	int		count;
	int		label_rc = 0;
	int		fdisk_rval;
	diskaddr_t	capacity;

	ASSERT(mutex_owned(CMLB_MUTEX(un)));

	if (cmlb_check_update_blockcount(un) != 0)
		return (EINVAL);

#if defined(_SUNOS_VTOC_16)
	/*
	 * Set up the "whole disk" fdisk partition; this should always
	 * exist, regardless of whether the disk contains an fdisk table
	 * or vtoc.
	 */
	un->un_map[P0_RAW_DISK].dkl_cylno = 0;
	un->un_map[P0_RAW_DISK].dkl_nblk = un->un_blockcount;
#endif	/* defined(_SUNOS_VTOC_16) */

	/*
	 * copy the lbasize and capacity so that if they're
	 * reset while we're not holding the CMLB_MUTEX(un), we will
	 * continue to use valid values after the CMLB_MUTEX(un) is
	 * reacquired.
	 */
	capacity = un->un_blockcount;

	/*
	 * refresh the logical and physical geometry caches.
	 * (data from mode sense format/rigid disk geometry pages,
	 * and scsi_ifgetcap("geometry").
	 */
	cmlb_resync_geom_caches(un, capacity);

	/*
	 * Only DIRECT ACCESS devices will have Sun labels.
	 * CD's supposedly have a Sun label, too
	 */
	if (un->un_device_type == DTYPE_DIRECT || ISREMOVABLE(un)) {
		fdisk_rval = cmlb_read_fdisk(un, capacity);
		if (fdisk_rval != 0) {
			ASSERT(mutex_owned(CMLB_MUTEX(un)));
			return (fdisk_rval);
		}

		if (un->un_solaris_size <= DK_LABEL_LOC) {
			/*
			 * Found fdisk table but no Solaris partition entry,
			 * so don't call cmlb_uselabel() and don't create
			 * a default label.
			 */
			label_rc = 0;
			un->un_f_geometry_is_valid = TRUE;
			goto no_solaris_partition;
		}
	} else if (capacity < 0) {
		ASSERT(mutex_owned(CMLB_MUTEX(un)));
		return (EINVAL);
	}

	/*
	 * For Removable media We reach here if we have found a
	 * SOLARIS PARTITION.
	 * If un_f_geometry_is_valid is FALSE it indicates that the SOLARIS
	 * PARTITION has changed from the previous one, hence we will setup a
	 * default VTOC in this case.
	 */
	if (un->un_f_geometry_is_valid == FALSE) {
		/* if we get here it is writable */
		/* we are called from SMBOOT, and after a write of fdisk */
		cmlb_build_default_label(un);
		label_rc = 0;
	}

no_solaris_partition:

#if defined(_SUNOS_VTOC_16)
	/*
	 * If we have valid geometry, set up the remaining fdisk partitions.
	 * Note that dkl_cylno is not used for the fdisk map entries, so
	 * we set it to an entirely bogus value.
	 */
	for (count = 0; count < FD_NUMPART; count++) {
		un->un_map[FDISK_P1 + count].dkl_cylno = -1;
		un->un_map[FDISK_P1 + count].dkl_nblk =
		    un->un_fmap[count].fmap_nblk;
		un->un_offset[FDISK_P1 + count] =
		    un->un_fmap[count].fmap_start;
	}
#endif

	for (count = 0; count < NDKMAP; count++) {
#if defined(_SUNOS_VTOC_8)
		struct dk_map *lp  = &un->un_map[count];
		un->un_offset[count] =
		    un->un_g.dkg_nhead * un->un_g.dkg_nsect * lp->dkl_cylno;
#elif defined(_SUNOS_VTOC_16)
		struct dkl_partition *vp = &un->un_vtoc.v_part[count];
		un->un_offset[count] = vp->p_start + un->un_solaris_offset;
#else
#error "No VTOC format defined."
#endif
	}

	ASSERT(mutex_owned(CMLB_MUTEX(un)));
	return (label_rc);
}
#endif

#if defined(__i386) || defined(__amd64)
static int
cmlb_dkio_get_virtgeom(struct cmlb_lun *un, caddr_t arg, int flag)
{
	int err = 0;

	/* Return the driver's notion of the media's logical geometry */
	struct dk_geom	disk_geom;
	struct dk_geom	*dkgp = &disk_geom;

	mutex_enter(CMLB_MUTEX(un));
	/*
	 * If there is no HBA geometry available, or
	 * if the HBA returned us something that doesn't
	 * really fit into an Int 13/function 8 geometry
	 * result, just fail the ioctl.  See PSARC 1998/313.
	 */
	if (un->un_lgeom.g_nhead == 0 ||
	    un->un_lgeom.g_nsect == 0 ||
	    un->un_lgeom.g_ncyl > 1024) {
		mutex_exit(CMLB_MUTEX(un));
		err = EINVAL;
	} else {
		dkgp->dkg_ncyl	= un->un_lgeom.g_ncyl;
		dkgp->dkg_acyl	= un->un_lgeom.g_acyl;
		dkgp->dkg_pcyl	= dkgp->dkg_ncyl + dkgp->dkg_acyl;
		dkgp->dkg_nhead	= un->un_lgeom.g_nhead;
		dkgp->dkg_nsect	= un->un_lgeom.g_nsect;

		if (ddi_copyout(dkgp, (void *)arg,
		    sizeof (struct dk_geom), flag)) {
			mutex_exit(CMLB_MUTEX(un));
			err = EFAULT;
		} else {
			mutex_exit(CMLB_MUTEX(un));
			err = 0;
		}
	}
	return (err);
}
#endif

#if defined(__i386) || defined(__amd64)
static int
cmlb_dkio_get_phygeom(struct cmlb_lun *un, caddr_t  arg, int flag)
{
	int err = 0;


	/* Return the driver's notion of the media physical geometry */
	struct dk_geom	disk_geom;
	struct dk_geom	*dkgp = &disk_geom;

	mutex_enter(CMLB_MUTEX(un));

	if (un->un_g.dkg_nhead != 0 &&
	    un->un_g.dkg_nsect != 0) {
		/*
		 * We succeeded in getting a geometry, but
		 * right now it is being reported as just the
		 * Solaris fdisk partition, just like for
		 * DKIOCGGEOM. We need to change that to be
		 * correct for the entire disk now.
		 */
		bcopy(&un->un_g, dkgp, sizeof (*dkgp));
		dkgp->dkg_acyl = 0;
		dkgp->dkg_ncyl = un->un_blockcount /
		    (dkgp->dkg_nhead * dkgp->dkg_nsect);
	} else {
		bzero(dkgp, sizeof (struct dk_geom));
		/*
		 * This disk does not have a Solaris VTOC
		 * so we must present a physical geometry
		 * that will remain consistent regardless
		 * of how the disk is used. This will ensure
		 * that the geometry does not change regardless
		 * of the fdisk partition type (ie. EFI, FAT32,
		 * Solaris, etc).
		 */
		if (ISCD(un)) {
			dkgp->dkg_nhead = un->un_pgeom.g_nhead;
			dkgp->dkg_nsect = un->un_pgeom.g_nsect;
			dkgp->dkg_ncyl = un->un_pgeom.g_ncyl;
			dkgp->dkg_acyl = un->un_pgeom.g_acyl;
		} else {
			cmlb_convert_geometry(un->un_blockcount, dkgp);
			dkgp->dkg_acyl = 0;
			dkgp->dkg_ncyl = un->un_blockcount /
			    (dkgp->dkg_nhead * dkgp->dkg_nsect);
		}
	}
	dkgp->dkg_pcyl = dkgp->dkg_ncyl + dkgp->dkg_acyl;

	if (ddi_copyout(dkgp, (void *)arg,
	    sizeof (struct dk_geom), flag)) {
		mutex_exit(CMLB_MUTEX(un));
		err = EFAULT;
	} else {
		mutex_exit(CMLB_MUTEX(un));
		err = 0;
	}
	return (err);
}
#endif

#if defined(__i386) || defined(__amd64)
static int
cmlb_dkio_partinfo(struct cmlb_lun *un, dev_t dev, caddr_t  arg, int flag)
{
	int err = 0;

	/*
	 * Return parameters describing the selected disk slice.
	 * Note: this ioctl is for the intel platform only
	 */
	int part;

	part = CMLBPART(dev);

	/* don't check un_solaris_size for pN */
	if (part < P0_RAW_DISK && un->un_solaris_size == 0) {
		err = EIO;
	} else {
		struct part_info p;

		p.p_start = (daddr_t)un->un_offset[part];
		p.p_length = (int)un->un_map[part].dkl_nblk;
#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(flag & FMODELS)) {
		case DDI_MODEL_ILP32:
		{
			struct part_info32 p32;

			p32.p_start = (daddr32_t)p.p_start;
			p32.p_length = p.p_length;
			if (ddi_copyout(&p32, (void *)arg,
			    sizeof (p32), flag))
				err = EFAULT;
			break;
		}

		case DDI_MODEL_NONE:
		{
			if (ddi_copyout(&p, (void *)arg, sizeof (p),
			    flag))
				err = EFAULT;
			break;
		}
		}
#else /* ! _MULTI_DATAMODEL */
		if (ddi_copyout(&p, (void *)arg, sizeof (p), flag))
			err = EFAULT;
#endif /* _MULTI_DATAMODEL */
	}
	return (err);
}
#endif
