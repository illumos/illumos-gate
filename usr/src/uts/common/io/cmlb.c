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


/*
 * External kernel interfaces
 */
extern struct mod_ops mod_miscops;

extern int ddi_create_internal_pathname(dev_info_t *dip, char *name,
    int spec_type, minor_t minor_num);

/*
 * Global buffer and mutex for debug logging
 */
static char	cmlb_log_buffer[1024];
static kmutex_t	cmlb_log_mutex;


struct cmlb_lun *cmlb_debug_cl = NULL;
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
static dev_t cmlb_make_device(struct cmlb_lun *cl);
static int cmlb_validate_geometry(struct cmlb_lun *cl, int forcerevalid,
    int flags, void *tg_cookie);
static void cmlb_resync_geom_caches(struct cmlb_lun *cl, diskaddr_t capacity,
    void *tg_cookie);
static int cmlb_read_fdisk(struct cmlb_lun *cl, diskaddr_t capacity,
    void *tg_cookie);
static void cmlb_swap_efi_gpt(efi_gpt_t *e);
static void cmlb_swap_efi_gpe(int nparts, efi_gpe_t *p);
static int cmlb_validate_efi(efi_gpt_t *labp);
static int cmlb_use_efi(struct cmlb_lun *cl, diskaddr_t capacity, int flags,
    void *tg_cookie);
static void cmlb_build_default_label(struct cmlb_lun *cl, void *tg_cookie);
static int  cmlb_uselabel(struct cmlb_lun *cl,  struct dk_label *l, int flags);
#if defined(_SUNOS_VTOC_8)
static void cmlb_build_user_vtoc(struct cmlb_lun *cl, struct vtoc *user_vtoc);
#endif
static int cmlb_build_label_vtoc(struct cmlb_lun *cl, struct vtoc *user_vtoc);
static int cmlb_write_label(struct cmlb_lun *cl, void *tg_cookie);
static int cmlb_set_vtoc(struct cmlb_lun *cl, struct dk_label *dkl,
    void *tg_cookie);
static void cmlb_clear_efi(struct cmlb_lun *cl, void *tg_cookie);
static void cmlb_clear_vtoc(struct cmlb_lun *cl, void *tg_cookie);
static void cmlb_setup_default_geometry(struct cmlb_lun *cl, void *tg_cookie);
static int cmlb_create_minor_nodes(struct cmlb_lun *cl);
static int cmlb_check_update_blockcount(struct cmlb_lun *cl, void *tg_cookie);
static int cmlb_check_efi_mbr(uchar_t *buf);

#if defined(__i386) || defined(__amd64)
static int cmlb_update_fdisk_and_vtoc(struct cmlb_lun *cl, void *tg_cookie);
#endif

#if defined(_FIRMWARE_NEEDS_FDISK)
static int  cmlb_has_max_chs_vals(struct ipart *fdp);
#endif

#if defined(_SUNOS_VTOC_16)
static void cmlb_convert_geometry(diskaddr_t capacity, struct dk_geom *cl_g);
#endif

static int cmlb_dkio_get_geometry(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_set_geometry(struct cmlb_lun *cl, caddr_t arg, int flag);
static int cmlb_dkio_get_partition(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_set_partition(struct cmlb_lun *cl, caddr_t arg, int flag);
static int cmlb_dkio_get_efi(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_set_efi(struct cmlb_lun *cl, dev_t dev, caddr_t arg,
    int flag, void *tg_cookie);
static int cmlb_dkio_get_vtoc(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_set_vtoc(struct cmlb_lun *cl, dev_t dev, caddr_t arg,
    int flag, void *tg_cookie);
static int cmlb_dkio_get_mboot(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_set_mboot(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_partition(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);

#if defined(__i386) || defined(__amd64)
static int cmlb_dkio_get_virtgeom(struct cmlb_lun *cl, caddr_t arg, int flag);
static int cmlb_dkio_get_phygeom(struct cmlb_lun *cl, caddr_t  arg, int flag);
static int cmlb_dkio_partinfo(struct cmlb_lun *cl, dev_t dev, caddr_t arg,
    int flag);
#endif

static void cmlb_dbg(uint_t comp, struct cmlb_lun *cl, const char *fmt, ...);
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
cmlb_dbg(uint_t comp, struct cmlb_lun *cl, const char *fmt, ...)
{
	va_list		ap;
	dev_info_t	*dev;
	uint_t		level_mask = 0;

	ASSERT(cl != NULL);
	dev = CMLB_DEVINFO(cl);
	ASSERT(dev != NULL);
	/*
	 * Filter messages based on the global component and level masks,
	 * also print if cl matches the value of cmlb_debug_cl, or if
	 * cmlb_debug_cl is set to NULL.
	 */
	if (comp & CMLB_TRACE)
		level_mask |= CMLB_LOGMASK_TRACE;

	if (comp & CMLB_INFO)
		level_mask |= CMLB_LOGMASK_INFO;

	if (comp & CMLB_ERROR)
		level_mask |= CMLB_LOGMASK_ERROR;

	if ((cmlb_level_mask & level_mask) &&
	    ((cmlb_debug_cl == NULL) || (cmlb_debug_cl == cl))) {
		va_start(ap, fmt);
		cmlb_v_log(dev, CMLB_LABEL(cl), CE_CONT, fmt, ap);
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
	struct cmlb_lun 	*cl;

	cl = kmem_zalloc(sizeof (struct cmlb_lun), KM_SLEEP);
	ASSERT(cmlbhandlep != NULL);

	cl->cl_state = CMLB_INITED;
	cl->cl_def_labeltype = CMLB_LABEL_UNDEF;
	mutex_init(CMLB_MUTEX(cl), NULL, MUTEX_DRIVER, NULL);

	*cmlbhandlep = (cmlb_handle_t)(cl);
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
	struct cmlb_lun 	*cl;

	cl = (struct cmlb_lun *)*cmlbhandlep;
	if (cl != NULL) {
		mutex_destroy(CMLB_MUTEX(cl));
		kmem_free(cl, sizeof (struct cmlb_lun));
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
 *	is_hotpluggable	whether or not device is hotpluggable.
 *			0 non-hotpluggable, 1 hotpluggable.
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
 * 			CMLB_OFF_BY_ONE: do the workaround for legacy off-by-
 *                      one bug in obtaining capacity (in sd):
 *			SCSI READ_CAPACITY command returns the LBA number of the
 *			last logical block, but sd once treated this number as
 *			disks' capacity on x86 platform. And LBAs are addressed
 *			based 0. So the last block was lost on x86 platform.
 *
 *			Now, we remove this workaround. In order for present sd
 *			driver to work with disks which are labeled/partitioned
 *			via previous sd, we add workaround as follows:
 *
 *			1) Locate backup EFI label: cmlb searches the next to
 *			   last
 *			   block for backup EFI label. If fails, it will
 *			   turn to the last block for backup EFI label;
 *
 *			2) Clear backup EFI label: cmlb first search the last
 *			   block for backup EFI label, and will search the
 *			   next to last block only if failed for the last
 *			   block.
 *
 *			3) Calculate geometry:refer to cmlb_convert_geometry()
 *			   If capacity increasing by 1 causes disks' capacity
 *			   to cross over the limits in table CHS_values,
 *			   geometry info will change. This will raise an issue:
 *			   In case that primary VTOC label is destroyed, format
 *			   commandline can restore it via backup VTOC labels.
 *			   And format locates backup VTOC labels by use of
 *			   geometry. So changing geometry will
 *			   prevent format from finding backup VTOC labels. To
 *			   eliminate this side effect for compatibility,
 *			   sd uses (capacity -1) to calculate geometry;
 *
 *			4) 1TB disks: some important data structures use
 *			   32-bit signed long/int (for example, daddr_t),
 *			   so that sd doesn't support a disk with capacity
 *			   larger than 1TB on 32-bit platform. However,
 *			   for exactly 1TB disk, it was treated as (1T - 512)B
 *			   in the past, and could have valid Solaris
 *			   partitions. To workaround this, if an exactly 1TB
 *			   disk has Solaris fdisk partition, it will be allowed
 *			   to work with sd.
 *
 *
 *
 *			CMLB_FAKE_LABEL_ONE_PARTITION: create s0 and s2 covering
 *			the entire disk, if there is no valid partition info.
 *			If there is a valid Solaris partition, s0 and s2 will
 *			only cover the entire Solaris partition.
 *
 *
 *	cmlbhandle	cmlb handle associated with device
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
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
 *	EINVAL  invalid arg, unsupported tg_ops version
 */
int
cmlb_attach(dev_info_t *devi, cmlb_tg_ops_t *tgopsp, int device_type,
    int is_removable, int is_hotpluggable, char *node_type,
    int alter_behavior, cmlb_handle_t cmlbhandle, void *tg_cookie)
{

	struct cmlb_lun	*cl = (struct cmlb_lun *)cmlbhandle;
	diskaddr_t	cap;
	int		status;

	if (tgopsp->tg_version < TG_DK_OPS_VERSION_1)
		return (EINVAL);

	mutex_enter(CMLB_MUTEX(cl));

	CMLB_DEVINFO(cl) = devi;
	cl->cmlb_tg_ops = tgopsp;
	cl->cl_device_type = device_type;
	cl->cl_is_removable = is_removable;
	cl->cl_is_hotpluggable = is_hotpluggable;
	cl->cl_node_type = node_type;
	cl->cl_sys_blocksize = DEV_BSIZE;
	cl->cl_f_geometry_is_valid = FALSE;
	cl->cl_def_labeltype = CMLB_LABEL_VTOC;
	cl->cl_alter_behavior = alter_behavior;
	cl->cl_reserved = -1;

	if (is_removable != 0) {
		mutex_exit(CMLB_MUTEX(cl));
		status = DK_TG_GETCAP(cl, &cap, tg_cookie);
		mutex_enter(CMLB_MUTEX(cl));
		if (status == 0 && cap > DK_MAX_BLOCKS) {
			/* set default EFI if > 1TB */
			cl->cl_def_labeltype = CMLB_LABEL_EFI;
		}
	}

	/* create minor nodes based on default label type */
	cl->cl_last_labeltype = CMLB_LABEL_UNDEF;
	cl->cl_cur_labeltype = CMLB_LABEL_UNDEF;

	if (cmlb_create_minor_nodes(cl) != 0) {
		mutex_exit(CMLB_MUTEX(cl));
		return (ENXIO);
	}

	cl->cl_state = CMLB_ATTACHED;

	mutex_exit(CMLB_MUTEX(cl));
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
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 */
/*ARGSUSED1*/
void
cmlb_detach(cmlb_handle_t cmlbhandle, void *tg_cookie)
{
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;

	mutex_enter(CMLB_MUTEX(cl));
	cl->cl_def_labeltype = CMLB_LABEL_UNDEF;
	cl->cl_f_geometry_is_valid = FALSE;
	ddi_remove_minor_node(CMLB_DEVINFO(cl), NULL);
	cl->cl_state = CMLB_INITED;
	mutex_exit(CMLB_MUTEX(cl));
}

/*
 * cmlb_validate:
 *
 *	Validates label.
 *
 * Arguments
 *	cmlbhandle	cmlb handle associated with device.
 *
 *	flags		operation flags. used for verbosity control
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
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
cmlb_validate(cmlb_handle_t cmlbhandle, int flags, void *tg_cookie)
{
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;
	int 		rval;
	int  		ret = 0;

	/*
	 * Temp work-around checking cl for NULL since there is a bug
	 * in sd_detach calling this routine from taskq_dispatch
	 * inited function.
	 */
	if (cl == NULL)
		return (ENXIO);

	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(cl));
		return (ENXIO);
	}

	rval = cmlb_validate_geometry((struct cmlb_lun *)cmlbhandle, 1,
	    flags, tg_cookie);

	if (rval == ENOTSUP) {
		if (cl->cl_f_geometry_is_valid == TRUE) {
			cl->cl_cur_labeltype = CMLB_LABEL_EFI;
			ret = 0;
		} else {
			ret = EINVAL;
		}
	} else {
		ret = rval;
		if (ret == 0)
			cl->cl_cur_labeltype = CMLB_LABEL_VTOC;
	}

	if (ret == 0)
		(void) cmlb_create_minor_nodes(cl);

	mutex_exit(CMLB_MUTEX(cl));
	return (ret);
}

/*
 * cmlb_invalidate:
 *	Invalidate in core label data
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 */
/*ARGSUSED1*/
void
cmlb_invalidate(cmlb_handle_t cmlbhandle, void *tg_cookie)
{
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;

	if (cl == NULL)
		return;

	mutex_enter(CMLB_MUTEX(cl));
	cl->cl_f_geometry_is_valid = FALSE;
	mutex_exit(CMLB_MUTEX(cl));
}

/*
 * cmlb_is_valid
 * 	Get status on whether the incore label/geom data is valid
 *
 * Arguments:
 *	cmlbhandle      cmlb handle associated with device.
 *
 * Return values:
 *	TRUE if incore label/geom data is valid.
 *	FALSE otherwise.
 *
 */


int
cmlb_is_valid(cmlb_handle_t cmlbhandle)
{
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;

	if (cmlbhandle == NULL)
		return (FALSE);

	return (cl->cl_f_geometry_is_valid);

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
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 * Return values:
 *	0	Success
 * 	ENXIO	Re-creating minor node failed.
 */
/*ARGSUSED1*/
int
cmlb_close(cmlb_handle_t cmlbhandle, void *tg_cookie)
{
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;

	mutex_enter(CMLB_MUTEX(cl));
	cl->cl_f_geometry_is_valid = FALSE;

	/* revert to default minor node for this device */
	if (ISREMOVABLE(cl)) {
		cl->cl_cur_labeltype = CMLB_LABEL_UNDEF;
		(void) cmlb_create_minor_nodes(cl);
	}

	mutex_exit(CMLB_MUTEX(cl));
	return (0);
}

/*
 * cmlb_get_devid_block:
 *	 get the block number where device id is stored.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	devidblockp	pointer to block number.
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
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
/*ARGSUSED2*/
int
cmlb_get_devid_block(cmlb_handle_t cmlbhandle, diskaddr_t *devidblockp,
    void *tg_cookie)
{
	daddr_t			spc, blk, head, cyl;
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;

	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}

	if ((cl->cl_f_geometry_is_valid == FALSE) ||
	    (cl->cl_solaris_size < DK_LABEL_LOC)) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}

	if (cl->cl_cur_labeltype == CMLB_LABEL_EFI) {
		if (cl->cl_reserved != -1) {
			blk = cl->cl_map[cl->cl_reserved].dkl_cylno;
		} else {
			mutex_exit(CMLB_MUTEX(cl));
			return (EINVAL);
		}
	} else {
		/* if the disk is unlabeled, don't write a devid to it */
		if (!cl->cl_vtoc_label_is_from_media) {
			mutex_exit(CMLB_MUTEX(cl));
			return (EINVAL);
		}

		/* this geometry doesn't allow us to write a devid */
		if (cl->cl_g.dkg_acyl < 2) {
			mutex_exit(CMLB_MUTEX(cl));
			return (EINVAL);
		}

		/*
		 * Subtract 2 guarantees that the next to last cylinder
		 * is used
		 */
		cyl  = cl->cl_g.dkg_ncyl  + cl->cl_g.dkg_acyl - 2;
		spc  = cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect;
		head = cl->cl_g.dkg_nhead - 1;
		blk  = cl->cl_solaris_offset +
		    (cyl * (spc - cl->cl_g.dkg_apc)) +
		    (head * cl->cl_g.dkg_nsect) + 1;
	}

	*devidblockp = blk;
	mutex_exit(CMLB_MUTEX(cl));
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
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
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
    diskaddr_t *startblockp, char **partnamep, uint16_t *tagp, void *tg_cookie)
{

	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;
	int rval;

	ASSERT(cl != NULL);
	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}

	if (part  < 0 || part >= MAXPART) {
		rval = EINVAL;
	} else {
		if (cl->cl_f_geometry_is_valid == FALSE)
			(void) cmlb_validate_geometry((struct cmlb_lun *)cl, 0,
			    0, tg_cookie);

		if ((cl->cl_f_geometry_is_valid == FALSE) ||
		    (part < NDKMAP && cl->cl_solaris_size == 0)) {
			rval = EINVAL;
		} else {
			if (startblockp != NULL)
				*startblockp = (diskaddr_t)cl->cl_offset[part];

			if (nblocksp != NULL)
				*nblocksp = (diskaddr_t)
				    cl->cl_map[part].dkl_nblk;

			if (tagp != NULL)
				if (cl->cl_cur_labeltype == CMLB_LABEL_EFI)
					*tagp = V_UNASSIGNED;
				else
					*tagp = cl->cl_vtoc.v_part[part].p_tag;
			rval = 0;
		}

		/* consistent with behavior of sd for getting minor name */
		if (partnamep != NULL)
			*partnamep = dk_minor_data[part].name;

	}

	mutex_exit(CMLB_MUTEX(cl));
	return (rval);
}

/*
 * cmlb_efi_label_capacity:
 *	Get capacity stored in EFI disk label.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	capacity	pointer to capacity stored in EFI disk label.
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 *
 * Notes:
 *	If in-core label is not valid, this functions tries to revalidate
 *	the label. If label is valid and is an EFI label, it stores the capacity
 *      in disk label in the area pointed to by capacity.
 *
 *
 * Return values:
 *	0	success
 *	EINVAL  no valid EFI label or capacity is NULL.
 *
 */
int
cmlb_efi_label_capacity(cmlb_handle_t cmlbhandle, diskaddr_t *capacity,
    void *tg_cookie)
{
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;
	int rval;

	ASSERT(cl != NULL);
	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}

	if (cl->cl_f_geometry_is_valid == FALSE)
		(void) cmlb_validate_geometry((struct cmlb_lun *)cl, 0,
		    0, tg_cookie);

	if ((cl->cl_f_geometry_is_valid == FALSE) || (capacity == NULL) ||
	    (cl->cl_cur_labeltype != CMLB_LABEL_EFI)) {
		rval = EINVAL;
	} else {
		*capacity = (diskaddr_t)cl->cl_map[WD_NODE].dkl_nblk;
		rval = 0;
	}

	mutex_exit(CMLB_MUTEX(cl));
	return (rval);
}

/* Caller should make sure Test Unit Ready succeeds before calling this. */
/*ARGSUSED*/
int
cmlb_ioctl(cmlb_handle_t cmlbhandle, dev_t dev, int cmd, intptr_t arg,
    int flag, cred_t *cred_p, int *rval_p, void *tg_cookie)
{

	int err;
	struct cmlb_lun *cl;
	int status;

	cl = (struct cmlb_lun *)cmlbhandle;

	ASSERT(cl != NULL);

	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EIO);
	}

	switch (cmd) {
		case DKIOCSVTOC:
		case DKIOCSGEOM:
		case DKIOCSETEFI:
		case DKIOCSMBOOT:
			break;
		default:
			status = cmlb_validate_geometry(cl, 1, CMLB_SILENT,
			    tg_cookie);

			/*
			 * VTOC related ioctls except SVTOC/SGEOM should
			 * fail if > 1TB disk and there is not already a VTOC
			 * on the disk.i.e either EFI or blank
			 *
			 * PHYGEOM AND VIRTGEOM succeeds when disk is
			 * EFI labeled but <1TB
			 */

			if (status == ENOTSUP &&
			    cl->cl_f_geometry_is_valid == FALSE) {
				switch (cmd) {
				case DKIOCGAPART:
				case DKIOCGGEOM:
				case DKIOCGVTOC:
				case DKIOCSAPART:
				case DKIOCG_PHYGEOM:
				case DKIOCG_VIRTGEOM:

					mutex_exit(CMLB_MUTEX(cl));
					return (ENOTSUP);
				}
			} else {
				if ((cl->cl_f_geometry_is_valid == TRUE) &&
				    (cl->cl_solaris_size > 0)) {
					if (cl->cl_vtoc.v_sanity != VTOC_SANE) {
					/*
					 * it is EFI, so return ENOTSUP for
					 * these
					 */
					switch (cmd) {
					case DKIOCGAPART:
					case DKIOCGGEOM:
					case DKIOCGVTOC:
					case DKIOCSVTOC:
					case DKIOCSAPART:

						mutex_exit(CMLB_MUTEX(cl));
						return (ENOTSUP);
					}
				}
			}
		}
	}

	mutex_exit(CMLB_MUTEX(cl));

	switch (cmd) {
	case DKIOCGGEOM:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCGGEOM\n");
		err = cmlb_dkio_get_geometry(cl, (caddr_t)arg, flag, tg_cookie);
		break;

	case DKIOCSGEOM:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCSGEOM\n");
		err = cmlb_dkio_set_geometry(cl, (caddr_t)arg, flag);
		break;

	case DKIOCGAPART:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCGAPART\n");
		err = cmlb_dkio_get_partition(cl, (caddr_t)arg,
		    flag, tg_cookie);
		break;

	case DKIOCSAPART:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCSAPART\n");
		err = cmlb_dkio_set_partition(cl, (caddr_t)arg, flag);
		break;

	case DKIOCGVTOC:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCGVTOC\n");
		err = cmlb_dkio_get_vtoc(cl, (caddr_t)arg, flag, tg_cookie);
		break;

	case DKIOCGETEFI:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCGETEFI\n");
		err = cmlb_dkio_get_efi(cl, (caddr_t)arg, flag, tg_cookie);
		break;

	case DKIOCPARTITION:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCPARTITION\n");
		err = cmlb_dkio_partition(cl, (caddr_t)arg, flag, tg_cookie);
		break;

	case DKIOCSVTOC:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCSVTOC\n");
		err = cmlb_dkio_set_vtoc(cl, dev, (caddr_t)arg, flag,
		    tg_cookie);
		break;

	case DKIOCSETEFI:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCSETEFI\n");
		err = cmlb_dkio_set_efi(cl, dev, (caddr_t)arg, flag, tg_cookie);
		break;

	case DKIOCGMBOOT:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCGMBOOT\n");
		err = cmlb_dkio_get_mboot(cl, (caddr_t)arg, flag, tg_cookie);
		break;

	case DKIOCSMBOOT:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCSMBOOT\n");
		err = cmlb_dkio_set_mboot(cl, (caddr_t)arg, flag, tg_cookie);
		break;
	case DKIOCG_PHYGEOM:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCG_PHYGEOM\n");
#if defined(__i386) || defined(__amd64)
		err = cmlb_dkio_get_phygeom(cl, (caddr_t)arg, flag);
#else
		err = ENOTTY;
#endif
		break;
	case DKIOCG_VIRTGEOM:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCG_VIRTGEOM\n");
#if defined(__i386) || defined(__amd64)
		err = cmlb_dkio_get_virtgeom(cl, (caddr_t)arg, flag);
#else
		err = ENOTTY;
#endif
		break;
	case DKIOCPARTINFO:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCPARTINFO");
#if defined(__i386) || defined(__amd64)
		err = cmlb_dkio_partinfo(cl, dev, (caddr_t)arg, flag);
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
cmlb_make_device(struct cmlb_lun *cl)
{
	return (makedevice(ddi_name_to_major(ddi_get_name(CMLB_DEVINFO(cl))),
	    ddi_get_instance(CMLB_DEVINFO(cl)) << CMLBUNIT_SHIFT));
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
cmlb_check_update_blockcount(struct cmlb_lun *cl, void *tg_cookie)
{
	int status;
	diskaddr_t capacity;
	uint32_t lbasize;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	if (cl->cl_f_geometry_is_valid == FALSE)  {
		mutex_exit(CMLB_MUTEX(cl));
		status = DK_TG_GETCAP(cl, &capacity, tg_cookie);
		if (status != 0) {
			mutex_enter(CMLB_MUTEX(cl));
			return (EIO);
		}

		status = DK_TG_GETBLOCKSIZE(cl, &lbasize, tg_cookie);
		mutex_enter(CMLB_MUTEX(cl));
		if (status != 0)
			return (EIO);

		if ((capacity != 0) && (lbasize != 0)) {
			cl->cl_blockcount = capacity;
			cl->cl_tgt_blocksize = lbasize;
			return (0);
		} else
			return (EIO);
	} else
		return (0);
}

static int
cmlb_create_minor(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag, boolean_t internal)
{
	if (internal)
		return (ddi_create_internal_pathname(dip,
		    name, spec_type, minor_num));
	else
		return (ddi_create_minor_node(dip,
		    name, spec_type, minor_num, node_type, flag));
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
 *   Arguments: cl - driver soft state (unit) structure
 *
 * Return Code: 0 success
 *		ENXIO	failure.
 *
 *     Context: Kernel thread context
 */
static int
cmlb_create_minor_nodes(struct cmlb_lun *cl)
{
	struct driver_minor_data	*dmdp;
	int				instance;
	char				name[48];
	cmlb_label_t			newlabeltype;
	boolean_t			internal;

	ASSERT(cl != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	internal = ((cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);

	/* check the most common case */
	if (cl->cl_cur_labeltype != CMLB_LABEL_UNDEF &&
	    cl->cl_last_labeltype == cl->cl_cur_labeltype) {
		/* do nothing */
		return (0);
	}

	if (cl->cl_def_labeltype == CMLB_LABEL_UNDEF) {
		/* we should never get here */
		return (ENXIO);
	}

	if (cl->cl_last_labeltype == CMLB_LABEL_UNDEF) {
		/* first time during attach */
		newlabeltype = cl->cl_def_labeltype;

		instance = ddi_get_instance(CMLB_DEVINFO(cl));

		/* Create all the minor nodes for this target. */
		dmdp = (newlabeltype == CMLB_LABEL_EFI) ? dk_minor_data_efi :
		    dk_minor_data;
		while (dmdp->name != NULL) {

			(void) sprintf(name, "%s", dmdp->name);

			if (cmlb_create_minor(CMLB_DEVINFO(cl), name,
			    dmdp->type,
			    (instance << CMLBUNIT_SHIFT) | dmdp->minor,
			    cl->cl_node_type, NULL, internal) == DDI_FAILURE) {
				/*
				 * Clean up any nodes that may have been
				 * created, in case this fails in the middle
				 * of the loop.
				 */
				ddi_remove_minor_node(CMLB_DEVINFO(cl), NULL);
				return (ENXIO);
			}
			dmdp++;
		}
		cl->cl_last_labeltype = newlabeltype;
		return (0);
	}

	/* Not first time  */
	if (cl->cl_cur_labeltype == CMLB_LABEL_UNDEF) {
		if (cl->cl_last_labeltype != cl->cl_def_labeltype) {
			/* close time, revert to default. */
			newlabeltype = cl->cl_def_labeltype;
		} else {
			/*
			 * do nothing since the type for which we last created
			 * nodes matches the default
			 */
			return (0);
		}
	} else {
		if (cl->cl_cur_labeltype != cl->cl_last_labeltype) {
			/* We are not closing, use current label type */
			newlabeltype = cl->cl_cur_labeltype;
		} else {
			/*
			 * do nothing since the type for which we last created
			 * nodes matches the current label type
			 */
			return (0);
		}
	}

	instance = ddi_get_instance(CMLB_DEVINFO(cl));

	/*
	 * Currently we only fix up the s7 node when we are switching
	 * label types from or to EFI. This is consistent with
	 * current behavior of sd.
	 */
	if (newlabeltype == CMLB_LABEL_EFI &&
	    cl->cl_last_labeltype != CMLB_LABEL_EFI) {
		/* from vtoc to EFI */
		ddi_remove_minor_node(CMLB_DEVINFO(cl), "h");
		ddi_remove_minor_node(CMLB_DEVINFO(cl), "h,raw");
		(void) cmlb_create_minor(CMLB_DEVINFO(cl), "wd",
		    S_IFBLK, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    cl->cl_node_type, NULL, internal);
		(void) cmlb_create_minor(CMLB_DEVINFO(cl), "wd,raw",
		    S_IFCHR, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    cl->cl_node_type, NULL, internal);
	} else {
		/* from efi to vtoc */
		ddi_remove_minor_node(CMLB_DEVINFO(cl), "wd");
		ddi_remove_minor_node(CMLB_DEVINFO(cl), "wd,raw");
		(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h",
		    S_IFBLK, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    cl->cl_node_type, NULL, internal);
		(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h,raw",
		    S_IFCHR, (instance << CMLBUNIT_SHIFT) | WD_NODE,
		    cl->cl_node_type, NULL, internal);
	}

	cl->cl_last_labeltype = newlabeltype;
	return (0);
}

/*
 *    Function: cmlb_validate_geometry
 *
 * Description: Read the label from the disk (if present). Update the unit's
 *		geometry and vtoc information from the data in the label.
 *		Verify that the label is valid.
 *
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *
 *	forcerevalid	force revalidation even if we are already valid.
 *	flags		operation flags from target driver. Used for verbosity
 *			control	at this time.
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0 - Successful completion
 *		EINVAL  - Invalid value in cl->cl_tgt_blocksize or
 *			  cl->cl_blockcount; or label on disk is corrupted
 *			  or unreadable.
 *		EACCES  - Reservation conflict at the device.
 *		ENOMEM  - Resource allocation error
 *		ENOTSUP - geometry not applicable
 *
 *     Context: Kernel thread only (can sleep).
 */
static int
cmlb_validate_geometry(struct cmlb_lun *cl, int forcerevalid, int flags,
    void *tg_cookie)
{
	int		label_error = 0;
	diskaddr_t	capacity;
	int		count;
#if defined(__i386) || defined(__amd64)
	int forced_under_1t = 0;
#endif

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	if ((cl->cl_f_geometry_is_valid == TRUE) && (forcerevalid == 0)) {
		if (cl->cl_cur_labeltype == CMLB_LABEL_EFI)
			return (ENOTSUP);
		return (0);
	}

	if (cmlb_check_update_blockcount(cl, tg_cookie) != 0)
		return (EIO);

	capacity = cl->cl_blockcount;

#if defined(_SUNOS_VTOC_16)
	/*
	 * Set up the "whole disk" fdisk partition; this should always
	 * exist, regardless of whether the disk contains an fdisk table
	 * or vtoc.
	 */
	cl->cl_map[P0_RAW_DISK].dkl_cylno = 0;
	/*
	 * note if capacity > uint32_max we should be using efi,
	 * and not use p0, so the truncation does not matter.
	 */
	cl->cl_map[P0_RAW_DISK].dkl_nblk  = capacity;
#endif
	/*
	 * Refresh the logical and physical geometry caches.
	 * (data from MODE SENSE format/rigid disk geometry pages,
	 * and scsi_ifgetcap("geometry").
	 */
	cmlb_resync_geom_caches(cl, capacity, tg_cookie);

	label_error = cmlb_use_efi(cl, capacity, flags, tg_cookie);
	if (label_error == 0) {

		/* found a valid EFI label */
		cmlb_dbg(CMLB_TRACE, cl,
		    "cmlb_validate_geometry: found EFI label\n");
		/*
		 * solaris_size and geometry_is_valid are set in
		 * cmlb_use_efi
		 */
		return (ENOTSUP);
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
			if (!(flags & CMLB_SILENT)) {
				cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl),
				    CE_WARN, "is >1TB and has a VTOC label: "
				    "use format(1M) to either decrease the");

				cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl),
				    CE_NOTE, "size to be < 1TB or relabel the "
				    "disk with an EFI label");
#if defined(__i386) || defined(__amd64)
				forced_under_1t = 1;
#endif
			}
		} else {
			/* unlabeled disk over 1TB */
#if defined(__i386) || defined(__amd64)

			/*
			 * Refer to comments on off-by-1 at the head of the file
			 * A 1TB disk was treated as (1T - 512)B in the past,
			 * thus, it might have valid solaris partition. We
			 * will return ENOTSUP later only if this disk has no
			 * valid solaris partition.
			 */
			if (!(cl->cl_alter_behavior & CMLB_OFF_BY_ONE) ||
			    (cl->cl_sys_blocksize != cl->cl_tgt_blocksize) ||
			    (capacity - 1 > DK_MAX_BLOCKS))
#endif
				return (ENOTSUP);
		}
	}

	label_error = 0;

	/*
	 * at this point it is either labeled with a VTOC or it is
	 * under 1TB (<= 1TB actually for off-by-1)
	 */

	/*
	 * Only DIRECT ACCESS devices will have Scl labels.
	 * CD's supposedly have a Scl label, too
	 */
	if (cl->cl_device_type == DTYPE_DIRECT || ISREMOVABLE(cl)) {
		struct	dk_label *dkl;
		offset_t label_addr;
		int	rval;
		size_t	buffer_size;

		/*
		 * Note: This will set up cl->cl_solaris_size and
		 * cl->cl_solaris_offset.
		 */
		rval = cmlb_read_fdisk(cl, capacity, tg_cookie);
		if ((rval != 0) && !ISCD(cl)) {
			ASSERT(mutex_owned(CMLB_MUTEX(cl)));
			return (rval);
		}

		if (cl->cl_solaris_size <= DK_LABEL_LOC) {

#if defined(__i386) || defined(__amd64)
			/*
			 * Refer to comments on off-by-1 at the head of the file
			 * This is for 1TB disk only. Since that there is no
			 * solaris partitions, return ENOTSUP as we do for
			 * >1TB disk.
			 */
			if (cl->cl_blockcount > DK_MAX_BLOCKS)
				return (ENOTSUP);
#endif
			/*
			 * Found fdisk table but no Solaris partition entry,
			 * so don't call cmlb_uselabel() and don't create
			 * a default label.
			 */
			label_error = 0;
			cl->cl_f_geometry_is_valid = TRUE;
			goto no_solaris_partition;
		}

		label_addr = (daddr_t)(cl->cl_solaris_offset + DK_LABEL_LOC);

#if defined(__i386) || defined(__amd64)
		/*
		 * Refer to comments on off-by-1 at the head of the file
		 * Now, this 1TB disk has valid solaris partition. It
		 * must be created by previous sd driver, we have to
		 * treat it as (1T-512)B.
		 */
		if ((cl->cl_blockcount > DK_MAX_BLOCKS) &&
		    (forced_under_1t != 1)) {
			/*
			 * Refer to cmlb_read_fdisk, when there is no
			 * fdisk partition table, cl_solaris_size is
			 * set to disk's capacity. In this case, we
			 * need to adjust it
			 */
			if (cl->cl_solaris_size > DK_MAX_BLOCKS)
				cl->cl_solaris_size = DK_MAX_BLOCKS;
			cmlb_resync_geom_caches(cl, DK_MAX_BLOCKS, tg_cookie);
		}
#endif

		buffer_size = sizeof (struct dk_label);

		cmlb_dbg(CMLB_TRACE, cl, "cmlb_validate_geometry: "
		    "label_addr: 0x%x allocation size: 0x%x\n",
		    label_addr, buffer_size);

		if ((dkl = kmem_zalloc(buffer_size, KM_NOSLEEP)) == NULL)
			return (ENOMEM);

		mutex_exit(CMLB_MUTEX(cl));
		rval = DK_TG_READ(cl, dkl, label_addr, buffer_size, tg_cookie);
		mutex_enter(CMLB_MUTEX(cl));

		switch (rval) {
		case 0:
			/*
			 * cmlb_uselabel will establish that the geometry
			 * is valid.
			 */
			if (cmlb_uselabel(cl,
			    (struct dk_label *)(uintptr_t)dkl, flags) !=
			    CMLB_LABEL_IS_VALID) {
				label_error = EINVAL;
			} else
				cl->cl_vtoc_label_is_from_media = 1;
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
	 * for removables and hotpluggables only.  For VTOC_16 devices, the
	 * default label will be created for all devices.
	 * (see cmlb_build_default_label)
	 */
#if defined(_SUNOS_VTOC_8)
	if ((ISREMOVABLE(cl) || ISHOTPLUGGABLE(cl)) &&
	    (label_error != EACCES)) {
#elif defined(_SUNOS_VTOC_16)
	if (label_error != EACCES) {
#endif
		if (cl->cl_f_geometry_is_valid == FALSE) {
			cmlb_build_default_label(cl, tg_cookie);
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
		cl->cl_map[FDISK_P1 + count].dkl_cylno = -1;
		cl->cl_map[FDISK_P1 + count].dkl_nblk =
		    cl->cl_fmap[count].fmap_nblk;

		cl->cl_offset[FDISK_P1 + count] =
		    cl->cl_fmap[count].fmap_start;
	}
#endif

	for (count = 0; count < NDKMAP; count++) {
#if defined(_SUNOS_VTOC_8)
		struct dk_map *lp  = &cl->cl_map[count];
		cl->cl_offset[count] =
		    cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect * lp->dkl_cylno;
#elif defined(_SUNOS_VTOC_16)
		struct dkl_partition *vp = &cl->cl_vtoc.v_part[count];

		cl->cl_offset[count] = vp->p_start + cl->cl_solaris_offset;
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
cmlb_convert_geometry(diskaddr_t capacity, struct dk_geom *cl_g)
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
		cl_g->dkg_nhead = 2;
		cl_g->dkg_ncyl = 80;
		cl_g->dkg_nsect = capacity / (cl_g->dkg_nhead * cl_g->dkg_ncyl);
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

	cl_g->dkg_nhead = CHS_values[i].nhead;
	cl_g->dkg_nsect = CHS_values[i].nsect;
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
 *   Arguments:
 *	cl 		driver soft state (unit) structure
 *	capacity	disk capacity in #blocks
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 *     Context: Kernel thread only (can sleep).
 */
static void
cmlb_resync_geom_caches(struct cmlb_lun *cl, diskaddr_t capacity,
    void *tg_cookie)
{
	struct	cmlb_geom 	pgeom;
	struct	cmlb_geom	lgeom;
	struct 	cmlb_geom	*pgeomp = &pgeom;
	unsigned short 		nhead;
	unsigned short 		nsect;
	int 			spc;
	int			ret;

	ASSERT(cl != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	/*
	 * Ask the controller for its logical geometry.
	 * Note: if the HBA does not support scsi_ifgetcap("geometry"),
	 * then the lgeom cache will be invalid.
	 */
	mutex_exit(CMLB_MUTEX(cl));
	bzero(&lgeom, sizeof (struct cmlb_geom));
	ret = DK_TG_GETVIRTGEOM(cl, &lgeom, tg_cookie);
	mutex_enter(CMLB_MUTEX(cl));

	bcopy(&lgeom, &cl->cl_lgeom, sizeof (cl->cl_lgeom));

	/*
	 * Initialize the pgeom cache from lgeom, so that if MODE SENSE
	 * doesn't work, DKIOCG_PHYSGEOM can return reasonable values.
	 */
	if (ret != 0 || cl->cl_lgeom.g_nsect == 0 ||
	    cl->cl_lgeom.g_nhead == 0) {
		/*
		 * Note: Perhaps this needs to be more adaptive? The rationale
		 * is that, if there's no HBA geometry from the HBA driver, any
		 * guess is good, since this is the physical geometry. If MODE
		 * SENSE fails this gives a max cylinder size for non-LBA access
		 */
		nhead = 255;
		nsect = 63;
	} else {
		nhead = cl->cl_lgeom.g_nhead;
		nsect = cl->cl_lgeom.g_nsect;
	}

	if (ISCD(cl)) {
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

	mutex_exit(CMLB_MUTEX(cl));
	(void) DK_TG_GETPHYGEOM(cl, pgeomp, tg_cookie);
	mutex_enter(CMLB_MUTEX(cl));

	/*
	 * Now update the real copy while holding the mutex. This
	 * way the global copy is never in an inconsistent state.
	 */
	bcopy(pgeomp, &cl->cl_pgeom,  sizeof (cl->cl_pgeom));

	cmlb_dbg(CMLB_INFO, cl, "cmlb_resync_geom_caches: "
	    "(cached from lgeom)\n");
	cmlb_dbg(CMLB_INFO,  cl,
	    "   ncyl: %ld; acyl: %d; nhead: %d; nsect: %d\n",
	    cl->cl_pgeom.g_ncyl, cl->cl_pgeom.g_acyl,
	    cl->cl_pgeom.g_nhead, cl->cl_pgeom.g_nsect);
	cmlb_dbg(CMLB_INFO,  cl, "   lbasize: %d; capacity: %ld; "
	    "intrlv: %d; rpm: %d\n", cl->cl_pgeom.g_secsize,
	    cl->cl_pgeom.g_capacity, cl->cl_pgeom.g_intrlv,
	    cl->cl_pgeom.g_rpm);
}


/*
 *    Function: cmlb_read_fdisk
 *
 * Description: utility routine to read the fdisk table.
 *
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *	capacity	disk capacity in #blocks
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0 for success (includes not reading for no_fdisk_present case
 *		errnos from tg_rw if failed to read the first block.
 *
 *     Context: Kernel thread only (can sleep).
 */
/*ARGSUSED*/
static int
cmlb_read_fdisk(struct cmlb_lun *cl, diskaddr_t capacity, void *tg_cookie)
{
#if defined(_NO_FDISK_PRESENT)

	cl->cl_solaris_offset = 0;
	cl->cl_solaris_size = capacity;
	bzero(cl->cl_fmap, sizeof (struct fmap) * FD_NUMPART);
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

	ASSERT(cl != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	/*
	 * Start off assuming no fdisk table
	 */
	solaris_offset = 0;
	solaris_size   = capacity;

	blocksize = cl->cl_tgt_blocksize;

	bufp = kmem_zalloc(blocksize, KM_SLEEP);

	mutex_exit(CMLB_MUTEX(cl));
	rval = DK_TG_READ(cl, bufp, 0, blocksize, tg_cookie);
	mutex_enter(CMLB_MUTEX(cl));

	if (rval != 0) {
		cmlb_dbg(CMLB_ERROR,  cl,
		    "cmlb_read_fdisk: fdisk read err\n");
		bzero(cl->cl_fmap, sizeof (struct fmap) * FD_NUMPART);
		goto done;
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

	if (lba != 0) {
		dev_t dev = cmlb_make_device(cl);

		if (ddi_getprop(dev, CMLB_DEVINFO(cl), DDI_PROP_DONTPASS,
		    "lba-access-ok", 0) == 0) {
			/* not found; create it */
			if (ddi_prop_create(dev, CMLB_DEVINFO(cl), 0,
			    "lba-access-ok", (caddr_t)NULL, 0) !=
			    DDI_PROP_SUCCESS) {
				cmlb_dbg(CMLB_ERROR,  cl,
				    "cmlb_read_fdisk: Can't create lba "
				    "property for instance %d\n",
				    ddi_get_instance(CMLB_DEVINFO(cl)));
			}
		}
	}

	bcopy(&mbp->signature, sigbuf, sizeof (sigbuf));

	/*
	 * Endian-independent signature check
	 */
	if (((sigbuf[1] & 0xFF) != ((MBB_MAGIC >> 8) & 0xFF)) ||
	    (sigbuf[0] != (MBB_MAGIC & 0xFF))) {
		cmlb_dbg(CMLB_ERROR,  cl,
		    "cmlb_read_fdisk: no fdisk\n");
		bzero(cl->cl_fmap, sizeof (struct fmap) * FD_NUMPART);
		goto done;
	}

#ifdef CMLBDEBUG
	if (cmlb_level_mask & CMLB_LOGMASK_INFO) {
		fdp = fdisk;
		cmlb_dbg(CMLB_INFO,  cl, "cmlb_read_fdisk:\n");
		cmlb_dbg(CMLB_INFO,  cl, "         relsect    "
		    "numsect         sysid       bootid\n");
		for (i = 0; i < FD_NUMPART; i++, fdp++) {
			cmlb_dbg(CMLB_INFO,  cl,
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
			cl->cl_fmap[i].fmap_start = 0;
			cl->cl_fmap[i].fmap_nblk  = 0;
			continue;
		}

		/*
		 * Data in the fdisk table is little-endian.
		 */
		relsect = LE_32(fdp->relsect);
		numsect = LE_32(fdp->numsect);

		cl->cl_fmap[i].fmap_start = relsect;
		cl->cl_fmap[i].fmap_nblk  = numsect;

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

	cmlb_dbg(CMLB_INFO,  cl, "fdisk 0x%x 0x%lx",
	    cl->cl_solaris_offset, cl->cl_solaris_size);
done:

	/*
	 * Clear the VTOC info, only if the Solaris partition entry
	 * has moved, changed size, been deleted, or if the size of
	 * the partition is too small to even fit the label sector.
	 */
	if ((cl->cl_solaris_offset != solaris_offset) ||
	    (cl->cl_solaris_size != solaris_size) ||
	    solaris_size <= DK_LABEL_LOC) {
		cmlb_dbg(CMLB_INFO,  cl, "fdisk moved 0x%x 0x%lx",
		    solaris_offset, solaris_size);
		bzero(&cl->cl_g, sizeof (struct dk_geom));
		bzero(&cl->cl_vtoc, sizeof (struct dk_vtoc));
		bzero(&cl->cl_map, NDKMAP * (sizeof (struct dk_map)));
		cl->cl_f_geometry_is_valid = FALSE;
	}
	cl->cl_solaris_offset = solaris_offset;
	cl->cl_solaris_size = solaris_size;
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

/*
 * This function returns FALSE if there is a valid MBR signature and no
 * partition table entries of type EFI_PMBR (0xEE). Otherwise it returns TRUE.
 *
 * The EFI spec (1.10 and later) requires having a Protective MBR (PMBR) to
 * recognize the disk as GPT partitioned. However, some other OS creates an MBR
 * where a PMBR entry is not the only one. Also, if the first block has been
 * corrupted, currently best attempt to allow data access would be to try to
 * check for GPT headers. Hence in case of more than one partition entry, but
 * at least one EFI_PMBR partition type or no valid magic number, the function
 * returns TRUE to continue with looking for GPT header.
 */

static int
cmlb_check_efi_mbr(uchar_t *buf)
{
	struct ipart	*fdp;
	struct mboot	*mbp = (struct mboot *)buf;
	struct ipart	fdisk[FD_NUMPART];
	int		i;

	if (LE_16(mbp->signature) != MBB_MAGIC)
		return (TRUE);

	bcopy(&mbp->parts[0], fdisk, sizeof (fdisk));

	for (fdp = fdisk, i = 0; i < FD_NUMPART; i++, fdp++) {
		if (fdp->systid == EFI_PMBR)
			return (TRUE);
	}

	return (FALSE);
}

static int
cmlb_use_efi(struct cmlb_lun *cl, diskaddr_t capacity, int flags,
    void *tg_cookie)
{
	int		i;
	int		rval = 0;
	efi_gpe_t	*partitions;
	uchar_t		*buf;
	uint_t		lbasize;	/* is really how much to read */
	diskaddr_t	cap = 0;
	uint_t		nparts;
	diskaddr_t	gpe_lba;
	diskaddr_t	alternate_lba;
	int		iofailed = 0;
	struct uuid	uuid_type_reserved = EFI_RESERVED;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	if (cl->cl_tgt_blocksize != cl->cl_sys_blocksize) {
		rval = EINVAL;
		goto done_err1;
	}


	lbasize = cl->cl_sys_blocksize;

	cl->cl_reserved = -1;
	mutex_exit(CMLB_MUTEX(cl));

	buf = kmem_zalloc(EFI_MIN_ARRAY_SIZE, KM_SLEEP);

	rval = DK_TG_READ(cl, buf, 0, lbasize, tg_cookie);
	if (rval) {
		iofailed = 1;
		goto done_err;
	}
	if (((struct dk_label *)buf)->dkl_magic == DKL_MAGIC) {
		/* not ours */
		rval = ESRCH;
		goto done_err;
	}

	if (cmlb_check_efi_mbr(buf) == FALSE) {
		rval = EINVAL;
		goto done_err;
	}

	rval = DK_TG_READ(cl, buf, 1, lbasize, tg_cookie);
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
		rval = DK_TG_GETCAP(cl, &cap, tg_cookie);
		if (rval) {
			iofailed = 1;
			goto done_err;
		}

		/*
		 * CMLB_OFF_BY_ONE case, we check the next to last block first
		 * for backup GPT header, otherwise check the last block.
		 */

		if ((rval = DK_TG_READ(cl, buf,
		    cap - ((cl->cl_alter_behavior & CMLB_OFF_BY_ONE) ? 2 : 1),
		    lbasize, tg_cookie))
		    != 0) {
			iofailed = 1;
			goto done_err;
		}
		cmlb_swap_efi_gpt((efi_gpt_t *)buf);

		if ((rval = cmlb_validate_efi((efi_gpt_t *)buf)) != 0) {

			if (!(cl->cl_alter_behavior & CMLB_OFF_BY_ONE))
				goto done_err;
			if ((rval = DK_TG_READ(cl, buf, cap - 1, lbasize,
			    tg_cookie)) != 0)
				goto done_err;
			cmlb_swap_efi_gpt((efi_gpt_t *)buf);
			if ((rval = cmlb_validate_efi((efi_gpt_t *)buf)) != 0)
				goto done_err;
		}
		if (!(flags & CMLB_SILENT))
			cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl), CE_WARN,
			    "primary label corrupt; using backup\n");
	}

	nparts = ((efi_gpt_t *)buf)->efi_gpt_NumberOfPartitionEntries;
	gpe_lba = ((efi_gpt_t *)buf)->efi_gpt_PartitionEntryLBA;
	alternate_lba = ((efi_gpt_t *)buf)->efi_gpt_AlternateLBA;

	rval = DK_TG_READ(cl, buf, gpe_lba, EFI_MIN_ARRAY_SIZE, tg_cookie);
	if (rval) {
		iofailed = 1;
		goto done_err;
	}
	partitions = (efi_gpe_t *)buf;

	if (nparts > MAXPART) {
		nparts = MAXPART;
	}
	cmlb_swap_efi_gpe(nparts, partitions);

	mutex_enter(CMLB_MUTEX(cl));

	/* Fill in partition table. */
	for (i = 0; i < nparts; i++) {
		if (partitions->efi_gpe_StartingLBA != 0 ||
		    partitions->efi_gpe_EndingLBA != 0) {
			cl->cl_map[i].dkl_cylno =
			    partitions->efi_gpe_StartingLBA;
			cl->cl_map[i].dkl_nblk =
			    partitions->efi_gpe_EndingLBA -
			    partitions->efi_gpe_StartingLBA + 1;
			cl->cl_offset[i] =
			    partitions->efi_gpe_StartingLBA;
		}

		if (cl->cl_reserved == -1) {
			if (bcmp(&partitions->efi_gpe_PartitionTypeGUID,
			    &uuid_type_reserved, sizeof (struct uuid)) == 0) {
				cl->cl_reserved = i;
			}
		}
		if (i == WD_NODE) {
			/*
			 * minor number 7 corresponds to the whole disk
			 * if the disk capacity is expanded after disk is
			 * labeled, minor number 7 represents the capacity
			 * indicated by the disk label.
			 */
			cl->cl_map[i].dkl_cylno = 0;
			if (alternate_lba == 1) {
				/*
				 * We are using backup label. Since we can
				 * find a valid label at the end of disk,
				 * the disk capacity is not expanded.
				 */
				cl->cl_map[i].dkl_nblk = capacity;
			} else {
				cl->cl_map[i].dkl_nblk = alternate_lba + 1;
			}
			cl->cl_offset[i] = 0;
		}
		partitions++;
	}
	cl->cl_solaris_offset = 0;
	cl->cl_solaris_size = capacity;
	cl->cl_f_geometry_is_valid = TRUE;

	/* clear the vtoc label */
	bzero(&cl->cl_vtoc, sizeof (struct dk_vtoc));

	kmem_free(buf, EFI_MIN_ARRAY_SIZE);
	return (0);

done_err:
	kmem_free(buf, EFI_MIN_ARRAY_SIZE);
	mutex_enter(CMLB_MUTEX(cl));
done_err1:
	/*
	 * if we didn't find something that could look like a VTOC
	 * and the disk is over 1TB, we know there isn't a valid label.
	 * Otherwise let cmlb_uselabel decide what to do.  We only
	 * want to invalidate this if we're certain the label isn't
	 * valid because cmlb_prop_op will now fail, which in turn
	 * causes things like opens and stats on the partition to fail.
	 */
	if ((capacity > DK_MAX_BLOCKS) && (rval != ESRCH) && !iofailed) {
		cl->cl_f_geometry_is_valid = FALSE;
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
 *   Arguments: cl: unit struct.
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
cmlb_uselabel(struct cmlb_lun *cl, struct dk_label *labp, int flags)
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
	ASSERT(cl != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	/* Validate the magic number of the label. */
	if (labp->dkl_magic != DKL_MAGIC) {
#if defined(__sparc)
		if (!ISREMOVABLE(cl) && !ISHOTPLUGGABLE(cl)) {
			if (!(flags & CMLB_SILENT))
				cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl),
				    CE_WARN,
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
		if (!ISCD(cl)) {
#elif defined(_SUNOS_VTOC_8)
		if (!ISREMOVABLE(cl) && !ISHOTPLUGGABLE(cl)) {
#endif
			if (!(flags & CMLB_SILENT))
				cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl),
				    CE_WARN,
				    "Corrupt label - label checksum failed\n");
		}
		return (CMLB_LABEL_IS_INVALID);
	}


	/*
	 * Fill in geometry structure with data from label.
	 */
	bzero(&cl->cl_g, sizeof (struct dk_geom));
	cl->cl_g.dkg_ncyl   = labp->dkl_ncyl;
	cl->cl_g.dkg_acyl   = labp->dkl_acyl;
	cl->cl_g.dkg_bcyl   = 0;
	cl->cl_g.dkg_nhead  = labp->dkl_nhead;
	cl->cl_g.dkg_nsect  = labp->dkl_nsect;
	cl->cl_g.dkg_intrlv = labp->dkl_intrlv;

#if defined(_SUNOS_VTOC_8)
	cl->cl_g.dkg_gap1   = labp->dkl_gap1;
	cl->cl_g.dkg_gap2   = labp->dkl_gap2;
	cl->cl_g.dkg_bhead  = labp->dkl_bhead;
#endif
#if defined(_SUNOS_VTOC_16)
	cl->cl_dkg_skew = labp->dkl_skew;
#endif

#if defined(__i386) || defined(__amd64)
	cl->cl_g.dkg_apc = labp->dkl_apc;
#endif

	/*
	 * Currently we rely on the values in the label being accurate. If
	 * dkl_rpm or dkl_pcly are zero in the label, use a default value.
	 *
	 * Note: In the future a MODE SENSE may be used to retrieve this data,
	 * although this command is optional in SCSI-2.
	 */
	cl->cl_g.dkg_rpm  = (labp->dkl_rpm  != 0) ? labp->dkl_rpm  : 3600;
	cl->cl_g.dkg_pcyl = (labp->dkl_pcyl != 0) ? labp->dkl_pcyl :
	    (cl->cl_g.dkg_ncyl + cl->cl_g.dkg_acyl);

	/*
	 * The Read and Write reinstruct values may not be valid
	 * for older disks.
	 */
	cl->cl_g.dkg_read_reinstruct  = labp->dkl_read_reinstruct;
	cl->cl_g.dkg_write_reinstruct = labp->dkl_write_reinstruct;

	/* Fill in partition table. */
#if defined(_SUNOS_VTOC_8)
	for (i = 0; i < NDKMAP; i++) {
		cl->cl_map[i].dkl_cylno = labp->dkl_map[i].dkl_cylno;
		cl->cl_map[i].dkl_nblk  = labp->dkl_map[i].dkl_nblk;
	}
#endif
#if  defined(_SUNOS_VTOC_16)
	vpartp		= labp->dkl_vtoc.v_part;
	track_capacity	= labp->dkl_nhead * labp->dkl_nsect;

	/* Prevent divide by zero */
	if (track_capacity == 0) {
		if (!(flags & CMLB_SILENT))
			cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl), CE_WARN,
			    "Corrupt label - zero nhead or nsect value\n");

		return (CMLB_LABEL_IS_INVALID);
	}

	for (i = 0; i < NDKMAP; i++, vpartp++) {
		cl->cl_map[i].dkl_cylno = vpartp->p_start / track_capacity;
		cl->cl_map[i].dkl_nblk  = vpartp->p_size;
	}
#endif

	/* Fill in VTOC Structure. */
	bcopy(&labp->dkl_vtoc, &cl->cl_vtoc, sizeof (struct dk_vtoc));
#if defined(_SUNOS_VTOC_8)
	/*
	 * The 8-slice vtoc does not include the ascii label; save it into
	 * the device's soft state structure here.
	 */
	bcopy(labp->dkl_asciilabel, cl->cl_asciilabel, LEN_DKL_ASCII);
#endif

	/* Now look for a valid capacity. */
	track_capacity	= (cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect);
	label_capacity	= (cl->cl_g.dkg_ncyl  * track_capacity);

	if (cl->cl_g.dkg_acyl) {
#if defined(__i386) || defined(__amd64)
		/* we may have > 1 alts cylinder */
		label_capacity += (track_capacity * cl->cl_g.dkg_acyl);
#else
		label_capacity += track_capacity;
#endif
	}

	/*
	 * Force check here to ensure the computed capacity is valid.
	 * If capacity is zero, it indicates an invalid label and
	 * we should abort updating the relevant data then.
	 */
	if (label_capacity == 0) {
		if (!(flags & CMLB_SILENT))
			cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl), CE_WARN,
			    "Corrupt label - no valid capacity could be "
			    "retrieved\n");

		return (CMLB_LABEL_IS_INVALID);
	}

	/* Mark the geometry as valid. */
	cl->cl_f_geometry_is_valid = TRUE;

	/*
	 * if we got invalidated when mutex exit and entered again,
	 * if blockcount different than when we came in, need to
	 * retry from beginning of cmlb_validate_geometry.
	 * revisit this on next phase of utilizing this for
	 * sd.
	 */

	if (label_capacity <= cl->cl_blockcount) {
#if defined(_SUNOS_VTOC_8)
		/*
		 * We can't let this happen on drives that are subdivided
		 * into logical disks (i.e., that have an fdisk table).
		 * The cl_blockcount field should always hold the full media
		 * size in sectors, period.  This code would overwrite
		 * cl_blockcount with the size of the Solaris fdisk partition.
		 */
		cmlb_dbg(CMLB_ERROR,  cl,
		    "cmlb_uselabel: Label %d blocks; Drive %d blocks\n",
		    label_capacity, cl->cl_blockcount);
		cl->cl_solaris_size = label_capacity;

#endif	/* defined(_SUNOS_VTOC_8) */
		goto done;
	}

	if (ISCD(cl)) {
		/* For CDROMs, we trust that the data in the label is OK. */
#if defined(_SUNOS_VTOC_8)
		for (i = 0; i < NDKMAP; i++) {
			part_end = labp->dkl_nhead * labp->dkl_nsect *
			    labp->dkl_map[i].dkl_cylno +
			    labp->dkl_map[i].dkl_nblk  - 1;

			if ((labp->dkl_map[i].dkl_nblk) &&
			    (part_end > cl->cl_blockcount)) {
				cl->cl_f_geometry_is_valid = FALSE;
				break;
			}
		}
#endif
#if defined(_SUNOS_VTOC_16)
		vpartp = &(labp->dkl_vtoc.v_part[0]);
		for (i = 0; i < NDKMAP; i++, vpartp++) {
			part_end = vpartp->p_start + vpartp->p_size;
			if ((vpartp->p_size > 0) &&
			    (part_end > cl->cl_blockcount)) {
				cl->cl_f_geometry_is_valid = FALSE;
				break;
			}
		}
#endif
	} else {
		/* label_capacity > cl->cl_blockcount */
		if (!(flags & CMLB_SILENT)) {
			cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl), CE_WARN,
			    "Corrupt label - bad geometry\n");
			cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl), CE_CONT,
			    "Label says %llu blocks; Drive says %llu blocks\n",
			    label_capacity, cl->cl_blockcount);
		}
		cl->cl_f_geometry_is_valid = FALSE;
		label_error = CMLB_LABEL_IS_INVALID;
	}

done:

	cmlb_dbg(CMLB_INFO,  cl, "cmlb_uselabel: (label geometry)\n");
	cmlb_dbg(CMLB_INFO,  cl,
	    "   ncyl: %d; acyl: %d; nhead: %d; nsect: %d\n",
	    cl->cl_g.dkg_ncyl,  cl->cl_g.dkg_acyl,
	    cl->cl_g.dkg_nhead, cl->cl_g.dkg_nsect);

	cmlb_dbg(CMLB_INFO,  cl,
	    "   label_capacity: %d; intrlv: %d; rpm: %d\n",
	    cl->cl_blockcount, cl->cl_g.dkg_intrlv, cl->cl_g.dkg_rpm);
	cmlb_dbg(CMLB_INFO,  cl, "   wrt_reinstr: %d; rd_reinstr: %d\n",
	    cl->cl_g.dkg_write_reinstruct, cl->cl_g.dkg_read_reinstruct);

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

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
/*ARGSUSED*/
static void
cmlb_build_default_label(struct cmlb_lun *cl, void *tg_cookie)
{
#if defined(_SUNOS_VTOC_16)
	uint_t	phys_spc;
	uint_t	disksize;
	struct  dk_geom cl_g;
	diskaddr_t capacity;
#endif

	ASSERT(cl != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

#if defined(_SUNOS_VTOC_8)
	/*
	 * Note: This is a legacy check for non-removable devices on VTOC_8
	 * only. This may be a valid check for VTOC_16 as well.
	 * Once we understand why there is this difference between SPARC and
	 * x86 platform, we could remove this legacy check.
	 */
	if (!ISREMOVABLE(cl) && !ISHOTPLUGGABLE(cl)) {
		return;
	}
#endif

	bzero(&cl->cl_g, sizeof (struct dk_geom));
	bzero(&cl->cl_vtoc, sizeof (struct dk_vtoc));
	bzero(&cl->cl_map, NDKMAP * (sizeof (struct dk_map)));

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
	cl->cl_solaris_size = cl->cl_blockcount;
	if (ISCD(cl)) {
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

		mutex_exit(CMLB_MUTEX(cl));
		is_writable =
		    (DK_TG_GETATTRIBUTE(cl, &tgattribute, tg_cookie) == 0) ?
		    tgattribute.media_is_writable : 1;
		mutex_enter(CMLB_MUTEX(cl));

		if (is_writable) {
			cl->cl_g.dkg_nhead = 64;
			cl->cl_g.dkg_nsect = 32;
			cl->cl_g.dkg_ncyl = cl->cl_blockcount / (64 * 32);
			cl->cl_solaris_size = cl->cl_g.dkg_ncyl *
			    cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect;
		} else {
			cl->cl_g.dkg_ncyl  = 1;
			cl->cl_g.dkg_nhead = 1;
			cl->cl_g.dkg_nsect = cl->cl_blockcount;
		}
	} else {
		if (cl->cl_blockcount <= 0x1000) {
			/* unlabeled SCSI floppy device */
			cl->cl_g.dkg_nhead = 2;
			cl->cl_g.dkg_ncyl = 80;
			cl->cl_g.dkg_nsect = cl->cl_blockcount / (2 * 80);
		} else if (cl->cl_blockcount <= 0x200000) {
			cl->cl_g.dkg_nhead = 64;
			cl->cl_g.dkg_nsect = 32;
			cl->cl_g.dkg_ncyl  = cl->cl_blockcount / (64 * 32);
		} else {
			cl->cl_g.dkg_nhead = 255;

			cl->cl_g.dkg_nsect = ((cl->cl_blockcount +
			    (UINT16_MAX * 255 * 63) - 1) /
			    (UINT16_MAX * 255 * 63)) * 63;

			if (cl->cl_g.dkg_nsect == 0)
				cl->cl_g.dkg_nsect = (UINT16_MAX / 63) * 63;

			cl->cl_g.dkg_ncyl = cl->cl_blockcount /
			    (255 * cl->cl_g.dkg_nsect);
		}

		cl->cl_solaris_size =
		    cl->cl_g.dkg_ncyl * cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect;

	}

	cl->cl_g.dkg_acyl	= 0;
	cl->cl_g.dkg_bcyl	= 0;
	cl->cl_g.dkg_rpm	= 200;
	cl->cl_asciilabel[0]	= '\0';
	cl->cl_g.dkg_pcyl	= cl->cl_g.dkg_ncyl;

	cl->cl_map[0].dkl_cylno = 0;
	cl->cl_map[0].dkl_nblk  = cl->cl_solaris_size;

	cl->cl_map[2].dkl_cylno = 0;
	cl->cl_map[2].dkl_nblk  = cl->cl_solaris_size;

#elif defined(_SUNOS_VTOC_16)

	if (cl->cl_solaris_size == 0) {
		/*
		 * Got fdisk table but no solaris entry therefore
		 * don't create a default label
		 */
		cl->cl_f_geometry_is_valid = TRUE;
		return;
	}

	/*
	 * For CDs we continue to use the physical geometry to calculate
	 * number of cylinders. All other devices must convert the
	 * physical geometry (cmlb_geom) to values that will fit
	 * in a dk_geom structure.
	 */
	if (ISCD(cl)) {
		phys_spc = cl->cl_pgeom.g_nhead * cl->cl_pgeom.g_nsect;
	} else {
		/* Convert physical geometry to disk geometry */
		bzero(&cl_g, sizeof (struct dk_geom));

		/*
		 * Refer to comments related to off-by-1 at the
		 * header of this file.
		 * Before caculating geometry, capacity should be
		 * decreased by 1.
		 */

		if (cl->cl_alter_behavior & CMLB_OFF_BY_ONE)
			capacity = cl->cl_blockcount - 1;
		else
			capacity = cl->cl_blockcount;


		cmlb_convert_geometry(capacity, &cl_g);
		bcopy(&cl_g, &cl->cl_g, sizeof (cl->cl_g));
		phys_spc = cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect;
	}

	ASSERT(phys_spc != 0);
	cl->cl_g.dkg_pcyl = cl->cl_solaris_size / phys_spc;
	if (cl->cl_alter_behavior & CMLB_FAKE_LABEL_ONE_PARTITION) {
		/* disable devid */
		cl->cl_g.dkg_ncyl = cl->cl_g.dkg_pcyl;
		disksize = cl->cl_solaris_size;
	} else {
		cl->cl_g.dkg_acyl = DK_ACYL;
		cl->cl_g.dkg_ncyl = cl->cl_g.dkg_pcyl - DK_ACYL;
		disksize = cl->cl_g.dkg_ncyl * phys_spc;
	}

	if (ISCD(cl)) {
		/*
		 * CD's don't use the "heads * sectors * cyls"-type of
		 * geometry, but instead use the entire capacity of the media.
		 */
		disksize = cl->cl_solaris_size;
		cl->cl_g.dkg_nhead = 1;
		cl->cl_g.dkg_nsect = 1;
		cl->cl_g.dkg_rpm =
		    (cl->cl_pgeom.g_rpm == 0) ? 200 : cl->cl_pgeom.g_rpm;

		cl->cl_vtoc.v_part[0].p_start = 0;
		cl->cl_vtoc.v_part[0].p_size  = disksize;
		cl->cl_vtoc.v_part[0].p_tag   = V_BACKUP;
		cl->cl_vtoc.v_part[0].p_flag  = V_UNMNT;

		cl->cl_map[0].dkl_cylno = 0;
		cl->cl_map[0].dkl_nblk  = disksize;
		cl->cl_offset[0] = 0;

	} else {
		/*
		 * Hard disks and removable media cartridges
		 */
		cl->cl_g.dkg_rpm =
		    (cl->cl_pgeom.g_rpm == 0) ? 3600: cl->cl_pgeom.g_rpm;
		cl->cl_vtoc.v_sectorsz = cl->cl_sys_blocksize;

		/* Add boot slice */
		cl->cl_vtoc.v_part[8].p_start = 0;
		cl->cl_vtoc.v_part[8].p_size  = phys_spc;
		cl->cl_vtoc.v_part[8].p_tag   = V_BOOT;
		cl->cl_vtoc.v_part[8].p_flag  = V_UNMNT;

		cl->cl_map[8].dkl_cylno = 0;
		cl->cl_map[8].dkl_nblk  = phys_spc;
		cl->cl_offset[8] = 0;

		if ((cl->cl_alter_behavior &
		    CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT) &&
		    cl->cl_device_type == DTYPE_DIRECT) {
			cl->cl_vtoc.v_part[9].p_start = phys_spc;
			cl->cl_vtoc.v_part[9].p_size  = 2 * phys_spc;
			cl->cl_vtoc.v_part[9].p_tag   = V_ALTSCTR;
			cl->cl_vtoc.v_part[9].p_flag  = 0;

			cl->cl_map[9].dkl_cylno = 1;
			cl->cl_map[9].dkl_nblk  = 2 * phys_spc;
			cl->cl_offset[9] = phys_spc;
		}
	}

	cl->cl_g.dkg_apc = 0;
	cl->cl_vtoc.v_nparts = V_NUMPAR;
	cl->cl_vtoc.v_version = V_VERSION;

	/* Add backup slice */
	cl->cl_vtoc.v_part[2].p_start = 0;
	cl->cl_vtoc.v_part[2].p_size  = disksize;
	cl->cl_vtoc.v_part[2].p_tag   = V_BACKUP;
	cl->cl_vtoc.v_part[2].p_flag  = V_UNMNT;

	cl->cl_map[2].dkl_cylno = 0;
	cl->cl_map[2].dkl_nblk  = disksize;
	cl->cl_offset[2] = 0;

	/*
	 * single slice (s0) covering the entire disk
	 */
	if (cl->cl_alter_behavior & CMLB_FAKE_LABEL_ONE_PARTITION) {
		cl->cl_vtoc.v_part[0].p_start = 0;
		cl->cl_vtoc.v_part[0].p_tag   = V_UNASSIGNED;
		cl->cl_vtoc.v_part[0].p_flag  = 0;
		cl->cl_vtoc.v_part[0].p_size  = disksize;
		cl->cl_map[0].dkl_cylno = 0;
		cl->cl_map[0].dkl_nblk  = disksize;
		cl->cl_offset[0] = 0;
	}

	(void) sprintf(cl->cl_vtoc.v_asciilabel, "DEFAULT cyl %d alt %d"
	    " hd %d sec %d", cl->cl_g.dkg_ncyl, cl->cl_g.dkg_acyl,
	    cl->cl_g.dkg_nhead, cl->cl_g.dkg_nsect);

#else
#error "No VTOC format defined."
#endif

	cl->cl_g.dkg_read_reinstruct  = 0;
	cl->cl_g.dkg_write_reinstruct = 0;

	cl->cl_g.dkg_intrlv = 1;

	cl->cl_vtoc.v_sanity  = VTOC_SANE;

	cl->cl_f_geometry_is_valid = TRUE;
	cl->cl_vtoc_label_is_from_media = 0;

	cmlb_dbg(CMLB_INFO,  cl,
	    "cmlb_build_default_label: Default label created: "
	    "cyl: %d\tacyl: %d\tnhead: %d\tnsect: %d\tcap: %d\n",
	    cl->cl_g.dkg_ncyl, cl->cl_g.dkg_acyl, cl->cl_g.dkg_nhead,
	    cl->cl_g.dkg_nsect, cl->cl_blockcount);
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
 *	arg		pointer to user provided dk_geom structure specifying
 *			the controller's notion of the current geometry.
 *
 *	flag 		this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_get_geometry(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie)
{
	struct dk_geom	*tmp_geom = NULL;
	int		rval = 0;

	/*
	 * cmlb_validate_geometry does not spin a disk up
	 * if it was spcl down. We need to make sure it
	 * is ready.
	 */
	mutex_enter(CMLB_MUTEX(cl));
	rval = cmlb_validate_geometry(cl, 1, 0, tg_cookie);
#if defined(_SUNOS_VTOC_8)
	if (rval == EINVAL &&
	    cl->cl_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8) {
		/*
		 * This is to return a default label geometry even when we
		 * do not really assume a default label for the device.
		 * dad driver utilizes this.
		 */
		if (cl->cl_blockcount <= DK_MAX_BLOCKS) {
			cmlb_setup_default_geometry(cl, tg_cookie);
			rval = 0;
		}
	}
#endif
	if (rval) {
		mutex_exit(CMLB_MUTEX(cl));
		return (rval);
	}

#if defined(__i386) || defined(__amd64)
	if (cl->cl_solaris_size == 0) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EIO);
	}
#endif

	/*
	 * Make a local copy of the soft state geometry to avoid some potential
	 * race conditions associated with holding the mutex and updating the
	 * write_reinstruct value
	 */
	tmp_geom = kmem_zalloc(sizeof (struct dk_geom), KM_SLEEP);
	bcopy(&cl->cl_g, tmp_geom, sizeof (struct dk_geom));

	if (tmp_geom->dkg_write_reinstruct == 0) {
		tmp_geom->dkg_write_reinstruct =
		    (int)((int)(tmp_geom->dkg_nsect * tmp_geom->dkg_rpm *
		    cmlb_rot_delay) / (int)60000);
	}
	mutex_exit(CMLB_MUTEX(cl));

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
 *	arg		pointer to user provided dk_geom structure used to set
 *			the controller's notion of the current geometry.
 *
 *	flag 		this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_set_geometry(struct cmlb_lun *cl, caddr_t arg, int flag)
{
	struct dk_geom	*tmp_geom;
	struct dk_map	*lp;
	int		rval = 0;
	int		i;


#if defined(__i386) || defined(__amd64)
	if (cl->cl_solaris_size == 0) {
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

	mutex_enter(CMLB_MUTEX(cl));
	bcopy(tmp_geom, &cl->cl_g, sizeof (struct dk_geom));
	for (i = 0; i < NDKMAP; i++) {
		lp  = &cl->cl_map[i];
		cl->cl_offset[i] =
		    cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect * lp->dkl_cylno;
#if defined(__i386) || defined(__amd64)
		cl->cl_offset[i] += cl->cl_solaris_offset;
#endif
	}
	cl->cl_f_geometry_is_valid = FALSE;
	mutex_exit(CMLB_MUTEX(cl));
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
 *	arg		pointer to user provided dk_allmap structure specifying
 *			the controller's notion of the current partition table.
 *
 *	flag		this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_get_partition(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie)
{
	int		rval = 0;
	int		size;

	/*
	 * Make sure the geometry is valid before getting the partition
	 * information.
	 */
	mutex_enter(CMLB_MUTEX(cl));
	if ((rval = cmlb_validate_geometry(cl, 1, 0, tg_cookie)) != 0) {
		mutex_exit(CMLB_MUTEX(cl));
		return (rval);
	}
	mutex_exit(CMLB_MUTEX(cl));

#if defined(__i386) || defined(__amd64)
	if (cl->cl_solaris_size == 0) {
		return (EIO);
	}
#endif

#ifdef _MULTI_DATAMODEL
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32: {
		struct dk_map32 dk_map32[NDKMAP];
		int		i;

		for (i = 0; i < NDKMAP; i++) {
			dk_map32[i].dkl_cylno = cl->cl_map[i].dkl_cylno;
			dk_map32[i].dkl_nblk  = cl->cl_map[i].dkl_nblk;
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
		rval = ddi_copyout(cl->cl_map, (void *)arg, size, flag);
		if (rval != 0) {
			rval = EFAULT;
		}
		break;
	}
#else /* ! _MULTI_DATAMODEL */
	size = NDKMAP * sizeof (struct dk_map);
	rval = ddi_copyout(cl->cl_map, (void *)arg, size, flag);
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
cmlb_dkio_set_partition(struct cmlb_lun *cl, caddr_t arg, int flag)
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
	_NOTE(DATA_READABLE_WITHOUT_LOCK(cmlb_lun::cl_solaris_size))
	mutex_enter(CMLB_MUTEX(cl));

	if (cl->cl_blockcount > DK_MAX_BLOCKS) {
		mutex_exit(CMLB_MUTEX(cl));
		return (ENOTSUP);
	}
	mutex_exit(CMLB_MUTEX(cl));
	if (cl->cl_solaris_size == 0) {
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

	mutex_enter(CMLB_MUTEX(cl));
	/* Note: The size used in this bcopy is set based upon the data model */
	bcopy(dk_map, cl->cl_map, size);
#if defined(_SUNOS_VTOC_16)
	vp = (struct dkl_partition *)&(cl->cl_vtoc);
#endif	/* defined(_SUNOS_VTOC_16) */
	for (i = 0; i < NDKMAP; i++) {
		lp  = &cl->cl_map[i];
		cl->cl_offset[i] =
		    cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect * lp->dkl_cylno;
#if defined(_SUNOS_VTOC_16)
		vp->p_start = cl->cl_offset[i];
		vp->p_size = lp->dkl_nblk;
		vp++;
#endif	/* defined(_SUNOS_VTOC_16) */
#if defined(__i386) || defined(__amd64)
		cl->cl_offset[i] += cl->cl_solaris_offset;
#endif
	}
	mutex_exit(CMLB_MUTEX(cl));
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
 *	arg		pointer to user provided vtoc structure specifying
 *			the current vtoc.
 *
 *	flag		this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EIO
 */
static int
cmlb_dkio_get_vtoc(struct cmlb_lun *cl, caddr_t arg, int flag, void *tg_cookie)
{
#if defined(_SUNOS_VTOC_8)
	struct vtoc	user_vtoc;
#endif	/* defined(_SUNOS_VTOC_8) */
	int		rval = 0;

	mutex_enter(CMLB_MUTEX(cl));
	rval = cmlb_validate_geometry(cl, 1, 0, tg_cookie);

#if defined(_SUNOS_VTOC_8)
	if (rval == EINVAL &&
	    (cl->cl_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8)) {
		/*
		 * This is to return a default label even when we do not
		 * really assume a default label for the device.
		 * dad driver utilizes this.
		 */
		if (cl->cl_blockcount <= DK_MAX_BLOCKS) {
			cmlb_setup_default_geometry(cl, tg_cookie);
			rval = 0;
		}
	}
#endif
	if (rval) {
		mutex_exit(CMLB_MUTEX(cl));
		return (rval);
	}

#if defined(_SUNOS_VTOC_8)
	cmlb_build_user_vtoc(cl, &user_vtoc);
	mutex_exit(CMLB_MUTEX(cl));

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
	mutex_exit(CMLB_MUTEX(cl));

#ifdef _MULTI_DATAMODEL
	/*
	 * The cl_vtoc structure is a "struct dk_vtoc"  which is always
	 * 32-bit to maintain compatibility with existing on-disk
	 * structures.  Thus, we need to convert the structure when copying
	 * it out to a datamodel-dependent "struct vtoc" in a 64-bit
	 * program.  If the target is a 32-bit program, then no conversion
	 * is necessary.
	 */
	/* LINTED: logical expression always true: op "||" */
	ASSERT(sizeof (cl->cl_vtoc) == sizeof (struct vtoc32));
	switch (ddi_model_convert_from(flag & FMODELS)) {
	case DDI_MODEL_ILP32:
		if (ddi_copyout(&(cl->cl_vtoc), (void *)arg,
		    sizeof (cl->cl_vtoc), flag)) {
			return (EFAULT);
		}
		break;

	case DDI_MODEL_NONE: {
		struct vtoc user_vtoc;

		vtoc32tovtoc(cl->cl_vtoc, user_vtoc);
		if (ddi_copyout(&user_vtoc, (void *)arg,
		    sizeof (struct vtoc), flag)) {
			return (EFAULT);
		}
		break;
	}
	}
#else /* ! _MULTI_DATAMODEL */
	if (ddi_copyout(&(cl->cl_vtoc), (void *)arg, sizeof (cl->cl_vtoc),
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
cmlb_dkio_get_efi(struct cmlb_lun *cl, caddr_t arg, int flag, void *tg_cookie)
{
	dk_efi_t	user_efi;
	int		rval = 0;
	void		*buffer;
	diskaddr_t	tgt_lba;

	if (ddi_copyin(arg, &user_efi, sizeof (dk_efi_t), flag))
		return (EFAULT);

	user_efi.dki_data = (void *)(uintptr_t)user_efi.dki_data_64;

	tgt_lba = user_efi.dki_lba;

	mutex_enter(CMLB_MUTEX(cl));
	if ((cmlb_check_update_blockcount(cl, tg_cookie) != 0) ||
	    (cl->cl_tgt_blocksize == 0)) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}
	if (cl->cl_tgt_blocksize != cl->cl_sys_blocksize)
		tgt_lba = tgt_lba * cl->cl_tgt_blocksize /
		    cl->cl_sys_blocksize;
	mutex_exit(CMLB_MUTEX(cl));

	buffer = kmem_alloc(user_efi.dki_length, KM_SLEEP);
	rval = DK_TG_READ(cl, buffer, tgt_lba, user_efi.dki_length, tg_cookie);
	if (rval == 0 && ddi_copyout(buffer, user_efi.dki_data,
	    user_efi.dki_length, flag) != 0)
		rval = EFAULT;

	kmem_free(buffer, user_efi.dki_length);
	return (rval);
}

#if defined(_SUNOS_VTOC_8)
/*
 *    Function: cmlb_build_user_vtoc
 *
 * Description: This routine populates a pass by reference variable with the
 *		current volume table of contents.
 *
 *   Arguments: cl - driver soft state (unit) structure
 *		user_vtoc - pointer to vtoc structure to be populated
 */
static void
cmlb_build_user_vtoc(struct cmlb_lun *cl, struct vtoc *user_vtoc)
{
	struct dk_map2		*lpart;
	struct dk_map		*lmap;
	struct partition	*vpart;
	int			nblks;
	int			i;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	/*
	 * Return vtoc structure fields in the provided VTOC area, addressed
	 * by *vtoc.
	 */
	bzero(user_vtoc, sizeof (struct vtoc));
	user_vtoc->v_bootinfo[0] = cl->cl_vtoc.v_bootinfo[0];
	user_vtoc->v_bootinfo[1] = cl->cl_vtoc.v_bootinfo[1];
	user_vtoc->v_bootinfo[2] = cl->cl_vtoc.v_bootinfo[2];
	user_vtoc->v_sanity	= VTOC_SANE;
	user_vtoc->v_version	= cl->cl_vtoc.v_version;
	bcopy(cl->cl_vtoc.v_volume, user_vtoc->v_volume, LEN_DKL_VVOL);
	user_vtoc->v_sectorsz = cl->cl_sys_blocksize;
	user_vtoc->v_nparts = cl->cl_vtoc.v_nparts;

	for (i = 0; i < 10; i++)
		user_vtoc->v_reserved[i] = cl->cl_vtoc.v_reserved[i];

	/*
	 * Convert partitioning information.
	 *
	 * Note the conversion from starting cylinder number
	 * to starting sector number.
	 */
	lmap = cl->cl_map;
	lpart = (struct dk_map2 *)cl->cl_vtoc.v_part;
	vpart = user_vtoc->v_part;

	nblks = cl->cl_g.dkg_nsect * cl->cl_g.dkg_nhead;

	for (i = 0; i < V_NUMPAR; i++) {
		vpart->p_tag	= lpart->p_tag;
		vpart->p_flag	= lpart->p_flag;
		vpart->p_start	= lmap->dkl_cylno * nblks;
		vpart->p_size	= lmap->dkl_nblk;
		lmap++;
		lpart++;
		vpart++;

		/* (4364927) */
		user_vtoc->timestamp[i] = (time_t)cl->cl_vtoc.v_timestamp[i];
	}

	bcopy(cl->cl_asciilabel, user_vtoc->v_asciilabel, LEN_DKL_ASCII);
}
#endif

static int
cmlb_dkio_partition(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie)
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
	rval = DK_TG_READ(cl, buffer, 1, DEV_BSIZE, tg_cookie);
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
	rval = DK_TG_READ(cl, buffer, gpe_lba, EFI_MIN_ARRAY_SIZE, tg_cookie);

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
 *   Arguments:
 *	dev		the device number
 *	arg		pointer to user provided vtoc structure used to set the
 *			current vtoc.
 *
 *	flag		this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0
 *		EFAULT
 *		ENXIO
 *		EINVAL
 *		ENOTSUP
 */
static int
cmlb_dkio_set_vtoc(struct cmlb_lun *cl, dev_t dev, caddr_t arg, int flag,
    void *tg_cookie)
{
	struct vtoc	user_vtoc;
	int		rval = 0;
	boolean_t	internal;

	internal = ((cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);

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

	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_blockcount > DK_MAX_BLOCKS) {
		mutex_exit(CMLB_MUTEX(cl));
		return (ENOTSUP);
	}

#if defined(__i386) || defined(__amd64)
	if (cl->cl_tgt_blocksize != cl->cl_sys_blocksize) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}
#endif

	if (cl->cl_g.dkg_ncyl == 0) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}

	mutex_exit(CMLB_MUTEX(cl));
	cmlb_clear_efi(cl, tg_cookie);
	ddi_remove_minor_node(CMLB_DEVINFO(cl), "wd");
	ddi_remove_minor_node(CMLB_DEVINFO(cl), "wd,raw");
	(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h",
	    S_IFBLK, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    cl->cl_node_type, NULL, internal);
	(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h,raw",
	    S_IFCHR, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    cl->cl_node_type, NULL, internal);
	mutex_enter(CMLB_MUTEX(cl));

	if ((rval = cmlb_build_label_vtoc(cl, &user_vtoc)) == 0) {
		if ((rval = cmlb_write_label(cl, tg_cookie)) == 0) {
			if (cmlb_validate_geometry(cl, 1, 0, tg_cookie) != 0) {
				cmlb_dbg(CMLB_ERROR, cl,
				    "cmlb_dkio_set_vtoc: "
				    "Failed validate geometry\n");
			}
		}
	}
	mutex_exit(CMLB_MUTEX(cl));
	return (rval);
}


/*
 *    Function: cmlb_build_label_vtoc
 *
 * Description: This routine updates the driver soft state current volume table
 *		of contents based on a user specified vtoc.
 *
 *   Arguments: cl - driver soft state (unit) structure
 *		user_vtoc - pointer to vtoc structure specifying vtoc to be used
 *			    to update the driver soft state.
 *
 * Return Code: 0
 *		EINVAL
 */
static int
cmlb_build_label_vtoc(struct cmlb_lun *cl, struct vtoc *user_vtoc)
{
	struct dk_map		*lmap;
	struct partition	*vpart;
	int			nblks;
#if defined(_SUNOS_VTOC_8)
	int			ncyl;
	struct dk_map2		*lpart;
#endif	/* defined(_SUNOS_VTOC_8) */
	int			i;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	/* Sanity-check the vtoc */
	if (user_vtoc->v_sanity != VTOC_SANE ||
	    user_vtoc->v_sectorsz != cl->cl_sys_blocksize ||
	    user_vtoc->v_nparts != V_NUMPAR) {
		cmlb_dbg(CMLB_INFO,  cl,
		    "cmlb_build_label_vtoc: vtoc not valid\n");
		return (EINVAL);
	}

	nblks = cl->cl_g.dkg_nsect * cl->cl_g.dkg_nhead;
	if (nblks == 0) {
		cmlb_dbg(CMLB_INFO,  cl,
		    "cmlb_build_label_vtoc: geom nblks is 0\n");
		return (EINVAL);
	}

#if defined(_SUNOS_VTOC_8)
	vpart = user_vtoc->v_part;
	for (i = 0; i < V_NUMPAR; i++) {
		if ((vpart->p_start % nblks) != 0) {
			cmlb_dbg(CMLB_INFO,  cl,
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
		if (ncyl > (int)cl->cl_g.dkg_ncyl) {
			cmlb_dbg(CMLB_INFO,  cl,
			    "cmlb_build_label_vtoc: ncyl %d  > dkg_ncyl %d"
			    "p_size %ld p_start %ld nblks %d  part number %d"
			    "tag %d\n",
			    ncyl, cl->cl_g.dkg_ncyl, vpart->p_size,
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
	vtoctovtoc32((*user_vtoc), (*((struct vtoc32 *)&(cl->cl_vtoc))));

	/*
	 * in the 16-slice vtoc, starting sectors are expressed in
	 * numbers *relative* to the start of the Solaris fdisk partition.
	 */
	lmap = cl->cl_map;
	vpart = user_vtoc->v_part;

	for (i = 0; i < (int)user_vtoc->v_nparts; i++, lmap++, vpart++) {
		lmap->dkl_cylno = vpart->p_start / nblks;
		lmap->dkl_nblk = vpart->p_size;
	}

#elif defined(_SUNOS_VTOC_8)

	cl->cl_vtoc.v_bootinfo[0] = (uint32_t)user_vtoc->v_bootinfo[0];
	cl->cl_vtoc.v_bootinfo[1] = (uint32_t)user_vtoc->v_bootinfo[1];
	cl->cl_vtoc.v_bootinfo[2] = (uint32_t)user_vtoc->v_bootinfo[2];

	cl->cl_vtoc.v_sanity = (uint32_t)user_vtoc->v_sanity;
	cl->cl_vtoc.v_version = (uint32_t)user_vtoc->v_version;

	bcopy(user_vtoc->v_volume, cl->cl_vtoc.v_volume, LEN_DKL_VVOL);

	cl->cl_vtoc.v_nparts = user_vtoc->v_nparts;

	for (i = 0; i < 10; i++)
		cl->cl_vtoc.v_reserved[i] =  user_vtoc->v_reserved[i];

	/*
	 * Note the conversion from starting sector number
	 * to starting cylinder number.
	 * Return error if division results in a remainder.
	 */
	lmap = cl->cl_map;
	lpart = cl->cl_vtoc.v_part;
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
			cl->cl_vtoc.v_timestamp[i] = TIME32_MAX;
		} else {
			cl->cl_vtoc.v_timestamp[i] = user_vtoc->timestamp[i];
		}
#else
		cl->cl_vtoc.v_timestamp[i] = user_vtoc->timestamp[i];
#endif
	}

	bcopy(user_vtoc->v_asciilabel, cl->cl_asciilabel, LEN_DKL_ASCII);
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
 *   Arguments:
 *	cl		 driver soft state (unit) structure
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 * Return Code: void
 */
static void
cmlb_clear_efi(struct cmlb_lun *cl, void *tg_cookie)
{
	efi_gpt_t	*gpt;
	diskaddr_t	cap;
	int		rval;

	ASSERT(!mutex_owned(CMLB_MUTEX(cl)));

	mutex_enter(CMLB_MUTEX(cl));
	cl->cl_reserved = -1;
	mutex_exit(CMLB_MUTEX(cl));

	gpt = kmem_alloc(sizeof (efi_gpt_t), KM_SLEEP);

	if (DK_TG_READ(cl, gpt, 1, DEV_BSIZE, tg_cookie) != 0) {
		goto done;
	}

	cmlb_swap_efi_gpt(gpt);
	rval = cmlb_validate_efi(gpt);
	if (rval == 0) {
		/* clear primary */
		bzero(gpt, sizeof (efi_gpt_t));
		if (rval = DK_TG_WRITE(cl, gpt, 1, EFI_LABEL_SIZE, tg_cookie)) {
			cmlb_dbg(CMLB_INFO,  cl,
			    "cmlb_clear_efi: clear primary label failed\n");
		}
	}
	/* the backup */
	rval = DK_TG_GETCAP(cl, &cap, tg_cookie);
	if (rval) {
		goto done;
	}

	if ((rval = DK_TG_READ(cl, gpt, cap - 1, EFI_LABEL_SIZE, tg_cookie))
	    != 0) {
		goto done;
	}
	cmlb_swap_efi_gpt(gpt);
	rval = cmlb_validate_efi(gpt);
	if (rval == 0) {
		/* clear backup */
		cmlb_dbg(CMLB_TRACE,  cl,
		    "cmlb_clear_efi clear backup@%lu\n", cap - 1);
		bzero(gpt, sizeof (efi_gpt_t));
		if ((rval = DK_TG_WRITE(cl,  gpt, cap - 1, EFI_LABEL_SIZE,
		    tg_cookie))) {
			cmlb_dbg(CMLB_INFO,  cl,
			    "cmlb_clear_efi: clear backup label failed\n");
		}
	} else {
		/*
		 * Refer to comments related to off-by-1 at the
		 * header of this file
		 */
		if ((rval = DK_TG_READ(cl, gpt, cap - 2,
		    EFI_LABEL_SIZE, tg_cookie)) != 0) {
			goto done;
		}
		cmlb_swap_efi_gpt(gpt);
		rval = cmlb_validate_efi(gpt);
		if (rval == 0) {
			/* clear legacy backup EFI label */
			cmlb_dbg(CMLB_TRACE,  cl,
			    "cmlb_clear_efi clear legacy backup@%lu\n",
			    cap - 2);
			bzero(gpt, sizeof (efi_gpt_t));
			if ((rval = DK_TG_WRITE(cl,  gpt, cap - 2,
			    EFI_LABEL_SIZE, tg_cookie))) {
				cmlb_dbg(CMLB_INFO,  cl,
				"cmlb_clear_efi: clear legacy backup label "
				"failed\n");
			}
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
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *
 *	dkl		the data to be written
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return: void
 */
static int
cmlb_set_vtoc(struct cmlb_lun *cl, struct dk_label *dkl, void *tg_cookie)
{
	uint_t	label_addr;
	int	sec;
	int	blk;
	int	head;
	int	cyl;
	int	rval;

#if defined(__i386) || defined(__amd64)
	label_addr = cl->cl_solaris_offset + DK_LABEL_LOC;
#else
	/* Write the primary label at block 0 of the solaris partition. */
	label_addr = 0;
#endif

	rval = DK_TG_WRITE(cl, dkl, label_addr, cl->cl_sys_blocksize,
	    tg_cookie);

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
		blk += cl->cl_solaris_offset;
#endif
		rval = DK_TG_WRITE(cl, dkl, blk, cl->cl_sys_blocksize,
		    tg_cookie);
		cmlb_dbg(CMLB_INFO,  cl,
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
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return: void
 */
static void
cmlb_clear_vtoc(struct cmlb_lun *cl, void *tg_cookie)
{
	struct dk_label		*dkl;

	mutex_exit(CMLB_MUTEX(cl));
	dkl = kmem_zalloc(sizeof (struct dk_label), KM_SLEEP);
	mutex_enter(CMLB_MUTEX(cl));
	/*
	 * cmlb_set_vtoc uses these fields in order to figure out
	 * where to overwrite the backup labels
	 */
	dkl->dkl_apc    = cl->cl_g.dkg_apc;
	dkl->dkl_ncyl   = cl->cl_g.dkg_ncyl;
	dkl->dkl_acyl   = cl->cl_g.dkg_acyl;
	dkl->dkl_nhead  = cl->cl_g.dkg_nhead;
	dkl->dkl_nsect  = cl->cl_g.dkg_nsect;
	mutex_exit(CMLB_MUTEX(cl));
	(void) cmlb_set_vtoc(cl, dkl, tg_cookie);
	kmem_free(dkl, sizeof (struct dk_label));

	mutex_enter(CMLB_MUTEX(cl));
}

/*
 *    Function: cmlb_write_label
 *
 * Description: This routine will validate and write the driver soft state vtoc
 *		contents to the device.
 *
 *   Arguments:
 *	cl		cmlb handle
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 *
 * Return Code: the code returned by cmlb_send_scsi_cmd()
 *		0
 *		EINVAL
 *		ENXIO
 *		ENOMEM
 */
static int
cmlb_write_label(struct cmlb_lun *cl, void *tg_cookie)
{
	struct dk_label	*dkl;
	short		sum;
	short		*sp;
	int		i;
	int		rval;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));
	mutex_exit(CMLB_MUTEX(cl));
	dkl = kmem_zalloc(sizeof (struct dk_label), KM_SLEEP);
	mutex_enter(CMLB_MUTEX(cl));

	bcopy(&cl->cl_vtoc, &dkl->dkl_vtoc, sizeof (struct dk_vtoc));
	dkl->dkl_rpm	= cl->cl_g.dkg_rpm;
	dkl->dkl_pcyl	= cl->cl_g.dkg_pcyl;
	dkl->dkl_apc	= cl->cl_g.dkg_apc;
	dkl->dkl_intrlv = cl->cl_g.dkg_intrlv;
	dkl->dkl_ncyl	= cl->cl_g.dkg_ncyl;
	dkl->dkl_acyl	= cl->cl_g.dkg_acyl;
	dkl->dkl_nhead	= cl->cl_g.dkg_nhead;
	dkl->dkl_nsect	= cl->cl_g.dkg_nsect;

#if defined(_SUNOS_VTOC_8)
	dkl->dkl_obs1	= cl->cl_g.dkg_obs1;
	dkl->dkl_obs2	= cl->cl_g.dkg_obs2;
	dkl->dkl_obs3	= cl->cl_g.dkg_obs3;
	for (i = 0; i < NDKMAP; i++) {
		dkl->dkl_map[i].dkl_cylno = cl->cl_map[i].dkl_cylno;
		dkl->dkl_map[i].dkl_nblk  = cl->cl_map[i].dkl_nblk;
	}
	bcopy(cl->cl_asciilabel, dkl->dkl_asciilabel, LEN_DKL_ASCII);
#elif defined(_SUNOS_VTOC_16)
	dkl->dkl_skew	= cl->cl_dkg_skew;
#else
#error "No VTOC format defined."
#endif

	dkl->dkl_magic			= DKL_MAGIC;
	dkl->dkl_write_reinstruct	= cl->cl_g.dkg_write_reinstruct;
	dkl->dkl_read_reinstruct	= cl->cl_g.dkg_read_reinstruct;

	/* Construct checksum for the new disk label */
	sum = 0;
	sp = (short *)dkl;
	i = sizeof (struct dk_label) / sizeof (short);
	while (i--) {
		sum ^= *sp++;
	}
	dkl->dkl_cksum = sum;

	mutex_exit(CMLB_MUTEX(cl));

	rval = cmlb_set_vtoc(cl, dkl, tg_cookie);
exit:
	kmem_free(dkl, sizeof (struct dk_label));
	mutex_enter(CMLB_MUTEX(cl));
	return (rval);
}

static int
cmlb_dkio_set_efi(struct cmlb_lun *cl, dev_t dev, caddr_t arg, int flag,
    void *tg_cookie)
{
	dk_efi_t	user_efi;
	int		rval = 0;
	void		*buffer;
	diskaddr_t	tgt_lba;
	boolean_t	internal;

	if (ddi_copyin(arg, &user_efi, sizeof (dk_efi_t), flag))
		return (EFAULT);

	internal = ((cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);

	user_efi.dki_data = (void *)(uintptr_t)user_efi.dki_data_64;

	buffer = kmem_alloc(user_efi.dki_length, KM_SLEEP);
	if (ddi_copyin(user_efi.dki_data, buffer, user_efi.dki_length, flag)) {
		rval = EFAULT;
	} else {
		/*
		 * let's clear the vtoc labels and clear the softstate
		 * vtoc.
		 */
		mutex_enter(CMLB_MUTEX(cl));
		if (cl->cl_vtoc.v_sanity == VTOC_SANE) {
			cmlb_dbg(CMLB_TRACE,  cl,
			    "cmlb_dkio_set_efi: CLEAR VTOC\n");
			if (cl->cl_vtoc_label_is_from_media)
				cmlb_clear_vtoc(cl, tg_cookie);
			bzero(&cl->cl_vtoc, sizeof (struct dk_vtoc));
			mutex_exit(CMLB_MUTEX(cl));
			ddi_remove_minor_node(CMLB_DEVINFO(cl), "h");
			ddi_remove_minor_node(CMLB_DEVINFO(cl), "h,raw");
			(void) cmlb_create_minor(CMLB_DEVINFO(cl), "wd",
			    S_IFBLK,
			    (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
			    cl->cl_node_type, NULL, internal);
			(void) cmlb_create_minor(CMLB_DEVINFO(cl), "wd,raw",
			    S_IFCHR,
			    (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
			    cl->cl_node_type, NULL, internal);
		} else
			mutex_exit(CMLB_MUTEX(cl));

		tgt_lba = user_efi.dki_lba;

		mutex_enter(CMLB_MUTEX(cl));
		if ((cmlb_check_update_blockcount(cl, tg_cookie) != 0) ||
		    (cl->cl_tgt_blocksize == 0)) {
			kmem_free(buffer, user_efi.dki_length);
			mutex_exit(CMLB_MUTEX(cl));
			return (EINVAL);
		}
		if (cl->cl_tgt_blocksize != cl->cl_sys_blocksize)
			tgt_lba = tgt_lba *
			    cl->cl_tgt_blocksize / cl->cl_sys_blocksize;

		mutex_exit(CMLB_MUTEX(cl));
		rval = DK_TG_WRITE(cl, buffer, tgt_lba, user_efi.dki_length,
		    tg_cookie);

		if (rval == 0) {
			mutex_enter(CMLB_MUTEX(cl));
			cl->cl_f_geometry_is_valid = FALSE;
			mutex_exit(CMLB_MUTEX(cl));
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
 *	arg		pointer to user provided mboot structure specifying
 *			the current mboot.
 *
 *	flag		this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0
 *		EINVAL
 *		EFAULT
 *		ENXIO
 */
static int
cmlb_dkio_get_mboot(struct cmlb_lun *cl, caddr_t arg, int flag, void *tg_cookie)
{
	struct mboot	*mboot;
	int		rval;
	size_t		buffer_size;


#if defined(_SUNOS_VTOC_8)
	if ((!ISREMOVABLE(cl) && !ISHOTPLUGGABLE(cl)) || (arg == NULL)) {
#elif defined(_SUNOS_VTOC_16)
	if (arg == NULL) {
#endif
		return (EINVAL);
	}

	/*
	 * Read the mboot block, located at absolute block 0 on the target.
	 */
	buffer_size = sizeof (struct mboot);

	cmlb_dbg(CMLB_TRACE,  cl,
	    "cmlb_dkio_get_mboot: allocation size: 0x%x\n", buffer_size);

	mboot = kmem_zalloc(buffer_size, KM_SLEEP);
	if ((rval = DK_TG_READ(cl, mboot, 0, buffer_size, tg_cookie)) == 0) {
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
 *	arg		pointer to user provided mboot structure used to set the
 *			master boot.
 *
 *	flag		this argument is a pass through to ddi_copyxxx()
 *			directly from the mode argument of ioctl().
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0
 *		EINVAL
 *		EFAULT
 *		ENXIO
 */
static int
cmlb_dkio_set_mboot(struct cmlb_lun *cl, caddr_t arg, int flag, void *tg_cookie)
{
	struct mboot	*mboot = NULL;
	int		rval;
	ushort_t	magic;


	ASSERT(!mutex_owned(CMLB_MUTEX(cl)));

#if defined(_SUNOS_VTOC_8)
	if (!ISREMOVABLE(cl) && !ISHOTPLUGGABLE(cl)) {
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

	rval = DK_TG_WRITE(cl, mboot, 0, cl->cl_sys_blocksize, tg_cookie);

	mutex_enter(CMLB_MUTEX(cl));
#if defined(__i386) || defined(__amd64)
	if (rval == 0) {
		/*
		 * mboot has been written successfully.
		 * update the fdisk and vtoc tables in memory
		 */
		rval = cmlb_update_fdisk_and_vtoc(cl, tg_cookie);
		if ((cl->cl_f_geometry_is_valid == FALSE) || (rval != 0)) {
			mutex_exit(CMLB_MUTEX(cl));
			kmem_free(mboot, (size_t)(sizeof (struct mboot)));
			return (rval);
		}
	}

#ifdef __lock_lint
	cmlb_setup_default_geometry(cl, tg_cookie);
#endif

#else
	if (rval == 0) {
		/*
		 * mboot has been written successfully.
		 * set up the default geometry and VTOC
		 */
		if (cl->cl_blockcount <= DK_MAX_BLOCKS)
			cmlb_setup_default_geometry(cl, tg_cookie);
	}
#endif
	mutex_exit(CMLB_MUTEX(cl));
	kmem_free(mboot, (size_t)(sizeof (struct mboot)));
	return (rval);
}


/*
 *    Function: cmlb_setup_default_geometry
 *
 * Description: This local utility routine sets the default geometry as part of
 *		setting the device mboot.
 *
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 *
 * Note: This may be redundant with cmlb_build_default_label.
 */
static void
cmlb_setup_default_geometry(struct cmlb_lun *cl, void *tg_cookie)
{
	struct cmlb_geom	pgeom;
	struct cmlb_geom	*pgeomp = &pgeom;
	int			ret;
	int			geom_base_cap = 1;


	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	/* zero out the soft state geometry and partition table. */
	bzero(&cl->cl_g, sizeof (struct dk_geom));
	bzero(&cl->cl_vtoc, sizeof (struct dk_vtoc));
	bzero(cl->cl_map, NDKMAP * (sizeof (struct dk_map)));

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
	if (cl->cl_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8) {
		/*
		 * newfs currently can not handle 255 ntracks for SPARC
		 * so get the geometry from target driver instead of coming up
		 * with one based on capacity.
		 */
		mutex_exit(CMLB_MUTEX(cl));
		ret = DK_TG_GETPHYGEOM(cl, pgeomp, tg_cookie);
		mutex_enter(CMLB_MUTEX(cl));

		if (ret  == 0) {
			geom_base_cap = 0;
		} else {
			cmlb_dbg(CMLB_ERROR,  cl,
			    "cmlb_setup_default_geometry: "
			    "tg_getphygeom failed %d\n", ret);

			/* do default setting, geometry based on capacity */
		}
	}

	if (geom_base_cap) {
		if (ISCD(cl)) {
			cl->cl_g.dkg_ncyl = 1;
			cl->cl_g.dkg_nhead = 1;
			cl->cl_g.dkg_nsect = cl->cl_blockcount;
		} else if (cl->cl_blockcount <= 0x1000) {
			/* Needed for unlabeled SCSI floppies. */
			cl->cl_g.dkg_nhead = 2;
			cl->cl_g.dkg_ncyl = 80;
			cl->cl_g.dkg_pcyl = 80;
			cl->cl_g.dkg_nsect = cl->cl_blockcount / (2 * 80);
		} else if (cl->cl_blockcount <= 0x200000) {
			cl->cl_g.dkg_nhead = 64;
			cl->cl_g.dkg_nsect = 32;
			cl->cl_g.dkg_ncyl = cl->cl_blockcount / (64 * 32);
		} else {
			cl->cl_g.dkg_nhead = 255;

			cl->cl_g.dkg_nsect = ((cl->cl_blockcount +
			    (UINT16_MAX * 255 * 63) - 1) /
			    (UINT16_MAX * 255 * 63)) * 63;

			if (cl->cl_g.dkg_nsect == 0)
				cl->cl_g.dkg_nsect = (UINT16_MAX / 63) * 63;

			cl->cl_g.dkg_ncyl = cl->cl_blockcount /
			    (255 * cl->cl_g.dkg_nsect);
		}

		cl->cl_g.dkg_acyl = 0;
		cl->cl_g.dkg_bcyl = 0;
		cl->cl_g.dkg_intrlv = 1;
		cl->cl_g.dkg_rpm = 200;
		if (cl->cl_g.dkg_pcyl == 0)
			cl->cl_g.dkg_pcyl = cl->cl_g.dkg_ncyl +
			    cl->cl_g.dkg_acyl;
	} else {
		cl->cl_g.dkg_ncyl = (short)pgeomp->g_ncyl;
		cl->cl_g.dkg_acyl = pgeomp->g_acyl;
		cl->cl_g.dkg_nhead = pgeomp->g_nhead;
		cl->cl_g.dkg_nsect = pgeomp->g_nsect;
		cl->cl_g.dkg_intrlv = pgeomp->g_intrlv;
		cl->cl_g.dkg_rpm = pgeomp->g_rpm;
		cl->cl_g.dkg_pcyl = cl->cl_g.dkg_ncyl + cl->cl_g.dkg_acyl;
	}

	cl->cl_g.dkg_read_reinstruct = 0;
	cl->cl_g.dkg_write_reinstruct = 0;
	cl->cl_solaris_size = cl->cl_g.dkg_ncyl *
	    cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect;

	cl->cl_map['a'-'a'].dkl_cylno = 0;
	cl->cl_map['a'-'a'].dkl_nblk = cl->cl_solaris_size;

	cl->cl_map['c'-'a'].dkl_cylno = 0;
	cl->cl_map['c'-'a'].dkl_nblk = cl->cl_solaris_size;

	cl->cl_vtoc.v_part[2].p_tag   = V_BACKUP;
	cl->cl_vtoc.v_part[2].p_flag  = V_UNMNT;
	cl->cl_vtoc.v_nparts = V_NUMPAR;
	cl->cl_vtoc.v_version = V_VERSION;
	(void) sprintf((char *)cl->cl_asciilabel, "DEFAULT cyl %d alt %d"
	    " hd %d sec %d", cl->cl_g.dkg_ncyl, cl->cl_g.dkg_acyl,
	    cl->cl_g.dkg_nhead, cl->cl_g.dkg_nsect);

	cl->cl_f_geometry_is_valid = FALSE;
}


#if defined(__i386) || defined(__amd64)
/*
 *    Function: cmlb_update_fdisk_and_vtoc
 *
 * Description: This local utility routine updates the device fdisk and vtoc
 *		as part of setting the device mboot.
 *
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 *
 * Return Code: 0 for success or errno-type return code.
 *
 *    Note:x86: This looks like a duplicate of cmlb_validate_geometry(), but
 *		these did exist separately in x86 sd.c.
 */
static int
cmlb_update_fdisk_and_vtoc(struct cmlb_lun *cl, void *tg_cookie)
{
	int		count;
	int		label_rc = 0;
	int		fdisk_rval;
	diskaddr_t	capacity;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	if (cmlb_check_update_blockcount(cl, tg_cookie) != 0)
		return (EINVAL);

#if defined(_SUNOS_VTOC_16)
	/*
	 * Set up the "whole disk" fdisk partition; this should always
	 * exist, regardless of whether the disk contains an fdisk table
	 * or vtoc.
	 */
	cl->cl_map[P0_RAW_DISK].dkl_cylno = 0;
	cl->cl_map[P0_RAW_DISK].dkl_nblk = cl->cl_blockcount;
#endif	/* defined(_SUNOS_VTOC_16) */

	/*
	 * copy the lbasize and capacity so that if they're
	 * reset while we're not holding the CMLB_MUTEX(cl), we will
	 * continue to use valid values after the CMLB_MUTEX(cl) is
	 * reacquired.
	 */
	capacity = cl->cl_blockcount;

	/*
	 * refresh the logical and physical geometry caches.
	 * (data from mode sense format/rigid disk geometry pages,
	 * and scsi_ifgetcap("geometry").
	 */
	cmlb_resync_geom_caches(cl, capacity, tg_cookie);

	/*
	 * Only DIRECT ACCESS devices will have Scl labels.
	 * CD's supposedly have a Scl label, too
	 */
	if (cl->cl_device_type == DTYPE_DIRECT || ISREMOVABLE(cl)) {
		fdisk_rval = cmlb_read_fdisk(cl, capacity, tg_cookie);
		if (fdisk_rval != 0) {
			ASSERT(mutex_owned(CMLB_MUTEX(cl)));
			return (fdisk_rval);
		}

		if (cl->cl_solaris_size <= DK_LABEL_LOC) {
			/*
			 * Found fdisk table but no Solaris partition entry,
			 * so don't call cmlb_uselabel() and don't create
			 * a default label.
			 */
			label_rc = 0;
			cl->cl_f_geometry_is_valid = TRUE;
			goto no_solaris_partition;
		}
	} else if (capacity < 0) {
		ASSERT(mutex_owned(CMLB_MUTEX(cl)));
		return (EINVAL);
	}

	/*
	 * For Removable media We reach here if we have found a
	 * SOLARIS PARTITION.
	 * If cl_f_geometry_is_valid is FALSE it indicates that the SOLARIS
	 * PARTITION has changed from the previous one, hence we will setup a
	 * default VTOC in this case.
	 */
	if (cl->cl_f_geometry_is_valid == FALSE) {
		/* if we get here it is writable */
		/* we are called from SMBOOT, and after a write of fdisk */
		cmlb_build_default_label(cl, tg_cookie);
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
		cl->cl_map[FDISK_P1 + count].dkl_cylno = -1;
		cl->cl_map[FDISK_P1 + count].dkl_nblk =
		    cl->cl_fmap[count].fmap_nblk;
		cl->cl_offset[FDISK_P1 + count] =
		    cl->cl_fmap[count].fmap_start;
	}
#endif

	for (count = 0; count < NDKMAP; count++) {
#if defined(_SUNOS_VTOC_8)
		struct dk_map *lp  = &cl->cl_map[count];
		cl->cl_offset[count] =
		    cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect * lp->dkl_cylno;
#elif defined(_SUNOS_VTOC_16)
		struct dkl_partition *vp = &cl->cl_vtoc.v_part[count];
		cl->cl_offset[count] = vp->p_start + cl->cl_solaris_offset;
#else
#error "No VTOC format defined."
#endif
	}

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));
	return (label_rc);
}
#endif

#if defined(__i386) || defined(__amd64)
static int
cmlb_dkio_get_virtgeom(struct cmlb_lun *cl, caddr_t arg, int flag)
{
	int err = 0;

	/* Return the driver's notion of the media's logical geometry */
	struct dk_geom	disk_geom;
	struct dk_geom	*dkgp = &disk_geom;

	mutex_enter(CMLB_MUTEX(cl));
	/*
	 * If there is no HBA geometry available, or
	 * if the HBA returned us something that doesn't
	 * really fit into an Int 13/function 8 geometry
	 * result, just fail the ioctl.  See PSARC 1998/313.
	 */
	if (cl->cl_lgeom.g_nhead == 0 ||
	    cl->cl_lgeom.g_nsect == 0 ||
	    cl->cl_lgeom.g_ncyl > 1024) {
		mutex_exit(CMLB_MUTEX(cl));
		err = EINVAL;
	} else {
		dkgp->dkg_ncyl	= cl->cl_lgeom.g_ncyl;
		dkgp->dkg_acyl	= cl->cl_lgeom.g_acyl;
		dkgp->dkg_pcyl	= dkgp->dkg_ncyl + dkgp->dkg_acyl;
		dkgp->dkg_nhead	= cl->cl_lgeom.g_nhead;
		dkgp->dkg_nsect	= cl->cl_lgeom.g_nsect;

		mutex_exit(CMLB_MUTEX(cl));
		if (ddi_copyout(dkgp, (void *)arg,
		    sizeof (struct dk_geom), flag)) {
			err = EFAULT;
		} else {
			err = 0;
		}
	}
	return (err);
}
#endif

#if defined(__i386) || defined(__amd64)
static int
cmlb_dkio_get_phygeom(struct cmlb_lun *cl, caddr_t  arg, int flag)
{
	int err = 0;
	diskaddr_t capacity;


	/* Return the driver's notion of the media physical geometry */
	struct dk_geom	disk_geom;
	struct dk_geom	*dkgp = &disk_geom;

	mutex_enter(CMLB_MUTEX(cl));

	if (cl->cl_g.dkg_nhead != 0 &&
	    cl->cl_g.dkg_nsect != 0) {
		/*
		 * We succeeded in getting a geometry, but
		 * right now it is being reported as just the
		 * Solaris fdisk partition, just like for
		 * DKIOCGGEOM. We need to change that to be
		 * correct for the entire disk now.
		 */
		bcopy(&cl->cl_g, dkgp, sizeof (*dkgp));
		dkgp->dkg_acyl = 0;
		dkgp->dkg_ncyl = cl->cl_blockcount /
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
		if (ISCD(cl)) {
			dkgp->dkg_nhead = cl->cl_pgeom.g_nhead;
			dkgp->dkg_nsect = cl->cl_pgeom.g_nsect;
			dkgp->dkg_ncyl = cl->cl_pgeom.g_ncyl;
			dkgp->dkg_acyl = cl->cl_pgeom.g_acyl;
		} else {
			/*
			 * Invalid cl_blockcount can generate invalid
			 * dk_geom and may result in division by zero
			 * system failure. Should make sure blockcount
			 * is valid before using it here.
			 */
			if (cl->cl_blockcount == 0) {
				mutex_exit(CMLB_MUTEX(cl));
				err = EIO;
				return (err);
			}
			/*
			 * Refer to comments related to off-by-1 at the
			 * header of this file
			 */
			if (cl->cl_alter_behavior & CMLB_OFF_BY_ONE)
				capacity = cl->cl_blockcount - 1;
			else
				capacity = cl->cl_blockcount;

			cmlb_convert_geometry(capacity, dkgp);
			dkgp->dkg_acyl = 0;
			dkgp->dkg_ncyl = capacity /
			    (dkgp->dkg_nhead * dkgp->dkg_nsect);
		}
	}
	dkgp->dkg_pcyl = dkgp->dkg_ncyl + dkgp->dkg_acyl;

	mutex_exit(CMLB_MUTEX(cl));
	if (ddi_copyout(dkgp, (void *)arg, sizeof (struct dk_geom), flag))
		err = EFAULT;

	return (err);
}
#endif

#if defined(__i386) || defined(__amd64)
static int
cmlb_dkio_partinfo(struct cmlb_lun *cl, dev_t dev, caddr_t  arg, int flag)
{
	int err = 0;

	/*
	 * Return parameters describing the selected disk slice.
	 * Note: this ioctl is for the intel platform only
	 */
	int part;

	part = CMLBPART(dev);

	mutex_enter(CMLB_MUTEX(cl));
	/* don't check cl_solaris_size for pN */
	if (part < P0_RAW_DISK && cl->cl_solaris_size == 0) {
		err = EIO;
		mutex_exit(CMLB_MUTEX(cl));
	} else {
		struct part_info p;

		p.p_start = (daddr_t)cl->cl_offset[part];
		p.p_length = (int)cl->cl_map[part].dkl_nblk;
		mutex_exit(CMLB_MUTEX(cl));
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
