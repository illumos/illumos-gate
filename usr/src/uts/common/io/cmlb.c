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
 * Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#if defined(__i386) || defined(__amd64)
#include <sys/fs/dv_node.h>
#endif
#include <sys/ddi_impldefs.h>

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

#if defined(__i386) || defined(__amd64)
#if defined(_FIRMWARE_NEEDS_FDISK)
static struct driver_minor_data dk_ext_minor_data[] = {
	{"p5", 21, S_IFBLK},
	{"p6", 22, S_IFBLK},
	{"p7", 23, S_IFBLK},
	{"p8", 24, S_IFBLK},
	{"p9", 25, S_IFBLK},
	{"p10", 26, S_IFBLK},
	{"p11", 27, S_IFBLK},
	{"p12", 28, S_IFBLK},
	{"p13", 29, S_IFBLK},
	{"p14", 30, S_IFBLK},
	{"p15", 31, S_IFBLK},
	{"p16", 32, S_IFBLK},
	{"p17", 33, S_IFBLK},
	{"p18", 34, S_IFBLK},
	{"p19", 35, S_IFBLK},
	{"p20", 36, S_IFBLK},
	{"p21", 37, S_IFBLK},
	{"p22", 38, S_IFBLK},
	{"p23", 39, S_IFBLK},
	{"p24", 40, S_IFBLK},
	{"p25", 41, S_IFBLK},
	{"p26", 42, S_IFBLK},
	{"p27", 43, S_IFBLK},
	{"p28", 44, S_IFBLK},
	{"p29", 45, S_IFBLK},
	{"p30", 46, S_IFBLK},
	{"p31", 47, S_IFBLK},
	{"p32", 48, S_IFBLK},
	{"p33", 49, S_IFBLK},
	{"p34", 50, S_IFBLK},
	{"p35", 51, S_IFBLK},
	{"p36", 52, S_IFBLK},
	{"p5,raw", 21, S_IFCHR},
	{"p6,raw", 22, S_IFCHR},
	{"p7,raw", 23, S_IFCHR},
	{"p8,raw", 24, S_IFCHR},
	{"p9,raw", 25, S_IFCHR},
	{"p10,raw", 26, S_IFCHR},
	{"p11,raw", 27, S_IFCHR},
	{"p12,raw", 28, S_IFCHR},
	{"p13,raw", 29, S_IFCHR},
	{"p14,raw", 30, S_IFCHR},
	{"p15,raw", 31, S_IFCHR},
	{"p16,raw", 32, S_IFCHR},
	{"p17,raw", 33, S_IFCHR},
	{"p18,raw", 34, S_IFCHR},
	{"p19,raw", 35, S_IFCHR},
	{"p20,raw", 36, S_IFCHR},
	{"p21,raw", 37, S_IFCHR},
	{"p22,raw", 38, S_IFCHR},
	{"p23,raw", 39, S_IFCHR},
	{"p24,raw", 40, S_IFCHR},
	{"p25,raw", 41, S_IFCHR},
	{"p26,raw", 42, S_IFCHR},
	{"p27,raw", 43, S_IFCHR},
	{"p28,raw", 44, S_IFCHR},
	{"p29,raw", 45, S_IFCHR},
	{"p30,raw", 46, S_IFCHR},
	{"p31,raw", 47, S_IFCHR},
	{"p32,raw", 48, S_IFCHR},
	{"p33,raw", 49, S_IFCHR},
	{"p34,raw", 50, S_IFCHR},
	{"p35,raw", 51, S_IFCHR},
	{"p36,raw", 52, S_IFCHR},
	{0}
};
#endif			/* defined(_FIRMWARE_NEEDS_FDISK) */
#endif			/* if defined(__i386) || defined(__amd64) */

static struct driver_minor_data dk_minor_data_efi[] = {
	{"a", 0, S_IFBLK},
	{"b", 1, S_IFBLK},
	{"c", 2, S_IFBLK},
	{"d", 3, S_IFBLK},
	{"e", 4, S_IFBLK},
	{"f", 5, S_IFBLK},
	{"g", 6, S_IFBLK},
	{"wd", 7, S_IFBLK},
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
	{"wd,raw", 7, S_IFCHR},
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

/*
 * Declare the dynamic properties implemented in prop_op(9E) implementation
 * that we want to have show up in a di_init(3DEVINFO) device tree snapshot
 * of drivers that call cmlb_attach().
 */
static i_ddi_prop_dyn_t cmlb_prop_dyn[] = {
	{"Nblocks",		DDI_PROP_TYPE_INT64,	S_IFBLK},
	{"Size",		DDI_PROP_TYPE_INT64,	S_IFCHR},
	{"device-nblocks",	DDI_PROP_TYPE_INT64},
	{"device-blksize",	DDI_PROP_TYPE_INT},
	{"device-solid-state",	DDI_PROP_TYPE_INT},
	{NULL}
};

/*
 * This implies an upper limit of 8192 GPT partitions
 * in one transfer for GUID Partition Entry Array.
 */
len_t cmlb_tg_max_efi_xfer = 1024 * 1024;

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
	"Common Labeling module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

/* Local function prototypes */
static dev_t cmlb_make_device(struct cmlb_lun *cl);
static int cmlb_validate_geometry(struct cmlb_lun *cl, boolean_t forcerevalid,
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
static boolean_t cmlb_check_efi_mbr(uchar_t *buf, boolean_t *is_mbr);

#if defined(__i386) || defined(__amd64)
static int cmlb_update_fdisk_and_vtoc(struct cmlb_lun *cl, void *tg_cookie);
#endif

#if defined(_FIRMWARE_NEEDS_FDISK)
static boolean_t  cmlb_has_max_chs_vals(struct ipart *fdp);
#endif

#if defined(_SUNOS_VTOC_16)
static void cmlb_convert_geometry(struct cmlb_lun *cl, diskaddr_t capacity,
    struct dk_geom *cl_g, void *tg_cookie);
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
static int cmlb_dkio_get_extvtoc(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_set_vtoc(struct cmlb_lun *cl, dev_t dev, caddr_t arg,
    int flag, void *tg_cookie);
static int cmlb_dkio_set_extvtoc(struct cmlb_lun *cl, dev_t dev, caddr_t arg,
    int flag, void *tg_cookie);
static int cmlb_dkio_get_mboot(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_set_mboot(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_partition(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);

#if defined(__i386) || defined(__amd64)
static int cmlb_dkio_set_ext_part(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie);
static int cmlb_validate_ext_part(struct cmlb_lun *cl, int part, int epart,
    uint32_t start, uint32_t size);
static int cmlb_is_linux_swap(struct cmlb_lun *cl, uint32_t part_start,
    void *tg_cookie);
static int cmlb_dkio_get_virtgeom(struct cmlb_lun *cl, caddr_t arg, int flag);
static int cmlb_dkio_get_phygeom(struct cmlb_lun *cl, caddr_t  arg, int flag,
    void *tg_cookie);
static int cmlb_dkio_partinfo(struct cmlb_lun *cl, dev_t dev, caddr_t arg,
    int flag);
static int cmlb_dkio_extpartinfo(struct cmlb_lun *cl, dev_t dev, caddr_t arg,
    int flag);
#endif

static void cmlb_dbg(uint_t comp, struct cmlb_lun *cl, const char *fmt, ...);
static void cmlb_v_log(dev_info_t *dev, const char *label, uint_t level,
    const char *fmt, va_list ap);
static void cmlb_log(dev_info_t *dev, const char *label, uint_t level,
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
cmlb_log(dev_info_t *dev, const char *label, uint_t level, const char *fmt, ...)
{
	va_list		ap;

	va_start(ap, fmt);
	cmlb_v_log(dev, label, level, fmt, ap);
	va_end(ap);
}

static void
cmlb_v_log(dev_info_t *dev, const char *label, uint_t level, const char *fmt,
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
 *
 *	is_hotpluggable	whether or not device is hotpluggable.
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
 *			   to cross over the limits in geometry calculation,
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
    boolean_t is_removable, boolean_t is_hotpluggable, char *node_type,
    int alter_behavior, cmlb_handle_t cmlbhandle, void *tg_cookie)
{

	struct cmlb_lun	*cl = (struct cmlb_lun *)cmlbhandle;
	diskaddr_t	cap;
	int		status;

	ASSERT(VALID_BOOLEAN(is_removable));
	ASSERT(VALID_BOOLEAN(is_hotpluggable));

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
	cl->cl_f_geometry_is_valid = B_FALSE;
	cl->cl_def_labeltype = CMLB_LABEL_VTOC;
	cl->cl_alter_behavior = alter_behavior;
	cl->cl_reserved = -1;
	cl->cl_msglog_flag |= CMLB_ALLOW_2TB_WARN;
#if defined(__i386) || defined(__amd64)
	cl->cl_logical_drive_count = 0;
#endif

	if (!is_removable) {
		mutex_exit(CMLB_MUTEX(cl));
		status = DK_TG_GETCAP(cl, &cap, tg_cookie);
		mutex_enter(CMLB_MUTEX(cl));
		if (status == 0 && cap > CMLB_EXTVTOC_LIMIT) {
			/* set default EFI if > 2TB */
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

	/* Define the dynamic properties for devinfo spapshots. */
	i_ddi_prop_dyn_driver_set(CMLB_DEVINFO(cl), cmlb_prop_dyn);

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
	cl->cl_f_geometry_is_valid = B_FALSE;
	ddi_remove_minor_node(CMLB_DEVINFO(cl), NULL);
	i_ddi_prop_dyn_driver_set(CMLB_DEVINFO(cl), NULL);
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

	rval = cmlb_validate_geometry((struct cmlb_lun *)cmlbhandle, B_TRUE,
	    flags, tg_cookie);

	if (rval == ENOTSUP) {
		if (cl->cl_f_geometry_is_valid) {
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
	cl->cl_f_geometry_is_valid = B_FALSE;
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
 *	B_TRUE if incore label/geom data is valid.
 *	B_FALSE otherwise.
 *
 */


boolean_t
cmlb_is_valid(cmlb_handle_t cmlbhandle)
{
	struct cmlb_lun *cl = (struct cmlb_lun *)cmlbhandle;

	if (cmlbhandle == NULL)
		return (B_FALSE);

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
	cl->cl_f_geometry_is_valid = B_FALSE;

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

	if ((!cl->cl_f_geometry_is_valid) ||
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
		if (cl->cl_label_from_media != CMLB_LABEL_VTOC) {
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
#if defined(__i386) || defined(__amd64)
	int ext_part;
#endif

	ASSERT(cl != NULL);
	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}

	if (part  < 0 || part >= MAXPART) {
		rval = EINVAL;
	} else {
		if (!cl->cl_f_geometry_is_valid)
			(void) cmlb_validate_geometry((struct cmlb_lun *)cl,
			    B_FALSE, 0, tg_cookie);

#if defined(_SUNOS_VTOC_16)
		if (((!cl->cl_f_geometry_is_valid) ||
		    (part < NDKMAP && cl->cl_solaris_size == 0)) &&
		    (part != P0_RAW_DISK)) {
#else
		if ((!cl->cl_f_geometry_is_valid) ||
		    (part < NDKMAP && cl->cl_solaris_size == 0)) {
#endif
			rval = EINVAL;
		} else {
			if (startblockp != NULL)
				*startblockp = (diskaddr_t)cl->cl_offset[part];

			if (nblocksp != NULL)
				*nblocksp = (diskaddr_t)
				    cl->cl_map[part].dkl_nblk;

			if (tagp != NULL)
				*tagp =
				    ((cl->cl_cur_labeltype == CMLB_LABEL_EFI) ||
				    (part >= NDKMAP)) ? V_UNASSIGNED :
				    cl->cl_vtoc.v_part[part].p_tag;
			rval = 0;
		}

		/* consistent with behavior of sd for getting minor name */
		if (partnamep != NULL) {
#if defined(__i386) || defined(__amd64)
#if defined(_FIRMWARE_NEEDS_FDISK)
		if (part > FDISK_P4) {
			ext_part = part-FDISK_P4-1;
			*partnamep = dk_ext_minor_data[ext_part].name;
		} else
#endif
#endif
			*partnamep = dk_minor_data[part].name;
		}

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

	if (!cl->cl_f_geometry_is_valid)
		(void) cmlb_validate_geometry((struct cmlb_lun *)cl, B_FALSE,
		    0, tg_cookie);

	if ((!cl->cl_f_geometry_is_valid) || (capacity == NULL) ||
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

	cl = (struct cmlb_lun *)cmlbhandle;

	ASSERT(cl != NULL);

	mutex_enter(CMLB_MUTEX(cl));
	if (cl->cl_state < CMLB_ATTACHED) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EIO);
	}

	switch (cmd) {
		case DKIOCSEXTVTOC:
		case DKIOCSGEOM:
		case DKIOCSETEFI:
		case DKIOCSMBOOT:
#if defined(__i386) || defined(__amd64)
		case DKIOCSETEXTPART:
#endif
			break;
		case DKIOCSVTOC:
#if defined(__i386) || defined(__amd64)
		case DKIOCPARTINFO:
#endif
			if (cl->cl_blockcount > CMLB_OLDVTOC_LIMIT) {
				mutex_exit(CMLB_MUTEX(cl));
				return (EOVERFLOW);
			}
			break;
		default:
			(void) cmlb_validate_geometry(cl, 1, CMLB_SILENT,
			    tg_cookie);

			switch (cmd) {
			case DKIOCGVTOC:
			case DKIOCGAPART:
			case DKIOCSAPART:

				if (cl->cl_label_from_media == CMLB_LABEL_EFI) {
					/* GPT label on disk */
					mutex_exit(CMLB_MUTEX(cl));
					return (ENOTSUP);
				} else if
				    (cl->cl_blockcount > CMLB_OLDVTOC_LIMIT) {
					mutex_exit(CMLB_MUTEX(cl));
					return (EOVERFLOW);
				}
				break;

			case DKIOCGGEOM:
				if (cl->cl_label_from_media == CMLB_LABEL_EFI) {
					/* GPT label on disk */
					mutex_exit(CMLB_MUTEX(cl));
					return (ENOTSUP);
				}
				break;
			default:
				break;
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

	case DKIOCGEXTVTOC:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCGVTOC\n");
		err = cmlb_dkio_get_extvtoc(cl, (caddr_t)arg, flag, tg_cookie);
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

	case DKIOCSEXTVTOC:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCSVTOC\n");
		err = cmlb_dkio_set_extvtoc(cl, dev, (caddr_t)arg, flag,
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
		err = cmlb_dkio_get_phygeom(cl, (caddr_t)arg, flag, tg_cookie);
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
	case DKIOCEXTPARTINFO:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCPARTINFO");
#if defined(__i386) || defined(__amd64)
		err = cmlb_dkio_extpartinfo(cl, dev, (caddr_t)arg, flag);
#else
		err = ENOTTY;
#endif
		break;
#if defined(__i386) || defined(__amd64)
	case DKIOCSETEXTPART:
		cmlb_dbg(CMLB_TRACE, cl, "DKIOCSETEXTPART");
		err = cmlb_dkio_set_ext_part(cl, (caddr_t)arg, flag, tg_cookie);
		break;
#endif
	default:
		err = ENOTTY;

	}

	/*
	 * An ioctl that succeeds and changed ('set') size(9P) information
	 * needs to invalidate the cached devinfo snapshot to avoid having
	 * old information being returned in a snapshots.
	 *
	 * NB: When available, call ddi_change_minor_node() to clear
	 * SSIZEVALID in specfs vnodes via spec_size_invalidate().
	 */
	if (err == 0) {
		switch (cmd) {
		case DKIOCSGEOM:
		case DKIOCSAPART:
		case DKIOCSVTOC:
		case DKIOCSEXTVTOC:
		case DKIOCSETEFI:
			i_ddi_prop_dyn_cache_invalidate(CMLB_DEVINFO(cl),
			    i_ddi_prop_dyn_driver_get(CMLB_DEVINFO(cl)));
		}
	}
	return (err);
}

dev_t
cmlb_make_device(struct cmlb_lun *cl)
{
	return (makedevice(ddi_driver_major(CMLB_DEVINFO(cl)),
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

	if (cl->cl_f_geometry_is_valid)
		return (0);

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
		if (!cl->cl_is_removable) {
			cl->cl_sys_blocksize = lbasize;
		}
		return (0);
	} else {
		return (EIO);
	}
}

static int
cmlb_create_minor(dev_info_t *dip, char *name, int spec_type,
    minor_t minor_num, char *node_type, int flag, boolean_t internal)
{
	ASSERT(VALID_BOOLEAN(internal));

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

	internal = VOID2BOOLEAN(
	    (cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);

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
cmlb_validate_geometry(struct cmlb_lun *cl, boolean_t forcerevalid, int flags,
    void *tg_cookie)
{
	int		label_error = 0;
	diskaddr_t	capacity;
	int		count;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));
	ASSERT(VALID_BOOLEAN(forcerevalid));

	if ((cl->cl_f_geometry_is_valid) && (!forcerevalid)) {
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
	cl->cl_offset[P0_RAW_DISK] = 0;
	/*
	 * note if capacity > int32_max(1TB) we are in 64bit environment
	 * so no truncation happens
	 */
	cl->cl_map[P0_RAW_DISK].dkl_nblk  = capacity;
#endif
	/*
	 * Refresh the logical and physical geometry caches.
	 * (data from MODE SENSE format/rigid disk geometry pages,
	 * and scsi_ifgetcap("geometry").
	 */
	cmlb_resync_geom_caches(cl, capacity, tg_cookie);

	cl->cl_label_from_media = CMLB_LABEL_UNDEF;
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

	if (capacity > CMLB_EXTVTOC_LIMIT) {
		if (label_error == ESRCH) {
			/*
			 * they've configured a LUN over 2TB, but used
			 * format.dat to restrict format's view of the
			 * capacity to be under 2TB in some earlier Solaris
			 * release.
			 */
			/* i.e > 2TB with a VTOC < 2TB */
			if (!(flags & CMLB_SILENT) &&
			    (cl->cl_msglog_flag & CMLB_ALLOW_2TB_WARN)) {

				cmlb_log(CMLB_DEVINFO(cl), CMLB_LABEL(cl),
				    CE_NOTE, "!Disk (%s%d) is limited to 2 TB "
				    "due to VTOC label. To use the full "
				    "capacity of the disk, use format(1M) to "
				    "relabel the disk with EFI/GPT label.\n",
				    CMLB_LABEL(cl),
				    ddi_get_instance(CMLB_DEVINFO(cl)));

				cl->cl_msglog_flag &= ~CMLB_ALLOW_2TB_WARN;
			}
		} else {
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
			/*
			 * Found fdisk table but no Solaris partition entry,
			 * so don't call cmlb_uselabel() and don't create
			 * a default label.
			 */
			label_error = 0;
			cl->cl_f_geometry_is_valid = B_TRUE;
			goto no_solaris_partition;
		}

		label_addr = (daddr_t)(cl->cl_solaris_offset + DK_LABEL_LOC);

		buffer_size = cl->cl_sys_blocksize;

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
				cl->cl_label_from_media = CMLB_LABEL_VTOC;
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
		if (!cl->cl_f_geometry_is_valid) {
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
	for (count = 0; count < FDISK_PARTS; count++) {
		cl->cl_map[FDISK_P1 + count].dkl_cylno = UINT16_MAX;
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
 *    Function: cmlb_convert_geometry
 *
 * Description: Convert physical geometry into a dk_geom structure. In
 *		other words, make sure we don't wrap 16-bit values.
 *		e.g. converting from geom_cache to dk_geom
 *
 *     Context: Kernel thread only
 */
static void
cmlb_convert_geometry(struct cmlb_lun *cl, diskaddr_t capacity,
    struct dk_geom *cl_g, void *tg_cookie)
{

	ASSERT(cl != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	/* Unlabeled SCSI floppy device */
	if (capacity < 160) {
		/* Less than 80K */
		cl_g->dkg_nhead = 1;
		cl_g->dkg_ncyl = capacity;
		cl_g->dkg_nsect = 1;
		return;
	} else if (capacity <= 0x1000) {
		cl_g->dkg_nhead = 2;
		cl_g->dkg_ncyl = 80;
		cl_g->dkg_nsect = capacity / (cl_g->dkg_nhead * cl_g->dkg_ncyl);
		return;
	}

	/*
	 * For all devices we calculate cylinders using the heads and sectors
	 * we assign based on capacity of the device.  The algorithm is
	 * designed to be compatible with the way other operating systems
	 * lay out fdisk tables for X86 and to insure that the cylinders never
	 * exceed 65535 to prevent problems with X86 ioctls that report
	 * geometry.
	 * For some smaller disk sizes we report geometry that matches those
	 * used by X86 BIOS usage. For larger disks, we use SPT that are
	 * multiples of 63, since other OSes that are not limited to 16-bits
	 * for cylinders stop at 63 SPT we make do by using multiples of 63 SPT.
	 *
	 * The following table (in order) illustrates some end result
	 * calculations:
	 *
	 * Maximum number of blocks 		nhead	nsect
	 *
	 * 2097152 (1GB)			64	32
	 * 16777216 (8GB)			128	32
	 * 1052819775 (502.02GB)		255  	63
	 * 2105639550 (0.98TB)			255	126
	 * 3158459325 (1.47TB)			255  	189
	 * 4211279100 (1.96TB)			255  	252
	 * 5264098875 (2.45TB)			255  	315
	 * ...
	 *
	 * For Solid State Drive(SSD), it uses 4K page size inside and may be
	 * double with every new generation. If the I/O is not aligned with
	 * page size on SSDs, SSDs perform a lot slower.
	 * By default, Solaris partition starts from cylinder 1. It will be
	 * misaligned even with 4K if using heads(255) and SPT(63). To
	 * workaround the problem, if the device is SSD, we use heads(224) and
	 * SPT multiple of 56. Thus the default Solaris partition starts from
	 * a position that aligns with 128K on a 512 bytes sector size SSD.
	 */

	if (capacity <= 0x200000) {
		cl_g->dkg_nhead = 64;
		cl_g->dkg_nsect = 32;
	} else if (capacity <= 0x01000000) {
		cl_g->dkg_nhead = 128;
		cl_g->dkg_nsect = 32;
	} else {
		tg_attribute_t tgattribute;
		int is_solid_state;
		unsigned short nhead;
		unsigned short nsect;

		bzero(&tgattribute, sizeof (tg_attribute_t));

		mutex_exit(CMLB_MUTEX(cl));
		is_solid_state =
		    (DK_TG_GETATTRIBUTE(cl, &tgattribute, tg_cookie) == 0) ?
		    tgattribute.media_is_solid_state : FALSE;
		mutex_enter(CMLB_MUTEX(cl));

		if (is_solid_state) {
			nhead = 224;
			nsect = 56;
		} else {
			nhead = 255;
			nsect = 63;
		}

		cl_g->dkg_nhead = nhead;

		/* make dkg_nsect be smallest multiple of nsect */
		cl_g->dkg_nsect = ((capacity +
		    (UINT16_MAX * nhead * nsect) - 1) /
		    (UINT16_MAX * nhead * nsect)) * nsect;

		if (cl_g->dkg_nsect == 0)
			cl_g->dkg_nsect = (UINT16_MAX / nsect) * nsect;
	}

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
	if (spc == 0)
		pgeomp->g_ncyl = 0;
	else
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


#if defined(__i386) || defined(__amd64)
/*
 *    Function: cmlb_update_ext_minor_nodes
 *
 * Description: Routine to add/remove extended partition device nodes
 *
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *	num_parts	Number of logical drives found on the LUN
 *
 * Should be called with the mutex held
 *
 * Return Code: 0 for success
 *
 *     Context: User and Kernel thread
 *
 */
static int
cmlb_update_ext_minor_nodes(struct cmlb_lun *cl, int num_parts)
{
	int				i, count;
	char				name[48];
	int				instance;
	struct driver_minor_data	*demdp, *demdpr;
	char				*devnm;
	dev_info_t			*pdip;
	boolean_t 			internal;

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));
	ASSERT(cl->cl_update_ext_minor_nodes == 1);

	internal = VOID2BOOLEAN(
	    (cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);
	instance = ddi_get_instance(CMLB_DEVINFO(cl));
	demdp = dk_ext_minor_data;
	demdpr = &dk_ext_minor_data[MAX_EXT_PARTS];


	if (cl->cl_logical_drive_count) {
		for (i = 0; i < cl->cl_logical_drive_count; i++) {
			(void) sprintf(name, "%s", demdp->name);
			ddi_remove_minor_node(CMLB_DEVINFO(cl), name);
			(void) sprintf(name, "%s", demdpr->name);
			ddi_remove_minor_node(CMLB_DEVINFO(cl), name);
			demdp++;
			demdpr++;
		}
		/* There are existing device nodes. Remove them */
		devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
		(void) ddi_deviname(cl->cl_devi, devnm);
		pdip = ddi_get_parent(cl->cl_devi);
		(void) devfs_clean(pdip, devnm + 1, DV_CLEAN_FORCE);
		kmem_free(devnm, MAXNAMELEN + 1);
	}

	demdp = dk_ext_minor_data;
	demdpr = &dk_ext_minor_data[MAX_EXT_PARTS];

	for (i = 0; i < num_parts; i++) {
		(void) sprintf(name, "%s", demdp->name);
		if (cmlb_create_minor(CMLB_DEVINFO(cl), name,
		    demdp->type,
		    (instance << CMLBUNIT_SHIFT) | demdp->minor,
		    cl->cl_node_type, NULL, internal) == DDI_FAILURE) {
			/*
			 * Clean up any nodes that may have been
			 * created, in case this fails in the middle
			 * of the loop.
			 */
			ddi_remove_minor_node(CMLB_DEVINFO(cl), NULL);
			cl->cl_logical_drive_count = 0;
			return (ENXIO);
		}
		(void) sprintf(name, "%s", demdpr->name);
		if (ddi_create_minor_node(CMLB_DEVINFO(cl), name,
		    demdpr->type,
		    (instance << CMLBUNIT_SHIFT) | demdpr->minor,
		    cl->cl_node_type, NULL) == DDI_FAILURE) {
			/*
			 * Clean up any nodes that may have been
			 * created, in case this fails in the middle
			 * of the loop.
			 */
			ddi_remove_minor_node(CMLB_DEVINFO(cl), NULL);
			cl->cl_logical_drive_count = 0;
			return (ENXIO);
		}
		demdp++;
		demdpr++;
	}

	/* Update the cl_map array for logical drives */
	for (count = 0; count < MAX_EXT_PARTS; count++) {
		cl->cl_map[FDISK_P4 + 1 + count].dkl_cylno = UINT32_MAX;
		cl->cl_map[FDISK_P4 + 1 + count].dkl_nblk =
		    cl->cl_fmap[FD_NUMPART + count].fmap_nblk;
		cl->cl_offset[FDISK_P4 + 1 + count] =
		    cl->cl_fmap[FD_NUMPART + count].fmap_start;
	}

	cl->cl_logical_drive_count = i;
	cl->cl_update_ext_minor_nodes = 0;
	return (0);
}
/*
 *    Function: cmlb_validate_ext_part
 *
 * Description: utility routine to validate an extended partition's
 *		metadata as found on disk
 *
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *	part		partition number of the extended partition
 *	epart		partition number of the logical drive
 *	start		absolute sector number of the start of the logical
 *			drive being validated
 *	size		size of logical drive being validated
 *
 * Return Code: 0 for success
 *
 *     Context: User and Kernel thread
 *
 * Algorithm :
 * Error cases are :
 *	1. If start block is lesser than or equal to the end block
 *	2. If either start block or end block is beyond the bounadry
 *	   of the extended partition.
 *	3. start or end block overlap with existing partitions.
 *		To check this, first make sure that the start block doesnt
 *		overlap with existing partitions. Then, calculate the
 *		possible end block for the given start block that doesnt
 *		overlap with existing partitions. This can be calculated by
 *		first setting the possible end block to the end of the
 *		extended partition (optimistic) and then, checking if there
 *		is any other partition that lies after the start of the
 *		partition being validated. If so, set the possible end to
 *		one block less than the beginning of the next nearest partition
 *		If the actual end block is greater than the calculated end
 *		block, we have an overlap.
 *
 */
static int
cmlb_validate_ext_part(struct cmlb_lun *cl, int part, int epart, uint32_t start,
    uint32_t size)
{
	int i;
	uint32_t end = start + size - 1;
	uint32_t ext_start = cl->cl_fmap[part].fmap_start;
	uint32_t ext_end = ext_start + cl->cl_fmap[part].fmap_nblk - 1;
	uint32_t ts, te;
	uint32_t poss_end = ext_end;

	if (end <= start) {
		return (1);
	}

	/*
	 * Check if the logical drive boundaries are within that of the
	 * extended partition.
	 */
	if (start <= ext_start || start > ext_end || end <= ext_start ||
	    end > ext_end) {
		return (1);
	}

	/*
	 * epart will be equal to FD_NUMPART if it is the first logical drive.
	 * There is no need to check for overlaps with other logical drives,
	 * since it is the only logical drive that we have come across so far.
	 */
	if (epart == FD_NUMPART) {
		return (0);
	}

	/* Check for overlaps with existing logical drives */
	i = FD_NUMPART;
	ts = cl->cl_fmap[FD_NUMPART].fmap_start;
	te = ts + cl->cl_fmap[FD_NUMPART].fmap_nblk - 1;

	while ((i < epart) && ts && te) {
		if (start >= ts && start <= te) {
			return (1);
		}

		if ((ts < poss_end) && (ts > start)) {
			poss_end = ts - 1;
		}

		i++;
		ts = cl->cl_fmap[i].fmap_start;
		te = ts + cl->cl_fmap[i].fmap_nblk - 1;
	}

	if (end > poss_end) {
		return (1);
	}

	return (0);
}


/*
 *    Function: cmlb_is_linux_swap
 *
 * Description: utility routine to verify if a partition is a linux swap
 *		partition or not.
 *
 *   Arguments:
 *	cl		driver soft state (unit) structure
 *	part_start	absolute sector number of the start of the partition
 *			being verified
 *	tg_cookie	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Return Code: 0 for success
 *
 *     Context: User and Kernel thread
 *
 * Notes:
 *	The linux swap magic "SWAP-SPACE" or "SWAPSPACE2" is found as the
 *	last 10 bytes of a disk block whose size is that of the linux page
 *	size. This disk block is found at the beginning of the swap partition.
 */
static int
cmlb_is_linux_swap(struct cmlb_lun *cl, uint32_t part_start, void *tg_cookie)
{
	int		i;
	int		rval = -1;
	uint32_t	seek_offset;
	uint32_t	linux_pg_size;
	char 		*buf, *linux_swap_magic;
	int		sec_sz = cl->cl_sys_blocksize;
	/* Known linux kernel page sizes */
	uint32_t	linux_pg_size_arr[] = {4096, };

	ASSERT(cl != NULL);
	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	if ((buf = kmem_zalloc(sec_sz, KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	/*
	 * Check if there is a sane Solaris VTOC
	 * If there is a valid vtoc, no need to lookup
	 * for the linux swap signature.
	 */
	mutex_exit(CMLB_MUTEX(cl));
	rval = DK_TG_READ(cl, buf, part_start + DK_LABEL_LOC,
	    sec_sz, tg_cookie);
	mutex_enter(CMLB_MUTEX(cl));
	if (rval != 0) {
		cmlb_dbg(CMLB_ERROR,  cl,
		    "cmlb_is_linux_swap: disk vtoc read err\n");
		rval = EIO;
		goto done;
	}

	if ((((struct dk_label *)buf)->dkl_magic == DKL_MAGIC) &&
	    (((struct dk_label *)buf)->dkl_vtoc.v_sanity == VTOC_SANE)) {
		rval = -1;
		goto done;
	}


	/* No valid vtoc, so check for linux swap signature */
	linux_swap_magic = buf + sec_sz - 10;

	for (i = 0; i < sizeof (linux_pg_size_arr)/sizeof (uint32_t); i++) {
		linux_pg_size = linux_pg_size_arr[i];
		seek_offset = linux_pg_size/sec_sz - 1;
		seek_offset += part_start;

		mutex_exit(CMLB_MUTEX(cl));
		rval = DK_TG_READ(cl, buf, seek_offset, sec_sz, tg_cookie);
		mutex_enter(CMLB_MUTEX(cl));

		if (rval != 0) {
			cmlb_dbg(CMLB_ERROR,  cl,
			    "cmlb_is_linux_swap: disk read err\n");
			rval = EIO;
			break;
		}

		rval = -1;

		if ((strncmp(linux_swap_magic, "SWAP-SPACE", 10) == 0) ||
		    (strncmp(linux_swap_magic, "SWAPSPACE2", 10) == 0)) {
			/* Found a linux swap */
			rval = 0;
			break;
		}
	}

done:
	kmem_free(buf, sec_sz);
	return (rval);
}
#endif

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
	int		i, k;
	char		sigbuf[2];
	caddr_t		bufp;
	int		uidx;
	int 		rval;
	int		lba = 0;
	uint_t		solaris_offset;	/* offset to solaris part. */
	daddr_t		solaris_size;	/* size of solaris partition */
	uint32_t	blocksize;
#if defined(__i386) || defined(__amd64)
	struct ipart	eparts[2];
	struct ipart	*efdp1 = &eparts[0];
	struct ipart	*efdp2 = &eparts[1];
	int		ext_part_exists = 0;
	int		ld_count = 0;
#endif

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
		uint32_t relsect;
		uint32_t numsect;
		uchar_t systid;
#if defined(__i386) || defined(__amd64)
		/*
		 * Stores relative block offset from the beginning of the
		 * Extended Partition.
		 */
		int	ext_relsect = 0;
#endif

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
		cl->cl_fmap[i].fmap_systid = LE_8(fdp->systid);

#if defined(__i386) || defined(__amd64)
		/* Support only one extended partition per LUN */
		if ((fdp->systid == EXTDOS || fdp->systid == FDISK_EXTLBA) &&
		    (ext_part_exists == 0)) {
			int j;
			uint32_t logdrive_offset;
			uint32_t ext_numsect;
			uint32_t abs_secnum;

			ext_part_exists = 1;

			for (j = FD_NUMPART; j < FDISK_PARTS; j++) {
				mutex_exit(CMLB_MUTEX(cl));
				rval = DK_TG_READ(cl, bufp,
				    (relsect + ext_relsect), blocksize,
				    tg_cookie);
				mutex_enter(CMLB_MUTEX(cl));

				if (rval != 0) {
					cmlb_dbg(CMLB_ERROR,  cl,
					    "cmlb_read_fdisk: Extended "
					    "partition read err\n");
					goto done;
				}
				/*
				 * The first ipart entry provides the offset
				 * at which the logical drive starts off from
				 * the beginning of the container partition
				 * and the size of the logical drive.
				 * The second ipart entry provides the offset
				 * of the next container partition from the
				 * beginning of the extended partition.
				 */
				bcopy(&bufp[FDISK_PART_TABLE_START], eparts,
				    sizeof (eparts));
				logdrive_offset = LE_32(efdp1->relsect);
				ext_numsect = LE_32(efdp1->numsect);
				systid = LE_8(efdp1->systid);
				if (logdrive_offset <= 0 || ext_numsect <= 0)
					break;
				abs_secnum = relsect + ext_relsect +
				    logdrive_offset;

				/* Boundary condition and overlap checking */
				if (cmlb_validate_ext_part(cl, i, j, abs_secnum,
				    ext_numsect)) {
					break;
				}

				if ((cl->cl_fmap[j].fmap_start != abs_secnum) ||
				    (cl->cl_fmap[j].fmap_nblk != ext_numsect) ||
				    (cl->cl_fmap[j].fmap_systid != systid)) {
					/*
					 * Indicates change from previous
					 * partinfo. Need to recreate
					 * logical device nodes.
					 */
					cl->cl_update_ext_minor_nodes = 1;
				}
				cl->cl_fmap[j].fmap_start = abs_secnum;
				cl->cl_fmap[j].fmap_nblk  = ext_numsect;
				cl->cl_fmap[j].fmap_systid = systid;
				ld_count++;

				if ((efdp1->systid == SUNIXOS &&
				    (cmlb_is_linux_swap(cl, abs_secnum,
				    tg_cookie) != 0)) ||
				    efdp1->systid == SUNIXOS2) {
					if (uidx == -1) {
						uidx = 0;
						solaris_offset = abs_secnum;
						solaris_size = ext_numsect;
					}
				}

				if ((ext_relsect = LE_32(efdp2->relsect)) == 0)
					break;
			}
		}

#endif

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
#if defined(__i386) || defined(__amd64)
			if (fdp->systid != SUNIXOS ||
			    (fdp->systid == SUNIXOS &&
			    (cmlb_is_linux_swap(cl, relsect,
			    tg_cookie) != 0))) {
#endif
				uidx = i;
				solaris_offset = relsect;
				solaris_size   = numsect;
#if defined(__i386) || defined(__amd64)
			}
#endif
		}
	}
#if defined(__i386) || defined(__amd64)
	if (ld_count < cl->cl_logical_drive_count) {
		/*
		 * Some/all logical drives were deleted. Clear out
		 * the fmap entries correspoding to those deleted drives.
		 */
		for (k = ld_count + FD_NUMPART;
		    k < cl->cl_logical_drive_count + FD_NUMPART; k++) {
			cl->cl_fmap[k].fmap_start = 0;
			cl->cl_fmap[k].fmap_nblk  = 0;
			cl->cl_fmap[k].fmap_systid = 0;
		}
		cl->cl_update_ext_minor_nodes = 1;
	}
	if (cl->cl_update_ext_minor_nodes) {
		rval = cmlb_update_ext_minor_nodes(cl, ld_count);
		if (rval != 0) {
			goto done;
		}
	}
#endif
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
		cl->cl_f_geometry_is_valid = B_FALSE;
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
 * This function returns B_FALSE if there is a valid MBR signature and no
 * partition table entries of type EFI_PMBR (0xEE). Otherwise it returns B_TRUE.
 *
 * The EFI spec (1.10 and later) requires having a Protective MBR (PMBR) to
 * recognize the disk as GPT partitioned. However, some other OS creates an MBR
 * where a PMBR entry is not the only one. Also, if the first block has been
 * corrupted, currently best attempt to allow data access would be to try to
 * check for GPT headers. Hence in case of more than one partition entry, but
 * at least one EFI_PMBR partition type or no valid magic number, the function
 * returns B_TRUE to continue with looking for GPT header.
 */

static boolean_t
cmlb_check_efi_mbr(uchar_t *buf, boolean_t *is_mbr)
{
	struct ipart	*fdp;
	struct mboot	*mbp = (struct mboot *)buf;
	struct ipart	fdisk[FD_NUMPART];
	int		i;

	if (is_mbr != NULL)
		*is_mbr = B_TRUE;

	if (LE_16(mbp->signature) != MBB_MAGIC) {
		if (is_mbr != NULL)
			*is_mbr = B_FALSE;
		return (B_TRUE);
	}

	bcopy(&mbp->parts[0], fdisk, sizeof (fdisk));

	for (fdp = fdisk, i = 0; i < FD_NUMPART; i++, fdp++) {
		if (fdp->systid == EFI_PMBR)
			return (B_TRUE);
	}

	return (B_FALSE);
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
#if defined(_FIRMWARE_NEEDS_FDISK)
	boolean_t 	is_mbr;
#endif

	ASSERT(mutex_owned(CMLB_MUTEX(cl)));

	lbasize = cl->cl_sys_blocksize;

	cl->cl_reserved = -1;
	mutex_exit(CMLB_MUTEX(cl));

	buf = kmem_zalloc(EFI_MIN_ARRAY_SIZE, KM_SLEEP);

	rval = DK_TG_READ(cl, buf,  0, lbasize, tg_cookie);
	if (rval) {
		iofailed = 1;
		goto done_err;
	}
	if (((struct dk_label *)buf)->dkl_magic == DKL_MAGIC) {
		/* not ours */
		rval = ESRCH;
		goto done_err;
	}

#if defined(_FIRMWARE_NEEDS_FDISK)
	if (!cmlb_check_efi_mbr(buf, &is_mbr)) {
		if (is_mbr)
			rval = ESRCH;
		else
			rval = EINVAL;
		goto done_err;
	}
#else
	if (!cmlb_check_efi_mbr(buf, NULL)) {
		rval = EINVAL;
		goto done_err;
	}

#endif

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
	cl->cl_label_from_media = CMLB_LABEL_EFI;
	cl->cl_f_geometry_is_valid = B_TRUE;

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
	if ((capacity > CMLB_EXTVTOC_LIMIT) && (rval != ESRCH) && !iofailed) {
		cl->cl_f_geometry_is_valid = B_FALSE;
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
	uint32_t	part_end;
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
	cl->cl_f_geometry_is_valid = B_TRUE;

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
				cl->cl_f_geometry_is_valid = B_FALSE;
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
				cl->cl_f_geometry_is_valid = B_FALSE;
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
		cl->cl_f_geometry_is_valid = B_FALSE;
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
			cl->cl_solaris_size = (diskaddr_t)cl->cl_g.dkg_ncyl *
			    cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect;
		} else {
			cl->cl_g.dkg_ncyl  = 1;
			cl->cl_g.dkg_nhead = 1;
			cl->cl_g.dkg_nsect = cl->cl_blockcount;
		}
	} else {
		if (cl->cl_blockcount < 160) {
			/* Less than 80K */
			cl->cl_g.dkg_nhead = 1;
			cl->cl_g.dkg_ncyl = cl->cl_blockcount;
			cl->cl_g.dkg_nsect = 1;
		} else if (cl->cl_blockcount <= 0x1000) {
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
		    (diskaddr_t)cl->cl_g.dkg_ncyl * cl->cl_g.dkg_nhead *
		    cl->cl_g.dkg_nsect;

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
		cl->cl_f_geometry_is_valid = B_TRUE;
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
		 * Before calculating geometry, capacity should be
		 * decreased by 1.
		 */

		if (cl->cl_alter_behavior & CMLB_OFF_BY_ONE)
			capacity = cl->cl_blockcount - 1;
		else
			capacity = cl->cl_blockcount;


		cmlb_convert_geometry(cl, capacity, &cl_g, tg_cookie);
		bcopy(&cl_g, &cl->cl_g, sizeof (cl->cl_g));
		phys_spc = cl->cl_g.dkg_nhead * cl->cl_g.dkg_nsect;
	}

	if (phys_spc == 0)
		return;
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
	cl->cl_vtoc.v_nparts = V_NUMPAR;
	cl->cl_vtoc.v_version = V_VERSION;

	cl->cl_f_geometry_is_valid = B_TRUE;
	cl->cl_label_from_media = CMLB_LABEL_UNDEF;

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
 * Description: Return B_TRUE if Cylinder-Head-Sector values are all at maximum.
 *
 *   Arguments: fdp - ptr to CHS info
 *
 * Return Code: True or false
 *
 *     Context: Any.
 */
static boolean_t
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
	rval = cmlb_validate_geometry(cl, B_TRUE, 0, tg_cookie);
#if defined(_SUNOS_VTOC_8)
	if (rval == EINVAL &&
	    cl->cl_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8) {
		/*
		 * This is to return a default label geometry even when we
		 * do not really assume a default label for the device.
		 * dad driver utilizes this.
		 */
		if (cl->cl_blockcount <= CMLB_OLDVTOC_LIMIT) {
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
	cl->cl_f_geometry_is_valid = B_FALSE;
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
	if ((rval = cmlb_validate_geometry(cl, B_TRUE, 0, tg_cookie)) != 0) {
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

	if (cl->cl_blockcount > CMLB_OLDVTOC_LIMIT) {
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
	if (cl->cl_blockcount > CMLB_OLDVTOC_LIMIT) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EOVERFLOW);
	}

	rval = cmlb_validate_geometry(cl, B_TRUE, 0, tg_cookie);

#if defined(_SUNOS_VTOC_8)
	if (rval == EINVAL &&
	    (cl->cl_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8)) {
		/*
		 * This is to return a default label even when we do not
		 * really assume a default label for the device.
		 * dad driver utilizes this.
		 */
		if (cl->cl_blockcount <= CMLB_OLDVTOC_LIMIT) {
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


/*
 *    Function: cmlb_dkio_get_extvtoc
 */
static int
cmlb_dkio_get_extvtoc(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie)
{
	struct extvtoc	ext_vtoc;
#if defined(_SUNOS_VTOC_8)
	struct vtoc	user_vtoc;
#endif	/* defined(_SUNOS_VTOC_8) */
	int		rval = 0;

	bzero(&ext_vtoc, sizeof (struct extvtoc));
	mutex_enter(CMLB_MUTEX(cl));
	rval = cmlb_validate_geometry(cl, B_TRUE, 0, tg_cookie);

#if defined(_SUNOS_VTOC_8)
	if (rval == EINVAL &&
	    (cl->cl_alter_behavior & CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8)) {
		/*
		 * This is to return a default label even when we do not
		 * really assume a default label for the device.
		 * dad driver utilizes this.
		 */
		if (cl->cl_blockcount <= CMLB_OLDVTOC_LIMIT) {
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

	/*
	 * Checking callers data model does not make much sense here
	 * since extvtoc will always be equivalent to 64bit vtoc.
	 * What is important is whether the kernel is in 32 or 64 bit
	 */

#ifdef _LP64
		if (ddi_copyout(&user_vtoc, (void *)arg,
		    sizeof (struct extvtoc), flag)) {
			return (EFAULT);
		}
#else
		vtoc32tovtoc(user_vtoc, ext_vtoc);
		if (ddi_copyout(&ext_vtoc, (void *)arg,
		    sizeof (struct extvtoc), flag)) {
			return (EFAULT);
		}
#endif

#elif defined(_SUNOS_VTOC_16)
	/*
	 * The cl_vtoc structure is a "struct dk_vtoc"  which is always
	 * 32-bit to maintain compatibility with existing on-disk
	 * structures.  Thus, we need to convert the structure when copying
	 * it out to extvtoc
	 */
	vtoc32tovtoc(cl->cl_vtoc, ext_vtoc);
	mutex_exit(CMLB_MUTEX(cl));

	if (ddi_copyout(&ext_vtoc, (void *)arg, sizeof (struct extvtoc), flag))
		return (EFAULT);
#else
#error "No VTOC format defined."
#endif

	return (rval);
}

/*
 * This routine implements the DKIOCGETEFI ioctl. This ioctl is currently
 * used to read the GPT Partition Table Header (primary/backup), the GUID
 * partition Entry Array (primary/backup), and the MBR.
 */
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

	if (user_efi.dki_length == 0 ||
	    user_efi.dki_length > cmlb_tg_max_efi_xfer)
		return (EINVAL);

	tgt_lba = user_efi.dki_lba;

	mutex_enter(CMLB_MUTEX(cl));
	if ((cmlb_check_update_blockcount(cl, tg_cookie) != 0) ||
	    (cl->cl_tgt_blocksize == 0) ||
	    (user_efi.dki_length % cl->cl_sys_blocksize)) {
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
	uint32_t		nblks;
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
	int			n_gpe_per_blk = 0;

	if (ddi_copyin((const void *)arg, &p64,
	    sizeof (struct partition64), flag)) {
		return (EFAULT);
	}

	buffer = kmem_alloc(cl->cl_sys_blocksize, KM_SLEEP);
	rval = DK_TG_READ(cl, buffer, 1, cl->cl_sys_blocksize, tg_cookie);
	if (rval != 0)
		goto done_error;

	cmlb_swap_efi_gpt(buffer);

	if ((rval = cmlb_validate_efi(buffer)) != 0)
		goto done_error;

	nparts = buffer->efi_gpt_NumberOfPartitionEntries;
	gpe_lba = buffer->efi_gpt_PartitionEntryLBA;
	if (p64.p_partno >= nparts) {
		/* couldn't find it */
		rval = ESRCH;
		goto done_error;
	}
	/*
	 * Read the block that contains the requested GPE.
	 */
	n_gpe_per_blk = cl->cl_sys_blocksize / sizeof (efi_gpe_t);
	gpe_lba += p64.p_partno / n_gpe_per_blk;
	rval = DK_TG_READ(cl, buffer, gpe_lba, cl->cl_sys_blocksize, tg_cookie);

	if (rval) {
		goto done_error;
	}
	partitions = (efi_gpe_t *)buffer;
	partitions += p64.p_partno % n_gpe_per_blk;

	/* Byte swap only the requested GPE */
	cmlb_swap_efi_gpe(1, partitions);

	bcopy(&partitions->efi_gpe_PartitionTypeGUID, &p64.p_type,
	    sizeof (struct uuid));
	p64.p_start = partitions->efi_gpe_StartingLBA;
	p64.p_size = partitions->efi_gpe_EndingLBA -
	    p64.p_start + 1;

	if (ddi_copyout(&p64, (void *)arg, sizeof (struct partition64), flag))
		rval = EFAULT;

done_error:
	kmem_free(buffer, cl->cl_sys_blocksize);
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

	internal = VOID2BOOLEAN(
	    (cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);

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

	if (cl->cl_blockcount > CMLB_OLDVTOC_LIMIT) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EOVERFLOW);
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

	/*
	 * cmlb_dkio_set_vtoc creates duplicate minor nodes when
	 * relabeling an SMI disk. To avoid that we remove them
	 * before creating.
	 * It should be OK to remove a non-existed minor node.
	 */
	ddi_remove_minor_node(CMLB_DEVINFO(cl), "h");
	ddi_remove_minor_node(CMLB_DEVINFO(cl), "h,raw");

	(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h",
	    S_IFBLK, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    cl->cl_node_type, NULL, internal);
	(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h,raw",
	    S_IFCHR, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    cl->cl_node_type, NULL, internal);
	mutex_enter(CMLB_MUTEX(cl));

	if ((rval = cmlb_build_label_vtoc(cl, &user_vtoc)) == 0) {
		if ((rval = cmlb_write_label(cl, tg_cookie)) == 0) {
			if (cmlb_validate_geometry(cl,
			    B_TRUE, 0, tg_cookie) != 0) {
				cmlb_dbg(CMLB_ERROR, cl,
				    "cmlb_dkio_set_vtoc: "
				    "Failed validate geometry\n");
			}
			cl->cl_msglog_flag |= CMLB_ALLOW_2TB_WARN;
		}
	}
	mutex_exit(CMLB_MUTEX(cl));
	return (rval);
}

/*
 *    Function: cmlb_dkio_set_extvtoc
 */
static int
cmlb_dkio_set_extvtoc(struct cmlb_lun *cl, dev_t dev, caddr_t arg, int flag,
    void *tg_cookie)
{
	int		rval = 0;
	struct vtoc	user_vtoc;
	boolean_t	internal;


	/*
	 * Checking callers data model does not make much sense here
	 * since extvtoc will always be equivalent to 64bit vtoc.
	 * What is important is whether the kernel is in 32 or 64 bit
	 */

#ifdef _LP64
	if (ddi_copyin((const void *)arg, &user_vtoc,
		    sizeof (struct extvtoc), flag)) {
			return (EFAULT);
	}
#else
	struct	extvtoc	user_extvtoc;
	if (ddi_copyin((const void *)arg, &user_extvtoc,
		    sizeof (struct extvtoc), flag)) {
			return (EFAULT);
	}

	vtoctovtoc32(user_extvtoc, user_vtoc);
#endif

	internal = VOID2BOOLEAN(
	    (cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);
	mutex_enter(CMLB_MUTEX(cl));
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
	/*
	 * cmlb_dkio_set_extvtoc creates duplicate minor nodes when
	 * relabeling an SMI disk. To avoid that we remove them
	 * before creating.
	 * It should be OK to remove a non-existed minor node.
	 */
	ddi_remove_minor_node(CMLB_DEVINFO(cl), "h");
	ddi_remove_minor_node(CMLB_DEVINFO(cl), "h,raw");

	(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h",
	    S_IFBLK, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    cl->cl_node_type, NULL, internal);
	(void) cmlb_create_minor(CMLB_DEVINFO(cl), "h,raw",
	    S_IFCHR, (CMLBUNIT(dev) << CMLBUNIT_SHIFT) | WD_NODE,
	    cl->cl_node_type, NULL, internal);

	mutex_enter(CMLB_MUTEX(cl));

	if ((rval = cmlb_build_label_vtoc(cl, &user_vtoc)) == 0) {
		if ((rval = cmlb_write_label(cl, tg_cookie)) == 0) {
			if (cmlb_validate_geometry(cl,
			    B_TRUE, 0, tg_cookie) != 0) {
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
	uint_t			nblks;
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
		if (((unsigned)vpart->p_start % nblks) != 0) {
			cmlb_dbg(CMLB_INFO,  cl,
			    "cmlb_build_label_vtoc: p_start not multiply of"
			    "nblks part %d p_start %d nblks %d\n", i,
			    vpart->p_start, nblks);
			return (EINVAL);
		}
		ncyl = (unsigned)vpart->p_start / nblks;
		ncyl += (unsigned)vpart->p_size / nblks;
		if (((unsigned)vpart->p_size % nblks) != 0) {
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
		lmap->dkl_cylno = (unsigned)vpart->p_start / nblks;
		lmap->dkl_nblk = (unsigned)vpart->p_size;
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
		lmap->dkl_cylno = (unsigned)vpart->p_start / nblks;
		lmap->dkl_nblk = (unsigned)vpart->p_size;

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

	gpt = kmem_alloc(cl->cl_sys_blocksize, KM_SLEEP);

	if (DK_TG_READ(cl, gpt, 1, cl->cl_sys_blocksize, tg_cookie) != 0) {
		goto done;
	}

	cmlb_swap_efi_gpt(gpt);
	rval = cmlb_validate_efi(gpt);
	if (rval == 0) {
		/* clear primary */
		bzero(gpt, sizeof (efi_gpt_t));
		if (rval = DK_TG_WRITE(cl, gpt, 1, cl->cl_sys_blocksize,
		    tg_cookie)) {
			cmlb_dbg(CMLB_INFO,  cl,
			    "cmlb_clear_efi: clear primary label failed\n");
		}
	}
	/* the backup */
	rval = DK_TG_GETCAP(cl, &cap, tg_cookie);
	if (rval) {
		goto done;
	}

	if ((rval = DK_TG_READ(cl, gpt, cap - 1, cl->cl_sys_blocksize,
	    tg_cookie)) != 0) {
		goto done;
	}
	cmlb_swap_efi_gpt(gpt);
	rval = cmlb_validate_efi(gpt);
	if (rval == 0) {
		/* clear backup */
		cmlb_dbg(CMLB_TRACE,  cl,
		    "cmlb_clear_efi clear backup@%lu\n", cap - 1);
		bzero(gpt, sizeof (efi_gpt_t));
		if ((rval = DK_TG_WRITE(cl,  gpt, cap - 1, cl->cl_sys_blocksize,
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
		    cl->cl_sys_blocksize, tg_cookie)) != 0) {
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
			    cl->cl_sys_blocksize, tg_cookie))) {
				cmlb_dbg(CMLB_INFO,  cl,
				"cmlb_clear_efi: clear legacy backup label "
				"failed\n");
			}
		}
	}

done:
	kmem_free(gpt, cl->cl_sys_blocksize);
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
	diskaddr_t	blk;
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
		blk = (diskaddr_t)(
		    (cyl * ((dkl->dkl_nhead * dkl->dkl_nsect) - dkl->dkl_apc)) +
		    (head * dkl->dkl_nsect) + sec);
#if defined(__i386) || defined(__amd64)
		blk += cl->cl_solaris_offset;
#endif
		rval = DK_TG_WRITE(cl, dkl, blk, cl->cl_sys_blocksize,
		    tg_cookie);
		cmlb_dbg(CMLB_INFO,  cl,
		"cmlb_set_vtoc: wrote backup label %llx\n", blk);
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
	dkl = kmem_zalloc(cl->cl_sys_blocksize, KM_SLEEP);
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
	kmem_free(dkl, cl->cl_sys_blocksize);

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
	dkl = kmem_zalloc(cl->cl_sys_blocksize, KM_SLEEP);
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
	kmem_free(dkl, cl->cl_sys_blocksize);
	mutex_enter(CMLB_MUTEX(cl));
	return (rval);
}

/*
 * This routine implements the DKIOCSETEFI ioctl. This ioctl is currently
 * used to write (or clear) the GPT Partition Table header (primary/backup)
 * and GUID partition Entry Array (primary/backup). It is also used to write
 * the Protective MBR.
 */
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

	internal = VOID2BOOLEAN(
	    (cl->cl_alter_behavior & (CMLB_INTERNAL_MINOR_NODES)) != 0);

	user_efi.dki_data = (void *)(uintptr_t)user_efi.dki_data_64;

	if (user_efi.dki_length == 0 ||
	    user_efi.dki_length > cmlb_tg_max_efi_xfer)
		return (EINVAL);

	tgt_lba = user_efi.dki_lba;

	mutex_enter(CMLB_MUTEX(cl));
	if ((cmlb_check_update_blockcount(cl, tg_cookie) != 0) ||
	    (cl->cl_tgt_blocksize == 0) ||
	    (user_efi.dki_length % cl->cl_sys_blocksize)) {
		mutex_exit(CMLB_MUTEX(cl));
		return (EINVAL);
	}
	if (cl->cl_tgt_blocksize != cl->cl_sys_blocksize)
		tgt_lba = tgt_lba *
		    cl->cl_tgt_blocksize / cl->cl_sys_blocksize;
	mutex_exit(CMLB_MUTEX(cl));

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
			if (cl->cl_label_from_media == CMLB_LABEL_VTOC)
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

		rval = DK_TG_WRITE(cl, buffer, tgt_lba, user_efi.dki_length,
		    tg_cookie);

		if (rval == 0) {
			mutex_enter(CMLB_MUTEX(cl));
			cl->cl_f_geometry_is_valid = B_FALSE;
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
	buffer_size = cl->cl_sys_blocksize;

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

	mboot = kmem_zalloc(cl->cl_sys_blocksize, KM_SLEEP);

	if (ddi_copyin((const void *)arg, mboot,
	    cl->cl_sys_blocksize, flag) != 0) {
		kmem_free(mboot, cl->cl_sys_blocksize);
		return (EFAULT);
	}

	/* Is this really a master boot record? */
	magic = LE_16(mboot->signature);
	if (magic != MBB_MAGIC) {
		kmem_free(mboot, cl->cl_sys_blocksize);
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
		if ((!cl->cl_f_geometry_is_valid) || (rval != 0)) {
			mutex_exit(CMLB_MUTEX(cl));
			kmem_free(mboot, cl->cl_sys_blocksize);
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
		if (cl->cl_blockcount <= CMLB_EXTVTOC_LIMIT)
			cmlb_setup_default_geometry(cl, tg_cookie);
	}
#endif
	cl->cl_msglog_flag |= CMLB_ALLOW_2TB_WARN;
	mutex_exit(CMLB_MUTEX(cl));
	kmem_free(mboot, cl->cl_sys_blocksize);
	return (rval);
}


#if defined(__i386) || defined(__amd64)
/*ARGSUSED*/
static int
cmlb_dkio_set_ext_part(struct cmlb_lun *cl, caddr_t arg, int flag,
    void *tg_cookie)
{
	int fdisk_rval;
	diskaddr_t capacity;

	ASSERT(!mutex_owned(CMLB_MUTEX(cl)));

	mutex_enter(CMLB_MUTEX(cl));
	capacity = cl->cl_blockcount;
	fdisk_rval = cmlb_read_fdisk(cl, capacity, tg_cookie);
	if (fdisk_rval != 0) {
		mutex_exit(CMLB_MUTEX(cl));
		return (fdisk_rval);
	}

	mutex_exit(CMLB_MUTEX(cl));
	return (fdisk_rval);
}
#endif

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

		if (ret == 0) {
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
		} else if (cl->cl_blockcount < 160) {
			/* Less than 80K */
			cl->cl_g.dkg_nhead = 1;
			cl->cl_g.dkg_ncyl = cl->cl_blockcount;
			cl->cl_g.dkg_nsect = 1;
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

	cl->cl_f_geometry_is_valid = B_FALSE;
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
			cl->cl_f_geometry_is_valid = B_TRUE;
			goto no_solaris_partition;
		}
	} else if (capacity < 0) {
		ASSERT(mutex_owned(CMLB_MUTEX(cl)));
		return (EINVAL);
	}

	/*
	 * For Removable media We reach here if we have found a
	 * SOLARIS PARTITION.
	 * If cl_f_geometry_is_valid is B_FALSE it indicates that the SOLARIS
	 * PARTITION has changed from the previous one, hence we will setup a
	 * default VTOC in this case.
	 */
	if (!cl->cl_f_geometry_is_valid) {
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
	for (count = 0; count < FDISK_PARTS; count++) {
		cl->cl_map[FDISK_P1 + count].dkl_cylno = UINT32_MAX;
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
cmlb_dkio_get_phygeom(struct cmlb_lun *cl, caddr_t  arg, int flag,
    void *tg_cookie)
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

			cmlb_convert_geometry(cl, capacity, dkgp, tg_cookie);
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
static int
cmlb_dkio_extpartinfo(struct cmlb_lun *cl, dev_t dev, caddr_t  arg, int flag)
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
		struct extpart_info p;

		p.p_start = (diskaddr_t)cl->cl_offset[part];
		p.p_length = (diskaddr_t)cl->cl_map[part].dkl_nblk;
		mutex_exit(CMLB_MUTEX(cl));
		if (ddi_copyout(&p, (void *)arg, sizeof (p), flag))
			err = EFAULT;
	}
	return (err);
}
#endif

int
cmlb_prop_op(cmlb_handle_t cmlbhandle,
    dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp, int part, void *tg_cookie)
{
	struct cmlb_lun	*cl;
	diskaddr_t	capacity;
	uint32_t	lbasize;
	enum		dp { DP_NBLOCKS, DP_BLKSIZE, DP_SSD } dp;
	int		callers_length;
	caddr_t		buffer;
	uint64_t	nblocks64;
	uint_t		dblk;
	tg_attribute_t	tgattr;

	/* Always fallback to ddi_prop_op... */
	cl = (struct cmlb_lun *)cmlbhandle;
	if (cl == NULL) {
fallback:	return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	}

	/* Pick up capacity and blocksize information. */
	capacity = cl->cl_blockcount;
	if (capacity == 0)
		goto fallback;
	lbasize = cl->cl_tgt_blocksize;
	if (lbasize == 0)
		lbasize = DEV_BSIZE;	/* 0 -> DEV_BSIZE units */

	/* Check for dynamic property of whole device. */
	if (dev == DDI_DEV_T_ANY) {
		/* Fallback to ddi_prop_op if we don't understand.  */
		if (strcmp(name, "device-nblocks") == 0)
			dp = DP_NBLOCKS;
		else if (strcmp(name, "device-blksize") == 0)
			dp = DP_BLKSIZE;
		else if (strcmp(name, "device-solid-state") == 0)
			dp = DP_SSD;
		else
			goto fallback;

		/* get callers length, establish length of our dynamic prop */
		callers_length = *lengthp;
		if (dp == DP_NBLOCKS)
			*lengthp = sizeof (uint64_t);
		else if ((dp == DP_BLKSIZE) || (dp == DP_SSD))
			*lengthp = sizeof (uint32_t);

		/* service request for the length of the property */
		if (prop_op == PROP_LEN)
			return (DDI_PROP_SUCCESS);

		switch (prop_op) {
		case PROP_LEN_AND_VAL_ALLOC:
			if ((buffer = kmem_alloc(*lengthp,
			    (mod_flags & DDI_PROP_CANSLEEP) ?
			    KM_SLEEP : KM_NOSLEEP)) == NULL)
				return (DDI_PROP_NO_MEMORY);
			*(caddr_t *)valuep = buffer;	/* set callers buf */
			break;

		case PROP_LEN_AND_VAL_BUF:
			/* the length of the prop and the request must match */
			if (callers_length != *lengthp)
				return (DDI_PROP_INVAL_ARG);
			buffer = valuep;		/* get callers buf */
			break;

		default:
			return (DDI_PROP_INVAL_ARG);
		}

		/* transfer the value into the buffer */
		switch (dp) {
		case DP_NBLOCKS:
			*((uint64_t *)buffer) = capacity;
			break;
		case DP_BLKSIZE:
			*((uint32_t *)buffer) = lbasize;
			break;
		case DP_SSD:
			if (DK_TG_GETATTRIBUTE(cl, &tgattr, tg_cookie) != 0)
				tgattr.media_is_solid_state = B_FALSE;
			*((uint32_t *)buffer) =
			    tgattr.media_is_solid_state ? 1 : 0;
			break;
		}
		return (DDI_PROP_SUCCESS);
	}

	/*
	 * Support dynamic size oriented properties of partition. Requests
	 * issued under conditions where size is valid are passed to
	 * ddi_prop_op_nblocks with the size information, otherwise the
	 * request is passed to ddi_prop_op. Size depends on valid geometry.
	 */
	if (!cmlb_is_valid(cmlbhandle))
		goto fallback;

	/* Get partition nblocks value. */
	(void) cmlb_partinfo(cmlbhandle, part,
	    (diskaddr_t *)&nblocks64, NULL, NULL, NULL, tg_cookie);

	/*
	 * Assume partition information is in sys_blocksize units, compute
	 * divisor for size(9P) property representation.
	 */
	dblk = lbasize / cl->cl_sys_blocksize;

	/* Now let ddi_prop_op_nblocks_blksize() handle the request. */
	return (ddi_prop_op_nblocks_blksize(dev, dip, prop_op, mod_flags,
	    name, valuep, lengthp, nblocks64 / dblk, lbasize));
}
