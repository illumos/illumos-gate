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
 * Copyright 2016 Toomas Soome <tsoome@me.com>
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_CMLB_H
#define	_SYS_CMLB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/dktp/fdisk.h>

/*
 * structure used for getting phygeom and virtgeom from target driver
 */
typedef struct cmlb_geom {
	unsigned int    g_ncyl;
	unsigned short  g_acyl;
	unsigned short  g_nhead;
	unsigned short  g_nsect;
	unsigned short  g_secsize;
	diskaddr_t	g_capacity;
	unsigned short  g_intrlv;
	unsigned short  g_rpm;
} cmlb_geom_t;


typedef struct tg_attribute {
	int media_is_writable;
	int media_is_solid_state;
} tg_attribute_t;



/* bit definitions for alter_behavior passed to cmlb_attach */

#define	CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT	0x00000001
#define	CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8		0x00000002
#define	CMLB_OFF_BY_ONE					0x00000004
#define	CMLB_FAKE_LABEL_ONE_PARTITION			0x00000008
#define	CMLB_INTERNAL_MINOR_NODES			0x00000010
#define	CMLB_CREATE_P0_MINOR_NODE			0x00000020

/* bit definitions of flag passed to cmlb_validate */
#define	CMLB_SILENT					0x00000001

/* version for tg_ops */
#define	TG_DK_OPS_VERSION_0	0
#define	TG_DK_OPS_VERSION_1	1

/* definitions for cmd passed to tg_rdwr */
#define	TG_READ			0
#define	TG_WRITE		1

/* definitions for cmd passed to tg_getinfo */
#define	TG_GETPHYGEOM		1
#define	TG_GETVIRTGEOM		2
#define	TG_GETCAPACITY		3
#define	TG_GETBLOCKSIZE		4
#define	TG_GETATTR		5

#if defined(_SUNOS_VTOC_8)

#define	CMLBUNIT_DFT_SHIFT	3
/* This will support p0 node on sparc */
#define	CMLBUNIT_FORCE_P0_SHIFT	(CMLBUNIT_DFT_SHIFT + 1)

#elif defined(_SUNOS_VTOC_16)

#define	CMLBUNIT_DFT_SHIFT	6
#define	CMLBUNIT_FORCE_P0_SHIFT	(CMLBUNIT_DFT_SHIFT)

#else	/* defined(_SUNOS_VTOC_16) */

#error "No VTOC format defined."

#endif	/* defined(_SUNOS_VTOC_8) */

/*
 * Ops vector including utility functions into target driver that cmlb uses.
 */
typedef struct cmlb_tg_ops {
	int	tg_version;

	/*
	 * tg_rdwr:
	 *	perform read/write on target device associated with devi.
	 *
	 * Arguments:
	 *
	 *	devi:		pointer to device's dev_info structure.
	 *
	 *	cmd:		operation to perform.
	 *			Possible values: TG_READ, TG_WRITE
	 *
	 *	bufp:		pointer to allocated buffer for transfer
	 *
	 *	start_block:	starting block number to read/write (based on
	 *			system blocksize, DEV_BSIZE)
	 *
	 *	reqlength:	requested transfer length (in bytes)
	 *
	 *	tg_cookie 	cookie from target driver to be passed back to
	 *			target driver when we call back to it through
	 *			tg_ops.
	 *
	 * Note: It is the responsibility of caller to make sure
	 *	length of buffer pointed to by bufp is at least equal to
	 *	requested transfer length
	 *
	 * Return values:
	 *	0		success
	 *	ENOMEM		can not allocate memory
	 *	EACCESS  	reservation conflict
	 *	EIO		I/O error
	 *	EFAULT		copyin/copyout error
	 *	ENXIO		internal error/ invalid devi
	 *	EINVAL		invalid command value.
	 */
	int (*tg_rdwr)(dev_info_t *devi, uchar_t cmd, void *bufp,
	    diskaddr_t start_block, size_t reqlength, void *tg_cookie);

	/*
	 * tg_getinfo:
	 * 	Report the information requested on device/media and
	 *	store the requested info in area pointed to by arg.
	 *
	 * Arguments:
	 *	devi:		pointer to device's dev_info structure.
	 *
	 *	cmd:		operation to perform
	 *
	 *	arg:		arg for the operation for result.
	 *
	 *	tg_cookie 	cookie from target driver to be passed back to
	 *			target driver when we call back to it through
	 *			tg_ops.
	 *
	 * 	Possible commands and the interpretation of arg:
	 *
	 *	cmd:
	 *		TG_GETPHYGEOM
	 *			Obtain raw physical geometry from target,
	 *			and store in structure pointed to by arg,
	 *			a cmlb_geom_t structure.
	 *
	 * 		TG_GETVIRTGEOM:
	 *			Obtain HBA geometry for the target and
	 *			store in struct pointed to by arg,
	 *			a cmlb_geom_t structure.
	 *
	 *		TG_GETCAPACITY:
	 *			Report the capacity of the target (in system
	 *			blocksize (DEV_BSIZE) and store in the
	 *			space pointed to by arg, a diskaddr_t.
	 *
	 *		TG_GETBLOCKSIZE:
	 *			Report the block size of the target
	 *			in the space pointed to by arg, a uint32_t.
	 *
	 *		TG_GETATTR:
	 * 			Report the information requested on
	 *			device/media and store in area pointed to by
	 *			arg, a tg_attribute_t structure.
	 *			Return values:
	 *
	 * Return values:
	 *	0		success
	 *
	 *	EACCESS		reservation conflict
	 *
	 *	ENXIO		internal error/invalid devi
	 *
	 *	EINVAL		When command is TG_GETPHYGEOM or
	 *			TG_GETVIRTGEOM, or TG_GETATTR, this return code
	 *			indicates the operation is not applicable to
	 *			target.
	 *			In case of TG_GETCAP, this return code
	 *			indicates no media in the drive.
	 *
	 *	EIO		An error occurred during obtaining info
	 *			from device/media.
	 *
	 *	ENOTSUP		In case of TG_GETCAP, target does not
	 *			support getting capacity info.
	 *
	 *	ENOTTY		Unknown command.
	 *
	 *
	 */
	int (*tg_getinfo)(dev_info_t *devi, int cmd, void *arg,
	    void *tg_cookie);

} cmlb_tg_ops_t;


typedef struct __cmlb_handle *cmlb_handle_t;

/*
 *
 * Functions exported from cmlb
 *
 * Note: Most these functions can callback to target driver through the
 * tg_ops functions. Target driver should consider this for synchronization.
 * Any functions that may adjust minor nodes should be called when
 * the target driver ensures it is safe to do so.
 */

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
cmlb_alloc_handle(cmlb_handle_t *cmlbhandlep);


/*
 * cmlb_attach:
 *
 *	Attach handle to device, create minor nodes for device.
 *
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
 *			on architecture with VTOC 8 label types.
 *
 * 			CMLB_OFF_BY_ONE: do the workaround for legacy off-by-
 *			one bug in obtaining capacity (used for sd).
 *
 *
 *	cmlbhandle	cmlb handle associated with device
 *
 *	tg_cookie 	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 *			cmlb does not interpret the values. It is currently
 *			used for sd to indicate whether retries are allowed
 *			on commands or not. e.g when cmlb entries are called
 *			from interrupt context on removable media, sd rather
 *			not have retries done.
 *
 *
 *
 * Notes:
 *	Assumes a default label based on capacity for non-removable devices.
 *	If capacity > 1TB, EFI is assumed otherwise VTOC (default VTOC
 *	for the architecture).
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
 *	EINVAL	invalid arg, unsupported tg_ops version
 *
 */
int
cmlb_attach(dev_info_t *devi, cmlb_tg_ops_t *tgopsp, int device_type,
    boolean_t is_removable, boolean_t is_hotpluggable, char *node_type,
    int alter_behavior, cmlb_handle_t cmlbhandle, void *tg_cookie);


/*
 * cmlb_validate:
 *
 *	Validates label.
 *
 * Arguments
 *	cmlbhandle	cmlb handle associated with device.
 *
 * 	int 		flags
 *			currently used for verbosity control.
 *			CMLB_SILENT is the only current definition for it
 *	tg_cookie 	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
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
 *
 */
int
cmlb_validate(cmlb_handle_t cmlbhandle, int flags, void *tg_cookie);

/*
 * cmlb_invalidate:
 *	Invalidate in core label data
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	tg_cookie 	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 */
void
cmlb_invalidate(cmlb_handle_t cmlbhandle, void *tg_cookie);



/*
 * cmlb_is_valid
 *	 Get status on whether the incore label/geom data is valid
 *
 * Arguments:
 *      cmlbhandle      cmlb handle associated with device.
 *
 * Return values:
 *      TRUE if valid
 *      FALSE otherwise.
 *
 */
boolean_t
cmlb_is_valid(cmlb_handle_t cmlbhandle);

/*
 * cmlb_partinfo:
 *	Get partition info for specified partition number.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	part		partition number
 *			driver when we call back to it through tg_ops.
 *	nblocksp	pointer to number of blocks
 *	startblockp	pointer to starting block
 *	partnamep	pointer to name of partition
 *	tagp		pointer to tag info
 *	tg_cookie 	cookie from target driver to be passed back to target
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
    diskaddr_t *startblockp, char **partnamep, uint16_t *tagp, void *tg_cookie);

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
    void *tg_cookie);

/*
 * cmlb_ioctl:
 * Ioctls for label handling will be handled by this function.
 * These are:
 *	DKIOCGGEOM
 *	DKIOCSGEOM
 *	DKIOCGAPART
 *	DKIOCSAPART
 *	DKIOCGVTOC
 *	DKIOCGETEFI
 *	DKIOCPARTITION
 *	DKIOCSVTOC
 * 	DKIOCSETEFI
 *	DKIOCGMBOOT
 *	DKIOCSMBOOT
 *	DKIOCG_PHYGEOM
 *	DKIOCG_VIRTGEOM
 *	DKIOCPARTINFO
 *
 *
 *   Arguments:
 *	cmlbhandle 	handle associated with device.
 *      cmd     	ioctl operation to be performed
 *      arg     	user argument, contains data to be set or reference
 *                      parameter for get
 *	flag    	bit flag, indicating open settings, 32/64 bit type
 *      cred_p  	user credential pointer (not currently used)
 *	rval_p  	not currently used
 *	tg_cookie 	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 *
 *
 * Return values:
 *	0
 *	EINVAL
 *	ENOTTY
 *	ENXIO
 *	EIO
 *	EFAULT
 *	ENOTSUP
 *	EPERM
 */
int
cmlb_ioctl(cmlb_handle_t cmlbhandle, dev_t dev, int cmd,
    intptr_t arg, int flag, cred_t *cred_p, int *rval_p, void *tg_cookie);

/*
 * cmlb_prop_op:
 *	provide common label prop_op(9E) implementation that understands the
 *	size(9p) properties.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	dev		See prop_op(9E)
 *	dip		"
 *	prop_op		"
 *	mod_flags	"
 *	name		"
 *	valuep		"
 *	lengthp		"
 *	part		partition number
 *	tg_cookie 	cookie from target driver to be passed back to target
 */
int
cmlb_prop_op(cmlb_handle_t cmlbhandle,
    dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp, int part, void *tg_cookie);

/*
 * cmlb_get_devid_block:
 *	 get the block number where device id is stored.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	devidblockp	pointer to block number.
 *	tg_cookie 	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 * Notes:
 *	It stores the block number of device id in the area pointed to
 *	by devidblockp.
 *
 * Return values:
 *	0	success
 *	EINVAL 	device id does not apply to current label type.
 */
int
cmlb_get_devid_block(cmlb_handle_t cmlbhandle, diskaddr_t *devidblockp,
    void *tg_cookie);


/*
 * cmlb_close:
 *
 * Close the device, revert to a default label minor node for the device,
 * if it is removable.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *
 *	tg_cookie 	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 * Return values:
 *	0	Success
 * 	ENXIO	Re-creating minor node failed.
 */
int
cmlb_close(cmlb_handle_t cmlbhandle, void *tg_cookie);

/*
 * cmlb_detach:
 *
 * Invalidate in-core labeling data and remove all minor nodes for
 * the device associate with handle.
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 *	tg_cookie 	cookie from target driver to be passed back to target
 *			driver when we call back to it through tg_ops.
 *
 */
void
cmlb_detach(cmlb_handle_t cmlbhandle, void *tg_cookie);

/*
 * cmlb_free_handle
 *
 *	Frees handle.
 *
 * Arguments:
 *	cmlbhandlep	pointer to handle
 *
 */
void
cmlb_free_handle(cmlb_handle_t *cmlbhandlep);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_CMLB_H */
