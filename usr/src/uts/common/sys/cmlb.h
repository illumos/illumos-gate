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

#ifndef _SYS_CMLB_H
#define	_SYS_CMLB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
} tg_attribute_t;

#define	TG_READ		0
#define	TG_WRITE	1

#define	TG_DK_OPS_VERSION_0	0x0

/* flag definitions for alter_behavior arg on attach */

#define	CMLB_CREATE_ALTSLICE_VTOC_16_DTYPE_DIRECT	0x00000001
#define	CMLB_FAKE_GEOM_LABEL_IOCTLS_VTOC8		0x00000002

/*
 * Ops vector including utility functions into target driver that cmlb uses.
 */
typedef struct cmlb_tg_ops {
	int	version;
	/*
	 * tg_rdwr:
	 *	perform read/write on target device associated with devi.
	 * Arguments:
	 *	devi:		pointer to device's dev_info structure.
	 *	cmd:		operation to perform.
	 *			Possible values: TG_READ, TG_WRITE
	 *	bufp:		pointer to allocated buffer for transfer
	 *	start_block:	starting block number to read/write (based on
	 *			system blocksize, DEV_BSIZE)
	 *
	 *	reqlength:	requested transfer length (in bytes)
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
	    diskaddr_t start_block, size_t reqlength);

	/*
	 * tg_getphygeom:
	 *	Obtain raw physical geometry from target, and store in structure
	 *	pointed to by phygeomp
	 *
	 * Arguments:
	 *	devi:		pointer to device's dev_info structure.
	 *	phygeomp	pointer to allocated structure for
	 *			physical geometry info.
	 * Return values:
	 *	0		success
	 * 	EACCESS		reservation conflict
	 *	EINVAL		not applicable
	 *	EIO		other errors occurred.
	 *	ENXIO		internal error/ invalid devi
	 */
	int (*tg_getphygeom)(dev_info_t *devi, cmlb_geom_t *phygeomp);

	/*
	 * tg_getvirtgeom:
	 *	obtain HBA geometry for the target and store in struct pointed
	 *	to by virtgeomp
	 * Arguments:
	 *	devi:		pointer to device's dev_info structure.
	 *	virtgeomp	pointer to allocated structure for
	 *			virtual geometry info.
	 * Return values:
	 *	0		success
	 * 	EACCESS		reservation conflict
	 *	EINVAL		not applicable or HBA does not provide info.
	 *	EIO		other errors occured.
	 *	ENXIO		internal error/ invalid devi
	 *
	 */
	int (*tg_getvirtgeom)(dev_info_t *devi, cmlb_geom_t *virtgeomp);

	/*
	 * tg_getcapacity
	 *	Report the capacity of the target (in system blocksize,
	 *	DEV_BSIZE) and store the value where capp is pointing to.
	 *
	 * Arguments:
	 *	devi:		pointer to device's dev_info structure.
	 *	capp		pointer to capacity value.
	 *
	 * Return values:
	 *	0		success
	 * 	EINVAL		no media in drive
	 *	EIO		error occured.
	 *	ENOTSUP		target does not support getting capacity info.
	 *	EACCESS		reservation conflict
	 *	ENXIO		internal error/ invalid devi
	 */
	int (*tg_getcapacity)(dev_info_t *devi, diskaddr_t *capp);

	/*
	 * tg_getattribute:
	 * 	Report the information requested on device/media and
	 *	store in area pointed to by tgdevmediainfop
	 *
	 * Arguments:
	 *	devi:		pointer to device's dev_info structure.
	 *	tgattribute	pointer to area for attribute info
	 *
	 * Return values:
	 *	0		success
	 * 	EINVAL		no media in drive
	 *	EIO		error occured.
	 *	ENOTSUP		target does not support getting capacity info.
	 *	EACCESS		reservation conflict
	 *
	 * Return values:
	 *	ENXIO		internal error/ invalid devi
	 *	EACCESS		reservation conflict
	 * 	EINVAL		not applicable
	 * 	EIO		I/O failed
	 */
	int (*tg_getattribute)(dev_info_t *devi, tg_attribute_t
	    *tgattribute);
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
 *			on architecture with VTOC 8 label types.
 *
 *
 *	cmlbhandle	cmlb handle associated with device
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
 *
 */
int
cmlb_attach(dev_info_t *devi, cmlb_tg_ops_t *tgopsp, int device_type,
    int is_removable, char *node_type, int alter_behavior, cmlb_handle_t
    cmlbhandle);


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
 *
 */
int
cmlb_validate(cmlb_handle_t cmlbhandle);

/*
 * cmlb_invalidate:
 *	Invalidate in core label data
 *
 * Arguments:
 *	cmlbhandle	cmlb handle associated with device.
 */
void
cmlb_invalidate(cmlb_handle_t cmlbhandle);


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
    diskaddr_t *startblockp, char **partnamep, uint16_t *tagp);


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
cmlb_ioctl(cmlb_handle_t cmlbhandle, dev_t dev, int cmd, intptr_t arg,
    int flag, cred_t *cred_p, int *rval_p);

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
cmlb_get_devid_block(cmlb_handle_t cmlbhandle, diskaddr_t *devidblockp);


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
cmlb_close(cmlb_handle_t cmlbhandle);

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
cmlb_detach(cmlb_handle_t cmlbhandle);

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
