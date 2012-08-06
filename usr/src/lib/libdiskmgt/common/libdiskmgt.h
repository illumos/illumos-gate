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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2012, Joyent, Inc. All rights reserved.
 */

#ifndef _LIBDISKMGT_H
#define	_LIBDISKMGT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <libnvpair.h>
#include <sys/swap.h>


/*
 * Disk Management Library
 *
 * This library provides a common way to gather information about a system's
 * disks, controllers, and related components.
 *
 *
 * THREADS
 * -------
 *
 * In general all of the functions are thread safe, however there are some
 * specific considerations for getting events.  The dm_get_event function may
 * block the calling thread if no event is currently available.  If another
 * thread calls dm_get_event while a thread is already blocked in this function,
 * the second thread will also block.  When an event arrives and multiple
 * threads are waiting for events, it is undefined which thread will be
 * unblocked and receive the event.  If a callback is used for handling events,
 * this is equivalent to the dm_get_event function, so mixing callbacks and
 * dm_get_event is also nondeterministic.
 *
 *
 * ERRORS
 * ------
 *
 * In general all of the functions take an errno pointer.  This is an integer
 * that will contain 0 if the function succeeded or contains an errno (see
 * errno.h) if there was an error.  If the function returns some data, that
 * return data will generally be null if an error occured (see the API comment
 * for the specific function for details).  Many of the functions take a
 * descriptor and provide more information for that descriptor.  These functions
 * may return an error if the object was removed between the call which obtained
 * the descriptor and the call to get more information about the object (errno
 * will be ENODEV).  Only a few of the possible errno values will be returned;
 * typically:
 *     EPERM       not super-user
 *     ENOMEM      not enough memory
 *     ENODEV      no such device
 *     EINVAL      invalid argument
 *     ENOENT      no event queue has been created
 *
 * Many of the functions require the application to be running as root in order
 * to get complete information.  EPERM will be returned if the application is
 * not running as root.  However, not all of the functions have this requirement
 * (i.e. event handling).
 *
 * It is possible for the system to run out of memory while receiving events.
 * Since event receipt is asyncronous from the dm_get_event call there may not
 * be a thread waiting when the event occurs and ENOMEM is detected.  In this
 * case the event will be lost.  The first call to dm_get_event following this
 * condition will immediately return ENOMEM, even if events are queued.
 * Subsequent calls can return events.  The dm_get_event call will clear the
 * pending ENOMEM condition.  There is no way to know how many events were lost
 * when this situation occurs.  If a thread is waiting when the event arrives
 * and the ENOMEM condition occurs, the call will also return with ENOMEM.
 * There is no way to determine if the system ran out of memory before the
 * dm_get_event call or while the thread was blocked in the dm_get_event call
 * since both conditions cause dm_get_event to return ENOMEM.
 *
 *
 * MEMORY MANAGEMENT
 * -----------------
 *
 * Most of the functions that return data are returning memory that has been
 * allocated and must be freed by the application when no longer needed.  The
 * application should call the proper free function to free the memory.  Most of
 * the functions return either a nvlist or an array of descriptors.  The normal
 * nvlist function (nvlist_free; see libnvpair(3LIB)) can be used to free the
 * simple nvlists.  Other functions are provided to free the more complex data
 * structures.
 *
 * The following list shows the functions that return allocated memory and the
 * corresponding function to free the memory:
 *     dm_get_descriptors            dm_free_descriptors
 *     dm_get_associated_descriptors dm_free_descriptors
 *     dm_get_descriptor_by_name     dm_free_descriptor
 *     dm_get_name                   dm_free_name
 *     dm_get_attributes             nvlist_free
 *     dm_get_stats	          nvlist_free
 *     dm_get_event                  nvlist_free
 *
 *
 * EVENTS
 * ------
 *
 * Event information is returned as a nvlist.  It may be possible to return more
 * information about events over time, especially information about what has
 * changed.  However, that may not always be the case, so by using an nvlist we
 * have a very generic event indication.  At a minimum the event will return the
 * name of the device, the type of device (see dm_desc_type_t) and the type of
 * event.  The event type is a string which can currently be; add, remove,
 * change.
 *
 * If a drive goes up or down this could be returned as event type "change".
 * The application could get the drive information to see that the "status"
 * attribute has changed value (ideally the event would include an attribute
 * with the name of the changed attribute as the value).  Although the API can
 * return events for all drive related changes, events will not necessarily be
 * delivered for all changes unless the system generates those events.
 *
 *
 * Controller/HBAs
 * ---------------
 *
 * In general the API means "the parent node of the drive in the device tree"
 * where the word "controller" is used.  This can actually be either the HBA or
 * the drive controller depending on the type of the drive.
 *
 * Drives can be connected to their controller(s) in three different ways:
 *     single controller
 *     multiple controllers
 *     multiple controllers with mpxio
 * These cases will lead to different information being available for the
 * configuration.  The two interesting cases are multi-path with and without
 * mpxio.  With mpxio the drive will have a unique name and a single controller
 * (scsi_vhci).  The physical controllers, the paths to the drive, can be
 * obtained by calling dm_get_associated_descriptors with a drive descriptor and
 * a type of DM_PATH.  This will only return these physical paths when MPXIO, or
 * possibly some future similar feature, is controlling the drive.
 *
 * Without mpxio the drive does not have a unique public name (in all cases the
 * alias(es) of the drive can be determined by calling
 * dm_get_associated_descriptors to get the DM_ALIAS descriptors.  There will be
 * more than one controller returned from dm_get_associated_descriptors when
 * called with a type of DM_CONTROLLER.  The controllers for each of the aliases
 * will be returned in the same order as the aliases descriptors.  For example,
 * a drive with two paths has the aliases c5t3d2 and c7t1d0.  There will be two
 * controllers returned; the first corresponds to c5 and the second corresponds
 * to c7.
 *
 * In the multi-path, non-mpxio case the drive has more than one alias.
 * Although most of the drive attributes are represented on the drive (see
 * dm_get_attributes) there can be some different attributes for the different
 * aliases for the drive.  Use dm_get_associated_descriptors to get the DM_ALIAS
 * descriptors which can then be used to obtain these attributes.  Use of this
 * algorithm is not restricted to the multi-path, non-mpxio case.  For example,
 * it can be used to get the target/lun for a SCSI drive with a single path.
 */

/*
 * Holds all the data regarding the device.
 * Private to libdiskmgt. Must use dm_xxx functions to set/get data.
 */
typedef uint64_t  dm_descriptor_t;

typedef enum {
	DM_WHO_MKFS = 0,
	DM_WHO_ZPOOL,
	DM_WHO_ZPOOL_FORCE,
	DM_WHO_FORMAT,
	DM_WHO_SWAP,
	DM_WHO_DUMP,
	DM_WHO_ZPOOL_SPARE
} dm_who_type_t;

/*
 * The API uses a "descriptor" to identify the managed objects such as drives,
 * controllers, media, slices, partitions, paths and buses.  The descriptors are
 * opaque and are only returned or used as parameters to the other functions in
 * the API.  The descriptor definition is a typedef to dm_descriptor_t.
 *
 * Applications call either the dm_get_descriptors or
 * dm_get_associated_descriptors function to obtain a list of descriptors of a
 * specific type.  The application specifies the desired type from the following
 * enumeration:
 */
typedef enum {
    DM_DRIVE = 0,
    DM_CONTROLLER,
    DM_MEDIA,
    DM_SLICE,
    DM_PARTITION,
    DM_PATH,
    DM_ALIAS,
    DM_BUS
} dm_desc_type_t;

/*
 * These descriptors are associated with each other in the following way:
 *
 *                      alias                 partition
 *     _                    \                /   |
 *    / \                    \              /    |
 *    \ /                     \            /     |
 *    bus --- controller --- drive --- media     |
 *                     |      /            \     |
 *                     |     /              \    |
 *                     |    /                \   |
 *                      path                  slice
 *
 * The dm_get_associated_descriptors function can be used get the descriptors
 * associated with a given descriptor.  The dm_get_associated_types function can
 * be used to find the types that can be associated with a given type.
 *
 * The attributes and values for these objects are described using a list of
 * name/value pairs (see libnvpair(3LIB) and the specific comments for each
 * function in the API section of this document).
 *
 * Drives and media have a type which are defined as the following enumerations.
 * There could be additional types added to these enumerations as new drive and
 * media types are supported by the system.
 */

typedef enum {
    DM_DT_UNKNOWN = 0,
    DM_DT_FIXED,
    DM_DT_ZIP,
    DM_DT_JAZ,
    DM_DT_FLOPPY,
    DM_DT_MO_ERASABLE,
    DM_DT_MO_WRITEONCE,
    DM_DT_AS_MO,
    DM_DT_CDROM,
    DM_DT_CDR,
    DM_DT_CDRW,
    DM_DT_DVDROM,
    DM_DT_DVDR,
    DM_DT_DVDRAM,
    DM_DT_DVDRW,
    DM_DT_DDCDROM,
    DM_DT_DDCDR,
    DM_DT_DDCDRW
} dm_drive_type_t;

typedef enum {
    DM_MT_UNKNOWN = 0,
    DM_MT_FIXED,
    DM_MT_FLOPPY,
    DM_MT_CDROM,
    DM_MT_ZIP,
    DM_MT_JAZ,
    DM_MT_CDR,
    DM_MT_CDRW,
    DM_MT_DVDROM,
    DM_MT_DVDR,
    DM_MT_DVDRAM,
    DM_MT_MO_ERASABLE,
    DM_MT_MO_WRITEONCE,
    DM_MT_AS_MO
} dm_media_type_t;

#define	DM_FILTER_END	-1

/*
 * The dm_get_stats function takes a stat_type argument for the specific sample
 * to get for the descriptor.  The following enums specify the drive and slice
 * stat types.
 */
/* drive stat name */
typedef enum {
    DM_DRV_STAT_PERFORMANCE = 0,
    DM_DRV_STAT_DIAGNOSTIC,
    DM_DRV_STAT_TEMPERATURE
} dm_drive_stat_t;

/* slice stat name */
typedef enum {
    DM_SLICE_STAT_USE = 0
} dm_slice_stat_t;

/* partition type */
typedef enum {
	DM_PRIMARY = 0,
	DM_EXTENDED,
	DM_LOGICAL
} dm_partition_type_t;

/* attribute definitions */

/* drive */
#define	DM_DISK_UP		1
#define	DM_DISK_DOWN		0

#define	DM_CLUSTERED		"clustered"
#define	DM_DRVTYPE		"drvtype"
#define	DM_FAILING		"failing"
#define	DM_LOADED		"loaded"	/* also in media */
#define	DM_NDNRERRS		"ndevice_not_ready_errors"
#define	DM_NBYTESREAD		"nbytes_read"
#define	DM_NBYTESWRITTEN	"nbytes_written"
#define	DM_NHARDERRS		"nhard_errors"
#define	DM_NILLREQERRS		"nillegal_req_errors"
#define	DM_NMEDIAERRS		"nmedia_errors"
#define	DM_NNODEVERRS		"nno_dev_errors"
#define	DM_NREADOPS		"nread_ops"
#define	DM_NRECOVERRS		"nrecoverable_errors"
#define	DM_NSOFTERRS		"nsoft_errors"
#define	DM_NTRANSERRS		"ntransport_errors"
#define	DM_NWRITEOPS		"nwrite_ops"
#define	DM_OPATH		"opath"
#define	DM_PRODUCT_ID		"product_id"
#define	DM_REMOVABLE		"removable"	/* also in media */
#define	DM_RPM			"rpm"
#define	DM_SOLIDSTATE		"solid_state"
#define	DM_STATUS		"status"
#define	DM_SYNC_SPEED		"sync_speed"
#define	DM_TEMPERATURE		"temperature"
#define	DM_VENDOR_ID		"vendor_id"
#define	DM_WIDE			"wide"		/* also on controller */
#define	DM_WWN			"wwn"

/* bus */
#define	DM_BTYPE		"btype"
#define	DM_CLOCK		"clock"		/* also on controller */
#define	DM_PNAME		"pname"

/* controller */
#define	DM_FAST			"fast"
#define	DM_FAST20		"fast20"
#define	DM_FAST40		"fast40"
#define	DM_FAST80		"fast80"
#define	DM_MULTIPLEX		"multiplex"
#define	DM_PATH_STATE		"path_state"

#define	DM_CTYPE_ATA		"ata"
#define	DM_CTYPE_SCSI		"scsi"
#define	DM_CTYPE_FIBRE		"fibre channel"
#define	DM_CTYPE_USB		"usb"
#define	DM_CTYPE_UNKNOWN	"unknown"

/* media */
#define	DM_BLOCKSIZE		"blocksize"
#define	DM_FDISK		"fdisk"
#define	DM_MTYPE		"mtype"
#define	DM_NACTUALCYLINDERS	"nactual_cylinders"
#define	DM_NALTCYLINDERS	"nalt_cylinders"
#define	DM_NCYLINDERS		"ncylinders"
#define	DM_NHEADS		"nheads"
#define	DM_NPHYSCYLINDERS	"nphys_cylinders"
#define	DM_NSECTORS		"nsectors"	/* also in partition */
#define	DM_SIZE			"size"		/* also in slice */
#define	DM_NACCESSIBLE		"naccessible"
#define	DM_LABEL		"label"

/* partition */
#define	DM_BCYL			"bcyl"
#define	DM_BHEAD		"bhead"
#define	DM_BOOTID		"bootid"
#define	DM_BSECT		"bsect"
#define	DM_ECYL			"ecyl"
#define	DM_EHEAD		"ehead"
#define	DM_ESECT		"esect"
#define	DM_PTYPE		"ptype" /* this references the partition id */
#define	DM_PARTITION_TYPE	"part_type" /* primary, extended, logical */
#define	DM_RELSECT		"relsect"

/* slice */
#define	DM_DEVICEID		"deviceid"
#define	DM_DEVT			"devt"
#define	DM_INDEX		"index"
#define	DM_EFI_NAME		"name"
#define	DM_MOUNTPOINT		"mountpoint"
#define	DM_LOCALNAME		"localname"
#define	DM_START		"start"
#define	DM_TAG			"tag"
#define	DM_FLAG			"flag"
#define	DM_EFI			"efi"	/* also on media */
#define	DM_USED_BY		"used_by"
#define	DM_USED_NAME		"used_name"
#define	DM_USE_MOUNT		"mount"
#define	DM_USE_SVM		"svm"
#define	DM_USE_LU		"lu"
#define	DM_USE_DUMP		"dump"
#define	DM_USE_VXVM		"vxvm"
#define	DM_USE_FS		"fs"
#define	DM_USE_VFSTAB		"vfstab"
#define	DM_USE_EXPORTED_ZPOOL	"exported_zpool"
#define	DM_USE_ACTIVE_ZPOOL	"active_zpool"
#define	DM_USE_SPARE_ZPOOL	"spare_zpool"
#define	DM_USE_L2CACHE_ZPOOL	"l2cache_zpool"

/* event */
#define	DM_EV_NAME		"name"
#define	DM_EV_DTYPE		"edtype"
#define	DM_EV_TYPE		"evtype"
#define	DM_EV_TADD		"add"
#define	DM_EV_TREMOVE		"remove"
#define	DM_EV_TCHANGE		"change"

/* findisks */
#define	DM_CTYPE		"ctype"
#define	DM_LUN			"lun"
#define	DM_TARGET		"target"

#define	NOINUSE_SET	getenv("NOINUSE_CHECK") != NULL

void			dm_free_descriptors(dm_descriptor_t *desc_list);
void			dm_free_descriptor(dm_descriptor_t desc);
void			dm_free_name(char *name);
void			dm_free_swapentries(swaptbl_t *);

dm_descriptor_t		*dm_get_descriptors(dm_desc_type_t type, int filter[],
			    int *errp);
dm_descriptor_t		*dm_get_associated_descriptors(dm_descriptor_t desc,
			    dm_desc_type_t type, int *errp);
dm_desc_type_t		*dm_get_associated_types(dm_desc_type_t type);
dm_descriptor_t		dm_get_descriptor_by_name(dm_desc_type_t desc_type,
			    char *name, int *errp);
char			*dm_get_name(dm_descriptor_t desc, int *errp);
dm_desc_type_t		dm_get_type(dm_descriptor_t desc);
nvlist_t		*dm_get_attributes(dm_descriptor_t desc, int *errp);
nvlist_t		*dm_get_stats(dm_descriptor_t desc, int stat_type,
			    int *errp);
void			dm_init_event_queue(void(*callback)(nvlist_t *, int),
			    int *errp);
nvlist_t		*dm_get_event(int *errp);
void			dm_get_slices(char *drive, dm_descriptor_t **slices,
			    int *errp);
void			dm_get_slice_stats(char *slice, nvlist_t **dev_stats,
			    int *errp);
int			dm_get_swapentries(swaptbl_t **, int *);
void			dm_get_usage_string(char *who, char *data, char **msg);
int			dm_inuse(char *dev_name, char **msg, dm_who_type_t who,
			    int *errp);
int			dm_inuse_swap(const char *dev_name, int *errp);
int			dm_isoverlapping(char *dev_name, char **msg, int *errp);

#ifdef __cplusplus
}
#endif

#endif /* _LIBDISKMGT_H */
