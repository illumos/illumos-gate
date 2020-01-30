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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2019, Joyent, Inc.
 */

/*
 * Virtual disk server
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/crc32.h>
#include <sys/ddi.h>
#include <sys/dkio.h>
#include <sys/file.h>
#include <sys/fs/hsfs_isospec.h>
#include <sys/mdeg.h>
#include <sys/mhd.h>
#include <sys/modhash.h>
#include <sys/note.h>
#include <sys/pathname.h>
#include <sys/sdt.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sysmacros.h>
#include <sys/vio_common.h>
#include <sys/vio_util.h>
#include <sys/vdsk_mailbox.h>
#include <sys/vdsk_common.h>
#include <sys/vtoc.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/ontrap.h>
#include <vm/seg_map.h>

#define	ONE_MEGABYTE	(1ULL << 20)
#define	ONE_GIGABYTE	(1ULL << 30)
#define	ONE_TERABYTE	(1ULL << 40)

/* Virtual disk server initialization flags */
#define	VDS_LDI			0x01
#define	VDS_MDEG		0x02

/* Virtual disk server tunable parameters */
#define	VDS_RETRIES		5
#define	VDS_LDC_DELAY		1000 /* 1 msecs */
#define	VDS_DEV_DELAY		10000000 /* 10 secs */
#define	VDS_NCHAINS		32

/* Identification parameters for MD, synthetic dkio(7i) structures, etc. */
#define	VDS_NAME		"virtual-disk-server"

#define	VD_NAME			"vd"
#define	VD_VOLUME_NAME		"vdisk"
#define	VD_ASCIILABEL		"Virtual Disk"

#define	VD_CHANNEL_ENDPOINT	"channel-endpoint"
#define	VD_ID_PROP		"id"
#define	VD_BLOCK_DEVICE_PROP	"vds-block-device"
#define	VD_BLOCK_DEVICE_OPTS	"vds-block-device-opts"
#define	VD_REG_PROP		"reg"

/* Virtual disk initialization flags */
#define	VD_DISK_READY		0x01
#define	VD_LOCKING		0x02
#define	VD_LDC			0x04
#define	VD_DRING		0x08
#define	VD_SID			0x10
#define	VD_SEQ_NUM		0x20
#define	VD_SETUP_ERROR		0x40

/* Number of backup labels */
#define	VD_DSKIMG_NUM_BACKUP	5

/* Timeout for SCSI I/O */
#define	VD_SCSI_RDWR_TIMEOUT	30	/* 30 secs */

/*
 * Default number of threads for the I/O queue. In many cases, we will not
 * receive more than 8 I/O requests at the same time. However there are
 * cases (for example during the OS installation) where we can have a lot
 * more (up to the limit of the DRing size).
 */
#define	VD_IOQ_NTHREADS		8

/* Maximum number of logical partitions */
#define	VD_MAXPART	(NDKMAP + 1)

/*
 * By Solaris convention, slice/partition 2 represents the entire disk;
 * unfortunately, this convention does not appear to be codified.
 */
#define	VD_ENTIRE_DISK_SLICE	2

/* Logical block address for EFI */
#define	VD_EFI_LBA_GPT		1	/* LBA of the GPT */
#define	VD_EFI_LBA_GPE		2	/* LBA of the GPE */

#define	VD_EFI_DEV_SET(dev, vdsk, ioctl)	\
	VDSK_EFI_DEV_SET(dev, vdsk, ioctl,	\
	    (vdsk)->vdisk_bsize, (vdsk)->vdisk_size)

/*
 * Flags defining the behavior for flushing asynchronous writes used to
 * performed some write I/O requests.
 *
 * The VD_AWFLUSH_IMMEDIATE enables immediate flushing of asynchronous
 * writes. This ensures that data are committed to the backend when the I/O
 * request reply is sent to the guest domain so this prevents any data to
 * be lost in case a service domain unexpectedly crashes.
 *
 * The flag VD_AWFLUSH_DEFER indicates that flushing is deferred to another
 * thread while the request is immediatly marked as completed. In that case,
 * a guest domain can a receive a reply that its write request is completed
 * while data haven't been flushed to disk yet.
 *
 * Flags VD_AWFLUSH_IMMEDIATE and VD_AWFLUSH_DEFER are mutually exclusive.
 */
#define	VD_AWFLUSH_IMMEDIATE	0x01	/* immediate flushing */
#define	VD_AWFLUSH_DEFER	0x02	/* defer flushing */
#define	VD_AWFLUSH_GROUP	0x04	/* group requests before flushing */

/* Driver types */
typedef enum vd_driver {
	VD_DRIVER_UNKNOWN = 0,	/* driver type unknown  */
	VD_DRIVER_DISK,		/* disk driver */
	VD_DRIVER_VOLUME	/* volume driver */
} vd_driver_t;

#define	VD_DRIVER_NAME_LEN	64

#define	VDS_NUM_DRIVERS	(sizeof (vds_driver_types) / sizeof (vd_driver_type_t))

typedef struct vd_driver_type {
	char name[VD_DRIVER_NAME_LEN];	/* driver name */
	vd_driver_t type;		/* driver type (disk or volume) */
} vd_driver_type_t;

/*
 * There is no reliable way to determine if a device is representing a disk
 * or a volume, especially with pseudo devices. So we maintain a list of well
 * known drivers and the type of device they represent (either a disk or a
 * volume).
 *
 * The list can be extended by adding a "driver-type-list" entry in vds.conf
 * with the following syntax:
 *
 *	driver-type-list="<driver>:<type>", ... ,"<driver>:<type>";
 *
 * Where:
 *	<driver> is the name of a driver (limited to 64 characters)
 *	<type> is either the string "disk" or "volume"
 *
 * Invalid entries in "driver-type-list" will be ignored.
 *
 * For example, the following line in vds.conf:
 *
 *	driver-type-list="foo:disk","bar:volume";
 *
 * defines that "foo" is a disk driver, and driver "bar" is a volume driver.
 *
 * When a list is defined in vds.conf, it is checked before the built-in list
 * (vds_driver_types[]) so that any definition from this list can be overriden
 * using vds.conf.
 */
vd_driver_type_t vds_driver_types[] = {
	{ "dad",	VD_DRIVER_DISK },	/* Solaris */
	{ "did",	VD_DRIVER_DISK },	/* Sun Cluster */
	{ "dlmfdrv",	VD_DRIVER_DISK },	/* Hitachi HDLM */
	{ "emcp",	VD_DRIVER_DISK },	/* EMC Powerpath */
	{ "lofi",	VD_DRIVER_VOLUME },	/* Solaris */
	{ "md",		VD_DRIVER_VOLUME },	/* Solaris - SVM */
	{ "sd",		VD_DRIVER_DISK },	/* Solaris */
	{ "ssd",	VD_DRIVER_DISK },	/* Solaris */
	{ "vdc",	VD_DRIVER_DISK },	/* Solaris */
	{ "vxdmp",	VD_DRIVER_DISK },	/* Veritas */
	{ "vxio",	VD_DRIVER_VOLUME },	/* Veritas - VxVM */
	{ "zfs",	VD_DRIVER_VOLUME }	/* Solaris */
};

/* Return a cpp token as a string */
#define	STRINGIZE(token)	#token

/*
 * Print a message prefixed with the current function name to the message log
 * (and optionally to the console for verbose boots); these macros use cpp's
 * concatenation of string literals and C99 variable-length-argument-list
 * macros
 */
#define	PRN(...)	_PRN("?%s():  "__VA_ARGS__, "")
#define	_PRN(format, ...)					\
	cmn_err(CE_CONT, format"%s", __func__, __VA_ARGS__)

/* Return a pointer to the "i"th vdisk dring element */
#define	VD_DRING_ELEM(i)	((vd_dring_entry_t *)(void *)	\
	    (vd->dring + (i)*vd->descriptor_size))

/* Return the virtual disk client's type as a string (for use in messages) */
#define	VD_CLIENT(vd)							\
	(((vd)->xfer_mode == VIO_DESC_MODE) ? "in-band client" :	\
	    (((vd)->xfer_mode == VIO_DRING_MODE_V1_0) ? "dring client" :    \
		(((vd)->xfer_mode == 0) ? "null client" :		\
		    "unsupported client")))

/* Read disk label from a disk image */
#define	VD_DSKIMG_LABEL_READ(vd, labelp) \
	vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BREAD, (caddr_t)labelp, \
	    0, sizeof (struct dk_label))

/* Write disk label to a disk image */
#define	VD_DSKIMG_LABEL_WRITE(vd, labelp)	\
	vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BWRITE, (caddr_t)labelp, \
	    0, sizeof (struct dk_label))

/* Identify if a backend is a disk image */
#define	VD_DSKIMG(vd)	((vd)->vdisk_type == VD_DISK_TYPE_DISK &&	\
	((vd)->file || (vd)->volume))

/* Next index in a write queue */
#define	VD_WRITE_INDEX_NEXT(vd, id)		\
	((((id) + 1) >= vd->dring_len)? 0 : (id) + 1)

/* Message for disk access rights reset failure */
#define	VD_RESET_ACCESS_FAILURE_MSG \
	"Fail to reset disk access rights for disk %s"

/*
 * Specification of an MD node passed to the MDEG to filter any
 * 'vport' nodes that do not belong to the specified node. This
 * template is copied for each vds instance and filled in with
 * the appropriate 'cfg-handle' value before being passed to the MDEG.
 */
static mdeg_prop_spec_t	vds_prop_template[] = {
	{ MDET_PROP_STR,	"name",		VDS_NAME },
	{ MDET_PROP_VAL,	"cfg-handle",	NULL },
	{ MDET_LIST_END,	NULL,		NULL }
};

#define	VDS_SET_MDEG_PROP_INST(specp, val) (specp)[1].ps_val = (val);

/*
 * Matching criteria passed to the MDEG to register interest
 * in changes to 'virtual-device-port' nodes identified by their
 * 'id' property.
 */
static md_prop_match_t	vd_prop_match[] = {
	{ MDET_PROP_VAL,	VD_ID_PROP },
	{ MDET_LIST_END,	NULL }
};

static mdeg_node_match_t vd_match = {"virtual-device-port",
				    vd_prop_match};

/*
 * Options for the VD_BLOCK_DEVICE_OPTS property.
 */
#define	VD_OPT_RDONLY		0x1	/* read-only  */
#define	VD_OPT_SLICE		0x2	/* single slice */
#define	VD_OPT_EXCLUSIVE	0x4	/* exclusive access */

#define	VD_OPTION_NLEN	128

typedef struct vd_option {
	char vdo_name[VD_OPTION_NLEN];
	uint64_t vdo_value;
} vd_option_t;

vd_option_t vd_bdev_options[] = {
	{ "ro",		VD_OPT_RDONLY },
	{ "slice",	VD_OPT_SLICE },
	{ "excl",	VD_OPT_EXCLUSIVE }
};

/* Debugging macros */
#ifdef DEBUG

static int	vd_msglevel = 0;

#define	PR0 if (vd_msglevel > 0)	PRN
#define	PR1 if (vd_msglevel > 1)	PRN
#define	PR2 if (vd_msglevel > 2)	PRN

#define	VD_DUMP_DRING_ELEM(elem)					\
	PR0("dst:%x op:%x st:%u nb:%lx addr:%lx ncook:%u\n",		\
	    elem->hdr.dstate,						\
	    elem->payload.operation,					\
	    elem->payload.status,					\
	    elem->payload.nbytes,					\
	    elem->payload.addr,						\
	    elem->payload.ncookies);

char *
vd_decode_state(int state)
{
	char *str;

#define	CASE_STATE(_s)	case _s: str = #_s; break;

	switch (state) {
	CASE_STATE(VD_STATE_INIT)
	CASE_STATE(VD_STATE_VER)
	CASE_STATE(VD_STATE_ATTR)
	CASE_STATE(VD_STATE_DRING)
	CASE_STATE(VD_STATE_RDX)
	CASE_STATE(VD_STATE_DATA)
	default: str = "unknown"; break;
	}

#undef CASE_STATE

	return (str);
}

void
vd_decode_tag(vio_msg_t *msg)
{
	char *tstr, *sstr, *estr;

#define	CASE_TYPE(_s)	case _s: tstr = #_s; break;

	switch (msg->tag.vio_msgtype) {
	CASE_TYPE(VIO_TYPE_CTRL)
	CASE_TYPE(VIO_TYPE_DATA)
	CASE_TYPE(VIO_TYPE_ERR)
	default: tstr = "unknown"; break;
	}

#undef CASE_TYPE

#define	CASE_SUBTYPE(_s) case _s: sstr = #_s; break;

	switch (msg->tag.vio_subtype) {
	CASE_SUBTYPE(VIO_SUBTYPE_INFO)
	CASE_SUBTYPE(VIO_SUBTYPE_ACK)
	CASE_SUBTYPE(VIO_SUBTYPE_NACK)
	default: sstr = "unknown"; break;
	}

#undef CASE_SUBTYPE

#define	CASE_ENV(_s)	case _s: estr = #_s; break;

	switch (msg->tag.vio_subtype_env) {
	CASE_ENV(VIO_VER_INFO)
	CASE_ENV(VIO_ATTR_INFO)
	CASE_ENV(VIO_DRING_REG)
	CASE_ENV(VIO_DRING_UNREG)
	CASE_ENV(VIO_RDX)
	CASE_ENV(VIO_PKT_DATA)
	CASE_ENV(VIO_DESC_DATA)
	CASE_ENV(VIO_DRING_DATA)
	default: estr = "unknown"; break;
	}

#undef CASE_ENV

	PR1("(%x/%x/%x) message : (%s/%s/%s)",
	    msg->tag.vio_msgtype, msg->tag.vio_subtype,
	    msg->tag.vio_subtype_env, tstr, sstr, estr);
}

#else	/* !DEBUG */

#define	PR0(...)
#define	PR1(...)
#define	PR2(...)

#define	VD_DUMP_DRING_ELEM(elem)

#define	vd_decode_state(_s)	(NULL)
#define	vd_decode_tag(_s)	(NULL)

#endif	/* DEBUG */


/*
 * Soft state structure for a vds instance
 */
typedef struct vds {
	uint_t		initialized;	/* driver inst initialization flags */
	dev_info_t	*dip;		/* driver inst devinfo pointer */
	ldi_ident_t	ldi_ident;	/* driver's identifier for LDI */
	mod_hash_t	*vd_table;	/* table of virtual disks served */
	mdeg_node_spec_t *ispecp;	/* mdeg node specification */
	mdeg_handle_t	mdeg;		/* handle for MDEG operations  */
	vd_driver_type_t *driver_types;	/* extra driver types (from vds.conf) */
	int		num_drivers;	/* num of extra driver types */
} vds_t;

/*
 * Types of descriptor-processing tasks
 */
typedef enum vd_task_type {
	VD_NONFINAL_RANGE_TASK,	/* task for intermediate descriptor in range */
	VD_FINAL_RANGE_TASK,	/* task for last in a range of descriptors */
} vd_task_type_t;

/*
 * Structure describing the task for processing a descriptor
 */
typedef struct vd_task {
	struct vd		*vd;		/* vd instance task is for */
	vd_task_type_t		type;		/* type of descriptor task */
	int			index;		/* dring elem index for task */
	vio_msg_t		*msg;		/* VIO message task is for */
	size_t			msglen;		/* length of message content */
	vd_dring_payload_t	*request;	/* request task will perform */
	struct buf		buf;		/* buf(9s) for I/O request */
	ldc_mem_handle_t	mhdl;		/* task memory handle */
	int			status;		/* status of processing task */
	int	(*completef)(struct vd_task *task); /* completion func ptr */
	uint32_t		write_index;	/* index in the write_queue */
} vd_task_t;

/*
 * Soft state structure for a virtual disk instance
 */
typedef struct vd {
	uint64_t		id;		/* vdisk id */
	uint_t			initialized;	/* vdisk initialization flags */
	uint64_t		operations;	/* bitmask of VD_OPs exported */
	vio_ver_t		version;	/* ver negotiated with client */
	vds_t			*vds;		/* server for this vdisk */
	ddi_taskq_t		*startq;	/* queue for I/O start tasks */
	ddi_taskq_t		*completionq;	/* queue for completion tasks */
	ddi_taskq_t		*ioq;		/* queue for I/O */
	uint32_t		write_index;	/* next write index */
	buf_t			**write_queue;	/* queue for async writes */
	ldi_handle_t		ldi_handle[V_NUMPAR];	/* LDI slice handles */
	char			device_path[MAXPATHLEN + 1]; /* vdisk device */
	dev_t			dev[V_NUMPAR];	/* dev numbers for slices */
	int			open_flags;	/* open flags */
	uint_t			nslices;	/* number of slices we export */
	size_t			vdisk_size;	/* number of blocks in vdisk */
	size_t			vdisk_bsize;	/* blk size of the vdisk */
	vd_disk_type_t		vdisk_type;	/* slice or entire disk */
	vd_disk_label_t		vdisk_label;	/* EFI or VTOC label */
	vd_media_t		vdisk_media;	/* media type of backing dev. */
	boolean_t		is_atapi_dev;	/* Is this an IDE CD-ROM dev? */
	ushort_t		max_xfer_sz;	/* max xfer size in DEV_BSIZE */
	size_t			backend_bsize;	/* blk size of backend device */
	int			vio_bshift;	/* shift for blk convertion */
	boolean_t		volume;		/* is vDisk backed by volume */
	boolean_t		zvol;		/* is vDisk backed by a zvol */
	boolean_t		file;		/* is vDisk backed by a file? */
	boolean_t		scsi;		/* is vDisk backed by scsi? */
	vnode_t			*file_vnode;	/* file vnode */
	size_t			dskimg_size;	/* size of disk image */
	ddi_devid_t		dskimg_devid;	/* devid for disk image */
	int			efi_reserved;	/* EFI reserved slice */
	caddr_t			flabel;		/* fake label for slice type */
	uint_t			flabel_size;	/* fake label size */
	uint_t			flabel_limit;	/* limit of the fake label */
	struct dk_geom		dk_geom;	/* synthetic for slice type */
	struct extvtoc		vtoc;		/* synthetic for slice type */
	vd_slice_t		slices[VD_MAXPART]; /* logical partitions */
	boolean_t		ownership;	/* disk ownership status */
	ldc_status_t		ldc_state;	/* LDC connection state */
	ldc_handle_t		ldc_handle;	/* handle for LDC comm */
	size_t			max_msglen;	/* largest LDC message len */
	vd_state_t		state;		/* client handshake state */
	uint8_t			xfer_mode;	/* transfer mode with client */
	uint32_t		sid;		/* client's session ID */
	uint64_t		seq_num;	/* message sequence number */
	uint64_t		dring_ident;	/* identifier of dring */
	ldc_dring_handle_t	dring_handle;	/* handle for dring ops */
	uint32_t		descriptor_size;	/* num bytes in desc */
	uint32_t		dring_len;	/* number of dring elements */
	uint8_t			dring_mtype;	/* dring mem map type */
	caddr_t			dring;		/* address of dring */
	caddr_t			vio_msgp;	/* vio msg staging buffer */
	vd_task_t		inband_task;	/* task for inband descriptor */
	vd_task_t		*dring_task;	/* tasks dring elements */

	kmutex_t		lock;		/* protects variables below */
	boolean_t		enabled;	/* is vdisk enabled? */
	boolean_t		reset_state;	/* reset connection state? */
	boolean_t		reset_ldc;	/* reset LDC channel? */
} vd_t;

/*
 * Macros to manipulate the fake label (flabel) for single slice disks.
 *
 * If we fake a VTOC label then the fake label consists of only one block
 * containing the VTOC label (struct dk_label).
 *
 * If we fake an EFI label then the fake label consists of a blank block
 * followed by a GPT (efi_gpt_t) and a GPE (efi_gpe_t).
 *
 */
#define	VD_LABEL_VTOC_SIZE(lba)					\
	P2ROUNDUP(sizeof (struct dk_label), (lba))

#define	VD_LABEL_EFI_SIZE(lba)					\
	P2ROUNDUP(2 * (lba) + sizeof (efi_gpe_t) * VD_MAXPART,	\
	    (lba))

#define	VD_LABEL_VTOC(vd)	\
		((struct dk_label *)(void *)((vd)->flabel))

#define	VD_LABEL_EFI_GPT(vd, lba)	\
		((efi_gpt_t *)(void *)((vd)->flabel + (lba)))
#define	VD_LABEL_EFI_GPE(vd, lba)	\
		((efi_gpe_t *)(void *)((vd)->flabel + 2 * (lba)))


typedef struct vds_operation {
	char	*namep;
	uint8_t	operation;
	int	(*start)(vd_task_t *task);
	int	(*complete)(vd_task_t *task);
} vds_operation_t;

typedef struct vd_ioctl {
	uint8_t		operation;		/* vdisk operation */
	const char	*operation_name;	/* vdisk operation name */
	size_t		nbytes;			/* size of operation buffer */
	int		cmd;			/* corresponding ioctl cmd */
	const char	*cmd_name;		/* ioctl cmd name */
	void		*arg;			/* ioctl cmd argument */
	/* convert input vd_buf to output ioctl_arg */
	int		(*copyin)(void *vd_buf, size_t, void *ioctl_arg);
	/* convert input ioctl_arg to output vd_buf */
	void		(*copyout)(void *ioctl_arg, void *vd_buf);
	/* write is true if the operation writes any data to the backend */
	boolean_t	write;
} vd_ioctl_t;

/* Define trivial copyin/copyout conversion function flag */
#define	VD_IDENTITY_IN	((int (*)(void *, size_t, void *))-1)
#define	VD_IDENTITY_OUT	((void (*)(void *, void *))-1)


static int	vds_ldc_retries = VDS_RETRIES;
static int	vds_ldc_delay = VDS_LDC_DELAY;
static int	vds_dev_retries = VDS_RETRIES;
static int	vds_dev_delay = VDS_DEV_DELAY;
static void	*vds_state;

static short	vd_scsi_rdwr_timeout = VD_SCSI_RDWR_TIMEOUT;
static int	vd_scsi_debug = USCSI_SILENT;

/*
 * Number of threads in the taskq handling vdisk I/O. This can be set up to
 * the size of the DRing which is the maximum number of I/O we can receive
 * in parallel. Note that using a high number of threads can improve performance
 * but this is going to consume a lot of resources if there are many vdisks.
 */
static int	vd_ioq_nthreads = VD_IOQ_NTHREADS;

/*
 * Tunable to define the behavior for flushing asynchronous writes used to
 * performed some write I/O requests. The default behavior is to group as
 * much asynchronous writes as possible and to flush them immediatly.
 *
 * If the tunable is set to 0 then explicit flushing is disabled. In that
 * case, data will be flushed by traditional mechanism (like fsflush) but
 * this might not happen immediatly.
 *
 */
static int	vd_awflush = VD_AWFLUSH_IMMEDIATE | VD_AWFLUSH_GROUP;

/*
 * Tunable to define the behavior of the service domain if the vdisk server
 * fails to reset disk exclusive access when a LDC channel is reset. When a
 * LDC channel is reset the vdisk server will try to reset disk exclusive
 * access by releasing any SCSI-2 reservation or resetting the disk. If these
 * actions fail then the default behavior (vd_reset_access_failure = 0) is to
 * print a warning message. This default behavior can be changed by setting
 * the vd_reset_access_failure variable to A_REBOOT (= 0x1) and that will
 * cause the service domain to reboot, or A_DUMP (= 0x5) and that will cause
 * the service domain to panic. In both cases, the reset of the service domain
 * should trigger a reset SCSI buses and hopefully clear any SCSI-2 reservation.
 */
static int	vd_reset_access_failure = 0;

/*
 * Tunable for backward compatibility. When this variable is set to B_TRUE,
 * all disk volumes (ZFS, SVM, VxvM volumes) will be exported as single
 * slice disks whether or not they have the "slice" option set. This is
 * to provide a simple backward compatibility mechanism when upgrading
 * the vds driver and using a domain configuration created before the
 * "slice" option was available.
 */
static boolean_t vd_volume_force_slice = B_FALSE;

/*
 * The label of disk images created with some earlier versions of the virtual
 * disk software is not entirely correct and have an incorrect v_sanity field
 * (usually 0) instead of VTOC_SANE. This creates a compatibility problem with
 * these images because we are now validating that the disk label (and the
 * sanity) is correct when a disk image is opened.
 *
 * This tunable is set to false to not validate the sanity field and ensure
 * compatibility. If the tunable is set to true, we will do a strict checking
 * of the sanity but this can create compatibility problems with old disk
 * images.
 */
static boolean_t vd_dskimg_validate_sanity = B_FALSE;

/*
 * Enables the use of LDC_DIRECT_MAP when mapping in imported descriptor rings.
 */
static boolean_t vd_direct_mapped_drings = B_TRUE;

/*
 * When a backend is exported as a single-slice disk then we entirely fake
 * its disk label. So it can be exported either with a VTOC label or with
 * an EFI label. If vd_slice_label is set to VD_DISK_LABEL_VTOC then all
 * single-slice disks will be exported with a VTOC label; and if it is set
 * to VD_DISK_LABEL_EFI then all single-slice disks will be exported with
 * an EFI label.
 *
 * If vd_slice_label is set to VD_DISK_LABEL_UNK and the backend is a disk
 * or volume device then it will be exported with the same type of label as
 * defined on the device. Otherwise if the backend is a file then it will
 * exported with the disk label type set in the vd_file_slice_label variable.
 *
 * Note that if the backend size is greater than 1TB then it will always be
 * exported with an EFI label no matter what the setting is.
 */
static vd_disk_label_t vd_slice_label = VD_DISK_LABEL_UNK;

static vd_disk_label_t vd_file_slice_label = VD_DISK_LABEL_VTOC;

/*
 * Tunable for backward compatibility. If this variable is set to B_TRUE then
 * single-slice disks are exported as disks with only one slice instead of
 * faking a complete disk partitioning.
 */
static boolean_t vd_slice_single_slice = B_FALSE;

/*
 * Supported protocol version pairs, from highest (newest) to lowest (oldest)
 *
 * Each supported major version should appear only once, paired with (and only
 * with) its highest supported minor version number (as the protocol requires
 * supporting all lower minor version numbers as well)
 */
static const vio_ver_t	vds_version[] = {{1, 1}};
static const size_t	vds_num_versions =
    sizeof (vds_version)/sizeof (vds_version[0]);

static void vd_free_dring_task(vd_t *vdp);
static int vd_setup_vd(vd_t *vd);
static int vd_setup_single_slice_disk(vd_t *vd);
static int vd_setup_slice_image(vd_t *vd);
static int vd_setup_disk_image(vd_t *vd);
static int vd_backend_check_size(vd_t *vd);
static boolean_t vd_enabled(vd_t *vd);
static ushort_t vd_lbl2cksum(struct dk_label *label);
static int vd_dskimg_validate_geometry(vd_t *vd);
static boolean_t vd_dskimg_is_iso_image(vd_t *vd);
static void vd_set_exported_operations(vd_t *vd);
static void vd_reset_access(vd_t *vd);
static int vd_backend_ioctl(vd_t *vd, int cmd, caddr_t arg);
static int vds_efi_alloc_and_read(vd_t *, efi_gpt_t **, efi_gpe_t **);
static void vds_efi_free(vd_t *, efi_gpt_t *, efi_gpe_t *);
static void vds_driver_types_free(vds_t *vds);
static void vd_vtocgeom_to_label(struct extvtoc *vtoc, struct dk_geom *geom,
    struct dk_label *label);
static void vd_label_to_vtocgeom(struct dk_label *label, struct extvtoc *vtoc,
    struct dk_geom *geom);
static boolean_t vd_slice_geom_isvalid(vd_t *vd, struct dk_geom *geom);
static boolean_t vd_slice_vtoc_isvalid(vd_t *vd, struct extvtoc *vtoc);

extern int is_pseudo_device(dev_info_t *);

/*
 * Function:
 *	vd_get_readable_size
 *
 * Description:
 *	Convert a given size in bytes to a human readable format in
 *	kilobytes, megabytes, gigabytes or terabytes.
 *
 * Parameters:
 *	full_size	- the size to convert in bytes.
 *	size		- the converted size.
 *	unit		- the unit of the converted size: 'K' (kilobyte),
 *			  'M' (Megabyte), 'G' (Gigabyte), 'T' (Terabyte).
 *
 * Return Code:
 *	none
 */
static void
vd_get_readable_size(size_t full_size, size_t *size, char *unit)
{
	if (full_size < (1ULL << 20)) {
		*size = full_size >> 10;
		*unit = 'K'; /* Kilobyte */
	} else if (full_size < (1ULL << 30)) {
		*size = full_size >> 20;
		*unit = 'M'; /* Megabyte */
	} else if (full_size < (1ULL << 40)) {
		*size = full_size >> 30;
		*unit = 'G'; /* Gigabyte */
	} else {
		*size = full_size >> 40;
		*unit = 'T'; /* Terabyte */
	}
}

/*
 * Function:
 *	vd_dskimg_io_params
 *
 * Description:
 *	Convert virtual disk I/O parameters (slice, block, length) to
 *	(offset, length) relative to the disk image and according to
 *	the virtual disk partitioning.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	slice		- slice to which is the I/O parameters apply.
 *			  VD_SLICE_NONE indicates that parameters are
 *			  are relative to the entire virtual disk.
 *	blkp		- pointer to the starting block relative to the
 *			  slice; return the starting block relative to
 *			  the disk image.
 *	lenp		- pointer to the number of bytes requested; return
 *			  the number of bytes that can effectively be used.
 *
 * Return Code:
 *	0		- I/O parameters have been successfully converted;
 *			  blkp and lenp point to the converted values.
 *	ENODATA		- no data are available for the given I/O parameters;
 *			  This occurs if the starting block is past the limit
 *			  of the slice.
 *	EINVAL		- I/O parameters are invalid.
 */
static int
vd_dskimg_io_params(vd_t *vd, int slice, size_t *blkp, size_t *lenp)
{
	size_t blk = *blkp;
	size_t len = *lenp;
	size_t offset, maxlen;

	ASSERT(vd->file || VD_DSKIMG(vd));
	ASSERT(len > 0);
	ASSERT(vd->vdisk_bsize == DEV_BSIZE);

	/*
	 * If a file is exported as a slice then we don't care about the vtoc.
	 * In that case, the vtoc is a fake mainly to make newfs happy and we
	 * handle any I/O as a raw disk access so that we can have access to the
	 * entire backend.
	 */
	if (vd->vdisk_type == VD_DISK_TYPE_SLICE || slice == VD_SLICE_NONE) {
		/* raw disk access */
		offset = blk * DEV_BSIZE;
		if (offset >= vd->dskimg_size) {
			/* offset past the end of the disk */
			PR0("offset (0x%lx) >= size (0x%lx)",
			    offset, vd->dskimg_size);
			return (ENODATA);
		}
		maxlen = vd->dskimg_size - offset;
	} else {
		ASSERT(slice >= 0 && slice < V_NUMPAR);

		/*
		 * v1.0 vDisk clients depended on the server not verifying
		 * the label of a unformatted disk.  This "feature" is
		 * maintained for backward compatibility but all versions
		 * from v1.1 onwards must do the right thing.
		 */
		if (vd->vdisk_label == VD_DISK_LABEL_UNK &&
		    vio_ver_is_supported(vd->version, 1, 1)) {
			(void) vd_dskimg_validate_geometry(vd);
			if (vd->vdisk_label == VD_DISK_LABEL_UNK) {
				PR0("Unknown disk label, can't do I/O "
				    "from slice %d", slice);
				return (EINVAL);
			}
		}

		if (vd->vdisk_label == VD_DISK_LABEL_VTOC) {
			ASSERT(vd->vtoc.v_sectorsz == DEV_BSIZE);
		} else {
			ASSERT(vd->vdisk_label == VD_DISK_LABEL_EFI);
		}

		if (blk >= vd->slices[slice].nblocks) {
			/* address past the end of the slice */
			PR0("req_addr (0x%lx) >= psize (0x%lx)",
			    blk, vd->slices[slice].nblocks);
			return (ENODATA);
		}

		offset = (vd->slices[slice].start + blk) * DEV_BSIZE;
		maxlen = (vd->slices[slice].nblocks - blk) * DEV_BSIZE;
	}

	/*
	 * If the requested size is greater than the size
	 * of the partition, truncate the read/write.
	 */
	if (len > maxlen) {
		PR0("I/O size truncated to %lu bytes from %lu bytes",
		    maxlen, len);
		len = maxlen;
	}

	/*
	 * We have to ensure that we are reading/writing into the mmap
	 * range. If we have a partial disk image (e.g. an image of
	 * s0 instead s2) the system can try to access slices that
	 * are not included into the disk image.
	 */
	if ((offset + len) > vd->dskimg_size) {
		PR0("offset + nbytes (0x%lx + 0x%lx) > "
		    "dskimg_size (0x%lx)", offset, len, vd->dskimg_size);
		return (EINVAL);
	}

	*blkp = offset / DEV_BSIZE;
	*lenp = len;

	return (0);
}

/*
 * Function:
 *	vd_dskimg_rw
 *
 * Description:
 *	Read or write to a disk image. It handles the case where the disk
 *	image is a file or a volume exported as a full disk or a file
 *	exported as single-slice disk. Read or write to volumes exported as
 *	single slice disks are done by directly using the ldi interface.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	slice		- slice on which the operation is performed,
 *			  VD_SLICE_NONE indicates that the operation
 *			  is done using an absolute disk offset.
 *	operation	- operation to execute: read (VD_OP_BREAD) or
 *			  write (VD_OP_BWRITE).
 *	data		- buffer where data are read to or written from.
 *	blk		- starting block for the operation.
 *	len		- number of bytes to read or write.
 *
 * Return Code:
 *	n >= 0		- success, n indicates the number of bytes read
 *			  or written.
 *	-1		- error.
 */
static ssize_t
vd_dskimg_rw(vd_t *vd, int slice, int operation, caddr_t data, size_t offset,
    size_t len)
{
	ssize_t resid;
	struct buf buf;
	int status;

	ASSERT(vd->file || VD_DSKIMG(vd));
	ASSERT(len > 0);
	ASSERT(vd->vdisk_bsize == DEV_BSIZE);

	if ((status = vd_dskimg_io_params(vd, slice, &offset, &len)) != 0)
		return ((status == ENODATA)? 0: -1);

	if (vd->volume) {

		bioinit(&buf);
		buf.b_flags	= B_BUSY |
		    ((operation == VD_OP_BREAD)? B_READ : B_WRITE);
		buf.b_bcount	= len;
		buf.b_lblkno	= offset;
		buf.b_edev	= vd->dev[0];
		buf.b_un.b_addr = data;

		/*
		 * We use ldi_strategy() and not ldi_read()/ldi_write() because
		 * the read/write functions of the underlying driver may try to
		 * lock pages of the data buffer, and this requires the data
		 * buffer to be kmem_alloc'ed (and not allocated on the stack).
		 *
		 * Also using ldi_strategy() ensures that writes are immediatly
		 * commited and not cached as this may be the case with
		 * ldi_write() (for example with a ZFS volume).
		 */
		if (ldi_strategy(vd->ldi_handle[0], &buf) != 0) {
			biofini(&buf);
			return (-1);
		}

		if (biowait(&buf) != 0) {
			biofini(&buf);
			return (-1);
		}

		resid = buf.b_resid;
		biofini(&buf);

		ASSERT(resid <= len);
		return (len - resid);
	}

	ASSERT(vd->file);

	status = vn_rdwr((operation == VD_OP_BREAD)? UIO_READ : UIO_WRITE,
	    vd->file_vnode, data, len, offset * DEV_BSIZE, UIO_SYSSPACE, FSYNC,
	    RLIM64_INFINITY, kcred, &resid);

	if (status != 0)
		return (-1);

	return (len);
}

/*
 * Function:
 *	vd_build_default_label
 *
 * Description:
 *	Return a default label for a given disk size. This is used when the disk
 *	does not have a valid VTOC so that the user can get a valid default
 *	configuration. The default label has all slice sizes set to 0 (except
 *	slice 2 which is the entire disk) to force the user to write a valid
 *	label onto the disk image.
 *
 * Parameters:
 *	disk_size	- the disk size in bytes
 *	bsize		- the disk block size in bytes
 *	label		- the returned default label.
 *
 * Return Code:
 *	none.
 */
static void
vd_build_default_label(size_t disk_size, size_t bsize, struct dk_label *label)
{
	size_t size;
	char unit;

	ASSERT(bsize > 0);

	bzero(label, sizeof (struct dk_label));

	/*
	 * Ideally we would like the cylinder size (nsect * nhead) to be the
	 * same whatever the disk size is. That way the VTOC label could be
	 * easily updated in case the disk size is increased (keeping the
	 * same cylinder size allows to preserve the existing partitioning
	 * when updating the VTOC label). But it is not possible to have
	 * a fixed cylinder size and to cover all disk size.
	 *
	 * So we define different cylinder sizes depending on the disk size.
	 * The cylinder size is chosen so that we don't have too few cylinders
	 * for a small disk image, or so many on a big disk image that you
	 * waste space for backup superblocks or cylinder group structures.
	 * Also we must have a resonable number of cylinders and sectors so
	 * that newfs can run using default values.
	 *
	 *	+-----------+--------+---------+--------+
	 *	| disk_size |  < 2MB | 2MB-4GB | >= 8GB |
	 *	+-----------+--------+---------+--------+
	 *	| nhead	    |	 1   |	   1   |    96  |
	 *	| nsect	    |  200   |   600   |   768  |
	 *	+-----------+--------+---------+--------+
	 *
	 * Other parameters are computed from these values:
	 *
	 *	pcyl = disk_size / (nhead * nsect * 512)
	 *	acyl = (pcyl > 2)? 2 : 0
	 *	ncyl = pcyl - acyl
	 *
	 * The maximum number of cylinder is 65535 so this allows to define a
	 * geometry for a disk size up to 65535 * 96 * 768 * 512 = 2.24 TB
	 * which is more than enough to cover the maximum size allowed by the
	 * extended VTOC format (2TB).
	 */

	if (disk_size >= 8 * ONE_GIGABYTE) {

		label->dkl_nhead = 96;
		label->dkl_nsect = 768;

	} else if (disk_size >= 2 * ONE_MEGABYTE) {

		label->dkl_nhead = 1;
		label->dkl_nsect = 600;

	} else {

		label->dkl_nhead = 1;
		label->dkl_nsect = 200;
	}

	label->dkl_pcyl = disk_size /
	    (label->dkl_nsect * label->dkl_nhead * bsize);

	if (label->dkl_pcyl == 0)
		label->dkl_pcyl = 1;

	label->dkl_acyl = 0;

	if (label->dkl_pcyl > 2)
		label->dkl_acyl = 2;

	label->dkl_ncyl = label->dkl_pcyl - label->dkl_acyl;
	label->dkl_write_reinstruct = 0;
	label->dkl_read_reinstruct = 0;
	label->dkl_rpm = 7200;
	label->dkl_apc = 0;
	label->dkl_intrlv = 0;

	PR0("requested disk size: %ld bytes\n", disk_size);
	PR0("setup: ncyl=%d nhead=%d nsec=%d\n", label->dkl_pcyl,
	    label->dkl_nhead, label->dkl_nsect);
	PR0("provided disk size: %ld bytes\n", (uint64_t)
	    (label->dkl_pcyl * label->dkl_nhead *
	    label->dkl_nsect * bsize));

	vd_get_readable_size(disk_size, &size, &unit);

	/*
	 * We must have a correct label name otherwise format(1m) will
	 * not recognized the disk as labeled.
	 */
	(void) snprintf(label->dkl_asciilabel, LEN_DKL_ASCII,
	    "SUN-DiskImage-%ld%cB cyl %d alt %d hd %d sec %d",
	    size, unit,
	    label->dkl_ncyl, label->dkl_acyl, label->dkl_nhead,
	    label->dkl_nsect);

	/* default VTOC */
	label->dkl_vtoc.v_version = V_EXTVERSION;
	label->dkl_vtoc.v_nparts = V_NUMPAR;
	label->dkl_vtoc.v_sanity = VTOC_SANE;
	label->dkl_vtoc.v_part[VD_ENTIRE_DISK_SLICE].p_tag = V_BACKUP;
	label->dkl_map[VD_ENTIRE_DISK_SLICE].dkl_cylno = 0;
	label->dkl_map[VD_ENTIRE_DISK_SLICE].dkl_nblk = label->dkl_ncyl *
	    label->dkl_nhead * label->dkl_nsect;
	label->dkl_magic = DKL_MAGIC;
	label->dkl_cksum = vd_lbl2cksum(label);
}

/*
 * Function:
 *	vd_dskimg_set_vtoc
 *
 * Description:
 *	Set the vtoc of a disk image by writing the label and backup
 *	labels into the disk image backend.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	label		- the data to be written.
 *
 * Return Code:
 *	0		- success.
 *	n > 0		- error, n indicates the errno code.
 */
static int
vd_dskimg_set_vtoc(vd_t *vd, struct dk_label *label)
{
	size_t blk, sec, cyl, head, cnt;

	ASSERT(VD_DSKIMG(vd));

	if (VD_DSKIMG_LABEL_WRITE(vd, label) < 0) {
		PR0("fail to write disk label");
		return (EIO);
	}

	/*
	 * Backup labels are on the last alternate cylinder's
	 * first five odd sectors.
	 */
	if (label->dkl_acyl == 0) {
		PR0("no alternate cylinder, can not store backup labels");
		return (0);
	}

	cyl = label->dkl_ncyl  + label->dkl_acyl - 1;
	head = label->dkl_nhead - 1;

	blk = (cyl * ((label->dkl_nhead * label->dkl_nsect) - label->dkl_apc)) +
	    (head * label->dkl_nsect);

	/*
	 * Write the backup labels. Make sure we don't try to write past
	 * the last cylinder.
	 */
	sec = 1;

	for (cnt = 0; cnt < VD_DSKIMG_NUM_BACKUP; cnt++) {

		if (sec >= label->dkl_nsect) {
			PR0("not enough sector to store all backup labels");
			return (0);
		}

		if (vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BWRITE,
		    (caddr_t)label, blk + sec, sizeof (struct dk_label)) < 0) {
			PR0("error writing backup label at block %lu\n",
			    blk + sec);
			return (EIO);
		}

		PR1("wrote backup label at block %lu\n", blk + sec);

		sec += 2;
	}

	return (0);
}

/*
 * Function:
 *	vd_dskimg_get_devid_block
 *
 * Description:
 *	Return the block number where the device id is stored.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	blkp		- pointer to the block number
 *
 * Return Code:
 *	0		- success
 *	ENOSPC		- disk has no space to store a device id
 */
static int
vd_dskimg_get_devid_block(vd_t *vd, size_t *blkp)
{
	diskaddr_t spc, head, cyl;

	ASSERT(VD_DSKIMG(vd));

	if (vd->vdisk_label == VD_DISK_LABEL_UNK) {
		/*
		 * If no label is defined we don't know where to find
		 * a device id.
		 */
		return (ENOSPC);
	}

	if (vd->vdisk_label == VD_DISK_LABEL_EFI) {
		/*
		 * For an EFI disk, the devid is at the beginning of
		 * the reserved slice
		 */
		if (vd->efi_reserved == -1) {
			PR0("EFI disk has no reserved slice");
			return (ENOSPC);
		}

		*blkp = vd->slices[vd->efi_reserved].start;
		return (0);
	}

	ASSERT(vd->vdisk_label == VD_DISK_LABEL_VTOC);

	/* this geometry doesn't allow us to have a devid */
	if (vd->dk_geom.dkg_acyl < 2) {
		PR0("not enough alternate cylinder available for devid "
		    "(acyl=%u)", vd->dk_geom.dkg_acyl);
		return (ENOSPC);
	}

	/* the devid is in on the track next to the last cylinder */
	cyl = vd->dk_geom.dkg_ncyl + vd->dk_geom.dkg_acyl - 2;
	spc = vd->dk_geom.dkg_nhead * vd->dk_geom.dkg_nsect;
	head = vd->dk_geom.dkg_nhead - 1;

	*blkp = (cyl * (spc - vd->dk_geom.dkg_apc)) +
	    (head * vd->dk_geom.dkg_nsect) + 1;

	return (0);
}

/*
 * Return the checksum of a disk block containing an on-disk devid.
 */
static uint_t
vd_dkdevid2cksum(struct dk_devid *dkdevid)
{
	uint_t chksum, *ip;
	int i;

	chksum = 0;
	ip = (void *)dkdevid;
	for (i = 0; i < ((DEV_BSIZE - sizeof (int)) / sizeof (int)); i++)
		chksum ^= ip[i];

	return (chksum);
}

/*
 * Function:
 *	vd_dskimg_read_devid
 *
 * Description:
 *	Read the device id stored on a disk image.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	devid		- the return address of the device ID.
 *
 * Return Code:
 *	0		- success
 *	EIO		- I/O error while trying to access the disk image
 *	EINVAL		- no valid device id was found
 *	ENOSPC		- disk has no space to store a device id
 */
static int
vd_dskimg_read_devid(vd_t *vd, ddi_devid_t *devid)
{
	struct dk_devid *dkdevid;
	size_t blk;
	uint_t chksum;
	int status, sz;

	ASSERT(vd->vdisk_bsize == DEV_BSIZE);

	if ((status = vd_dskimg_get_devid_block(vd, &blk)) != 0)
		return (status);

	dkdevid = kmem_zalloc(DEV_BSIZE, KM_SLEEP);

	/* get the devid */
	if ((vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BREAD, (caddr_t)dkdevid, blk,
	    DEV_BSIZE)) < 0) {
		PR0("error reading devid block at %lu", blk);
		status = EIO;
		goto done;
	}

	/* validate the revision */
	if ((dkdevid->dkd_rev_hi != DK_DEVID_REV_MSB) ||
	    (dkdevid->dkd_rev_lo != DK_DEVID_REV_LSB)) {
		PR0("invalid devid found at block %lu (bad revision)", blk);
		status = EINVAL;
		goto done;
	}

	/* compute checksum */
	chksum = vd_dkdevid2cksum(dkdevid);

	/* compare the checksums */
	if (DKD_GETCHKSUM(dkdevid) != chksum) {
		PR0("invalid devid found at block %lu (bad checksum)", blk);
		status = EINVAL;
		goto done;
	}

	/* validate the device id */
	if (ddi_devid_valid((ddi_devid_t)&dkdevid->dkd_devid) != DDI_SUCCESS) {
		PR0("invalid devid found at block %lu", blk);
		status = EINVAL;
		goto done;
	}

	PR1("devid read at block %lu", blk);

	sz = ddi_devid_sizeof((ddi_devid_t)&dkdevid->dkd_devid);
	*devid = kmem_alloc(sz, KM_SLEEP);
	bcopy(&dkdevid->dkd_devid, *devid, sz);

done:
	kmem_free(dkdevid, DEV_BSIZE);
	return (status);

}

/*
 * Function:
 *	vd_dskimg_write_devid
 *
 * Description:
 *	Write a device id into disk image.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	devid		- the device ID to store.
 *
 * Return Code:
 *	0		- success
 *	EIO		- I/O error while trying to access the disk image
 *	ENOSPC		- disk has no space to store a device id
 */
static int
vd_dskimg_write_devid(vd_t *vd, ddi_devid_t devid)
{
	struct dk_devid *dkdevid;
	uint_t chksum;
	size_t blk;
	int status;

	ASSERT(vd->vdisk_bsize == DEV_BSIZE);

	if (devid == NULL) {
		/* nothing to write */
		return (0);
	}

	if ((status = vd_dskimg_get_devid_block(vd, &blk)) != 0)
		return (status);

	dkdevid = kmem_zalloc(DEV_BSIZE, KM_SLEEP);

	/* set revision */
	dkdevid->dkd_rev_hi = DK_DEVID_REV_MSB;
	dkdevid->dkd_rev_lo = DK_DEVID_REV_LSB;

	/* copy devid */
	bcopy(devid, &dkdevid->dkd_devid, ddi_devid_sizeof(devid));

	/* compute checksum */
	chksum = vd_dkdevid2cksum(dkdevid);

	/* set checksum */
	DKD_FORMCHKSUM(chksum, dkdevid);

	/* store the devid */
	if ((status = vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BWRITE,
	    (caddr_t)dkdevid, blk, DEV_BSIZE)) < 0) {
		PR0("Error writing devid block at %lu", blk);
		status = EIO;
	} else {
		PR1("devid written at block %lu", blk);
		status = 0;
	}

	kmem_free(dkdevid, DEV_BSIZE);
	return (status);
}

/*
 * Function:
 *	vd_do_scsi_rdwr
 *
 * Description:
 *	Read or write to a SCSI disk using an absolute disk offset.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	operation	- operation to execute: read (VD_OP_BREAD) or
 *			  write (VD_OP_BWRITE).
 *	data		- buffer where data are read to or written from.
 *	blk		- starting block for the operation.
 *	len		- number of bytes to read or write.
 *
 * Return Code:
 *	0		- success
 *	n != 0		- error.
 */
static int
vd_do_scsi_rdwr(vd_t *vd, int operation, caddr_t data, size_t blk, size_t len)
{
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int nsectors, nblk;
	int max_sectors;
	int status, rval;

	ASSERT(!vd->file);
	ASSERT(!vd->volume);
	ASSERT(vd->vdisk_bsize > 0);

	max_sectors = vd->max_xfer_sz;
	nblk = (len / vd->vdisk_bsize);

	if (len % vd->vdisk_bsize != 0)
		return (EINVAL);

	/*
	 * Build and execute the uscsi ioctl.  We build a group0, group1
	 * or group4 command as necessary, since some targets
	 * do not support group1 commands.
	 */
	while (nblk) {

		bzero(&ucmd, sizeof (ucmd));
		bzero(&cdb, sizeof (cdb));

		nsectors = (max_sectors < nblk) ? max_sectors : nblk;

		/*
		 * Some of the optical drives on sun4v machines are ATAPI
		 * devices which use Group 1 Read/Write commands so we need
		 * to explicitly check a flag which is set when a domain
		 * is bound.
		 */
		if (blk < (2 << 20) && nsectors <= 0xff && !vd->is_atapi_dev) {
			FORMG0ADDR(&cdb, blk);
			FORMG0COUNT(&cdb, (uchar_t)nsectors);
			ucmd.uscsi_cdblen = CDB_GROUP0;
		} else if (blk > 0xffffffff) {
			FORMG4LONGADDR(&cdb, blk);
			FORMG4COUNT(&cdb, nsectors);
			ucmd.uscsi_cdblen = CDB_GROUP4;
			cdb.scc_cmd |= SCMD_GROUP4;
		} else {
			FORMG1ADDR(&cdb, blk);
			FORMG1COUNT(&cdb, nsectors);
			ucmd.uscsi_cdblen = CDB_GROUP1;
			cdb.scc_cmd |= SCMD_GROUP1;
		}
		ucmd.uscsi_cdb = (caddr_t)&cdb;
		ucmd.uscsi_bufaddr = data;
		ucmd.uscsi_buflen = nsectors * vd->backend_bsize;
		ucmd.uscsi_timeout = vd_scsi_rdwr_timeout;
		/*
		 * Set flags so that the command is isolated from normal
		 * commands and no error message is printed.
		 */
		ucmd.uscsi_flags = USCSI_ISOLATE | USCSI_SILENT;

		if (operation == VD_OP_BREAD) {
			cdb.scc_cmd |= SCMD_READ;
			ucmd.uscsi_flags |= USCSI_READ;
		} else {
			cdb.scc_cmd |= SCMD_WRITE;
		}

		status = ldi_ioctl(vd->ldi_handle[VD_ENTIRE_DISK_SLICE],
		    USCSICMD, (intptr_t)&ucmd, (vd->open_flags | FKIOCTL),
		    kcred, &rval);

		if (status == 0)
			status = ucmd.uscsi_status;

		if (status != 0)
			break;

		/*
		 * Check if partial DMA breakup is required. If so, reduce
		 * the request size by half and retry the last request.
		 */
		if (ucmd.uscsi_resid == ucmd.uscsi_buflen) {
			max_sectors >>= 1;
			if (max_sectors <= 0) {
				status = EIO;
				break;
			}
			continue;
		}

		if (ucmd.uscsi_resid != 0) {
			status = EIO;
			break;
		}

		blk += nsectors;
		nblk -= nsectors;
		data += nsectors * vd->vdisk_bsize;
	}

	return (status);
}

/*
 * Function:
 *	vd_scsi_rdwr
 *
 * Description:
 *	Wrapper function to read or write to a SCSI disk using an absolute
 *	disk offset. It checks the blocksize of the underlying device and,
 *	if necessary, adjusts the buffers accordingly before calling
 *	vd_do_scsi_rdwr() to do the actual read or write.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	operation	- operation to execute: read (VD_OP_BREAD) or
 *			  write (VD_OP_BWRITE).
 *	data		- buffer where data are read to or written from.
 *	blk		- starting block for the operation.
 *	len		- number of bytes to read or write.
 *
 * Return Code:
 *	0		- success
 *	n != 0		- error.
 */
static int
vd_scsi_rdwr(vd_t *vd, int operation, caddr_t data, size_t vblk, size_t vlen)
{
	int	rv;

	size_t	pblk;	/* physical device block number of data on device */
	size_t	delta;	/* relative offset between pblk and vblk */
	size_t	pnblk;	/* number of physical blocks to be read from device */
	size_t	plen;	/* length of data to be read from physical device */
	char	*buf;	/* buffer area to fit physical device's block size */

	if (vd->backend_bsize == 0) {
		/*
		 * The block size was not available during the attach,
		 * try to update it now.
		 */
		if (vd_backend_check_size(vd) != 0)
			return (EIO);
	}

	/*
	 * If the vdisk block size and the block size of the underlying device
	 * match we can skip straight to vd_do_scsi_rdwr(), otherwise we need
	 * to create a buffer large enough to handle the device's block size
	 * and adjust the block to be read from and the amount of data to
	 * read to correspond with the device's block size.
	 */
	if (vd->vdisk_bsize == vd->backend_bsize)
		return (vd_do_scsi_rdwr(vd, operation, data, vblk, vlen));

	if (vd->vdisk_bsize > vd->backend_bsize)
		return (EINVAL);

	/*
	 * Writing of physical block sizes larger than the virtual block size
	 * is not supported. This would be added if/when support for guests
	 * writing to DVDs is implemented.
	 */
	if (operation == VD_OP_BWRITE)
		return (ENOTSUP);

	/* BEGIN CSTYLED */
	/*
	 * Below is a diagram showing the relationship between the physical
	 * and virtual blocks. If the virtual blocks marked by 'X' below are
	 * requested, then the physical blocks denoted by 'Y' are read.
	 *
	 *           vblk
	 *             |      vlen
	 *             |<--------------->|
	 *             v                 v
	 *  --+--+--+--+--+--+--+--+--+--+--+--+--+--+--+-   virtual disk:
	 *    |  |  |  |XX|XX|XX|XX|XX|XX|  |  |  |  |  |  } block size is
	 *  --+--+--+--+--+--+--+--+--+--+--+--+--+--+--+-   vd->vdisk_bsize
	 *          :  :                 :  :
	 *         >:==:< delta          :  :
	 *          :  :                 :  :
	 *  --+-----+-----+-----+-----+-----+-----+-----+--   physical disk:
	 *    |     |YY:YY|YYYYY|YYYYY|YY:YY|     |     |   } block size is
	 *  --+-----+-----+-----+-----+-----+-----+-----+--   vd->backend_bsize
	 *          ^                       ^
	 *          |<--------------------->|
	 *          |         plen
	 *	   pblk
	 */
	/* END CSTYLED */
	pblk = (vblk * vd->vdisk_bsize) / vd->backend_bsize;
	delta = (vblk * vd->vdisk_bsize) - (pblk * vd->backend_bsize);
	pnblk = ((delta + vlen - 1) / vd->backend_bsize) + 1;
	plen = pnblk * vd->backend_bsize;

	PR2("vblk %lx:pblk %lx: vlen %ld:plen %ld", vblk, pblk, vlen, plen);

	buf = kmem_zalloc(sizeof (caddr_t) * plen, KM_SLEEP);
	rv = vd_do_scsi_rdwr(vd, operation, (caddr_t)buf, pblk, plen);
	bcopy(buf + delta, data, vlen);

	kmem_free(buf, sizeof (caddr_t) * plen);

	return (rv);
}

/*
 * Function:
 *	vd_slice_flabel_read
 *
 * Description:
 *	This function simulates a read operation from the fake label of
 *	a single-slice disk.
 *
 * Parameters:
 *	vd		- single-slice disk to read from
 *	data		- buffer where data should be read to
 *	offset		- offset in byte where the read should start
 *	length		- number of bytes to read
 *
 * Return Code:
 *	n >= 0		- success, n indicates the number of bytes read
 *	-1		- error
 */
static ssize_t
vd_slice_flabel_read(vd_t *vd, caddr_t data, size_t offset, size_t length)
{
	size_t n = 0;
	uint_t limit = vd->flabel_limit * vd->vdisk_bsize;

	ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);
	ASSERT(vd->flabel != NULL);

	/* if offset is past the fake label limit there's nothing to read */
	if (offset >= limit)
		return (0);

	/* data with offset 0 to flabel_size are read from flabel */
	if (offset < vd->flabel_size) {

		if (offset + length <= vd->flabel_size) {
			bcopy(vd->flabel + offset, data, length);
			return (length);
		}

		n = vd->flabel_size - offset;
		bcopy(vd->flabel + offset, data, n);
		data += n;
	}

	/* data with offset from flabel_size to flabel_limit are all zeros */
	if (offset + length <= limit) {
		bzero(data, length - n);
		return (length);
	}

	bzero(data, limit - offset - n);
	return (limit - offset);
}

/*
 * Function:
 *	vd_slice_flabel_write
 *
 * Description:
 *	This function simulates a write operation to the fake label of
 *	a single-slice disk. Write operations are actually faked and return
 *	success although the label is never changed. This is mostly to
 *	simulate a successful label update.
 *
 * Parameters:
 *	vd		- single-slice disk to write to
 *	data		- buffer where data should be written from
 *	offset		- offset in byte where the write should start
 *	length		- number of bytes to written
 *
 * Return Code:
 *	n >= 0		- success, n indicates the number of bytes written
 *	-1		- error
 */
static ssize_t
vd_slice_flabel_write(vd_t *vd, caddr_t data, size_t offset, size_t length)
{
	uint_t limit = vd->flabel_limit * vd->vdisk_bsize;
	struct dk_label *label;
	struct dk_geom geom;
	struct extvtoc vtoc;

	ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);
	ASSERT(vd->flabel != NULL);

	if (offset >= limit)
		return (0);

	/*
	 * If this is a request to overwrite the VTOC disk label, check that
	 * the new label is similar to the previous one and return that the
	 * write was successful, but note that nothing is actually overwritten.
	 */
	if (vd->vdisk_label == VD_DISK_LABEL_VTOC &&
	    offset == 0 && length == vd->vdisk_bsize) {
		label = (void *)data;

		/* check that this is a valid label */
		if (label->dkl_magic != DKL_MAGIC ||
		    label->dkl_cksum != vd_lbl2cksum(label))
			return (-1);

		/* check the vtoc and geometry */
		vd_label_to_vtocgeom(label, &vtoc, &geom);
		if (vd_slice_geom_isvalid(vd, &geom) &&
		    vd_slice_vtoc_isvalid(vd, &vtoc))
			return (length);
	}

	/* fail any other write */
	return (-1);
}

/*
 * Function:
 *	vd_slice_fake_rdwr
 *
 * Description:
 *	This function simulates a raw read or write operation to a single-slice
 *	disk. It only handles the faked part of the operation i.e. I/Os to
 *	blocks which have no mapping with the vdisk backend (I/Os to the
 *	beginning and to the end of the vdisk).
 *
 *	The function returns 0 is the operation	is completed and it has been
 *	entirely handled as a fake read or write. In that case, lengthp points
 *	to the number of bytes not read or written. Values returned by datap
 *	and blkp are undefined.
 *
 *	If the fake operation has succeeded but the read or write is not
 *	complete (i.e. the read/write operation extends beyond the blocks
 *	we fake) then the function returns EAGAIN and datap, blkp and lengthp
 *	pointers points to the parameters for completing the operation.
 *
 *	In case of an error, for example if the slice is empty or parameters
 *	are invalid, then the function returns a non-zero value different
 *	from EAGAIN. In that case, the returned values of datap, blkp and
 *	lengthp are undefined.
 *
 * Parameters:
 *	vd		- single-slice disk on which the operation is performed
 *	slice		- slice on which the operation is performed,
 *			  VD_SLICE_NONE indicates that the operation
 *			  is done using an absolute disk offset.
 *	operation	- operation to execute: read (VD_OP_BREAD) or
 *			  write (VD_OP_BWRITE).
 *	datap		- pointer to the buffer where data are read to
 *			  or written from. Return the pointer where remaining
 *			  data have to be read to or written from.
 *	blkp		- pointer to the starting block for the operation.
 *			  Return the starting block relative to the vdisk
 *			  backend for the remaining operation.
 *	lengthp		- pointer to the number of bytes to read or write.
 *			  This should be a multiple of vdisk_bsize. Return the
 *			  remaining number of bytes to read or write.
 *
 * Return Code:
 *	0		- read/write operation is completed
 *	EAGAIN		- read/write operation is not completed
 *	other values	- error
 */
static int
vd_slice_fake_rdwr(vd_t *vd, int slice, int operation, caddr_t *datap,
    size_t *blkp, size_t *lengthp)
{
	struct dk_label *label;
	caddr_t data;
	size_t blk, length, csize;
	size_t ablk, asize, aoff, alen;
	ssize_t n;
	int sec, status;
	size_t bsize = vd->vdisk_bsize;

	ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);
	ASSERT(slice != 0);

	data = *datap;
	blk = *blkp;
	length = *lengthp;

	/*
	 * If this is not a raw I/O or an I/O from a full disk slice then
	 * this is an I/O to/from an empty slice.
	 */
	if (slice != VD_SLICE_NONE &&
	    (slice != VD_ENTIRE_DISK_SLICE ||
	    vd->vdisk_label != VD_DISK_LABEL_VTOC) &&
	    (slice != VD_EFI_WD_SLICE ||
	    vd->vdisk_label != VD_DISK_LABEL_EFI)) {
		return (EIO);
	}

	if (length % bsize != 0)
		return (EINVAL);

	/* handle any I/O with the fake label */
	if (operation == VD_OP_BWRITE)
		n = vd_slice_flabel_write(vd, data, blk * bsize, length);
	else
		n = vd_slice_flabel_read(vd, data, blk * bsize, length);

	if (n == -1)
		return (EINVAL);

	ASSERT(n % bsize == 0);

	/* adjust I/O arguments */
	data += n;
	blk += n / bsize;
	length -= n;

	/* check if there's something else to process */
	if (length == 0) {
		status = 0;
		goto done;
	}

	if (vd->vdisk_label == VD_DISK_LABEL_VTOC &&
	    slice == VD_ENTIRE_DISK_SLICE) {
		status = EAGAIN;
		goto done;
	}

	if (vd->vdisk_label == VD_DISK_LABEL_EFI) {
		asize = EFI_MIN_RESV_SIZE + (EFI_MIN_ARRAY_SIZE / bsize) + 1;
		ablk = vd->vdisk_size - asize;
	} else {
		ASSERT(vd->vdisk_label == VD_DISK_LABEL_VTOC);
		ASSERT(vd->dk_geom.dkg_apc == 0);

		csize = vd->dk_geom.dkg_nhead * vd->dk_geom.dkg_nsect;
		ablk = vd->dk_geom.dkg_ncyl * csize;
		asize = vd->dk_geom.dkg_acyl * csize;
	}

	alen = length / bsize;
	aoff = blk;

	/* if we have reached the last block then the I/O is completed */
	if (aoff == ablk + asize) {
		status = 0;
		goto done;
	}

	/* if we are past the last block then return an error */
	if (aoff > ablk + asize)
		return (EIO);

	/* check if there is any I/O to end of the disk */
	if (aoff + alen < ablk) {
		status = EAGAIN;
		goto done;
	}

	/* we don't allow any write to the end of the disk */
	if (operation == VD_OP_BWRITE)
		return (EIO);

	if (aoff < ablk) {
		alen -= (ablk - aoff);
		aoff = ablk;
	}

	if (aoff + alen > ablk + asize) {
		alen = ablk + asize - aoff;
	}

	alen *= bsize;

	if (operation == VD_OP_BREAD) {
		bzero(data + (aoff - blk) * bsize, alen);

		if (vd->vdisk_label == VD_DISK_LABEL_VTOC) {
			/* check if we read backup labels */
			label = VD_LABEL_VTOC(vd);
			ablk += (label->dkl_acyl - 1) * csize +
			    (label->dkl_nhead - 1) * label->dkl_nsect;

			for (sec = 1; (sec < 5 * 2 + 1); sec += 2) {

				if (ablk + sec >= blk &&
				    ablk + sec < blk + (length / bsize)) {
					bcopy(label, data +
					    (ablk + sec - blk) * bsize,
					    sizeof (struct dk_label));
				}
			}
		}
	}

	length -= alen;

	status = (length == 0)? 0: EAGAIN;

done:
	ASSERT(length == 0 || blk >= vd->flabel_limit);

	/*
	 * Return the parameters for the remaining I/O. The starting block is
	 * adjusted so that it is relative to the vdisk backend.
	 */
	*datap = data;
	*blkp = blk - vd->flabel_limit;
	*lengthp = length;

	return (status);
}

static int
vd_flush_write(vd_t *vd)
{
	int status, rval;

	if (vd->file) {
		status = VOP_FSYNC(vd->file_vnode, FSYNC, kcred, NULL);
	} else {
		status = ldi_ioctl(vd->ldi_handle[0], DKIOCFLUSHWRITECACHE,
		    (intptr_t)NULL, vd->open_flags | FKIOCTL, kcred, &rval);
	}

	return (status);
}

static void
vd_bio_task(void *arg)
{
	struct buf *buf = (struct buf *)arg;
	vd_task_t *task = (vd_task_t *)buf->b_private;
	vd_t *vd = task->vd;
	ssize_t resid;
	int status;

	ASSERT(vd->vdisk_bsize == DEV_BSIZE);

	if (vd->zvol) {

		status = ldi_strategy(vd->ldi_handle[0], buf);

	} else {

		ASSERT(vd->file);

		status = vn_rdwr((buf->b_flags & B_READ)? UIO_READ : UIO_WRITE,
		    vd->file_vnode, buf->b_un.b_addr, buf->b_bcount,
		    buf->b_lblkno * DEV_BSIZE, UIO_SYSSPACE, 0,
		    RLIM64_INFINITY, kcred, &resid);

		if (status == 0) {
			buf->b_resid = resid;
			biodone(buf);
			return;
		}
	}

	if (status != 0) {
		bioerror(buf, status);
		biodone(buf);
	}
}

/*
 * We define our own biodone function so that buffers used for
 * asynchronous writes are not released when biodone() is called.
 */
static int
vd_biodone(struct buf *bp)
{
	ASSERT((bp->b_flags & B_DONE) == 0);
	ASSERT(SEMA_HELD(&bp->b_sem));

	bp->b_flags |= B_DONE;
	sema_v(&bp->b_io);

	return (0);
}

/*
 * Return Values
 *	EINPROGRESS	- operation was successfully started
 *	EIO		- encountered LDC (aka. task error)
 *	0		- operation completed successfully
 *
 * Side Effect
 *     sets request->status = <disk operation status>
 */
static int
vd_start_bio(vd_task_t *task)
{
	int			rv, status = 0;
	vd_t			*vd		= task->vd;
	vd_dring_payload_t	*request	= task->request;
	struct buf		*buf		= &task->buf;
	uint8_t			mtype;
	int			slice;
	char			*bufaddr = 0;
	size_t			buflen;
	size_t			offset, length, nbytes;

	ASSERT(vd != NULL);
	ASSERT(request != NULL);

	slice = request->slice;

	ASSERT(slice == VD_SLICE_NONE || slice < vd->nslices);
	ASSERT((request->operation == VD_OP_BREAD) ||
	    (request->operation == VD_OP_BWRITE));

	if (request->nbytes == 0) {
		/* no service for trivial requests */
		request->status = EINVAL;
		return (0);
	}

	PR1("%s %lu bytes at block %lu",
	    (request->operation == VD_OP_BREAD) ? "Read" : "Write",
	    request->nbytes, request->addr);

	/*
	 * We have to check the open flags because the functions processing
	 * the read/write request will not do it.
	 */
	if (request->operation == VD_OP_BWRITE && !(vd->open_flags & FWRITE)) {
		PR0("write fails because backend is opened read-only");
		request->nbytes = 0;
		request->status = EROFS;
		return (0);
	}

	mtype = LDC_SHADOW_MAP;

	/* Map memory exported by client */
	status = ldc_mem_map(task->mhdl, request->cookie, request->ncookies,
	    mtype, (request->operation == VD_OP_BREAD) ? LDC_MEM_W : LDC_MEM_R,
	    &bufaddr, NULL);
	if (status != 0) {
		PR0("ldc_mem_map() returned err %d ", status);
		return (EIO);
	}

	/*
	 * The buffer size has to be 8-byte aligned, so the client should have
	 * sent a buffer which size is roundup to the next 8-byte aligned value.
	 */
	buflen = P2ROUNDUP(request->nbytes, 8);

	status = ldc_mem_acquire(task->mhdl, 0, buflen);
	if (status != 0) {
		(void) ldc_mem_unmap(task->mhdl);
		PR0("ldc_mem_acquire() returned err %d ", status);
		return (EIO);
	}

	offset = request->addr;
	nbytes = request->nbytes;
	length = nbytes;

	/* default number of byte returned by the I/O */
	request->nbytes = 0;

	if (vd->vdisk_type == VD_DISK_TYPE_SLICE) {

		if (slice != 0) {
			/* handle any fake I/O */
			rv = vd_slice_fake_rdwr(vd, slice, request->operation,
			    &bufaddr, &offset, &length);

			/* record the number of bytes from the fake I/O */
			request->nbytes = nbytes - length;

			if (rv == 0) {
				request->status = 0;
				goto io_done;
			}

			if (rv != EAGAIN) {
				request->nbytes = 0;
				request->status = EIO;
				goto io_done;
			}

			/*
			 * If we return with EAGAIN then this means that there
			 * are still data to read or write.
			 */
			ASSERT(length != 0);

			/*
			 * We need to continue the I/O from the slice backend to
			 * complete the request. The variables bufaddr, offset
			 * and length have been adjusted to have the right
			 * information to do the remaining I/O from the backend.
			 * The backend is entirely mapped to slice 0 so we just
			 * have to complete the I/O from that slice.
			 */
			slice = 0;
		}

	} else if (vd->volume || vd->file) {

		rv = vd_dskimg_io_params(vd, slice, &offset, &length);
		if (rv != 0) {
			request->status = (rv == ENODATA)? 0: EIO;
			goto io_done;
		}
		slice = 0;

	} else if (slice == VD_SLICE_NONE) {

		/*
		 * This is not a disk image so it is a real disk. We
		 * assume that the underlying device driver supports
		 * USCSICMD ioctls. This is the case of all SCSI devices
		 * (sd, ssd...).
		 *
		 * In the future if we have non-SCSI disks we would need
		 * to invoke the appropriate function to do I/O using an
		 * absolute disk offset (for example using DIOCTL_RWCMD
		 * for IDE disks).
		 */
		rv = vd_scsi_rdwr(vd, request->operation, bufaddr, offset,
		    length);
		if (rv != 0) {
			request->status = EIO;
		} else {
			request->nbytes = length;
			request->status = 0;
		}
		goto io_done;
	}

	/* Start the block I/O */
	bioinit(buf);
	buf->b_flags	= B_BUSY;
	buf->b_bcount	= length;
	buf->b_lblkno	= offset;
	buf->b_bufsize	= buflen;
	buf->b_edev	= vd->dev[slice];
	buf->b_un.b_addr = bufaddr;
	buf->b_iodone	= vd_biodone;

	if (vd->file || vd->zvol) {
		/*
		 * I/O to a file are dispatched to an I/O queue, so that several
		 * I/Os can be processed in parallel. We also do that for ZFS
		 * volumes because the ZFS volume strategy() function will only
		 * return after the I/O is completed (instead of just starting
		 * the I/O).
		 */

		if (request->operation == VD_OP_BREAD) {
			buf->b_flags |= B_READ;
		} else {
			/*
			 * For ZFS volumes and files, we do an asynchronous
			 * write and we will wait for the completion of the
			 * write in vd_complete_bio() by flushing the volume
			 * or file.
			 *
			 * This done for performance reasons, so that we can
			 * group together several write requests into a single
			 * flush operation.
			 */
			buf->b_flags |= B_WRITE | B_ASYNC;

			/*
			 * We keep track of the write so that we can group
			 * requests when flushing. The write queue has the
			 * same number of slots as the dring so this prevents
			 * the write queue from wrapping and overwriting
			 * existing entries: if the write queue gets full
			 * then that means that the dring is full so we stop
			 * receiving new requests until an existing request
			 * is processed, removed from the write queue and
			 * then from the dring.
			 */
			task->write_index = vd->write_index;
			vd->write_queue[task->write_index] = buf;
			vd->write_index =
			    VD_WRITE_INDEX_NEXT(vd, vd->write_index);
		}

		buf->b_private = task;

		ASSERT(vd->ioq != NULL);

		request->status = 0;
		(void) ddi_taskq_dispatch(task->vd->ioq, vd_bio_task, buf,
		    DDI_SLEEP);

	} else {

		if (request->operation == VD_OP_BREAD) {
			buf->b_flags |= B_READ;
		} else {
			buf->b_flags |= B_WRITE;
		}

		/* convert VIO block number to buf block number */
		buf->b_lblkno = offset << vd->vio_bshift;

		request->status = ldi_strategy(vd->ldi_handle[slice], buf);
	}

	/*
	 * This is to indicate to the caller that the request
	 * needs to be finished by vd_complete_bio() by calling
	 * biowait() there and waiting for that to return before
	 * triggering the notification of the vDisk client.
	 *
	 * This is necessary when writing to real disks as
	 * otherwise calls to ldi_strategy() would be serialized
	 * behind the calls to biowait() and performance would
	 * suffer.
	 */
	if (request->status == 0)
		return (EINPROGRESS);

	biofini(buf);

io_done:
	/* Clean up after error or completion */
	rv = ldc_mem_release(task->mhdl, 0, buflen);
	if (rv) {
		PR0("ldc_mem_release() returned err %d ", rv);
		status = EIO;
	}
	rv = ldc_mem_unmap(task->mhdl);
	if (rv) {
		PR0("ldc_mem_unmap() returned err %d ", rv);
		status = EIO;
	}

	return (status);
}

/*
 * This function should only be called from vd_notify to ensure that requests
 * are responded to in the order that they are received.
 */
static int
send_msg(ldc_handle_t ldc_handle, void *msg, size_t msglen)
{
	int	status;
	size_t	nbytes;

	do {
		nbytes = msglen;
		status = ldc_write(ldc_handle, msg, &nbytes);
		if (status != EWOULDBLOCK)
			break;
		drv_usecwait(vds_ldc_delay);
	} while (status == EWOULDBLOCK);

	if (status != 0) {
		if (status != ECONNRESET)
			PR0("ldc_write() returned errno %d", status);
		return (status);
	} else if (nbytes != msglen) {
		PR0("ldc_write() performed only partial write");
		return (EIO);
	}

	PR1("SENT %lu bytes", msglen);
	return (0);
}

static void
vd_need_reset(vd_t *vd, boolean_t reset_ldc)
{
	mutex_enter(&vd->lock);
	vd->reset_state	= B_TRUE;
	vd->reset_ldc	= reset_ldc;
	mutex_exit(&vd->lock);
}

/*
 * Reset the state of the connection with a client, if needed; reset the LDC
 * transport as well, if needed.  This function should only be called from the
 * "vd_recv_msg", as it waits for tasks - otherwise a deadlock can occur.
 */
static void
vd_reset_if_needed(vd_t *vd)
{
	int	status = 0;

	mutex_enter(&vd->lock);
	if (!vd->reset_state) {
		ASSERT(!vd->reset_ldc);
		mutex_exit(&vd->lock);
		return;
	}
	mutex_exit(&vd->lock);

	PR0("Resetting connection state with %s", VD_CLIENT(vd));

	/*
	 * Let any asynchronous I/O complete before possibly pulling the rug
	 * out from under it; defer checking vd->reset_ldc, as one of the
	 * asynchronous tasks might set it
	 */
	if (vd->ioq != NULL)
		ddi_taskq_wait(vd->ioq);
	ddi_taskq_wait(vd->completionq);

	status = vd_flush_write(vd);
	if (status) {
		PR0("flushwrite returned error %d", status);
	}

	if ((vd->initialized & VD_DRING) &&
	    ((status = ldc_mem_dring_unmap(vd->dring_handle)) != 0))
		PR0("ldc_mem_dring_unmap() returned errno %d", status);

	vd_free_dring_task(vd);

	/* Free the staging buffer for msgs */
	if (vd->vio_msgp != NULL) {
		kmem_free(vd->vio_msgp, vd->max_msglen);
		vd->vio_msgp = NULL;
	}

	/* Free the inband message buffer */
	if (vd->inband_task.msg != NULL) {
		kmem_free(vd->inband_task.msg, vd->max_msglen);
		vd->inband_task.msg = NULL;
	}

	mutex_enter(&vd->lock);

	if (vd->reset_ldc)
		PR0("taking down LDC channel");
	if (vd->reset_ldc && ((status = ldc_down(vd->ldc_handle)) != 0))
		PR0("ldc_down() returned errno %d", status);

	/* Reset exclusive access rights */
	vd_reset_access(vd);

	vd->initialized	&= ~(VD_SID | VD_SEQ_NUM | VD_DRING);
	vd->state	= VD_STATE_INIT;
	vd->max_msglen	= sizeof (vio_msg_t);	/* baseline vio message size */

	/* Allocate the staging buffer */
	vd->vio_msgp = kmem_alloc(vd->max_msglen, KM_SLEEP);

	PR0("calling ldc_up\n");
	(void) ldc_up(vd->ldc_handle);

	vd->reset_state	= B_FALSE;
	vd->reset_ldc	= B_FALSE;

	mutex_exit(&vd->lock);
}

static void vd_recv_msg(void *arg);

static void
vd_mark_in_reset(vd_t *vd)
{
	int status;

	PR0("vd_mark_in_reset: marking vd in reset\n");

	vd_need_reset(vd, B_FALSE);
	status = ddi_taskq_dispatch(vd->startq, vd_recv_msg, vd, DDI_SLEEP);
	if (status == DDI_FAILURE) {
		PR0("cannot schedule task to recv msg\n");
		vd_need_reset(vd, B_TRUE);
		return;
	}
}

static int
vd_mark_elem_done(vd_t *vd, int idx, int elem_status, int elem_nbytes)
{
	boolean_t		accepted;
	int			status;
	on_trap_data_t		otd;
	vd_dring_entry_t	*elem = VD_DRING_ELEM(idx);

	if (vd->reset_state)
		return (0);

	/* Acquire the element */
	if ((status = VIO_DRING_ACQUIRE(&otd, vd->dring_mtype,
	    vd->dring_handle, idx, idx)) != 0) {
		if (status == ECONNRESET) {
			vd_mark_in_reset(vd);
			return (0);
		} else {
			return (status);
		}
	}

	/* Set the element's status and mark it done */
	accepted = (elem->hdr.dstate == VIO_DESC_ACCEPTED);
	if (accepted) {
		elem->payload.nbytes	= elem_nbytes;
		elem->payload.status	= elem_status;
		elem->hdr.dstate	= VIO_DESC_DONE;
	} else {
		/* Perhaps client timed out waiting for I/O... */
		PR0("element %u no longer \"accepted\"", idx);
		VD_DUMP_DRING_ELEM(elem);
	}
	/* Release the element */
	if ((status = VIO_DRING_RELEASE(vd->dring_mtype,
	    vd->dring_handle, idx, idx)) != 0) {
		if (status == ECONNRESET) {
			vd_mark_in_reset(vd);
			return (0);
		} else {
			PR0("VIO_DRING_RELEASE() returned errno %d",
			    status);
			return (status);
		}
	}

	return (accepted ? 0 : EINVAL);
}

/*
 * Return Values
 *	0	- operation completed successfully
 *	EIO	- encountered LDC / task error
 *
 * Side Effect
 *	sets request->status = <disk operation status>
 */
static int
vd_complete_bio(vd_task_t *task)
{
	int			status		= 0;
	int			rv		= 0;
	vd_t			*vd		= task->vd;
	vd_dring_payload_t	*request	= task->request;
	struct buf		*buf		= &task->buf;
	int			wid, nwrites;


	ASSERT(vd != NULL);
	ASSERT(request != NULL);
	ASSERT(task->msg != NULL);
	ASSERT(task->msglen >= sizeof (*task->msg));

	if (buf->b_flags & B_DONE) {
		/*
		 * If the I/O is already done then we don't call biowait()
		 * because biowait() might already have been called when
		 * flushing a previous asynchronous write. So we just
		 * retrieve the status of the request.
		 */
		request->status = geterror(buf);
	} else {
		/*
		 * Wait for the I/O. For synchronous I/O, biowait() will return
		 * when the I/O has completed. For asynchronous write, it will
		 * return the write has been submitted to the backend, but it
		 * may not have been committed.
		 */
		request->status = biowait(buf);
	}

	if (buf->b_flags & B_ASYNC) {
		/*
		 * Asynchronous writes are used when writing to a file or a
		 * ZFS volume. In that case the bio notification indicates
		 * that the write has started. We have to flush the backend
		 * to ensure that the write has been committed before marking
		 * the request as completed.
		 */
		ASSERT(task->request->operation == VD_OP_BWRITE);

		wid = task->write_index;

		/* check if write has been already flushed */
		if (vd->write_queue[wid] != NULL) {

			vd->write_queue[wid] = NULL;
			wid = VD_WRITE_INDEX_NEXT(vd, wid);

			/*
			 * Because flushing is time consuming, it is worth
			 * waiting for any other writes so that they can be
			 * included in this single flush request.
			 */
			if (vd_awflush & VD_AWFLUSH_GROUP) {
				nwrites = 1;
				while (vd->write_queue[wid] != NULL) {
					(void) biowait(vd->write_queue[wid]);
					vd->write_queue[wid] = NULL;
					wid = VD_WRITE_INDEX_NEXT(vd, wid);
					nwrites++;
				}
				DTRACE_PROBE2(flushgrp, vd_task_t *, task,
				    int, nwrites);
			}

			if (vd_awflush & VD_AWFLUSH_IMMEDIATE) {
				request->status = vd_flush_write(vd);
			} else if (vd_awflush & VD_AWFLUSH_DEFER) {
				(void) taskq_dispatch(system_taskq,
				    (void (*)(void *))vd_flush_write, vd,
				    DDI_SLEEP);
				request->status = 0;
			}
		}
	}

	/* Update the number of bytes read/written */
	request->nbytes += buf->b_bcount - buf->b_resid;

	/* Release the buffer */
	if (!vd->reset_state)
		status = ldc_mem_release(task->mhdl, 0, buf->b_bufsize);
	if (status) {
		PR0("ldc_mem_release() returned errno %d copying to "
		    "client", status);
		if (status == ECONNRESET) {
			vd_mark_in_reset(vd);
		}
		rv = EIO;
	}

	/* Unmap the memory, even if in reset */
	status = ldc_mem_unmap(task->mhdl);
	if (status) {
		PR0("ldc_mem_unmap() returned errno %d copying to client",
		    status);
		if (status == ECONNRESET) {
			vd_mark_in_reset(vd);
		}
		rv = EIO;
	}

	biofini(buf);

	return (rv);
}

/*
 * Description:
 *	This function is called by the two functions called by a taskq
 *	[ vd_complete_notify() and vd_serial_notify()) ] to send the
 *	message to the client.
 *
 * Parameters:
 *	arg	- opaque pointer to structure containing task to be completed
 *
 * Return Values
 *	None
 */
static void
vd_notify(vd_task_t *task)
{
	int	status;

	ASSERT(task != NULL);
	ASSERT(task->vd != NULL);

	/*
	 * Send the "ack" or "nack" back to the client; if sending the message
	 * via LDC fails, arrange to reset both the connection state and LDC
	 * itself
	 */
	PR2("Sending %s",
	    (task->msg->tag.vio_subtype == VIO_SUBTYPE_ACK) ? "ACK" : "NACK");

	status = send_msg(task->vd->ldc_handle, task->msg, task->msglen);
	switch (status) {
	case 0:
		break;
	case ECONNRESET:
		vd_mark_in_reset(task->vd);
		break;
	default:
		PR0("initiating full reset");
		vd_need_reset(task->vd, B_TRUE);
		break;
	}

	DTRACE_PROBE1(task__end, vd_task_t *, task);
}

/*
 * Description:
 *	Mark the Dring entry as Done and (if necessary) send an ACK/NACK to
 *	the vDisk client
 *
 * Parameters:
 *	task		- structure containing the request sent from client
 *
 * Return Values
 *	None
 */
static void
vd_complete_notify(vd_task_t *task)
{
	int			status		= 0;
	vd_t			*vd		= task->vd;
	vd_dring_payload_t	*request	= task->request;

	/* Update the dring element for a dring client */
	if (!vd->reset_state && (vd->xfer_mode == VIO_DRING_MODE_V1_0)) {
		status = vd_mark_elem_done(vd, task->index,
		    request->status, request->nbytes);
		if (status == ECONNRESET)
			vd_mark_in_reset(vd);
		else if (status == EACCES)
			vd_need_reset(vd, B_TRUE);
	}

	/*
	 * If a transport error occurred while marking the element done or
	 * previously while executing the task, arrange to "nack" the message
	 * when the final task in the descriptor element range completes
	 */
	if ((status != 0) || (task->status != 0))
		task->msg->tag.vio_subtype = VIO_SUBTYPE_NACK;

	/*
	 * Only the final task for a range of elements will respond to and
	 * free the message
	 */
	if (task->type == VD_NONFINAL_RANGE_TASK) {
		return;
	}

	/*
	 * We should only send an ACK/NACK here if we are not currently in
	 * reset as, depending on how we reset, the dring may have been
	 * blown away and we don't want to ACK/NACK a message that isn't
	 * there.
	 */
	if (!vd->reset_state)
		vd_notify(task);
}

/*
 * Description:
 *	This is the basic completion function called to handle inband data
 *	requests and handshake messages. All it needs to do is trigger a
 *	message to the client that the request is completed.
 *
 * Parameters:
 *	arg	- opaque pointer to structure containing task to be completed
 *
 * Return Values
 *	None
 */
static void
vd_serial_notify(void *arg)
{
	vd_task_t		*task = (vd_task_t *)arg;

	ASSERT(task != NULL);
	vd_notify(task);
}

/* ARGSUSED */
static int
vd_geom2dk_geom(void *vd_buf, size_t vd_buf_len, void *ioctl_arg)
{
	VD_GEOM2DK_GEOM((vd_geom_t *)vd_buf, (struct dk_geom *)ioctl_arg);
	return (0);
}

/* ARGSUSED */
static int
vd_vtoc2vtoc(void *vd_buf, size_t vd_buf_len, void *ioctl_arg)
{
	VD_VTOC2VTOC((vd_vtoc_t *)vd_buf, (struct extvtoc *)ioctl_arg);
	return (0);
}

static void
dk_geom2vd_geom(void *ioctl_arg, void *vd_buf)
{
	DK_GEOM2VD_GEOM((struct dk_geom *)ioctl_arg, (vd_geom_t *)vd_buf);
}

static void
vtoc2vd_vtoc(void *ioctl_arg, void *vd_buf)
{
	VTOC2VD_VTOC((struct extvtoc *)ioctl_arg, (vd_vtoc_t *)vd_buf);
}

static int
vd_get_efi_in(void *vd_buf, size_t vd_buf_len, void *ioctl_arg)
{
	vd_efi_t *vd_efi = (vd_efi_t *)vd_buf;
	dk_efi_t *dk_efi = (dk_efi_t *)ioctl_arg;
	size_t data_len;

	data_len = vd_buf_len - (sizeof (vd_efi_t) - sizeof (uint64_t));
	if (vd_efi->length > data_len)
		return (EINVAL);

	dk_efi->dki_lba = vd_efi->lba;
	dk_efi->dki_length = vd_efi->length;
	dk_efi->dki_data = kmem_zalloc(vd_efi->length, KM_SLEEP);
	return (0);
}

static void
vd_get_efi_out(void *ioctl_arg, void *vd_buf)
{
	int len;
	vd_efi_t *vd_efi = (vd_efi_t *)vd_buf;
	dk_efi_t *dk_efi = (dk_efi_t *)ioctl_arg;

	len = vd_efi->length;
	DK_EFI2VD_EFI(dk_efi, vd_efi);
	kmem_free(dk_efi->dki_data, len);
}

static int
vd_set_efi_in(void *vd_buf, size_t vd_buf_len, void *ioctl_arg)
{
	vd_efi_t *vd_efi = (vd_efi_t *)vd_buf;
	dk_efi_t *dk_efi = (dk_efi_t *)ioctl_arg;
	size_t data_len;

	data_len = vd_buf_len - (sizeof (vd_efi_t) - sizeof (uint64_t));
	if (vd_efi->length > data_len)
		return (EINVAL);

	dk_efi->dki_data = kmem_alloc(vd_efi->length, KM_SLEEP);
	VD_EFI2DK_EFI(vd_efi, dk_efi);
	return (0);
}

static void
vd_set_efi_out(void *ioctl_arg, void *vd_buf)
{
	vd_efi_t *vd_efi = (vd_efi_t *)vd_buf;
	dk_efi_t *dk_efi = (dk_efi_t *)ioctl_arg;

	kmem_free(dk_efi->dki_data, vd_efi->length);
}

static int
vd_scsicmd_in(void *vd_buf, size_t vd_buf_len, void *ioctl_arg)
{
	size_t vd_scsi_len;
	vd_scsi_t *vd_scsi = (vd_scsi_t *)vd_buf;
	struct uscsi_cmd *uscsi = (struct uscsi_cmd *)ioctl_arg;

	/* check buffer size */
	vd_scsi_len = VD_SCSI_SIZE;
	vd_scsi_len += P2ROUNDUP(vd_scsi->cdb_len, sizeof (uint64_t));
	vd_scsi_len += P2ROUNDUP(vd_scsi->sense_len, sizeof (uint64_t));
	vd_scsi_len += P2ROUNDUP(vd_scsi->datain_len, sizeof (uint64_t));
	vd_scsi_len += P2ROUNDUP(vd_scsi->dataout_len, sizeof (uint64_t));

	ASSERT(vd_scsi_len % sizeof (uint64_t) == 0);

	if (vd_buf_len < vd_scsi_len)
		return (EINVAL);

	/* set flags */
	uscsi->uscsi_flags = vd_scsi_debug;

	if (vd_scsi->options & VD_SCSI_OPT_NORETRY) {
		uscsi->uscsi_flags |= USCSI_ISOLATE;
		uscsi->uscsi_flags |= USCSI_DIAGNOSE;
	}

	/* task attribute */
	switch (vd_scsi->task_attribute) {
	case VD_SCSI_TASK_ACA:
		uscsi->uscsi_flags |= USCSI_HEAD;
		break;
	case VD_SCSI_TASK_HQUEUE:
		uscsi->uscsi_flags |= USCSI_HTAG;
		break;
	case VD_SCSI_TASK_ORDERED:
		uscsi->uscsi_flags |= USCSI_OTAG;
		break;
	default:
		uscsi->uscsi_flags |= USCSI_NOTAG;
		break;
	}

	/* timeout */
	uscsi->uscsi_timeout = vd_scsi->timeout;

	/* cdb data */
	uscsi->uscsi_cdb = (caddr_t)VD_SCSI_DATA_CDB(vd_scsi);
	uscsi->uscsi_cdblen = vd_scsi->cdb_len;

	/* sense buffer */
	if (vd_scsi->sense_len != 0) {
		uscsi->uscsi_flags |= USCSI_RQENABLE;
		uscsi->uscsi_rqbuf = (caddr_t)VD_SCSI_DATA_SENSE(vd_scsi);
		uscsi->uscsi_rqlen = vd_scsi->sense_len;
	}

	if (vd_scsi->datain_len != 0 && vd_scsi->dataout_len != 0) {
		/* uscsi does not support read/write request */
		return (EINVAL);
	}

	/* request data-in */
	if (vd_scsi->datain_len != 0) {
		uscsi->uscsi_flags |= USCSI_READ;
		uscsi->uscsi_buflen = vd_scsi->datain_len;
		uscsi->uscsi_bufaddr = (char *)VD_SCSI_DATA_IN(vd_scsi);
	}

	/* request data-out */
	if (vd_scsi->dataout_len != 0) {
		uscsi->uscsi_buflen = vd_scsi->dataout_len;
		uscsi->uscsi_bufaddr = (char *)VD_SCSI_DATA_OUT(vd_scsi);
	}

	return (0);
}

static void
vd_scsicmd_out(void *ioctl_arg, void *vd_buf)
{
	vd_scsi_t *vd_scsi = (vd_scsi_t *)vd_buf;
	struct uscsi_cmd *uscsi = (struct uscsi_cmd *)ioctl_arg;

	/* output fields */
	vd_scsi->cmd_status = uscsi->uscsi_status;

	/* sense data */
	if ((uscsi->uscsi_flags & USCSI_RQENABLE) &&
	    (uscsi->uscsi_status == STATUS_CHECK ||
	    uscsi->uscsi_status == STATUS_TERMINATED)) {
		vd_scsi->sense_status = uscsi->uscsi_rqstatus;
		if (uscsi->uscsi_rqstatus == STATUS_GOOD)
			vd_scsi->sense_len -= uscsi->uscsi_rqresid;
		else
			vd_scsi->sense_len = 0;
	} else {
		vd_scsi->sense_len = 0;
	}

	if (uscsi->uscsi_status != STATUS_GOOD) {
		vd_scsi->dataout_len = 0;
		vd_scsi->datain_len = 0;
		return;
	}

	if (uscsi->uscsi_flags & USCSI_READ) {
		/* request data (read) */
		vd_scsi->datain_len -= uscsi->uscsi_resid;
		vd_scsi->dataout_len = 0;
	} else {
		/* request data (write) */
		vd_scsi->datain_len = 0;
		vd_scsi->dataout_len -= uscsi->uscsi_resid;
	}
}

static ushort_t
vd_lbl2cksum(struct dk_label *label)
{
	int	count;
	ushort_t sum, *sp;

	count =	(sizeof (struct dk_label)) / (sizeof (short)) - 1;
	sp = (ushort_t *)label;
	sum = 0;
	while (count--) {
		sum ^= *sp++;
	}

	return (sum);
}

/*
 * Copy information from a vtoc and dk_geom structures to a dk_label structure.
 */
static void
vd_vtocgeom_to_label(struct extvtoc *vtoc, struct dk_geom *geom,
    struct dk_label *label)
{
	int i;

	ASSERT(vtoc->v_nparts == V_NUMPAR);
	ASSERT(vtoc->v_sanity == VTOC_SANE);

	bzero(label, sizeof (struct dk_label));

	label->dkl_ncyl = geom->dkg_ncyl;
	label->dkl_acyl = geom->dkg_acyl;
	label->dkl_pcyl = geom->dkg_pcyl;
	label->dkl_nhead = geom->dkg_nhead;
	label->dkl_nsect = geom->dkg_nsect;
	label->dkl_intrlv = geom->dkg_intrlv;
	label->dkl_apc = geom->dkg_apc;
	label->dkl_rpm = geom->dkg_rpm;
	label->dkl_write_reinstruct = geom->dkg_write_reinstruct;
	label->dkl_read_reinstruct = geom->dkg_read_reinstruct;

	label->dkl_vtoc.v_nparts = V_NUMPAR;
	label->dkl_vtoc.v_sanity = VTOC_SANE;
	label->dkl_vtoc.v_version = vtoc->v_version;
	for (i = 0; i < V_NUMPAR; i++) {
		label->dkl_vtoc.v_timestamp[i] = vtoc->timestamp[i];
		label->dkl_vtoc.v_part[i].p_tag = vtoc->v_part[i].p_tag;
		label->dkl_vtoc.v_part[i].p_flag = vtoc->v_part[i].p_flag;
		label->dkl_map[i].dkl_cylno = vtoc->v_part[i].p_start /
		    (label->dkl_nhead * label->dkl_nsect);
		label->dkl_map[i].dkl_nblk = vtoc->v_part[i].p_size;
	}

	/*
	 * The bootinfo array can not be copied with bcopy() because
	 * elements are of type long in vtoc (so 64-bit) and of type
	 * int in dk_vtoc (so 32-bit).
	 */
	label->dkl_vtoc.v_bootinfo[0] = vtoc->v_bootinfo[0];
	label->dkl_vtoc.v_bootinfo[1] = vtoc->v_bootinfo[1];
	label->dkl_vtoc.v_bootinfo[2] = vtoc->v_bootinfo[2];
	bcopy(vtoc->v_asciilabel, label->dkl_asciilabel, LEN_DKL_ASCII);
	bcopy(vtoc->v_volume, label->dkl_vtoc.v_volume, LEN_DKL_VVOL);

	/* re-compute checksum */
	label->dkl_magic = DKL_MAGIC;
	label->dkl_cksum = vd_lbl2cksum(label);
}

/*
 * Copy information from a dk_label structure to a vtoc and dk_geom structures.
 */
static void
vd_label_to_vtocgeom(struct dk_label *label, struct extvtoc *vtoc,
    struct dk_geom *geom)
{
	int i;

	bzero(vtoc, sizeof (struct extvtoc));
	bzero(geom, sizeof (struct dk_geom));

	geom->dkg_ncyl = label->dkl_ncyl;
	geom->dkg_acyl = label->dkl_acyl;
	geom->dkg_nhead = label->dkl_nhead;
	geom->dkg_nsect = label->dkl_nsect;
	geom->dkg_intrlv = label->dkl_intrlv;
	geom->dkg_apc = label->dkl_apc;
	geom->dkg_rpm = label->dkl_rpm;
	geom->dkg_pcyl = label->dkl_pcyl;
	geom->dkg_write_reinstruct = label->dkl_write_reinstruct;
	geom->dkg_read_reinstruct = label->dkl_read_reinstruct;

	vtoc->v_sanity = label->dkl_vtoc.v_sanity;
	vtoc->v_version = label->dkl_vtoc.v_version;
	vtoc->v_sectorsz = DEV_BSIZE;
	vtoc->v_nparts = label->dkl_vtoc.v_nparts;

	for (i = 0; i < vtoc->v_nparts; i++) {
		vtoc->v_part[i].p_tag = label->dkl_vtoc.v_part[i].p_tag;
		vtoc->v_part[i].p_flag = label->dkl_vtoc.v_part[i].p_flag;
		vtoc->v_part[i].p_start = label->dkl_map[i].dkl_cylno *
		    (label->dkl_nhead * label->dkl_nsect);
		vtoc->v_part[i].p_size = label->dkl_map[i].dkl_nblk;
		vtoc->timestamp[i] = label->dkl_vtoc.v_timestamp[i];
	}

	/*
	 * The bootinfo array can not be copied with bcopy() because
	 * elements are of type long in vtoc (so 64-bit) and of type
	 * int in dk_vtoc (so 32-bit).
	 */
	vtoc->v_bootinfo[0] = label->dkl_vtoc.v_bootinfo[0];
	vtoc->v_bootinfo[1] = label->dkl_vtoc.v_bootinfo[1];
	vtoc->v_bootinfo[2] = label->dkl_vtoc.v_bootinfo[2];
	bcopy(label->dkl_asciilabel, vtoc->v_asciilabel, LEN_DKL_ASCII);
	bcopy(label->dkl_vtoc.v_volume, vtoc->v_volume, LEN_DKL_VVOL);
}

/*
 * Check if a geometry is valid for a single-slice disk. A geometry is
 * considered valid if the main attributes of the geometry match with the
 * attributes of the fake geometry we have created.
 */
static boolean_t
vd_slice_geom_isvalid(vd_t *vd, struct dk_geom *geom)
{
	ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);
	ASSERT(vd->vdisk_label == VD_DISK_LABEL_VTOC);

	if (geom->dkg_ncyl != vd->dk_geom.dkg_ncyl ||
	    geom->dkg_acyl != vd->dk_geom.dkg_acyl ||
	    geom->dkg_nsect != vd->dk_geom.dkg_nsect ||
	    geom->dkg_pcyl != vd->dk_geom.dkg_pcyl)
		return (B_FALSE);

	return (B_TRUE);
}

/*
 * Check if a vtoc is valid for a single-slice disk. A vtoc is considered
 * valid if the main attributes of the vtoc match with the attributes of the
 * fake vtoc we have created.
 */
static boolean_t
vd_slice_vtoc_isvalid(vd_t *vd, struct extvtoc *vtoc)
{
	size_t csize;
	int i;

	ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);
	ASSERT(vd->vdisk_label == VD_DISK_LABEL_VTOC);

	if (vtoc->v_sanity != vd->vtoc.v_sanity ||
	    vtoc->v_version != vd->vtoc.v_version ||
	    vtoc->v_nparts != vd->vtoc.v_nparts ||
	    strcmp(vtoc->v_volume, vd->vtoc.v_volume) != 0 ||
	    strcmp(vtoc->v_asciilabel, vd->vtoc.v_asciilabel) != 0)
		return (B_FALSE);

	/* slice 2 should be unchanged */
	if (vtoc->v_part[VD_ENTIRE_DISK_SLICE].p_start !=
	    vd->vtoc.v_part[VD_ENTIRE_DISK_SLICE].p_start ||
	    vtoc->v_part[VD_ENTIRE_DISK_SLICE].p_size !=
	    vd->vtoc.v_part[VD_ENTIRE_DISK_SLICE].p_size)
		return (B_FALSE);

	/*
	 * Slice 0 should be mostly unchanged and cover most of the disk.
	 * However we allow some flexibility wrt to the start and the size
	 * of this slice mainly because we can't exactly know how it will
	 * be defined by the OS installer.
	 *
	 * We allow slice 0 to be defined as starting on any of the first
	 * 4 cylinders.
	 */
	csize = vd->dk_geom.dkg_nhead * vd->dk_geom.dkg_nsect;

	if (vtoc->v_part[0].p_start > 4 * csize ||
	    vtoc->v_part[0].p_size > vtoc->v_part[VD_ENTIRE_DISK_SLICE].p_size)
			return (B_FALSE);

	if (vd->vtoc.v_part[0].p_size >= 4 * csize &&
	    vtoc->v_part[0].p_size < vd->vtoc.v_part[0].p_size - 4 *csize)
			return (B_FALSE);

	/* any other slice should have a size of 0 */
	for (i = 1; i < vtoc->v_nparts; i++) {
		if (i != VD_ENTIRE_DISK_SLICE &&
		    vtoc->v_part[i].p_size != 0)
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Handle ioctls to a disk slice.
 *
 * Return Values
 *	0	- Indicates that there are no errors in disk operations
 *	ENOTSUP	- Unknown disk label type or unsupported DKIO ioctl
 *	EINVAL	- Not enough room to copy the EFI label
 *
 */
static int
vd_do_slice_ioctl(vd_t *vd, int cmd, void *ioctl_arg)
{
	dk_efi_t *dk_ioc;
	struct extvtoc *vtoc;
	struct dk_geom *geom;
	size_t len, lba;

	ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);

	if (cmd == DKIOCFLUSHWRITECACHE)
		return (vd_flush_write(vd));

	switch (vd->vdisk_label) {

	/* ioctls for a single slice disk with a VTOC label */
	case VD_DISK_LABEL_VTOC:

		switch (cmd) {

		case DKIOCGGEOM:
			ASSERT(ioctl_arg != NULL);
			bcopy(&vd->dk_geom, ioctl_arg, sizeof (vd->dk_geom));
			return (0);

		case DKIOCGEXTVTOC:
			ASSERT(ioctl_arg != NULL);
			bcopy(&vd->vtoc, ioctl_arg, sizeof (vd->vtoc));
			return (0);

		case DKIOCSGEOM:
			ASSERT(ioctl_arg != NULL);
			if (vd_slice_single_slice)
				return (ENOTSUP);

			/* fake success only if new geometry is valid */
			geom = (struct dk_geom *)ioctl_arg;
			if (!vd_slice_geom_isvalid(vd, geom))
				return (EINVAL);

			return (0);

		case DKIOCSEXTVTOC:
			ASSERT(ioctl_arg != NULL);
			if (vd_slice_single_slice)
				return (ENOTSUP);

			/* fake sucess only if the new vtoc is valid */
			vtoc = (struct extvtoc *)ioctl_arg;
			if (!vd_slice_vtoc_isvalid(vd, vtoc))
				return (EINVAL);

			return (0);

		default:
			return (ENOTSUP);
		}

	/* ioctls for a single slice disk with an EFI label */
	case VD_DISK_LABEL_EFI:

		if (cmd != DKIOCGETEFI && cmd != DKIOCSETEFI)
			return (ENOTSUP);

		ASSERT(ioctl_arg != NULL);
		dk_ioc = (dk_efi_t *)ioctl_arg;

		len = dk_ioc->dki_length;
		lba = dk_ioc->dki_lba;

		if ((lba != VD_EFI_LBA_GPT && lba != VD_EFI_LBA_GPE) ||
		    (lba == VD_EFI_LBA_GPT && len < sizeof (efi_gpt_t)) ||
		    (lba == VD_EFI_LBA_GPE && len < sizeof (efi_gpe_t)))
			return (EINVAL);

		switch (cmd) {
		case DKIOCGETEFI:
			len = vd_slice_flabel_read(vd,
			    (caddr_t)dk_ioc->dki_data,
			    lba * vd->vdisk_bsize, len);

			ASSERT(len > 0);

			return (0);

		case DKIOCSETEFI:
			if (vd_slice_single_slice)
				return (ENOTSUP);

			/* we currently don't support writing EFI */
			return (EIO);
		}

	default:
		/* Unknown disk label type */
		return (ENOTSUP);
	}
}

static int
vds_efi_alloc_and_read(vd_t *vd, efi_gpt_t **gpt, efi_gpe_t **gpe)
{
	vd_efi_dev_t edev;
	int status;

	VD_EFI_DEV_SET(edev, vd, (vd_efi_ioctl_func)vd_backend_ioctl);

	status = vd_efi_alloc_and_read(&edev, gpt, gpe);

	return (status);
}

static void
vds_efi_free(vd_t *vd, efi_gpt_t *gpt, efi_gpe_t *gpe)
{
	vd_efi_dev_t edev;

	VD_EFI_DEV_SET(edev, vd, (vd_efi_ioctl_func)vd_backend_ioctl);

	vd_efi_free(&edev, gpt, gpe);
}

static int
vd_dskimg_validate_efi(vd_t *vd)
{
	efi_gpt_t *gpt;
	efi_gpe_t *gpe;
	int i, nparts, status;
	struct uuid efi_reserved = EFI_RESERVED;

	if ((status = vds_efi_alloc_and_read(vd, &gpt, &gpe)) != 0)
		return (status);

	bzero(&vd->vtoc, sizeof (struct extvtoc));
	bzero(&vd->dk_geom, sizeof (struct dk_geom));
	bzero(vd->slices, sizeof (vd_slice_t) * VD_MAXPART);

	vd->efi_reserved = -1;

	nparts = gpt->efi_gpt_NumberOfPartitionEntries;

	for (i = 0; i < nparts && i < VD_MAXPART; i++) {

		if (gpe[i].efi_gpe_StartingLBA == 0 &&
		    gpe[i].efi_gpe_EndingLBA == 0) {
			continue;
		}

		vd->slices[i].start = gpe[i].efi_gpe_StartingLBA;
		vd->slices[i].nblocks = gpe[i].efi_gpe_EndingLBA -
		    gpe[i].efi_gpe_StartingLBA + 1;

		if (bcmp(&gpe[i].efi_gpe_PartitionTypeGUID, &efi_reserved,
		    sizeof (struct uuid)) == 0)
			vd->efi_reserved = i;

	}

	ASSERT(vd->vdisk_size != 0);
	vd->slices[VD_EFI_WD_SLICE].start = 0;
	vd->slices[VD_EFI_WD_SLICE].nblocks = vd->vdisk_size;

	vds_efi_free(vd, gpt, gpe);

	return (status);
}

/*
 * Function:
 *	vd_dskimg_validate_geometry
 *
 * Description:
 *	Read the label and validate the geometry of a disk image. The driver
 *	label, vtoc and geometry information are updated according to the
 *	label read from the disk image.
 *
 *	If no valid label is found, the label is set to unknown and the
 *	function returns EINVAL, but a default vtoc and geometry are provided
 *	to the driver. If an EFI label is found, ENOTSUP is returned.
 *
 * Parameters:
 *	vd	- disk on which the operation is performed.
 *
 * Return Code:
 *	0	- success.
 *	EIO	- error reading the label from the disk image.
 *	EINVAL	- unknown disk label.
 *	ENOTSUP	- geometry not applicable (EFI label).
 */
static int
vd_dskimg_validate_geometry(vd_t *vd)
{
	struct dk_label label;
	struct dk_geom *geom = &vd->dk_geom;
	struct extvtoc *vtoc = &vd->vtoc;
	int i;
	int status = 0;

	ASSERT(VD_DSKIMG(vd));

	if (VD_DSKIMG_LABEL_READ(vd, &label) < 0)
		return (EIO);

	if (label.dkl_magic != DKL_MAGIC ||
	    label.dkl_cksum != vd_lbl2cksum(&label) ||
	    (vd_dskimg_validate_sanity &&
	    label.dkl_vtoc.v_sanity != VTOC_SANE) ||
	    label.dkl_vtoc.v_nparts != V_NUMPAR) {

		if (vd_dskimg_validate_efi(vd) == 0) {
			vd->vdisk_label = VD_DISK_LABEL_EFI;
			return (ENOTSUP);
		}

		vd->vdisk_label = VD_DISK_LABEL_UNK;
		vd_build_default_label(vd->dskimg_size, vd->vdisk_bsize,
		    &label);
		status = EINVAL;
	} else {
		vd->vdisk_label = VD_DISK_LABEL_VTOC;
	}

	/* Update the driver geometry and vtoc */
	vd_label_to_vtocgeom(&label, vtoc, geom);

	/* Update logical partitions */
	bzero(vd->slices, sizeof (vd_slice_t) * VD_MAXPART);
	if (vd->vdisk_label != VD_DISK_LABEL_UNK) {
		for (i = 0; i < vtoc->v_nparts; i++) {
			vd->slices[i].start = vtoc->v_part[i].p_start;
			vd->slices[i].nblocks = vtoc->v_part[i].p_size;
		}
	}

	return (status);
}

/*
 * Handle ioctls to a disk image.
 *
 * Return Values
 *	0	- Indicates that there are no errors
 *	!= 0	- Disk operation returned an error
 */
static int
vd_do_dskimg_ioctl(vd_t *vd, int cmd, void *ioctl_arg)
{
	struct dk_label label;
	struct dk_geom *geom;
	struct extvtoc *vtoc;
	dk_efi_t *efi;
	int rc;

	ASSERT(VD_DSKIMG(vd));

	switch (cmd) {

	case DKIOCGGEOM:
		ASSERT(ioctl_arg != NULL);
		geom = (struct dk_geom *)ioctl_arg;

		rc = vd_dskimg_validate_geometry(vd);
		if (rc != 0 && rc != EINVAL)
			return (rc);
		bcopy(&vd->dk_geom, geom, sizeof (struct dk_geom));
		return (0);

	case DKIOCGEXTVTOC:
		ASSERT(ioctl_arg != NULL);
		vtoc = (struct extvtoc *)ioctl_arg;

		rc = vd_dskimg_validate_geometry(vd);
		if (rc != 0 && rc != EINVAL)
			return (rc);
		bcopy(&vd->vtoc, vtoc, sizeof (struct extvtoc));
		return (0);

	case DKIOCSGEOM:
		ASSERT(ioctl_arg != NULL);
		geom = (struct dk_geom *)ioctl_arg;

		if (geom->dkg_nhead == 0 || geom->dkg_nsect == 0)
			return (EINVAL);

		/*
		 * The current device geometry is not updated, just the driver
		 * "notion" of it. The device geometry will be effectively
		 * updated when a label is written to the device during a next
		 * DKIOCSEXTVTOC.
		 */
		bcopy(ioctl_arg, &vd->dk_geom, sizeof (vd->dk_geom));
		return (0);

	case DKIOCSEXTVTOC:
		ASSERT(ioctl_arg != NULL);
		ASSERT(vd->dk_geom.dkg_nhead != 0 &&
		    vd->dk_geom.dkg_nsect != 0);
		vtoc = (struct extvtoc *)ioctl_arg;

		if (vtoc->v_sanity != VTOC_SANE ||
		    vtoc->v_sectorsz != DEV_BSIZE ||
		    vtoc->v_nparts != V_NUMPAR)
			return (EINVAL);

		vd_vtocgeom_to_label(vtoc, &vd->dk_geom, &label);

		/* write label to the disk image */
		if ((rc = vd_dskimg_set_vtoc(vd, &label)) != 0)
			return (rc);

		break;

	case DKIOCFLUSHWRITECACHE:
		return (vd_flush_write(vd));

	case DKIOCGETEFI:
		ASSERT(ioctl_arg != NULL);
		efi = (dk_efi_t *)ioctl_arg;

		if (vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BREAD,
		    (caddr_t)efi->dki_data, efi->dki_lba, efi->dki_length) < 0)
			return (EIO);

		return (0);

	case DKIOCSETEFI:
		ASSERT(ioctl_arg != NULL);
		efi = (dk_efi_t *)ioctl_arg;

		if (vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BWRITE,
		    (caddr_t)efi->dki_data, efi->dki_lba, efi->dki_length) < 0)
			return (EIO);

		break;


	default:
		return (ENOTSUP);
	}

	ASSERT(cmd == DKIOCSEXTVTOC || cmd == DKIOCSETEFI);

	/* label has changed, revalidate the geometry */
	(void) vd_dskimg_validate_geometry(vd);

	/*
	 * The disk geometry may have changed, so we need to write
	 * the devid (if there is one) so that it is stored at the
	 * right location.
	 */
	if (vd_dskimg_write_devid(vd, vd->dskimg_devid) != 0) {
		PR0("Fail to write devid");
	}

	return (0);
}

static int
vd_backend_ioctl(vd_t *vd, int cmd, caddr_t arg)
{
	int rval = 0, status;
	struct vtoc vtoc;

	/*
	 * Call the appropriate function to execute the ioctl depending
	 * on the type of vdisk.
	 */
	if (vd->vdisk_type == VD_DISK_TYPE_SLICE) {

		/* slice, file or volume exported as a single slice disk */
		status = vd_do_slice_ioctl(vd, cmd, arg);

	} else if (VD_DSKIMG(vd)) {

		/* file or volume exported as a full disk */
		status = vd_do_dskimg_ioctl(vd, cmd, arg);

	} else {

		/* disk device exported as a full disk */
		status = ldi_ioctl(vd->ldi_handle[0], cmd, (intptr_t)arg,
		    vd->open_flags | FKIOCTL, kcred, &rval);

		/*
		 * By default VTOC ioctls are done using ioctls for the
		 * extended VTOC. Some drivers (in particular non-Sun drivers)
		 * may not support these ioctls. In that case, we fallback to
		 * the regular VTOC ioctls.
		 */
		if (status == ENOTTY) {
			switch (cmd) {

			case DKIOCGEXTVTOC:
				cmd = DKIOCGVTOC;
				status = ldi_ioctl(vd->ldi_handle[0], cmd,
				    (intptr_t)&vtoc, vd->open_flags | FKIOCTL,
				    kcred, &rval);
				vtoctoextvtoc(vtoc,
				    (*(struct extvtoc *)(void *)arg));
				break;

			case DKIOCSEXTVTOC:
				cmd = DKIOCSVTOC;
				extvtoctovtoc((*(struct extvtoc *)(void *)arg),
				    vtoc);
				status = ldi_ioctl(vd->ldi_handle[0], cmd,
				    (intptr_t)&vtoc, vd->open_flags | FKIOCTL,
				    kcred, &rval);
				break;
			}
		}
	}

#ifdef DEBUG
	if (rval != 0) {
		PR0("ioctl %x set rval = %d, which is not being returned"
		    " to caller", cmd, rval);
	}
#endif /* DEBUG */

	return (status);
}

/*
 * Description:
 *	This is the function that processes the ioctl requests (farming it
 *	out to functions that handle slices, files or whole disks)
 *
 * Return Values
 *     0		- ioctl operation completed successfully
 *     != 0		- The LDC error value encountered
 *			  (propagated back up the call stack as a task error)
 *
 * Side Effect
 *     sets request->status to the return value of the ioctl function.
 */
static int
vd_do_ioctl(vd_t *vd, vd_dring_payload_t *request, void* buf, vd_ioctl_t *ioctl)
{
	int	status = 0;
	size_t	nbytes = request->nbytes;	/* modifiable copy */


	ASSERT(request->slice < vd->nslices);
	PR0("Performing %s", ioctl->operation_name);

	/* Get data from client and convert, if necessary */
	if (ioctl->copyin != NULL)  {
		ASSERT(nbytes != 0 && buf != NULL);
		PR1("Getting \"arg\" data from client");
		if ((status = ldc_mem_copy(vd->ldc_handle, buf, 0, &nbytes,
		    request->cookie, request->ncookies,
		    LDC_COPY_IN)) != 0) {
			PR0("ldc_mem_copy() returned errno %d "
			    "copying from client", status);
			return (status);
		}

		/* Convert client's data, if necessary */
		if (ioctl->copyin == VD_IDENTITY_IN) {
			/* use client buffer */
			ioctl->arg = buf;
		} else {
			/* convert client vdisk operation data to ioctl data */
			status = (ioctl->copyin)(buf, nbytes,
			    (void *)ioctl->arg);
			if (status != 0) {
				request->status = status;
				return (0);
			}
		}
	}

	if (ioctl->operation == VD_OP_SCSICMD) {
		struct uscsi_cmd *uscsi = (struct uscsi_cmd *)ioctl->arg;

		/* check write permission */
		if (!(vd->open_flags & FWRITE) &&
		    !(uscsi->uscsi_flags & USCSI_READ)) {
			PR0("uscsi fails because backend is opened read-only");
			request->status = EROFS;
			return (0);
		}
	}

	/*
	 * Send the ioctl to the disk backend.
	 */
	request->status = vd_backend_ioctl(vd, ioctl->cmd, ioctl->arg);

	if (request->status != 0) {
		PR0("ioctl(%s) = errno %d", ioctl->cmd_name, request->status);
		if (ioctl->operation == VD_OP_SCSICMD &&
		    ((struct uscsi_cmd *)ioctl->arg)->uscsi_status != 0)
			/*
			 * USCSICMD has reported an error and the uscsi_status
			 * field is not zero. This means that the SCSI command
			 * has completed but it has an error. So we should
			 * mark the VD operation has succesfully completed
			 * and clients can check the SCSI status field for
			 * SCSI errors.
			 */
			request->status = 0;
		else
			return (0);
	}

	/* Convert data and send to client, if necessary */
	if (ioctl->copyout != NULL)  {
		ASSERT(nbytes != 0 && buf != NULL);
		PR1("Sending \"arg\" data to client");

		/* Convert ioctl data to vdisk operation data, if necessary */
		if (ioctl->copyout != VD_IDENTITY_OUT)
			(ioctl->copyout)((void *)ioctl->arg, buf);

		if ((status = ldc_mem_copy(vd->ldc_handle, buf, 0, &nbytes,
		    request->cookie, request->ncookies,
		    LDC_COPY_OUT)) != 0) {
			PR0("ldc_mem_copy() returned errno %d "
			    "copying to client", status);
			return (status);
		}
	}

	return (status);
}

#define	RNDSIZE(expr) P2ROUNDUP(sizeof (expr), sizeof (uint64_t))

/*
 * Description:
 *	This generic function is called by the task queue to complete
 *	the processing of the tasks. The specific completion function
 *	is passed in as a field in the task pointer.
 *
 * Parameters:
 *	arg	- opaque pointer to structure containing task to be completed
 *
 * Return Values
 *	None
 */
static void
vd_complete(void *arg)
{
	vd_task_t	*task = (vd_task_t *)arg;

	ASSERT(task != NULL);
	ASSERT(task->status == EINPROGRESS);
	ASSERT(task->completef != NULL);

	task->status = task->completef(task);
	if (task->status)
		PR0("%s: Error %d completing task", __func__, task->status);

	/* Now notify the vDisk client */
	vd_complete_notify(task);
}

static int
vd_ioctl(vd_task_t *task)
{
	int			i, status;
	void			*buf = NULL;
	struct dk_geom		dk_geom = {0};
	struct extvtoc		vtoc = {0};
	struct dk_efi		dk_efi = {0};
	struct uscsi_cmd	uscsi = {0};
	vd_t			*vd		= task->vd;
	vd_dring_payload_t	*request	= task->request;
	vd_ioctl_t		ioctl[] = {
		/* Command (no-copy) operations */
		{VD_OP_FLUSH, STRINGIZE(VD_OP_FLUSH), 0,
		    DKIOCFLUSHWRITECACHE, STRINGIZE(DKIOCFLUSHWRITECACHE),
		    NULL, NULL, NULL, B_TRUE},

		/* "Get" (copy-out) operations */
		{VD_OP_GET_WCE, STRINGIZE(VD_OP_GET_WCE), RNDSIZE(int),
		    DKIOCGETWCE, STRINGIZE(DKIOCGETWCE),
		    NULL, VD_IDENTITY_IN, VD_IDENTITY_OUT, B_FALSE},
		{VD_OP_GET_DISKGEOM, STRINGIZE(VD_OP_GET_DISKGEOM),
		    RNDSIZE(vd_geom_t),
		    DKIOCGGEOM, STRINGIZE(DKIOCGGEOM),
		    &dk_geom, NULL, dk_geom2vd_geom, B_FALSE},
		{VD_OP_GET_VTOC, STRINGIZE(VD_OP_GET_VTOC), RNDSIZE(vd_vtoc_t),
		    DKIOCGEXTVTOC, STRINGIZE(DKIOCGEXTVTOC),
		    &vtoc, NULL, vtoc2vd_vtoc, B_FALSE},
		{VD_OP_GET_EFI, STRINGIZE(VD_OP_GET_EFI), RNDSIZE(vd_efi_t),
		    DKIOCGETEFI, STRINGIZE(DKIOCGETEFI),
		    &dk_efi, vd_get_efi_in, vd_get_efi_out, B_FALSE},

		/* "Set" (copy-in) operations */
		{VD_OP_SET_WCE, STRINGIZE(VD_OP_SET_WCE), RNDSIZE(int),
		    DKIOCSETWCE, STRINGIZE(DKIOCSETWCE),
		    NULL, VD_IDENTITY_IN, VD_IDENTITY_OUT, B_TRUE},
		{VD_OP_SET_DISKGEOM, STRINGIZE(VD_OP_SET_DISKGEOM),
		    RNDSIZE(vd_geom_t),
		    DKIOCSGEOM, STRINGIZE(DKIOCSGEOM),
		    &dk_geom, vd_geom2dk_geom, NULL, B_TRUE},
		{VD_OP_SET_VTOC, STRINGIZE(VD_OP_SET_VTOC), RNDSIZE(vd_vtoc_t),
		    DKIOCSEXTVTOC, STRINGIZE(DKIOCSEXTVTOC),
		    &vtoc, vd_vtoc2vtoc, NULL, B_TRUE},
		{VD_OP_SET_EFI, STRINGIZE(VD_OP_SET_EFI), RNDSIZE(vd_efi_t),
		    DKIOCSETEFI, STRINGIZE(DKIOCSETEFI),
		    &dk_efi, vd_set_efi_in, vd_set_efi_out, B_TRUE},

		{VD_OP_SCSICMD, STRINGIZE(VD_OP_SCSICMD), RNDSIZE(vd_scsi_t),
		    USCSICMD, STRINGIZE(USCSICMD),
		    &uscsi, vd_scsicmd_in, vd_scsicmd_out, B_FALSE},
	};
	size_t		nioctls = (sizeof (ioctl))/(sizeof (ioctl[0]));


	ASSERT(vd != NULL);
	ASSERT(request != NULL);
	ASSERT(request->slice < vd->nslices);

	/*
	 * Determine ioctl corresponding to caller's "operation" and
	 * validate caller's "nbytes"
	 */
	for (i = 0; i < nioctls; i++) {
		if (request->operation == ioctl[i].operation) {
			/* LDC memory operations require 8-byte multiples */
			ASSERT(ioctl[i].nbytes % sizeof (uint64_t) == 0);

			if (request->operation == VD_OP_GET_EFI ||
			    request->operation == VD_OP_SET_EFI ||
			    request->operation == VD_OP_SCSICMD) {
				if (request->nbytes >= ioctl[i].nbytes)
					break;
				PR0("%s:  Expected at least nbytes = %lu, "
				    "got %lu", ioctl[i].operation_name,
				    ioctl[i].nbytes, request->nbytes);
				return (EINVAL);
			}

			if (request->nbytes != ioctl[i].nbytes) {
				PR0("%s:  Expected nbytes = %lu, got %lu",
				    ioctl[i].operation_name, ioctl[i].nbytes,
				    request->nbytes);
				return (EINVAL);
			}

			break;
		}
	}

	VERIFY(i < nioctls); /* because "operation" already validated */

	if (!(vd->open_flags & FWRITE) && ioctl[i].write) {
		PR0("%s fails because backend is opened read-only",
		    ioctl[i].operation_name);
		request->status = EROFS;
		return (0);
	}

	if (request->nbytes)
		buf = kmem_zalloc(request->nbytes, KM_SLEEP);
	status = vd_do_ioctl(vd, request, buf, &ioctl[i]);
	if (request->nbytes)
		kmem_free(buf, request->nbytes);

	return (status);
}

static int
vd_get_devid(vd_task_t *task)
{
	vd_t *vd = task->vd;
	vd_dring_payload_t *request = task->request;
	vd_devid_t *vd_devid;
	impl_devid_t *devid;
	int status, bufid_len, devid_len, len, sz;
	int bufbytes;

	PR1("Get Device ID, nbytes=%ld", request->nbytes);

	if (vd->vdisk_type == VD_DISK_TYPE_SLICE) {
		/*
		 * We don't support devid for single-slice disks because we
		 * have no space to store a fabricated devid and for physical
		 * disk slices, we can't use the devid of the disk otherwise
		 * exporting multiple slices from the same disk will produce
		 * the same devids.
		 */
		PR2("No Device ID for slices");
		request->status = ENOTSUP;
		return (0);
	}

	if (VD_DSKIMG(vd)) {
		if (vd->dskimg_devid == NULL) {
			PR2("No Device ID");
			request->status = ENOENT;
			return (0);
		} else {
			sz = ddi_devid_sizeof(vd->dskimg_devid);
			devid = kmem_alloc(sz, KM_SLEEP);
			bcopy(vd->dskimg_devid, devid, sz);
		}
	} else {
		if (ddi_lyr_get_devid(vd->dev[request->slice],
		    (ddi_devid_t *)&devid) != DDI_SUCCESS) {
			PR2("No Device ID");
			request->status = ENOENT;
			return (0);
		}
	}

	bufid_len = request->nbytes - sizeof (vd_devid_t) + 1;
	devid_len = DEVID_GETLEN(devid);

	/*
	 * Save the buffer size here for use in deallocation.
	 * The actual number of bytes copied is returned in
	 * the 'nbytes' field of the request structure.
	 */
	bufbytes = request->nbytes;

	vd_devid = kmem_zalloc(bufbytes, KM_SLEEP);
	vd_devid->length = devid_len;
	vd_devid->type = DEVID_GETTYPE(devid);

	len = (devid_len > bufid_len)? bufid_len : devid_len;

	bcopy(devid->did_id, vd_devid->id, len);

	request->status = 0;

	/* LDC memory operations require 8-byte multiples */
	ASSERT(request->nbytes % sizeof (uint64_t) == 0);

	if ((status = ldc_mem_copy(vd->ldc_handle, (caddr_t)vd_devid, 0,
	    &request->nbytes, request->cookie, request->ncookies,
	    LDC_COPY_OUT)) != 0) {
		PR0("ldc_mem_copy() returned errno %d copying to client",
		    status);
	}
	PR1("post mem_copy: nbytes=%ld", request->nbytes);

	kmem_free(vd_devid, bufbytes);
	ddi_devid_free((ddi_devid_t)devid);

	return (status);
}

static int
vd_scsi_reset(vd_t *vd)
{
	int rval, status;
	struct uscsi_cmd uscsi = { 0 };

	uscsi.uscsi_flags = vd_scsi_debug | USCSI_RESET;
	uscsi.uscsi_timeout = vd_scsi_rdwr_timeout;

	status = ldi_ioctl(vd->ldi_handle[0], USCSICMD, (intptr_t)&uscsi,
	    (vd->open_flags | FKIOCTL), kcred, &rval);

	return (status);
}

static int
vd_reset(vd_task_t *task)
{
	vd_t *vd = task->vd;
	vd_dring_payload_t *request = task->request;

	ASSERT(request->operation == VD_OP_RESET);
	ASSERT(vd->scsi);

	PR0("Performing VD_OP_RESET");

	if (request->nbytes != 0) {
		PR0("VD_OP_RESET:  Expected nbytes = 0, got %lu",
		    request->nbytes);
		return (EINVAL);
	}

	request->status = vd_scsi_reset(vd);

	return (0);
}

static int
vd_get_capacity(vd_task_t *task)
{
	int rv;
	size_t nbytes;
	vd_t *vd = task->vd;
	vd_dring_payload_t *request = task->request;
	vd_capacity_t vd_cap = { 0 };

	ASSERT(request->operation == VD_OP_GET_CAPACITY);

	PR0("Performing VD_OP_GET_CAPACITY");

	nbytes = request->nbytes;

	if (nbytes != RNDSIZE(vd_capacity_t)) {
		PR0("VD_OP_GET_CAPACITY:  Expected nbytes = %lu, got %lu",
		    RNDSIZE(vd_capacity_t), nbytes);
		return (EINVAL);
	}

	/*
	 * Check the backend size in case it has changed. If the check fails
	 * then we will return the last known size.
	 */

	(void) vd_backend_check_size(vd);
	ASSERT(vd->vdisk_size != 0);

	request->status = 0;

	vd_cap.vdisk_block_size = vd->vdisk_bsize;
	vd_cap.vdisk_size = vd->vdisk_size;

	if ((rv = ldc_mem_copy(vd->ldc_handle, (char *)&vd_cap, 0, &nbytes,
	    request->cookie, request->ncookies, LDC_COPY_OUT)) != 0) {
		PR0("ldc_mem_copy() returned errno %d copying to client", rv);
		return (rv);
	}

	return (0);
}

static int
vd_get_access(vd_task_t *task)
{
	uint64_t access;
	int rv, rval = 0;
	size_t nbytes;
	vd_t *vd = task->vd;
	vd_dring_payload_t *request = task->request;

	ASSERT(request->operation == VD_OP_GET_ACCESS);
	ASSERT(vd->scsi);

	PR0("Performing VD_OP_GET_ACCESS");

	nbytes = request->nbytes;

	if (nbytes != sizeof (uint64_t)) {
		PR0("VD_OP_GET_ACCESS:  Expected nbytes = %lu, got %lu",
		    sizeof (uint64_t), nbytes);
		return (EINVAL);
	}

	request->status = ldi_ioctl(vd->ldi_handle[request->slice], MHIOCSTATUS,
	    (intptr_t)NULL, (vd->open_flags | FKIOCTL), kcred, &rval);

	if (request->status != 0)
		return (0);

	access = (rval == 0)? VD_ACCESS_ALLOWED : VD_ACCESS_DENIED;

	if ((rv = ldc_mem_copy(vd->ldc_handle, (char *)&access, 0, &nbytes,
	    request->cookie, request->ncookies, LDC_COPY_OUT)) != 0) {
		PR0("ldc_mem_copy() returned errno %d copying to client", rv);
		return (rv);
	}

	return (0);
}

static int
vd_set_access(vd_task_t *task)
{
	uint64_t flags;
	int rv, rval;
	size_t nbytes;
	vd_t *vd = task->vd;
	vd_dring_payload_t *request = task->request;

	ASSERT(request->operation == VD_OP_SET_ACCESS);
	ASSERT(vd->scsi);

	nbytes = request->nbytes;

	if (nbytes != sizeof (uint64_t)) {
		PR0("VD_OP_SET_ACCESS:  Expected nbytes = %lu, got %lu",
		    sizeof (uint64_t), nbytes);
		return (EINVAL);
	}

	if ((rv = ldc_mem_copy(vd->ldc_handle, (char *)&flags, 0, &nbytes,
	    request->cookie, request->ncookies, LDC_COPY_IN)) != 0) {
		PR0("ldc_mem_copy() returned errno %d copying from client", rv);
		return (rv);
	}

	if (flags == VD_ACCESS_SET_CLEAR) {
		PR0("Performing VD_OP_SET_ACCESS (CLEAR)");
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    MHIOCRELEASE, (intptr_t)NULL, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		if (request->status == 0)
			vd->ownership = B_FALSE;
		return (0);
	}

	/*
	 * As per the VIO spec, the PREEMPT and PRESERVE flags are only valid
	 * when the EXCLUSIVE flag is set.
	 */
	if (!(flags & VD_ACCESS_SET_EXCLUSIVE)) {
		PR0("Invalid VD_OP_SET_ACCESS flags: 0x%lx", flags);
		request->status = EINVAL;
		return (0);
	}

	switch (flags & (VD_ACCESS_SET_PREEMPT | VD_ACCESS_SET_PRESERVE)) {

	case VD_ACCESS_SET_PREEMPT | VD_ACCESS_SET_PRESERVE:
		/*
		 * Flags EXCLUSIVE and PREEMPT and PRESERVE. We have to
		 * acquire exclusive access rights, preserve them and we
		 * can use preemption. So we can use the MHIOCTKNOWN ioctl.
		 */
		PR0("Performing VD_OP_SET_ACCESS (EXCLUSIVE|PREEMPT|PRESERVE)");
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    MHIOCTKOWN, (intptr_t)NULL, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		break;

	case VD_ACCESS_SET_PRESERVE:
		/*
		 * Flags EXCLUSIVE and PRESERVE. We have to acquire exclusive
		 * access rights and preserve them, but not preempt any other
		 * host. So we need to use the MHIOCTKOWN ioctl to enable the
		 * "preserve" feature but we can not called it directly
		 * because it uses preemption. So before that, we use the
		 * MHIOCQRESERVE ioctl to ensure we can get exclusive rights
		 * without preempting anyone.
		 */
		PR0("Performing VD_OP_SET_ACCESS (EXCLUSIVE|PRESERVE)");
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    MHIOCQRESERVE, (intptr_t)NULL, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		if (request->status != 0)
			break;
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    MHIOCTKOWN, (intptr_t)NULL, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		break;

	case VD_ACCESS_SET_PREEMPT:
		/*
		 * Flags EXCLUSIVE and PREEMPT. We have to acquire exclusive
		 * access rights and we can use preemption. So we try to do
		 * a SCSI reservation, if it fails we reset the disk to clear
		 * any reservation and we try to reserve again.
		 */
		PR0("Performing VD_OP_SET_ACCESS (EXCLUSIVE|PREEMPT)");
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    MHIOCQRESERVE, (intptr_t)NULL, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		if (request->status == 0)
			break;

		/* reset the disk */
		(void) vd_scsi_reset(vd);

		/* try again even if the reset has failed */
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    MHIOCQRESERVE, (intptr_t)NULL, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		break;

	case 0:
		/* Flag EXCLUSIVE only. Just issue a SCSI reservation */
		PR0("Performing VD_OP_SET_ACCESS (EXCLUSIVE)");
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    MHIOCQRESERVE, (intptr_t)NULL, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		break;
	}

	if (request->status == 0)
		vd->ownership = B_TRUE;
	else
		PR0("VD_OP_SET_ACCESS: error %d", request->status);

	return (0);
}

static void
vd_reset_access(vd_t *vd)
{
	int status, rval;

	if (vd->file || vd->volume || !vd->ownership)
		return;

	PR0("Releasing disk ownership");
	status = ldi_ioctl(vd->ldi_handle[0], MHIOCRELEASE, (intptr_t)NULL,
	    (vd->open_flags | FKIOCTL), kcred, &rval);

	/*
	 * An EACCES failure means that there is a reservation conflict,
	 * so we are not the owner of the disk anymore.
	 */
	if (status == 0 || status == EACCES) {
		vd->ownership = B_FALSE;
		return;
	}

	PR0("Fail to release ownership, error %d", status);

	/*
	 * We have failed to release the ownership, try to reset the disk
	 * to release reservations.
	 */
	PR0("Resetting disk");
	status = vd_scsi_reset(vd);

	if (status != 0)
		PR0("Fail to reset disk, error %d", status);

	/* whatever the result of the reset is, we try the release again */
	status = ldi_ioctl(vd->ldi_handle[0], MHIOCRELEASE, (intptr_t)NULL,
	    (vd->open_flags | FKIOCTL), kcred, &rval);

	if (status == 0 || status == EACCES) {
		vd->ownership = B_FALSE;
		return;
	}

	PR0("Fail to release ownership, error %d", status);

	/*
	 * At this point we have done our best to try to reset the
	 * access rights to the disk and we don't know if we still
	 * own a reservation and if any mechanism to preserve the
	 * ownership is still in place. The ultimate solution would
	 * be to reset the system but this is usually not what we
	 * want to happen.
	 */

	if (vd_reset_access_failure == A_REBOOT) {
		cmn_err(CE_WARN, VD_RESET_ACCESS_FAILURE_MSG
		    ", rebooting the system", vd->device_path);
		(void) uadmin(A_SHUTDOWN, AD_BOOT, (uintptr_t)NULL);
	} else if (vd_reset_access_failure == A_DUMP) {
		panic(VD_RESET_ACCESS_FAILURE_MSG, vd->device_path);
	}

	cmn_err(CE_WARN, VD_RESET_ACCESS_FAILURE_MSG, vd->device_path);
}

/*
 * Define the supported operations once the functions for performing them have
 * been defined
 */
static const vds_operation_t	vds_operation[] = {
#define	X(_s)	#_s, _s
	{X(VD_OP_BREAD),	vd_start_bio,	vd_complete_bio},
	{X(VD_OP_BWRITE),	vd_start_bio,	vd_complete_bio},
	{X(VD_OP_FLUSH),	vd_ioctl,	NULL},
	{X(VD_OP_GET_WCE),	vd_ioctl,	NULL},
	{X(VD_OP_SET_WCE),	vd_ioctl,	NULL},
	{X(VD_OP_GET_VTOC),	vd_ioctl,	NULL},
	{X(VD_OP_SET_VTOC),	vd_ioctl,	NULL},
	{X(VD_OP_GET_DISKGEOM),	vd_ioctl,	NULL},
	{X(VD_OP_SET_DISKGEOM),	vd_ioctl,	NULL},
	{X(VD_OP_GET_EFI),	vd_ioctl,	NULL},
	{X(VD_OP_SET_EFI),	vd_ioctl,	NULL},
	{X(VD_OP_GET_DEVID),	vd_get_devid,	NULL},
	{X(VD_OP_SCSICMD),	vd_ioctl,	NULL},
	{X(VD_OP_RESET),	vd_reset,	NULL},
	{X(VD_OP_GET_CAPACITY),	vd_get_capacity, NULL},
	{X(VD_OP_SET_ACCESS),	vd_set_access,	NULL},
	{X(VD_OP_GET_ACCESS),	vd_get_access,	NULL},
#undef	X
};

static const size_t	vds_noperations =
	(sizeof (vds_operation))/(sizeof (vds_operation[0]));

/*
 * Process a task specifying a client I/O request
 *
 * Parameters:
 *	task		- structure containing the request sent from client
 *
 * Return Value
 *	0	- success
 *	ENOTSUP	- Unknown/Unsupported VD_OP_XXX operation
 *	EINVAL	- Invalid disk slice
 *	!= 0	- some other non-zero return value from start function
 */
static int
vd_do_process_task(vd_task_t *task)
{
	int			i;
	vd_t			*vd		= task->vd;
	vd_dring_payload_t	*request	= task->request;

	ASSERT(vd != NULL);
	ASSERT(request != NULL);

	/* Find the requested operation */
	for (i = 0; i < vds_noperations; i++) {
		if (request->operation == vds_operation[i].operation) {
			/* all operations should have a start func */
			ASSERT(vds_operation[i].start != NULL);

			task->completef = vds_operation[i].complete;
			break;
		}
	}

	/*
	 * We need to check that the requested operation is permitted
	 * for the particular client that sent it or that the loop above
	 * did not complete without finding the operation type (indicating
	 * that the requested operation is unknown/unimplemented)
	 */
	if ((VD_OP_SUPPORTED(vd->operations, request->operation) == B_FALSE) ||
	    (i == vds_noperations)) {
		PR0("Unsupported operation %u", request->operation);
		request->status = ENOTSUP;
		return (0);
	}

	/* Range-check slice */
	if (request->slice >= vd->nslices &&
	    ((vd->vdisk_type != VD_DISK_TYPE_DISK && vd_slice_single_slice) ||
	    request->slice != VD_SLICE_NONE)) {
		PR0("Invalid \"slice\" %u (max %u) for virtual disk",
		    request->slice, (vd->nslices - 1));
		request->status = EINVAL;
		return (0);
	}

	/*
	 * Call the function pointer that starts the operation.
	 */
	return (vds_operation[i].start(task));
}

/*
 * Description:
 *	This function is called by both the in-band and descriptor ring
 *	message processing functions paths to actually execute the task
 *	requested by the vDisk client. It in turn calls its worker
 *	function, vd_do_process_task(), to carry our the request.
 *
 *	Any transport errors (e.g. LDC errors, vDisk protocol errors) are
 *	saved in the 'status' field of the task and are propagated back
 *	up the call stack to trigger a NACK
 *
 *	Any request errors (e.g. ENOTTY from an ioctl) are saved in
 *	the 'status' field of the request and result in an ACK being sent
 *	by the completion handler.
 *
 * Parameters:
 *	task		- structure containing the request sent from client
 *
 * Return Value
 *	0		- successful synchronous request.
 *	!= 0		- transport error (e.g. LDC errors, vDisk protocol)
 *	EINPROGRESS	- task will be finished in a completion handler
 */
static int
vd_process_task(vd_task_t *task)
{
	vd_t	*vd = task->vd;
	int	status;

	DTRACE_PROBE1(task__start, vd_task_t *, task);

	task->status =  vd_do_process_task(task);

	/*
	 * If the task processing function returned EINPROGRESS indicating
	 * that the task needs completing then schedule a taskq entry to
	 * finish it now.
	 *
	 * Otherwise the task processing function returned either zero
	 * indicating that the task was finished in the start function (and we
	 * don't need to wait in a completion function) or the start function
	 * returned an error - in both cases all that needs to happen is the
	 * notification to the vDisk client higher up the call stack.
	 * If the task was using a Descriptor Ring, we need to mark it as done
	 * at this stage.
	 */
	if (task->status == EINPROGRESS) {
		/* Queue a task to complete the operation */
		(void) ddi_taskq_dispatch(vd->completionq, vd_complete,
		    task, DDI_SLEEP);
		return (EINPROGRESS);
	}

	if (!vd->reset_state && (vd->xfer_mode == VIO_DRING_MODE_V1_0)) {
		/* Update the dring element if it's a dring client */
		status = vd_mark_elem_done(vd, task->index,
		    task->request->status, task->request->nbytes);
		if (status == ECONNRESET)
			vd_mark_in_reset(vd);
		else if (status == EACCES)
			vd_need_reset(vd, B_TRUE);
	}

	return (task->status);
}

/*
 * Return true if the "type", "subtype", and "env" fields of the "tag" first
 * argument match the corresponding remaining arguments; otherwise, return false
 */
boolean_t
vd_msgtype(vio_msg_tag_t *tag, int type, int subtype, int env)
{
	return ((tag->vio_msgtype == type) &&
	    (tag->vio_subtype == subtype) &&
	    (tag->vio_subtype_env == env)) ? B_TRUE : B_FALSE;
}

/*
 * Check whether the major/minor version specified in "ver_msg" is supported
 * by this server.
 */
static boolean_t
vds_supported_version(vio_ver_msg_t *ver_msg)
{
	for (int i = 0; i < vds_num_versions; i++) {
		ASSERT(vds_version[i].major > 0);
		ASSERT((i == 0) ||
		    (vds_version[i].major < vds_version[i-1].major));

		/*
		 * If the major versions match, adjust the minor version, if
		 * necessary, down to the highest value supported by this
		 * server and return true so this message will get "ack"ed;
		 * the client should also support all minor versions lower
		 * than the value it sent
		 */
		if (ver_msg->ver_major == vds_version[i].major) {
			if (ver_msg->ver_minor > vds_version[i].minor) {
				PR0("Adjusting minor version from %u to %u",
				    ver_msg->ver_minor, vds_version[i].minor);
				ver_msg->ver_minor = vds_version[i].minor;
			}
			return (B_TRUE);
		}

		/*
		 * If the message contains a higher major version number, set
		 * the message's major/minor versions to the current values
		 * and return false, so this message will get "nack"ed with
		 * these values, and the client will potentially try again
		 * with the same or a lower version
		 */
		if (ver_msg->ver_major > vds_version[i].major) {
			ver_msg->ver_major = vds_version[i].major;
			ver_msg->ver_minor = vds_version[i].minor;
			return (B_FALSE);
		}

		/*
		 * Otherwise, the message's major version is less than the
		 * current major version, so continue the loop to the next
		 * (lower) supported version
		 */
	}

	/*
	 * No common version was found; "ground" the version pair in the
	 * message to terminate negotiation
	 */
	ver_msg->ver_major = 0;
	ver_msg->ver_minor = 0;
	return (B_FALSE);
}

/*
 * Process a version message from a client.  vds expects to receive version
 * messages from clients seeking service, but never issues version messages
 * itself; therefore, vds can ACK or NACK client version messages, but does
 * not expect to receive version-message ACKs or NACKs (and will treat such
 * messages as invalid).
 */
static int
vd_process_ver_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	vio_ver_msg_t	*ver_msg = (vio_ver_msg_t *)msg;


	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO,
	    VIO_VER_INFO)) {
		return (ENOMSG);	/* not a version message */
	}

	if (msglen != sizeof (*ver_msg)) {
		PR0("Expected %lu-byte version message; "
		    "received %lu bytes", sizeof (*ver_msg), msglen);
		return (EBADMSG);
	}

	if (ver_msg->dev_class != VDEV_DISK) {
		PR0("Expected device class %u (disk); received %u",
		    VDEV_DISK, ver_msg->dev_class);
		return (EBADMSG);
	}

	/*
	 * We're talking to the expected kind of client; set our device class
	 * for "ack/nack" back to the client
	 */
	ver_msg->dev_class = VDEV_DISK_SERVER;

	/*
	 * Check whether the (valid) version message specifies a version
	 * supported by this server.  If the version is not supported, return
	 * EBADMSG so the message will get "nack"ed; vds_supported_version()
	 * will have updated the message with a supported version for the
	 * client to consider
	 */
	if (!vds_supported_version(ver_msg))
		return (EBADMSG);


	/*
	 * A version has been agreed upon; use the client's SID for
	 * communication on this channel now
	 */
	ASSERT(!(vd->initialized & VD_SID));
	vd->sid = ver_msg->tag.vio_sid;
	vd->initialized |= VD_SID;

	/*
	 * Store the negotiated major and minor version values in the "vd" data
	 * structure so that we can check if certain operations are supported
	 * by the client.
	 */
	vd->version.major = ver_msg->ver_major;
	vd->version.minor = ver_msg->ver_minor;

	PR0("Using major version %u, minor version %u",
	    ver_msg->ver_major, ver_msg->ver_minor);
	return (0);
}

static void
vd_set_exported_operations(vd_t *vd)
{
	vd->operations = 0;	/* clear field */

	/*
	 * We need to check from the highest version supported to the
	 * lowest because versions with a higher minor number implicitly
	 * support versions with a lower minor number.
	 */
	if (vio_ver_is_supported(vd->version, 1, 1)) {
		ASSERT(vd->open_flags & FREAD);
		vd->operations |= VD_OP_MASK_READ | (1 << VD_OP_GET_CAPACITY);

		if (vd->open_flags & FWRITE)
			vd->operations |= VD_OP_MASK_WRITE;

		if (vd->scsi)
			vd->operations |= VD_OP_MASK_SCSI;

		if (VD_DSKIMG(vd) && vd_dskimg_is_iso_image(vd)) {
			/*
			 * can't write to ISO images, make sure that write
			 * support is not set in case administrator did not
			 * use "options=ro" when doing an ldm add-vdsdev
			 */
			vd->operations &= ~VD_OP_MASK_WRITE;
		}
	} else if (vio_ver_is_supported(vd->version, 1, 0)) {
		vd->operations = VD_OP_MASK_READ | VD_OP_MASK_WRITE;
	}

	/* we should have already agreed on a version */
	ASSERT(vd->operations != 0);
}

static int
vd_process_attr_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	vd_attr_msg_t	*attr_msg = (vd_attr_msg_t *)msg;
	int		status, retry = 0;


	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO,
	    VIO_ATTR_INFO)) {
		PR0("Message is not an attribute message");
		return (ENOMSG);
	}

	if (msglen != sizeof (*attr_msg)) {
		PR0("Expected %lu-byte attribute message; "
		    "received %lu bytes", sizeof (*attr_msg), msglen);
		return (EBADMSG);
	}

	if (attr_msg->max_xfer_sz == 0) {
		PR0("Received maximum transfer size of 0 from client");
		return (EBADMSG);
	}

	if ((attr_msg->xfer_mode != VIO_DESC_MODE) &&
	    (attr_msg->xfer_mode != VIO_DRING_MODE_V1_0)) {
		PR0("Client requested unsupported transfer mode");
		return (EBADMSG);
	}

	/*
	 * check if the underlying disk is ready, if not try accessing
	 * the device again. Open the vdisk device and extract info
	 * about it, as this is needed to respond to the attr info msg
	 */
	if ((vd->initialized & VD_DISK_READY) == 0) {
		PR0("Retry setting up disk (%s)", vd->device_path);
		do {
			status = vd_setup_vd(vd);
			if (status != EAGAIN || ++retry > vds_dev_retries)
				break;

			/* incremental delay */
			delay(drv_usectohz(vds_dev_delay));

			/* if vdisk is no longer enabled - return error */
			if (!vd_enabled(vd))
				return (ENXIO);

		} while (status == EAGAIN);

		if (status)
			return (ENXIO);

		vd->initialized |= VD_DISK_READY;
		ASSERT(vd->nslices > 0 && vd->nslices <= V_NUMPAR);
		PR0("vdisk_type = %s, volume = %s, file = %s, nslices = %u",
		    ((vd->vdisk_type == VD_DISK_TYPE_DISK) ? "disk" : "slice"),
		    (vd->volume ? "yes" : "no"),
		    (vd->file ? "yes" : "no"),
		    vd->nslices);
	}

	/* Success:  valid message and transfer mode */
	vd->xfer_mode = attr_msg->xfer_mode;

	if (vd->xfer_mode == VIO_DESC_MODE) {

		/*
		 * The vd_dring_inband_msg_t contains one cookie; need room
		 * for up to n-1 more cookies, where "n" is the number of full
		 * pages plus possibly one partial page required to cover
		 * "max_xfer_sz".  Add room for one more cookie if
		 * "max_xfer_sz" isn't an integral multiple of the page size.
		 * Must first get the maximum transfer size in bytes.
		 */
		size_t	max_xfer_bytes = attr_msg->vdisk_block_size ?
		    attr_msg->vdisk_block_size * attr_msg->max_xfer_sz :
		    attr_msg->max_xfer_sz;
		size_t	max_inband_msglen =
		    sizeof (vd_dring_inband_msg_t) +
		    ((max_xfer_bytes/PAGESIZE +
		    ((max_xfer_bytes % PAGESIZE) ? 1 : 0))*
		    (sizeof (ldc_mem_cookie_t)));

		/*
		 * Set the maximum expected message length to
		 * accommodate in-band-descriptor messages with all
		 * their cookies
		 */
		vd->max_msglen = MAX(vd->max_msglen, max_inband_msglen);

		/*
		 * Initialize the data structure for processing in-band I/O
		 * request descriptors
		 */
		vd->inband_task.vd	= vd;
		vd->inband_task.msg	= kmem_alloc(vd->max_msglen, KM_SLEEP);
		vd->inband_task.index	= 0;
		vd->inband_task.type	= VD_FINAL_RANGE_TASK;	/* range == 1 */
	}

	/* Return the device's block size and max transfer size to the client */
	attr_msg->vdisk_block_size	= vd->vdisk_bsize;
	attr_msg->max_xfer_sz		= vd->max_xfer_sz;

	attr_msg->vdisk_size = vd->vdisk_size;
	attr_msg->vdisk_type = (vd_slice_single_slice)? vd->vdisk_type :
	    VD_DISK_TYPE_DISK;
	attr_msg->vdisk_media = vd->vdisk_media;

	/* Discover and save the list of supported VD_OP_XXX operations */
	vd_set_exported_operations(vd);
	attr_msg->operations = vd->operations;

	PR0("%s", VD_CLIENT(vd));

	ASSERT(vd->dring_task == NULL);

	return (0);
}

static int
vd_process_dring_reg_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	int			status;
	size_t			expected;
	ldc_mem_info_t		dring_minfo;
	uint8_t			mtype;
	vio_dring_reg_msg_t	*reg_msg = (vio_dring_reg_msg_t *)msg;


	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO,
	    VIO_DRING_REG)) {
		PR0("Message is not a register-dring message");
		return (ENOMSG);
	}

	if (msglen < sizeof (*reg_msg)) {
		PR0("Expected at least %lu-byte register-dring message; "
		    "received %lu bytes", sizeof (*reg_msg), msglen);
		return (EBADMSG);
	}

	expected = sizeof (*reg_msg) +
	    (reg_msg->ncookies - 1)*(sizeof (reg_msg->cookie[0]));
	if (msglen != expected) {
		PR0("Expected %lu-byte register-dring message; "
		    "received %lu bytes", expected, msglen);
		return (EBADMSG);
	}

	if (vd->initialized & VD_DRING) {
		PR0("A dring was previously registered; only support one");
		return (EBADMSG);
	}

	if (reg_msg->num_descriptors > INT32_MAX) {
		PR0("reg_msg->num_descriptors = %u; must be <= %u (%s)",
		    reg_msg->ncookies, INT32_MAX, STRINGIZE(INT32_MAX));
		return (EBADMSG);
	}

	if (reg_msg->ncookies != 1) {
		/*
		 * In addition to fixing the assertion in the success case
		 * below, supporting drings which require more than one
		 * "cookie" requires increasing the value of vd->max_msglen
		 * somewhere in the code path prior to receiving the message
		 * which results in calling this function.  Note that without
		 * making this change, the larger message size required to
		 * accommodate multiple cookies cannot be successfully
		 * received, so this function will not even get called.
		 * Gracefully accommodating more dring cookies might
		 * reasonably demand exchanging an additional attribute or
		 * making a minor protocol adjustment
		 */
		PR0("reg_msg->ncookies = %u != 1", reg_msg->ncookies);
		return (EBADMSG);
	}

	if (vd_direct_mapped_drings)
		mtype = LDC_DIRECT_MAP;
	else
		mtype = LDC_SHADOW_MAP;

	status = ldc_mem_dring_map(vd->ldc_handle, reg_msg->cookie,
	    reg_msg->ncookies, reg_msg->num_descriptors,
	    reg_msg->descriptor_size, mtype, &vd->dring_handle);
	if (status != 0) {
		PR0("ldc_mem_dring_map() returned errno %d", status);
		return (status);
	}

	/*
	 * To remove the need for this assertion, must call
	 * ldc_mem_dring_nextcookie() successfully ncookies-1 times after a
	 * successful call to ldc_mem_dring_map()
	 */
	ASSERT(reg_msg->ncookies == 1);

	if ((status =
	    ldc_mem_dring_info(vd->dring_handle, &dring_minfo)) != 0) {
		PR0("ldc_mem_dring_info() returned errno %d", status);
		if ((status = ldc_mem_dring_unmap(vd->dring_handle)) != 0)
			PR0("ldc_mem_dring_unmap() returned errno %d", status);
		return (status);
	}

	if (dring_minfo.vaddr == NULL) {
		PR0("Descriptor ring virtual address is NULL");
		return (ENXIO);
	}


	/* Initialize for valid message and mapped dring */
	vd->initialized |= VD_DRING;
	vd->dring_ident = 1;	/* "There Can Be Only One" */
	vd->dring = dring_minfo.vaddr;
	vd->descriptor_size = reg_msg->descriptor_size;
	vd->dring_len = reg_msg->num_descriptors;
	vd->dring_mtype = dring_minfo.mtype;
	reg_msg->dring_ident = vd->dring_ident;
	PR1("descriptor size = %u, dring length = %u",
	    vd->descriptor_size, vd->dring_len);

	/*
	 * Allocate and initialize a "shadow" array of data structures for
	 * tasks to process I/O requests in dring elements
	 */
	vd->dring_task =
	    kmem_zalloc((sizeof (*vd->dring_task)) * vd->dring_len, KM_SLEEP);
	for (int i = 0; i < vd->dring_len; i++) {
		vd->dring_task[i].vd		= vd;
		vd->dring_task[i].index		= i;

		status = ldc_mem_alloc_handle(vd->ldc_handle,
		    &(vd->dring_task[i].mhdl));
		if (status) {
			PR0("ldc_mem_alloc_handle() returned err %d ", status);
			return (ENXIO);
		}

		/*
		 * The descriptor payload varies in length. Calculate its
		 * size by subtracting the header size from the total
		 * descriptor size.
		 */
		vd->dring_task[i].request = kmem_zalloc((vd->descriptor_size -
		    sizeof (vio_dring_entry_hdr_t)), KM_SLEEP);
		vd->dring_task[i].msg = kmem_alloc(vd->max_msglen, KM_SLEEP);
	}

	if (vd->file || vd->zvol) {
		vd->write_queue =
		    kmem_zalloc(sizeof (buf_t *) * vd->dring_len, KM_SLEEP);
	}

	return (0);
}

static int
vd_process_dring_unreg_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	vio_dring_unreg_msg_t	*unreg_msg = (vio_dring_unreg_msg_t *)msg;


	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO,
	    VIO_DRING_UNREG)) {
		PR0("Message is not an unregister-dring message");
		return (ENOMSG);
	}

	if (msglen != sizeof (*unreg_msg)) {
		PR0("Expected %lu-byte unregister-dring message; "
		    "received %lu bytes", sizeof (*unreg_msg), msglen);
		return (EBADMSG);
	}

	if (unreg_msg->dring_ident != vd->dring_ident) {
		PR0("Expected dring ident %lu; received %lu",
		    vd->dring_ident, unreg_msg->dring_ident);
		return (EBADMSG);
	}

	return (0);
}

static int
process_rdx_msg(vio_msg_t *msg, size_t msglen)
{
	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO, VIO_RDX)) {
		PR0("Message is not an RDX message");
		return (ENOMSG);
	}

	if (msglen != sizeof (vio_rdx_msg_t)) {
		PR0("Expected %lu-byte RDX message; received %lu bytes",
		    sizeof (vio_rdx_msg_t), msglen);
		return (EBADMSG);
	}

	PR0("Valid RDX message");
	return (0);
}

static int
vd_check_seq_num(vd_t *vd, uint64_t seq_num)
{
	if ((vd->initialized & VD_SEQ_NUM) && (seq_num != vd->seq_num + 1)) {
		PR0("Received seq_num %lu; expected %lu",
		    seq_num, (vd->seq_num + 1));
		PR0("initiating soft reset");
		vd_need_reset(vd, B_FALSE);
		return (1);
	}

	vd->seq_num = seq_num;
	vd->initialized |= VD_SEQ_NUM;	/* superfluous after first time... */
	return (0);
}

/*
 * Return the expected size of an inband-descriptor message with all the
 * cookies it claims to include
 */
static size_t
expected_inband_size(vd_dring_inband_msg_t *msg)
{
	return ((sizeof (*msg)) +
	    (msg->payload.ncookies - 1)*(sizeof (msg->payload.cookie[0])));
}

/*
 * Process an in-band descriptor message:  used with clients like OBP, with
 * which vds exchanges descriptors within VIO message payloads, rather than
 * operating on them within a descriptor ring
 */
static int
vd_process_desc_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	size_t			expected;
	vd_dring_inband_msg_t	*desc_msg = (vd_dring_inband_msg_t *)msg;


	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_DATA, VIO_SUBTYPE_INFO,
	    VIO_DESC_DATA)) {
		PR1("Message is not an in-band-descriptor message");
		return (ENOMSG);
	}

	if (msglen < sizeof (*desc_msg)) {
		PR0("Expected at least %lu-byte descriptor message; "
		    "received %lu bytes", sizeof (*desc_msg), msglen);
		return (EBADMSG);
	}

	if (msglen != (expected = expected_inband_size(desc_msg))) {
		PR0("Expected %lu-byte descriptor message; "
		    "received %lu bytes", expected, msglen);
		return (EBADMSG);
	}

	if (vd_check_seq_num(vd, desc_msg->hdr.seq_num) != 0)
		return (EBADMSG);

	/*
	 * Valid message:  Set up the in-band descriptor task and process the
	 * request.  Arrange to acknowledge the client's message, unless an
	 * error processing the descriptor task results in setting
	 * VIO_SUBTYPE_NACK
	 */
	PR1("Valid in-band-descriptor message");
	msg->tag.vio_subtype = VIO_SUBTYPE_ACK;

	ASSERT(vd->inband_task.msg != NULL);

	bcopy(msg, vd->inband_task.msg, msglen);
	vd->inband_task.msglen	= msglen;

	/*
	 * The task request is now the payload of the message
	 * that was just copied into the body of the task.
	 */
	desc_msg = (vd_dring_inband_msg_t *)vd->inband_task.msg;
	vd->inband_task.request	= &desc_msg->payload;

	return (vd_process_task(&vd->inband_task));
}

static int
vd_process_element(vd_t *vd, vd_task_type_t type, uint32_t idx,
    vio_msg_t *msg, size_t msglen)
{
	int			status;
	boolean_t		ready;
	on_trap_data_t		otd;
	vd_dring_entry_t	*elem = VD_DRING_ELEM(idx);

	/* Accept the updated dring element */
	if ((status = VIO_DRING_ACQUIRE(&otd, vd->dring_mtype,
	    vd->dring_handle, idx, idx)) != 0) {
		return (status);
	}
	ready = (elem->hdr.dstate == VIO_DESC_READY);
	if (ready) {
		elem->hdr.dstate = VIO_DESC_ACCEPTED;
		bcopy(&elem->payload, vd->dring_task[idx].request,
		    (vd->descriptor_size - sizeof (vio_dring_entry_hdr_t)));
	} else {
		PR0("descriptor %u not ready", idx);
		VD_DUMP_DRING_ELEM(elem);
	}
	if ((status = VIO_DRING_RELEASE(vd->dring_mtype,
	    vd->dring_handle, idx, idx)) != 0) {
		PR0("VIO_DRING_RELEASE() returned errno %d", status);
		return (status);
	}
	if (!ready)
		return (EBUSY);


	/* Initialize a task and process the accepted element */
	PR1("Processing dring element %u", idx);
	vd->dring_task[idx].type	= type;

	/* duplicate msg buf for cookies etc. */
	bcopy(msg, vd->dring_task[idx].msg, msglen);

	vd->dring_task[idx].msglen	= msglen;
	return (vd_process_task(&vd->dring_task[idx]));
}

static int
vd_process_element_range(vd_t *vd, int start, int end,
    vio_msg_t *msg, size_t msglen)
{
	int		i, n, nelem, status = 0;
	boolean_t	inprogress = B_FALSE;
	vd_task_type_t	type;


	ASSERT(start >= 0);
	ASSERT(end >= 0);

	/*
	 * Arrange to acknowledge the client's message, unless an error
	 * processing one of the dring elements results in setting
	 * VIO_SUBTYPE_NACK
	 */
	msg->tag.vio_subtype = VIO_SUBTYPE_ACK;

	/*
	 * Process the dring elements in the range
	 */
	nelem = ((end < start) ? end + vd->dring_len : end) - start + 1;
	for (i = start, n = nelem; n > 0; i = (i + 1) % vd->dring_len, n--) {
		((vio_dring_msg_t *)msg)->end_idx = i;
		type = (n == 1) ? VD_FINAL_RANGE_TASK : VD_NONFINAL_RANGE_TASK;
		status = vd_process_element(vd, type, i, msg, msglen);
		if (status == EINPROGRESS)
			inprogress = B_TRUE;
		else if (status != 0)
			break;
	}

	/*
	 * If some, but not all, operations of a multi-element range are in
	 * progress, wait for other operations to complete before returning
	 * (which will result in "ack" or "nack" of the message).  Note that
	 * all outstanding operations will need to complete, not just the ones
	 * corresponding to the current range of dring elements; howevever, as
	 * this situation is an error case, performance is less critical.
	 */
	if ((nelem > 1) && (status != EINPROGRESS) && inprogress) {
		if (vd->ioq != NULL)
			ddi_taskq_wait(vd->ioq);
		ddi_taskq_wait(vd->completionq);
	}

	return (status);
}

static int
vd_process_dring_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	vio_dring_msg_t	*dring_msg = (vio_dring_msg_t *)msg;


	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_DATA, VIO_SUBTYPE_INFO,
	    VIO_DRING_DATA)) {
		PR1("Message is not a dring-data message");
		return (ENOMSG);
	}

	if (msglen != sizeof (*dring_msg)) {
		PR0("Expected %lu-byte dring message; received %lu bytes",
		    sizeof (*dring_msg), msglen);
		return (EBADMSG);
	}

	if (vd_check_seq_num(vd, dring_msg->seq_num) != 0)
		return (EBADMSG);

	if (dring_msg->dring_ident != vd->dring_ident) {
		PR0("Expected dring ident %lu; received ident %lu",
		    vd->dring_ident, dring_msg->dring_ident);
		return (EBADMSG);
	}

	if (dring_msg->start_idx >= vd->dring_len) {
		PR0("\"start_idx\" = %u; must be less than %u",
		    dring_msg->start_idx, vd->dring_len);
		return (EBADMSG);
	}

	if ((dring_msg->end_idx < 0) ||
	    (dring_msg->end_idx >= vd->dring_len)) {
		PR0("\"end_idx\" = %u; must be >= 0 and less than %u",
		    dring_msg->end_idx, vd->dring_len);
		return (EBADMSG);
	}

	/* Valid message; process range of updated dring elements */
	PR1("Processing descriptor range, start = %u, end = %u",
	    dring_msg->start_idx, dring_msg->end_idx);
	return (vd_process_element_range(vd, dring_msg->start_idx,
	    dring_msg->end_idx, msg, msglen));
}

static int
recv_msg(ldc_handle_t ldc_handle, void *msg, size_t *nbytes)
{
	int	retry, status;
	size_t	size = *nbytes;


	for (retry = 0, status = ETIMEDOUT;
	    retry < vds_ldc_retries && status == ETIMEDOUT;
	    retry++) {
		PR1("ldc_read() attempt %d", (retry + 1));
		*nbytes = size;
		status = ldc_read(ldc_handle, msg, nbytes);
	}

	if (status) {
		PR0("ldc_read() returned errno %d", status);
		if (status != ECONNRESET)
			return (ENOMSG);
		return (status);
	} else if (*nbytes == 0) {
		PR1("ldc_read() returned 0 and no message read");
		return (ENOMSG);
	}

	PR1("RCVD %lu-byte message", *nbytes);
	return (0);
}

static int
vd_do_process_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	int		status;


	PR1("Processing (%x/%x/%x) message", msg->tag.vio_msgtype,
	    msg->tag.vio_subtype, msg->tag.vio_subtype_env);
#ifdef	DEBUG
	vd_decode_tag(msg);
#endif

	/*
	 * Validate session ID up front, since it applies to all messages
	 * once set
	 */
	if ((msg->tag.vio_sid != vd->sid) && (vd->initialized & VD_SID)) {
		PR0("Expected SID %u, received %u", vd->sid,
		    msg->tag.vio_sid);
		return (EBADMSG);
	}

	PR1("\tWhile in state %d (%s)", vd->state, vd_decode_state(vd->state));

	/*
	 * Process the received message based on connection state
	 */
	switch (vd->state) {
	case VD_STATE_INIT:	/* expect version message */
		if ((status = vd_process_ver_msg(vd, msg, msglen)) != 0)
			return (status);

		/* Version negotiated, move to that state */
		vd->state = VD_STATE_VER;
		return (0);

	case VD_STATE_VER:	/* expect attribute message */
		if ((status = vd_process_attr_msg(vd, msg, msglen)) != 0)
			return (status);

		/* Attributes exchanged, move to that state */
		vd->state = VD_STATE_ATTR;
		return (0);

	case VD_STATE_ATTR:
		switch (vd->xfer_mode) {
		case VIO_DESC_MODE:	/* expect RDX message */
			if ((status = process_rdx_msg(msg, msglen)) != 0)
				return (status);

			/* Ready to receive in-band descriptors */
			vd->state = VD_STATE_DATA;
			return (0);

		case VIO_DRING_MODE_V1_0:  /* expect register-dring message */
			if ((status =
			    vd_process_dring_reg_msg(vd, msg, msglen)) != 0)
				return (status);

			/* One dring negotiated, move to that state */
			vd->state = VD_STATE_DRING;
			return (0);

		default:
			ASSERT("Unsupported transfer mode");
			PR0("Unsupported transfer mode");
			return (ENOTSUP);
		}

	case VD_STATE_DRING:	/* expect RDX, register-dring, or unreg-dring */
		if ((status = process_rdx_msg(msg, msglen)) == 0) {
			/* Ready to receive data */
			vd->state = VD_STATE_DATA;
			return (0);
		} else if (status != ENOMSG) {
			return (status);
		}


		/*
		 * If another register-dring message is received, stay in
		 * dring state in case the client sends RDX; although the
		 * protocol allows multiple drings, this server does not
		 * support using more than one
		 */
		if ((status =
		    vd_process_dring_reg_msg(vd, msg, msglen)) != ENOMSG)
			return (status);

		/*
		 * Acknowledge an unregister-dring message, but reset the
		 * connection anyway:  Although the protocol allows
		 * unregistering drings, this server cannot serve a vdisk
		 * without its only dring
		 */
		status = vd_process_dring_unreg_msg(vd, msg, msglen);
		return ((status == 0) ? ENOTSUP : status);

	case VD_STATE_DATA:
		switch (vd->xfer_mode) {
		case VIO_DESC_MODE:	/* expect in-band-descriptor message */
			return (vd_process_desc_msg(vd, msg, msglen));

		case VIO_DRING_MODE_V1_0: /* expect dring-data or unreg-dring */
			/*
			 * Typically expect dring-data messages, so handle
			 * them first
			 */
			if ((status = vd_process_dring_msg(vd, msg,
			    msglen)) != ENOMSG)
				return (status);

			/*
			 * Acknowledge an unregister-dring message, but reset
			 * the connection anyway:  Although the protocol
			 * allows unregistering drings, this server cannot
			 * serve a vdisk without its only dring
			 */
			status = vd_process_dring_unreg_msg(vd, msg, msglen);
			return ((status == 0) ? ENOTSUP : status);

		default:
			ASSERT("Unsupported transfer mode");
			PR0("Unsupported transfer mode");
			return (ENOTSUP);
		}

	default:
		ASSERT("Invalid client connection state");
		PR0("Invalid client connection state");
		return (ENOTSUP);
	}
}

static int
vd_process_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	int		status;
	boolean_t	reset_ldc = B_FALSE;
	vd_task_t	task;

	/*
	 * Check that the message is at least big enough for a "tag", so that
	 * message processing can proceed based on tag-specified message type
	 */
	if (msglen < sizeof (vio_msg_tag_t)) {
		PR0("Received short (%lu-byte) message", msglen);
		/* Can't "nack" short message, so drop the big hammer */
		PR0("initiating full reset");
		vd_need_reset(vd, B_TRUE);
		return (EBADMSG);
	}

	/*
	 * Process the message
	 */
	switch (status = vd_do_process_msg(vd, msg, msglen)) {
	case 0:
		/* "ack" valid, successfully-processed messages */
		msg->tag.vio_subtype = VIO_SUBTYPE_ACK;
		break;

	case EINPROGRESS:
		/* The completion handler will "ack" or "nack" the message */
		return (EINPROGRESS);
	case ENOMSG:
		PR0("Received unexpected message");
		_NOTE(FALLTHROUGH);
	case EBADMSG:
	case ENOTSUP:
		/* "transport" error will cause NACK of invalid messages */
		msg->tag.vio_subtype = VIO_SUBTYPE_NACK;
		break;

	default:
		/* "transport" error will cause NACK of invalid messages */
		msg->tag.vio_subtype = VIO_SUBTYPE_NACK;
		/* An LDC error probably occurred, so try resetting it */
		reset_ldc = B_TRUE;
		break;
	}

	PR1("\tResulting in state %d (%s)", vd->state,
	    vd_decode_state(vd->state));

	/* populate the task so we can dispatch it on the taskq */
	task.vd = vd;
	task.msg = msg;
	task.msglen = msglen;

	/*
	 * Queue a task to send the notification that the operation completed.
	 * We need to ensure that requests are responded to in the correct
	 * order and since the taskq is processed serially this ordering
	 * is maintained.
	 */
	(void) ddi_taskq_dispatch(vd->completionq, vd_serial_notify,
	    &task, DDI_SLEEP);

	/*
	 * To ensure handshake negotiations do not happen out of order, such
	 * requests that come through this path should not be done in parallel
	 * so we need to wait here until the response is sent to the client.
	 */
	ddi_taskq_wait(vd->completionq);

	/* Arrange to reset the connection for nack'ed or failed messages */
	if ((status != 0) || reset_ldc) {
		PR0("initiating %s reset",
		    (reset_ldc) ? "full" : "soft");
		vd_need_reset(vd, reset_ldc);
	}

	return (status);
}

static boolean_t
vd_enabled(vd_t *vd)
{
	boolean_t	enabled;

	mutex_enter(&vd->lock);
	enabled = vd->enabled;
	mutex_exit(&vd->lock);
	return (enabled);
}

static void
vd_recv_msg(void *arg)
{
	vd_t	*vd = (vd_t *)arg;
	int	rv = 0, status = 0;

	ASSERT(vd != NULL);

	PR2("New task to receive incoming message(s)");


	while (vd_enabled(vd) && status == 0) {
		size_t		msglen, msgsize;
		ldc_status_t	lstatus;

		/*
		 * Receive and process a message
		 */
		vd_reset_if_needed(vd);	/* can change vd->max_msglen */

		/*
		 * check if channel is UP - else break out of loop
		 */
		status = ldc_status(vd->ldc_handle, &lstatus);
		if (lstatus != LDC_UP) {
			PR0("channel not up (status=%d), exiting recv loop\n",
			    lstatus);
			break;
		}

		ASSERT(vd->max_msglen != 0);

		msgsize = vd->max_msglen; /* stable copy for alloc/free */
		msglen	= msgsize;	  /* actual len after recv_msg() */

		status = recv_msg(vd->ldc_handle, vd->vio_msgp, &msglen);
		switch (status) {
		case 0:
			rv = vd_process_msg(vd, (void *)vd->vio_msgp, msglen);
			/* check if max_msglen changed */
			if (msgsize != vd->max_msglen) {
				PR0("max_msglen changed 0x%lx to 0x%lx bytes\n",
				    msgsize, vd->max_msglen);
				kmem_free(vd->vio_msgp, msgsize);
				vd->vio_msgp =
				    kmem_alloc(vd->max_msglen, KM_SLEEP);
			}
			if (rv == EINPROGRESS)
				continue;
			break;

		case ENOMSG:
			break;

		case ECONNRESET:
			PR0("initiating soft reset (ECONNRESET)\n");
			vd_need_reset(vd, B_FALSE);
			status = 0;
			break;

		default:
			/* Probably an LDC failure; arrange to reset it */
			PR0("initiating full reset (status=0x%x)", status);
			vd_need_reset(vd, B_TRUE);
			break;
		}
	}

	PR2("Task finished");
}

static uint_t
vd_handle_ldc_events(uint64_t event, caddr_t arg)
{
	vd_t	*vd = (vd_t *)(void *)arg;
	int	status;

	ASSERT(vd != NULL);

	if (!vd_enabled(vd))
		return (LDC_SUCCESS);

	if (event & LDC_EVT_DOWN) {
		PR0("LDC_EVT_DOWN: LDC channel went down");

		vd_need_reset(vd, B_TRUE);
		status = ddi_taskq_dispatch(vd->startq, vd_recv_msg, vd,
		    DDI_SLEEP);
		if (status == DDI_FAILURE) {
			PR0("cannot schedule task to recv msg\n");
			vd_need_reset(vd, B_TRUE);
		}
	}

	if (event & LDC_EVT_RESET) {
		PR0("LDC_EVT_RESET: LDC channel was reset");

		if (vd->state != VD_STATE_INIT) {
			PR0("scheduling full reset");
			vd_need_reset(vd, B_FALSE);
			status = ddi_taskq_dispatch(vd->startq, vd_recv_msg,
			    vd, DDI_SLEEP);
			if (status == DDI_FAILURE) {
				PR0("cannot schedule task to recv msg\n");
				vd_need_reset(vd, B_TRUE);
			}

		} else {
			PR0("channel already reset, ignoring...\n");
			PR0("doing ldc up...\n");
			(void) ldc_up(vd->ldc_handle);
		}

		return (LDC_SUCCESS);
	}

	if (event & LDC_EVT_UP) {
		PR0("EVT_UP: LDC is up\nResetting client connection state");
		PR0("initiating soft reset");
		vd_need_reset(vd, B_FALSE);
		status = ddi_taskq_dispatch(vd->startq, vd_recv_msg,
		    vd, DDI_SLEEP);
		if (status == DDI_FAILURE) {
			PR0("cannot schedule task to recv msg\n");
			vd_need_reset(vd, B_TRUE);
			return (LDC_SUCCESS);
		}
	}

	if (event & LDC_EVT_READ) {
		int	status;

		PR1("New data available");
		/* Queue a task to receive the new data */
		status = ddi_taskq_dispatch(vd->startq, vd_recv_msg, vd,
		    DDI_SLEEP);

		if (status == DDI_FAILURE) {
			PR0("cannot schedule task to recv msg\n");
			vd_need_reset(vd, B_TRUE);
		}
	}

	return (LDC_SUCCESS);
}

static uint_t
vds_check_for_vd(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	_NOTE(ARGUNUSED(key, val))
	(*((uint_t *)arg))++;
	return (MH_WALK_TERMINATE);
}


static int
vds_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	uint_t	vd_present = 0;
	minor_t	instance;
	vds_t	*vds;


	switch (cmd) {
	case DDI_DETACH:
		/* the real work happens below */
		break;
	case DDI_SUSPEND:
		PR0("No action required for DDI_SUSPEND");
		return (DDI_SUCCESS);
	default:
		PR0("Unrecognized \"cmd\"");
		return (DDI_FAILURE);
	}

	ASSERT(cmd == DDI_DETACH);
	instance = ddi_get_instance(dip);
	if ((vds = ddi_get_soft_state(vds_state, instance)) == NULL) {
		PR0("Could not get state for instance %u", instance);
		ddi_soft_state_free(vds_state, instance);
		return (DDI_FAILURE);
	}

	/* Do no detach when serving any vdisks */
	mod_hash_walk(vds->vd_table, vds_check_for_vd, &vd_present);
	if (vd_present) {
		PR0("Not detaching because serving vdisks");
		return (DDI_FAILURE);
	}

	PR0("Detaching");
	if (vds->initialized & VDS_MDEG) {
		(void) mdeg_unregister(vds->mdeg);
		kmem_free(vds->ispecp->specp, sizeof (vds_prop_template));
		kmem_free(vds->ispecp, sizeof (mdeg_node_spec_t));
		vds->ispecp = NULL;
		vds->mdeg = 0;
	}

	vds_driver_types_free(vds);

	if (vds->initialized & VDS_LDI)
		(void) ldi_ident_release(vds->ldi_ident);
	mod_hash_destroy_hash(vds->vd_table);
	ddi_soft_state_free(vds_state, instance);
	return (DDI_SUCCESS);
}

/*
 * Description:
 *	This function checks to see if the disk image being used as a
 *	virtual disk is an ISO image. An ISO image is a special case
 *	which can be booted/installed from like a CD/DVD.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *
 * Return Code:
 *	B_TRUE		- The disk image is an ISO 9660 compliant image
 *	B_FALSE		- just a regular disk image
 */
static boolean_t
vd_dskimg_is_iso_image(vd_t *vd)
{
	char	iso_buf[ISO_SECTOR_SIZE];
	int	i, rv;
	uint_t	sec;

	ASSERT(VD_DSKIMG(vd));

	/*
	 * If we have already discovered and saved this info we can
	 * short-circuit the check and avoid reading the disk image.
	 */
	if (vd->vdisk_media == VD_MEDIA_DVD || vd->vdisk_media == VD_MEDIA_CD)
		return (B_TRUE);

	/*
	 * We wish to read the sector that should contain the 2nd ISO volume
	 * descriptor. The second field in this descriptor is called the
	 * Standard Identifier and is set to CD001 for a CD-ROM compliant
	 * to the ISO 9660 standard.
	 */
	sec = (ISO_VOLDESC_SEC * ISO_SECTOR_SIZE) / vd->vdisk_bsize;
	rv = vd_dskimg_rw(vd, VD_SLICE_NONE, VD_OP_BREAD, (caddr_t)iso_buf,
	    sec, ISO_SECTOR_SIZE);

	if (rv < 0)
		return (B_FALSE);

	for (i = 0; i < ISO_ID_STRLEN; i++) {
		if (ISO_STD_ID(iso_buf)[i] != ISO_ID_STRING[i])
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Description:
 *	This function checks to see if the virtual device is an ATAPI
 *	device. ATAPI devices use Group 1 Read/Write commands, so
 *	any USCSI calls vds makes need to take this into account.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *
 * Return Code:
 *	B_TRUE		- The virtual disk is backed by an ATAPI device
 *	B_FALSE		- not an ATAPI device (presumably SCSI)
 */
static boolean_t
vd_is_atapi_device(vd_t *vd)
{
	boolean_t	is_atapi = B_FALSE;
	char		*variantp;
	int		rv;

	ASSERT(vd->ldi_handle[0] != NULL);
	ASSERT(!vd->file);

	rv = ldi_prop_lookup_string(vd->ldi_handle[0],
	    (LDI_DEV_T_ANY | DDI_PROP_DONTPASS), "variant", &variantp);
	if (rv == DDI_PROP_SUCCESS) {
		PR0("'variant' property exists for %s", vd->device_path);
		if (strcmp(variantp, "atapi") == 0)
			is_atapi = B_TRUE;
		ddi_prop_free(variantp);
	}

	rv = ldi_prop_exists(vd->ldi_handle[0], LDI_DEV_T_ANY, "atapi");
	if (rv) {
		PR0("'atapi' property exists for %s", vd->device_path);
		is_atapi = B_TRUE;
	}

	return (is_atapi);
}

static int
vd_setup_full_disk(vd_t *vd)
{
	int		status;
	major_t		major = getmajor(vd->dev[0]);
	minor_t		minor = getminor(vd->dev[0]) - VD_ENTIRE_DISK_SLICE;

	ASSERT(vd->vdisk_type == VD_DISK_TYPE_DISK);

	/* set the disk size, block size and the media type of the disk */
	status = vd_backend_check_size(vd);

	if (status != 0) {
		if (!vd->scsi) {
			/* unexpected failure */
			PRN("Check size failed for %s (errno %d)",
			    vd->device_path, status);
			return (EIO);
		}

		/*
		 * The function can fail for SCSI disks which are present but
		 * reserved by another system. In that case, we don't know the
		 * size of the disk and the block size.
		 */
		vd->vdisk_size = VD_SIZE_UNKNOWN;
		vd->vdisk_bsize = 0;
		vd->backend_bsize = 0;
		vd->vdisk_media = VD_MEDIA_FIXED;
	}

	/* Move dev number and LDI handle to entire-disk-slice array elements */
	vd->dev[VD_ENTIRE_DISK_SLICE]		= vd->dev[0];
	vd->dev[0]				= 0;
	vd->ldi_handle[VD_ENTIRE_DISK_SLICE]	= vd->ldi_handle[0];
	vd->ldi_handle[0]			= NULL;

	/* Initialize device numbers for remaining slices and open them */
	for (int slice = 0; slice < vd->nslices; slice++) {
		/*
		 * Skip the entire-disk slice, as it's already open and its
		 * device known
		 */
		if (slice == VD_ENTIRE_DISK_SLICE)
			continue;
		ASSERT(vd->dev[slice] == 0);
		ASSERT(vd->ldi_handle[slice] == NULL);

		/*
		 * Construct the device number for the current slice
		 */
		vd->dev[slice] = makedevice(major, (minor + slice));

		/*
		 * Open all slices of the disk to serve them to the client.
		 * Slices are opened exclusively to prevent other threads or
		 * processes in the service domain from performing I/O to
		 * slices being accessed by a client.  Failure to open a slice
		 * results in vds not serving this disk, as the client could
		 * attempt (and should be able) to access any slice immediately.
		 * Any slices successfully opened before a failure will get
		 * closed by vds_destroy_vd() as a result of the error returned
		 * by this function.
		 *
		 * We need to do the open with FNDELAY so that opening an empty
		 * slice does not fail.
		 */
		PR0("Opening device major %u, minor %u = slice %u",
		    major, minor, slice);

		/*
		 * Try to open the device. This can fail for example if we are
		 * opening an empty slice. So in case of a failure, we try the
		 * open again but this time with the FNDELAY flag.
		 */
		status = ldi_open_by_dev(&vd->dev[slice], OTYP_BLK,
		    vd->open_flags, kcred, &vd->ldi_handle[slice],
		    vd->vds->ldi_ident);

		if (status != 0) {
			status = ldi_open_by_dev(&vd->dev[slice], OTYP_BLK,
			    vd->open_flags | FNDELAY, kcred,
			    &vd->ldi_handle[slice], vd->vds->ldi_ident);
		}

		if (status != 0) {
			PRN("ldi_open_by_dev() returned errno %d "
			    "for slice %u", status, slice);
			/* vds_destroy_vd() will close any open slices */
			vd->ldi_handle[slice] = NULL;
			return (status);
		}
	}

	return (0);
}

/*
 * When a slice or a volume is exported as a single-slice disk, we want
 * the disk backend (i.e. the slice or volume) to be entirely mapped as
 * a slice without the addition of any metadata.
 *
 * So when exporting the disk as a VTOC disk, we fake a disk with the following
 * layout:
 *                flabel +--- flabel_limit
 *                 <->   V
 *                 0 1   C                          D  E
 *                 +-+---+--------------------------+--+
 *  virtual disk:  |L|XXX|           slice 0        |AA|
 *                 +-+---+--------------------------+--+
 *                  ^    :                          :
 *                  |    :                          :
 *      VTOC LABEL--+    :                          :
 *                       +--------------------------+
 *  disk backend:        |     slice/volume/file    |
 *                       +--------------------------+
 *                       0                          N
 *
 * N is the number of blocks in the slice/volume/file.
 *
 * We simulate a disk with N+M blocks, where M is the number of blocks
 * simluated at the beginning and at the end of the disk (blocks 0-C
 * and D-E).
 *
 * The first blocks (0 to C-1) are emulated and can not be changed. Blocks C
 * to D defines slice 0 and are mapped to the backend. Finally we emulate 2
 * alternate cylinders at the end of the disk (blocks D-E). In summary we have:
 *
 * - block 0 (L) returns a fake VTOC label
 * - blocks 1 to C-1 (X) are unused and return 0
 * - blocks C to D-1 are mapped to the exported slice or volume
 * - blocks D and E (A) are blocks defining alternate cylinders (2 cylinders)
 *
 * Note: because we define a fake disk geometry, it is possible that the length
 * of the backend is not a multiple of the size of cylinder, in that case the
 * very end of the backend will not map to any block of the virtual disk.
 */
static int
vd_setup_partition_vtoc(vd_t *vd)
{
	char *device_path = vd->device_path;
	char unit;
	size_t size, csize;

	/* Initialize dk_geom structure for single-slice device */
	if (vd->dk_geom.dkg_nsect == 0) {
		PRN("%s geometry claims 0 sectors per track", device_path);
		return (EIO);
	}
	if (vd->dk_geom.dkg_nhead == 0) {
		PRN("%s geometry claims 0 heads", device_path);
		return (EIO);
	}

	/* size of a cylinder in block */
	csize = vd->dk_geom.dkg_nhead * vd->dk_geom.dkg_nsect;

	/*
	 * Add extra cylinders: we emulate the first cylinder (which contains
	 * the disk label).
	 */
	vd->dk_geom.dkg_ncyl = vd->vdisk_size / csize + 1;

	/* we emulate 2 alternate cylinders */
	vd->dk_geom.dkg_acyl = 2;
	vd->dk_geom.dkg_pcyl = vd->dk_geom.dkg_ncyl + vd->dk_geom.dkg_acyl;


	/* Initialize vtoc structure for single-slice device */
	bzero(vd->vtoc.v_part, sizeof (vd->vtoc.v_part));
	vd->vtoc.v_part[0].p_tag = V_UNASSIGNED;
	vd->vtoc.v_part[0].p_flag = 0;
	/*
	 * Partition 0 starts on cylinder 1 and its size has to be
	 * a multiple of a number of cylinder.
	 */
	vd->vtoc.v_part[0].p_start = csize; /* start on cylinder 1 */
	vd->vtoc.v_part[0].p_size = (vd->vdisk_size / csize) * csize;

	if (vd_slice_single_slice) {
		vd->vtoc.v_nparts = 1;
		bcopy(VD_ASCIILABEL, vd->vtoc.v_asciilabel,
		    MIN(sizeof (VD_ASCIILABEL),
		    sizeof (vd->vtoc.v_asciilabel)));
		bcopy(VD_VOLUME_NAME, vd->vtoc.v_volume,
		    MIN(sizeof (VD_VOLUME_NAME), sizeof (vd->vtoc.v_volume)));
	} else {
		/* adjust the number of slices */
		vd->nslices = V_NUMPAR;
		vd->vtoc.v_nparts = V_NUMPAR;

		/* define slice 2 representing the entire disk */
		vd->vtoc.v_part[VD_ENTIRE_DISK_SLICE].p_tag = V_BACKUP;
		vd->vtoc.v_part[VD_ENTIRE_DISK_SLICE].p_flag = 0;
		vd->vtoc.v_part[VD_ENTIRE_DISK_SLICE].p_start = 0;
		vd->vtoc.v_part[VD_ENTIRE_DISK_SLICE].p_size =
		    vd->dk_geom.dkg_ncyl * csize;

		vd_get_readable_size(vd->vdisk_size * vd->vdisk_bsize,
		    &size, &unit);

		/*
		 * Set some attributes of the geometry to what format(1m) uses
		 * so that writing a default label using format(1m) does not
		 * produce any error.
		 */
		vd->dk_geom.dkg_bcyl = 0;
		vd->dk_geom.dkg_intrlv = 1;
		vd->dk_geom.dkg_write_reinstruct = 0;
		vd->dk_geom.dkg_read_reinstruct = 0;

		/*
		 * We must have a correct label name otherwise format(1m) will
		 * not recognized the disk as labeled.
		 */
		(void) snprintf(vd->vtoc.v_asciilabel, LEN_DKL_ASCII,
		    "SUN-DiskSlice-%ld%cB cyl %d alt %d hd %d sec %d",
		    size, unit,
		    vd->dk_geom.dkg_ncyl, vd->dk_geom.dkg_acyl,
		    vd->dk_geom.dkg_nhead, vd->dk_geom.dkg_nsect);
		bzero(vd->vtoc.v_volume, sizeof (vd->vtoc.v_volume));

		/* create a fake label from the vtoc and geometry */
		vd->flabel_limit = (uint_t)csize;
		vd->flabel_size = VD_LABEL_VTOC_SIZE(vd->vdisk_bsize);
		vd->flabel = kmem_zalloc(vd->flabel_size, KM_SLEEP);
		vd_vtocgeom_to_label(&vd->vtoc, &vd->dk_geom,
		    VD_LABEL_VTOC(vd));
	}

	/* adjust the vdisk_size, we emulate 3 cylinders */
	vd->vdisk_size += csize * 3;

	return (0);
}

/*
 * When a slice, volume or file is exported as a single-slice disk, we want
 * the disk backend (i.e. the slice, volume or file) to be entirely mapped
 * as a slice without the addition of any metadata.
 *
 * So when exporting the disk as an EFI disk, we fake a disk with the following
 * layout: (assuming the block size is 512 bytes)
 *
 *                  flabel        +--- flabel_limit
 *                 <------>       v
 *                 0 1 2  L      34                        34+N      P
 *                 +-+-+--+-------+--------------------------+-------+
 *  virtual disk:  |X|T|EE|XXXXXXX|           slice 0        |RRRRRRR|
 *                 +-+-+--+-------+--------------------------+-------+
 *                    ^ ^         :                          :
 *                    | |         :                          :
 *                GPT-+ +-GPE     :                          :
 *                                +--------------------------+
 *  disk backend:                 |     slice/volume/file    |
 *                                +--------------------------+
 *                                0                          N
 *
 * N is the number of blocks in the slice/volume/file.
 *
 * We simulate a disk with N+M blocks, where M is the number of blocks
 * simluated at the beginning and at the end of the disk (blocks 0-34
 * and 34+N-P).
 *
 * The first 34 blocks (0 to 33) are emulated and can not be changed. Blocks 34
 * to 34+N defines slice 0 and are mapped to the exported backend, and we
 * emulate some blocks at the end of the disk (blocks 34+N to P) as a the EFI
 * reserved partition.
 *
 * - block 0 (X) is unused and return 0
 * - block 1 (T) returns a fake EFI GPT (via DKIOCGETEFI)
 * - blocks 2 to L-1 (E) defines a fake EFI GPE (via DKIOCGETEFI)
 * - blocks L to 33 (X) are unused and return 0
 * - blocks 34 to 34+N are mapped to the exported slice, volume or file
 * - blocks 34+N+1 to P define a fake reserved partition and backup label, it
 *   returns 0
 *
 * Note: if the backend size is not a multiple of the vdisk block size then
 * the very end of the backend will not map to any block of the virtual disk.
 */
static int
vd_setup_partition_efi(vd_t *vd)
{
	efi_gpt_t *gpt;
	efi_gpe_t *gpe;
	struct uuid uuid = EFI_USR;
	struct uuid efi_reserved = EFI_RESERVED;
	uint32_t crc;
	uint64_t s0_start, s0_end, first_u_lba;
	size_t bsize;

	ASSERT(vd->vdisk_bsize > 0);

	bsize = vd->vdisk_bsize;
	/*
	 * The minimum size for the label is 16K (EFI_MIN_ARRAY_SIZE)
	 * for GPEs plus one block for the GPT and one for PMBR.
	 */
	first_u_lba = (EFI_MIN_ARRAY_SIZE / bsize) + 2;
	vd->flabel_limit = (uint_t)first_u_lba;
	vd->flabel_size = VD_LABEL_EFI_SIZE(bsize);
	vd->flabel = kmem_zalloc(vd->flabel_size, KM_SLEEP);
	gpt = VD_LABEL_EFI_GPT(vd, bsize);
	gpe = VD_LABEL_EFI_GPE(vd, bsize);

	/*
	 * Adjust the vdisk_size, we emulate the first few blocks
	 * for the disk label.
	 */
	vd->vdisk_size += first_u_lba;
	s0_start = first_u_lba;
	s0_end = vd->vdisk_size - 1;

	gpt->efi_gpt_Signature = LE_64(EFI_SIGNATURE);
	gpt->efi_gpt_Revision = LE_32(EFI_VERSION_CURRENT);
	gpt->efi_gpt_HeaderSize = LE_32(EFI_HEADER_SIZE);
	gpt->efi_gpt_FirstUsableLBA = LE_64(first_u_lba);
	gpt->efi_gpt_PartitionEntryLBA = LE_64(2ULL);
	gpt->efi_gpt_SizeOfPartitionEntry = LE_32(sizeof (efi_gpe_t));

	UUID_LE_CONVERT(gpe[0].efi_gpe_PartitionTypeGUID, uuid);
	gpe[0].efi_gpe_StartingLBA = LE_64(s0_start);
	gpe[0].efi_gpe_EndingLBA = LE_64(s0_end);

	if (vd_slice_single_slice) {
		gpt->efi_gpt_NumberOfPartitionEntries = LE_32(1);
	} else {
		/* adjust the number of slices */
		gpt->efi_gpt_NumberOfPartitionEntries = LE_32(VD_MAXPART);
		vd->nslices = V_NUMPAR;

		/* define a fake reserved partition */
		UUID_LE_CONVERT(gpe[VD_MAXPART - 1].efi_gpe_PartitionTypeGUID,
		    efi_reserved);
		gpe[VD_MAXPART - 1].efi_gpe_StartingLBA =
		    LE_64(s0_end + 1);
		gpe[VD_MAXPART - 1].efi_gpe_EndingLBA =
		    LE_64(s0_end + EFI_MIN_RESV_SIZE);

		/* adjust the vdisk_size to include the reserved slice */
		vd->vdisk_size += EFI_MIN_RESV_SIZE;
	}

	gpt->efi_gpt_LastUsableLBA = LE_64(vd->vdisk_size - 1);

	/* adjust the vdisk size for the backup GPT and GPE */
	vd->vdisk_size += (EFI_MIN_ARRAY_SIZE / bsize) + 1;
	gpt->efi_gpt_AlternateLBA = LE_64(vd->vdisk_size - 1);

	CRC32(crc, gpe, sizeof (efi_gpe_t) * VD_MAXPART, -1U, crc32_table);
	gpt->efi_gpt_PartitionEntryArrayCRC32 = LE_32(~crc);

	CRC32(crc, gpt, EFI_HEADER_SIZE, -1U, crc32_table);
	gpt->efi_gpt_HeaderCRC32 = LE_32(~crc);

	return (0);
}

/*
 * Setup for a virtual disk whose backend is a file (exported as a single slice
 * or as a full disk). In that case, the backend is accessed using the vnode
 * interface.
 */
static int
vd_setup_backend_vnode(vd_t *vd)
{
	int		rval, status;
	dev_t		dev;
	char		*file_path = vd->device_path;
	ldi_handle_t	lhandle;
	struct dk_cinfo	dk_cinfo;

	ASSERT(!vd->volume);

	if ((status = vn_open(file_path, UIO_SYSSPACE, vd->open_flags | FOFFMAX,
	    0, &vd->file_vnode, 0, 0)) != 0) {
		if ((status == ENXIO || status == ENODEV || status == ENOENT ||
		    status == EROFS) && (!(vd->initialized & VD_SETUP_ERROR) &&
		    !(DEVI_IS_ATTACHING(vd->vds->dip)))) {
			PRN("vn_open(%s) = errno %d", file_path, status);
		}
		return (status);
	}

	/*
	 * We set vd->file now so that vds_destroy_vd will take care of
	 * closing the file and releasing the vnode in case of an error.
	 */
	vd->file = B_TRUE;

	vd->max_xfer_sz = maxphys / DEV_BSIZE; /* default transfer size */

	/*
	 * Get max_xfer_sz from the device where the file is.
	 */
	dev = vd->file_vnode->v_vfsp->vfs_dev;
	PR0("underlying device of %s = (%d, %d)\n", file_path,
	    getmajor(dev), getminor(dev));

	status = ldi_open_by_dev(&dev, OTYP_BLK, FREAD, kcred, &lhandle,
	    vd->vds->ldi_ident);

	if (status != 0) {
		PR0("ldi_open() returned errno %d for underlying device",
		    status);
	} else {
		if ((status = ldi_ioctl(lhandle, DKIOCINFO,
		    (intptr_t)&dk_cinfo, (vd->open_flags | FKIOCTL), kcred,
		    &rval)) != 0) {
			PR0("ldi_ioctl(DKIOCINFO) returned errno %d for "
			    "underlying device", status);
		} else {
			/*
			 * Store the device's max transfer size for
			 * return to the client
			 */
			vd->max_xfer_sz = dk_cinfo.dki_maxtransfer;
		}

		PR0("close the underlying device");
		(void) ldi_close(lhandle, FREAD, kcred);
	}

	PR0("using file %s on device (%d, %d), max_xfer = %u blks",
	    file_path, getmajor(dev), getminor(dev), vd->max_xfer_sz);

	if (vd->vdisk_type == VD_DISK_TYPE_SLICE)
		status = vd_setup_slice_image(vd);
	else
		status = vd_setup_disk_image(vd);

	return (status);
}

static int
vd_setup_slice_image(vd_t *vd)
{
	struct dk_label label;
	int status;

	if ((status = vd_backend_check_size(vd)) != 0) {
		PRN("Check size failed for %s (errno %d)",
		    vd->device_path, status);
		return (EIO);
	}

	vd->vdisk_media = VD_MEDIA_FIXED;
	vd->vdisk_label = (vd_slice_label == VD_DISK_LABEL_UNK)?
	    vd_file_slice_label : vd_slice_label;

	if (vd->vdisk_label == VD_DISK_LABEL_EFI ||
	    vd->dskimg_size >= 2 * ONE_TERABYTE) {
		status = vd_setup_partition_efi(vd);
	} else {
		/*
		 * We build a default label to get a geometry for
		 * the vdisk. Then the partition setup function will
		 * adjust the vtoc so that it defines a single-slice
		 * disk.
		 */
		vd_build_default_label(vd->dskimg_size, vd->vdisk_bsize,
		    &label);
		vd_label_to_vtocgeom(&label, &vd->vtoc, &vd->dk_geom);
		status = vd_setup_partition_vtoc(vd);
	}

	return (status);
}

static int
vd_setup_disk_image(vd_t *vd)
{
	int status;
	char *backend_path = vd->device_path;

	if ((status = vd_backend_check_size(vd)) != 0) {
		PRN("Check size failed for %s (errno %d)",
		    backend_path, status);
		return (EIO);
	}

	/* size should be at least sizeof(dk_label) */
	if (vd->dskimg_size < sizeof (struct dk_label)) {
		PRN("Size of file has to be at least %ld bytes",
		    sizeof (struct dk_label));
		return (EIO);
	}

	/*
	 * Find and validate the geometry of a disk image.
	 */
	status = vd_dskimg_validate_geometry(vd);
	if (status != 0 && status != EINVAL && status != ENOTSUP) {
		PRN("Failed to read label from %s", backend_path);
		return (EIO);
	}

	if (vd_dskimg_is_iso_image(vd)) {
		/*
		 * Indicate whether to call this a CD or DVD from the size
		 * of the ISO image (images for both drive types are stored
		 * in the ISO-9600 format). CDs can store up to just under 1Gb
		 */
		if ((vd->vdisk_size * vd->vdisk_bsize) > ONE_GIGABYTE)
			vd->vdisk_media = VD_MEDIA_DVD;
		else
			vd->vdisk_media = VD_MEDIA_CD;
	} else {
		vd->vdisk_media = VD_MEDIA_FIXED;
	}

	/* Setup devid for the disk image */

	if (vd->vdisk_label != VD_DISK_LABEL_UNK) {

		status = vd_dskimg_read_devid(vd, &vd->dskimg_devid);

		if (status == 0) {
			/* a valid devid was found */
			return (0);
		}

		if (status != EINVAL) {
			/*
			 * There was an error while trying to read the devid.
			 * So this disk image may have a devid but we are
			 * unable to read it.
			 */
			PR0("can not read devid for %s", backend_path);
			vd->dskimg_devid = NULL;
			return (0);
		}
	}

	/*
	 * No valid device id was found so we create one. Note that a failure
	 * to create a device id is not fatal and does not prevent the disk
	 * image from being attached.
	 */
	PR1("creating devid for %s", backend_path);

	if (ddi_devid_init(vd->vds->dip, DEVID_FAB, 0, 0,
	    &vd->dskimg_devid) != DDI_SUCCESS) {
		PR0("fail to create devid for %s", backend_path);
		vd->dskimg_devid = NULL;
		return (0);
	}

	/*
	 * Write devid to the disk image. The devid is stored into the disk
	 * image if we have a valid label; otherwise the devid will be stored
	 * when the user writes a valid label.
	 */
	if (vd->vdisk_label != VD_DISK_LABEL_UNK) {
		if (vd_dskimg_write_devid(vd, vd->dskimg_devid) != 0) {
			PR0("fail to write devid for %s", backend_path);
			ddi_devid_free(vd->dskimg_devid);
			vd->dskimg_devid = NULL;
		}
	}

	return (0);
}


/*
 * Description:
 *	Open a device using its device path (supplied by ldm(1m))
 *
 * Parameters:
 *	vd	- pointer to structure containing the vDisk info
 *	flags	- open flags
 *
 * Return Value
 *	0	- success
 *	!= 0	- some other non-zero return value from ldi(9F) functions
 */
static int
vd_open_using_ldi_by_name(vd_t *vd, int flags)
{
	int		status;
	char		*device_path = vd->device_path;

	/* Attempt to open device */
	status = ldi_open_by_name(device_path, flags, kcred,
	    &vd->ldi_handle[0], vd->vds->ldi_ident);

	/*
	 * The open can fail for example if we are opening an empty slice.
	 * In case of a failure, we try the open again but this time with
	 * the FNDELAY flag.
	 */
	if (status != 0)
		status = ldi_open_by_name(device_path, flags | FNDELAY,
		    kcred, &vd->ldi_handle[0], vd->vds->ldi_ident);

	if (status != 0) {
		PR0("ldi_open_by_name(%s) = errno %d", device_path, status);
		vd->ldi_handle[0] = NULL;
		return (status);
	}

	return (0);
}

/*
 * Setup for a virtual disk which backend is a device (a physical disk,
 * slice or volume device) exported as a full disk or as a slice. In these
 * cases, the backend is accessed using the LDI interface.
 */
static int
vd_setup_backend_ldi(vd_t *vd)
{
	int		rval, status;
	struct dk_cinfo	dk_cinfo;
	char		*device_path = vd->device_path;

	/* device has been opened by vd_identify_dev() */
	ASSERT(vd->ldi_handle[0] != NULL);
	ASSERT(vd->dev[0] != NULL);

	vd->file = B_FALSE;

	/* Verify backing device supports dk_cinfo */
	if ((status = ldi_ioctl(vd->ldi_handle[0], DKIOCINFO,
	    (intptr_t)&dk_cinfo, (vd->open_flags | FKIOCTL), kcred,
	    &rval)) != 0) {
		PRN("ldi_ioctl(DKIOCINFO) returned errno %d for %s",
		    status, device_path);
		return (status);
	}
	if (dk_cinfo.dki_partition >= V_NUMPAR) {
		PRN("slice %u >= maximum slice %u for %s",
		    dk_cinfo.dki_partition, V_NUMPAR, device_path);
		return (EIO);
	}

	/*
	 * The device has been opened read-only by vd_identify_dev(), re-open
	 * it read-write if the write flag is set and we don't have an optical
	 * device such as a CD-ROM, which, for now, we do not permit writes to
	 * and thus should not export write operations to the client.
	 *
	 * Future: if/when we implement support for guest domains writing to
	 * optical devices we will need to do further checking of the media type
	 * to distinguish between read-only and writable discs.
	 */
	if (dk_cinfo.dki_ctype == DKC_CDROM) {

		vd->open_flags &= ~FWRITE;

	} else if (vd->open_flags & FWRITE) {

		(void) ldi_close(vd->ldi_handle[0], vd->open_flags & ~FWRITE,
		    kcred);
		status = vd_open_using_ldi_by_name(vd, vd->open_flags);
		if (status != 0) {
			PR0("Failed to open (%s) = errno %d",
			    device_path, status);
			return (status);
		}
	}

	/* Store the device's max transfer size for return to the client */
	vd->max_xfer_sz = dk_cinfo.dki_maxtransfer;

	/*
	 * We need to work out if it's an ATAPI (IDE CD-ROM) or SCSI device so
	 * that we can use the correct CDB group when sending USCSI commands.
	 */
	vd->is_atapi_dev = vd_is_atapi_device(vd);

	/*
	 * Export a full disk.
	 *
	 * The exported device can be either a volume, a disk or a CD/DVD
	 * device.  We export a device as a full disk if we have an entire
	 * disk slice (slice 2) and if this slice is exported as a full disk
	 * and not as a single slice disk. A CD or DVD device is exported
	 * as a full disk (even if it isn't s2). A volume is exported as a
	 * full disk as long as the "slice" option is not specified.
	 */
	if (vd->vdisk_type == VD_DISK_TYPE_DISK) {

		if (vd->volume) {
			/* setup disk image */
			return (vd_setup_disk_image(vd));
		}

		if (dk_cinfo.dki_partition == VD_ENTIRE_DISK_SLICE ||
		    dk_cinfo.dki_ctype == DKC_CDROM) {
			ASSERT(!vd->volume);
			if (dk_cinfo.dki_ctype == DKC_SCSI_CCS)
				vd->scsi = B_TRUE;
			return (vd_setup_full_disk(vd));
		}
	}

	/*
	 * Export a single slice disk.
	 *
	 * The exported device can be either a volume device or a disk slice. If
	 * it is a disk slice different from slice 2 then it is always exported
	 * as a single slice disk even if the "slice" option is not specified.
	 * If it is disk slice 2 or a volume device then it is exported as a
	 * single slice disk only if the "slice" option is specified.
	 */
	return (vd_setup_single_slice_disk(vd));
}

static int
vd_setup_single_slice_disk(vd_t *vd)
{
	int status, rval;
	struct dk_label label;
	char *device_path = vd->device_path;
	struct vtoc vtoc;

	vd->vdisk_media = VD_MEDIA_FIXED;

	if (vd->volume) {
		ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);
	}

	/*
	 * We export the slice as a single slice disk even if the "slice"
	 * option was not specified.
	 */
	vd->vdisk_type  = VD_DISK_TYPE_SLICE;
	vd->nslices	= 1;

	/* Get size of backing device */
	if ((status = vd_backend_check_size(vd)) != 0) {
		PRN("Check size failed for %s (errno %d)", device_path, status);
		return (EIO);
	}

	/*
	 * When exporting a slice or a device as a single slice disk, we don't
	 * care about any partitioning exposed by the backend. The goal is just
	 * to export the backend as a flat storage. We provide a fake partition
	 * table (either a VTOC or EFI), which presents only one slice, to
	 * accommodate tools expecting a disk label. The selection of the label
	 * type (VTOC or EFI) depends on the value of the vd_slice_label
	 * variable.
	 */
	if (vd_slice_label == VD_DISK_LABEL_EFI ||
	    vd->vdisk_size >= ONE_TERABYTE / vd->vdisk_bsize) {
		vd->vdisk_label = VD_DISK_LABEL_EFI;
	} else {
		status = ldi_ioctl(vd->ldi_handle[0], DKIOCGEXTVTOC,
		    (intptr_t)&vd->vtoc, (vd->open_flags | FKIOCTL),
		    kcred, &rval);

		if (status == ENOTTY) {
			/* try with the non-extended vtoc ioctl */
			status = ldi_ioctl(vd->ldi_handle[0], DKIOCGVTOC,
			    (intptr_t)&vtoc, (vd->open_flags | FKIOCTL),
			    kcred, &rval);
			vtoctoextvtoc(vtoc, vd->vtoc);
		}

		if (status == 0) {
			status = ldi_ioctl(vd->ldi_handle[0], DKIOCGGEOM,
			    (intptr_t)&vd->dk_geom, (vd->open_flags | FKIOCTL),
			    kcred, &rval);

			if (status != 0) {
				PRN("ldi_ioctl(DKIOCGEOM) returned errno %d "
				    "for %s", status, device_path);
				return (status);
			}
			vd->vdisk_label = VD_DISK_LABEL_VTOC;

		} else if (vd_slice_label == VD_DISK_LABEL_VTOC) {

			vd->vdisk_label = VD_DISK_LABEL_VTOC;
			vd_build_default_label(vd->vdisk_size * vd->vdisk_bsize,
			    vd->vdisk_bsize, &label);
			vd_label_to_vtocgeom(&label, &vd->vtoc, &vd->dk_geom);

		} else {
			vd->vdisk_label = VD_DISK_LABEL_EFI;
		}
	}

	if (vd->vdisk_label == VD_DISK_LABEL_VTOC) {
		/* export with a fake VTOC label */
		status = vd_setup_partition_vtoc(vd);

	} else {
		/* export with a fake EFI label */
		status = vd_setup_partition_efi(vd);
	}

	return (status);
}

/*
 * This function is invoked when setting up the vdisk backend and to process
 * the VD_OP_GET_CAPACITY operation. It checks the backend size and set the
 * following attributes of the vd structure:
 *
 * - vdisk_bsize: block size for the virtual disk used by the VIO protocol. Its
 *   value is 512 bytes (DEV_BSIZE) when the backend is a file, a volume or a
 *   CD/DVD. When the backend is a disk or a disk slice then it has the value
 *   of the logical block size of that disk (as returned by the DKIOCGMEDIAINFO
 *   ioctl). This block size is expected to be a power of 2 and a multiple of
 *   512.
 *
 * - vdisk_size: size of the virtual disk expressed as a number of vdisk_bsize
 *   blocks.
 *
 * vdisk_size and vdisk_bsize are sent to the vdisk client during the connection
 * handshake and in the result of a VD_OP_GET_CAPACITY operation.
 *
 * - backend_bsize: block size of the backend device. backend_bsize has the same
 *   value as vdisk_bsize except when the backend is a CD/DVD. In that case,
 *   vdisk_bsize is set to 512 (DEV_BSIZE) while backend_bsize is set to the
 *   effective logical block size of the CD/DVD (usually 2048).
 *
 * - dskimg_size: size of the backend when the backend is a disk image. This
 *   attribute is set only when the backend is a file or a volume, otherwise it
 *   is unused.
 *
 * - vio_bshift: number of bit to shift to convert a VIO block number (which
 *   uses a block size of vdisk_bsize) to a buf(9s) block number (which uses a
 *   block size of 512 bytes) i.e. we have vdisk_bsize = 512 x 2 ^ vio_bshift
 *
 * - vdisk_media: media of the virtual disk. This function only sets this
 *   attribute for physical disk and CD/DVD. For other backend types, this
 *   attribute is set in the setup function of the backend.
 */
static int
vd_backend_check_size(vd_t *vd)
{
	size_t backend_size, backend_bsize, vdisk_bsize;
	size_t old_size, new_size;
	struct dk_minfo minfo;
	vattr_t vattr;
	int rval, rv, media, nshift = 0;
	uint32_t n;

	if (vd->file) {

		/* file (slice or full disk) */
		vattr.va_mask = AT_SIZE;
		rv = VOP_GETATTR(vd->file_vnode, &vattr, 0, kcred, NULL);
		if (rv != 0) {
			PR0("VOP_GETATTR(%s) = errno %d", vd->device_path, rv);
			return (rv);
		}
		backend_size = vattr.va_size;
		backend_bsize = DEV_BSIZE;
		vdisk_bsize = DEV_BSIZE;

	} else if (vd->volume) {

		/* volume (slice or full disk) */
		rv = ldi_get_size(vd->ldi_handle[0], &backend_size);
		if (rv != DDI_SUCCESS) {
			PR0("ldi_get_size() failed for %s", vd->device_path);
			return (EIO);
		}
		backend_bsize = DEV_BSIZE;
		vdisk_bsize = DEV_BSIZE;

	} else {

		/* physical disk or slice */
		rv = ldi_ioctl(vd->ldi_handle[0], DKIOCGMEDIAINFO,
		    (intptr_t)&minfo, (vd->open_flags | FKIOCTL),
		    kcred, &rval);
		if (rv != 0) {
			PR0("DKIOCGMEDIAINFO failed for %s (err=%d)",
			    vd->device_path, rv);
			return (rv);
		}

		if (vd->vdisk_type == VD_DISK_TYPE_SLICE) {
			rv = ldi_get_size(vd->ldi_handle[0], &backend_size);
			if (rv != DDI_SUCCESS) {
				PR0("ldi_get_size() failed for %s",
				    vd->device_path);
				return (EIO);
			}
		} else {
			ASSERT(vd->vdisk_type == VD_DISK_TYPE_DISK);
			backend_size = minfo.dki_capacity * minfo.dki_lbsize;
		}

		backend_bsize = minfo.dki_lbsize;
		media = DK_MEDIATYPE2VD_MEDIATYPE(minfo.dki_media_type);

		/*
		 * If the device is a CD or a DVD then we force the vdisk block
		 * size to 512 bytes (DEV_BSIZE). In that case, vdisk_bsize can
		 * be different from backend_size.
		 */
		if (media == VD_MEDIA_CD || media == VD_MEDIA_DVD)
			vdisk_bsize = DEV_BSIZE;
		else
			vdisk_bsize = backend_bsize;
	}

	/* check vdisk block size */
	if (vdisk_bsize == 0 || vdisk_bsize % DEV_BSIZE != 0)
		return (EINVAL);

	old_size = vd->vdisk_size;
	new_size = backend_size / vdisk_bsize;

	/* check if size has changed */
	if (old_size != VD_SIZE_UNKNOWN && old_size == new_size &&
	    vd->vdisk_bsize == vdisk_bsize)
		return (0);

	/* cache info for blk conversion */
	for (n = vdisk_bsize / DEV_BSIZE; n > 1; n >>= 1) {
		if ((n & 0x1) != 0) {
			/* blk_size is not a power of 2 */
			return (EINVAL);
		}
		nshift++;
	}

	vd->vio_bshift = nshift;
	vd->vdisk_size = new_size;
	vd->vdisk_bsize = vdisk_bsize;
	vd->backend_bsize = backend_bsize;

	if (vd->file || vd->volume)
		vd->dskimg_size = backend_size;

	/*
	 * If we are exporting a single-slice disk and the size of the backend
	 * has changed then we regenerate the partition setup so that the
	 * partitioning matches with the new disk backend size.
	 */

	if (vd->vdisk_type == VD_DISK_TYPE_SLICE) {
		/* slice or file or device exported as a slice */
		if (vd->vdisk_label == VD_DISK_LABEL_VTOC) {
			rv = vd_setup_partition_vtoc(vd);
			if (rv != 0) {
				PR0("vd_setup_partition_vtoc() failed for %s "
				    "(err = %d)", vd->device_path, rv);
				return (rv);
			}
		} else {
			rv = vd_setup_partition_efi(vd);
			if (rv != 0) {
				PR0("vd_setup_partition_efi() failed for %s "
				    "(err = %d)", vd->device_path, rv);
				return (rv);
			}
		}

	} else if (!vd->file && !vd->volume) {
		/* physical disk */
		ASSERT(vd->vdisk_type == VD_DISK_TYPE_DISK);
		vd->vdisk_media = media;
	}

	return (0);
}

/*
 * Description:
 *	Open a device using its device path and identify if this is
 *	a disk device or a volume device.
 *
 * Parameters:
 *	vd	- pointer to structure containing the vDisk info
 *	dtype	- return the driver type of the device
 *
 * Return Value
 *	0	- success
 *	!= 0	- some other non-zero return value from ldi(9F) functions
 */
static int
vd_identify_dev(vd_t *vd, int *dtype)
{
	int status, i;
	char *device_path = vd->device_path;
	char *drv_name;
	int drv_type;
	vds_t *vds = vd->vds;

	status = vd_open_using_ldi_by_name(vd, vd->open_flags & ~FWRITE);
	if (status != 0) {
		PR0("Failed to open (%s) = errno %d", device_path, status);
		return (status);
	}

	/* Get device number of backing device */
	if ((status = ldi_get_dev(vd->ldi_handle[0], &vd->dev[0])) != 0) {
		PRN("ldi_get_dev() returned errno %d for %s",
		    status, device_path);
		return (status);
	}

	/*
	 * We start by looking if the driver is in the list from vds.conf
	 * so that we can override the built-in list using vds.conf.
	 */
	drv_name = ddi_major_to_name(getmajor(vd->dev[0]));
	drv_type = VD_DRIVER_UNKNOWN;

	/* check vds.conf list */
	for (i = 0; i < vds->num_drivers; i++) {
		if (vds->driver_types[i].type == VD_DRIVER_UNKNOWN) {
			/* ignore invalid entries */
			continue;
		}
		if (strcmp(drv_name, vds->driver_types[i].name) == 0) {
			drv_type = vds->driver_types[i].type;
			goto done;
		}
	}

	/* check built-in list */
	for (i = 0; i < VDS_NUM_DRIVERS; i++) {
		if (strcmp(drv_name, vds_driver_types[i].name) == 0) {
			drv_type = vds_driver_types[i].type;
			goto done;
		}
	}

done:
	PR0("driver %s identified as %s", drv_name,
	    (drv_type == VD_DRIVER_DISK)? "DISK" :
	    (drv_type == VD_DRIVER_VOLUME)? "VOLUME" : "UNKNOWN");

	if (strcmp(drv_name, "zfs") == 0)
		vd->zvol = B_TRUE;

	*dtype = drv_type;

	return (0);
}

static int
vd_setup_vd(vd_t *vd)
{
	int		status, drv_type, pseudo;
	dev_info_t	*dip;
	vnode_t		*vnp;
	char		*path = vd->device_path;
	char		tq_name[TASKQ_NAMELEN];

	/* make sure the vdisk backend is valid */
	if ((status = lookupname(path, UIO_SYSSPACE,
	    FOLLOW, NULLVPP, &vnp)) != 0) {
		PR0("Cannot lookup %s errno %d", path, status);
		goto done;
	}

	switch (vnp->v_type) {
	case VREG:
		/*
		 * Backend is a file so it is exported as a full disk or as a
		 * single slice disk using the vnode interface.
		 */
		VN_RELE(vnp);
		vd->volume = B_FALSE;
		status = vd_setup_backend_vnode(vd);
		break;

	case VBLK:
	case VCHR:
		/*
		 * Backend is a device. In that case, it is exported using the
		 * LDI interface, and it is exported either as a single-slice
		 * disk or as a full disk depending on the "slice" option and
		 * on the type of device.
		 *
		 * - A volume device is exported as a single-slice disk if the
		 *   "slice" is specified, otherwise it is exported as a full
		 *   disk.
		 *
		 * - A disk slice (different from slice 2) is always exported
		 *   as a single slice disk using the LDI interface.
		 *
		 * - The slice 2 of a disk is exported as a single slice disk
		 *   if the "slice" option is specified, otherwise the entire
		 *   disk will be exported.
		 *
		 * - The slice of a CD or DVD is exported as single slice disk
		 *   if the "slice" option is specified, otherwise the entire
		 *   disk will be exported.
		 */

		/* check if this is a pseudo device */
		if ((dip = ddi_hold_devi_by_instance(getmajor(vnp->v_rdev),
		    dev_to_instance(vnp->v_rdev), 0))  == NULL) {
			PRN("%s is no longer accessible", path);
			VN_RELE(vnp);
			status = EIO;
			break;
		}
		pseudo = is_pseudo_device(dip);
		ddi_release_devi(dip);
		VN_RELE(vnp);

		if ((status = vd_identify_dev(vd, &drv_type)) != 0) {
			if (status != ENODEV && status != ENXIO &&
			    status != ENOENT && status != EROFS) {
				PRN("%s identification failed with status %d",
				    path, status);
				status = EIO;
			}
			break;
		}

		/*
		 * If the driver hasn't been identified then we consider that
		 * pseudo devices are volumes and other devices are disks.
		 */
		if (drv_type == VD_DRIVER_VOLUME ||
		    (drv_type == VD_DRIVER_UNKNOWN && pseudo)) {
			vd->volume = B_TRUE;
		}

		/*
		 * If this is a volume device then its usage depends if the
		 * "slice" option is set or not. If the "slice" option is set
		 * then the volume device will be exported as a single slice,
		 * otherwise it will be exported as a full disk.
		 *
		 * For backward compatibility, if vd_volume_force_slice is set
		 * then we always export volume devices as slices.
		 */
		if (vd->volume && vd_volume_force_slice) {
			vd->vdisk_type = VD_DISK_TYPE_SLICE;
			vd->nslices = 1;
		}

		status = vd_setup_backend_ldi(vd);
		break;

	default:
		PRN("Unsupported vdisk backend %s", path);
		VN_RELE(vnp);
		status = EBADF;
	}

done:
	if (status != 0) {
		/*
		 * If the error is retryable print an error message only
		 * during the first try.
		 */
		if (status == ENXIO || status == ENODEV ||
		    status == ENOENT || status == EROFS) {
			if (!(vd->initialized & VD_SETUP_ERROR) &&
			    !(DEVI_IS_ATTACHING(vd->vds->dip))) {
				PRN("%s is currently inaccessible (error %d)",
				    path, status);
			}
			status = EAGAIN;
		} else {
			PRN("%s can not be exported as a virtual disk "
			    "(error %d)", path, status);
		}
		vd->initialized |= VD_SETUP_ERROR;

	} else if (vd->initialized & VD_SETUP_ERROR) {
		/* print a message only if we previously had an error */
		PRN("%s is now online", path);
		vd->initialized &= ~VD_SETUP_ERROR;
	}

	/*
	 * For file or ZFS volume we also need an I/O queue.
	 *
	 * The I/O task queue is initialized here and not in vds_do_init_vd()
	 * (as the start and completion queues) because vd_setup_vd() will be
	 * call again if the backend is not available, and we need to know if
	 * the backend is a ZFS volume or a file.
	 */
	if ((vd->file || vd->zvol) && vd->ioq == NULL) {
		(void) snprintf(tq_name, sizeof (tq_name), "vd_ioq%lu", vd->id);

		if ((vd->ioq = ddi_taskq_create(vd->vds->dip, tq_name,
		    vd_ioq_nthreads, TASKQ_DEFAULTPRI, 0)) == NULL) {
			PRN("Could not create io task queue");
			return (EIO);
		}
	}

	return (status);
}

static int
vds_do_init_vd(vds_t *vds, uint64_t id, char *device_path, uint64_t options,
    uint64_t ldc_id, vd_t **vdp)
{
	char			tq_name[TASKQ_NAMELEN];
	int			status;
	ddi_iblock_cookie_t	iblock = NULL;
	ldc_attr_t		ldc_attr;
	vd_t			*vd;


	ASSERT(vds != NULL);
	ASSERT(device_path != NULL);
	ASSERT(vdp != NULL);
	PR0("Adding vdisk for %s", device_path);

	if ((vd = kmem_zalloc(sizeof (*vd), KM_NOSLEEP)) == NULL) {
		PRN("No memory for virtual disk");
		return (EAGAIN);
	}
	*vdp = vd;	/* assign here so vds_destroy_vd() can cleanup later */
	vd->id = id;
	vd->vds = vds;
	(void) strncpy(vd->device_path, device_path, MAXPATHLEN);

	/* Setup open flags */
	vd->open_flags = FREAD;

	if (!(options & VD_OPT_RDONLY))
		vd->open_flags |= FWRITE;

	if (options & VD_OPT_EXCLUSIVE)
		vd->open_flags |= FEXCL;

	/* Setup disk type */
	if (options & VD_OPT_SLICE) {
		vd->vdisk_type = VD_DISK_TYPE_SLICE;
		vd->nslices = 1;
	} else {
		vd->vdisk_type = VD_DISK_TYPE_DISK;
		vd->nslices = V_NUMPAR;
	}

	/* default disk label */
	vd->vdisk_label = VD_DISK_LABEL_UNK;

	/* Open vdisk and initialize parameters */
	if ((status = vd_setup_vd(vd)) == 0) {
		vd->initialized |= VD_DISK_READY;

		ASSERT(vd->nslices > 0 && vd->nslices <= V_NUMPAR);
		PR0("vdisk_type = %s, volume = %s, file = %s, nslices = %u",
		    ((vd->vdisk_type == VD_DISK_TYPE_DISK) ? "disk" : "slice"),
		    (vd->volume ? "yes" : "no"), (vd->file ? "yes" : "no"),
		    vd->nslices);
	} else {
		if (status != EAGAIN)
			return (status);
	}

	/* Initialize locking */
	if (ddi_get_soft_iblock_cookie(vds->dip, DDI_SOFTINT_MED,
	    &iblock) != DDI_SUCCESS) {
		PRN("Could not get iblock cookie.");
		return (EIO);
	}

	mutex_init(&vd->lock, NULL, MUTEX_DRIVER, iblock);
	vd->initialized |= VD_LOCKING;


	/* Create start and completion task queues for the vdisk */
	(void) snprintf(tq_name, sizeof (tq_name), "vd_startq%lu", id);
	PR1("tq_name = %s", tq_name);
	if ((vd->startq = ddi_taskq_create(vds->dip, tq_name, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		PRN("Could not create task queue");
		return (EIO);
	}
	(void) snprintf(tq_name, sizeof (tq_name), "vd_completionq%lu", id);
	PR1("tq_name = %s", tq_name);
	if ((vd->completionq = ddi_taskq_create(vds->dip, tq_name, 1,
	    TASKQ_DEFAULTPRI, 0)) == NULL) {
		PRN("Could not create task queue");
		return (EIO);
	}

	/* Allocate the staging buffer */
	vd->max_msglen = sizeof (vio_msg_t);	/* baseline vio message size */
	vd->vio_msgp = kmem_alloc(vd->max_msglen, KM_SLEEP);

	vd->enabled = 1;	/* before callback can dispatch to startq */


	/* Bring up LDC */
	ldc_attr.devclass	= LDC_DEV_BLK_SVC;
	ldc_attr.instance	= ddi_get_instance(vds->dip);
	ldc_attr.mode		= LDC_MODE_UNRELIABLE;
	ldc_attr.mtu		= VD_LDC_MTU;
	if ((status = ldc_init(ldc_id, &ldc_attr, &vd->ldc_handle)) != 0) {
		PRN("Could not initialize LDC channel %lx, "
		    "init failed with error %d", ldc_id, status);
		return (status);
	}
	vd->initialized |= VD_LDC;

	if ((status = ldc_reg_callback(vd->ldc_handle, vd_handle_ldc_events,
	    (caddr_t)vd)) != 0) {
		PRN("Could not initialize LDC channel %lu,"
		    "reg_callback failed with error %d", ldc_id, status);
		return (status);
	}

	if ((status = ldc_open(vd->ldc_handle)) != 0) {
		PRN("Could not initialize LDC channel %lu,"
		    "open failed with error %d", ldc_id, status);
		return (status);
	}

	if ((status = ldc_up(vd->ldc_handle)) != 0) {
		PR0("ldc_up() returned errno %d", status);
	}

	/* Allocate the inband task memory handle */
	status = ldc_mem_alloc_handle(vd->ldc_handle, &(vd->inband_task.mhdl));
	if (status) {
		PRN("Could not initialize LDC channel %lu,"
		    "alloc_handle failed with error %d", ldc_id, status);
		return (ENXIO);
	}

	/* Add the successfully-initialized vdisk to the server's table */
	if (mod_hash_insert(vds->vd_table, (mod_hash_key_t)id, vd) != 0) {
		PRN("Error adding vdisk ID %lu to table", id);
		return (EIO);
	}

	/* store initial state */
	vd->state = VD_STATE_INIT;

	return (0);
}

static void
vd_free_dring_task(vd_t *vdp)
{
	if (vdp->dring_task != NULL) {
		ASSERT(vdp->dring_len != 0);
		/* Free all dring_task memory handles */
		for (int i = 0; i < vdp->dring_len; i++) {
			(void) ldc_mem_free_handle(vdp->dring_task[i].mhdl);
			kmem_free(vdp->dring_task[i].request,
			    (vdp->descriptor_size -
			    sizeof (vio_dring_entry_hdr_t)));
			vdp->dring_task[i].request = NULL;
			kmem_free(vdp->dring_task[i].msg, vdp->max_msglen);
			vdp->dring_task[i].msg = NULL;
		}
		kmem_free(vdp->dring_task,
		    (sizeof (*vdp->dring_task)) * vdp->dring_len);
		vdp->dring_task = NULL;
	}

	if (vdp->write_queue != NULL) {
		kmem_free(vdp->write_queue, sizeof (buf_t *) * vdp->dring_len);
		vdp->write_queue = NULL;
	}
}

/*
 * Destroy the state associated with a virtual disk
 */
static void
vds_destroy_vd(void *arg)
{
	vd_t	*vd = (vd_t *)arg;
	int	retry = 0, rv;

	if (vd == NULL)
		return;

	PR0("Destroying vdisk state");

	/* Disable queuing requests for the vdisk */
	if (vd->initialized & VD_LOCKING) {
		mutex_enter(&vd->lock);
		vd->enabled = 0;
		mutex_exit(&vd->lock);
	}

	/* Drain and destroy start queue (*before* destroying ioq) */
	if (vd->startq != NULL)
		ddi_taskq_destroy(vd->startq);	/* waits for queued tasks */

	/* Drain and destroy the I/O queue (*before* destroying completionq) */
	if (vd->ioq != NULL)
		ddi_taskq_destroy(vd->ioq);

	/* Drain and destroy completion queue (*before* shutting down LDC) */
	if (vd->completionq != NULL)
		ddi_taskq_destroy(vd->completionq);	/* waits for tasks */

	vd_free_dring_task(vd);

	/* Free the inband task memory handle */
	(void) ldc_mem_free_handle(vd->inband_task.mhdl);

	/* Shut down LDC */
	if (vd->initialized & VD_LDC) {
		/* unmap the dring */
		if (vd->initialized & VD_DRING)
			(void) ldc_mem_dring_unmap(vd->dring_handle);

		/* close LDC channel - retry on EAGAIN */
		while ((rv = ldc_close(vd->ldc_handle)) == EAGAIN) {
			if (++retry > vds_ldc_retries) {
				PR0("Timed out closing channel");
				break;
			}
			drv_usecwait(vds_ldc_delay);
		}
		if (rv == 0) {
			(void) ldc_unreg_callback(vd->ldc_handle);
			(void) ldc_fini(vd->ldc_handle);
		} else {
			/*
			 * Closing the LDC channel has failed. Ideally we should
			 * fail here but there is no Zeus level infrastructure
			 * to handle this. The MD has already been changed and
			 * we have to do the close. So we try to do as much
			 * clean up as we can.
			 */
			(void) ldc_set_cb_mode(vd->ldc_handle, LDC_CB_DISABLE);
			while (ldc_unreg_callback(vd->ldc_handle) == EAGAIN)
				drv_usecwait(vds_ldc_delay);
		}
	}

	/* Free the staging buffer for msgs */
	if (vd->vio_msgp != NULL) {
		kmem_free(vd->vio_msgp, vd->max_msglen);
		vd->vio_msgp = NULL;
	}

	/* Free the inband message buffer */
	if (vd->inband_task.msg != NULL) {
		kmem_free(vd->inband_task.msg, vd->max_msglen);
		vd->inband_task.msg = NULL;
	}

	if (vd->file) {
		/* Close file */
		(void) VOP_CLOSE(vd->file_vnode, vd->open_flags, 1,
		    0, kcred, NULL);
		VN_RELE(vd->file_vnode);
	} else {
		/* Close any open backing-device slices */
		for (uint_t slice = 0; slice < V_NUMPAR; slice++) {
			if (vd->ldi_handle[slice] != NULL) {
				PR0("Closing slice %u", slice);
				(void) ldi_close(vd->ldi_handle[slice],
				    vd->open_flags, kcred);
			}
		}
	}

	/* Free disk image devid */
	if (vd->dskimg_devid != NULL)
		ddi_devid_free(vd->dskimg_devid);

	/* Free any fake label */
	if (vd->flabel) {
		kmem_free(vd->flabel, vd->flabel_size);
		vd->flabel = NULL;
		vd->flabel_size = 0;
	}

	/* Free lock */
	if (vd->initialized & VD_LOCKING)
		mutex_destroy(&vd->lock);

	/* Finally, free the vdisk structure itself */
	kmem_free(vd, sizeof (*vd));
}

static int
vds_init_vd(vds_t *vds, uint64_t id, char *device_path, uint64_t options,
    uint64_t ldc_id)
{
	int	status;
	vd_t	*vd = NULL;


	if ((status = vds_do_init_vd(vds, id, device_path, options,
	    ldc_id, &vd)) != 0)
		vds_destroy_vd(vd);

	return (status);
}

static int
vds_do_get_ldc_id(md_t *md, mde_cookie_t vd_node, mde_cookie_t *channel,
    uint64_t *ldc_id)
{
	int	num_channels;


	/* Look for channel endpoint child(ren) of the vdisk MD node */
	if ((num_channels = md_scan_dag(md, vd_node,
	    md_find_name(md, VD_CHANNEL_ENDPOINT),
	    md_find_name(md, "fwd"), channel)) <= 0) {
		PRN("No \"%s\" found for virtual disk", VD_CHANNEL_ENDPOINT);
		return (-1);
	}

	/* Get the "id" value for the first channel endpoint node */
	if (md_get_prop_val(md, channel[0], VD_ID_PROP, ldc_id) != 0) {
		PRN("No \"%s\" property found for \"%s\" of vdisk",
		    VD_ID_PROP, VD_CHANNEL_ENDPOINT);
		return (-1);
	}

	if (num_channels > 1) {
		PRN("Using ID of first of multiple channels for this vdisk");
	}

	return (0);
}

static int
vds_get_ldc_id(md_t *md, mde_cookie_t vd_node, uint64_t *ldc_id)
{
	int		num_nodes, status;
	size_t		size;
	mde_cookie_t	*channel;


	if ((num_nodes = md_node_count(md)) <= 0) {
		PRN("Invalid node count in Machine Description subtree");
		return (-1);
	}
	size = num_nodes*(sizeof (*channel));
	channel = kmem_zalloc(size, KM_SLEEP);
	status = vds_do_get_ldc_id(md, vd_node, channel, ldc_id);
	kmem_free(channel, size);

	return (status);
}

/*
 * Function:
 *	vds_get_options
 *
 * Description:
 *	Parse the options of a vds node. Options are defined as an array
 *	of strings in the vds-block-device-opts property of the vds node
 *	in the machine description. Options are returned as a bitmask. The
 *	mapping between the bitmask options and the options strings from the
 *	machine description is defined in the vd_bdev_options[] array.
 *
 *	The vds-block-device-opts property is optional. If a vds has no such
 *	property then no option is defined.
 *
 * Parameters:
 *	md		- machine description.
 *	vd_node		- vds node in the machine description for which
 *			  options have to be parsed.
 *	options		- the returned options.
 *
 * Return Code:
 *	none.
 */
static void
vds_get_options(md_t *md, mde_cookie_t vd_node, uint64_t *options)
{
	char	*optstr, *opt;
	int	len, n, i;

	*options = 0;

	if (md_get_prop_data(md, vd_node, VD_BLOCK_DEVICE_OPTS,
	    (uint8_t **)&optstr, &len) != 0) {
		PR0("No options found");
		return;
	}

	/* parse options */
	opt = optstr;
	n = sizeof (vd_bdev_options) / sizeof (vd_option_t);

	while (opt < optstr + len) {
		for (i = 0; i < n; i++) {
			if (strncmp(vd_bdev_options[i].vdo_name,
			    opt, VD_OPTION_NLEN) == 0) {
				*options |= vd_bdev_options[i].vdo_value;
				break;
			}
		}

		if (i < n) {
			PR0("option: %s", opt);
		} else {
			PRN("option %s is unknown or unsupported", opt);
		}

		opt += strlen(opt) + 1;
	}
}

static void
vds_driver_types_free(vds_t *vds)
{
	if (vds->driver_types != NULL) {
		kmem_free(vds->driver_types, sizeof (vd_driver_type_t) *
		    vds->num_drivers);
		vds->driver_types = NULL;
		vds->num_drivers = 0;
	}
}

/*
 * Update the driver type list with information from vds.conf.
 */
static void
vds_driver_types_update(vds_t *vds)
{
	char **list, *s;
	uint_t i, num, count = 0, len;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, vds->dip,
	    DDI_PROP_DONTPASS, "driver-type-list", &list, &num) !=
	    DDI_PROP_SUCCESS)
		return;

	/*
	 * We create a driver_types list with as many as entries as there
	 * is in the driver-type-list from vds.conf. However only valid
	 * entries will be populated (i.e. entries from driver-type-list
	 * with a valid syntax). Invalid entries will be left blank so
	 * they will have no driver name and the driver type will be
	 * VD_DRIVER_UNKNOWN (= 0).
	 */
	vds->num_drivers = num;
	vds->driver_types = kmem_zalloc(sizeof (vd_driver_type_t) * num,
	    KM_SLEEP);

	for (i = 0; i < num; i++) {

		s = strchr(list[i], ':');

		if (s == NULL) {
			PRN("vds.conf: driver-type-list, entry %d (%s): "
			    "a colon is expected in the entry",
			    i, list[i]);
			continue;
		}

		len = (uintptr_t)s - (uintptr_t)list[i];

		if (len == 0) {
			PRN("vds.conf: driver-type-list, entry %d (%s): "
			    "the driver name is empty",
			    i, list[i]);
			continue;
		}

		if (len >= VD_DRIVER_NAME_LEN) {
			PRN("vds.conf: driver-type-list, entry %d (%s): "
			    "the driver name is too long",
			    i, list[i]);
			continue;
		}

		if (strcmp(s + 1, "disk") == 0) {

			vds->driver_types[i].type = VD_DRIVER_DISK;

		} else if (strcmp(s + 1, "volume") == 0) {

			vds->driver_types[i].type = VD_DRIVER_VOLUME;

		} else {
			PRN("vds.conf: driver-type-list, entry %d (%s): "
			    "the driver type is invalid",
			    i, list[i]);
			continue;
		}

		(void) strncpy(vds->driver_types[i].name, list[i], len);

		PR0("driver-type-list, entry %d (%s) added",
		    i, list[i]);

		count++;
	}

	ddi_prop_free(list);

	if (count == 0) {
		/* nothing was added, clean up */
		vds_driver_types_free(vds);
	}
}

static void
vds_add_vd(vds_t *vds, md_t *md, mde_cookie_t vd_node)
{
	char		*device_path = NULL;
	uint64_t	id = 0, ldc_id = 0, options = 0;

	if (md_get_prop_val(md, vd_node, VD_ID_PROP, &id) != 0) {
		PRN("Error getting vdisk \"%s\"", VD_ID_PROP);
		return;
	}
	PR0("Adding vdisk ID %lu", id);
	if (md_get_prop_str(md, vd_node, VD_BLOCK_DEVICE_PROP,
	    &device_path) != 0) {
		PRN("Error getting vdisk \"%s\"", VD_BLOCK_DEVICE_PROP);
		return;
	}

	vds_get_options(md, vd_node, &options);

	if (vds_get_ldc_id(md, vd_node, &ldc_id) != 0) {
		PRN("Error getting LDC ID for vdisk %lu", id);
		return;
	}

	if (vds_init_vd(vds, id, device_path, options, ldc_id) != 0) {
		PRN("Failed to add vdisk ID %lu", id);
		if (mod_hash_destroy(vds->vd_table, (mod_hash_key_t)id) != 0)
			PRN("No vDisk entry found for vdisk ID %lu", id);
		return;
	}
}

static void
vds_remove_vd(vds_t *vds, md_t *md, mde_cookie_t vd_node)
{
	uint64_t	id = 0;


	if (md_get_prop_val(md, vd_node, VD_ID_PROP, &id) != 0) {
		PRN("Unable to get \"%s\" property from vdisk's MD node",
		    VD_ID_PROP);
		return;
	}
	PR0("Removing vdisk ID %lu", id);
	if (mod_hash_destroy(vds->vd_table, (mod_hash_key_t)id) != 0)
		PRN("No vdisk entry found for vdisk ID %lu", id);
}

static void
vds_change_vd(vds_t *vds, md_t *prev_md, mde_cookie_t prev_vd_node,
    md_t *curr_md, mde_cookie_t curr_vd_node)
{
	char		*curr_dev, *prev_dev;
	uint64_t	curr_id = 0, curr_ldc_id = 0, curr_options = 0;
	uint64_t	prev_id = 0, prev_ldc_id = 0, prev_options = 0;
	size_t		len;


	/* Validate that vdisk ID has not changed */
	if (md_get_prop_val(prev_md, prev_vd_node, VD_ID_PROP, &prev_id) != 0) {
		PRN("Error getting previous vdisk \"%s\" property",
		    VD_ID_PROP);
		return;
	}
	if (md_get_prop_val(curr_md, curr_vd_node, VD_ID_PROP, &curr_id) != 0) {
		PRN("Error getting current vdisk \"%s\" property", VD_ID_PROP);
		return;
	}
	if (curr_id != prev_id) {
		PRN("Not changing vdisk:  ID changed from %lu to %lu",
		    prev_id, curr_id);
		return;
	}

	/* Validate that LDC ID has not changed */
	if (vds_get_ldc_id(prev_md, prev_vd_node, &prev_ldc_id) != 0) {
		PRN("Error getting LDC ID for vdisk %lu", prev_id);
		return;
	}

	if (vds_get_ldc_id(curr_md, curr_vd_node, &curr_ldc_id) != 0) {
		PRN("Error getting LDC ID for vdisk %lu", curr_id);
		return;
	}
	if (curr_ldc_id != prev_ldc_id) {
		_NOTE(NOTREACHED);	/* lint is confused */
		PRN("Not changing vdisk:  "
		    "LDC ID changed from %lu to %lu", prev_ldc_id, curr_ldc_id);
		return;
	}

	/* Determine whether device path has changed */
	if (md_get_prop_str(prev_md, prev_vd_node, VD_BLOCK_DEVICE_PROP,
	    &prev_dev) != 0) {
		PRN("Error getting previous vdisk \"%s\"",
		    VD_BLOCK_DEVICE_PROP);
		return;
	}
	if (md_get_prop_str(curr_md, curr_vd_node, VD_BLOCK_DEVICE_PROP,
	    &curr_dev) != 0) {
		PRN("Error getting current vdisk \"%s\"", VD_BLOCK_DEVICE_PROP);
		return;
	}
	if (((len = strlen(curr_dev)) == strlen(prev_dev)) &&
	    (strncmp(curr_dev, prev_dev, len) == 0))
		return;	/* no relevant (supported) change */

	/* Validate that options have not changed */
	vds_get_options(prev_md, prev_vd_node, &prev_options);
	vds_get_options(curr_md, curr_vd_node, &curr_options);
	if (prev_options != curr_options) {
		PRN("Not changing vdisk:  options changed from %lx to %lx",
		    prev_options, curr_options);
		return;
	}

	PR0("Changing vdisk ID %lu", prev_id);

	/* Remove old state, which will close vdisk and reset */
	if (mod_hash_destroy(vds->vd_table, (mod_hash_key_t)prev_id) != 0)
		PRN("No entry found for vdisk ID %lu", prev_id);

	/* Re-initialize vdisk with new state */
	if (vds_init_vd(vds, curr_id, curr_dev, curr_options,
	    curr_ldc_id) != 0) {
		PRN("Failed to change vdisk ID %lu", curr_id);
		return;
	}
}

static int
vds_process_md(void *arg, mdeg_result_t *md)
{
	int	i;
	vds_t	*vds = arg;


	if (md == NULL)
		return (MDEG_FAILURE);
	ASSERT(vds != NULL);

	for (i = 0; i < md->removed.nelem; i++)
		vds_remove_vd(vds, md->removed.mdp, md->removed.mdep[i]);
	for (i = 0; i < md->match_curr.nelem; i++)
		vds_change_vd(vds, md->match_prev.mdp, md->match_prev.mdep[i],
		    md->match_curr.mdp, md->match_curr.mdep[i]);
	for (i = 0; i < md->added.nelem; i++)
		vds_add_vd(vds, md->added.mdp, md->added.mdep[i]);

	return (MDEG_SUCCESS);
}


static int
vds_do_attach(dev_info_t *dip)
{
	int			status, sz;
	int			cfg_handle;
	minor_t			instance = ddi_get_instance(dip);
	vds_t			*vds;
	mdeg_prop_spec_t	*pspecp;
	mdeg_node_spec_t	*ispecp;

	/*
	 * The "cfg-handle" property of a vds node in an MD contains the MD's
	 * notion of "instance", or unique identifier, for that node; OBP
	 * stores the value of the "cfg-handle" MD property as the value of
	 * the "reg" property on the node in the device tree it builds from
	 * the MD and passes to Solaris.  Thus, we look up the devinfo node's
	 * "reg" property value to uniquely identify this device instance when
	 * registering with the MD event-generation framework.  If the "reg"
	 * property cannot be found, the device tree state is presumably so
	 * broken that there is no point in continuing.
	 */
	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    VD_REG_PROP)) {
		PRN("vds \"%s\" property does not exist", VD_REG_PROP);
		return (DDI_FAILURE);
	}

	/* Get the MD instance for later MDEG registration */
	cfg_handle = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    VD_REG_PROP, -1);

	if (ddi_soft_state_zalloc(vds_state, instance) != DDI_SUCCESS) {
		PRN("Could not allocate state for instance %u", instance);
		return (DDI_FAILURE);
	}

	if ((vds = ddi_get_soft_state(vds_state, instance)) == NULL) {
		PRN("Could not get state for instance %u", instance);
		ddi_soft_state_free(vds_state, instance);
		return (DDI_FAILURE);
	}

	vds->dip	= dip;
	vds->vd_table	= mod_hash_create_ptrhash("vds_vd_table", VDS_NCHAINS,
	    vds_destroy_vd, sizeof (void *));

	ASSERT(vds->vd_table != NULL);

	if ((status = ldi_ident_from_dip(dip, &vds->ldi_ident)) != 0) {
		PRN("ldi_ident_from_dip() returned errno %d", status);
		return (DDI_FAILURE);
	}
	vds->initialized |= VDS_LDI;

	/* Register for MD updates */
	sz = sizeof (vds_prop_template);
	pspecp = kmem_alloc(sz, KM_SLEEP);
	bcopy(vds_prop_template, pspecp, sz);

	VDS_SET_MDEG_PROP_INST(pspecp, cfg_handle);

	/* initialize the complete prop spec structure */
	ispecp = kmem_zalloc(sizeof (mdeg_node_spec_t), KM_SLEEP);
	ispecp->namep = "virtual-device";
	ispecp->specp = pspecp;

	if (mdeg_register(ispecp, &vd_match, vds_process_md, vds,
	    &vds->mdeg) != MDEG_SUCCESS) {
		PRN("Unable to register for MD updates");
		kmem_free(ispecp, sizeof (mdeg_node_spec_t));
		kmem_free(pspecp, sz);
		return (DDI_FAILURE);
	}

	vds->ispecp = ispecp;
	vds->initialized |= VDS_MDEG;

	/* Prevent auto-detaching so driver is available whenever MD changes */
	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip, DDI_NO_AUTODETACH, 1) !=
	    DDI_PROP_SUCCESS) {
		PRN("failed to set \"%s\" property for instance %u",
		    DDI_NO_AUTODETACH, instance);
	}

	/* read any user defined driver types from conf file and update list */
	vds_driver_types_update(vds);

	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
vds_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	status;

	switch (cmd) {
	case DDI_ATTACH:
		PR0("Attaching");
		if ((status = vds_do_attach(dip)) != DDI_SUCCESS)
			(void) vds_detach(dip, DDI_DETACH);
		return (status);
	case DDI_RESUME:
		PR0("No action required for DDI_RESUME");
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static struct dev_ops vds_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	ddi_no_info,	/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	vds_attach,	/* devo_attach */
	vds_detach,	/* devo_detach */
	nodev,		/* devo_reset */
	NULL,		/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	nulldev,	/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"virtual disk server",
	&vds_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};


int
_init(void)
{
	int		status;

	if ((status = ddi_soft_state_init(&vds_state, sizeof (vds_t), 1)) != 0)
		return (status);

	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&vds_state);
		return (status);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	status;

	if ((status = mod_remove(&modlinkage)) != 0)
		return (status);
	ddi_soft_state_fini(&vds_state);
	return (0);
}
