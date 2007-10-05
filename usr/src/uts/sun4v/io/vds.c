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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Virtual disk server
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/crc32.h>
#include <sys/ddi.h>
#include <sys/dkio.h>
#include <sys/file.h>
#include <sys/mdeg.h>
#include <sys/modhash.h>
#include <sys/note.h>
#include <sys/pathname.h>
#include <sys/sdt.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sysmacros.h>
#include <sys/vio_common.h>
#include <sys/vdsk_mailbox.h>
#include <sys/vdsk_common.h>
#include <sys/vtoc.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/scsi/impl/uscsi.h>
#include <vm/seg_map.h>

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

/* Flags for writing to a vdisk which is a file */
#define	VD_FILE_WRITE_FLAGS	SM_ASYNC

/* Number of backup labels */
#define	VD_FILE_NUM_BACKUP	5

/* Timeout for SCSI I/O */
#define	VD_SCSI_RDWR_TIMEOUT	30	/* 30 secs */

/*
 * By Solaris convention, slice/partition 2 represents the entire disk;
 * unfortunately, this convention does not appear to be codified.
 */
#define	VD_ENTIRE_DISK_SLICE	2

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
	    (((vd)->xfer_mode == VIO_DRING_MODE) ? "dring client" :	\
		(((vd)->xfer_mode == 0) ? "null client" :		\
		    "unsupported client")))

/* Read disk label from a disk on file */
#define	VD_FILE_LABEL_READ(vd, labelp) \
	vd_file_rw(vd, VD_SLICE_NONE, VD_OP_BREAD, (caddr_t)labelp, \
	    0, sizeof (struct dk_label))

/* Write disk label to a disk on file */
#define	VD_FILE_LABEL_WRITE(vd, labelp)	\
	vd_file_rw(vd, VD_SLICE_NONE, VD_OP_BWRITE, (caddr_t)labelp, \
	    0, sizeof (struct dk_label))

/*
 * Specification of an MD node passed to the MDEG to filter any
 * 'vport' nodes that do not belong to the specified node. This
 * template is copied for each vds instance and filled in with
 * the appropriate 'cfg-handle' value before being passed to the MDEG.
 */
static mdeg_prop_spec_t	vds_prop_template[] = {
	{ MDET_PROP_STR,	"name",		VDS_NAME },
	{ MDET_PROP_VAL,	"cfg-handle",	NULL },
	{ MDET_LIST_END,	NULL, 		NULL }
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
	{ "slice", 	VD_OPT_SLICE },
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
} vd_task_t;

/*
 * Soft state structure for a virtual disk instance
 */
typedef struct vd {
	uint_t			initialized;	/* vdisk initialization flags */
	vds_t			*vds;		/* server for this vdisk */
	ddi_taskq_t		*startq;	/* queue for I/O start tasks */
	ddi_taskq_t		*completionq;	/* queue for completion tasks */
	ldi_handle_t		ldi_handle[V_NUMPAR];	/* LDI slice handles */
	char			device_path[MAXPATHLEN + 1]; /* vdisk device */
	dev_t			dev[V_NUMPAR];	/* dev numbers for slices */
	int			open_flags;	/* open flags */
	uint_t			nslices;	/* number of slices */
	size_t			vdisk_size;	/* number of blocks in vdisk */
	vd_disk_type_t		vdisk_type;	/* slice or entire disk */
	vd_disk_label_t		vdisk_label;	/* EFI or VTOC label */
	ushort_t		max_xfer_sz;	/* max xfer size in DEV_BSIZE */
	boolean_t		pseudo;		/* underlying pseudo dev */
	boolean_t		file;		/* underlying file */
	vnode_t			*file_vnode;	/* file vnode */
	size_t			file_size;	/* file size */
	ddi_devid_t		file_devid;	/* devid for disk image */
	struct dk_efi		dk_efi;		/* synthetic for slice type */
	struct dk_geom		dk_geom;	/* synthetic for slice type */
	struct vtoc		vtoc;		/* synthetic for slice type */
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
	caddr_t			dring;		/* address of dring */
	caddr_t			vio_msgp;	/* vio msg staging buffer */
	vd_task_t		inband_task;	/* task for inband descriptor */
	vd_task_t		*dring_task;	/* tasks dring elements */

	kmutex_t		lock;		/* protects variables below */
	boolean_t		enabled;	/* is vdisk enabled? */
	boolean_t		reset_state;	/* reset connection state? */
	boolean_t		reset_ldc;	/* reset LDC channel? */
} vd_t;

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
	void		(*copyin)(void *vd_buf, void *ioctl_arg);
	/* convert input ioctl_arg to output vd_buf */
	void		(*copyout)(void *ioctl_arg, void *vd_buf);
	/* write is true if the operation writes any data to the backend */
	boolean_t	write;
} vd_ioctl_t;

/* Define trivial copyin/copyout conversion function flag */
#define	VD_IDENTITY	((void (*)(void *, void *))-1)


static int	vds_ldc_retries = VDS_RETRIES;
static int	vds_ldc_delay = VDS_LDC_DELAY;
static int	vds_dev_retries = VDS_RETRIES;
static int	vds_dev_delay = VDS_DEV_DELAY;
static void	*vds_state;
static uint64_t	vds_operations;	/* see vds_operation[] definition below */

static uint_t	vd_file_write_flags = VD_FILE_WRITE_FLAGS;

static short	vd_scsi_rdwr_timeout = VD_SCSI_RDWR_TIMEOUT;

/*
 * Supported protocol version pairs, from highest (newest) to lowest (oldest)
 *
 * Each supported major version should appear only once, paired with (and only
 * with) its highest supported minor version number (as the protocol requires
 * supporting all lower minor version numbers as well)
 */
static const vio_ver_t	vds_version[] = {{1, 0}};
static const size_t	vds_num_versions =
    sizeof (vds_version)/sizeof (vds_version[0]);

static void vd_free_dring_task(vd_t *vdp);
static int vd_setup_vd(vd_t *vd);
static int vd_setup_single_slice_disk(vd_t *vd);
static boolean_t vd_enabled(vd_t *vd);
static ushort_t vd_lbl2cksum(struct dk_label *label);
static int vd_file_validate_geometry(vd_t *vd);

/*
 * Function:
 *	vd_file_rw
 *
 * Description:
 * 	Read or write to a disk on file.
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
vd_file_rw(vd_t *vd, int slice, int operation, caddr_t data, size_t blk,
    size_t len)
{
	caddr_t	maddr;
	size_t offset, maxlen, moffset, mlen, n;
	uint_t smflags;
	enum seg_rw srw;

	ASSERT(vd->file);
	ASSERT(len > 0);

	/*
	 * If a file is exported as a slice then we don't care about the vtoc.
	 * In that case, the vtoc is a fake mainly to make newfs happy and we
	 * handle any I/O as a raw disk access so that we can have access to the
	 * entire backend.
	 */
	if (vd->vdisk_type == VD_DISK_TYPE_SLICE || slice == VD_SLICE_NONE) {
		/* raw disk access */
		offset = blk * DEV_BSIZE;
	} else {
		ASSERT(slice >= 0 && slice < V_NUMPAR);

		if (vd->vdisk_label == VD_DISK_LABEL_UNK &&
		    vd_file_validate_geometry(vd) != 0) {
			PR0("Unknown disk label, can't do I/O from slice %d",
			    slice);
			return (-1);
		}

		if (blk >= vd->vtoc.v_part[slice].p_size) {
			/* address past the end of the slice */
			PR0("req_addr (0x%lx) > psize (0x%lx)",
			    blk, vd->vtoc.v_part[slice].p_size);
			return (0);
		}

		offset = (vd->vtoc.v_part[slice].p_start + blk) * DEV_BSIZE;

		/*
		 * If the requested size is greater than the size
		 * of the partition, truncate the read/write.
		 */
		maxlen = (vd->vtoc.v_part[slice].p_size - blk) * DEV_BSIZE;

		if (len > maxlen) {
			PR0("I/O size truncated to %lu bytes from %lu bytes",
			    maxlen, len);
			len = maxlen;
		}
	}

	/*
	 * We have to ensure that we are reading/writing into the mmap
	 * range. If we have a partial disk image (e.g. an image of
	 * s0 instead s2) the system can try to access slices that
	 * are not included into the disk image.
	 */
	if ((offset + len) >= vd->file_size) {
		PR0("offset + nbytes (0x%lx + 0x%lx) >= "
		    "file_size (0x%lx)", offset, len, vd->file_size);
		return (-1);
	}

	srw = (operation == VD_OP_BREAD)? S_READ : S_WRITE;
	smflags = (operation == VD_OP_BREAD)? 0 :
	    (SM_WRITE | vd_file_write_flags);
	n = len;

	do {
		/*
		 * segmap_getmapflt() returns a MAXBSIZE chunk which is
		 * MAXBSIZE aligned.
		 */
		moffset = offset & MAXBOFFSET;
		mlen = MIN(MAXBSIZE - moffset, n);
		maddr = segmap_getmapflt(segkmap, vd->file_vnode, offset,
		    mlen, 1, srw);
		/*
		 * Fault in the pages so we can check for error and ensure
		 * that we can safely used the mapped address.
		 */
		if (segmap_fault(kas.a_hat, segkmap, maddr, mlen,
		    F_SOFTLOCK, srw) != 0) {
			(void) segmap_release(segkmap, maddr, 0);
			return (-1);
		}

		if (operation == VD_OP_BREAD)
			bcopy(maddr + moffset, data, mlen);
		else
			bcopy(data, maddr + moffset, mlen);

		if (segmap_fault(kas.a_hat, segkmap, maddr, mlen,
		    F_SOFTUNLOCK, srw) != 0) {
			(void) segmap_release(segkmap, maddr, 0);
			return (-1);
		}
		if (segmap_release(segkmap, maddr, smflags) != 0)
			return (-1);
		n -= mlen;
		offset += mlen;
		data += mlen;

	} while (n > 0);

	return (len);
}

/*
 * Function:
 *	vd_file_build_default_label
 *
 * Description:
 *	Return a default label for the given disk. This is used when the disk
 *	does not have a valid VTOC so that the user can get a valid default
 *	configuration. The default label have all slices size set to 0 (except
 *	slice 2 which is the entire disk) to force the user to write a valid
 *	label onto the disk image.
 *
 * Parameters:
 *	vd		- disk on which the operation is performed.
 *	label		- the returned default label.
 *
 * Return Code:
 *	none.
 */
static void
vd_file_build_default_label(vd_t *vd, struct dk_label *label)
{
	size_t size;
	char prefix;
	int slice, nparts;
	uint16_t tag;

	ASSERT(vd->file);

	/*
	 * We must have a resonable number of cylinders and sectors so
	 * that newfs can run using default values.
	 *
	 * if (disk_size < 2MB)
	 * 	phys_cylinders = disk_size / 100K
	 * else
	 * 	phys_cylinders = disk_size / 300K
	 *
	 * phys_cylinders = (phys_cylinders == 0) ? 1 : phys_cylinders
	 * alt_cylinders = (phys_cylinders > 2) ? 2 : 0;
	 * data_cylinders = phys_cylinders - alt_cylinders
	 *
	 * sectors = disk_size / (phys_cylinders * blk_size)
	 *
	 * The file size test is an attempt to not have too few cylinders
	 * for a small file, or so many on a big file that you waste space
	 * for backup superblocks or cylinder group structures.
	 */
	if (vd->file_size < (2 * 1024 * 1024))
		label->dkl_pcyl = vd->file_size / (100 * 1024);
	else
		label->dkl_pcyl = vd->file_size / (300 * 1024);

	if (label->dkl_pcyl == 0)
		label->dkl_pcyl = 1;

	label->dkl_acyl = 0;

	if (vd->vdisk_type == VD_DISK_TYPE_SLICE) {
		nparts = 1;
		slice = 0;
		tag = V_UNASSIGNED;
	} else {
		if (label->dkl_pcyl > 2)
			label->dkl_acyl = 2;
		nparts = V_NUMPAR;
		slice = VD_ENTIRE_DISK_SLICE;
		tag = V_BACKUP;
	}

	label->dkl_nsect = vd->file_size /
	    (DEV_BSIZE * label->dkl_pcyl);
	label->dkl_ncyl = label->dkl_pcyl - label->dkl_acyl;
	label->dkl_nhead = 1;
	label->dkl_write_reinstruct = 0;
	label->dkl_read_reinstruct = 0;
	label->dkl_rpm = 7200;
	label->dkl_apc = 0;
	label->dkl_intrlv = 0;

	PR0("requested disk size: %ld bytes\n", vd->file_size);
	PR0("setup: ncyl=%d nhead=%d nsec=%d\n", label->dkl_pcyl,
	    label->dkl_nhead, label->dkl_nsect);
	PR0("provided disk size: %ld bytes\n", (uint64_t)
	    (label->dkl_pcyl * label->dkl_nhead *
	    label->dkl_nsect * DEV_BSIZE));

	if (vd->file_size < (1ULL << 20)) {
		size = vd->file_size >> 10;
		prefix = 'K'; /* Kilobyte */
	} else if (vd->file_size < (1ULL << 30)) {
		size = vd->file_size >> 20;
		prefix = 'M'; /* Megabyte */
	} else if (vd->file_size < (1ULL << 40)) {
		size = vd->file_size >> 30;
		prefix = 'G'; /* Gigabyte */
	} else {
		size = vd->file_size >> 40;
		prefix = 'T'; /* Terabyte */
	}

	/*
	 * We must have a correct label name otherwise format(1m) will
	 * not recognized the disk as labeled.
	 */
	(void) snprintf(label->dkl_asciilabel, LEN_DKL_ASCII,
	    "SUN-DiskImage-%ld%cB cyl %d alt %d hd %d sec %d",
	    size, prefix,
	    label->dkl_ncyl, label->dkl_acyl, label->dkl_nhead,
	    label->dkl_nsect);

	/* default VTOC */
	label->dkl_vtoc.v_version = V_VERSION;
	label->dkl_vtoc.v_nparts = nparts;
	label->dkl_vtoc.v_sanity = VTOC_SANE;
	label->dkl_vtoc.v_part[slice].p_tag = tag;
	label->dkl_map[slice].dkl_cylno = 0;
	label->dkl_map[slice].dkl_nblk = label->dkl_ncyl *
	    label->dkl_nhead * label->dkl_nsect;
	label->dkl_cksum = vd_lbl2cksum(label);
}

/*
 * Function:
 *	vd_file_set_vtoc
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
vd_file_set_vtoc(vd_t *vd, struct dk_label *label)
{
	int blk, sec, cyl, head, cnt;

	ASSERT(vd->file);

	if (VD_FILE_LABEL_WRITE(vd, label) < 0) {
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

	for (cnt = 0; cnt < VD_FILE_NUM_BACKUP; cnt++) {

		if (sec >= label->dkl_nsect) {
			PR0("not enough sector to store all backup labels");
			return (0);
		}

		if (vd_file_rw(vd, VD_SLICE_NONE, VD_OP_BWRITE, (caddr_t)label,
		    blk + sec, sizeof (struct dk_label)) < 0) {
			PR0("error writing backup label at block %d\n",
			    blk + sec);
			return (EIO);
		}

		PR1("wrote backup label at block %d\n", blk + sec);

		sec += 2;
	}

	return (0);
}

/*
 * Function:
 *	vd_file_get_devid_block
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
vd_file_get_devid_block(vd_t *vd, size_t *blkp)
{
	diskaddr_t spc, head, cyl;

	ASSERT(vd->file);
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
	ip = (uint_t *)dkdevid;
	for (i = 0; i < ((DEV_BSIZE - sizeof (int)) / sizeof (int)); i++)
		chksum ^= ip[i];

	return (chksum);
}

/*
 * Function:
 *	vd_file_read_devid
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
vd_file_read_devid(vd_t *vd, ddi_devid_t *devid)
{
	struct dk_devid *dkdevid;
	size_t blk;
	uint_t chksum;
	int status, sz;

	if ((status = vd_file_get_devid_block(vd, &blk)) != 0)
		return (status);

	dkdevid = kmem_zalloc(DEV_BSIZE, KM_SLEEP);

	/* get the devid */
	if ((vd_file_rw(vd, VD_SLICE_NONE, VD_OP_BREAD, (caddr_t)dkdevid, blk,
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
 *	vd_file_write_devid
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
vd_file_write_devid(vd_t *vd, ddi_devid_t devid)
{
	struct dk_devid *dkdevid;
	uint_t chksum;
	size_t blk;
	int status;

	if ((status = vd_file_get_devid_block(vd, &blk)) != 0)
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
	if ((status = vd_file_rw(vd, VD_SLICE_NONE, VD_OP_BWRITE,
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
 *	vd_scsi_rdwr
 *
 * Description:
 * 	Read or write to a SCSI disk using an absolute disk offset.
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
vd_scsi_rdwr(vd_t *vd, int operation, caddr_t data, size_t blk, size_t len)
{
	struct uscsi_cmd ucmd;
	union scsi_cdb cdb;
	int nsectors, nblk;
	int max_sectors;
	int status, rval;

	ASSERT(!vd->file);

	max_sectors = vd->max_xfer_sz;
	nblk = (len / DEV_BSIZE);

	if (len % DEV_BSIZE != 0)
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

		if (blk < (2 << 20) && nsectors <= 0xff) {
			FORMG0ADDR(&cdb, blk);
			FORMG0COUNT(&cdb, nsectors);
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
		ucmd.uscsi_buflen = nsectors * DEV_BSIZE;
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
		data += nsectors * DEV_BSIZE; /* SECSIZE */
	}

	return (status);
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
	int 			slice;
	char			*bufaddr = 0;
	size_t			buflen;

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

	mtype = (&vd->inband_task == task) ? LDC_SHADOW_MAP : LDC_DIRECT_MAP;

	/* Map memory exported by client */
	status = ldc_mem_map(task->mhdl, request->cookie, request->ncookies,
	    mtype, (request->operation == VD_OP_BREAD) ? LDC_MEM_W : LDC_MEM_R,
	    &bufaddr, NULL);
	if (status != 0) {
		PR0("ldc_mem_map() returned err %d ", status);
		return (EIO);
	}

	buflen = request->nbytes;

	status = ldc_mem_acquire(task->mhdl, 0, buflen);
	if (status != 0) {
		(void) ldc_mem_unmap(task->mhdl);
		PR0("ldc_mem_acquire() returned err %d ", status);
		return (EIO);
	}

	/* Start the block I/O */
	if (vd->file) {
		rv = vd_file_rw(vd, slice, request->operation, bufaddr,
		    request->addr, request->nbytes);
		if (rv < 0) {
			request->nbytes = 0;
			request->status = EIO;
		} else {
			request->nbytes = rv;
			request->status = 0;
		}
	} else {
		if (slice == VD_SLICE_NONE) {
			/*
			 * This is not a disk image so it is a real disk. We
			 * assume that the underlying device driver supports
			 * USCSICMD ioctls. This is the case of all SCSI devices
			 * (sd, ssd...).
			 *
			 * In the future if we have non-SCSI disks we would need
			 * to invoke the appropriate function to do I/O using an
			 * absolute disk offset (for example using DKIOCTL_RWCMD
			 * for IDE disks).
			 */
			rv = vd_scsi_rdwr(vd, request->operation, bufaddr,
			    request->addr, request->nbytes);
			if (rv != 0) {
				request->nbytes = 0;
				request->status = EIO;
			} else {
				request->status = 0;
			}
		} else {
			bioinit(buf);
			buf->b_flags	= B_BUSY;
			buf->b_bcount	= request->nbytes;
			buf->b_lblkno	= request->addr;
			buf->b_edev 	= vd->dev[slice];
			buf->b_un.b_addr = bufaddr;
			buf->b_flags 	|= (request->operation == VD_OP_BREAD)?
			    B_READ : B_WRITE;

			request->status =
			    ldi_strategy(vd->ldi_handle[slice], buf);

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
		}
	}

	/* Clean up after error */
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
	ddi_taskq_wait(vd->completionq);

	if (vd->file) {
		status = VOP_FSYNC(vd->file_vnode, FSYNC, kcred);
		if (status) {
			PR0("VOP_FSYNC returned errno %d", status);
		}
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
	vd_dring_entry_t	*elem = VD_DRING_ELEM(idx);

	if (vd->reset_state)
		return (0);

	/* Acquire the element */
	if (!vd->reset_state &&
	    (status = ldc_mem_dring_acquire(vd->dring_handle, idx, idx)) != 0) {
		if (status == ECONNRESET) {
			vd_mark_in_reset(vd);
			return (0);
		} else {
			PR0("ldc_mem_dring_acquire() returned errno %d",
			    status);
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
	if (!vd->reset_state &&
	    (status = ldc_mem_dring_release(vd->dring_handle, idx, idx)) != 0) {
		if (status == ECONNRESET) {
			vd_mark_in_reset(vd);
			return (0);
		} else {
			PR0("ldc_mem_dring_release() returned errno %d",
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


	ASSERT(vd != NULL);
	ASSERT(request != NULL);
	ASSERT(task->msg != NULL);
	ASSERT(task->msglen >= sizeof (*task->msg));
	ASSERT(!vd->file);
	ASSERT(request->slice != VD_SLICE_NONE);

	/* Wait for the I/O to complete [ call to ldi_strategy(9f) ] */
	request->status = biowait(buf);

	/* return back the number of bytes read/written */
	request->nbytes = buf->b_bcount - buf->b_resid;

	/* Release the buffer */
	if (!vd->reset_state)
		status = ldc_mem_release(task->mhdl, 0, buf->b_bcount);
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
 *	arg 	- opaque pointer to structure containing task to be completed
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

	if (task->vd->reset_state)
		return;

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
 *	task 		- structure containing the request sent from client
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
	if (!vd->reset_state && (vd->xfer_mode == VIO_DRING_MODE)) {
		status = vd_mark_elem_done(vd, task->index,
		    request->status, request->nbytes);
		if (status == ECONNRESET)
			vd_mark_in_reset(vd);
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

	vd_notify(task);
}

/*
 * Description:
 *	This is the basic completion function called to handle inband data
 *	requests and handshake messages. All it needs to do is trigger a
 *	message to the client that the request is completed.
 *
 * Parameters:
 *	arg 	- opaque pointer to structure containing task to be completed
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

static void
vd_geom2dk_geom(void *vd_buf, void *ioctl_arg)
{
	VD_GEOM2DK_GEOM((vd_geom_t *)vd_buf, (struct dk_geom *)ioctl_arg);
}

static void
vd_vtoc2vtoc(void *vd_buf, void *ioctl_arg)
{
	VD_VTOC2VTOC((vd_vtoc_t *)vd_buf, (struct vtoc *)ioctl_arg);
}

static void
dk_geom2vd_geom(void *ioctl_arg, void *vd_buf)
{
	DK_GEOM2VD_GEOM((struct dk_geom *)ioctl_arg, (vd_geom_t *)vd_buf);
}

static void
vtoc2vd_vtoc(void *ioctl_arg, void *vd_buf)
{
	VTOC2VD_VTOC((struct vtoc *)ioctl_arg, (vd_vtoc_t *)vd_buf);
}

static void
vd_get_efi_in(void *vd_buf, void *ioctl_arg)
{
	vd_efi_t *vd_efi = (vd_efi_t *)vd_buf;
	dk_efi_t *dk_efi = (dk_efi_t *)ioctl_arg;

	dk_efi->dki_lba = vd_efi->lba;
	dk_efi->dki_length = vd_efi->length;
	dk_efi->dki_data = kmem_zalloc(vd_efi->length, KM_SLEEP);
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

static void
vd_set_efi_in(void *vd_buf, void *ioctl_arg)
{
	vd_efi_t *vd_efi = (vd_efi_t *)vd_buf;
	dk_efi_t *dk_efi = (dk_efi_t *)ioctl_arg;

	dk_efi->dki_data = kmem_alloc(vd_efi->length, KM_SLEEP);
	VD_EFI2DK_EFI(vd_efi, dk_efi);
}

static void
vd_set_efi_out(void *ioctl_arg, void *vd_buf)
{
	vd_efi_t *vd_efi = (vd_efi_t *)vd_buf;
	dk_efi_t *dk_efi = (dk_efi_t *)ioctl_arg;

	kmem_free(dk_efi->dki_data, vd_efi->length);
}

static vd_disk_label_t
vd_read_vtoc(vd_t *vd, struct vtoc *vtoc)
{
	int status, rval;
	struct dk_gpt *efi;
	size_t efi_len;

	ASSERT(vd->ldi_handle[0] != NULL);

	status = ldi_ioctl(vd->ldi_handle[0], DKIOCGVTOC, (intptr_t)vtoc,
	    (vd->open_flags | FKIOCTL), kcred, &rval);

	if (status == 0) {
		return (VD_DISK_LABEL_VTOC);
	} else if (status != ENOTSUP) {
		PR0("ldi_ioctl(DKIOCGVTOC) returned error %d", status);
		return (VD_DISK_LABEL_UNK);
	}

	status = vds_efi_alloc_and_read(vd->ldi_handle[0], &efi, &efi_len);

	if (status) {
		PR0("vds_efi_alloc_and_read returned error %d", status);
		return (VD_DISK_LABEL_UNK);
	}

	vd_efi_to_vtoc(efi, vtoc);
	vd_efi_free(efi, efi_len);

	return (VD_DISK_LABEL_EFI);
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

	switch (vd->vdisk_label) {

	/* ioctls for a slice from a disk with a VTOC label */
	case VD_DISK_LABEL_VTOC:

		switch (cmd) {
		case DKIOCGGEOM:
			ASSERT(ioctl_arg != NULL);
			bcopy(&vd->dk_geom, ioctl_arg, sizeof (vd->dk_geom));
			return (0);
		case DKIOCGVTOC:
			ASSERT(ioctl_arg != NULL);
			bcopy(&vd->vtoc, ioctl_arg, sizeof (vd->vtoc));
			return (0);
		default:
			return (ENOTSUP);
		}

	/* ioctls for a slice from a disk with an EFI label */
	case VD_DISK_LABEL_EFI:

		switch (cmd) {
		case DKIOCGETEFI:
			ASSERT(ioctl_arg != NULL);
			dk_ioc = (dk_efi_t *)ioctl_arg;
			if (dk_ioc->dki_length < vd->dk_efi.dki_length)
				return (EINVAL);
			bcopy(vd->dk_efi.dki_data, dk_ioc->dki_data,
			    vd->dk_efi.dki_length);
			return (0);
		default:
			return (ENOTSUP);
		}

	default:
		/* Unknown disk label type */
		return (ENOTSUP);
	}
}

/*
 * Function:
 *	vd_file_validate_geometry
 *
 * Description:
 *	Read the label and validate the geometry of a disk image. The driver
 *	label, vtoc and geometry information are updated according to the
 *	label read from the disk image.
 *
 *	If no valid label is found, the label is set to unknown and the
 *	function returns EINVAL, but a default vtoc and geometry are provided
 *	to the driver.
 *
 * Parameters:
 *	vd	- disk on which the operation is performed.
 *
 * Return Code:
 *	0	- success.
 *	EIO	- error reading the label from the disk image.
 *	EINVAL	- unknown disk label.
 */
static int
vd_file_validate_geometry(vd_t *vd)
{
	struct dk_label label;
	struct dk_geom *geom = &vd->dk_geom;
	struct vtoc *vtoc = &vd->vtoc;
	int i;
	int status = 0;

	ASSERT(vd->file);

	if (vd->vdisk_type == VD_DISK_TYPE_SLICE) {
		/*
		 * For single slice disk we always fake the geometry, and we
		 * only need to do it once because the geometry will never
		 * change.
		 */
		if (vd->vdisk_label == VD_DISK_LABEL_VTOC)
			/* geometry was already validated */
			return (0);

		ASSERT(vd->vdisk_label == VD_DISK_LABEL_UNK);
		vd_file_build_default_label(vd, &label);
		vd->vdisk_label = VD_DISK_LABEL_VTOC;
	} else {
		if (VD_FILE_LABEL_READ(vd, &label) < 0)
			return (EIO);

		if (label.dkl_magic != DKL_MAGIC ||
		    label.dkl_cksum != vd_lbl2cksum(&label) ||
		    label.dkl_vtoc.v_sanity != VTOC_SANE ||
		    label.dkl_vtoc.v_nparts != V_NUMPAR) {
			vd->vdisk_label = VD_DISK_LABEL_UNK;
			vd_file_build_default_label(vd, &label);
			status = EINVAL;
		} else {
			vd->vdisk_label = VD_DISK_LABEL_VTOC;
		}
	}

	/* Update the driver geometry */
	bzero(geom, sizeof (struct dk_geom));

	geom->dkg_ncyl = label.dkl_ncyl;
	geom->dkg_acyl = label.dkl_acyl;
	geom->dkg_nhead = label.dkl_nhead;
	geom->dkg_nsect = label.dkl_nsect;
	geom->dkg_intrlv = label.dkl_intrlv;
	geom->dkg_apc = label.dkl_apc;
	geom->dkg_rpm = label.dkl_rpm;
	geom->dkg_pcyl = label.dkl_pcyl;
	geom->dkg_write_reinstruct = label.dkl_write_reinstruct;
	geom->dkg_read_reinstruct = label.dkl_read_reinstruct;

	/* Update the driver vtoc */
	bzero(vtoc, sizeof (struct vtoc));

	vtoc->v_sanity = label.dkl_vtoc.v_sanity;
	vtoc->v_version = label.dkl_vtoc.v_version;
	vtoc->v_sectorsz = DEV_BSIZE;
	vtoc->v_nparts = label.dkl_vtoc.v_nparts;

	for (i = 0; i < vtoc->v_nparts; i++) {
		vtoc->v_part[i].p_tag =
		    label.dkl_vtoc.v_part[i].p_tag;
		vtoc->v_part[i].p_flag =
		    label.dkl_vtoc.v_part[i].p_flag;
		vtoc->v_part[i].p_start =
		    label.dkl_map[i].dkl_cylno *
		    (label.dkl_nhead * label.dkl_nsect);
		vtoc->v_part[i].p_size = label.dkl_map[i].dkl_nblk;
		vtoc->timestamp[i] =
		    label.dkl_vtoc.v_timestamp[i];
	}
	/*
	 * The bootinfo array can not be copied with bcopy() because
	 * elements are of type long in vtoc (so 64-bit) and of type
	 * int in dk_vtoc (so 32-bit).
	 */
	vtoc->v_bootinfo[0] = label.dkl_vtoc.v_bootinfo[0];
	vtoc->v_bootinfo[1] = label.dkl_vtoc.v_bootinfo[1];
	vtoc->v_bootinfo[2] = label.dkl_vtoc.v_bootinfo[2];
	bcopy(label.dkl_asciilabel, vtoc->v_asciilabel,
	    LEN_DKL_ASCII);
	bcopy(label.dkl_vtoc.v_volume, vtoc->v_volume,
	    LEN_DKL_VVOL);

	return (status);
}

/*
 * Handle ioctls to a disk image (file-based).
 *
 * Return Values
 *	0	- Indicates that there are no errors
 *	!= 0	- Disk operation returned an error
 */
static int
vd_do_file_ioctl(vd_t *vd, int cmd, void *ioctl_arg)
{
	struct dk_label label;
	struct dk_geom *geom;
	struct vtoc *vtoc;
	int i, rc;

	ASSERT(vd->file);

	switch (cmd) {

	case DKIOCGGEOM:
		ASSERT(ioctl_arg != NULL);
		geom = (struct dk_geom *)ioctl_arg;

		rc = vd_file_validate_geometry(vd);
		if (rc != 0 && rc != EINVAL) {
			ASSERT(vd->vdisk_type != VD_DISK_TYPE_SLICE);
			return (rc);
		}

		bcopy(&vd->dk_geom, geom, sizeof (struct dk_geom));
		return (0);

	case DKIOCGVTOC:
		ASSERT(ioctl_arg != NULL);
		vtoc = (struct vtoc *)ioctl_arg;

		rc = vd_file_validate_geometry(vd);
		if (rc != 0 && rc != EINVAL) {
			ASSERT(vd->vdisk_type != VD_DISK_TYPE_SLICE);
			return (rc);
		}

		bcopy(&vd->vtoc, vtoc, sizeof (struct vtoc));
		return (0);

	case DKIOCSGEOM:
		ASSERT(ioctl_arg != NULL);
		geom = (struct dk_geom *)ioctl_arg;

		/* geometry can only be changed for full disk */
		if (vd->vdisk_type != VD_DISK_TYPE_DISK)
			return (ENOTSUP);

		if (geom->dkg_nhead == 0 || geom->dkg_nsect == 0)
			return (EINVAL);

		/*
		 * The current device geometry is not updated, just the driver
		 * "notion" of it. The device geometry will be effectively
		 * updated when a label is written to the device during a next
		 * DKIOCSVTOC.
		 */
		bcopy(ioctl_arg, &vd->dk_geom, sizeof (vd->dk_geom));
		return (0);

	case DKIOCSVTOC:
		ASSERT(ioctl_arg != NULL);
		ASSERT(vd->dk_geom.dkg_nhead != 0 &&
		    vd->dk_geom.dkg_nsect != 0);
		vtoc = (struct vtoc *)ioctl_arg;

		/* vtoc can only be changed for full disk */
		if (vd->vdisk_type != VD_DISK_TYPE_DISK)
			return (ENOTSUP);

		if (vtoc->v_sanity != VTOC_SANE ||
		    vtoc->v_sectorsz != DEV_BSIZE ||
		    vtoc->v_nparts != V_NUMPAR)
			return (EINVAL);

		bzero(&label, sizeof (label));
		label.dkl_ncyl = vd->dk_geom.dkg_ncyl;
		label.dkl_acyl = vd->dk_geom.dkg_acyl;
		label.dkl_pcyl = vd->dk_geom.dkg_pcyl;
		label.dkl_nhead = vd->dk_geom.dkg_nhead;
		label.dkl_nsect = vd->dk_geom.dkg_nsect;
		label.dkl_intrlv = vd->dk_geom.dkg_intrlv;
		label.dkl_apc = vd->dk_geom.dkg_apc;
		label.dkl_rpm = vd->dk_geom.dkg_rpm;
		label.dkl_write_reinstruct = vd->dk_geom.dkg_write_reinstruct;
		label.dkl_read_reinstruct = vd->dk_geom.dkg_read_reinstruct;

		label.dkl_vtoc.v_nparts = V_NUMPAR;
		label.dkl_vtoc.v_sanity = VTOC_SANE;
		label.dkl_vtoc.v_version = vtoc->v_version;
		for (i = 0; i < V_NUMPAR; i++) {
			label.dkl_vtoc.v_timestamp[i] =
			    vtoc->timestamp[i];
			label.dkl_vtoc.v_part[i].p_tag =
			    vtoc->v_part[i].p_tag;
			label.dkl_vtoc.v_part[i].p_flag =
			    vtoc->v_part[i].p_flag;
			label.dkl_map[i].dkl_cylno =
			    vtoc->v_part[i].p_start /
			    (label.dkl_nhead * label.dkl_nsect);
			label.dkl_map[i].dkl_nblk =
			    vtoc->v_part[i].p_size;
		}
		/*
		 * The bootinfo array can not be copied with bcopy() because
		 * elements are of type long in vtoc (so 64-bit) and of type
		 * int in dk_vtoc (so 32-bit).
		 */
		label.dkl_vtoc.v_bootinfo[0] = vtoc->v_bootinfo[0];
		label.dkl_vtoc.v_bootinfo[1] = vtoc->v_bootinfo[1];
		label.dkl_vtoc.v_bootinfo[2] = vtoc->v_bootinfo[2];
		bcopy(vtoc->v_asciilabel, label.dkl_asciilabel,
		    LEN_DKL_ASCII);
		bcopy(vtoc->v_volume, label.dkl_vtoc.v_volume,
		    LEN_DKL_VVOL);

		/* re-compute checksum */
		label.dkl_magic = DKL_MAGIC;
		label.dkl_cksum = vd_lbl2cksum(&label);

		/* write label to the disk image */
		if ((rc = vd_file_set_vtoc(vd, &label)) != 0)
			return (rc);

		/* check the geometry and update the driver info */
		if ((rc = vd_file_validate_geometry(vd)) != 0)
			return (rc);

		/*
		 * The disk geometry may have changed, so we need to write
		 * the devid (if there is one) so that it is stored at the
		 * right location.
		 */
		if (vd->file_devid != NULL &&
		    vd_file_write_devid(vd, vd->file_devid) != 0) {
			PR0("Fail to write devid");
		}

		return (0);

	case DKIOCFLUSHWRITECACHE:
		return (VOP_FSYNC(vd->file_vnode, FSYNC, kcred));

	default:
		return (ENOTSUP);
	}
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
	int	rval = 0, status = 0;
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
		if (ioctl->copyin == VD_IDENTITY)	/* use client buffer */
			ioctl->arg = buf;
		else	/* convert client vdisk operation data to ioctl data */
			(ioctl->copyin)(buf, (void *)ioctl->arg);
	}

	/*
	 * Handle single-slice block devices internally; otherwise, have the
	 * real driver perform the ioctl()
	 */
	if (vd->file) {
		request->status =
		    vd_do_file_ioctl(vd, ioctl->cmd, (void *)ioctl->arg);

	} else if (vd->vdisk_type == VD_DISK_TYPE_SLICE && !vd->pseudo) {
		request->status =
		    vd_do_slice_ioctl(vd, ioctl->cmd, (void *)ioctl->arg);

	} else {
		request->status = ldi_ioctl(vd->ldi_handle[request->slice],
		    ioctl->cmd, (intptr_t)ioctl->arg, vd->open_flags | FKIOCTL,
		    kcred, &rval);

#ifdef DEBUG
		if (rval != 0) {
			PR0("%s set rval = %d, which is not being returned to"
			    " client", ioctl->cmd_name, rval);
		}
#endif /* DEBUG */
	}

	if (request->status != 0) {
		PR0("ioctl(%s) = errno %d", ioctl->cmd_name, request->status);
		return (0);
	}

	/* Convert data and send to client, if necessary */
	if (ioctl->copyout != NULL)  {
		ASSERT(nbytes != 0 && buf != NULL);
		PR1("Sending \"arg\" data to client");

		/* Convert ioctl data to vdisk operation data, if necessary */
		if (ioctl->copyout != VD_IDENTITY)
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
 *	arg 	- opaque pointer to structure containing task to be completed
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
	struct vtoc		vtoc = {0};
	struct dk_efi		dk_efi = {0};
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
		    NULL, VD_IDENTITY, VD_IDENTITY, B_FALSE},
		{VD_OP_GET_DISKGEOM, STRINGIZE(VD_OP_GET_DISKGEOM),
		    RNDSIZE(vd_geom_t),
		    DKIOCGGEOM, STRINGIZE(DKIOCGGEOM),
		    &dk_geom, NULL, dk_geom2vd_geom, B_FALSE},
		{VD_OP_GET_VTOC, STRINGIZE(VD_OP_GET_VTOC), RNDSIZE(vd_vtoc_t),
		    DKIOCGVTOC, STRINGIZE(DKIOCGVTOC),
		    &vtoc, NULL, vtoc2vd_vtoc, B_FALSE},
		{VD_OP_GET_EFI, STRINGIZE(VD_OP_GET_EFI), RNDSIZE(vd_efi_t),
		    DKIOCGETEFI, STRINGIZE(DKIOCGETEFI),
		    &dk_efi, vd_get_efi_in, vd_get_efi_out, B_FALSE},

		/* "Set" (copy-in) operations */
		{VD_OP_SET_WCE, STRINGIZE(VD_OP_SET_WCE), RNDSIZE(int),
		    DKIOCSETWCE, STRINGIZE(DKIOCSETWCE),
		    NULL, VD_IDENTITY, VD_IDENTITY, B_TRUE},
		{VD_OP_SET_DISKGEOM, STRINGIZE(VD_OP_SET_DISKGEOM),
		    RNDSIZE(vd_geom_t),
		    DKIOCSGEOM, STRINGIZE(DKIOCSGEOM),
		    &dk_geom, vd_geom2dk_geom, NULL, B_TRUE},
		{VD_OP_SET_VTOC, STRINGIZE(VD_OP_SET_VTOC), RNDSIZE(vd_vtoc_t),
		    DKIOCSVTOC, STRINGIZE(DKIOCSVTOC),
		    &vtoc, vd_vtoc2vtoc, NULL, B_TRUE},
		{VD_OP_SET_EFI, STRINGIZE(VD_OP_SET_EFI), RNDSIZE(vd_efi_t),
		    DKIOCSETEFI, STRINGIZE(DKIOCSETEFI),
		    &dk_efi, vd_set_efi_in, vd_set_efi_out, B_TRUE},
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
			    request->operation == VD_OP_SET_EFI) {
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
	ASSERT(i < nioctls);	/* because "operation" already validated */

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

	if (vd->file) {
		if (vd->file_devid == NULL) {
			PR2("No Device ID");
			request->status = ENOENT;
			return (0);
		} else {
			sz = ddi_devid_sizeof(vd->file_devid);
			devid = kmem_alloc(sz, KM_SLEEP);
			bcopy(vd->file_devid, devid, sz);
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
#undef	X
};

static const size_t	vds_noperations =
	(sizeof (vds_operation))/(sizeof (vds_operation[0]));

/*
 * Process a task specifying a client I/O request
 *
 * Parameters:
 *	task 		- structure containing the request sent from client
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
	if (i == vds_noperations) {
		PR0("Unsupported operation %u", request->operation);
		return (ENOTSUP);
	}

	/* Range-check slice */
	if (request->slice >= vd->nslices &&
	    (vd->vdisk_type != VD_DISK_TYPE_DISK ||
	    request->slice != VD_SLICE_NONE)) {
		PR0("Invalid \"slice\" %u (max %u) for virtual disk",
		    request->slice, (vd->nslices - 1));
		return (EINVAL);
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
 *	task 		- structure containing the request sent from client
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

	} else if (!vd->reset_state && (vd->xfer_mode == VIO_DRING_MODE)) {
		/* Update the dring element if it's a dring client */
		status = vd_mark_elem_done(vd, task->index,
		    task->request->status, task->request->nbytes);
		if (status == ECONNRESET)
			vd_mark_in_reset(vd);
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
	 * When multiple versions are supported, this function should store
	 * the negotiated major and minor version values in the "vd" data
	 * structure to govern further communication; in particular, note that
	 * the client might have specified a lower minor version for the
	 * agreed major version than specifed in the vds_version[] array.  The
	 * following assertions should help remind future maintainers to make
	 * the appropriate changes to support multiple versions.
	 */
	ASSERT(vds_num_versions == 1);
	ASSERT(ver_msg->ver_major == vds_version[0].major);
	ASSERT(ver_msg->ver_minor == vds_version[0].minor);

	PR0("Using major version %u, minor version %u",
	    ver_msg->ver_major, ver_msg->ver_minor);
	return (0);
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
	    (attr_msg->xfer_mode != VIO_DRING_MODE)) {
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
		PR0("vdisk_type = %s, pseudo = %s, file = %s, nslices = %u",
		    ((vd->vdisk_type == VD_DISK_TYPE_DISK) ? "disk" : "slice"),
		    (vd->pseudo ? "yes" : "no"),
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
		    attr_msg->vdisk_block_size*attr_msg->max_xfer_sz :
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
	attr_msg->vdisk_block_size	= DEV_BSIZE;
	attr_msg->max_xfer_sz		= vd->max_xfer_sz;

	attr_msg->vdisk_size = vd->vdisk_size;
	attr_msg->vdisk_type = vd->vdisk_type;
	attr_msg->operations = vds_operations;
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

	status = ldc_mem_dring_map(vd->ldc_handle, reg_msg->cookie,
	    reg_msg->ncookies, reg_msg->num_descriptors,
	    reg_msg->descriptor_size, LDC_DIRECT_MAP, &vd->dring_handle);
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
	PR1("descriptor size = %u, dring length = %u",
	    vd->descriptor_size, vd->dring_len);
	vd->initialized |= VD_DRING;
	vd->dring_ident = 1;	/* "There Can Be Only One" */
	vd->dring = dring_minfo.vaddr;
	vd->descriptor_size = reg_msg->descriptor_size;
	vd->dring_len = reg_msg->num_descriptors;
	reg_msg->dring_ident = vd->dring_ident;

	/*
	 * Allocate and initialize a "shadow" array of data structures for
	 * tasks to process I/O requests in dring elements
	 */
	vd->dring_task =
	    kmem_zalloc((sizeof (*vd->dring_task)) * vd->dring_len, KM_SLEEP);
	for (int i = 0; i < vd->dring_len; i++) {
		vd->dring_task[i].vd		= vd;
		vd->dring_task[i].index		= i;
		vd->dring_task[i].request	= &VD_DRING_ELEM(i)->payload;

		status = ldc_mem_alloc_handle(vd->ldc_handle,
		    &(vd->dring_task[i].mhdl));
		if (status) {
			PR0("ldc_mem_alloc_handle() returned err %d ", status);
			return (ENXIO);
		}

		vd->dring_task[i].msg = kmem_alloc(vd->max_msglen, KM_SLEEP);
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
	vd_dring_entry_t	*elem = VD_DRING_ELEM(idx);


	/* Accept the updated dring element */
	if ((status = ldc_mem_dring_acquire(vd->dring_handle, idx, idx)) != 0) {
		PR0("ldc_mem_dring_acquire() returned errno %d", status);
		return (status);
	}
	ready = (elem->hdr.dstate == VIO_DESC_READY);
	if (ready) {
		elem->hdr.dstate = VIO_DESC_ACCEPTED;
	} else {
		PR0("descriptor %u not ready", idx);
		VD_DUMP_DRING_ELEM(elem);
	}
	if ((status = ldc_mem_dring_release(vd->dring_handle, idx, idx)) != 0) {
		PR0("ldc_mem_dring_release() returned errno %d", status);
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
	if ((nelem > 1) && (status != EINPROGRESS) && inprogress)
		ddi_taskq_wait(vd->completionq);

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

		case VIO_DRING_MODE:	/* expect register-dring message */
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

		case VIO_DRING_MODE:	/* expect dring-data or unreg-dring */
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
			rv = vd_process_msg(vd, (vio_msg_t *)vd->vio_msgp,
			    msglen);
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
		vds->mdeg = NULL;
	}

	if (vds->initialized & VDS_LDI)
		(void) ldi_ident_release(vds->ldi_ident);
	mod_hash_destroy_hash(vds->vd_table);
	ddi_soft_state_free(vds_state, instance);
	return (DDI_SUCCESS);
}

static boolean_t
is_pseudo_device(dev_info_t *dip)
{
	dev_info_t	*parent, *root = ddi_root_node();


	for (parent = ddi_get_parent(dip); (parent != NULL) && (parent != root);
	    parent = ddi_get_parent(parent)) {
		if (strcmp(ddi_get_name(parent), DEVI_PSEUDO_NEXNAME) == 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

static int
vd_setup_full_disk(vd_t *vd)
{
	int		rval, status;
	major_t		major = getmajor(vd->dev[0]);
	minor_t		minor = getminor(vd->dev[0]) - VD_ENTIRE_DISK_SLICE;
	struct dk_minfo	dk_minfo;

	ASSERT(vd->vdisk_type == VD_DISK_TYPE_DISK);

	/*
	 * At this point, vdisk_size is set to the size of partition 2 but
	 * this does not represent the size of the disk because partition 2
	 * may not cover the entire disk and its size does not include reserved
	 * blocks. So we update vdisk_size to be the size of the entire disk.
	 */
	if ((status = ldi_ioctl(vd->ldi_handle[0], DKIOCGMEDIAINFO,
	    (intptr_t)&dk_minfo, (vd->open_flags | FKIOCTL),
	    kcred, &rval)) != 0) {
		PRN("ldi_ioctl(DKIOCGMEDIAINFO) returned errno %d",
		    status);
		return (status);
	}
	vd->vdisk_size = dk_minfo.dki_capacity;

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

static int
vd_setup_partition_vtoc(vd_t *vd)
{
	int rval, status;
	char *device_path = vd->device_path;

	status = ldi_ioctl(vd->ldi_handle[0], DKIOCGGEOM,
	    (intptr_t)&vd->dk_geom, (vd->open_flags | FKIOCTL), kcred, &rval);

	if (status != 0) {
		PRN("ldi_ioctl(DKIOCGEOM) returned errno %d for %s",
		    status, device_path);
		return (status);
	}

	/* Initialize dk_geom structure for single-slice device */
	if (vd->dk_geom.dkg_nsect == 0) {
		PRN("%s geometry claims 0 sectors per track", device_path);
		return (EIO);
	}
	if (vd->dk_geom.dkg_nhead == 0) {
		PRN("%s geometry claims 0 heads", device_path);
		return (EIO);
	}
	vd->dk_geom.dkg_ncyl = vd->vdisk_size / vd->dk_geom.dkg_nsect /
	    vd->dk_geom.dkg_nhead;
	vd->dk_geom.dkg_acyl = 0;
	vd->dk_geom.dkg_pcyl = vd->dk_geom.dkg_ncyl + vd->dk_geom.dkg_acyl;


	/* Initialize vtoc structure for single-slice device */
	bcopy(VD_VOLUME_NAME, vd->vtoc.v_volume,
	    MIN(sizeof (VD_VOLUME_NAME), sizeof (vd->vtoc.v_volume)));
	bzero(vd->vtoc.v_part, sizeof (vd->vtoc.v_part));
	vd->vtoc.v_nparts = 1;
	vd->vtoc.v_part[0].p_tag = V_UNASSIGNED;
	vd->vtoc.v_part[0].p_flag = 0;
	vd->vtoc.v_part[0].p_start = 0;
	vd->vtoc.v_part[0].p_size = vd->vdisk_size;
	bcopy(VD_ASCIILABEL, vd->vtoc.v_asciilabel,
	    MIN(sizeof (VD_ASCIILABEL), sizeof (vd->vtoc.v_asciilabel)));

	return (0);
}

static int
vd_setup_partition_efi(vd_t *vd)
{
	efi_gpt_t *gpt;
	efi_gpe_t *gpe;
	struct uuid uuid = EFI_RESERVED;
	uint32_t crc;
	int length;

	length = sizeof (efi_gpt_t) + sizeof (efi_gpe_t);

	gpt = kmem_zalloc(length, KM_SLEEP);
	gpe = (efi_gpe_t *)(gpt + 1);

	gpt->efi_gpt_Signature = LE_64(EFI_SIGNATURE);
	gpt->efi_gpt_Revision = LE_32(EFI_VERSION_CURRENT);
	gpt->efi_gpt_HeaderSize = LE_32(sizeof (efi_gpt_t));
	gpt->efi_gpt_FirstUsableLBA = LE_64(0ULL);
	gpt->efi_gpt_LastUsableLBA = LE_64(vd->vdisk_size - 1);
	gpt->efi_gpt_NumberOfPartitionEntries = LE_32(1);
	gpt->efi_gpt_SizeOfPartitionEntry = LE_32(sizeof (efi_gpe_t));

	UUID_LE_CONVERT(gpe->efi_gpe_PartitionTypeGUID, uuid);
	gpe->efi_gpe_StartingLBA = gpt->efi_gpt_FirstUsableLBA;
	gpe->efi_gpe_EndingLBA = gpt->efi_gpt_LastUsableLBA;

	CRC32(crc, gpe, sizeof (efi_gpe_t), -1U, crc32_table);
	gpt->efi_gpt_PartitionEntryArrayCRC32 = LE_32(~crc);

	CRC32(crc, gpt, sizeof (efi_gpt_t), -1U, crc32_table);
	gpt->efi_gpt_HeaderCRC32 = LE_32(~crc);

	vd->dk_efi.dki_lba = 0;
	vd->dk_efi.dki_length = length;
	vd->dk_efi.dki_data = gpt;

	return (0);
}

/*
 * Setup for a virtual disk whose backend is a file (exported as a single slice
 * or as a full disk) or a pseudo device (for example a ZFS, SVM or VxVM volume)
 * exported as a full disk. In these cases, the backend is accessed using the
 * vnode interface.
 */
static int
vd_setup_backend_vnode(vd_t *vd)
{
	int 		rval, status;
	vattr_t		vattr;
	dev_t		dev;
	char		*file_path = vd->device_path;
	char		dev_path[MAXPATHLEN + 1];
	ldi_handle_t	lhandle;
	struct dk_cinfo	dk_cinfo;

	if ((status = vn_open(file_path, UIO_SYSSPACE, vd->open_flags | FOFFMAX,
	    0, &vd->file_vnode, 0, 0)) != 0) {
		PRN("vn_open(%s) = errno %d", file_path, status);
		return (status);
	}

	/*
	 * We set vd->file now so that vds_destroy_vd will take care of
	 * closing the file and releasing the vnode in case of an error.
	 */
	vd->file = B_TRUE;

	vattr.va_mask = AT_SIZE;
	if ((status = VOP_GETATTR(vd->file_vnode, &vattr, 0, kcred)) != 0) {
		PRN("VOP_GETATTR(%s) = errno %d", file_path, status);
		return (EIO);
	}

	vd->file_size = vattr.va_size;
	/* size should be at least sizeof(dk_label) */
	if (vd->file_size < sizeof (struct dk_label)) {
		PRN("Size of file has to be at least %ld bytes",
		    sizeof (struct dk_label));
		return (EIO);
	}

	if (vd->file_vnode->v_flag & VNOMAP) {
		PRN("File %s cannot be mapped", file_path);
		return (EIO);
	}

	/*
	 * Find and validate the geometry of a disk image. For a single slice
	 * disk image, this will build a fake geometry and vtoc.
	 */
	status = vd_file_validate_geometry(vd);
	if (status != 0 && status != EINVAL) {
		PRN("Fail to read label from %s", file_path);
		return (EIO);
	}

	/* sector size = block size = DEV_BSIZE */
	vd->vdisk_size = vd->file_size / DEV_BSIZE;
	vd->max_xfer_sz = maxphys / DEV_BSIZE; /* default transfer size */

	/*
	 * Get max_xfer_sz from the device where the file is or from the device
	 * itself if we have a pseudo device.
	 */
	dev_path[0] = '\0';

	if (vd->pseudo) {
		status = ldi_open_by_name(file_path, FREAD, kcred, &lhandle,
		    vd->vds->ldi_ident);
	} else {
		dev = vd->file_vnode->v_vfsp->vfs_dev;
		if (ddi_dev_pathname(dev, S_IFBLK, dev_path) == DDI_SUCCESS) {
			PR0("underlying device = %s\n", dev_path);
		}

		status = ldi_open_by_dev(&dev, OTYP_BLK, FREAD, kcred, &lhandle,
		    vd->vds->ldi_ident);
	}

	if (status != 0) {
		PR0("ldi_open() returned errno %d for device %s",
		    status, (dev_path[0] == '\0')? file_path : dev_path);
	} else {
		if ((status = ldi_ioctl(lhandle, DKIOCINFO,
		    (intptr_t)&dk_cinfo, (vd->open_flags | FKIOCTL), kcred,
		    &rval)) != 0) {
			PR0("ldi_ioctl(DKIOCINFO) returned errno %d for %s",
			    status, dev_path);
		} else {
			/*
			 * Store the device's max transfer size for
			 * return to the client
			 */
			vd->max_xfer_sz = dk_cinfo.dki_maxtransfer;
		}

		PR0("close the device %s", dev_path);
		(void) ldi_close(lhandle, FREAD, kcred);
	}

	PR0("using file %s, dev %s, max_xfer = %u blks",
	    file_path, dev_path, vd->max_xfer_sz);

	/* Setup devid for the disk image */

	if (vd->vdisk_type == VD_DISK_TYPE_SLICE)
		return (0);

	if (vd->vdisk_label != VD_DISK_LABEL_UNK) {

		status = vd_file_read_devid(vd, &vd->file_devid);

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
			PR0("can not read devid for %s", file_path);
			vd->file_devid = NULL;
			return (0);
		}
	}

	/*
	 * No valid device id was found so we create one. Note that a failure
	 * to create a device id is not fatal and does not prevent the disk
	 * image from being attached.
	 */
	PR1("creating devid for %s", file_path);

	if (ddi_devid_init(vd->vds->dip, DEVID_FAB, NULL, 0,
	    &vd->file_devid) != DDI_SUCCESS) {
		PR0("fail to create devid for %s", file_path);
		vd->file_devid = NULL;
		return (0);
	}

	/*
	 * Write devid to the disk image. The devid is stored into the disk
	 * image if we have a valid label; otherwise the devid will be stored
	 * when the user writes a valid label.
	 */
	if (vd->vdisk_label != VD_DISK_LABEL_UNK) {
		if (vd_file_write_devid(vd, vd->file_devid) != 0) {
			PR0("fail to write devid for %s", file_path);
			ddi_devid_free(vd->file_devid);
			vd->file_devid = NULL;
		}
	}

	return (0);
}

/*
 * Setup for a virtual disk which backend is a device (a physical disk,
 * slice or pseudo device) that is directly exported either as a full disk
 * for a physical disk or as a slice for a pseudo device or a disk slice.
 * In these cases, the backend is accessed using the LDI interface.
 */
static int
vd_setup_backend_ldi(vd_t *vd)
{
	int		rval, status;
	struct dk_cinfo	dk_cinfo;
	char		*device_path = vd->device_path;

	/*
	 * Try to open the device. This can fail for example if we are opening
	 * an empty slice. So in case of a failure, we try the open again but
	 * this time with the FNDELAY flag.
	 */
	status = ldi_open_by_name(device_path, vd->open_flags, kcred,
	    &vd->ldi_handle[0], vd->vds->ldi_ident);

	if (status != 0)
		status = ldi_open_by_name(device_path, vd->open_flags | FNDELAY,
		    kcred, &vd->ldi_handle[0], vd->vds->ldi_ident);

	if (status != 0) {
		PR0("ldi_open_by_name(%s) = errno %d", device_path, status);
		vd->ldi_handle[0] = NULL;
		return (status);
	}

	vd->file = B_FALSE;

	/* Get device number of backing device */
	if ((status = ldi_get_dev(vd->ldi_handle[0], &vd->dev[0])) != 0) {
		PRN("ldi_get_dev() returned errno %d for %s",
		    status, device_path);
		return (status);
	}

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

	vd->vdisk_label = vd_read_vtoc(vd, &vd->vtoc);

	/* Store the device's max transfer size for return to the client */
	vd->max_xfer_sz = dk_cinfo.dki_maxtransfer;

	/*
	 * Export a full disk.
	 *
	 * When we use the LDI interface, we export a device as a full disk
	 * if we have an entire disk slice (slice 2) and if this slice is
	 * exported as a full disk and not as a single slice disk.
	 *
	 * Note that pseudo devices are exported as full disks using the vnode
	 * interface, not the LDI interface.
	 */
	if (dk_cinfo.dki_partition == VD_ENTIRE_DISK_SLICE &&
	    vd->vdisk_type == VD_DISK_TYPE_DISK) {
		ASSERT(!vd->pseudo);
		return (vd_setup_full_disk(vd));
	}

	/*
	 * Export a single slice disk.
	 *
	 * The exported device can be either a pseudo device or a disk slice. If
	 * it is a disk slice different from slice 2 then it is always exported
	 * as a single slice disk even if the "slice" option is not specified.
	 * If it is disk slice 2 or a pseudo device then it is exported as a
	 * single slice disk only if the "slice" option is specified.
	 */
	ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE ||
	    dk_cinfo.dki_partition == VD_ENTIRE_DISK_SLICE);
	return (vd_setup_single_slice_disk(vd));
}

static int
vd_setup_single_slice_disk(vd_t *vd)
{
	int status;
	char *device_path = vd->device_path;

	/* Get size of backing device */
	if (ldi_get_size(vd->ldi_handle[0], &vd->vdisk_size) != DDI_SUCCESS) {
		PRN("ldi_get_size() failed for %s", device_path);
		return (EIO);
	}
	vd->vdisk_size = lbtodb(vd->vdisk_size);	/* convert to blocks */

	if (vd->pseudo) {

		ASSERT(vd->vdisk_type == VD_DISK_TYPE_SLICE);

		/*
		 * Currently we only support exporting pseudo devices which
		 * provide a valid disk label.
		 */
		if (vd->vdisk_label == VD_DISK_LABEL_UNK) {
			PRN("%s is a pseudo device with an invalid disk "
			    "label\n", device_path);
			return (EINVAL);
		}
		return (0);	/* ...and we're done */
	}

	/* We can only export a slice if the disk has a valid label */
	if (vd->vdisk_label == VD_DISK_LABEL_UNK) {
		PRN("%s is a slice from a disk with an unknown disk label\n",
		    device_path);
		return (EINVAL);
	}

	/*
	 * We export the slice as a single slice disk even if the "slice"
	 * option was not specified.
	 */
	vd->vdisk_type	= VD_DISK_TYPE_SLICE;
	vd->nslices	= 1;

	if (vd->vdisk_label == VD_DISK_LABEL_EFI) {
		/* Slice from a disk with an EFI label */
		status = vd_setup_partition_efi(vd);
	} else {
		/* Slice from a disk with a VTOC label */
		ASSERT(vd->vdisk_label == VD_DISK_LABEL_VTOC);
		status = vd_setup_partition_vtoc(vd);
	}

	return (status);
}

static int
vd_setup_vd(vd_t *vd)
{
	int		status;
	dev_info_t	*dip;
	vnode_t 	*vnp;
	char		*path = vd->device_path;

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
		vd->pseudo = B_FALSE;
		status = vd_setup_backend_vnode(vd);
		break;

	case VBLK:
	case VCHR:
		/*
		 * Backend is a device. The way it is exported depends on the
		 * type of the device.
		 *
		 * - A pseudo device is exported as a full disk using the vnode
		 *   interface or as a single slice disk using the LDI
		 *   interface.
		 *
		 * - A disk (represented by the slice 2 of that disk) is
		 *   exported as a full disk using the LDI interface.
		 *
		 * - A disk slice (different from slice 2) is always exported
		 *   as a single slice disk using the LDI interface.
		 *
		 * - The slice 2 of a disk is exported as a single slice disk
		 *   if the "slice" option is specified, otherwise the entire
		 *   disk will be exported. In any case, the LDI interface is
		 *   used.
		 */

		/* check if this is a pseudo device */
		if ((dip = ddi_hold_devi_by_instance(getmajor(vnp->v_rdev),
		    dev_to_instance(vnp->v_rdev), 0))  == NULL) {
			PRN("%s is no longer accessible", path);
			VN_RELE(vnp);
			status = EIO;
			break;
		}
		vd->pseudo = is_pseudo_device(dip);
		ddi_release_devi(dip);
		VN_RELE(vnp);

		/*
		 * If this is a pseudo device then its usage depends if the
		 * "slice" option is set or not. If the "slice" option is set
		 * then the pseudo device will be exported as a single slice,
		 * otherwise it will be exported as a full disk.
		 */
		if (vd->pseudo && vd->vdisk_type == VD_DISK_TYPE_DISK)
			status = vd_setup_backend_vnode(vd);
		else
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
			if (!(vd->initialized & VD_SETUP_ERROR)) {
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
		PR0("vdisk_type = %s, pseudo = %s, file = %s, nslices = %u",
		    ((vd->vdisk_type == VD_DISK_TYPE_DISK) ? "disk" : "slice"),
		    (vd->pseudo ? "yes" : "no"), (vd->file ? "yes" : "no"),
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
	vd->enabled = 1;	/* before callback can dispatch to startq */


	/* Bring up LDC */
	ldc_attr.devclass	= LDC_DEV_BLK_SVC;
	ldc_attr.instance	= ddi_get_instance(vds->dip);
	ldc_attr.mode		= LDC_MODE_UNRELIABLE;
	ldc_attr.mtu		= VD_LDC_MTU;
	if ((status = ldc_init(ldc_id, &ldc_attr, &vd->ldc_handle)) != 0) {
		PRN("Could not initialize LDC channel %lu, "
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

	/* Allocate the staging buffer */
	vd->max_msglen	= sizeof (vio_msg_t);	/* baseline vio message size */
	vd->vio_msgp = kmem_alloc(vd->max_msglen, KM_SLEEP);

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
			kmem_free(vdp->dring_task[i].msg, vdp->max_msglen);
			vdp->dring_task[i].msg = NULL;
		}
		kmem_free(vdp->dring_task,
		    (sizeof (*vdp->dring_task)) * vdp->dring_len);
		vdp->dring_task = NULL;
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

	if (vd->dk_efi.dki_data != NULL)
		kmem_free(vd->dk_efi.dki_data, vd->dk_efi.dki_length);

	/* Disable queuing requests for the vdisk */
	if (vd->initialized & VD_LOCKING) {
		mutex_enter(&vd->lock);
		vd->enabled = 0;
		mutex_exit(&vd->lock);
	}

	/* Drain and destroy start queue (*before* destroying completionq) */
	if (vd->startq != NULL)
		ddi_taskq_destroy(vd->startq);	/* waits for queued tasks */

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
		    0, kcred);
		VN_RELE(vd->file_vnode);
		if (vd->file_devid != NULL)
			ddi_devid_free(vd->file_devid);
	} else {
		/* Close any open backing-device slices */
		for (uint_t slice = 0; slice < vd->nslices; slice++) {
			if (vd->ldi_handle[slice] != NULL) {
				PR0("Closing slice %u", slice);
				(void) ldi_close(vd->ldi_handle[slice],
				    vd->open_flags, kcred);
			}
		}
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
 * 	Parse the options of a vds node. Options are defined as an array
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
	nulldev		/* devo_power */
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
	int		i, status;


	if ((status = ddi_soft_state_init(&vds_state, sizeof (vds_t), 1)) != 0)
		return (status);
	if ((status = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&vds_state);
		return (status);
	}

	/* Fill in the bit-mask of server-supported operations */
	for (i = 0; i < vds_noperations; i++)
		vds_operations |= 1 << (vds_operation[i].operation - 1);

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
