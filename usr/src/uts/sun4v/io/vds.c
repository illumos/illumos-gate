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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Virtual disk server
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/dkio.h>
#include <sys/file.h>
#include <sys/mdeg.h>
#include <sys/modhash.h>
#include <sys/note.h>
#include <sys/pathname.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sysmacros.h>
#include <sys/vio_common.h>
#include <sys/vdsk_mailbox.h>
#include <sys/vdsk_common.h>
#include <sys/vtoc.h>


/* Virtual disk server initialization flags */
#define	VDS_LOCKING		0x01
#define	VDS_LDI			0x02
#define	VDS_MDEG		0x04

/* Virtual disk server tunable parameters */
#define	VDS_LDC_RETRIES		3
#define	VDS_NCHAINS		32

/* Identification parameters for MD, synthetic dkio(7i) structures, etc. */
#define	VDS_NAME		"virtual-disk-server"

#define	VD_NAME			"vd"
#define	VD_VOLUME_NAME		"vdisk"
#define	VD_ASCIILABEL		"Virtual Disk"

#define	VD_CHANNEL_ENDPOINT	"channel-endpoint"
#define	VD_ID_PROP		"id"
#define	VD_BLOCK_DEVICE_PROP	"vds-block-device"

/* Virtual disk initialization flags */
#define	VD_LOCKING		0x01
#define	VD_TASKQ		0x02
#define	VD_LDC			0x04
#define	VD_DRING		0x08
#define	VD_SID			0x10
#define	VD_SEQ_NUM		0x20

/* Flags for opening/closing backing devices via LDI */
#define	VD_OPEN_FLAGS		(FEXCL | FREAD | FWRITE)

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

/* Debugging macros */
#ifdef DEBUG
#define	PR0 if (vd_msglevel > 0)	PRN
#define	PR1 if (vd_msglevel > 1)	PRN
#define	PR2 if (vd_msglevel > 2)	PRN

#define	VD_DUMP_DRING_ELEM(elem)					\
	PRN("dst:%x op:%x st:%u nb:%lx addr:%lx ncook:%u\n",		\
	    elem->hdr.dstate,						\
	    elem->payload.operation,					\
	    elem->payload.status,					\
	    elem->payload.nbytes,					\
	    elem->payload.addr,						\
	    elem->payload.ncookies);

#else	/* !DEBUG */
#define	PR0(...)
#define	PR1(...)
#define	PR2(...)

#define	VD_DUMP_DRING_ELEM(elem)

#endif	/* DEBUG */


typedef struct vds {
	uint_t		initialized;	/* driver inst initialization flags */
	dev_info_t	*dip;		/* driver inst devinfo pointer */
	kmutex_t	lock;		/* lock for this structure */
	ldi_ident_t	ldi_ident;	/* driver's identifier for LDI */
	mod_hash_t	*vd_table;	/* table of virtual disks served */
	mdeg_handle_t	mdeg;		/* handle for MDEG operations  */
} vds_t;

typedef struct vd {
	uint_t			initialized;	/* vdisk initialization flags */
	kmutex_t		lock;		/* lock for this structure */
	vds_t			*vds;		/* server for this vdisk */
	ddi_taskq_t		*taskq;		/* taskq for this vdisk */
	ldi_handle_t		ldi_handle[V_NUMPAR];	/* LDI slice handles */
	dev_t			dev[V_NUMPAR];	/* dev numbers for slices */
	uint_t			nslices;	/* number for slices */
	size_t			vdisk_size;	/* number of blocks in vdisk */
	vd_disk_type_t		vdisk_type;	/* slice or entire disk */
	boolean_t		pseudo;		/* underlying pseudo dev */
	struct dk_geom		dk_geom;	/* synthetic for slice type */
	struct vtoc		vtoc;		/* synthetic for slice type */
	ldc_status_t		ldc_state;	/* LDC connection state */
	ldc_handle_t		ldc_handle;	/* handle for LDC comm */
	size_t			max_msglen;	/* largest LDC message len */
	boolean_t		enabled;	/* whether vdisk is enabled */
	vd_state_t		state;		/* client handshake state */
	uint8_t			xfer_mode;	/* transfer mode with client */
	uint32_t		sid;		/* client's session ID */
	uint64_t		seq_num;	/* message sequence number */
	uint64_t		dring_ident;	/* identifier of dring */
	ldc_dring_handle_t	dring_handle;	/* handle for dring ops */
	uint32_t		descriptor_size;	/* num bytes in desc */
	uint32_t		dring_len;	/* number of dring elements */
	caddr_t			dring;		/* address of dring */
} vd_t;

typedef struct vds_operation {
	uint8_t	operation;
	int	(*function)(vd_t *vd, vd_dring_payload_t *request);
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
} vd_ioctl_t;

/* Define trivial copyin/copyout conversion function flag */
#define	VD_IDENTITY	((void (*)(void *, void *))-1)


static int	vds_ldc_retries = VDS_LDC_RETRIES;
static void	*vds_state;
static uint64_t	vds_operations;	/* see vds_operation[] definition below */

static int	vd_open_flags = VD_OPEN_FLAGS;

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

#ifdef DEBUG
static int	vd_msglevel;
#endif /* DEBUG */


static int
vd_bread(vd_t *vd, vd_dring_payload_t *request)
{
	int		status;
	struct buf	buf;

	PR1("Read %lu bytes at block %lu", request->nbytes, request->addr);
	if (request->nbytes == 0)
		return (EINVAL);	/* no service for trivial requests */
	ASSERT(mutex_owned(&vd->lock));
	ASSERT(request->slice < vd->nslices);

	bioinit(&buf);
	buf.b_flags	= B_BUSY | B_READ;
	buf.b_bcount	= request->nbytes;
	buf.b_un.b_addr = kmem_alloc(buf.b_bcount, KM_SLEEP);
	buf.b_lblkno	= request->addr;
	buf.b_edev	= vd->dev[request->slice];

	if ((status = ldi_strategy(vd->ldi_handle[request->slice], &buf)) == 0)
		status = biowait(&buf);
	biofini(&buf);
	if ((status == 0) &&
	    ((status = ldc_mem_copy(vd->ldc_handle, buf.b_un.b_addr, 0,
		    &request->nbytes, request->cookie, request->ncookies,
		    LDC_COPY_OUT)) != 0)) {
		PRN("ldc_mem_copy() returned errno %d copying to client",
		    status);
	}
	kmem_free(buf.b_un.b_addr, buf.b_bcount);	/* nbytes can change */
	return (status);
}

static int
vd_do_bwrite(vd_t *vd, uint_t slice, diskaddr_t block, size_t nbytes,
    ldc_mem_cookie_t *cookie, uint64_t ncookies, caddr_t data)
{
	int		status;
	struct buf	buf;

	ASSERT(mutex_owned(&vd->lock));
	ASSERT(slice < vd->nslices);
	ASSERT(nbytes != 0);
	ASSERT(data != NULL);

	/* Get data from client */
	if ((status = ldc_mem_copy(vd->ldc_handle, data, 0, &nbytes,
		    cookie, ncookies, LDC_COPY_IN)) != 0) {
		PRN("ldc_mem_copy() returned errno %d copying from client",
		    status);
		return (status);
	}

	bioinit(&buf);
	buf.b_flags	= B_BUSY | B_WRITE;
	buf.b_bcount	= nbytes;
	buf.b_un.b_addr	= data;
	buf.b_lblkno	= block;
	buf.b_edev	= vd->dev[slice];

	if ((status = ldi_strategy(vd->ldi_handle[slice], &buf)) == 0)
		status = biowait(&buf);
	biofini(&buf);
	return (status);
}

static int
vd_bwrite(vd_t *vd, vd_dring_payload_t *request)
{
	int	status;
	caddr_t	data;


	PR1("Write %ld bytes at block %lu", request->nbytes, request->addr);
	if (request->nbytes == 0)
		return (EINVAL);	/* no service for trivial requests */
	data = kmem_alloc(request->nbytes, KM_SLEEP);
	status = vd_do_bwrite(vd, request->slice, request->addr,
	    request->nbytes, request->cookie, request->ncookies, data);
	kmem_free(data, request->nbytes);
	return (status);
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

static int
vd_do_slice_ioctl(vd_t *vd, int cmd, void *ioctl_arg)
{
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
}

static int
vd_do_ioctl(vd_t *vd, vd_dring_payload_t *request, void* buf, vd_ioctl_t *ioctl)
{
	int	rval = 0, status;
	size_t	nbytes = request->nbytes;	/* modifiable copy */


	ASSERT(mutex_owned(&vd->lock));
	ASSERT(request->slice < vd->nslices);
	PR0("Performing %s", ioctl->operation_name);

	/* Get data from client and convert, if necessary */
	if (ioctl->copyin != NULL)  {
		ASSERT(nbytes != 0 && buf != NULL);
		PR1("Getting \"arg\" data from client");
		if ((status = ldc_mem_copy(vd->ldc_handle, buf, 0, &nbytes,
			    request->cookie, request->ncookies,
			    LDC_COPY_IN)) != 0) {
			PRN("ldc_mem_copy() returned errno %d "
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
	if (vd->vdisk_type == VD_DISK_TYPE_SLICE && !vd->pseudo) {
		if ((status = vd_do_slice_ioctl(vd, ioctl->cmd,
			    (void *)ioctl->arg)) != 0)
			return (status);
	} else if ((status = ldi_ioctl(vd->ldi_handle[request->slice],
		    ioctl->cmd, (intptr_t)ioctl->arg, FKIOCTL, kcred,
		    &rval)) != 0) {
		PR0("ldi_ioctl(%s) = errno %d", ioctl->cmd_name, status);
		return (status);
	}
#ifdef DEBUG
	if (rval != 0) {
		PRN("%s set rval = %d, which is not being returned to client",
		    ioctl->cmd_name, rval);
	}
#endif /* DEBUG */

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
			PRN("ldc_mem_copy() returned errno %d "
			    "copying to client", status);
			return (status);
		}
	}

	return (status);
}

/*
 * Open any slices which have become non-empty as a result of performing a
 * set-VTOC operation for the client.
 *
 * When serving a full disk, vds attempts to exclusively open all of the
 * disk's slices to prevent another thread or process in the service domain
 * from "stealing" a slice or from performing I/O to a slice while a vds
 * client is accessing it.  Unfortunately, underlying drivers, such as sd(7d)
 * and cmdk(7d), return an error when attempting to open the device file for a
 * slice which is currently empty according to the VTOC.  This driver behavior
 * means that vds must skip opening empty slices when initializing a vdisk for
 * full-disk service and try to open slices that become non-empty (via a
 * set-VTOC operation) during use of the full disk in order to begin serving
 * such slices to the client.  This approach has an inherent (and therefore
 * unavoidable) race condition; it also means that failure to open a
 * newly-non-empty slice has different semantics than failure to open an
 * initially-non-empty slice:  Due to driver bahavior, opening a
 * newly-non-empty slice is a necessary side effect of vds performing a
 * (successful) set-VTOC operation for a client on an in-service (and in-use)
 * disk in order to begin serving the slice; failure of this side-effect
 * operation does not mean that the client's set-VTOC operation failed or that
 * operations on other slices must fail.  Therefore, this function prints an
 * error message on failure to open a slice, but does not return an error to
 * its caller--unlike failure to open a slice initially, which results in an
 * error that prevents serving the vdisk (and thereby requires an
 * administrator to resolve the problem).  Note that, apart from another
 * thread or process opening a new slice during the race-condition window,
 * failure to open a slice in this function will likely indicate an underlying
 * drive problem, which will also likely become evident in errors returned by
 * operations on other slices, and which will require administrative
 * intervention and possibly servicing the drive.
 */
static void
vd_open_new_slices(vd_t *vd)
{
	int		rval, status;
	struct vtoc	vtoc;


	/* Get the (new) VTOC for updated slice sizes */
	if ((status = ldi_ioctl(vd->ldi_handle[0], DKIOCGVTOC, (intptr_t)&vtoc,
		    FKIOCTL, kcred, &rval)) != 0) {
		PRN("ldi_ioctl(DKIOCGVTOC) returned errno %d", status);
		return;
	}

	/* Open any newly-non-empty slices */
	for (int slice = 0; slice < vd->nslices; slice++) {
		/* Skip zero-length slices */
		if (vtoc.v_part[slice].p_size == 0) {
			if (vd->ldi_handle[slice] != NULL)
				PR0("Open slice %u now has zero length", slice);
			continue;
		}

		/* Skip already-open slices */
		if (vd->ldi_handle[slice] != NULL)
			continue;

		PR0("Opening newly-non-empty slice %u", slice);
		if ((status = ldi_open_by_dev(&vd->dev[slice], OTYP_BLK,
			    vd_open_flags, kcred, &vd->ldi_handle[slice],
			    vd->vds->ldi_ident)) != 0) {
			PRN("ldi_open_by_dev() returned errno %d "
			    "for slice %u", status, slice);
		}
	}
}

#define	RNDSIZE(expr) P2ROUNDUP(sizeof (expr), sizeof (uint64_t))
static int
vd_ioctl(vd_t *vd, vd_dring_payload_t *request)
{
	int		i, status;
	void		*buf = NULL;
	struct dk_geom	dk_geom = {0};
	struct vtoc	vtoc = {0};
	vd_ioctl_t	ioctl[] = {
		/* Command (no-copy) operations */
		{VD_OP_FLUSH, STRINGIZE(VD_OP_FLUSH), 0,
		    DKIOCFLUSHWRITECACHE, STRINGIZE(DKIOCFLUSHWRITECACHE),
		    NULL, NULL, NULL},

		/* "Get" (copy-out) operations */
		{VD_OP_GET_WCE, STRINGIZE(VD_OP_GET_WCE), RNDSIZE(int),
		    DKIOCGETWCE, STRINGIZE(DKIOCGETWCE),
		    NULL, NULL, VD_IDENTITY},
		{VD_OP_GET_DISKGEOM, STRINGIZE(VD_OP_GET_DISKGEOM),
		    RNDSIZE(vd_geom_t),
		    DKIOCGGEOM, STRINGIZE(DKIOCGGEOM),
		    &dk_geom, NULL, dk_geom2vd_geom},
		{VD_OP_GET_VTOC, STRINGIZE(VD_OP_GET_VTOC), RNDSIZE(vd_vtoc_t),
		    DKIOCGVTOC, STRINGIZE(DKIOCGVTOC),
		    &vtoc, NULL, vtoc2vd_vtoc},

		/* "Set" (copy-in) operations */
		{VD_OP_SET_WCE, STRINGIZE(VD_OP_SET_WCE), RNDSIZE(int),
		    DKIOCSETWCE, STRINGIZE(DKIOCSETWCE),
		    NULL, VD_IDENTITY, NULL},
		{VD_OP_SET_DISKGEOM, STRINGIZE(VD_OP_SET_DISKGEOM),
		    RNDSIZE(vd_geom_t),
		    DKIOCSGEOM, STRINGIZE(DKIOCSGEOM),
		    &dk_geom, vd_geom2dk_geom, NULL},
		{VD_OP_SET_VTOC, STRINGIZE(VD_OP_SET_VTOC), RNDSIZE(vd_vtoc_t),
		    DKIOCSVTOC, STRINGIZE(DKIOCSVTOC),
		    &vtoc, vd_vtoc2vtoc, NULL},
	};
	size_t		nioctls = (sizeof (ioctl))/(sizeof (ioctl[0]));


	ASSERT(mutex_owned(&vd->lock));
	ASSERT(request->slice < vd->nslices);

	/*
	 * Determine ioctl corresponding to caller's "operation" and
	 * validate caller's "nbytes"
	 */
	for (i = 0; i < nioctls; i++) {
		if (request->operation == ioctl[i].operation) {
			/* LDC memory operations require 8-byte multiples */
			ASSERT(ioctl[i].nbytes % sizeof (uint64_t) == 0);

			if (request->nbytes != ioctl[i].nbytes) {
				PRN("%s:  Expected nbytes = %lu, got %lu",
				    ioctl[i].operation_name, ioctl[i].nbytes,
				    request->nbytes);
				return (EINVAL);
			}

			break;
		}
	}
	ASSERT(i < nioctls);	/* because "operation" already validated */

	if (request->nbytes)
		buf = kmem_zalloc(request->nbytes, KM_SLEEP);
	status = vd_do_ioctl(vd, request, buf, &ioctl[i]);
	if (request->nbytes)
		kmem_free(buf, request->nbytes);
	if ((request->operation == VD_OP_SET_VTOC) &&
	    (vd->vdisk_type == VD_DISK_TYPE_DISK))
		vd_open_new_slices(vd);
	return (status);
}

/*
 * Define the supported operations once the functions for performing them have
 * been defined
 */
static const vds_operation_t	vds_operation[] = {
	{VD_OP_BREAD,		vd_bread},
	{VD_OP_BWRITE,		vd_bwrite},
	{VD_OP_FLUSH,		vd_ioctl},
	{VD_OP_GET_WCE,		vd_ioctl},
	{VD_OP_SET_WCE,		vd_ioctl},
	{VD_OP_GET_VTOC,	vd_ioctl},
	{VD_OP_SET_VTOC,	vd_ioctl},
	{VD_OP_GET_DISKGEOM,	vd_ioctl},
	{VD_OP_SET_DISKGEOM,	vd_ioctl}
};

static const size_t	vds_noperations =
	(sizeof (vds_operation))/(sizeof (vds_operation[0]));

/*
 * Process a request using a defined operation
 */
static int
vd_process_request(vd_t *vd, vd_dring_payload_t *request)
{
	int	i;


	PR1("Entered");
	ASSERT(mutex_owned(&vd->lock));

	/* Range-check slice */
	if (request->slice >= vd->nslices) {
		PRN("Invalid \"slice\" %u (max %u) for virtual disk",
		    request->slice, (vd->nslices - 1));
		return (EINVAL);
	}

	/* Perform the requested operation */
	for (i = 0; i < vds_noperations; i++)
		if (request->operation == vds_operation[i].operation)
			return (vds_operation[i].function(vd, request));

	/* No matching operation found */
	PRN("Unsupported operation %u", request->operation);
	return (ENOTSUP);
}

static int
send_msg(ldc_handle_t ldc_handle, void *msg, size_t msglen)
{
	int	retry, status;
	size_t	nbytes;


	for (retry = 0, status = EWOULDBLOCK;
	    retry < vds_ldc_retries && status == EWOULDBLOCK;
	    retry++) {
		PR1("ldc_write() attempt %d", (retry + 1));
		nbytes = msglen;
		status = ldc_write(ldc_handle, msg, &nbytes);
	}

	if (status != 0) {
		PRN("ldc_write() returned errno %d", status);
		return (status);
	} else if (nbytes != msglen) {
		PRN("ldc_write() performed only partial write");
		return (EIO);
	}

	PR1("SENT %lu bytes", msglen);
	return (0);
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
		PRN("Expected %lu-byte version message; "
		    "received %lu bytes", sizeof (*ver_msg), msglen);
		return (EBADMSG);
	}

	if (ver_msg->dev_class != VDEV_DISK) {
		PRN("Expected device class %u (disk); received %u",
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


	PR0("Entered");
	ASSERT(mutex_owned(&vd->lock));
	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO,
		VIO_ATTR_INFO)) {
		return (ENOMSG);	/* not an attribute message */
	}

	if (msglen != sizeof (*attr_msg)) {
		PRN("Expected %lu-byte attribute message; "
		    "received %lu bytes", sizeof (*attr_msg), msglen);
		return (EBADMSG);
	}

	if (attr_msg->max_xfer_sz == 0) {
		PRN("Received maximum transfer size of 0 from client");
		return (EBADMSG);
	}

	if ((attr_msg->xfer_mode != VIO_DESC_MODE) &&
	    (attr_msg->xfer_mode != VIO_DRING_MODE)) {
		PRN("Client requested unsupported transfer mode");
		return (EBADMSG);
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
	}

	attr_msg->vdisk_size = vd->vdisk_size;
	attr_msg->vdisk_type = vd->vdisk_type;
	attr_msg->operations = vds_operations;
	PR0("%s", VD_CLIENT(vd));
	return (0);
}

static int
vd_process_dring_reg_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	int			status;
	size_t			expected;
	ldc_mem_info_t		dring_minfo;
	vio_dring_reg_msg_t	*reg_msg = (vio_dring_reg_msg_t *)msg;


	PR0("Entered");
	ASSERT(mutex_owned(&vd->lock));
	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO,
		VIO_DRING_REG)) {
		return (ENOMSG);	/* not a register-dring message */
	}

	if (msglen < sizeof (*reg_msg)) {
		PRN("Expected at least %lu-byte register-dring message; "
		    "received %lu bytes", sizeof (*reg_msg), msglen);
		return (EBADMSG);
	}

	expected = sizeof (*reg_msg) +
	    (reg_msg->ncookies - 1)*(sizeof (reg_msg->cookie[0]));
	if (msglen != expected) {
		PRN("Expected %lu-byte register-dring message; "
		    "received %lu bytes", expected, msglen);
		return (EBADMSG);
	}

	if (vd->initialized & VD_DRING) {
		PRN("A dring was previously registered; only support one");
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
		PRN("reg_msg->ncookies = %u != 1", reg_msg->ncookies);
		return (EBADMSG);
	}

	status = ldc_mem_dring_map(vd->ldc_handle, reg_msg->cookie,
	    reg_msg->ncookies, reg_msg->num_descriptors,
	    reg_msg->descriptor_size, LDC_SHADOW_MAP, &vd->dring_handle);
	if (status != 0) {
		PRN("ldc_mem_dring_map() returned errno %d", status);
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
		PRN("ldc_mem_dring_info() returned errno %d", status);
		if ((status = ldc_mem_dring_unmap(vd->dring_handle)) != 0)
			PRN("ldc_mem_dring_unmap() returned errno %d", status);
		return (status);
	}

	if (dring_minfo.vaddr == NULL) {
		PRN("Descriptor ring virtual address is NULL");
		return (ENXIO);
	}


	/* Valid message and dring mapped */
	PR1("descriptor size = %u, dring length = %u",
	    vd->descriptor_size, vd->dring_len);
	vd->initialized |= VD_DRING;
	vd->dring_ident = 1;	/* "There Can Be Only One" */
	vd->dring = dring_minfo.vaddr;
	vd->descriptor_size = reg_msg->descriptor_size;
	vd->dring_len = reg_msg->num_descriptors;
	reg_msg->dring_ident = vd->dring_ident;
	return (0);
}

static int
vd_process_dring_unreg_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	vio_dring_unreg_msg_t	*unreg_msg = (vio_dring_unreg_msg_t *)msg;


	PR0("Entered");
	ASSERT(mutex_owned(&vd->lock));
	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO,
		VIO_DRING_UNREG)) {
		return (ENOMSG);	/* not an unregister-dring message */
	}

	if (msglen != sizeof (*unreg_msg)) {
		PRN("Expected %lu-byte unregister-dring message; "
		    "received %lu bytes", sizeof (*unreg_msg), msglen);
		return (EBADMSG);
	}

	if (unreg_msg->dring_ident != vd->dring_ident) {
		PRN("Expected dring ident %lu; received %lu",
		    vd->dring_ident, unreg_msg->dring_ident);
		return (EBADMSG);
	}

	return (0);
}

static int
process_rdx_msg(vio_msg_t *msg, size_t msglen)
{
	PR0("Entered");
	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_CTRL, VIO_SUBTYPE_INFO, VIO_RDX))
		return (ENOMSG);	/* not an RDX message */

	if (msglen != sizeof (vio_rdx_msg_t)) {
		PRN("Expected %lu-byte RDX message; received %lu bytes",
		    sizeof (vio_rdx_msg_t), msglen);
		return (EBADMSG);
	}

	return (0);
}

static void
vd_reset_connection(vd_t *vd, boolean_t reset_ldc)
{
	int	status = 0;


	ASSERT(mutex_owned(&vd->lock));
	PR0("Resetting connection with %s", VD_CLIENT(vd));
	if ((vd->initialized & VD_DRING) &&
	    ((status = ldc_mem_dring_unmap(vd->dring_handle)) != 0))
		PRN("ldc_mem_dring_unmap() returned errno %d", status);
	if ((reset_ldc == B_TRUE) &&
	    ((status = ldc_reset(vd->ldc_handle)) != 0))
		PRN("ldc_reset() returned errno %d", status);
	vd->initialized &= ~(VD_SID | VD_SEQ_NUM | VD_DRING);
	vd->state = VD_STATE_INIT;
	vd->max_msglen = sizeof (vio_msg_t);	/* baseline vio message size */
}

static int
vd_check_seq_num(vd_t *vd, uint64_t seq_num)
{
	ASSERT(mutex_owned(&vd->lock));
	if ((vd->initialized & VD_SEQ_NUM) && (seq_num != vd->seq_num + 1)) {
		PRN("Received seq_num %lu; expected %lu",
		    seq_num, (vd->seq_num + 1));
		vd_reset_connection(vd, B_FALSE);
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


	PR1("Entered");
	ASSERT(mutex_owned(&vd->lock));
	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_DATA, VIO_SUBTYPE_INFO,
		VIO_DESC_DATA))
		return (ENOMSG);	/* not an in-band-descriptor message */

	if (msglen < sizeof (*desc_msg)) {
		PRN("Expected at least %lu-byte descriptor message; "
		    "received %lu bytes", sizeof (*desc_msg), msglen);
		return (EBADMSG);
	}

	if (msglen != (expected = expected_inband_size(desc_msg))) {
		PRN("Expected %lu-byte descriptor message; "
		    "received %lu bytes", expected, msglen);
		return (EBADMSG);
	}

	if (vd_check_seq_num(vd, desc_msg->hdr.seq_num) != 0) {
		return (EBADMSG);
	}

	/* Valid message; process the request */
	desc_msg->payload.status = vd_process_request(vd, &desc_msg->payload);
	return (0);
}

static boolean_t
vd_accept_dring_elems(vd_t *vd, uint32_t start, uint32_t ndesc)
{
	uint32_t	i, n;


	/* Check descriptor states */
	for (n = ndesc, i = start; n > 0; n--, i = (i + 1) % vd->dring_len) {
		if (VD_DRING_ELEM(i)->hdr.dstate != VIO_DESC_READY) {
			PRN("descriptor %u not ready", i);
			VD_DUMP_DRING_ELEM(VD_DRING_ELEM(i));
			return (B_FALSE);
		}
	}

	/* Descriptors are valid; accept them */
	for (n = ndesc, i = start; n > 0; n--, i = (i + 1) % vd->dring_len)
		VD_DRING_ELEM(i)->hdr.dstate = VIO_DESC_ACCEPTED;

	return (B_TRUE);
}

static int
vd_process_dring(vd_t *vd, uint32_t start, uint32_t end)
{
	int		status;
	boolean_t	accepted;
	uint32_t	i, io_status, n, ndesc;


	ASSERT(mutex_owned(&vd->lock));
	PR1("start = %u, end = %u", start, end);

	/* Validate descriptor range */
	if ((start >= vd->dring_len) || (end >= vd->dring_len)) {
		PRN("\"start\" = %u, \"end\" = %u; both must be less than %u",
		    start, end, vd->dring_len);
		return (EINVAL);
	}

	/* Acquire updated dring elements */
	if ((status = ldc_mem_dring_acquire(vd->dring_handle,
		    start, end)) != 0) {
		PRN("ldc_mem_dring_acquire() returned errno %d", status);
		return (status);
	}
	/* Accept updated dring elements */
	ndesc = ((end < start) ? end + vd->dring_len : end) - start + 1;
	PR1("ndesc = %u", ndesc);
	accepted = vd_accept_dring_elems(vd, start, ndesc);
	/* Release dring elements */
	if ((status = ldc_mem_dring_release(vd->dring_handle,
		    start, end)) != 0) {
		PRN("ldc_mem_dring_release() returned errno %d", status);
		return (status);
	}
	/* If a descriptor was in the wrong state, return an error */
	if (!accepted)
		return (EINVAL);


	/* Process accepted dring elements */
	for (n = ndesc, i = start; n > 0; n--, i = (i + 1) % vd->dring_len) {
		vd_dring_entry_t	*elem = VD_DRING_ELEM(i);

		/* Process descriptor outside acquire/release bracket */
		PR1("Processing dring element %u", i);
		io_status = vd_process_request(vd, &elem->payload);

		/* Re-acquire client's dring element */
		if ((status = ldc_mem_dring_acquire(vd->dring_handle,
			    i, i)) != 0) {
			PRN("ldc_mem_dring_acquire() returned errno %d",
			    status);
			return (status);
		}
		/* Update processed element */
		if (elem->hdr.dstate == VIO_DESC_ACCEPTED) {
			elem->payload.status	= io_status;
			elem->hdr.dstate	= VIO_DESC_DONE;
		} else {
			/* Perhaps client timed out waiting for I/O... */
			accepted = B_FALSE;
			PRN("element %u no longer \"accepted\"", i);
			VD_DUMP_DRING_ELEM(elem);
		}
		/* Release updated processed element */
		if ((status = ldc_mem_dring_release(vd->dring_handle,
			    i, i)) != 0) {
			PRN("ldc_mem_dring_release() returned errno %d",
			    status);
			return (status);
		}
		/* If the descriptor was in the wrong state, return an error */
		if (!accepted)
			return (EINVAL);
	}

	return (0);
}

static int
vd_process_dring_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	vio_dring_msg_t	*dring_msg = (vio_dring_msg_t *)msg;


	PR1("Entered");
	ASSERT(mutex_owned(&vd->lock));
	ASSERT(msglen >= sizeof (msg->tag));

	if (!vd_msgtype(&msg->tag, VIO_TYPE_DATA, VIO_SUBTYPE_INFO,
		VIO_DRING_DATA)) {
		return (ENOMSG);	/* not a dring-data message */
	}

	if (msglen != sizeof (*dring_msg)) {
		PRN("Expected %lu-byte dring message; received %lu bytes",
		    sizeof (*dring_msg), msglen);
		return (EBADMSG);
	}

	if (vd_check_seq_num(vd, dring_msg->seq_num) != 0) {
		return (EBADMSG);
	}

	if (dring_msg->dring_ident != vd->dring_ident) {
		PRN("Expected dring ident %lu; received ident %lu",
		    vd->dring_ident, dring_msg->dring_ident);
		return (EBADMSG);
	}


	/* Valid message; process dring */
	dring_msg->tag.vio_subtype = VIO_SUBTYPE_ACK;
	return (vd_process_dring(vd, dring_msg->start_idx, dring_msg->end_idx));
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

	if (status != 0) {
		PRN("ldc_read() returned errno %d", status);
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
	ASSERT(mutex_owned(&vd->lock));

	/*
	 * Validate session ID up front, since it applies to all messages
	 * once set
	 */
	if ((msg->tag.vio_sid != vd->sid) && (vd->initialized & VD_SID)) {
		PRN("Expected SID %u, received %u", vd->sid,
		    msg->tag.vio_sid);
		return (EBADMSG);
	}


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
			PRN("Unsupported transfer mode");
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
			PRN("Unsupported transfer mode");
			return (ENOTSUP);
		}

	default:
		ASSERT("Invalid client connection state");
		PRN("Invalid client connection state");
		return (ENOTSUP);
	}
}

static void
vd_process_msg(vd_t *vd, vio_msg_t *msg, size_t msglen)
{
	int		status;
	boolean_t	reset_ldc = B_FALSE;


	ASSERT(mutex_owned(&vd->lock));

	/*
	 * Check that the message is at least big enough for a "tag", so that
	 * message processing can proceed based on tag-specified message type
	 */
	if (msglen < sizeof (vio_msg_tag_t)) {
		PRN("Received short (%lu-byte) message", msglen);
		/* Can't "nack" short message, so drop the big hammer */
		vd_reset_connection(vd, B_TRUE);
		return;
	}

	/*
	 * Process the message
	 */
	switch (status = vd_do_process_msg(vd, msg, msglen)) {
	case 0:
		/* "ack" valid, successfully-processed messages */
		msg->tag.vio_subtype = VIO_SUBTYPE_ACK;
		break;

	case ENOMSG:
		PRN("Received unexpected message");
		_NOTE(FALLTHROUGH);
	case EBADMSG:
	case ENOTSUP:
		/* "nack" invalid messages */
		msg->tag.vio_subtype = VIO_SUBTYPE_NACK;
		break;

	default:
		/* "nack" failed messages */
		msg->tag.vio_subtype = VIO_SUBTYPE_NACK;
		/* An LDC error probably occurred, so try resetting it */
		reset_ldc = B_TRUE;
		break;
	}

	/* "ack" or "nack" the message */
	PR1("Sending %s",
	    (msg->tag.vio_subtype == VIO_SUBTYPE_ACK) ? "ACK" : "NACK");
	if (send_msg(vd->ldc_handle, msg, msglen) != 0)
		reset_ldc = B_TRUE;

	/* Reset the connection for nack'ed or failed messages */
	if ((status != 0) || reset_ldc)
		vd_reset_connection(vd, reset_ldc);
}

static void
vd_recv_msg(void *arg)
{
	vd_t	*vd = (vd_t *)arg;
	int	status = 0;


	PR2("Entered");
	ASSERT(vd != NULL);
	mutex_enter(&vd->lock);
	/*
	 * Receive and process any messages in the LDC queue; max_msglen is
	 * reset each time through the loop, as vd->max_msglen can increase
	 * during connection handshake
	 */
	for (size_t max_msglen = vd->max_msglen;
	    vd->enabled && status == 0;
	    max_msglen = vd->max_msglen) {
		size_t		msglen = max_msglen;
		vio_msg_t	*vio_msg = kmem_alloc(max_msglen, KM_SLEEP);

		if ((status = recv_msg(vd->ldc_handle, vio_msg, &msglen)) == 0)
			vd_process_msg(vd, vio_msg, msglen);
		else if (status != ENOMSG)
			vd_reset_connection(vd, B_TRUE);
		kmem_free(vio_msg, max_msglen);
	}
	mutex_exit(&vd->lock);
	PR2("Returning");
}

static uint_t
vd_do_handle_ldc_events(vd_t *vd, uint64_t event)
{
	ASSERT(mutex_owned(&vd->lock));

	if (!vd->enabled)
		return (LDC_SUCCESS);

	if (event & LDC_EVT_RESET) {
		PR0("Channel was reset");
		return (LDC_SUCCESS);
	}

	if (event & LDC_EVT_UP) {
		/* Reset the connection state when channel comes (back) up */
		vd_reset_connection(vd, B_FALSE);
	}

	if (event & LDC_EVT_READ) {
		PR1("New data available");
		/* Queue a task to receive the new data */
		if (ddi_taskq_dispatch(vd->taskq, vd_recv_msg, vd, DDI_SLEEP) !=
		    DDI_SUCCESS)
			PRN("Unable to dispatch vd_recv_msg()");
	}

	return (LDC_SUCCESS);
}

static uint_t
vd_handle_ldc_events(uint64_t event, caddr_t arg)
{
	uint_t	status;
	vd_t	*vd = (vd_t *)(void *)arg;


	ASSERT(vd != NULL);
	mutex_enter(&vd->lock);
	status = vd_do_handle_ldc_events(vd, event);
	mutex_exit(&vd->lock);
	return (status);
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


	PR0("Entered");
	switch (cmd) {
	case DDI_DETACH:
		/* the real work happens below */
		break;
	case DDI_SUSPEND:
		/* nothing to do for this non-device */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ASSERT(cmd == DDI_DETACH);
	instance = ddi_get_instance(dip);
	if ((vds = ddi_get_soft_state(vds_state, instance)) == NULL) {
		PRN("Could not get state for instance %u", instance);
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
	if (vds->initialized & VDS_MDEG)
		(void) mdeg_unregister(vds->mdeg);
	if (vds->initialized & VDS_LDI)
		(void) ldi_ident_release(vds->ldi_ident);
	mod_hash_destroy_hash(vds->vd_table);
	if (vds->initialized & VDS_LOCKING)
		mutex_destroy(&vds->lock);
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
	struct vtoc	vtoc;


	/* Get the VTOC for slice sizes */
	if ((status = ldi_ioctl(vd->ldi_handle[0], DKIOCGVTOC, (intptr_t)&vtoc,
		    FKIOCTL, kcred, &rval)) != 0) {
		PRN("ldi_ioctl(DKIOCGVTOC) returned errno %d", status);
		return (status);
	}

	/* Set full-disk parameters */
	vd->vdisk_type	= VD_DISK_TYPE_DISK;
	vd->nslices	= (sizeof (vd->dev))/(sizeof (vd->dev[0]));

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
		 * At least some underlying drivers refuse to open
		 * devices for (currently) zero-length slices, so skip
		 * them for now
		 */
		if (vtoc.v_part[slice].p_size == 0) {
			PR0("Skipping zero-length slice %u", slice);
			continue;
		}

		/*
		 * Open all non-empty slices of the disk to serve them to the
		 * client.  Slices are opened exclusively to prevent other
		 * threads or processes in the service domain from performing
		 * I/O to slices being accessed by a client.  Failure to open
		 * a slice results in vds not serving this disk, as the client
		 * could attempt (and should be able) to access any non-empty
		 * slice immediately.  Any slices successfully opened before a
		 * failure will get closed by vds_destroy_vd() as a result of
		 * the error returned by this function.
		 */
		PR0("Opening device major %u, minor %u = slice %u",
		    major, minor, slice);
		if ((status = ldi_open_by_dev(&vd->dev[slice], OTYP_BLK,
			    vd_open_flags, kcred, &vd->ldi_handle[slice],
			    vd->vds->ldi_ident)) != 0) {
			PRN("ldi_open_by_dev() returned errno %d "
			    "for slice %u", status, slice);
			/* vds_destroy_vd() will close any open slices */
			return (status);
		}
	}

	return (0);
}

static int
vd_setup_vd(char *block_device, vd_t *vd)
{
	int		otyp, rval, status;
	dev_info_t	*dip;
	struct dk_cinfo	dk_cinfo;


	if ((status = ldi_open_by_name(block_device, vd_open_flags, kcred,
		    &vd->ldi_handle[0], vd->vds->ldi_ident)) != 0) {
		PRN("ldi_open_by_name(%s) = errno %d", block_device, status);
		return (status);
	}

	/* Get block device's device number, otyp, and size */
	if ((status = ldi_get_dev(vd->ldi_handle[0], &vd->dev[0])) != 0) {
		PRN("ldi_get_dev() returned errno %d for %s",
		    status, block_device);
		return (status);
	}
	if ((status = ldi_get_otyp(vd->ldi_handle[0], &otyp)) != 0) {
		PRN("ldi_get_otyp() returned errno %d for %s",
		    status, block_device);
		return (status);
	}
	if (otyp != OTYP_BLK) {
		PRN("Cannot serve non-block device %s", block_device);
		return (ENOTBLK);
	}
	if (ldi_get_size(vd->ldi_handle[0], &vd->vdisk_size) != DDI_SUCCESS) {
		PRN("ldi_get_size() failed for %s", block_device);
		return (EIO);
	}

	/* Determine if backing block device is a pseudo device */
	if ((dip = ddi_hold_devi_by_instance(getmajor(vd->dev[0]),
		    dev_to_instance(vd->dev[0]), 0))  == NULL) {
		PRN("%s is no longer accessible", block_device);
		return (EIO);
	}
	vd->pseudo = is_pseudo_device(dip);
	ddi_release_devi(dip);
	if (vd->pseudo) {
		vd->vdisk_type	= VD_DISK_TYPE_SLICE;
		vd->nslices	= 1;
		return (0);	/* ...and we're done */
	}

	/* Get dk_cinfo to determine slice of backing block device */
	if ((status = ldi_ioctl(vd->ldi_handle[0], DKIOCINFO,
		    (intptr_t)&dk_cinfo, FKIOCTL, kcred, &rval)) != 0) {
		PRN("ldi_ioctl(DKIOCINFO) returned errno %d for %s",
		    status, block_device);
		return (status);
	}

	if (dk_cinfo.dki_partition >= V_NUMPAR) {
		PRN("slice %u >= maximum slice %u for %s",
		    dk_cinfo.dki_partition, V_NUMPAR, block_device);
		return (EIO);
	}


	/* If slice is entire-disk slice, initialize for full disk */
	if (dk_cinfo.dki_partition == VD_ENTIRE_DISK_SLICE)
		return (vd_setup_full_disk(vd));


	/* Otherwise, we have a non-entire slice of a block device */
	vd->vdisk_type	= VD_DISK_TYPE_SLICE;
	vd->nslices	= 1;


	/* Initialize dk_geom structure for single-slice block device */
	if ((status = ldi_ioctl(vd->ldi_handle[0], DKIOCGGEOM,
		    (intptr_t)&vd->dk_geom, FKIOCTL, kcred, &rval)) != 0) {
		PRN("ldi_ioctl(DKIOCGEOM) returned errno %d for %s",
		    status, block_device);
		return (status);
	}
	if (vd->dk_geom.dkg_nsect == 0) {
		PRN("%s geometry claims 0 sectors per track", block_device);
		return (EIO);
	}
	if (vd->dk_geom.dkg_nhead == 0) {
		PRN("%s geometry claims 0 heads", block_device);
		return (EIO);
	}
	vd->dk_geom.dkg_ncyl =
	    lbtodb(vd->vdisk_size)/vd->dk_geom.dkg_nsect/vd->dk_geom.dkg_nhead;
	vd->dk_geom.dkg_acyl = 0;
	vd->dk_geom.dkg_pcyl = vd->dk_geom.dkg_ncyl + vd->dk_geom.dkg_acyl;


	/* Initialize vtoc structure for single-slice block device */
	if ((status = ldi_ioctl(vd->ldi_handle[0], DKIOCGVTOC,
		    (intptr_t)&vd->vtoc, FKIOCTL, kcred, &rval)) != 0) {
		PRN("ldi_ioctl(DKIOCGVTOC) returned errno %d for %s",
		    status, block_device);
		return (status);
	}
	bcopy(VD_VOLUME_NAME, vd->vtoc.v_volume,
	    MIN(sizeof (VD_VOLUME_NAME), sizeof (vd->vtoc.v_volume)));
	bzero(vd->vtoc.v_part, sizeof (vd->vtoc.v_part));
	vd->vtoc.v_nparts = 1;
	vd->vtoc.v_part[0].p_tag = V_UNASSIGNED;
	vd->vtoc.v_part[0].p_flag = 0;
	vd->vtoc.v_part[0].p_start = 0;
	vd->vtoc.v_part[0].p_size = lbtodb(vd->vdisk_size);
	bcopy(VD_ASCIILABEL, vd->vtoc.v_asciilabel,
	    MIN(sizeof (VD_ASCIILABEL), sizeof (vd->vtoc.v_asciilabel)));


	return (0);
}

static int
vds_do_init_vd(vds_t *vds, uint64_t id, char *block_device, uint64_t ldc_id,
    vd_t **vdp)
{
	char			tq_name[TASKQ_NAMELEN];
	int			status;
	ddi_iblock_cookie_t	iblock = NULL;
	ldc_attr_t		ldc_attr;
	vd_t			*vd;


	ASSERT(vds != NULL);
	ASSERT(block_device != NULL);
	ASSERT(vdp != NULL);
	PR0("Adding vdisk for %s", block_device);

	if ((vd = kmem_zalloc(sizeof (*vd), KM_NOSLEEP)) == NULL) {
		PRN("No memory for virtual disk");
		return (EAGAIN);
	}
	*vdp = vd;	/* assign here so vds_destroy_vd() can cleanup later */
	vd->vds = vds;


	/* Open vdisk and initialize parameters */
	if ((status = vd_setup_vd(block_device, vd)) != 0)
		return (status);
	ASSERT(vd->nslices > 0 && vd->nslices <= V_NUMPAR);
	PR0("vdisk_type = %s, pseudo = %s, nslices = %u",
	    ((vd->vdisk_type == VD_DISK_TYPE_DISK) ? "disk" : "slice"),
	    (vd->pseudo ? "yes" : "no"), vd->nslices);


	/* Initialize locking */
	if (ddi_get_soft_iblock_cookie(vds->dip, DDI_SOFTINT_MED,
		&iblock) != DDI_SUCCESS) {
		PRN("Could not get iblock cookie.");
		return (EIO);
	}

	mutex_init(&vd->lock, NULL, MUTEX_DRIVER, iblock);
	vd->initialized |= VD_LOCKING;


	/* Create the task queue for the vdisk */
	(void) snprintf(tq_name, sizeof (tq_name), "vd%lu", id);
	PR1("tq_name = %s", tq_name);
	if ((vd->taskq = ddi_taskq_create(vds->dip, tq_name, 1,
		    TASKQ_DEFAULTPRI, 0)) == NULL) {
		PRN("Could not create task queue");
		return (EIO);
	}
	vd->initialized |= VD_TASKQ;
	vd->enabled = 1;	/* before callback can dispatch to taskq */


	/* Bring up LDC */
	ldc_attr.devclass	= LDC_DEV_BLK_SVC;
	ldc_attr.instance	= ddi_get_instance(vds->dip);
	ldc_attr.mode		= LDC_MODE_UNRELIABLE;
	ldc_attr.qlen		= VD_LDC_QLEN;
	if ((status = ldc_init(ldc_id, &ldc_attr, &vd->ldc_handle)) != 0) {
		PRN("ldc_init(%lu) = errno %d", ldc_id, status);
		return (status);
	}
	vd->initialized |= VD_LDC;

	if ((status = ldc_reg_callback(vd->ldc_handle, vd_handle_ldc_events,
		(caddr_t)vd)) != 0) {
		PRN("ldc_reg_callback() returned errno %d", status);
		return (status);
	}

	if ((status = ldc_open(vd->ldc_handle)) != 0) {
		PRN("ldc_open() returned errno %d", status);
		return (status);
	}


	/* Add the successfully-initialized vdisk to the server's table */
	if (mod_hash_insert(vds->vd_table, (mod_hash_key_t)id, vd) != 0) {
		PRN("Error adding vdisk ID %lu to table", id);
		return (EIO);
	}

	return (0);
}

/*
 * Destroy the state associated with a virtual disk
 */
static void
vds_destroy_vd(void *arg)
{
	vd_t	*vd = (vd_t *)arg;


	PR0("Entered");
	if (vd == NULL)
		return;

	/* Disable queuing requests for the vdisk */
	if (vd->initialized & VD_LOCKING) {
		mutex_enter(&vd->lock);
		vd->enabled = 0;
		mutex_exit(&vd->lock);
	}

	/* Drain and destroy the task queue (*before* shutting down LDC) */
	if (vd->initialized & VD_TASKQ)
		ddi_taskq_destroy(vd->taskq);	/* waits for queued tasks */

	/* Shut down LDC */
	if (vd->initialized & VD_LDC) {
		if (vd->initialized & VD_DRING)
			(void) ldc_mem_dring_unmap(vd->dring_handle);
		(void) ldc_unreg_callback(vd->ldc_handle);
		(void) ldc_close(vd->ldc_handle);
		(void) ldc_fini(vd->ldc_handle);
	}

	/* Close any open backing-device slices */
	for (uint_t slice = 0; slice < vd->nslices; slice++) {
		if (vd->ldi_handle[slice] != NULL) {
			PR0("Closing slice %u", slice);
			(void) ldi_close(vd->ldi_handle[slice],
			    vd_open_flags, kcred);
		}
	}

	/* Free lock */
	if (vd->initialized & VD_LOCKING)
		mutex_destroy(&vd->lock);

	/* Finally, free the vdisk structure itself */
	kmem_free(vd, sizeof (*vd));
}

static int
vds_init_vd(vds_t *vds, uint64_t id, char *block_device, uint64_t ldc_id)
{
	int	status;
	vd_t	*vd = NULL;


#ifdef lint
	(void) vd;
#endif	/* lint */

	if ((status = vds_do_init_vd(vds, id, block_device, ldc_id, &vd)) != 0)
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

static void
vds_add_vd(vds_t *vds, md_t *md, mde_cookie_t vd_node)
{
	char		*block_device = NULL;
	uint64_t	id = 0, ldc_id = 0;


	if (md_get_prop_val(md, vd_node, VD_ID_PROP, &id) != 0) {
		PRN("Error getting vdisk \"%s\"", VD_ID_PROP);
		return;
	}
	PR0("Adding vdisk ID %lu", id);
	if (md_get_prop_str(md, vd_node, VD_BLOCK_DEVICE_PROP,
		&block_device) != 0) {
		PRN("Error getting vdisk \"%s\"", VD_BLOCK_DEVICE_PROP);
		return;
	}

	if (vds_get_ldc_id(md, vd_node, &ldc_id) != 0) {
		PRN("Error getting LDC ID for vdisk %lu", id);
		return;
	}

	if (vds_init_vd(vds, id, block_device, ldc_id) != 0) {
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
	uint64_t	curr_id = 0, curr_ldc_id = 0;
	uint64_t	prev_id = 0, prev_ldc_id = 0;
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

	PR0("Changing vdisk ID %lu", prev_id);
	/* Remove old state, which will close vdisk and reset */
	if (mod_hash_destroy(vds->vd_table, (mod_hash_key_t)prev_id) != 0)
		PRN("No entry found for vdisk ID %lu", prev_id);
	/* Re-initialize vdisk with new state */
	if (vds_init_vd(vds, curr_id, curr_dev, curr_ldc_id) != 0) {
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
	static char	reg_prop[] = "reg";	/* devinfo ID prop */

	/* MDEG specification for a (particular) vds node */
	static mdeg_prop_spec_t	vds_prop_spec[] = {
		{MDET_PROP_STR, "name", {VDS_NAME}},
		{MDET_PROP_VAL, "cfg-handle", {0}},
		{MDET_LIST_END, NULL, {0}}};
	static mdeg_node_spec_t	vds_spec = {"virtual-device", vds_prop_spec};

	/* MDEG specification for matching a vd node */
	static md_prop_match_t	vd_prop_spec[] = {
		{MDET_PROP_VAL, VD_ID_PROP},
		{MDET_LIST_END, NULL}};
	static mdeg_node_match_t vd_spec = {"virtual-device-port",
					    vd_prop_spec};

	int			status;
	uint64_t		cfg_handle;
	minor_t			instance = ddi_get_instance(dip);
	vds_t			*vds;


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
	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, reg_prop)) {
		PRN("vds \"%s\" property does not exist", reg_prop);
		return (DDI_FAILURE);
	}

	/* Get the MD instance for later MDEG registration */
	cfg_handle = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    reg_prop, -1);

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
							vds_destroy_vd,
							sizeof (void *));
	ASSERT(vds->vd_table != NULL);

	mutex_init(&vds->lock, NULL, MUTEX_DRIVER, NULL);
	vds->initialized |= VDS_LOCKING;

	if ((status = ldi_ident_from_dip(dip, &vds->ldi_ident)) != 0) {
		PRN("ldi_ident_from_dip() returned errno %d", status);
		return (DDI_FAILURE);
	}
	vds->initialized |= VDS_LDI;

	/* Register for MD updates */
	vds_prop_spec[1].ps_val = cfg_handle;
	if (mdeg_register(&vds_spec, &vd_spec, vds_process_md, vds,
		&vds->mdeg) != MDEG_SUCCESS) {
		PRN("Unable to register for MD updates");
		return (DDI_FAILURE);
	}
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

	PR0("Entered");
	switch (cmd) {
	case DDI_ATTACH:
		if ((status = vds_do_attach(dip)) != DDI_SUCCESS)
			(void) vds_detach(dip, DDI_DETACH);
		return (status);
	case DDI_RESUME:
		/* nothing to do for this non-device */
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
	"virtual disk server v%I%",
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


	PR0("Built %s %s", __DATE__, __TIME__);
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


	PR0("Entered");
	if ((status = mod_remove(&modlinkage)) != 0)
		return (status);
	ddi_soft_state_fini(&vds_state);
	return (0);
}
