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
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/uio.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/mman.h>
#include <sys/errno.h>
#include <sys/aio_req.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/vnode.h>
#include <sys/lofi.h>
#include <sys/fcntl.h>
#include <sys/pathname.h>
#include <sys/filio.h>
#include <sys/fdio.h>
#include <sys/open.h>
#include <sys/disp.h>
#include <vm/seg_map.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/sdt.h>

#include <stmf.h>
#include <lpif.h>
#include <stmf_sbd.h>
#include <stmf_sbd_ioctl.h>
#include <sbd_impl.h>

typedef struct sbd_filedisk {
	uint32_t	sfd_flags;
	uint64_t	sfd_lun_size;
	uint64_t	sfd_cur_store_size;
	struct vnode	*sfd_vp;
	char		sfd_filename[1];
} sbd_filedisk_t;

#define	META_DATA_SIZE	0x10000	/* 64 * 1024 */
/*
 * sfd_flags
 */
#define	SFD_OPENED		0x0001

stmf_status_t filedisk_online(sbd_store_t *sst);
stmf_status_t filedisk_offline(sbd_store_t *sst);
stmf_status_t filedisk_deregister_lu(sbd_store_t *sst);

stmf_status_t
filedisk_data_read(struct sbd_store *sst, uint64_t offset, uint64_t size,
						uint8_t *buf)
{
	sbd_filedisk_t *sfd = (sbd_filedisk_t *)sst->sst_store_private;
	int ret;
	ssize_t resid;

	if (((offset + size) > sfd->sfd_lun_size) ||
	    ((sfd->sfd_flags & SFD_OPENED) == 0)) {
		return (STMF_FAILURE);
	}

	if ((offset + size) > sfd->sfd_cur_store_size) {
		uint64_t store_end;

		if (offset >= sfd->sfd_cur_store_size) {
			bzero(buf, size);
			return (STMF_SUCCESS);
		}
		store_end = sfd->sfd_cur_store_size - offset;
		bzero(buf + store_end, size - store_end);
		size = store_end;
	}

	DTRACE_PROBE4(backing__store__read__start, sbd_store_t *, sst,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset);

	ret = vn_rdwr(UIO_READ, sfd->sfd_vp, (caddr_t)buf, (ssize_t)size,
	    (offset_t)offset, UIO_SYSSPACE, 0,
	    RLIM64_INFINITY, CRED(), &resid);

	DTRACE_PROBE5(backing__store__read__end, sbd_store_t *, sst,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset,
	    int, ret);

	if (ret || resid) {
		stmf_trace(0, "UIO_READ failed, ret %d, resid %d", ret, resid);
		return (STMF_FAILURE);
	}

	return (STMF_SUCCESS);
}

stmf_status_t
filedisk_data_write(struct sbd_store *sst, uint64_t offset, uint64_t size,
						uint8_t *buf)
{
	sbd_filedisk_t *sfd = (sbd_filedisk_t *)sst->sst_store_private;
	int ret;
	ssize_t resid;

	if (((offset + size) > sfd->sfd_lun_size) ||
	    ((sfd->sfd_flags & SFD_OPENED) == 0)) {
		return (STMF_FAILURE);
	}


	DTRACE_PROBE4(backing__store__write__start, sbd_store_t *, sst,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset);

	ret = vn_rdwr(UIO_WRITE, sfd->sfd_vp, (caddr_t)buf,
	    (ssize_t)size, (offset_t)offset, UIO_SYSSPACE, 0,
	    RLIM64_INFINITY, CRED(), &resid);

	DTRACE_PROBE5(backing__store__write__end, sbd_store_t *, sst,
	    uint8_t *, buf, uint64_t, size, uint64_t, offset,
	    int, ret);

	if (ret || resid) {
		stmf_trace(0, "UIO_WRITE failed, ret %d, resid %d", ret, resid);
		return (STMF_FAILURE);
	} else if ((offset + size) > sfd->sfd_cur_store_size) {
		uint64_t old_size, new_size;

		do {
			old_size = sfd->sfd_cur_store_size;
			if ((offset + size) <= old_size)
				break;
			new_size = offset + size;
		} while (atomic_cas_64(&sfd->sfd_cur_store_size, old_size,
		    new_size) != old_size);
	}

	return (STMF_SUCCESS);
}

stmf_status_t
filedisk_data_flush(struct sbd_store *sst)
{
	sbd_filedisk_t	*sfd = (sbd_filedisk_t *)sst->sst_store_private;
	int		rval;

	rval = VOP_FSYNC(sfd->sfd_vp, FSYNC, kcred, NULL);

	if (rval != 0) {
		stmf_trace(0, "filedisk_data_flush: VOP_FSYNC failed");
		return (STMF_FAILURE);
	}

	return (STMF_SUCCESS);
}

/*
 * Registers a logical unit. Optionally creates it as well.
 */
stmf_status_t
filedisk_register_lu(register_lu_cmd_t *rlc)
{
	sbd_filedisk_t *sfd;
	sbd_store_t *sst;
	sbd_lu_t *slu;
	sst_init_data_t sid;
	stmf_status_t ret;
	struct vnode *vp;
	vattr_t vattr;
	enum vtype vt;
	int flag, error;
	long nbits;
	uint64_t supported_size;
	uint64_t file_size;

	error = lookupname(rlc->name, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	if (error) {
		rlc->return_code = RLC_RET_FILE_LOOKUP_FAILED;
		return (SBD_FILEIO_FAILURE | error);
	}
	vt = vp->v_type;
	VN_RELE(vp);
	if ((vt != VREG) && (vt != VCHR) && (vt != VBLK)) {
		rlc->return_code = RLC_RET_WRONG_FILE_TYPE;
		return (SBD_FAILURE);
	}

	/* Check if this file is already registered */
	for (slu = sbd_lu_list; slu; slu = slu->sl_next) {
		sst = slu->sl_sst;
		sfd = (sbd_filedisk_t *)sst->sst_store_private;
		if (strcmp(sfd->sfd_filename, rlc->name) == 0) {
			rlc->return_code = RLC_RET_FILE_ALREADY_REGISTERED;
			return (STMF_ALREADY);
		}
	}

	flag = FREAD | FWRITE | FOFFMAX | FEXCL;
	error = vn_open(rlc->name, UIO_SYSSPACE, flag, 0, &vp, 0, 0);
	if (error) {
		rlc->return_code = RLC_RET_FILE_OPEN_FAILED;
		return (SBD_FILEIO_FAILURE | error);
	}

	vattr.va_mask = AT_SIZE;
	error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL);
	if (error) {
		rlc->return_code = RLC_RET_FILE_GETATTR_FAILED;
		ret = SBD_FILEIO_FAILURE | error;
		goto closeout;
	}

	if ((vt != VREG) && (vattr.va_size == 0)) {
		/*
		 * Its a zero byte block or char device. This cannot be
		 * a raw disk.
		 */
		rlc->return_code = RLC_RET_WRONG_FILE_TYPE;
		ret = SBD_FAILURE;
		goto closeout;
	}

	if (VOP_PATHCONF(vp, _PC_FILESIZEBITS, (ulong_t *)&nbits, CRED(),
	    NULL) != 0) {
		nbits = 0;
	}

	if (rlc->lu_size) {
		file_size = rlc->lu_size + META_DATA_SIZE;
		if ((nbits > 0) && (nbits < 64)) {
			/*
			 * The expression below is correct only if nbits is
			 * positive and less than 64.
			 */
			supported_size = (((uint64_t)1) << nbits) - 1;
			if (file_size > supported_size) {
				rlc->return_code =
				    RLC_RET_SIZE_NOT_SUPPORTED_BY_FS;
				rlc->filesize_nbits = (uint32_t)nbits;
				ret = SBD_FAILURE;
				goto closeout;
			}
		}
	} else {
		file_size = vattr.va_size;
		rlc->lu_size = (file_size > META_DATA_SIZE)?
		    (file_size - META_DATA_SIZE):0;
	}
	if (rlc->flags & RLC_CREATE_LU) {
		if (rlc->lu_size < (1024 * 1024)) {
			rlc->return_code = RLC_RET_FILE_SIZE_ERROR;
			ret = SBD_FAILURE;
			goto closeout;
		}
		if (rlc->lu_size % DEV_BSIZE) {
			rlc->return_code = RLC_RET_FILE_ALIGN_ERROR;
			ret = SBD_FAILURE;
			goto closeout;
		}
	}

	sst = sbd_sst_alloc(sizeof (sbd_filedisk_t) + strlen(rlc->name), 0);
	sfd = (sbd_filedisk_t *)sst->sst_store_private;
	(void) strcpy(sfd->sfd_filename, rlc->name);
	/*
	 * If we are only registering LU, then we should use the size
	 * get from the meta data as the lun_size, but for now, we have to
	 * temporarily set it to the file size to avoid read failure when
	 * reading meta data
	 */
	sfd->sfd_lun_size = file_size;
	if (sfd->sfd_lun_size < META_DATA_SIZE)
		/*
		 * with aligned read/write, now we have to set this larger to
		 * avoid read failure with old style LU
		 */
		sfd->sfd_lun_size = META_DATA_SIZE;
	sfd->sfd_cur_store_size = vattr.va_size;
	sfd->sfd_vp = vp;
	sfd->sfd_flags = SFD_OPENED;

	sst->sst_online = filedisk_online;
	sst->sst_offline = filedisk_offline;
	sst->sst_deregister_lu = filedisk_deregister_lu;
	sst->sst_data_read = filedisk_data_read;
	sst->sst_data_write = filedisk_data_write;
	sst->sst_data_flush = filedisk_data_flush;
	sst->sst_alias = sfd->sfd_filename;

	if (rlc->flags & RLC_CREATE_LU) {
		sid.sst_store_size = sfd->sfd_lun_size;
		sid.sst_store_meta_data_size = 0;	/* XXX */
		sid.sst_flags = 0;
		sid.sst_blocksize = 512;

		if ((ret = sbd_create_meta(sst, &sid)) != STMF_SUCCESS) {
			rlc->return_code = RLC_RET_META_CREATION_FAILED;
			sbd_sst_free(sst);
			goto closeout;
		}
		bcopy(sid.sst_guid, rlc->guid, 16);
	}

	if (rlc->flags & RLC_REGISTER_LU) {
		if ((ret = sbd_register_sst(sst, &sid)) != STMF_SUCCESS) {
			bcopy(sid.sst_guid, rlc->guid, 16);
			if (ret == STMF_ALREADY) {
				rlc->return_code =
				    RLC_RET_GUID_ALREADY_REGISTERED;
			} else if (ret == STMF_INVALID_ARG) {
				rlc->return_code = RLC_RET_LU_NOT_INITIALIZED;
			} else {
				rlc->return_code = RLC_RET_REGISTER_SST_FAILED;
			}
			sbd_sst_free(sst);
			goto closeout;
		}
		sfd->sfd_lun_size = sid.sst_store_size;
		bcopy(sid.sst_guid, rlc->guid, 16);
		if ((nbits > 0) && (nbits < 64)) {
			/*
			 * The expression below is correct only if nbits is
			 * positive and less than 64.
			 */
			supported_size = (((uint64_t)1) << nbits) - 1;
			if (sfd->sfd_lun_size > supported_size) {
				(void) sbd_deregister_sst(sst);
				sbd_sst_free(sst);
				rlc->return_code =
				    RLC_RET_SIZE_NOT_SUPPORTED_BY_FS;
				rlc->filesize_nbits = (uint32_t)nbits;
				ret = SBD_FAILURE;
				goto closeout;
			}
		}
	} else {
		sbd_sst_free(sst);
		goto closeout;
	}

	rlc->lu_handle = (uint64_t)(unsigned long)sst->sst_sbd_private;

	return (STMF_SUCCESS);

closeout:;
	(void) VOP_CLOSE(vp, flag, 1, 0, CRED(), NULL);
	VN_RELE(vp);
	return (ret);
}

stmf_status_t
filedisk_modify_lu(sbd_store_t *sst, modify_lu_cmd_t *mlc)
{
	sbd_filedisk_t *sfd;
	sst_init_data_t sid;
	stmf_status_t ret = STMF_SUCCESS;
	int lun_registered = 1;
	struct vnode *vp;
	vattr_t	vattr;
	int flag, error;
	uint64_t lun_old_size;
	uint64_t file_size;
	long nbits;

	if (mlc->lu_size < (1024 * 1024)) {
		mlc->return_code = RLC_RET_FILE_SIZE_ERROR;
		return (SBD_FAILURE);
	}
	if (mlc->lu_size % DEV_BSIZE) {
		mlc->return_code = RLC_RET_FILE_ALIGN_ERROR;
		return (SBD_FAILURE);
	}

	if (sst) {
		sfd = (sbd_filedisk_t *)sst->sst_store_private;
		ASSERT(sfd->sfd_flags & SFD_OPENED);
	} else {
		/*
		 * This LUN is not registered, we don't check the file type here
		 * because meta data should have been created for this file,
		 * or else, sbd_modify_meta will fail when read the meta data.
		 */
		lun_registered = 0;

		flag = FREAD | FWRITE | FOFFMAX | FEXCL;
		error = vn_open(mlc->name, UIO_SYSSPACE, flag, 0, &vp, 0, 0);
		if (error) {
			mlc->return_code = RLC_RET_FILE_OPEN_FAILED;
			return (SBD_FILEIO_FAILURE | error);
		}

		vattr.va_mask = AT_SIZE;
		error = VOP_GETATTR(vp, &vattr, 0, CRED(), NULL);
		if (error) {
			mlc->return_code = RLC_RET_FILE_GETATTR_FAILED;
			ret = SBD_FILEIO_FAILURE | error;
			goto closeout;
		}

		sst = sbd_sst_alloc(
		    sizeof (sbd_filedisk_t) + strlen(mlc->name), 0);
		sfd = (sbd_filedisk_t *)sst->sst_store_private;
		(void) strcpy(sfd->sfd_filename, mlc->name);
		sfd->sfd_vp = vp;
		sfd->sfd_flags = SFD_OPENED;
		/* set this, or else read meta data will fail */
		sfd->sfd_cur_store_size = vattr.va_size;
		sst->sst_data_read = filedisk_data_read;
		sst->sst_data_write = filedisk_data_write;
		sst->sst_alias = sfd->sfd_filename;
	}

	file_size = mlc->lu_size + META_DATA_SIZE;
	if ((VOP_PATHCONF(sfd->sfd_vp, _PC_FILESIZEBITS, (ulong_t *)&nbits,
	    CRED(), NULL) == 0) && (nbits > 0) && (nbits < 64)) {
		uint64_t supported_size;

		supported_size = (((uint64_t)1) << nbits) - 1;
		if (file_size > supported_size) {
			mlc->return_code =
			    RLC_RET_SIZE_NOT_SUPPORTED_BY_FS;
			mlc->filesize_nbits = (uint32_t)nbits;
			ret = SBD_FAILURE;
			goto closeout;
		}
	}

	lun_old_size = sfd->sfd_lun_size;
	sfd->sfd_lun_size = file_size;
	sid.sst_store_size = file_size;
	sid.sst_store_meta_data_size = 0;
	sid.sst_flags = 0;
	sid.sst_blocksize = 512;

	ret = sbd_modify_meta(sst, &sid);
	bcopy(sid.sst_guid, mlc->guid, 16);
	if (ret != STMF_SUCCESS) {
		/* if fail, just restore the old size */
		sfd->sfd_lun_size = lun_old_size;
		if (ret == STMF_INVALID_ARG) {
			mlc->return_code = RLC_RET_LU_NOT_INITIALIZED;
		}
	}
closeout:
	if (lun_registered == 0) {
		if (sst)
			sbd_sst_free(sst);
		(void) VOP_CLOSE(vp, flag, 1, 0, CRED(), NULL);
		VN_RELE(vp);
	}
	return (ret);
}

void
filedisk_fillout_attr(struct sbd_store *sst, struct sbd_lu_attr *sla)
{
	sbd_filedisk_t *sfd = (sbd_filedisk_t *)sst->sst_store_private;

	if (sst->sst_data_read != filedisk_data_read)
		return;

	sla->flags = RLC_LU_TYPE_FILEDISK;
	if (sla->max_name_length < 2)
		return;
	(void) strncpy(sla->name, sfd->sfd_filename, sla->max_name_length-1);
	sla->name[sla->max_name_length-2] = 0;
}

/*
 * Ideally file should be opened when the lu is onlined but the metadata
 * access is needed even if lu is not yet onlined. Until we implement better
 * metadata handling routines i.e. allow metadata access even if lu is not
 * online, we will open the file during lu register itself.
 */
/* ARGSUSED */
stmf_status_t
filedisk_online(sbd_store_t *sst)
{
#if 0
	sbd_filedisk_t *sfd;
	int flag, error;

	sfd = (sbd_filedisk_t *)sst->sst_store_private;
	ASSERT((sfd->sfd_flags & SFD_OPENED) == 0);
	error = lookupname(sfd->sfd_filename, UIO_SYSSPACE, FOLLOW,
	    NULLVPP, &sfd->sfd_vp);
	if (error) {
		return (SBD_FILEIO_FAILURE | error);
	}
	VN_RELE(sfd->sfd_vp);

	flag = FREAD | FWRITE | FOFFMAX | FEXCL;
	error = vn_open(sfd->sfd_filename, UIO_SYSSPACE, flag, 0,
	    &sfd->sfd_vp, 0, 0);
	if (error) {
		return (SBD_FILEIO_FAILURE | error);
	}
	sfd->sfd_flags = SFD_OPENED;
#endif

	return (STMF_SUCCESS);
}

/* ARGSUSED */
stmf_status_t
filedisk_offline(sbd_store_t *sst)
{
#if 0
	sbd_filedisk_t *sfd;
	int flag;

	sfd = (sbd_filedisk_t *)sst->sst_store_private;
	ASSERT(sfd->sfd_flags & SFD_OPENED);
	flag = FREAD | FWRITE | FOFFMAX | FEXCL;
	(void) VOP_CLOSE(sfd->sfd_vp, flag, 1, 0, CRED());
	VN_RELE(sfd->sfd_vp);

	sfd->sfd_flags &= ~SFD_OPENED;
#endif
	return (STMF_SUCCESS);
}

stmf_status_t
filedisk_deregister_lu(sbd_store_t *sst)
{
	stmf_status_t ret;
	sbd_filedisk_t *sfd = (sbd_filedisk_t *)sst->sst_store_private;

	if ((ret = sbd_deregister_sst(sst)) != STMF_SUCCESS)
		return (ret);
	if (sfd->sfd_flags & SFD_OPENED) {
		int flag = FREAD | FWRITE | FOFFMAX | FEXCL;
		sfd->sfd_flags &= ~SFD_OPENED;
		(void) VOP_CLOSE(sfd->sfd_vp, flag, 1, 0, CRED(), NULL);
		VN_RELE(sfd->sfd_vp);
	}
	sbd_sst_free(sst);

	return (STMF_SUCCESS);
}
