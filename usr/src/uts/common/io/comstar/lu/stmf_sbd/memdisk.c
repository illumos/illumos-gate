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

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>

#include <stmf.h>
#include <lpif.h>
#include <stmf_sbd.h>
#include <stmf_sbd_ioctl.h>

stmf_status_t memdisk_online(sbd_store_t *sst);
stmf_status_t memdisk_offline(sbd_store_t *sst);
stmf_status_t memdisk_deregister_lu(sbd_store_t *sst);

typedef struct sbd_memdisk {
	uint64_t	smd_size;
	uint8_t		*smd_buf;
} sbd_memdisk_t;

stmf_status_t
memdisk_data_read(struct sbd_store *sst, uint64_t offset, uint64_t size,
						uint8_t *buf)
{
	sbd_memdisk_t *smd = (sbd_memdisk_t *)sst->sst_store_private;

	if ((offset + size) > smd->smd_size) {
		return (STMF_FAILURE);
	}

	bcopy(&smd->smd_buf[offset], buf, (size_t)size);
	return (STMF_SUCCESS);
}

stmf_status_t
memdisk_data_write(struct sbd_store *sst, uint64_t offset, uint64_t size,
						uint8_t *buf)
{
	sbd_memdisk_t *smd = (sbd_memdisk_t *)sst->sst_store_private;

	if ((offset + size) > smd->smd_size) {
		return (STMF_FAILURE);
	}

	bcopy(buf, &smd->smd_buf[offset], (size_t)size);
	return (STMF_SUCCESS);
}

/* ARGSUSED */
stmf_status_t
memdisk_data_flush(struct sbd_store *sst)
{
	return (STMF_SUCCESS);
}

/*
 * Creates and registers a LU
 */
stmf_status_t
memdisk_register_lu(register_lu_cmd_t *rlc)
{
	sbd_memdisk_t *smd;
	sbd_store_t *sst;
	sst_init_data_t sid;
	stmf_status_t ret;

	if (((rlc->lu_size < MEMDISK_MIN_SIZE) ||
	    (rlc->lu_size > MEMDISK_MAX_SIZE)) &&
	    ((rlc->flags & RLC_FORCE_OP) == 0)) {
		rlc->return_code = RLC_RET_SIZE_OUT_OF_RANGE;
		return (STMF_INVALID_ARG);
	}
	sst = sbd_sst_alloc(sizeof (sbd_memdisk_t), 0);
	smd = (sbd_memdisk_t *)sst->sst_store_private;
	smd->smd_size = rlc->lu_size;
	smd->smd_buf = kmem_zalloc((size_t)smd->smd_size, KM_SLEEP);

	sst->sst_online = memdisk_online;
	sst->sst_offline = memdisk_offline;
	sst->sst_deregister_lu = memdisk_deregister_lu;
	sst->sst_data_read = memdisk_data_read;
	sst->sst_data_write = memdisk_data_write;
	sst->sst_data_flush = memdisk_data_flush;

	sid.sst_store_size = smd->smd_size;
	sid.sst_store_meta_data_size = 0;
	sid.sst_flags = SST_NOT_PERSISTENT;
	sid.sst_blocksize = 512;

	if ((ret = sbd_create_meta(sst, &sid)) != STMF_SUCCESS) {
		rlc->return_code = RLC_RET_META_CREATION_FAILED;
		kmem_free(smd->smd_buf, (size_t)smd->smd_size);
		sbd_sst_free(sst);
		return (ret);
	}

	if ((ret = sbd_register_sst(sst, &sid)) != STMF_SUCCESS) {
		rlc->return_code = RLC_RET_REGISTER_SST_FAILED;
		kmem_free(smd->smd_buf, (size_t)smd->smd_size);
		sbd_sst_free(sst);
		return (ret);
	}

	rlc->lu_handle = (uint64_t)(unsigned long)sst->sst_sbd_private;

	return (STMF_SUCCESS);
}

void
memdisk_fillout_attr(struct sbd_store *sst, struct sbd_lu_attr *sla)
{
	if (sst->sst_data_read != memdisk_data_read)
		return;

	sla->flags = RLC_LU_TYPE_MEMDISK;
}

/* ARGSUSED */
stmf_status_t
memdisk_online(sbd_store_t *sst)
{
	return (STMF_SUCCESS);
}

/* ARGSUSED */
stmf_status_t
memdisk_offline(sbd_store_t *sst)
{
	return (STMF_SUCCESS);
}

stmf_status_t
memdisk_deregister_lu(sbd_store_t *sst)
{
	stmf_status_t ret;
	sbd_memdisk_t *smd;

	if ((ret = sbd_deregister_sst(sst)) != STMF_SUCCESS)
		return (ret);
	smd = (sbd_memdisk_t *)sst->sst_store_private;
	kmem_free(smd->smd_buf, smd->smd_size);
	sbd_sst_free(sst);

	return (STMF_SUCCESS);
}
