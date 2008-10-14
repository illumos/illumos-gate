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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/stat.h>
#include <sys/errno.h>

#include "../solaris/nsc_thread.h"
#ifdef DS_DDICT
#include "../contract.h"
#endif
#include <sys/nsctl/nsctl.h>

#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>

#include "rdc_io.h"
#include "rdc_bitmap.h"
#include "rdc_clnt.h"
#include "rdc_diskq.h"

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

#ifndef UINT8_MAX
#define	UINT8_MAX 255
#endif

#ifndef UINT_MAX
#define	UINT_MAX 0xffffffff
#endif

/*
 * RDC bitmap functions.
 */

/*
 * RDC cluster integration notes.
 *
 * 1. Configuration
 *
 * 1.1. Change 'rdc_bitmap_mode' in /usr/kernel/drv/rdc.conf to '1'.
 *
 * 2. Operation
 *
 * 2.1. SunCluster ensures that only one physical host has any rdc
 *	controlled device imported at any one time.  Hence rdc will
 *	only be active on a single node for any set at a time.
 *
 * 2.2. So operation from the kernel perspective looks just like
 *	operation on a single, standalone, node.
 *
 */

struct rdc_bitmap_ops *rdc_bitmap_ops;		/* the bitmap ops switch */
static int rdc_wrflag;				/* write flag for io */
int rdc_bitmap_delay = 0;
extern nsc_io_t *_rdc_io_hc;

int rdc_suspend_diskq(rdc_k_info_t *krdc);

/*
 * rdc_ns_io
 *	Perform read or write on an underlying ns device
 *
 * fd		- nsc file descriptor
 * flag		- nsc io direction and characteristics flag
 * fba_pos	- offset from beginning of device in FBAs
 * io_addr	- pointer to data buffer
 * io_len	- length of io in bytes
 */

int
rdc_ns_io(nsc_fd_t *fd, int flag, nsc_off_t fba_pos, uchar_t *io_addr,
    nsc_size_t io_len)
{
	nsc_buf_t *tmp;
	nsc_vec_t *vecp;
	uchar_t	*vaddr;
	size_t	copy_len;
	int	vlen;
	int	rc;
	nsc_size_t	fba_req, fba_len;
	nsc_size_t	maxfbas = 0;
	nsc_size_t	tocopy;
	unsigned char *toaddr;

	rc = nsc_maxfbas(fd, 0, &maxfbas);
	if (!RDC_SUCCESS(rc)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_ns_io: maxfbas failed (%d)", rc);
#endif
		maxfbas = 256;
	}
	toaddr = io_addr;
	fba_req = FBA_LEN(io_len);
loop:
	tmp = NULL;
	fba_len = min(fba_req, maxfbas);
	tocopy = min(io_len, FBA_SIZE(fba_len));
	ASSERT(tocopy < INT32_MAX);

	rc = nsc_alloc_buf(fd, fba_pos, fba_len, flag, &tmp);
	if (!RDC_SUCCESS(rc)) {
		if (tmp) {
			(void) nsc_free_buf(tmp);
		}
		return (EIO);
	}

	if ((flag & NSC_WRITE) != 0 && (flag & NSC_READ) == 0 &&
	    FBA_OFF(io_len) != 0) {
		/*
		 * Not overwriting all of the last FBA, so read in the
		 * old contents now before we overwrite it with the new
		 * data.
		 */
		rc = nsc_read(tmp, fba_pos+FBA_NUM(io_len), 1, 0);
		if (!RDC_SUCCESS(rc)) {
			(void) nsc_free_buf(tmp);
			return (EIO);
		}
	}

	vecp = tmp->sb_vec;
	vlen = vecp->sv_len;
	vaddr = vecp->sv_addr;

	while (tocopy > 0) {
		if (vecp->sv_addr == 0 || vecp->sv_len == 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "rdc_ns_io: ran off end of handle");
#endif
			break;
		}

		copy_len = (size_t)min(vlen, (int)tocopy);

		if (flag & NSC_WRITE)
			bcopy(toaddr, vaddr, copy_len);
		else
			bcopy(vaddr, toaddr, copy_len);

		toaddr += copy_len;
		io_addr += copy_len;	/* adjust position in callers buffer */
		io_len -= copy_len;	/* adjust total byte length remaining */
		tocopy -= copy_len;	/* adjust chunk byte length remaining */
		vaddr += copy_len;	/* adjust location in sv_vec_t */
		vlen -= copy_len;	/* adjust length left in sv_vec_t */

		if (vlen <= 0) {
			vecp++;
			vaddr = vecp->sv_addr;
			vlen = vecp->sv_len;
		}
	}

	if (flag & NSC_WRITE) {
		rc = nsc_write(tmp, tmp->sb_pos, tmp->sb_len, 0);
		if (!RDC_SUCCESS(rc)) {
			(void) nsc_free_buf(tmp);
			return (rc);
		}
	}

	(void) nsc_free_buf(tmp);

	fba_pos += fba_len;
	fba_req -= fba_len;
	if (fba_req > 0)
		goto loop;

	return (0);
}

/*
 * Must be called with krdc->bmapmutex held.
 */
static void
rdc_fill_header(rdc_u_info_t *urdc, rdc_header_t *header)
{
	rdc_k_info_t *krdc = &rdc_k_info[urdc->index];
#ifdef DEBUG
	ASSERT(MUTEX_HELD(&krdc->bmapmutex));
#endif

	header->magic = RDC_HDR_MAGIC;
	(void) strncpy(header->primary.file, urdc->primary.file, NSC_MAXPATH);
	(void) strncpy(header->primary.bitmap, urdc->primary.bitmap,
	    NSC_MAXPATH);
	(void) strncpy(header->secondary.file, urdc->secondary.file,
	    NSC_MAXPATH);
	(void) strncpy(header->secondary.bitmap, urdc->secondary.bitmap,
	    NSC_MAXPATH);
	header->flags = urdc->flags | urdc->sync_flags | urdc->bmap_flags;
	header->autosync = urdc->autosync;
	header->maxqfbas = urdc->maxqfbas;
	header->maxqitems = urdc->maxqitems;
	header->asyncthr = urdc->asyncthr;
	header->syshostid = urdc->syshostid;
	header->refcntsize = rdc_refcntsize(krdc);
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
}

/*
 * Must be called with krdc->bmapmutex held.
 */
static int
rdc_read_header(rdc_k_info_t *krdc, rdc_header_t *header)
{
	int sts;
	rdc_u_info_t *urdc;
	union {
		rdc_header_t *current;
		rdc_headerv4_t *v4;
	} u_hdrp;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_read_header: NULL krdc");
#endif
		return (-1);
	}

	ASSERT(MUTEX_HELD(&krdc->bmapmutex));

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED)
		return (-1);

	if (krdc->bitmapfd == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_read_header: NULL bitmapfd");
#endif
		return (-1);
	}
	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		return (-1);
	}

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}

	sts = rdc_ns_io(krdc->bitmapfd, NSC_RDBUF, 0, (uchar_t *)header,
		sizeof (rdc_header_t));

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->reads++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nread += sizeof (rdc_header_t);
	}

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_read_header: %s read failed %d",
		    urdc->primary.file, sts);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "read header failed");
	}

	_rdc_rlse_devs(krdc, RDC_BMP);

	if (!RDC_SUCCESS(sts))
		return (-1);
	switch (header->magic) {
	case RDC_HDR_V4:
		/*
		 * old header format - upgrade incore copy, disk copy will
		 * be changed when state is re-written.
		 */
#ifdef DEBUG
		cmn_err(CE_NOTE, "sndr: old style (V4) bit map header");
#endif
		header->magic = RDC_HDR_MAGIC;
		u_hdrp.current = header;
		/* copy down items moved by new maxq??? sizes */
		u_hdrp.current->asyncthr = u_hdrp.v4->asyncthr;
		u_hdrp.current->syshostid = u_hdrp.v4->syshostid;
		u_hdrp.current->maxqitems = u_hdrp.v4->maxqitems;
		u_hdrp.current->maxqfbas = u_hdrp.v4->maxqfbas;
		u_hdrp.current->refcntsize = 1;	/* new field */
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)u_hdrp.current->refcntsize, __LINE__, __FILE__);
#endif
		return (0);
	case RDC_HDR_MAGIC:
		/* current header type */
		return (0);
	default:
		/* not a header we currently understand */
		return (0);
	}
}

/*
 * Must be called with krdc->bmapmutex held.
 */
static int
rdc_write_header(rdc_k_info_t *krdc, rdc_header_t *header)
{
	rdc_u_info_t *urdc;
	int sts;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_header: NULL krdc");
#endif
		return (-1);
	}

	ASSERT(MUTEX_HELD(&krdc->bmapmutex));

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED)
		return (-1);

	if (krdc->bitmapfd == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_header: NULL bitmapfd");
#endif
		return (-1);
	}

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		return (-1);
	}

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}

	sts = rdc_ns_io(krdc->bitmapfd, rdc_wrflag, 0, (uchar_t *)header,
		sizeof (rdc_header_t));

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->writes++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nwritten +=
			sizeof (rdc_header_t);
	}

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_write_header: %s write failed %d",
		    urdc->primary.file, sts);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "write failed");
	}

	_rdc_rlse_devs(krdc, RDC_BMP);

	if (!RDC_SUCCESS(sts))
		return (-1);
	else
		return (0);
}

struct bm_ref_ops rdc_ref_byte_ops;
struct bm_ref_ops rdc_ref_int_ops;

static void
rdc_set_refcnt_ops(rdc_k_info_t *krdc, size_t refcntsize)
{
	switch (refcntsize) {
	default:
		/* FALLTHRU */
	case sizeof (unsigned char):
		krdc->bm_refs = &rdc_ref_byte_ops;
		break;
	case sizeof (unsigned int):
		krdc->bm_refs = &rdc_ref_int_ops;
		break;
	}
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	set refcnt ops for refcntsize %d - %d:%s",
		(int)refcntsize, __LINE__, __FILE__);
#endif
}

size_t
rdc_refcntsize(rdc_k_info_t *krdc)
{
	if (krdc->bm_refs == &rdc_ref_int_ops)
		return (sizeof (unsigned int));
	return (sizeof (unsigned char));
}

int
rdc_read_state(rdc_k_info_t *krdc, int *statep, int *hostidp)
{
	rdc_header_t header;
	rdc_u_info_t *urdc;
	int sts;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_read_state: NULL krdc");
#endif
		return (-1);
	}

	mutex_enter(&krdc->bmapmutex);

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED) {
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bitmapfd == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_read_state: NULL bitmapfd");
#endif
		return (-1);
	}

	sts = rdc_read_header(krdc, &header);
	mutex_exit(&krdc->bmapmutex);

	if (!RDC_SUCCESS(sts)) {
		return (-1);
	}

	switch (header.magic) {
	case RDC_HDR_MAGIC:
		*statep = header.flags;
		*hostidp = header.syshostid;
		rdc_set_refcnt_ops(krdc, header.refcntsize);
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
		sts = 0;
		break;
	default:
		sts = -1;
		break;
	}

	return (sts);
}

int
rdc_clear_state(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	int sts;
	rdc_header_t header;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_clear_state: NULL krdc");
#endif
		return (-1);
	}

	mutex_enter(&krdc->bmapmutex);

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED) {
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bitmapfd == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_clear_state: NULL bitmapfd");
#endif
		return (-1);
	}

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	bzero(&header, sizeof (header));

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}

	sts = rdc_ns_io(krdc->bitmapfd, rdc_wrflag, 0,
	    (uchar_t *)&header, sizeof (header));

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->writes++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nwritten +=
			sizeof (rdc_header_t);
	}

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_clear_state: %s write failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "write failed");
	}

	_rdc_rlse_devs(krdc, RDC_BMP);
	mutex_exit(&krdc->bmapmutex);

	if (!RDC_SUCCESS(sts))
		return (-1);
	else
		return (0);
}

void
rdc_write_state(rdc_u_info_t *urdc)
{
	rdc_k_info_t *krdc;
	int sts;
	rdc_header_t header;

	if (urdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_state: NULL urdc");
#endif
		return;
	}

	krdc = &rdc_k_info[urdc->index];

	mutex_enter(&krdc->bmapmutex);

	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED) {
		mutex_exit(&krdc->bmapmutex);
		return;
	}

	if (krdc->bitmapfd == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_state: NULL bitmapfd");
#endif
		return;
	}

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		mutex_exit(&krdc->bmapmutex);
		return;
	}

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}

	sts = rdc_ns_io(krdc->bitmapfd, NSC_RDBUF, 0, (uchar_t *)&header,
	    sizeof (header));

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->reads++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nread += sizeof (header);
	}

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_write_state: %s read failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "read failed");
		goto done;
	}

	rdc_fill_header(urdc, &header);

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}

	sts = rdc_ns_io(krdc->bitmapfd, rdc_wrflag, 0,
	    (uchar_t *)&header, sizeof (header));

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->writes++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nwritten += sizeof (header);
	}

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_write_state: %s write failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "write failed");
	}

done:
	_rdc_rlse_devs(krdc, RDC_BMP);
	mutex_exit(&krdc->bmapmutex);
}


struct bitmapdata {
	uchar_t	*data;
	size_t	len;
};

static int
rdc_read_bitmap(rdc_k_info_t *krdc, struct bitmapdata *data)
{
	rdc_u_info_t *urdc;
	int sts;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_read_bitmap: NULL krdc");
#endif
		return (-1);
	}

	if (data != NULL) {
		data->data = kmem_alloc(krdc->bitmap_size, KM_SLEEP);
		data->len = krdc->bitmap_size;

		if (data->data == NULL) {
#ifdef DEBUG
			cmn_err(CE_WARN, "rdc_read_bitmap: kmem_alloc failed");
#endif
			return (-1);
		}
	}

	mutex_enter(&krdc->bmapmutex);

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED) {
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bitmapfd == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_read_bitmap: NULL bitmapfd");
#endif
		return (-1);
	}

	if (data == NULL && krdc->dcio_bitmap == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_read_bitmap: NULL dcio_bitmap");
#endif
		return (-1);
	}

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		cmn_err(CE_WARN, "rdc_read_bitmap: %s reserve failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}

	sts = rdc_ns_io(krdc->bitmapfd, NSC_RDBUF, RDC_BITMAP_FBA,
		data ? data->data : krdc->dcio_bitmap, krdc->bitmap_size);

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->reads++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nread += krdc->bitmap_size;
	}

	_rdc_rlse_devs(krdc, RDC_BMP);

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_read_bitmap: %s read failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "read failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	mutex_exit(&krdc->bmapmutex);
	return (0);
}

int
rdc_write_bitmap(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	int sts;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap: NULL krdc");
#endif
		return (-1);
	}

	mutex_enter(&krdc->bmapmutex);

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED) {
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bitmapfd == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap: NULL bitmapfd");
#endif
		return (-1);
	}

	if (krdc->dcio_bitmap == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap: NULL dcio_bitmap");
#endif
		return (-1);
	}

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}

	sts = rdc_ns_io(krdc->bitmapfd, rdc_wrflag, RDC_BITMAP_FBA,
		krdc->dcio_bitmap, krdc->bitmap_size);

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->writes++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nwritten += krdc->bitmap_size;
	}

	_rdc_rlse_devs(krdc, RDC_BMP);

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_write_bitmap: %s write failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "write failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	mutex_exit(&krdc->bmapmutex);
	return (0);
}

int
rdc_write_bitmap_fba(rdc_k_info_t *krdc, nsc_off_t fba)
{
	rdc_u_info_t *urdc;
	int sts;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap_fba: NULL krdc");
#endif
		return (-1);
	}

	mutex_enter(&krdc->bmapmutex);

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED) {
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bitmapfd == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap_fba: NULL bitmapfd");
#endif
		return (-1);
	}

	if (krdc->dcio_bitmap == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap_fba: NULL dcio_bitmap");
#endif
		return (-1);
	}

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		cmn_err(CE_WARN, "rdc_write_bitmap_fba: %s reserve failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
	}
	sts = rdc_ns_io(krdc->bitmapfd, rdc_wrflag, RDC_BITMAP_FBA + fba,
		krdc->dcio_bitmap + fba * 512, 512);

	if (krdc->bmp_kstats) {
		mutex_enter(krdc->bmp_kstats->ks_lock);
		kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
		mutex_exit(krdc->bmp_kstats->ks_lock);
		KSTAT_IO_PTR(krdc->bmp_kstats)->writes++;
		KSTAT_IO_PTR(krdc->bmp_kstats)->nwritten += 512;
	}

	_rdc_rlse_devs(krdc, RDC_BMP);

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_write_bitmap_fba: %s write failed",
		    urdc->primary.file);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "write failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	mutex_exit(&krdc->bmapmutex);
	return (0);
}


static int
rdc_write_bitmap_pattern(rdc_k_info_t *krdc, const char pattern)
{
	rdc_u_info_t *urdc;
	char *buffer;
	nsc_buf_t *h;
	nsc_vec_t *v;
	int rc;
	size_t i;
	nsc_size_t len;
	int  off;
	size_t buffer_size;
	size_t iolen;
	nsc_size_t	fba_req;
	nsc_off_t	fba_len, fba_pos;
	nsc_size_t	maxfbas = 0;
	nsc_size_t	tocopy;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap_pattern: NULL krdc");
#endif
		return (-1);
	}

	mutex_enter(&krdc->bmapmutex);

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED) {
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	if (krdc->bitmapfd == NULL) {
		mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_write_bitmap_pattern: NULL bitmapfd");
#endif
		return (-1);
	}

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reserve failed");
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	buffer_size = FBA_SIZE(1);
	ASSERT(buffer_size < INT32_MAX);
	buffer = kmem_alloc(buffer_size, KM_SLEEP);

	for (i = 0; i < buffer_size; i++) {
		buffer[i] = pattern;
	}

	rc = nsc_maxfbas(krdc->bitmapfd, 0, &maxfbas);
	if (!RDC_SUCCESS(rc)) {
#ifdef DEBUG
		cmn_err(CE_WARN,
			"rdc_write_bitmap_pattern: maxfbas failed (%d)", rc);
#endif
		maxfbas = 256;
	}

	fba_req = FBA_LEN(krdc->bitmap_size);	/* total FBAs left to copy */
	fba_pos = RDC_BITMAP_FBA;		/* current FBA position */
	tocopy = krdc->bitmap_size;		/* total bytes left to copy */
loop:
	h = NULL;
	fba_len = min(fba_req, maxfbas);	/* FBAs to alloc this time */

	rc = nsc_alloc_buf(krdc->bitmapfd, fba_pos, fba_len, rdc_wrflag, &h);
	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "rdc_write_bitmap_pattern: %s write failed %d",
		    urdc->primary.file, rc);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "nsc_alloc_buf failed");
		if (h) {
			(void) nsc_free_handle(h);
		}

		_rdc_rlse_devs(krdc, RDC_BMP);
		mutex_exit(&krdc->bmapmutex);
		rc = -1;
		goto finish;
	}

				/* bytes to copy this time */
	len = min(tocopy, FBA_SIZE(fba_len));
	v = h->sb_vec;
	off = 0;

	while (len) {
		if (off >= v->sv_len) {
			off = 0;
			v++;
		}

		if (v->sv_addr == 0 || v->sv_len == 0) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "rdc_write_bitmap_pattern: ran off end of handle");
#endif
			break;
		}

		iolen = (size_t)min(len, buffer_size);

		bcopy(buffer, (char *)(v->sv_addr + off), iolen);
		off += iolen;
		len -= iolen;
	}

	rc = nsc_write(h, h->sb_pos, h->sb_len, 0);
	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "rdc_write_bitmap_pattern: %s write failed %d",
		    urdc->primary.file, rc);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "write failed");
		(void) nsc_free_buf(h);
		_rdc_rlse_devs(krdc, RDC_BMP);
		mutex_exit(&krdc->bmapmutex);
		rc = -1;
		goto finish;
	}

	(void) nsc_free_buf(h);

	fba_pos += fba_len;
	fba_req -= fba_len;
	tocopy -= FBA_SIZE(fba_len);    /* adjust byte length remaining */
	if (fba_req > 0)
		goto loop;

	_rdc_rlse_devs(krdc, RDC_BMP);
	mutex_exit(&krdc->bmapmutex);
	rc = 0;
finish:
	kmem_free(buffer, buffer_size);
	return (rc);
}


/*
 * rdc_write_bitmap_fill()
 *
 * Write a bitmap full of 1's out to disk without touching the
 * in-memory bitmap.
 */
int
rdc_write_bitmap_fill(rdc_k_info_t *krdc)
{
	return (rdc_write_bitmap_pattern(krdc, 0xff));
}


void
rdc_merge_bitmaps(rdc_k_info_t *src, rdc_k_info_t *dst)
{
	if (src->dcio_bitmap == NULL || dst->dcio_bitmap == NULL)
		return;

	rdc_lor(src->dcio_bitmap, dst->dcio_bitmap,
	    min(src->bitmap_size, dst->bitmap_size));
	if (dst->bitmap_write > 0)
		(void) rdc_write_bitmap(dst);
}


/*
 * bitmap size in bytes, vol_size fba's
 */

size_t
rdc_ref_size_possible(nsc_size_t bitmap_size, nsc_size_t vol_size)
{
	nsc_size_t ref_size;
	nsc_size_t bitmap_end_fbas;

	bitmap_end_fbas = RDC_BITMAP_FBA + FBA_LEN(bitmap_size);
	ref_size = FBA_LEN(bitmap_size * BITS_IN_BYTE *
			sizeof (unsigned char));
	if (bitmap_end_fbas + ref_size > vol_size)
		return ((size_t)0);

	ref_size = FBA_LEN(bitmap_size * BITS_IN_BYTE *
			sizeof (unsigned int));
	if (bitmap_end_fbas + ref_size > vol_size)
		return (sizeof (unsigned char));
	return (sizeof (unsigned int));
}

int
rdc_move_bitmap(rdc_k_info_t *krdc, char *newbitmap)
{
	rdc_u_info_t *urdc;
	nsc_fd_t *oldfd;
	nsc_fd_t *newfd = NULL;
	rdc_header_t header;
	int sts;
	nsc_size_t vol_size;
	nsc_size_t req_size;
	size_t ref_size;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_move_bitmap: NULL krdc");
#endif
		return (-1);
	}

	if (krdc->bitmapfd == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_move_bitmap: NULL bitmapfd");
#endif
		return (-1);
	}

	req_size = RDC_BITMAP_FBA + FBA_LEN(krdc->bitmap_size);
	if (RDC_IS_DISKQ(krdc->group)) {
		/* new volume must support at least the old refcntsize */
		req_size += FBA_LEN(krdc->bitmap_size * BITS_IN_BYTE *
			rdc_refcntsize(krdc));
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
	}

	mutex_enter(&krdc->bmapmutex);

	if (rdc_read_header(krdc, &header) < 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_move_bitmap: Read old header failed");
#endif
		mutex_exit(&krdc->bmapmutex);
		return (-1);
	}

	oldfd = krdc->bitmapfd;

	newfd = nsc_open(newbitmap, NSC_RDCHR_ID|NSC_FILE|NSC_RDWR, 0, 0, 0);
	if (newfd == NULL) {
		newfd = nsc_open(newbitmap,
		    NSC_RDCHR_ID|NSC_CACHE|NSC_DEVICE|NSC_RDWR, 0, 0, 0);
		if (newfd == NULL) {
			/* Can't open new bitmap */
			cmn_err(CE_WARN,
			    "rdc_move_bitmap: Cannot open new bitmap %s",
			    newbitmap);
			goto fail;
		}
	}

	sts = nsc_reserve(newfd, 0);
	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_move_bitmap: Reserve failed for %s",
		    newbitmap);
		goto fail;
	}
	sts = nsc_partsize(newfd, &vol_size);
	nsc_release(newfd);

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN,
		    "rdc_move_bitmap: nsc_partsize failed for %s", newbitmap);
		goto fail;
	}

	ref_size = rdc_ref_size_possible(krdc->bitmap_size, vol_size);

	if (vol_size < req_size) {
		cmn_err(CE_WARN,
		    "rdc_move_bitmap: bitmap %s too small: %" NSC_SZFMT
		    " vs %" NSC_SZFMT " blocks", newbitmap, vol_size, req_size);
		goto fail;
	}

	mutex_enter(&krdc->devices->id_rlock);
	krdc->bitmapfd = newfd;			/* swap under lock */
	if (krdc->bmaprsrv > 0) {
		sts = nsc_reserve(krdc->bitmapfd, 0);
		if (!RDC_SUCCESS(sts)) {
			krdc->bitmapfd = oldfd;	/* replace under lock */
			mutex_exit(&krdc->devices->id_rlock);
			cmn_err(CE_WARN,
			    "rdc_move_bitmap: Reserve failed for %s",
			    newbitmap);
			goto fail;
		}
	}
	rdc_set_refcnt_ops(krdc, ref_size);
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
	mutex_exit(&krdc->devices->id_rlock);

	/* Forget newfd now it is krdc->bitmapfd */
	newfd = NULL;

	/* Put new bitmap name into header and user-visible data structure */
	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		(void) strncpy(header.primary.bitmap, newbitmap, NSC_MAXPATH);
		(void) strncpy(urdc->primary.bitmap, newbitmap, NSC_MAXPATH);
	} else {
		(void) strncpy(header.secondary.bitmap, newbitmap, NSC_MAXPATH);
		(void) strncpy(urdc->secondary.bitmap, newbitmap, NSC_MAXPATH);
	}

	if (rdc_write_header(krdc, &header) < 0) {
		cmn_err(CE_WARN,
		    "rdc_move_bitmap: Write header %s failed", newbitmap);
		goto fail;
	}

	mutex_exit(&krdc->bmapmutex);

	if (rdc_write_bitmap(krdc) < 0) {
		mutex_enter(&krdc->bmapmutex);
		cmn_err(CE_WARN,
		    "rdc_move_bitmap: Write bitmap %s failed", newbitmap);
		goto fail;
	}

	/* Unintercept the old bitmap */
	if (krdc->b_tok) {
		int rc;

		rdc_group_exit(krdc);
		rc = nsc_unregister_path(krdc->b_tok, 0);
		if (rc)
			cmn_err(CE_WARN,
			    "rdc_move_bitmap: unregister bitmap failed %d", rc);
		else
			krdc->b_tok = nsc_register_path(newbitmap,
			    NSC_CACHE | NSC_DEVICE, _rdc_io_hc);
		rdc_group_enter(krdc);
	}

	/* clear the old bitmap header */
	bzero(&header, sizeof (header));

	sts = nsc_held(oldfd) ? 0 : nsc_reserve(oldfd, 0);
	if (sts == 0) {

		if (krdc->bmp_kstats) {
			mutex_enter(krdc->bmp_kstats->ks_lock);
			kstat_runq_enter(KSTAT_IO_PTR(krdc->bmp_kstats));
			mutex_exit(krdc->bmp_kstats->ks_lock);
		}

		sts = rdc_ns_io(oldfd, rdc_wrflag, 0,
		    (uchar_t *)&header, sizeof (header));

		if (krdc->bmp_kstats) {
			mutex_enter(krdc->bmp_kstats->ks_lock);
			kstat_runq_exit(KSTAT_IO_PTR(krdc->bmp_kstats));
			mutex_exit(krdc->bmp_kstats->ks_lock);
			KSTAT_IO_PTR(krdc->bmp_kstats)->writes++;
			KSTAT_IO_PTR(krdc->bmp_kstats)->nwritten +=
				sizeof (header);
		}

	}
#ifdef DEBUG
	if (sts != 0) {
		cmn_err(CE_WARN,
		    "rdc_move_bitmap: unable to clear bitmap header on %s",
		    nsc_pathname(oldfd));
	}
#endif

	/* nsc_close will undo any reservation */
	if (nsc_close(oldfd) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_move_bitmap: close of old bitmap failed");
#else
		;
		/*EMPTY*/
#endif
	}

	return (0);

fail:
	/* Close newfd if it was unused */
	if (newfd && newfd != krdc->bitmapfd) {
		(void) nsc_close(newfd);
		newfd = NULL;
	}

	mutex_exit(&krdc->bmapmutex);
	return (-1);
}


void
rdc_close_bitmap(rdc_k_info_t *krdc)
{

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_close_bitmap: NULL krdc");
#endif
		return;
	}

	mutex_enter(&krdc->bmapmutex);

	if (krdc->bitmapfd) {
		if (nsc_close(krdc->bitmapfd) != 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "nsc_close on bitmap failed");
#else
			;
			/*EMPTY*/
#endif
		}
		krdc->bitmapfd = 0;
	}

	mutex_exit(&krdc->bmapmutex);
}

void
rdc_free_bitmap(rdc_k_info_t *krdc, int cmd)
{
	rdc_header_t header;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_free_bitmap: NULL krdc");
#endif
		return;
	}

	mutex_enter(&krdc->bmapmutex);

	if (cmd != RDC_CMD_SUSPEND) {

		bzero((char *)&header, sizeof (rdc_header_t));

		if (krdc->bitmapfd)
			(void) rdc_write_header(krdc, &header);
	} else {
		mutex_exit(&krdc->bmapmutex);
		/* gotta drop mutex, in case q needs to fail */
		if (RDC_IS_DISKQ(krdc->group) && rdc_suspend_diskq(krdc) < 0) {
			cmn_err(CE_WARN,
			    "rdc_free_bitmap: diskq suspend failed");
		}

		mutex_enter(&krdc->bmapmutex);
		if (rdc_read_header(krdc, &header) < 0) {
			cmn_err(CE_WARN,
			    "rdc_free_bitmap: Read header failed");
		} else {
			rdc_fill_header(urdc, &header);

			(void) rdc_write_header(krdc, &header);
		}
	}

	mutex_exit(&krdc->bmapmutex);

	if (krdc->dcio_bitmap != NULL) {
		if (cmd == RDC_CMD_SUSPEND) {
			if (krdc->bitmapfd)
				(void) rdc_write_bitmap(krdc);
		}

		kmem_free(krdc->dcio_bitmap, krdc->bitmap_size);
		krdc->dcio_bitmap = NULL;
	}
	if (krdc->bitmap_ref != NULL) {
		kmem_free(krdc->bitmap_ref, (krdc->bitmap_size * BITS_IN_BYTE *
		    BMAP_REF_PREF_SIZE));
		krdc->bitmap_ref = NULL;
	}

	krdc->bitmap_size = 0;
}

static int
rdc_alloc_bitmap(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	char *bitmapname;
	nsc_size_t bitmap_ref_size;

	if (krdc == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "rdc_alloc_bitmap: NULL krdc");
#endif
		return (-1);
	}

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_PRIMARY)
		bitmapname = &urdc->primary.bitmap[0];
	else
		bitmapname = &urdc->secondary.bitmap[0];

	if (krdc->dcio_bitmap) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_alloc_bitmap: bitmap %s already allocated",
		    bitmapname);
#endif
		return (0);
	}

	if (urdc->volume_size == 0)
		return (-1);

	krdc->bitmap_size = BMAP_LOG_BYTES(urdc->volume_size);
	/* Round up */
	krdc->bitmap_size = (krdc->bitmap_size + 511) / 512 * 512;

	krdc->dcio_bitmap = (uchar_t *)kmem_zalloc(krdc->bitmap_size,
	    KM_SLEEP);
	if (krdc->dcio_bitmap == NULL) {
		cmn_err(CE_WARN, "rdc_alloc_bitmap: alloc %" NSC_SZFMT
		    " failed for %s", krdc->bitmap_size, bitmapname);
		return (-1);
	}

	/*
	 * use largest ref count type size as we haven't opened the bitmap
	 * volume yet to find out what has acutally be used.
	 */
	bitmap_ref_size = krdc->bitmap_size * BITS_IN_BYTE * BMAP_REF_PREF_SIZE;
	if ((rdc_get_vflags(urdc) & RDC_PRIMARY) &&
	    ((krdc->type_flag & RDC_ASYNCMODE) != 0)) {
		krdc->bitmap_ref = (uchar_t *)kmem_zalloc(bitmap_ref_size,
		    KM_SLEEP);
		if (krdc->bitmap_ref == NULL) {
			cmn_err(CE_WARN,
			    "rdc_alloc_bitmap: ref alloc %" NSC_SZFMT
			    " failed for %s",
			    bitmap_ref_size, bitmapname);
			return (-1);
		}
	}

	return (0);
}


static int
rdc_open_bitmap(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	int sts;
	uint_t hints = 0;
	nsc_size_t vol_size;
	char *bitmapname;
	nsc_size_t req_size;
	nsc_size_t bit_size;

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_PRIMARY)
		bitmapname = &urdc->primary.bitmap[0];
	else
		bitmapname = &urdc->secondary.bitmap[0];

	urdc->bits_set = 0;

	bit_size = req_size = RDC_BITMAP_FBA + FBA_LEN(krdc->bitmap_size);
	if (RDC_IS_DISKQ(krdc->group)) {
		req_size += FBA_LEN(krdc->bitmap_size * BITS_IN_BYTE *
		    sizeof (unsigned char));
	}

	mutex_enter(&krdc->bmapmutex);

	rdc_set_refcnt_ops(krdc, sizeof (unsigned char));
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
	if (krdc->bitmapfd == NULL)
		krdc->bitmapfd = nsc_open(bitmapname,
		    NSC_RDCHR_ID|NSC_FILE|NSC_RDWR, 0, 0, 0);
	if (krdc->bitmapfd == NULL) {
		krdc->bitmapfd = nsc_open(bitmapname,
		    NSC_RDCHR_ID|NSC_CACHE|NSC_DEVICE|NSC_RDWR, 0, 0, 0);
		if (krdc->bitmapfd == NULL) {
			cmn_err(CE_WARN, "rdc_open_bitmap: Unable to open %s",
			    bitmapname);
			goto fail;
		}
	}

	sts = _rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL);
	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN, "rdc_open_bitmap: Reserve failed for %s",
		    bitmapname);
		goto fail;
	}
	sts = nsc_partsize(krdc->bitmapfd, &vol_size);
	_rdc_rlse_devs(krdc, RDC_BMP);

	if (!RDC_SUCCESS(sts)) {
		cmn_err(CE_WARN,
		    "rdc_open_bitmap: nsc_partsize failed for %s", bitmapname);
		goto fail;
	}

	if (vol_size < req_size) {
		/* minimum size supports unsigned char reference counts */
		cmn_err(CE_WARN,
		    "rdc_open_bitmap: bitmap %s too small: %" NSC_SZFMT " vs %"
		    NSC_SZFMT "blocks",
		    bitmapname, vol_size, req_size);
		goto fail;
	}

	if (rdc_bitmap_mode == RDC_BMP_NEVER) {
		krdc->bitmap_write = 0;		/* forced off */
	} else if (rdc_bitmap_mode == RDC_BMP_ALWAYS ||
	    (nsc_node_hints(&hints) == 0 && (hints & NSC_FORCED_WRTHRU) == 0)) {
		krdc->bitmap_write = 1;		/* forced or autodetect on */
	} else {
		/* autodetect off */
		krdc->bitmap_write = 0;
	}

	mutex_exit(&krdc->bmapmutex);
	if (RDC_IS_DISKQ(krdc->group) && (rdc_refcntsize(krdc) <
	    BMAP_REF_PREF_SIZE)) {
		/* test for larger ref counts */
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
		req_size = bit_size;
		req_size += FBA_LEN(krdc->bitmap_size * BITS_IN_BYTE *
		    sizeof (unsigned int));
		if (vol_size >= req_size)
			rdc_set_refcnt_ops(krdc, sizeof (unsigned int));
	}
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
	return (0);

fail:
	mutex_exit(&krdc->bmapmutex);
	return (-1);
}

int
rdc_enable_bitmap(rdc_k_info_t *krdc, int set)
{
	rdc_header_t header;
	rdc_u_info_t *urdc;
	char *bitmapname;

	urdc = &rdc_u_info[krdc->index];

	if (rdc_alloc_bitmap(krdc) < 0)
		goto fail;

	if (rdc_open_bitmap(krdc) < 0)
		goto fail;

	if (rdc_get_vflags(urdc) & RDC_PRIMARY)
		bitmapname = &urdc->primary.bitmap[0];
	else
		bitmapname = &urdc->secondary.bitmap[0];

	mutex_enter(&krdc->bmapmutex);

	rdc_clr_flags(urdc, RDC_BMP_FAILED);
	if (rdc_read_header(krdc, &header) < 0) {
		cmn_err(CE_WARN,
		    "rdc_enable_bitmap: Read header %s failed", bitmapname);
		mutex_exit(&krdc->bmapmutex);
		goto fail;
	}

	rdc_fill_header(urdc, &header);
	rdc_set_refcnt_ops(krdc, (size_t)header.refcntsize);

	if (set)
		(void) RDC_FILL_BITMAP(krdc, FALSE);

	if (rdc_write_header(krdc, &header) < 0) {
		cmn_err(CE_WARN,
		    "rdc_enable_bitmap: Write header %s failed",
		    bitmapname);
		mutex_exit(&krdc->bmapmutex);
		goto fail;
	}
	mutex_exit(&krdc->bmapmutex);

	if (rdc_write_bitmap(krdc) < 0) {
		cmn_err(CE_WARN,
		    "rdc_enable_bitmap: Write bitmap %s failed",
		    bitmapname);
		goto fail;
	}

	return (0);

fail:
	rdc_free_bitmap(krdc, RDC_CMD_ENABLE);
	rdc_close_bitmap(krdc);

	mutex_enter(&krdc->bmapmutex);
	rdc_set_flags_log(urdc, RDC_BMP_FAILED, "I/O failed");
	mutex_exit(&krdc->bmapmutex);
	return (-1);
}

static int
_rdc_rdwr_refcnt(rdc_k_info_t *krdc, int rwflg)
{
	rdc_u_info_t *urdc;
	int rc;
	nsc_off_t offset;
	nsc_size_t len;

	urdc = &rdc_u_info[krdc->index];

#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "rdc_rdwr_refcnt: %s refcount for %s",
	    (rwflg == NSC_READ) ? "resuming" : "writing",
	    urdc->primary.bitmap);
#endif
	ASSERT(MUTEX_HELD(QLOCK((&krdc->group->diskq))));
	mutex_enter(&krdc->bmapmutex);

	if (_rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL)) {
		cmn_err(CE_WARN, "rdc_rdwr_refcnt: reserve failed");
		goto fail;
	}

	if (krdc->bitmap_size == 0) {
		cmn_err(CE_WARN, "rdc_rdwr_refcnt: NULL bitmap!");
		goto fail;
	}

	offset = RDC_BITREF_FBA(krdc);
	len = krdc->bitmap_size * BITS_IN_BYTE * rdc_refcntsize(krdc);

	rc = rdc_ns_io(krdc->bitmapfd, rwflg, offset,
	    (uchar_t *)krdc->bitmap_ref, len);

	if (!RDC_SUCCESS(rc)) {
		cmn_err(CE_WARN, "unable to %s refcount from bitmap %s",
		    (rwflg == NSC_READ) ? "retrieve" : "write",
		    urdc->primary.bitmap);
		rdc_set_flags_log(urdc, RDC_BMP_FAILED, "refcount I/O failed");
		goto fail;
	}

	_rdc_rlse_devs(krdc, RDC_BMP);

	mutex_exit(&krdc->bmapmutex);

#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "rdc_rdwr_refcnt: %s refcount for %s",
	    (rwflg == NSC_READ) ? "resumed" : "wrote",
	    urdc->primary.bitmap);
#endif
	return (0);

	fail:
	_rdc_rlse_devs(krdc, RDC_BMP);

	mutex_exit(&krdc->bmapmutex);

	return (-1);

}

/*
 * rdc_read_refcount
 * read the stored refcount from disk
 * queue lock is held
 */
int
rdc_read_refcount(rdc_k_info_t *krdc)
{
	int	rc;

	rc = _rdc_rdwr_refcnt(krdc, NSC_READ);

	return (rc);
}

/*
 * rdc_write_refcount
 * writes krdc->bitmap_ref to the diskq
 * called with qlock held
 */
int
rdc_write_refcount(rdc_k_info_t *krdc)
{
	int	rc;

	rc = _rdc_rdwr_refcnt(krdc, NSC_WRBUF);

	return (rc);
}

static int
rdc_resume_state(rdc_k_info_t *krdc, const rdc_header_t *header)
{
	rdc_u_info_t *urdc;
	char *bitmapname;

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_PRIMARY)
		bitmapname = &urdc->primary.bitmap[0];
	else
		bitmapname = &urdc->secondary.bitmap[0];

	if (header->magic != RDC_HDR_MAGIC) {
		cmn_err(CE_WARN, "rdc_resume_state: Bad magic in %s",
		    bitmapname);
		return (-1);
	}

	if (strncmp(urdc->primary.file, header->primary.file,
	    NSC_MAXPATH) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_resume_state: Found %s Expected %s",
		    header->primary.file, urdc->primary.file);
#endif /* DEBUG */
		return (-1);
	}

	if (strncmp(urdc->secondary.file, header->secondary.file,
	    NSC_MAXPATH) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_resume_state: Found %s Expected %s",
		    header->secondary.file, urdc->secondary.file);
#endif /* DEBUG */
		return (-1);
	}

	if (strncmp(urdc->primary.bitmap, header->primary.bitmap,
	    NSC_MAXPATH) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_resume_state: Found %s Expected %s",
		    header->primary.bitmap, urdc->primary.bitmap);
#endif /* DEBUG */
		return (-1);
	}

	if (strncmp(urdc->secondary.bitmap, header->secondary.bitmap,
	    NSC_MAXPATH) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_resume_state: Found %s Expected %s",
		    header->secondary.bitmap, urdc->secondary.bitmap);
#endif /* DEBUG */
		return (-1);
	}

	if (header->maxqfbas)
		urdc->maxqfbas = header->maxqfbas;

	if (header->maxqitems)
		urdc->maxqitems = header->maxqitems;

	if (header->autosync >= 0)
		urdc->autosync = header->autosync;

	if (header->asyncthr)
		urdc->asyncthr = header->asyncthr;

	rdc_many_enter(krdc);
	rdc_set_refcnt_ops(krdc, header->refcntsize);
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
	if (header->flags & RDC_VOL_FAILED)
		rdc_set_flags(urdc, RDC_VOL_FAILED);
	if (header->flags & RDC_QUEUING)
		rdc_set_flags(urdc, RDC_QUEUING);

	rdc_clr_flags(urdc, RDC_SYNC_NEEDED | RDC_RSYNC_NEEDED);
	rdc_set_mflags(urdc, (header->flags & RDC_RSYNC_NEEDED));
	rdc_set_flags(urdc, (header->flags & RDC_SYNC_NEEDED));
	rdc_many_exit(krdc);

	if (urdc->flags & RDC_VOL_FAILED) {

		/* Our disk was failed so set all the bits in the bitmap */

		if (RDC_FILL_BITMAP(krdc, TRUE) != 0) {
			cmn_err(CE_WARN,
			    "rdc_resume_state: Fill bitmap %s failed",
			    bitmapname);
			return (-1);
		}
		rdc_many_enter(krdc);
		if (IS_STATE(urdc, RDC_QUEUING))
			rdc_clr_flags(urdc, RDC_QUEUING);
		rdc_many_exit(krdc);
	} else {
		/* Header was good, so read in the bitmap */

		if (rdc_read_bitmap(krdc, NULL) < 0) {
			cmn_err(CE_WARN,
			    "rdc_resume_state: Read bitmap %s failed",
			    bitmapname);
			return (-1);
		}

		urdc->bits_set = RDC_COUNT_BITMAP(krdc);

		/*
		 * Check if another node went down with bits set, but
		 * without setting logging mode.
		 */
		if (urdc->bits_set != 0 &&
		    (rdc_get_vflags(urdc) & RDC_ENABLED) &&
		    !(rdc_get_vflags(urdc) & RDC_LOGGING)) {
			rdc_group_log(krdc, RDC_NOFLUSH | RDC_NOREMOTE, NULL);
		}
	}

	/* if we are using a disk queue, read in the reference count bits */
	if (RDC_IS_DISKQ(krdc->group)) {
		disk_queue *q = &krdc->group->diskq;
		mutex_enter(QLOCK(q));
		if ((rdc_read_refcount(krdc) < 0)) {
			cmn_err(CE_WARN,
			    "rdc_resume_state: Resume bitmap %s's refcount"
			    "failed",
			    urdc->primary.bitmap);
			mutex_exit(QLOCK(q));
			rdc_many_enter(krdc);
			if (IS_STATE(urdc, RDC_QUEUING))
				rdc_clr_flags(urdc, RDC_QUEUING);
			rdc_many_exit(krdc);
			return (-1);
		}
		mutex_exit(QLOCK(q));
	}

	return (0);
}


int
rdc_resume_bitmap(rdc_k_info_t *krdc)
{
	rdc_header_t header;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	char *bitmapname;

	if (rdc_alloc_bitmap(krdc) < 0)
		goto allocfail;

	if (rdc_open_bitmap(krdc) < 0)
		goto fail;

	if (rdc_get_vflags(urdc) & RDC_PRIMARY)
		bitmapname = &urdc->primary.bitmap[0];
	else
		bitmapname = &urdc->secondary.bitmap[0];

	mutex_enter(&krdc->bmapmutex);

	rdc_clr_flags(urdc, RDC_BMP_FAILED);
	if (rdc_read_header(krdc, &header) < 0) {
		cmn_err(CE_WARN,
		    "rdc_resume_bitmap: Read header %s failed", bitmapname);
		mutex_exit(&krdc->bmapmutex);
		goto fail;
	}

	mutex_exit(&krdc->bmapmutex);

	/* Resuming from the bitmap, so do some checking */

	/*CONSTCOND*/
	ASSERT(FBA_LEN(sizeof (rdc_header_t)) <= RDC_BITMAP_FBA);
	/*CONSTCOND*/
	ASSERT(sizeof (rdc_header_t) >= sizeof (rdc_headerv2_t));

	if (header.magic == RDC_HDR_V2) {
		rdc_headerv2_t *hdr_v2 = (rdc_headerv2_t *)&header;
		rdc_header_t new_header;

#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_resume_bitmap: Converting v2 header for bitmap %s",
		    bitmapname);
#endif
		bzero((char *)&new_header, sizeof (rdc_header_t));

		new_header.autosync = -1;
		new_header.magic = RDC_HDR_MAGIC;
		new_header.syshostid = urdc->syshostid;

		if (hdr_v2->volume_failed)
			new_header.flags |= RDC_VOL_FAILED;
		if (hdr_v2->sync_needed == RDC_SYNC)
			new_header.flags |= RDC_SYNC_NEEDED;
		if (hdr_v2->sync_needed == RDC_FULL_SYNC)
			new_header.flags |= RDC_SYNC_NEEDED;
		if (hdr_v2->sync_needed == RDC_REV_SYNC)
			new_header.flags |= RDC_RSYNC_NEEDED;
		if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
			(void) strncpy(new_header.primary.file,
			    hdr_v2->filename, NSC_MAXPATH);
			(void) strncpy(new_header.primary.bitmap,
			    hdr_v2->bitmapname, NSC_MAXPATH);
			(void) strncpy(new_header.secondary.file,
			    urdc->secondary.file, NSC_MAXPATH);
			(void) strncpy(new_header.secondary.bitmap,
			    urdc->secondary.bitmap, NSC_MAXPATH);
		} else {
			(void) strncpy(new_header.secondary.file,
			    hdr_v2->filename, NSC_MAXPATH);
			(void) strncpy(new_header.secondary.bitmap,
			    hdr_v2->bitmapname, NSC_MAXPATH);
			(void) strncpy(new_header.primary.file,
			    urdc->primary.file, NSC_MAXPATH);
			(void) strncpy(new_header.primary.bitmap,
			    urdc->primary.bitmap, NSC_MAXPATH);
		}

		bcopy(&new_header, &header, sizeof (rdc_header_t));

		mutex_enter(&krdc->bmapmutex);
		if (rdc_write_header(krdc, &header) < 0) {
			mutex_exit(&krdc->bmapmutex);
			cmn_err(CE_WARN,
			    "rdc_resume_bitmap: Write header %s failed",
			    bitmapname);
			goto fail;
		}
		mutex_exit(&krdc->bmapmutex);

	} else if (header.magic == RDC_HDR_V3) {
		/*
		 * just update asyncthr and magic, and then we're done
		 */
		header.magic = RDC_HDR_MAGIC;
		header.asyncthr = RDC_ASYNCTHR;
		mutex_enter(&krdc->bmapmutex);
		if (rdc_write_header(krdc, &header) < 0) {
			mutex_exit(&krdc->bmapmutex);
			cmn_err(CE_WARN,
			    "rdc_resume_bitmap: Write header %s failed",
			    bitmapname);
			goto fail;
		}
		mutex_exit(&krdc->bmapmutex);
	}

	if (rdc_resume_state(krdc, &header) == 0)
		return (0);

	rdc_close_bitmap(krdc);

fail:
	(void) RDC_FILL_BITMAP(krdc, FALSE);
	rdc_clr_flags(urdc, RDC_QUEUING);
	if (krdc->bitmap_ref)
		bzero(krdc->bitmap_ref, krdc->bitmap_size * BITS_IN_BYTE *
		    rdc_refcntsize(krdc));

allocfail:
	mutex_enter(&krdc->bmapmutex);
	rdc_set_flags_log(urdc, RDC_BMP_FAILED, "resume bitmap failed");
	mutex_exit(&krdc->bmapmutex);

	return (-1);
}

void
rdc_std_zero_bitref(rdc_k_info_t *krdc)
{
	nsc_size_t vol_size;
	int sts;
	size_t newrefcntsize;

	if (krdc->bitmap_ref) {
		mutex_enter(&krdc->bmapmutex);
		bzero(krdc->bitmap_ref, krdc->bitmap_size * BITS_IN_BYTE *
		    BMAP_REF_PREF_SIZE);
		if (RDC_IS_DISKQ(krdc->group) && rdc_refcntsize(krdc) !=
		    BMAP_REF_PREF_SIZE) {
			/* see if we can upgrade the size of the ref counters */
#ifdef DEBUG_REFCNT
			cmn_err(CE_NOTE, "sndr: check for new refcount size");
#endif
			sts = _rdc_rsrv_devs(krdc, RDC_BMP, RDC_INTERNAL);
			if (!RDC_SUCCESS(sts)) {
				goto nochange;
			}
			sts = nsc_partsize(krdc->bitmapfd, &vol_size);

			newrefcntsize = rdc_ref_size_possible(krdc->bitmap_size,
				vol_size);
			if (newrefcntsize > rdc_refcntsize(krdc)) {
				rdc_set_refcnt_ops(krdc, newrefcntsize);
#ifdef DEBUG_REFCNT
	cmn_err(CE_NOTE, "sndr:	refcntsize %d - %d:%s",
		(int)rdc_refcntsize(krdc), __LINE__, __FILE__);
#endif
			}
nochange:
			_rdc_rlse_devs(krdc, RDC_BMP);
		}
		mutex_exit(&krdc->bmapmutex);
	}
}

int
rdc_reset_bitmap(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc;
	rdc_header_t header;
	char *bitmapname;

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_PRIMARY)
		bitmapname = &urdc->primary.bitmap[0];
	else
		bitmapname = &urdc->secondary.bitmap[0];

	mutex_enter(&krdc->bmapmutex);

	rdc_clr_flags(urdc, RDC_BMP_FAILED);
	if (rdc_read_header(krdc, &header) < 0) {
		cmn_err(CE_WARN,
		    "rdc_reset_bitmap: Read header %s failed", bitmapname);
		goto fail_with_mutex;
	}

	rdc_fill_header(urdc, &header);

	if (rdc_write_header(krdc, &header) < 0) {
		cmn_err(CE_WARN,
		    "rdc_reset_bitmap: Write header %s failed",
		    bitmapname);
		goto fail_with_mutex;
	}
	mutex_exit(&krdc->bmapmutex);

	if (krdc->bitmap_write == -1)
		krdc->bitmap_write = 0;

	if (krdc->bitmap_write == 0) {
		if (rdc_write_bitmap_fill(krdc) < 0) {
			cmn_err(CE_WARN,
			    "rdc_reset_bitmap: Write bitmap %s failed",
			    bitmapname);
			goto fail;
		}
		krdc->bitmap_write = -1;
	} else if (rdc_write_bitmap(krdc) < 0) {
		cmn_err(CE_WARN,
		    "rdc_reset_bitmap: Write bitmap %s failed",
		    bitmapname);
		goto fail;
	}

	return (0);

fail:
	mutex_enter(&krdc->bmapmutex);
fail_with_mutex:
	rdc_set_flags_log(urdc, RDC_BMP_FAILED, "reset failed");
	mutex_exit(&krdc->bmapmutex);
#ifdef DEBUG
	cmn_err(CE_NOTE, "SNDR: unable to reset bitmap for %s:%s",
		urdc->secondary.intf, urdc->secondary.file);
#endif
	return (-1);
}


/*
 * General bitmap operations
 */

/*
 * rdc_set_bitmap_many()
 *
 * Used during reverse syncs to a 1-to-many primary to keep the 'many'
 * bitmaps up to date.
 */
void
rdc_set_bitmap_many(rdc_k_info_t *krdc, nsc_off_t pos, nsc_size_t len)
{
	uint_t dummy;

#ifdef DEBUG
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	if (!(rdc_get_vflags(urdc) & RDC_PRIMARY)) {
		cmn_err(CE_PANIC, "rdc_set_bitmap_many: not primary, urdc %p",
		    (void *) urdc);
	}
#endif

	if (IS_MANY(krdc)) {
		rdc_k_info_t *krd;
		rdc_u_info_t *urd;

		rdc_many_enter(krdc);

		for (krd = krdc->many_next; krd != krdc; krd = krd->many_next) {
			urd = &rdc_u_info[krd->index];
			if (!IS_ENABLED(urd))
				continue;
			ASSERT(urd->flags & RDC_PRIMARY);
			(void) RDC_SET_BITMAP(krd, pos, len, &dummy);
		}

		rdc_many_exit(krdc);
	}
}


static int
_rdc_net_bmap(const struct bmap6 *b6, net_bdata6 *bd6)
{
	rdc_k_info_t *krdc = &rdc_k_info[b6->cd];
	struct timeval t;
	int e, ret;
	uint64_t left;
	uint64_t bmap_blksize = krdc->rpc_version < RDC_VERSION7 ?
		BMAP_BLKSIZE : BMAP_BLKSIZEV7;

	t.tv_sec = rdc_rpc_tmout;
	t.tv_usec = 0;

	if (bd6->data.data_val == NULL) {
		return (EINVAL);
	}

	left = b6->size;
	bd6->endoblk = 0;
	while (left) {
		if (left >= bmap_blksize)
			bd6->size = (int)bmap_blksize;
		else
			bd6->size = (int)left;

		bd6->data.data_len = bd6->size;

		if ((uint64_t)bd6->size > left) {
			left = 0;
		} else {
			left -= bd6->size;
		}
		/*
		 * mark the last block sent.
		 */
		if (left == 0) {
			bd6->endoblk = 1;
		}
		ASSERT(krdc->rpc_version);
		if (krdc->rpc_version <= RDC_VERSION5) {
			struct net_bdata bd;
			bd.cd = bd6->cd;
			bd.offset = bd6->offset;
			bd.size = bd6->size;
			bd.data.data_len = bd6->data.data_len;
			bd.data.data_val = bd6->data.data_val;
			e = rdc_clnt_call(krdc->lsrv, RDCPROC_BDATA,
			    krdc->rpc_version, xdr_net_bdata, (char *)&bd,
			    xdr_int, (char *)&ret, &t);
		} else {
			e = rdc_clnt_call(krdc->lsrv, RDCPROC_BDATA6,
			    krdc->rpc_version, xdr_net_bdata6, (char *)bd6,
			    xdr_int, (char *)&ret, &t);
		}
		if (e || ret) {
			if (e)
				ret = e;
			return (ret);
		}
		bd6->offset += bmap_blksize;
		bd6->data.data_val += bmap_blksize;
	}
	return (0);
}


/*
 * Standard bitmap operations (combined kmem/disk bitmaps).
 */

/*
 * rdc_std_set_bitmask(pos, len, &bitmask)
 * set a bitmask for this range. used to clear the correct
 * bits after flushing
 */
static void
rdc_std_set_bitmask(const nsc_off_t fba_pos, const nsc_size_t fba_len,
    uint_t *bitmask)
{
	int first, st, en;
	if (bitmask)
		*bitmask = 0;
	else
		return;

	first = st = FBA_TO_LOG_NUM(fba_pos);
	en = FBA_TO_LOG_NUM(fba_pos + fba_len - 1);
	while (st <= en) {
		BMAP_BIT_SET((uchar_t *)bitmask, st - first);
		st++;
	}

}
/*
 * rdc_std_set_bitmap(krdc, fba_pos, fba_len, &bitmask)
 *
 * Mark modified segments in the dual copy file bitmap
 * to provide fast recovery
 * Note that bitmask allows for 32 segments, which at 32k per segment equals
 * 1 megabyte. If we ever allow more than this to be transferred in one
 * operation, or decrease the segment size, then this code will have to be
 * changed accordingly.
 */

static int
rdc_std_set_bitmap(rdc_k_info_t *krdc, const nsc_off_t fba_pos,
    const nsc_size_t fba_len, uint_t *bitmask)
{
	int first, st, en;
	int fbaset = 0;
	nsc_off_t fba = 0;
	int printerr = 10;
	int tries = RDC_FUTILE_ATTEMPTS;
	int queuing = RDC_QUEUING;
	rdc_u_info_t *urdc;

	if (bitmask)
		*bitmask = 0;
	else
		return (-1);

	urdc = &rdc_u_info[krdc->index];
	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED)
		return (-1);

	if (krdc->bitmap_write == 0) {
		if (rdc_write_bitmap_fill(krdc) < 0)
			return (-1);
		krdc->bitmap_write = -1;
	}
	first = st = FBA_TO_LOG_NUM(fba_pos);
	en = FBA_TO_LOG_NUM(fba_pos + fba_len - 1);
	ASSERT(st <= en);
	while (st <= en) {
		int use_ref;
again:
		mutex_enter(&krdc->bmapmutex);

		if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
		    cmn_err(CE_WARN,
			"rdc_std_set_bitmap: recovery bitmaps not allocated");
#endif
		    mutex_exit(&krdc->bmapmutex);
		    return (-1);
		}

		use_ref = IS_PRIMARY(urdc) && IS_ASYNC(urdc) &&
		    ((rdc_get_vflags(urdc) & RDC_QUEUING) ||
		    !(rdc_get_vflags(urdc) & RDC_LOGGING));


		if (!BMAP_BIT_ISSET(krdc->dcio_bitmap, st)) {
			BMAP_BIT_SET(krdc->dcio_bitmap, st);
			if (use_ref) {
				ASSERT(BMAP_REF_ISSET(krdc, st) ==
				    0);
				BMAP_REF_FORCE(krdc, st, 1);
			}
			BMAP_BIT_SET((uchar_t *)bitmask, st - first);
			urdc->bits_set++;
			if ((!fbaset) || fba != BIT_TO_FBA(st)) {
				if (fbaset && krdc->bitmap_write > 0) {
					mutex_exit(&krdc->bmapmutex);
					if (rdc_write_bitmap_fba(krdc, fba) < 0)
						return (-1);
					mutex_enter(&krdc->bmapmutex);
				}
				fba = BIT_TO_FBA(st);
				fbaset = 1;
			}
		} else {
		/*
		 * Just bump reference count
		 * For logging or syncing we do not care what the reference
		 * is as it will be forced back on the state transition.
		 */
			if (use_ref) {
				if (BMAP_REF_ISSET(krdc, st) ==
				    BMAP_REF_MAXVAL(krdc)) {
					/*
					 * Rollover of reference count.
					 */

					if (!(rdc_get_vflags(urdc) &
					    RDC_VOL_FAILED)) {
						/*
						 * Impose throttle to help dump
						 * queue
						 */
						mutex_exit(&krdc->bmapmutex);
						delay(4);
						rdc_bitmap_delay++;
						if (printerr--) {
	cmn_err(CE_WARN, "SNDR: bitmap reference count maxed out for %s:%s",
	    urdc->secondary.intf, urdc->secondary.file);

						}

						if ((tries-- <= 0) &&
						    IS_STATE(urdc, queuing)) {
	cmn_err(CE_WARN, "SNDR: giving up on reference count, logging set"
	    " %s:%s", urdc->secondary.intf, urdc->secondary.file);
							rdc_group_enter(krdc);
							rdc_group_log(krdc,
							    RDC_NOFLUSH |
							    RDC_NOREMOTE|
							    RDC_FORCE_GROUP,
					    "ref count retry limit exceeded");
							rdc_group_exit(krdc);
						}
						goto again;
					}
				} else {
					BMAP_REF_SET(krdc, st);
				}
			}
		}
		mutex_exit(&krdc->bmapmutex);
		st++;
	}
	if (fbaset && krdc->bitmap_write > 0) {
		if (rdc_write_bitmap_fba(krdc, fba) < 0)
			return (-1);
	}
	return (0);
}

static void
rdc_std_clr_bitmap(rdc_k_info_t *krdc, const nsc_off_t fba_pos,
    const nsc_size_t fba_len, const uint_t bitmask, const int force)
{
	int first, st, en;
	nsc_off_t fba = 0;
	int fbaset = 0;
	uint_t bm = bitmask;
	uchar_t *ptr = (uchar_t *)&bm;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];

	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED)
		return;

	first = st = FBA_TO_LOG_NUM(fba_pos);
	en = FBA_TO_LOG_NUM(fba_pos + fba_len - 1);
	ASSERT(st <= en);
	while (st <= en) {
		mutex_enter(&krdc->bmapmutex);

		if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
		    cmn_err(CE_WARN,
			"rdc_std_clr_bitmap: recovery bitmaps not allocated");
#endif
		    mutex_exit(&krdc->bmapmutex);
		    return;
		}

		if (((bitmask == 0xffffffff) ||
		    (BMAP_BIT_ISSET(ptr, st - first))) &&
		    BMAP_BIT_ISSET(krdc->dcio_bitmap, st)) {

			int use_ref = IS_PRIMARY(urdc) && IS_ASYNC(urdc) &&
			    ((rdc_get_vflags(urdc) & RDC_QUEUING) ||
			    !(rdc_get_vflags(urdc) & RDC_LOGGING));

			if (force || (use_ref == 0)) {
				if (krdc->bitmap_ref)
					BMAP_REF_FORCE(krdc, st, 0);
			} else if (use_ref) {
				if (BMAP_REF_ISSET(krdc, st) != 0)
					BMAP_REF_CLR(krdc, st);

			}

			if ((use_ref == 0) || (use_ref &&
			    !BMAP_REF_ISSET(krdc, st))) {
				BMAP_BIT_CLR(krdc->dcio_bitmap, st);

				urdc->bits_set--;
				if (!fbaset || fba != BIT_TO_FBA(st)) {
					if (fbaset &&
						krdc->bitmap_write > 0) {
						mutex_exit(&krdc->bmapmutex);
						if (rdc_write_bitmap_fba(krdc,
						    fba) < 0)
							return;
						mutex_enter(&krdc->bmapmutex);
					}
					fba = BIT_TO_FBA(st);
					fbaset = 1;
				}
			}
		}
		mutex_exit(&krdc->bmapmutex);
		st++;
	}
	if (fbaset && krdc->bitmap_write > 0) {
		if (rdc_write_bitmap_fba(krdc, fba) < 0)
			return;
	}
}

/*
 * make sure that this bit is set. if it isn't, set it
 * used when transitioning from async to sync while going
 * from rep to log. an overlapping sync write may unconditionally
 * clear the bit that has not been replicated. when the queue
 * is being dumped or this is called just to make sure pending stuff
 * is in the bitmap
 */
void
rdc_std_check_bit(rdc_k_info_t *krdc, nsc_off_t pos, nsc_size_t len)
{
	int st;
	int en;
	nsc_off_t fba;
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	st = FBA_TO_LOG_NUM(pos);
	en = FBA_TO_LOG_NUM(pos + len - 1);

	if (rdc_get_vflags(urdc) & RDC_BMP_FAILED)
		return;

	while (st <= en) {
		mutex_enter(&krdc->bmapmutex);

		if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
		    cmn_err(CE_WARN,
			"rdc_std_check_bit: recovery bitmaps not allocated");
#endif
		    mutex_exit(&krdc->bmapmutex);
		    return;
		}

		if (!BMAP_BIT_ISSET(krdc->dcio_bitmap, st)) {
			BMAP_BIT_SET(krdc->dcio_bitmap, st);
			if (krdc->bitmap_write > 0) {
				fba = BIT_TO_FBA(st);
				mutex_exit(&krdc->bmapmutex);
				(void) rdc_write_bitmap_fba(krdc, fba);
				mutex_enter(&krdc->bmapmutex);
			}
			urdc->bits_set++;

		}
		mutex_exit(&krdc->bmapmutex);
		st++;
	}

}

/*
 * rdc_std_count_dirty(krdc):
 *
 * Determine the number of segments that need to be flushed, This should
 * agree with the number of segments logged, but since we don't lock when
 * we increment, we force these values to agree
 */
static int
rdc_std_count_dirty(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int i, count, size;

	if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_std_count_dirty: no bitmap configured for %s",
		    urdc->primary.file);
#endif
		return (0);
	}

	count = 0;
	ASSERT(urdc->volume_size != 0);
	size = FBA_TO_LOG_LEN(urdc->volume_size);
	for (i = 0; i < size; i++)
		if (BMAP_BIT_ISSET(krdc->dcio_bitmap, i))
			count++;

	if (count > size)
		count = size;

	return (count);
}


static int
rdc_std_bit_isset(rdc_k_info_t *krdc, const int bit)
{
	return (BMAP_BIT_ISSET(krdc->dcio_bitmap, bit));
}


/*
 * rdc_std_fill_bitmap(krdc, write)
 *
 * Called to force bitmaps to a fully dirty state
 */
static int
rdc_std_fill_bitmap(rdc_k_info_t *krdc, const int write)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int i, size;

	if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_std_fill_bitmap: no bitmap configured for %s",
		    urdc->primary.file);
#endif
		return (-1);
	}

	ASSERT(urdc->volume_size != 0);
	size = FBA_TO_LOG_LEN(urdc->volume_size);
	for (i = 0; i < size; i++)
		BMAP_BIT_SET(krdc->dcio_bitmap, i);

	urdc->bits_set = size;

	if (write)
		return (rdc_write_bitmap(krdc));

	return (0);
}


/*
 * rdc_std_zero_bitmap(krdc)
 *
 * Called on the secondary after a sync has completed to force bitmaps
 * to a fully clean state
 */
static void
rdc_std_zero_bitmap(rdc_k_info_t *krdc)
{
	rdc_u_info_t *urdc = &rdc_u_info[krdc->index];
	int i, size;

	if (krdc->dcio_bitmap == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "rdc_std_zero_bitmap: no bitmap configured for %s",
		    urdc->primary.file);
#endif
		return;
	}
#ifdef DEBUG
	cmn_err(CE_NOTE, "Clearing bitmap for %s", urdc->secondary.file);
#endif

	ASSERT(urdc->volume_size != 0);
	size = FBA_TO_LOG_LEN(urdc->volume_size);
	for (i = 0; i < size; i++)
		BMAP_BIT_CLR(krdc->dcio_bitmap, i);
	if (krdc->bitmap_write > 0)
		(void) rdc_write_bitmap(krdc);

	urdc->bits_set = 0;
}


/*
 * rdc_std_net_bmap()
 *
 * WARNING acts as both client and server
 */
static int
rdc_std_net_bmap(const struct bmap6 *b)
{
	rdc_k_info_t *krdc = &rdc_k_info[b->cd];
	struct net_bdata6 bd;

	bd.data.data_val = (char *)krdc->dcio_bitmap;
	bd.cd = b->dual;
	bd.offset = 0;

	return (_rdc_net_bmap(b, &bd));
}


/*
 * rdc_std_net_bdata
 */
static int
rdc_std_net_bdata(const struct net_bdata6 *bd)
{
	rdc_k_info_t *krdc = &rdc_k_info[bd->cd];

	rdc_lor((uchar_t *)bd->data.data_val,
	    (uchar_t *)(((char *)krdc->dcio_bitmap) + bd->offset), bd->size);

	return (0);
}


static struct rdc_bitmap_ops rdc_std_bitmap_ops = {
	rdc_std_set_bitmap,
	rdc_std_clr_bitmap,
	rdc_std_count_dirty,
	rdc_std_bit_isset,
	rdc_std_fill_bitmap,
	rdc_std_zero_bitmap,
	rdc_std_net_bmap,
	rdc_std_net_bdata,
	rdc_std_zero_bitref,
	rdc_std_set_bitmask,
	rdc_std_check_bit
};


void
rdc_bitmap_init()
{
	rdc_bitmap_ops = &rdc_std_bitmap_ops;
	rdc_wrflag = NSC_WRITE;
}

static void
rdc_bmap_ref_byte_set(rdc_k_info_t *krdc, int ind)
{
	unsigned char *bmap = (unsigned char *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned char));
	bmap[ind]++;
}

static void
rdc_bmap_ref_byte_clr(rdc_k_info_t *krdc, int ind)
{
	unsigned char *bmap = (unsigned char *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned char));
	bmap[ind]--;
}

static unsigned int
rdc_bmap_ref_byte_isset(rdc_k_info_t *krdc, int ind)
{
	unsigned char *bmap = (unsigned char *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned char));
	return ((unsigned int)(bmap[ind]));
}

static void
rdc_bmap_ref_byte_force(rdc_k_info_t *krdc, int ind, unsigned int val)
{
	unsigned char *bmap = (unsigned char *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned char));
	bmap[ind] = (unsigned char) val;
}

/* ARGSUSED */
static unsigned int
rdc_bmap_ref_byte_maxval(rdc_k_info_t *krdc)
{
	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned char));
	return ((unsigned int)(UINT8_MAX));
}

struct bm_ref_ops rdc_ref_byte_ops = {
	rdc_bmap_ref_byte_set,
	rdc_bmap_ref_byte_clr,
	rdc_bmap_ref_byte_isset,
	rdc_bmap_ref_byte_force,
	rdc_bmap_ref_byte_maxval,
	sizeof (unsigned char)
};

static void
rdc_bmap_ref_int_set(rdc_k_info_t *krdc, int ind)
{
	unsigned int *bmap = (unsigned int *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned int));
	bmap[ind]++;
}

static void
rdc_bmap_ref_int_clr(rdc_k_info_t *krdc, int ind)
{
	unsigned int *bmap = (unsigned int *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned int));
	bmap[ind]--;
}

static unsigned int
rdc_bmap_ref_int_isset(rdc_k_info_t *krdc, int ind)
{
	unsigned int *bmap = (unsigned int *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned int));
	return ((bmap[ind]));
}

static void
rdc_bmap_ref_int_force(rdc_k_info_t *krdc, int ind, unsigned int val)
{
	unsigned int *bmap = (unsigned int *)krdc->bitmap_ref;

	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned int));
	bmap[ind] = val;
}

/* ARGSUSED */
static unsigned int
rdc_bmap_ref_int_maxval(rdc_k_info_t *krdc)
{
	ASSERT(BMAP_REF_SIZE(krdc) == sizeof (unsigned int));
	return ((unsigned int)(UINT_MAX));
}

struct bm_ref_ops rdc_ref_int_ops = {
	rdc_bmap_ref_int_set,
	rdc_bmap_ref_int_clr,
	rdc_bmap_ref_int_isset,
	rdc_bmap_ref_int_force,
	rdc_bmap_ref_int_maxval,
	sizeof (unsigned int)
};
