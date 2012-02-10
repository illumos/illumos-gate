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
#include <sys/time.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/ddi.h>
#include <sys/nsc_thread.h>
#include <sys/sysmacros.h>
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_errors.h>

#include <sys/unistat/spcs_s_k.h>
#include <sys/nsctl/nsctl.h>
#include "dsw.h"
#include "dsw_dev.h"
#include "../rdc/rdc_update.h"
#include <sys/nskernd.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#ifdef DS_DDICT
#include "../contract.h"
#endif

/*
 * Instant Image
 *
 * This file contains the core implementation of II.
 *
 * II is implemented as a simple filter module that pushes itself between
 * user (SV, STE, etc.) and SDBC or NET.
 *
 */


#define	REMOTE_VOL(s, ip)	(((s) && ((ip->bi_flags)&DSW_SHDEXPORT)) || \
				    (!(s)&&((ip->bi_flags)&DSW_SHDIMPORT)))

#define	total_ref(ip)	((ip->bi_shdref + ip->bi_shdrref + ip->bi_bmpref) + \
			    (NSHADOWS(ip) ? 0 : ip->bi_mstref + ip->bi_mstrref))


#define	II_TAIL_COPY(d, s, m, t)	bcopy(&(s.m), &(d.m), \
					sizeof (d) - (uintptr_t)&((t *)0)->m)
extern dev_info_t *ii_dip;

#define	II_LINK_CLUSTER(ip, cluster) \
	_ii_ll_add(ip, &_ii_cluster_mutex, &_ii_cluster_top, cluster, \
	    &ip->bi_cluster)
#define	II_UNLINK_CLUSTER(ip) \
	_ii_ll_remove(ip, &_ii_cluster_mutex, &_ii_cluster_top, &ip->bi_cluster)

#define	II_LINK_GROUP(ip, group) \
	_ii_ll_add(ip, &_ii_group_mutex, &_ii_group_top, group, &ip->bi_group)
#define	II_UNLINK_GROUP(ip) \
	_ii_ll_remove(ip, &_ii_group_mutex, &_ii_group_top, &ip->bi_group)

_ii_info_t *_ii_info_top;
_ii_info_t *_ii_mst_top = 0;
_ii_overflow_t	*_ii_overflow_top;
_ii_lsthead_t *_ii_cluster_top;
_ii_lsthead_t *_ii_group_top;

int	ii_debug;		/* level of cmn_err noise */
int	ii_bitmap;		/* bitmap operations switch */
uint_t	ii_header = 16;		/* Undocumented tunable (with adb!), start */
				/* of area cleared in volume when a dependent */
				/* shadow is disabled. */
				/* max # of chunks in copy loop before delay */
int	ii_throttle_unit = MIN_THROTTLE_UNIT;
				/* length of delay during update loop */
int	ii_throttle_delay = MIN_THROTTLE_DELAY;
int	ii_copy_direct = 1;
int	ii_nconcopy = 10;	/* default value when starting with no cache */
kmutex_t _ii_cluster_mutex;
kmutex_t _ii_group_mutex;

static int _ii_shutting_down = 0;
static nsc_io_t *_ii_io, *_ii_ior;
static nsc_mem_t *_ii_local_mem;
static nsc_def_t _ii_fd_def[], _ii_io_def[], _ii_ior_def[];
static kmutex_t	_ii_info_mutex;
static kmutex_t	_ii_overflow_mutex;
static kmutex_t _ii_config_mutex;
static _ii_bmp_ops_t alloc_buf_bmp, kmem_buf_bmp;
static nsc_svc_t *ii_volume_update;	/* IIVolumeUpdate token */
static nsc_svc_t *ii_report_luns;	/* IIReportLuns token */
static nsc_svc_t *ii_get_initiators;	/* IIGetInitiators token */
static ksema_t	_ii_concopy_sema;
static int	_ii_concopy_init = 0;
static int	_ii_instance = 0;

void _ii_deinit_dev();

static void _ii_info_free(_ii_info_t *ip);
static void _ii_info_freeshd(_ii_info_t *ip);
static void ii_sibling_free(_ii_info_t *ip);
ii_header_t *_ii_bm_header_get(_ii_info_t *ip, nsc_buf_t **tmp);
int _ii_bm_header_put(ii_header_t *hdr, _ii_info_t *ip,
    nsc_buf_t *tmp);
static void _ii_bm_header_free(ii_header_t *hdr, _ii_info_t *ip,
    nsc_buf_t *tmp);
static int _ii_copyvol(_ii_info_t *, int, int, spcs_s_info_t, int);
static void _ii_stopvol(_ii_info_t *ip);
static int _ii_stopcopy(_ii_info_t *ip);
static _ii_info_t *_ii_find_set(char *volume);
static _ii_info_t *_ii_find_vol(char *, int);
static _ii_overflow_t *_ii_find_overflow(char *volume);
static void _ii_ioctl_done(_ii_info_t *ip);
static void _ii_lock_chunk(_ii_info_t *ip, chunkid_t);
static void _ii_unlock_chunks(_ii_info_t *ip, chunkid_t, int);
void _ii_error(_ii_info_t *ip, int error_type);
static nsc_buf_t *_ii_alloc_handle(void (*d_cb)(), void (*r_cb)(),
    void (*w_cb)(), ii_fd_t *bfd);
static int _ii_free_handle(ii_buf_t *h, ii_fd_t *bfd);
extern nsc_size_t ii_btsize(nsc_size_t);
extern int ii_tinit(_ii_info_t *);
extern chunkid_t ii_tsearch(_ii_info_t *, chunkid_t);
extern void ii_tdelete(_ii_info_t *, chunkid_t);
extern void ii_reclaim_overflow(_ii_info_t *);
static void ii_overflow_free(_ii_info_t *ip, int disable);
static int ii_overflow_attach(_ii_info_t *, char *, int);
int _ii_nsc_io(_ii_info_t *, int, nsc_fd_t *, int, nsc_off_t, unsigned char *,
	nsc_size_t);
static nsc_path_t *_ii_register_path(char *path, int type, nsc_io_t *io);
static int _ii_unregister_path(nsc_path_t *sp, int flag, char *type);
static int _ii_reserve_begin(_ii_info_t *ip);
static int _ii_wait_for_it(_ii_info_t *ip);
static void _ii_reserve_end(_ii_info_t *ip);
static kstat_t *_ii_overflow_kstat_create(_ii_info_t *ip, _ii_overflow_t *op);
static int _ii_ll_add(_ii_info_t *, kmutex_t *, _ii_lsthead_t **, char *,
    char **);
static int _ii_ll_remove(_ii_info_t *, kmutex_t *, _ii_lsthead_t **, char **);
#define	_ii_unlock_chunk(ip, chunk)	_ii_unlock_chunks(ip, chunk, 1)
extern const int dsw_major_rev;
extern const int dsw_minor_rev;
extern const int dsw_micro_rev;
extern const int dsw_baseline_rev;

/*
 * These constants are used by ii_overflow_free() to indicate how the
 * reclamation should take place.
 *	NO_RECLAIM: just detach the overflow from the set; do not
 *		attempt to reclaim chunks, do not decrement the
 *		used-by count
 *	RECLAIM: reclaim all chunks before decrementing the used-by count
 *	INIT_OVR: decrement the used-by count only; do not reclaim chunks
 */

#define	NO_RECLAIM 0
#define	RECLAIM 1
#define	INIT_OVR 2

struct	copy_args {			/* arguments passed to copy process */
	_ii_info_t *ip;
	int flag;
	int rtype;
	int wait;
	spcs_s_info_t kstatus;
	int rc;
};

/* set-specific kstats info */
ii_kstat_set_t ii_kstat_set = {
	{ DSW_SKSTAT_SIZE, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_MTIME, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_FLAGS, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_THROTTLE_UNIT, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_THROTTLE_DELAY, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_SHDCHKS, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_SHDCHKUSED, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_SHDBITS, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_COPYBITS, KSTAT_DATA_ULONG },
	{ DSW_SKSTAT_MSTA, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_MSTB, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_MSTC, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_MSTD, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_SETA, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_SETB, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_SETC, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_SETD, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_BMPA, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_BMPB, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_BMPC, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_BMPD, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_OVRA, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_OVRB, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_OVRC, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_OVRD, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_MSTIO, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_SHDIO, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_BMPIO, KSTAT_DATA_CHAR },
	{ DSW_SKSTAT_OVRIO, KSTAT_DATA_CHAR },
};

/*
 * _ii_init_dev
 *	Initialise the shadow driver
 *
 */

int
_ii_init_dev()
{
	_ii_io = nsc_register_io("ii", NSC_II_ID|NSC_REFCNT|NSC_FILTER,
	    _ii_io_def);
	if (_ii_io == NULL)
		cmn_err(CE_WARN, "!ii: nsc_register_io failed.");

	_ii_ior = nsc_register_io("ii-raw", NSC_IIR_ID|NSC_REFCNT|NSC_FILTER,
	    _ii_ior_def);
	if (_ii_ior == NULL)
		cmn_err(CE_WARN, "!ii: nsc_register_io r failed.");

	_ii_local_mem = nsc_register_mem("ii:kmem", NSC_MEM_LOCAL, 0);
	if (_ii_local_mem == NULL)
		cmn_err(CE_WARN, "!ii: nsc_register_mem failed.");


	if (!_ii_io || !_ii_ior || !_ii_local_mem) {
		_ii_deinit_dev();
		return (ENOMEM);
	}

	mutex_init(&_ii_info_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&_ii_overflow_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&_ii_config_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&_ii_cluster_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&_ii_group_mutex, NULL, MUTEX_DRIVER, NULL);

	ii_volume_update = nsc_register_svc("RDCVolumeUpdated", 0);
	ii_report_luns = nsc_register_svc("IIReportLuns", 0);
	ii_get_initiators = nsc_register_svc("IIGetInitiators", 0);

	if (!ii_volume_update || !ii_report_luns || !ii_get_initiators) {
		_ii_deinit_dev();
		return (ENOMEM);
	}

	return (0);
}


/*
 * _ii_deinit_dev
 *	De-initialise the shadow driver
 *
 */

void
_ii_deinit_dev()
{

	if (_ii_io)
		(void) nsc_unregister_io(_ii_io, 0);

	if (_ii_ior)
		(void) nsc_unregister_io(_ii_ior, 0);

	if (_ii_local_mem)
		(void) nsc_unregister_mem(_ii_local_mem);

	if (ii_volume_update)
		(void) nsc_unregister_svc(ii_volume_update);

	if (ii_report_luns)
		(void) nsc_unregister_svc(ii_report_luns);

	if (ii_get_initiators)
		(void) nsc_unregister_svc(ii_get_initiators);

	mutex_destroy(&_ii_info_mutex);
	mutex_destroy(&_ii_overflow_mutex);
	mutex_destroy(&_ii_config_mutex);
	mutex_destroy(&_ii_cluster_mutex);
	mutex_destroy(&_ii_group_mutex);
	if (_ii_concopy_init)
		sema_destroy(&_ii_concopy_sema);
	_ii_concopy_init = 0;

}

static char *
ii_pathname(nsc_fd_t *fd)
{
	char *rc;

	if (fd == NULL || (rc = nsc_pathname(fd)) == NULL)
		return ("");
	else
		return (rc);
}


/*
 * _ii_rlse_d
 *	Internal mechanics of _ii_rlse_devs().  Takes care of
 *	resetting the ownership information as required.
 */

static void
_ii_rlse_d(ip, mst, raw)
_ii_info_t *ip;
int mst, raw;
{
	_ii_info_dev_t *cip;
	_ii_info_dev_t *rip;

	rip = mst ? (ip->bi_mstrdev) : &(ip->bi_shdrdev);
	cip = mst ? (ip->bi_mstdev) : &(ip->bi_shddev);

	DTRACE_PROBE2(_ii_rlse_d_type,
			_ii_info_dev_t *, rip,
			_ii_info_dev_t *, cip);


	if (RSRV(cip)) {
		if (raw) {
			ASSERT(cip->bi_orsrv > 0);
			cip->bi_orsrv--;
		} else {
			ASSERT(cip->bi_rsrv > 0);
			cip->bi_rsrv--;
		}

		if (cip->bi_rsrv > 0) {
			nsc_set_owner(cip->bi_fd, cip->bi_iodev);
		} else if (cip->bi_orsrv > 0) {
			nsc_set_owner(cip->bi_fd, rip->bi_iodev);
		} else {
			nsc_set_owner(cip->bi_fd, NULL);
		}

		if (!RSRV(cip)) {
			nsc_release(cip->bi_fd);
		}
	} else {
		if (raw) {
			ASSERT(rip->bi_rsrv > 0);
			rip->bi_rsrv--;
		} else {
			ASSERT(rip->bi_orsrv > 0);
			rip->bi_orsrv--;
		}

		if (rip->bi_rsrv > 0) {
			nsc_set_owner(rip->bi_fd, rip->bi_iodev);
		} else if (rip->bi_orsrv > 0) {
			nsc_set_owner(rip->bi_fd, cip->bi_iodev);
		} else {
			nsc_set_owner(rip->bi_fd, NULL);
		}

		if (!RSRV(rip)) {
			rip->bi_flag = 0;
			nsc_release(rip->bi_fd);
			cv_broadcast(&ip->bi_releasecv);
		}
	}

}


/*
 * _ii_rlse_devs
 *	Release named underlying devices.
 *
 *	NOTE: the 'devs' argument must be the same as that passed to
 *	the preceding _ii_rsrv_devs call.
 */

void
_ii_rlse_devs(ip, devs)
_ii_info_t *ip;
int devs;
{

	ASSERT(!(devs & (MST|SHD)));

	ASSERT(ip->bi_head != (_ii_info_t *)0xdeadbeef);
	if (!ip) {
		cmn_err(CE_WARN, "!ii: _ii_rlse_devs null ip");
		return;
	}

	mutex_enter(&ip->bi_rsrvmutex);

	DTRACE_PROBE(_ii_rlse_devs_mutex);

	if ((devs&(MST|MSTR)) != 0 && (ip->bi_flags&DSW_SHDIMPORT) == 0) {
		if (NSHADOWS(ip) && ip != ip->bi_master)
			_ii_rlse_devs(ip->bi_master, devs&(MST|MSTR));
		else
			_ii_rlse_d(ip, 1, (devs&MSTR));
	}

	if ((devs&(SHD|SHDR)) != 0 && (ip->bi_flags&DSW_SHDEXPORT) == 0) {
		_ii_rlse_d(ip, 0, (devs&SHDR));
	}

	if ((devs&BMP) != 0 && ip->bi_bmpfd) {
		if (--(ip->bi_bmprsrv) == 0)
			nsc_release(ip->bi_bmpfd);
	}

	ASSERT(ip->bi_bmprsrv >= 0);
	ASSERT(ip->bi_shdrsrv >= 0);
	ASSERT(ip->bi_shdrrsrv >= 0);
	mutex_exit(&ip->bi_rsrvmutex);

}


/*
 * _ii_rsrv_d
 *	Reserve device flagged, unless its companion is already reserved,
 *	in that case increase the reserve on the companion.
 */

static int
_ii_rsrv_d(int raw, _ii_info_dev_t *rid, _ii_info_dev_t *cid, int flag,
    _ii_info_t *ip)
{
	_ii_info_dev_t *p = NULL;
	int other = 0;
	int rc;

	/*
	 * If user wants to do a cache reserve and it's already
	 * raw reserved, we need to do a real nsc_reserve, so wait
	 * until the release has been done.
	 */
	if (RSRV(rid) && (flag == II_EXTERNAL) &&
	    (raw == 0) && (rid->bi_flag != II_EXTERNAL)) {
		ip->bi_release++;
		while (RSRV(rid)) {
			DTRACE_PROBE1(_ii_rsrv_d_wait, _ii_info_dev_t *, rid);
			cv_wait(&ip->bi_releasecv, &ip->bi_rsrvmutex);
			DTRACE_PROBE1(_ii_rsrv_d_resume, _ii_info_dev_t *, rid);
		}
		ip->bi_release--;
	}

	if (RSRV(rid)) {
		p = rid;
		if (!raw) {
			other = 1;
		}
	} else if (RSRV(cid)) {
		p = cid;
		if (raw) {
			other = 1;
		}
	}

	if (p) {
		if (other) {
			p->bi_orsrv++;
		} else {
			p->bi_rsrv++;
		}

		if (p->bi_iodev) {
			nsc_set_owner(p->bi_fd, p->bi_iodev);
		}

		return (0);
	}
	p = raw ? rid : cid;

	if ((rc = nsc_reserve(p->bi_fd, 0)) == 0) {
		if (p->bi_iodev) {
			nsc_set_owner(p->bi_fd, p->bi_iodev);
		}
		p->bi_rsrv++;
		if (raw)
			p->bi_flag = flag;
	}

	return (rc);
}

/*
 * _ii_rsrv_devs
 *	Reserve named underlying devices.
 *
 */

int
_ii_rsrv_devs(_ii_info_t *ip, int devs, int flag)
{
	int rc = 0;
	int got = 0;

	ASSERT(!(devs & (MST|SHD)));

	if (!ip) {
		cmn_err(CE_WARN, "!ii: _ii_rsrv_devs null ip");
		return (EINVAL);
	}

	mutex_enter(&ip->bi_rsrvmutex);

	DTRACE_PROBE(_ii_rsrv_devs_mutex);

	if (rc == 0 && (devs&(MST|MSTR)) != 0 &&
	    (ip->bi_flags&DSW_SHDIMPORT) == 0) {
		DTRACE_PROBE(_ii_rsrv_devs_master);
		if (NSHADOWS(ip) && ip != ip->bi_master) {
			if ((rc = _ii_rsrv_devs(ip->bi_master, devs&(MST|MSTR),
			    flag)) != 0) {
				cmn_err(CE_WARN,
				    "!ii: nsc_reserve multi-master failed");
			} else {
				got |= devs&(MST|MSTR);
			}
		} else {
			if ((rc = _ii_rsrv_d((devs&MSTR) != 0, ip->bi_mstrdev,
			    ip->bi_mstdev, flag, ip)) != 0) {
				cmn_err(CE_WARN,
				    "!ii: nsc_reserve master failed %d", rc);
			} else {
				got |= (devs&(MST|MSTR));
			}
		}
	}

	if (rc == 0 && (devs&(SHD|SHDR)) != 0 &&
	    (ip->bi_flags&DSW_SHDEXPORT) == 0) {
		DTRACE_PROBE(_ii_rsrv_devs_shadow);
		if ((rc = _ii_rsrv_d((devs&SHDR) != 0, &ip->bi_shdrdev,
		    &ip->bi_shddev, flag, ip)) != 0) {
			cmn_err(CE_WARN,
			    "!ii: nsc_reserve shadow failed %d", rc);
		} else {
			got |= (devs&(SHD|SHDR));
		}
	}

	if (rc == 0 && (devs&BMP) != 0 && ip->bi_bmpfd) {
		DTRACE_PROBE(_ii_rsrv_devs_bitmap);
		if ((ip->bi_bmprsrv == 0) &&
		    (rc = nsc_reserve(ip->bi_bmpfd, 0)) != 0) {
			cmn_err(CE_WARN,
			    "!ii: nsc_reserve bitmap failed %d", rc);
		} else {
			(ip->bi_bmprsrv)++;
			got |= BMP;
		}
	}
	mutex_exit(&ip->bi_rsrvmutex);
	if (rc != 0 && got != 0)
		_ii_rlse_devs(ip, got);

	return (rc);
}

static int
_ii_reserve_begin(_ii_info_t *ip)
{
	int rc;

	mutex_enter(&ip->bi_rlsemutex);
	if ((rc = _ii_wait_for_it(ip)) == 0) {
		++ip->bi_rsrvcnt;
	}
	mutex_exit(&ip->bi_rlsemutex);

	return (rc);
}

static int
_ii_wait_for_it(_ii_info_t *ip)
{
	int nosig;

	nosig = 1;
	while (ip->bi_rsrvcnt > 0) {
		nosig = cv_wait_sig(&ip->bi_reservecv, &ip->bi_rlsemutex);
		if (!nosig) {
			break;
		}
	}

	return (nosig? 0 : EINTR);
}

static void
_ii_reserve_end(_ii_info_t *ip)
{
	mutex_enter(&ip->bi_rlsemutex);
	if (ip->bi_rsrvcnt <= 0) {
		mutex_exit(&ip->bi_rlsemutex);
		return;
	}
	--ip->bi_rsrvcnt;
	mutex_exit(&ip->bi_rlsemutex);
	cv_broadcast(&ip->bi_reservecv);

}

static int
ii_fill_copy_bmp(_ii_info_t *ip)
{
	int rc;
	chunkid_t max_chunk, chunk_num;

	if ((rc = II_FILL_COPY_BMP(ip)) != 0)
		return (rc);
	/*
	 * make certain that the last bits of the last byte of the bitmap
	 * aren't filled as they may be copied out to the user.
	 */

	chunk_num = ip->bi_size / DSW_SIZE;
	if ((ip->bi_size % DSW_SIZE) != 0)
		++chunk_num;

	max_chunk = chunk_num;
	if ((max_chunk & 0x7) != 0)
		max_chunk = (max_chunk + 7) & ~7;

	DTRACE_PROBE2(_ii_fill_copy_bmp_chunks, chunkid_t, chunk_num,
	    chunkid_t, max_chunk);

	for (; chunk_num < max_chunk; chunk_num++) {
		(void) II_CLR_COPY_BIT(ip, chunk_num);
	}

	return (0);
}

static int
ii_update_denied(_ii_info_t *ip, spcs_s_info_t kstatus,
				int direction, int all)
{
	rdc_update_t update;
	int size;
	unsigned char *bmp;

	update.volume = direction == CV_SHD2MST ? ii_pathname(MSTFD(ip)) :
	    ip->bi_keyname;
	update.denied = 0;
	update.protocol = RDC_SVC_ONRETURN;
	update.size = size = FBA_SIZE(DSW_BM_FBA_LEN(ip->bi_size));
	update.status = kstatus;
	update.bitmap = bmp = kmem_alloc(update.size, KM_SLEEP);
	if (bmp == NULL) {
		spcs_s_add(kstatus, ENOMEM);
		return (1);
	}

	DTRACE_PROBE2(_ii_update_denied, int, all, int, size);

	if (all) {
		while (size-- > 0)
			*bmp++ = (unsigned char)0xff;
	} else {
		if (II_CHANGE_BMP(ip, update.bitmap) != 0) {
			/* failed to read bitmap */
			spcs_s_add(kstatus, EIO);
			update.denied = 1;
		}
	}

	/* check that no user of volume objects */
	if (update.denied == 0) {
		(void) nsc_call_svc(ii_volume_update, (intptr_t)&update);
	}
	kmem_free(update.bitmap, FBA_SIZE(DSW_BM_FBA_LEN(ip->bi_size)));

	return (update.denied);
}

static int
ii_need_same_size(_ii_info_t *ip)
{
	rdc_update_t update;

	update.volume = ip->bi_keyname;
	update.denied = 0;
	update.protocol = RDC_SVC_VOL_ENABLED;

	(void) nsc_call_svc(ii_volume_update, (intptr_t)&update);

	return (update.denied);
}

/*
 * ii_volume:	check if vol is already known to Instant Image and return
 *	volume type if it is.
 */

static int
ii_volume(char *vol, int locked)
{
	_ii_info_t *ip;
	_ii_overflow_t	*op;
	int rc = NONE;

	/* scan overflow volume list */
	mutex_enter(&_ii_overflow_mutex);

	DTRACE_PROBE(_ii_volume_mutex);

	for (op = _ii_overflow_top; op; op = op->ii_next) {
		if (strcmp(vol, op->ii_volname) == 0)
			break;
	}
	mutex_exit(&_ii_overflow_mutex);
	if (op) {
		return (OVR);
	}

	if (!locked) {
		mutex_enter(&_ii_info_mutex);
	}

	DTRACE_PROBE(_ii_volume_mutex2);

	for (ip = _ii_info_top; ip; ip = ip->bi_next) {
		if (strcmp(vol, ii_pathname(ip->bi_mstfd)) == 0) {
			rc = MST;
			break;
		}
		if (strcmp(vol, ip->bi_keyname)  == 0) {
			rc = SHD;
			break;
		}
		if (strcmp(vol, ii_pathname(ip->bi_bmpfd)) == 0) {
			rc = BMP;
			break;
		}
	}
	DTRACE_PROBE1(_ii_volume_data, int, rc);

	if (!locked) {
		mutex_exit(&_ii_info_mutex);
	}

	return (rc);
}

/*
 * ii_open_shadow: open shadow volume for both cached and raw access,
 *	if the normal device open fails attempt a file open to allow
 *	shadowing into a file.
 */

static int
ii_open_shadow(_ii_info_t *ip, char *shadow_vol)
{
	int rc = 0;
	int file_rc = 0;

	ip->bi_shdfd = nsc_open(shadow_vol,
	    NSC_IIR_ID|NSC_DEVICE|NSC_RDWR, _ii_fd_def,
	    (blind_t)&(ip->bi_shddev), &rc);
	if (!ip->bi_shdfd) {
		ip->bi_shdfd = nsc_open(shadow_vol,
		    NSC_IIR_ID|NSC_FILE|NSC_RDWR, _ii_fd_def,
		    (blind_t)&(ip->bi_shddev), &file_rc);
		file_rc = 1;
		if (!ip->bi_shdfd) {
			return (rc);
		}
		DTRACE_PROBE(_ii_open_shadow);
	}
	else
		DTRACE_PROBE(_ii_open_shadow);

	if (file_rc == 0) {
		ip->bi_shdrfd = nsc_open(shadow_vol,
		    NSC_IIR_ID|NSC_DEVICE|NSC_RDWR, _ii_fd_def,
		    (blind_t)&(ip->bi_shdrdev), &rc);
		DTRACE_PROBE(_ii_open_shadow);
	} else {
		ip->bi_shdrfd = nsc_open(shadow_vol,
		    NSC_IIR_ID|NSC_FILE|NSC_RDWR, _ii_fd_def,
		    (blind_t)&(ip->bi_shdrdev), &rc);
		DTRACE_PROBE(_ii_open_shadow);
	}

	if (!ip->bi_shdrfd) {
		(void) nsc_close(ip->bi_shdfd);
		DTRACE_PROBE(_ii_open_shadow);
		return (rc);
	}

	return (0);
}

static void
ii_register_shd(_ii_info_t *ip)
{
	ip->bi_shd_tok = _ii_register_path(ip->bi_keyname,
	    NSC_CACHE, _ii_io);
	ip->bi_shdr_tok = _ii_register_path(ip->bi_keyname,
	    NSC_DEVICE, _ii_ior);

}

static void
ii_register_mst(_ii_info_t *ip)
{
	ip->bi_mst_tok = _ii_register_path(ii_pathname(ip->bi_mstfd),
	    NSC_CACHE, _ii_io);
	ip->bi_mstr_tok = _ii_register_path(ii_pathname(ip->bi_mstrfd),
	    NSC_DEVICE, _ii_ior);

}

static int
ii_register_ok(_ii_info_t *ip)
{
	int rc;
	int sibling;
	int exported;

	rc = 1;
	sibling = NSHADOWS(ip) && ip != ip->bi_head;
	exported = ip->bi_flags & DSW_SHDEXPORT;

	if ((ip->bi_bmpfd && !ip->bi_bmp_tok) || (!exported && (
	    !ip->bi_shd_tok || !ip->bi_shdr_tok)))
		rc = 0;
	else if (!sibling && (!ip->bi_mst_tok || !ip->bi_mstr_tok))
		rc = 0;

	return (rc);
}

#ifndef DISABLE_KSTATS

/*
 * _ii_kstat_create
 *	Create and install kstat_io data
 *
 * Calling/Exit State:
 *	Returns 0 if kstats couldn't be created, otherwise it returns
 *	a pointer to the created kstat_t.
 */

static kstat_t *
_ii_kstat_create(_ii_info_t *ip, char *type)
{
	kstat_t *result;
	char name[ IOSTAT_NAME_LEN ];
	int setnum;
	char *nptr;
	static int mstnum = 0;
	static int shdbmpnum = -1;

	switch (*type) {
	case 'm':
		setnum = mstnum++;
		nptr = ip->bi_kstat_io.mstio;
		break;
	case 's':
		/* assumption: shadow kstats created before bitmap */
		setnum = ++shdbmpnum;
		nptr = ip->bi_kstat_io.shdio;
		break;
	case 'b':
		setnum = shdbmpnum;
		nptr = ip->bi_kstat_io.bmpio;
		break;
	default:
		cmn_err(CE_WARN, "!Unable to determine kstat type (%c)", *type);
		setnum = -1;
		break;
	}
	/*
	 * The name of the kstat, defined below, is designed to work
	 * with the 'iostat -x' command.  This command leaves only
	 * 9 characters for the name, and the kstats built in to Solaris
	 * all seem to be of the form <service><number>.  For that
	 * reason, we have chosen ii<type><number>, where <type> is
	 * m, s, b, or o (for master, shadow, bitmap, and overflow
	 * respectively), and the number is monotonically increasing from
	 * 0 for each time one of those <type>s are created.  Note that
	 * the shadow and bitmap are always created in pairs and so, for
	 * any given set, they will have the same <number>.
	 */
	(void) sprintf(name, "ii%c%d", *type, setnum);
	(void) strncpy(nptr, name, IOSTAT_NAME_LEN);
	result = kstat_create("ii", 0, name, "disk", KSTAT_TYPE_IO, 1, 0);
	if (result) {
		result->ks_private = ip;
		result->ks_lock = &ip->bi_kstat_io.statmutex;
		kstat_install(result);
	} else {
		cmn_err(CE_WARN, "!Unable to create %s kstats for set %s", type,
		    ip->bi_keyname);
	}

	return (result);
}

/*
 * _ii_overflow_kstat_create
 *	Create and install kstat_io data for an overflow volume
 *
 * Calling/Exit State:
 *	Returns 0 if kstats couldn't be created, otherwise it returns
 *	a pointer to the created kstat_t.
 *
 * See comments in _ii_kstat_create for additional information.
 *
 */
static kstat_t *
_ii_overflow_kstat_create(_ii_info_t *ip, _ii_overflow_t *op)
{
	kstat_t *result;
	char *nptr;
	char name [IOSTAT_NAME_LEN];
	static int ovrnum = 0;
	int setnum = ovrnum++;

	nptr = ip->bi_kstat_io.ovrio;

	(void) sprintf(name, "iio%d", setnum);
	(void) strncpy(nptr, name, IOSTAT_NAME_LEN);

	mutex_init(&op->ii_kstat_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((result =
	    kstat_create("ii", 0, name, "disk", KSTAT_TYPE_IO, 1, 0))) {
		result->ks_private = ip;
		result->ks_lock = &op->ii_kstat_mutex;
		kstat_install(result);
	} else {
		mutex_destroy(&op->ii_kstat_mutex);
		cmn_err(CE_WARN, "!Unabled to create overflow kstat for set "
		    "%s", ip->bi_keyname);
	}

	return (result);
}

#endif

static void
ii_str_kstat_copy(char *str, char *p1, char *p2, char *p3, char *p4)
{
	static int whinged = 0;
	char *part[ 4 ];
	char fulldata[ DSW_NAMELEN ];
	int i, offset, remain;
	int num_parts;
	int leftover;
	int kscharsize = KSTAT_DATA_CHAR_LEN - 1;

	/*
	 * NOTE: the following lines must be changed if DSW_NAMELEN
	 * ever changes.  You'll need a part[] for every kscharsize
	 * characters (or fraction thereof).  The ii_kstat_set_t
	 * definition in dsw_dev.h will also need new ovr_? entries.
	 */
	part[ 0 ] = p1;
	part[ 1 ] = p2;
	part[ 2 ] = p3;
	part[ 3 ] = p4;

	bzero(fulldata, DSW_NAMELEN);
	if (str) {
		(void) strncpy(fulldata, str, DSW_NAMELEN);
	}

	num_parts = DSW_NAMELEN / kscharsize;
	leftover = DSW_NAMELEN % kscharsize;
	if (leftover) {
		++num_parts;
	}

	if (num_parts > sizeof (part) / sizeof (part[0])) {
		/*
		 * DSW_NAMELEN is 64 and kscharsize is 15.
		 * It's always "whinged"
		 */
		if (!whinged) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!May not have enough room "
			    "to store volume name in kstats");
#endif
			whinged = 1;
		}
		num_parts = sizeof (part) / sizeof (part[0]);
	}

	offset = 0;
	remain = DSW_NAMELEN;
	for (i = 0; i < num_parts; i++) {
		int to_copy = remain > kscharsize? kscharsize : remain;
		bcopy(&fulldata[ offset ], part[ i ], to_copy);
		offset += to_copy;
		remain -= to_copy;
	}
}

static int
ii_set_stats_update(kstat_t *ksp, int rw)
{
	_ii_info_t *ip = (_ii_info_t *)ksp->ks_private;
	ii_kstat_set_t *kp = (ii_kstat_set_t *)ksp->ks_data;

	if (KSTAT_WRITE == rw) {
		return (EACCES);
	}

	/* copy values over */
	kp->size.value.ul = ip->bi_size;
	kp->flags.value.ul = ip->bi_flags;
	kp->unit.value.ul = ip->bi_throttle_unit;
	kp->delay.value.ul = ip->bi_throttle_delay;
	kp->mtime.value.ul = ip->bi_mtime;

	/* update bitmap counters if necessary */
	if (ip->bi_state & DSW_CNTCPYBITS) {
		ip->bi_copybits = 0;
		if (_ii_rsrv_devs(ip, BMP, II_INTERNAL) == 0) {
			ip->bi_state &= ~DSW_CNTCPYBITS;
			II_CNT_BITS(ip, ip->bi_copyfba,
			    &ip->bi_copybits,
			    DSW_BM_SIZE_BYTES(ip));
			_ii_rlse_devs(ip, BMP);
		}
	}

	if (ip->bi_state & DSW_CNTSHDBITS) {
		ip->bi_shdbits = 0;
		if (_ii_rsrv_devs(ip, BMP, II_INTERNAL) == 0) {
			ip->bi_state &= ~DSW_CNTSHDBITS;
			II_CNT_BITS(ip, ip->bi_shdfba,
			    &ip->bi_shdbits,
			    DSW_BM_SIZE_BYTES(ip));
			_ii_rlse_devs(ip, BMP);
		}
	}

	kp->copybits.value.ul = ip->bi_copybits;
	kp->shdbits.value.ul = ip->bi_shdbits;

	/* copy volume names */
	ii_str_kstat_copy(ii_pathname(MSTFD(ip)),
	    kp->mst_a.value.c, kp->mst_b.value.c,
	    kp->mst_c.value.c, kp->mst_d.value.c);

	ii_str_kstat_copy(ip->bi_keyname, kp->set_a.value.c, kp->set_b.value.c,
	    kp->set_c.value.c, kp->set_d.value.c);

	ii_str_kstat_copy(ii_pathname(ip->bi_bmpfd),
	    kp->bmp_a.value.c, kp->bmp_b.value.c,
	    kp->bmp_c.value.c, kp->bmp_d.value.c);

	if (ip->bi_overflow) {
		ii_str_kstat_copy(ip->bi_overflow->ii_volname,
		    kp->ovr_a.value.c, kp->ovr_b.value.c, kp->ovr_c.value.c,
		    kp->ovr_d.value.c);
		(void) strlcpy(kp->ovr_io.value.c, ip->bi_kstat_io.ovrio,
		    KSTAT_DATA_CHAR_LEN);
	} else {
		ii_str_kstat_copy("", kp->ovr_a.value.c, kp->ovr_b.value.c,
		    kp->ovr_c.value.c, kp->ovr_d.value.c);
		bzero(kp->ovr_io.value.c, KSTAT_DATA_CHAR_LEN);
	}
	if ((ip->bi_flags) & DSW_TREEMAP) {
		kp->shdchks.value.ul = ip->bi_shdchks;
		kp->shdchkused.value.ul = ip->bi_shdchkused;
	} else {
		kp->shdchks.value.ul = 0;
		kp->shdchkused.value.ul = 0;
	}
	/* make sure value.c are always null terminated */
	(void) strlcpy(kp->mst_io.value.c, ip->bi_kstat_io.mstio,
	    KSTAT_DATA_CHAR_LEN);
	(void) strlcpy(kp->shd_io.value.c, ip->bi_kstat_io.shdio,
	    KSTAT_DATA_CHAR_LEN);
	(void) strlcpy(kp->bmp_io.value.c, ip->bi_kstat_io.bmpio,
	    KSTAT_DATA_CHAR_LEN);

	return (0);
}

/*
 * _ii_config
 *	Configure an II device pair
 *
 * Calling/Exit State:
 *	Returns 0 if the pairing was configured, otherwise an
 *	error code. The ioctl data stucture is copied out to the user
 *	and contains any additional error information, and the master
 *	and shadow volume names if not supplied by the user.
 *
 * Description:
 *	Reads the user configuration structure and attempts
 *	to establish an II pairing. The snapshot of the master
 *	device is established at this point in time.
 */

int
_ii_config(intptr_t arg, int ilp32, int *rvp, int iflags)
{
	dsw_config_t uconf;
	dsw_config32_t *uconf32;
	_ii_info_t *ip, *hip, **ipp;
	int rc;
	int type;
	int nshadows;
	int add_to_mst_top;
	int import;
	int existing;
	int resized;
	nsc_size_t mst_size, shd_size, bmp_size;
	nsc_off_t shdfba;
	nsc_off_t copyfba;
	int keylen, keyoffset;
	ii_header_t *bm_header;
	nsc_buf_t *tmp;
	spcs_s_info_t kstatus;
	spcs_s_info32_t ustatus32;
	int rtype;
	uint_t hints;

	/* Import is a once only operation like an enable */
	ASSERT((iflags&(II_EXISTING|II_IMPORT)) != (II_EXISTING|II_IMPORT));
	existing = (iflags&II_EXISTING) != 0;
	import = (iflags&II_IMPORT) != 0;
	*rvp = 0;
	if (ilp32) {
		uconf32 = kmem_zalloc(sizeof (dsw_config32_t), KM_SLEEP);
		if (uconf32 == NULL) {
			return (ENOMEM);
		}
		if (copyin((void *)arg, uconf32, sizeof (*uconf32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uconf, (*uconf32), master_vol, dsw_config_t);
		uconf.status = (spcs_s_info_t)uconf32->status;
		ustatus32 = uconf32->status;
		kmem_free(uconf32, sizeof (dsw_config32_t));
	} else if (copyin((void *)arg, &uconf, sizeof (uconf)) < 0)
		return (EFAULT);

	DTRACE_PROBE3(_ii_config_info, char *, uconf.master_vol,
	    char *, uconf.shadow_vol, char *, uconf.bitmap_vol);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (_ii_shutting_down)
		return (spcs_s_ocopyoutf(&kstatus, uconf.status,
		    DSW_ESHUTDOWN));

	if (uconf.bitmap_vol[0] == 0)
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EEMPTY));

	mutex_enter(&_ii_config_mutex);
	ip = nsc_kmem_zalloc(sizeof (*ip), KM_SLEEP, _ii_local_mem);
	if (!ip) {
		mutex_exit(&_ii_config_mutex);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, ENOMEM));
	}
	ip->bi_mstdev = nsc_kmem_zalloc(sizeof (*ip->bi_mstdev), KM_SLEEP,
	    _ii_local_mem);
	ip->bi_mstrdev = nsc_kmem_zalloc(sizeof (*ip->bi_mstdev), KM_SLEEP,
	    _ii_local_mem);
	if (ip->bi_mstdev == NULL || ip->bi_mstrdev == NULL) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, ENOMEM));
	}

	ip->bi_disabled = 1;	/* mark as disabled until we are ready to go */
	mutex_init(&ip->bi_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ip->bi_bmpmutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ip->bi_rsrvmutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ip->bi_rlsemutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ip->bi_chksmutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&ip->bi_copydonecv, NULL, CV_DRIVER, NULL);
	cv_init(&ip->bi_reservecv, NULL, CV_DRIVER, NULL);
	cv_init(&ip->bi_releasecv, NULL, CV_DRIVER, NULL);
	cv_init(&ip->bi_ioctlcv, NULL, CV_DRIVER, NULL);
	cv_init(&ip->bi_closingcv, NULL, CV_DRIVER, NULL);
	cv_init(&ip->bi_busycv, NULL, CV_DRIVER, NULL);
	rw_init(&ip->bi_busyrw, NULL, RW_DRIVER, NULL);
	rw_init(&ip->bi_linkrw, NULL, RW_DRIVER, NULL);
	(void) strncpy(ip->bi_keyname, uconf.shadow_vol, DSW_NAMELEN);
	ip->bi_keyname[DSW_NAMELEN-1] = '\0';
	ip->bi_throttle_unit = ii_throttle_unit;
	ip->bi_throttle_delay = ii_throttle_delay;

	/* First check the list to see if uconf.bitmap_vol's already there */

	if (ii_volume(uconf.bitmap_vol, 0) != NONE) {
		DTRACE_PROBE(_ii_config_bmp_found);
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EINUSE));
	}

	ip->bi_bmpfd = nsc_open(uconf.bitmap_vol,
	    NSC_IIR_ID|NSC_FILE|NSC_RDWR, NULL, (blind_t)&(ip->bi_bmpdev), &rc);
	if (!ip->bi_bmpfd)
		ip->bi_bmpfd = nsc_open(uconf.bitmap_vol,
		    NSC_IIR_ID|NSC_CACHE|NSC_DEVICE|NSC_RDWR, NULL,
		    (blind_t)&(ip->bi_bmpdev), &rc);
	if (!ip->bi_bmpfd && !existing) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		spcs_s_add(kstatus, rc);
		DTRACE_PROBE(_ii_config_no_bmp);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EOPEN));
	}

	if (import) {
		uconf.flag = DSW_GOLDEN;
		II_FLAG_SETX(DSW_SHDIMPORT|DSW_GOLDEN, ip);
	}

	if (existing) {

		DTRACE_PROBE(_ii_config_existing);
		/*
		 * ii_config is used by enable, import and resume (existing)
		 * If not importing or resuming, then this must be enable.
		 * Indicate this fact for SNMP use.
		 */

		if (!ip->bi_bmpfd) {
			/*
			 * Couldn't read bitmap, mark master and shadow as
			 * unusable.
			 */
			II_FLAG_ASSIGN(DSW_BMPOFFLINE|DSW_MSTOFFLINE|
			    DSW_SHDOFFLINE, ip);

			/*
			 * Set cluster tag for this element so it can
			 * be suspended later
			 */
			(void) II_LINK_CLUSTER(ip, uconf.cluster_tag);

			/* need to check on master, might be shared */
			goto header_checked;
		}
		/* check the header */
		(void) _ii_rsrv_devs(ip, BMP, II_INTERNAL);

		/* get first block of bit map */
		mutex_enter(&ip->bi_mutex);
		bm_header = _ii_bm_header_get(ip, &tmp);
		mutex_exit(&ip->bi_mutex);
		if (bm_header == NULL) {
			if (ii_debug > 0)
				cmn_err(CE_WARN,
				    "!ii: _ii_bm_header_get returned NULL");
			mutex_exit(&_ii_config_mutex);
			_ii_info_free(ip);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status,
			    DSW_EHDRBMP));
		}

		if (bm_header->ii_magic != DSW_DIRTY &&
		    bm_header->ii_magic != DSW_CLEAN) {
			mutex_exit(&_ii_config_mutex);
			_ii_bm_header_free(bm_header, ip, tmp);
			_ii_info_free(ip);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status,
			    DSW_EINVALBMP));
		}

		II_FLAG_ASSIGN(bm_header->ii_state, ip);
		/* Restore copy throttle parameters, if header version is 3 */
		if (bm_header->ii_version >= 3) {	/* II_HEADER_VERSION */
			ip->bi_throttle_delay = bm_header->ii_throttle_delay;
			ip->bi_throttle_unit  = bm_header->ii_throttle_unit;
		}

		/* Restore cluster & group names, if header version is 4 */
		if (bm_header->ii_version >= 4) {
			/* cluster */
			if (*bm_header->clstr_name) {
				(void) strncpy(uconf.cluster_tag,
				    bm_header->clstr_name, DSW_NAMELEN);
				(void) II_LINK_CLUSTER(ip, uconf.cluster_tag);
			}

			/* group */
			if (*bm_header->group_name) {
				(void) strncpy(uconf.group_name,
				    bm_header->group_name, DSW_NAMELEN);
				(void) II_LINK_GROUP(ip, uconf.group_name);
			}
		}
		/* restore latest modification time, if header version >= 5 */
		if (bm_header->ii_version >= 5) {
			ip->bi_mtime = bm_header->ii_mtime;
		}

		/* Fetch master and shadow names from bitmap header */
		if (uconf.master_vol[0] == 0)
			(void) strncpy(uconf.master_vol, bm_header->master_vol,
			    DSW_NAMELEN);
		if (uconf.shadow_vol[0] == 0)
			(void) strncpy(uconf.shadow_vol, bm_header->shadow_vol,
			    DSW_NAMELEN);

		/* return the fetched names to the user */
		if (ilp32) {
			uconf32 = kmem_zalloc(sizeof (dsw_config32_t),
			    KM_SLEEP);
			if (uconf32 == NULL) {
				mutex_exit(&_ii_config_mutex);
				_ii_bm_header_free(bm_header, ip, tmp);
				_ii_rlse_devs(ip, BMP);
				_ii_info_free(ip);
				return (ENOMEM);
			}
			uconf32->status = ustatus32;
			II_TAIL_COPY((*uconf32), uconf, master_vol,
			    dsw_config32_t);
			rc = copyout(uconf32, (void *)arg, sizeof (*uconf32));
			kmem_free(uconf32, sizeof (dsw_config32_t));
		} else {
			rc = copyout(&uconf, (void *)arg, sizeof (uconf));
		}
		if (rc) {
			mutex_exit(&_ii_config_mutex);
			_ii_bm_header_free(bm_header, ip, tmp);
			_ii_rlse_devs(ip, BMP);
			_ii_info_free(ip);
			return (EFAULT);
		}

		if (strncmp(bm_header->bitmap_vol, uconf.bitmap_vol,
		    DSW_NAMELEN) || ((!(ip->bi_flags&DSW_SHDIMPORT)) &&
		    strncmp(bm_header->master_vol, uconf.master_vol,
		    DSW_NAMELEN)) || strncmp(bm_header->shadow_vol,
		    uconf.shadow_vol, DSW_NAMELEN)) {
			mutex_exit(&_ii_config_mutex);
			_ii_bm_header_free(bm_header, ip, tmp);
			_ii_rlse_devs(ip, BMP);
			_ii_info_free(ip);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status,
			    DSW_EMISMATCH));
		}
		shdfba = bm_header->ii_shdfba;
		copyfba = bm_header->ii_copyfba;
		if ((ip->bi_flags)&DSW_TREEMAP) {
			if (ii_debug > 0)
				cmn_err(CE_NOTE,
				    "!II: Resuming short shadow volume");

			ip->bi_mstchks = bm_header->ii_mstchks;
			ip->bi_shdchks = bm_header->ii_shdchks;
			ip->bi_shdchkused = bm_header->ii_shdchkused;
			ip->bi_shdfchk = bm_header->ii_shdfchk;

			if (bm_header->overflow_vol[0] != 0)
				if ((rc = ii_overflow_attach(ip,
				    bm_header->overflow_vol, 0)) != 0) {
					mutex_exit(&_ii_config_mutex);
					_ii_bm_header_free(bm_header, ip, tmp);
					_ii_rlse_devs(ip, BMP);
					_ii_info_free(ip);
					return (spcs_s_ocopyoutf(&kstatus,
					    uconf.status, rc));
			}
		}
		_ii_bm_header_free(bm_header, ip, tmp);
		_ii_rlse_devs(ip, BMP);
	}
header_checked:

	if (ip->bi_flags&DSW_SHDIMPORT)
		(void) strcpy(uconf.master_vol, "<imported shadow>");
	if (!uconf.master_vol[0] || !uconf.shadow_vol[0]) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EEMPTY));
	}

	/* check that no volume has been given twice */
	if (strncmp(uconf.master_vol, uconf.shadow_vol, DSW_NAMELEN) == 0) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EOPEN));
	}

	if (strncmp(uconf.master_vol, uconf.bitmap_vol, DSW_NAMELEN) == 0) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EOPEN));
	}

	if (strncmp(uconf.bitmap_vol, uconf.shadow_vol, DSW_NAMELEN) == 0) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EOPEN));
	}

	/* check that master is not already a bitmap, shadow or overflow */
	type = ii_volume(uconf.master_vol, 1);
	if (type != NONE && type != MST) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EINUSE));
	}

	/* check that shadow is not used as anything else */
	type = ii_volume(uconf.shadow_vol, 1);
	if (type != NONE && type != SHD) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EINUSE));
	}

	/* Setup the table bitmap operations table */
	switch (ii_bitmap) {
	case II_KMEM:
		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!ii: using volatile bitmaps");
		ip->bi_bitmap_ops = &kmem_buf_bmp;
		break;
	case II_FWC:
		hints = 0;
		(void) nsc_node_hints(&hints);
		if ((hints & NSC_FORCED_WRTHRU) == 0)
			ip->bi_bitmap_ops = &kmem_buf_bmp;
		else
			ip->bi_bitmap_ops = &alloc_buf_bmp;
		if (ii_debug > 0) {
			cmn_err(CE_NOTE, "!ii: chosen to use %s bitmaps",
			    ip->bi_bitmap_ops == &kmem_buf_bmp ?
			    "volatile" : "persistent");
		}
		break;
	case II_WTHRU:
	default:
		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!ii: using persistent bitmaps");
		ip->bi_bitmap_ops = &alloc_buf_bmp;
		break;
	}

	/*
	 * If we found aother shadow volume with the same name,
	 * If this is an resume operation,
	 * If this shadow is in the exported state
	 * then try an on the fly join instead
	 */
	for (hip = _ii_info_top; hip; hip = hip->bi_next)
		if (strcmp(uconf.shadow_vol, hip->bi_keyname) == 0)
				break;
	if ((hip) && (type == SHD) && existing &&
	    (ip->bi_flags & DSW_SHDEXPORT)) {

		/*
		 * Stop any copy in progress
		 */
		while (_ii_stopcopy(hip) == EINTR)
			;

		/*
		 * Start the imported shadow teardown
		 */
		mutex_enter(&hip->bi_mutex);

		/* disable accesss to imported shadow */
		hip->bi_disabled = 1;

		/* Wait for any I/O's to complete */
		while (hip->bi_ioctl) {
			hip->bi_state |= DSW_IOCTL;
			cv_wait(&hip->bi_ioctlcv, &hip->bi_mutex);
		}
		mutex_exit(&hip->bi_mutex);

		/* this rw_enter forces us to drain all active IO */
		rw_enter(&hip->bi_linkrw, RW_WRITER);
		rw_exit(&hip->bi_linkrw);

		/* remove ip from _ii_info_top linked list */
		mutex_enter(&_ii_info_mutex);
		for (ipp = &_ii_info_top; *ipp; ipp = &((*ipp)->bi_next)) {
			if (hip == *ipp) {
				*ipp = hip->bi_next;
				break;
			}
		}
		if (hip->bi_kstat) {
			kstat_delete(hip->bi_kstat);
			hip->bi_kstat = NULL;
		}
		mutex_exit(&_ii_info_mutex);

		/* Gain access to both bitmap volumes */
		rtype = BMP;
		if (((rc = _ii_rsrv_devs(hip, rtype, II_INTERNAL)) != 0) ||
		    ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0)) {
			mutex_exit(&_ii_config_mutex);
			_ii_info_free(ip);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status, rc));
		}

		/* Merge imported bitmap */
		rc = II_JOIN_BMP(ip, hip);

		/* Release access to bitmap volume */
		_ii_rlse_devs(hip, rtype);
		ii_sibling_free(hip);

		/* Clear the fact that we are exported */
		mutex_enter(&ip->bi_mutex);
		II_FLAG_CLR(DSW_SHDEXPORT, ip);

		/* Release resources */
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, BMP);

	} else if (type != NONE) {
		mutex_exit(&_ii_config_mutex);
		_ii_info_free(ip);
		return (spcs_s_ocopyoutf(&kstatus, uconf.status, DSW_EINUSE));
	}

	/*
	 * Handle non-exported shadow
	 */
	if ((ip->bi_flags & DSW_SHDEXPORT) == 0) {
		if ((rc = ii_open_shadow(ip, uconf.shadow_vol)) != 0) {
			mutex_exit(&_ii_config_mutex);
			_ii_info_free(ip);
			spcs_s_add(kstatus, rc);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status,
			    DSW_EOPEN));
		}
	}

	/*
	 * allocate _ii_concopy_sema and set to a value that won't allow
	 * all cache to be allocated by copy loops.
	 */

	if (_ii_concopy_init == 0 && ip->bi_bmpfd != NULL) {
		int asize = 0, wsize;
		nsc_size_t cfbas, maxfbas;

		(void) nsc_cache_sizes(&asize, &wsize);

		if (asize > 0) {
			cfbas = FBA_NUM(asize);
			(void) _ii_rsrv_devs(ip, BMP, II_INTERNAL);
			rc = nsc_maxfbas(ip->bi_bmpfd, 0, &maxfbas);
			_ii_rlse_devs(ip, BMP);
			if (!II_SUCCESS(rc))
				maxfbas = 1024;		/* i.e. _SD_MAX_FBAS */
			ii_nconcopy = cfbas / (maxfbas * 2) / 3;
		}
		if (ii_nconcopy < 2)
			ii_nconcopy = 2;
		ASSERT(ii_nconcopy > 0);
		sema_init(&_ii_concopy_sema, ii_nconcopy, NULL,
		    SEMA_DRIVER, NULL);
		_ii_concopy_init = 1;
	}

	/* check for shared master volume */
	for (hip = _ii_mst_top; hip; hip = hip->bi_nextmst)
		if (strcmp(uconf.master_vol, ii_pathname(hip->bi_mstfd)) == 0)
			break;
	add_to_mst_top = (hip == NULL);
	if (!hip)
		for (hip = _ii_info_top; hip; hip = hip->bi_next)
			if (strcmp(uconf.master_vol,
			    ii_pathname(hip->bi_mstfd)) == 0)
				break;
	nshadows = (hip != NULL);

	/* Check if master is offline */
	if (hip) {
		if (hip->bi_flags & DSW_MSTOFFLINE) {
			mutex_exit(&_ii_config_mutex);
			_ii_info_free(ip);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status,
			    DSW_EOFFLINE));
		}
	}

	if (!nshadows && (ip->bi_flags&DSW_SHDIMPORT) == 0) {
		ip->bi_mstfd = nsc_open(uconf.master_vol,
		    NSC_IIR_ID|NSC_DEVICE|NSC_RDWR, _ii_fd_def,
		    (blind_t)(ip->bi_mstdev), &rc);
		if (!ip->bi_mstfd) {
			mutex_exit(&_ii_config_mutex);
			_ii_info_free(ip);
			spcs_s_add(kstatus, rc);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status,
			    DSW_EOPEN));
		}

		ip->bi_mstrfd = nsc_open(uconf.master_vol,
		    NSC_IIR_ID|NSC_DEVICE|NSC_RDWR, _ii_fd_def,
		    (blind_t)(ip->bi_mstrdev), &rc);
		if (!ip->bi_mstrfd) {
			mutex_exit(&_ii_config_mutex);
			_ii_info_free(ip);
			spcs_s_add(kstatus, rc);
			return (spcs_s_ocopyoutf(&kstatus, uconf.status,
			    DSW_EOPEN));
		}
	}

	ip->bi_head = ip;
	ip->bi_master = ip;

	mutex_enter(&_ii_info_mutex);
	ip->bi_next = _ii_info_top;
	_ii_info_top = ip;
	if (nshadows) {
		/* link new shadow group together with others sharing master */
		if (ii_debug > 0)
			cmn_err(CE_NOTE,
			    "!II: shadow %s shares master %s with other shadow"
			    " groups", uconf.shadow_vol, uconf.master_vol);
		hip = hip->bi_head;
		nsc_kmem_free(ip->bi_mstrdev, sizeof (*ip->bi_mstrdev));
		nsc_kmem_free(ip->bi_mstdev, sizeof (*ip->bi_mstdev));
		ip->bi_mstrdev = hip->bi_mstrdev;
		ip->bi_mstdev = hip->bi_mstdev;
		ip->bi_head = hip;
		ip->bi_sibling = hip->bi_sibling;
		if (add_to_mst_top) {
			hip->bi_nextmst = _ii_mst_top;
			_ii_mst_top = hip;
		}
		hip->bi_sibling = ip;
		ip->bi_master = ip->bi_head->bi_master;
	}
	mutex_exit(&_ii_info_mutex);
	mutex_exit(&_ii_config_mutex);

	keylen = strlen(ip->bi_keyname);
	if (keylen > KSTAT_STRLEN - 1) {
		keyoffset = keylen + 1 - KSTAT_STRLEN;
	} else {
		keyoffset = 0;
	}
	ip->bi_kstat = kstat_create("ii", _ii_instance++,
	    &ip->bi_keyname[ keyoffset ], "iiset", KSTAT_TYPE_NAMED,
	    sizeof (ii_kstat_set) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (ip->bi_kstat) {
		ip->bi_kstat->ks_data = &ii_kstat_set;
		ip->bi_kstat->ks_update = ii_set_stats_update;
		ip->bi_kstat->ks_private = ip;
		kstat_install(ip->bi_kstat);
	} else {
		cmn_err(CE_WARN, "!Unable to create set-specific kstats");
	}

#ifndef DISABLE_KSTATS
	/* create kstats information */
	mutex_init(&ip->bi_kstat_io.statmutex, NULL, MUTEX_DRIVER, NULL);
	if (ip == ip->bi_master) {
		ip->bi_kstat_io.master = _ii_kstat_create(ip, "master");
	} else {
		ip->bi_kstat_io.master = ip->bi_master->bi_kstat_io.master;
		(void) strlcpy(ip->bi_kstat_io.mstio,
		    ip->bi_master->bi_kstat_io.mstio, KSTAT_DATA_CHAR_LEN);
	}
	ip->bi_kstat_io.shadow = _ii_kstat_create(ip, "shadow");
	ip->bi_kstat_io.bitmap = _ii_kstat_create(ip, "bitmap");
#endif

	(void) _ii_reserve_begin(ip);
	rtype = MSTR|SHDR|BMP;
	if ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0) {
		spcs_s_add(kstatus, rc);
		rc = DSW_ERSRVFAIL;
		goto fail;
	}

	if (ip->bi_flags&DSW_SHDIMPORT) {
		rc = 0;		/* no master for imported volumes */
		mst_size = 0;
	} else
		rc = nsc_partsize(MSTFD(ip), &mst_size);
	if (rc == 0 && (ip->bi_flags&DSW_SHDEXPORT) == 0)
		rc = nsc_partsize(SHDFD(ip), &shd_size);
	if (!ip->bi_bmpfd)
		rc = EINVAL;
	if (rc == 0)
		rc = nsc_partsize(ip->bi_bmpfd, &bmp_size);

	if (ip->bi_flags&DSW_SHDIMPORT)
		ip->bi_size = shd_size;
	else
		ip->bi_size = mst_size;

	if ((((ip->bi_flags&DSW_SHDIMPORT) != DSW_SHDIMPORT) &&
	    (mst_size < 1)) ||
	    (((ip->bi_flags&DSW_SHDEXPORT) != DSW_SHDEXPORT) &&
	    (shd_size < 1)) ||
	    ((rc == 0) && (bmp_size < 1))) {
		/* could be really zero, or could be > 1 TB; fail the enable */
		rc = EINVAL;
	}

	if (rc != 0) {	/* rc set means an nsc_partsize() failed */
		/*
		 * If existing group, mark bitmap as offline and set
		 * bmp_size to "right size".
		 */
		if (existing) {
			bmp_size = 2 * DSW_BM_FBA_LEN(mst_size) +
			    DSW_SHD_BM_OFFSET;
			goto no_more_bmp_tests;
		}
		spcs_s_add(kstatus, rc);
		rc = DSW_EPARTSIZE;
		_ii_rlse_devs(ip, rtype);
		_ii_reserve_end(ip);
		goto fail;
	}

	if (ip->bi_flags&DSW_SHDIMPORT)
		mst_size = shd_size;
	if (ip->bi_flags&DSW_SHDEXPORT)
		shd_size = mst_size;
	/*
	 * Check with RDC if the master & shadow sizes are different.
	 * Once II is enabled, the shadow size will be made to appear
	 * the same as the master, and this will panic RDC if we're
	 * changing sizes on it.
	 */
	resized = (shd_size != mst_size);
	if (resized && ii_need_same_size(ip)) {
		cmn_err(CE_WARN, "!Cannot enable II set: would change volume "
		    "size on RDC");
		rc = DSW_EOPACKAGE;
		_ii_rlse_devs(ip, rtype);
		_ii_reserve_end(ip);
		goto fail;
	}
	if (bmp_size < 2 * DSW_BM_FBA_LEN(mst_size) + DSW_SHD_BM_OFFSET) {
		/* bitmap volume too small */
		if (ii_debug > 0)
			cmn_err(CE_NOTE,
			    "!ii: invalid sizes: bmp %" NSC_SZFMT " mst %"
			    NSC_SZFMT " %" NSC_SZFMT "",
			    bmp_size, mst_size, DSW_BM_FBA_LEN(mst_size));
		rc = DSW_EBMPSIZE;
		_ii_rlse_devs(ip, rtype);
		_ii_reserve_end(ip);
		goto fail;
	}
	if ((shd_size < mst_size) && (uconf.flag&DSW_GOLDEN) != 0) {
		/* shadow volume too small */
		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!shd size too small (%" NSC_SZFMT
			    ") for independent set's master (%" NSC_SZFMT ")",
			    shd_size, mst_size);
		rc = DSW_ESHDSIZE;
		_ii_rlse_devs(ip, rtype);
		_ii_reserve_end(ip);
		goto fail;
	}

	ip->bi_busy = kmem_zalloc(1 + (ip->bi_size / (DSW_SIZE * DSW_BITS)),
	    KM_SLEEP);
	if (!ip->bi_busy) {
		rc = ENOMEM;
		_ii_rlse_devs(ip, rtype);
		_ii_reserve_end(ip);
		goto fail;
	}

	if (existing == 0) {

		DTRACE_PROBE(_ii_config);

		/* first time this shadow has been set up */
		mutex_enter(&ip->bi_mutex);
		bm_header = _ii_bm_header_get(ip, &tmp);
		mutex_exit(&ip->bi_mutex);
		if (bm_header == NULL) {
			if (ii_debug > 0)
				cmn_err(CE_WARN,
				    "!ii: _ii_bm_header_get returned NULL");
			rc = DSW_EHDRBMP;
			_ii_rlse_devs(ip, rtype);
			_ii_reserve_end(ip);
			goto fail;
		}
		bzero(bm_header, sizeof (*bm_header));
		/* copy pathnames into it */
		(void) strncpy(bm_header->master_vol, uconf.master_vol,
		    DSW_NAMELEN);
		(void) strncpy(bm_header->shadow_vol, uconf.shadow_vol,
		    DSW_NAMELEN);
		(void) strncpy(bm_header->bitmap_vol, uconf.bitmap_vol,
		    DSW_NAMELEN);
		(void) strncpy(bm_header->clstr_name, uconf.cluster_tag,
		    DSW_NAMELEN);
		(void) strncpy(bm_header->group_name, uconf.group_name,
		    DSW_NAMELEN);

		if (uconf.cluster_tag[0] != 0)
			(void) II_LINK_CLUSTER(ip, uconf.cluster_tag);

		if (uconf.group_name[0] != 0)
			(void) II_LINK_GROUP(ip, uconf.group_name);


		bm_header->ii_state = (uconf.flag & DSW_GOLDEN);
		II_FLAG_ASSIGN(bm_header->ii_state, ip);

		if (import) {
			II_FLAG_SETX(DSW_SHDIMPORT, ip);
			bm_header->ii_state |= DSW_SHDIMPORT;
		}
		if (resized) {
			II_FLAG_SETX(DSW_RESIZED, ip);
			bm_header->ii_state |= DSW_RESIZED;
		}
		bm_header->ii_type = (uconf.flag & DSW_GOLDEN) ?
		    DSW_GOLDEN_TYPE : DSW_QUICK_TYPE;
		bm_header->ii_magic = DSW_DIRTY;
		bm_header->ii_version = II_HEADER_VERSION;
		bm_header->ii_shdfba = DSW_SHD_BM_OFFSET;
		bm_header->ii_copyfba = DSW_COPY_BM_OFFSET;
		bm_header->ii_throttle_delay = ip->bi_throttle_delay;
		bm_header->ii_throttle_unit = ip->bi_throttle_unit;
		ip->bi_shdfba = bm_header->ii_shdfba;
		ip->bi_copyfba = bm_header->ii_copyfba;
		ip->bi_mtime = ddi_get_time();

		/* write it to disk */
		mutex_enter(&ip->bi_mutex);
		rc = _ii_bm_header_put(bm_header, ip, tmp);
		mutex_exit(&ip->bi_mutex);
		if (!II_SUCCESS(rc)) {
			spcs_s_add(kstatus, rc);
			rc = DSW_EHDRBMP;
			_ii_rlse_devs(ip, rtype);
			_ii_reserve_end(ip);
			goto fail;
		}
		if ((shd_size < mst_size) && (uconf.flag & DSW_GOLDEN) == 0) {
		/*
		 * shadow volume smaller than master, must use a dependent
		 * copy with a bitmap file stored mapping for chunk locations.
		 */
					/* number of chunks in shadow volume */
			nsc_size_t shd_chunks;
			nsc_size_t bmp_chunks;
			nsc_size_t tmp_chunks;

			if (ii_debug > 1)
				cmn_err(CE_NOTE, "!ii: using tree index on %s",
				    uconf.master_vol);
			shd_chunks = shd_size / DSW_SIZE;
			/* do not add in partial chunk at end */

			ip->bi_mstchks = mst_size / DSW_SIZE;
			if (mst_size % DSW_SIZE != 0)
				ip->bi_mstchks++;
			bmp_chunks = ii_btsize(bmp_size - ip->bi_copyfba -
			    DSW_BM_FBA_LEN(ip->bi_size));
			tmp_chunks = ip->bi_copyfba +
			    DSW_BM_FBA_LEN(ip->bi_size);
			if (bmp_chunks < (nsc_size_t)ip->bi_mstchks) {
				if (ii_debug > -1) {
					cmn_err(CE_NOTE, "!ii: bitmap vol too"
					    "small: %" NSC_SZFMT " vs. %"
					    NSC_SZFMT, bmp_size,
					    tmp_chunks);
				}
				spcs_s_add(kstatus, rc);
				rc = DSW_EHDRBMP;
				_ii_rlse_devs(ip, rtype);
				_ii_reserve_end(ip);
				goto fail;
			}
			mutex_enter(&ip->bi_mutex);
			II_FLAG_SET(DSW_TREEMAP, ip);
			mutex_exit(&ip->bi_mutex);

			/* following values are written to header by ii_tinit */
#if (defined(NSC_MULTI_TERABYTE) && !defined(II_MULTIMULTI_TERABYTE))
			ASSERT(shd_chunks <= INT32_MAX);
			ASSERT(mst_size / DSW_SIZE <= INT32_MAX);
#endif
			ip->bi_mstchks = mst_size / DSW_SIZE;
			if (mst_size % DSW_SIZE != 0)
				ip->bi_mstchks++;
#ifdef	II_MULTIMULTI_TERABYTE
			ip->bi_shdchks = shd_chunks;
#else
			/* still have 31 bit chunkid's */
			ip->bi_shdchks = (chunkid_t)shd_chunks;
#endif
			ip->bi_shdchkused = 0;
			rc = ii_tinit(ip);
		} else {
			ip->bi_shdchks = shd_size / DSW_SIZE;
			ip->bi_shdchkused = 0;
		}
		if (rc == 0)
			rc = II_LOAD_BMP(ip, 1);
		if (rc == 0)
			rc = II_ZEROBM(ip);
		if (rc == 0)
			rc = II_COPYBM(ip);	/* also clear copy bitmap */
		if (rc == 0 && (uconf.flag & DSW_GOLDEN) && !import)
			rc = ii_fill_copy_bmp(ip);
		if (rc) {
			spcs_s_add(kstatus, rc);
			rc = DSW_EHDRBMP;
			_ii_rlse_devs(ip, rtype);
			goto fail;
		}
		/* check that changing shadow won't upset RDC */
		if (ii_update_denied(ip, kstatus, 0, 1)) {
			rc = DSW_EOPACKAGE;
			_ii_rlse_devs(ip, rtype);
			_ii_reserve_end(ip);
			goto fail;
		}
		ip->bi_disabled = 0;	/* all okay and ready, we can go now */
		_ii_rlse_devs(ip, rtype);
		/* no _ii_reserve_end() here - we must register first */
		ip->bi_bmp_tok = _ii_register_path(ii_pathname(ip->bi_bmpfd),
		    NSC_CACHE|NSC_DEVICE, _ii_io);
		if (!nshadows)
			ii_register_mst(ip);
		ii_register_shd(ip);

		if (!ii_register_ok(ip)) {
			ip->bi_disabled = 1;	/* argh */
			rc = DSW_EREGISTER;
			goto fail;
		}
		/* no _ii_reserve_begin() here -- we're still in process */
		(void) _ii_rsrv_devs(ip, rtype, II_INTERNAL);

		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!ii: config: master %s shadow %s",
			    uconf.master_vol, uconf.shadow_vol);
		rc = 0;
		if ((uconf.flag & DSW_GOLDEN) && !import) {
			mutex_enter(&ip->bi_mutex);
			II_FLAG_SET(DSW_COPYINGM | DSW_COPYINGP, ip);
			ip->bi_ioctl++;	/* we are effectively in an ioctl */
			mutex_exit(&ip->bi_mutex);
			rc = _ii_copyvol(ip, 0, rtype, kstatus, 1);
		}
		_ii_rlse_devs(ip, rtype);
		_ii_reserve_end(ip);

		++iigkstat.num_sets.value.ul;

		return (spcs_s_ocopyoutf(&kstatus, uconf.status, rc));
	}

	ip->bi_shdchks = shd_size / DSW_SIZE;
	ip->bi_shdfba = shdfba;
	ip->bi_copyfba = copyfba;
	rc = II_LOAD_BMP(ip, 0);		/* reload saved bitmap */
	mutex_enter(&ip->bi_mutex);
	if (rc == 0)
		bm_header = _ii_bm_header_get(ip, &tmp);
	mutex_exit(&ip->bi_mutex);
	if (rc || bm_header == NULL) {
		if (existing) {
			goto no_more_bmp_tests;
		}
		rc = DSW_EHDRBMP;
		goto fail;
	}

	/*
	 * If the header is dirty and it wasn't kept on persistent storage
	 * then the bitmaps must be assumed to be bad.
	 */
	if (bm_header->ii_magic == DSW_DIRTY &&
	    ip->bi_bitmap_ops != &alloc_buf_bmp) {
		type = bm_header->ii_type;
		_ii_bm_header_free(bm_header, ip, tmp);
		if (type == DSW_GOLDEN_TYPE) {
			if ((ip->bi_flags & DSW_COPYINGM) != 0)
				_ii_error(ip, DSW_SHDOFFLINE);
			else if ((ip->bi_flags & DSW_COPYINGS) != 0)
				_ii_error(ip, DSW_MSTOFFLINE);
			else {
				/* No copying, so they're just different */
				rc = ii_fill_copy_bmp(ip);
				if (rc) {
					spcs_s_add(kstatus, rc);
					rc = DSW_EHDRBMP;
					goto fail;
				}
			}
		} else
			_ii_error(ip, DSW_SHDOFFLINE);

		mutex_enter(&ip->bi_mutex);
		bm_header = _ii_bm_header_get(ip, &tmp);
		mutex_exit(&ip->bi_mutex);
		if (bm_header == NULL) {
			rc = DSW_EHDRBMP;
			goto fail;
		}
	}

	bm_header->ii_magic = DSW_DIRTY;
	mutex_enter(&ip->bi_mutex);
	rc = _ii_bm_header_put(bm_header, ip, tmp);
	mutex_exit(&ip->bi_mutex);
	if (!II_SUCCESS(rc)) {
		spcs_s_add(kstatus, rc);
		rc = DSW_EHDRBMP;
		goto fail;
	}

	ip->bi_bmp_tok = _ii_register_path(ii_pathname(ip->bi_bmpfd),
	    NSC_CACHE|NSC_DEVICE, _ii_io);
no_more_bmp_tests:
	_ii_rlse_devs(ip, rtype);
	ip->bi_disabled = 0;	/* all okay and ready, we can go now */
	if (!nshadows)
		ii_register_mst(ip);
	if ((ip->bi_flags & DSW_SHDEXPORT) == 0)
		ii_register_shd(ip);

	if (!ii_register_ok(ip)) {
		rc = DSW_EREGISTER;
		goto fail;
	}
	_ii_reserve_end(ip);

	if (ii_debug > 0)
		cmn_err(CE_NOTE, "!ii: config: master %s shadow %s",
		    uconf.master_vol, uconf.shadow_vol);

	rc = 0;
	if (ip->bi_flags & DSW_COPYINGP) {
		/* Copy was in progress, so continue it */
		(void) _ii_rsrv_devs(ip, rtype, II_INTERNAL);
		mutex_enter(&ip->bi_mutex);
		ip->bi_ioctl++;		/* we are effectively in an ioctl */
		mutex_exit(&ip->bi_mutex);
		rc = _ii_copyvol(ip, ((ip->bi_flags & DSW_COPYINGS) != 0) ?
		    CV_SHD2MST : 0, rtype, kstatus, 0);
	}

	++iigkstat.num_sets.value.ul;

	return (spcs_s_ocopyoutf(&kstatus, uconf.status, rc));

fail:
	/* remove ip from _ii_info_top linked list */
	mutex_enter(&_ii_info_mutex);
	for (ipp = &_ii_info_top; *ipp; ipp = &((*ipp)->bi_next)) {
		if (ip == *ipp) {
			*ipp = ip->bi_next;
			break;
		}
	}
	mutex_exit(&_ii_info_mutex);
	ii_sibling_free(ip);

	return (spcs_s_ocopyoutf(&kstatus, uconf.status, rc));
}

static int
_ii_perform_disable(char *setname, spcs_s_info_t *kstatusp, int reclaim)
{
	_ii_info_t **xip, *ip;
	_ii_overflow_t *op;
	nsc_buf_t *tmp = NULL;
	int rc;
	ii_header_t *bm_header;
	int rtype;

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(setname);
	if (ip == NULL) {
		mutex_exit(&_ii_info_mutex);
		return (DSW_ENOTFOUND);
	}

	if ((ip->bi_flags & DSW_GOLDEN) &&
	    ((ip->bi_flags & DSW_COPYINGP) != 0)) {
		/*
		 * Cannot disable an independent copy while still copying
		 * as it means that a data dependency exists.
		 */
		mutex_exit(&_ii_info_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		DTRACE_PROBE(_ii_perform_disable_end_DSW_EDEPENDENCY);
		return (DSW_EDEPENDENCY);
	}

	if ((ip->bi_flags & DSW_GOLDEN) == 0 &&
	    ii_update_denied(ip, *kstatusp, 0, 1)) {
		/* Cannot disable a dependent shadow while RDC is unsure */
		mutex_exit(&_ii_info_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		DTRACE_PROBE(DSW_EOPACKAGE);
		return (DSW_EOPACKAGE);
	}

	if (((ip->bi_flags & DSW_RESIZED) == DSW_RESIZED) &&
	    ii_need_same_size(ip)) {
		/* We can't disable the set whilst RDC is using it */
		mutex_exit(&_ii_info_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		cmn_err(CE_WARN, "!Cannot disable II set: would change "
		    "volume size on RDC");
		DTRACE_PROBE(DSW_EOPACKAGE_resize);
		return (DSW_EOPACKAGE);
	}

	ip->bi_disabled = 1;
	if (NSHADOWS(ip) && (ip->bi_master == ip)) {
		ip->bi_flags &= (~DSW_COPYING);
		ip->bi_state |= DSW_MULTIMST;
	}
	mutex_exit(&_ii_info_mutex);

	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	_ii_stopvol(ip);

	rtype = SHDR|BMP;
	if ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0) {
		spcs_s_add(*kstatusp, rc);
		DTRACE_PROBE(DSW_ERSRVFAIL);
		return (DSW_ERSRVFAIL);
	}

	if ((ii_header < 128) &&
	    (((ip->bi_flags & DSW_GOLDEN) == 0) ||
	    (ip->bi_flags & DSW_COPYING))) {
		/*
		 * Not a full copy so attempt to prevent use of partial copy
		 * by clearing where the first ufs super-block would be
		 * located. Solaris often incorporates the disk header into
		 * the start of the first slice, so avoid clearing the very
		 * first 16 blocks of the volume.
		 */

		if (ii_debug > 1)
			cmn_err(CE_NOTE, "!ii: Shadow copy invalidated");
		II_READ_START(ip, shadow);
		rc = nsc_alloc_buf(SHDFD(ip), ii_header, 128 - ii_header,
		    NSC_RDWRBUF, &tmp);
		II_READ_END(ip, shadow, rc, 128 - ii_header);
		if (II_SUCCESS(rc)) {
			rc = nsc_zero(tmp, ii_header, 128 - ii_header, 0);
			if (II_SUCCESS(rc)) {
				II_NSC_WRITE(ip, shadow, rc, tmp, ii_header,
				    (128 - ii_header), 0);
			}
		}
		if (tmp)
			(void) nsc_free_buf(tmp);
		if (!II_SUCCESS(rc))
			_ii_error(ip, DSW_SHDOFFLINE);
	}

	/* this rw_enter forces us to drain all active IO */
	rw_enter(&ip->bi_linkrw, RW_WRITER);
	rw_exit(&ip->bi_linkrw);

	/* remove ip from _ii_info_top linked list */
	mutex_enter(&_ii_info_mutex);
	for (xip = &_ii_info_top; *xip; xip = &((*xip)->bi_next)) {
		if (ip == *xip) {
			*xip = ip->bi_next;
			break;
		}
	}
	if (ip->bi_kstat) {
		kstat_delete(ip->bi_kstat);
		ip->bi_kstat = NULL;
	}
	mutex_exit(&_ii_info_mutex);

	rc = II_SAVE_BMP(ip, 1);
	mutex_enter(&ip->bi_mutex);
	if (rc == 0)
		bm_header = _ii_bm_header_get(ip, &tmp);
	if (rc == 0 && bm_header) {
		if (ii_debug > 1)
			cmn_err(CE_NOTE, "!ii: Invalid header written");
		bm_header->ii_magic = DSW_INVALID;
		/* write it to disk */
		(void) _ii_bm_header_put(bm_header, ip, tmp);
	}
	mutex_exit(&ip->bi_mutex);

	op = ip->bi_overflow;
	if (op && (reclaim == -1)) {
		reclaim = (op->ii_drefcnt == 1? NO_RECLAIM : RECLAIM);
	}

	if ((op != NULL) && (op->ii_hversion >= 1) &&
	    (op->ii_hmagic == II_OMAGIC)) {
		mutex_enter(&_ii_overflow_mutex);
		if (ip->bi_flags & DSW_OVRHDRDRTY) {
			mutex_enter(&ip->bi_mutex);
			ip->bi_flags &= ~DSW_OVRHDRDRTY;
			mutex_exit(&ip->bi_mutex);
			ASSERT(op->ii_urefcnt > 0);
			op->ii_urefcnt--;
		}
		if (op->ii_urefcnt == 0) {
			op->ii_flags &= ~IIO_CNTR_INVLD;
			op->ii_unused = op->ii_nchunks - 1;
		}
		mutex_exit(&_ii_overflow_mutex);
	}
	ii_overflow_free(ip, reclaim);
	_ii_rlse_devs(ip, rtype);

	ii_sibling_free(ip);

	--iigkstat.num_sets.value.ul;
	return (0);
}

/*
 * _ii_disable
 *	Deconfigures an II pair
 *
 * Calling/Exit State:
 *	Returns 0 if the pair was disabled. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 *
 * Description:
 *	Reads the user configuration structure and attempts to
 *	deconfigure that pairing based on the master device pathname.
 */

int
_ii_disable(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uparms;
	dsw_ioctl32_t uparms32;
	_ii_overflow_t *op;
	int rc, rerr;
	spcs_s_info_t kstatus;
	uint64_t hash;
	int reclaim;
	_ii_lsthead_t *oldhead, **head;
	_ii_lstinfo_t *np, **xnp, *oldp;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &uparms32, sizeof (uparms32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uparms, uparms32, shadow_vol, dsw_ioctl_t);
		uparms.status = (spcs_s_info_t)uparms32.status;
	} else if (copyin((void *)arg, &uparms, sizeof (uparms)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uparms.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EEMPTY));

	DTRACE_PROBE2(_ii_disable_info, char *, uparms.shadow_vol,
	    int, uparms.flags);

	/* group or single set? */
	if (uparms.flags & CV_IS_GROUP) {
		hash = nsc_strhash(uparms.shadow_vol);
		mutex_enter(&_ii_group_mutex);
		for (head = &_ii_group_top; *head;
		    head = &((*head)->lst_next)) {
			if ((hash == (*head)->lst_hash) &&
			    strncmp((*head)->lst_name, uparms.shadow_vol,
			    DSW_NAMELEN) == 0)
				break;
		}

		if (!*head) {
			mutex_exit(&_ii_group_mutex);
			return (spcs_s_ocopyoutf(&kstatus, uparms.status,
			    DSW_EGNOTFOUND));
		}

		/* clear any overflow vol usage counts */
		for (np = (*head)->lst_start; np; np = np->lst_next) {
			if (np->lst_ip->bi_overflow) {
				np->lst_ip->bi_overflow->ii_detachcnt = 0;
			}
		}

		/* now increment */
		for (np = (*head)->lst_start; np; np = np->lst_next) {
			if (np->lst_ip->bi_overflow) {
				++np->lst_ip->bi_overflow->ii_detachcnt;
			}
		}

		/* finally, disable all group members */
		rerr = 0;
		xnp = &(*head)->lst_start;
		while (*xnp) {
			op = (*xnp)->lst_ip->bi_overflow;
			if (op) {
				reclaim = (op->ii_drefcnt == op->ii_detachcnt?
				    NO_RECLAIM : RECLAIM);
				--op->ii_detachcnt;
			}

			/* clear out the group pointer */
			(*xnp)->lst_ip->bi_group = NULL;

			rc = _ii_perform_disable((*xnp)->lst_ip->bi_keyname,
			    &kstatus, reclaim);
			if (rc) {
				/* restore group name */
				(*xnp)->lst_ip->bi_group = (*head)->lst_name;

				/* restore detachcnt */
				if (op) {
					++op->ii_detachcnt;
				}

				/* don't delete branch */
				++rerr;
				spcs_s_add(kstatus, rc);

				/* move forward in linked list */
				xnp = &(*xnp)->lst_next;
			} else {
				oldp = (*xnp);
				*xnp = (*xnp)->lst_next;
				kmem_free(oldp, sizeof (_ii_lstinfo_t));
			}
		}
		if (rerr) {
			mutex_exit(&_ii_group_mutex);
			return (spcs_s_ocopyoutf(&kstatus, uparms.status,
			    DSW_EDISABLE));
		}
		/* no errors, all sets disabled, OK to free list head */
		oldhead = *head;
		*head = (*head)->lst_next;
		kmem_free(oldhead, sizeof (_ii_lsthead_t));
		mutex_exit(&_ii_group_mutex);
	} else {
		/* only a single set is being disabled */
		rc = _ii_perform_disable(uparms.shadow_vol, &kstatus, -1);
		if (rc)
			return (spcs_s_ocopyoutf(&kstatus, uparms.status, rc));
	}

	spcs_s_kfree(kstatus);

	return (0);
}


/*
 * _ii_stat
 *	Get state of the shadow.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise an error code is returned
 *	and any additional error information is copied out to the user.
 *	The size variable in the dsw_stat_t is set to the FBA size
 *	of the volume, the stat variable is set to the state, and
 *	the structure is copied out.
 */
/*ARGSUSED*/
int
_ii_stat(intptr_t arg, int ilp32, int *rvp)
{
	dsw_stat_t ustat;
	dsw_stat32_t ustat32;
	_ii_info_t *ip;
	spcs_s_info_t kstatus;
	char *group, *cluster;

	if (ilp32) {
		if (copyin((void *)arg, &ustat32, sizeof (ustat32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ustat, ustat32, shadow_vol, dsw_stat_t);
		ustat.status = (spcs_s_info_t)ustat32.status;
	} else if (copyin((void *)arg, &ustat, sizeof (ustat)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!ustat.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, ustat.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(ustat.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, ustat.status,
		    DSW_ENOTFOUND));

	ustat.stat = ip->bi_flags;
	ustat.size = ip->bi_size;
	ustat.mtime = ip->bi_mtime;

	if (ilp32)
		bzero(ustat32.overflow_vol, DSW_NAMELEN);
	else
		bzero(ustat.overflow_vol, DSW_NAMELEN);
	if (ip->bi_overflow) {
		(void) strncpy(ilp32 ? ustat32.overflow_vol :
		    ustat.overflow_vol, ip->bi_overflow->ii_volname,
		    DSW_NAMELEN);
	}

	ustat.shdsize = ip->bi_shdchks;
	if ((ip->bi_flags) & DSW_TREEMAP) {
		ustat.shdused = ip->bi_shdchkused;
	} else {
		ustat.shdused = 0;
	}

	/* copy over group and cluster associations */
	group = ilp32? ustat32.group_name : ustat.group_name;
	cluster = ilp32? ustat32.cluster_tag : ustat.cluster_tag;
	bzero(group, DSW_NAMELEN);
	bzero(cluster, DSW_NAMELEN);
	if (ip->bi_group)
		(void) strncpy(group, ip->bi_group, DSW_NAMELEN);
	if (ip->bi_cluster)
		(void) strncpy(cluster, ip->bi_cluster, DSW_NAMELEN);

	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	spcs_s_kfree(kstatus);
	if (ilp32) {
		ustat32.stat = ustat.stat;
		ustat32.size = ustat.size;
		ustat32.shdsize = ustat.shdsize;
		ustat32.shdused = ustat.shdused;
		ustat32.mtime = ustat.mtime;
		if (copyout(&ustat32, (void *)arg, sizeof (ustat32)))
			return (EFAULT);
	} else if (copyout(&ustat, (void *)arg, sizeof (ustat)))
		return (EFAULT);

	return (0);
}


/*
 * _ii_list
 *	List what shadow sets are currently configured.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise an error code is returned
 *	and any additional error information is copied out to the user.
 */
/*ARGSUSED*/
int
_ii_list(intptr_t arg, int ilp32, int *rvp)
{
	dsw_list_t ulist;
	dsw_list32_t ulist32;
	_ii_info_t *ip;
	dsw_config_t cf, *cfp;
	dsw_config32_t cf32, *cf32p;
	int rc;
	int used;
	spcs_s_info_t kstatus;

	if (ilp32) {
		if (copyin((void *)arg, &ulist32, sizeof (ulist32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ulist, ulist32, list_size, dsw_list_t);
		ulist.status = (spcs_s_info_t)ulist32.status;
	} else if (copyin((void *)arg, &ulist, sizeof (ulist)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	cf32p = (dsw_config32_t *)(unsigned long)ulist32.list;
	cfp = ulist.list;
	ulist.list_used = 0;
	mutex_enter(&_ii_info_mutex);
	ip = _ii_info_top;

	DTRACE_PROBE1(_ii_list_count, int, ulist.list_size);

	for (rc = used = 0; used < ulist.list_size && ip; ip = ip->bi_next) {

		if (ip->bi_disabled)
			continue;

		mutex_enter(&ip->bi_mutex);
		ip->bi_ioctl++;
		if (ilp32) {
			bzero(&cf32, sizeof (cf32));
			cf32.flag = ip->bi_flags;
			(void) strncpy(cf32.master_vol,
			    ii_pathname(ip->bi_mstfd), DSW_NAMELEN);
			(void) strncpy(cf32.shadow_vol,
			    ip->bi_keyname, DSW_NAMELEN);
			(void) strncpy(cf32.bitmap_vol, (ip->bi_bmpfd)
			    ? ii_pathname(ip->bi_bmpfd)
			    : "<offline_bitmap>", DSW_NAMELEN);
			if (copyout(&cf32, (void *)cf32p, sizeof (cf32)))
				rc = EFAULT;
			cf32p++;
		} else {
			bzero(&cf, sizeof (cf));
			cf.flag = ip->bi_flags;
			(void) strncpy(cf.master_vol,
			    ii_pathname(ip->bi_mstfd), DSW_NAMELEN);
			(void) strncpy(cf.shadow_vol,
			    ip->bi_keyname, DSW_NAMELEN);
			(void) strncpy(cf.bitmap_vol, (ip->bi_bmpfd)
			    ? ii_pathname(ip->bi_bmpfd)
			    : "<offline_bitmap>", DSW_NAMELEN);
			if (copyout(&cf, (void *)cfp, sizeof (cf)))
				rc = EFAULT;
			cfp++;
		}
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		used++;
	}
	mutex_exit(&_ii_info_mutex);

	spcs_s_kfree(kstatus);
	if (rc)
		return (rc);

	ulist.list_used = used;
	if (ilp32) {
		ulist32.list_used = ulist.list_used;
		if (copyout(&ulist32, (void *)arg, sizeof (ulist32)))
			return (EFAULT);
	} else if (copyout(&ulist, (void *)arg, sizeof (ulist)))
		return (EFAULT);

	return (0);
}

/*
 * _ii_listlen
 *	Counts the number of items the DSWIOC_LIST and DSWIOC_OLIST
 *	ioctl calls would return.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise an error code is returned.
 *	Result is returned as successful ioctl value.
 */
/*ARGSUSED*/
int
_ii_listlen(int cmd, int ilp32, int *rvp)
{
	_ii_info_t *ip;
	_ii_overflow_t *op;
	int count = 0;

	switch (cmd) {

	case DSWIOC_LISTLEN:
		mutex_enter(&_ii_info_mutex);
		for (ip = _ii_info_top; ip; ip = ip->bi_next) {
			if (ip->bi_disabled == 0) {
				count++;
			}
		}
		mutex_exit(&_ii_info_mutex);
		break;
	case DSWIOC_OLISTLEN:
		mutex_enter(&_ii_overflow_mutex);
		for (op = _ii_overflow_top; op; op = op->ii_next)
			count++;
		mutex_exit(&_ii_overflow_mutex);
		break;
	default:
		return (EINVAL);
	}
	*rvp = count;

	return (0);
}

/*
 * _ii_report_bmp
 *
 *	Report to the user daemon that the bitmap has gone bad
 */
static int
_ii_report_bmp(_ii_info_t *ip)
{
	int rc;
	struct nskernd *nsk;

	nsk = kmem_zalloc(sizeof (*nsk), KM_SLEEP);
	if (!nsk) {
		return (ENOMEM);
	}
	nsk->command = NSKERND_IIBITMAP;
	nsk->data1 = (int64_t)(ip->bi_flags | DSW_BMPOFFLINE);
	(void) strncpy(nsk->char1, ip->bi_keyname,
	    min(DSW_NAMELEN, NSC_MAXPATH));

	rc = nskernd_get(nsk);
	if (rc == 0) {
		rc = (int)nsk->data1;
	}
	if (rc == 0) {
		DTRACE_PROBE(_ii_report_bmp_end);
	} else {
		DTRACE_PROBE1(_ii_report_bmp_end_2, int, rc);
	}
	kmem_free(nsk, sizeof (*nsk));
	return (rc);
}

/*
 * _ii_offline
 *	Set volume offline flag(s) for a shadow.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise an error code is returned
 *	and any additional error information is copied out to the user.
 */
/*ARGSUSED*/
int
_ii_offline(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uparms;
	dsw_ioctl32_t uparms32;
	_ii_info_t *ip;
	int rc;
	spcs_s_info_t kstatus;

	if (ilp32) {
		if (copyin((void *)arg, &uparms32, sizeof (uparms32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uparms, uparms32, shadow_vol, dsw_ioctl_t);
		uparms.status = (spcs_s_info_t)uparms32.status;
	} else if (copyin((void *)arg, &uparms, sizeof (uparms)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uparms.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(uparms.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, uparms.status,
		    DSW_ENOTFOUND));

	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status,
		    DSW_ERSRVFAIL));
	}

	mutex_exit(&ip->bi_mutex);
	_ii_error(ip, uparms.flags & DSW_OFFLINE);
	mutex_enter(&ip->bi_mutex);
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	_ii_rlse_devs(ip, BMP);

	spcs_s_kfree(kstatus);

	return (0);
}


/*
 * _ii_wait
 *	Wait for a copy to complete.
 *
 * Calling/Exit State:
 *	Returns 0 if the copy completed, otherwise error code.
 *
 */
/*ARGSUSED*/
int
_ii_wait(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uparms;
	dsw_ioctl32_t uparms32;
	_ii_info_t *ip;
	int rc = 0;
	spcs_s_info_t kstatus;

	if (ilp32) {
		if (copyin((void *)arg, &uparms32, sizeof (uparms32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uparms, uparms32, shadow_vol, dsw_ioctl_t);
		uparms.status = (spcs_s_info_t)uparms32.status;
		uparms.pid = uparms32.pid;
	} else if (copyin((void *)arg, &uparms, sizeof (uparms)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uparms.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(uparms.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, uparms.status,
		    DSW_ENOTFOUND));

	while (ip->bi_flags & DSW_COPYINGP) {
		if (cv_wait_sig(&ip->bi_copydonecv, &ip->bi_mutex) == 0) {
			/* Awoken by a signal */
			rc = EINTR;
			break;
		}
	}

	/* Is this an attempt to unlock the copy/update PID? */
	if (uparms.flags & CV_LOCK_PID) {
		if (ip->bi_locked_pid == 0) {
			rc = DSW_ENOTLOCKED;
		} else if (uparms.pid == -1) {
			cmn_err(CE_WARN, "!ii: Copy/Update PID %d, cleared",
			    ip->bi_locked_pid);
			ip->bi_locked_pid = 0;
		} else if (uparms.pid != ip->bi_locked_pid) {
			rc = DSW_EINUSE;
		} else {
			ip->bi_locked_pid = 0;
		}
	}

	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	return (spcs_s_ocopyoutf(&kstatus, uparms.status, rc));
}


static int
_ii_reset_mstvol(_ii_info_t *ip)
{
	_ii_info_t *xip;

	if (!NSHADOWS(ip))
		return (DSW_COPYINGS | DSW_COPYINGP);

	/* check for siblings updating master */
	for (xip = ip->bi_head; xip; xip = xip->bi_sibling) {
		if (xip == ip)
			continue;
		/* check if master is okay */
		if ((xip->bi_flags & DSW_MSTOFFLINE) == 0) {
			return (0);
		}
	}

	return (DSW_COPYINGS | DSW_COPYINGP);
}

/*
 * _ii_reset
 *	Reset offlined underlying volumes
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise an error code is returned
 *	and any additional error information is copied out to the user.
 */
/*ARGSUSED*/
int
_ii_reset(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uparms;
	dsw_ioctl32_t uparms32;
	_ii_info_t *ip;
	nsc_buf_t *tmp = NULL;
	int rc;
	int flags;
	ii_header_t *bm_header;
	spcs_s_info_t kstatus;
	int rtype;

	if (ilp32) {
		if (copyin((void *)arg, &uparms32, sizeof (uparms32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uparms, uparms32, shadow_vol, dsw_ioctl_t);
		uparms.status = (spcs_s_info_t)uparms32.status;
	} else if (copyin((void *)arg, &uparms, sizeof (uparms)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uparms.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(uparms.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, uparms.status,
		    DSW_ENOTFOUND));

	mutex_exit(&ip->bi_mutex);

	/* Figure out what to do according to what was flagged as  */

	if ((ip->bi_flags & DSW_OFFLINE) == 0) {
		/* Nothing offline, so no op */
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_kfree(kstatus);
		return (0);
	}

	if (!ip->bi_bmpfd) {
		/* No bitmap fd, can't do anything */
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_kfree(kstatus);
		return (DSW_EHDRBMP);
	}

	rtype = MSTR|SHDR|BMP;
	if ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0) {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status,
		    DSW_ERSRVFAIL));
	}

	/*
	 * Cannot use _ii_bm_header_get as it will fail if DSW_BMPOFFLINE
	 */
	II_READ_START(ip, bitmap);
	rc = nsc_alloc_buf(ip->bi_bmpfd, 0, FBA_LEN(sizeof (ii_header_t)),
	    NSC_RDWRBUF, &tmp);
	II_READ_END(ip, bitmap, rc, FBA_LEN(sizeof (ii_header_t)));
	if (!II_SUCCESS(rc)) {
		_ii_rlse_devs(ip, rtype);
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		if (tmp)
			(void) nsc_free_buf(tmp);
		_ii_error(ip, DSW_BMPOFFLINE);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EHDRBMP));
	}

	bm_header = (ii_header_t *)(tmp)->sb_vec[0].sv_addr;
	if (bm_header == NULL) {
		_ii_rlse_devs(ip, rtype);
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		if (tmp)
			(void) nsc_free_buf(tmp);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EHDRBMP));
	}

	flags = ip->bi_flags & ~DSW_COPY_FLAGS;
	if ((flags & (DSW_SHDIMPORT|DSW_SHDEXPORT)) == 0) {
		if (((flags & DSW_SHDOFFLINE) == 0) &&
		    ((flags & DSW_MSTOFFLINE) == DSW_MSTOFFLINE)) {
			/* Shadow was OK but master was offline */
			flags |= _ii_reset_mstvol(ip);
		} else if ((flags & DSW_SHDOFFLINE) == DSW_SHDOFFLINE) {
			/* Shadow was offline, don't care what the master was */
			flags |= (DSW_COPYINGM | DSW_COPYINGP);
		}
	}
	if (ip->bi_flags & DSW_VOVERFLOW) {
		ip->bi_flags &= ~DSW_VOVERFLOW;
		ip->bi_flags |= DSW_FRECLAIM;
	}
	flags &= ~(DSW_OFFLINE | DSW_CFGOFFLINE | DSW_VOVERFLOW | DSW_OVERFLOW);
	if ((ip->bi_flags & DSW_BMPOFFLINE) == DSW_BMPOFFLINE) {
		/* free any overflow allocation */
		ii_overflow_free(ip, INIT_OVR);
		/* Bitmap now OK, so set up new bitmap header */
		(void) strncpy(bm_header->master_vol, ii_pathname(ip->bi_mstfd),
		    DSW_NAMELEN);
		(void) strncpy(bm_header->shadow_vol, ii_pathname(ip->bi_shdfd),
		    DSW_NAMELEN);
		(void) strncpy(bm_header->bitmap_vol, ii_pathname(ip->bi_bmpfd),
		    DSW_NAMELEN);
		if (ip->bi_cluster) {
			(void) strncpy(bm_header->clstr_name, ip->bi_cluster,
			    DSW_NAMELEN);
		}
		if (ip->bi_group) {
			(void) strncpy(bm_header->group_name, ip->bi_group,
			    DSW_NAMELEN);
		}
		bm_header->ii_type = (flags & DSW_GOLDEN) ?
		    DSW_GOLDEN_TYPE : DSW_QUICK_TYPE;
		bm_header->ii_magic = DSW_DIRTY;
		bm_header->ii_version = II_HEADER_VERSION;
		bm_header->ii_shdfba = DSW_SHD_BM_OFFSET;
		bm_header->ii_copyfba = DSW_COPY_BM_OFFSET;
		bm_header->ii_throttle_delay = ip->bi_throttle_delay;
		bm_header->ii_throttle_unit = ip->bi_throttle_unit;
		ip->bi_shdfba = bm_header->ii_shdfba;
		ip->bi_copyfba = bm_header->ii_copyfba;
	} else if ((ip->bi_flags & DSW_SHDOFFLINE) == DSW_SHDOFFLINE) {
		/* bitmap didn't go offline, but shadow did */
		if (ip->bi_overflow) {
			ii_overflow_free(ip, RECLAIM);
		}
	}
	_ii_lock_chunk(ip, II_NULLCHUNK);
	mutex_enter(&ip->bi_mutex);
	II_FLAG_ASSIGN(flags, ip);

	mutex_exit(&ip->bi_mutex);
	rc = ii_fill_copy_bmp(ip);
	if (rc == 0)
		rc = II_ZEROBM(ip);
	if (rc == 0) {
		if ((ip->bi_flags&(DSW_GOLDEN)) == 0) {
			/* just clear bitmaps for dependent copy */
			if (ip->bi_flags & DSW_TREEMAP) {
				bm_header->ii_state = ip->bi_flags;
				mutex_enter(&ip->bi_mutex);
				rc = _ii_bm_header_put(bm_header, ip, tmp);
				mutex_exit(&ip->bi_mutex);
				tmp = NULL;
				if (rc == 0) {
					rc = ii_tinit(ip);
					if (rc == 0) {
						mutex_enter(&ip->bi_mutex);
						bm_header =
						    _ii_bm_header_get(ip, &tmp);
						mutex_exit(&ip->bi_mutex);
					}
				}
			}

			if (rc == 0)
				II_FLAG_CLRX(DSW_COPY_FLAGS, ip);
			/*
			 * if copy flags were set, another process may be
			 * waiting
			 */
			if (rc == 0 && (flags & DSW_COPYINGP))
				cv_broadcast(&ip->bi_copydonecv);

			if (rc == 0)
				rc = II_COPYBM(ip);
		}
	}
	_ii_unlock_chunk(ip, II_NULLCHUNK);
	if (rc) {
		if (tmp)
			_ii_bm_header_free(bm_header, ip, tmp);
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EHDRBMP));
	}
	bm_header->ii_state = ip->bi_flags;
	mutex_enter(&ip->bi_mutex);
	rc = _ii_bm_header_put(bm_header, ip, tmp);
	if (!II_SUCCESS(rc)) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EHDRBMP));
	}

	/* check with RDC */
	if (ii_update_denied(ip, kstatus, (ip->bi_flags & DSW_COPYINGS) ?
	    CV_SHD2MST : 0, 1)) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, rc));
	}

	/* don't perform copy for dependent shadows */
	if ((ip->bi_flags&(DSW_GOLDEN)) == 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, rc));
	}

	mutex_exit(&ip->bi_mutex);
	/* _ii_copyvol calls _ii_ioctl_done() */
	if (ip->bi_flags & DSW_COPYINGS)
		rc = _ii_copyvol(ip, CV_SHD2MST, rtype, kstatus, 1);
	else if (ip->bi_flags & DSW_COPYINGM)
		rc = _ii_copyvol(ip, 0, rtype, kstatus, 1);
	else {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
	}

	_ii_rlse_devs(ip, rtype);

	return (spcs_s_ocopyoutf(&kstatus, uparms.status, rc));
}


/*
 * _ii_version
 *	Get version of the InstantImage module.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise EFAULT is returned.
 *	The major and minor revisions are copied out to the user if
 *	successful.
 */
/*ARGSUSED*/
int
_ii_version(intptr_t arg, int ilp32, int *rvp)
{
	dsw_version_t uversion;
	dsw_version32_t uversion32;

	if (ilp32) {
		if (copyin((void *)arg, &uversion32, sizeof (uversion32)) < 0)
			return (EFAULT);

		uversion32.major = dsw_major_rev;
		uversion32.minor = dsw_minor_rev;
		uversion32.micro = dsw_micro_rev;
		uversion32.baseline = dsw_baseline_rev;

		if (copyout(&uversion32, (void *)arg, sizeof (uversion32)))
			return (EFAULT);
	} else {
		if (copyin((void *)arg, &uversion, sizeof (uversion)) < 0)
			return (EFAULT);

		uversion.major = dsw_major_rev;
		uversion.minor = dsw_minor_rev;
		uversion.micro = dsw_micro_rev;
		uversion.baseline = dsw_baseline_rev;

		if (copyout(&uversion, (void *)arg, sizeof (uversion)))
			return (EFAULT);
	}

	return (0);
}

/*
 * _ii_copyparm
 *	Get and set copy parameters.
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise EFAULT is returned.
 *	The previous values are returned to the user.
 */
/*ARGSUSED*/
int
_ii_copyparm(intptr_t arg, int ilp32, int *rvp)
{
	dsw_copyp_t copyp;
	dsw_copyp32_t copyp32;
	spcs_s_info_t kstatus;
	_ii_info_t *ip;
	int rc = 0;
	int tmp;

	if (ilp32) {
		if (copyin((void *)arg, &copyp32, sizeof (copyp32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(copyp, copyp32, shadow_vol, dsw_copyp_t);
		copyp.status = (spcs_s_info_t)copyp32.status;
	} else if (copyin((void *)arg, &copyp, sizeof (copyp)) < 0)
			return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!copyp.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, copyp.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(copyp.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, copyp.status,
		    DSW_ENOTFOUND));

	tmp = ip->bi_throttle_delay;
	if (copyp.copy_delay != -1) {
		if (copyp.copy_delay >= MIN_THROTTLE_DELAY &&
		    copyp.copy_delay <= MAX_THROTTLE_DELAY)
			ip->bi_throttle_delay = copyp.copy_delay;
		else {
			cmn_err(CE_WARN, "!ii: delay out of range %d",
			    copyp.copy_delay);
			rc = EINVAL;
		}
	}
	copyp.copy_delay = tmp;

	tmp = ip->bi_throttle_unit;
	if (copyp.copy_unit != -1) {
		if (copyp.copy_unit >= MIN_THROTTLE_UNIT &&
		    copyp.copy_unit <= MAX_THROTTLE_UNIT) {
			if (rc != EINVAL)
				ip->bi_throttle_unit = copyp.copy_unit;
		} else {
			cmn_err(CE_WARN, "!ii: unit out of range %d",
			    copyp.copy_unit);
			if (rc != EINVAL) {
				rc = EINVAL;
				ip->bi_throttle_delay = copyp.copy_delay;
			}
		}
	}
	copyp.copy_unit = tmp;

	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	if (ilp32) {
		copyp32.copy_delay = copyp.copy_delay;
		copyp32.copy_unit = copyp.copy_unit;
		if (copyout(&copyp32, (void *)arg, sizeof (copyp32)) < 0)
			return (EFAULT);
	} else if (copyout(&copyp, (void *)arg, sizeof (copyp)))
			return (EFAULT);

	return (spcs_s_ocopyoutf(&kstatus, copyp.status, rc));
}


/*
 * _ii_suspend_vol
 *	suspend an individual InstantImage group
 *
 * Calling/Exit State:
 *	Returns 0 on success, nonzero otherwise
 */

int
_ii_suspend_vol(_ii_info_t *ip)
{
	_ii_info_t **xip;
	int copy_flag;
	int rc;
	nsc_buf_t *tmp = NULL;
	ii_header_t *bm_header;

	copy_flag = ip->bi_flags & DSW_COPY_FLAGS;

	_ii_stopvol(ip);
	ASSERT(total_ref(ip) == 0);

	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0)
		return (rc);

	/* this rw_enter forces us to drain all active IO */
	rw_enter(&ip->bi_linkrw, RW_WRITER);
	rw_exit(&ip->bi_linkrw);

	mutex_enter(&_ii_info_mutex);
	for (xip = &_ii_info_top; *xip; xip = &(*xip)->bi_next) {
		if (ip == *xip)
			break;
	}
	*xip = ip->bi_next;
	mutex_exit(&_ii_info_mutex);

	rc = II_SAVE_BMP(ip, 1);
	mutex_enter(&ip->bi_mutex);
	if (rc == 0)
		bm_header = _ii_bm_header_get(ip, &tmp);
	if (rc == 0 && bm_header) {
		bm_header->ii_magic = DSW_CLEAN;
		bm_header->ii_state |= copy_flag;
		bm_header->ii_throttle_delay = ip->bi_throttle_delay;
		bm_header->ii_throttle_unit = ip->bi_throttle_unit;
		/* copy over the mtime */
		bm_header->ii_mtime = ip->bi_mtime;
		/* write it to disk */
		rc = _ii_bm_header_put(bm_header, ip, tmp);
	}
	--iigkstat.num_sets.value.ul;
	mutex_exit(&ip->bi_mutex);

	ii_overflow_free(ip, NO_RECLAIM);
	_ii_rlse_devs(ip, BMP);

	ii_sibling_free(ip);

	return (rc);
}

/*
 * _ii_suspend_cluster
 *	Cluster resource group is switching over to another node, so
 *	all shadowed volumes in that group are suspended.
 *
 * Returns 0 on success, or ESRCH if the name of the cluster resource
 * group couldn't be found.
 */
int
_ii_suspend_cluster(char *shadow_vol)
{
	int found, last;
	uint64_t hash;
	_ii_info_t *ip;
	_ii_lsthead_t **cp, *xcp;
	_ii_lstinfo_t **np, *xnp;

	/* find appropriate cluster list */
	mutex_enter(&_ii_cluster_mutex);
	hash = nsc_strhash(shadow_vol);
	for (cp = &_ii_cluster_top; *cp; cp = &((*cp)->lst_next)) {
		if ((hash == (*cp)->lst_hash) && strncmp(shadow_vol,
		    (*cp)->lst_name, DSW_NAMELEN) == 0)
			break;
	}

	if (!*cp) {
		mutex_exit(&_ii_cluster_mutex);
		return (DSW_ECNOTFOUND);
	}

	found = 1;
	last = 0;
	while (found && !last) {
		found = 0;

		mutex_enter(&_ii_info_mutex);
		for (np = &(*cp)->lst_start; *np; np = &((*np)->lst_next)) {
			ip = (*np)->lst_ip;

			if (ip->bi_disabled)
				continue;

			found++;

			ip->bi_disabled = 1;
			if (NSHADOWS(ip) && (ip->bi_master == ip)) {
				ip->bi_flags &= (~DSW_COPYING);
				ip->bi_state |= DSW_MULTIMST;
			}
			mutex_exit(&_ii_info_mutex);

			xnp = *np;
			*np = (*np)->lst_next;
			kmem_free(xnp, sizeof (_ii_lstinfo_t));
			ip->bi_cluster = NULL;

			(void) _ii_suspend_vol(ip);
			break;
		}
		if (found == 0)
			mutex_exit(&_ii_info_mutex);
		else if (!(*cp)->lst_start) {
			xcp = *cp;
			*cp = (*cp)->lst_next;
			kmem_free(xcp, sizeof (_ii_lsthead_t));
			last = 1;
		}
	}
	mutex_exit(&_ii_cluster_mutex);

	return (0);
}

/*
 * _ii_shutdown
 *	System is shutting down, so all shadowed volumes are suspended.
 *
 *	This always succeeds, so always returns 0.
 */

/* ARGSUSED */

int
_ii_shutdown(intptr_t arg, int *rvp)
{
	_ii_info_t **xip, *ip;
	int found;

	*rvp = 0;

	_ii_shutting_down = 1;

	/* Go through the list until only disabled entries are found */

	found = 1;
	while (found) {
		found = 0;

		mutex_enter(&_ii_info_mutex);
		for (xip = &_ii_info_top; *xip; xip = &(*xip)->bi_next) {
			ip = *xip;
			if (ip->bi_disabled) {
				/* Also covers not fully configured yet */
				continue;
			}
			found++;

			ip->bi_disabled = 1;
			mutex_exit(&_ii_info_mutex);

			(void) _ii_suspend_vol(ip);

			break;
		}
		if (found == 0)
			mutex_exit(&_ii_info_mutex);
	}

	_ii_shutting_down = 0;

	return (0);
}

/*
 * _ii_suspend
 *	Suspend an InstantImage, saving its state to allow a subsequent resume.
 *
 * Calling/Exit State:
 *	Returns 0 if the pair was suspended. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 */

/* ARGSUSED */

int
_ii_suspend(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uparms;
	dsw_ioctl32_t uparms32;
	_ii_info_t *ip;
	int rc;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &uparms32, sizeof (uparms32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uparms, uparms32, shadow_vol, dsw_ioctl_t);
		uparms.status = (spcs_s_info_t)uparms32.status;
	} else if (copyin((void *)arg, &uparms, sizeof (uparms)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uparms.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EEMPTY));

	if ((uparms.flags & CV_IS_CLUSTER) != 0) {
		rc = _ii_suspend_cluster(uparms.shadow_vol);
	} else {
		mutex_enter(&_ii_info_mutex);
		ip = _ii_find_set(uparms.shadow_vol);
		if (ip == NULL) {
			mutex_exit(&_ii_info_mutex);
			return (spcs_s_ocopyoutf(&kstatus, uparms.status,
			    DSW_ENOTFOUND));
		}

		ip->bi_disabled = 1;
		if (NSHADOWS(ip) && (ip->bi_master == ip)) {
			ip->bi_flags &= (~DSW_COPYING);
			ip->bi_state |= DSW_MULTIMST;
		}
		mutex_exit(&_ii_info_mutex);

		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);

		rc = _ii_suspend_vol(ip);
	}

	return (spcs_s_ocopyoutf(&kstatus, uparms.status, rc));
}


/*
 * _ii_abort
 *	Stop any copying process for shadow.
 *
 * Calling/Exit State:
 *	Returns 0 if the abort succeeded. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 */

/* ARGSUSED */

int
_ii_abort(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uabort;
	dsw_ioctl32_t uabort32;
	_ii_info_t *ip;
	int rc;
	spcs_s_info_t kstatus;

	if (ilp32) {
		if (copyin((void *)arg, &uabort32, sizeof (uabort32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uabort, uabort32, shadow_vol, dsw_ioctl_t);
		uabort.status = (spcs_s_info_t)uabort32.status;
	} else if (copyin((void *)arg, &uabort, sizeof (uabort)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uabort.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uabort.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(uabort.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, uabort.status,
		    DSW_ENOTFOUND));

	mutex_exit(&ip->bi_mutex);

	rc = _ii_stopcopy(ip);

	mutex_enter(&ip->bi_mutex);
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	return (spcs_s_ocopyoutf(&kstatus, uabort.status, rc));
}


/*
 * _ii_segment
 *	Copy out II pair bitmaps (cpy, shd, idx) in segments
 *
 * Calling/Exit State:
 *	Returns 0 if the operation succeeded. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 *
 */
int
_ii_segment(intptr_t arg, int ilp32, int *rvp)
{
	dsw_segment_t usegment;
	dsw_segment32_t usegment32;
	_ii_info_t *ip;
	int rc, size;
	spcs_s_info_t kstatus;
	int32_t bi_idxfba;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &usegment32, sizeof (usegment32)))
			return (EFAULT);
		usegment.status = (spcs_s_info_t)usegment32.status;
		bcopy(usegment32.shadow_vol, usegment.shadow_vol, DSW_NAMELEN);
		usegment.seg_number = (unsigned)usegment32.seg_number;
		usegment.shd_bitmap =
		    (unsigned char   *)(unsigned long)usegment32.shd_bitmap;
		usegment.shd_size = usegment32.shd_size;
		usegment.cpy_bitmap =
		    (unsigned char   *)(unsigned long)usegment32.cpy_bitmap;
		usegment.cpy_size = usegment32.cpy_size;
		usegment.idx_bitmap =
		    (unsigned char   *)(unsigned long)usegment32.idx_bitmap;
		usegment.idx_size = usegment32.idx_size;
	} else if (copyin((void *)arg, &usegment, sizeof (usegment)))
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (usegment.shadow_vol[0]) {
		mutex_enter(&_ii_info_mutex);
		ip = _ii_find_set(usegment.shadow_vol);
		mutex_exit(&_ii_info_mutex);
		if (ip == NULL)
			return (spcs_s_ocopyoutf(&kstatus, usegment.status,
			    DSW_ENOTFOUND));
	} else
		return (spcs_s_ocopyoutf(&kstatus, usegment.status,
		    DSW_EEMPTY));

	mutex_exit(&ip->bi_mutex);

	size = ((((ip->bi_size + (DSW_SIZE-1))
	    / DSW_SIZE) + (DSW_BITS-1))) / DSW_BITS;
	bi_idxfba = ip->bi_copyfba + (ip->bi_copyfba - ip->bi_shdfba);
	if (((nsc_size_t)usegment.seg_number > DSW_BM_FBA_LEN(ip->bi_size)) ||
	    (usegment.shd_size > size) ||
	    (usegment.cpy_size > size) ||
	    (!(ip->bi_flags & DSW_GOLDEN) && (usegment.idx_size > size*32))) {
		_ii_ioctl_done(ip);
		return (spcs_s_ocopyoutf(&kstatus, usegment.status,
		    DSW_EMISMATCH));
	}

	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0) {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, usegment.status,
		    DSW_ERSRVFAIL));
	}

	if (usegment.shd_bitmap && usegment.shd_size > 0)
		rc = II_CO_BMP(ip, ip->bi_shdfba+usegment.seg_number,
		    usegment.shd_bitmap, usegment.shd_size);
	if (rc == 0 && usegment.cpy_bitmap && usegment.cpy_size > 0)
		rc = II_CO_BMP(ip, ip->bi_copyfba+usegment.seg_number,
		    usegment.cpy_bitmap, usegment.cpy_size);
	if (!(ip->bi_flags & DSW_GOLDEN)) {
		if (rc == 0 && usegment.idx_bitmap && usegment.idx_size > 0)
			rc = II_CO_BMP(ip, bi_idxfba+usegment.seg_number*32,
			    usegment.idx_bitmap, usegment.idx_size);
	}

	_ii_rlse_devs(ip, BMP);
	mutex_enter(&ip->bi_mutex);
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);
	if (rc) {
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, usegment.status, DSW_EIO));
	}

	spcs_s_kfree(kstatus);
	return (0);
}


/*
 * _ii_bitmap
 *	Copy out II pair bitmaps to user program
 *
 * Calling/Exit State:
 *	Returns 0 if the operation succeeded. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 */

int
_ii_bitmap(intptr_t arg, int ilp32, int *rvp)
{
	dsw_bitmap_t ubitmap;
	dsw_bitmap32_t ubitmap32;
	_ii_info_t *ip;
	int rc;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &ubitmap32, sizeof (ubitmap32)))
			return (EFAULT);
		ubitmap.status = (spcs_s_info_t)ubitmap32.status;
		bcopy(ubitmap32.shadow_vol, ubitmap.shadow_vol, DSW_NAMELEN);
		ubitmap.shd_bitmap =
		    (unsigned char   *)(unsigned long)ubitmap32.shd_bitmap;
		ubitmap.shd_size = ubitmap32.shd_size;
		ubitmap.copy_bitmap =
		    (unsigned char   *)(unsigned long)ubitmap32.copy_bitmap;
		ubitmap.copy_size = ubitmap32.copy_size;
	} else if (copyin((void *)arg, &ubitmap, sizeof (ubitmap)))
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!ubitmap.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(ubitmap.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_ENOTFOUND));

	mutex_exit(&ip->bi_mutex);

	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0) {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_ERSRVFAIL));
	}

	if (ubitmap.shd_bitmap && ubitmap.shd_size > 0)
		rc = II_CO_BMP(ip, ip->bi_shdfba, ubitmap.shd_bitmap,
		    ubitmap.shd_size);
	if (rc == 0 && ubitmap.copy_bitmap && ubitmap.copy_size > 0)
		rc = II_CO_BMP(ip, ip->bi_copyfba, ubitmap.copy_bitmap,
		    ubitmap.copy_size);
	_ii_rlse_devs(ip, BMP);
	mutex_enter(&ip->bi_mutex);
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);
	if (rc) {
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status, DSW_EIO));
	}

	spcs_s_kfree(kstatus);

	return (0);
}

/*
 * _ii_export
 *	Exports the shadow volume
 *
 * Calling/Exit State:
 *	Returns 0 if the shadow was exported. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 *
 * Description:
 */

int
_ii_export(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uparms;
	dsw_ioctl32_t uparms32;
	_ii_info_t *ip;
	nsc_fd_t *fd;
	int rc = 0;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &uparms32, sizeof (uparms32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uparms, uparms32, shadow_vol, dsw_ioctl_t);
		uparms.status = (spcs_s_info_t)uparms32.status;
	} else if (copyin((void *)arg, &uparms, sizeof (uparms)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uparms.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(uparms.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, uparms.status,
		    DSW_ENOTFOUND));

	if ((ip->bi_flags & DSW_GOLDEN) == 0 ||
	    ((ip->bi_flags & (DSW_COPYING|DSW_SHDEXPORT|DSW_SHDIMPORT)) != 0)) {
		/*
		 * Cannot export a dependent copy or while still copying or
		 * the shadow is already in an exported state
		 */
		rc = ip->bi_flags & (DSW_SHDEXPORT|DSW_SHDIMPORT)
		    ? DSW_EALREADY : DSW_EDEPENDENCY;
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status, rc));
	}
	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uparms.status,
		    DSW_ERSRVFAIL));
	}
	II_FLAG_SET(DSW_SHDEXPORT, ip);

	mutex_exit(&ip->bi_mutex);

	/* this rw_enter forces us to drain all active IO */
	rw_enter(&ip->bi_linkrw, RW_WRITER);
	rw_exit(&ip->bi_linkrw);

	mutex_enter(&ip->bi_mutex);

	_ii_rlse_devs(ip, BMP);

	/* Shut shadow volume. */
	if (ip->bi_shdfd) {
		if (ip->bi_shdrsrv) {
			nsc_release(ip->bi_shdfd);
			ip->bi_shdrsrv = NULL;
		}
		fd = ip->bi_shdfd;
		ip->bi_shdfd = NULL;
		mutex_exit(&ip->bi_mutex);
		(void) nsc_close(fd);
		mutex_enter(&ip->bi_mutex);
	}

	if (ip->bi_shdrfd) {
		if (ip->bi_shdrrsrv) {
			nsc_release(ip->bi_shdrfd);
			ip->bi_shdrrsrv = NULL;
		}
		fd = ip->bi_shdrfd;
		ip->bi_shdrfd = NULL;
		mutex_exit(&ip->bi_mutex);
		(void) nsc_close(fd);
		mutex_enter(&ip->bi_mutex);
	}
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	(void) _ii_reserve_begin(ip);
	if (ip->bi_shd_tok) {
		(void) _ii_unregister_path(ip->bi_shd_tok, 0, "shadow");
		ip->bi_shd_tok = NULL;
	}

	if (ip->bi_shdr_tok) {
		(void) _ii_unregister_path(ip->bi_shdr_tok, 0,
		    "raw shadow");
		ip->bi_shdr_tok = NULL;
	}
	_ii_reserve_end(ip);

	spcs_s_kfree(kstatus);

	return (0);
}

/*
 * _ii_join
 *	Rejoins the shadow volume
 *
 * Calling/Exit State:
 *	Returns 0 if the shadow was exported. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 *
 * Description:
 */

int
_ii_join(intptr_t arg, int ilp32, int *rvp)
{
	dsw_bitmap_t ubitmap;
	dsw_bitmap32_t ubitmap32;
	_ii_info_t *ip;
	uint64_t bm_size;
	int rc = 0;
	int rtype = 0;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &ubitmap32, sizeof (ubitmap32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ubitmap, ubitmap32, shadow_vol, dsw_bitmap_t);
		ubitmap.status = (spcs_s_info_t)ubitmap32.status;
		ubitmap.shd_bitmap =
		    (unsigned char   *)(unsigned long)ubitmap32.shd_bitmap;
		ubitmap.shd_size = ubitmap32.shd_size;
	} else if (copyin((void *)arg, &ubitmap, sizeof (ubitmap)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!ubitmap.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(ubitmap.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_ENOTFOUND));

	/*
	 * Check that group has shadow exported.
	 */
	if ((ip->bi_flags & DSW_SHDEXPORT) == 0) {
		/*
		 * Cannot join if the shadow isn't exported.
		 */
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_ENOTEXPORTED));
	}
	/* check bitmap is at least large enough for master volume size */
	bm_size = FBA_SIZE(DSW_BM_FBA_LEN(ip->bi_size));
	if (ubitmap.shd_size < bm_size) {
		/* bitmap is to small */
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_EINVALBMP));
	}
	/* read in bitmap and or with differences bitmap */
	rtype = BMP;
	if ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_ERSRVFAIL));
	}
	rc = II_CI_BMP(ip, ip->bi_shdfba, ubitmap.shd_bitmap,
	    ubitmap.shd_size);
	/* open up shadow */
	if ((rc = ii_open_shadow(ip, ip->bi_keyname)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		_ii_rlse_devs(ip, rtype);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status, DSW_EOPEN));
	}
	ii_register_shd(ip);
	if (!rc)
		II_FLAG_CLR(DSW_SHDEXPORT, ip);
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);
	_ii_rlse_devs(ip, rtype);

	if (rc) {
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status, DSW_EIO));
	}

	spcs_s_kfree(kstatus);

	return (0);
}


/*
 * _ii_ocreate
 *	Configures a volume suitable for use as an overflow volume.
 *
 * Calling/Exit State:
 *	Returns 0 if the volume was configured successfully. Otherwise
 *	 an error code is returned and any additional error information
 *	is copied out to the user.
 *
 * Description:
 */

int
_ii_ocreate(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t uioctl;
	dsw_ioctl32_t uioctl32;
	_ii_overflow_t	ov;
	_ii_overflow_t	*op = &ov;
	int rc = 0;
	nsc_fd_t	*fd;
	nsc_iodev_t	*iodev;
	nsc_size_t vol_size;
	char *overflow_vol;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &uioctl32, sizeof (uioctl32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uioctl, uioctl32, shadow_vol, dsw_ioctl_t);
		uioctl.status = (spcs_s_info_t)uioctl32.status;
	} else if (copyin((void *)arg, &uioctl, sizeof (uioctl)) < 0)
		return (EFAULT);

	overflow_vol = uioctl.shadow_vol;
	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!overflow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uioctl.status, DSW_EEMPTY));

	if (ii_volume(overflow_vol, 0) != NONE)
		return (spcs_s_ocopyoutf(&kstatus, uioctl.status, DSW_EINUSE));

	fd = nsc_open(overflow_vol,
	    NSC_IIR_ID|NSC_FILE|NSC_RDWR, NULL, (blind_t)&(iodev), &rc);
	if (!fd)
		fd = nsc_open(uioctl.shadow_vol,
		    NSC_IIR_ID|NSC_DEVICE|NSC_RDWR, NULL,
		    (blind_t)&(iodev), &rc);
	if (fd == NULL) {
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uioctl.status, DSW_EIO));
	}
	if ((rc = nsc_reserve(fd, 0)) != 0) {
		spcs_s_add(kstatus, rc);
		(void) nsc_close(fd);
		return (spcs_s_ocopyoutf(&kstatus, uioctl.status,
		    DSW_ERSRVFAIL));
	}
	/* setup magic number etc; */
	rc = nsc_partsize(fd, &vol_size);
	if (rc) {
		spcs_s_add(kstatus, rc);
		(void) nsc_close(fd);
		return (spcs_s_ocopyoutf(&kstatus, uioctl.status, DSW_EIO));
	}
	op->ii_hmagic = II_OMAGIC;
		/* take 1 off as chunk 0 contains header */
	op->ii_nchunks = (vol_size / DSW_SIZE) -1;
	op->ii_drefcnt = 0;
	op->ii_used = 1;			/* we have used the header */
	op->ii_unused = op->ii_nchunks - op->ii_used;
	op->ii_freehead = II_NULLNODE;
	op->ii_hversion = OV_HEADER_VERSION;
	op->ii_flags = 0;
	op->ii_urefcnt = 0;
	(void) strncpy(op->ii_volname, uioctl.shadow_vol, DSW_NAMELEN);
	rc = _ii_nsc_io(0, KS_NA, fd, NSC_WRBUF, II_OHEADER_FBA,
	    (unsigned char *)&op->ii_do, sizeof (op->ii_do));
	(void) nsc_release(fd);
	(void) nsc_close(fd);
	if (rc) {
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uioctl.status, DSW_EIO));
	}

	spcs_s_kfree(kstatus);

	return (0);
}


/*
 * _ii_oattach
 *	Attaches the volume in the "bitmap_vol" field as an overflow volume.
 *
 * Calling/Exit State:
 *	Returns 0 if the volume was attached. Fails if the shadow group
 *	is of the wrong type (eg independent) or already has an overflow
 *	volume attached.
 *
 * Description:
 */

int
_ii_oattach(intptr_t arg, int ilp32, int *rvp)
{
	dsw_config_t uconfig;
	dsw_config32_t uconfig32;
	_ii_info_t *ip;
	int rc = 0;
	int rtype = 0;
	ii_header_t *bm_header;
	nsc_buf_t *tmp = NULL;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &uconfig32, sizeof (uconfig32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(uconfig, uconfig32, shadow_vol, dsw_config_t);
		uconfig.status = (spcs_s_info_t)uconfig32.status;
	} else if (copyin((void *)arg, &uconfig, sizeof (uconfig)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!uconfig.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status, DSW_EEMPTY));

	switch (ii_volume(uconfig.bitmap_vol, 0)) {
	case NONE:
	case OVR:
		break;
	default:
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status, DSW_EINUSE));
	}
	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(uconfig.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status,
		    DSW_ENOTFOUND));

	/* check shadow doesn't already have an overflow volume */
	if (ip->bi_overflow) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status,
		    DSW_EALREADY));
	}
	/* check shadow is mapped so can have an overflow */
	if ((ip->bi_flags&DSW_TREEMAP) == 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status,
		    DSW_EWRONGTYPE));
	}
	rtype = BMP;
	if ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status,
		    DSW_ERSRVFAIL));
	}
	/* attach volume */
	if ((rc = ii_overflow_attach(ip, uconfig.bitmap_vol, 1)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status, rc));
	}

	/* re-write header so shadow can be restarted with overflow volume */

	bm_header = _ii_bm_header_get(ip, &tmp);
	if (bm_header == NULL) {
		/* detach volume */
		ii_overflow_free(ip, RECLAIM);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		return (spcs_s_ocopyoutf(&kstatus, uconfig.status,
		    DSW_EHDRBMP));
	}
	(void) strncpy(bm_header->overflow_vol, uconfig.bitmap_vol,
	    DSW_NAMELEN);
	(void) _ii_bm_header_put(bm_header, ip, tmp);
	_ii_rlse_devs(ip, rtype);
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	spcs_s_kfree(kstatus);

	return (0);
}


/*
 * _ii_odetach
 *	Breaks the link with the overflow volume.
 *
 * Calling/Exit State:
 *	Returns 0 if the overflow volume was detached. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 *
 * Description:
 */

int
_ii_odetach(intptr_t arg, int ilp32, int *rvp)
{
	dsw_bitmap_t ubitmap;
	dsw_bitmap32_t ubitmap32;
	_ii_info_t *ip;
	int rc = 0;
	int rtype = 0;
	ii_header_t *bm_header;
	nsc_buf_t *tmp = NULL;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &ubitmap32, sizeof (ubitmap32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ubitmap, ubitmap32, shadow_vol, dsw_bitmap_t);
		ubitmap.status = (spcs_s_info_t)ubitmap32.status;
	} else if (copyin((void *)arg, &ubitmap, sizeof (ubitmap)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!ubitmap.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(ubitmap.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_ENOTFOUND));

	if ((ip->bi_flags&DSW_VOVERFLOW) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_EODEPENDENCY));
	}
	rtype = BMP;
	if ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_ERSRVFAIL));
	}
	ii_overflow_free(ip, RECLAIM);
	/* re-write header to break link with overflow volume */

	bm_header = _ii_bm_header_get(ip, &tmp);
	if (bm_header == NULL) {
		_ii_rlse_devs(ip, rtype);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status,
		    DSW_EHDRBMP));
	}
	bzero(bm_header->overflow_vol, DSW_NAMELEN);
	(void) _ii_bm_header_put(bm_header, ip, tmp);

	_ii_rlse_devs(ip, rtype);
	_ii_ioctl_done(ip);

	mutex_exit(&ip->bi_mutex);
	if (rc) {
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitmap.status, DSW_EIO));
	}

	spcs_s_kfree(kstatus);

	--iigkstat.assoc_over.value.ul;

	return (0);
}


/*
 * _ii_gc_list
 *	Returns a list of all lists, or all entries in a list
 *
 */
int
_ii_gc_list(intptr_t arg, int ilp32, int *rvp, kmutex_t *mutex,
    _ii_lsthead_t *lst)
{
	dsw_aioctl_t ulist;
	dsw_aioctl32_t ulist32;
	size_t name_offset;
	int i;
	spcs_s_info_t kstatus;
	char *carg = (char *)arg;
	uint64_t hash;
	_ii_lsthead_t *cp;
	_ii_lstinfo_t *np;

	*rvp = 0;
	name_offset = offsetof(dsw_aioctl_t, shadow_vol[0]);
	if (ilp32) {
		if (copyin((void *) arg, &ulist32, sizeof (ulist32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ulist, ulist32, flags, dsw_aioctl_t);
		ulist.status = (spcs_s_info_t)ulist32.status;
		name_offset = offsetof(dsw_aioctl32_t, shadow_vol[0]);
	} else if (copyin((void *) arg, &ulist, sizeof (ulist)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	mutex_enter(mutex);
	if (ulist.shadow_vol[ 0 ] != 0) {
		/* search for specific list */
		hash = nsc_strhash(ulist.shadow_vol);
		for (cp = lst; cp; cp = cp->lst_next) {
			if ((hash == cp->lst_hash) && strncmp(ulist.shadow_vol,
			    cp->lst_name, DSW_NAMELEN) == 0) {
				break;
			}
		}
		if (cp) {
			for (i = 0, np = cp->lst_start; i < ulist.count && np;
			    np = np->lst_next, carg += DSW_NAMELEN, i++) {
				if (copyout(np->lst_ip->bi_keyname,
				    carg + name_offset, DSW_NAMELEN)) {
					mutex_exit(mutex);
					return (spcs_s_ocopyoutf(&kstatus,
					    ulist.status, EFAULT));
				}
			}
		} else {
			i = 0;
		}
	} else {
		/* return full list */
		for (i = 0, cp = lst; i < ulist.count && cp;
		    carg += DSW_NAMELEN, i++, cp = cp->lst_next) {
			if (copyout(cp->lst_name, carg + name_offset,
			    DSW_NAMELEN)) {
				mutex_exit(mutex);
				return (spcs_s_ocopyoutf(&kstatus, ulist.status,
				    EFAULT));
			}
		}
	}
	mutex_exit(mutex);
	ulist32.count = ulist.count = i;

	if (ilp32) {
		if (copyout(&ulist32, (void *) arg, name_offset))
			return (EFAULT);
	} else {
		if (copyout(&ulist, (void*) arg, name_offset))
			return (EFAULT);
	}

	return (spcs_s_ocopyoutf(&kstatus, ulist.status, 0));
}

/*
 * _ii_olist
 *	Breaks the link with the overflow volume.
 *
 * Calling/Exit State:
 *	Returns 0 if the overflow volume was detached. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 *
 * Description:
 */

int
_ii_olist(intptr_t arg, int ilp32, int *rvp)
{
	dsw_aioctl_t ulist;
	dsw_aioctl32_t ulist32;
	_ii_overflow_t *op;
	size_t name_offset;
	int rc = 0;
	int i;
	char *carg = (char *)arg;
	spcs_s_info_t kstatus;

	*rvp = 0;

	name_offset = offsetof(dsw_aioctl_t, shadow_vol[0]);
	if (ilp32) {
		if (copyin((void *)arg, &ulist32, sizeof (ulist32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ulist, ulist32, flags, dsw_aioctl_t);
		ulist.status = (spcs_s_info_t)ulist32.status;
		name_offset = offsetof(dsw_aioctl32_t, shadow_vol[0]);
	} else if (copyin((void *)arg, &ulist, sizeof (ulist)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	i = 0;

	mutex_enter(&_ii_overflow_mutex);
	for (op = _ii_overflow_top; i < ulist.count && op;
	    carg += DSW_NAMELEN) {
		if (copyout(op->ii_volname, carg+name_offset, DSW_NAMELEN)) {
			mutex_exit(&_ii_overflow_mutex);
			return (spcs_s_ocopyoutf(&kstatus, ulist.status,
			    EFAULT));
		}
		i++;
		op = op->ii_next;
	}
	mutex_exit(&_ii_overflow_mutex);
	ulist32.count = ulist.count = i;
	/* return count of items listed to user */
	if (ilp32) {
		if (copyout(&ulist32, (void *)arg, name_offset))
			return (EFAULT);
	} else {
		if (copyout(&ulist, (void *)arg, name_offset))
			return (EFAULT);
	}

	return (spcs_s_ocopyoutf(&kstatus, ulist.status, rc));
}

/*
 * _ii_ostat
 *	Breaks the link with the overflow volume.
 *
 * Calling/Exit State:
 *	Returns 0 if the overflow volume was detached. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 *
 * Description:
 */

int
_ii_ostat(intptr_t arg, int ilp32, int *rvp, int is_iost_2)
{
	dsw_ostat_t ustat;
	dsw_ostat32_t ustat32;
	_ii_overflow_t *op;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &ustat32, sizeof (ustat32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ustat, ustat32, overflow_vol, dsw_ostat_t);
		ustat.status = (spcs_s_info_t)ustat32.status;
	} else if (copyin((void *)arg, &ustat, sizeof (ustat)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);
	if (!ustat.overflow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, ustat.status, DSW_EEMPTY));

	op = _ii_find_overflow(ustat.overflow_vol);
	if (op == NULL)
		return (spcs_s_ocopyoutf(&kstatus, ustat.status,
		    DSW_ENOTFOUND));

	ustat.nchunks = op->ii_nchunks;
	ustat.used = op->ii_used;
	ustat.unused = op->ii_unused;
	ustat.drefcnt = op->ii_drefcnt;
	ustat.crefcnt = op->ii_crefcnt;
	if (is_iost_2) {
		ustat.hversion = op->ii_hversion;
		ustat.flags = op->ii_flags;
		ustat.hmagic = op->ii_hmagic;
	}

	spcs_s_kfree(kstatus);
	if (ilp32) {
		ustat32.nchunks = ustat.nchunks;
		ustat32.used = ustat.used;
		ustat32.unused = ustat.unused;
		ustat32.drefcnt = ustat.drefcnt;
		ustat32.crefcnt = ustat.crefcnt;
		if (is_iost_2) {
			ustat32.hversion = ustat.hversion;
			ustat32.flags = ustat.flags;
			ustat32.hmagic = ustat.hmagic;
		}
		if (copyout(&ustat32, (void *)arg, sizeof (ustat32)))
			return (EFAULT);
	} else {
		if (copyout(&ustat, (void *)arg, sizeof (ustat)))
			return (EFAULT);
	}
	return (0);
}

/*
 * _ii_move_grp()
 *	Move a set from one group to another, possibly creating the new
 *	group.
 */

int
_ii_move_grp(intptr_t arg, int ilp32, int *rvp)
{
	dsw_movegrp_t umove;
	dsw_movegrp32_t umove32;
	spcs_s_info_t kstatus;
	_ii_info_t *ip;
	int rc = 0;
	nsc_buf_t *tmp;
	ii_header_t *bm_header;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &umove32, sizeof (umove32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(umove, umove32, shadow_vol, dsw_movegrp_t);
		umove.status = (spcs_s_info_t)umove32.status;
	} else if (copyin((void *)arg, &umove, sizeof (umove)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!umove.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, umove.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(umove.shadow_vol);
	mutex_exit(&_ii_info_mutex);

	if (!ip)
		return (spcs_s_ocopyoutf(&kstatus, umove.status,
		    DSW_ENOTFOUND));

	if (!umove.new_group[0]) {
		/* are we clearing the group association? */
		if (ip->bi_group) {
			DTRACE_PROBE2(_ii_move_grp1, char *, ip->bi_keyname,
			    char *, ip->bi_group);
			rc = II_UNLINK_GROUP(ip);
		}
	} else if (!ip->bi_group) {
		rc = II_LINK_GROUP(ip, umove.new_group);
		DTRACE_PROBE2(_ii_move_grp2, char *, ip->bi_keyname,
		    char *, ip->bi_group);
	} else {
		/* remove it from one group and add it to the other */
		DTRACE_PROBE3(_ii_move_grp, char *, ip->bi_keyname,
		    char *, ip->bi_group, char *, umove.new_group);
		rc = II_UNLINK_GROUP(ip);
		if (!rc)
			rc = II_LINK_GROUP(ip, umove.new_group);
	}

	/* ** BEGIN UPDATE BITMAP HEADER ** */
	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, umove.status,
		    DSW_ERSRVFAIL));
	}
	bm_header = _ii_bm_header_get(ip, &tmp);
	if (bm_header) {
		(void) strncpy(bm_header->group_name, umove.new_group,
		    DSW_NAMELEN);
		(void) _ii_bm_header_put(bm_header, ip, tmp);
	}
	_ii_rlse_devs(ip, BMP);
	/* ** END UPDATE BITMAP HEADER ** */

	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	return (spcs_s_ocopyoutf(&kstatus, umove.status, rc));
}

/*
 * _ii_change_tag()
 *	Move a set from one group to another, possibly creating the new
 *	group.
 */

int
_ii_change_tag(intptr_t arg, int ilp32, int *rvp)
{
	dsw_movegrp_t umove;
	dsw_movegrp32_t umove32;
	spcs_s_info_t kstatus;
	_ii_info_t *ip;
	int rc = 0;
	nsc_buf_t *tmp;
	ii_header_t *bm_header;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &umove32, sizeof (umove32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(umove, umove32, shadow_vol, dsw_movegrp_t);
		umove.status = (spcs_s_info_t)umove32.status;
	} else if (copyin((void *)arg, &umove, sizeof (umove)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!umove.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, umove.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(umove.shadow_vol);
	mutex_exit(&_ii_info_mutex);

	if (!ip)
		return (spcs_s_ocopyoutf(&kstatus, umove.status,
		    DSW_ENOTFOUND));

	if (!umove.new_group[0]) {
		/* are we clearing the group association? */
		if (ip->bi_cluster) {
			DTRACE_PROBE2(_ii_change_tag, char *, ip->bi_keyname,
			    char *, ip->bi_cluster);
			rc = II_UNLINK_CLUSTER(ip);
		}
	} else if (!ip->bi_cluster) {
		/* are we adding it to a group for the first time? */
		rc = II_LINK_CLUSTER(ip, umove.new_group);
		DTRACE_PROBE2(_ii_change_tag, char *, ip->bi_keyname,
		    char *, ip->bi_cluster);
	} else {
		/* remove it from one group and add it to the other */
		DTRACE_PROBE3(_ii_change_tag_2, char *, ip->bi_keyname,
		    char *, ip->bi_cluster, char *, umove.new_group);
		rc = II_UNLINK_CLUSTER(ip);
		if (!rc)
			rc = II_LINK_CLUSTER(ip, umove.new_group);
	}

	/* ** BEGIN UPDATE BITMAP HEADER ** */
	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, umove.status,
		    DSW_ERSRVFAIL));
	}
	bm_header = _ii_bm_header_get(ip, &tmp);
	if (bm_header) {
		(void) strncpy(bm_header->clstr_name, umove.new_group,
		    DSW_NAMELEN);
		(void) _ii_bm_header_put(bm_header, ip, tmp);
	}
	_ii_rlse_devs(ip, BMP);
	/* ** END UPDATE BITMAP HEADER ** */

	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	return (spcs_s_ocopyoutf(&kstatus, umove.status, rc));
}


/*
 * _ii_spcs_s_ocopyoutf()
 * Wrapper for spcs_s_ocopyoutf() used by _ii_chk_copy() which permits
 * the spcs_s_info_t argument to be NULL. _ii_chk_copy() requires this
 * functionality as it is sometimes called by _ii_control_copy() which
 * has no user context to copy any errors into. At all other times a NULL
 * spcs_s_info_t argument would indicate a bug in the calling function.
 */

static int
_ii_spcs_s_ocopyoutf(spcs_s_info_t *kstatusp, spcs_s_info_t ustatus, int err)
{
	if (ustatus)
		return (spcs_s_ocopyoutf(kstatusp, ustatus, err));
	spcs_s_kfree(*kstatusp);
	return (err);
}

static int
_ii_chk_copy(_ii_info_t *ip, int flags, spcs_s_info_t *kstatusp, pid_t pid,
    spcs_s_info_t ustatus)
{
	_ii_info_t *xip;
	int rc;
	int rtype;

	if ((ip->bi_flags & DSW_COPYINGP) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus, DSW_ECOPYING));
	}

	if (ip->bi_flags & DSW_OFFLINE) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus, DSW_EOFFLINE));
	}

	if ((ip->bi_flags & (DSW_SHDIMPORT|DSW_SHDEXPORT)) != 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus,
		    DSW_EISEXPORTED));
	}

	if ((flags & CV_SHD2MST) == CV_SHD2MST) {
		if ((ip->bi_flags & DSW_COPYINGM) != 0) {
				_ii_ioctl_done(ip);
				mutex_exit(&ip->bi_mutex);
				return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus,
				    DSW_ECOPYING));
		}
		/* check if any sibling shadow is copying towards this master */
		for (xip = ip->bi_head; xip; xip = xip->bi_sibling) {
			if (ip != xip && (xip->bi_flags & DSW_COPYINGS) != 0) {
				_ii_ioctl_done(ip);
				mutex_exit(&ip->bi_mutex);
				return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus,
				    DSW_ECOPYING));
			}
		}
	}

	if (((flags & CV_SHD2MST) == 0) &&
	    ((ip->bi_flags & DSW_COPYINGS) != 0)) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus, DSW_ECOPYING));
	}

	if (ip->bi_flags & DSW_TREEMAP) {
		if ((ip->bi_flags & DSW_OVERFLOW) && (flags & CV_SHD2MST)) {
			_ii_ioctl_done(ip);
			mutex_exit(&ip->bi_mutex);
			return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus,
			    DSW_EINCOMPLETE));
		}
	}

	/* Assure that no other PID owns this copy/update */
	if (ip->bi_locked_pid == 0) {
		if (flags & CV_LOCK_PID)
			ip->bi_locked_pid = pid;
	} else if (ip->bi_locked_pid != pid) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (spcs_s_ocopyoutf(kstatusp, ustatus, DSW_EINUSE));
	}

	mutex_exit(&ip->bi_mutex);

	rtype = MSTR|SHDR|BMP;
	if ((rc = _ii_rsrv_devs(ip, rtype, II_INTERNAL)) != 0) {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(*kstatusp, rc);
		return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus,
		    DSW_ERSRVFAIL));
	}

	if (ii_update_denied(ip, *kstatusp, flags & CV_SHD2MST, 0)) {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		return (_ii_spcs_s_ocopyoutf(kstatusp, ustatus,
		    DSW_EOPACKAGE));
	}

	return (0);
}

static int
_ii_do_copy(_ii_info_t *ip, int flags, spcs_s_info_t kstatus, int waitflag)
{
	int rc = 0;
	int rtype = MSTR|SHDR|BMP;
	_ii_overflow_t *op;
	int quick_update = 0;

	waitflag = (waitflag != 0);
	/*
	 * a copy of a tree-mapped device must be downgraded to
	 * an update.
	 */
	if (ip->bi_flags & DSW_TREEMAP)
		flags |= CV_BMP_ONLY;

	/*
	 * If we want to update the dependent shadow we only need to zero
	 * the shadow bitmap.
	 */

	if (((ip->bi_flags & DSW_GOLDEN) == 0) &&
	    (flags & (CV_BMP_ONLY|CV_SHD2MST)) == CV_BMP_ONLY) {

		DTRACE_PROBE(DEPENDENT);

		/* assign updating time */
		ip->bi_mtime = ddi_get_time();

		if (ip->bi_flags & DSW_TREEMAP) {
			DTRACE_PROBE(COMPACT_DEPENDENT);

			if (ip->bi_overflow &&
			    (ip->bi_overflow->ii_flags & IIO_VOL_UPDATE) == 0) {
				/* attempt to do a quick update */
				quick_update = 1;
				ip->bi_overflow->ii_flags |= IIO_VOL_UPDATE;
				ip->bi_overflow->ii_detachcnt = 1;
			}

			rc = ii_tinit(ip);

			if (quick_update && ip->bi_overflow) {
				/* clean up */
				ip->bi_overflow->ii_flags &= ~(IIO_VOL_UPDATE);
				ip->bi_overflow->ii_detachcnt = 0;
			}
		}

		if (rc == 0)
			rc = II_ZEROBM(ip);	/* update copy of shadow */
		if (((op = ip->bi_overflow) != NULL) &&
		    (op->ii_hversion >= 1) && (op->ii_hmagic == II_OMAGIC)) {
			mutex_enter(&_ii_overflow_mutex);
			if (ip->bi_flags & DSW_OVRHDRDRTY) {
				mutex_enter(&ip->bi_mutex);
				ip->bi_flags &= ~DSW_OVRHDRDRTY;
				mutex_exit(&ip->bi_mutex);
				ASSERT(op->ii_urefcnt > 0);
				op->ii_urefcnt--;
			}
			if (op->ii_urefcnt == 0) {
				op->ii_flags &= ~IIO_CNTR_INVLD;
				op->ii_unused = op->ii_nchunks - 1;
			}
			mutex_exit(&_ii_overflow_mutex);
		}
		mutex_enter(&ip->bi_mutex);
		II_FLAG_CLR(DSW_OVERFLOW, ip);
		mutex_exit(&ip->bi_mutex);

		_ii_unlock_chunk(ip, II_NULLCHUNK);
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		_ii_rlse_devs(ip, rtype);
		if (rc) {
			spcs_s_add(kstatus, rc);
			return (DSW_EIO);
		} else {
			DTRACE_PROBE(_ii_do_copy_end);
			return (0);
		}
	}

	/*
	 * need to perform an actual copy.
	 */

	/*
	 * Perform bitmap copy if asked or from dependent shadow to master.
	 */
	if ((flags & CV_BMP_ONLY) ||
	    ((flags & CV_SHD2MST) &&
	    ((ip->bi_flags & DSW_GOLDEN) == 0))) {
		DTRACE_PROBE(INDEPENDENT_fast);
		rc = II_ORBM(ip);		/* save shadow bits for copy */
	} else {
		DTRACE_PROBE(INDEPENDENT_slow);
		rc = ii_fill_copy_bmp(ip); /* set bits for independent copy */
	}
	if (rc == 0)
		rc = II_ZEROBM(ip);
	_ii_unlock_chunk(ip, II_NULLCHUNK);
	if (rc == 0) {
		mutex_enter(&ip->bi_mutex);
		if (ip->bi_flags & (DSW_COPYINGP | DSW_SHDEXPORT)) {
			rc = (ip->bi_flags & DSW_COPYINGP)
			    ? DSW_ECOPYING : DSW_EISEXPORTED;

			_ii_ioctl_done(ip);
			mutex_exit(&ip->bi_mutex);
			_ii_rlse_devs(ip, rtype);
			return (rc);
		}

		/* assign copying time */
		ip->bi_mtime = ddi_get_time();

		if (flags & CV_SHD2MST)
			II_FLAG_SET(DSW_COPYINGS | DSW_COPYINGP, ip);
		else
			II_FLAG_SET(DSW_COPYINGM | DSW_COPYINGP, ip);
		mutex_exit(&ip->bi_mutex);
		rc = _ii_copyvol(ip, (flags & CV_SHD2MST),
		    rtype, kstatus, waitflag);
	} else {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
	}

	if (waitflag)
		_ii_rlse_devs(ip, rtype);

	return (rc);
}

/*
 * _ii_copy
 *	Copy or update (take snapshot) II volume.
 *
 * Calling/Exit State:
 *	Returns 0 if the operation succeeded. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 */

int
_ii_copy(intptr_t arg, int ilp32, int *rvp)
{
	dsw_ioctl_t ucopy;
	dsw_ioctl32_t ucopy32;
	_ii_info_t *ip;
	int rc = 0;
	spcs_s_info_t kstatus;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &ucopy32, sizeof (ucopy32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ucopy, ucopy32, shadow_vol, dsw_ioctl_t);
		ucopy.status = (spcs_s_info_t)ucopy32.status;
	} else if (copyin((void *)arg, &ucopy, sizeof (ucopy)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!ucopy.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, ucopy.status, DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(ucopy.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, ucopy.status,
		    DSW_ENOTFOUND));

	/* Check that the copy/update makes sense */
	if ((rc = _ii_chk_copy(ip, ucopy.flags, &kstatus, ucopy.pid,
	    ucopy.status)) == 0) {
		/* perform the copy */
		_ii_lock_chunk(ip, II_NULLCHUNK);
		/* _ii_do_copy() calls _ii_ioctl_done() */
		rc = _ii_do_copy(ip, ucopy.flags, kstatus, 1);
		return (spcs_s_ocopyoutf(&kstatus, ucopy.status, rc));
	}

	return (rc);
}

/*
 * _ii_mass_copy
 * Copies/updates the sets pointed to in the ipa array.
 *
 * Calling/Exit State:
 * Returns 0 if the operations was successful.  Otherwise an
 * error code.
 */
int
_ii_mass_copy(_ii_info_t **ipa, dsw_aioctl_t *ucopy, int wait)
{
	int i;
	int rc = 0;
	int failed;
	int rtype = MSTR|SHDR|BMP;
	_ii_info_t *ip;
	spcs_s_info_t kstatus;

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	/* Check copy validitity */
	for (i = 0; i < ucopy->count; i++) {
		ip = ipa[i];

		rc = _ii_chk_copy(ip, ucopy->flags, &kstatus, ucopy->pid,
		    ucopy->status);

		if (rc) {
			/* Clean up the mess */

			DTRACE_PROBE1(_ii_mass_copy_end1, int, rc);

			/*
			 * The array ipa now looks like:
			 *    0..(i-1): needs mutex_enter/ioctl_done/mutex_exit
			 *    i: needs nothing (_ii_chk_copy does cleanup)
			 *    (i+1)..n: needs just ioctl_done/mutex_exit
			 */

			failed = i;

			for (i = 0; i < failed; i++) {
				mutex_enter(&(ipa[i]->bi_mutex));
				_ii_ioctl_done(ipa[i]);
				mutex_exit(&(ipa[i]->bi_mutex));
				_ii_rlse_devs(ipa[i], rtype);
			}

			/* skip 'failed', start with failed + 1 */

			for (i = failed + 1; i < ucopy->count; i++) {
				_ii_ioctl_done(ipa[i]);
				mutex_exit(&(ipa[i]->bi_mutex));
			}

			return (rc);
		}
	}

	/* Check for duplicate shadows in same II group */
	if (ucopy->flags & CV_SHD2MST) {
		/* Reset the state of all masters */
		for (i = 0; i < ucopy->count; i++) {
			ip = ipa[i];
			ip->bi_master->bi_state &= ~DSW_MSTTARGET;
		}

		for (i = 0; i < ucopy->count; i++) {
			ip = ipa[i];
			/*
			 * Check the state of the master.  If DSW_MSTTARGET is
			 * set, it's because this master is attached to another
			 * shadow within this set.
			 */
			if (ip->bi_master->bi_state & DSW_MSTTARGET) {
				rc = EINVAL;
				break;
			}

			/*
			 * Set the DSW_MSTTARGET bit on the master associated
			 * with this shadow.  This will allow us to detect
			 * multiple shadows pointing to this master within
			 * this loop.
			 */
			ip->bi_master->bi_state |= DSW_MSTTARGET;
		}
	}

	/* Handle error */
	if (rc) {
		DTRACE_PROBE1(_ii_mass_copy_end2, int, rc);
		for (i = 0; i < ucopy->count; i++) {
			ip = ipa[i];

			_ii_rlse_devs(ip, rtype);

			mutex_enter(&ip->bi_mutex);
			_ii_ioctl_done(ip);
			mutex_exit(&ip->bi_mutex);
		}

		return (spcs_s_ocopyoutf(&kstatus, ucopy->status, rc));
	}

	/* Lock bitmaps & prepare counts */
	for (i = 0; i < ucopy->count; i++) {
		ip = ipa[i];
		_ii_lock_chunk(ip, II_NULLCHUNK);
		if (ip->bi_overflow) {
			ip->bi_overflow->ii_detachcnt = 0;
		}
	}

	/* determine which volumes we're dealing with */
	for (i = 0; i < ucopy->count; i++) {
		ip = ipa[i];
		if (ip->bi_overflow) {
			ip->bi_overflow->ii_flags |= IIO_VOL_UPDATE;
			if ((ucopy->flags & (CV_BMP_ONLY|CV_SHD2MST)) ==
			    CV_BMP_ONLY) {
				++ip->bi_overflow->ii_detachcnt;
			}
		}
	}

	/* Perform copy */
	for (i = 0; i < ucopy->count; i++) {
		ip = ipa[i];
		rc = _ii_do_copy(ip, ucopy->flags, kstatus, wait);
		/* Hum... what to do if one of these fails? */
	}

	/* clear out flags so as to prevent any accidental reuse */
	for (i = 0; i < ucopy->count; i++) {
		ip = ipa[i];
		if (ip->bi_overflow)
			ip->bi_overflow->ii_flags &= ~(IIO_VOL_UPDATE);
	}

	/*
	 * We can only clean up the kstatus structure if there are
	 * no waiters.  If someone's waiting for the information,
	 * _ii_copyvolp() uses spcs_s_add to write to kstatus.  Panic
	 * would ensue if we freed it up now.
	 */
	if (!wait)
		rc = spcs_s_ocopyoutf(&kstatus, ucopy->status, rc);

	return (rc);
}

/*
 * _ii_list_copy
 * Retrieve a list from a character array and use _ii_mass_copy to
 * initiate a copy/update operation on all of the specified sets.
 *
 * Calling/Exit State:
 * Returns 0 if the operations was successful.  Otherwise an
 * error code.
 */
int
_ii_list_copy(char *list, dsw_aioctl_t *ucopy, int wait)
{
	int i;
	int rc = 0;
	char *name;
	_ii_info_t *ip;
	_ii_info_t **ipa;

	ipa = kmem_zalloc(sizeof (_ii_info_t *) * ucopy->count, KM_SLEEP);

	/* Reserve devices */
	name = list;
	mutex_enter(&_ii_info_mutex);
	for (i = 0; i < ucopy->count; i++, name += DSW_NAMELEN) {
		ip = _ii_find_set(name);

		if (ip == NULL) {
			rc = DSW_ENOTFOUND;
			break;
		}

		ipa[i] = ip;
	}

	if (rc != 0) {
		/* Failed to find all sets, release those we do have */
		while (i-- > 0) {
			ip = ipa[i];
			mutex_enter(&ip->bi_mutex);
			_ii_ioctl_done(ip);
			mutex_exit(&ip->bi_mutex);
		}
	} else {
		/* Begin copy operation */
		rc = _ii_mass_copy(ipa, ucopy, wait);
	}

	mutex_exit(&_ii_info_mutex);

	kmem_free(ipa, sizeof (_ii_info_t *) * ucopy->count);

	return (rc);
}

/*
 * _ii_group_copy
 * Retrieve list of sets in a group and use _ii_mass_copy to initiate
 * a copy/update of all of them.
 *
 * Calling/Exit State:
 * Returns 0 if the operations was successful.  Otherwise an
 * error code.
 */
int
_ii_group_copy(char *name, dsw_aioctl_t *ucopy, int wait)
{
	int		i;
	int		rc;
	uint64_t	hash;
	_ii_info_t	**ipa;
	_ii_lsthead_t	*head;
	_ii_lstinfo_t	*np;

	/* find group */
	hash = nsc_strhash(name);

	mutex_enter(&_ii_group_mutex);

	for (head = _ii_group_top; head; head = head->lst_next) {
		if (hash == head->lst_hash && strncmp(head->lst_name,
		    name, DSW_NAMELEN) == 0)
			break;
	}

	if (!head) {
		mutex_exit(&_ii_group_mutex);
		DTRACE_PROBE(_ii_group_copy);
		return (DSW_EGNOTFOUND);
	}

	/* Count entries */
	for (ucopy->count = 0, np = head->lst_start; np; np = np->lst_next)
		++ucopy->count;

	if (ucopy->count == 0) {
		mutex_exit(&_ii_group_mutex);
		return (DSW_EGNOTFOUND);
	}

	ipa = kmem_zalloc(sizeof (_ii_info_t *) * ucopy->count, KM_SLEEP);
	if (ipa == NULL) {
		mutex_exit(&_ii_group_mutex);
		return (ENOMEM);
	}

	/* Create list */
	mutex_enter(&_ii_info_mutex);
	np = head->lst_start;
	for (i = 0; i < ucopy->count; i++) {
		ASSERT(np != 0);

		ipa[i] = np->lst_ip;

		mutex_enter(&ipa[i]->bi_mutex);
		ipa[i]->bi_ioctl++;

		np = np->lst_next;
	}

	/* Begin copy operation */
	rc = _ii_mass_copy(ipa, ucopy, wait);

	mutex_exit(&_ii_info_mutex);
	mutex_exit(&_ii_group_mutex);

	kmem_free(ipa, sizeof (_ii_info_t *) * ucopy->count);

	return (rc);
}

/*
 * _ii_acopy
 *	Copy or update (take snapshot) II multiple volumes.
 *
 * Calling/Exit State:
 *	Returns 0 if the operation succeeded. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 */
int
_ii_acopy(intptr_t arg, int ilp32, int *rvp)
{
	int rc;
	size_t name_offset;
	char *list;
	char *nptr;
	char name[DSW_NAMELEN];
	dsw_aioctl_t ucopy;
	dsw_aioctl32_t ucopy32;
	spcs_s_info_t kstatus;

	*rvp = 0;

	name_offset = offsetof(dsw_aioctl_t, shadow_vol[0]);

	if (ilp32) {
		if (copyin((void *)arg, &ucopy32, sizeof (ucopy32)) < 0)
			return (EFAULT);
		II_TAIL_COPY(ucopy, ucopy32, flags, dsw_ioctl_t);
		ucopy.status = (spcs_s_info_t)ucopy32.status;
		name_offset = offsetof(dsw_aioctl32_t, shadow_vol[0]);
	} else if (copyin((void *)arg, &ucopy, sizeof (ucopy)) < 0)
		return (EFAULT);

	kstatus = spcs_s_kcreate();

	if (kstatus == NULL)
		return (ENOMEM);

	nptr = (char *)arg + name_offset;
	rc = 0;

	if (ucopy.flags & CV_IS_GROUP) {
		if (copyin(nptr, name, DSW_NAMELEN) < 0)
			return (spcs_s_ocopyoutf(&kstatus, ucopy.status,
			    EFAULT));

		/* kstatus information is handled within _ii_group_copy */
		rc = _ii_group_copy(name, &ucopy, 0);
	} else if (ucopy.count > 0) {
		list = kmem_alloc(DSW_NAMELEN * ucopy.count, KM_SLEEP);

		if (list == NULL)
			return (spcs_s_ocopyoutf(&kstatus, ucopy.status,
			    ENOMEM));

		if (copyin(nptr, list, DSW_NAMELEN * ucopy.count) < 0)
			return (spcs_s_ocopyoutf(&kstatus, ucopy.status,
			    EFAULT));

		rc = _ii_list_copy(list, &ucopy, 0);
		kmem_free(list, DSW_NAMELEN * ucopy.count);
	}

	return (spcs_s_ocopyoutf(&kstatus, ucopy.status, rc));
}

/*
 * _ii_bitsset
 *	Copy out II pair bitmaps to user program
 *
 * Calling/Exit State:
 *	Returns 0 if the operation succeeded. Otherwise an error code
 *	is returned and any additional error information is copied
 *	out to the user.
 */
int
_ii_bitsset(intptr_t arg, int ilp32, int cmd, int *rvp)
{
	dsw_bitsset_t ubitsset;
	dsw_bitsset32_t ubitsset32;
	nsc_size_t nbitsset;
	_ii_info_t *ip;
	int rc;
	spcs_s_info_t kstatus;
	int bitmap_size;

	*rvp = 0;

	if (ilp32) {
		if (copyin((void *)arg, &ubitsset32, sizeof (ubitsset32)))
			return (EFAULT);
		ubitsset.status = (spcs_s_info_t)ubitsset32.status;
		bcopy(ubitsset32.shadow_vol, ubitsset.shadow_vol, DSW_NAMELEN);
	} else if (copyin((void *)arg, &ubitsset, sizeof (ubitsset)))
		return (EFAULT);

	kstatus = spcs_s_kcreate();
	if (kstatus == NULL)
		return (ENOMEM);

	if (!ubitsset.shadow_vol[0])
		return (spcs_s_ocopyoutf(&kstatus, ubitsset.status,
		    DSW_EEMPTY));

	mutex_enter(&_ii_info_mutex);
	ip = _ii_find_set(ubitsset.shadow_vol);
	mutex_exit(&_ii_info_mutex);
	if (ip == NULL)
		return (spcs_s_ocopyoutf(&kstatus, ubitsset.status,
		    DSW_ENOTFOUND));

	mutex_exit(&ip->bi_mutex);

	if ((rc = _ii_rsrv_devs(ip, BMP, II_INTERNAL)) != 0) {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitsset.status,
		    DSW_ERSRVFAIL));
	}

	ubitsset.tot_size = ip->bi_size / DSW_SIZE;
	if ((ip->bi_size % DSW_SIZE) != 0)
		++ubitsset.tot_size;
	bitmap_size = (ubitsset.tot_size + 7) / 8;
	if (cmd == DSWIOC_SBITSSET)
		rc = II_CNT_BITS(ip, ip->bi_shdfba, &nbitsset, bitmap_size);
	else
		rc = II_CNT_BITS(ip, ip->bi_copyfba, &nbitsset, bitmap_size);
	ubitsset.tot_set = nbitsset;
	_ii_rlse_devs(ip, BMP);
	mutex_enter(&ip->bi_mutex);
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);
	if (rc) {
		spcs_s_add(kstatus, rc);
		return (spcs_s_ocopyoutf(&kstatus, ubitsset.status, DSW_EIO));
	}

	spcs_s_kfree(kstatus);
	/* return the fetched names to the user */
	if (ilp32) {
		ubitsset32.status = (spcs_s_info32_t)ubitsset.status;
		ubitsset32.tot_size = ubitsset.tot_size;
		ubitsset32.tot_set = ubitsset.tot_set;
		rc = copyout(&ubitsset32, (void *)arg, sizeof (ubitsset32));
	} else {
		rc = copyout(&ubitsset, (void *)arg, sizeof (ubitsset));
	}

	return (rc);
}

/*
 * _ii_stopvol
 *	Stop any copying process for shadow, and stop shadowing
 *
 */

static void
_ii_stopvol(_ii_info_t *ip)
{
	nsc_path_t *mst_tok;
	nsc_path_t *mstr_tok;
	nsc_path_t *shd_tok;
	nsc_path_t *shdr_tok;
	nsc_path_t *bmp_tok;
	int rc;

	while (_ii_stopcopy(ip) == EINTR)
		;

	DTRACE_PROBE(_ii_stopvol);

	mutex_enter(&ip->bi_mutex);
	mst_tok = ip->bi_mst_tok;
	mstr_tok = ip->bi_mstr_tok;
	shd_tok = ip->bi_shd_tok;
	shdr_tok = ip->bi_shdr_tok;
	bmp_tok = ip->bi_bmp_tok;
	ip->bi_shd_tok = 0;
	ip->bi_shdr_tok = 0;
	if (!NSHADOWS(ip)) {
		ip->bi_mst_tok = 0;
		ip->bi_mstr_tok = 0;
	}
	ip->bi_bmp_tok = 0;

	/* Wait for any _ii_open() calls to complete */

	while (ip->bi_ioctl) {
		ip->bi_state |= DSW_IOCTL;
		cv_wait(&ip->bi_ioctlcv, &ip->bi_mutex);
	}
	mutex_exit(&ip->bi_mutex);

	rc = _ii_reserve_begin(ip);
	if (rc) {
		cmn_err(CE_WARN, "!_ii_stopvol: _ii_reserve_begin %d", rc);
	}
	if (!NSHADOWS(ip)) {
		if (mst_tok) {
			rc = _ii_unregister_path(mst_tok, NSC_PCATCH,
			    "master");
			if (rc)
				cmn_err(CE_WARN, "!ii: unregister master %d",
				    rc);
		}

		if (mstr_tok) {
			rc = _ii_unregister_path(mstr_tok, NSC_PCATCH,
			    "raw master");
			if (rc)
				cmn_err(CE_WARN, "!ii: unregister raw "
				    "master %d", rc);
		}
	}

	if (shd_tok) {
		rc = _ii_unregister_path(shd_tok, NSC_PCATCH, "shadow");
		if (rc)
			cmn_err(CE_WARN, "!ii: unregister shadow %d", rc);
	}

	if (shdr_tok) {
		rc = _ii_unregister_path(shdr_tok, NSC_PCATCH, "raw shadow");
		if (rc)
			cmn_err(CE_WARN, "!ii: unregister raw shadow %d", rc);
	}

	if (bmp_tok) {
		rc = _ii_unregister_path(bmp_tok, NSC_PCATCH, "bitmap");
		if (rc)
			cmn_err(CE_WARN, "!ii: unregister bitmap %d", rc);
	}
	_ii_reserve_end(ip);

	/* Wait for all necessary _ii_close() calls to complete */
	mutex_enter(&ip->bi_mutex);

	while (total_ref(ip) != 0) {
		ip->bi_state |= DSW_CLOSING;
		cv_wait(&ip->bi_closingcv, &ip->bi_mutex);
	}
	if (!NSHADOWS(ip)) {
		nsc_set_owner(ip->bi_mstfd, NULL);
		nsc_set_owner(ip->bi_mstrfd, NULL);
	}
	nsc_set_owner(ip->bi_shdfd, NULL);
	nsc_set_owner(ip->bi_shdrfd, NULL);
	mutex_exit(&ip->bi_mutex);

}


/*
 * _ii_ioctl_done
 *	If this is the last one to complete, wakeup all processes waiting
 *	for ioctls to complete
 *
 */

static void
_ii_ioctl_done(_ii_info_t *ip)
{
	ASSERT(ip->bi_ioctl > 0);
	ip->bi_ioctl--;
	if (ip->bi_ioctl == 0 && (ip->bi_state & DSW_IOCTL)) {
		ip->bi_state &= ~DSW_IOCTL;
		cv_broadcast(&ip->bi_ioctlcv);
	}

}

/*
 * _ii_find_vol
 *	Search the configured shadows list for the supplied volume.
 *	If found, flag an ioctl in progress and return the locked _ii_info_t.
 *
 *	The caller must check to see if the bi_disable flag is set and
 *	treat it appropriately.
 *
 * ASSUMPTION:
 *	_ii_info_mutex must be locked prior to calling this function
 *
 */

static _ii_info_t *
_ii_find_vol(char *volume, int vol)
{
	_ii_info_t **xip, *ip;

	for (xip = &_ii_info_top; *xip; xip = &(*xip)->bi_next) {
		if ((*xip)->bi_disabled)
			continue;
		if (strcmp(volume, vol == MST ? ii_pathname((*xip)->bi_mstfd) :
		    (*xip)->bi_keyname) == 0) {
			break;
		}
	}

	if (!*xip) {
		DTRACE_PROBE(VolNotFound);
		return (NULL);
	}

	ip = *xip;
	if (!ip->bi_shd_tok && ((ip->bi_flags & DSW_SHDEXPORT) == 0)) {
		/* Not fully configured until bi_shd_tok is set */
		DTRACE_PROBE(SetNotConfiged);
		return (NULL);

	}
	mutex_enter(&ip->bi_mutex);
	ip->bi_ioctl++;

	return (ip);
}

static _ii_info_t *
_ii_find_set(char *volume)
{
	return (_ii_find_vol(volume, SHD));
}

/*
 * _ii_find_overflow
 *	Search the configured shadows list for the supplied overflow volume.
 *
 */

static _ii_overflow_t *
_ii_find_overflow(char *volume)
{
	_ii_overflow_t **xop, *op;

	mutex_enter(&_ii_overflow_mutex);

	DTRACE_PROBE(_ii_find_overflowmutex);

	for (xop = &_ii_overflow_top; *xop; xop = &(*xop)->ii_next) {
		if (strcmp(volume, (*xop)->ii_volname) == 0) {
			break;
		}
	}

	if (!*xop) {
		mutex_exit(&_ii_overflow_mutex);
		return (NULL);
	}

	op = *xop;
	mutex_exit(&_ii_overflow_mutex);

	return (op);
}

/*
 * _ii_bm_header_get
 *	Fetch the bitmap volume header
 *
 */

ii_header_t *
_ii_bm_header_get(_ii_info_t *ip, nsc_buf_t **tmp)
{
	ii_header_t *hdr;
	nsc_off_t read_fba;
	int rc;

	ASSERT(ip->bi_bmprsrv);		/* assert bitmap is reserved */
	ASSERT(MUTEX_HELD(&ip->bi_mutex));

	if ((ip->bi_flags & DSW_BMPOFFLINE) != 0)
		return (NULL);

	*tmp = NULL;
	read_fba = 0;

	II_READ_START(ip, bitmap);
	rc = nsc_alloc_buf(ip->bi_bmpfd, read_fba,
	    FBA_LEN(sizeof (ii_header_t)), NSC_RDWRBUF, tmp);
	II_READ_END(ip, bitmap, rc, FBA_LEN(sizeof (ii_header_t)));
	if (!II_SUCCESS(rc)) {
		if (ii_debug > 2)
			cmn_err(CE_WARN, "!ii: nsc_alloc_buf returned 0x%x",
			    rc);
		if (*tmp)
			(void) nsc_free_buf(*tmp);
		*tmp = NULL;
		mutex_exit(&ip->bi_mutex);
		_ii_error(ip, DSW_BMPOFFLINE);
		mutex_enter(&ip->bi_mutex);
		return (NULL);
	}

	hdr = (ii_header_t *)(*tmp)->sb_vec[0].sv_addr;

	return (hdr);
}


/*
 * _ii_bm_header_free
 *	Free the bitmap volume header
 *
 */

/* ARGSUSED */

void
_ii_bm_header_free(ii_header_t *hdr, _ii_info_t *ip, nsc_buf_t *tmp)
{
	(void) nsc_free_buf(tmp);

}

/*
 * _ii_bm_header_put
 *	Write out the modified bitmap volume header and free it
 *
 */

/* ARGSUSED */

int
_ii_bm_header_put(ii_header_t *hdr, _ii_info_t *ip, nsc_buf_t *tmp)
{
	nsc_off_t write_fba;
	int rc;

	ASSERT(MUTEX_HELD(&ip->bi_mutex));

	write_fba = 0;

	II_NSC_WRITE(ip, bitmap, rc, tmp, write_fba,
	    FBA_LEN(sizeof (ii_header_t)), 0);

	(void) nsc_free_buf(tmp);
	if (!II_SUCCESS(rc)) {
		mutex_exit(&ip->bi_mutex);
		_ii_error(ip, DSW_BMPOFFLINE);
		mutex_enter(&ip->bi_mutex);
		DTRACE_PROBE(_ii_bm_header_put);
		return (rc);
	} else {
		DTRACE_PROBE(_ii_bm_header_put_end);
		return (0);
	}
}

/*
 * _ii_flag_op
 *	Clear or set a flag in bi_flags and dsw_state.
 *	This relies on the ownership of the header block's nsc_buf
 *	for locking.
 *
 */

void
_ii_flag_op(and, or, ip, update)
int	and, or;
_ii_info_t *ip;
int update;
{
	ii_header_t *bm_header;
	nsc_buf_t *tmp;

	ip->bi_flags &= and;
	ip->bi_flags |= or;

	if (update == TRUE) {

		/*
		 * No point trying to access bitmap header if it's offline
		 * or has been disassociated from set via DSW_HANGING
		 */
		if ((ip->bi_flags & (DSW_BMPOFFLINE|DSW_HANGING)) == 0) {
			bm_header = _ii_bm_header_get(ip, &tmp);
			if (bm_header == NULL) {
				if (tmp)
					(void) nsc_free_buf(tmp);
				DTRACE_PROBE(_ii_flag_op_end);
				return;
			}
			bm_header->ii_state &= and;
			bm_header->ii_state |= or;
			/* copy over the mtime */
			bm_header->ii_mtime = ip->bi_mtime;
			(void) _ii_bm_header_put(bm_header, ip, tmp);
		}
	}

}

/*
 * _ii_nsc_io
 *	Perform read or write on an underlying nsc device
 * fd		- nsc file descriptor
 * flag		- nsc io direction and characteristics flag
 * fba_pos	- offset from beginning of device in FBAs
 * io_addr	- pointer to data buffer
 * io_len	- length of io in bytes
 */

int
_ii_nsc_io(_ii_info_t *ip, int ks, nsc_fd_t *fd, int flag, nsc_off_t fba_pos,
    unsigned char *io_addr, nsc_size_t io_len)
{
	nsc_buf_t *tmp = NULL;
	nsc_vec_t *vecp;
	uchar_t	*vaddr;
	size_t	copy_len;
	int64_t	vlen;
	int	rc;
	nsc_size_t	fba_req, fba_len;
	nsc_size_t	maxfbas = 0;
	nsc_size_t	tocopy;
	unsigned char *toaddr;

	rc = nsc_maxfbas(fd, 0, &maxfbas);
	if (!II_SUCCESS(rc)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!_ii_nsc_io: maxfbas failed (%d)", rc);
#endif
		maxfbas = DSW_CBLK_FBA;
	}

	toaddr = io_addr;
	fba_req = FBA_LEN(io_len);

#ifdef DEBUG_SPLIT_IO
	cmn_err(CE_NOTE, "!_ii_nsc_io: maxfbas = %08x", maxfbas);
	cmn_err(CE_NOTE, "!_ii_nsc_io: toaddr=%08x, io_len=%08x, fba_req=%08x",
	    toaddr, io_len, fba_req);
#endif

loop:
	tmp = NULL;
	fba_len = min(fba_req, maxfbas);
	tocopy = min(io_len, FBA_SIZE(fba_len));

	DTRACE_PROBE2(_ii_nsc_io_buffer, nsc_off_t, fba_pos,
	    nsc_size_t, fba_len);

#ifdef DEBUG_SPLIT_IO
	cmn_err(CE_NOTE, "!_ii_nsc_io: fba_pos=%08x, fba_len=%08x",
	    fba_pos, fba_len);
#endif

#ifndef DISABLE_KSTATS
	if (flag & NSC_READ) {
		switch (ks) {
		case KS_MST:
			II_READ_START(ip, master);
			break;
		case KS_SHD:
			II_READ_START(ip, shadow);
			break;
		case KS_BMP:
			II_READ_START(ip, bitmap);
			break;
		case KS_OVR:
			II_READ_START(ip, overflow);
			break;
		default:
			cmn_err(CE_WARN, "!Invalid kstats type %d", ks);
			break;
		}
	}
#endif

	rc = nsc_alloc_buf(fd, fba_pos, fba_len, flag, &tmp);

#ifndef DISABLE_KSTATS
	if (flag & NSC_READ) {
		switch (ks) {
		case KS_MST:
			II_READ_END(ip, master, rc, fba_len);
			break;
		case KS_SHD:
			II_READ_END(ip, shadow, rc, fba_len);
			break;
		case KS_BMP:
			II_READ_END(ip, bitmap, rc, fba_len);
			break;
		case KS_OVR:
			II_READ_END(ip, overflow, rc, fba_len);
			break;
		}
	}
#endif

	if (!II_SUCCESS(rc)) {
		if (tmp) {
			(void) nsc_free_buf(tmp);
		}

		return (EIO);
	}

	if ((flag & (NSC_WRITE|NSC_READ)) == NSC_WRITE &&
	    (FBA_OFF(io_len) != 0)) {
		/*
		 * Not overwriting all of the last FBA, so read in the
		 * old contents now before we overwrite it with the new
		 * data.
		 */
#ifdef DEBUG_SPLIT_IO
		cmn_err(CE_NOTE, "!_ii_nsc_io: Read-B4-Write %08x",
		    fba_pos+FBA_NUM(io_len));
#endif

#ifdef DISABLE_KSTATS
		rc = nsc_read(tmp, fba_pos+FBA_NUM(io_len), 1, 0);
#else
		switch (ks) {
		case KS_MST:
			II_NSC_READ(ip, master, rc, tmp,
			    fba_pos+FBA_NUM(io_len), 1, 0);
			break;
		case KS_SHD:
			II_NSC_READ(ip, shadow, rc, tmp,
			    fba_pos+FBA_NUM(io_len), 1, 0);
			break;
		case KS_BMP:
			II_NSC_READ(ip, bitmap, rc, tmp,
			    fba_pos+FBA_NUM(io_len), 1, 0);
			break;
		case KS_OVR:
			II_NSC_READ(ip, overflow, rc, tmp,
			    fba_pos+FBA_NUM(io_len), 1, 0);
			break;
		case KS_NA:
			rc = nsc_read(tmp, fba_pos+FBA_NUM(io_len), 1, 0);
			break;
		default:
			cmn_err(CE_WARN, "!Invalid kstats type %d", ks);
			rc = nsc_read(tmp, fba_pos+FBA_NUM(io_len), 1, 0);
			break;
		}
#endif
		if (!II_SUCCESS(rc)) {
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
			cmn_err(CE_WARN, "!_ii_nsc_io: ran off end of handle");
#endif
			break;
		}

		copy_len = (size_t)min(vlen, tocopy);

		DTRACE_PROBE1(_ii_nsc_io_bcopy, size_t, copy_len);

		if (flag & NSC_WRITE)
			bcopy(io_addr, vaddr, copy_len);
		else
			bcopy(vaddr, io_addr, copy_len);

		toaddr += copy_len;
		tocopy -= copy_len;
		io_addr += copy_len;
		io_len -= copy_len;
		vaddr += copy_len;
		vlen -= copy_len;

		if (vlen <= 0) {
			vecp++;
			vaddr = vecp->sv_addr;
			vlen = vecp->sv_len;
		}
	}

	if (flag & NSC_WRITE) {
#ifdef DISABLE_KSTATS
		rc = nsc_write(tmp, tmp->sb_pos, tmp->sb_len, 0);
#else
		switch (ks) {
		case KS_MST:
			II_NSC_WRITE(ip, master, rc, tmp, tmp->sb_pos,
			    tmp->sb_len, 0);
			break;
		case KS_SHD:
			II_NSC_WRITE(ip, shadow, rc, tmp, tmp->sb_pos,
			    tmp->sb_len, 0);
			break;
		case KS_BMP:
			II_NSC_WRITE(ip, bitmap, rc, tmp, tmp->sb_pos,
			    tmp->sb_len, 0);
			break;
		case KS_OVR:
			II_NSC_WRITE(ip, overflow, rc, tmp, tmp->sb_pos,
			    tmp->sb_len, 0);
			break;
		case KS_NA:
			rc = nsc_write(tmp, tmp->sb_pos, tmp->sb_len, 0);
			break;
		default:
			cmn_err(CE_WARN, "!Invalid kstats type %d", ks);
			rc = nsc_write(tmp, tmp->sb_pos, tmp->sb_len, 0);
			break;
		}
#endif
		if (!II_SUCCESS(rc)) {
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
 * ii_overflow_attach
 */
static int
ii_overflow_attach(_ii_info_t *ip, char *name, int first)
{
	_ii_overflow_t *op;
	int rc = 0;
	int reserved = 0;
	int mutex_set = 0;
	int II_OLD_OMAGIC = 0x426c7565; /* "Blue" */

	mutex_enter(&_ii_overflow_mutex);
	/* search for name in list */
	for (op = _ii_overflow_top; op; op = op->ii_next) {
		if (strncmp(op->ii_volname, name, DSW_NAMELEN) == 0)
			break;
	}
	if (op) {
		ip->bi_overflow = op;
		op->ii_crefcnt++;
		op->ii_drefcnt++;
		if ((op->ii_flags & IIO_CNTR_INVLD) && (op->ii_hversion >= 1)) {
			if (!first)
				mutex_enter(&ip->bi_mutex);
			ip->bi_flags |= DSW_OVRHDRDRTY;
			if (!first)
				mutex_exit(&ip->bi_mutex);
			op->ii_urefcnt++;
		}
#ifndef DISABLE_KSTATS
		ip->bi_kstat_io.overflow = op->ii_overflow;
		(void) strlcpy(ip->bi_kstat_io.ovrio, op->ii_ioname,
		    KSTAT_DATA_CHAR_LEN);
#endif
		/* write header */
		if (!(rc = nsc_reserve(op->ii_dev->bi_fd, NSC_MULTI))) {
			rc = _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd,
			    NSC_WRBUF, II_OHEADER_FBA,
			    (unsigned char *)&op->ii_do, sizeof (op->ii_do));
			(void) nsc_release(op->ii_dev->bi_fd);
			++iigkstat.assoc_over.value.ul;
		}
		mutex_exit(&_ii_overflow_mutex);
		return (rc);
	}
	if ((op = kmem_zalloc(sizeof (*op), KM_SLEEP)) == NULL) {
		mutex_exit(&_ii_overflow_mutex);
		return (ENOMEM);
	}
	if ((op->ii_dev = kmem_zalloc(sizeof (_ii_info_dev_t), KM_SLEEP))
	    == NULL) {
		kmem_free(op, sizeof (*op));
		mutex_exit(&_ii_overflow_mutex);
		return (ENOMEM);
	}
#ifndef DISABLE_KSTATS
	if ((op->ii_overflow = _ii_overflow_kstat_create(ip, op))) {
		ip->bi_kstat_io.overflow = op->ii_overflow;
		(void) strlcpy(op->ii_ioname, ip->bi_kstat_io.ovrio,
		    KSTAT_DATA_CHAR_LEN);
	} else {
		goto fail;
	}
#endif
	/* open overflow volume */
	op->ii_dev->bi_fd = nsc_open(name, NSC_IIR_ID|NSC_FILE|NSC_RDWR, NULL,
	    (blind_t)&(op->ii_dev->bi_iodev), &rc);
	if (!op->ii_dev->bi_fd)
		op->ii_dev->bi_fd = nsc_open(name,
		    NSC_IIR_ID|NSC_DEVICE|NSC_RDWR, NULL,
		    (blind_t)&(op->ii_dev->bi_iodev), &rc);
	if (op->ii_dev->bi_fd == NULL) {
		goto fail;
	}
	if ((rc = nsc_reserve(op->ii_dev->bi_fd, 0)) != 0)
		goto fail;
	reserved = 1;
	/* register path */
	op->ii_dev->bi_tok = _ii_register_path(name, NSC_DEVICE,
	    _ii_ior);
	if (!op->ii_dev->bi_tok) {
		goto fail;
	}
	/* read header */
	rc = _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd, NSC_RDBUF,
	    II_OHEADER_FBA, (unsigned char *)&op->ii_do, sizeof (op->ii_do));
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_OVROFFLINE);
		goto fail;
	}
	/* On resume, check for old hmagic */
	if (strncmp(op->ii_volname, name, DSW_NAMELEN) ||
	    ((op->ii_hmagic != II_OLD_OMAGIC) &&
	    (op->ii_hmagic != II_OMAGIC))) {
		rc = DSW_EOMAGIC;
		goto fail;
	}
	/* set up counts */
	op->ii_crefcnt = 1;
	op->ii_drefcnt = 0;
	op->ii_urefcnt = 0;
	op->ii_hmagic = II_OMAGIC;
	if (!first) {
		/* if header version > 0, check if header written */
		if (((op->ii_flags & IIO_HDR_WRTN) == 0) &&
		    (op->ii_hversion >= 1)) {
			op->ii_flags |= IIO_CNTR_INVLD;
			mutex_enter(&ip->bi_mutex);
			ip->bi_flags |= DSW_OVRHDRDRTY;
			mutex_exit(&ip->bi_mutex);
			op->ii_urefcnt++;
		}
	}
	op->ii_flags &= ~IIO_HDR_WRTN;
	op->ii_drefcnt++;
	/* write header */
	rc = _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd, NSC_WRBUF,
	    II_OHEADER_FBA, (unsigned char *)&op->ii_do, sizeof (op->ii_do));
	nsc_release(op->ii_dev->bi_fd);
	reserved = 0;
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_OVROFFLINE);
		goto fail;
	}

	mutex_init(&op->ii_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_set++;

	/* link onto list */
	op->ii_next = _ii_overflow_top;
	_ii_overflow_top = op;
	ip->bi_overflow = op;

	++iigkstat.assoc_over.value.ul;
	mutex_exit(&_ii_overflow_mutex);

	DTRACE_PROBE(_ii_overflow_attach_end);
	return (0);
fail:
#ifndef DISABLE_KSTATS
	/* Clean-up kstat stuff */
	if (op->ii_overflow) {
		kstat_delete(op->ii_overflow);
		mutex_destroy(&op->ii_kstat_mutex);
	}
#endif
	/* clean up mutex if we made it that far */
	if (mutex_set) {
		mutex_destroy(&op->ii_mutex);
	}

	if (op->ii_dev) {
		if (op->ii_dev->bi_tok) {
			(void) _ii_unregister_path(op->ii_dev->bi_tok, 0,
			    "overflow");
		}
		if (reserved)
			(void) nsc_release(op->ii_dev->bi_fd);
		if (op->ii_dev->bi_fd)
			(void) nsc_close(op->ii_dev->bi_fd);
		kmem_free(op->ii_dev, sizeof (_ii_info_dev_t));
	}
	kmem_free(op, sizeof (*op));
	mutex_exit(&_ii_overflow_mutex);

	return (rc);
}

/*
 * ii_overflow_free
 * Assumes that ip is locked for I/O
 */
static void
ii_overflow_free(_ii_info_t *ip, int reclaim)
{
	_ii_overflow_t *op, **xp;

	if ((op = ip->bi_overflow) == NULL)
		return;
	ip->bi_kstat_io.overflow = NULL;
	mutex_enter(&_ii_overflow_mutex);
	switch (reclaim) {
	case NO_RECLAIM:
		if (--(op->ii_drefcnt) == 0) {
			/* indicate header written */
			op->ii_flags |= IIO_HDR_WRTN;
			/* write out header */
			ASSERT(op->ii_dev->bi_fd);
			(void) nsc_reserve(op->ii_dev->bi_fd, NSC_MULTI);
			(void) _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd,
			    NSC_WRBUF, II_OHEADER_FBA,
			    (unsigned char *)&op->ii_do,
			    sizeof (op->ii_do));
			nsc_release(op->ii_dev->bi_fd);
		}
		break;
	case RECLAIM:
		ii_reclaim_overflow(ip);
		/* FALLTHRU */
	case INIT_OVR:
		if (--(op->ii_drefcnt) == 0) {
			/* reset to new condition, c.f. _ii_ocreate() */
			op->ii_used = 1;
			op->ii_unused = op->ii_nchunks - op->ii_used;
			op->ii_freehead = II_NULLNODE;
		}

		/* write out header */
		ASSERT(op->ii_dev->bi_fd);
		(void) nsc_reserve(op->ii_dev->bi_fd, NSC_MULTI);
		(void) _ii_nsc_io(ip, KS_OVR, op->ii_dev->bi_fd, NSC_WRBUF,
		    II_OHEADER_FBA, (unsigned char *)&op->ii_do,
		    sizeof (op->ii_do));
		nsc_release(op->ii_dev->bi_fd);
	}

	if (--(op->ii_crefcnt) == 0) {
		/* Close fd and unlink from active chain; */

		(void) _ii_unregister_path(op->ii_dev->bi_tok, 0, "overflow");
		(void) nsc_close(op->ii_dev->bi_fd);

		for (xp = &_ii_overflow_top; *xp && *xp != op;
		    xp = &((*xp)->ii_next))
			/* NULL statement */;
		*xp = op->ii_next;

		if (op->ii_overflow) {
			kstat_delete(op->ii_overflow);
		}

		/* Clean up ii_overflow_t mutexs */
		mutex_destroy(&op->ii_kstat_mutex);
		mutex_destroy(&op->ii_mutex);

		if (op->ii_dev)
			kmem_free(op->ii_dev, sizeof (_ii_info_dev_t));
		kmem_free(op, sizeof (*op));
	}
	ip->bi_overflow = NULL;
	--iigkstat.assoc_over.value.ul;
	mutex_exit(&_ii_overflow_mutex);

}

/*
 * ii_sibling_free
 *	Free resources and unlink the sibling chains etc.
 */

static void
ii_sibling_free(_ii_info_t *ip)
{
	_ii_info_t *hip, *yip;

	if (!ip)
		return;

	if (ip->bi_shdr_tok)
		(void) _ii_unregister_path(ip->bi_shdr_tok, 0, "raw shadow");

	if (ip->bi_shd_tok)
		(void) _ii_unregister_path(ip->bi_shd_tok, 0, "shadow");

	rw_enter(&ip->bi_linkrw, RW_WRITER);

	ip->bi_shd_tok = NULL;
	ip->bi_shdr_tok = NULL;

	if (NSHADOWS(ip)) {
		mutex_enter(&_ii_info_mutex);
		if (ip->bi_head == ip) {	/* removing head of list */
			hip = ip->bi_sibling;
			for (yip = hip; yip; yip = yip->bi_sibling)
				yip->bi_head = hip;

		} else {		/* removing member of list */
			hip = ip->bi_head;
			for (yip = ip->bi_head; yip; yip = yip->bi_sibling) {
				if (yip->bi_sibling == ip) {
					yip->bi_sibling = ip->bi_sibling;
					break;
				}
			}
		}
		hip->bi_master->bi_head = hip;
		if (ip->bi_master == ip) {    /* master I/O goes through this */
			mutex_exit(&_ii_info_mutex);
			_ii_info_freeshd(ip);
			rw_exit(&ip->bi_linkrw);
			return;
		}
		mutex_exit(&_ii_info_mutex);
	} else {
		if (ip->bi_master != ip)	/* last ref to master side ip */
			_ii_info_free(ip->bi_master);	/* ==A== */
	}

	if (ip->bi_master != ip) {	/* info_free ==A== will close these */
		/*
		 * Null out any pointers to shared master side resources
		 * that should only be freed once when the last reference
		 * to this master is freed and calls _ii_info_free().
		 */
		ip->bi_mstdev = NULL;
		ip->bi_mstrdev = NULL;
		ip->bi_kstat_io.master = NULL;
	}
	rw_exit(&ip->bi_linkrw);
	_ii_info_free(ip);

}

/*
 * _ii_info_freeshd
 *	Free shadow side resources
 *
 * Calling/Exit State:
 *	No mutexes should be held on entry to this function.
 *
 * Description:
 *	Frees the system resources associated with the shadow
 *	access, leaving the master side alone. This allows the
 *	original master side to continue in use while there are
 *	outstanding references to this _ii_info_t.
 */

static void
_ii_info_freeshd(_ii_info_t *ip)
{
	if (!ip)
		return;
	if ((ip->bi_flags&DSW_HANGING) == DSW_HANGING)
		return;		/* this work has already been completed */

	II_FLAG_SETX(DSW_HANGING, ip);

	if (ip->bi_cluster)
		(void) II_UNLINK_CLUSTER(ip);
	if (ip->bi_group)
		(void) II_UNLINK_GROUP(ip);

	if (ip->bi_shdfd && ip->bi_shdrsrv)
		nsc_release(ip->bi_shdfd);
	if (ip->bi_shdrfd && ip->bi_shdrrsrv)
		nsc_release(ip->bi_shdrfd);
	if (ip->bi_bmpfd && ip->bi_bmprsrv)
		nsc_release(ip->bi_bmpfd);

	if (ip->bi_bmp_tok)
		(void) _ii_unregister_path(ip->bi_bmp_tok, 0, "bitmap");

	if (ip->bi_shdr_tok)
		(void) _ii_unregister_path(ip->bi_shdr_tok, 0, "raw shadow");

	if (ip->bi_shd_tok)
		(void) _ii_unregister_path(ip->bi_shd_tok, 0, "shadow");
	ip->bi_shd_tok = NULL;
	ip->bi_shdr_tok = NULL;

	if (ip->bi_shdfd)
		(void) nsc_close(ip->bi_shdfd);

	if (ip->bi_shdrfd)
		(void) nsc_close(ip->bi_shdrfd);

	if (ip->bi_bmpfd)
		(void) nsc_close(ip->bi_bmpfd);

	ip->bi_shdfd = NULL;
	ip->bi_shdrfd = NULL;
	ip->bi_bmpfd = NULL;

	if (ip->bi_busy)
		kmem_free(ip->bi_busy,
		    1 + (ip->bi_size / (DSW_SIZE * DSW_BITS)));
	ip->bi_busy = NULL;

	if (ip->bi_kstat_io.shadow) {
		kstat_delete(ip->bi_kstat_io.shadow);
		ip->bi_kstat_io.shadow = NULL;
	}
	if (ip->bi_kstat_io.bitmap) {
		kstat_delete(ip->bi_kstat_io.bitmap);
		ip->bi_kstat_io.bitmap = NULL;
	}
	if (ip->bi_kstat) {
		kstat_delete(ip->bi_kstat);
		ip->bi_kstat = NULL;
	}

}

/*
 * _ii_info_free
 *	Free resources
 *
 * Calling/Exit State:
 *	No mutexes should be held on entry to this function.
 *
 * Description:
 *	Frees the system resources associated with the specified
 *	II information structure.
 */

static void
_ii_info_free(_ii_info_t *ip)
{
	_ii_info_t **xip;

	if (!ip)
		return;

	mutex_enter(&_ii_info_mutex);
	for (xip = &_ii_mst_top; *xip; xip = &((*xip)->bi_nextmst)) {
		if (ip == *xip) {
			*xip = ip->bi_nextmst;
			break;
		}
	}
	mutex_exit(&_ii_info_mutex);

	/* this rw_enter forces us to wait until all nsc_buffers are freed */
	rw_enter(&ip->bi_linkrw, RW_WRITER);
	if (ip->bi_mstdev && ip->bi_mstfd && ip->bi_mstrsrv)
		nsc_release(ip->bi_mstfd);
	if (ip->bi_mstrdev && ip->bi_mstrfd && ip->bi_mstrrsrv)
		nsc_release(ip->bi_mstrfd);

	if (ip->bi_mstdev && ip->bi_mst_tok)
		(void) _ii_unregister_path(ip->bi_mst_tok, 0, "master");
	if (ip->bi_mstrdev && ip->bi_mstr_tok)
		(void) _ii_unregister_path(ip->bi_mstr_tok, 0, "raw master");

	if (ip->bi_mstdev && ip->bi_mstfd)
		(void) nsc_close(ip->bi_mstfd);
	if (ip->bi_mstrdev && ip->bi_mstrfd)
		(void) nsc_close(ip->bi_mstrfd);
	rw_exit(&ip->bi_linkrw);

	if (ip->bi_mstdev) {
		nsc_kmem_free(ip->bi_mstdev, sizeof (*ip->bi_mstdev));
	}
	if (ip->bi_mstrdev) {
		nsc_kmem_free(ip->bi_mstrdev, sizeof (*ip->bi_mstrdev));
	}

	if (ip->bi_kstat_io.master) {
		kstat_delete(ip->bi_kstat_io.master);
	}
	if (ip->bi_kstat_io.shadow) {
		kstat_delete(ip->bi_kstat_io.shadow);
		ip->bi_kstat_io.shadow = 0;
	}
	if (ip->bi_kstat_io.bitmap) {
		kstat_delete(ip->bi_kstat_io.bitmap);
		ip->bi_kstat_io.bitmap = 0;
	}
	if (ip->bi_kstat) {
		kstat_delete(ip->bi_kstat);
		ip->bi_kstat = NULL;
	}

	/* this rw_enter forces us to wait until all nsc_buffers are freed */
	rw_enter(&ip->bi_linkrw, RW_WRITER);
	rw_exit(&ip->bi_linkrw);

	mutex_destroy(&ip->bi_mutex);
	mutex_destroy(&ip->bi_rsrvmutex);
	mutex_destroy(&ip->bi_rlsemutex);
	mutex_destroy(&ip->bi_bmpmutex);
	mutex_destroy(&ip->bi_chksmutex);
	cv_destroy(&ip->bi_copydonecv);
	cv_destroy(&ip->bi_reservecv);
	cv_destroy(&ip->bi_releasecv);
	cv_destroy(&ip->bi_ioctlcv);
	cv_destroy(&ip->bi_closingcv);
	cv_destroy(&ip->bi_busycv);
	rw_destroy(&ip->bi_busyrw);
	rw_destroy(&ip->bi_linkrw);

	_ii_info_freeshd(ip);

#ifdef DEBUG
	ip->bi_head = (_ii_info_t *)0xdeadbeef;
#endif

	nsc_kmem_free(ip, sizeof (*ip));

}

/*
 * _ii_copy_chunks
 *	Perform a copy of some chunks
 *
 * Calling/Exit State:
 *	Returns 0 if the data was copied successfully, otherwise
 *	error code.
 *
 * Description:
 *	flag is set to CV_SHD2MST if the data is to be copied from the shadow
 *	to the master, 0 if it is to be copied from the master to the shadow.
 */

static int
_ii_copy_chunks(_ii_info_t *ip, int flag, chunkid_t chunk_num, int nchunks)
{
	int	mst_flag;
	int	shd_flag;
	int	ovr_flag;
	nsc_off_t	pos;
	nsc_size_t	len;
	int	rc;
	nsc_off_t	shd_pos;
	chunkid_t	shd_chunk;
	nsc_buf_t *mst_tmp = NULL;
	nsc_buf_t *shd_tmp = NULL;

	if (ip->bi_flags & DSW_MSTOFFLINE) {
		DTRACE_PROBE(_ii_copy_chunks_end);
		return (EIO);
	}

	if (ip->bi_flags & (DSW_SHDOFFLINE|DSW_SHDEXPORT|DSW_SHDIMPORT)) {
		DTRACE_PROBE(_ii_copy_chunks_end);
		return (EIO);
	}

	if (flag == CV_SHD2MST) {
		mst_flag = NSC_WRBUF|NSC_WRTHRU;
		shd_flag = NSC_RDBUF;
	} else {
		shd_flag = NSC_WRBUF|NSC_WRTHRU;
		mst_flag = NSC_RDBUF;
	}

	pos = DSW_CHK2FBA(chunk_num);
	len = DSW_SIZE * nchunks;
	if (pos + len > ip->bi_size)
		len = ip->bi_size - pos;
	if (ip->bi_flags & DSW_TREEMAP) {
		ASSERT(nchunks == 1);
		shd_chunk = ii_tsearch(ip, chunk_num);
		if (shd_chunk == II_NULLNODE) {
			/* shadow is full */
			mutex_enter(&ip->bi_mutex);
			II_FLAG_SET(DSW_OVERFLOW, ip);
			mutex_exit(&ip->bi_mutex);
			DTRACE_PROBE(_ii_copy_chunks_end);
			return (EIO);
		}

		ovr_flag = II_ISOVERFLOW(shd_chunk);
		shd_pos = DSW_CHK2FBA((ovr_flag) ?
		    II_2OVERFLOW(shd_chunk) : shd_chunk);
	} else {
		ovr_flag = FALSE;
		shd_chunk = chunk_num;
		shd_pos = pos;
	}

	/*
	 * Always allocate the master side before the shadow to
	 * avoid deadlocks on the same chunk.
	 */

	DTRACE_PROBE2(_ii_copy_chunks_alloc, nsc_off_t, pos, nsc_size_t, len);

	II_ALLOC_BUF(ip, master, rc, MSTFD(ip), pos, len, mst_flag, &mst_tmp);
	if (!II_SUCCESS(rc)) {
		if (mst_tmp)
			(void) nsc_free_buf(mst_tmp);
		_ii_error(ip, DSW_MSTOFFLINE);
		DTRACE_PROBE(_ii_copy_chunks_end);
		return (rc);
	}

	if (ovr_flag) {
		/* use overflow volume */
		(void) nsc_reserve(OVRFD(ip), NSC_MULTI);
		II_ALLOC_BUF(ip, overflow, rc, OVRFD(ip), shd_pos, len,
		    shd_flag, &shd_tmp);
	} else {
		II_ALLOC_BUF(ip, shadow, rc, SHDFD(ip), shd_pos, len, shd_flag,
		    &shd_tmp);
	}
	if (!II_SUCCESS(rc)) {
		(void) nsc_free_buf(mst_tmp);
		if (shd_tmp)
			(void) nsc_free_buf(shd_tmp);
		if (ovr_flag)
			nsc_release(OVRFD(ip));
		_ii_error(ip, DSW_SHDOFFLINE);
		if (ovr_flag)
			_ii_error(ip, DSW_OVROFFLINE);
		DTRACE_PROBE(_ii_copy_chunks_end);
		return (rc);
	}

	/*
	 * The direction of copy is determined by the mst_flag.
	 */
	DTRACE_PROBE2(_ii_copy_chunks_copy, kstat_named_t, ii_copy_direct,
	    int, mst_flag);

	if (ii_copy_direct) {
		if (mst_flag & NSC_WRBUF) {
			if (ovr_flag) {
				II_NSC_COPY_DIRECT(ip, overflow, master, rc,
				    shd_tmp, mst_tmp, shd_pos, pos, len)
			} else {
				II_NSC_COPY_DIRECT(ip, shadow, master, rc,
				    shd_tmp, mst_tmp, shd_pos, pos, len)
			}
			if (!II_SUCCESS(rc)) {
				/* A copy has failed - something is wrong */
				_ii_error(ip, DSW_MSTOFFLINE);
				_ii_error(ip, DSW_SHDOFFLINE);
				if (ovr_flag)
					_ii_error(ip, DSW_OVROFFLINE);
			}
		} else {
			if (ovr_flag) {
				II_NSC_COPY_DIRECT(ip, master, overflow, rc,
				    mst_tmp, shd_tmp, pos, shd_pos, len);
			} else {
				II_NSC_COPY_DIRECT(ip, master, shadow, rc,
				    mst_tmp, shd_tmp, pos, shd_pos, len);
			}
			if (!II_SUCCESS(rc)) {
				/*
				 * A failure has occurred during the above copy.
				 * The macro calls nsc_copy_direct, which will
				 * never return a read failure, only a write
				 * failure. With this assumption, we should
				 * take only the target volume offline.
				 */
				_ii_error(ip, DSW_SHDOFFLINE);
				if (ovr_flag)
					_ii_error(ip, DSW_OVROFFLINE);
			}
		}
	} else {
		if (mst_flag & NSC_WRBUF) {
			rc = nsc_copy(shd_tmp, mst_tmp, shd_pos, pos, len);
			if (II_SUCCESS(rc)) {
				II_NSC_WRITE(ip, master, rc, mst_tmp, pos, len,
				    0);
				if (!II_SUCCESS(rc))
					_ii_error(ip, DSW_MSTOFFLINE);
			} else {
				/* A copy has failed - something is wrong */
				_ii_error(ip, DSW_MSTOFFLINE);
				_ii_error(ip, DSW_SHDOFFLINE);
			}
		} else {
			rc = nsc_copy(mst_tmp, shd_tmp, pos, shd_pos, len);
			if (II_SUCCESS(rc)) {
				if (ovr_flag) {
					II_NSC_WRITE(ip, overflow, rc, shd_tmp,
					    shd_pos, len, 0);
				} else {
					II_NSC_WRITE(ip, shadow, rc, shd_tmp,
					    shd_pos, len, 0);
				}
				if (!II_SUCCESS(rc)) {
					_ii_error(ip, DSW_SHDOFFLINE);
					if (ovr_flag)
						_ii_error(ip, DSW_OVROFFLINE);
				}
			} else {
				/* A copy has failed - something is wrong */
				_ii_error(ip, DSW_MSTOFFLINE);
				_ii_error(ip, DSW_SHDOFFLINE);
			}
		}
	}

	(void) nsc_free_buf(mst_tmp);
	(void) nsc_free_buf(shd_tmp);
	if (ovr_flag)
		nsc_release(OVRFD(ip));

	DTRACE_PROBE(_ii_copy_chunks);

	if (II_SUCCESS(rc)) {
		(void) II_CLR_COPY_BITS(ip, chunk_num, nchunks);
		rc = 0;
	}

	return (rc);
}


/*
 * _ii_copy_on_write
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise error code.
 *
 * Description:
 *	Determines if a copy on write is necessary, and performs it.
 *	A copy on write is necessary in the following cases:
 *		- No copy is in progress and the shadow bit is clear, which
 *		  means this is the first write to this track.
 *		- A copy is in progress and the copy bit is set, which means
 *		  that a track copy is required.
 *	If a copy to the master is to be done, make a recursive call to this
 *	function to do any necessary copy on write on other InstantImage groups
 * 	that share the same master volume.
 */

static int
_ii_copy_on_write(_ii_info_t *ip, int flag, chunkid_t chunk_num, int nchunks)
{
	int rc = 0;
	int rtype;
	int hanging =  (ip->bi_flags&DSW_HANGING);

	if (hanging ||
	    (flag & (CV_SIBLING|CV_SHD2MST)) == CV_SHD2MST && NSHADOWS(ip)) {
		_ii_info_t *xip;
		/*
		 * Preserve copy of master for all other shadows of this master
		 * before writing our data onto the master.
		 */

		/*
		 * Avoid deadlock with COW on same chunk of sibling shadow
		 * by unlocking this chunk before copying all other sibling
		 * chunks.
		 */

		/*
		 * Only using a single chunk when copying to master avoids
		 * complex code here.
		 */

		ASSERT(nchunks == 1);
		if (!hanging)
			_ii_unlock_chunk(ip, chunk_num);
		for (xip = ip->bi_head; xip; xip = xip->bi_sibling) {
			if (xip == ip)		/* don't copy ourselves again */
				continue;

			DTRACE_PROBE(_ii_copy_on_write);

			rw_enter(&xip->bi_linkrw, RW_READER);
			mutex_enter(&xip->bi_mutex);
			if (xip->bi_disabled) {
				mutex_exit(&xip->bi_mutex);
				rw_exit(&xip->bi_linkrw);
				continue;	/* this set is stopping */
			}
			xip->bi_shdref++;
			mutex_exit(&xip->bi_mutex);
			/* don't waste time asking for MST as ip shares it */
			rtype = SHDR|BMP;
			(void) _ii_rsrv_devs(xip, rtype, II_INTERNAL);
			_ii_lock_chunk(xip, chunk_num);
			rc = _ii_copy_on_write(xip, flag | CV_SIBLING,
			    chunk_num, 1);

			/*
			 * See comments in _ii_shadow_write()
			 */
			if (rc == 0 ||
			    (rc == EIO && (xip->bi_flags&DSW_OVERFLOW) != 0))
				(void) II_SET_SHD_BIT(xip, chunk_num);

			_ii_unlock_chunk(xip, chunk_num);
			_ii_rlse_devs(xip, rtype);
			mutex_enter(&xip->bi_mutex);
			xip->bi_shdref--;
			if (xip->bi_state & DSW_CLOSING) {
				if (total_ref(xip) == 0) {
					cv_signal(&xip->bi_closingcv);
				}
			}
			mutex_exit(&xip->bi_mutex);
			rw_exit(&xip->bi_linkrw);
		}
		if (hanging) {
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (0);
		}
		/*
		 * Reacquire chunk lock and check that a COW by a sibling
		 * has not already copied this chunk.
		 */
		_ii_lock_chunk(ip, chunk_num);
		rc = II_TST_SHD_BIT(ip, chunk_num);
		if (rc < 0) {
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (EIO);
		}
		if (rc != 0) {
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (0);
		}
	}

	if ((ip->bi_flags & DSW_COPYING) == 0) {
		/* Not copying at all */

		if ((ip->bi_flags & DSW_GOLDEN) == DSW_GOLDEN) {
			/* No copy-on-write as it is independent */
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (0);
		}

		/* Dependent, so depends on shadow bit */

		if ((flag == CV_SHD2MST) &&
		    ((ip->bi_flags & DSW_SHDOFFLINE) != 0)) {
			/*
			 * Writing master but shadow is offline, so
			 * no need to copy on write or set shadow bit
			 */
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (0);
		}
		if (ip->bi_flags & DSW_BMPOFFLINE) {
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (EIO);
		}
		rc = II_TST_SHD_BIT(ip, chunk_num);
		if (rc < 0) {
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (EIO);
		}
		if (rc == 0) {
			/* Shadow bit clear, copy master to shadow */
			rc = _ii_copy_chunks(ip, 0, chunk_num, nchunks);
		}
	} else {
		/* Copying one way or the other */
		if (ip->bi_flags & DSW_BMPOFFLINE) {
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (EIO);
		}
		rc = II_TST_COPY_BIT(ip, chunk_num);
		if (rc < 0) {
			DTRACE_PROBE(_ii_copy_on_write_end);
			return (EIO);
		}
		if (rc) {
			/* Copy bit set, do a copy */
			if ((ip->bi_flags & DSW_COPYINGS) == 0) {
				/* Copy master to shadow */
				rc = _ii_copy_chunks(ip, 0, chunk_num, nchunks);
			} else {
				/* Copy shadow to master */
				rc = _ii_copy_chunks(ip, CV_SHD2MST, chunk_num,
				    nchunks);
			}
		}
	}
	return (rc);
}

#ifdef	DEBUG
int ii_maxchunks = 0;
#endif

/*
 * _ii_copyvolp()
 *	Copy volume process.
 *
 * Calling/Exit State:
 *	Passes 0 back to caller when the copy is complete or has been aborted,
 * 	otherwise error code.
 *
 * Description:
 *	According to the flag, copy the master to the shadow volume or the
 *	shadow to the master volume. Upon return wakeup all processes waiting
 *	for this copy.
 *
 */

static void
_ii_copyvolp(struct copy_args *ca)
{
	chunkid_t	chunk_num;
	int	rc = 0;
	chunkid_t	max_chunk;
	nsc_size_t	nc_max;
	int		nc_try, nc_got;
	nsc_size_t	mst_max, shd_max;
	_ii_info_t *ip;
	int	flag;
	nsc_size_t	bitmap_size;
	nsc_size_t	shadow_set, copy_set;
	int	chunkcount = 0;
	int	rsrv = 1;
	spcs_s_info_t kstatus;

	ip = ca->ip;
	flag = ca->flag;
	kstatus = ca->kstatus;

	if (ip->bi_disabled) {
		rc = DSW_EABORTED;
		goto skip;
	}
	max_chunk = ip->bi_size / DSW_SIZE;
	if ((ip->bi_size % DSW_SIZE) != 0)
		++max_chunk;
	if ((ip->bi_flags&DSW_TREEMAP))
		nc_max = 1;
	else {
		mst_max = shd_max = 0;
		(void) nsc_maxfbas(MSTFD(ip), 0, &mst_max);
		(void) nsc_maxfbas(SHDFD(ip), 0, &shd_max);
		nc_max = (mst_max < shd_max) ? mst_max : shd_max;
		nc_max /= DSW_SIZE;
		ASSERT(nc_max > 0 && nc_max < 1000);
	}
#ifdef	DEBUG
	if (ii_maxchunks > 0)
		nc_max = ii_maxchunks;
#endif
	for (chunk_num = nc_got = 0; /* CSTYLED */; /* CSTYLED */) {
		if ((flag & CV_SHD2MST) && NSHADOWS(ip))
			nc_try = 1;
		else
			nc_try = (int)nc_max;
		chunk_num = II_NEXT_COPY_BIT(ip, chunk_num + nc_got,
		    max_chunk, nc_try, &nc_got);

		if (chunk_num >= max_chunk)	/* loop complete */
			break;
		if (ip->bi_flags & DSW_COPYINGX) {
			/* request to abort copy */
			_ii_unlock_chunks(ip, chunk_num, nc_got);
			rc = DSW_EABORTED;
			break;
		}

		sema_p(&_ii_concopy_sema);
		rc = _ii_copy_on_write(ip, (flag & CV_SHD2MST), chunk_num,
		    nc_got);
		sema_v(&_ii_concopy_sema);
		if (ip->bi_flags & DSW_TREEMAP)
			ii_tdelete(ip, chunk_num);
		_ii_unlock_chunks(ip, chunk_num, nc_got);
		if (!II_SUCCESS(rc)) {
			if (ca->wait)
				spcs_s_add(kstatus, rc);
			rc = DSW_EIO;
			break;
		}
		if (ip->bi_release ||
		    (++chunkcount % ip->bi_throttle_unit) == 0) {
			_ii_rlse_devs(ip, (ca->rtype&(~BMP)));
			rsrv = 0;
			delay(ip->bi_throttle_delay);
			ca->rtype = MSTR|SHDR|(ca->rtype&BMP);
			if ((rc = _ii_rsrv_devs(ip, (ca->rtype&(~BMP)),
			    II_INTERNAL)) != 0) {
				if (ca->wait)
					spcs_s_add(kstatus, rc);
				rc = DSW_EIO;
				break;
			}
			rsrv = 1;
			if (nc_max > 1) {
				/*
				 * maxfbas could have changed during the
				 * release/reserve, so recalculate the size
				 * of transfer we can do.
				 */
				(void) nsc_maxfbas(MSTFD(ip), 0, &mst_max);
				(void) nsc_maxfbas(SHDFD(ip), 0, &shd_max);
				nc_max = (mst_max < shd_max) ?
				    mst_max : shd_max;
				nc_max /= DSW_SIZE;
			}
		}
	}
skip:
	mutex_enter(&ip->bi_mutex);
	if (ip->bi_flags & DSW_COPYINGX)
		II_FLAG_CLR(DSW_COPYINGP|DSW_COPYINGX, ip);
	else
		II_FLAG_CLR(DSW_COPY_FLAGS, ip);

	if ((ip->bi_flags & DSW_TREEMAP) && (flag & CV_SHD2MST) &&
	    (ip->bi_flags & DSW_VOVERFLOW)) {
		int rs;
		bitmap_size = ip->bi_size / DSW_SIZE;
		if ((ip->bi_size % DSW_SIZE) != 0)
			++bitmap_size;
		bitmap_size += 7;
		bitmap_size /= 8;

		/* Count the number of copy bits set */
		rs = II_CNT_BITS(ip, ip->bi_copyfba, &copy_set, bitmap_size);
		if ((rs == 0) && (copy_set == 0)) {
			/*
			 * If we counted successfully and completed the copy
			 * see if any writes have forced the set into the
			 * overflow
			 */
			rs = II_CNT_BITS(ip, ip->bi_shdfba, &shadow_set,
			    bitmap_size);
			if ((rs == 0) && (shadow_set <
			    (nsc_size_t)ip->bi_shdchks)) {
				II_FLAG_CLR(DSW_VOVERFLOW, ip);
				--iigkstat.spilled_over.value.ul;
			}
		}
	}

	ca->rc = rc;
	cv_broadcast(&ip->bi_copydonecv);
	mutex_exit(&ip->bi_mutex);
	if (!ca->wait) {
		if (rsrv)
			_ii_rlse_devs(ip, ca->rtype);
		kmem_free(ca, sizeof (*ca));
	}

}

/*
 * _ii_copyvol()
 *	Copy a volume.
 *
 * Calling/Exit State:
 *	Returns 0 when the copy is complete or has been aborted,
 * 	otherwise error code.
 *
 * Description:
 *	According to the flag, copy the master to the shadow volume or the
 *	shadow to the master volume. Upon return wakeup all processes waiting
 *	for this copy. Uses a separate process (_ii_copyvolp) to allow the
 *	caller to be interrupted.
 */

static int
_ii_copyvol(_ii_info_t *ip, int flag, int rtype, spcs_s_info_t kstatus,
				int wait)
{
	struct copy_args *ca;
	int rc;

	/*
	 * start copy in separate process.
	 */

	ca = (struct copy_args *)kmem_alloc(sizeof (*ca), KM_SLEEP);
	ca->ip = ip;
	ca->flag = flag;
	ca->rtype = rtype;
	ca->kstatus = kstatus;
	ca->wait = wait;
	ca->rc = 0;

	if (rc = nsc_create_process((void (*)(void *))_ii_copyvolp,
	    (void *)ca, FALSE)) {
		mutex_enter(&ip->bi_mutex);
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		cmn_err(CE_NOTE, "!Can't create II copy process");
		kmem_free(ca, sizeof (*ca));
		return (rc);
	}
	mutex_enter(&ip->bi_mutex);
	if (wait == 0) {
		_ii_ioctl_done(ip);
		mutex_exit(&ip->bi_mutex);
		return (0);
	}
	while (ip->bi_flags & DSW_COPYINGP) {
		(void) cv_wait_sig(&ip->bi_copydonecv, &ip->bi_mutex);
	}
	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);
	rc = ca->rc;
	kmem_free(ca, sizeof (*ca));

	return (rc);
}

/*
 * _ii_stopcopy
 *	Stops any copy process on ip.
 *
 * Calling/Exit State:
 *	Returns 0 if the copy was stopped, otherwise error code.
 *
 * Description:
 *	Stop an in-progress copy by setting the DSW_COPYINGX flag, then
 *	wait for the copy to complete.
 */

static int
_ii_stopcopy(_ii_info_t *ip)
{
	mutex_enter(&ip->bi_mutex);
	DTRACE_PROBE1(_ii_stopcopy_flags,
	    uint_t, ip->bi_flags);

	while (ip->bi_flags & DSW_COPYINGP) {

		DTRACE_PROBE(_ii_stopcopy);

		II_FLAG_SET(DSW_COPYINGX, ip);

		if (cv_wait_sig(&ip->bi_copydonecv, &ip->bi_mutex) == 0) {
			/* Awoken by a signal */
			mutex_exit(&ip->bi_mutex);
			DTRACE_PROBE(_ii_stopcopy);
			return (EINTR);
		}
	}

	mutex_exit(&ip->bi_mutex);

	return (0);
}

/*
 * _ii_error
 *	Given the error type that occurred, and the current state of the
 *	shadowing, set the appropriate error condition(s).
 *
 */

void
_ii_error(_ii_info_t *ip, int error_type)
{
	int copy_flags;
	int golden;
	int flags;
	int recursive_call = (error_type & DSW_OVERFLOW) != 0;
	int offline_bits = DSW_OFFLINE;
	_ii_info_t *xip;
	int rc;

	error_type &= ~DSW_OVERFLOW;

	mutex_enter(&ip->bi_mutex);
	flags = (ip->bi_flags) & offline_bits;
	if ((flags ^ error_type) == 0) {
		/* nothing new offline */
		mutex_exit(&ip->bi_mutex);
		return;
	}

	if (error_type == DSW_BMPOFFLINE &&
	    (ip->bi_flags & DSW_BMPOFFLINE) == 0) {
		/* first, let nskerd know */
		rc = _ii_report_bmp(ip);
		if (rc) {
			if (ii_debug > 0) {
				cmn_err(CE_WARN, "!Unable to mark bitmap bad in"
				    " config DB; rc = %d", rc);
			}
			ip->bi_flags |= DSW_CFGOFFLINE;
		}
	}

	flags = ip->bi_flags;
	golden = ((flags & DSW_GOLDEN) == DSW_GOLDEN);
	copy_flags = flags & DSW_COPYING;

	switch (error_type) {

	case DSW_BMPOFFLINE:
		/* prevent further use of bitmap */
		flags |= DSW_BMPOFFLINE;
		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!ii: Bitmap offline");

		switch (copy_flags) {

		case DSW_COPYINGM:
			/* Bitmap offline, copying master to shadow */
			flags |= DSW_SHDOFFLINE;
			if (ii_debug > 0)
				cmn_err(CE_NOTE, "!ii: Implied shadow offline");
			break;

		case DSW_COPYINGS:
			/* Bitmap offline, copying shadow to master */
			if (golden) {
				/* Shadow is still usable */
				if (ii_debug > 0)
					cmn_err(CE_NOTE,
					    "!ii: Implied master offline");
				flags |= DSW_MSTOFFLINE;
			} else {
				/*
				 * Snapshot restore from shadow to master
				 * is a dumb thing to do anyway. Lose both.
				 */
				flags |= DSW_SHDOFFLINE | DSW_MSTOFFLINE;
				if (ii_debug > 0)
					cmn_err(CE_NOTE,
					    "ii: Implied master and "
					    "shadow offline");
			}
			break;

		case 0:
			/* Bitmap offline, no copying in progress */
			if (!golden) {
				if (ii_debug > 0)
					cmn_err(CE_NOTE,
					    "!ii: Implied shadow offline");
				flags |= DSW_SHDOFFLINE;
			}
			break;
		}
		break;

	case DSW_OVROFFLINE:
		flags |= DSW_OVROFFLINE;
		ASSERT(ip->bi_overflow);
		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!ii: Overflow offline");
		/* FALLTHRU */
	case DSW_SHDOFFLINE:
		flags |= DSW_SHDOFFLINE;
		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!ii: Shadow offline");

		if (copy_flags == DSW_COPYINGS) {
			/* Shadow offline, copying shadow to master */
			if (ii_debug > 0)
				cmn_err(CE_NOTE, "!ii: Implied master offline");
			flags |= DSW_MSTOFFLINE;
		}
		break;

	case DSW_MSTOFFLINE:
		flags |= DSW_MSTOFFLINE;
		if (ii_debug > 0)
			cmn_err(CE_NOTE, "!ii: Master offline");

		switch (copy_flags) {

		case DSW_COPYINGM:
			/* Master offline, copying master to shadow */
			flags |= DSW_SHDOFFLINE;
			if (ii_debug > 0)
				cmn_err(CE_NOTE, "!ii: Implied shadow offline");
			break;

		case DSW_COPYINGS:
			/* Master offline, copying shadow to master */
			if (!golden) {
				flags |= DSW_SHDOFFLINE;
				if (ii_debug > 0)
					cmn_err(CE_NOTE,
					    "!ii: Implied shadow offline");
			}
			break;

		case 0:
			/* Master offline, no copying in progress */
			if (!golden) {
				flags |= DSW_SHDOFFLINE;
				if (ii_debug > 0)
					cmn_err(CE_NOTE,
					    "!ii: Implied shadow offline");
			}
			break;
		}
		break;

	default:
		break;
	}

	II_FLAG_SET(flags, ip);
	mutex_exit(&ip->bi_mutex);

	if (!recursive_call &&
	    NSHADOWS(ip) && (flags&DSW_MSTOFFLINE) == DSW_MSTOFFLINE) {
		/* take master offline for all other sibling shadows */
		for (xip = ip->bi_head; xip; xip = xip->bi_sibling) {
			if (xip == ip)
				continue;
			if (_ii_rsrv_devs(xip, BMP, II_INTERNAL) != 0)
				continue;
					/* overload DSW_OVERFLOW */
			_ii_error(xip, DSW_MSTOFFLINE|DSW_OVERFLOW);
			_ii_rlse_devs(xip, BMP);
		}
	}

}


/*
 * _ii_lock_chunk
 *	Locks access to the specified chunk
 *
 */

static void
_ii_lock_chunk(_ii_info_t *ip, chunkid_t chunk)
{
	if (chunk == II_NULLCHUNK) {

		DTRACE_PROBE(_ii_lock_chunk_type);

		rw_enter(&ip->bi_busyrw, RW_WRITER);

	} else {

		DTRACE_PROBE(_ii_lock_chunk_type);

		if (ip->bi_busy == NULL) {
			DTRACE_PROBE(_ii_lock_chunk_end);
			return;
		}

		rw_enter(&ip->bi_busyrw, RW_READER);
		mutex_enter(&ip->bi_mutex);
		while (DSW_BIT_ISSET(ip->bi_busy[chunk / DSW_BITS],
		    chunk % DSW_BITS))
			cv_wait(&ip->bi_busycv, &ip->bi_mutex);
		DSW_BIT_SET(ip->bi_busy[chunk / DSW_BITS], chunk % DSW_BITS);
		mutex_exit(&ip->bi_mutex);
	}

}


/*
 * _ii_trylock_chunk
 *	Tries to lock access to the specified chunk
 * Returns non-zero on success.
 *
 */

static int
_ii_trylock_chunk(_ii_info_t *ip, chunkid_t chunk)
{
	int rc;

	ASSERT(chunk != II_NULLCHUNK);
	if (rw_tryenter(&ip->bi_busyrw, RW_READER) == 0) {
		DTRACE_PROBE(_ii_trylock_chunk);
		return (0);
	}

	if (ip->bi_busy == NULL) {
		DTRACE_PROBE(_ii_trylock_chunk_end);
		return (0);
	}

	mutex_enter(&ip->bi_mutex);
	if (DSW_BIT_ISSET(ip->bi_busy[chunk / DSW_BITS], chunk % DSW_BITS)) {
		rw_exit(&ip->bi_busyrw);	/* RW_READER */
		rc = 0;
	} else {
		DSW_BIT_SET(ip->bi_busy[chunk / DSW_BITS], chunk % DSW_BITS);
		rc = 1;
	}
	mutex_exit(&ip->bi_mutex);

	return (rc);
}

/*
 * _ii_unlock_chunks
 *	Unlocks access to the specified chunks
 *
 */

static void
_ii_unlock_chunks(_ii_info_t *ip, chunkid_t  chunk, int n)
{
	if (chunk == II_NULLCHUNK) {

		DTRACE_PROBE(_ii_unlock_chunks);

		rw_exit(&ip->bi_busyrw);	/* RW_WRITER */

	} else {

		if (ip->bi_busy == NULL) {
			DTRACE_PROBE(_ii_unlock_chunks_end);
			return;
		}
		mutex_enter(&ip->bi_mutex);

		DTRACE_PROBE(_ii_unlock_chunks);

		for (; n-- > 0; chunk++) {
			ASSERT(DSW_BIT_ISSET(ip->bi_busy[chunk / DSW_BITS],
			    chunk % DSW_BITS));
			DSW_BIT_CLR(ip->bi_busy[chunk / DSW_BITS],
			    chunk % DSW_BITS);
			rw_exit(&ip->bi_busyrw);	/* RW_READER */
		}
		cv_broadcast(&ip->bi_busycv);
		mutex_exit(&ip->bi_mutex);

	}
}

/*
 * Copyout the bit map.
 */
static int
_ii_ab_co_bmp(_ii_info_t *ip, nsc_off_t bm_offset, unsigned char *user_bm,
    int user_bm_size)
{
	nsc_off_t	last_fba;
	nsc_buf_t *tmp;
	nsc_vec_t *nsc_vecp;
	nsc_off_t	fba_pos;
	int	buf_fba_len;
	int	buf_byte_len;
	size_t	co_len;
	int	rc;

	DTRACE_PROBE2(_ii_ab_co_bmp_start, nsc_off_t, bm_offset,
	    nsc_size_t, user_bm_size);

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	/* First calculate the size of the shadow and copy bitmaps */
	co_len = DSW_BM_FBA_LEN(ip->bi_size);
	ASSERT((ip->bi_copyfba - ip->bi_shdfba) == co_len);

	/* Are we in the ranges of the various bitmaps/indexes? */
	if (bm_offset < ip->bi_shdfba)
		return (EIO);
	else if (bm_offset < (last_fba = ip->bi_shdfba + co_len))
		/*EMPTY*/;
	else if (bm_offset < (last_fba = ip->bi_copyfba + co_len))
		/*EMPTY*/;
	else if ((ip->bi_flags & DSW_TREEMAP) &&
	    (bm_offset < (last_fba = last_fba + (co_len * 32))))
		/*EMPTY*/;
	else return (EIO);

	/* Are we within the size of the segment being copied? */
	if (FBA_LEN(user_bm_size) > last_fba - bm_offset)
		return (EIO);

	for (fba_pos = bm_offset; fba_pos < last_fba && user_bm_size > 0;
	    fba_pos += DSW_CBLK_FBA) {
		tmp = NULL;
		buf_fba_len = fba_pos + DSW_CBLK_FBA < last_fba ?
		    DSW_CBLK_FBA : last_fba - fba_pos;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba_pos, buf_fba_len,
		    NSC_RDBUF, &tmp);
		II_READ_END(ip, bitmap, rc, buf_fba_len);
		if (!II_SUCCESS(rc)) {
			if (tmp)
				(void) nsc_free_buf(tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			return (EIO);
		}

		/* copyout each nsc_vec's worth of data */
		buf_byte_len = FBA_SIZE(buf_fba_len);
		for (nsc_vecp = tmp->sb_vec;
		    buf_byte_len > 0 && user_bm_size > 0;
		    nsc_vecp++) {
			co_len = (user_bm_size > nsc_vecp->sv_len) ?
			    nsc_vecp->sv_len : user_bm_size;
			if (copyout(nsc_vecp->sv_addr, user_bm, co_len)) {
				(void) nsc_free_buf(tmp);
				return (EFAULT);
			}
			user_bm += co_len;
			user_bm_size -= co_len;
			buf_byte_len -= co_len;
		}


		(void) nsc_free_buf(tmp);
	}

	return (0);
}

/*
 * Copyin a bit map and or with differences bitmap.
 */
static int
_ii_ab_ci_bmp(_ii_info_t *ip, nsc_off_t bm_offset, unsigned char *user_bm,
int user_bm_size)
{
	nsc_off_t	last_fba;
	nsc_buf_t *tmp;
	nsc_vec_t *nsc_vecp;
	nsc_off_t	fba_pos;
	int	buf_fba_len;
	int	buf_byte_len;
	size_t	ci_len;
	int	rc;
	int	n;
	unsigned char *tmp_buf, *tmpp, *tmpq;

	DTRACE_PROBE2(_ii_ab_ci_bmp_start, nsc_off_t, bm_offset,
	    nsc_size_t, user_bm_size);

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	tmp_buf = NULL;
	last_fba = bm_offset + DSW_BM_FBA_LEN(ip->bi_size);

	for (fba_pos = bm_offset; fba_pos < last_fba && user_bm_size > 0;
	    fba_pos += DSW_CBLK_FBA) {
		tmp = NULL;
		buf_fba_len = fba_pos + DSW_CBLK_FBA < last_fba ?
		    DSW_CBLK_FBA : last_fba - fba_pos;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba_pos, buf_fba_len,
		    NSC_RDWRBUF, &tmp);
		II_READ_END(ip, bitmap, rc, buf_fba_len);
		if (!II_SUCCESS(rc)) {
			if (tmp)
				(void) nsc_free_buf(tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			return (EIO);
		}

		/* copyin each nsc_vec's worth of data */
		buf_byte_len = FBA_SIZE(buf_fba_len);
		for (nsc_vecp = tmp->sb_vec;
		    buf_byte_len > 0 && user_bm_size > 0;
		    nsc_vecp++) {
			ci_len = (user_bm_size > nsc_vecp->sv_len) ?
			    nsc_vecp->sv_len : user_bm_size;
			tmpp = tmp_buf = kmem_alloc(ci_len, KM_SLEEP);
			tmpq = nsc_vecp->sv_addr;
			if (copyin(user_bm, tmpp, ci_len)) {
				(void) nsc_free_buf(tmp);
				kmem_free(tmp_buf, ci_len);
				return (EFAULT);
			}
			for (n = ci_len; n-- > 0; /* CSTYLED */)
				*tmpq++ |= *tmpp++;
			user_bm += ci_len;
			user_bm_size -= ci_len;
			buf_byte_len -= ci_len;
			kmem_free(tmp_buf, ci_len);
		}

		II_NSC_WRITE(ip, bitmap, rc, tmp, fba_pos, buf_fba_len, 0);
		if (!II_SUCCESS(rc)) {
			(void) nsc_free_buf(tmp);
			_ii_error(ip, DSW_BMPOFFLINE);
			return (EIO);
		}

		(void) nsc_free_buf(tmp);
	}

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}

/*
 * Completely zero the bit map.
 *
 *	Returns 0 if no error
 *	Returns non-zero if there was an error
 */
static int
_ii_ab_zerobm(_ii_info_t *ip)
{
	nsc_off_t fba_pos;
	int rc;
	nsc_size_t len;
	nsc_size_t size;
	nsc_buf_t *tmp;

	size = DSW_BM_FBA_LEN(ip->bi_size) + ip->bi_shdfba;
	for (fba_pos = ip->bi_shdfba; fba_pos < size; fba_pos += DSW_CBLK_FBA) {
		tmp = NULL;
		len = fba_pos + DSW_CBLK_FBA < size ?
		    DSW_CBLK_FBA : size - fba_pos;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba_pos, len, NSC_RDWRBUF,
		    &tmp);
		II_READ_END(ip, bitmap, rc, len);
		if (!II_SUCCESS(rc)) {
			if (tmp)
				(void) nsc_free_buf(tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}

		rc = nsc_zero(tmp, fba_pos, len, 0);
		if (II_SUCCESS(rc)) {
			II_NSC_WRITE(ip, bitmap, rc, tmp, fba_pos, len, 0);
		}

		(void) nsc_free_buf(tmp);
		if (!II_SUCCESS(rc)) {
			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}
	}

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}


/*
 * Copy shadow bitmap to copy bitmap
 */
static int
_ii_ab_copybm(_ii_info_t *ip)
{
	nsc_off_t copy_fba_pos, shd_fba_pos;
	int rc;
	nsc_size_t len;
	nsc_off_t size;
	nsc_buf_t *copy_tmp, *shd_tmp;

	size = DSW_BM_FBA_LEN(ip->bi_size) + ip->bi_shdfba;
	copy_fba_pos = ip->bi_copyfba;
	for (shd_fba_pos = ip->bi_shdfba; shd_fba_pos < size;
	    copy_fba_pos += DSW_CBLK_FBA, shd_fba_pos += DSW_CBLK_FBA) {
		shd_tmp = NULL;
		len = shd_fba_pos + DSW_CBLK_FBA < size ?
		    DSW_CBLK_FBA : size - shd_fba_pos;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, shd_fba_pos, len, NSC_RDBUF,
		    &shd_tmp);
		II_READ_END(ip, bitmap, rc, len);
		if (!II_SUCCESS(rc)) {
			if (shd_tmp)
				(void) nsc_free_buf(shd_tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			if (ii_debug > 1)
				cmn_err(CE_NOTE, "!ii: copybm failed 1 rc %d",
				    rc);

			return (rc);
		}

		copy_tmp = NULL;
		rc = nsc_alloc_buf(ip->bi_bmpfd, copy_fba_pos, len, NSC_WRBUF,
		    &copy_tmp);
		if (!II_SUCCESS(rc)) {
			(void) nsc_free_buf(shd_tmp);
			if (copy_tmp)
				(void) nsc_free_buf(copy_tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			if (ii_debug > 1)
				cmn_err(CE_NOTE, "!ii: copybm failed 2 rc %d",
				    rc);

			return (rc);
		}
		rc = nsc_copy(shd_tmp, copy_tmp, shd_fba_pos, copy_fba_pos,
		    len);
		if (II_SUCCESS(rc)) {
			II_NSC_WRITE(ip, bitmap, rc, copy_tmp, copy_fba_pos,
			    len, 0);
		}

		(void) nsc_free_buf(shd_tmp);
		(void) nsc_free_buf(copy_tmp);
		if (!II_SUCCESS(rc)) {
			if (ii_debug > 1)
				cmn_err(CE_NOTE, "!ii: copybm failed 4 rc %d",
				    rc);
			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}
	}

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}


/*
 * stolen from nsc_copy_h()
 */

static int
_ii_nsc_or(nsc_buf_t *h1, nsc_buf_t *h2, nsc_off_t pos1, nsc_off_t pos2,
	nsc_size_t len)
{
	unsigned char *a1, *a2;
	unsigned char *b1, *b2;
	nsc_vec_t *v1, *v2;
	int i, sz, l1, l2;

	if (pos1 < h1->sb_pos || pos1 + len > h1->sb_pos + h1->sb_len ||
	    pos2 < h2->sb_pos || pos2 + len > h2->sb_pos + h2->sb_len)
		return (EINVAL);

	if (!len)
		return (0);

	/* find starting point in "from" vector */

	v1 = h1->sb_vec;
	pos1 -= h1->sb_pos;

	for (; pos1 >= FBA_NUM(v1->sv_len); v1++)
		pos1 -= FBA_NUM(v1->sv_len);

	a1 = v1->sv_addr + FBA_SIZE(pos1);
	l1 = v1->sv_len - FBA_SIZE(pos1);

	/* find starting point in "to" vector */

	v2 = h2->sb_vec;
	pos2 -= h2->sb_pos;

	for (; pos2 >= FBA_NUM(v2->sv_len); v2++)
		pos2 -= FBA_NUM(v2->sv_len);

	a2 = v2->sv_addr + FBA_SIZE(pos2);
	l2 = v2->sv_len - FBA_SIZE(pos2);

	/* copy required data */

	len = FBA_SIZE(len);

	while (len) {
		sz = min(l1, l2);
		sz = (int)min((nsc_size_t)sz, len);

		b1 = a1;
		b2 = a2;
		for (i = sz; i-- > 0; /* CSTYLED */)
			*b2++ |= *b1++;

		l1 -= sz;
		l2 -= sz;
		a1 += sz;
		a2 += sz;
		len -= sz;

		if (!l1) {
			a1 = (++v1)->sv_addr;
			l1 = v1->sv_len;
		}
		if (!l2) {
			a2 = (++v2)->sv_addr;
			l2 = v2->sv_len;
		}
	}

	return (0);
}


/*
 * Or the shadow bitmap in to the copy bitmap, clear the
 * shadow bitmap.
 */
static int
_ii_ab_orbm(_ii_info_t *ip)
{
	nsc_off_t copy_fba_pos, shd_fba_pos;
	int rc;
	nsc_size_t len;
	size_t size;
	nsc_buf_t *copy_tmp, *shd_tmp;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	size = DSW_BM_FBA_LEN(ip->bi_size) + ip->bi_shdfba;
	copy_fba_pos = ip->bi_copyfba;
	for (shd_fba_pos = ip->bi_shdfba; shd_fba_pos < size;
	    copy_fba_pos += DSW_CBLK_FBA, shd_fba_pos += DSW_CBLK_FBA) {
		shd_tmp = NULL;
		len = shd_fba_pos + DSW_CBLK_FBA < size ?
		    DSW_CBLK_FBA : size - shd_fba_pos;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, shd_fba_pos, len,
		    NSC_RDBUF|NSC_WRBUF, &shd_tmp);
		II_READ_END(ip, bitmap, rc, len);
		if (!II_SUCCESS(rc)) {
			if (shd_tmp)
				(void) nsc_free_buf(shd_tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}

		copy_tmp = NULL;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, copy_fba_pos, len,
		    NSC_RDBUF|NSC_WRBUF, &copy_tmp);
		II_READ_END(ip, bitmap, rc, len);
		if (!II_SUCCESS(rc)) {
			(void) nsc_free_buf(shd_tmp);
			if (copy_tmp)
				(void) nsc_free_buf(copy_tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}
		rc = _ii_nsc_or(shd_tmp, copy_tmp, shd_fba_pos, copy_fba_pos,
		    len);
		if (II_SUCCESS(rc)) {
			II_NSC_WRITE(ip, bitmap, rc, copy_tmp, copy_fba_pos,
			    len, 0);
		}
		if (II_SUCCESS(rc))
			rc = nsc_zero(shd_tmp, shd_fba_pos, len, 0);
		if (II_SUCCESS(rc)) {
			II_NSC_WRITE(ip, bitmap, rc, shd_tmp, shd_fba_pos, len,
			    0);
		}

		(void) nsc_free_buf(shd_tmp);
		(void) nsc_free_buf(copy_tmp);
		if (!II_SUCCESS(rc)) {
			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}
	}

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}

/*
 * _ii_ab_tst_shd_bit
 *	Determine if a chunk has been copied to the shadow device
 *	Relies on the alloc_buf/free_buf semantics for locking.
 *
 * Calling/Exit State:
 *	Returns 1 if the modified bit has been set for the shadow device,
 *	Returns 0 if the modified bit has not been set for the shadow device,
 *	Returns -1 if there was an error
 */

static int
_ii_ab_tst_shd_bit(_ii_info_t *ip, chunkid_t chunk)
{
	int rc;
	nsc_off_t fba;
	nsc_buf_t *tmp = NULL;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	fba = ip->bi_shdfba + chunk / (FBA_SIZE(1) * DSW_BITS);
	chunk %= FBA_SIZE(1) * DSW_BITS;
	II_READ_START(ip, bitmap);
	rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_RDBUF, &tmp);
	II_READ_END(ip, bitmap, rc, 1);
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_BMPOFFLINE);
		if (tmp)
			(void) nsc_free_buf(tmp);
		return (-1);
	}
	rc = DSW_BIT_ISSET(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
	    chunk%DSW_BITS);
	(void) nsc_free_buf(tmp);

	return (rc);
}


/*
 * _ii_ab_set_shd_bit
 *	Records that a chunk has been copied to the shadow device
 *
 *	Returns non-zero if an error is encountered
 *	Returns 0 if no error
 */

static int
_ii_ab_set_shd_bit(_ii_info_t *ip, chunkid_t chunk)
{
	int rc;
	nsc_off_t fba;
	nsc_buf_t *tmp = NULL;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	fba = ip->bi_shdfba + chunk / (FBA_SIZE(1) * DSW_BITS);
	chunk %= FBA_SIZE(1) * DSW_BITS;
	II_READ_START(ip, bitmap);
	rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_RDBUF|NSC_WRBUF, &tmp);
	II_READ_END(ip, bitmap, rc, 1);
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_BMPOFFLINE);
		if (tmp)
			(void) nsc_free_buf(tmp);
		return (rc);
	}
	if (DSW_BIT_ISSET(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
	    chunk%DSW_BITS) == 0) {
		DSW_BIT_SET(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
		    chunk%DSW_BITS);
		II_NSC_WRITE(ip, bitmap, rc, tmp, fba, 1, 0);
		if ((ip->bi_state & DSW_CNTSHDBITS) == 0)
			ip->bi_shdbits++;
	}
	(void) nsc_free_buf(tmp);
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_BMPOFFLINE);
		return (rc);
	}

	return (0);
}


/*
 * _ii_ab_tst_copy_bit
 *	Determine if a chunk needs to be copied during updates.
 *
 * Calling/Exit State:
 *	Returns 1 if the copy bit for the chunk is set
 *	Returns 0 if the copy bit for the chunk is not set
 *	Returns -1 if an error is encountered
 */

static int
_ii_ab_tst_copy_bit(_ii_info_t *ip, chunkid_t chunk)
{
	int rc;
	nsc_off_t fba;
	nsc_buf_t *tmp = NULL;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (-1);

	fba = ip->bi_copyfba + chunk / (FBA_SIZE(1) * DSW_BITS);
	chunk %= FBA_SIZE(1) * DSW_BITS;
	II_READ_START(ip, bitmap);
	rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_RDBUF, &tmp);
	II_READ_END(ip, bitmap, rc, 1);
	if (!II_SUCCESS(rc)) {
		if (tmp)
			(void) nsc_free_buf(tmp);
		_ii_error(ip, DSW_BMPOFFLINE);
		return (-1);
	}
	rc = DSW_BIT_ISSET(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
	    chunk%DSW_BITS);
	(void) nsc_free_buf(tmp);

	return (rc);
}


/*
 * _ii_ab_set_copy_bit
 *	Records that a chunk has been copied to the shadow device
 *
 *	Returns non-zero if an error is encountered
 *	Returns 0 if no error
 */

static int
_ii_ab_set_copy_bit(_ii_info_t *ip, chunkid_t chunk)
{
	int rc;
	nsc_off_t fba;
	nsc_buf_t *tmp = NULL;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	fba = ip->bi_copyfba + chunk / (FBA_SIZE(1) * DSW_BITS);
	chunk %= FBA_SIZE(1) * DSW_BITS;
	II_READ_START(ip, bitmap);
	rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_RDBUF|NSC_WRBUF, &tmp);
	II_READ_END(ip, bitmap, rc, 1);
	if (!II_SUCCESS(rc)) {
		if (tmp)
			(void) nsc_free_buf(tmp);
		_ii_error(ip, DSW_BMPOFFLINE);
		return (rc);
	}
	if (DSW_BIT_ISSET(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
	    chunk%DSW_BITS) == 0) {
		DSW_BIT_SET(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
		    chunk%DSW_BITS);
		if ((ip->bi_state & DSW_CNTCPYBITS) == 0)
			ip->bi_copybits++;

		II_NSC_WRITE(ip, bitmap, rc, tmp, fba, 1, 0);
	}
	(void) nsc_free_buf(tmp);
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_BMPOFFLINE);
		return (rc);
	}

	return (0);
}


/*
 * _ii_ab_clr_copy_bits
 *	Records that a chunk has been cleared on the shadow device, this
 *	function assumes that the bits to clear are all in the same fba,
 *	as is the case when they were generated by _ii_ab_next_copy_bit().
 *
 *	Returns non-zero if an error is encountered
 *	Returns 0 if no error
 */

static int
_ii_ab_clr_copy_bits(_ii_info_t *ip, chunkid_t chunk, int nchunks)
{
	int rc;
	nsc_off_t fba;
	nsc_buf_t *tmp = NULL;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	fba = ip->bi_copyfba + chunk / (FBA_SIZE(1) * DSW_BITS);
	chunk %= FBA_SIZE(1) * DSW_BITS;
	II_READ_START(ip, bitmap);
	rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_RDBUF|NSC_WRBUF, &tmp);
	II_READ_END(ip, bitmap, rc, 1);
	if (!II_SUCCESS(rc)) {
		if (tmp)
			(void) nsc_free_buf(tmp);
		_ii_error(ip, DSW_BMPOFFLINE);
		return (rc);
	}
	for (; nchunks-- > 0; chunk++) {
		DSW_BIT_CLR(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
		    chunk%DSW_BITS);
		if (ip->bi_copybits > 0)
			ip->bi_copybits--;
	}

	II_NSC_WRITE(ip, bitmap, rc, tmp, fba, 1, 0);
	(void) nsc_free_buf(tmp);
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_BMPOFFLINE);
		return (rc);
	}

	return (0);
}

/*
 * _ii_ab_fill_copy_bmp
 *	Fills the copy bitmap with 1's.
 *
 *	Returns non-zero if an error is encountered
 *	Returns 0 if no error
 */

static int
_ii_ab_fill_copy_bmp(_ii_info_t *ip)
{
	int rc;
	nsc_off_t fba;
	nsc_buf_t *tmp;
	unsigned char *p;
	int i, j;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	fba = ip->bi_copyfba;
	for (i = DSW_BM_FBA_LEN(ip->bi_size); i-- > 0; fba++) {
		tmp = NULL;
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_WRBUF, &tmp);
		if (!II_SUCCESS(rc)) {
			if (tmp)
				(void) nsc_free_buf(tmp);
			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}
		p = (unsigned char *)tmp->sb_vec->sv_addr;
		for (j = FBA_SIZE(1); j-- > 0; p++)
			*p = (unsigned char)0xff;
		II_NSC_WRITE(ip, bitmap, rc, tmp, fba, 1, 0);
		if (!II_SUCCESS(rc)) {
			_ii_error(ip, DSW_BMPOFFLINE);
			(void) nsc_free_buf(tmp);
			return (rc);
		}
		(void) nsc_free_buf(tmp);
	}

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}

/*
 * _ii_ab_load_bmp
 *	Load bitmap from persistent storage.
 */

static int
_ii_ab_load_bmp(_ii_info_t *ip, int flag)
/* ARGSUSED */
{
	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}

/*
 * _ii_ab_next_copy_bit
 *	Find next set copy bit.
 *
 * Returns the next bits set in the copy bitmap, with the corresponding chunks
 * locked. Used to avoid having to reread the same bit map block as each bit
 * is tested.
 */

static chunkid_t
_ii_ab_next_copy_bit(_ii_info_t *ip, chunkid_t startchunk, chunkid_t maxchunk,
	int wanted, int *got)
{
	chunkid_t rc;
	nsc_off_t fba;
	chunkid_t chunk;
	int bits_per_fba = FBA_SIZE(1) * DSW_BITS;
	int high;
	chunkid_t nextchunk;
	nsc_buf_t *tmp = NULL;

	*got = 0;
again:
	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (maxchunk + 1);

	while (startchunk < maxchunk) {
		tmp = NULL;
		fba = ip->bi_copyfba + startchunk / bits_per_fba;
		chunk = startchunk % bits_per_fba;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_RDBUF, &tmp);
		II_READ_END(ip, bitmap, rc, 1);
		if (!II_SUCCESS(rc)) {
			if (tmp)
				(void) nsc_free_buf(tmp);
			_ii_error(ip, DSW_BMPOFFLINE);
			return (maxchunk + 1);
		}
		high = startchunk + bits_per_fba - startchunk%bits_per_fba;
		if (high > maxchunk)
			high = maxchunk;
		for (; startchunk < high; chunk++, startchunk++) {
			if (DSW_BIT_ISSET(tmp->sb_vec->sv_addr[chunk/DSW_BITS],
			    chunk%DSW_BITS)) {
				/*
				 * trylock won't sleep so can use while
				 * holding the buf.
				 */
				if (!_ii_trylock_chunk(ip, startchunk)) {
					(void) nsc_free_buf(tmp);
					_ii_lock_chunk(ip, startchunk);
					if (_ii_ab_tst_copy_bit(ip, startchunk)
					    != 1) {
						/*
						 * another process copied this
						 * chunk while we were acquiring
						 * the chunk lock.
						 */
						_ii_unlock_chunk(ip,
						    startchunk);
						DTRACE_PROBE(
						    _ii_ab_next_copy_bit_again);
						goto again;
					}
					*got = 1;
					DTRACE_PROBE(_ii_ab_next_copy_bit_end);
					return (startchunk);
				}
				*got = 1;
				nextchunk = startchunk + 1;
				chunk++;
				for (; --wanted > 0 && nextchunk < high;
				    nextchunk++, chunk++) {
					if (!DSW_BIT_ISSET(tmp->sb_vec->sv_addr
					    [chunk/DSW_BITS], chunk%DSW_BITS)) {
						break;	/* end of bit run */
					}
					if (_ii_trylock_chunk(ip, nextchunk))
						(*got)++;
					else
						break;
				}
				(void) nsc_free_buf(tmp);
				DTRACE_PROBE(_ii_ab_next_copy_bit);
				return (startchunk);
			}
		}
		(void) nsc_free_buf(tmp);
	}

	return (maxchunk + 1);
}

/*
 * _ii_ab_save_bmp
 *	Save bitmap to persistent storage.
 */

static int
_ii_ab_save_bmp(_ii_info_t *ip, int flag)
/* ARGSUSED */
{
	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	return (0);
}

/*
 * _ii_ab_change_bmp
 *	copy change bitmap to memory
 */

static int
_ii_ab_change_bmp(_ii_info_t *ip, unsigned char *ptr)
/* ARGSUSED */
{
	int	bm_size;
	int	i, j, fba;
	int	rc;
	unsigned char *p;
	nsc_buf_t *tmp = NULL;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);
	bm_size = FBA_SIZE(DSW_BM_FBA_LEN(ip->bi_size));

	rc = _ii_nsc_io(ip, KS_BMP, ip->bi_bmpfd, NSC_RDBUF, ip->bi_shdfba,
	    ptr, bm_size);
	if (!II_SUCCESS(rc)) {
		_ii_error(ip, DSW_BMPOFFLINE);
		return (rc);
	}

	fba = ip->bi_copyfba;
	for (i = DSW_BM_FBA_LEN(ip->bi_size); i-- > 0; fba++) {
		tmp = NULL;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba, 1, NSC_RDBUF, &tmp);
		II_READ_END(ip, bitmap, rc, 1);
		if (!II_SUCCESS(rc)) {
			if (tmp)
				(void) nsc_free_buf(tmp);
			_ii_error(ip, DSW_BMPOFFLINE);
			return (rc);
		}
		p = (unsigned char *)tmp->sb_vec->sv_addr;
		for (j = FBA_SIZE(1); j-- > 0; p++)
			*ptr |= *p;
		(void) nsc_free_buf(tmp);
	}

	return (0);
}

/*
 * Count bits set in the bit map.
 */
static int
_ii_ab_cnt_bits(_ii_info_t *ip, nsc_off_t bm_offset, nsc_size_t *counter,
int bm_size)
{
	nsc_size_t	last_fba;
	nsc_buf_t *tmp;
	nsc_vec_t *sd_vecp;
	nsc_off_t	fba_pos;
	int	buf_fba_len;
	int	buf_byte_len;
	int	co_len;
	int	i;
	unsigned int j, k;
	unsigned char *cp;
	int	rc;

	*counter = 0;
	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	last_fba = bm_offset + DSW_BM_FBA_LEN(ip->bi_size);

	for (fba_pos = bm_offset; fba_pos < last_fba && bm_size > 0;
	    fba_pos += DSW_CBLK_FBA) {
		tmp = NULL;
		buf_fba_len = fba_pos + DSW_CBLK_FBA < last_fba ?
		    DSW_CBLK_FBA : last_fba - fba_pos;
		II_READ_START(ip, bitmap);
		rc = nsc_alloc_buf(ip->bi_bmpfd, fba_pos, buf_fba_len,
		    NSC_RDBUF, &tmp);
		II_READ_END(ip, bitmap, rc, 1);
		if (!II_SUCCESS(rc)) {
			if (tmp)
				(void) nsc_free_buf(tmp);

			_ii_error(ip, DSW_BMPOFFLINE);
			return (EIO);
		}

		/* count each sd_vec's worth of data */
		buf_byte_len = FBA_SIZE(buf_fba_len);
		for (sd_vecp = tmp->sb_vec;
		    buf_byte_len > 0 && bm_size > 0;
		    sd_vecp++) {
			co_len = (bm_size > sd_vecp->sv_len) ?
			    sd_vecp->sv_len : bm_size;
			cp = sd_vecp->sv_addr;
			for (i = k = 0; i < co_len; i++)
				for (j = (unsigned)*cp++; j; j &= j - 1)
					k++;
			*counter += k;
			bm_size -= co_len;
			buf_byte_len -= co_len;
		}


		(void) nsc_free_buf(tmp);
	}

	return (0);
}

/*
 * OR the bitmaps as part of a join operation
 */
static int
_ii_ab_join_bmp(_ii_info_t *dest_ip, _ii_info_t *src_ip)
{
	int rc;
	nsc_size_t len;
	nsc_size_t size;
	nsc_buf_t *dest_tmp, *src_tmp;
	nsc_off_t src_fba_pos;

	if ((src_ip->bi_flags & DSW_BMPOFFLINE) ||
	    (dest_ip->bi_flags & DSW_BMPOFFLINE))
		return (EIO);

	size = DSW_BM_FBA_LEN(src_ip->bi_size) + src_ip->bi_shdfba;
	for (src_fba_pos = src_ip->bi_shdfba; src_fba_pos < size;
	    src_fba_pos += DSW_CBLK_FBA) {
		src_tmp = NULL;
		len = src_fba_pos + DSW_CBLK_FBA < size ?
		    DSW_CBLK_FBA : size - src_fba_pos;
		II_READ_START(src_ip, bitmap);
		rc = nsc_alloc_buf(src_ip->bi_bmpfd, src_fba_pos, len,
		    NSC_RDWRBUF, &src_tmp);
		II_READ_END(src_ip, bitmap, rc, len);
		if (!II_SUCCESS(rc)) {
			if (src_tmp)
				(void) nsc_free_buf(src_tmp);

			_ii_error(src_ip, DSW_BMPOFFLINE);
			return (rc);
		}

		dest_tmp = NULL;
		II_READ_START(dest_ip, bitmap);
		rc = nsc_alloc_buf(dest_ip->bi_bmpfd, src_fba_pos, len,
		    NSC_RDWRBUF, &dest_tmp);
		II_READ_END(dest_ip, bitmap, rc, len);
		if (!II_SUCCESS(rc)) {
			(void) nsc_free_buf(src_tmp);
			if (dest_tmp)
				(void) nsc_free_buf(dest_tmp);

			_ii_error(dest_ip, DSW_BMPOFFLINE);
			return (rc);
		}
		rc = _ii_nsc_or(src_tmp, dest_tmp, src_fba_pos, src_fba_pos,
		    len);
		if (II_SUCCESS(rc)) {
			II_NSC_WRITE(dest_ip, bitmap, rc, dest_tmp,
			    src_fba_pos, len, 0);
		}

		(void) nsc_free_buf(src_tmp);
		(void) nsc_free_buf(dest_tmp);
		if (!II_SUCCESS(rc)) {
			_ii_error(dest_ip, DSW_BMPOFFLINE);
			return (rc);
		}
	}

	dest_ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);

}

static _ii_bmp_ops_t alloc_buf_bmp = {
	_ii_ab_co_bmp,
	_ii_ab_ci_bmp,
	_ii_ab_zerobm,
	_ii_ab_copybm,
	_ii_ab_orbm,
	_ii_ab_tst_shd_bit,
	_ii_ab_set_shd_bit,
	_ii_ab_tst_copy_bit,
	_ii_ab_set_copy_bit,
	_ii_ab_clr_copy_bits,
	_ii_ab_next_copy_bit,
	_ii_ab_fill_copy_bmp,
	_ii_ab_load_bmp,
	_ii_ab_save_bmp,
	_ii_ab_change_bmp,
	_ii_ab_cnt_bits,
	_ii_ab_join_bmp
};


/*
 * Copyout the bit map.
 */
static int
_ii_km_co_bmp(_ii_info_t *ip, nsc_off_t bm_offset, unsigned char *user_bm,
    int user_bm_size)
{
	int	start_offset;
	int	bm_size;
	size_t	co_len;
	nsc_off_t	last_fba;

	/* First calculate the size of the shadow and copy bitmaps */
	co_len = DSW_BM_FBA_LEN(ip->bi_size);
	ASSERT((ip->bi_copyfba - ip->bi_shdfba) == co_len);

	/* Are we in the ranges of the various bitmaps/indexes? */
	if (bm_offset < ip->bi_shdfba)
		return (EIO);
	else if (bm_offset < (last_fba = ip->bi_shdfba + co_len))
		/*EMPTY*/;
	else if (bm_offset < (last_fba = ip->bi_copyfba + co_len))
		/*EMPTY*/;
	else if ((ip->bi_flags & DSW_TREEMAP) &&
	    (bm_offset < (last_fba = last_fba + (co_len * 32))))
		/*EMPTY*/;
	else return (EIO);

	if (FBA_LEN(user_bm_size) > last_fba - bm_offset)
		return (EIO);

	start_offset = FBA_SIZE(bm_offset);
	bm_size = FBA_SIZE(last_fba);

	co_len = (user_bm_size > bm_size) ? bm_size : user_bm_size;
	if (copyout(ip->bi_bitmap + start_offset, user_bm, co_len))
		return (EFAULT);

	return (0);
}

/*
 * Copyin a bit map and or with differences bitmap.
 */
static int
_ii_km_ci_bmp(_ii_info_t *ip, nsc_off_t bm_offset, unsigned char *user_bm,
    int user_bm_size)
{
	unsigned char *tmp_buf;
	unsigned char *dest;
	unsigned char *p;
	size_t	tmp_size;
	int	n;
	int	start_offset;
	int	bm_size;
	size_t	ci_len;
	int	rc = 0;

	start_offset = FBA_SIZE(bm_offset);
	bm_size = FBA_SIZE(DSW_BM_FBA_LEN(ip->bi_size));

	tmp_buf = NULL;
	tmp_size = FBA_SIZE(1);

	tmp_buf = kmem_alloc(tmp_size, KM_SLEEP);
	start_offset = FBA_SIZE(bm_offset);
	dest = ip->bi_bitmap + start_offset;
	bm_size = FBA_SIZE(DSW_BM_FBA_LEN(ip->bi_size));

	ci_len = (user_bm_size > bm_size) ? bm_size : user_bm_size;
	while (ci_len > 0) {
		n = (tmp_size > ci_len) ? ci_len : tmp_size;
		if (copyin(user_bm, tmp_buf, n)) {
			rc = EFAULT;
			break;
		}
		user_bm += n;
		for (p = tmp_buf; n--> 0; ci_len--)
			*dest++ |= *p++;
	}
	if (tmp_buf)
		kmem_free(tmp_buf, tmp_size);

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (rc);
}

/*
 * Completely zero the bit map.
 */
static int
_ii_km_zerobm(_ii_info_t *ip)
{
	int start_offset = FBA_SIZE(ip->bi_shdfba);
	int len;

	len = FBA_SIZE(ip->bi_copyfba - ip->bi_shdfba);
	mutex_enter(&ip->bi_bmpmutex);
	bzero(ip->bi_bitmap+start_offset, len);
	mutex_exit(&ip->bi_bmpmutex);

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}


/*
 * Copy shadow bitmap to copy bitmap
 */
static int
_ii_km_copybm(_ii_info_t *ip)
{
	int copy_offset, shd_offset;
	int len;

	len = FBA_SIZE(ip->bi_copyfba - ip->bi_shdfba);
	shd_offset = FBA_SIZE(ip->bi_shdfba);
	copy_offset = FBA_SIZE(ip->bi_copyfba);
	mutex_enter(&ip->bi_bmpmutex);
	bcopy(ip->bi_bitmap+shd_offset, ip->bi_bitmap+copy_offset, len);
	mutex_exit(&ip->bi_bmpmutex);

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}


/*
 * Or the shadow bitmap in to the copy bitmap, clear the
 * shadow bitmap.
 */
static int
_ii_km_orbm(_ii_info_t *ip)
{
	unsigned char *copy, *shd;
	int copy_offset, shd_offset;
	int len;

	len = FBA_SIZE(ip->bi_copyfba - ip->bi_shdfba);
	shd_offset = FBA_SIZE(ip->bi_shdfba);
	copy_offset = FBA_SIZE(ip->bi_copyfba);
	shd = ip->bi_bitmap + shd_offset;
	copy = ip->bi_bitmap + copy_offset;

	mutex_enter(&ip->bi_bmpmutex);
	while (len-- > 0)
		*copy++ |= *shd++;
	mutex_exit(&ip->bi_bmpmutex);

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}

/*
 * _ii_km_tst_shd_bit
 *	Determine if a chunk has been copied to the shadow device
 *
 * Calling/Exit State:
 *	Returns 1 if the modified bit has been set for the shadow device,
 *	otherwise returns 0.
 */

static int
_ii_km_tst_shd_bit(_ii_info_t *ip, chunkid_t chunk)
{
	unsigned char *bmp;
	int bmp_offset;
	int rc;

	bmp_offset = FBA_SIZE(ip->bi_shdfba);
	bmp = ip->bi_bitmap + bmp_offset;

	mutex_enter(&ip->bi_bmpmutex);
	rc = DSW_BIT_ISSET(bmp[chunk/DSW_BITS], chunk%DSW_BITS);
	mutex_exit(&ip->bi_bmpmutex);

	return (rc);
}


/*
 * _ii_km_set_shd_bit
 *	Records that a chunk has been copied to the shadow device
 */

static int
_ii_km_set_shd_bit(_ii_info_t *ip, chunkid_t chunk)
{
	unsigned char *bmp;
	int bmp_offset;

	bmp_offset = FBA_SIZE(ip->bi_shdfba);
	bmp = ip->bi_bitmap + bmp_offset;

	mutex_enter(&ip->bi_bmpmutex);
	if (DSW_BIT_ISSET(bmp[chunk/DSW_BITS], chunk%DSW_BITS) == 0) {
		DSW_BIT_SET(bmp[chunk/DSW_BITS], chunk%DSW_BITS);
		if ((ip->bi_state & DSW_CNTSHDBITS) == 0)
			ip->bi_shdbits++;
	}
	mutex_exit(&ip->bi_bmpmutex);

	return (0);
}

/*
 * _ii_km_tst_copy_bit
 *	Determine if a chunk needs to be copied during updates.
 *
 * Calling/Exit State:
 *	Returns 1 if the copy bit for the chunk is set,
 *	otherwise returns 0
 */

static int
_ii_km_tst_copy_bit(_ii_info_t *ip, chunkid_t chunk)
{
	unsigned char *bmp;
	int bmp_offset;
	int rc;

	bmp_offset = FBA_SIZE(ip->bi_copyfba);
	bmp = ip->bi_bitmap + bmp_offset;

	mutex_enter(&ip->bi_bmpmutex);
	rc = DSW_BIT_ISSET(bmp[chunk/DSW_BITS], chunk%DSW_BITS);
	mutex_exit(&ip->bi_bmpmutex);

	return (rc);
}


/*
 * _ii_km_set_copy_bit
 *	Records that a chunk has been copied to the shadow device
 */

static int
_ii_km_set_copy_bit(_ii_info_t *ip, chunkid_t chunk)
{
	unsigned char *bmp;
	int bmp_offset;

	bmp_offset = FBA_SIZE(ip->bi_copyfba);
	bmp = ip->bi_bitmap + bmp_offset;

	mutex_enter(&ip->bi_bmpmutex);
	if (DSW_BIT_ISSET(bmp[chunk/DSW_BITS], chunk%DSW_BITS) == 0) {
		DSW_BIT_SET(bmp[chunk/DSW_BITS], chunk%DSW_BITS);
		if ((ip->bi_state & DSW_CNTCPYBITS) == 0)
			ip->bi_copybits++;
	}
	mutex_exit(&ip->bi_bmpmutex);

	return (0);
}


/*
 * _ii_km_clr_copy_bits
 *	Records that a chunk has been cleared on the shadow device
 */

static int
_ii_km_clr_copy_bits(_ii_info_t *ip, chunkid_t chunk, int nchunks)
{
	unsigned char *bmp;
	int bmp_offset;

	bmp_offset = FBA_SIZE(ip->bi_copyfba);
	bmp = ip->bi_bitmap + bmp_offset;

	mutex_enter(&ip->bi_bmpmutex);
	for (; nchunks-- > 0; chunk++) {
		DSW_BIT_CLR(bmp[chunk/DSW_BITS], chunk%DSW_BITS);
		if (ip->bi_copybits > 0)
			ip->bi_copybits--;
	}
	mutex_exit(&ip->bi_bmpmutex);

	return (0);
}

/*
 * _ii_km_fill_copy_bmp
 *	Fills the copy bitmap with 1's.
 */

static int
_ii_km_fill_copy_bmp(_ii_info_t *ip)
{
	int len;
	unsigned char *bmp;
	int bmp_offset;

	bmp_offset = FBA_SIZE(ip->bi_copyfba);
	bmp = ip->bi_bitmap + bmp_offset;

	len = FBA_SIZE(ip->bi_copyfba - ip->bi_shdfba);

	mutex_enter(&ip->bi_bmpmutex);
	while (len-- > 0)
		*bmp++ = (unsigned char)0xff;
	mutex_exit(&ip->bi_bmpmutex);

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}

/*
 * _ii_km_load_bmp
 *	Load bitmap from persistent storage.
 */

static int
_ii_km_load_bmp(_ii_info_t *ip, int flag)
{
	nsc_off_t bmp_offset;
	nsc_size_t bitmap_size;
	int rc;

	if (ip->bi_flags & DSW_BMPOFFLINE)
		return (EIO);

	if (ip->bi_bitmap == NULL) {
		bitmap_size = FBA_SIZE(2 * (ip->bi_copyfba - ip->bi_shdfba) +
		    ip->bi_shdfba);
		ip->bi_bitmap = nsc_kmem_zalloc(bitmap_size, KM_SLEEP,
		    _ii_local_mem);
	}
	if (flag)
		return (0);		/* just create an empty bitmap */
	bmp_offset = FBA_SIZE(ip->bi_shdfba);
	rc = _ii_nsc_io(ip, KS_BMP, ip->bi_bmpfd, NSC_RDBUF, ip->bi_shdfba,
	    ip->bi_bitmap + bmp_offset,
	    2 * FBA_SIZE(ip->bi_copyfba - ip->bi_shdfba));
	if (!II_SUCCESS(rc))
		_ii_error(ip, DSW_BMPOFFLINE);

	ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (rc);
}

/*
 * _ii_km_save_bmp
 *	Save bitmap to persistent storage.
 */

static int
_ii_km_save_bmp(_ii_info_t *ip, int flag)
{
	int bmp_offset;
	int bitmap_size;
	int rc;

	bmp_offset = FBA_SIZE(ip->bi_shdfba);
	if (ip->bi_flags & DSW_BMPOFFLINE)
		rc = EIO;
	else {
		rc = _ii_nsc_io(ip, KS_BMP, ip->bi_bmpfd, NSC_WRBUF,
		    ip->bi_shdfba, ip->bi_bitmap + bmp_offset,
		    2 * FBA_SIZE(ip->bi_copyfba - ip->bi_shdfba));
		if (!II_SUCCESS(rc))
			_ii_error(ip, DSW_BMPOFFLINE);
	}

	if (flag && ip->bi_bitmap) {		/* dispose of bitmap memory */
		bitmap_size = FBA_SIZE(2 * (ip->bi_copyfba - ip->bi_shdfba) +
		    ip->bi_shdfba);
		nsc_kmem_free(ip->bi_bitmap, bitmap_size);
		ip->bi_bitmap = NULL;
	}

	return (rc);
}

/*
 * _ii_km_next_copy_bit
 *	Find next set copy bit.
 *
 * Returns the next bits set in the copy bitmap, with the corresponding chunks
 * locked. Used to cut down on the number of times the bmpmutex is acquired.
 */

static chunkid_t
_ii_km_next_copy_bit(_ii_info_t *ip, chunkid_t chunk, chunkid_t maxchunk,
	int want, int *got)
{
	unsigned char *bmp;
	int bmp_offset;
	int nextchunk;

	*got = 0;
	bmp_offset = FBA_SIZE(ip->bi_copyfba);
	bmp = ip->bi_bitmap + bmp_offset;

	mutex_enter(&ip->bi_bmpmutex);
	for (; chunk < maxchunk; chunk++) {
		if (DSW_BIT_ISSET(bmp[chunk/DSW_BITS], chunk%DSW_BITS)) {
			/*
			 * trylock won't sleep so can use while
			 * holding bi_bmpmutex.
			 */
			if (!_ii_trylock_chunk(ip, chunk)) {
				mutex_exit(&ip->bi_bmpmutex);
				_ii_lock_chunk(ip, chunk);
				*got = 1;

				DTRACE_PROBE(_ii_km_next_copy_bit);

				return (chunk);
			}
			*got = 1;
			for (nextchunk = chunk + 1;
			    *got < want && nextchunk < maxchunk; nextchunk++) {
				if (!DSW_BIT_ISSET(bmp[nextchunk/DSW_BITS],
				    nextchunk%DSW_BITS))
					break;
				if (_ii_trylock_chunk(ip, nextchunk))
					(*got)++;
				else
					break;
			}
			mutex_exit(&ip->bi_bmpmutex);

			DTRACE_PROBE(_ii_km_next_copy_bit);
			return (chunk);
		}
	}
	mutex_exit(&ip->bi_bmpmutex);

	return (maxchunk + 1);
}

/*
 * _ii_km_change_bmp
 *	copy change bitmap to memory
 */

static int
_ii_km_change_bmp(_ii_info_t *ip, unsigned char *ptr)
/* ARGSUSED */
{
	int	start_offset;
	int	bm_size;
	unsigned char *q;

	bm_size = FBA_SIZE(DSW_BM_FBA_LEN(ip->bi_size));

	start_offset = FBA_SIZE(ip->bi_shdfba);
	bcopy(ip->bi_bitmap + start_offset, ptr, bm_size);

	start_offset = FBA_SIZE(ip->bi_copyfba);
	q = ip->bi_bitmap + start_offset;
	while (bm_size-- > 0)
		*ptr |= *q;

	return (0);
}

/*
 * Count bits set in the bit map.
 */
static int
_ii_km_cnt_bits(_ii_info_t *ip, nsc_off_t bm_offset, nsc_size_t *counter,
    int bm_size)
{
	int	start_offset;
	int	i;
	nsc_size_t j, k;
	unsigned char *cp;

	start_offset = FBA_SIZE(bm_offset);

	cp = ip->bi_bitmap + start_offset;
	for (i = k = 0; i < bm_size; i++)
		for (j = (unsigned)*cp++; j; j &= j - 1)
			k++;
	*counter = k;

	return (0);
}

/*
 * Or the shadow bitmap in to the copy bitmap, clear the
 * shadow bitmap.
 */
static int
_ii_km_join_bmp(_ii_info_t *dest_ip, _ii_info_t *src_ip)
{
	uchar_t *dest, *src;
	nsc_size_t bm_size;

	dest = dest_ip->bi_bitmap + FBA_SIZE(dest_ip->bi_shdfba);
	src = src_ip->bi_bitmap + FBA_SIZE(src_ip->bi_shdfba);
	bm_size = FBA_SIZE(DSW_BM_FBA_LEN(dest_ip->bi_size));

	while (bm_size-- > 0)
		*dest++ |= *src++;

	dest_ip->bi_state |= (DSW_CNTSHDBITS|DSW_CNTCPYBITS);

	return (0);
}

static _ii_bmp_ops_t kmem_buf_bmp = {
	_ii_km_co_bmp,
	_ii_km_ci_bmp,
	_ii_km_zerobm,
	_ii_km_copybm,
	_ii_km_orbm,
	_ii_km_tst_shd_bit,
	_ii_km_set_shd_bit,
	_ii_km_tst_copy_bit,
	_ii_km_set_copy_bit,
	_ii_km_clr_copy_bits,
	_ii_km_next_copy_bit,
	_ii_km_fill_copy_bmp,
	_ii_km_load_bmp,
	_ii_km_save_bmp,
	_ii_km_change_bmp,
	_ii_km_cnt_bits,
	_ii_km_join_bmp
};


static int
ii_read_volume(_ii_info_t *ip, int mst_src, nsc_buf_t *srcbuf,
	nsc_buf_t *dstbuf, chunkid_t chunk_num, nsc_off_t fba, nsc_size_t len)
{
	int rc;
	nsc_buf_t *tmp;
	nsc_off_t mapped_fba;
	chunkid_t mapped_chunk;
	int overflow;

	if (mst_src || (ip->bi_flags&DSW_TREEMAP) == 0) {
		/* simple read with optional copy */
		if (mst_src) {
			II_NSC_READ(ip, master, rc, srcbuf, fba, len, 0);
		} else {
			II_NSC_READ(ip, shadow, rc, srcbuf, fba, len, 0);
		}
		if (dstbuf && II_SUCCESS(rc)) {
			rc = nsc_copy(srcbuf, dstbuf, fba, fba, len);
		}

		return (rc);
	}
	/* read from mapped shadow into final buffer */
	mapped_chunk = ii_tsearch(ip, chunk_num);
	if (mapped_chunk == II_NULLNODE)
		return (EIO);
	overflow = II_ISOVERFLOW(mapped_chunk);
	if (overflow)
		mapped_chunk = II_2OVERFLOW(mapped_chunk);
	/* convert chunk number from tsearch into final fba */
	mapped_fba = DSW_CHK2FBA(mapped_chunk) + (fba % DSW_SIZE);
	tmp = NULL;
	if (overflow) {
		(void) nsc_reserve(OVRFD(ip), NSC_MULTI);
		II_READ_START(ip, overflow);
		rc = nsc_alloc_buf(OVRFD(ip), mapped_fba, len, NSC_RDBUF, &tmp);
		II_READ_END(ip, overflow, rc, len);
	} else {
		II_READ_START(ip, shadow);
		rc = nsc_alloc_buf(SHDFD(ip), mapped_fba, len, NSC_RDBUF, &tmp);
		II_READ_END(ip, shadow, rc, len);
	}
	if (II_SUCCESS(rc)) {
		if (dstbuf == NULL)
			dstbuf = srcbuf;
		rc = nsc_copy(tmp, dstbuf, mapped_fba, fba, len);
		(void) nsc_free_buf(tmp);
	}
	if (overflow)
		nsc_release(OVRFD(ip));

	return (rc);
}

/*
 * _ii_fill_buf
 *	Read data from the required device
 *
 * Calling/Exit State:
 *	Returns 0 if the data was read successfully, otherwise
 *	error code.
 *
 * Description:
 *	Reads the data from fba_pos for length fba_len from the
 *	required device. This data may be a mix of data from the master
 *	device and the shadow device, depending on the state of the
 *	bitmaps.
 */

static int
_ii_fill_buf(ii_fd_t *bfd, nsc_off_t fba_pos, nsc_size_t fba_len, int flag,
    nsc_buf_t **handle, nsc_buf_t **handle2)
{
	_ii_info_t *ip = bfd->ii_info;
	_ii_info_t *xip;
	int second_shd = 0;
	nsc_off_t temp_fba;
	nsc_size_t temp_len;
	nsc_size_t bmp_len;
	chunkid_t chunk_num;
	int rc;
	int fill_from_pair;
	int rtype = SHDR|BMP;
	nsc_buf_t *second_buf = NULL;

	if (flag&NSC_RDAHEAD)
		return (NSC_DONE);

	chunk_num = fba_pos / DSW_SIZE;
	temp_fba = fba_pos;
	temp_len = fba_len;

	/*
	 * If the master is being updated from a shadow we need to fill from
	 * the correct shadow volume.
	 */
	if (NSHADOWS(ip) && bfd->ii_shd == 0) {
		for (xip = ip->bi_head; xip; xip = xip->bi_sibling) {
			if (xip == ip)
				continue;
			if (xip->bi_flags &DSW_COPYINGS) {
				second_shd = 1;
				ip = xip;
				if ((rc = _ii_rsrv_devs(ip, rtype,
				    II_INTERNAL)) != 0)
					return (EIO);
				rc = nsc_alloc_buf(SHDFD(ip), fba_pos, fba_len,
				    (flag&NSC_RDAHEAD)|NSC_MIXED, &second_buf);
				if (!II_SUCCESS(rc)) {
					rc = EIO;
					goto out;
				}
				handle2 = &second_buf;
				break;
			}
		}
	}

	while (temp_len > 0) {
		if ((temp_fba + temp_len) > DSW_CHK2FBA(chunk_num + 1)) {
			bmp_len = DSW_CHK2FBA(chunk_num + 1) - temp_fba;
			temp_len -= bmp_len;
		} else {
			bmp_len = temp_len;
			temp_len = 0;
		}

		fill_from_pair = 0;

		if ((ip->bi_flags & DSW_COPYINGM) == DSW_COPYINGM) {
			rc = II_TST_COPY_BIT(ip, chunk_num);
			/* Treat a failed bitmap volume as a clear bit */
			if (rc > 0) {
				/* Copy bit set */
				if (bfd->ii_shd) {
					if (*handle2)
						fill_from_pair = 1;
					else {
						rc = EIO;
						goto out;
					}
				}
			}
		}
		if ((ip->bi_flags & DSW_COPYINGS) == DSW_COPYINGS) {
			rc = II_TST_COPY_BIT(ip, chunk_num);
			/* Treat a failed bitmap volume as a clear bit */
			if (rc > 0) {
				/* Copy bit set */
				if (bfd->ii_shd == 0) {
					if (*handle2 ||
					    (ip->bi_flags&DSW_TREEMAP))
						fill_from_pair = 1;
					else {
						rc = EIO;
						goto out;
					}
				}
			}
		}
		if (((ip->bi_flags & DSW_GOLDEN) == 0) && bfd->ii_shd) {
			/* Dependent shadow read */

			rc = II_TST_SHD_BIT(ip, chunk_num);
			if (rc < 0) {
				rc = EIO;
				goto out;
			}
			if (rc == 0) {
				/* Shadow bit clear */
				if (*handle2)
					fill_from_pair = 1;
				else {
					rc = EIO;
					goto out;
				}
			}
		}

		if (fill_from_pair) {
			/* it matters now */
			if (ip->bi_flags & (DSW_MSTOFFLINE | DSW_SHDOFFLINE)) {
				rc = EIO;
				goto out;
			}
			if (*handle2 == NULL &&
			    (ip->bi_flags&DSW_TREEMAP) == 0) {
				rc = EIO;
				goto out;
			}
			rc = ii_read_volume(ip, bfd->ii_shd,
			    *handle2, *handle, chunk_num, temp_fba, bmp_len);
			if (!II_SUCCESS(rc)) {
				_ii_error(ip, DSW_MSTOFFLINE);
				_ii_error(ip, DSW_SHDOFFLINE);
				goto out;
			}
		} else {
			if (bfd->ii_shd && (ip->bi_flags & DSW_SHDOFFLINE)) {
				rc = EIO;
				goto out;
			}
			if ((bfd->ii_shd == 0) &&
			    (ip->bi_flags & DSW_MSTOFFLINE)) {
				rc = EIO;
				goto out;
			}
			rc = ii_read_volume(ip, !(bfd->ii_shd), *handle, NULL,
			    chunk_num, temp_fba, bmp_len);
			if (!II_SUCCESS(rc)) {
				if (bfd->ii_shd)
					_ii_error(ip, DSW_SHDOFFLINE);
				else
					_ii_error(ip, DSW_MSTOFFLINE);
				goto out;
			}
		}

		temp_fba += bmp_len;
		chunk_num++;
	}

	rc = 0;
out:
	if (second_buf)
		(void) nsc_free_buf(second_buf);
	if (second_shd)
		_ii_rlse_devs(ip, rtype);

	return (rc);
}


/*
 * _ii_shadow_write
 *	Perform any copy on write required by a write buffer request
 *
 * Calling/Exit State:
 *	Returns 0 on success, otherwise error code.
 *
 */

static int
_ii_shadow_write(ii_fd_t *bfd, nsc_off_t pos, nsc_size_t len)
{
	_ii_info_t *ip = bfd->ii_info;
	chunkid_t	chunk_num;
	int	rc;
	int	flag;
	int hanging;

	DTRACE_PROBE2(_ii_shadow_write_start, nsc_off_t, pos, nsc_size_t, len);

	/* fail immediately if config DB is unavailable */
	if ((ip->bi_flags & DSW_CFGOFFLINE) == DSW_CFGOFFLINE) {
		return (EIO);
	}

	chunk_num = pos / DSW_SIZE;

	if (bfd->ii_shd)
		flag = 0;		/* To shadow */
	else
		flag = CV_SHD2MST;	/* To master */

	mutex_enter(&ip->bi_mutex);
	ip->bi_shdref++;
	mutex_exit(&ip->bi_mutex);
	hanging = (ip->bi_flags&DSW_HANGING) != 0;

	for (; (chunk_num >= 0) &&
	    DSW_CHK2FBA(chunk_num) < (pos + len); chunk_num++) {

		if (!hanging)
			_ii_lock_chunk(ip, chunk_num);
		rc = _ii_copy_on_write(ip, flag, chunk_num, 1);

		/*
		 * Set the shadow bit when a small shadow has overflowed so
		 * that ii_read_volume can return an error if an attempt is
		 * made to read that chunk.
		 */
		if (!hanging) {
			if (rc == 0 ||
			    (rc == EIO && (ip->bi_flags&DSW_OVERFLOW) != 0))
				(void) II_SET_SHD_BIT(ip, chunk_num);
			_ii_unlock_chunk(ip, chunk_num);
		}
	}

	mutex_enter(&ip->bi_mutex);
	ip->bi_shdref--;
	if (ip->bi_state & DSW_CLOSING) {
		if (total_ref(ip) == 0) {
			cv_signal(&ip->bi_closingcv);
		}
	}
	mutex_exit(&ip->bi_mutex);

	/* did the bitmap fail during this process? */
	return (ip->bi_flags & DSW_CFGOFFLINE? EIO : 0);
}

/*
 * _ii_alloc_buf
 *	Allocate a buffer of data
 *
 * Calling/Exit State:
 *	Returns 0 for success, < 0 for async I/O, > 0 is an error code.
 *
 * Description:
 *	For a write buffer, calls dsw_shadow_write to perform any necessary
 *	copy on write operations, then allocates the real buffers from the
 *	underlying devices.
 *	For a read buffer, allocates the real buffers from the underlying
 *	devices, then calls _ii_fill_buf to fill the required buffer.
 *	For a buffer that is neither read nor write, just allocate the
 *	buffers so that a _ii_fill_buf can be done later by _ii_read.
 */

static int
_ii_alloc_buf(ii_fd_t *bfd, nsc_off_t pos, nsc_size_t len, int flag,
    ii_buf_t **ptr)
{
	_ii_info_t *ip = bfd->ii_info;
	ii_buf_t *h;
	int	raw = II_RAW(bfd);
	int rc = 0;
	int ioflag;
	int fbuf = 0, fbuf2 = 0, abuf = 0;
	int rw_ent = 0;

	if (bfd->ii_bmp) {
		DTRACE_PROBE(_ii_alloc_buf_end);
		/* any I/O to the bitmap device is barred */
		return (EIO);
	}

	if (len == 0) {
		DTRACE_PROBE(_ii_alloc_buf_end);
		return (EINVAL);
	}

	/* Bounds checking */
	if (pos + len > ip->bi_size) {
		if (ii_debug > 1)
			cmn_err(CE_NOTE,
			    "!ii: Attempt to access beyond end of ii volume");
		DTRACE_PROBE(_ii_alloc_buf_end);
		return (EIO);
	}

	h = *ptr;
	if (h == NULL) {
		h = (ii_buf_t *)_ii_alloc_handle(NULL, NULL, NULL, bfd);
		if (h == NULL) {
			DTRACE_PROBE(_ii_alloc_buf_end);
			return (ENOMEM);
		}
	}

	/*
	 * Temporary nsc_reserve of bitmap and other device.
	 * This device has already been reserved by the preceding _ii_attach.
	 * Corresponding nsc_release is in _ii_free_buf.
	 */

	h->ii_rsrv = BMP | (raw ? (bfd->ii_shd ? MSTR : SHDR)
	    : (bfd->ii_shd ? MST : SHD));

	if (!bfd->ii_shd)
		ip = ip->bi_master;

	rw_enter(&ip->bi_linkrw, RW_READER);
	rw_ent = 1;
	if (ip->bi_shdfd == NULL || (ip->bi_flags & DSW_SHDEXPORT) ==
	    DSW_SHDEXPORT)
		h->ii_rsrv &= ~(SHD|SHDR);
	if ((rc = _ii_rsrv_devs(ip, h->ii_rsrv, II_EXTERNAL)) != 0) {
		rw_exit(&ip->bi_linkrw);
		rw_ent = 0;
		h->ii_rsrv = NULL;
		goto error;
	}

	if (flag & NSC_WRBUF) {
		rc = _ii_shadow_write(bfd, pos, len);
		if (!II_SUCCESS(rc))
			goto error;
	}

	if (!(flag & NSC_RDAHEAD))
		ioflag = flag & ~(NSC_RDBUF);
	else
		ioflag = flag;

	if (bfd->ii_shd) {
		/*
		 * SHADOW
		 */

		if (ip->bi_flags & DSW_SHDEXPORT) {
			rc = EIO;
			goto error;
		}
		/*
		 * The master device buffer has to be allocated first
		 * so that deadlocks are avoided.
		 */
		DTRACE_PROBE(AllocBufFor_SHADOW);

		if ((ip->bi_flags & (DSW_MSTOFFLINE|DSW_SHDIMPORT)) == 0) {
			rc = nsc_alloc_buf(MSTFD(ip), pos, len,
			    (flag&NSC_RDAHEAD)|NSC_MIXED, &h->ii_bufp2);
			if (!II_SUCCESS(rc)) {
				if (ii_debug > 2)
					cmn_err(CE_WARN, "!ii: "
					    "Join/write-S race detected\n");
				if (h->ii_bufp2)
					(void) nsc_free_buf(h->ii_bufp2);
				h->ii_bufp2 = NULL;
				/*
				 * Carry on as this will not matter if
				 * _ii_fill_buf is not called, or if
				 * it is called but doesn't need to read this
				 * volume.
				 */
				rc = 0;
			}
			fbuf2 = 1;
		}

		if (ip->bi_flags & DSW_SHDOFFLINE) {
			rc = EIO;
			goto error;
		}
		if ((ip->bi_flags)&DSW_TREEMAP) {
			rc = nsc_alloc_abuf(pos, len, 0, &h->ii_abufp);
			if (!II_SUCCESS(rc)) {
				_ii_error(ip, DSW_SHDOFFLINE);
				goto error;
			}
			abuf = 1;
		} else {
			II_ALLOC_BUF(ip, shadow, rc, SHDFD(ip), pos, len,
			    ioflag, &h->ii_bufp);	/* do not read yet */
			if (!II_SUCCESS(rc)) {
				_ii_error(ip, DSW_SHDOFFLINE);
				goto error;
			}
			fbuf = 1;
		}
	} else {
		/*
		 * MASTER
		 */

		/*
		 * The master device buffer has to be allocated first
		 * so that deadlocks are avoided.
		 */

		if (ip->bi_flags & (DSW_MSTOFFLINE|DSW_SHDIMPORT)) {
			rc = EIO;
			goto error;
		}

		DTRACE_PROBE(AllocBufFor_MASTER);

		II_ALLOC_BUF(ip, master, rc, MSTFD(ip), pos, len, ioflag,
		    &h->ii_bufp);		/* do not read yet */
		if (!II_SUCCESS(rc)) {
			_ii_error(ip, DSW_MSTOFFLINE);
			goto error;
		}
		fbuf = 1;

		/*
		 * If shadow FD and (dependent set OR copying) and
		 * not (compact dependent && shadow offline && shadow exported)
		 */
		if ((ip->bi_shdfd) &&
		    ((ip->bi_flags & DSW_COPYINGP) ||
		    (!(ip->bi_flags & DSW_GOLDEN))) &&
		    (!(ip->bi_flags &
		    (DSW_TREEMAP|DSW_SHDOFFLINE|DSW_SHDEXPORT)))) {
			rc = nsc_alloc_buf(SHDFD(ip), pos, len,
			    (flag&NSC_RDAHEAD)|NSC_MIXED, &h->ii_bufp2);
			if (!II_SUCCESS(rc)) {
				if (ii_debug > 2)
					cmn_err(CE_WARN, "!ii: "
					    "Join/write-M race detected\n");
				if (h->ii_bufp2)
					(void) nsc_free_buf(h->ii_bufp2);
				h->ii_bufp2 = NULL;
				/*
				 * Carry on as this will not matter if
				 * _ii_fill_buf is not called, or if
				 * it is called but doesn't need to read this
				 * volume.
				 */
				rc = 0;
			}
			fbuf2 = 1;
		}
	}

	if (flag & NSC_RDBUF)
		rc = _ii_fill_buf(bfd, pos, len, flag,
		    h->ii_abufp ? &h->ii_abufp : &h->ii_bufp, &h->ii_bufp2);

error:
	if (II_SUCCESS(rc)) {
		h->ii_bufh.sb_vec = h->ii_abufp ? h->ii_abufp->sb_vec :
		    h->ii_bufp->sb_vec;
		h->ii_bufh.sb_error = 0;
		h->ii_bufh.sb_flag |= flag;
		h->ii_bufh.sb_pos = pos;
		h->ii_bufh.sb_len = len;
	} else {
		h->ii_bufh.sb_error = rc;
		if (h->ii_bufp2 && fbuf2) {
			(void) nsc_free_buf(h->ii_bufp2);
			h->ii_bufp2 = NULL;
		}
		if (h->ii_bufp && fbuf) {
			(void) nsc_free_buf(h->ii_bufp);
			h->ii_bufp = NULL;
		}
		if (h->ii_abufp && abuf) {
			(void) nsc_free_buf(h->ii_abufp);
			h->ii_abufp = NULL;
		}

		if (h->ii_rsrv) {
			/*
			 * Release temporary reserve - reserved above.
			 */
			_ii_rlse_devs(ip, h->ii_rsrv);
			h->ii_rsrv = NULL;
		}
		if (rw_ent)
			rw_exit(&ip->bi_linkrw);
	}

	return (rc);
}


/*
 * _ii_free_buf
 */

static int
_ii_free_buf(ii_buf_t *h)
{
	ii_fd_t *bfd;
	int rsrv;
	int rc;

	if (h->ii_abufp == NULL) {
		rc = nsc_free_buf(h->ii_bufp);
	} else {
		rc = nsc_free_buf(h->ii_abufp);
		h->ii_abufp = NULL;
	}
	if (!II_SUCCESS(rc))
		return (rc);
	if (h->ii_bufp2) {
		rc = nsc_free_buf(h->ii_bufp2);
		h->ii_bufp2 = NULL;
		if (!II_SUCCESS(rc))
			return (rc);
	}

	bfd = h->ii_fd;
	rsrv = h->ii_rsrv;

	if ((h->ii_bufh.sb_flag & NSC_HALLOCATED) == 0) {
		rc = _ii_free_handle(h, h->ii_fd);
		if (!II_SUCCESS(rc))
			return (rc);
	} else {
		h->ii_bufh.sb_flag = NSC_HALLOCATED;
		h->ii_bufh.sb_vec = NULL;
		h->ii_bufh.sb_error = 0;
		h->ii_bufh.sb_pos = 0;
		h->ii_bufh.sb_len = 0;
		h->ii_rsrv = NULL;
	}

	/*
	 * Release temporary reserve - reserved in _ii_alloc_buf.
	 */

	if (rsrv)
		_ii_rlse_devs(bfd->ii_info, rsrv);
	rw_exit(&bfd->ii_info->bi_linkrw);

	return (0);
}


/*
 * _ii_open
 *	Open a device
 *
 * Calling/Exit State:
 *	Returns a token to identify the shadow device.
 *
 * Description:
 *	Performs the housekeeping operations associated with an upper layer
 *	of the nsc stack opening a shadowed device.
 */

/* ARGSUSED */

static int
_ii_open(char *path, int flag, blind_t *cdp, nsc_iodev_t *iodev)
{
	_ii_info_t *ip;
	_ii_overflow_t *op;
	ii_fd_t *bfd;
	int is_mst = 0;
	int is_shd = 0;
	int raw = (flag & NSC_CACHE) == 0;

	bfd = nsc_kmem_zalloc(sizeof (*bfd), KM_SLEEP, _ii_local_mem);
	if (!bfd)
		return (ENOMEM);

	DTRACE_PROBE1(_ii_open_mutex,
	    ii_fd_t *, bfd);

	mutex_enter(&_ii_info_mutex);

	for (ip = _ii_info_top; ip; ip = ip->bi_next) {
		if (strcmp(path, ii_pathname(ip->bi_mstfd)) == 0) {
			is_mst = 1;
			break;
		} else if (strcmp(path, ip->bi_keyname) == 0) {
			is_shd = 1;
			break;
		} else if (strcmp(path, ii_pathname(ip->bi_bmpfd)) == 0)
			break;
	}

	if (is_mst)
		ip = ip->bi_master;

	if (ip && ip->bi_disabled && !(ip->bi_state & DSW_MULTIMST)) {
		DTRACE_PROBE(_ii_open_Disabled);
		mutex_exit(&_ii_info_mutex);
		return (EINTR);
	}

	if (!ip) {
		/* maybe it's an overflow */
		mutex_exit(&_ii_info_mutex);
		mutex_enter(&_ii_overflow_mutex);
		for (op = _ii_overflow_top; op; op = op->ii_next) {
			if (strcmp(path, op->ii_volname) == 0)
				break;
		}
		mutex_exit(&_ii_overflow_mutex);

		if (!op) {
			nsc_kmem_free(bfd, sizeof (*bfd));
			DTRACE_PROBE(_ii_open_end_EINVAL);
			return (EINVAL);
		}
		bfd->ii_ovr = 1;
		bfd->ii_oflags = flag;
		bfd->ii_optr = op;
		*cdp = (blind_t)bfd;

		DTRACE_PROBE(_ii_open_end_overflow);
		return (0);
	}
	mutex_enter(&ip->bi_mutex);
	ip->bi_ioctl++;
	mutex_exit(&_ii_info_mutex);

	if (is_mst) {
		if (raw) {
			ip->bi_mstr_iodev = NULL;	/* set in attach */
			ip->bi_mstrref++;
		} else {
			ip->bi_mst_iodev = NULL;	/* set in attach */
			ip->bi_mstref++;
		}
		ip->bi_master->bi_iifd = bfd;
	} else if (is_shd) {
		if (raw) {
			ip->bi_shdr_iodev = NULL;	/* set in attach */
			ip->bi_shdrref++;
		} else {
			ip->bi_shd_iodev = NULL;	/* set in attach */
			ip->bi_shdref++;
		}
		bfd->ii_shd = 1;
	} else {
		ip->bi_bmpref++;
		ip->bi_bmp_iodev = NULL;	/* set in attach */
		bfd->ii_bmp = 1;
	}

	_ii_ioctl_done(ip);
	mutex_exit(&ip->bi_mutex);

	bfd->ii_info = ip;
	bfd->ii_oflags = flag;

	*cdp = (blind_t)bfd;

	return (0);
}

static int
_ii_openc(char *path, int flag, blind_t *cdp, nsc_iodev_t *iodev)
{
	return (_ii_open(path, NSC_CACHE|flag, cdp, iodev));
}

static int
_ii_openr(char *path, int flag, blind_t *cdp, nsc_iodev_t *iodev)
{
	return (_ii_open(path, NSC_DEVICE|flag, cdp, iodev));
}


/*
 * _ii_close
 *	Close a device
 *
 * Calling/Exit State:
 *	Always succeeds - returns 0
 *
 * Description:
 *	Performs the housekeeping operations associated with an upper layer
 *	of the nsc stack closing a shadowed device.
 */

static int
_ii_close(bfd)
ii_fd_t *bfd;
{
	_ii_info_t *ip = bfd->ii_info;
	_ii_info_dev_t *dip;
	int raw;

	if (!ip) {
		ASSERT(bfd->ii_ovr);
		return (0);
	}

	raw = II_RAW(bfd);

	mutex_enter(&ip->bi_mutex);

	if (bfd->ii_shd && raw) {
		dip = &ip->bi_shdrdev;
	} else if (bfd->ii_shd) {
		dip = &ip->bi_shddev;
	} else if (bfd->ii_bmp) {
		dip = &ip->bi_bmpdev;
	} else if (raw) {
		dip = ip->bi_mstrdev;
	} else {
		dip = ip->bi_mstdev;
	}

	if (dip) {
		dip->bi_ref--;
		if (dip->bi_ref == 0)
			dip->bi_iodev = NULL;
	}

	if (ip->bi_state & DSW_CLOSING) {
		if (total_ref(ip) == 0) {
			cv_signal(&ip->bi_closingcv);
		}
	} else if ((ip->bi_flags & DSW_HANGING) &&
	    (ip->bi_head->bi_state & DSW_CLOSING))
		cv_signal(&ip->bi_head->bi_closingcv);

	if (!(bfd->ii_shd || bfd->ii_bmp))	/* is master device */
		ip->bi_master->bi_iifd = NULL;
	mutex_exit(&ip->bi_mutex);

	nsc_kmem_free(bfd, sizeof (*bfd));

	return (0);
}

/*
 * _ii_alloc_handle
 *	Allocate a handle
 *
 */

static nsc_buf_t *
_ii_alloc_handle(void (*d_cb)(), void (*r_cb)(), void (*w_cb)(), ii_fd_t *bfd)
{
	ii_buf_t *h;

	if (REMOTE_VOL(bfd->ii_shd, bfd->ii_info))
		return (NULL);

	h = kmem_alloc(sizeof (*h), KM_SLEEP);
	if (!h)
		return (NULL);

	h->ii_abufp = NULL;
	h->ii_bufp = nsc_alloc_handle(II_FD(bfd), d_cb, r_cb, w_cb);
	if (!h->ii_bufp) {
		kmem_free(h, sizeof (*h));
		return (NULL);
	}
	h->ii_bufp2 = NULL;
	h->ii_bufh.sb_flag = NSC_HALLOCATED;
	h->ii_fd = bfd;
	h->ii_rsrv = NULL;

	return ((nsc_buf_t *)h);
}


/*
 * _ii_free_handle
 *	Free a handle
 *
 */

static int	 /*ARGSUSED*/
_ii_free_handle(ii_buf_t *h, ii_fd_t *bfd)
{
	int rc;

	if (h->ii_abufp)
		(void) nsc_free_buf(h->ii_abufp);
	rc = nsc_free_handle(h->ii_bufp);
	if (!II_SUCCESS(rc)) {
		return (rc);
	}

	kmem_free(h, sizeof (ii_buf_t));

	return (0);
}


/*
 * _ii_attach
 *	Attach
 *
 * Calling/Exit State:
 *	Returns 0 for success, errno on failure.
 *
 * Description:
 */

static int
_ii_attach(ii_fd_t *bfd, nsc_iodev_t *iodev)
{
	_ii_info_t *ip;
	int dev;
	int raw;
	int rc;
	_ii_info_dev_t *infop;

	raw  = II_RAW(bfd);

	DTRACE_PROBE2(_ii_attach_info,
	    char *, bfd->ii_shd? "shadow" : "master",
	    int, raw);

	if (bfd->ii_ovr)
		return (EINVAL);

	ip = bfd->ii_info;
	if (ip == NULL)
		return (EINVAL);

	mutex_enter(&ip->bi_mutex);
	if (bfd->ii_bmp) {
		infop = &ip->bi_bmpdev;
	} else if (bfd->ii_shd) {
		if (raw) {
			infop = &ip->bi_shdrdev;
		} else {
			infop = &ip->bi_shddev;
		}
	} else if (!bfd->ii_ovr) {
		if (raw) {
			infop = ip->bi_mstrdev;
		} else {
			infop = ip->bi_mstdev;
		}
	}

	if (iodev) {
		infop->bi_iodev = iodev;
		nsc_set_owner(infop->bi_fd, infop->bi_iodev);
	}
	mutex_exit(&ip->bi_mutex);

	if (bfd->ii_bmp)
		return (EINVAL);

	if (raw)
		dev = bfd->ii_shd ? SHDR : MSTR;
	else
		dev = bfd->ii_shd ? SHD : MST;

	rc = _ii_rsrv_devs(ip, dev, II_EXTERNAL);

	return (rc);
}


/*
 * _ii_detach
 *	Detach
 *
 * Calling/Exit State:
 *	Returns 0 for success, always succeeds
 *
 * Description:
 */

static int
_ii_detach(bfd)
ii_fd_t *bfd;
{
	int dev;
	int raw;

	raw = II_RAW(bfd);

	DTRACE_PROBE2(_ii_detach_info,
	    char *, bfd->ii_shd? "shadow" : "master",
	    int, raw);

	if (bfd->ii_bmp)
		return (0);

	ASSERT(bfd->ii_info);
	dev = bfd->ii_shd ? (raw ? SHDR : SHD) : (raw ? MSTR : MST);
	_ii_rlse_devs(bfd->ii_info, dev);

	return (0);
}

/*
 * _ii_get_pinned
 *
 */

static int
_ii_get_pinned(ii_fd_t *bfd)
{
	int rc;

	if (REMOTE_VOL(bfd->ii_shd, bfd->ii_info))
		return (EIO);

	rc = nsc_get_pinned(II_FD(bfd));

	return (rc);
}

/*
 * _ii_discard_pinned
 *
 */

static int
_ii_discard_pinned(ii_fd_t *bfd, nsc_off_t pos, nsc_size_t len)
{
	int rc;

	if (REMOTE_VOL(bfd->ii_shd, bfd->ii_info))
		return (EIO);
	rc = nsc_discard_pinned(II_FD(bfd), pos, len);

	return (rc);
}

/*
 * _ii_partsize
 *
 */

static int
_ii_partsize(ii_fd_t *bfd, nsc_size_t *ptr)
{
	/* Always return saved size */
	*ptr = bfd->ii_info->bi_size;
	return (0);
}

/*
 * _ii_maxfbas
 *
 */

static int
_ii_maxfbas(ii_fd_t *bfd, int flag, nsc_size_t *ptr)
{
	int rc;
	int rs;
	int dev;
	_ii_info_t *ip;

	ip = bfd->ii_info;
	if (REMOTE_VOL(bfd->ii_shd, ip))
		return (EIO);

	dev =  ((ip->bi_flags)&DSW_SHDIMPORT) ? SHDR : MSTR;

	DTRACE_PROBE1(_ii_maxfbas_info,
	    char *, dev == SHDR? "shadow" : "master");

	rs = _ii_rsrv_devs(ip, dev, II_INTERNAL);
	rc = nsc_maxfbas((dev == MSTR) ? MSTFD(ip) : SHDFD(ip), flag, ptr);

	if (rs == 0)
		_ii_rlse_devs(ip, dev);

	return (rc);
}

/*
 * ii_get_group_list
 */
_ii_info_t **
ii_get_group_list(char *group, int *count)
{
	int i;
	int nip;
	uint64_t   hash;
	_ii_info_t **ipa;
	_ii_lsthead_t *head;
	_ii_lstinfo_t *np;

	hash = nsc_strhash(group);

	for (head = _ii_group_top; head; head = head->lst_next) {
		if (hash == head->lst_hash && strncmp(head->lst_name,
		    group, DSW_NAMELEN) == 0)
			break;
	}

	if (!head) {
		return (NULL);
	}

	/* Count entries */
	for (nip = 0, np = head->lst_start; np; np = np->lst_next)
		++nip;

	ASSERT(nip > 0);

	ipa = kmem_zalloc(sizeof (_ii_info_t *) * nip, KM_SLEEP);

	np = head->lst_start;

	for (i = 0; i < nip; i++) {
		ASSERT(np != 0);

		ipa[i] = np->lst_ip;
		np = np->lst_next;
	}

	*count = nip;
	return (ipa);
}

/*
 * _ii_pinned
 *
 */

static void
_ii_pinned(_ii_info_dev_t *dip, nsc_off_t pos, nsc_size_t len)
{
	DTRACE_PROBE3(_ii_pinned_start, nsc_iodev_t, dip->bi_iodev,
	    nsc_off_t, pos, nsc_size_t, len);

	nsc_pinned_data(dip->bi_iodev, pos, len);

}

/*
 * _ii_unpinned
 *
 */

static void
_ii_unpinned(_ii_info_dev_t *dip, nsc_off_t pos, nsc_size_t len)
{
	nsc_unpinned_data(dip->bi_iodev, pos, len);

}


/*
 * _ii_read
 */

static int
_ii_read(ii_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	int rc;
	void *sb_vec;
	nsc_vec_t **src;

	if (REMOTE_VOL(h->ii_fd->ii_shd, h->ii_fd->ii_info))
		rc = EIO;
	else {
		src =  h->ii_abufp? &h->ii_abufp->sb_vec : &h->ii_bufp->sb_vec;
		sb_vec = *src;
		*src = h->ii_bufh.sb_vec;
		rc = _ii_fill_buf(h->ii_fd, pos, len, flag,
		    h->ii_abufp ? &h->ii_abufp : &h->ii_bufp, &h->ii_bufp2);
		*src = sb_vec;
	}
	if (!II_SUCCESS(rc))
		h->ii_bufh.sb_error = rc;

	return (rc);
}


/*
 * _ii_write
 */

static int
_ii_write(ii_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	int rc;
	ii_fd_t *bfd = h->ii_fd;
	_ii_info_t *ip = bfd->ii_info;
	chunkid_t	chunk_num;
	nsc_size_t	copy_len;
	nsc_off_t	mapped_fba;
	chunkid_t	mapped_chunk;
	int	overflow;
	nsc_buf_t *tmp;
	void	*sb_vec;

	if (REMOTE_VOL(h->ii_fd->ii_shd, h->ii_fd->ii_info))
		rc = EIO;
	else if ((ip->bi_flags&DSW_TREEMAP) == 0 || !bfd->ii_shd) {
		sb_vec = h->ii_bufp->sb_vec;
		h->ii_bufp->sb_vec = h->ii_bufh.sb_vec;
		if (bfd->ii_shd) {
			II_NSC_WRITE(ip, shadow, rc, h->ii_bufp, pos, len,
			    flag);
		} else {
			II_NSC_WRITE(ip, master, rc, h->ii_bufp, pos, len,
			    flag);
		}
		h->ii_bufp->sb_vec = sb_vec;
	} else {
		/* write of mapped shadow buffer */
		rc = 0;
		chunk_num = pos / DSW_SIZE;
		while (len > 0 && II_SUCCESS(rc)) {
			/*
			 * don't need to test bitmaps as allocating the
			 * write buffer will c-o-write the chunk.
			 */
			mapped_chunk = ii_tsearch(ip, chunk_num);
			if (mapped_chunk == II_NULLNODE) {
				rc = EIO;
				break;
			}
			overflow = II_ISOVERFLOW(mapped_chunk);
			if (overflow)
				mapped_chunk = II_2OVERFLOW(mapped_chunk);
			mapped_fba = DSW_CHK2FBA(mapped_chunk) +
			    (pos % DSW_SIZE);
			copy_len = DSW_SIZE - (pos % DSW_SIZE);
			if (copy_len > len)
				copy_len = len;
			tmp = NULL;
			if (overflow) {
				(void) nsc_reserve(OVRFD(ip), NSC_MULTI);
				rc = nsc_alloc_buf(OVRFD(ip), mapped_fba,
				    copy_len, NSC_WRBUF, &tmp);
			} else
				rc = nsc_alloc_buf(SHDFD(ip), mapped_fba,
				    copy_len, NSC_WRBUF, &tmp);
			sb_vec = h->ii_abufp->sb_vec;
			h->ii_abufp->sb_vec = h->ii_bufh.sb_vec;
			if (II_SUCCESS(rc)) {
				rc = nsc_copy(h->ii_abufp, tmp, pos,
				    mapped_fba, copy_len);
			}
			if (overflow) {
				II_NSC_WRITE(ip, overflow, rc, tmp, mapped_fba,
				    copy_len, flag);
			} else {
				II_NSC_WRITE(ip, shadow, rc, tmp, mapped_fba,
				    copy_len, flag);
			}
			h->ii_abufp->sb_vec = sb_vec;
			(void) nsc_free_buf(tmp);
			if (overflow)
				nsc_release(OVRFD(ip));
			/* move on to next chunk */
			pos += copy_len;
			len -= copy_len;
			chunk_num++;
		}
	}
	if (!II_SUCCESS(rc))
		h->ii_bufh.sb_error = rc;

	return (rc);
}


/*
 * _ii_zero
 */

static int
_ii_zero(ii_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	int rc;
	void *sb_vec;

	sb_vec = h->ii_bufp->sb_vec;
	h->ii_bufp->sb_vec = h->ii_bufh.sb_vec;
	rc = nsc_zero(h->ii_bufp, pos, len, flag);
	h->ii_bufp->sb_vec = sb_vec;
	if (!II_SUCCESS(rc))
		h->ii_bufh.sb_error = rc;

	return (rc);
}


/*
 * _ii_uncommit
 */

static int
_ii_uncommit(ii_buf_t *h, nsc_off_t pos, nsc_size_t len, int flag)
{
	int rc;
	void *sb_vec;

	sb_vec = h->ii_bufp->sb_vec;
	h->ii_bufp->sb_vec = h->ii_bufh.sb_vec;
	rc = nsc_uncommit(h->ii_bufp, pos, len, flag);
	h->ii_bufp->sb_vec = sb_vec;
	if (!II_SUCCESS(rc))
		h->ii_bufh.sb_error = rc;

	return (rc);
}


/*
 * _ii_trksize
 */

static int
_ii_trksize(ii_fd_t *bfd, int trksize)
{
	int rc;

	rc = nsc_set_trksize(II_FD(bfd), trksize);

	return (rc);
}

/*
 * _ii_register_path
 */

static nsc_path_t *
_ii_register_path(char *path, int type, nsc_io_t *io)
{
	nsc_path_t *tok;

	tok = nsc_register_path(path, type, io);

	return (tok);
}

/*
 * _ii_unregister_path
 */
/*ARGSUSED*/
static int
_ii_unregister_path(nsc_path_t *sp, int flag, char *type)
{
	int rc;

	rc = nsc_unregister_path(sp, flag);

	return (rc);
}

int
_ii_ll_add(_ii_info_t *ip, kmutex_t *mutex, _ii_lsthead_t **lst, char *name,
    char **key)
{
	_ii_lsthead_t **head;
	_ii_lstinfo_t *node;
	uint64_t hash;

	ASSERT(key && !*key);
	ASSERT(ip && mutex && lst && name);

	node = kmem_zalloc(sizeof (_ii_lstinfo_t), KM_SLEEP);
	if (!node) {
		cmn_err(CE_WARN, "!ii: _ii_ll_add: ENOMEM");
		DTRACE_PROBE(_ii_ll_add_end_ENOMEM);
		return (ENOMEM);
	}
	node->lst_ip = ip;

	/* find out where we should insert it */
	hash = nsc_strhash(name);

	mutex_enter(mutex);
	for (head = lst; *head; head = &((*head)->lst_next)) {
		if (((*head)->lst_hash == hash) &&
		    strncmp(name, (*head)->lst_name, DSW_NAMELEN) == 0) {
			node->lst_next = (*head)->lst_start;
			(*head)->lst_start = node;
			break;
		}
	}

	if (!*head) {
		/* create a new entry */
		*head = kmem_zalloc(sizeof (_ii_lsthead_t), KM_SLEEP);
		if (!*head) {
			/* bother */
			cmn_err(CE_WARN, "!ii: _ii_ll_add: ENOMEM");
			kmem_free(node, sizeof (_ii_lstinfo_t));
			DTRACE_PROBE(_ii_ll_add_end_2);
			return (ENOMEM);
		}
		(*head)->lst_hash = hash;
		(void) strncpy((*head)->lst_name, name, DSW_NAMELEN);
		(*head)->lst_start = node;
	}
	mutex_exit(mutex);

	*key = (*head)->lst_name;

	return (0);
}

int
_ii_ll_remove(_ii_info_t *ip, kmutex_t *mutex, _ii_lsthead_t **lst, char **key)
{
	_ii_lsthead_t **head, *oldhead = 0;
	_ii_lstinfo_t **node, *oldnode = 0;
	uint64_t hash;
	int found;

	ASSERT(key && *key);
	ASSERT(ip && lst);

	hash = nsc_strhash(*key);

	mutex_enter(mutex);
	for (head = lst; *head; head = &((*head)->lst_next)) {
		if (((*head)->lst_hash == hash) &&
		    strncmp(*key, (*head)->lst_name, DSW_NAMELEN) == 0)
			break;
	}
	if (!*head) {
		/* no such link (!) */
		mutex_exit(mutex);
		return (0);
	}

	found = 0;
	for (node = &(*head)->lst_start; *node; node = &((*node)->lst_next)) {
		if (ip == (*node)->lst_ip) {
			oldnode = *node;
			*node = (*node)->lst_next;
			kmem_free(oldnode, sizeof (_ii_lstinfo_t));
			found = 1;
			break;
		}
	}

	ASSERT(found);

	if (!found) {
		mutex_exit(mutex);
		return (0);
	}

	/* did we just delete the last set in this resource group? */
	if (!(*head)->lst_start) {
		oldhead = *head;
		*head = (*head)->lst_next;
		kmem_free(oldhead, sizeof (_ii_lsthead_t));
	}
	mutex_exit(mutex);

	*key = NULL;

	return (0);
}

static nsc_def_t _ii_fd_def[] = {
	"Pinned",	(uintptr_t)_ii_pinned,		0,
	"Unpinned",	(uintptr_t)_ii_unpinned,	0,
	0,		0,				0
};


static nsc_def_t _ii_io_def[] = {
	"Open",		(uintptr_t)_ii_openc,		0,
	"Close",	(uintptr_t)_ii_close,		0,
	"Attach",	(uintptr_t)_ii_attach,		0,
	"Detach",	(uintptr_t)_ii_detach,		0,
	"AllocHandle",	(uintptr_t)_ii_alloc_handle,	0,
	"FreeHandle",	(uintptr_t)_ii_free_handle,	0,
	"AllocBuf",	(uintptr_t)_ii_alloc_buf,	0,
	"FreeBuf",	(uintptr_t)_ii_free_buf,	0,
	"GetPinned",	(uintptr_t)_ii_get_pinned,	0,
	"Discard",	(uintptr_t)_ii_discard_pinned,	0,
	"PartSize",	(uintptr_t)_ii_partsize,	0,
	"MaxFbas",	(uintptr_t)_ii_maxfbas,	0,
	"Read",		(uintptr_t)_ii_read,		0,
	"Write",	(uintptr_t)_ii_write,		0,
	"Zero",		(uintptr_t)_ii_zero,		0,
	"Uncommit",	(uintptr_t)_ii_uncommit,	0,
	"TrackSize",	(uintptr_t)_ii_trksize,	0,
	"Provide",	0,				0,
	0,		0,				0
};

static nsc_def_t _ii_ior_def[] = {
	"Open",		(uintptr_t)_ii_openr,		0,
	"Close",	(uintptr_t)_ii_close,		0,
	"Attach",	(uintptr_t)_ii_attach,		0,
	"Detach",	(uintptr_t)_ii_detach,		0,
	"AllocHandle",	(uintptr_t)_ii_alloc_handle,	0,
	"FreeHandle",	(uintptr_t)_ii_free_handle,	0,
	"AllocBuf",	(uintptr_t)_ii_alloc_buf,	0,
	"FreeBuf",	(uintptr_t)_ii_free_buf,	0,
	"GetPinned",	(uintptr_t)_ii_get_pinned,	0,
	"Discard",	(uintptr_t)_ii_discard_pinned,	0,
	"PartSize",	(uintptr_t)_ii_partsize,	0,
	"MaxFbas",	(uintptr_t)_ii_maxfbas,	0,
	"Read",		(uintptr_t)_ii_read,		0,
	"Write",	(uintptr_t)_ii_write,		0,
	"Zero",		(uintptr_t)_ii_zero,		0,
	"Uncommit",	(uintptr_t)_ii_uncommit,	0,
	"TrackSize",	(uintptr_t)_ii_trksize,	0,
	"Provide",	0,				0,
	0,		0,				0
};
