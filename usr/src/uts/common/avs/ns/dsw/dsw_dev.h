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

#ifndef	_DSW_DEV_H
#define	_DSW_DEV_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions for kstats
 */
#define	DSW_SKSTAT_SIZE			"size"
#define	DSW_SKSTAT_MTIME		"latest modified time"
#define	DSW_SKSTAT_FLAGS		"flags"
#define	DSW_SKSTAT_THROTTLE_UNIT	"ii_throttle_unit"
#define	DSW_SKSTAT_THROTTLE_DELAY	"ii_throttle_delay"
#define	DSW_SKSTAT_SHDCHKS		"shdchks"
#define	DSW_SKSTAT_SHDCHKUSED		"shdchkused"
#define	DSW_SKSTAT_SHDBITS		"shdbits"
#define	DSW_SKSTAT_COPYBITS		"copybits"
#define	DSW_SKSTAT_MSTA			"mst-a"
#define	DSW_SKSTAT_MSTB			"mst-b"
#define	DSW_SKSTAT_MSTC			"mst-c"
#define	DSW_SKSTAT_MSTD			"mst-d"
#define	DSW_SKSTAT_SETA			"set-a"
#define	DSW_SKSTAT_SETB			"set-b"
#define	DSW_SKSTAT_SETC			"set-c"
#define	DSW_SKSTAT_SETD			"set-d"
#define	DSW_SKSTAT_BMPA			"bmp-a"
#define	DSW_SKSTAT_BMPB			"bmp-b"
#define	DSW_SKSTAT_BMPC			"bmp-c"
#define	DSW_SKSTAT_BMPD			"bmp-d"
#define	DSW_SKSTAT_OVRA			"ovr-a"
#define	DSW_SKSTAT_OVRB			"ovr-b"
#define	DSW_SKSTAT_OVRC			"ovr-c"
#define	DSW_SKSTAT_OVRD			"ovr-d"
#define	DSW_SKSTAT_MSTIO		"mst-io"
#define	DSW_SKSTAT_SHDIO		"shd-io"
#define	DSW_SKSTAT_BMPIO		"bmp-io"
#define	DSW_SKSTAT_OVRIO		"ovr-io"

/*
 * Bitmap macros
 */

#define	DSW_BIT_CLR(bmap, bit)		(bmap &= (char)~(1 << bit))
#define	DSW_BIT_SET(bmap, bit)		(bmap |= (char)(1 << bit))
#define	DSW_BIT_ISSET(bmap, bit)	((bmap & (1 << bit)) != 0)

#define	DSW_CBLK_FBA		16		/* cache blocks in fba's */
#define	DSW_SHD_BM_OFFSET	DSW_CBLK_FBA	/* offset to allow for header */
#define	DSW_COPY_BM_OFFSET	(DSW_SHD_BM_OFFSET + \
					DSW_BM_FBA_LEN(ip->bi_size))
#define	DSW_BM_FBA_LEN(mst_size)  ((mst_size) / FBA_SIZE(DSW_SIZE*DSW_BITS) + \
					DSW_CBLK_FBA)

#define	DSW_BM_SIZE_CHUNKS(ip)	((ip->bi_size + DSW_SIZE - 1) / DSW_SIZE)
#define	DSW_BM_SIZE_BYTES(ip)	((DSW_BM_SIZE_CHUNKS(ip) + DSW_BITS - 1) /  \
					DSW_BITS)

#define	DSW_CHK2FBA(chunk)		(((nsc_off_t)(chunk)) * DSW_SIZE)

#if defined(_KERNEL) || defined(_KMEMUSER)

/*
 * Shadow types.
 */

#define	DSW_GOLDEN_TYPE	0x1000
#define	DSW_QUICK_TYPE	0x2000

/*
 * Miscellaneous defines
 */

#define	II_INTERNAL	0x1
#define	II_EXTERNAL	0x2

#define	II_EXISTING	0x01	/* Internal dsw_ioctl()/dsw_config() flags */
#define	II_IMPORT	0x02

/*
 * defines for _ii_nsc_io and _ii_write, used by kstats
 */

#define	KS_NA	0
#define	KS_MST	1
#define	KS_SHD	2
#define	KS_BMP	3
#define	KS_OVR	4

/*
 * global kstats
 */

typedef struct _iigkstat_s {
	/* static */
	kstat_named_t ii_debug;
	kstat_named_t ii_bitmap;
	kstat_named_t ii_throttle_unit;
	kstat_named_t ii_throttle_delay;
	kstat_named_t ii_copy_direct;

	/* dynamic */
	kstat_named_t num_sets;
	kstat_named_t assoc_over;
	kstat_named_t spilled_over;
} iigkstat_t;

extern iigkstat_t iigkstat;

/*
 * set-specific kstats
 */
typedef struct _ii_kstat_set_s {
	kstat_named_t size;		/* from _ii_stat() */
	kstat_named_t mtime;		/* from _ii_stat() */
	kstat_named_t flags;		/* from _ii_stat() */
	kstat_named_t unit;		/* ii_throttle_unit */
	kstat_named_t delay;		/* ii_throttle_delay */
	kstat_named_t shdchks;		/* from _ii_stat() */
	kstat_named_t shdchkused;	/* from _ii_stat() */
	kstat_named_t shdbits;		/* # bits set shadow bitmap */
	kstat_named_t copybits;		/* # bits set copy bitmap */
	kstat_named_t mst_a;		/* name		*/
	kstat_named_t mst_b;		/* .. of	*/
	kstat_named_t mst_c;		/* .. master	*/
	kstat_named_t mst_d;		/* .. volume	*/
	kstat_named_t set_a;		/* name		*/
	kstat_named_t set_b;		/* .. of	*/
	kstat_named_t set_c;		/* .. the	*/
	kstat_named_t set_d;		/* .. set	*/
	kstat_named_t bmp_a;		/* name		*/
	kstat_named_t bmp_b;		/* .. of	*/
	kstat_named_t bmp_c;		/* .. bitmap	*/
	kstat_named_t bmp_d;		/* .. volume	*/
	kstat_named_t ovr_a;		/* name		*/
	kstat_named_t ovr_b;		/* .. of	*/
	kstat_named_t ovr_c;		/* .. overflow	*/
	kstat_named_t ovr_d;		/* .. volume	*/
	kstat_named_t mst_io;		/* kstat_io of master */
	kstat_named_t shd_io;		/* kstat_io of shadow */
	kstat_named_t bmp_io;		/* kstat_io of bitmap */
	kstat_named_t ovr_io;		/* kstat_io of overflow */
} ii_kstat_set_t;

extern ii_kstat_set_t ii_kstat_set;
#define	IOSTAT_NAME_LEN 10

/* Basic types */
#ifdef II_MULTIMULTI_TERABYTE
typedef	int64_t	chunkid_t;
typedef	int32_t	chunkid32_t;
#else
typedef	int32_t	chunkid_t;
#endif

/*
 * OV_HEADER_VERSION
 *      0 = original OV header version
 *      1 = flags support
 */
#define	OV_HEADER_VERSION	1

/* Overflow disk volume header */
typedef	struct	_ii_doverflow_s {
	char	ii_dvolname[DSW_NAMELEN];	/* this volumes name */
	uint32_t	ii_dhmagic;		/* sanity check */
	uint32_t	ii_dhversion;		/* volume format */
	int32_t		ii_ddrefcnt;		/* total number of users */
	int32_t		ii_dflags;		/* status flags */
	int64_t		ii_dfreehead;		/* chain of freed chunks */
	int64_t		ii_dnchunks;		/* total number of chunks */
	int64_t		ii_dunused;		/* number of chunks available */
	int64_t		ii_dused;		/* number of chunks allocated */
	int32_t		ii_urefcnt;		/* # shadows needing update */
	int32_t		ii_dcrefcnt;		/* current number of users */
} _ii_doverflow_t;

/* Overflow volume in core structure */
typedef	struct	_ii_overflow_s {
	_ii_doverflow_t	ii_do;
	kmutex_t		ii_mutex;	/* Mutex */
	kmutex_t		ii_kstat_mutex;	/* Mutex for overflow kstat */
	int	ii_detachcnt;			/* users detaching on disable */
	struct	_ii_overflow_s *ii_next;	/* chain of incore structs */
	struct	_ii_info_dev_s *ii_dev;		/* pointer to device details */
	kstat_t		*ii_overflow;		/* kstats data for this vol */
	char	ii_ioname[KSTAT_DATA_CHAR_LEN];	/* name for iostat -x */
} _ii_overflow_t;

#define	ii_volname	ii_do.ii_dvolname
#define	ii_hmagic	ii_do.ii_dhmagic
#define	ii_drefcnt	ii_do.ii_ddrefcnt
#define	ii_freehead	ii_do.ii_dfreehead
#define	ii_nchunks	ii_do.ii_dnchunks
#define	ii_unused	ii_do.ii_dunused
#define	ii_used		ii_do.ii_dused
#define	ii_hversion	ii_do.ii_dhversion
#define	ii_flags	ii_do.ii_dflags
#define	ii_urefcnt	ii_do.ii_urefcnt
#define	ii_crefcnt	ii_do.ii_dcrefcnt

#define	II_OHEADER_FBA	0			/* overflow header location */
/*
 * logging of kstat_io
 */
#ifdef DISABLE_KSTATS
#define	II_READ_START(ip, type)
#define	II_READ_END(ip, type, rc, blocks)
#define	II_WRITE_START(ip, type)
#define	II_WRITE_END(ip, type, rc, blocks)
#else

#define	II_KS(ip, x) KSTAT_IO_PTR(ip->bi_kstat_io.x)
#define	II_MUTEX(ip, x) ip->bi_kstat_io.x->ks_lock
#define	II_BLKSIZE 512

#define	II_READ_START(ip, type)						\
	if (ip->bi_kstat_io.type) {					\
		mutex_enter(II_MUTEX(ip, type));			\
		kstat_runq_enter(II_KS(ip, type));			\
		mutex_exit(II_MUTEX(ip, type));				\
	}
#define	II_READ_END(ip, type, rc, blocks)				\
	if (ip->bi_kstat_io.type) {					\
		mutex_enter(II_MUTEX(ip, type));			\
		if (II_SUCCESS(rc)) {					\
			II_KS(ip, type)->reads++;			\
			II_KS(ip, type)->nread += II_BLKSIZE * (blocks);\
		}							\
		kstat_runq_exit(II_KS(ip, type));			\
		mutex_exit(II_MUTEX(ip, type));				\
	}

#define	II_WRITE_START(ip, type)					\
	if (ip->bi_kstat_io.type) {					\
		mutex_enter(II_MUTEX(ip, type));			\
		kstat_runq_enter(II_KS(ip, type));			\
		mutex_exit(II_MUTEX(ip, type));				\
	}
#define	II_WRITE_END(ip, type, rc, blocks)				\
	if (ip->bi_kstat_io.type) {					\
		mutex_enter(II_MUTEX(ip, type));			\
		if (II_SUCCESS(rc)) {					\
			II_KS(ip, type)->writes++;			\
			II_KS(ip, type)->nwritten += II_BLKSIZE * (blocks);\
		}							\
		kstat_runq_exit(II_KS(ip, type));			\
		mutex_exit(II_MUTEX(ip, type));				\
	}
#endif

#define	II_NSC_READ(ip, type, rc, buf, pos, len, flag)			\
		II_READ_START(ip, type);				\
		rc = nsc_read(buf, pos, len, flag);			\
		II_READ_END(ip, type, rc, len);

#define	II_NSC_WRITE(ip, type, rc, buf, pos, len, flag)			\
		II_WRITE_START(ip, type);				\
		rc = nsc_write(buf, pos, len, flag);			\
		II_WRITE_END(ip, type, rc, len);

#define	II_NSC_COPY_DIRECT(ip, t1, t2, rc, buf1, buf2, pos1, pos2, len)	\
		II_WRITE_START(ip, t2);					\
		rc = nsc_copy_direct(buf1, buf2, pos1, pos2, len);	\
		II_WRITE_END(ip, t2, rc, len);

#define	II_ALLOC_BUF(ip, type, rc, fd, pos, len, flag, tmp)		\
	if (flag & NSC_READ) {						\
		II_READ_START(ip, type);				\
	}								\
	rc = nsc_alloc_buf(fd, pos, len, flag, tmp);			\
	if (flag & NSC_READ) {						\
		II_READ_END(ip, type, rc, len);				\
	}

/*
 * All kstat_io associated with a set.  NOTE: only one mutex for all
 * of the kstats for a given set; all master/shadow/bmp/overflow mutexes
 * point back to the statmutex
 */

typedef struct _ii_kstat_info_s {
	kstat_t		*master;
	kstat_t		*shadow;
	kstat_t		*bitmap;
	kstat_t		*overflow;
	kmutex_t	statmutex;
	char	mstio[KSTAT_DATA_CHAR_LEN];	/* name of mst in iostat -x */
	char	shdio[KSTAT_DATA_CHAR_LEN];	/* name of shd in iostat -x */
	char	bmpio[KSTAT_DATA_CHAR_LEN];	/* name of bmp in iostat -x */
	char	ovrio[KSTAT_DATA_CHAR_LEN];	/* name of ovr in iostat -x */
} ii_kstat_info_t;

/*
 * II device info structure
 */

typedef struct _ii_info_dev_s {
	nsc_fd_t		*bi_fd;		/* Bitmap file descriptor */
	nsc_iodev_t		*bi_iodev;	/* I/O device structure */
	nsc_path_t		*bi_tok;	/* Register path token */
	int			bi_ref;		/* Count of fd's referencing */
	int			bi_rsrv;	/* Count of reserves held */
	int			bi_orsrv;	/* Reserves for other io prov */
	int			bi_flag;	/* Internal/External reserve */
} _ii_info_dev_t;

typedef struct _ii_info_s {
	struct _ii_info_s	*bi_next;	/* Chain of all groups */
	struct _ii_info_s	*bi_head;	/* head of sibling chain */
	struct _ii_info_s	*bi_sibling;	/* Chain of groups with same */
							/* master */
	struct _ii_info_s	*bi_master;	/* location of master */
	struct _ii_info_s	*bi_nextmst;	/* next multimaster */
	kmutex_t		bi_mutex;	/* Mutex */
	_ii_info_dev_t		*bi_mstdev;
	_ii_info_dev_t		*bi_mstrdev;
	_ii_info_dev_t		bi_shddev;
	_ii_info_dev_t		bi_shdrdev;
	_ii_info_dev_t		bi_bmpdev;
	char			bi_keyname[DSW_NAMELEN];
	unsigned char		*bi_bitmap;	/* Master device bitmap */
	char			*bi_cluster;	/* cluster name */
	char			*bi_group;	/* group name */
	char			*bi_busy;	/* Busy bitmap */
	nsc_off_t		bi_shdfba;	/* location of shadow bitmap */
	nsc_size_t		bi_shdbits;	/* shadow bitmap counter */
	nsc_off_t		bi_copyfba;	/* location of copy bitmap */
	nsc_size_t		bi_copybits;	/* copy bitmap counter */
	nsc_size_t		bi_size;	/* Size of mst device */
	uint_t			bi_flags;	/* Flags */
	uint_t			bi_state;	/* State flags */
	int			bi_disabled;	/* Disable has started */
	int			bi_ioctl;	/* Number of active ioctls */
	int			bi_release;	/* Do a release in copyvol */
	int			bi_rsrvcnt;	/* reserve count */
	kcondvar_t		bi_copydonecv;	/* Copy operation condvar */
	kcondvar_t		bi_reservecv;	/* Reserve condvar */
	kcondvar_t		bi_releasecv;	/* Release condvar */
	kcondvar_t		bi_closingcv;	/* Shadow closing condvar */
	kcondvar_t		bi_ioctlcv;	/* Ioctls complete condvar */
	kcondvar_t		bi_busycv;	/* Busy bitmap condvar */
	krwlock_t		bi_busyrw;	/* Busy bitmap rwlock */
	struct _ii_bmp_ops_s	*bi_bitmap_ops;	/* Functions for bitmap ops */
	kmutex_t		bi_rsrvmutex;	/* Reserve operation mutex */
	kmutex_t		bi_rlsemutex;	/* Release operation mutex */
	kmutex_t		bi_bmpmutex;	/* mutex for bi_bitmap_ops */
	chunkid_t		bi_mstchks;
	chunkid_t		bi_shdchks;	/* # of chunks on shadow vol */
	chunkid_t		bi_shdchkused;	/* # of allocated */
	chunkid_t		bi_shdfchk;	/* start of shd chunk flst */
	_ii_overflow_t		*bi_overflow;
	struct ii_fd_s		*bi_iifd;	/* fd holding master's ip */
	int32_t			bi_throttle_unit;
	int32_t			bi_throttle_delay;
	krwlock_t		bi_linkrw;	/* altering linkage rwlock */
	kmutex_t		bi_chksmutex;	/* Mutex for bi_???chks */
	pid_t			bi_locked_pid;	/* lock pid for update/copy */
	kstat_t			*bi_kstat;	/* kstat data for set */
	ii_kstat_info_t		bi_kstat_io;	/* kstat I/O data for set */
	time_t			bi_mtime;
} _ii_info_t;

#define	bi_bmpfd	bi_bmpdev.bi_fd
#define	bi_mstfd	bi_mstdev->bi_fd
#define	bi_mstrfd	bi_mstrdev->bi_fd
#define	bi_shdfd	bi_shddev.bi_fd
#define	bi_shdrfd	bi_shdrdev.bi_fd
#define	bi_mst_iodev	bi_mstdev->bi_iodev
#define	bi_mstr_iodev	bi_mstrdev->bi_iodev
#define	bi_shd_iodev	bi_shddev.bi_iodev
#define	bi_shdr_iodev	bi_shdrdev.bi_iodev
#define	bi_bmp_iodev	bi_bmpdev.bi_iodev
#define	bi_mst_tok	bi_mstdev->bi_tok
#define	bi_mstr_tok	bi_mstrdev->bi_tok
#define	bi_shd_tok	bi_shddev.bi_tok
#define	bi_shdr_tok	bi_shdrdev.bi_tok
#define	bi_bmp_tok	bi_bmpdev.bi_tok
#define	bi_mstref	bi_mstdev->bi_ref
#define	bi_mstrref	bi_mstrdev->bi_ref
#define	bi_shdref	bi_shddev.bi_ref
#define	bi_shdrref	bi_shdrdev.bi_ref
#define	bi_bmpref	bi_bmpdev.bi_ref
#define	bi_mstrsrv	bi_mstdev->bi_rsrv
#define	bi_mstrrsrv	bi_mstrdev->bi_rsrv
#define	bi_shdrsrv	bi_shddev.bi_rsrv
#define	bi_shdrrsrv	bi_shdrdev.bi_rsrv
#define	bi_bmprsrv	bi_bmpdev.bi_rsrv
#define	bi_mstrflag	bi_mstrdev->bi_flag
#define	bi_shdrflag	bi_shdrdev.bi_flag
/*
 * Cluster and group linked lists
 */
typedef struct _ii_lstinfo_s {
	_ii_info_t		*lst_ip;	/* ptr to info_t */
	struct _ii_lstinfo_s	*lst_next;	/* ptr to next in chain */
} _ii_lstinfo_t;

typedef struct _ii_lsthead_s {
	uint64_t	lst_hash;		/* from nsc_strhash */
	char		lst_name[DSW_NAMELEN];	/* resource group */
	_ii_lstinfo_t	*lst_start;		/* start of set list */
	struct _ii_lsthead_s *lst_next;		/* next list head */
} _ii_lsthead_t;

/*
 * Flag set and clear macros and function.
 */

void _ii_flag_op(int and, int or, _ii_info_t *ip, int update);

#define	II_FLAG_SET(f, ip)		_ii_flag_op(~0, (f), ip, TRUE)
#define	II_FLAG_CLR(f, ip)		_ii_flag_op(~(f), 0, ip, TRUE)

#define	II_FLAG_SETX(f, ip)		_ii_flag_op(~0, (f), ip, FALSE)
#define	II_FLAG_CLRX(f, ip)		_ii_flag_op(~(f), 0, ip, FALSE)
#define	II_FLAG_ASSIGN(f, ip)		_ii_flag_op(0, (f), ip, FALSE);
#define	LOG_EVENT(msg, level)		\
		nsc_do_sysevent("ii", msg, level, level, component, ii_dip);

/* Reserve and release macros */

	/* also used by ii_volume() volume identification, hence NONE & OVR */
#define	NONE	0x0000			/* no volume type */
#define	MST	0x0001			/* master reserve/release flag */
#define	MSTR	0x0010			/* raw master reserve/release flag */
#define	SHD	0x0002			/* shadow reserve/release flag */
#define	SHDR	0x0020			/* raw shadow reserve/release flag */
#define	BMP	0x0100			/* bitmap reserve/release flag */
#define	OVR	0x0400			/* overflow volume */

#define	RSRV(ip)	((ip)->bi_rsrv > 0 || (ip)->bi_orsrv > 0)

#define	MSTRSRV(ip)	(RSRV(((ip)->bi_mstdev)))
#define	SHDRSRV(ip)	(RSRV(&((ip)->bi_shddev)))

#define	MSTFD(ip)	(MSTRSRV(ip) ? (ip)->bi_mstfd : (ip)->bi_mstrfd)
#define	SHDFD(ip)	(SHDRSRV(ip) ? (ip)->bi_shdfd : (ip)->bi_shdrfd)
#define	OVRFD(ip)	(ip->bi_overflow->ii_dev->bi_fd)

#define	II_RAW(ii)	(((ii)->ii_oflags&NSC_DEVICE) != 0)
#define	II_FD(ii)	((ii)->ii_shd ? SHDFD((ii)->ii_info) : \
					MSTFD((ii)->ii_info))

			/* are there multiple shadows of ip's master volume? */
#define	NSHADOWS(ip)	((ip)->bi_head != (ip) || (ip)->bi_sibling)

typedef	struct _ii_bmp_ops_s {
	int	(*co_bmp)(_ii_info_t *, nsc_off_t, unsigned char *, int);
	int	(*ci_bmp)(_ii_info_t *, nsc_off_t, unsigned char *, int);
	int	(*zerobm)(_ii_info_t *);
	int	(*copybm)(_ii_info_t *);
	int	(*orbm)(_ii_info_t *);
	int	(*tst_shd_bit)(_ii_info_t *, chunkid_t);
	int	(*set_shd_bit)(_ii_info_t *, chunkid_t);
	int	(*tst_copy_bit)(_ii_info_t *, chunkid_t);
	int	(*set_copy_bit)(_ii_info_t *, chunkid_t);
	int	(*clr_copy_bits)(_ii_info_t *, chunkid_t, int);
	chunkid_t	(*next_copy_bit)(_ii_info_t *, chunkid_t, chunkid_t,
						int, int *);
	int	(*fill_copy_bmp)(_ii_info_t *);
	int	(*load_bmp)(_ii_info_t *, int);
	int	(*save_bmp)(_ii_info_t *, int);
	int	(*change_bmp)(_ii_info_t *, unsigned char *);
	int	(*cnt_bits)(_ii_info_t *, nsc_off_t, nsc_size_t *, int);
	int	(*join_bmp)(_ii_info_t *, _ii_info_t *);
} _ii_bmp_ops_t;

#define	II_CO_BMP(ip, a, b, c)	(*(ip)->bi_bitmap_ops->co_bmp)(ip, a, b, c)
#define	II_CI_BMP(ip, a, b, c)	(*(ip)->bi_bitmap_ops->ci_bmp)(ip, a, b, c)
#define	II_ZEROBM(ip)		(*(ip)->bi_bitmap_ops->zerobm)(ip)
#define	II_COPYBM(ip)		(*(ip)->bi_bitmap_ops->copybm)(ip)
#define	II_ORBM(ip)		(*(ip)->bi_bitmap_ops->orbm)(ip)
#define	II_TST_SHD_BIT(ip, c)	(*(ip)->bi_bitmap_ops->tst_shd_bit)(ip, c)
#define	II_SET_SHD_BIT(ip, c)	(*(ip)->bi_bitmap_ops->set_shd_bit)(ip, c)
#define	II_TST_COPY_BIT(ip, c)	(*(ip)->bi_bitmap_ops->tst_copy_bit)(ip, c)
#define	II_SET_COPY_BIT(ip, c)	(*(ip)->bi_bitmap_ops->set_copy_bit)(ip, c)
#define	II_CLR_COPY_BITS(ip, c, n)	(*(ip)->bi_bitmap_ops->clr_copy_bits) \
						(ip, c, n)
#define	II_CLR_COPY_BIT(ip, c)	(*(ip)->bi_bitmap_ops->clr_copy_bits)(ip, c, 1)
#define	II_NEXT_COPY_BIT(ip, c, m, w, g)	\
			(*(ip)->bi_bitmap_ops->next_copy_bit)(ip, c, m, w, g)
#define	II_FILL_COPY_BMP(ip)	(*(ip)->bi_bitmap_ops->fill_copy_bmp)(ip)
#define	II_LOAD_BMP(ip, f)	(*(ip)->bi_bitmap_ops->load_bmp)(ip, f)
#define	II_SAVE_BMP(ip, f)	(*(ip)->bi_bitmap_ops->save_bmp)(ip, f)
#define	II_CHANGE_BMP(ip, p)	(*(ip)->bi_bitmap_ops->change_bmp)(ip, p)
#define	II_CNT_BITS(ip, a, b, c) (*(ip)->bi_bitmap_ops->cnt_bits)(ip, a, b, c)
#define	II_JOIN_BMP(dip, sip) (*(ip)->bi_bitmap_ops->join_bmp)(dip, sip)

/*
 * State flags
 */
#define	DSW_IOCTL	0x0001		/* Waiting for ioctl to complete */
#define	DSW_CLOSING	0x0002		/* Waiting for shadow to close */
#define	DSW_MSTTARGET	0x0004		/* Master is target of update */
#define	DSW_MULTIMST	0x0008		/* disabled set is multi master */
#define	DSW_CNTSHDBITS	0x0010		/* need to count # of shd bits set */
#define	DSW_CNTCPYBITS	0x0020		/* need to count # of copy bits set */

/*
 * DSW file descriptor structure
 */

typedef struct ii_fd_s {
	_ii_info_t	*ii_info;	/* Info structure */
	int		ii_bmp;		/* This fd is for the bmp device */
	int		ii_shd;		/* This fd is for the shadow device */
	int		ii_ovr;		/* This fd is for the overflow device */
	_ii_overflow_t	*ii_optr;	/* pointer to overflow structure */
	int		ii_oflags;	/* raw or cached open type */
} ii_fd_t;


/*
 * II buffer header
 */

typedef struct ii_buf_s {
	nsc_buf_t	ii_bufh;	/* exported buffer header */
	nsc_buf_t	*ii_bufp;	/* main underlying buffer */
	nsc_buf_t	*ii_bufp2;	/* second underlying buffer */
	nsc_buf_t	*ii_abufp;	/* anonymous underlying buffer */
	ii_fd_t		*ii_fd;		/* back link */
	int		ii_rsrv;	/* fd to release in free_buf */
} ii_buf_t;
#endif	/* _KERNEL || _KMEMUSER */


/*
 * Valid magic numbers in the bitmap volume header
 */

#define	DSW_DIRTY	0x44495254
#define	DSW_CLEAN	0x434C4541
#define	DSW_INVALID	0x00000000

/*
 * II_HEADER_VERSION
 *	1 = original II header version
 *	2 = Compact Dependent Shadows (DSW_TREEMAP)
 *	3 = Persistance of throttle parameters
 *	4 = add cluster & group information
 *	5 = add time string to hold last modify time
 */
#define	II_HEADER_VERSION	5

/*
 * DSW bitmap volume header structure
 */

typedef struct ii_header_s {
	int32_t	ii_magic;	/* magic number */
	int32_t	ii_type;	/* bitmap or independent copy */
	int32_t	ii_state;	/* State of the master/shadow/bitmap tuple */
	int32_t	ii_version;	/* version or format of bitmap volume */
	int32_t	ii_shdfba;	/* location of shadow bitmap */
	int32_t	ii_copyfba;	/* location of copy bitmap */
	char	master_vol[DSW_NAMELEN];
	char	shadow_vol[DSW_NAMELEN];
	char	bitmap_vol[DSW_NAMELEN];
	/* II_HEADER_VERSION 2 */
	char	overflow_vol[DSW_NAMELEN];
	int64_t	ii_mstchks;	/* # of chunks in master volume */
	int64_t	ii_shdchks;	/* # of chunks in shadow volume */
	int64_t	ii_shdchkused;	/* # of shd chunks allocated or on free list */
	int64_t	ii_shdfchk;	/* list of free shadow chunks */
	/* II_HEADER_VERSION 3 */
	int32_t	ii_throttle_unit;  /* Last setting of throttle unit */
	int32_t ii_throttle_delay; /* Last setting of throttle delay */
	/* II_HEADER_VERSION 4 */
	char	clstr_name[DSW_NAMELEN];
	char	group_name[DSW_NAMELEN];
	/* II_HEADER_VERSION 5 */
	time_t ii_mtime;
} ii_header_t;

#define	II_SUCCESS(rc)	(((rc) == NSC_DONE) || ((rc) == NSC_HIT))

/*
 * Overflow volume defines.
 */

#define	II_OMAGIC		0x476F6C64		/* "Gold" */
#define	II_ISOVERFLOW(n)	((n) < 0 && (n) != II_NULLCHUNK)
#define	II_2OVERFLOW(n)		(-(n))
				/* -tive node id's are in overflow volume */

#ifdef	_SunOS_5_6
#define	II_NULLNODE		(INT_MIN)
#define	II_NULLCHUNK		(INT_MIN)
#else
#ifdef II_MULTIMULTI_TERABYTE
#define	II_NULLNODE		(INT64_MIN)
#define	II_NULLCHUNK		(INT64_MIN)
#define	II_NULL32NODE		(INT32_MIN)
#define	II_NULL32CHUNK		(INT32_MIN)
#else
#define	II_NULLNODE		(INT32_MIN)
#define	II_NULLCHUNK		(INT32_MIN)
#endif /* II_MULTIMULTI_TERABYTE */
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _DSW_DEV_H */
