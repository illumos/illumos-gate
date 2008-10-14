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

#ifndef	_SV_IMPL_H
#define	_SV_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Storage Volume Character and Block Driver (SV)
 * Private header file.
 */

#if defined(_KERNEL)

/*
 * Locking.
 * Define SV_SLEEP_LOCK to get full sleep lock semantics (ie. mutex not
 * held across calls to sdctl functions.
 *
 * #define SV_SLEEP_LOCK
 */


/*
 * Misc defines, enums.
 */

enum { SV_DISABLE = 0, SV_PENDING, SV_ENABLE };


/*
 * Guard device clients
 */

typedef int64_t sv_gid_t;		/* bitmask */

typedef struct sv_gclient_s {
	struct sv_gclient_s *sg_next;	/* linked list */
	char		*sg_name;	/* name of client */
	sv_gid_t	sg_id;		/* id (bitmask) of client */
} sv_gclient_t;


/*
 * Hashing.
 *
 * SV_MAJOR_HASH_CNT & SV_MINOR_HASH_CNT should be prime.
 *
 * In a given system, there is likely to be one or two major devices in use.
 *
 * Examples are:
 *	SD	- Direct Attached Storage (SCSI-2/3)
 *	SSD	- SAN Direct Attached Storage FC SCSI-2/3
 *	SVM	- Solaris Volume Manager
 *	VxVM	- Veritas Volume Manager
 *	Global	- Sun Cluster  Global Devices
 *
 * For a typical system, there may be a 10s to 100s of minor devices configured
 * per major device, but most are likely to be configured under a single major
 * number. SV_MINOR_HASH_CNT has been chosen to ensure that the hash chains are
 * not too long (one or two devices), for the worst case.
 */

#define	SV_MAJOR_HASH_CNT	3	/* # hash buckets per system */
#define	SV_MAJOR_HASH(min)	((min) % SV_MAJOR_HASH_CNT)

#define	SV_MINOR_HASH_CNT	37	/* # hash buckets per major */
#define	SV_MINOR_HASH(min)	((min) % SV_MINOR_HASH_CNT)

/*
 * Per major device structure.
 *
 */

typedef struct sv_maj_s {
	struct dev_ops	*sm_dev_ops;
	int		(*sm_strategy)();
	int		(*sm_awrite)();
	int		(*sm_write)();
	int		(*sm_ioctl)();
	int		(*sm_close)();
	int		(*sm_aread)();
	int		(*sm_read)();
	int		(*sm_open)();
	major_t		sm_major;			/* Major device # */
	int		sm_flag;
	volatile int	sm_inuse;
	volatile int	sm_seq;
	struct sv_dev_s	*sm_hash[SV_MINOR_HASH_CNT];	/* Minor Hash Table */
	struct sv_maj_s *sm_next;			/* Major Hash Chain */
} sv_maj_t;

/*
 * Per configured sv structure.
 */

typedef struct sv_dev_s {
	struct sv_dev_s	*sv_hash;	/* Minor hash chain */
	krwlock_t	sv_lock;	/* mutual exclusion */
	kmutex_t	sv_olock;	/* mutual exclusion for otyp flags */
	dev_t		sv_dev;		/* underlying dev_t */
	nsc_fd_t	*sv_fd;		/* underlying fd */
	nsc_size_t	sv_maxfbas;	/* maxfbas accepted by I/O module */
	nsc_size_t	sv_nblocks;	/* size of device */
	int		sv_state;	/* state */
	int		sv_flag;	/* internal flags */
	sv_gid_t	sv_gclients;	/* bitmask of all guard clients */
	sv_gid_t	sv_gkernel;	/* bitmask of kernel guard clients */
	int		sv_openlcnt;	/* # of OTYP_LYR opens whilst failed */
	clock_t		sv_timestamp;	/* time of successful {en,dis}able */
	ldi_handle_t	sv_lh;		/* layered open handle */
	void		*sv_pending;	/* the thread setting SV_PENDING */
} sv_dev_t;

/*
 * private functions exported from nskern to sv.
 */
extern int nskern_partition(dev_t, int *);
extern int nskernd_isdaemon(void);

#endif  /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SV_IMPL_H */
