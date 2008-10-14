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

#ifndef	_RDC_IOCTL_H
#define	_RDC_IOCTL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/unistat/spcs_s.h>
#include <sys/nsctl/nsctl.h>
#ifndef DS_DDICT
#include <rpc/rpc.h>
#endif

#ifdef _SunOS_5_6
#define	netbuf32 netbuf
#include <sys/nsctl/model.h>
#endif

typedef struct _rdc_ioctl_s {
	long arg0;
	long arg1;
	long arg2;
	long arg3;
	long arg4;
	long magic;
	spcs_s_info_t ustatus;
	long pad[1];
} _rdc_ioctl_t;

#ifdef _SYSCALL32
typedef struct _rdc_ioctl32_s {
	int32_t arg0;
	int32_t arg1;
	int32_t arg2;
	int32_t arg3;
	int32_t arg4;
	int32_t magic;
	spcs_s_info32_t ustatus;
	int32_t pad[1];
} _rdc_ioctl32_t;
#endif /* _SYSCALL32 */

/*
 * Ioctl command numbers
 */

#define	_RDCI_(x)	(('R'<<16)|('D'<<8)|(x))

/*
 * Generic rdc ioctl arguments structure.
 * Individual ioctl's will use 0-n of these arguments.
 *
 * Each rdc ioctl is described first by the command number
 * e.g. #define	RDC_CONFIG		_RDCI_(0)
 *
 * Followed by a description of each argument (if any).
 * Each argument is on a single line.
 *
 */

#define	RDC_CONFIG		_RDCI_(0)
/*
 *	rdc_config_t	*user_configuration;
 */

#define	RDC_ENABLE_SVR		_RDCI_(1)
/*
 *	rdc_svc_args_t	*daemon_configuration;
 */

#define	RDC_STATUS		_RDCI_(2)
/*
 *	rdc_status_t	*rdc_status;
 */

#define	RDC_VERSION		_RDCI_(3)
/*
 *	rdc_version_t	*rdc_version;
 */

#define	RDC_LINK_DOWN		_RDCI_(4)
/*
 *	char 		*rdc_host;
 */

#define	RDC_SYNC_EVENT		_RDCI_(5)
/*
 *	char		*rdc_master;
 *	char		*rdc_group;
 */

#define	RDC_POOL_CREATE		_RDCI_(6)
/*
 * struct svcpool_args *
 */

#define	RDC_POOL_WAIT		_RDCI_(7)
/*
 * int id
 */

#define	RDC_POOL_RUN		_RDCI_(8)
/*
 * int id
 */
#define	RDC_BITMAPOP		_RDCI_(9)

#ifdef	DEBUG
#define	RDC_ASYNC6		_RDCI_(20)	/* send async message by hand */
#define	RDC_CLRKSTAT		_RDCI_(21)	/* clear kstat_io structure */
#define	RDC_STALL0		_RDCI_(22)	/* stall sequence 0 on server */
#define	RDC_READGEN		_RDCI_(23)	/* cause a read on server */
#endif


#define	MAX_RDC_HOST_SIZE	64

/*
 * Change this when the ioctl structure changes
 */
#define	RDC_MAGIC	0xf00d0001

typedef struct rdc_addr {
	struct netbuf addr;
	char intf[MAX_RDC_HOST_SIZE];
	char file[NSC_MAXPATH];
	char bitmap[NSC_MAXPATH];
} rdc_addr_t;

#ifdef _SYSCALL32
struct rdc_addr32 {
	struct netbuf32	addr;
	char intf[MAX_RDC_HOST_SIZE];
	char file[NSC_MAXPATH];
	char bitmap[NSC_MAXPATH];
};
#endif /* _SYSCALL32 */

/*
 * User level rdc set structure - must be a multiple of 64bits long.
 */
typedef struct rdc_set {
	rdc_addr_t primary;
	rdc_addr_t secondary;
	struct knetconfig *netconfig;
	long align1;
	double alignfix;
	int flags;				/* See RDC flags below */
	int sync_flags;				/* See RDC flags below */
	int bmap_flags;				/* See RDC flags below */
	int mflags;				/* RDC 1-to-many flags */
	int index;				/* 0 .. rdc_max_sets - 1 */
	int bits_set;				/* Bits set in bitmap */
	int autosync;				/* Autosync on (1) or off (0) */
	int syshostid;				/* for cluster integration */
	int asyncthr;				/* # of async threads */
	int setid;				/* unique set id for this set */
	uint64_t sync_pos;			/* Progress through sync */
	uint64_t volume_size;			/* Size of volume */
	int64_t maxqfbas;			/* max # of fbas on async q */
	int64_t maxqitems;			/* max # of items on async q */
	char group_name[NSC_MAXPATH];		/* Group the set belongs to */
	char direct_file[NSC_MAXPATH];		/* Local FCAL direct io file */
	char disk_queue[NSC_MAXPATH];	   /* Disk Queue for set|group */
} rdc_set_t;

#ifdef _SYSCALL32
struct rdc_set32 {
	struct rdc_addr32 primary;
	struct rdc_addr32 secondary;
	caddr32_t netconfig;
	int32_t align1;
	double alignfix;
	int32_t flags;				/* See RDC flags below */
	int32_t sync_flags;			/* See RDC flags below */
	int32_t bmap_flags;			/* See RDC flags below */
	int32_t mflags;				/* RDC 1-to-many flags */
	int32_t index;				/* 0 .. rdc_max_sets - 1 */
	int32_t bits_set;			/* Bits set in bitmap */
	int32_t autosync;			/* Autosync on (1) or off (0) */
	int32_t syshostid;			/* for cluster integration */
	int32_t asyncthr;			/* # of async threads */
	int32_t setid;				/* unique set id for this set */
	uint64_t sync_pos;			/* Progress through sync */
	uint64_t volume_size;			/* Size of volume */
	int64_t maxqfbas;			/* max # of fbas on async q */
	int64_t maxqitems;			/* max # of items on async q */
	char group_name[NSC_MAXPATH];		/* Group the set belongs to */
	char direct_file[NSC_MAXPATH];		/* Local FCAL direct io file */
	char disk_queue[NSC_MAXPATH];	   /* Disk Queue for set|group */
};
#endif /* _SYSCALL32 */

/*
 * Parameter structure to pass to RDC_CONFIG
 */

typedef struct rdc_config {
	int command;			/* RDC_CMD_XXX */
	int options;			/* RDC_OPT_XXX */
	int pad[2];			/* Do NOT remove - 32/64-bit padding */
	rdc_set_t rdc_set[1];		/* The rdc sets */
} rdc_config_t;

#ifdef _SYSCALL32
struct rdc_config32 {
	int32_t command;		/* RDC_CMD_XXX */
	int32_t options;		/* RDC_OPT_XXX */
	int32_t pad[2];			/* Do NOT remove - 32/64-bit padding */
	struct rdc_set32 rdc_set[1];	/* The rdc sets */
};
#endif /* _SYSCALL32 */

#define	RDC_BITMAPSET	0x01
#define	RDC_BITMAPOR	0x02
typedef struct rdc_bitmap_op {
	nsc_off_t	offset;		/* byte offset within bitmap mod fba */
	int32_t		op;		/* or/set operation */
	char		sechost[MAX_RDC_HOST_SIZE];
	char		secfile[NSC_MAXPATH];
	int32_t		len;		/* length of bitmap in bytes */
	unsigned long   addr;		/* address of bitmap in userland */
} rdc_bitmap_op_t;

#ifdef _SYSCALL32
typedef struct rdc_bitmap_op32 {
	nsc_off_t	offset;
	int32_t		op;
	char		sechost[MAX_RDC_HOST_SIZE];
	char		secfile[NSC_MAXPATH];
	int32_t		len;
	uint32_t	addr;
} rdc_bitmap_op32_t;

#endif /* _SYSCALL32 */

#ifdef	DEBUG
/*
 * structure to initiate an asynchronous send to the secondary,
 * so we can test the queuing code.
 */
typedef struct rdc_async6 {
	char sechost[MAX_RDC_HOST_SIZE];
	char secfile[NSC_MAXPATH];
	int  pos;		/* Position in file */
	int  len;
	int  seq;
	int  pat;		/* fill data with this */
	int  idx;		/* server returned index */
	int  spos;		/* sub task start block */
	int  slen;		/* sub task length */
	int  endind;		/* set when last block in multi request */
} rdc_async6_t;
/*
 * structure to initiate a read on the secondary, so we can test the
 * maxfba break up code.
 */
typedef struct rdc_readgen {
	char sechost[MAX_RDC_HOST_SIZE];
	char secfile[NSC_MAXPATH];
	int  len;
	int  pos;
	int  idx;
	int  flag;
	int  rpcversion;
	void *data;	/* where to place the data from the read */
} rdc_readgen_t;

#ifdef _SYSCALL32
typedef struct rdc_readgen32 {
	char sechost[MAX_RDC_HOST_SIZE];
	char secfile[NSC_MAXPATH];
	int  len;
	int  pos;
	int  idx;
	int  flag;
	int  rpcversion;
	caddr32_t data;	/* where to place the data from the read */
} rdc_readgen32_t;
#endif
#endif





/*
 * Config ioctl commands
 */
#define	RDC_CMD_ENABLE		1	/* New enable */
#define	RDC_CMD_DISABLE		2	/* Complete disable */
#define	RDC_CMD_RESUME		3	/* Local re-enable */
#define	RDC_CMD_SUSPEND		4	/* Local clear */
#define	RDC_CMD_LOG		5	/* Start logging mode */
#define	RDC_CMD_COPY		6	/* Start synching */
#define	RDC_CMD_RECONFIG	7	/* Change the rdc set */
#define	RDC_CMD_TUNABLE		8	/* Change a tunable parameter */
#define	RDC_CMD_WAIT		9	/* Wait for syncs to complete */
#define	RDC_CMD_HEALTH		10	/* Return health state */
#define	RDC_CMD_STATUS		11	/* Single set status */
#define	RDC_CMD_RESET		12	/* reset error or failed status */
#define	RDC_CMD_INITQ		14	/* initialise the disk queue */
#define	RDC_CMD_FLUSHQ		15	/* flush queue for set */
#define	RDC_CMD_ADDQ		16	/* add diskq to a set/group */
#define	RDC_CMD_REMQ		17 	/* nice remove a diskq from set/grp */
#define	RDC_CMD_KILLQ		18	/* forced disgard of queue */
#define	RDC_CMD_REPQ		19	/* replace queue */





/*
 * Config ioctl options
 */
#define	RDC_OPT_SYNC		0x1	/* RDC_CMD_ENABLE, RDC_CMD_RESUME */
#define	RDC_OPT_ASYNC		0x2	/* RDC_CMD_ENABLE, RDC_CMD_RESUME */
#define	RDC_OPT_PRIMARY		0x4	/* All */
#define	RDC_OPT_SECONDARY	0x8	/* All */
#define	RDC_OPT_FORWARD		0x10	/* RDC_CMD_COPY */
#define	RDC_OPT_REVERSE		0x20	/* RDC_CMD_COPY */
#define	RDC_OPT_FULL		0x40	/* RDC_CMD_COPY */
#define	RDC_OPT_UPDATE		0x80	/* RDC_CMD_COPY */
#define	RDC_OPT_SETBMP		0x100	/* RDC_CMD_ENABLE */
#define	RDC_OPT_CLRBMP		0x200	/* RDC_CMD_ENABLE */
#define	RDC_OPT_REVERSE_ROLE	0x400	/* RDC_CMD_RECONFIG */
#define	RDC_OPT_FORCE_QINIT	0x800	/* RDC_CMD_INITQ */
#define	RDC_OPT_SET_QNOBLOCK	0x1000	/* RDC_CMD_TUNABLE */
#define	RDC_OPT_CLR_QNOBLOCK	0x2000	/* RDC_CMD_TUNABLE */
#define	RDC_OPT_FORCE_DISABLE	0x4000	/* RDC_CMD_DISABLE */

/*
 * RDC flags
 */

/*
 * Passed out by the kernel (status)
 */
#define	RDC_ENABLED		0x2	/* RDC enabled */
#define	RDC_PRIMARY		0x4	/* This node is the primary */
#define	RDC_SLAVE		0x8	/* This node is target of the synch */
#define	RDC_VOL_FAILED		0x10	/* Volume is failed */
#define	RDC_BMP_FAILED		0x20	/* Bitmap is failed */
#define	RDC_SYNC_NEEDED		0x40	/* Sync is needed */
#define	RDC_RSYNC_NEEDED	0x80	/* Reverse sync is needed */
#define	RDC_SYNCING		0x100	/* Synch in progress */
#define	RDC_LOGGING		0x200	/* Logging */
#define	RDC_FCAL_FAILED		0x400	/* Direct remote I/O failed */
#define	RDC_ASYNC		0x800	/* Set is in async replicating mode */
#define	RDC_FULL		0x1000	/* Full sync, not an update */
#define	RDC_CLR_AFTERSYNC	0x2000	/* clr bitmap on secondary after sync */
#define	RDC_DISKQ_FAILED	0x4000  /* Diskq I/O has failed */
#define	RDC_QUEUING		0x8000	/* logging, but queueing to disk */
#ifndef	RDC_QNOBLOCK
#define	RDC_QNOBLOCK		0x10000
#endif
#define	RDC_SYNC_START		0
#define	RDC_SYNC_DONE		1
#define	RDC_RSYNC_START		2

#ifdef _KERNEL

/*
 * urdc->flags vs urdc->mflags usage:
 *
 * All flags are valid in urdc->flags, in which case the condition
 * holds for the specific urdc.
 *
 * The flags in RDC_MFLAGS can also be in urdc->mflags, in which case
 * the condition holds for a urdc somewhere on the many/multi chains
 * connected to this urdc.
 */

#define	RDC_GROUP		0x7f8	/* Volume states that affect a group */

/*
 * Mask of volume flags that are valid in urdc->mflags
 */
#define	RDC_MFLAGS		(RDC_SLAVE | RDC_RSYNC_NEEDED)

#define	IS_SLAVE(urdc)	  (rdc_get_mflags(urdc) & RDC_SLAVE)

/*
 * Mask of volume flags that are maintained in sync_flags not flags,
 * and protected by rdc_many_lock rather than the group lock.
 * This allows code that is operating on one set to change the flags
 * of another set.
 */
#define	RDC_SFLAGS		(RDC_SYNC_NEEDED | RDC_RSYNC_NEEDED | \
				    RDC_VOL_FAILED | RDC_CLR_AFTERSYNC)

/*
 * Mask of volume flags that are maintained in bmap_flags not flags,
 * and protected by the bmapmutex rather than the group lock.
 */
#define	RDC_BFLAGS		RDC_BMP_FAILED

#define	RDC_VFLAGS		(~(RDC_SFLAGS | RDC_BFLAGS))

#define	RDC_SYNC_STATE_FLAGS	(RDC_LOGGING | RDC_SYNCING | RDC_QUEUING | \
				RDC_ASYNC)

#define	IS_ASYNC(urdc)		(rdc_get_vflags(urdc) & RDC_ASYNC)
#define	IS_PRIMARY(urdc)	(rdc_get_vflags(urdc) & RDC_PRIMARY)
#define	IS_SECONDARY(urdc)	(!IS_PRIMARY(urdc))
#define	IS_STATE(urdc, state)   (rdc_get_vflags(urdc) & (state))
#define	IS_REPLICATING(urdc)	(!(rdc_get_vflags(urdc) & RDC_LOGGING) && \
				    !(rdc_get_vflags(urdc) & RDC_SYNCING))

#endif	/* _KERNEL */

typedef struct rdc_status {
	int nset;			/* Number of sets requested/enabled */
	int maxsets;			/* Max # of sets allowed today */
	rdc_set_t rdc_set[1];
} rdc_status_t;

#ifdef _SYSCALL32
struct rdc_status32 {
	int32_t nset;			/* Number of sets requested/enabled */
	int32_t maxsets;		/* Max # of sets allowed today */
	struct rdc_set32 rdc_set[1];
};
#endif /* _SYSCALL32 */

typedef struct rdc_svc_args {
	int		fd;		/* Connection endpoint */
	int		nthr;		/* Number of server threads */
	char		netid[128];	/* Identify transport */
	struct netbuf	addrmask;	/* Address mask for host */
} rdc_svc_args_t;

#ifdef _SYSCALL32
struct rdc_svc_args32 {
	int32_t			fd;
	int32_t			nthr;
	char			netid[128];
	struct	netbuf32	addrmask;
};
#endif /* _SYSCALL32 */

typedef struct rdc_version {
	int	major;			/* Major release number */
	int	minor;			/* Minor release number */
	int	micro;			/* Micro release number */
	int	baseline;		/* Baseline revison number */
} rdc_version_t;
#ifdef _SYSCALL32
typedef struct rdc_version32 {
	int32_t	major;			/* Major release number */
	int32_t minor;			/* Minor release number */
	int32_t	micro;			/* Micro release number */
	int32_t	baseline;		/* Baseline revison number */
} rdc_version32_t;
#endif


#if !defined(_KERNEL)

#define	RDC_IOCTL(cmd, a0, a1, a2, a3, a4, ustatus) \
		rdc_ioctl((long)(cmd), (long)(a0), (long)(a1), (long)(a2), \
		    (long)(a3), (long)(a4), (ustatus))

extern int rdc_ioctl(long, long, long, long, long, long, spcs_s_info_t);
extern int rdc_ioctl_simple(long, void *);

#endif	/* ! _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _RDC_IOCTL_H */
