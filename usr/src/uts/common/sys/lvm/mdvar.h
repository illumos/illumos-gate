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

#ifndef	_SYS_MDVAR_H
#define	_SYS_MDVAR_H

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/t_lock.h>
#include <sys/open.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#ifdef	DEBUG
#include <sys/thread.h>
#endif
#include <sys/kstat.h>
#include <sys/efi_partition.h>
#include <sys/byteorder.h>
#include <sys/door.h>

#include <sys/lvm/mdmn_commd.h>
#include <sys/lvm/mdio.h>
#include <sys/lvm/md_mdiox.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_notify.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * defaults
 */
#define	NMD_DEFAULT		128	/* number of metadevices */
#define	MD_NOPS			25	/* number of misc modules */
#define	MAXBOOTLIST		64

/*
 * Needed for backwards-compatibility with metadevices created under
 * 2.6 or earlier.  Back then, a krwlock_t was twelve bytes.  More
 * recently, it's four bytes.  Since these get included in structures
 * written out to disk, we have to make sure we're using the largest
 * size.  Things will get interesting if krwlock_t ever gets bigger
 * than twelve bytes.
 */

typedef union _md_krwlock {
	krwlock_t	lock;
	struct {
		void	*_opaque[3];
	} xx;
} md_krwlock_t;

typedef struct {
	kmutex_t	md_io_mx;		/* counter mutex */
	kcondvar_t	md_io_cv;		/* ioctl wait on if draining */
	long		io_cnt;			/* number of I/Os */
	long		io_state;		/* !0 if waiting on zero */
} md_set_io_t;

typedef enum set_iostate {
	MD_SET_ACTIVE = 1,
	MD_SET_RELEASE = 2
}set_iostate_t;

/*
 * for md_dev64_t translation
 */
struct md_xlate_table {
	dev32_t		mini_devt;
	dev32_t		targ_devt;
};

extern struct md_xlate_table	*md_tuple_table;

/*
 * for major number translation
 */

struct md_xlate_major_table {
	char		*drv_name;
	major_t		targ_maj;
};

extern struct md_xlate_major_table *md_major_tuple_table;

extern int	md_tuple_length;
extern uint_t	md_majortab_len;
extern int	md_in_upgrade;

extern md_mn_nodeid_t	md_mn_mynode_id;

#define	MD_UPGRADE (md_in_upgrade == 1)

/*
 * Flags used during upgrade:
 *
 * md_keep_repl_state flag means that mddb should be kept in the format
 *   that was found on disk (non-device id format vs. device id format).
 *   This is used during the upgrade process when install is probing
 *   for root disks so that the user can choose the one to be upgraded.
 *
 * md_devid_destroy flag is used to destroy device ids stored in the
 *   metadevice state database (mddb).
 *
 *   The md_devid_destroy flag is to be used only in a catastrophic failure
 *   case. An example of this would be if a user upgrades firmware on all
 *   disks where this causes the disks to now have different device id's.
 *   The user would not be able to boot a mirror'd root filesystem since the
 *   system would recognize none of the device id's stored in the mddb.
 *   This flag would destroy all device id information stored in the mddb and
 *   if the md_keep_repl_state flag was not set, the mddb would be reconverted
 *   to device id format on SLVM startup and all of the device id
 *   information would be regenerated.
 *
 *   If the md_devid_destroy flag is set and the md_keep_repl_state flag is
 *   set, the mddb's would have their device id information destroyed and
 *   would be left in non-devid format since the device id information would
 *   not be regenerated.
 *
 *   This flag is not documented anywhere and is only to be used as a last
 *   resort as in the described case or if a device driver has a bug where
 *   device id's are found to not be unique.  If device id's aren't unique,
 *   the user could run without device id's until a patch is released for
 *   that driver.
 */
extern int	md_keep_repl_state;
extern int	md_devid_destroy;
extern int	mdmn_door_did;
#ifdef _KERNEL
extern door_handle_t	mdmn_door_handle;
#endif /* _KERNEL */

/*
 * An io_lock mechanism for raid, the MD_UL_XXXX bits are used for
 * convenience.
 */
typedef struct md_io_lock {
	ulong_t		io_readercnt;	/* number of unit readers */
	ulong_t		io_wanabecnt;	/* # pending on becoming unit writer */
	ulong_t		io_lock;
	void		*io_list_front;
	void		*io_list_back;
	kmutex_t	io_mx;
	kcondvar_t	io_cv;
	kmutex_t	io_list_mutex;	/* list of waiting io */
	kthread_id_t	io_owner;	/* writer thread */
} md_io_lock_t;

/*
 * The following flags are in un_flag field of mdc_unit struct.
 */
#define	MD_LABELED	0x1	/* First sector of the metadevice is a label */
#define	MD_EFILABEL	0x2	/* This md has an EFI label and no vtoc */

/*
 * This is the number of bytes a DKIOCGETEFI ioctl returns
 * For now it's one time the header and once the size for a partition info
 */
#define	MD_EFI_LABEL_SIZE (sizeof (efi_gpt_t) + sizeof (efi_gpe_t))

/* This is the number of bytes consumed by efi_gpe_PartitionName */
#define	MD_EFI_PARTNAME_BYTES (EFI_PART_NAME_LEN * sizeof (ushort_t))

typedef enum hs_cmds {
	HS_GET, HS_FREE, HS_BAD, HSP_INCREF, HSP_DECREF, HS_MKDEV
} hs_cmds_t;

typedef struct md_link {
	struct md_link	*ln_next;
	set_t		ln_setno;
	uint_t		ln_id;
} md_link_t;

typedef struct mdi_unit {
	md_link_t	ui_link;
	ulong_t		ui_readercnt;	/* number of unit readers */
	ulong_t		ui_wanabecnt;	/* # pending on becoming unit writer */
	ulong_t		ui_lock;
	kmutex_t	ui_mx;
	kcondvar_t	ui_cv;
	int		ui_opsindex;
	uint_t		ui_ocnt[OTYPCNT]; /* open counts */
	md_io_lock_t	*ui_io_lock;	/* pointer to io lock */
	kstat_t		*ui_kstat;	/* kernel statistics */
	kthread_id_t	ui_owner;	/* writer thread */
	uint_t		ui_tstate;	/* transient state bits */
	uint_t		ui_capab;	/* Capability bits supported */
} mdi_unit_t;

/*
 * Following are used with ui_lock
 * which is in the unit incore structure.
 */
#define	MD_UL_WRITER		0x0001 /* Stall all new strategy calls */
#define	MD_UL_WANABEWRITER	0x0002
#define	MD_UL_OPENORCLOSE	0x0004

#define	MD_UL_OPEN		0x0008	/* unit is open */
#define	MD_UL_EXCL		0x0010	/* unit is open exclusively */

/*
 * The softpart open code may do an I/O to validate the watermarks
 * and should hold no open locks during this I/O.  So, mark the unit
 * as OPENINPROGRESS and drop the locks.  This will keep any other
 * softpart open's waiting until the validate has completed.
 */
#define	MD_UL_OPENINPROGRESS	0x0020	/* Open in Progress */

/*
 * Following are used with ui_tstate to specify any transient states which
 * occur during metadevice operation. These are not written to the metadb as
 * they do not represent a failure of the underlying metadevice.
 * Transient errors are stored in the lower 16 bits and other transient
 * state is stored in the upper 16 bits.
 * MD_NOTOPENABLE should contain all the states that are set prior to an
 * open (by snarf) and that indicate that a metadevice cannot be opened.
 */
#define	MD_DEV_ERRORED		0x0000ffff /* ui_tstate error bits */
#define	MD_EOF_METADEVICE	0x00000001 /* EOF'd metadevice */
#define	MD_64MD_ON_32KERNEL	0x00000002 /* 64bit metadev on 32bit kernel */
#define	MD_INACCESSIBLE		0x00000004 /* metadevice unavailable */
#define	MD_RETRYING		0x00010000 /* retrying errored failfast I/O */
#define	MD_OPENLOCKED		0x00020000 /* MN: open locked before removing */
#define	MD_ERR_PENDING		0x00040000 /* MN: error pending */
#define	MD_ABR_CAP		0x00080000 /* MN: Application Based Recovery */
#define	MD_DMR_CAP		0x00100000 /* MN: Directed Mirror Read */
#define	MD_RELEASE_IOERR_DONE	0x00200000 /* ioerr console message done */
#define	MD_RESYNC_NOT_DONE	0x00400000 /* resync not done yet */

/* A metadevice cannot be opened when these states are set */
#define	MD_NOTOPENABLE		(MD_EOF_METADEVICE|MD_64MD_ON_32KERNEL)

typedef struct md_ioctl_lock {
	int		l_flags;	/* locks held */
	mdi_unit_t	*l_ui;		/* unit for which lock is held */
} md_ioctl_lock_t;

#define	MD_MASTER_DROPPED	0x0001
#define	MD_READER_HELD		0x0002
#define	MD_WRITER_HELD		0x0004
#define	MD_IO_HELD		0x0008
#define	MD_ARRAY_READER		0x0010
#define	MD_ARRAY_WRITER		0x0020
#define	STALE_OK		0x0100
#define	NO_OLD			0x0200
#define	NO_LOCK			0x0400
#define	MD_MT_IOCTL		0x80000 /* MD_GBL_IOCTL_LOCK not set */
#define	IOLOCK	md_ioctl_lock_t

#define	WR_LOCK			MD_WRITER_HELD
#define	RD_LOCK			MD_READER_HELD | STALE_OK
#define	ARRAY_WRITER		MD_ARRAY_WRITER
#define	ARRAY_READER		MD_ARRAY_READER
#define	WRITERS			MD_WRITER_HELD | MD_IO_HELD | MD_ARRAY_WRITER
#define	READERS			RD_LOCK | MD_ARRAY_READER

#define	IOLOCK_RETURN_IOCTLEND(code, lock) \
	md_ioctl_lock_exit((code), (lock)->l_flags, (lock)->l_ui, TRUE)

#define	IOLOCK_RETURN(code, lock) \
	md_ioctl_lock_exit((code), (lock)->l_flags, (lock)->l_ui, FALSE)

#define	IOLOCK_RETURN_RELEASE(code, lock) \
	md_ioctl_releaselocks((code), (lock)->l_flags, (lock)->l_ui)

#define	IOLOCK_RETURN_REACQUIRE(lock) \
	md_ioctl_reacquirelocks((lock)->l_flags, (lock)->l_ui)

#define	IOLOCK_INIT(lock)	bzero((caddr_t)(lock), sizeof (*(lock)))
/*
 * checks to be sure locks are held
 */
#define	UNIT_WRITER_HELD(un) \
	(MDI_UNIT(MD_SID(un))->ui_lock & MD_UL_WRITER)
#define	UNIT_READER_HELD(un) \
	(MDI_UNIT(MD_SID(un))->ui_readercnt != 0)
#define	IO_WRITER_HELD(un) \
	(MDI_UNIT(MD_SID(un))->ui_io_lock->io_lock & MD_UL_WRITER)
#define	IO_READER_HELD(un) \
	(MDI_UNIT(MD_SID(un))->ui_io_lock->io_readercnt != 0)

#ifdef  DEBUG
#define	STAT_INC(statvar)		\
	statvar++
#define	STAT_DEC(statvar)		\
	statvar--
#define	STAT_ZERO(statvar)		\
	statvar = 0;
#define	STAT_MAX(statmax, statvar)	\
	{				\
	statvar++;			\
	if (statvar > statmax)		\
		statmax = statvar;	\
	}
#define	STAT_CHECK(statvar, value)	\
	{				\
	if (value)			\
		statvar++;		\
	}
#else
#define	STAT_INC(statvar)
#define	STAT_DEC(statvar)
#define	STAT_ZERO(statvar)
#define	STAT_MAX(statmax, statvar)
#define	STAT_CHECK(statvar, value)
#endif
/*
 * bit map related macros
 */
#define	setbit(a, i)	((a)[(i)/NBBY] |= 1<<((i)%NBBY))
#define	clrbit(a, i)	((a)[(i)/NBBY] &= ~(1<<((i)%NBBY)))
#define	isset(a, i)	((a)[(i)/NBBY] & (1<<((i)%NBBY)))
#define	isclr(a, i)	(((a)[(i)/NBBY] & (1<<((i)%NBBY))) == 0)

typedef struct daemon_queue {
	int	maxq_len;
	int	qlen;
	int	treqs;		/* total number of requests */
	struct daemon_queue	*dq_next;
	struct daemon_queue	*dq_prev;
	void			(*dq_call)();
} daemon_queue_t;

#define	DAEMON_QUEUE daemon_queue_t	dq;

#ifdef _KERNEL
#include	<sys/buf.h>
#include	<sys/dkio.h>
#include	<sys/vtoc.h>

#define	MD_DEV2SET(d)	(MD_MIN2SET(md_getminor(d)))

#define	MD_UNIT(m)	(md_set[MD_MIN2SET(m)].s_un[MD_MIN2UNIT(m)])
#define	MDI_UNIT(m)	((mdi_unit_t *) \
			    md_set[MD_MIN2SET(m)].s_ui[MD_MIN2UNIT(m)])
#define	MD_VOIDUNIT(m)	(md_set[MD_MIN2SET(m)].s_un[MD_MIN2UNIT(m)])
#define	MDI_VOIDUNIT(m)	(md_set[MD_MIN2SET(m)].s_ui[MD_MIN2UNIT(m)])

/*
 * This is the current maximum number of real disks per Virtual Disk.
 */
extern	uint_t	md_mdelay;	/* md_mirror timeout delay */

#define	MD_ADM_MINOR		L_MAXMIN32 /* the minor number for md_admin */
#define	MD_MDELAY		(md_mdelay)
#define	NUM_USEC_IN_SEC		1000000 /* 1 million usec in a second */

#define	ANY_SERVICE		-1	/* md_get_named_service() wild card */

/*
 * daemon threads are used in multiple places in md. The following set of
 * structures and routines allow a common way to create and initialize them.
 *
 * md_requestq_entry_t - entry of creating request queues.
 * struct mdq_anchor - request queue header
 *
 * Functions associated with request queues:
 *
 * int init_requestq_entry -
 * void daemon_request - put a request on the queue.
 */

typedef struct md_requestq_entry {
	struct mdq_anchor	*dispq_headp;
	int		*num_threadsp; /* threads servicing the queue */
} md_requestq_entry_t;

#define	NULL_REQUESTQ_ENTRY(rqp)\
		((rqp)->dispq_headp == NULL || (rqp)->num_threadsp == NULL)

/* this typedef is used to differentiate between the two call styles */
typedef enum callstyle {
	REQ_OLD,
	REQ_NEW
} callstyle_t;


#define	daemon_request_new daemon_request

typedef struct mdq_anchor {
	DAEMON_QUEUE
	kcondvar_t	 a_cv;		/* Request has been put on queue */
	kmutex_t	 a_mx;
} mdq_anchor_t;

typedef struct daemon_request {
	DAEMON_QUEUE
	kmutex_t	dr_mx;
	int		dr_pending;
	timeout_id_t	dr_timeout_id;
} daemon_request_t;

typedef struct sv_dev {
	set_t	setno;
	side_t	side;
	mdkey_t	key;
} sv_dev_t;

/*
 * Types of device probes
 */


typedef struct probe_req {
	DAEMON_QUEUE
	minor_t mnum;			/* mnum of the metadevice to probe */
	void   *private_handle;		/* private handle */
	intptr_t (*probe_fcn)();	/* type of probeing to be done */
} probe_req_t;

/* Global flags */
#define	MD_NO_GBL_LOCKS_HELD	0x0000	/* currently holding no global locks */
#define	MD_GBL_DAEMONS_LIVE	0x0001	/* master daemon has been started. */
#define	MD_GBL_DAEMONS_DIE	0x0002
#define	MD_GBL_HALTED		0x0004	/* driver is shut down */

/* Available bit was GBL_STALE	0x0008	*/

#define	MD_GBL_IOCTL_LOCK	0x0010	/* single-threads ioctls */
#define	MD_GBL_HS_LOCK		0x0020	/* single-threads hotspares */
#define	MD_GBL_OPEN		0x0040	/* admin is open */
#define	MD_GBL_EXCL		0x0080	/* admin is open exclusively */

#define	MD_OFLG_NULL		0x0000	/* Null flag */
#define	MD_OFLG_CONT_ERRS	0x0001	/* Continue on open errors */
#define	MD_OFLG_PROBEDEV	0x0002  /* force a simulated open */
#define	MD_OFLG_ISINIT		0x0004  /* raid initialization */
#define	MD_OFLG_FROMIOCTL	0x0008  /* Called from an ioctl handler */


typedef struct md_named_services {

	intptr_t	(*md_service)();
	char		*md_name;
} md_named_services_t;

typedef enum md_snarfcmd {MD_SNARF_CLEANUP, MD_SNARF_DOIT} md_snarfcmd_t;

typedef struct md_ops {
	int	(*md_open)(
		    dev_t		*devp,
		    int			flag,
		    int			otyp,
		    cred_t		*credp,
		    int			md_oflags);
	int	(*md_close)(
		    dev_t		dev,
		    int			flag,
		    int			otyp,
		    cred_t		*credp,
		    int			md_oflags);
	void	(*md_strategy)(
		    buf_t		*bufp,
		    int			flag,
		    void		*private);
	int	(*md_print)();		/* unused now */
	int	(*md_dump)(
		    dev_t		dev,
		    caddr_t		addr,
		    daddr_t		blkno,
		    int			nblk);
	int	(*md_read)(
		    dev_t		dev,
		    struct uio		*uiop,
		    cred_t		*credp);
	int	(*md_write)(
		    dev_t		dev,
		    struct uio		*uiop,
		    cred_t		*credp);
	int	(*md_ioctl)(
		    dev_t		dev,
		    int			cmd,
		    void		*data,
		    int			mode,
		    IOLOCK		*lockp);
	int	(*md_snarf)(
		    md_snarfcmd_t	cmd,
		    set_t		setno);
	int	(*md_halt)();
	int	(*md_aread)(
		    dev_t		dev,
		    struct aio_req	*aiop,
		    cred_t		*credp);
	int	(*md_awrite)(
		    dev_t		dev,
		    struct aio_req	*aiop,
		    cred_t		*credp);
	int	(*md_imp_set)(
		    set_t		setno);
	md_named_services_t	*md_services;
	md_krwlock_t		md_link_rw;
	md_link_t		*md_head;
	/*
	 * NOTE: when TSlvm s10/onnv compatibility is not an issue:
	 *	o md_modid and md_locked should be deleted.
	 *	o md_mod should be added
	 *		ddi_modhandle_t		md_mod;
	 *	  and used instead of the md_mods array (md_mods should
	 *	  be deleted).
	 */
	int			md_modid;
	int			md_locked;
	int			md_selfindex;
	struct md_ops		*md_next;
	md_driver_t		md_driver;
	/* NOTE: TSlvm depends on offsets in and sizeof this structure */
} md_ops_t;

/* macro to generate linkage for a md misc plugin module */
#define	md_noop
#define	MD_PLUGIN_MISC_MODULE(desc, init_init, fini_uninit)		\
	static struct modlmisc		modlmisc = {			\
		&mod_miscops, "Solaris Volume Manager " desc		\
	};								\
	static struct modlinkage	modlinkage = {			\
		MODREV_1, (void *)&modlmisc, NULL			\
	};								\
	int								\
	_init(void)							\
	{								\
		int	i;						\
		init_init;						\
		if ((i = mod_install(&modlinkage)) != 0) {		\
			fini_uninit;					\
		}							\
		return (i);						\
	}								\
	int								\
	_fini()								\
	{								\
		int	i;                                              \
		if ((i = mod_remove(&modlinkage)) == 0) {		\
			fini_uninit;					\
		}							\
		return (i);						\
	}								\
	int								\
	_info(struct modinfo *modinfop)					\
	{								\
		return (mod_info(&modlinkage, modinfop));		\
	}

typedef enum md_haltcmd {MD_HALT_ALL, MD_HALT_CHECK, MD_HALT_DOIT,
			MD_HALT_CLOSE, MD_HALT_OPEN, MD_HALT_UNLOAD
} md_haltcmd_t;

/*
 * To support cpr (Energy Star) we need to know when the resync threads are
 * running to not allow suspention.
 */
typedef struct md_resync_thds_cnt {
	int md_raid_resync;	/* count of active raid resync threads */
	int md_mirror_resync;	/* count of active mirror resync threads */
	kmutex_t md_resync_mutex;	/* protects both resync counts */
} md_resync_t;

/*
 * flags used with call to individual strategy routines
 */
#define	MD_STR_PASSEDON 0x0000ffff
#define	MD_STR_NOTTOP	0x00000001
#define	MD_STR_MAPPED	0x00000002	/* set when buf_t is mapped in	*/
#define	MD_STR_ABR	0x00000004	/* use ABR to handle any recovery */
#define	MD_STR_WMUPDATE	0x00000008	/* set if updating watermarks for sp */
#define	MD_IO_COUNTED	0x00000400	/* io has been counted */
#define	MD_NOBLOCK	0x00000800	/* do not block io durring release */

#define	MD_STR_WAR	0x00010000	/* this write is write after read */
#define	MD_STR_WOW	0x00020000	/* handling a write-on-write */
#define	MD_STR_DMR	0x00040000	/* Directed Read request */
#define	MD_STR_DIRTY_RD	0x00080000	/* Read of a dirty block */
#define	MD_STR_FLAG_ERR	0x00100000	/* Flag any write error on this i/o */

/*
 * Bits for return value of md_getdevnum
 */
#define	MD_TRUST_DEVT	1
#define	MD_NOTRUST_DEVT	0

/* Flag for drivers to pass to kmem_cache_alloc() */
#define	MD_ALLOCFLAGS   (KM_PUSHPAGE | KM_SLEEP)

/* Named services */
#define	MD_CHECK_OFFLINE	"check_offline"
#define	MD_INC_ABR_COUNT	"inc abr count"
#define	MD_DEC_ABR_COUNT	"dec abr count"

/* md_getdevname_common flags for namespace lock */
#define	MD_WAIT_LOCK	0
#define	MD_NOWAIT_LOCK	1

/* Externals from md.c */
extern int	md_snarf_db_set(set_t setno, md_error_t *ep);
extern void	get_info(struct dk_cinfo *, minor_t);
extern void	get_minfo(struct dk_minfo *, minor_t);
extern int	mdstrategy(buf_t *);
extern int	md_create_minor_node(set_t, minor_t);


/* External from md_subr.c */
extern int	md_inc_iocount(set_t);
extern void	md_inc_iocount_noblock(set_t);
extern void	md_dec_iocount(set_t);
extern int	md_isblock_setio(set_t);
extern int	md_block_setio(set_t);
extern void	md_clearblock_setio(set_t);
extern void	md_unblock_setio(set_t);
extern int	md_tas_block_setio(set_t);
extern void	md_biodone(struct buf *);
extern void	md_bioreset(struct buf *);
extern md_dev64_t md_xlate_targ_2_mini(md_dev64_t);
extern md_dev64_t md_xlate_mini_2_targ(md_dev64_t);
extern void	md_xlate_free(int);
extern major_t	md_targ_name_to_major(char *);
extern char	*md_targ_major_to_name(major_t);
extern void	md_majortab_free();
extern void	md_set_status(int);
extern void	md_clr_status(int);
extern int	md_get_status(void);
extern void	md_set_setstatus(set_t, int);
extern void	md_clr_setstatus(set_t, int);
extern uint_t	md_get_setstatus(set_t);
extern void	*md_unit_readerlock(mdi_unit_t *);
extern void	*md_unit_writerlock(mdi_unit_t *);
extern void	md_unit_readerexit(mdi_unit_t *);
extern void	md_unit_writerexit(mdi_unit_t *);
extern void	md_ioctl_releaselocks(int, int, mdi_unit_t *);
extern void	md_ioctl_reacquirelocks(int, mdi_unit_t *);
extern int	md_ioctl_lock_exit(int, int, mdi_unit_t *, int);
extern int	md_ioctl_lock_enter(void);
extern void	*md_ioctl_readerlock(IOLOCK *, mdi_unit_t *);
extern void	md_ioctl_readerexit(IOLOCK *);
extern void	*md_ioctl_writerlock(IOLOCK *, mdi_unit_t *);
extern void	md_ioctl_writerexit(IOLOCK *);
extern void	md_ioctl_io_exit(IOLOCK *);
extern void	*md_ioctl_io_lock(IOLOCK *, mdi_unit_t *);
extern void	md_ioctl_droplocks(IOLOCK *);
extern void	md_array_writer(IOLOCK *);
extern void	md_array_reader(IOLOCK *);
extern void	*md_ioctl_openclose_enter(IOLOCK *, mdi_unit_t *);
extern void	md_ioctl_openclose_exit(IOLOCK *);
extern void	md_ioctl_openclose_exit_lh(IOLOCK *);
extern void	*md_unit_openclose_enter(mdi_unit_t *);
extern void	md_unit_openclose_exit(mdi_unit_t *);
extern void	md_unit_openclose_exit_lh(mdi_unit_t *);
extern int	md_unit_isopen(mdi_unit_t *ui);
extern int	md_unit_incopen(minor_t mnum, int flag, int otyp);
extern int	md_unit_decopen(minor_t mnum, int otyp);
extern void	*md_io_readerlock(mdi_unit_t *);
extern void	*md_io_writerlock(mdi_unit_t *);
extern void	md_io_readerexit(mdi_unit_t *);
extern void	md_io_writerexit(mdi_unit_t *);
extern intptr_t	(*md_get_named_service())();
extern int	init_requestq(md_requestq_entry_t *, void (*)(),
						caddr_t, int, int);
extern void	daemon_request(mdq_anchor_t *, void(*)(),
				daemon_queue_t *, callstyle_t);
extern void	md_daemon(int, mdq_anchor_t *);
extern void	mddb_commitrec_wrapper(mddb_recid_t);
extern void	mddb_commitrecs_wrapper(mddb_recid_t *);
extern void	mddb_deleterec_wrapper(mddb_recid_t);
extern void	md_holdset_enter(set_t setno);
extern void	md_holdset_exit(set_t setno);
extern int	md_holdset_testandenter(set_t setno);
extern void	md_haltsnarf_enter(set_t setno);
extern void	md_haltsnarf_exit(set_t setno);
extern void	md_haltsnarf_wait(set_t setno);
extern int	md_halt_set(set_t setno, enum md_haltcmd cmd);
extern int	md_halt(int global_lock_flag);
extern int	md_layered_open(minor_t, md_dev64_t *, int);
extern void	md_layered_close(md_dev64_t, int);
extern char	*md_get_device_name(md_dev64_t);
extern int	errdone(mdi_unit_t *, struct buf *, int);
extern int	md_checkbuf(mdi_unit_t *, md_unit_t *, buf_t *);
extern int	md_start_daemons(int init_queues);
extern int	md_loadsubmod(set_t, char *, int);
extern int	md_getmodindex(md_driver_t *, int, int);
extern void	md_call_strategy(buf_t *, int, void *);
extern int	md_call_ioctl(md_dev64_t, int, void *, int, IOLOCK *);
extern void	md_rem_link(set_t, int, krwlock_t *, md_link_t **);
extern int	md_dev_exists(md_dev64_t);
extern md_parent_t md_get_parent(md_dev64_t);
extern void	md_set_parent(md_dev64_t, md_parent_t);
extern void	md_reset_parent(md_dev64_t);
extern struct hot_spare_pool *find_hot_spare_pool(set_t, int);
extern int	md_hot_spare_ifc(hs_cmds_t, mddb_recid_t, u_longlong_t, int,
		    mddb_recid_t *, mdkey_t *, md_dev64_t *, diskaddr_t *);
extern int	md_notify_interface(md_event_cmds_t cmd, md_tags_t type,
		set_t set, md_dev64_t dev, md_event_type_t event);
extern void	svm_gen_sysevent(char *se_class, char *se_subclass,
		    uint32_t tag, set_t setno, md_dev64_t devid);
extern void	md_create_unit_incore(minor_t, md_ops_t *, int);
extern void	md_destroy_unit_incore(minor_t, md_ops_t *);
extern void	md_rem_names(sv_dev_t *, int);
struct uio;
extern int	md_chk_uio(struct uio *);
extern char	*md_shortname(minor_t mnum);
extern char	*md_devname(set_t setno, md_dev64_t dev, char *buf,
		size_t size);
extern void	md_minphys(buf_t *);
extern void	md_kstat_init(minor_t mnum);
extern void	md_kstat_init_ui(minor_t mnum, mdi_unit_t *ui);
extern void	md_kstat_destroy(minor_t mnum);
extern void	md_kstat_destroy_ui(mdi_unit_t *ui);
extern void	md_kstat_waitq_enter(mdi_unit_t *ui);
extern void	md_kstat_waitq_to_runq(mdi_unit_t *ui);
extern void	md_kstat_waitq_exit(mdi_unit_t *ui);
extern void	md_kstat_runq_enter(mdi_unit_t *ui);
extern void	md_kstat_runq_exit(mdi_unit_t *ui);
extern void	md_kstat_done(mdi_unit_t *ui, buf_t *bp, int war);
extern pid_t	md_getpid(void);
extern proc_t	*md_getproc(void);
extern int	md_checkpid(pid_t pid, proc_t *proc);
extern char	*md_strdup(char *cp);
extern void	freestr(char *cp);
extern int	md_check_ioctl_against_unit(int, mdc_unit_t);
extern mddb_recid_t md_vtoc_to_efi_record(mddb_recid_t, set_t);

extern int	mdmn_ksend_message(set_t, md_mn_msgtype_t, uint_t, char *, int,
		    md_mn_kresult_t *);
extern void	mdmn_ksend_show_error(int, md_mn_kresult_t *, const char *);
extern int	mdmn_send_capability_message(minor_t, volcap_t, IOLOCK *);
extern void	mdmn_clear_all_capabilities(minor_t);
extern int	md_init_probereq(struct md_probedev_impl *p,
		    daemon_queue_t **hdrpp);
extern boolean_t callb_md_mrs_cpr(void *, int);
extern void	md_upd_set_unnext(set_t, unit_t);
extern int	md_rem_selfname(minor_t);
extern void	md_rem_hspname(set_t, mdkey_t);

/* Externals from md_ioctl.c */
extern int	md_mn_is_commd_present(void);
extern void	md_mn_clear_commd_present(void);
extern int	md_admin_ioctl(md_dev64_t, int, caddr_t, int, IOLOCK *lockp);
extern void	md_get_geom(md_unit_t *, struct dk_geom *);
extern int	md_set_vtoc(md_unit_t *, struct vtoc *);
extern void	md_get_vtoc(md_unit_t *, struct vtoc *);
extern int	md_set_extvtoc(md_unit_t *, struct extvtoc *);
extern void	md_get_extvtoc(md_unit_t *, struct extvtoc *);
extern void	md_get_cgapart(md_unit_t *, struct dk_map *);
extern void	md_get_efi(md_unit_t *, char *);
extern int	md_set_efi(md_unit_t *, char *);
extern int	md_dkiocgetefi(minor_t, void *, int);
extern int	md_dkiocsetefi(minor_t, void *, int);
extern int	md_dkiocpartition(minor_t, void *, int);
extern void	md_remove_minor_node(minor_t);


/* Externals from md_names.c */
extern mdkey_t	md_setdevname(set_t, side_t, mdkey_t, char *, minor_t, char *,
		    int imp_flag, ddi_devid_t devid, char *minorname,
			set_t, md_error_t *);
extern int	md_getdevname(set_t, side_t, mdkey_t, md_dev64_t, char *,
		    size_t);
extern int	md_getdevname_common(set_t, side_t, mdkey_t, md_dev64_t, char *,
		    size_t, int);
extern int	md_gethspinfo(set_t, side_t, mdkey_t, char *, hsp_t *,
		    char *);
extern int	md_getkeyfromdev(set_t, side_t, md_dev64_t, mdkey_t *, int *);
extern int	md_devid_found(set_t, side_t, mdkey_t);
extern int	md_getnment(set_t, side_t, mdkey_t, md_dev64_t,
		    char *, uint_t, major_t *, minor_t *, mdkey_t *);
extern md_dev64_t md_getdevnum(set_t, side_t, mdkey_t, int);
extern mdkey_t	md_getnextkey(set_t, side_t, mdkey_t, uint_t *);
extern int	md_remdevname(set_t, side_t, mdkey_t);
extern mdkey_t	md_setshared_name(set_t, char *, int);
extern char	*md_getshared_name(set_t, mdkey_t);
extern int	md_remshared_name(set_t, mdkey_t);
extern mdkey_t	md_getshared_key(set_t, char *);
extern int	md_setshared_data(set_t, uint_t, caddr_t);
extern caddr_t	md_getshared_data(set_t, uint_t);
extern int	md_load_namespace(set_t, md_error_t *ep, int);
extern void	md_unload_namespace(set_t, int);
extern int	md_nm_did_chkspace(set_t);
extern void	md_bioinit();
extern buf_t	*md_bioclone(buf_t *, off_t, size_t, dev_t, diskaddr_t,
		    int (*)(buf_t *), buf_t *, int);
extern int	md_getdevid(set_t setno, side_t side, mdkey_t key,
		    ddi_devid_t devid, ushort_t *did_size);
extern int	md_getdevidminor(set_t setno, side_t side, mdkey_t key,
		    char *minorname, size_t minorname_len);
extern int	md_update_namespace(set_t setno, side_t side, mdkey_t key,
		    caddr_t devname, caddr_t pathname, minor_t mnum);
extern int	md_update_locator_namespace(set_t setno, side_t side,
		    caddr_t devname, caddr_t pathname, md_dev64_t devt);
extern int	md_update_namespace_did(set_t setno, side_t side, mdkey_t key,
		    md_error_t *ep);
extern int	md_validate_devid(set_t setno, side_t side, int *maxsz);
extern int	md_get_invdid(set_t setno, side_t side, int cnt, int maxsz,
		    void *didptr);
extern md_dev64_t md_resolve_bydevid(minor_t, md_dev64_t, mdkey_t key);
extern md_dev64_t md_expldev(md_dev64_t);
extern dev32_t	md_cmpldev(md_dev64_t);
extern dev_t	md_dev64_to_dev(md_dev64_t);
extern md_dev64_t md_makedevice(major_t, minor_t);
extern major_t	md_getmajor(md_dev64_t);
extern minor_t	md_getminor(md_dev64_t);
extern void	md_timeval(md_timeval32_t *);
extern int	md_imp_snarf_set(mddb_config_t *);

/* externals from md_mddb.c */
extern int	mddb_reread_rr(set_t, mddb_recid_t);
extern int	mddb_setowner(mddb_recid_t id, md_mn_nodeid_t owner);
extern int	mddb_parse(mddb_parse_parm_t *mpp);
extern int	mddb_block(mddb_block_parm_t *mpp);
extern int	mddb_optrecfix(mddb_optrec_parm_t *mop);
extern int	mddb_check_write_ioctl(mddb_config_t *info);
extern int	mddb_setflags_ioctl(mddb_setflags_config_t *info);
extern struct nm_next_hdr	*get_first_record(set_t, int, int);
extern void	*lookup_entry(struct nm_next_hdr *, set_t,
			side_t, mdkey_t, md_dev64_t, int);
extern void	*lookup_shared_entry(struct nm_next_hdr *,
		    mdkey_t key, char *, mddb_recid_t *, int);
extern int	remove_shared_entry(struct nm_next_hdr *, mdkey_t key,
		    char *, int);
extern void	*alloc_entry(struct nm_next_hdr *, mddb_recid_t, size_t, int,
		    mddb_recid_t *);
extern void	*getshared_name(set_t, mdkey_t, int);

#endif	/* _KERNEL */


/* externals from md_revchk.c */
extern int	revchk(uint_t my_rev, uint_t data);


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MDVAR_H */
