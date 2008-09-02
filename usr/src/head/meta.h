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

#ifndef	_META_H
#define	_META_H

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <locale.h>
#include <time.h>
#include <assert.h>
#include <stdarg.h>
#include <signal.h>
#include <devid.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mkdev.h>
#include <sys/time.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/efi_partition.h>
#include <meta_basic.h>
#include <mdiox.h>
#include <metamed.h>
#include <sys/lvm/mdio.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_sp.h>
#include <sys/lvm/mdmn_commd.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* debug malloc include */
#ifdef	DEBUG_MALLOC
#ifdef	_REENTRANT
die right now
#endif
#include <../lib/malloclib/malloc.h>
#endif

/*
 * useful macros
 */
#ifndef	min
#define	min(x, y)	(((x) < (y)) ? (x) : (y))
#endif
#ifndef	max
#define	max(x, y)	(((x) > (y)) ? (x) : (y))
#endif
#ifndef	rounddown
#define	rounddown(x, y)	(((x) / (y)) * (y))
#endif

/*
 * external names
 */

#define	METATAB			"/etc/lvm/md.tab"
#define	METACONF		"/etc/lvm/md.cf"
#define	METACONFTMP		"/etc/lvm/md.cf.new"
#define	META_DBCONF		"/etc/lvm/mddb.cf"
#define	META_DBCONFTMP		"/etc/lvm/mddb.cf.new"
#define	META_MNSET_NODELIST	"/var/run/nodelist"
#define	METALOG			"/etc/lvm/md.log"
#define	METALOCK		"/etc/lvm/lock"
#define	METADEVPATH		"/etc/lvm/devpath"
#define	METALOGENV		"MD_LOG"
#define	METAPKGROOT		"/usr"
#define	ADMSPECIAL		"/dev/md/admin"

#define	MDB_STR			"metadevice state database"
#define	META_LONGDISKNAME_STR	"<long disk name>"

/* default database size (4MB) */
#define	MD_DBSIZE	(8192)

/* default Multinode database size (16MB) */
#define	MD_MN_DBSIZE	(32768)

/* disk label size */
#define	VTOC_SIZE	(16)

/* EFI geometry data */
#define	MD_EFI_FG_HEADS		128
#define	MD_EFI_FG_SECTORS	256
#define	MD_EFI_FG_RPM		7200
#define	MD_EFI_FG_WRI		1
#define	MD_EFI_FG_RRI		1

/* maximum ctd name size (in # of digits) for printing out */
#define	CTD_FORMAT_LEN	6

/* Recommend timeout in seconds for RPC client creation. */
#define	MD_CLNT_CREATE_TOUT	(60)

/*
 * If event needs to be checked during wait of MD_CLNT_CREATE_TOUT,
 * spin checking for event and then waiting for MD_CLNT_CREATE_SUBTIMEOUT
 * seconds until MD_CLNT_CREATE_TOUT seconds are used.
 */
#define	MD_CLNT_CREATE_SUBTIMEOUT	(5)

/*
 * metaclust verbosity levels and what they are for. Messages upto MC_LOG2
 * will also be logged in syslog.
 */
#define	MC_LOG0		0	/* special class. log messages regardless of */
				/* debug level */
#define	MC_LOG1		1	/* log standard error messages */
#define	MC_LOG2		2	/* log metaclust step level timing messages */
#define	MC_LOG3		3	/* log per set level timing messages */
				/* intended for use in loops walking mn sets */
#define	MC_LOG4		4	/* log per device level timing messages */
				/* intended for use in loops walking devices */
#define	MC_LOG5		5	/* typically for use in deep nested loops */
				/* or in libmeta routines */

/*
 * for meta_print* options
 */
typedef	uint_t	mdprtopts_t;
#define	PRINT_SHORT		0x00000001
#define	PRINT_SUBDEVS		0x00000002
#define	PRINT_HEADER		0x00000004
#define	PRINT_DEBUG		0x00000008
#define	PRINT_TIMES		0x00000010
#define	PRINT_SETSTAT		0x00000020
#define	PRINT_SETSTAT_ONLY	0x00000040
#define	PRINT_FAST		0x00000080
#define	PRINT_DEVID		0x00000100
#define	PRINT_LARGEDEVICES	0x00000200
#define	PRINT_FN		0x00000400

/*
 * for meta_devadm options
 */
typedef	uint_t  mddevopts_t;
#define	DEV_VERBOSE		0x00000001
#define	DEV_NOACTION		0x00000002
#define	DEV_LOG			0x00000004
#define	DEV_RELOAD		0x00000008
#define	DEV_UPDATE		0x00000010
#define	DEV_LOCAL_SET		0x00000020	/* update only MD_LOCAL_SET */

/*
 * return values for meta_devadm operations
 */
#define	METADEVADM_SUCCESS	0
#define	METADEVADM_ERR		1
#define	METADEVADM_DEVIDINVALID	2
#define	METADEVADM_DSKNAME_ERR	3
#define	METADEVADM_DISKMOVE	4

/*
 * return values for the splitname function
 */
#define	METASPLIT_SUCCESS		0
#define	METASPLIT_LONGPREFIX		1
#define	METASPLIT_LONGDISKNAME		2

/*
 * meta_check* options
 */
typedef	uint_t	mdchkopts_t;
#define	MDCHK_ALLOW_MDDB	0x01	/* allows repliica in md's (metainit) */
#define	MDCHK_ALLOW_HS		0x02	/* allows hs in multiple hsp's (hs) */
#define	MDCHK_ALLOW_LOG		0x04	/* allows sharing of logs (trans) */
#define	MDCHK_ALLOW_REPSLICE	0x08	/* allow replica slice to be used */
#define	MDCHK_ALLOW_NODBS	0x10	/* no db replicas allowed (metadb) */
#define	MDCHK_DRVINSET		0x20	/* drive is in set (metaset) */
#define	MDCHK_SET_LOCKED	0x40	/* The set is locked */
#define	MDCHK_SET_FORCE		0x80	/* This is a forced operation */

/*
 * meta_check_inuse options
 */
typedef uint_t	mdinuseopts_t;
#define	MDCHK_SWAP	0x01		/* check swap & overlap w/swap */
#define	MDCHK_DUMP	0x02		/* check dump & overlap w/dump */
#define	MDCHK_MOUNTED	0x04		/* check mounted & overlap w/mounted */
#define	MDCHK_INUSE	0xff		/* check all */

/*
 * meta* force options
 */
typedef	uint_t	mdforceopts_t;
#define	MDFORCE_NONE		0x01	/* no extra force used */
#define	MDFORCE_LOCAL		0x02	/* force from metadb command line */
#define	MDFORCE_DS		0x04	/* force from metaset library */
#define	MDFORCE_SET_LOCKED	0x10	/* The set is locked */


/*
 * meta* options
 */
typedef	uint_t	mdcmdopts_t;
#define	MDCMD_DOIT		0x0001	/* really do operation */
#define	MDCMD_FORCE		0x0002	/* force operation */
#define	MDCMD_PRINT		0x0004	/* print success messages to stdout */
#define	MDCMD_RECURSE		0x0008	/* recursive operation */
#define	MDCMD_INIT		0x0010	/* init operation */
#define	MDCMD_UPDATE		0x0020	/* update sizes used w/o DOIT mostly */
#define	MDCMD_NOLOCK		0x0040	/* lock already held, DONT acquire */
#define	MDCMD_VERBOSE		0x0100	/* be verbose */
#define	MDCMD_USE_WHOLE_DISK	0x0200	/* repartition disk */
#define	MDCMD_DIRECT		0x0400	/* extents specified directly */
#define	MDCMD_ALLOPTION		0x0800	/* the all option is being used */
#define	MDCMD_MN_OPEN_CHECK	0x1000	/* Perform open check on all nodes */

/*
 * meta_tab* definitions
 */
#define	TAB_ARG_ALLOC	5
#define	TAB_LINE_ALLOC	10

typedef uint_t mdinittypes_t;
#define	TAB_UNKNOWN		0x0000
#define	TAB_MDDB		0x0001
#define	TAB_HSP			0x0002
#define	TAB_STRIPE		0x0004
#define	TAB_MIRROR		0x0008
#define	TAB_RAID		0x0010
#define	TAB_TRANS		0x0020
#define	TAB_SP			0x0040
#define	TAB_MD			(TAB_STRIPE | TAB_MIRROR | TAB_RAID |\
					TAB_TRANS | TAB_SP)
#define	TAB_MD_HSP		(TAB_MD | TAB_HSP)

typedef	struct {
	mdinittypes_t	type;
	char		*context;
	char		*cname;
	int		argc;
	char		**argv;
	size_t		alloc;
	uint_t		flags;	/* for application use */
} md_tab_line_t;

typedef	struct {
	char		*filename;
	char		*data;
	size_t		total;
	size_t		nlines;
	md_tab_line_t	*lines;
	size_t		alloc;
} md_tab_t;

/*
 * disk status definitions
 */
typedef struct md_disk_status_list {
	struct md_disk_status_list	*next;
	mddrivename_t			*drivenamep;
	md_error_t			status;
} md_disk_status_list_t;

/*
 * module name list used by meta_patch_root & meta_systemfile
 */
struct modname {
	char		*name;
	struct modname	*next;
};

/*
 * list to be used for printing Device Relocation Information
 */
typedef struct mddevid_t {
	struct mddevid_t *next;
	char *ctdname;
	mdkey_t key;
} mddevid_t;

/*
 * Multi-Node Diskset List
 *
 * we either store the IP address of the private interconnect or its name
 * in the msl_node_addr member
 */
typedef struct mndiskset_membershiplist {
	uint_t				msl_node_id;
	md_mnnode_nm_t			msl_node_name;
	md_mnnode_nm_t			msl_node_addr;
	struct mndiskset_membershiplist	*next;
} mndiskset_membershiplist_t;

/*
 * client pool for rpc calls to mdcommd
 */
typedef struct md_mn_client_list {
	CLIENT *mcl_clnt;
	struct md_mn_client_list *mcl_next;
} md_mn_client_list_t;

/*
 * Resync thread manipulation commands.
 *
 * The resync thread can now be started, blocked, unblocked or killed.
 * This typedef specifies the action to be taken by meta_resync.c
 * routines.
 */
typedef enum {
	MD_RESYNC_START = 1,
	MD_RESYNC_BLOCK,
	MD_RESYNC_UNBLOCK,
	MD_RESYNC_KILL,
	MD_RESYNC_KILL_NO_WAIT,
	MD_RESYNC_FORCE_MNSTART
} md_resync_cmd_t;


/*
 * rpc.metad macro definitions.
 */
#define	METAD_SETUP_DR(cmd, id)	\
	{				\
	req.ur_cmd = cmd;		\
	req.ur_setno = MD_LOCAL_SET;	\
	req.ur_type = MDDB_USER;	\
	req.ur_type2 = MDDB_UR_DR;	\
	req.ur_recid = id;		\
	}

#define	METAD_SETUP_NR(cmd, id)	\
	{				\
	req.ur_cmd = cmd;		\
	req.ur_setno = MD_LOCAL_SET;	\
	req.ur_type = MDDB_USER;	\
	req.ur_type2 = MDDB_UR_NR;	\
	req.ur_recid = id;		\
	}

#define	METAD_SETUP_SR(cmd, id)	\
	{				\
	req.ur_cmd = cmd;		\
	req.ur_setno = MD_LOCAL_SET;	\
	req.ur_type = MDDB_USER;	\
	req.ur_type2 = MDDB_UR_SR;	\
	req.ur_recid = id;		\
	}

#define	METAD_SETUP_UR(cmd, type2, id)	\
	{				\
	req.ur_cmd = cmd;		\
	req.ur_setno = MD_LOCAL_SET;	\
	req.ur_type = MDDB_USER;	\
	req.ur_type2 = type2;		\
	req.ur_recid = id;		\
	}

#define	METAD_SETUP_LR(cmd, setno, id)	\
	{				\
	req.ur_cmd = cmd;		\
	req.ur_setno = setno;	\
	req.ur_type = MDDB_USER;	\
	req.ur_type2 = MDDB_UR_LR;	\
	req.ur_recid = id;		\
	}

/*
 * This typedef specifies the signature of a function that
 * meta_client_create_retry can use to establish an rpc connection.
 * private is used to pass data from the caller of meta_client_create_retry
 * to clnt_create_func.
 */
typedef CLIENT *(*clnt_create_func_t)(char *hostname,
	void *private,
	struct timeval *time_out);

/* definition of the table for the different message types */
typedef struct md_mn_msg_tbl_entry {
	md_mn_msgclass_t	mte_class;
	void (*mte_handler)
	    (md_mn_msg_t *msg, uint_t flags, md_mn_result_t *res);
	int (*mte_smgen)
	    (md_mn_msg_t *msg, md_mn_msg_t **msglist);
	time_t		mte_timeout; /* seconds before msg times out */
	uint_t		mte_retry1; /* nretries in case of class busy */
	uint_t		mte_ticks1; /* sleep nticks before retry */
	uint_t		mte_retry2; /* nretries in case of comm fail */
	uint_t		mte_ticks2; /* sleep nticks before retry */
} md_mn_msg_tbl_entry_t;

/*
 * Flags for the take command
 */
#define	TAKE_FORCE	0x0001
#define	TAKE_USETAG	0x0002
#define	TAKE_USEIT	0x0004
#define	TAKE_IMP	0x0008
#define	TAKE_RETAKE	0x0010

/*
 * ignore gettext for lint so we check printf args
 */
#ifdef __lint
#define	dgettext(d, s)	s
#define	gettext(s)	s
#endif

/*
 * Defines for enabling/disabling SVM services in SMF.
 */
#define	META_SMF_CORE		0x01
#define	META_SMF_DISKSET	0x02
#define	META_SMF_MN_DISKSET	0x04
#define	META_SMF_ALL		0xFF

/*
 * Defines to send/not_send addition of mddb sidenames to
 * rpc.mdcommd for MN disksets.
 */
#define	DB_ADDSIDENMS_NO_BCAST	0
#define	DB_ADDSIDENMS_BCAST	1

/*
 * Defines and structures to support rpc.mdcommd.
 * RPC routines in rpc.metad will be used to suspend, resume
 * and reinitialize the rpc.mdcommd running on that node.
 * These actions are needed when the nodelist is changing.
 */
#define	COMMDCTL_SUSPEND	1
#define	COMMDCTL_RESUME		2
#define	COMMDCTL_REINIT		3

/*
 * Defines used when joining a node to a MN diskset.
 * A MN diskset is stale if < 50% mddbs are available when the first node
 * joins the set.  A MN diskset is stale when 50% mddbs are available when
 * the first node joins the set if the mediator is unable to provide an
 * extra vote.
 * Once a MN set is marked stale, it stays in the stale state (even if > 50%
 * mddbs are available) until all nodes are withdrawn from the diskset.
 * Any new nodes joining a stale MN diskset are marked stale regardless of
 * the availability of mddbs in order to keep the diskset consistent across
 * all nodes.
 *
 * If a reconfig cycle is underway, set the reconfig flag so that rpc.metad
 * clnt_locks are not enforced.  Since the reconfig cycle has locked out the
 * meta* commands, this is safe to do.
 */
#define	MNSET_IS_STALE		1	/* Is MN set stale? */
#define	MNSET_IN_RECONFIG	2	/* Is MN set in reconfig? */

/*
 * Structure used during reconfig step2 to aid in sychronization
 * of the drives in a diskset.
 */
typedef struct md_mnsr_node {
	md_mnset_record		*mmn_mnsr;
	md_mnnode_nm_t		mmn_nodename;
	int			mmn_numdrives;
	md_drive_desc		*mmn_dd;
	struct md_mnsr_node	*mmn_next;
} md_mnsr_node_t;


/*
 * meta events definitions ("meta_notify.h")
 */

/*
 * event flags
 * meta_notify_createq(),	(EXISTERR, PERMANENT)
 * meta_notify_getev(),		(WAIT)
 * meta_notify_getevlist()	(WAIT)
 */
#define	EVFLG_WAIT	0x00000001	/* block until events are pending */
#define	EVFLG_EXISTERR	0x00000002	/* if q exists, return an error */
#define	EVFLG_PERMANENT	0x00000004	/* queue persists after process exit */

/*
 * events are always associated with an underlying object
 * This object is of one of the following types.
 */
typedef enum md_ev_objtype_t {
	EVO_EMPTY	= 0,
	EVO_METADEV,
	EVO_MIRROR,
	EVO_STRIPE,
	EVO_RAID5,
	EVO_TRANS,
	EVO_REPLICA,
	EVO_HSP,
	EVO_HS,
	EVO_SET,
	EVO_DRIVE,
	EVO_HOST,
	EVO_MEDIATOR,
	EVO_UNSPECIFIED,
	EVO_LAST
} ev_obj_t;

/*
 * Specific events are sent upon state changes
 * in the underlying devices or when sent by
 * user applications. These events have a unique
 * type. These types map to kernel event types (sys/md_notify.h)
 *
 * When updating these UPDATE THE TABLE in lib/config/config.c
 */
typedef enum md_ev_id_t {
	EV_UNK = 0,
	EV_EMPTY,
	EV_CREATE,
	EV_DELETE,
	EV_ADD,
	EV_REMOVE,
	EV_REPLACE,
	EV_GROW,
	EV_RENAME_SRC,
	EV_RENAME_DST,
	EV_MEDIATOR_ADD,
	EV_MEDIATOR_DELETE,
	EV_HOST_ADD,
	EV_HOST_DELETE,
	EV_DRIVE_ADD,
	EV_DRIVE_DELETE,
	EV_INIT_START,
	EV_INIT_FAILED,
	EV_INIT_FATAL,
	EV_INIT_SUCCESS,
	EV_IOERR,
	EV_ERRED,
	EV_LASTERRED,
	EV_OK,
	EV_ENABLE,
	EV_RESYNC_START,
	EV_RESYNC_FAILED,
	EV_RESYNC_SUCCESS,
	EV_RESYNC_DONE,
	EV_HOTSPARED,
	EV_HS_FREED,
	EV_HS_CHANGED,
	EV_TAKEOVER,
	EV_RELEASE,
	EV_OPEN_FAIL,
	EV_OFFLINE,
	EV_ONLINE,
	EV_GROW_PENDING,
	EV_DETACH,
	EV_DETACHING,
	EV_ATTACH,
	EV_ATTACHING,
	EV_CHANGE,
	EV_EXCHANGE,
	EV_REGEN_START,
	EV_REGEN_DONE,
	EV_REGEN_FAILED,
	EV_USER,
	EV_NOTIFY_LOST,
	EV_LAST
} evid_t;

#define	EV_ALLOBJS	(~0ULL)
#define	EV_ALLSETS	((set_t)(~0))

#if !defined(_KERNEL)

#define	NOTIFY_MD(tag, set, dev, ev)					\
	(void) meta_notify_sendev((tag), (set), (dev), (ev))

#define	SE_NOTIFY(se_class, se_subclass, tag, set, dev)			\
	meta_svm_sysevent((se_class), (se_subclass), (tag), (set), (dev))

#endif /* _KERNEL */

typedef struct md_ev {
	ev_obj_t	obj_type;
	set_t		setno;
	evid_t		ev;
	u_longlong_t	obj;	/* usually md_dev64_t or hsp id */
	u_longlong_t	uev;	/* for (EV_USER) user-defined events */
} md_ev_t;

typedef struct md_evlist {
	struct md_evlist	*next;
	md_ev_t			*evp;
} md_evlist_t;

/* end of meta event definitions ("meta_notify.h") */

typedef struct md_im_names {
	int	min_count;
	char	**min_names;
} md_im_names_t;

/* Values for replica info status */
#define	MD_IM_REPLICA_SCANNED	(0x01)
#define	MD_IM_REPLICA_VALID	(0x02)

typedef struct md_im_replica_info {
	struct md_im_replica_info	*mir_next;
	int				mir_status;
	int				mir_flags;
	daddr32_t			mir_offset;
	daddr32_t			mir_length;
	md_timeval32_t			mir_timestamp;
} md_im_replica_info_t;

typedef struct md_im_drive_info {
	struct md_im_drive_info		*mid_next; /* next drive in this set */
	mddrivename_t			*mid_dnp;
	void 				*mid_devid;
	void				*mid_o_devid;
	int				mid_devid_sz;
	int				mid_o_devid_sz;
	char				mid_minor_name[MDDB_MINOR_NAME_MAX];
	minor_t				mid_mnum;
	int				mid_available;
	md_timeval32_t			mid_setcreatetimestamp;
	char				*mid_driver_name;
	char				*mid_devname;
	md_im_replica_info_t		*mid_replicas;
	int				overlapped_disk;
	struct md_im_drive_info		*overlap; /* chain of overlap disks */
} md_im_drive_info_t;

/* Values for mid_available */
#define	MD_IM_DISK_AVAILABLE		0x00
#define	MD_IM_DISK_NOT_AVAILABLE	0x01

/* Values for set descriptor flags */
#define	MD_IM_SET_INVALID	0x10
#define	MD_IM_SET_REPLICATED	0x20

/* Values for mis_partial */
#define	MD_IM_COMPLETE_DISKSET	0x04
#define	MD_IM_PARTIAL_DISKSET	0x08

typedef struct md_im_set_desc {
	struct md_im_set_desc		*mis_next;
	int				mis_flags;
	int				mis_oldsetno;
	md_im_drive_info_t		*mis_drives;
	int				mis_active_replicas;
	int				mis_partial;
} md_im_set_desc_t;

/* meta_admin.c */
extern	int		open_admin(md_error_t *ep);
extern	int		close_admin(md_error_t *ep);
extern	int		meta_dev_ismeta(md_dev64_t dev);
extern	int		meta_get_nunits(md_error_t *ep);
extern	md_dev64_t	metamakedev(minor_t mnum);

/* meta_attach.c */
extern	int		meta_concat_generic(mdsetname_t *sp, mdname_t *namep,
			    u_longlong_t big_or_little, md_error_t *ep);
extern	int		meta_concat_parent(mdsetname_t *sp, mdname_t *childnp,
			    md_error_t *ep);

/* meta_check.c */
extern	int		meta_check_inuse(mdsetname_t *sp, mdname_t *np,
			    mdinuseopts_t inuse_flag, md_error_t *ep);
extern	int		meta_check_driveinset(mdsetname_t *sp,
			    mddrivename_t *dnp, md_error_t *ep);
extern	int		meta_check_drivemounted(mdsetname_t *sp,
			    mddrivename_t *dnp, md_error_t *ep);
extern	int		meta_check_driveswapped(mdsetname_t *sp,
			    mddrivename_t *dnp, md_error_t *ep);
extern	int		meta_check_samedrive(mdname_t *np1, mdname_t *np2,
			    md_error_t *ep);
extern	int		meta_check_overlap(char *uname, mdname_t *np1,
			    diskaddr_t slblk1, diskaddr_t nblks1, mdname_t *np2,
			    diskaddr_t slblk2, diskaddr_t nblks2,
			    md_error_t *ep);
extern	int		meta_check_inmeta(mdsetname_t *sp, mdname_t *np,
			    mdchkopts_t options, diskaddr_t slblk,
			    diskaddr_t nblks,
			    md_error_t *ep);
extern	int		meta_check_inset(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern  int		meta_check_root(md_error_t *ep);


/* meta_db.c */
extern	char		*meta_devid_encode_str(ddi_devid_t devid,
			    char *minor_name);
extern	void		meta_devid_encode_str_free(char *devidstr);
extern	int		meta_devid_decode_str(char *devidstr,
			    ddi_devid_t *devidp, char **minor_namep);
extern	int		meta_check_inreplica(mdsetname_t *sp, mdname_t *np,
			    diskaddr_t slblk, diskaddr_t nblks, md_error_t *ep);
extern	int		meta_check_replica(mdsetname_t *sp, mdname_t *np,
			    mdchkopts_t options, diskaddr_t slblk,
			    diskaddr_t nblks, md_error_t *ep);
extern	int		meta_db_addsidenms(mdsetname_t *sp, mdname_t *np,
			    daddr_t blkno, int bcast, md_error_t *ep);
extern	int		meta_db_delsidenm(mdsetname_t *sp, side_t sideno,
			    mdname_t *np, daddr_t blkno, md_error_t *ep);
extern	int		meta_db_patch(char *sname, char *cname, int patch,
			    md_error_t *ep);
extern	int		meta_db_attach(mdsetname_t *sp, mdnamelist_t *db_nlp,
			    mdchkopts_t options, md_timeval32_t *timeval,
			    int dbcnt, int dbsize, char *sysfilename,
			    md_error_t *ep);
extern	int		meta_db_detach(mdsetname_t *sp, mdnamelist_t *db_nlp,
			    mdforceopts_t force, char *sysfilename,
			    md_error_t *ep);
extern	void		metafreereplicalist(md_replicalist_t *rlp);
extern	int		metareplicalist(mdsetname_t *sp, int flags,
			    md_replicalist_t **rlpp, md_error_t *ep);
extern	void		meta_sync_db_locations(mdsetname_t *sp,
			    md_error_t *ep);
extern	int		meta_setup_db_locations(md_error_t *ep);
extern	daddr_t		meta_db_minreplica(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_get_replica_names(mdsetname_t *,
			    mdnamelist_t **, int options, md_error_t *);
extern	void		meta_mkdummymaster(mdsetname_t *sp, int fd,
			    daddr_t firstblk);
extern md_timeval32_t	meta_get_lb_inittime(mdsetname_t *sp, md_error_t *ep);

/* meta_db_balance.c */
extern	int		meta_db_balance(mdsetname_t *sp, md_drive_desc *opdd,
			    md_drive_desc *curdd, daddr_t dbsize,
			    md_error_t *ep);

/* metadevstamp.c */
extern 	int		getdevstamp(mddrivename_t *dnp, time_t *stamp,
			    md_error_t *ep);
extern 	int		setdevstamp(mddrivename_t *dnp, time_t *stamp,
			    md_error_t *ep);

/* meta_error.c */
extern	int		metaioctl(int cmd, void *data, md_error_t *ep,
			    char *name);
extern	void		md_logpfx(FILE *fp);
/* PRINTFLIKE2 */
extern	char		*mde_sperror(md_error_t *mdep, const char *fmt, ...);
/* PRINTFLIKE2 */
extern	void		mde_perror(md_error_t *mdep, const char *fmt, ...);
/* PRINTFLIKE1 */
extern	void		md_perror(const char *fmt, ...);
/* PRINTFLIKE1 */
extern	void		md_eprintf(const char *fmt, ...);
extern	void		meta_mc_log(int level, const char *fmt, ...);

/* meta_getdevs.c */
extern	minor_t		meta_getminor(md_dev64_t dev64);
extern	major_t		meta_getmajor(md_dev64_t dev64);
extern	md_dev64_t	meta_expldev(md_dev64_t dev);
extern	dev32_t		meta_cmpldev(md_dev64_t dev64);

extern	int		meta_fix_compnames(mdsetname_t *sp,
			    mdname_t *namep, md_dev64_t dev, md_error_t *ep);
extern	int		meta_getdevs(mdsetname_t *sp, mdname_t *namep,
			    mdnamelist_t **nlpp, md_error_t *ep);
extern	int		meta_getalldevs(mdsetname_t *sp, mdnamelist_t **nlpp,
			    int check_db, md_error_t *ep);
extern	int		meta_getvtoc(int fd, char *devname,
			    struct vtoc *vtocbufp, int *partno,
			    md_error_t *ep);
extern	int		meta_setvtoc(int fd, char *devname,
			    struct vtoc *vtocbufp, md_error_t *ep);
extern	int		meta_setmdvtoc(int fd, char *devname,
			    mdvtoc_t *mdvtocbufp, md_error_t *ep);
extern	int		meta_get_names(char *drivername, mdsetname_t *sp,
			    mdnamelist_t **nlpp, mdprtopts_t options,
			    md_error_t *ep);
extern	int		meta_deviceid_to_nmlist(char *search_path,
			    ddi_devid_t devid, char *minor_name,
			    devid_nmlist_t **retlist);

/* meta_hotspares.c */
extern	int		meta_get_hsp_names(mdsetname_t *sp,
			    mdhspnamelist_t **hspnlpp, int options,
			    md_error_t *ep);
extern	void		meta_free_hsp(md_hsp_t *hspp);
extern	void		meta_invalidate_hsp(mdhspname_t *hspnp);
extern	md_hsp_t	*meta_get_hsp(mdsetname_t *sp, mdhspname_t *hspnp,
			    md_error_t *ep);
extern	md_hsp_t	*meta_get_hsp_common(mdsetname_t *sp,
			    mdhspname_t *hspnp, int fast, md_error_t *ep);
extern	int		meta_check_inhsp(mdsetname_t *sp, mdname_t *np,
			    diskaddr_t slblk, diskaddr_t nblks, md_error_t *ep);
extern	int		meta_check_hotspare(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	char		*hs_state_to_name(md_hs_t *hsp,
			    md_timeval32_t *tvp);
extern	int		meta_hsp_print(mdsetname_t *sp, mdhspname_t *hspnp,
			    mdnamelist_t **nlpp, char *fname, FILE *fp,
			    mdprtopts_t options, md_error_t *ep);
extern	int		metachkhsp(mdsetname_t *sp, mdhspname_t *hspnp,
			    md_error_t *ep);
extern	int		meta_hs_add(mdsetname_t *sp, mdhspname_t *hspnp,
			    mdnamelist_t *nlp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_hs_delete(mdsetname_t *sp, mdhspname_t *hspnp,
			    mdnamelist_t *nlp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_hs_replace(mdsetname_t *sp, mdhspname_t *hspnp,
			    mdname_t *oldnp, mdname_t *newnp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_hs_enable(mdsetname_t *sp, mdnamelist_t *nlp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_check_hsp(mdsetname_t *sp, md_hsp_t *hspp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_create_hsp(mdsetname_t *sp, md_hsp_t *hspp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_init_hsp(mdsetname_t **spp,
			    int argc, char *argv[], mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_hsp_reset(mdsetname_t *sp, mdhspname_t *hspnp,
			    mdcmdopts_t options, md_error_t *ep);

/* meta_init.c */
extern	int		parse_interlace(char *uname, char *name,
			    diskaddr_t *interlacep, md_error_t *ep);
extern	int		meta_cook_syntax(md_error_t *ep,
			    md_void_errno_t errcode, char *uname,
			    int argc, char *argv[]);
extern	int		meta_setup_geom(md_unit_t *md, mdname_t *np,
			    mdgeom_t *geomp, uint_t write_reinstruct,
			    uint_t read_reinstruct, uint_t round_cyl,
			    md_error_t *ep);
extern	int		meta_adjust_geom(md_unit_t *md, mdname_t *np,
			    uint_t write_reinstruct, uint_t read_reinstruct,
			    uint_t round_cyl, md_error_t *ep);
extern	int		meta_init_name(mdsetname_t **spp, int argc,
			    char *argv[], char *cname, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_check_devicesize(diskaddr_t total_blocks);
extern	int		meta_init_make_device(mdsetname_t **spp, char *uname,
			    md_error_t *ep);
extern mdinittypes_t	meta_get_init_type(int argc, char *argv[]);

/* meta_mdcf.c */
extern	int		meta_update_md_cf(mdsetname_t *sp, md_error_t *ep);

/* meta_med.c */
extern	int		meddstealerror(md_error_t *ep, med_err_t *medep);
extern	int		clnt_med_null(char *hostname, md_error_t *ep);
extern	int		clnt_med_upd_data(md_h_t *mdhp, mdsetname_t *sp,
			    med_data_t *meddp, md_error_t *ep);
extern	int		clnt_med_get_data(md_h_t *mdhp, mdsetname_t *sp,
			    med_data_t *meddp, md_error_t *ep);
extern	int		clnt_med_get_rec(md_h_t *mdhp, mdsetname_t *sp,
			    med_rec_t *medrp, md_error_t *ep);
extern	int		clnt_med_upd_rec(md_h_t *mdhp, mdsetname_t *sp,
			    med_rec_t *medrp, md_error_t *ep);
extern	int		clnt_med_hostname(char *hostname, char **ret_hostname,
			    md_error_t *ep);
extern	int		clnt_user_med_upd_data(md_h_t *mdhp, bool_t obandiskset,
			    char *setname, uint_t setnum, med_data_t *meddp,
			    md_error_t *ep);
extern	int		clnt_user_med_get_data(md_h_t *mdhp, bool_t obandiskset,
			    char *setname, uint_t setnum, med_data_t  *meddp,
			    md_error_t *ep);

extern	int		meta_med_hnm2ip(md_hi_arr_t *mp, md_error_t *ep);
extern	int		meta_h2hi(md_h_arr_t *mdhp, md_hi_arr_t *mdhip,
			    md_error_t *ep);
extern	int		meta_hi2h(md_hi_arr_t *mdhip, md_h_arr_t *mdhp,
			    md_error_t *ep);
extern	int		setup_med_cfg(mdsetname_t *sp, mddb_config_t *cp,
			    int force, md_error_t *ep);
extern	int		meta_mediator_info_from_file(char *sname, int verbose,
			    md_error_t *ep);

/* meta_mem.c */
#ifdef	_DEBUG_MALLOC_INC
extern	void		*_Malloc(char *file, int line, size_t s);
extern	void		*_Zalloc(char *file, int line, size_t s);
extern	void		*_Realloc(char *file, int line, void *p, size_t s);
extern	void		*_Calloc(char *file, int line, size_t n, size_t s);
extern	char		*_Strdup(char *file, int line, char *p);
extern	void		_Free(char *file, int line, void *p);
#define	Malloc(s)	_Malloc(__FILE__, __LINE__, (s))
#define	Zalloc(s)	_Zalloc(__FILE__, __LINE__, (s))
#define	Realloc(p, s)	_Realloc(__FILE__, __LINE__, (p), (s))
#define	Calloc(n, s)	_Calloc(__FILE__, __LINE__, (n), (s))
#define	Strdup(p)	_Strdup(__FILE__, __LINE__, (p))
#define	Free(p)		_Free(__FILE__, __LINE__, (p))
#else	/* ! _DEBUG_MALLOC_INC */
extern	void		*Malloc(size_t s);
extern	void		*Zalloc(size_t s);
extern	void		*Realloc(void *p, size_t s);
extern	void		*Calloc(size_t n, size_t s);
extern	char		*Strdup(char *p);
extern	void		Free(void *p);
#endif	/* ! _DEBUG_MALLOC_INC */

/* meta_metad.c */
extern	int		clnt_adddrvs(char *hostname, mdsetname_t *sp,
			    md_drive_desc *dd, md_timeval32_t timestamp,
			    ulong_t genid, md_error_t *ep);
extern	int		clnt_addhosts(char *hostname, mdsetname_t *sp,
			    int node_c, char **node_v, md_error_t *ep);
extern	int		clnt_update_namespace(char *hostname, mdsetname_t *sp,
			    side_t side, mddrivename_t *dnp, char *newname,
			    md_error_t *ep);
extern	int		clnt_add_drv_sidenms(char *hostname, char *this_host,
			    mdsetname_t *sp, md_set_desc *sd, int node_c,
			    char **node_v, md_error_t *ep);
extern	int		clnt_createset(char *hostname, mdsetname_t *sp,
			    md_node_nm_arr_t nodes, md_timeval32_t timestamp,
			    ulong_t genid, md_error_t *ep);
extern	int		clnt_mncreateset(char *hostname, mdsetname_t *sp,
			    md_mnnode_desc *nodelist, md_timeval32_t timestamp,
			    ulong_t genid, md_node_nm_t master_nodenm,
			    int master_nodeid, md_error_t *ep);
extern	int		clnt_joinset(char *hostname, mdsetname_t *sp,
			    int flags, md_error_t *ep);
extern	int		clnt_withdrawset(char *hostname, mdsetname_t *sp,
			    md_error_t *ep);
extern	int		clnt_deldrvs_by_devid(char *hostname, mdsetname_t *sp,
			    md_drive_desc *dd, md_error_t *ep);
extern	int		clnt_deldrvs(char *hostname, mdsetname_t *sp,
			    md_drive_desc *dd, md_error_t *ep);
extern	int		clnt_delhosts(char *hostname, mdsetname_t *sp,
			    int node_c, char **node_v, md_error_t *ep);
extern	int		clnt_delset(char *hostname, mdsetname_t *sp,
			    md_error_t *ep);
extern	int		clnt_del_drv_sidenms(char *hostname, mdsetname_t *sp,
			    md_error_t *ep);
extern	int		clnt_devinfo(char *hostname, mdsetname_t *sp,
			    mddrivename_t *dp, md_dev64_t *ret_dev,
			    time_t *ret_timestamp, md_error_t *ep);
extern	int		clnt_devid(char *hostname, mdsetname_t *sp,
			    mddrivename_t *dp, char **ret_encdevid,
			    md_error_t *ep);
extern	int		clnt_devinfo_by_devid(char *hostname, mdsetname_t *sp,
			    char *devidstr, md_dev64_t *retdev,
			    char *orig_devname, char **ret_devname,
			    char **ret_driver, md_error_t *ep);
extern	int		clnt_drvused(char *hostname, mdsetname_t *sp,
			    mddrivename_t *dp, md_error_t *ep);
extern	void		free_sr(md_set_record *sr);
extern	int		clnt_getset(char *hostname, char *setname, set_t setno,
			    md_set_record **sr, md_error_t *ep);
extern	int		clnt_mngetset(char *hostname, char *setname,
			    set_t setno, md_mnset_record **mnsr,
			    md_error_t *ep);
extern	int		clnt_hostname(char *hostname, char **ret_hostname,
			    md_error_t *ep);
extern	int		clnt_nullproc(char *hostname, md_error_t *ep);
extern	int		clnt_ownset(char *hostname, mdsetname_t *sp,
			    int *ret_bool, md_error_t *ep);
extern	int		clnt_setnameok(char *hostname, mdsetname_t *sp,
			    int *ret_bool, md_error_t *ep);
extern	int		clnt_setnumbusy(char *hostname, set_t setno,
			    int *ret_bool, md_error_t *ep);
extern	int		clnt_upd_dr_dbinfo(char *hostname, mdsetname_t *sp,
			    md_drive_desc *dd, md_error_t *ep);
extern	int		clnt_stimeout(char *hostname, mdsetname_t *sp,
			    mhd_mhiargs_t *mhiargsp, md_error_t *ep);
extern	int		clnt_gtimeout(char *hostname, mdsetname_t *sp,
			    mhd_mhiargs_t *ret_mhiargs, md_error_t *ep);
extern	int		clnt_upd_dr_flags(char *hostname, mdsetname_t *sp,
			    md_drive_desc *dd, uint_t new_flags,
			    md_error_t *ep);
extern	int		clnt_enable_sr_flags(char *hostname, mdsetname_t *sp,
			    uint_t new_flags, md_error_t *ep);
extern	int		clnt_disable_sr_flags(char *hostname, mdsetname_t *sp,
			    uint_t new_flags, md_error_t *ep);
extern	int		clnt_upd_sr_flags(char *hostname, mdsetname_t *sp,
			    uint_t new_flags, md_error_t *ep);
extern	int		clnt_upd_nr_flags(char *hostname, mdsetname_t *sp,
			    md_mnnode_desc *nd, uint_t flag_action,
			    uint_t flags, md_error_t *ep);
extern	int		clnt_unlock_set(char *hostname, md_setkey_t *cl_sk,
			    md_error_t *ep);
extern	int		clnt_lock_set(char *hostname, mdsetname_t *sp,
			    md_error_t *ep);
extern	int		clnt_updmeds(char *hostname, mdsetname_t *sp,
			    md_h_arr_t *meddp, md_error_t *ep);
extern  int		clnt_resnarf_set(char *hostname, set_t setno,
			    md_error_t *ep);
extern	md_setkey_t	*cl_get_setkey(set_t setno, char *setname);
extern	void		cl_set_setkey(md_setkey_t *cl_sk);
extern	void		meta_conv_drvname_new2old(o_mddrivename_t *,
			    mddrivename_t *);
extern	void		meta_conv_drvname_old2new(o_mddrivename_t *,
			    mddrivename_t *);
extern	void		meta_conv_drvdesc_new2old(o_md_drive_desc *,
			    md_drive_desc *);
extern	void		meta_conv_drvdesc_old2new(o_md_drive_desc *,
			    md_drive_desc *);
extern  void 		alloc_olddrvdesc(o_md_drive_desc **, md_drive_desc *);
extern  void 		alloc_newdrvdesc(o_md_drive_desc *, md_drive_desc **);
extern  void		free_olddrvdesc(o_md_drive_desc *);
extern  void		free_newdrvdesc(md_drive_desc *);
extern	char		*meta_get_devid(char *);
extern	int		clnt_mnsetmaster(char *hostname, mdsetname_t *sp,
			    md_node_nm_t master_nodenm, int master_nodeid,
			    md_error_t *ep);
extern	int		clnt_clr_mnsetlock(char *hostname, md_error_t *ep);
extern	int		clnt_mdcommdctl(char *hostname, int flag_action,
			    mdsetname_t *sp, md_mn_msgclass_t class,
			    uint_t flags, md_error_t *ep);
extern	int		clnt_mn_is_stale(char *hostname, mdsetname_t *sp,
			    int *ret_bool, md_error_t *ep);
extern	int		clnt_getdrivedesc(char *hostname, mdsetname_t *sp,
			    md_drive_desc **dd, md_error_t *ep);
extern	void		free_rem_dd(md_drive_desc *dd);
extern	int		clnt_upd_dr_reconfig(char *hostname, mdsetname_t *sp,
			    md_drive_desc *dd, md_error_t *ep);
extern	int		clnt_reset_mirror_owner(char *hostname, mdsetname_t *sp,
			    int node_c, int *node_id, md_error_t *ep);
extern	int		clnt_mn_susp_res_io(char *hostname, set_t setno,
			    int flag, md_error_t *ep);
extern	int		clnt_mn_mirror_resync_all(char *hostname, set_t setno,
			    md_error_t *ep);
extern	int		clnt_mn_sp_update_abr(char *hostname, set_t setno,
			    md_error_t *ep);

/* meta_metad_subr.c */
extern	mddb_userreq_t	*get_db_rec(md_ur_get_cmd_t cmd, set_t setno,
			    mddb_type_t type, uint_t type2, mddb_recid_t *idp,
			    md_error_t *ep);
extern	void		*get_ur_rec(set_t setno, md_ur_get_cmd_t cmd,
			    uint_t type2, mddb_recid_t *idp, md_error_t *ep);
extern	void		sr_validate(void);
extern	void		sr_del_drv(md_set_record *sr, mddb_recid_t recid);
extern	int		set_snarf(md_error_t *ep);
extern	void		sr_cache_add(md_set_record *sr);
extern	void		sr_cache_del(mddb_recid_t recid);
extern	void		dr_cache_add(md_set_record *sr, md_drive_record *dr);
extern	void		dr_cache_del(md_set_record *sr, mddb_recid_t recid);
extern	void		mnnr_cache_add(md_mnset_record *sr,
			    md_mnnode_record *nr);
extern	void		mnnr_cache_del(md_mnset_record *sr, mddb_recid_t recid);
extern	int		metad_isautotakebyname(char *setname);
extern	int		metad_isautotakebynum(set_t setno);
extern	md_set_record	*metad_getsetbyname(char *setname, md_error_t *ep);
extern	md_set_record	*metad_getsetbynum(set_t setno, md_error_t *ep);
extern	void		commitset(md_set_record *sr, int inc_genid,
			    md_error_t *ep);
extern	md_set_record	*setdup(md_set_record *sr);
extern	md_mnset_record	*mnsetdup(md_mnset_record *mnsr);
extern	md_drive_record	*drdup(md_drive_record *dr);
extern	md_mnnode_record *nrdup(md_mnnode_record *nr);
extern	md_drive_desc	*dd_list_dup(md_drive_desc *dd);
extern	void		sr_cache_flush(int flushnames);
extern	void		sr_cache_flush_setno(set_t setno);
extern	void		s_delset(char *setname, md_error_t *ep);
extern	void		s_delrec(mddb_recid_t recid, md_error_t *ep);
extern	int		s_ownset(set_t setno, md_error_t *ep);
extern	int		resnarf_set(set_t setno, md_error_t *ep);

/* meta_mh.c */
extern	mhd_mhiargs_t	defmhiargs;
extern	int		meta_take_own(char *sname, mddrivenamelist_t *dnlp,
			    mhd_mhiargs_t *mhiargsp, int partial_set,
			    md_error_t *ep);
extern	int		tk_own_bydd(mdsetname_t *sp, md_drive_desc *dd,
			    mhd_mhiargs_t *mhiargsp, int partial_set,
			    md_error_t *ep);
extern	int		meta_rel_own(char *sname, mddrivenamelist_t *dnlp,
			    int partial_set, md_error_t *ep);
extern	int		rel_own_bydd(mdsetname_t *sp, md_drive_desc *dd,
			    int partial_set, md_error_t *ep);
extern	int		meta_status_own(char *sname,
			    md_disk_status_list_t *dslp, int partial_set,
			    md_error_t *ep);
extern	md_disk_status_list_t *meta_drive_to_disk_status_list(
			    mddrivenamelist_t *dnlp);
extern	void		meta_free_disk_status_list(md_disk_status_list_t *dslp);
extern	void		meta_free_drive_info_list(mhd_drive_info_list_t *listp);
extern	int		meta_list_drives(char *hostname, char *path,
			    mhd_did_flags_t flags,
			    mhd_drive_info_list_t *listp, md_error_t *ep);
extern	int		meta_get_drive_names(mdsetname_t *sp,
			    mddrivenamelist_t **dnlpp, int options,
			    md_error_t *ep);

/* meta_mirror.c */
extern	int		meta_get_mirror_names(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
extern	void		meta_free_mirror(md_mirror_t *mirrorp);
extern	md_mirror_t	*meta_get_mirror(mdsetname_t *sp, mdname_t *mirnp,
			    md_error_t *ep);
extern	int		meta_check_inmirror(mdsetname_t *sp, mdname_t *np,
			    diskaddr_t slblk, diskaddr_t nblks, md_error_t *ep);
extern	int		meta_check_submirror(mdsetname_t *sp, mdname_t *np,
			    mdname_t *mirnp, int force, md_error_t *ep);
extern	char		*rd_opt_to_name(mm_rd_opt_t opt);
extern	int		name_to_rd_opt(char *uname, char *name,
			    mm_rd_opt_t *optp, md_error_t *ep);
extern	char		*wr_opt_to_name(mm_wr_opt_t opt);
extern	int		name_to_wr_opt(char *uname, char *name,
			    mm_wr_opt_t *optp, md_error_t *ep);
extern	int		name_to_pass_num(char *uname, char *name,
			    mm_pass_num_t *passp, md_error_t *ep);
extern	char		*sm_state_to_name(md_submirror_t *mdsp,
			    md_status_t mirror_status, md_timeval32_t *tvp,
			    uint_t tstate);
extern	int		sm_state_to_action(mdsetname_t *sp,
			    md_submirror_t *mdsp, md_status_t mirror_status,
			    md_mirror_t *mirrorp, char **actionp,
			    md_error_t *ep);
extern	int		meta_print_mirror_options(mm_rd_opt_t read_options,
			    mm_wr_opt_t write_option, mm_pass_num_t pass_num,
			    uint_t tstate, char *fname,
			    mdsetname_t *sp, FILE *fp, md_error_t *ep);
extern	int		meta_mirror_print(mdsetname_t *sp, mdname_t *mirnp,
			    mdnamelist_t **nlpp, char *fname, FILE *fp,
			    mdprtopts_t options, md_error_t *ep);
extern	int		meta_mirror_online(mdsetname_t *sp, mdname_t *mirnp,
			    mdname_t *submirnp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_mirror_offline(mdsetname_t *sp, mdname_t *mirnp,
			    mdname_t *submirnp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_mirror_attach(mdsetname_t *sp, mdname_t *mirnp,
			    mdname_t *submirnp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_mirror_detach(mdsetname_t *sp, mdname_t *mirnp,
			    mdname_t *submirnp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_mirror_get_params(mdsetname_t *sp,
			    mdname_t *mirnp, mm_params_t *paramsp,
			    md_error_t *ep);
extern	int		meta_mirror_set_params(mdsetname_t *sp,
			    mdname_t *mirnp, mm_params_t *paramsp,
			    md_error_t *ep);
extern	int		meta_mirror_replace(mdsetname_t *sp, mdname_t *mirnp,
			    mdname_t *oldnp, mdname_t *newnp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_mirror_enable(mdsetname_t *sp, mdname_t *mirnp,
			    mdname_t *compnp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_check_mirror(mdsetname_t *sp,
			    md_mirror_t *mirrorp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_create_mirror(mdsetname_t *sp,
			    md_mirror_t *mirrorp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_init_mirror(mdsetname_t **spp,
			    int argc, char *argv[], mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_mirror_reset(mdsetname_t *sp, mdname_t *mirnp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_mirror_anycomp_is_err(mdsetname_t *,
			    mdnamelist_t *);

/* meta_mirror_resync.c */
extern	int		meta_mirror_resync(mdsetname_t *sp, mdname_t *mirnp,
			    daddr_t size, md_error_t *ep, md_resync_cmd_t cmd);
extern	int		meta_mirror_resync_all(mdsetname_t *sp, daddr_t size,
			    md_error_t *ep);
extern	void		*meta_mn_mirror_resync_all(void *arg);
extern	void		meta_mirror_resync_kill_all(void);
extern	void		meta_mirror_resync_block_all(void);
extern	void		meta_mirror_resync_unblock_all(void);
extern	void		meta_mirror_resync_unblock(mdsetname_t *sp);
extern	void		meta_mirror_resync_kill(mdsetname_t *sp);

/* meta_mount.c */
extern	char		*meta_get_mountp(mdsetname_t *, mdname_t *,
			    md_error_t *);

/* meta_name.c */
extern  char		*meta_name_getname(mdsetname_t **spp, char *uname,
			    meta_device_type_t uname_type, md_error_t *ep);
extern	char		*meta_canonicalize(mdsetname_t *sp, char *uname);
extern	char		*meta_canonicalize_check_set(mdsetname_t **sp,
			    char *uname, md_error_t *ep);
extern	int		meta_is_all(char *uname);
extern	int		is_existing_metadevice(mdsetname_t *sp, char *uname);
extern	int		is_existing_hsp(mdsetname_t *sp, char *uname);
extern	int		is_existing_meta_hsp(mdsetname_t *sp, char *uname);
extern	int		is_metaname(char *uname);
extern	int		meta_is_none(char *uname);
extern	int		is_hspname(char *uname);
extern	int		parse_ctd(char *uname, uint_t *slice);
extern	void		parse_device(mdsetname_t *, char *, char **, char **);
extern	md_set_desc	*sr2setdesc(md_set_record *sr);
extern	mdsetname_t	*metasetname(char *sname, md_error_t *ep);
extern	mdsetname_t	*metasetnosetname(set_t setno, md_error_t *ep);
extern	mdsetname_t	*metafakesetname(set_t setno, char *sname);
extern	md_set_desc	*metaget_setdesc(mdsetname_t *sp, md_error_t *ep);
extern	void		metaflushsetname(mdsetname_t *sp);
extern	void		metaflushdrivenames(void);
extern	int		metaislocalset(mdsetname_t *sp);
extern	int		metaissameset(mdsetname_t *sp1, mdsetname_t *sp2);
extern	void		metaflushsidenames(mddrivename_t *dnp);
extern	char		*metadiskname(char *name);
extern	mddrivename_t	*metadrivename(mdsetname_t **spp, char *uname,
			    md_error_t *ep);
extern	mddrivename_t	*metadrivenamebydevid(mdsetname_t **spp, char *devid,
			    char *uname, md_error_t *ep);
extern	mdname_t	*metaslicename(mddrivename_t *dnp, uint_t sliceno,
			    md_error_t *ep);
extern	void		metafreedrivename(mddrivename_t *dnp);
extern	void		metafreedrivenamelist(mddrivenamelist_t *dnlp);
extern	int		metadrivenamelist(mdsetname_t **spp,
			    mddrivenamelist_t **dnlpp,
			    int argc, char *argv[], md_error_t *ep);
extern	mddrivename_t	*metadrivenamelist_append(mddrivenamelist_t **dnlpp,
			    mddrivename_t *dnp);
extern  mddrivenamelist_t	**meta_drivenamelist_append_wrapper(
				    mddrivenamelist_t **dnlpp,
				    mddrivename_t *dnp);
extern	int		meta_getdev(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	mdname_t	*metaname_fast(mdsetname_t **spp, char *uname,
			    meta_device_type_t uname_type, md_error_t *ep);
extern	mdname_t	*metaname(mdsetname_t **spp, char *uname,
			    meta_device_type_t uname_type, md_error_t *ep);
extern	mdname_t	*metamnumname(mdsetname_t **spp, minor_t mnum,
			    int fast, md_error_t *ep);
extern	char		*get_mdname(mdsetname_t *sp, minor_t mnum);
extern	int		metaismeta(mdname_t *np);
extern	int		metachkmeta(mdname_t *np, md_error_t *ep);
extern	int		metachkdisk(mdname_t *np, md_error_t *ep);
extern	int		metachkcomp(mdname_t *np, md_error_t *ep);
extern	void		metafreenamelist(mdnamelist_t *nlp);
extern	int		metanamelist(mdsetname_t **spp, mdnamelist_t **nlpp,
			    int argc, char *argv[], meta_device_type_t type,
			    md_error_t *ep);
extern	mdname_t	*metanamelist_append(mdnamelist_t **nlpp,
			    mdname_t *np);
extern  mdnamelist_t	**meta_namelist_append_wrapper(mdnamelist_t **nlpp,
			    mdname_t *np);
extern	mdhspname_t	*metahspname(mdsetname_t **spp,
			    char *uname, md_error_t *ep);
extern	mdhspname_t	*metahsphspname(mdsetname_t **spp,
			    hsp_t hsp, md_error_t *ep);
extern	char		*get_hspname(mdsetname_t *sp, hsp_t mnum);
extern	void		metafreehspnamelist(mdhspnamelist_t *hspnlp);
extern	int		metahspnamelist(mdsetname_t **spp,
			    mdhspnamelist_t **hspnlpp,
			    int argc, char *argv[], md_error_t *ep);
extern	mdhspname_t	*metahspnamelist_append(mdhspnamelist_t **hspnlp,
			    mdhspname_t *hspnp);
extern	mdname_t	*metadevname(mdsetname_t **spp,
			    md_dev64_t dev, md_error_t *ep);
extern	char		*get_devname(set_t setno, md_dev64_t dev);
extern	mdname_t	*metakeyname(mdsetname_t **spp,
			    mdkey_t key, int fast, md_error_t *ep);
extern	void		metaflushmetanames(void);
extern	void		metaflushnames(int flush_sr_cache);
extern	int		meta_get_hotspare_names(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
extern	void		meta_create_non_dup_list(mdname_t *mdnp,
			    mddevid_t **ldevidpp);
extern	mddrivename_t	*meta_getdnp_bydevid(mdsetname_t *sp, side_t sideno,
			    ddi_devid_t devidp, mdkey_t key, md_error_t *ep);


/* meta_nameinfo.c */
extern	mdsetname_t	*metagetset(mdname_t *np, int bypass_daemon,
			    md_error_t *ep);
extern	void		metafreevtoc(mdvtoc_t *vtocp);
extern	int		meta_match_enclosure(mdname_t *, mdcinfo_t *,
			    md_error_t *);
extern	mdvtoc_t	*metagetvtoc(mdname_t *np, int nocache, uint_t *partnop,
			    md_error_t *ep);
extern	int		metasetvtoc(mdname_t *np, md_error_t *ep);
extern	void		metaflushctlrcache(void);
extern	mdgeom_t	*metagetgeom(mdname_t *np, md_error_t *ep);
extern	mdcinfo_t	*metagetcinfo(mdname_t *np, md_error_t *ep);
extern	int		metagetpartno(mdname_t *np, md_error_t *ep);
extern	diskaddr_t	metagetsize(mdname_t *np, md_error_t *ep);
extern	diskaddr_t	metagetlabel(mdname_t *np, md_error_t *ep);
extern	diskaddr_t	metagetstart(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	int		metahasmddb(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	char		*metagetdevicesname(mdname_t *np, md_error_t *ep);
extern	char		*metagetmiscname(mdname_t *np, md_error_t *ep);
extern	md_unit_t	*meta_get_mdunit(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	void		meta_free_unit(mddrivename_t *dnp);
extern	void		meta_invalidate_name(mdname_t *np);
extern	md_common_t	*meta_get_unit(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	int		meta_isopen(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep, mdcmdopts_t options);

/* meta_namespace.c */
extern	char		*meta_getnmbykey(set_t setno, side_t sideno,
			    mdkey_t key, md_error_t *ep);
extern	char		*meta_getnmentbykey(set_t setno, side_t sideno,
			    mdkey_t key, char **drvnm, minor_t *mnum,
			    md_dev64_t *dev, md_error_t *ep);
extern	char		*meta_getnmentbydev(set_t setno, side_t sideno,
			    md_dev64_t dev, char **drvnm, minor_t *mnum,
			    mdkey_t *key, md_error_t *ep);
extern	char		*meta_gethspnmentbyid(set_t setno, side_t sideno,
			    hsp_t hspid, md_error_t *ep);
extern	hsp_t		meta_gethspnmentbyname(set_t setno, side_t sideno,
			    char *hspname, md_error_t *ep);
extern	char		*meta_getdidminorbykey(set_t setno, side_t sideno,
			    mdkey_t key, md_error_t *ep);
extern	ddi_devid_t	meta_getdidbykey(set_t setno, side_t sideno,
			    mdkey_t key, md_error_t *ep);
extern	int		meta_setdid(set_t setno, side_t sideno, mdkey_t key,
			    md_error_t *ep);
extern	int		add_name(mdsetname_t *sp, side_t sideno, mdkey_t key,
			    char *dname, minor_t mnum, char *bname,
			    char *minorname, ddi_devid_t devid, md_error_t *ep);
extern	int		del_name(mdsetname_t *sp, side_t sideno, mdkey_t key,
			    md_error_t *ep);
extern	int		add_key_name(mdsetname_t *sp, mdname_t *np,
			    mdnamelist_t **nlpp, md_error_t *ep);
extern	int		del_key_name(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	int		del_key_names(mdsetname_t *sp, mdnamelist_t *nlp,
			    md_error_t *ep);
extern	mdkey_t		add_self_name(mdsetname_t *, char *,
			    md_mkdev_params_t *, md_error_t *);
extern	int		del_self_name(mdsetname_t *, mdkey_t,
			    md_error_t *);

/* meta_patch.c */
extern	int		meta_patch_vfstab(char *cmpname, mdname_t *fsnp,
			    char *vname, char *old_bdevname, int doit,
			    int verbose, char **tname, md_error_t *ep);
extern	int		meta_patch_fsdev(char *fsname, mdname_t *fsnp,
			    char *vname, md_error_t *ep);
extern	int		meta_patch_swapdev(mdname_t *fsnp,
			    char *vname, char *old_bdevname, md_error_t *ep);
extern	int		meta_patch_mddb(char *sname, char *cname, int patch,
			    md_error_t *ep);

/* meta_patch_root.c */
extern	int		meta_patch_rootdev(mdname_t *np, char *sname,
			    char *vname, char *cname, char *dbname, int doit,
			    int verbose, md_error_t *ep);

/* meta_print.c */
extern	int		meta_print_name(mdsetname_t *sp, mdname_t *namep,
			    mdnamelist_t **nlpp, char *fname, FILE *fp,
			    mdprtopts_t options, mdnamelist_t **lognlpp,
			    md_error_t *ep);
extern	int		meta_print_all(mdsetname_t *sp, char *fname,
			    mdnamelist_t **nlpp, FILE *fp,
			    mdprtopts_t options, int *meta_print_trans_msgp,
			    md_error_t *ep);
extern	char		*meta_print_time(md_timeval32_t *timep);
extern	char		*meta_print_hrtime(hrtime_t secs);
extern	int		meta_prbits(FILE *fp, const char *fmt, ...);
extern	char 		*meta_number_to_string(diskaddr_t number,
			    u_longlong_t blk_sz);
extern	int		meta_get_tstate(md_dev64_t dev64, uint_t *tstatep,
			    md_error_t *ep);
extern	int		meta_print_devid(mdsetname_t *sp, FILE *fp,
			    mddevid_t *mddevidp, md_error_t *ep);

/* meta_raid.c */
extern	int		meta_raid_check_component(mdsetname_t *sp,
			    mdname_t *np, md_dev64_t dev, md_error_t *ep);
extern	int		meta_get_raid_names(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
extern	void		meta_free_raid(md_raid_t *raidp);
extern	md_raid_t	*meta_get_raid_common(mdsetname_t *sp, mdname_t *raidnp,
			    int fast, md_error_t *ep);
extern	md_raid_t	*meta_get_raid(mdsetname_t *sp, mdname_t *raidnp,
			    md_error_t *ep);
extern	int		meta_check_inraid(mdsetname_t *sp, mdname_t *np,
			    diskaddr_t slblk, diskaddr_t nblks, md_error_t *ep);
extern	int		meta_check_column(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	char		*raid_state_to_name(md_raid_t *raidp,
			    md_timeval32_t *tvp, uint_t tstate);
extern	char		*raid_state_to_action(md_raid_t *raidp);
extern	char		*raid_col_state_to_name(md_raidcol_t *colp,
			    md_timeval32_t *tvp, uint_t tstate);
extern	int		meta_print_raid_options(mdhspname_t *hspnamep,
			    char *fname, FILE *fp, md_error_t *ep);
extern	int		meta_raid_print(mdsetname_t *sp, mdname_t *raidnp,
			    mdnamelist_t **nlpp, char *fname, FILE *fp,
			    mdprtopts_t options, md_error_t *ep);
extern	int		meta_raid_attach(mdsetname_t *sp, mdname_t *raidnp,
			    mdnamelist_t *nlp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_raid_get_params(mdsetname_t *sp, mdname_t *raidnp,
			    mr_params_t *paramsp, md_error_t *ep);
extern	int		meta_raid_set_params(mdsetname_t *sp, mdname_t *raidnp,
			    mr_params_t *paramsp, md_error_t *ep);
extern	int		meta_raid_replace(mdsetname_t *sp, mdname_t *raidnp,
			    mdname_t *oldnp, mdname_t *newnp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_raid_enable(mdsetname_t *sp, mdname_t *raidnp,
			    mdname_t *compnp, mdcmdopts_t options,
			    md_error_t *ep);
extern	diskaddr_t		meta_default_raid_interlace(void);
extern	int		meta_raid_check_interlace(diskaddr_t interlace,
			    char *uname, md_error_t *ep);
extern	int		meta_check_raid(mdsetname_t *sp, md_raid_t *raidp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_create_raid(mdsetname_t *sp, md_raid_t *raidp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_init_raid(mdsetname_t **spp,
			    int argc, char *argv[], mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_raid_reset(mdsetname_t *sp, mdname_t *np,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_raid_anycomp_is_err(mdsetname_t *, mdnamelist_t *);

/* meta_raid_resync.c */
extern	int		meta_raid_resync(mdsetname_t *sp, mdname_t *raidnp,
			    daddr_t size, md_error_t *ep);
extern	int		meta_raid_resync_all(mdsetname_t *sp, daddr_t size,
			    md_error_t *ep);

extern	int		meta_raid_regen_byname(mdsetname_t *sp,
			    mdname_t *raidnp, diskaddr_t size, md_error_t *ep);

/* meta_repartition.c */
extern	int		meta_replicaslice(mddrivename_t *dnp,
			    uint_t *slicep, md_error_t *ep);

/* meta_replace.c */
extern	int		meta_replace_byname(mdsetname_t *sp, mdname_t *namep,
			    mdname_t *oldnp, mdname_t *newnp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_enable_byname(mdsetname_t *sp, mdname_t *namep,
			    mdname_t *compnp, mdcmdopts_t options,
			    md_error_t *ep);

/* meta_reset.c */
extern	int		meta_reset(mdsetname_t *sp, mdname_t *np,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_reset_all(mdsetname_t *sp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_reset_by_name(mdsetname_t *sp, mdname_t *np,
			    mdcmdopts_t options, md_error_t *ep);

/* meta_resync.c */
extern	int		meta_resync_byname(mdsetname_t *sp, mdname_t *np,
			    daddr_t size, md_error_t *ep, md_resync_cmd_t cmd);
extern	int		meta_resync_all(mdsetname_t *sp, daddr_t size,
			    md_error_t *ep);

/* meta_set.c */
extern	set_t		get_max_sets(md_error_t *ep);
extern	int		get_max_meds(md_error_t *ep);
extern	side_t		getmyside(mdsetname_t *sp, md_error_t *ep);
extern	md_set_record	*getsetbyname(char *setname, md_error_t *ep);
extern	md_set_record	*getsetbynum(set_t setno, md_error_t *ep);
extern	int		meta_check_drive_inuse(mdsetname_t *sp,
			    mddrivename_t *dnp, int check_db, md_error_t *ep);
extern	int		meta_check_ownership(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_check_ownership_on_host(mdsetname_t *sp,
			    char *hostname, md_error_t *ep);
extern	int		meta_is_member(char *node_name, md_mn_nodeid_t node_id,
			    mndiskset_membershiplist_t *nl);
extern	int		meta_getnextside_devinfo(mdsetname_t *sp, char *bname,
			    side_t *sideno, char **ret_bname, char **ret_dname,
			    minor_t *ret_mnum, md_error_t *ep);
extern	int		meta_getside_devinfo(mdsetname_t *sp, char *bname,
			    side_t sideno, char **ret_bname, char **ret_dname,
			    minor_t *ret_mnum, md_error_t *ep);
extern	int		meta_is_drive_in_anyset(mddrivename_t *dnp,
			    mdsetname_t **spp, int bypass_daemon,
			    md_error_t *ep);
extern	int		meta_is_drive_in_thisset(mdsetname_t *sp,
			    mddrivename_t *dnp, int bypass_daemon,
			    md_error_t *ep);
extern	int		meta_is_devid_in_anyset(void *devid,
			    mdsetname_t **spp, md_error_t *ep);
extern	int		meta_is_devid_in_thisset(mdsetname_t *sp,
			    void *devid, md_error_t *ep);
extern	int		meta_set_balance(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_set_destroy(mdsetname_t *sp, int lock_set,
			    md_error_t *ep);
extern	int		meta_set_purge(mdsetname_t *sp, int bypass_cluster,
			    int forceflg, md_error_t *ep);
extern	int		meta_set_query(mdsetname_t *sp, mddb_dtag_lst_t **dtlpp,
			    md_error_t *ep);
extern	mddrivename_t	*metadrivename_withdrkey(mdsetname_t *sp,
			    side_t sideno, mdkey_t key, int flags,
			    md_error_t *ep);
extern	void		metafreedrivedesc(md_drive_desc **dd);
extern	md_drive_desc	*metaget_drivedesc(mdsetname_t *sp, int flags,
			    md_error_t *ep);
extern	md_drive_desc	*metaget_drivedesc_fromnamelist(mdsetname_t *sp,
			    mdnamelist_t *nlp, md_error_t *ep);
extern	md_drive_desc	*metaget_drivedesc_sideno(mdsetname_t *sp,
			    side_t sideno, int flags, md_error_t *ep);
extern	int		metaget_setownership(mdsetname_t *sp, md_error_t *ep);
extern	char		*mynode(void);
extern	int		strinlst(char *str, int cnt, char **lst);
extern	int		meta_get_reserved_names(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
extern	int		meta_set_join(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_set_withdraw(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_reconfig_choose_master();
extern	int		meta_mnsync_user_records(mdsetname_t *sp,
			    md_error_t *ep);
extern	int		meta_mnsync_diskset_mddbs(mdsetname_t *sp,
			    md_error_t *ep);
extern	int		meta_mnjoin_all(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_getandsetmaster(mdsetname_t *sp,
			    md_mnset_record *mnsr, md_set_desc *sd,
			    md_error_t *ep);
extern	int		meta_devid_use(md_error_t *ep);

/* meta_set_drv.c */
extern	int		meta_make_sidenmlist(mdsetname_t *,
			    mddrivename_t *, int imp_flag,
			    md_im_drive_info_t *midp, md_error_t *);
extern	int		meta_set_adddrives(mdsetname_t *sp,
			    mddrivenamelist_t *dnlp, daddr_t dbsize,
			    int force_label, md_error_t *ep);
extern	int		meta_set_deletedrives(mdsetname_t *sp,
			    mddrivenamelist_t *dnlp, int forceflg,
			    md_error_t *ep);

/* meta_set_hst.c */
extern	int		meta_set_checkname(char *setname, md_error_t *ep);
extern	int		meta_set_addhosts(mdsetname_t *sp, int multi_node,
			    int node_c, char **node_v, int auto_take,
			    md_error_t *ep);
extern	int		meta_set_deletehosts(mdsetname_t *sp, int node_c,
			    char **node_v, int forceflg, md_error_t *ep);
extern	int		meta_set_auto_take(mdsetname_t *sp, int take_val,
			    md_error_t *ep);

/* meta_set_med.c */
extern	int		meta_set_addmeds(mdsetname_t *sp, int node_c,
			    char **node_v, md_error_t *ep);
extern	int		meta_set_deletemeds(mdsetname_t *sp, int node_c,
			    char **node_v, int forceflg, md_error_t *ep);

/* meta_set_tkr.c */
extern	int		meta_set_take(mdsetname_t *sp, mhd_mhiargs_t *mhiargsp,
			    int flags, int usetag, md_error_t *ep);
extern	int		meta_set_release(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_update_mb(mdsetname_t *sp, md_drive_desc *dd,
			    md_error_t *ep);

/* meta_setup.c */
extern	char		*myname;
extern	FILE		*metalogfp;
extern	int		metasyslog;
extern	uint_t		verbosity;
extern	hrtime_t	start_time;
extern	sigset_t	allsigs;
#define	ANYSIG		allsigs
extern	char		*meta_lock_name(set_t setno);
extern	int		meta_unlock(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_lock(mdsetname_t *sp, int print_status,
			    md_error_t *ep);
extern	int		meta_lock_nowait(mdsetname_t *sp, md_error_t *ep);
extern	int		meta_lock_status(mdsetname_t *sp, md_error_t *ep);
extern	int		md_daemonize(mdsetname_t *sp, md_error_t *ep);
extern	void		md_exit(mdsetname_t *sp, int eval);
extern	void		md_post_sig(int sig);
extern	int		md_got_sig(void);
extern	int		md_which_sig(void);
extern	void		md_rb_sig_handling_on(void);
extern	void		md_rb_sig_handling_off(int sig_seen, int sig);
extern	void		setup_mc_log(uint_t level);
extern	int		md_init(int argc, char *argv[],
			    int dosyslog, int doadmin, md_error_t *ep);
extern	int		md_init_nosig(int argc, char *argv[],
			    int dosyslog, int doadmin, md_error_t *ep);

extern	int		md_init_daemon(char *name, md_error_t *ep);

/* meta_smf.c */
extern	int		meta_smf_enable(uint_t flags, md_error_t *ep);
extern	int		meta_smf_disable(uint_t flags, md_error_t *ep);
extern	int		meta_smf_isonline(uint_t flags, md_error_t *ep);
extern	int		meta_smf_getmask();

/* meta_sp.c */
extern	int		meta_sp_check_component(mdsetname_t *sp,
			    mdname_t *np, md_error_t *ep);
extern	int		meta_get_sp_names(mdsetname_t *sp, mdnamelist_t **nlpp,
			    int options, md_error_t *ep);
extern	int		meta_check_insp(mdsetname_t *sp, mdname_t *np,
			    diskaddr_t slblk, diskaddr_t nblks, md_error_t *ep);
extern	int		meta_sp_print(mdsetname_t *sp, mdname_t *np,
			    mdnamelist_t **nlpp, char *fname, FILE *fp,
			    mdprtopts_t options, md_error_t *ep);
extern	md_sp_t		*meta_get_sp_common(mdsetname_t *sp, mdname_t *np,
			    int fast, md_error_t *ep);
extern	md_sp_t		*meta_get_sp(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	int		meta_init_sp(mdsetname_t **spp, int argc, char *argv[],
			    mdcmdopts_t options, md_error_t *ep);
extern	void		meta_free_sp(md_sp_t *spp);
extern	int		meta_sp_issp(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	int		meta_sp_reset(mdsetname_t *sp, mdname_t *np,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_sp_reset_component(mdsetname_t *sp, char *name,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_sp_attach(mdsetname_t *sp, mdname_t *np,
			    char *addsize, mdcmdopts_t options,
			    sp_ext_length_t alignment, md_error_t *ep);
extern	int		meta_recover_sp(mdsetname_t *sp, mdname_t *np, int argc,
			    char *argv[], mdcmdopts_t options, md_error_t *ep);
extern boolean_t	meta_sp_can_create_sps(mdsetname_t *mdsetnamep,
				mdname_t *mdnamep, int number_of_sps,
				blkcnt_t sp_size);
extern boolean_t	meta_sp_can_create_sps_on_drive(mdsetname_t *mdsetnamep,
				mddrivename_t *mddrivenamep, int number_of_sps,
				blkcnt_t sp_size);
extern blkcnt_t		meta_sp_get_free_space(mdsetname_t *mdsetnamep,
				mdname_t *mdnamep);
extern blkcnt_t		meta_sp_get_free_space_on_drive(mdsetname_t *mdsetnamep,
				mddrivename_t *mddrivenamep);
extern int 		meta_sp_get_number_of_possible_sps(
				mdsetname_t *mdsetnamep, mdname_t *mdnamep,
				blkcnt_t sp_size);
extern int 		meta_sp_get_number_of_possible_sps_on_drive(
				mdsetname_t *mdsetnamep,
				mddrivename_t *mddrivenamep, blkcnt_t sp_size);
extern blkcnt_t		meta_sp_get_possible_sp_size(mdsetname_t *mdsetnamep,
				mdname_t *mdnamep, int number_of_sps);
extern blkcnt_t		meta_sp_get_possible_sp_size_on_drive(
				mdsetname_t *mdsetnamep,
				mddrivename_t *mddrivenamep, int number_of_sps);
extern int		meta_sp_setstatus(mdsetname_t *sp, minor_t *minors,
			    int num_units, sp_status_t status, md_error_t *ep);
extern int		meta_sp_parsesize(char *s, sp_ext_length_t *szp);
extern int		meta_sp_update_abr(mdsetname_t *sp, md_error_t *ep);
extern void		*meta_mn_sp_update_abr(void *arg);

/* meta_stat.c */
extern	int		meta_stat(const char *, struct stat *);
extern	void		metaflushstatcache(void);

/* meta_stripe.c */
extern	int		meta_stripe_check_component(mdsetname_t *sp,
			    mdname_t *np, md_dev64_t dev, md_error_t *ep);
extern	int		meta_stripe_replace(mdsetname_t *sp, mdname_t *stripenp,
			    mdname_t *oldnp, mdname_t *newnp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_get_stripe_names(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
extern	void		meta_free_stripe(md_stripe_t *stripep);
extern	md_stripe_t	*meta_get_stripe_common(mdsetname_t *sp,
			    mdname_t *stripenp, int fast, md_error_t *ep);
extern	md_stripe_t	*meta_get_stripe(mdsetname_t *sp, mdname_t *stripenp,
			    md_error_t *ep);
extern	int		meta_check_instripe(mdsetname_t *sp, mdname_t *np,
			    diskaddr_t slblk, diskaddr_t nblks, md_error_t *ep);
extern	int		meta_check_component(mdsetname_t *sp, mdname_t *np,
			    int force, md_error_t *ep);
extern	char		*comp_state_to_name(md_comp_t *mdcp,
			    md_timeval32_t *tvp, uint_t tstate);
extern	int		meta_print_stripe_options(mdhspname_t *hspnamep,
			    char *fname, FILE *fp, md_error_t *ep);
extern	int		meta_stripe_print(mdsetname_t *sp, mdname_t *stripenp,
			    mdnamelist_t **nlpp, char *fname, FILE *fp,
			    mdprtopts_t options, md_error_t *ep);
extern	int		meta_find_erred_comp(mdsetname_t *sp,
			    mdname_t *stripenp, mdname_t **compnpp,
			    comp_state_t *compstate, md_error_t *ep);
extern	int		meta_stripe_attach(mdsetname_t *sp, mdname_t *stripenp,
			    mdnamelist_t *nlp, diskaddr_t interlace,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_stripe_get_params(mdsetname_t *sp,
			    mdname_t *stripenp, ms_params_t *paramsp,
			    md_error_t *ep);
extern	int		meta_stripe_set_params(mdsetname_t *sp,
			    mdname_t *stripenp, ms_params_t *paramsp,
			    md_error_t *ep);
extern	diskaddr_t		meta_default_stripe_interlace(void);
extern	int		meta_stripe_check_interlace(diskaddr_t interlace,
				char *uname, md_error_t *ep);
extern	int		meta_check_stripe(mdsetname_t *sp,
			    md_stripe_t *stripep, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_create_stripe(mdsetname_t *sp,
			    md_stripe_t *stripep, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_init_stripe(mdsetname_t **spp,
			    int argc, char *argv[], mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_stripe_reset(mdsetname_t *sp, mdname_t *stripenp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_stripe_anycomp_is_err(mdsetname_t *,
			    mdnamelist_t *);

/* meta_systemfile.c */
extern	int		meta_systemfile_copy(char *sname, int doroot,
			    int domddb, int doit, int verbose, char **tname,
			    FILE **tfp, md_error_t *ep);
extern	int		meta_systemfile_append_mdroot(mdname_t *rootnp,
			    char *sname, char *tname, FILE *tfp, int ismeta,
			    int doit, int verbose, md_error_t *ep);
extern	int		meta_systemfile_append_mddb(char *cname, char *sname,
			    char *tname, FILE *tfp, int doit, int verbose,
			    int check, md_error_t *ep);

/* meta_tab.c */
extern	void		meta_tab_dump(md_tab_t *tabp, FILE *fp);
extern	void		meta_tab_free(md_tab_t *tabp);
extern	md_tab_t	*meta_tab_parse(char *filename, md_error_t *ep);
extern	md_tab_line_t	*meta_tab_find(mdsetname_t *sp, md_tab_t *tabp,
			    char *name, mdinittypes_t type);

/* meta_trans.c */
extern	int		meta_trans_replace(mdsetname_t *sp, mdname_t *transnp,
			    mdname_t *oldnp, mdname_t *newnp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_get_trans_names(mdsetname_t *sp,
			    mdnamelist_t **nlpp, int options, md_error_t *ep);
extern	void		meta_free_trans(md_trans_t *transp);
extern	md_trans_t	*meta_get_trans(mdsetname_t *sp, mdname_t *transnp,
			    md_error_t *ep);
extern	md_trans_t	*meta_get_trans_common(mdsetname_t *sp,
			    mdname_t *transnp, int fast, md_error_t *ep);
extern	int		meta_check_intrans(mdsetname_t *sp, mdname_t *np,
			    mdchkopts_t options, diskaddr_t slblk,
			    diskaddr_t nblks, md_error_t *ep);
extern	int		meta_check_master(mdsetname_t *sp, mdname_t *np,
			    int force, md_error_t *ep);
extern	int		meta_check_log(mdsetname_t *sp, mdname_t *np,
			    md_error_t *ep);
extern	char		*mt_l_error_to_name(md_trans_t *transp,
			    md_timeval32_t *tvp, uint_t tstate);
extern	char		*mt_flags_to_name(md_trans_t *transp,
			    md_timeval32_t *tvp, uint_t tstate);
extern	char		*mt_flags_to_action(md_trans_t *transp);
extern	char		*mt_l_error_to_action(
				mdsetname_t	*sp,
				mdnamelist_t	*transnlp,
				mdname_t	*lognamep,
				md_error_t	*ep);
extern	int		meta_trans_print(mdsetname_t *sp, mdname_t *transnp,
			    mdnamelist_t **nlistpp, char *fname, FILE *fp,
			    mdprtopts_t options, int *meta_print_trans_msgp,
			    mdnamelist_t **lognlpp, md_error_t *ep);
extern	int		meta_logs_print(mdsetname_t *sp, mdnamelist_t *lognlp,
			    mdnamelist_t **nlistpp, char *fname, FILE *fp,
			    mdprtopts_t options, md_error_t *ep);
extern	int		meta_trans_attach(mdsetname_t *sp, mdname_t *transnp,
			    mdname_t *lognp, mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_trans_detach(mdsetname_t *sp, mdname_t *transnp,
			    mdcmdopts_t options, int *delayed, md_error_t *ep);
extern	int		meta_check_trans(mdsetname_t *sp, md_trans_t *transp,
			    mdcmdopts_t options, md_error_t *ep);
extern	int		meta_create_trans(mdsetname_t *sp, md_trans_t *transp,
			    mdcmdopts_t options, char *uname, md_error_t *ep);
extern	int		meta_init_trans(mdsetname_t **spp,
			    int argc, char *argv[], mdcmdopts_t options,
			    md_error_t *ep);
extern	int		meta_trans_reset(mdsetname_t *sp, mdname_t *transnp,
			    mdcmdopts_t options, md_error_t *ep);

/* meta_userflags.c */
extern int		meta_getuserflags(mdsetname_t *sp, mdname_t *np,
			    uint_t *userflags, md_error_t *ep);
extern int		meta_setuserflags(mdsetname_t *sp, mdname_t *np,
			    uint_t userflags, md_error_t *ep);

/* metarpcopen.c */
extern CLIENT		*meta_client_create_retry(char *hostname,
				clnt_create_func_t func, void *data,
				time_t tout, md_error_t *ep);
extern	CLIENT		*meta_client_create(char *host, rpcprog_t prognum,
				rpcvers_t version, char *nettype);
extern	CLIENT		*metarpcopen(char *hostname, long time_out,
			    md_error_t *ep);
extern	void		metarpcclose(CLIENT *clntp);
extern	void		metarpccloseall(void);
extern	int		cl_sto(CLIENT *clntp, char *hostname, long time_out,
			    md_error_t *ep);

/* metasplitname.c */
extern	int		splitname(char *devname, md_splitname *splitname);
extern	char		*splicename(md_splitname *splitname);

/* meta_notify.c */
extern	int		meta_notify_createq(char *qname, ulong_t flags,
			    md_error_t *ep);
extern	int		meta_notify_deleteq(char *qname, md_error_t *ep);
extern	int		meta_notify_validq(char *qname, md_error_t *ep);
extern	int		meta_notify_listq(char ***qnames, md_error_t *ep);
extern	int		meta_notify_flushq(char *qname, md_error_t *ep);

extern	int		meta_notify_getev(char *qname, ulong_t flags,
			    md_ev_t *evp, md_error_t *ep);
extern	int		meta_notify_getevlist(char *qname, ulong_t flags,
			    md_evlist_t **evlpp, md_error_t *ep);
extern	int		meta_notify_putev(md_ev_t *evp, md_error_t *ep);
extern	int		meta_notify_putevlist(md_evlist_t *evlistp,
			    md_error_t *ep);
extern	void		meta_notify_freeevlist(md_evlist_t *evlp);

extern	int		meta_notify_sendev(ev_obj_t tag, set_t set,
			    md_dev64_t dev, evid_t event);

extern	int		meta_exchange(mdsetname_t *, mdname_t *, mdname_t *,
			    mdcmdopts_t, md_error_t *);
extern	int		meta_rename(mdsetname_t *, mdname_t *, mdname_t *,
			    mdcmdopts_t, md_error_t *);
/* meta_se_notify.c */
extern  void		meta_svm_sysevent(char *se_class, char *se_subclass,
			    uint32_t tag, set_t setno, md_dev64_t devid);

/* metgetroot.c */
extern  void		*meta_get_current_root(md_error_t *ep);
extern  mdname_t	*meta_get_current_root_dev(mdsetname_t *sp,
			    md_error_t *ep);

/* meta_time.c */
extern  int		meta_gettimeofday(md_timeval32_t *tv);

/* meta_devadm.c */
extern	int		meta_update_namespace(set_t setno, side_t sideno,
			    char *devname, md_dev64_t dev, mdkey_t key,
			    char *pname, md_error_t *ep);
extern	int		meta_fixdevid(mdsetname_t *sp, mddevopts_t options,
			    char *diskname, md_error_t *ep);
extern	int		meta_upd_ctdnames(mdsetname_t **sp, set_t setno,
			    side_t sideno, mddrivename_t *dnp, char **newname,
			    md_error_t *ep);
extern  int		pathname_reload(mdsetname_t **sp, set_t setno,
			    md_error_t *ep);
extern	int		meta_update_devtree(minor_t mnum);

/* meta_mn_comm.c */
extern int		mdmn_send_message(set_t setno, md_mn_msgtype_t type,
			    uint_t flags, char *data, int size,
			    md_mn_result_t **resp, md_error_t *ep);
extern int		mdmn_send_message_with_msgid(set_t setno,
			    md_mn_msgtype_t type, uint_t flags, char *data,
			    int size, md_mn_result_t **resp,
			    md_mn_msgid_t *msgid, md_error_t *ep);
extern int		mdmn_create_msgid(md_mn_msgid_t *id);
extern int		mdmn_reinit_set(set_t setno, long timeout);
extern int		mdmn_resume(set_t setno, md_mn_msgclass_t class,
			    uint_t flags, long timeout);
extern int		mdmn_suspend(set_t setno, md_mn_msgclass_t class,
			    long timeout);
extern int		mdmn_msgtype_lock(md_mn_msgtype_t msgtype,
			    uint_t locktype);
extern void		mdmn_abort(void);
extern md_mn_result_t	*copy_result(md_mn_result_t *res);
extern void		free_result(md_mn_result_t *res);
extern md_mn_msg_t	*copy_msg(md_mn_msg_t *src, md_mn_msg_t *dest);

/* meta_import.c */
extern	int		read_master_block(md_error_t *ep, int fd, void *bp,
			    int bsize);
extern	int		read_database_block(md_error_t *, int, mddb_mb_t *, int,
			    void *, int);
extern	daddr_t		getphysblk(mddb_block_t, mddb_mb_t *);

extern	md_im_drive_info_t	*pick_good_disk(md_im_set_desc_t *misp);

extern	void		meta_unrslv_replicated_mb(mdsetname_t *sp,
			    md_drive_desc *dd, mddrivenamelist_t *dnlp,
			    md_error_t *ep);
extern	void		meta_unrslv_replicated_nm(mdsetname_t *sp,
			    md_drive_desc *dd, mddrivenamelist_t *dnlp,
			    md_error_t *ep);
extern  void *		replicated_list_lookup(uint_t devid_len,
			    void *old_devid);
extern  int		build_replicated_disks_list(md_error_t *ep,
			    mddrivenamelist_t *dnlp);

/*
 * pnm_rec is used to store the mapping from keys in the NM namespace
 * to actual physical devices.  The current name of a physical device, used
 * by a set that can be imported, can be retrieved by matching the did_key
 * (deviceID entry) in the DID_SHR_NM namespace to the min_devid_key in the
 * DID_NM namespace(the did_key to the min_key).  Then matching the min_key
 * in the DID_NM namespace to the n_key in the NM namespace.
 *
 * n_name is defined to be an array, so that only one malloc is needed for the
 * entire datastructure.
 */
typedef struct pnm_rec {
	mdkey_t		n_key;  /* The n_key/min_key value */
	struct pnm_rec	*next;
	ushort_t	n_namlen;
	char		n_name[1]; /* The name of the physical device */
} pnm_rec_t;

/* Indentation value for metaimport output */
#define	META_INDENT			4

/* Flags for metaimport reporting */
#define	META_IMP_REPORT		0x0001
#define	META_IMP_VERBOSE	0x0002
#define	META_IMP_PASS1		0x1000

extern	int			meta_list_disks(md_error_t *, md_im_names_t *);
extern	mddrivenamelist_t	*meta_prune_cnames(md_error_t *,
				    md_im_names_t *, int);
extern	int			meta_get_and_report_set_info(
				    mddrivenamelist_t *, md_im_set_desc_t **,
				    int, uint_t, int *, int,
				    md_im_drive_info_t *, md_error_t *);
extern	void			free_pnm_rec_list(pnm_rec_t **);
extern	int			meta_imp_set(md_im_set_desc_t *,
				    char *, int, bool_t, md_error_t *);
extern	int			meta_imp_drvused(mdsetname_t *sp,
				    mddrivename_t *dnp, md_error_t *ep);
extern	int			meta_replica_quorum(md_im_set_desc_t *misp);
extern	int			meta_imp_set_adddrives(mdsetname_t *sp,
				    mddrivenamelist_t *dnlp,
				    md_im_set_desc_t *misp, md_error_t *ep);
extern	void			meta_free_im_set_desc(md_im_set_desc_t *misp);
extern	int			clnt_imp_adddrvs(char *hostname,
				    mdsetname_t *sp, md_drive_desc *dd,
				    md_timeval32_t timestamp,
				    ulong_t genid, md_error_t *ep);

/* Flags for direction in copy_msg_1 */
#define	MD_MN_COPY_TO_ONDISK 0x0001
#define	MD_MN_COPY_TO_INCORE 0x0002

extern void		copy_msg_1(md_mn_msg_t *incorep,
			    md_mn_msg_od_t *ondiskp, int direction);
extern void		free_msg(md_mn_msg_t *msg);

extern md_mn_msgclass_t	mdmn_get_message_class(md_mn_msgtype_t msgtype);
extern void		(*mdmn_get_handler(md_mn_msgtype_t msgtype))
			    (md_mn_msg_t *msg, uint_t flags,
			    md_mn_result_t *res);
extern int		(*mdmn_get_submessage_generator(md_mn_msgtype_t type))
			    (md_mn_msg_t *msg, md_mn_msg_t **msglist);
extern time_t		mdmn_get_timeout(md_mn_msgtype_t msgtype);

extern	int		meta_read_nodelist(int *nodecnt,
			    mndiskset_membershiplist_t **nl, md_error_t *ep);
extern	int		meta_write_nodelist(int nodecnt, char **nids,
			    md_error_t *ep);
extern	void		meta_free_nodelist(mndiskset_membershiplist_t *nl);

/* meta_mn_subr.c */
/* defines for flags argument for meta_mn_send_command() */
#define	MD_DISP_STDERR			0x0000
#define	MD_IGNORE_STDERR		0x0001
#define	MD_DRYRUN			0x0002
#define	MD_RETRY_BUSY			0x0004
#define	MD_NOLOG			0x0008
#define	MD_PANIC_WHEN_INCONSISTENT	0x0010

/* define for initall_context argument for meta_mn_send_command() */
#define	NO_CONTEXT_STRING	NULL

extern int		meta_is_mn_set(mdsetname_t *sp, md_error_t *ep);
extern int		meta_is_mn_name(mdsetname_t **sp, char *name,
			    md_error_t *ep);
extern void		meta_ping_mnset(set_t setno);
extern int		meta_mn_send_command(mdsetname_t *sp, int argc,
			    char *argv[], int flags, char *initall_context,
			    md_error_t *ep);
extern int		meta_mn_send_suspend_writes(minor_t mnum,
			    md_error_t *ep);
extern int		meta_mn_send_setsync(mdsetname_t *sp,
			    mdname_t *mirnp, daddr_t size, md_error_t *ep);
extern int		meta_mn_send_metaclear_command(mdsetname_t *sp,
			    char *name, mdcmdopts_t options, int pflag,
			    md_error_t *ep);
extern int		meta_mn_send_resync_starting(mdname_t *mirnp,
			    md_error_t *ep);
extern int		meta_mn_change_owner(md_set_mmown_params_t **opp,
			    set_t setno, uint_t mnum, uint_t owner,
			    uint_t flags);
extern int		meta_mn_singlenode(void);
extern int		meta_mn_send_get_tstate(md_dev64_t dev, uint_t *tstatep,
			    md_error_t *ep);
/* meta_set_prv.c */
extern int		setup_db_bydd(mdsetname_t *sp, md_drive_desc *dd,
			    int force, md_error_t *ep);
extern int		snarf_set(mdsetname_t *sp, bool_t stale_bool,
			    md_error_t *ep);
extern int		halt_set(mdsetname_t *sp, md_error_t *ep);

/* meta_statconcise.c */
extern  void		print_concise_entry(int indent, char *name,
			    diskaddr_t size, char mtype);
extern	char		*meta_get_raid_col_state(rcs_state_t);
extern	char		*meta_get_stripe_state(comp_state_t);
extern	char		*meta_get_hs_state(hotspare_states_t);
extern	int		report_metastat_info(mddb_mb_t *, mddb_lb_t *,
			    mddb_rb_t *, pnm_rec_t **, mdname_t *, int,
			    md_timeval32_t *, md_error_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _META_H */
