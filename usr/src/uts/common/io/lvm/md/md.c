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

/*
 * Md - is the meta-disk driver.   It sits below the UFS file system
 * but above the 'real' disk drivers, xy, id, sd etc.
 *
 * To the UFS software, md looks like a normal driver, since it has
 * the normal kinds of entries in the bdevsw and cdevsw arrays. So
 * UFS accesses md in the usual ways.  In particular, the strategy
 * routine, mdstrategy(), gets called by fbiwrite(), ufs_getapage(),
 * and ufs_writelbn().
 *
 * Md maintains an array of minor devices (meta-partitions).   Each
 * meta partition stands for a matrix of real partitions, in rows
 * which are not necessarily of equal length.	Md maintains a table,
 * with one entry for each meta-partition,  which lists the rows and
 * columns of actual partitions, and the job of the strategy routine
 * is to translate from the meta-partition device and block numbers
 * known to UFS into the actual partitions' device and block numbers.
 *
 * See below, in mdstrategy(), mdreal(), and mddone() for details of
 * this translation.
 */

/*
 * Driver for Virtual Disk.
 */

#include <sys/user.h>
#include <sys/sysmacros.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/utsname.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_names.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_sp.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/cladm.h>
#include <sys/priv_names.h>
#include <sys/modhash.h>

#ifndef	lint
char 		_depends_on[] = "strmod/rpcmod";
#endif	/* lint */
int		md_init_debug	= 0;	/* module binding debug */

/*
 * Tunable to turn off the failfast behavior.
 */
int		md_ff_disable = 0;

/*
 * dynamically allocated list of non FF driver names - needs to
 * be freed when md is detached.
 */
char	**non_ff_drivers = NULL;

md_krwlock_t	md_unit_array_rw;	/* protects all unit arrays */
md_krwlock_t	nm_lock;		/* protects all the name spaces */

md_resync_t	md_cpr_resync;

extern char	svm_bootpath[];
#define	SVM_PSEUDO_STR	"/pseudo/md@0:"

#define		VERSION_LENGTH	6
#define		VERSION		"1.0"

/*
 * Keep track of possible 'orphan' entries in the name space
 */
int		*md_nm_snarfed = NULL;

/*
 * Global tunable giving the percentage of free space left in replica during
 * conversion of non-devid style replica to devid style replica.
 */
int		md_conv_perc = MDDB_DEVID_CONV_PERC;

#ifdef	DEBUG
/* debug code to verify framework exclusion guarantees */
int		md_in;
kmutex_t	md_in_mx;			/* used to md global stuff */
#define	IN_INIT		0x01
#define	IN_FINI		0x02
#define	IN_ATTACH	0x04
#define	IN_DETACH	0x08
#define	IN_OPEN		0x10
#define	MD_SET_IN(x) {						\
	mutex_enter(&md_in_mx);					\
	if (md_in)						\
		debug_enter("MD_SET_IN exclusion lost");	\
	if (md_in & x)						\
		debug_enter("MD_SET_IN already set");		\
	md_in |= x;						\
	mutex_exit(&md_in_mx);					\
}

#define	MD_CLR_IN(x) {						\
	mutex_enter(&md_in_mx);					\
	if (md_in & ~(x))					\
		debug_enter("MD_CLR_IN exclusion lost");	\
	if (!(md_in & x))					\
		debug_enter("MD_CLR_IN already clr");		\
	md_in &= ~x;						\
	mutex_exit(&md_in_mx);					\
}
#else	/* DEBUG */
#define	MD_SET_IN(x)
#define	MD_CLR_IN(x)
#endif	/* DEBUG */
hrtime_t savetime1, savetime2;


/*
 * list things protected by md_mx even if they aren't
 * used in this file.
 */
kmutex_t	md_mx;			/* used to md global stuff */
kcondvar_t	md_cv;			/* md_status events */
int		md_status = 0;		/* global status for the meta-driver */
int		md_num_daemons = 0;
int		md_ioctl_cnt = 0;
int		md_mtioctl_cnt = 0;	/* multithreaded ioctl cnt */
uint_t		md_mdelay = 10;		/* variable so can be patched */

int		(*mdv_strategy_tstpnt)(buf_t *, int, void*);

major_t		md_major, md_major_targ;

unit_t		md_nunits = MD_MAXUNITS;
set_t		md_nsets = MD_MAXSETS;
int		md_nmedh = 0;
char		*md_med_trans_lst = NULL;
md_set_t	md_set[MD_MAXSETS];
md_set_io_t	md_set_io[MD_MAXSETS];

md_krwlock_t	hsp_rwlp;		/* protects hot_spare_interface */
md_krwlock_t	ni_rwlp;		/* protects notify_interface */
md_ops_t	**md_ops = NULL;
ddi_modhandle_t	*md_mods = NULL;
md_ops_t	*md_opslist;
clock_t		md_hz;
md_event_queue_t	*md_event_queue = NULL;

int		md_in_upgrade;
int		md_keep_repl_state;
int		md_devid_destroy;

/* for sending messages thru a door to userland */
door_handle_t	mdmn_door_handle = NULL;
int		mdmn_door_did = -1;

dev_info_t		*md_devinfo = NULL;

md_mn_nodeid_t	md_mn_mynode_id = ~0u;	/* My node id (for multi-node sets) */

static	uint_t		md_ocnt[OTYPCNT];

static int		mdinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int		mdattach(dev_info_t *, ddi_attach_cmd_t);
static int		mddetach(dev_info_t *, ddi_detach_cmd_t);
static int		mdopen(dev_t *, int, int, cred_t *);
static int		mdclose(dev_t, int, int, cred_t *);
static int		mddump(dev_t, caddr_t, daddr_t, int);
static int		mdread(dev_t, struct uio *, cred_t *);
static int		mdwrite(dev_t, struct uio *, cred_t *);
static int		mdaread(dev_t, struct aio_req *, cred_t *);
static int		mdawrite(dev_t, struct aio_req *, cred_t *);
static int		mdioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int		mdprop_op(dev_t, dev_info_t *,
				ddi_prop_op_t, int, char *, caddr_t, int *);

static struct cb_ops md_cb_ops = {
	mdopen,			/* open */
	mdclose,		/* close */
	mdstrategy,		/* strategy */
				/* print routine -- none yet */
	(int(*)(dev_t, char *))nulldev,
	mddump,			/* dump */
	mdread,			/* read */
	mdwrite,		/* write */
	mdioctl,		/* ioctl */
				/* devmap */
	(int(*)(dev_t, devmap_cookie_t, offset_t, size_t, size_t *,
			uint_t))nodev,
				/* mmap */
	(int(*)(dev_t, off_t, int))nodev,
				/* segmap */
	(int(*)(dev_t, off_t, struct as *, caddr_t *, off_t, unsigned,
		unsigned, unsigned, cred_t *))nodev,
	nochpoll,		/* poll */
	mdprop_op,		/* prop_op */
	0,			/* streamtab */
	(D_64BIT|D_MP|D_NEW),	/* driver compatibility flag */
	CB_REV,			/* cb_ops version */
	mdaread,		/* aread */
	mdawrite,		/* awrite */
};

static struct dev_ops md_devops = {
	DEVO_REV,		/* dev_ops version */
	0,			/* device reference count */
	mdinfo,			/* info routine */
	nulldev,		/* identify routine */
	nulldev,		/* probe - not defined */
	mdattach,		/* attach routine */
	mddetach,		/* detach routine */
	nodev,			/* reset - not defined */
	&md_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* power management */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * loadable module wrapper
 */
#include <sys/modctl.h>

static struct modldrv modldrv = {
	&mod_driverops,			/* type of module -- a pseudodriver */
	"Solaris Volume Manager base module", /* name of the module */
	&md_devops,			/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};


/* md_medd.c */
extern	void	med_init(void);
extern	void	med_fini(void);
extern  void	md_devid_cleanup(set_t, uint_t);

/* md_names.c */
extern void			*lookup_entry(struct nm_next_hdr *, set_t,
					side_t, mdkey_t, md_dev64_t, int);
extern struct nm_next_hdr	*get_first_record(set_t, int, int);
extern int			remove_entry(struct nm_next_hdr *,
					side_t, mdkey_t, int);

int		md_maxphys	= 0;	/* maximum io size in bytes */
#define		MD_MAXBCOUNT	(1024 * 1024)
unsigned	md_maxbcount	= 0;	/* maximum physio size in bytes */

/*
 * Some md ioctls trigger io framework device tree operations.  An
 * example is md ioctls that call md_resolve_bydevid(): which uses the
 * io framework to resolve a devid. Such operations result in acquiring
 * io framework locks (like ndi_devi_enter() of "/") while holding
 * driver locks (like md_unit_writerlock()).
 *
 * The prop_op(9E) entry point is called from the devinfo driver with
 * an active ndi_devi_enter of "/". To avoid deadlock, md's prop_op
 * implementation must avoid taking a lock that is held per above md
 * ioctl description: i.e. mdprop_op(9E) can't call md_unit_readerlock()
 * without risking deadlock.
 *
 * To service "size" requests without risking deadlock, we maintain a
 * "mnum->nblocks" sizemap (protected by a short-term global mutex).
 */
static kmutex_t		md_nblocks_mutex;
static mod_hash_t	*md_nblocksmap;		/* mnum -> nblocks */
int			md_nblocksmap_size = 512;

/*
 * Maintain "mnum->nblocks" sizemap for mdprop_op use:
 *
 * Create: any code that establishes a unit's un_total_blocks needs the
 * following type of call to establish nblocks for mdprop_op():
 *	md_nblocks_set(mnum, un->c.un_total_blocks);"
 *	NOTE: locate via cscope md_create_minor_node/md_create_unit_incore
 *		...or  "MD_UNIT..*="
 *
 * Change: any code that changes a unit's un_total_blocks needs the
 * following type of call to sync nblocks for mdprop_op():
 *	md_nblocks_set(mnum, un->c.un_total_blocks);"
 *	NOTE: locate via cscope for "un_total_blocks[ \t]*="
 *
 * Destroy: any code that deletes a unit needs the following type of call
 * to sync nblocks for mdprop_op():
 *	md_nblocks_set(mnum, -1ULL);
 *	NOTE: locate via cscope md_remove_minor_node/md_destroy_unit_incore
 *		...or  "MD_UNIT..*="
 */
void
md_nblocks_set(minor_t mnum, uint64_t nblocks)
{
	mutex_enter(&md_nblocks_mutex);
	if (nblocks == -1ULL)
		(void) mod_hash_destroy(md_nblocksmap,
		    (mod_hash_key_t)(intptr_t)mnum);
	else
		(void) mod_hash_replace(md_nblocksmap,
		    (mod_hash_key_t)(intptr_t)mnum,
		    (mod_hash_val_t)(intptr_t)nblocks);
	mutex_exit(&md_nblocks_mutex);
}

/* get the size of a mnum from "mnum->nblocks" sizemap */
uint64_t
md_nblocks_get(minor_t mnum)
{
	mod_hash_val_t	hv;

	mutex_enter(&md_nblocks_mutex);
	if (mod_hash_find(md_nblocksmap,
	    (mod_hash_key_t)(intptr_t)mnum, &hv) == 0) {
		mutex_exit(&md_nblocks_mutex);
		return ((uint64_t)(intptr_t)hv);
	}
	mutex_exit(&md_nblocks_mutex);
	return (0);
}

/* allocate/free dynamic space associated with driver globals */
void
md_global_alloc_free(int alloc)
{
	set_t	s;

	if (alloc) {
		/* initialize driver global locks */
		cv_init(&md_cv, NULL, CV_DEFAULT, NULL);
		mutex_init(&md_mx, NULL, MUTEX_DEFAULT, NULL);
		rw_init(&md_unit_array_rw.lock, NULL, RW_DEFAULT, NULL);
		rw_init(&nm_lock.lock, NULL, RW_DEFAULT, NULL);
		rw_init(&ni_rwlp.lock, NULL, RW_DRIVER, NULL);
		rw_init(&hsp_rwlp.lock, NULL, RW_DRIVER, NULL);
		mutex_init(&md_cpr_resync.md_resync_mutex, NULL,
		    MUTEX_DEFAULT, NULL);
		mutex_init(&md_nblocks_mutex, NULL, MUTEX_DEFAULT, NULL);

		/* initialize per set driver global locks */
		for (s = 0; s < MD_MAXSETS; s++) {
			/* initialize per set driver globals locks */
			mutex_init(&md_set[s].s_dbmx,
			    NULL, MUTEX_DEFAULT, NULL);
			mutex_init(&md_set_io[s].md_io_mx,
			    NULL, MUTEX_DEFAULT, NULL);
			cv_init(&md_set_io[s].md_io_cv,
			    NULL, CV_DEFAULT, NULL);
		}
	} else {
		/* destroy per set driver global locks */
		for (s = 0; s < MD_MAXSETS; s++) {
			cv_destroy(&md_set_io[s].md_io_cv);
			mutex_destroy(&md_set_io[s].md_io_mx);
			mutex_destroy(&md_set[s].s_dbmx);
		}

		/* destroy driver global locks */
		mutex_destroy(&md_nblocks_mutex);
		mutex_destroy(&md_cpr_resync.md_resync_mutex);
		rw_destroy(&hsp_rwlp.lock);
		rw_destroy(&ni_rwlp.lock);
		rw_destroy(&nm_lock.lock);
		rw_destroy(&md_unit_array_rw.lock);
		mutex_destroy(&md_mx);
		cv_destroy(&md_cv);
	}
}

int
_init(void)
{
	set_t	s;
	int	err;

	MD_SET_IN(IN_INIT);

	/* allocate dynamic space associated with driver globals */
	md_global_alloc_free(1);

	/* initialize driver globals */
	md_major = ddi_name_to_major("md");
	md_hz = drv_usectohz(NUM_USEC_IN_SEC);

	/* initialize tunable globals */
	if (md_maxphys == 0)		/* maximum io size in bytes */
		md_maxphys = maxphys;
	if (md_maxbcount == 0)		/* maximum physio size in bytes */
		md_maxbcount = MD_MAXBCOUNT;

	/* initialize per set driver globals */
	for (s = 0; s < MD_MAXSETS; s++)
		md_set_io[s].io_state = MD_SET_ACTIVE;

	/*
	 * NOTE: the framework does not currently guarantee exclusion
	 * between _init and attach after calling mod_install.
	 */
	MD_CLR_IN(IN_INIT);
	if ((err = mod_install(&modlinkage))) {
		MD_SET_IN(IN_INIT);
		md_global_alloc_free(0);	/* free dynamic space */
		MD_CLR_IN(IN_INIT);
	}
	return (err);
}

int
_fini(void)
{
	int	err;

	/*
	 * NOTE: the framework currently does not guarantee exclusion
	 * with attach until after mod_remove returns 0.
	 */
	if ((err = mod_remove(&modlinkage)))
		return (err);

	MD_SET_IN(IN_FINI);
	md_global_alloc_free(0);	/* free dynamic space */
	MD_CLR_IN(IN_FINI);
	return (err);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
mdattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	len;
	unit_t	i;
	size_t	sz;
	char	ver[VERSION_LENGTH];
	char	**maj_str_array;
	char	*str, *str2;

	MD_SET_IN(IN_ATTACH);
	md_in_upgrade = 0;
	md_keep_repl_state = 0;
	md_devid_destroy = 0;

	if (cmd != DDI_ATTACH) {
		MD_CLR_IN(IN_ATTACH);
		return (DDI_FAILURE);
	}

	if (md_devinfo != NULL) {
		MD_CLR_IN(IN_ATTACH);
		return (DDI_FAILURE);
	}

	mddb_init();

	if (md_start_daemons(TRUE)) {
		MD_CLR_IN(IN_ATTACH);
		mddb_unload();		/* undo mddb_init() allocations */
		return (DDI_FAILURE);
	}

	/* clear the halted state */
	md_clr_status(MD_GBL_HALTED);

	/* see if the diagnostic switch is on */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "md_init_debug", 0))
		md_init_debug++;

	/* see if the failfast disable switch is on */
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "md_ff_disable", 0))
		md_ff_disable++;

	/* try and get the md_nmedh property */
	md_nmedh = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "md_nmedh", MED_DEF_HOSTS);
	if ((md_nmedh <= 0) || (md_nmedh > MED_MAX_HOSTS))
		md_nmedh = MED_DEF_HOSTS;

	/* try and get the md_med_trans_lst property */
	len = 0;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN,
	    0, "md_med_trans_lst", NULL, &len) != DDI_PROP_SUCCESS ||
	    len == 0) {
		md_med_trans_lst = md_strdup("tcp");
	} else {
		md_med_trans_lst = kmem_zalloc((size_t)len, KM_SLEEP);
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
		    0, "md_med_trans_lst", md_med_trans_lst, &len) !=
		    DDI_PROP_SUCCESS) {
			kmem_free(md_med_trans_lst, (size_t)len);
			md_med_trans_lst = md_strdup("tcp");
		}
	}

	/*
	 * Must initialize the internal data structures before the
	 * any possible calls to 'goto attach_failure' as _fini
	 * routine references them.
	 */
	med_init();

	md_ops = (md_ops_t **)kmem_zalloc(
	    sizeof (md_ops_t *) * MD_NOPS, KM_SLEEP);
	md_mods = (ddi_modhandle_t *)kmem_zalloc(
	    sizeof (ddi_modhandle_t) * MD_NOPS, KM_SLEEP);

	/* try and get the md_xlate property */
	/* Should we only do this if upgrade? */
	len = sizeof (char) * 5;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN_AND_VAL_BUF,
	    0, "md_xlate_ver", ver, &len) == DDI_PROP_SUCCESS) {
		if (strcmp(ver, VERSION) == 0) {
			len = 0;
			if (ddi_prop_op(DDI_DEV_T_ANY, dip,
			    PROP_LEN_AND_VAL_ALLOC, 0, "md_xlate",
			    (caddr_t)&md_tuple_table, &len) !=
			    DDI_PROP_SUCCESS) {
				if (md_init_debug)
					cmn_err(CE_WARN,
					    "md_xlate ddi_prop_op failed");
				goto attach_failure;
			} else {
				md_tuple_length =
				    len/(2 * ((int)sizeof (dev32_t)));
				md_in_upgrade = 1;
			}

			/* Get target's name to major table */
			if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY,
			    dip, DDI_PROP_DONTPASS,
			    "md_targ_nm_table", &maj_str_array,
			    &md_majortab_len) != DDI_PROP_SUCCESS) {
				md_majortab_len = 0;
				if (md_init_debug)
					cmn_err(CE_WARN, "md_targ_nm_table "
					    "ddi_prop_lookup_string_array "
					    "failed");
				goto attach_failure;
			}

			md_major_tuple_table =
			    (struct md_xlate_major_table *)
			    kmem_zalloc(md_majortab_len *
			    sizeof (struct md_xlate_major_table), KM_SLEEP);

			for (i = 0; i < md_majortab_len; i++) {
				/* Getting major name */
				str = strchr(maj_str_array[i], ' ');
				if (str == NULL)
					continue;
				*str = '\0';
				md_major_tuple_table[i].drv_name =
				    md_strdup(maj_str_array[i]);

				/* Simplified atoi to get major number */
				str2 = str + 1;
				md_major_tuple_table[i].targ_maj = 0;
				while ((*str2 >= '0') && (*str2 <= '9')) {
					md_major_tuple_table[i].targ_maj *= 10;
					md_major_tuple_table[i].targ_maj +=
					    *str2++ - '0';
				}
				*str = ' ';
			}
			ddi_prop_free((void *)maj_str_array);
		} else {
			if (md_init_debug)
				cmn_err(CE_WARN, "md_xlate_ver is incorrect");
			goto attach_failure;
		}
	}

	/*
	 * Check for properties:
	 * 	md_keep_repl_state and md_devid_destroy
	 * and set globals if these exist.
	 */
	md_keep_repl_state = ddi_getprop(DDI_DEV_T_ANY, dip,
	    0, "md_keep_repl_state", 0);

	md_devid_destroy = ddi_getprop(DDI_DEV_T_ANY, dip,
	    0, "md_devid_destroy", 0);

	if (MD_UPGRADE)
		md_major_targ = md_targ_name_to_major("md");
	else
		md_major_targ = 0;

	/* allocate admin device node */
	if (ddi_create_priv_minor_node(dip, "admin", S_IFCHR,
	    MD_ADM_MINOR, DDI_PSEUDO, 0, NULL, PRIV_SYS_CONFIG, 0640))
		goto attach_failure;

	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0) != DDI_SUCCESS)
		goto attach_failure;

	if (ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "ddi-abrwrite-supported", 1) != DDI_SUCCESS)
		goto attach_failure;

	/* these could have been cleared by a detach */
	md_nunits = MD_MAXUNITS;
	md_nsets = MD_MAXSETS;

	sz = sizeof (void *) * MD_MAXUNITS;
	if (md_set[0].s_un == NULL)
		md_set[0].s_un = kmem_zalloc(sz, KM_SLEEP);
	if (md_set[0].s_ui == NULL)
		md_set[0].s_ui = kmem_zalloc(sz, KM_SLEEP);

	md_devinfo = dip;

	/*
	 * Only allocate device node for root mirror metadevice.
	 * Don't pre-allocate unnecessary device nodes (thus slowing down a
	 * boot when we attach).
	 * We can't read the mddbs in attach.  The mddbs will be read
	 * by metainit during the boot process when it is doing the
	 * auto-take processing and any other minor nodes will be
	 * allocated at that point.
	 *
	 * There are two scenarios to be aware of here:
	 * 1) when we are booting from a mirrored root we need the root
	 *    metadevice to exist very early (during vfs_mountroot processing)
	 * 2) we need all of the nodes to be created so that any mnttab entries
	 *    will succeed (handled by metainit reading the mddb during boot).
	 */
	if (strncmp(SVM_PSEUDO_STR, svm_bootpath, sizeof (SVM_PSEUDO_STR) - 1)
	    == 0) {
		char *p;
		int mnum = 0;

		/*
		 * The svm_bootpath string looks something like
		 * /pseudo/md@0:0,150,blk where 150 is the minor number
		 * in this example so we need to set the pointer p onto
		 * the first digit of the minor number and convert it
		 * from ascii.
		 */
		for (p = svm_bootpath + sizeof (SVM_PSEUDO_STR) + 1;
		    *p >= '0' && *p <= '9'; p++) {
			mnum *= 10;
			mnum += *p - '0';
		}

		if (md_create_minor_node(0, mnum)) {
			kmem_free(md_set[0].s_un, sz);
			kmem_free(md_set[0].s_ui, sz);
			goto attach_failure;
		}
	}

	/* create the hash to store the meta device sizes */
	md_nblocksmap = mod_hash_create_idhash("md_nblocksmap",
	    md_nblocksmap_size, mod_hash_null_valdtor);

	MD_CLR_IN(IN_ATTACH);
	return (DDI_SUCCESS);

attach_failure:
	/*
	 * Use our own detach routine to toss any stuff we allocated above.
	 * NOTE: detach will call md_halt to free the mddb_init allocations.
	 */
	MD_CLR_IN(IN_ATTACH);
	if (mddetach(dip, DDI_DETACH) != DDI_SUCCESS)
		cmn_err(CE_WARN, "detach from attach failed");
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
mddetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	extern int	check_active_locators();
	set_t		s;
	size_t		sz;
	int		len;

	MD_SET_IN(IN_DETACH);

	/* check command */
	if (cmd != DDI_DETACH) {
		MD_CLR_IN(IN_DETACH);
		return (DDI_FAILURE);
	}

	/*
	 * if we have not already halted yet we have no active config
	 * then automatically initiate a halt so we can detach.
	 */
	if (!(md_get_status() & MD_GBL_HALTED)) {
		if (check_active_locators() == 0) {
			/*
			 * NOTE: a successful md_halt will have done the
			 * mddb_unload to free allocations done in mddb_init
			 */
			if (md_halt(MD_NO_GBL_LOCKS_HELD)) {
				cmn_err(CE_NOTE, "md:detach: "
				    "Could not halt Solaris Volume Manager");
				MD_CLR_IN(IN_DETACH);
				return (DDI_FAILURE);
			}
		}

		/* fail detach if we have not halted */
		if (!(md_get_status() & MD_GBL_HALTED)) {
			MD_CLR_IN(IN_DETACH);
			return (DDI_FAILURE);
		}
	}

	/* must be in halted state, this will be cleared on next attach */
	ASSERT(md_get_status() & MD_GBL_HALTED);

	/* cleanup attach allocations and initializations */
	md_major_targ = 0;

	sz = sizeof (void *) * md_nunits;
	for (s = 0; s < md_nsets; s++) {
		if (md_set[s].s_un != NULL) {
			kmem_free(md_set[s].s_un, sz);
			md_set[s].s_un = NULL;
		}

		if (md_set[s].s_ui != NULL) {
			kmem_free(md_set[s].s_ui, sz);
			md_set[s].s_ui = NULL;
		}
	}
	md_nunits = 0;
	md_nsets = 0;
	md_nmedh = 0;

	if (non_ff_drivers != NULL) {
		int	i;

		for (i = 0; non_ff_drivers[i] != NULL; i++)
			kmem_free(non_ff_drivers[i],
			    strlen(non_ff_drivers[i]) + 1);

		/* free i+1 entries because there is a null entry at list end */
		kmem_free(non_ff_drivers, (i + 1) * sizeof (char *));
		non_ff_drivers = NULL;
	}

	if (md_med_trans_lst != NULL) {
		kmem_free(md_med_trans_lst, strlen(md_med_trans_lst) + 1);
		md_med_trans_lst = NULL;
	}

	if (md_mods != NULL) {
		kmem_free(md_mods, sizeof (ddi_modhandle_t) * MD_NOPS);
		md_mods = NULL;
	}

	if (md_ops != NULL) {
		kmem_free(md_ops, sizeof (md_ops_t *) * MD_NOPS);
		md_ops = NULL;
	}

	if (MD_UPGRADE) {
		len = md_tuple_length * (2 * ((int)sizeof (dev32_t)));
		md_in_upgrade = 0;
		md_xlate_free(len);
		md_majortab_free();
	}

	/*
	 * Undo what we did in mdattach, freeing resources
	 * and removing things we installed.  The system
	 * framework guarantees we are not active with this devinfo
	 * node in any other entry points at this time.
	 */
	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);

	med_fini();

	mod_hash_destroy_idhash(md_nblocksmap);

	md_devinfo = NULL;

	MD_CLR_IN(IN_DETACH);
	return (DDI_SUCCESS);
}


/*
 * Given the device number return the devinfo pointer
 * given to md via md_attach
 */
/*ARGSUSED*/
static int
mdinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int		error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (md_devinfo) {
			*result = (void *)md_devinfo;
			error = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	}
	return (error);
}

/*
 * property operation routine.  return the number of blocks for the partition
 * in question or forward the request to the property facilities.
 */
static int
mdprop_op(
	dev_t dev,		/* device number associated with device */
	dev_info_t *dip,	/* device info struct for this device */
	ddi_prop_op_t prop_op,	/* property operator */
	int mod_flags,		/* property flags */
	char *name,		/* name of property */
	caddr_t valuep,		/* where to put property value */
	int *lengthp)		/* put length of property here */
{
	return (ddi_prop_op_nblocks(dev, dip, prop_op, mod_flags,
	    name, valuep, lengthp, md_nblocks_get(getminor(dev))));
}

static void
snarf_user_data(set_t setno)
{
	mddb_recid_t		recid;
	mddb_recstatus_t	status;

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, MDDB_USER, 0)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		status = mddb_getrecstatus(recid);
		if (status == MDDB_STALE)
			continue;

		if (status == MDDB_NODATA) {
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
			continue;
		}

		ASSERT(status == MDDB_OK);

		mddb_setrecprivate(recid, MD_PRV_GOTIT);
	}
}

static void
md_print_block_usage(mddb_set_t *s, uint_t blks)
{
	uint_t		ib;
	int		li;
	mddb_mb_ic_t	*mbip;
	uint_t		max_blk_needed;
	mddb_lb_t	*lbp;
	mddb_sidelocator_t	*slp;
	int		drv_index;
	md_splitname	sn;
	char		*name;
	char		*suffix;
	size_t		prefixlen;
	size_t		suffixlen;
	int		alloc_sz;


	max_blk_needed = s->s_totalblkcnt - s->s_freeblkcnt + blks;

	cmn_err(CE_WARN, "Blocks in Metadevice State Database: %d\n"
	    "            Additional Blocks Needed:            %d\n\n"
	    "            Increase size of following replicas for\n"
	    "            device relocatability by deleting listed\n"
	    "            replica and re-adding replica with\n"
	    "            increased size (see metadb(1M)):\n"
	    "                Replica                   Increase By",
	    s->s_totalblkcnt, (blks - s->s_freeblkcnt));

	lbp = s->s_lbp;

	for (li = 0; li < lbp->lb_loccnt; li++) {
		if (lbp->lb_locators[li].l_flags & MDDB_F_DELETED)
			continue;
		ib = 0;
		for (mbip = s->s_mbiarray[li]; mbip != NULL;
		    mbip = mbip->mbi_next) {
			ib += (uint_t)mbip->mbi_mddb_mb.mb_blkcnt;
		}
		if (ib == 0)
			continue;
		if (ib < max_blk_needed) {
			slp = &lbp->lb_sidelocators[s->s_sideno][li];
			drv_index = slp->l_drvnm_index;
			mddb_locatorblock2splitname(s->s_lnp, li, s->s_sideno,
			    &sn);
			prefixlen = SPN_PREFIX(&sn).pre_len;
			suffixlen = SPN_SUFFIX(&sn).suf_len;
			alloc_sz = (int)(prefixlen + suffixlen + 2);
			name = (char *)kmem_alloc(alloc_sz, KM_SLEEP);
			(void) strncpy(name, SPN_PREFIX(&sn).pre_data,
			    prefixlen);
			name[prefixlen] = '/';
			suffix = name + (prefixlen + 1);
			(void) strncpy(suffix, SPN_SUFFIX(&sn).suf_data,
			    suffixlen);
			name[prefixlen + suffixlen + 1] = '\0';
			cmn_err(CE_WARN,
			    "  %s (%s:%d:%d)   %d blocks",
			    name, lbp->lb_drvnm[drv_index].dn_data,
			    slp->l_mnum, lbp->lb_locators[li].l_blkno,
			    (max_blk_needed - ib));
			kmem_free(name, alloc_sz);
		}
	}
}

/*
 * md_create_minor_node:
 *	Create the minor device for the given set and un_self_id.
 *
 * Input:
 *	setno	- set number
 *	mnum	- selfID of unit
 *
 * Output:
 *	None.
 *
 * Returns 0 for success, 1 for failure.
 *
 * Side-effects:
 *	None.
 */
int
md_create_minor_node(set_t setno, minor_t mnum)
{
	char		name[20];

	/* Check for valid arguments */
	if (setno >= MD_MAXSETS || MD_MIN2UNIT(mnum) >= MD_MAXUNITS)
		return (1);

	(void) snprintf(name, 20, "%u,%u,blk",
	    (unsigned)setno, (unsigned)MD_MIN2UNIT(mnum));

	if (ddi_create_minor_node(md_devinfo, name, S_IFBLK,
	    MD_MKMIN(setno, mnum), DDI_PSEUDO, 0))
		return (1);

	(void) snprintf(name, 20, "%u,%u,raw",
	    (unsigned)setno, (unsigned)MD_MIN2UNIT(mnum));

	if (ddi_create_minor_node(md_devinfo, name, S_IFCHR,
	    MD_MKMIN(setno, mnum), DDI_PSEUDO, 0))
		return (1);

	return (0);
}

/*
 * For a given key check if it is an orphaned record.
 * The following conditions are used to determine an orphan.
 * 1. The device associated with that key is not a metadevice.
 * 2. If DEVID_STYLE then the physical device does not have a device Id
 * associated with it.
 *
 * If a key does not have an entry in the devid namespace it could be
 * a device that does not support device ids. Hence the record is not
 * deleted.
 */

static int
md_verify_orphaned_record(set_t setno, mdkey_t key)
{
	md_dev64_t	odev; /* orphaned dev */
	mddb_set_t	*s;
	side_t		side = 0;
	struct nm_next_hdr	*did_nh = NULL;

	s = (mddb_set_t *)md_set[setno].s_db;
	if ((did_nh = get_first_record(setno, 1,  (NM_DEVID | NM_NOTSHARED)))
	    == NULL)
		return (0);
	/*
	 * If devid style is set then get the dev_t using MD_NOTRUST_DEVT
	 */
	if (s->s_lbp->lb_flags & MDDB_DEVID_STYLE) {
		odev = md_getdevnum(setno, side, key, MD_NOTRUST_DEVT);
		if ((odev == NODEV64) || (md_getmajor(odev) == md_major))
			return (0);
		if (lookup_entry(did_nh, setno, side, key, odev, NM_DEVID) ==
		    NULL)
			return (1);
	}
	return (0);
}

int
md_snarf_db_set(set_t setno, md_error_t *ep)
{
	int			err = 0;
	int			i;
	mddb_recid_t		recid;
	mddb_type_t		drvrid;
	mddb_recstatus_t	status;
	md_ops_t		*ops;
	uint_t			privat;
	mddb_set_t		*s;
	uint_t			cvt_blks;
	struct nm_next_hdr	*nh;
	mdkey_t			key = MD_KEYWILD;
	side_t			side = 0;
	int			size;
	int			devid_flag;
	int			retval;
	uint_t			un;
	int			un_next_set = 0;

	md_haltsnarf_enter(setno);

	mutex_enter(&md_mx);
	if (md_set[setno].s_status & MD_SET_SNARFED) {
		mutex_exit(&md_mx);
		md_haltsnarf_exit(setno);
		return (0);
	}
	mutex_exit(&md_mx);

	if (! (md_get_status() & MD_GBL_DAEMONS_LIVE)) {
		if (md_start_daemons(TRUE)) {
			if (ep != NULL)
				(void) mdsyserror(ep, ENXIO);
			err = -1;
			goto out;
		}
	}


	/*
	 * Load the devid name space if it exists
	 */
	(void) md_load_namespace(setno, NULL, NM_DEVID);
	if (!md_load_namespace(setno, ep, 0L)) {
		/*
		 * Unload the devid namespace
		 */
		(void) md_unload_namespace(setno, NM_DEVID);
		err = -1;
		goto out;
	}

	/*
	 * If replica is in non-devid state, convert if:
	 * 	- not in probe during upgrade (md_keep_repl_state = 0)
	 * 	- enough space available in replica
	 *	- local set
	 *	- not a multi-node diskset
	 *	- clustering is not present (for non-local set)
	 */
	s = (mddb_set_t *)md_set[setno].s_db;
	devid_flag = 0;
	if (!(s->s_lbp->lb_flags & MDDB_DEVID_STYLE) && !md_keep_repl_state)
		devid_flag = 1;
	if (cluster_bootflags & CLUSTER_CONFIGURED)
		if (setno != MD_LOCAL_SET)
			devid_flag = 0;
	if (MD_MNSET_SETNO(setno))
		devid_flag = 0;
	if ((md_devid_destroy == 1) && (md_keep_repl_state == 1))
		devid_flag = 0;

	/*
	 * if we weren't devid style before and md_keep_repl_state=1
	 * we need to stay non-devid
	 */
	if ((md_keep_repl_state == 1) &&
	    ((s->s_lbp->lb_flags & MDDB_DEVID_STYLE) == 0))
		devid_flag = 0;
	if (devid_flag) {
		/*
		 * Determine number of free blocks needed to convert
		 * entire replica to device id format - locator blocks
		 * and namespace.
		 */
		cvt_blks = 0;
		if (mddb_lb_did_convert(s, 0, &cvt_blks) != 0) {
			if (ep != NULL)
				(void) mdsyserror(ep, EIO);
			err = -1;
			goto out;

		}
		cvt_blks += md_nm_did_chkspace(setno);

		/* add MDDB_DEVID_CONV_PERC% */
		if ((md_conv_perc > 0) && (md_conv_perc <= 100)) {
			cvt_blks = cvt_blks * (100 + md_conv_perc) / 100;
		}

		if (cvt_blks <= s->s_freeblkcnt) {
			if (mddb_lb_did_convert(s, 1, &cvt_blks) != 0) {
				if (ep != NULL)
					(void) mdsyserror(ep, EIO);
				err = -1;
				goto out;
			}

		} else {
			/*
			 * Print message that replica can't be converted for
			 * lack of space.   No failure - just continue to
			 * run without device ids.
			 */
			cmn_err(CE_WARN,
			    "Unable to add Solaris Volume Manager device "
			    "relocation data.\n"
			    "          To use device relocation feature:\n"
			    "          - Increase size of listed replicas\n"
			    "          - Reboot");
			md_print_block_usage(s, cvt_blks);
			cmn_err(CE_WARN,
			    "Loading set without device relocation data.\n"
			    "          Solaris Volume Manager disk movement "
			    "not tracked in local set.");
		}
	}

	/*
	 * go through and load any modules referenced in
	 * data base
	 */
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, MDDB_ALL, 0)) > 0) {
		status = mddb_getrecstatus(recid);
		if (status == MDDB_STALE) {
			if (! (md_get_setstatus(setno) & MD_SET_STALE)) {
				md_set_setstatus(setno, MD_SET_STALE);
				cmn_err(CE_WARN,
				    "md: state database is stale");
			}
		} else if (status == MDDB_NODATA) {
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
			continue;
		}
		drvrid = mddb_getrectype1(recid);
		if (drvrid < MDDB_FIRST_MODID)
			continue;
		if (md_loadsubmod(setno, md_getshared_name(setno, drvrid),
		    drvrid) < 0) {
			cmn_err(CE_NOTE, "md: could not load misc/%s",
			    md_getshared_name(setno, drvrid));
		}
	}

	if (recid < 0)
		goto out;

	snarf_user_data(setno);

	/*
	 * Initialize the md_nm_snarfed array
	 * this array is indexed by the key and
	 * is set by md_getdevnum during the snarf time
	 */
	if ((nh = get_first_record(setno, 0, NM_NOTSHARED)) != NULL) {
		size = (int)((((struct nm_rec_hdr *)nh->nmn_record)->
		    r_next_key) * (sizeof (int)));
		md_nm_snarfed = (int *)kmem_zalloc(size, KM_SLEEP);
	}

	/*
	 * go through and snarf until nothing gets added
	 */
	do {
		i = 0;
		for (ops = md_opslist; ops != NULL; ops = ops->md_next) {
			if (ops->md_snarf != NULL) {
				retval = ops->md_snarf(MD_SNARF_DOIT, setno);
				if (retval == -1) {
					err = -1;
					/* Don't know the failed unit */
					(void) mdmderror(ep, MDE_RR_ALLOC_ERROR,
					    0);
					(void) md_halt_set(setno, MD_HALT_ALL);
					(void) mddb_unload_set(setno);
					md_haltsnarf_exit(setno);
					return (err);
				} else {
					i += retval;
				}
			}
		}
	} while (i);

	/*
	 * Set the first available slot and availability
	 */
	md_set[setno].s_un_avail = 0;
	for (un = 0; un < MD_MAXUNITS; un++) {
		if (md_set[setno].s_un[un] != NULL) {
			continue;
		} else {
			if (!un_next_set) {
				md_set[setno].s_un_next = un;
				un_next_set = 1;
			}
			md_set[setno].s_un_avail++;
		}
	}

	md_set_setstatus(setno, MD_SET_SNARFED);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, MDDB_ALL, 0)) > 0) {
		privat = mddb_getrecprivate(recid);
		if (privat & MD_PRV_COMMIT) {
			if (mddb_commitrec(recid)) {
				if (!(md_get_setstatus(setno) & MD_SET_STALE)) {
					md_set_setstatus(setno, MD_SET_STALE);
					cmn_err(CE_WARN,
					    "md: state database is stale");
				}
			}
			mddb_setrecprivate(recid, MD_PRV_GOTIT);
		}
	}

	/* Deletes must happen after all the commits */
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, MDDB_ALL, 0)) > 0) {
		privat = mddb_getrecprivate(recid);
		if (privat & MD_PRV_DELETE) {
			if (mddb_deleterec(recid)) {
				if (!(md_get_setstatus(setno) & MD_SET_STALE)) {
					md_set_setstatus(setno, MD_SET_STALE);
					cmn_err(CE_WARN,
					    "md: state database is stale");
				}
				mddb_setrecprivate(recid, MD_PRV_GOTIT);
			}
			recid = mddb_makerecid(setno, 0);
		}
	}

	/*
	 * go through and clean up records until nothing gets cleaned up.
	 */
	do {
		i = 0;
		for (ops = md_opslist; ops != NULL; ops = ops->md_next)
			if (ops->md_snarf != NULL)
				i += ops->md_snarf(MD_SNARF_CLEANUP, setno);
	} while (i);

	if (md_nm_snarfed != NULL &&
	    !(md_get_setstatus(setno) & MD_SET_STALE)) {
		/*
		 * go thru and cleanup the namespace and the device id
		 * name space
		 */
		for (key = 1;
		    key < ((struct nm_rec_hdr *)nh->nmn_record)->r_next_key;
		    key++) {
			/*
			 * Is the entry an 'orphan'?
			 */
			if (lookup_entry(nh, setno, side, key, NODEV64, 0L) !=
			    NULL) {
				/*
				 * If the value is not set then apparently
				 * it is not part of the current configuration,
				 * remove it this can happen when system panic
				 * between the primary name space update and
				 * the device id name space update
				 */
				if (md_nm_snarfed[key] == 0) {
					if (md_verify_orphaned_record(setno,
					    key) == 1)
						(void) remove_entry(nh,
						    side, key, 0L);
				}
			}
		}
	}

	if (md_nm_snarfed != NULL) {
		/*
		 * Done and free the memory
		 */
		kmem_free(md_nm_snarfed, size);
		md_nm_snarfed = NULL;
	}

	if (s->s_lbp->lb_flags & MDDB_DEVID_STYLE &&
	    !(md_get_setstatus(setno) & MD_SET_STALE)) {
		/*
		 * if the destroy flag has been set and
		 * the MD_SET_DIDCLUP bit is not set in
		 * the set's status field, cleanup the
		 * entire device id namespace
		 */
		if (md_devid_destroy &&
		    !(md_get_setstatus(setno) & MD_SET_DIDCLUP)) {
			(void) md_devid_cleanup(setno, 1);
			md_set_setstatus(setno, MD_SET_DIDCLUP);
		} else
			(void) md_devid_cleanup(setno, 0);
	}

	/*
	 * clear single threading on snarf, return success or error
	 */
out:
	md_haltsnarf_exit(setno);
	return (err);
}

void
get_minfo(struct dk_minfo *info, minor_t mnum)
{
	md_unit_t	*un;
	mdi_unit_t	*ui;

	info->dki_capacity = 0;
	info->dki_lbsize = 0;
	info->dki_media_type = 0;

	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return;
	}
	un = (md_unit_t *)md_unit_readerlock(ui);
	info->dki_capacity = un->c.un_total_blocks;
	md_unit_readerexit(ui);
	info->dki_lbsize = DEV_BSIZE;
	info->dki_media_type = DK_UNKNOWN;
}


void
get_info(struct dk_cinfo *info, minor_t mnum)
{
	/*
	 * Controller Information
	 */
	info->dki_ctype = DKC_MD;
	info->dki_cnum = ddi_get_instance(ddi_get_parent(md_devinfo));
	(void) strcpy(info->dki_cname,
	    ddi_get_name(ddi_get_parent(md_devinfo)));
	/*
	 * Unit Information
	 */
	info->dki_unit = mnum;
	info->dki_slave = 0;
	(void) strcpy(info->dki_dname, ddi_driver_name(md_devinfo));
	info->dki_flags = 0;
	info->dki_partition = 0;
	info->dki_maxtransfer = (ushort_t)(md_maxphys / DEV_BSIZE);

	/*
	 * We can't get from here to there yet
	 */
	info->dki_addr = 0;
	info->dki_space = 0;
	info->dki_prio = 0;
	info->dki_vec = 0;
}

/*
 * open admin device
 */
static int
mdadminopen(
	int	flag,
	int	otyp)
{
	int	err = 0;

	/* single thread */
	mutex_enter(&md_mx);

	/* check type and flags */
	if ((otyp != OTYP_CHR) && (otyp != OTYP_LYR)) {
		err = EINVAL;
		goto out;
	}
	if (((flag & FEXCL) && (md_status & MD_GBL_OPEN)) ||
	    (md_status & MD_GBL_EXCL)) {
		err = EBUSY;
		goto out;
	}

	/* count and flag open */
	md_ocnt[otyp]++;
	md_status |= MD_GBL_OPEN;
	if (flag & FEXCL)
		md_status |= MD_GBL_EXCL;

	/* unlock return success */
out:
	mutex_exit(&md_mx);
	return (err);
}

/*
 * open entry point
 */
static int
mdopen(
	dev_t		*dev,
	int		flag,
	int		otyp,
	cred_t		*cred_p)
{
	minor_t		mnum = getminor(*dev);
	unit_t		unit = MD_MIN2UNIT(mnum);
	set_t		setno = MD_MIN2SET(mnum);
	mdi_unit_t	*ui = NULL;
	int		err = 0;
	md_parent_t	parent;

	/* dispatch admin device opens */
	if (mnum == MD_ADM_MINOR)
		return (mdadminopen(flag, otyp));

	/* lock, check status */
	rw_enter(&md_unit_array_rw.lock, RW_READER);

tryagain:
	if (md_get_status() & MD_GBL_HALTED)  {
		err = ENODEV;
		goto out;
	}

	/* check minor */
	if ((setno >= md_nsets) || (unit >= md_nunits)) {
		err = ENXIO;
		goto out;
	}

	/* make sure we're snarfed */
	if ((md_get_setstatus(MD_LOCAL_SET) & MD_SET_SNARFED) == 0) {
		if (md_snarf_db_set(MD_LOCAL_SET, NULL) != 0) {
			err = ENODEV;
			goto out;
		}
	}
	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0) {
		err = ENODEV;
		goto out;
	}

	/* check unit */
	if ((ui = MDI_UNIT(mnum)) == NULL) {
		err = ENXIO;
		goto out;
	}

	/*
	 * The softpart open routine may do an I/O during the open, in
	 * which case the open routine will set the OPENINPROGRESS flag
	 * and drop all locks during the I/O.  If this thread sees
	 * the OPENINPROGRESS flag set, if should wait until the flag
	 * is reset before calling the driver's open routine.  It must
	 * also revalidate the world after it grabs the unit_array lock
	 * since the set may have been released or the metadevice cleared
	 * during the sleep.
	 */
	if (MD_MNSET_SETNO(setno)) {
		mutex_enter(&ui->ui_mx);
		if (ui->ui_lock & MD_UL_OPENINPROGRESS) {
			rw_exit(&md_unit_array_rw.lock);
			cv_wait(&ui->ui_cv, &ui->ui_mx);
			rw_enter(&md_unit_array_rw.lock, RW_READER);
			mutex_exit(&ui->ui_mx);
			goto tryagain;
		}
		mutex_exit(&ui->ui_mx);
	}

	/* Test if device is openable */
	if ((ui->ui_tstate & MD_NOTOPENABLE) != 0) {
		err = ENXIO;
		goto out;
	}

	/* don't allow opens w/WRITE flag if stale */
	if ((flag & FWRITE) && (md_get_setstatus(setno) & MD_SET_STALE)) {
		err = EROFS;
		goto out;
	}

	/* don't allow writes to subdevices */
	parent = md_get_parent(md_expldev(*dev));
	if ((flag & FWRITE) && MD_HAS_PARENT(parent)) {
		err = EROFS;
		goto out;
	}

	/* open underlying driver */
	if (md_ops[ui->ui_opsindex]->md_open != NULL) {
		if ((err = (*md_ops[ui->ui_opsindex]->md_open)
		    (dev, flag, otyp, cred_p, 0)) != 0)
			goto out;
	}

	/* or do it ourselves */
	else {
		/* single thread */
		(void) md_unit_openclose_enter(ui);
		err = md_unit_incopen(mnum, flag, otyp);
		md_unit_openclose_exit(ui);
		if (err != 0)
			goto out;
	}

	/* unlock, return status */
out:
	rw_exit(&md_unit_array_rw.lock);
	return (err);
}

/*
 * close admin device
 */
static int
mdadminclose(
	int	otyp)
{
	int	i;
	int	err = 0;

	/* single thread */
	mutex_enter(&md_mx);

	/* check type and flags */
	if ((otyp < 0) || (otyp >= OTYPCNT)) {
		err = EINVAL;
		goto out;
	} else if (md_ocnt[otyp] == 0) {
		err = ENXIO;
		goto out;
	}

	/* count and flag closed */
	if (otyp == OTYP_LYR)
		md_ocnt[otyp]--;
	else
		md_ocnt[otyp] = 0;
	md_status &= ~MD_GBL_OPEN;
	for (i = 0; (i < OTYPCNT); ++i)
		if (md_ocnt[i] != 0)
			md_status |= MD_GBL_OPEN;
	if (! (md_status & MD_GBL_OPEN))
		md_status &= ~MD_GBL_EXCL;

	/* unlock return success */
out:
	mutex_exit(&md_mx);
	return (err);
}

/*
 * close entry point
 */
static int
mdclose(
	dev_t		dev,
	int		flag,
	int		otyp,
	cred_t		*cred_p)
{
	minor_t		mnum = getminor(dev);
	set_t		setno = MD_MIN2SET(mnum);
	unit_t		unit = MD_MIN2UNIT(mnum);
	mdi_unit_t	*ui = NULL;
	int		err = 0;

	/* dispatch admin device closes */
	if (mnum == MD_ADM_MINOR)
		return (mdadminclose(otyp));

	/* check minor */
	if ((setno >= md_nsets) || (unit >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL)) {
		err = ENXIO;
		goto out;
	}

	/* close underlying driver */
	if (md_ops[ui->ui_opsindex]->md_close != NULL) {
		if ((err = (*md_ops[ui->ui_opsindex]->md_close)
		    (dev, flag, otyp, cred_p, 0)) != 0)
			goto out;
	}

	/* or do it ourselves */
	else {
		/* single thread */
		(void) md_unit_openclose_enter(ui);
		err = md_unit_decopen(mnum, otyp);
		md_unit_openclose_exit(ui);
		if (err != 0)
			goto out;
	}

	/* return success */
out:
	return (err);
}


/*
 * This routine performs raw read operations.  It is called from the
 * device switch at normal priority.
 *
 * The main catch is that the *uio struct which is passed to us may
 * specify a read which spans two buffers, which would be contiguous
 * on a single partition,  but not on a striped partition. This will
 * be handled by mdstrategy.
 */
/*ARGSUSED*/
static int
mdread(dev_t dev, struct uio *uio, cred_t *credp)
{
	minor_t		mnum;
	mdi_unit_t	*ui;
	int		error;

	if (((mnum = getminor(dev)) == MD_ADM_MINOR) ||
	    (MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL))
		return (ENXIO);

	if (md_ops[ui->ui_opsindex]->md_read  != NULL)
		return ((*md_ops[ui->ui_opsindex]->md_read)
		    (dev, uio, credp));

	if ((error = md_chk_uio(uio)) != 0)
		return (error);

	return (physio(mdstrategy, NULL, dev, B_READ, md_minphys, uio));
}

/*
 * This routine performs async raw read operations.  It is called from the
 * device switch at normal priority.
 *
 * The main catch is that the *aio struct which is passed to us may
 * specify a read which spans two buffers, which would be contiguous
 * on a single partition,  but not on a striped partition. This will
 * be handled by mdstrategy.
 */
/*ARGSUSED*/
static int
mdaread(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	minor_t		mnum;
	mdi_unit_t	*ui;
	int		error;


	if (((mnum = getminor(dev)) == MD_ADM_MINOR) ||
	    (MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL))
		return (ENXIO);

	if (md_ops[ui->ui_opsindex]->md_aread  != NULL)
		return ((*md_ops[ui->ui_opsindex]->md_aread)
		    (dev, aio, credp));

	if ((error = md_chk_uio(aio->aio_uio)) != 0)
		return (error);

	return (aphysio(mdstrategy, anocancel, dev, B_READ, md_minphys, aio));
}

/*
 * This routine performs raw write operations.	It is called from the
 * device switch at normal priority.
 *
 * The main catch is that the *uio struct which is passed to us may
 * specify a write which spans two buffers, which would be contiguous
 * on a single partition,  but not on a striped partition. This is
 * handled by mdstrategy.
 *
 */
/*ARGSUSED*/
static int
mdwrite(dev_t dev, struct uio *uio, cred_t *credp)
{
	minor_t		mnum;
	mdi_unit_t	*ui;
	int		error;

	if (((mnum = getminor(dev)) == MD_ADM_MINOR) ||
	    (MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL))
		return (ENXIO);

	if (md_ops[ui->ui_opsindex]->md_write  != NULL)
		return ((*md_ops[ui->ui_opsindex]->md_write)
		    (dev, uio, credp));

	if ((error = md_chk_uio(uio)) != 0)
		return (error);

	return (physio(mdstrategy, NULL, dev, B_WRITE, md_minphys, uio));
}

/*
 * This routine performs async raw write operations.  It is called from the
 * device switch at normal priority.
 *
 * The main catch is that the *aio struct which is passed to us may
 * specify a write which spans two buffers, which would be contiguous
 * on a single partition,  but not on a striped partition. This is
 * handled by mdstrategy.
 *
 */
/*ARGSUSED*/
static int
mdawrite(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	minor_t		mnum;
	mdi_unit_t	*ui;
	int		error;


	if (((mnum = getminor(dev)) == MD_ADM_MINOR) ||
	    (MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL))
		return (ENXIO);

	if (md_ops[ui->ui_opsindex]->md_awrite  != NULL)
		return ((*md_ops[ui->ui_opsindex]->md_awrite)
		    (dev, aio, credp));

	if ((error = md_chk_uio(aio->aio_uio)) != 0)
		return (error);

	return (aphysio(mdstrategy, anocancel, dev, B_WRITE, md_minphys, aio));
}

int
mdstrategy(struct buf *bp)
{
	minor_t		mnum;
	mdi_unit_t	*ui;

	ASSERT((bp->b_flags & B_DONE) == 0);

	if (panicstr)
		md_clr_status(MD_GBL_DAEMONS_LIVE);

	if (((mnum = getminor(bp->b_edev)) == MD_ADM_MINOR) ||
	    (MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL)) {
		bp->b_flags |= B_ERROR;
		bp->b_error = ENXIO;
		bp->b_resid = bp->b_bcount;
		biodone(bp);
		return (0);
	}

	bp->b_flags &= ~(B_ERROR | B_DONE);
	if (md_ops[ui->ui_opsindex]->md_strategy  != NULL) {
		(*md_ops[ui->ui_opsindex]->md_strategy) (bp, 0, NULL);
	} else {
		(void) errdone(ui, bp, ENXIO);
	}
	return (0);
}

/*
 * Return true if the ioctl is allowed to be multithreaded.
 * All the ioctls with MN are sent only from the message handlers through
 * rpc.mdcommd, which (via it's own locking mechanism) takes care that not two
 * ioctl for the same metadevice are issued at the same time.
 * So we are safe here.
 * The other ioctls do not mess with any metadevice structures and therefor
 * are harmless too, if called multiple times at the same time.
 */
static boolean_t
is_mt_ioctl(int cmd) {

	switch (cmd) {
	case MD_IOCGUNIQMSGID:
	case MD_IOCGVERSION:
	case MD_IOCISOPEN:
	case MD_MN_SET_MM_OWNER:
	case MD_MN_SET_STATE:
	case MD_MN_SUSPEND_WRITES:
	case MD_MN_ALLOCATE_HOTSPARE:
	case MD_MN_SET_SETFLAGS:
	case MD_MN_GET_SETFLAGS:
	case MD_MN_MDDB_OPTRECFIX:
	case MD_MN_MDDB_PARSE:
	case MD_MN_MDDB_BLOCK:
	case MD_MN_DB_USERREQ:
	case MD_IOC_SPSTATUS:
	case MD_MN_COMMD_ERR:
	case MD_MN_SET_COMMD_RUNNING:
	case MD_MN_RESYNC:
	case MD_MN_SETSYNC:
	case MD_MN_POKE_HOTSPARES:
		return (1);
	default:
		return (0);
	}
}

/*
 * This routine implements the ioctl calls for the Virtual Disk System.
 * It is called from the device switch at normal priority.
 */
/* ARGSUSED */
static int
mdioctl(dev_t dev, int cmd, intptr_t data, int mode, cred_t *cred_p,
	int *rval_p)
{
	minor_t		mnum = getminor(dev);
	mdi_unit_t	*ui;
	IOLOCK		lock;
	int		err;

	/*
	 * For multinode disksets  number of ioctls are allowed to be
	 * multithreaded.
	 * A fundamental assumption made in this implementation is that
	 * ioctls either do not interact with other md structures  or the
	 * ioctl to the admin device can only occur if the metadevice
	 * device is open. i.e. avoid a race between metaclear and the
	 * progress of a multithreaded ioctl.
	 */

	if (!is_mt_ioctl(cmd) && md_ioctl_lock_enter() == EINTR) {
		return (EINTR);
	}

	/*
	 * initialize lock tracker
	 */
	IOLOCK_INIT(&lock);

	/* Flag to indicate that MD_GBL_IOCTL_LOCK is not acquired */

	if (is_mt_ioctl(cmd)) {
		/* increment the md_mtioctl_cnt */
		mutex_enter(&md_mx);
		md_mtioctl_cnt++;
		mutex_exit(&md_mx);
		lock.l_flags |= MD_MT_IOCTL;
	}

	/*
	 * this has been added to prevent notification from re-snarfing
	 * so metaunload will work.  It may interfere with other modules
	 * halt process.
	 */
	if (md_get_status() & (MD_GBL_HALTED | MD_GBL_DAEMONS_DIE))
		return (IOLOCK_RETURN(ENXIO, &lock));

	/*
	 * admin device ioctls
	 */
	if (mnum == MD_ADM_MINOR) {
		err = md_admin_ioctl(md_expldev(dev), cmd, (void *) data,
		    mode, &lock);
	}

	/*
	 * metadevice ioctls
	 */
	else if ((MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL)) {
		err = ENXIO;
	} else if (md_ops[ui->ui_opsindex]->md_ioctl == NULL) {
		err = ENOTTY;
	} else {
		err = (*md_ops[ui->ui_opsindex]->md_ioctl)
		    (dev, cmd, (void *) data, mode, &lock);
	}

	/*
	 * drop any locks we grabbed
	 */
	return (IOLOCK_RETURN_IOCTLEND(err, &lock));
}

static int
mddump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	minor_t		mnum;
	set_t		setno;
	mdi_unit_t	*ui;

	if ((mnum = getminor(dev)) == MD_ADM_MINOR)
		return (ENXIO);

	setno = MD_MIN2SET(mnum);

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL))
		return (ENXIO);


	if ((md_get_setstatus(setno) & MD_SET_SNARFED) == 0)
		return (ENXIO);

	if (md_ops[ui->ui_opsindex]->md_dump  != NULL)
		return ((*md_ops[ui->ui_opsindex]->md_dump)
		    (dev, addr, blkno, nblk));

	return (ENXIO);
}

/*
 * Metadevice unit number dispatcher
 * When this routine is called it will scan the
 * incore unit array and return the avail slot
 * hence the unit number to the caller
 *
 * Return -1 if there is nothing available
 */
unit_t
md_get_nextunit(set_t setno)
{
	unit_t	un, start;

	/*
	 * If nothing available
	 */
	if (md_set[setno].s_un_avail == 0) {
		return (MD_UNITBAD);
	}

	mutex_enter(&md_mx);
	start = un = md_set[setno].s_un_next;

	/* LINTED: E_CONSTANT_CONDITION */
	while (1) {
		if (md_set[setno].s_un[un] == NULL) {
			/*
			 * Advance the starting index for the next
			 * md_get_nextunit call
			 */
			if (un == MD_MAXUNITS - 1) {
				md_set[setno].s_un_next = 0;
			} else {
				md_set[setno].s_un_next = un + 1;
			}
			break;
		}

		un = ((un == MD_MAXUNITS - 1) ? 0 : un + 1);

		if (un == start) {
			un = MD_UNITBAD;
			break;
		}

	}

	mutex_exit(&md_mx);
	return (un);
}
