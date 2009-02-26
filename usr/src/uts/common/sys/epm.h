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

#ifndef	_SYS_EPM_H
#define	_SYS_EPM_H

#include <sys/pm.h>
#include <sys/dditypes.h>
#include <sys/devops.h>
#include <sys/ddi_impldefs.h>
#include <sys/taskq.h>
#include <sys/tzfile.h>

/*
 * XXXX
 * Do we really need this include?  It may be leftover from early CPUPM code.
 * #include <sys/processor.h>
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

/*
 * epm.h:	Function prototypes and data structs for kernel pm functions.
 */

void e_pm_props(dev_info_t *);
int e_new_pm_props(dev_info_t *);

#define	PM_LEVEL_UPONLY (-2)	/* only raise power level */
#define	PM_LEVEL_DOWNONLY (-3)	/* only lower power level */
#define	PM_LEVEL_EXACT (-4)	/* wants exact power level */

/*
 * Values used by e_pm_props and friends, found in devi_pm_flags
 */
#define	PMC_NEEDS_SR		0x00001	/* do suspend/resume despite no "reg" */
#define	PMC_NO_SR		0x00002	/* don't suspend/resume despite "reg" */
#define	PMC_PARENTAL_SR		0x00004	/* call up tree to suspend/resume */
#define	PMC_WANTS_NOTIFY	0x00008	/* notify if child pwr level changes */
#define	PMC_BC			0x00010	/* no pm-components, backwards compat */
#define	PMC_COMPONENTS_DONE	0x00020 /* parsed pm-components */
#define	PMC_COMPONENTS_FAILED	0x00040 /* failed parsing pm-components */
#define	PMC_SUSPENDED		0x00080 /* device has been suspended */
#define	PMC_DEF_THRESH		0x00100 /* thresholds are default */
#define	PMC_DEV_THRESH		0x00200 /* SET_THRESHOLD ioctl seen */
#define	PMC_COMP_THRESH		0x00400 /* relative threshold set */
#define	PMC_NEXDEF_THRESH	0x00800 /* relative threshold set for nexus */
#define	PMC_NOPMKID		0x01000 /* non-pm'd child of pm'd parent */
#define	PMC_NO_INVOL		0x02000 /* no pm without driver's consent */
#define	PMC_VOLPMD		0x04000 /* went down voluntarily */
#define	PMC_SKIP_BRINGUP	0x08000 /* Skipped a dependency bringup */

/*
 * A node which is the console frame buffer, and should not be powered down
 * automatically because the OBP driver doesn't know how to power it back up
 * before using it  (can remove this when prom calls back into kernel to do
 * io to console).
 */
#define	PMC_CONSOLE_FB		0x10000	/* console framebuffer */
#define	PMC_NOINVOL_DONE	0x20000 /* processed by pm_noinvol_specd() */
#define	PMC_DRIVER_REMOVED	0x40000 /* driver is removed	*/
#define	PMC_CPU_DEVICE		0x80000 /* device is a power manageable CPU */
#define	PMC_CPU_THRESH		0x100000 /* cpu threshold set */

#define	PMC_THRESH_ALL	(PMC_DEF_THRESH | PMC_DEV_THRESH | \
    PMC_COMP_THRESH | PMC_NEXDEF_THRESH | PMC_CPU_THRESH)
#define	PMC_THRESH_NONE	~(PMC_THRESH_ALL)

/* Flags for the component */
#define	PM_POWER_OP		0x00001	/* set power in process */
#define	PM_PHC_WHILE_SET_POWER	0x00002	/* phc and set power deadlock */

/*
 * One of these is attached to each devinfo that is autopm'd.
 */
typedef struct pm_scan {
	int		ps_idle_down;	/* PMID_XXX flags */
	int		ps_scan_flags;	/* scan flags, defined below */
	timeout_id_t	ps_scan_id;	/* per dip scan timeout id */
} pm_scan_t;

/*
 * ps_scan_flags may take the following values, plus possibly
 * more defined.
 */
#define	PM_SCANNING		0x100	/* scanning: pm_scan_dev is active */
#define	PM_SCAN_AGAIN		0x200
#define	PM_SCAN_STOP		0x400
#define	PM_SCAN_DISPATCHED	0x800

#define	PM_DEFAULT_MIN_SCAN	((clock_t)15) /* Minimum scan interval in sec */
#define	PM_CPU_MIN_SCAN		((clock_t)1) /* Minimum interval for CPUs */

/*
 * Power management component definitions, used for tracking idleness of
 * devices.  An array of these hangs off the devi_pm_components member of the
 * dev_info struct (if initialized by driver and/or auto-pm)
 * The array of these structs is followed in the same kmem_zalloc'd chunk by
 * the names pointed to by the structs.
 */

/*
 * This (sub-)struct contains all the info extracted from the pm-components
 * property for each component (name of component, names and values of power
 * levels supported).  It is in a separate structure to allow it to be handled
 * as a struct assignment.
 */
typedef struct pm_comp {
	char 	*pmc_name;		/* name of component */
	int	pmc_numlevels;		/* number of power levels supported */
	int	*pmc_lvals;		/* numerical values of levels */
	int	*pmc_thresh;		/* thresholds in secs, last INT_MAX */
	char	**pmc_lnames;		/* human readable names of levels */
	/*
	 * This part is just bookkeeping for the storage space involved above
	 * used for copying and freeing the struct members.  This because C
	 * is really an assembler at heart.
	 */
	size_t	pmc_name_sz;		/* size of name string		*/
	char	*pmc_lname_buf;		/* buffer holding *pmc_lnames	*/
	size_t	pmc_lnames_sz;		/* total size of pmc_lname_buf	*/
} pm_comp_t;

/*
 * Here we have the rest of what we need to know about a component.
 */
typedef struct pm_component {
	uint_t pmc_flags;		/* flags this component */
	uint_t pmc_busycount;		/* for nesting busy calls */
	time_t pmc_timestamp;		/* timestamp */
	uint_t pmc_norm_pwr;		/* normal power index (or value) */
	int pmc_cur_pwr;		/* current power index (or value)  */
	int pmc_phc_pwr;		/* prev. value of curpwr (deadlock) */
	pm_comp_t pmc_comp;		/* component description */
} pm_component_t;

/*
 * All members of this struct are protected by PM_LOCK_DIP(dip).
 *
 * kidsupcnt counts (the number of components of new-style children at non-zero
 * level (unknown counts as non-zero)) + (the number of old-style children with
 * component 0 at non-zero level) for parents that have not asked for
 * notification.  When kidsupcnt is 0 for a nexus node, then pm scans it,
 * otherwise it leaves it alone.
 * Parents that ask for notification always get get scanned,
 * so we keep their kidsupcnt at zero.
 */
typedef struct pm_info {
	uint_t		pmi_dev_pm_state; /* PM state of a device */
	int		pmi_clone;	/* owner for direct pm'd devs */
	int		pmi_levels[2];	/* storage space for 2 levels */
	int		*pmi_lp;	/* storage space for >2 levels */
	kcondvar_t	pmi_cv;		/* condvar for direct PM access */
} pm_info_t;

/*
 * Work request structure for the dependency processing thread.
 */
typedef struct pm_dep_wk {
	int		pdw_type;		/* Type of request */
	int		pdw_wait;		/* caller waits for result */
	int		pdw_done;		/* set when req is done */
	int		pdw_ret;		/* return value to caller */
	int		pdw_pwr;		/* pwr level of keeper */
	kcondvar_t	pdw_cv;			/* cv to wake up caller */
	struct		pm_dep_wk *pdw_next;	/* next element */
	char		*pdw_keeper;
	char		*pdw_kept;
} pm_dep_wk_t;

/*
 * Types of work, depends on when it gets called:
 */
#define	PM_DEP_WK_POWER_ON		1	/* power on */
#define	PM_DEP_WK_POWER_OFF		2	/* power off */
#define	PM_DEP_WK_DETACH		3	/* detach */
#define	PM_DEP_WK_REMOVE_DEP		4	/* dependency removed */
#define	PM_DEP_WK_BRINGUP_SELF		5	/* released from direct PM */
#define	PM_DEP_WK_RECORD_KEEPER		6	/* PM_ADD_DEPENDENT */
#define	PM_DEP_WK_RECORD_KEEPER_PROP	7	/* PM_ADD_DEPENDENT_PROP */
#define	PM_DEP_WK_KEPT			8	/* dep. work as a kept */
#define	PM_DEP_WK_KEEPER		9	/* dep. work as a keeper */
#define	PM_DEP_WK_ATTACH		10	/* when dip is attached */
#define	PM_DEP_WK_CHECK_KEPT		11	/* check if this is a kept */
#define	PM_DEP_WK_CPR_SUSPEND		12	/* Suspend dep. during CPR */
#define	PM_DEP_WK_CPR_RESUME		13	/* Resume dep. after CPR */

/*
 * Wait for dependency work to finish or not.
 */
#define	PM_DEP_WAIT	1
#define	PM_DEP_NOWAIT	0

typedef enum pm_canblock
{
	PM_CANBLOCK_BLOCK,	/* wait for controlling process action */
	PM_CANBLOCK_FAIL,	/* don't wait, fail request */
	PM_CANBLOCK_BYPASS	/* don't wait, ignore controlling process */
} pm_canblock_t;

typedef enum pm_cpupm
{
	PM_CPUPM_NOTSET,	/* no specific treatment of CPU devices */
	PM_CPUPM_POLLING,	/* CPUPM enabled: polling mode */
	PM_CPUPM_EVENT,		/* CPUPM enabled: event driven mode */
	PM_CPUPM_DISABLE	/* do not power manage CPU devices */
} pm_cpupm_t;

#define	PPM(dip) ((dev_info_t *)DEVI(dip)->devi_pm_ppm)

/*
 * The power request struct uses for the DDI_CTLOPS_POWER busctl.
 *
 * Note: When changing this enum it is necessary to maintain binary
 * compatibility with older versions.  To insure that, add new values only
 * at the end and refrain from deleting any existing values.
 */
typedef enum {
	PMR_SET_POWER = 1,		/* called ddi_power (obsolete)	*/
	PMR_SUSPEND,			/* parental suspend		*/
	PMR_RESUME,			/* parental resume		*/
	PMR_PRE_SET_POWER,		/* parent's "pre" notification	*/
	PMR_POST_SET_POWER,		/* parent's "post" notification	*/
	PMR_PPM_SET_POWER,		/* platform pm set power	*/
	PMR_PPM_ATTACH,			/* ppm attach notify - unused	*/
	PMR_PPM_DETACH,			/* ppm detach notify - unused   */
	PMR_PPM_POWER_CHANGE_NOTIFY,	/* ppm level change notify	*/
	PMR_REPORT_PMCAP,		/* report pm capability		*/
	PMR_CHANGED_POWER,		/* parent's power_has_changed notif. */
	PMR_PPM_PRE_PROBE,		/* ppm pre probe notify		*/
	PMR_PPM_POST_PROBE,		/* ppm post probe notify	*/
	PMR_PPM_PRE_ATTACH,		/* ppm pre attach notify	*/
	PMR_PPM_POST_ATTACH,		/* ppm post pm attach notify	*/
	PMR_PPM_PRE_DETACH,		/* ppm pre pm detach notify	*/
	PMR_PPM_POST_DETACH,		/* ppm post pm detach notify	*/
	PMR_PPM_UNMANAGE,		/* device being unmanaged	*/
	PMR_PPM_PRE_RESUME,		/* ppm resume notify		*/
	PMR_PPM_ALL_LOWEST,		/* ppm all lowest power notify	*/
	PMR_PPM_LOCK_POWER,		/* ppm lock power		*/
	PMR_PPM_UNLOCK_POWER,		/* ppm unlock power		*/
	PMR_PPM_TRY_LOCK_POWER,		/* ppm try lock power		*/
	PMR_PPM_INIT_CHILD,		/* ppm init child notify	*/
	PMR_PPM_UNINIT_CHILD,		/* ppm uninit child notify	*/
	PMR_PPM_POWER_LOCK_OWNER,	/* ppm power lock owner's address */
	PMR_PPM_ENTER_SX,		/* ppm: enter ACPI S[2-4] state	*/
	PMR_PPM_EXIT_SX,		/* ppm: enter ACPI S[2-4] state	*/
	PMR_PPM_SEARCH_LIST		/* ppm: search tuple list	*/
} pm_request_type;

/*
 * When changing the elements of the union below it is necessary to
 * maintain binary compatibility with older versions.  Refrain from
 * deleting existing elements of the union or modifying their contents.
 * Avoid increasing the total size of this structure if new elements
 * must be added.
 */
typedef struct power_req {
	pm_request_type request_type;
	union req {
		/*
		 * PMR_SET_POWER (obsolete)
		 */
		struct set_power_req {
			dev_info_t	*who;
			int		cmpt;
			int		level;
		} set_power_req;
		/*
		 * PMR_SUSPEND
		 */
		struct suspend_req {
			dev_info_t	*who;
			ddi_detach_cmd_t cmd;
		} suspend_req;
		/*
		 * PMR_PPM_PRE_RESUME or PMR_RESUME
		 */
		struct resume_req {
			dev_info_t	*who;
			ddi_attach_cmd_t cmd;
		} resume_req;
		/*
		 * PMR_PRE_SET_POWER
		 */
		struct pre_set_power_req {
			dev_info_t	*who;
			int		cmpt;
			int		old_level;
			int		new_level;
		} pre_set_power_req;
		/*
		 * PMR_POST_SET_POWER
		 */
		struct post_set_power_req {
			dev_info_t	*who;
			int		cmpt;
			int		old_level;
			int		new_level;
			int		result;		/* driver's return */
		} post_set_power_req;
		/*
		 * PMR_PPM_SET_POWER
		 */
		struct ppm_set_power_req {
			dev_info_t	*who;
			int		cmpt;
			int		old_level;
			int		new_level;
			pm_canblock_t	canblock;
			void		*cookie;
		} ppm_set_power_req;
		/*
		 * PMR_PPM_POWER_CHANGE_NOTIFY
		 */
		struct ppm_notify_level_req {
			dev_info_t	*who;
			int		cmpt;
			int		old_level;
			int		new_level;
		} ppm_notify_level_req;
		/*
		 * PMR_REPORT_PMCAP
		 */
		struct report_pmcap_req {
			dev_info_t	*who;
			int		cap;
			void 		*arg;
		} report_pmcap_req;
		/*
		 * PMR_CHANGED_POWER
		 */
		struct changed_power_req {
			dev_info_t	*who;
			int		cmpt;
			int		old_level;
			int		new_level;
			int		result;
		} changed_power_req;
		/*
		 * PMR_PPM_PRE_PROBE, PMR_PPM_POST_PROBE, PMR_PPM_PRE_ATTACH,
		 * PMR_PPM_POST_ATTACH, PMR_PPM_PRE_DETACH, PMR_PPM_POST_DETACH
		 * PMR_PPM_INIT_CHILD, PMR_PPM_UNINIT_CHILD, or PMR_PPM_UNMANAGE
		 */
		struct ppm_config_req {
			dev_info_t	*who;
			int		result;		/* post only */
		} ppm_config_req;
		/*
		 * PMR_PPM_ALL_LOWEST
		 */
		struct ppm_all_lowest_req {
			int		mode;
		} ppm_all_lowest_req;
		/*
		 * PMR_PPM_LOCK_POWER, PMR_PPM_TRY_LOCK_POWER
		 */
		struct ppm_lock_power_req {
			dev_info_t	*who;
			int		*circp;
		} ppm_lock_power_req;
		/*
		 * PMR_PPM_UNLOCK_POWER
		 */
		struct ppm_unlock_power_req {
			dev_info_t	*who;
			int		circ;
		} ppm_unlock_power_req;
		/*
		 * PMR_PPM_POWER_LOCK_OWNER
		 */
		struct ppm_power_lock_owner_req {
			dev_info_t	*who;
			kthread_t	*owner;
		} ppm_power_lock_owner_req;
		/*
		 * PMR_PPM_POWER_ENTER_SX
		 */
		struct ppm_power_enter_sx_req {
			int	sx_state;	/* S3, S4 */
			int	test_point;	/* test point */
			uint64_t wakephys;	/* restart vector phys addr */
			void *psr;		/* PSM (apic) state buffer */
		} ppm_power_enter_sx_req;
		/*
		 * PMR_PPM_SEARCH_LIST
		 */
		struct ppm_search_list {
			pm_searchargs_t *searchlist;
			int		result;
		} ppm_search_list_req;
	} req;
} power_req_t;

#define	S3	3
#define	S4	4

extern int cpr_test_point;
extern major_t cpr_device;

#define	LOOP_BACK_NONE	0
#define	LOOP_BACK_PASS	1
#define	LOOP_BACK_FAIL	2
#define	FORCE_SUSPEND_TO_RAM	3
#define	DEVICE_SUSPEND_TO_RAM	4

/*
 * Struct passed as arg to appm_ioctl
 */
typedef struct s3_args {
	int		s3a_state;	/* S3, S4 */
	int		s3a_test_point;	/* test point */
	uint64_t	s3a_wakephys;	/* restart vector physical addr */
	void		*s3a_psr;	/* apic state save buffer */
} s3a_t;

/*
 * Structure used by the following bus_power operations:
 *
 *	BUS_POWER_PRE_NOTIFICATION
 *	BUS_POWER_POST_NOTIFICATION
 *	BUS_POWER_CHILD_PWRCHG
 */
typedef struct pm_bp_child_pwrchg {
	dev_info_t	*bpc_dip;	/* dip of the target device */
	char		*bpc_path;	/* path to the target device */
	int		bpc_comp;	/* component changing power */
	int		bpc_olevel;	/* old power level */
	int		bpc_nlevel;	/* new power level */
	void		*bpc_private;	/* PM framework private */
} pm_bp_child_pwrchg_t;

/*
 * Structure used by the BUS_POWER_NEXUS_PWRUP operation
 */
typedef struct pm_bp_nexus_pwrup {
	dev_info_t	*bpn_dip;	/* dip of the nexus device */
	int		bpn_comp;	/* component powering up */
	int		bpn_level;	/* new power level */
	void		*bpn_private;	/* PM framework private */
} pm_bp_nexus_pwrup_t;

/*
 * Structure used by the BUS_POWER_HAS_CHANGED operation
 */
typedef struct pm_bp_has_changed {
	dev_info_t	*bphc_dip;	/* dip of the target device */
	char		*bphc_path;	/* path to the target device */
	int		bphc_comp;	/* component changing power */
	int		bphc_olevel;	/* old power level */
	int		bphc_nlevel;	/* new power level */
	void		*bphc_private;	/* PM framework private */
} pm_bp_has_changed_t;

/*
 * Commands indicating which activity is requiring an
 * update to the noinvol counters.
 */
#define	PM_BP_NOINVOL_ATTACH	1
#define	PM_BP_NOINVOL_DETACH	2
#define	PM_BP_NOINVOL_REMDRV	3
#define	PM_BP_NOINVOL_CFB	4
#define	PM_BP_NOINVOL_POWER	5

/*
 * Structure used by the BUS_POWER_NOINVOL operation.
 */
typedef struct pm_bp_noinvol {
	dev_info_t	*bpni_dip;	/* dip of the target device */
	char		*bpni_path;	/* path to the target device */
	int		bpni_cmd;	/* how to update the counters */
	int		bpni_volpmd;	/* volpmd of target device */
	int		bpni_wasvolpmd;	/* whether to update volpmd */
	void		*bpni_private;	/* PM framework private */
} pm_bp_noinvol_t;

/*
 * This struct is used by the code that makes a PMR_PPM_SET_POWER request
 * to ppm. Devices that changed power other than the primary device (which
 * was requested) are passed back to the pm framework through this
 * structure.
 */
typedef struct pm_ppm_devlist {
	dev_info_t	*ppd_who;
	int		ppd_cmpt;
	int		ppd_old_level;
	int		ppd_new_level;
	struct pm_ppm_devlist	*ppd_next;
} pm_ppm_devlist_t;

/*
 * This struct is used by the code that brings up parents and notifies
 * ppm drivers across probe/attach/detach (pm_pre/post_probe/attach/detach())
 */
typedef struct pm_ppm_cookie {
	dev_info_t		*ppc_dip;	/* dip of target node */
	dev_info_t		*ppc_pdip;	/* parent's dip */
	dev_info_t		*ppc_ppm;	/* interested ppm driver */
	int			ppc_cmd;	/* attach/detach cmd */
} pm_ppm_cookie_t;

/*
 * This struct records one dependency (a device keeps another or others up)
 * pdr_size includes size of strings.
 */
typedef struct pm_dep_rec {
	char *pdr_keeper;		/* physpath of device keeping up */
	char *pdr_kept;			/* physpath or property name */
	char **pdr_kept_paths;		/* array of kept devices' paths */
	struct pm_dep_rec *pdr_next;	/* next dependency device */
	size_t pdr_size;		/* size to kmem_free */
	major_t pdr_major;		/* major of kept driver (not props) */
	int pdr_isprop;			/* true if kept is property name */
	int pdr_kept_count;		/* how many kept altogether */
	int pdr_satisfied;		/* true if in force (not properties) */
} pm_pdr_t;


/*
 * This struct records threshold information about a single component
 */
typedef struct pm_thresh_entry {
	int pte_numthresh;
	int *pte_thresh;
} pm_pte_t;

/*
 * Note that this header and its array of entry structs with their arrays
 * of thresholds and string storage for physpath are all kmem_alloced in one
 * chunk for easy freeing ptr_size is the size of that chunk
 */
typedef struct pm_thresh_rec {
	char			*ptr_physpath;	/* identifies node */
	struct pm_thresh_rec	*ptr_next;
	int			ptr_numcomps;	/* number of components */
	size_t			ptr_size;	/* total size for kmem_free */
	pm_pte_t 		*ptr_entries;
} pm_thresh_rec_t;

/*
 * pmi_dev_pm_state state bits:
 */

/*
 * a direct-pm device, not scanned, but controlled by a process
 */
#define	PM_DIRECT	0x1
/*
 * autopm is suspended while waiting to see if detach succeeds
 */
#define	PM_DETACHING	0x2

/*
 * An all_to_normal operation for an autopm device that is detaching, is
 * deferred in case the detach fails.
 */
#define	PM_ALLNORM_DEFERRED	0x4

#define	PM_GET_PM_INFO(dip) (DEVI(dip)->devi_pm_info)
#define	PM_GET_PM_SCAN(dip) (DEVI(dip)->devi_pm_scan)

#define	PM_NUMCMPTS(dip) (DEVI(dip)->devi_pm_num_components)
#define	PM_CP(dip, comp) (&DEVI(dip)->devi_pm_components[comp])

/*
 * Returns true if the device specified by dip is directly power managed
 */
#define	PM_ISDIRECT(dip) \
	(((pm_info_t *)PM_GET_PM_INFO(dip))->pmi_dev_pm_state & PM_DIRECT)

/*
 * Returns true if the device specified by dip is an old node for which we
 * provide backwards compatible behavior (e.g. no pm-components property).
 */
#define	PM_ISBC(dip) (DEVI(dip)->devi_pm_flags & PMC_BC)

/*
 * Returns true if we have skipped a dependency bringup on this dip.
 */
#define	PM_SKBU(dip) (DEVI(dip)->devi_pm_flags & PMC_SKIP_BRINGUP)

/*
 * Returns true if device specified by dip is a power manageable CPU.
 */
#define	PM_ISCPU(dip) (DEVI(dip)->devi_pm_flags & PMC_CPU_DEVICE)

/*
 * Returns true if cpupm is enabled in event driven mode.
 */
#define	PM_EVENT_CPUPM (cpupm == PM_CPUPM_EVENT)

/*
 * Returns true if cpupm is enabled in polling mode.
 */
#define	PM_POLLING_CPUPM (cpupm == PM_CPUPM_POLLING)

/*
 * Returns true if cpupm operating using the default mode.
 */
#define	PM_DEFAULT_CPUPM (cpupm == cpupm_default_mode)

/*
 * Returns true if is disabled.
 */
#define	PM_CPUPM_DISABLED (cpupm == PM_CPUPM_DISABLE)

/*
 * If ((autopm is enabled and
 *	(CPUPM is not disabled and we're not in event mode, or it isn't a cpu))
 *	  OR
 *	(CPUPM are enabled and it is one))
 */
#define	PM_SCANABLE(dip) ((autopm_enabled && \
	((!PM_CPUPM_DISABLED && !PM_EVENT_CPUPM) || !PM_ISCPU(dip))) || \
	(PM_POLLING_CPUPM && PM_ISCPU(dip)))

#define	PM_NOT_ALL_LOWEST	0x0	/* not all components are at lowest */
#define	PM_ALL_LOWEST		0x1	/* all components are at lowest lvl */

#define	PM_ADDR(dip)	(ddi_get_name_addr(dip) ? ddi_get_name_addr(dip) : "")
#define	PM_NAME(dip)	(ddi_binding_name(dip))
#define	PM_NODE(dip)	(ddi_node_name(dip))
#define	PM_INST(dip)	(ddi_get_instance(dip))
#define	PM_DEVICE(dip)	PM_NAME(dip), PM_ADDR(dip), PM_NODE(dip), PM_INST(dip)

#ifdef	DEBUG
/*
 * Flags passed to PMD to enable debug printfs.  If the same flag is set in
 * pm_debug below then the message is printed.  The most generally useful
 * ones are the first 3 or 4.
 */
#define	PMD_ERROR	0x0000001
#define	PMD_FAIL	0x0000002
#define	PMD_IOCTL	0x0000004
#define	PMD_SCAN	0x0000008
#define	PMD_RESCAN	0x0000010
#define	PMD_REMINFO	0x0000020
#define	PMD_NAMETODIP	0x0000040
#define	PMD_CLOSE	0x0000080
#define	PMD_DIN		0x0000100	/* Dev Is Needed */
#define	PMD_PMC		0x0000200	/* for testing with sun4m pmc driver */
#define	PMD_PPM		0x0000400
#define	PMD_DEP		0x0000800	/* dependency processing */
#define	PMD_IDLEDOWN	0x0001000
#define	PMD_SET		0x0002000
#define	PMD_BRING	0x0004000
#define	PMD_ALLNORM	0x0008000
#define	PMD_REMDEV	0x0010000
#define	PMD_LEVEL	0x0020000
#define	PMD_THRESH	0x0040000
#define	PMD_DPM		0x0080000	/* Direct Power Management */
#define	PMD_NORM	0x0100000
#define	PMD_STATS	0x0200000
#define	PMD_DEREG	0x0400000
#define	PMD_KEEPS	0x0800000
#define	PMD_KIDSUP	0x1000000
#define	PMD_TCHECK	0x2000000
#define	PMD_NOINVOL	0x4000000
#define	PMD_CFB		0x8000000	/* console fb pm */
#define	PMD_DHR		0x10000000	/* driver hold/rele changes */
#define	PMD_PIL		0x20000000	/* print out PIL when calling power */
#define	PMD_PHC		0x40000000	/* pm_power_has_changed messages */
#define	PMD_LOCK	0x80000000
#define	PMD_SX		0x80000000	/* ACPI S[1234] states */
#define	PMD_PROTO	PMD_SX		/* and other Prototype stuff */

extern uint_t	pm_debug;
extern uint_t	pm_divertdebug;
/*PRINTFLIKE1*/
extern void	pm_log(const char *fmt, ...) __KPRINTFLIKE(1);

#if !defined(__sparc)
/*
 * On non-sparc machines, PMDDEBUG isn't as big a deal as Sparc, so we
 * define PMDDEUG here for use on non-sparc platforms.
 */
#define	PMDDEBUG
#endif /* !__sparc */

#ifdef PMDDEBUG
#define	PMD(level, arglist) { 			\
	if (pm_debug & (level)) {		\
		pm_log arglist;			\
	}					\
}
#else /* !PMDDEBUG */
#define	PMD(level, arglist)	((void)0);
#endif /* PMDDEBUG */
#ifndef	sparc
extern clock_t pt_sleep;
/* code is char hex number to display on POST LED */
#define	PT(code) {outb(0x80, (char)code); drv_usecwait(pt_sleep); }
#else
#define	PT(code)
#endif
#else
#define	PMD(level, arglist)
#define	PT(code)
#endif
/*
 * Code	Value	Indication
 *
 */
#define	PT_SPL7		0x01	/* pm_suspend spl7 */
#define	PT_PMSRET	0x02	/* pm_suspend returns */
#define	PT_PPMCTLOP	0x03	/* invoking ppm_ctlops */
#define	PT_ACPISDEV	0x04	/* acpi suspend devices */
#define	PT_IC		0x05	/* acpi intr_clear */
#define	PT_1to1		0x06	/* 1:1 mapping */
#define	PT_SC		0x07	/* save context */
#define	PT_SWV		0x08	/* set waking vector */
#define	PT_SWV_FAIL	0x09	/* set waking vector failed */
#define	PT_EWE		0x0a	/* enable wake events */
#define	PT_EWE_FAIL	0x0b	/* enable wake events failed */
#define	PT_RTCW		0x0c	/* setting rtc wakeup */
#define	PT_RTCW_FAIL	0x0d	/* setting rtc wakeup failed */
#define	PT_TOD		0x0e	/* setting tod */
#define	PT_SXP		0x0f	/* sx prep */
#define	PT_SXE		0x10	/* sx enter */
#define	PT_SXE_FAIL	0x11	/* sx enter failed */
#define	PT_INSOM	0x12	/* insomnia label */
#define	PT_WOKE		0x20	/* woke up */
#define	PT_UNDO1to1	0x21	/* Undo 1:1 mapping */
#define	PT_LSS		0x22	/* leave sleep state */
#define	PT_LSS_FAIL	0x23	/* leave sleep state failed */
#define	PT_CPB		0x24	/* clear power button event */
#define	PT_CPB_FAIL	0x25	/* clear power button event failed */
#define	PT_DRTC_FAIL	0x26	/* disable rtc fails */
#define	PT_ACPIREINIT	0x27	/* reinit apic */
#define	PT_ACPIRESTORE	0x28	/* restore apic */
#define	PT_INTRRESTORE	0x28	/* restore interrupts */
#define	PT_RESDEV	0x2a	/* ressume acpi devices */
#define	PT_CPU		0x2b	/* init_cpu_syscall */
#define	PT_PRESUME	0x30	/* pm_resume entered */
#define	PT_RSUS		0x31	/* pm_resume "suspended" */
#define	PT_RKERN	0x32	/* pm_resume "kernel" */
#define	PT_RDRV		0x33	/* pm_resume "driver" */
#define	PT_RDRV_FAIL	0x34	/* pm_resume "driver" failed */
#define	PT_RRNOINVOL	0x35	/* pm_resume "reattach_noinvol" */
#define	PT_RUSER	0x36	/* pm_resume "user" */
#define	PT_RAPMSIG	0x37	/* pm_resume APM/SRN signal */
#define	PT_RMPO		0x38	/* pm_resume "mp_online" */
#define	PT_RDONE	0x39	/* pm_resume done */

extern void	pm_detaching(dev_info_t *);
extern void	pm_detach_failed(dev_info_t *);
extern int	pm_power(dev_info_t *, int, int);
extern int	pm_unmanage(dev_info_t *);
extern void	pm_rem_info(dev_info_t *);
extern int	pm_get_norm_pwrs(dev_info_t *, int **, size_t *);
extern dev_info_t *pm_name_to_dip(char *, int);
extern int	pm_power_up(dev_info_t *, int, int, int, pm_info_t *);
extern int	pm_default_idle_threshold;
extern void	pm_set_device_threshold(dev_info_t *, int, int);
extern int	pm_valid_power(dev_info_t *, int, int);
extern void	pm_lock_power(dev_info_t *, int *);
extern void	pm_unlock_power(dev_info_t *, int);
extern int	pm_try_locking_power(dev_info_t *, int *);
extern void	pm_lock_power_single(dev_info_t *, int *);
extern void	pm_unlock_power_single(dev_info_t *, int);
extern int	pm_try_locking_power_single(dev_info_t *, int *);
extern int	pm_isbc(dev_info_t *dip);
extern int	pm_isdirect(dev_info_t *dip);
extern int	pm_ctlops(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t o,
			void *a, void *v);
extern int	pm_noinvol_detached(char *);
extern int	pm_init_child(dev_info_t *);
extern int	pm_uninit_child(dev_info_t *);

extern int	pm_all_to_normal(dev_info_t *, pm_canblock_t);
extern int	pm_set_power(dev_info_t *, int, int, int, pm_canblock_t, int,
			int *);
extern void	pm_scan_init(dev_info_t *dip);
extern void	pm_scan_fini(dev_info_t *dip);
extern void	pm_scan_stop(dev_info_t *dip);
extern int	pm_scan_stop_walk(dev_info_t *dip, void *);
extern void	pm_scan(void *);
extern time_t	pm_scan_dev(dev_info_t *dip);
extern void	pm_rescan(void *);
extern int	pm_rescan_walk(dev_info_t *, void *);
extern void	pm_forget_power_level(dev_info_t *);
extern int	pm_pre_config(dev_info_t *, char *);
extern int	pm_pre_unconfig(dev_info_t *, int, int *, char *);
extern void	pm_post_config(dev_info_t *, char *);
extern void	pm_post_unconfig(dev_info_t *, int, char *);
extern void	pm_pre_probe(dev_info_t *, pm_ppm_cookie_t *);
extern void	pm_post_probe(pm_ppm_cookie_t *, int, int);
extern void	pm_post_attach(pm_ppm_cookie_t *, int);
extern void	pm_pre_attach(dev_info_t *, pm_ppm_cookie_t *,
			ddi_attach_cmd_t);
extern void	pm_pre_detach(dev_info_t *, ddi_detach_cmd_t,
			pm_ppm_cookie_t *);
extern void	pm_post_detach(pm_ppm_cookie_t *, int);
extern int	pm_powerup(dev_info_t *);
extern int	pm_all_at_normal(dev_info_t *);
extern int	pm_busop_bus_power(dev_info_t *, void *,
		    pm_bus_power_op_t, void *, void *);
extern void	pm_hold_power(dev_info_t *);
extern void	pm_rele_power(dev_info_t *);
extern void	pm_driver_removed(major_t);
extern void	pm_borrow_lock(kthread_t *);
extern void	pm_return_lock(void);
extern int	pm_reattach_noinvol(void);
extern void	pm_reattach_noinvol_fini();
extern void	pm_restore_direct_levels(void);
extern void	pm_save_direct_levels(void);
extern void	pm_cfb_setup(const char *);
extern void	pm_proceed(dev_info_t *, int, int, int);
extern void	pm_get_timestamps(dev_info_t *, time_t *);
extern void	pm_deregister_watcher(int, dev_info_t *);
extern void	pm_dispatch_to_dep_thread(int, char *, char *, int, int *, int);
extern int	e_pm_valid_comp(dev_info_t *, int, pm_component_t **);
extern int	e_pm_valid_info(dev_info_t *, pm_info_t **);
extern int	e_pm_valid_power(dev_info_t *, int, int);
extern void	pm_init_locks(void);
extern int	pm_register_ppm(int (*)(dev_info_t *), dev_info_t *);
extern int	pm_is_cfb(dev_info_t *);
#ifdef	DEBUG
extern int	pm_cfb_is_up(void);
#endif

#ifdef DIPLOCKDEBUG
#define	PM_LOCK_DIP(dip)	{ PMD(PMD_LOCK, ("dip lock %s@%s(%s#%d) " \
				    "%s %d\n", PM_DEVICE(dip),		  \
				    __FILE__, __LINE__)) 		  \
				    mutex_enter(&DEVI(dip)->devi_pm_lock); }
#define	PM_UNLOCK_DIP(dip)	{ PMD(PMD_LOCK, ("dip unlock %s@%s(%s#%d) " \
				    "%s %d\n", PM_DEVICE(dip),		    \
				    __FILE__, __LINE__))		    \
				    mutex_exit(&DEVI(dip)->devi_pm_lock); }
#else
#define	PM_LOCK_DIP(dip)	mutex_enter(&DEVI(dip)->devi_pm_lock)
#define	PM_UNLOCK_DIP(dip)	mutex_exit(&DEVI(dip)->devi_pm_lock)
#endif

/*
 * These are the same DEBUG or not
 */
#define	PM_LOCK_BUSY(dip)	mutex_enter(&DEVI(dip)->devi_pm_busy_lock)
#define	PM_UNLOCK_BUSY(dip)	mutex_exit(&DEVI(dip)->devi_pm_busy_lock)
#define	PM_LOCK_POWER(dip, circp)	pm_lock_power(dip, circp)
#define	PM_UNLOCK_POWER(dip, circ)	pm_unlock_power(dip, circ)
#define	PM_TRY_LOCK_POWER(dip, circp)	pm_try_locking_power(dip, circp)
#define	PM_IAM_LOCKING_DIP(dip)	(mutex_owned(&DEVI(dip)->devi_pm_lock))

#define	PM_DEFAULT_SYS_IDLENESS	1800	/* 30 minutes */

/*
 * Codes put into the pr_retval field of pm_rsvp_t that tell pm_block()
 * how to proceed
 */
#define	PMP_SUCCEED	0x1	/* return success, the process did it */
#define	PMP_FAIL	0x2	/* return fail, process did something else */
#define	PMP_RELEASE	0x3	/* let it go, the process has lost interest */
				/* also arg to pm_proceed to signal this */
/*
 * Values of "style" for e_pm_manage and pm_premanage
 */
#define	PM_STYLE_NEW		0
#define	PM_STYLE_UNKNOWN	1

/*
 * Arg passed to pm_proceed that results in PMP_SUCCEED or PMP_FAIL being set
 * in pr_retval depending on what is pending
 */
#define	PMP_SETPOWER	0x4

#define	PM_MAX_CLONE	256

typedef struct pm_rsvp {
	dev_info_t	*pr_dip;
	int		pr_comp;
	int		pr_newlevel;
	int		pr_oldlevel;
	kcondvar_t	pr_cv;		/* a place to sleep */
	int		pr_retval;	/* what to do when you wake up */
	struct pm_rsvp	*pr_next;
	struct pm_rsvp	*pr_prev;
} pm_rsvp_t;

typedef struct psce {	/* pm_state_change_entries */
	struct pm_state_change		*psce_first;
	struct pm_state_change		*psce_in;
	struct pm_state_change		*psce_out;
	struct pm_state_change		*psce_last;
	int				psce_overruns;
	int				psce_references;
	kmutex_t			psce_lock;
} psce_t;

typedef struct pscc {			/* pm_state_change_control */
	int		pscc_clone;
	dev_info_t	*pscc_dip;
	psce_t		*pscc_entries;
	struct pscc	*pscc_next;
	struct pscc	*pscc_prev;
} pscc_t;

#define	PSCCOUNT 128	/* number of state change entries kept per process */

/*
 * Struct used to track the existence of devices exporting the
 * no-involuntary-power-cycles property, and remember things from their
 * devinfo node for later attach.
 */
typedef struct pm_noinvol {
	struct pm_noinvol	*ni_next;
	char			*ni_path;
	major_t			ni_major;	/* for attaching at cpr time */
	uint_t			ni_flags;	/* selected PMC_* values */
	uint_t			ni_noinvolpm;	/* saved noinvolpm count */
	uint_t			ni_volpmd;	/* saved volpmd count */
	uint_t			ni_wasvolpmd;	/* was vol pm'd at detach */
	size_t			ni_size;
	int			ni_persistent;	/* still around */
} pm_noinvol_t;

#define	PMID_IOCTIMER		0x1		/* pm_ioctl sets during timer */
#define	PMID_CFBTIMER		0x2		/* cfb sets during timer */
#define	PMID_IOCSCAN		0x4		/* pm_ioctl sets during scan */
#define	PMID_CFBSCAN		0x8		/* cfb sets during scan */

#define	PMID_IOC		(PMID_IOCTIMER | PMID_IOCSCAN)
#define	PMID_CFB		(PMID_CFBTIMER | PMID_CFBSCAN)
#define	PMID_TIMERS		(PMID_IOCTIMER | PMID_CFBTIMER)
#define	PMID_SCANS		(PMID_IOCSCAN | PMID_CFBSCAN)
#define	PMID_SCANS_SHIFT	2
#define	PMID_SET_SCANS(pmid)	(pmid) |= (((pmid) & PMID_TIMERS) <<	\
				    PMID_SCANS_SHIFT);
#define	PMID_IS_IOC(pmid)	((pmid) & PMID_IOC)
#define	PMID_IS_CFB(pmid, dip)	(((pmid) & PMID_CFB) &&			\
				    (DEVI(dip)->devi_pm_flags &		\
				    (PMC_DEF_THRESH | PMC_NEXDEF_THRESH)))
#define	PM_IS_PID(dip)	(PMID_IS_IOC(PM_GET_PM_SCAN(dip)->ps_idle_down) || \
	PMID_IS_CFB(PM_GET_PM_SCAN(dip)->ps_idle_down, dip))
#define	PM_IS_CFB(dip)		(DEVI(dip)->devi_pm_flags & PMC_CONSOLE_FB)
#define	PM_KUC(dip)		(DEVI(dip)->devi_pm_kidsupcnt)
#define	PM_CURPOWER(dip, comp)	cur_power(PM_CP(dip, comp))

#define	PM_WANTS_NOTIFICATION(dip)					\
	(DEVI(dip)->devi_pm_flags & PMC_WANTS_NOTIFY)

#define	PM_HAS_BUS_POWER(dip)						\
	((DEVI(dip)->devi_ops->devo_bus_ops != NULL) &&			\
	(DEVI(dip)->devi_ops->devo_bus_ops->busops_rev >= BUSO_REV_7) &&\
	(DEVI(dip)->devi_ops->devo_bus_ops->bus_power != NULL))

#define	PM_BUS_POWER_FUNC(dip)						\
	DEVI(dip)->devi_ops->devo_bus_ops->bus_power

/*
 * Structure used to pass down sunpm's private data variables
 * through the bus_power bus_op calls
 */
typedef struct pm_sp_misc {
	pm_canblock_t   pspm_canblock;
	int pspm_scan;
	int *pspm_errnop;
	int pspm_direction;
} pm_sp_misc_t;

/*
 * This structure is used in validating that the power level
 * of the descendents are off, while a device is powered off.
 */
typedef struct pm_desc_pwrchk {
	dev_info_t *pdpc_dip;
	int pdpc_par_involved;
} pm_desc_pwrchk_t;


/*
 * These defines are used by pm_trans_check() to calculate time.
 * Mostly copied from "tzfile.h".
 */
#define	DC_SPY			(SECSPERDAY * DAYSPERNYEAR)
#define	DC_SPW			(SECSPERDAY * DAYSPERWEEK)
#define	DC_SPD			SECSPERDAY

#define	DC_SCSI_YEAR_LEN	4		/* YYYY */
#define	DC_SCSI_WEEK_LEN	2		/* WW */
#define	DC_SCSI_NPY		5		/* # power-cycle years */

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_EPM_H */
