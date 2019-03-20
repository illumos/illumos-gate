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
/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * sunpm.c builds sunpm.o	"power management framework"
 *	kernel-resident power management code.  Implements power management
 *	policy
 *	Assumes: all backwards compat. device components wake up on &
 *		 the pm_info pointer in dev_info is initially NULL
 *
 * PM - (device) Power Management
 *
 * Each device may have 0 or more components.  If a device has no components,
 * then it can't be power managed.  Each component has 2 or more
 * power states.
 *
 * "Backwards Compatible" (bc) devices:
 * There are two different types of devices from the point of view of this
 * code.  The original type, left over from the original PM implementation on
 * the voyager platform are known in this code as "backwards compatible"
 * devices (PM_ISBC(dip) returns true).
 * They are recognized by the pm code by the lack of a pm-components property
 * and a call made by the driver to pm_create_components(9F).
 * For these devices, component 0 is special, and represents the power state
 * of the device.  If component 0 is to be set to power level 0 (off), then
 * the framework must first call into the driver's detach(9E) routine with
 * DDI_PM_SUSPEND, to get the driver to save the hardware state of the device.
 * After setting component 0 from 0 to a non-zero power level, a call must be
 * made into the driver's attach(9E) routine with DDI_PM_RESUME.
 *
 * Currently, the only way to get a bc device power managed is via a set of
 * ioctls (PM_DIRECT_PM, PM_SET_CURRENT_POWER) issued to /dev/pm.
 *
 * For non-bc devices, the driver describes the components by exporting a
 * pm-components(9P) property that tells how many components there are,
 * tells what each component's power state values are, and provides human
 * readable strings (currently unused) for each component name and power state.
 * Devices which export pm-components(9P) are automatically power managed
 * whenever autopm is enabled (via PM_START_PM ioctl issued by pmconfig(1M)
 * after parsing power.conf(4)). The exception to this rule is that power
 * manageable CPU devices may be automatically managed independently of autopm
 * by either enabling or disabling (via PM_START_CPUPM and PM_STOP_CPUPM
 * ioctls) cpupm. If the CPU devices are not managed independently, then they
 * are managed by autopm. In either case, for automatically power managed
 * devices, all components are considered independent of each other, and it is
 * up to the driver to decide when a transition requires saving or restoring
 * hardware state.
 *
 * Each device component also has a threshold time associated with each power
 * transition (see power.conf(4)), and a busy/idle state maintained by the
 * driver calling pm_idle_component(9F) and pm_busy_component(9F).
 * Components are created idle.
 *
 * The PM framework provides several functions:
 * -implement PM policy as described in power.conf(4)
 *  Policy is set by pmconfig(1M) issuing pm ioctls based on power.conf(4).
 *  Policies consist of:
 *    -set threshold values (defaults if none provided by pmconfig)
 *    -set dependencies among devices
 *    -enable/disable autopm
 *    -enable/disable cpupm
 *    -turn down idle components based on thresholds (if autopm or cpupm is
 *     enabled) (aka scanning)
 *    -maintain power states based on dependencies among devices
 *    -upon request, or when the frame buffer powers off, attempt to turn off
 *     all components that are idle or become idle over the next (10 sec)
 *     period in an attempt to get down to an EnergyStar compliant state
 *    -prevent powering off of a device which exported the
 *     pm-no-involuntary-power-cycles property without active involvement of
 *     the device's driver (so no removing power when the device driver is
 *     not attached)
 * -provide a mechanism for a device driver to request that a device's component
 *  be brought back to the power level necessary for the use of the device
 * -allow a process to directly control the power levels of device components
 *  (via ioctls issued to /dev/pm--see usr/src/uts/common/io/pm.c)
 * -ensure that the console frame buffer is powered up before being referenced
 *  via prom_printf() or other prom calls that might generate console output
 * -maintain implicit dependencies (e.g. parent must be powered up if child is)
 * -provide "backwards compatible" behavior for devices without pm-components
 *  property
 *
 * Scanning:
 * Whenever autopm or cpupm  is enabled, the framework attempts to bring each
 * component of each managed device to its lowest power based on the threshold
 * of idleness associated with each transition and the busy/idle state of the
 * component.
 *
 * The actual work of this is done by pm_scan_dev(), which cycles through each
 * component of a device, checking its idleness against its current threshold,
 * and calling pm_set_power() as appropriate to change the power level.
 * This function also indicates when it would next be profitable to scan the
 * device again, and a new scan is scheduled after that time.
 *
 * Dependencies:
 * It is possible to establish a dependency between the power states of two
 * otherwise unrelated devices.  This is currently done to ensure that the
 * cdrom is always up whenever the console framebuffer is up, so that the user
 * can insert a cdrom and see a popup as a result.
 *
 * The dependency terminology used in power.conf(4) is not easy to understand,
 * so we've adopted a different terminology in the implementation.  We write
 * of a "keeps up" and a "kept up" device.  A relationship can be established
 * where one device keeps up another.  That means that if the keepsup device
 * has any component that is at a non-zero power level, all components of the
 * "kept up" device must be brought to full power.  This relationship is
 * asynchronous.  When the keeping device is powered up, a request is queued
 * to a worker thread to bring up the kept device.  The caller does not wait.
 * Scan will not turn down a kept up device.
 *
 * Direct PM:
 * A device may be directly power managed by a process.  If a device is
 * directly pm'd, then it will not be scanned, and dependencies will not be
 * enforced.  * If a directly pm'd device's driver requests a power change (via
 * pm_raise_power(9F)), then the request is blocked and notification is sent
 * to the controlling process, which must issue the requested power change for
 * the driver to proceed.
 *
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/callb.h>		/* callback registration during CPR */
#include <sys/conf.h>		/* driver flags and functions */
#include <sys/open.h>		/* OTYP_CHR definition */
#include <sys/stat.h>		/* S_IFCHR definition */
#include <sys/pathname.h>	/* name -> dev_info xlation */
#include <sys/ddi_impldefs.h>	/* dev_info node fields */
#include <sys/kmem.h>		/* memory alloc stuff */
#include <sys/debug.h>
#include <sys/archsystm.h>
#include <sys/pm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sunpm.h>
#include <sys/epm.h>
#include <sys/vfs.h>
#include <sys/mode.h>
#include <sys/mkdev.h>
#include <sys/promif.h>
#include <sys/consdev.h>
#include <sys/esunddi.h>
#include <sys/modctl.h>
#include <sys/fs/ufs_fs.h>
#include <sys/note.h>
#include <sys/taskq.h>
#include <sys/bootconf.h>
#include <sys/reboot.h>
#include <sys/spl.h>
#include <sys/disp.h>
#include <sys/sobject.h>
#include <sys/sunmdi.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/cyclic.h>
#include <sys/uadmin.h>
#include <sys/srn.h>


/*
 * PM LOCKING
 *	The list of locks:
 * Global pm mutex locks.
 *
 * pm_scan_lock:
 *		It protects the timeout id of the scan thread, and the value
 *		of autopm_enabled and cpupm.  This lock is not held
 *		concurrently with any other PM locks.
 *
 * pm_clone_lock:	Protects the clone list and count of poll events
 *		pending for the pm driver.
 *		Lock ordering:
 *			pm_clone_lock -> pm_pscc_interest_rwlock,
 *			pm_clone_lock -> pm_pscc_direct_rwlock.
 *
 * pm_rsvp_lock:
 *		Used to synchronize the data structures used for processes
 *		to rendezvous with state change information when doing
 *		direct PM.
 *		Lock ordering:
 *			pm_rsvp_lock -> pm_pscc_interest_rwlock,
 *			pm_rsvp_lock -> pm_pscc_direct_rwlock,
 *			pm_rsvp_lock -> pm_clone_lock.
 *
 * ppm_lock:	protects the list of registered ppm drivers
 *		Lock ordering:
 *			ppm_lock -> ppm driver unit_lock
 *
 * pm_compcnt_lock:
 *		Protects count of components that are not at their lowest
 *		power level.
 *		Lock ordering:
 *			pm_compcnt_lock -> ppm_lock.
 *
 * pm_dep_thread_lock:
 *		Protects work list for pm_dep_thread.  Not taken concurrently
 *		with any other pm lock.
 *
 * pm_remdrv_lock:
 *		Serializes the operation of removing noinvol data structure
 *		entries for a branch of the tree when a driver has been
 *		removed from the system (modctl_rem_major).
 *		Lock ordering:
 *			pm_remdrv_lock -> pm_noinvol_rwlock.
 *
 * pm_cfb_lock: (High level spin lock)
 *		Protects the count of how many components of the console
 *		frame buffer are off (so we know if we have to bring up the
 *		console as a result of a prom_printf, etc.
 *		No other locks are taken while holding this lock.
 *
 * pm_loan_lock:
 *		Protects the lock_loan list.  List is used to record that one
 *		thread has acquired a power lock but has launched another thread
 *		to complete its processing.  An entry in the list indicates that
 *		the worker thread can borrow the lock held by the other thread,
 *		which must block on the completion of the worker.  Use is
 *		specific to module loading.
 *		No other locks are taken while holding this lock.
 *
 * Global PM rwlocks
 *
 * pm_thresh_rwlock:
 *		Protects the list of thresholds recorded for future use (when
 *		devices attach).
 *		Lock ordering:
 *			pm_thresh_rwlock -> devi_pm_lock
 *
 * pm_noinvol_rwlock:
 *		Protects list of detached nodes that had noinvol registered.
 *		No other PM locks are taken while holding pm_noinvol_rwlock.
 *
 * pm_pscc_direct_rwlock:
 *		Protects the list that maps devices being directly power
 *		managed to the processes that manage them.
 *		Lock ordering:
 *			pm_pscc_direct_rwlock -> psce_lock
 *
 * pm_pscc_interest_rwlock;
 *		Protects the list that maps state change events to processes
 *		that want to know about them.
 *		Lock ordering:
 *			pm_pscc_interest_rwlock -> psce_lock
 *
 * per-dip locks:
 *
 * Each node has these per-dip locks, which are only used if the device is
 * a candidate for power management (e.g. has pm components)
 *
 * devi_pm_lock:
 *		Protects all power management state of the node except for
 *		power level, which is protected by ndi_devi_enter().
 *		Encapsulated in macros PM_LOCK_DIP()/PM_UNLOCK_DIP().
 *		Lock ordering:
 *			devi_pm_lock -> pm_rsvp_lock,
 *			devi_pm_lock -> pm_dep_thread_lock,
 *			devi_pm_lock -> pm_noinvol_rwlock,
 *			devi_pm_lock -> power lock
 *
 * power lock (ndi_devi_enter()):
 *		Since changing power level is possibly a slow operation (30
 *		seconds to spin up a disk drive), this is locked separately.
 *		Since a call into the driver to change the power level of one
 *		component may result in a call back into the framework to change
 *		the power level of another, this lock allows re-entrancy by
 *		the same thread (ndi_devi_enter is used for this because
 *		the USB framework uses ndi_devi_enter in its power entry point,
 *		and use of any other lock would produce a deadlock.
 *
 * devi_pm_busy_lock:
 *		This lock protects the integrity of the busy count.  It is
 *		only taken by pm_busy_component() and pm_idle_component and
 *		some code that adjust the busy time after the timer gets set
 *		up or after a CPR operation.  It is per-dip to keep from
 *		single-threading all the disk drivers on a system.
 *		It could be per component instead, but most devices have
 *		only one component.
 *		No other PM locks are taken while holding this lock.
 *
 */

static int stdout_is_framebuffer;
static kmutex_t	e_pm_power_lock;
static kmutex_t pm_loan_lock;
kmutex_t	pm_scan_lock;
callb_id_t	pm_cpr_cb_id;
callb_id_t	pm_panic_cb_id;
callb_id_t	pm_halt_cb_id;
int		pm_comps_notlowest;	/* no. of comps not at lowest power */
int		pm_powering_down;	/* cpr is source of DDI_SUSPEND calls */

clock_t pm_id_ticks = 5;	/* ticks to wait before scan during idle-down */
clock_t pm_default_min_scan = PM_DEFAULT_MIN_SCAN;
clock_t pm_cpu_min_scan = PM_CPU_MIN_SCAN;

#define	PM_MIN_SCAN(dip)	(PM_ISCPU(dip) ? pm_cpu_min_scan : \
				    pm_default_min_scan)

static int pm_busop_set_power(dev_info_t *,
    void *, pm_bus_power_op_t, void *, void *);
static int pm_busop_match_request(dev_info_t *, void *);
static int pm_all_to_normal_nexus(dev_info_t *, pm_canblock_t);
static void e_pm_set_max_power(dev_info_t *, int, int);
static int e_pm_get_max_power(dev_info_t *, int);

/*
 * Dependency Processing is done thru a seperate thread.
 */
kmutex_t	pm_dep_thread_lock;
kcondvar_t	pm_dep_thread_cv;
pm_dep_wk_t	*pm_dep_thread_workq = NULL;
pm_dep_wk_t	*pm_dep_thread_tail = NULL;

/*
 * Autopm  must be turned on by a PM_START_PM ioctl, so we don't end up
 * power managing things in single user mode that have been suppressed via
 * power.conf entries.  Protected by pm_scan_lock.
 */
int		autopm_enabled;

/*
 * cpupm is turned on and off, by the PM_START_CPUPM and PM_STOP_CPUPM ioctls,
 * to define the power management behavior of CPU devices separate from
 * autopm. Protected by pm_scan_lock.
 */
pm_cpupm_t	cpupm = PM_CPUPM_NOTSET;

/*
 * Defines the default mode of operation for CPU power management,
 * either the polling implementation, or the event based dispatcher driven
 * implementation.
 */
pm_cpupm_t	cpupm_default_mode = PM_CPUPM_EVENT;

/*
 * AutoS3 depends on autopm being enabled, and must be enabled by
 * PM_START_AUTOS3 command.
 */
int		autoS3_enabled;

#if !defined(__sparc)
/*
 * on sparc these live in fillsysinfo.c
 *
 * If this variable is non-zero, cpr should return "not supported" when
 * it is queried even though it would normally be supported on this platform.
 */
int cpr_supported_override;

/*
 * Some platforms may need to support CPR even in the absence of
 * having the correct platform id information.  If this
 * variable is non-zero, cpr should proceed even in the absence
 * of otherwise being qualified.
 */
int cpr_platform_enable = 0;

#endif

/*
 * pm_S3_enabled indicates that we believe the platform can support S3,
 * which we get from pmconfig(1M)
 */
int		pm_S3_enabled;

/*
 * This flag is true while processes are stopped for a checkpoint/resume.
 * Controlling processes of direct pm'd devices are not available to
 * participate in power level changes, so we bypass them when this is set.
 */
static int	pm_processes_stopped;

#ifdef	DEBUG

/*
 * see common/sys/epm.h for PMD_* values
 */

uint_t		pm_debug = 0;

/*
 * If pm_divertdebug is set, then no prom_printf calls will be made by
 * PMD(), which will prevent debug output from bringing up the console
 * frame buffer.  Clearing this variable before setting pm_debug will result
 * in PMD output going to the console.
 *
 * pm_divertdebug is incremented in pm_set_power() if dip == cfb_dip to avoid
 * deadlocks and decremented at the end of pm_set_power()
 */
uint_t		pm_divertdebug = 1;
volatile uint_t pm_debug_to_console = 0;
kmutex_t	pm_debug_lock;		/* protects pm_divertdebug */

void prdeps(char *);
#endif

/* Globals */

/*
 * List of recorded thresholds and dependencies
 */
pm_thresh_rec_t *pm_thresh_head;
krwlock_t pm_thresh_rwlock;

pm_pdr_t *pm_dep_head;
static int pm_unresolved_deps = 0;
static int pm_prop_deps = 0;

/*
 * List of devices that exported no-involuntary-power-cycles property
 */
pm_noinvol_t *pm_noinvol_head;

/*
 * Locks used in noinvol processing
 */
krwlock_t pm_noinvol_rwlock;
kmutex_t pm_remdrv_lock;

int pm_default_idle_threshold = PM_DEFAULT_SYS_IDLENESS;
int pm_system_idle_threshold;
int pm_cpu_idle_threshold;

/*
 * By default nexus has 0 threshold, and depends on its children to keep it up
 */
int pm_default_nexus_threshold = 0;

/*
 * Data structures shared with common/io/pm.c
 */
kmutex_t	pm_clone_lock;
kcondvar_t	pm_clones_cv[PM_MAX_CLONE];
uint_t		pm_poll_cnt[PM_MAX_CLONE];	/* count of events for poll */
unsigned char	pm_interest[PM_MAX_CLONE];
struct pollhead	pm_pollhead;

/*
 * Data structures shared with common/io/srn.c
 */
kmutex_t	srn_clone_lock;		/* protects srn_signal, srn_inuse */
void (*srn_signal)(int type, int event);
int srn_inuse;				/* stop srn detach */

extern int	hz;
extern char	*platform_module_list[];

/*
 * Wrappers for use in ddi_walk_devs
 */

static int		pm_set_dev_thr_walk(dev_info_t *, void *);
static int		pm_restore_direct_lvl_walk(dev_info_t *, void *);
static int		pm_save_direct_lvl_walk(dev_info_t *, void *);
static int		pm_discard_dep_walk(dev_info_t *, void *);
#ifdef DEBUG
static int		pm_desc_pwrchk_walk(dev_info_t *, void *);
#endif

/*
 * Routines for managing noinvol devices
 */
int			pm_noinvol_update(int, int, int, char *, dev_info_t *);
void			pm_noinvol_update_node(dev_info_t *,
			    pm_bp_noinvol_t *req);

kmutex_t pm_rsvp_lock;
kmutex_t pm_compcnt_lock;
krwlock_t pm_pscc_direct_rwlock;
krwlock_t pm_pscc_interest_rwlock;

#define	PSC_INTEREST	0	/* belongs to interest psc list */
#define	PSC_DIRECT	1	/* belongs to direct psc list */

pscc_t *pm_pscc_interest;
pscc_t *pm_pscc_direct;

#define	PM_MAJOR(dip) ddi_driver_major(dip)
#define	PM_IS_NEXUS(dip) ((PM_MAJOR(dip) == DDI_MAJOR_T_NONE) ? 0 : \
	NEXUS_DRV(devopsp[PM_MAJOR(dip)]))
#define	POWERING_ON(old, new) ((old) == 0 && (new) != 0)
#define	POWERING_OFF(old, new) ((old) != 0 && (new) == 0)

#define	PM_INCR_NOTLOWEST(dip) {					\
	mutex_enter(&pm_compcnt_lock);					\
	if (!PM_IS_NEXUS(dip) ||					\
	    (DEVI(dip)->devi_pm_flags & (PMC_DEV_THRESH|PMC_COMP_THRESH))) {\
		if (pm_comps_notlowest == 0)				\
			pm_ppm_notify_all_lowest(dip, PM_NOT_ALL_LOWEST);\
		pm_comps_notlowest++;					\
		PMD(PMD_LEVEL, ("%s: %s@%s(%s#%d) incr notlowest->%d\n",\
		    pmf, PM_DEVICE(dip), pm_comps_notlowest))		\
	}								\
	mutex_exit(&pm_compcnt_lock);					\
}
#define	PM_DECR_NOTLOWEST(dip) {					\
	mutex_enter(&pm_compcnt_lock);					\
	if (!PM_IS_NEXUS(dip) ||					\
	    (DEVI(dip)->devi_pm_flags & (PMC_DEV_THRESH|PMC_COMP_THRESH))) {\
		ASSERT(pm_comps_notlowest);				\
		pm_comps_notlowest--;					\
		PMD(PMD_LEVEL, ("%s: %s@%s(%s#%d) decr notlowest to "	\
			    "%d\n", pmf, PM_DEVICE(dip), pm_comps_notlowest))\
		if (pm_comps_notlowest == 0)				\
			pm_ppm_notify_all_lowest(dip, PM_ALL_LOWEST);	\
	}								\
	mutex_exit(&pm_compcnt_lock);					\
}

/*
 * console frame-buffer power-management is not enabled when
 * debugging services are present.  to override, set pm_cfb_override
 * to non-zero.
 */
uint_t pm_cfb_comps_off = 0;	/* PM_LEVEL_UNKNOWN is considered on */
kmutex_t pm_cfb_lock;
int pm_cfb_enabled = 1;		/* non-zero allows pm of console frame buffer */
#ifdef DEBUG
int pm_cfb_override = 1;	/* non-zero allows pm of cfb with debuggers */
#else
int pm_cfb_override = 0;	/* non-zero allows pm of cfb with debuggers */
#endif

static dev_info_t *cfb_dip = 0;
static dev_info_t *cfb_dip_detaching = 0;
uint_t cfb_inuse = 0;
static ddi_softintr_t pm_soft_id;
static boolean_t pm_soft_pending;
int	pm_scans_disabled = 0;

/*
 * A structure to record the fact that one thread has borrowed a lock held
 * by another thread.  The context requires that the lender block on the
 * completion of the borrower.
 */
typedef struct lock_loan {
	struct lock_loan	*pmlk_next;
	kthread_t		*pmlk_borrower;
	kthread_t		*pmlk_lender;
	dev_info_t		*pmlk_dip;
} lock_loan_t;
static lock_loan_t lock_loan_head;	/* list head is a dummy element */

#ifdef	DEBUG
#ifdef	PMDDEBUG
#define	PMD_FUNC(func, name)	char *(func) = (name);
#else	/* !PMDDEBUG */
#define	PMD_FUNC(func, name)
#endif	/* PMDDEBUG */
#else	/* !DEBUG */
#define	PMD_FUNC(func, name)
#endif	/* DEBUG */


/*
 * Must be called before first device (including pseudo) attach
 */
void
pm_init_locks(void)
{
	mutex_init(&pm_scan_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pm_rsvp_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pm_compcnt_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pm_dep_thread_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pm_remdrv_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&pm_loan_lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&pm_thresh_rwlock, NULL, RW_DEFAULT, NULL);
	rw_init(&pm_noinvol_rwlock, NULL, RW_DEFAULT, NULL);
	cv_init(&pm_dep_thread_cv, NULL, CV_DEFAULT, NULL);
}

static int pm_reset_timestamps(dev_info_t *, void *);

static boolean_t
pm_cpr_callb(void *arg, int code)
{
	_NOTE(ARGUNUSED(arg))
	static int auto_save;
	static pm_cpupm_t cpupm_save;

	switch (code) {
	case CB_CODE_CPR_CHKPT:
		/*
		 * Cancel scan or wait for scan in progress to finish
		 * Other threads may be trying to restart the scan, so we
		 * have to keep at it unil it sticks
		 */
		mutex_enter(&pm_scan_lock);
		ASSERT(!pm_scans_disabled);
		pm_scans_disabled = 1;
		auto_save = autopm_enabled;
		autopm_enabled = 0;
		cpupm_save = cpupm;
		cpupm = PM_CPUPM_NOTSET;
		mutex_exit(&pm_scan_lock);
		ddi_walk_devs(ddi_root_node(), pm_scan_stop_walk, NULL);
		break;

	case CB_CODE_CPR_RESUME:
		ASSERT(!autopm_enabled);
		ASSERT(cpupm == PM_CPUPM_NOTSET);
		ASSERT(pm_scans_disabled);
		pm_scans_disabled = 0;
		/*
		 * Call pm_reset_timestamps to reset timestamps of each
		 * device to the time when the system is resumed so that their
		 * idleness can be re-calculated. That's to avoid devices from
		 * being powered down right after resume if the system was in
		 * suspended mode long enough.
		 */
		ddi_walk_devs(ddi_root_node(), pm_reset_timestamps, NULL);

		autopm_enabled = auto_save;
		cpupm = cpupm_save;
		/*
		 * If there is any auto-pm device, get the scanning
		 * going. Otherwise don't bother.
		 */
		ddi_walk_devs(ddi_root_node(), pm_rescan_walk, NULL);
		break;
	}
	return (B_TRUE);
}

/*
 * This callback routine is called when there is a system panic.  This function
 * exists for prototype matching.
 */
static boolean_t
pm_panic_callb(void *arg, int code)
{
	_NOTE(ARGUNUSED(arg, code))
	void pm_cfb_check_and_powerup(void);
	PMD(PMD_CFB, ("pm_panic_callb\n"))
	pm_cfb_check_and_powerup();
	return (B_TRUE);
}

static boolean_t
pm_halt_callb(void *arg, int code)
{
	_NOTE(ARGUNUSED(arg, code))
	return (B_TRUE);
}

static void pm_dep_thread(void);

/*
 * This needs to be called after the root and platform drivers are loaded
 * and be single-threaded with respect to driver attach/detach
 */
void
pm_init(void)
{
	PMD_FUNC(pmf, "pm_init")
	char **mod;
	extern pri_t minclsyspri;

	pm_comps_notlowest = 0;
	pm_system_idle_threshold = pm_default_idle_threshold;
	pm_cpu_idle_threshold = 0;

	pm_cpr_cb_id = callb_add(pm_cpr_callb, (void *)NULL,
	    CB_CL_CPR_PM, "pm_cpr");
	pm_panic_cb_id = callb_add(pm_panic_callb, (void *)NULL,
	    CB_CL_PANIC, "pm_panic");
	pm_halt_cb_id = callb_add(pm_halt_callb, (void *)NULL,
	    CB_CL_HALT, "pm_halt");

	/*
	 * Create a thread to do dependency processing.
	 */
	(void) thread_create(NULL, 0, (void (*)())pm_dep_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);

	/*
	 * loadrootmodules already loaded these ppm drivers, now get them
	 * attached so they can claim the root drivers as they attach
	 */
	for (mod = platform_module_list; *mod; mod++) {
		if (i_ddi_attach_hw_nodes(*mod) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "!cannot load platform pm driver %s\n",
			    *mod);
		} else {
			PMD(PMD_DHR, ("%s: %s (%s)\n", pmf, *mod,
			    ddi_major_to_name(ddi_name_to_major(*mod))))
		}
	}
}

/*
 * pm_scan_init - create pm scan data structure.  Called (if autopm or cpupm
 * enabled) when device becomes power managed or after a failed detach and
 * when autopm is started via PM_START_PM or PM_START_CPUPM ioctls, and after
 * a CPR resume to get all the devices scanning again.
 */
void
pm_scan_init(dev_info_t *dip)
{
	PMD_FUNC(pmf, "scan_init")
	pm_scan_t	*scanp;

	ASSERT(!PM_ISBC(dip));

	PM_LOCK_DIP(dip);
	scanp = PM_GET_PM_SCAN(dip);
	if (!scanp) {
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): create scan data\n",
		    pmf, PM_DEVICE(dip)))
		scanp =  kmem_zalloc(sizeof (pm_scan_t), KM_SLEEP);
		DEVI(dip)->devi_pm_scan = scanp;
	} else if (scanp->ps_scan_flags & PM_SCAN_STOP) {
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): "
		    "clear PM_SCAN_STOP flag\n", pmf, PM_DEVICE(dip)))
		scanp->ps_scan_flags &= ~PM_SCAN_STOP;
	}
	PM_UNLOCK_DIP(dip);
}

/*
 * pm_scan_fini - remove pm scan data structure when stopping pm on the device
 */
void
pm_scan_fini(dev_info_t *dip)
{
	PMD_FUNC(pmf, "scan_fini")
	pm_scan_t	*scanp;

	PMD(PMD_SCAN, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	ASSERT(!PM_ISBC(dip));
	PM_LOCK_DIP(dip);
	scanp = PM_GET_PM_SCAN(dip);
	if (!scanp) {
		PM_UNLOCK_DIP(dip);
		return;
	}

	ASSERT(!scanp->ps_scan_id && !(scanp->ps_scan_flags &
	    (PM_SCANNING | PM_SCAN_DISPATCHED | PM_SCAN_AGAIN)));

	kmem_free(scanp, sizeof (pm_scan_t));
	DEVI(dip)->devi_pm_scan = NULL;
	PM_UNLOCK_DIP(dip);
}

/*
 * Given a pointer to a component struct, return the current power level
 * (struct contains index unless it is a continuous level).
 * Located here in hopes of getting both this and dev_is_needed into the
 * cache together
 */
static int
cur_power(pm_component_t *cp)
{
	if (cp->pmc_cur_pwr == PM_LEVEL_UNKNOWN)
		return (cp->pmc_cur_pwr);

	return (cp->pmc_comp.pmc_lvals[cp->pmc_cur_pwr]);
}

static char *
pm_decode_direction(int direction)
{
	switch (direction) {
	case PM_LEVEL_UPONLY:
		return ("up");

	case PM_LEVEL_EXACT:
		return ("exact");

	case PM_LEVEL_DOWNONLY:
		return ("down");

	default:
		return ("INVALID DIRECTION");
	}
}

char *
pm_decode_op(pm_bus_power_op_t op)
{
	switch (op) {
	case BUS_POWER_CHILD_PWRCHG:
		return ("CHILD_PWRCHG");
	case BUS_POWER_NEXUS_PWRUP:
		return ("NEXUS_PWRUP");
	case BUS_POWER_PRE_NOTIFICATION:
		return ("PRE_NOTIFICATION");
	case BUS_POWER_POST_NOTIFICATION:
		return ("POST_NOTIFICATION");
	case BUS_POWER_HAS_CHANGED:
		return ("HAS_CHANGED");
	case BUS_POWER_NOINVOL:
		return ("NOINVOL");
	default:
		return ("UNKNOWN OP");
	}
}

/*
 * Returns true if level is a possible (valid) power level for component
 */
int
e_pm_valid_power(dev_info_t *dip, int cmpt, int level)
{
	PMD_FUNC(pmf, "e_pm_valid_power")
	pm_component_t *cp = PM_CP(dip, cmpt);
	int i;
	int *ip = cp->pmc_comp.pmc_lvals;
	int limit = cp->pmc_comp.pmc_numlevels;

	if (level < 0)
		return (0);
	for (i = 0; i < limit; i++) {
		if (level == *ip++)
			return (1);
	}
#ifdef DEBUG
	if (pm_debug & PMD_FAIL) {
		ip = cp->pmc_comp.pmc_lvals;

		for (i = 0; i < limit; i++)
			PMD(PMD_FAIL, ("%s: index=%d, level=%d\n",
			    pmf, i, *ip++))
	}
#endif
	return (0);
}

static int pm_start(dev_info_t *dip);
/*
 * Returns true if device is pm'd (after calling pm_start if need be)
 */
int
e_pm_valid_info(dev_info_t *dip, pm_info_t **infop)
{
	pm_info_t *info;

	/*
	 * Check if the device is power managed if not.
	 * To make the common case (device is power managed already)
	 * fast, we check without the lock.  If device is not already
	 * power managed, then we take the lock and the long route through
	 * go get it managed.  Devices never go unmanaged until they
	 * detach.
	 */
	info = PM_GET_PM_INFO(dip);
	if (!info) {
		if (!DEVI_IS_ATTACHING(dip)) {
			return (0);
		}
		if (pm_start(dip) != DDI_SUCCESS) {
			return (0);
		}
		info = PM_GET_PM_INFO(dip);
	}
	ASSERT(info);
	if (infop != NULL)
		*infop = info;
	return (1);
}

int
e_pm_valid_comp(dev_info_t *dip, int cmpt, pm_component_t **cpp)
{
	if (cmpt >= 0 && cmpt < PM_NUMCMPTS(dip)) {
		if (cpp != NULL)
			*cpp = PM_CP(dip, cmpt);
		return (1);
	} else {
		return (0);
	}
}

/*
 * Internal guts of ddi_dev_is_needed and pm_raise/lower_power
 */
static int
dev_is_needed(dev_info_t *dip, int cmpt, int level, int direction)
{
	PMD_FUNC(pmf, "din")
	pm_component_t *cp;
	char *pathbuf;
	int result;

	ASSERT(direction == PM_LEVEL_UPONLY || direction == PM_LEVEL_DOWNONLY);
	if (!e_pm_valid_info(dip, NULL) || !e_pm_valid_comp(dip, cmpt, &cp) ||
	    !e_pm_valid_power(dip, cmpt, level))
		return (DDI_FAILURE);

	PMD(PMD_DIN, ("%s: %s@%s(%s#%d) cmpt=%d, dir=%s, new=%d, cur=%d\n",
	    pmf, PM_DEVICE(dip), cmpt, pm_decode_direction(direction),
	    level, cur_power(cp)))

	if (pm_set_power(dip, cmpt, level,  direction,
	    PM_CANBLOCK_BLOCK, 0, &result) != DDI_SUCCESS) {
		if (direction == PM_LEVEL_UPONLY) {
			pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			(void) ddi_pathname(dip, pathbuf);
			cmn_err(CE_WARN, "Device %s failed to power up.",
			    pathbuf);
			kmem_free(pathbuf, MAXPATHLEN);
		}
		PMD(PMD_DIN | PMD_FAIL, ("%s: %s@%s(%s#%d) [%d] %s->%d failed, "
		    "errno %d\n", pmf, PM_DEVICE(dip), cmpt,
		    pm_decode_direction(direction), level, result))
		return (DDI_FAILURE);
	}

	PMD(PMD_RESCAN | PMD_DIN, ("%s: pm_rescan %s@%s(%s#%d)\n", pmf,
	    PM_DEVICE(dip)))
	pm_rescan(dip);
	return (DDI_SUCCESS);
}

/*
 * We can get multiple pm_rescan() threads, if one of them discovers
 * that no scan is running at the moment, it kicks it into action.
 * Otherwise, it tells the current scanning thread to scan again when
 * it is done by asserting the PM_SCAN_AGAIN flag. The PM_SCANNING and
 * PM_SCAN_AGAIN flags are used to regulate scan, to make sure only one
 * thread at a time runs the pm_scan_dev() code.
 */
void
pm_rescan(void *arg)
{
	PMD_FUNC(pmf, "rescan")
	dev_info_t	*dip = (dev_info_t *)arg;
	pm_info_t	*info;
	pm_scan_t	*scanp;
	timeout_id_t	scanid;

	PMD(PMD_SCAN, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	PM_LOCK_DIP(dip);
	info = PM_GET_PM_INFO(dip);
	scanp = PM_GET_PM_SCAN(dip);
	if (pm_scans_disabled || !PM_SCANABLE(dip) || !info || !scanp ||
	    (scanp->ps_scan_flags & PM_SCAN_STOP)) {
		PM_UNLOCK_DIP(dip);
		return;
	}
	if (scanp->ps_scan_flags & PM_SCANNING) {
		scanp->ps_scan_flags |= PM_SCAN_AGAIN;
		PM_UNLOCK_DIP(dip);
		return;
	} else if (scanp->ps_scan_id) {
		scanid = scanp->ps_scan_id;
		scanp->ps_scan_id = 0;
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): cancel timeout scanid %lx\n",
		    pmf, PM_DEVICE(dip), (ulong_t)scanid))
		PM_UNLOCK_DIP(dip);
		(void) untimeout(scanid);
		PM_LOCK_DIP(dip);
	}

	/*
	 * Dispatching pm_scan during attach time is risky due to the fact that
	 * attach might soon fail and dip dissolved, and panic may happen while
	 * attempting to stop scan. So schedule a pm_rescan instead.
	 * (Note that if either of the first two terms are true, taskq_dispatch
	 * will not be invoked).
	 *
	 * Multiple pm_scan dispatching is unecessary and costly to keep track
	 * of. The PM_SCAN_DISPATCHED flag is used between pm_rescan and pm_scan
	 * to regulate the dispatching.
	 *
	 * Scan is stopped before the device is detached (in pm_detaching())
	 * but it may get re-started during the post_detach processing if the
	 * driver fails to detach.
	 */
	if (DEVI_IS_ATTACHING(dip) ||
	    (scanp->ps_scan_flags & PM_SCAN_DISPATCHED) ||
	    taskq_dispatch(system_taskq, pm_scan, (void *)dip, TQ_NOSLEEP) ==
	    TASKQID_INVALID) {
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): attaching, pm_scan already "
		    "dispatched or dispatching failed\n", pmf, PM_DEVICE(dip)))
		if (scanp->ps_scan_id) {
			scanid = scanp->ps_scan_id;
			scanp->ps_scan_id = 0;
			PM_UNLOCK_DIP(dip);
			(void) untimeout(scanid);
			PM_LOCK_DIP(dip);
			if (scanp->ps_scan_id) {
				PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): a competing "
				    "thread scheduled pm_rescan, scanid %lx\n",
				    pmf, PM_DEVICE(dip),
				    (ulong_t)scanp->ps_scan_id))
				PM_UNLOCK_DIP(dip);
				return;
			}
		}
		scanp->ps_scan_id = timeout(pm_rescan, (void *)dip,
		    (scanp->ps_idle_down ? pm_id_ticks :
		    (PM_MIN_SCAN(dip) * hz)));
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): scheduled next pm_rescan, "
		    "scanid %lx\n", pmf, PM_DEVICE(dip),
		    (ulong_t)scanp->ps_scan_id))
	} else {
		PMD(PMD_SCAN, ("%s: dispatched pm_scan for %s@%s(%s#%d)\n",
		    pmf, PM_DEVICE(dip)))
		scanp->ps_scan_flags |= PM_SCAN_DISPATCHED;
	}
	PM_UNLOCK_DIP(dip);
}

void
pm_scan(void *arg)
{
	PMD_FUNC(pmf, "scan")
	dev_info_t	*dip = (dev_info_t *)arg;
	pm_scan_t	*scanp;
	time_t		nextscan;

	PMD(PMD_SCAN, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))

	PM_LOCK_DIP(dip);
	scanp = PM_GET_PM_SCAN(dip);
	ASSERT(scanp && PM_GET_PM_INFO(dip));

	if (pm_scans_disabled || !PM_SCANABLE(dip) ||
	    (scanp->ps_scan_flags & PM_SCAN_STOP)) {
		scanp->ps_scan_flags &= ~(PM_SCAN_AGAIN | PM_SCAN_DISPATCHED);
		PM_UNLOCK_DIP(dip);
		return;
	}

	if (scanp->ps_idle_down) {
		/*
		 * make sure we remember idledown was in affect until
		 * we've completed the scan
		 */
		PMID_SET_SCANS(scanp->ps_idle_down)
		PMD(PMD_IDLEDOWN, ("%s: %s@%s(%s#%d): idledown starts "
		    "(pmid %x)\n", pmf, PM_DEVICE(dip), scanp->ps_idle_down))
	}

	/* possible having two threads running pm_scan() */
	if (scanp->ps_scan_flags & PM_SCANNING) {
		scanp->ps_scan_flags |= PM_SCAN_AGAIN;
		PMD(PMD_SCAN, ("%s: scanning, will scan %s@%s(%s#%d) again\n",
		    pmf, PM_DEVICE(dip)))
		scanp->ps_scan_flags &= ~PM_SCAN_DISPATCHED;
		PM_UNLOCK_DIP(dip);
		return;
	}

	scanp->ps_scan_flags |= PM_SCANNING;
	scanp->ps_scan_flags &= ~PM_SCAN_DISPATCHED;
	do {
		scanp->ps_scan_flags &= ~PM_SCAN_AGAIN;
		PM_UNLOCK_DIP(dip);
		nextscan = pm_scan_dev(dip);
		PM_LOCK_DIP(dip);
	} while (scanp->ps_scan_flags & PM_SCAN_AGAIN);

	ASSERT(scanp->ps_scan_flags & PM_SCANNING);
	scanp->ps_scan_flags &= ~PM_SCANNING;

	if (scanp->ps_idle_down) {
		scanp->ps_idle_down &= ~PMID_SCANS;
		PMD(PMD_IDLEDOWN, ("%s: %s@%s(%s#%d): idledown ends "
		    "(pmid %x)\n", pmf, PM_DEVICE(dip), scanp->ps_idle_down))
	}

	/* schedule for next idle check */
	if (nextscan != LONG_MAX) {
		if (nextscan > (LONG_MAX / hz))
			nextscan = (LONG_MAX - 1) / hz;
		if (scanp->ps_scan_id) {
			PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): while scanning "
			    "another rescan scheduled scanid(%lx)\n", pmf,
			    PM_DEVICE(dip), (ulong_t)scanp->ps_scan_id))
			PM_UNLOCK_DIP(dip);
			return;
		} else if (!(scanp->ps_scan_flags & PM_SCAN_STOP)) {
			scanp->ps_scan_id = timeout(pm_rescan, (void *)dip,
			    (clock_t)(nextscan * hz));
			PMD(PMD_SCAN, ("%s: nextscan for %s@%s(%s#%d) in "
			    "%lx sec, scanid(%lx) \n", pmf, PM_DEVICE(dip),
			    (ulong_t)nextscan, (ulong_t)scanp->ps_scan_id))
		}
	}
	PM_UNLOCK_DIP(dip);
}

void
pm_get_timestamps(dev_info_t *dip, time_t *valuep)
{
	int components = PM_NUMCMPTS(dip);
	int i;

	ASSERT(components > 0);
	PM_LOCK_BUSY(dip);	/* so we get a consistent view */
	for (i = 0; i < components; i++) {
		valuep[i] = PM_CP(dip, i)->pmc_timestamp;
	}
	PM_UNLOCK_BUSY(dip);
}

/*
 * Returns true if device needs to be kept up because it exported the
 * "no-involuntary-power-cycles" property or we're pretending it did (console
 * fb case) or it is an ancestor of such a device and has used up the "one
 * free cycle" allowed when all such leaf nodes have voluntarily powered down
 * upon detach
 */
int
pm_noinvol(dev_info_t *dip)
{
	PMD_FUNC(pmf, "noinvol")

	/*
	 * This doesn't change over the life of a driver, so no locking needed
	 */
	if (PM_IS_CFB(dip)) {
		PMD(PMD_NOINVOL | PMD_CFB, ("%s: inhibits CFB %s@%s(%s#%d)\n",
		    pmf, PM_DEVICE(dip)))
		return (1);
	}
	/*
	 * Not an issue if no such kids
	 */
	if (DEVI(dip)->devi_pm_noinvolpm == 0) {
#ifdef DEBUG
		if (DEVI(dip)->devi_pm_volpmd != 0) {
			dev_info_t *pdip = dip;
			do {
				PMD(PMD_NOINVOL, ("%s: %s@%s(%s#%d) noinvol %d "
				    "volpmd %d\n", pmf, PM_DEVICE(pdip),
				    DEVI(pdip)->devi_pm_noinvolpm,
				    DEVI(pdip)->devi_pm_volpmd))
				pdip = ddi_get_parent(pdip);
			} while (pdip);
		}
#endif
		ASSERT(DEVI(dip)->devi_pm_volpmd == 0);
		return (0);
	}

	/*
	 * Since we now maintain the counts correct at every node, we no longer
	 * need to look up the tree.  An ancestor cannot use up the free cycle
	 * without the children getting their counts adjusted.
	 */

#ifdef	DEBUG
	if (DEVI(dip)->devi_pm_noinvolpm != DEVI(dip)->devi_pm_volpmd)
		PMD(PMD_NOINVOL, ("%s: (%d != %d) inhibits %s@%s(%s#%d)\n", pmf,
		    DEVI(dip)->devi_pm_noinvolpm, DEVI(dip)->devi_pm_volpmd,
		    PM_DEVICE(dip)))
#endif
	return (DEVI(dip)->devi_pm_noinvolpm != DEVI(dip)->devi_pm_volpmd);
}

static int	cur_threshold(dev_info_t *, int);
static int	pm_next_lower_power(pm_component_t *, int);

/*
 * This function performs the actual scanning of the device.
 * It attempts to power off the indicated device's components if they have
 * been idle and other restrictions are met.
 * pm_scan_dev calculates and returns when the next scan should happen for
 * this device.
 */
time_t
pm_scan_dev(dev_info_t *dip)
{
	PMD_FUNC(pmf, "scan_dev")
	pm_scan_t	*scanp;
	time_t		*timestamp, idletime, now, thresh;
	time_t		timeleft = 0;
#ifdef PMDDEBUG
	int		curpwr;
#endif
	int		i, nxtpwr, pwrndx, unused;
	size_t		size;
	pm_component_t	 *cp;
	dev_info_t	*pdip = ddi_get_parent(dip);
	int		circ;
	clock_t		min_scan = pm_default_min_scan;

	/*
	 * skip attaching device
	 */
	if (DEVI_IS_ATTACHING(dip)) {
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) is attaching, timeleft(%lx)\n",
		    pmf, PM_DEVICE(dip), min_scan))
		return (min_scan);
	}

	PM_LOCK_DIP(dip);
	scanp = PM_GET_PM_SCAN(dip);
	min_scan = PM_MIN_SCAN(dip);
	ASSERT(scanp && PM_GET_PM_INFO(dip));

	PMD(PMD_SCAN, ("%s: [BEGIN %s@%s(%s#%d)]\n", pmf, PM_DEVICE(dip)))
	PMD(PMD_SCAN, ("%s: %s@%s(%s#%d): kuc is %d\n", pmf, PM_DEVICE(dip),
	    PM_KUC(dip)))

	/* no scan under the following conditions */
	if (pm_scans_disabled || !PM_SCANABLE(dip) ||
	    (scanp->ps_scan_flags & PM_SCAN_STOP) ||
	    (PM_KUC(dip) != 0) ||
	    PM_ISDIRECT(dip) || pm_noinvol(dip)) {
		PM_UNLOCK_DIP(dip);
		PMD(PMD_SCAN, ("%s: [END, %s@%s(%s#%d)] no scan, "
		    "scan_disabled(%d), apm_enabled(%d), cpupm(%d), "
		    "kuc(%d), %s directpm, %s pm_noinvol\n",
		    pmf, PM_DEVICE(dip), pm_scans_disabled, autopm_enabled,
		    cpupm, PM_KUC(dip),
		    PM_ISDIRECT(dip) ? "is" : "is not",
		    pm_noinvol(dip) ? "is" : "is not"))
		return (LONG_MAX);
	}
	PM_UNLOCK_DIP(dip);

	if (!ndi_devi_tryenter(pdip, &circ)) {
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) can't hold pdip",
		    pmf, PM_DEVICE(pdip)))
		return ((time_t)1);
	}
	now = gethrestime_sec();
	size = PM_NUMCMPTS(dip) * sizeof (time_t);
	timestamp = kmem_alloc(size, KM_SLEEP);
	pm_get_timestamps(dip, timestamp);

	/*
	 * Since we removed support for backwards compatible devices,
	 * (see big comment at top of file)
	 * it is no longer required to deal with component 0 last.
	 */
	for (i = 0; i < PM_NUMCMPTS(dip); i++) {
		/*
		 * If already off (an optimization, perhaps)
		 */
		cp = PM_CP(dip, i);
		pwrndx = cp->pmc_cur_pwr;
#ifdef PMDDEBUG
		curpwr = (pwrndx == PM_LEVEL_UNKNOWN) ?
		    PM_LEVEL_UNKNOWN :
		    cp->pmc_comp.pmc_lvals[pwrndx];
#endif

		if (pwrndx == 0) {
			PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) comp %d off or "
			    "lowest\n", pmf, PM_DEVICE(dip), i))
			/* skip device if off or at its lowest */
			continue;
		}

		thresh = cur_threshold(dip, i);		/* comp i threshold */
		if ((timestamp[i] == 0) || (cp->pmc_busycount > 0)) {
			/* were busy or newly became busy by another thread */
			if (timeleft == 0)
				timeleft = max(thresh, min_scan);
			else
				timeleft = min(
				    timeleft, max(thresh, min_scan));
			continue;
		}

		idletime = now - timestamp[i];		/* idle time */
		PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) comp %d idle time %lx\n",
		    pmf, PM_DEVICE(dip), i, idletime))
		if (idletime >= thresh || PM_IS_PID(dip)) {
			nxtpwr = pm_next_lower_power(cp, pwrndx);
			PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) comp %d, %d->%d\n",
			    pmf, PM_DEVICE(dip), i, curpwr, nxtpwr))
			if (pm_set_power(dip, i, nxtpwr, PM_LEVEL_DOWNONLY,
			    PM_CANBLOCK_FAIL, 1, &unused) != DDI_SUCCESS &&
			    PM_CURPOWER(dip, i) != nxtpwr) {
				PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) comp %d, "
				    "%d->%d Failed\n", pmf, PM_DEVICE(dip),
				    i, curpwr, nxtpwr))
				timeleft = min_scan;
				continue;
			} else {
				PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) comp %d, "
				    "%d->%d, GOOD curpwr %d\n", pmf,
				    PM_DEVICE(dip), i, curpwr, nxtpwr,
				    cur_power(cp)))

				if (nxtpwr == 0)	/* component went off */
					continue;

				/*
				 * scan to next lower level
				 */
				if (timeleft == 0)
					timeleft = max(
					    1, cur_threshold(dip, i));
				else
					timeleft = min(timeleft,
					    max(1, cur_threshold(dip, i)));
				PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) comp %d, "
				    "timeleft(%lx)\n", pmf, PM_DEVICE(dip),
				    i, timeleft))
			}
		} else {	/* comp not idle long enough */
			if (timeleft == 0)
				timeleft = thresh - idletime;
			else
				timeleft = min(timeleft, (thresh - idletime));
			PMD(PMD_SCAN, ("%s: %s@%s(%s#%d) comp %d, timeleft="
			    "%lx\n", pmf, PM_DEVICE(dip), i, timeleft))
		}
	}
	ndi_devi_exit(pdip, circ);
	kmem_free(timestamp, size);
	PMD(PMD_SCAN, ("%s: [END %s@%s(%s#%d)] timeleft(%lx)\n", pmf,
	    PM_DEVICE(dip), timeleft))

	/*
	 * if components are already at lowest level, timeleft is left 0
	 */
	return ((timeleft == 0) ? LONG_MAX : timeleft);
}

/*
 * pm_scan_stop - cancel scheduled pm_rescan,
 *                wait for termination of dispatched pm_scan thread
 *                     and active pm_scan_dev thread.
 */
void
pm_scan_stop(dev_info_t *dip)
{
	PMD_FUNC(pmf, "scan_stop")
	pm_scan_t	*scanp;
	timeout_id_t	scanid;

	PMD(PMD_SCAN, ("%s: [BEGIN %s@%s(%s#%d)]\n", pmf, PM_DEVICE(dip)))
	PM_LOCK_DIP(dip);
	scanp = PM_GET_PM_SCAN(dip);
	if (!scanp) {
		PMD(PMD_SCAN, ("%s: [END %s@%s(%s#%d)] scan not initialized\n",
		    pmf, PM_DEVICE(dip)))
		PM_UNLOCK_DIP(dip);
		return;
	}
	scanp->ps_scan_flags |= PM_SCAN_STOP;

	/* cancel scheduled scan taskq */
	while (scanp->ps_scan_id) {
		scanid = scanp->ps_scan_id;
		scanp->ps_scan_id = 0;
		PM_UNLOCK_DIP(dip);
		(void) untimeout(scanid);
		PM_LOCK_DIP(dip);
	}

	while (scanp->ps_scan_flags & (PM_SCANNING | PM_SCAN_DISPATCHED)) {
		PM_UNLOCK_DIP(dip);
		delay(1);
		PM_LOCK_DIP(dip);
	}
	PM_UNLOCK_DIP(dip);
	PMD(PMD_SCAN, ("%s: [END %s@%s(%s#%d)]\n", pmf, PM_DEVICE(dip)))
}

int
pm_scan_stop_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	if (!PM_GET_PM_SCAN(dip))
		return (DDI_WALK_CONTINUE);
	ASSERT(!PM_ISBC(dip));
	pm_scan_stop(dip);
	return (DDI_WALK_CONTINUE);
}

/*
 * Converts a power level value to its index
 */
static int
power_val_to_index(pm_component_t *cp, int val)
{
	int limit, i, *ip;

	ASSERT(val != PM_LEVEL_UPONLY && val != PM_LEVEL_DOWNONLY &&
	    val != PM_LEVEL_EXACT);
	/*  convert power value into index (i) */
	limit = cp->pmc_comp.pmc_numlevels;
	ip = cp->pmc_comp.pmc_lvals;
	for (i = 0; i < limit; i++)
		if (val == *ip++)
			return (i);
	return (-1);
}

/*
 * Converts a numeric power level to a printable string
 */
static char *
power_val_to_string(pm_component_t *cp, int val)
{
	int index;

	if (val == PM_LEVEL_UPONLY)
		return ("<UPONLY>");

	if (val == PM_LEVEL_UNKNOWN ||
	    (index = power_val_to_index(cp, val)) == -1)
		return ("<LEVEL_UNKNOWN>");

	return (cp->pmc_comp.pmc_lnames[index]);
}

/*
 * Return true if this node has been claimed by a ppm.
 */
static int
pm_ppm_claimed(dev_info_t *dip)
{
	return (PPM(dip) != NULL);
}

/*
 * A node which was voluntarily power managed has just used up its "free cycle"
 * and need is volpmd field cleared, and the same done to all its descendents
 */
static void
pm_clear_volpm_dip(dev_info_t *dip)
{
	PMD_FUNC(pmf, "clear_volpm_dip")

	if (dip == NULL)
		return;
	PMD(PMD_NOINVOL, ("%s: clear volpm from %s@%s(%s#%d)\n", pmf,
	    PM_DEVICE(dip)))
	DEVI(dip)->devi_pm_volpmd = 0;
	for (dip = ddi_get_child(dip); dip; dip = ddi_get_next_sibling(dip)) {
		pm_clear_volpm_dip(dip);
	}
}

/*
 * A node which was voluntarily power managed has used up the "free cycles"
 * for the subtree that it is the root of.  Scan through the list of detached
 * nodes and adjust the counts of any that are descendents of the node.
 */
static void
pm_clear_volpm_list(dev_info_t *dip)
{
	PMD_FUNC(pmf, "clear_volpm_list")
	char	*pathbuf;
	size_t	len;
	pm_noinvol_t *ip;

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);
	len = strlen(pathbuf);
	PMD(PMD_NOINVOL, ("%s: clear volpm list %s\n", pmf, pathbuf))
	rw_enter(&pm_noinvol_rwlock, RW_WRITER);
	for (ip = pm_noinvol_head; ip; ip = ip->ni_next) {
		PMD(PMD_NOINVOL, ("%s: clear volpm: ni_path %s\n", pmf,
		    ip->ni_path))
		if (strncmp(pathbuf, ip->ni_path, len) == 0 &&
		    ip->ni_path[len] == '/') {
			PMD(PMD_NOINVOL, ("%s: clear volpm: %s\n", pmf,
			    ip->ni_path))
			ip->ni_volpmd = 0;
			ip->ni_wasvolpmd = 0;
		}
	}
	kmem_free(pathbuf, MAXPATHLEN);
	rw_exit(&pm_noinvol_rwlock);
}

/*
 * Powers a device, suspending or resuming the driver if it is a backward
 * compatible device, calling into ppm to change power level.
 * Called with the component's power lock held.
 */
static int
power_dev(dev_info_t *dip, int comp, int level, int old_level,
    pm_canblock_t canblock, pm_ppm_devlist_t **devlist)
{
	PMD_FUNC(pmf, "power_dev")
	power_req_t power_req;
	int		power_op_ret;	/* DDI_SUCCESS or DDI_FAILURE */
	int		resume_needed = 0;
	int		suspended = 0;
	int		result;
#ifdef PMDDEBUG
	struct pm_component *cp = PM_CP(dip, comp);
#endif
	int		bc = PM_ISBC(dip);
	int pm_all_components_off(dev_info_t *);
	int		clearvolpmd = 0;
	char		pathbuf[MAXNAMELEN];
#ifdef PMDDEBUG
	char *ppmname, *ppmaddr;
#endif
	/*
	 * If this is comp 0 of a backwards compat device and we are
	 * going to take the power away, we need to detach it with
	 * DDI_PM_SUSPEND command.
	 */
	if (bc && comp == 0 && POWERING_OFF(old_level, level)) {
		if (devi_detach(dip, DDI_PM_SUSPEND) != DDI_SUCCESS) {
			/* We could not suspend before turning cmpt zero off */
			PMD(PMD_ERROR, ("%s: could not suspend %s@%s(%s#%d)\n",
			    pmf, PM_DEVICE(dip)))
			return (DDI_FAILURE);
		} else {
			DEVI(dip)->devi_pm_flags |= PMC_SUSPENDED;
			suspended++;
		}
	}
	power_req.request_type = PMR_PPM_SET_POWER;
	power_req.req.ppm_set_power_req.who = dip;
	power_req.req.ppm_set_power_req.cmpt = comp;
	power_req.req.ppm_set_power_req.old_level = old_level;
	power_req.req.ppm_set_power_req.new_level = level;
	power_req.req.ppm_set_power_req.canblock = canblock;
	power_req.req.ppm_set_power_req.cookie = NULL;
#ifdef PMDDEBUG
	if (pm_ppm_claimed(dip)) {
		ppmname = PM_NAME(PPM(dip));
		ppmaddr = PM_ADDR(PPM(dip));

	} else {
		ppmname = "noppm";
		ppmaddr = "0";
	}
	PMD(PMD_PPM, ("%s: %s@%s(%s#%d):%s[%d] %s (%d) -> %s (%d) via %s@%s\n",
	    pmf, PM_DEVICE(dip), cp->pmc_comp.pmc_name, comp,
	    power_val_to_string(cp, old_level), old_level,
	    power_val_to_string(cp, level), level, ppmname, ppmaddr))
#endif
	/*
	 * If non-bc noinvolpm device is turning first comp on, or noinvolpm
	 * bc device comp 0 is powering on, then we count it as a power cycle
	 * against its voluntary count.
	 */
	if (DEVI(dip)->devi_pm_volpmd &&
	    (!bc && pm_all_components_off(dip) && level != 0) ||
	    (bc && comp == 0 && POWERING_ON(old_level, level)))
		clearvolpmd = 1;
	if ((power_op_ret = pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER,
	    &power_req, &result)) == DDI_SUCCESS) {
		/*
		 * Now do involuntary pm accounting;  If we've just cycled power
		 * on a voluntarily pm'd node, and by inference on its entire
		 * subtree, we need to set the subtree (including those nodes
		 * already detached) volpmd counts to 0, and subtract out the
		 * value of the current node's volpmd count from the ancestors
		 */
		if (clearvolpmd) {
			int volpmd = DEVI(dip)->devi_pm_volpmd;
			pm_clear_volpm_dip(dip);
			pm_clear_volpm_list(dip);
			if (volpmd) {
				(void) ddi_pathname(dip, pathbuf);
				(void) pm_noinvol_update(PM_BP_NOINVOL_POWER,
				    volpmd, 0, pathbuf, dip);
			}
		}
	} else {
		PMD(PMD_FAIL, ("%s: can't set comp %d (%s) of %s@%s(%s#%d) "
		    "to level %d (%s)\n", pmf, comp, cp->pmc_comp.pmc_name,
		    PM_DEVICE(dip), level, power_val_to_string(cp, level)))
	}
	/*
	 * If some other devices were also powered up (e.g. other cpus in
	 * the same domain) return a pointer to that list
	 */
	if (devlist) {
		*devlist = (pm_ppm_devlist_t *)
		    power_req.req.ppm_set_power_req.cookie;
	}
	/*
	 * We will have to resume the device if the device is backwards compat
	 * device and either of the following is true:
	 * -This is comp 0 and we have successfully powered it up
	 * -This is comp 0 and we have failed to power it down. Resume is
	 *  needed because we have suspended it above
	 */

	if (bc && comp == 0) {
		ASSERT(PM_ISDIRECT(dip) || DEVI_IS_DETACHING(dip));
		if (power_op_ret == DDI_SUCCESS) {
			if (POWERING_ON(old_level, level)) {
				/*
				 * It must be either suspended or resumed
				 * via pm_power_has_changed path
				 */
				ASSERT((DEVI(dip)->devi_pm_flags &
				    PMC_SUSPENDED) ||
				    (PM_CP(dip, comp)->pmc_flags &
				    PM_PHC_WHILE_SET_POWER));

					resume_needed = suspended;
			}
		} else {
			if (POWERING_OFF(old_level, level)) {
				/*
				 * It must be either suspended or resumed
				 * via pm_power_has_changed path
				 */
				ASSERT((DEVI(dip)->devi_pm_flags &
				    PMC_SUSPENDED) ||
				    (PM_CP(dip, comp)->pmc_flags &
				    PM_PHC_WHILE_SET_POWER));

					resume_needed = suspended;
			}
		}
	}
	if (resume_needed) {
		ASSERT(DEVI(dip)->devi_pm_flags & PMC_SUSPENDED);
		/* ppm is not interested in DDI_PM_RESUME */
		if ((power_op_ret = devi_attach(dip, DDI_PM_RESUME)) ==
		    DDI_SUCCESS) {
			DEVI(dip)->devi_pm_flags &= ~PMC_SUSPENDED;
		} else
			cmn_err(CE_WARN, "!pm: Can't resume %s@%s(%s#%d)",
			    PM_DEVICE(dip));
	}
	return (power_op_ret);
}

/*
 * Return true if we are the owner or a borrower of the devi lock.  See
 * pm_lock_power_single() about borrowing the lock.
 */
static int
pm_devi_lock_held(dev_info_t *dip)
{
	lock_loan_t *cur;

	if (DEVI_BUSY_OWNED(dip))
		return (1);

	/* return false if no locks borrowed */
	if (lock_loan_head.pmlk_next == NULL)
		return (0);

	mutex_enter(&pm_loan_lock);
	/* see if our thread is registered as a lock borrower. */
	for (cur = lock_loan_head.pmlk_next; cur; cur = cur->pmlk_next)
		if (cur->pmlk_borrower == curthread)
			break;
	mutex_exit(&pm_loan_lock);

	return (cur != NULL && cur->pmlk_lender == DEVI(dip)->devi_busy_thread);
}

/*
 * pm_set_power: adjusts power level of device.	 Assumes device is power
 * manageable & component exists.
 *
 * Cases which require us to bring up devices we keep up ("wekeepups") for
 * backwards compatible devices:
 *	component 0 is off and we're bringing it up from 0
 *		bring up wekeepup first
 *	and recursively when component 0 is off and we bring some other
 *	component up from 0
 * For devices which are not backward compatible, our dependency notion is much
 * simpler.  Unless all components are off, then wekeeps must be on.
 * We don't treat component 0 differently.
 * Canblock tells how to deal with a direct pm'd device.
 * Scan arg tells us if we were called from scan, in which case we don't need
 * to go back to the root node and walk down to change power.
 */
int
pm_set_power(dev_info_t *dip, int comp, int level, int direction,
    pm_canblock_t canblock, int scan, int *retp)
{
	PMD_FUNC(pmf, "set_power")
	char		*pathbuf;
	pm_bp_child_pwrchg_t bpc;
	pm_sp_misc_t	pspm;
	int		ret = DDI_SUCCESS;
	int		unused = DDI_SUCCESS;
	dev_info_t	*pdip = ddi_get_parent(dip);

#ifdef DEBUG
	int		diverted = 0;

	/*
	 * This prevents operations on the console from calling prom_printf and
	 * either deadlocking or bringing up the console because of debug
	 * output
	 */
	if (dip == cfb_dip) {
		diverted++;
		mutex_enter(&pm_debug_lock);
		pm_divertdebug++;
		mutex_exit(&pm_debug_lock);
	}
#endif
	ASSERT(direction == PM_LEVEL_UPONLY || direction == PM_LEVEL_DOWNONLY ||
	    direction == PM_LEVEL_EXACT);
	PMD(PMD_SET, ("%s: %s@%s(%s#%d), comp=%d, dir=%s, new=%d\n",
	    pmf, PM_DEVICE(dip), comp, pm_decode_direction(direction), level))
	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);
	bpc.bpc_dip = dip;
	bpc.bpc_path = pathbuf;
	bpc.bpc_comp = comp;
	bpc.bpc_olevel = PM_CURPOWER(dip, comp);
	bpc.bpc_nlevel = level;
	pspm.pspm_direction = direction;
	pspm.pspm_errnop = retp;
	pspm.pspm_canblock = canblock;
	pspm.pspm_scan = scan;
	bpc.bpc_private = &pspm;

	/*
	 * If a config operation is being done (we've locked the parent) or
	 * we already hold the power lock (we've locked the node)
	 * then we can operate directly on the node because we have already
	 * brought up all the ancestors, otherwise, we have to go back to the
	 * top of the tree.
	 */
	if (pm_devi_lock_held(pdip) || pm_devi_lock_held(dip))
		ret = pm_busop_set_power(dip, NULL, BUS_POWER_CHILD_PWRCHG,
		    (void *)&bpc, (void *)&unused);
	else
		ret = pm_busop_bus_power(ddi_root_node(), NULL,
		    BUS_POWER_CHILD_PWRCHG, (void *)&bpc, (void *)&unused);
#ifdef DEBUG
	if (ret != DDI_SUCCESS || *retp != DDI_SUCCESS) {
		PMD(PMD_ERROR, ("%s: %s@%s(%s#%d) can't change power, ret=%d, "
		    "errno=%d\n", pmf, PM_DEVICE(dip), ret, *retp))
	}
	if (diverted) {
		mutex_enter(&pm_debug_lock);
		pm_divertdebug--;
		mutex_exit(&pm_debug_lock);
	}
#endif
	kmem_free(pathbuf, MAXPATHLEN);
	return (ret);
}

/*
 * If holddip is set, then if a dip is found we return with the node held.
 *
 * This code uses the same locking scheme as e_ddi_hold_devi_by_path
 * (resolve_pathname), but it does not drive attach.
 */
dev_info_t *
pm_name_to_dip(char *pathname, int holddip)
{
	struct pathname pn;
	char		*component;
	dev_info_t	*parent, *child;
	int		circ;

	if ((pathname == NULL) || (*pathname != '/'))
		return (NULL);

	/* setup pathname and allocate component */
	if (pn_get(pathname, UIO_SYSSPACE, &pn))
		return (NULL);
	component = kmem_alloc(MAXNAMELEN, KM_SLEEP);

	/* start at top, process '/' component */
	parent = child = ddi_root_node();
	ndi_hold_devi(parent);
	pn_skipslash(&pn);
	ASSERT(i_ddi_devi_attached(parent));

	/* process components of pathname */
	while (pn_pathleft(&pn)) {
		(void) pn_getcomponent(&pn, component);

		/* enter parent and search for component child */
		ndi_devi_enter(parent, &circ);
		child = ndi_devi_findchild(parent, component);
		if ((child == NULL) || !i_ddi_devi_attached(child)) {
			child = NULL;
			ndi_devi_exit(parent, circ);
			ndi_rele_devi(parent);
			goto out;
		}

		/* attached child found, hold child and release parent */
		ndi_hold_devi(child);
		ndi_devi_exit(parent, circ);
		ndi_rele_devi(parent);

		/* child becomes parent, and process next component */
		parent = child;
		pn_skipslash(&pn);

		/* loop with active ndi_devi_hold of child->parent */
	}

out:
	pn_free(&pn);
	kmem_free(component, MAXNAMELEN);

	/* if we are not asked to return with hold, drop current hold */
	if (child && !holddip)
		ndi_rele_devi(child);
	return (child);
}

/*
 * Search for a dependency and mark it unsatisfied
 */
static void
pm_unsatisfy(char *keeper, char *kept)
{
	PMD_FUNC(pmf, "unsatisfy")
	pm_pdr_t *dp;

	PMD(PMD_KEEPS, ("%s: keeper=%s, kept=%s\n", pmf, keeper, kept))
	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (!dp->pdr_isprop) {
			if (strcmp(dp->pdr_keeper, keeper) == 0 &&
			    (dp->pdr_kept_count > 0) &&
			    strcmp(dp->pdr_kept_paths[0], kept) == 0) {
				if (dp->pdr_satisfied) {
					dp->pdr_satisfied = 0;
					pm_unresolved_deps++;
					PMD(PMD_KEEPS, ("%s: clear satisfied, "
					    "pm_unresolved_deps now %d\n", pmf,
					    pm_unresolved_deps))
				}
			}
		}
	}
}

/*
 * Device dip is being un power managed, it keeps up count other devices.
 * We need to release any hold we have on the kept devices, and also
 * mark the dependency no longer satisfied.
 */
static void
pm_unkeeps(int count, char *keeper, char **keptpaths, int pwr)
{
	PMD_FUNC(pmf, "unkeeps")
	int i, j;
	dev_info_t *kept;
	dev_info_t *dip;
	struct pm_component *cp;
	int keeper_on = 0, circ;

	PMD(PMD_KEEPS, ("%s: count=%d, keeper=%s, keptpaths=%p\n", pmf, count,
	    keeper, (void *)keptpaths))
	/*
	 * Try to grab keeper. Keeper may have gone away by now,
	 * in this case, used the passed in value pwr
	 */
	dip = pm_name_to_dip(keeper, 1);
	for (i = 0; i < count; i++) {
		/* Release power hold */
		kept = pm_name_to_dip(keptpaths[i], 1);
		if (kept) {
			PMD(PMD_KEEPS, ("%s: %s@%s(%s#%d)[%d]\n", pmf,
			    PM_DEVICE(kept), i))
			/*
			 * We need to check if we skipped a bringup here
			 * because we could have failed the bringup
			 * (ie DIRECT PM device) and have
			 * not increment the count.
			 */
			if ((dip != NULL) && (PM_GET_PM_INFO(dip) != NULL)) {
				keeper_on = 0;
				PM_LOCK_POWER(dip, &circ);
				for (j = 0; j < PM_NUMCMPTS(dip); j++) {
					cp = &DEVI(dip)->devi_pm_components[j];
					if (cur_power(cp)) {
						keeper_on++;
						break;
					}
				}
				if (keeper_on && (PM_SKBU(kept) == 0)) {
					pm_rele_power(kept);
					DEVI(kept)->devi_pm_flags
					    &= ~PMC_SKIP_BRINGUP;
				}
				PM_UNLOCK_POWER(dip, circ);
			} else if (pwr) {
				if (PM_SKBU(kept) == 0) {
					pm_rele_power(kept);
					DEVI(kept)->devi_pm_flags
					    &= ~PMC_SKIP_BRINGUP;
				}
			}
			ddi_release_devi(kept);
		}
		/*
		 * mark this dependency not satisfied
		 */
		pm_unsatisfy(keeper, keptpaths[i]);
	}
	if (dip)
		ddi_release_devi(dip);
}

/*
 * Device kept is being un power managed, it is kept up by keeper.
 * We need to mark the dependency no longer satisfied.
 */
static void
pm_unkepts(char *kept, char *keeper)
{
	PMD_FUNC(pmf, "unkepts")
	PMD(PMD_KEEPS, ("%s: kept=%s, keeper=%s\n", pmf, kept, keeper))
	ASSERT(keeper != NULL);
	/*
	 * mark this dependency not satisfied
	 */
	pm_unsatisfy(keeper, kept);
}

/*
 * Removes dependency information and hold on the kepts, if the path is a
 * path of a keeper.
 */
static void
pm_free_keeper(char *path, int pwr)
{
	pm_pdr_t *dp;
	int i;
	size_t length;

	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (strcmp(dp->pdr_keeper, path) != 0)
			continue;
		/*
		 * Remove all our kept holds and the dependency records,
		 * then free up the kept lists.
		 */
		pm_unkeeps(dp->pdr_kept_count, path, dp->pdr_kept_paths, pwr);
		if (dp->pdr_kept_count)  {
			for (i = 0; i < dp->pdr_kept_count; i++) {
				length = strlen(dp->pdr_kept_paths[i]);
				kmem_free(dp->pdr_kept_paths[i], length + 1);
			}
			kmem_free(dp->pdr_kept_paths,
			    dp->pdr_kept_count * sizeof (char **));
			dp->pdr_kept_paths = NULL;
			dp->pdr_kept_count = 0;
		}
	}
}

/*
 * Removes the device represented by path from the list of kepts, if the
 * path is a path of a kept
 */
static void
pm_free_kept(char *path)
{
	pm_pdr_t *dp;
	int i;
	int j, count;
	size_t length;
	char **paths;

	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (dp->pdr_kept_count == 0)
			continue;
		count = dp->pdr_kept_count;
		/* Remove this device from the kept path lists */
		for (i = 0; i < count; i++) {
			if (strcmp(dp->pdr_kept_paths[i], path) == 0) {
				pm_unkepts(path, dp->pdr_keeper);
				length = strlen(dp->pdr_kept_paths[i]) + 1;
				kmem_free(dp->pdr_kept_paths[i], length);
				dp->pdr_kept_paths[i] = NULL;
				dp->pdr_kept_count--;
			}
		}
		/* Compact the kept paths array */
		if (dp->pdr_kept_count) {
			length = dp->pdr_kept_count * sizeof (char **);
			paths = kmem_zalloc(length, KM_SLEEP);
			j = 0;
			for (i = 0; i < count; i++) {
				if (dp->pdr_kept_paths[i] != NULL) {
					paths[j] = dp->pdr_kept_paths[i];
					j++;
				}
			}
			ASSERT(j == dp->pdr_kept_count);
		}
		/* Now free the old array and point to the new one */
		kmem_free(dp->pdr_kept_paths, count * sizeof (char **));
		if (dp->pdr_kept_count)
			dp->pdr_kept_paths = paths;
		else
			dp->pdr_kept_paths = NULL;
	}
}

/*
 * Free the dependency information for a device.
 */
void
pm_free_keeps(char *path, int pwr)
{
	PMD_FUNC(pmf, "free_keeps")

#ifdef DEBUG
	int doprdeps = 0;
	void prdeps(char *);

	PMD(PMD_KEEPS, ("%s: %s\n", pmf, path))
	if (pm_debug & PMD_KEEPS) {
		doprdeps = 1;
		prdeps("pm_free_keeps before");
	}
#endif
	/*
	 * First assume we are a keeper and remove all our kepts.
	 */
	pm_free_keeper(path, pwr);
	/*
	 * Now assume we a kept device, and remove all our records.
	 */
	pm_free_kept(path);
#ifdef	DEBUG
	if (doprdeps) {
		prdeps("pm_free_keeps after");
	}
#endif
}

static int
pm_is_kept(char *path)
{
	pm_pdr_t *dp;
	int i;

	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (dp->pdr_kept_count == 0)
			continue;
		for (i = 0; i < dp->pdr_kept_count; i++) {
			if (strcmp(dp->pdr_kept_paths[i], path) == 0)
				return (1);
		}
	}
	return (0);
}

static void
e_pm_hold_rele_power(dev_info_t *dip, int cnt)
{
	PMD_FUNC(pmf, "hold_rele_power")
	int circ;

	if ((dip == NULL) ||
	    (PM_GET_PM_INFO(dip) == NULL) || PM_ISBC(dip))
		return;

	PM_LOCK_POWER(dip, &circ);
	ASSERT(cnt >= 0 && PM_KUC(dip) >= 0 || cnt < 0 && PM_KUC(dip) > 0);
	PMD(PMD_KIDSUP, ("%s: kidsupcnt for %s@%s(%s#%d) %d->%d\n", pmf,
	    PM_DEVICE(dip), PM_KUC(dip), (PM_KUC(dip) + cnt)))

	PM_KUC(dip) += cnt;

	ASSERT(PM_KUC(dip) >= 0);
	PM_UNLOCK_POWER(dip, circ);

	if (cnt < 0 && PM_KUC(dip) == 0)
		pm_rescan(dip);
}

#define	MAX_PPM_HANDLERS	4

kmutex_t ppm_lock;	/* in case we ever do multi-threaded startup */

struct	ppm_callbacks {
	int (*ppmc_func)(dev_info_t *);
	dev_info_t	*ppmc_dip;
} ppm_callbacks[MAX_PPM_HANDLERS + 1];


/*
 * This routine calls into all the registered ppms to notify them
 * that either all components of power-managed devices are at their
 * lowest levels or no longer all are at their lowest levels.
 */
static void
pm_ppm_notify_all_lowest(dev_info_t *dip, int mode)
{
	struct ppm_callbacks *ppmcp;
	power_req_t power_req;
	int result = 0;

	power_req.request_type = PMR_PPM_ALL_LOWEST;
	power_req.req.ppm_all_lowest_req.mode = mode;
	mutex_enter(&ppm_lock);
	for (ppmcp = ppm_callbacks; ppmcp->ppmc_func; ppmcp++)
		(void) pm_ctlops((dev_info_t *)ppmcp->ppmc_dip, dip,
		    DDI_CTLOPS_POWER, &power_req, &result);
	mutex_exit(&ppm_lock);
	if (mode == PM_ALL_LOWEST) {
		if (autoS3_enabled) {
			PMD(PMD_SX, ("pm_ppm_notify_all_lowest triggering "
			    "autos3\n"))
			mutex_enter(&srn_clone_lock);
			if (srn_signal) {
				srn_inuse++;
				PMD(PMD_SX, ("(*srn_signal)(AUTOSX, 3)\n"))
				(*srn_signal)(SRN_TYPE_AUTOSX, 3);
				srn_inuse--;
			} else {
				PMD(PMD_SX, ("srn_signal NULL\n"))
			}
			mutex_exit(&srn_clone_lock);
		} else {
			PMD(PMD_SX, ("pm_ppm_notify_all_lowest autos3 "
			    "disabled\n"));
		}
	}
}

static void
pm_set_pm_info(dev_info_t *dip, void *value)
{
	DEVI(dip)->devi_pm_info = value;
}

pm_rsvp_t *pm_blocked_list;

/*
 * Look up an entry in the blocked list by dip and component
 */
static pm_rsvp_t *
pm_rsvp_lookup(dev_info_t *dip, int comp)
{
	pm_rsvp_t *p;
	ASSERT(MUTEX_HELD(&pm_rsvp_lock));
	for (p = pm_blocked_list; p; p = p->pr_next)
		if (p->pr_dip == dip && p->pr_comp == comp) {
			return (p);
		}
	return (NULL);
}

/*
 * Called when a device which is direct power managed (or the parent or
 * dependent of such a device) changes power, or when a pm clone is closed
 * that was direct power managing a device.  This call results in pm_blocked()
 * (below) returning.
 */
void
pm_proceed(dev_info_t *dip, int cmd, int comp, int newlevel)
{
	PMD_FUNC(pmf, "proceed")
	pm_rsvp_t *found = NULL;
	pm_rsvp_t *p;

	mutex_enter(&pm_rsvp_lock);
	switch (cmd) {
	/*
	 * we're giving up control, let any pending op continue
	 */
	case PMP_RELEASE:
		for (p = pm_blocked_list; p; p = p->pr_next) {
			if (dip == p->pr_dip) {
				p->pr_retval = PMP_RELEASE;
				PMD(PMD_DPM, ("%s: RELEASE %s@%s(%s#%d)\n",
				    pmf, PM_DEVICE(dip)))
				cv_signal(&p->pr_cv);
			}
		}
		break;

	/*
	 * process has done PM_SET_CURRENT_POWER; let a matching request
	 * succeed and a non-matching request for the same device fail
	 */
	case PMP_SETPOWER:
		found = pm_rsvp_lookup(dip, comp);
		if (!found)	/* if driver not waiting */
			break;
		/*
		 * This cannot be pm_lower_power, since that can only happen
		 * during detach or probe
		 */
		if (found->pr_newlevel <= newlevel) {
			found->pr_retval = PMP_SUCCEED;
			PMD(PMD_DPM, ("%s: SUCCEED %s@%s(%s#%d)\n", pmf,
			    PM_DEVICE(dip)))
		} else {
			found->pr_retval = PMP_FAIL;
			PMD(PMD_DPM, ("%s: FAIL %s@%s(%s#%d)\n", pmf,
			    PM_DEVICE(dip)))
		}
		cv_signal(&found->pr_cv);
		break;

	default:
		panic("pm_proceed unknown cmd %d", cmd);
	}
	mutex_exit(&pm_rsvp_lock);
}

/*
 * This routine dispatches new work to the dependency thread. Caller must
 * be prepared to block for memory if necessary.
 */
void
pm_dispatch_to_dep_thread(int cmd, char *keeper, char *kept, int wait,
    int *res, int cached_pwr)
{
	pm_dep_wk_t	*new_work;

	new_work = kmem_zalloc(sizeof (pm_dep_wk_t), KM_SLEEP);
	new_work->pdw_type = cmd;
	new_work->pdw_wait = wait;
	new_work->pdw_done = 0;
	new_work->pdw_ret = 0;
	new_work->pdw_pwr = cached_pwr;
	cv_init(&new_work->pdw_cv, NULL, CV_DEFAULT, NULL);
	if (keeper != NULL) {
		new_work->pdw_keeper = kmem_zalloc(strlen(keeper) + 1,
		    KM_SLEEP);
		(void) strcpy(new_work->pdw_keeper, keeper);
	}
	if (kept != NULL) {
		new_work->pdw_kept = kmem_zalloc(strlen(kept) + 1, KM_SLEEP);
		(void) strcpy(new_work->pdw_kept, kept);
	}
	mutex_enter(&pm_dep_thread_lock);
	if (pm_dep_thread_workq == NULL) {
		pm_dep_thread_workq = new_work;
		pm_dep_thread_tail = new_work;
		new_work->pdw_next = NULL;
	} else {
		pm_dep_thread_tail->pdw_next = new_work;
		pm_dep_thread_tail = new_work;
		new_work->pdw_next = NULL;
	}
	cv_signal(&pm_dep_thread_cv);
	/* If caller asked for it, wait till it is done. */
	if (wait)  {
		while (!new_work->pdw_done)
			cv_wait(&new_work->pdw_cv, &pm_dep_thread_lock);
		/*
		 * Pass return status, if any, back.
		 */
		if (res != NULL)
			*res = new_work->pdw_ret;
		/*
		 * If we asked to wait, it is our job to free the request
		 * structure.
		 */
		if (new_work->pdw_keeper)
			kmem_free(new_work->pdw_keeper,
			    strlen(new_work->pdw_keeper) + 1);
		if (new_work->pdw_kept)
			kmem_free(new_work->pdw_kept,
			    strlen(new_work->pdw_kept) + 1);
		kmem_free(new_work, sizeof (pm_dep_wk_t));
	}
	mutex_exit(&pm_dep_thread_lock);
}

/*
 * Release the pm resource for this device.
 */
void
pm_rem_info(dev_info_t *dip)
{
	PMD_FUNC(pmf, "rem_info")
	int		i, count = 0;
	pm_info_t	*info = PM_GET_PM_INFO(dip);
	dev_info_t	*pdip = ddi_get_parent(dip);
	char		*pathbuf;
	int		work_type = PM_DEP_WK_DETACH;

	ASSERT(info);

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	if (PM_ISDIRECT(dip)) {
		info->pmi_dev_pm_state &= ~PM_DIRECT;
		ASSERT(info->pmi_clone);
		info->pmi_clone = 0;
		pm_proceed(dip, PMP_RELEASE, -1, -1);
	}
	ASSERT(!PM_GET_PM_SCAN(dip));

	/*
	 * Now adjust parent's kidsupcnt.  BC nodes we check only comp 0,
	 * Others we check all components.  BC node that has already
	 * called pm_destroy_components() has zero component count.
	 * Parents that get notification are not adjusted because their
	 * kidsupcnt is always 0 (or 1 during configuration).
	 */
	PMD(PMD_KEEPS, ("%s: %s@%s(%s#%d) has %d components\n", pmf,
	    PM_DEVICE(dip), PM_NUMCMPTS(dip)))

	/* node is detached, so we can examine power without locking */
	if (PM_ISBC(dip)) {
		count = (PM_CURPOWER(dip, 0) != 0);
	} else {
		for (i = 0; i < PM_NUMCMPTS(dip); i++)
			count += (PM_CURPOWER(dip, i) != 0);
	}

	if (PM_NUMCMPTS(dip) && pdip && !PM_WANTS_NOTIFICATION(pdip))
		e_pm_hold_rele_power(pdip, -count);

	/* Schedule a request to clean up dependency records */
	pathbuf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);
	pm_dispatch_to_dep_thread(work_type, pathbuf, pathbuf,
	    PM_DEP_NOWAIT, NULL, (count > 0));
	kmem_free(pathbuf, MAXPATHLEN);

	/*
	 * Adjust the pm_comps_notlowest count since this device is
	 * not being power-managed anymore.
	 */
	for (i = 0; i < PM_NUMCMPTS(dip); i++) {
		pm_component_t *cp = PM_CP(dip, i);
		if (cp->pmc_cur_pwr != 0)
			PM_DECR_NOTLOWEST(dip)
	}
	/*
	 * Once we clear the info pointer, it looks like it is not power
	 * managed to everybody else.
	 */
	pm_set_pm_info(dip, NULL);
	kmem_free(info, sizeof (pm_info_t));
}

int
pm_get_norm_pwrs(dev_info_t *dip, int **valuep, size_t *length)
{
	int components = PM_NUMCMPTS(dip);
	int *bufp;
	size_t size;
	int i;

	if (components <= 0) {
		cmn_err(CE_NOTE, "!pm: %s@%s(%s#%d) has no components, "
		    "can't get normal power values\n", PM_DEVICE(dip));
		return (DDI_FAILURE);
	} else {
		size = components * sizeof (int);
		bufp = kmem_alloc(size, KM_SLEEP);
		for (i = 0; i < components; i++) {
			bufp[i] = pm_get_normal_power(dip, i);
		}
	}
	*length = size;
	*valuep = bufp;
	return (DDI_SUCCESS);
}

static int
pm_reset_timestamps(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	int components;
	int	i;

	if (!PM_GET_PM_INFO(dip))
		return (DDI_WALK_CONTINUE);
	components = PM_NUMCMPTS(dip);
	ASSERT(components > 0);
	PM_LOCK_BUSY(dip);
	for (i = 0; i < components; i++) {
		struct pm_component *cp;
		/*
		 * If the component was not marked as busy,
		 * reset its timestamp to now.
		 */
		cp = PM_CP(dip, i);
		if (cp->pmc_timestamp)
			cp->pmc_timestamp = gethrestime_sec();
	}
	PM_UNLOCK_BUSY(dip);
	return (DDI_WALK_CONTINUE);
}

/*
 * Convert a power level to an index into the levels array (or
 * just PM_LEVEL_UNKNOWN in that special case).
 */
static int
pm_level_to_index(dev_info_t *dip, pm_component_t *cp, int level)
{
	PMD_FUNC(pmf, "level_to_index")
	int i;
	int limit = cp->pmc_comp.pmc_numlevels;
	int *ip = cp->pmc_comp.pmc_lvals;

	if (level == PM_LEVEL_UNKNOWN)
		return (level);

	for (i = 0; i < limit; i++) {
		if (level == *ip++) {
			PMD(PMD_LEVEL, ("%s: %s@%s(%s#%d)[%d] to %x\n",
			    pmf, PM_DEVICE(dip),
			    (int)(cp - DEVI(dip)->devi_pm_components), level))
			return (i);
		}
	}
	panic("pm_level_to_index: level %d not found for device "
	    "%s@%s(%s#%d)", level, PM_DEVICE(dip));
	/*NOTREACHED*/
}

/*
 * Internal function to set current power level
 */
static void
e_pm_set_cur_pwr(dev_info_t *dip, pm_component_t *cp, int level)
{
	PMD_FUNC(pmf, "set_cur_pwr")
	int curpwr = (cp->pmc_flags & PM_PHC_WHILE_SET_POWER ?
	    cp->pmc_phc_pwr : cp->pmc_cur_pwr);

	/*
	 * Nothing to adjust if current & new levels are the same.
	 */
	if (curpwr != PM_LEVEL_UNKNOWN &&
	    level == cp->pmc_comp.pmc_lvals[curpwr])
		return;

	/*
	 * Keep the count for comps doing transition to/from lowest
	 * level.
	 */
	if (curpwr == 0) {
		PM_INCR_NOTLOWEST(dip);
	} else if (level == cp->pmc_comp.pmc_lvals[0]) {
		PM_DECR_NOTLOWEST(dip);
	}
	cp->pmc_phc_pwr = PM_LEVEL_UNKNOWN;
	cp->pmc_cur_pwr = pm_level_to_index(dip, cp, level);
}

static int pm_phc_impl(dev_info_t *, int, int, int);

/*
 * This is the default method of setting the power of a device if no ppm
 * driver has claimed it.
 */
int
pm_power(dev_info_t *dip, int comp, int level)
{
	PMD_FUNC(pmf, "power")
	struct dev_ops	*ops;
	int		(*fn)(dev_info_t *, int, int);
	struct pm_component *cp = PM_CP(dip, comp);
	int retval;
	pm_info_t *info = PM_GET_PM_INFO(dip);

	PMD(PMD_KIDSUP, ("%s: %s@%s(%s#%d), comp=%d, level=%d\n", pmf,
	    PM_DEVICE(dip), comp, level))
	if (!(ops = ddi_get_driver(dip))) {
		PMD(PMD_FAIL, ("%s: %s@%s(%s#%d) has no ops\n", pmf,
		    PM_DEVICE(dip)))
		return (DDI_FAILURE);
	}
	if ((ops->devo_rev < 2) || !(fn = ops->devo_power)) {
		PMD(PMD_FAIL, ("%s: %s%s\n", pmf,
		    (ops->devo_rev < 2 ? " wrong devo_rev" : ""),
		    (!fn ? " devo_power NULL" : "")))
		return (DDI_FAILURE);
	}
	cp->pmc_flags |= PM_POWER_OP;
	retval = (*fn)(dip, comp, level);
	cp->pmc_flags &= ~PM_POWER_OP;
	if (retval == DDI_SUCCESS) {
		e_pm_set_cur_pwr(dip, PM_CP(dip, comp), level);
		return (DDI_SUCCESS);
	}

	/*
	 * If pm_power_has_changed() detected a deadlock with pm_power() it
	 * updated only the power level of the component.  If our attempt to
	 * set the device new to a power level above has failed we sync the
	 * total power state via phc code now.
	 */
	if (cp->pmc_flags & PM_PHC_WHILE_SET_POWER) {
		int phc_lvl =
		    cp->pmc_comp.pmc_lvals[cp->pmc_cur_pwr];

		ASSERT(info);
		(void) pm_phc_impl(dip, comp, phc_lvl, 0);
		PMD(PMD_PHC, ("%s: phc %s@%s(%s#%d) comp=%d level=%d\n",
		    pmf, PM_DEVICE(dip), comp, phc_lvl))
	}

	PMD(PMD_FAIL, ("%s: can't set comp=%d (%s) of %s@%s(%s#%d) to "
	    "level=%d (%s)\n", pmf, comp, cp->pmc_comp.pmc_name, PM_DEVICE(dip),
	    level, power_val_to_string(cp, level)));
	return (DDI_FAILURE);
}

int
pm_unmanage(dev_info_t *dip)
{
	PMD_FUNC(pmf, "unmanage")
	power_req_t power_req;
	int result, retval = 0;

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	PMD(PMD_REMDEV | PMD_KIDSUP, ("%s: %s@%s(%s#%d)\n", pmf,
	    PM_DEVICE(dip)))
	power_req.request_type = PMR_PPM_UNMANAGE;
	power_req.req.ppm_config_req.who = dip;
	if (pm_ppm_claimed(dip))
		retval = pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER,
		    &power_req, &result);
#ifdef DEBUG
	else
		retval = pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER,
		    &power_req, &result);
#endif
	ASSERT(retval == DDI_SUCCESS);
	pm_rem_info(dip);
	return (retval);
}

int
pm_raise_power(dev_info_t *dip, int comp, int level)
{
	if (level < 0)
		return (DDI_FAILURE);
	if (!e_pm_valid_info(dip, NULL) || !e_pm_valid_comp(dip, comp, NULL) ||
	    !e_pm_valid_power(dip, comp, level))
		return (DDI_FAILURE);

	return (dev_is_needed(dip, comp, level, PM_LEVEL_UPONLY));
}

int
pm_lower_power(dev_info_t *dip, int comp, int level)
{
	PMD_FUNC(pmf, "pm_lower_power")

	if (!e_pm_valid_info(dip, NULL) || !e_pm_valid_comp(dip, comp, NULL) ||
	    !e_pm_valid_power(dip, comp, level)) {
		PMD(PMD_FAIL, ("%s: validation checks failed for %s@%s(%s#%d) "
		    "comp=%d level=%d\n", pmf, PM_DEVICE(dip), comp, level))
		return (DDI_FAILURE);
	}

	if (!DEVI_IS_DETACHING(dip)) {
		PMD(PMD_FAIL, ("%s: %s@%s(%s#%d) not detaching\n",
		    pmf, PM_DEVICE(dip)))
		return (DDI_FAILURE);
	}

	/*
	 * If we don't care about saving power, or we're treating this node
	 * specially, then this is a no-op
	 */
	if (!PM_SCANABLE(dip) || pm_noinvol(dip)) {
		PMD(PMD_FAIL, ("%s: %s@%s(%s#%d) %s%s%s%s\n",
		    pmf, PM_DEVICE(dip),
		    !autopm_enabled ? "!autopm_enabled " : "",
		    !PM_POLLING_CPUPM ? "!cpupm_polling " : "",
		    PM_CPUPM_DISABLED ? "cpupm_disabled " : "",
		    pm_noinvol(dip) ? "pm_noinvol()" : ""))
		return (DDI_SUCCESS);
	}

	if (dev_is_needed(dip, comp, level, PM_LEVEL_DOWNONLY) != DDI_SUCCESS) {
		PMD(PMD_FAIL, ("%s: %s@%s(%s#%d) dev_is_needed failed\n", pmf,
		    PM_DEVICE(dip)))
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Find the entries struct for a given dip in the blocked list, return it locked
 */
static psce_t *
pm_psc_dip_to_direct(dev_info_t *dip, pscc_t **psccp)
{
	pscc_t *p;
	psce_t *psce;

	rw_enter(&pm_pscc_direct_rwlock, RW_READER);
	for (p = pm_pscc_direct; p; p = p->pscc_next) {
		if (p->pscc_dip == dip) {
			*psccp = p;
			psce = p->pscc_entries;
			mutex_enter(&psce->psce_lock);
			ASSERT(psce);
			rw_exit(&pm_pscc_direct_rwlock);
			return (psce);
		}
	}
	rw_exit(&pm_pscc_direct_rwlock);
	panic("sunpm: no entry for dip %p in direct list", (void *)dip);
	/*NOTREACHED*/
}

/*
 * Write an entry indicating a power level change (to be passed to a process
 * later) in the given psce.
 * If we were called in the path that brings up the console fb in the
 * case of entering the prom, we don't want to sleep.  If the alloc fails, then
 * we create a record that has a size of -1, a physaddr of NULL, and that
 * has the overflow flag set.
 */
static int
psc_entry(ushort_t event, psce_t *psce, dev_info_t *dip, int comp, int new,
    int old, int which, pm_canblock_t canblock)
{
	char	buf[MAXNAMELEN];
	pm_state_change_t *p;
	size_t	size;
	caddr_t physpath = NULL;
	int	overrun = 0;

	ASSERT(MUTEX_HELD(&psce->psce_lock));
	(void) ddi_pathname(dip, buf);
	size = strlen(buf) + 1;
	p = psce->psce_in;
	if (canblock == PM_CANBLOCK_BYPASS) {
		physpath = kmem_alloc(size, KM_NOSLEEP);
		if (physpath == NULL) {
			/*
			 * mark current entry as overrun
			 */
			p->flags |= PSC_EVENT_LOST;
			size = (size_t)-1;
		}
	} else
		physpath = kmem_alloc(size, KM_SLEEP);
	if (p->size) {	/* overflow; mark the next entry */
		if (p->size != (size_t)-1)
			kmem_free(p->physpath, p->size);
		ASSERT(psce->psce_out == p);
		if (p == psce->psce_last) {
			psce->psce_first->flags |= PSC_EVENT_LOST;
			psce->psce_out = psce->psce_first;
		} else {
			(p + 1)->flags |= PSC_EVENT_LOST;
			psce->psce_out = (p + 1);
		}
		overrun++;
	} else if (physpath == NULL) {	/* alloc failed, mark this entry */
		p->flags |= PSC_EVENT_LOST;
		p->size = 0;
		p->physpath = NULL;
	}
	if (which == PSC_INTEREST) {
		mutex_enter(&pm_compcnt_lock);
		if (pm_comps_notlowest == 0)
			p->flags |= PSC_ALL_LOWEST;
		else
			p->flags &= ~PSC_ALL_LOWEST;
		mutex_exit(&pm_compcnt_lock);
	}
	p->event = event;
	p->timestamp = gethrestime_sec();
	p->component = comp;
	p->old_level = old;
	p->new_level = new;
	p->physpath = physpath;
	p->size = size;
	if (physpath != NULL)
		(void) strcpy(p->physpath, buf);
	if (p == psce->psce_last)
		psce->psce_in = psce->psce_first;
	else
		psce->psce_in = ++p;
	mutex_exit(&psce->psce_lock);
	return (overrun);
}

/*
 * Find the next entry on the interest list.  We keep a pointer to the item we
 * last returned in the user's cooke.  Returns a locked entries struct.
 */
static psce_t *
psc_interest(void **cookie, pscc_t **psccp)
{
	pscc_t *pscc;
	pscc_t **cookiep = (pscc_t **)cookie;

	if (*cookiep == NULL)
		pscc = pm_pscc_interest;
	else
		pscc = (*cookiep)->pscc_next;
	if (pscc) {
		*cookiep = pscc;
		*psccp = pscc;
		mutex_enter(&pscc->pscc_entries->psce_lock);
		return (pscc->pscc_entries);
	} else {
		return (NULL);
	}
}

/*
 * Create an entry for a process to pick up indicating a power level change.
 */
static void
pm_enqueue_notify(ushort_t cmd, dev_info_t *dip, int comp,
    int newlevel, int oldlevel, pm_canblock_t canblock)
{
	PMD_FUNC(pmf, "enqueue_notify")
	pscc_t	*pscc;
	psce_t	*psce;
	void		*cookie = NULL;
	int	overrun;

	ASSERT(MUTEX_HELD(&pm_rsvp_lock));
	switch (cmd) {
	case PSC_PENDING_CHANGE:	/* only for controlling process */
		PMD(PMD_DPM, ("%s: PENDING %s@%s(%s#%d), comp %d, %d -> %d\n",
		    pmf, PM_DEVICE(dip), comp, oldlevel, newlevel))
		psce = pm_psc_dip_to_direct(dip, &pscc);
		ASSERT(psce);
		PMD(PMD_IOCTL, ("%s: PENDING: %s@%s(%s#%d) pm_poll_cnt[%d] "
		    "%d\n", pmf, PM_DEVICE(dip), pscc->pscc_clone,
		    pm_poll_cnt[pscc->pscc_clone]))
		overrun = psc_entry(cmd, psce, dip, comp, newlevel, oldlevel,
		    PSC_DIRECT, canblock);
		PMD(PMD_DPM, ("%s: sig %d\n", pmf, pscc->pscc_clone))
		mutex_enter(&pm_clone_lock);
		if (!overrun)
			pm_poll_cnt[pscc->pscc_clone]++;
		cv_signal(&pm_clones_cv[pscc->pscc_clone]);
		pollwakeup(&pm_pollhead, (POLLRDNORM | POLLIN));
		mutex_exit(&pm_clone_lock);
		break;
	case PSC_HAS_CHANGED:
		PMD(PMD_DPM, ("%s: HAS %s@%s(%s#%d), comp %d, %d -> %d\n",
		    pmf, PM_DEVICE(dip), comp, oldlevel, newlevel))
		if (PM_ISDIRECT(dip) && canblock != PM_CANBLOCK_BYPASS) {
			psce = pm_psc_dip_to_direct(dip, &pscc);
			PMD(PMD_IOCTL, ("%s: HAS: %s@%s(%s#%d) pm_poll_cnt[%d] "
			    "%d\n", pmf, PM_DEVICE(dip), pscc->pscc_clone,
			    pm_poll_cnt[pscc->pscc_clone]))
			overrun = psc_entry(cmd, psce, dip, comp, newlevel,
			    oldlevel, PSC_DIRECT, canblock);
			PMD(PMD_DPM, ("%s: sig %d\n", pmf, pscc->pscc_clone))
			mutex_enter(&pm_clone_lock);
			if (!overrun)
				pm_poll_cnt[pscc->pscc_clone]++;
			cv_signal(&pm_clones_cv[pscc->pscc_clone]);
			pollwakeup(&pm_pollhead, (POLLRDNORM | POLLIN));
			mutex_exit(&pm_clone_lock);
		}
		mutex_enter(&pm_clone_lock);
		rw_enter(&pm_pscc_interest_rwlock, RW_READER);
		while ((psce = psc_interest(&cookie, &pscc)) != NULL) {
			(void) psc_entry(cmd, psce, dip, comp, newlevel,
			    oldlevel, PSC_INTEREST, canblock);
			cv_signal(&pm_clones_cv[pscc->pscc_clone]);
		}
		rw_exit(&pm_pscc_interest_rwlock);
		mutex_exit(&pm_clone_lock);
		break;
#ifdef DEBUG
	default:
		ASSERT(0);
#endif
	}
}

static void
pm_enqueue_notify_others(pm_ppm_devlist_t **listp, pm_canblock_t canblock)
{
	if (listp) {
		pm_ppm_devlist_t *p, *next = NULL;

		for (p = *listp; p; p = next) {
			next = p->ppd_next;
			pm_enqueue_notify(PSC_HAS_CHANGED, p->ppd_who,
			    p->ppd_cmpt, p->ppd_new_level, p->ppd_old_level,
			    canblock);
			kmem_free(p, sizeof (pm_ppm_devlist_t));
		}
		*listp = NULL;
	}
}

/*
 * Try to get the power locks of the parent node and target (child)
 * node.  Return true if successful (with both locks held) or false
 * (with no locks held).
 */
static int
pm_try_parent_child_locks(dev_info_t *pdip,
    dev_info_t *dip, int *pcircp, int *circp)
{
	if (ndi_devi_tryenter(pdip, pcircp))
		if (PM_TRY_LOCK_POWER(dip, circp)) {
			return (1);
		} else {
			ndi_devi_exit(pdip, *pcircp);
		}
	return (0);
}

/*
 * Determine if the power lock owner is blocked by current thread.
 * returns :
 * 	1 - If the thread owning the effective power lock (the first lock on
 *          which a thread blocks when it does PM_LOCK_POWER) is blocked by
 *          a mutex held by the current thread.
 *
 *	0 - otherwise
 *
 * Note : This function is called by pm_power_has_changed to determine whether
 * it is executing in parallel with pm_set_power.
 */
static int
pm_blocked_by_us(dev_info_t *dip)
{
	power_req_t power_req;
	kthread_t *owner;
	int result;
	kmutex_t *mp;
	dev_info_t *ppm = (dev_info_t *)DEVI(dip)->devi_pm_ppm;

	power_req.request_type = PMR_PPM_POWER_LOCK_OWNER;
	power_req.req.ppm_power_lock_owner_req.who = dip;
	if (pm_ctlops(ppm, dip, DDI_CTLOPS_POWER, &power_req, &result) !=
	    DDI_SUCCESS) {
		/*
		 * It is assumed that if the device is claimed by ppm, ppm
		 * will always implement this request type and it'll always
		 * return success. We panic here, if it fails.
		 */
		panic("pm: Can't determine power lock owner of %s@%s(%s#%d)\n",
		    PM_DEVICE(dip));
		/*NOTREACHED*/
	}

	if ((owner = power_req.req.ppm_power_lock_owner_req.owner) != NULL &&
	    owner->t_state == TS_SLEEP &&
	    owner->t_sobj_ops &&
	    SOBJ_TYPE(owner->t_sobj_ops) == SOBJ_MUTEX &&
	    (mp = (kmutex_t *)owner->t_wchan) &&
	    mutex_owner(mp) == curthread)
		return (1);

	return (0);
}

/*
 * Notify parent which wants to hear about a child's power changes.
 */
static void
pm_notify_parent(dev_info_t *dip,
    dev_info_t *pdip, int comp, int old_level, int level)
{
	pm_bp_has_changed_t bphc;
	pm_sp_misc_t pspm;
	char *pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	int result = DDI_SUCCESS;

	bphc.bphc_dip = dip;
	bphc.bphc_path = ddi_pathname(dip, pathbuf);
	bphc.bphc_comp = comp;
	bphc.bphc_olevel = old_level;
	bphc.bphc_nlevel = level;
	pspm.pspm_canblock = PM_CANBLOCK_BLOCK;
	pspm.pspm_scan = 0;
	bphc.bphc_private = &pspm;
	(void) (*PM_BUS_POWER_FUNC(pdip))(pdip, NULL,
	    BUS_POWER_HAS_CHANGED, (void *)&bphc, (void *)&result);
	kmem_free(pathbuf, MAXPATHLEN);
}

/*
 * Check if we need to resume a BC device, and make the attach call as required.
 */
static int
pm_check_and_resume(dev_info_t *dip, int comp, int old_level, int level)
{
	int ret = DDI_SUCCESS;

	if (PM_ISBC(dip) && comp == 0 && old_level == 0 && level != 0) {
		ASSERT(DEVI(dip)->devi_pm_flags & PMC_SUSPENDED);
		/* ppm is not interested in DDI_PM_RESUME */
		if ((ret = devi_attach(dip, DDI_PM_RESUME)) != DDI_SUCCESS)
			/* XXX Should we mark it resumed, */
			/* even though it failed? */
			cmn_err(CE_WARN, "!pm: Can't resume %s@%s",
			    PM_NAME(dip), PM_ADDR(dip));
		DEVI(dip)->devi_pm_flags &= ~PMC_SUSPENDED;
	}

	return (ret);
}

/*
 * Tests outside the lock to see if we should bother to enqueue an entry
 * for any watching process.  If yes, then caller will take the lock and
 * do the full protocol
 */
static int
pm_watchers()
{
	if (pm_processes_stopped)
		return (0);
	return (pm_pscc_direct || pm_pscc_interest);
}

static int pm_phc_impl(dev_info_t *, int, int, int);

/*
 * A driver is reporting that the power of one of its device's components
 * has changed.  Update the power state accordingly.
 */
int
pm_power_has_changed(dev_info_t *dip, int comp, int level)
{
	PMD_FUNC(pmf, "pm_power_has_changed")
	int ret;
	dev_info_t *pdip = ddi_get_parent(dip);
	struct pm_component *cp;
	int blocked, circ, pcirc, old_level;

	if (level < 0) {
		PMD(PMD_FAIL, ("%s: %s@%s(%s#%d): bad level=%d\n", pmf,
		    PM_DEVICE(dip), level))
		return (DDI_FAILURE);
	}

	PMD(PMD_KIDSUP | PMD_DEP, ("%s: %s@%s(%s#%d), comp=%d, level=%d\n", pmf,
	    PM_DEVICE(dip), comp, level))

	if (!e_pm_valid_info(dip, NULL) || !e_pm_valid_comp(dip, comp, &cp) ||
	    !e_pm_valid_power(dip, comp, level))
		return (DDI_FAILURE);

	/*
	 * A driver thread calling pm_power_has_changed and another thread
	 * calling pm_set_power can deadlock.  The problem is not resolvable
	 * by changing lock order, so we use pm_blocked_by_us() to detect
	 * this specific deadlock.  If we can't get the lock immediately
	 * and we are deadlocked, just update the component's level, do
	 * notifications, and return.  We intend to update the total power
	 * state later (if the other thread fails to set power to the
	 * desired level).  If we were called because of a power change on a
	 * component that isn't involved in a set_power op, update all state
	 * immediately.
	 */
	cp = PM_CP(dip, comp);
	while (!pm_try_parent_child_locks(pdip, dip, &pcirc, &circ)) {
		if (((blocked = pm_blocked_by_us(dip)) != 0) &&
		    (cp->pmc_flags & PM_POWER_OP)) {
			if (pm_watchers()) {
				mutex_enter(&pm_rsvp_lock);
				pm_enqueue_notify(PSC_HAS_CHANGED, dip, comp,
				    level, cur_power(cp), PM_CANBLOCK_BLOCK);
				mutex_exit(&pm_rsvp_lock);
			}
			if (pdip && PM_WANTS_NOTIFICATION(pdip))
				pm_notify_parent(dip,
				    pdip, comp, cur_power(cp), level);
			(void) pm_check_and_resume(dip,
			    comp, cur_power(cp), level);

			/*
			 * Stash the old power index, update curpwr, and flag
			 * that the total power state needs to be synched.
			 */
			cp->pmc_flags |= PM_PHC_WHILE_SET_POWER;
			/*
			 * Several pm_power_has_changed calls could arrive
			 * while the set power path remains blocked.  Keep the
			 * oldest old power and the newest new power of any
			 * sequence of phc calls which arrive during deadlock.
			 */
			if (cp->pmc_phc_pwr == PM_LEVEL_UNKNOWN)
				cp->pmc_phc_pwr = cp->pmc_cur_pwr;
			cp->pmc_cur_pwr =
			    pm_level_to_index(dip, cp, level);
			PMD(PMD_PHC, ("%s: deadlock for %s@%s(%s#%d), comp=%d, "
			    "level=%d\n", pmf, PM_DEVICE(dip), comp, level))
			return (DDI_SUCCESS);
		} else
			if (blocked) {	/* blocked, but different cmpt? */
				if (!ndi_devi_tryenter(pdip, &pcirc)) {
					cmn_err(CE_NOTE,
					    "!pm: parent kuc not updated due "
					    "to possible deadlock.\n");
					return (pm_phc_impl(dip,
					    comp, level, 1));
				}
				old_level = cur_power(cp);
				if (pdip && !PM_WANTS_NOTIFICATION(pdip) &&
				    (!PM_ISBC(dip) || comp == 0) &&
				    POWERING_ON(old_level, level))
					pm_hold_power(pdip);
				ret = pm_phc_impl(dip, comp, level, 1);
				if (pdip && !PM_WANTS_NOTIFICATION(pdip)) {
					if ((!PM_ISBC(dip) ||
					    comp == 0) && level == 0 &&
					    old_level != PM_LEVEL_UNKNOWN)
						pm_rele_power(pdip);
				}
				ndi_devi_exit(pdip, pcirc);
				/* child lock not held: deadlock */
				return (ret);
			}
		delay(1);
		PMD(PMD_PHC, ("%s: try lock again\n", pmf))
	}

	/* non-deadlock case */
	old_level = cur_power(cp);
	if (pdip && !PM_WANTS_NOTIFICATION(pdip) &&
	    (!PM_ISBC(dip) || comp == 0) && POWERING_ON(old_level, level))
		pm_hold_power(pdip);
	ret = pm_phc_impl(dip, comp, level, 1);
	if (pdip && !PM_WANTS_NOTIFICATION(pdip)) {
		if ((!PM_ISBC(dip) || comp == 0) && level == 0 &&
		    old_level != PM_LEVEL_UNKNOWN)
			pm_rele_power(pdip);
	}
	PM_UNLOCK_POWER(dip, circ);
	ndi_devi_exit(pdip, pcirc);
	return (ret);
}

/*
 * Account for power changes to a component of the the console frame buffer.
 * If lowering power from full (or "unkown", which is treatd as full)
 * we will increment the "components off" count of the fb device.
 * Subsequent lowering of the same component doesn't affect the count.  If
 * raising a component back to full power, we will decrement the count.
 *
 * Return: the increment value for pm_cfb_comps_off (-1, 0, or 1)
 */
static int
calc_cfb_comps_incr(dev_info_t *dip, int cmpt, int old, int new)
{
	struct pm_component *cp = PM_CP(dip, cmpt);
	int on = (old == PM_LEVEL_UNKNOWN || old == cp->pmc_norm_pwr);
	int want_normal = (new == cp->pmc_norm_pwr);
	int incr = 0;

	if (on && !want_normal)
		incr = 1;
	else if (!on && want_normal)
		incr = -1;
	return (incr);
}

/*
 * Adjust the count of console frame buffer components < full power.
 */
static void
update_comps_off(int incr, dev_info_t *dip)
{
		mutex_enter(&pm_cfb_lock);
		pm_cfb_comps_off += incr;
		ASSERT(pm_cfb_comps_off <= PM_NUMCMPTS(dip));
		mutex_exit(&pm_cfb_lock);
}

/*
 * Update the power state in the framework (via the ppm).  The 'notify'
 * argument tells whether to notify watchers.  Power lock is already held.
 */
static int
pm_phc_impl(dev_info_t *dip, int comp, int level, int notify)
{
	PMD_FUNC(pmf, "phc_impl")
	power_req_t power_req;
	int i, dodeps = 0;
	dev_info_t *pdip = ddi_get_parent(dip);
	int result;
	int old_level;
	struct pm_component *cp;
	int incr = 0;
	dev_info_t *ppm = (dev_info_t *)DEVI(dip)->devi_pm_ppm;
	int work_type = 0;
	char *pathbuf;

	/* Must use "official" power level for this test. */
	cp = PM_CP(dip, comp);
	old_level = (cp->pmc_flags & PM_PHC_WHILE_SET_POWER ?
	    cp->pmc_phc_pwr : cp->pmc_cur_pwr);
	if (old_level != PM_LEVEL_UNKNOWN)
		old_level = cp->pmc_comp.pmc_lvals[old_level];

	if (level == old_level) {
		PMD(PMD_SET, ("%s: %s@%s(%s#%d), comp=%d is already at "
		    "level=%d\n", pmf, PM_DEVICE(dip), comp, level))
		return (DDI_SUCCESS);
	}

	/*
	 * Tell ppm about this.
	 */
	power_req.request_type = PMR_PPM_POWER_CHANGE_NOTIFY;
	power_req.req.ppm_notify_level_req.who = dip;
	power_req.req.ppm_notify_level_req.cmpt = comp;
	power_req.req.ppm_notify_level_req.new_level = level;
	power_req.req.ppm_notify_level_req.old_level = old_level;
	if (pm_ctlops(ppm, dip, DDI_CTLOPS_POWER, &power_req,
	    &result) == DDI_FAILURE) {
		PMD(PMD_FAIL, ("%s: pm_ctlops %s@%s(%s#%d) to %d failed\n",
		    pmf, PM_DEVICE(dip), level))
		return (DDI_FAILURE);
	}

	if (PM_IS_CFB(dip)) {
		incr = calc_cfb_comps_incr(dip, comp, old_level, level);

		if (incr) {
			update_comps_off(incr, dip);
			PMD(PMD_CFB, ("%s: %s@%s(%s#%d) comp=%d %d->%d "
			    "cfb_comps_off->%d\n", pmf, PM_DEVICE(dip),
			    comp, old_level, level, pm_cfb_comps_off))
		}
	}
	e_pm_set_cur_pwr(dip, PM_CP(dip, comp), level);
	result = DDI_SUCCESS;

	if (notify) {
		if (pdip && PM_WANTS_NOTIFICATION(pdip))
			pm_notify_parent(dip, pdip, comp, old_level, level);
		(void) pm_check_and_resume(dip, comp, old_level, level);
	}

	/*
	 * Decrement the dependency kidsup count if we turn a device
	 * off.
	 */
	if (POWERING_OFF(old_level, level)) {
		dodeps = 1;
		for (i = 0; i < PM_NUMCMPTS(dip); i++) {
			cp = PM_CP(dip, i);
			if (cur_power(cp)) {
				dodeps = 0;
				break;
			}
		}
		if (dodeps)
			work_type = PM_DEP_WK_POWER_OFF;
	}

	/*
	 * Increment if we turn it on. Check to see
	 * if other comps are already on, if so,
	 * dont increment.
	 */
	if (POWERING_ON(old_level, level)) {
		dodeps = 1;
		for (i = 0; i < PM_NUMCMPTS(dip); i++) {
			cp = PM_CP(dip, i);
			if (comp == i)
				continue;
			/* -1 also treated as 0 in this case */
			if (cur_power(cp) > 0) {
				dodeps = 0;
				break;
			}
		}
		if (dodeps)
			work_type = PM_DEP_WK_POWER_ON;
	}

	if (dodeps) {
		pathbuf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(dip, pathbuf);
		pm_dispatch_to_dep_thread(work_type, pathbuf, NULL,
		    PM_DEP_NOWAIT, NULL, 0);
		kmem_free(pathbuf, MAXPATHLEN);
	}

	if (notify && (level != old_level) && pm_watchers()) {
		mutex_enter(&pm_rsvp_lock);
		pm_enqueue_notify(PSC_HAS_CHANGED, dip, comp, level, old_level,
		    PM_CANBLOCK_BLOCK);
		mutex_exit(&pm_rsvp_lock);
	}

	PMD(PMD_RESCAN, ("%s: %s@%s(%s#%d): pm_rescan\n", pmf, PM_DEVICE(dip)))
	pm_rescan(dip);
	return (DDI_SUCCESS);
}

/*
 * This function is called at startup time to notify pm of the existence
 * of any platform power managers for this platform.  As a result of
 * this registration, each function provided will be called each time
 * a device node is attached, until one returns true, and it must claim the
 * device node (by returning non-zero) if it wants to be involved in the
 * node's power management.  If it does claim the node, then it will
 * subsequently be notified of attach and detach events.
 *
 */

int
pm_register_ppm(int (*func)(dev_info_t *), dev_info_t *dip)
{
	PMD_FUNC(pmf, "register_ppm")
	struct ppm_callbacks *ppmcp;
	pm_component_t *cp;
	int i, pwr, result, circ;
	power_req_t power_req;
	struct ppm_notify_level_req *p = &power_req.req.ppm_notify_level_req;
	void pm_ppm_claim(dev_info_t *);

	mutex_enter(&ppm_lock);
	ppmcp = ppm_callbacks;
	for (i = 0; i < MAX_PPM_HANDLERS; i++, ppmcp++) {
		if (ppmcp->ppmc_func == NULL) {
			ppmcp->ppmc_func = func;
			ppmcp->ppmc_dip = dip;
			break;
		}
	}
	mutex_exit(&ppm_lock);

	if (i >= MAX_PPM_HANDLERS)
		return (DDI_FAILURE);
	while ((dip = ddi_get_parent(dip)) != NULL) {
		if (dip != ddi_root_node() && PM_GET_PM_INFO(dip) == NULL)
			continue;
		pm_ppm_claim(dip);
		/* don't bother with the not power-manageable nodes */
		if (pm_ppm_claimed(dip) && PM_GET_PM_INFO(dip)) {
			/*
			 * Tell ppm about this.
			 */
			power_req.request_type = PMR_PPM_POWER_CHANGE_NOTIFY;
			p->old_level = PM_LEVEL_UNKNOWN;
			p->who = dip;
			PM_LOCK_POWER(dip, &circ);
			for (i = 0; i < PM_NUMCMPTS(dip); i++) {
				cp = PM_CP(dip, i);
				pwr = cp->pmc_cur_pwr;
				if (pwr != PM_LEVEL_UNKNOWN) {
					p->cmpt = i;
					p->new_level = cur_power(cp);
					p->old_level = PM_LEVEL_UNKNOWN;
					if (pm_ctlops(PPM(dip), dip,
					    DDI_CTLOPS_POWER, &power_req,
					    &result) == DDI_FAILURE) {
						PMD(PMD_FAIL, ("%s: pc "
						    "%s@%s(%s#%d) to %d "
						    "fails\n", pmf,
						    PM_DEVICE(dip), pwr))
					}
				}
			}
			PM_UNLOCK_POWER(dip, circ);
		}
	}
	return (DDI_SUCCESS);
}

/*
 * Call the ppm's that have registered and adjust the devinfo struct as
 * appropriate.  First one to claim it gets it.  The sets of devices claimed
 * by each ppm are assumed to be disjoint.
 */
void
pm_ppm_claim(dev_info_t *dip)
{
	struct ppm_callbacks *ppmcp;

	if (PPM(dip)) {
		return;
	}
	mutex_enter(&ppm_lock);
	for (ppmcp = ppm_callbacks; ppmcp->ppmc_func; ppmcp++) {
		if ((*ppmcp->ppmc_func)(dip)) {
			DEVI(dip)->devi_pm_ppm =
			    (struct dev_info *)ppmcp->ppmc_dip;
			mutex_exit(&ppm_lock);
			return;
		}
	}
	mutex_exit(&ppm_lock);
}

/*
 * Node is being detached so stop autopm until we see if it succeeds, in which
 * case pm_stop will be called.  For backwards compatible devices we bring the
 * device up to full power on the assumption the detach will succeed.
 */
void
pm_detaching(dev_info_t *dip)
{
	PMD_FUNC(pmf, "detaching")
	pm_info_t *info = PM_GET_PM_INFO(dip);
	int iscons;

	PMD(PMD_REMDEV, ("%s: %s@%s(%s#%d), %d comps\n", pmf, PM_DEVICE(dip),
	    PM_NUMCMPTS(dip)))
	if (info == NULL)
		return;
	ASSERT(DEVI_IS_DETACHING(dip));
	PM_LOCK_DIP(dip);
	info->pmi_dev_pm_state |= PM_DETACHING;
	PM_UNLOCK_DIP(dip);
	if (!PM_ISBC(dip))
		pm_scan_stop(dip);

	/*
	 * console and old-style devices get brought up when detaching.
	 */
	iscons = PM_IS_CFB(dip);
	if (iscons || PM_ISBC(dip)) {
		(void) pm_all_to_normal(dip, PM_CANBLOCK_BYPASS);
		if (iscons) {
			mutex_enter(&pm_cfb_lock);
			while (cfb_inuse) {
				mutex_exit(&pm_cfb_lock);
				PMD(PMD_CFB, ("%s: delay; cfb_inuse\n", pmf))
				delay(1);
				mutex_enter(&pm_cfb_lock);
			}
			ASSERT(cfb_dip_detaching == NULL);
			ASSERT(cfb_dip);
			cfb_dip_detaching = cfb_dip;	/* case detach fails */
			cfb_dip = NULL;
			mutex_exit(&pm_cfb_lock);
		}
	}
}

/*
 * Node failed to detach.  If it used to be autopm'd, make it so again.
 */
void
pm_detach_failed(dev_info_t *dip)
{
	PMD_FUNC(pmf, "detach_failed")
	pm_info_t *info = PM_GET_PM_INFO(dip);
	int pm_all_at_normal(dev_info_t *);

	if (info == NULL)
		return;
	ASSERT(DEVI_IS_DETACHING(dip));
	if (info->pmi_dev_pm_state & PM_DETACHING) {
		info->pmi_dev_pm_state &= ~PM_DETACHING;
		if (info->pmi_dev_pm_state & PM_ALLNORM_DEFERRED) {
			/* Make sure the operation is still needed */
			if (!pm_all_at_normal(dip)) {
				if (pm_all_to_normal(dip,
				    PM_CANBLOCK_FAIL) != DDI_SUCCESS) {
					PMD(PMD_ERROR, ("%s: could not bring "
					    "%s@%s(%s#%d) to normal\n", pmf,
					    PM_DEVICE(dip)))
				}
			}
			info->pmi_dev_pm_state &= ~PM_ALLNORM_DEFERRED;
		}
	}
	if (!PM_ISBC(dip)) {
		mutex_enter(&pm_scan_lock);
		if (PM_SCANABLE(dip))
			pm_scan_init(dip);
		mutex_exit(&pm_scan_lock);
		pm_rescan(dip);
	}
}

/* generic Backwards Compatible component */
static char *bc_names[] = {"off", "on"};

static pm_comp_t bc_comp = {"unknown", 2, NULL, NULL, &bc_names[0]};

static void
e_pm_default_levels(dev_info_t *dip, pm_component_t *cp, int norm)
{
	pm_comp_t *pmc;
	pmc = &cp->pmc_comp;
	pmc->pmc_numlevels = 2;
	pmc->pmc_lvals[0] = 0;
	pmc->pmc_lvals[1] = norm;
	e_pm_set_cur_pwr(dip, cp, norm);
}

static void
e_pm_default_components(dev_info_t *dip, int cmpts)
{
	int i;
	pm_component_t *p = DEVI(dip)->devi_pm_components;

	p = DEVI(dip)->devi_pm_components;
	for (i = 0; i < cmpts; i++, p++) {
		p->pmc_comp = bc_comp;	/* struct assignment */
		p->pmc_comp.pmc_lvals = kmem_zalloc(2 * sizeof (int),
		    KM_SLEEP);
		p->pmc_comp.pmc_thresh = kmem_alloc(2 * sizeof (int),
		    KM_SLEEP);
		p->pmc_comp.pmc_numlevels = 2;
		p->pmc_comp.pmc_thresh[0] = INT_MAX;
		p->pmc_comp.pmc_thresh[1] = INT_MAX;
	}
}

/*
 * Called from functions that require components to exist already to allow
 * for their creation by parsing the pm-components property.
 * Device will not be power managed as a result of this call
 * No locking needed because we're single threaded by the ndi_devi_enter
 * done while attaching, and the device isn't visible until after it has
 * attached
 */
int
pm_premanage(dev_info_t *dip, int style)
{
	PMD_FUNC(pmf, "premanage")
	pm_comp_t	*pcp, *compp;
	int		cmpts, i, norm, error;
	pm_component_t *p = DEVI(dip)->devi_pm_components;
	pm_comp_t *pm_autoconfig(dev_info_t *, int *);

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	/*
	 * If this dip has already been processed, don't mess with it
	 */
	if (DEVI(dip)->devi_pm_flags & PMC_COMPONENTS_DONE)
		return (DDI_SUCCESS);
	if (DEVI(dip)->devi_pm_flags & PMC_COMPONENTS_FAILED) {
		return (DDI_FAILURE);
	}
	/*
	 * Look up pm-components property and create components accordingly
	 * If that fails, fall back to backwards compatibility
	 */
	if ((compp = pm_autoconfig(dip, &error)) == NULL) {
		/*
		 * If error is set, the property existed but was not well formed
		 */
		if (error || (style == PM_STYLE_NEW)) {
			DEVI(dip)->devi_pm_flags |= PMC_COMPONENTS_FAILED;
			return (DDI_FAILURE);
		}
		/*
		 * If they don't have the pm-components property, then we
		 * want the old "no pm until PM_SET_DEVICE_THRESHOLDS ioctl"
		 * behavior driver must have called pm_create_components, and
		 * we need to flesh out dummy components
		 */
		if ((cmpts = PM_NUMCMPTS(dip)) == 0) {
			/*
			 * Not really failure, but we don't want the
			 * caller to treat it as success
			 */
			return (DDI_FAILURE);
		}
		DEVI(dip)->devi_pm_flags |= PMC_BC;
		e_pm_default_components(dip, cmpts);
		for (i = 0; i < cmpts; i++) {
			/*
			 * if normal power not set yet, we don't really know
			 * what *ANY* of the power values are.  If normal
			 * power is set, then we assume for this backwards
			 * compatible case that the values are 0, normal power.
			 */
			norm = pm_get_normal_power(dip, i);
			if (norm == (uint_t)-1) {
				PMD(PMD_ERROR, ("%s: %s@%s(%s#%d)[%d]\n", pmf,
				    PM_DEVICE(dip), i))
				return (DDI_FAILURE);
			}
			/*
			 * Components of BC devices start at their normal power,
			 * so count them to be not at their lowest power.
			 */
			PM_INCR_NOTLOWEST(dip);
			e_pm_default_levels(dip, PM_CP(dip, i), norm);
		}
	} else {
		/*
		 * e_pm_create_components was called from pm_autoconfig(), it
		 * creates components with no descriptions (or known levels)
		 */
		cmpts = PM_NUMCMPTS(dip);
		ASSERT(cmpts != 0);
		pcp = compp;
		p = DEVI(dip)->devi_pm_components;
		for (i = 0; i < cmpts; i++, p++) {
			p->pmc_comp = *pcp++;   /* struct assignment */
			ASSERT(PM_CP(dip, i)->pmc_cur_pwr == 0);
			e_pm_set_cur_pwr(dip, PM_CP(dip, i), PM_LEVEL_UNKNOWN);
		}
		if (DEVI(dip)->devi_pm_flags & PMC_CPU_THRESH)
			pm_set_device_threshold(dip, pm_cpu_idle_threshold,
			    PMC_CPU_THRESH);
		else
			pm_set_device_threshold(dip, pm_system_idle_threshold,
			    PMC_DEF_THRESH);
		kmem_free(compp, cmpts * sizeof (pm_comp_t));
	}
	return (DDI_SUCCESS);
}

/*
 * Called from during or after the device's attach to let us know it is ready
 * to play autopm.   Look up the pm model and manage the device accordingly.
 * Returns system call errno value.
 * If DDI_ATTACH and DDI_DETACH were in same namespace, this would be
 * a little cleaner
 *
 * Called with dip lock held, return with dip lock unheld.
 */

int
e_pm_manage(dev_info_t *dip, int style)
{
	PMD_FUNC(pmf, "e_manage")
	pm_info_t	*info;
	dev_info_t	*pdip = ddi_get_parent(dip);
	int	pm_thresh_specd(dev_info_t *);
	int	count;
	char	*pathbuf;

	if (pm_premanage(dip, style) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	PMD(PMD_KIDSUP, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	ASSERT(PM_GET_PM_INFO(dip) == NULL);
	info = kmem_zalloc(sizeof (pm_info_t), KM_SLEEP);

	/*
	 * Now set up parent's kidsupcnt.  BC nodes are assumed to start
	 * out at their normal power, so they are "up", others start out
	 * unknown, which is effectively "up".  Parent which want notification
	 * get kidsupcnt of 0 always.
	 */
	count = (PM_ISBC(dip)) ? 1 : PM_NUMCMPTS(dip);
	if (count && pdip && !PM_WANTS_NOTIFICATION(pdip))
		e_pm_hold_rele_power(pdip, count);

	pm_set_pm_info(dip, info);
	/*
	 * Apply any recorded thresholds
	 */
	(void) pm_thresh_specd(dip);

	/*
	 * Do dependency processing.
	 */
	pathbuf = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);
	pm_dispatch_to_dep_thread(PM_DEP_WK_ATTACH, pathbuf, pathbuf,
	    PM_DEP_NOWAIT, NULL, 0);
	kmem_free(pathbuf, MAXPATHLEN);

	if (!PM_ISBC(dip)) {
		mutex_enter(&pm_scan_lock);
		if (PM_SCANABLE(dip)) {
			pm_scan_init(dip);
			mutex_exit(&pm_scan_lock);
			pm_rescan(dip);
		} else {
			mutex_exit(&pm_scan_lock);
		}
	}
	return (0);
}

/*
 * This is the obsolete exported interface for a driver to find out its
 * "normal" (max) power.
 * We only get components destroyed while no power management is
 * going on (and the device is detached), so we don't need a mutex here
 */
int
pm_get_normal_power(dev_info_t *dip, int comp)
{

	if (comp >= 0 && comp < PM_NUMCMPTS(dip)) {
		return (PM_CP(dip, comp)->pmc_norm_pwr);
	}
	return (DDI_FAILURE);
}

/*
 * Fetches the current power level.  Return DDI_SUCCESS or DDI_FAILURE.
 */
int
pm_get_current_power(dev_info_t *dip, int comp, int *levelp)
{
	if (comp >= 0 && comp < PM_NUMCMPTS(dip)) {
		*levelp = PM_CURPOWER(dip, comp);
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

/*
 * Returns current threshold of indicated component
 */
static int
cur_threshold(dev_info_t *dip, int comp)
{
	pm_component_t *cp = PM_CP(dip, comp);
	int pwr;

	if (PM_ISBC(dip)) {
		/*
		 * backwards compatible nodes only have one threshold
		 */
		return (cp->pmc_comp.pmc_thresh[1]);
	}
	pwr = cp->pmc_cur_pwr;
	if (pwr == PM_LEVEL_UNKNOWN) {
		int thresh;
		if (DEVI(dip)->devi_pm_flags & PMC_NEXDEF_THRESH)
			thresh = pm_default_nexus_threshold;
		else if (DEVI(dip)->devi_pm_flags & PMC_CPU_THRESH)
			thresh = pm_cpu_idle_threshold;
		else
			thresh = pm_system_idle_threshold;
		return (thresh);
	}
	ASSERT(cp->pmc_comp.pmc_thresh);
	return (cp->pmc_comp.pmc_thresh[pwr]);
}

/*
 * Compute next lower component power level given power index.
 */
static int
pm_next_lower_power(pm_component_t *cp, int pwrndx)
{
	int nxt_pwr;

	if (pwrndx == PM_LEVEL_UNKNOWN) {
		nxt_pwr = cp->pmc_comp.pmc_lvals[0];
	} else {
		pwrndx--;
		ASSERT(pwrndx >= 0);
		nxt_pwr = cp->pmc_comp.pmc_lvals[pwrndx];
	}
	return (nxt_pwr);
}

/*
 * Update the maxpower (normal) power of a component. Note that the
 * component's power level is only changed if it's current power level
 * is higher than the new max power.
 */
int
pm_update_maxpower(dev_info_t *dip, int comp, int level)
{
	PMD_FUNC(pmf, "update_maxpower")
	int old;
	int result;

	if (!e_pm_valid_info(dip, NULL) || !e_pm_valid_comp(dip, comp, NULL) ||
	    !e_pm_valid_power(dip, comp, level)) {
		PMD(PMD_FAIL, ("%s: validation checks failed for %s@%s(%s#%d) "
		    "comp=%d level=%d\n", pmf, PM_DEVICE(dip), comp, level))
		return (DDI_FAILURE);
	}
	old = e_pm_get_max_power(dip, comp);
	e_pm_set_max_power(dip, comp, level);

	if (pm_set_power(dip, comp, level, PM_LEVEL_DOWNONLY,
	    PM_CANBLOCK_BLOCK, 0, &result) != DDI_SUCCESS) {
		e_pm_set_max_power(dip, comp, old);
		PMD(PMD_FAIL, ("%s: %s@%s(%s#%d) pm_set_power failed\n", pmf,
		    PM_DEVICE(dip)))
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Bring all components of device to normal power
 */
int
pm_all_to_normal(dev_info_t *dip, pm_canblock_t canblock)
{
	PMD_FUNC(pmf, "all_to_normal")
	int		*normal;
	int		i, ncomps, result;
	size_t		size;
	int		changefailed = 0;

	PMD(PMD_ALLNORM, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	ASSERT(PM_GET_PM_INFO(dip));
	if (pm_get_norm_pwrs(dip, &normal, &size) != DDI_SUCCESS) {
		PMD(PMD_ALLNORM, ("%s: can't get norm pwrs for "
		    "%s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
		return (DDI_FAILURE);
	}
	ncomps = PM_NUMCMPTS(dip);
	for (i = 0; i < ncomps; i++) {
		if (pm_set_power(dip, i, normal[i],
		    PM_LEVEL_UPONLY, canblock, 0, &result) != DDI_SUCCESS) {
			changefailed++;
			PMD(PMD_ALLNORM | PMD_FAIL, ("%s: failed to set "
			    "%s@%s(%s#%d)[%d] to %d, errno %d\n", pmf,
			    PM_DEVICE(dip), i, normal[i], result))
		}
	}
	kmem_free(normal, size);
	if (changefailed) {
		PMD(PMD_FAIL, ("%s: failed to set %d comps %s@%s(%s#%d) "
		    "to full power\n", pmf, changefailed, PM_DEVICE(dip)))
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Returns true if all components of device are at normal power
 */
int
pm_all_at_normal(dev_info_t *dip)
{
	PMD_FUNC(pmf, "all_at_normal")
	int		*normal;
	int		i;
	size_t		size;

	PMD(PMD_ALLNORM, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	if (pm_get_norm_pwrs(dip, &normal, &size) != DDI_SUCCESS) {
		PMD(PMD_ALLNORM, ("%s: can't get normal power\n", pmf))
		return (DDI_FAILURE);
	}
	for (i = 0; i < PM_NUMCMPTS(dip); i++) {
		int current = PM_CURPOWER(dip, i);
		if (normal[i] > current) {
			PMD(PMD_ALLNORM, ("%s: %s@%s(%s#%d) comp=%d, "
			    "norm=%d, cur=%d\n", pmf, PM_DEVICE(dip), i,
			    normal[i], current))
			break;
		}
	}
	kmem_free(normal, size);
	if (i != PM_NUMCMPTS(dip)) {
		return (0);
	}
	return (1);
}

static void bring_pmdep_up(dev_info_t *, int);

static void
bring_wekeeps_up(char *keeper)
{
	PMD_FUNC(pmf, "bring_wekeeps_up")
	int i;
	pm_pdr_t *dp;
	pm_info_t *wku_info;
	char *kept_path;
	dev_info_t *kept;

	if (panicstr) {
		return;
	}
	/*
	 * We process the request even if the keeper detaches because
	 * detach processing expects this to increment kidsupcnt of kept.
	 */
	PMD(PMD_BRING, ("%s: keeper= %s\n", pmf, keeper))
	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (strcmp(dp->pdr_keeper, keeper) != 0)
			continue;
		for (i = 0; i < dp->pdr_kept_count; i++) {
			kept_path = dp->pdr_kept_paths[i];
			if (kept_path == NULL)
				continue;
			ASSERT(kept_path[0] != '\0');
			if ((kept = pm_name_to_dip(kept_path, 1)) == NULL)
				continue;
			wku_info = PM_GET_PM_INFO(kept);
			if (wku_info == NULL) {
				if (kept)
					ddi_release_devi(kept);
				continue;
			}
			/*
			 * Don't mess with it if it is being detached, it isn't
			 * safe to call its power entry point
			 */
			if (wku_info->pmi_dev_pm_state & PM_DETACHING) {
				if (kept)
					ddi_release_devi(kept);
				continue;
			}
			bring_pmdep_up(kept, 1);
			ddi_release_devi(kept);
		}
	}
}

/*
 * Bring up the 'kept' device passed as argument
 */
static void
bring_pmdep_up(dev_info_t *kept_dip, int hold)
{
	PMD_FUNC(pmf, "bring_pmdep_up")
	int is_all_at_normal = 0;

	/*
	 * If the kept device has been unmanaged, do nothing.
	 */
	if (!PM_GET_PM_INFO(kept_dip))
		return;

	/* Just ignore DIRECT PM device till they are released. */
	if (!pm_processes_stopped && PM_ISDIRECT(kept_dip) &&
	    !(is_all_at_normal = pm_all_at_normal(kept_dip))) {
		PMD(PMD_BRING, ("%s: can't bring up PM_DIRECT %s@%s(%s#%d) "
		    "controlling process did something else\n", pmf,
		    PM_DEVICE(kept_dip)))
		DEVI(kept_dip)->devi_pm_flags |= PMC_SKIP_BRINGUP;
		return;
	}
	/* if we got here the keeper had a transition from OFF->ON */
	if (hold)
		pm_hold_power(kept_dip);

	if (!is_all_at_normal)
		(void) pm_all_to_normal(kept_dip, PM_CANBLOCK_FAIL);
}

/*
 * A bunch of stuff that belongs only to the next routine (or two)
 */

static const char namestr[] = "NAME=";
static const int nameln = sizeof (namestr) - 1;
static const char pmcompstr[] = "pm-components";

struct pm_comp_pkg {
	pm_comp_t		*comp;
	struct pm_comp_pkg	*next;
};

#define	isdigit(ch)	((ch) >= '0' && (ch) <= '9')

#define	isxdigit(ch)	(isdigit(ch) || ((ch) >= 'a' && (ch) <= 'f') || \
			((ch) >= 'A' && (ch) <= 'F'))

/*
 * Rather than duplicate this code ...
 * (this code excerpted from the function that follows it)
 */
#define	FINISH_COMP { \
	ASSERT(compp); \
	compp->pmc_lnames_sz = size; \
	tp = compp->pmc_lname_buf = kmem_alloc(size, KM_SLEEP); \
	compp->pmc_numlevels = level; \
	compp->pmc_lnames = kmem_alloc(level * sizeof (char *), KM_SLEEP); \
	compp->pmc_lvals = kmem_alloc(level * sizeof (int), KM_SLEEP); \
	compp->pmc_thresh = kmem_alloc(level * sizeof (int), KM_SLEEP); \
	/* copy string out of prop array into buffer */ \
	for (j = 0; j < level; j++) { \
		compp->pmc_thresh[j] = INT_MAX;		/* only [0] sticks */ \
		compp->pmc_lvals[j] = lvals[j]; \
		(void) strcpy(tp, lnames[j]); \
		compp->pmc_lnames[j] = tp; \
		tp += lszs[j]; \
	} \
	ASSERT(tp > compp->pmc_lname_buf && tp <= \
	    compp->pmc_lname_buf + compp->pmc_lnames_sz); \
	}

/*
 * Create (empty) component data structures.
 */
static void
e_pm_create_components(dev_info_t *dip, int num_components)
{
	struct pm_component *compp, *ocompp;
	int i, size = 0;

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	ASSERT(!DEVI(dip)->devi_pm_components);
	ASSERT(!(DEVI(dip)->devi_pm_flags & PMC_COMPONENTS_DONE));
	size = sizeof (struct pm_component) * num_components;

	compp = kmem_zalloc(size, KM_SLEEP);
	ocompp = compp;
	DEVI(dip)->devi_pm_comp_size = size;
	DEVI(dip)->devi_pm_num_components = num_components;
	PM_LOCK_BUSY(dip);
	for (i = 0; i < num_components;  i++) {
		compp->pmc_timestamp = gethrestime_sec();
		compp->pmc_norm_pwr = (uint_t)-1;
		compp++;
	}
	PM_UNLOCK_BUSY(dip);
	DEVI(dip)->devi_pm_components = ocompp;
	DEVI(dip)->devi_pm_flags |= PMC_COMPONENTS_DONE;
}

/*
 * Parse hex or decimal value from char string
 */
static char *
pm_parsenum(char *cp, int *valp)
{
	int ch, offset;
	char numbuf[256];
	char *np = numbuf;
	int value = 0;

	ch = *cp++;
	if (isdigit(ch)) {
		if (ch == '0') {
			if ((ch = *cp++) == 'x' || ch == 'X') {
				ch = *cp++;
				while (isxdigit(ch)) {
					*np++ = (char)ch;
					ch = *cp++;
				}
				*np = 0;
				cp--;
				goto hexval;
			} else {
				goto digit;
			}
		} else {
digit:
			while (isdigit(ch)) {
				*np++ = (char)ch;
				ch = *cp++;
			}
			*np = 0;
			cp--;
			goto decval;
		}
	} else
		return (NULL);

hexval:
	for (np = numbuf; *np; np++) {
		if (*np >= 'a' && *np <= 'f')
			offset = 'a' - 10;
		else if (*np >= 'A' && *np <= 'F')
			offset = 'A' - 10;
		else if (*np >= '0' && *np <= '9')
			offset = '0';
		value *= 16;
		value += *np - offset;
	}
	*valp = value;
	return (cp);

decval:
	offset = '0';
	for (np = numbuf; *np; np++) {
		value *= 10;
		value += *np - offset;
	}
	*valp = value;
	return (cp);
}

/*
 * Set max (previously documented as "normal") power.
 */
static void
e_pm_set_max_power(dev_info_t *dip, int component_number, int level)
{
	PM_CP(dip, component_number)->pmc_norm_pwr = level;
}

/*
 * Get max (previously documented as "normal") power.
 */
static int
e_pm_get_max_power(dev_info_t *dip, int component_number)
{
	return (PM_CP(dip, component_number)->pmc_norm_pwr);
}

/*
 * Internal routine for destroying components
 * It is called even when there might not be any, so it must be forgiving.
 */
static void
e_pm_destroy_components(dev_info_t *dip)
{
	int i;
	struct pm_component *cp;

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	if (PM_NUMCMPTS(dip) == 0)
		return;
	cp = DEVI(dip)->devi_pm_components;
	ASSERT(cp);
	for (i = 0; i < PM_NUMCMPTS(dip); i++, cp++) {
		int nlevels = cp->pmc_comp.pmc_numlevels;
		kmem_free(cp->pmc_comp.pmc_lvals, nlevels * sizeof (int));
		kmem_free(cp->pmc_comp.pmc_thresh, nlevels * sizeof (int));
		/*
		 * For BC nodes, the rest is static in bc_comp, so skip it
		 */
		if (PM_ISBC(dip))
			continue;
		kmem_free(cp->pmc_comp.pmc_name, cp->pmc_comp.pmc_name_sz);
		kmem_free(cp->pmc_comp.pmc_lnames, nlevels * sizeof (char *));
		kmem_free(cp->pmc_comp.pmc_lname_buf,
		    cp->pmc_comp.pmc_lnames_sz);
	}
	kmem_free(DEVI(dip)->devi_pm_components, DEVI(dip)->devi_pm_comp_size);
	DEVI(dip)->devi_pm_components = NULL;
	DEVI(dip)->devi_pm_num_components = 0;
	DEVI(dip)->devi_pm_flags &=
	    ~(PMC_COMPONENTS_DONE | PMC_COMPONENTS_FAILED);
}

/*
 * Read the pm-components property (if there is one) and use it to set up
 * components.  Returns a pointer to an array of component structures if
 * pm-components found and successfully parsed, else returns NULL.
 * Sets error return *errp to true to indicate a failure (as opposed to no
 * property being present).
 */
pm_comp_t *
pm_autoconfig(dev_info_t *dip, int *errp)
{
	PMD_FUNC(pmf, "autoconfig")
	uint_t nelems;
	char **pp;
	pm_comp_t *compp = NULL;
	int i, j, level, components = 0;
	size_t size = 0;
	struct pm_comp_pkg *p, *ptail;
	struct pm_comp_pkg *phead = NULL;
	int *lvals = NULL;
	int *lszs = NULL;
	int *np = NULL;
	int npi = 0;
	char **lnames = NULL;
	char *cp, *tp;
	pm_comp_t *ret = NULL;

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	*errp = 0;	/* assume success */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    (char *)pmcompstr, &pp, &nelems) != DDI_PROP_SUCCESS) {
		return (NULL);
	}

	if (nelems < 3) {	/* need at least one name and two levels */
		goto errout;
	}

	/*
	 * pm_create_components is no longer allowed
	 */
	if (PM_NUMCMPTS(dip) != 0) {
		PMD(PMD_ERROR, ("%s: %s@%s(%s#%d) has %d comps\n",
		    pmf, PM_DEVICE(dip), PM_NUMCMPTS(dip)))
		goto errout;
	}

	lvals = kmem_alloc(nelems * sizeof (int), KM_SLEEP);
	lszs = kmem_alloc(nelems * sizeof (int), KM_SLEEP);
	lnames = kmem_alloc(nelems * sizeof (char *), KM_SLEEP);
	np = kmem_alloc(nelems * sizeof (int), KM_SLEEP);

	level = 0;
	phead = NULL;
	for (i = 0; i < nelems; i++) {
		cp = pp[i];
		if (!isdigit(*cp)) {	/*  must be name */
			if (strncmp(cp, namestr, nameln) != 0) {
				goto errout;
			}
			if (i != 0) {
				if (level == 0) {	/* no level spec'd */
					PMD(PMD_ERROR, ("%s: no level spec'd\n",
					    pmf))
					goto errout;
				}
				np[npi++] = lvals[level - 1];
				/* finish up previous component levels */
				FINISH_COMP;
			}
			cp += nameln;
			if (!*cp) {
				PMD(PMD_ERROR, ("%s: nsa\n", pmf))
				goto errout;
			}
			p = kmem_zalloc(sizeof (*phead), KM_SLEEP);
			if (phead == NULL) {
				phead = ptail = p;
			} else {
				ptail->next = p;
				ptail = p;
			}
			compp = p->comp = kmem_zalloc(sizeof (pm_comp_t),
			    KM_SLEEP);
			compp->pmc_name_sz = strlen(cp) + 1;
			compp->pmc_name = kmem_zalloc(compp->pmc_name_sz,
			    KM_SLEEP);
			(void) strncpy(compp->pmc_name, cp, compp->pmc_name_sz);
			components++;
			level = 0;
		} else {	/* better be power level <num>=<name> */
#ifdef DEBUG
			tp = cp;
#endif
			if (i == 0 ||
			    (cp = pm_parsenum(cp, &lvals[level])) == NULL) {
				PMD(PMD_ERROR, ("%s: parsenum(%s)\n", pmf, tp))
				goto errout;
			}
#ifdef DEBUG
			tp = cp;
#endif
			if (*cp++ != '=' || !*cp) {
				PMD(PMD_ERROR, ("%s: ex =, got %s\n", pmf, tp))
				goto errout;
			}

			lszs[level] = strlen(cp) + 1;
			size += lszs[level];
			lnames[level] = cp;	/* points into prop string */
			level++;
		}
	}
	np[npi++] = lvals[level - 1];
	if (level == 0) {	/* ended with a name */
		PMD(PMD_ERROR, ("%s: ewn\n", pmf))
		goto errout;
	}
	FINISH_COMP;


	/*
	 * Now we have a list of components--we have to return instead an
	 * array of them, but we can just copy the top level and leave
	 * the rest as is
	 */
	(void) e_pm_create_components(dip, components);
	for (i = 0; i < components; i++)
		e_pm_set_max_power(dip, i, np[i]);

	ret = kmem_zalloc(components * sizeof (pm_comp_t), KM_SLEEP);
	for (i = 0, p = phead; i < components; i++) {
		ASSERT(p);
		/*
		 * Now sanity-check values:  levels must be monotonically
		 * increasing
		 */
		if (p->comp->pmc_numlevels < 2) {
			PMD(PMD_ERROR, ("%s: comp %s of %s@%s(%s#%d) only %d "
			    "levels\n", pmf,
			    p->comp->pmc_name, PM_DEVICE(dip),
			    p->comp->pmc_numlevels))
			goto errout;
		}
		for (j = 0; j < p->comp->pmc_numlevels; j++) {
			if ((p->comp->pmc_lvals[j] < 0) || ((j > 0) &&
			    (p->comp->pmc_lvals[j] <=
			    p->comp->pmc_lvals[j - 1]))) {
				PMD(PMD_ERROR, ("%s: comp %s of %s@%s(%s#%d) "
				    "not mono. incr, %d follows %d\n", pmf,
				    p->comp->pmc_name, PM_DEVICE(dip),
				    p->comp->pmc_lvals[j],
				    p->comp->pmc_lvals[j - 1]))
				goto errout;
			}
		}
		ret[i] = *p->comp;	/* struct assignment */
		for (j = 0; j < i; j++) {
			/*
			 * Test for unique component names
			 */
			if (strcmp(ret[j].pmc_name, ret[i].pmc_name) == 0) {
				PMD(PMD_ERROR, ("%s: %s of %s@%s(%s#%d) not "
				    "unique\n", pmf, ret[j].pmc_name,
				    PM_DEVICE(dip)))
				goto errout;
			}
		}
		ptail = p;
		p = p->next;
		phead = p;	/* errout depends on phead making sense */
		kmem_free(ptail->comp, sizeof (*ptail->comp));
		kmem_free(ptail, sizeof (*ptail));
	}
out:
	ddi_prop_free(pp);
	if (lvals)
		kmem_free(lvals, nelems * sizeof (int));
	if (lszs)
		kmem_free(lszs, nelems * sizeof (int));
	if (lnames)
		kmem_free(lnames, nelems * sizeof (char *));
	if (np)
		kmem_free(np, nelems * sizeof (int));
	return (ret);

errout:
	e_pm_destroy_components(dip);
	*errp = 1;	/* signal failure */
	cmn_err(CE_CONT, "!pm: %s property ", pmcompstr);
	for (i = 0; i < nelems - 1; i++)
		cmn_err(CE_CONT, "!'%s', ", pp[i]);
	if (nelems != 0)
		cmn_err(CE_CONT, "!'%s'", pp[nelems - 1]);
	cmn_err(CE_CONT, "! for %s@%s(%s#%d) is ill-formed.\n", PM_DEVICE(dip));
	for (p = phead; p; ) {
		pm_comp_t *pp;
		int n;

		ptail = p;
		/*
		 * Free component data structures
		 */
		pp = p->comp;
		n = pp->pmc_numlevels;
		if (pp->pmc_name_sz) {
			kmem_free(pp->pmc_name, pp->pmc_name_sz);
		}
		if (pp->pmc_lnames_sz) {
			kmem_free(pp->pmc_lname_buf, pp->pmc_lnames_sz);
		}
		if (pp->pmc_lnames) {
			kmem_free(pp->pmc_lnames, n * (sizeof (char *)));
		}
		if (pp->pmc_thresh) {
			kmem_free(pp->pmc_thresh, n * (sizeof (int)));
		}
		if (pp->pmc_lvals) {
			kmem_free(pp->pmc_lvals, n * (sizeof (int)));
		}
		p = ptail->next;
		kmem_free(ptail, sizeof (*ptail));
	}
	if (ret != NULL)
		kmem_free(ret, components * sizeof (pm_comp_t));
	ret = NULL;
	goto out;
}

/*
 * Set threshold values for a devices components by dividing the target
 * threshold (base) by the number of transitions and assign each transition
 * that threshold.  This will get the entire device down in the target time if
 * all components are idle and even if there are dependencies among components.
 *
 * Devices may well get powered all the way down before the target time, but
 * at least the EPA will be happy.
 */
void
pm_set_device_threshold(dev_info_t *dip, int base, int flag)
{
	PMD_FUNC(pmf, "set_device_threshold")
	int target_threshold = (base * 95) / 100;
	int level, comp;		/* loop counters */
	int transitions = 0;
	int ncomp = PM_NUMCMPTS(dip);
	int thresh;
	int remainder;
	pm_comp_t *pmc;
	int i, circ;

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	PM_LOCK_DIP(dip);
	/*
	 * First we handle the easy one.  If we're setting the default
	 * threshold for a node with children, then we set it to the
	 * default nexus threshold (currently 0) and mark it as default
	 * nexus threshold instead
	 */
	if (PM_IS_NEXUS(dip)) {
		if (flag == PMC_DEF_THRESH) {
			PMD(PMD_THRESH, ("%s: [%s@%s(%s#%d) NEXDEF]\n", pmf,
			    PM_DEVICE(dip)))
			thresh = pm_default_nexus_threshold;
			for (comp = 0; comp < ncomp; comp++) {
				pmc = &PM_CP(dip, comp)->pmc_comp;
				for (level = 1; level < pmc->pmc_numlevels;
				    level++) {
					pmc->pmc_thresh[level] = thresh;
				}
			}
			DEVI(dip)->devi_pm_dev_thresh =
			    pm_default_nexus_threshold;
			/*
			 * If the nexus node is being reconfigured back to
			 * the default threshold, adjust the notlowest count.
			 */
			if (DEVI(dip)->devi_pm_flags &
			    (PMC_DEV_THRESH|PMC_COMP_THRESH)) {
				PM_LOCK_POWER(dip, &circ);
				for (i = 0; i < PM_NUMCMPTS(dip); i++) {
					if (PM_CURPOWER(dip, i) == 0)
						continue;
					mutex_enter(&pm_compcnt_lock);
					ASSERT(pm_comps_notlowest);
					pm_comps_notlowest--;
					PMD(PMD_LEVEL, ("%s: %s@%s(%s#%d) decr "
					    "notlowest to %d\n", pmf,
					    PM_DEVICE(dip), pm_comps_notlowest))
					if (pm_comps_notlowest == 0)
						pm_ppm_notify_all_lowest(dip,
						    PM_ALL_LOWEST);
					mutex_exit(&pm_compcnt_lock);
				}
				PM_UNLOCK_POWER(dip, circ);
			}
			DEVI(dip)->devi_pm_flags &= PMC_THRESH_NONE;
			DEVI(dip)->devi_pm_flags |= PMC_NEXDEF_THRESH;
			PM_UNLOCK_DIP(dip);
			return;
		} else if (DEVI(dip)->devi_pm_flags & PMC_NEXDEF_THRESH) {
			/*
			 * If the nexus node is being configured for a
			 * non-default threshold, include that node in
			 * the notlowest accounting.
			 */
			PM_LOCK_POWER(dip, &circ);
			for (i = 0; i < PM_NUMCMPTS(dip); i++) {
				if (PM_CURPOWER(dip, i) == 0)
					continue;
				mutex_enter(&pm_compcnt_lock);
				if (pm_comps_notlowest == 0)
					pm_ppm_notify_all_lowest(dip,
					    PM_NOT_ALL_LOWEST);
				pm_comps_notlowest++;
				PMD(PMD_LEVEL, ("%s: %s@%s(%s#%d) incr "
				    "notlowest to %d\n", pmf,
				    PM_DEVICE(dip), pm_comps_notlowest))
				mutex_exit(&pm_compcnt_lock);
			}
			PM_UNLOCK_POWER(dip, circ);
		}
	}
	/*
	 * Compute the total number of transitions for all components
	 * of the device.  Distribute the threshold evenly over them
	 */
	for (comp = 0; comp < ncomp; comp++) {
		pmc = &PM_CP(dip, comp)->pmc_comp;
		ASSERT(pmc->pmc_numlevels > 1);
		transitions += pmc->pmc_numlevels - 1;
	}
	ASSERT(transitions);
	thresh = target_threshold / transitions;

	for (comp = 0; comp < ncomp; comp++) {
		pmc = &PM_CP(dip, comp)->pmc_comp;
		for (level = 1; level < pmc->pmc_numlevels; level++) {
			pmc->pmc_thresh[level] = thresh;
		}
	}

#ifdef DEBUG
	for (comp = 0; comp < ncomp; comp++) {
		pmc = &PM_CP(dip, comp)->pmc_comp;
		for (level = 1; level < pmc->pmc_numlevels; level++) {
			PMD(PMD_THRESH, ("%s: thresh before %s@%s(%s#%d) "
			    "comp=%d, level=%d, %d\n", pmf, PM_DEVICE(dip),
			    comp, level, pmc->pmc_thresh[level]))
		}
	}
#endif
	/*
	 * Distribute any remainder till they are all gone
	 */
	remainder = target_threshold - thresh * transitions;
	level = 1;
#ifdef DEBUG
	PMD(PMD_THRESH, ("%s: remainder=%d target_threshold=%d thresh=%d "
	    "trans=%d\n", pmf, remainder, target_threshold, thresh,
	    transitions))
#endif
	while (remainder > 0) {
		comp = 0;
		while (remainder && (comp < ncomp)) {
			pmc = &PM_CP(dip, comp)->pmc_comp;
			if (level < pmc->pmc_numlevels) {
				pmc->pmc_thresh[level] += 1;
				remainder--;
			}
			comp++;
		}
		level++;
	}
#ifdef DEBUG
	for (comp = 0; comp < ncomp; comp++) {
		pmc = &PM_CP(dip, comp)->pmc_comp;
		for (level = 1; level < pmc->pmc_numlevels; level++) {
			PMD(PMD_THRESH, ("%s: thresh after %s@%s(%s#%d) "
			    "comp=%d level=%d, %d\n", pmf, PM_DEVICE(dip),
			    comp, level, pmc->pmc_thresh[level]))
		}
	}
#endif
	ASSERT(PM_IAM_LOCKING_DIP(dip));
	DEVI(dip)->devi_pm_dev_thresh = base;
	DEVI(dip)->devi_pm_flags &= PMC_THRESH_NONE;
	DEVI(dip)->devi_pm_flags |= flag;
	PM_UNLOCK_DIP(dip);
}

/*
 * Called when there is no old-style platform power management driver
 */
static int
ddi_no_platform_power(power_req_t *req)
{
	_NOTE(ARGUNUSED(req))
	return (DDI_FAILURE);
}

/*
 * This function calls the entry point supplied by the platform-specific
 * pm driver to bring the device component 'pm_cmpt' to power level 'pm_level'.
 * The use of global for getting the  function name from platform-specific
 * pm driver is not ideal, but it is simple and efficient.
 * The previous property lookup was being done in the idle loop on swift
 * systems without pmc chips and hurt deskbench performance as well as
 * violating scheduler locking rules
 */
int	(*pm_platform_power)(power_req_t *) = ddi_no_platform_power;

/*
 * Old obsolete interface for a device to request a power change (but only
 * an increase in power)
 */
int
ddi_dev_is_needed(dev_info_t *dip, int cmpt, int level)
{
	return (pm_raise_power(dip, cmpt, level));
}

/*
 * The old obsolete interface to platform power management.  Only used by
 * Gypsy platform and APM on X86.
 */
int
ddi_power(dev_info_t *dip, int pm_cmpt, int pm_level)
{
	power_req_t	request;

	request.request_type = PMR_SET_POWER;
	request.req.set_power_req.who = dip;
	request.req.set_power_req.cmpt = pm_cmpt;
	request.req.set_power_req.level = pm_level;
	return (ddi_ctlops(dip, dip, DDI_CTLOPS_POWER, &request, NULL));
}

/*
 * A driver can invoke this from its detach routine when DDI_SUSPEND is
 * passed.  Returns true if subsequent processing could result in power being
 * removed from the device.  The arg is not currently used because it is
 * implicit in the operation of cpr/DR.
 */
int
ddi_removing_power(dev_info_t *dip)
{
	_NOTE(ARGUNUSED(dip))
	return (pm_powering_down);
}

/*
 * Returns true if a device indicates that its parent handles suspend/resume
 * processing for it.
 */
int
e_ddi_parental_suspend_resume(dev_info_t *dip)
{
	return (DEVI(dip)->devi_pm_flags & PMC_PARENTAL_SR);
}

/*
 * Called for devices which indicate that their parent does suspend/resume
 * handling for them
 */
int
e_ddi_suspend(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	power_req_t	request;
	request.request_type = PMR_SUSPEND;
	request.req.suspend_req.who = dip;
	request.req.suspend_req.cmd = cmd;
	return (ddi_ctlops(dip, dip, DDI_CTLOPS_POWER, &request, NULL));
}

/*
 * Called for devices which indicate that their parent does suspend/resume
 * handling for them
 */
int
e_ddi_resume(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	power_req_t	request;
	request.request_type = PMR_RESUME;
	request.req.resume_req.who = dip;
	request.req.resume_req.cmd = cmd;
	return (ddi_ctlops(dip, dip, DDI_CTLOPS_POWER, &request, NULL));
}

/*
 * Old obsolete exported interface for drivers to create components.
 * This is now handled by exporting the pm-components property.
 */
int
pm_create_components(dev_info_t *dip, int num_components)
{
	PMD_FUNC(pmf, "pm_create_components")

	if (num_components < 1)
		return (DDI_FAILURE);

	if (!DEVI_IS_ATTACHING(dip)) {
		return (DDI_FAILURE);
	}

	/* don't need to lock dip because attach is single threaded */
	if (DEVI(dip)->devi_pm_components) {
		PMD(PMD_ERROR, ("%s: %s@%s(%s#%d) already has %d\n", pmf,
		    PM_DEVICE(dip), PM_NUMCMPTS(dip)))
		return (DDI_FAILURE);
	}
	e_pm_create_components(dip, num_components);
	DEVI(dip)->devi_pm_flags |= PMC_BC;
	e_pm_default_components(dip, num_components);
	return (DDI_SUCCESS);
}

/*
 * Obsolete interface previously called by drivers to destroy their components
 * at detach time.  This is now done automatically.  However, we need to keep
 * this for the old drivers.
 */
void
pm_destroy_components(dev_info_t *dip)
{
	PMD_FUNC(pmf, "pm_destroy_components")
	dev_info_t *pdip = ddi_get_parent(dip);

	PMD(PMD_REMDEV | PMD_KIDSUP, ("%s: %s@%s(%s#%d)\n", pmf,
	    PM_DEVICE(dip)))
	ASSERT(DEVI_IS_DETACHING(dip));
#ifdef DEBUG
	if (!PM_ISBC(dip))
		cmn_err(CE_WARN, "!driver exporting pm-components property "
		    "(%s@%s) calls pm_destroy_components", PM_NAME(dip),
		    PM_ADDR(dip));
#endif
	/*
	 * We ignore this unless this is an old-style driver, except for
	 * printing the message above
	 */
	if (PM_NUMCMPTS(dip) == 0 || !PM_ISBC(dip)) {
		PMD(PMD_REMDEV, ("%s: ignore %s@%s(%s#%d)\n", pmf,
		    PM_DEVICE(dip)))
		return;
	}
	ASSERT(PM_GET_PM_INFO(dip));

	/*
	 * pm_unmanage will clear info pointer later, after dealing with
	 * dependencies
	 */
	ASSERT(!PM_GET_PM_SCAN(dip));	/* better be gone already */
	/*
	 * Now adjust parent's kidsupcnt.  We check only comp 0.
	 * Parents that get notification are not adjusted because their
	 * kidsupcnt is always 0 (or 1 during probe and attach).
	 */
	if ((PM_CURPOWER(dip, 0) != 0) && pdip && !PM_WANTS_NOTIFICATION(pdip))
		pm_rele_power(pdip);
#ifdef DEBUG
	else {
		PMD(PMD_KIDSUP, ("%s: kuc stays %s@%s(%s#%d) comps gone\n",
		    pmf, PM_DEVICE(dip)))
	}
#endif
	e_pm_destroy_components(dip);
	/*
	 * Forget we ever knew anything about the components of this  device
	 */
	DEVI(dip)->devi_pm_flags &=
	    ~(PMC_BC | PMC_COMPONENTS_DONE | PMC_COMPONENTS_FAILED);
}

/*
 * Exported interface for a driver to set a component busy.
 */
int
pm_busy_component(dev_info_t *dip, int cmpt)
{
	struct pm_component *cp;

	ASSERT(dip != NULL);
	if (!e_pm_valid_info(dip, NULL) || !e_pm_valid_comp(dip, cmpt, &cp))
		return (DDI_FAILURE);
	PM_LOCK_BUSY(dip);
	cp->pmc_busycount++;
	cp->pmc_timestamp = 0;
	PM_UNLOCK_BUSY(dip);
	return (DDI_SUCCESS);
}

/*
 * Exported interface for a driver to set a component idle.
 */
int
pm_idle_component(dev_info_t *dip, int cmpt)
{
	PMD_FUNC(pmf, "pm_idle_component")
	struct pm_component *cp;
	pm_scan_t	*scanp = PM_GET_PM_SCAN(dip);

	if (!e_pm_valid_info(dip, NULL) || !e_pm_valid_comp(dip, cmpt, &cp))
		return (DDI_FAILURE);

	PM_LOCK_BUSY(dip);
	if (cp->pmc_busycount) {
		if (--(cp->pmc_busycount) == 0)
			cp->pmc_timestamp = gethrestime_sec();
	} else {
		cp->pmc_timestamp = gethrestime_sec();
	}

	PM_UNLOCK_BUSY(dip);

	/*
	 * if device becomes idle during idle down period, try scan it down
	 */
	if (scanp && PM_IS_PID(dip)) {
		PMD(PMD_IDLEDOWN, ("%s: %s@%s(%s#%d) idle.\n", pmf,
		    PM_DEVICE(dip)))
		pm_rescan(dip);
		return (DDI_SUCCESS);
	}

	/*
	 * handle scan not running with nexus threshold == 0
	 */

	if (PM_IS_NEXUS(dip) && (cp->pmc_busycount == 0)) {
		pm_rescan(dip);
	}

	return (DDI_SUCCESS);
}

/*
 * This is the old  obsolete interface called by drivers to set their normal
 * power.  Thus we can't fix its behavior or return a value.
 * This functionality is replaced by the pm-component property.
 * We'll only get components destroyed while no power management is
 * going on (and the device is detached), so we don't need a mutex here
 */
void
pm_set_normal_power(dev_info_t *dip, int comp, int level)
{
	PMD_FUNC(pmf, "set_normal_power")
#ifdef DEBUG
	if (!PM_ISBC(dip))
		cmn_err(CE_WARN, "!call to pm_set_normal_power() by %s@%s "
		    "(driver exporting pm-components property) ignored",
		    PM_NAME(dip), PM_ADDR(dip));
#endif
	if (PM_ISBC(dip)) {
		PMD(PMD_NORM, ("%s: %s@%s(%s#%d) set normal power comp=%d, "
		    "level=%d\n", pmf, PM_DEVICE(dip), comp, level))
		e_pm_set_max_power(dip, comp, level);
		e_pm_default_levels(dip, PM_CP(dip, comp), level);
	}
}

/*
 * Called on a successfully detached driver to free pm resources
 */
static void
pm_stop(dev_info_t *dip)
{
	PMD_FUNC(pmf, "stop")
	dev_info_t *pdip = ddi_get_parent(dip);

	ASSERT(!PM_IAM_LOCKING_DIP(dip));
	/* stopping scan, destroy scan data structure */
	if (!PM_ISBC(dip)) {
		pm_scan_stop(dip);
		pm_scan_fini(dip);
	}

	if (PM_GET_PM_INFO(dip) != NULL) {
		if (pm_unmanage(dip) == DDI_SUCCESS) {
			/*
			 * Old style driver may have called
			 * pm_destroy_components already, but just in case ...
			 */
			e_pm_destroy_components(dip);
		} else {
			PMD(PMD_FAIL, ("%s: can't pm_unmanage %s@%s(%s#%d)\n",
			    pmf, PM_DEVICE(dip)))
		}
	} else {
		if (PM_NUMCMPTS(dip))
			e_pm_destroy_components(dip);
		else {
			if (DEVI(dip)->devi_pm_flags & PMC_NOPMKID) {
				DEVI(dip)->devi_pm_flags &= ~PMC_NOPMKID;
				if (pdip && !PM_WANTS_NOTIFICATION(pdip)) {
					pm_rele_power(pdip);
				} else if (pdip &&
				    MDI_VHCI(pdip) && MDI_CLIENT(dip)) {
					(void) mdi_power(pdip,
					    MDI_PM_RELE_POWER,
					    (void *)dip, NULL, 0);
				}
			}
		}
	}
}

/*
 * The node is the subject of a reparse pm props ioctl. Throw away the old
 * info and start over.
 */
int
e_new_pm_props(dev_info_t *dip)
{
	if (PM_GET_PM_INFO(dip) != NULL) {
		pm_stop(dip);

		if (e_pm_manage(dip, PM_STYLE_NEW) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}
	}
	e_pm_props(dip);
	return (DDI_SUCCESS);
}

/*
 * Device has been attached, so process its pm properties
 */
void
e_pm_props(dev_info_t *dip)
{
	char *pp;
	int len;
	int flags = 0;
	int propflag = DDI_PROP_DONTPASS|DDI_PROP_CANSLEEP;

	/*
	 * It doesn't matter if we do this more than once, we should always
	 * get the same answers, and if not, then the last one in is the
	 * best one.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, propflag, "pm-hardware-state",
	    (caddr_t)&pp, &len) == DDI_PROP_SUCCESS) {
		if (strcmp(pp, "needs-suspend-resume") == 0) {
			flags = PMC_NEEDS_SR;
		} else if (strcmp(pp, "no-suspend-resume") == 0) {
			flags = PMC_NO_SR;
		} else if (strcmp(pp, "parental-suspend-resume") == 0) {
			flags = PMC_PARENTAL_SR;
		} else {
			cmn_err(CE_NOTE, "!device %s@%s has unrecognized "
			    "%s property value '%s'", PM_NAME(dip),
			    PM_ADDR(dip), "pm-hardware-state", pp);
		}
		kmem_free(pp, len);
	}
	/*
	 * This next segment (PMC_WANTS_NOTIFY) is in
	 * support of nexus drivers which will want to be involved in
	 * (or at least notified of) their child node's power level transitions.
	 * "pm-want-child-notification?" is defined by the parent.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, propflag,
	    "pm-want-child-notification?") && PM_HAS_BUS_POWER(dip))
		flags |= PMC_WANTS_NOTIFY;
	ASSERT(PM_HAS_BUS_POWER(dip) || !ddi_prop_exists(DDI_DEV_T_ANY,
	    dip, propflag, "pm-want-child-notification?"));
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, propflag,
	    "no-involuntary-power-cycles"))
		flags |= PMC_NO_INVOL;
	/*
	 * Is the device a CPU device?
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, propflag, "pm-class",
	    (caddr_t)&pp, &len) == DDI_PROP_SUCCESS) {
		if (strcmp(pp, "CPU") == 0) {
			flags |= PMC_CPU_DEVICE;
		} else {
			cmn_err(CE_NOTE, "!device %s@%s has unrecognized "
			    "%s property value '%s'", PM_NAME(dip),
			    PM_ADDR(dip), "pm-class", pp);
		}
		kmem_free(pp, len);
	}
	/* devfs single threads us */
	DEVI(dip)->devi_pm_flags |= flags;
}

/*
 * This is the DDI_CTLOPS_POWER handler that is used when there is no ppm
 * driver which has claimed a node.
 * Sets old_power in arg struct.
 */
static int
pm_default_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	_NOTE(ARGUNUSED(dip))
	PMD_FUNC(pmf, "ctlops")
	power_req_t *reqp = (power_req_t *)arg;
	int retval;
	dev_info_t *target_dip;
	int new_level, old_level, cmpt;
#ifdef PMDDEBUG
	char *format;
#endif

	/*
	 * The interface for doing the actual power level changes is now
	 * through the DDI_CTLOPS_POWER bus_ctl, so that we can plug in
	 * different platform-specific power control drivers.
	 *
	 * This driver implements the "default" version of this interface.
	 * If no ppm driver has been installed then this interface is called
	 * instead.
	 */
	ASSERT(dip == NULL);
	switch (ctlop) {
	case DDI_CTLOPS_POWER:
		switch (reqp->request_type) {
		case PMR_PPM_SET_POWER:
		{
			target_dip = reqp->req.ppm_set_power_req.who;
			ASSERT(target_dip == rdip);
			new_level = reqp->req.ppm_set_power_req.new_level;
			cmpt = reqp->req.ppm_set_power_req.cmpt;
			/* pass back old power for the PM_LEVEL_UNKNOWN case */
			old_level = PM_CURPOWER(target_dip, cmpt);
			reqp->req.ppm_set_power_req.old_level = old_level;
			retval = pm_power(target_dip, cmpt, new_level);
			PMD(PMD_PPM, ("%s: PPM_SET_POWER %s@%s(%s#%d)[%d] %d->"
			    "%d %s\n", pmf, PM_DEVICE(target_dip), cmpt,
			    old_level, new_level, (retval == DDI_SUCCESS ?
			    "chd" : "no chg")))
			return (retval);
		}

		case PMR_PPM_PRE_DETACH:
		case PMR_PPM_POST_DETACH:
		case PMR_PPM_PRE_ATTACH:
		case PMR_PPM_POST_ATTACH:
		case PMR_PPM_PRE_PROBE:
		case PMR_PPM_POST_PROBE:
		case PMR_PPM_PRE_RESUME:
		case PMR_PPM_INIT_CHILD:
		case PMR_PPM_UNINIT_CHILD:
#ifdef PMDDEBUG
			switch (reqp->request_type) {
				case PMR_PPM_PRE_DETACH:
					format = "%s: PMR_PPM_PRE_DETACH "
					    "%s@%s(%s#%d)\n";
					break;
				case PMR_PPM_POST_DETACH:
					format = "%s: PMR_PPM_POST_DETACH "
					    "%s@%s(%s#%d) rets %d\n";
					break;
				case PMR_PPM_PRE_ATTACH:
					format = "%s: PMR_PPM_PRE_ATTACH "
					    "%s@%s(%s#%d)\n";
					break;
				case PMR_PPM_POST_ATTACH:
					format = "%s: PMR_PPM_POST_ATTACH "
					    "%s@%s(%s#%d) rets %d\n";
					break;
				case PMR_PPM_PRE_PROBE:
					format = "%s: PMR_PPM_PRE_PROBE "
					    "%s@%s(%s#%d)\n";
					break;
				case PMR_PPM_POST_PROBE:
					format = "%s: PMR_PPM_POST_PROBE "
					    "%s@%s(%s#%d) rets %d\n";
					break;
				case PMR_PPM_PRE_RESUME:
					format = "%s: PMR_PPM_PRE_RESUME "
					    "%s@%s(%s#%d) rets %d\n";
					break;
				case PMR_PPM_INIT_CHILD:
					format = "%s: PMR_PPM_INIT_CHILD "
					    "%s@%s(%s#%d)\n";
					break;
				case PMR_PPM_UNINIT_CHILD:
					format = "%s: PMR_PPM_UNINIT_CHILD "
					    "%s@%s(%s#%d)\n";
					break;
				default:
					break;
			}
			PMD(PMD_PPM, (format, pmf, PM_DEVICE(rdip),
			    reqp->req.ppm_config_req.result))
#endif
			return (DDI_SUCCESS);

		case PMR_PPM_POWER_CHANGE_NOTIFY:
			/*
			 * Nothing for us to do
			 */
			ASSERT(reqp->req.ppm_notify_level_req.who == rdip);
			PMD(PMD_PPM, ("%s: PMR_PPM_POWER_CHANGE_NOTIFY "
			    "%s@%s(%s#%d)[%d] %d->%d\n", pmf,
			    PM_DEVICE(reqp->req.ppm_notify_level_req.who),
			    reqp->req.ppm_notify_level_req.cmpt,
			    PM_CURPOWER(reqp->req.ppm_notify_level_req.who,
			    reqp->req.ppm_notify_level_req.cmpt),
			    reqp->req.ppm_notify_level_req.new_level))
			return (DDI_SUCCESS);

		case PMR_PPM_UNMANAGE:
			PMD(PMD_PPM, ("%s: PMR_PPM_UNMANAGE %s@%s(%s#%d)\n",
			    pmf, PM_DEVICE(rdip)))
			return (DDI_SUCCESS);

		case PMR_PPM_LOCK_POWER:
			pm_lock_power_single(reqp->req.ppm_lock_power_req.who,
			    reqp->req.ppm_lock_power_req.circp);
			return (DDI_SUCCESS);

		case PMR_PPM_UNLOCK_POWER:
			pm_unlock_power_single(
			    reqp->req.ppm_unlock_power_req.who,
			    reqp->req.ppm_unlock_power_req.circ);
			return (DDI_SUCCESS);

		case PMR_PPM_TRY_LOCK_POWER:
			*(int *)result = pm_try_locking_power_single(
			    reqp->req.ppm_lock_power_req.who,
			    reqp->req.ppm_lock_power_req.circp);
			return (DDI_SUCCESS);

		case PMR_PPM_POWER_LOCK_OWNER:
			target_dip = reqp->req.ppm_power_lock_owner_req.who;
			ASSERT(target_dip == rdip);
			reqp->req.ppm_power_lock_owner_req.owner =
			    DEVI(rdip)->devi_busy_thread;
			return (DDI_SUCCESS);
		default:
			PMD(PMD_ERROR, ("%s: default!\n", pmf))
			return (DDI_FAILURE);
		}

	default:
		PMD(PMD_ERROR, ("%s: unknown\n", pmf))
		return (DDI_FAILURE);
	}
}

/*
 * We overload the bus_ctl ops here--perhaps we ought to have a distinct
 * power_ops struct for this functionality instead?
 * However, we only ever do this on a ppm driver.
 */
int
pm_ctlops(dev_info_t *d, dev_info_t *r, ddi_ctl_enum_t op, void *a, void *v)
{
	int (*fp)();

	/* if no ppm handler, call the default routine */
	if (d == NULL) {
		return (pm_default_ctlops(d, r, op, a, v));
	}
	if (!d || !r)
		return (DDI_FAILURE);
	ASSERT(DEVI(d)->devi_ops && DEVI(d)->devi_ops->devo_bus_ops &&
	    DEVI(d)->devi_ops->devo_bus_ops->bus_ctl);

	fp = DEVI(d)->devi_ops->devo_bus_ops->bus_ctl;
	return ((*fp)(d, r, op, a, v));
}

/*
 * Called on a node when attach completes or the driver makes its first pm
 * call (whichever comes first).
 * In the attach case, device may not be power manageable at all.
 * Don't need to lock the dip because we're single threaded by the devfs code
 */
static int
pm_start(dev_info_t *dip)
{
	PMD_FUNC(pmf, "start")
	int ret;
	dev_info_t *pdip = ddi_get_parent(dip);
	int e_pm_manage(dev_info_t *, int);
	void pm_noinvol_specd(dev_info_t *dip);

	e_pm_props(dip);
	pm_noinvol_specd(dip);
	/*
	 * If this dip has already been processed, don't mess with it
	 * (but decrement the speculative count we did above, as whatever
	 * code put it under pm already will have dealt with it)
	 */
	if (PM_GET_PM_INFO(dip)) {
		PMD(PMD_KIDSUP, ("%s: pm already done for %s@%s(%s#%d)\n",
		    pmf, PM_DEVICE(dip)))
		return (0);
	}
	ret = e_pm_manage(dip, PM_STYLE_UNKNOWN);

	if (PM_GET_PM_INFO(dip) == NULL) {
		/*
		 * keep the kidsupcount increment as is
		 */
		DEVI(dip)->devi_pm_flags |= PMC_NOPMKID;
		if (pdip && !PM_WANTS_NOTIFICATION(pdip)) {
			pm_hold_power(pdip);
		} else if (pdip && MDI_VHCI(pdip) && MDI_CLIENT(dip)) {
			(void) mdi_power(pdip, MDI_PM_HOLD_POWER,
			    (void *)dip, NULL, 0);
		}

		PMD(PMD_KIDSUP, ("%s: pm of %s@%s(%s#%d) failed, parent "
		    "left up\n", pmf, PM_DEVICE(dip)))
	}

	return (ret);
}

/*
 * Keep a list of recorded thresholds.  For now we just keep a list and
 * search it linearly.  We don't expect too many entries.  Can always hash it
 * later if we need to.
 */
void
pm_record_thresh(pm_thresh_rec_t *rp)
{
	pm_thresh_rec_t *pptr, *ptr;

	ASSERT(*rp->ptr_physpath);
	rw_enter(&pm_thresh_rwlock, RW_WRITER);
	for (pptr = NULL, ptr = pm_thresh_head;
	    ptr; pptr = ptr,  ptr = ptr->ptr_next) {
		if (strcmp(rp->ptr_physpath, ptr->ptr_physpath) == 0) {
			/* replace this one */
			rp->ptr_next = ptr->ptr_next;
			if (pptr) {
				pptr->ptr_next = rp;
			} else {
				pm_thresh_head = rp;
			}
			rw_exit(&pm_thresh_rwlock);
			kmem_free(ptr, ptr->ptr_size);
			return;
		}
		continue;
	}
	/*
	 * There was not a match in the list, insert this one in front
	 */
	if (pm_thresh_head) {
		rp->ptr_next = pm_thresh_head;
		pm_thresh_head = rp;
	} else {
		rp->ptr_next = NULL;
		pm_thresh_head = rp;
	}
	rw_exit(&pm_thresh_rwlock);
}

/*
 * Create a new dependency record and hang a new dependency entry off of it
 */
pm_pdr_t *
newpdr(char *kept, char *keeps, int isprop)
{
	size_t size = strlen(kept) + strlen(keeps) + 2 + sizeof (pm_pdr_t);
	pm_pdr_t *p = kmem_zalloc(size, KM_SLEEP);
	p->pdr_size = size;
	p->pdr_isprop = isprop;
	p->pdr_kept_paths = NULL;
	p->pdr_kept_count = 0;
	p->pdr_kept = (char *)((intptr_t)p + sizeof (pm_pdr_t));
	(void) strcpy(p->pdr_kept, kept);
	p->pdr_keeper = (char *)((intptr_t)p->pdr_kept + strlen(kept) + 1);
	(void) strcpy(p->pdr_keeper, keeps);
	ASSERT((intptr_t)p->pdr_keeper + strlen(p->pdr_keeper) + 1 <=
	    (intptr_t)p + size);
	ASSERT((intptr_t)p->pdr_kept + strlen(p->pdr_kept) + 1 <=
	    (intptr_t)p + size);
	return (p);
}

/*
 * Keep a list of recorded dependencies.  We only keep the
 * keeper -> kept list for simplification. At this point We do not
 * care about whether the devices are attached or not yet,
 * this would be done in pm_keeper() and pm_kept().
 * If a PM_RESET_PM happens, then we tear down and forget the dependencies,
 * and it is up to the user to issue the ioctl again if they want it
 * (e.g. pmconfig)
 * Returns true if dependency already exists in the list.
 */
int
pm_record_keeper(char *kept, char *keeper, int isprop)
{
	PMD_FUNC(pmf, "record_keeper")
	pm_pdr_t *npdr, *ppdr, *pdr;

	PMD(PMD_KEEPS, ("%s: %s, %s\n", pmf, kept, keeper))
	ASSERT(kept && keeper);
#ifdef DEBUG
	if (pm_debug & PMD_KEEPS)
		prdeps("pm_record_keeper entry");
#endif
	for (ppdr = NULL, pdr = pm_dep_head; pdr;
	    ppdr = pdr, pdr = pdr->pdr_next) {
		PMD(PMD_KEEPS, ("%s: check %s, %s\n", pmf, pdr->pdr_kept,
		    pdr->pdr_keeper))
		if (strcmp(kept, pdr->pdr_kept) == 0 &&
		    strcmp(keeper, pdr->pdr_keeper) == 0) {
			PMD(PMD_KEEPS, ("%s: match\n", pmf))
			return (1);
		}
	}
	/*
	 * We did not find any match, so we have to make an entry
	 */
	npdr = newpdr(kept, keeper, isprop);
	if (ppdr) {
		ASSERT(ppdr->pdr_next == NULL);
		ppdr->pdr_next = npdr;
	} else {
		ASSERT(pm_dep_head == NULL);
		pm_dep_head = npdr;
	}
#ifdef DEBUG
	if (pm_debug & PMD_KEEPS)
		prdeps("pm_record_keeper after new record");
#endif
	if (!isprop)
		pm_unresolved_deps++;
	else
		pm_prop_deps++;
	return (0);
}

/*
 * Look up this device in the set of devices we've seen ioctls for
 * to see if we are holding a threshold spec for it.  If so, make it so.
 * At ioctl time, we were given the physical path of the device.
 */
int
pm_thresh_specd(dev_info_t *dip)
{
	void pm_apply_recorded_thresh(dev_info_t *, pm_thresh_rec_t *);
	char *path = 0;
	char pathbuf[MAXNAMELEN];
	pm_thresh_rec_t *rp;

	path = ddi_pathname(dip, pathbuf);

	rw_enter(&pm_thresh_rwlock, RW_READER);
	for (rp = pm_thresh_head; rp; rp = rp->ptr_next) {
		if (strcmp(rp->ptr_physpath, path) != 0)
			continue;
		pm_apply_recorded_thresh(dip, rp);
		rw_exit(&pm_thresh_rwlock);
		return (1);
	}
	rw_exit(&pm_thresh_rwlock);
	return (0);
}

static int
pm_set_keeping(dev_info_t *keeper, dev_info_t *kept)
{
	PMD_FUNC(pmf, "set_keeping")
	int j, up = 0, circ;
	void prdeps(char *);

	PMD(PMD_KEEPS, ("%s: keeper=%s@%s(%s#%d), kept=%s@%s(%s#%d)\n", pmf,
	    PM_DEVICE(keeper), PM_DEVICE(kept)))
#ifdef DEBUG
	if (pm_debug & PMD_KEEPS)
		prdeps("Before PAD\n");
#endif
	ASSERT(keeper != kept);
	if (PM_GET_PM_INFO(keeper) == NULL) {
		cmn_err(CE_CONT, "!device %s@%s(%s#%d) keeps up device "
		    "%s@%s(%s#%d), but the former is not power managed",
		    PM_DEVICE(keeper), PM_DEVICE(kept));
		PMD((PMD_FAIL | PMD_KEEPS), ("%s: keeper %s@%s(%s#%d) is not"
		    "power managed\n", pmf, PM_DEVICE(keeper)))
		return (0);
	}
	if (PM_GET_PM_INFO(kept) == NULL) {
		cmn_err(CE_CONT, "!device %s@%s(%s#%d) keeps up device "
		    "%s@%s(%s#%d), but the latter is not power managed",
		    PM_DEVICE(keeper), PM_DEVICE(kept));
		PMD((PMD_FAIL | PMD_KEEPS), ("%s: kept %s@%s(%s#%d) is not"
		    "power managed\n", pmf, PM_DEVICE(kept)))
		return (0);
	}

	PM_LOCK_POWER(keeper, &circ);
	for (j = 0; j < PM_NUMCMPTS(keeper); j++) {
		if (PM_CURPOWER(keeper, j)) {
			up++;
			break;
		}
	}
	if (up) {
		/* Bringup and maintain a hold on the kept */
		PMD(PMD_KEEPS, ("%s: place a hold on kept %s@%s(%s#%d)\n", pmf,
		    PM_DEVICE(kept)))
		bring_pmdep_up(kept, 1);
	}
	PM_UNLOCK_POWER(keeper, circ);
#ifdef DEBUG
	if (pm_debug & PMD_KEEPS)
		prdeps("After PAD\n");
#endif
	return (1);
}

/*
 * Should this device keep up another device?
 * Look up this device in the set of devices we've seen ioctls for
 * to see if we are holding a dependency spec for it.  If so, make it so.
 * Because we require the kept device to be attached already in order to
 * make the list entry (and hold it), we only need to look for keepers.
 * At ioctl time, we were given the physical path of the device.
 */
int
pm_keeper(char *keeper)
{
	PMD_FUNC(pmf, "keeper")
	int pm_apply_recorded_dep(dev_info_t *, pm_pdr_t *);
	dev_info_t *dip;
	pm_pdr_t *dp;
	dev_info_t *kept = NULL;
	int ret = 0;
	int i;

	if (!pm_unresolved_deps && !pm_prop_deps)
		return (0);
	ASSERT(keeper != NULL);
	dip = pm_name_to_dip(keeper, 1);
	if (dip == NULL)
		return (0);
	PMD(PMD_KEEPS, ("%s: keeper=%s\n", pmf, keeper))
	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (!dp->pdr_isprop) {
			if (!pm_unresolved_deps)
				continue;
			PMD(PMD_KEEPS, ("%s: keeper %s\n", pmf, dp->pdr_keeper))
			if (dp->pdr_satisfied) {
				PMD(PMD_KEEPS, ("%s: satisfied\n", pmf))
				continue;
			}
			if (strcmp(dp->pdr_keeper, keeper) == 0) {
				ret += pm_apply_recorded_dep(dip, dp);
			}
		} else {
			if (strcmp(dp->pdr_keeper, keeper) != 0)
				continue;
			for (i = 0; i < dp->pdr_kept_count; i++) {
				if (dp->pdr_kept_paths[i] == NULL)
					continue;
				kept = pm_name_to_dip(dp->pdr_kept_paths[i], 1);
				if (kept == NULL)
					continue;
				ASSERT(ddi_prop_exists(DDI_DEV_T_ANY, kept,
				    DDI_PROP_DONTPASS, dp->pdr_kept));
				PMD(PMD_KEEPS, ("%s: keeper=%s@%s(%s#%d), "
				    "kept=%s@%s(%s#%d) keptcnt=%d\n",
				    pmf, PM_DEVICE(dip), PM_DEVICE(kept),
				    dp->pdr_kept_count))
				if (kept != dip) {
					ret += pm_set_keeping(dip, kept);
				}
				ddi_release_devi(kept);
			}

		}
	}
	ddi_release_devi(dip);
	return (ret);
}

/*
 * Should this device be kept up by another device?
 * Look up all dependency recorded from PM_ADD_DEPENDENT and
 * PM_ADD_DEPENDENT_PROPERTY ioctls. Record down on the keeper's
 * kept device lists.
 */
static int
pm_kept(char *keptp)
{
	PMD_FUNC(pmf, "kept")
	pm_pdr_t *dp;
	int found = 0;
	int ret = 0;
	dev_info_t *keeper;
	dev_info_t *kept;
	size_t length;
	int i;
	char **paths;
	char *path;

	ASSERT(keptp != NULL);
	kept = pm_name_to_dip(keptp, 1);
	if (kept == NULL)
		return (0);
	PMD(PMD_KEEPS, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(kept)))
	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (dp->pdr_isprop) {
			PMD(PMD_KEEPS, ("%s: property %s\n", pmf, dp->pdr_kept))
			if (ddi_prop_exists(DDI_DEV_T_ANY, kept,
			    DDI_PROP_DONTPASS, dp->pdr_kept)) {
				/*
				 * Dont allow self dependency.
				 */
				if (strcmp(dp->pdr_keeper, keptp) == 0)
					continue;
				keeper = pm_name_to_dip(dp->pdr_keeper, 1);
				if (keeper == NULL)
					continue;
				PMD(PMD_KEEPS, ("%s: adding to kepts path list "
				    "%p\n", pmf, (void *)kept))
#ifdef DEBUG
				if (pm_debug & PMD_DEP)
					prdeps("Before Adding from pm_kept\n");
#endif
				/*
				 * Add ourselves to the dip list.
				 */
				if (dp->pdr_kept_count == 0) {
					length = strlen(keptp) + 1;
					path =
					    kmem_alloc(length, KM_SLEEP);
					paths = kmem_alloc(sizeof (char **),
					    KM_SLEEP);
					(void) strcpy(path, keptp);
					paths[0] = path;
					dp->pdr_kept_paths = paths;
					dp->pdr_kept_count++;
				} else {
					/* Check to see if already on list */
					for (i = 0; i < dp->pdr_kept_count;
					    i++) {
						if (strcmp(keptp,
						    dp->pdr_kept_paths[i])
						    == 0) {
							found++;
							break;
						}
					}
					if (found) {
						ddi_release_devi(keeper);
						continue;
					}
					length = dp->pdr_kept_count *
					    sizeof (char **);
					paths = kmem_alloc(
					    length + sizeof (char **),
					    KM_SLEEP);
					if (dp->pdr_kept_count) {
						bcopy(dp->pdr_kept_paths,
						    paths, length);
						kmem_free(dp->pdr_kept_paths,
						    length);
					}
					dp->pdr_kept_paths = paths;
					length = strlen(keptp) + 1;
					path =
					    kmem_alloc(length, KM_SLEEP);
					(void) strcpy(path, keptp);
					dp->pdr_kept_paths[i] = path;
					dp->pdr_kept_count++;
				}
#ifdef DEBUG
				if (pm_debug & PMD_DEP)
					prdeps("After from pm_kept\n");
#endif
				if (keeper) {
					ret += pm_set_keeping(keeper, kept);
					ddi_release_devi(keeper);
				}
			}
		} else {
			/*
			 * pm_keeper would be called later to do
			 * the actual pm_set_keeping.
			 */
			PMD(PMD_KEEPS, ("%s: adding to kepts path list %p\n",
			    pmf, (void *)kept))
#ifdef DEBUG
			if (pm_debug & PMD_DEP)
				prdeps("Before Adding from pm_kept\n");
#endif
			if (strcmp(keptp, dp->pdr_kept) == 0) {
				if (dp->pdr_kept_paths == NULL) {
					length = strlen(keptp) + 1;
					path =
					    kmem_alloc(length, KM_SLEEP);
					paths = kmem_alloc(sizeof (char **),
					    KM_SLEEP);
					(void) strcpy(path, keptp);
					paths[0] = path;
					dp->pdr_kept_paths = paths;
					dp->pdr_kept_count++;
				}
			}
#ifdef DEBUG
			if (pm_debug & PMD_DEP)
				prdeps("After from pm_kept\n");
#endif
		}
	}
	ddi_release_devi(kept);
	return (ret);
}

/*
 * Apply a recorded dependency.  dp specifies the dependency, and
 * keeper is already known to be the device that keeps up the other (kept) one.
 * We have to the whole tree for the "kept" device, then apply
 * the dependency (which may already be applied).
 */
int
pm_apply_recorded_dep(dev_info_t *keeper, pm_pdr_t *dp)
{
	PMD_FUNC(pmf, "apply_recorded_dep")
	dev_info_t *kept = NULL;
	int ret = 0;
	char *keptp = NULL;

	/*
	 * Device to Device dependency can only be 1 to 1.
	 */
	if (dp->pdr_kept_paths == NULL)
		return (0);
	keptp = dp->pdr_kept_paths[0];
	if (keptp == NULL)
		return (0);
	ASSERT(*keptp != '\0');
	kept = pm_name_to_dip(keptp, 1);
	if (kept == NULL)
		return (0);
	if (kept) {
		PMD(PMD_KEEPS, ("%s: keeper=%s, kept=%s\n", pmf,
		    dp->pdr_keeper, keptp))
		if (pm_set_keeping(keeper, kept)) {
			ASSERT(dp->pdr_satisfied == 0);
			dp->pdr_satisfied = 1;
			ASSERT(pm_unresolved_deps);
			pm_unresolved_deps--;
			ret++;
		}
	}
	ddi_release_devi(kept);

	return (ret);
}

/*
 * Called from common/io/pm.c
 */
int
pm_cur_power(pm_component_t *cp)
{
	return (cur_power(cp));
}

/*
 * External interface to sanity-check a power level.
 */
int
pm_valid_power(dev_info_t *dip, int comp, int level)
{
	PMD_FUNC(pmf, "valid_power")

	if (comp >= 0 && comp < PM_NUMCMPTS(dip) && level >= 0)
		return (e_pm_valid_power(dip, comp, level));
	else {
		PMD(PMD_FAIL, ("%s: comp=%d, ncomp=%d, level=%d\n",
		    pmf, comp, PM_NUMCMPTS(dip), level))
		return (0);
	}
}

/*
 * Called when a device that is direct power managed needs to change state.
 * This routine arranges to block the request until the process managing
 * the device makes the change (or some other incompatible change) or
 * the process closes /dev/pm.
 */
static int
pm_block(dev_info_t *dip, int comp, int newpower, int oldpower)
{
	pm_rsvp_t *new = kmem_zalloc(sizeof (*new), KM_SLEEP);
	int ret = 0;
	void pm_dequeue_blocked(pm_rsvp_t *);
	void pm_enqueue_blocked(pm_rsvp_t *);

	ASSERT(!pm_processes_stopped);
	ASSERT(PM_IAM_LOCKING_DIP(dip));
	new->pr_dip = dip;
	new->pr_comp = comp;
	new->pr_newlevel = newpower;
	new->pr_oldlevel = oldpower;
	cv_init(&new->pr_cv, NULL, CV_DEFAULT, NULL);
	mutex_enter(&pm_rsvp_lock);
	pm_enqueue_blocked(new);
	pm_enqueue_notify(PSC_PENDING_CHANGE, dip, comp, newpower, oldpower,
	    PM_CANBLOCK_BLOCK);
	PM_UNLOCK_DIP(dip);
	/*
	 * truss may make the cv_wait_sig return prematurely
	 */
	while (ret == 0) {
		/*
		 * Normally there will be no user context involved, but if
		 * there is (e.g. we are here via an ioctl call to a driver)
		 * then we should allow the process to abort the request,
		 * or we get an unkillable process if the same thread does
		 * PM_DIRECT_PM and pm_raise_power
		 */
		if (cv_wait_sig(&new->pr_cv, &pm_rsvp_lock) == 0) {
			ret = PMP_FAIL;
		} else {
			ret = new->pr_retval;
		}
	}
	pm_dequeue_blocked(new);
	mutex_exit(&pm_rsvp_lock);
	cv_destroy(&new->pr_cv);
	kmem_free(new, sizeof (*new));
	return (ret);
}

/*
 * Returns true if the process is interested in power level changes (has issued
 * PM_GET_STATE_CHANGE ioctl).
 */
int
pm_interest_registered(int clone)
{
	ASSERT(clone >= 0 && clone < PM_MAX_CLONE - 1);
	return (pm_interest[clone]);
}

static void pm_enqueue_pscc(pscc_t *, pscc_t **);

/*
 * Process with clone has just done PM_DIRECT_PM on dip, or has asked to
 * watch all state transitions (dip == NULL).  Set up data
 * structs to communicate with process about state changes.
 */
void
pm_register_watcher(int clone, dev_info_t *dip)
{
	pscc_t	*p;
	psce_t	*psce;

	/*
	 * We definitely need a control struct, then we have to search to see
	 * there is already an entries struct (in the dip != NULL case).
	 */
	pscc_t	*pscc = kmem_zalloc(sizeof (*pscc), KM_SLEEP);
	pscc->pscc_clone = clone;
	pscc->pscc_dip = dip;

	if (dip) {
		int found = 0;
		rw_enter(&pm_pscc_direct_rwlock, RW_WRITER);
		for (p = pm_pscc_direct; p; p = p->pscc_next) {
			/*
			 * Already an entry for this clone, so just use it
			 * for the new one (for the case where a single
			 * process is watching multiple devices)
			 */
			if (p->pscc_clone == clone) {
				pscc->pscc_entries = p->pscc_entries;
				pscc->pscc_entries->psce_references++;
				found++;
				break;
			}
		}
		if (!found) {		/* create a new one */
			psce = kmem_zalloc(sizeof (psce_t), KM_SLEEP);
			mutex_init(&psce->psce_lock, NULL, MUTEX_DEFAULT, NULL);
			psce->psce_first =
			    kmem_zalloc(sizeof (pm_state_change_t) * PSCCOUNT,
			    KM_SLEEP);
			psce->psce_in = psce->psce_out = psce->psce_first;
			psce->psce_last = &psce->psce_first[PSCCOUNT - 1];
			psce->psce_references = 1;
			pscc->pscc_entries = psce;
		}
		pm_enqueue_pscc(pscc, &pm_pscc_direct);
		rw_exit(&pm_pscc_direct_rwlock);
	} else {
		ASSERT(!pm_interest_registered(clone));
		rw_enter(&pm_pscc_interest_rwlock, RW_WRITER);
#ifdef DEBUG
		for (p = pm_pscc_interest; p; p = p->pscc_next) {
			/*
			 * Should not be an entry for this clone!
			 */
			ASSERT(p->pscc_clone != clone);
		}
#endif
		psce = kmem_zalloc(sizeof (psce_t), KM_SLEEP);
		psce->psce_first = kmem_zalloc(sizeof (pm_state_change_t) *
		    PSCCOUNT, KM_SLEEP);
		psce->psce_in = psce->psce_out = psce->psce_first;
		psce->psce_last = &psce->psce_first[PSCCOUNT - 1];
		psce->psce_references = 1;
		pscc->pscc_entries = psce;
		pm_enqueue_pscc(pscc, &pm_pscc_interest);
		pm_interest[clone] = 1;
		rw_exit(&pm_pscc_interest_rwlock);
	}
}

/*
 * Remove the given entry from the blocked list
 */
void
pm_dequeue_blocked(pm_rsvp_t *p)
{
	ASSERT(MUTEX_HELD(&pm_rsvp_lock));
	if (pm_blocked_list == p) {
		ASSERT(p->pr_prev == NULL);
		if (p->pr_next != NULL)
			p->pr_next->pr_prev = NULL;
		pm_blocked_list = p->pr_next;
	} else {
		ASSERT(p->pr_prev != NULL);
		p->pr_prev->pr_next = p->pr_next;
		if (p->pr_next != NULL)
			p->pr_next->pr_prev = p->pr_prev;
	}
}

/*
 * Remove the given control struct from the given list
 */
static void
pm_dequeue_pscc(pscc_t *p, pscc_t **list)
{
	if (*list == p) {
		ASSERT(p->pscc_prev == NULL);
		if (p->pscc_next != NULL)
			p->pscc_next->pscc_prev = NULL;
		*list = p->pscc_next;
	} else {
		ASSERT(p->pscc_prev != NULL);
		p->pscc_prev->pscc_next = p->pscc_next;
		if (p->pscc_next != NULL)
			p->pscc_next->pscc_prev = p->pscc_prev;
	}
}

/*
 * Stick the control struct specified on the front of the list
 */
static void
pm_enqueue_pscc(pscc_t *p, pscc_t **list)
{
	pscc_t *h;	/* entry at head of list */
	if ((h = *list) == NULL) {
		*list = p;
		ASSERT(p->pscc_next == NULL);
		ASSERT(p->pscc_prev == NULL);
	} else {
		p->pscc_next = h;
		ASSERT(h->pscc_prev == NULL);
		h->pscc_prev = p;
		ASSERT(p->pscc_prev == NULL);
		*list = p;
	}
}

/*
 * If dip is NULL, process is closing "clone" clean up all its registrations.
 * Otherwise only clean up those for dip because process is just giving up
 * control of a direct device.
 */
void
pm_deregister_watcher(int clone, dev_info_t *dip)
{
	pscc_t	*p, *pn;
	psce_t	*psce;
	int found = 0;

	if (dip == NULL) {
		rw_enter(&pm_pscc_interest_rwlock, RW_WRITER);
		for (p = pm_pscc_interest; p; p = pn) {
			pn = p->pscc_next;
			if (p->pscc_clone == clone) {
				pm_dequeue_pscc(p, &pm_pscc_interest);
				psce = p->pscc_entries;
				ASSERT(psce->psce_references == 1);
				mutex_destroy(&psce->psce_lock);
				kmem_free(psce->psce_first,
				    sizeof (pm_state_change_t) * PSCCOUNT);
				kmem_free(psce, sizeof (*psce));
				kmem_free(p, sizeof (*p));
			}
		}
		pm_interest[clone] = 0;
		rw_exit(&pm_pscc_interest_rwlock);
	}
	found = 0;
	rw_enter(&pm_pscc_direct_rwlock, RW_WRITER);
	for (p = pm_pscc_direct; p; p = pn) {
		pn = p->pscc_next;
		if ((dip && p->pscc_dip == dip) ||
		    (dip == NULL && clone == p->pscc_clone)) {
			ASSERT(clone == p->pscc_clone);
			found++;
			/*
			 * Remove from control list
			 */
			pm_dequeue_pscc(p, &pm_pscc_direct);
			/*
			 * If we're the last reference, free the
			 * entries struct.
			 */
			psce = p->pscc_entries;
			ASSERT(psce);
			if (psce->psce_references == 1) {
				kmem_free(psce->psce_first,
				    PSCCOUNT * sizeof (pm_state_change_t));
				kmem_free(psce, sizeof (*psce));
			} else {
				psce->psce_references--;
			}
			kmem_free(p, sizeof (*p));
		}
	}
	ASSERT(dip == NULL || found);
	rw_exit(&pm_pscc_direct_rwlock);
}

/*
 * Search the indicated list for an entry that matches clone, and return a
 * pointer to it.  To be interesting, the entry must have something ready to
 * be passed up to the controlling process.
 * The returned entry will be locked upon return from this call.
 */
static psce_t *
pm_psc_find_clone(int clone, pscc_t **list, krwlock_t *lock)
{
	pscc_t	*p;
	psce_t	*psce;
	rw_enter(lock, RW_READER);
	for (p = *list; p; p = p->pscc_next) {
		if (clone == p->pscc_clone) {
			psce = p->pscc_entries;
			mutex_enter(&psce->psce_lock);
			if (psce->psce_out->size) {
				rw_exit(lock);
				return (psce);
			} else {
				mutex_exit(&psce->psce_lock);
			}
		}
	}
	rw_exit(lock);
	return (NULL);
}

static psce_t *pm_psc_find_clone(int, pscc_t **, krwlock_t *);
/*
 * Find an entry for a particular clone in the direct list.
 */
psce_t *
pm_psc_clone_to_direct(int clone)
{
	return (pm_psc_find_clone(clone, &pm_pscc_direct,
	    &pm_pscc_direct_rwlock));
}

/*
 * Find an entry for a particular clone in the interest list.
 */
psce_t *
pm_psc_clone_to_interest(int clone)
{
	return (pm_psc_find_clone(clone, &pm_pscc_interest,
	    &pm_pscc_interest_rwlock));
}

/*
 * Put the given entry at the head of the blocked list
 */
void
pm_enqueue_blocked(pm_rsvp_t *p)
{
	ASSERT(MUTEX_HELD(&pm_rsvp_lock));
	ASSERT(p->pr_next == NULL);
	ASSERT(p->pr_prev == NULL);
	if (pm_blocked_list != NULL) {
		p->pr_next = pm_blocked_list;
		ASSERT(pm_blocked_list->pr_prev == NULL);
		pm_blocked_list->pr_prev = p;
		pm_blocked_list = p;
	} else {
		pm_blocked_list = p;
	}
}

/*
 * Sets every power managed device back to its default threshold
 */
void
pm_all_to_default_thresholds(void)
{
	ddi_walk_devs(ddi_root_node(), pm_set_dev_thr_walk,
	    (void *) &pm_system_idle_threshold);
}

static int
pm_set_dev_thr_walk(dev_info_t *dip, void *arg)
{
	int thr = (int)(*(int *)arg);

	if (!PM_GET_PM_INFO(dip))
		return (DDI_WALK_CONTINUE);
	pm_set_device_threshold(dip, thr, PMC_DEF_THRESH);
	return (DDI_WALK_CONTINUE);
}

/*
 * Returns the current threshold value (in seconds) for the indicated component
 */
int
pm_current_threshold(dev_info_t *dip, int comp, int *threshp)
{
	if (comp < 0 || comp >= PM_NUMCMPTS(dip)) {
		return (DDI_FAILURE);
	} else {
		*threshp = cur_threshold(dip, comp);
		return (DDI_SUCCESS);
	}
}

/*
 * To be called when changing the power level of a component of a device.
 * On some platforms, changing power on one device may require that power
 * be changed on other, related devices in the same transaction.  Thus, we
 * always pass this request to the platform power manager so that all the
 * affected devices will be locked.
 */
void
pm_lock_power(dev_info_t *dip, int *circp)
{
	power_req_t power_req;
	int result;

	power_req.request_type = PMR_PPM_LOCK_POWER;
	power_req.req.ppm_lock_power_req.who = dip;
	power_req.req.ppm_lock_power_req.circp = circp;
	(void) pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER, &power_req, &result);
}

/*
 * Release the lock (or locks) acquired to change the power of a device.
 * See comments for pm_lock_power.
 */
void
pm_unlock_power(dev_info_t *dip, int circ)
{
	power_req_t power_req;
	int result;

	power_req.request_type = PMR_PPM_UNLOCK_POWER;
	power_req.req.ppm_unlock_power_req.who = dip;
	power_req.req.ppm_unlock_power_req.circ = circ;
	(void) pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER, &power_req, &result);
}


/*
 * Attempt (without blocking) to acquire the lock(s) needed to change the
 * power of a component of a device.  See comments for pm_lock_power.
 *
 * Return: 1 if lock(s) acquired, 0 if not.
 */
int
pm_try_locking_power(dev_info_t *dip, int *circp)
{
	power_req_t power_req;
	int result;

	power_req.request_type = PMR_PPM_TRY_LOCK_POWER;
	power_req.req.ppm_lock_power_req.who = dip;
	power_req.req.ppm_lock_power_req.circp = circp;
	(void) pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER, &power_req, &result);
	return (result);
}


/*
 * Lock power state of a device.
 *
 * The implementation handles a special case where another thread may have
 * acquired the lock and created/launched this thread to do the work.  If
 * the lock cannot be acquired immediately, we check to see if this thread
 * is registered as a borrower of the lock.  If so, we may proceed without
 * the lock.  This assumes that the lending thread blocks on the completion
 * of this thread.
 *
 * Note 1: for use by ppm only.
 *
 * Note 2: On failing to get the lock immediately, we search lock_loan list
 * for curthread (as borrower of the lock).  On a hit, we check that the
 * lending thread already owns the lock we want.  It is safe to compare
 * devi_busy_thread and thread id of the lender because in the == case (the
 * only one we care about) we know that the owner is blocked.  Similarly,
 * If we find that curthread isn't registered as a lock borrower, it is safe
 * to use the blocking call (ndi_devi_enter) because we know that if we
 * weren't already listed as a borrower (upstream on the call stack) we won't
 * become one.
 */
void
pm_lock_power_single(dev_info_t *dip, int *circp)
{
	lock_loan_t *cur;

	/* if the lock is available, we are done. */
	if (ndi_devi_tryenter(dip, circp))
		return;

	mutex_enter(&pm_loan_lock);
	/* see if our thread is registered as a lock borrower. */
	for (cur = lock_loan_head.pmlk_next; cur; cur = cur->pmlk_next)
		if (cur->pmlk_borrower == curthread)
			break;
	mutex_exit(&pm_loan_lock);

	/* if this thread not already registered, it is safe to block */
	if (cur == NULL)
		ndi_devi_enter(dip, circp);
	else {
		/* registered: does lender own the lock we want? */
		if (cur->pmlk_lender == DEVI(dip)->devi_busy_thread) {
			ASSERT(cur->pmlk_dip == NULL || cur->pmlk_dip == dip);
			cur->pmlk_dip = dip;
		} else /* no: just block for it */
			ndi_devi_enter(dip, circp);

	}
}

/*
 * Drop the lock on the device's power state.  See comment for
 * pm_lock_power_single() for special implementation considerations.
 *
 * Note: for use by ppm only.
 */
void
pm_unlock_power_single(dev_info_t *dip, int circ)
{
	lock_loan_t *cur;

	/* optimization: mutex not needed to check empty list */
	if (lock_loan_head.pmlk_next == NULL) {
		ndi_devi_exit(dip, circ);
		return;
	}

	mutex_enter(&pm_loan_lock);
	/* see if our thread is registered as a lock borrower. */
	for (cur = lock_loan_head.pmlk_next; cur; cur = cur->pmlk_next)
		if (cur->pmlk_borrower == curthread)
			break;
	mutex_exit(&pm_loan_lock);

	if (cur == NULL || cur->pmlk_dip != dip)
		/* we acquired the lock directly, so return it */
		ndi_devi_exit(dip, circ);
}

/*
 * Try to take the lock for changing the power level of a component.
 *
 * Note: for use by ppm only.
 */
int
pm_try_locking_power_single(dev_info_t *dip, int *circp)
{
	return (ndi_devi_tryenter(dip, circp));
}

#ifdef	DEBUG
/*
 * The following are used only to print out data structures for debugging
 */
void
prdeps(char *msg)
{

	pm_pdr_t *rp;
	int i;

	pm_log("pm_dep_head %s %p\n", msg, (void *)pm_dep_head);
	for (rp = pm_dep_head; rp; rp = rp->pdr_next) {
		pm_log("%p: %s keeper %s, kept %s, kept count %d, next %p\n",
		    (void *)rp, (rp->pdr_isprop ? "property" : "device"),
		    rp->pdr_keeper, rp->pdr_kept, rp->pdr_kept_count,
		    (void *)rp->pdr_next);
		if (rp->pdr_kept_count != 0) {
			pm_log("kept list = ");
			i = 0;
			while (i < rp->pdr_kept_count) {
				pm_log("%s ", rp->pdr_kept_paths[i]);
				i++;
			}
			pm_log("\n");
		}
	}
}

void
pr_noinvol(char *hdr)
{
	pm_noinvol_t *ip;

	pm_log("%s\n", hdr);
	rw_enter(&pm_noinvol_rwlock, RW_READER);
	for (ip = pm_noinvol_head; ip; ip = ip->ni_next)
		pm_log("\tmaj %d, flags %x, noinvolpm %d %s\n",
		    ip->ni_major, ip->ni_flags, ip->ni_noinvolpm, ip->ni_path);
	rw_exit(&pm_noinvol_rwlock);
}
#endif

/*
 * Attempt to apply the thresholds indicated by rp to the node specified by
 * dip.
 */
void
pm_apply_recorded_thresh(dev_info_t *dip, pm_thresh_rec_t *rp)
{
	PMD_FUNC(pmf, "apply_recorded_thresh")
	int i, j;
	int comps = PM_NUMCMPTS(dip);
	struct pm_component *cp;
	pm_pte_t *ep;
	int pm_valid_thresh(dev_info_t *, pm_thresh_rec_t *);

	PMD(PMD_THRESH, ("%s: part: %s@%s(%s#%d), rp %p, %s\n", pmf,
	    PM_DEVICE(dip), (void *)rp, rp->ptr_physpath))
	PM_LOCK_DIP(dip);
	if (!PM_GET_PM_INFO(dip) || PM_ISBC(dip) || !pm_valid_thresh(dip, rp)) {
		PMD(PMD_FAIL, ("%s: part: %s@%s(%s#%d) PM_GET_PM_INFO %p\n",
		    pmf, PM_DEVICE(dip), (void*)PM_GET_PM_INFO(dip)))
		PMD(PMD_FAIL, ("%s: part: %s@%s(%s#%d) PM_ISBC %d\n",
		    pmf, PM_DEVICE(dip), PM_ISBC(dip)))
		PMD(PMD_FAIL, ("%s: part: %s@%s(%s#%d) pm_valid_thresh %d\n",
		    pmf, PM_DEVICE(dip), pm_valid_thresh(dip, rp)))
		PM_UNLOCK_DIP(dip);
		return;
	}

	ep = rp->ptr_entries;
	/*
	 * Here we do the special case of a device threshold
	 */
	if (rp->ptr_numcomps == 0) {	/* PM_SET_DEVICE_THRESHOLD product */
		ASSERT(ep && ep->pte_numthresh == 1);
		PMD(PMD_THRESH, ("%s: set dev thr %s@%s(%s#%d) to 0x%x\n",
		    pmf, PM_DEVICE(dip), ep->pte_thresh[0]))
		PM_UNLOCK_DIP(dip);
		pm_set_device_threshold(dip, ep->pte_thresh[0], PMC_DEV_THRESH);
		if (PM_SCANABLE(dip))
			pm_rescan(dip);
		return;
	}
	for (i = 0; i < comps; i++) {
		cp = PM_CP(dip, i);
		for (j = 0; j < ep->pte_numthresh; j++) {
			PMD(PMD_THRESH, ("%s: set thr %d for %s@%s(%s#%d)[%d] "
			    "to %x\n", pmf, j, PM_DEVICE(dip),
			    i, ep->pte_thresh[j]))
			cp->pmc_comp.pmc_thresh[j + 1] = ep->pte_thresh[j];
		}
		ep++;
	}
	DEVI(dip)->devi_pm_flags &= PMC_THRESH_NONE;
	DEVI(dip)->devi_pm_flags |= PMC_COMP_THRESH;
	PM_UNLOCK_DIP(dip);

	if (PM_SCANABLE(dip))
		pm_rescan(dip);
}

/*
 * Returns true if the threshold specified by rp could be applied to dip
 * (that is, the number of components and transitions are the same)
 */
int
pm_valid_thresh(dev_info_t *dip, pm_thresh_rec_t *rp)
{
	PMD_FUNC(pmf, "valid_thresh")
	int comps, i;
	pm_component_t *cp;
	pm_pte_t *ep;

	if (!PM_GET_PM_INFO(dip) || PM_ISBC(dip)) {
		PMD(PMD_ERROR, ("%s: %s: no pm_info or BC\n", pmf,
		    rp->ptr_physpath))
		return (0);
	}
	/*
	 * Special case: we represent the PM_SET_DEVICE_THRESHOLD case by
	 * an entry with numcomps == 0, (since we don't know how many
	 * components there are in advance).  This is always a valid
	 * spec.
	 */
	if (rp->ptr_numcomps == 0) {
		ASSERT(rp->ptr_entries && rp->ptr_entries->pte_numthresh == 1);
		return (1);
	}
	if (rp->ptr_numcomps != (comps = PM_NUMCMPTS(dip))) {
		PMD(PMD_ERROR, ("%s: comp # mm (dip %d cmd %d) for %s\n",
		    pmf, PM_NUMCMPTS(dip), rp->ptr_numcomps, rp->ptr_physpath))
		return (0);
	}
	ep = rp->ptr_entries;
	for (i = 0; i < comps; i++) {
		cp = PM_CP(dip, i);
		if ((ep + i)->pte_numthresh !=
		    cp->pmc_comp.pmc_numlevels - 1) {
			PMD(PMD_ERROR, ("%s: %s[%d]: thresh=%d, record=%d\n",
			    pmf, rp->ptr_physpath, i,
			    cp->pmc_comp.pmc_numlevels - 1,
			    (ep + i)->pte_numthresh))
			return (0);
		}
	}
	return (1);
}

/*
 * Remove any recorded threshold for device physpath
 * We know there will be at most one.
 */
void
pm_unrecord_threshold(char *physpath)
{
	pm_thresh_rec_t *pptr, *ptr;

	rw_enter(&pm_thresh_rwlock, RW_WRITER);
	for (pptr = NULL, ptr = pm_thresh_head; ptr; ptr = ptr->ptr_next) {
		if (strcmp(physpath, ptr->ptr_physpath) == 0) {
			if (pptr) {
				pptr->ptr_next = ptr->ptr_next;
			} else {
				ASSERT(pm_thresh_head == ptr);
				pm_thresh_head = ptr->ptr_next;
			}
			kmem_free(ptr, ptr->ptr_size);
			break;
		}
		pptr = ptr;
	}
	rw_exit(&pm_thresh_rwlock);
}

/*
 * Discard all recorded thresholds.  We are returning to the default pm state.
 */
void
pm_discard_thresholds(void)
{
	pm_thresh_rec_t *rp;
	rw_enter(&pm_thresh_rwlock, RW_WRITER);
	while (pm_thresh_head) {
		rp = pm_thresh_head;
		pm_thresh_head = rp->ptr_next;
		kmem_free(rp, rp->ptr_size);
	}
	rw_exit(&pm_thresh_rwlock);
}

/*
 * Discard all recorded dependencies.  We are returning to the default pm state.
 */
void
pm_discard_dependencies(void)
{
	pm_pdr_t *rp;
	int i;
	size_t length;

#ifdef DEBUG
	if (pm_debug & PMD_DEP)
		prdeps("Before discard\n");
#endif
	ddi_walk_devs(ddi_root_node(), pm_discard_dep_walk, NULL);

#ifdef DEBUG
	if (pm_debug & PMD_DEP)
		prdeps("After discard\n");
#endif
	while (pm_dep_head) {
		rp = pm_dep_head;
		if (!rp->pdr_isprop) {
			ASSERT(rp->pdr_satisfied == 0);
			ASSERT(pm_unresolved_deps);
			pm_unresolved_deps--;
		} else {
			ASSERT(pm_prop_deps);
			pm_prop_deps--;
		}
		pm_dep_head = rp->pdr_next;
		if (rp->pdr_kept_count)  {
			for (i = 0; i < rp->pdr_kept_count; i++) {
				length = strlen(rp->pdr_kept_paths[i]) + 1;
				kmem_free(rp->pdr_kept_paths[i], length);
			}
			kmem_free(rp->pdr_kept_paths,
			    rp->pdr_kept_count * sizeof (char **));
		}
		kmem_free(rp, rp->pdr_size);
	}
}


static int
pm_discard_dep_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	char *pathbuf;

	if (PM_GET_PM_INFO(dip) == NULL)
		return (DDI_WALK_CONTINUE);
	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);
	pm_free_keeper(pathbuf, 0);
	kmem_free(pathbuf, MAXPATHLEN);
	return (DDI_WALK_CONTINUE);
}

static int
pm_kept_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	char *pathbuf;

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);
	(void) pm_kept(pathbuf);
	kmem_free(pathbuf, MAXPATHLEN);

	return (DDI_WALK_CONTINUE);
}

static int
pm_keeper_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	char *pathbuf;

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);
	(void) pm_keeper(pathbuf);
	kmem_free(pathbuf, MAXPATHLEN);

	return (DDI_WALK_CONTINUE);
}

static char *
pdw_type_decode(int type)
{
	switch (type) {
	case PM_DEP_WK_POWER_ON:
		return ("power on");
	case PM_DEP_WK_POWER_OFF:
		return ("power off");
	case PM_DEP_WK_DETACH:
		return ("detach");
	case PM_DEP_WK_REMOVE_DEP:
		return ("remove dep");
	case PM_DEP_WK_BRINGUP_SELF:
		return ("bringup self");
	case PM_DEP_WK_RECORD_KEEPER:
		return ("add dependent");
	case PM_DEP_WK_RECORD_KEEPER_PROP:
		return ("add dependent property");
	case PM_DEP_WK_KEPT:
		return ("kept");
	case PM_DEP_WK_KEEPER:
		return ("keeper");
	case PM_DEP_WK_ATTACH:
		return ("attach");
	case PM_DEP_WK_CHECK_KEPT:
		return ("check kept");
	case PM_DEP_WK_CPR_SUSPEND:
		return ("suspend");
	case PM_DEP_WK_CPR_RESUME:
		return ("resume");
	default:
		return ("unknown");
	}

}

static void
pm_rele_dep(char *keeper)
{
	PMD_FUNC(pmf, "rele_dep")
	pm_pdr_t *dp;
	char *kept_path = NULL;
	dev_info_t *kept = NULL;
	int count = 0;

	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (strcmp(dp->pdr_keeper, keeper) != 0)
			continue;
		for (count = 0; count < dp->pdr_kept_count; count++) {
			kept_path = dp->pdr_kept_paths[count];
			if (kept_path == NULL)
				continue;
			kept = pm_name_to_dip(kept_path, 1);
			if (kept) {
				PMD(PMD_KEEPS, ("%s: release kept=%s@%s(%s#%d) "
				    "of keeper=%s\n", pmf, PM_DEVICE(kept),
				    keeper))
				ASSERT(DEVI(kept)->devi_pm_kidsupcnt > 0);
				pm_rele_power(kept);
				ddi_release_devi(kept);
			}
		}
	}
}

/*
 * Called when we are just released from direct PM.  Bring ourself up
 * if our keeper is up since dependency is not honored while a kept
 * device is under direct PM.
 */
static void
pm_bring_self_up(char *keptpath)
{
	PMD_FUNC(pmf, "bring_self_up")
	dev_info_t *kept;
	dev_info_t *keeper;
	pm_pdr_t *dp;
	int i, j;
	int up = 0, circ;

	kept = pm_name_to_dip(keptpath, 1);
	if (kept == NULL)
		return;
	PMD(PMD_KEEPS, ("%s: kept=%s@%s(%s#%d)\n", pmf, PM_DEVICE(kept)))
	for (dp = pm_dep_head; dp; dp = dp->pdr_next) {
		if (dp->pdr_kept_count == 0)
			continue;
		for (i = 0; i < dp->pdr_kept_count; i++) {
			if (strcmp(dp->pdr_kept_paths[i], keptpath) != 0)
				continue;
			keeper = pm_name_to_dip(dp->pdr_keeper, 1);
			if (keeper) {
				PMD(PMD_KEEPS, ("%s: keeper=%s@%s(%s#%d)\n",
				    pmf, PM_DEVICE(keeper)))
				PM_LOCK_POWER(keeper, &circ);
				for (j = 0; j < PM_NUMCMPTS(keeper);
				    j++) {
					if (PM_CURPOWER(keeper, j)) {
						PMD(PMD_KEEPS, ("%s: comp="
						    "%d is up\n", pmf, j))
						up++;
					}
				}
				if (up) {
					if (PM_SKBU(kept))
						DEVI(kept)->devi_pm_flags &=
						    ~PMC_SKIP_BRINGUP;
					bring_pmdep_up(kept, 1);
				}
				PM_UNLOCK_POWER(keeper, circ);
				ddi_release_devi(keeper);
			}
		}
	}
	ddi_release_devi(kept);
}

static void
pm_process_dep_request(pm_dep_wk_t *work)
{
	PMD_FUNC(pmf, "dep_req")
	int ret;

	PMD(PMD_DEP, ("%s: work=%s\n", pmf,
	    pdw_type_decode(work->pdw_type)))
	PMD(PMD_DEP, ("%s: keeper=%s, kept=%s\n", pmf,
	    (work->pdw_keeper ? work->pdw_keeper : "NULL"),
	    (work->pdw_kept ? work->pdw_kept : "NULL")))

	switch (work->pdw_type) {
	case PM_DEP_WK_POWER_ON:
		/* Bring up the kept devices and put a hold on them */
		bring_wekeeps_up(work->pdw_keeper);
		break;
	case PM_DEP_WK_POWER_OFF:
		/* Release the kept devices */
		pm_rele_dep(work->pdw_keeper);
		break;
	case PM_DEP_WK_DETACH:
		pm_free_keeps(work->pdw_keeper, work->pdw_pwr);
		break;
	case PM_DEP_WK_REMOVE_DEP:
		pm_discard_dependencies();
		break;
	case PM_DEP_WK_BRINGUP_SELF:
		/*
		 * We deferred satisfying our dependency till now, so satisfy
		 * it again and bring ourselves up.
		 */
		pm_bring_self_up(work->pdw_kept);
		break;
	case PM_DEP_WK_RECORD_KEEPER:
		(void) pm_record_keeper(work->pdw_kept, work->pdw_keeper, 0);
		ddi_walk_devs(ddi_root_node(), pm_kept_walk, NULL);
		ddi_walk_devs(ddi_root_node(), pm_keeper_walk, NULL);
		break;
	case PM_DEP_WK_RECORD_KEEPER_PROP:
		(void) pm_record_keeper(work->pdw_kept, work->pdw_keeper, 1);
		ddi_walk_devs(ddi_root_node(), pm_keeper_walk, NULL);
		ddi_walk_devs(ddi_root_node(), pm_kept_walk, NULL);
		break;
	case PM_DEP_WK_KEPT:
		ret = pm_kept(work->pdw_kept);
		PMD(PMD_DEP, ("%s: PM_DEP_WK_KEPT: pm_kept returns %d\n", pmf,
		    ret))
		break;
	case PM_DEP_WK_KEEPER:
		ret = pm_keeper(work->pdw_keeper);
		PMD(PMD_DEP, ("%s: PM_DEP_WK_KEEPER: pm_keeper returns %d\n",
		    pmf, ret))
		break;
	case PM_DEP_WK_ATTACH:
		ret = pm_keeper(work->pdw_keeper);
		PMD(PMD_DEP, ("%s: PM_DEP_WK_ATTACH: pm_keeper returns %d\n",
		    pmf, ret))
		ret = pm_kept(work->pdw_kept);
		PMD(PMD_DEP, ("%s: PM_DEP_WK_ATTACH: pm_kept returns %d\n",
		    pmf, ret))
		break;
	case PM_DEP_WK_CHECK_KEPT:
		ret = pm_is_kept(work->pdw_kept);
		PMD(PMD_DEP, ("%s: PM_DEP_WK_CHECK_KEPT: kept=%s, ret=%d\n",
		    pmf, work->pdw_kept, ret))
		break;
	case PM_DEP_WK_CPR_SUSPEND:
		pm_discard_dependencies();
		break;
	case PM_DEP_WK_CPR_RESUME:
		ddi_walk_devs(ddi_root_node(), pm_kept_walk, NULL);
		ddi_walk_devs(ddi_root_node(), pm_keeper_walk, NULL);
		break;
	default:
		ASSERT(0);
		break;
	}
	/*
	 * Free the work structure if the requester is not waiting
	 * Otherwise it is the requester's responsiblity to free it.
	 */
	if (!work->pdw_wait) {
		if (work->pdw_keeper)
			kmem_free(work->pdw_keeper,
			    strlen(work->pdw_keeper) + 1);
		if (work->pdw_kept)
			kmem_free(work->pdw_kept, strlen(work->pdw_kept) + 1);
		kmem_free(work, sizeof (pm_dep_wk_t));
	} else {
		/*
		 * Notify requester if it is waiting for it.
		 */
		work->pdw_ret = ret;
		work->pdw_done = 1;
		cv_signal(&work->pdw_cv);
	}
}

/*
 * Process PM dependency requests.
 */
static void
pm_dep_thread(void)
{
	pm_dep_wk_t *work;
	callb_cpr_t cprinfo;

	CALLB_CPR_INIT(&cprinfo, &pm_dep_thread_lock, callb_generic_cpr,
	    "pm_dep_thread");
	for (;;) {
		mutex_enter(&pm_dep_thread_lock);
		if (pm_dep_thread_workq == NULL) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&pm_dep_thread_cv, &pm_dep_thread_lock);
			CALLB_CPR_SAFE_END(&cprinfo, &pm_dep_thread_lock);
		}
		work = pm_dep_thread_workq;
		pm_dep_thread_workq = work->pdw_next;
		if (pm_dep_thread_tail == work)
			pm_dep_thread_tail = work->pdw_next;
		mutex_exit(&pm_dep_thread_lock);
		pm_process_dep_request(work);

	}
	/*NOTREACHED*/
}

/*
 * Set the power level of the indicated device to unknown (if it is not a
 * backwards compatible device), as it has just been resumed, and it won't
 * know if the power was removed or not. Adjust parent's kidsupcnt if necessary.
 */
void
pm_forget_power_level(dev_info_t *dip)
{
	dev_info_t *pdip = ddi_get_parent(dip);
	int i, count = 0;

	if (!PM_ISBC(dip)) {
		for (i = 0; i < PM_NUMCMPTS(dip); i++)
			count += (PM_CURPOWER(dip, i) == 0);

		if (count && pdip && !PM_WANTS_NOTIFICATION(pdip))
			e_pm_hold_rele_power(pdip, count);

		/*
		 * Count this as a power cycle if we care
		 */
		if (DEVI(dip)->devi_pm_volpmd &&
		    PM_CP(dip, 0)->pmc_cur_pwr == 0)
			DEVI(dip)->devi_pm_volpmd = 0;
		for (i = 0; i < PM_NUMCMPTS(dip); i++)
			e_pm_set_cur_pwr(dip, PM_CP(dip, i), PM_LEVEL_UNKNOWN);
	}
}

/*
 * This function advises the caller whether it should make a power-off
 * transition at this time or not.  If the transition is not advised
 * at this time, the time that the next power-off transition can
 * be made from now is returned through "intervalp" pointer.
 * This function returns:
 *
 *  1  power-off advised
 *  0  power-off not advised, intervalp will point to seconds from
 *	  now that a power-off is advised.  If it is passed the number
 *	  of years that policy specifies the device should last,
 *	  a large number is returned as the time interval.
 *  -1  error
 */
int
pm_trans_check(struct pm_trans_data *datap, time_t *intervalp)
{
	PMD_FUNC(pmf, "pm_trans_check")
	char dbuf[DC_SCSI_MFR_LEN];
	struct pm_scsi_cycles *scp;
	int service_years, service_weeks, full_years;
	time_t now, service_seconds, tdiff;
	time_t within_year, when_allowed;
	char *ptr;
	int lower_bound_cycles, upper_bound_cycles, cycles_allowed;
	int cycles_diff, cycles_over;
	struct pm_smart_count *smart_p;

	if (datap == NULL) {
		PMD(PMD_TCHECK, ("%s: NULL data pointer!\n", pmf))
		return (-1);
	}

	if (datap->format == DC_SCSI_FORMAT) {
		/*
		 * Power cycles of the scsi drives are distributed
		 * over 5 years with the following percentage ratio:
		 *
		 *	30%, 25%, 20%, 15%, and 10%
		 *
		 * The power cycle quota for each year is distributed
		 * linearly through out the year.  The equation for
		 * determining the expected cycles is:
		 *
		 *	e = a * (n / y)
		 *
		 * e = expected cycles
		 * a = allocated cycles for this year
		 * n = number of seconds since beginning of this year
		 * y = number of seconds in a year
		 *
		 * Note that beginning of the year starts the day that
		 * the drive has been put on service.
		 *
		 * If the drive has passed its expected cycles, we
		 * can determine when it can start to power cycle
		 * again to keep it on track to meet the 5-year
		 * life expectancy.  The equation for determining
		 * when to power cycle is:
		 *
		 *	w = y * (c / a)
		 *
		 * w = when it can power cycle again
		 * y = number of seconds in a year
		 * c = current number of cycles
		 * a = allocated cycles for the year
		 *
		 */
		char pcnt[DC_SCSI_NPY] = { 30, 55, 75, 90, 100 };

		scp = &datap->un.scsi_cycles;
		PMD(PMD_TCHECK, ("%s: format=%d, lifemax=%d, ncycles=%d, "
		    "svc_date=%s, svc_flag=%d\n", pmf, datap->format,
		    scp->lifemax, scp->ncycles, scp->svc_date, scp->flag))
		if (scp->ncycles < 0 || scp->flag != 0) {
			PMD(PMD_TCHECK, ("%s: ncycles < 0 || flag != 0\n", pmf))
			return (-1);
		}

		if (scp->ncycles > scp->lifemax) {
			*intervalp = (LONG_MAX / hz);
			return (0);
		}

		/*
		 * convert service date to time_t
		 */
		bcopy(scp->svc_date, dbuf, DC_SCSI_YEAR_LEN);
		dbuf[DC_SCSI_YEAR_LEN] = '\0';
		ptr = dbuf;
		service_years = stoi(&ptr) - EPOCH_YEAR;
		bcopy(&scp->svc_date[DC_SCSI_YEAR_LEN], dbuf,
		    DC_SCSI_WEEK_LEN);
		dbuf[DC_SCSI_WEEK_LEN] = '\0';

		/*
		 * scsi standard does not specify WW data,
		 * could be (00-51) or (01-52)
		 */
		ptr = dbuf;
		service_weeks = stoi(&ptr);
		if (service_years < 0 ||
		    service_weeks < 0 || service_weeks > 52) {
			PMD(PMD_TCHECK, ("%s: service year %d and week %d\n",
			    pmf, service_years, service_weeks))
			return (-1);
		}

		/*
		 * calculate service date in seconds-since-epoch,
		 * adding one day for each leap-year.
		 *
		 * (years-since-epoch + 2) fixes integer truncation,
		 * example: (8) leap-years during [1972, 2000]
		 * (2000 - 1970) = 30;  and  (30 + 2) / 4 = 8;
		 */
		service_seconds = (service_years * DC_SPY) +
		    (service_weeks * DC_SPW) +
		    (((service_years + 2) / 4) * DC_SPD);

		now = gethrestime_sec();
		/*
		 * since the granularity of 'svc_date' is day not second,
		 * 'now' should be rounded up to full day.
		 */
		now = ((now + DC_SPD -1) / DC_SPD) * DC_SPD;
		if (service_seconds > now) {
			PMD(PMD_TCHECK, ("%s: service date (%ld) later "
			    "than now (%ld)!\n", pmf, service_seconds, now))
			return (-1);
		}

		tdiff = now - service_seconds;
		PMD(PMD_TCHECK, ("%s: age is %ld sec\n", pmf, tdiff))

		/*
		 * NOTE - Leap years are not considered in the calculations
		 * below.
		 */
		full_years = (tdiff / DC_SPY);
		if ((full_years >= DC_SCSI_NPY) &&
		    (scp->ncycles <= scp->lifemax))
			return (1);

		/*
		 * Determine what is the normal cycle usage for the
		 * device at the beginning and the end of this year.
		 */
		lower_bound_cycles = (!full_years) ? 0 :
		    ((scp->lifemax * pcnt[full_years - 1]) / 100);
		upper_bound_cycles = (scp->lifemax * pcnt[full_years]) / 100;

		if (scp->ncycles <= lower_bound_cycles)
			return (1);

		/*
		 * The linear slope that determines how many cycles
		 * are allowed this year is number of seconds
		 * passed this year over total number of seconds in a year.
		 */
		cycles_diff = (upper_bound_cycles - lower_bound_cycles);
		within_year = (tdiff % DC_SPY);
		cycles_allowed = lower_bound_cycles +
		    (((uint64_t)cycles_diff * (uint64_t)within_year) / DC_SPY);
		PMD(PMD_TCHECK, ("%s: lived %d yrs and %ld secs\n", pmf,
		    full_years, within_year))
		PMD(PMD_TCHECK, ("%s: # of cycles allowed %d\n", pmf,
		    cycles_allowed))

		if (scp->ncycles <= cycles_allowed)
			return (1);

		/*
		 * The transition is not advised now but we can
		 * determine when the next transition can be made.
		 *
		 * Depending on how many cycles the device has been
		 * over-used, we may need to skip years with
		 * different percentage quota in order to determine
		 * when the next transition can be made.
		 */
		cycles_over = (scp->ncycles - lower_bound_cycles);
		while (cycles_over > cycles_diff) {
			full_years++;
			if (full_years >= DC_SCSI_NPY) {
				*intervalp = (LONG_MAX / hz);
				return (0);
			}
			cycles_over -= cycles_diff;
			lower_bound_cycles = upper_bound_cycles;
			upper_bound_cycles =
			    (scp->lifemax * pcnt[full_years]) / 100;
			cycles_diff = (upper_bound_cycles - lower_bound_cycles);
		}

		/*
		 * The linear slope that determines when the next transition
		 * can be made is the relative position of used cycles within a
		 * year over total number of cycles within that year.
		 */
		when_allowed = service_seconds + (full_years * DC_SPY) +
		    (((uint64_t)DC_SPY * (uint64_t)cycles_over) / cycles_diff);
		*intervalp = (when_allowed - now);
		if (*intervalp > (LONG_MAX / hz))
			*intervalp = (LONG_MAX / hz);
		PMD(PMD_TCHECK, ("%s: no cycle is allowed in %ld secs\n", pmf,
		    *intervalp))
		return (0);
	} else if (datap->format == DC_SMART_FORMAT) {
		/*
		 * power cycles of SATA disks are reported from SMART
		 * attributes.
		 */
		smart_p = &datap->un.smart_count;
		if (smart_p->consumed >= smart_p->allowed) {
			*intervalp = (LONG_MAX / hz);
			PMD(PMD_TCHECK, ("%s: exceeded lifemax cycles.\n", pmf))
			return (0);
		} else
			return (1);
	}

	PMD(PMD_TCHECK, ("%s: unknown format!\n", pmf))
	return (-1);
}

/*
 * Nexus drivers call into pm framework to indicate which child driver is about
 * to be installed.  In some platforms, ppm may need to configure the hardware
 * for successful installation of a driver.
 */
int
pm_init_child(dev_info_t *dip)
{
	power_req_t power_req;

	ASSERT(ddi_binding_name(dip));
	ASSERT(ddi_get_name_addr(dip));
	pm_ppm_claim(dip);
	if (pm_ppm_claimed(dip)) {	/* if ppm driver claims the node */
		power_req.request_type = PMR_PPM_INIT_CHILD;
		power_req.req.ppm_config_req.who = dip;
		ASSERT(PPM(dip) != NULL);
		return (pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER, &power_req,
		    NULL));
	} else {
#ifdef DEBUG
		/* pass it to the default handler so we can debug things */
		power_req.request_type = PMR_PPM_INIT_CHILD;
		power_req.req.ppm_config_req.who = dip;
		(void) pm_ctlops(NULL, dip,
		    DDI_CTLOPS_POWER, &power_req, NULL);
#endif
	}
	return (DDI_SUCCESS);
}

/*
 * Bring parent of a node that is about to be probed up to full power, and
 * arrange for it to stay up until pm_post_probe() or pm_post_attach() decide
 * it is time to let it go down again
 */
void
pm_pre_probe(dev_info_t *dip, pm_ppm_cookie_t *cp)
{
	int result;
	power_req_t power_req;

	bzero(cp, sizeof (*cp));
	cp->ppc_dip = dip;

	pm_ppm_claim(dip);
	if (pm_ppm_claimed(dip)) {	/* if ppm driver claims the node */
		power_req.request_type = PMR_PPM_PRE_PROBE;
		power_req.req.ppm_config_req.who = dip;
		ASSERT(PPM(dip) != NULL);
		(void) pm_ctlops(PPM(dip), dip,
		    DDI_CTLOPS_POWER, &power_req, &result);
		cp->ppc_ppm = PPM(dip);
	} else {
#ifdef DEBUG
		/* pass it to the default handler so we can debug things */
		power_req.request_type = PMR_PPM_PRE_PROBE;
		power_req.req.ppm_config_req.who = dip;
		(void) pm_ctlops(NULL, dip,
		    DDI_CTLOPS_POWER, &power_req, &result);
#endif
		cp->ppc_ppm = NULL;
	}
}

int
pm_pre_config(dev_info_t *dip, char *devnm)
{
	PMD_FUNC(pmf, "pre_config")
	int ret;

	if (MDI_VHCI(dip)) {
		PMD(PMD_SET, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
		ret = mdi_power(dip, MDI_PM_PRE_CONFIG, NULL, devnm, 0);
		return (ret == MDI_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
	} else if (!PM_GET_PM_INFO(dip))
		return (DDI_SUCCESS);

	PMD(PMD_SET, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	pm_hold_power(dip);
	ret = pm_all_to_normal(dip, PM_CANBLOCK_BLOCK);
	if (ret != DDI_SUCCESS)
		pm_rele_power(dip);
	return (ret);
}

/*
 * This routine is called by devfs during its walk to unconfigue a node.
 * If the call is due to auto mod_unloads and the dip is not at its
 * full power, we return DDI_FAILURE to terminate the walk, otherwise
 * return DDI_SUCCESS.
 */
int
pm_pre_unconfig(dev_info_t *dip, int flags, int *held, char *devnm)
{
	PMD_FUNC(pmf, "pre_unconfig")
	int ret;

	if (MDI_VHCI(dip)) {
		PMD(PMD_SET, ("%s: %s@%s(%s#%d), flags=%x\n", pmf,
		    PM_DEVICE(dip), flags))
		ret = mdi_power(dip, MDI_PM_PRE_UNCONFIG, held, devnm, flags);
		return (ret == MDI_SUCCESS ? DDI_SUCCESS : DDI_FAILURE);
	} else if (!PM_GET_PM_INFO(dip))
		return (DDI_SUCCESS);

	PMD(PMD_SET, ("%s: %s@%s(%s#%d), flags=%x\n", pmf, PM_DEVICE(dip),
	    flags))
	*held = 0;

	/*
	 * If the dip is a leaf node, don't power it up.
	 */
	if (!ddi_get_child(dip))
		return (DDI_SUCCESS);

	/*
	 * Do not power up the node if it is called due to auto-modunload.
	 */
	if ((flags & NDI_AUTODETACH) && !pm_all_at_normal(dip))
		return (DDI_FAILURE);

	pm_hold_power(dip);
	*held = 1;
	ret = pm_all_to_normal(dip, PM_CANBLOCK_BLOCK);
	if (ret != DDI_SUCCESS) {
		pm_rele_power(dip);
		*held = 0;
	}
	return (ret);
}

/*
 * Notify ppm of attach action.  Parent is already held at full power by
 * probe action.
 */
void
pm_pre_attach(dev_info_t *dip, pm_ppm_cookie_t *cp, ddi_attach_cmd_t cmd)
{
	static char *me = "pm_pre_attach";
	power_req_t power_req;
	int result;

	/*
	 * Initialize and fill in the PPM cookie
	 */
	bzero(cp, sizeof (*cp));
	cp->ppc_cmd = (int)cmd;
	cp->ppc_ppm = PPM(dip);
	cp->ppc_dip = dip;

	/*
	 * DDI_ATTACH and DDI_RESUME cmds need to call platform specific
	 * Power Management stuff. DDI_RESUME also has to purge it's
	 * powerlevel information.
	 */
	switch (cmd) {
	case DDI_ATTACH:
		if (cp->ppc_ppm) {	/* if ppm driver claims the node */
			power_req.request_type = PMR_PPM_PRE_ATTACH;
			power_req.req.ppm_config_req.who = dip;
			ASSERT(PPM(dip));
			(void) pm_ctlops(cp->ppc_ppm, dip, DDI_CTLOPS_POWER,
			    &power_req, &result);
		}
#ifdef DEBUG
		else {
			power_req.request_type = PMR_PPM_PRE_ATTACH;
			power_req.req.ppm_config_req.who = dip;
			(void) pm_ctlops(NULL, dip,
			    DDI_CTLOPS_POWER, &power_req, &result);
		}
#endif
		break;
	case DDI_RESUME:
		pm_forget_power_level(dip);

		if (cp->ppc_ppm) {	/* if ppm driver claims the node */
			power_req.request_type = PMR_PPM_PRE_RESUME;
			power_req.req.resume_req.who = cp->ppc_dip;
			power_req.req.resume_req.cmd =
			    (ddi_attach_cmd_t)cp->ppc_cmd;
			ASSERT(PPM(cp->ppc_dip) == cp->ppc_ppm);
			(void) pm_ctlops(cp->ppc_ppm, cp->ppc_dip,
			    DDI_CTLOPS_POWER, &power_req, &result);
		}
#ifdef DEBUG
		else {
			power_req.request_type = PMR_PPM_PRE_RESUME;
			power_req.req.resume_req.who = cp->ppc_dip;
			power_req.req.resume_req.cmd =
			    (ddi_attach_cmd_t)cp->ppc_cmd;
			(void) pm_ctlops(NULL, cp->ppc_dip,
			    DDI_CTLOPS_POWER, &power_req, &result);
		}
#endif
		break;

	case DDI_PM_RESUME:
		break;

	default:
		panic(me);
	}
}

/*
 * Nexus drivers call into pm framework to indicate which child driver is
 * being uninstalled.  In some platforms, ppm may need to reconfigure the
 * hardware since the device driver is no longer installed.
 */
int
pm_uninit_child(dev_info_t *dip)
{
	power_req_t power_req;

	ASSERT(ddi_binding_name(dip));
	ASSERT(ddi_get_name_addr(dip));
	pm_ppm_claim(dip);
	if (pm_ppm_claimed(dip)) {	/* if ppm driver claims the node */
		power_req.request_type = PMR_PPM_UNINIT_CHILD;
		power_req.req.ppm_config_req.who = dip;
		ASSERT(PPM(dip));
		return (pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER, &power_req,
		    NULL));
	} else {
#ifdef DEBUG
		/* pass it to the default handler so we can debug things */
		power_req.request_type = PMR_PPM_UNINIT_CHILD;
		power_req.req.ppm_config_req.who = dip;
		(void) pm_ctlops(NULL, dip, DDI_CTLOPS_POWER, &power_req, NULL);
#endif
	}
	return (DDI_SUCCESS);
}
/*
 * Decrement kidsupcnt so scan can turn the parent back off if it is idle
 * Also notify ppm of result of probe if there is a ppm that cares
 */
void
pm_post_probe(pm_ppm_cookie_t *cp, int ret, int probe_failed)
{
	_NOTE(ARGUNUSED(probe_failed))
	int result;
	power_req_t power_req;

	if (cp->ppc_ppm) {	/* if ppm driver claims the node */
		power_req.request_type = PMR_PPM_POST_PROBE;
		power_req.req.ppm_config_req.who = cp->ppc_dip;
		power_req.req.ppm_config_req.result = ret;
		ASSERT(PPM(cp->ppc_dip) == cp->ppc_ppm);
		(void) pm_ctlops(cp->ppc_ppm, cp->ppc_dip, DDI_CTLOPS_POWER,
		    &power_req, &result);
	}
#ifdef DEBUG
	else {
		power_req.request_type = PMR_PPM_POST_PROBE;
		power_req.req.ppm_config_req.who = cp->ppc_dip;
		power_req.req.ppm_config_req.result = ret;
		(void) pm_ctlops(NULL, cp->ppc_dip, DDI_CTLOPS_POWER,
		    &power_req, &result);
	}
#endif
}

void
pm_post_config(dev_info_t *dip, char *devnm)
{
	PMD_FUNC(pmf, "post_config")

	if (MDI_VHCI(dip)) {
		PMD(PMD_SET, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
		(void) mdi_power(dip, MDI_PM_POST_CONFIG, NULL, devnm, 0);
		return;
	} else if (!PM_GET_PM_INFO(dip))
		return;

	PMD(PMD_SET, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	pm_rele_power(dip);
}

void
pm_post_unconfig(dev_info_t *dip, int held, char *devnm)
{
	PMD_FUNC(pmf, "post_unconfig")

	if (MDI_VHCI(dip)) {
		PMD(PMD_SET, ("%s: %s@%s(%s#%d), held = %d\n", pmf,
		    PM_DEVICE(dip), held))
		(void) mdi_power(dip, MDI_PM_POST_UNCONFIG, &held, devnm, 0);
		return;
	} else if (!PM_GET_PM_INFO(dip))
		return;

	PMD(PMD_SET, ("%s: %s@%s(%s#%d), held = %d\n", pmf, PM_DEVICE(dip),
	    held))
	if (!held)
		return;
	/*
	 * We have held power in pre_unconfig, release it here.
	 */
	pm_rele_power(dip);
}

/*
 * Notify ppm of result of attach if there is a ppm that cares
 */
void
pm_post_attach(pm_ppm_cookie_t *cp, int ret)
{
	int result;
	power_req_t power_req;
	dev_info_t	*dip;

	if (cp->ppc_cmd != DDI_ATTACH)
		return;

	dip = cp->ppc_dip;

	if (ret == DDI_SUCCESS) {
		/*
		 * Attach succeeded, so proceed to doing post-attach pm tasks
		 */
		if (PM_GET_PM_INFO(dip) == NULL)
			(void) pm_start(dip);
	} else {
		/*
		 * Attach may have got pm started before failing
		 */
		pm_stop(dip);
	}

	if (cp->ppc_ppm) {	/* if ppm driver claims the node */
		power_req.request_type = PMR_PPM_POST_ATTACH;
		power_req.req.ppm_config_req.who = cp->ppc_dip;
		power_req.req.ppm_config_req.result = ret;
		ASSERT(PPM(cp->ppc_dip) == cp->ppc_ppm);
		(void) pm_ctlops(cp->ppc_ppm, cp->ppc_dip,
		    DDI_CTLOPS_POWER, &power_req, &result);
	}
#ifdef DEBUG
	else {
		power_req.request_type = PMR_PPM_POST_ATTACH;
		power_req.req.ppm_config_req.who = cp->ppc_dip;
		power_req.req.ppm_config_req.result = ret;
		(void) pm_ctlops(NULL, cp->ppc_dip,
		    DDI_CTLOPS_POWER, &power_req, &result);
	}
#endif
}

/*
 * Notify ppm of attach action.  Parent is already held at full power by
 * probe action.
 */
void
pm_pre_detach(dev_info_t *dip, ddi_detach_cmd_t cmd, pm_ppm_cookie_t *cp)
{
	int result;
	power_req_t power_req;

	bzero(cp, sizeof (*cp));
	cp->ppc_dip = dip;
	cp->ppc_cmd = (int)cmd;

	switch (cmd) {
	case DDI_DETACH:
		pm_detaching(dip);		/* suspend pm while detaching */
		if (pm_ppm_claimed(dip)) {	/* if ppm driver claims node */
			power_req.request_type = PMR_PPM_PRE_DETACH;
			power_req.req.ppm_config_req.who = dip;
			ASSERT(PPM(dip));
			(void) pm_ctlops(PPM(dip), dip, DDI_CTLOPS_POWER,
			    &power_req, &result);
			cp->ppc_ppm = PPM(dip);
		} else {
#ifdef DEBUG
			/* pass to the default handler so we can debug things */
			power_req.request_type = PMR_PPM_PRE_DETACH;
			power_req.req.ppm_config_req.who = dip;
			(void) pm_ctlops(NULL, dip,
			    DDI_CTLOPS_POWER, &power_req, &result);
#endif
			cp->ppc_ppm = NULL;
		}
		break;

	default:
		break;
	}
}

/*
 * Dip is either a leaf node that exported "no-involuntary-power-cycles" prop.,
 * (if devi_pm_noinvol count is 0) or an ancestor of such a node.  We need to
 * make an entry to record the details, which includes certain flag settings.
 */
static void
pm_record_invol_path(char *path, int flags, int noinvolpm, int volpmd,
    int wasvolpmd, major_t major)
{
	PMD_FUNC(pmf, "record_invol_path")
	major_t pm_path_to_major(char *);
	size_t plen;
	pm_noinvol_t *ip, *np, *pp;
	pp = NULL;

	plen = strlen(path) + 1;
	np = kmem_zalloc(sizeof (*np), KM_SLEEP);
	np->ni_size = plen;
	np->ni_path = kmem_alloc(plen, KM_SLEEP);
	np->ni_noinvolpm = noinvolpm;
	np->ni_volpmd = volpmd;
	np->ni_wasvolpmd = wasvolpmd;
	np->ni_flags = flags;
	(void) strcpy(np->ni_path, path);
	/*
	 * If we haven't actually seen the node attached, it is hard to figure
	 * out its major.  If we could hold the node by path, we would be much
	 * happier here.
	 */
	if (major == DDI_MAJOR_T_NONE) {
		np->ni_major = pm_path_to_major(path);
	} else {
		np->ni_major = major;
	}
	rw_enter(&pm_noinvol_rwlock, RW_WRITER);
	for (ip = pm_noinvol_head; ip; pp = ip, ip = ip->ni_next) {
		int comp = strcmp(path, ip->ni_path);
		if (comp < 0) {
			PMD(PMD_NOINVOL, ("%s: %s insert before %s\n",
			    pmf, path, ip->ni_path))
			/* insert before current entry */
			np->ni_next = ip;
			if (pp) {
				pp->ni_next = np;
			} else {
				pm_noinvol_head = np;
			}
			rw_exit(&pm_noinvol_rwlock);
#ifdef DEBUG
			if (pm_debug & PMD_NOINVOL)
				pr_noinvol("record_invol_path exit0");
#endif
			return;
		} else if (comp == 0) {
			panic("%s already in pm_noinvol list", path);
		}
	}
	/*
	 * If we did not find an entry in the list that this should go before,
	 * then it must go at the end
	 */
	if (pp) {
		PMD(PMD_NOINVOL, ("%s: %s append after %s\n", pmf, path,
		    pp->ni_path))
		ASSERT(pp->ni_next == 0);
		pp->ni_next = np;
	} else {
		PMD(PMD_NOINVOL, ("%s: %s added to end-of-list\n", pmf, path))
		ASSERT(!pm_noinvol_head);
		pm_noinvol_head = np;
	}
	rw_exit(&pm_noinvol_rwlock);
#ifdef DEBUG
	if (pm_debug & PMD_NOINVOL)
		pr_noinvol("record_invol_path exit");
#endif
}

void
pm_record_invol(dev_info_t *dip)
{
	char *pathbuf;
	int pm_all_components_off(dev_info_t *);
	int volpmd = (PM_NUMCMPTS(dip) > 0) && pm_all_components_off(dip);

	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);

	pm_record_invol_path(pathbuf, (DEVI(dip)->devi_pm_flags &
	    (PMC_NO_INVOL | PMC_CONSOLE_FB)), DEVI(dip)->devi_pm_noinvolpm,
	    DEVI(dip)->devi_pm_volpmd, volpmd, PM_MAJOR(dip));

	/*
	 * If this child's detach will be holding up its ancestors, then we
	 * allow for an exception to that if all children of this type have
	 * gone down voluntarily.
	 * Now walk down the tree incrementing devi_pm_noinvolpm
	 */
	(void) pm_noinvol_update(PM_BP_NOINVOL_DETACH, 0, volpmd, pathbuf,
	    dip);
	kmem_free(pathbuf, MAXPATHLEN);
}

void
pm_post_detach(pm_ppm_cookie_t *cp, int ret)
{
	dev_info_t *dip = cp->ppc_dip;
	int result;
	power_req_t power_req;

	switch (cp->ppc_cmd) {
	case DDI_DETACH:
		if (cp->ppc_ppm) {	/* if ppm driver claims the node */
			power_req.request_type = PMR_PPM_POST_DETACH;
			power_req.req.ppm_config_req.who = cp->ppc_dip;
			power_req.req.ppm_config_req.result = ret;
			ASSERT(PPM(cp->ppc_dip) == cp->ppc_ppm);
			(void) pm_ctlops(cp->ppc_ppm, cp->ppc_dip,
			    DDI_CTLOPS_POWER, &power_req, &result);
		}
#ifdef DEBUG
		else {
			power_req.request_type = PMR_PPM_POST_DETACH;
			power_req.req.ppm_config_req.who = cp->ppc_dip;
			power_req.req.ppm_config_req.result = ret;
			(void) pm_ctlops(NULL, cp->ppc_dip,
			    DDI_CTLOPS_POWER, &power_req, &result);
		}
#endif
		if (ret == DDI_SUCCESS) {
			/*
			 * For hotplug detach we assume it is *really* gone
			 */
			if (cp->ppc_cmd == DDI_DETACH &&
			    ((DEVI(dip)->devi_pm_flags &
			    (PMC_NO_INVOL | PMC_CONSOLE_FB)) ||
			    DEVI(dip)->devi_pm_noinvolpm))
				pm_record_invol(dip);
			DEVI(dip)->devi_pm_flags &=
			    ~(PMC_NO_INVOL | PMC_NOINVOL_DONE);

			/*
			 * If console fb is detaching, then we don't need to
			 * worry any more about it going off (pm_detaching has
			 * brought up all components)
			 */
			if (PM_IS_CFB(dip)) {
				mutex_enter(&pm_cfb_lock);
				ASSERT(cfb_dip_detaching);
				ASSERT(cfb_dip == NULL);
				ASSERT(pm_cfb_comps_off == 0);
				cfb_dip_detaching = NULL;
				mutex_exit(&pm_cfb_lock);
			}
			pm_stop(dip);	/* make it permanent */
		} else {
			if (PM_IS_CFB(dip)) {
				mutex_enter(&pm_cfb_lock);
				ASSERT(cfb_dip_detaching);
				ASSERT(cfb_dip == NULL);
				ASSERT(pm_cfb_comps_off == 0);
				cfb_dip = cfb_dip_detaching;
				cfb_dip_detaching = NULL;
				mutex_exit(&pm_cfb_lock);
			}
			pm_detach_failed(dip);	/* resume power management */
		}
		break;
	case DDI_PM_SUSPEND:
		break;
	case DDI_SUSPEND:
		break;				/* legal, but nothing to do */
	default:
#ifdef DEBUG
		panic("pm_post_detach: unrecognized cmd %d for detach",
		    cp->ppc_cmd);
		/*NOTREACHED*/
#else
		break;
#endif
	}
}

/*
 * Called after vfs_mountroot has got the clock started to fix up timestamps
 * that were set when root bush drivers attached.  hresttime was 0 then, so the
 * devices look busy but have a 0 busycnt
 */
int
pm_adjust_timestamps(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	pm_info_t *info = PM_GET_PM_INFO(dip);
	struct pm_component *cp;
	int i;

	if (!info)
		return (DDI_WALK_CONTINUE);
	PM_LOCK_BUSY(dip);
	for (i = 0; i < PM_NUMCMPTS(dip); i++) {
		cp = PM_CP(dip, i);
		if (cp->pmc_timestamp == 0 && cp->pmc_busycount == 0)
			cp->pmc_timestamp = gethrestime_sec();
	}
	PM_UNLOCK_BUSY(dip);
	return (DDI_WALK_CONTINUE);
}

/*
 * Called at attach time to see if the device being attached has a record in
 * the no involuntary power cycles list.  If so, we do some bookkeeping on the
 * parents and set a flag in the dip
 */
void
pm_noinvol_specd(dev_info_t *dip)
{
	PMD_FUNC(pmf, "noinvol_specd")
	char *pathbuf;
	pm_noinvol_t *ip, *pp = NULL;
	int wasvolpmd;
	int found = 0;

	if (DEVI(dip)->devi_pm_flags & PMC_NOINVOL_DONE)
		return;
	DEVI(dip)->devi_pm_flags |=  PMC_NOINVOL_DONE;
	pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, pathbuf);

	PM_LOCK_DIP(dip);
	DEVI(dip)->devi_pm_volpmd = 0;
	DEVI(dip)->devi_pm_noinvolpm = 0;
	rw_enter(&pm_noinvol_rwlock, RW_READER);
	for (ip = pm_noinvol_head; ip; pp = ip, ip = ip->ni_next) {
		PMD(PMD_NOINVOL, ("%s: comparing '%s' to '%s'\n",
		    pmf, pathbuf, ip->ni_path))
		if (strcmp(pathbuf, ip->ni_path) == 0) {
			found++;
			break;
		}
	}
	rw_exit(&pm_noinvol_rwlock);
	if (!found) {
		PM_UNLOCK_DIP(dip);
		kmem_free(pathbuf, MAXPATHLEN);
		return;
	}
	rw_enter(&pm_noinvol_rwlock, RW_WRITER);
	pp = NULL;
	for (ip = pm_noinvol_head; ip; pp = ip, ip = ip->ni_next) {
		PMD(PMD_NOINVOL, ("%s: comparing '%s' to '%s'\n",
		    pmf, pathbuf, ip->ni_path))
		if (strcmp(pathbuf, ip->ni_path) == 0) {
			ip->ni_flags &= ~PMC_DRIVER_REMOVED;
			DEVI(dip)->devi_pm_flags |= ip->ni_flags;
			/*
			 * Handle special case of console fb
			 */
			if (PM_IS_CFB(dip)) {
				mutex_enter(&pm_cfb_lock);
				cfb_dip = dip;
				PMD(PMD_CFB, ("%s: %s@%s(%s#%d) setting "
				    "cfb_dip\n", pmf, PM_DEVICE(dip)))
				mutex_exit(&pm_cfb_lock);
			}
			DEVI(dip)->devi_pm_noinvolpm = ip->ni_noinvolpm;
			ASSERT((DEVI(dip)->devi_pm_flags &
			    (PMC_NO_INVOL | PMC_CONSOLE_FB)) ||
			    DEVI(dip)->devi_pm_noinvolpm);
			DEVI(dip)->devi_pm_volpmd = ip->ni_volpmd;
			PMD(PMD_NOINVOL, ("%s: noinvol=%d, volpmd=%d, "
			    "wasvolpmd=%d, flags=%x, path=%s\n", pmf,
			    ip->ni_noinvolpm, ip->ni_volpmd,
			    ip->ni_wasvolpmd, ip->ni_flags, ip->ni_path))
			/*
			 * free the entry in hopes the list will now be empty
			 * and we won't have to search it any more until the
			 * device detaches
			 */
			if (pp) {
				PMD(PMD_NOINVOL, ("%s: free %s, prev %s\n",
				    pmf, ip->ni_path, pp->ni_path))
				pp->ni_next = ip->ni_next;
			} else {
				PMD(PMD_NOINVOL, ("%s: free %s head\n",
				    pmf, ip->ni_path))
				ASSERT(pm_noinvol_head == ip);
				pm_noinvol_head = ip->ni_next;
			}
			PM_UNLOCK_DIP(dip);
			wasvolpmd = ip->ni_wasvolpmd;
			rw_exit(&pm_noinvol_rwlock);
			kmem_free(ip->ni_path, ip->ni_size);
			kmem_free(ip, sizeof (*ip));
			/*
			 * Now walk up the tree decrementing devi_pm_noinvolpm
			 * (and volpmd if appropriate)
			 */
			(void) pm_noinvol_update(PM_BP_NOINVOL_ATTACH, 0,
			    wasvolpmd, pathbuf, dip);
#ifdef DEBUG
			if (pm_debug & PMD_NOINVOL)
				pr_noinvol("noinvol_specd exit");
#endif
			kmem_free(pathbuf, MAXPATHLEN);
			return;
		}
	}
	kmem_free(pathbuf, MAXPATHLEN);
	rw_exit(&pm_noinvol_rwlock);
	PM_UNLOCK_DIP(dip);
}

int
pm_all_components_off(dev_info_t *dip)
{
	int i;
	pm_component_t *cp;

	for (i = 0; i < PM_NUMCMPTS(dip); i++) {
		cp = PM_CP(dip, i);
		if (cp->pmc_cur_pwr == PM_LEVEL_UNKNOWN ||
		    cp->pmc_comp.pmc_lvals[cp->pmc_cur_pwr])
			return (0);
	}
	return (1);	/* all off */
}

/*
 * Make sure that all "no involuntary power cycles" devices are attached.
 * Called before doing a cpr suspend to make sure the driver has a say about
 * the power cycle
 */
int
pm_reattach_noinvol(void)
{
	PMD_FUNC(pmf, "reattach_noinvol")
	pm_noinvol_t *ip;
	char *path;
	dev_info_t *dip;

	/*
	 * Prevent the modunload thread from unloading any modules until we
	 * have completely stopped all kernel threads.
	 */
	modunload_disable();
	for (ip = pm_noinvol_head; ip; ip = ip->ni_next) {
		/*
		 * Forget we'v ever seen any entry
		 */
		ip->ni_persistent = 0;
	}
restart:
	rw_enter(&pm_noinvol_rwlock, RW_READER);
	for (ip = pm_noinvol_head; ip; ip = ip->ni_next) {
#ifdef PMDDEBUG
		major_t maj;
		maj = ip->ni_major;
#endif
		path = ip->ni_path;
		if (path != NULL && !(ip->ni_flags & PMC_DRIVER_REMOVED)) {
			if (ip->ni_persistent) {
				/*
				 * If we weren't able to make this entry
				 * go away, then we give up, as
				 * holding/attaching the driver ought to have
				 * resulted in this entry being deleted
				 */
				PMD(PMD_NOINVOL, ("%s: can't reattach %s "
				    "(%s|%d)\n", pmf, ip->ni_path,
				    ddi_major_to_name(maj), (int)maj))
				cmn_err(CE_WARN, "cpr: unable to reattach %s ",
				    ip->ni_path);
				modunload_enable();
				rw_exit(&pm_noinvol_rwlock);
				return (0);
			}
			ip->ni_persistent++;
			rw_exit(&pm_noinvol_rwlock);
			PMD(PMD_NOINVOL, ("%s: holding %s\n", pmf, path))
			dip = e_ddi_hold_devi_by_path(path, 0);
			if (dip == NULL) {
				PMD(PMD_NOINVOL, ("%s: can't hold (%s|%d)\n",
				    pmf, path, (int)maj))
				cmn_err(CE_WARN, "cpr: unable to hold %s "
				    "driver", path);
				modunload_enable();
				return (0);
			} else {
				PMD(PMD_DHR, ("%s: release %s\n", pmf, path))
				/*
				 * Since the modunload thread is stopped, we
				 * don't have to keep the driver held, which
				 * saves a ton of bookkeeping
				 */
				ddi_release_devi(dip);
				goto restart;
			}
		} else {
			PMD(PMD_NOINVOL, ("%s: skip %s; unknown major\n",
			    pmf, ip->ni_path))
			continue;
		}
	}
	rw_exit(&pm_noinvol_rwlock);
	return (1);
}

void
pm_reattach_noinvol_fini(void)
{
	modunload_enable();
}

/*
 * Display pm support code
 */


/*
 * console frame-buffer power-mgmt gets enabled when debugging
 * services are not present or console fbpm override is set
 */
void
pm_cfb_setup(const char *stdout_path)
{
	PMD_FUNC(pmf, "cfb_setup")
	extern int obpdebug;
	char *devname;
	dev_info_t *dip;
	int devname_len;
	extern dev_info_t *fbdip;

	/*
	 * By virtue of this function being called (from consconfig),
	 * we know stdout is a framebuffer.
	 */
	stdout_is_framebuffer = 1;

	if (obpdebug || (boothowto & RB_DEBUG)) {
		if (pm_cfb_override == 0) {
			/*
			 * Console is frame buffer, but we want to suppress
			 * pm on it because of debugging setup
			 */
			pm_cfb_enabled = 0;
			cmn_err(CE_NOTE, "Kernel debugger present: disabling "
			    "console power management.");
			/*
			 * however, we still need to know which is the console
			 * fb in order to suppress pm on it
			 */
		} else {
			cmn_err(CE_WARN, "Kernel debugger present: see "
			    "kmdb(1M) for interaction with power management.");
		}
	}
#ifdef DEBUG
	/*
	 * IF console is fb and is power managed, don't do prom_printfs from
	 * pm debug macro
	 */
	if (pm_cfb_enabled && !pm_debug_to_console) {
		if (pm_debug)
			prom_printf("pm debug output will be to log only\n");
		pm_divertdebug++;
	}
#endif
	devname = i_ddi_strdup((char *)stdout_path, KM_SLEEP);
	devname_len = strlen(devname) + 1;
	PMD(PMD_CFB, ("%s: stripped %s\n", pmf, devname))
	/* if the driver is attached */
	if ((dip = fbdip) != NULL) {
		PMD(PMD_CFB, ("%s: attached: %s@%s(%s#%d)\n", pmf,
		    PM_DEVICE(dip)))
		/*
		 * We set up here as if the driver were power manageable in case
		 * we get a later attach of a pm'able driver (which would result
		 * in a panic later)
		 */
		cfb_dip = dip;
		DEVI(dip)->devi_pm_flags |= (PMC_CONSOLE_FB | PMC_NO_INVOL);
		PMD(PMD_CFB, ("%s: cfb_dip -> %s@%s(%s#%d)\n", pmf,
		    PM_DEVICE(dip)))
#ifdef DEBUG
		if (!(PM_GET_PM_INFO(dip) != NULL && PM_NUMCMPTS(dip))) {
			PMD(PMD_CFB, ("%s: %s@%s(%s#%d) not power-managed\n",
			    pmf, PM_DEVICE(dip)))
		}
#endif
	} else {
		char *ep;
		PMD(PMD_CFB, ("%s: pntd %s failed\n", pmf, devname))
		pm_record_invol_path(devname,
		    (PMC_CONSOLE_FB | PMC_NO_INVOL), 1, 0, 0,
		    DDI_MAJOR_T_NONE);
		for (ep = strrchr(devname, '/'); ep != devname;
		    ep = strrchr(devname, '/')) {
			PMD(PMD_CFB, ("%s: devname %s\n", pmf, devname))
			*ep = '\0';
			dip = pm_name_to_dip(devname, 0);
			if (dip != NULL) {
				/*
				 * Walk up the tree incrementing
				 * devi_pm_noinvolpm
				 */
				(void) pm_noinvol_update(PM_BP_NOINVOL_CFB,
				    0, 0, devname, dip);
				break;
			} else {
				pm_record_invol_path(devname,
				    PMC_NO_INVOL, 1, 0, 0, DDI_MAJOR_T_NONE);
			}
		}
	}
	kmem_free(devname, devname_len);
}

void
pm_cfb_rele(void)
{
	mutex_enter(&pm_cfb_lock);
	/*
	 * this call isn't using the console any  more, it is ok to take it
	 * down if the count goes to 0
	 */
	cfb_inuse--;
	mutex_exit(&pm_cfb_lock);
}

/*
 * software interrupt handler for fbpm; this function exists because we can't
 * bring up the frame buffer power from above lock level.  So if we need to,
 * we instead schedule a softint that runs this routine and takes us into
 * debug_enter (a bit delayed from the original request, but avoiding a panic).
 */
static uint_t
pm_cfb_softint(caddr_t int_handler_arg)
{
	_NOTE(ARGUNUSED(int_handler_arg))
	int rval = DDI_INTR_UNCLAIMED;

	mutex_enter(&pm_cfb_lock);
	if (pm_soft_pending) {
		mutex_exit(&pm_cfb_lock);
		debug_enter((char *)NULL);
		/* acquired in debug_enter before calling pm_cfb_trigger */
		pm_cfb_rele();
		mutex_enter(&pm_cfb_lock);
		pm_soft_pending = B_FALSE;
		mutex_exit(&pm_cfb_lock);
		rval = DDI_INTR_CLAIMED;
	} else
		mutex_exit(&pm_cfb_lock);

	return (rval);
}

void
pm_cfb_setup_intr(void)
{
	PMD_FUNC(pmf, "cfb_setup_intr")
	extern void prom_set_outfuncs(void (*)(void), void (*)(void));
	void pm_cfb_check_and_powerup(void);

	mutex_init(&pm_cfb_lock, NULL, MUTEX_SPIN, (void *)ipltospl(SPL8));
#ifdef PMDDEBUG
	mutex_init(&pm_debug_lock, NULL, MUTEX_SPIN, (void *)ipltospl(SPL8));
#endif

	if (!stdout_is_framebuffer) {
		PMD(PMD_CFB, ("%s: console not fb\n", pmf))
		return;
	}

	/*
	 * setup software interrupt handler
	 */
	if (ddi_add_softintr(ddi_root_node(), DDI_SOFTINT_HIGH, &pm_soft_id,
	    NULL, NULL, pm_cfb_softint, NULL) != DDI_SUCCESS)
		panic("pm: unable to register soft intr.");

	prom_set_outfuncs(pm_cfb_check_and_powerup, pm_cfb_rele);
}

/*
 * Checks to see if it is safe to write to the console wrt power management
 * (i.e. if the console is a framebuffer, then it must be at full power)
 * returns 1 when power is off (power-up is needed)
 * returns 0 when power is on (power-up not needed)
 */
int
pm_cfb_check_and_hold(void)
{
	/*
	 * cfb_dip is set iff console is a power manageable frame buffer
	 * device
	 */
	extern int modrootloaded;

	mutex_enter(&pm_cfb_lock);
	cfb_inuse++;
	ASSERT(cfb_inuse);	/* wrap? */
	if (modrootloaded && cfb_dip) {
		/*
		 * don't power down the frame buffer, the prom is using it
		 */
		if (pm_cfb_comps_off) {
			mutex_exit(&pm_cfb_lock);
			return (1);
		}
	}
	mutex_exit(&pm_cfb_lock);
	return (0);
}

/*
 * turn on cfb power (which is known to be off).
 * Must be called below lock level!
 */
void
pm_cfb_powerup(void)
{
	pm_info_t *info;
	int norm;
	int ccount, ci;
	int unused;
#ifdef DEBUG
	/*
	 * Can't reenter prom_prekern, so suppress pm debug messages
	 * (still go to circular buffer).
	 */
	mutex_enter(&pm_debug_lock);
	pm_divertdebug++;
	mutex_exit(&pm_debug_lock);
#endif
	info = PM_GET_PM_INFO(cfb_dip);
	ASSERT(info);

	ccount = PM_NUMCMPTS(cfb_dip);
	for (ci = 0; ci < ccount; ci++) {
		norm = pm_get_normal_power(cfb_dip, ci);
		(void) pm_set_power(cfb_dip, ci, norm, PM_LEVEL_UPONLY,
		    PM_CANBLOCK_BYPASS, 0, &unused);
	}
#ifdef DEBUG
	mutex_enter(&pm_debug_lock);
	pm_divertdebug--;
	mutex_exit(&pm_debug_lock);
#endif
}

/*
 * Check if the console framebuffer is powered up.  If not power it up.
 * Note: Calling pm_cfb_check_and_hold has put a hold on the power state which
 * must be released by calling pm_cfb_rele when the console fb operation
 * is completed.
 */
void
pm_cfb_check_and_powerup(void)
{
	if (pm_cfb_check_and_hold())
		pm_cfb_powerup();
}

/*
 * Trigger a low level interrupt to power up console frame buffer.
 */
void
pm_cfb_trigger(void)
{
	if (cfb_dip == NULL)
		return;

	mutex_enter(&pm_cfb_lock);
	/*
	 * If the machine appears to be hung, pulling the keyboard connector of
	 * the console will cause a high level interrupt and go to debug_enter.
	 * But, if the fb is powered down, this routine will be called to bring
	 * it up (by generating a softint to do the work). If a second attempt
	 * at triggering this softint happens before the first one completes,
	 * we panic as softints are most likely not being handled.
	 */
	if (pm_soft_pending) {
		panicstr = "pm_cfb_trigger: failed to enter the debugger";
		panic(panicstr);	/* does a power up at any intr level */
		/* NOTREACHED */
	}
	pm_soft_pending = B_TRUE;
	mutex_exit(&pm_cfb_lock);
	ddi_trigger_softintr(pm_soft_id);
}

static major_t i_path_to_major(char *, char *);

major_t
pm_path_to_major(char *path)
{
	PMD_FUNC(pmf, "path_to_major")
	char *np, *ap, *bp;
	major_t ret;
	size_t len;

	PMD(PMD_NOINVOL, ("%s: %s\n", pmf, path))

	np = strrchr(path, '/');
	if (np != NULL)
		np++;
	else
		np = path;
	len = strlen(np) + 1;
	bp = kmem_alloc(len, KM_SLEEP);
	(void) strcpy(bp, np);
	if ((ap = strchr(bp, '@')) != NULL) {
		*ap = '\0';
	}
	PMD(PMD_NOINVOL, ("%s: %d\n", pmf, ddi_name_to_major(np)))
	ret = i_path_to_major(path, np);
	kmem_free(bp, len);
	return (ret);
}

#ifdef DEBUG
#ifndef sparc
clock_t pt_sleep = 1;
#endif

char	*pm_msgp;
char	*pm_bufend;
char	*pm_msgbuf = NULL;
int	pm_logpages = 0x100;
#include <sys/sunldi.h>
#include <sys/uio.h>
clock_t	pm_log_sleep = 1000;
int	pm_extra_cr = 1;
volatile int pm_tty = 1;

#define	PMLOGPGS	pm_logpages

#if defined(__x86)
void pm_printf(char *s);
#endif

/*PRINTFLIKE1*/
void
pm_log(const char *fmt, ...)
{
	va_list adx;
	size_t size;

	mutex_enter(&pm_debug_lock);
	if (pm_msgbuf == NULL) {
		pm_msgbuf = kmem_zalloc(mmu_ptob(PMLOGPGS), KM_SLEEP);
		pm_bufend = pm_msgbuf + mmu_ptob(PMLOGPGS) - 1;
		pm_msgp = pm_msgbuf;
	}
	va_start(adx, fmt);
	size = vsnprintf(NULL, 0, fmt, adx) + 1;
	va_end(adx);
	va_start(adx, fmt);
	if (size > (pm_bufend - pm_msgp)) {		/* wraps */
		bzero(pm_msgp, pm_bufend - pm_msgp);
		(void) vsnprintf(pm_msgbuf, size, fmt, adx);
		if (!pm_divertdebug)
			prom_printf("%s", pm_msgp);
#if defined(__x86)
		if (pm_tty) {
			pm_printf(pm_msgp);
			if (pm_extra_cr)
				pm_printf("\r");
		}
#endif
		pm_msgp = pm_msgbuf + size;
	} else {
		(void) vsnprintf(pm_msgp, size, fmt, adx);
#if defined(__x86)
		if (pm_tty) {
			pm_printf(pm_msgp);
			if (pm_extra_cr)
				pm_printf("\r");
		}
#endif
		if (!pm_divertdebug)
			prom_printf("%s", pm_msgp);
		pm_msgp += size;
	}
	va_end(adx);
	mutex_exit(&pm_debug_lock);
	drv_usecwait((clock_t)pm_log_sleep);
}
#endif	/* DEBUG */

/*
 * We want to save the state of any directly pm'd devices over the suspend/
 * resume process so that we can put them back the way the controlling
 * process left them.
 */
void
pm_save_direct_levels(void)
{
	pm_processes_stopped = 1;
	ddi_walk_devs(ddi_root_node(), pm_save_direct_lvl_walk, 0);
}

static int
pm_save_direct_lvl_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	int i;
	int *ip;
	pm_info_t *info = PM_GET_PM_INFO(dip);

	if (!info)
		return (DDI_WALK_CONTINUE);

	if (PM_ISDIRECT(dip) && !PM_ISBC(dip)) {
		if (PM_NUMCMPTS(dip) > 2) {
			info->pmi_lp = kmem_alloc(PM_NUMCMPTS(dip) *
			    sizeof (int), KM_SLEEP);
			ip = info->pmi_lp;
		} else {
			ip = info->pmi_levels;
		}
		/* autopm and processes are stopped, ok not to lock power */
		for (i = 0; i < PM_NUMCMPTS(dip); i++)
			*ip++ = PM_CURPOWER(dip, i);
		/*
		 * There is a small window between stopping the
		 * processes and setting pm_processes_stopped where
		 * a driver could get hung up in a pm_raise_power()
		 * call.  Free any such driver now.
		 */
		pm_proceed(dip, PMP_RELEASE, -1, -1);
	}

	return (DDI_WALK_CONTINUE);
}

void
pm_restore_direct_levels(void)
{
	/*
	 * If cpr didn't call pm_save_direct_levels, (because stopping user
	 * threads failed) then we don't want to try to restore them
	 */
	if (!pm_processes_stopped)
		return;

	ddi_walk_devs(ddi_root_node(), pm_restore_direct_lvl_walk, 0);
	pm_processes_stopped = 0;
}

static int
pm_restore_direct_lvl_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))
	PMD_FUNC(pmf, "restore_direct_lvl_walk")
	int i, nc, result;
	int *ip;

	pm_info_t *info = PM_GET_PM_INFO(dip);
	if (!info)
		return (DDI_WALK_CONTINUE);

	if (PM_ISDIRECT(dip) && !PM_ISBC(dip)) {
		if ((nc = PM_NUMCMPTS(dip)) > 2) {
			ip = &info->pmi_lp[nc - 1];
		} else {
			ip = &info->pmi_levels[nc - 1];
		}
		/*
		 * Because fb drivers fail attempts to turn off the
		 * fb when the monitor is on, but treat a request to
		 * turn on the monitor as a request to turn on the
		 * fb too, we process components in descending order
		 * Because autopm is disabled and processes aren't
		 * running, it is ok to examine current power outside
		 * of the power lock
		 */
		for (i = nc - 1; i >= 0; i--, ip--) {
			if (PM_CURPOWER(dip, i) == *ip)
				continue;
			if (pm_set_power(dip, i, *ip, PM_LEVEL_EXACT,
			    PM_CANBLOCK_BYPASS, 0, &result) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "cpr: unable "
				    "to restore power level of "
				    "component %d of directly "
				    "power manged device %s@%s"
				    " to %d",
				    i, PM_NAME(dip),
				    PM_ADDR(dip), *ip);
				PMD(PMD_FAIL, ("%s: failed to restore "
				    "%s@%s(%s#%d)[%d] exact(%d)->%d, "
				    "errno %d\n", pmf, PM_DEVICE(dip), i,
				    PM_CURPOWER(dip, i), *ip, result))
			}
		}
		if (nc > 2) {
			kmem_free(info->pmi_lp, nc * sizeof (int));
			info->pmi_lp = NULL;
		}
	}
	return (DDI_WALK_CONTINUE);
}

/*
 * Stolen from the bootdev module
 * attempt to convert a path to a major number
 */
static major_t
i_path_to_major(char *path, char *leaf_name)
{
	extern major_t path_to_major(char *pathname);
	major_t maj;

	if ((maj = path_to_major(path)) == DDI_MAJOR_T_NONE) {
		maj = ddi_name_to_major(leaf_name);
	}

	return (maj);
}

static void i_pm_driver_removed(major_t major);

/*
 * When user calls rem_drv, we need to forget no-involuntary-power-cycles state
 * An entry in the list means that the device is detached, so we need to
 * adjust its ancestors as if they had just seen this attach, and any detached
 * ancestors need to have their list entries adjusted.
 */
void
pm_driver_removed(major_t major)
{

	/*
	 * Serialize removal of drivers. This is to keep ancestors of
	 * a node that is being deleted from getting deleted and added back
	 * with different counters.
	 */
	mutex_enter(&pm_remdrv_lock);
	i_pm_driver_removed(major);
	mutex_exit(&pm_remdrv_lock);
}

static void adjust_ancestors(char *, int);
static int pm_is_noinvol_ancestor(pm_noinvol_t *);
static void pm_noinvol_process_ancestors(char *);

/*
 * This routine is called recursively by pm_noinvol_process_ancestors()
 */
static void
i_pm_driver_removed(major_t major)
{
	PMD_FUNC(pmf, "driver_removed")
	pm_noinvol_t *ip, *pp = NULL;
	int wasvolpmd;
	ASSERT(major != DDI_MAJOR_T_NONE);
	PMD(PMD_NOINVOL, ("%s: %s\n", pmf, ddi_major_to_name(major)))
again:
	rw_enter(&pm_noinvol_rwlock, RW_WRITER);
	for (ip = pm_noinvol_head; ip; pp = ip, ip = ip->ni_next) {
		if (major != ip->ni_major)
			continue;
		/*
		 * If it is an ancestor of no-invol node, which is
		 * not removed, skip it. This is to cover the case of
		 * ancestor removed without removing its descendants.
		 */
		if (pm_is_noinvol_ancestor(ip)) {
			ip->ni_flags |= PMC_DRIVER_REMOVED;
			continue;
		}
		wasvolpmd = ip->ni_wasvolpmd;
		/*
		 * remove the entry from the list
		 */
		if (pp) {
			PMD(PMD_NOINVOL, ("%s: freeing %s, prev is %s\n",
			    pmf, ip->ni_path, pp->ni_path))
			pp->ni_next = ip->ni_next;
		} else {
			PMD(PMD_NOINVOL, ("%s: free %s head\n", pmf,
			    ip->ni_path))
			ASSERT(pm_noinvol_head == ip);
			pm_noinvol_head = ip->ni_next;
		}
		rw_exit(&pm_noinvol_rwlock);
		adjust_ancestors(ip->ni_path, wasvolpmd);
		/*
		 * Had an ancestor been removed before this node, it would have
		 * been skipped. Adjust the no-invol counters for such skipped
		 * ancestors.
		 */
		pm_noinvol_process_ancestors(ip->ni_path);
		kmem_free(ip->ni_path, ip->ni_size);
		kmem_free(ip, sizeof (*ip));
		goto again;
	}
	rw_exit(&pm_noinvol_rwlock);
}

/*
 * returns 1, if *aip is a ancestor of a no-invol node
 *	   0, otherwise
 */
static int
pm_is_noinvol_ancestor(pm_noinvol_t *aip)
{
	pm_noinvol_t *ip;

	ASSERT(strlen(aip->ni_path) != 0);
	for (ip = pm_noinvol_head; ip; ip = ip->ni_next) {
		if (ip == aip)
			continue;
		/*
		 * To be an ancestor, the path must be an initial substring of
		 * the descendent, and end just before a '/' in the
		 * descendent's path.
		 */
		if ((strstr(ip->ni_path, aip->ni_path) == ip->ni_path) &&
		    (ip->ni_path[strlen(aip->ni_path)] == '/'))
			return (1);
	}
	return (0);
}

/*
 * scan through the pm_noinvolpm list adjusting ancestors of the current
 * node;  Modifies string *path.
 */
static void
adjust_ancestors(char *path, int wasvolpmd)
{
	PMD_FUNC(pmf, "adjust_ancestors")
	char *cp;
	pm_noinvol_t *lp;
	pm_noinvol_t *pp = NULL;
	major_t locked = DDI_MAJOR_T_NONE;
	dev_info_t *dip;
	char	*pathbuf;
	size_t pathbuflen = strlen(path) + 1;

	/*
	 * First we look up the ancestor's dip.  If we find it, then we
	 * adjust counts up the tree
	 */
	PMD(PMD_NOINVOL, ("%s: %s wasvolpmd %d\n", pmf, path, wasvolpmd))
	pathbuf = kmem_alloc(pathbuflen, KM_SLEEP);
	(void) strcpy(pathbuf, path);
	cp = strrchr(pathbuf, '/');
	if (cp == NULL)	{
		/* if no ancestors, then nothing to do */
		kmem_free(pathbuf, pathbuflen);
		return;
	}
	*cp = '\0';
	dip = pm_name_to_dip(pathbuf, 1);
	if (dip != NULL) {
		locked = PM_MAJOR(dip);

		(void) pm_noinvol_update(PM_BP_NOINVOL_REMDRV, 0, wasvolpmd,
		    path, dip);

		if (locked != DDI_MAJOR_T_NONE)
			ddi_release_devi(dip);
	} else {
		char *apath;
		size_t len = strlen(pathbuf) + 1;
		int  lock_held = 1;

		/*
		 * Now check for ancestors that exist only in the list
		 */
		apath = kmem_alloc(len, KM_SLEEP);
		(void) strcpy(apath, pathbuf);
		rw_enter(&pm_noinvol_rwlock, RW_WRITER);
		for (lp = pm_noinvol_head; lp; pp = lp, lp = lp->ni_next) {
			/*
			 * This can only happen once.  Since we have to drop
			 * the lock, we need to extract the relevant info.
			 */
			if (strcmp(pathbuf, lp->ni_path) == 0) {
				PMD(PMD_NOINVOL, ("%s: %s no %d -> %d\n", pmf,
				    lp->ni_path, lp->ni_noinvolpm,
				    lp->ni_noinvolpm - 1))
				lp->ni_noinvolpm--;
				if (wasvolpmd && lp->ni_volpmd) {
					PMD(PMD_NOINVOL, ("%s: %s vol %d -> "
					    "%d\n", pmf, lp->ni_path,
					    lp->ni_volpmd, lp->ni_volpmd - 1))
					lp->ni_volpmd--;
				}
				/*
				 * remove the entry from the list, if there
				 * are no more no-invol descendants and node
				 * itself is not a no-invol node.
				 */
				if (!(lp->ni_noinvolpm ||
				    (lp->ni_flags & PMC_NO_INVOL))) {
					ASSERT(lp->ni_volpmd == 0);
					if (pp) {
						PMD(PMD_NOINVOL, ("%s: freeing "
						    "%s, prev is %s\n", pmf,
						    lp->ni_path, pp->ni_path))
						pp->ni_next = lp->ni_next;
					} else {
						PMD(PMD_NOINVOL, ("%s: free %s "
						    "head\n", pmf, lp->ni_path))
						ASSERT(pm_noinvol_head == lp);
						pm_noinvol_head = lp->ni_next;
					}
					lock_held = 0;
					rw_exit(&pm_noinvol_rwlock);
					adjust_ancestors(apath, wasvolpmd);
					/* restore apath */
					(void) strcpy(apath, pathbuf);
					kmem_free(lp->ni_path, lp->ni_size);
					kmem_free(lp, sizeof (*lp));
				}
				break;
			}
		}
		if (lock_held)
			rw_exit(&pm_noinvol_rwlock);
		adjust_ancestors(apath, wasvolpmd);
		kmem_free(apath, len);
	}
	kmem_free(pathbuf, pathbuflen);
}

/*
 * Do no-invol processing for any ancestors i.e. adjust counters of ancestors,
 * which were skipped even though their drivers were removed.
 */
static void
pm_noinvol_process_ancestors(char *path)
{
	pm_noinvol_t *lp;

	rw_enter(&pm_noinvol_rwlock, RW_READER);
	for (lp = pm_noinvol_head; lp; lp = lp->ni_next) {
		if (strstr(path, lp->ni_path) &&
		    (lp->ni_flags & PMC_DRIVER_REMOVED)) {
			rw_exit(&pm_noinvol_rwlock);
			i_pm_driver_removed(lp->ni_major);
			return;
		}
	}
	rw_exit(&pm_noinvol_rwlock);
}

/*
 * Returns true if (detached) device needs to be kept up because it exported the
 * "no-involuntary-power-cycles" property or we're pretending it did (console
 * fb case) or it is an ancestor of such a device and has used up the "one
 * free cycle" allowed when all such leaf nodes have voluntarily powered down
 * upon detach.  In any event, we need an exact hit on the path or we return
 * false.
 */
int
pm_noinvol_detached(char *path)
{
	PMD_FUNC(pmf, "noinvol_detached")
	pm_noinvol_t *ip;
	int ret = 0;

	rw_enter(&pm_noinvol_rwlock, RW_READER);
	for (ip = pm_noinvol_head; ip; ip = ip->ni_next) {
		if (strcmp(path, ip->ni_path) == 0) {
			if (ip->ni_flags & PMC_CONSOLE_FB) {
				PMD(PMD_NOINVOL | PMD_CFB, ("%s: inhibits CFB "
				    "%s\n", pmf, path))
				ret = 1;
				break;
			}
#ifdef	DEBUG
			if (ip->ni_noinvolpm != ip->ni_volpmd)
				PMD(PMD_NOINVOL, ("%s: (%d != %d) inhibits %s"
				    "\n", pmf, ip->ni_noinvolpm, ip->ni_volpmd,
				    path))
#endif
			ret = (ip->ni_noinvolpm != ip->ni_volpmd);
			break;
		}
	}
	rw_exit(&pm_noinvol_rwlock);
	return (ret);
}

int
pm_is_cfb(dev_info_t *dip)
{
	return (dip == cfb_dip);
}

#ifdef	DEBUG
/*
 * Return true if all components of the console frame buffer are at
 * "normal" power, i.e., fully on.  For the case where the console is not
 * a framebuffer, we also return true
 */
int
pm_cfb_is_up(void)
{
	return (pm_cfb_comps_off == 0);
}
#endif

/*
 * Preventing scan from powering down the node by incrementing the
 * kidsupcnt.
 */
void
pm_hold_power(dev_info_t *dip)
{
	e_pm_hold_rele_power(dip, 1);
}

/*
 * Releasing the hold by decrementing the kidsupcnt allowing scan
 * to power down the node if all conditions are met.
 */
void
pm_rele_power(dev_info_t *dip)
{
	e_pm_hold_rele_power(dip, -1);
}

/*
 * A wrapper of pm_all_to_normal() to power up a dip
 * to its normal level
 */
int
pm_powerup(dev_info_t *dip)
{
	PMD_FUNC(pmf, "pm_powerup")

	PMD(PMD_ALLNORM, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	ASSERT(!(servicing_interrupt()));

	/*
	 * in case this node is not already participating pm
	 */
	if (!PM_GET_PM_INFO(dip)) {
		if (!DEVI_IS_ATTACHING(dip))
			return (DDI_SUCCESS);
		if (pm_start(dip) != DDI_SUCCESS)
			return (DDI_FAILURE);
		if (!PM_GET_PM_INFO(dip))
			return (DDI_SUCCESS);
	}

	return (pm_all_to_normal(dip, PM_CANBLOCK_BLOCK));
}

int
pm_rescan_walk(dev_info_t *dip, void *arg)
{
	_NOTE(ARGUNUSED(arg))

	if (!PM_GET_PM_INFO(dip) || PM_ISBC(dip))
		return (DDI_WALK_CONTINUE);

	/*
	 * Currently pm_cpr_callb/resume code is the only caller
	 * and it needs to make sure that stopped scan get
	 * reactivated. Otherwise, rescan walk needn't reactive
	 * stopped scan.
	 */
	pm_scan_init(dip);

	(void) pm_rescan(dip);
	return (DDI_WALK_CONTINUE);
}

static dev_info_t *
pm_get_next_descendent(dev_info_t *dip, dev_info_t *tdip)
{
	dev_info_t *wdip, *pdip;

	for (wdip = tdip; wdip != dip; wdip = pdip) {
		pdip = ddi_get_parent(wdip);
		if (pdip == dip)
			return (wdip);
	}
	return (NULL);
}

int
pm_busop_bus_power(dev_info_t *dip, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	PMD_FUNC(pmf, "bp_bus_power")
	dev_info_t	*cdip;
	pm_info_t	*cinfo;
	pm_bp_child_pwrchg_t	*bpc;
	pm_sp_misc_t		*pspm;
	pm_bp_nexus_pwrup_t *bpn;
	pm_bp_child_pwrchg_t new_bpc;
	pm_bp_noinvol_t *bpi;
	dev_info_t *tdip;
	char *pathbuf;
	int		ret = DDI_SUCCESS;
	int		errno = 0;
	pm_component_t *cp;

	PMD(PMD_SET, ("%s: %s@%s(%s#%d) %s\n", pmf, PM_DEVICE(dip),
	    pm_decode_op(op)))
	switch (op) {
	case BUS_POWER_CHILD_PWRCHG:
		bpc = (pm_bp_child_pwrchg_t *)arg;
		pspm = (pm_sp_misc_t *)bpc->bpc_private;
		tdip = bpc->bpc_dip;
		cdip = pm_get_next_descendent(dip, tdip);
		cinfo = PM_GET_PM_INFO(cdip);
		if (cdip != tdip) {
			/*
			 * If the node is an involved parent, it needs to
			 * power up the node as it is needed.  There is nothing
			 * else the framework can do here.
			 */
			if (PM_WANTS_NOTIFICATION(cdip)) {
				PMD(PMD_SET, ("%s: call bus_power for "
				    "%s@%s(%s#%d)\n", pmf, PM_DEVICE(cdip)))
				return ((*PM_BUS_POWER_FUNC(cdip))(cdip,
				    impl_arg, op, arg, result));
			}
			ASSERT(pspm->pspm_direction == PM_LEVEL_UPONLY ||
			    pspm->pspm_direction == PM_LEVEL_DOWNONLY ||
			    pspm->pspm_direction == PM_LEVEL_EXACT);
			/*
			 * we presume that the parent needs to be up in
			 * order for the child to change state (either
			 * because it must already be on if the child is on
			 * (and the pm_all_to_normal_nexus() will be a nop)
			 * or because it will need to be on for the child
			 * to come on; so we make the call regardless
			 */
			pm_hold_power(cdip);
			if (cinfo) {
				pm_canblock_t canblock = pspm->pspm_canblock;
				ret = pm_all_to_normal_nexus(cdip, canblock);
				if (ret != DDI_SUCCESS) {
					pm_rele_power(cdip);
					return (ret);
				}
			}
			PMD(PMD_SET, ("%s: walk down to %s@%s(%s#%d)\n", pmf,
			    PM_DEVICE(cdip)))
			ret = pm_busop_bus_power(cdip, impl_arg, op, arg,
			    result);
			pm_rele_power(cdip);
		} else {
			ret = pm_busop_set_power(cdip, impl_arg, op, arg,
			    result);
		}
		return (ret);

	case BUS_POWER_NEXUS_PWRUP:
		bpn = (pm_bp_nexus_pwrup_t *)arg;
		pspm = (pm_sp_misc_t *)bpn->bpn_private;

		if (!e_pm_valid_info(dip, NULL) ||
		    !e_pm_valid_comp(dip, bpn->bpn_comp, &cp) ||
		    !e_pm_valid_power(dip, bpn->bpn_comp, bpn->bpn_level)) {
			PMD(PMD_SET, ("%s: %s@%s(%s#%d) has no pm info; EIO\n",
			    pmf, PM_DEVICE(dip)))
			*pspm->pspm_errnop = EIO;
			*(int *)result = DDI_FAILURE;
			return (DDI_FAILURE);
		}

		ASSERT(bpn->bpn_dip == dip);
		PMD(PMD_SET, ("%s: nexus powerup for %s@%s(%s#%d)\n", pmf,
		    PM_DEVICE(dip)))
		new_bpc.bpc_dip = dip;
		pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		new_bpc.bpc_path = ddi_pathname(dip, pathbuf);
		new_bpc.bpc_comp = bpn->bpn_comp;
		new_bpc.bpc_olevel = PM_CURPOWER(dip, bpn->bpn_comp);
		new_bpc.bpc_nlevel = bpn->bpn_level;
		new_bpc.bpc_private = bpn->bpn_private;
		((pm_sp_misc_t *)(new_bpc.bpc_private))->pspm_direction =
		    PM_LEVEL_UPONLY;
		((pm_sp_misc_t *)(new_bpc.bpc_private))->pspm_errnop =
		    &errno;
		ret = pm_busop_set_power(dip, impl_arg, BUS_POWER_CHILD_PWRCHG,
		    (void *)&new_bpc, result);
		kmem_free(pathbuf, MAXPATHLEN);
		return (ret);

	case BUS_POWER_NOINVOL:
		bpi = (pm_bp_noinvol_t *)arg;
		tdip = bpi->bpni_dip;
		cdip = pm_get_next_descendent(dip, tdip);

		/* In case of rem_drv, the leaf node has been removed */
		if (cdip == NULL)
			return (DDI_SUCCESS);

		cinfo = PM_GET_PM_INFO(cdip);
		if (cdip != tdip) {
			if (PM_WANTS_NOTIFICATION(cdip)) {
				PMD(PMD_NOINVOL,
				    ("%s: call bus_power for %s@%s(%s#%d)\n",
				    pmf, PM_DEVICE(cdip)))
				ret = (*PM_BUS_POWER_FUNC(cdip))
				    (cdip, NULL, op, arg, result);
				if ((cinfo) && (ret == DDI_SUCCESS))
					(void) pm_noinvol_update_node(cdip,
					    bpi);
				return (ret);
			} else {
				PMD(PMD_NOINVOL,
				    ("%s: walk down to %s@%s(%s#%d)\n", pmf,
				    PM_DEVICE(cdip)))
				ret = pm_busop_bus_power(cdip, NULL, op,
				    arg, result);
				/*
				 * Update the current node.
				 */
				if ((cinfo) && (ret == DDI_SUCCESS))
					(void) pm_noinvol_update_node(cdip,
					    bpi);
				return (ret);
			}
		} else {
			/*
			 * For attach, detach, power up:
			 * Do nothing for leaf node since its
			 * counts are already updated.
			 * For CFB and driver removal, since the
			 * path and the target dip passed in is up to and incl.
			 * the immediate ancestor, need to do the update.
			 */
			PMD(PMD_NOINVOL, ("%s: target %s@%s(%s#%d) is "
			    "reached\n", pmf, PM_DEVICE(cdip)))
			if (cinfo && ((bpi->bpni_cmd == PM_BP_NOINVOL_REMDRV) ||
			    (bpi->bpni_cmd == PM_BP_NOINVOL_CFB)))
				(void) pm_noinvol_update_node(cdip, bpi);
			return (DDI_SUCCESS);
		}

	default:
		PMD(PMD_SET, ("%s: operation %d is not supported!\n", pmf, op))
		return (DDI_FAILURE);
	}
}

static int
pm_busop_set_power(dev_info_t *dip, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *resultp)
{
	_NOTE(ARGUNUSED(impl_arg))
	PMD_FUNC(pmf, "bp_set_power")
	pm_ppm_devlist_t *devl = NULL;
	int clevel, circ;
#ifdef	DEBUG
	int circ_db, ccirc_db;
#endif
	int ret = DDI_SUCCESS;
	dev_info_t *cdip;
	pm_bp_child_pwrchg_t *bpc = (pm_bp_child_pwrchg_t *)arg;
	pm_sp_misc_t *pspm = (pm_sp_misc_t *)bpc->bpc_private;
	pm_canblock_t canblock = pspm->pspm_canblock;
	int scan = pspm->pspm_scan;
	int comp = bpc->bpc_comp;
	int olevel = bpc->bpc_olevel;
	int nlevel = bpc->bpc_nlevel;
	int comps_off_incr = 0;
	dev_info_t *pdip = ddi_get_parent(dip);
	int dodeps;
	int direction = pspm->pspm_direction;
	int *errnop = pspm->pspm_errnop;
#ifdef PMDDEBUG
	char *dir = pm_decode_direction(direction);
#endif
	int *iresp = (int *)resultp;
	time_t	idletime, thresh;
	pm_component_t *cp = PM_CP(dip, comp);
	int work_type;

	*iresp = DDI_SUCCESS;
	*errnop = 0;
	ASSERT(op == BUS_POWER_CHILD_PWRCHG);
	PMD(PMD_SET, ("%s: %s@%s(%s#%d) %s\n", pmf, PM_DEVICE(dip),
	    pm_decode_op(op)))

	/*
	 * The following set of conditions indicate we are here to handle a
	 * driver's pm_[raise|lower]_power request, but the device is being
	 * power managed (PM_DIRECT_PM) by a user process.  For that case
	 * we want to pm_block and pass a status back to the caller based
	 * on whether the controlling process's next activity on the device
	 * matches the current request or not.  This distinction tells
	 * downstream functions to avoid calling into a driver or changing
	 * the framework's power state.  To actually block, we need:
	 *
	 * PM_ISDIRECT(dip)
	 *	no reason to block unless a process is directly controlling dev
	 * direction != PM_LEVEL_EXACT
	 *	EXACT is used by controlling proc's PM_SET_CURRENT_POWER ioctl
	 * !pm_processes_stopped
	 *	don't block if controlling proc already be stopped for cpr
	 * canblock != PM_CANBLOCK_BYPASS
	 *	our caller must not have explicitly prevented blocking
	 */
	if (direction != PM_LEVEL_EXACT && canblock != PM_CANBLOCK_BYPASS) {
		PM_LOCK_DIP(dip);
		while (PM_ISDIRECT(dip) && !pm_processes_stopped) {
			/* releases dip lock */
			ret = pm_busop_match_request(dip, bpc);
			if (ret == EAGAIN) {
				PM_LOCK_DIP(dip);
				continue;
			}
			return (*iresp = ret);
		}
		PM_UNLOCK_DIP(dip);
	}
	/* BC device is never scanned, so power will stick until we are done */
	if (PM_ISBC(dip) && comp != 0 && nlevel != 0 &&
	    direction != PM_LEVEL_DOWNONLY) {
		int nrmpwr0 = pm_get_normal_power(dip, 0);
		if (pm_set_power(dip, 0, nrmpwr0, direction,
		    canblock, 0, resultp) != DDI_SUCCESS) {
			/* *resultp set by pm_set_power */
			return (DDI_FAILURE);
		}
	}
	if (PM_WANTS_NOTIFICATION(pdip)) {
		PMD(PMD_SET, ("%s: pre_notify %s@%s(%s#%d) for child "
		    "%s@%s(%s#%d)\n", pmf, PM_DEVICE(pdip), PM_DEVICE(dip)))
		ret = (*PM_BUS_POWER_FUNC(pdip))(pdip, NULL,
		    BUS_POWER_PRE_NOTIFICATION, bpc, resultp);
		if (ret != DDI_SUCCESS) {
			PMD(PMD_SET, ("%s: failed to pre_notify %s@%s(%s#%d)\n",
			    pmf, PM_DEVICE(pdip)))
			return (DDI_FAILURE);
		}
	} else {
		/*
		 * Since we don't know what the actual power level is,
		 * we place a power hold on the parent no matter what
		 * component and level is changing.
		 */
		pm_hold_power(pdip);
	}
	PM_LOCK_POWER(dip, &circ);
	clevel = PM_CURPOWER(dip, comp);
	/*
	 * It's possible that a call was made to pm_update_maxpower()
	 * on another thread before we took the lock above. So, we need to
	 * make sure that this request isn't processed after the
	 * change of power executed on behalf of pm_update_maxpower().
	 */
	if (nlevel > pm_get_normal_power(dip, comp)) {
		PMD(PMD_SET, ("%s: requested level is higher than normal.\n",
		    pmf))
		ret = DDI_FAILURE;
		*iresp = DDI_FAILURE;
		goto post_notify;
	}
	PMD(PMD_SET, ("%s: %s@%s(%s#%d), cmp=%d, olvl=%d, nlvl=%d, clvl=%d, "
	    "dir=%s\n", pmf, PM_DEVICE(dip), comp, bpc->bpc_olevel, nlevel,
	    clevel, dir))
	switch (direction) {
	case PM_LEVEL_UPONLY:
		/* Powering up */
		if (clevel >= nlevel) {
			PMD(PMD_SET, ("%s: current level is already "
			    "at or above the requested level.\n", pmf))
			*iresp = DDI_SUCCESS;
			ret = DDI_SUCCESS;
			goto post_notify;
		}
		break;
	case PM_LEVEL_EXACT:
		/* specific level request */
		if (clevel == nlevel && !PM_ISBC(dip)) {
			PMD(PMD_SET, ("%s: current level is already "
			    "at the requested level.\n", pmf))
			*iresp = DDI_SUCCESS;
			ret = DDI_SUCCESS;
			goto post_notify;
		} else if (PM_IS_CFB(dip) && (nlevel < clevel)) {
			PMD(PMD_CFB, ("%s: powerdown of console\n", pmf))
			if (!pm_cfb_enabled) {
				PMD(PMD_ERROR | PMD_CFB,
				    ("%s: !pm_cfb_enabled, fails\n", pmf))
				*errnop = EINVAL;
				*iresp = DDI_FAILURE;
				ret = DDI_FAILURE;
				goto post_notify;
			}
			mutex_enter(&pm_cfb_lock);
			while (cfb_inuse) {
				mutex_exit(&pm_cfb_lock);
				if (delay_sig(1) == EINTR) {
					ret = DDI_FAILURE;
					*iresp = DDI_FAILURE;
					*errnop = EINTR;
					goto post_notify;
				}
				mutex_enter(&pm_cfb_lock);
			}
			mutex_exit(&pm_cfb_lock);
		}
		break;
	case PM_LEVEL_DOWNONLY:
		/* Powering down */
		thresh = cur_threshold(dip, comp);
		idletime = gethrestime_sec() - cp->pmc_timestamp;
		if (scan && ((PM_KUC(dip) != 0) ||
		    (cp->pmc_busycount > 0) ||
		    ((idletime < thresh) && !PM_IS_PID(dip)))) {
#ifdef	DEBUG
			if (DEVI(dip)->devi_pm_kidsupcnt != 0)
				PMD(PMD_SET, ("%s: scan failed: "
				    "kidsupcnt != 0\n", pmf))
			if (cp->pmc_busycount > 0)
				PMD(PMD_SET, ("%s: scan failed: "
				    "device become busy\n", pmf))
			if (idletime < thresh)
				PMD(PMD_SET, ("%s: scan failed: device "
				    "hasn't been idle long enough\n", pmf))
#endif
			*iresp = DDI_FAILURE;
			*errnop = EBUSY;
			ret = DDI_FAILURE;
			goto post_notify;
		} else if (clevel != PM_LEVEL_UNKNOWN && clevel <= nlevel) {
			PMD(PMD_SET, ("%s: current level is already at "
			    "or below the requested level.\n", pmf))
			*iresp = DDI_SUCCESS;
			ret = DDI_SUCCESS;
			goto post_notify;
		}
		break;
	}

	if (PM_IS_CFB(dip) && (comps_off_incr =
	    calc_cfb_comps_incr(dip, comp, clevel, nlevel)) > 0) {
		/*
		 * Pre-adjust pm_cfb_comps_off if lowering a console fb
		 * component from full power.  Remember that we tried to
		 * lower power in case it fails and we need to back out
		 * the adjustment.
		 */
		update_comps_off(comps_off_incr, dip);
		PMD(PMD_CFB, ("%s: %s@%s(%s#%d)[%d] %d->%d cfb_comps_off->%d\n",
		    pmf, PM_DEVICE(dip), comp, clevel, nlevel,
		    pm_cfb_comps_off))
	}

	if ((*iresp = power_dev(dip,
	    comp, nlevel, clevel, canblock, &devl)) == DDI_SUCCESS) {
#ifdef DEBUG
		/*
		 * All descendents of this node should already be powered off.
		 */
		if (PM_CURPOWER(dip, comp) == 0) {
			pm_desc_pwrchk_t pdpchk;
			pdpchk.pdpc_dip = dip;
			pdpchk.pdpc_par_involved = PM_WANTS_NOTIFICATION(dip);
			ndi_devi_enter(dip, &circ_db);
			for (cdip = ddi_get_child(dip); cdip != NULL;
			    cdip = ddi_get_next_sibling(cdip)) {
				ndi_devi_enter(cdip, &ccirc_db);
				ddi_walk_devs(cdip, pm_desc_pwrchk_walk,
				    (void *)&pdpchk);
				ndi_devi_exit(cdip, ccirc_db);
			}
			ndi_devi_exit(dip, circ_db);
		}
#endif
		/*
		 * Post-adjust pm_cfb_comps_off if we brought an fb component
		 * back up to full power.
		 */
		if (PM_IS_CFB(dip) && comps_off_incr < 0) {
			update_comps_off(comps_off_incr, dip);
			PMD(PMD_CFB, ("%s: %s@%s(%s#%d)[%d] %d->%d "
			    "cfb_comps_off->%d\n", pmf, PM_DEVICE(dip),
			    comp, clevel, nlevel, pm_cfb_comps_off))
		}
		dodeps = 0;
		if (POWERING_OFF(clevel, nlevel)) {
			if (PM_ISBC(dip)) {
				dodeps = (comp == 0);
			} else {
				int i;
				dodeps = 1;
				for (i = 0; i < PM_NUMCMPTS(dip); i++) {
					/* if some component still on */
					if (PM_CURPOWER(dip, i)) {
						dodeps = 0;
						break;
					}
				}
			}
			if (dodeps)
				work_type = PM_DEP_WK_POWER_OFF;
		} else if (POWERING_ON(clevel, nlevel)) {
			if (PM_ISBC(dip)) {
				dodeps = (comp == 0);
			} else {
				int i;
				dodeps = 1;
				for (i = 0; i < PM_NUMCMPTS(dip); i++) {
					if (i == comp)
						continue;
					if (PM_CURPOWER(dip, i) > 0) {
						dodeps = 0;
						break;
					}
				}
			}
			if (dodeps)
				work_type = PM_DEP_WK_POWER_ON;
		}

		if (dodeps) {
			char *pathbuf = kmem_alloc(MAXPATHLEN, KM_SLEEP);

			(void) ddi_pathname(dip, pathbuf);
			pm_dispatch_to_dep_thread(work_type, pathbuf, NULL,
			    PM_DEP_NOWAIT, NULL, 0);
			kmem_free(pathbuf, MAXPATHLEN);
		}
		if ((PM_CURPOWER(dip, comp) == nlevel) && pm_watchers()) {
			int old;

			/* If old power cached during deadlock, use it. */
			old = (cp->pmc_flags & PM_PHC_WHILE_SET_POWER ?
			    cp->pmc_phc_pwr : olevel);
			mutex_enter(&pm_rsvp_lock);
			pm_enqueue_notify(PSC_HAS_CHANGED, dip, comp, nlevel,
			    old, canblock);
			pm_enqueue_notify_others(&devl, canblock);
			mutex_exit(&pm_rsvp_lock);
		} else {
			pm_ppm_devlist_t *p;
			pm_ppm_devlist_t *next;
			for (p = devl; p != NULL; p = next) {
				next = p->ppd_next;
				kmem_free(p, sizeof (pm_ppm_devlist_t));
			}
			devl = NULL;
		}

		/*
		 * If we are coming from a scan, don't do it again,
		 * else we can have infinite loops.
		 */
		if (!scan)
			pm_rescan(dip);
	} else {
		/* if we incremented pm_comps_off_count, but failed */
		if (comps_off_incr > 0) {
			update_comps_off(-comps_off_incr, dip);
			PMD(PMD_CFB, ("%s: %s@%s(%s#%d)[%d] %d->%d "
			    "cfb_comps_off->%d\n", pmf, PM_DEVICE(dip),
			    comp, clevel, nlevel, pm_cfb_comps_off))
		}
		*errnop = EIO;
	}

post_notify:
	/*
	 * This thread may have been in deadlock with pm_power_has_changed.
	 * Before releasing power lock, clear the flag which marks this
	 * condition.
	 */
	cp->pmc_flags &= ~PM_PHC_WHILE_SET_POWER;

	/*
	 * Update the old power level in the bus power structure with the
	 * actual power level before the transition was made to the new level.
	 * Some involved parents depend on this information to keep track of
	 * their children's power transition.
	 */
	if (*iresp != DDI_FAILURE)
		bpc->bpc_olevel = clevel;

	if (PM_WANTS_NOTIFICATION(pdip)) {
		ret = (*PM_BUS_POWER_FUNC(pdip))(pdip, NULL,
		    BUS_POWER_POST_NOTIFICATION, bpc, resultp);
		PM_UNLOCK_POWER(dip, circ);
		PMD(PMD_SET, ("%s: post_notify %s@%s(%s#%d) for "
		    "child %s@%s(%s#%d), ret=%d\n", pmf, PM_DEVICE(pdip),
		    PM_DEVICE(dip), ret))
	} else {
		nlevel = cur_power(cp); /* in case phc deadlock updated pwr */
		PM_UNLOCK_POWER(dip, circ);
		/*
		 * Now that we know what power transition has occurred
		 * (if any), release the power hold.  Leave the hold
		 * in effect in the case of OFF->ON transition.
		 */
		if (!(clevel == 0 && nlevel > 0 &&
		    (!PM_ISBC(dip) || comp == 0)))
			pm_rele_power(pdip);
		/*
		 * If the power transition was an ON->OFF transition,
		 * remove the power hold from the parent.
		 */
		if ((clevel > 0 || clevel == PM_LEVEL_UNKNOWN) &&
		    nlevel == 0 && (!PM_ISBC(dip) || comp == 0))
			pm_rele_power(pdip);
	}
	if (*iresp != DDI_SUCCESS || ret != DDI_SUCCESS)
		return (DDI_FAILURE);
	else
		return (DDI_SUCCESS);
}

/*
 * If an app (SunVTS or Xsun) has taken control, then block until it
 * gives it up or makes the requested power level change, unless
 * we have other instructions about blocking.  Returns DDI_SUCCESS,
 * DDI_FAILURE or EAGAIN (owner released device from directpm).
 */
static int
pm_busop_match_request(dev_info_t *dip, void *arg)
{
	PMD_FUNC(pmf, "bp_match_request")
	pm_bp_child_pwrchg_t *bpc = (pm_bp_child_pwrchg_t *)arg;
	pm_sp_misc_t *pspm = (pm_sp_misc_t *)bpc->bpc_private;
	int comp = bpc->bpc_comp;
	int nlevel = bpc->bpc_nlevel;
	pm_canblock_t canblock = pspm->pspm_canblock;
	int direction = pspm->pspm_direction;
	int clevel, circ;

	ASSERT(PM_IAM_LOCKING_DIP(dip));
	PM_LOCK_POWER(dip, &circ);
	clevel = PM_CURPOWER(dip, comp);
	PMD(PMD_SET, ("%s: %s@%s(%s#%d), cmp=%d, nlvl=%d, clvl=%d\n",
	    pmf, PM_DEVICE(dip), comp, nlevel, clevel))
	if (direction == PM_LEVEL_UPONLY) {
		if (clevel >= nlevel) {
			PM_UNLOCK_POWER(dip, circ);
			PM_UNLOCK_DIP(dip);
			return (DDI_SUCCESS);
		}
	} else if (clevel == nlevel) {
		PM_UNLOCK_POWER(dip, circ);
		PM_UNLOCK_DIP(dip);
		return (DDI_SUCCESS);
	}
	if (canblock == PM_CANBLOCK_FAIL) {
		PM_UNLOCK_POWER(dip, circ);
		PM_UNLOCK_DIP(dip);
		return (DDI_FAILURE);
	}
	if (canblock == PM_CANBLOCK_BLOCK) {
		/*
		 * To avoid a deadlock, we must not hold the
		 * power lock when we pm_block.
		 */
		PM_UNLOCK_POWER(dip, circ);
		PMD(PMD_SET, ("%s: blocking\n", pmf))
		/* pm_block releases dip lock */
		switch (pm_block(dip, comp, nlevel, clevel)) {
		case PMP_RELEASE:
			return (EAGAIN);
		case PMP_SUCCEED:
			return (DDI_SUCCESS);
		case PMP_FAIL:
			return (DDI_FAILURE);
		}
	} else {
		ASSERT(0);
	}
	_NOTE(NOTREACHED);
	return (DDI_FAILURE);	/* keep gcc happy */
}

static int
pm_all_to_normal_nexus(dev_info_t *dip, pm_canblock_t canblock)
{
	PMD_FUNC(pmf, "all_to_normal_nexus")
	int		*normal;
	int		i, ncomps;
	size_t		size;
	int		changefailed = 0;
	int		ret, result = DDI_SUCCESS;
	pm_bp_nexus_pwrup_t	bpn;
	pm_sp_misc_t	pspm;

	ASSERT(PM_GET_PM_INFO(dip));
	PMD(PMD_ALLNORM, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	if (pm_get_norm_pwrs(dip, &normal, &size) != DDI_SUCCESS) {
		PMD(PMD_ALLNORM, ("%s: can't get norm pwrs\n", pmf))
		return (DDI_FAILURE);
	}
	ncomps = PM_NUMCMPTS(dip);
	for (i = 0; i < ncomps; i++) {
		bpn.bpn_dip = dip;
		bpn.bpn_comp = i;
		bpn.bpn_level = normal[i];
		pspm.pspm_canblock = canblock;
		pspm.pspm_scan = 0;
		bpn.bpn_private = &pspm;
		ret = pm_busop_bus_power(dip, NULL, BUS_POWER_NEXUS_PWRUP,
		    (void *)&bpn, (void *)&result);
		if (ret != DDI_SUCCESS || result != DDI_SUCCESS) {
			PMD(PMD_FAIL | PMD_ALLNORM, ("%s: %s@%s(%s#%d)[%d] "
			    "->%d failure result %d\n", pmf, PM_DEVICE(dip),
			    i, normal[i], result))
			changefailed++;
		}
	}
	kmem_free(normal, size);
	if (changefailed) {
		PMD(PMD_FAIL, ("%s: failed to set %d comps %s@%s(%s#%d) "
		    "full power\n", pmf, changefailed, PM_DEVICE(dip)))
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

int
pm_noinvol_update(int subcmd, int volpmd, int wasvolpmd, char *path,
    dev_info_t *tdip)
{
	PMD_FUNC(pmf, "noinvol_update")
	pm_bp_noinvol_t args;
	int ret;
	int result = DDI_SUCCESS;

	args.bpni_path = path;
	args.bpni_dip = tdip;
	args.bpni_cmd = subcmd;
	args.bpni_wasvolpmd = wasvolpmd;
	args.bpni_volpmd = volpmd;
	PMD(PMD_NOINVOL, ("%s: update for path %s tdip %p subcmd %d "
	    "volpmd %d wasvolpmd %d\n", pmf,
	    path, (void *)tdip, subcmd, wasvolpmd, volpmd))
	ret = pm_busop_bus_power(ddi_root_node(), NULL, BUS_POWER_NOINVOL,
	    &args, &result);
	return (ret);
}

void
pm_noinvol_update_node(dev_info_t *dip, pm_bp_noinvol_t *req)
{
	PMD_FUNC(pmf, "noinvol_update_node")

	PMD(PMD_NOINVOL, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	switch (req->bpni_cmd) {
	case PM_BP_NOINVOL_ATTACH:
		PMD(PMD_NOINVOL, ("%s: PM_PB_NOINVOL_ATTACH %s@%s(%s#%d) "
		    "noinvol %d->%d\n", pmf, PM_DEVICE(dip),
		    DEVI(dip)->devi_pm_noinvolpm,
		    DEVI(dip)->devi_pm_noinvolpm - 1))
		ASSERT(DEVI(dip)->devi_pm_noinvolpm);
		PM_LOCK_DIP(dip);
		DEVI(dip)->devi_pm_noinvolpm--;
		if (req->bpni_wasvolpmd) {
			PMD(PMD_NOINVOL, ("%s: PM_BP_NOINVOL_ATTACH "
			    "%s@%s(%s#%d) volpmd %d->%d\n", pmf,
			    PM_DEVICE(dip), DEVI(dip)->devi_pm_volpmd,
			    DEVI(dip)->devi_pm_volpmd - 1))
			if (DEVI(dip)->devi_pm_volpmd)
				DEVI(dip)->devi_pm_volpmd--;
		}
		PM_UNLOCK_DIP(dip);
		break;

	case PM_BP_NOINVOL_DETACH:
		PMD(PMD_NOINVOL, ("%s: PM_BP_NOINVOL_DETACH %s@%s(%s#%d) "
		    "noinvolpm %d->%d\n", pmf, PM_DEVICE(dip),
		    DEVI(dip)->devi_pm_noinvolpm,
		    DEVI(dip)->devi_pm_noinvolpm + 1))
		PM_LOCK_DIP(dip);
		DEVI(dip)->devi_pm_noinvolpm++;
		if (req->bpni_wasvolpmd) {
			PMD(PMD_NOINVOL, ("%s: PM_BP_NOINVOL_DETACH "
			    "%s@%s(%s#%d) volpmd %d->%d\n", pmf,
			    PM_DEVICE(dip), DEVI(dip)->devi_pm_volpmd,
			    DEVI(dip)->devi_pm_volpmd + 1))
			DEVI(dip)->devi_pm_volpmd++;
		}
		PM_UNLOCK_DIP(dip);
		break;

	case PM_BP_NOINVOL_REMDRV:
		PMD(PMD_NOINVOL, ("%s: PM_BP_NOINVOL_REMDRV %s@%s(%s#%d) "
		    "noinvol %d->%d\n", pmf, PM_DEVICE(dip),
		    DEVI(dip)->devi_pm_noinvolpm,
		    DEVI(dip)->devi_pm_noinvolpm - 1))
		ASSERT(DEVI(dip)->devi_pm_noinvolpm);
		PM_LOCK_DIP(dip);
		DEVI(dip)->devi_pm_noinvolpm--;
		if (req->bpni_wasvolpmd) {
			PMD(PMD_NOINVOL,
			    ("%s: PM_BP_NOINVOL_REMDRV %s@%s(%s#%d) "
			    "volpmd %d->%d\n", pmf, PM_DEVICE(dip),
			    DEVI(dip)->devi_pm_volpmd,
			    DEVI(dip)->devi_pm_volpmd - 1))
			/*
			 * A power up could come in between and
			 * clear the volpmd, if that's the case,
			 * volpmd would be clear.
			 */
			if (DEVI(dip)->devi_pm_volpmd)
				DEVI(dip)->devi_pm_volpmd--;
		}
		PM_UNLOCK_DIP(dip);
		break;

	case PM_BP_NOINVOL_CFB:
		PMD(PMD_NOINVOL,
		    ("%s: PM_BP_NOIVOL_CFB %s@%s(%s#%d) noinvol %d->%d\n",
		    pmf, PM_DEVICE(dip), DEVI(dip)->devi_pm_noinvolpm,
		    DEVI(dip)->devi_pm_noinvolpm + 1))
		PM_LOCK_DIP(dip);
		DEVI(dip)->devi_pm_noinvolpm++;
		PM_UNLOCK_DIP(dip);
		break;

	case PM_BP_NOINVOL_POWER:
		PMD(PMD_NOINVOL,
		    ("%s: PM_BP_NOIVOL_PWR %s@%s(%s#%d) volpmd %d->%d\n",
		    pmf, PM_DEVICE(dip),
		    DEVI(dip)->devi_pm_volpmd, DEVI(dip)->devi_pm_volpmd -
		    req->bpni_volpmd))
		PM_LOCK_DIP(dip);
		DEVI(dip)->devi_pm_volpmd -= req->bpni_volpmd;
		PM_UNLOCK_DIP(dip);
		break;

	default:
		break;
	}

}

#ifdef DEBUG
static int
pm_desc_pwrchk_walk(dev_info_t *dip, void *arg)
{
	PMD_FUNC(pmf, "desc_pwrchk")
	pm_desc_pwrchk_t *pdpchk = (pm_desc_pwrchk_t *)arg;
	pm_info_t *info = PM_GET_PM_INFO(dip);
	int i;
	/* LINTED */
	int curpwr, ce_level;

	if (!info)
		return (DDI_WALK_CONTINUE);

	PMD(PMD_SET, ("%s: %s@%s(%s#%d)\n", pmf, PM_DEVICE(dip)))
	for (i = 0; i < PM_NUMCMPTS(dip); i++) {
		/* LINTED */
		if ((curpwr = PM_CURPOWER(dip, i)) == 0)
			continue;
		/* E_FUNC_SET_NOT_USED */
		ce_level = (pdpchk->pdpc_par_involved == 0) ? CE_PANIC :
		    CE_WARN;
		PMD(PMD_SET, ("%s: %s@%s(%s#%d) is powered off while desc "
		    "%s@%s(%s#%d)[%d] is at %d\n", pmf,
		    PM_DEVICE(pdpchk->pdpc_dip), PM_DEVICE(dip), i, curpwr))
		cmn_err(ce_level, "!device %s@%s(%s#%d) is powered on, "
		    "while its ancestor, %s@%s(%s#%d), is powering off!",
		    PM_DEVICE(dip), PM_DEVICE(pdpchk->pdpc_dip));
	}
	return (DDI_WALK_CONTINUE);
}
#endif

/*
 * Record the fact that one thread is borrowing the lock on a device node.
 * Use is restricted to the case where the lending thread will block until
 * the borrowing thread (always curthread) completes.
 */
void
pm_borrow_lock(kthread_t *lender)
{
	lock_loan_t *prev = &lock_loan_head;
	lock_loan_t *cur = (lock_loan_t *)kmem_zalloc(sizeof (*cur), KM_SLEEP);

	cur->pmlk_borrower = curthread;
	cur->pmlk_lender = lender;
	mutex_enter(&pm_loan_lock);
	cur->pmlk_next = prev->pmlk_next;
	prev->pmlk_next = cur;
	mutex_exit(&pm_loan_lock);
}

/*
 * Return the borrowed lock.  A thread can borrow only one.
 */
void
pm_return_lock(void)
{
	lock_loan_t *cur;
	lock_loan_t *prev = &lock_loan_head;

	mutex_enter(&pm_loan_lock);
	ASSERT(prev->pmlk_next != NULL);
	for (cur = prev->pmlk_next; cur; prev = cur, cur = cur->pmlk_next)
		if (cur->pmlk_borrower == curthread)
			break;

	ASSERT(cur != NULL);
	prev->pmlk_next = cur->pmlk_next;
	mutex_exit(&pm_loan_lock);
	kmem_free(cur, sizeof (*cur));
}

#if defined(__x86)

#define	CPR_RXR	0x1
#define	CPR_TXR	0x20
#define	CPR_DATAREG	0x3f8
#define	CPR_LSTAT	0x3fd
#define	CPR_INTRCTL	0x3f9

char
pm_getchar(void)
{
	while ((inb(CPR_LSTAT) & CPR_RXR) != CPR_RXR)
		drv_usecwait(10);

	return (inb(CPR_DATAREG));

}

void
pm_putchar(char c)
{
	while ((inb(CPR_LSTAT) & CPR_TXR) == 0)
		drv_usecwait(10);

	outb(CPR_DATAREG, c);
}

void
pm_printf(char *s)
{
	while (*s) {
		pm_putchar(*s++);
	}
}

#endif

int
pm_ppm_searchlist(pm_searchargs_t *sp)
{
	power_req_t power_req;
	int result = 0;
	/* LINTED */
	int ret;

	power_req.request_type = PMR_PPM_SEARCH_LIST;
	power_req.req.ppm_search_list_req.searchlist = sp;
	ASSERT(DEVI(ddi_root_node())->devi_pm_ppm);
	ret = pm_ctlops((dev_info_t *)DEVI(ddi_root_node())->devi_pm_ppm,
	    ddi_root_node(), DDI_CTLOPS_POWER, &power_req, &result);
	PMD(PMD_SX, ("pm_ppm_searchlist returns %d, result %d\n",
	    ret, result))
	return (result);
}
