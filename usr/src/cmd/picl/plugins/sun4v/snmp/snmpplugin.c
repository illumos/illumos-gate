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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The SNMP picl plugin connects to the agent on the SP and creates
 * and populates the /physical-platform subtree in picl tree for use
 * by picl consumers.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <libgen.h>
#include <libintl.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <time.h>
#include <signal.h>

#include <picldefs.h>
#include <picl.h>
#include <picltree.h>

#include "picloids.h"
#include "libpiclsnmp.h"
#include "snmpplugin.h"

#pragma init(snmpplugin_register)	/* place in .init section */

picld_plugin_reg_t snmpplugin_reg = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"snmp_plugin",
	snmpplugin_init,
	snmpplugin_fini
};

static picl_snmphdl_t	hdl;

/*
 * The stale_tree_rwlp protects the stale_xxx vars. The 'stale_tree' flag
 * and the 'rebuild_tree' flag below are both initialized to B_TRUE to
 * let the tree_builder() thread build the initial tree without blocking.
 */
static rwlock_t		stale_tree_rwlp;
static boolean_t	stale_tree = B_TRUE;

/*
 * vol_props, volprop_ndx and n_vol_props are protected by the stale_tree
 * flag.  They are read only when the stale_tree flag is B_FALSE and written
 * to only when the flag is B_TRUE.
 *
 * The change_time (last changed time) is read by only one thread at a
 * time when stale_tree is B_FALSE (protected by stale_tree_rwlp).  It is
 * written by only one thread (the tree builder) when stale_tree is B_TRUE.
 *
 * Note that strictly speaking, change_time should be uint_t (timeticks32).
 * But keeping it as int is fine, since we don't do any arithmetic on it
 * except equality check.
 */
static vol_prophdl_t	*vol_props = NULL;
static int		volprop_ndx = 0, n_vol_props = 0;
static int		change_time = 0;
static time_t		change_time_check;

/*
 * The rebuild_tree_lock and cv are used by the tree builder thread.
 * rebuild_tree has to be initialized to B_TRUE to let the tree_builder
 * do the first build without blocking.
 */
static mutex_t		rebuild_tree_lock;
static cond_t		rebuild_tree_cv;
static boolean_t	rebuild_tree = B_TRUE;
static boolean_t	tree_builder_thr_exit = B_FALSE;
static thread_t		tree_builder_thr_id;

/*
 * The cache_refresh thread periodically queries the snmp cache refresh work
 * queue and processes jobs from it to keep cache entries from expiring.  It
 * attempts to run in cycles of CACHE_REFRESH_CYCLE seconds each, first
 * processing cache refresh jobs and then sleeping for the remainder of the
 * cycle once the next refresh job expiration is at least
 * CACHE_REFRESH_MIN_WINDOW seconds in the future.
 *
 * NOTE: By using a thread to keep the SNMP cache refreshed in the background,
 * we are both adding load to the system and reducing the system's ability to
 * operate in power-saving mode when there is minimal load.  While these
 * tradeoffs are acceptable at this time in light of customer concerns about
 * performance, it may be desirable in the future to move this work into the
 * firmware.  Also, while the current cycle times performed well on the largest
 * sun4v config currently available (Batoka), they may need to be revisited for
 * future systems if the number of sensors increases significantly.
 */
#define	CACHE_REFRESH_CYCLE		60
#define	CACHE_REFRESH_MIN_WINDOW	75
static mutex_t		cache_refresh_lock;
static cond_t		cache_refresh_cv;
static boolean_t	cache_refresh_thr_exit = B_FALSE;
static thread_t		cache_refresh_thr_id;

/*
 * These two should really not be global
 */
static picl_nodehdl_t	*physplat_nodes = NULL;
static int		n_physplat_nodes = 0;

static char *group1[] = {
	OID_entPhysicalDescr,
	OID_entPhysicalContainedIn,
	OID_entPhysicalClass,
	OID_entPhysicalName,
	OID_entPhysicalHardwareRev,
	OID_entPhysicalFirmwareRev,
	OID_entPhysicalSerialNum,
	OID_entPhysicalMfgName,
	OID_entPhysicalModelName,
	OID_entPhysicalIsFRU,
	0
};

static char *group2[] = {
	OID_sunPlatEquipmentHolderAcceptableTypes,
	OID_sunPlatCircuitPackReplaceable,
	OID_sunPlatCircuitPackHotSwappable,
	OID_sunPlatPhysicalClass,
	OID_sunPlatSensorClass,
	OID_sunPlatSensorType,
	OID_sunPlatAlarmType,
	OID_sunPlatPowerSupplyClass,
	0
};

static char *group3[] = {
	OID_sunPlatNumericSensorEnabledThresholds,
	OID_sunPlatNumericSensorBaseUnits,
	OID_sunPlatNumericSensorRateUnits,
	0
};

static char *group4[] = {
	OID_sunPlatBinarySensorInterpretTrue,
	OID_sunPlatBinarySensorInterpretFalse,
	0
};

static char *volgroup1[] = {
	OID_sunPlatBinarySensorCurrent,
	OID_sunPlatBinarySensorExpected,
	0
};

static char *volgroup2[] = {
	OID_sunPlatNumericSensorExponent,
	OID_sunPlatNumericSensorCurrent,
	OID_sunPlatNumericSensorLowerThresholdFatal,
	OID_sunPlatNumericSensorLowerThresholdCritical,
	OID_sunPlatNumericSensorLowerThresholdNonCritical,
	OID_sunPlatNumericSensorUpperThresholdNonCritical,
	OID_sunPlatNumericSensorUpperThresholdCritical,
	OID_sunPlatNumericSensorUpperThresholdFatal,
	0
};

static char *volgroup3[] = {
	OID_sunPlatEquipmentOperationalState,
	0
};

static char *volgroup4[] = {
	OID_sunPlatAlarmState,
	0
};

static char *volgroup5[] = {
	OID_sunPlatBatteryStatus,
	0
};

/*
 * The following two items must match the Sun Platform MIB specification
 * in their indices and values.
 */
static char *sensor_baseunits[] = {
	"", "other", "unknown", "degC", "degF", "degK", "volts", "amps",
	"watts", "joules", "coulombs", "va", "nits", "lumens", "lux",
	"candelas", "kPa", "psi", "newtons", "cfm", "rpm", "hertz",
	"seconds", "minutes", "hours", "days", "weeks", "mils", "inches",
	"feet", "cubicInches", "cubicFeet", "meters", "cubicCentimeters",
	"cubicMeters", "liters", "fluidOunces", "radians", "steradians",
	"revolutions", "cycles", "gravities", "ounces", "pounds", "footPounds",
	"ounceInches", "gauss", "gilberts", "henries", "farads", "ohms",
	"siemens", "moles", "becquerels", "ppm", "decibels", "dBA", "dbC",
	"grays", "sieverts", "colorTemperatureDegK", "bits", "bytes", "words",
	"doubleWords", "quadWords", "percentage"
};
static const int n_baseunits = sizeof (sensor_baseunits) / sizeof (char *);

static char *sensor_rateunits[] = {
	"",
	"none",
	"perMicroSecond",
	"perMilliSecond",
	"perSecond",
	"perMinute",
	"perHour",
	"perDay",
	"perWeek",
	"perMonth",
	"perYear"
};
static const int n_rateunits = sizeof (sensor_rateunits) / sizeof (char *);

/*
 * Local declarations
 */
static void snmpplugin_register(void);
static void register_group(char **g, int is_volatile);
static void *tree_builder(void *arg);
static int build_physplat(picl_nodehdl_t *subtree_rootp);
static void free_resources(picl_nodehdl_t subtree_root);

static picl_nodehdl_t make_node(picl_nodehdl_t subtree_root, int row,
    int *snmp_syserr_p);
static void save_nodeh(picl_nodehdl_t nodeh, int row);
static picl_nodehdl_t lookup_nodeh(int row);

static void save_volprop(picl_prophdl_t prop, char *oidstr, int row,
    int proptype);
static void check_for_stale_data(boolean_t nocache);
static int read_volprop(ptree_rarg_t *parg, void *buf);

static void threshold(picl_nodehdl_t node, char *oidstr, int row,
    char *propname, int *snmp_syserr_p);
static void add_thresholds(picl_nodehdl_t node, int row, int *snmp_syserr_p);

static char *get_slot_type(int row, int *snmp_syserr_p);
static int add_volatile_prop(picl_nodehdl_t nodeh, char *name,
    int type, int access, int size, int (*rdfunc)(ptree_rarg_t *, void *),
    int (*wrfunc)(ptree_warg_t *, const void *), picl_prophdl_t *propp);
static int add_string_prop(picl_nodehdl_t node, char *propname, char *propval);
static int add_void_prop(picl_nodehdl_t node, char *propname);
static void add_prop(picl_nodehdl_t nodeh, picl_prophdl_t *php, char *label,
    int row, sp_propid_t pp, int *snmp_syserr_p);

static void *cache_refresher(void *arg);
static void cache_refresher_fini(void);

static void log_msg(int pri, const char *fmt, ...);

#ifdef SNMPPLUGIN_DEBUG
static mutex_t	snmpplugin_dbuf_lock;
static char	*snmpplugin_dbuf = NULL;
static char	*snmpplugin_dbuf_curp = NULL;
static int	snmpplugin_dbuf_sz = 0;
static int	snmpplugin_dbuf_overflow = 0;
static char	snmpplugin_lbuf[SNMPPLUGIN_DMAX_LINE];

static void	snmpplugin_log_init(void);
static void	snmpplugin_log(const char *fmt, ...);
static void	snmpplugin_log_append(void);
static void	snmpplugin_dbuf_realloc(void);
#endif

static void
snmpplugin_register(void)
{
	(void) picld_plugin_register(&snmpplugin_reg);
}

static void
register_group(char **g, int is_volatile)
{
	int	i, len = 0;
	int	n_oids;
	char	*p, *oidstrs;

	for (i = 0; g[i]; i++)
		len += strlen(g[i]) + 1;
	n_oids = i;

	if ((oidstrs = (char *)calloc(1, len)) == NULL)
		return;

	for (p = oidstrs, i = 0; g[i]; i++) {
		(void) strcpy(p, g[i]);
		p += strlen(g[i]) + 1;
	}

	snmp_register_group(hdl, oidstrs, n_oids, is_volatile);
	free(oidstrs);
}

void
snmpplugin_init(void)
{
	int		ret;

	(void) mutex_init(&rebuild_tree_lock, USYNC_THREAD, NULL);
	(void) cond_init(&rebuild_tree_cv, USYNC_THREAD, NULL);
	(void) rwlock_init(&stale_tree_rwlp, USYNC_THREAD, NULL);
	tree_builder_thr_exit = B_FALSE;

	LOGINIT();

	/*
	 * Create the tree-builder thread and let it take over
	 */
	LOGPRINTF("Tree-builder thread being created.\n");
	if ((ret = thr_create(NULL, 0, tree_builder, NULL,
	    THR_BOUND, &tree_builder_thr_id)) < 0) {
		log_msg(LOG_ERR, SNMPP_CANT_CREATE_TREE_BUILDER, ret);
		snmp_fini(hdl);
		hdl = NULL;
		(void) rwlock_destroy(&stale_tree_rwlp);
		(void) cond_destroy(&rebuild_tree_cv);
		(void) mutex_destroy(&rebuild_tree_lock);
		tree_builder_thr_exit = B_TRUE;

		return;
	}

	/*
	 * While the cache refresher thread does improve performance, it is not
	 * integral to the proper function of the plugin.  If we fail to create
	 * the thread for some reason, we will simply continue without
	 * refreshing.
	 */
	(void) mutex_init(&cache_refresh_lock, USYNC_THREAD, NULL);
	(void) cond_init(&cache_refresh_cv, USYNC_THREAD, NULL);
	cache_refresh_thr_exit = B_FALSE;

	LOGPRINTF("Cache refresher thread being created.\n");
	if (thr_create(NULL, 0, cache_refresher, NULL, THR_BOUND,
	    &cache_refresh_thr_id) < 0) {
		(void) cond_destroy(&cache_refresh_cv);
		(void) mutex_destroy(&cache_refresh_lock);
		cache_refresh_thr_exit = B_TRUE;
	}
}

void
snmpplugin_fini(void)
{

	if (tree_builder_thr_exit == B_TRUE)
		return;

	/*
	 * Make reads of volatile properties return PICL_PROPUNAVAILABLE
	 * since we're about to recycle the plug-in.  No need to worry
	 * about removing /physical-platform since tree_builder() will
	 * take care of recycling it for us.
	 */
	(void) rw_wrlock(&stale_tree_rwlp);
	stale_tree = B_TRUE;
	if (vol_props) {
		free(vol_props);
	}
	vol_props = NULL;
	volprop_ndx = 0;
	n_vol_props = 0;
	(void) rw_unlock(&stale_tree_rwlp);

	/* clean up the cache_refresher thread and structures */
	cache_refresher_fini();

	/* wake up the tree_builder thread, tell it to exit */
	(void) mutex_lock(&rebuild_tree_lock);
	rebuild_tree = B_TRUE;
	tree_builder_thr_exit = B_TRUE;
	(void) cond_signal(&rebuild_tree_cv);
	(void) mutex_unlock(&rebuild_tree_lock);

	/* send SIGUSR1 to get tree_builder out of a blocked system call */
	(void) thr_kill(tree_builder_thr_id, SIGUSR1);

	/* reap the thread */
	(void) thr_join(tree_builder_thr_id, NULL, NULL);

	/* close the channel */
	if (hdl != NULL) {
		snmp_fini(hdl);
		hdl = NULL;
	}

	/* finish cleanup... */
	(void) rwlock_destroy(&stale_tree_rwlp);
	(void) cond_destroy(&rebuild_tree_cv);
	(void) mutex_destroy(&rebuild_tree_lock);
}

/*ARGSUSED*/
static void
usr1_handler(int sig, siginfo_t *siginfo, void *sigctx)
{
	/*
	 * Nothing to do here.
	 * The act of catching the signal causes any cond_wait() or blocked
	 * system call to return EINTR. This is used to trigger early exit from
	 * the tree builder thread which may be blocked in snmp_init. More work
	 * would be required to allow early exit if the tree builder thread is
	 * already in its main processing loop and not blocked in cond_wait.
	 */
}

/*ARGSUSED*/
static void *
tree_builder(void *arg)
{
	int		ret, rv;
	picl_nodehdl_t	root_node;
	picl_nodehdl_t	physplat_root;
	picl_nodehdl_t	old_physplat_root;
	struct sigaction	act;

	/*
	 * catch SIGUSR1 to allow early exit from snmp_init which may block
	 * indefinitely in a guest domain.
	 */
	act.sa_sigaction = usr1_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGUSR1, &act, NULL) == -1) {
		syslog(LOG_ERR, SIGACT_FAILED, strsignal(SIGUSR1),
		    strerror(errno));
	}

	/*
	 * Initialize SNMP service
	 */
	LOGPRINTF("Initializing SNMP service.\n");
	if ((hdl = snmp_init()) == NULL) {
		log_msg(LOG_ERR, SNMPP_CANT_INIT);
		return ((void *)-1);
	}

	/*
	 * Register OID groupings for BULKGET optimizations
	 */
	LOGPRINTF("Registering OID groups.\n");
	register_group(group1, 0);
	register_group(group2, 0);
	register_group(group3, 0);
	register_group(group4, 0);
	register_group(volgroup1, 1);
	register_group(volgroup2, 1);
	register_group(volgroup3, 1);
	register_group(volgroup4, 1);
	register_group(volgroup5, 1);

	(void) mutex_lock(&rebuild_tree_lock);

	for (;;) {
		LOGPRINTF("tree_builder: check whether to rebuild subtree\n");
		while (rebuild_tree == B_FALSE)
			(void) cond_wait(&rebuild_tree_cv, &rebuild_tree_lock);

		LOGPRINTF("tree_builder: woke up\n");

		if (tree_builder_thr_exit == B_TRUE) {
			(void) mutex_unlock(&rebuild_tree_lock);
			LOGPRINTF("tree_builder: time to exit\n");
			return (NULL);
		}

		old_physplat_root = 0;
		physplat_root = 0;

		LOGPRINTF("tree_builder: getting root node\n");
		if ((ret = ptree_get_root(&root_node)) != PICL_SUCCESS) {
			(void) mutex_unlock(&rebuild_tree_lock);
			log_msg(LOG_ERR, SNMPP_NO_ROOT, ret);
			return ((void *)-2);
		}

		LOGPRINTF("tree_builder: getting existing physplat node\n");
		rv = ptree_find_node(root_node, PICL_PROP_NAME,
		    PICL_PTYPE_CHARSTRING, PICL_NODE_PHYSPLAT,
		    sizeof (PICL_NODE_PHYSPLAT), &old_physplat_root);

		LOGPRINTF("tree_builder: building physical-platform\n");
		if ((ret = build_physplat(&physplat_root)) < 0) {
			(void) mutex_unlock(&rebuild_tree_lock);
			log_msg(LOG_ERR, SNMPP_CANT_CREATE_PHYSPLAT, ret);
			cache_refresher_fini();
			snmp_fini(hdl);
			hdl = NULL;
			return ((void *)-3);
		}

		if (rv == PICL_SUCCESS && old_physplat_root != 0) {
			LOGPRINTF("tree_builder: destroying existing nodes\n");
			ptree_delete_node(old_physplat_root);
			ptree_destroy_node(old_physplat_root);
		}

		LOGPRINTF("tree_builder: attaching new subtree\n");
		if ((ret = ptree_add_node(root_node, physplat_root)) < 0) {
			(void) mutex_unlock(&rebuild_tree_lock);
			free_resources(physplat_root);
			log_msg(LOG_ERR, SNMPP_CANT_CREATE_PHYSPLAT, ret);
			cache_refresher_fini();
			snmp_fini(hdl);
			hdl = NULL;
			return ((void *)-4);
		}

		LOGPRINTF("tree_builder: setting stale_tree to FALSE\n");
		(void) rw_wrlock(&stale_tree_rwlp);
		stale_tree = B_FALSE;
		(void) rw_unlock(&stale_tree_rwlp);

		LOGPRINTF("tree_builder: setting rebuild_tree to FALSE\n");
		rebuild_tree = B_FALSE;
	}

	/*NOTREACHED*/
	return (NULL);
}

static int
build_physplat(picl_nodehdl_t *subtree_rootp)
{
	int	change_time1;
	int	row, nxtrow;
	int	clr_linkreset = 0;
	int	ret = 0;
	int	snmp_syserr = 0;

retry:
	(void) snmp_reinit(hdl, clr_linkreset);
	clr_linkreset = 0;

	/*
	 * Record LastChangeTime before we start building the tree
	 */
	ret = snmp_get_int(hdl, OID_entLastChangeTime, 0,
	    &change_time1, &snmp_syserr);
	if (ret < 0) {
		if (snmp_syserr == ECANCELED) {
			LOGPRINTF(SNMPP_LINK_RESET);
			clr_linkreset = 1;
			goto retry;
		}
		log_msg(LOG_WARNING, SNMPP_CANT_FETCH_OBJECT_VAL,
		    snmp_syserr ? snmp_syserr : ret, OID_entLastChangeTime, 0);
	}

	/*
	 * Create the physical-platform node
	 */
	ret = ptree_create_node(PICL_NODE_PHYSPLAT, PICL_CLASS_PICL,
	    subtree_rootp);
	if (ret != PICL_SUCCESS)
		return (-1);

	/*
	 * Scan entPhysicalTable and build the "physical-platform" subtree
	 */
	ret = 0;
	for (row = -1; ret == 0; row = nxtrow) {
		ret = snmp_get_nextrow(hdl, OID_entPhysicalDescr,
		    row, &nxtrow, &snmp_syserr);
		if (ret == 0)
			(void) make_node(*subtree_rootp, nxtrow, &snmp_syserr);
		switch (snmp_syserr) {
		case ECANCELED:
			/*
			 * If we get this error, a link reset must've
			 * happened and we need to throw away everything
			 * we have now and rebuild the tree again.
			 */
			log_msg(LOG_WARNING, SNMPP_LINK_RESET);
			free_resources(*subtree_rootp);
			clr_linkreset = 1;
			goto retry;
			/*NOTREACHED*/
			break;
		case ENOSPC:	/* end of MIB */
			LOGPRINTF("build_physplat: end of MIB\n");
			break;
		case ENOENT:	/* end of table */
			LOGPRINTF("build_physplat: end of table\n");
			break;
		default:
			/*
			 * make_node() will print messages so don't
			 * repeat that exercise here.
			 */
			if (ret == -1) {
				log_msg(LOG_WARNING,
				    SNMPP_CANT_FETCH_OBJECT_VAL,
				    snmp_syserr ? snmp_syserr : ret,
				    OID_entPhysicalDescr, row);
			}
		}
	}

	/*
	 * Record LastChangeTime after we're done building the tree
	 */
	ret = snmp_get_int(hdl, OID_entLastChangeTime, 0,
	    &change_time, &snmp_syserr);
	if (ret < 0) {
		if (snmp_syserr == ECANCELED) {
			log_msg(LOG_WARNING, SNMPP_LINK_RESET);
			free_resources(*subtree_rootp);
			clr_linkreset = 1;
			goto retry;
		} else
			log_msg(LOG_WARNING, SNMPP_CANT_FETCH_OBJECT_VAL,
			    snmp_syserr ? snmp_syserr : ret,
			    OID_entLastChangeTime, row);
	}

	/*
	 * If they don't match, some hotplugging must've happened,
	 * free resources we've created and still holding, then go
	 * back and retry
	 */
	if (change_time != change_time1) {
		LOGPRINTF("build_physplat: entLastChangeTime has changed!\n");
		free_resources(*subtree_rootp);
		change_time1 = change_time;
		goto retry;
	}

	/*
	 * The physplat_nodes table is no longer needed, free it
	 */
	if (physplat_nodes) {
		free(physplat_nodes);
		physplat_nodes = NULL;
		n_physplat_nodes = 0;
	}

	return (0);
}

/*
 * Destroy all resources that were created during the building
 * of the subtree
 */
static void
free_resources(picl_nodehdl_t subtree_root)
{
	if (physplat_nodes) {
		free(physplat_nodes);
		physplat_nodes = NULL;
		n_physplat_nodes = 0;
	}

	if (subtree_root) {
		(void) ptree_delete_node(subtree_root);
		(void) ptree_destroy_node(subtree_root);
	}

	if (vol_props) {
		free(vol_props);
		vol_props = NULL;
		n_vol_props = 0;
		volprop_ndx = 0;
	}
}

static picl_nodehdl_t
make_node(picl_nodehdl_t subtree_root, int row, int *snmp_syserr_p)
{
	picl_nodehdl_t	nodeh, parenth;
	picl_prophdl_t	proph;
	char	*phys_name, *node_name;
	int	parent_row;
	int	ent_physclass, sunplat_physclass;
	int	sensor_class, sensor_type;
	int	alarm_type;
	int	ps_class;
	int	ret;

	/*
	 * If we've already created this picl node, just return it
	 */
	if ((nodeh = lookup_nodeh(row)) != 0)
		return (nodeh);

	/*
	 * If we are creating it only now, make sure we have the parent
	 * created first; if there's no parent, then parent it to the
	 * subtree's root node
	 */
	ret = snmp_get_int(hdl, OID_entPhysicalContainedIn, row,
	    &parent_row, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)
	if (ret < 0 || parent_row <= 0)
		parenth = subtree_root;
	else {
		parenth = make_node(subtree_root, parent_row, snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		if (parenth == 0)
			parenth = subtree_root;
	}

	/*
	 * Figure out the physical-platform node name from entPhysicalName;
	 * all rows in the MIB that have a valid entPhysicalIndex should
	 * have a physical name.
	 */
	ret = snmp_get_str(hdl, OID_entPhysicalName, row,
	    &phys_name, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)
	if (ret < 0 || phys_name == NULL) {
		log_msg(LOG_WARNING, SNMPP_NO_ENTPHYSNAME, row);
		return (0);
	}

	node_name = basename(phys_name);

	ret = snmp_get_int(hdl, OID_entPhysicalClass, row,
	    &ent_physclass, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)
	if (ret < 0) {
		log_msg(LOG_WARNING, SNMPP_CANT_FETCH_OBJECT_VAL,
		    *snmp_syserr_p ? *snmp_syserr_p : ret,
		    OID_entPhysicalClass, row);
		free(phys_name);
		return (0);
	}

	switch (ent_physclass) {
	case SPC_OTHER:
		ret = snmp_get_int(hdl, OID_sunPlatPhysicalClass, row,
		    &sunplat_physclass, snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		if (ret < 0) {
			log_msg(LOG_WARNING, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatPhysicalClass, row);
			free(phys_name);
			return (0);
		}

		if (sunplat_physclass == SSPC_ALARM) {
			ret = snmp_get_int(hdl, OID_sunPlatAlarmType,
			    row, &alarm_type, snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)
			if (ret < 0) {
				log_msg(LOG_WARNING,
				    SNMPP_CANT_FETCH_OBJECT_VAL,
				    *snmp_syserr_p ? *snmp_syserr_p : ret,
				    OID_sunPlatAlarmType, row);
				free(phys_name);
				return (0);
			}

			if (alarm_type == SSAT_VISIBLE) {
				ADD_NODE(PICL_CLASS_LED)
			} else {
				ADD_NODE(PICL_CLASS_ALARM)
			}

			add_prop(nodeh, &proph, node_name, row, PP_STATE,
			    snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)
		} else {
			ADD_NODE(PICL_CLASS_OTHER)
		}

		add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		break;

	case SPC_UNKNOWN:
		ADD_NODE(PICL_CLASS_UNKNOWN)
		break;

	case SPC_CHASSIS:
		ADD_NODE(PICL_CLASS_CHASSIS)
		add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		break;

	case SPC_BACKPLANE:
		ADD_NODE(PICL_CLASS_BACKPLANE)
		add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		break;

	case SPC_CONTAINER:
		ADD_NODE(PICL_CLASS_CONTAINER)

		add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)

		add_prop(nodeh, &proph, node_name, row, PP_SLOT_TYPE,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		break;

	case SPC_POWERSUPPLY:
		ret = snmp_get_int(hdl, OID_sunPlatPowerSupplyClass,
		    row, &ps_class, snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		if (ret < 0) {
			log_msg(LOG_WARNING, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatPowerSupplyClass, row);
			free(phys_name);
			return (0);
		}

		if (ps_class == SSPSC_BATTERY) {
			ADD_NODE(PICL_CLASS_BATTERY)
			add_prop(nodeh, &proph, node_name, row,
			    PP_BATT_STATUS, snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)
		} else {
			ADD_NODE(PICL_CLASS_POWERSUPPLY)
		}
		add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		break;

	case SPC_FAN:
		ADD_NODE(PICL_CLASS_FAN)
		add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		break;

	case SPC_SENSOR:
		ret = snmp_get_int(hdl, OID_sunPlatSensorClass,
		    row, &sensor_class, snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		if (ret < 0) {
			log_msg(LOG_WARNING, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatSensorClass, row);
			free(phys_name);
			return (0);
		}

		ret = snmp_get_int(hdl, OID_sunPlatSensorType,
		    row, &sensor_type, snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		if (ret < 0) {
			log_msg(LOG_WARNING, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatSensorType, row);
			free(phys_name);
			return (0);
		}

		if (sensor_class == SSSC_NUMERIC) {
			if (sensor_type == SSST_TEMPERATURE) {
				ADD_NODE(PICL_CLASS_TEMPERATURE_SENSOR)
				add_prop(nodeh, &proph, node_name, row,
				    PP_TEMPERATURE, snmp_syserr_p);
			} else if (sensor_type == SSST_VOLTAGE) {
				ADD_NODE(PICL_CLASS_VOLTAGE_SENSOR)
				add_prop(nodeh, &proph, node_name, row,
				    PP_VOLTAGE, snmp_syserr_p);
			} else if (sensor_type == SSST_CURRENT) {
				ADD_NODE(PICL_CLASS_CURRENT_SENSOR)
				add_prop(nodeh, &proph, node_name, row,
				    PP_CURRENT, snmp_syserr_p);
			} else if (sensor_type == SSST_TACHOMETER) {
				ADD_NODE(PICL_CLASS_RPM_SENSOR)
				add_prop(nodeh, &proph, node_name, row,
				    PP_SPEED, snmp_syserr_p);
			} else {
				ADD_NODE(PICL_CLASS_SENSOR)
				add_prop(nodeh, &proph, node_name, row,
				    PP_SENSOR_VALUE, snmp_syserr_p);
			}
			CHECK_LINKRESET(snmp_syserr_p, 0)

			add_prop(nodeh, &proph, node_name, row,
			    PP_OPSTATUS, snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)

			add_prop(nodeh, &proph, node_name, row,
			    PP_BASE_UNITS, snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)

			add_prop(nodeh, &proph, node_name, row,
			    PP_EXPONENT, snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)

			add_prop(nodeh, &proph, node_name, row,
			    PP_RATE_UNITS, snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)

			add_thresholds(nodeh, row, snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)

		} else if (sensor_class == SSSC_BINARY) {
			if (sensor_type == SSST_TEMPERATURE) {
				ADD_NODE(PICL_CLASS_TEMPERATURE_INDICATOR)
			} else if (sensor_type == SSST_VOLTAGE) {
				ADD_NODE(PICL_CLASS_VOLTAGE_INDICATOR)
			} else if (sensor_type == SSST_CURRENT) {
				ADD_NODE(PICL_CLASS_CURRENT_INDICATOR)
			} else if (sensor_type == SSST_TACHOMETER) {
				ADD_NODE(PICL_CLASS_RPM_INDICATOR)
			} else if (sensor_type == SSST_PRESENCE) {
				ADD_NODE(PICL_CLASS_PRESENCE_INDICATOR)
			} else {
				ADD_NODE(PICL_CLASS_INDICATOR)
			}

			add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
			    snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)

			add_prop(nodeh, &proph, node_name, row, PP_CONDITION,
			    snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)

			add_prop(nodeh, &proph, node_name, row, PP_EXPECTED,
			    snmp_syserr_p);
			CHECK_LINKRESET(snmp_syserr_p, 0)
		} else {
			log_msg(LOG_ERR,
			    SNMPP_UNSUPP_SENSOR_CLASS, sensor_class, row);
			return (0);
		}
		break;

	case SPC_MODULE:
		ADD_NODE(PICL_CLASS_MODULE)

		add_prop(nodeh, &proph, node_name, row, PP_OPSTATUS,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)

		add_prop(nodeh, &proph, node_name, row, PP_REPLACEABLE,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)

		add_prop(nodeh, &proph, node_name, row, PP_HOTSWAPPABLE,
		    snmp_syserr_p);
		CHECK_LINKRESET(snmp_syserr_p, 0)
		break;

	case SPC_PORT:
		ADD_NODE(PICL_CLASS_PORT)
		break;

	case SPC_STACK:
		ADD_NODE(PICL_CLASS_STACK)
		break;

	default:
		log_msg(LOG_WARNING,
		    SNMPP_UNKNOWN_ENTPHYSCLASS, ent_physclass, row);
		free(phys_name);
		return (0);
	}

	add_prop(nodeh, &proph, node_name, row, PP_DESCRIPTION, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	add_prop(nodeh, &proph, node_name, row, PP_LABEL, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	add_prop(nodeh, &proph, node_name, row, PP_HW_REVISION, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	add_prop(nodeh, &proph, node_name, row, PP_FW_REVISION, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	add_prop(nodeh, &proph, node_name, row, PP_SERIAL_NUM, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	add_prop(nodeh, &proph, node_name, row, PP_MFG_NAME, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	add_prop(nodeh, &proph, node_name, row, PP_MODEL_NAME, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	add_prop(nodeh, &proph, node_name, row, PP_IS_FRU, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, 0)

	free(phys_name);
	save_nodeh(nodeh, row);

	return (nodeh);
}

/*
 * Saves the node handle and the row id into physplat_nodes[]. If we're
 * doing this in response to a hotplug event, we should've freed the
 * old physplat_nodes before entering here to save the first node of the
 * new physplat subtree.
 */
static void
save_nodeh(picl_nodehdl_t nodeh, int row)
{
	size_t		sz, count;
	picl_nodehdl_t	*p;

	if (row >= n_physplat_nodes) {
		count = (((size_t)row >> NODE_BLOCK_SHIFT) + 1) *
		    N_ELEMS_IN_NODE_BLOCK;
		sz = count * sizeof (picl_nodehdl_t);

		p = (picl_nodehdl_t *)calloc(count, sizeof (picl_nodehdl_t));
		if (p == NULL) {
			log_msg(LOG_ERR, SNMPP_NO_MEM, sz);
			return;
		}

		if (physplat_nodes) {
			(void) memcpy((void *) p, (void *) physplat_nodes,
			    n_physplat_nodes * sizeof (picl_nodehdl_t));
			free((void *) physplat_nodes);
		}

		physplat_nodes = p;
		n_physplat_nodes = count;
	}

	physplat_nodes[row] = nodeh;
}

static picl_nodehdl_t
lookup_nodeh(int row)
{
	if (row >= n_physplat_nodes)
		return (0);

	return (physplat_nodes[row]);
}

/*
 * We enter this routine only when we are building the physical-platform
 * subtree, whether for the first time or in response to a hotplug event.
 * If we're here for rebuilding the tree, we have already set stale_tree
 * to be B_TRUE, so no one else would be accessing vol_props, n_vol_props
 * or volprop_ndx. If we're here to build the tree for the first time,
 * picld hasn't yet created doors and is running single-threaded, so no
 * one else would be accessing them anyway.
 */
static void
save_volprop(picl_prophdl_t prop, char *oidstr, int row, int proptype)
{
	vol_prophdl_t	*p;
	int		count;

	if (volprop_ndx == n_vol_props) {
		count = n_vol_props + N_ELEMS_IN_VOLPROP_BLOCK;
		p = (vol_prophdl_t *)calloc(count, sizeof (vol_prophdl_t));
		if (p == NULL) {
			log_msg(LOG_ERR, SNMPP_NO_MEM,
			    count * sizeof (vol_prophdl_t));
			return;
		}

		if (vol_props) {
			(void) memcpy((void *) p, (void *) vol_props,
			    n_vol_props * sizeof (vol_prophdl_t));
			free((void *) vol_props);
		}

		vol_props = p;
		n_vol_props += N_ELEMS_IN_VOLPROP_BLOCK;
	}

	vol_props[volprop_ndx].prop = prop;
	vol_props[volprop_ndx].oidstr = oidstr;
	vol_props[volprop_ndx].row = row;
	vol_props[volprop_ndx].proptype = proptype;

	volprop_ndx++;
}

static void
check_for_stale_data(boolean_t nocache)
{
	int	cur_change_time;
	int	ret;
	int	snmp_syserr;

	(void) rw_wrlock(&stale_tree_rwlp);

	/*
	 * Check if some other thread beat us to it
	 */
	if (stale_tree == B_TRUE) {
		(void) rw_unlock(&stale_tree_rwlp);
		return;
	}

	/*
	 * Cache OID_entLastChangeTime for up to 10 seconds before
	 * fetching it from ILOM again.  This prevents us from fetching
	 * this value from ILOM when the we're filling or refreshing a
	 * whole bunch of items in the cache around the same time.
	 */
	if (nocache == B_FALSE && time(NULL) - change_time_check <= 10) {
		(void) rw_unlock(&stale_tree_rwlp);
		return;
	}

	/*
	 * Check if mib data has changed (hotplug? link-reset?)
	 */
	do {
		snmp_syserr = 0;
		ret = snmp_get_int(hdl, OID_entLastChangeTime, 0,
		    &cur_change_time, &snmp_syserr);
		(void) time(&change_time_check);
		if ((ret == 0) && (cur_change_time == change_time)) {
			(void) rw_unlock(&stale_tree_rwlp);
			return;
		}
	} while (ret != 0 && snmp_syserr == EINTR);

	/*
	 * If we can't read entLastChangeTime we assume we need to rebuild
	 * the tree. This will also cover the case when we need to rebuild
	 * the tree because a link reset had happened.
	 */
	LOGPRINTF2("check_for_stale_data: LastChange times have changed, "
	    "(%#x != %#x)\n", change_time, cur_change_time);

	/*
	 * If the mib data has changed, we need to rebuild the physical-platform
	 * subtree. To do this, we set a flag to mark the tree stale,
	 * so that any future reads to get value of volatile properties will
	 * return PICL_PROPVALUNAVAILABLE, until the stale_tree flag
	 * is reset by the tree builder thread.
	 */
	stale_tree = B_TRUE;
	if (vol_props) {
		free(vol_props);
	}
	vol_props = NULL;
	volprop_ndx = 0;
	n_vol_props = 0;

	(void) rw_unlock(&stale_tree_rwlp);

	(void) mutex_lock(&rebuild_tree_lock);
	rebuild_tree = B_TRUE;
	(void) cond_signal(&rebuild_tree_cv);
	LOGPRINTF("check_for_stale_data: signalled tree builder\n");
	(void) mutex_unlock(&rebuild_tree_lock);
}

/*
 * This is the critical routine.  This callback is invoked by picl whenever
 * it needs to fetch the value of a volatile property. The first thing we
 * must do, however, is to see if there has been a hotplug or a link-reset
 * event since the last time we built the tree and whether we need to
 * rebuild the tree. If so, we do whatever is necessary to make that happen,
 * but return PICL_PROPVALUNAVAILABLE for now, without making any further
 * snmp requests or accessing any globals.
 */
static int
read_volprop(ptree_rarg_t *parg, void *buf)
{
	char	*pstr;
	int	propval;
	int	i, ndx;
	int	ret;
	int	snmp_syserr = 0;

	/*
	 * First check for any event that would make us throw away
	 * the existing /physical-platform subtree and rebuild
	 * another one. If we are rebuilding the subtree, we just
	 * return the stale value until the tree is fully built.
	 */
	check_for_stale_data(B_FALSE);

	(void) rw_rdlock(&stale_tree_rwlp);

	if (stale_tree == B_TRUE) {
		(void) rw_unlock(&stale_tree_rwlp);
		return (PICL_PROPVALUNAVAILABLE);
	}

	for (i = 0; i < volprop_ndx; i++) {
		if (vol_props[i].prop == parg->proph) {
			ndx = i;
			break;
		}
	}
	if (i == volprop_ndx) {
		(void) rw_unlock(&stale_tree_rwlp);
		log_msg(LOG_ERR, SNMPP_CANT_FIND_VOLPROP, parg->proph);
		return (PICL_FAILURE);
	}

	/*
	 * If we can't read the value, return failure. Even if this was
	 * due to a link reset, between the check for stale data and now,
	 * the next volatile callback by picl will initiate a tree-rebuild.
	 */
	ret = snmp_get_int(hdl, vol_props[ndx].oidstr, vol_props[ndx].row,
	    &propval, &snmp_syserr);
	if (ret < 0) {
		(void) rw_unlock(&stale_tree_rwlp);
		check_for_stale_data(B_TRUE);
		if (stale_tree == B_TRUE) {
			return (PICL_PROPVALUNAVAILABLE);
		}
		log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
		    snmp_syserr ? snmp_syserr : ret,
		    vol_props[ndx].oidstr, vol_props[ndx].row);
		return (PICL_FAILURE);
	}

	switch (vol_props[ndx].proptype) {
	case VPT_PLATOPSTATE:
		if (propval == SSOS_DISABLED) {
			(void) strlcpy(buf, STR_SSOS_DISABLED, MAX_OPSTATE_LEN);
		} else if (propval == SSOS_ENABLED) {
			(void) strlcpy(buf, STR_SSOS_ENABLED, MAX_OPSTATE_LEN);
		} else {
			(void) rw_unlock(&stale_tree_rwlp);
			log_msg(LOG_ERR, SNMPP_INV_PLAT_EQUIP_OPSTATE,
			    propval, vol_props[ndx].row);
			return (PICL_FAILURE);
		}
		break;

	case VPT_NUMSENSOR:
		(void) memcpy(buf, &propval, sizeof (propval));
		break;

	case VPT_BINSENSOR:
		if (propval == ST_TRUE) {
			ret = snmp_get_str(hdl,
			    OID_sunPlatBinarySensorInterpretTrue,
			    vol_props[ndx].row, &pstr, &snmp_syserr);
			if (snmp_syserr == ECANCELED) {
				(void) rw_unlock(&stale_tree_rwlp);
				if (pstr)
					free(pstr);
				return (PICL_FAILURE);
			}
			if (ret < 0 || pstr == NULL) {
				log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
				    snmp_syserr ? snmp_syserr : ret,
				    OID_sunPlatBinarySensorInterpretTrue,
				    vol_props[ndx].row);
				(void) strlcpy(buf, STR_ST_TRUE,
				    MAX_TRUTHVAL_LEN);
			} else {
				(void) strlcpy(buf, pstr, MAX_TRUTHVAL_LEN);
			}
			if (pstr)
				free(pstr);
		} else if (propval == ST_FALSE) {
			ret = snmp_get_str(hdl,
			    OID_sunPlatBinarySensorInterpretFalse,
			    vol_props[ndx].row, &pstr, &snmp_syserr);
			if (snmp_syserr == ECANCELED) {
				(void) rw_unlock(&stale_tree_rwlp);
				if (pstr)
					free(pstr);
				return (PICL_FAILURE);
			}
			if (ret < 0 || pstr == NULL) {
				log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
				    snmp_syserr ? snmp_syserr : ret,
				    OID_sunPlatBinarySensorInterpretFalse,
				    vol_props[ndx].row);
				(void) strlcpy(buf, STR_ST_FALSE,
				    MAX_TRUTHVAL_LEN);
			} else {
				(void) strlcpy(buf, pstr, MAX_TRUTHVAL_LEN);
			}
			if (pstr)
				free(pstr);
		} else {
			(void) rw_unlock(&stale_tree_rwlp);
			log_msg(LOG_ERR, SNMPP_INV_PLAT_BINSNSR_CURRENT,
			    propval, vol_props[ndx].row);
			return (PICL_FAILURE);
		}
		break;

	case VPT_ALARMSTATE:
		if (propval == SSAS_OFF) {
			(void) strlcpy(buf, STR_SSAS_OFF, MAX_ALARMSTATE_LEN);
		} else if (propval == SSAS_STEADY) {
			(void) strlcpy(buf, STR_SSAS_STEADY,
			    MAX_ALARMSTATE_LEN);
		} else if (propval == SSAS_ALTERNATING) {
			(void) strlcpy(buf, STR_SSAS_ALTERNATING,
			    MAX_ALARMSTATE_LEN);
		} else {
			(void) strlcpy(buf, STR_SSAS_UNKNOWN,
			    MAX_ALARMSTATE_LEN);
		}
		break;

	case VPT_BATTERYSTATUS:
		switch (propval) {
		case SSBS_OTHER:
			(void) strlcpy(buf, STR_SSBS_OTHER,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_FULLYCHARGED:
			(void) strlcpy(buf, STR_SSBS_FULLYCHARGED,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_LOW:
			(void) strlcpy(buf, STR_SSBS_LOW,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_CRITICAL:
			(void) strlcpy(buf, STR_SSBS_CRITICAL,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_CHARGING:
			(void) strlcpy(buf, STR_SSBS_CHARGING,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_CHARGING_AND_LOW:
			(void) strlcpy(buf, STR_SSBS_CHARGING_AND_LOW,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_CHARGING_AND_HIGH:
			(void) strlcpy(buf, STR_SSBS_CHARGING_AND_HIGH,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_CHARGING_AND_CRITICAL:
			(void) strlcpy(buf, STR_SSBS_CHARGING_AND_CRITICAL,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_UNDEFINED:
			(void) strlcpy(buf, STR_SSBS_UNDEFINED,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_PARTIALLY_CHARGED:
			(void) strlcpy(buf, STR_SSBS_PARTIALLY_CHARGED,
			    MAX_BATTERYSTATUS_LEN);
			break;
		case SSBS_UNKNOWN:
		default:
			(void) strlcpy(buf, STR_SSBS_UNKNOWN,
			    MAX_BATTERYSTATUS_LEN);
			break;
		}
		break;
	}

	(void) rw_unlock(&stale_tree_rwlp);

	return (PICL_SUCCESS);
}

static void
threshold(picl_nodehdl_t node, char *oidstr, int row, char *propname,
    int *snmp_syserr_p)
{
	picl_prophdl_t	prop;
	int		err;
	int		val;

	if ((err = snmp_get_int(hdl, oidstr, row, &val, snmp_syserr_p)) != -1) {
		err = add_volatile_prop(node, propname, PICL_PTYPE_INT,
		    PICL_READ, sizeof (int), read_volprop, NULL, &prop);
		if (err == PICL_SUCCESS)
			save_volprop(prop, oidstr, row, VPT_NUMSENSOR);
	} else
		log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
		    *snmp_syserr_p ? *snmp_syserr_p : err, oidstr, row);
}

static void
add_thresholds(picl_nodehdl_t node, int row, int *snmp_syserr_p)
{
	uchar_t	*bitstr = NULL;
	uchar_t	enabled;
	uint_t	nbytes;
	int	ret;

	ret = snmp_get_str(hdl,
	    OID_sunPlatNumericSensorEnabledThresholds,
	    row, (char **)&bitstr, snmp_syserr_p);
	if (ret == -1) {
		log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
		    *snmp_syserr_p ? *snmp_syserr_p : ret,
		    OID_sunPlatNumericSensorEnabledThresholds, row);
	} else {
		nbytes = strlen((const char *)bitstr);
	}

	CHECK_LINKRESET_VOID(snmp_syserr_p);

	/*
	 * No bit string of threshold masks was returned, so we can't
	 * assume that any thresholds exist.
	 *
	 * This mask prevents us from attempting to fetch thresholds
	 * which don't apply to the sensor or that aren't there anyway,
	 * That speeds up the plug-in significantly since otherwise it
	 * takes several seconds to time out.
	 */
	if (ret < 0 || bitstr == NULL || nbytes == 0 || 2 < nbytes) {
		if (bitstr)
			free(bitstr);
		return;
	} else if (nbytes == 1) {
		/*
		 * The ALOM snmp agent doesn't adhere to the BER rules for
		 * encoding bit strings. While the BER states that bitstrings
		 * must begin from the second octet after length, and the
		 * first octet after length must indicate the number of unused
		 * bits in the last octet, the snmp agent simply sends the
		 * bitstring data as if it were octet string -- that is, the
		 * "unused bits" octet is missing.
		 */
		enabled = bitstr[0];
	} else if (nbytes == 2)
		enabled = bitstr[1];

	if (bitstr) {
		free(bitstr);
	}

	if (enabled & LOWER_FATAL) {
		threshold(node,
		    OID_sunPlatNumericSensorLowerThresholdFatal, row,
		    PICL_PROP_LOW_POWER_OFF, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
	}
	if (enabled & LOWER_CRITICAL) {
		threshold(node,
		    OID_sunPlatNumericSensorLowerThresholdCritical, row,
		    PICL_PROP_LOW_SHUTDOWN, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
	}
	if (enabled & LOWER_NON_CRITICAL) {
		threshold(node,
		    OID_sunPlatNumericSensorLowerThresholdNonCritical, row,
		    PICL_PROP_LOW_WARNING, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
	}
	if (enabled & UPPER_NON_CRITICAL) {
		threshold(node,
		    OID_sunPlatNumericSensorUpperThresholdNonCritical, row,
		    PICL_PROP_HIGH_WARNING, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
	}
	if (enabled & UPPER_CRITICAL) {
		threshold(node,
		    OID_sunPlatNumericSensorUpperThresholdCritical, row,
		    PICL_PROP_HIGH_SHUTDOWN, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
	}
	if (enabled & UPPER_FATAL) {
		threshold(node,
		    OID_sunPlatNumericSensorUpperThresholdFatal, row,
		    PICL_PROP_HIGH_POWER_OFF, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
	}
}

static char *
get_slot_type(int row, int *snmp_syserr_p)
{
	char	*p;
	char	*slott = NULL;
	int	ret;

	ret = snmp_get_str(hdl, OID_sunPlatEquipmentHolderAcceptableTypes,
	    row, &p, snmp_syserr_p);
	CHECK_LINKRESET(snmp_syserr_p, NULL)

	if ((ret == 0) && p && *p) {
		slott = p;
		if ((p = strchr(slott, '\n')) != NULL)
			*p = 0;
	} else {
		log_msg(LOG_WARNING, SNMPP_NO_SLOT_TYPE, row);
		if (p) {
			free(p);
		}
	}

	return (slott);
}

/*
 * Create and add the specified volatile property
 */
static int
add_volatile_prop(picl_nodehdl_t node, char *name, int type, int access,
    int size, int (*rdfunc)(ptree_rarg_t *, void *),
    int (*wrfunc)(ptree_warg_t *, const void *), picl_prophdl_t *propp)
{
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		prop;
	int			err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    type, (access|PICL_VOLATILE), size, name, rdfunc, wrfunc);
	if (err != PICL_SUCCESS) {
		log_msg(LOG_ERR, SNMPP_CANT_INIT_PROPINFO, err);
		return (err);
	}

	err = ptree_create_and_add_prop(node, &propinfo, NULL, &prop);
	if (err != PICL_SUCCESS) {
		log_msg(LOG_ERR, SNMPP_CANT_ADD_PROP, err, node);
		return (err);
	}

	if (propp)
		*propp = prop;

	return (PICL_SUCCESS);
}

/*
 * Add the specified string property to the node
 */
static int
add_string_prop(picl_nodehdl_t node, char *propname, char *propval)
{
	ptree_propinfo_t	propinfo;
	int			err;

	if (*propval == '\0')
		return (PICL_SUCCESS);

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(propval) + 1,
	    propname, NULL, NULL);
	if (err != PICL_SUCCESS) {
		log_msg(LOG_ERR, SNMPP_CANT_INIT_STR_PROPINFO, err);
		return (err);
	}

	err = ptree_create_and_add_prop(node, &propinfo, propval, NULL);
	if (err != PICL_SUCCESS) {
		log_msg(LOG_ERR, SNMPP_CANT_ADD_STR_PROP, err, node);
		return (err);
	}

	return (PICL_SUCCESS);
}

/*
 * Add the specified void property to the node
 */
static int
add_void_prop(picl_nodehdl_t node, char *propname)
{
	ptree_propinfo_t	propinfo;
	int			err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_VOID, PICL_READ, 0, propname, NULL, NULL);
	if (err != PICL_SUCCESS) {
		log_msg(LOG_ERR, SNMPP_CANT_INIT_VOID_PROPINFO, err);
		return (err);
	}

	err = ptree_create_and_add_prop(node, &propinfo, NULL, NULL);
	if (err != PICL_SUCCESS) {
		log_msg(LOG_ERR, SNMPP_CANT_ADD_VOID_PROP, err, node);
		return (err);
	}

	return (PICL_SUCCESS);
}

static void
add_prop(picl_nodehdl_t nodeh, picl_prophdl_t *php, char *label,
    int row, sp_propid_t pp, int *snmp_syserr_p)
{
	char	*serial_num;
	char	*slot_type;
	char	*fw_revision, *hw_revision;
	char	*mfg_name, *model_name;
	char	*phys_descr;
	int	val;
	int	ret;

	switch (pp) {
	case PP_SERIAL_NUM:
		ret = snmp_get_str(hdl, OID_entPhysicalSerialNum,
		    row, &serial_num, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && serial_num) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_SERIAL_NUMBER, serial_num);
			free((void *) serial_num);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_entPhysicalSerialNum, row);
		break;

	case PP_SLOT_TYPE:
		if ((slot_type = get_slot_type(row, snmp_syserr_p)) == NULL) {
			CHECK_LINKRESET_VOID(snmp_syserr_p)
			(void) add_string_prop(nodeh,
			    PICL_PROP_SLOT_TYPE, DEFAULT_SLOT_TYPE);
		} else {
			(void) add_string_prop(nodeh,
			    PICL_PROP_SLOT_TYPE, slot_type);
			free((void *) slot_type);
		}
		break;

	case PP_STATE:
		ret = add_volatile_prop(nodeh, PICL_PROP_STATE,
		    PICL_PTYPE_CHARSTRING, PICL_READ, MAX_ALARMSTATE_LEN,
		    read_volprop, NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatAlarmState, row,
			    VPT_ALARMSTATE);
		}
		break;

	case PP_OPSTATUS:
		ret = add_volatile_prop(nodeh, PICL_PROP_OPERATIONAL_STATUS,
		    PICL_PTYPE_CHARSTRING, PICL_READ, MAX_OPSTATE_LEN,
		    read_volprop, NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php,
			    OID_sunPlatEquipmentOperationalState, row,
			    VPT_PLATOPSTATE);
		}
		break;

	case PP_BATT_STATUS:
		ret = add_volatile_prop(nodeh, PICL_PROP_BATTERY_STATUS,
		    PICL_PTYPE_CHARSTRING, PICL_READ, MAX_BATTERYSTATUS_LEN,
		    read_volprop, NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatBatteryStatus, row,
			    VPT_BATTERYSTATUS);
		}
		break;

	case PP_TEMPERATURE:
		ret = add_volatile_prop(nodeh, PICL_PROP_TEMPERATURE,
		    PICL_PTYPE_INT, PICL_READ, sizeof (int), read_volprop,
		    NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatNumericSensorCurrent,
			    row, VPT_NUMSENSOR);
		}
		break;

	case PP_VOLTAGE:
		ret = add_volatile_prop(nodeh, PICL_PROP_VOLTAGE,
		    PICL_PTYPE_INT, PICL_READ, sizeof (int), read_volprop,
		    NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatNumericSensorCurrent,
			    row, VPT_NUMSENSOR);
		}
		break;

	case PP_CURRENT:
		ret = add_volatile_prop(nodeh, PICL_PROP_CURRENT,
		    PICL_PTYPE_INT, PICL_READ, sizeof (int), read_volprop,
		    NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatNumericSensorCurrent,
			    row, VPT_NUMSENSOR);
		}
		break;

	case PP_SPEED:
		ret = add_volatile_prop(nodeh, PICL_PROP_SPEED, PICL_PTYPE_INT,
		    PICL_READ, sizeof (int), read_volprop, NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatNumericSensorCurrent,
			    row, VPT_NUMSENSOR);
		}
		break;

	case PP_SENSOR_VALUE:
		ret = add_volatile_prop(nodeh, PICL_PROP_SENSOR_VALUE,
		    PICL_PTYPE_INT, PICL_READ, sizeof (int), read_volprop,
		    NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatNumericSensorCurrent,
			    row, VPT_NUMSENSOR);
		}
		break;

	case PP_CONDITION:
		ret = add_volatile_prop(nodeh, PICL_PROP_CONDITION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, MAX_TRUTHVAL_LEN,
		    read_volprop, NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatBinarySensorCurrent,
			    row, VPT_BINSENSOR);
		}
		break;

	case PP_EXPECTED:
		ret = add_volatile_prop(nodeh, PICL_PROP_EXPECTED,
		    PICL_PTYPE_CHARSTRING, PICL_READ, MAX_TRUTHVAL_LEN,
		    read_volprop, NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatBinarySensorExpected,
			    row, VPT_BINSENSOR);
		}
		break;

	case PP_EXPONENT:
		ret = add_volatile_prop(nodeh, PICL_PROP_EXPONENT,
		    PICL_PTYPE_INT, PICL_READ, sizeof (int), read_volprop,
		    NULL, php);
		if (ret == PICL_SUCCESS) {
			save_volprop(*php, OID_sunPlatNumericSensorExponent,
			    row, VPT_NUMSENSOR);
		}
		break;

	case PP_REPLACEABLE:
		ret = snmp_get_int(hdl, OID_sunPlatCircuitPackReplaceable,
		    row, &val, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && (val == ST_TRUE))
			(void) add_void_prop(nodeh, PICL_PROP_IS_REPLACEABLE);
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatCircuitPackReplaceable, row);
		break;

	case PP_HOTSWAPPABLE:
		ret = snmp_get_int(hdl, OID_sunPlatCircuitPackHotSwappable,
		    row, &val, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && (val == ST_TRUE))
			(void) add_void_prop(nodeh, PICL_PROP_IS_HOT_SWAPPABLE);
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatCircuitPackHotSwappable, row);
		break;

	case PP_IS_FRU:
		ret = snmp_get_int(hdl, OID_entPhysicalIsFRU, row,
		    &val, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && (val == ST_TRUE))
			(void) add_void_prop(nodeh, PICL_PROP_IS_FRU);
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_entPhysicalIsFRU, row);
		break;

	case PP_HW_REVISION:
		ret = snmp_get_str(hdl, OID_entPhysicalHardwareRev,
		    row, &hw_revision, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && hw_revision) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_HW_REVISION, hw_revision);
			free((void *) hw_revision);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_entPhysicalHardwareRev, row);
		break;

	case PP_FW_REVISION:
		ret = snmp_get_str(hdl, OID_entPhysicalFirmwareRev,
		    row, &fw_revision, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && fw_revision) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_FW_REVISION, fw_revision);
			free((void *) fw_revision);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_entPhysicalFirmwareRev, row);
		break;

	case PP_MFG_NAME:
		ret = snmp_get_str(hdl, OID_entPhysicalMfgName,
		    row, &mfg_name, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && mfg_name) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_MFG_NAME, mfg_name);
			free((void *) mfg_name);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_entPhysicalMfgName, row);
		break;

	case PP_MODEL_NAME:
		ret = snmp_get_str(hdl, OID_entPhysicalModelName,
		    row, &model_name, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && model_name) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_MODEL_NAME, model_name);
			free((void *) model_name);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_entPhysicalModelName, row);
		break;

	case PP_DESCRIPTION:
		ret = snmp_get_str(hdl, OID_entPhysicalDescr,
		    row, &phys_descr, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && phys_descr) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_PHYS_DESCRIPTION, phys_descr);
			free((void *) phys_descr);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_entPhysicalDescr, row);
		break;

	case PP_LABEL:
		if (label && *label)
			(void) add_string_prop(nodeh, PICL_PROP_LABEL, label);
		break;

	case PP_BASE_UNITS:
		ret = snmp_get_int(hdl, OID_sunPlatNumericSensorBaseUnits,
		    row, &val, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && (val > 0) && (val < n_baseunits)) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_BASE_UNITS, sensor_baseunits[val]);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatNumericSensorBaseUnits, row);
		break;

	case PP_RATE_UNITS:
		ret = snmp_get_int(hdl, OID_sunPlatNumericSensorRateUnits,
		    row, &val, snmp_syserr_p);
		CHECK_LINKRESET_VOID(snmp_syserr_p)
		if ((ret == 0) && (val > 0) && (val < n_rateunits)) {
			(void) add_string_prop(nodeh,
			    PICL_PROP_RATE_UNITS, sensor_rateunits[val]);
		}
		if (ret == -1)
			log_msg(LOG_ERR, SNMPP_CANT_FETCH_OBJECT_VAL,
			    *snmp_syserr_p ? *snmp_syserr_p : ret,
			    OID_sunPlatNumericSensorRateUnits, row);
		break;
	}
}

/*
 * Initialize the SNMP library's cache refresh subsystem, then periodically
 * process refresh job to prevent cache entries from expiring.
 */
/*ARGSUSED*/
static void *
cache_refresher(void *arg)
{
	int		jobs;
	int		next_expiration;
	timestruc_t	to;
	hrtime_t	cycle_start, cycle_elapsed;

	/*
	 * Initialize refresh subsystem
	 */
	LOGPRINTF("Initializing SNMP refresh subsystem.\n");
	if (snmp_refresh_init() < 0) {
		return ((void *)-1);
	}

	(void) mutex_lock(&cache_refresh_lock);


	for (;;) {
		cycle_start = gethrtime();

		/*
		 * Process jobs from the snmp cache refresh work queue until one
		 * of the following conditions is true:
		 * 1) we are told to exit, or
		 * 2) we have processed at least as many jobs as recommended by
		 * the library, and the next job expiration is at least
		 * CACHE_REFRESH_MIN_WINDOW * seconds away.
		 */
		jobs = snmp_refresh_get_cycle_hint(CACHE_REFRESH_CYCLE);
		while ((cache_refresh_thr_exit == B_FALSE) && (jobs > 0)) {
			(void) snmp_refresh_process_job();
			jobs--;
		}

		next_expiration = snmp_refresh_get_next_expiration();
		while ((cache_refresh_thr_exit == B_FALSE) &&
		    ((next_expiration >= 0) &&
		    (next_expiration < CACHE_REFRESH_MIN_WINDOW))) {
			(void) snmp_refresh_process_job();
			next_expiration = snmp_refresh_get_next_expiration();
		}

		/*
		 * As long as we haven't been told to exit, sleep for
		 * CACHE_REFRESH_CYCLE seconds minus the amount of time that has
		 * elapsed since this cycle started.  If the elapsed time is
		 * equal to or greater than 60 seconds, skip sleeping entirely.
		 */
		cycle_elapsed = (gethrtime() - cycle_start) / NANOSEC;
		if ((cache_refresh_thr_exit == B_FALSE) &&
		    (cycle_elapsed < CACHE_REFRESH_CYCLE)) {
			to.tv_sec = CACHE_REFRESH_CYCLE - cycle_elapsed;
			to.tv_nsec = 0;
			(void) cond_reltimedwait(&cache_refresh_cv,
			    &cache_refresh_lock, &to);
		}

		/*
		 * If we have been told to exit, clean up and bail out.
		 */
		if (cache_refresh_thr_exit == B_TRUE) {
			snmp_refresh_fini();
			(void) mutex_unlock(&cache_refresh_lock);
			LOGPRINTF("cache_refresher: time to exit\n");
			return (NULL);
		}

	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Check to see if the cache_refresher thread is running.  If it is, signal it
 * to terminate and clean up associated data structures.
 */
void
cache_refresher_fini(void)
{
	/* if the thread isn't running, there is nothing to do */
	if (cache_refresh_thr_exit == B_TRUE)
		return;

	/* wake up the cache_refresher thread, tell it to exit */
	(void) mutex_lock(&cache_refresh_lock);
	cache_refresh_thr_exit = B_TRUE;
	(void) cond_signal(&cache_refresh_cv);
	(void) mutex_unlock(&cache_refresh_lock);

	/* reap the thread */
	(void) thr_join(cache_refresh_thr_id, NULL, NULL);

	/* finish cleanup... */
	(void) cond_destroy(&cache_refresh_cv);
	(void) mutex_destroy(&cache_refresh_lock);
}

/*VARARGS2*/
static void
log_msg(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

#ifdef SNMPPLUGIN_DEBUG

static void
snmpplugin_log_init(void)
{
	(void) mutex_init(&snmpplugin_dbuf_lock, USYNC_THREAD, NULL);
}

static void
snmpplugin_log(const char *fmt, ...)
{
	va_list	ap;

	(void) mutex_lock(&snmpplugin_dbuf_lock);

	va_start(ap, fmt);
	(void) vsnprintf(snmpplugin_lbuf, SNMPPLUGIN_DMAX_LINE, fmt, ap);
	snmpplugin_log_append();
	va_end(ap);

	(void) mutex_unlock(&snmpplugin_dbuf_lock);
}

static void
snmpplugin_log_append(void)
{
	int	len;

	len = strlen(snmpplugin_lbuf);

	if ((snmpplugin_dbuf_curp + len) >=
	    (snmpplugin_dbuf + snmpplugin_dbuf_sz)) {
		snmpplugin_dbuf_realloc();
		if (snmpplugin_dbuf == NULL) {
			return;
		}
	}

	(void) strcpy(snmpplugin_dbuf_curp, snmpplugin_lbuf);
	snmpplugin_dbuf_curp += len;
}

static void
snmpplugin_dbuf_realloc(void)
{
	char	*p;
	size_t	offset = 0;
	size_t	count;

	count = snmpplugin_dbuf_sz + SNMPPLUGIN_DBLOCK_SZ;
	if ((p = (char *)calloc(count, 1)) == NULL) {
		snmpplugin_dbuf_overflow++;
		snmpplugin_dbuf_curp = snmpplugin_dbuf;
		return;
	}

	if (snmpplugin_dbuf) {
		offset = snmpplugin_dbuf_curp - snmpplugin_dbuf;
		(void) memcpy(p, snmpplugin_dbuf, snmpplugin_dbuf_sz);
		free(snmpplugin_dbuf);
	}

	snmpplugin_dbuf = p;
	snmpplugin_dbuf_sz += SNMPPLUGIN_DBLOCK_SZ;

	snmpplugin_dbuf_curp = snmpplugin_dbuf + offset;
}
#endif
