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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This plugin-in creates the FRU Hierarchy for the
 * SUNW,Netra-T12 platform and manages the environmental sensors
 * on the platform.
 */

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <strings.h>
#include <libintl.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <picl.h>
#include <picltree.h>
#include <sys/stat.h>
#include <libnvpair.h>
#include <sys/param.h>
#include <kstat.h>
#include <config_admin.h>
#include <sys/sbd_ioctl.h>
#include <sys/sgfrutree.h>
#include <sys/sgenv.h>
#include <sys/ioccom.h>
#include <sys/lw8.h>
#include <sys/sysevent/dr.h>
#include <pthread.h>
#include <sys/obpdefs.h>
#include "libdevice.h"
#include "picldefs.h"
#define	NDEBUG
#include <assert.h>

/*
 * Plugin registration entry points
 */
static void	piclfrutree_register(void);
static void	piclfrutree_init(void);
static void	piclfrutree_fini(void);
#pragma	init(piclfrutree_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_Netra-T12_frutree",
	piclfrutree_init,
	piclfrutree_fini,
};

/*
 * Log message texts
 */
#define	DEV_OPEN_FAIL gettext("piclfrutree_init: open of %s failed: %s")
#define	ADD_NODES_FAIL gettext("piclfrutree_init: add_all_nodes failed: %d")
#define	GET_ROOT_FAIL gettext("piclfrutree_init: ptree_get_root failed")
#define	ADD_FRUTREE_FAIL gettext("piclfrutree_init: add frutree failed")
#define	INVALID_PICL_CLASS gettext("add_subtree: invalid picl class 0x%x")
#define	ADD_NODE_FAIL gettext("ptree_create_and_add_node %s failed: %d")
#define	GET_NEXT_BY_ROW_FAIL gettext("ptree_get_next_by_row %s failed: %d")
#define	PROPINFO_FAIL gettext("ptree_init_propinfo %s failed: %d")
#define	GET_PROPVAL_FAIL gettext("ptree_get_propval failed: %d")
#define	DELETE_PROP_FAIL gettext("ptree_delete_prop failed: %d")
#define	DELETE_NODE_FAIL gettext("ptree_delete_node failed: %d")
#define	ADD_PROP_FAIL gettext("ptree_create_and_add_prop %s failed: %d")
#define	SGFRU_IOCTL_FAIL gettext("sgfru ioctl 0x%x handle 0x%llx failed: %s")
#define	LED_IOCTL_FAIL gettext("led ioctl failed: %s")
#define	MALLOC_FAIL gettext("piclfrutree: malloc failed")
#define	NO_SC_FAIL gettext("piclfrutree: cannot find sc node")
#define	NO_NODE_FAIL gettext("piclfrutree: cannot find node %s: %d")
#define	KSTAT_FAIL gettext("piclfrutree: failure accessing kstats")
#define	ADD_TBL_ENTRY_FAIL gettext("piclfrutree: cannot add entry to table")
#define	PROP_LOOKUP_FAIL gettext("piclfrutree: cannot find %s property: %d")
#define	EM_DI_INIT_FAIL	gettext("frutree: di_init failed: %s")
#define	EM_THREAD_CREATE_FAILED gettext("frutree: pthread_create failed: %s")
#define	EM_MUTEX_FAIL gettext("frutree: pthread_mutex_lock returned: %s")
#define	EM_POLL_FAIL gettext("frutree: poll() failed: %s")
#define	DEVCTL_DEVICE_ACQUIRE_FAILED \
    gettext("frutree: devctl_device_acquire() failed: %s")

/*
 * PICL property values
 */
#define	PICL_PROPVAL_TRUE		"true"
#define	PICL_PROPVAL_SYSTEM		"system"
#define	PICL_PROPVAL_ON			"ON"
#define	PICL_PROPVAL_OFF		"OFF"
#define	PICL_PROPVAL_BLINKING		"BLINKING"
#define	PICL_PROPVAL_FLASHING		"FLASHING"
#define	PICL_PROPVAL_CHASSIS		"chassis"
#define	PICL_PROPVAL_AMBIENT		"Ambient"
#define	PICL_PROPVAL_DIE		"Die"
#define	PICL_PROPVAL_GREEN		"green"
#define	PICL_PROPVAL_AMBER		"amber"
#define	PICL_PROPVAL_OKAY		"okay"
#define	PICL_PROPVAL_FAILED		"failed"
#define	PICL_PROPVAL_WARNING		"warning"
#define	PICL_PROPVAL_DISABLED		"disabled"
#define	PICL_PROPVAL_UNKNOWN		"unknown"
#define	PICL_PROPVAL_SELF_REGULATING	"self-regulating"
#define	PICL_PROPVAL_PER_CENT		"%"
#define	PICL_PROP_BANK_STATUS		"bank-status"

/*
 * PICL property names
 */
#define	PICL_PROP_LOW_WARNING_THRESHOLD	"LowWarningThreshold"

/*
 * Local defines
 */
#define	MAX_LINE_SIZE		1024
#define	MAX_TRIES		4
#define	MAX_SPEED_UNIT_LEN	20
#define	MAX_OPERATIONAL_STATUS_LEN	10
#define	MAX_CONDITION_LEN	10
#define	MAX_LABEL_LEN		256
#define	MAX_STATE_LEN		10
#define	MAX_STATE_SIZE		32
#define	LED_PSEUDO_DEV "/devices/pseudo/lw8@0:lw8"
#define	SC_DEV "/platform/ssm@0,0/pci@18,700000/bootbus-controller@4"
#define	SC_DEV_PCIX "/platform/ssm@0,0/pci@18,700000/pci@4/bootbus-controller@3"
#define	CPU_DEV "/platform/ssm@0,0/SUNW,UltraSPARC-III@%x,0"
#define	CPU_DEV2 "/platform/ssm@0,0/SUNW,UltraSPARC-III+@%x,0"
#define	CPU_DEV3C0 "/platform/ssm@0,0/cmp@%x,0/cpu@0"
#define	CPU_DEV3C1 "/platform/ssm@0,0/cmp@%x,0/cpu@1"
#define	MEMORY_DEV "/platform/ssm@0,0/memory-controller@%x,400000"
#define	IO_DEV "/platform/ssm@0,0/pci@%s"
#define	DISK0_BASE_PATH "/ssm@0,0/pci@18,600000/scsi@2/sd@0,0"
#define	DISK0_DEV "/platform" DISK0_BASE_PATH
#define	DISK1_BASE_PATH "/ssm@0,0/pci@18,600000/scsi@2/sd@1,0"
#define	DISK1_DEV "/platform" DISK1_BASE_PATH
#define	DISK0_BASE_PATH_PCIX "/ssm@0,0/pci@18,700000/scsi@2/sd@0,0"
#define	DISK0_DEV_PCIX "/platform" DISK0_BASE_PATH_PCIX
#define	DISK1_BASE_PATH_PCIX "/ssm@0,0/pci@18,700000/scsi@2/sd@1,0"
#define	DISK1_DEV_PCIX "/platform" DISK1_BASE_PATH_PCIX
#define	TAPE_DEV "/platform/ssm@0,0/pci@18,600000/scsi@2/st@5,0"
#define	TAPE_DEV_PCIX "/platform/ssm@0,0/pci@18,700000/scsi@2/st@5,0"
#define	DVD_DEV "/platform/ssm@0,0/pci@18,700000/ide@3/sd@0,0"
#define	DVD_DEV_PCIX "/platform/ssm@0,0/pci@18,700000/pci@4/ide@2/sd@0,0"
#define	CHASSIS_PATH "/frutree/chassis"
#define	CHASSIS_LOC_PATH "/frutree/chassis/%s"
#define	PROC_LOC_PATH "/frutree/chassis/SB%d/SB%d/P%d"
#define	PROC_FRU_PATH "/frutree/chassis/SB%d/SB%d/P%d/P%d"
/*
 * Calculate safari address to put in CPU_DEV/MEMORY_DEV string based on
 * SBx/Py fru path name
 */
#define	SB_P_TO_SAFARI_ADDR(sbname, pname) \
	((pname[1] - '0') + (4 * (sbname[2] - '0')))
#define	SAFARI_ADDR_TO_SB(value) (value >> 2)
#define	SAFARI_ADDR_TO_P(value) (value & 3)
#define	AP_ID_PREAMBLE "ssm0:N0."
#define	AP_ID_PREAMBLE_LEN 8
#define	LABEL_PREAMBLE "N0/"
#define	LABEL_PREAMBLE_LEN 3
/*
 * work out type of fru based on name
 */
#define	IS_ECACHE_NODE(name)	(name[0] == 'E')
#define	IS_DIMM_NODE(name)	(name[0] == 'D' && name[1] != 'V')
#define	IS_PROC_NODE(name)	(name[0] == 'P' && name[1] != 'S')
#define	IS_PSU_NODE(name)	(name[0] == 'P' && name[1] == 'S')
#define	IS_SB_NODE(name)	(name[0] == 'S' && name[1] == 'B')
#define	IS_IB_NODE(name)	(name[0] == 'I')
#define	IS_FT_NODE(name)	(name[0] == 'F' && name[1] == 'T')
#define	IS_FAN_NODE(name)	(name[0] == 'F' && name[1] != 'T')
#define	IS_RP_NODE(name)	(name[0] == 'R')
/*
 * rename sgfru driver's node_t to sgfrunode_t to avoid confusion
 */
#define	sgfrunode_t node_t

/*
 * disk_led data
 */
#define	REMOK_LED "ok_to_remove"
#define	FAULT_LED "fault"
#define	POWER_LED "power"

/*
 * 'struct lw8_disk' contains the per-disk metadata needed to
 * manage the current state of one of the internal disks.
 *
 * 'lw8_disks[]' is an array that contains the metadata
 * for N_DISKS disks.
 *
 * The d_fruname field of 'struct lw8_disk' is static.
 * d_plat_path and d_devices_path are aliases for device-paths
 * to the disk.  They are logically static, as they are computed
 * when the disk_leds_thread() thread does its initialization.
 *
 * d_state is the most interesting field, as it changes
 * dynamically, based on whether the associated disk
 * is currently Configured or Unconfigured (by DR).  d_state
 * is an optimization that minimizes per-disk actions such
 * as setting of LEDs and updating the FRU Tree.
 *
 * A disk starts in a d_state of DISK_STATE_NOT_INIT
 * and moves to DISK_STATE_READY when the disk is
 * Configured (by DR) and it moves to DISK_STATE_NOT_READY
 * when it is Unconfigured (by DR).
 */
typedef enum {
	DISK_STATE_NOT_INIT,
	DISK_STATE_READY,
	DISK_STATE_NOT_READY
} disk_state_t;

struct lw8_disk {
	char		*d_fruname;		/* FRU name */
	char		*d_plat_path;		/* /platform */
	char		*d_devices_path;	/* /devices */
	disk_state_t	d_state;
};

#define	N_DISKS 2
static	struct lw8_disk	lw8_disks[N_DISKS] = {
	{"DISK0", NULL, NULL, DISK_STATE_NOT_INIT},
	{"DISK1", NULL, NULL, DISK_STATE_NOT_INIT} };

/* Duration of inactivity within disk_leds_thread() */
#define	THR_POLL_PERIOD 5000    /* milliseconds */

static volatile boolean_t	disk_leds_thread_ack = B_FALSE;
static pthread_t		ledsthr_tid;
static pthread_attr_t		ledsthr_attr;
static boolean_t		ledsthr_created = B_FALSE;
static uint_t			ledsthr_poll_period =
				    THR_POLL_PERIOD;
static boolean_t		g_mutex_init = B_FALSE;
static pthread_cond_t		g_cv;
static pthread_cond_t		g_cv_ack;
static pthread_mutex_t		g_mutex;
static volatile boolean_t	g_wait_now = B_FALSE;

static void disk_leds_init(void);
static void disk_leds_fini(void);
static void *disk_leds_thread(void *args);

/*
 * Tables to convert sgenv information
 */
static char *hpu_type_table[] = { "", "SSC", "SB", "RP", "FT",
	"IB", "PS", "ID"};
static char *hpu_fru_type_table[] = { "", "SSC", "CPU", "RP", "FT",
	"PCIB", "PS", "ID"};
static char *hpu_part_table[] = { "", "sbbc", "sdc",
	"ar", "cbh", "dx", "cheetah", "1.5vdc", "3.3vdc",
	"5vdc", "12vdc", "output", "current", "board", "sc-app",
	"schizo", "fan", "input"};
static char *hpu_sensor_table[] = { "", "", "current",
	"temp", "cooling", "1.5vdc", "1.8vdc", "3.3vdc", "5vdc",
	"12vdc", "48vdc", NULL, "2.4vdc"};
static char *hpu_sensor_class_table[] = { "", "", PICL_CLASS_CURRENT_SENSOR,
	PICL_CLASS_TEMPERATURE_SENSOR, PICL_CLASS_FAN,
	PICL_CLASS_VOLTAGE_SENSOR, PICL_CLASS_VOLTAGE_SENSOR,
	PICL_CLASS_VOLTAGE_SENSOR, PICL_CLASS_VOLTAGE_SENSOR,
	PICL_CLASS_VOLTAGE_SENSOR, PICL_CLASS_VOLTAGE_INDICATOR,
	NULL, PICL_CLASS_VOLTAGE_SENSOR};
static char *hpu_sensor_prop_table[] = { "", "", PICL_PROP_CURRENT,
	PICL_PROP_TEMPERATURE, PICL_PROP_FAN_SPEED, PICL_PROP_VOLTAGE,
	PICL_PROP_VOLTAGE, PICL_PROP_VOLTAGE, PICL_PROP_VOLTAGE,
	PICL_PROP_VOLTAGE, PICL_PROP_CONDITION, NULL, PICL_PROP_VOLTAGE};
static char *hpu_condition_table[] = {"unknown", "okay", "failing",
	"failed", "unusable"};

/*
 * variables set up in init
 */
static picl_nodehdl_t	frutreeh;
static picl_nodehdl_t	sch = 0;
static int init_complete;
static int pcix_io = 0;

/*
 * forward reference
 */
static int add_all_nodes(void);
static int remove_subtree(picl_nodehdl_t parh);
static int add_subtree(picl_nodehdl_t parh, fru_hdl_t fruparent);
static int add_picl_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp);
static int add_chassis_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp);
static int add_fru_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp);
static int add_location_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp);
static int add_led_nodes(picl_nodehdl_t nodeh, char *name, int position,
    picl_prophdl_t tblhdl);
static int add_env_nodes(picl_nodehdl_t nodeh, char *nodename,
    picl_prophdl_t tblhdl);
static int add_intermediate_nodes(picl_nodehdl_t *nodep, char *labelp,
    picl_prophdl_t *tblhdlp, char *slot_name, char *fru_name);
static int add_intermediate_location(picl_nodehdl_t *nodep, char *labelp,
    char *slot_name);
static int add_pci_location(picl_nodehdl_t childh, char *parent_addr,
    char bus_addr, char *slot_name);
static picl_nodehdl_t find_child_by_name(picl_nodehdl_t parh, char *name);
static int create_dimm_references(picl_nodehdl_t parh, int dimm_id,
    picl_nodehdl_t nodeh, picl_prophdl_t tblhdl);
static int create_cpu_references(char *pname, picl_nodehdl_t nodeh,
    picl_prophdl_t tblhdl);
static void post_frudr_event(char *ename, picl_nodehdl_t parenth,
    picl_nodehdl_t fruh);
static int remove_references(picl_prophdl_t refprop, char *class);
static int remove_picl_node(picl_nodehdl_t nodeh);
static sgfrunode_t *get_node_children(fru_hdl_t fruparent, int *num_childrenp);
static int add_prop_ull(picl_nodehdl_t nodeh, uint64_t handle, char *name);
static int add_prop_void(picl_nodehdl_t nodeh, char *name);
static int add_prop_ref(picl_nodehdl_t nodeh, picl_nodehdl_t value, char *name);
static int add_prop_int(picl_nodehdl_t nodeh, int value, char *name);
static int add_prop_float(picl_nodehdl_t nodeh, float value, char *name);
static int add_prop_charstring(picl_nodehdl_t nodeh, char *value, char *name);
static void frudr_evhandler(const char *ename, const void *earg,
    size_t size, void *cookie);
static void frumemcfg_evhandler(const char *ename, const void *earg,
    size_t size, void *cookie);
static int add_sensor_prop(picl_nodehdl_t nodeh, char *class);
static int add_sensor_node(picl_nodehdl_t fruhdl, picl_nodehdl_t lochdl,
    char *nodename, char *class, char *prop_class,
    picl_prophdl_t tblhdl, picl_nodehdl_t *sensorhdlp);
static int create_table(picl_nodehdl_t fruhdl, picl_prophdl_t *tblhdlp,
    char *tbl_name);
static int create_table_entry(picl_prophdl_t tblhdl,
    picl_nodehdl_t refhdl, char *class);
static int get_sensor_data(ptree_rarg_t *arg, void *result);
static int get_led(char *name, char *ptr, char *result);
static int get_led_data(ptree_rarg_t *arg, void *result);
static int set_led_data(ptree_warg_t *arg, const void *value);
static int get_cpu_status(ptree_rarg_t *arg, void *result);
static int add_board_status(picl_nodehdl_t nodeh, char *nodename);
static int get_board_status(ptree_rarg_t *arg, void *result);
static int get_op_status(ptree_rarg_t *arg, void *result);

#define	sprintf_buf2(buf, a1, a2) (void) snprintf(buf, sizeof (buf), a1, a2)
#define	sprintf_buf3(buf, a1, a2, a3) \
	(void) snprintf(buf, sizeof (buf), a1, a2, a3)
#define	sprintf_buf4(buf, a1, a2, a3, a4) \
	(void) snprintf(buf, sizeof (buf), a1, a2, a3, a4)
#define	sprintf_buf5(buf, a1, a2, a3, a4, a5) \
	(void) snprintf(buf, sizeof (buf), a1, a2, a3, a4, a5)
/*
 * This function is executed as part of .init when the plugin is
 * dlopen()ed
 */
static void
piclfrutree_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * This function is the init entry point of the plugin.
 * It initializes the /frutree tree
 */
static void
piclfrutree_init(void)
{
	int err;

	(void) ptree_register_handler(PICLEVENT_DR_AP_STATE_CHANGE,
	    frudr_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_MC_ADDED,
	    frumemcfg_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_MC_REMOVED,
	    frumemcfg_evhandler, NULL);
	init_complete = 0;

	err = add_all_nodes();
	disk_leds_init();
	init_complete = 1;
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_NODES_FAIL, err);
		piclfrutree_fini();
	}
}

/*
 * This function is the fini entry point of the plugin.
 */
static void
piclfrutree_fini(void)
{
	(void) ptree_unregister_handler(PICLEVENT_DR_AP_STATE_CHANGE,
	    frudr_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_MC_ADDED,
	    frumemcfg_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_MC_REMOVED,
	    frumemcfg_evhandler, NULL);
	(void) remove_subtree(frutreeh);
	disk_leds_fini();
}

/*
 * called from piclfrutree_init() to initialise picl frutree
 */
static int
add_all_nodes(void)
{
	int err;
	picl_nodehdl_t rooth;

	/* Get the root node of the PICL tree */
	err = ptree_get_root(&rooth);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, GET_ROOT_FAIL);
		return (err);
	}

	/* find sc node so we can create sensor nodes under it */

	err = ptree_get_node_by_path(SC_DEV, &sch);
	if (err != PICL_SUCCESS) {

		/*
		 * There is a XMITS/PCI-X IO Board assembly implements
		 * a different path for the the bootbus controller.
		 */
		err = ptree_get_node_by_path(SC_DEV_PCIX, &sch);
		if (err == PICL_SUCCESS)
			pcix_io = 1;
	}

	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, NO_SC_FAIL);
		return (err);
	}

	/* Create and add the root node of the FRU subtree */
	err = ptree_create_and_add_node(rooth, PICL_NODE_FRUTREE,
	    PICL_CLASS_PICL, &frutreeh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_FRUTREE_FAIL);
		return (err);
	}

	/* Recursively query the SC and add frutree nodes */
	return (add_subtree(frutreeh, ROOTPARENT));
}

/*
 * Recursive routine to add picl nodes to the frutree. Called from
 * add_all_nodes() for the whole frutree at initialisation, and from
 * frudr_evhandler() for portions of the frutree on DR insert events
 */
static int
add_subtree(picl_nodehdl_t parh, fru_hdl_t handle)
{
	int	err, i;
	int	num_children;
	sgfrunode_t	*cp, *fruchildren = NULL;
	picl_nodehdl_t childh;

	/* find children of the parent node */
	fruchildren = get_node_children(handle, &num_children);
	if (fruchildren == NULL)
		return (PICL_FAILURE);

	/* for each child, add a new picl node */
	for (i = 0, cp = fruchildren; i < num_children; i++, cp++) {
		/*
		 * Add the appropriate PICL class
		 */
		childh = 0;
		err = add_picl_node(parh, cp, &childh);
		if (err == PICL_NOTNODE)
			continue;
		if (err != PICL_SUCCESS) {
			free(fruchildren);
			return (err);
		}

		/*
		 * Recursively call this function based on has_children hint
		 */
		if (childh && cp->has_children) {
			err = add_subtree(childh, cp->handle);
			if (err != PICL_SUCCESS) {
				free(fruchildren);
				return (err);
			}
		}
	}
	free(fruchildren);
	return (PICL_SUCCESS);
}

/*
 * Recursive routine to remove picl nodes to the frutree. Called from
 * piclfrutree_fini() for the whole frutree at termination, and from
 * frudr_completion_handler() for portions of the frutree on DR remove events
 */
static int
remove_subtree(picl_nodehdl_t parh)
{
	picl_nodehdl_t chdh;

	for (;;) {
		if (ptree_get_propval_by_name(parh, PICL_PROP_CHILD, &chdh,
		    sizeof (picl_nodehdl_t)) == PICL_SUCCESS) {
			if (remove_subtree(chdh) != PICL_SUCCESS)
				return (PICL_FAILURE);
		} else {
			return (remove_picl_node(parh));
		}
	}
	/* NOTREACHED */
}

/*
 * Add fru and location nodes with SC_handle property
 * (aka, container handle, for frus).
 * Return picl_nodehdl of created node in *childp.
 */
static int
add_picl_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp)
{
	switch (sgfrunode->class) {
	case PSEUDO_FRU_CLASS:
		return (add_chassis_node(parh, sgfrunode, childp));

	case FRU_CLASS:
		return (add_fru_node(parh, sgfrunode, childp));

	case LOCATION_CLASS:
		return (add_location_node(parh, sgfrunode, childp));

	default:
		syslog(LOG_ERR, INVALID_PICL_CLASS, sgfrunode->class);
		return (PICL_NOTNODE);
	}
}

/*
 * create chassis node
 */
static int
add_chassis_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp)
{
	int err;
	uint64_t handle = (uint64_t)sgfrunode->handle;
	picl_prophdl_t	tblhdl;
	picl_nodehdl_t nodeh;
	picl_nodehdl_t devhdl;
	picl_nodehdl_t childh;

	err = ptree_create_and_add_node(parh, PICL_PROPVAL_CHASSIS,
	    PICL_CLASS_FRU, &childh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_NODE_FAIL, PICL_PROPVAL_CHASSIS, err);
		return (err);
	}
	err = add_prop_ull(childh, handle, PICL_PROP_SC_HANDLE);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * add devices table to chassis node (may need references
	 * to led devices)
	 */
	err = create_table(childh, &tblhdl, PICL_PROP_DEVICES);
	if (err != PICL_SUCCESS)
		return (err);

	err = add_led_nodes(childh, "chassis", LOM_LED_POSITION_FRU, tblhdl);
	if (err != PICL_SUCCESS)
		return (err);

	if (pcix_io)
		err = ptree_get_node_by_path(DISK0_DEV_PCIX, &devhdl);
	else
		err = ptree_get_node_by_path(DISK0_DEV, &devhdl);

	nodeh = childh;
	if (err != PICL_SUCCESS) {
		err = add_intermediate_location(&nodeh, "DISK0", "disk-slot");
	} else {
		err = add_intermediate_nodes(&nodeh, "DISK0", &tblhdl,
		    "disk-slot", NULL);
		if (err != PICL_SUCCESS)
			return (err);
		err = add_prop_ref(devhdl, nodeh, PICL_REFPROP_FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
		err = create_table_entry(tblhdl, devhdl, PICL_CLASS_BLOCK);
	}
	if (err != PICL_SUCCESS)
		return (err);

	if (pcix_io)
		err = ptree_get_node_by_path(DISK1_DEV_PCIX, &devhdl);
	else
		err = ptree_get_node_by_path(DISK1_DEV, &devhdl);

	nodeh = childh;
	if (err != PICL_SUCCESS) {
		err = add_intermediate_location(&nodeh, "DISK1", "disk-slot");
	} else {
		err = add_intermediate_nodes(&nodeh, "DISK1", &tblhdl,
		    "disk-slot", NULL);
		if (err != PICL_SUCCESS)
			return (err);
		err = add_prop_ref(devhdl, nodeh, PICL_REFPROP_FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
		err = create_table_entry(tblhdl, devhdl, PICL_CLASS_BLOCK);
	}
	if (err != PICL_SUCCESS)
		return (err);

	if (pcix_io)
		err = ptree_get_node_by_path(TAPE_DEV_PCIX, &devhdl);
	else
		err = ptree_get_node_by_path(TAPE_DEV, &devhdl);

	nodeh = childh;
	if (err != PICL_SUCCESS) {
		err = add_intermediate_location(&nodeh, "TAPE", "tape-slot");
	} else {
		err = add_intermediate_nodes(&nodeh, "TAPE", &tblhdl,
		    "tape-slot", NULL);
		if (err != PICL_SUCCESS)
			return (err);
		err = add_prop_ref(devhdl, nodeh, PICL_REFPROP_FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
		err = create_table_entry(tblhdl, devhdl, PICL_CLASS_TAPE);
	}
	if (err != PICL_SUCCESS)
		return (err);

	if (pcix_io)
		err = ptree_get_node_by_path(DVD_DEV_PCIX, &devhdl);
	else
		err = ptree_get_node_by_path(DVD_DEV, &devhdl);

	nodeh = childh;
	if (err != PICL_SUCCESS) {
		err = add_intermediate_location(&nodeh, "DVD", "dvd-slot");
	} else {
		err = add_intermediate_nodes(&nodeh, "DVD", &tblhdl,
		    "dvd-slot", NULL);
		if (err != PICL_SUCCESS)
			return (err);
		err = add_prop_ref(devhdl, nodeh, PICL_REFPROP_FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
		err = create_table_entry(tblhdl, devhdl, PICL_CLASS_CDROM);
	}
	if (err != PICL_SUCCESS)
		return (err);

	if (pcix_io) {
		/*
		 * The XMITS/PCI-X IO Assembly is layed out a bit differently.
		 */
		err = add_pci_location(childh, "19,600000", '1', "PCI0");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "19,600000", '2', "PCI1");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "19,700000", '1', "PCI2");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "19,700000", '2', "PCI3");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "18,600000", '1', "PCI4");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "18,600000", '2', "PCI5");
		if (err != PICL_SUCCESS)
			return (err);
	} else {
		err = add_pci_location(childh, "18,700000", '1', "PCI0");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "18,700000", '2', "PCI1");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "19,700000", '1', "PCI2");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "19,700000", '2', "PCI3");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "19,700000", '3', "PCI4");
		if (err != PICL_SUCCESS)
			return (err);
		err = add_pci_location(childh, "18,600000", '1', "PCI5");
		if (err != PICL_SUCCESS)
			return (err);
	}
	*childp = childh;
	return (PICL_SUCCESS);
}

/*
 * create fru node, based on sgfru node "sgfrunode" under parent parh. Return
 * picl_nodehdl of created node in *childp.
 */
static int
add_fru_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp)
{
	int err;
	picl_prophdl_t	tblhdl;
	picl_nodehdl_t childh;
	uint64_t handle = (uint64_t)sgfrunode->handle;
	char *nodename = sgfrunode->nodename;

	/*
	 * if sgfrunode already there, then just carry on own the tree
	 */
	childh = find_child_by_name(parh, nodename);
	if (childh != 0) {
		/*
		 * for frus other than dimms and ecaches, update environmental
		 * sensors and board status if necessary
		 */
		if (IS_ECACHE_NODE(nodename)) {
			*childp = childh;
			return (PICL_SUCCESS);
		}
		if (IS_DIMM_NODE(nodename)) {
			/*
			 * for dimms we just want status
			 */
			err = add_board_status(childh, nodename);
			if (err != PICL_SUCCESS)
				return (err);
			*childp = childh;
			return (PICL_SUCCESS);
		}
		err = add_board_status(childh, nodename);
		if (err != PICL_SUCCESS)
			return (err);
		err = ptree_get_propval_by_name(childh, PICL_PROP_DEVICES,
		    &tblhdl, sizeof (tblhdl));
		if (err != PICL_SUCCESS)
			return (err);
		err = add_env_nodes(childh, nodename, tblhdl);
		if (err != PICL_SUCCESS)
			return (err);
		*childp = childh;
		return (PICL_SUCCESS);
	}

	/*
	 * create requested fru node
	 */
	err = ptree_create_and_add_node(parh, nodename, PICL_CLASS_FRU,
	    &childh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_NODE_FAIL, nodename, err);
		return (err);
	}

	/*
	 * if sgfru has sent us a valid handle, then there is fruid information.
	 * create the SC_handle, and FRUDateAvailable properties for FRUID.
	 */
	if (handle != -1ULL) {
		err = add_prop_ull(childh, handle, PICL_PROP_SC_HANDLE);
		if (err != PICL_SUCCESS)
			return (err);
		err = add_prop_void(childh, PICL_PROP_FRUDATA_AVAIL);
		if (err != PICL_SUCCESS)
			return (err);
	}

	/*
	 * post fru added event to fru data plugin if this was due to
	 * a dr event - ie post-initialisation
	 */
	if (init_complete)
		post_frudr_event(PICL_FRU_ADDED, parh, 0);

	/*
	 * Create empty Devices table - we'll add lines to it as we go along
	 */
	err = create_table(childh, &tblhdl, PICL_PROP_DEVICES);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * Ecache nodes don't have sensors - just set up FRUType
	 */
	if (IS_ECACHE_NODE(nodename)) {
		err = add_prop_charstring(childh, "EEPROM", PICL_PROP_FRU_TYPE);
		if (err != PICL_SUCCESS)
			return (err);
		*childp = childh;
		return (PICL_SUCCESS);
	}

	/*
	 * Dimm nodes don't have sensors - just set up FRUType and
	 * also reference properties to memory module nodes and OpStatus
	 */
	if (IS_DIMM_NODE(nodename)) {
		err = add_prop_charstring(childh, "DIMM", PICL_PROP_FRU_TYPE);
		if (err != PICL_SUCCESS)
			return (err);
		err = create_dimm_references(parh, nodename[1] - '0',
		    childh, tblhdl);
		if (err != PICL_SUCCESS)
			return (err);
		err = add_board_status(childh, nodename);
		if (err != PICL_SUCCESS)
			return (err);
		*childp = childh;
		return (PICL_SUCCESS);
	}

	/*
	 * not a Dimm or Ecache node - set up environmental info,
	 * board status and led info
	 */
	err = add_env_nodes(childh, nodename, tblhdl);
	if (err != PICL_SUCCESS)
		return (err);

	err = add_board_status(childh, nodename);
	if (err != PICL_SUCCESS)
		return (err);

	err = add_led_nodes(childh, nodename, LOM_LED_POSITION_FRU, tblhdl);
	if (err != PICL_SUCCESS)
		return (err);

	*childp = childh;
	return (PICL_SUCCESS);
}

/*
 * create location node, based on sgfru node "sgfrunode" under parent parh.
 * Return picl_nodehdl of created node in *childp.
 */
static int
add_location_node(picl_nodehdl_t parh, sgfrunode_t *sgfrunode,
    picl_nodehdl_t *childp)
{
	int err;
	uint64_t handle = (uint64_t)sgfrunode->handle;
	char *labelp;
	char	label[MAX_LABEL_LEN];
	char *ptr;
	picl_prophdl_t tblhdl;
	picl_nodehdl_t childh;

	/*
	 * strip "N0/" off the label if present (hang-over from wildcat)
	 */
	if (strncmp(sgfrunode->location_label, LABEL_PREAMBLE,
	    LABEL_PREAMBLE_LEN) == 0)
		(void) strlcpy(label, &sgfrunode->location_label[
		    LABEL_PREAMBLE_LEN], sizeof (label));
	else
		(void) strlcpy(label, &sgfrunode->location_label[0],
		    sizeof (label));

	/*
	 * some of the locations returned by sgfru are actually of the form
	 * XX/YY/ZZ - we need to create multiple levels in the picl tree for
	 * these.
	 */
	labelp = label;
	while ((ptr = strchr(labelp, '/')) != NULL) {
		/*
		 * null end of this section of label
		 */
		*ptr = '\0';

		/*
		 * add intermediate nodes - parh will point to the created node
		 */
		if (IS_PROC_NODE(labelp)) {
			err = add_intermediate_nodes(&parh, labelp, &tblhdl,
			    "cpu", "PROC");
		} else {
			err = add_intermediate_nodes(&parh, labelp, &tblhdl,
			    NULL, NULL);
		}
		if (err != PICL_SUCCESS)
			return (err);
		/*
		 * if processor node, then create links to associated cpu node
		 * and OpStatus property
		 */
		if (IS_PROC_NODE(labelp)) {
			err = create_cpu_references(labelp, parh, tblhdl);
			if (err != PICL_SUCCESS)
				return (err);
			err = add_board_status(parh, labelp);
			if (err != PICL_SUCCESS)
				return (err);
		}
		labelp = ptr + 1;

		/*
		 * set back to "/"
		 */
		*ptr = '/';
	}

	/*
	 * if node already there, then just carry on down the tree
	 */
	childh = find_child_by_name(parh, labelp);
	if (childh != 0) {
		*childp = childh;
		return (PICL_SUCCESS);
	}

	/*
	 * now just have the final level of the node left. First create it.
	 */
	err = ptree_create_and_add_node(parh, labelp, PICL_CLASS_LOCATION,
	    &childh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_NODE_FAIL, labelp, err);
		return (err);
	}

	/*
	 * if sgfru has sent us a valid handle, then there is fruid information.
	 * create the SC_handle property for FRUID.
	 */
	if (handle != -1ULL) {
		err = add_prop_ull(childh, handle, PICL_PROP_SC_HANDLE);
		if (err != PICL_SUCCESS)
			return (err);
	}

	/* create label property for location class */
	err = add_prop_charstring(childh, labelp, PICL_PROP_LABEL);
	if (err != PICL_SUCCESS)
		return (err);

	/* create SlotType property where appropriate */
	if (IS_ECACHE_NODE(sgfrunode->nodename)) {
		err = add_prop_charstring(childh,
		    "ecache", PICL_PROP_SLOT_TYPE);
		/*
		 * For Ecache, don't need to add environmental info
		 * so return here
		 */
		*childp = childh;
		return (err);
	} else if (IS_DIMM_NODE(sgfrunode->nodename)) {
		err = add_prop_charstring(childh, "memory-module",
		    PICL_PROP_SLOT_TYPE);
		/*
		 * For Dimm, don't need to add environmental info
		 * so return here
		 */
		*childp = childh;
		return (err);
	} else if (IS_SB_NODE(sgfrunode->nodename)) {
		err = add_prop_charstring(childh, "system-board",
		    PICL_PROP_SLOT_TYPE);
	} else if (IS_PSU_NODE(sgfrunode->nodename)) {
		err = add_prop_charstring(childh, "power-supply",
		    PICL_PROP_SLOT_TYPE);
	} else if (IS_FT_NODE(sgfrunode->nodename)) {
		err = add_prop_charstring(childh, "fan-tray",
		    PICL_PROP_SLOT_TYPE);
	}
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * add devices table to location node (may need
	 * references to led devices)
	 */
	err = create_table(childh, &tblhdl, PICL_PROP_DEVICES);
	if (err != PICL_SUCCESS)
		return (err);

	err = add_led_nodes(childh, labelp, LOM_LED_POSITION_LOCATION, tblhdl);
	if (err != PICL_SUCCESS)
		return (err);
	*childp = childh;
	return (PICL_SUCCESS);
}

/*
 * remove an individual picl node - called from remove_subtree()
 * also removes any sensor nodes pointed at by Devices table
 */
static int
remove_picl_node(picl_nodehdl_t nodeh)
{
	int err;
	picl_prophdl_t  tblhdl;
	picl_prophdl_t  nextprop;
	picl_prophdl_t  refprop;
	char	class[PICL_CLASSNAMELEN_MAX];

	/*
	 * first scan Devices table so we can find any sensor nodes
	 * we need to delete as well
	 */
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_DEVICES,
	    &tblhdl, sizeof (tblhdl));

	/*
	 * If Devices table present, then read first column.
	 * Devices table may be empty so don't treat this as an error
	 */
	if (err == PICL_SUCCESS &&
	    ptree_get_next_by_row(tblhdl, &nextprop) == PICL_SUCCESS) {
		/* find second column */
		err = ptree_get_next_by_row(nextprop, &nextprop);
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, GET_NEXT_BY_ROW_FAIL,
			    PICL_PROP_DEVICES, err);
			return (err);
		}

		/*
		 * walk down second column (ref ptr)
		 * deleting the referenced nodes
		 */
		while (err == PICL_SUCCESS) {
			err = ptree_get_propval(nextprop, &refprop,
			    sizeof (refprop));
			if (err != PICL_SUCCESS) {
				syslog(LOG_ERR, GET_PROPVAL_FAIL, err);
				return (err);
			}

			/*
			 * don't delete memory-module nodes
			 * or cpu nodes (they weren't created
			 * by this plugin)
			 */
			err = ptree_get_propval_by_name(refprop,
			    PICL_PROP_CLASSNAME, class, sizeof (class));
			if (err == PICL_STALEHANDLE) {
				/*
				 * if another plugin has already deleted the
				 * node for us then that is ok
				 */
				err = ptree_get_next_by_col(nextprop,
				    &nextprop);
				continue;
			}
			if (err != PICL_SUCCESS) {
				syslog(LOG_ERR, PROP_LOOKUP_FAIL,
				    PICL_PROP_CLASSNAME, err);
				return (err);
			}
			if (strcmp(class, PICL_CLASS_MEMORY_MODULE) == 0 ||
			    strcmp(class, PICL_CLASS_CPU) == 0) {
				/*
				 * but - do need to remove _fru_parent
				 * property and Environment table (for cpu)
				 */
				err = remove_references(refprop, class);
				if (err != PICL_SUCCESS)
					return (err);
			} else {
				/*
				 * sensor node - need to delete it
				 */
				err = ptree_delete_node(refprop);
				if (err != PICL_SUCCESS) {
					syslog(LOG_ERR, DELETE_PROP_FAIL, err);
					return (err);
				}
				(void) ptree_destroy_node(refprop);
			}
			err = ptree_get_next_by_col(nextprop, &nextprop);
		}
	}

	/*
	 * now we can remove the frutree node
	 */
	err = ptree_delete_node(nodeh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, DELETE_PROP_FAIL, err);
		return (err);
	}
	(void) ptree_destroy_node(nodeh);
	return (PICL_SUCCESS);
}

static int
add_child_pci_references(picl_nodehdl_t nodeh, picl_prophdl_t tblhdl,
    picl_nodehdl_t devnodeh)
{
	int err = PICL_SUCCESS;
	picl_nodehdl_t childnodeh;
	char	class[PICL_CLASSNAMELEN_MAX];

	if (ptree_get_propval_by_name(devnodeh, PICL_PROP_CHILD, &childnodeh,
	    sizeof (childnodeh)) != PICL_SUCCESS) {
		return (PICL_SUCCESS);
	}
	for (;;) {
		err = ptree_get_propval_by_name(childnodeh,
		    PICL_PROP_CLASSNAME, class, sizeof (class));
		if (err != PICL_SUCCESS)
			break;
		err = add_prop_ref(childnodeh, nodeh, PICL_REFPROP_FRU_PARENT);
		if (err != PICL_SUCCESS)
			break;
		err = create_table_entry(tblhdl, childnodeh, class);
		if (err != PICL_SUCCESS)
			break;
		err = add_child_pci_references(nodeh, tblhdl, childnodeh);
		if (err != PICL_SUCCESS)
			break;
		err = ptree_get_propval_by_name(childnodeh,
		    PICL_PROP_PEER, &childnodeh, sizeof (picl_nodehdl_t));
		if (err != PICL_SUCCESS) {
			err = PICL_SUCCESS;
			break;
		}
	}
	return (err);
}

static int
add_pci_location(picl_nodehdl_t childh, char *parent_addr, char bus_addr,
    char *slot_name)
{
	int err;
	int got_one = 0;
	picl_nodehdl_t nodeh;
	picl_nodehdl_t devnodeh;
	picl_nodehdl_t devhdl;
	char	addr[MAXPATHLEN];
	char parent_path[MAXPATHLEN];
	picl_prophdl_t tblhdl;
	char	class[PICL_CLASSNAMELEN_MAX];

	/*
	 * search for any device nodes whose BUS_ADDR or UNIT_ADDRESS
	 * are appropriate for this pci slot
	 */
	sprintf_buf2(parent_path, IO_DEV, parent_addr);
	if (ptree_get_node_by_path(parent_path, &devhdl) == PICL_SUCCESS &&
	    ptree_get_propval_by_name(devhdl, PICL_PROP_CHILD, &devnodeh,
	    sizeof (devnodeh)) == PICL_SUCCESS) {
		while (!got_one) {
			err = ptree_get_propval_by_name(devnodeh,
			    PICL_PROP_BUS_ADDR, addr, sizeof (addr));
			if (err == PICL_SUCCESS && addr[0] == bus_addr &&
			    (addr[1] == ',' || addr[1] == '\0')) {
				got_one = 1;
				break;
			}
			err = ptree_get_propval_by_name(devnodeh,
			    PICL_PROP_UNIT_ADDRESS, addr, sizeof (addr));
			if (err == PICL_SUCCESS && addr[0] == bus_addr &&
			    (addr[1] == ',' || addr[1] == '\0')) {
				got_one = 1;
				break;
			}
			err = ptree_get_propval_by_name(devnodeh,
			    PICL_PROP_PEER, &devnodeh, sizeof (picl_nodehdl_t));
			if (err != PICL_SUCCESS)
				break;
		}
	}
	nodeh = childh;
	if (got_one == 0) {
		/*
		 * no devnodes for this slot. Create location node but
		 * no fru node (empty slot)
		 */
		return (add_intermediate_location(&nodeh, slot_name, "pci"));
	}

	/*
	 * we've got the first devnode for this slot. Create the fru node
	 * then walk along other nodes looking for further devnodes
	 */
	err = add_intermediate_nodes(&nodeh, slot_name, &tblhdl, "pci", NULL);
	if (err != PICL_SUCCESS)
		return (err);

	for (;;) {
		if (((err = ptree_get_propval_by_name(devnodeh,
		    PICL_PROP_BUS_ADDR, addr, sizeof (addr))) ==
		    PICL_SUCCESS && addr[0] == bus_addr &&
		    (addr[1] == ',' || addr[1] == '\0')) ||
		    ((err = ptree_get_propval_by_name(devnodeh,
		    PICL_PROP_UNIT_ADDRESS, addr, sizeof (addr))) ==
		    PICL_SUCCESS && addr[0] == bus_addr &&
		    (addr[1] == ',' || addr[1] == '\0'))) {
			err = ptree_get_propval_by_name(devnodeh,
			    PICL_PROP_CLASSNAME, class, sizeof (class));
			if (err != PICL_SUCCESS)
				break;
			err = add_prop_ref(devnodeh, nodeh,
			    PICL_REFPROP_FRU_PARENT);
			if (err != PICL_SUCCESS)
				break;
			err = create_table_entry(tblhdl, devnodeh, class);
			if (err != PICL_SUCCESS)
				break;
			err = add_child_pci_references(nodeh, tblhdl, devnodeh);
			if (err != PICL_SUCCESS)
				break;
		}
		err = ptree_get_propval_by_name(devnodeh,
		    PICL_PROP_PEER, &devnodeh, sizeof (picl_nodehdl_t));
		if (err != PICL_SUCCESS) {
			err = PICL_SUCCESS;
			break;
		}
	}
	return (err);
}

/*
 * add intermediate location into frutree (ie a location that we know
 * exists but sgfru doesn't)
 */
static int
add_intermediate_location(picl_nodehdl_t *nodep, char *labelp, char *slot_name)
{
	int err;
	picl_nodehdl_t intermediate;
	picl_prophdl_t tblhdl;
	char	parent_name[PICL_PROPNAMELEN_MAX];

	err = ptree_create_and_add_node(*nodep, labelp, PICL_CLASS_LOCATION,
	    &intermediate);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_NODE_FAIL, labelp, err);
		return (err);
	}

	/*
	 * create label property for location class
	 */
	err = add_prop_charstring(intermediate, labelp, PICL_PROP_LABEL);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * add devices table to location node (may need references to led
	 * devices)
	 */
	err = create_table(intermediate, &tblhdl, PICL_PROP_DEVICES);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * scapp knows FANs 0 and 1 on IB as FAN8 and FAN9
	 */
	err = ptree_get_propval_by_name(*nodep, PICL_PROP_NAME, parent_name,
	    sizeof (parent_name));
	if (err != PICL_SUCCESS)
		return (err);
	if (strcmp(labelp, "FAN0") == 0 && strcmp(parent_name, "IB6") == 0)
		err = add_led_nodes(intermediate, "FAN8",
		    LOM_LED_POSITION_LOCATION, tblhdl);
	else if (strcmp(labelp, "FAN1") == 0 && strcmp(parent_name, "IB6") == 0)
		err = add_led_nodes(intermediate, "FAN9",
		    LOM_LED_POSITION_LOCATION, tblhdl);
	else
		err = add_led_nodes(intermediate, labelp,
		    LOM_LED_POSITION_LOCATION, tblhdl);
	if (err != PICL_SUCCESS)
		return (err);

	if (slot_name) {
		err = add_prop_charstring(intermediate, slot_name,
		    PICL_PROP_SLOT_TYPE);
		if (err != PICL_SUCCESS)
			return (err);
	}
	*nodep = intermediate;
	return (PICL_SUCCESS);
}

/*
 * adds an intermediate location/fru pair into frutree
 */
static int
add_intermediate_nodes(picl_nodehdl_t *nodep, char *labelp,
    picl_prophdl_t *tblhdlp, char *slot_name, char *fru_name)
{
	int err;
	picl_nodehdl_t intermediate;
	picl_nodehdl_t intermediate2;

	/*
	 * create intermediate location node (unless it has already been
	 * created)
	 */
	intermediate = find_child_by_name(*nodep, labelp);
	if (intermediate == 0) {
		intermediate = *nodep;
		err = add_intermediate_location(&intermediate, labelp,
		    slot_name);
		if (err != PICL_SUCCESS) {
			return (err);
		}
	}

	/*
	 * create intermediate fru node (unless it has already been
	 * created)
	 */
	intermediate2 = find_child_by_name(intermediate, labelp);
	if (intermediate2 == 0) {
		/*
		 * need to create intermediate fru node node
		 */
		err = ptree_create_and_add_node(intermediate, labelp,
		    PICL_CLASS_FRU, &intermediate2);
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, ADD_NODE_FAIL, labelp, err);
			return (err);
		}

		/*
		 * Create empty Devices table
		 */
		err = create_table(intermediate2, tblhdlp, PICL_PROP_DEVICES);
		if (err != PICL_SUCCESS)
			return (err);

		if (fru_name) {
			err = add_prop_charstring(intermediate2, fru_name,
			    PICL_PROP_FRU_TYPE);
			if (err != PICL_SUCCESS)
				return (err);
		}
	} else  {
		err = ptree_get_propval_by_name(intermediate2,
		    PICL_PROP_DEVICES, tblhdlp, sizeof (*tblhdlp));
		if (err != PICL_SUCCESS)
			return (err);
	}
	*nodep = intermediate2;
	return (PICL_SUCCESS);
}

/*
 * need to remove _fru_parent property and Environment table (for cpu)
 */
static int
remove_references(picl_prophdl_t refprop, char *class)
{
	picl_prophdl_t  platprop;
	int err;

	err = ptree_get_prop_by_name(refprop, PICL_REFPROP_FRU_PARENT,
	    &platprop);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_delete_prop(platprop);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, DELETE_PROP_FAIL, err);
		return (err);
	}
	(void) ptree_destroy_prop(platprop);
	if (strcmp(class, PICL_CLASS_CPU) == 0) {
		err = ptree_get_prop_by_name(refprop, PICL_PROP_ENV, &platprop);
		if (err != PICL_SUCCESS) {
			/*
			 * multi-core cpu is setup with only one cpu having
			 * env table so ignore PICL_PROPNOTFOUND error.
			 */
			if (err == PICL_PROPNOTFOUND) {
				return (PICL_SUCCESS);
			}
			syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_ENV, err);
			return (err);
		}
		err = ptree_delete_prop(platprop);
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, DELETE_PROP_FAIL, err);
			return (err);
		}
		(void) ptree_destroy_prop(platprop);
	}
	return (PICL_SUCCESS);
}

/*
 * subroutine for various functions. Finds immediate child of parh with
 * requested name if present. Otherwise returns NULL.
 */
static picl_nodehdl_t
find_child_by_name(picl_nodehdl_t parh, char *name)
{
	picl_nodehdl_t nodeh;
	int err;
	char	nodename[PICL_PROPNAMELEN_MAX];

	err = ptree_get_propval_by_name(parh, PICL_PROP_CHILD,
	    &nodeh, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS)
		return (0);
	for (;;) {
		err = ptree_get_propval_by_name(nodeh, PICL_PROP_NAME, nodename,
		    sizeof (nodename));
		if (err != PICL_SUCCESS)
			return (0);
		if (strcmp(name, nodename) == 0) {
			return (nodeh);
		}
		err = ptree_get_propval_by_name(nodeh, PICL_PROP_PEER,
		    &nodeh, sizeof (picl_nodehdl_t));
		if (err != PICL_SUCCESS)
			return (0);
	}
}

static int
create_dimm_references(picl_nodehdl_t parh, int dimm_id,
    picl_nodehdl_t nodeh, picl_prophdl_t tblhdl)
{
	int err;
	picl_nodehdl_t memctlhdl = 0;
	picl_nodehdl_t memgrphdl;
	picl_nodehdl_t memhdl;
	char name[MAXPATHLEN];
	char	sbname[PICL_PROPNAMELEN_MAX];
	char	pname[PICL_PROPNAMELEN_MAX];
	char	bname[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t parentfruh;
	picl_nodehdl_t parentloch;
	int id;

	/*
	 * create reference properties for memory nodes
	 * - first find names of ancestor frus - ie "SBx/Py/Bz"
	 */
	err = ptree_get_propval_by_name(parh, PICL_PROP_PARENT, &parentfruh,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentfruh, PICL_PROP_NAME,
	    bname, sizeof (bname));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_NAME, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentfruh, PICL_PROP_PARENT,
	    &parentloch, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentloch, PICL_PROP_PARENT,
	    &parentfruh, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentfruh, PICL_PROP_NAME,
	    pname, sizeof (pname));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_NAME, err);
		return (err);
	}

	err = ptree_get_propval_by_name(parentfruh, PICL_PROP_PARENT,
	    &parentloch, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentloch, PICL_PROP_PARENT,
	    &parentfruh, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentfruh, PICL_PROP_NAME, sbname,
	    sizeof (sbname));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_NAME, err);
		return (err);
	}

	/*
	 * ok - we've now got name of system board node in sbname and
	 * name of processor node in pname.
	 * Now find corresponding memory-controller node if present
	 */
	sprintf_buf2(name, MEMORY_DEV, SB_P_TO_SAFARI_ADDR(sbname, pname));
	err = ptree_get_node_by_path(name, &memctlhdl);
	if (err != PICL_SUCCESS)
		return (PICL_SUCCESS);

	/*
	 * now find corresponding memory-module-group node if present
	 */
	err = ptree_get_propval_by_name(memctlhdl, PICL_PROP_CHILD, &memgrphdl,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS)
		return (PICL_SUCCESS);

	/*
	 * check if this is the right bank - if not move on to sibling
	 */
	err = ptree_get_propval_by_name(memgrphdl, PICL_PROP_ID,
	    &id, sizeof (int));
	if (err != PICL_SUCCESS)
		return (PICL_SUCCESS);
	if (bname[1] != id + '0') {
		err = ptree_get_propval_by_name(memgrphdl, PICL_PROP_PEER,
		    &memgrphdl, sizeof (picl_nodehdl_t));
		if (err != PICL_SUCCESS)
			return (PICL_SUCCESS);
		err = ptree_get_propval_by_name(memgrphdl, PICL_PROP_ID,
		    &id, sizeof (int));
		if (err != PICL_SUCCESS)
			return (PICL_SUCCESS);
		if (bname[1] != id + '0')
			return (PICL_SUCCESS);
	}

	/*
	 * now find corresponding memory-module node if present
	 */
	err = ptree_get_propval_by_name(memgrphdl, PICL_PROP_CHILD, &memhdl,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS)
		return (PICL_SUCCESS);

	/*
	 * for each DIMM set up links with matching memory-module node
	 */
	for (;;) {
		err = ptree_get_propval_by_name(memhdl, PICL_PROP_ID,
		    &id, sizeof (int));
		if (err == PICL_SUCCESS && dimm_id == id) {
			err = add_prop_ref(memhdl, nodeh,
			    PICL_REFPROP_FRU_PARENT);
			if (err != PICL_SUCCESS)
				return (err);
			err = create_table_entry(tblhdl, memhdl,
			    PICL_CLASS_MEMORY_MODULE);
			if (err != PICL_SUCCESS)
				return (err);
		}
		err = ptree_get_propval_by_name(memhdl, PICL_PROP_PEER,
		    &memhdl, sizeof (picl_nodehdl_t));
		if (err != PICL_SUCCESS)
			break;
	}
	return (PICL_SUCCESS);
}

static int
create_cpu_references(char *pname, picl_nodehdl_t nodeh, picl_prophdl_t tblhdl)
{
	int err;
	picl_nodehdl_t sensorhdl;
	picl_nodehdl_t parentloch;
	picl_nodehdl_t parentfruh;
	picl_nodehdl_t cpuhdl;
	picl_nodehdl_t cpuhdl1;
	picl_prophdl_t envtblhdl;
	picl_prophdl_t prophdl;
	char name[MAXPATHLEN];
	char	sbname[PICL_PROPNAMELEN_MAX];

	err = ptree_get_propval_by_name(nodeh, PICL_PROP_PARENT,
	    &parentloch, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentloch, PICL_PROP_PARENT,
	    &parentfruh, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(parentfruh, PICL_PROP_NAME, sbname,
	    sizeof (sbname));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_NAME, err);
		return (err);
	}

	/*
	 * Find corresponding cpu node if present. Note, this code will
	 * attempt to find a corresponding cpu node, by searching for devices
	 * of the types  /platform/ssm@0,0/SUNW,UltraSPARC-III+@%x,0,
	 * /platform/ssm@0,0/SUNW,UltraSPARC-III@%x,0 or
	 * /platform/ssm@0,0/cmp@%x,0/cpu@0 or 1. If we can not find
	 * any such device, we return PICL_SUCCESS such that we
	 * continue the construction of the remaining part of the
	 * tree. We first check for UltraSPARC-III. If we do not
	 * find such a device we check for UltraSPARC-III+. If
	 * we are unsuccesful again we try one of the jaguar cores
	 * /platform/ssm@0,0/cmp@%x,0/cpu@. If we do not find the
	 * first one, there's no point in continuing and we just
	 * return PICL_SUCCESS. Similarly if we find one core
	 * but not the other, something must be wrong, so we
	 * again just return PICL_SUCCESS without creating any
	 * references.
	 */
	sprintf_buf2(name, CPU_DEV, SB_P_TO_SAFARI_ADDR(sbname, pname));

	err = ptree_get_node_by_path(name, &cpuhdl);

	if (err != PICL_SUCCESS) {
		sprintf_buf2(name, CPU_DEV2,
		    SB_P_TO_SAFARI_ADDR(sbname, pname));
		err = ptree_get_node_by_path(name, &cpuhdl);
		if (err != PICL_SUCCESS) {
			/* check for jaguar cores */
			sprintf_buf2(name, CPU_DEV3C1,
			    SB_P_TO_SAFARI_ADDR(sbname, pname));
			err = ptree_get_node_by_path(name, &cpuhdl1);
			if (err != PICL_SUCCESS)
				return (PICL_SUCCESS);
			/* add fru parent reference for the second core */
			err = ptree_get_prop_by_name(cpuhdl1,
			    PICL_REFPROP_FRU_PARENT, &prophdl);
			if (err != PICL_SUCCESS) {
				err = add_prop_ref(cpuhdl1, nodeh,
				    PICL_REFPROP_FRU_PARENT);
			if (err != PICL_SUCCESS)
				return (err);
			err = create_table_entry(tblhdl, cpuhdl1,
			    PICL_CLASS_CPU);
			if (err != PICL_SUCCESS)
				return (err);
			}
			sprintf_buf2(name, CPU_DEV3C0,
			    SB_P_TO_SAFARI_ADDR(sbname, pname));
			err = ptree_get_node_by_path(name, &cpuhdl);
			if (err != PICL_SUCCESS)
				return (PICL_SUCCESS);

		}
	}

	/*
	 * now create reference properties
	 */
	err = ptree_get_prop_by_name(cpuhdl, PICL_REFPROP_FRU_PARENT, &prophdl);
	if (err != PICL_SUCCESS) {
		err = add_prop_ref(cpuhdl, nodeh, PICL_REFPROP_FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
		err = create_table_entry(tblhdl, cpuhdl, PICL_CLASS_CPU);
		if (err != PICL_SUCCESS)
			return (err);
	}

	/*
	 * create Environment table on cpu node - with Die and Ambient
	 * temperature sensors if present. If already there, delete and start
	 * again
	 */
	err = ptree_get_prop_by_name(cpuhdl, PICL_PROP_ENV, &prophdl);
	if (err == PICL_SUCCESS) {
		err = ptree_delete_prop(prophdl);
		if (err != PICL_SUCCESS)
			return (err);
		(void) ptree_destroy_prop(prophdl);
	}
	err = create_table(cpuhdl, &envtblhdl, PICL_PROP_ENV);
	if (err != PICL_SUCCESS)
		return (err);

	if (pcix_io)
		sprintf_buf4(name, "%s/%s_t_cheetah%d@0", SC_DEV_PCIX, sbname,
		    (pname[1] - '0'));
	else
		sprintf_buf4(name, "%s/%s_t_cheetah%d@0", SC_DEV, sbname,
		    (pname[1] - '0'));

	err = ptree_get_node_by_path(name, &sensorhdl);
	if (err == PICL_SUCCESS) {
		err = create_table_entry(envtblhdl, sensorhdl,
		    PICL_CLASS_TEMPERATURE_SENSOR);
		if (err != PICL_SUCCESS)
			return (err);
	}

	if (pcix_io)
		sprintf_buf4(name, "%s/%s_t_ambient%d@0", SC_DEV_PCIX, sbname,
		    (pname[1] - '0'));
	else
		sprintf_buf4(name, "%s/%s_t_ambient%d@0", SC_DEV, sbname,
		    (pname[1] - '0'));

	err = ptree_get_node_by_path(name, &sensorhdl);
	if (err == PICL_SUCCESS) {
		return (create_table_entry(envtblhdl, sensorhdl,
		    PICL_CLASS_TEMPERATURE_SENSOR));
	}
	return (PICL_SUCCESS);
}

/*
 * subroutine of add_subtree - get a list of children of a parent node
 */
static sgfrunode_t *
get_node_children(fru_hdl_t fruparent, int *num_childrenp)
{
	int	max_children, i;
	sgfrunode_t	*fruchildren = NULL;
	child_info_t child_info;
	int  frufd;

	/*
	 * Open the sgfru pseudo dev
	 */
	if ((frufd = open(FRU_PSEUDO_DEV, O_RDWR, 0)) == -1) {
		syslog(LOG_ERR, DEV_OPEN_FAIL, FRU_PSEUDO_DEV, strerror(errno));
		return (NULL);
	}
	for (i = 1; i <= MAX_TRIES; i++) {
		max_children = i * MAX_NODE_CHILDREN;
		if ((fruchildren = calloc(max_children,
		    sizeof (sgfrunode_t))) == NULL) {
			(void) close(frufd);
			syslog(LOG_ERR, MALLOC_FAIL);
			return (NULL);
		}
		child_info.fru_hdl = fruparent;
		child_info.fru_cnt = max_children;
		child_info.frus = (void *)fruchildren;
		if (ioctl(frufd, SGFRU_GETCHILDLIST, &child_info) == 0) {
			/*
			 * got them - return success
			 */
			(void) close(frufd);
			*num_childrenp = child_info.fru_cnt;
			return (fruchildren);
		}
		free(fruchildren);

		/*
		 * if ENOMEM, need to calloc more space - so go round loop again
		 * otherwise fail
		 */
		if (errno != ENOMEM) {
			(void) close(frufd);
			syslog(LOG_ERR, SGFRU_IOCTL_FAIL, SGFRU_GETCHILDLIST,
			    fruparent, strerror(errno));
			return (NULL);
		}
	}
	(void) close(frufd);
	syslog(LOG_ERR, MALLOC_FAIL);
	return (NULL);
}

/* Creates an unsigned longlong property for a given PICL node */
static int
add_prop_ull(picl_nodehdl_t nodeh, uint64_t handle, char *name)
{
	picl_prophdl_t proph;
	ptree_propinfo_t propinfo;
	int err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (unsigned long long),
	    PICL_PROP_SC_HANDLE, NULL, NULL);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROPINFO_FAIL, name, err);
		return (err);
	}
	err = ptree_create_and_add_prop(nodeh, &propinfo, &handle, &proph);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, name, err);
		return (err);
	}
	return (PICL_SUCCESS);
}

/* Creates a void property for a given PICL node */
static int
add_prop_void(picl_nodehdl_t nodeh, char *name)
{
	picl_prophdl_t proph;
	ptree_propinfo_t propinfo;
	int err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_VOID, PICL_READ, 0, PICL_PROP_FRUDATA_AVAIL, NULL, NULL);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROPINFO_FAIL, name, err);
		return (err);
	}
	err = ptree_create_and_add_prop(nodeh, &propinfo, NULL, &proph);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, name, err);
		return (err);
	}
	return (PICL_SUCCESS);
}

/* Creates a reference property for a given PICL node */
static int
add_prop_ref(picl_nodehdl_t nodeh, picl_nodehdl_t value, char *name)
{
	picl_prophdl_t proph;
	ptree_propinfo_t propinfo;
	int err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_REFERENCE, PICL_READ, sizeof (picl_nodehdl_t), name,
	    NULL, NULL);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROPINFO_FAIL, name, err);
		return (err);
	}
	err = ptree_create_and_add_prop(nodeh, &propinfo, &value, &proph);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, name, err);
		return (err);
	}
	return (PICL_SUCCESS);
}

/* Creates an integer property for a given PICL node */
static int
add_prop_int(picl_nodehdl_t nodeh, int value, char *name)
{
	picl_prophdl_t proph;
	ptree_propinfo_t propinfo;
	int err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_INT, PICL_READ, sizeof (int), name, NULL, NULL);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROPINFO_FAIL, name, err);
		return (err);
	}
	err = ptree_create_and_add_prop(nodeh, &propinfo, &value, &proph);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, name, err);
		return (err);
	}
	return (PICL_SUCCESS);
}

/* Creates an integer property for a given PICL node */
static int
add_prop_float(picl_nodehdl_t nodeh, float value, char *name)
{
	picl_prophdl_t proph;
	ptree_propinfo_t propinfo;
	int err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_FLOAT, PICL_READ, sizeof (float), name, NULL, NULL);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROPINFO_FAIL, name, err);
		return (err);
	}
	err = ptree_create_and_add_prop(nodeh, &propinfo, &value, &proph);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, name, err);
		return (err);
	}
	return (PICL_SUCCESS);
}

/* Creates a charstring property for a given PICL node */
static int
add_prop_charstring(picl_nodehdl_t nodeh, char *value, char *name)
{
	picl_prophdl_t proph;
	ptree_propinfo_t propinfo;
	int err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(value) + 1,
	    name, NULL, NULL);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROPINFO_FAIL, name, err);
		return (err);
	}
	err = ptree_create_and_add_prop(nodeh, &propinfo, value, &proph);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, name, err);
		return (err);
	}
	return (PICL_SUCCESS);
}

/* create an entry in the specified table */
static int
create_table_entry(picl_prophdl_t tblhdl, picl_nodehdl_t refhdl, char *class)
{
	int			err;
	ptree_propinfo_t	prop;
	picl_prophdl_t		prophdl[2];

	/* first column is class */
	prop.version = PTREE_PROPINFO_VERSION;
	prop.piclinfo.type =  PICL_PTYPE_CHARSTRING;
	prop.piclinfo.accessmode = PICL_READ;
	prop.piclinfo.size = PICL_CLASSNAMELEN_MAX;
	prop.read = NULL;
	prop.write = NULL;
	(void) strlcpy(prop.piclinfo.name, PICL_PROP_CLASS,
	    sizeof (prop.piclinfo.name));
	err = ptree_create_prop(&prop, class, &prophdl[0]);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_TBL_ENTRY_FAIL, err);
		return (err);
	}

	/* second column is refernce property */
	prop.version = PTREE_PROPINFO_VERSION;
	prop.piclinfo.type =  PICL_PTYPE_REFERENCE;
	prop.piclinfo.accessmode = PICL_READ;
	prop.piclinfo.size = sizeof (picl_nodehdl_t);
	prop.read = NULL;
	prop.write = NULL;
	sprintf_buf2(prop.piclinfo.name, "_%s_", class);
	err = ptree_create_prop(&prop, &refhdl, &prophdl[1]);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_TBL_ENTRY_FAIL, err);
		return (err);
	}

	/* add row to table */
	err = ptree_add_row_to_table(tblhdl, 2, prophdl);
	if (err != PICL_SUCCESS)
		syslog(LOG_ERR, ADD_TBL_ENTRY_FAIL, err);
	return (err);
}

/* create an empty table property */
static int
create_table(picl_nodehdl_t fruhdl, picl_prophdl_t *tblhdlp, char *tbl_name)
{
	int			err;
	ptree_propinfo_t	prop;
	picl_prophdl_t		tblprophdl;

	err = ptree_create_table(tblhdlp);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, tbl_name, err);
		return (err);
	}
	prop.version = PTREE_PROPINFO_VERSION;
	prop.piclinfo.type =  PICL_PTYPE_TABLE;
	prop.piclinfo.accessmode = PICL_READ;
	prop.piclinfo.size = sizeof (picl_prophdl_t);
	prop.read = NULL;
	prop.write = NULL;
	(void) strlcpy(prop.piclinfo.name, tbl_name,
	    sizeof (prop.piclinfo.name));
	err = ptree_create_and_add_prop(fruhdl, &prop, tblhdlp, &tblprophdl);
	if (err != PICL_SUCCESS)
		syslog(LOG_ERR, ADD_PROP_FAIL, tbl_name, err);
	return (err);
}

static void
frudr_add_subtree(picl_nodehdl_t parh)
{
	fru_hdl_t	sgfruhdl;
	if (ptree_get_propval_by_name(parh, PICL_PROP_SC_HANDLE,
	    &sgfruhdl, sizeof (sgfruhdl)) != PICL_SUCCESS) {
		return;
	}
	(void) add_subtree(parh, sgfruhdl);
}

/* event completion handler for PICL_FRU_ADDED/PICL_FRU_REMOVED events */
/*ARGSUSED*/
static void
frudr_completion_handler(char *ename, void *earg, size_t size)
{
	picl_nodehdl_t	fruh;
	picl_nodehdl_t	parh;

	if (strcmp(ename, PICL_FRU_REMOVED) == 0) {
		/*
		 * now frudata has been notified that the node is to be
		 * removed, we can actually remove it
		 */
		fruh = 0;
		(void) nvlist_lookup_uint64(earg,
		    PICLEVENTARG_FRUHANDLE, &fruh);
		if (fruh != 0) {
			(void) remove_subtree(fruh);

			/*
			 * Now repopulate the frutree with current data.
			 */
			parh = 0;
			(void) nvlist_lookup_uint64(earg,
			    PICLEVENTARG_PARENTHANDLE, &parh);
			if (parh != 0) {
				frudr_add_subtree(parh);
			}
		}
	}
	nvlist_free(earg);
	free(earg);
	free(ename);
}

/*
 * Post the PICL_FRU_ADDED/PICL_FRU_REMOVED event
 */
static void
post_frudr_event(char *ename, picl_nodehdl_t parenth, picl_nodehdl_t fruh)
{
	nvlist_t	*nvl;
	char		*ev_name;

	ev_name = strdup(ename);
	if (ev_name == NULL)
		return;
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0)) {
		free(ev_name);
		return;
	}
	if (parenth != 0L &&
	    nvlist_add_uint64(nvl, PICLEVENTARG_PARENTHANDLE, parenth)) {
		free(ev_name);
		nvlist_free(nvl);
		return;
	}
	if (fruh != 0L &&
	    nvlist_add_uint64(nvl, PICLEVENTARG_FRUHANDLE, fruh)) {
		free(ev_name);
		nvlist_free(nvl);
		return;
	}
	if (ptree_post_event(ev_name, nvl, sizeof (nvl),
	    frudr_completion_handler) != 0) {
		free(ev_name);
		nvlist_free(nvl);
	}
}

/*
 * updates the picl node 'loc' with the new fru handle (PICL_PROP_SC_HANDLE)
 * (helper function for frudr_evhandler, when a stale fru handle is
 * detected)
 */
static void
update_fru_hdl(picl_nodehdl_t loc, fru_hdl_t newsgfruhdl)
{
	picl_prophdl_t	schproph;
	int		err;

	err = ptree_get_prop_by_name(loc, PICL_PROP_SC_HANDLE, &schproph);
	if (err == PICL_SUCCESS) {
		if (ptree_delete_prop(schproph) == PICL_SUCCESS) {
			(void) ptree_destroy_prop(schproph);
		}
	}
	(void) add_prop_ull(loc, (uint64_t)newsgfruhdl, PICL_PROP_SC_HANDLE);
}

/*
 * Get the fru handle of loc by iterating through the parent's children.
 * Sets fruhdl and returns PICL_SUCCESS unless an error is encountered.
 */
static int
get_fruhdl_from_parent(picl_nodehdl_t loc, fru_hdl_t *fruhdl)
{
	picl_nodehdl_t	parlocnodeh;
	fru_hdl_t	parsgfruhdl;
	sgfrunode_t	*cp;
	sgfrunode_t	*fruchildren;
	char		nodename[PICL_PROPNAMELEN_MAX];
	int		err;
	int		num_children;
	int		i;

	err = ptree_get_propval_by_name(loc, PICL_PROP_NAME, (void *)nodename,
	    PICL_PROPNAMELEN_MAX);
	if (err != PICL_SUCCESS)
		return (err);
	err = ptree_get_propval_by_name(loc, PICL_PROP_PARENT, &parlocnodeh,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS)
		return (err);
	if ((err = ptree_get_propval_by_name(parlocnodeh, PICL_PROP_SC_HANDLE,
	    &parsgfruhdl, sizeof (parsgfruhdl))) != PICL_SUCCESS)
		return (err);
	/* find children of the parent node */
	fruchildren = get_node_children(parsgfruhdl, &num_children);
	if (fruchildren == NULL)
		return (PICL_FAILURE);
	for (i = 0, cp = fruchildren; i < num_children; i++, cp++) {
		/* find the child we're interested in */
		if (strcmp(cp->nodename, nodename) == 0) {
			*fruhdl = cp->handle;
			free(fruchildren);
			return (PICL_SUCCESS);
		}
	}
	free(fruchildren);
	return (PICL_FAILURE);
}

/*
 * handle EC_DR picl events
 */
/*ARGSUSED*/
static void
frudr_evhandler(const char *ename, const void *earg, size_t size, void *cookie)
{
	nvlist_t		*nvlp;
	char			*dtype;
	char			*ap_id;
	char			*hint;
	char			path[MAXPATHLEN];
	picl_nodehdl_t		fruh;
	picl_nodehdl_t		locnodeh;
	fru_hdl_t		sgfruhdl;
	fru_hdl_t		sgfruhdl_from_parent;

	if (strcmp(ename, PICLEVENT_DR_AP_STATE_CHANGE) != 0)
		return;

	if (nvlist_unpack((char *)earg, size, &nvlp, 0))
		return;

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_DATA_TYPE, &dtype)) {
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(dtype, PICLEVENTARG_PICLEVENT_DATA) != 0) {
		nvlist_free(nvlp);
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_AP_ID, &ap_id)) {
		nvlist_free(nvlp);
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_HINT, &hint)) {
		nvlist_free(nvlp);
		return;
	}

	if (strncmp(ap_id, AP_ID_PREAMBLE, AP_ID_PREAMBLE_LEN) != 0) {
		nvlist_free(nvlp);
		return;
	}

	/*
	 * OK - so this is an EC_DR event - let's handle it.
	 */
	sprintf_buf2(path, CHASSIS_LOC_PATH, &ap_id[AP_ID_PREAMBLE_LEN]);

	/*
	 * special case - SSC arrival means that SSC has been reset - we
	 * need to flush the cached sgfru handles
	 */
	if (strcmp(&ap_id[AP_ID_PREAMBLE_LEN], "SSC1") == 0) {
		picl_nodehdl_t chdh;
		picl_nodehdl_t peerh;
		picl_nodehdl_t parh;
		int got_peer;
		char	label[MAX_LABEL_LEN];
		int err;
		sgfrunode_t	*sgfruchassisp = NULL;
		int num_children;
		picl_prophdl_t	schproph;

		/* find existing chassis node */
		if (ptree_get_node_by_path(CHASSIS_PATH, &parh) !=
		    PICL_SUCCESS) {
			nvlist_free(nvlp);
			return;
		}

		/* find new chassis sgfru node */
		sgfruchassisp = get_node_children(ROOTPARENT, &num_children);
		if (sgfruchassisp == NULL || num_children != 1) {
			nvlist_free(nvlp);
			return;
		}

		/* update chassis SC_HANDLE property */
		err = ptree_get_prop_by_name(parh, PICL_PROP_SC_HANDLE,
		    &schproph);
		if (err != PICL_SUCCESS) {
			nvlist_free(nvlp);
			return;
		}
		err = ptree_delete_prop(schproph);
		if (err != PICL_SUCCESS) {
			nvlist_free(nvlp);
			return;
		}
		(void) ptree_destroy_prop(schproph);
		err = add_prop_ull(parh, sgfruchassisp->handle,
		    PICL_PROP_SC_HANDLE);
		if (err != PICL_SUCCESS) {
			nvlist_free(nvlp);
			return;
		}

		/*
		 * remove all subtrees except DISK, TAPE, DVD and PCI subtrees
		 */
		if (ptree_get_propval_by_name(parh, PICL_PROP_CHILD, &chdh,
		    sizeof (picl_nodehdl_t)) == PICL_SUCCESS) {
			for (;;) {
				if (ptree_get_propval_by_name(chdh,
				    PICL_PROP_PEER, &peerh,
				    sizeof (picl_nodehdl_t)) != PICL_SUCCESS)
					got_peer = 0;
				else
					got_peer = 1;
				err = ptree_get_propval_by_name(chdh,
				    PICL_PROP_LABEL, label, sizeof (label));
				if (err == PICL_SUCCESS) {
					if (strncmp(label, "DISK",
					    strlen("DISK")) != 0 &&
					    strncmp(label, "TAPE",
					    strlen("TAPE")) != 0 &&
					    strncmp(label, "PCI",
					    strlen("PCI")) != 0 &&
					    strncmp(label, "DVD",
					    strlen("DVD")) != 0) {
						(void) remove_subtree(chdh);
					}
				}
				if (got_peer == 0)
					break;
				chdh = peerh;
			}
		}

		/* add new subtrees */
		(void) add_subtree(parh, sgfruchassisp->handle);
		free(sgfruchassisp);

		nvlist_free(nvlp);
		return;
	}

	if (ptree_get_node_by_path(path, &locnodeh) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}
	if (ptree_get_propval_by_name(locnodeh, PICL_PROP_SC_HANDLE,
	    &sgfruhdl, sizeof (sgfruhdl)) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	/*
	 * now either add or delete the fru node as appropriate. If no
	 * hint, treat as insert - add_subtree will update the tree if
	 * necessary.
	 */
	if (strcmp(hint, DR_HINT_REMOVE) == 0) {
		if (ptree_get_propval_by_name(locnodeh, PICL_PROP_CHILD,
		    &fruh, sizeof (picl_nodehdl_t)) != PICL_PROPNOTFOUND) {
			/*
			 * fru was there - but has gone away
			 */
			post_frudr_event(PICL_FRU_REMOVED, locnodeh, fruh);
		}
	} else {
		/*
		 * fru has been inserted (or may need to update)
		 *
		 * sgfruhdl may be stale due to hotplugging. We check this
		 * by getting the fru_hdl_t from the parent's children
		 * and compare it to the cached value in sgfruhdl.  If we
		 * have a stale handle, we update the cached value and
		 * use it in the call to add_subtree.
		 */
		if (get_fruhdl_from_parent(locnodeh, &sgfruhdl_from_parent) ==
		    PICL_SUCCESS) {
			if (sgfruhdl != sgfruhdl_from_parent) {
				update_fru_hdl(locnodeh, sgfruhdl_from_parent);
				sgfruhdl = sgfruhdl_from_parent;
			}
		}

		(void) add_subtree(locnodeh, sgfruhdl);
	}
	nvlist_free(nvlp);
}

/*
 * handle memcfg picl events - need to update reference properties
 */
/*ARGSUSED*/
static void
frumemcfg_evhandler(const char *ename, const void *earg, size_t size,
    void *cookie)
{
	picl_nodehdl_t	nodeh;
	picl_nodehdl_t	lochdl;
	picl_nodehdl_t	fruhdl;
	picl_nodehdl_t	memgrphdl;
	picl_nodehdl_t	memhdl;
	picl_prophdl_t	tblhdl;
	picl_prophdl_t	tblproph;
	nvlist_t	*nvlp;
	char	addr[MAXPATHLEN];
	char	bname[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t	banklochdl;
	picl_nodehdl_t	bankfruhdl;
	char	label[MAX_LABEL_LEN];
	int err;
	int id;
	char *ptr;
	int value;
	char buf[MAX_LINE_SIZE];

	if (strcmp(ename, PICLEVENT_MC_ADDED) != 0 &&
	    strcmp(ename, PICLEVENT_MC_REMOVED) != 0)
		return;

	/*
	 * find corresponding frutree dimm nodes
	 */
	if (nvlist_unpack((char *)earg, size, &nvlp, 0))
		return;
	if (nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE, &nodeh)) {
		nvlist_free(nvlp);
		return;
	}
	nvlist_free(nvlp);
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_UNIT_ADDRESS, addr,
	    sizeof (addr));
	if (err != PICL_SUCCESS)
		return;
	ptr = strchr(addr, ',');
	if (ptr == NULL)
		return;
	*ptr = '\0';
	value = strtol(addr, NULL, 16);
	sprintf_buf5(buf, PROC_FRU_PATH, SAFARI_ADDR_TO_SB(value),
	    SAFARI_ADDR_TO_SB(value), SAFARI_ADDR_TO_P(value),
	    SAFARI_ADDR_TO_P(value));
	err = ptree_get_node_by_path(buf, &fruhdl);
	if (err != PICL_SUCCESS)
		return;
	err = ptree_get_propval_by_name(fruhdl, PICL_PROP_CHILD,
	    &banklochdl, sizeof (banklochdl));
	if (err != PICL_SUCCESS)
		return;

	/*
	 * walk through the DIMM locations
	 */
	for (;;) {
		err = ptree_get_propval_by_name(banklochdl, PICL_PROP_CHILD,
		    &bankfruhdl, sizeof (bankfruhdl));
		if (err != PICL_SUCCESS)
			goto next_bank;
		err = ptree_get_propval_by_name(bankfruhdl, PICL_PROP_CHILD,
		    &lochdl, sizeof (lochdl));
		if (err != PICL_SUCCESS)
			goto next_bank;
		for (;;) {
			err = ptree_get_propval_by_name(lochdl, PICL_PROP_CHILD,
			    &fruhdl, sizeof (fruhdl));
			if (err != PICL_SUCCESS)
				goto next_dimm;

			/*
			 * this is a frutree dimm node corresponding to the
			 * memory controller that has been added/deleted
			 * - so create/delete reference properties
			 */
			if (strcmp(ename, PICLEVENT_MC_ADDED) == 0) {
				/*
				 * find bank name
				 */
				err = ptree_get_propval_by_name(fruhdl,
				    PICL_PROP_DEVICES, &tblhdl,
				    sizeof (tblhdl));
				if (err != PICL_SUCCESS)
					goto next_dimm;
				err = ptree_get_propval_by_name(lochdl,
				    PICL_PROP_LABEL, label, sizeof (label));
				if (err != PICL_SUCCESS)
					goto next_dimm;

				err = ptree_get_propval_by_name(bankfruhdl,
				    PICL_PROP_NAME, bname, sizeof (bname));
				if (err != PICL_SUCCESS)
					goto next_dimm;

				/*
				 * find memory group node
				 */
				err = ptree_get_propval_by_name(nodeh,
				    PICL_PROP_CHILD, &memgrphdl,
				    sizeof (memgrphdl));
				if (err != PICL_SUCCESS)
					goto next_dimm;

				/*
				 * check if this is the right bank - if not
				 * move on to sibling
				 */
				err = ptree_get_propval_by_name(memgrphdl,
				    PICL_PROP_ID, &id, sizeof (id));
				if (err != PICL_SUCCESS)
					goto next_dimm;
				if (bname[1] != id + '0') {
					err =
					    ptree_get_propval_by_name(memgrphdl,
					    PICL_PROP_PEER, &memgrphdl,
					    sizeof (memgrphdl));
					if (err != PICL_SUCCESS)
						goto next_dimm;
					err =
					    ptree_get_propval_by_name(memgrphdl,
					    PICL_PROP_ID, &id, sizeof (id));
					if (err != PICL_SUCCESS)
						goto next_dimm;
					if (bname[1] != id + '0')
						goto next_dimm;
				}

				/*
				 * got the right bank - now create appropriate
				 * link
				 */
				err = ptree_get_propval_by_name(memgrphdl,
				    PICL_PROP_CHILD, &memhdl,
				    sizeof (memhdl));
				if (err != PICL_SUCCESS)
					goto next_dimm;
				for (;;) {
					err = ptree_get_propval_by_name(memhdl,
					    PICL_PROP_ID, &id, sizeof (id));
					if (err != PICL_SUCCESS)
						goto next_dimm;
					if (label[1] == ('0' + id)) {
						err = add_prop_ref(memhdl,
						    fruhdl,
						    PICL_REFPROP_FRU_PARENT);
						if (err != PICL_SUCCESS)
							return;
						err = create_table_entry(tblhdl,
						    memhdl,
						    PICL_CLASS_MEMORY_MODULE);
						if (err != PICL_SUCCESS)
							return;
					}
					err = ptree_get_propval_by_name(memhdl,
					    PICL_PROP_PEER,
					    &memhdl, sizeof (memhdl));
					if (err == PICL_PROPNOTFOUND)
						break;
					if (err != PICL_SUCCESS)
						return;
				}
			} else if (strcmp(ename, PICLEVENT_MC_REMOVED) == 0) {
				/*
				 * XXX - no mechanism for deleting row - so
				 * delete whole tabel and start again
				 */
				err = ptree_get_prop_by_name(fruhdl,
				    PICL_PROP_DEVICES, &tblproph);
				if (err == PICL_SUCCESS) {
					err = ptree_delete_prop(tblproph);
					if (err != PICL_SUCCESS)
						return;
					(void) ptree_destroy_prop(tblproph);
				}
				err = create_table(fruhdl, &tblhdl,
				    PICL_PROP_DEVICES);
				if (err != PICL_SUCCESS)
					return;
			}
next_dimm:
			err = ptree_get_propval_by_name(lochdl,
			    PICL_PROP_PEER, &lochdl, sizeof (lochdl));
			if (err == PICL_PROPNOTFOUND)
				break;
			if (err != PICL_SUCCESS)
				return;
		}
next_bank:
		err = ptree_get_propval_by_name(banklochdl,
		    PICL_PROP_PEER, &banklochdl, sizeof (banklochdl));
		if (err == PICL_PROPNOTFOUND)
			break;
		if (err != PICL_SUCCESS)
			return;
	}
	/*
	 * We don't get an event to say that cpu nodes have been added/
	 * deleted (in fact as things stand they are never deleted). However
	 * we know that all cpus must be configured before the MC_ADDED event
	 * we are handling here. So if the cpu links haven't been set up yet
	 * then we do it now.
	 */
	if (strcmp(ename, PICLEVENT_MC_ADDED) == 0) {
		sprintf_buf4(buf, PROC_LOC_PATH, SAFARI_ADDR_TO_SB(value),
		    SAFARI_ADDR_TO_SB(value), SAFARI_ADDR_TO_P(value));
		err = ptree_get_node_by_path(buf, &lochdl);
		if (err != PICL_SUCCESS)
			return;
		sprintf_buf5(buf, PROC_FRU_PATH, SAFARI_ADDR_TO_SB(value),
		    SAFARI_ADDR_TO_SB(value), SAFARI_ADDR_TO_P(value),
		    SAFARI_ADDR_TO_P(value));
		err = ptree_get_node_by_path(buf, &fruhdl);
		if (err != PICL_SUCCESS)
			return;
		sprintf_buf2(buf, "P%d", SAFARI_ADDR_TO_P(value));
		err = ptree_get_propval_by_name(fruhdl,
		    PICL_PROP_DEVICES, &tblhdl, sizeof (tblhdl));
		if (err != PICL_SUCCESS)
			return;
		(void) create_cpu_references(buf, fruhdl, tblhdl);
	}
}

/*
 * subroutine for add_env_nodes(), and add_led_node(). Adds a sensor
 * node under the sc node in the platform tree, of name "nodename" and
 * class "class". Also add UnitAddress property (always 0 as the nodenames
 * are unique anyway). Add reference property back to parent fru/location node
 * in frutree and a Devices table entry pointing to this node from the
 * parent fru/location node in frutree.
 */
static int
add_sensor_node(picl_nodehdl_t fruhdl, picl_nodehdl_t lochdl, char *nodename,
    char *class, char *prop_class, picl_prophdl_t tblhdl,
    picl_nodehdl_t *sensorhdlp)
{
	int err;

	err = ptree_create_and_add_node(sch, nodename, class, sensorhdlp);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_NODE_FAIL, nodename, err);
		return (err);
	}

	err = create_table_entry(tblhdl, *sensorhdlp, class);
	if (err != PICL_SUCCESS)
		return (err);

	err = add_sensor_prop(*sensorhdlp, prop_class);
	if (err != PICL_SUCCESS)
		return (err);

	err = add_prop_charstring(*sensorhdlp, "0", PICL_PROP_UNIT_ADDRESS);
	if (err != PICL_SUCCESS)
		return (err);

	if (fruhdl != 0) {
		err = add_prop_ref(*sensorhdlp, fruhdl,
		    PICL_REFPROP_FRU_PARENT);
	} else {
		err = add_prop_ref(*sensorhdlp, lochdl,
		    PICL_REFPROP_LOC_PARENT);
	}
	return (err);
}

/*
 * subroutine for add_sensor_node()/add_env_nodes(). Used for adding dynamic
 * properties
 */
static int
add_sensor_prop(picl_nodehdl_t nodeh, char *class)
{
	ptree_propinfo_t propinfo;
	int err;

	if (strcmp(class, PICL_PROP_TEMPERATURE) == 0) {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ + PICL_VOLATILE,
		    sizeof (int), class, get_sensor_data, NULL);
	} else if (strcmp(class, PICL_PROP_FAN_SPEED) == 0) {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ + PICL_VOLATILE,
		    sizeof (int), class, get_sensor_data, NULL);
	} else if (strcmp(class, PICL_PROP_FAN_SPEED_UNIT) == 0) {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ + PICL_VOLATILE,
		    MAX_SPEED_UNIT_LEN, class, get_sensor_data, NULL);
	} else if (strcmp(class, PICL_PROP_CONDITION) == 0) {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ + PICL_VOLATILE,
		    MAX_CONDITION_LEN, class, get_sensor_data, NULL);
	} else if (strcmp(class, PICL_PROP_STATE) == 0) {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ + PICL_WRITE +
		    PICL_VOLATILE, MAX_STATE_LEN, class, get_led_data,
		    set_led_data);
	} else {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_FLOAT, PICL_READ + PICL_VOLATILE,
		    sizeof (float), class, get_sensor_data, NULL);
	}
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROPINFO_FAIL, class, err);
		return (err);
	}

	err = ptree_create_and_add_prop(nodeh, &propinfo, NULL, NULL);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, ADD_PROP_FAIL, class, err);
		return (err);
	}
	return (PICL_SUCCESS);
}

/*
 * Get requested kstat
 */
static int
open_kstat(char *name, void **ptr, kstat_ctl_t **kcp)
{
	kstat_t *info_ksp;

	*kcp = kstat_open();
	if (*kcp == NULL) {
		syslog(LOG_ERR, KSTAT_FAIL);
		return (PICL_FAILURE);
	}
	info_ksp = kstat_lookup(*kcp, NULL, -1, name);
	if (info_ksp == NULL) {
		kstat_close(*kcp);
		syslog(LOG_ERR, KSTAT_FAIL);
		return (PICL_FAILURE);
	}
	if (kstat_read(*kcp, info_ksp, NULL) == -1) {
		kstat_close(*kcp);
		syslog(LOG_ERR, KSTAT_FAIL);
		return (PICL_FAILURE);
	}
	*ptr = info_ksp;
	return (PICL_SUCCESS);
}

/*
 * dimm status - uses bank-status property on memory-controller node
 */

static int
get_dimm_status(ptree_rarg_t *arg, void *result)
{
	int err;
	int i;
	picl_prophdl_t	tblhdl;
	picl_prophdl_t  nextprop;
	picl_prophdl_t  refprop;
	picl_prophdl_t  mmgprop;
	picl_prophdl_t  mcprop;
	picl_prophdl_t  bankprop;
	char	nodename[PICL_PROPNAMELEN_MAX];
	char    class[PICL_CLASSNAMELEN_MAX];
	char	bankname[PICL_PROPNAMELEN_MAX];
	char    state[MAX_STATE_SIZE];

	/*
	 * find the name of this node
	 */
	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_NAME, nodename,
	    sizeof (nodename));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_NAME, err);
		return (err);
	}

	/*
	 * find the name of grandparent (dimm bank) node
	 */
	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_PARENT, &bankprop,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(bankprop, PICL_PROP_PARENT, &bankprop,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(bankprop, PICL_PROP_NAME, bankname,
	    sizeof (bankname));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_NAME, err);
		return (err);
	}

	/*
	 * lookup memory-module node in Devices table
	 */
	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_DEVICES, &tblhdl,
	    sizeof (tblhdl));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_DEVICES, err);
		return (err);
	}
	err = ptree_get_next_by_row(tblhdl, &nextprop);
	if (err != PICL_SUCCESS) {
		/*
		 * if Devices table empty then dimm is unconfigured
		 */
		(void) strlcpy(result, PICL_PROPVAL_DISABLED,
		    MAX_OPERATIONAL_STATUS_LEN);
		return (PICL_SUCCESS);
	}
	err = ptree_get_next_by_row(nextprop, &nextprop);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, GET_NEXT_BY_ROW_FAIL, PICL_PROP_DEVICES, err);
		return (err);
	}

	/*
	 * walk down second column (ref ptr)
	 */
	while (err == PICL_SUCCESS) {
		err = ptree_get_propval(nextprop, &refprop, sizeof (refprop));
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, GET_PROPVAL_FAIL, err);
			return (PICL_PROPVALUNAVAILABLE);
		}
		err = ptree_get_propval_by_name(refprop, PICL_PROP_CLASSNAME,
		    class, sizeof (class));
		if (err == PICL_SUCCESS && strcmp(class,
		    PICL_CLASS_MEMORY_MODULE) == 0)
			break;
		if (err != PICL_SUCCESS && err != PICL_STALEHANDLE) {
			syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_CLASSNAME,
			    err);
			return (err);
		}
		err = ptree_get_next_by_col(nextprop, &nextprop);
		if (err != PICL_SUCCESS) {
			/*
			 * if no memory-module in Devices table
			 *  then dimm is unconfigured
			 */
			(void) strlcpy(result, PICL_PROPVAL_DISABLED,
			    MAX_OPERATIONAL_STATUS_LEN);
			return (PICL_SUCCESS);
		}
	}

	/*
	 * we've finally found the associated memory-module
	 * node. Now need to find the bank-status property on
	 * its parent memory-controller.
	 */
	err = ptree_get_propval_by_name(refprop, PICL_PROP_PARENT,
	    &mmgprop, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(mmgprop, PICL_PROP_PARENT, &mcprop,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_PARENT, err);
		return (err);
	}
	err = ptree_get_propval_by_name(mcprop, PICL_PROP_BANK_STATUS, &tblhdl,
	    sizeof (tblhdl));
	if (err != PICL_SUCCESS) {
		(void) strlcpy(result, PICL_PROPVAL_UNKNOWN,
		    MAX_OPERATIONAL_STATUS_LEN);
		return (PICL_SUCCESS);
	}

	/*
	 * bank-status is a table. Need to find the entry corresponding
	 * to this node
	 */
	err = ptree_get_next_by_row(tblhdl, &nextprop);
	if (err != PICL_SUCCESS) {
		(void) strlcpy(result, PICL_PROPVAL_UNKNOWN,
		    MAX_OPERATIONAL_STATUS_LEN);
		return (PICL_SUCCESS);
	}
	for (i = 0; i < 4; i++) {
		err = ptree_get_propval(nextprop, &state, sizeof (state));
		if (err != PICL_SUCCESS) {
			(void) strlcpy(result, PICL_PROPVAL_UNKNOWN,
			    MAX_OPERATIONAL_STATUS_LEN);
			return (err);
		}
		if ((i & 1) == (bankname[1] - '0')) {
			if (strcmp(state, "pass") == 0) {
				(void) strlcpy(result, PICL_PROPVAL_OKAY,
				    MAX_OPERATIONAL_STATUS_LEN);
			} else if (strcmp(state, "fail") == 0) {
				(void) strlcpy(result, PICL_PROPVAL_FAILED,
				    MAX_OPERATIONAL_STATUS_LEN);
			} else {
				(void) strlcpy(result, state,
				    MAX_OPERATIONAL_STATUS_LEN);
			}
			break;
		}
		err = ptree_get_next_by_col(nextprop, &nextprop);
		if (err != PICL_SUCCESS) {
			(void) strlcpy(result, PICL_PROPVAL_OKAY,
			    MAX_OPERATIONAL_STATUS_LEN);
			break;
		}
	}
	return (PICL_SUCCESS);
}

/*
 * cpu status - uses State property on cpu node
 */

static int
get_cpu_status(ptree_rarg_t *arg, void *result)
{
	int err;
	picl_prophdl_t	tblhdl;
	picl_prophdl_t  nextprop;
	picl_prophdl_t  refprop;
	char    class[PICL_CLASSNAMELEN_MAX];
	char    state[MAX_STATE_SIZE];

	/*
	 * lookup cpu node in Devices table
	 */
	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_DEVICES, &tblhdl,
	    sizeof (tblhdl));
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_DEVICES, err);
		return (err);
	}
	err = ptree_get_next_by_row(tblhdl, &nextprop);
	if (err != PICL_SUCCESS) {
		/*
		 * if Devices table empty then cpu is unconfigured
		 */
		(void) strlcpy(result, PICL_PROPVAL_DISABLED,
		    MAX_OPERATIONAL_STATUS_LEN);
		return (PICL_SUCCESS);
	}
	err = ptree_get_next_by_row(nextprop, &nextprop);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, GET_NEXT_BY_ROW_FAIL, PICL_PROP_DEVICES, err);
		return (err);
	}

	/*
	 * walk down second column (ref ptr)
	 */
	while (err == PICL_SUCCESS) {
		err = ptree_get_propval(nextprop, &refprop, sizeof (refprop));
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, GET_PROPVAL_FAIL, err);
			return (err);
		}
		err = ptree_get_propval_by_name(refprop, PICL_PROP_CLASSNAME,
		    class, sizeof (class));
		if (err == PICL_SUCCESS && strcmp(class, PICL_CLASS_CPU) == 0)
			break;
		if (err != PICL_SUCCESS && err != PICL_STALEHANDLE) {
			syslog(LOG_ERR, PROP_LOOKUP_FAIL, PICL_PROP_CLASSNAME,
			    err);
			return (err);
		}
		err = ptree_get_next_by_col(nextprop, &nextprop);
		if (err != PICL_SUCCESS) {
			/*
			 * if no cpu in Devices table
			 *  then cpu is unconfigured
			 */
			(void) strlcpy(result, PICL_PROPVAL_DISABLED,
			    MAX_OPERATIONAL_STATUS_LEN);
			return (PICL_SUCCESS);
		}
	}

	/*
	 * we've finally found the associated cpu node. Now need to find its
	 * status property if present (if not assume OK)
	 */
	err = ptree_get_propval_by_name(refprop, OBP_STATUS,
	    state, sizeof (state));
	if (err == PICL_SUCCESS) {
		if (strcmp(state, "fail") == 0)
			(void) strlcpy(result, PICL_PROPVAL_FAILED,
			    MAX_OPERATIONAL_STATUS_LEN);
		else
			(void) strlcpy(result, state,
			    MAX_OPERATIONAL_STATUS_LEN);
		return (PICL_SUCCESS);
	}

	(void) strlcpy(result, PICL_PROPVAL_OKAY, MAX_OPERATIONAL_STATUS_LEN);
	return (PICL_SUCCESS);
}

/*
 * system/io board condition - uses sgenv driver kstats
 */

static int
get_board_status(ptree_rarg_t *arg, void *result)
{
	int err = PICL_SUCCESS;
	int i;
	sg_board_info_t	*brd;
	char name[PICL_PROPNAMELEN_MAX];
	char buf[PICL_PROPNAMELEN_MAX];
	kstat_ctl_t *kc;
	kstat_t *board_info_ksp;

	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_NAME, name,
	    sizeof (name));
	if (err != PICL_SUCCESS) {
		return (err);
	}

	err = open_kstat(SG_BOARD_STATUS_KSTAT_NAME, (void **)&board_info_ksp,
	    &kc);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	brd = board_info_ksp->ks_data;
	for (i = 0; i < SGENV_NUM_BOARD_READINGS(board_info_ksp); i++, brd++) {
		/*
		 * check this kstat matches the name of the node
		 */
		if (SG_BOARD_IS_CPU_TYPE(brd->board_num)) {
			sprintf_buf3(buf, "%s%d",
			    SG_HPU_TYPE_CPU_BOARD_ID, brd->board_num);
		} else {
			sprintf_buf3(buf, "%s%d",
			    SG_HPU_TYPE_PCI_IO_BOARD_ID, brd->board_num);
		}
		if (strncmp(buf, name, strlen(buf)) != 0)
			continue;

		/*
		 * ok - got the right kstat - get it's value
		 * note that values 0-4 are defined in sbdp_mbox.h
		 */
		if (brd->condition >= 0 && brd->condition < 5)
			(void) strlcpy(result,
			    hpu_condition_table[brd->condition],
			    MAX_OPERATIONAL_STATUS_LEN);
		kstat_close(kc);
		return (PICL_SUCCESS);
	}
	kstat_close(kc);
	return (PICL_PROPVALUNAVAILABLE);
}

static int
get_op_status(ptree_rarg_t *arg, void *result)
{
	int err = PICL_SUCCESS;
	char name[PICL_PROPNAMELEN_MAX];
	char value[MAX_STATE_LEN];
	char	parent_name[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t loch;
	picl_nodehdl_t parentfruh;

	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_NAME, name,
	    sizeof (name));
	if (err != PICL_SUCCESS) {
		return (err);
	}

	/*
	 * handle dimms, cpus and system boards specially
	 */
	if (IS_PROC_NODE(name)) {
		return (get_cpu_status(arg, result));
	} else if (IS_DIMM_NODE(name)) {
		return (get_dimm_status(arg, result));
	} else if (IS_SB_NODE(name) || IS_IB_NODE(name)) {
		return (get_board_status(arg, result));
	}

	/*
	 * otherwise OperationalStatus is derived from the fault led state
	 */

	/*
	 * scapp knows FANs 0 and 1 on IB as FAN8 and FAN9
	 */
	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_PARENT, &loch,
	    sizeof (loch));
	if (err != PICL_SUCCESS)
		return (PICL_PROPVALUNAVAILABLE);
	err = ptree_get_propval_by_name(loch, PICL_PROP_PARENT, &parentfruh,
	    sizeof (parentfruh));
	if (err != PICL_SUCCESS)
		return (PICL_PROPVALUNAVAILABLE);
	err = ptree_get_propval_by_name(parentfruh, PICL_PROP_NAME, parent_name,
	    sizeof (parent_name));
	if (err != PICL_SUCCESS)
		return (PICL_PROPVALUNAVAILABLE);
	if (strcmp(name, "FAN0") == 0 && strcmp(parent_name, "IB6") == 0) {
		if (get_led("FAN8", FAULT_LED, value) != PICL_SUCCESS) {
			return (PICL_PROPVALUNAVAILABLE);
		}
	} else if (strcmp(name, "FAN1") == 0 && strcmp(parent_name,
	    "IB6") == 0) {
		if (get_led("FAN9", FAULT_LED, value) != PICL_SUCCESS) {
			return (PICL_PROPVALUNAVAILABLE);
		}
	} else {
		if (get_led(name, FAULT_LED, value) != PICL_SUCCESS) {
			return (PICL_PROPVALUNAVAILABLE);
		}
	}
	if (strcmp(value, PICL_PROPVAL_ON) == 0)
		(void) strlcpy(result, PICL_PROPVAL_FAILED,
		    MAX_OPERATIONAL_STATUS_LEN);
	else
		(void) strlcpy(result, PICL_PROPVAL_OKAY,
		    MAX_OPERATIONAL_STATUS_LEN);
	return (PICL_SUCCESS);
}

static int
add_board_status(picl_nodehdl_t nodeh, char *nodename)
{
	ptree_propinfo_t propinfo;
	int err;
	picl_prophdl_t prophdl;

	/*
	 * check if OperationalStatus property already created for this fru
	 */
	err = ptree_get_prop_by_name(nodeh, PICL_PROP_OPERATIONAL_STATUS,
	    &prophdl);
	if (err == PICL_SUCCESS)
		return (PICL_SUCCESS);

	/*
	 * put operational status on dimms, cpus, SBs, IBs, PSUs, FTs, Fans, RPs
	 */
	if (IS_DIMM_NODE(nodename) || IS_PROC_NODE(nodename) ||
	    IS_SB_NODE(nodename) || IS_IB_NODE(nodename) ||
	    IS_PSU_NODE(nodename) || IS_FT_NODE(nodename) ||
	    IS_FAN_NODE(nodename) || IS_RP_NODE(nodename)) {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ + PICL_VOLATILE,
		    MAX_OPERATIONAL_STATUS_LEN, PICL_PROP_OPERATIONAL_STATUS,
		    get_op_status, NULL);
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, PROPINFO_FAIL,
			    PICL_PROP_OPERATIONAL_STATUS, err);
			return (err);
		}
		err = ptree_create_and_add_prop(nodeh, &propinfo, NULL, NULL);
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, ADD_PROP_FAIL,
			    PICL_PROP_OPERATIONAL_STATUS, err);
			return (err);
		}
	}
	return (PICL_SUCCESS);
}

/*
 * environmental information handling - uses sgenv driver kstats
 */

static int
add_env_nodes(picl_nodehdl_t nodeh, char *nodename, picl_prophdl_t tblhdl)
{
	int err = PICL_SUCCESS;
	env_sensor_t	*env;
	int	i;
	picl_prophdl_t	tblhdl2;
	picl_prophdl_t	frutype;
	char fruname[PICL_PROPNAMELEN_MAX];
	char buf[PICL_PROPNAMELEN_MAX];
	char id[PICL_PROPNAMELEN_MAX];
	float scale;
	picl_nodehdl_t childh;
	picl_nodehdl_t sensorhdl;
	kstat_ctl_t *kc;
	kstat_t *env_info_ksp;

	err = open_kstat(SG_ENV_INFO_KSTAT_NAME, (void **)&env_info_ksp, &kc);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	env = env_info_ksp->ks_data;
	for (i = 0; i < SGENV_NUM_ENV_READINGS(env_info_ksp); i++, env++) {
		/*
		 * check values from kstat entry are within valid range
		 */
		if (env->sd_id.id.sensor_type < SG_SENSOR_TYPE_CURRENT)
			continue;
		if (env->sd_id.id.sensor_type == SG_SENSOR_TYPE_ENVDB)
			continue;
		if (env->sd_id.id.sensor_type > SG_SENSOR_TYPE_2_5_VDC)
			continue;
		if ((env->sd_id.id.hpu_type >> 8) >=
		    (SG_HPU_TYPE_SUN_FIRE_3800_CENTERPLANE >> 8))
			continue;
		if (env->sd_id.id.sensor_part > SG_SENSOR_PART_INPUT)
			continue;

		/*
		 * does this kstat entry belong to this fru?
		 * Note sc reports RPS as 10 and 12 via env messages
		 * but by 0 and 2 via fru messages, so correct here
		 */
		if ((env->sd_id.id.hpu_type >> 8) ==
		    (SG_HPU_TYPE_REPEATER_BOARD >> 8)) {
			sprintf_buf3(fruname, "%s%d",
			    hpu_type_table[env->sd_id.id.hpu_type >> 8],
			    env->sd_id.id.hpu_slot - 10);
		} else {
			sprintf_buf3(fruname, "%s%d",
			    hpu_type_table[env->sd_id.id.hpu_type >> 8],
			    env->sd_id.id.hpu_slot);
		}
		if (strcmp(nodename, fruname) != 0)
			continue;

		/*
		 * set up FRUType. Note we only want to do this once per fru
		 */
		err = ptree_get_prop_by_name(nodeh, PICL_PROP_FRU_TYPE,
		    &frutype);
		if (err != PICL_SUCCESS) {
			err = add_prop_charstring(nodeh,
			    hpu_fru_type_table[env->sd_id.id.hpu_type >> 8],
			    PICL_PROP_FRU_TYPE);
			if (err != PICL_SUCCESS)
				goto done;
		}

		/*
		 * create the sensor node with a sensible name
		 */
		switch (env->sd_id.id.sensor_type) {
		case SG_SENSOR_TYPE_TEMPERATURE:
			if (env->sd_id.id.sensor_part == SG_SENSOR_PART_BOARD) {
				sprintf_buf2(id, "t_ambient%d",
				    env->sd_id.id.sensor_typenum);
			} else {
				sprintf_buf3(id, "t_%s%d",
				    hpu_part_table[env->sd_id.id.sensor_part],
				    env->sd_id.id.sensor_partnum);
			}
			break;
		case SG_SENSOR_TYPE_CURRENT:
			sprintf_buf3(id, "i_%s%d",
			    hpu_part_table[env->sd_id.id.sensor_part],
			    env->sd_id.id.sensor_partnum);
			break;
		case SG_SENSOR_TYPE_COOLING:
			sprintf_buf3(id, "ft_%s%d",
			    hpu_part_table[env->sd_id.id.sensor_part],
			    env->sd_id.id.sensor_partnum);
			break;
		default: /* voltage */
			if (env->sd_id.id.sensor_part == SG_SENSOR_PART_BOARD) {
				sprintf_buf3(id, "v_%s%d",
				    hpu_sensor_table[env->sd_id.id.sensor_type],
				    env->sd_id.id.sensor_typenum);
			} else {
				sprintf_buf3(id, "v_%s%d",
				    hpu_part_table[env->sd_id.id.sensor_part],
				    env->sd_id.id.sensor_partnum);
			}
			break;
		}

		/*
		 * check if sensor node has already been created
		 */
		sprintf_buf3(buf, "%s_%s", nodename, id);
		if (find_child_by_name(sch, buf) != 0)
			continue;

		if (env->sd_id.id.sensor_type == SG_SENSOR_TYPE_COOLING) {
			/*
			 * create individual fan_unit nodes
			 */
			childh = nodeh;
			sprintf_buf2(fruname, "FAN%d",
			    env->sd_id.id.sensor_partnum);
			err = add_intermediate_nodes(&childh, fruname,
			    &tblhdl2, "fan-unit", "FAN");
			if (err != PICL_SUCCESS)
				goto done;
			err = add_board_status(childh, fruname);
			if (err != PICL_SUCCESS)
				goto done;
		} else if (env->sd_id.id.sensor_part ==
		    SG_SENSOR_PART_CHEETAH ||
		    ((env->sd_id.id.hpu_type >> 8) ==
		    (SG_HPU_TYPE_CPU_BOARD >> 8) &&
		    (env->sd_id.id.sensor_type == SG_SENSOR_TYPE_TEMPERATURE) &&
		    (env->sd_id.id.sensor_part == SG_SENSOR_PART_BOARD))) {
			/*
			 * put sensors under individual processor nodes
			 */
			childh = nodeh;
			if (env->sd_id.id.sensor_part == SG_SENSOR_PART_BOARD)
				sprintf_buf2(fruname, "P%d",
				    env->sd_id.id.sensor_typenum);
			else
				sprintf_buf2(fruname, "P%d",
				    env->sd_id.id.sensor_partnum);
			err = add_intermediate_nodes(&childh, fruname,
			    &tblhdl2, "cpu", "PROC");
			if (err != PICL_SUCCESS)
				goto done;
		} else {
			childh = nodeh;
			tblhdl2 = tblhdl;
		}
		err = add_sensor_node(childh, 0, buf,
		    hpu_sensor_class_table[env->sd_id.id.sensor_type],
		    hpu_sensor_prop_table[env->sd_id.id.sensor_type],
		    tblhdl2, &sensorhdl);
		if (err != PICL_SUCCESS)
			goto done;

		/*
		 * add additional properties
		 */
		switch (env->sd_id.id.sensor_type) {
		case SG_SENSOR_TYPE_COOLING:
			err = add_prop_charstring(sensorhdl, id,
			    PICL_PROP_LABEL);
			if (err != PICL_SUCCESS)
				goto done;
			/*
			 * add threshold at 75% of full speed
			 */
			err = add_prop_int(sensorhdl, 75,
			    PICL_PROP_LOW_WARNING_THRESHOLD);
			if (err != PICL_SUCCESS)
				goto done;
			err = add_sensor_prop(sensorhdl,
			    PICL_PROP_FAN_SPEED_UNIT);
			if (err != PICL_SUCCESS)
				goto done;
			continue;
		case SG_SENSOR_TYPE_TEMPERATURE:
			if ((env->sd_id.id.hpu_type >> 8 ==
			    (SG_HPU_TYPE_CPU_BOARD >> 8)) &&
			    (env->sd_id.id.sensor_part ==
			    SG_SENSOR_PART_BOARD)) {
				err = add_prop_charstring(sensorhdl,
				    PICL_PROPVAL_AMBIENT, PICL_PROP_LABEL);
				if (err != PICL_SUCCESS)
					goto done;
			} else if (env->sd_id.id.sensor_part ==
			    SG_SENSOR_PART_CHEETAH) {
				err = add_prop_charstring(sensorhdl,
				    PICL_PROPVAL_DIE, PICL_PROP_LABEL);
				if (err != PICL_SUCCESS)
					goto done;
			} else {
				err = add_prop_charstring(sensorhdl, id,
				    PICL_PROP_LABEL);
				if (err != PICL_SUCCESS)
					goto done;
			}
			err = add_prop_int(sensorhdl, env->sd_lo_warn /
			    SG_TEMPERATURE_SCALE, PICL_PROP_LOW_WARNING);
			if (err != PICL_SUCCESS)
				goto done;
			err = add_prop_int(sensorhdl, env->sd_lo /
			    SG_TEMPERATURE_SCALE, PICL_PROP_LOW_SHUTDOWN);
			if (err != PICL_SUCCESS)
				goto done;
			err = add_prop_int(sensorhdl, env->sd_hi_warn /
			    SG_TEMPERATURE_SCALE, PICL_PROP_HIGH_WARNING);
			if (err != PICL_SUCCESS)
				goto done;
			err = add_prop_int(sensorhdl, env->sd_hi /
			    SG_TEMPERATURE_SCALE, PICL_PROP_HIGH_SHUTDOWN);
			if (err != PICL_SUCCESS)
				goto done;
			continue;
		case SG_SENSOR_TYPE_1_5_VDC:
			scale = SG_1_5_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_1_8_VDC:
			scale = SG_1_8_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_2_5_VDC:
			scale = SG_2_5_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_3_3_VDC:
			scale = SG_3_3_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_5_VDC:
			scale = SG_5_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_12_VDC:
			scale = SG_12_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_48_VDC:
			/*
			 * The 48VDC sensor is just an indicator - doesn't
			 * give reading or thresholds
			 */
			err = add_prop_charstring(sensorhdl, id,
			    PICL_PROP_LABEL);
			if (err != PICL_SUCCESS)
				goto done;
			continue;
		case SG_SENSOR_TYPE_CURRENT:
			scale = SG_CURRENT_SCALE;
			break;
		}
		err = add_prop_charstring(sensorhdl, id, PICL_PROP_LABEL);
		if (err != PICL_SUCCESS)
			goto done;
		err = add_prop_float(sensorhdl, (float)env->sd_lo_warn / scale,
		    PICL_PROP_LOW_WARNING);
		if (err != PICL_SUCCESS)
			goto done;
		err = add_prop_float(sensorhdl, (float)env->sd_lo / scale,
		    PICL_PROP_LOW_SHUTDOWN);
		if (err != PICL_SUCCESS)
			goto done;
		err = add_prop_float(sensorhdl, (float)env->sd_hi_warn / scale,
		    PICL_PROP_HIGH_WARNING);
		if (err != PICL_SUCCESS)
			goto done;
		err = add_prop_float(sensorhdl, (float)env->sd_hi / scale,
		    PICL_PROP_HIGH_SHUTDOWN);
		if (err != PICL_SUCCESS)
			goto done;
	}
done:
	kstat_close(kc);
	return (err);
}

static int
get_sensor_data(ptree_rarg_t *arg, void *result)
{
	int err;				/* return code */
	kstat_ctl_t		*kc;
	char	name[PICL_PROPNAMELEN_MAX];
	ptree_propinfo_t propinfo;
	int	i;
	env_sensor_t	*env;
	char buf[PICL_PROPNAMELEN_MAX];
	char buf1[PICL_PROPNAMELEN_MAX];
	kstat_t *env_info_ksp;

	err = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_NAME, name,
	    sizeof (name));
	if (err != PICL_SUCCESS)
		return (err);
	err = ptree_get_propinfo(arg->proph, &propinfo);
	if (err != PICL_SUCCESS)
		return (err);

	err = open_kstat(SG_ENV_INFO_KSTAT_NAME, (void **)&env_info_ksp, &kc);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	env = env_info_ksp->ks_data;
	for (i = 0; i < SGENV_NUM_ENV_READINGS(env_info_ksp); i++, env++) {
		/*
		 * check kstat values are within range
		 */
		if (SG_INFO_VALUESTATUS(env->sd_infostamp) != SG_INFO_VALUE_OK)
			continue;
		if (env->sd_id.id.sensor_type < SG_SENSOR_TYPE_CURRENT)
			continue;
		if (env->sd_id.id.sensor_type == SG_SENSOR_TYPE_ENVDB)
			continue;
		if (env->sd_id.id.sensor_type > SG_SENSOR_TYPE_2_5_VDC)
			continue;
		if ((env->sd_id.id.hpu_type >> 8) >=
		    (SG_HPU_TYPE_SUN_FIRE_3800_CENTERPLANE >> 8))
			continue;
		if (env->sd_id.id.sensor_part > SG_SENSOR_PART_INPUT)
			continue;

		/*
		 * check this kstat matches the name of the node
		 * note sc reports RPS as 10 and 12 via env messages
		 * but by 0 and 2 via fru messages, so correct here
		 */
		if ((env->sd_id.id.hpu_type >> 8) ==
		    (SG_HPU_TYPE_REPEATER_BOARD >> 8))
			sprintf_buf3(buf, "%s%d",
			    hpu_type_table[env->sd_id.id.hpu_type >> 8],
			    env->sd_id.id.hpu_slot - 10);
		else
			sprintf_buf3(buf, "%s%d",
			    hpu_type_table[env->sd_id.id.hpu_type >> 8],
			    env->sd_id.id.hpu_slot);
		switch (env->sd_id.id.sensor_type) {
		case SG_SENSOR_TYPE_TEMPERATURE:
			if (env->sd_id.id.sensor_part == SG_SENSOR_PART_BOARD) {
				sprintf_buf3(buf1, "%s_t_ambient%d",
				    buf, env->sd_id.id.sensor_typenum);
			} else {
				sprintf_buf4(buf1, "%s_t_%s%d", buf,
				    hpu_part_table[env->sd_id.id.sensor_part],
				    env->sd_id.id.sensor_partnum);
			}
			break;
		case SG_SENSOR_TYPE_CURRENT:
			sprintf_buf4(buf1, "%s_i_%s%d", buf,
			    hpu_part_table[env->sd_id.id.sensor_part],
			    env->sd_id.id.sensor_partnum);
			break;
		case SG_SENSOR_TYPE_COOLING:
			sprintf_buf4(buf1, "%s_ft_%s%d", buf,
			    hpu_part_table[env->sd_id.id.sensor_part],
			    env->sd_id.id.sensor_partnum);
			break;
		default: /* voltage */
			if (env->sd_id.id.sensor_part == SG_SENSOR_PART_BOARD) {
				sprintf_buf4(buf1, "%s_v_%s%d", buf,
				    hpu_sensor_table[env->sd_id.id.sensor_type],
				    env->sd_id.id.sensor_typenum);
			} else {
				sprintf_buf4(buf1, "%s_v_%s%d", buf,
				    hpu_part_table[env->sd_id.id.sensor_part],
				    env->sd_id.id.sensor_partnum);
			}
			break;
		}
		if (strcmp(buf1, name) != 0)
			continue;

		/*
		 * ok - this is the kstat we want - update
		 * Condition, or sensor reading as requested
		 */
		if (strcmp(propinfo.piclinfo.name, PICL_PROP_CONDITION) == 0) {
			switch (SG_GET_SENSOR_STATUS(env->sd_status)) {
			case SG_SENSOR_STATUS_OK:
				(void) strlcpy(result, PICL_PROPVAL_OKAY,
				    MAX_CONDITION_LEN);
				break;
			case SG_SENSOR_STATUS_LO_WARN:
			case SG_SENSOR_STATUS_HI_WARN:
				(void) strlcpy(result, PICL_PROPVAL_WARNING,
				    MAX_CONDITION_LEN);
				break;
			case SG_SENSOR_STATUS_LO_DANGER:
			case SG_SENSOR_STATUS_HI_DANGER:
				(void) strlcpy(result, PICL_PROPVAL_FAILED,
				    MAX_CONDITION_LEN);
				break;
			default:
				kstat_close(kc);
				return (PICL_PROPVALUNAVAILABLE);
			}
			kstat_close(kc);
			return (PICL_SUCCESS);
		}
		switch (env->sd_id.id.sensor_type) {
		case SG_SENSOR_TYPE_TEMPERATURE:
			*(int *)result = env->sd_value / SG_TEMPERATURE_SCALE;
			break;
		case SG_SENSOR_TYPE_1_5_VDC:
			*(float *)result =
			    (float)env->sd_value / (float)SG_1_5_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_1_8_VDC:
			*(float *)result =
			    (float)env->sd_value / (float)SG_1_8_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_2_5_VDC:
			*(float *)result =
			    (float)env->sd_value / (float)SG_2_5_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_3_3_VDC:
			*(float *)result =
			    (float)env->sd_value / (float)SG_3_3_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_5_VDC:
			*(float *)result =
			    (float)env->sd_value / (float)SG_5_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_12_VDC:
			*(float *)result =
			    (float)env->sd_value / (float)SG_12_VDC_SCALE;
			break;
		case SG_SENSOR_TYPE_CURRENT:
			*(float *)result =
			    (float)env->sd_value / (float)SG_CURRENT_SCALE;
			break;
		case SG_SENSOR_TYPE_COOLING:
			if (strcmp(propinfo.piclinfo.name,
			    PICL_PROP_FAN_SPEED_UNIT) == 0) {
				if (SG_GET_SENSOR_STATUS(env->sd_status) ==
				    SG_SENSOR_STATUS_FAN_LOW) {
					(void) strlcpy(result,
					    PICL_PROPVAL_SELF_REGULATING,
					    MAX_SPEED_UNIT_LEN);
				} else {
					(void) strlcpy(result,
					    PICL_PROPVAL_PER_CENT,
					    MAX_SPEED_UNIT_LEN);
				}
			} else {
				switch (SG_GET_SENSOR_STATUS(env->sd_status)) {
				case SG_SENSOR_STATUS_FAN_HIGH:
					*(int *)result = 100;
					break;
				case SG_SENSOR_STATUS_FAN_FAIL:
				case SG_SENSOR_STATUS_FAN_OFF:
					*(int *)result = 0;
					break;
				default:
				case SG_SENSOR_STATUS_FAN_LOW:
					kstat_close(kc);
					return (PICL_PROPVALUNAVAILABLE);
				}
			}
			break;
		default:
			kstat_close(kc);
			return (PICL_PROPVALUNAVAILABLE);
		}
		kstat_close(kc);
		return (PICL_SUCCESS);
	}
	kstat_close(kc);
	return (PICL_PROPVALUNAVAILABLE);
}

/*
 * led information handling - uses lw8 driver
 */

static int
add_led_nodes(picl_nodehdl_t nodeh, char *name, int position,
    picl_prophdl_t tblhdl)
{
	int err;
	int  ledfd;
	lom_get_led_t lom_get_led;
	picl_nodehdl_t sensorhdl;
	char buf[PICL_PROPNAMELEN_MAX];

	/*
	 * Open the lw8 pseudo dev to get the led information
	 */
	if ((ledfd = open(LED_PSEUDO_DEV, O_RDWR, 0)) == -1) {
		syslog(LOG_ERR, DEV_OPEN_FAIL, LED_PSEUDO_DEV, strerror(errno));
		return (PICL_SUCCESS);
	}
	bzero(&lom_get_led, sizeof (lom_get_led));
	(void) strlcpy(lom_get_led.location, name,
	    sizeof (lom_get_led.location));
	if (ioctl(ledfd, LOMIOCGETLED, &lom_get_led) == -1) {
		(void) close(ledfd);
		syslog(LOG_ERR, LED_IOCTL_FAIL, strerror(errno));
		return (PICL_FAILURE);
	}
	while (lom_get_led.next_id[0] != '\0') {
		(void) strlcpy(lom_get_led.id, lom_get_led.next_id,
		    sizeof (lom_get_led.id));
		lom_get_led.next_id[0] = '\0';
		lom_get_led.position = LOM_LED_POSITION_FRU;
		if (ioctl(ledfd, LOMIOCGETLED, &lom_get_led) == -1) {
			(void) close(ledfd);
			syslog(LOG_ERR, LED_IOCTL_FAIL, strerror(errno));
			return (PICL_FAILURE);
		}
		sprintf_buf3(buf, "%s_%s", name, lom_get_led.id);
		if (position != lom_get_led.position)
			continue;
		if (position == LOM_LED_POSITION_LOCATION) {
			err = add_sensor_node(0, nodeh, buf, PICL_CLASS_LED,
			    PICL_PROP_STATE, tblhdl, &sensorhdl);
		} else {
			err = add_sensor_node(nodeh, 0, buf, PICL_CLASS_LED,
			    PICL_PROP_STATE, tblhdl, &sensorhdl);
		}
		if (err != PICL_SUCCESS) {
			(void) close(ledfd);
			return (err);
		}
		if (strcmp(name, "chassis") == 0 && strcmp(lom_get_led.id,
		    "locator") == 0) {
			err = add_prop_charstring(sensorhdl, PICL_PROPVAL_TRUE,
			    PICL_PROP_IS_LOCATOR);
			if (err != PICL_SUCCESS) {
				(void) close(ledfd);
				return (err);
			}
			err = add_prop_charstring(sensorhdl,
			    PICL_PROPVAL_SYSTEM, PICL_PROP_LOCATOR_NAME);
			if (err != PICL_SUCCESS) {
				(void) close(ledfd);
				return (err);
			}
		}
		err = add_prop_charstring(sensorhdl, lom_get_led.id,
		    PICL_PROP_LABEL);
		if (err != PICL_SUCCESS) {
			(void) close(ledfd);
			return (err);
		}
		err = add_prop_charstring(sensorhdl, lom_get_led.color,
		    PICL_PROP_COLOR);
		if (err != PICL_SUCCESS) {
			(void) close(ledfd);
			return (err);
		}
	}
	(void) close(ledfd);
	return (PICL_SUCCESS);
}

static int
get_led(char *name, char *ptr, char *result)
{
	int ledfd;
	lom_get_led_t lom_get_led;

	/*
	 * Open the lw8 pseudo dev to get the led information
	 */
	if ((ledfd = open(LED_PSEUDO_DEV, O_RDWR, 0)) == -1) {
		syslog(LOG_ERR, DEV_OPEN_FAIL, LED_PSEUDO_DEV, strerror(errno));
		return (PICL_FAILURE);
	}
	bzero(&lom_get_led, sizeof (lom_get_led));
	(void) strlcpy(lom_get_led.location, name,
	    sizeof (lom_get_led.location));
	(void) strlcpy(lom_get_led.id, ptr, sizeof (lom_get_led.id));
	if (ioctl(ledfd, LOMIOCGETLED, &lom_get_led) == -1) {
		(void) close(ledfd);
		syslog(LOG_ERR, LED_IOCTL_FAIL, strerror(errno));
		return (PICL_PROPVALUNAVAILABLE);
	}
	if (lom_get_led.status == LOM_LED_STATUS_ON)
		(void) strlcpy(result, PICL_PROPVAL_ON, MAX_STATE_LEN);
	else if (lom_get_led.status == LOM_LED_STATUS_FLASHING)
		(void) strlcpy(result, PICL_PROPVAL_FLASHING, MAX_STATE_LEN);
	else if (lom_get_led.status == LOM_LED_STATUS_BLINKING)
		(void) strlcpy(result, PICL_PROPVAL_BLINKING, MAX_STATE_LEN);
	else
		(void) strlcpy(result, PICL_PROPVAL_OFF, MAX_STATE_LEN);
	(void) close(ledfd);
	return (PICL_SUCCESS);
}

static int
get_led_data(ptree_rarg_t *arg, void *result)
{
	int rc;				/* return code */
	char	name[PICL_PROPNAMELEN_MAX];
	char *ptr;

	rc = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_NAME, name,
	    sizeof (name));
	if (rc != PICL_SUCCESS)
		return (rc);

	ptr = strchr(name, '_');
	*ptr++ = '\0'; /* now name is fru name, ptr is led name */
	return (get_led(name, ptr, (char *)result));
}

static int
set_led(char *name, char *ptr, char *value)
{
	int ledfd;
	lom_set_led_t lom_set_led;

	/*
	 * Open the lw8 pseudo dev to set the led information
	 */
	if ((ledfd = open(LED_PSEUDO_DEV, O_RDWR, 0)) == -1) {
		syslog(LOG_ERR, DEV_OPEN_FAIL, LED_PSEUDO_DEV, strerror(errno));
		return (PICL_FAILURE);
	}
	bzero(&lom_set_led, sizeof (lom_set_led));
	(void) strlcpy(lom_set_led.location, name,
	    sizeof (lom_set_led.location));
	(void) strlcpy(lom_set_led.id, ptr, sizeof (lom_set_led.id));
	if (strcmp(value, PICL_PROPVAL_ON) == 0) {
		lom_set_led.status = LOM_LED_STATUS_ON;
	} else if (strcmp(value, PICL_PROPVAL_FLASHING) == 0) {
		lom_set_led.status = LOM_LED_STATUS_FLASHING;
	} else if (strcmp(value, PICL_PROPVAL_BLINKING) == 0) {
		lom_set_led.status = LOM_LED_STATUS_BLINKING;
	} else {
		lom_set_led.status = LOM_LED_STATUS_OFF;
	}
	if (ioctl(ledfd, LOMIOCSETLED, &lom_set_led) == -1) {
		(void) close(ledfd);
		syslog(LOG_ERR, LED_IOCTL_FAIL, strerror(errno));
		return (PICL_PROPVALUNAVAILABLE);
	}
	(void) close(ledfd);
	return (PICL_SUCCESS);
}

static int
set_led_data(ptree_warg_t *arg, const void *value)
{
	int rc;				/* return code */
	char	name[PICL_PROPNAMELEN_MAX];
	char *ptr;

	rc = ptree_get_propval_by_name(arg->nodeh, PICL_PROP_NAME, name,
	    sizeof (name));
	if (rc != PICL_SUCCESS)
		return (rc);

	ptr = strchr(name, '_');
	*ptr++ = '\0'; /* now name is fru name, ptr is led name */
	return (set_led(name, ptr, (char *)value));
}

static void
disk_leds_init(void)
{
	int err = 0, i;

	if (!g_mutex_init) {
		if ((pthread_cond_init(&g_cv, NULL) == 0) &&
		    (pthread_cond_init(&g_cv_ack, NULL) == 0) &&
		    (pthread_mutex_init(&g_mutex, NULL) == 0)) {
			g_mutex_init = B_TRUE;
		} else {
			return;
		}
	}

	if (ledsthr_created) {
		/*
		 * this is a restart, wake up sleeping threads
		 */
		err = pthread_mutex_lock(&g_mutex);
		if (err != 0) {
			syslog(LOG_ERR, EM_MUTEX_FAIL, strerror(err));
			return;
		}
		g_wait_now = B_FALSE;
		(void) pthread_cond_broadcast(&g_cv);
		(void) pthread_mutex_unlock(&g_mutex);
	} else {
		if ((pthread_attr_init(&ledsthr_attr) != 0) ||
		    (pthread_attr_setscope(&ledsthr_attr,
		    PTHREAD_SCOPE_SYSTEM) != 0))
			return;
		if ((err = pthread_create(&ledsthr_tid, &ledsthr_attr,
		    disk_leds_thread, NULL)) != 0) {
			syslog(LOG_ERR, EM_THREAD_CREATE_FAILED, strerror(err));
			return;
		}
		ledsthr_created = B_TRUE;
	}
	for (i = 0; i < N_DISKS; i++) {
		(void) set_led(lw8_disks[i].d_fruname, FAULT_LED,
		    PICL_PROPVAL_OFF);
	}
}

static void
disk_leds_fini(void)
{
	int	err;

	/*
	 * tell led thread to pause
	 */
	if (!ledsthr_created)
		return;
	err = pthread_mutex_lock(&g_mutex);
	if (err != 0) {
		syslog(LOG_ERR, EM_MUTEX_FAIL, strerror(err));
		return;
	}
	g_wait_now = B_TRUE;
	disk_leds_thread_ack = B_FALSE;
	(void) pthread_cond_broadcast(&g_cv);

	/*
	 * and wait for the led thread to acknowledge
	 */
	while (!disk_leds_thread_ack) {
		(void) pthread_cond_wait(&g_cv_ack, &g_mutex);
	}
	(void) pthread_mutex_unlock(&g_mutex);
}

static void
update_disk_node(struct lw8_disk *diskp)
{
	picl_nodehdl_t slotndh;
	picl_nodehdl_t diskndh;
	picl_nodehdl_t devhdl;
	picl_prophdl_t	tblhdl;
	int err;
	char path[MAXPATHLEN];
	char *fruname = diskp->d_fruname;

	sprintf_buf2(path, CHASSIS_LOC_PATH, fruname);
	if (ptree_get_node_by_path(path, &slotndh) != PICL_SUCCESS) {
		return;
	}
	diskndh = find_child_by_name(slotndh, fruname);
	err = ptree_get_node_by_path(diskp->d_plat_path, &devhdl);
	if (err == PICL_SUCCESS) {
		if (diskndh != 0)
			return;
		err = ptree_create_and_add_node(slotndh, fruname,
		    PICL_CLASS_FRU, &diskndh);
		if (err != PICL_SUCCESS) {
			syslog(LOG_ERR, ADD_NODE_FAIL, fruname, err);
			return;
		}
		err = create_table(diskndh, &tblhdl, PICL_PROP_DEVICES);
		if (err != PICL_SUCCESS)
			return;
		err = create_table_entry(tblhdl, devhdl, PICL_CLASS_BLOCK);
		if (err != PICL_SUCCESS)
			return;
		err = add_prop_ref(devhdl, diskndh, PICL_REFPROP_FRU_PARENT);
		if (err != PICL_SUCCESS)
			return;
	} else {
		if (diskndh == 0)
			return;
		err = ptree_delete_node(diskndh);
		if (err != PICL_SUCCESS)
			return;
		(void) ptree_destroy_node(diskndh);
	}
}

/*
 * Implement a state machine in order to:
 *
 *  o enable/disable disk LEDs
 *  o add/delete the disk's node in the FRU tree
 *
 * The machine changes state based on the current, in-memory
 * state of the disk (eg, the d_state field of 'struct lw8_disk')
 * and libdevice's current view of whether the disk is
 * Configured or Unconfigured.
 *
 * If the new state is the same as the previous state, then
 * no side effects occur.  Otherwise, the LEDs for the
 * disk are set and the disk's associated node in the
 * FRU Tree is added or deleted.
 */
static void
set_disk_leds(struct lw8_disk *disk)
{
	devctl_hdl_t	dhdl;
	uint_t		cur_state = 0;

	dhdl = devctl_device_acquire(disk->d_devices_path, 0);
	if (dhdl == NULL) {
		int err = errno;
		syslog(LOG_ERR, DEVCTL_DEVICE_ACQUIRE_FAILED,
		    strerror(err));
		return;
	}
	devctl_device_getstate(dhdl, &cur_state);
	devctl_release(dhdl);

	if ((cur_state & DEVICE_OFFLINE) != 0) {
		switch (disk->d_state) {
		default:
			/*
			 * State machine should never get here.
			 * When NDEBUG is defined, control will
			 * fall through and force d_state to
			 * match the semantics of "DEVICE_OFFLINE".
			 * During development, NDEBUG can be undefined,
			 * and this will fire an assertion.
			 */
			assert(0);
			/*FALLTHROUGH*/

		case DISK_STATE_NOT_INIT:
		case DISK_STATE_READY:
			disk->d_state = DISK_STATE_NOT_READY;

			(void) set_led(disk->d_fruname, POWER_LED,
			    PICL_PROPVAL_OFF);
			(void) set_led(disk->d_fruname, REMOK_LED,
			    PICL_PROPVAL_ON);

			update_disk_node(disk);
			break;

		case DISK_STATE_NOT_READY:
			break;
		}
	} else if ((cur_state & DEVICE_ONLINE) != 0) {
		switch (disk->d_state) {
		default:
			/*
			 * State machine should never get here.
			 * When NDEBUG is defined, control will
			 * fall through and force d_state to
			 * match the semantics of "DEVICE_ONLINE".
			 * During development, NDEBUG can be undefined,
			 * and this will fire an assertion.
			 */
			assert(0);
			/*FALLTHROUGH*/

		case DISK_STATE_NOT_INIT:
		case DISK_STATE_NOT_READY:
			disk->d_state = DISK_STATE_READY;

			(void) set_led(disk->d_fruname, REMOK_LED,
			    PICL_PROPVAL_OFF);
			(void) set_led(disk->d_fruname, POWER_LED,
			    PICL_PROPVAL_ON);

			update_disk_node(disk);
			break;

		case DISK_STATE_READY:
			break;
		}
	}
}

/*
 * NOTE: this implementation of disk_leds_thread is based on the version in
 * plugins/sun4u/mpxu/frudr/piclfrudr.c (with V440 raid support removed). Some
 * day the source code layout and build environment should support common code
 * used by platform specific plugins, in which case LW8 support could be added
 * to the mpxu version (which would be moved to a common directory).
 */
/*ARGSUSED*/
static void *
disk_leds_thread(void *args)
{
	int	i;
	int	err = 0;
	int	n_disks = N_DISKS;

	static char *lw8_pci_devs[] = {
		DISK0_BASE_PATH,
		DISK1_BASE_PATH
	};

	static char *lw8_pcix_devs[] = {
		DISK0_BASE_PATH_PCIX,
		DISK1_BASE_PATH_PCIX
	};

	static char **lw8_devs;

	if (pcix_io) {
		lw8_devs = lw8_pcix_devs;
	} else {
		lw8_devs = lw8_pci_devs;
	}

	/*
	 * create aliases for disk names
	 */
	for (i = 0; i < n_disks; i++) {
		char buffer[MAXPATHLEN];

		(void) snprintf(buffer, sizeof (buffer), "/devices%s",
		    lw8_devs[i]);
		lw8_disks[i].d_devices_path = strdup(buffer);

		(void) snprintf(buffer, sizeof (buffer), "/platform%s",
		    lw8_devs[i]);
		lw8_disks[i].d_plat_path = strdup(buffer);
	}

	for (;;) {
		for (i = 0; i < n_disks; i++) {
			set_disk_leds(&lw8_disks[i]);
		}

		/*
		 * wait a bit until we check again
		 */
		err = poll(NULL, 0, ledsthr_poll_period);
		if (err == -1) {
			err = errno;
			syslog(LOG_ERR, EM_POLL_FAIL, strerror(err));
			break;
		}
		err = pthread_mutex_lock(&g_mutex);
		if (err != 0) {
			syslog(LOG_ERR, EM_MUTEX_FAIL, strerror(err));
			break;
		}
		if (g_wait_now != B_FALSE) {
			/* notify _fini routine that we've paused */
			disk_leds_thread_ack = B_TRUE;
			(void) pthread_cond_signal(&g_cv_ack);
			/* and go to sleep in case we get restarted */
			while (g_wait_now != B_FALSE)
				(void) pthread_cond_wait(&g_cv, &g_mutex);
		}
		(void) pthread_mutex_unlock(&g_mutex);
	}
	return ((void *)err);
}
