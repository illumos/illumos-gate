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
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stddef.h>
#include <syslog.h>
#include <strings.h>
#include <unistd.h>
#include <libintl.h>
#include <stdlib.h>
#include <ctype.h>
#include <picl.h>
#include <picltree.h>
#include <picld_pluginutil.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/sysevent/dr.h>
#include <pthread.h>
#include <libdevinfo.h>
#include <limits.h>
#include <sys/systeminfo.h>
#include <sys/envmon.h>
#include <i2c_gpio.h>
#include "libdevice.h"
#include "picldefs.h"
#include <sys/raidioctl.h>
#include <sys/param.h>
#include <sys/epic.h>

/*
 * Plugin registration entry points
 */
static void	piclfrudr_register(void);
static void	piclfrudr_init(void);
static void	piclfrudr_fini(void);
static void	rmc_state_event(void);
static void	seattle_setleds(void);
static void	boston_set_frontleds(const char *, int);
static void	boston_set_rearleds(const char *, int);

#pragma	init(piclfrudr_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_MPXU_frudr",
	piclfrudr_init,
	piclfrudr_fini,
};

/*
 * Log message texts
 */
#define	EM_THREAD_CREATE_FAILED gettext("piclfrudr: pthread_create failed: %s")
#define	DELETE_PROP_FAIL gettext("ptree_delete_prop failed: %d")
#define	EM_DI_INIT_FAIL	gettext("piclfrudr: di_init failed: %s")
#define	PROPINFO_FAIL gettext("ptree_init_propinfo %s failed: %d")
#define	ADD_NODE_FAIL gettext("ptree_create_and_add_node %s failed: %d")
#define	ADD_TBL_ENTRY_FAIL gettext("piclfrudr: cannot add entry to table")
#define	EM_POLL_FAIL gettext("piclfrudr: poll() failed: %s")
#define	ADD_PROP_FAIL gettext("ptree_create_and_add_prop %s failed: %d")
#define	EM_MUTEX_FAIL gettext("piclfrudr: pthread_mutex_lock returned: %s")
#define	EM_UNK_FRU gettext("piclfrudr: Fru removed event for unknown node")
#define	PARSE_CONF_FAIL gettext("parse config file %s failed")
#define	EM_NO_SC_DEV gettext("piclfrudr: failed to locate SC device node")
#define	EM_NO_SYSINFO gettext("piclfrudr: failed to get SC sysinfo: %s")

/*
 * PICL property values
 */
#define	PICL_PROPVAL_ON		"ON"
#define	PICL_PROPVAL_OFF	"OFF"

/*
 * Local defines
 */
#define	SEEPROM_DRIVER_NAME	"seeprom"
#define	FRUTREE_PATH		"/frutree"
#define	CHASSIS_LOC_PATH	"/frutree/chassis/%s"
#define	SYS_BOARD_PATH		"/frutree/chassis/MB/system-board/%s"
#define	SEATTLE1U_HDDBP_PATH	\
	"/frutree/chassis/MB/system-board/HDDBP/disk-backplane-1/%s"
#define	SEATTLE2U_HDDBP_PATH	\
	"/frutree/chassis/MB/system-board/HDDBP/disk-backplane-3/%s"
#define	BOSTON_HDDBP_PATH	\
	"/frutree/chassis/MB/system-board/HDDCNTRL/disk-controller/HDDBP" \
	"/disk-backplane-8/%s"

#define	CONFFILE_PREFIX		"fru_"
#define	CONFFILE_SUFFIX		".conf"
#define	CONFFILE_FRUTREE	"piclfrutree.conf"
#define	PS_NAME			"PS"
#define	PS_NAME_LEN		2
#define	PS_FRU_NAME		"power-supply"
#define	PS_PLATFORM_NAME	"power-supply-fru-prom"
#define	DISK_NAME		"HDD"
#define	DISK_NAME_LEN		3
#define	DISK_FRU_NAME		"disk"
#define	SCC_NAME		"SCC"
#define	SCC_NAME_LEN		3
#define	SCC_FRU_NAME		"scc"
#define	RMC_NAME		"SC"
#define	RMC_NAME_LEN		2
#define	RMC_FRU_NAME		"sc"
#define	FT_NAME			"FT"
#define	FT_NAME_LEN		2
#define	F0_NAME			"F0"
#define	F0_NAME_LEN		2
#define	F1_NAME			"F1"
#define	F1_NAME_LEN		2
#define	FT_FRU_NAME		"fan-tray"
#define	FT_FRU_NAME_LEN	8
#define	FT_ID_BUFSZ		(FT_NAME_LEN + 2)
#define	DEV_PREFIX		"/devices"
#define	ENXS_FRONT_SRVC_LED	0x20
#define	ENXS_FRONT_ACT_LED	0x10
#define	ENXS_REAR_SRVC_LED	0x20
#define	ENXS_REAR_ACT_LED	0x10
#define	ENTS_SRVC_LED		0x20
#define	ENTS_ACT_LED		0x10
#define	V440_SRVC_LED		0x2
#define	V440_ACT_LED		0x1
#define	BOSTON_FRONT_SRVC_LED	0x2
#define	BOSTON_FRONT_ACT_LED	0x4
#define	BOSTON_FRONT_CLEAR_DIR	0x0
#define	BOSTON_FRONT_CLEAR_POL	0x0
#define	BOSTON_FRONT_LED_MASK	0xffffffff
#define	BOSTON_REAR_SRVC_LED	0x8000
#define	BOSTON_REAR_ACT_LED	0x2000
#define	BOSTON_REAR_CLEAR_POL	0x0000
#define	BOSTON_REAR_LED_MASK	0xe000

/*
 * PSU defines
 */
#define	PSU_I2C_BUS_DEV "/devices/pci@1e,600000/isa@7/i2c@0,320:devctl"
#define	PSU_DEV	\
	"/devices/pci@1e,600000/isa@7/i2c@0,320/power-supply-fru-prom@0,%x"
#define	PSU_PLATFORM	"/platform/pci@1e,600000/isa@7/i2c@0,320"
#define	PS0_ADDR ((sys_platform == PLAT_CHALUPA19) ? 0xc0 : 0xb0)
#define	PS1_ADDR ((sys_platform == PLAT_CHALUPA19) ? 0xc2 : 0xa4)
#define	PS2_ADDR 0x70
#define	PS3_ADDR 0x72
#define	PS0_UNITADDR	((sys_platform == PLAT_CHALUPA19) ? "0,c0" : "0,b0")
#define	PS1_UNITADDR	((sys_platform == PLAT_CHALUPA19) ? "0,c2" : "0,a4")
#define	PS2_UNITADDR	"0,70"
#define	PS3_UNITADDR	"0,72"
#define	PS0_NAME "PS0"
#define	PS1_NAME "PS1"
#define	PS2_NAME "PS2"
#define	PS3_NAME "PS3"
#define	PSU0_NAME "PSU0"
#define	PSU1_NAME "PSU1"
#define	PSU2_NAME "PSU2"
#define	PSU3_NAME "PSU3"
#define	PS_DEVICE_NAME "power-supply-fru-prom"
#define	PSU_COMPATIBLE	"i2c-at24c64"

/*
 * Seattle/Boston PSU defines
 */
#define	SEATTLE_PSU_I2C_BUS_DEV "/devices/i2c@1f,530000:devctl"
#define	SEATTLE_PSU_DEV	\
	"/devices/i2c@1f,530000/power-supply-fru-prom@0,%x"
#define	SEATTLE_PSU_PLATFORM	"/platform/i2c@1f,530000"
#define	SEATTLE_PS0_ADDR	0x6c
#define	SEATTLE_PS1_ADDR	0x6e
#define	SEATTLE_PS0_UNITADDR	"0,6c"
#define	SEATTLE_PS1_UNITADDR	"0,6e"
#define	SEATTLE_PSU_COMPATIBLE	"i2c-at34c02"
#define	BOSTON_PSU_I2C_BUS_DEV	"/devices/i2c@1f,520000:devctl"
#define	BOSTON_PSU_DEV	\
	"/devices/i2c@1f,520000/power-supply-fru-prom@0,%x"
#define	BOSTON_PSU_PLATFORM	"/platform/i2c@1f,520000"
#define	BOSTON_PS0_ADDR		0x24
#define	BOSTON_PS1_ADDR		0x32
#define	BOSTON_PS2_ADDR		0x52
#define	BOSTON_PS3_ADDR		0x72
#define	BOSTON_PS0_UNITADDR	"0,24"
#define	BOSTON_PS1_UNITADDR	"0,32"
#define	BOSTON_PS2_UNITADDR	"0,52"
#define	BOSTON_PS3_UNITADDR	"0,72"
#define	BOSTON_PSU_COMPATIBLE	"i2c-at34c02"

/*
 * Seattle fan-tray paths
 */
#define	SEATTLE_FCB0_1U \
	"/frutree/chassis/MB/system-board/FIOB/front-io-board-1" \
	"/FCB0/fan-connector-board/%s"
#define	SEATTLE_FCB1_1U \
	"/frutree/chassis/MB/system-board/FIOB/front-io-board-1" \
	"/FCB1/fan-connector-board/%s"
#define	SEATTLE_PDB_1U \
	"/frutree/chassis/PDB/power-distribution-board/%s"
#define	SEATTLE_FCB0_2U	\
	"/frutree/chassis/MB/system-board/FIOB/front-io-board-2" \
	"/FCB0/fan-connector-board/%s"
#define	SEATTLE_FCB1_2U \
	"/frutree/chassis/MB/system-board/FIOB/front-io-board-2" \
	"/FCB1/fan-connector-board/%s"
#define	SEATTLE_PDB_2U \
	"/frutree/chassis/PDB/power-distribution-board" \
	"/HDDFB/fan-connector-board/%s"

/*
 * disk defines
 */
#define	REMOK_LED "OK2RM"
#define	FAULT_LED "SERVICE"
#define	PLATFORMLEN 9
#define	N_DISKS 8
#define	N_CHALUPA_DISKS 4
#define	N_ENTS_DISKS 8
#define	N_MPXU_DISKS 4
#define	N_EN19_DISKS 2
#define	DISK_POLL_TIME	5000
/* For V440 RAID policy */
#define	V440_DISK_DEVCTL "/devices/pci@1f,700000/scsi@2:devctl"

/*
 * Seattle/Boston disk defines
 */
#define	N_SEATTLE1U_DISKS	2
#define	N_SEATTLE2U_DISKS	4
#define	N_BOSTON_DISKS		8
#define	SEATTLE_DISK_DEVCTL \
	"/devices/pci@1e,600000/pci@0/pci@a/pci@0/pci@8/scsi@1:devctl"
#define	BOSTON_DISK_DEVCTL_1068X \
	"/devices/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1:devctl"
#define	BOSTON_DISK_DEVCTL_1068E \
	"/devices/pci@1e,600000/pci@0/pci@2/scsi@0:devctl"

/*
 * led defines
 */
#define	ENXS_LED_DIR	"/devices/pci@1e,600000/isa@7/i2c@0,320/"
#define	ENXS_FRONT_LEDS	"gpio@0,70:"
#define	ENXS_REAR_LEDS	ENXS_LED_DIR "gpio@0,44:port_1"

#define	ENTS_LED_DIR	"/devices/pci@1e,600000/isa@7/i2c@0,320/"
#define	ENTS_LEDS	"gpio@0,70:"

#define	V440_LED_DIR	"/devices/pci@1e,600000/isa@7/i2c@0,320/"
#define	V440_LED_PATH	V440_LED_DIR "gpio@0,48:port_0"

/*
 * Seattle/Boston led defines
 */
#define	SEATTLE_LED_DEV	"/devices/ebus@1f,464000/env-monitor@3,0:env-monitor0"
#define	BOSTON_LED_DIR	"/devices/i2c@1f,520000/"
#define	BOSTON_FRONT_LED_PATH	BOSTON_LED_DIR "gpio@0,3a:port_0"
#define	BOSTON_REAR_LED_PATH	BOSTON_LED_DIR "hardware-monitor@0,5c:adm1026"

/*
 * Seattle/Boston USB defines
 */
#define	MAX_USB_PORTS		4
#define	USB_CONF_FILE_NAME	"usb-a-"

typedef struct id_props {
	envmon_handle_t	envhandle;
	picl_prophdl_t	volprop;
} id_props_t;

typedef struct idp_lkup {
	int		maxnum;		/* entries in array */
	int		num;		/* entries in use */
	id_props_t	idp[1];
} idp_lkup_t;

/*
 * table for mapping RMC handles to volatile property handles
 */
static idp_lkup_t	*idprop = NULL;

/*
 * path names to system-controller device and fault led gpio
 */
static char		*sc_device_name = NULL;
static char		*bezel_leds = NULL;

/*
 * disk data
 */
static int disk_ready[N_DISKS];
static char *disk_name[N_DISKS] = { "HDD0", "HDD1", "HDD2", "HDD3",
					"HDD4", "HDD5", "HDD6", "HDD7" };
static volatile boolean_t	disk_leds_thread_ack = B_FALSE;
static volatile	boolean_t	disk_leds_thread_running = B_FALSE;
static pthread_t		ledsthr_tid;
static pthread_attr_t		ledsthr_attr;
static boolean_t		ledsthr_created = B_FALSE;
static boolean_t		g_mutex_init = B_FALSE;
static pthread_cond_t		g_cv;
static pthread_cond_t		g_cv_ack;
static pthread_mutex_t		g_mutex;
static volatile boolean_t	g_finish_now = B_FALSE;

/*
 * Boston platform-specific flag which tells us if we are using
 * a LSI 1068X disk controller (0) or a LSI 1068E (1).
 */
static int boston_1068e_flag = 0;

/*
 * static strings
 */
static const char		str_devfs_path[] = "devfs-path";

/*
 * OperationalStatus property values
 */
static const char		str_opst_present[] = "present";
static const char		str_opst_ok[] = "okay";
static const char		str_opst_faulty[] = "faulty";
static const char		str_opst_download[] = "download";
static const char		str_opst_unknown[] = "unknown";
static size_t			max_opst_len = sizeof (str_opst_download);

/*
 * forward reference
 */
static void opst_init(void);
static void add_op_status_by_name(const char *name, const char *child_name,
    picl_prophdl_t *prophdl_p);
static void add_op_status_to_node(picl_nodehdl_t nodeh,
    picl_prophdl_t *prophdl_p);
static int read_vol_data(ptree_rarg_t *r_arg, void *buf);
static int find_picl_handle(picl_prophdl_t proph);
static void disk_leds_init(void);
static void disk_leds_fini(void);
static void *disk_leds_thread(void *args);
static picl_nodehdl_t find_child_by_name(picl_nodehdl_t parh, char *name);
static void post_frudr_event(char *ename, picl_nodehdl_t parenth,
    picl_nodehdl_t fruh);
static int add_prop_ref(picl_nodehdl_t nodeh, picl_nodehdl_t value, char *name);
static void remove_fru_parents(picl_nodehdl_t fruh);
static int get_node_by_class(picl_nodehdl_t nodeh, const char *classname,
    picl_nodehdl_t *foundnodeh);
static int get_sys_controller_node(picl_nodehdl_t *nodeh);
static char *create_sys_controller_pathname(picl_nodehdl_t sysconh);
static char *create_bezel_leds_pathname(const char *dirpath,
    const char *devname);
static void frudr_evhandler(const char *ename, const void *earg,
    size_t size, void *cookie);
static void fru_add_handler(const char *ename, const void *earg,
    size_t size, void *cookie);
static void frutree_evhandler(const char *ename, const void *earg,
	size_t size, void *cookie);
static int create_table(picl_nodehdl_t fruhdl, picl_prophdl_t *tblhdlp,
    char *tbl_name);
static int create_table_entry(picl_prophdl_t tblhdl,
    picl_nodehdl_t refhdl, char *class);
static int create_i2c_node(char *ap_id);
static void delete_i2c_node(char *ap_id);
static int set_led(char *name, char *ptr, char *value);
static int ps_name_to_addr(char *name);
static char *ps_name_to_unitaddr(char *name);
static char *ps_apid_to_nodename(char *apid);
static void add_op_status(envmon_hpu_t *hpu, int *index);
static void get_fantray_path(char *ap_id, char *path, int bufsz);

#define	sprintf_buf2(buf, a1, a2) (void) snprintf(buf, sizeof (buf), a1, a2)

/*
 * Because this plugin is shared across different platforms, we need to
 * distinguish for certain functionality
 */
#define	PLAT_UNKNOWN	(-1)
#define	PLAT_ENXS	0
#define	PLAT_ENTS	1
#define	PLAT_CHALUPA	2
#define	PLAT_EN19	3
#define	PLAT_CHALUPA19	4
#define	PLAT_SALSA19	5
#define	PLAT_SEATTLE1U	6
#define	PLAT_SEATTLE2U	7
#define	PLAT_BOSTON	8

static int sys_platform;

static void
get_platform()
{
	char	platform[64];
	(void) sysinfo(SI_PLATFORM, platform, sizeof (platform));
	if (strcmp(platform, "SUNW,Sun-Fire-V250") == 0)
		sys_platform = PLAT_ENTS;
	else if (strcmp(platform, "SUNW,Sun-Fire-V440") == 0)
		sys_platform = PLAT_CHALUPA;
	else if (strcmp(platform, "SUNW,Sun-Fire-V210") == 0)
		sys_platform = PLAT_ENXS;
	else if (strcmp(platform, "SUNW,Sun-Fire-V240") == 0)
		sys_platform = PLAT_ENXS;
	else if (strcmp(platform, "SUNW,Netra-240") == 0)
		sys_platform = PLAT_EN19;
	else if (strcmp(platform, "SUNW,Netra-210") == 0)
		sys_platform = PLAT_SALSA19;
	else if (strcmp(platform, "SUNW,Netra-440") == 0)
		sys_platform = PLAT_CHALUPA19;
	else if (strcmp(platform, "SUNW,Sun-Fire-V215") == 0)
		sys_platform = PLAT_SEATTLE1U;
	else if (strcmp(platform, "SUNW,Sun-Fire-V245") == 0)
		sys_platform = PLAT_SEATTLE2U;
	else if (strcmp(platform, "SUNW,Sun-Fire-V445") == 0)
		sys_platform = PLAT_BOSTON;
	else
		sys_platform = PLAT_UNKNOWN;
}

/*
 * This function is executed as part of .init when the plugin is
 * dlopen()ed
 */
static void
piclfrudr_register(void)
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * This function is the init entry point of the plugin.
 * It initializes the /frutree tree
 */
static void
piclfrudr_init(void)
{
	picl_nodehdl_t	sc_nodeh;
	picl_nodehdl_t	locationh;
	picl_nodehdl_t	childh;
	char namebuf[PATH_MAX];

	get_platform();

	if (sc_device_name != NULL) {
		free(sc_device_name);	/* must have reen restarted */
		sc_device_name = NULL;
	}

	if ((get_sys_controller_node(&sc_nodeh) != PICL_SUCCESS) ||
	    ((sc_device_name = create_sys_controller_pathname(sc_nodeh)) ==
	    NULL))
		syslog(LOG_ERR, EM_NO_SC_DEV);

	opst_init();
	disk_leds_init();

	(void) ptree_register_handler(PICLEVENT_DR_AP_STATE_CHANGE,
	    frudr_evhandler, NULL);
	(void) ptree_register_handler(PICL_FRU_ADDED, fru_add_handler, NULL);
	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    frutree_evhandler, NULL);

	/*
	 * There is a window of opportunity for the RMC to deliver an event
	 * indicating a newly operable state just before we are listening for
	 * it. In this case, envmon will have missed setting up /platform
	 * and won't get a signal from frudr. So send it a PICL_FRU_ADDED just
	 * in case.
	 */

	if ((sys_platform == PLAT_CHALUPA) ||
	    (sys_platform == PLAT_CHALUPA19)) {
		sprintf_buf2(namebuf, CHASSIS_LOC_PATH, RMC_NAME);
	} else {
		sprintf_buf2(namebuf, SYS_BOARD_PATH, RMC_NAME);
	}

	if (ptree_get_node_by_path(namebuf, &locationh) != PICL_SUCCESS)
		return;
	if (ptree_get_propval_by_name(locationh, PICL_PROP_CHILD,
	    &childh, sizeof (picl_nodehdl_t)) != PICL_SUCCESS)
		return;
	post_frudr_event(PICL_FRU_ADDED, locationh, childh);
}

static void
add_op_status_by_name(const char *name, const char *child_name,
    picl_prophdl_t *prophdl_p)
{
	picl_nodehdl_t		nodeh;

	if (ptree_get_node_by_path(name, &nodeh) != PICL_SUCCESS) {
		return;
	}

	if (ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD,
	    &nodeh, sizeof (picl_nodehdl_t)) != PICL_SUCCESS) {

		if (child_name == NULL)
			return;
		/*
		 * create fru node of supplied name
		 */
		if (ptree_create_and_add_node(nodeh, child_name,
		    PICL_CLASS_FRU, &nodeh) != PICL_SUCCESS)
			return;
	}

	add_op_status_to_node(nodeh, prophdl_p);
}

/*
 * function to add a volatile property to a specified node
 */
static void
add_op_status_to_node(picl_nodehdl_t nodeh, picl_prophdl_t *prophdl_p)
{
	int			err;
	ptree_propinfo_t	info;
	picl_prophdl_t		proph;

	err = ptree_init_propinfo(&info, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_VOLATILE | PICL_READ, max_opst_len,
	    PICL_PROP_OPERATIONAL_STATUS, read_vol_data, NULL);

	if (err == PICL_SUCCESS) {
		if (ptree_get_prop_by_name(nodeh, PICL_PROP_OPERATIONAL_STATUS,
		    &proph) == PICL_SUCCESS) {
			if (ptree_delete_prop(proph) == PICL_SUCCESS)
				err = ptree_destroy_prop(proph);
		}
	}

	if ((err != PICL_SUCCESS) || ((err = ptree_create_and_add_prop(nodeh,
	    &info, NULL, prophdl_p)) != PICL_SUCCESS)) {
		syslog(LOG_ERR, ADD_PROP_FAIL, PICL_PROP_OPERATIONAL_STATUS,
		    err);
		return;
	}
}

/*
 * Deliver volatile property value.
 * prtpicl gets very upset if we fail this command, so if the property
 * cannot be retrieved, return a status of unknown.
 */
static int
read_vol_data(ptree_rarg_t *r_arg, void *buf)
{
	picl_prophdl_t	proph;
	int		index;
	int		envmon_fd;
	int		err;
	envmon_hpu_t	data;

	proph = r_arg->proph;
	index = find_picl_handle(proph);

	if (index < 0) {
		/*
		 * We drop memory of PSU op status handles in opst_init()
		 * when we get an RMC faulty event. We cannot access the
		 * status info in this circumstance, so returning "unknown"
		 * is appropriate.
		 */
		(void) strlcpy(buf, str_opst_unknown, max_opst_len);
		return (PICL_SUCCESS);
	}

	envmon_fd = open(sc_device_name, O_RDONLY);

	if (envmon_fd < 0) {
		/*
		 * To get this far we must have succeeded with an earlier
		 * open, so this is an unlikely failure. It would be more
		 * helpful to indicate the nature of the failure, but we
		 * don't have the space to say much. Just return "unknown".
		 */
		(void) strlcpy(buf, str_opst_unknown, max_opst_len);
		return (PICL_SUCCESS);
	}

	data.id = idprop->idp[index].envhandle;
	err = ioctl(envmon_fd, ENVMONIOCHPU, &data);

	if (err < 0) {
		/*
		 * If we can't read the stats, "unknown" is a reasonable
		 * status to return. This one really shouldn't happen.
		 */
		(void) strlcpy(buf, str_opst_unknown, max_opst_len);
		(void) close(envmon_fd);
		return (PICL_SUCCESS);
	}

	(void) close(envmon_fd);

	if (strncmp(data.id.name, DISK_NAME, DISK_NAME_LEN) == 0 &&
	    data.fru_status == ENVMON_FRU_PRESENT) {
		(void) strlcpy(buf, str_opst_present, max_opst_len);
		return (PICL_SUCCESS);
	}

	if (data.sensor_status != ENVMON_SENSOR_OK) {
		(void) strlcpy(buf, str_opst_unknown, max_opst_len);
		return (PICL_SUCCESS);
	}

	(void) strlcpy(buf,
	    data.fru_status == ENVMON_FRU_PRESENT ? str_opst_ok :
	    data.fru_status == ENVMON_FRU_DOWNLOAD ? str_opst_download :
	    data.fru_status == ENVMON_FRU_FAULT ? str_opst_faulty :
	    str_opst_unknown, max_opst_len);

	return (PICL_SUCCESS);
}

/*
 * Function for explicitly turning on system leds
 * for a failed/degraded RMC (SC).
 */
static void
solaris_setleds(const char *led_path, int leds)
{
	i2c_gpio_t	gpio;
	int		fd = open(led_path, O_RDWR);

	if (fd < 0)
		return;

	gpio.reg_val = (leds ^ 0xff);
	gpio.reg_mask = 0xffffffff;
	if (ioctl(fd, GPIO_SET_CONFIG, &gpio) == 0) {
		gpio.reg_val = (leds ^ 0xff);
		gpio.reg_mask = 0xffffffff;
		(void) ioctl(fd, GPIO_SET_OUTPUT, &gpio);
	}
	(void) close(fd);
}

/*
 * Function for explicitly turning on system leds
 * for a failed/degraded RMC (SC) on Seattle
 */
static void
seattle_setleds(void)
{
	int fd;

	fd = open(SEATTLE_LED_DEV, O_RDWR);

	if (fd < 0)
		return;

	ioctl(fd, EPIC_SET_POWER_LED, (char *)0);
	ioctl(fd, EPIC_SET_ALERT_LED, (char *)0);
	(void) close(fd);
}

/*
 * Function for explicitly turning on the front system leds
 * for a failed/degraded RMC (SC) on Boston
 */
static void
boston_set_frontleds(const char *led_path, int leds)
{
	i2c_gpio_t	gpio;
	int		fd = open(led_path, O_RDWR);

	if (fd < 0) {
		return;
	}

	/* first clear the polarity */
	gpio.reg_val  = BOSTON_FRONT_CLEAR_POL;
	gpio.reg_mask = BOSTON_FRONT_LED_MASK;
	if (ioctl(fd, GPIO_SET_POLARITY, &gpio) < 0)	{
		(void) close(fd);
		return;
	}

	/* now clear the direction */
	gpio.reg_val  = BOSTON_FRONT_CLEAR_DIR;
	gpio.reg_mask = BOSTON_FRONT_LED_MASK;
	if (ioctl(fd, GPIO_SET_CONFIG, &gpio) < 0)	{
		(void) close(fd);
		return;
	}

	/* and light the leds */
	gpio.reg_val = leds;
	gpio.reg_mask = BOSTON_FRONT_LED_MASK;
	ioctl(fd, GPIO_SET_OUTPUT, &gpio);
	(void) close(fd);
}

/*
 * Function for explicitly turning on the rear system leds
 * for a failed/degraded RMC (SC) on Boston
 */
static void
boston_set_rearleds(const char *led_path, int leds)
{
	i2c_gpio_t	gpio;
	int		fd = open(led_path, O_RDWR);

	if (fd < 0) {
		return;
	}

	/* first clear the polarity */
	gpio.reg_val  = BOSTON_REAR_CLEAR_POL;
	gpio.reg_mask = BOSTON_REAR_LED_MASK;
	if (ioctl(fd, GPIO_SET_POLARITY, &gpio) < 0)	{
		(void) close(fd);
		return;
	}

	/* now set the direction */
	gpio.reg_val  = BOSTON_REAR_LED_MASK;
	gpio.reg_mask = BOSTON_REAR_LED_MASK;
	if (ioctl(fd, GPIO_SET_CONFIG, &gpio) < 0)	{
		(void) close(fd);
		return;
	}

	/* and light the leds */
	gpio.reg_val = leds;
	gpio.reg_mask = BOSTON_REAR_LED_MASK;
	ioctl(fd, GPIO_SET_OUTPUT, &gpio);
	(void) close(fd);
}

static void
rmc_state_event(void)
{
	envmon_hpu_t	hpu;
	int		res;
	int		fd = open(sc_device_name, O_RDONLY);

	if (fd < 0)
		return;

	(void) strlcpy(hpu.id.name, RMC_NAME, sizeof (hpu.id.name));
	res = ioctl(fd, ENVMONIOCHPU, &hpu);
	(void) close(fd);

	if ((res == 0) && (hpu.sensor_status == ENVMON_SENSOR_OK) &&
	    ((hpu.fru_status & ENVMON_FRU_FAULT) != 0)) {
		/*
		 * SC failed event - light the service led
		 * note that as Solaris is still running,
		 * the Solaris active led should be lit too.
		 */
		switch (sys_platform) {
		case PLAT_ENXS:
		case PLAT_SALSA19:
		case PLAT_EN19:
			solaris_setleds(ENXS_REAR_LEDS,
			    ENXS_REAR_SRVC_LED | ENXS_REAR_ACT_LED);
			/*
			 * the device name for the bezel leds GPIO device
			 * tends to vary from Unix to Unix. Search for it.
			 */
			if (bezel_leds  == NULL) {
				bezel_leds =
				    create_bezel_leds_pathname(ENXS_LED_DIR,
				    ENXS_FRONT_LEDS);
			}
			if (bezel_leds == NULL)
				return;
			solaris_setleds(bezel_leds,
			    ENXS_FRONT_SRVC_LED | ENXS_FRONT_ACT_LED);
			break;
		case PLAT_ENTS:
			/*
			 * the device name for the system leds gpio can vary
			 * as there are several similar gpio devices. Search
			 * for one with the desired address.
			 */
			if (bezel_leds  == NULL) {
				bezel_leds =
				    create_bezel_leds_pathname(ENTS_LED_DIR,
				    ENTS_LEDS);
			}
			if (bezel_leds == NULL)
				return;
			solaris_setleds(bezel_leds,
			    ENTS_SRVC_LED | ENTS_ACT_LED);
			break;
		case PLAT_CHALUPA:
		case PLAT_CHALUPA19:
			solaris_setleds(V440_LED_PATH,
			    V440_SRVC_LED | V440_ACT_LED);
			break;
		case PLAT_BOSTON:
			/* set front leds */
			boston_set_frontleds(BOSTON_FRONT_LED_PATH,
			    BOSTON_FRONT_SRVC_LED | BOSTON_FRONT_ACT_LED);
			/* and then the rear leds */
			boston_set_rearleds(BOSTON_REAR_LED_PATH,
			    BOSTON_REAR_SRVC_LED | BOSTON_REAR_ACT_LED);
			break;
		case PLAT_SEATTLE1U:
		case PLAT_SEATTLE2U:
			seattle_setleds();
			break;
		default:
			break;
		}
	}
}

static int
find_picl_handle(picl_prophdl_t proph)
{
	int index;

	if (idprop == NULL)
		return (-1);

	for (index = 0; index < idprop->num; index++) {
		if (idprop->idp[index].volprop == proph)
			return (index);
	}

	return (-1);
}

static int
find_vol_prop_by_name(const char *name)
{
	int index;

	if (idprop == NULL)
		return (-1);

	for (index = 0; index < idprop->num; index++) {
		if (strcmp(idprop->idp[index].envhandle.name, name) == 0)
			return (index);
	}

	return (-1);
}

/*
 * This function is the fini entry point of the plugin.
 */
static void
piclfrudr_fini(void)
{
	(void) ptree_unregister_handler(PICLEVENT_DR_AP_STATE_CHANGE,
	    frudr_evhandler, NULL);
	(void) ptree_unregister_handler(PICL_FRU_ADDED, fru_add_handler,
	    NULL);
	disk_leds_fini();
	if (idprop != NULL) {
		free(idprop);
		idprop = NULL;
	}
	if (sc_device_name != NULL) {
		free(sc_device_name);
		sc_device_name = NULL;
	}
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

	/* second column is reference property */
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

/*
 * The size of outfilename must be PATH_MAX
 */
static int
get_config_file(char *outfilename, char *fru)
{
	char		nmbuf[SYS_NMLN];
	char		pname[PATH_MAX];
	int		dir;

	for (dir = 0; dir < 2; dir++) {
		if (sysinfo(dir == 0 ? SI_PLATFORM : SI_MACHINE,
		    nmbuf, sizeof (nmbuf)) == -1) {
			continue;
		}

		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, CONFFILE_PREFIX, PATH_MAX);
		(void) strlcat(pname, fru, PATH_MAX);
		(void) strlcat(pname, CONFFILE_SUFFIX, PATH_MAX);

		if (access(pname, R_OK) == 0) {
			(void) strlcpy(outfilename, pname, PATH_MAX);
			return (0);
		}
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s%s%s",
	    PICLD_COMMON_PLUGIN_DIR, CONFFILE_PREFIX, fru,
	    CONFFILE_SUFFIX);

	if (access(pname, R_OK) == 0) {
		(void) strlcpy(outfilename, pname, PATH_MAX);
		return (0);
	}

	return (-1);
}

/*
 * This helper function for Netra-440 fan tray removal removes
 * the rmclomv-rooted nodes and their properties.
 */
static void
delete_node_and_props(picl_nodehdl_t hdl)
{
	picl_prophdl_t prop;
	int err;

	do {
		err = ptree_get_first_prop(hdl, &prop);
		if (err == PICL_SUCCESS) {
			if (ptree_delete_prop(prop) == PICL_SUCCESS)
				(void) ptree_destroy_prop(prop);
		}
	} while (err == PICL_SUCCESS);
	if (ptree_delete_node(hdl) == PICL_SUCCESS)
		(void) ptree_destroy_node(hdl);
}

static void
remove_fru_parents(picl_nodehdl_t fruh)
{
	char			name[MAXPATHLEN];
	int			retval;
	picl_nodehdl_t		nodeh;
	picl_prophdl_t		tableh;
	picl_prophdl_t		tblh;
	picl_prophdl_t		fruph;
	picl_nodehdl_t		childh;
	int			fanfru = 0;

	retval = ptree_get_propval_by_name(fruh, PICL_PROP_NAME, name,
	    sizeof (name));
	if (retval != PICL_SUCCESS) {
		syslog(LOG_ERR, EM_UNK_FRU);
		return;
	}

	retval = ptree_get_prop_by_name(fruh, PICL_PROP_DEVICES, &tableh);
	if (retval != PICL_SUCCESS) {
		/*
		 * No Devices table. However on Seattle, Boston and
		 * Netra-440 (Chalupa19) (which support fan fru hotplug),
		 * the Devices table will be found under the child node (Fn)
		 * of the fru (fan-tray).
		 * Therefore, check the first child of the fru for the
		 * Devices table on these platforms before returning.
		 */
		switch (sys_platform) {
		case PLAT_SEATTLE1U:
		case PLAT_SEATTLE2U:
		case PLAT_BOSTON:
			if (strcmp(name, FT_FRU_NAME) != 0)
				return;
			fanfru = 1;
			break;
		case PLAT_CHALUPA19:
			if (strncmp(name, F0_NAME, F0_NAME_LEN) &&
			    strncmp(name, F1_NAME, F1_NAME_LEN))
				return;
			fanfru = 1;
			break;
		default:
			/* nothing to do */
			return;
		}
		retval = ptree_get_propval_by_name(fruh,
		    PICL_PROP_CHILD, &childh, sizeof (picl_nodehdl_t));
		if (retval != PICL_SUCCESS)
			return;
		retval = ptree_get_prop_by_name(childh,
		    PICL_PROP_DEVICES, &tableh);
		if (retval != PICL_SUCCESS)
			return;
	}

	/*
	 * follow all reference properties in the second
	 * column of the table and delete any _fru_parent node
	 * at the referenced node.
	 */
	retval = ptree_get_propval(tableh, &tblh, sizeof (tblh));
	if (retval != PICL_SUCCESS) {
		/* can't get value of table property */
		goto afterloop;
	}

	/* get first col, first row */
	retval = ptree_get_next_by_col(tblh, &tblh);
	if (retval != PICL_SUCCESS) {
		/* no rows? */
		goto afterloop;
	}

	/*
	 * starting at next col, get every entry in the column
	 */
	for (retval = ptree_get_next_by_row(tblh, &tblh);
	    retval == PICL_SUCCESS;
	    retval = ptree_get_next_by_col(tblh, &tblh)) {
		/*
		 * should be a ref prop in our hands,
		 * get the target node handle
		 */
		retval = ptree_get_propval(tblh, &nodeh,
		    sizeof (nodeh));
		if (retval != PICL_SUCCESS) {
			continue;
		}
		/*
		 * got the referenced node, has it got a
		 * _fru_parent property?
		 */
		retval = ptree_get_prop_by_name(nodeh,
		    PICL_REFPROP_FRU_PARENT, &fruph);
		if (retval != PICL_SUCCESS) {
			/*
			 * on Boston, Seattle and Netra-440 we should
			 * actually be looking for the _location_parent
			 * property for fan frus
			 */
			if (fanfru) {
				retval = ptree_get_prop_by_name(nodeh,
				    PICL_REFPROP_LOC_PARENT, &fruph);
			}
			if (retval != PICL_SUCCESS)
				continue;
		}
		/*
		 * got a _fru_parent node reference delete it
		 */
		if (ptree_delete_prop(fruph) == PICL_SUCCESS)
			(void) ptree_destroy_prop(fruph);

		/* On Netra-440, extra clean-up is required for fan trays */
		if ((sys_platform == PLAT_CHALUPA19) && (fanfru)) {
			/* remove the rmclomv node and its properties */
			delete_node_and_props(nodeh);
		}
	}
afterloop:
	/* More Netra-440 fan tray clean-up  */
	if ((sys_platform == PLAT_CHALUPA19) && (fanfru)) {
		/* remove the fru's child's table */
		if (ptree_delete_prop(tableh) == PICL_SUCCESS)
			(void) ptree_destroy_prop(tableh);
		/* remove the child */
		if (ptree_delete_node(childh) == PICL_SUCCESS)
			(void) ptree_destroy_node(childh);
	}
}

static void
remove_tables(picl_nodehdl_t rootnd)
{
	picl_nodehdl_t	tableh;
	int		retval;

	retval = ptree_get_prop_by_name(rootnd, PICL_PROP_DEVICES, &tableh);

	if (retval == PICL_SUCCESS) {
		/*
		 * found a Devices property, delete it
		 */
		if ((retval = ptree_delete_prop(tableh)) == PICL_SUCCESS) {
			(void) ptree_destroy_prop(tableh);
		}
	}

	/*
	 * is there a child node?
	 */
	retval = ptree_get_propval_by_name(rootnd, PICL_PROP_CHILD, &rootnd,
	    sizeof (rootnd));

	while (retval == PICL_SUCCESS) {

		remove_tables(rootnd);

		/*
		 * any siblings?
		 */
		retval = ptree_get_propval_by_name(rootnd, PICL_PROP_PEER,
		    &rootnd, sizeof (rootnd));
	}
}

/*
 * Event completion handler for PICL_FRU_ADDED/PICL_FRU_REMOVED events
 */
/* ARGSUSED */
static void
frudr_completion_handler(char *ename, void *earg, size_t size)
{
	picl_nodehdl_t	fruh;
	picl_nodehdl_t	parh;
	picl_nodehdl_t	peerh = 0;
	char	nodename[PICL_PROPNAMELEN_MAX] = { '\0' };
	int err;

	if (strcmp(ename, PICL_FRU_REMOVED) == 0) {
		/*
		 * now frudata has been notified that the node is to be
		 * removed, we can actually remove it
		 */
		fruh = 0;
		(void) nvlist_lookup_uint64(earg,
		    PICLEVENTARG_FRUHANDLE, &fruh);
		if (fruh != 0) {
			(void) ptree_get_propval_by_name(fruh, PICL_PROP_PEER,
			    &peerh, sizeof (peerh));

			/*
			 * first find name of the fru
			 */
			err = ptree_get_propval_by_name(fruh, PICL_PROP_PARENT,
			    &parh, sizeof (parh));
			if (err == PICL_SUCCESS) {
				err = ptree_get_propval_by_name(parh,
				    PICL_PROP_NAME, nodename,
				    sizeof (nodename));
			}
			if (err == PICL_SUCCESS) {
				/*
				 * if it was a power supply, delete i2c node
				 */
				if (strncmp(nodename, PS_NAME,
				    PS_NAME_LEN) == 0) {
					(void) delete_i2c_node(nodename);
				}

				/*
				 * is disk node, make thread re-evaluate led
				 * state
				 */
				if (strncmp(nodename, DISK_NAME,
				    DISK_NAME_LEN) == 0) {
					disk_ready[nodename[DISK_NAME_LEN] -
					    '0'] = -1;
				}
			}

			remove_fru_parents(fruh);

			/*
			 * now we can delete the node
			 */
			err = ptree_delete_node(fruh);
			if (err == PICL_SUCCESS) {
				(void) ptree_destroy_node(fruh);
			} else {
				syslog(LOG_ERR, DELETE_PROP_FAIL, err);
			}

			if ((sys_platform == PLAT_CHALUPA19) &&
			    (strncmp(nodename, FT_NAME, FT_NAME_LEN) == 0) &&
			    (peerh != 0)) {
				/*
				 * On Netra-440 platforms, a fan tray
				 * may contain 2 fans (F0 and F1) but
				 * we only receive a single notification
				 * for removal of F0.  If F1 is present,
				 * peerh will be valid and we need to
				 * process it as well.
				 */
				remove_fru_parents(peerh);
				err = ptree_delete_node(peerh);
				if (err == PICL_SUCCESS) {
					(void) ptree_destroy_node(peerh);
				} else {
					syslog(LOG_ERR, DELETE_PROP_FAIL, err);
				}
			}
		}
	}

	free(ename);
	nvlist_free(earg);
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

static void
add_ps_to_platform(char *unit)
{
	picl_nodehdl_t		parent_hdl;
	picl_nodehdl_t		child_hdl;
	ptree_propinfo_t	info;
	int			unit_size = 1 + strlen(unit);
	int			res;
	char			unit_addr[PICL_UNITADDR_LEN_MAX];

	switch (sys_platform) {
	case PLAT_SEATTLE1U:
	case PLAT_SEATTLE2U:
		res = ptree_get_node_by_path(SEATTLE_PSU_PLATFORM, &parent_hdl);
		break;
	case PLAT_BOSTON:
		res = ptree_get_node_by_path(BOSTON_PSU_PLATFORM, &parent_hdl);
		break;
	default:
		res = ptree_get_node_by_path(PSU_PLATFORM, &parent_hdl);
		break;
	}

	if (res != PICL_SUCCESS)
		return;
	/*
	 * seeprom nodes sit below this node,
	 * is there one with the supplied unit address?
	 */
	res = ptree_get_propval_by_name(parent_hdl, PICL_PROP_CHILD,
	    &child_hdl, sizeof (picl_nodehdl_t));

	while (res == PICL_SUCCESS) {
		res = ptree_get_propval_by_name(child_hdl, PICL_PROP_PEER,
		    &child_hdl, sizeof (picl_nodehdl_t));
		if ((res == PICL_SUCCESS) &&
		    ptree_get_propval_by_name(child_hdl,
		    PICL_PROP_UNIT_ADDRESS, unit_addr,
		    sizeof (unit_addr)) == PICL_SUCCESS) {
			unit_addr[sizeof (unit_addr) - 1] = '\0';
			if (strcmp(unit_addr, unit) == 0)
				return;	/* unit address exists already */
		}
	}

	/*
	 * found platform location for PS seeprom node, create it
	 */
	if (ptree_create_and_add_node(parent_hdl, PS_PLATFORM_NAME,
	    PICL_CLASS_SEEPROM, &child_hdl) != PICL_SUCCESS)
		return;
	if (ptree_init_propinfo(&info, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, unit_size,
	    PICL_PROP_UNIT_ADDRESS, NULL, NULL) != PICL_SUCCESS)
		return;
	(void) ptree_create_and_add_prop(child_hdl, &info, unit, NULL);
}

static void
get_fantray_path(char *ap_id, char *path, int bufsz)
{
	char	ft_id[FT_ID_BUFSZ];

	(void) strlcpy(ft_id, ap_id, FT_ID_BUFSZ);

	switch (sys_platform) {
	case PLAT_SEATTLE1U:
		if ((strncmp(ap_id, "FT0", 3) == 0) ||
		    (strncmp(ap_id, "FT1", 3) == 0) ||
		    (strncmp(ap_id, "FT2", 3) == 0)) {
			(void) snprintf(path, bufsz, SEATTLE_FCB0_1U, ft_id);
		} else if ((strncmp(ap_id, "FT3", 3) == 0) ||
		    (strncmp(ap_id, "FT4", 3) == 0) ||
		    (strncmp(ap_id, "FT5", 3) == 0)) {
			(void) snprintf(path, bufsz, SEATTLE_FCB1_1U, ft_id);
		} else {
			(void) snprintf(path, bufsz, SEATTLE_PDB_1U, ft_id);
		}
		break;

	case PLAT_SEATTLE2U:
		if ((strncmp(ap_id, "FT0", 3) == 0) ||
		    (strncmp(ap_id, "FT1", 3) == 0) ||
		    (strncmp(ap_id, "FT2", 3) == 0)) {
			(void) snprintf(path, bufsz, SEATTLE_FCB0_2U, ft_id);
		} else if ((strncmp(ap_id, "FT3", 3) == 0) ||
		    (strncmp(ap_id, "FT4", 3) == 0) ||
		    (strncmp(ap_id, "FT5", 3) == 0)) {
			(void) snprintf(path, bufsz, SEATTLE_FCB1_2U, ft_id);
		} else {
			(void) snprintf(path, bufsz, SEATTLE_PDB_2U, ft_id);
		}
		break;

	case PLAT_BOSTON:
		(void) snprintf(path, bufsz, SYS_BOARD_PATH, ft_id);
		break;

	default:
		(void) snprintf(path, bufsz, CHASSIS_LOC_PATH, ft_id);
		break;
	}
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
	int			err;
	int			index;
	picl_nodehdl_t		childh;
	char			*fru_name;
	boolean_t		rmc_flag = B_FALSE;

	if (strcmp(ename, PICLEVENT_DR_AP_STATE_CHANGE) != 0) {
		return;
	}

	if (nvlist_unpack((char *)earg, size, &nvlp, 0)) {
		return;
	}

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

	/*
	 * check ap_id really is a hot-plug device
	 */
	if (strncmp(ap_id, PS_NAME, PS_NAME_LEN) == 0) {
		fru_name = PS_FRU_NAME;
	} else if (strncmp(ap_id, DISK_NAME, DISK_NAME_LEN) == 0) {
		fru_name = DISK_FRU_NAME;
	} else if (strncmp(ap_id, SCC_NAME, SCC_NAME_LEN) == 0) {
		fru_name = SCC_FRU_NAME;
	} else if (strncmp(ap_id, RMC_NAME, RMC_NAME_LEN) == 0) {
		fru_name = RMC_FRU_NAME;
		rmc_flag = B_TRUE;
	} else if (strncmp(ap_id, FT_NAME, FT_NAME_LEN) == 0) {
		fru_name = FT_FRU_NAME;
	} else {
		nvlist_free(nvlp);
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_HINT, &hint)) {
		nvlist_free(nvlp);
		return;
	}

	/*
	 * OK - so this is an EC_DR event - let's handle it.
	 */
	if (rmc_flag && (sys_platform != PLAT_CHALUPA) &&
	    (sys_platform != PLAT_CHALUPA19))
		sprintf_buf2(path, SYS_BOARD_PATH, ap_id);
	else {
		if ((sys_platform == PLAT_CHALUPA19) &&
		    (strncmp(ap_id, PS_NAME, PS_NAME_LEN) == 0)) {
			sprintf_buf2(path, CHASSIS_LOC_PATH,
			    ps_apid_to_nodename(ap_id));
		} else	if (strncmp(ap_id, DISK_NAME, DISK_NAME_LEN) == 0) {
			switch (sys_platform)	{
			case PLAT_SEATTLE1U:
				sprintf_buf2(path, SEATTLE1U_HDDBP_PATH, ap_id);
				break;
			case PLAT_SEATTLE2U:
				sprintf_buf2(path, SEATTLE2U_HDDBP_PATH, ap_id);
				break;
			case PLAT_BOSTON:
				sprintf_buf2(path, BOSTON_HDDBP_PATH, ap_id);
				break;
			default:
				sprintf_buf2(path, CHASSIS_LOC_PATH, ap_id);
				break;
			}
		} else if (strncmp(ap_id, FT_NAME, FT_NAME_LEN) == 0) {
			get_fantray_path(ap_id, path, MAXPATHLEN);
		} else	{
			sprintf_buf2(path, CHASSIS_LOC_PATH, ap_id);
		}
	}

	if (ptree_get_node_by_path(path, &locnodeh) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	/*
	 * now either add or delete the fru node as appropriate. If no
	 * hint, treat as insert and update the tree if necessary.
	 */
	if (strcmp(hint, DR_HINT_REMOVE) == 0) {
		if (ptree_get_propval_by_name(locnodeh, PICL_PROP_CHILD,
		    &fruh, sizeof (picl_nodehdl_t)) == PICL_SUCCESS) {
			/*
			 * fru was there - but has gone away
			 */
			post_frudr_event(PICL_FRU_REMOVED, 0, fruh);
		}
	} else if (rmc_flag) {
		/*
		 * An event on the RMC location, just pass it on
		 * it's not really a PICL_FRU_ADDED event, so offer
		 * the child handle as well (if it exists).
		 */
		if (ptree_get_propval_by_name(locnodeh, PICL_PROP_CHILD,
		    &fruh, sizeof (picl_nodehdl_t)) != PICL_SUCCESS) {
			fruh = 0;
		}
		post_frudr_event(PICL_FRU_ADDED, locnodeh, fruh);
	} else {
		/*
		 * fru has been inserted (or may need to update)
		 * if node already there, then just return
		 */
		childh = find_child_by_name(locnodeh, fru_name);
		if (childh != 0) {
			nvlist_free(nvlp);
			return;
		}

		/*
		 * On Netra-440, the fan-tray location nodes are
		 * not deleted when fan-trays are physically
		 * removed, so we do not need to create another
		 * fru node.
		 */
		if ((sys_platform != PLAT_CHALUPA19) ||
		    (strncmp(fru_name, FT_FRU_NAME, FT_FRU_NAME_LEN) != 0)) {
			/*
			 * create requested fru node
			 */
			err = ptree_create_and_add_node(locnodeh, fru_name,
			    PICL_CLASS_FRU, &childh);
			if (err != PICL_SUCCESS) {
				syslog(LOG_ERR, ADD_NODE_FAIL, ap_id, err);
				nvlist_free(nvlp);
				return;
			}
		}

		/*
		 * power supplies have operational status and fruid -
		 * add OperationalStatus property and create i2c device node
		 * before posting fru_added event
		 */
		if (strncmp(ap_id, PS_NAME, PS_NAME_LEN) == 0) {
			index = find_vol_prop_by_name(
			    ps_apid_to_nodename(ap_id));
			if (index >= 0)
				add_op_status_to_node(childh,
				    &idprop->idp[index].volprop);
			(void) create_i2c_node(ap_id);
			add_ps_to_platform(ps_name_to_unitaddr(ap_id));
		}

		/*
		 * now post event
		 */
		post_frudr_event(PICL_FRU_ADDED, locnodeh, 0);
	}
	nvlist_free(nvlp);
}

/*
 * Handle PICL_FRU_ADDED events.
 * These events are posted by the frudr_evhandler of this plugin in response to
 * PICLEVENT_DR_AP_STATE_CHANGE events. The sequence is as follows:
 *	1) frudr_evhandler catches PICLEVENT_DR_AP_STATE_CHANGE and creates a
 *	child node below the relevant location.
 *	2) frudr_evhandler posts a PICL_FRU_ADDED event.
 *	3) envmon catches PICL_FRU_ADDED event, gropes the RMC configuration
 *	and creates platform tree nodes (primarily for PSUs). (If the event
 *	is for the RMC itself, envmon deletes existing platform nodes and
 *	rebuilds from scratch.)
 *	4) this plugin catches PICL_FRU_ADDED event, looks for a related
 *	configuration file and parses it. This adds Fru data properties (etc.).
 *	5) frudata catches the event and updates its FRUID data cache.
 */
/*ARGSUSED*/
static void
fru_add_handler(const char *ename, const void *earg, size_t size, void *cookie)
{
	int			retval;
	picl_nodehdl_t		locnodeh;
	picl_nodehdl_t		rooth;
	char			path[MAXPATHLEN];
	char			*fru_name;

	if (strcmp(ename, PICL_FRU_ADDED) != 0)
		return;

	retval = nvlist_lookup_uint64((nvlist_t *)earg,
	    PICLEVENTARG_PARENTHANDLE, &locnodeh);
	if (retval != PICL_SUCCESS)
		return;

	retval = ptree_get_propval_by_name(locnodeh, PICL_PROP_NAME,
	    path, sizeof (path));
	if (retval != PICL_SUCCESS)
		return;

	fru_name = strdup(path);
	if (fru_name == NULL)
		return;

	/*
	 * We're about to parse a fru-specific .conf file to populate
	 * picl nodes relating to the dynamically added component. In the
	 * case of the RMC, there is a problem: all of its /platform tree
	 * nodes have just been replaced by envmon. It is now necessary to
	 * repopulate Devices tables in /frutree.
	 * picld_pluginutil_parse_config_file doesn't handle repopulating
	 * existing tables, so as a work round, delete all tables found
	 * under /frutree. This works on Enchilada Server as the tables
	 * are all created from parsing a .conf file, and we're about to
	 * redo that action.
	 */
	if (strcmp(fru_name, RMC_NAME) == 0) {
		rmc_state_event();
		retval = ptree_get_node_by_path(FRUTREE_PATH, &rooth);
		if (retval == PICL_SUCCESS) {
			remove_tables(rooth);
		}
	}

	/*
	 * Re-establish the HPU(FRU) volatile properties.
	 * This needs to be done before the .conf file is parsed because
	 * it has a side effect of re-creating any missing power-supply
	 * fru node. The .conf file can then hang properties beneath.
	 */
	opst_init();

	/*
	 * see if there's a .conf file for this fru
	 */
	if (get_config_file(path, fru_name) == 0) {
		if ((ptree_get_root(&rooth) != PICL_SUCCESS) ||
		    (picld_pluginutil_parse_config_file(rooth, path) !=
		    PICL_SUCCESS)) {
			syslog(LOG_ERR, PARSE_CONF_FAIL, path);
		}
	}

	free(fru_name);
}

/*
 * Handle PICLEVENT_SYSEVENT_DEVICE_ADDED events.
 */
/*ARGSUSED*/
static void
frutree_evhandler(const char *ename, const void *earg, size_t size,
    void *cookie)
{
	nvlist_t		*nvlp;
	picl_nodehdl_t		rooth;
	char			path[MAXPATHLEN];
	char			*fru_name;
	char			*dtype;
	char			*dpath;
	char			*ptr;
	char			*ptr2;
	int			done = B_FALSE;
	int			i;

	if (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_ADDED) != 0)
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

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_DEVFS_PATH, &dpath)) {
		nvlist_free(nvlp);
		return;
	}

	fru_name = strdup(dpath);
	if (fru_name == NULL) {
		nvlist_free(nvlp);
		return;
	}

	nvlist_free(nvlp);

	/*
	 * fru_name is of the form
	 *	"/pci@1e,600000/usb@a/mouse@2"
	 * or
	 *	"/pci@1e,600000/usb@a/device@2/mouse@0"
	 * reduce it to "usb-a-2"
	 */
	if ((sys_platform == PLAT_SEATTLE1U) ||
	    (sys_platform == PLAT_SEATTLE2U) ||
	    (sys_platform == PLAT_BOSTON)) {
		for (i = 0; i < MAX_USB_PORTS; i++) {
			sprintf(fru_name, "%s%d", USB_CONF_FILE_NAME, i+1);
			if (get_config_file(path, fru_name) == 0) {
				if ((ptree_get_root(&rooth) != PICL_SUCCESS) ||
				    (picld_pluginutil_parse_config_file(rooth,
				    path) != PICL_SUCCESS)) {
					syslog(LOG_ERR, PARSE_CONF_FAIL, path);
				}
			}
		}
	} else {
		ptr = fru_name;
		if (*ptr == '/') {
			ptr++;
			ptr = strchr(ptr, '/');
			if (ptr != NULL) {
				ptr++;
				(void) memmove(fru_name, ptr, strlen(ptr) + 1);
				ptr = strchr(fru_name, '@');
				if (ptr != NULL) {
					*ptr = '-';
					ptr++;
					ptr = strchr(ptr, '/');
					if (ptr != NULL) {
						*ptr = '-';
						ptr++;
						ptr2 = ptr;
						ptr = strchr(ptr, '@');
						if (ptr != NULL) {
							ptr++;
							(void) memmove(ptr2,
							    ptr, strlen(ptr)+1);
							ptr2 = strchr(ptr2,
							    '/');
							if (ptr2 != NULL) {
								*ptr2 = '\0';
							}
							done = B_TRUE;
						}
					}
				}
			}
		}
		if (done == B_FALSE) {
			free(fru_name);
			return;
		}

		/*
		 * see if there's a .conf file for this fru
		 */

		if (get_config_file(path, fru_name) == 0) {
			if ((ptree_get_root(&rooth) != PICL_SUCCESS) ||
			    (picld_pluginutil_parse_config_file(rooth, path) !=
			    PICL_SUCCESS)) {
				syslog(LOG_ERR, PARSE_CONF_FAIL, path);
			}
		}
	}

	free(fru_name);
}

static int
set_led(char *name, char *ptr, char *value)
{
	char			path[MAXPATHLEN];
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		tableh;
	picl_nodehdl_t		locnodeh;
	picl_nodehdl_t		nodeh;
	picl_prophdl_t		tblh;
	int			retval;
	char			*value_ptr;
	char			label[PICL_PROPNAMELEN_MAX];
	char			class[PICL_PROPNAMELEN_MAX];

	/* find the location node */
	switch (sys_platform)	{
	case PLAT_CHALUPA:
	case PLAT_CHALUPA19:
		sprintf_buf2(path, CHASSIS_LOC_PATH, name);
		break;
	case PLAT_SEATTLE1U:
		sprintf_buf2(path, SEATTLE1U_HDDBP_PATH, name);
		break;
	case PLAT_SEATTLE2U:
		sprintf_buf2(path, SEATTLE2U_HDDBP_PATH, name);
		break;
	case PLAT_BOSTON:
		sprintf_buf2(path, BOSTON_HDDBP_PATH, name);
		break;
	default:
		sprintf_buf2(path, CHASSIS_LOC_PATH, name);
		break;
	}

	if (ptree_get_node_by_path(path, &locnodeh) != PICL_SUCCESS)	{
		return (PICL_FAILURE);
	}

	/*
	 * if no fru node, then turn led off
	 */
	if (find_child_by_name(locnodeh, DISK_FRU_NAME) != 0)
		value_ptr = value;
	else
		value_ptr = PICL_PROPVAL_OFF;

	/* get its Devices table */
	if (ptree_get_prop_by_name(locnodeh, PICL_PROP_DEVICES, &tableh) !=
	    PICL_SUCCESS)
		return (PICL_FAILURE);
	if (ptree_get_propval(tableh, &tblh, sizeof (tblh)) != PICL_SUCCESS)
		return (PICL_FAILURE);

	/* get first col, first row */
	if (ptree_get_next_by_col(tblh, &tblh) != PICL_SUCCESS)
		return (PICL_FAILURE);

	/*
	 * starting at next col, get every entry in the column
	 */
	for (retval = ptree_get_next_by_row(tblh, &tblh);
	    retval == PICL_SUCCESS;
	    retval = ptree_get_next_by_col(tblh, &tblh)) {
		/*
		 * get the target node handle
		 */
		if (ptree_get_propval(tblh, &nodeh, sizeof (nodeh))
		    != PICL_SUCCESS)
			continue;

		/*
		 * check it's a led
		 */
		if (ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		    class, sizeof (class)) != PICL_SUCCESS)
			continue;
		if (strcmp(class, "led") != 0)
			continue;

		/*
		 * check its the right led
		 */
		if (ptree_get_propval_by_name(nodeh, PICL_PROP_LABEL,
		    label, sizeof (label)) != PICL_SUCCESS)
			continue;
		if (strcmp(label, ptr) == 0) {
			/*
			 * set it
			 */
			if (ptree_get_prop_by_name(nodeh, PICL_PROP_STATE,
			    &proph) != PICL_SUCCESS)
				continue;
			if (ptree_get_propinfo(proph, &propinfo) !=
			    PICL_SUCCESS)
				continue;
			retval =  ptree_update_propval_by_name(nodeh,
			    PICL_PROP_STATE, value_ptr, propinfo.piclinfo.size);
			return (retval);
		}
	}
	return (PICL_FAILURE);
}

/*
 * function to find first node of specified class beneath supplied node
 */
static int
get_node_by_class(picl_nodehdl_t nodeh, const char *classname,
    picl_nodehdl_t *foundnodeh)
{
	int		err;
	char		clname[PICL_CLASSNAMELEN_MAX+1];
	picl_nodehdl_t	childh;

	/*
	 * go through the children
	 */
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD, &childh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		err = ptree_get_propval_by_name(childh, PICL_PROP_CLASSNAME,
		    clname, sizeof (clname));

		if ((err == PICL_SUCCESS) && (strcmp(clname, classname) == 0)) {
			*foundnodeh = childh;
			return (PICL_SUCCESS);
		}

		err = get_node_by_class(childh, classname, foundnodeh);
		if (err == PICL_SUCCESS)
			return (PICL_SUCCESS);

		err = ptree_get_propval_by_name(childh, PICL_PROP_PEER,
		    &childh, sizeof (picl_nodehdl_t));
	}

	return (PICL_NODENOTFOUND);
}

/*
 * get system-controller node
 */
static int
get_sys_controller_node(picl_nodehdl_t *nodeh)
{
	int		err;

	/* get platform node */
	err = ptree_get_node_by_path(PICL_NODE_ROOT PICL_NODE_PLATFORM, nodeh);
	if (err != PICL_SUCCESS)
		return (err);
	err = get_node_by_class(*nodeh, PICL_CLASS_SERVICE_PROCESSOR, nodeh);
	return (err);
}

/*
 * create pathname string for system-controller device
 */
static char *
create_sys_controller_pathname(picl_nodehdl_t sysconh)
{
	char		*ptr;
	char		namebuf[PATH_MAX];
	size_t		len;
	DIR		*dirp;
	struct dirent	*dp;
	struct stat	statbuf;

	/*
	 * prefix devfs-path name with /devices
	 */
	(void) strlcpy(namebuf, DEV_PREFIX, PATH_MAX);

	/*
	 * append devfs-path property
	 */
	len = strlen(namebuf);
	if (ptree_get_propval_by_name(sysconh, str_devfs_path, namebuf + len,
	    sizeof (namebuf) - len) != PICL_SUCCESS) {
		return (NULL);
	}

	/*
	 * locate final component of name
	 */
	ptr = strrchr(namebuf, '/');
	if (ptr == NULL)
		return (NULL);
	*ptr = '\0';		/* terminate at end of directory path */
	len = strlen(ptr + 1);	/* length of terminal name */
	dirp = opendir(namebuf);
	if (dirp == NULL) {
		return (NULL);
	}
	*ptr++ = '/';		/* restore '/' and advance to final name */

	while ((dp = readdir(dirp)) != NULL) {
		/*
		 * look for a name which starts with the string at *ptr
		 */
		if (strlen(dp->d_name) < len)
			continue;	/* skip short names */
		if (strncmp(dp->d_name, ptr, len) == 0) {
			/*
			 * Got a match, restore full pathname and stat the
			 * entry. Reject if not a char device
			 */
			(void) strlcpy(ptr, dp->d_name,
			    sizeof (namebuf) - (ptr - namebuf));
			if (stat(namebuf, &statbuf) < 0)
				continue;	/* reject if can't stat it */
			if (!S_ISCHR(statbuf.st_mode))
				continue;	/* not a character device */
			/*
			 * go with this entry
			 */
			(void) closedir(dirp);
			return (strdup(namebuf));
		}
	}
	(void) closedir(dirp);
	return (NULL);
}

/*
 * create pathname string for bezel leds device
 */
static char *
create_bezel_leds_pathname(const char *dirpath, const char *devname)
{
	char		namebuf[PATH_MAX];
	size_t		lendirpath;
	size_t		len;
	DIR		*dirp;
	struct dirent	*dp;
	struct stat	statbuf;

	/*
	 * start with directory name
	 */
	(void) strlcpy(namebuf, dirpath, PATH_MAX);

	/*
	 * append devfs-path property
	 */
	lendirpath = strlen(namebuf);
	dirp = opendir(namebuf);
	if (dirp == NULL) {
		return (NULL);
	}

	len = strlen(devname);

	while ((dp = readdir(dirp)) != NULL) {
		/*
		 * look for a name which starts with the gpio string
		 */
		if (strlen(dp->d_name) < len)
			continue;	/* skip short names */
		if (strncmp(dp->d_name, devname, len) == 0) {
			/*
			 * Got a match, restore full pathname and stat the
			 * entry. Reject if not a char device
			 */
			(void) strlcpy(namebuf + lendirpath, dp->d_name,
			    sizeof (namebuf) - lendirpath);
			if (stat(namebuf, &statbuf) < 0)
				continue;	/* reject if can't stat it */
			if (!S_ISCHR(statbuf.st_mode))
				continue;	/* not a character device */
			/*
			 * go with this entry
			 */
			(void) closedir(dirp);
			return (strdup(namebuf));
		}
	}
	(void) closedir(dirp);
	return (NULL);
}

/*
 * initialise structure associated with nodes requiring OperationalStatus
 */
static void
opst_init(void)
{
	int			res;
	int			index = 0;
	int			fd;
	int			entries = 0;
	int			err = 0;
	boolean_t		rmc_flag;
	boolean_t		ps_flag;
	boolean_t		disk_flag;
	size_t			len;
	envmon_sysinfo_t	sysinfo;
	envmon_hpu_t		hpu;

	if (idprop != NULL) {
		/*
		 * This must be a restart, clean up earlier allocation
		 */
		free(idprop);
		idprop = NULL;
	}

	if (sc_device_name == NULL)
		err = 1;
	else {
		fd = open(sc_device_name, O_RDONLY);

		if (fd < 0) {
			syslog(LOG_ERR, EM_NO_SC_DEV);
			err = 1;
		}
	}

	if (err == 0) {
		res = ioctl(fd, ENVMONIOCSYSINFO, &sysinfo);

		if (res < 0) {
			syslog(LOG_ERR, EM_NO_SYSINFO, strerror(errno));
			(void) close(fd);
			err = 1;
		}
	}

	if (err == 0) {
		entries = sysinfo.maxHPU;
		len = offsetof(idp_lkup_t, idp) + entries * sizeof (id_props_t);
		idprop = calloc(len, 1);
		if (idprop == NULL) {
			(void) close(fd);
			err = 1;
		}
	}

	if (err == 0) {
		idprop->maxnum = entries;
		hpu.id.name[0] = '\0';	/* request for first name */
		res = ioctl(fd, ENVMONIOCHPU, &hpu);

		/*
		 * The HPU node for the RMC is a special case. Its handle is
		 * generated by the rmclomv driver. Rather than building
		 * knowledge of its frutree hierarchic name into the driver, we
		 * put that knowledge here.
		 */
		while ((res == 0) && (index < entries) &&
		    (hpu.next_id.name[0] != '\0')) {
			hpu.id = hpu.next_id;
			res = ioctl(fd, ENVMONIOCHPU, &hpu);
			if ((res == 0) &&
			    ((hpu.sensor_status & ENVMON_NOT_PRESENT) == 0)) {
				add_op_status(&hpu, &index);
			}
		}

		idprop->num = index;
		(void) close(fd);
	}
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

	/*
	 * Initialise to -1 so the led thread will set correctly.
	 * Do this before creating the disk_leds thread,
	 * so there's no race.
	 */
	for (i = 0; i < N_DISKS; i++)
		disk_ready[i] = -1;

	if (ledsthr_created) {
		/*
		 * this is a restart, wake up sleeping threads
		 */
		err = pthread_mutex_lock(&g_mutex);
		if (err != 0) {
			syslog(LOG_ERR, EM_MUTEX_FAIL, strerror(errno));
			return;
		}
		g_finish_now = B_FALSE;
		(void) pthread_cond_broadcast(&g_cv);
		(void) pthread_mutex_unlock(&g_mutex);
	} else {
		if ((pthread_attr_init(&ledsthr_attr) != 0) ||
		    (pthread_attr_setscope(&ledsthr_attr,
		    PTHREAD_SCOPE_SYSTEM) != 0))
			return;
		if ((err = pthread_create(&ledsthr_tid, &ledsthr_attr,
		    disk_leds_thread, NULL)) != 0) {
			syslog(LOG_ERR, EM_THREAD_CREATE_FAILED,
			    strerror(errno));
			return;
		}
		ledsthr_created = B_TRUE;
	}
}

static void
disk_leds_fini(void)
{
	int	err, i;

	/*
	 * turn the leds off as we'll no longer be monitoring them
	 */
	for (i = 0; i < N_DISKS; i++)
		(void) set_led(disk_name[i], REMOK_LED, PICL_PROPVAL_OFF);

	/*
	 * disk_leds_thread() never started or an error occured so
	 * that it's not running
	 */
	if (!disk_leds_thread_running)
		return;

	/*
	 * tell led thread to pause
	 */
	if (!ledsthr_created)
		return;
	err = pthread_mutex_lock(&g_mutex);
	if (err != 0) {
		syslog(LOG_ERR, EM_MUTEX_FAIL, strerror(errno));
		return;
	}
	g_finish_now = B_TRUE;
	disk_leds_thread_ack = B_FALSE;
	(void) pthread_cond_broadcast(&g_cv);

	/*
	 * and wait for them to acknowledge
	 */
	while (!disk_leds_thread_ack) {
		(void) pthread_cond_wait(&g_cv_ack, &g_mutex);
	}
	(void) pthread_mutex_unlock(&g_mutex);
}

static void
update_disk_node(char *fruname, char *devpath)
{
	picl_nodehdl_t slotndh;
	picl_nodehdl_t diskndh;
	picl_nodehdl_t devhdl;
	picl_prophdl_t tblhdl;
	picl_prophdl_t tblhdl2;
	picl_prophdl_t tblproph;
	int err;
	char path[MAXPATHLEN];

	switch (sys_platform)	{
	case PLAT_CHALUPA:
	case PLAT_CHALUPA19:
		sprintf_buf2(path, CHASSIS_LOC_PATH, fruname);
		break;
	case PLAT_SEATTLE1U:
		sprintf_buf2(path, SEATTLE1U_HDDBP_PATH, fruname);
		break;
	case PLAT_SEATTLE2U:
		sprintf_buf2(path, SEATTLE2U_HDDBP_PATH, fruname);
		break;
	case PLAT_BOSTON:
		sprintf_buf2(path, BOSTON_HDDBP_PATH, fruname);
		break;
	default:
		sprintf_buf2(path, CHASSIS_LOC_PATH, fruname);
		break;
	}

	if (ptree_get_node_by_path(path, &slotndh) != PICL_SUCCESS) {
		return;
	}
	diskndh = find_child_by_name(slotndh, DISK_FRU_NAME);
	if (diskndh == 0) {
		return;
	}
	err = ptree_get_node_by_path(devpath, &devhdl);
	if (err == PICL_SUCCESS) {
		err = ptree_get_propval_by_name(diskndh,
		    PICL_PROP_DEVICES, &tblhdl, sizeof (tblhdl));
		if (err != PICL_SUCCESS)
			return;
		err = ptree_get_next_by_col(tblhdl, &tblhdl2);
		if (err != PICL_SUCCESS) {
			err = create_table_entry(tblhdl, devhdl,
			    PICL_CLASS_BLOCK);
			if (err != PICL_SUCCESS)
				return;
			err = add_prop_ref(devhdl, diskndh,
			    PICL_REFPROP_FRU_PARENT);
			if (err != PICL_SUCCESS)
				return;
		}
	} else {
		/*
		 * no mechanism for deleting row - so delete
		 * whole table and start again
		 */
		err = ptree_get_prop_by_name(diskndh, PICL_PROP_DEVICES,
		    &tblproph);
		if (err != PICL_SUCCESS)
			return;
		err = ptree_delete_prop(tblproph);
		if (err != PICL_SUCCESS)
			return;
		(void) ptree_destroy_prop(tblproph);
		err = create_table(diskndh, &tblhdl, PICL_PROP_DEVICES);
		if (err != PICL_SUCCESS)
			return;
	}
}

/*
 * We will light the OK2REMOVE LED for disks configured
 * into a raid if (and only if) the driver reports
 * that the disk has failed.
 */
static int
raid_ok2rem_policy(raid_config_t config, int target)
{
	int i;

	for (i = 0; i < config.ndisks; i++) {
		int d = config.disk[i];
		int dstatus = config.diskstatus[i];

		if (d  == target)	{
			switch (dstatus) {
			case RAID_DISKSTATUS_MISSING:
				/* If LED is on, turn it off */
				if (disk_ready[d] == B_FALSE) {
					if (set_led(disk_name[d], REMOK_LED,
					    PICL_PROPVAL_OFF) == PICL_SUCCESS) {
						disk_ready[d] = B_TRUE;
					}
				}
			break;
			case RAID_DISKSTATUS_GOOD:
				if (disk_ready[d] != B_TRUE) {
					if (set_led(disk_name[d], REMOK_LED,
					    PICL_PROPVAL_OFF) == PICL_SUCCESS) {
						disk_ready[d] = B_TRUE;
					}
				}
			break;
			case RAID_DISKSTATUS_FAILED:
				if (disk_ready[d] != B_FALSE) {
					if (set_led(disk_name[d], REMOK_LED,
					    PICL_PROPVAL_ON) == PICL_SUCCESS) {
						disk_ready[d] = B_FALSE;
					}
				}
			break;
			default:
			break;
			}
			return (1);
		}
	}
	return (0);
}

static int
check_raid(int target)
{
	raid_config_t	config;
	int	fd;
	int	numvols;
	int	i, j;

	switch (sys_platform) {
	case PLAT_CHALUPA:
	case PLAT_CHALUPA19:
		fd = open(V440_DISK_DEVCTL, O_RDONLY);
		break;
	case PLAT_SEATTLE1U:
	case PLAT_SEATTLE2U:
		fd = open(SEATTLE_DISK_DEVCTL, O_RDONLY);
		break;
	case PLAT_BOSTON:
		if (boston_1068e_flag) {
			fd = open(BOSTON_DISK_DEVCTL_1068E, O_RDONLY);
		} else {
			fd = open(BOSTON_DISK_DEVCTL_1068X, O_RDONLY);
		}
		break;
	default:
		fd = -1;
		break;
	}

	if (fd == -1) {
		return (0);
	}

	if (ioctl(fd, RAID_NUMVOLUMES, &numvols)) {
		(void) close(fd);
		return (0);
	}

	for (i = 0; i < numvols; i++)	{
		config.unitid = i;
		if (ioctl(fd, RAID_GETCONFIG, &config)) {
			(void) close(fd);
			return (0);
		}
		if (raid_ok2rem_policy(config, target))	{
			(void) close(fd);
			return (1);
		}
	}

	(void) close(fd);
	return (0);
}

/*ARGSUSED*/
static void *
disk_leds_thread(void *args)
{
	int	c;
	int	i;
	char	**disk_dev;
	int fd;

	devctl_hdl_t dhdl;

	int	n_disks = 0, do_raid = 0, err = 0;
	uint_t	statep	= 0;

	static char *mpxu_devs[] = {
		"/pci@1c,600000/scsi@2/sd@0,0",
		"/pci@1c,600000/scsi@2/sd@1,0",
		"/pci@1c,600000/scsi@2/sd@2,0",
		"/pci@1c,600000/scsi@2/sd@3,0"
	};

	static char *ents_devs[] = {
		"/pci@1d,700000/scsi@4/sd@0,0",
		"/pci@1d,700000/scsi@4/sd@1,0",
		"/pci@1d,700000/scsi@4/sd@2,0",
		"/pci@1d,700000/scsi@4/sd@3,0",
		"/pci@1d,700000/scsi@4/sd@8,0",
		"/pci@1d,700000/scsi@4/sd@9,0",
		"/pci@1d,700000/scsi@4/sd@a,0",
		"/pci@1d,700000/scsi@4/sd@b,0"
	};

	static char *v440_devs[] = {
		"/pci@1f,700000/scsi@2/sd@0,0",
		"/pci@1f,700000/scsi@2/sd@1,0",
		"/pci@1f,700000/scsi@2/sd@2,0",
		"/pci@1f,700000/scsi@2/sd@3,0"
	};

	static char *n210_devs[] = {
		"/pci@1c,600000/LSILogic,sas@1/sd@0,0",
		"/pci@1c,600000/LSILogic,sas@1/sd@1,0"
	};

	static char *seattle_devs[] = {
		"/pci@1e,600000/pci@0/pci@a/pci@0/pci@8/scsi@1/sd@0,0",
		"/pci@1e,600000/pci@0/pci@a/pci@0/pci@8/scsi@1/sd@1,0",
		"/pci@1e,600000/pci@0/pci@a/pci@0/pci@8/scsi@1/sd@2,0",
		"/pci@1e,600000/pci@0/pci@a/pci@0/pci@8/scsi@1/sd@3,0"
	};

	static char *boston_devs_1068e[] = {
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@0,0",
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@1,0",
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@2,0",
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@3,0",
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@4,0",
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@5,0",
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@6,0",
		"/pci@1e,600000/pci@0/pci@2/scsi@0/sd@7,0"
	};
	static char *boston_devs_1068x[] = {
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@0,0",
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@1,0",
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@2,0",
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@3,0",
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@4,0",
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@5,0",
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@6,0",
		"/pci@1f,700000/pci@0/pci@2/pci@0/pci@8/LSILogic,sas@1/sd@7,0"
	};

	char	*ddev[N_DISKS];		/* "/devices"  */
	char	*pdev[N_DISKS];		/* "/platform" */

	switch (sys_platform) {

	case PLAT_ENTS:
		disk_dev = ents_devs;
		n_disks = N_ENTS_DISKS;
		break;

	case PLAT_CHALUPA:
	case PLAT_CHALUPA19:
		do_raid = 1;
		disk_dev = v440_devs;
		n_disks = N_CHALUPA_DISKS;
		break;

	case PLAT_SALSA19:
		disk_dev = n210_devs;
		n_disks = N_EN19_DISKS;
		break;

	case PLAT_SEATTLE1U:
	case PLAT_SEATTLE2U:
		do_raid = 1;
		disk_dev = seattle_devs;
		n_disks = (sys_platform == PLAT_SEATTLE1U) ?
		    N_SEATTLE1U_DISKS : N_SEATTLE2U_DISKS;
		break;

	case PLAT_BOSTON:
		/*
		 * If we can open the devctl path for the built-in 1068E
		 * controller then assume we're a 1068E-equipped Boston
		 * and make all the paths appropriate for that hardware.
		 * Otherwise assume we are a 1068X-equipped Boston and
		 * make all of the paths appropriate for a 1068X PCI-X
		 * controller in PCI slot 4.
		 *
		 * The flag is also used in the check_raid() function.
		 */
		if ((fd = open(BOSTON_DISK_DEVCTL_1068E, O_RDONLY)) != -1) {
			boston_1068e_flag = 1;
			disk_dev = boston_devs_1068e;
		} else {
			boston_1068e_flag = 0;
			disk_dev = boston_devs_1068x;
		}
		(void) close(fd);
		do_raid = 1;
		n_disks = N_BOSTON_DISKS;
		break;

	default: /* PLAT_ENXS/PLAT_EN19 */
		disk_dev = mpxu_devs;
		n_disks = (sys_platform == PLAT_EN19) ?
		    N_EN19_DISKS : N_MPXU_DISKS;
	}

	/*
	 * make up disk names
	 */

	for (i = 0; i < n_disks; i++) {
		char buffer[MAXPATHLEN];
		sprintf(buffer, "/devices%s", disk_dev[i]);
		ddev[i] = strdup(buffer);
		sprintf(buffer, "/platform%s", disk_dev[i]);
		pdev[i] = strdup(buffer);
	}

	disk_leds_thread_running = B_TRUE;

	for (;;) {
		for (i = 0; i < n_disks; i++) {
			/*
			 * If it's one of the RAID disks, we have already
			 * applied the ok2remove policy.
			 */
			if (do_raid && check_raid(i))	{
				continue;
			}

			dhdl = devctl_device_acquire(ddev[i], 0);
			devctl_device_getstate(dhdl, &statep);
			devctl_release(dhdl);

			if (statep & DEVICE_OFFLINE) {
				if (disk_ready[i] != B_FALSE) {
					update_disk_node(disk_name[i], pdev[i]);
					if (set_led(disk_name[i], REMOK_LED,
					    PICL_PROPVAL_ON) == PICL_SUCCESS)
						disk_ready[i] = B_FALSE;
				}
			} else if (statep & DEVICE_ONLINE) {
				if (disk_ready[i] != B_TRUE) {
					update_disk_node(disk_name[i], pdev[i]);
					if (set_led(disk_name[i], REMOK_LED,
					    PICL_PROPVAL_OFF) == PICL_SUCCESS)
						disk_ready[i] = B_TRUE;
				}
			}
		}

		/*
		 * wait a bit until we check again
		 */

		(void) poll(NULL, 0, DISK_POLL_TIME);

		/*
		 * are we to stop?
		 */

		(void) pthread_mutex_lock(&g_mutex);

		while (g_finish_now) {
			/*
			 * notify _fini routine that we've paused
			 */
			disk_leds_thread_ack = B_TRUE;
			(void) pthread_cond_signal(&g_cv_ack);

			/*
			 * and go to sleep in case we get restarted
			 */
			(void) pthread_cond_wait(&g_cv, &g_mutex);
		}
		(void) pthread_mutex_unlock(&g_mutex);
	}

	return ((void *)err);
}

/*
 * Given the powersupply name, convert to addr
 */
static int
ps_name_to_addr(char *name)
{
	int ps_addr = 0;
	if ((strcmp(name, PS0_NAME) == 0) ||
	    (strcmp(name, PSU0_NAME) == 0))	{
		switch (sys_platform) {
		case PLAT_SEATTLE1U:
		case PLAT_SEATTLE2U:
			ps_addr = SEATTLE_PS0_ADDR;
			break;
		case PLAT_BOSTON:
			ps_addr = BOSTON_PS0_ADDR;
			break;
		default:
			ps_addr = PS0_ADDR;
			break;
		}
	} else if ((strcmp(name, PS1_NAME) == 0) ||
	    (strcmp(name, PSU1_NAME) == 0))	{
		switch (sys_platform) {
		case PLAT_SEATTLE1U:
		case PLAT_SEATTLE2U:
			ps_addr = SEATTLE_PS1_ADDR;
			break;
		case PLAT_BOSTON:
			ps_addr = BOSTON_PS1_ADDR;
			break;
		default:
			ps_addr = PS1_ADDR;
			break;
		}
	} else if ((strcmp(name, PS2_NAME) == 0) ||
	    (strcmp(name, PSU2_NAME) == 0))	{
		switch (sys_platform) {
		case PLAT_BOSTON:
			ps_addr = BOSTON_PS2_ADDR;
			break;
		default:
			ps_addr = PS2_ADDR;
			break;
		}
	} else if ((strcmp(name, PS3_NAME) == 0) ||
	    (strcmp(name, PSU3_NAME) == 0))	{
		switch (sys_platform) {
		case PLAT_BOSTON:
			ps_addr = BOSTON_PS3_ADDR;
			break;
		default:
			ps_addr = PS3_ADDR;
			break;
		}
	}

	return (ps_addr);
}

/*
 * Given powersupply name, convert to unit addr
 */
static char *
ps_name_to_unitaddr(char *name)
{
	char *unitaddr;

	if (strcmp(name, PS0_NAME) == 0)	{
		switch (sys_platform) {
		case PLAT_SEATTLE1U:
		case PLAT_SEATTLE2U:
			unitaddr = SEATTLE_PS0_UNITADDR;
			break;
		case PLAT_BOSTON:
			unitaddr = BOSTON_PS0_UNITADDR;
			break;
		default:
			unitaddr = PS0_UNITADDR;
			break;
		}
	} else if (strcmp(name, PS1_NAME) == 0)	{
		switch (sys_platform) {
		case PLAT_SEATTLE1U:
		case PLAT_SEATTLE2U:
			unitaddr = SEATTLE_PS1_UNITADDR;
			break;
		case PLAT_BOSTON:
			unitaddr = BOSTON_PS1_UNITADDR;
			break;
		default:
			unitaddr = PS1_UNITADDR;
			break;
		}
	} else if (strcmp(name, PS2_NAME) == 0)	{
		switch (sys_platform) {
		case PLAT_BOSTON:
			unitaddr = BOSTON_PS2_UNITADDR;
			break;
		default:
			unitaddr = PS2_UNITADDR;
			break;
		}
	} else if (strcmp(name, PS3_NAME) == 0)	{
		switch (sys_platform) {
		case PLAT_BOSTON:
			unitaddr = BOSTON_PS3_UNITADDR;
			break;
		default:
			unitaddr = PS3_UNITADDR;
			break;
		}
	}
	else
		unitaddr = NULL;

	return (unitaddr);
}

/*
 * converts apid to real FRU name in PICL tree. The
 * name of powersupply devices on chalupa19 are
 * PSU instead of PS
 */
static char *
ps_apid_to_nodename(char *apid)
{
	char *nodename;

	if (sys_platform != PLAT_CHALUPA19)
		return (apid);

	if (strcmp(apid, PS0_NAME) == 0)
		nodename = PSU0_NAME;
	else if (strcmp(apid, PS1_NAME) == 0)
		nodename = PSU1_NAME;
	else if (strcmp(apid, PS2_NAME) == 0)
		nodename = PSU2_NAME;
	else if (strcmp(apid, PS3_NAME) == 0)
		nodename = PSU3_NAME;
	else
		nodename = apid;

	return (nodename);
}

/*
 * Create SEEPROM node at insertion time.
 */
static int
create_i2c_node(char *ap_id)
{
	int	nd_reg[2];
	devctl_ddef_t	ddef_hdl;
	devctl_hdl_t	bus_hdl;
	devctl_hdl_t	dev_hdl;
	char		dev_path[MAXPATHLEN];
	char		*compatible;

	/* create seeprom node */
	nd_reg[0] = 0;
	nd_reg[1] = ps_name_to_addr(ap_id);

	switch (sys_platform) {
	case PLAT_SEATTLE1U:
	case PLAT_SEATTLE2U:
		bus_hdl = devctl_bus_acquire(SEATTLE_PSU_I2C_BUS_DEV, 0);
		compatible = SEATTLE_PSU_COMPATIBLE;
		break;
	case PLAT_BOSTON:
		bus_hdl = devctl_bus_acquire(BOSTON_PSU_I2C_BUS_DEV, 0);
		compatible = BOSTON_PSU_COMPATIBLE;
		break;
	default:
		bus_hdl = devctl_bus_acquire(PSU_I2C_BUS_DEV, 0);
		compatible = PSU_COMPATIBLE;
		break;
	}

	if (bus_hdl == NULL)
		return (DDI_FAILURE);

	/* device definition properties */
	ddef_hdl = devctl_ddef_alloc(PS_DEVICE_NAME, 0);
	(void) devctl_ddef_string(ddef_hdl, "compatible", compatible);
	(void) devctl_ddef_string(ddef_hdl, "device_type", "seeprom");
	(void) devctl_ddef_int_array(ddef_hdl, "reg", 2, nd_reg);

	/* create the device node */
	if (devctl_bus_dev_create(bus_hdl, ddef_hdl, 0, &dev_hdl))
		return (DDI_FAILURE);

	if (devctl_get_pathname(dev_hdl, dev_path, MAXPATHLEN) == NULL)
		return (DDI_FAILURE);

	devctl_release(dev_hdl);
	devctl_ddef_free(ddef_hdl);
	devctl_release(bus_hdl);
	return (DDI_SUCCESS);
}

/*
 * Delete SEEPROM node at insertion time.
 */
static void
delete_i2c_node(char *ap_id)
{
	devctl_hdl_t	dev_hdl;
	char	buf[MAXPATHLEN];

	switch (sys_platform) {
	case PLAT_SEATTLE1U:
	case PLAT_SEATTLE2U:
		sprintf_buf2(buf, SEATTLE_PSU_DEV, ps_name_to_addr(ap_id));
		break;
	case PLAT_BOSTON:
		sprintf_buf2(buf, BOSTON_PSU_DEV, ps_name_to_addr(ap_id));
		break;
	default:
		sprintf_buf2(buf, PSU_DEV, ps_name_to_addr(ap_id));
		break;
	}

	dev_hdl = devctl_device_acquire(buf, 0);
	if (dev_hdl == NULL) {
		return;
	}

	/*
	 * If the seeprom driver is not loaded, calls to
	 * devctl_device_remove fails for seeprom devices
	 */
	if (devctl_device_remove(dev_hdl)) {
		di_init_driver(SEEPROM_DRIVER_NAME, 0);
		devctl_device_remove(dev_hdl);
	}
	devctl_release(dev_hdl);
}

static void
add_op_status(envmon_hpu_t *hpu, int *index)
{
	boolean_t		rmc_flag;
	boolean_t		ps_flag;
	boolean_t		disk_flag;
	char			node_name[MAXPATHLEN];
	boolean_t		flag;

	rmc_flag = (strcmp(hpu->id.name, RMC_NAME) == 0);
	ps_flag = (strncmp(hpu->id.name, PS_NAME,
	    PS_NAME_LEN) == 0);
	disk_flag = (strncmp(hpu->id.name, DISK_NAME,
	    DISK_NAME_LEN) == 0);
	if (rmc_flag || ps_flag) {
		idprop->idp[*index].envhandle = hpu->id;
		flag = rmc_flag && ((sys_platform != PLAT_CHALUPA) &&
		    (sys_platform != PLAT_CHALUPA19));
		sprintf_buf2(node_name,
		    flag ? SYS_BOARD_PATH : CHASSIS_LOC_PATH, ps_flag ?
		    ps_apid_to_nodename(hpu->id.name) : hpu->id.name);

		add_op_status_by_name(node_name, ps_flag ? PS_FRU_NAME : NULL,
		    &idprop->idp[(*index)++].volprop);
	} else if (disk_flag)	{
		idprop->idp[*index].envhandle = hpu->id;
		switch (sys_platform)	{
		case PLAT_CHALUPA:
		case PLAT_CHALUPA19:
			sprintf_buf2(node_name, CHASSIS_LOC_PATH, hpu->id.name);
			break;
		case PLAT_SEATTLE1U:
			sprintf_buf2(node_name, SEATTLE1U_HDDBP_PATH, \
			    hpu->id.name);
			break;
		case PLAT_SEATTLE2U:
			sprintf_buf2(node_name, SEATTLE2U_HDDBP_PATH, \
			    hpu->id.name);
			break;
		case PLAT_BOSTON:
			sprintf_buf2(node_name, BOSTON_HDDBP_PATH, \
			    hpu->id.name);
			break;
		default:
			sprintf_buf2(node_name, SYS_BOARD_PATH, hpu->id.name);
			break;
		}
		add_op_status_by_name(node_name, DISK_FRU_NAME,
		    &idprop->idp[(*index)++].volprop);
	}
}
