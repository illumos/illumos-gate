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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IPMI Plugin for the disk hotplug & fault monitor
 */

#include <sys/types.h>
#include <sys/byteorder.h>
#include <sys/stat.h>
#include <sys/stropts.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <ctype.h>
#include <limits.h>
#include <utility.h>
#include <libnvpair.h>
#include <sys/bmc_intf.h>
#include <libuutil.h>

#include "dm_plugin.h"
#include "util.h"
#include "ipmi_plugin.h"

#define	BMC_CHECK_UPTIME_INTERVAL	60	/* seconds */
#define	MESSAGE_BUFSIZE 1024
#define	BMC_DEV "/dev/bmc"

#define	STRUCT_MIN_SIZE(t, o) offsetof(t, o)
#define	TDZMALLOC(sz) ((sz *)dzmalloc(sizeof (sz)))
#define	TDMALLOC(sz) ((sz *)dmalloc(sizeof (sz)))

/* For the purposes of disk capacity, a <X>B is 1000x, not 1024x */
#define	ONE_KILOBYTE 1000.0
#define	ONE_MEGABYTE (ONE_KILOBYTE * 1000)
#define	ONE_GIGABYTE (ONE_MEGABYTE * 1000)
#define	ONE_TERABYTE (ONE_GIGABYTE * 1000)
#define	ONE_PETABYTE (ONE_TERABYTE * 1000)

/* IPMI Command Code definitions */
#define	IPMI_NETFN_OEM			0x2E
#define	IPMI_CMD_GET_UPTIME		0x08
#define	IPMI_CMD_FRU_UPDATE		0x16
#define	IPMI_CMD_GET_SENSOR_READING	0x2d
#define	IPMI_CMD_SET_SENSOR_READING	0x30
#define	IPMI_CMD_ADD_SEL_ENTRY		0x44

/* IPMI Request types supported by this plugin: */
#pragma pack(1)
struct ipmi_sensor_control {
	uint8_t		sensor_number;
	uint8_t		operation;	/* ASSERT_OP | DEASSERT_OP | Both */
#define	SC_ASSERT_OP	0x20
#define	SC_DEASSERT_OP	0x08
	uint8_t		sensor_reading;	/* UNUSED */
	/*
	 * The following two fields are stored and sent to the bmc in
	 * little-endian form
	 */
	uint16_t	assert_states;
	uint16_t	deassert_states;
#define	STATE_RESERVED_BITS ((uint16_t)0x8000)
};

/*
 * Virtual sensor format for FRU data (Sun OEM)
 */
struct ipmi_fru_update {
	uint8_t		global_id;
	uint8_t		disk_number;	/* Disk number 0-47 on the X4500 */
	uint8_t		data_length;
	char		d_manuf[16];
	char		d_model[28];
	char		d_serial[20];
	char		d_firmware[8];
	char		d_capacity[16];
};

struct ipmi_sel_entry {
	uint16_t	recid;		/* Don't care -- bmc will overwrite */
	uint8_t		type;		/* 0xc0 = OEM SEL Entry */
#define	SEL_TYPE_OEM	0xC0
	uint32_t	timestamp;	/* Don't care -- bmc will overwrite */
	uint8_t		manuf_id[3];
	uint8_t		oem_defined[6];
};

struct ipmi_sensor_reading {
	uint8_t		reading;

	uint8_t		reserved		: 5,
			data_unavailable	: 1,
			scanning_enabled	: 1,
			event_messages_enabled	: 1;

	uint8_t		states_0_7;
	uint8_t		states_8_14;	/* High bit is reserved */
#define	sensor_reading_optional_field_start	states_0_7
};

/*
 * The following structure's members is returned in BIG-ENDIAN form.
 */
struct bmc_uptime_info {
	uint32_t	uptime_seconds;
	uint32_t	incarnation;
};
#pragma pack()
/* End of request types supported */

typedef dm_plugin_error_t (*ipmi_packet_setup_fn_t)(nvlist_t *props,
    void **databpp, int *datablen, void *arg);

struct ipmi_cmd_setup {
	const char 		*name;
	ipmi_packet_setup_fn_t	setupfn;
	uint8_t			netfn;
	uint8_t			lun;
	uint8_t			cmd;
};

typedef struct ipmi_action_handle {
	uint8_t		netfn;
	uint8_t		lun;
	uint8_t		cmd;
	void		*databp;
	int		datablen;
} ipmi_action_handle_t;

typedef enum {
	CACHE_ENT_FIRST,
	CACHE_ENT_FRUINFO,
	CACHE_ENT_SENSORCTL,
	CACHE_ENT_LAST
} bmc_cache_ent_type_t;

typedef struct bmc_cache_ent {
	bmc_cache_ent_type_t		type;
	union {
		struct ipmi_fru_update		fru_Info;
		/*
		 * The deasserted field is not used
		 * to cache data in the sensor_control
		 * structure (we cache asserted states):
		 */
		struct ipmi_sensor_control	sensor_Ctl;
	} u;
	uu_list_node_t			un_node;
#define	fruInfo		u.fru_Info
#define	sensorCtl	u.sensor_Ctl
} bmc_cache_ent_t;

typedef struct bmc_replay_list_ent {
	uint8_t		netfn;
	uint8_t		lun;
	uint8_t		cmd;
	uint8_t		*databp;
	int		datablen;
	uu_list_node_t	un_node;
} bmc_replay_list_ent_t;

/*
 * The ipmi_mutex protects the bmc state$ and serializes bmc device access
 */
static pthread_mutex_t ipmi_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t ipmi_cond = PTHREAD_COND_INITIALIZER;
static dm_plugin_error_t (*sendrecv_fn)(int fd, uint8_t netfn, uint8_t lun,
    uint8_t cmd, uint8_t *datap, int datalen, bmc_rsp_t *rspp) = NULL;


static int bmc_method(int fd, int *if_type);
static void dump_request(bmc_req_t *request);
static void dump_response(bmc_rsp_t *response);
static dm_plugin_error_t ipmi_bmc_send_cmd_ioctl(int fd, uint8_t netfn,
    uint8_t lun, uint8_t cmd, uint8_t *datap, int datalen, bmc_rsp_t *rspp);
static dm_plugin_error_t ipmi_bmc_send_cmd_putmsg(int fd, uint8_t netfn,
    uint8_t lun, uint8_t cmd, uint8_t *datap, int datalen, bmc_rsp_t *rspp);
static dm_plugin_error_t ipmi_bmc_send_cmd(uint8_t netfn, uint8_t lun,
    uint8_t cmd, uint8_t *datap, int datalen, bmc_rsp_t *rspp);

/* IPMI Command Buffer-Setup Functions: */
static dm_plugin_error_t fru_setupfn(nvlist_t *props, void **databpp,
    int *datablen, void *arg);
static dm_plugin_error_t state_setupfn(nvlist_t *props, void **databpp,
    int *datablen, void *arg);
static dm_plugin_error_t sel_setupfn(nvlist_t *props, void **databpp,
    int *datablen, void *arg);

/* BMC Monitor and BMC Cache functions: */
static int bmc_cache_init(void);
static void bmc_cache_fini(void);
static int bmc_state_refresh(boolean_t *refreshed);
static int bmc_state_refresh_from_cache(void);
static bmc_cache_ent_t *bmc_state_cache_lookup(uint8_t netfn, uint8_t lun,
    uint8_t cmd, uint8_t *databp, int datablen);
static void bmc_state_cache_update(uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *databp, int datablen);
static void bmc_monitor_thread(void *arg);

/* BMC Replay List functions: */
static int bmc_replay_list_init(void);
static void bmc_replay_list_fini(void);
static int bmc_replay_list_execute(void);
static void bmc_replay_list_add(uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *databp, int datablen);

/* IPMI commands used internally */
static dm_plugin_error_t bmc_get_uptime(uint32_t *uptime, uint32_t *bootgen);
static dm_plugin_error_t bmc_get_sensor(uint8_t sensor_id, uint16_t *assrtd,
    boolean_t *updated_flag);

/* plugin entry points: */
static dm_plugin_error_t ipmi_plugin_init(void);
static dm_plugin_error_t ipmi_plugin_fru_update(const char *actionString,
    dm_fru_t *frup);
static dm_plugin_error_t ipmi_plugin_bind_handle(const char *actionString,
    dm_plugin_action_handle_t *hdlp);
static dm_plugin_error_t ipmi_plugin_execute(dm_plugin_action_handle_t hdl);
static dm_plugin_error_t ipmi_plugin_free_handle(
    dm_plugin_action_handle_t *hdlp);
static dm_plugin_error_t ipmi_plugin_fini(void);

dm_plugin_ops_t ipmi_dm_plugin_ops = {
	DM_PLUGIN_VERSION,
	ipmi_plugin_init,
	ipmi_plugin_fru_update,
	ipmi_plugin_bind_handle,
	ipmi_plugin_execute,
	ipmi_plugin_free_handle,
	ipmi_plugin_fini
};

static struct ipmi_cmd_setup ipmi_cmd_tab[] = {
	{ "fru", fru_setupfn, IPMI_NETFN_OEM,
	    0, IPMI_CMD_FRU_UPDATE },
	{ "state", state_setupfn, BMC_NETFN_SE,
	    0, IPMI_CMD_SET_SENSOR_READING },
	{ "sel", sel_setupfn, BMC_NETFN_STORAGE,
	    0, IPMI_CMD_ADD_SEL_ENTRY },
	{ NULL, NULL, 0, 0, 0 }
};

static pthread_t g_bmcmon_tid;
static boolean_t g_bmc_monitor_active;
static boolean_t g_bmcmon_done;
static boolean_t g_need_exec_replay = B_FALSE;
static uu_list_pool_t *g_uu_pool_cache = NULL;
static uu_list_pool_t *g_uu_pool_replay = NULL;
static uu_list_t *g_uu_cachelist = NULL;
static uu_list_t *g_uu_replaylist = NULL;
static int g_BMCErrorInjectionRate = 0;
static int g_bmc_fd = -1;

/*
 * The textual strings that are used in the actions may be one of the
 * following forms:
 *
 * [1] `fru gid=<n> hdd=<m>'
 * [2] `sensor id=<x> assert=<y> deassert=<z>'
 *
 * The generic parser will take a string and spit out the first token
 * (e.g. `fru' or `sensor') and an nvlist that contains the key-value
 * pairs in the rest of the string.  The assumption is that there are
 * no embedded spaces or tabs in the keys or values.
 */

static boolean_t
isnumber(const char *str)
{
	boolean_t hex = B_FALSE;
	int digits = 0;

	if (strncasecmp(str, "0x", 2) == 0) {
		hex = B_TRUE;
		str += 2;
	} else if (*str == '-' || *str == '+') {
		str++;
	}

	while (*str != 0) {
		if ((hex && !isxdigit(*str)) ||
		    (!hex && !isdigit(*str))) {
			return (B_FALSE);
		}

		str++;
		digits++;
	}

	return ((digits == 0) ? B_FALSE : B_TRUE);
}

static void
tolowerString(char *str)
{
	while (*str != 0) {
		*str = tolower(*str);
		str++;
	}
}

static boolean_t
parse_action_string(const char *actionString, char **cmdp, nvlist_t **propsp)
{
	char *action;
	char *tok, *lasts, *eq;
	int actionlen;
	boolean_t rv = B_TRUE;

	if (nvlist_alloc(propsp, NV_UNIQUE_NAME, 0) != 0)
		return (B_FALSE);

	actionlen = strlen(actionString) + 1;
	action = dstrdup(actionString);

	*cmdp = NULL;

	if ((tok = strtok_r(action, " \t", &lasts)) != NULL) {

		*cmdp = dstrdup(tok);

		while (rv && (tok = strtok_r(NULL, " \t", &lasts)) != NULL) {

			/* Look for a name=val construct */
			if ((eq = strchr(tok, '=')) != NULL && eq[1] != 0) {

				*eq = 0;
				eq++;

				/*
				 * Convert token to lowercase to preserve
				 * case-insensitivity, because nvlist doesn't
				 * do case-insensitive lookups
				 */
				tolowerString(tok);

				if (isnumber(eq)) {
					/* Integer property */

					if (nvlist_add_uint64(*propsp, tok,
					    strtoull(eq, NULL, 0)) != 0)
						rv = B_FALSE;
				} else {
					/* String property */

					if (nvlist_add_string(*propsp, tok,
					    eq) != 0)
						rv = B_FALSE;
				}
			} else if (eq == NULL) {
				/* Boolean property */
				if (nvlist_add_boolean(*propsp, tok) != 0)
					rv = B_FALSE;
			} else /* Parse error (`X=' is invalid) */
				rv = B_FALSE;
		}
	} else
		rv = B_FALSE;

	dfree(action, actionlen);
	if (!rv) {
		if (*cmdp) {
			dstrfree(*cmdp);
			*cmdp = NULL;
		}
		nvlist_free(*propsp);
		*propsp = NULL;
	}
	return (rv);
}

static ipmi_action_handle_t *
new_ipmi_action_handle(uint8_t netfn, uint8_t lun, uint8_t cmd, void *databp,
    int datablen)
{
	ipmi_action_handle_t *ret = TDMALLOC(ipmi_action_handle_t);

	ret->netfn = netfn;
	ret->lun = lun;
	ret->cmd = cmd;
	ret->databp = databp;
	ret->datablen = datablen;

	return (ret);
}

static void
bmc_reopen(void)
{
	if (g_bmc_fd >= 0)
		(void) close(g_bmc_fd);
	if ((g_bmc_fd = open(BMC_DEV, O_RDWR)) <= 0) {
		log_warn_e("Could not reopen bmc device");
	}
}

static void
free_ipmi_action_handle(ipmi_action_handle_t **hdlpp)
{
	ipmi_action_handle_t *hdlp = *hdlpp;

	if (hdlp) {
		dfree(hdlp->databp, hdlp->datablen);
		dfree(hdlp, sizeof (ipmi_action_handle_t));
		*hdlpp = NULL;
	}
}

static boolean_t
cmd_setup_entry_exists(uint8_t netfn, uint8_t lun, uint8_t cmd)
{
	int i;

	for (i = 0; ipmi_cmd_tab[i].name != NULL; i++) {

		if (ipmi_cmd_tab[i].netfn == netfn &&
		    ipmi_cmd_tab[i].lun == lun &&
		    ipmi_cmd_tab[i].cmd == cmd)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static dm_plugin_error_t
ipmi_exec_action_with_replay(uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *databp, int datablen)
{
	bmc_rsp_t		rsp;
	dm_plugin_error_t	rv;

	(void) bmc_state_refresh(NULL);

	if (g_need_exec_replay)
		g_need_exec_replay = (bmc_replay_list_execute() != 0);

	if (!g_need_exec_replay) {
		rv = (ipmi_bmc_send_cmd(netfn, lun, cmd, databp, datablen, &rsp)
		    == DMPE_SUCCESS && rsp.ccode == 0)
		    ? DMPE_SUCCESS : DMPE_FAILURE;
	}

	/*
	 * If the command failed (or we couldn't execute the command because
	 * we couldn't execute the replay list), and the failure is due to a
	 * timeout error, save the command's result for later replay
	 */
	if (g_need_exec_replay || (rv == DMPE_FAILURE &&
	    rsp.ccode == BMC_IPMI_COMMAND_TIMEOUT)) {

		/*
		 * Fake the return value as success (since we queued the
		 * command for later execution).
		 */
		rv = DMPE_SUCCESS;
		bmc_replay_list_add(netfn, lun, cmd, databp, datablen);
		g_need_exec_replay = B_TRUE;

	} else if (!g_need_exec_replay && rv == DMPE_SUCCESS) {

		/* Apply the command to the bmc state$ */
		bmc_state_cache_update(netfn, lun, cmd, databp, datablen);
	}

	return (rv);
}

static dm_plugin_error_t
exec_action_handle(ipmi_action_handle_t *hdlp)
{
	dm_plugin_error_t rv;

	/*
	 * Sanity check this handle -- the netfn/lun/cmd should match one
	 * of those defined in the ipmi_cmd_tab:
	 */
	if (!cmd_setup_entry_exists(hdlp->netfn, hdlp->lun, hdlp->cmd)) {
		log_warn("Possible corrupt handle @%p (netfn/lun/cmd does "
		    "not match any known commands.\n", (void *)hdlp);
		return (DMPE_FAILURE);
	}

	assert(pthread_mutex_lock(&ipmi_mutex) == 0);

	rv = ipmi_exec_action_with_replay(hdlp->netfn, hdlp->lun, hdlp->cmd,
	    hdlp->databp, hdlp->datablen);

	assert(pthread_mutex_unlock(&ipmi_mutex) == 0);

	return (rv);
}

static dm_plugin_error_t
action_do(const char *actionString, void *arg, boolean_t exec,
    ipmi_action_handle_t **hdlpp)
{
	nvlist_t	*props;
	char		*cmd;
	int		found_index;
	int		datablen, i;
	void		*databp;
	uint8_t		netfn, lun, cmdno;
	dm_plugin_error_t rv = DMPE_FAILURE;	/* Be pessimistic */

	if (parse_action_string(actionString, &cmd, &props)) {
		for (found_index = -1, i = 0;
		    found_index == -1 && ipmi_cmd_tab[i].name != NULL; i++) {
			if (strcasecmp(cmd, ipmi_cmd_tab[i].name) == 0) {
				assert(ipmi_cmd_tab[i].setupfn != NULL);
				rv = ipmi_cmd_tab[i].setupfn(props,
				    &databp, &datablen, arg);
				found_index = i;
			}
		}

		dstrfree(cmd);
		nvlist_free(props);

		netfn = ipmi_cmd_tab[found_index].netfn;
		lun = ipmi_cmd_tab[found_index].lun;
		cmdno = ipmi_cmd_tab[found_index].cmd;

		if (exec && found_index != -1 && rv == DMPE_SUCCESS) {

			assert(pthread_mutex_lock(&ipmi_mutex) == 0);

			rv = ipmi_exec_action_with_replay(netfn, lun,
			    cmdno, databp, datablen);

			assert(pthread_mutex_unlock(&ipmi_mutex) == 0);

			dfree(databp, datablen);

		} else if (found_index != -1 && rv == DMPE_SUCCESS) {
			assert(hdlpp != NULL);

			*hdlpp = new_ipmi_action_handle(netfn, lun, cmdno,
			    databp, datablen);
		}
	}

	return (rv);
}

static dm_plugin_error_t
fru_setupfn(nvlist_t *props, void **databpp, int *datablen,
    void *arg)
{
	uint64_t gid, hdd;
	struct ipmi_fru_update *fup;
	char *buf;
	dm_fru_t *frup = (dm_fru_t *)arg;

	/* We need 2 properties: `gid' and `hdd': */
	if (nvlist_lookup_uint64(props, "gid", &gid) != 0 ||
	    nvlist_lookup_uint64(props, "hdd", &hdd) != 0) {
		return (DMPE_FAILURE);
	}

	fup = TDZMALLOC(struct ipmi_fru_update);
	buf = (char *)dzmalloc(sizeof (fup->d_capacity) + 1);

	*datablen = sizeof (struct ipmi_fru_update);
	*databpp = fup;

	fup->global_id = (uint8_t)gid;
	fup->disk_number = (uint8_t)hdd;
	fup->data_length = sizeof (fup->d_manuf) + sizeof (fup->d_model) +
	    sizeof (fup->d_serial) + sizeof (fup->d_firmware) +
	    sizeof (fup->d_capacity);
	(void) memcpy(fup->d_manuf, frup->manuf,
	    MIN(sizeof (fup->d_manuf), sizeof (frup->manuf)));
	(void) memcpy(fup->d_model, frup->model,
	    MIN(sizeof (fup->d_model), sizeof (frup->model)));
	(void) memcpy(fup->d_serial, frup->serial,
	    MIN(sizeof (fup->d_serial), sizeof (frup->serial)));
	(void) memcpy(fup->d_firmware, frup->rev,
	    MIN(sizeof (fup->d_firmware), sizeof (frup->rev)));
	/*
	 * Print the size of the disk to a temporary buffer whose size is
	 * 1 more than the size of the buffer in the ipmi request data
	 * structure, so we can get the full 8 characters (instead of 7 + NUL)
	 */
	(void) snprintf(buf, sizeof (fup->d_capacity) + 1,
	    "%.1f%s",
	    frup->size_in_bytes >= ONE_PETABYTE ?
		(frup->size_in_bytes / ONE_PETABYTE) :
		    (frup->size_in_bytes >= ONE_TERABYTE ?
			    (frup->size_in_bytes / ONE_TERABYTE) :
				(frup->size_in_bytes >= ONE_GIGABYTE ?
				    (frup->size_in_bytes / ONE_GIGABYTE) :
					(frup->size_in_bytes >= ONE_MEGABYTE ?
				(frup->size_in_bytes / ONE_MEGABYTE) :
				    (frup->size_in_bytes / ONE_KILOBYTE)))),

	    frup->size_in_bytes >= ONE_PETABYTE ? "PB" :
		    (frup->size_in_bytes >= ONE_TERABYTE ? "TB" :
			(frup->size_in_bytes >= ONE_GIGABYTE ? "GB" :
				(frup->size_in_bytes >= ONE_MEGABYTE ? "MB" :
					"KB"))));
	(void) memcpy(fup->d_capacity, buf, sizeof (fup->d_capacity));

	dfree(buf, sizeof (fup->d_capacity) + 1);
	return (DMPE_SUCCESS);
}

/*ARGSUSED*/
static dm_plugin_error_t
state_setupfn(nvlist_t *props, void **databpp, int *datablen,
    void *arg)
{
	uint64_t assertmask = 0, deassertmask = 0, sid;
	boolean_t am_present, dam_present;
	struct ipmi_sensor_control *scp;

	/* We need at least 2 properties: `sid' and (`amask' || `dmask'): */
	am_present = nvlist_lookup_uint64(props, "amask", &assertmask) == 0;
	dam_present = nvlist_lookup_uint64(props, "dmask", &deassertmask) == 0;

	if (nvlist_lookup_uint64(props, "sid", &sid) != 0 ||
	    (!am_present && !dam_present)) {
		return (DMPE_FAILURE);
	}

	if (sid > UINT8_MAX) {
		log_warn("IPMI Plugin: Invalid sensor id `0x%" PRIx64 "'.\n",
		    sid);
		return (DMPE_FAILURE);
	} else if (assertmask > UINT16_MAX) {
		log_warn("IPMI Plugin: Invalid assertion mask `0x%" PRIx64
		    "'.\n", assertmask);
		return (DMPE_FAILURE);
	} else if (assertmask > UINT16_MAX) {
		log_warn("IPMI Plugin: Invalid deassertion mask `0x%" PRIx64
		    "'.\n", deassertmask);
		return (DMPE_FAILURE);
	}

	scp = TDZMALLOC(struct ipmi_sensor_control);

	scp->sensor_number = (uint8_t)sid;
	scp->operation = (am_present ? SC_ASSERT_OP : 0) |
	    (dam_present ? SC_DEASSERT_OP : 0);
	scp->assert_states = (uint16_t)assertmask;
	scp->deassert_states = (uint16_t)deassertmask;

	*datablen = sizeof (struct ipmi_sensor_control);
	*databpp = scp;

	return (DMPE_SUCCESS);
}

/*ARGSUSED*/
static dm_plugin_error_t
sel_setupfn(nvlist_t *props, void **databpp, int *datablen,
    void *arg)
{
	uint64_t oem_data, manuf_id;
	struct ipmi_sel_entry *sep;

	/* We need 2 properties: `oem' and `manu': */
	if (nvlist_lookup_uint64(props, "oem", &oem_data) != 0 ||
	    nvlist_lookup_uint64(props, "manu", &manuf_id) != 0) {

		return (DMPE_FAILURE);
	}

	if ((manuf_id & ~0xFFFFFFULL) != 0) {
		log_warn("IPMI Plugin: Invalid manuf field `0x%" PRIx64 "'.\n",
		    manuf_id);
		return (DMPE_FAILURE);
	} else if ((oem_data & ~0xFFFFFFFFFFFFULL) != 0) {
		log_warn("IPMI Plugin: Invalid oemd field `0x%" PRIx64
		    "'.\n", oem_data);
		return (DMPE_FAILURE);
	}

	sep = TDZMALLOC(struct ipmi_sel_entry);

	sep->type = SEL_TYPE_OEM;
	sep->manuf_id[0] = (uint8_t)(manuf_id & 0xFFULL);
	sep->manuf_id[1] = (uint8_t)((manuf_id & 0xFF00ULL) >> 8);
	sep->manuf_id[2] = (uint8_t)((manuf_id & 0xFF0000ULL) >> 16);
	sep->oem_defined[0] = (uint8_t)((oem_data & 0xFFULL) >> 8);
	sep->oem_defined[1] = (uint8_t)((oem_data & 0xFF00ULL) >> 16);
	sep->oem_defined[2] = (uint8_t)((oem_data & 0xFF0000ULL) >> 24);
	sep->oem_defined[3] = (uint8_t)((oem_data & 0xFF000000ULL) >> 32);
	sep->oem_defined[4] = (uint8_t)((oem_data & 0xFF00000000ULL) >> 40);
	sep->oem_defined[5] = (uint8_t)((oem_data & 0xFF0000000000ULL) >> 48);

	*datablen = sizeof (struct ipmi_sel_entry);
	*databpp = sep;

	return (DMPE_SUCCESS);
}

static dm_plugin_error_t
bmc_get_sensor(uint8_t sensor_id, uint16_t *assrtd, boolean_t *updated_flag)
{
	dm_plugin_error_t		rv;
	bmc_rsp_t			rsp;
	struct ipmi_sensor_reading	*srp;

	rv = ipmi_bmc_send_cmd(IPMI_NETFN_OEM, 0, IPMI_CMD_GET_SENSOR_READING,
	    &sensor_id, 1, &rsp);

	/* The command must return precisely the size of the data we expect */
	if (rsp.ccode ||
	    rsp.datalength > sizeof (struct ipmi_sensor_reading) ||
	    rsp.datalength < STRUCT_MIN_SIZE(struct ipmi_sensor_reading,
	    sensor_reading_optional_field_start))
		rv = DMPE_FAILURE;

	srp = (struct ipmi_sensor_reading *)&rsp.data[0];

	if (rv == DMPE_SUCCESS &&
	    rsp.datalength == sizeof (struct ipmi_sensor_reading) &&
	    !srp->data_unavailable && srp->scanning_enabled) {

		if (assrtd) {
			*assrtd = (srp->states_8_14 << 8) | srp->states_0_7;
			if (updated_flag)
				*updated_flag = B_TRUE;
		}
	}
	return (rv);
}

static dm_plugin_error_t
bmc_get_uptime(uint32_t *uptime, uint32_t *bootgen)
{
	dm_plugin_error_t	rv;
	uint8_t			junk = 0;
	bmc_rsp_t		rsp;
	struct bmc_uptime_info	*utinfop;

	rv = ipmi_bmc_send_cmd(IPMI_NETFN_OEM, 0, IPMI_CMD_GET_UPTIME, &junk,
	    1, &rsp);

	/* The command must return precisely the size of the data we expect */
	if (rsp.ccode ||
	    rsp.datalength != sizeof (struct bmc_uptime_info))
		rv = DMPE_FAILURE;

	if (rv == DMPE_SUCCESS) {
		utinfop = (struct bmc_uptime_info *)&rsp.data[0];
		if (uptime)
			*uptime = BE_32(utinfop->uptime_seconds);
		if (bootgen)
			*bootgen = BE_32(utinfop->incarnation);
	}
	return (rv);
}

/* ****** B M C   R E P L A Y    L I S T   I M P L E M E N T A T I O N ****** */

/*
 * The reasoning behind the replay list is to try to ensure that commands are
 * reliably sent to the BMC.  In the case of the replay list, any commands that
 * fail because they timed out are added tothe replay list.  Then, the next time
 * a command is attempted, the replay list is sent to the BMC first, then the
 * new command (to preserve ordering).  Currently, the only commands that are
 * supported by this plugin are write-oriented commands, where information is
 * sent to the BMC.  If, if the future, read-oriented commands are desired,
 * The replay mechanism will need to be enhanced to force all pending commands
 * in the replay list out to the BMC before executing the read-oriented
 * command (similar to a write cache that's flushed when a read is requested).
 */

static void
bmc_replay_list_ent_destroy(bmc_replay_list_ent_t *p)
{
	if (p->databp)
		dfree(p->databp, p->datablen);
	dfree(p, sizeof (bmc_replay_list_ent_t));
}

static int
bmc_replay_list_init(void)
{
	if ((g_uu_pool_replay = uu_list_pool_create(
	    "bmc_replay_list_pool", sizeof (bmc_replay_list_ent_t),
	    offsetof(bmc_replay_list_ent_t, un_node), NULL, 0)) == NULL)
		return (DMPE_FAILURE);

	if ((g_uu_replaylist = uu_list_create(g_uu_pool_replay, NULL, 0))
	    == NULL) {
		uu_list_pool_destroy(g_uu_pool_replay);
		return (DMPE_FAILURE);
	}

	return (DMPE_SUCCESS);
}

static void
bmc_replay_list_fini(void)
{
	void			*cookie = NULL;
	bmc_replay_list_ent_t	*p;

	while ((p = (bmc_replay_list_ent_t *)uu_list_teardown(g_uu_replaylist,
	    &cookie)) != NULL) {
		bmc_replay_list_ent_destroy(p);
	}

	uu_list_destroy(g_uu_replaylist);
	uu_list_pool_destroy(g_uu_pool_replay);
	g_uu_replaylist = NULL;
	g_uu_pool_replay = NULL;
}

/*
 * The caller must hold the ipmi_mutex!
 */
static void
bmc_replay_list_add(uint8_t netfn, uint8_t lun, uint8_t cmd, uint8_t *databp,
    int datablen)
{
	bmc_replay_list_ent_t *p = TDMALLOC(bmc_replay_list_ent_t);

	p->netfn = netfn;
	p->lun = lun;
	p->cmd = cmd;
	/*
	 * Make a deep copy of the data buffer, since we can't assume
	 * anything about when it will be deallocated.
	 */
	if (datablen > 0) {
		p->databp = (uint8_t *)dmalloc(datablen);
		(void) memcpy(p->databp, databp, datablen);
	}
	p->datablen = datablen;

	assert(g_uu_pool_replay != NULL);
	assert(g_uu_replaylist != NULL);
	uu_list_node_init(p, &p->un_node, g_uu_pool_replay);
	/* The replay list is a queue, so add to its tail: */
	(void) uu_list_insert_before(g_uu_replaylist, NULL, p);
}

/*
 * The caller must hold the ipmi_mutex!
 *
 * Returns < 0 if the replay list should be executed at a later time
 * (due to transient errors)
 */
static int
bmc_replay_list_execute(void)
{
	uu_list_walk_t		*walkp;
	bmc_replay_list_ent_t	*p = NULL;
	boolean_t		timedout_err = B_FALSE;
	bmc_rsp_t		rsp;
	dm_plugin_error_t	rv;

	if ((walkp = uu_list_walk_start(g_uu_replaylist, 0)) == NULL)
		return (-1);

	/*
	 * On the first timeout error, abort the replay; We cannot execute
	 * commands later in the list because they may depend on the state
	 * set by earlier commands.  We'll retry the command that failed
	 * later. (Note that non-timeout-related failures do not cause
	 * aborts because the assumption is that the original command caller
	 * would not behave differently if a command were to fail.)  If this
	 * assumption does not remain valid in the future, an enhancement to
	 * the plugin API would be required to introduce a synchronous flag
	 * that would result in the blocking of the calling thread until
	 * BOTH the replay list is fully executed AND the user's current
	 * command is executed (at which point the status can be examined
	 * by the caller).
	 */
	while (!timedout_err && (p = uu_list_walk_next(walkp)) != NULL) {
		rv = ipmi_bmc_send_cmd(p->netfn, p->lun, p->cmd, p->databp,
		    p->datablen, &rsp);

		if (rv == DMPE_SUCCESS ||
		    (rv == DMPE_FAILURE &&
		    rsp.ccode != BMC_IPMI_COMMAND_TIMEOUT)) {

			if (rsp.ccode != 0) {
				log_msg(MM_PLUGIN, "ipmi plugin: netfn 0x%x "
				    "cmd 0x%x ccode=0x%x\n", p->netfn, p->cmd,
				    rsp.ccode);
			}
			if (rv == DMPE_SUCCESS) {
				/* Add the command to the bmc state$ */
				bmc_state_cache_update(p->netfn, p->lun, p->cmd,
				    p->databp, p->datablen);
			}
			uu_list_remove(g_uu_replaylist, p);
			bmc_replay_list_ent_destroy(p);

		} else if (rv == DMPE_FAILURE &&
		    rsp.ccode == BMC_IPMI_COMMAND_TIMEOUT) {

			timedout_err = B_TRUE;
		}
	}

	uu_list_walk_end(walkp);
	return (timedout_err ? -1 : 0);
}

/* ************** B M C  C A C H E  I M P L E M E N T A T I O N ************* */

/*
 * The reasoning behind the cache is to maintain a mirror of the BMC's state
 * as it pertains to the commands that were sent from the plugin.  For Sun's
 * BMC implementations, the sensor and FRU information is not currently
 * preserved when the BMC (or service processor) is reset (or rebooted).  To
 * maintain consistency from the user/administrator's perspective, once the
 * BMC comes back online after a reset, the information from the state cache
 * is sent, all at once, in particular order, to the BMC.
 */

static int
bmc_cache_init(void)
{
	if ((g_uu_pool_cache = uu_list_pool_create(
	    "bmc_cache_entry_pool", sizeof (bmc_cache_ent_t),
	    offsetof(bmc_cache_ent_t, un_node), NULL, 0)) == NULL)
		return (DMPE_FAILURE);

	if ((g_uu_cachelist = uu_list_create(g_uu_pool_cache, NULL, 0))
	    == NULL) {
		uu_list_pool_destroy(g_uu_pool_cache);
		return (DMPE_FAILURE);
	}

	return (DMPE_SUCCESS);
}

static void
bmc_cache_fini(void)
{
	void	*cookie = NULL;
	void	*p;

	while ((p = uu_list_teardown(g_uu_cachelist, &cookie)) != NULL)
		dfree(p, sizeof (bmc_cache_ent_t));

	uu_list_destroy(g_uu_cachelist);
	uu_list_pool_destroy(g_uu_pool_cache);

	g_uu_cachelist = NULL;
	g_uu_pool_cache = NULL;
}

static void
bmc_cache_member_init_sensorctl(bmc_cache_ent_t *p, void *databp)
{
	struct ipmi_sensor_control	*tgt;
	uint16_t			assrtd;
	boolean_t			was_assrtd_updated = B_FALSE;

	tgt = (struct ipmi_sensor_control *)databp;

	/*
	 * operation is initted here so that when we do the bmc update from
	 * the cache, the structure will ready to send directly from the cache
	 */
	p->sensorCtl.sensor_number = tgt->sensor_number;
	p->sensorCtl.operation = SC_ASSERT_OP;
	p->sensorCtl.assert_states = tgt->assert_states;

	/*
	 * If the command fails, we'll still have the asserted
	 * states that were set by the command that just finished
	 */
	if (bmc_get_sensor(p->sensorCtl.sensor_number, &assrtd,
	    &was_assrtd_updated) == DMPE_SUCCESS &&
	    was_assrtd_updated == B_TRUE) {

		/*
		 * If the states that were just asserted are not when we
		 * check, issues a warning, but only if the verbosity is
		 * jacked up -- this could be OK (if another user updates
		 * the sensor's state between the time we executed the
		 * update sensor command and the time we check the sensor's
		 * value.
		 */
		if ((p->sensorCtl.assert_states & assrtd)
		    != p->sensorCtl.assert_states) {

			log_msg(MM_PLUGIN,
			    "Asserted state(s) set before cache addition "
			    "(0x%x) didn't stick -- caching them anyway\n",
			    p->sensorCtl.assert_states);
		}

		p->sensorCtl.assert_states |= assrtd;
	}
}

static void
bmc_cache_member_update_sensorctl(bmc_cache_ent_t *p, void *databp)
{
	struct ipmi_sensor_control *tgt = (struct ipmi_sensor_control *)databp;

	/*
	 * It's not possible for the same bits to be set in the assert and
	 * deassert masks- it would have cause an IPMI error when the
	 * command was originally executed (and the cache update would
	 * therefore not have occurred)
	 */
	p->sensorCtl.assert_states |= tgt->assert_states;
	p->sensorCtl.assert_states &= ~tgt->deassert_states;
}

static boolean_t
bmc_cache_member_match_sensorctl(bmc_cache_ent_t *p, void *databp)
{
	struct ipmi_sensor_control *tgt = (struct ipmi_sensor_control *)databp;

	return (p->sensorCtl.sensor_number == tgt->sensor_number);
}

static void
bmc_cache_member_bufsetup_sensorctl(bmc_cache_ent_t *p, void **bufpp,
    int *buflenp)
{
	/* Mask off bits that shouldn't be set according to the spec */
	p->sensorCtl.operation = SC_ASSERT_OP|SC_DEASSERT_OP;
	p->sensorCtl.assert_states &= ~STATE_RESERVED_BITS;
	p->sensorCtl.deassert_states =
	    (~p->sensorCtl.assert_states & ~STATE_RESERVED_BITS);

	*bufpp = &p->sensorCtl;
	*buflenp = sizeof (struct ipmi_sensor_control);
}

static void
bmc_cache_member_init_fru_update(bmc_cache_ent_t *p, void *databp)
{
	(void) memcpy(&p->fruInfo, databp, sizeof (struct ipmi_fru_update));
}

static void
bmc_cache_member_update_fru_update(bmc_cache_ent_t *p, void *databp)
{
	(void) memcpy(&p->fruInfo, databp, sizeof (struct ipmi_fru_update));
}


static boolean_t
bmc_cache_member_match_fru_update(bmc_cache_ent_t *p, void *databp)
{
	struct ipmi_fru_update *frup = (struct ipmi_fru_update *)databp;

	return (p->fruInfo.global_id == frup->global_id &&
	    p->fruInfo.disk_number == frup->disk_number);
}

static void
bmc_cache_member_bufsetup_fru_update(bmc_cache_ent_t *p, void **bufpp,
    int *buflenp)
{
	*bufpp = &p->fruInfo;
	*buflenp = sizeof (struct ipmi_fru_update);
}

/*
 * Different elements in the cache need to be restored in order
 * (e.g. sensor state information must be populated before FRU information
 * is populated because the FRU information won't "stick" if the right
 * state isn't asserted)
 * The g_restoreOrder array is indexed by cache entry type
 */
static const bmc_cache_ent_type_t g_restoreOrder[] = {
	CACHE_ENT_SENSORCTL,
	CACHE_ENT_FRUINFO,
	CACHE_ENT_LAST
};

static struct bmc_cache_member {
	uint8_t				netfn;
	uint8_t				lun;
	uint8_t				cmd;
	int				dataszmin;
	boolean_t			(*matchfn)(bmc_cache_ent_t *, void *);
	void				(*updatefn)(bmc_cache_ent_t *, void *);
	void				(*initfn)(bmc_cache_ent_t *, void *);
	void				(*bufsetupfn)(bmc_cache_ent_t *,
							void **, int *);
	void				(*bufdonefn)(bmc_cache_ent_t *, void *,
							int);

} g_cachemembers[] = {

	/* CACHE_ENT_FIRST */
	{ 0, 0, 0, 0, NULL },

	/* CACHE_ENT_FRUINFO */
	{ IPMI_NETFN_OEM, 0, IPMI_CMD_FRU_UPDATE,
	    sizeof (struct ipmi_fru_update),
	    bmc_cache_member_match_fru_update,
	    bmc_cache_member_update_fru_update,
	    bmc_cache_member_init_fru_update,
	    bmc_cache_member_bufsetup_fru_update,
	    NULL },

	/* CACHE_ENT_SENSORCTL */
	{ BMC_NETFN_SE, 0, IPMI_CMD_SET_SENSOR_READING,
	    sizeof (struct ipmi_sensor_control),
	    bmc_cache_member_match_sensorctl,
	    bmc_cache_member_update_sensorctl,
	    bmc_cache_member_init_sensorctl,
	    bmc_cache_member_bufsetup_sensorctl,
	    NULL },

	/* CACHE_ENT_LAST */
	{ 0, 0, 0, 0, NULL }
};

static bmc_cache_ent_t *
bmc_state_cache_lookup(uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *databp, int datablen)
{
	uu_list_walk_t		*walkp;
	bmc_cache_ent_t		*p = NULL;
	boolean_t		found = B_FALSE;

	if ((walkp = uu_list_walk_start(g_uu_cachelist, 0)) == NULL)
		return (NULL);

	while (!found && (p = uu_list_walk_next(walkp)) != NULL) {

		if (g_cachemembers[p->type].netfn == netfn &&
		    g_cachemembers[p->type].lun == lun &&
		    g_cachemembers[p->type].cmd == cmd &&
		    datablen >= g_cachemembers[p->type].dataszmin &&
		    (*(g_cachemembers[p->type].matchfn))(p, databp) == B_TRUE) {

				found = B_TRUE;
		}
	}

	uu_list_walk_end(walkp);
	return (found ? p : NULL);
}

static void
bmc_state_cache_add(uint8_t netfn, uint8_t lun, uint8_t cmd, uint8_t *databp,
    int datablen)
{
	boolean_t	found_initfn = B_FALSE;
	int		i;
	bmc_cache_ent_t	*p;

	p = (bmc_cache_ent_t *)dzmalloc(sizeof (bmc_cache_ent_t));
	for (i = CACHE_ENT_FIRST + 1; !found_initfn && i < CACHE_ENT_LAST;
	    i++) {

		if (g_cachemembers[i].netfn == netfn &&
		    g_cachemembers[i].lun == lun &&
		    g_cachemembers[i].cmd == cmd &&
		    datablen >= g_cachemembers[i].dataszmin) {

			p->type = i;
			(*(g_cachemembers[i].initfn))(p, databp);
			found_initfn = B_TRUE;
		}
	}

	if (found_initfn) {

		assert(g_uu_pool_cache != NULL);
		assert(g_uu_cachelist != NULL);
		uu_list_node_init(p, &p->un_node, g_uu_pool_cache);
		uu_list_insert(g_uu_cachelist, p, 0);

	} else {
		log_msg(MM_PLUGIN, "Not adding netfn=0x%x cmd=0x%x to the "
		    "bmc$\n", netfn, cmd);

		dfree(p, sizeof (bmc_cache_ent_t));
	}
}

/*
 * The caller must hold the ipmi_mutex!
 */
static void
bmc_state_cache_update(uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *databp, int datablen)
{
	bmc_cache_ent_t			*p;

	/*
	 * Do a lookup to see if we have an entry for this entity.
	 * If so, update it, otherwise, create a new entry in the cache.
	 */


	if ((p = bmc_state_cache_lookup(netfn, lun, cmd, databp, datablen))
	    != NULL) {

		/* Update the cache with the command payload */
		(*(g_cachemembers[p->type].updatefn))(p, databp);

	} else {

		/* Add the item to the cache */
		bmc_state_cache_add(netfn, lun, cmd, databp, datablen);
	}
}

/*
 * Caller MUST hold the ipmi_lock
 */
static int
bmc_state_refresh_from_cache(void)
{
	int			i;
	uu_list_walk_t		*walkp;
	bmc_cache_ent_t		*p = NULL;
	boolean_t		bail = B_FALSE;
	void			*databp;
	int			datablen;
	dm_plugin_error_t	rv;
	bmc_rsp_t		rsp;

	/*
	 * Since cached state needs to be restored in a particular
	 * order, make several passes through the cache list, restoring
	 * the state in pass-order. If this becomes performance-limiting,
	 * the cache list can be populated in sorted order (in pass order)
	 */
	for (i = 0; !bail && g_restoreOrder[i] != CACHE_ENT_LAST; i++) {

		if ((walkp = uu_list_walk_start(g_uu_cachelist, 0)) == NULL)
			return (-1);

		while (!bail && (p = uu_list_walk_next(walkp)) != NULL) {

			if (p->type == g_restoreOrder[i]) {

				(*(g_cachemembers[p->type].bufsetupfn))
				    (p, &databp, &datablen);

				rv = ipmi_bmc_send_cmd(
				    g_cachemembers[p->type].netfn,
				    g_cachemembers[p->type].lun,
				    g_cachemembers[p->type].cmd,
				    databp, datablen, &rsp);

				if (rv == DMPE_FAILURE &&
				    rsp.ccode != BMC_IPMI_COMMAND_TIMEOUT)
					bail = B_TRUE;

				if (g_cachemembers[p->type].bufdonefn)
					(*(g_cachemembers[p->type].bufdonefn))
					    (p, databp, datablen);
			}
		}

		uu_list_walk_end(walkp);
	}

	return (bail ? -1 : 0);
}

/*
 * Caller MUST hold the ipmi_lock
 */
static int
bmc_state_refresh(boolean_t *refreshed)
{
	static uint32_t		last_utime = 0;
	static uint32_t		last_iter = 0;
	static boolean_t	initted = B_FALSE;
	uint32_t		utime;
	uint32_t		iter;
	dm_plugin_error_t	rv;

	if (!g_bmc_monitor_active)
		return (0);

	rv = bmc_get_uptime(&utime, &iter);

	if (refreshed)
		*refreshed = B_FALSE;

	if (rv == DMPE_SUCCESS) {

		/*
		 * This also handles the wrap-around case (when utime is
		 * less than last_utime, but iter == last_iter), and
		 * also the case when the BMC's configuration is
		 * reset after a reboot (e.g. the reboot iteration #
		 * is reset to 0).
		 */
		if (initted &&
		    (utime < last_utime || iter != last_iter)) {
			/* BMC Reboot/Reset Detected */
			log_msg(MM_PLUGIN, "BMC refresh in progress...");
			if (bmc_state_refresh_from_cache() < 0) {
				log_msg(MM_PLUGIN, "BMC refresh failed!\n");
				return (-1);
			} else {
				if (refreshed)
					*refreshed = B_TRUE;
			}
		}

		last_utime = utime;
		last_iter = iter;
		initted = B_TRUE;
	}

	return (0);
}

/*ARGSUSED*/
static void
bmc_monitor_thread(void *arg)
{
	struct timespec 	tspec;
	boolean_t		refreshed;

	assert(pthread_mutex_lock(&ipmi_mutex) == 0);
	while (!g_bmcmon_done) {

		if (bmc_state_refresh(&refreshed) == 0 && refreshed) {
			/*
			 * If the state was successfully refreshed, and there's
			 * replay list, execute that list.
			 */
			if (g_need_exec_replay) {
				g_need_exec_replay =
				    (bmc_replay_list_execute() != 0);
			}

			log_msg(MM_PLUGIN, "BMC successfully refreshed with "
				    "cached state!\n");
		}

		/* Poll the BMC for any changes in its state every minute */
		tspec.tv_sec = time(0) + BMC_CHECK_UPTIME_INTERVAL;
		tspec.tv_nsec = 0;

		(void) pthread_cond_timedwait(&ipmi_cond,
		    &ipmi_mutex, &tspec);
	}
	assert(pthread_mutex_unlock(&ipmi_mutex) == 0);

	log_msg(MM_PLUGIN, "BMC monitoring thread exiting...");
}

/* ***************** P L U G I N  E N T R Y  P O I N T S ******************* */

static dm_plugin_error_t
ipmi_plugin_init(void)
{
	int method;
	const char *monpropval =
	    dm_plugin_prop_lookup(GLOBAL_PROP_IPMI_BMC_MON);
	const char *errinjprop =
	    dm_plugin_prop_lookup(GLOBAL_PROP_IPMI_ERR_INJ);
	boolean_t bmcmon_enabled;

	if ((g_bmc_fd = open(BMC_DEV, O_RDWR)) <= 0) {
		log_warn_e("Could not open bmc device");
		return (DMPE_FAILURE);
	}

	if (bmc_method(g_bmc_fd, &method) < 0) {
		(void) close(g_bmc_fd);
		log_warn("IPMI plugin: Could not determine bmc messaging "
		    "interface!\n");
		return (DMPE_FAILURE);
	}

	/*
	 * Keep the bmc device open to prevent the driver from unloading
	 * at a critical moment (e.g. when the BMC is not available).  If
	 * we didn't do this, subsequent attempt at opening the bmc device
	 * would fail because the bmc driver would not be able to find
	 * the BMC (if it's resetting), and once the bmc's probe fails,
	 * the system will not reload it automatically.
	 */

	sendrecv_fn = (method == BMC_PUTMSG_METHOD) ?
	    ipmi_bmc_send_cmd_putmsg : ipmi_bmc_send_cmd_ioctl;

	if (bmc_replay_list_init() != 0) {
		return (DMPE_FAILURE);
	}

	if (errinjprop != NULL)
		g_BMCErrorInjectionRate = strtol(errinjprop, 0, 0);

	bmcmon_enabled = (monpropval != NULL && strtol(monpropval, 0, 0) != 0);

	/*
	 * Check to see if the BMC supports the Sun OEM uptime command
	 * If it does, spawn a monitoring thread that will periodically poll
	 * the bmc and check for bmc resets (since the bmc does not retain
	 * the state across resets)
	 */
	if (bmcmon_enabled && bmc_get_uptime(NULL, NULL) == 0) {
		if (bmc_cache_init() != 0) {
			bmc_replay_list_fini();
			return (DMPE_FAILURE);
		}

		g_bmc_monitor_active = B_TRUE;
		g_bmcmon_done = B_FALSE;
		g_bmcmon_tid = dm_plugin_thr_create(bmc_monitor_thread, NULL);
	} else
		g_bmc_monitor_active = B_FALSE;

	return (DMPE_SUCCESS);
}

static dm_plugin_error_t
ipmi_plugin_fru_update(const char *actionString, dm_fru_t *frup)
{
	return (action_do(actionString, frup, B_TRUE, NULL));
}

static dm_plugin_error_t
ipmi_plugin_bind_handle(const char *actionString,
    dm_plugin_action_handle_t *hdlp)
{
	return (action_do(actionString, NULL, B_FALSE,
	    (ipmi_action_handle_t **)hdlp));
}

static dm_plugin_error_t
ipmi_plugin_execute(dm_plugin_action_handle_t hdl)
{
	return (exec_action_handle((ipmi_action_handle_t *)hdl));
}

static dm_plugin_error_t
ipmi_plugin_free_handle(dm_plugin_action_handle_t *hdlp)
{
	free_ipmi_action_handle((ipmi_action_handle_t **)hdlp);
	return (DMPE_SUCCESS);
}

static dm_plugin_error_t
ipmi_plugin_fini(void)
{
	if (g_bmc_monitor_active) {
		g_bmcmon_done = B_TRUE;
		assert(pthread_mutex_lock(&ipmi_mutex) == 0);
		(void) pthread_cond_broadcast(&ipmi_cond);
		assert(pthread_mutex_unlock(&ipmi_mutex) == 0);

		/* Signal the thread just in case it's blocked doing BMC I/O */
		dm_plugin_thr_signal(g_bmcmon_tid);
		dm_plugin_thr_destroy(g_bmcmon_tid);

		/* Clean up cache lists */
		bmc_cache_fini();
	}
	bmc_replay_list_fini();
	(void) close(g_bmc_fd);
	return (DMPE_SUCCESS);
}

/* ************** I P M I  S U P P O R T  F U N C T I O N S **************** */

static dm_plugin_error_t
ipmi_bmc_send_cmd(uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *datap, int datalen, bmc_rsp_t *rspp)
{
	dm_plugin_error_t rv;
	static int inject_rep = 0;

	if (g_BMCErrorInjectionRate > 0 &&
	    (++inject_rep % g_BMCErrorInjectionRate) == 0) {
		inject_rep = 0;
		rspp->ccode = BMC_IPMI_COMMAND_TIMEOUT;
		return (DMPE_FAILURE);
	}

	if (g_bmc_fd < 0)
		bmc_reopen();

	/* sendrecv_fn cannot be NULL at this point */
	assert(sendrecv_fn != NULL);
	rv = (*sendrecv_fn)(g_bmc_fd, netfn, lun, cmd, datap, datalen, rspp);

	return (rv);
}

static dm_plugin_error_t
ipmi_bmc_send_cmd_ioctl(int fd, uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *datap, int datalen, bmc_rsp_t *rspp)
{
	struct strioctl istr;
	struct bmc_reqrsp reqrsp;

	if (datalen > SEND_MAX_PAYLOAD_SIZE) {
		log_warn("IPMI Plugin: Data payload length (%d) is too "
		    "large; it cannot be processed by this version of "
		    "the bmc driver.\n", datalen);
		return (DMPE_FAILURE);
	}

	(void) memset(&reqrsp, 0, sizeof (reqrsp));
	reqrsp.req.fn = netfn;
	reqrsp.req.lun = lun;
	reqrsp.req.cmd = cmd;
	reqrsp.req.datalength = (uint8_t)datalen;
	(void) memcpy(reqrsp.req.data, datap, datalen);
	reqrsp.rsp.datalength = RECV_MAX_PAYLOAD_SIZE;

	istr.ic_cmd = IOCTL_IPMI_KCS_ACTION;
	istr.ic_timout = 0;
	istr.ic_dp = (char *)&reqrsp;
	istr.ic_len = sizeof (struct bmc_reqrsp);

	log_msg(MM_PLUGIN, "--\n");
		dump_request(&reqrsp.req);
	log_msg(MM_PLUGIN, "--\n");

	if (ioctl(fd, I_STR, &istr) < 0) {
		log_warn_e("IPMI Plugin: ioctl failure");
		return (DMPE_FAILURE);
	}

	dump_response(&reqrsp.rsp);
	log_msg(MM_PLUGIN, "--\n");

	(void) memcpy(rspp, &reqrsp.rsp, sizeof (bmc_rsp_t));

	/* Decrement for sizeof lun, cmd and ccode */
	if (rspp->ccode || rspp->datalength == 0)
		(void) memset(rspp->data, 0, sizeof (rspp->data));
	else if (rspp->datalength > 3)
		rspp->datalength -= 3;

	return (DMPE_SUCCESS);
}

static dm_plugin_error_t
ipmi_bmc_send_cmd_putmsg(int fd, uint8_t netfn, uint8_t lun, uint8_t cmd,
    uint8_t *datap, int datalen, bmc_rsp_t *rspp)
{
	struct strbuf sb;
	int flags = 0;
	static uint32_t msg_seq = 0;

	/*
	 * The length of the message structure is equal to the size of the
	 * bmc_req_t structure, PLUS any additional data space in excess of
	 * the data space already reserved in the data member + <n> for
	 * the rest of the members in the bmc_msg_t structure.
	 */
	int msgsz = offsetof(bmc_msg_t, msg) + sizeof (bmc_req_t) +
		((datalen > SEND_MAX_PAYLOAD_SIZE) ?
			(datalen - SEND_MAX_PAYLOAD_SIZE) : 0);
	bmc_msg_t *msg = (bmc_msg_t *)dzmalloc(msgsz);
	bmc_req_t *request = (bmc_req_t *)&msg->msg[0];
	bmc_rsp_t *response;

	msg->m_type = BMC_MSG_REQUEST;
	msg->m_id = msg_seq++;
	request->fn = netfn;
	request->lun = lun;
	request->cmd = cmd;
	request->datalength = (uint8_t)datalen;
	(void) memcpy(request->data, datap, datalen);

	sb.len = msgsz;
	sb.buf = (char *)msg;

	log_msg(MM_PLUGIN, "--\n");
	dump_request(request);
	log_msg(MM_PLUGIN, "--\n");

	if (putmsg(fd, NULL, &sb, 0) < 0) {
		log_warn_e("IPMI Plugin: putmsg failure");
		dfree(msg, msgsz);

		/*
		 * As a workaround for a bug in bmc, if an error was returned
		 * from putmsg, we need to close the fd and reopen it to clear
		 * the error state.
		 */
		bmc_reopen();

		return (DMPE_FAILURE);
	}

	dfree(msg, msgsz);

	sb.buf = dzmalloc(MESSAGE_BUFSIZE);
	sb.maxlen = MESSAGE_BUFSIZE;

	if (getmsg(fd, NULL, &sb, &flags) < 0) {
		log_warn_e("IPMI Plugin: getmsg failure");
		dfree(sb.buf, MESSAGE_BUFSIZE);
		return (DMPE_FAILURE);
	}

	/*LINTED*/
	msg = (bmc_msg_t *)sb.buf;

	log_msg(MM_PLUGIN, "Got msg (id 0x%x) type 0x%x\n", msg->m_id,
	    msg->m_type);


	/* Did we get an error back from the stream? */
	switch (msg->m_type) {

	case BMC_MSG_RESPONSE:
		response = (bmc_rsp_t *)&msg->msg[0];

		dump_response(response);
		log_msg(MM_PLUGIN, "--\n");

		(void) memcpy(rspp, response, sizeof (bmc_rsp_t));

		if (rspp->ccode || rspp->datalength == 0)
			(void) memset(rspp->data, 0, sizeof (rspp->data));

		break;

	case BMC_MSG_ERROR:
		/* In case of an error, msg->msg[0] has the error code */
		log_warn("IPMI Plugin: bmc_send_cmd error: %s\n",
		    strerror(msg->msg[0]));
		break;

	}

	dfree(sb.buf, MESSAGE_BUFSIZE);
	return (DMPE_SUCCESS);
}

/*
 * Determine which interface to use.  Returns the interface method
 * to use.
 */
static int
bmc_method(int fd, int *if_type)
{
	struct strioctl istr;
	int retval = 0;
	uint8_t method = BMC_PUTMSG_METHOD;

	istr.ic_cmd = IOCTL_IPMI_INTERFACE_METHOD;
	istr.ic_timout = 0;
	istr.ic_dp = (char *)&method;
	istr.ic_len = 1;

	/*
	 * If the ioctl doesn't exist, we should get an EINVAL back.
	 * Bail out on any other error.
	 */
	if (ioctl(fd, I_STR, &istr) < 0) {

		if (errno != EINVAL)
			retval = -1;
		else
			method = BMC_IOCTL_METHOD;
	}

	if (retval == 0)
		*if_type = method;

	return (retval);
}

static void
dump_request(bmc_req_t *request)
{
	int i;

	log_msg(MM_PLUGIN, "BMC req.fn         : 0x%x\n", request->fn);
	log_msg(MM_PLUGIN, "BMC req.lun        : 0x%x\n", request->lun);
	log_msg(MM_PLUGIN, "BMC req.cmd        : 0x%x\n", request->cmd);
	log_msg(MM_PLUGIN, "BMC req.datalength : 0x%x\n", request->datalength);
	log_msg(MM_PLUGIN, "BMC req.data       : ");

	if (request->datalength > 0) {
		for (i = 0; i < request->datalength; i++)
			log_msg(MM_PLUGIN, "0x%x ", request->data[i]);
	} else {
		log_msg(MM_PLUGIN, "<NONE>");
	}
	log_msg(MM_PLUGIN, "\n");
}

static void
dump_response(bmc_rsp_t *response)
{
	int i;

	log_msg(MM_PLUGIN, "BMC rsp.fn         : 0x%x\n", response->fn);
	log_msg(MM_PLUGIN, "BMC rsp.lun        : 0x%x\n", response->lun);
	log_msg(MM_PLUGIN, "BMC rsp.cmd        : 0x%x\n", response->cmd);
	log_msg(MM_PLUGIN, "BMC rsp.ccode      : 0x%x\n", response->ccode);
	log_msg(MM_PLUGIN, "BMC rsp.datalength : 0x%x\n", response->datalength);
	log_msg(MM_PLUGIN, "BMC rsp.data       : ");

	if (response->datalength > 0) {
		for (i = 0; i < response->datalength; i++)
			log_msg(MM_PLUGIN, "0x%x ", response->data[i]);
	} else {
		log_msg(MM_PLUGIN, "<NONE>");
	}
	log_msg(MM_PLUGIN, "\n");
}
