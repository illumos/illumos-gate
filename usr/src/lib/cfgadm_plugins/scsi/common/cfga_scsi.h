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

#ifndef _CFGA_SCSI_H
#define	_CFGA_SCSI_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <locale.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <locale.h>
#include <langinfo.h>
#include <time.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/dditypes.h>
#include <sys/modctl.h>
#include <libdevinfo.h>
#include <libdevice.h>
#include <librcm.h>
#include <dirent.h>
#include <strings.h>

#include <sys/ioctl.h>
#include <sys/byteorder.h>
#include <sys/scsi/scsi.h>
#include <strings.h>
#include <sys/vfstab.h>
#include <sys/stat.h>
#include <sys/mnttab.h>
#include <sys/wait.h>
#include <signal.h>

#include <sys/uio.h>
#include <sys/param.h>

#include <synch.h>
#include <thread.h>

#include <limits.h>
#include <ftw.h>

#define	CFGA_PLUGIN_LIB
#include <config_admin.h>

#if	!defined(DEBUG)
#define	NDEBUG	1
#else
#undef	NDEBUG
#endif

#include <assert.h>

/* Return/error codes */
typedef enum {
	SCFGA_ERR = -1,
	SCFGA_LIB_ERR = 0,
	SCFGA_OK,
	SCFGA_NACK,
	SCFGA_BUSY,
	SCFGA_SYSTEM_BUSY,
	SCFGA_APID_NOEXIST,
	SCFGA_OPNOTSUPP,
	SCFGA_PRIV,
	SCFGA_UNLOCKED,
	SCFGA_NO_REC,
	SCFGA_OP_INTR,
	SCFGA_DB_INVAL,
	SCFGA_UNKNOWN_ERR
} scfga_ret_t;

/* Commands used internally */
typedef enum {
	SCFGA_INVAL_CMD = -1,
	SCFGA_DEV_OP = 0,
	SCFGA_BUS_OP,
	SCFGA_STAT_DEV,
	SCFGA_STAT_BUS,
	SCFGA_STAT_ALL,
	SCFGA_GET_DEVPATH,
	SCFGA_INSERT_DEV,
	SCFGA_REMOVE_DEV,
	SCFGA_REPLACE_DEV,
	SCFGA_WALK_NODE,
	SCFGA_WALK_MINOR,
	SCFGA_WALK_PATH,
	SCFGA_BUS_QUIESCE,
	SCFGA_BUS_UNQUIESCE,
	SCFGA_BUS_GETSTATE,
	SCFGA_DEV_GETSTATE,
	SCFGA_BUS_CONFIGURE,
	SCFGA_BUS_UNCONFIGURE,
	SCFGA_DEV_CONFIGURE,
	SCFGA_DEV_UNCONFIGURE,
	SCFGA_DEV_REMOVE,
	SCFGA_LED_DEV,
	SCFGA_LOCATOR_DEV,
	SCFGA_RESET_DEV,
	SCFGA_RESET_BUS,
	SCFGA_RESET_ALL,
	SCFGA_READ,
	SCFGA_WRITE
} scfga_cmd_t;

typedef enum {
	SCFGA_TERMINATE = 0,
	SCFGA_CONTINUE
} scfga_recur_t;

typedef enum {
	NODYNCOMP = 1,
	DEV_APID,
	PATH_APID
} dyncomp_t;


/* Structures for tree walking code */

typedef struct {
	uint_t flags;
	int (*fcn)(di_node_t node, void *argp);
} walk_node_t;

typedef struct {
	const char *nodetype;
	int (*fcn)(di_node_t node, di_minor_t minor, void *argp);
} walk_minor_t;

typedef union {
	walk_node_t	node_args;
	walk_minor_t	minor_args;
} walkarg_t;

typedef struct {
	char *phys;
	char *log;
	scfga_ret_t ret;
	int match_minor;
	int l_errno;
} pathm_t;

typedef struct ldata_list {
	cfga_list_data_t ldata;
	struct ldata_list *next;
} ldata_list_t;

typedef struct {
	struct cfga_confirm	*confp;
	struct cfga_msg		*msgp;
} prompt_t;

typedef struct {
	char		*hba_phys;
	char		*dyncomp;
	dyncomp_t	dyntype;    /* is pathinfo or dev apid? */
	char		*path;	    /* for apid with device dyn comp. */
	uint_t		flags;
} apid_t;

/* Private hardware options */
#define	OPT_DISABLE_RCM	"disable_rcm"
#define	OPT_USE_DIFORCE	"use_diforce"

/* apid_t flags */
#define	FLAG_DISABLE_RCM	0x01
#define	FLAG_USE_DIFORCE	0x02

/* internal use for handling pathinfo */
#define	FLAG_CLIENT_DEV		0x04

/* Message ids */
typedef enum {

/* ERRORS */
ERR_UNKNOWN = -1,
ERR_OP_FAILED,
ERR_CMD_INVAL,
ERR_NOT_BUSAPID,
ERR_APID_INVAL,
ERR_NOT_BUSOP,
ERR_NOT_DEVOP,
ERR_UNAVAILABLE,
ERR_CTRLR_CRIT,
ERR_BUS_GETSTATE,
ERR_BUS_NOTCONNECTED,
ERR_BUS_CONNECTED,
ERR_BUS_QUIESCE,
ERR_BUS_UNQUIESCE,
ERR_BUS_CONFIGURE,
ERR_BUS_UNCONFIGURE,
ERR_DEV_CONFIGURE,
ERR_DEV_RECONFIGURE,
ERR_DEV_UNCONFIGURE,
ERR_DEV_REMOVE,
ERR_DEV_REPLACE,
ERR_DEV_INSERT,
ERR_DEV_GETSTATE,
ERR_RESET,
ERR_LIST,
ERR_MAYBE_BUSY,
ERR_BUS_DEV_MISMATCH,
ERR_VAR_RUN,
ERR_FORK,

/* Errors with arguments */
ERRARG_OPT_INVAL,
ERRARG_HWCMD_INVAL,
ERRARG_DEVINFO,
ERRARG_OPEN,
ERRARG_LOCK,
ERRARG_QUIESCE_LOCK,

/* RCM Errors */
ERR_RCM_HANDLE,
ERRARG_RCM_SUSPEND,
ERRARG_RCM_RESUME,
ERRARG_RCM_OFFLINE,
ERRARG_RCM_CLIENT_OFFLINE,
ERRARG_RCM_ONLINE,
ERRARG_RCM_REMOVE,

/* Commands */
CMD_INSERT_DEV,
CMD_REMOVE_DEV,
CMD_REPLACE_DEV,
CMD_LED_DEV,
CMD_LOCATOR_DEV,
CMD_RESET_DEV,
CMD_RESET_BUS,
CMD_RESET_ALL,

/* help messages */
MSG_HELP_HDR,
MSG_HELP_USAGE,

/* Hotplug messages */
MSG_INSDEV,
MSG_RMDEV,
MSG_REPLDEV,
MSG_WAIT_LOCK,

/* Hotplugging confirmation prompts */
CONF_QUIESCE_1,
CONF_QUIESCE_2,
CONF_UNQUIESCE,
CONF_NO_QUIESCE,

/* Misc. */
WARN_DISCONNECT,

/* HDD led/locator messages */
MSG_LED_HDR,
MSG_MISSING_LED_NAME,
MSG_MISSING_LED_MODE
} msgid_t;

typedef enum {
	LED_STR_FAULT,
	LED_STR_POWER,
	LED_STR_ATTN,
	LED_STR_ACTIVE,
	LED_STR_LOCATOR
} led_strid_t;

typedef enum {
	LED_MODE_OFF,
	LED_MODE_ON,
	LED_MODE_BLINK,
	LED_MODE_FAULTED,
	LED_MODE_UNK
} led_modeid_t;


typedef struct {
	msgid_t str_id;
	scfga_cmd_t cmd;
	scfga_ret_t (*fcn)(const char *, scfga_cmd_t, apid_t *, prompt_t *,
	    cfga_flags_t, char **);
} hw_cmd_t;

typedef struct {
	msgid_t msgid;
	int nargs;		/* Number of arguments following msgid */
	int intl;		/* Flag: if 1, internationalize */
	const char *msgstr;
} msgcvt_t;


#define	SLASH			"/"
#define	CFGA_DEV_DIR		"/dev/cfg"
#define	DEV_DIR			"/dev"
#define	DEVICES_DIR		"/devices"
#define	DEV_DSK			"/dev/dsk"
#define	DEV_RDSK		"/dev/rdsk"
#define	DEV_RMT			"/dev/rmt"
#define	DSK_DIR			"dsk"
#define	RDSK_DIR		"rdsk"
#define	RMT_DIR			"rmt"


#define	DYN_SEP			"::"
#define	MINOR_SEP		":"
#define	PATH_APID_DYN_SEP	","

#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	S_STR(x)	(((x) == NULL) ? "" : (x))


#define	IS_STUB_NODE(s)	(di_instance(s) == -1 &&	\
			    di_nodeid(s) == (DI_PROM_NODEID))

#define	GET_MSG_STR(i)		(str_tbl[msg_idx(i)].msgstr)

#define	GET_DYN(a)	(((a) != NULL) ? strstr((a), DYN_SEP) : (void *)0)

/*
 * The following macro removes the separator from the dynamic component.
 */
#define	DYN_TO_DYNCOMP(a)	((a) + strlen(DYN_SEP))

extern int _scfga_debug;

/*
 * Tracing/debugging macros
 */
#define	CFGA_TRACE1(args)	(void) ((_scfga_debug >= 1) ? fprintf args : 0)
#define	CFGA_TRACE2(args)	(void) ((_scfga_debug >= 2) ? fprintf args : 0)
#define	CFGA_TRACE3(args)	(void) ((_scfga_debug >= 3) ? fprintf args : 0)

/* Function prototypes */

/* bus/device ctl routines */
scfga_ret_t bus_change_state(cfga_cmd_t state_change_cmd,
    apid_t *apidp, struct cfga_confirm *confp, cfga_flags_t flags,
    char **errstring);
scfga_ret_t dev_change_state(cfga_cmd_t state_change_cmd,
    apid_t *apidp, cfga_flags_t flags, char **errstring);
scfga_ret_t dev_insert(const char *func, scfga_cmd_t cmd, apid_t *apidp,
    prompt_t *argsp, cfga_flags_t flags, char **errstring);
scfga_ret_t dev_replace(const char *func, scfga_cmd_t cmd, apid_t *apidp,
    prompt_t *argsp, cfga_flags_t flags, char **errstring);
scfga_ret_t dev_remove(const char *func, scfga_cmd_t cmd, apid_t *apidp,
    prompt_t *argsp, cfga_flags_t flags, char **errstring);
scfga_ret_t reset_common(const char *func, scfga_cmd_t cmd, apid_t *apidp,
    prompt_t *argsp, cfga_flags_t flags, char **errstring);
scfga_ret_t dev_led(const char *func, scfga_cmd_t cmd, apid_t *apidp,
    prompt_t *argsp, cfga_flags_t flags, char **errstring);
scfga_ret_t plat_dev_led(const char *func, scfga_cmd_t cmd, apid_t *apidp,
    prompt_t *argsp, cfga_flags_t flags, char **errstring);


/* List related routines */
scfga_ret_t do_list(apid_t *apidp, scfga_cmd_t cmd,
    ldata_list_t **llpp, int *nelem, char **errstring);
scfga_ret_t list_ext_postprocess(ldata_list_t **llpp, int nelem,
    cfga_list_data_t **ap_id_list, int *nlistp, char **errstring);
int stat_path_info(di_node_t root, void *arg, int *l_errnop);


/* Conversion routines */
scfga_ret_t make_hba_logid(const char *hba_phys, char **hba_logpp,
    int *l_errnop);
scfga_ret_t apid_to_path(const char *hba_phys, const char *dyncomp,
    char **pathpp, int *l_errnop);
scfga_ret_t make_dyncomp(di_node_t node, const char *physpath,
    char **dyncompp, int *l_errnop);
scfga_ret_t make_path_dyncomp(di_path_t path, char **dyncomp, int *l_errnop);


/* RCM routines */
scfga_ret_t scsi_rcm_suspend(char **rsrclist, char **errstring,
    cfga_flags_t flags, int pflag);
scfga_ret_t scsi_rcm_resume(char **rsrclist, char **errstring,
    cfga_flags_t flags, int pflag);
scfga_ret_t scsi_rcm_offline(char **rsrclist, char **errstring,
    cfga_flags_t flags);
scfga_ret_t scsi_rcm_online(char **rsrclist, char **errstring,
    cfga_flags_t flags);
scfga_ret_t scsi_rcm_remove(char **rsrclist, char **errstring,
    cfga_flags_t flags);


/* Utility routines */
scfga_ret_t physpath_to_devlink(char *physpath, char **linkpp, int *l_errnop,
    int match_minor);
scfga_ret_t apidt_create(const char *ap_id, apid_t *apidp,
    char **errstring);
void apidt_free(apid_t *apidp);
cfga_err_t err_cvt(scfga_ret_t err);
void list_free(ldata_list_t **llpp);
int known_state(di_node_t node);
scfga_ret_t devctl_cmd(const char *ap_id, scfga_cmd_t cmd,
    uint_t *statep, int *l_errnop);
scfga_ret_t path_apid_state_change(apid_t *apidp, scfga_cmd_t cmd,
    cfga_flags_t flags, char **errstring, int *l_errnop, msgid_t errid);
scfga_ret_t invoke_cmd(const char *func, apid_t *apidt, prompt_t *prp,
    cfga_flags_t flags, char **errstring);

void cfga_err(char **errstring, int use_errno, ...);
void cfga_msg(struct cfga_msg *msgp, ...);
void cfga_led_msg(struct cfga_msg *msgp, apid_t *apidp, led_strid_t,
    led_modeid_t);
char *cfga_str(int append_newline, ...);
int msg_idx(msgid_t msgid);
scfga_ret_t walk_tree(const char *physpath, void *arg, uint_t init_flags,
    walkarg_t *up, scfga_cmd_t cmd, int *l_errnop);
int hba_dev_cmp(const char *hba, const char *dev);
int dev_cmp(const char *dev1, const char *dev2, int match_minor);

extern msgcvt_t str_tbl[];

#ifdef __cplusplus
}
#endif

#endif /* _CFGA_SCSI_H */
