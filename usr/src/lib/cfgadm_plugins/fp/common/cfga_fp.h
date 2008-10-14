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

#ifndef _CFGA_FP_H
#define	_CFGA_FP_H



#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/mkdev.h>
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
#include <sys/mman.h>
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
#include <setjmp.h>
#include <signal.h>
#include <hbaapi.h>
#include <sys/fibre-channel/fcio.h>
#include <sys/fibre-channel/ulp/fcp_util.h>

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
	FPCFGA_ERR = -2,
	FPCFGA_LIB_ERR = -1,
	FPCFGA_OK = 0,
	FPCFGA_ACCESS_OK,
	FPCFGA_NACK,
	FPCFGA_BUSY,
	FPCFGA_SYSTEM_BUSY,
	FPCFGA_APID_NOCONFIGURE,
	FPCFGA_APID_NOACCESS,
	FPCFGA_APID_NOEXIST,
	FPCFGA_OPNOTSUPP,
	FPCFGA_PRIV,
	FPCFGA_UNLOCKED,
	FPCFGA_NO_REC,
	FPCFGA_OP_INTR,
	FPCFGA_DB_INVAL,
	FPCFGA_CONF_OK_UPD_REP_FAILED,
	FPCFGA_UNCONF_OK_UPD_REP_FAILED,
	FPCFGA_INVALID_PATH,
	FPCFGA_VHCI_GET_PATHLIST_FAILED,
	FPCFGA_XPORT_NOT_IN_PHCI_LIST,
	FPCFGA_UNKNOWN_ERR,
	FPCFGA_FCP_TGT_SEND_SCSI_FAILED,
	FPCFGA_FCP_SEND_SCSI_DEV_NOT_TGT
} fpcfga_ret_t;

/* Commands used internally */
typedef enum {
	FPCFGA_INVAL_CMD = -1,
	FPCFGA_DEV_OP = 0,
	FPCFGA_BUS_OP,
	FPCFGA_STAT_FC_DEV,
	FPCFGA_STAT_FCA_PORT,
	FPCFGA_STAT_ALL,
	FPCFGA_GET_DEVPATH,
	FPCFGA_INSERT_DEV,
	FPCFGA_REMOVE_DEV,
	FPCFGA_REPLACE_DEV,
	FPCFGA_WALK_NODE,
	FPCFGA_WALK_MINOR,
	FPCFGA_BUS_QUIESCE,
	FPCFGA_BUS_UNQUIESCE,
	FPCFGA_BUS_GETSTATE,
	FPCFGA_DEV_GETSTATE,
	FPCFGA_BUS_CONFIGURE,
	FPCFGA_BUS_UNCONFIGURE,
	FPCFGA_DEV_CONFIGURE,
	FPCFGA_DEV_UNCONFIGURE,
	FPCFGA_DEV_REMOVE,
	FPCFGA_RESET_DEV,
	FPCFGA_RESET_BUS,
	FPCFGA_RESET_ALL,
	FPCFGA_READ,
	FPCFGA_WRITE
} fpcfga_cmd_t;

typedef enum {
	FPCFGA_TERMINATE = 0,
	FPCFGA_CONTINUE
} fpcfga_recur_t;


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
} walkmode_t;

typedef struct {
	uint_t flags;
	walkmode_t walkmode;
} walkarg_t;

typedef struct {
	char *phys;
	char *log;
	fpcfga_ret_t ret;
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

typedef struct luninfo_list {
	int 	lunnum;
	uint_t	node_state;
	uint_t	lun_flag;
	char	*path;
	struct luninfo_list *next;
} luninfo_list_t;

typedef struct {
	char		*xport_phys;
	char		*dyncomp;
	uint_t		flags;
	luninfo_list_t	*lunlist;	/* Singly linked list */
} apid_t;

/* Report luns names */
#define	FP_SCMD_REPORT_LUN	0xA0
#define	DEFAULT_NUM_LUN		1024
#define	REPORT_LUN_HDR_SIZE	8
#define	SAM_LUN_SIZE		8

#ifdef _BIG_ENDIAN
#define	htonll(x)	(x)
#define	ntohll(x)	(x)
#else
#define	htonll(x)   ((((unsigned long long)htonl(x)) << 32) + htonl(x >> 32))
#define	ntohll(x)   ((((unsigned long long)ntohl(x)) << 32) + ntohl(x >> 32))
#endif

typedef struct report_lun_resp {
	uint32_t	num_lun;
	uint32_t	reserved;
	longlong_t	lun_string[DEFAULT_NUM_LUN];
} report_lun_resp_t;

/*
 * Hardware options acceptable for fp plugin.
 * list related options are handled by getsupopts() and set to
 * index of array.
 */
#define	OPT_DEVINFO_FORCE	0
#define	OPT_SHOW_SCSI_LUN	1
#define	OPT_FCP_DEV		2
#define	OPT_DISABLE_RCM		0
#define	OPT_FORCE_UPDATE_REP	1
#define	OPT_NO_UPDATE_REP	2
#define	OPT_REMOVE_UNUSABLE_SCSI_LUN	3
#define	OPT_REMOVE_UNUSABLE_FCP_DEV	4

/* walk tree flag */
#define	FLAG_PATH_INFO_WALK	0x00000001

/* apid_t flags */
#define	FLAG_DISABLE_RCM	0x00000001
#define	FLAG_FORCE_UPDATE_REP	0x00000010
#define	FLAG_NO_UPDATE_REP	0x00000100
#define	FLAG_DYN_AP_CONFIGURED	0x00001000
#define	FLAG_DEVINFO_FORCE	0x00010000
#define	FLAG_FCP_DEV		0x00100000
#define	FLAG_REMOVE_UNUSABLE_FCP_DEV	0x01000000

/* apid_t lun flags */
#define	FLAG_SKIP_RCMOFFLINE	0x00000001
#define	FLAG_SKIP_RCMREMOVE	0x00000010
#define	FLAG_SKIP_ONLINEOTHERS	0x00000100

/* define for peripheral qualifier mask */
#define	FP_PERI_QUAL_MASK	0xE0

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
ERR_DEV_UNCONFIGURE,
ERR_FCA_CONFIGURE,
ERR_FCA_UNCONFIGURE,
ERR_DEV_REPLACE,
ERR_DEV_INSERT,
ERR_DEV_GETSTATE,
ERR_RESET,
ERR_LIST,
ERR_FC,
ERR_FC_GET_DEVLIST,
ERR_FC_GET_FIRST_DEV,
ERR_FC_GET_NEXT_DEV,
ERRARG_FC_DEV_MAP_INIT,
ERRARG_FC_PROP_LOOKUP_BYTES,
ERRARG_FC_INQUIRY,
ERRARG_FC_REP_LUNS,
ERRARG_FC_TOPOLOGY,
ERRARG_PATH_TOO_LONG,
ERRARG_INVALID_PATH,
ERRARG_OPENDIR,
ERRARG_VHCI_GET_PATHLIST,
ERRARG_XPORT_NOT_IN_PHCI_LIST,
ERR_SIG_STATE,
ERR_MAYBE_BUSY,
ERR_BUS_DEV_MISMATCH,
ERR_GET_DEVLIST,
ERR_MEM_ALLOC,
ERR_DEVCTL_OFFLINE,
ERR_UPD_REP,
ERR_CONF_OK_UPD_REP,
ERR_UNCONF_OK_UPD_REP,
ERR_PARTIAL_SUCCESS,
ERR_HBA_LOAD_LIBRARY,
ERR_MATCHING_HBA_PORT,
ERR_NO_ADAPTER_FOUND,

/* Errors with arguments */
ERRARG_OPT_INVAL,
ERRARG_HWCMD_INVAL,
ERRARG_DEVINFO,
ERRARG_NOT_IN_DEVLIST,
ERRARG_NOT_IN_DEVINFO,
ERRARG_DI_GET_PROP,
ERRARG_DC_DDEF_ALLOC,
ERRARG_DC_BYTE_ARRAY,
ERRARG_DC_BUS_ACQUIRE,
ERRARG_BUS_DEV_CREATE,
ERRARG_BUS_DEV_CREATE_UNKNOWN,
ERRARG_DEV_ACQUIRE,
ERRARG_DEV_REMOVE,

/* RCM Errors */
ERR_RCM_HANDLE,
ERRARG_RCM_SUSPEND,
ERRARG_RCM_RESUME,
ERRARG_RCM_OFFLINE,
ERRARG_RCM_ONLINE,
ERRARG_RCM_REMOVE,
ERRARG_RCM_INFO,

/* Commands */
CMD_INSERT_DEV,
CMD_REMOVE_DEV,
CMD_REPLACE_DEV,
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

/* Hotplugging confirmation prompts */
CONF_QUIESCE_1,
CONF_QUIESCE_2,
CONF_UNQUIESCE,

/* Misc. */
WARN_DISCONNECT
} msgid_t;

typedef struct {
	msgid_t str_id;
	fpcfga_cmd_t cmd;
	fpcfga_ret_t (*fcn)(fpcfga_cmd_t, apid_t *, prompt_t *, char **);
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
#define	LUN_COMP_SEP		","
#define	MINOR_SEP		":"

#define	S_FREE(x)	(((x) != NULL) ? (free(x), (x) = NULL) : (void *)0)
#define	S_STR(x)	(((x) == NULL) ? "" : (x))


#define	IS_STUB_NODE(s)	(di_instance(s) == -1 &&	\
			    di_nodeid(s) == (DI_PROM_NODEID))

#define	GET_MSG_STR(i)		(str_tbl[msg_idx(i)].msgstr)

#define	GET_DYN(a)	(((a) != NULL) ? strstr((a), DYN_SEP) : (void *)0)
#define	GET_LUN_DYN(a)	(((a) != NULL) ? strstr((a), LUN_COMP_SEP) : (void *)0)

/*
 * The following macro removes the separator from the dynamic component.
 */
#define	DYN_TO_DYNCOMP(a)	((a) + strlen(DYN_SEP))
#define	LUN_DYN_TO_LUNCOMP(a)	((a) + strlen(LUN_COMP_SEP))

/*
 * Property names
 */
#define	PORT_WWN_PROP	"port-wwn"
#define	LUN_GUID_PROP	"client-guid"
#define	LUN_PROP	"lun"

#define	WWN_S_LEN	17	/* NULL terminated string */
#define	WWN_SIZE	8
/* Constants used for repository updates */
#define	ADD_ENTRY	0
#define	REMOVE_ENTRY	1

#define	FAB_REPOSITORY_DIR	"/etc/cfg/fp"
#define	FAB_REPOSITORY		"/etc/cfg/fp/fabric_WWN_map"
#define	TMP_FAB_REPOSITORY	"/etc/cfg/fp/fabric_WWN_map.tmp"
#define	OLD_FAB_REPOSITORY	"/etc/cfg/fp/fabric_WWN_map.old"

/* MPXIO VHCI root dir */
#define	SCSI_VHCI_ROOT		"/devices/scsi_vhci/"
#define	SCSI_VHCI_DRVR		"scsi_vhci"
#define	HBA_MAX_RETRIES		10

/* Function prototypes */

fpcfga_ret_t get_report_lun_data(const char *xport_phys,
	const char *dyncomp, int *num_luns, report_lun_resp_t **resp_buf,
	struct scsi_extended_sense *sense, int *l_errnop);
/* Functions in cfga_cs.c */
fpcfga_ret_t
dev_change_state(cfga_cmd_t, apid_t *, la_wwn_t *, cfga_flags_t, char **,
    HBA_HANDLE handle, HBA_PORTATTRIBUTES portAttrs);
fpcfga_ret_t
fca_change_state(cfga_cmd_t, apid_t *, cfga_flags_t, char **);

/* Functions in cfga_rep.c */
int update_fabric_wwn_list(int, const char *, char **);

fpcfga_ret_t dev_insert(fpcfga_cmd_t cmd, apid_t *apidp, prompt_t *argsp,
    char **errstring);
fpcfga_ret_t dev_replace(fpcfga_cmd_t cmd, apid_t *apidp, prompt_t *argsp,
    char **errstring);
fpcfga_ret_t dev_remove(fpcfga_cmd_t cmd, apid_t *apidp, prompt_t *argsp,
    char **errstring);
fpcfga_ret_t reset_common(fpcfga_cmd_t cmd, apid_t *apidp, prompt_t *argsp,
    char **errstring);


/* List related routines */
fpcfga_ret_t do_list(apid_t *apidp, fpcfga_cmd_t cmd,
    ldata_list_t **ldatalistp, int *nelem, char **errstring);
fpcfga_ret_t do_list_FCP_dev(const char *ap_id, uint_t flags, fpcfga_cmd_t cmd,
	ldata_list_t **llpp, int *nelemp, char **errstring);
fpcfga_ret_t list_ext_postprocess(ldata_list_t **ldatalistp, int nelem,
    cfga_list_data_t **ap_id_list, int *nlistp, char **errstring);
int stat_path_info_node(di_node_t root, void *arg, int *l_errnop);

/* Conversion routines */
fpcfga_ret_t make_xport_logid(const char *xport_phys, char **xport_logpp,
    int *l_errnop);
fpcfga_ret_t dyn_apid_to_path(const char *xport_phys, const char *dyncomp,
	struct luninfo_list **lunlistpp, int *l_errnop);
void cvt_lawwn_to_dyncomp(const la_wwn_t *pwwn, char **dyncomp, int *l_errnop);
int cvt_dyncomp_to_lawwn(const char *dyncomp, la_wwn_t *port_wwn);
fpcfga_ret_t make_dyncomp_from_dinode(const di_node_t node, char **dyncompp,
	int *l_errnop);
fpcfga_ret_t make_portwwn_luncomp_from_dinode(const di_node_t node,
	char **dyncompp, int **luncompp, int *l_errnop);
fpcfga_ret_t make_portwwn_luncomp_from_pinode(const di_path_t pinode,
	char **dyncompp, int **luncompp, int *l_errnop);
fpcfga_ret_t construct_nodepath_from_dinode(const di_node_t node,
	char **node_pathp, int *l_errnop);
u_longlong_t wwnConversion(uchar_t *wwn);


/* Functions in cfga_rcm.c */
fpcfga_ret_t fp_rcm_offline(char *, char **, cfga_flags_t);
fpcfga_ret_t fp_rcm_online(char *, char **, cfga_flags_t);
fpcfga_ret_t fp_rcm_remove(char *, char **, cfga_flags_t);
fpcfga_ret_t fp_rcm_suspend(char *, char *, char **, cfga_flags_t);
fpcfga_ret_t fp_rcm_resume(char *, char *, char **, cfga_flags_t);
fpcfga_ret_t fp_rcm_info(char *, char **, char **);

/* Utility routines */
fpcfga_ret_t physpath_to_devlink(const char *basedir, char *xport_phys,
    char **xport_logpp, int *l_errnop, int match_minor);
fpcfga_ret_t recurse_dev(const char *basedir, void *arg,
    fpcfga_recur_t (*fcn)(const char *lpath, void *arg));
fpcfga_ret_t apidt_create(const char *ap_id, apid_t *apidp,
    char **errstring);
void apidt_free(apid_t *apidp);
cfga_err_t err_cvt(fpcfga_ret_t err);
void list_free(ldata_list_t **llpp);
int known_state(di_node_t node);

fpcfga_ret_t devctl_cmd(const char *ap_id, fpcfga_cmd_t cmd,
    uint_t *statep, int *l_errnop);
fpcfga_ret_t invoke_cmd(const char *func, apid_t *apidt, prompt_t *prp,
    char **errstring);

void cfga_err(char **errstring, int use_errno, ...);
void cfga_msg(struct cfga_msg *msgp, ...);
char *cfga_str(int append_newline, ...);
int msg_idx(msgid_t msgid);
fpcfga_ret_t walk_tree(const char *physpath, void *arg, uint_t init_flags,
    walkarg_t *up, fpcfga_cmd_t cmd, int *l_errnop);
int hba_dev_cmp(const char *hba, const char *dev);
int dev_cmp(const char *dev1, const char *dev2, int match_minor);
char *pathdup(const char *path, int *l_errnop);
int getPortAttrsByWWN(HBA_HANDLE handle, HBA_WWN wwn,
	HBA_PORTATTRIBUTES *attrs);
int getDiscPortAttrs(HBA_HANDLE handle, int portIndex,
	int discIndex, HBA_PORTATTRIBUTES *attrs);
int getAdapterPortAttrs(HBA_HANDLE handle, int portIndex,
	HBA_PORTATTRIBUTES *attrs);
int getAdapterAttrs(HBA_HANDLE handle, HBA_ADAPTERATTRIBUTES *attrs);
fpcfga_ret_t findMatchingAdapterPort(char *portPath,
	HBA_HANDLE *matchingHandle, int *matchingPortIndex,
	HBA_PORTATTRIBUTES *matchingPortAttrs, char **errstring);

extern msgcvt_t str_tbl[];

#ifdef __cplusplus
}
#endif

#endif /* _CFGA_FP_H */
