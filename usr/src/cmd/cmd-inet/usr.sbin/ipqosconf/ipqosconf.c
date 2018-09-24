/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* enable debug output and some debug asserts */
#undef	_IPQOS_CONF_DEBUG

#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>
#include <signal.h>
#include <strings.h>
#include <sys/nvpair.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/socket.h>
#include <limits.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <libipp.h>
#include <ipp/ipp_config.h>
#include <ipp/ipgpc/ipgpc.h>
#include <ipp/ipp.h>
#ifdef	_IPQOS_CONF_DEBUG
#include <assert.h>
#endif
#include <sys/sockio.h>
#include <syslog.h>
#include <stdarg.h>
#include <libintl.h>
#include <locale.h>
#include <pwd.h>
#include "ipqosconf.h"

#if	defined(_IPQOS_CONF_DEBUG)

/* debug level */
static int ipqosconf_dbg_flgs =
/*
 */
RBK |
MHME |
KRET |
DIFF |
APPLY |
L2 |
L1 |
L0 |
0;



#define	IPQOSCDBG0(lvl, x)\
	if (lvl & ipqosconf_dbg_flgs)\
		(void) fprintf(stderr, x)

#define	IPQOSCDBG1(lvl, x, y)\
	if (lvl & ipqosconf_dbg_flgs)\
		(void) fprintf(stderr, x, y)

#define	IPQOSCDBG2(lvl, x, y, z)\
	if (lvl & ipqosconf_dbg_flgs)\
		(void) fprintf(stderr, x, y, z)

#define	IPQOSCDBG3(lvl, x, y, z, a)\
	if (lvl & ipqosconf_dbg_flgs)\
		(void) fprintf(stderr, x, y, z, a)

#define	IPQOSCDBG4(lvl, x, y, z, a, b)\
	if (lvl & ipqosconf_dbg_flgs)\
		(void) fprintf(stderr, x, y, z, a, b)

#define	IPQOSCDBG5(lvl, x, y, z, a, b, c)\
	if (lvl & ipqosconf_dbg_flgs)\
		(void) fprintf(stderr, x, y, z, a, b, c)

#else	/* defined(_IPQOS_CONF_DEBUG) && !defined(lint) */

#define	IPQOSCDBG0(lvl, x)
#define	IPQOSCDBG1(lvl, x, y)
#define	IPQOSCDBG2(lvl, x, y, z)
#define	IPQOSCDBG3(lvl, x, y, z, a)
#define	IPQOSCDBG4(lvl, x, y, z, a, b)
#define	IPQOSCDBG5(lvl, x, y, z, a, b, c)

#endif	/* defined(_IPQOS_CONF_DEBUG) */



/* function prototypes */

static int modify_params(char *, nvlist_t **, int, boolean_t);
static int add_class(char *, char *, int, boolean_t, char *);
static int modify_class(char *, char *, int, boolean_t, char *,
    enum ipp_flags);
static int remove_class(char *, char *, int, enum ipp_flags);
static int add_filter(char *, ipqos_conf_filter_t *, int);
static int modify_filter(char *, ipqos_conf_filter_t *, int);
static int remove_filter(char *, char *, int, int);
static boolean_t arrays_equal(int *, int *, uint32_t);
static int diffclass(ipqos_conf_class_t *, ipqos_conf_class_t *);
static int diffparams(ipqos_conf_params_t *, ipqos_conf_params_t *, char *);
static int difffilter(ipqos_conf_filter_t *, ipqos_conf_filter_t *, char *);
static int add_filters(ipqos_conf_filter_t *, char *, int, boolean_t);
static int add_classes(ipqos_conf_class_t *, char *,  int, boolean_t);
static int modify_items(ipqos_conf_action_t *);
static int add_items(ipqos_conf_action_t *, boolean_t);
static int add_item(ipqos_conf_action_t *, boolean_t);
static int remove_items(ipqos_conf_action_t *, boolean_t);
static int remove_item(ipqos_conf_action_t *, boolean_t);
static int undo_modifys(ipqos_conf_action_t *, ipqos_conf_action_t *);
static int applydiff(ipqos_conf_action_t *, ipqos_conf_action_t *);
static int rollback(ipqos_conf_action_t *, ipqos_conf_action_t *);
static int rollback_recover(ipqos_conf_action_t *);
static ipqos_conf_class_t *classexist(char *, ipqos_conf_class_t *);
static ipqos_conf_filter_t *filterexist(char *, int, ipqos_conf_filter_t *);
static ipqos_conf_action_t *actionexist(char *, ipqos_conf_action_t *);
static int diffnvlists(nvlist_t *, nvlist_t *, char *, int *, place_t);
static int diffaction(ipqos_conf_action_t *, ipqos_conf_action_t *);
static int diffconf(ipqos_conf_action_t *, ipqos_conf_action_t *);
static int readllong(char *, long long *, char **);
static int readuint8(char *, uint8_t *, char **);
static int readuint16(char *, uint16_t *, char **);
static int readint16(char *, int16_t *, char **);
static int readint32(char *, int *, char **);
static int readuint32(char *, uint32_t *, char **);
static int readbool(char *, boolean_t *);
static void setmask(int, in6_addr_t *, int);
static int readtoken(FILE *, char **);
static nvpair_t *find_nvpair(nvlist_t *, char *);
static char *prepend_module_name(char *, char *);
static int readnvpair(FILE *, FILE *, nvlist_t **, nvpair_t **,
    ipqos_nvtype_t *, place_t, char *);
static int add_aref(ipqos_conf_act_ref_t **, char *, char *);
static int readparams(FILE *, FILE *, char *, ipqos_conf_params_t *);
static int readclass(FILE *, char *, ipqos_conf_class_t **, char **, int);
static int readfilter(FILE *, FILE *, char *, ipqos_conf_filter_t **, char **,
    int);
static FILE *validmod(char *, int *);
static int readaction(FILE *, ipqos_conf_action_t **);
static int actions_unique(ipqos_conf_action_t *, char **);
static int validconf(ipqos_conf_action_t *, int);
static int readconf(FILE *, ipqos_conf_action_t **);
static int flush(boolean_t *);
static int atomic_flush(boolean_t);
static int flushconf();
static int writeconf(ipqos_conf_action_t *, char *);
static int commitconf();
static int applyconf(char *ifile);
static int block_all_signals();
static int restore_all_signals();
static int unlock(int fd);
static int lock();
static int viewconf(int);
static void usage();
static int valid_name(char *);
static int in_cycle(ipqos_conf_action_t *);
static int readtype(FILE *, char *, char *, ipqos_nvtype_t *, str_val_nd_t **,
    char *, boolean_t, place_t *);
static int read_int_array_info(char *, str_val_nd_t **, uint32_t *, int *,
    int *, char *);
static str_val_nd_t *read_enum_nvs(char *, char *);
static int add_str_val_entry(str_val_nd_t **, char *, uint32_t);
static void free_str_val_entrys(str_val_nd_t *);
static void get_str_val_value_range(str_val_nd_t *, int *, int *);
static int read_enum_value(FILE *, char *, str_val_nd_t *, uint32_t *);
static int read_mapped_values(FILE *, nvlist_t **, char *, char *,
    int);
static int read_int_array(FILE *, char *, int **, uint32_t, int, int,
    str_val_nd_t *);
static int str_val_list_lookup(str_val_nd_t *, char *, uint32_t *);
static int parse_kparams(char *, ipqos_conf_params_t *, nvlist_t *);
static int parse_kclass(ipqos_conf_class_t *, nvlist_t *);
static int parse_kfilter(ipqos_conf_filter_t *, nvlist_t *);
static int parse_kaction(nvlist_t *, ipqos_actinfo_prm_t *);
static int readkconf(ipqos_conf_action_t **);
static void print_int_array(FILE *, int *, uint32_t, int, int, str_val_nd_t *,
    int);
static void printrange(FILE *fp, uint32_t, uint32_t);
static void printenum(FILE *, uint32_t, str_val_nd_t *);
static void printproto(FILE *, uint8_t);
static void printport(FILE *, uint16_t);
static int printnvlist(FILE *, char *, nvlist_t *, int, ipqos_conf_filter_t *,
    int, place_t);
static int virtual_action(char *);
static void free_arefs(ipqos_conf_act_ref_t *);
static void print_action_nm(FILE *, char *);
static int add_orig_ipqosconf(nvlist_t *);
static char *get_originator_nm(uint32_t);
static void mark_classes_filters_new(ipqos_conf_action_t *);
static void mark_classes_filters_del(ipqos_conf_action_t *);
static void mark_config_new(ipqos_conf_action_t *);
static int printifname(FILE *, int);
static int readifindex(char *, int *);
static void cleanup_string_table(char **, int);
static int domultihome(ipqos_conf_filter_t *, ipqos_conf_filter_t **,
    boolean_t);
static int dup_filter(ipqos_conf_filter_t *, ipqos_conf_filter_t **, int, int,
    void *, void *, int);
static void free_actions(ipqos_conf_action_t *);
static ipqos_conf_filter_t *alloc_filter();
static void free_filter(ipqos_conf_filter_t *);
static int read_curl_begin(FILE *);
static ipqos_conf_class_t *alloc_class(void);
static int diffclasses(ipqos_conf_action_t *old, ipqos_conf_action_t *new);
static int difffilters(ipqos_conf_action_t *old, ipqos_conf_action_t *new);
static int dup_class(ipqos_conf_class_t *src, ipqos_conf_class_t **dst);
static int add_action(ipqos_conf_action_t *act);
static int masktocidr(int af, in6_addr_t *mask);
static int read_perm_items(int, FILE *, char *, char ***, int *);
static int in_string_table(char *stable[], int size, char *string);
static void list_end(ipqos_list_el_t **listp, ipqos_list_el_t ***lendpp);
static void add_to_list(ipqos_list_el_t **listp, ipqos_list_el_t *el);
static int read_cfile_ver(FILE *, char *);
static char *quote_ws_string(const char *);
static int read_tfile_ver(FILE *, char *, char *);
static int ver_str_to_int(char *);
static void printuser(FILE *fp, uid_t uid);
static int readuser(char *str, uid_t *uid);

/*
 * macros to call list functions with the more complex list element type
 * cast to the skeletal type iqpos_list_el_t.
 */
#define	LIST_END(list, end)\
	list_end((ipqos_list_el_t **)list,  (ipqos_list_el_t ***)end)
#define	ADD_TO_LIST(list, el)\
	add_to_list((ipqos_list_el_t **)list, (ipqos_list_el_t *)el)

/*
 *	Macros to produce a quoted string containing the value of a
 *	preprocessor macro. For example, if SIZE is defined to be 256,
 *	VAL2STR(SIZE) is "256". This is used to construct format
 *	strings for scanf-family functions below.
 */
#define	QUOTE(x)	#x
#define	VAL2STR(x)	QUOTE(x)


/* globals */

/* table of supported parameter types and enum value */
static str_val_t nv_types[] = {
{"uint8",		IPQOS_DATA_TYPE_UINT8},
{"int16",		IPQOS_DATA_TYPE_INT16},
{"uint16",		IPQOS_DATA_TYPE_UINT16},
{"int32",		IPQOS_DATA_TYPE_INT32},
{"uint32",		IPQOS_DATA_TYPE_UINT32},
{"boolean",		IPQOS_DATA_TYPE_BOOLEAN},
{"string",		IPQOS_DATA_TYPE_STRING},
{"action",		IPQOS_DATA_TYPE_ACTION},
{"address",		IPQOS_DATA_TYPE_ADDRESS},
{"port",		IPQOS_DATA_TYPE_PORT},
{"protocol",		IPQOS_DATA_TYPE_PROTO},
{"enum",		IPQOS_DATA_TYPE_ENUM},
{"ifname",		IPQOS_DATA_TYPE_IFNAME},
{"mindex",		IPQOS_DATA_TYPE_M_INDEX},
{"int_array",		IPQOS_DATA_TYPE_INT_ARRAY},
{"user",		IPQOS_DATA_TYPE_USER},
{"",			0}
};

/* table of name to id mappings for originator field */

static str_val_t originators[] = {
{IPP_CONFIG_NAME_PERMANENT,	IPP_CONFIG_PERMANENT},
{IPP_CONFIG_NAME_IPQOSCONF,	IPP_CONFIG_IPQOSCONF},
{IPP_CONFIG_NAME_FTPCL,		IPP_CONFIG_FTPCL},
{"", -1}
};

/* current parse line */
static int lineno;

/* verbose output flag */
static int verbose;

/* use syslog for msg reporting flag */
static int use_syslog;

#ifdef	_IPQOS_CONF_DEBUG
/*
 * flag used to indicate that a rollback should be carried out regardless.
 * Only settable during debug.
 */
static int force_rback = 0;
#endif	/* _IPQOS_CONF_DEBUG */

/*
 * delivers messages to either syslog or stderr, dependant upon the
 * the state of the flags use_syslog and verbose. The type
 * of the msg as given in msg_type is indicated in the output msg.
 *
 * valid message types are:
 * o  MT_ERROR (standard error message)
 * o  MT_ENOSTR (error message with system error string appended)
 * o  MT_WARNING (warning message)
 * o  MT_LOG (logging message)
 *
 * Log messages only go to syslog. Warning messages only go to stderr
 * and only when the verbose flag is set. All other messages go by default
 * to the console; to syslog if syslog flag set, and to both if both
 * syslog and verbose are set.
 *
 */
/*PRINTFLIKE2*/
static void
ipqos_msg(enum msg_type msgt, char *format, ...)
{
	va_list ap;
	char str_buf[IPQOS_MSG_BUF_SZ];
	char fmt_buf[IPQOS_MSG_BUF_SZ];
	char *cp;

	IPQOSCDBG0(L1, "In ipqos_msg:\n");

	va_start(ap, format);

	/*
	 * send msgs to syslog if use_syslog set (except warning msgs),
	 * or a log msg.
	 */
	if ((use_syslog && (msgt != MT_WARNING)) || msgt == MT_LOG) {

		/* fill in format string */
		(void) vsnprintf(str_buf, IPQOS_MSG_BUF_SZ, format, ap);

		/*
		 * print message to syslog with appropriate severity
		 */
		if (msgt == MT_ERROR) {
			syslog(LOG_ERR, str_buf);
		} else if (msgt == MT_LOG) {
			syslog(LOG_INFO, str_buf);
		/*
		 * for errno message type suffix with %m for syslog to
		 * interpret.
		 */
		} else if (msgt == MT_ENOSTR) {
			/*
			 * remove any newline in message parameter.
			 * syslog will reapply a newline for us later.
			 */
			if ((cp = strchr(str_buf, '\n')) != NULL)
				*cp = '\0';
			(void) strlcat(str_buf, ": %m", IPQOS_MSG_BUF_SZ);
			syslog(LOG_ERR, str_buf);
		}
	}

	/*
	 * send msgs to stderr if use_syslog not set (except log msgs), or
	 * if verbose set.
	 */
	if ((!use_syslog && (msgt != MT_LOG)) || (verbose)) {

		/*
		 * prefix message with appropriate severity string
		 */
		if (msgt == MT_ERROR) {
			(void) strlcpy(fmt_buf, gettext("Error: "),
			    IPQOS_MSG_BUF_SZ);
		} else if (msgt == MT_WARNING) {
			if (!verbose) { /* don't show warn msg if !verbose */
				va_end(ap);
				return;
			}
			(void) strlcpy(fmt_buf, gettext("Warning: "),
			    IPQOS_MSG_BUF_SZ);
		} else if (msgt == MT_ENOSTR) {
			(void) strlcpy(fmt_buf, gettext("Error: "),
			    IPQOS_MSG_BUF_SZ);
		} else if (msgt == MT_LOG) {
			(void) strlcpy(fmt_buf, gettext("Notice: "),
			    IPQOS_MSG_BUF_SZ);
		}
		(void) strlcat(fmt_buf, format, IPQOS_MSG_BUF_SZ);

		/*
		 * for errno message type suffix message with errno string
		 */
		if (msgt == MT_ENOSTR) {
			/*
			 * get rid of any newline in passed message.
			 * we'll apply another later.
			 */
			if ((cp = strchr(fmt_buf, '\n')) != NULL)
				*cp = '\0';
			(void) strlcat(fmt_buf, ": ", IPQOS_MSG_BUF_SZ);
			(void) strlcat(fmt_buf, strerror(errno),
			    IPQOS_MSG_BUF_SZ);
		}

		/*
		 * append a newline to message if not one already.
		 */
		if ((cp = strchr(fmt_buf, '\n')) == NULL)
			(void) strlcat(fmt_buf, "\n", IPQOS_MSG_BUF_SZ);

		(void) vfprintf(stderr, fmt_buf, ap);
	}

	va_end(ap);
}

/* **************** kernel filter/class/params manipulation fns *********** */


/*
 * modify the kernel parameters of the action action_nm using the nvlist
 * parameter nvl and setting the stats according to stats_enable.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */

static int
modify_params(
char *action_name,
nvlist_t **nvl,
int module_version,
boolean_t stats_enable)
{

	int res;
	int created = 0;

	IPQOSCDBG1(APPLY, "In modify_params: action: %s\n", action_name);

	/* create nvlist if NULL */
	if (*nvl == NULL) {
		created++;
		res = nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
		if (res != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_alloc");
			return (IPQOS_CONF_ERR);
		}
	}

	/* add params modify config type */
	res = nvlist_add_byte(*nvl, IPP_CONFIG_TYPE, IPP_SET);
	if (res != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		goto fail;
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(*nvl, IPP_MODULE_VERSION,
	    (uint32_t)module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		goto fail;
	}

	/* add stats_enable */
	res = nvlist_add_uint32(*nvl, IPP_ACTION_STATS_ENABLE,
	    (uint32_t)stats_enable);
	if (res != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		goto fail;
	}

	/* add ipqosconf as originator */
	res = add_orig_ipqosconf(*nvl);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* call lib to do modify */
	res = ipp_action_modify(action_name, nvl, 0);
	if (res != 0) {

		/* invalid parameters */

		if (errno == EINVAL) {
			ipqos_msg(MT_ERROR,
			    gettext("Invalid parameters for action %s.\n"),
			    action_name);


		} else if (errno == ENOENT) {
			ipqos_msg(MT_ERROR,
			    gettext("Mandatory parameter missing for "
			    "action %s.\n"), action_name);


		} else {	/* unexpected error */
			ipqos_msg(MT_ERROR, gettext("Failed to modify action "
			    "%s parameters: %s.\n"), action_name,
			    strerror(errno));
		}

		goto fail;
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	if (created && *nvl != NULL) {
		nvlist_free(*nvl);
		*nvl = NULL;
	}
	return (IPQOS_CONF_ERR);
}

/*
 * add a class to the kernel action action_name called class_name with
 * stats set according to stats_enable and the first action set to
 * first_action.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
add_class(
char *action_name,
char *class_name,
int module_version,
boolean_t stats_enable,
char *first_action)
{

	nvlist_t *nvl;

	IPQOSCDBG4(APPLY, "add_class: action: %s, class: %s, "
	    "first_action: %s, stats: %s\n", action_name, class_name,
	    first_action, (stats_enable == B_TRUE ? "true" : "false"));


	/* create nvlist */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_alloc");
		return (IPQOS_CONF_ERR);
	}

	/* add 'add class' config type */
	if (nvlist_add_byte(nvl, IPP_CONFIG_TYPE, CLASSIFIER_ADD_CLASS) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		goto fail;
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(nvl, IPP_MODULE_VERSION,
	    (uint32_t)module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		goto fail;
	}

	/* add class name */
	if (nvlist_add_string(nvl, CLASSIFIER_CLASS_NAME, class_name) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		goto fail;
	}

	/* add next action */
	if (nvlist_add_string(nvl, CLASSIFIER_NEXT_ACTION, first_action) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		goto fail;
	}

	/* add stats_enable */
	if (nvlist_add_uint32(nvl, CLASSIFIER_CLASS_STATS_ENABLE,
	    (uint32_t)stats_enable) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		goto fail;
	}

	/* add ipqosconf as originator */
	if (add_orig_ipqosconf(nvl) != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* call lib to do modify */
	if (ipp_action_modify(action_name, &nvl, 0) != 0) {

		/* ipgpc max classes */

		if (errno == ENOSPC &&
		    strcmp(action_name, IPGPC_CLASSIFY) == 0) {
			ipqos_msg(MT_ERROR,
			    gettext("Max number of classes reached in %s.\n"),
			    IPGPC_NAME);

		/* other errors */

		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Failed to create class %s in action "
			    "%s: %s.\n"), class_name, action_name,
			    strerror(errno));
		}

		goto fail;
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	nvlist_free(nvl);
	return (IPQOS_CONF_ERR);
}


/*
 * modify the class in the kernel action action_name called class_name with
 * stats set according to stats_enable and the first action set to
 * first_action.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
modify_class(
char *action_name,
char *class_name,
int module_version,
boolean_t stats_enable,
char *first_action,
enum ipp_flags flags)
{

	nvlist_t *nvl;

	IPQOSCDBG5(APPLY, "modify_class: action: %s, class: %s, first: %s, "
	    "stats: %s, flags: %x\n", action_name, class_name, first_action,
	    stats_enable == B_TRUE ? "true" : "false", flags);


	/* create nvlist */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_alloc");
		return (IPQOS_CONF_ERR);
	}

	/* add 'modify class' config type */
	if (nvlist_add_byte(nvl, IPP_CONFIG_TYPE, CLASSIFIER_MODIFY_CLASS) !=
	    0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		goto fail;
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(nvl, IPP_MODULE_VERSION,
	    (uint32_t)module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		goto fail;
	}

	/* add class name */
	if (nvlist_add_string(nvl, CLASSIFIER_CLASS_NAME, class_name) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		goto fail;
	}

	/* add next action */
	if (nvlist_add_string(nvl, CLASSIFIER_NEXT_ACTION, first_action) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		goto fail;
	}

	/* add stats enable */
	if (nvlist_add_uint32(nvl, CLASSIFIER_CLASS_STATS_ENABLE,
	    (uint32_t)stats_enable) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		goto fail;
	}

	/* add originator ipqosconf */
	if (add_orig_ipqosconf(nvl) != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* call lib to do modify */
	if (ipp_action_modify(action_name, &nvl, flags) != 0) {

		/* generic error message */

		ipqos_msg(MT_ERROR,
		    gettext("Modifying class %s in action %s failed: %s.\n"),
		    class_name, action_name, strerror(errno));

		goto fail;
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	nvlist_free(nvl);
	return (IPQOS_CONF_ERR);
}

/*
 * removes the class class_name from the kernel action action_name. The
 * flags argument can currently be set to IPP_ACTION_DESTROY which will
 * result in the action this class references being destroyed.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
remove_class(
char *action_name,
char *class_name,
int module_version,
enum ipp_flags flags)
{

	nvlist_t *nvl;

	IPQOSCDBG3(APPLY, "remove_class: action: %s, class: %s, "
	    "flags: %x\n", action_name, class_name, flags);

	/* allocate nvlist */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_alloc");
		return (IPQOS_CONF_ERR);
	}

	/* add 'remove class' config type */
	if (nvlist_add_byte(nvl, IPP_CONFIG_TYPE, CLASSIFIER_REMOVE_CLASS) !=
	    0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		goto fail;
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(nvl, IPP_MODULE_VERSION,
	    (uint32_t)module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		goto fail;
	}

	/* add class name */
	if (nvlist_add_string(nvl, CLASSIFIER_CLASS_NAME, class_name) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		goto fail;
	}

	if (ipp_action_modify(action_name, &nvl, flags) != 0) {

		/* generic error message */

		ipqos_msg(MT_ERROR,
		    gettext("Removing class %s in action %s failed: %s.\n"),
		    class_name, action_name, strerror(errno));

		goto fail;
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	nvlist_free(nvl);
	return (IPQOS_CONF_ERR);
}

/*
 * add the filter flt to the kernel action named action_name.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
add_filter(
char *action_name,
ipqos_conf_filter_t *flt,
int module_version)
{

	nvlist_t *nvl = flt->nvlist;
	char ipvsbuf[IPQOS_INT_STR_LEN];

	IPQOSCDBG4(APPLY, "add_filter: action: %s, filter: %s, "
	    "instance: %d, class: %s\n", action_name, flt->name,
	    flt->instance, flt->class_name);


	/* add 'add filter' config type to filter nvlist */
	if (nvlist_add_byte(nvl, IPP_CONFIG_TYPE, CLASSIFIER_ADD_FILTER) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		return (IPQOS_CONF_ERR);
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(nvl, IPP_MODULE_VERSION,
	    (uint32_t)module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		return (IPQOS_CONF_ERR);
	}

	/* add filter name to nvlist */
	if (nvlist_add_string(nvl, CLASSIFIER_FILTER_NAME, flt->name) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		return (IPQOS_CONF_ERR);
	}

	/* add class name to nvlist */
	if (nvlist_add_string(nvl, CLASSIFIER_CLASS_NAME, flt->class_name) !=
	    0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		return (IPQOS_CONF_ERR);
	}

	/* add ipqosconf as originator to nvlist */
	if (add_orig_ipqosconf(nvl) != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	/* add ipgpc specific nv entrys */
	if (strcmp(action_name, IPGPC_CLASSIFY) == 0) {

		/* add src and dst nodes to nvlist if present */

		if (flt->src_nd_name != NULL &&
		    nvlist_add_string(nvl, IPGPC_SADDR_HOSTNAME,
		    flt->src_nd_name) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_string");
			return (IPQOS_CONF_ERR);
		}
		if (flt->dst_nd_name != NULL &&
		    nvlist_add_string(nvl, IPGPC_DADDR_HOSTNAME,
		    flt->dst_nd_name) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_string");
			return (IPQOS_CONF_ERR);
		}

		/*
		 * add ip_version to private list element if present.
		 * NOTE: this value is of only real use to ipqosconf so
		 * it is placed in this opaque private field.
		 */
		if (flt->ip_versions != 0) {
			(void) sprintf(ipvsbuf, "%d", flt->ip_versions);
			if (nvlist_add_string(nvl, IPGPC_FILTER_PRIVATE,
			    ipvsbuf) != 0) {
				ipqos_msg(MT_ENOSTR, "nvlist_add_string");
				return (IPQOS_CONF_ERR);
			}
		}

		/* add filter instance if present */

		if (nvlist_add_int32(nvl, IPGPC_FILTER_INSTANCE,
		    flt->instance) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_int32");
			return (IPQOS_CONF_ERR);
		}
	}

	if (ipp_action_modify(action_name, &flt->nvlist, 0) != 0) {

		/* invalid parameters */

		if (errno == EINVAL) {
			ipqos_msg(MT_ERROR,
			    gettext("Invalid/missing parameters for filter "
			    "%s in action %s.\n"), flt->name, action_name);

		/* max ipgpc filters/classes */

		} else if (errno == ENOSPC &&
		    strcmp(action_name, IPGPC_CLASSIFY) == 0) {
			ipqos_msg(MT_ERROR, gettext("Max number of filters "
			    "reached in action %s.\n"), IPGPC_NAME);

		/* anything other errnos */
		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Failed to create filter %s in action "
			    "%s: %s.\n"), flt->name, action_name,
			    strerror(errno));
		}

		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}


/*
 * modify the filter flt in the kernel action named action_name.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
modify_filter(
char *action_name,
ipqos_conf_filter_t *flt,
int module_version)
{

	nvlist_t *nvl = flt->nvlist;
	char ipvsbuf[IPQOS_INT_STR_LEN];

	IPQOSCDBG4(APPLY, "modify_filter: action: %s, filter: %s, "
	    "instance: %d, class: %s\n", action_name, flt->name,
	    flt->instance, flt->class_name);

/* show src address and dst address if present */
#ifdef	_IPQOS_CONF_DEBUG
	if (ipqosconf_dbg_flgs & APPLY) {
		uint_t tmp;
		in6_addr_t *add;
		char st[100];

		if (nvlist_lookup_uint32_array(nvl, IPGPC_SADDR,
		    (uint32_t **)&add, &tmp) == 0) {
			(void) fprintf(stderr, "saddr: %s\n",
			    inet_ntop(AF_INET6, add, st, 100));
		}

		if (nvlist_lookup_uint32_array(nvl, IPGPC_DADDR,
		    (uint32_t **)&add, &tmp) == 0) {
			(void) fprintf(stderr, "daddr: %s\n",
			    inet_ntop(AF_INET6, add, st, 100));
		}
	}
#endif	/* _IPQOS_CONF_DEBUG */

	/* add 'modify filter' config type to filters nvlist */
	if (nvlist_add_byte(nvl, IPP_CONFIG_TYPE,
	    CLASSIFIER_MODIFY_FILTER) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		return (IPQOS_CONF_ERR);
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(nvl, IPP_MODULE_VERSION,
	    (uint32_t)module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		return (IPQOS_CONF_ERR);
	}

	/* add filter name to nvlist */
	if (nvlist_add_string(nvl, CLASSIFIER_FILTER_NAME, flt->name) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		return (IPQOS_CONF_ERR);
	}

	/* add class name to nvlist */
	if (nvlist_add_string(nvl, CLASSIFIER_CLASS_NAME, flt->class_name) !=
	    0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		return (IPQOS_CONF_ERR);
	}

	/* add originator ipqosconf to nvlist */
	if (add_orig_ipqosconf(nvl) != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	/* add ipgpc specific nvpairs */
	if (strcmp(action_name, IPGPC_CLASSIFY) == 0) {

		/* add src and dst nodes to nvlist if present */

		if (flt->src_nd_name &&
		    nvlist_add_string(nvl, IPGPC_SADDR_HOSTNAME,
		    flt->src_nd_name) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_string");
			return (IPQOS_CONF_ERR);
		}
		if (flt->dst_nd_name &&
		    nvlist_add_string(nvl, IPGPC_DADDR_HOSTNAME,
		    flt->dst_nd_name) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_string");
			return (IPQOS_CONF_ERR);
		}

		/*
		 * add ip_version to private list element if present.
		 * NOTE: this value is of only real use to ipqosconf so
		 * it is placed in this opaque private field.
		 */
		if (flt->ip_versions != 0) {
			(void) sprintf(ipvsbuf, "%d", flt->ip_versions);
			if (nvlist_add_string(nvl, IPGPC_FILTER_PRIVATE,
			    ipvsbuf) != 0) {
				ipqos_msg(MT_ENOSTR, "nvlist_add_string");
				return (IPQOS_CONF_ERR);
			}
		}

		/* add filter instance if present */

		if (nvlist_add_int32(nvl, IPGPC_FILTER_INSTANCE,
		    flt->instance) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_int32");
			return (IPQOS_CONF_ERR);
		}
	}

	if (ipp_action_modify(action_name, &flt->nvlist, 0) != 0) {

		/* invalid parameters */

		if (errno == EINVAL) {
			ipqos_msg(MT_ERROR, gettext("Missing/Invalid "
			    "parameter for filter %s in action %s.\n"),
			    flt->name, action_name);

		/* any other errnos */

		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Failed to modify filter %s in action %s: "
			    "%s.\n"), flt->name, action_name, strerror(errno));
		}

		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * remove the filter named filter_name instance number instance from the
 * kernel action action_name.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
remove_filter(
char *action_name,
char *filter_name,
int instance,
int module_version)
{

	nvlist_t *nvl;

	IPQOSCDBG2(APPLY, "remove_filter: action: %s, filter: %s\n",
	    action_name, filter_name);

	/* create nvlist */
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_alloc");
		return (IPQOS_CONF_ERR);
	}

	/* add 'remove filter' config type to list */
	if (nvlist_add_byte(nvl, IPP_CONFIG_TYPE, CLASSIFIER_REMOVE_FILTER)
	!= 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		return (IPQOS_CONF_ERR);
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(nvl, IPP_MODULE_VERSION,
	    (uint32_t)module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		return (IPQOS_CONF_ERR);
	}

	/* add filter name to list */
	if (nvlist_add_string(nvl, CLASSIFIER_FILTER_NAME, filter_name) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_string");
		return (IPQOS_CONF_ERR);
	}

	/* add instance number if part of multi-instance filter */
	if (instance != -1 && nvlist_add_int32(nvl, IPGPC_FILTER_INSTANCE,
	    instance) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_int32");
		return (IPQOS_CONF_ERR);
	}

	/* call into lib to remove */
	if (ipp_action_modify(action_name, &nvl, 0) != 0) {

		/* generic error message */

		ipqos_msg(MT_ERROR,
		    gettext("Removing filter %s in action %s failed: %s.\n"),
		    filter_name, action_name, strerror(errno));

		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}

/* ******************************************************************* */


/*
 * add originator nvpair set to ipqosconf to nvl.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
add_orig_ipqosconf(nvlist_t *nvl)
{

	if (nvlist_add_uint32(nvl, IPP_CONFIG_ORIGINATOR,
	    IPP_CONFIG_IPQOSCONF) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32: originator:");
		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}

/* ************************* differencing functions ************************ */


/*
 * compares the contents of arrays array1 and array2, both of size size, and
 * returns B_TRUE or B_FALSE if they're equal or not respectively.
 * RETURNS: B_TRUE if equal, else B_FALSE.
 */
static boolean_t
arrays_equal(
int array1[],
int array2[],
uint32_t size)
{
	int x;

	for (x = 0; x < size; x++) {
		if (array1[x] != array2[x])
			return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * difference class old against class new. It marks the new class as
 * modified if it is different.
 * RETURNS: IPQOS_CONF_SUCCESS.
 */
static int
diffclass(
ipqos_conf_class_t *old,
ipqos_conf_class_t *new)
{

	IPQOSCDBG0(L0, "In diffclass:\n");

	/* two different spec'd actions */
	if (strcmp(old->alist->name, new->alist->name) != 0) {
		IPQOSCDBG1(DIFF, "marking class %s as modified\n", new->name);

		new->modified = B_TRUE;
		return (IPQOS_CONF_SUCCESS);
	}

	/* different stats values */
	if (old->stats_enable != new->stats_enable) {
		IPQOSCDBG1(DIFF, "marking class %s as modified\n", new->name);

		new->modified = B_TRUE;
		return (IPQOS_CONF_SUCCESS);
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * difference params set old against params set new of module module_name. It
 * marks the new params as modified if different.
 * RETURNS: if error IPQOS_CONF_ERR, else IPQOS_CONF_SUCCESS.
 */
static int
diffparams(
ipqos_conf_params_t *old,
ipqos_conf_params_t *new,
char *module_name)
{

	int diff;
	int res;

	IPQOSCDBG0(L0, "In diffparams\n");

	/* diff stats */
	if (old->stats_enable != new->stats_enable) {

		new->modified = B_TRUE;
		return (IPQOS_CONF_SUCCESS);
	}

	/* diff module specific params */
	res = diffnvlists(old->nvlist, new->nvlist, module_name, &diff,
	    PL_PARAMS);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}
	if (diff) {

		new->modified = B_TRUE;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * differences filter old against filter new of module module_name. It marks
 * filter new as different if so.
 * RETURNS: if error IPQOS_CONF_ERR, else IPQOS_CONF_SUCCESS.
 */
static int
difffilter(
ipqos_conf_filter_t *old,
ipqos_conf_filter_t *new,
char *module_name)
{

	int res;
	int diff;

	IPQOSCDBG0(L0, "In difffilter\n");

	/* compare class name */

	if (strcmp(old->class_name, new->class_name) != 0) {
		IPQOSCDBG1(DIFF, "Marking filter %s as modified\n", new->name);

		new->modified = B_TRUE;
		return (IPQOS_CONF_SUCCESS);
	}

	/* compare module specific params */

	res = diffnvlists(old->nvlist, new->nvlist, module_name, &diff,
	    PL_FILTER);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	if (diff) {
		IPQOSCDBG1(DIFF, "Marking filter %s as modified\n", new->name);
		new->modified = B_TRUE;
	}

	return (IPQOS_CONF_SUCCESS);
}


/*
 * mark all the filters and classes in parameter action either
 * for deletion (if they are ipqosconf originated) or for modification.
 */
static void
mark_classes_filters_del(ipqos_conf_action_t *action)
{

	ipqos_conf_filter_t *flt;
	ipqos_conf_class_t *cls;

	IPQOSCDBG1(L1, "In mark_classes_filters_del: action: %s\n",
	    action->name);

	/* mark all non-permanent filters for del and permanent to modify */
	for (flt = action->filters; flt; flt = flt->next) {
		if (flt->originator == IPP_CONFIG_PERMANENT) {
			IPQOSCDBG1(DIFF, "Marking prm filter %s as modified.\n",
			    flt->name);

			flt->modified = B_TRUE;
		} else {
			IPQOSCDBG1(DIFF, "Marking filter %s as del.\n",
			    flt->name);

			flt->todel = B_TRUE;
		}
	}

	/* mark all non-permanent classes for del and permanent to modify */
	for (cls = action->classes; cls; cls = cls->next) {
		if (cls->originator == IPP_CONFIG_PERMANENT) {
			IPQOSCDBG1(DIFF, "Marking prm class %s as modified.\n",
			    cls->name);

			cls->modified = B_TRUE;
		} else {
			IPQOSCDBG1(DIFF, "Marking class %s as del.\n",
			    cls->name);

			cls->todel = B_TRUE;
		}
	}
}

/*
 * mark all classes and filters either new (non-permanent) or modified.
 */
static void
mark_classes_filters_new(ipqos_conf_action_t *action)
{

	ipqos_conf_filter_t *flt;
	ipqos_conf_class_t *cls;

	IPQOSCDBG1(L1, "In mark_classes_filters_new: action: %s\n",
	    action->name);

	/* mark all permanent filters as modified and all others new */

	for (flt = action->filters; flt; flt = flt->next) {
		if (flt->originator == IPP_CONFIG_PERMANENT) {
			IPQOSCDBG1(DIFF, "Marking prm filter %s as modified.\n",
			    flt->name);

			flt->modified = B_TRUE;
			action->modified = B_TRUE;
		} else {
			IPQOSCDBG1(DIFF, "Marking filter %s as new.\n",
			    flt->name);

			flt->new = B_TRUE;
		}
	}

	/* mark all permanent classes as modified and all others new */
	for (cls = action->classes; cls; cls = cls->next) {
		if (cls->originator == IPP_CONFIG_PERMANENT) {
			IPQOSCDBG1(DIFF, "Marking prm class %s as modified.\n",
			    cls->name);

			cls->modified = B_TRUE;
			action->modified = B_TRUE;
		} else {
			IPQOSCDBG1(DIFF, "Marking class %s as new.\n",
			    cls->name);

			cls->new = B_TRUE;
		}
	}
}

/*
 * Marks all the actions and their constituent elements in conf
 * as new.
 */
static void
mark_config_new(
ipqos_conf_action_t *conf)
{
	while (conf != NULL) {
		IPQOSCDBG1(DIFF, "Marking action %s as new\n", conf->name);
		mark_classes_filters_new(conf);
		conf->new = B_TRUE;
		conf->visited = 0;
		conf = conf->next;
	}
}

/*
 * differences the configuration  in new against old marking the actions
 * and their contents appropriately.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
diffconf(
ipqos_conf_action_t *old,
ipqos_conf_action_t *new)
{

	int res;
	ipqos_conf_action_t *act;
	ipqos_conf_action_t *tmp;

	IPQOSCDBG0((L0 | DIFF), "In diffconf\n");

	/* check the new actions against the old */

	for (act = new; act; act = act->next) {

		/* if action not in old mark it and it's contents as new */

		if ((tmp = actionexist(act->name, old)) == NULL) {
			IPQOSCDBG1(DIFF, "marking act %s as new\n", act->name);

			act->new = B_TRUE;
			mark_classes_filters_new(act);
			continue;
		}

		/* if action in old diff old against new */

		res = diffaction(tmp, act);
		if (res != IPQOS_CONF_SUCCESS) {
			return (res);
		}
	}

	/*
	 * mark actions, and their contents, in old but not new that were
	 * created by us for del.
	 */

	for (act = old; act; act = act->next) {
		if (act->params->originator == IPP_CONFIG_IPQOSCONF &&
		    actionexist(act->name, new) == NULL) {
			IPQOSCDBG1(DIFF, "marking act %s for del\n", act->name);

			act->todel = B_TRUE;
			mark_classes_filters_del(act);
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * differences action old against action new, comparing its classes, filters
 * and parameters. If it is different the new action is marked as modified
 * and it's different sub-objects are also marked approriately.
 * RETURNS: IPQOS_CONF_ERR if error, else IPQOS_CONF_SUCCESS.
 */
static int
diffaction(
ipqos_conf_action_t *old,
ipqos_conf_action_t *new)
{

	int res;

	IPQOSCDBG0(L0, "In diffaction\n");

	/* compare and mark classes */
	res = diffclasses(old, new);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/* compare and mark filters */
	res = difffilters(old, new);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/* compare and mark parameters */
	res = diffparams(old->params, new->params, old->module);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/* mark action as modified if params are */
	if (new->params->modified == B_TRUE) {
		IPQOSCDBG1(DIFF, "Marking params for action %s modified\n",
		    new->name);

		new->modified = B_TRUE;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * differences the set of classes in new against those in old, marking any
 * that are new/modified, approriately in the new class, and any removed
 * in the old class appropriately. Also marks the action which has had an
 * object within marked, as modified.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */

static int
diffclasses(
ipqos_conf_action_t *old,
ipqos_conf_action_t *new)
{


	ipqos_conf_class_t *cls;
	ipqos_conf_class_t *tmpc;
	ipqos_conf_class_t *ncls;
	int res;


	/* loop through old classes checking for classes not present in new */

	for (cls = old->classes; cls; cls = cls->next) {

		if (classexist(cls->name, new->classes) == NULL) {

			/* if we created original class mark for deletion */

			if (cls->originator == IPP_CONFIG_IPQOSCONF) {
				IPQOSCDBG1(DIFF, "marking class %s for del\n",
				    cls->name);

				cls->todel = B_TRUE;

				/* mark old action */
				old->modified = B_TRUE;

			/*
			 * if permanent class and next action created by us
			 * copy it, set it's next action to continue and
			 * add it to new action. This will cause the class
			 * to be marked as and modified. This returns the class
			 * to an assumed default state and prevents the
			 * case where the class is pointing at an action
			 * we want to remove and therefore couldn't without
			 * this forced modify.
			 */
			} else if (cls->originator == IPP_CONFIG_PERMANENT &&
			    cls->alist->action &&	/* not virtual action */
			    cls->alist->action->params->originator ==
			    IPP_CONFIG_IPQOSCONF) {

				/* copy class */

				res = dup_class(cls, &ncls);
				if (res != IPQOS_CONF_SUCCESS) {
					return (IPQOS_CONF_ERR);
				}

				/* set next action to continue */

				(void) strcpy(ncls->alist->name,
				    IPP_ANAME_CONT);

				/* add to news classes to be diffed below */
				ADD_TO_LIST(&new->classes, ncls);
			}
		}
	}

	/* loop through new classes checking for new / modified classes */

	for (cls = new->classes; cls; cls = cls->next) {

		/* new ipqosconf class */

		if ((tmpc = classexist(cls->name, old->classes)) == NULL ||
		    (tmpc->originator != IPP_CONFIG_IPQOSCONF &&
		    tmpc->originator != IPP_CONFIG_PERMANENT)) {
			IPQOSCDBG1(DIFF, "marking class %s new\n",
			    cls->name);

			cls->new = B_TRUE;

			new->modified = B_TRUE;	/* mark new action */
			continue;

		/* existing ipqosconf/perm class */
		} else {
			res = diffclass(tmpc, cls);
			if (res != IPQOS_CONF_SUCCESS) {
				return (res);
			}

			if (cls->modified == B_TRUE) {
				new->modified = B_TRUE;
			}
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * differences the set of filters in new against those in old, marking any
 * that are new/modified, approriately in the new filter/s, and any removed
 * in the old filter appropriately. Also marks the action which has had an
 * object within marked, as modified.
 * RETURNS: IPQOS_CONF_SUCCESS (we return an int for symmetry with diffclasses
 * and difffparams).
 */
static int
difffilters(
ipqos_conf_action_t *old,
ipqos_conf_action_t *new)
{

	ipqos_conf_filter_t *flt;
	ipqos_conf_filter_t *tmpf;
	int maxi;
	int newi;
	int res;

	/* check for new/modified filters */

	for (flt = new->filters; flt; flt = flt->next) {

		/* new ipqosconf filter */

		if ((tmpf = filterexist(flt->name, -1, old->filters)) == NULL) {

			/* mark all instances of this filter as new */
			for (;;) {
				IPQOSCDBG1(DIFF, "Marking filter %s as "
				    "new\n", flt->name);

				flt->new = B_TRUE;


				if (flt->next == NULL ||
				    strcmp(flt->next->name, flt->name) != 0) {
					break;
				}
				flt = flt->next;
			}
			new->modified = B_TRUE;	/* mark new action */

		/* ipqosconf/permanent filter existed */
		} else {
			/*
			 * if ip node name force filter refresh - ie. mark
			 * all old filter instances as todel and all new new.
			 */
			if (tmpf->src_nd_name || tmpf->dst_nd_name ||
			    flt->src_nd_name || flt->dst_nd_name) {

				/* init max previous filter instance */
				maxi = tmpf->instance;

				/* mark old instances for deletion */
				do {
					IPQOSCDBG2(DIFF, "Marking filter "
					    "%s, instance %d for del\n",
					    tmpf->name, tmpf->instance);

					tmpf->todel = B_TRUE;

					/*
					 * check and update previous instance
					 * max.
					 */
					if (tmpf->instance > maxi) {
						maxi = tmpf->instance;
					}

					tmpf = tmpf->next;
				} while (tmpf != NULL &&
					strcmp(tmpf->name, flt->name) == 0);

				/*
				 * use the max previous instance + 1 for
				 * the start of the new instance numbers.
				 */
				newi = (uint32_t)++maxi % INT_MAX;

				/*
				 * mark new instances for addition and
				 * give new instance number.
				 */
				for (;;) {
					IPQOSCDBG2(DIFF, "Marking filter "
					    "%s, instance %d as new\n",
					    flt->name, newi);

					flt->new = B_TRUE;
					flt->instance = newi++;
					if (flt->next == NULL ||
					    strcmp(flt->next->name,
					    flt->name) != 0) {
						break;
					}
					flt = flt->next;
				}
				new->modified = B_TRUE; /* mark new action */

				/* mark old action */
				old->modified = B_TRUE;

			/* non-node name filter */
			} else {
				/* compare and mark as modified if diff */

				res = difffilter(tmpf, flt, new->module);
				if (res != IPQOS_CONF_SUCCESS) {
					return (res);
				}
				if (flt->modified == B_TRUE) {
					/* mark action if diff */
					new->modified = B_TRUE;
				}
			}
		}
	}

	/*
	 * Check for deleted ipqosconf created filters and mark
	 * any found for deletion.
	 * For non-ipqosconf generated filters, including permanent
	 * ones (none of these exist at the moment) we just leave
	 * the filter unmarked.
	 */
	for (flt = old->filters; flt; flt = flt->next) {

		if (flt->originator == IPP_CONFIG_IPQOSCONF &&
		    filterexist(flt->name, -1, new->filters) == NULL) {

			/* mark all old instances for deletions */
			for (;;) {
				IPQOSCDBG2(DIFF, "marking flt %s, inst %d "
				    "for del\n", flt->name, flt->instance);

				flt->todel = B_TRUE;
				old->modified = B_TRUE; /* mark old action */

				if (flt->next == NULL ||
				    strcmp(flt->next->name, flt->name) != 0) {
					break;
				}
				flt = flt->next;
			}
		}
	}

	return (IPQOS_CONF_SUCCESS);
}


/*
 * differences the elements of nvlists old and new using the types file
 * for module name to interpret the element types. It sets pdiff to either
 * 0 or 1 if they are the same or different respectively.
 * RETURNS: IPQOS_CONF_ERR if any errors, else IPQOS_CONF_SUCCESS.
 */
static int
diffnvlists(
nvlist_t *old,
nvlist_t *new,
char *module_name,
int *pdiff,
place_t place)
{

	int first_pass = 1;
	nvlist_t *tmp;
	int res;
	nvpair_t *nvp;
	FILE *tfp;
	str_val_nd_t *enum_nvs;
	char dfltst[IPQOS_VALST_MAXLEN+1] = "";
	char *lo;
	ipqos_nvtype_t type;
	char *nme;
	int diff;
	int openerr;


	IPQOSCDBG0(L0, "In diffnvlists\n");

	/* open stream to types file */

	tfp = validmod(module_name, &openerr);
	if (tfp == NULL) {
		if (openerr) {
			ipqos_msg(MT_ENOSTR, "fopen");
		}
		return (IPQOS_CONF_ERR);
	}
start:
	/*
	 * loop through each of the elements of the new list comparing
	 * it with the old one if present. If the old one isn't present
	 * then it is compared with the default value for that type (if
	 * set). Any time the values are determined to be different
	 * or the default value is to be used but isn't present the diff
	 * param is set to 1 and we return.
	 *
	 * If the loop runs its course then the new and old nvlists are
	 * reversed and the loop is entered for a second time.
	 */
	nvp = nvlist_next_nvpair(new, NULL);
	while (nvp != NULL) {

		/* get name */
		nme = nvpair_name(nvp);

		/*
		 * get type.
		 */
		place = PL_ANY;
		res = readtype(tfp, module_name, SHORT_NAME(nme), &type,
		    &enum_nvs, dfltst, B_TRUE, &place);
		if (res != IPQOS_CONF_SUCCESS) {
			return (res);
		}

		/* init diff to 1 */
		diff = 1;

		switch (type) {

		/* interface name */
		case IPQOS_DATA_TYPE_IFINDEX: {
			uint32_t ifidx;
			uint32_t oifidx;

			/* get new value */
			(void) nvpair_value_uint32(nvp, &ifidx);

			/* compare against old if present */

			res = nvlist_lookup_uint32(old, nme, &oifidx);
			if (res == 0) {
				/* diff values */
				diff = (ifidx != oifidx);

			/* not in old so see if new value is default */

			} else {
				diff = (ifidx != 0);
			}
			break;
		}
		/* protocol */
		case IPQOS_DATA_TYPE_PROTO: {
			uchar_t proto;
			uchar_t oproto;

			(void) nvpair_value_byte(nvp, &proto);

			res = nvlist_lookup_byte(old, nme, &oproto);
			if (res == 0) {
				diff = (proto != oproto);
			} else {
				diff = (proto != 0);
			}
			break;
		}
		/* port */
		case IPQOS_DATA_TYPE_PORT: {
			uint16_t port;
			uint16_t oport;

			(void) nvpair_value_uint16(nvp, &port);
			res = nvlist_lookup_uint16(old, nme, &oport);
			if (res == 0) {
				diff = (port != oport);
			} else {
				diff = (port != 0);
			}
			break;
		}
		/* action name / string */
		case IPQOS_DATA_TYPE_ACTION:
		case IPQOS_DATA_TYPE_STRING: {
			char *str;
			char *ostr;

			(void) nvpair_value_string(nvp, &str);
			res = nvlist_lookup_string(old, nme, &ostr);
			if (res == 0) {
				diff = strcmp(str, ostr);
			} else if (*dfltst) {
				diff = strcmp(str, dfltst);
			}
			break;
		}
		/* address mask / address */
		case IPQOS_DATA_TYPE_ADDRESS_MASK:
		case IPQOS_DATA_TYPE_ADDRESS: {
			in6_addr_t *in6;
			in6_addr_t *oin6;
			uint_t x;

			/*
			 * all addresses are stored as v6 addresses, so
			 * a uint32_t[4] array is used.
			 */

			/* lookup new value */

			(void) nvpair_value_uint32_array(nvp,
			    (uint32_t **)&in6, &x);

			/* see if there's an old value and diff it */

			res = nvlist_lookup_uint32_array(old, nme,
			    (uint32_t **)&oin6, &x);
			if (res == 0) {
				/* diff each of the 16 v6 address bytes */

				for (x = 0; x < 16; x++) {
					if (in6->s6_addr[x] !=
					    oin6->s6_addr[x]) {
						diff++;
						break;
					}
				}
			}
			break;
		}
		/* boolean */
		case IPQOS_DATA_TYPE_BOOLEAN: {
			boolean_t bl;
			boolean_t obl;

			(void) nvpair_value_uint32(nvp, (uint32_t *)&bl);

			/* see if there's an old value and diff it */
			res = nvlist_lookup_uint32(old, nme, (uint32_t *)&obl);
			if (res == 0) {
				diff = (bl != obl);

			/* compare against default if present */
			} else if (*dfltst) {
				res = readbool(dfltst, &obl);
				if (res == IPQOS_CONF_SUCCESS) {
					diff = (bl != obl);
				}
			}
			break;
		}
		/* uint 8 */
		case IPQOS_DATA_TYPE_UINT8: {
			uint8_t u8;
			uint8_t ou8;

			(void) nvpair_value_byte(nvp, (uchar_t *)&u8);
			res = nvlist_lookup_byte(old, nme, (uchar_t *)&ou8);
			if (res == 0) {
				diff = (u8 != ou8);
			} else if (*dfltst) {
				res = readuint8(dfltst, &ou8, &lo);
				if (res == IPQOS_CONF_SUCCESS) {
					diff = (u8 != ou8);
				}
			}
			break;
		}
		/* int 16 */
		case IPQOS_DATA_TYPE_INT16: {
			int16_t i16;
			int16_t oi16;

			(void) nvpair_value_int16(nvp, &i16);
			res = nvlist_lookup_int16(old, nme, &oi16);
			if (res == 0) {
				diff = (i16 != oi16);
			} else if (*dfltst) {
				res = readint16(dfltst, &oi16, &lo);
				if (res == IPQOS_CONF_SUCCESS) {
					diff = (i16 != oi16);
				}
			}
			break;
		}
		/* uint16 */
		case IPQOS_DATA_TYPE_UINT16: {
			uint16_t ui16;
			uint16_t oui16;

			(void) nvpair_value_uint16(nvp, &ui16);
			res = nvlist_lookup_uint16(old, nme, &oui16);
			if (res == 0) {
				diff = (ui16 != oui16);
			} else if (*dfltst) {
				res = readuint16(dfltst, &oui16, &lo);
				if (res == IPQOS_CONF_SUCCESS) {
					diff = (ui16 != oui16);
				}
			}
			break;
		}
		/*
		 * int32 and user.
		 * Since user uids are stored in an int32 nvpair we can use
		 * the same comparison code.
		 */
		case IPQOS_DATA_TYPE_USER:
		case IPQOS_DATA_TYPE_INT32: {
			int32_t i32;
			int32_t oi32;

			(void) nvpair_value_int32(nvp, &i32);
			res = nvlist_lookup_int32(old, nme, &oi32);
			if (res == 0) {
				diff = (i32 != oi32);
			} else if (*dfltst) {
				res = readint32(dfltst, &oi32, &lo);
				if (res == IPQOS_CONF_SUCCESS) {
					diff = (i32 != oi32);
				}
			}
			break;
		}
		/* uint32 */
		case IPQOS_DATA_TYPE_UINT32: {
			uint32_t ui32;
			uint32_t oui32;

			(void) nvpair_value_uint32(nvp, &ui32);
			res = nvlist_lookup_uint32(old, nme, &oui32);
			if (res == 0) {
				diff = (ui32 != oui32);
			} else if (*dfltst) {
				res = readuint32(dfltst, &oui32, &lo);
				if (res == IPQOS_CONF_SUCCESS) {
					diff = (ui32 != oui32);
				}
			}
			break;
		}
		/* enumeration */
		case IPQOS_DATA_TYPE_ENUM: {
			uint32_t eval;
			uint32_t oeval;

			(void) nvpair_value_uint32(nvp, &eval);
			res = nvlist_lookup_uint32(old, nme, &oeval);
			if (res == 0) {
				diff = (eval != oeval);
			} else if (*dfltst) {
				res = readuint32(dfltst, &oeval, &lo);
				if (res == IPQOS_CONF_SUCCESS) {
					diff = (eval != oeval);
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_M_INDEX: {
			uint8_t idx, oidx;

			(void) nvpair_value_byte(nvp, &idx);
			res = nvlist_lookup_byte(old, nme, &oidx);
			if (res == 0)
				diff = (idx != oidx);
			break;
		}
		case IPQOS_DATA_TYPE_INT_ARRAY: {
			int *oarr, *arr;
			uint32_t osize, size;

			(void) nvpair_value_int32_array(nvp, &arr, &size);
			res = nvlist_lookup_int32_array(old, nme, &oarr,
			    &osize);
			if (res == 0)
				diff = (arrays_equal(arr, oarr, size) ==
				    B_FALSE);
			break;
		}
#ifdef	_IPQOS_CONF_DEBUG
		default: {
			/* shouldn't get here as all types should be covered */
			assert(1);
		}
#endif
		}	/* switch */
		if (diff != 0) {
			IPQOSCDBG1(DIFF, "parameter %s different\n", nme);
			*pdiff = 1;
			(void) fclose(tfp);
			return (IPQOS_CONF_SUCCESS);
		}


		nvp = nvlist_next_nvpair(new, nvp);

	}

	/* now compare all the stuff in the second list with the first */
	if (first_pass) {
		tmp = old;
		old = new;
		new = tmp;
		first_pass = 0;
		goto start;
	}

	(void) fclose(tfp);

	*pdiff = 0;
	return (IPQOS_CONF_SUCCESS);
}



/* ************************** difference application *********************** */



/*
 * causes all items marked as requiring change in actions and old_actions
 * to have the change applied.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
applydiff(
ipqos_conf_action_t *actions,
ipqos_conf_action_t *old_actions)
{

	int res;

	IPQOSCDBG0(L1, "In applydiff:\n");


	/* add each item marked as new */

	res = add_items(actions, B_FALSE);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/* modify items marked for modification */

	res = modify_items(actions);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/* delete items marked for deletion */

	res = remove_items(old_actions, B_FALSE);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	return (IPQOS_CONF_SUCCESS);
}

static int
add_items(
ipqos_conf_action_t *actions,
boolean_t rem_undo)
{

	int res;
	ipqos_conf_action_t *act;

	IPQOSCDBG1(L1, "In add_items, rem_undo: %u\n", rem_undo);

	/*
	 * we need to create ipgpc action before any others as some actions
	 * such as ftpcl which make calls to it depend on it being there on
	 * their creation.
	 */
	act = actionexist(IPGPC_CLASSIFY, actions);
	if (act &&
	    (rem_undo == B_FALSE && act->new == B_TRUE ||
	    rem_undo == B_TRUE && act->deleted == B_TRUE)) {

		res = add_action(act);
		if (res != IPQOS_CONF_SUCCESS) {
			return (res);
		}
	}

	/*
	 * loop though action list and add any actions marked as
	 * new/modified action and apply any additions there, then return.
	 */

	for (act = actions; act; act = act->next) {
		res = add_item(act, rem_undo);
		if (res != IPQOS_CONF_SUCCESS) {
			return (IPQOS_CONF_ERR);
		}
	}

	return (IPQOS_CONF_SUCCESS);
}


/*
 *
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
add_item(
ipqos_conf_action_t *actions,
boolean_t rem_undo)
{

	ipqos_conf_action_t *act = actions;
	int res;
	ipqos_conf_class_t *cls;
	ipqos_conf_act_ref_t *pact;

	IPQOSCDBG2(L1, "In add_item: action: %s, rem_undo: %u\n",
	    actions->name, rem_undo);

	/* if already visited return immediately */

	if (act->visited == ADD_VISITED) {
		IPQOSCDBG0(L1, "Early exit due to visited\n");
		return (IPQOS_CONF_SUCCESS);
	}
	act->visited = ADD_VISITED;


	/* recurse to last action in tree */

	for (cls = act->classes; cls; cls = cls->next) {

		/* if not virtual action */

		if (cls->alist->action) {
			res = add_item(cls->alist->action, rem_undo);
			if (res != IPQOS_CONF_SUCCESS) {
				return (res);
			}
		}
	}

	for (pact = act->params->actions; pact; pact = pact->next) {

		/* if not virtual */

		if (pact->action) {
			res = add_item(pact->action, rem_undo);
			if (res != IPQOS_CONF_SUCCESS) {
				return (res);
			}
		}
	}


	/* if action marked as new and not ipgpc, create */

	if (((rem_undo == B_FALSE && act->new == B_TRUE) ||
	    (rem_undo == B_TRUE && act->deleted == B_TRUE)) &&
	    strcmp(act->name, IPGPC_CLASSIFY) != 0) {
		res = add_action(act);
		if (res != IPQOS_CONF_SUCCESS) {
			return (res);
		}
	}

	/* add any classes and filters marked as new */

	if (add_classes(act->classes, act->name, act->module_version,
	    rem_undo) != IPQOS_CONF_SUCCESS ||
	    add_filters(act->filters, act->name, act->module_version,
	    rem_undo) != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}


/*
 * Uses the contents of acts params nvlist and adds an originator
 * element set to ipqosconf and the stats parameter. This list
 * is then used as the parameter to a call to ipp_action_create to create
 * this action in the kernel.
 * RETURNS: IPQOS_CONF_ERR on err, else IPQOS_CONF_SUCCESS.
 */
static int
add_action(ipqos_conf_action_t *act)
{

	int res;
	nvlist_t **nvl;

	IPQOSCDBG2(APPLY, "add_action: action: %s, module: %s\n", act->name,
	    act->module);

	nvl = &act->params->nvlist;

	/* alloc params nvlist if not already one */

	if (*nvl == NULL) {
		res = nvlist_alloc(nvl, NV_UNIQUE_NAME, 0);
		if (res != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_alloc");
			return (IPQOS_CONF_ERR);
		}
	}

	/*
	 * add module version
	 */
	if (nvlist_add_uint32(*nvl, IPP_MODULE_VERSION,
	    (uint32_t)act->module_version) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32");
		return (IPQOS_CONF_ERR);
	}

	/* add action stats */

	if (nvlist_add_uint32(*nvl, IPP_ACTION_STATS_ENABLE,
	    (uint32_t)act->params->stats_enable) != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_uint32: action stats");
		return (IPQOS_CONF_ERR);
	}

	/* add ipqosconf originator id */

	if (add_orig_ipqosconf(*nvl) != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	/* call into lib to create action */

	res = ipp_action_create(act->module, act->name, nvl, 0);
	if (res != 0) {
		IPQOSCDBG2(APPLY, "Create action %s, module %s failed\n",
		    act->name, act->module);

		/* invalid params */

		if (errno == EINVAL) {
			ipqos_msg(MT_ERROR,
			    gettext("Invalid Parameters for action %s.\n"),
			    act->name);

		} else if (errno == ENOENT) {
			ipqos_msg(MT_ERROR,
			    gettext("Missing required parameter for action "
			    "%s.\n"), act->name);

		} else {	/* unexpected error */
			ipqos_msg(MT_ERROR, gettext("Failed to create action "
			    "%s: %s.\n"), act->name, strerror(errno));
		}

		return (IPQOS_CONF_ERR);
	}

	/* mark action as created */
	act->cr_mod = B_TRUE;

	return (IPQOS_CONF_SUCCESS);
}

/*
 * for each of the filters in parameter filters if rem_undo is false and
 * the filter is marked as new or if rem_undo is true and the filter is
 * marked as deleted then add the filter to the kernel action named by action
 * and if successful mark as created.
 * RETURNS: IPQOS_CONF_ERR on errors, else IPQOS_CONF_SUCCESS.
 */
static int
add_filters(
ipqos_conf_filter_t *filters,
char *action,
int module_version,
boolean_t rem_undo)
{

	ipqos_conf_filter_t *flt;

	IPQOSCDBG0(L1, "In add_filters\n");

	/* loop through filters in filters param */
	for (flt = filters; flt; flt = flt->next) {
		/*
		 * skip filter if in normal mode and not new filter or
		 * if doing rollback and filter wasn't previously deleted.
		 */
		if ((rem_undo == B_FALSE && flt->new == B_FALSE) ||
		    (rem_undo == B_TRUE && flt->deleted == B_FALSE)) {
			continue;
		}

		/* add filter to action */
		if (add_filter(action, flt, module_version) !=
		    IPQOS_CONF_SUCCESS) {
			return (IPQOS_CONF_ERR);
		}

		/* mark as created */
		flt->cr_mod = B_TRUE;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * for each of the classes in parameter classes if rem_undo is false and
 * the class is marked as new or if rem_undo is true and the class is
 * marked as deleted then add the class to the kernel action named by action
 * and if successful mark as created.
 * RETURNS: IPQOS_CONF_ERR on errors, else IPQOS_CONF_SUCCESS.
 */
int
add_classes(
ipqos_conf_class_t *classes,
char *action,
int module_version,
boolean_t rem_undo) {

	int res;
	ipqos_conf_class_t *cls;

	IPQOSCDBG0(L1, "In add_classes\n");

	/* for each class */
	for (cls = classes; cls; cls = cls->next) {
		/*
		 * skip class if in normal mode and not new class or
		 * if doing rollback and class wasn't deleted.
		 */
		if ((rem_undo == B_FALSE && cls->new == B_FALSE) ||
		(rem_undo == B_TRUE && cls->deleted == B_FALSE)) {
			continue;
		}

		/* add class to action */
		res = add_class(action, cls->name, module_version,
		    cls->stats_enable, cls->alist->name);
		if (res != IPQOS_CONF_SUCCESS) {
			return (IPQOS_CONF_ERR);
		}

		/* mark class as created */
		cls->cr_mod = B_TRUE;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * For each of the actions in actions remove the action if marked as
 * such or remove any objects within marked as such.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
remove_items(
ipqos_conf_action_t *actions,
boolean_t add_undo)
{

	int res;
	ipqos_conf_action_t *act;

	IPQOSCDBG1(L0, "In remove_items, add_undo: %u\n", add_undo);

	/*
	 * loop through actions removing any actions, or action contents
	 * that are marked as such.
	 */
	for (act = actions; act; act = act->next) {
		res = remove_item(act, add_undo);
		if (res != IPQOS_CONF_SUCCESS) {
			return (res);
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Deletes this action if marked for deletion or any of it's contents marked
 * for deletion. If the action is marked for deletion any actions referencing
 * this action are destroyed first if marked or have their contents destroyed
 * if marked. This is recursive.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
remove_item(
ipqos_conf_action_t *act,
boolean_t add_undo)
{

	ipqos_conf_class_t *cls;
	ipqos_conf_filter_t *flt;
	ipqos_conf_act_ref_t *dep;
	int res;

	IPQOSCDBG3(L1, "In remove_item: action: %s, add_undo: %u, mod: %u\n",
	    act->name, add_undo, act->modified);


	/* return immmediately if previously visited in remove phase */

	if (act->visited == REM_VISITED) {
		IPQOSCDBG0(L1, "Exit due to REM_VISITED set\n");
		return (IPQOS_CONF_SUCCESS);
	}
	act->visited = REM_VISITED;


	/* if this action is to be deleted */

	if (add_undo == B_FALSE && act->todel == B_TRUE ||
	    add_undo == B_TRUE && act->new == B_TRUE &&
	    act->cr_mod == B_TRUE) {

		/* modify parent actions first */

		for (dep = act->dependencies; dep; dep = dep->next) {
			res = remove_item(dep->action, add_undo);
			if (res != IPQOS_CONF_SUCCESS) {
				return (res);
			}
		}

		/* delete this action */

			IPQOSCDBG1(APPLY, "deleting action %s\n", act->name);
		res = ipp_action_destroy(act->name, 0);
		if (res != 0) {
			IPQOSCDBG1(APPLY, "failed to destroy action %s\n",
			    act->name);
			return (IPQOS_CONF_ERR);
		}

		/* flag as deleted */

		act->deleted = B_TRUE;

	/* if modified action */

	} else if (act->modified == B_TRUE) {

		/* loop through removing any filters marked for del */

		for (flt = act->filters; flt; flt = flt->next) {
			if ((add_undo == B_FALSE && flt->todel == B_TRUE) ||
			    (add_undo == B_TRUE && flt->new == B_TRUE &&
			    flt->cr_mod == B_TRUE)) {

				/* do deletion */

				res = remove_filter(act->name, flt->name,
				    flt->instance, act->module_version);
				if (res != IPQOS_CONF_SUCCESS) {
					IPQOSCDBG2(APPLY, "failed to destroy "
					    "filter %s, inst: %d\n", flt->name,
					    flt->instance);

					return (IPQOS_CONF_ERR);
				}

				/* flag deleted */

				flt->deleted = B_TRUE;
			}
		}

		/* remove any classes marked for del */

		for (cls = act->classes; cls; cls = cls->next) {
			if ((add_undo == B_FALSE && cls->todel == B_TRUE) ||
			    (add_undo == B_TRUE && cls->new == B_TRUE &&
			    cls->cr_mod == B_TRUE)) {

				/* do deletion */

				res = remove_class(act->name, cls->name,
				    act->module_version, 0);
				if (res != IPQOS_CONF_SUCCESS) {
					IPQOSCDBG1(APPLY, "failed to destroy "
					    "class %s\n", cls->name);

					return (IPQOS_CONF_ERR);
				}

				/* flag deleted */

				cls->deleted = B_TRUE;
			}
		}

		/* mark action as having been modified */

		act->cr_mod = B_TRUE;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * for each of the actions in parameter actions apply any objects marked as
 * modified as a modification to the kernel action represented.
 * RETURNS: IPQOS_CONF_ERR on err, else IPQOS_CONF_SUCCESS.
 */
static int
modify_items(ipqos_conf_action_t *actions)
{

	ipqos_conf_action_t *act;
	int res;
	ipqos_conf_filter_t *flt;
	ipqos_conf_class_t *cls;


	IPQOSCDBG0(L1, "In modify_items\n");

	/* loop through actions in parameter actions */

	for (act = actions; act; act = act->next) {

		/* skip unchanged actions */

		if (act->modified == B_FALSE) {
			continue;
		}

		/* apply any parameter mods */

		if (act->params->modified) {
			res = modify_params(act->name,
			    &act->params->nvlist,
			    act->module_version, act->params->stats_enable);
			if (res != IPQOS_CONF_SUCCESS) {
				return (IPQOS_CONF_ERR);
			}

			act->params->cr_mod = B_TRUE;
		}

		/* apply any class mods */

		for (cls = act->classes; cls; cls = cls->next) {
			if (cls->modified) {
				res = modify_class(act->name, cls->name,
				    act->module_version, cls->stats_enable,
				    cls->alist->name, 0);
				if (res != IPQOS_CONF_SUCCESS) {
					return (IPQOS_CONF_ERR);
				}

				/* mark modification done */
				cls->cr_mod = B_TRUE;
			}
		}

		/* apply any filter mods */

		for (flt = act->filters; flt; flt = flt->next) {
			if (flt->modified) {
				res = modify_filter(act->name, flt,
				    act->module_version);
				if (res != 0) {
					return (IPQOS_CONF_ERR);
				}

				/* mark modification done */
				flt->cr_mod = B_TRUE;
			}
		}

		/* mark action modified */

		act->cr_mod = B_TRUE;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * For each of the objects of each of the actions in nactions that are
 * marked as having been modified the object modification is done in
 * reverse using the same named object from oactions.
 * RETURNS: IPQOS_CONF_ERR on error, IPQOS_CONF_SUCCESS otherwise.
 */
static int
undo_modifys(
ipqos_conf_action_t *oactions,
ipqos_conf_action_t *nactions)
{

	ipqos_conf_filter_t *flt;
	ipqos_conf_class_t *cls;
	ipqos_conf_action_t *act;
	ipqos_conf_action_t *oldact;
	ipqos_conf_filter_t *oldflt;
	ipqos_conf_class_t *oldcls;
	int res;

	IPQOSCDBG0(L1, "In undo_modifys:\n");

	/* loop throught new actions */

	for (act = nactions; act; act = act->next) {
		oldact = actionexist(act->name, oactions);

		/*
		 * if the action was new then it will be removed and
		 * any permamanent items that were marked for modify
		 * will dissappear, so ignore action.
		 */
		if (oldact == NULL) {
			continue;
		}

		/* if parameters were modified switch them back */

		if (act->params->modified == B_TRUE &&
		    act->params->cr_mod == B_TRUE) {
			res = modify_params(act->name,
			    &oldact->params->nvlist,
			    act->module_version, act->params->stats_enable);
			if (res != IPQOS_CONF_SUCCESS) {
				return (res);
			}
		}

		/* for each filter in action if filter modified switch back */

		for (flt = act->filters; flt; flt = flt->next) {
			if (flt->modified == B_TRUE &&
			    flt->cr_mod == B_TRUE) {
				oldflt = filterexist(flt->name, -1,
				    oldact->filters);
				res = modify_filter(act->name, oldflt,
				    act->module_version);
				if (res != IPQOS_CONF_SUCCESS) {
					return (res);
				}
			}
		}

		/* for each class in action if class modified switch back */

		for (cls = act->classes; cls; cls = cls->next) {
			if (cls->modified == B_TRUE &&
			    cls->cr_mod == B_TRUE) {
				oldcls = classexist(cls->name, oldact->classes);
				if (oldcls->alist) {
					res = modify_class(act->name,
					    cls->name, act->module_version,
					    oldcls->stats_enable,
					    oldcls->alist->name, 0);
				}
				if (res != IPQOS_CONF_SUCCESS) {
					return (res);
				}
			}
		}
	}

	/*
	 * Go through the old actions modifying perm filters and classes
	 * whose action was deleted.
	 *
	 */
	for (act = oactions; act != NULL; act = act->next) {

		if (act->deleted == B_FALSE) {
			continue;
		}

		for (flt = act->filters; flt != NULL; flt = flt->next) {
			if (flt->originator == IPP_CONFIG_PERMANENT) {
				res = modify_filter(act->name, flt,
				    act->module_version);
				if (res != IPQOS_CONF_SUCCESS) {
					return (res);
				}
			}
		}

		for (cls = act->classes; cls != NULL; cls = cls->next) {
			if (cls->originator == IPP_CONFIG_PERMANENT) {
				res = modify_class(act->name, cls->name,
				    act->module_version, cls->stats_enable,
				    cls->alist->name, 0);
				if (res != IPQOS_CONF_SUCCESS) {
					return (res);
				}
			}

		}
	}

	return (IPQOS_CONF_SUCCESS);
}


/*
 * causes all changes marked as being done in actions and old_actions
 * to be undone.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
rollback(
ipqos_conf_action_t *actions,
ipqos_conf_action_t *old_actions)
{

	int res;

	IPQOSCDBG0(RBK, "In rollback:\n");

	/* re-add items that were deleted */

	res = add_items(old_actions, B_TRUE);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/* change modified items back how they were */

	res = undo_modifys(old_actions, actions);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/* remove new items that were added */

	res = remove_items(actions, B_TRUE);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	return (IPQOS_CONF_SUCCESS);
}

/* ******************************* print config **************************** */

/*
 * Prints the username of the user with uid 'uid' to 'fp' if the uid belongs
 * to a known user on the system, otherwise just print 'uid'.
 */
static void
printuser(
FILE *fp,
uid_t uid)
{
	struct passwd *pwd;

	IPQOSCDBG0(L0, "In printuser\n");

	pwd = getpwuid(uid);
	if (pwd != NULL) {
		(void) fprintf(fp, "%s\n", pwd->pw_name);
	} else {
		(void) fprintf(fp, "%u\n", (int)uid);
	}
}

/*
 * print either a single value of start to fp (if start equals end), else
 * print start'-'end if start is the smaller of the two values, otherwise
 * print end'-'start.
 */
static void
printrange(
FILE *fp,
uint32_t start,
uint32_t end)
{
	uint32_t tmp;

	if (start > end) {
		tmp = start;
		start = end;
		end = tmp;
	}

	(void) fprintf(fp, "%u", start);
	if (end != start)
		(void) fprintf(fp, "-%u", end);
}

/*
 * print the contents of the array arr to fp in the form:
 * {0-6:1;7-12:2;13:3.....} or {0-6:GREEN;7-12:YELLOW:...}
 * dependant upon whether this is an integer or enumerated array resectively
 * (if enum_nvs isn't set to NULL this is assumed to be an enumerated array);
 * where 0-6 is the range of indexes with value 1 (or GREEN), 7-12 the range
 * with value 2 (or YELLOW), and so forth. size is the array size and llimit
 * and ulimit are the lower and upper limits of the array values printed
 * respectively. For enumerated arrays enum_nvs carries the list of name
 * and value pairs and ulimit and llimit parameters are ignored and instead
 * determined from the enum_nvs list.
 */
static void
print_int_array(
FILE *fp,
int arr[],
uint32_t size,
int llimit,
int ulimit,
str_val_nd_t *enum_nvs,
int tab_inserts)
{
	int x, y;
	uint32_t first, last;
	boolean_t first_entry;	/* first 'ranges:value' to be printed ? */
	boolean_t first_range;	/* first range for a value to be printed ? */
	boolean_t found_range;	/* did we find a range for this value ? */

	IPQOSCDBG4(L0, "In print_int_array: size: %u, llimit: %u, ulimit: %u, "
	    "enum_nvs: %x \n", size, llimit, ulimit, enum_nvs);

	/*
	 * if an enumeration retrieve value range.
	 */
	if (enum_nvs != NULL)
		get_str_val_value_range(enum_nvs, &llimit, &ulimit);

	/*
	 * print opening curl.
	 */
	(void) fprintf(fp, "%c\n", CURL_BEGIN);
	PRINT_TABS(fp, tab_inserts + 1);

	first_entry = B_TRUE;
	/*
	 * for each value in range.
	 */
	for (x = llimit; x <= ulimit; x++) {
		found_range = B_FALSE;
		first_range = B_TRUE;
		y = 0;
		/*
		 * scan array and print ranges of indexes with value x.
		 */
		while (y < size) {
			/*
			 * get first occurence of value for this range.
			 */
			while ((arr[y] != x) && (y < size))
				y++;
			if (y == size) {
				break;
			} else {
				found_range = B_TRUE;
			}
			first = y;

			/*
			 * get last occurence of value for this range.
			 */
			while ((arr[y] == x) && (y < size))
				y++;
			last = y - 1;

			/*
			 * print entry delimiter (semi-colon)? It must be
			 * the first range for this value and this mustn't
			 * be the first 'ranges:value' entry.
			 */
			if (!first_entry && first_range) {
				(void) fprintf(fp, ";\n");
				PRINT_TABS(fp, tab_inserts + 1);
			} else {
				first_entry = B_FALSE;
			}

			/*
			 * print comma (range delimeter) only if there was
			 * a previous range for this value.
			 */
			if (!first_range) {
				(void) fprintf(fp, ",");
			} else {
				first_range = B_FALSE;
			}

			/*
			 * print range.
			 */
			printrange(fp, first, last);
		}
		/*
		 * only print a colon and value if we found a range with
		 * this value.
		 */
		if (found_range) {
			(void) fprintf(fp, ":");

			/*
			 * print numeric/symbolic value.
			 */
			if (enum_nvs) {
				printenum(fp, x, enum_nvs);
			} else {
				(void) fprintf(fp, "%d", x);
			}
		}
	}

	/*
	 * print closing curl.
	 */
	(void) fprintf(fp, "\n");
	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, "%c\n", CURL_END);
}

/* print the protocol name for proto, or if unknown protocol number proto. */
static void
printproto(
FILE *fp,
uint8_t proto)
{

	struct protoent *pent;

	pent = getprotobynumber(proto);
	if (pent != NULL) {
		(void) fprintf(fp, "%s\n", pent->p_name);
	} else {
		(void) fprintf(fp, "%u\n", proto);
	}
}

/*
 * prints the name associated with interface with index ifindex to fp.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
printifname(
FILE *fp,
int ifindex)
{

	int s;
	struct lifconf lc;
	struct lifnum ln;
	struct lifreq *lr;
	char *buf;
	int len;
	char *cp;
	int ret;
	int x;
	int idx;

	/* open socket */

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		ipqos_msg(MT_ENOSTR, gettext("opening AF_INET socket"));
		return (IPQOS_CONF_ERR);
	}

	/* get number of lifreq structs that need to be alloc'd for */

	ln.lifn_family = AF_UNSPEC;
	ln.lifn_flags = 0;
	ret = ioctl(s, SIOCGLIFNUM, &ln);
	if (ret < 0) {
		ipqos_msg(MT_ENOSTR, "SIOCLIFNUM ioctl");
		(void) close(s);
		return (IPQOS_CONF_ERR);
	}

	/* allocate buffer for SIOGLIFCONF ioctl */

	len = ln.lifn_count * sizeof (struct lifreq);
	buf = malloc(len);
	if (buf == NULL) {
		ipqos_msg(MT_ENOSTR, "malloc");
		(void) close(s);
		return (IPQOS_CONF_ERR);
	}

	/* setup lifconf params for ioctl */

	lc.lifc_family = AF_UNSPEC;
	lc.lifc_flags = 0;
	lc.lifc_len = len;
	lc.lifc_buf = buf;

	/* do SIOCGLIFCONF ioctl */

	ret = ioctl(s, SIOCGLIFCONF, &lc);
	if (ret < 0) {
		ipqos_msg(MT_ENOSTR, "SIGLIFCONF");
		(void) close(s);
		free(buf);
		return (IPQOS_CONF_ERR);
	}
	(void) close(s);

	/*
	 * for each interface name given in the returned lifreq list get
	 * it's index and compare with ifindex param. Break if equal.
	 */
	for (x = ln.lifn_count, lr = lc.lifc_req; x > 0; x--, lr++) {
		ret = readifindex(lr->lifr_name, &idx);
		if (ret != IPQOS_CONF_SUCCESS) {
			free(buf);
			return (IPQOS_CONF_ERR);
		}
		if (idx == ifindex) {
			break;
		}
	}
	free(buf);

	if (x == 0) {
		IPQOSCDBG1(L1, "Failed to find if index %u in returned "
		    "if list.\n", ifindex);
		return (IPQOS_CONF_ERR);
	}
	/* truncate any logical suffix */

	if ((cp = strchr(lr->lifr_name, '@')) != NULL) {
		*cp = NULL;
	}

	/* print interface name */
	(void) fprintf(fp, "%s\n", lr->lifr_name);

	return (IPQOS_CONF_SUCCESS);
}

/*
 * print to fp the enumeration clause evaluating to the value val using the
 * names/values given in enum_nvs.
 */
static void
printenum(
FILE *fp,
uint32_t val,
str_val_nd_t *enum_nvs)
{

	boolean_t isfirstval = B_TRUE;
	str_val_nd_t *name_val = enum_nvs;

	/* for each value in enum_nvs if same bit set in val print name */

	while (name_val) {
		if ((name_val->sv.value & val) == name_val->sv.value) {
			if (isfirstval == B_TRUE) {
				(void) fprintf(fp, "%s", name_val->sv.string);
				isfirstval = B_FALSE;
			} else {
				(void) fprintf(fp, ", %s", name_val->sv.string);
			}
		}
		name_val = name_val->next;
	}
}


/* prints the service name of port, or if unknown the number to fp. */
static void
printport(
FILE *fp,
uint16_t port)
{

	struct servent *sent;

	sent = getservbyport(port, NULL);
	if (sent != NULL) {
		(void) fprintf(fp, "%s\n", sent->s_name);
	} else {
		(void) fprintf(fp, "%u\n", ntohs(port));
	}
}

/*
 * prints tp fp the name and value of all user specifiable parameters in the
 * nvlist.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
printnvlist(
FILE *fp,
char *module,
nvlist_t *nvl,
int printall,	/* are we want ip addresses printing if node name */
ipqos_conf_filter_t *flt,	/* used to determine if node name set */
int tab_inserts,
place_t place)
{
	FILE *tfp;
	nvpair_t *nvp;
	char *name;
	ipqos_nvtype_t type;
	str_val_nd_t *enum_nvs;
	int ret;
	char dfltst[IPQOS_VALST_MAXLEN+1];
	char *param;
	int openerr;
	int res;

	IPQOSCDBG0(L1, "In printnvlist\n");


	/* open stream to types file */

	tfp = validmod(module, &openerr);
	if (tfp == NULL) {
		if (openerr) {
			ipqos_msg(MT_ENOSTR, "fopen");
		}
		return (IPQOS_CONF_ERR);
	}


	/* go through list getting param name and type and printing it */

	nvp = nvlist_next_nvpair(nvl, NULL);
	while (nvp) {

		/* get nvpair name */
		name = nvpair_name(nvp);
		IPQOSCDBG1(L0, "processing element %s.\n", name);

		/* skip ipgpc params that are not explicitly user settable */

		if (strcmp(name, IPGPC_FILTER_TYPE) == 0 ||
		    strcmp(name, IPGPC_SADDR_MASK) == 0 ||
		    strcmp(name, IPGPC_DADDR_MASK) == 0 ||
		    strcmp(name, IPGPC_SPORT_MASK) == 0 ||
		    strcmp(name, IPGPC_DPORT_MASK) == 0) {
			nvp = nvlist_next_nvpair(nvl, nvp);
			continue;
		}

		param = SHORT_NAME(name);

		/*
		 * get parameter type from types file.
		 */
		place = PL_ANY;
		ret = readtype(tfp, module, param, &type, &enum_nvs, dfltst,
		    B_TRUE, &place);
		if (ret != IPQOS_CONF_SUCCESS) {
			return (ret);
		}

		/*
		 * for map entries we don't print the map value, only
		 * the index value it was derived from.
		 */
		if (place == PL_MAP) {
			nvp = nvlist_next_nvpair(nvl, nvp);
			continue;
		}

		/*
		 * the ifindex is converted to the name and printed out
		 * so print the parameter name as ifname.
		 */
		if (strcmp(name, IPGPC_IF_INDEX) == 0) {
			PRINT_TABS(fp, tab_inserts);
			(void) fprintf(fp, "%s ", IPQOS_IFNAME_STR);
		/*
		 * we may not print the address due to us instead printing
		 * the node name in printfilter, therefore we leave the
		 * printing of the parameter in the addresses switch case code.
		 */
		} else if ((strcmp(name, IPGPC_SADDR) != 0 &&
		    strcmp(name, IPGPC_DADDR) != 0)) {
			PRINT_TABS(fp, tab_inserts);
			(void) fprintf(fp, "%s ", param);
		}

		switch (type) {
			case IPQOS_DATA_TYPE_IFINDEX: {
				uint32_t ifidx;

				(void) nvpair_value_uint32(nvp, &ifidx);
				(void) printifname(fp, ifidx);
				break;
			}
			case IPQOS_DATA_TYPE_BOOLEAN: {
				boolean_t bl;

				(void) nvpair_value_uint32(nvp,
				    (uint32_t *)&bl);
				(void) fprintf(fp, "%s\n",
				    bl == B_TRUE ? "true" : "false");
				break;
			}
			case IPQOS_DATA_TYPE_ACTION: {
				char *strval;

				(void) nvpair_value_string(nvp, &strval);
				print_action_nm(fp, strval);
				break;
			}
			case IPQOS_DATA_TYPE_STRING: {
				char *strval;

				(void) nvpair_value_string(nvp, &strval);
				(void) fprintf(fp, "%s\n",
				    quote_ws_string(strval));
				break;
			}
			case IPQOS_DATA_TYPE_ADDRESS: {
				uint_t tmp;
				in6_addr_t *addr;
				char addrstr[INET6_ADDRSTRLEN];
				uchar_t ftype;
				int af;
				in6_addr_t *mask;

				/*
				 * skip addresses that have node names for
				 * non printall listings.
				 */
				if (printall == 0 &&
				    (strcmp(nvpair_name(nvp), IPGPC_SADDR) ==
				    0 && flt->src_nd_name ||
				    strcmp(nvpair_name(nvp), IPGPC_DADDR) ==
				    0 && flt->dst_nd_name)) {
					break;
				}

				/* we skipped this above */

				PRINT_TABS(fp, tab_inserts);
				(void) fprintf(fp, "%s ", param);

				(void) nvpair_value_uint32_array(nvp,
				    (uint32_t **)&addr, &tmp);

				/* get filter type */

				(void) nvlist_lookup_byte(nvl,
				    IPGPC_FILTER_TYPE, &ftype);
				if (ftype == IPGPC_V4_FLTR) {
					af = AF_INET;
					addr = (in6_addr_t *)
					&V4_PART_OF_V6((*addr));
				} else {
					af = AF_INET6;
				}
				/* get mask */

				if (strcmp(nvpair_name(nvp), IPGPC_SADDR) ==
				    0) {
					ret = nvlist_lookup_uint32_array(nvl,
					    IPGPC_SADDR_MASK,
					    (uint32_t **)&mask, &tmp);
				} else {
					ret = nvlist_lookup_uint32_array(nvl,
					    IPGPC_DADDR_MASK,
					    (uint32_t **)&mask, &tmp);
				}

				/* print address/mask to fp */

				(void) fprintf(fp, "%s/%u\n",
				    inet_ntop(af, addr, addrstr,
				    INET6_ADDRSTRLEN), masktocidr(af, mask));
				break;
			}
			case IPQOS_DATA_TYPE_ENUM: {
				uint32_t val;

				(void) nvpair_value_uint32(nvp, &val);

				/*
				 * print list of tokens resulting in val
				 */
				(void) fprintf(fp, "{ ");
				printenum(fp, val, enum_nvs);
				(void) fprintf(fp, " }\n");
				break;
			}
			case IPQOS_DATA_TYPE_PORT: {
				uint16_t port;

				(void) nvpair_value_uint16(nvp, &port);
				printport(fp, port);
				break;
			}
			case IPQOS_DATA_TYPE_PROTO: {
				uint8_t proto;

				(void) nvpair_value_byte(nvp, &proto);
				printproto(fp, proto);
				break;
			}
			case IPQOS_DATA_TYPE_M_INDEX:
			case IPQOS_DATA_TYPE_UINT8: {
				uchar_t u8;

				(void) nvpair_value_byte(nvp, &u8);
				(void) fprintf(fp, "%u\n", u8);
				break;
			}
			case IPQOS_DATA_TYPE_UINT16: {
				uint16_t u16;

				(void) nvpair_value_uint16(nvp, &u16);
				(void) fprintf(fp, "%u\n", u16);
				break;
			}
			case IPQOS_DATA_TYPE_INT16: {
				int16_t i16;

				(void) nvpair_value_int16(nvp, &i16);
				(void) fprintf(fp, "%d\n", i16);
				break;
			}
			case IPQOS_DATA_TYPE_UINT32: {
				uint32_t u32;

				(void) nvpair_value_uint32(nvp, &u32);
				(void) fprintf(fp, "%u\n", u32);
				break;
			}
			case IPQOS_DATA_TYPE_INT32: {
				int i32;

				(void) nvpair_value_int32(nvp, &i32);
				(void) fprintf(fp, "%d\n", i32);
				break;
			}
			case IPQOS_DATA_TYPE_INT_ARRAY: {
				str_val_nd_t *arr_enum_nvs = NULL;
				uint32_t size;
				int llimit, ulimit;
				int *arr;

				(void) nvpair_value_int32_array(nvp, &arr,
				    &size);

				/*
				 * read array info from types file.
				 */
				res = read_int_array_info(dfltst,
				    &arr_enum_nvs, &size, &llimit, &ulimit,
				    module);

				/*
				 * print array with numbers, or symbols
				 * if enumerated.
				 */
				if (res == IPQOS_CONF_SUCCESS) {
					print_int_array(fp, arr, size,
					    llimit, ulimit, arr_enum_nvs,
					    tab_inserts);
					if (arr_enum_nvs != NULL) {
						free_str_val_entrys(
						    arr_enum_nvs);
					}
				}
				break;
			}
			case IPQOS_DATA_TYPE_USER: {
				uid_t uid;

				(void) nvpair_value_int32(nvp, (int *)&uid);
				printuser(fp, uid);
				break;
			}
#ifdef	_IPQOS_CONF_DEBUG
			default: {
				/*
				 * we should have catered for all used data
				 * types that readtype returns.
				 */
				assert(1);
			}
#endif
		}

		nvp = nvlist_next_nvpair(nvl, nvp);
	}

	(void) fclose(tfp);
	return (IPQOS_CONF_SUCCESS);
}

/*
 * print a parameter clause for the parmeters given in params to fp.
 * If printall is set, then the originator of the parameter object is printed.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
printparams(
FILE *fp,
char *module,
ipqos_conf_params_t *params,
int printall,
int tab_inserts)
{

	int res;

	/* print opening clause */

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, IPQOS_CONF_PARAMS_STR " {\n");

	/* print originator name if printall flag set */

	if (printall) {
		PRINT_TABS(fp, tab_inserts + 1);
		(void) fprintf(stdout, "Originator %s\n",
		    quote_ws_string(get_originator_nm(params->originator)));
	}

	/* print global stats */

	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, IPQOS_CONF_GLOBAL_STATS_STR " %s\n",
	    params->stats_enable == B_TRUE ? "true" : "false");

	/* print module specific parameters */
	res = printnvlist(fp, module, params->nvlist, printall, NULL,
	    tab_inserts + 1, PL_PARAMS);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, "}\n");

	return (IPQOS_CONF_SUCCESS);
}

/*
 * print the interpreted name of the action_nm parameter if it is a special
 * action, else action_nm verbatim to fp parameter.
 */
static void
print_action_nm(FILE *fp, char *action_nm)
{

	if (strcmp(action_nm, IPP_ANAME_CONT) == 0) {
		(void) fprintf(fp, IPQOS_CONF_CONT_STR "\n");
	} else if (strcmp(action_nm, IPP_ANAME_DEFER) == 0) {
		(void) fprintf(fp, IPQOS_CONF_DEFER_STR "\n");
	} else if (strcmp(action_nm, IPP_ANAME_DROP) == 0) {
		(void) fprintf(fp, IPQOS_CONF_DROP_STR "\n");
	} else {
		(void) fprintf(fp, "%s\n", quote_ws_string(action_nm));
	}
}

/*
 * print a class clause for class to fp. If printall is set the originator
 * is printed.
 */
static void
printclass(
FILE *fp,
ipqos_conf_class_t *class,
int printall,
int tab_inserts)
{

	/* print opening clause */

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, IPQOS_CONF_CLASS_STR " {\n");


	/* if printall flag print originator name */

	if (printall) {
		PRINT_TABS(fp, tab_inserts + 1);
		(void) fprintf(stdout, "Originator %s\n",
		    get_originator_nm(class->originator));
	}

	/* print name, next action and stats enable */

	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, IPQOS_CONF_NAME_STR " %s\n",
	    quote_ws_string(class->name));
	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, IPQOS_CONF_NEXT_ACTION_STR " ");
	    print_action_nm(fp, class->alist->name);
	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, IPQOS_CONF_STATS_ENABLE_STR " %s\n",
	    class->stats_enable == B_TRUE ? "true" : "false");

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, "}\n");
}

/*
 * Returns a ptr to the originator name associated with origid. If unknown
 * id returns ptr to "unknown".
 * RETURNS: ptr to originator name, or if id not known "unknown".
 */
static char *
get_originator_nm(uint32_t origid)
{

	int x;

	/* scan originators table for origid */

	for (x = 0; originators[x].value != -1 &&
	    originators[x].value != origid; x++) {}

	/* if we've reached end of array due to unknown type return "unknown" */

	if (originators[x].value == -1) {
		return ("unknown");
	}

	return (originators[x].string);
}

/*
 * print a filter clause for filter pointed to by filter out to fp. If printall
 * is set then the originator is printed, for filters with node names instance
 * numbers are printed, and the filter pointer isn't advanced to point at the
 * last instance of the printed filter.
 * RETURNS: IPQOS_CONF_ERR on errors, else IPQOS_CONF_SUCCESS.
 */
static int
printfilter(
FILE *fp,
char *module,
ipqos_conf_filter_t **filter,
int printall,
int tab_inserts)
{

	int res;

	/* print opening clause */

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, IPQOS_CONF_FILTER_STR " {\n");

	/* print originator if printall flag set */

	if (printall) {
		PRINT_TABS(fp, tab_inserts + 1);
		(void) fprintf(stdout, "Originator %s\n",
		    quote_ws_string(get_originator_nm((*filter)->originator)));
	}

	/* print name and class */

	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, IPQOS_CONF_NAME_STR " %s\n",
	    quote_ws_string((*filter)->name));
	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, IPQOS_CONF_CLASS_STR " %s\n",
	    quote_ws_string((*filter)->class_name));

	/* print the instance if printall and potential mhomed addresses */

	if (printall && ((*filter)->src_nd_name || (*filter)->dst_nd_name)) {
		PRINT_TABS(fp, tab_inserts + 1);
		(void) fprintf(fp, "Instance %u\n", (*filter)->instance);
	}

	/* print node names if any */

	if ((*filter)->src_nd_name) {
		PRINT_TABS(fp, tab_inserts + 1);
		(void) fprintf(fp, "%s %s\n", strchr(IPGPC_SADDR, '.') + 1,
		    (*filter)->src_nd_name);
	}
	if ((*filter)->dst_nd_name) {
		PRINT_TABS(fp, tab_inserts + 1);
		(void) fprintf(fp, "%s %s\n", strchr(IPGPC_DADDR, '.') + 1,
		    (*filter)->dst_nd_name);
	}

	/* print ip_version enumeration if set */

	if ((*filter)->ip_versions != 0) {
		PRINT_TABS(fp, tab_inserts + 1);
		(void) fprintf(fp, IPQOS_CONF_IP_VERSION_STR " {");
		if (VERSION_IS_V4(*filter)) {
			(void) fprintf(fp, " V4");
		}
		if (VERSION_IS_V6(*filter)) {
			(void) fprintf(fp, " V6");
		}
		(void) fprintf(fp, " }\n");
	}

	/* print other module specific parameters parameters */

	res = printnvlist(fp, module, (*filter)->nvlist, printall, *filter,
	    tab_inserts + 1, PL_FILTER);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, "}\n");

	/*
	 * if not printall advance filter parameter to last instance of this
	 * filter.
	 */

	if (!printall) {
		for (;;) {
			if ((*filter)->next == NULL ||
			    strcmp((*filter)->name, (*filter)->next->name) !=
			    0) {
				break;
			}
			*filter = (*filter)->next;
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Returns a pointer to str if no whitespace is present, else it returns
 * a pointer to a string with the contents of str enclose in double quotes.
 * This returned strings contents may change in subsequent calls so a copy
 * should be made of it if the caller wishes to retain it.
 */
static char *
quote_ws_string(const char *str)
{
	static char *buf = NULL;
	const char *cp;	/* we don't modify the contents of str so const */

	IPQOSCDBG0(L0, "In quote_ws_string\n");

	/*
	 * Just return str if no whitespace.
	 */
	for (cp = str; (*cp != '\0') && !isspace(*cp); cp++)
		;
	if (*cp == '\0')
		return ((char *)str);

	if (buf == NULL) {
		/*
		 * if first run just allocate buffer of
		 * strlen(str) + 2 quote characters + NULL terminator.
		 */
		buf = malloc(strlen(str) + 3);
	} else if ((strlen(str) + 2) > strlen(buf)) {
		/*
		 * Not first run, so check if we have a big enough buffer
		 * and if not reallocate the buffer to a sufficient size.
		 */
		buf = realloc(buf, strlen(str) + 3);
	}
	if (buf == NULL)
		return ("");

	/*
	 * copy string into buffer with quotes.
	 */
	(void) strcpy(buf, "\"");
	(void) strcat(buf, str);
	(void) strcat(buf, "\"");

	return (buf);
}

/*
 * print an action clause for action to fp. If the printall flag is set
 * then all filters and classes (regardless of their originator) and
 * their originators are displayed.
 * RETURNS: IPQOS_CONF_ERR on errors, else IPQOS_CONF_SUCCESS.
 */
static int
printaction(
FILE *fp,
ipqos_conf_action_t *action,
int printall,
int tab_inserts)
{

	ipqos_conf_filter_t *flt;
	ipqos_conf_class_t *cls;
	int res;

	/* print opening clause, module and name */

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, IPQOS_CONF_ACTION_STR " {\n");
	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, IPQOS_CONF_MODULE_STR " %s\n",
	    quote_ws_string(action->module));
	PRINT_TABS(fp, tab_inserts + 1);
	(void) fprintf(fp, "name %s\n", quote_ws_string(action->name));

	/* print params clause */

	(void) fprintf(fp, "\n");
	res = printparams(fp, action->module, action->params, printall,
	    tab_inserts + 1);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/*
	 * print classes clause for each class if printall is set, else
	 * just ipqosconf created or permanent classes.
	 */
	for (cls = action->classes; cls != NULL; cls = cls->next) {
		if (printall ||
		    cls->originator == IPP_CONFIG_IPQOSCONF ||
		    cls->originator == IPP_CONFIG_PERMANENT) {
			(void) fprintf(fp, "\n");
			printclass(fp, cls, printall, tab_inserts + 1);
		}
	}

	/*
	 * print filter clause for each filter if printall is set, else
	 * just ipqosconf created or permanent filters.
	 */
	for (flt = action->filters; flt != NULL; flt = flt->next) {
		if (printall ||
		    flt->originator == IPP_CONFIG_IPQOSCONF ||
		    flt->originator == IPP_CONFIG_PERMANENT) {
			(void) fprintf(fp, "\n");
			res = printfilter(fp, action->module, &flt, printall,
			    tab_inserts + 1);
			if (res != IPQOS_CONF_SUCCESS) {
				return (res);
			}
		}
	}

	PRINT_TABS(fp, tab_inserts);
	(void) fprintf(fp, "}\n");

	return (IPQOS_CONF_SUCCESS);
}



/* *************************************************************** */


static void
list_end(
ipqos_list_el_t **listp,
ipqos_list_el_t ***lendpp)
{
	*lendpp = listp;
	while (**lendpp != NULL) {
		*lendpp = &(**lendpp)->next;
	}
}

static void
add_to_list(
ipqos_list_el_t **listp,
ipqos_list_el_t *el)
{
	el->next = *listp;
	*listp = el;
}

/*
 * given mask calculates the number of bits it spans. The mask must be
 * continuous.
 * RETURNS: number of bits spanned.
 */
static int
masktocidr(
int af,
in6_addr_t *mask)
{
	int zeros = 0;
	int byte;
	int cidr;

	/*
	 * loop through from lowest byte to highest byte counting the
	 * number of zero bits till hitting a one bit.
	 */
	for (byte = 15; byte >= 0; byte--) {
		/*
		 * zero byte, so add 8 to zeros.
		 */
		if (mask->s6_addr[byte] == 0) {
			zeros += 8;
		/*
		 * non-zero byte, add zero count to zeros.
		 */
		} else {
			zeros += (ffs((int)mask->s6_addr[byte]) - 1);
			break;
		}
	}
	/*
	 * translate zero bits to 32 or 128 bit mask based on af.
	 */
	if (af == AF_INET) {
		cidr = 32 - zeros;
	} else {
		cidr = 128 - zeros;
	}

	return (cidr);
}

/*
 * Sets the first prefix_len bits in the v4 or v6 address (based upon af)
 * contained in the v6 address referenced by addr to 1.
 */
static void
setmask(int prefix_len, in6_addr_t *addr, int af)
{

	int i;
	int shift;
	int maskstartbit = 128 - prefix_len;
	int end_u32;

	IPQOSCDBG2(L1, "In setmask, prefix_len: %u, af: %s\n", prefix_len,
	    af == AF_INET ? "AF_INET" : "AF_INET6");

	/* zero addr */
	bzero(addr, sizeof (in6_addr_t));


	/* set which 32bits in *addr are relevant to this af */

	if (af == AF_INET) {
		end_u32 = 3;
		maskstartbit = 32 - prefix_len;
	/* AF_INET6 */
	} else {
		end_u32 = 0;
	}
	/*
	 * go through each of the 32bit quantities in 128 bit in6_addr_t
	 * and set appropriate bits according to prefix_len.
	 */
	for (i = 3; i >= end_u32; i--) {

		/* does the prefix apply to this 32bits? */

		if (maskstartbit < ((4 - i) * 32)) {

			/* is this 32bits fully masked? */

			if (maskstartbit <= ((3 - i) * 32)) {
				shift = 0;
			} else {
				shift = maskstartbit % 32;
			}
			addr->_S6_un._S6_u32[i] = (uint32_t)~0;
			addr->_S6_un._S6_u32[i] =
			    addr->_S6_un._S6_u32[i] >> shift;
			addr->_S6_un._S6_u32[i] =
			    addr->_S6_un._S6_u32[i] << shift;
		}

		/* translate to NBO */
		addr->_S6_un._S6_u32[i] = htonl(addr->_S6_un._S6_u32[i]);
	}
}

/*
 * search nvlist for an element with the name specified and return a ptr
 * to it if found.
 * RETURNS: pointer to nvpair named name if found, else NULL.
 */
static nvpair_t *
find_nvpair(nvlist_t *nvl, char *name)
{

	nvpair_t *nvp;
	nvpair_t *match = NULL;
	char *nvp_name;

	IPQOSCDBG0(L1, "In find_nvpair\n");

	nvp = nvlist_next_nvpair(nvl, NULL);
	while (nvp) {
		nvp_name = nvpair_name(nvp);
		if (strcmp(name, nvp_name) == 0) {
			match = nvp;
		}
		nvp = nvlist_next_nvpair(nvl, nvp);
	}

	return (match);
}

/*
 * returns a string containing module_name '.' name.
 * RETURNS: IPQOS_CONF_ERR if error, else IPQOS_CONF_SUCCESS.
 */
static char *
prepend_module_name(
char *name,
char *module)
{

	char *ret;

	IPQOSCDBG0(L2, "In prepend_module_name\n");

	ret = malloc(strlen(module) + strlen(".") + strlen(name) + 1);
	if (ret == NULL) {
		ipqos_msg(MT_ENOSTR, "malloc");
		return (NULL);
	}

	(void) strcpy(ret, module);
	(void) strcat(ret, ".");
	(void) strcat(ret, name);

	return (ret);
}

#if 0

/*
 * check if element with matching s1 and s2 string is in table table.
 * RETURNS: 1 if found else 0.
 */
static int
in_str_str_table(
str_str_t *table,
char *s1,
char *s2)
{

	str_str_t *ss = table;

	/* loop through table till matched or end */

	while (ss->s1[0] != '\0' &&
	    (strcmp(ss->s1, s1) != 0 || strcmp(ss->s2, s2) != 0)) {
		ss++;
	}

	if (ss->s1[0] != '\0') {
		return (1);
	}

	return (0);
}
#endif	/* 0 */

/*
 * check whether name is a valid action/class/filter name.
 * RETURNS: IPQOS_CONF_ERR if invalid name else IPQOS_CONF_SUCCESS.
 */
static int
valid_name(char *name)
{

	IPQOSCDBG1(L1, "In valid_name: name: %s\n", name);

	/* first char can't be '!' */
	if (name[0] == '!') {
		ipqos_msg(MT_ERROR, gettext("Name not allowed to start with "
		    "'!', line %u.\n"), lineno);
		return (IPQOS_CONF_ERR);
	}

	/* can't exceed IPQOS_CONF_NAME_LEN size */
	if (strlen(name) >= IPQOS_CONF_NAME_LEN) {
		ipqos_msg(MT_ERROR, gettext("Name exceeds maximum name length "
		    "line %u.\n"), lineno);
		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}

/* ********************* string value manip fns ************************** */


/*
 * searches through the str_val_nd_t list of string value pairs finding
 * the minimum and maximum values for value and places them in the
 * integers pointed at by min and max.
 */
static void
get_str_val_value_range(
str_val_nd_t *svnp,
int *min,
int *max)
{
	if (svnp != NULL) {
		*min = *max = svnp->sv.value;
		svnp = svnp->next;
	}
	while (svnp != NULL) {
		if (svnp->sv.value > *max)
			*max = svnp->sv.value;
		if (svnp->sv.value < *min)
			*min = svnp->sv.value;
		svnp = svnp->next;
	}
}

/*
 * add an entry with string string and value val to sv_entrys.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
add_str_val_entry(
str_val_nd_t **sv_entrys,
char *string,
uint32_t val)
{

	str_val_nd_t *sv_entry;

	IPQOSCDBG2(L1, "In add_str_val_entry: string: %s, val: %u\n", string,
	    val);

	/* alloc new node */

	sv_entry = malloc(sizeof (str_val_nd_t));
	if (sv_entry == NULL) {
		return (IPQOS_CONF_ERR);
	}

	/* populate node */

	sv_entry->sv.string = malloc(strlen(string) + 1);
	if (sv_entry->sv.string == NULL) {
		free(sv_entry);
		ipqos_msg(MT_ENOSTR, "malloc");
		return (IPQOS_CONF_ERR);
	} else {
		(void) strcpy(sv_entry->sv.string, string);
	}
	sv_entry->sv.value = val;

	/* place at start of sv_entrys list */

	sv_entry->next = *sv_entrys;
	*sv_entrys = sv_entry;

	return (IPQOS_CONF_SUCCESS);
}


/* frees all the elements of sv_entrys. */
static void
free_str_val_entrys(
str_val_nd_t *sv_entrys)
{

	str_val_nd_t *sve = sv_entrys;
	str_val_nd_t *tmp;

	IPQOSCDBG0(L1, "In free_str_val_entrys\n");

	while (sve) {
		free(sve->sv.string);
		tmp = sve->next;
		free(sve);
		sve = tmp;
	}
}

/*
 * finds the value associated with string and assigns it to value ref'd by
 * val.
 * RETURNS: IPQOS_CONF_ERR if string not found, else IPQOS_CONF_SUCCESS.
 */
static int
str_val_list_lookup(
str_val_nd_t *svs,
char *string,
uint32_t *val)
{

	str_val_nd_t *sv = svs;

	IPQOSCDBG1(L1, "In str_val_list_lookup: %s\n", string);

	/* loop through list and exit when found or list end */

	while (sv != NULL) {
		if (strcmp(sv->sv.string, string) == 0) {
			break;
		}
		sv = sv->next;
	}

	/* ret error if not found */

	if (sv == NULL) {
		return (IPQOS_CONF_ERR);
	}

	*val = sv->sv.value;

	IPQOSCDBG1(L1, "svll: Value returned is %u\n", *val);
	return (IPQOS_CONF_SUCCESS);
}


/* ************************ conf file read fns ***************************** */

/*
 * Reads a uid or username from string 'str' and assigns either the uid
 * or associated uid respectively to storage pointed at by 'uid'. The
 * function determines whether to read a uid by checking whether the first
 * character of 'str' is numeric, in which case it reads a uid; otherwise it
 * assumes a username.
 * RETURNS: IPQOS_CONF_ERR if a NULL string pointer is passed, the read uid
 * doesn't have an entry on the system, or the read username doesn't have an
 * entry on the system.
 */
static int
readuser(
char *str,
uid_t *uid)
{
	struct passwd *pwd;
	char *lo;

	IPQOSCDBG1(L0, "In readuser, str: %s\n", str);

	if (str == NULL)
		return (IPQOS_CONF_ERR);
	/*
	 * Check if this appears to be a uid, and if so check that a
	 * corresponding user exists.
	 */
	if (isdigit((int)str[0])) {
		/*
		 * Read a 32bit integer and check in doing so that
		 * we have consumed the whole string.
		 */
		if (readint32(str, (int *)uid, &lo) != IPQOS_CONF_SUCCESS ||
		    *lo != '\0')
			return (IPQOS_CONF_ERR);
		if (getpwuid(*uid) == NULL)
			return (IPQOS_CONF_ERR);

	} else {	/* This must be a username, so lookup the uid. */
		pwd = getpwnam(str);
		if (pwd == NULL) {
			return (IPQOS_CONF_ERR);
		} else {
			*uid = pwd->pw_uid;
		}
	}
	return (IPQOS_CONF_SUCCESS);
}

/*
 * Reads a range from range_st, either of form 'a-b' or simply 'a'.
 * In the former case lower and upper have their values set to a
 * and b respectively; in the later lower and upper have both
 * their values set to a.
 * RETURNS: IPQOS_CONF_ERR if there's a parse error, else IPQOS_CONF_SUCCESS.
 */
static int
readrange(
char *range_st,
int *lower,
int *upper)
{
	char *cp;
	char *end, *end2;

	IPQOSCDBG1(L0, "In readrange: string: %s\n", range_st);

	/*
	 * get range boundarys.
	 */
	cp = strchr(range_st, '-');

	if (cp != NULL) {	/* we have a range */
		*cp++ = '\0';
		*lower = (int)strtol(range_st, &end, 10);
		*upper = (int)strtol(cp, &end2, 10);
		SKIPWS(end);
		SKIPWS(end2);
		if ((range_st == end) || (*end != NULL) ||
		    (cp == end) || (*end2 != NULL)) {
			IPQOSCDBG0(L0, "Failed reading a-b\n");
			return (IPQOS_CONF_ERR);
		}

	} else {		/* single value */

		*lower = *upper = (int)strtol(range_st, &end, 10);
		SKIPWS(end);
		if ((range_st == end) || (*end != NULL)) {
			IPQOSCDBG0(L0, "Failed reading a\n");
			return (IPQOS_CONF_ERR);
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Reads the values of an integer array from fp whose format is:
 * '{'RANGE[,RANGE[..]]:VALUE[;RANGE:VALUE[..]]'}', creates an array of size
 * arr_size, applies the values to it and points arrp at this array.
 * RANGE is one set of array indexes over which this value is to
 * be applied, and VALUE either an integer within the range
 * llimit - ulimit, or if enum_nvs isn't NULL, an enumeration value
 * found in the list enum_nvs. Those values which aren't explicity set
 * will be set to -1.
 *
 * RETURNS: IPQOS_CONF_ERR on resource or parse error, else IPQOS_CONF_SUCCESS.
 */
static int
read_int_array(
FILE *fp,
char *first_token,
int **arrp,
uint32_t arr_size,
int llimit,
int ulimit,
str_val_nd_t *enum_nvs)
{

	char buf[5 * IPQOS_CONF_LINEBUF_SZ];
	char *token;
	char *range;
	char *ranges;
	char *svalue;
	int value;
	int res;
	char *entry;
	char *tmp;
	char *end;
	int lower, upper;
	int x;
	uint32_t startln;

	IPQOSCDBG4(L0, "In read_int_array: size: %u, lower: %u, upper: %u, "
	    "first_token: %s\n", arr_size, llimit, ulimit, first_token);

	/*
	 * read beginning curl.
	 */
	if (first_token[0] != CURL_BEGIN) {
		ipqos_msg(MT_ERROR, gettext("\'{\' missing at line "
		    "%u.\n"), lineno);
		return (IPQOS_CONF_ERR);
	}

	/*
	 * allocate and initialise array for holding read values.
	 */
	*arrp = malloc(arr_size * sizeof (int));
	if (*arrp == NULL) {
		ipqos_msg(MT_ENOSTR, "malloc");
		return (IPQOS_CONF_ERR);
	}
	(void) memset(*arrp, -1, arr_size * sizeof (int));

	/*
	 * read whole array declaration string into buffer.
	 * this is because readtoken doesn't interpret our
	 * delimeter values specially and may return them
	 * within another string.
	 */
	startln = lineno;	/* store starting lineno for error reports */
	buf[0] = '\0';
	res = readtoken(fp, &token);
	while ((res != IPQOS_CONF_CURL_END) && (res != IPQOS_CONF_ERR) &&
	    (res != IPQOS_CONF_EOF)) {
		(void) strlcat(buf, token, sizeof (buf));
		free(token);
		res = readtoken(fp, &token);
	}
	if (res != IPQOS_CONF_CURL_END) {
		goto array_err;
	}
	IPQOSCDBG1(L0, "array declaration buffer contains: %s\n", buf);

	/*
	 * loop reading "ranges ':' value;" till end of buffer.
	 */
	entry = strtok(buf, ";");
	while (entry != NULL) {
		svalue = strchr(entry, ':');
		if (svalue == NULL) {	/* missing value string */
			IPQOSCDBG0(L0, "Missing value string\n");
			goto array_err;
		}
		*svalue++ = '\0';
		ranges = entry;

		/*
		 * get value of number or enumerated symbol.
		 */
		if (enum_nvs) {
			/*
			 * get rid of surrounding whitespace so as not to
			 * confuse read_enum_value.
			 */
			SKIPWS(svalue);
			tmp = svalue;
			while (*tmp != '\0') {
				if (isspace(*tmp)) {
					*tmp = '\0';
					break;
				} else {
					tmp++;
				}
			}

			/*
			 * read enumeration value.
			 */
			res = read_enum_value(NULL, svalue, enum_nvs,
			    (uint32_t *)&value);
			if (res != IPQOS_CONF_SUCCESS)
				goto array_err;
		} else {
			value = (int)strtol(svalue, &end, 10);
			SKIPWS(end);
			if ((svalue == end) || (*end != NULL)) {
				IPQOSCDBG0(L0, "Invalid value\n");
				goto array_err;
			}
			IPQOSCDBG1(L0, "value: %u\n", value);

			/*
			 * check value within valid range.
			 */
			if ((value < llimit) || (value > ulimit)) {
				IPQOSCDBG0(L0, "value out of range\n");
				goto array_err;
			}
		}

		/*
		 * loop reading ranges for this value.
		 */
		range = strtok_r(ranges, ",", &tmp);
		while (range != NULL) {
			res = readrange(range, &lower, &upper);
			if (res != IPQOS_CONF_SUCCESS)
				goto array_err;
			IPQOSCDBG2(L0, "range: %u - %u\n", lower, upper);


			if (upper < lower) {
				uint32_t u = lower;
				lower = upper;
				upper = u;
			}

			/*
			 * check range valid for array size.
			 */
			if ((lower < 0) || (upper > arr_size)) {
				IPQOSCDBG0(L0, "Range out of array "
				    "dimensions\n");
				goto array_err;
			}

			/*
			 * add this value to array indexes within range.
			 */
			for (x = lower; x <= upper; x++)
				(*arrp)[x] = value;

			/*
			 * get next range.
			 */
			range = strtok_r(NULL, ",", &tmp);
		}

		entry = strtok(NULL, ";");
	}

	return (IPQOS_CONF_SUCCESS);

array_err:
	ipqos_msg(MT_ERROR,
	    gettext("Array declaration line %u is invalid.\n"), startln);
	free(*arrp);
	return (IPQOS_CONF_ERR);
}

static int
readllong(char *str, long long *llp, char **lo)
{

	*llp = strtoll(str, lo, 0);
	if (*lo == str) {
		return (IPQOS_CONF_ERR);
	}
	return (IPQOS_CONF_SUCCESS);
}

static int
readuint8(char *str, uint8_t *ui8, char **lo)
{

	long long tmp;

	if (readllong(str, &tmp, lo) != 0) {
		return (IPQOS_CONF_ERR);
	}
	if (tmp > UCHAR_MAX || tmp < 0) {
		return (IPQOS_CONF_ERR);
	}
	*ui8 = (uint8_t)tmp;
	return (IPQOS_CONF_SUCCESS);
}

static int
readuint16(char *str, uint16_t *ui16, char **lo)
{
	long long tmp;

	if (readllong(str, &tmp, lo) != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}
	if (tmp > USHRT_MAX || tmp < 0) {
		return (IPQOS_CONF_ERR);
	}
	*ui16 = (uint16_t)tmp;
	return (IPQOS_CONF_SUCCESS);
}

static int
readint16(char *str, int16_t *i16, char **lo)
{
	long long tmp;

	if (readllong(str, &tmp, lo) != 0) {
		return (IPQOS_CONF_ERR);
	}
	if (tmp > SHRT_MAX || tmp < SHRT_MIN) {
		return (IPQOS_CONF_ERR);
	}
	*i16 = (int16_t)tmp;
	return (IPQOS_CONF_SUCCESS);
}

static int
readint32(char *str, int *i32, char **lo)
{
	long long tmp;

	if (readllong(str, &tmp, lo) != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}
	if (tmp > INT_MAX || tmp < INT_MIN) {
		return (IPQOS_CONF_ERR);
	}
	*i32 = tmp;
	return (IPQOS_CONF_SUCCESS);
}

static int
readuint32(char *str, uint32_t *ui32, char **lo)
{
	long long tmp;

	if (readllong(str, &tmp, lo) != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}
	if (tmp > UINT_MAX || tmp < 0) {
		return (IPQOS_CONF_ERR);
	}
	*ui32 = (uint32_t)tmp;
	return (IPQOS_CONF_SUCCESS);
}

/*
 * retrieves the index associated with the interface named ifname and assigns
 * it to the int pointed to by ifindex.
 * RETURNS: IPQOS_CONF_ERR on errors, else IPQOS_CONF_SUCCESS.
 */
static int
readifindex(
char *ifname,
int *ifindex)
{

	int s;
	struct lifreq lifrq;


	/* open socket */

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		ipqos_msg(MT_ENOSTR, gettext("opening AF_INET socket"));
		return (IPQOS_CONF_ERR);
	}

	/* copy ifname into lifreq */

	(void) strlcpy(lifrq.lifr_name, ifname, LIFNAMSIZ);

	/* do SIOGLIFINDEX ioctl */

	if (ioctl(s, SIOCGLIFINDEX, (caddr_t)&lifrq) == -1) {
		(void) close(s);
		return (IPQOS_CONF_ERR);
	}

	/* Warn if a virtual interface is specified */
	if ((ioctl(s, SIOCGLIFFLAGS, (caddr_t)&lifrq) != -1) &&
	    (lifrq.lifr_flags & IFF_VIRTUAL)) {
		ipqos_msg(MT_WARNING, gettext("Invalid interface"));
	}
	(void) close(s);
	*ifindex = lifrq.lifr_index;
	return (IPQOS_CONF_SUCCESS);
}

/*
 * Case insensitively compares the string in str with IPQOS_CONF_TRUE_STR
 * and IPQOS_CONF_FALSE_STR and sets boolean pointed to by bool accordingly.
 * RETURNS: if failure to match either IPQOS_CONF_ERR, else IPQOS_CONF_SUCCESS.
 */
static int
readbool(char *str, boolean_t *bool)
{

	if (strcasecmp(str, IPQOS_CONF_TRUE_STR) == 0) {
		*bool = B_TRUE;
	} else if (strcasecmp(str, IPQOS_CONF_FALSE_STR) == 0) {
		*bool = B_FALSE;
	} else {
		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * reads a protocol name/number from proto_str and assigns the number
 * to the uint8 ref'd by proto.
 * RETURNS: If not a valid name or protocol number IPQOS_CONF_ERR, else
 * IPQOS_CONF_SUCCESS.
 */
static int
readproto(char *proto_str, uint8_t *proto)
{

	struct protoent *pent;
	char *lo;
	int res;

	IPQOSCDBG1(L1, "In readproto: string: %s\n", proto_str);

	/* try name lookup */

	pent = getprotobyname(proto_str);
	if (pent) {
		*proto = pent->p_proto;

	/* check valid protocol number */
	} else {
		res = readuint8(proto_str, proto, &lo);
		if (res != IPQOS_CONF_SUCCESS || proto == 0) {
			return (IPQOS_CONF_ERR);
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * reads either a port service, or a port number from port_str and assigns
 * the associated port number to short ref'd by port.
 * RETURNS: If invalid name and number IPQOS_CONF_ERR, else IPQOS_CONF_SUCCESS.
 */
static int
readport(char *port_str, uint16_t *port)
{

	struct servent *sent;
	char *tmp;

	IPQOSCDBG1(L1, "In readport: string: %s\n", port_str);

	/* try service name lookup */
	sent = getservbyname(port_str, NULL);

	/* failed name lookup so read port number */
	if (sent == NULL) {
		if (readuint16(port_str, port, &tmp) != IPQOS_CONF_SUCCESS ||
		    *port == 0) {
			return (IPQOS_CONF_ERR);
		}
		*port = htons(*port);
	} else {
		*port = sent->s_port;
	}

	return (IPQOS_CONF_SUCCESS);
}


/*
 * Reads a curly brace, a string enclosed in double quotes, or a whitespace/
 * curly brace delimited string. If a double quote enclosed string the
 * closing quotes need to be on the same line.
 * RETURNS:
 * on reading a CURL_BEGIN token it returns IPQOS_CONF_CURL_BEGIN,
 * on reading a CURL_END token it returns IPQOS_CONF_CURL_END,
 * on reading another valid token it returns IPQOS_CONF_SUCCESS.
 * for each of these token is set to point at the read string.
 * at EOF it returns IPQOS_CONF_EOF and if errors it returns IPQOS_CONF_ERR.
 */
static int
readtoken(
FILE *fp,
char **token)
{

	char *st, *tmp;
	int len;
	int quoted = 0;
	char *cmnt;
	char *bpos;
	int rembuf;

	static char *lo;
	static char *buf = NULL;
	static int bufsize;

	/* if first call initialize line buf to default size */

	if (buf == NULL) {
		bufsize = IPQOS_CONF_LINEBUF_SZ;
		buf = malloc(bufsize);
		if (buf == NULL) {
			ipqos_msg(MT_ENOSTR, "malloc");
			return (IPQOS_CONF_ERR);
		}
	}

	/* set buffer postition and size to use whole buffer */

	bpos = buf;
	rembuf = bufsize;


	/*
	 * loop reading lines until we've read a line with a non-whitespace
	 * char.
	 */

	do {
		/* if no leftover from previous invocation */

		if (lo == NULL) {

			/*
			 * loop reading into buffer doubling if necessary until
			 * we have either read a complete line or reached the
			 * end of file.
			 */
			for (;;) {
				st = fgets(bpos, rembuf, fp);

				if (st == NULL) {

					/* if read error */
					if (ferror(fp)) {
						free(buf);
						buf = NULL;
						ipqos_msg(MT_ENOSTR,
						    "fgets");
						return (IPQOS_CONF_ERR);

					/* end of file */
					} else {
						free(buf);
						buf = NULL;
						*token = NULL;
						return (IPQOS_CONF_EOF);
					}
				} else {
					/* if read a newline */

					if (buf[strlen(buf) - 1] == '\n') {
						lineno++;
						break;

					/* if read the last line */

					} else if (feof(fp)) {
						break;

					/*
					 * not read a full line so buffer size
					 * is too small, double it and retry.
					 */
					} else {
						bufsize *= 2;
						tmp = realloc(buf, bufsize);
						if (tmp == NULL) {
							ipqos_msg(MT_ENOSTR,
							    "realloc");
							free(buf);
							return (IPQOS_CONF_ERR);
						} else {
							buf = tmp;
						}

						/*
						 * make parameters to fgets read
						 * into centre of doubled buffer
						 * so we retain what we've
						 * already read.
						 */
						bpos = &buf[(bufsize / 2) - 1];
						rembuf = (bufsize / 2) + 1;
					}
				}
			}

			st = buf;

		/* previous leftover, assign to st */

		} else {
			st = lo;
			lo = NULL;
		}

		/* truncate at comment */

		cmnt = strchr(st, '#');
		if (cmnt) {
			*cmnt = '\0';
		}

		/* Skip any whitespace */

		while (isspace(*st) && *st != '\0') {
			st++;
		}

	} while (*st == '\0');


	/* find end of token */

	tmp = st;

	/* if curl advance 1 char */

	if (*tmp == CURL_BEGIN || *tmp == CURL_END) {
		tmp++;


	/* if dbl quote read until matching quote */

	} else if (*tmp == '"') {
		quoted++;
		tmp = ++st;

		while (*tmp != '"' && *tmp != '\n' && *tmp != '\0') {
			tmp++;
		}
		if (*tmp != '"') {
			ipqos_msg(MT_ERROR, gettext("Quoted string exceeds "
			    "line, line %u.\n"), lineno);
			free(buf);
			return (IPQOS_CONF_ERR);
		}

	/* normal token */
	} else {
		/* find first whitespace, curl, newline or string end */

		while (!isspace(*tmp) && *tmp != CURL_BEGIN &&
		    *tmp != CURL_END && *tmp != '\n' && *tmp != '\0') {
			tmp++;
		}
	}

	/* copy token to return */
	len = tmp - st;
	*token = malloc(len + 1);
	if (!*token) {
		free(buf);
		ipqos_msg(MT_ENOSTR, "malloc");
		return (IPQOS_CONF_ERR);
	}
	bcopy(st, *token, len);
	(*token)[len] = '\0';

	/* if just read quoted string remove quote from remaining string */

	if (quoted) {
		tmp++;
	}

	/* if not end of string, store rest for latter parsing */

	if (*tmp != '\0' && *tmp != '\n') {
		lo = tmp;
	}

	/* for curl_end and curl_begin return special ret codes */

	if ((*token)[1] == '\0') {
		if (**token == CURL_BEGIN) {
			return (IPQOS_CONF_CURL_BEGIN);
		} else if (**token == CURL_END) {
			return (IPQOS_CONF_CURL_END);
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Reads an enumeration bitmask definition from line. The format is:
 * { NAME=VAL, NAME2=VAL2 }. The resulting names and values are returned.
 * RETURNS: NULL on error, else ptr to name/values.
 */
static str_val_nd_t *
read_enum_nvs(char *line, char *module_name)
{

	str_val_nd_t *enum_vals = NULL;
	char *cp;
	char *start;
	char *name = NULL;
	int len;
	uint32_t val;
	int ret;
	int readc;

	IPQOSCDBG1(L1, "In read_enum_nvs, line: %s\n", line);

	/* read opening brace */

	cp = strchr(line, CURL_BEGIN);
	if (cp == NULL) {
		IPQOSCDBG0(L1, "missing curl begin\n");
		goto fail;
	} else {
		start = cp + 1;
	}

	/*
	 * loop reading 'name = value' entrys seperated by comma until
	 * reach closing brace.
	 */

	for (;;) {
		SKIPWS(start);
		if (*start == '\0') {
			IPQOSCDBG0(L1, "missing closing bracket\n");
			goto fail;
		}

		/*
		 * read name - read until whitespace, '=', closing curl,
		 * or string end.
		 */

		for (cp = start;
		    !isspace(*cp) && *cp != '=' && *cp != CURL_END &&
		    *cp != '\0'; cp++) {}

		if (*cp == '\0') {
			IPQOSCDBG0(L1, "Unexpected line end in enum def'n\n");
			goto fail;

		/* finished definition, exit loop */
		} else if (*cp == CURL_END) {
			break;
		}

		/* store name */

		len = cp - start;
		name = malloc(len + 1);
		if (name == NULL) {
			ipqos_msg(MT_ENOSTR, "malloc");
			goto fail;
		}
		bcopy(start, name, len);
		name[len] = NULL;
		IPQOSCDBG1(L0, "Stored name: %s\n", name);

		/* read assignment */

		start = strchr(cp, '=');
		if (start == NULL) {
			IPQOSCDBG0(L1, "Missing = in enum def'n\n");
			goto fail;
		}

		/* read value */

		ret = sscanf(++start, "%x%n", &val, &readc);
		if (ret != 1) {
			IPQOSCDBG1(L1, "sscanf of value failed, string: %s\n",
			    cp);
			goto fail;
		}

		/* add name value to set */

		ret = add_str_val_entry(&enum_vals, name, val);
		if (ret != IPQOS_CONF_SUCCESS) {
			IPQOSCDBG0(L1, "Failed to add str_val entry\n");
			goto fail;
		}
		free(name);
		name = NULL;

		/* try reading comma */
		cp = strchr(start, ',');

		if (cp != NULL) {
			start = cp + 1;

		/* no comma, advance to char past value last read */
		} else {
			start += readc;
		}
	}

	return (enum_vals);
fail:
	free_str_val_entrys(enum_vals);
	if (name != NULL)
		free(name);

	/* if a parse error */

	if (errno == 0) {
		ipqos_msg(MT_ERROR, gettext("Types file for module %s is "
		    "corrupt.\n"), module_name);
	}

	return (NULL);
}

/*
 * Given mapped_list with is a comma seperated list of map names, and value,
 * which is used to index into these maps, the function creates x new entries
 * in nvpp, where x is the number of map names specified. Each of these
 * entries has the value from the map in the position indexed by value and
 * with name module.${MAP_NAME}. The maps are contained in the modules config
 * file and have the form:
 * map map1 uint32 1,23,32,45,3
 * As you can see the map values are uint32, and along with uint8 are the
 * only supported types at the moment.
 *
 * RETURNS: IPQOS_CONF_ERR if one of the maps specified in mapped_list
 * doesn't exist, if value is not a valid map position for a map, or if
 * there's a resource failure. otherwise IPQOS_CONF_SUCCESS is returned.
 */
static int
read_mapped_values(
FILE *tfp,
nvlist_t **nvlp,
char *module,
char *mapped_list,
int value)
{
	char *map_name, *lastparam, *tmpname;
	int res;
	ipqos_nvtype_t type;
	char dfltst[IPQOS_VALST_MAXLEN+1] = "";
	str_val_nd_t *enum_nvs;
	place_t place;

	IPQOSCDBG0(L1, "In read_mapped_values\n");

	map_name = (char *)strtok_r(mapped_list, ",", &lastparam);
	while (map_name != NULL) {
		char *tokval, *lastval;
		int index = 0;

		/*
		 * get map info from types file.
		 */
		place = PL_MAP;
		res = readtype(tfp, module, map_name, &type, &enum_nvs,
		    dfltst, B_FALSE, &place);
		if (res != IPQOS_CONF_SUCCESS) {
			return (IPQOS_CONF_ERR);
		}

		/*
		 * Just keep browsing the list till we get to the element
		 * with the index from the value parameter or the end.
		 */
		tokval = (char *)strtok_r(dfltst, ",", &lastval);
		for (;;) {
			if (tokval == NULL) {
				ipqos_msg(MT_ERROR,
				    gettext("Invalid value, %u, line %u.\n"),
				    value, lineno);
				return (IPQOS_CONF_ERR);
			}
			if (index++ == value) {
				break;
			}
			tokval = (char *)strtok_r(NULL, ",", &lastval);
		}


		/*
		 * create fully qualified parameter name for map value.
		 */
		tmpname = prepend_module_name(map_name, module);
		if (tmpname == NULL) {
			return (IPQOS_CONF_ERR);
		}

		/*
		 * add map value with fqn to parameter nvlist.
		 */
		IPQOSCDBG2(L0, "Adding map %s, value %u to nvlist\n",
		    tmpname, atoi(tokval));
		switch (type) {
			case IPQOS_DATA_TYPE_UINT8: {
				res = nvlist_add_byte(*nvlp, tmpname,
				    (uint8_t)atoi(tokval));
				if (res != 0)  {
					free(tmpname);
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint8");
					return (IPQOS_CONF_ERR);
				}
				break;
			}
			case IPQOS_DATA_TYPE_UINT32: {
				res = nvlist_add_uint32(*nvlp, tmpname,
				    (uint32_t)atoi(tokval));
				if (res != 0)  {
					free(tmpname);
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint32");
					return (IPQOS_CONF_ERR);
				}
				break;
			}
			default: {
				ipqos_msg(MT_ERROR,
				    gettext("Types file for module %s is "
				    "corrupt.\n"), module);
				IPQOSCDBG1(L0, "Unsupported map type for "
				    "parameter %s given in types file.\n",
				    map_name);
				return (IPQOS_CONF_ERR);
			}
		}
		free(tmpname);

		map_name = (char *)strtok_r(NULL, ",", &lastparam);
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Parses the string info_str into it's components. Its format is:
 * SIZE','[ENUM_DEF | RANGE], where SIZE is the size of the array,
 * ENUM_DEF is the definition of the enumeration for this array,
 * and RANGE is the set of values this array can accept. In
 * the event this array has an enumeration definition enum_nvs is
 * set to point at a str_val_nd_t structure which stores the names
 * and values associated with this enumeration. Otherwise, if this
 * is not an enumerated array, lower and upper are set to the lower
 * and upper values of RANGE.
 * RETURNS: IPQOS_CONF_ERR due to unexpected parse errors, else
 * IPQOS_CONF_SUCCESS.
 */
static int
read_int_array_info(
char *info_str,
str_val_nd_t **enum_nvs,
uint32_t *size,
int *lower,
int *upper,
char *module)
{
	int res;
	char *end;
	char *token;
	char *tmp;

	IPQOSCDBG1(L0, "In read_array_info: info_str: %s\n",
	    (info_str != NULL) ? info_str : "NULL");

	if (info_str == NULL) {
		IPQOSCDBG0(L0, "Null info string\n");
		goto fail;
	}

	/*
	 * read size.
	 */
	token = strtok(info_str, ",");
	*size = (uint32_t)strtol(token, &end, 10);
	SKIPWS(end);
	if ((end == token) || (*end != NULL)) {
		IPQOSCDBG0(L0, "Invalid size\n");
		goto fail;
	}
	IPQOSCDBG1(L0, "read size: %u\n", *size);

	/*
	 * check we have another string.
	 */
	token = strtok(NULL, "\n");
	if (token == NULL) {
		IPQOSCDBG0(L0, "Missing range/enum def\n");
		goto fail;
	}
	IPQOSCDBG1(L0, "range/enum def: %s\n", token);

	/*
	 * check if enumeration set or integer set and read enumeration
	 * definition or integer range respectively.
	 */
	tmp = strchr(token, CURL_BEGIN);
	if (tmp == NULL) {	/* a numeric range */
		res = readrange(token, lower, upper);
		if (res != IPQOS_CONF_SUCCESS) {
			IPQOSCDBG0(L0, "Failed reading range\n");
			goto fail;
		}
	} else {		/* an enumeration */
		*enum_nvs = read_enum_nvs(token, module);
		if (*enum_nvs == NULL) {
			IPQOSCDBG0(L0, "Failed reading enum def\n");
			goto fail;
		}
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	ipqos_msg(MT_ERROR,
	    gettext("Types file for module %s is corrupt.\n"), module);
	return (IPQOS_CONF_ERR);
}

/*
 * reads the value of an enumeration parameter from first_token and fp.
 * first_token is the first token of the value.
 * The format expected is NAME | { NAME1 [, NAME2 ] [, NAME3 ]  }.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
read_enum_value(
FILE *fp,
char *first_token,
str_val_nd_t *enum_vals,
uint32_t *val)
{

	uint32_t u32;
	int ret;
	char *tk;
	char *lo = NULL;
	char *cm;
	int name_expected = 0;

	IPQOSCDBG0(L1, "In read_enum_value\n");

	/* init param val */
	*val = 0;

	/* first token not curl_begin, so lookup its value */

	if (*first_token != CURL_BEGIN) {
		ret = str_val_list_lookup(enum_vals, first_token, val);
		if (ret != IPQOS_CONF_SUCCESS) {
			ipqos_msg(MT_ERROR,
			    gettext("Unrecognized value, %s, line %u.\n"),
			    first_token, lineno);
			return (ret);
		}

	/* curl_begin, so read values till curl_end, dicing at ',' */
	} else {

		name_expected++;

		for (;;) {

			/*
			 * no leftover from pervious iteration so read new
			 * token. This leftover happens because readtoken
			 * doesn't interpret comma's as special characters
			 * and thus could return 'val1,val2' as one token.
			 * If this happens the val1 will be used in the
			 * current iteration and what follows saved in lo
			 * for processing by successive iterations.
			 */

			if (lo == NULL) {
				ret = readtoken(fp, &tk);
				if (ret == IPQOS_CONF_ERR) {
					return (ret);
				} else if (ret == IPQOS_CONF_EOF) {
					ipqos_msg(MT_ERROR,
					    gettext("Unexpected EOF.\n"));
					return (IPQOS_CONF_ERR);

				}
			} else {	/* previous leftover, so use it */

				IPQOSCDBG1(L1, "Using leftover %s.\n", lo);
				tk = lo;
				lo = NULL;
			}

			if (name_expected) {
				if (ret == IPQOS_CONF_CURL_END ||
				    tk[0] == ',') {
					ipqos_msg(MT_ERROR,
					    gettext("Malformed value list "
					    "line %u.\n"), lineno);
					free(tk);
					return (IPQOS_CONF_ERR);
				}

				/*
				 * check if this token contains a ',' and
				 * if so store it and what follows for next
				 * iteration.
				 */
				cm = strchr(tk, ',');
				if (cm != NULL) {
					lo = malloc(strlen(cm) + 1);
					if (lo == NULL) {
						ipqos_msg(MT_ENOSTR, "malloc");
						free(tk);
						return (IPQOS_CONF_ERR);
					}

					(void) strcpy(lo, cm);
					*cm = '\0';
				}


				/* get name value and add to total val */

				ret = str_val_list_lookup(enum_vals, tk, &u32);
				if (ret != IPQOS_CONF_SUCCESS) {
					ipqos_msg(MT_ERROR,
					    gettext("Unrecognized value, %s, "
					    "line %u.\n"), tk, lineno);
					free(tk);
					return (IPQOS_CONF_ERR);
				}

				*val = *val | u32;
				name_expected--;

			/* comma or curl end accepted */
			} else {

				/* we've reached curl_end so break */

				if (ret == IPQOS_CONF_CURL_END) {
					free(tk);
					break;

				/* not curl end and not comma */

				} else if (tk[0] != ',') {
					ipqos_msg(MT_ERROR,
					    gettext("Malformed value list "
					    "line %u.\n"), lineno);
					free(tk);
					return (IPQOS_CONF_ERR);
				}

				/*
				 * store anything after the comma for next
				 * iteration.
				 */
				if (tk[1] != '\0') {
					lo = malloc(strlen(&tk[1]) + 1);
					if (lo == NULL) {
						ipqos_msg(MT_ENOSTR, "malloc");
						free(tk);
						return (IPQOS_CONF_ERR);
					}
					(void) strcpy(lo, &tk[1]);
				}

				name_expected++;
			}

			free(tk);
		}
	}

	IPQOSCDBG1(L1, "value returned is: %u\n", *val);

	return (IPQOS_CONF_SUCCESS);
}

/*
 * read the set of permanent classes/filter from the types file ref'd by tfp
 * and store them in a string table pointed to by perm_items,
 * with *nitems getting set to number of items read. perm_filters is set
 * to 1 if we're searching for permanent filters, else 0 for classes.
 * RETURNS: IPQOS_CONF_ERR if any errors, else IPQOS_CONF_SUCCESS.
 */
static int
read_perm_items(
int perm_filters,
FILE *tfp,
char *module_name,
char ***perm_items,
int *nitems)
{

	char lbuf[IPQOS_CONF_TYPE_LINE_LEN];
	int cnt = 0;
	char name[IPQOS_CONF_NAME_LEN+1];
	char foo[IPQOS_CONF_NAME_LEN+1];
	int res;
	char **items = NULL;
	char **tmp;
	char *marker;

	IPQOSCDBG0(L1, "In read_perm_items\n");


	/* seek to start of types file */

	if (fseek(tfp, 0, SEEK_SET) != 0) {
		ipqos_msg(MT_ENOSTR, "fseek");
		return (IPQOS_CONF_ERR);
	}

	/* select which marker were looking for */

	if (perm_filters) {
		marker = IPQOS_CONF_PERM_FILTER_MK;
	} else {
		marker = IPQOS_CONF_PERM_CLASS_MK;
	}

	/* scan file line by line till end */

	while (fgets(lbuf, IPQOS_CONF_TYPE_LINE_LEN, tfp) != NULL) {

		/*
		 * if the line is marked as containing a default item name
		 * read the name, extend the items string array
		 * and store the string off the array.
		 */
		if (strncmp(lbuf, marker, strlen(marker)) == 0) {

			res = sscanf(lbuf,
			    "%" VAL2STR(IPQOS_CONF_NAME_LEN) "s"
			    "%" VAL2STR(IPQOS_CONF_NAME_LEN) "s",
			    foo, name);
			if (res < 2) {
				ipqos_msg(MT_ERROR,
				    gettext("Types file for module %s is "
				    "corrupt.\n"), module_name);
				IPQOSCDBG1(L0, "Missing name with a %s.\n",
				    marker);
				goto fail;
			}

			/* extend items array to accomodate new item */

			tmp = realloc(items, (cnt + 1) * sizeof (char *));
			if (tmp == NULL) {
				ipqos_msg(MT_ENOSTR, "realloc");
				goto fail;
			} else {
				items = tmp;
			}

			/* copy and store item name */

			items[cnt] = malloc(strlen(name) + 1);
			if (items[cnt] == NULL) {
				ipqos_msg(MT_ENOSTR, "malloc");
				goto fail;
			}

			(void) strcpy(items[cnt], name);
			cnt++;


			IPQOSCDBG1(L1, "stored %s in perm items array\n",
			    name);
		}
	}

	*perm_items = items;
	*nitems = cnt;

	return (IPQOS_CONF_SUCCESS);
fail:
	for (cnt--; cnt >= 0; cnt--)
		free(items[cnt]);
	free(items);
	return (IPQOS_CONF_ERR);
}

/*
 * Searches types file ref'd by tfp for the parameter named name
 * with the place corresponding with place parameter. The format
 * of the lines in the file are:
 * PLACE NAME TYPE [ ENUM_DEF ] [ DEFAULT_STR ]
 * The ENUM_DEF is an enumeration definition and is only present
 * for parameters of type enum. DEFAULT_STR is a default value for
 * this parameter. If present type is set to the appropriate type
 * enumeration and dfltst filled with DEFAULT_STR if one was set.
 * Also if the type is enum enum_nvps is made to point at a
 * set of name value pairs representing ENUM_DEF.
 *
 * RETURNS: If any resource errors occur, or a matching parameter
 * isn't found IPQOS_CONF_ERR is returned, else IPQOS_CONF_SUCCESS.
 */
static int
readtype(
FILE *tfp,
char *module_name,
char *name,
ipqos_nvtype_t *type,
str_val_nd_t **enum_nvps,
char *dfltst,
boolean_t allow_ipgpc_priv,
place_t *place)
{

	int ac;
	char lbuf[IPQOS_CONF_TYPE_LINE_LEN];
	char param[IPQOS_CONF_PNAME_LEN+1];
	char typest[IPQOS_CONF_TYPE_LEN+1];
	char place_st[IPQOS_CONF_TYPE_LEN+1];
	char *cp;
	int x;
	char *ipgpc_nm;
	int found = 0;

	IPQOSCDBG1(L1, "In readtype: param: %s\n", name);


	/*
	 * if allow_ipgpc_priv is true then we allow ipgpc parameters that are
	 * private between ipqosconf and ipgpc. eg. address masks, port masks.
	 */
	if (allow_ipgpc_priv && strcmp(module_name, IPGPC_NAME) == 0) {
		ipgpc_nm = prepend_module_name(name, IPGPC_NAME);
		if (ipgpc_nm == NULL) {
			return (IPQOS_CONF_ERR);
		}

		if (strcmp(ipgpc_nm, IPGPC_SADDR_MASK) == 0 ||
		    strcmp(ipgpc_nm, IPGPC_DADDR_MASK) == 0) {
			*type = IPQOS_DATA_TYPE_ADDRESS_MASK;
			return (IPQOS_CONF_SUCCESS);
		} else if (strcmp(ipgpc_nm, IPGPC_SPORT_MASK) == 0 ||
		    strcmp(ipgpc_nm, IPGPC_DPORT_MASK) == 0) {
			*type = IPQOS_DATA_TYPE_UINT16;
			return (IPQOS_CONF_SUCCESS);
		} else if (strcmp(ipgpc_nm, IPGPC_FILTER_TYPE) == 0) {
			*type = IPQOS_DATA_TYPE_UINT32;
			return (IPQOS_CONF_SUCCESS);
		} else if (strcmp(ipgpc_nm, IPGPC_IF_INDEX) == 0) {
			*type = IPQOS_DATA_TYPE_IFINDEX;
			return (IPQOS_CONF_SUCCESS);
		}

		free(ipgpc_nm);
	}

	/*
	 * read upto and including module version line.
	 */
	if (read_tfile_ver(tfp, IPQOS_MOD_STR, module_name) == -1)
		return (IPQOS_CONF_ERR);


	/*
	 * loop reading lines of the types file until named parameter
	 * found or EOF.
	 */
	while (fgets(lbuf, IPQOS_CONF_TYPE_LINE_LEN, tfp) != NULL) {

		/*
		 * check whether blank or commented line; if so skip
		 */
		for (cp = lbuf; isspace(*cp) && *cp != '\0'; cp++) {}
		if (*cp == '\0' || *cp == '#') {
			continue;
		}

		dfltst[0] = '\0';

		/*
		 * read place, param, type and if present default str
		 * from line.
		 */
		ac = sscanf(lbuf,
		    "%" VAL2STR(IPQOS_CONF_TYPE_LEN) "s "
		    "%" VAL2STR(IPQOS_CONF_PNAME_LEN) "s "
		    "%" VAL2STR(IPQOS_CONF_TYPE_LEN) "s "
		    "%" VAL2STR(IPQOS_VALST_MAXLEN) "s",
		    place_st, param, typest, dfltst);
		if (ac < 3) {
			ipqos_msg(MT_ERROR,
			    gettext("Types file for module %s is corrupt.\n"),
			    module_name);
			IPQOSCDBG0(L0, "sscanf failed to read 3 strings.\n");
			return (IPQOS_CONF_ERR);
		}

		/*
		 * if the place and name match no need to look any further.
		 */
		if ((*place == PL_ANY) ||
		    ((*place == PL_PARAMS) &&
		    strcmp(place_st, IPQOS_PLACE_PRM_STR) == 0) ||
		    ((*place == PL_FILTER) &&
		    strcmp(place_st, IPQOS_PLACE_FILTER_STR) == 0) ||
		    ((*place == PL_MAP) &&
		    strcmp(place_st, IPQOS_PLACE_MAP_STR) == 0)) {
			if (strcmp(param, name) == 0) {
				found++;
				break;
			}
		}
	}
	if (found == 0) {
		ipqos_msg(MT_ERROR,
		    gettext("Invalid parameter, %s, line %u.\n"), name,
		    lineno);
		return (IPQOS_CONF_ERR);
	}

	/*
	 * set the place parameter to the actual place when the PL_ANY flag
	 * was set.
	 */
	if (*place == PL_ANY) {
		if (strcmp(place_st, IPQOS_PLACE_PRM_STR) == 0) {
			*place = PL_PARAMS;
		} else if (strcmp(place_st, IPQOS_PLACE_FILTER_STR) == 0) {
			*place = PL_FILTER;
		} else if (strcmp(place_st, IPQOS_PLACE_MAP_STR) == 0) {
			*place = PL_MAP;
		}
	}

	/*
	 * get type enumeration
	 */
	for (x = 0; nv_types[x].string[0]; x++) {
		if (strcmp(nv_types[x].string, typest) == 0) {
			break;
		}
	}
	/*
	 * check that we have a type corresponding with the one the types
	 * file specifies.
	 */
	if (nv_types[x].string[0] == '\0') {
		ipqos_msg(MT_ERROR,
		    gettext("Types file for module %s is corrupt.\n"),
		    module_name);
		return (IPQOS_CONF_ERR);
	}
	*type = nv_types[x].value;

	/*
	 * if enumeration type get set of name/vals and any default value
	 */
	if (*type == IPQOS_DATA_TYPE_ENUM) {
		*enum_nvps = read_enum_nvs(lbuf, module_name);
		if (*enum_nvps == NULL) {
			return (IPQOS_CONF_ERR);
		}

		dfltst[0] = '\0';
		cp = strchr(lbuf, CURL_END);
		(void) sscanf(++cp,
		    "%" VAL2STR(IPQOS_VALST_MAXLEN) "s", dfltst);
	}


	IPQOSCDBG2(L1, "read type: %s default: %s\n", nv_types[x].string,
	    *dfltst ? dfltst : "None");
	return (IPQOS_CONF_SUCCESS);
}


/*
 * Reads a name and a value from file ref'd by cfp into list indirectly
 * ref'd by nvlp; If this list is NULL it will be created to accomodate
 * the name/value. The name must be either a special token for
 * for the place, or be present in the module types file ref'd by tfp.
 * *type is set to the enumeration of the type of the parameter and
 * nvp to point at the element with the nvlp ref'd list.
 * RETURNS: IPQOS_CONF_CURL_END if read CURL_END as name,
 * IPQOS_CONF_ERR on errors, else IPQOS_CONF_SUCCESS.
 */
static int
readnvpair(
FILE *cfp,
FILE *tfp,
nvlist_t **nvlp,
nvpair_t **nvp,
ipqos_nvtype_t *type,
place_t place,
char *module_name)
{

	char *name = NULL;
	char *valst = NULL;
	int res;
	char *tmp;
	str_val_nd_t *enum_nvs = NULL;
	char dfltst[IPQOS_VALST_MAXLEN+1];

	IPQOSCDBG0(L1, "in readnvpair\n");

	/*
	 * read nvpair name
	 */
	res = readtoken(cfp, &name);

	/*
	 * if reached eof, curl end or error encountered return to caller
	 */
	if (res == IPQOS_CONF_EOF) {
		ipqos_msg(MT_ERROR, gettext("Unexpected EOF.\n"));
		return (IPQOS_CONF_ERR);
	} else if (res == IPQOS_CONF_ERR) {
		return (res);
	} else if (res == IPQOS_CONF_CURL_END) {
		free(name);
		return (res);
	}

	/*
	 * read nvpair value
	 */
	res = readtoken(cfp, &valst);

	/*
	 * check we've read a valid value
	 */
	if (res != IPQOS_CONF_SUCCESS && res != IPQOS_CONF_CURL_BEGIN) {
		if (res == IPQOS_CONF_EOF) {
			ipqos_msg(MT_ERROR, gettext("Unexpected EOF.\n"));
		} else if (res == IPQOS_CONF_CURL_END) {
			ipqos_msg(MT_ERROR,
			    gettext("Missing parameter value line %u.\n"),
			    lineno);
			free(valst);
		}	/* we do nothing special for IPQOS_CONF_ERR */
		free(name);
		return (IPQOS_CONF_ERR);
	}

	/*
	 * check for generic parameters.
	 */

	if ((place == PL_CLASS) &&
	    strcmp(name, IPQOS_CONF_NEXT_ACTION_STR) == 0) {
		*type = IPQOS_DATA_TYPE_ACTION;

	} else if (place == PL_PARAMS &&
	    strcmp(name, IPQOS_CONF_GLOBAL_STATS_STR) == 0 ||
	    place == PL_CLASS &&
	    strcmp(name, IPQOS_CONF_STATS_ENABLE_STR) == 0) {
		*type = IPQOS_DATA_TYPE_BOOLEAN;

	} else if (tfp == NULL ||
	    ((place != PL_PARAMS) && strcmp(name, IPQOS_CONF_NAME_STR) == 0) ||
	    (place == PL_FILTER) && (strcmp(name, IPQOS_CONF_CLASS_STR) ==
	    0) ||
	    (place == PL_ACTION) && (strcmp(name, IPQOS_CONF_MODULE_STR) ==
	    0)) {
		*type = IPQOS_DATA_TYPE_STRING;

	} else {	/* if not generic parameter */
		/*
		 * get type from types file
		 */
		if (readtype(tfp, module_name, name, type, &enum_nvs, dfltst,
		    B_FALSE, &place) != IPQOS_CONF_SUCCESS) {
			free(name);
			free(valst);
			return (IPQOS_CONF_ERR);
		}

		/*
		 * get full module prefix parameter name
		 */
		tmp = name;
		if ((name = prepend_module_name(name, module_name)) == NULL) {
			name = tmp;
			goto fail;
		}
		free(tmp);
	}

	IPQOSCDBG3(L1, "NVP, name: %s, str_value: %s, type: %s\n", name,
	    valst, nv_types[*type].string);


	/*
	 * create nvlist if not present already
	 */
	if (*nvlp == NULL) {
		res = nvlist_alloc(nvlp, NV_UNIQUE_NAME, 0);
		if (res != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_alloc");
			free(name);
			free(valst);
			return (IPQOS_CONF_ERR);
		}
	}

	/*
	 * check we haven't already read this parameter
	 */
	if (find_nvpair(*nvlp, name)) {
		ipqos_msg(MT_ERROR, gettext("Duplicate parameter line %u.\n"),
		    lineno);
		goto fail;
	}

	/*
	 * convert value string to appropriate type and add to nvlist
	 */

	switch (*type) {
		case IPQOS_DATA_TYPE_IFNAME: {
			uint32_t ifidx;

			res = readifindex(valst, (int *)&ifidx);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_uint32(*nvlp, IPGPC_IF_INDEX,
				    ifidx);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint32");
					goto fail;
				}
				(void) nvlist_remove_all(*nvlp, name);
				/*
				 * change name to point at the name of the
				 * new ifindex nvlist entry as name is used
				 * later in the function.
				 */
				free(name);
				name = malloc(strlen(IPGPC_IF_INDEX) + 1);
				if (name == NULL) {
					ipqos_msg(MT_ENOSTR, "malloc");
					goto fail;
				}
				(void) strcpy(name, IPGPC_IF_INDEX);
			}
			break;
		}
		case IPQOS_DATA_TYPE_PROTO: {
			uint8_t proto;

			res = readproto(valst, &proto);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_byte(*nvlp, name, proto);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_PORT: {
			uint16_t port;

			res = readport(valst, &port);
			if (res == IPQOS_CONF_SUCCESS) {

				/* add port */

				res = nvlist_add_uint16(*nvlp, name, port);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint16");
					goto fail;
				}

				/* add appropriate all ones port mask */

				if (strcmp(name, IPGPC_DPORT) == 0) {
					res = nvlist_add_uint16(*nvlp,
					    IPGPC_DPORT_MASK, ~0);

				} else if (strcmp(name, IPGPC_SPORT) == 0) {
					res = nvlist_add_uint16(*nvlp,
					    IPGPC_SPORT_MASK, ~0);
				}
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint16");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_ADDRESS:
		case IPQOS_DATA_TYPE_ACTION:
		case IPQOS_DATA_TYPE_STRING:
			res = nvlist_add_string(*nvlp, name, valst);
			if (res != 0) {
				ipqos_msg(MT_ENOSTR, "nvlist_add_string");
				goto fail;
			}
			break;
		case IPQOS_DATA_TYPE_BOOLEAN: {
			boolean_t b;

			res = readbool(valst, &b);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_uint32(*nvlp, name,
				    (uint32_t)b);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint32");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_UINT8: {
			uint8_t u8;

			res = readuint8(valst, &u8, &tmp);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_byte(*nvlp, name, u8);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_INT16: {
			int16_t i16;

			res = readint16(valst, &i16, &tmp);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_int16(*nvlp, name, i16);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_int16");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_UINT16: {
			uint16_t u16;

			res = readuint16(valst, &u16, &tmp);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_uint16(*nvlp, name, u16);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_int16");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_INT32: {
			int i32;

			res = readint32(valst, &i32, &tmp);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_int32(*nvlp, name, i32);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_int32");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_UINT32: {
			uint32_t u32;

			res = readuint32(valst, &u32, &tmp);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_uint32(*nvlp, name, u32);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint32");
					goto fail;
				}
			}
			break;
		}
		case IPQOS_DATA_TYPE_ENUM: {
			uint32_t val;

			res = read_enum_value(cfp, valst, enum_nvs, &val);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_uint32(*nvlp, name, val);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint32");
					goto fail;
				}
			} else {
				goto fail;
			}
			break;
		}
		/*
		 * For now the dfltst contains a comma separated list of the
		 * type we need this parameter to be mapped to.
		 * read_mapped_values will fill in all the mapped parameters
		 * and their values in the nvlist.
		 */
		case IPQOS_DATA_TYPE_M_INDEX: {
			uint8_t u8;

			res = readuint8(valst, &u8, &tmp);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_byte(*nvlp, name, u8);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint8");
					goto fail;
				}
			} else {
				*type = IPQOS_DATA_TYPE_UINT8;
				break;
			}
			res = read_mapped_values(tfp, nvlp, module_name,
			    dfltst, u8);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}
			break;
		}
		case IPQOS_DATA_TYPE_INT_ARRAY: {
			str_val_nd_t *arr_enum_nvs = NULL;
			uint32_t size;
			int llimit = 0, ulimit = 0;
			int *arr;

			/*
			 * read array info from types file.
			 */
			res = read_int_array_info(dfltst, &arr_enum_nvs, &size,
			    &llimit, &ulimit, module_name);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			/*
			 * read array contents from config file and construct
			 * array with them.
			 */
			res = read_int_array(cfp, valst, &arr, size, llimit,
			    ulimit, arr_enum_nvs);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			/*
			 * add array to nvlist.
			 */
			res = nvlist_add_int32_array(*nvlp, name, arr, size);
			if (res != 0) {
				ipqos_msg(MT_ENOSTR, "nvlist_add_int32");
				goto fail;
			}

			/*
			 * free uneeded resources.
			 */
			free(arr);
			if (arr_enum_nvs)
				free_str_val_entrys(arr_enum_nvs);

			break;
		}
		case IPQOS_DATA_TYPE_USER: {
			uid_t uid;

			res = readuser(valst, &uid);
			if (res == IPQOS_CONF_SUCCESS) {
				res = nvlist_add_int32(*nvlp, name, (int)uid);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_int32");
					goto fail;
				}
			}
			break;
		}
#ifdef	_IPQOS_CONF_DEBUG
		default: {
			/*
			 * we shouldn't have a type that doesn't have a switch
			 * entry.
			 */
			assert(1);
		}
#endif
	}
	if (res != 0) {
		ipqos_msg(MT_ERROR, gettext("Invalid %s, line %u.\n"),
		    nv_types[*type].string, lineno);
		goto fail;
	}

	/* set the nvp parameter to point at the newly added nvlist entry */

	*nvp = find_nvpair(*nvlp, name);

	free(name);
	free(valst);
	if (enum_nvs)
		free_str_val_entrys(enum_nvs);
	return (IPQOS_CONF_SUCCESS);
fail:
	if (name != NULL)
		free(name);
	if (valst != NULL)
		free(valst);
	if (enum_nvs != NULL)
		free_str_val_entrys(enum_nvs);
	return (IPQOS_CONF_ERR);
}

/*
 * read a parameter clause from cfp into *params.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
readparams(
FILE *cfp,
FILE *tfp,
char *module_name,
ipqos_conf_params_t *params)
{

	int res;
	nvpair_t *nvp;
	ipqos_nvtype_t type;
	boolean_t bl;
	char *nm;
	char *action;
	char tmp[IPQOS_CONF_PNAME_LEN];
	int read_stats = 0;

	IPQOSCDBG0(L0, "in readparams\n");

	/* read beginning curl */

	res = read_curl_begin(cfp);
	if (res != IPQOS_CONF_SUCCESS) {
		return (res);
	}

	/*
	 * loop reading nvpairs, adding to params nvlist until encounter
	 * CURL_END.
	 */
	for (;;) {
		/* read nvpair */

		res = readnvpair(cfp, tfp, &params->nvlist,
		    &nvp, &type, PL_PARAMS, module_name);
		if (res == IPQOS_CONF_ERR) {
			goto fail;

		/* we have finished reading params */

		} else if (res == IPQOS_CONF_CURL_END) {
			break;
		}

		/*
		 * read global stats - place into params struct and remove
		 * from nvlist.
		 */
		if (strcmp(nvpair_name(nvp), IPQOS_CONF_GLOBAL_STATS_STR) ==
		    0) {
			/* check we haven't read stats before */

			if (read_stats) {
				ipqos_msg(MT_ERROR,
				    gettext("Duplicate parameter line %u.\n"),
				    lineno);
				goto fail;
			}
			read_stats++;

			(void) nvpair_value_uint32(nvp, (uint32_t *)&bl);
			params->stats_enable = bl;
			(void) nvlist_remove_all(params->nvlist,
			    IPQOS_CONF_GLOBAL_STATS_STR);


		/*
		 * read action type parameter - add it to list of action refs.
		 * also, if it's one of continue or drop virtual actions
		 * change the action name to their special ipp names in
		 * the action ref list and the nvlist.
		 */
		} else if (type == IPQOS_DATA_TYPE_ACTION) {

			/* get name and value from nvlist */

			nm = nvpair_name(nvp);
			(void) nvpair_value_string(nvp, &action);

			/* if virtual action names change to ipp name */

			if ((strcmp(action, IPQOS_CONF_CONT_STR) == 0) ||
			    strcmp(action, IPQOS_CONF_DROP_STR) == 0) {
				/*
				 * we copy nm to a seperate buffer as nv_pair
				 * name above gave us a ptr to internal
				 * memory which causes strange behaviour
				 * when we re-value that nvlist element.
				 */
				(void) strlcpy(tmp, nm, sizeof (tmp));
				nm = tmp;


				/* modify nvlist entry and change action */

				if (strcmp(action, IPQOS_CONF_CONT_STR) == 0) {
					action = IPP_ANAME_CONT;
					res = nvlist_add_string(params->nvlist,
					    nm, action);
				} else {
					action = IPP_ANAME_DROP;
					res = nvlist_add_string(params->nvlist,
					    nm, action);
				}
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_string");
					goto fail;
				}
			}

			/* add action reference to params */

			res = add_aref(&params->actions, nm, action);
		}
	}

	return (IPQOS_CONF_SUCCESS);
fail:

	if (params->nvlist) {
		nvlist_free(params->nvlist);
		params->nvlist = NULL;
	}
	if (params->actions) {
		free_arefs(params->actions);
		params->actions = NULL;
	}
	return (IPQOS_CONF_ERR);
}

/* ************************* class manip fns ****************************** */



/*
 * make dst point at a dupicate class struct with duplicate elements to src.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
dup_class(
ipqos_conf_class_t *src,
ipqos_conf_class_t **dst)
{

	ipqos_conf_class_t *cls;
	int res;

	IPQOSCDBG1(DIFF, "In dup_class: class: %s\n", src->name);
	cls = alloc_class();
	if (cls == NULL) {
		return (IPQOS_CONF_ERR);
	}

	/* struct copy */
	*cls = *src;

	/* we're not interested in the nvlist for a class */
	cls->nvlist = NULL;


	/* copy first action reference */
	cls->alist = NULL;
	res = add_aref(&cls->alist, src->alist->field, src->alist->name);
	if (res != IPQOS_CONF_SUCCESS) {
		free(cls);
		return (res);
	}

	*dst = cls;

	return (IPQOS_CONF_SUCCESS);
}

/*
 * create a zero'd class struct and return a ptr to it.
 * RETURNS: ptr to struct on success, NULL otherwise.
 */
static ipqos_conf_class_t *
alloc_class()
{

	ipqos_conf_class_t *class;

	class = malloc(sizeof (ipqos_conf_class_t));
	if (class) {
		bzero(class, sizeof (ipqos_conf_class_t));
	} else {
		ipqos_msg(MT_ENOSTR, "malloc");
	}

	return (class);
}

/* frees up all memory occupied by a filter struct and its contents. */
static void
free_class(ipqos_conf_class_t *cls)
{

	if (cls == NULL)
		return;

	/* free its nvlist if present */

	nvlist_free(cls->nvlist);

	/* free its action refs if present */

	if (cls->alist)
		free_arefs(cls->alist);

	/* finally free class itself */
	free(cls);
}

/*
 * Checks whether there is a class called class_nm  in classes list.
 * RETURNS: ptr to first matched class, else if not matched NULL.
 */
static ipqos_conf_class_t *
classexist(
char *class_nm,
ipqos_conf_class_t *classes)
{

	ipqos_conf_class_t *cls;

	IPQOSCDBG1(L1, "In classexist: name: %s\n", class_nm);

	for (cls = classes; cls; cls = cls->next) {
		if (strcmp(class_nm, cls->name) == 0) {
			break;
		}
	}

	return (cls);
}



/* ************************** filter manip fns **************************** */



/*
 * Checks whether there is a filter called filter_nm with instance number
 * instance in filters list created by us or permanent. Instance value -1
 * is a wildcard.
 * RETURNS: ptr to first matched filter, else if not matched NULL.
 */
static ipqos_conf_filter_t *
filterexist(
char *filter_nm,
int instance,
ipqos_conf_filter_t *filters)
{

	IPQOSCDBG2(L1, "In filterexist: name :%s, inst: %d\n", filter_nm,
	    instance);

	while (filters) {
		if (strcmp(filters->name, filter_nm) == 0 &&
		    (instance == -1 || filters->instance == instance) &&
		    (filters->originator == IPP_CONFIG_IPQOSCONF ||
		    filters->originator == IPP_CONFIG_PERMANENT)) {
			break;
		}
		filters = filters->next;
	}
	return (filters);
}

/*
 * allocate and zero a filter structure.
 * RETURNS: NULL on error, else ptr to filter struct.
 */
static ipqos_conf_filter_t *
alloc_filter()
{

	ipqos_conf_filter_t *flt;

	flt = malloc(sizeof (ipqos_conf_filter_t));
	if (flt) {
		bzero(flt, sizeof (ipqos_conf_filter_t));
		flt->instance = -1;
	} else {
		ipqos_msg(MT_ENOSTR, "malloc");
	}

	return (flt);
}

/* free flt and all it's contents. */

static void
free_filter(ipqos_conf_filter_t *flt)
{

	IPQOSCDBG2(L1, "In free_filter: filter: %s, inst: %d\n", flt->name,
	    flt->instance);

	if (flt == NULL)
		return;

	if (flt->src_nd_name)
		free(flt->src_nd_name);
	if (flt->dst_nd_name)
		free(flt->dst_nd_name);
	if (flt->nvlist) {
		nvlist_free(flt->nvlist);
	}
	free(flt);
}

/*
 * makes a copy of ofilter and its contents and points nfilter at it. It
 * also adds an instance number to the filter and if either saddr or
 * daddr are non-null that address to the filters nvlist along with
 * an all 1s address mask and the af.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
dup_filter(
ipqos_conf_filter_t *ofilter,
ipqos_conf_filter_t **nfilter,
int af,
int inv6,	/* if saddr or daddr set and v4 filter are they in v6 addr */
void *saddr,
void *daddr,
int inst)
{

	ipqos_conf_filter_t *nf;
	int res;
	in6_addr_t v6addr;
	in6_addr_t all_1s_v6;

	IPQOSCDBG4(MHME, "In dup_filter: name: %s, af: %u, inv6: %u, ins: %d\n",
	    ofilter->name, af, inv6, inst);

/* show src address and dst address if present */
#ifdef	_IPQOS_CONF_DEBUG
	if (ipqosconf_dbg_flgs & MHME) {
		char st[100];

		if (saddr) {
			(void) fprintf(stderr, "saddr: %s\n",
			    inet_ntop(inv6 ? AF_INET6 : AF_INET, saddr, st,
			    100));
		}

		if (daddr) {
			(void) fprintf(stderr, "daddr: %s\n",
			    inet_ntop(inv6 ? AF_INET6 : AF_INET, daddr, st,
			    100));
		}
	}
#endif	/* _IPQOS_CONF_DEBUG */

	/* init local v6 address to 0 */
	(void) bzero(&v6addr, sizeof (in6_addr_t));

	/* create an all 1s address for use as mask */
	(void) memset(&all_1s_v6, ~0, sizeof (in6_addr_t));

	/* create a new filter */

	nf = alloc_filter();
	if (nf == NULL) {
		return (IPQOS_CONF_ERR);
	}

	/* struct copy old filter to new */
	*nf = *ofilter;

	/* copy src filters nvlist if there is one to copy */

	if (ofilter->nvlist) {
		res = nvlist_dup(ofilter->nvlist, &nf->nvlist, 0);
		if (res != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_dup");
			goto fail;
		}
	}

	/* copy src and dst node names if present */

	if (ofilter->src_nd_name) {
		nf->src_nd_name = malloc(strlen(ofilter->src_nd_name) + 1);
		if (nf->src_nd_name == NULL) {
			ipqos_msg(MT_ENOSTR, "malloc");
			goto fail;
		}
		(void) strcpy(nf->src_nd_name, ofilter->src_nd_name);
	}
	if (ofilter->dst_nd_name) {
		nf->dst_nd_name = malloc(strlen(ofilter->dst_nd_name) + 1);
		if (nf->dst_nd_name == NULL) {
			ipqos_msg(MT_ENOSTR, "malloc");
			goto fail;
		}
		(void) strcpy(nf->dst_nd_name, ofilter->dst_nd_name);
	}

	/* add filter addresses type */

	res = nvlist_add_byte(nf->nvlist, IPGPC_FILTER_TYPE,
	    af == AF_INET ? IPGPC_V4_FLTR : IPGPC_V6_FLTR);
	if (res != 0) {
		ipqos_msg(MT_ENOSTR, "nvlist_add_byte");
		goto fail;
	}
	IPQOSCDBG1(MHME, "adding address type %s in dup filter\n",
	    af == AF_INET ? "AF_INET" : "AF_INET6");

	/* add saddr if present */

	if (saddr) {
		if (af == AF_INET && !inv6) {
			V4_PART_OF_V6(v6addr) = *(uint32_t *)saddr;
			saddr = &v6addr;
		}

		/* add address and all 1's mask */

		if (nvlist_add_uint32_array(nf->nvlist, IPGPC_SADDR,
		    (uint32_t *)saddr, 4) != 0 ||
		    nvlist_add_uint32_array(nf->nvlist, IPGPC_SADDR_MASK,
		    (uint32_t *)&all_1s_v6, 4) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_uint32_array");
			goto fail;
		}

	}

	/* add daddr if present */

	if (daddr) {
		if (af == AF_INET && !inv6) {
			V4_PART_OF_V6(v6addr) = *(uint32_t *)daddr;
			daddr = &v6addr;
		}

		/* add address and all 1's mask */

		if (nvlist_add_uint32_array(nf->nvlist, IPGPC_DADDR,
		    (uint32_t *)daddr, 4) != 0 ||
		    nvlist_add_uint32_array(nf->nvlist, IPGPC_DADDR_MASK,
		    (uint32_t *)&all_1s_v6, 4) != 0) {
			ipqos_msg(MT_ENOSTR, "nvlist_add_uint32_array");
			goto fail;
		}
	}

	/* add filter instance */

	nf->instance = inst;

	*nfilter = nf;
	return (IPQOS_CONF_SUCCESS);
fail:
	free_filter(nf);
	return (IPQOS_CONF_ERR);
}



/* ************************* action manip fns ********************** */



/*
 * create and zero action structure and a params structure hung off of it.
 * RETURNS: ptr to allocated action on success, else NULL.
 */
static ipqos_conf_action_t *
alloc_action()
{

	ipqos_conf_action_t *action;

	action = (ipqos_conf_action_t *)malloc(sizeof (ipqos_conf_action_t));
	if (action == NULL) {
		ipqos_msg(MT_ENOSTR, "malloc");
		return (action);
	}
	bzero(action, sizeof (ipqos_conf_action_t));

	action->params = (ipqos_conf_params_t *)
			malloc(sizeof (ipqos_conf_params_t));
	if (action->params == NULL) {
		free(action);
		return (NULL);
	}
	bzero(action->params, sizeof (ipqos_conf_params_t));
	action->params->stats_enable = B_FALSE;

	return (action);
}

/*
 * free all the memory used in all the actions in actions list.
 */
static void
free_actions(
ipqos_conf_action_t *actions)
{

	ipqos_conf_action_t *act = actions;
	ipqos_conf_action_t *next;
	ipqos_conf_filter_t *flt, *nf;
	ipqos_conf_class_t *cls, *nc;

	while (act != NULL) {
		/* free parameters */

		if (act->params != NULL) {
			free_arefs(act->params->actions);
			if (act->params->nvlist != NULL) {
				nvlist_free(act->params->nvlist);
			}
			free(act->params);
		}

		/* free action nvlist */

		if (act->nvlist != NULL)
			free(act->nvlist);

		/* free filters */

		flt = act->filters;
		while (flt != NULL) {
			nf = flt->next;
			free_filter(flt);
			flt = nf;
		}

		/* free classes */

		cls = act->classes;
		while (cls != NULL) {
			nc = cls->next;
			free_class(cls);
			cls = nc;
		}

		/* free permanent classes table */
		cleanup_string_table(act->perm_classes, act->num_perm_classes);

		/* free filters to retry */

		flt = act->retry_filters;
		while (flt != NULL) {
			nf = flt->next;
			free_filter(flt);
			flt = nf;
		}

		/* free dependency pointers */
		free_arefs(act->dependencies);

		next = act->next;
		free(act);
		act = next;
	}
}

/*
 * Checks whether there is an action called action_name in actions list.
 * RETURNS: ptr to first matched action, else if not matched NULL.
 *
 */
static ipqos_conf_action_t *
actionexist(
char *action_name,
ipqos_conf_action_t *actions)
{

	IPQOSCDBG1(L1, "In actionexist: name: %s\n", action_name);

	while (actions) {
		if (strcmp(action_name, actions->name) == 0) {
			break;
		}
		actions = actions->next;
	}

	return (actions);
}

/* **************************** act ref manip fns ******************** */


/*
 * add an action reference element with parameter field and action
 * action_name to arefs.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
add_aref(
ipqos_conf_act_ref_t **arefs,
char *field,
char *action_name)
{

	ipqos_conf_act_ref_t *aref;

	IPQOSCDBG1(L1, "add_aref: action: %s.\n", action_name);

	/* allocate zero'd aref */

	aref = malloc(sizeof (ipqos_conf_act_ref_t));
	if (aref == NULL) {
		ipqos_msg(MT_ENOSTR, "malloc");
		return (IPQOS_CONF_ERR);
	}
	(void) bzero(aref, sizeof (ipqos_conf_act_ref_t));

	/* copy parameter name if present */

	if (field)
		(void) strlcpy(aref->field, field, IPQOS_CONF_PNAME_LEN);

	/* copy action name */
	(void) strlcpy(aref->name, action_name, IPQOS_CONF_NAME_LEN);

	/* place at head of list */

	aref->next = *arefs;
	*arefs = aref;

	return (IPQOS_CONF_SUCCESS);
}

/*
 * free all the memory used by the action references in arefs.
 */
static void
free_arefs(
ipqos_conf_act_ref_t *arefs)
{

	ipqos_conf_act_ref_t *aref = arefs;
	ipqos_conf_act_ref_t *next;

	while (aref) {
		nvlist_free(aref->nvlist);
		next = aref->next;
		free(aref);
		aref = next;
	}
}



/* *************************************************************** */



/*
 * checks whether aname is a valid action name.
 * RETURNS: IPQOS_CONF_ERR if invalid, else IPQOS_CONF_SUCCESS.
 */
static int
valid_aname(char *aname)
{

	/*
	 * dissallow the use of the name of a virtual action, either
	 * the ipqosconf name, or the longer ipp names.
	 */
	if (strcmp(aname, IPQOS_CONF_CONT_STR) == 0 ||
	    strcmp(aname, IPQOS_CONF_DEFER_STR) == 0 ||
	    strcmp(aname, IPQOS_CONF_DROP_STR) == 0 ||
	    virtual_action(aname)) {
		ipqos_msg(MT_ERROR, gettext("Invalid action name line %u.\n"),
		    lineno);
		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Opens a stream to the types file for module module_name (assuming
 * that the file path is TYPES_FILE_DIR/module_name.types). if
 * a file open failure occurs, *openerr is set to 1.
 * RETURNS: NULL on error, else stream ptr to module types file.
 */
static FILE *
validmod(
char *module_name,
int *openerr)
{

	FILE *fp;
	char *path;

	IPQOSCDBG1(L1, "In validmod: module_name: %s\n", module_name);

	*openerr = 0;

	/* create modules type file path */

	path = malloc(strlen(TYPES_FILE_DIR) + strlen(module_name) +
	    strlen(".types") + 1);
	if (path == NULL) {
		ipqos_msg(MT_ENOSTR, "malloc");
		return (NULL);
	}
	(void) strcpy(path, TYPES_FILE_DIR);
	(void) strcat(path, module_name);
	(void) strcat(path, ".types");


	IPQOSCDBG1(L1, "opening file %s\n", path);

	/* open stream to types file */

	fp = fopen(path, "r");
	if (fp == NULL) {
		(*openerr)++;
	}

	free(path);
	return (fp);
}


/*
 * read a class clause from cfp into a class struct and point class at this.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
readclass(
FILE *cfp,
char *module_name,
ipqos_conf_class_t **class,
char **perm_classes,
int num_perm_classes)
{

	int nm, act;
	int res;
	nvpair_t *nvp;
	ipqos_nvtype_t type;
	char *name;
	char *action;
	int stats;

	IPQOSCDBG0(L0, "in readclass\n");

	/* create and zero class struct */

	*class = alloc_class();
	if (!*class) {
		return (IPQOS_CONF_ERR);
	}
	(*class)->originator = IPP_CONFIG_IPQOSCONF;

	/* get starting line for error reporting */
	(*class)->lineno = lineno;

	/* read curl_begin */

	res = read_curl_begin(cfp);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* loop reading parameters till read curl_end */

	stats = nm = act = 0;
	for (;;) {
		/* read nvpair */
		res = readnvpair(cfp, NULL, &(*class)->nvlist,
		    &nvp, &type, PL_CLASS, module_name);
		if (res == IPQOS_CONF_ERR) {
			goto fail;

		/* reached end of class clause */
		} else if (res == IPQOS_CONF_CURL_END) {
			break;
		}

		/*
		 * catch name and action nv pairs and stats if present
		 * and place values in class structure.
		 */

		/* name */

		if (nm == 0 &&
		    strcmp(nvpair_name(nvp), IPQOS_CONF_NAME_STR) == 0) {

			(void) nvpair_value_string(nvp, &name);

			if (valid_name(name) != IPQOS_CONF_SUCCESS) {
				goto fail;
			}
			(void) strcpy((*class)->name, name);
			nm++;

		/* next action */

		} else if (act == 0 &&
		    strcmp(nvpair_name(nvp), IPQOS_CONF_NEXT_ACTION_STR) == 0) {

			(void) nvpair_value_string(nvp, &action);

			/*
			 * if next action string continue string set action to
			 * IPP_ANAME_CONT, else if drop string IPP_ANAME_DROP
			 */
			if (strcmp(action, IPQOS_CONF_CONT_STR) == 0) {
				action = IPP_ANAME_CONT;
			} else if (strcmp(action, IPQOS_CONF_DROP_STR) == 0) {
				action = IPP_ANAME_DROP;
			}

			/* add an action reference to action list */

			res = add_aref(&(*class)->alist,
			    IPQOS_CONF_NEXT_ACTION_STR, action);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}
			act++;

		/* class stats enable */

		} else if (stats == 0 &&
		    strcmp(nvpair_name(nvp), IPQOS_CONF_STATS_ENABLE_STR) ==
		    0) {
			boolean_t bl;

			(void) nvpair_value_uint32(nvp, (uint32_t *)&bl);
			(*class)->stats_enable = bl;

			stats++;

		/* no other / duplicate parameters allowed */

		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Unexpected parameter line %u.\n"), lineno);
			goto fail;
		}
	}
	if (nm == 0 || act == 0) {
		ipqos_msg(MT_ERROR,
		    gettext("Missing class name/next action before line %u.\n"),
		    lineno);
		goto fail;
	}

	/* change class originator field to permanent if permanent class */

	if (in_string_table(perm_classes, num_perm_classes, (*class)->name)) {
	    IPQOSCDBG1(L0, "Setting class %s as permanent.\n", (*class)->name);
		(*class)->originator = IPP_CONFIG_PERMANENT;
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	if (*class)
		free_class(*class);
	return (IPQOS_CONF_ERR);
}

/*
 * This function assumes either src_nd_name or dst_node_nm are set in filter.
 *
 * Creates one of more copies of filter according to the ip versions
 * requested (or assumed) and the resolution of the src and dst address
 * node names if spec'd. If both node names are spec'd then a filter is
 * created for each pair of addresses (one from each node name) that is
 * compatible with the chosen address family, otherwise a filter copy is
 * created for just each address of the single node name that is
 * compatible.
 * If filter->ip_versions has been set that is used to determine the
 * af's we will create filters for, else if a numeric address was
 * added the family of that will be used, otherwise we fall back
 * to both v4 and v6 addresses.
 *
 * Any name lookup failures that occur are checked to see whether the failure
 * was a soft or hard failure and the nlerr field of filter set accordingly
 * before the error is returned.
 *
 * RETURNS: IPQOS_CONF_ERR on any error, else IPQOS_CONF_SUCCESS.
 */

static int
domultihome(
ipqos_conf_filter_t *filter,
ipqos_conf_filter_t **flist,
boolean_t last_retry)
{

	uint32_t ftype;
	int v4 = 1, v6 = 1;	/* default lookup family is v4 and v6 */
	int saf, daf;
	struct hostent *shp = NULL;
	struct hostent *dhp = NULL;
	in6_addr_t daddr, saddr;
	int idx = 0;
	ipqos_conf_filter_t *nfilter;
	int res;
	int ernum;
	int in32b = 0;
	char **sp, **dp;

	IPQOSCDBG3(MHME, "In domultihome: filter: %s, src_node: %s, "
	    "dst_node: %s\n", filter->name,
	    (filter->src_nd_name ? filter->src_nd_name : "NULL"),
	    (filter->dst_nd_name ? filter->dst_nd_name : "NULL"));

	/* check if we've read an ip_version request to get the versions */

	if (filter->ip_versions != 0) {
		v4 = VERSION_IS_V4(filter);
		v6 = VERSION_IS_V6(filter);

	/* otherwise check if we've read a numeric address and get versions */

	} else if (nvlist_lookup_uint32(filter->nvlist, IPGPC_FILTER_TYPE,
	    &ftype) == 0) {
		if (ftype == IPGPC_V4_FLTR) {
			v6--;
		} else {
			v4--;
		}
	}

	/* read saddrs if src node name */

	if (filter->src_nd_name) {

		/* v4 only address */

		if (v4 && !v6) {
			in32b++;
			shp = getipnodebyname(filter->src_nd_name, AF_INET,
			    AI_ADDRCONFIG, &ernum);

		/* v6 only  */

		} else if (v6 && !v4) {
			shp = getipnodebyname(filter->src_nd_name, AF_INET6,
			    AI_DEFAULT, &ernum);

		/* v4 and v6 */

		} else if (v6 && v4) {
			shp = getipnodebyname(filter->src_nd_name, AF_INET6,
			    AI_DEFAULT|AI_ALL, &ernum);
		}

#ifdef	TESTING_RETRY
if (!last_retry) {
	filter->nlerr = IPQOS_LOOKUP_RETRY;
	goto fail;
}
#endif

		/*
		 * if lookup error determine whether it was a soft or hard
		 * failure and mark as such in filter.
		 */
		if (shp == NULL) {
			if (ernum != TRY_AGAIN) {
				ipqos_msg(MT_ERROR, gettext("Failed to "
				    "resolve src host name for filter at "
				    "line %u, ignoring filter.\n"),
				    filter->lineno);
				filter->nlerr = IPQOS_LOOKUP_FAIL;
			} else {
				if (last_retry) {
					ipqos_msg(MT_ERROR, gettext("Failed "
					    "to resolve src host name for "
					    "filter at line %u, ignoring "
					    "filter.\n"), filter->lineno);
				}
				filter->nlerr = IPQOS_LOOKUP_RETRY;
			}
			goto fail;
		}
	}

	/* read daddrs if dst node name */
	if (filter->dst_nd_name) {

		/* v4 only address */

		if (v4 && !v6) {
			in32b++;
			dhp = getipnodebyname(filter->dst_nd_name, AF_INET,
			    AI_ADDRCONFIG, &ernum);

		/* v6 only */

		} else if (v6 && !v4) {
			dhp = getipnodebyname(filter->dst_nd_name, AF_INET6,
			    AI_DEFAULT, &ernum);

		/*  v6 and v4 addresses */

		} else {
			dhp = getipnodebyname(filter->dst_nd_name, AF_INET6,
			    AI_DEFAULT|AI_ALL, &ernum);
		}

		if (dhp == NULL) {
			if (ernum != TRY_AGAIN) {
				ipqos_msg(MT_ERROR, gettext("Failed to "
				    "resolve dst host name for filter at "
				    "line %u, ignoring filter.\n"),
				    filter->lineno);
				filter->nlerr = IPQOS_LOOKUP_FAIL;
			} else {
				if (last_retry) {
					ipqos_msg(MT_ERROR, gettext("Failed "
					    "to resolve dst host name for "
					    "filter at line %u, ignoring "
					    "filter.\n"), filter->lineno);
				}
				filter->nlerr = IPQOS_LOOKUP_RETRY;
			}
			goto fail;
		}
	}

	/*
	 * if src and dst node name, create set of filters; one for each
	 * src and dst address of matching types.
	 */
	if (filter->src_nd_name && filter->dst_nd_name) {

		for (sp = shp->h_addr_list; *sp != NULL; sp++) {
			(void) bcopy(*sp, &saddr, shp->h_length);

			/* get saddr family */

			if (in32b || IN6_IS_ADDR_V4MAPPED(&saddr)) {
				saf = AF_INET;
			} else {
				saf = AF_INET6;
			}

			for (dp = dhp->h_addr_list; *dp != NULL; dp++) {
				(void) bcopy(*dp, &daddr, dhp->h_length);

				/* get daddr family */

				if (in32b || IN6_IS_ADDR_V4MAPPED(&daddr)) {
					daf = AF_INET;
				} else {
					daf = AF_INET6;
				}

				/*
				 * if saddr and daddr same af duplicate
				 * filter adding addresses and new instance
				 * number and add to flist filter list.
				 */

				if (daf == saf) {

					res = dup_filter(filter, &nfilter, saf,
					    !in32b, &saddr, &daddr, ++idx);
					if (res != IPQOS_CONF_SUCCESS) {
						goto fail;
					}
					ADD_TO_LIST(flist, nfilter);
				}
			}
		}

	/* if src name only create set of filters, one for each node address */

	} else if (filter->src_nd_name) {

		for (sp = shp->h_addr_list; *sp != NULL; sp++) {
			(void) bcopy(*sp, &saddr, shp->h_length);

			/* get af */

			if (in32b || IN6_IS_ADDR_V4MAPPED(&saddr)) {
				saf = AF_INET;
			} else {
				saf = AF_INET6;
			}


			/*
			 * dup filter adding saddr and new instance num and
			 * add to flist filter list.
			 */
			res = dup_filter(filter, &nfilter, saf, !in32b, &saddr,
			    NULL, ++idx);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			ADD_TO_LIST(flist, nfilter);

		}

	/* if dname only create set of filters, one for each node address */

	} else {
		for (dp = dhp->h_addr_list; *dp != NULL; dp++) {
			(void) bcopy(*dp, &daddr, dhp->h_length);

			/* get af */

			if (in32b || IN6_IS_ADDR_V4MAPPED(&daddr)) {
				daf = AF_INET;
			} else {
				daf = AF_INET6;
			}

			/*
			 * dup filter adding daddr and new instance num and
			 * add to flist filter list.
			 */
			res = dup_filter(filter, &nfilter, daf, !in32b, NULL,
			    &daddr, ++idx);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			ADD_TO_LIST(flist, nfilter);
		}
	}

	if (shp)
		freehostent(shp);
	if (dhp)
		freehostent(dhp);
	return (IPQOS_CONF_SUCCESS);
fail:
	/*
	 * should really clean up any filters that we have created,
	 * however, free_actions called from readaction will cleam them up.
	 */
	if (shp)
		freehostent(shp);
	if (dhp)
		freehostent(dhp);
	return (IPQOS_CONF_ERR);
}


/*
 * read a filter clause from cfp into a filter struct and point filter
 * at this.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
readfilter(
FILE *cfp,
FILE *tfp,
char *module_name,
ipqos_conf_filter_t **filter,
char **perm_filters,
int num_perm_filters)
{

	int res;
	int nm, cls, ipv;
	in6_addr_t mask;
	char *addr_str;
	char *sl = NULL;
	in6_addr_t addr;
	int sa;
	struct hostent *hp;
	int err_num;
	int v4 = 0, v6 = 0;
	uchar_t mlen;
	char *tmp;
	nvpair_t *nvp;
	ipqos_nvtype_t type;
	char *name;
	char *class;
	uchar_t b;
	in6_addr_t v6addr;

	IPQOSCDBG0(L0, "in readfilter\n");


	/* create and zero filter struct */

	*filter = alloc_filter();
	if (*filter == NULL) {
		return (IPQOS_CONF_ERR);
	}
	(*filter)->originator = IPP_CONFIG_IPQOSCONF;

	/* get starting line for error reporting */
	(*filter)->lineno = lineno;

	/* read beginning curl */

	res = read_curl_begin(cfp);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}


	/*
	 * loop reading nvpairs onto nvlist until encounter CURL_END
	 */
	ipv = nm = cls = 0;
	for (;;) {
		/* read nvpair */

		res = readnvpair(cfp, tfp, &(*filter)->nvlist,
		    &nvp, &type, PL_FILTER, module_name);
		if (res == IPQOS_CONF_ERR) {
			goto fail;

		/* reached the end of filter definition */

		} else if (res == IPQOS_CONF_CURL_END) {
			break;
		}

		/*
		 * catch name and class and place value into filter
		 * structure.
		 */

		/* read filter name */

		if (strcmp(nvpair_name(nvp), IPQOS_CONF_NAME_STR) == 0) {
			if (nm != 0) {
				ipqos_msg(MT_ERROR,
				    gettext("Duplicate parameter line %u.\n"),
				    lineno);
				goto fail;
			}

			(void) nvpair_value_string(nvp, &name);
			if (valid_name(name) != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			(void) strcpy((*filter)->name, name);
			(void) nvlist_remove_all((*filter)->nvlist,
			    IPQOS_CONF_NAME_STR);
			nm++;

		/* read class name */

		} else if (strcmp(nvpair_name(nvp), IPQOS_CONF_CLASS_STR) ==
		    0) {
			if (cls != 0) {
				ipqos_msg(MT_ERROR,
				    gettext("Duplicate parameter line %u.\n"),
				    lineno);
				goto fail;
			}

			if (nvpair_value_string(nvp, &class) != 0) {
				ipqos_msg(MT_ENOSTR, "nvpair_value_string");
				break;
			}
			if (valid_name(class) != IPQOS_CONF_SUCCESS) {
				goto fail;
			}
			(void) strcpy((*filter)->class_name, class);
			(void) nvlist_remove_all((*filter)->nvlist,
			    IPQOS_CONF_CLASS_STR);
			cls++;

		/*
		 * if a src or dst ip node name/address. For those that
		 * are determined to be addresses we convert them from
		 * strings here and add to the filter nvlist; for node names
		 * we add the name to the filter struct for readaction to
		 * process.
		 */
		} else if (strcmp(nvpair_name(nvp), IPGPC_SADDR) == 0 ||
		    strcmp(nvpair_name(nvp), IPGPC_DADDR) == 0) {

			sa = 0;

			if (strcmp(nvpair_name(nvp), IPGPC_SADDR) == 0) {
				sa++;
			}

			(void) nvpair_value_string(nvp, &addr_str);

			/*
			 * get the address mask if present.
			 * make a copy so that the nvlist element that
			 * it is part of doesn't dissapear and causes probs.
			 */
			sl = strchr(addr_str, '/');
			if (sl) {
				*sl = '\0';
				tmp = malloc(strlen(++sl) + 1);
				if (tmp == NULL) {
					ipqos_msg(MT_ENOSTR, "malloc");
					goto fail;
				}
				(void) strcpy(tmp, sl);
				sl = tmp;
			}


			/* if a numeric address */

			if (inet_pton(AF_INET, addr_str, &addr) == 1 ||
			    inet_pton(AF_INET6, addr_str, &addr) == 1) {

				/* get address */

				hp = getipnodebyname(addr_str, AF_INET6,
				    AI_DEFAULT, &err_num);
				if (hp == NULL) {
					ipqos_msg(MT_ENOSTR,
					    "getipnodebyname");
					goto fail;
				}

				(void) bcopy(hp->h_addr_list[0], &v6addr,
				    hp->h_length);
				freehostent(hp);

				/* determine address type */

				v4 = IN6_IS_ADDR_V4MAPPED(&v6addr);
				if (!v4) {
					v6++;
				}

				/*
				 * check any previous addresses have same
				 * version.
				 */
				if (nvlist_lookup_byte((*filter)->nvlist,
				    IPGPC_FILTER_TYPE, &b) == 0) {
					if (v4 && b != IPGPC_V4_FLTR ||
					    v6 && b != IPGPC_V6_FLTR) {
						ipqos_msg(MT_ERROR,
						    gettext("Incompatible "
						    "address version line "
						    "%u.\n"), lineno);
						goto fail;
					}
				}

				/*
				 * check that if ip_version spec'd it
				 * corresponds.
				 */
				if ((*filter)->ip_versions != 0) {
					if (v4 && !VERSION_IS_V4(*filter) ||
					    v6 && !VERSION_IS_V6(*filter)) {
						ipqos_msg(MT_ERROR,
						    gettext("Incompatible "
						    "address version line %u"
						    ".\n"), lineno);
						goto fail;
					}
				}

				/* add the address type */

				res = nvlist_add_byte(
				(*filter)->nvlist, IPGPC_FILTER_TYPE,
				    v4 ? IPGPC_V4_FLTR : IPGPC_V6_FLTR);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_byte");
					goto fail;
				}

				/* add address to list */

				res = nvlist_add_uint32_array((*filter)->nvlist,
				    sa ? IPGPC_SADDR : IPGPC_DADDR,
				    (uint32_t *)&v6addr, 4);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint32_array");
					goto fail;
				}


				/*
				 * add mask entry in list.
				 */

				if (sl) {	/* have CIDR mask */
					char *lo;
					res = readuint8(sl, &mlen, &lo);
					if (res != IPQOS_CONF_SUCCESS ||
					    v4 && mlen > 32 ||
					    !v4 && mlen > 128 ||
					    mlen == 0) {
						ipqos_msg(MT_ERROR,
						    gettext("Invalid CIDR "
						    "mask line %u.\n"), lineno);
						goto fail;
					}
					setmask(mlen, &mask,
					    v4 ? AF_INET : AF_INET6);
					free(sl);
				} else {
					/* no CIDR mask spec'd - use all 1s */

					(void) memset(&mask, ~0,
					    sizeof (in6_addr_t));
				}
				res = nvlist_add_uint32_array((*filter)->nvlist,
				    sa ? IPGPC_SADDR_MASK : IPGPC_DADDR_MASK,
				    (uint32_t *)&mask, 4);
				if (res != 0) {
					ipqos_msg(MT_ENOSTR,
					    "nvlist_add_uint32_arr");
					goto fail;
				}

			/* inet_pton returns fail - we assume a node name */

			} else {
				/*
				 * doesn't make sense to have a mask
				 * with a node name.
				 */
				if (sl) {
					ipqos_msg(MT_ERROR,
					    gettext("Address masks aren't "
					    "allowed for host names line "
					    "%u.\n"), lineno);
					goto fail;
				}

				/*
				 * store node name in filter struct for
				 * later resolution.
				 */
				if (sa) {
					(*filter)->src_nd_name =
					    malloc(strlen(addr_str) + 1);
					(void) strcpy((*filter)->src_nd_name,
					    addr_str);
				} else {
					(*filter)->dst_nd_name =
					    malloc(strlen(addr_str) + 1);
					(void) strcpy((*filter)->dst_nd_name,
					    addr_str);
				}
			}

		/* ip_version enumeration */

		} else if (strcmp(nvpair_name(nvp), IPQOS_CONF_IP_VERSION) ==
		    0) {
			/* check we haven't read ip_version before */
			if (ipv) {
				ipqos_msg(MT_ERROR,
				    gettext("Duplicate parameter line %u.\n"),
				    lineno);
				goto fail;
			}
			ipv++;

			/* get bitmask value */

			(void) nvpair_value_uint32(nvp,
			    &(*filter)->ip_versions);

			/*
			 * check that if either ip address is spec'd it
			 * corresponds.
			 */
			if (v4 && !VERSION_IS_V4(*filter) ||
			    v6 && !VERSION_IS_V6(*filter)) {
				ipqos_msg(MT_ERROR, gettext("Incompatible "
				    "address version line %u.\n"), lineno);
				goto fail;
			}

			/* remove ip_version from nvlist */

			(void) nvlist_remove_all((*filter)->nvlist,
			    IPQOS_CONF_IP_VERSION);
		}
	}
	if (nm == 0 || cls == 0) {
		ipqos_msg(MT_ERROR, gettext("Missing filter/class name "
		    "before line %u.\n"), lineno);
		goto fail;
	}

	if (in_string_table(perm_filters, num_perm_filters, (*filter)->name)) {
		IPQOSCDBG1(L0, "Setting filter %s as permanent.\n",
		    (*filter)->name);

		(*filter)->originator = IPP_CONFIG_PERMANENT;
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	if (*filter)
		free_filter(*filter);
	if (hp)
		freehostent(hp);
	if (sl)
		free(sl);

	return (IPQOS_CONF_ERR);
}

/*
 * reads the curl begin token from cfp stream.
 * RETURNS: IPQOS_CONF_ERR if not read successfully, else IPQOS_CONF_SUCCES.
 */
static int
read_curl_begin(FILE *cfp)
{

	int res;
	char *st;

	res = readtoken(cfp, &st);

	if (res != IPQOS_CONF_CURL_BEGIN) {
		if (res == IPQOS_CONF_EOF) {
			ipqos_msg(MT_ERROR, gettext("Unexpected EOF.\n"));

		/* if CURL_END or something else */
		} else if (res != IPQOS_CONF_ERR) {
			free(st);
			ipqos_msg(MT_ERROR, gettext("\'{\' missing at line "
			    "%u.\n"), lineno);
		}
		return (IPQOS_CONF_ERR);
	}

	free(st);
	return (IPQOS_CONF_SUCCESS);
}

/*
 * This function parses the parameter string version into a version of the
 * form "%u.%u" (as a sscanf format string). It then encodes this into an
 * int and returns this encoding.
 * RETURNS: -1 if an invalid string, else the integer encoding.
 */
static int
ver_str_to_int(
char *version)
{
	uint32_t major, minor;
	int ver;

	if (sscanf(version, "%u.%u", &major, &minor) != 2) {
		IPQOSCDBG0(L0, "Failed to process version number string\n");
		return (-1);
	}

	ver = (int)((major * 10000) + minor);
	return (ver);
}

/*
 * This function scans through the stream fp line by line looking for
 * a line beginning with version_tag and returns a integer encoding of
 * the version following it.
 *
 * RETURNS: If the version definition isn't found or the version is not
 * a valid version (%u.%u) then -1 is returned, else an integer encoding
 * of the read version.
 */
static int
read_tfile_ver(
FILE *fp,
char *version_tag,
char *module_name)
{
	char lbuf[IPQOS_CONF_LINEBUF_SZ];
	char buf[IPQOS_CONF_LINEBUF_SZ+1];
	char buf2[IPQOS_CONF_LINEBUF_SZ+1];
	int found = 0;
	int version;

	/*
	 * reset to file start
	 */
	if (fseek(fp, 0, SEEK_SET) != 0) {
		ipqos_msg(MT_ENOSTR, "fseek");
		return (-1);
	}

	/*
	 * loop reading lines till found the one beginning with version_tag.
	 */
	while (fgets(lbuf, IPQOS_CONF_LINEBUF_SZ, fp) != NULL) {
		if ((sscanf(lbuf,
		    "%" VAL2STR(IPQOS_CONF_LINEBUF_SZ) "s"
		    "%" VAL2STR(IPQOS_CONF_LINEBUF_SZ) "s",
		    buf, buf2) == 2) &&
		    (strcmp(buf, version_tag) == 0)) {
			found++;
			break;
		}
	}
	if (found == 0) {
		ipqos_msg(MT_ERROR, gettext("Types file for module %s is "
		    "corrupt.\n"), module_name);
		IPQOSCDBG1(L1, "Couldn't find %s in types file\n",
		    version_tag);
		return (-1);
	}

	/*
	 * convert version string into int.
	 */
	if ((version = ver_str_to_int(buf2)) == -1) {
		ipqos_msg(MT_ERROR, gettext("Types file for module %s is "
		    "corrupt.\n"), module_name);
		return (-1);
	}

	return (version);
}

/*
 * read action clause and params/classes/filters clauses within and
 * store in and hang off an action structure, and point action at it.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
readaction(
FILE *cfp,
ipqos_conf_action_t **action)
{

	char *st;
	FILE *tfp = NULL;
	int nm, md;
	int readprms = 0;
	int res;
	char *strval;
	char *name;
	nvpair_t *nvp;
	ipqos_nvtype_t type;
	ipqos_conf_filter_t *filter;
	ipqos_conf_class_t *class;
	int oe;
	char **perm_filters;
	int num_perm_filters;
	int tf_fmt_ver;

	IPQOSCDBG0(L0, "in readaction\n");

	res = readtoken(cfp, &st);
	if (res == IPQOS_CONF_ERR || res == IPQOS_CONF_EOF) {
		return (res);
	} else if (strcmp(st, IPQOS_CONF_ACTION_STR) != 0) {
			ipqos_msg(MT_ERROR, gettext("Missing %s token line "
			    "%u.\n"), IPQOS_CONF_ACTION_STR, lineno);
			free(st);
			return (IPQOS_CONF_ERR);
	}
	free(st);

	/* create action structure */

	*action = alloc_action();
	if (*action == NULL) {
		return (IPQOS_CONF_ERR);
	}
	(*action)->params->originator = IPP_CONFIG_IPQOSCONF;


	/* get starting line for error reporting */
	(*action)->lineno = lineno;

	/* read beginning curl */

	res = read_curl_begin(cfp);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* loop till read both action name and module */

	nm = md = 0;
	do {
		/* read nvpair */

		res = readnvpair(cfp, NULL, &(*action)->nvlist, &nvp, &type,
		    PL_ACTION, NULL);
		if (res == IPQOS_CONF_ERR) {
			goto fail;

		/* read curl_end */

		} else if (res == IPQOS_CONF_CURL_END) {
			if (nm == 0 || md == 0) {
				ipqos_msg(MT_ERROR,
				    gettext("Missing action name/ module "
				    "before line %u.\n"), lineno);
				goto fail;
			}
		}


		/* store name and module in action structure */

		name = nvpair_name(nvp);

		/* read action name */

		if (nm == 0 && strcmp(name, IPQOS_CONF_NAME_STR) == 0) {

			(void) nvpair_value_string(nvp, &strval);

			/* check name is valid */

			if (valid_name(strval) != IPQOS_CONF_SUCCESS ||
			    valid_aname(strval) != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			/* store and remove from list */

			(void) strcpy((*action)->name, strval);
			/* remove name from nvlist */
			(void) nvlist_remove_all((*action)->nvlist,
			    IPQOS_CONF_NAME_STR);

			nm++;

		/* read module name */

		} else if (md == 0 &&
		    strcmp(name, IPQOS_CONF_MODULE_STR) == 0) {
			/*
			 * check that module has a type file and get
			 * open stream to it.
			 */
			(void) nvpair_value_string(nvp, &strval);
			if ((tfp = validmod(strval, &oe)) == NULL) {
				if (oe) {
					if (errno == ENOENT) {
						ipqos_msg(MT_ERROR,
						    gettext("Invalid "
						    "module name line %u.\n"),
						    lineno);
					} else {
						ipqos_msg(MT_ENOSTR, "fopen");
					}
				}
				goto fail;
			}

			/*
			 * move module name to action struct
			 */
			(void) strlcpy((*action)->module, strval,
			    IPQOS_CONF_NAME_LEN);
			(void) nvlist_remove_all((*action)->nvlist,
			    IPQOS_CONF_MODULE_STR);
			md++;

		/* duplicate/other parameter */

		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Unexpected parameter line %u.\n"),
			    lineno);
			goto fail;
		}

	} while (nm == 0 || md == 0);

	/*
	 * check that if the ipgpc action it is named correctly
	 */
	if ((strcmp((*action)->module, IPGPC_NAME) == 0) &&
	    (strcmp((*action)->name, IPGPC_CLASSIFY) != 0)) {
		ipqos_msg(MT_ERROR,
		    gettext("%s action has incorrect name line %u.\n"),
		    IPGPC_NAME, (*action)->lineno);
		goto fail;
	}

	/* get list of permanent classes */

	res = read_perm_items(0, tfp, (*action)->module,
	    &(*action)->perm_classes, &(*action)->num_perm_classes);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* get list of permanent filters */

	res = read_perm_items(1, tfp, (*action)->module,
	    &perm_filters, &num_perm_filters);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/*
	 * get types file format version and check its supported.
	 */
	if ((tf_fmt_ver = read_tfile_ver(tfp, IPQOS_FMT_STR,
	    (*action)->module)) == -1)
		goto fail;
	if (IPP_MAJOR_MODULE_VER(tf_fmt_ver) > 1 ||
	    IPP_MINOR_MODULE_VER(tf_fmt_ver) > 0) {
		ipqos_msg(MT_ERROR, gettext("Types file for module %s is "
		    "incompatible.\n"), (*action)->module);
		IPQOSCDBG0(L1, "Unsupported fmt major/minor version\n");
		goto fail;
	}

	/*
	 * get module version
	 */
	if (((*action)->module_version = read_tfile_ver(tfp, IPQOS_MOD_STR,
	    (*action)->module)) == -1)
		goto fail;

	/* read filter/class/params blocks until CURL_END */

	for (;;) {
		/* read token */
		res = readtoken(cfp, &st);

		if (res == IPQOS_CONF_ERR) {
			goto fail;
		} else if (res == IPQOS_CONF_EOF) {
			ipqos_msg(MT_ERROR, gettext("Unexpected EOF.\n"));
			goto fail;

		/* read CURL_END - end of action definition */

		} else if (res == IPQOS_CONF_CURL_END) {
			free(st);
			break;
		}


		/*
		 * read in either a filter/class or parameter block.
		 */

		/* read filter */

		if (strcmp(st, IPQOS_CONF_FILTER_STR) == 0) {
			free(st);

			res = readfilter(cfp, tfp, (*action)->module, &filter,
			    perm_filters, num_perm_filters);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			/*
			 * if we read a host name for either src or dst addr
			 * resolve the hostnames and create the appropriate
			 * number of filters.
			 */

			if (filter->src_nd_name || filter->dst_nd_name) {

				res = domultihome(filter, &(*action)->filters,
				    B_FALSE);
				/*
				 * if a lookup fails and the filters
				 * marked as retry we add it to a list
				 * for another attempt later, otherwise
				 * it is thrown away.
				 */
				if (res != IPQOS_CONF_SUCCESS) {

					/* if not name lookup problem */

					if (filter->nlerr == 0) {
						free_filter(filter);
						goto fail;

					/* name lookup problem */

					/*
					 * if intermitent lookup failure
					 * add to list of filters to
					 * retry later.
					 */
					} else if (filter->nlerr ==
					    IPQOS_LOOKUP_RETRY) {
						filter->nlerr = 0;
						ADD_TO_LIST(
						    &(*action)->retry_filters,
						    filter);
					/*
					 * for non-existing names
					 * ignore the filter.
					 */
					} else {
						free_filter(filter);
					}

				/* creation of new filters successful */

				} else {
					free_filter(filter);
				}

			/* non-node name filter */

			} else {
				ADD_TO_LIST(&(*action)->filters, filter);
			}

		/* read class */

		} else if (strcmp(st, IPQOS_CONF_CLASS_STR) == 0) {
			free(st);
			res = readclass(cfp, (*action)->module, &class,
			    (*action)->perm_classes,
			    (*action)->num_perm_classes);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}

			ADD_TO_LIST(&(*action)->classes, class);

		/* read params */

		} else if (strcmp(st, IPQOS_CONF_PARAMS_STR) == 0) {
			free(st);
			if (readprms) {
				ipqos_msg(MT_ERROR,
				    gettext("Second parameter clause not "
				    "supported line %u.\n"), lineno);
				goto fail;
			}
			res = readparams(cfp, tfp, (*action)->module,
			    (*action)->params);
			if (res != IPQOS_CONF_SUCCESS) {
				goto fail;
			}
			readprms++;

		/* something unexpected */
		} else {
			free(st);
			ipqos_msg(MT_ERROR,
			    gettext("Params/filter/class clause expected "
			    "line %u.\n"), lineno);
			goto fail;
		}
	}

	(void) fclose(tfp);
	return (IPQOS_CONF_SUCCESS);

fail:
	if (tfp)
		(void) fclose(tfp);
	if (*action) {
		free_actions(*action);
		*action = NULL;
	}
	return (IPQOS_CONF_ERR);
}

/*
 * check that each of the actions in actions is uniquely named. If one isn't
 * set *name to point at the name of the duplicate action.
 * RETURNS: IPQOS_CONF_ERR if a non-unique action, else IPQOS_CONF_SUCCESS.
 */
static int
actions_unique(ipqos_conf_action_t *actions, char **name)
{

	IPQOSCDBG0(L1, "In actions_unique.\n");

	while (actions) {
		if (actionexist(actions->name, actions->next)) {
			*name = actions->name;
			return (IPQOS_CONF_ERR);
		}
		actions = actions->next;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * checks whether the action parameter is involved in an action cycle.
 * RETURNS: 1 if involved in a cycle, 0 otherwise.
 */
static int
in_cycle(
ipqos_conf_action_t *action)
{

	ipqos_conf_act_ref_t *aref;
	ipqos_conf_class_t *c;

	IPQOSCDBG1(L0, "in_cycle: visiting action %s\n", action->name);


	/* have we visited this action before? */

	if (action->visited == INCYCLE_VISITED) {
		action->visited = 0;
		return (1);
	}
	action->visited = INCYCLE_VISITED;

	/*
	 * recurse down the child actions of this action through the
	 * classes next action and parameter actions.
	 */

	for (aref = action->params->actions; aref != NULL; aref = aref->next) {

		/* skip virtual actions - they can't be in a cycle */

		if (virtual_action(aref->name)) {
			continue;
		}

		if (in_cycle(aref->action)) {
			action->visited = 0;
			return (1);
		}
	}

	for (c = action->classes; c != NULL; c = c->next) {
		aref = c->alist;

		if (virtual_action(aref->name)) {
			continue;
		}

		if (in_cycle(aref->action)) {
			action->visited = 0;
			return (1);
		}
	}

	IPQOSCDBG0(L0, "in_cycle: return\n");
	action->visited = 0;
	return (0);
}

/*
 * checks that the configuration in actions is a valid whole, that
 * all actions are unique, all filters and classes are unique within
 * their action, that classes referenced by filters exist and actions
 * referenced by classes and params exist. Also checks that there are no root
 * actions but ipgpc and that no actions are involved in cycles. As
 * a consequence of checking that the actions exist two way pointers
 * are created between the dependee and dependant actions.
 *
 * In the case the the userconf flag is zero only this link creation is
 * set as we trust the kernel to return a valid configuration.
 *
 * RETURNS: IPQOS_CONF_ERR if config isn't valid, else IPQOS_CONF_SUCCESS.
 *
 */

static int
validconf(
ipqos_conf_action_t *actions,
int userconf)			/* are we checking a conf file ? */
{
	char *name;
	ipqos_conf_action_t *act;
	int res;
	ipqos_conf_action_t *dact;
	ipqos_conf_filter_t *flt;
	ipqos_conf_class_t *cls;
	ipqos_conf_params_t *params;
	ipqos_conf_act_ref_t *aref;

	IPQOSCDBG0(L0, "In validconf\n");

	/* check actions are unique */

	if (userconf && actions_unique(actions, &name) != IPQOS_CONF_SUCCESS) {
		ipqos_msg(MT_ERROR, gettext("Duplicate named action %s.\n"),
		    name);
		return (IPQOS_CONF_ERR);
	}

	for (act = actions; act; act = act->next) {

		/*
		 * check filters (for user land configs only).
		 * check they are unique in this action and their class exists.
		 */
		if (userconf) {
			for (flt = act->filters; flt; flt = flt->next) {

				/* check unique name */

				if (filterexist(flt->name, flt->instance,
				    flt->next)) {
					ipqos_msg(MT_ERROR,
					    gettext("Duplicate named filter "
					    "%s in action %s.\n"), flt->name,
					    act->name);
					return (IPQOS_CONF_ERR);
				}

				/*
				 * check existence of class and error if
				 * class doesn't exist and not a perm class
				 */

				if (!classexist(flt->class_name,
				    act->classes)) {
					if (!in_string_table(act->perm_classes,
					    act->num_perm_classes,
					    flt->class_name)) {
						ipqos_msg(MT_ERROR,
						    gettext("Undefined "
						    "class in filter %s, "
						    "action %s.\n"), flt->name,
						    act->name);
						return (IPQOS_CONF_ERR);
					}
				}
			}
		}

		/* check classes */

		for (cls = act->classes; cls; cls = cls->next) {

			/* check if class name unique (userland only) */

			if (userconf && classexist(cls->name, cls->next)) {
				ipqos_msg(MT_ERROR,
				    gettext("Duplicate named class %s in "
				    "action %s.\n"), cls->name, act->name);
				return (IPQOS_CONF_ERR);
			}

			/*
			 * virtual actions always exist so don't check for next
			 * action.
			 */
			if (virtual_action(cls->alist->name)) {
				continue;
			}

			/*
			 * check existance of next action and create link to
			 * it.
			 */
			if ((cls->alist->action =
			    actionexist(cls->alist->name, actions)) == NULL) {
				ipqos_msg(MT_ERROR,
				    gettext("Undefined action in class %s, "
				    "action %s.\n"), cls->name, act->name);
				return (IPQOS_CONF_ERR);
			}

			/* create backwards link - used for deletions */

			dact = cls->alist->action;
			res = add_aref(&dact->dependencies, NULL, act->name);
			if (res != IPQOS_CONF_SUCCESS) {
				return (IPQOS_CONF_ERR);
			}
			dact->dependencies->action = act;
		}


		/* check actions exist for action type parameters */

		params = act->params;
		for (aref = params->actions; aref; aref = aref->next) {

			/* skip virtuals */

			if (virtual_action(aref->name)) {
				continue;
			}

			/*
			 * check existance of action in this ref
			 * and if present create a ptr to it.
			 */
			aref->action = actionexist(aref->name, actions);
			if (aref->action == NULL) {
				ipqos_msg(MT_ERROR,
				    gettext("Undefined action in parameter "
				    "%s, action %s.\n"),
				    SHORT_NAME(aref->field), act->name);
				return (IPQOS_CONF_ERR);
			}

			/* create backwards link */

			dact = aref->action;
			res = add_aref(&dact->dependencies, NULL,
			    act->name);
			if (res != IPQOS_CONF_SUCCESS) {
				return (IPQOS_CONF_ERR);
			}
			dact->dependencies->action = act;
		}
	}

	/* for kernel retrieved configs we don't do the following checks. */
	if (!userconf) {
		return (IPQOS_CONF_SUCCESS);
	}

	/* check for cycles in config and orphaned actions other than ipgpc */

	for (act = actions; act; act = act->next) {

		/* check if involved in cycle */

		if (in_cycle(act)) {
			ipqos_msg(MT_ERROR,
			    gettext("Action %s involved in cycle.\n"),
			    act->name);
			return (IPQOS_CONF_ERR);
		}

		/* check that this action has a parent (except ipgpc) */

		if (act->dependencies == NULL &&
		    strcmp(act->name, IPGPC_CLASSIFY) != 0) {
			ipqos_msg(MT_ERROR, gettext("Action %s isn't "
			    "referenced by any other actions.\n"), act->name);
			return (IPQOS_CONF_ERR);
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Read the version from the config file with stream cfp with
 * the tag version_tag. The tag-value pair should be the first tokens
 * encountered.
 *
 * RETURNS: -1 if a missing or invalid version or a read error,
 * else an integer encoding of the version.
 */
static int
read_cfile_ver(
FILE *cfp,
char *version_tag)
{
	char *sp = NULL;
	int res;
	int version;

	IPQOSCDBG0(L1, "In read_cfile_ver:\n");

	/*
	 * read version tag string.
	 */
	res = readtoken(cfp, &sp);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	} else if (strcasecmp(sp, version_tag) != 0) {
		goto fail;
	}
	free(sp);
	sp = NULL;

	/*
	 * read version number string.
	 */
	res = readtoken(cfp, &sp);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/*
	 * encode version into int.
	 */
	if ((version = ver_str_to_int(sp)) == -1) {
		goto fail;
	}
	free(sp);

	return (version);
fail:
	ipqos_msg(MT_ERROR,
	    gettext("Missing/Invalid config file %s.\n"), version_tag);
	if (sp != NULL)
		free(sp);
	return (-1);
}

/*
 * read the set of actions definitions from the stream cfp and store
 * them in a list pointed to by conf.
 * RETURNS: IPQOS_CONF_ERR if any errors, else IPQOS_CONF_SUCCESS.
 */
static int
readconf(
FILE *cfp,
ipqos_conf_action_t **conf)
{

	int res;
	ipqos_conf_action_t *action;
	boolean_t ipgpc_action = B_FALSE;
	int fmt_ver;

	IPQOSCDBG0(L0, "In readconf\n");

	*conf = NULL;

	/*
	 * get config file format version.
	 */
	fmt_ver = read_cfile_ver(cfp, IPQOS_FMT_VERSION_STR);
	if (fmt_ver == -1) {
		return (IPQOS_CONF_ERR);
	} else {
		/*
		 * check version is valid
		 */
		if ((IPP_MAJOR_MODULE_VER(fmt_ver) > 1) ||
		    (IPP_MINOR_MODULE_VER(fmt_ver) > 0)) {
			ipqos_msg(MT_ERROR, gettext("Unsupported config file "
			    "format version.\n"));
			return (IPQOS_CONF_ERR);
		}
	}

	/* loop reading actions adding to conf till EOF */

	for (;;) {
		action = NULL;

		/* readaction */

		res = readaction(cfp, &action);
		if (res == IPQOS_CONF_ERR) {
			goto fail;
		}

		/* reached eof, finish */

		if (res == IPQOS_CONF_EOF) {
			break;
		}

		ADD_TO_LIST(conf, action);

		/* check if we just read an ipgpc action */

		if (strcmp(action->name, IPGPC_CLASSIFY) == 0)
			ipgpc_action = B_TRUE;
	}

	/* check that there is one or more actions and that one is ipgpc */

	if (ipgpc_action == B_FALSE) {
		ipqos_msg(MT_ERROR, gettext("No %s action defined.\n"),
		    IPGPC_NAME);
		goto fail;
	}

	return (IPQOS_CONF_SUCCESS);
fail:
	free_actions(*conf);
	*conf = NULL;
	return (IPQOS_CONF_ERR);
}

/* ************************ kernel config retrieval ************************ */


/*
 * read the current configuration from the kernel and make *conf a ptr to it.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
readkconf(ipqos_conf_action_t **conf)
{

	int res;
	char **modnames = NULL;
	int nmods;
	char **actnames = NULL;
	int nacts;
	int x, y;
	FILE *tfp;
	int openerr;
	ipqos_actinfo_prm_t ai_prm;


	IPQOSCDBG0(L0, "In readkconf\n");

	/* initialise conf to NULL */
	*conf = NULL;

	/* get list of modules currently loaded */

	res = ipp_list_mods(&modnames, &nmods);
	if (res != 0) {
		ipqos_msg(MT_ENOSTR, "ipp_list_mods");
		return (IPQOS_CONF_ERR);
	}

	/*
	 * iterate through all loaded modules retrieving their list of actions
	 * and then retrieving the configuration of each of these
	 * and attatching it to conf.
	 */
	for (x = 0; x < nmods; x++) {

		/* skip actions of modules that we can't open types file of */

		if ((tfp = validmod(modnames[x], &openerr)) == NULL) {

			/* mem error */

			if (!openerr) {
				goto fail;

			/*
			 * fopen fail - if we failed because the file didn't
			 * exist we assume this is an unknown module and
			 * ignore this module, otherwise error.
			 */
			} else {
				if (errno == ENOENT) {
					continue;
				} else {
					ipqos_msg(MT_ENOSTR, "fopen");
					goto fail;
				}
			}
		}
		(void) fclose(tfp);

		/* get action list for this module */

		res = ipp_mod_list_actions(modnames[x], &actnames, &nacts);
		if (res != 0) {
			ipqos_msg(MT_ENOSTR, "ipp_mod_list_actions");
			goto fail;
		}

		/* read config of each action of this module */

		for (y = 0; y < nacts; y++) {
			ai_prm.action = alloc_action();
			if (ai_prm.action == NULL) {
				goto fail;
			}

			/* copy action name into action struct */

			(void) strlcpy(ai_prm.action->name, actnames[y],
			    IPQOS_CONF_NAME_LEN);

			/* copy module name into action struct */

			(void) strlcpy(ai_prm.action->module, modnames[x],
			    IPQOS_CONF_NAME_LEN);

			/* get action info */

			res = ipp_action_info(actnames[y],
			    (int (*)(nvlist_t *, void *))parse_kaction,
			    (void *)&ai_prm, 0);
			if (res != 0) {
				/* was this an ipp error */
				if (ai_prm.intl_ret == IPQOS_CONF_SUCCESS) {
					ipqos_msg(MT_ENOSTR,
					    "ipp_action_info");
				}
				goto fail;
			}

			ADD_TO_LIST(conf, ai_prm.action);
		}

		cleanup_string_table(actnames, nacts);
	}

	cleanup_string_table(modnames, nmods);
	return (IPQOS_CONF_SUCCESS);
fail:
	free_actions(*conf);
	*conf = NULL;
	cleanup_string_table(modnames, nmods);
	cleanup_string_table(actnames, nacts);
	return (IPQOS_CONF_ERR);
}

/*
 * This is passed as a parameter to ipp_action_info() in readkaction and
 * is called back one for each configuration element within the action
 * specified. This results in filters and classes being created and chained
 * off of action, and action having its params set.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCESS.
 */
static int
parse_kaction(
nvlist_t *nvl,
ipqos_actinfo_prm_t *ai_prm)
{

	int ret;
	uint8_t cfgtype;
	ipqos_conf_filter_t *filter = NULL;
	ipqos_conf_class_t *class = NULL;
	ipqos_conf_action_t *action = ai_prm->action;


	IPQOSCDBG1(KRET, "In parse_kaction: action_name: %s\n", action->name);

	/* get config type */

	(void) nvlist_lookup_byte(nvl, IPP_CONFIG_TYPE, &cfgtype);
	(void) nvlist_remove_all(nvl, IPP_CONFIG_TYPE);

	switch (cfgtype) {
		case CLASSIFIER_ADD_FILTER: {
			/*
			 * parse the passed filter nvlist
			 * and add result to action's filter list.
			 */
			filter = alloc_filter();
			if (filter == NULL) {
				ai_prm->intl_ret = IPQOS_CONF_ERR;
				return (IPQOS_CONF_ERR);
			}

			ret = parse_kfilter(filter, nvl);
			if (ret != IPQOS_CONF_SUCCESS) {
				free_filter(filter);
				ai_prm->intl_ret = IPQOS_CONF_ERR;
				return (ret);
			}

			ADD_TO_LIST(&action->filters, filter);
			break;
		}
		case CLASSIFIER_ADD_CLASS:
		case CLASSIFIER_MODIFY_CLASS: {
			/*
			 * parse the passed class nvlist
			 * and add result to action's class list.
			 */
			class = alloc_class();
			if (class == NULL) {
				ai_prm->intl_ret = IPQOS_CONF_ERR;
				return (IPQOS_CONF_ERR);
			}

			ret = parse_kclass(class, nvl);
			if (ret != IPQOS_CONF_SUCCESS) {
				free_class(class);
				ai_prm->intl_ret = IPQOS_CONF_ERR;
				return (ret);
			}

			ADD_TO_LIST(&action->classes, class);
			break;
		}
		case IPP_SET: {
			/*
			 * we don't alloc a params struct as it is created
			 * as part of an action.
			 */

			/* parse the passed params nvlist */

			ret = parse_kparams(action->module, action->params,
			    nvl);
			if (ret != IPQOS_CONF_SUCCESS) {
				ai_prm->intl_ret = IPQOS_CONF_ERR;
				return (ret);
			}
		}
	}

	ai_prm->intl_ret = IPQOS_CONF_SUCCESS;
	return (IPQOS_CONF_SUCCESS);
}

/*
 * parses a params nvlist returned from the kernel.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
int
parse_kparams(
char *module,
ipqos_conf_params_t *params,
nvlist_t *nvl) {

	int ret;
	ipqos_nvtype_t type;
	str_val_nd_t *tmp;
	char *act;
	uint32_t u32;
	nvpair_t *nvp;
	FILE *tfp;
	char dfltst[IPQOS_VALST_MAXLEN];
	char *param;
	nvlist_t *nvlcp;
	int openerr;
	place_t place;

	IPQOSCDBG0(KRET, "In parse_kparams:\n");

	/* get stream to module types file */

	tfp = validmod(module, &openerr);
	if (tfp == NULL) {
		if (openerr) {
			ipqos_msg(MT_ENOSTR, "fopen");
		}
		return (IPQOS_CONF_ERR);
	}

	/* make copy of passed in nvlist as it is freed by the caller */

	ret = nvlist_dup(nvl, &nvlcp, 0);
	if (ret != 0) {
		return (IPQOS_CONF_ERR);
	}

	/*
	 * get config originator and remove from nvlist. If no owner we
	 * assume ownership.
	 */
	ret = nvlist_lookup_uint32(nvlcp, IPP_CONFIG_ORIGINATOR, &u32);
	if (ret == 0) {
		params->originator = u32;
		(void) nvlist_remove_all(nvlcp, IPP_CONFIG_ORIGINATOR);
	} else {
		params->originator = IPP_CONFIG_IPQOSCONF;
	}

	/* get action stats and remove from nvlist */

	ret = nvlist_lookup_uint32(nvlcp, IPP_ACTION_STATS_ENABLE, &u32);
	if (ret == 0) {
		params->stats_enable = *(boolean_t *)&u32;
		(void) nvlist_remove_all(nvlcp, IPP_ACTION_STATS_ENABLE);
	}

	/*
	 * loop throught nvlist elements and for those that are actions create
	 * action ref entrys for them.
	 */
	nvp = nvlist_next_nvpair(nvlcp, NULL);
	while (nvp != NULL) {
		param = SHORT_NAME(nvpair_name(nvp));
		place = PL_ANY;
		ret = readtype(tfp, module, param, &type, &tmp, dfltst,
		    B_FALSE, &place);
		if (ret != IPQOS_CONF_SUCCESS) {
			goto fail;
		}

		if ((place == PL_PARAMS) &&	/* avoid map entries */
		    (type == IPQOS_DATA_TYPE_ACTION)) {
			(void) nvpair_value_string(nvp, &act);
			ret = add_aref(&params->actions, nvpair_name(nvp), act);
			if (ret != IPQOS_CONF_SUCCESS) {
				goto fail;
			}
		}

		nvp = nvlist_next_nvpair(nvlcp, nvp);
	}

	/* assign copied nvlist to params struct */

	params->nvlist = nvlcp;

	(void) fclose(tfp);
	return (IPQOS_CONF_SUCCESS);
fail:
	(void) fclose(tfp);
	free_arefs(params->actions);
	params->actions = NULL;
	nvlist_free(nvlcp);
	return (IPQOS_CONF_ERR);
}

/*
 * parses a classes nvlist returned from the kernel.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
parse_kclass(
ipqos_conf_class_t *class,
nvlist_t *nvl)
{

	int ret;
	uint32_t u32;
	char *str;

	IPQOSCDBG0(KRET, "In parse_kclass:\n");

	/* lookup object originator */

	ret = nvlist_lookup_uint32(nvl, IPP_CONFIG_ORIGINATOR, &u32);
	if (ret == 0) {
		class->originator = u32;
	} else {
		class->originator = IPP_CONFIG_IPQOSCONF;
	}

	/* lookup name */

	(void) nvlist_lookup_string(nvl, CLASSIFIER_CLASS_NAME, &str);
	(void) strlcpy(class->name, str, IPQOS_CONF_NAME_LEN);
	IPQOSCDBG1(KRET, "reading class %s\n", class->name);

	/* lookup next action */

	(void) nvlist_lookup_string(nvl, CLASSIFIER_NEXT_ACTION, &str);
	ret = add_aref(&class->alist, NULL, str);
	if (ret != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	/* lookup stats enable */

	ret = nvlist_lookup_uint32(nvl, CLASSIFIER_CLASS_STATS_ENABLE, &u32);
	if (ret == 0) {
		class->stats_enable = *(boolean_t *)&u32;
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * parses a filters nvlist returned from the kernel.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
parse_kfilter(
ipqos_conf_filter_t *filter,
nvlist_t *nvl)
{

	int ret;
	char *str;
	uint32_t u32;
	nvlist_t *nvlcp;
	char *end;

	IPQOSCDBG0(KRET, "In parse_kfilter:\n");

	/* make copy of passed in nvlist as it is freed by the caller */

	ret = nvlist_dup(nvl, &nvlcp, 0);
	if (ret != 0) {
		return (IPQOS_CONF_ERR);
	}

	/* lookup originator */

	ret = nvlist_lookup_uint32(nvlcp, IPP_CONFIG_ORIGINATOR, &u32);
	if (ret == 0) {
		filter->originator = u32;
		(void) nvlist_remove_all(nvlcp, IPP_CONFIG_ORIGINATOR);
	} else {
		filter->originator = IPP_CONFIG_IPQOSCONF;
	}

	/* lookup filter name */

	(void) nvlist_lookup_string(nvlcp, CLASSIFIER_FILTER_NAME, &str);
	(void) strlcpy(filter->name, str, IPQOS_CONF_NAME_LEN);
	(void) nvlist_remove_all(nvlcp, CLASSIFIER_FILTER_NAME);

	/* lookup class name */

	(void) nvlist_lookup_string(nvlcp, CLASSIFIER_CLASS_NAME, &str);
	(void) strlcpy(filter->class_name, str, IPQOS_CONF_NAME_LEN);
	(void) nvlist_remove_all(nvlcp, CLASSIFIER_CLASS_NAME);

	/* lookup src and dst host names if present */

	if (nvlist_lookup_string(nvlcp, IPGPC_SADDR_HOSTNAME, &str) == 0) {
		filter->src_nd_name = malloc(strlen(str) + 1);
		if (filter->src_nd_name) {
			(void) strcpy(filter->src_nd_name, str);
			(void) nvlist_remove_all(nvlcp, IPGPC_SADDR_HOSTNAME);
		} else {
			ipqos_msg(MT_ENOSTR, "malloc");
			nvlist_free(nvlcp);
			return (IPQOS_CONF_ERR);
		}
	}
	if (nvlist_lookup_string(nvlcp, IPGPC_DADDR_HOSTNAME, &str) == 0) {
		filter->dst_nd_name = malloc(strlen(str) + 1);
		if (filter->dst_nd_name) {
			(void) strcpy(filter->dst_nd_name, str);
			(void) nvlist_remove_all(nvlcp, IPGPC_DADDR_HOSTNAME);
		} else {
			ipqos_msg(MT_ENOSTR, "malloc");
			nvlist_free(nvlcp);
			return (IPQOS_CONF_ERR);
		}
	}

	/* lookup ip_version if present */

	if (nvlist_lookup_string(nvlcp, IPGPC_FILTER_PRIVATE, &str) == 0) {
		filter->ip_versions = (uint32_t)strtol(str, &end, 0);
		if (end != str) {
			(void) nvlist_remove_all(nvlcp, IPGPC_FILTER_PRIVATE);
		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Corrupted ip_version returned from "
			    "kernel.\n"));
			nvlist_free(nvlcp);
			return (IPQOS_CONF_ERR);
		}
	}

	/* lookup filter instance if present */

	ret = nvlist_lookup_int32(nvlcp, IPGPC_FILTER_INSTANCE,
	    &filter->instance);
	if (ret != 0) {
		filter->instance = -1;
	} else {
		(void) nvlist_remove_all(nvlcp, IPGPC_FILTER_INSTANCE);
	}

	/* attach new trimmed nvlist to filter */
	filter->nvlist = nvlcp;

	return (IPQOS_CONF_SUCCESS);
}


/*
 * determines whether action_name is a virtual action name.
 * RETURNS: if virtual action 1, else 0.
 */
static int
virtual_action(char *action_name)
{

	if (strcmp(action_name, IPP_ANAME_CONT) == 0 ||
	    strcmp(action_name, IPP_ANAME_DEFER) == 0 ||
	    strcmp(action_name, IPP_ANAME_DROP) == 0) {
		return (1);
	}

	return (0);
}

/*
 * remove all the actions within the kernel. If there is a failure
 * modified is set to represent whether the attempt to flush modified
 * the configuration in any way.
 * RETURNS: IPQOS_CONF_ERR if the ipp_* functions return any errors,
 * else IPQOS_CONF_SUCCESS.
 */
static int
flush(
boolean_t *modified)
{

	int res;
	char **modnames = NULL;
	int nmods;
	char **actnames = NULL;
	int nacts;
	int x, y;

	IPQOSCDBG0(L0, "In flush\n");

	*modified = B_FALSE;

	/*
	 * get list of modules currently loaded.
	 */
	res = ipp_list_mods(&modnames, &nmods);
	if (res != 0) {
		ipqos_msg(MT_ENOSTR, "ipp_list_mods");
		return (IPQOS_CONF_ERR);
	}

	/*
	 * iterate through all the modules listing their actions and
	 * deleting all of them.
	 */
	for (x = 0; x < nmods; x++) {
		IPQOSCDBG1(APPLY, "Getting actions of module %s.\n",
		    modnames[x]);
		res = ipp_mod_list_actions(modnames[x], &actnames, &nacts);
		if (res != 0) {
			ipqos_msg(MT_ENOSTR, "ipp_mod_list_actions");
			cleanup_string_table(modnames, nmods);
			return (IPQOS_CONF_ERR);
		}

		for (y = 0; y < nacts; y++) {
			IPQOSCDBG1(APPLY, "deleting action %s\n", actnames[y]);
			res = ipp_action_destroy(actnames[y], IPP_DESTROY_REF);
			/*
			 * if fails for reason other than action doesn't
			 * exist or action has dependency.
			 */
			if (res != 0 && errno != ENOENT && errno != EBUSY) {
				ipqos_msg(MT_ENOSTR, "ipp_action_destroy");
				cleanup_string_table(modnames, nmods);
				cleanup_string_table(actnames, nacts);
				return (IPQOS_CONF_ERR);
			}

			if (res == 0)
				*modified = B_TRUE;
		}
		cleanup_string_table(actnames, nacts);
	}
	cleanup_string_table(modnames, nmods);

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Trys to flush the configuration. If it fails and nothing has been modified
 * and force_flush is false just return an error, otherwise persist trying to
 * completion.
 * RETURNS: IPQOS_CONF_ERR if flush attempt failed without modifying anything
 * and force_flush was set to false, otherwise IPQOS_CONF_SUCCESS.
 */
static int
atomic_flush(
boolean_t force_flush)
{
	int x = 0;
	int res;
	boolean_t modified = B_FALSE;

	/*
	 * attempt first flush of config.
	 */
	res = flush(&modified);
	if ((force_flush == B_FALSE) && (res != IPQOS_CONF_SUCCESS) &&
	    (modified == B_FALSE)) {
		return (IPQOS_CONF_ERR);
	} else if (res == IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_SUCCESS);
	}

	/*
	 * failed flush that modified config, or force flush set; loop till
	 * successful flush.
	 */
	while (res != IPQOS_CONF_SUCCESS) {
		if (x == 5) {	/* 10 secs since start/last message. */
			ipqos_msg(MT_ERROR,
			    gettext("Retrying configuration flush.\n"));
			x = 0;
		}
		(void) sleep(2);
		x++;
		res = flush(&modified);
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Performs a flush of the configuration within a signal blocking region
 * so that there's minimal chance of it being killed and the flush only
 * partially completing.
 * RETURNS: IPQOS_CONF_SUCCESS (for symmetry with the other main functions).
 */
static int
flushconf()
{
	int res;

	/*
	 * make sure that flush is as atomic as possible.
	 */
	if ((res = block_all_signals()) == -1)
		return (IPQOS_CONF_ERR);

	res = atomic_flush(B_FALSE);

	/*
	 * restore signals.
	 */
	(void) restore_all_signals();

	if (res == IPQOS_CONF_SUCCESS) {
		ipqos_msg(MT_LOG, gettext("Configuration flushed.\n"));
	} else {
		ipqos_msg(MT_ENOSTR, "atomic_flush");
	}

	return (res);
}

static int
in_string_table(char *stable[], int size, char *string)
{

	IPQOSCDBG1(L1, "In in_string_table: search string %s\n", string);

	for (--size; size >= 0; size--) {
		if (strcmp(stable[size], string) == 0) {
			IPQOSCDBG1(L1, "Found %s in string table\n", string);
			return (1);
		}
	}

	return (0);
}

/* free the memory occupied by the string table ctable and its contents. */
static void
cleanup_string_table(char *ctable[], int size)
{

	int x;

	if (ctable) {
		for (x = 0; x < size; x++) {
			free(ctable[x]);
		}
		free(ctable);
	}
}

#if 0

/*
 * makes a copy of a string table and returns a ptr to it.
 * RETURNS: NULL on error or if size was 0, else ptr to copied table.
 */
static char **
copy_string_table(char *stable1[], int size)
{

	char **st = NULL;
	int pos;

	/* create char ptr array */

	st = malloc(size * sizeof (char *));
	if (st == NULL) {
		ipqos_msg(MT_ENOSTR, "malloc");
		return (st);
	}

	/* create copy of each string from stable1 in array */

	for (pos = size - 1; pos >= 0; pos--) {
		st[pos] = malloc(strlen(stable1[pos] + 1));
		if (st[pos] == NULL) {
			for (pos++; pos < size; pos++)
				free(st[pos]);
			free(st);
			ipqos_msg(MT_ENOSTR, "malloc");
			return (NULL);
		}

		(void) strcpy(st[pos], stable1[pos]);
	}

	return (st);
}
#endif	/* 0 */

/*
 * retry lookups on filters that soft failed a previous lookup and
 * were put on the retry list.
 * RETURNS: IPQOS_CONF_ERR on any errors, else IPQOS_CONF_SUCCESS.
 */
static int
retry_name_lookups(
ipqos_conf_action_t *actions)
{

	ipqos_conf_action_t *act;
	ipqos_conf_filter_t **new_filters;
	ipqos_conf_filter_t *flt;

	IPQOSCDBG0(APPLY, "In retry_name_lookups:\n");

	for (act = actions; act != NULL; act = act->next) {

		/* store start of new resolved filters */
		LIST_END(&act->filters, &new_filters);

		/*
		 * do name resolution on retry list adding resolved filters
		 * to end of actions filters.
		 */
		for (flt = act->retry_filters; flt != NULL; flt = flt->next) {

			if (domultihome(flt, new_filters, B_TRUE) !=
			    IPQOS_CONF_SUCCESS) {

				/* if resource failure */

				if (flt->nlerr == 0) {
					return (IPQOS_CONF_ERR);
				}
			}
		}

		/* add the newly resolved filters to the kernel action */

		for (flt = *new_filters; flt != NULL; flt = flt->next) {
			if (add_filter(act->name, flt, act->module_version) !=
			    IPQOS_CONF_SUCCESS) {
				return (IPQOS_CONF_ERR);
			}
		}
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * write the configuration in conf to the file given in dstpath. This
 * is done by writing first to a temporary file and then renaming that
 * file to dstpath. This assures an atomic write.
 * RETURNS: IPQOS_CONF_ERR on any errors, else IPQOS_CONF_SUCCESS.
 */
static int
writeconf(
ipqos_conf_action_t *conf,
char *dstpath)
{

	FILE *tmpfp;
	char *tmppath;
	char *pathend;
	ipqos_conf_action_t *act;
	int res;

	IPQOSCDBG0(L0, "in writeconf\n");

	/* construct tmp file path so we can use rename() */

	pathend = strrchr(dstpath, '/');

	/* dstpath in current dir */

	if (pathend == NULL) {
		tmppath = malloc(strlen("ipqosconf.tmp") + 1);
		if (tmppath == NULL) {
			ipqos_msg(MT_ENOSTR, "malloc");
			return (IPQOS_CONF_ERR);
		}
		(void) strcpy(tmppath, "ipqosconf.tmp");

	/* dstpath in root dir */

	} else if (pathend == dstpath) {
		tmppath = malloc(strlen("/ipqosconf.tmp") + 1);
		if (tmppath == NULL) {
			ipqos_msg(MT_ENOSTR, "malloc");
			return (IPQOS_CONF_ERR);
		}
		(void) strcpy(tmppath, "/ipqosconf.tmp");

	/* not pwd or root */

	} else {
		*pathend = NULL;
		tmppath = malloc(strlen(dstpath) + strlen("/ipqosconf.tmp") +
		    1);
		if (tmppath == NULL) {
			ipqos_msg(MT_ENOSTR, "malloc");
			return (IPQOS_CONF_ERR);
		}
		(void) strcpy(tmppath, dstpath);
		(void) strcat(tmppath, "/ipqosconf.tmp");
		*pathend = '/';
	}


	/* open tmp file */

	tmpfp = fopen(tmppath, "w");
	if (tmpfp == NULL) {
		ipqos_msg(MT_ENOSTR, "fopen");
		free(tmppath);
		return (IPQOS_CONF_ERR);
	}

	/* write out format version */

	(void) fprintf(tmpfp, "%s %d.%d\n\n", IPQOS_FMT_VERSION_STR,
	    IPQOS_CUR_FMT_MAJOR_VER, IPQOS_CUR_FMT_MINOR_VER);

	/*
	 * loop through actions in list writing ipqosconf originated
	 * ones out to the tmp file.
	 */
	for (act = conf; act != NULL; act = act->next) {
		if (act->params->originator == IPP_CONFIG_IPQOSCONF) {
			res = printaction(tmpfp, act, 0, 0);
			if (res != IPQOS_CONF_SUCCESS) {
				free(tmppath);
				(void) fclose(tmpfp);
				return (res);
			}
		}
	}
	(void) fclose(tmpfp);

	/* rename tmp file to dst file */

	if (rename(tmppath, dstpath) != 0) {
		ipqos_msg(MT_ENOSTR, "rename");
		free(tmppath);
		return (IPQOS_CONF_ERR);
	}
	free(tmppath);

	return (IPQOS_CONF_SUCCESS);
}

/*
 * read the configuration back from the kernel and then write each of the
 * actions read to IPQOS_CONF_INIT_PATH.
 * RETURNS: IPQOS_CONF_ERR if error, else IPQOS_CONF_SUCCESS.
 */
static int
commitconf()
{

	int ret;
	ipqos_conf_action_t *conf;

	IPQOSCDBG0(L0, "In commitconf\n");

	/* read the configuration from the kernel */

	ret = readkconf(&conf);
	if (ret != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	/* dissallow a null config to be stored (we can't read one in) */

	if (conf == NULL) {
		ipqos_msg(MT_ERROR,
		    gettext("Can't commit a null configuration.\n"));
		return (IPQOS_CONF_ERR);
	}

	/* make sure if we create file that perms are 644 */

	(void) umask(S_IXUSR | S_IWGRP | S_IXGRP | S_IWOTH | S_IXOTH);

	/* write the configuration to the init file */

	ret = writeconf(conf, IPQOS_CONF_INIT_PATH);
	if (ret != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	ipqos_msg(MT_LOG,
	    gettext("Current configuration saved to init file.\n"));

	return (IPQOS_CONF_SUCCESS);
}

/*
 * Called in the event of a failed rollback. It first flushes the
 * current configuration, then attempts to apply the oconf (the old
 * one), and if that fails flushes again.
 *
 * RETURNS: IPQOS_CONF_ERR if the application of old config fails,
 * else IPQOS_CONF_SUCCESS.
 */
static int
rollback_recover(
ipqos_conf_action_t *oconf)
{
	int res;

	IPQOSCDBG0(RBK, "In rollback_recover\n");

	/*
	 * flush configuration.
	 */
	(void) atomic_flush(B_TRUE);

	/*
	 * mark all elements of old config for application.
	 */
	mark_config_new(oconf);

	/*
	 * attempt to apply old config.
	 */
	res = applydiff(oconf, NULL);
	/*
	 * if failed force flush of config.
	 */
	if (res != IPQOS_CONF_SUCCESS) {
		(void) atomic_flush(B_TRUE);
		return (IPQOS_CONF_ERR);
	}

	return (IPQOS_CONF_SUCCESS);
}

/*
 * read and apply the configuration contained if file ifile to the kernel.
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */
static int
applyconf(char *ifile)
{

	FILE *ifp;
	ipqos_conf_action_t *conf = NULL;
	ipqos_conf_action_t *oconf = NULL;
	ipqos_conf_action_t *act, *oact;
	int res;

	IPQOSCDBG0(L0, "In applyconf:\n");


	/* if filename '-' read from stdin */

	if (strcmp(ifile, "-") == 0) {
		ifp = stdin;
	} else {
		ifp = fopen(ifile, "r");
		if (ifp == NULL) {
			ipqos_msg(MT_ERROR,
			    gettext("Opening file %s for read: %s.\n"),
			    ifile, strerror(errno));
			return (IPQOS_CONF_ERR);
		}
	}

	/* read in new configuration */

	res = readconf(ifp, &conf);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* check configuration is valid */

	res = validconf(conf, 1);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* read in kernel configuration */

	res = readkconf(&oconf);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/*
	 * check there are no same named actions in both config file and the
	 * the kernel that are for a different module. The application
	 * system can't handle these as we would try to add the new
	 * action before we deleted the old one and because actions
	 * in the kernel are indexed solely on their name (their module
	 * isn't included) the kernel would return an error. We want
	 * to avoid this error and the resulting rollback.
	 */
	for (act = conf; act != NULL; act = act->next) {
		for (oact = oconf; oact != NULL; oact = oact->next) {
			/* found action */
			if (strcmp(act->name, oact->name) == 0) {
				/* different module */
				if (strcmp(act->module, oact->module) != 0) {
					ipqos_msg(MT_ERROR,
					    gettext("Action at line %u has "
					    "same name as currently "
					    "installed action, but is for a "
					    "different module.\n"),
					    act->lineno);
					goto fail;
				/* same module - stop search */
				} else {
					break;
				}
			}
		}
	}


	/* create links between actions for use with deletions etc.. */

	res = validconf(oconf, 0);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* diff conf file against kernel */

	res = diffconf(oconf, conf);
	if (res != IPQOS_CONF_SUCCESS) {
		goto fail;
	}

	/* make kernel mods as atomic as possible */

	if ((res = block_all_signals()) == -1) {
		res = IPQOS_CONF_ERR;
		goto fail;
	}

	/* apply difference to kernel */

	res = applydiff(conf, oconf);
#ifdef	_IPQOS_CONF_DEBUG
	if (force_rback || res != IPQOS_CONF_SUCCESS) {
#else
	if (res != IPQOS_CONF_SUCCESS) {
#endif	/* _IPQOS_CONF_DEBUG */

		res = rollback(conf, oconf);
		if (res != IPQOS_CONF_SUCCESS) {
			res = rollback_recover(oconf);
			if (res != IPQOS_CONF_SUCCESS) {
				/* system left flushed */
				ipqos_msg(MT_ERROR,
				    gettext("Failed to rollback from failed "
				    "configuration, configuration flushed.\n"));
				res = IPQOS_CONF_RECOVER_ERR;
			} else {	/* old config re-applied */
				ipqos_msg(MT_ERROR,
				    gettext("Configuration failed, system "
				    "state unchanged.\n"));
				res = IPQOS_CONF_ERR;
			}
		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Configuration failed, system "
			    "state unchanged.\n"));
			res = IPQOS_CONF_ERR;
		}
		goto fail;
	}

	/* retry any soft name lookup failures */

	res = retry_name_lookups(conf);
	if (res != IPQOS_CONF_SUCCESS) {
		res = rollback(conf, oconf);
		if (res != IPQOS_CONF_SUCCESS) {
			res = rollback_recover(oconf);
			if (res != IPQOS_CONF_SUCCESS) {
			/* system left flushed */
				ipqos_msg(MT_ERROR,
				    gettext("Failed to rollback from failed "
				    "configuration, configuration flushed.\n"));
				res = IPQOS_CONF_RECOVER_ERR;
			} else {	/* old config re-applied */
				ipqos_msg(MT_ERROR,
				    gettext("Configuration failed, system "
				    "state unchanged.\n"));
				res = IPQOS_CONF_ERR;
			}
		} else {
			ipqos_msg(MT_ERROR,
			    gettext("Configuration failed, system "
			    "state unchanged.\n"));
			res = IPQOS_CONF_ERR;
		}
		goto fail;

	}

	ipqos_msg(MT_LOG, gettext("IPQoS configuration applied.\n"));

	/* re-enable signals */
	(void) restore_all_signals();

	(void) fclose(ifp);
	free_actions(conf);
	free_actions(oconf);
	return (IPQOS_CONF_SUCCESS);
fail:
	(void) fclose(ifp);
	(void) restore_all_signals();
	if (conf)
		free_actions(conf);
	if (oconf)
		free_actions(oconf);
	if (res == IPQOS_CONF_RECOVER_ERR)
		ipqos_msg(MT_LOG, gettext("Configuration flushed.\n"));
	return (res);
}

static sigset_t set, oset;

static int
block_all_signals()
{
	if (sigfillset(&set) == -1) {
		ipqos_msg(MT_ENOSTR, "sigfillset");
		return (-1);
	}
	if (sigprocmask(SIG_SETMASK, &set, &oset) == -1) {
		ipqos_msg(MT_ENOSTR, "sigprocmask");
		return (-1);
	}
	return (0);
}

static int
restore_all_signals()
{
	if (sigprocmask(SIG_SETMASK, &oset, NULL) == -1) {
		ipqos_msg(MT_ENOSTR, "sigprocmask");
		return (-1);
	}
	return (0);
}

static int
unlock(int fd)
{
	if (lockf(fd, F_ULOCK, 0) == -1) {
		ipqos_msg(MT_ENOSTR, "lockf");
		return (-1);
	}
	return (0);
}

static int
lock()
{
	int fd;
	struct stat sbuf1;
	struct stat sbuf2;

	/*
	 * Open the file with O_CREAT|O_EXCL. If it exists already, it
	 * will fail. If it already exists, check whether it looks like
	 * the one we created.
	 */
	(void) umask(0077);
	if ((fd = open(IPQOS_CONF_LOCK_FILE, O_EXCL|O_CREAT|O_RDWR,
	    S_IRUSR|S_IWUSR)) == -1) {
		if (errno != EEXIST) {
			/* Some other problem. */
			ipqos_msg(MT_ENOSTR,
			    gettext("Cannot open lock file %s"),
			    IPQOS_CONF_LOCK_FILE);
			return (-1);
		}

		/*
		 * open() returned an EEXIST error. We don't fail yet
		 * as it could be a residual from a previous
		 * execution. However, we need to clear errno here.
		 * If we don't and print_cmd_buf() is later invoked
		 * as the result of a parsing error, it
		 * will assume that the current error is EEXIST and
		 * that a corresponding error message has already been
		 * printed, which results in an incomplete error
		 * message. If errno is zero, print_cmd_buf() will
		 * assume that it is called as a result of a
		 * parsing error and will print the appropriate
		 * error message.
		 */
		errno = 0;

		/*
		 * File exists. make sure it is OK. We need to lstat()
		 * as fstat() stats the file pointed to by the symbolic
		 * link.
		 */
		if (lstat(IPQOS_CONF_LOCK_FILE, &sbuf1) == -1) {
			ipqos_msg(MT_ENOSTR,
			    gettext("Cannot lstat lock file %s\n"),
			    IPQOS_CONF_LOCK_FILE);
			return (-1);
		}
		/*
		 * Check whether it is a regular file and not a symbolic
		 * link. Its link count should be 1. The owner should be
		 * root and the file should be empty.
		 */
		if (!S_ISREG(sbuf1.st_mode) ||
		    sbuf1.st_nlink != 1 ||
		    sbuf1.st_uid != 0 ||
		    sbuf1.st_size != 0) {
			ipqos_msg(MT_ERROR, gettext("Bad lock file %s.\n"),
			    IPQOS_CONF_LOCK_FILE);
			return (-1);
		}
		if ((fd = open(IPQOS_CONF_LOCK_FILE, O_CREAT|O_RDWR,
		    S_IRUSR|S_IWUSR)) == -1) {
			ipqos_msg(MT_ENOSTR,
			    gettext("Cannot open lock file %s"),
			    IPQOS_CONF_LOCK_FILE);
			return (-1);
		}

		/* Check whether we opened the file that we lstat()ed. */
		if (fstat(fd, &sbuf2) == -1) {
			ipqos_msg(MT_ENOSTR,
			    gettext("Cannot fstat lock file %s\n"),
			    IPQOS_CONF_LOCK_FILE);
			return (-1);
		}
		if (sbuf1.st_dev != sbuf2.st_dev ||
		    sbuf1.st_ino != sbuf2.st_ino) {
			/* File changed after we did the lstat() above */
			ipqos_msg(MT_ERROR, gettext("Bad lock file %s.\n"),
			    IPQOS_CONF_LOCK_FILE);
			return (-1);
		}
	}
	if (lockf(fd, F_LOCK, 0) == -1) {
		ipqos_msg(MT_ENOSTR, "lockf");
		return (-1);
	}
	return (fd);
}

/*
 * print the current kernel configuration out to stdout. If viewall
 * is set this causes more verbose configuration listing including
 * showing objects we didn't create, each instance of a mhome filter,
 * etc.. see printaction().
 * RETURNS: IPQOS_CONF_ERR on error, else IPQOS_CONF_SUCCES.
 */

static int
viewconf(int viewall)
{

	ipqos_conf_action_t *conf = NULL;
	ipqos_conf_action_t *act;
	int ret;

	IPQOSCDBG0(L0, "In viewconf\n");

	/* get kernel configuration */

	ret = readkconf(&conf);
	if (ret != IPQOS_CONF_SUCCESS) {
		return (IPQOS_CONF_ERR);
	}

	/* write out format version */

	if (conf != NULL) {
		(void) fprintf(stdout, "%s %d.%d\n\n", IPQOS_FMT_VERSION_STR,
		    IPQOS_CUR_FMT_MAJOR_VER, IPQOS_CUR_FMT_MINOR_VER);
	}

	/* print each of the actions in the kernel config to stdout */

	for (act = conf; act != NULL; act = act->next) {
		ret = printaction(stdout, act, viewall, 0);
		if (ret != IPQOS_CONF_SUCCESS) {
			free_actions(conf);
			return (ret);
		}
		(void) fprintf(stdout, "\n");
	}

	free_actions(conf);

	return (IPQOS_CONF_SUCCESS);
}


/*
 * debug function that reads the config file and prints it out after
 * interpreting to stdout.
 */
#ifdef	_IPQOS_CONF_DEBUG
static int
viewcfile(char *cfile)
{

	ipqos_conf_action_t *conf;
	ipqos_conf_action_t *act;
	int res;
	FILE *ifp;
	int viewall = 1;

	IPQOSCDBG0(L0, "In viewcfile\n");
	ifp = fopen(cfile, "r");
	if (ifp == NULL) {
		ipqos_msg(MT_ERROR, gettext("Opening file %s for read: %s.\n"),
		    cfile, strerror(errno));
		return (IPQOS_CONF_ERR);
	}

	res = readconf(ifp, &conf);
	if (res != IPQOS_CONF_SUCCESS) {
		free(ifp);
		return (IPQOS_CONF_ERR);
	}

	/* print each of the actions in the kernel config to stdout */
	for (act = conf; act != NULL; act = act->next) {
		res = printaction(stdout, act, viewall, 0);
		if (res != IPQOS_CONF_SUCCESS) {
			free(ifp);
			return (res);
		}

		(void) fprintf(stdout, "\n");
	}

	(void) fprintf(stdout, "\n");


	return (IPQOS_CONF_SUCCESS);
}
#endif	/* _IPQOS_CONF_DEBUG */

static void
usage(void)
{
	(void) fprintf(stderr, gettext("usage:\n"
	    "\tipqosconf [-sv] -a file|-\n"
	    "\tipqosconf -c\n"
	    "\tipqosconf -l\n"
	    "\tipqosconf -L\n"
	    "\tipqosconf -f\n"));
}

int
main(int argc, char *argv[])
{

	int c;
	char *ifile = NULL;
	int args;
	int ret;
	int cmd;
	int viewall = 0;
	int lfp;

	/* init global flags */
	use_syslog = verbose = 0;

	/* init current line number */
	lineno = 0;

	/* setup internationalisation */

	(void) setlocale(LC_ALL, "");
#if	!defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* setup syslog parameters */
	openlog("ipqosconf", 0, LOG_USER);

	args = 0;

/* enable debug options */

#ifdef	_IPQOS_CONF_DEBUG
#define	DBGOPTS	"rz:"
#else
#define	DBGOPTS
#endif	/* _IPQOS_CONF_DEBUG */

	while ((c = getopt(argc, argv, "sca:vflL" DBGOPTS)) != EOF) {
		switch (c) {
#ifdef	_IPQOS_CONF_DEBUG
			case 'z':
				cmd = -1;
				ifile = optarg;
				if (*ifile == '\0') {
					usage();
					exit(1);
				}
				args++;
				break;
			case 'r':
				force_rback++;
				break;
#endif	/* _IPQOS_CONF_DEBUG */
			case 'c':
				cmd = IPQOS_CONF_COMMIT;
				args++;
				break;
			case 'a':
				cmd = IPQOS_CONF_APPLY;
				ifile = optarg;
				if (*ifile == '\0') {
					usage();
					exit(1);
				}
				args++;
				break;
			case 'f':
				cmd = IPQOS_CONF_FLUSH;
				args++;
				break;
			case 'l':
				cmd = IPQOS_CONF_VIEW;
				args++;
				break;
			case 'L':
				cmd = IPQOS_CONF_VIEW;
				viewall++;
				args++;
				break;
			case 'v':
				verbose++;
				break;
			case 's':
				use_syslog++;
				break;
			case '?':
				usage();
				return (1);
		}
	}

	/*
	 * dissallow non-option args, > 1 cmd args and syslog/verbose flags set
	 * for anything but apply.
	 */
	if (optind != argc || args > 1 ||
	    use_syslog && cmd != IPQOS_CONF_APPLY ||
	    verbose && cmd != IPQOS_CONF_APPLY) {
		usage();
		exit(1);
	}

	/* if no cmd option then show config */

	if (args == 0) {
		cmd = IPQOS_CONF_VIEW;
	}

	/* stop concurrent ipqosconf invocations */
	lfp = lock();
	if (lfp == -1) {
		exit(1);
	}

	switch (cmd) {
#ifdef	_IPQOS_CONF_DEBUG
		case -1:
			ret = viewcfile(ifile);
			break;
#endif	/* _IPQOS_CONF_DEBUG */
		case IPQOS_CONF_APPLY:
			ret = applyconf(ifile);
			break;
		case IPQOS_CONF_COMMIT:
			ret = commitconf();
			break;
		case IPQOS_CONF_VIEW:
			ret = viewconf(viewall);
			break;
		case IPQOS_CONF_FLUSH:
			ret = flushconf();
			break;
	}

	(void) unlock(lfp);

	return (ret);

}
