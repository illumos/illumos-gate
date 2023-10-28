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
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/ddi.h>
#include <stropts.h>
#include <assert.h>
#include <termios.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <auth_attr.h>
#include <auth_list.h>
#include <libdevinfo.h>
#include <secdb.h>
#include <priv.h>
#include <pwd.h>
#include <umem.h>
#include <locale.h>
#include <libintl.h>
#include <dirent.h>
#include <inet/wifi_ioctl.h>

/*
 * Debug information
 */
#ifdef	DEBUG
int wifi_debug = 0;
void wifi_dbgprintf(char *fmt, ...);
#define	PRTDBG(msg) if (wifi_debug > 1) wifi_dbgprintf msg
#else /* DEBUG */
#define	PRTDBG(msg)
#endif /* DEBUG */

#define	MAX_HISTORY_NUM			10
#define	MAX_PREFERENCE_NUM		10
#define	MAX_SCANBUF_LEN			256
#define	MAX_CONFIG_FILE_LENGTH		256
#define	MAX_LOADPF_LENGTH		256
#define	LOADPROFILE_TIMEOUT		10
#define	RECORD_ADD		0
#define	RECORD_DEL		1
/*
 * Wificonfig exit status
 */
#define	WIFI_EXIT_DEF		0
#define	WIFI_FATAL_ERR		1
#define	WIFI_IMPROPER_USE	2
#define	WIFI_MINOR_ERR		3

#define	WIFI_LOCKF "/var/run/lockf_wifi"

typedef enum {
	PREFERENCE,
	HISTORY,
	ACTIVEP,
	PROFILE,
	OTHER
} list_type_t;

#define	WIFI_PREFER	"{preference}"
#define	WIFI_HISTORY	"{history}"
#define	WIFI_ACTIVEP	"{active_profile}"

typedef enum {
	LINKSTATUS = 0,
	BSSID,
	ESSID,
	BSSTYPE,
	CREATEIBSS,
	CHANNEL,
	RATES,
	POWERMODE,
	AUTHMODE,
	ENCRYPTION,
	WEPKEYID,
	WEPKEY,
	SIGNAL,
	RADIOON,
	WLANLIST,
	CONFIG_ITEM_END /* 15 */
} config_item_t;
typedef struct ae {
	struct ae *ae_next;
	char *ae_arg;
}ae_t;
typedef struct aelist {
	int ael_argc;
	ae_t *ael_head, *ael_tail;
	list_type_t type;
}aelist_t;
typedef struct section {
	struct section *section_next;
	aelist_t *list;
	char *section_id;
}section_t;

/*
 * config_file_t is an abstract of configration file,
 * either/etc/inet/wifi/wifi.<interface> or /etc/inet/secret/
 * wifi/wifiwepkey.<interface>
 */
typedef struct config_file {
	int section_argc;
	section_t *section_head, *section_tail;
}config_file_t;

static config_file_t *gp_config_file = NULL;
static config_file_t *gp_wepkey_file = NULL;
static char *p_file_wifi = "/etc/inet/wifi";
static char *p_file_wifiwepkey = "/etc/inet/secret/wifiwepkey";

typedef enum {
	AUTH_WEP = 0,
	AUTH_OTHER = 1
} wifi_auth_t;

static char *p_auth_string[] = {
	WIFI_WEP_AUTH,
	WIFI_CONFIG_AUTH
};

/*
 * gbuf: is a global buf, which is used to communicate between the user and
 * the driver
 */
static wldp_t *gbuf = NULL;
static char *gExecName = NULL;

static void print_error(uint32_t);
static void *safe_malloc(size_t);
static void *safe_calloc(size_t, size_t);
static char *safe_strdup(const char *s1);
static void safe_snprintf(char *s, size_t n,
    const char *format, ...);
static void safe_fclose(FILE *stream);
static void new_ae(aelist_t *ael, const char *arg);
static aelist_t *new_ael(list_type_t type);
static config_file_t *new_config_file();
static void new_section(config_file_t *p_config_file, aelist_t *p_list,
	const char *section_id);
static void destroy_config(config_file_t *p_config_file);
static config_file_t *parse_file(const char *pfile);
static char **aeltoargv(aelist_t *ael, int *ael_num);
static boolean_t fprint_config_file(config_file_t *p_config_file,
	const char *file_name);
static char *append_pa(const char *arg);
static section_t *find_section(config_file_t *p_config_file,
	const char *section_id);
static ae_t *find_ae(aelist_t *plist, const char *arg);
static void update_aelist(aelist_t *plist, const char *arg);
static const char *get_value(const char *arg);
static char *find_active_profile(int);
static const char *essid_of_profile(const char *profile);
static boolean_t search_interface(char *interface);
static int open_dev(char *devname);
static boolean_t call_ioctl(int, int, uint32_t, uint32_t);
static boolean_t del_prefer(config_file_t *p_config_file, const char *prefer,
    boolean_t rflag);
static boolean_t del_section(config_file_t *p_config_file, char *section_id);
static boolean_t set_prefer(config_file_t *p_config_file, const char *prefer,
	int rank);
static void add_to_history(config_file_t *p_config_file,
    int argc, char **argv);
static boolean_t check_authority(wifi_auth_t type);
static void heuristic_load(int fd, uint32_t ess_num, wl_ess_conf_t **);
static char *select_profile(int fd, int readonly, int timeout);
static char *construct_format(uint32_t nt);
static void print_gbuf(config_item_t index);
static boolean_t items_in_profile(aelist_t *, aelist_t *, int, char **);
static char *get_commit_key(int, int, char **);
static void print_wepkey_info(const char *id, const char *wepkeyn);
static void  do_print_usage();
static boolean_t do_print_support_params(int fd);
static boolean_t do_autoconf(int fd, int argc, char **argv);
static boolean_t do_startconf(int fd, int argc, char **argv);
static boolean_t do_loadpf(int fd, int argc, char **argv);
static boolean_t do_disconnect(int fd, int argc, char **argv);
static boolean_t do_printpf(int fd, int argc, char **argv);
static boolean_t do_restoredef(int fd, int argc, char **argv);
static boolean_t do_history(int fd, int argc, char **argv);
static boolean_t do_deletepf(int fd, int argc, char **argv);
static boolean_t do_wepkey(int fd, int argc, char **argv);
static boolean_t do_setprefer(int fd, int argc, char **arg);
static boolean_t do_rmprefer(int fd, int argc, char **argv);
static boolean_t do_lsprefer(int fd, int argc, char **argv);
static boolean_t do_wlanlist(int fd, int argc, char **argv);
static boolean_t do_showstatus(int fd, int argc, char **argv);
static boolean_t do_getprofparam(int fd, int argc, char **argv);
static boolean_t do_setprofparam(int fd, int argc, char **argv);
static boolean_t do_setprofwepkey(int fd, int argc, char **argv);
static boolean_t is_rates_support(int fd, int num, uint8_t *rates);
static boolean_t do_set_bsstype(int fd, const char *arg);
static boolean_t do_set_essid(int fd, const char *arg);
static boolean_t do_set_powermode(int fd, const char *arg);
static boolean_t do_set_rates(int fd, const char *arg);
static boolean_t do_set_channel(int fd, const char *arg);
static boolean_t do_set_createibss(int fd, const char *arg);
static boolean_t do_set_radioon(int fd, const char *arg);
static boolean_t do_set_wepkeyid(int fd, const char *arg);
static boolean_t do_set_encryption(int fd, const char *arg);
static boolean_t do_set_authmode(int fd, const char *arg);
static boolean_t do_set_wepkey(int fd, const char *pbuf);
static boolean_t do_get_createibss(int fd);
static boolean_t do_get_bsstype(int fd);
static boolean_t do_get_essid(int fd);
static boolean_t do_get_bssid(int fd);
static boolean_t do_get_radioon(int fd);
static boolean_t do_get_signal(int fd);
static boolean_t do_get_wepkeyid(int fd);
static boolean_t do_get_encryption(int fd);
static boolean_t do_get_authmode(int fd);
static boolean_t do_get_powermode(int fd);
static boolean_t do_get_rates(int fd);
static boolean_t do_get_wlanlist(int fd);
static boolean_t do_get_linkstatus(int fd);
static boolean_t do_get_channel(int fd);
static boolean_t do_get(int fd, int argc, char **argv);
static boolean_t do_set(int fd, int argc, char **argv);
static boolean_t do_createprofile(int fd, int argc, char **argv);
static boolean_t value_is_valid(config_item_t item, const char *value);

typedef struct cmd_ops {
	char cmd[32];
	boolean_t (*p_do_func)(int fd, int argc, char **argv);
	boolean_t b_auth;
	boolean_t b_fileonly; /* operation only on the config file */
	boolean_t b_readonly; /* only read from the card or config file */
} cmd_ops_t;
static cmd_ops_t do_func[] = {
	{
		"autoconf",
		do_autoconf,
		B_TRUE,
		B_FALSE,
		B_FALSE
	},
	{
		"startconf",
		do_startconf,
		B_TRUE,
		B_FALSE,
		B_TRUE
	},
	{
		"connect",
		do_loadpf,
		B_TRUE,
		B_FALSE,
		B_FALSE
	},
	{
		"disconnect",
		do_disconnect,
		B_TRUE,
		B_FALSE,
		B_FALSE
	},
	{
		"showprofile",
		do_printpf,
		B_FALSE,
		B_TRUE,
		B_TRUE
	},
	{
		"deleteprofile",
		do_deletepf,
		B_TRUE,
		B_TRUE,
		B_FALSE
	},
	{
		"history",
		do_history,
		B_FALSE,
		B_TRUE,
		B_TRUE
	},
	{
		"listprefer",
		do_lsprefer,
		B_FALSE,
		B_TRUE,
		B_TRUE
	},
	{
		"removeprefer",
		do_rmprefer,
		B_TRUE,
		B_TRUE,
		B_FALSE
	},
	{
		"setprefer",
		do_setprefer,
		B_TRUE,
		B_TRUE,
		B_FALSE
	},
	{
		"setwepkey",
		do_wepkey,
		B_TRUE,
		B_FALSE,
		B_FALSE
	},
	{
		"restoredef",
		do_restoredef,
		B_TRUE,
		B_FALSE,
		B_FALSE
	},
	{
		"getparam",
		do_get,
		B_FALSE,
		B_FALSE,
		B_TRUE
	},
	{
		"setparam",
		do_set,
		B_TRUE,
		B_FALSE,
		B_FALSE
	},
	{
		"createprofile",
		do_createprofile,
		B_TRUE,
		B_TRUE,
		B_FALSE
	},
	{
		"scan",
		do_wlanlist,
		B_FALSE,
		B_FALSE,
		B_FALSE
	},
	{
		"showstatus",
		do_showstatus,
		B_FALSE,
		B_FALSE,
		B_TRUE
	},
	{
		"setprofileparam",
		do_setprofparam,
		B_TRUE,
		B_TRUE,
		B_FALSE
	},
	{
		"getprofileparam",
		do_getprofparam,
		B_FALSE,
		B_TRUE,
		B_TRUE
	},
	{
		"setprofilewepkey",
		do_setprofwepkey,
		B_TRUE,
		B_TRUE,
		B_FALSE
	}
};


typedef enum {RW, RO, WO} rw_property_t;
typedef struct gs_ops {
	config_item_t index;
	char cmd[32];
	boolean_t (*p_do_get_func)(int fd);
	boolean_t (*p_do_set_func)(int fd, const char *arg);
	rw_property_t rw;
} gs_ops_t;
static gs_ops_t do_gs_func[] = {
	{LINKSTATUS, "linkstatus", NULL, NULL, RO},
	{BSSID, "bssid", do_get_bssid, NULL, RO},
	{ESSID, "essid", do_get_essid, do_set_essid, RW},
	{BSSTYPE, "bsstype", do_get_bsstype, do_set_bsstype, RW},
	{CREATEIBSS, "createibss", do_get_createibss, do_set_createibss, RW},
	{CHANNEL, "channel", do_get_channel, do_set_channel, RW},
	{RATES, "rates", do_get_rates, do_set_rates, RW},
	{POWERMODE, "powermode", do_get_powermode, do_set_powermode, RW},
	{AUTHMODE, "authmode", do_get_authmode, do_set_authmode, RW},
	{ENCRYPTION, "encryption", do_get_encryption, do_set_encryption, RW},
	{WEPKEYID, "wepkeyindex", do_get_wepkeyid, do_set_wepkeyid, RW},
	{WEPKEY, "wepkey|1-4", NULL, do_set_wepkey, WO},
	{SIGNAL, "signal", do_get_signal, NULL, RO},
	{RADIOON, "radio",	do_get_radioon, do_set_radioon, RW},
};

#define	N_FUNC		sizeof (do_func) / sizeof (cmd_ops_t)
#define	N_GS_FUNC	sizeof (do_gs_func) / sizeof (gs_ops_t)

/*
 * valid rate value
 */
typedef	struct wifi_rates_tab {
	char *rates_s;
	uint8_t rates_i;
	uint8_t rates_reserve0;
	uint8_t rates_reserve1;
	uint8_t rates_reserve2;
} wifi_rates_tab_t;

/*
 * the rates value is in increments of 500kb/s.
 * according to the 802.11 a/b/g specs(IEEE):
 * 802.11b(IEEE Std 802.11b-1999) page35, rates should be:
 *	X02, X04, X0b, X16
 * 802.11a(IEEE Std 802.11a-1999) page47, rates should be:
 *	6,9,12,18,24,36,48,54 Mb/s
 * 802.11g(IEEE Std 802.11g-2003) page44, rates should be:
 *	1,2,5.5,11,6,9,12,18,22,24,33,36,48,54 Mb/s
 */
#define	WIFI_RATES_NUM	14
static wifi_rates_tab_t wifi_rates_s[WIFI_RATES_NUM] = {
	{"1",	WL_RATE_1M,	0,	0,	0},
	{"2",	WL_RATE_2M,	0,	0,	0},
	{"5.5",	WL_RATE_5_5M,	0,	0,	0},
	{"6",	WL_RATE_6M,	0,	0,	0},
	{"9",	WL_RATE_9M,	0,	0,	0},
	{"11",	WL_RATE_11M,	0,	0,	0},
	{"12",	WL_RATE_12M,	0,	0,	0},
	{"18",	WL_RATE_18M,	0,	0,	0},
	{"22",	WL_RATE_22M,	0,	0,	0},
	{"24",	WL_RATE_24M,	0,	0,	0},
	{"33",	WL_RATE_33M,	0,	0,	0},
	{"36",	WL_RATE_36M,	0,	0,	0},
	{"48",	WL_RATE_48M,	0,	0,	0},
	{"54",	WL_RATE_54M,	0,	0,	0}
};
/* print the error message on why set or get ioctl command failed. */
static void
print_error(uint32_t errorno)
{
	char *buf;

	switch (errorno) {
	case WL_SUCCESS:
		buf = gettext("command succeeded");
		break;
	case WL_NOTSUPPORTED:
	case WL_LACK_FEATURE:
	case WL_HW_ERROR:
	case WL_ACCESS_DENIED:
		buf = strerror(errorno);
		break;
	case WL_READONLY:
		buf = gettext("parameter read-only");
		break;
	case WL_WRITEONLY:
		buf = gettext("parameter write-only");
		break;
	case WL_NOAP:
		buf = gettext("no access point available");
		break;
	default:
		buf = gettext("unknown error");
		break;
	}
	(void) fprintf(stderr, "%s\n", buf);
}

static void *
safe_malloc(size_t size)
{
	void *buf;

	buf = malloc(size);
	if (buf == NULL) {
		(void) fprintf(stderr, gettext("%s: malloc: %s\n"),
		    gExecName, strerror(errno));
		exit(WIFI_FATAL_ERR);
	}
	return (buf);
}

static void *
safe_calloc(size_t nelem, size_t elsize)
{
	void *buf;

	buf = calloc(nelem, elsize);
	if (buf == NULL) {
		(void) fprintf(stderr, gettext("%s: calloc: %s\n"),
		    gExecName, strerror(errno));
		exit(WIFI_FATAL_ERR);
	}
	return (buf);
}

static char *
safe_strdup(const char *s1)
{
	char *p;

	p = strdup(s1);
	if (p == NULL) {
		(void) fprintf(stderr, gettext("%s: strdup: %s\n"),
		    gExecName, strerror(errno));
		exit(WIFI_FATAL_ERR);
	}
	return (p);
}

static void
safe_snprintf(char *s, size_t n,  const  char  *format, ...)
{
	int len;
	va_list ap;
	va_start(ap, format);

	len = vsnprintf(s, n, format, ap);
	if ((len <= 0) || (len > n - 1)) {
		(void) fprintf(stderr,
		    gettext("%s: snprintf: %s\n"),
		    gExecName, strerror(errno));
		exit(WIFI_FATAL_ERR);
	}
	va_end(ap);
}

static void
safe_fclose(FILE *stream)
{
	int err;

	err = fclose(stream);
	if (err == EOF) {
		(void) fprintf(stderr, gettext("%s: fclose: %s\n"),
		    gExecName, strerror(errno));
		exit(WIFI_FATAL_ERR);
	}
}
/*
 * new_ae: Add an element with content pointed by arg to the list *ael.
 */
static void
new_ae(aelist_t *ael, const char *arg)
{
	ae_t *pae = NULL;

	PRTDBG(("new_ae(0x%x, \"%s\")\n", ael, arg));
	assert((ael != NULL) && (arg != NULL));

	pae = safe_calloc(sizeof (*pae), 1);
	pae->ae_arg = safe_strdup(arg);
	pae->ae_next = NULL;

	if (ael->ael_tail == NULL) {
		ael->ael_head = pae;
	} else {
		ael->ael_tail->ae_next = pae;
	}
	ael->ael_tail = pae;
	ael->ael_argc++;
}
/*
 * new_ael:  Create a new aelist with list_type "type"
 * and return the list pointer.
 */
static aelist_t *
new_ael(list_type_t type)
{
	aelist_t *plist;

	plist = safe_calloc(sizeof (*plist), 1);
	plist->type = type;
	plist->ael_argc = 0;
	plist->ael_head = plist->ael_tail = NULL;

	PRTDBG(("new_ael(%d) = 0x%x\n", type, plist));
	return (plist);
}

/*
 * new_config_file: Creates a new config_file_t struct which is counterpart of
 * of the configration file, and return the pointer.
 */
static config_file_t *
new_config_file()
{
	config_file_t *p_config_file;

	p_config_file = safe_calloc(sizeof (config_file_t), 1);
	p_config_file->section_argc = 0;
	p_config_file->section_head = p_config_file->section_tail = NULL;

	PRTDBG(("new_config_file() = 0x%x\n", p_config_file));
	return (p_config_file);
}

/*
 * new_section: Add a list pointed by "p_list", with identity "section_id" to
 * the config_file_t struct pointed by "p_config_file"
 */
static void
new_section(config_file_t *p_config_file, aelist_t *p_list,
    const char *section_id)
{
	section_t *p_section = NULL;

	PRTDBG(("new_section(0x%x, 0x%x, \"%s\")\n", p_config_file, p_list,
	    section_id));
	assert((p_config_file != NULL) && (p_list != NULL) &&
	    (section_id != NULL));

	p_section = safe_calloc(sizeof (*p_section), 1);
	p_section->list = p_list;
	p_section->section_next = NULL;
	p_section->section_id = safe_strdup(section_id);

	if (p_config_file->section_tail == NULL) {
		p_config_file->section_head = p_section;
	} else {
		p_config_file->section_tail->section_next = p_section;
	}
	p_config_file->section_tail = p_section;
	p_config_file->section_argc++;
}

/*
 * destroy_config:Destroy the config_file struct
 */
static void
destroy_config(config_file_t *p_config_file)
{
	section_t *p_section = NULL;
	aelist_t *p_list = NULL;
	ae_t *pae = NULL;

	PRTDBG(("destory_config(0x%x)\n", p_config_file));
	assert(p_config_file != NULL);

	p_section = p_config_file->section_head;
	while (p_section != NULL) {
		p_list = p_section->list;
		if (p_list != NULL) {
			pae = p_list->ael_head;
			while (pae != NULL) {
				if (pae->ae_arg != NULL)
					free(pae->ae_arg);
				pae->ae_arg = NULL;
				pae = pae->ae_next;
				free(p_list->ael_head);
				p_list->ael_head = pae;
			}
			free(p_list);
			p_list = NULL;
		}
		if (p_section->section_id != NULL)
			free(p_section->section_id);
		p_section->section_id = NULL;
		p_section = p_section->section_next;
		free(p_config_file->section_head);
		p_config_file->section_head = p_section;
	}
	free(p_config_file);
	p_config_file = NULL;
}

/*
 * parse_file: Parse each section of the configration file
 * and construct the config_file_t structure.
 * Example:
 * A config file has contents below:
 *
 * {preferrence}
 * essid=ap7-3
 * essid=linksys
 *
 * {history}
 * essid=ap7-3
 * essid=ap7-2
 *
 * [ap7-3]
 * essid=ap7-3
 * wepkeyid=3
 * channel=11
 * rates=1,2
 *
 * [linksys]
 * essid=linksys
 * createibss=BSS
 * authmode=OPENSYSTEM
 * wepkeyid=1
 *
 * then its config_file_t structure will be:
 *
 *                        config_file_t
 *                       |~~~~~~~~~~~~~~~~~~~~~~~~~~|
 *                       |      section_argc=5      |
 *                       |~~~~~~~~~~~~T~~~~~~~~~~~~~|
 *                      /|   *head    |    *tail    |\
 *                     / ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \
 *                    /                                \
 *                   /	                                \
 *                  /                                    \
 *                 /                                      \
 *                /                                        \
 *  section_t    V           section_t                      V section_t
 * |~~~~~~~~~~~~~~~|~~|     |~~~~~~~~~~~~~~~|~~|      |~~~~~~~~~~~~~~|~~|
 * |"{preferrence}"|  |     |  "{history}"  |  |      | "[linksys]"  |  |
 * |~~~~~~~~~~~~~~~| -+---->|~~~~~~~~~~~~~~~| -+->..->|~~~~~~~~~~~~~~| -+->NULL
 * |    *list      |  |     |    *list      |  |      |    *list     |  |
 * ~~T~~~~~~~~~~~~~~~~~     ~~~T~~~~~~~~~~~~~~~~      ~~~T~~~~~~~~~~~~~~~
 *   |                         |                         |
 *   |                         |                         |
 *   V aelist_t                V aelist_t                V aelist_t
 * |~~~~~~~~~~~~~|          |~~~~~~~~~~~~~|           |~~~~~~~~~~~~~|
 * |  argc=2     |          |  argc=3     |           |  argc=4     |
 * |~~~~~~~~~~~~~|          |~~~~~~~~~~~~~|           |~~~~~~~~~~~~~|
 * |PREFFERRENCE |          |   HISTORY   |           |   PROFILE   |
 * |~~~~~~T~~~~~~|          |~~~~~~T~~~~~~|           |~~~~~~T~~~~~~|
 * |*head |*tail |\         |*head |*tail |\          |*head |*tail |
 * ~~T~~~~~~~~~~~~ \        ~~T~~~~~~~~~~~~ \        /~~~~~~~~~~~~~~~\
 *   |              \         V              V      /                 \
 *   |               \        ...            ...   /                   \
 *   V ae_t           V  ae_t             ae_t    V           ae_t      V
 * |~~~~~~~~~T~~|  |~~~~~~~~~T~~|       |~~~~~~~~~T~~|      |~~~~~~~~~T~~|
 * |"essid=  | -+->|"essid=  | -+->NULL |"essid=  | -+->..->|"wepkeyid| -+->NULL
 * | ap7-3"  |  |  | linksys"|  |       | linksys"|  |      | =1"     |  |
 * ~~~~~~~~~~~~~~  ~~~~~~~~~~~~~~       ~~~~~~~~~~~~~~      ~~~~~~~~~~~~~~
 *
 */

static config_file_t *
parse_file(const char *pfile)
{
	FILE *file = NULL;
	int fd = 0;
	char buf_line[256];
	config_file_t *p_config_file;
	list_type_t cur_list = OTHER;
	aelist_t *prefer_list = NULL;
	aelist_t *history_list = NULL;
	aelist_t *profile_list = NULL;
	aelist_t *activep_list = NULL;

	assert(pfile != NULL);
	/*
	 * The files /etc/inet/wifi and /etc/inet/secret/wifiwepkey should
	 * be opened with "r" attribute. If these two files do not exist,
	 * create them here.
	 */
	file = fopen(pfile, "r");

	if (file == NULL) {
		fd = open(pfile, O_CREAT|O_EXCL|O_RDWR, 0600);
		if (fd < 0) {
			(void) fprintf(stderr, gettext("%s: failed to open %s"
			    "\n"), gExecName, pfile);
			goto error1;
		}
		file = fdopen(fd, "w");
		(void) chmod(pfile, S_IRUSR);
	}

	p_config_file = new_config_file();

	while (fgets(buf_line, sizeof (buf_line), file) != NULL) {
		if ((buf_line[0] == '\n') || (buf_line[0] == ' '))
			continue;
		/* replace the old '\n' to '\0' */
		buf_line[strlen(buf_line) - 1] = '\0';
		if (strstr(buf_line, WIFI_PREFER) == buf_line) {
			if (prefer_list == NULL) {
				cur_list = PREFERENCE;
				prefer_list = new_ael(PREFERENCE);
				new_section(p_config_file, prefer_list,
				    WIFI_PREFER);
			} else {
				(void) fprintf(stderr, gettext("%s: "
				    "%s : duplicated %s section\n"),
				    gExecName, pfile, WIFI_PREFER);
				goto error;
			}
		} else if (strstr(buf_line, WIFI_HISTORY) == buf_line) {
			if (history_list == NULL) {
				cur_list = HISTORY;
				history_list = new_ael(HISTORY);
				new_section(p_config_file, history_list,
				    WIFI_HISTORY);
			} else {
				(void) fprintf(stderr, gettext("%s: "
				    "%s : duplicated %s section\n"),
				    gExecName, pfile, WIFI_HISTORY);
				goto error;
			}
		} else if (strstr(buf_line, WIFI_ACTIVEP) == buf_line) {
			if (activep_list == NULL) {
				cur_list = ACTIVEP;
				activep_list = new_ael(ACTIVEP);
				new_section(p_config_file, activep_list,
				    WIFI_ACTIVEP);
			} else {
				(void) fprintf(stderr, gettext("%s: "
				    "%s : duplicated %s section\n"),
				    gExecName, pfile, WIFI_ACTIVEP);
				goto error;
			}
		} else if ((strchr(buf_line, '[') == buf_line) &&
		    (buf_line[strlen(buf_line) - 1] == ']')) {
			cur_list = PROFILE;
			profile_list = new_ael(PROFILE);
			new_section(p_config_file, profile_list,
			    buf_line);
		} else {
			switch (cur_list) {
			case PREFERENCE:
				if (prefer_list->ael_argc <=
				    MAX_PREFERENCE_NUM)
					new_ae(prefer_list, buf_line);
				break;
			case HISTORY:
				if (history_list->ael_argc <=
				    MAX_HISTORY_NUM)
					new_ae(history_list, buf_line);
				break;
			case ACTIVEP:
				if ((activep_list->ael_argc <= 1) &&
				    (strpbrk(buf_line, "=") != NULL))
					new_ae(activep_list, buf_line);
				break;
			case PROFILE:
				if (strpbrk(buf_line, "=") != NULL)
					new_ae(profile_list, buf_line);
				break;
			default:
				(void) fprintf(stderr,
				    gettext("%s: %s: file format error\n"),
				    gExecName, pfile);
				goto error;
			}
		}
	}
	PRTDBG(("parse_file(\"%s\")=0x%x\n", pfile, p_config_file));
	(void) fclose(file);
	return (p_config_file);
error:
	destroy_config(p_config_file);
	(void) fclose(file);
error1:
	return (NULL);
}
/*
 * construct an argument vector from an aelist
 */
static char **
aeltoargv(aelist_t *ael, int *ael_num)
{
	ae_t *ae = NULL;
	char **argv = NULL;
	int argc = 0;

	PRTDBG(("aeltoargv(%x)\n", ael));
	assert(ael != NULL);

	argv = safe_calloc(sizeof (*argv), ael->ael_argc);

	for (argc = 0, ae = ael->ael_head; ae; ae = ae->ae_next) {
		/* skip bssid since it can not be set */
		if (strncmp(ae->ae_arg, "bssid=", strlen("bssid=")) == 0)
			continue;
		argv[argc] = safe_strdup(ae->ae_arg);
		argc++;
		if (ae == ael->ael_tail)
			break;
	}

	PRTDBG(("aeltoargv(0x%x) = 0x%x\n\n", ael, argv));
	*ael_num = argc;
	return (argv);
}

/*
 * archived contents into a file
 */
static boolean_t
fprint_config_file(config_file_t *p_config_file, const char *file_name)
{
	FILE *file = NULL;
	int fd = 0;
	int len;
	section_t *p_section = NULL;
	aelist_t *p_list = NULL;
	ae_t *pae = NULL;
	char temp_file[256];
	struct stat buf;

	PRTDBG(("fprint_config_file(0x%x, \"%s\")\n", p_config_file,
	    file_name));
	assert((p_config_file != NULL)&&(strcmp(file_name, "") != 0));

	safe_snprintf(temp_file, sizeof (temp_file),
	    "%s.tmp", file_name);
	fd = open(temp_file, O_CREAT|O_WRONLY|O_TRUNC, 0600);
	if (fd < 0) {
		(void) fprintf(stderr, gettext("%s: failed to open %s\n"),
		    gExecName, temp_file);
		return (B_FALSE);
	}
	file = fdopen(fd, "w");

	p_section = p_config_file->section_head;
	while (p_section != NULL) {
		p_list = p_section->list;
		if (p_list != NULL) {
			PRTDBG(("fprint_config_file: section_id=%s\n",
			    p_section->section_id));
			len = fprintf(file, "\n%s\n", p_section->section_id);
			if (len < 0) {
				(void) fprintf(stderr, gettext("%s: "
				    "failed to update %s: %s\n"),
				    gExecName, file_name, strerror(errno));
				safe_fclose(file);
				return (B_FALSE);
			}
			pae = p_list->ael_head;
			while (pae != NULL) {
				if (pae->ae_arg != NULL) {
					len = fprintf(file, "%s\n",
					    pae->ae_arg);
					if (len < 0) {
						(void) fprintf(stderr,
						    gettext("%s: failed to "
						    "update %s: %s\n"),
						    gExecName, file_name,
						    strerror(errno));
						safe_fclose(file);
						return (B_FALSE);
					}
				}
				pae = pae->ae_next;
			}
		}
		p_section = p_section->section_next;
	}
	safe_fclose(file);
	/*
	 * The attribute of the file /etc/inet/wifi and
	 * /etc/inet/security/wifiwepkey should be retained.
	 * if those file do not exist, set default file mode.
	 */
	if (stat(file_name, &buf) != 0) {
		if (errno == ENOENT) {
			buf.st_mode = 0600;
		} else {
			(void) fprintf(stderr, gettext("%s: failed to get "
			    "file %s stat: %s\n"),
			    gExecName, file_name, strerror(errno));
			return (B_FALSE);
		}
	}
	if (rename(temp_file, file_name) != 0) {
		(void) fprintf(stderr, gettext("%s: failed to update %s: %s"
		    "\n"), gExecName, file_name, strerror(errno));
		return (B_FALSE);
	}
	(void) chmod(file_name, buf.st_mode);
	return (B_TRUE);
}
/*
 * append_pa: Each section holds a section_id which identifies a section
 * a profile uses its essid appending "[]" to denote its section_id.
 * note: new memory is allocated, remember to free.
 */
static char *
append_pa(const char *arg)
{
	char *pbuf = NULL;
	int len;

	assert(arg != NULL);

	len = strlen(arg) + 3;
	pbuf = safe_malloc(len);
	safe_snprintf(pbuf, len, "[%s]", arg);
	PRTDBG(("append_pa(\"%s\") = \"%s\"\n", arg, pbuf));
	return (pbuf);
}
/*
 * find a section by section_id from p_config_file,
 * return the section pointer.
 */
static section_t *
find_section(config_file_t *p_config_file, const char *section_id)
{
	section_t *p_section = NULL;

	PRTDBG(("find_section(0x%x, \"%s\")\n", p_config_file, section_id));
	assert((section_id != NULL)&&(p_config_file != NULL));

	p_section = p_config_file->section_head;

	while (p_section != NULL) {
		if ((p_section->section_id != NULL) &&
		    (strcmp(p_section->section_id, section_id) == 0))
			return (p_section);
		p_section = p_section->section_next;
	}
	return (NULL);
}

/*
 * get_value: Get rid of "parameter=" from a "parameter=value", for example:
 * when we read an line from file, we gets "essid=ap7-2", this function
 * returns the pointer to string "ap7-2";
 */

static const char *
get_value(const char *arg)
{
	char *p;
	assert(arg != NULL);

	p = strchr(arg, '=');
	PRTDBG(("get_value(\"%s\") = \"%s\"\n", arg, p + 1));
	if (p != NULL)
		return (p + 1);
	else
		return (NULL);
}

/*
 * search /dev/wifi to see which interface is available
 */
static boolean_t
search_interface(char *interface)
{
	DIR *dirp;
	struct dirent *dp;
	char buf[256];
	int fd;

	PRTDBG(("search interface\n"));
	assert(interface != NULL);

	/*
	 * Try to return the first found wifi interface.
	 * If no wifi interface is available, return B_FALSE
	 */

	if ((dirp = opendir("/dev/wifi")) == NULL) {
		PRTDBG(("failed to open '/dev/wifi'\n"));
		return (B_FALSE);
	}
	while ((dp = readdir(dirp)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;
		if (dp->d_name[strlen(dp->d_name) - 1] < '0' ||
		    dp->d_name[strlen(dp->d_name) - 1] > '9')
			continue;
		safe_snprintf(buf, sizeof (buf), "%s%s",
		    "/dev/wifi/", dp->d_name);
		fd = open(buf, O_RDWR);
		if (fd == -1) {
			PRTDBG(("interface %s doesn't exist\n", dp->d_name));
			continue;
		} else {
			PRTDBG(("interface %s is the first found interface\n",
			    dp->d_name));
			(void) strlcpy(interface, buf, LIFNAMSIZ);
			(void) close(fd);
			(void) closedir(dirp);
			return (B_TRUE);
		}
	}

	PRTDBG(("failed to find available wireless interface\n"));
	(void) closedir(dirp);
	return (B_FALSE);

}
/*
 * open_dev: Open the driver.
 * if the 'devname' has format like 'ath0', we should add the path to that
 * device(/dev/ath0) and open it; if the 'devname' has format like
 * '/dev/wifi/ath0', we open it directly.
 */
static int
open_dev(char *devname)
{
	int fd;
	int len;
	char *pbuf = NULL;

	PRTDBG(("open_dev(\"%s\")\n", devname));
	assert(devname != NULL);
	/*
	 * If the devname is got from the user input, we
	 * add '/dev/' to that relative devname. If it
	 * is got from the 'search interface', it is an
	 * absolute path.
	 */
	if (strncmp(devname, "/dev/wifi/", strlen("/dev/wifi/")) == 0) {
		pbuf = safe_strdup(devname);
	} else {
		len = strlen(devname) + strlen("/dev/") + 1;
		pbuf = safe_malloc(len);
		safe_snprintf(pbuf, len, "/dev/%s", devname);
	}
	fd = open(pbuf, O_RDWR);
	free(pbuf);

	if (fd == -1) {
		(void) fprintf(stderr, gettext("%s: failed to open '%s': %s"
		    "\n"), gExecName, devname, strerror(errno));
		return (-1);
	}
	if (!isastream(fd)) {
		(void) fprintf(stderr, gettext("%s: %s is "
		    "not a stream device\n"),
		    gExecName, devname);
		(void) close(fd);
		return (-1);
	}
	return (fd);
}
/*
 * call_ioctl: Fill strioctl structure and issue an ioctl system call
 */
static boolean_t
call_ioctl(int fd, int cmd, uint32_t params, uint32_t buf_len)
{
	struct strioctl stri;

	PRTDBG(("call_ioctl_gs(%d, 0x%x, 0x%x, 0x%x)\n",
	    fd, cmd, params, buf_len));

	switch (cmd) {
	case WLAN_GET_PARAM:
		(void) memset(gbuf, 0, MAX_BUF_LEN);
		stri.ic_len = MAX_BUF_LEN;
		break;
	case WLAN_SET_PARAM:
		gbuf->wldp_length = buf_len + WIFI_BUF_OFFSET;
		stri.ic_len = gbuf->wldp_length;
		break;
	case WLAN_COMMAND:
		gbuf->wldp_length = sizeof (wldp_t);
		stri.ic_len = gbuf->wldp_length;
		break;
	default:
		(void) fprintf(stderr, gettext("%s: ioctl : "
		    "unsupported ioctl command\n"), gExecName);
		return (B_FALSE);
	}
	gbuf->wldp_type = NET_802_11;
	gbuf->wldp_id = params;

	stri.ic_cmd = cmd;
	stri.ic_timout = 0;
	stri.ic_dp = (char *)gbuf;

	if (ioctl(fd, I_STR, &stri) == -1) {
		gbuf->wldp_result = 0xffff;
		return (B_FALSE);
	}
	if (cmd == WLAN_COMMAND) {
		return (B_TRUE);
	} else {
		return (gbuf->wldp_result != WL_SUCCESS ?
		    B_FALSE:B_TRUE);
	}
}

/*
 * del_prefer: Delete an item from the {preferrence} list, the idea is
 * simply free the ae_t element, and set ae_arg to NULL, then when archive
 * the config_file_t struct to the file, it will be delete.
 * The last flag is used to identify whether this function is invoked due to
 * the 'removeprefer' subcommand or due to 'deleteprofile' subcommand.
 */
static boolean_t
del_prefer(config_file_t *p_config_file, const char *prefer, boolean_t rflag)
{
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	int i = 0, position = 0;
	int number;
	ae_t *prm_ae = NULL;

	PRTDBG(("del_prefer(0x%x, \"%s\")\n", p_config_file, prefer));
	assert((prefer != NULL)&&(p_config_file != NULL));

	p_section = find_section(p_config_file, WIFI_PREFER);
	if (p_section != NULL)
		plist = p_section->list;

	if ((p_section == NULL) || (plist == NULL))
		return (B_FALSE);

	number = plist->ael_argc;
	pae = plist->ael_head;
	prm_ae = plist->ael_head;
	while (pae != NULL) {
		if (strcmp(prefer, pae->ae_arg) == 0) {
			free(pae->ae_arg);
			pae->ae_arg = NULL; /* mark */
			if (!position) {
				plist->ael_head = pae->ae_next;
				if (pae->ae_next == NULL)
					plist->ael_tail = NULL;
			} else {
				for (i = 0; i < position - 1; i++)
					prm_ae = prm_ae->ae_next;
				prm_ae->ae_next = pae->ae_next;
				if (pae->ae_next == NULL)
					plist->ael_tail = prm_ae;
			}
			free(pae);
			pae = NULL;
			plist->ael_argc--;
			break;
		}
		position++;
		pae = pae->ae_next;
	}
	if ((number == plist->ael_argc) && (rflag == B_TRUE)) {
		(void) fprintf(stderr, gettext("%s: removeprefer : "
		    "no such profile: '%s' in the preference list\n"),
		    gExecName, prefer);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * del_section: Delete an section from p_config_file, the idea is
 * simply free the aelist_t struct and set it to NULL, when archiving
 * config_file_t struct to the file, we will find section list is NULL,
 * and will not write it to file, so it will be deleted.
 */
static boolean_t
del_section(config_file_t *p_config_file, char *section_id)
{
	section_t *p_section = NULL;
	section_t *prm_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	int i = 0, position = 0;

	PRTDBG(("del_section(0x%x, \"%s\")\n", p_config_file, section_id));
	PRTDBG(("del_section: %d section(s) in config file\n",
	    p_config_file->section_argc));
	assert((section_id != NULL)&&(p_config_file != NULL));

	if (find_section(p_config_file, section_id) == NULL) {
		return (B_FALSE);
	}
	p_section = p_config_file->section_head;
	prm_section = p_config_file->section_head;
	while (p_section != NULL) {
		if (p_section->section_id != NULL) {
			if (strcmp(p_section->section_id, section_id) == 0) {
				plist = p_section->list;
				pae = plist->ael_head;
				while (pae != NULL) {
					free(pae->ae_arg);
					pae->ae_arg = NULL;
					pae = pae->ae_next;
					free(plist->ael_head);
					plist->ael_head = pae;
				}
				free(plist);
				p_section->list = NULL;
				free(p_section->section_id);
				p_section->section_id = NULL;

				if (!position) {
					p_config_file->section_head =
					    p_section->section_next;
					if (p_section->section_next == NULL)
						p_config_file->section_tail =
						    NULL;
				} else {
					for (i = 0; i < position - 1; i++) {
						prm_section =
						    prm_section->section_next;
					}
					prm_section->section_next =
					    p_section->section_next;
					if (p_section->section_next == NULL)
						p_config_file->section_tail =
						    prm_section;
				}
				free(p_section);
				p_config_file->section_argc--;
				break;
			}
			position++;
		}
		p_section = p_section->section_next;
	}
	return (B_TRUE);
}

/*
 * set_prefer: Reorder the preferrence list.
 */
static boolean_t
set_prefer(config_file_t *p_config_file, const char *prefer, int rank)
{
	char *pbuf = NULL;
	aelist_t *plist = NULL;
	section_t *p_section = NULL;
	ae_t *pae = NULL;
	int i = 0, position = 0;
	ae_t *pae_move = NULL;

	assert(prefer != NULL);
	PRTDBG(("set_prefer(0x%x, \"%s\", %d)\n", p_config_file, prefer, rank));

	pbuf = append_pa(prefer);
	if (find_section(p_config_file, pbuf) == NULL) {
		(void) fprintf(stderr, gettext("%s: setprefer: "
		    "no such profile: '%s'\n"),
		    gExecName, prefer);
		free(pbuf);
		return (B_FALSE);
	}
	free(pbuf);

	p_section = find_section(p_config_file, WIFI_PREFER);

	if (p_section == NULL) {
		plist = new_ael(PREFERENCE);
		new_section(p_config_file, plist, WIFI_PREFER);
		new_ae(plist, prefer);
		return (B_TRUE);
	} else {
		plist = p_section->list;
	}

	pae = plist->ael_head;
	pae_move = plist->ael_head;
	while (pae != NULL) {
		if (strcmp(prefer, pae->ae_arg) == 0) {
			free(pae->ae_arg);
			pae->ae_arg = NULL;
			if (!position) {
				plist->ael_head = pae->ae_next;
				if (pae->ae_next == NULL)
					plist->ael_tail = NULL;
			} else {
				for (i = 0; i < position - 1; i++)
					pae_move = pae_move->ae_next;
				pae_move->ae_next = pae->ae_next;
				if (pae->ae_next == NULL)
					plist->ael_tail = pae_move;
			}
			free(pae);
			plist->ael_argc--;
			break;
		}
		position++;
		pae = pae->ae_next;
	}
	PRTDBG(("set_prefer: %d Profiles in prefer list\n", plist->ael_argc));
	if (rank > plist->ael_argc) {
		new_ae(plist, prefer);
	} else if (rank <= 1) {
		pae = safe_calloc(sizeof (ae_t), 1);
		pae->ae_arg = safe_strdup(prefer);
		pae->ae_next = plist->ael_head;
		plist->ael_head = pae;
		plist->ael_argc++;
	} else {
		pae_move = plist->ael_head;
		for (i = 1; i < rank-1; i++) {
			pae_move = pae_move->ae_next;
		}
		pae = safe_calloc(sizeof (ae_t), 1);
		pae->ae_arg = safe_strdup(prefer);
		pae->ae_next = pae_move->ae_next;
		pae_move->ae_next = pae;
		plist->ael_argc++;
	}
	/*
	 * If number of prefer list items is larger than the MAX_PREFERENCE_NUM
	 * delete those items whose No is larger than MAX_PREFERENCE_NUM.
	 */
	if (plist->ael_argc > MAX_PREFERENCE_NUM) {
		pae = plist->ael_head;
		while (pae->ae_next != plist->ael_tail)
			pae = pae->ae_next;
		free(plist->ael_tail->ae_arg);
		plist->ael_tail->ae_arg = NULL;
		free(plist->ael_tail);
		plist->ael_tail = pae;
		plist->ael_tail->ae_next = NULL;
		plist->ael_argc--;
	}
	PRTDBG(("set_prefer: %d Profiles in prefer list\n", plist->ael_argc));
	return (B_TRUE);
}
/*
 * add_to_history: Save the scanlist argv into history section
 */
static void
add_to_history(config_file_t *p_config_file, int argc, char **argv)
{
	int i = 0, j = 0, pos = 0;
	aelist_t *plist = NULL;
	section_t *p_section = NULL;
	ae_t *pae = NULL;
	ae_t *pae_m = NULL;
	char item[256];
	time_t cltime;

	PRTDBG(("add_to_history(0x%x, %d, 0x%x)\n", p_config_file, argc, argv));
	assert(p_config_file != NULL);

	p_section = find_section(p_config_file, WIFI_HISTORY);

	if (p_section == NULL) {
		plist = new_ael(HISTORY);
		new_section(p_config_file, plist, WIFI_HISTORY);
	} else {
		plist = p_section->list;
	}

	if (plist != NULL) {
		for (i = 0; i < argc; i++) {
			if (!strlen(argv[i]))
				continue;
			pos = 0;
			pae = plist->ael_head;
			pae_m = plist->ael_head;
			/*
			 * add time stamp to the history record
			 */
			cltime = time(&cltime);
			(void) snprintf(item, sizeof (item), "%s%c%ld",
			    argv[i], ',', cltime);
			while (pae != NULL) {
				if (strncmp(item, pae->ae_arg,
				    strlen(argv[i])) == 0) {
					free(pae->ae_arg);
					pae->ae_arg = NULL;
					if (!pos) {
						plist->ael_head = pae->ae_next;
						if (pae->ae_next == NULL)
							plist->ael_tail = NULL;
					} else {
						for (j = 0; j < pos - 1; j++)
							pae_m = pae_m->ae_next;
						pae_m->ae_next = pae->ae_next;
						if (pae->ae_next == NULL)
							plist->ael_tail = pae_m;
					}
					free(pae);
					plist->ael_argc--;
					break;
				}
				pos++;
				pae = pae->ae_next;
			}
			new_ae(plist, item);
		}

		if (plist->ael_argc > MAX_HISTORY_NUM) {
			for (i = 0; i < plist->ael_argc - MAX_HISTORY_NUM;
			    i++) {
				pae = plist->ael_head;
				free(pae->ae_arg);
				plist->ael_head = pae->ae_next;
				free(pae);
			}
			plist->ael_argc = MAX_HISTORY_NUM;
		}
	}
}

static void
do_print_usage()
{
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " autoconf [wait={n|forever}]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " connect profile [wait={n|forever}]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " connect essid [wait={n|forever}]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " disconnect\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " getparam [parameter [...]]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " setparam [parameter=value [...]]\n"), gExecName);
	(void) fprintf(stderr, gettext(
	    "\tparameters:\n"
	    "\t\tbssid\t\t - read only: 6 byte mac address of "
	    "base station\n"
	    "\t\tessid\t\t - name of the network, a string of up "
	    "to 32 chars\n"
	    "\t\tbsstype\t\t - bss(ap, infrastructure), ibss(ad-hoc)"
	    " or auto\n"
	    "\t\tcreateibss\t - flag to identify whether a ibss is to be\n"
	    "\t\t\t\t   created when the network to connect is\n"
	    "\t\t\t\t   not available, yes or no\n"
	    "\t\tchannel\t\t - channel(used only when creating an ibss)\n"
	    "\t\t\t\t   valid value:\n"
	    "\t\t\t\t\t 802.11a: 0-99\n"
	    "\t\t\t\t\t 802.11b: 1-14\n"
	    "\t\t\t\t\t 802.11g: 1-14\n"
	    "\t\trates\t\t - set of rates, seperated by ',' valid rates:\n"
	    "\t\t\t\t   1,2,5.5,6,9,11,12,18,22,24,33,36,48 and 54\n"
	    "\t\tpowermode\t - off, mps or fast\n"
	    "\t\tauthmode\t - opensystem or shared_key\n"
	    "\t\tencryption\t - none or wep\n"
	    "\t\twepkey|1-4\t - write only:\n"
	    "\t\t\t\t   5 chars or 10 hex digits for 40bit wepkey;\n"
	    "\t\t\t\t   13 chars or 26 hex digits for 128bit wepkey\n"
	    "\t\twepkeyindex\t - an integer within the range 1-4\n"
	    "\t\tsignal\t\t - read only: signal strength from 0 to 15\n"
	    "\t\tradio\t\t - on or off\n"));
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " restoredef\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " scan\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " showstatus\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path][-i interface]"
	    " setwepkey 1|2|3|4\n"), gExecName);

	(void) fprintf(stderr, "\n");

	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " createprofile profile parameter=value [...]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " deleteprofile profile1 [profile2 [...]]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " showprofile profile1 [profile2 [...]]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " setprofilewepkey profile 1|2|3|4\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " getprofileparam profile [parameter [...]]\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " setprofileparam profile [parameter=value [...]]\n"), gExecName);

	(void) fprintf(stderr, "\n");

	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " history\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " listprefer\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " removeprefer profile\n"), gExecName);
	(void) fprintf(stderr, gettext("\t%s [-R root_path]"
	    " setprefer profile [n]\n"), gExecName);
}

/*
 * do_print_support_params: Query interface which cmd is supported
 */
static boolean_t
do_print_support_params(int fd)
{
	int i = 0, n = 0;

	PRTDBG(("do_print_support_params(\"%d\")\n", fd));
	assert(fd != -1);

	(void) printf(gettext("\t  parameter\tproperty\n"));
	for (i = 0; i < N_GS_FUNC; i++) {
		gbuf->wldp_result = WL_LACK_FEATURE;
		if ((do_gs_func[i].p_do_get_func != NULL) &&
		    (do_gs_func[i].p_do_get_func(fd) != B_TRUE)) {
				continue;
		}
		if (gbuf->wldp_result == WL_SUCCESS) {
			(void) printf("\t%11s", do_gs_func[i].cmd);
			if (do_gs_func[i].rw == RO)
				(void) printf(gettext("\tread only\n"));
			else
				(void) printf(gettext("\tread/write\n"));
			n++;
		}
	}

	return (n ? B_TRUE : B_FALSE);
}

/*
 * check_authority: Check if command is permitted.
 */
static boolean_t
check_authority(wifi_auth_t type)
{
	struct passwd *pw = NULL;

	PRTDBG(("check_authority()\n"));

	pw = getpwuid(getuid());
	if (pw == NULL)
		return (B_FALSE);
	if (chkauthattr(p_auth_string[type], pw->pw_name) == 0) {
		if (type == AUTH_WEP)
			(void) fprintf(stderr, gettext("%s: "
			    "privilege '%s' is required for setting "
			    "wepkey.\n"), gExecName, WIFI_WEP_AUTH);
		else
			(void) fprintf(stderr, gettext("%s: "
			    "privilege '%s' is required.\n"),
			    gExecName, WIFI_CONFIG_AUTH);
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

/*
 * construct the 'history' and 'scan' output format
 * memory allocated. need to free after the function is invoked.
 */
static char *
construct_format(uint32_t nt)
{
	char *format;
	int len = 0, i;

#define	FORMAT_LEN 256
	assert((nt >= 1) && (nt <= 4));
	format = safe_malloc(FORMAT_LEN);

	for (i = 0; i < nt; i++)
		len += snprintf(format + len, FORMAT_LEN - len, "\t");
	if ((len <= 0) || (len > FORMAT_LEN - 1)) {
		return ("\t\t\t\t");
	}
	return (format);
}

/*
 * find the essid of the named profile.
 * gp_config_file is golable, so the return is gloable too.
 */
static const char *
essid_of_profile(const char *profile)
{
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	char *pbuf;

	PRTDBG(("essid_of_profile: profile = %s\n", profile));
	pbuf = append_pa(profile);
	p_section = find_section(gp_config_file, pbuf);
	free(pbuf);

	if (p_section == NULL) {
		return (NULL);
	} else {
		plist = p_section->list;
	}
	pae = plist->ael_head;
	while (pae != NULL) {
		if (strncmp(pae->ae_arg, "essid=", strlen("essid=")) == 0) {
			PRTDBG(("essid_of_profile: essid = %s\n",
			    pae->ae_arg));
			return (get_value(pae->ae_arg));
		}
		pae = pae->ae_next;
	}
	return (NULL);
}

/*
 * If we don't know which profile is our favorate in 'autoconf',
 * we select the wifi network based on the following heuristic
 * 1. the network without wep.
 * 2. the network with the strongst signal.
 * 3. the network with the faster speed(not implemented since signal affects
 * the speed in some degree).
 */
static void
heuristic_load(int fd, uint32_t ess_num, wl_ess_conf_t **p_ess_conf)
{
	int i = 0;
	char *flag = NULL;
	int have_nowep_wlan = 0;
	wl_rssi_t maxsignal = 0;
	char essid[34];
	int timeout = LOADPROFILE_TIMEOUT;

	PRTDBG(("heuristic_load: enter\n"));
	(void) call_ioctl(fd, WLAN_COMMAND, WL_LOAD_DEFAULTS, 0);
	flag = calloc(sizeof (char), ess_num);
	for (i = 0; i < ess_num; i++) { /* extract none-wep network */
		if (p_ess_conf[i]->wl_ess_conf_wepenabled == B_FALSE) {
			flag[i] = 1;
			have_nowep_wlan = 1;
		}
	}
	/*
	 * if all the wlans are weped, we select the one with strongest signal
	 * in all of them, otherwise we just select in the none weped ones.
	 */
	if (!have_nowep_wlan)
		(void) memset(flag, 1, ess_num);
	for (i = 0; i < ess_num; i++) { /* extract the strongest signal ones */
		if (flag[i] == 1) {
			if (p_ess_conf[i]->wl_ess_conf_sl > maxsignal) {
				maxsignal = p_ess_conf[i]->wl_ess_conf_sl;
				(void) memset(flag, 0, i);
			} else if (p_ess_conf[i]->wl_ess_conf_sl == maxsignal)
				continue;
			else
				flag[i] = 0;
		}
	}
	for (i = 0; i < ess_num; i++) {
		if (flag[i] == 1)
			break;
	}
	free(flag);
	PRTDBG(("heuristic_load: %s is selected\n",
	    p_ess_conf[i]->wl_ess_conf_essid.wl_essid_essid));
	/* select one in all the networks which meet the preceding stardands */
	if (i == ess_num)
		(void) do_set_essid(fd, "");
	else
		(void) do_set_essid(fd,
		    p_ess_conf[i]->wl_ess_conf_essid.wl_essid_essid);

	if ((ess_num == 0) || (do_get_essid(fd) == B_FALSE)) {
		(void) fprintf(stderr, gettext("%s: autoconf:"
		    " failed to connect to any essid\n"),
		    gExecName);
		exit(WIFI_MINOR_ERR);
	}
	(void) strlcpy(essid, ((wl_essid_t *)(gbuf->wldp_buf))->wl_essid_essid,
	    sizeof (essid));
	(void) printf(gettext("%s: autoconf: essid '%s' is selected%s\n"),
	    gExecName, essid,
	    have_nowep_wlan ? "" : ": this is a WEPed "
	    "access point");

	if (!have_nowep_wlan)
		exit(WIFI_FATAL_ERR);

	while (timeout > 0) {
		if ((do_get_linkstatus(fd) == B_TRUE) &&
		    (*(wl_linkstatus_t *)(gbuf->wldp_buf) == WL_CONNECTED)) {
			(void) printf(gettext("%s: connecting to "
			    "essid '%s'\n"), gExecName, essid);
			return;
		}
		(void) sleep(1);
		timeout--;
	}
	(void) fprintf(stderr, gettext("%s: failed to connect to "
	    "essid '%s'\n"), gExecName, essid);
	exit(WIFI_FATAL_ERR);
}

/*
 * Called in autoconf and startconf to find which 'profile' is selected.
 * The process is: check profile names in the prefer list item by item,
 * if the essid of the profile is in the scan list, then it is the wanted.
 * readonly: 1 for startconf
 *           0 for autoconf
 * for autoconf, the scan result will be recorded in the history list.
 */
static char *
select_profile(int fd, int readonly, int timeout)
{
	uint32_t ess_num = 0;
	int nprefer = 1;
	char **ess_argv;
	char **hisess_argv;
	wl_ess_conf_t **p_ess_conf;
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	int i;
	const char *parg;
	char *selected = NULL;
	boolean_t flag = B_FALSE;

	if ((call_ioctl(fd, WLAN_COMMAND, WL_SCAN, 0) == B_FALSE) ||
	    (do_get_wlanlist(fd) == B_FALSE)) {
		(void) fprintf(stderr, gettext("%s: "
		    "autoconf : failed to scan\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}
	ess_num = ((wl_ess_list_t *)(gbuf->wldp_buf))->wl_ess_list_num;
	ess_argv = safe_calloc(sizeof (char *), ess_num);
	hisess_argv = safe_calloc(sizeof (char *), ess_num);
	p_ess_conf = safe_calloc(sizeof (wl_ess_list_t *), ess_num);
	for (i = 0; i < ess_num; i++) {
		p_ess_conf[i] = ((wl_ess_list_t *)gbuf->wldp_buf)
		    ->wl_ess_list_ess + i;
		ess_argv[i] = safe_malloc(MAX_SCANBUF_LEN);
		if (readonly == 0) {
			hisess_argv[i] = safe_malloc(MAX_SCANBUF_LEN);
			(void) snprintf(hisess_argv[i], MAX_SCANBUF_LEN,
			    "%s%c%02x:%02x:%02x:%02x:%02x:%02x%c%s",
			    p_ess_conf[i]->wl_ess_conf_essid.wl_essid_essid,
			    ',',
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[0]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[1]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[2]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[3]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[4]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[5]), ',',
			    (p_ess_conf[i]->wl_ess_conf_wepenabled == B_TRUE
			    ?  "wep":"none"));
		}
		(void) snprintf(ess_argv[i], MAX_SCANBUF_LEN, "%s",
		    p_ess_conf[i]->wl_ess_conf_essid.wl_essid_essid);
	}
	if (readonly == 0) {
		add_to_history(gp_config_file, ess_num, hisess_argv);
		for (i = 0; i < ess_num; i++) {
			free(hisess_argv[i]);
		}
		free(hisess_argv);
	}

	p_section = find_section(gp_config_file, WIFI_PREFER);
	if (p_section == NULL) {
		if (ess_num > 0) {
			heuristic_load(fd, ess_num, p_ess_conf);
			exit(WIFI_EXIT_DEF);
		}
		goto done;
	}
	plist = p_section->list;
	assert(plist != NULL);
	if (plist != NULL) {
		nprefer = plist->ael_argc;
		if (nprefer == 0) {
			if (ess_num > 0) {
				heuristic_load(fd, ess_num, p_ess_conf);
				exit(WIFI_EXIT_DEF);
			}
			goto done;
		}
	}
	pae = plist->ael_head;
	while ((pae != NULL) && (flag != B_TRUE)) {
		parg = essid_of_profile(pae->ae_arg);
		if (parg != NULL) {
			for (i = 0; i < ess_num; i++) {
				if (strcmp(parg, ess_argv[i]) == 0) {
					selected = pae->ae_arg;
					flag = B_TRUE;
					break;
				}
			}
		}
		pae = pae->ae_next;
	}
done:
	if ((selected == NULL) && (timeout == 0)) {
		heuristic_load(fd, ess_num, p_ess_conf);
	}
	for (i = 0; i < ess_num; i++) {
		free(ess_argv[i]);
	}
	free(ess_argv);
	free(p_ess_conf);
	return (selected);
}

static boolean_t
is_waittime_valid(char *pbuf)
{
	int i;

	i = atoi(pbuf);
	if (i == -1)
		return (B_TRUE);
	for (i = 0; i < strlen(pbuf); i++) {
		if (isdigit(pbuf[i]) == 0) {
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}
/*
 * do_autoconf: First scan the wlanlist, and select one essid from scan result
 * by the order in {preferrence} list. If no match, then heuristic_load;
 */
/*ARGSUSED*/
static boolean_t
do_autoconf(int fd, int argc, char **argv)
{
	const char *selected = NULL;
	int timeout = LOADPROFILE_TIMEOUT, forever = 0, len = 0;
	char *pequal, *param;
	char **ld_argv = NULL;
	boolean_t ret = B_TRUE;

	PRTDBG(("do_autoconf(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);
	if (argc > 0) {
		param = safe_strdup(argv[0]);
		pequal = strchr(param, '=');
		if (pequal != NULL) {
			*pequal++ = '\0';
		} else {
			do_print_usage();
			exit(WIFI_IMPROPER_USE);
		}
		if (strcmp(param, "wait") != 0) {
			do_print_usage();
			exit(WIFI_IMPROPER_USE);
		} else {
			if (strcmp(pequal, "forever") == 0) {
				forever = 1;
			} else {
				if (is_waittime_valid(pequal) == B_FALSE) {
					(void) fprintf(stderr, gettext("%s: "
					    "invalid value %s for 'wait'\n"),
					    gExecName, pequal);
					exit(WIFI_FATAL_ERR);
				}
				if (sscanf(pequal, "%d", &timeout) != 1) {
					do_print_usage();
					exit(WIFI_IMPROPER_USE);
				}
				if (timeout == -1) {
					forever = 1;
				}
			}
		}
		free(param);
		if (argc > 1) {
			(void) fprintf(stderr, gettext("%s: trailing "
			    "useless tokens after '%s'\n"),
			    gExecName, argv[0]);
		}
	}

	while ((forever == 1) || (timeout > 0)) {
		timeout--;
		selected = select_profile(fd, 0, max(timeout, forever));
		if (selected != NULL)
			break;
		(void) sleep(1);
	}
	if (selected == NULL) {
		return (B_TRUE);
	}
	(void) printf(gettext("%s: autoconf: profile [%s]"
	    " is selected\n"), gExecName, selected);
	ld_argv = safe_calloc(sizeof (char *), argc+1);
	ld_argv[0] = safe_strdup(selected);
	if (argc > 0) {
		len = max(strlen(argv[0]), strlen("wait=forever"));
		ld_argv[1] = safe_malloc(len);
		safe_snprintf(ld_argv[1], len + 1, forever == 1 ?
		    "wait=forever" : "wait=%d", timeout);
	}
	ret = do_loadpf(fd, argc+1, ld_argv);
	free(ld_argv[0]);
	if (argc > 0) {
		free(ld_argv[1]);
	}
	free(ld_argv);
	return (ret);
}

/*
 * do_startconf: almost the same as the do_autoconf, except that doesn't
 * write file.
 */
/*ARGSUSED*/
static boolean_t
do_startconf(int fd, int argc, char **argv)
{
	int i = 0, ael_num = 0;
	section_t *p_section = NULL;
	section_t *p_wep_section = NULL;
	aelist_t *plist = NULL;
	const char *selected = NULL;
	ae_t *pae = NULL;
	char *pbuf = NULL;
	char **argvnew = NULL;

	PRTDBG(("do_startconf(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);

	selected = select_profile(fd, 1, 0);
	if (selected == NULL) {
		return (B_TRUE);
	}

	(void) call_ioctl(fd, WLAN_COMMAND, WL_LOAD_DEFAULTS, 0);

	pbuf = append_pa(selected);
	p_wep_section = find_section(gp_wepkey_file, pbuf);
	p_section = find_section(gp_config_file, pbuf);
	free(pbuf);

	if (p_wep_section != NULL) {
		plist = p_wep_section->list;
		pae = plist->ael_head;
		while (pae != NULL) {
			if (pae->ae_arg != NULL)
				(void) do_set_wepkey(fd, pae->ae_arg);
			pae = pae->ae_next;
		}
	}

	if (p_section != NULL) {
		plist = p_section->list;
		if (plist->ael_argc == 0) {
			return (B_TRUE);
		}
		argvnew = aeltoargv(plist, &ael_num);
		(void) do_set(fd, ael_num, argvnew);

		for (i = 0; i < ael_num; i++)
			free(argvnew[i]);
		free(argvnew);
	}
	return (B_TRUE);
}

static char *
find_active_profile(int fd)
{
	section_t *p_section = NULL, *activep_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	const char *pessid = NULL, *pbssid = NULL;
	char essid[34], bssid[32];
	const char *activeprofile = NULL;

	PRTDBG(("find_active_profile: %d\n", fd));
	if (do_get_essid(fd) == B_FALSE) {
		return (NULL);
	}
	(void) strlcpy(essid, ((wl_essid_t *)(gbuf->wldp_buf))->wl_essid_essid,
	    sizeof (essid));
	if (do_get_bssid(fd) == B_FALSE) {
		return (NULL);
	}
	safe_snprintf(bssid, sizeof (bssid), "%02x:%02x:%02x:%02x:%02x:%02x",
	    ((uint8_t *)gbuf->wldp_buf)[0],
	    ((uint8_t *)gbuf->wldp_buf)[1],
	    ((uint8_t *)gbuf->wldp_buf)[2],
	    ((uint8_t *)gbuf->wldp_buf)[3],
	    ((uint8_t *)gbuf->wldp_buf)[4],
	    ((uint8_t *)gbuf->wldp_buf)[5]);
	activep_section = find_section(gp_config_file, WIFI_ACTIVEP);
	if (activep_section == NULL)
		return (NULL);
	activeprofile = get_value(activep_section->list->
	    ael_head->ae_arg);
	if (activeprofile == NULL)
		return (NULL);
	p_section = gp_config_file->section_head;
	while (p_section != NULL) {
		if (((plist = p_section->list) != NULL) &&
		    (plist->type == PROFILE) &&
		    (strcmp(p_section->section_id, activeprofile) == 0)) {
			pae = plist->ael_head;
			while (pae != NULL) {
				if (strncmp(pae->ae_arg, "essid=",
				    strlen("essid=")) == 0) {
					pessid = get_value(pae->ae_arg);
				}
				if (strncmp(pae->ae_arg, "bssid=",
				    strlen("bssid=")) == 0) {
					pbssid = get_value(pae->ae_arg);
				}
				pae = pae->ae_next;
			}
			if (pessid && pbssid &&
			    (strcmp(essid, pessid) == 0) &&
			    (strcmp(bssid, pbssid) == 0)) {
				return (p_section->section_id);
			}
		}
		p_section = p_section->section_next;
	}
	return (NULL);
}

static void
record_active_profile(char *pname, int action)
{
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	char pbuf[256];

	p_section = find_section(gp_config_file, WIFI_ACTIVEP);
	if (p_section == NULL) {
		plist = new_ael(ACTIVEP);
		new_section(gp_config_file, plist, WIFI_ACTIVEP);
	} else {
		plist = p_section->list;
	}

	if (action == RECORD_ADD) {
		assert(pname != NULL);
		safe_snprintf(pbuf, sizeof (pbuf), "activep=%s", pname);
		update_aelist(plist, pbuf);
	} else if (action == RECORD_DEL) {
		assert(pname == NULL);
		update_aelist(plist, "activep= ");
	}
}

/*
 * do_loadpf: load a profile, set related parameters both in wifi
 * and in wifiwepkey, if network name is not exist in the
 * configration files, then we clean all parameters and set essid only
 */
static boolean_t
do_loadpf(int fd, int argc, char ** argv)
{
	int i = 0, ael_num = 0;
	int timeout = LOADPROFILE_TIMEOUT, forever = 0;
	section_t *p_section = NULL;
	section_t *p_wep_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	char *pbuf = NULL;
	char **argvnew = NULL;
	char *connect;
	char *pequal, *param;

	PRTDBG(("do_loadpf(%d, %x)\n", argc, argv));
	assert(fd > 0);
	if (argc == 0) {
		(void) fprintf(stderr, gettext("%s: connect: "
		    "profile name missing\n"), gExecName);
		return (B_FALSE);
	}
	if (argc > 1) {
		param = safe_strdup(argv[1]);
		pequal = strchr(param, '=');
		if (pequal != NULL) {
			*pequal++ = '\0';
		} else {
			do_print_usage();
			exit(WIFI_IMPROPER_USE);
		}
		if (strcmp(param, "wait") != 0) {
			do_print_usage();
			exit(WIFI_IMPROPER_USE);
		} else {
			if (strcmp(pequal, "forever") == 0) {
				forever = 1;
			} else {
				if (is_waittime_valid(pequal) == B_FALSE) {
					(void) fprintf(stderr, gettext("%s: "
					    "invalid value %s for 'wait'\n"),
					    gExecName, pequal);
					exit(WIFI_FATAL_ERR);
				}
				if (sscanf(pequal, "%d", &timeout) != 1) {
					do_print_usage();
					exit(WIFI_IMPROPER_USE);
				}
				if (timeout == -1) {
					forever = 1;
				}
			}
		}
		free(param);
		if (argc > 2) {
			(void) fprintf(stderr, gettext("%s: trailing "
			    "useless tokens after '%s'\n"),
			    gExecName, argv[1]);
		}
	}
	(void) call_ioctl(fd, WLAN_COMMAND, WL_LOAD_DEFAULTS, 0);

	pbuf = append_pa(argv[0]);
	p_wep_section = find_section(gp_wepkey_file, pbuf);
	p_section = find_section(gp_config_file, pbuf);

	if (p_wep_section != NULL) {
		(void) set_prefer(gp_config_file, argv[0], 1);
		plist = p_wep_section->list;
		pae = plist->ael_head;
		while (pae != NULL) {
			if (pae->ae_arg != NULL) {
				(void) do_set_wepkey(fd, pae->ae_arg);
			}
			pae = pae->ae_next;
		}
	}

	if (p_section != NULL) {
		connect = "profile";

		(void) set_prefer(gp_config_file, argv[0], 1);
		plist = p_section->list;
		if (plist->ael_argc == 0) {
			free(pbuf);
			return (B_TRUE);
		}
		argvnew = aeltoargv(plist, &ael_num);
		/*
		 * if there is no 'essid' item in argvnew, the profile
		 * name(argv[0]) is treated as essid.
		 */
		for (i = 0; i < ael_num; i++) {
			if (strncmp(argvnew[i], "essid=", strlen("essid="))
			    == 0)
				break;
		}
		if (i == ael_num)
			(void) do_set_essid(fd, argv[0]);

		(void) do_set(fd, ael_num, argvnew);

		for (i = 0; i < ael_num; i++)
			free(argvnew[i]);
		free(argvnew);

		/*
		 * set flag in {active_profile} so that showprofile knows
		 * which profile is active when more than one profiles are
		 * created for the same WLAN.
		 */
		record_active_profile(pbuf, RECORD_ADD);
	} else {
		(void) do_set_essid(fd, argv[0]);
		connect = "essid";
	}

	while ((forever == 1) || (timeout > 0)) {
		if ((do_get_linkstatus(fd) == B_TRUE) &&
		    (*(wl_linkstatus_t *)(gbuf->wldp_buf) == WL_CONNECTED)) {
			section_t *p_section = NULL;
			aelist_t *plist = NULL;
			char bssid[32];
			/* record bssid in the profile */
			if (do_get_bssid(fd) == B_FALSE) {
				free(pbuf);
				return (B_TRUE);
			}
			safe_snprintf(bssid, sizeof (bssid),
			    "bssid=%02x:%02x:%02x:%02x:%02x:%02x",
			    ((uint8_t *)gbuf->wldp_buf)[0],
			    ((uint8_t *)gbuf->wldp_buf)[1],
			    ((uint8_t *)gbuf->wldp_buf)[2],
			    ((uint8_t *)gbuf->wldp_buf)[3],
			    ((uint8_t *)gbuf->wldp_buf)[4],
			    ((uint8_t *)gbuf->wldp_buf)[5]);

			p_section = find_section(gp_config_file, pbuf);
			if (p_section != NULL) {
				plist = p_section->list;
				update_aelist(plist, bssid);
			}
			free(pbuf);
			(void) printf(gettext("%s: connecting to "
			    "%s '%s'\n"), gExecName, connect, argv[0]);
			return (B_TRUE);
		}
		(void) sleep(1);
		timeout--;
		PRTDBG(("connect counting:......%d\n", timeout));
	}
	(void) fprintf(stderr, gettext("%s: failed to connect to "
	    "%s '%s'\n"), gExecName, connect, argv[0]);
	free(pbuf);
	return (B_FALSE);
}

/*
 * if wepkey is set in the profile, display wepkey|n=*****
 * when showprofile and getprofilewepkey.
 * if wepkeyn is NULL, all the wepkeys will be display,
 * otherwise, just display the matching one.
 */
static void
print_wepkey_info(const char *id, const char *wepkeyn)
{
	char *pequal, *param;
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;

	p_section = find_section(gp_wepkey_file, id);
	if (p_section != NULL) {
		plist = p_section->list;
		pae = plist->ael_head;
		while (pae != NULL) {
			if (pae->ae_arg != NULL) {
				param = safe_strdup(pae->ae_arg);
				pequal = strchr(param, '=');
				if (pequal == NULL)
					return;
				*pequal = '\0';
				if (wepkeyn != NULL) {
					if (strcmp(wepkeyn, param) == 0)
						(void) printf("\t%s=*****\n",
						    param);
					free(param);
					return;
				} else {
					(void) printf("\t%s=*****\n", param);
					free(param);
				}
			}
			pae = pae->ae_next;
		}
	}
}

/*
 * do_printpf: print each parameters of the profile, if no network name
 * assigned, then print all profile saved in configration file.
 */
/*ARGSUSED*/
static boolean_t
do_printpf(int fd, int argc, char ** argv)
{
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	char *pbuf = NULL;
	int i;

	PRTDBG(("do_printpf(%d, %x)\n", argc, argv));

	/*
	 * if no profile name is inputted, all the profiles will be displayed.
	 */
	if (argc == 0) {
		p_section = gp_config_file->section_head;
		while (p_section != NULL) {
			plist = p_section->list;
			if (plist->type == PROFILE) {
				(void) printf("%s\n", p_section->section_id);
				pae = plist->ael_head;
				while (pae != NULL) {
					if (pae->ae_arg != NULL) {
						(void) printf("\t%s\n",
						    pae->ae_arg);
					}
					pae = pae->ae_next;
				}
				/*
				 * identify whether wepkey is set
				 * in the profile
				 */
				print_wepkey_info(p_section->section_id, NULL);
			}
			p_section = p_section->section_next;
		}
		return (B_TRUE);
	}

	for (i = 0; i < argc; i++) {
		pbuf =	append_pa(argv[i]);
		p_section = find_section(gp_config_file, pbuf);
		free(pbuf);
		if (p_section != NULL)	{
			(void) printf("%s\n", p_section->section_id);
			plist = p_section->list;
			if (plist != NULL) {
				pae = plist->ael_head;
				while (pae != NULL) {
					if (pae->ae_arg != NULL) {
						(void) printf("\t%s\n",
						    pae->ae_arg);
					}
					pae = pae->ae_next;
				}
				/*
				 * identify whether wepkey is set
				 * in the profile
				 */
				print_wepkey_info(p_section->section_id, NULL);
			}
		} else {
			(void) fprintf(stderr,
			    gettext("%s: showprofile : "
			    "no such profile: '%s'\n"),
			    gExecName, argv[i]);
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}
/*
 * find_ae: Find an ae by its contents, return its pointer.
 */
static ae_t *
find_ae(aelist_t *plist, const char *arg)
{
	char *param = NULL;
	char *pnext = NULL;
	ae_t *pae = NULL;

	if ((arg == NULL) || (plist == NULL)) {
		PRTDBG(("find_ae: arg= NULL or plist=NULL\n"));
		return (NULL);
	}
	PRTDBG(("find_ae(0x%x, \"%s\")\n", plist, arg));
	param = safe_strdup(arg);
	pnext = strchr(param, '=');
	if (pnext != NULL) {
		*pnext = '\0';
	} else {
		PRTDBG(("find_ae: param = \"%s\"\n", param));
		free(param);
		return (NULL);
	}

	pae = plist->ael_head;
	while (pae != NULL) {
		if ((pae->ae_arg != NULL) &&
		    (strncmp(pae->ae_arg, param, strlen(param)) == 0)) {
			PRTDBG(("find_ae: param = \"%s\"\n", param));
			free(param);
			return (pae);
		}
		pae = pae->ae_next;
	}
	free(param);
	return (NULL);
}

/*
 * update_aelist: Update an aelist by arg, for example:
 * there are an item with content"essid=ap7-2",
 * update_aelist(0x..., "essid=myssid2") will update it as "essid=myssid2"
 */
static void
update_aelist(aelist_t *plist, const char *arg)
{
	ae_t *pae = NULL;

	assert((arg != NULL)&&(plist != NULL));
	PRTDBG(("update_aelist(0x%x, \"%s\")\n", plist, arg));
	pae = find_ae(plist, arg);
	if (pae == NULL) {
		new_ae(plist, arg);
	} else {
		free(pae->ae_arg);
		pae->ae_arg = safe_strdup(arg);
	}
}

/*
 * do_deletepf: delete a profile in configration files.
 */
/*ARGSUSED*/
static boolean_t
do_deletepf(int fd, int argc, char **argv)
{
	int i = 0;
	char *section_id;
	char *prefer;
	section_t *p_section = NULL, *p_sectionbak = NULL;
	aelist_t *plist = NULL;

	PRTDBG(("do_deletepf(%d, \"%s\")\n", argc, argv));
	if (argc <= 0) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}

	/*
	 * if a "all" is inputted, all the profiles will be deleted.
	 */
	if (strcasecmp(argv[0], "all") == 0) {
		p_section = gp_config_file->section_head;
		while ((p_section != NULL) &&
		    ((plist = p_section->list) != NULL)) {
			if (plist->type == PROFILE) {
				p_sectionbak = p_section->section_next;
				section_id = safe_strdup(p_section->section_id);
				(void) del_section(gp_config_file, section_id);
				(void) del_section(gp_wepkey_file, section_id);
				/*
				 * remove the '[]' of the [section_id]
				 */
				prefer = section_id + 1;
				*(prefer + strlen(section_id) - 2) = '\0';
				(void) del_prefer(gp_config_file, prefer,
				    B_FALSE);
				free(section_id);
				p_section = p_sectionbak;
				continue;
			}
			p_section = p_section->section_next;
		}
		return (B_TRUE);
	}
	if (gp_config_file != NULL) {
		for (i = 0; i < argc; i++) {
			section_id = append_pa(argv[i]);
			if (del_section(gp_config_file, section_id)
			    == B_FALSE) {
				if (del_section(gp_wepkey_file, section_id)
				    == B_TRUE) {
					(void) del_prefer(gp_config_file,
					    argv[i], B_FALSE);
					free(section_id);
					return (B_TRUE);
				} else {
					(void) fprintf(stderr,
					    gettext("%s: deleteprofile"
					    ": no such profile: '%s'\n"),
					    gExecName, argv[i]);
					free(section_id);
					return (B_FALSE);
				}
			}
			(void) del_prefer(gp_config_file, argv[i], B_FALSE);
			(void) del_section(gp_wepkey_file, section_id);
			free(section_id);
		}
	}
	return (B_TRUE);
}

/*
 * do_history: Print the list in {history} section.
 */
/*ARGSUSED*/
static boolean_t
do_history(int fd, int argc, char **argv)
{
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	char *param, *param_bak, *pcomma;
	uint32_t maxessidlen = 0, ulen;
	char format[256], *ntstr;
	uint32_t nt = 0, cnt = 0;
	int len;
	time_t cltime;

	PRTDBG(("do_history(%d, 0x%x)\n", argc, argv));
	if (argc > 0) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'history'\n"), gExecName);
	}
	p_section = find_section(gp_config_file, WIFI_HISTORY);
	if (p_section == NULL) {
		PRTDBG(("no history section\n"));
		return (B_FALSE);
	}
	plist = p_section->list;

	/*
	 * If history section is empty, directly return.
	 */
	if (plist == NULL)
		return (B_TRUE);
	/*
	 * construct the output format in terms of the
	 * maxmium essid length
	 */
	pae = NULL;
	pae = plist->ael_head;
	while (pae != NULL) {
		if (pae->ae_arg != NULL) {
			param = safe_strdup(pae->ae_arg);
			pcomma = strchr(param, ',');
			if (pcomma == NULL) {
				(void) fprintf(stderr,
				    gettext("%s: history : "
				    "data format error\n"),
				    gExecName);
				free(param);
				return (B_FALSE);
			}
			*pcomma = '\0';
			ulen = strlen(param);
			maxessidlen = (maxessidlen > ulen
			    ? maxessidlen:ulen);
			free(param);
		}
		pae = pae->ae_next;
	}
	if ((nt = (maxessidlen / 8 + 1)) > 4)
		nt = 4;
	len = snprintf(format, sizeof (format), gettext("essid"));
	ntstr = construct_format(nt);
	assert((ntstr != NULL) && (strlen(ntstr) <= 4));
	len += snprintf(format + len, sizeof (format) - len, "%s", ntstr);
	len += snprintf(format + len, sizeof (format) - len,
	    gettext("bssid\t\t  encryption\tlast seen\n"));

	if ((len <= 0) || (len > sizeof (format) - 1)) {
		(void) printf(gettext("essid\t\t\t\tbssid\t\t  encryption"
		    "\tlast seen\n"));
	} else {
		(void) printf("%s", format);
	}
	/*
	 * output the contents of the history section.
	 */
	pae = plist->ael_head;
	while (pae != NULL) {
		if (pae->ae_arg != NULL) {
			param = safe_strdup(pae->ae_arg);
			param_bak = param;
			if ((pcomma = strchr(param, ',')) != NULL) {
				*pcomma = '\0';
				cnt = nt - (min((strlen(param)/8 + 1), 4) - 1);
				ntstr = construct_format(cnt);
				assert(ntstr != NULL);
				/* display essid */
				(void) printf("%s%s", param, ntstr);
				free(ntstr);
			}
			param = pcomma + 1;
			if ((pcomma = strchr(param, ',')) != NULL) {
				*pcomma = '\0';
				/* display bssid */
				(void) printf("%s ", param);
			}
			param = pcomma + 1;
			if ((pcomma = strchr(param, ',')) != NULL) {
				*pcomma = '\0';
				/* display wep */
				(void) printf("%s\t\t", param);
			}
			param = pcomma + 1;
			/* display time stamp */
			cltime = (time_t)atol(param);
			(void) printf("%s", ctime(&cltime));
			free(param_bak);
		}
		pae = pae->ae_next;
	}

	return (B_TRUE);
}

/*
 * do_lsprefer: Print the list in {preferrence} section
 */
/*ARGSUSED*/
static boolean_t
do_lsprefer(int fd, int argc, char **argv)
{
	int i = 0;
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	char *pbuf;

	PRTDBG(("do_lsprefer(%d, 0x%x)\n", argc, argv));
	if (argc > 0) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'listprefer'\n"), gExecName);
	}
	p_section = find_section(gp_config_file, WIFI_PREFER);
	if (p_section != NULL) {
		plist = p_section->list;
		if (plist != NULL) {
			pae = NULL;
			pae = plist->ael_head;
			while (pae != NULL) {
				if (pae->ae_arg != NULL) {
					pbuf = append_pa(pae->ae_arg);
					(void) printf("%d\t%s\n", ++i, pbuf);
				}
				pae = pae->ae_next;
			}
		}
		return (B_TRUE);
	} else {
		PRTDBG(("no preference section\n"));
		return (B_FALSE);
	}
}

/*
 * do_rmprefer: Remove an item in {preferrence} list
 */
/*ARGSUSED*/
static boolean_t
do_rmprefer(int fd, int argc, char **argv)
{
	int i = 0;
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;

	PRTDBG(("do_rmprefer(%d, 0x%x)\n", argc, argv));
	if (argc <= 0) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}

	/*
	 * if a "all" is inputted, all the items in the preference
	 * list will be deleted.
	 */
	if (strcasecmp(argv[0], "all") == 0) {
		p_section = find_section(gp_config_file, WIFI_PREFER);
		if (p_section != NULL)
			plist = p_section->list;

		if ((p_section == NULL) || (plist == NULL))
			return (B_FALSE);
		pae = plist->ael_head;
		while (pae != NULL) {
			ae_t *next = pae->ae_next;
			free(pae);
			pae = next;
		}
		plist->ael_head = plist->ael_tail = NULL;
		plist->ael_argc = 0;
	} else if (gp_config_file != NULL) {
		for (i = 0; i < argc; i++) {
			if (del_prefer(gp_config_file, argv[i], B_TRUE)
			    == B_FALSE) {
				return (B_FALSE);
			}
		}
	}
	return (B_TRUE);
}

static boolean_t
is_prefer_rank_valid(const char *pbuf)
{
	int i;
	boolean_t ret = B_FALSE;

	for (i = 0; i < strlen(pbuf); i++) {
		if (isdigit(pbuf[i]) == 0) {
			ret = B_FALSE;
			goto exit0;
		}
	}
	i = atoi(pbuf);
	if ((i >= 1) && (i <= MAX_PREFERENCE_NUM))
		ret = B_TRUE;
exit0:
	return (ret);
}

/*
 * do_setprefer: Set network preferrence
 */
/*ARGSUSED*/
static boolean_t
do_setprefer(int fd, int argc, char **argv)
{
	int rank = 0;

	PRTDBG(("do_setprefer(%d, 0x%x)\n", argc, argv));
	if (argc <= 0) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}
	if (argc == 1) {
		rank = 1;
	} else {
		if (is_prefer_rank_valid(argv[1]) == B_FALSE) {
			(void) fprintf(stderr, gettext("%s: preference rank "
			    "should be an integer within 1-10\n"), gExecName);
			return (B_FALSE);
		}
		rank = atoi(argv[1]);
	}
	return (set_prefer(gp_config_file, argv[0], rank));
}

static boolean_t
is_wepkeyindex_valid(const char *pbuf)
{
	int i;
	boolean_t ret = B_FALSE;

	for (i = 0; i < strlen(pbuf); i++) {
		if (isdigit(pbuf[i]) == 0) {
			ret = B_FALSE;
			goto exit0;
		}
	}
	i = atoi(pbuf);
	if ((i >= 1) && (i <= MAX_NWEPKEYS))
		ret = B_TRUE;
exit0:
	return (ret);
}

static boolean_t
is_channel_valid(const char *pbuf)
{
	int i;
	boolean_t ret = B_FALSE;

	for (i = 0; i < strlen(pbuf); i++) {
		if (isdigit(pbuf[i]) == 0) {
			ret = B_FALSE;
			goto exit0;
		}
	}
	i = atoi(pbuf);
	if ((i >= 0) && (i <= MAX_CHANNEL_NUM))
		ret = B_TRUE;
exit0:
	return (ret);
}

static boolean_t
is_wepkey_valid(const char *pbuf, uint32_t length)
{
	int i;
	boolean_t ret = B_FALSE;

	switch (length) {
	case 10:
	case 26:
		for (i = 0; i < length; i++) {
			if (isxdigit(pbuf[i]) == 0) {
				ret = B_FALSE;
				goto exit0;
			}
		}
		ret = B_TRUE;
		break;
	case 5:
	case 13:
		ret = B_TRUE;
		break;
	default:
		ret = B_FALSE;
		break;
	}
exit0:
	if (ret == B_FALSE) {
		(void) fprintf(stderr, gettext("%s: "
		    "wepkey should be:\n"
		    "\t 40bits: 5 char or 10 hex digits.\n"
		    "\t 128bits: 13 char or 26 hex digits.\n"),
		    gExecName);
	}
	return (ret);
}

/*
 * get_valid_wepkey: get an valid wepkey from stdin
 */
static char *
get_valid_wepkey()
{
	int i = 0;
	char *buf = NULL;
	uint8_t length = 0;
	struct termios stored_settings;
	struct termios new_settings;

	PRTDBG(("get_valid_wepkey()\n"));
	buf = safe_calloc(sizeof (char), MAX_KEY_LENGTH + 2);
	/*
	 * Because we need to get single char from terminal, so we need to
	 * disable canonical mode and set buffer size to 1 tyte. And because
	 * wepkey should not be see by others, so we disable echo too.
	 */
	(void) fflush(stdin);
	(void) tcgetattr(0, &stored_settings);
	new_settings = stored_settings;
	new_settings.c_lflag &= (~ICANON);
	new_settings.c_lflag &= (~ECHO);
	new_settings.c_cc[VTIME] = 0;
	new_settings.c_cc[VMIN] = 1;
	/* Set new terminal attributes */
	(void) tcsetattr(0, TCSANOW, &new_settings);
	while (((buf[i++] = getchar()) != '\n') && (i < MAX_KEY_LENGTH + 1)) {
		(void) putchar('*');
	}
	(void) putchar('\n');
	/* Restore terminal attributes */
	(void) tcsetattr(0, TCSANOW, &stored_settings);
	(void) fflush(stdin);

	if (buf[--i] != '\n') {
		(void) fprintf(stderr, gettext("%s: wepkey length "
		    "exceeds 26 hex digits\n"), gExecName);
		free(buf);
		return (NULL);
	}
	/* Replace last char '\n' with '\0' */
	buf[i] = '\0';
	length = (uint8_t)i;
	return ((is_wepkey_valid(buf, length) == B_TRUE)?
	    buf : NULL);
}

/*
 * do_set_wepkey: Set parameters in wepkey, and call ioctl
 */
static boolean_t
do_set_wepkey(int fd, const char *pbuf)
{
	int id = 0;
	char i = 0;
	uint8_t len = 0;
	uint8_t length;
	const char *wepkey = NULL;
	char key[MAX_KEY_LENGTH] = {0};
	unsigned int keytmp;
	wl_wep_key_tab_t wepkey_tab;

	PRTDBG(("do_set_wepkey(%d, \"%s\")\n", fd, pbuf));
	if (!check_authority(AUTH_WEP)) {
		exit(WIFI_FATAL_ERR);
	}
	id = pbuf[strlen("wepkeyn") - 1] - '0';
	wepkey = get_value(pbuf);
	length = strlen(wepkey);
	switch (length) {
	case 10:
	case 26:
		for (i = 0; i < length / 2; i++) {
			(void) sscanf(wepkey + i * 2, "%2x", &keytmp);
			key[i] = (char)keytmp;
		}
		len = length / 2;
		break;
	case 5:
	case 13:
		(void) strlcpy(key, wepkey, MAX_KEY_LENGTH);
		len = length;
		break;
	default:
		PRTDBG(("do_set_wepkey: error pbuf size\n"));
		(void) fprintf(stderr, gettext("%s: "
		    "wepkey should be:\n"
		    "\t 40bits: 5 char or 10 hex digits.\n"
		    "\t 128bits: 13 char or 26 hex digits.\n"),
		    gExecName);
		exit(WIFI_FATAL_ERR);
	}

	(void) memset(wepkey_tab, 0, sizeof (wepkey_tab));
	for (i = 0; i < MAX_NWEPKEYS; i++) {
		wepkey_tab[i].wl_wep_operation = WL_NUL;
	}

	if (id > 0 && id <= MAX_NWEPKEYS) {
		wepkey_tab[id-1].wl_wep_operation = WL_ADD;
		wepkey_tab[id-1].wl_wep_length = len;
		(void) memcpy(wepkey_tab[id-1].wl_wep_key, key, len);
	} else {
		(void) fprintf(stderr, gettext("%s: wepkeyindex "
		    "should be an integer within the range 1-4\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}
	(void) memmove(gbuf->wldp_buf, &wepkey_tab, sizeof (wl_wep_key_tab_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_WEP_KEY_TAB,
	    sizeof (wl_wep_key_tab_t)));
}

/*
 * get the committed wepkey. the return form is like wepkey1=*****;
 */
/*ARGSUSED*/
static char *
get_commit_key(int fd, int argc, char **argv)
{
	int key;
	int len;
	char *wepkey = NULL;
	char *wepkey_confirm = NULL;
	char *pbuf = NULL;

	key = atoi(argv[0]);
	if (key <= 0 || key > MAX_NWEPKEYS) {
		(void) fprintf(stderr, gettext("%s: wepkeyindex "
		    "should be an integer within the range 1-4\n"), gExecName);
		goto exit0;
	}
	(void) printf(gettext("input wepkey%d:"), key);
	wepkey = get_valid_wepkey();
	if (wepkey == NULL) {
		goto exit0;
	}
	(void) printf(gettext("confirm wepkey%d:"), key);
	wepkey_confirm = get_valid_wepkey();
	if (wepkey_confirm == NULL) {
		free(wepkey);
		goto exit0;
	}
	if (strcmp(wepkey, wepkey_confirm) != 0) {
		free(wepkey);
		free(wepkey_confirm);
		(void) fprintf(stderr,
		    gettext("%s: wepkey: "
		    "two inputs are not identical\n"), gExecName);
		goto exit0;
	}
	free(wepkey_confirm); /* wepkey_confirm is no longer used */

	len = MAX_KEY_LENGTH + strlen("wepkey1=\n") + 1;
	pbuf = safe_malloc(len);
	safe_snprintf(pbuf, len, "%s%d=%s", "wepkey", key, wepkey);

	free(wepkey); /* wepkey is no longer used */
	return (pbuf);
exit0:
	return (NULL);
}

/*
 * do_wepkey: Get input from user, call do_set_wepkey
 */
/*ARGSUSED*/
static boolean_t
do_wepkey(int fd, int argc, char **argv)
{
	char *pbuf;

	PRTDBG(("do_wepkey(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);
	if (argc <= 0) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}
	if (argc > 1) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'setwepkey'\n"), gExecName);
	}
	pbuf = get_commit_key(fd, argc, argv);
	if ((pbuf != NULL) && (do_set_wepkey(fd, pbuf) == B_TRUE)) {
		free(pbuf);
		return (B_TRUE);
	}
	free(pbuf);
	return (B_FALSE);
}

/*ARGSUSED*/
static boolean_t
do_setprofwepkey(int fd, int argc, char **argv)
{
	char *pbuf;
	char *section_id = NULL;
	section_t *p_section = NULL;
	aelist_t *plist = NULL;

	PRTDBG(("do_setprofwepkey(%d, 0x%x)\n", argc, argv));
	if (argc < 2) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}
	if (argc > 2) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'setprofwepkey'\n"), gExecName);
	}

	section_id = append_pa(argv[0]);
	p_section = find_section(gp_wepkey_file, section_id);
	free(section_id);
	if (p_section == NULL) {
		(void) fprintf(stderr, gettext("%s: "
		    "no such profile: '%s'\n"),
		    gExecName, argv[0]);
		return (B_FALSE);
	}

	argc--;
	argv++;
	pbuf = get_commit_key(fd, argc, argv);
	if (pbuf == NULL)
		return (B_FALSE);
	plist = p_section->list;
	update_aelist(plist, pbuf);

	return (B_TRUE);
}

/*
 * do_wlanlist: Scan for wlanlist
 */
/*ARGSUSED*/
static boolean_t
do_wlanlist(int fd, int argc, char **argv)
{
	PRTDBG(("do_wlanlist(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);
	if (argc > 0) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'scan'\n"), gExecName);
	}
	if (call_ioctl(fd, WLAN_COMMAND, WL_SCAN, 0) == B_FALSE) {
		(void) fprintf(stderr, gettext("%s: failed to scan\n"),
		    gExecName);
		return (B_FALSE);
	}
	if (do_get_wlanlist(fd) == B_TRUE) {
		print_gbuf(WLANLIST);
	}
	return (B_TRUE);
}

/*
 * do_showstatus: show the basic status of the interface, including
 * linkstatus, essid, encryption and signal strength.
 */
/*ARGSUSED*/
static boolean_t
do_showstatus(int fd, int argc, char **argv)
{
	wl_rssi_t signal;
	char *active_profile = NULL;

	PRTDBG(("do_showstatus(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);

	if (argc > 0) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'showstatus'\n"), gExecName);
	}
	if (do_get_linkstatus(fd) == B_TRUE) {
		print_gbuf(LINKSTATUS);
		if (*(wl_linkstatus_t *)(gbuf->wldp_buf) == WL_NOTCONNECTED) {
			return (B_TRUE);
		}
	}
	active_profile = find_active_profile(fd);
	(void) printf("\tactive profile: %s\n",
	    active_profile ? active_profile : "none");
	if (do_get_essid(fd) == B_TRUE) {
		print_gbuf(ESSID);
	}
	if (do_get_bssid(fd) == B_TRUE) {
		print_gbuf(BSSID);
	}
	if (do_get_encryption(fd) == B_TRUE) {
		print_gbuf(ENCRYPTION);
	}
	if (do_get_signal(fd) == B_TRUE) {
		signal = *(wl_rssi_t *)(gbuf->wldp_buf);
		if (signal < 4) {
			(void) printf("\tsignal strength: weak(%d)\n",
			    signal);
		} else if ((signal >= 4) && (signal <= 11)) {
			(void) printf("\tsignal strength: medium(%d)\n",
			    signal);
		} else {
			(void) printf("\tsignal strength: strong(%d)\n",
			    signal);
		}
	}

	return (B_TRUE);
}


/*
 * do_restoredef: Ask driver for loading default parameters
 */
/*ARGSUSED*/
static boolean_t
do_restoredef(int fd, int argc, char **argv)
{
	PRTDBG(("do_restoredef(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);

	if (argc > 0) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'restoredef'\n"), gExecName);
	}
	record_active_profile(NULL, RECORD_DEL);
	if (call_ioctl(fd, WLAN_COMMAND, WL_LOAD_DEFAULTS, 0) == B_FALSE) {
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

/*
 * do_disconnect: disconnect from the current connectted network
 */
/*ARGSUSED*/
static boolean_t
do_disconnect(int fd, int argc, char **argv)
{
	PRTDBG(("do_disconnect(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);

	if (argc > 0) {
		(void) fprintf(stderr, gettext("%s: trailing useless tokens "
		    "after 'disconnect'\n"), gExecName);
	}
	record_active_profile(NULL, RECORD_DEL);
	if (call_ioctl(fd, WLAN_COMMAND, WL_DISASSOCIATE, 0) == B_FALSE) {
		return (B_FALSE);
	} else {
		return (B_TRUE);
	}
}

static boolean_t
do_set_essid(int fd, const char *arg)
{
	wl_essid_t essid;

	PRTDBG(("do_set_essid(%d, \"%s\")\n", fd, arg));

	/*
	 * a trick here: clean the active_profile flag
	 * in section{active_profile}
	 */
	record_active_profile(NULL, RECORD_DEL);

	(void) memset(&essid, 0x0, sizeof (essid));

	if (arg == NULL || strcmp(arg, "") == 0) {
		essid.wl_essid_length = 0;
		essid.wl_essid_essid[0] = '\0';
	} else {
		essid.wl_essid_length = strlen(arg);
		if (essid.wl_essid_length > MAX_ESSID_LENGTH - 1) {
			(void) fprintf(stderr, gettext("%s: "
			    "essid exceeds 32 bytes\n"), gExecName);
			exit(WIFI_FATAL_ERR);
		}
		(void) strcpy(essid.wl_essid_essid, arg);
	}
	(void) memmove(gbuf->wldp_buf, &essid, sizeof (wl_essid_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_ESSID, sizeof (wl_essid_t)));
}

static boolean_t
do_set_bsstype(int fd, const char *arg)
{
	wl_bss_type_t bsstype;

	assert(arg != NULL);

	PRTDBG(("do_set_bsstype(%d, \"%s\")\n", fd, arg));

	(void) memset(&bsstype, 0xff, sizeof (bsstype));

	if ((strcasecmp(arg, "BSS") == 0) ||
	    (strcasecmp(arg, "AP") == 0) ||
	    (strcasecmp(arg, "INFRASTRUCTURE") == 0)) {
		bsstype = WL_BSS_BSS;
	} else if ((strcasecmp(arg, "IBSS") == 0) ||
	    (strcasecmp(arg, "AD-HOC") == 0)) {
		bsstype = WL_BSS_IBSS;
	} else if (strcasecmp(arg, "AUTO") == 0) {
		bsstype = WL_BSS_ANY;
	} else {
		(void) fprintf(stderr, gettext("%s: bsstype: "
		    "bss(ap,infrastructure) ibss(ad-hoc) or auto\n"),
		    gExecName);
		exit(WIFI_FATAL_ERR);
	}

	(void) memmove(gbuf->wldp_buf, &bsstype, sizeof (wl_bss_type_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_BSS_TYPE,
	    sizeof (wl_bss_type_t)));
}

static boolean_t
do_set_createibss(int fd, const char *arg)
{
	wl_create_ibss_t create_ibss;

	assert(arg != NULL);

	PRTDBG(("do_set_createibss(%d, \"%s\")\n", fd, arg));

	(void) memset(&create_ibss, 0x0, sizeof (create_ibss));

	if (strcasecmp(arg, "YES") == 0) {
		create_ibss = B_TRUE;
	} else if (strcasecmp(arg, "NO") == 0) {
		create_ibss = B_FALSE;
	} else {
		(void) fprintf(stderr, gettext("%s: "
		    "createibss: yes or no\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}

	(void) memmove(gbuf->wldp_buf, &create_ibss,
	    sizeof (wl_create_ibss_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_CREATE_IBSS,
	    sizeof (wl_create_ibss_t)));
}

static boolean_t
do_set_channel(int fd, const char *arg)
{
	wl_phy_conf_t phy_conf;

	assert(arg != NULL);
	PRTDBG(("do_set_channel(%d, \"%s\")\n", fd, arg));

	(void) memset(&phy_conf, 0xff, sizeof (phy_conf));

	if (is_channel_valid(arg) == B_FALSE) {
		(void) fprintf(stderr, gettext("%s: channel No. "
		    "should be:\n"
		    "\t802.11a: 0-99\n"
		    "\t802.11b: 1-14\n"
		    "\t802.11g: 1-14\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}
	phy_conf.wl_phy_dsss_conf.wl_dsss_channel = atoi(arg);
	PRTDBG(("channel=%d\n", phy_conf.wl_phy_dsss_conf.wl_dsss_channel));

	(void) memmove(gbuf->wldp_buf, &phy_conf, sizeof (wl_phy_conf_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_PHY_CONFIG,
	    sizeof (wl_phy_conf_t)));
}
/*
 * is_rates_support: Querying driver about supported rates.
 */
static boolean_t
is_rates_support(int fd, int num, uint8_t *rates)
{
	int rates_num = 0;
	int i = 0, j = 0;
	uint8_t value = 0;

	assert((rates != NULL)&&(num != 0));
	PRTDBG(("is_rates_support(%d, %d, 0x%x)\n", fd, num, rates));

	if (call_ioctl(fd, WLAN_GET_PARAM, WL_SUPPORTED_RATES, 0)
	    == B_TRUE) {
		rates_num = ((wl_rates_t *)(gbuf->wldp_buf))->wl_rates_num;

		for (i = 0; i < num; i++) {
			PRTDBG(("rates[%d] = %d\n", i, rates[i]));
			for (j = 0; j < rates_num; j++) {
				value = ((wl_rates_t *)gbuf->wldp_buf)
				    ->wl_rates_rates[j];
				PRTDBG(("supported rates[%d]=%d\n", j, value));
				if (value == rates[i]) {
					break;
				}
			}
			if (j == rates_num) {
				if (rates[i] == 11) {
					(void) fprintf(stderr,
					    gettext("%s: "
					    "rate 5.5M is not supported\n"),
					    gExecName);
				} else {
					(void) fprintf(stderr,
					    gettext("%s: "
					    "rate %dM is not supported\n"),
					    gExecName, rates[i]/2);
				}
				return (B_FALSE);
			}
		}
		return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 *
 */
static uint8_t
rates_convert(const char *rates)
{
	int i;
	uint8_t ret;

	for (i = 0; i < WIFI_RATES_NUM; i++) {
		if (strcmp(rates, wifi_rates_s[i].rates_s) == 0) {
			ret = wifi_rates_s[i].rates_i;
			break;
		}
	}
	if (i == WIFI_RATES_NUM) {
		(void) fprintf(stderr, gettext("%s: "
		    "invalid rates '%s'\n"), gExecName, rates);
		exit(WIFI_FATAL_ERR);
	}
	return (ret);
}

/*
 * get_rates: convert string value arg into uint8_t array,
 * array length will be save into *len[i].
 * for example:
 * arg = "1,2,5.5,11"
 * then after call, rates[] = {2,4,11,22} will be returned.
 * and *len will equal to 4
 */
static uint8_t *
get_rates(const char *arg, uint32_t *len)
{
	int i = 1, j = 0;
	uint8_t *rates = NULL;
	char *pnext = NULL;
	char *token;
	char *pstart;
	char *pstart_bak;

	assert(arg != NULL);

	if (strlen(arg) == 0) {
		PRTDBG(("get_rates: empty rates string\n"));
		return (NULL);
	}
	PRTDBG(("get_rates(\"%s\", 0x%x)\n", arg, len));
	pstart = safe_strdup(arg);
	pstart_bak = pstart;
	while ((pnext = strchr(pstart, ',')) != NULL) {
		pstart = pnext + 1;
		i++;
	}
	*len = i;
	rates = safe_calloc(sizeof (uint8_t), i);

	pstart = pstart_bak;
	if ((token = strtok(pstart, ",")) != NULL) {
		PRTDBG(("rates[0]: %s\n", token));
		rates[0] = rates_convert(token);
		i = 1;
		while ((token = strtok(NULL, ",")) != NULL) {
			PRTDBG(("rates[%d]: %s\n", i, token));
			rates[i++] = rates_convert(token);
		}
	}
	free(pstart_bak);
	for (i = 0; i < *len; i++) {
		for (j = 0; j < i; j++)
			if (rates[j] == rates[i]) {
				(void) fprintf(stderr,
				    gettext("%s: rates duplicated\n"),
				    gExecName);
				free(rates);
				return (NULL);
			}
	}

	return (rates);
}

static boolean_t
do_set_rates(int fd, const char *arg)
{
	int i = 0;
	uint32_t num = 0;
	uint8_t *rates;

	assert(arg != NULL);

	PRTDBG(("do_set_rates(%d, \"%s\")\n", fd, arg));

	rates = get_rates(arg, &num);
	if ((rates == NULL) ||
	    is_rates_support(fd, num, rates) == B_FALSE) {
		exit(WIFI_FATAL_ERR);
	}

	((wl_rates_t *)(gbuf->wldp_buf))->wl_rates_num = num;
	for (i = 0; i < num; i++) {
		((wl_rates_t *)gbuf->wldp_buf)->wl_rates_rates[i]
		    = rates[i];
	}
	free(rates);
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_DESIRED_RATES,
	    offsetof(wl_rates_t, wl_rates_rates) +
	    num*sizeof (char)));
}

static boolean_t
do_set_powermode(int fd, const char *arg)
{
	wl_ps_mode_t ps_mode;

	assert(arg != NULL);

	PRTDBG(("do_set_powermode(%d, \"%s\")\n", fd, arg));

	(void) memset(&ps_mode, 0xff, sizeof (ps_mode));

	if ((strcasecmp(arg, "OFF") == 0) ||
	    (strcasecmp(arg, "MPS") == 0) ||
	    (strcasecmp(arg, "FAST") == 0)) {
		switch (arg[0]) {
		case 'O':
		case 'o':
			ps_mode.wl_ps_mode = WL_PM_AM;
			break;
		case 'M':
		case 'm':
			ps_mode.wl_ps_mode = WL_PM_MPS;
			break;
		case 'F':
		case 'f':
			ps_mode.wl_ps_mode = WL_PM_FAST;
			break;
		default:
			break;
		}
	} else {
		(void) fprintf(stderr,
		    gettext("%s: powermode: off mps or fast\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}

	(void) memmove(gbuf->wldp_buf, &ps_mode, sizeof (wl_ps_mode_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_POWER_MODE,
	    sizeof (wl_ps_mode_t)));
}

static boolean_t
do_set_authmode(int fd, const char *arg)
{
	wl_authmode_t auth_mode;

	assert(arg != NULL);
	PRTDBG(("do_set_authmode(%d, \"%s\")\n", fd, arg));

	(void) memset(&auth_mode, 0xff, sizeof (auth_mode));
	/* Mark */
	if (strcasecmp(arg, "OPENSYSTEM") == 0) {
		auth_mode = WL_OPENSYSTEM;
	} else if (strcasecmp(arg, "SHARED_KEY") == 0) {
		auth_mode = WL_SHAREDKEY;
	} else {
		(void) fprintf(stderr,
		    gettext("%s: authmode: "
		    "opensystem or shared_key\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}

	(void) memmove(gbuf->wldp_buf, &auth_mode, sizeof (wl_authmode_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_AUTH_MODE,
	    sizeof (wl_authmode_t)));
}

static boolean_t
do_set_encryption(int fd, const char *arg)
{
	wl_encryption_t encryption;

	assert(arg != NULL);
	PRTDBG(("do_set_encryption(%d, \"%s\")\n", fd, arg));

	(void) memset(&encryption, 0xff, sizeof (encryption));

	if (strcasecmp(arg, "NONE") == 0) {
		encryption = WL_NOENCRYPTION;
	} else if (strcasecmp(arg, "WEP") == 0) {
		encryption = WL_ENC_WEP;
	} else {
		(void) fprintf(stderr, gettext("%s: encryption: "
		    "none or wep\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}

	(void) memmove(gbuf->wldp_buf, &encryption, sizeof (wl_encryption_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_ENCRYPTION,
	    sizeof (wl_encryption_t)));
}

static boolean_t
do_set_wepkeyid(int fd, const char *arg)
{
	wl_wep_key_id_t wep_key_id;

	assert(arg != NULL);
	PRTDBG(("do_set_wepkeyid(%d, \"%s\")\n", fd, arg));

	(void) memset(&wep_key_id, 0xff, sizeof (wep_key_id));
	if (is_wepkeyindex_valid(arg) == B_FALSE) {
		(void) fprintf(stderr, gettext("%s: wepkeyindex "
		    "should be an integer within the range 1-4\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}
	wep_key_id = atoi(arg) - 1;

	(void) memmove(gbuf->wldp_buf, &wep_key_id, sizeof (wl_wep_key_id_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_WEP_KEY_ID,
	    sizeof (wl_wep_key_id_t)));
}

static boolean_t
do_set_radioon(int fd, const char *arg)
{
	wl_radio_t radio;

	assert(arg != NULL);
	PRTDBG(("do_set_radioon(%d, \"%s\")\n", fd, arg));

	(void) memset(&radio, 0xff, sizeof (radio));

	if (strcasecmp(arg, "ON") == 0) {
		radio = B_TRUE;
	} else if (strcasecmp(arg, "OFF") == 0) {
		radio = B_FALSE;
	} else {
		(void) fprintf(stderr,
		    gettext("%s: radio : on or off\n"), gExecName);
		exit(WIFI_FATAL_ERR);
	}

	(void) memmove(gbuf->wldp_buf, &radio, sizeof (wl_radio_t));
	return (call_ioctl(fd, WLAN_SET_PARAM, WL_RADIO, sizeof (wl_radio_t)));
}
/*
 * print_gbuf: After each ioctl system call, gbuf will contain result, gbuf
 * contents's format varies from each kind of ioctl system call.
 */
static void
print_gbuf(config_item_t index)
{
	int i = 0, j = 0;
	uint32_t ess_num;
	char **ess_argv;
	uint32_t rates_num;
	uint32_t subtype;
	wl_bss_type_t bsstype;
	wl_create_ibss_t createibss;
	wl_ps_mode_t *ps_mode;
	wl_authmode_t authmode;
	wl_encryption_t encryption;
	wl_wep_key_id_t wepkeyid;
	wl_rssi_t signal;
	wl_radio_t radioon;
	wl_ess_conf_t **p_ess_conf;
	wl_linkstatus_t linkstatus;
	char format[256], *ntstr;
	uint32_t maxessidlen = 0, nt = 0, cnt = 0;
	int len;
	uint8_t bssid[6];

	PRTDBG(("print_gbuf(%d)\n", index));
	assert(gbuf->wldp_length < MAX_BUF_LEN);

	switch (index) {
	case BSSID:
		(void) printf("\tbssid: ");
		(void) memset(bssid, 0, sizeof (bssid));
		if (memcmp((uint8_t *)gbuf->wldp_buf, bssid, sizeof (bssid))
		    == 0) {
			(void) printf("none\n");
			break;
		}
		(void) memset(bssid, 0xff, sizeof (bssid));
		if (memcmp((uint8_t *)gbuf->wldp_buf, bssid, sizeof (bssid))
		    == 0) {
			(void) printf("none\n");
			break;
		}
		for (i = 0; i < 5; i++)
			(void) printf("%02x:", ((uint8_t *)gbuf->wldp_buf)[i]);
		(void) printf("%02x\n", ((uint8_t *)gbuf->wldp_buf)[i]);
		break;
	case ESSID:
		(void) printf("\tessid: %s\n", ((wl_essid_t *)(gbuf->wldp_buf))
		    ->wl_essid_essid);
		break;
	case BSSTYPE:
		bsstype = *(wl_bss_type_t *)(gbuf->wldp_buf);
		switch (bsstype) {
		case WL_BSS_BSS:
			(void) printf("\tbsstype: bss(ap, infrastructure)\n");
			break;
		case WL_BSS_IBSS:
			(void) printf("\tbsstype: ibss(ad-hoc)\n");
			break;
		case WL_BSS_ANY:
			(void) printf("\tbsstype: auto\n");
			break;
		default:
			(void) fprintf(stderr,
			    gettext("%s: "
			    "invalid bsstype value\n"), gExecName);
		}
		break;
	case CREATEIBSS:
		createibss = *(wl_create_ibss_t *)(gbuf->wldp_buf);
		switch (createibss) {
		case B_TRUE:
			(void) printf("\tcreateibss: yes\n");
			break;
		case B_FALSE:
			(void) printf("\tcreateibss: no\n");
			break;
		default:
			(void) fprintf(stderr,
			    gettext("%s: "
			    "invalid createibss value\n"), gExecName);
		}
		break;
	case CHANNEL:
		subtype = ((wl_fhss_t *)(gbuf->wldp_buf))->wl_fhss_subtype;
		switch (subtype) {
		case WL_FHSS:
		case WL_DSSS:
		case WL_IRBASE:
		case WL_HRDS:
		case WL_ERP:
			(void) printf("\tchannel: %d\n", ((wl_fhss_t *)
			    (gbuf->wldp_buf))->wl_fhss_channel);
			break;
		case WL_OFDM:
			(void) printf("\tchannel: %d\n", ((wl_ofdm_t *)
			    (gbuf->wldp_buf))
			    ->wl_ofdm_frequency);
			break;
		default:
			(void) fprintf(stderr, gettext("%s: "
			    "invalid subtype\n"), gExecName);
			break;
		}
		break;
	case RATES:
		rates_num = ((wl_rates_t *)(gbuf->wldp_buf))->wl_rates_num;
		(void) printf("\trates: ");
		for (i = 0; i < rates_num; i++) {
			char rate;
			rate = ((wl_rates_t *)gbuf->wldp_buf)
			    ->wl_rates_rates[i];
			if (rate == WL_RATE_5_5M)
				(void) printf("5.5");
			else
				(void) printf("%d", (uint8_t)(rate / 2));

			if (i == (rates_num - 1))
				(void) printf("\n");
			else
				(void) printf(",");
		}
		break;
	case POWERMODE:
		ps_mode = (wl_ps_mode_t *)(gbuf->wldp_buf);
		switch (ps_mode->wl_ps_mode) {
		case WL_PM_AM:
			(void) printf("\tpowermode: off\n");
			break;
		case WL_PM_MPS:
			(void) printf("\tpowermode: mps\n");
			break;
		case WL_PM_FAST:
			(void) printf("\tpowermode: fast\n");
			break;
		default:
			(void) fprintf(stderr,
			    gettext("%s: "
			    "invalid powermode value\n"), gExecName);
			break;
		}
		break;
	case AUTHMODE:
		authmode = *(wl_authmode_t *)(gbuf->wldp_buf);
		switch (authmode) {
		case WL_OPENSYSTEM:
			(void) printf("\tauthmode: opensystem\n");
			break;
		case WL_SHAREDKEY:
			(void) printf("\tauthmode: shared_key\n");
			break;
		default:
			(void) fprintf(stderr,
			    gettext("%s: "
			    "invalid authmode value\n"), gExecName);
			break;
		}
		break;
	case ENCRYPTION:
		encryption = *(wl_encryption_t *)(gbuf->wldp_buf);
		switch (encryption) {
		case WL_NOENCRYPTION:
			(void) printf("\tencryption: none\n");
			break;
		case WL_ENC_WEP:
			(void) printf("\tencryption: wep\n");
			break;
		default:
			(void) fprintf(stderr,
			    gettext("%s: "
			    "invalid encryption value\n"), gExecName);
			break;
		}
		break;
	case WEPKEYID:
		wepkeyid = *(wl_wep_key_id_t *)(gbuf->wldp_buf);
		(void) printf("\twepkeyindex: %d\n", wepkeyid + 1);
		break;
	case SIGNAL:
		signal = *(wl_rssi_t *)(gbuf->wldp_buf);
		(void) printf("\tsignal: %d\n", signal);
		break;
	case RADIOON:
		radioon = *(wl_radio_t *)(gbuf->wldp_buf);
		switch (radioon) {
		case B_TRUE:
			(void) printf("\tradio: on\n");
			break;
		case B_FALSE:
			(void) printf("\tradio: off\n");
			break;
		default: /* Mark */
			(void) fprintf(stderr,
			    gettext("%s: "
			    "invalid radioon value\n"), gExecName);
		}
		break;
	case LINKSTATUS:
		linkstatus = *(wl_linkstatus_t *)(gbuf->wldp_buf);
		switch (linkstatus) {
		case WL_CONNECTED:
			(void) printf("\tlinkstatus: connected\n");
			break;
		case WL_NOTCONNECTED:
			(void) printf("\tlinkstatus: not connected\n");
			break;
		default: /* Mark */
			(void) fprintf(stderr,
			    gettext("%s: "
			    "invalid linkstatus value\n"), gExecName);
		}
		break;
	case WLANLIST:
		ess_num = ((wl_ess_list_t *)(gbuf->wldp_buf))->wl_ess_list_num;
		ess_argv = safe_calloc(sizeof (char *), ess_num);
		p_ess_conf = safe_calloc(sizeof (wl_ess_conf_t *), ess_num);
		for (i = 0; i < ess_num; i++) {
			p_ess_conf[i] = ((wl_ess_list_t *)gbuf->wldp_buf)
			    ->wl_ess_list_ess + i;
			maxessidlen = (maxessidlen >
			    strlen(p_ess_conf[i]
			    ->wl_ess_conf_essid.wl_essid_essid) ?
			    maxessidlen :
			    strlen(p_ess_conf[i]
			    ->wl_ess_conf_essid.wl_essid_essid));
		}
		/*
		 * construct the output format.
		 */
		if ((nt = (maxessidlen / 8 + 1)) > 4)
			nt = 4;
		len = snprintf(format, sizeof (format), gettext("essid"));
		ntstr = construct_format(nt);
		assert(ntstr != NULL);
		len += snprintf(format + len, sizeof (format) - len, "%s",
		    ntstr);
		len += snprintf(format + len, sizeof (format) - len,
		    gettext("bssid\t\t  type\t\tencryption\tsignallevel\n"));

		if ((len <= 0) || (len > sizeof (format) - 1)) {
			(void) printf("essid\t\t\t\tbssid\t\t  type\t\t"
			    "encryption\tsignallevel\n");
		} else {
			(void) printf("%s", format);
		}

		for (i = 0; i < ess_num; i++) {
			ess_argv[i] = safe_malloc(MAX_SCANBUF_LEN);
			safe_snprintf(ess_argv[i], MAX_SCANBUF_LEN,
			    "%s%c%02x:%02x:%02x:%02x:%02x:%02x%c%s",
			    p_ess_conf[i]->wl_ess_conf_essid.wl_essid_essid,
			    ',',
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[0]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[1]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[2]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[3]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[4]),
			    (uint8_t)(p_ess_conf[i]->wl_ess_conf_bssid[5]), ',',
			    (p_ess_conf[i]->wl_ess_conf_wepenabled ==
			    B_TRUE ? "wep":"none"));
			len = strlen(p_ess_conf[i]->wl_ess_conf_essid.
			    wl_essid_essid);
			cnt = nt - (min(len /8 + 1, 4) - 1);
			ntstr = construct_format(cnt);
			assert(ntstr != NULL);
			(void) printf("%s%s", p_ess_conf[i]->wl_ess_conf_essid.
			    wl_essid_essid, ntstr);
			free(ntstr);
			for (j = 0; j < 5; j++) {
				(void) printf("%02x:", (uint8_t)(p_ess_conf[i]
				    ->wl_ess_conf_bssid[j]));
			}
			(void) printf("%02x ", (uint8_t)(p_ess_conf[i]
			    ->wl_ess_conf_bssid[j]));

			if (p_ess_conf[i]->wl_ess_conf_bsstype ==
			    WL_BSS_BSS)
				(void) printf("access point");
			else
				(void) printf("ad-hoc");
			if (p_ess_conf[i]->wl_ess_conf_wepenabled ==
			    WL_ENC_WEP)
				(void) printf("\twep\t");
			else
				(void) printf("\tnone\t");
			(void) printf("\t%d\n", p_ess_conf[i]->wl_ess_conf_sl);
		}
		add_to_history(gp_config_file, ess_num, ess_argv);
		free(p_ess_conf);
		for (i = 0; i < ess_num; i++) {
			free(ess_argv[i]);
		}
		free(ess_argv);
		break;
	default:
		(void) fprintf(stderr, gettext("%s: "
		    "invalid parameter type\n"), gExecName);
		break;
	}
}
/*
 * do_get_xxx: will send ioctl to driver, then the driver will fill gbuf
 * with related value. gbuf has a format of wldp_t structure.
 */
static boolean_t
do_get_bssid(int fd)
{
	PRTDBG(("do_get_bssid(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_BSSID, 0));
}

static boolean_t
do_get_essid(int fd)
{
	PRTDBG(("do_get_essid(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_ESSID, 0));
}

static boolean_t
do_get_bsstype(int fd)
{
	PRTDBG(("do_get_bsstype(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_BSS_TYPE, 0));
}

static boolean_t
do_get_createibss(int fd)
{
	PRTDBG(("do_get_createibss(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_CREATE_IBSS, 0));
}

static boolean_t
do_get_channel(int fd)
{
	PRTDBG(("do_get_channel(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_PHY_CONFIG, 0));
}

static boolean_t
do_get_wlanlist(int fd)
{
	PRTDBG(("do_get_wlanlist(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_ESS_LIST, 0));
}

static boolean_t
do_get_linkstatus(int fd)
{
	PRTDBG(("do_get_linkstatus(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_LINKSTATUS, 0));
}

static boolean_t
do_get_rates(int fd)
{
	PRTDBG(("do_get_rates(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_DESIRED_RATES, 0));
}

static boolean_t
do_get_powermode(int fd)
{
	PRTDBG(("do_get_powermode(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_POWER_MODE, 0));
}

static boolean_t
do_get_authmode(int fd)
{
	PRTDBG(("do_get_authmode(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_AUTH_MODE, 0));
}

static boolean_t
do_get_encryption(int fd)
{
	PRTDBG(("do_get_encryption(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_ENCRYPTION, 0));
}

static boolean_t
do_get_wepkeyid(int fd)
{
	PRTDBG(("do_get_wepkeyid(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_WEP_KEY_ID, 0));
}
static boolean_t
do_get_signal(int fd)
{
	PRTDBG(("do_get_signal(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_RSSI, 0));
}

static boolean_t
do_get_radioon(int fd)
{
	PRTDBG(("do_get_radioon(%d)\n", fd));
	return (call_ioctl(fd, WLAN_GET_PARAM, WL_RADIO, 0));
}

/*
 * param has two kinds of forms:
 * 'wepkeyn=*****' (when equalflag == B_TRUE),
 * 'wepkeyn' (when equalflag == B_FALSE)
 */
static boolean_t
param_is_wepkey(char *param, boolean_t equalflag)
{
	if ((equalflag == B_FALSE) &&
	    (strcmp(param, "wepkey1") == 0) ||
	    (strcmp(param, "wepkey2") == 0) ||
	    (strcmp(param, "wepkey3") == 0) ||
	    (strcmp(param, "wepkey4") == 0))
		return (B_TRUE);
	else if ((equalflag == B_TRUE) &&
	    (strncmp(param, "wepkey1=", strlen("wepkey1="))) == 0 ||
	    (strncmp(param, "wepkey2=", strlen("wepkey2="))) == 0 ||
	    (strncmp(param, "wepkey3=", strlen("wepkey3="))) == 0 ||
	    (strncmp(param, "wepkey4=", strlen("wepkey4="))) == 0)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * update/add items in the profile
 */
static boolean_t
items_in_profile(aelist_t *cplist, aelist_t *wplist, int argc, char **argv)
{
	int i = 0, j = 0;
	char *param;
	char *pequal;
	const char *wepkey;

	for (i = 0; i < argc; i++) {
		if (param_is_wepkey(argv[i], B_TRUE) == B_TRUE) {
			wepkey = get_value(argv[i]);
			if (value_is_valid(WEPKEY, wepkey) == B_FALSE) {
				(void) fprintf(stderr, gettext("%s: "
				    "invalid value '%s' for parameter "
				    "'wepkey'\n"), gExecName, wepkey);
				return (B_FALSE);
			}
			update_aelist(wplist, argv[i]);
			continue;
		}
		param = safe_strdup(argv[i]);
		pequal = strchr(param, '=');
		if (pequal == NULL) {
			(void) fprintf(stderr, gettext("%s: "
			    "invalid argument '%s', use "
			    "parameter=value'\n"),
			    gExecName, argv[i]);
			free(param);
			return (B_FALSE);
		}

		*pequal++ = '\0';
		for (j = 0; j < N_GS_FUNC; j++) {
			if (strcmp(param, do_gs_func[j].cmd) == 0) {
				break;
			}
		}
		if (j == N_GS_FUNC) {
			(void) fprintf(stderr, gettext("%s: "
			    "unrecognized parameter '%s'\n"),
			    gExecName, param);
			free(param);
			return (B_FALSE);
		}
		if (value_is_valid(do_gs_func[j].index, pequal) ==
		    B_FALSE) {
			(void) fprintf(stderr, gettext("%s: "
			    "invalid value '%s' for parameter '%s'\n"),
			    gExecName, pequal, param);
			return (B_FALSE);
		}
		free(param);
		update_aelist(cplist, argv[i]);
	}
	return (B_TRUE);
}

/*
 * do_createprofile: Called when create a profile off-line.
 */
/*ARGSUSED*/
static boolean_t
do_createprofile(int fd, int argc, char **argv)
{
	int i = 0;
	char *pbuf = NULL;
	char *pfbuf = NULL;
	const char *profilename;
	aelist_t *plist_config = NULL, *plist_wepkey = NULL;

	PRTDBG(("do_createprofile(%d, 0x%x)\n", argc, argv));
	if (argc <= 0) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}
	/*
	 * When creating a profile, if the profile name is not specified,
	 * the essid is selected as the profile name. the paramters are
	 * saved into the section.
	 */
	if (strchr(argv[0], '=') == NULL) {
		pfbuf = safe_strdup(argv[0]);
		argc--;
		argv++;
	}
	for (i = 0; i < argc; i++) {
		if (strncmp(argv[i], "essid=", strlen("essid=")) == 0) {
			break;
		}
	}
	if (i == argc) {
		(void) fprintf(stderr,
		    gettext("%s: "
		    "essid required when creating profile\n"),
		    gExecName);
		goto exit0;
	}
	profilename = (pfbuf ? pfbuf : get_value(argv[i]));
	if (strlen(profilename) == 0) {
		(void) fprintf(stderr,
		    gettext("%s: "
		    "non-empty essid required\n"),
		    gExecName);
		goto exit0;
	}
	/*
	 * 'all', '{preference}', '{history}', '{active_profile}'
	 * and any string with '[' as start and ']' as end should
	 * not be a profile name
	 */
	if ((strcasecmp(profilename, "all") == 0) ||
	    (strcmp(profilename, WIFI_HISTORY) == 0) ||
	    (strcmp(profilename, WIFI_PREFER) == 0) ||
	    (strcmp(profilename, WIFI_ACTIVEP) == 0) ||
	    ((profilename[0] == '[') &&
	    (profilename[strlen(profilename) - 1] == ']'))) {
		(void) fprintf(stderr, gettext("%s: "
		    "'%s' is an invalid profile name\n"),
		    gExecName, profilename);
		goto exit0;
	}
	pbuf = append_pa(profilename);

	PRTDBG(("do_createprofile: profile_name = %s\n", pbuf));
	if ((find_section(gp_config_file, pbuf) != NULL) ||
	    find_section(gp_wepkey_file, pbuf) != NULL) {
		(void) fprintf(stderr,
		    gettext("%s: "
		    "profile '%s' already exists\n"),
		    gExecName, profilename);
		goto exit1;
	}
	/*
	 * Save each parameters in the profile.
	 */
	plist_config = new_ael(PROFILE);
	new_section(gp_config_file, plist_config, pbuf);
	plist_wepkey = new_ael(PROFILE);
	new_section(gp_wepkey_file, plist_wepkey, pbuf);
	free(pfbuf);
	free(pbuf);
	return (items_in_profile(plist_config, plist_wepkey,
	    argc, argv));
exit1:
	free(pbuf);
exit0:
	free(pfbuf);
	return (B_FALSE);
}

/*ARGSUSED*/
static boolean_t
do_setprofparam(int fd, int argc, char **argv)
{
	char *pbuf = NULL;
	section_t *psection_config = NULL, *psection_wep = NULL;
	aelist_t *plist_config = NULL, *plist_wepkey = NULL;

	PRTDBG(("do_setprofparam(%d, 0x%x)\n", argc, argv));
	if (argc < 1) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}
	pbuf = append_pa(argv[0]);

	psection_config = find_section(gp_config_file, pbuf);
	psection_wep = find_section(gp_wepkey_file, pbuf);
	if ((psection_config == NULL) || (psection_wep == NULL)) {
		(void) fprintf(stderr, gettext("%s: "
		    "profile '%s' doesn't exist\n"),
		    gExecName, argv[0]);
		free(pbuf);
		return (B_FALSE);
	}
	free(pbuf);
	/*
	 * modify each parameters in the profile.
	 */
	plist_config = psection_config->list;
	plist_wepkey = psection_wep->list;
	argc--;
	argv++;
	return (items_in_profile(plist_config, plist_wepkey,
	    argc, argv));
}

/*ARGSUSED*/
static boolean_t
do_getprofparam(int fd, int argc, char **argv)
{
	int i = 0, j = 0;
	int flag;
	boolean_t ret = B_TRUE;
	section_t *p_section = NULL;
	aelist_t *plist = NULL;
	ae_t *pae = NULL;
	char *pbuf = NULL;

	PRTDBG(("do_getprofparam(%d, 0x%x)\n", argc, argv));
	if (argc < 1) {
		do_print_usage();
		exit(WIFI_IMPROPER_USE);
	}
	pbuf = append_pa(argv[0]);
	p_section = find_section(gp_config_file, pbuf);
	if (p_section == NULL) {
		(void) fprintf(stderr, gettext("%s: "
		    "profile '%s' doesn't exist\n"),
		    gExecName, argv[0]);
		ret = B_FALSE;
		goto exit0;
	}
	argc--;
	argv++;

	plist = p_section->list;
	assert(plist != NULL);
	/*
	 * If no specific parameter typed, we print out all parameters
	 */
	if (argc == 0) {
		pae = plist->ael_head;
		while (pae != NULL) {
			if (pae->ae_arg != NULL) {
				(void) printf("\t%s\n", pae->ae_arg);
			}
			pae = pae->ae_next;
		}
		print_wepkey_info(p_section->section_id, NULL);
		ret = B_TRUE;
		goto exit0;
	}

	/*
	 * Match function with do_gs_func[] table, and print its result
	 */
	for (i = 0; i < argc; i++) {
		flag = 0;
		for (j = 0; j < N_GS_FUNC; j++) {
			if (strcmp(argv[i], do_gs_func[j].cmd) == 0) {
				break;
			}
			if (param_is_wepkey(argv[i], B_FALSE) == B_TRUE) {
				j = WEPKEY;
				print_wepkey_info(p_section->section_id,
				    argv[i]);
				flag++;
				break;
			}
		}
		if (j == N_GS_FUNC) {
			(void) fprintf(stderr,
			    gettext("wificonifg: unrecognized parameter: "
			    "%s\n"), argv[i]);
			ret = B_FALSE;
			goto exit0;
		}

		pae = plist->ael_head;
		while ((pae != NULL) && (!flag)) {
			if ((pae->ae_arg != NULL) &&
			    (strncmp(pae->ae_arg, argv[i],
			    strlen(argv[i])) == 0)) {
				(void) printf("\t%s\n", pae->ae_arg);
				flag++;
			}
			pae = pae->ae_next;
		}
		if (!flag) {
			(void) fprintf(stderr, gettext("%s: "
			    "parameter '%s' has not been set in profile %s\n"),
			    gExecName, argv[i], pbuf);
			ret = B_FALSE;
			goto exit0;
		}
	}
exit0:
	free(pbuf);
	return (ret);
}

/*
 * Verify whether the value in the parameter=value pair is valid or not.
 * For the channel, since we donot know what kind of wifi card(a,b,or g)
 * is in the system, so we just leave to verify the validity of the value
 * when the value is set to the card.
 * The same goes for the rates.
 */
static boolean_t
value_is_valid(config_item_t item, const char *value)
{
	uint32_t num = 0;
	uint8_t *rates;
	boolean_t ret;

	assert(value != NULL);
	switch (item) {
	case ESSID:
		if (strlen(value) > 32)
			ret = B_FALSE;
		else
			ret = B_TRUE;
		break;
	case BSSTYPE:
		if ((strcasecmp(value, "bss") == 0) ||
		    (strcasecmp(value, "ap") == 0) ||
		    (strcasecmp(value, "infrastructure") == 0) ||
		    (strcasecmp(value, "ibss") == 0) ||
		    (strcasecmp(value, "ad-hoc") == 0) ||
		    (strcasecmp(value, "auto") == 0))
			ret = B_TRUE;
		else
			ret = B_FALSE;
		break;
	case CREATEIBSS:
		if ((strcasecmp(value, "yes") == 0) ||
		    (strcasecmp(value, "no") == 0))
			ret = B_TRUE;
		else
			ret = B_FALSE;
		break;
	case AUTHMODE:
		if ((strcasecmp(value, "opensystem") == 0) ||
		    (strcasecmp(value, "shared_key") == 0))
			ret = B_TRUE;
		else
			ret = B_FALSE;
		break;
	case POWERMODE:
		if ((strcasecmp(value, "off") == 0) ||
		    (strcasecmp(value, "mps") == 0) ||
		    (strcasecmp(value, "fast") == 0))
			ret = B_TRUE;
		else
			ret = B_FALSE;
		break;
	case ENCRYPTION:
		if ((strcasecmp(value, "wep") == 0) ||
		    (strcasecmp(value, "none") == 0))
			ret = B_TRUE;
		else
			ret = B_FALSE;
		break;
	case RADIOON:
		if ((strcasecmp(value, "on") == 0) ||
		    (strcasecmp(value, "off") == 0))
			ret = B_TRUE;
		else
			ret = B_FALSE;
		break;
	case WEPKEYID:
		ret = is_wepkeyindex_valid(value);
		break;
	case WEPKEY:
		ret = is_wepkey_valid(value, strlen(value));
		break;
	case CHANNEL:
		ret = is_channel_valid(value);
		break;
	case RATES:
		rates = get_rates(value, &num);
		if (rates == NULL) {
			ret = B_FALSE;
		} else {
			free(rates);
			ret = B_TRUE;
		}
		break;
	default:
		ret = B_FALSE;
		break;
	}

	return (ret);
}

/*
 * do_set: Called when set a parameter, the format should be
 * parameter=value.
 */
static boolean_t
do_set(int fd, int argc, char **argv)
{
	int i = 0, j = 0;
	char *param;
	char *pequal;
	char *value;
	boolean_t ret;

	PRTDBG(("do_set(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);
	if (argc <= 0) {
		(void) do_print_support_params(fd);
		ret = B_FALSE;
		goto exit0;
	}
	/*
	 * Set each parameters, if one failed, others behind it will
	 * not be set
	 */
	for (i = 0; i < argc; i++) {
		/*
		 * Separate param and its value, if the user types "param=",
		 * then value will be set to "";if the user types "param",
		 * it is an error.
		 */
		param = safe_strdup(argv[i]);
		pequal = strchr(param, '=');
		value = NULL;
		if (pequal != NULL) {
			*pequal = '\0';
			value = pequal + 1;
		} else {
			(void) fprintf(stderr,
			    gettext("%s: invalid setparam argument "
			    "'%s', use 'parameter=value'\n"),
			    gExecName, argv[i]);
			free(param);
			ret = B_FALSE;
			goto exit0;
		}
		PRTDBG(("do_set: param = \"%s\", value = \"%s\"\n",
		    param, value));
		for (j = 0; j < N_GS_FUNC; j++) {
			/*
			 * Match each parameters with do_gs_func table,
			 */
			if (strcmp(param, do_gs_func[j].cmd) == 0)
				break;
			if (param_is_wepkey(param, B_FALSE) == B_TRUE) {
				value = argv[i];
				j = WEPKEY;
				break;
			}
		}
		if (j == N_GS_FUNC) {
			(void) fprintf(stderr,
			    gettext("%s: unrecognized parameter: "
			    "%s\n"), gExecName, param);
			free(param);
			ret  = B_FALSE;
			goto exit0;
		}

		if (do_gs_func[j].p_do_set_func == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: parameter '%s' is read-only\n"),
			    gExecName, do_gs_func[j].cmd);
			free(param);
			ret = B_FALSE;
			goto exit0;
		}
		if (do_gs_func[j].p_do_set_func(fd, value)
		    == B_TRUE) {
			ret = B_TRUE;
		} else {
			if (gbuf->wldp_result != WL_SUCCESS) {
				(void) fprintf(stderr,
				    gettext("%s: "
				    "failed to set '%s' for "),
				    gExecName, param);
				print_error(gbuf->wldp_result);
			}
			free(param);
			ret = B_FALSE;
			goto exit0;
		}
		free(param);
	}
exit0:
	return (ret);
}

static boolean_t
do_get(int fd, int argc, char **argv)
{
	int i = 0, j = 0, n = 0;
	boolean_t ret = B_TRUE;

	PRTDBG(("do_get(%d, 0x%x)\n", argc, argv));
	assert(fd > 0);
	/*
	 * If no specific parameter typed, we print out all parameters
	 */
	if (argc <= 0) {
		for (i = 0; i < N_GS_FUNC; i++) {
			if ((do_gs_func[i].p_do_get_func != NULL) &&
			    (do_gs_func[i].p_do_get_func(fd)
			    == B_TRUE)) {
				print_gbuf(do_gs_func[i].index);
				n++;
			}
		}
		ret = n ? B_TRUE:B_FALSE;
		goto exit0;
	}
	/*
	 * Match function with do_gs_func[] table, and print its result
	 */
	for (i = 0; i < argc; i++) {
		for (j = 0; j < N_GS_FUNC; j++) {
			if (strcmp(argv[i], do_gs_func[j].cmd) == 0) {
				break;
			}
			if (param_is_wepkey(argv[i], B_FALSE) == B_TRUE) {
				j = WEPKEY;
				break;
			}
		}
		if (j == N_GS_FUNC) {
			(void) fprintf(stderr,
			    gettext("wificonifg: unrecognized parameter: "
			    "%s\n"), argv[i]);
			ret = B_FALSE;
			goto exit0;
		}
		if (do_gs_func[j].p_do_get_func == NULL) {
			(void) fprintf(stderr,
			    gettext("%s: parameter '%s' is write-only\n"),
			    gExecName, do_gs_func[j].cmd);
			ret = B_FALSE;
			goto exit0;
		}
		if (do_gs_func[j].p_do_get_func(fd) == B_TRUE) {
			print_gbuf(do_gs_func[j].index);
			ret = B_TRUE;
		} else {
			(void) fprintf(stderr,
			    gettext("%s: "
			    "failed to read parameter '%s' : "),
			    gExecName, argv[i]);
			print_error(gbuf->wldp_result);
			ret = B_FALSE;
		}
	}
exit0:
	return (ret);
}

/*
 * Only one wificonfig is running at one time.
 * The following wificonfig which tries to be run will return error,
 * and the pid of the process will own the filelock will be printed out.
 */
static pid_t
enter_wifi_lock(int *fd)
{
	int fd0 = -1;
	struct flock lock;

	fd0 = open(WIFI_LOCKF, O_CREAT|O_WRONLY, 0600);
	if (fd0 < 0) {
		(void) fprintf(stderr, gettext("%s: failed to open lockfile"
		    " '"WIFI_LOCKF"': %s\n"), gExecName, strerror(errno));
		exit(WIFI_FATAL_ERR);
	}

	*fd = fd0;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if ((fcntl(fd0, F_SETLK, &lock) == -1) &&
	    (errno == EAGAIN || errno == EDEADLK)) {
		if (fcntl(fd0, F_GETLK, &lock) == -1) {
			(void) fprintf(stderr,
			    gettext("%s: enter_filelock"));
			exit(WIFI_FATAL_ERR);
		}
		(void) fprintf(stderr, gettext("%s:"
		    "enter_filelock:filelock is owned "
		    "by 'process %d'\n"), gExecName, lock.l_pid);
		return (lock.l_pid);
	}

	return (getpid());
}

static void
exit_wifi_lock(int fd)
{
	struct flock lock;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;
	if (fcntl(fd, F_SETLK, &lock) == -1) {
		(void) fprintf(stderr, gettext("%s: failed to"
		    " exit_filelock: %s\n"),
		    gExecName, strerror(errno));
	}
	(void) close(fd);
}

int
main(int argc, char **argv)
{
	int i, ret;
	int fddev = -1;
	int c, iflag = 0, rflag = 0, fileonly = 0, readonly = 0;
	int fd;
	char *iname = NULL;
	char *path = NULL;
	extern char *optarg;
	extern int optind;
	char interface[LIFNAMSIZ];
	char file_wifi[MAX_CONFIG_FILE_LENGTH];
	char file_wifiwepkey[MAX_CONFIG_FILE_LENGTH];
	priv_set_t *ppriv;
	wifi_auth_t autht;

	PRTDBG(("main(%d, 0x%x)\n", argc, argv));
	PRTDBG(("uid=%d\n", getuid()));
	PRTDBG(("euid=%d\n", geteuid()));

#ifdef DEBUG
	if (wifi_debug == 1) { /* for debuf purpose only */
		(void) printf("Press RETURN to continue...\n");
		(void) getchar();
	}
#endif
	ret = WIFI_EXIT_DEF;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	gExecName = argv[0];

	gbuf = safe_malloc(MAX_BUF_LEN);

	if ((ppriv = priv_str_to_set("basic", ",", NULL)) == NULL) {
		PRTDBG(("main: priviledge init error\n"));
		(void) fprintf(stderr, gettext("%s: "
		    "set priviledge to 'basic' error\n"),
		    gExecName);
		ret = WIFI_FATAL_ERR;
		goto exit0;
	}
	(void) priv_addset(ppriv, PRIV_NET_RAWACCESS);
	(void) priv_addset(ppriv, PRIV_SYS_NET_CONFIG);
	if (setppriv(PRIV_SET, PRIV_PERMITTED, ppriv) == -1) {
		(void) fprintf(stderr, gettext("%s: "
		    "set permitted priviledge: %s\n"),
		    gExecName, strerror(errno));
		ret = WIFI_FATAL_ERR;
		goto exit0;
	}
	if (setppriv(PRIV_SET, PRIV_LIMIT, ppriv) == -1) {
		(void) fprintf(stderr, gettext("%s: "
		    "set limit priviledge: %s\n"),
		    gExecName, strerror(errno));
		ret = WIFI_FATAL_ERR;
		goto exit0;
	}
	if (setppriv(PRIV_SET, PRIV_INHERITABLE, ppriv) == -1) {
		(void) fprintf(stderr, gettext("%s: "
		    "set inherit priviledge: %s\n"),
		    gExecName, strerror(errno));
		ret = WIFI_FATAL_ERR;
		goto exit0;
	}
	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, ppriv) == -1) {
		(void) fprintf(stderr, gettext("%s: "
		    "set effective priviledge: %s\n"),
		    gExecName, strerror(errno));
		ret = WIFI_FATAL_ERR;
		goto exit0;
	}
	priv_freeset(ppriv);

	for (i = 0; i < argc; i++) {
		PRTDBG(("%d\t\t\"%s\"\n", i, argv[i]));
	}

	while ((c = getopt(argc, argv, "i:R:")) != EOF) {
		switch (c) {
		case 'i':
			if (iflag) {
				do_print_usage();
				ret = WIFI_IMPROPER_USE;
				goto exit0;
			}
			iflag = 1;
			iname = optarg;
			break;
		case 'R':
			if (rflag) {
				do_print_usage();
				ret = WIFI_IMPROPER_USE;
				goto exit0;
			}
			rflag = 1;
			path = optarg;
			break;
		case '?':
		default:
			do_print_usage();
			ret = WIFI_IMPROPER_USE;
			goto exit0;
		}
	}
	argc -= optind;
	argv +=	optind;

	if (argc <= 0) {
		if (iname) {
			if ((fddev = open_dev(iname)) == -1) {
				ret = WIFI_FATAL_ERR;
				goto exit0;
			}
			if (do_print_support_params(fddev) ==
			    B_TRUE)
				ret = WIFI_EXIT_DEF;
			else
				ret = WIFI_FATAL_ERR;
			goto exit1;
		} else {
			do_print_usage();
			ret = WIFI_IMPROPER_USE;
			goto exit0;
		}
	}

	for (i = 0; i < N_FUNC; i++) {
		if (strcmp(argv[0], do_func[i].cmd) == 0) {
			autht = ((strcmp(argv[0], "setwepkey") == 0) ||
			    (strcmp(argv[0], "setprofwepkey") == 0)) ?
			    AUTH_WEP:AUTH_OTHER;
			if (do_func[i].b_auth &&
			    !check_authority(autht)) {
				ret = WIFI_FATAL_ERR;
				goto exit0;
			}
			if (do_func[i].b_fileonly)
				fileonly++;
			if (do_func[i].b_readonly)
				readonly++;
			break;
		}
	}
	if (i == N_FUNC) {
		(void) fprintf(stderr, gettext("%s: unrecognized "
		    "subcommand: %s\n"), gExecName, argv[0]);
		do_print_usage();
		ret = WIFI_IMPROPER_USE;
		goto exit0;
	}
	if ((fileonly) && (iname)) {
		do_print_usage();
		ret = WIFI_IMPROPER_USE;
		goto exit0;
	}
	if ((!fileonly) && (!iname)) {
		if (search_interface(interface) != B_TRUE) {
			(void) fprintf(stderr, gettext("%s: "
			    "failed to find the default wifi interface;"
			    " -i option should be used to specify the "
			    "wifi interface\n"), gExecName);
			ret = WIFI_FATAL_ERR;
			goto exit0;
		}
		iname = interface;
	}
	if (iname) {
		if ((fddev = open_dev(iname)) == -1) {
			ret = WIFI_FATAL_ERR;
			goto exit0;
		}
	}
	if (rflag) {
		safe_snprintf(file_wifi, sizeof (file_wifi),
		    "%s%s", path, p_file_wifi);
		safe_snprintf(file_wifiwepkey, sizeof (file_wifiwepkey),
		    "%s%s", path, p_file_wifiwepkey);
	} else {
		safe_snprintf(file_wifi, sizeof (file_wifi),
		    "%s", p_file_wifi);
		safe_snprintf(file_wifiwepkey, sizeof (file_wifiwepkey),
		    "%s", p_file_wifiwepkey);
	}
	/*
	 * There is an occasion when more than one wificonfig processes
	 * which attempt to write the <wifi> and <wifiwepkey> files are
	 * running. We must be able to avoid this.
	 * We use file lock here to implement this.
	 */
	if ((!readonly) && (enter_wifi_lock(&fd) != getpid())) {
		ret = WIFI_FATAL_ERR;
		goto exit1;
	}
	gp_config_file = parse_file(file_wifi);
	if (gp_config_file == NULL) {
		ret = WIFI_FATAL_ERR;
		goto exit2;
	}

	gp_wepkey_file = parse_file(file_wifiwepkey);
	if (gp_wepkey_file == NULL) {
		destroy_config(gp_config_file);
		ret = WIFI_FATAL_ERR;
		goto exit2;
	}
	if (do_func[i].p_do_func(fddev, argc-1, argv+1)
	    == B_TRUE) {
		/*
		 * can not write file when startconfing
		 * during boot
		 */
		if (do_func[i].b_readonly)
			ret = WIFI_EXIT_DEF;
		else if ((fprint_config_file(gp_config_file,
		    file_wifi) != B_TRUE) ||
		    (fprint_config_file(gp_wepkey_file,
		    file_wifiwepkey) != B_TRUE))
			ret = WIFI_FATAL_ERR;
		else
			ret = WIFI_EXIT_DEF;
	} else {
		PRTDBG(("Command %s failed\n", argv[0]));
		ret = WIFI_FATAL_ERR;
	}
	destroy_config(gp_wepkey_file);
	destroy_config(gp_config_file);
exit2:
	if (!readonly)
		exit_wifi_lock(fd);
exit1:
	if (iname)
		(void) close(fddev);
exit0:
	free(gbuf);
	return (ret);
}

#ifdef DEBUG
static void
wifi_dbgprintf(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	(void) vfprintf(stdout, fmt, ap);
	va_end(ap);
}
#endif
