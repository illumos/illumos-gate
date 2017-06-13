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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <libintl.h>
#include <locale.h>
#include <fcntl.h>
#include <libdlpi.h>
#include <libdladm.h>
#include <libdlib.h>
#include <libdllink.h>
#include <sys/ib/ibnex/ibnex_devctl.h>

#define	DATADM_OP_VIEW		0x0000
#define	DATADM_OP_UPDATE	0x0001
#define	DATADM_OP_ADD		0x0002
#define	DATADM_OP_REMOVE	0x0003
#define	DATADM_NUM_OPS		0x0004
#define	DATADM_DAT_CONF		"/etc/dat/dat.conf"
#define	DATADM_LINESZ		1024
#define	DATADM_NUM_SP_TOKENS	7
#define	DATADM_NUM_DAT_TOKENS	8
#define	DATADM_DRV_NAME		"driver_name"
#define	DATADM_MAX_TOKENS	16

/*
 * generic entry
 * placed at the top of all entry types
 */
typedef struct datadm_entry {
	struct datadm_entry	*de_next;
} datadm_entry_t;

/*
 * list structure
 * can be manipulated using datadm_walk_list or
 * datadm_enqueue_entry
 */
typedef struct datadm_list {
	datadm_entry_t		*dl_head;
	datadm_entry_t		*dl_tail;
	uint_t			dl_count;
} datadm_list_t;

/*
 * internal representation of the version string in
 * dat.conf or service_provider.conf. the format is
 * <dv_name><dv_major>.<dv_minor>
 */
typedef struct datadm_version {
	char	*dv_name;
	uint_t	dv_major;
	uint_t	dv_minor;
} datadm_version_t;

/*
 * each sp_entry corresponds to an entry in dat.conf or
 * service_provider.conf. an sp_entry is processed by the
 * function datadm_process_sp_entry.
 */
typedef struct datadm_sp_entry {
	datadm_entry_t		spe_header;
	char			*spe_devname;
	datadm_version_t	spe_api_version;
	int			spe_threadsafe;
	int			spe_default;
	char			*spe_libpath;
	datadm_version_t	spe_sp_version;
	char			*spe_sp_data;
	int			spe_invalid;
} datadm_sp_entry_t;

/*
 * an hca_entry is created whenever a new hca device is
 * encountered during sp_entry processing. this structure
 * contains two lists. the sp_list holds sp entries that
 * are added when sp entry processing occurs. duplicate
 * sp entries are not added to this list. the ia_list may
 * be built statically using the information in dat.conf or
 * dynamically. similar to the sp_list,
 * the ia_list contains only unique entries.
 */
typedef struct datadm_hca_entry {
	datadm_entry_t		he_header;
	char			*he_name;
	datadm_list_t		he_sp_list;
	datadm_list_t		he_ia_list;
} datadm_hca_entry_t;

/*
 * an ia_entry is created when a new ia name is encountered
 * during sp_entry processing or when a new ia name is
 * discovered by datadm_build_ia_lists. ia_entry holds the ia
 * device's instance number.
 */
typedef struct datadm_ia_entry {
	datadm_entry_t		iae_header;
	char			iae_name[MAXLINKNAMELEN];
} datadm_ia_entry_t;

/*
 * a comment entry represents one of the comment lines at the
 * top of dat.conf. a list of these lines are saved during the
 * parsing of dat.conf. these lines are written back to dat.conf
 * when dat.conf gets regenerated.
 */
typedef struct datadm_cmnt_entry {
	datadm_entry_t		cmnt_header;
	char			*cmnt_line;
} datadm_cmnt_entry_t;

typedef struct datadm_hca_find_by_name {
	char			*hf_name;
	datadm_hca_entry_t	*hf_hca_entry;
} datadm_hca_find_by_name_t;

/*
 * 2nd argument to datadm_hca_entry_find.
 * hf_hca_entry is filled in if an hca_entry with
 * a matching he_name is found.
 */
typedef struct datadm_hca_find {
	datadm_sp_entry_t	*hf_sp_entry;
	datadm_hca_entry_t	*hf_hca_entry;
} datadm_hca_find_t;

/*
 * 2nd argument to datadm_ia_entry_find.
 * if_ia_entry is filled in if an ia_entry with
 * a matching ia_name is found.
 */
typedef struct datadm_ia_find {
	char			*if_ia_name;
	datadm_ia_entry_t	*if_ia_entry;
} datadm_ia_find_t;

/*
 * this gets passed to datadm_add_plink.
 */
typedef struct datadm_fill_ia_list {
	datadm_list_t		*ia_hca_list;
	dladm_handle_t		ia_dlh;
	int			ia_ibnex_fd;
	int			ia_sock_fd_v4;
	int			ia_sock_fd_v6;
} datadm_fill_ia_list_t;

/*
 * this defines the commandline parameters specified
 * by the user.
 */
typedef struct datadm_args {
	char			*da_sp_conf;
	char			*da_dat_conf;
	int			da_op_type;
} datadm_args_t;

static datadm_args_t		datadm_args;
static datadm_list_t		datadm_conf_header;
static char			*datadm_conf_header_default =
	"#\n"
	"# Copyright (c) 2003, 2010, Oracle and/or its affiliates. "
	"All rights reserved.\n"
	"#\n"
	"# DAT configuration file.\n"
	"#\n"
	"# This file is updated using the datadm(1) command.\n"
	"# Do not hand edit this file.\n"
	"# See datadm(1) man page for more details.\n"
	"#\n"
	"# The fields in this file are -\n"
	"#\n"
	"# IAname version threadsafe default library-path provider-version \\\n"
	"# instance-data platform-information\n"
	"#\n";

/*
 * common parsing functions.
 */
typedef int (*datadm_parse_func_t)(char *, void *);
static int datadm_parse_line(char *, char *[], int *);
static int datadm_parse_generic_str(char *, char **);
static int datadm_parse_nonnull_str(char *, char **);
static int datadm_parse_version(char *, datadm_version_t *);
static int datadm_parse_devname(char *, datadm_sp_entry_t *);
static int datadm_parse_api_version(char *, datadm_sp_entry_t *);
static int datadm_parse_threadsafe(char *, datadm_sp_entry_t *);
static int datadm_parse_default(char *, datadm_sp_entry_t *);
static int datadm_parse_libpath(char *, datadm_sp_entry_t *);
static int datadm_parse_sp_version(char *, datadm_sp_entry_t *);
static int datadm_parse_sp_data(char *, datadm_sp_entry_t *);
static int datadm_parse_ia_name(char *, char *);

/*
 * utility functions
 */
static void datadm_enqueue_entry(datadm_list_t *, datadm_entry_t *);
static int datadm_walk_list(datadm_list_t *,
    int (*)(datadm_entry_t *, void *), void *);
static int datadm_str_match(char *, char *);
static int datadm_version_match(datadm_version_t *, datadm_version_t *);
static int datadm_sp_entry_match(datadm_sp_entry_t *, datadm_sp_entry_t *);

/*
 * entry allocation/deallocation
 */
static datadm_sp_entry_t *datadm_alloc_sp_entry(void);
static datadm_ia_entry_t *datadm_alloc_ia_entry(void);
static datadm_hca_entry_t *datadm_alloc_hca_entry(void);
static datadm_cmnt_entry_t *datadm_alloc_cmnt_entry(void);
static void datadm_free_sp_entry(datadm_sp_entry_t *);
static void datadm_free_ia_entry(datadm_ia_entry_t *);
static void datadm_free_hca_entry(datadm_hca_entry_t *);
static void datadm_free_cmnt_entry(datadm_cmnt_entry_t *);


/*
 * high level parsing functions
 */
static int datadm_parse_sp_conf(datadm_list_t *);
static int datadm_parse_dat_conf(datadm_list_t *);
static int datadm_process_sp_entry(datadm_list_t *, datadm_sp_entry_t *,
    char *);

/*
 * ia devices discovery
 */
static int datadm_build_ia_lists(datadm_list_t *);

/*
 * helper function for OP_REMOVE
 */
static void datadm_invalidate_common_sp_entries(datadm_list_t *,
    datadm_list_t *);

/*
 * output generation
 */
static int datadm_generate_dat_conf(datadm_list_t *);
static int datadm_generate_conf_header(FILE *);
static int datadm_generate_conf_entry(FILE *, datadm_ia_entry_t *,
    datadm_sp_entry_t *);

/*
 * datadm operations
 */
static int datadm_view(void);
static int datadm_update(void);
static int datadm_add(void);
static int datadm_remove(void);

/*
 * usage
 */
static void datadm_usage(void);


/*
 * parse function tables
 */
static datadm_parse_func_t datadm_sp_parse_funcs[DATADM_NUM_SP_TOKENS] = {
	(datadm_parse_func_t)datadm_parse_devname,
	(datadm_parse_func_t)datadm_parse_api_version,
	(datadm_parse_func_t)datadm_parse_threadsafe,
	(datadm_parse_func_t)datadm_parse_default,
	(datadm_parse_func_t)datadm_parse_libpath,
	(datadm_parse_func_t)datadm_parse_sp_version,
	(datadm_parse_func_t)datadm_parse_sp_data
};

static datadm_parse_func_t datadm_dat_parse_funcs[DATADM_NUM_DAT_TOKENS] = {
	(datadm_parse_func_t)datadm_parse_ia_name,
	(datadm_parse_func_t)datadm_parse_api_version,
	(datadm_parse_func_t)datadm_parse_threadsafe,
	(datadm_parse_func_t)datadm_parse_default,
	(datadm_parse_func_t)datadm_parse_libpath,
	(datadm_parse_func_t)datadm_parse_sp_version,
	(datadm_parse_func_t)datadm_parse_sp_data,
	(datadm_parse_func_t)datadm_parse_devname
};

/*
 * operation table
 */
static int (*datadm_ops[DATADM_NUM_OPS])(void) = {
	datadm_view,
	datadm_update,
	datadm_add,
	datadm_remove
};

static void
datadm_usage(void)
{
	(void) fprintf(stderr, gettext(
	    "usage: datadm -v\n"
	    "              -u\n"
	    "              -a <service_provider.conf>\n"
	    "              -r <service_provider.conf>\n"));
}

static int
datadm_parse_generic_str(char *str, char **strptr)
{
	int	len;

	len = strlen(str);
	*strptr = (char *)malloc(len + 1);
	if (*strptr == NULL) {
		return (-1);
	}
	(void) strcpy(*strptr, str);
	return (0);
}

/*
 * this function strips off leading and trailing
 * whitespaces and returns an error for null or
 * empty strings.
 */
static int
datadm_parse_nonnull_str(char *str, char **strptr)
{
	int	len, i;
	char	*start;

	if (str[0] == '\0') {
		return (-1);
	}
	start = str;
	for (i = 0; str[i] != '\0'; i++) {
		if (!isspace(str[i])) {
			start = &str[i];
			break;
		}
	}
	for (; str[i] != '\0'; i++) {
		if (isspace(str[i])) {
			str[i] = '\0';
		}
	}
	len = strlen(start);
	*strptr = (char *)malloc(len + 1);
	if (*strptr == NULL) {
		return (-1);
	}
	(void) strcpy(*strptr, start);
	return (0);
}

/*
 * parses the api_version and sp_version fields in
 * dat.conf and service_provider.conf
 */
static int
datadm_parse_version(char *str, datadm_version_t *version)
{
	int	i = 0, len;
	int	major_idx, minor_idx;

	len = strlen(str);

	for (i = 0; i < len; i++) {
		if (isdigit(str[i])) break;
	}
	if (i == len) {
		return (-1);
	}
	if (i > 0) {
		version->dv_name = (char *)malloc(i + 1);
		bcopy(str, version->dv_name, i);
		version->dv_name[i] = '\0';
	} else {
		version->dv_name = NULL;
	}
	major_idx = i;

	for (; i < len; i++) {
		if (!isdigit(str[i])) break;
	}
	if (i == len) {
		return (-1);
	}
	if (str[i] != '.') {
		return (-1);
	}
	minor_idx = ++i;
	if (i == len) {
		return (-1);
	}
	for (; i < len; i++) {
		if (!isdigit(str[i])) break;
	}
	if (i != len) {
		return (-1);
	}
	version->dv_major = atoi(str + major_idx);
	version->dv_minor = atoi(str + minor_idx);
	return (0);
}

/*
 * parses the ia_name field in dat.conf
 */
static int
datadm_parse_ia_name(char *str, char *ia_name)
{
	if (strlen(str) >= MAXLINKNAMELEN)
		return (-1);
	(void) strlcpy(ia_name, str, MAXLINKNAMELEN);
	return (0);
}

/*
 * parses the device name, strips leading and trailing spaces.
 * the format should be "driver_name=<dev_name>"
 */
static int
datadm_parse_devname(char *str, datadm_sp_entry_t *sp_entry)
{
	int	len, dlen, i, j = 0;
	char	*drv_name = DATADM_DRV_NAME;

	len = strlen(str);
	dlen = strlen(drv_name);

	/*
	 * strip out leading spaces and try to match
	 * the expected string
	 */
	for (i = 0; i < len; i++) {
		if (isspace(str[i]) && j == 0) {
			continue;
		} else {
			if (str[i] == drv_name[j]) {
				j++;
				if (j == dlen) {
					break;
				} else {
					continue;
				}
			} else {
				break;
			}
		}
	}

	/*
	 * j must be dlen if the matching string is found
	 */
	if (j != dlen) {
		return (-1);
	}

	/*
	 * skip past the last char of drv_name
	 */
	i++;

	/*
	 * strip the spaces before the '='
	 */
	for (; i < len; i++) {
		if (!isspace(str[i])) {
			break;
		}
	}

	/*
	 * return if the string is too long or if
	 * the '=' isn't found
	 */
	if (i >= len || str[i] != '=') {
		return (-1);
	}
	i++;
	if (i >= len) {
		/*
		 * no string after the equal
		 */
		return (-1);
	}
	return (datadm_parse_nonnull_str(str + i, &sp_entry->spe_devname));
}

static int
datadm_parse_api_version(char *str, datadm_sp_entry_t *sp_entry)
{
	return (datadm_parse_version(str, &sp_entry->spe_api_version));
}

static int
datadm_parse_threadsafe(char *str, datadm_sp_entry_t *sp_entry)
{
	int retval = 0;

	if (strcmp(str, "threadsafe") == 0) {
		sp_entry->spe_threadsafe = 1;
	} else if (strcmp(str, "nonthreadsafe") == 0) {
		sp_entry->spe_threadsafe = 0;
	} else {
		retval = -1;
	}
	return (retval);
}

static int
datadm_parse_default(char *str, datadm_sp_entry_t *sp_entry)
{
	int retval = 0;

	if (strcmp(str, "default") == 0) {
		sp_entry->spe_default = 1;
	} else if (strcmp(str, "nondefault") == 0) {
		sp_entry->spe_default = 0;
	} else {
		retval = -1;
	}
	return (retval);
}

static int
datadm_parse_libpath(char *str, datadm_sp_entry_t *sp_entry)
{
	return (datadm_parse_nonnull_str(str, &sp_entry->spe_libpath));
}

static int
datadm_parse_sp_version(char *str, datadm_sp_entry_t *sp_entry)
{
	return (datadm_parse_version(str, &sp_entry->spe_sp_version));
}

static int
datadm_parse_sp_data(char *str, datadm_sp_entry_t *sp_entry)
{
	return (datadm_parse_generic_str(str, &sp_entry->spe_sp_data));
}

static void
datadm_enqueue_entry(datadm_list_t *list, datadm_entry_t *entry)
{
	if (list->dl_head == NULL) {
		list->dl_head = entry;
		list->dl_tail = entry;
		list->dl_count = 1;
	} else {
		list->dl_tail->de_next = entry;
		list->dl_tail = entry;
		list->dl_count++;
	}
}

/*
 * iterates through the list applying func on each element.
 * break and return if func returns non-zero.
 */
static int
datadm_walk_list(datadm_list_t *list, int (*func)(datadm_entry_t *, void *),
    void *arg)
{
	datadm_entry_t	*entry;
	int		retval = 0;

	entry = list->dl_head;
	while (entry != NULL) {
		retval = (*func)(entry, arg);
		if (retval != 0) break;
		entry = entry->de_next;
	}
	return (retval);
}

/*
 * iterates through the list applying free_func to each element.
 * list becomes empty when the function returns.
 */
static void
datadm_free_list(datadm_list_t *list, void (*free_func)(datadm_entry_t *))
{
	while (list->dl_head != NULL) {
		datadm_entry_t	*entry;

		entry = list->dl_head;
		list->dl_head = entry->de_next;
		(*free_func)(entry);
	}
	list->dl_count = 0;
	list->dl_tail = NULL;
}

static datadm_sp_entry_t *
datadm_alloc_sp_entry(void)
{
	datadm_sp_entry_t	*sp_entry;

	sp_entry = (datadm_sp_entry_t *)malloc(sizeof (*sp_entry));
	if (sp_entry == NULL) {
		return (NULL);
	}
	bzero(sp_entry, sizeof (*sp_entry));
	return (sp_entry);
}

static void
datadm_free_sp_entry(datadm_sp_entry_t *sp_entry)
{
	if (sp_entry->spe_devname != NULL) {
		free(sp_entry->spe_devname);
		sp_entry->spe_devname = NULL;
	}
	if (sp_entry->spe_api_version.dv_name != NULL) {
		free(sp_entry->spe_api_version.dv_name);
		sp_entry->spe_api_version.dv_name = NULL;
	}
	sp_entry->spe_api_version.dv_major = 0;
	sp_entry->spe_api_version.dv_minor = 0;
	sp_entry->spe_threadsafe = 0;
	sp_entry->spe_default = 0;
	if (sp_entry->spe_libpath != NULL) {
		free(sp_entry->spe_libpath);
		sp_entry->spe_libpath = NULL;
	}
	if (sp_entry->spe_sp_version.dv_name != NULL) {
		free(sp_entry->spe_sp_version.dv_name);
		sp_entry->spe_sp_version.dv_name = NULL;
	}
	sp_entry->spe_sp_version.dv_major = 0;
	sp_entry->spe_sp_version.dv_minor = 0;
	if (sp_entry->spe_sp_data != NULL) {
		free(sp_entry->spe_sp_data);
		sp_entry->spe_sp_data = NULL;
	}
	free(sp_entry);
}

static int
datadm_str_match(char *s1, char *s2)
{
	if (s1 == NULL || s2 == NULL) {
		if (s1 != s2) {
			return (0);
		}
	} else {
		if (strcmp(s1, s2) != 0) {
			return (0);
		}
	}
	return (1);
}

static int
datadm_version_match(datadm_version_t *v1, datadm_version_t *v2)
{
	if (!datadm_str_match(v1->dv_name, v2->dv_name)) {
		return (0);
	}
	if (v1->dv_major != v2->dv_major) {
		return (0);
	}
	if (v1->dv_minor != v2->dv_minor) {
		return (0);
	}
	return (1);
}

static int
datadm_sp_entry_match(datadm_sp_entry_t *sp1, datadm_sp_entry_t *sp2)
{
	if (!datadm_str_match(sp1->spe_devname, sp2->spe_devname)) {
		return (0);
	}
	if (!datadm_version_match(&sp1->spe_api_version,
	    &sp2->spe_api_version)) {
		return (0);
	}
	if (sp1->spe_threadsafe != sp2->spe_threadsafe) {
		return (0);
	}
	if (sp1->spe_default != sp2->spe_default) {
		return (0);
	}
	if (!datadm_str_match(sp1->spe_libpath, sp2->spe_libpath)) {
		return (0);
	}
	if (!datadm_version_match(&sp1->spe_sp_version,
	    &sp2->spe_sp_version)) {
		return (0);
	}
	if (!datadm_str_match(sp1->spe_sp_data, sp2->spe_sp_data)) {
		return (0);
	}
	return (1);
}

static datadm_ia_entry_t *
datadm_alloc_ia_entry(void)
{
	datadm_ia_entry_t	*ia_entry;

	ia_entry = (datadm_ia_entry_t *)malloc(sizeof (*ia_entry));
	if (ia_entry == NULL) {
		return (NULL);
	}
	bzero(ia_entry, sizeof (*ia_entry));
	return (ia_entry);
}

static void
datadm_free_ia_entry(datadm_ia_entry_t *ia_entry)
{
	free(ia_entry);
}

static datadm_hca_entry_t *
datadm_alloc_hca_entry(void)
{
	datadm_hca_entry_t	*hca_entry;

	hca_entry = (datadm_hca_entry_t *)malloc(sizeof (*hca_entry));
	if (hca_entry == NULL) {
		return (NULL);
	}
	bzero(hca_entry, sizeof (*hca_entry));
	return (hca_entry);
}

static void
datadm_free_hca_entry(datadm_hca_entry_t *hca_entry)
{
	if (hca_entry->he_name != NULL) {
		free(hca_entry->he_name);
		hca_entry->he_name = NULL;
	}
	datadm_free_list(&hca_entry->he_sp_list,
	    (void (*)(datadm_entry_t *))datadm_free_sp_entry);
	datadm_free_list(&hca_entry->he_ia_list,
	    (void (*)(datadm_entry_t *))datadm_free_ia_entry);
	free(hca_entry);
}

static int
datadm_hca_entry_match(datadm_hca_entry_t *h1, datadm_hca_entry_t *h2)
{
	if (!datadm_str_match(h1->he_name, h2->he_name)) {
		return (0);
	}
	return (1);
}

static int
datadm_hca_entry_find(datadm_hca_entry_t *h1, datadm_hca_find_t *hf)
{
	if (datadm_str_match(h1->he_name, hf->hf_sp_entry->spe_devname)) {
		hf->hf_hca_entry = h1;
		return (1);
	}
	return (0);
}

static int
datadm_ia_entry_find(datadm_ia_entry_t *i1, datadm_ia_find_t *iaf)
{
	if (strcmp(i1->iae_name, iaf->if_ia_name) == 0) {
		iaf->if_ia_entry = i1;
		return (1);
	}
	return (0);
}

static datadm_cmnt_entry_t *
datadm_alloc_cmnt_entry(void)
{
	datadm_cmnt_entry_t	*cmnt_entry;

	cmnt_entry = (datadm_cmnt_entry_t *)malloc(sizeof (*cmnt_entry));
	if (cmnt_entry == NULL) {
		return (NULL);
	}
	bzero(cmnt_entry, sizeof (*cmnt_entry));
	return (cmnt_entry);
}

static void
datadm_free_cmnt_entry(datadm_cmnt_entry_t *cmnt_entry)
{
	if (cmnt_entry->cmnt_line != NULL) {
		free(cmnt_entry->cmnt_line);
		cmnt_entry->cmnt_line = NULL;
	}
	free(cmnt_entry);
}

/*
 * tokenizes a line and strips off the quotes from quoted strings
 */
static int
datadm_parse_line(char *line_buf, char *tokens[], int *token_count)
{
	int			len, i;
	int			count = 0;
	char			*start = NULL;

	/* the line must not be longer than DATADM_LINESZ */
	len = strlen(line_buf);
	if (line_buf[len - 1] != '\n') {
		return (-1);
	}
	/* discard blank lines and comments */
	if (len == 1) {
		*token_count = 0;
		return (0);
	}
	if (len >= 2 && line_buf[0] == '#') {
		*token_count = 0;
		return (0);
	}
	/* removes the new line */
	line_buf[len - 1] = '\0';
	len--;

	for (i = 0; i < len; i++) {
		if (start != NULL) {
			/*
			 * start points to the start of
			 * a new token. if start is '"',
			 * we should expect a quoted
			 * string.
			 */
			if (*start == '\"') {
				/*
				 * keep scanning until we
				 * hit the end quote.
				 */
				if (line_buf[i] != '\"') {
					continue;
				}
				/*
				 * skip past the start quote
				 */
				start++;
			} else {
				/*
				 * our token is not a quoted
				 * string. our token ends only
				 * when we hit a whitespace.
				 */
				if (!isspace(line_buf[i])) {
					continue;
				}
			}
			/*
			 * nullify the end quote (if any)
			 * and update the tokens array.
			 */
			line_buf[i] = '\0';
			tokens[count] = start;
			start = NULL;
			count++;
		} else {
			/*
			 * skip whitespaces
			 */
			if (isspace(line_buf[i])) {
				continue;
			} else {
				start = &line_buf[i];
			}
		}
		if (count == DATADM_MAX_TOKENS) {
			start = NULL;
			break;
		}
	}
	if (start != NULL) {
		tokens[count] = start;
		start = NULL;
		count++;
	}
	*token_count = count;
	return (0);
}

/*
 * attempts to save sp_entry into hca_list.
 * becomes no-op if sp entry already exists.
 * new hca entries and ia entries are created as needed.
 */
static int
datadm_process_sp_entry(datadm_list_t *hca_list, datadm_sp_entry_t *sp_entry,
    char *ia_name)
{
	datadm_hca_find_t	hca_find;
	datadm_ia_find_t	ia_find;
	datadm_hca_entry_t	*hca_entry;

	hca_find.hf_sp_entry = sp_entry;
	hca_find.hf_hca_entry = NULL;
	(void) datadm_walk_list(hca_list, (int (*)(datadm_entry_t *, void *))
	    datadm_hca_entry_find, (void *)&hca_find);

	if (hca_find.hf_hca_entry == NULL) {
		int	dlen;

		/*
		 * hca_entry not found, need to create
		 * and insert one.
		 */
		hca_entry = datadm_alloc_hca_entry();
		if (hca_entry == NULL) {
			return (-1);
		}
		dlen = strlen(sp_entry->spe_devname);
		hca_entry->he_name = (char *)malloc(dlen + 1);
		if (hca_entry->he_name == NULL) {
			datadm_free_hca_entry(hca_entry);
			return (-1);
		}
		(void) strcpy(hca_entry->he_name, sp_entry->spe_devname);
		datadm_enqueue_entry(hca_list, (datadm_entry_t *)hca_entry);
	} else {
		hca_entry = hca_find.hf_hca_entry;
	}
	if (ia_name == NULL) {
		goto put_sp_entry;
	}
	ia_find.if_ia_name = ia_name;
	ia_find.if_ia_entry = NULL;
	(void) datadm_walk_list(&hca_entry->he_ia_list,
	    (int (*)(datadm_entry_t *, void *))datadm_ia_entry_find, &ia_find);

	if (ia_find.if_ia_entry == NULL) {
		datadm_ia_entry_t	*ia_entry;

		/*
		 * ia_entry not found, need to create
		 * and insert one.
		 */
		ia_entry = datadm_alloc_ia_entry();
		if (ia_entry == NULL) {
			return (-1);
		}
		(void) strlcpy(ia_entry->iae_name, ia_name, MAXLINKNAMELEN);
		datadm_enqueue_entry(&hca_entry->he_ia_list,
		    (datadm_entry_t *)ia_entry);
	}

put_sp_entry:;

	if (datadm_walk_list(&hca_entry->he_sp_list,
	    (int (*)(datadm_entry_t *, void *))datadm_sp_entry_match,
	    (void *)sp_entry)) {
		return (1);
	} else {
		/*
		 * only insert sp_entry if it is not found.
		 */
		datadm_enqueue_entry(&hca_entry->he_sp_list,
		    (datadm_entry_t *)sp_entry);
	}
	return (0);
}

/*
 * parses service_provider.conf
 */
static int
datadm_parse_sp_conf(datadm_list_t *hca_list)
{
	datadm_sp_entry_t	*sp_entry;
	FILE			*sp_file;
	char			*sp_conf = datadm_args.da_sp_conf;
	char			*tokens[DATADM_MAX_TOKENS];
	char			line_buf[DATADM_LINESZ];
	int			retval = 0;
	int			token_count = 0;
	int			line_count = 0;

	sp_file = fopen(sp_conf, "r");
	if (sp_file == NULL) {
		(void) fprintf(stderr,
		    gettext("datadm: cannot open %s\n"), sp_conf);
		return (-1);
	}

	for (;;) {
		bzero(line_buf, DATADM_LINESZ);
		if (fgets(line_buf, DATADM_LINESZ, sp_file) == NULL) {
			break;
		}
		token_count = 0;
		line_count++;
		retval = datadm_parse_line(line_buf, tokens, &token_count);
		if (retval != 0) {
			(void) fprintf(stderr, gettext(
			    "datadm: %s: line %d exceeded max length %d\n"),
			    sp_conf, line_count, DATADM_LINESZ);
			break;
		}
		if (token_count == 0) continue;
		if (token_count == DATADM_NUM_SP_TOKENS) {
			int i = 0;

			sp_entry = datadm_alloc_sp_entry();
			if (sp_entry == NULL) {
				retval = -1;
				break;
			}

			/*
			 * sp_entry gets filled incrementally by
			 * each parsing function
			 */
			for (i = 0; i < DATADM_NUM_SP_TOKENS &&
			    retval == 0; i++) {
				retval = (*datadm_sp_parse_funcs[i])
				    (tokens[i], (void *)sp_entry);
			}
			if (retval != 0) {
				(void) fprintf(stderr, gettext(
				    "datadm: parse error: %s, "
				    "line %d, token: %s\n"),
				    sp_conf, line_count, tokens[i - 1]);
				datadm_free_sp_entry(sp_entry);
				sp_entry = NULL;
				break;
			}

			retval = datadm_process_sp_entry(hca_list,
			    sp_entry, NULL);
			if (retval != 0) {
				datadm_free_sp_entry(sp_entry);
				if (retval == 1) {
					retval = 0;
				} else {
					break;
				}
			}
		} else {
			(void) fprintf(stderr, gettext(
			    "datadm: parse error: %s, line %d, "
			    "# of tokens: %d, expected %d\n"), sp_conf,
			    line_count, token_count, DATADM_NUM_SP_TOKENS);
			retval = -1;
			break;
		}
	}
	if (retval != 0) {
		datadm_free_list(hca_list,
		    (void (*)(datadm_entry_t *))datadm_free_hca_entry);
	}
	(void) fclose(sp_file);
	return (retval);
}

/*
 * parses dat.conf
 */
static int
datadm_parse_dat_conf(datadm_list_t *hca_list)
{
	boolean_t		save_header = B_TRUE;
	datadm_sp_entry_t	*sp_entry;
	FILE			*dat_file;
	char			*dat_conf = datadm_args.da_dat_conf;
	char			*tokens[DATADM_MAX_TOKENS];
	char			line_buf[DATADM_LINESZ];
	int			retval = 0;
	int			token_count = 0;
	int			line_count = 0;

	dat_file = fopen(dat_conf, "r");
	if (dat_file == NULL) {
		/* dat.conf not existing is not an error for OP_ADD */
		if (datadm_args.da_op_type == DATADM_OP_ADD) {
			return (0);
		}
		(void) fprintf(stderr, gettext("datadm: cannot open %s\n"),
		    dat_conf);
		return (-1);
	}

	for (;;) {
		bzero(line_buf, DATADM_LINESZ);
		if (fgets(line_buf, DATADM_LINESZ, dat_file) == NULL) {
			break;
		}
		token_count = 0;
		line_count++;
		retval = datadm_parse_line(line_buf, tokens, &token_count);
		if (retval != 0) {
			(void) fprintf(stderr, gettext(
			    "datadm: %s: line %d exceeded max length %d\n"),
			    dat_conf, line_count, DATADM_LINESZ);
			break;
		}
		if (token_count == 0) {
			datadm_cmnt_entry_t	*cmnt_entry;
			int			cmnt_len;

			/*
			 * comments are saved only if they are
			 * at the top of dat.conf.
			 */
			if (!save_header) continue;
			cmnt_entry = datadm_alloc_cmnt_entry();
			if (cmnt_entry == NULL) {
				perror("datadm: malloc");
				retval = -1;
				break;
			}
			cmnt_len = strlen(line_buf);
			cmnt_entry->cmnt_line = (char *)malloc(cmnt_len + 1);
			if (cmnt_entry->cmnt_line == NULL) {
				perror("datadm: malloc");
				datadm_free_cmnt_entry(cmnt_entry);
				retval = -1;
				break;
			}
			(void) strncpy(cmnt_entry->cmnt_line,
			    line_buf, cmnt_len);
			cmnt_entry->cmnt_line[cmnt_len] = '\0';
			datadm_enqueue_entry(&datadm_conf_header,
			    (datadm_entry_t *)cmnt_entry);
			continue;
		}
		if (token_count == DATADM_NUM_DAT_TOKENS) {
			int i = 0;
			char ia_name[MAXLINKNAMELEN];

			/*
			 * we stop saving comment lines once
			 * we see the first valid line.
			 */
			save_header = B_FALSE;
			sp_entry = datadm_alloc_sp_entry();
			if (sp_entry == NULL) {
				retval = -1;
				break;
			}

			/*
			 * sp_entry gets filled incrementally by
			 * each parsing function
			 */
			for (i = 0; i < DATADM_NUM_DAT_TOKENS &&
			    retval == 0; i++) {
				void	*arg;

				if (i == 0) {
					/*
					 * the first token (ia name)
					 * does not belong to an
					 * sp_entry
					 */
					arg = (void *)ia_name;
				} else {
					arg = (void *)sp_entry;
				}
				retval = (*datadm_dat_parse_funcs[i])
				    (tokens[i], arg);
			}
			if (retval != 0) {
				(void) fprintf(stderr, gettext(
				    "datadm: parse error: %s, "
				    "line %d, token: %s\n"), dat_conf,
				    line_count, tokens[i - 1]);
				datadm_free_sp_entry(sp_entry);
				sp_entry = NULL;
				break;
			}

			/*
			 * we ignore the ibds in dat.conf if we are
			 * doing update
			 */
			if (datadm_args.da_op_type == DATADM_OP_UPDATE) {
				retval = datadm_process_sp_entry(hca_list,
				    sp_entry, NULL);
			} else {
				retval = datadm_process_sp_entry(hca_list,
				    sp_entry, ia_name);
			}
			if (retval != 0) {
				datadm_free_sp_entry(sp_entry);
				if (retval == 1) {
					retval = 0;
				} else {
					break;
				}
			}
		} else {
			(void) fprintf(stderr, gettext(
			    "datadm: parse error: %s, line %d, "
			    "# of tokens: %d, expected %d\n"), dat_conf,
			    line_count, token_count, DATADM_NUM_DAT_TOKENS);
			retval = -1;
			break;
		}
	}
	if (retval != 0) {
		datadm_free_list(&datadm_conf_header,
		    (void (*)(datadm_entry_t *))datadm_free_cmnt_entry);
		datadm_free_list(hca_list,
		    (void (*)(datadm_entry_t *))datadm_free_hca_entry);
	}
	(void) fclose(dat_file);
	return (retval);
}

/*
 * used by OP_REMOVE to invalidate common sp entries between hl1 and hl2.
 * invalid sp entries will be ignored by datadm_generate_dat_conf.
 */
static void
datadm_invalidate_common_sp_entries(datadm_list_t *hl1, datadm_list_t *hl2)
{
	datadm_entry_t	*he1, *he2;

	he1 = hl1->dl_head;
	while (he1 != NULL) {
		he2 = hl2->dl_head;
		while (he2 != NULL) {
			datadm_entry_t	*se1, *se2;

			if (!datadm_hca_entry_match(
			    (datadm_hca_entry_t *)he1,
			    (datadm_hca_entry_t *)he2)) {
				he2 = he2->de_next;
				continue;
			}
			se1 = ((datadm_hca_entry_t *)he1)->he_sp_list.dl_head;
			while (se1 != NULL) {
				se2 = ((datadm_hca_entry_t *)he2)->
				    he_sp_list.dl_head;
				while (se2 != NULL) {
					if (!datadm_sp_entry_match(
					    (datadm_sp_entry_t *)se1,
					    (datadm_sp_entry_t *)se2)) {
						se2 = se2->de_next;
						continue;
					}
					((datadm_sp_entry_t *)se1)->
					    spe_invalid = 1;
					break;
				}
				se1 = se1->de_next;
			}
			break;
		}
		he1 = he1->de_next;
	}
}

static int
datadm_hca_entry_find_by_name(datadm_hca_entry_t *h1,
    datadm_hca_find_by_name_t *hf)
{
	if (datadm_str_match(h1->he_name, hf->hf_name)) {
		hf->hf_hca_entry = h1;
		return (1);
	}
	return (0);
}

datadm_hca_entry_t *
datadm_hca_lookup_by_name(datadm_list_t *hca_list, char *hca_driver_name)
{
	datadm_hca_find_by_name_t	hf;

	hf.hf_name = hca_driver_name;
	hf.hf_hca_entry = NULL;
	(void) datadm_walk_list(hca_list,
	    (int (*)(datadm_entry_t *, void *))datadm_hca_entry_find_by_name,
	    &hf);
	return (hf.hf_hca_entry);
}

static boolean_t
datadm_add_plink(char *linkname, datadm_fill_ia_list_t *ia_args)
{
	datalink_class_t	class;
	datalink_id_t		linkid;
	dladm_ib_attr_t		ib_attr;
	ibnex_ctl_query_hca_t	query_hca;
	datadm_hca_entry_t	*hca;
	struct lifreq		req;
	datadm_ia_find_t	ia_find;
	datadm_ia_entry_t	*ia_entry;

	if ((dladm_name2info(ia_args->ia_dlh, linkname, &linkid, NULL, &class,
	    NULL) != DLADM_STATUS_OK) ||
	    (class != DATALINK_CLASS_PART) ||
	    (dladm_part_info(ia_args->ia_dlh, linkid, &ib_attr,
	    DLADM_OPT_ACTIVE) != DLADM_STATUS_OK)) {
		return (B_FALSE);
	}

	(void) strlcpy(req.lifr_name, linkname, sizeof (req.lifr_name));
	/*
	 * we don't really need to know the ip address.
	 * we just want to check if the device is plumbed
	 * or not.
	 */
	if (ioctl(ia_args->ia_sock_fd_v4, SIOCGLIFADDR, (caddr_t)&req) != 0) {
		/*
		 * we try v6 if the v4 address isn't found.
		 */
		if (ioctl(ia_args->ia_sock_fd_v6, SIOCGLIFADDR,
		    (caddr_t)&req) != 0)
			return (B_FALSE);
	}

	bzero(&query_hca, sizeof (query_hca));
	query_hca.hca_guid = ib_attr.dia_hca_guid;
	if (ioctl(ia_args->ia_ibnex_fd, IBNEX_CTL_QUERY_HCA, &query_hca) == -1)
		return (B_FALSE);

	if ((hca = datadm_hca_lookup_by_name(ia_args->ia_hca_list,
	    query_hca.hca_info.hca_driver_name)) == NULL)
		return (B_FALSE);

	ia_find.if_ia_name = linkname;
	ia_find.if_ia_entry = NULL;
	(void) datadm_walk_list(&hca->he_ia_list,
	    (int (*)(datadm_entry_t *, void *))
	    datadm_ia_entry_find, &ia_find);

	if (ia_find.if_ia_entry == NULL) {
		/*
		 * we insert an ia entry only if
		 * it is unique.
		 */
		ia_entry = datadm_alloc_ia_entry();
		if (ia_entry != NULL) {
			(void) strlcpy(ia_entry->iae_name, linkname,
			    MAXLINKNAMELEN);
			datadm_enqueue_entry(&hca->he_ia_list,
			    (datadm_entry_t *)ia_entry);
		}
	}

	return (B_FALSE);
}

/*
 * build ia lists for each hca_list element
 */
static int
datadm_build_ia_lists(datadm_list_t *hca_list)
{
	dladm_handle_t		dlh;
	datadm_fill_ia_list_t	ia_args;
	int			rv = -1;
	int			fd = -1;
	int			sv4 = -1;
	int			sv6 = -1;

	if (dladm_open(&dlh) != DLADM_STATUS_OK)
		return (-1);

	if ((fd = open(IBNEX_DEVCTL_DEV, O_RDONLY)) < 0)
		goto out;

	if ((sv4 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("datadm: socket");
		goto out;
	}

	if ((sv6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0) {
		perror("datadm: socket");
		goto out;
	}

	ia_args.ia_hca_list = hca_list;
	ia_args.ia_dlh = dlh;
	ia_args.ia_ibnex_fd = fd;
	ia_args.ia_sock_fd_v4 = sv4;
	ia_args.ia_sock_fd_v6 = sv6;

	dlpi_walk((boolean_t (*) (const char *, void *))datadm_add_plink,
	    &ia_args, 0);
	rv = 0;

out:
	if (sv4 != -1)
		(void) close(sv4);
	if (sv6 != -1)
		(void) close(sv6);
	if (fd != -1)
		(void) close(fd);

	dladm_close(dlh);
	return (rv);
}

static int
datadm_generate_conf_entry(FILE *outfile, datadm_ia_entry_t *ia_entry,
    datadm_sp_entry_t *sp_entry)
{
	int	retval;

	retval = fprintf(outfile,
	    "%s  %s%d.%d  %s  %s  %s  %s%d.%d  \"%s\"  \"%s%s%s\"\n",
	    ia_entry->iae_name,
	    (sp_entry->spe_api_version.dv_name ?
	    sp_entry->spe_api_version.dv_name : ""),
	    sp_entry->spe_api_version.dv_major,
	    sp_entry->spe_api_version.dv_minor,
	    (sp_entry->spe_threadsafe ? "threadsafe" : "nonthreadsafe"),
	    (sp_entry->spe_default ? "default" : "nondefault"),
	    sp_entry->spe_libpath,
	    (sp_entry->spe_sp_version.dv_name ?
	    sp_entry->spe_sp_version.dv_name : ""),
	    sp_entry->spe_sp_version.dv_major,
	    sp_entry->spe_sp_version.dv_minor,
	    sp_entry->spe_sp_data,
	    DATADM_DRV_NAME, "=", sp_entry->spe_devname);

	if (retval < 0) {
		return (-1);
	}
	return (0);
}

/*
 * generate dat.conf header
 */
static int
datadm_generate_conf_header(FILE *outfile)
{
	datadm_entry_t		*cep;
	datadm_cmnt_entry_t	*cmnt;
	int			retval = 0;

	cep = datadm_conf_header.dl_head;
	if (cep == NULL) {
		/*
		 * if dat.conf doesn't have a header, we prepend a
		 * default one.
		 */
		retval = fprintf(outfile, "%s", datadm_conf_header_default);
		goto done;
	}
	while (cep != NULL) {
		cmnt = (datadm_cmnt_entry_t *)cep;
		if (cmnt->cmnt_line != NULL) {
			int		len;

			retval = fprintf(outfile, "%s", cmnt->cmnt_line);
			if (retval < 0) {
				break;
			}

			/*
			 * append a newline if the comment line doesn't
			 * have one.
			 */
			len = strlen(cmnt->cmnt_line);
			if (cmnt->cmnt_line[len - 1] != '\n') {
				retval = fprintf(outfile, "\n");
				if (retval < 0) {
					break;
				}
			}
		}
		cep = cep->de_next;
	}
done:;
	if (retval < 0) {
		return (-1);
	}
	return (0);
}

/*
 * outputs dat.conf to stdout or to basedir/etc/dat/dat.conf
 */
static int
datadm_generate_dat_conf(datadm_list_t *hca_list)
{
	FILE			*outfile = NULL;
	char			*dat_conf = datadm_args.da_dat_conf;
	datadm_entry_t		*hep;
	int			retval = 0;

	if (datadm_args.da_op_type == DATADM_OP_VIEW) {
		outfile = stdout;
	} else {
		outfile = fopen(dat_conf, "w+");
		if (outfile == NULL) {
			(void) fprintf(stderr, gettext(
			    "datadm: cannot open %s: %s\n"),
			    dat_conf, strerror(errno));
			return (-1);
		}
	}
	if (outfile != stdout) {
		/*
		 * do not generate the header if we are
		 * printing to the screen
		 */
		retval = datadm_generate_conf_header(outfile);
		if (retval != 0) {
			goto done;
		}
	}
	hep = hca_list->dl_head;
	while (hep != NULL) {
		datadm_entry_t	*iep;

		iep = ((datadm_hca_entry_t *)hep)->he_ia_list.dl_head;
		while (iep != NULL) {
			datadm_entry_t	*sep;

			sep = ((datadm_hca_entry_t *)hep)->he_sp_list.dl_head;
			while (sep != NULL) {
				if (((datadm_sp_entry_t *)sep)->spe_invalid) {
					sep = sep->de_next;
					continue;
				}
				retval = datadm_generate_conf_entry(outfile,
				    (datadm_ia_entry_t *)iep,
				    (datadm_sp_entry_t *)sep);
				if (retval != 0) {
					goto done;
				}
				sep = sep->de_next;
			}
			iep = iep->de_next;
		}
		hep = hep->de_next;
	}
	retval = fflush(outfile);
done:;
	if (outfile != stdout) {
		(void) fclose(outfile);
	}
	if (retval < 0) {
		perror("datadm: fprintf");
	}
	return (retval);
}

static int
datadm_view(void)
{
	int			retval = 0;
	datadm_list_t		hca_list;

	bzero(&hca_list, sizeof (hca_list));

	retval = datadm_parse_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}
	retval = datadm_generate_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}

cleanup:;
	datadm_free_list(&datadm_conf_header,
	    (void (*)(datadm_entry_t *))datadm_free_cmnt_entry);
	datadm_free_list(&hca_list,
	    (void (*)(datadm_entry_t *))datadm_free_hca_entry);
	return (retval);
}

static int
datadm_update(void)
{
	int			retval = 0;
	datadm_list_t		hca_list;

	bzero(&hca_list, sizeof (hca_list));

	retval = datadm_parse_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}
	retval = datadm_build_ia_lists(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}
	retval = datadm_generate_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}

cleanup:;
	datadm_free_list(&datadm_conf_header,
	    (void (*)(datadm_entry_t *))datadm_free_cmnt_entry);
	datadm_free_list(&hca_list,
	    (void (*)(datadm_entry_t *))datadm_free_hca_entry);
	return (retval);
}

static int
datadm_add(void)
{
	int			retval = 0;
	datadm_list_t		hca_list;

	bzero(&hca_list, sizeof (hca_list));

	retval = datadm_parse_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}
	retval = datadm_parse_sp_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}
	retval = datadm_build_ia_lists(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}
	retval = datadm_generate_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}

cleanup:;
	datadm_free_list(&datadm_conf_header,
	    (void (*)(datadm_entry_t *))datadm_free_cmnt_entry);
	datadm_free_list(&hca_list,
	    (void (*)(datadm_entry_t *))datadm_free_hca_entry);
	return (retval);
}

static int
datadm_remove(void)
{
	int			retval = 0;
	datadm_list_t		hca_list;
	datadm_list_t		hca_list2;

	bzero(&hca_list, sizeof (hca_list));
	bzero(&hca_list2, sizeof (hca_list2));

	retval = datadm_parse_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}
	retval = datadm_parse_sp_conf(&hca_list2);
	if (retval != 0) {
		goto cleanup;
	}
	datadm_invalidate_common_sp_entries(&hca_list, &hca_list2);

	retval = datadm_generate_dat_conf(&hca_list);
	if (retval != 0) {
		goto cleanup;
	}

cleanup:;
	datadm_free_list(&datadm_conf_header,
	    (void (*)(datadm_entry_t *))datadm_free_cmnt_entry);
	datadm_free_list(&hca_list,
	    (void (*)(datadm_entry_t *))datadm_free_hca_entry);
	datadm_free_list(&hca_list2,
	    (void (*)(datadm_entry_t *))datadm_free_hca_entry);
	return (retval);
}

static int
datadm_locate_dat_conf(char *basedir)
{
	char		*dat_conf;

	if (basedir == NULL) {
		datadm_args.da_dat_conf = DATADM_DAT_CONF;
		return (0);
	}
	dat_conf = (char *)malloc(strlen(basedir) +
	    strlen(DATADM_DAT_CONF) + 1);
	if (dat_conf == NULL) {
		return (-1);
	}
	dat_conf[0] = '\0';
	(void) strcat(dat_conf, basedir);
	(void) strcat(dat_conf, DATADM_DAT_CONF);
	datadm_args.da_dat_conf = dat_conf;
	return (0);
}

int
main(int argc, char **argv)
{
	extern char	*optarg;
	extern int	optind;
	char		*basedir = NULL;
	int		c, retval;
	int		op_type = -1, errflg = 0;

	bzero(&datadm_args, sizeof (datadm_args));
	bzero(&datadm_conf_header, sizeof (datadm_conf_header));

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "vua:r:b:")) != EOF) {
		switch (c) {
		case 'v':
			if (op_type != -1) errflg = 1;
			op_type = DATADM_OP_VIEW;
			break;
		case 'u':
			if (op_type != -1) errflg = 1;
			op_type = DATADM_OP_UPDATE;
			break;
		case 'a':
			if (op_type != -1) errflg = 1;
			op_type = DATADM_OP_ADD;
			datadm_args.da_sp_conf = optarg;
			break;
		case 'r':
			if (op_type != -1) errflg = 1;
			op_type = DATADM_OP_REMOVE;
			datadm_args.da_sp_conf = optarg;
			break;
		case 'b':
			basedir = optarg;
			break;
		default:
			errflg = 1;
			break;
		}
		if (errflg != 0) {
			break;
		}
	}
	if (errflg != 0 || op_type == -1 || optind < argc) {
		datadm_usage();
		return (1);
	}
	datadm_args.da_op_type = op_type;
	if (datadm_locate_dat_conf(basedir)) {
		return (1);
	}

	retval = (*datadm_ops[op_type])();
	return (retval);
}
