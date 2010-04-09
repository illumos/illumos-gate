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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _DEVFSADM_H
#define	_DEVFSADM_H

#include <sys/types.h>
#include <libdevinfo.h>
#include <sys/devinfo_impl.h>
#include <regex.h>

#undef	DEBUG
#ifndef DEBUG
#define	NDEBUG 1
#else
#undef	NDEBUG
#endif

#include <assert.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DEVFSADM_SUCCESS 0
#define	DEVFSADM_FAILURE -1
#define	DEVFSADM_MULTIPLE -2
#define	DEVFSADM_TRUE 0
#define	DEVFSADM_FALSE -1

#define	ILEVEL_0 0
#define	ILEVEL_1 1
#define	ILEVEL_2 2
#define	ILEVEL_3 3
#define	ILEVEL_4 4
#define	ILEVEL_5 5
#define	ILEVEL_6 6
#define	ILEVEL_7 7
#define	ILEVEL_8 8
#define	ILEVEL_9 9

#define	DEVFSADM_V0 0
#define	DEVFSADM_V1 1

#define	DEVFSADM_CONTINUE 0
#define	DEVFSADM_TERMINATE 1

#define	INTEGER 0
#define	CHARACTER 1

#define	RM_HOT 0x01
#define	RM_PRE 0x02
#define	RM_POST 0x04
#define	RM_ALWAYS 0x08
#define	RM_NOINTERPOSE 0x10

#define	TYPE_EXACT 0x01
#define	TYPE_RE 0x02
#define	TYPE_PARTIAL 0x04
#define	TYPE_MASK 0x07
#define	DRV_EXACT 0x10
#define	DRV_RE 0x20
#define	DRV_MASK 0x30
#define	CREATE_DEFER 0x100
#define	CREATE_MASK 0x100

/* command to start daemon */
#define	DEVFSADMD_START_PATH	"/usr/lib/devfsadm/devfsadmd"
#define	DEVFSADMD_START		"devfsadmd"

/* devfsadm event service door */
#define	DEVFSADM_SERVICE_DOOR	"/etc/sysevent/devfsadm_event_channel"
#define	DEVNAME_LOOKUP_DOOR	".devname_lookup_door"

/* File of reserved devnames */
#define	ENUMERATE_RESERVED "/etc/dev/reserved_devnames"

/* flags for devfsadm_mklink */
#define	DEV_SYNC 0x02	/* synchronous mklink */

#define	INFO_MID		NULL		/* always prints */
#define	VERBOSE_MID		"verbose"	/* prints with -v */
#define	CHATTY_MID		"chatty" 	/* prints with -V chatty */

typedef struct devfsadm_create {
	char	*device_class;	/* eg "disk", "tape", "display" */
	char	*node_type;	/* eg DDI_NT_TAPE, DDI_NT_BLOCK, etc */
	char	*drv_name;	/* eg sd, ssd */
	int	flags;		/* TYPE_{EXACT,RE,PARTIAL}, DRV_{EXACT,RE} */
	int interpose_lvl;	/* eg ILEVEL_0.. ILEVEL_10 */
	int (*callback_fcn)(di_minor_t minor, di_node_t node);
} devfsadm_create_t;

typedef struct devfsadm_remove {
	char 	*device_class;	/* eg "disk", "tape", "display" */
	char    *dev_dirs_re;   /* dev dirs regex selector */
	int	flags;		/* eg POST, PRE, HOT, ALWAYS */
	int	interpose_lvl;	/* eg ILEVEL_0 .. ILEVEL_10 */
	void	(*callback_fcn)(char *);
} devfsadm_remove_t;

typedef struct devfsadm_remove_V1 {
	char 	*device_class;	/* eg "disk", "tape", "display" */
	char    *dev_dirs_re;   /* dev dirs regex selector */
	int	flags;		/* eg POST, PRE, HOT, ALWAYS */
	int	interpose_lvl;	/* eg ILEVEL_0 .. ILEVEL_10 */
	int	(*callback_fcn)(char *);
} devfsadm_remove_V1_t;

typedef struct _devfsadm_create_reg {
	uint_t version;
	uint_t count;	/* number of node type registration */
			/* structures */
	devfsadm_create_t *tblp;
} _devfsadm_create_reg_t;

typedef struct _devfsadm_remove_reg {
	uint_t version;
	uint_t count;   /* number of node type registration */
			/* structures */
	devfsadm_remove_t *tblp;
} _devfsadm_remove_reg_t;

typedef struct _devfsadm_remove_reg_V1 {
	uint_t version;
	uint_t count;   /* number of node type registration */
			/* structures */
	devfsadm_remove_V1_t *tblp;
} _devfsadm_remove_reg_V1_t;
/*
 * "flags" in the devfs_enumerate structure can take the following values.
 * These values specify the substring of devfs path to be used for
 * enumeration. Components (see MATCH_ADDR/MATCH_MINOR) may be specified
 * by using the "match_arg" member in the devfsadm_enumerate structure.
 */
#define	MATCH_ALL	0x001	/* Match entire devfs path */
#define	MATCH_PARENT	0x002	/* Match upto last '/' in devfs path */
#define	MATCH_ADDR	0x004	/* Match upto nth component of last address */
#define	MATCH_MINOR	0x008	/* Match upto nth component of minor name */
#define	MATCH_CALLBACK	0x010	/* Use callback to derive match string */

/*
 * The following flags are private to devfsadm and the disks module.
 * NOT to be used by other modules.
 */
#define	MATCH_NODE	0x020
#define	MATCH_MASK	0x03F
#define	MATCH_UNCACHED	0x040 /* retry flags for disks module */

typedef struct devfsadm_enumerate {
	char *re;
	int subexp;
	uint_t flags;
	char *match_arg;
	char *(*sel_fcn)(const char *path, void *cb_arg);
	void *cb_arg;
} devfsadm_enumerate_t;

#define	DEVFSADM_CREATE_INIT_V0(tbl) \
	_devfsadm_create_reg_t _devfsadm_create_reg = { \
	DEVFSADM_V0, \
	(sizeof (tbl) / sizeof (devfsadm_create_t)), \
	((devfsadm_create_t *)(tbl)) }

#define	DEVFSADM_REMOVE_INIT_V0(tbl)\
	_devfsadm_remove_reg_t _devfsadm_remove_reg = {\
	DEVFSADM_V0, \
	(sizeof (tbl) / sizeof (devfsadm_remove_t)), \
	((devfsadm_remove_t *)(tbl)) }

#define	DEVFSADM_REMOVE_INIT_V1(tbl)\
	_devfsadm_remove_reg_V1_t _devfsadm_remove_reg = {\
	DEVFSADM_V1, \
	(sizeof (tbl) / sizeof (devfsadm_remove_V1_t)), \
	((devfsadm_remove_V1_t *)(tbl)) }

/* reserved devname support */
typedef struct devlink_re {
	char *d_re;
	int d_subexp;
	regex_t d_rcomp;
	regmatch_t *d_pmatch;
} devlink_re_t;

typedef struct enumerate_file {
	char *er_file;
	char *er_id;
	struct enumerate_file *er_next;
} enumerate_file_t;

int devfsadm_noupdate(void);
const char *devfsadm_root_path(void);
int devfsadm_link_valid(di_node_t anynode, char *link);
int devfsadm_mklink(char *link, di_node_t node, di_minor_t minor, int flags);
int devfsadm_secondary_link(char *link, char *primary_link, int flags);
void devfsadm_rm_link(char *file);
void devfsadm_rm_all(char *file);
void devfsadm_rm_stale_links(char *dir_re, char *valid_link, di_node_t node,
		di_minor_t minor);
void devfsadm_errprint(char *message, ...);
void devfsadm_print(char *mid, char *message, ...);
int devfsadm_enumerate_int(char *devfs_path, int index, char **buf,
			    devfsadm_enumerate_t rules[], int nrules);
int devfsadm_enumerate_char(char *devfs_path, int index, char **buf,
			    devfsadm_enumerate_t rules[], int nrules);
char **devfsadm_lookup_dev_names(char *phys_path, char *re, int *lenp);
void devfsadm_free_dev_names(char **dev_names, int len);

/* devlink cache related */
di_devlink_handle_t devfsadm_devlink_cache(void);

/*
 * Private enumerate interface for disks and sgen modules
 */
int disk_enumerate_int(char *devfs_path, int index, char **buf,
			    devfsadm_enumerate_t rules[], int nrules);
/*
 * Private interfaces for ports module (port_link.c).
 */
int devfsadm_enumerate_char_start(char *devfs_path, int index,
    char **buf, devfsadm_enumerate_t rules[], int nrules, char *start);
int devfsadm_read_link(di_node_t node, char *link, char **devfs_path);
char *s_strdup(const char *ptr);

/* Private interface between reserve subsystm and disks link generator */
int devfsadm_have_reserved(void);
int devfsadm_is_reserved(devlink_re_t re_array[], char *devlink);
int devfsadm_reserve_id_cache(devlink_re_t re_array[], enumerate_file_t *head);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVFSADM_H */
