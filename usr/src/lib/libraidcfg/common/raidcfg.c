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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdlib.h>
#include <dirent.h>
#include <dlfcn.h>
#include <link.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mnttab.h>
#include <config_admin.h>
#include <sys/param.h>
#include <libintl.h>
#include <libdevinfo.h>
#include <raidcfg.h>
#include <thread.h>
#include <synch.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	HASH_SLOTS	16
#define	HANDLER_SLOTS	256

/*
 * Raid object status;
 */
#define	OBJ_STATUS_CMD_CLEAN	-1
#define	OBJ_STATUS_OPENED	1
#define	OBJ_STATUS_SCANCOMP	1 << 1

#if defined(__sparcv9)
#define	SUPP_PLUGIN_DIR	"/usr/lib/raidcfg/sparcv9"
#elif defined(__amd64)
#define	SUPP_PLUGIN_DIR	"/usr/lib/raidcfg/amd64"
#else
#define	SUPP_PLUGIN_DIR	"/usr/lib/raidcfg"
#endif

/*
 * Basic types
 */
typedef	int raid_obj_id_t;
typedef	int raid_obj_status_t;

/*
 * Data structures used for object maintennance
 */
typedef	struct {
	void *head;
	void *tail;
	size_t offset;	/* offset of double-linked element (raid_list_el_t) */
			/* in the linked data structures (objects) */
} raid_list_t;

typedef	struct {
	void *prev;
	void *next;
} raid_list_el_t;

typedef	struct {
	raid_obj_id_t obj_id_cnt;	/* id 0 is reserved */
	size_t slots;			/* How many lists linked by *table */
	raid_list_t *table;
} raid_obj_tab_t;

/*
 * Object type structure containing function pointers;
 */
typedef	struct {
	int (*compnum)(raid_obj_tab_t *, raid_obj_id_t, raid_obj_type_id_t);
	int (*complist)(raid_obj_tab_t *, raid_obj_id_t, int, raid_obj_id_t *,
		raid_obj_type_id_t);
	int (*get_attr)(raid_obj_tab_t *, raid_obj_id_t);
	int (*set_attr)(raid_obj_tab_t *, raid_obj_id_t, uint32_t, uint32_t *,
		char **);
	int (*act)(raid_obj_tab_t *, raid_obj_id_t, uint32_t, void *, char **);
	int (*create_obj)(raid_obj_tab_t *, raid_obj_id_t, int,
		raid_obj_id_t *, char **);
	int (*delete_obj)(raid_obj_tab_t *, raid_obj_id_t, char **);
	int (*bind_obj)(raid_obj_tab_t *, raid_obj_id_t *, char **);
	int (*unbind_obj)(raid_obj_tab_t *, raid_obj_id_t *, char **);
} raid_obj_op_t;

/*
 * Common object data structure
 */
typedef	struct {
	raid_list_el_t		el;	/* double-links */

	raid_obj_type_id_t	obj_type_id;
	raid_obj_id_t		obj_id;
	raid_obj_status_t	status;

	raid_obj_id_t		container;
	raid_obj_id_t		sibling;
	raid_obj_id_t		component;

	void			*data;	/* Pointer to attribute structure */
	raid_obj_handle_t	handle;
} raid_obj_t;

/*
 * Definition about handle
 */
typedef	struct {
	uint32_t	next;
	uint32_t	type;
	uint32_t	controller_id;
	uint32_t	array_id;
	uint32_t	disk_id;
	uint64_t	seq_id;
	uint32_t	task_id;
	uint32_t	prop_id;
	uint32_t	fd;		/* Only for controller */
	raid_lib_t	*raid_lib;	/* Only for controller */
} handle_attr_t;

#define	LIST_OBJ_TO_EL(list, obj)	\
	((void *)((char *)(obj) + (list)->offset))
#define	OBJ_TAB_SLOT(tab, id)	\
	((tab)->table + ((id)%(tab)->slots))

#pragma init(raidcfg_init)
#pragma fini(raidcfg_fini)

/*
 * Function prototypes
 */
static int intcompare(const void *p1, const void *p2);
static uint64_t raid_space_noalign(raid_obj_tab_t *, uint32_t, int,
	raid_obj_id_t *, arraypart_attr_t *);
static int raid_handle_init();
static void raid_handle_fini();
static raid_obj_handle_t raid_handle_new(raid_obj_type_id_t);
static void raid_handle_delete(raid_obj_handle_t);
static void raid_handle_delete_controller_comp(uint32_t);
static raid_obj_id_t raid_handle_to_obj(raid_obj_tab_t *,
	raid_obj_handle_t);
static raid_obj_handle_t raid_obj_to_handle(raid_obj_tab_t *,
	raid_obj_id_t);
static raid_lib_t *raid_obj_get_lib(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_lib(raid_obj_tab_t *, raid_obj_id_t, raid_lib_t *);
static int raid_obj_get_fd(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_fd(raid_obj_tab_t *, raid_obj_id_t, int);
static int obj_scan_comp(raid_obj_tab_t *, raid_obj_id_t);
static int obj_rescan(raid_obj_tab_t *);
static raid_obj_id_t obj_get_comp(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_type_id_t);
static raid_obj_id_t obj_get_sibling(raid_obj_tab_t *, raid_obj_id_t);
static int obj_get_attr(raid_obj_tab_t *, raid_obj_id_t, void **);
static raid_obj_id_t obj_locate_controller(raid_obj_tab_t *, uint32_t);
static raid_obj_id_t obj_locate_array(raid_obj_tab_t *, uint32_t, uint32_t);
static raid_obj_id_t obj_locate_array_recur(raid_obj_tab_t *, raid_obj_id_t,
	uint32_t);
static raid_obj_id_t obj_locate_hsp(raid_obj_tab_t *, uint32_t,
	uint32_t, uint32_t);
static raid_obj_id_t obj_locate_disk(raid_obj_tab_t *, uint32_t, uint32_t);
static raid_obj_id_t obj_locate_arraypart(raid_obj_tab_t *, uint32_t,
	uint32_t, uint32_t);
static raid_obj_id_t obj_locate_diskseg(raid_obj_tab_t *, uint32_t,
	uint32_t, uint32_t);
static raid_obj_id_t obj_locate_task(raid_obj_tab_t *, uint32_t, uint32_t);
static raid_obj_id_t obj_locate_prop(raid_obj_tab_t *, uint32_t, uint32_t,
	uint32_t);
static raid_obj_id_t obj_get_controller(raid_obj_tab_t *, raid_obj_id_t);

static int obj_sys_compnum(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_type_id_t);
static int obj_sys_complist(raid_obj_tab_t *, raid_obj_id_t, int,
	raid_obj_id_t *, raid_obj_type_id_t);
static int obj_controller_compnum(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_type_id_t);
static int obj_controller_complist(raid_obj_tab_t *, raid_obj_id_t, int,
	raid_obj_id_t *, raid_obj_type_id_t);
static int obj_controller_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_controller_act(raid_obj_tab_t *, raid_obj_id_t,
	uint32_t, void *, char **);
static int obj_array_compnum(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_type_id_t);
static int obj_array_complist(raid_obj_tab_t *, raid_obj_id_t, int,
	raid_obj_id_t *, raid_obj_type_id_t);
static int obj_array_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_array_set_attr(raid_obj_tab_t *, raid_obj_id_t,
	uint32_t, uint32_t *, char **);
static int obj_disk_compnum(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_type_id_t);
static int obj_disk_complist(raid_obj_tab_t *, raid_obj_id_t, int,
	raid_obj_id_t *, raid_obj_type_id_t);
static int obj_disk_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_hsp_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_arraypart_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_diskseg_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_task_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_prop_get_attr(raid_obj_tab_t *, raid_obj_id_t);
static int obj_array_create(raid_obj_tab_t *, raid_obj_id_t, int,
	raid_obj_id_t *, char **);
static int obj_array_delete(raid_obj_tab_t *, raid_obj_id_t, char **);
static int obj_hsp_bind(raid_obj_tab_t *, raid_obj_id_t *, char **);
static int obj_hsp_unbind(raid_obj_tab_t *, raid_obj_id_t *, char **);

static int raid_obj_create_system_obj(raid_obj_tab_t *);
static raid_obj_id_t raid_obj_id_new(raid_obj_tab_t *);
static void *raid_obj_attr_new(raid_obj_type_id_t);
static raid_obj_id_t raid_obj_create(raid_obj_tab_t *, raid_obj_type_id_t);
static int raid_obj_delete(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_add_org(raid_obj_tab_t *, raid_obj_id_t, raid_obj_id_t);
static raid_obj_type_id_t raid_obj_get_type(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_type(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_type_id_t);
static raid_obj_status_t raid_obj_get_status(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_status(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_status_t);
static int raid_obj_clear_status(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_status_t);
static raid_obj_id_t raid_obj_get_container(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_container(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_id_t);
static raid_obj_id_t raid_obj_get_comp(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_comp(raid_obj_tab_t *, raid_obj_id_t, raid_obj_id_t);
static raid_obj_id_t raid_obj_get_sibling(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_sibling(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_id_t);
static void *raid_obj_get_data_ptr(raid_obj_tab_t *, raid_obj_id_t);
static int raid_obj_set_data_ptr(raid_obj_tab_t *, raid_obj_id_t, void *);
static raid_obj_handle_t raid_obj_get_handle(raid_obj_tab_t *,
	raid_obj_id_t);
static int raid_obj_set_handle(raid_obj_tab_t *, raid_obj_id_t,
	raid_obj_handle_t);

static void raid_list_create(raid_list_t *, size_t);
static void *raid_list_head(raid_list_t *);
static void *raid_list_next(raid_list_t *, void *);
static void raid_list_insert_tail(raid_list_t *, void *);
static void raid_list_remove(raid_list_t *, void *);
static void *raid_list_remove_head(raid_list_t *);
static void *raid_list_find(raid_list_t *, raid_obj_id_t);
static int raid_obj_tab_create(raid_obj_tab_t *, size_t);
static void raid_obj_tab_destroy(raid_obj_tab_t *);
static int raid_obj_tab_insert(raid_obj_tab_t *, raid_obj_id_t, void *);
static void *raid_obj_tab_remove(raid_obj_tab_t *, raid_obj_id_t);
static void *raid_obj_tab_find(raid_obj_tab_t *, raid_obj_id_t);
static void raid_list_destroy(raid_list_t *);

static int controller_id_to_path(uint32_t, char *);
static char *controller_id_to_driver_name(uint32_t);
static void raid_plugin_init();
static raid_lib_t *raid_plugin_load(char *);
static raid_lib_t *raid_find_lib(raid_obj_tab_t *, raid_obj_id_t);

/* Global object table */
static raid_obj_tab_t raid_tab_sys = {0, 0, NULL};

/* Plug-in modules maintenance data structures */
static raid_lib_t *raid_lib_sys = NULL;

/* Handle table definition */
static struct {
	int		handle_num;
	int		used;
	int		unused;
	handle_attr_t	*handles;
} raid_handle_sys = {0, 0, 0, NULL};

/*
 * RAID object method table definition
 */
static raid_obj_op_t raid_obj_op_sys[OBJ_TYPE_ALL] = {
	{obj_sys_compnum, obj_sys_complist, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL},	/* system object methods */
	{obj_controller_compnum, obj_controller_complist,
		obj_controller_get_attr, NULL, obj_controller_act,
		NULL, NULL, NULL, NULL},	/* controller object methods */
	{obj_array_compnum, obj_array_complist, obj_array_get_attr,
		obj_array_set_attr, NULL, obj_array_create,
		obj_array_delete, NULL, NULL},	/* array object methods */
	{obj_disk_compnum, obj_disk_complist, obj_disk_get_attr, NULL,
		NULL, NULL, NULL, NULL, NULL},	/* disk object methods */
	{NULL, NULL, obj_hsp_get_attr, NULL, NULL, NULL, NULL, obj_hsp_bind,
		obj_hsp_unbind},		/* hsp object methods */
	{NULL, NULL, obj_arraypart_get_attr, NULL, NULL, NULL, NULL,
		NULL, NULL},			/* array part object methods */
	{NULL, NULL, obj_diskseg_get_attr, NULL, NULL, NULL, NULL, NULL, NULL},
	{NULL, NULL, obj_task_get_attr, NULL, NULL, NULL, NULL,
		NULL, NULL},			/* disk seg object methods */
	{NULL, NULL, obj_prop_get_attr, NULL, NULL, NULL, NULL,
		NULL, NULL}			/* property object methods */
};

/*
 * Mutex for multithread safe
 */
static mutex_t raidcfg_mp;

/*
 * RaidCfg library APIs
 */
const char *
raidcfg_errstr(int err_code)
{
	char *ret_val;

	(void) mutex_lock(&raidcfg_mp);
	switch (err_code) {
	case	SUCCESS:
		ret_val = dgettext(TEXT_DOMAIN, "Operation succeeded.\n");
		break;
	case	STD_IOCTL:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Request standard IOCTL service.\n");
		break;
	case	ERR_DRIVER_NOT_FOUND:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Controller device can not be found.\n");
		break;
	case	ERR_DRIVER_OPEN:
		ret_val = dgettext(TEXT_DOMAIN, "Can not open controller.\n");
		break;
	case	ERR_DRIVER_LOCK:
		ret_val = dgettext(TEXT_DOMAIN, "Controller is locked.\n");
		break;
	case	ERR_DRIVER_CLOSED:
		ret_val = dgettext(TEXT_DOMAIN, "Controller is not opened.\n");
		break;
	case	ERR_DRIVER_ACROSS:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Operation across multiple controllers.\n");
		break;
	case	ERR_ARRAY_LEVEL:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Operation not support with volume of this level.\n");
		break;
	case	ERR_ARRAY_SIZE:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Capacity of array out of range.\n");
		break;
	case	ERR_ARRAY_STRIPE_SIZE:
		ret_val = dgettext(TEXT_DOMAIN, "Illegal stripe size.\n");
		break;
	case	ERR_ARRAY_CACHE_POLICY:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Illegal cache-write policy.\n");
		break;
	case	ERR_ARRAY_IN_USE:
		ret_val = dgettext(TEXT_DOMAIN, "Array or disk in use.\n");
		break;
	case	ERR_ARRAY_TASK:
		ret_val = dgettext(TEXT_DOMAIN, "Array has background task.\n");
		break;
	case	ERR_ARRAY_CONFIG:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Configuration over device node failed.\n");
		break;
	case	ERR_ARRAY_DISKNUM:
		ret_val = dgettext(TEXT_DOMAIN, "Incorrect number of disks.\n");
		break;
	case	ERR_ARRAY_LAYOUT:
		ret_val = dgettext(TEXT_DOMAIN, "Illegal array layout.\n");
		break;
	case	ERR_ARRAY_AMOUNT:
		ret_val = dgettext(TEXT_DOMAIN, "Too many arrays.\n");
		break;
	case	ERR_DISK_STATE:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Incorrect disk status for current operation.\n");
		break;
	case	ERR_DISK_SPACE:
		ret_val = dgettext(TEXT_DOMAIN, "No enough disk space.\n");
		break;
	case	ERR_DISK_SEG_AMOUNT:
		ret_val = dgettext(TEXT_DOMAIN, "Too many disk segments.\n");
		break;
	case	ERR_DISK_NOT_EMPTY:
		ret_val = dgettext(TEXT_DOMAIN, "Disk has occupied space.\n");
		break;
	case	ERR_DISK_TASK:
		ret_val = dgettext(TEXT_DOMAIN, "Disk has background task.\n");
		break;
	case	ERR_TASK_STATE:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Incorrect task state for current operation.\n");
		break;
	case	ERR_OP_ILLEGAL:
		ret_val = dgettext(TEXT_DOMAIN, "Illegal operation.\n");
		break;
	case	ERR_OP_NO_IMPL:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Operation is not implemented.\n");
		break;
	case	ERR_OP_FAILED:
		ret_val = dgettext(TEXT_DOMAIN, "Operation failed.\n");
		break;
	case	ERR_DEVICE_NOENT:
		ret_val = dgettext(TEXT_DOMAIN, "Device not found.\n");
		break;
	case	ERR_DEVICE_TYPE:
		ret_val = dgettext(TEXT_DOMAIN, "Illegal type of device.\n");
		break;
	case	ERR_DEVICE_DUP:
		ret_val = dgettext(TEXT_DOMAIN, "Device record duplicated.\n");
		break;
	case	ERR_DEVICE_OVERFLOW:
		ret_val = dgettext(TEXT_DOMAIN, "Too many devices.\n");
		break;
	case	ERR_DEVICE_UNCLEAN:
		ret_val = dgettext(TEXT_DOMAIN, "Device pool is not clean.\n");
		break;
	case	ERR_DEVICE_INVALID:
		ret_val = dgettext(TEXT_DOMAIN, "Device record is invalid.\n");
		break;
	case	ERR_NOMEM:
		ret_val = dgettext(TEXT_DOMAIN,
		    "Can not allocate more memory space.\n");
		break;
	case	ERR_PRIV:
		ret_val = dgettext(TEXT_DOMAIN, "No privilege.\n");
		break;
	default:
		ret_val = dgettext(TEXT_DOMAIN, "Undefined error.\n");
	}
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_get_controller(uint32_t controller_id)
{
	raid_obj_id_t obj_id;
	int ret_val;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = obj_locate_controller(&raid_tab_sys, controller_id);
	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}

	if (obj_id == OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}
	ret_val = raid_obj_to_handle(&raid_tab_sys, obj_id);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_get_array(int controller_handle, uint64_t target_id, uint64_t lun)
{
	raid_obj_id_t obj_id;
	raidcfg_array_t *attr;
	int ret_val;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, controller_handle);
	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}

	obj_id = obj_get_comp(&raid_tab_sys, obj_id, OBJ_TYPE_ARRAY);

	while (obj_id > OBJ_NONE) {
		(void) obj_get_attr(&raid_tab_sys, obj_id, (void **)(&attr));
		if (attr->tag.idl.target_id == target_id &&
		    attr->tag.idl.lun == lun)
			break;

		obj_id = obj_get_sibling(&raid_tab_sys, obj_id);
	}

	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}
	if (obj_id == OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}
	ret_val = raid_obj_to_handle(&raid_tab_sys, obj_id);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_get_disk(int controller_handle, disk_tag_t tag)
{
	raid_obj_id_t obj_id;
	raidcfg_disk_t *attr;
	int ret_val;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, controller_handle);
	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}

	obj_id = obj_get_comp(&raid_tab_sys, obj_id, OBJ_TYPE_DISK);

	while (obj_id > OBJ_NONE) {
		(void) obj_get_attr(&raid_tab_sys, obj_id, (void **)(&attr));
		if (attr->tag.cidl.bus == tag.cidl.bus &&
		    attr->tag.cidl.target_id == tag.cidl.target_id &&
		    attr->tag.cidl.lun == tag.cidl.lun)
			break;

		obj_id = obj_get_sibling(&raid_tab_sys, obj_id);
	}

	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}
	if (obj_id == OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}
	ret_val = raid_obj_to_handle(&raid_tab_sys, obj_id);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_open_controller(int handle, char **plugin_err_str)
{
	raid_obj_id_t obj_id;
	int ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	ret = obj_controller_act(&raid_tab_sys, obj_id,
	    ACT_CONTROLLER_OPEN, NULL, plugin_err_str);
	if (ret < SUCCESS) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ret);
	}
	(void) mutex_unlock(&raidcfg_mp);

	return (SUCCESS);
}

int
raidcfg_close_controller(int handle, char **plugin_err_str)
{
	raid_obj_id_t obj_id;
	int ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	ret = obj_controller_act(&raid_tab_sys, obj_id,
	    ACT_CONTROLLER_CLOSE, NULL, plugin_err_str);
	if (ret < SUCCESS) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ret);
	}
	(void) mutex_unlock(&raidcfg_mp);

	return (SUCCESS);
}

int
raidcfg_get_type(int handle)
{
	raid_obj_id_t obj_id;
	int ret_val;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}
	ret_val = raid_obj_get_type(&raid_tab_sys, obj_id);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_get_attr(int handle, void *attr)
{
	raid_obj_id_t obj_id;
	raid_obj_type_id_t type;
	void *data;
	int ret, size;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	if (attr == NULL) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_INVALID);
	}

	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	type = raid_obj_get_type(&raid_tab_sys, obj_id);
	ret = obj_get_attr(&raid_tab_sys, obj_id, &data);
	if (ret < SUCCESS) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ret);
	}

	switch (type) {
	case	OBJ_TYPE_CONTROLLER:
		size = sizeof (controller_attr_t);
		break;
	case	OBJ_TYPE_ARRAY:
		size = sizeof (array_attr_t);
		break;
	case	OBJ_TYPE_HSP:
		{
			raidcfg_hsp_t *dst = attr;
			hsp_attr_t *src = data;
			controller_attr_t *ctlr_attr;
			array_attr_t *array_attr;

			dst->associated_id = src->associated_id;
			dst->type = src->type;

			obj_id = obj_get_controller(&raid_tab_sys, obj_id);
			ret = obj_get_attr(&raid_tab_sys, obj_id,
			    (void **)(&ctlr_attr));
			if (ret < SUCCESS) {
				(void) mutex_unlock(&raidcfg_mp);
				return (ret);
			}

			if (src->type == HSP_TYPE_LOCAL) {
				obj_id = obj_locate_array(&raid_tab_sys,
				    ctlr_attr->controller_id,
				    src->associated_id);
				ret = obj_get_attr(&raid_tab_sys, obj_id,
				    (void **)(&array_attr));
				if (ret < SUCCESS) {
					(void) mutex_unlock(&raidcfg_mp);
					return (ret);
				}

				dst->tag.idl.target_id =
				    array_attr->tag.idl.target_id;
				dst->tag.idl.lun = array_attr->tag.idl.lun;
			}
		}
		(void) mutex_unlock(&raidcfg_mp);
		return (SUCCESS);
	case	OBJ_TYPE_DISK:
		size = sizeof (disk_attr_t);
		break;
	case	OBJ_TYPE_ARRAY_PART:
		{
			raidcfg_arraypart_t *dst = attr;
			arraypart_attr_t *src = data;
			controller_attr_t *ctlr_attr;
			disk_attr_t *disk_attr;

			dst->disk_id = src->disk_id;
			dst->offset = src->offset;
			dst->size = src->size;
			dst->state = src->state;

			obj_id = obj_get_controller(&raid_tab_sys, obj_id);
			ret = obj_get_attr(&raid_tab_sys, obj_id,
			    (void **)(&ctlr_attr));
			if (ret < SUCCESS) {
				(void) mutex_unlock(&raidcfg_mp);
				return (ret);
			}

			obj_id = obj_locate_disk(&raid_tab_sys,
			    ctlr_attr->controller_id, src->disk_id);
			if (obj_id <= OBJ_NONE) {
				dst->tag.cidl.bus = (uint64_t)OBJ_ATTR_NONE;
				dst->tag.cidl.target_id =
				    (uint64_t)OBJ_ATTR_NONE;
				dst->tag.cidl.lun = (uint64_t)OBJ_ATTR_NONE;
				(void) mutex_unlock(&raidcfg_mp);
				return (SUCCESS);
			}

			ret = obj_get_attr(&raid_tab_sys, obj_id,
			    (void **)(&disk_attr));
			if (ret < SUCCESS) {
				(void) mutex_unlock(&raidcfg_mp);
				return (ret);
			}

			dst->tag.cidl.bus = disk_attr->tag.cidl.bus;
			dst->tag.cidl.target_id = disk_attr->tag.cidl.target_id;
			dst->tag.cidl.lun = disk_attr->tag.cidl.lun;
		}
		(void) mutex_unlock(&raidcfg_mp);
		return (SUCCESS);
	case	OBJ_TYPE_DISK_SEG:
		size = sizeof (diskseg_attr_t);
		break;
	case	OBJ_TYPE_TASK:
		size = sizeof (task_attr_t);
		break;
	case	OBJ_TYPE_PROP:
		{
			property_attr_t *src = data, *dst = attr;

			dst->prop_id = src->prop_id;
			dst->prop_type = src->prop_type;
			if (dst->prop_size == 0) {
				dst->prop_size = src->prop_size;
				(void) mutex_unlock(&raidcfg_mp);
				return (SUCCESS);
			}

			if (dst->prop_size < src->prop_size)
				size = dst->prop_size;
			else
				size = src->prop_size;

			(void) memcpy(dst->prop, src->prop, size);
			(void) mutex_unlock(&raidcfg_mp);
			return (SUCCESS);
		}
	default:
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_TYPE);
	}

	(void) memcpy(attr, data, size);

	(void) mutex_unlock(&raidcfg_mp);
	return (ret);
}

int
raidcfg_get_container(int handle)
{
	raid_obj_id_t obj_id;
	int ret_val;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	obj_id = raid_obj_get_container(&raid_tab_sys, obj_id);
	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}
	ret_val = raid_obj_to_handle(&raid_tab_sys, obj_id);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_list_head(int handle, raid_obj_type_id_t type)
{
	raid_obj_id_t obj_id;
	int ret_val;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	obj_id = obj_get_comp(&raid_tab_sys, obj_id, type);
	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}
	ret_val = raid_obj_to_handle(&raid_tab_sys, obj_id);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_list_next(int handle)
{
	raid_obj_id_t obj_id;
	int ret_val;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	obj_id = obj_get_sibling(&raid_tab_sys, obj_id);
	if (obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}
	ret_val = raid_obj_to_handle(&raid_tab_sys, obj_id);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret_val);
}

int
raidcfg_set_attr(int handle, uint32_t set_cmd, void *value,
    char **plugin_err_str)
{
	raid_obj_id_t obj_id;
	raid_obj_type_id_t type;
	int ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	type = raid_obj_get_type(&raid_tab_sys, obj_id);
	if (raid_obj_op_sys[type].set_attr == NULL) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_OP_NO_IMPL);
	}

	ret = raid_obj_op_sys[type].set_attr(&raid_tab_sys,
	    obj_id, set_cmd, value, plugin_err_str);

	(void) mutex_unlock(&raidcfg_mp);
	return (ret);
}

int
raidcfg_update_fw(int handle, char *file, char **plugin_err_str)
{
	raid_obj_id_t obj_id;
	int ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	obj_id = raid_handle_to_obj(&raid_tab_sys, handle);
	if (obj_id < OBJ_NONE) {
		raid_handle_delete(handle);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}

	if (raid_obj_get_type(&raid_tab_sys, obj_id) != OBJ_TYPE_CONTROLLER) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_OP_NO_IMPL);
	}

	ret = raid_obj_op_sys[OBJ_TYPE_CONTROLLER].act(&raid_tab_sys,
	    obj_id, ACT_CONTROLLER_FLASH_FW, file, plugin_err_str);

	(void) mutex_unlock(&raidcfg_mp);
	return (ret);
}

int
raidcfg_create_array(int num_of_comps, int *disk_handles,
    uint32_t raid_level, uint64_t size, uint32_t stripe_size,
    char **plugin_err_str)
{
	raid_obj_id_t *disk_obj_ids, obj_id;
	array_attr_t *array_attr;
	raid_obj_handle_t array_handle;
	int i, ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);

	disk_obj_ids = calloc(num_of_comps, sizeof (raid_obj_id_t));
	if (disk_obj_ids == NULL) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_NOMEM);
	}

	/* convert disk handles into disk object ids; */
	for (i = 0; i < num_of_comps; ++i) {
		if (*(disk_handles + i) == OBJ_SEPARATOR_BEGIN ||
		    *(disk_handles + i) == OBJ_SEPARATOR_END) {
			*(disk_obj_ids + i) = *(disk_handles + i);
			continue;
		}

		*(disk_obj_ids + i) = raid_handle_to_obj(&raid_tab_sys,
		    *(disk_handles + i));
		if (raid_obj_get_type(&raid_tab_sys, *(disk_obj_ids + i)) !=
		    OBJ_TYPE_DISK) {
			free(disk_obj_ids);
			(void) obj_rescan(&raid_tab_sys);
			(void) mutex_unlock(&raidcfg_mp);
			return (ERR_DEVICE_TYPE);
		}
	}

	/* Create an empty array object */
	obj_id = raid_obj_create(&raid_tab_sys, OBJ_TYPE_ARRAY);
	if (obj_id < OBJ_NONE) {
		free(disk_obj_ids);
		(void) obj_rescan(&raid_tab_sys);
		(void) mutex_unlock(&raidcfg_mp);
		return (obj_id);
	}
	(void) raid_obj_clear_status(&raid_tab_sys, obj_id,
	    OBJ_STATUS_CMD_CLEAN);

	array_attr = raid_obj_get_data_ptr(&raid_tab_sys, obj_id);
	array_attr->array_id = (uint32_t)OBJ_ATTR_NONE;
	array_attr->raid_level = raid_level;
	array_attr->capacity = size;
	array_attr->stripe_size = stripe_size;
	array_attr->write_policy = CACHE_WR_ON;
	array_attr->read_policy = CACHE_RD_ON;

	ret = raid_obj_op_sys[OBJ_TYPE_ARRAY].create_obj(&raid_tab_sys, obj_id,
	    num_of_comps, disk_obj_ids, plugin_err_str);
	free(disk_obj_ids);

	if (ret < SUCCESS) {
		(void) obj_rescan(&raid_tab_sys);
		(void) mutex_unlock(&raidcfg_mp);
		return (ret);
	}

	/* create_obj() method should put the array object in the device tree */
	array_handle = raid_obj_to_handle(&raid_tab_sys, obj_id);

	(void) obj_rescan(&raid_tab_sys);
	(void) mutex_unlock(&raidcfg_mp);
	return (array_handle);
}

int
raidcfg_delete_array(int array_handle, char **plugin_err_str)
{
	raid_obj_id_t array_obj_id;
	int ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);

	if (raidcfg_get_type(array_handle) != OBJ_TYPE_ARRAY) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_TYPE);
	}

	array_obj_id = raid_handle_to_obj(&raid_tab_sys, array_handle);
	if (array_obj_id < OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (array_obj_id);
	}
	if (array_obj_id == OBJ_NONE) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_INVALID);
	}

	ret = raid_obj_op_sys[OBJ_TYPE_ARRAY].delete_obj(&raid_tab_sys,
	    array_obj_id, plugin_err_str);
	(void) obj_rescan(&raid_tab_sys);

	(void) mutex_unlock(&raidcfg_mp);
	return (ret);
}

int
raidcfg_set_hsp(raidcfg_hsp_relation_t *hsp_relations,
    char **plugin_err_str)
{
	raid_obj_id_t disk_obj_id, array_obj_id;
	raid_obj_id_t *hsp_relation_objs;
	int ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	if (hsp_relations == NULL) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_OP_ILLEGAL);
	}

	hsp_relation_objs = malloc(2 * sizeof (raid_obj_id_t));
	if (hsp_relation_objs == NULL) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_NOMEM);
	}

	(void) obj_rescan(&raid_tab_sys);

	if (hsp_relations->array_handle != OBJ_ATTR_NONE) {
		array_obj_id = raid_handle_to_obj(&raid_tab_sys,
		    hsp_relations->array_handle);
		if (array_obj_id < OBJ_NONE) {
			free(hsp_relation_objs);
			(void) mutex_unlock(&raidcfg_mp);
			return (array_obj_id);
		}
		if (array_obj_id == OBJ_NONE) {
			(void) free(hsp_relation_objs);
			(void) mutex_unlock(&raidcfg_mp);
			return (ERR_DEVICE_NOENT);
		}
		if (raidcfg_get_type(hsp_relations->array_handle) !=
		    OBJ_TYPE_ARRAY) {
			free(hsp_relation_objs);
			(void) mutex_unlock(&raidcfg_mp);
			return (ERR_DEVICE_TYPE);
		}
	} else
		array_obj_id = OBJ_ATTR_NONE;

	disk_obj_id = raid_handle_to_obj(&raid_tab_sys,
	    hsp_relations->disk_handle);
	if (disk_obj_id < OBJ_NONE) {
		free(hsp_relation_objs);
		(void) mutex_unlock(&raidcfg_mp);
		return (disk_obj_id);
	}
	if (disk_obj_id == OBJ_NONE) {
		free(hsp_relation_objs);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}
	if (raidcfg_get_type(hsp_relations->disk_handle) !=
	    OBJ_TYPE_DISK) {
		free(hsp_relation_objs);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_TYPE);
	}

	hsp_relation_objs[0] = array_obj_id;
	hsp_relation_objs[1] = disk_obj_id;

	ret = raid_obj_op_sys[OBJ_TYPE_HSP].bind_obj(&raid_tab_sys,
	    hsp_relation_objs, plugin_err_str);

	(void) obj_rescan(&raid_tab_sys);
	free(hsp_relation_objs);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret);
}

int
raidcfg_unset_hsp(raidcfg_hsp_relation_t *hsp_relations,
    char **plugin_err_str)
{
	raid_obj_id_t disk_obj_id, array_obj_id;
	raid_obj_id_t *hsp_relation_objs;
	int ret;

	(void) mutex_lock(&raidcfg_mp);
	(void) obj_rescan(&raid_tab_sys);
	if (hsp_relations == NULL) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_OP_ILLEGAL);
	}

	hsp_relation_objs = malloc(2 * sizeof (raid_obj_id_t));
	if (hsp_relation_objs == NULL) {
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_NOMEM);
	}

	(void) obj_rescan(&raid_tab_sys);

	if (hsp_relations->array_handle != OBJ_ATTR_NONE) {
		array_obj_id = raid_handle_to_obj(&raid_tab_sys,
		    hsp_relations->array_handle);
		if (array_obj_id < OBJ_NONE) {
			free(hsp_relation_objs);
			(void) mutex_unlock(&raidcfg_mp);
			return (array_obj_id);
		}
		if (array_obj_id == OBJ_NONE) {
			free(hsp_relation_objs);
			(void) mutex_unlock(&raidcfg_mp);
			return (ERR_DEVICE_NOENT);
		}
		if (raidcfg_get_type(hsp_relations->array_handle) !=
		    OBJ_TYPE_ARRAY) {
			free(hsp_relation_objs);
			(void) mutex_unlock(&raidcfg_mp);
			return (ERR_DEVICE_TYPE);
		}
	} else
		array_obj_id = OBJ_ATTR_NONE;

	disk_obj_id = raid_handle_to_obj(&raid_tab_sys,
	    hsp_relations->disk_handle);
	if (disk_obj_id < OBJ_NONE) {
		free(hsp_relation_objs);
		(void) mutex_unlock(&raidcfg_mp);
		return (disk_obj_id);
	}
	if (disk_obj_id == OBJ_NONE) {
		free(hsp_relation_objs);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_NOENT);
	}
	if (raidcfg_get_type(hsp_relations->disk_handle) !=
	    OBJ_TYPE_DISK) {
		free(hsp_relation_objs);
		(void) mutex_unlock(&raidcfg_mp);
		return (ERR_DEVICE_TYPE);
	}

	hsp_relation_objs[0] = array_obj_id;
	hsp_relation_objs[1] = disk_obj_id;

	ret = raid_obj_op_sys[OBJ_TYPE_HSP].unbind_obj(&raid_tab_sys,
	    hsp_relation_objs, plugin_err_str);

	(void) obj_rescan(&raid_tab_sys);
	free(hsp_relation_objs);
	(void) mutex_unlock(&raidcfg_mp);

	return (ret);
}

/*
 * RaidCfg lib routines
 */
void
raidcfg_init(void)
{
	(void) mutex_init(&raidcfg_mp, USYNC_THREAD, NULL);
	raid_plugin_init();
	(void) raid_handle_init();
	(void) obj_rescan(&raid_tab_sys);
}

void
raidcfg_fini(void)
{
	/*
	 * Need to close all opened controllers before destroying object table
	 */
	(void) obj_rescan(&raid_tab_sys);
	raid_handle_fini();
	raid_obj_tab_destroy(&raid_tab_sys);
	raid_plugin_init();
	(void) mutex_destroy(&raidcfg_mp);
}

/*
 * Support routines
 */
static int
intcompare(const void *p1, const void *p2)
{
	int i, j;
	i = *((int *)p1);
	j = *((int *)p2);
	return (i - j);
}

static uint64_t
raid_space_noalign(raid_obj_tab_t *raid_tab, uint32_t raid_level, int num,
    raid_obj_id_t *disk_objs, arraypart_attr_t *arraypart_attrs)
{
	disk_attr_t *disk_attr;
	diskseg_attr_t *diskseg_attr;
	raid_obj_id_t obj_id;
	uint64_t offset, capacity;
	int i, disk_num, sub_array_num, disk_layer;

	/* Find out the maximum available space for all disks */
	for (i = 0; i < num; ++i) {
		if ((disk_objs[i] == OBJ_SEPARATOR_BEGIN) ||
		    (disk_objs[i] == OBJ_SEPARATOR_END))
			continue;

		(void) obj_get_attr(raid_tab, disk_objs[i],
		    (void **)(&disk_attr));
		obj_id = obj_get_comp(raid_tab, disk_objs[i],
		    OBJ_TYPE_DISK_SEG);
		if (obj_id == OBJ_NONE) {
			arraypart_attrs[i].offset = 0;
			arraypart_attrs[i].size = disk_attr->capacity;
			continue;
		}

		(void) obj_get_attr(raid_tab, obj_id, (void **)
		    (&diskseg_attr));
		arraypart_attrs[i].offset = 0;
		arraypart_attrs[i].size = diskseg_attr->offset;
		offset = diskseg_attr->offset + diskseg_attr->size;

		while ((obj_id = obj_get_sibling(raid_tab, obj_id)) !=
		    OBJ_NONE) {
			(void) obj_get_attr(raid_tab, obj_id,
			    (void **)(&diskseg_attr));
			if ((diskseg_attr->offset - offset) >
			    arraypart_attrs[i].size) {
				arraypart_attrs[i].offset = offset;
				arraypart_attrs[i].size = diskseg_attr->offset -
				    offset;
			}

			offset = diskseg_attr->offset + diskseg_attr->size;
		}

		if ((disk_attr->capacity - offset) > arraypart_attrs[i].size) {
			arraypart_attrs[i].offset = offset;
			arraypart_attrs[i].size = disk_attr->capacity -
			    offset;
		}
	}

	capacity = OBJ_ATTR_NONE;
	disk_num = 0;
	disk_layer = 0;
	sub_array_num = 0;
	for (i = 0; i < num; ++i) {
		if (disk_objs[i] == OBJ_SEPARATOR_BEGIN) {
			++ disk_layer;
			continue;
		}
		if (disk_objs[i] == OBJ_SEPARATOR_END) {
			-- disk_layer;
			if (disk_layer != 0)
				++ sub_array_num;
			continue;
		}

		if (capacity > arraypart_attrs[i].size)
			capacity = arraypart_attrs[i].size;
		++disk_num;
	}

	switch (raid_level) {
	case	RAID_LEVEL_0:
		capacity = capacity * disk_num;
		break;
	case	RAID_LEVEL_1:
		capacity = capacity * disk_num / 2;
		break;
	case	RAID_LEVEL_1E:
		capacity = capacity * disk_num / 2;
		break;
	case	RAID_LEVEL_5:
		capacity = capacity * (disk_num - 1);
		break;
	case	RAID_LEVEL_10:
		capacity = capacity * disk_num / 2;
		break;
	case	RAID_LEVEL_50:
		capacity = capacity * (disk_num - sub_array_num);
		break;
	default:
		return (ERR_ARRAY_LEVEL);
	}

	return (capacity);
}

/*
 * Raid handle maintenance routines
 */
static int
raid_handle_init()
{
	int i;
	void *ptr;

	raid_handle_sys.handle_num += HANDLER_SLOTS;
	ptr = realloc(raid_handle_sys.handles,
	    raid_handle_sys.handle_num * sizeof (handle_attr_t));
	if (ptr == NULL)
		return (ERR_NOMEM);
	raid_handle_sys.handles = ptr;

	/* Clean up the new allocated handles */
	for (i = raid_handle_sys.handle_num - HANDLER_SLOTS;
	    i < raid_handle_sys.handle_num; ++i) {
		bzero(&raid_handle_sys.handles[i], sizeof (handle_attr_t));
		raid_handle_sys.handles[i].type = OBJ_TYPE_ALL;
		raid_handle_sys.handles[i].next = i + 1;
	}

	/* For the first time of allocation, set up the system object handle */
	if (raid_handle_sys.handle_num == HANDLER_SLOTS) {
		raid_handle_sys.handles[0].type = OBJ_TYPE_SYSTEM;
		raid_handle_sys.handles[0].next = 0;
		raid_handle_sys.unused = 1;
		raid_handle_sys.used = 0;
	}
	return (SUCCESS);
}

static void
raid_handle_fini()
{
	raid_obj_handle_t i;

	i = raid_handle_sys.used;

	/* Close all opened controllers */
	while (i != 0) {
		if ((raid_handle_sys.handles[i].type == OBJ_TYPE_CONTROLLER) &&
		    (raid_handle_sys.handles[i].fd != 0) &&
		    (raid_handle_sys.handles[i].raid_lib != NULL))
			raid_handle_sys.handles[i].raid_lib->close_controller(
			    raid_handle_sys.handles[i].controller_id, NULL);
		i = raid_handle_sys.handles[i].next;
	}

	/* Clean up handle space */
	raid_handle_sys.handle_num = 0;
	raid_handle_sys.unused = 0;
	raid_handle_sys.used = 0;
	free(raid_handle_sys.handles);
	raid_handle_sys.handles = NULL;
}

static raid_obj_handle_t
raid_handle_new(raid_obj_type_id_t type)
{
	int ret;

	if (raid_handle_sys.unused == raid_handle_sys.handle_num - 1) {
		ret = raid_handle_init();
		if (ret < SUCCESS)
			return (ret);
	}

	ret = raid_handle_sys.unused;
	raid_handle_sys.unused = raid_handle_sys.handles[ret].next;

	raid_handle_sys.handles[ret].next = raid_handle_sys.used;
	raid_handle_sys.used = ret;
	raid_handle_sys.handles[ret].type = type;

	return (ret);
}

static void
raid_handle_delete(raid_obj_handle_t handle)
{
	int i = raid_handle_sys.used, j = 0;

	if (handle == 0)
		return;

	while (i != 0 && i != handle) {
		j = i;
		i = raid_handle_sys.handles[i].next;
	}

	if (i == handle) {
		if (j != 0)
			raid_handle_sys.handles[j].next =
			    raid_handle_sys.handles[i].next;
		else
			raid_handle_sys.used =
			    raid_handle_sys.handles[i].next;

		raid_handle_sys.handles[i].type = OBJ_TYPE_ALL;
		raid_handle_sys.handles[i].next =
		    raid_handle_sys.unused;
		raid_handle_sys.unused = i;
	}
}

static void
raid_handle_delete_controller_comp(uint32_t controller_id)
{
	int i = raid_handle_sys.used, j;

	while (i != 0) {
		j = i;
		i = raid_handle_sys.handles[i].next;
		if ((raid_handle_sys.handles[j].controller_id ==
		    controller_id) &&
		    (raid_handle_sys.handles[j].type !=
		    OBJ_TYPE_CONTROLLER))
		raid_handle_delete(j);
	}
}

static raid_obj_id_t
raid_handle_to_obj(raid_obj_tab_t *raid_tab, raid_obj_handle_t handle)
{
	handle_attr_t *handle_attr;
	raid_obj_id_t obj_id;

	if (handle == OBJ_SYSTEM)
		return (OBJ_SYSTEM);

	handle_attr = raid_handle_sys.handles + handle;

	switch (handle_attr->type) {
	case	OBJ_TYPE_SYSTEM:
		return (OBJ_SYSTEM);
	case	OBJ_TYPE_CONTROLLER:
		obj_id = obj_locate_controller(raid_tab,
		    handle_attr->controller_id);
		break;
	case	OBJ_TYPE_ARRAY:
		obj_id = obj_locate_array(raid_tab,
		    handle_attr->controller_id, handle_attr->array_id);
		break;
	case	OBJ_TYPE_HSP:
		obj_id = obj_locate_hsp(raid_tab,
		    handle_attr->controller_id, handle_attr->disk_id,
		    handle_attr->array_id);
		break;
	case	OBJ_TYPE_DISK:
		obj_id = obj_locate_disk(raid_tab,
		    handle_attr->controller_id, handle_attr->disk_id);
		break;
	case	OBJ_TYPE_ARRAY_PART:
		obj_id = obj_locate_arraypart(raid_tab,
		    handle_attr->controller_id, handle_attr->array_id,
		    handle_attr->disk_id);
		break;
	case	OBJ_TYPE_DISK_SEG:
		obj_id = obj_locate_diskseg(raid_tab,
		    handle_attr->controller_id,
		    handle_attr->disk_id, handle_attr->seq_id);
		break;
	case	OBJ_TYPE_TASK:
		obj_id = obj_locate_task(raid_tab,
		    handle_attr->controller_id, handle_attr->task_id);
		break;
	case	OBJ_TYPE_PROP:
		obj_id = obj_locate_prop(raid_tab,
		    handle_attr->controller_id, handle_attr->disk_id,
		    handle_attr->prop_id);
		break;
	default:
		return (ERR_DEVICE_INVALID);
	}

	if (obj_id < OBJ_NONE)
		return (obj_id);
	if (obj_id == OBJ_NONE)
		return (ERR_DEVICE_NOENT);

	(void) raid_obj_set_handle(raid_tab, obj_id, handle);
	return (obj_id);
}

static raid_obj_handle_t
raid_obj_to_handle(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_id_t obj_id_backup = obj_id;
	raid_obj_type_id_t type;
	raid_obj_handle_t handle;
	controller_attr_t *controller_attr;
	array_attr_t *array_attr;
	hsp_attr_t *hsp_attr;
	disk_attr_t *disk_attr;
	arraypart_attr_t *arraypart_attr;
	diskseg_attr_t *diskseg_attr;
	task_attr_t *task_attr;
	property_attr_t *prop_attr;

	if (obj_id == OBJ_SYSTEM)
		return (OBJ_SYSTEM);

	/* If the object mapped by a handle */
	handle = raid_obj_get_handle(raid_tab, obj_id);
	if (handle != 0)
		return (handle);

	/* Search for existing handles */
	for (handle = raid_handle_sys.used; handle != 0;
	    handle = raid_handle_sys.handles[handle].next)
		if (raid_handle_to_obj(raid_tab, handle) == obj_id)
			break;

	if (handle != 0)
		return (handle);

	/* Allocate new handle for this object */
	type = raid_obj_get_type(raid_tab, obj_id);
	handle = raid_handle_new(type);
	(void) raid_obj_set_handle(raid_tab, obj_id, handle);
	raid_handle_sys.handles[handle].type = type;

	switch (type) {
	case OBJ_TYPE_SYSTEM:
		break;
	case OBJ_TYPE_CONTROLLER:
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	case OBJ_TYPE_ARRAY:
		array_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].array_id = array_attr->array_id;
		obj_id = obj_get_controller(raid_tab, obj_id);
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	case OBJ_TYPE_HSP:
		hsp_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].array_id =
		    hsp_attr->associated_id;
		obj_id = raid_obj_get_container(raid_tab, obj_id);
		disk_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].disk_id = disk_attr->disk_id;
		obj_id = obj_get_controller(raid_tab, obj_id);
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	case OBJ_TYPE_DISK:
		disk_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].disk_id = disk_attr->disk_id;
		obj_id = obj_get_controller(raid_tab, obj_id);
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	case OBJ_TYPE_ARRAY_PART:
		arraypart_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].disk_id =
		    arraypart_attr->disk_id;
		obj_id = raid_obj_get_container(raid_tab, obj_id);
		array_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].array_id =
		    array_attr->array_id;
		obj_id = obj_get_controller(raid_tab, obj_id);
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	case OBJ_TYPE_DISK_SEG:
		diskseg_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].seq_id = diskseg_attr->seq_no;
		obj_id = raid_obj_get_container(raid_tab, obj_id);
		disk_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].disk_id =
		    disk_attr->disk_id;
		obj_id = obj_get_controller(raid_tab, obj_id);
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	case OBJ_TYPE_TASK:
		task_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].task_id = task_attr->task_id;
		obj_id = obj_get_controller(raid_tab, obj_id);
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	case OBJ_TYPE_PROP:
		prop_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].prop_id =
		    prop_attr->prop_id;
		obj_id = raid_obj_get_container(raid_tab, obj_id);
		disk_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].disk_id = disk_attr->disk_id;
		obj_id = obj_get_controller(raid_tab, obj_id);
		controller_attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		raid_handle_sys.handles[handle].controller_id =
		    controller_attr->controller_id;
		break;
	default:
		return (ERR_DEVICE_INVALID);
	}

	(void) raid_obj_set_handle(raid_tab, obj_id_backup, handle);
	return (handle);
}

static raid_lib_t *
raid_obj_get_lib(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_handle_t handle;
	controller_attr_t *attr;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (NULL);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	handle = raid_handle_sys.used;
	while (raid_handle_sys.handles[handle].type != OBJ_TYPE_CONTROLLER ||
	    raid_handle_sys.handles[handle].controller_id !=
	    attr->controller_id)
		handle = raid_handle_sys.handles[handle].next;

	if (handle == 0)
		return (NULL);

	return (raid_handle_sys.handles[handle].raid_lib);
}

static int
raid_obj_set_lib(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_lib_t *raid_lib)
{
	raid_obj_handle_t handle;
	controller_attr_t *attr;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (ERR_DEVICE_TYPE);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	handle = raid_handle_sys.used;
	while (raid_handle_sys.handles[handle].type != OBJ_TYPE_CONTROLLER ||
	    raid_handle_sys.handles[handle].controller_id !=
	    attr->controller_id)
		handle = raid_handle_sys.handles[handle].next;

	if (handle == 0)
		return (ERR_DEVICE_NOENT);

	raid_handle_sys.handles[handle].raid_lib = raid_lib;
	return (SUCCESS);
}

static int
raid_obj_get_fd(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_handle_t handle;
	controller_attr_t *attr;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (ERR_DEVICE_TYPE);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	handle = raid_handle_sys.used;
	while (raid_handle_sys.handles[handle].type != OBJ_TYPE_CONTROLLER ||
	    raid_handle_sys.handles[handle].controller_id !=
	    attr->controller_id)
		handle = raid_handle_sys.handles[handle].next;

	if (handle == 0)
		return (ERR_DEVICE_NOENT);

	return (raid_handle_sys.handles[handle].fd);
}

static int
raid_obj_set_fd(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id, int fd)
{
	raid_obj_handle_t handle;
	controller_attr_t *attr;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (ERR_DEVICE_TYPE);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	handle = raid_handle_sys.used;
	while (raid_handle_sys.handles[handle].type != OBJ_TYPE_CONTROLLER ||
	    raid_handle_sys.handles[handle].controller_id !=
	    attr->controller_id)
		handle = raid_handle_sys.handles[handle].next;

	if (handle == 0)
		return (ERR_DEVICE_NOENT);

	raid_handle_sys.handles[handle].fd = fd;
	return (SUCCESS);
}

/*
 * Raid object maintenance routines
 */
static int
obj_scan_comp(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_status_t status;
	raid_obj_type_id_t type;
	int ret, i, obj_type_cnt, comp_num;
	raid_obj_id_t *comp_list;

	status = raid_obj_get_status(raid_tab, obj_id);
	if (status < SUCCESS)
		return (status);

	if (status & OBJ_STATUS_SCANCOMP)
		return (SUCCESS);

	type = raid_obj_get_type(raid_tab, obj_id);
	/* type less than OBJ_TYPE_SYSTEM means error */
	if (type < OBJ_TYPE_SYSTEM)
		return (ERR_DEVICE_INVALID);

	for (obj_type_cnt = OBJ_SYSTEM; obj_type_cnt < OBJ_TYPE_ALL;
	    ++obj_type_cnt) {
		if (raid_obj_op_sys[type].compnum != NULL)
			comp_num = raid_obj_op_sys[type].compnum(
			    raid_tab, obj_id, obj_type_cnt);
		else
			comp_num = 0;

		if (comp_num < SUCCESS)
			return (comp_num);
		if (comp_num == 0)
			continue;

		comp_list = calloc(comp_num, sizeof (raid_obj_id_t));
		if (comp_list == NULL)
			return (ERR_NOMEM);

		for (i = 0; i < comp_num; ++i) {
			*(comp_list + i) = raid_obj_create(raid_tab,
			    obj_type_cnt);
			if (*(comp_list + i) < SUCCESS) {
				ret = *(comp_list + i);
				free(comp_list);
				return (ret);
			}

			(void) raid_obj_clear_status(raid_tab,
			    *(comp_list + i), OBJ_STATUS_CMD_CLEAN);
			(void) raid_obj_add_org(raid_tab, *(comp_list + i),
			    obj_id);
		}

		if (raid_obj_op_sys[type].complist != NULL)
			raid_obj_op_sys[type].complist(raid_tab,
			    obj_id, comp_num, comp_list, obj_type_cnt);
		free(comp_list);
	}

	(void) raid_obj_set_status(raid_tab, obj_id, OBJ_STATUS_SCANCOMP);
	return (SUCCESS);
}

static int
obj_rescan(raid_obj_tab_t *raid_tab)
{
	int ret;

	raid_obj_tab_destroy(raid_tab);

	if (raid_obj_tab_create(raid_tab, HASH_SLOTS) != SUCCESS)
		return (ERR_NOMEM);

	if ((ret = raid_obj_create_system_obj(raid_tab)) != SUCCESS) {
		raid_obj_tab_destroy(raid_tab);
		return (ret);
	}

	return (SUCCESS);
}

static raid_obj_id_t
obj_get_comp(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_type_id_t obj_type)
{
	raid_obj_id_t id;
	raid_obj_type_id_t type;
	raid_obj_status_t status;
	int ret;

	if ((obj_type < OBJ_TYPE_SYSTEM) || (obj_type > OBJ_TYPE_ALL))
		return (ERR_DEVICE_TYPE);

	status = raid_obj_get_status(raid_tab, obj_id);
	if (status < SUCCESS)
		return (status);

	if (!(status & OBJ_STATUS_SCANCOMP)) {
		ret = obj_scan_comp(raid_tab, obj_id);
		if (ret < SUCCESS)
			return (ret);
	}

	id = raid_obj_get_comp(raid_tab, obj_id);
	if (id <= OBJ_NONE)
		return (id);

	type = raid_obj_get_type(raid_tab, id);
	if (type < OBJ_TYPE_SYSTEM)
		return (type);

	if (type == obj_type)
		return (id);

	while (id > OBJ_NONE) {
		id = raid_obj_get_sibling(raid_tab, id);
		if (id <= OBJ_NONE)
			return (id);

		type = raid_obj_get_type(raid_tab, id);
		if (type < OBJ_TYPE_SYSTEM)
			return (type);

		if (type == obj_type)
			break;
	};

	return (id);
}

static raid_obj_id_t
obj_get_sibling(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_id_t id;
	raid_obj_type_id_t type, obj_type;

	id = obj_id;
	obj_type = raid_obj_get_type(raid_tab, id);
	if (obj_type < OBJ_TYPE_SYSTEM)
		return (obj_type);

	do {
		id = raid_obj_get_sibling(raid_tab, id);
		if (id < OBJ_NONE)
			return (id);

		type = raid_obj_get_type(raid_tab, id);
		if (type < OBJ_TYPE_SYSTEM)
			return (type);
	} while ((type != obj_type) && (id != OBJ_NONE));

	return (id);
}

static int
obj_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id, void **data)
{
	raid_obj_type_id_t type;
	raid_obj_status_t status;
	void *attr;
	int ret = SUCCESS;

	status = raid_obj_get_status(raid_tab, obj_id);
	if (status < SUCCESS)
		return (status);

	type = raid_obj_get_type(raid_tab, obj_id);
	if (type < OBJ_TYPE_SYSTEM)
		return (type);

	if (!(status & OBJ_STATUS_OPENED)) {
		if (raid_obj_op_sys[type].get_attr == NULL)
			(void) raid_obj_set_status(raid_tab, obj_id,
			    OBJ_STATUS_OPENED);
		else
			ret = raid_obj_op_sys[type].get_attr(raid_tab, obj_id);
	}
	if (ret < SUCCESS)
		return (ret);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL && type != OBJ_TYPE_SYSTEM)
		return (ERR_DEVICE_INVALID);

	*data = attr;
	return (SUCCESS);
}

static raid_obj_id_t
obj_locate_controller(raid_obj_tab_t *raid_tab, uint32_t controller_id)
{
	raid_obj_id_t obj_id;
	controller_attr_t *attr;

	obj_id = obj_get_comp(raid_tab, OBJ_SYSTEM, OBJ_TYPE_CONTROLLER);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	do {
		attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		if (attr == NULL)
			return (ERR_DEVICE_INVALID);

		if (attr->controller_id == controller_id)
			break;
	} while ((obj_id = obj_get_sibling(raid_tab, obj_id)) != OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_array(raid_obj_tab_t *raid_tab, uint32_t controller_id,
    uint32_t array_id)
{
	raid_obj_id_t obj_id;

	obj_id = obj_locate_controller(raid_tab, controller_id);
	if (obj_id < OBJ_NONE)
		return (obj_id);

	obj_id = obj_locate_array_recur(raid_tab, obj_id, array_id);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_array_recur(raid_obj_tab_t *raid_tab,
    raid_obj_id_t container_obj_id, uint32_t array_id)
{
	raid_obj_id_t obj_id, ret;
	array_attr_t *attr;

	obj_id = obj_get_comp(raid_tab, container_obj_id, OBJ_TYPE_ARRAY);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	do {
		attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		if (attr == NULL)
			return (ERR_DEVICE_INVALID);

		if (attr->array_id == array_id)
			break;

		ret = obj_locate_array_recur(raid_tab, obj_id, array_id);
		if (ret != OBJ_NONE)
			return (ret);

	} while ((obj_id = obj_get_sibling(raid_tab, obj_id)) > OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_hsp(raid_obj_tab_t *raid_tab, uint32_t controller_id,
    uint32_t disk_id, uint32_t array_id)
{
	raid_obj_id_t obj_id;
	hsp_attr_t *hsp_attr;

	obj_id = obj_locate_disk(raid_tab, controller_id, disk_id);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_HSP);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	do {
		(void) obj_get_attr(raid_tab, obj_id, (void **)(&hsp_attr));
		if (hsp_attr->associated_id == array_id)
			break;

		obj_id = obj_get_sibling(raid_tab, obj_id);
		if (obj_id < OBJ_NONE)
			return (obj_id);
	} while (obj_id > OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_disk(raid_obj_tab_t *raid_tab, uint32_t controller_id,
    uint32_t disk_id)
{
	raid_obj_id_t obj_id;
	disk_attr_t *attr;

	obj_id = obj_locate_controller(raid_tab, controller_id);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_DISK);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	do {
		attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		if (attr == NULL)
			return (ERR_DEVICE_INVALID);

		if (attr->disk_id == disk_id)
			break;
	} while ((obj_id = obj_get_sibling(raid_tab, obj_id)) > OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_arraypart(raid_obj_tab_t *raid_tab, uint32_t controller_id,
    uint32_t array_id, uint32_t disk_id)
{
	raid_obj_id_t obj_id;

	arraypart_attr_t *attr;

	obj_id = obj_locate_array(raid_tab, controller_id, array_id);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_ARRAY_PART);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	do {
		attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		if (attr == NULL)
			return (ERR_DEVICE_INVALID);

		if (attr->disk_id == disk_id)
			break;
	} while ((obj_id = obj_get_sibling(raid_tab, obj_id)) >
	    OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_diskseg(raid_obj_tab_t *raid_tab, uint32_t controller_id,
    uint32_t disk_id, uint32_t seq_no)
{
	raid_obj_id_t obj_id;
	diskseg_attr_t *attr;

	obj_id = obj_locate_disk(raid_tab, controller_id, disk_id);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_DISK_SEG);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	do {
		attr = raid_obj_get_data_ptr(raid_tab, obj_id);
		if (attr == NULL)
			return (ERR_DEVICE_INVALID);

		if (attr->seq_no == seq_no)
			break;
	} while ((obj_id = obj_get_sibling(raid_tab, obj_id)) > OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_task(raid_obj_tab_t *raid_tab, uint32_t controller_id,
    uint32_t task_id)
{
	raid_obj_id_t obj_id, obj_id2, task_obj_id;
	task_attr_t *attr;

	obj_id = obj_locate_controller(raid_tab, controller_id);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_ARRAY);
	if (obj_id < OBJ_NONE)
		return (obj_id);

	do {
		obj_id2 = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_ARRAY);
		while (obj_id2 != OBJ_NONE) {
			task_obj_id = obj_get_comp(raid_tab, obj_id2,
			    OBJ_TYPE_TASK);

			if (task_obj_id < OBJ_NONE)
				return (task_obj_id);

			if (task_obj_id == OBJ_NONE) {
				obj_id2 = obj_get_sibling(raid_tab, obj_id2);
				continue;
			}

			attr = raid_obj_get_data_ptr(raid_tab, task_obj_id);
			if (attr == NULL)
				return (ERR_DEVICE_INVALID);

			if (attr->task_id == task_id)
				return (task_obj_id);

			obj_id2 = obj_get_sibling(raid_tab, obj_id2);
		}

		task_obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_TASK);
		if (task_obj_id < OBJ_NONE)
			return (task_obj_id);

		if (task_obj_id == OBJ_NONE)
			continue;

		attr = raid_obj_get_data_ptr(raid_tab, task_obj_id);
		if (attr == NULL)
			return (ERR_DEVICE_INVALID);

		if (attr->task_id == task_id)
			return (task_obj_id);
	} while ((obj_id = obj_get_sibling(raid_tab, obj_id)) > OBJ_NONE);

	if (obj_id < OBJ_NONE)
		return (obj_id);

	obj_id = obj_locate_controller(raid_tab, controller_id);
	obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_DISK);
	if (obj_id < OBJ_NONE)
		return (obj_id);

	do {
		task_obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_TASK);
		if (task_obj_id < OBJ_NONE)
			return (task_obj_id);

		if (task_obj_id == OBJ_NONE)
			continue;

		attr = raid_obj_get_data_ptr(raid_tab, task_obj_id);
		if (attr == NULL)
			return (ERR_DEVICE_INVALID);

		if (attr->task_id == task_id)
			return (task_obj_id);
	} while ((obj_id = obj_get_sibling(raid_tab, obj_id)) > OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_locate_prop(raid_obj_tab_t *raid_tab, uint32_t controller_id,
    uint32_t disk_id, uint32_t prop_id)
{
	raid_obj_id_t obj_id;
	property_attr_t *prop_attr;

	obj_id = obj_locate_disk(raid_tab, controller_id, disk_id);
	if (obj_id < OBJ_NONE)
		return (obj_id);

	obj_id = obj_get_comp(raid_tab, obj_id, OBJ_TYPE_PROP);
	if (obj_id <= OBJ_NONE)
		return (obj_id);

	do {
		(void) obj_get_attr(raid_tab, obj_id, (void **)(&prop_attr));
		if (prop_attr->prop_id == prop_id)
			break;

		obj_id = obj_get_sibling(raid_tab, obj_id);
		if (obj_id < OBJ_NONE)
			return (obj_id);
	} while (obj_id > OBJ_NONE);

	return (obj_id);
}

static raid_obj_id_t
obj_get_controller(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_id_t id = obj_id;

	while (raid_obj_get_type(raid_tab, id) != OBJ_TYPE_CONTROLLER) {
		id = raid_obj_get_container(raid_tab, id);
		if ((id == OBJ_SYSTEM) || (id < OBJ_NONE))
			return (ERR_DEVICE_INVALID);
	}

	return (id);
}

/*
 * Raid object operation routines
 */
static int
obj_sys_compnum(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_type_id_t comp_type)
{
	DIR *dir;
	struct dirent *dp;
	int num = 0;

	if ((raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_SYSTEM))
		return (ERR_DEVICE_TYPE);

	if (comp_type != OBJ_TYPE_CONTROLLER)
		return (0);

	if ((dir = opendir(CFGDIR)) == NULL)
		return (ERR_DRIVER_NOT_FOUND);

	while ((dp = readdir(dir)) != NULL) {
		uint32_t controller_id;
		char path[MAX_PATH_LEN];

		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		if (sscanf(dp->d_name, "c%u", &controller_id) != 1)
			continue;

		if (controller_id_to_path(controller_id, path) == SUCCESS)
			++ num;
	}

	(void) closedir(dir);
	return (num);
}

static int
obj_sys_complist(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    int num, raid_obj_id_t *comp_list, raid_obj_type_id_t comp_type)
{
	DIR *dir;
	struct dirent *dp;
	controller_attr_t *attr;
	uint32_t controller_id;
	uint32_t *tmplist;
	char path[MAX_PATH_LEN];
	int i = 0;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_SYSTEM)
		return (ERR_DEVICE_TYPE);
	if ((num <= 0) || (comp_list == NULL))
		return (ERR_OP_ILLEGAL);

	if (comp_type != OBJ_TYPE_CONTROLLER)
		return (0);

	if ((dir = opendir(CFGDIR)) == NULL)
		return (ERR_DRIVER_NOT_FOUND);
	tmplist = calloc(num, sizeof (uint32_t));
	if (tmplist == NULL) {
		return (ERR_NOMEM);
	}
	while ((dp = readdir(dir)) != NULL) {
		if (strcmp(dp->d_name, ".") == 0 ||
		    strcmp(dp->d_name, "..") == 0)
			continue;

		if (sscanf(dp->d_name, "c%u", &controller_id) != 1)
			continue;

		if (controller_id_to_path(controller_id, path) == SUCCESS) {
			tmplist[i] = controller_id;
			++ i;
		}
	}
	qsort((void *)tmplist, num, sizeof (uint32_t), intcompare);
	for (i = 0; i < num; i++) {
		attr = raid_obj_get_data_ptr(raid_tab,
		    *(comp_list + i));

		if (attr == NULL) {
			free(tmplist);
			return (ERR_DEVICE_INVALID);
		}

		attr->controller_id = tmplist[i];
	}
	free(tmplist);
	(void) closedir(dir);
	return (SUCCESS);
}

static int
obj_controller_compnum(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_type_id_t comp_type)
{
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	controller_attr_t *ctl_attrp;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (ERR_DEVICE_TYPE);

	if ((comp_type != OBJ_TYPE_ARRAY) && (comp_type != OBJ_TYPE_DISK))
		return (0);

	raid_lib = raid_obj_get_lib(raid_tab, obj_id);
	fd = raid_obj_get_fd(raid_tab, obj_id);
	ctl_attrp = raid_obj_get_data_ptr(raid_tab, obj_id);
	if ((raid_lib == NULL) || (ctl_attrp == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->compnum(ctl_attrp->controller_id, 0,
	    OBJ_TYPE_CONTROLLER, comp_type);

	return (ret);
}

static int
obj_controller_complist(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    int comp_num, raid_obj_id_t *comp_list, raid_obj_type_id_t comp_type)
{
	raid_lib_t *raid_lib;
	controller_attr_t *ctl_attrp;
	int ret, i, fd;
	uint32_t *ids;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (ERR_DEVICE_TYPE);

	if ((comp_type != OBJ_TYPE_ARRAY) && (comp_type != OBJ_TYPE_DISK))
		return (0);

	if ((comp_num <= 0) || (comp_list == NULL))
		return (ERR_OP_ILLEGAL);

	for (i = 0; i < comp_num; ++i)
		if (raid_obj_get_type(raid_tab, *(comp_list + i)) !=
		    comp_type)
			return (ERR_DEVICE_TYPE);

	raid_lib = raid_obj_get_lib(raid_tab, obj_id);
	ctl_attrp = raid_obj_get_data_ptr(raid_tab, obj_id);
	fd = raid_obj_get_fd(raid_tab, obj_id);
	if ((raid_lib == NULL) || (ctl_attrp == NULL)|| (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ids = malloc(comp_num * sizeof (uint32_t));
	if (ids == NULL)
		return (ERR_NOMEM);

	ret = raid_lib->complist(ctl_attrp->controller_id, 0,
	    OBJ_TYPE_CONTROLLER, comp_type, comp_num, ids);
	if (ret < SUCCESS) {
		free(ids);
		return (ret);
	}
	qsort((void *)ids, comp_num, sizeof (uint32_t), intcompare);
	for (i = 0; i < comp_num; ++ i) {
		array_attr_t *array_attr;
		disk_attr_t *disk_attr;
		void *attr_buf;

		attr_buf = raid_obj_get_data_ptr(raid_tab, *(comp_list + i));
		if (attr_buf == NULL) {
			free(ids);
			return (ERR_DEVICE_INVALID);
		}

		switch (comp_type) {
		case OBJ_TYPE_ARRAY:
			array_attr = attr_buf;
			array_attr->array_id = *(ids + i);
			break;
		case OBJ_TYPE_DISK:
			disk_attr = attr_buf;
			disk_attr->disk_id = *(ids + i);
			break;
		default:
			free(ids);
			return (ERR_DEVICE_INVALID);
		}
	}

	free(ids);
	return (SUCCESS);
}

static int
obj_controller_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	controller_attr_t *attr;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (ERR_DEVICE_TYPE);

	if (raid_obj_get_status(raid_tab, obj_id) & OBJ_STATUS_OPENED)
		return (SUCCESS);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	raid_lib = raid_obj_get_lib(raid_tab, obj_id);
	fd = raid_obj_get_fd(raid_tab, obj_id);

	/*
	 * For a controller, even it's not opened, we can still
	 * get the driver name
	 */

	if (fd == 0)
		return (SUCCESS);

	if (raid_lib == NULL) {
		return (SUCCESS);
	}

	ret = raid_lib->get_attr(attr->controller_id, OBJ_ATTR_NONE,
	    OBJ_ATTR_NONE, OBJ_TYPE_CONTROLLER, attr);
	if (ret < SUCCESS)
		return (ret);

	(void) raid_obj_set_status(raid_tab, obj_id, OBJ_STATUS_OPENED);

	return (ret);
}

static int
obj_controller_act(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    uint32_t sub_cmd, void *prop_list, char **plugin_err_str)
{
	controller_attr_t *attr;
	raid_lib_t *raid_lib;
	int ret, fd;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_CONTROLLER)
		return (ERR_DEVICE_TYPE);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);

	raid_lib = raid_obj_get_lib(raid_tab, obj_id);
	fd = raid_obj_get_fd(raid_tab, obj_id);

	switch (sub_cmd) {
	case ACT_CONTROLLER_OPEN:
		/* Check if already opened */

		if (fd > 0)
			return (SUCCESS);

		/* Check if plugin is already attached */
		if (raid_lib == NULL) {
			raid_lib = raid_find_lib(raid_tab, obj_id);
			if (raid_lib == NULL)
				return (ERR_DRIVER_NOT_FOUND);
		}

		ret = raid_lib->open_controller(attr->controller_id,
		    plugin_err_str);
		if (ret == SUCCESS) {
			(void) raid_obj_set_lib(raid_tab, obj_id, raid_lib);
			(void) raid_obj_set_fd(raid_tab, obj_id, 1);
		}
		break;
	case ACT_CONTROLLER_CLOSE:

		if (fd <= 0)
			return (SUCCESS);

		if (raid_lib == NULL) {
			return (SUCCESS);
		}
		ret = raid_lib->close_controller(attr->controller_id,
		    plugin_err_str);
		if (ret == SUCCESS) {
			(void) raid_obj_set_fd(raid_tab, obj_id, 0);
			(void) raid_obj_set_lib(raid_tab, obj_id, NULL);
			raid_handle_delete_controller_comp(attr->controller_id);
		}
		break;
	case ACT_CONTROLLER_FLASH_FW:
		{
			char		*filebuf;
			int		image_fd;
			uint32_t	size;
			struct stat	statbuf;

			if (prop_list == NULL)
				return (ERR_OP_ILLEGAL);

			/* Open firmware image file */
			image_fd = open((const char *)prop_list,
			    O_RDONLY | O_NDELAY);
			if (image_fd == -1)
				return (ERR_OP_FAILED);

			if (fstat(image_fd, &statbuf) != 0) {
				(void) close(image_fd);
				return (ERR_OP_FAILED);
			}

			filebuf = malloc(statbuf.st_size);
			if (filebuf == NULL) {
				(void) close(image_fd);
				return (ERR_NOMEM);
			}

			size = read(image_fd, filebuf, statbuf.st_size);
			if (size != statbuf.st_size) {
				(void) close(image_fd);
				free(filebuf);
				return (ERR_OP_FAILED);
			}

			if (fd <= 0) {
				(void) close(image_fd);
				free(filebuf);
				return (ERR_DRIVER_CLOSED);
			}

			if (raid_lib == NULL) {
				(void) close(image_fd);
				free(filebuf);
				return (ERR_DRIVER_CLOSED);
			}
			if (raid_lib->flash_fw == NULL) {
				(void) close(image_fd);
				free(filebuf);
				return (ERR_OP_NO_IMPL);
			}

			ret = raid_lib->flash_fw(attr->controller_id,
			    filebuf, size, plugin_err_str);
		}
		break;
	default:
		return (ERR_OP_ILLEGAL);
	}

	return (ret);
}

static int
obj_array_compnum(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_type_id_t comp_type)
{
	array_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_obj_id_t controller_obj_id;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_ARRAY)
		return (ERR_DEVICE_TYPE);

	if (comp_type != OBJ_TYPE_ARRAY_PART &&
	    comp_type != OBJ_TYPE_ARRAY &&
	    comp_type != OBJ_TYPE_TASK)
		return (0);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->compnum(ctl_attrp->controller_id, attr->array_id,
	    OBJ_TYPE_ARRAY, comp_type);

	return (ret);
}

static int
obj_array_complist(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    int comp_num, raid_obj_id_t *comp_list, raid_obj_type_id_t comp_type)
{
	array_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_obj_id_t controller_obj_id;
	raid_lib_t *raid_lib;
	int ret, i, fd;
	uint32_t *ids;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_ARRAY)
		return (ERR_DEVICE_TYPE);

	if (comp_type != OBJ_TYPE_ARRAY_PART &&
	    comp_type != OBJ_TYPE_ARRAY &&
	    comp_type != OBJ_TYPE_TASK)
		return (0);

	if (comp_num <= 0 || comp_list == NULL)
		return (ERR_OP_ILLEGAL);

	for (i = 0; i < comp_num; ++i)
		if (raid_obj_get_type(raid_tab, *(comp_list + i)) !=
		    comp_type)
			return (ERR_DEVICE_TYPE);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ids = malloc(comp_num * sizeof (uint32_t));
	if (ids == NULL)
		return (ERR_NOMEM);

	ret = raid_lib->complist(ctl_attrp->controller_id,
	    attr->array_id, OBJ_TYPE_ARRAY, comp_type, comp_num, ids);

	if (ret < SUCCESS) {
		free(ids);
		return (ret);
	}

	for (i = 0; i < comp_num; ++ i) {
		array_attr_t *array_attr;
		arraypart_attr_t *arraypart_attr;
		task_attr_t *task_attr;
		void *attr_buf;

		attr_buf = raid_obj_get_data_ptr(raid_tab, *(comp_list + i));
		if (attr_buf == NULL) {
			free(ids);
			return (ERR_DEVICE_INVALID);
		}

		switch (comp_type) {
		case OBJ_TYPE_ARRAY:
			array_attr = attr_buf;
			array_attr->array_id = *(ids + i);
			break;
		case OBJ_TYPE_ARRAY_PART:
			arraypart_attr = attr_buf;
			arraypart_attr->disk_id = *(ids + i);
			break;
		case OBJ_TYPE_TASK:
			task_attr = attr_buf;
			task_attr->task_id = *(ids + i);
			break;
		default:
			free(ids);
			return (ERR_DEVICE_INVALID);
		}
	}


	free(ids);
	return (ret);
}

static int
obj_array_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	array_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	raid_obj_id_t controller_obj_id;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_ARRAY)
		return (ERR_DEVICE_TYPE);

	if (raid_obj_get_status(raid_tab, obj_id) & OBJ_STATUS_OPENED)
		return (SUCCESS);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->get_attr(ctl_attrp->controller_id,
	    attr->array_id, 0, OBJ_TYPE_ARRAY, attr);

	if (ret < SUCCESS)
		return (ret);

	(void) raid_obj_set_status(raid_tab, obj_id, OBJ_STATUS_OPENED);

	return (ret);
}

static int
obj_array_set_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    uint32_t sub_cmd, uint32_t *value, char **plugin_err_str)
{
	array_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	raid_obj_id_t controller_obj_id;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_ARRAY)
		return (ERR_DEVICE_TYPE);

	switch (sub_cmd) {
	case SET_CACHE_WR_PLY:
		if (*value != CACHE_WR_OFF &&
		    *value != CACHE_WR_ON)
			return (ERR_OP_ILLEGAL);
		break;
	case SET_CACHE_RD_PLY:
		if (*value != CACHE_RD_OFF &&
		    *value != CACHE_RD_ON)
			return (ERR_OP_ILLEGAL);
		break;
	case SET_ACTIVATION_PLY:
		if (*value != ARRAY_ACT_ACTIVATE)
			return (ERR_OP_ILLEGAL);
		break;
	default:
		return (ERR_OP_ILLEGAL);
	}

	(void) obj_get_attr(raid_tab, obj_id, (void **)(&attr));

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	if (raid_lib->set_attr == NULL)
		return (ERR_OP_NO_IMPL);

	ret = raid_lib->set_attr(ctl_attrp->controller_id,
	    attr->array_id, sub_cmd, value, plugin_err_str);

	return (ret);
}

static int
obj_disk_compnum(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_type_id_t comp_type)
{
	disk_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_obj_id_t controller_obj_id;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_DISK)
		return (ERR_DEVICE_TYPE);

	if (comp_type != OBJ_TYPE_DISK_SEG &&
	    comp_type != OBJ_TYPE_HSP &&
	    comp_type != OBJ_TYPE_TASK &&
	    comp_type != OBJ_TYPE_PROP)
		return (0);
	ret = obj_get_attr(raid_tab, obj_id, (void **)(&attr));
	if ((ret != SUCCESS) || (attr == NULL)) {
		return (ERR_DEVICE_INVALID);
	}
	if (attr->state == DISK_STATE_FAILED) {
		return (SUCCESS);
	}

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->compnum(ctl_attrp->controller_id,
	    attr->disk_id, OBJ_TYPE_DISK, comp_type);

	return (ret);
}

static int
obj_disk_complist(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    int comp_num, raid_obj_id_t *comp_list, raid_obj_type_id_t comp_type)
{
	disk_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_obj_id_t controller_obj_id;
	raid_lib_t *raid_lib;
	int ret, i, fd;
	uint32_t *ids;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_DISK)
		return (ERR_DEVICE_TYPE);

	if (comp_type != OBJ_TYPE_DISK_SEG &&
	    comp_type != OBJ_TYPE_HSP &&
	    comp_type != OBJ_TYPE_TASK &&
	    comp_type != OBJ_TYPE_PROP)
		return (0);

	if (comp_num <= 0 || comp_list == NULL)
		return (ERR_OP_ILLEGAL);

	for (i = 0; i < comp_num; ++i)
		if (raid_obj_get_type(raid_tab, *(comp_list + i)) !=
		    comp_type)
			return (ERR_DEVICE_TYPE);
	ret = obj_get_attr(raid_tab, obj_id, (void **)(&attr));
	if ((ret != SUCCESS) || (attr == NULL)) {
		return (ERR_DEVICE_INVALID);
	}
	if (attr->state == DISK_STATE_FAILED) {
		return (SUCCESS);
	}

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ids = malloc(comp_num * sizeof (uint32_t));
	if (ids == NULL)
		return (ERR_NOMEM);

	ret = raid_lib->complist(ctl_attrp->controller_id,
	    attr->disk_id, OBJ_TYPE_DISK, comp_type, comp_num, ids);

	if (ret < SUCCESS) {
		free(ids);
		return (ret);
	}

	for (i = 0; i < comp_num; ++ i) {
		diskseg_attr_t *diskseg_attr;
		hsp_attr_t *hsp_attr;
		task_attr_t *task_attr;
		property_attr_t *prop_attr;
		void *attr_buf;

		attr_buf = raid_obj_get_data_ptr(raid_tab, *(comp_list + i));
		if (attr_buf == NULL) {
			free(ids);
			return (ERR_DEVICE_INVALID);
		}

		switch (comp_type) {
		case OBJ_TYPE_DISK_SEG:
			diskseg_attr = attr_buf;
			diskseg_attr->seq_no = *(ids + i);
			break;
		case OBJ_TYPE_HSP:
			hsp_attr = attr_buf;
			hsp_attr->associated_id = *(ids + i);
			break;
		case OBJ_TYPE_TASK:
			task_attr = attr_buf;
			task_attr->task_id = *(ids + i);
			break;
		case OBJ_TYPE_PROP:
			prop_attr = attr_buf;
			prop_attr->prop_id = *(ids + i);
			break;
		default:
			free(ids);
			return (ERR_DEVICE_INVALID);
		}
	}


	free(ids);
	return (ret);
}

static int
obj_disk_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	disk_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	raid_obj_id_t controller_obj_id;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_DISK)
		return (ERR_DEVICE_TYPE);

	if (raid_obj_get_status(raid_tab, obj_id) & OBJ_STATUS_OPENED)
		return (SUCCESS);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->get_attr(ctl_attrp->controller_id,
	    attr->disk_id, 0, OBJ_TYPE_DISK, attr);

	if (ret < SUCCESS)
		return (ret);

	(void) raid_obj_set_status(raid_tab, obj_id, OBJ_STATUS_OPENED);

	return (ret);
}

static int
obj_hsp_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	hsp_attr_t *attr;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_HSP)
		return (ERR_DEVICE_TYPE);

	if (raid_obj_get_status(raid_tab, obj_id) & OBJ_STATUS_OPENED)
		return (SUCCESS);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	if (attr->associated_id == (uint32_t)OBJ_ATTR_NONE)
		attr->type = HSP_TYPE_GLOBAL;
	else
		attr->type = HSP_TYPE_LOCAL;

	return (SUCCESS);
}

static int
obj_arraypart_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	arraypart_attr_t *attr;
	array_attr_t *array_attr;
	controller_attr_t *ctl_attrp;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	raid_obj_id_t controller_obj_id, array_obj_id;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_ARRAY_PART)
		return (ERR_DEVICE_TYPE);

	if (raid_obj_get_status(raid_tab, obj_id) & OBJ_STATUS_OPENED)
		return (SUCCESS);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	array_obj_id = raid_obj_get_container(raid_tab, obj_id);
	if (array_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	array_attr = raid_obj_get_data_ptr(raid_tab, array_obj_id);
	if (array_attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->get_attr(ctl_attrp->controller_id,
	    array_attr->array_id, attr->disk_id,
	    OBJ_TYPE_ARRAY_PART, attr);

	if (ret < SUCCESS)
		return (ret);

	(void) raid_obj_set_status(raid_tab, obj_id, OBJ_STATUS_OPENED);

	return (ret);
}

static int
obj_diskseg_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	diskseg_attr_t *attr;
	disk_attr_t *disk_attr;
	controller_attr_t *ctl_attrp;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	raid_obj_id_t controller_obj_id, disk_obj_id;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_DISK_SEG)
		return (ERR_DEVICE_TYPE);

	if (raid_obj_get_status(raid_tab, obj_id) & OBJ_STATUS_OPENED)
		return (SUCCESS);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	disk_obj_id = raid_obj_get_container(raid_tab, obj_id);
	if (disk_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	disk_attr = raid_obj_get_data_ptr(raid_tab, disk_obj_id);
	if (disk_attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->get_attr(ctl_attrp->controller_id,
	    disk_attr->disk_id, attr->seq_no, OBJ_TYPE_DISK_SEG, attr);

	if (ret < SUCCESS)
		return (ret);

	(void) raid_obj_set_status(raid_tab, obj_id, OBJ_STATUS_OPENED);

	return (ret);
}

static int
obj_task_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	task_attr_t *attr;
	controller_attr_t *ctl_attrp;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	raid_obj_id_t controller_obj_id;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_TASK)
		return (ERR_DEVICE_TYPE);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->get_attr(ctl_attrp->controller_id,
	    attr->task_id, OBJ_ATTR_NONE, OBJ_TYPE_TASK, attr);

	return (ret);
}

static int
obj_prop_get_attr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	property_attr_t *attr, *attr_new;
	disk_attr_t *disk_attr;
	controller_attr_t *ctl_attrp;
	raid_lib_t *raid_lib;
	int ret = SUCCESS, fd;
	raid_obj_id_t controller_obj_id, disk_obj_id;

	if (raid_obj_get_type(raid_tab, obj_id) != OBJ_TYPE_PROP)
		return (ERR_DEVICE_TYPE);

	if (raid_obj_get_status(raid_tab, obj_id) & OBJ_STATUS_OPENED)
		return (SUCCESS);

	attr = raid_obj_get_data_ptr(raid_tab, obj_id);
	if (attr == NULL)
		return (ERR_DEVICE_INVALID);

	disk_obj_id = raid_obj_get_container(raid_tab, obj_id);
	if (disk_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	disk_attr = raid_obj_get_data_ptr(raid_tab, disk_obj_id);
	if (disk_attr == NULL)
		return (ERR_DEVICE_INVALID);

	controller_obj_id = obj_get_controller(raid_tab, obj_id);
	if (controller_obj_id < OBJ_NONE)
		return (ERR_DEVICE_INVALID);

	ctl_attrp = raid_obj_get_data_ptr(raid_tab, controller_obj_id);
	if (ctl_attrp == NULL) {
		return (ERR_DEVICE_INVALID);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	/* Get the property size at first */
	attr->prop_size = 0;
	ret = raid_lib->get_attr(ctl_attrp->controller_id,
	    disk_attr->disk_id, OBJ_ATTR_NONE, OBJ_TYPE_PROP, attr);

	if (ret < SUCCESS)
		return (ret);

	/* Allocate memory for property and fill the buffer */
	attr_new = realloc(attr, sizeof (property_attr_t) + attr->prop_size);
	if (attr_new == NULL)
		return (ERR_NOMEM);

	(void) raid_obj_set_data_ptr(raid_tab, obj_id, attr_new);

	ret = raid_lib->get_attr(ctl_attrp->controller_id,
	    disk_attr->disk_id, OBJ_ATTR_NONE, OBJ_TYPE_PROP, attr_new);

	if (ret < SUCCESS)
		return (ret);

	(void) raid_obj_set_status(raid_tab, obj_id, OBJ_STATUS_OPENED);

	return (ret);
}

static int
obj_array_create(raid_obj_tab_t *raid_tab, raid_obj_id_t array_obj_id,
    int num_of_comp, raid_obj_id_t *disk_list, char **plugin_err_str)
{
	controller_attr_t *controller_attr;
	array_attr_t *array_attr, array_attr2;
	disk_attr_t *disk_attr;
	arraypart_attr_t *arraypart_attrs;
	raid_obj_id_t obj_id, controller_obj_id = OBJ_NONE;
	raid_lib_t *raid_lib;
	int i, j, ret, fd;
	int disk_cnt = 0, disk_set_num = 0, set_num = 0, layer_cnt = 0;
	uint64_t min_disk_capacity = 0;

	array_attr = raid_obj_get_data_ptr(raid_tab, array_obj_id);
	if (array_attr == NULL)
		return (ERR_DEVICE_INVALID);

	/* Check the disk layout expression */
	if (disk_list[0] != OBJ_SEPARATOR_BEGIN ||
	    disk_list[num_of_comp - 1] != OBJ_SEPARATOR_END)
		return (ERR_ARRAY_LAYOUT);
	for (i = 0; i < num_of_comp; ++i) {
		if (disk_list[i] == OBJ_SEPARATOR_BEGIN) {
			if (disk_cnt != 0)
				return (ERR_ARRAY_LAYOUT);
			++layer_cnt;
			continue;
		}
		if (disk_list[i] == OBJ_SEPARATOR_END) {
			if (disk_set_num == 0)
				disk_set_num = disk_cnt;
			else if (disk_set_num != disk_cnt && disk_cnt != 0)
				return (ERR_ARRAY_LAYOUT);
			disk_cnt = 0;
			++set_num;
			--layer_cnt;
			continue;
		}
		switch (array_attr->raid_level) {
		case RAID_LEVEL_0:
		case RAID_LEVEL_1:
		case RAID_LEVEL_1E:
		case RAID_LEVEL_5:
			if (layer_cnt != 1)
				return (ERR_ARRAY_LAYOUT);
			break;
		case RAID_LEVEL_10:
		case RAID_LEVEL_50:
			if (layer_cnt != 2)
				return (ERR_ARRAY_LAYOUT);
			break;
		default:
			return (ERR_ARRAY_LEVEL);
		}
		++disk_cnt;
	}

	if (layer_cnt != 0)
		return (ERR_ARRAY_LAYOUT);

	switch (array_attr->raid_level) {
	case RAID_LEVEL_0:
		if (disk_set_num < 2 || set_num != 1)
			return (ERR_ARRAY_LAYOUT);
		break;
	case RAID_LEVEL_1:
		if (disk_set_num != 2 || set_num != 1)
			return (ERR_ARRAY_LAYOUT);
		break;
	case RAID_LEVEL_1E:
	case RAID_LEVEL_5:
		if (disk_set_num < 3 || set_num != 1)
			return (ERR_ARRAY_LAYOUT);
		break;
	case RAID_LEVEL_10:
		if (disk_set_num != 2 || set_num < 2)
			return (ERR_ARRAY_LAYOUT);
		break;
	case RAID_LEVEL_50:
		if (disk_set_num < 3 || set_num < 2)
			return (ERR_ARRAY_LAYOUT);
		break;
	default:
		return (ERR_ARRAY_LEVEL);
	}

	arraypart_attrs = calloc(num_of_comp, sizeof (arraypart_attr_t));
	if (arraypart_attrs == NULL)
		return (ERR_NOMEM);

	for (i = 0; i < num_of_comp; ++i) {
		/* Keep seperators */
		if (*(disk_list + i) == OBJ_SEPARATOR_BEGIN) {
			arraypart_attrs[i].disk_id =
			    (uint32_t)OBJ_SEPARATOR_BEGIN;
			continue;
		}

		if (*(disk_list + i) == OBJ_SEPARATOR_END) {
			arraypart_attrs[i].disk_id =
			    (uint32_t)OBJ_SEPARATOR_END;
			continue;
		}

		disk_cnt++;
		/* Check if it's a disk */
		if (raid_obj_get_type(raid_tab, *(disk_list + i)) !=
		    OBJ_TYPE_DISK)
			return (ERR_DEVICE_TYPE);

		/* Check if it's duplicated with other disks */
		for (j = 0; j < i; ++j)
			if (*(disk_list + j) == *(disk_list + i)) {
				free(arraypart_attrs);
				return (ERR_DEVICE_DUP);
			}

		/* Check disk status */
		ret = obj_get_attr(raid_tab, *(disk_list + i),
		    (void **)(&disk_attr));
		if (ret != SUCCESS)
			return (ret);

		if (disk_attr->state != DISK_STATE_GOOD) {
			free(arraypart_attrs);
			return (ERR_DISK_STATE);
		}

		/* All disks must belong to the same controller */
		obj_id = obj_get_controller(raid_tab, *(disk_list + i));
		if (obj_id <= OBJ_NONE)
			return (obj_id);
		if (controller_obj_id == OBJ_NONE) {
			controller_obj_id = obj_id;
			ret = obj_get_attr(raid_tab, controller_obj_id,
			    (void **)(&controller_attr));
		} else if (obj_id != controller_obj_id) {
			free(arraypart_attrs);
			return (ERR_DRIVER_ACROSS);
		}

		/* Check if the disk contains too many segments */
		obj_id = obj_get_comp(raid_tab, *(disk_list + i),
		    OBJ_TYPE_DISK_SEG);
		j = 0;
		while (obj_id > OBJ_NONE) {
			++j;
			obj_id = obj_get_sibling(raid_tab, obj_id);
		}
		if (j > controller_attr->max_seg_per_disk) {
			free(arraypart_attrs);
			return (ERR_DISK_SEG_AMOUNT);
		}

		/* Check if controller is a hostraid controller */
		if (controller_attr->capability & RAID_CAP_DISK_TRANS) {
			/*
			 * For hostraid, the first disk should
			 * be with of minimum capacity
			 */
			if (min_disk_capacity == 0) {
				min_disk_capacity = disk_attr->capacity;

				/* Can not specify capacity for hostraid */
				if (array_attr->capacity != 0) {
					free(arraypart_attrs);
					return (ERR_OP_ILLEGAL);
				}
			} else if (min_disk_capacity > disk_attr->capacity) {
				free(arraypart_attrs);
				return (ERR_DISK_SPACE);
			}

			/* Disk should not be used for hostraid */
			obj_id = obj_get_comp(raid_tab, *(disk_list + i),
			    OBJ_TYPE_DISK_SEG);
			if (obj_id < OBJ_NONE) {
				free(arraypart_attrs);
				return (obj_id);
			} else if (obj_id > OBJ_NONE) {
				free(arraypart_attrs);
				return (ERR_DISK_NOT_EMPTY);
			}
		}

		arraypart_attrs[i].disk_id = disk_attr->disk_id;
		arraypart_attrs[i].offset = OBJ_ATTR_NONE;
		arraypart_attrs[i].size = OBJ_ATTR_NONE;
	}

	/* Check if array amount exceeds limit */
	if (controller_attr->max_array_num <=
	    obj_controller_compnum(raid_tab, controller_obj_id,
	    OBJ_TYPE_ARRAY))
		return (ERR_ARRAY_AMOUNT);


	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	/* Check if the controller can support the array RAID level */
	switch (array_attr->raid_level) {
	case	RAID_LEVEL_0:
		if (!(controller_attr->capability & RAID_CAP_RAID0)) {
			free(arraypart_attrs);
			return (ERR_ARRAY_LEVEL);
		}
		break;
	case	RAID_LEVEL_1:
		if (!(controller_attr->capability & RAID_CAP_RAID1)) {
			free(arraypart_attrs);
			return (ERR_ARRAY_LEVEL);
		}
		break;
	case	RAID_LEVEL_1E:
		if (!(controller_attr->capability & RAID_CAP_RAID1E)) {
			free(arraypart_attrs);
			return (ERR_ARRAY_LEVEL);
		}
		break;
	case	RAID_LEVEL_5:
		if (!(controller_attr->capability & RAID_CAP_RAID5)) {
			free(arraypart_attrs);
			return (ERR_ARRAY_LEVEL);
		}
		break;
	case	RAID_LEVEL_10:
		if (!(controller_attr->capability & RAID_CAP_RAID10)) {
			free(arraypart_attrs);
			return (ERR_ARRAY_LEVEL);
		}
		break;
	case	RAID_LEVEL_50:
		if (!(controller_attr->capability & RAID_CAP_RAID50)) {
			free(arraypart_attrs);
			return (ERR_ARRAY_LEVEL);
		}
		break;
	default:
		free(arraypart_attrs);
		return (ERR_ARRAY_LEVEL);
	}

	/* Check if plug in can calculate the maximum size */
	(void) memcpy(&array_attr2, array_attr, sizeof (array_attr_t));
	array_attr2.capacity = OBJ_ATTR_NONE;
	ret = raid_lib->array_create(controller_attr->controller_id,
	    &array_attr2, num_of_comp, arraypart_attrs, plugin_err_str);

	/* If plugin/driver will not calculate space */
	if (ret == ERR_OP_NO_IMPL) {
		/* Calculate the maximum capacity */
		array_attr2.capacity = raid_space_noalign(raid_tab,
		    array_attr2.raid_level, num_of_comp, disk_list,
		    arraypart_attrs);

		/*
		 * If controller is capable to allocate space,
		 * set offset and size attributes to OBJ_ATTR_NONE
		 * and let the controller to determine these value
		 */
		if (controller_attr->capability & RAID_CAP_SMART_ALLOC)
			for (i = 0; i < num_of_comp; ++i) {
				arraypart_attrs[i].offset =
				    OBJ_ATTR_NONE;
				arraypart_attrs[i].size =
				    OBJ_ATTR_NONE;
			}

		/* There's no enough space for specified capacity */
		if (array_attr->capacity > array_attr2.capacity) {
			free(arraypart_attrs);
			return (ERR_ARRAY_SIZE);
		}

		/* capacity == 0, allocate maximum space */
		if (array_attr->capacity == 0)
			array_attr->capacity = array_attr2.capacity;
	} else if (ret < SUCCESS) {
		free(arraypart_attrs);
		return (ret);
	} else if (array_attr2.capacity < array_attr->capacity) {
		/* Return the maximum size */
		array_attr->capacity = array_attr2.capacity;
		free(arraypart_attrs);
		return (ERR_ARRAY_SIZE);
	}

	if (array_attr->capacity < ARRAYPART_MIN_SIZE * disk_cnt) {
		free(arraypart_attrs);
		return (ERR_ARRAY_SIZE);
	}


	ret = raid_lib->array_create(controller_attr->controller_id,
	    array_attr, num_of_comp, arraypart_attrs, plugin_err_str);
	free(arraypart_attrs);

	if (ret != SUCCESS)
		return (ret);

	/* Add array object into device tree so that we can map the handle */
	(void) raid_obj_add_org(raid_tab, array_obj_id, controller_obj_id);

	return (ret);
}

static int
obj_array_delete(raid_obj_tab_t *raid_tab, raid_obj_id_t array_obj_id,
    char **plugin_err_str)
{
	raid_obj_id_t controller_obj_id;
	controller_attr_t *controller_attr;
	array_attr_t *array_attr;
	raid_lib_t *raid_lib;
	int ret, fd;
	uint32_t *disk_ids = NULL;

	controller_obj_id = obj_get_controller(raid_tab, array_obj_id);
	if (controller_obj_id <= OBJ_NONE)
		return (controller_obj_id);

	ret = obj_get_attr(raid_tab, controller_obj_id,
	    (void **)(&controller_attr));
	if (ret < SUCCESS) {
		return (ret);
	}
	ret = obj_get_attr(raid_tab, array_obj_id, (void **)(&array_attr));
	if (ret < SUCCESS)
		return (ret);

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	ret = raid_lib->array_delete(controller_attr->controller_id,
	    array_attr->array_id, plugin_err_str);
	if (ret < SUCCESS) {
		if (disk_ids)
			free(disk_ids);
		return (ret);
	}

	if (disk_ids)
		free(disk_ids);
	return (ret);
}

static int
obj_hsp_bind(raid_obj_tab_t *raid_tab, raid_obj_id_t *obj_ids,
    char **plugin_err_str)
{
	raid_obj_id_t obj_id, controller_obj_id = OBJ_NONE;
	raid_obj_id_t array_obj_id, disk_obj_id;
	hsp_relation_t *hsp_relation;
	controller_attr_t *controller_attr;
	array_attr_t *array_attr;
	arraypart_attr_t *arraypart_attr;
	disk_attr_t *disk_attr;
	diskseg_attr_t *diskseg_attr;
	hsp_attr_t *hsp_attr;
	raid_lib_t *raid_lib;
	int ret, fd;

	hsp_relation = malloc(sizeof (hsp_relation_t));
	if (hsp_relation == NULL)
		return (ERR_NOMEM);

	array_obj_id = *(obj_ids);
	disk_obj_id = *(obj_ids + 1);

	if (raid_obj_get_type(raid_tab, disk_obj_id) != OBJ_TYPE_DISK ||
	    (array_obj_id != OBJ_ATTR_NONE &&
	    raid_obj_get_type(raid_tab, array_obj_id) !=
	    OBJ_TYPE_ARRAY)) {
		free(hsp_relation);
		return (ERR_DEVICE_TYPE);
	}

	/* Get controller attributes */
	if (controller_obj_id == OBJ_NONE)
		controller_obj_id = obj_get_controller(raid_tab,
		    disk_obj_id);
	else if (controller_obj_id != obj_get_controller(raid_tab,
	    disk_obj_id)) {
		free(hsp_relation);
		return (ERR_DRIVER_ACROSS);
	}

	ret = obj_get_attr(raid_tab, controller_obj_id,
	    (void **)(&controller_attr));

	/* Get disk attributes */
	ret = obj_get_attr(raid_tab,  disk_obj_id,
	    (void **)(&disk_attr));
	if (disk_attr->state == DISK_STATE_FAILED) {
		free(hsp_relation);
		return (ERR_DISK_STATE);
	}

	/* If it's not a hsp disk, check if there's occupied space */
	if (obj_get_comp(raid_tab, disk_obj_id, OBJ_TYPE_HSP) ==
	    OBJ_NONE) {
		obj_id = obj_get_comp(raid_tab, disk_obj_id,
		    OBJ_TYPE_DISK_SEG);
		while (obj_id != OBJ_NONE) {
			ret = obj_get_attr(raid_tab, obj_id,
			    (void **)(&diskseg_attr));
			if (!(diskseg_attr->state &
			    DISKSEG_STATE_RESERVED)) {
				free(hsp_relation);
				return (ERR_DISK_NOT_EMPTY);
			}
			obj_id = obj_get_sibling(raid_tab, obj_id);
		}
	}

	if (array_obj_id != OBJ_ATTR_NONE) {
		/* If local hsp is supported */
		if (!(controller_attr->capability & RAID_CAP_L_HSP)) {
			free(hsp_relation);
			return (ERR_OP_ILLEGAL);
		}

		if (raid_obj_get_type(raid_tab, array_obj_id) !=
		    OBJ_TYPE_ARRAY) {
			free(hsp_relation);
			return (ERR_DEVICE_TYPE);
		}

		/* Get array attributes */
		ret = obj_get_attr(raid_tab, array_obj_id,
		    (void **)(&array_attr));
		/* RAID 0 array can not use hsp */
		if (array_attr->raid_level == RAID_LEVEL_0) {
			free(hsp_relation);
			return (ERR_ARRAY_LEVEL);
		}

		/* If It's belong to another controller */
		if (controller_obj_id != obj_get_controller(raid_tab,
		    array_obj_id)) {
			free(hsp_relation);
			return (ERR_DRIVER_ACROSS);
		}

		/* Get an array part attributes */
		if ((array_attr->raid_level == RAID_LEVEL_10) ||
		    (array_attr->raid_level == RAID_LEVEL_50))
			obj_id = obj_get_comp(raid_tab, array_obj_id,
			    OBJ_TYPE_ARRAY);
		else
			obj_id = array_obj_id;
		obj_id = obj_get_comp(raid_tab, obj_id,
		    OBJ_TYPE_ARRAY_PART);
		ret = obj_get_attr(raid_tab, obj_id,
		    (void **)(&arraypart_attr));

		/* Check if disk space is enough for array */
		if (arraypart_attr->size > disk_attr->capacity) {
			free(hsp_relation);
			return (ERR_DISK_SPACE);
		}
		if (controller_attr->capability & RAID_CAP_ARRAY_ALIGN)
			if ((arraypart_attr->size +
			    arraypart_attr->offset) >
			    disk_attr->capacity) {
			free(hsp_relation);
			return (ERR_DISK_SPACE);
			}
	} else if (!(controller_attr->capability & RAID_CAP_G_HSP)) {
		/* if global hsp is supported */
		free(hsp_relation);
		return (ERR_OP_ILLEGAL);
	}

	/*
	 * If the array is already associated with the
	 * local hsp, or it's a global hsp, ignore it
	 */
	obj_id = obj_get_comp(raid_tab, disk_obj_id, OBJ_TYPE_HSP);
	if (obj_id > OBJ_NONE) {
		if (obj_get_attr(raid_tab, obj_id,
		    (void **)&hsp_attr) >= SUCCESS) {
			if (((hsp_attr->type == HSP_TYPE_GLOBAL) &&
			    (array_obj_id != OBJ_ATTR_NONE)) ||
			    ((hsp_attr->type == HSP_TYPE_LOCAL) &&
			    (array_obj_id == OBJ_ATTR_NONE))) {
				free(hsp_relation);
				return (ERR_OP_ILLEGAL);
			}
		}
	}

	if (array_obj_id != OBJ_ATTR_NONE)
		hsp_relation->array_id = array_attr->array_id;
	else
		hsp_relation->array_id = (uint32_t)OBJ_ATTR_NONE;
	hsp_relation->disk_id = disk_attr->disk_id;

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	if (raid_lib->hsp_bind == NULL) {
		free(hsp_relation);
		return (ERR_OP_NO_IMPL);
	}

	ret = raid_lib->hsp_bind(controller_attr->controller_id,
	    hsp_relation, plugin_err_str);

	free(hsp_relation);
	return (ret);
}

static int
obj_hsp_unbind(raid_obj_tab_t *raid_tab, raid_obj_id_t *obj_ids,
    char **plugin_err_str)
{
	raid_obj_id_t obj_id, controller_obj_id = OBJ_NONE;
	raid_obj_id_t array_obj_id, disk_obj_id;
	hsp_relation_t *hsp_relation;
	controller_attr_t *controller_attr;
	array_attr_t *array_attr;
	disk_attr_t *disk_attr;
	hsp_attr_t *hsp_attr;
	raid_lib_t *raid_lib;
	int ret, fd;

	hsp_relation = malloc(sizeof (hsp_relation_t));
	if (hsp_relation == NULL)
		return (ERR_NOMEM);

	array_obj_id = *(obj_ids);
	disk_obj_id = *(obj_ids + 1);

	if (raid_obj_get_type(raid_tab, disk_obj_id) != OBJ_TYPE_DISK) {
		free(hsp_relation);
		return (ERR_DEVICE_TYPE);
	}

	/* Get controller attributes */
	if (controller_obj_id == OBJ_NONE)
		controller_obj_id = obj_get_controller(raid_tab,
		    disk_obj_id);
	else if (controller_obj_id != obj_get_controller(raid_tab,
	    disk_obj_id)) {
		free(hsp_relation);
		return (ERR_DRIVER_ACROSS);
	}

	ret = obj_get_attr(raid_tab, controller_obj_id,
	    (void **)(&controller_attr));

	/* Get disk attributes */
	ret = obj_get_attr(raid_tab,  disk_obj_id,
	    (void **)(&disk_attr));
	if (disk_attr->state == DISK_STATE_FAILED) {
		free(hsp_relation);
		return (ERR_DISK_STATE);
	}

	/* If it's not a hsp disk */
	obj_id = obj_get_comp(raid_tab, disk_obj_id, OBJ_TYPE_HSP);
	if (obj_id == OBJ_NONE) {
		free(hsp_relation);
		return (ERR_DISK_STATE);
	}
	ret = obj_get_attr(raid_tab, obj_id, (void **)(&hsp_attr));

	if (array_obj_id != OBJ_ATTR_NONE) {
		if (raid_obj_get_type(raid_tab, array_obj_id) !=
		    OBJ_TYPE_ARRAY) {
			free(hsp_relation);
			return (ERR_DEVICE_TYPE);
		}

		/* Get array attributes */
		ret = obj_get_attr(raid_tab, array_obj_id,
		    (void **)(&array_attr));

		/* If It's belong to another controller */
		if (controller_obj_id != obj_get_controller(raid_tab,
		    array_obj_id)) {
			free(hsp_relation);
			return (ERR_DRIVER_ACROSS);
		}

		/* If want to remove an array from a global hsp */
		if (hsp_attr->type == HSP_TYPE_GLOBAL) {
			free(hsp_relation);
			return (ERR_OP_ILLEGAL);
		}

		do {
			(void) obj_get_attr(raid_tab, obj_id,
			    (void **)(&hsp_attr));

			if (hsp_attr->associated_id ==
			    array_attr->array_id ||
			    hsp_attr->type == HSP_TYPE_GLOBAL)
				break;

			obj_id = obj_get_sibling(raid_tab, obj_id);
		} while (obj_id > OBJ_NONE);
	} else if (hsp_attr->type != HSP_TYPE_GLOBAL) {
		/* if global hsp is supported */
		free(hsp_relation);
		return (ERR_OP_ILLEGAL);
	}

	/*
	 * If array is associated with a local hsp, or remove a
	 * global hsp disk
	 */
	if ((obj_id && (array_obj_id != OBJ_ATTR_NONE)) ||
	    (array_obj_id == OBJ_ATTR_NONE)) {
		if (array_obj_id != OBJ_ATTR_NONE)
			hsp_relation->array_id = array_attr->array_id;
		else
			hsp_relation->array_id =
			    (uint32_t)OBJ_ATTR_NONE;
		hsp_relation->disk_id = disk_attr->disk_id;
	} else {
		free(hsp_relation);
		return (ERR_OP_ILLEGAL);
	}

	raid_lib = raid_obj_get_lib(raid_tab, controller_obj_id);
	fd = raid_obj_get_fd(raid_tab, controller_obj_id);
	if ((raid_lib == NULL) || (fd == 0))
		return (ERR_DRIVER_CLOSED);

	if (raid_lib->hsp_unbind == NULL) {
		free(hsp_relation);
		return (ERR_OP_NO_IMPL);
	}

	ret = raid_lib->hsp_unbind(controller_attr->controller_id,
	    hsp_relation, plugin_err_str);

	free(hsp_relation);
	return (ret);
}

/*
 * Object maintennance routines
 */
static int
raid_obj_create_system_obj(raid_obj_tab_t *raid_tab)
{
	raid_obj_t *raid_obj;
	int ret;

	raid_obj = calloc(1, sizeof (raid_obj_t));
	if (raid_obj == NULL)
		return (ERR_NOMEM);

	raid_obj->obj_id = OBJ_SYSTEM;
	raid_obj->obj_type_id = OBJ_TYPE_SYSTEM;
	raid_obj->data = NULL;

	ret = raid_obj_tab_insert(raid_tab, raid_obj->obj_id, raid_obj);
	if (ret == ERR_DEVICE_DUP) {
		free(raid_obj);
		return (ERR_DEVICE_UNCLEAN);
	}

	return (SUCCESS);
}

static raid_obj_id_t
raid_obj_id_new(raid_obj_tab_t *raid_tab)
{
	++ raid_tab->obj_id_cnt;
	if (raid_tab->obj_id_cnt <= 0)
		return (ERR_DEVICE_OVERFLOW);

	return (raid_tab->obj_id_cnt);
}

static void *
raid_obj_attr_new(raid_obj_type_id_t obj_type)
{
	void *obj_attr = NULL;

	switch (obj_type) {
	case	OBJ_TYPE_CONTROLLER:
		obj_attr = calloc(1, sizeof (controller_attr_t));
		break;
	case	OBJ_TYPE_ARRAY:
		obj_attr = calloc(1, sizeof (array_attr_t));
		break;
	case	OBJ_TYPE_DISK:
		obj_attr = calloc(1, sizeof (disk_attr_t));
		break;
	case	OBJ_TYPE_HSP:
		obj_attr = calloc(1, sizeof (hsp_attr_t));
		break;
	case	OBJ_TYPE_ARRAY_PART:
		obj_attr = calloc(1, sizeof (arraypart_attr_t));
		break;
	case	OBJ_TYPE_DISK_SEG:
		obj_attr = calloc(1, sizeof (diskseg_attr_t));
		break;
	case	OBJ_TYPE_TASK:
		obj_attr = calloc(1, sizeof (task_attr_t));
		break;
	case	OBJ_TYPE_PROP:
		obj_attr = calloc(1, sizeof (property_attr_t));
		break;
	default:
		break;
	}

	return (obj_attr);
}

static raid_obj_id_t
raid_obj_create(raid_obj_tab_t *raid_tab, raid_obj_type_id_t obj_type)
{
	raid_obj_t *raid_obj;
	int ret;
	void *data_ptr;

	raid_obj = calloc(1, sizeof (raid_obj_t));
	if (raid_obj == NULL)
		return (ERR_NOMEM);

	raid_obj->obj_id = raid_obj_id_new(raid_tab);
	if (raid_obj->obj_id < OBJ_NONE)
		return (ERR_DEVICE_OVERFLOW);

	ret = raid_obj_tab_insert(raid_tab, raid_obj->obj_id, raid_obj);
	if (ret == ERR_DEVICE_DUP) {
		free(raid_obj);
		return (ERR_DEVICE_DUP);
	}

	data_ptr = raid_obj_attr_new(obj_type);
	if (data_ptr == NULL) {
		(void) raid_obj_delete(raid_tab, raid_obj->obj_id);
		return (ERR_NOMEM);
	}

	(void) raid_obj_set_data_ptr(raid_tab, raid_obj->obj_id, data_ptr);

	(void) raid_obj_set_type(raid_tab, raid_obj->obj_id, obj_type);
	return (raid_obj->obj_id);
}

static int
raid_obj_delete(raid_obj_tab_t *raid_tab, raid_obj_id_t raid_obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_remove(raid_tab, raid_obj_id);
	if (obj != NULL) {
		free(obj->data);
		free(obj);
		return (SUCCESS);
	}

	return (ERR_DEVICE_NOENT);
}

static int
raid_obj_add_org(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_id_t container_id)
{
	raid_obj_id_t tmp, tmp1;

	tmp = raid_obj_get_comp(raid_tab, container_id);
	if (tmp < OBJ_NONE)
		return (ERR_DEVICE_NOENT);

	if (tmp == OBJ_NONE) {
		(void) raid_obj_set_container(raid_tab, obj_id, container_id);
		(void) raid_obj_set_comp(raid_tab, container_id, obj_id);
		return (SUCCESS);
	}

	while ((tmp1 = raid_obj_get_sibling(raid_tab, tmp)) != OBJ_NONE)
		tmp = tmp1;

	if (raid_obj_set_sibling(raid_tab, tmp, obj_id) < SUCCESS)
		return (ERR_DEVICE_NOENT);
	(void) raid_obj_set_container(raid_tab, obj_id, container_id);

	return (SUCCESS);
}

static raid_obj_type_id_t
raid_obj_get_type(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	if ((obj->obj_type_id < OBJ_TYPE_SYSTEM) ||
	    (obj->obj_type_id >= OBJ_TYPE_ALL))
		return (ERR_DEVICE_INVALID);

	return (obj->obj_type_id);
}

static int
raid_obj_set_type(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_type_id_t type)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	if ((type < OBJ_TYPE_SYSTEM) || (type >= OBJ_TYPE_ALL))
		return (ERR_DEVICE_TYPE);

	obj->obj_type_id = type;
	return (SUCCESS);
}

static raid_obj_status_t
raid_obj_get_status(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	return (obj->status);
}

static int
raid_obj_set_status(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_status_t status)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	obj->status = obj->status | status;

	return (SUCCESS);
}

static int
raid_obj_clear_status(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_status_t status)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	obj->status = obj->status & ~status;

	return (SUCCESS);
}

static raid_obj_id_t
raid_obj_get_container(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	return (obj->container);
}

static int
raid_obj_set_container(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_id_t container_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	obj->container = container_id;
	return (SUCCESS);
}

static raid_obj_id_t
raid_obj_get_comp(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	return (obj->component);
}

static int
raid_obj_set_comp(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_id_t comp)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	obj->component = comp;
	return (SUCCESS);
}

static raid_obj_id_t
raid_obj_get_sibling(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	return (obj->sibling);
}

static int
raid_obj_set_sibling(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_id_t sibling)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	obj->sibling = sibling;

	return (SUCCESS);
}

static void *
raid_obj_get_data_ptr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (NULL);

	return (obj->data);
}

static int
raid_obj_set_data_ptr(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    void *data)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	obj->data = data;

	return (SUCCESS);
}

static raid_obj_handle_t
raid_obj_get_handle(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	return (obj->handle);
}

static int
raid_obj_set_handle(raid_obj_tab_t *raid_tab, raid_obj_id_t obj_id,
    raid_obj_handle_t handle)
{
	raid_obj_t *obj;

	obj = raid_obj_tab_find(raid_tab, obj_id);
	if (obj == NULL)
		return (ERR_DEVICE_NOENT);

	obj->handle = handle;
	return (SUCCESS);
}
/*
 * Object list maintennance routines
 */
static void
raid_list_create(raid_list_t *list, size_t offset)
{
	list->head = NULL;
	list->tail = NULL;
	list->offset = offset;
}

static void *
raid_list_head(raid_list_t *list)
{
	return (list->head);
}

static void *
raid_list_next(raid_list_t *list, void *obj)
{
	raid_list_el_t *el = LIST_OBJ_TO_EL(list, obj);

	return (el->next);
}

static void
raid_list_insert_tail(raid_list_t *list, void *obj)
{
	raid_list_el_t *el = LIST_OBJ_TO_EL(list, obj), *el1;

	el->prev = list->tail;
	list->tail = obj;

	el->next = NULL;

	if (list->head == NULL)
		list->head = obj;

	if (el->prev != NULL) {
		el1 = LIST_OBJ_TO_EL(list, el->prev);
		el1->next = obj;
	}
}

static void
raid_list_remove(raid_list_t *list, void *obj)
{
	raid_list_el_t *el = LIST_OBJ_TO_EL(list, obj), *el1;

	if (list->head == obj)
		list->head = el->next;

	if (list->tail == obj)
		list->tail = el->prev;

	if (el->next != NULL) {
		el1 = LIST_OBJ_TO_EL(list, el->next);
		el1->prev = el->prev;
	}

	if (el->prev != NULL) {
		el1 = LIST_OBJ_TO_EL(list, el->prev);
		el1->next = el->next;
	}

	el->prev = el->next = NULL;
}

static void *
raid_list_remove_head(raid_list_t *list)
{
	void *obj = list->head;

	if (obj != NULL)
		raid_list_remove(list, obj);

	return (obj);
}

static void *
raid_list_find(raid_list_t *list, raid_obj_id_t obj_id)
{
	raid_obj_t *obj;

	for (obj = raid_list_head(list); obj != NULL;
	    obj = raid_list_next(list, obj))
			if (obj->obj_id == obj_id)
				break;

	return (obj);
}

static int
raid_obj_tab_create(raid_obj_tab_t *tab, size_t hash_slots)
{
	unsigned i;

	if (hash_slots == 0)
		return (ERR_OP_ILLEGAL);

	tab->slots = hash_slots;

	if ((tab->table = calloc(hash_slots, sizeof (raid_list_t))) == NULL)
		return (ERR_NOMEM);

	for (i = 0; i < hash_slots; i++)
		raid_list_create(&tab->table[i], offsetof(raid_obj_t, el));

	return (SUCCESS);
}

static void
raid_obj_tab_destroy(raid_obj_tab_t *tab)
{
	unsigned i;

	for (i = 0; i < tab->slots; i++) {
		struct raid_obj_t *obj;

		while ((obj = raid_list_remove_head(&tab->table[i])) != NULL)
			free(obj);

		raid_list_destroy(&tab->table[i]);
	}

	if (tab->table)
		free(tab->table);

	tab->table = NULL;
	tab->slots = 0;
	tab->obj_id_cnt = 0;
}

static int
raid_obj_tab_insert(raid_obj_tab_t *tab, raid_obj_id_t id, void *obj)
{
	raid_list_t *list;

	list = OBJ_TAB_SLOT(tab, id);

	if (raid_list_find(list, id) != NULL)
		return (ERR_DEVICE_DUP);

	raid_list_insert_tail(list, obj);

	return (SUCCESS);
}

static void *
raid_obj_tab_remove(raid_obj_tab_t *tab, raid_obj_id_t id)
{
	raid_list_t *list;
	raid_obj_t *obj;

	list = OBJ_TAB_SLOT(tab, id);

	if ((obj = raid_list_find(list, id)) != NULL)
		raid_list_remove(list, obj);

	return (obj);
}

static void *
raid_obj_tab_find(raid_obj_tab_t *tab, raid_obj_id_t id)
{
	raid_list_t *list;
	raid_obj_t *obj;

	list = OBJ_TAB_SLOT(tab, id);
	obj = raid_list_find(list, id);

	return (obj);
}

static void
raid_list_destroy(raid_list_t *list)
{
	list->head = NULL;
	list->tail = NULL;
	list->offset = 0;
}

/*
 * Plug-in maintennance routines
 */
static int
controller_id_to_path(uint32_t controller_id, char *path)
{
	int fd;
	char buf[MAX_PATH_LEN] = {0}, buf1[MAX_PATH_LEN] = {0}, *colon;

	(void) snprintf(buf, MAX_PATH_LEN, "%s/c%d", CFGDIR, controller_id);
	if (readlink(buf, buf1, sizeof (buf1)) < 0)
		return (ERR_DRIVER_NOT_FOUND);

	if (buf1[0] != '/')
		(void) snprintf(buf, sizeof (buf), "%s/", CFGDIR);
	else
		buf[0] = 0;
	(void) strlcat(buf, buf1, MAX_PATH_LEN);

	colon = strrchr(buf, ':');
	if (colon == NULL)
		return (ERR_DRIVER_NOT_FOUND);
	else
		*colon = 0;

	(void) snprintf(path, MAX_PATH_LEN, "%s:devctl", buf);

	fd = open(path, O_RDONLY | O_NDELAY);

	if (fd < 0)
		return (ERR_DRIVER_NOT_FOUND);

	(void) close(fd);

	return (SUCCESS);
}

static char *
controller_id_to_driver_name(uint32_t controller_id)
{
	char buf[MAX_PATH_LEN];
	di_node_t di_node;
	char *name, *tmp;
	int ret;

	ret = controller_id_to_path(controller_id, buf);
	if (ret < SUCCESS)
		return (NULL);

	tmp = strrchr(buf, ':');
	if (tmp != NULL)
		*tmp = 0;

	tmp = strstr(buf, "pci");
	if (tmp == NULL)
		return (NULL);

	di_node = di_init(tmp, DINFOPROP);
	if (di_node == DI_NODE_NIL)
		return (NULL);

	name = di_driver_name(di_node);

	return (name);
}

static void
raid_plugin_init()
{
	raid_lib_t *raid_lib = raid_lib_sys;

	while (raid_lib) {
		raid_lib_sys = raid_lib->next;
		(void) dlclose(raid_lib->lib_handle);
		free(raid_lib);
		raid_lib = raid_lib_sys;
	}
}

static raid_lib_t *
raid_plugin_load(char *driver_name)
{
	char buf[MAX_PATH_LEN] = {0};
	raid_lib_t *supplib;
	void *sym;

	supplib = calloc(1, sizeof (raid_lib_t));
	if (supplib == NULL)
		return (NULL);

	(void) snprintf(buf, MAX_PATH_LEN, "%s/%s.so.1",
	    SUPP_PLUGIN_DIR, driver_name);

	supplib->lib_handle = dlopen(buf, RTLD_LAZY);
	if (supplib->lib_handle == NULL) {
		free(supplib);
		return (NULL);
	}

	supplib->name = driver_name;

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_version")) == NULL)
		supplib->version = RDCFG_PLUGIN_V1;
	else {
		supplib->version = *((uint32_t *)sym);
		if (supplib->version != RDCFG_PLUGIN_V1) {
			(void) dlclose(supplib->lib_handle);
			free(supplib);
			return (NULL);
		}
	}

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_open_controller")) ==
	    NULL) {
		(void) dlclose(supplib->lib_handle);
		free(supplib);
		return (NULL);
	} else
		supplib->open_controller = (int(*)(uint32_t, char **))sym;

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_close_controller")) ==
	    NULL) {
		(void) dlclose(supplib->lib_handle);
		free(supplib);
		return (NULL);
	} else
		supplib->close_controller = (int (*)(uint32_t, char **))sym;

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_compnum")) == NULL) {
		(void) dlclose(supplib->lib_handle);
		free(supplib);
		return (NULL);
	} else
		supplib->compnum = (int (*)(uint32_t, uint32_t,
		    raid_obj_type_id_t, raid_obj_type_id_t))sym;

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_complist")) == NULL) {
		(void) dlclose(supplib->lib_handle);
		free(supplib);
		return (NULL);
	} else
		supplib->complist = (int (*)(uint32_t, uint32_t,
		    raid_obj_type_id_t, raid_obj_type_id_t, int, void *))sym;

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_get_attr")) == NULL) {
		(void) dlclose(supplib->lib_handle);
		free(supplib);
		return (NULL);
	} else
		supplib->get_attr = (int (*)(uint32_t, uint32_t, uint32_t,
		    raid_obj_type_id_t, void*))sym;

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_array_create")) == NULL) {
		(void) dlclose(supplib->lib_handle);
		free(supplib);
		return (NULL);
	} else
		supplib->array_create = (int (*)(uint32_t, array_attr_t *, int,
		    arraypart_attr_t *, char **))sym;

	if ((sym = dlsym(supplib->lib_handle, "rdcfg_array_delete")) == NULL) {
		(void) dlclose(supplib->lib_handle);
		free(supplib);
		return (NULL);
	} else
		supplib->array_delete =
		    (int (*)(uint32_t, uint32_t, char **))sym;

	supplib->hsp_bind = (int (*)(uint32_t, hsp_relation_t *,
	    char **))dlsym(supplib->lib_handle, "rdcfg_hsp_bind");
	supplib->hsp_unbind = (int (*)(uint32_t, hsp_relation_t *,
	    char **))dlsym(supplib->lib_handle, "rdcfg_hsp_unbind");
	supplib->set_attr = (int (*)(uint32_t, uint32_t, uint32_t, uint32_t *,
	    char **))dlsym(supplib->lib_handle, "rdcfg_set_attr");
	supplib->flash_fw = (int (*)(uint32_t, char *, uint32_t, char **))
	    dlsym(supplib->lib_handle, "rdcfg_flash_fw");

	supplib->next = raid_lib_sys;
	raid_lib_sys = supplib;
	return (supplib);
}

static raid_lib_t *
raid_find_lib(raid_obj_tab_t *raid_tab, raid_obj_id_t controller_obj_id)
{
	controller_attr_t *controller_attr;
	raid_lib_t *raid_lib;
	char *driver_name;
	raid_obj_handle_t handle;

	/* Check if it's mapped to handle structure */
	handle = raid_obj_to_handle(raid_tab, controller_obj_id);
	if (raid_handle_sys.handles[handle].raid_lib != NULL)
		return (raid_handle_sys.handles[handle].raid_lib);

	(void) obj_get_attr(raid_tab, controller_obj_id,
	    (void **)(&controller_attr));

	/* Check if the plugin module is already loaded */
	driver_name = controller_id_to_driver_name(
	    controller_attr->controller_id);
	if (driver_name == NULL)
		return (NULL);

	raid_lib = raid_lib_sys;
	while (raid_lib != NULL) {
		if (raid_lib->name != NULL &&
		    strcmp(driver_name, raid_lib->name) == 0)
			return (raid_lib);

		raid_lib = raid_lib->next;
	}

	/* Loading the plugin module */
	raid_lib = raid_plugin_load(driver_name);

	return (raid_lib);
}
