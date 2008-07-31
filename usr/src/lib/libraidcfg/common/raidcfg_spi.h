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

#ifndef	_SYS_RAIDCFG_SPI_H
#define	_SYS_RAIDCFG_SPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Controller capabilities
 */
#define	RAID_CAP_RAID0		1
#define	RAID_CAP_RAID1		1 << 1
#define	RAID_CAP_RAID1E		1 << 2
#define	RAID_CAP_RAID5		1 << 3
#define	RAID_CAP_RAID10		1 << 4
#define	RAID_CAP_RAID50		1 << 5
#define	RAID_CAP_G_HSP		1 << 6
#define	RAID_CAP_L_HSP		1 << 7
#define	RAID_CAP_DISK_TRANS	1 << 8
#define	RAID_CAP_FULL_DISK_ONLY	1 << 9
#define	RAID_CAP_SMART_ALLOC	1 << 10
#define	RAID_CAP_ARRAY_ALIGN	1 << 11

/*
 * General constants
 */
#define	OBJ_SEPARATOR_BEGIN	-1
#define	OBJ_SEPARATOR_END	-2

#define	OBJ_ATTR_NONE		-1

/*
 * Array RAID level definition
 */
#define	RAID_LEVEL_0		1
#define	RAID_LEVEL_1		2
#define	RAID_LEVEL_1E		3
#define	RAID_LEVEL_5		4
#define	RAID_LEVEL_10		5
#define	RAID_LEVEL_50		6

/*
 * Array cache write policy
 */
#define	CACHE_WR_OFF		0
#define	CACHE_WR_ON		1

/*
 * Array cache read policy
 */
#define	CACHE_RD_OFF		0
#define	CACHE_RD_ON		1

/*
 * Array activation action
 */
#define	ARRAY_ACT_ACTIVATE	0

/*
 * Array status
 */
#define	ARRAY_STATE_OPTIMAL	0
#define	ARRAY_STATE_DEGRADED	1
#define	ARRAY_STATE_FAILED	2
#define	ARRAY_STATE_MISSING	3

/*
 * Array activation state
 */
#define	ARRAY_STATE_INACTIVATE	0x8000

/*
 * Disk state
 */
#define	DISK_STATE_GOOD		0
#define	DISK_STATE_FAILED	1

/*
 * Array part state
 */
#define	ARRAYPART_STATE_GOOD	0
#define	ARRAYPART_STATE_MISSED	1

/*
 * Disk segment state
 */
#define	DISKSEG_STATE_GOOD	1
#define	DISKSEG_STATE_RESERVED	1 << 1
#define	DISKSEG_STATE_DEAD	1 << 2
#define	DISKSEG_STATE_NORMAL	1 << 3

/*
 * Controller connection type
 */
#define	TYPE_UNKNOWN		0
#define	TYPE_SCSI		1
#define	TYPE_SAS		2

#define	RAID_TASK_SUSPEND	0
#define	RAID_TASK_RESUME	1
#define	RAID_TASK_TERMINATE	2

#define	HSP_TYPE_GLOBAL		0
#define	HSP_TYPE_LOCAL		1

/*
 * Sub-command of set attribute
 */
#define	SET_CACHE_WR_PLY	0
#define	SET_CACHE_RD_PLY	1
#define	SET_ACTIVATION_PLY	2

/*
 * Sub-commands for act method of object
 */
#define	ACT_CONTROLLER_OPEN	0
#define	ACT_CONTROLLER_CLOSE	1
#define	ACT_CONTROLLER_FLASH_FW	2

/*
 * Some definitions
 */
#define	CONTROLLER_FW_LEN	32
#define	CONTROLLER_TYPE_LEN	32

#define	DISK_VENDER_LEN		8
#define	DISK_PRODUCT_LEN	16
#define	DISK_REV_LEN		4

#define	RDCFG_PLUGIN_V1		0x10000
#define	CFGDIR		"/dev/cfg"
#define	MAX_PATH_LEN		255

/*
 * Mininum array part size: 256M
 */
#define	ARRAYPART_MIN_SIZE	(uint64_t)(1 << 28)

/*
 * Return code
 */
#define	SUCCESS			0
#define	STD_IOCTL		-1
#define	ERR_DRIVER_NOT_FOUND	-2
#define	ERR_DRIVER_OPEN		-3
#define	ERR_DRIVER_LOCK		-4
#define	ERR_DRIVER_CLOSED	-5
#define	ERR_DRIVER_ACROSS	-6
#define	ERR_ARRAY_LEVEL		-7
#define	ERR_ARRAY_SIZE		-8
#define	ERR_ARRAY_STRIPE_SIZE	-9
#define	ERR_ARRAY_CACHE_POLICY	-10
#define	ERR_ARRAY_IN_USE	-11
#define	ERR_ARRAY_TASK		-12
#define	ERR_ARRAY_CONFIG	-13
#define	ERR_ARRAY_DISKNUM	-14
#define	ERR_ARRAY_LAYOUT	-15
#define	ERR_ARRAY_AMOUNT	-16
#define	ERR_DISK_STATE		-17
#define	ERR_DISK_SPACE		-18
#define	ERR_DISK_SEG_AMOUNT	-19
#define	ERR_DISK_NOT_EMPTY	-20
#define	ERR_DISK_TASK		-21
#define	ERR_TASK_STATE		-22
#define	ERR_OP_ILLEGAL		-23
#define	ERR_OP_NO_IMPL		-24
#define	ERR_OP_FAILED		-25
#define	ERR_DEVICE_NOENT	-26
#define	ERR_DEVICE_TYPE		-27
#define	ERR_DEVICE_DUP		-28
#define	ERR_DEVICE_OVERFLOW	-29
#define	ERR_DEVICE_UNCLEAN	-30
#define	ERR_DEVICE_INVALID	-31
#define	ERR_NOMEM		-32
#define	ERR_PRIV		-33
#define	ERR_PLUGIN		-34

/*
 * Raid object types
 */
typedef enum {
	OBJ_TYPE_SYSTEM,
	OBJ_TYPE_CONTROLLER,
	OBJ_TYPE_ARRAY,
	OBJ_TYPE_DISK,
	OBJ_TYPE_HSP,
	OBJ_TYPE_ARRAY_PART,
	OBJ_TYPE_DISK_SEG,
	OBJ_TYPE_TASK,
	OBJ_TYPE_PROP,
	OBJ_TYPE_ALL
} raid_obj_type_id_t;

/*
 * Task functions
 */
typedef enum {
	TASK_FUNC_UNKNOWN,
	TASK_FUNC_INIT,
	TASK_FUNC_BUILD,
	TASK_FUNC_VERIFY
} raidtask_func_t;

/*
 * Task state
 */
typedef enum {
	TASK_STATE_UNKNOWN,
	TASK_STATE_TERMINATED,
	TASK_STATE_FAILED,
	TASK_STATE_DONE,
	TASK_STATE_RUNNING,
	TASK_STATE_SUSPENDED
} raidtask_state_t;

/*
 * Properties
 */
typedef	enum {
	PROP_GUID
} property_type_t;

/*
 * Attributes of all RAID objects
 */
typedef union {
	uint64_t	reserved[3];
	struct {
		uint64_t	target_id;
		uint64_t	lun;
	} idl;
} array_tag_t;

typedef union {
	struct {
		uint64_t bus;
		uint64_t target_id;
		uint64_t lun;
	} cidl;
} disk_tag_t;

typedef struct {
	uint32_t	controller_id;
	uint32_t	max_array_num;
	uint32_t	max_seg_per_disk;
	uint32_t	connection_type;
	uint64_t	capability;
	char		fw_version[CONTROLLER_FW_LEN];
	char		controller_type[CONTROLLER_TYPE_LEN];
} controller_attr_t;

typedef struct {
	uint32_t	array_id;
	uint32_t	state;
	array_tag_t	tag;
	uint64_t	capacity;
	uint32_t	raid_level;
	uint32_t	stripe_size;
	uint32_t	write_policy;
	uint32_t	read_policy;
} array_attr_t;

typedef struct {
	uint32_t	disk_id;
	uint32_t	state;
	disk_tag_t	tag;
	uint64_t	capacity;
	char		vendorid[DISK_VENDER_LEN];
	char		productid[DISK_PRODUCT_LEN];
	char		revision[DISK_REV_LEN];
} disk_attr_t;

typedef struct {
	uint32_t	associated_id;
	uint32_t	type;
} hsp_attr_t;

typedef struct {
	uint32_t	disk_id;
	uint32_t	state;
	uint64_t	offset;
	uint64_t	size;
} arraypart_attr_t;

typedef struct {
	uint32_t	seq_no;
	uint32_t	state;
	uint64_t	offset;
	uint64_t	size;
} diskseg_attr_t;

typedef struct {
	uint32_t	task_id;
	uint32_t	task_func;
	uint32_t	task_state;
	uint32_t	progress;
} task_attr_t;

typedef struct {
	uint32_t	prop_id;
	uint32_t	prop_size;
	property_type_t	prop_type;
	char		prop[1];
} property_attr_t;

typedef struct {
	uint32_t	array_id;
	uint32_t	disk_id;
} hsp_relation_t;

/*
 * Structure used to register plug-in modules
 */
typedef	struct raid_lib_type {
	uint32_t version;
	struct raid_lib_type *next;
	void	*lib_handle;
	const char	*name;

	int (*open_controller)(uint32_t, char **);
	int (*close_controller)(uint32_t, char **);
	int (*compnum)(uint32_t, uint32_t, raid_obj_type_id_t,
		raid_obj_type_id_t);
	int (*complist)(uint32_t, uint32_t, raid_obj_type_id_t,
		raid_obj_type_id_t, int, void *);
	int (*get_attr)(uint32_t, uint32_t, uint32_t, raid_obj_type_id_t,
		void *);
	int (*set_attr)(uint32_t, uint32_t, uint32_t, uint32_t *, char **);
	int (*array_create)(uint32_t, array_attr_t *, int,
		arraypart_attr_t *, char **);
	int (*array_delete)(uint32_t, uint32_t, char **);
	int (*hsp_bind)(uint32_t, uint32_t, hsp_relation_t *, char **);
	int (*hsp_unbind)(uint32_t, uint32_t, hsp_relation_t *, char **);
	int (*flash_fw)(uint32_t, char *, uint32_t, char **);
} raid_lib_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RAIDCFG_SPI_H */
