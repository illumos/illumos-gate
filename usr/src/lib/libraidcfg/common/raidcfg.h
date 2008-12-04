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

#ifndef	_RAIDCFG_H
#define	_RAIDCFG_H

#include <sys/types.h>
#include <raidcfg_spi.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Reserved Raid object IDs;
 * ID 0 is reserved for root object;
 * ID 0 also stands for NONE OBJECT.
 */
#define	OBJ_SYSTEM		0
#define	OBJ_NONE		0

typedef	int raid_obj_handle_t;

/*
 * API data structure definition
 */
typedef	struct {
	int	array_handle;
	int	disk_handle;
} raidcfg_hsp_relation_t;

typedef	controller_attr_t	raidcfg_controller_t;
typedef	array_attr_t		raidcfg_array_t;
typedef	disk_attr_t		raidcfg_disk_t;

typedef struct {
	uint32_t	associated_id;
	uint32_t	type;
	array_tag_t	tag;
} raidcfg_hsp_t;

typedef	struct {
	uint32_t	disk_id;
	uint32_t	state;
	uint64_t	offset;
	uint64_t	size;
	disk_tag_t	tag;
} raidcfg_arraypart_t;

typedef	diskseg_attr_t		raidcfg_diskseg_t;
typedef	task_attr_t		raidcfg_task_t;
typedef	property_attr_t		raidcfg_prop_t;

/*
 * raidcfg common library APIs
 */
const char *raidcfg_errstr(int);
int raidcfg_get_controller(uint32_t);
int raidcfg_get_array(int, uint64_t, uint64_t);
int raidcfg_get_disk(int, disk_tag_t);
int raidcfg_open_controller(int, char **);
int raidcfg_close_controller(int, char **);
int raidcfg_get_type(int);
int raidcfg_get_attr(int, void *);
int raidcfg_get_container(int);
int raidcfg_list_head(int, raid_obj_type_id_t);
int raidcfg_list_next(int);
int raidcfg_set_attr(int, uint32_t, void *, char **);
int raidcfg_set_hsp(raidcfg_hsp_relation_t *, char **);
int raidcfg_unset_hsp(raidcfg_hsp_relation_t *, char **);
int raidcfg_create_array(int, int *, uint32_t, uint64_t, uint32_t, char **);
int raidcfg_delete_array(int, char **);
int raidcfg_update_fw(int, char *, char **);

#ifdef	__cplusplus
}
#endif

#endif /* _RAIDCFG_H */
