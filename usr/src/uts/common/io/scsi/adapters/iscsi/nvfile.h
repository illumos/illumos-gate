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

#ifndef _NVFILE_H
#define	_NVFILE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

typedef enum iscsi_nvfile_status {
	/* Success */
	ISCSI_NVFILE_SUCCESS = 0,
	/* nvf_list not found */
	ISCSI_NVFILE_NVF_LIST_NOT_FOUND,
	/* name/value pair not found */
	ISCSI_NVFILE_NAMEVAL_NOT_FOUND,
	/* other failure */
	ISCSI_NVFILE_FAILURE
} iscsi_nvfile_status_t;

/*
 * Function Prototypes
 */
void		nvf_init(void);
void		nvf_fini(void);
boolean_t	nvf_load(void);
void		nvf_update(void);
boolean_t	nvf_list_check(char *id);
boolean_t	nvf_node_value_set(char *id, uint32_t value);
boolean_t	nvf_node_value_get(char *id, uint32_t *value);
boolean_t	nvf_node_name_set(char *id, char *name);
boolean_t	nvf_node_name_get(char *id, char *name, uint_t nsize);
boolean_t	nvf_node_data_set(char *name, void *data, uint_t dsize);
iscsi_nvfile_status_t	nvf_node_data_get(char *name, void *data, uint_t dsize);
boolean_t	nvf_node_data_clear(char *name);
boolean_t	nvf_data_set(char *id, char *name, void *data, uint_t dsize);
boolean_t	nvf_data_get(char *id, char *name, void *data, uint_t dsize);
boolean_t	nvf_data_next(char *id, void **v, char *name,
		    void *data, uint_t dsize);
boolean_t	nvf_data_clear(char *id, char *name);


#ifdef __cplusplus
}
#endif

#endif /* _NVFILE_H */
