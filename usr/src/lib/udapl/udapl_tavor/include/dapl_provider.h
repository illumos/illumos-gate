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
 * Copyright (c) 2002-2003, Network Appliance, Inc. All rights reserved.
 */

/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *
 * HEADER: dapl_provider.h
 *
 * PURPOSE: Provider function table
 * Description: DAT Interfaces to this provider
 *
 * $Id: dapl_provider.h,v 1.4 2003/07/31 14:04:17 jlentini Exp $
 */

#ifndef _DAPL_PROVIDER_H_
#define	_DAPL_PROVIDER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "dapl.h"


/*
 *
 * Structures
 *
 */

typedef struct DAPL_PROVIDER_LIST_NODE
{
	char				name[DAT_NAME_MAX_LENGTH];
	DAT_PROVIDER 			data;
	struct DAPL_PROVIDER_LIST_NODE	*next;
	struct DAPL_PROVIDER_LIST_NODE	*prev;
} DAPL_PROVIDER_LIST_NODE;


typedef struct DAPL_PROVIDER_LIST
{
    DAPL_PROVIDER_LIST_NODE 		*head;
    DAPL_PROVIDER_LIST_NODE 		*tail;
    DAT_COUNT				size;
} DAPL_PROVIDER_LIST;


/*
 *
 * Global Data
 *
 */

extern DAPL_PROVIDER_LIST 	g_dapl_provider_list;
extern DAT_PROVIDER 		g_dapl_provider_template;
extern int 			g_dapl_loopback_connection;


/*
 *
 * Function Prototypes
 *
 */

extern DAT_RETURN
dapl_provider_list_create(void);

extern DAT_RETURN
dapl_provider_list_destroy(void);

extern DAT_COUNT
dapl_provider_list_size(void);

extern DAT_RETURN
dapl_provider_list_insert(
    IN  const char *name,
    OUT DAT_PROVIDER **p_data);

extern DAT_RETURN
dapl_provider_list_search(
    IN  const char *name,
    OUT DAT_PROVIDER **p_data);

extern DAT_RETURN
dapl_provider_list_remove(
    IN  const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_PROVIDER_H_ */
