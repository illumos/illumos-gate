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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <stdlib.h>
#include <strings.h>
#include <mms_trace.h>
#include <mms_list.h>


static	char *_SrcFile = __FILE__;



typedef	struct dm_mem_ele {
	mms_list_node_t	dm_link;
	char		*dm_mem;
	char		*dm_file;
	int		dm_line;
} dm_mem_ele_t;

static  MMS_LIST_CREATE(dm_mem_list, dm_mem_ele_t, dm_link);

char   *
dm_malloc(size_t size, char *filename, int line)
{
	dm_mem_ele_t	*ele;

	if ((ele = (dm_mem_ele_t *)malloc(sizeof (dm_mem_ele_t))) == NULL) {
		return (NULL);
	}

	if ((ele->dm_mem = malloc(size)) == NULL) {
		free(ele);
		return (NULL);
	}
	ele->dm_file = filename;
	ele->dm_line = line;
	mms_list_insert_tail(&dm_mem_list, ele);
	mms_trace(MMS_DEBUG, "Allocated memory %p, %s, %d",
	    ele->dm_mem, ele->dm_file, ele->dm_line);
	return (ele->dm_mem);
}

char   *
dm_strdup(char *str, char *filename, int line)
{
	dm_mem_ele_t	*ele;

	if ((ele = malloc(sizeof (dm_mem_ele_t))) == NULL) {
		return (NULL);
	}

	if ((ele->dm_mem = strdup(str)) == NULL) {
		free(ele);
		return (NULL);
	}
	ele->dm_file = filename;
	ele->dm_line = line;
	mms_list_insert_tail(&dm_mem_list, ele);
	mms_trace(MMS_DEBUG, "Allocated memory %p, %s, %d",
	    ele->dm_mem, ele->dm_file, ele->dm_line);
	return (ele->dm_mem);
}

void
dm_free(void *ptr, char *filename, int line)
{
	dm_mem_ele_t	*ele;
	dm_mem_ele_t	*tmp;

	mms_list_foreach_safe(&dm_mem_list, ele, tmp) {
		if (ele->dm_mem == ptr) {
			mms_list_remove(&dm_mem_list, ele);
			mms_trace(MMS_DEBUG, "Freed memory %p, %s, %d",
			    ele->dm_mem, ele->dm_file, ele->dm_line);
			free(ele->dm_mem);
			free(ele);
			return;
		}
	}
	mms_trace(MMS_DEBUG, "Can't free memory %p, %s, %d",
	    ptr, filename, line);

}
