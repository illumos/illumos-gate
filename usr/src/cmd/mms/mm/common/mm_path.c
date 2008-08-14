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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libxml/parser.h>
#include "mms_strapp.h"
#include "mms_trace.h"
#include "mm_path.h"

static char *_SrcFile = __FILE__;

typedef struct mm_name mm_name_t;
struct mm_name {
	char		**mm_name;
	int		mm_name_num;
};

typedef struct mm_pkey_list mm_pkey_list_t;
struct mm_pkey_list {
	mm_pkey_t	**mm_pkey;
	int		mm_pkey_num;
};

typedef struct mm_path_list mm_path_list_t;
struct mm_path_list {
	mm_path_t	**mm_path;
	int		mm_path_num;
};

typedef struct mm_user_data mm_user_data_t;
struct mm_user_data {
	int		mm_once;
	int		mm_error;
	int		mm_level;
	int		mm_scan;
	mm_pkey_t	*mm_pkey;
	int		mm_path_num;
	int		mm_path_index;
	int		mm_node_index;
	int		mm_att_index;
};

static mm_name_t		mm_obj;		/* object name list */
static mm_name_t		mm_att;		/* attribute name list */
static mm_pkey_list_t		mm_pkey_list;	/* object primary key list */
static mm_path_list_t		mm_path_list;	/* object path list */



static int mm_parse_paths(mm_user_data_t *user_data, char *fn);
static void mm_parse_start_elements(void *xml_user_data,
    const xmlChar *xml_name, const xmlChar **xml_atts);
static void mm_parse_end_elements(void *xml_user_data,
    const xmlChar *xml_name);

static void mm_name_add(mm_name_t *name, char *token);
static char *mm_get_obj_ptr(char **obj);
static char *mm_get_att_ptr(char **att);
static int mm_name_cmp(const void *p1, const void *p2);
static int mm_pkey_cmp(const void *p1, const void *p2);
static int mm_path_cmp(const void *p1, const void *p2);



int
mm_init_paths(char *fn)
{
	int		i;
	mm_user_data_t	user_data;


	mms_trace(MMS_DEVP, "path init %s", fn);

	/*
	 * Zero data
	 */
	memset(&mm_obj, 0, sizeof (mm_name_t));
	memset(&mm_att, 0, sizeof (mm_name_t));
	memset(&mm_pkey_list, 0, sizeof (mm_pkey_list_t));
	memset(&mm_path_list, 0, sizeof (mm_path_list_t));

	/*
	 * Allocate unique object and attribute strings
	 */
	memset(&user_data, 0, sizeof (mm_user_data_t));
	user_data.mm_scan = 1;
	if (mm_parse_paths(&user_data, fn)) {
		return (1);
	}

	/* Sort unique object and attribute names */
	qsort(mm_obj.mm_name, mm_obj.mm_name_num, sizeof (char *),
	    mm_name_cmp);
	qsort(mm_att.mm_name, mm_att.mm_name_num, sizeof (char *),
	    mm_name_cmp);

	/* Pre-allocate object pkey array */
	mm_pkey_list.mm_pkey_num = mm_obj.mm_name_num;
	if ((mm_pkey_list.mm_pkey = (mm_pkey_t **)malloc(sizeof (mm_pkey_t *) *
	    mm_pkey_list.mm_pkey_num)) == NULL) {
		return (1);
	}
	for (i = 0; i < mm_pkey_list.mm_pkey_num; i++) {
		mm_pkey_list.mm_pkey[i] =
		    (mm_pkey_t *)calloc(1, sizeof (mm_pkey_t));
		mm_pkey_list.mm_pkey[i]->mm_obj = mm_obj.mm_name[i];
	}

	/* Pre-allocate paths array */
	mms_trace(MMS_DEVP, "number of paths %d", user_data.mm_path_num);
	mm_path_list.mm_path_num = user_data.mm_path_num;
	if ((mm_path_list.mm_path = (mm_path_t **)malloc(sizeof (mm_path_t *) *
	    mm_path_list.mm_path_num)) == NULL) {
		return (1);
	}
	for (i = 0; i < mm_path_list.mm_path_num; i++) {
		mm_path_list.mm_path[i] = (mm_path_t *)calloc(1,
		    sizeof (mm_path_t));
	}

	/*
	 * Build primary keys and paths using pre-allocated strings and arrays
	 */
	memset(&user_data, 0, sizeof (mm_user_data_t));
	if (mm_parse_paths(&user_data, fn)) {
		return (1);
	}

	/* Sort paths */
	qsort(mm_path_list.mm_path, mm_path_list.mm_path_num,
	    sizeof (mm_path_t *), mm_path_cmp);

	mms_trace(MMS_DEVP, "paths done");
	return (user_data.mm_error);
}

mm_path_t *
mm_get_path(char *obj_1, char *obj_2)
{
	mm_path_t	**path;
	mm_path_t	key_data;
	mm_path_t	*key = &key_data;

	/*
	 * Get path between object 1 and object 2
	 */

	if (obj_1 == NULL) {
		mms_trace(MMS_DEVP, "obj_1 is null");
		return (NULL);
	}

	if (obj_2 == NULL) {
		mms_trace(MMS_DEVP, "obj_2 is null");
		return (NULL);
	}

	if ((key_data.mm_id = mms_strnew("%s%s", obj_1, obj_2)) == NULL) {
		mms_trace(MMS_DEVP, "no mem");
		return (NULL);
	}

	path = bsearch(&key,
	    mm_path_list.mm_path,
	    mm_path_list.mm_path_num,
	    sizeof (mm_path_t **),
	    mm_path_cmp);

	free(key_data.mm_id);

	if (path == NULL) {
		return (NULL);
	}
	return (*path);
}

void
mm_print_path(mm_path_t *path)
{
	int		i, j;
	char		*buf;

	if (path == NULL) {
		mms_trace(MMS_DEVP, "path is null");
		return;
	}

	mms_trace(MMS_DEVP, "path id %s", path->mm_id);
	for (i = 0; i < path->mm_node_num; i++) {
		mms_trace(MMS_DEVP,
		    "node from %s to %s", path->mm_node[i]->mm_obj,
		    path->mm_node[i]->mm_ref_obj);

		buf = mms_strnew("pkey %s (", path->mm_node[i]->mm_obj);
		for (j = 0; j < path->mm_node[i]->mm_pkey->mm_att_num; j++) {
			buf = mms_strapp(buf, "%s ",
			    path->mm_node[i]->mm_pkey->mm_att[j]);
		}
		if (path->mm_node[i]->mm_pkey->mm_att_num) {
			buf[strlen(buf)-1] = '\0';
		}
		mms_trace(MMS_DEVP, "%s)", buf);
		free(buf);

		buf = mms_strnew("edge (");
		for (j = 0; j < path->mm_node[i]->mm_edge_num; j++) {
			if (path->mm_node[i]->mm_edge[j]->mm_ref_att == NULL) {
				buf = mms_strapp(buf, "%s, ",
				    path->mm_node[i]->mm_edge[j]->mm_att);
			} else {
				buf = mms_strapp(buf, "%s %s, ",
				    path->mm_node[i]->mm_edge[j]->mm_att,
				    path->mm_node[i]->mm_edge[j]->mm_ref_att);
			}
		}
		if (path->mm_node[i]->mm_edge_num) {
			buf[strlen(buf)-2] = '\0';
		}
		mms_trace(MMS_DEVP, "%s)", buf);
		free(buf);
	}
}

static int
mm_parse_paths(mm_user_data_t *user_data, char *fn)
{
	xmlSAXHandler	handler;

	memset(&handler, 0, sizeof (xmlSAXHandler));
	handler.startElement = mm_parse_start_elements;
	handler.endElement = mm_parse_end_elements;
	xmlDefaultSAXHandlerInit();
	xmlSAXUserParseFile(&handler, user_data, fn);
	if (user_data->mm_once == 0) {
		user_data->mm_error = __LINE__;
	}
	if (user_data->mm_error) {
		mms_trace(MMS_ERR, "%s parse - scan %d error %d level %d",
		    fn,
		    user_data->mm_scan,
		    user_data->mm_error,
		    user_data->mm_level);
	}
	return (user_data->mm_error);
}

static void
mm_parse_start_elements(void *xml_user_data, const xmlChar *xml_name,
    const xmlChar **xml_atts)
{
	int		i;
	mm_user_data_t	*user_data = (mm_user_data_t *)xml_user_data;
	char		*name = (char *)xml_name;
	char		**atts = (char **)xml_atts;
	int		num;
	char		*str;
	char		*from;
	char		*to;
	int		index;
	int		nindex;
	char		*value;
	char		*to_value;

	if (user_data->mm_error) {
		return;
	}

	if (user_data->mm_once == 0) {
		user_data->mm_once = 1;
	}

	if (user_data->mm_level == 0 && strcmp(name, "mm_paths") == 0) {
		user_data->mm_level = 1;
		return;
	}

	if (user_data->mm_level == 1 && strcmp(name, "primary_keys") == 0) {
		user_data->mm_level = 2;
		return;
	}

	if (user_data->mm_level == 2 && strcmp(name, "paths") == 0) {
		user_data->mm_level = 3;
		return;
	}

	if (user_data->mm_level == 2 && strcmp(name, "object") == 0) {
		if (atts[0] == NULL || strcmp(atts[0], "name") != 0) {
			user_data->mm_error = __LINE__;
		} else if (user_data->mm_scan) {
			mm_name_add(&mm_obj, atts[1]);
		} else if ((user_data->mm_pkey =
		    mm_get_pkey(atts[1])) == NULL) {
			user_data->mm_error = __LINE__;
		}
		user_data->mm_level = 3;
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "pkey") == 0) {
		if (atts[0] == NULL || strcmp(atts[0], "value") != 0) {
			user_data->mm_error = __LINE__;
		} else if (user_data->mm_scan) {
			mm_name_add(&mm_att, atts[1]);
		} else {
			num = user_data->mm_pkey->mm_att_num;
			if ((str = mm_get_att_ptr(&atts[1])) == NULL) {
				user_data->mm_error = __LINE__;
			} else if ((user_data->mm_pkey->mm_att =
			    (char **)realloc(user_data->mm_pkey->mm_att,
			    sizeof (char *) * (num + 1))) == NULL) {
				user_data->mm_error = __LINE__;
			} else {
				user_data->mm_pkey->mm_att[num++] = str;
				user_data->mm_pkey->mm_att_num = num;
			}
		}
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "path") == 0) {
		for (i = 0; atts[i] != NULL; i += 2) {
			if (strcmp(atts[i], "from") == 0) {
				from = atts[i+1];
				if (user_data->mm_scan) {
					mm_name_add(&mm_obj, from);
				}
			} else if (strcmp(atts[i], "to") == 0) {
				to = atts[i+1];
				if (user_data->mm_scan) {
					mm_name_add(&mm_obj, to);
				}
			} else {
				user_data->mm_error = __LINE__;
				return;
			}
		}
		if (user_data->mm_scan) {
			user_data->mm_path_num++;
		} else {
			num = user_data->mm_path_index;
			if ((mm_path_list.mm_path[num]->mm_id =
			    mms_strnew("%s%s", from, to)) == NULL) {
				user_data->mm_error = __LINE__;
			}
			user_data->mm_node_index = 0;
		}
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "node") == 0) {
		for (i = 0; atts[i] != NULL; i += 2) {
			if (strcmp(atts[i], "from") == 0) {
				from = atts[i+1];
				if (user_data->mm_scan) {
					mm_name_add(&mm_obj, from);
				}
			} else if (strcmp(atts[i], "to") == 0) {
				to = atts[i+1];
				if (user_data->mm_scan) {
					mm_name_add(&mm_obj, to);
				}
			} else {
				user_data->mm_error = __LINE__;
				return;
			}
		}
		if (user_data->mm_scan == 0) {
			mm_node_t **p;
			mm_node_t **q;
			mm_pkey_t *pkey;

			index = user_data->mm_path_index;
			q = mm_path_list.mm_path[index]->mm_node;
			num = mm_path_list.mm_path[index]->mm_node_num;

			if ((p = (mm_node_t **)realloc(q,
			    sizeof (mm_node_t **)*(num + 1))) == NULL) {
				user_data->mm_error = __LINE__;
				return;
			}
			mm_path_list.mm_path[index]->mm_node = p;
			if ((mm_path_list.mm_path[index]->mm_node[num] =
			    (mm_node_t *)calloc(1,
			    sizeof (mm_node_t))) == NULL) {
				user_data->mm_error = __LINE__;
				return;
			}
			if ((pkey = mm_get_pkey(from)) == NULL) {
				user_data->mm_error = __LINE__;
				return;
			}
			if ((str = mm_get_obj_ptr(&to)) == NULL) {
				user_data->mm_error = __LINE__;
				return;
			}
			mm_path_list.mm_path[index]->
			    mm_node[num]->mm_obj = pkey->mm_obj;
			mm_path_list.mm_path[index]->
			    mm_node[num]->mm_pkey = pkey;
			mm_path_list.mm_path[index]->
			    mm_node[num]->mm_ref_obj = str;
			mm_path_list.mm_path[index]->mm_node_num++;

			user_data->mm_att_index = 0;
		}
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "att") == 0) {
		to_value = NULL;
		for (i = 0; atts[i] != NULL; i += 2) {
			if (strcmp(atts[i], "value") == 0) {
				value = atts[i+1];
				if (user_data->mm_scan) {
					mm_name_add(&mm_att, value);
				}
			} else if (strcmp(atts[i], "to_value") == 0) {
				to_value = atts[i+1];
				if (user_data->mm_scan) {
					mm_name_add(&mm_att, to_value);
				}
			} else {
				user_data->mm_error = __LINE__;
				return;
			}
		}
		if (user_data->mm_scan == 0) {
			mm_att_t **p;
			mm_att_t **q;

			index = user_data->mm_path_index;
			nindex = user_data->mm_node_index;
			q = mm_path_list.mm_path[index]->
			    mm_node[nindex]->mm_edge;
			num = mm_path_list.mm_path[index]->
			    mm_node[nindex]->mm_edge_num;

			if ((p = (mm_att_t **)realloc(q,
			    sizeof (mm_att_t **)*(num + 1))) == NULL) {
				user_data->mm_error = __LINE__;
				return;
			}
			mm_path_list.mm_path[index]->
			    mm_node[nindex]->mm_edge = p;
			if ((mm_path_list.mm_path[index]->mm_node[nindex]->
			    mm_edge[num] = (mm_att_t *)calloc(1,
			    sizeof (mm_att_t))) == NULL) {
				user_data->mm_error = __LINE__;
				return;
			}

			if ((str = mm_get_att_ptr(&value)) == NULL) {
				user_data->mm_error = __LINE__;
				return;
			}
			mm_path_list.mm_path[index]->
			    mm_node[nindex]->mm_edge[num]->mm_att = str;

			if (to_value) {
				if ((str = mm_get_att_ptr(&to_value)) == NULL) {
					user_data->mm_error = __LINE__;
					return;
				}
				mm_path_list.mm_path[index]->mm_node[nindex]->
				    mm_edge[num]->mm_ref_att = str;
			}
			mm_path_list.mm_path[index]->
			    mm_node[nindex]->mm_edge_num++;
		}
		return;
	}

	user_data->mm_error = __LINE__;
}

static void
mm_parse_end_elements(void *xml_user_data, const xmlChar *xml_name)
{
	mm_user_data_t	*user_data = (mm_user_data_t *)xml_user_data;
	char		*name = (char *)xml_name;

	if (user_data->mm_error) {
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "object") == 0) {
		user_data->mm_level = 2;
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "path") == 0) {
		user_data->mm_path_index++;
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "node") == 0) {
		user_data->mm_node_index++;
		return;
	}

	if (user_data->mm_level == 3 && strcmp(name, "att") == 0) {
		user_data->mm_att_index++;
		return;
	}
}

static void
mm_name_add(mm_name_t *name, char *token)
{
	int		i;
	int		found;
	char		**p;

	found = 0;
	for (i = 0; !found && i < name->mm_name_num; i++) {
		if (strcmp(token, name->mm_name[i]) == 0) {
			found = 1;
		}
	}
	if (!found) {
		if ((p = (char **)realloc(name->mm_name,
		    sizeof (char **)*(name->mm_name_num + 1))) == NULL) {
			return;
		}
		name->mm_name = p;
		name->mm_name[name->mm_name_num] = strdup(token);
		if (name->mm_name[name->mm_name_num] == NULL) {
			return;
		}
		name->mm_name_num++;
	}
}

static int
mm_name_cmp(const void *p1, const void *p2)
{
	char	*name_1 = *((char **)p1);
	char	*name_2 = *((char **)p2);

	return (strcmp(name_1, name_2));
}

static char *
mm_get_obj_ptr(char **obj)
{
	char	**objname;

	if ((objname = bsearch(obj, mm_obj.mm_name, mm_obj.mm_name_num,
	    sizeof (char **), mm_name_cmp)) == NULL) {
		return (NULL);
	}
	return (*objname);
}

static char *
mm_get_att_ptr(char **att)
{
	char	**attname;

	if ((attname = bsearch(att, mm_att.mm_name, mm_att.mm_name_num,
	    sizeof (char **), mm_name_cmp)) == NULL) {
		return (NULL);
	}
	return (*attname);
}

static int
mm_path_cmp(const void *p1, const void *p2)
{
	mm_path_t	*path_1 = *((mm_path_t **)p1);
	mm_path_t	*path_2 = *((mm_path_t **)p2);

	return (strcmp(path_1->mm_id, path_2->mm_id));
}

static int
mm_pkey_cmp(const void *p1, const void *p2)
{
	mm_pkey_t	*pkey_1 = *((mm_pkey_t **)p1);
	mm_pkey_t	*pkey_2 = *((mm_pkey_t **)p2);

	return (strcmp(pkey_1->mm_obj, pkey_2->mm_obj));
}

mm_pkey_t *
mm_get_pkey(char *obj)
{
	mm_pkey_t	data;
	mm_pkey_t	*key = &data;
	mm_pkey_t	**pkey;

	if (obj == NULL) {
		return (NULL);
	}

	data.mm_obj = obj;
	if ((pkey = (mm_pkey_t **)bsearch(&key, mm_pkey_list.mm_pkey,
	    mm_pkey_list.mm_pkey_num, sizeof (mm_pkey_t **),
	    mm_pkey_cmp)) == NULL) {
		return (NULL);
	}
	return (*pkey);
}
