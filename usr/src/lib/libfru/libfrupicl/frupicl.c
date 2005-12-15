/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <alloca.h>
#include <picl.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "picldefs.h"
#include "fru_data.h"

#include "libfruds.h"
#include "libfrup.h"

/* ========================================================================= */
#define	TREEHDL_TO_PICLHDL(treehdl) ((picl_nodehdl_t)treehdl)
#define	PICLHDL_TO_TREEHDL(piclhdl) ((fru_treehdl_t)piclhdl)

#define	TREESEGHDL_TO_PICLHDL(treeseghdl) ((picl_nodehdl_t)treeseghdl)
#define	PICLHDL_TO_TREESEGHDL(piclhdl) ((fru_treeseghdl_t)piclhdl)

/* Cache of the root node for quick checks */
static picl_nodehdl_t picl_root_node;


/* ========================================================================= */
/*
 * Map the PICL errors the plugin would give me to FRU errors
 */
static fru_errno_t
map_plugin_err(int picl_err)
{
	switch (picl_err) {
		case PICL_SUCCESS:
			return (FRU_SUCCESS);
		case PICL_PERMDENIED:
			return (FRU_INVALPERM);
		case PICL_PROPEXISTS:
			return (FRU_DUPSEG);
		case PICL_NOSPACE:
			return (FRU_NOSPACE);
		case PICL_NORESPONSE:
			return (FRU_NORESPONSE);
		case PICL_PROPNOTFOUND:
			return (FRU_NODENOTFOUND);
		case PICL_ENDOFLIST:
			return (FRU_DATANOTFOUND);
	}
	return (FRU_IOERROR);
}

/* ========================================================================= */
/*
 * cause a refresh of the sub-nodes by writing anything to the container
 * property of the node.
 */
static fru_errno_t
update_data_nodes(picl_nodehdl_t handle)
{
	uint32_t container = FRUDATA_DELETE_TAG_KEY;
	int picl_err = PICL_SUCCESS;

	if ((picl_err = picl_set_propval_by_name(handle,
		PICL_PROP_CONTAINER, (void *)&container,
		sizeof (container))) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	return (FRU_SUCCESS);
}

/* ========================================================================= */
/*
 * picl like function which gets a string property with the proper length
 * NOTE: returns picl errno values NOT fru_errno_t
 */
static int
get_strprop_by_name(picl_nodehdl_t handle, char *prop_name, char **string)
{
	int picl_err = PICL_SUCCESS;
	picl_prophdl_t proph;
	picl_propinfo_t prop_info;
	char *tmp_buf = NULL;

	if ((picl_err = picl_get_propinfo_by_name(handle, prop_name,
		&prop_info, &proph)) != PICL_SUCCESS) {
		return (picl_err);
	}

	tmp_buf = malloc((sizeof (*tmp_buf) * prop_info.size));
	if (tmp_buf == NULL) {
		return (PICL_FAILURE);
	}

	if ((picl_err = picl_get_propval(proph, tmp_buf, prop_info.size))
			!= PICL_SUCCESS) {
		free(tmp_buf);
		return (picl_err);
	}

	*string = tmp_buf;
	return (PICL_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_name_from_hdl(fru_treehdl_t node, char **name)
{
	int picl_err = PICL_SUCCESS;
	char *tmp_name = NULL;
	char *label = NULL;
	picl_nodehdl_t handle = TREEHDL_TO_PICLHDL(node);

	/* get the name */
	if ((picl_err = get_strprop_by_name(handle, PICL_PROP_NAME,
		&tmp_name)) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	/* get the label, if any */
	if ((picl_err = get_strprop_by_name(handle, PICL_PROP_LABEL,
		&label)) != PICL_SUCCESS) {
		if (picl_err != PICL_PROPNOTFOUND) {
			free(tmp_name);
			return (map_plugin_err(picl_err));
		}
		/* else PICL_PROPNOTFOUND is OK because not all nodes */
		/* will have a label. */
	}

	/* construct the name as nessecary */
	if (label == NULL) {
		*name = strdup(tmp_name);
	} else {
#define	FRU_LABEL_PADDING 10
		size_t buf_size = strlen(tmp_name) + strlen(label) +
			FRU_LABEL_PADDING;
		char *tmp = malloc(buf_size);
		if (tmp == NULL) {
			free(tmp_name);
			free(label);
			return (FRU_FAILURE);
		}
		snprintf(tmp, buf_size, "%s?%s=%s", tmp_name,
			PICL_PROP_LABEL, label);
		*name = tmp;
	}

	free(tmp_name);
	free(label);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
/* compare the node name to the name passed */
static fru_errno_t
cmp_node_name(picl_nodehdl_t node, const char *name)
{
	char *node_name = NULL;

	if (get_strprop_by_name(node, PICL_PROP_NAME, &node_name)
			!= PICL_SUCCESS) {
		return (FRU_FAILURE);
	}

	if (strcmp(node_name, name) == 0) {
		free(node_name);
		return (FRU_SUCCESS);
	}

	free(node_name);
	return (FRU_FAILURE);
}

/* ========================================================================= */
/* compare the node class name to the name passed */
static fru_errno_t
cmp_class_name(picl_nodehdl_t node, const char *name)
{
	char *class_name = NULL;

	if (get_strprop_by_name(node, PICL_PROP_CLASSNAME, &class_name)
			!= PICL_SUCCESS) {
		return (FRU_FAILURE);
	}

	if (strcmp(class_name, name) == 0) {
		free(class_name);
		return (FRU_SUCCESS);
	}

	free(class_name);
	return (FRU_FAILURE);
}


/* ========================================================================= */
/* get the "frutree" root node */
static fru_errno_t
fpt_get_root(fru_treehdl_t *node)
{
	picl_nodehdl_t picl_node;
	int picl_err = PICL_SUCCESS;

	picl_err = picl_get_root(&picl_node);
	if ((picl_err = picl_get_propval_by_name(picl_node, PICL_PROP_CHILD,
		(void *)&picl_node, sizeof (picl_node)))
		!= PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	while (cmp_node_name(picl_node, PICL_NODE_FRUTREE)
			!= FRU_SUCCESS) {

		if ((picl_err = picl_get_propval_by_name(picl_node,
			PICL_PROP_PEER, (void *)&picl_node,
			sizeof (picl_node))) == PICL_PROPNOTFOUND) {
			return (FRU_NODENOTFOUND);
		} else if (picl_err != PICL_SUCCESS) {
			return (map_plugin_err(picl_err));
		}
	}

	picl_root_node = picl_node;
	*node = PICLHDL_TO_TREEHDL(picl_node);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_peer(fru_treehdl_t sibling, fru_treehdl_t *peer)
{
	int rc = PICL_SUCCESS;
	picl_nodehdl_t handle = TREEHDL_TO_PICLHDL(sibling);
	picl_nodehdl_t picl_peer;

	rc = picl_get_propval_by_name(handle, PICL_PROP_PEER,
		(void *)&picl_peer, sizeof (picl_peer));
	if (rc != PICL_SUCCESS) {
		return (map_plugin_err(rc));
	}

	*peer = PICLHDL_TO_TREEHDL(picl_peer);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_child(fru_treehdl_t handle, fru_treehdl_t *child)
{
	picl_nodehdl_t p_child;
	int rc = picl_get_propval_by_name(TREEHDL_TO_PICLHDL(handle),
		PICL_PROP_CHILD, (void *)&p_child, sizeof (p_child));
	if (rc != PICL_SUCCESS) {
		return (map_plugin_err(rc));
	}

	*child = PICLHDL_TO_TREEHDL(p_child);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_parent(fru_treehdl_t handle, fru_treehdl_t *parent)
{
	int rc = PICL_SUCCESS;
	picl_nodehdl_t p_parent;

	/* do not allow the libfru users to see the parent of the root */
	if (TREEHDL_TO_PICLHDL(handle) == picl_root_node) {
		return (FRU_NODENOTFOUND);
	}

	rc = picl_get_propval_by_name(TREEHDL_TO_PICLHDL(handle),
		PICL_PROP_PARENT, (void *)&p_parent, sizeof (p_parent));
	if (rc != PICL_SUCCESS) {
		return (map_plugin_err(rc));
	}

	*parent = PICLHDL_TO_TREEHDL(p_parent);
	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_node_type(fru_treehdl_t node, fru_node_t *type)
{
	int	rc = PICL_SUCCESS;
	char picl_class[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t handle = TREEHDL_TO_PICLHDL(node);

	if ((rc = picl_get_propval_by_name(handle, PICL_PROP_CLASSNAME,
		picl_class, sizeof (picl_class))) != PICL_SUCCESS) {
		return (map_plugin_err(rc));
	}

	if (strcmp(picl_class, PICL_CLASS_LOCATION) == 0)  {
		*type = FRU_NODE_LOCATION;
		return (FRU_SUCCESS);
	} else if (strcmp(picl_class, PICL_CLASS_FRU) == 0) {
		picl_prophdl_t proph;

		/* check for the CONTAINER_PROP property which indicates */
		/* there is data for this node.  (ie fru is a container) */
		if (picl_get_prop_by_name(handle,
			PICL_PROP_CONTAINER, &proph) == PICL_SUCCESS) {
			*type = FRU_NODE_CONTAINER;
			return (FRU_SUCCESS);
		}
		*type = FRU_NODE_FRU;
		return (FRU_SUCCESS);
	}

	*type = FRU_NODE_UNKNOWN;
	return (FRU_SUCCESS);
}

/* ========================================================================= */
/* find the next section or return NODENOTFOUND */
static fru_errno_t
find_next_section(picl_nodehdl_t current, picl_nodehdl_t *next)
{
	picl_nodehdl_t rc_next;

	if (picl_get_propval_by_name(current, PICL_PROP_PEER,
		(void *)&rc_next, sizeof (rc_next)) != PICL_SUCCESS) {
		return (FRU_NODENOTFOUND);
	}

	/* Make sure this is a "Section" node */
	if (cmp_class_name(rc_next, PICL_CLASS_SECTION)
			== FRU_SUCCESS) {
		*next = rc_next;
		return (FRU_SUCCESS);
	}

	/* and if this is not good keep trying to find a peer which */
	/* is a section */
	return (find_next_section(rc_next, next));
}

/* ========================================================================= */
/* find the first section or return NODENOTFOUND */
static fru_errno_t
find_first_section(picl_nodehdl_t parent, picl_nodehdl_t *section)
{
	picl_nodehdl_t rc_section;

	if (picl_get_propval_by_name(parent, PICL_PROP_CHILD,
		(void *)&rc_section, sizeof (rc_section)) != PICL_SUCCESS) {
		return (FRU_NODENOTFOUND);
	}

	/* Make sure this is a "Section" node */
	if (cmp_class_name(rc_section, PICL_CLASS_SECTION)
			== FRU_SUCCESS) {
		*section = rc_section;
		return (FRU_SUCCESS);
	}

	/* and if this is not good keep trying to find a peer which */
	/* is a section */
	return (find_next_section(rc_section, section));
}

/* ========================================================================= */
/*
 * Find the handle of the segment node "segment".
 * also returns the hardware description of this segment.  (read from the
 * section this was found in.)
 * If the ign_cor_flg is set this will still succeed even if the segment is
 * corrupt, otherwise it will return FRU_SEGCORRUPT for corrupt segments
 */
#define	IGN_CORRUPT_YES 1
#define	IGN_CORRUPT_NO 0
static fru_errno_t
get_segment_node(picl_nodehdl_t handle, const char *segment,
	picl_nodehdl_t *seg_hdl, fru_seg_hwdesc_t *hw_desc, int ign_cor_flg)
{
	fru_errno_t err = FRU_SUCCESS;
	picl_nodehdl_t sect_node;

	if ((err = update_data_nodes(handle)) != FRU_SUCCESS) {
		return (err);
	}

	if ((err = find_first_section(handle, &sect_node)) != FRU_SUCCESS) {
		return (err);
	}

	/* while there are sections. */
	while (err == FRU_SUCCESS) {
		uint32_t num_segs = 0;
		int rc = PICL_SUCCESS;
		picl_nodehdl_t seg_node;

		/* do this just in case the Segments have not been built. */
		if ((rc = picl_get_propval_by_name(sect_node,
			PICL_PROP_NUM_SEGMENTS,
			(void *)&num_segs,
			sizeof (num_segs))) != PICL_SUCCESS) {
			return (map_plugin_err(rc));
		}

		/* while there are segments. */
		rc = picl_get_propval_by_name(sect_node, PICL_PROP_CHILD,
			(void *)&seg_node, sizeof (seg_node));
		while (rc == PICL_SUCCESS) {
			char name[PICL_PROPNAMELEN_MAX];
			picl_get_propval_by_name(seg_node, PICL_PROP_NAME,
				name, sizeof (name));
			if (strcmp(segment, name) == 0) {
				int dummy = 0;
				int protection = 0;
				/* NUM_TAGS prop exists iff segment is OK */
				if ((ign_cor_flg == IGN_CORRUPT_NO) &&
					(picl_get_propval_by_name(seg_node,
					PICL_PROP_NUM_TAGS,
					(void *)&dummy,
					sizeof (dummy)) != PICL_SUCCESS)) {
					return (FRU_SEGCORRUPT);
				}
				/* get the HW protections of this section. */
				if ((rc = picl_get_propval_by_name(sect_node,
					PICL_PROP_PROTECTED,
					(void *)&protection,
					sizeof (protection)))
							!= PICL_SUCCESS) {
					return (map_plugin_err(rc));
				}
				hw_desc->all_bits = 0;
				hw_desc->field.read_only = protection;

				*seg_hdl = seg_node;
				return (FRU_SUCCESS);
			}
			rc = picl_get_propval_by_name(seg_node, PICL_PROP_PEER,
				(void *)&seg_node, sizeof (seg_node));
		}

		/* Peer property not found is ok */
		if (rc != PICL_PROPNOTFOUND) {
			return (map_plugin_err(rc));
		}

		err = find_next_section(sect_node, &sect_node);
	}

	return (FRU_INVALSEG);
}

/* ========================================================================= */
/*
 * For the section handle passed add to list all the segment names found.
 * Also incriments total by the number found.
 */
static fru_errno_t
add_segs_for_section(picl_nodehdl_t section, fru_strlist_t *list)
{
	uint32_t num_segments = 0;
	int rc = PICL_SUCCESS;

	if ((rc = picl_get_propval_by_name(section,
		PICL_PROP_NUM_SEGMENTS,
		(void *)&num_segments,
		sizeof (num_segments))) != PICL_SUCCESS) {
		fru_destroy_strlist(list);
		return (map_plugin_err(rc));
	}

	if (num_segments != 0) {
		picl_nodehdl_t seg_node;
		int total_space = list->num + num_segments;

		list->strs = realloc(list->strs,
			(sizeof (*(list->strs)) * (total_space)));
		if (list->strs == NULL) {
			return (FRU_FAILURE);
		}

		/* get the first segment */
		rc = picl_get_propval_by_name(section,
			PICL_PROP_CHILD, (void *)&seg_node,
			sizeof (seg_node));

		/* while there are more segments. */
		while (rc == PICL_SUCCESS) {
			char name[FRU_SEGNAMELEN +1];

			if ((rc = picl_get_propval_by_name(seg_node,
				PICL_PROP_NAME, name,
				sizeof (name))) != PICL_SUCCESS) {
				break;
			}

			/* check array bounds */
			if (list->num >= total_space) {
				/* PICL reported incorrect number of segs */
				return (FRU_IOERROR);
			}
			list->strs[(list->num)++] = strdup(name);

			rc = picl_get_propval_by_name(seg_node,
				PICL_PROP_PEER, (void *)&seg_node,
				sizeof (seg_node));
		}

		/* Peer property not found is ok */
		if (rc != PICL_PROPNOTFOUND) {
			return (map_plugin_err(rc));
		}

	}
	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_seg_list(fru_treehdl_t handle, fru_strlist_t *list)
{
	fru_errno_t err;
	picl_nodehdl_t sect_node;
	fru_strlist_t rc_list;
	rc_list.num = 0;
	rc_list.strs = NULL;

	if ((err = update_data_nodes(TREEHDL_TO_PICLHDL(handle)))
			!= FRU_SUCCESS) {
		return (err);
	}

	if ((err = find_first_section(TREEHDL_TO_PICLHDL(handle), &sect_node))
			!= FRU_SUCCESS) {
		return (err);
	}

	/* while there are sections. */
	while (err == FRU_SUCCESS) {
		if ((err = add_segs_for_section(sect_node, &rc_list))
				!= FRU_SUCCESS) {
			fru_destroy_strlist(&rc_list);
			return (err);
		}
		err = find_next_section(sect_node, &sect_node);
	}

	list->num = rc_list.num;
	list->strs = rc_list.strs;

	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_seg_def(fru_treehdl_t handle, const char *seg_name, fru_segdef_t *def)
{
	fru_errno_t err = FRU_SUCCESS;
	picl_nodehdl_t seg_node;
	fru_seg_hwdesc_t hw_desc;

	fru_segdesc_t desc;
	uint32_t size;
	uint32_t address;
	/* LINTED */
	int picl_err = PICL_SUCCESS;

	if ((err = get_segment_node(TREEHDL_TO_PICLHDL(handle), seg_name,
		&seg_node, &hw_desc, IGN_CORRUPT_YES)) != FRU_SUCCESS)
		return (err);

	if ((picl_err = picl_get_propval_by_name(seg_node,
		PICL_PROP_DESCRIPTOR,
		&desc, sizeof (desc))) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	if ((picl_err = picl_get_propval_by_name(seg_node,
		PICL_PROP_LENGTH,
		&size, sizeof (size))) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	if ((picl_err = picl_get_propval_by_name(seg_node,
		PICL_PROP_OFFSET,
		&address, sizeof (address))) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	def->version = LIBFRU_VERSION;
	strlcpy(def->name, seg_name, FRU_SEGNAMELEN+1);
	def->desc = desc;
	def->size = size;
	def->address = address;
	def->hw_desc = hw_desc;

	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_add_seg(fru_treehdl_t handle, fru_segdef_t *def)
{
	fru_errno_t err = FRU_SUCCESS;
	int picl_err = PICL_SUCCESS;
	picl_nodehdl_t section;

/*
 * for every section which has a ADD_SEGMENT_PROP try and add the segment
 */
	if ((err = find_first_section(TREEHDL_TO_PICLHDL(handle), &section))
		!= FRU_SUCCESS) {
		return (err);
	}
	do {
		fru_segdef_t dummy;
		if ((picl_err = picl_get_propval_by_name(section,
			PICL_PROP_ADD_SEGMENT, &dummy, sizeof (dummy)))
				== PICL_SUCCESS) {

			picl_err = picl_set_propval_by_name(section,
				PICL_PROP_ADD_SEGMENT, def, sizeof (*def));

			return (map_plugin_err(picl_err));
		}
	} while (find_next_section(section, &section) == FRU_SUCCESS);

	return (map_plugin_err(picl_err));
}

/* ========================================================================= */
static fru_errno_t
fpt_delete_seg(fru_treehdl_t handle, const char *seg_name)
{
	picl_nodehdl_t seg_hdl;
	fru_seg_hwdesc_t hw_desc;
	fru_errno_t err;

	int dead_flag = FRUDATA_DELETE_TAG_KEY;
	int rc = PICL_SUCCESS;

	if ((err = get_segment_node(TREEHDL_TO_PICLHDL(handle), seg_name,
		&seg_hdl, &hw_desc, IGN_CORRUPT_YES)) != FRU_SUCCESS) {
		return (err);
	}

	rc = picl_set_propval_by_name(seg_hdl, PICL_PROP_DELETE_SEGMENT,
		&dead_flag, sizeof (dead_flag));
	return (map_plugin_err(rc));
}

/* ========================================================================= */
static fru_errno_t
fpt_add_tag_to_seg(fru_treehdl_t handle, const char *seg_name,
		fru_tag_t tag, uint8_t *data, size_t data_len)
{
	fru_errno_t err = FRU_SUCCESS;
	picl_nodehdl_t segHdl;
	fru_seg_hwdesc_t hw_desc;
	int picl_err = PICL_SUCCESS;
	size_t buf_size = 0;
	uint8_t *buffer = NULL;
	picl_prophdl_t add_prop;
	picl_propinfo_t add_prop_info;

	if ((err = get_segment_node(TREEHDL_TO_PICLHDL(handle), seg_name,
		&segHdl, &hw_desc, IGN_CORRUPT_NO)) != FRU_SUCCESS) {
		return (err);
	}

	/* get the length of the buffer required. */
	if ((picl_err = picl_get_prop_by_name(segHdl,
		PICL_PROP_ADD_PACKET,
		&add_prop)) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}
	if ((picl_err = picl_get_propinfo(add_prop, &add_prop_info))
			!= PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	buf_size = add_prop_info.size;
	if (data_len >= (buf_size - get_tag_size(get_tag_type(&tag)))) {
		return (FRU_NOSPACE);
	}

	buffer = malloc(buf_size);
	if (buffer == NULL) {
		return (FRU_FAILURE);
	}
	/* write the tag and data into the buffer */
	memcpy(buffer, &tag, get_tag_size(get_tag_type(&tag)));
	memcpy((void *)(buffer+get_tag_size(get_tag_type(&tag))),
		data, data_len);

	picl_err = picl_set_propval(add_prop, buffer, buf_size);
	free(buffer);
	return (map_plugin_err(picl_err));
}

/* ========================================================================= */
static fru_errno_t
fpt_get_tag_list(fru_treehdl_t handle, const char *seg_name,
		fru_tag_t **tags, int *number)
{
	picl_nodehdl_t seg_node;
	fru_seg_hwdesc_t hw_desc;
	fru_errno_t err = FRU_SUCCESS;
	picl_prophdl_t tagTable;
	int picl_err = PICL_SUCCESS;
	unsigned int total_tags = 0;

	/* return variables */
	fru_tag_t *rc_tags = NULL;
	unsigned int rc_num = 0;

	if ((err = get_segment_node(TREEHDL_TO_PICLHDL(handle), seg_name,
		&seg_node, &hw_desc, IGN_CORRUPT_NO)) != FRU_SUCCESS) {
		return (err);
	}

	/* get the number of tags and allocate array for them */
	if ((picl_err = picl_get_propval_by_name(seg_node,
		PICL_PROP_NUM_TAGS,
		(void *)&total_tags,
		sizeof (total_tags))) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	if (total_tags == 0) {
		*tags = rc_tags;
		*number = rc_num;
		return (FRU_SUCCESS);
	}

	rc_tags = malloc((sizeof (*rc_tags) * total_tags));
	if (rc_tags == NULL) {
		return (FRU_FAILURE);
	}

	/* go through the tagTable and fill in the array */
	if ((picl_err = picl_get_propval_by_name(seg_node,
		PICL_PROP_PACKET_TABLE,
		&tagTable, sizeof (tagTable))) != PICL_SUCCESS) {
		free(rc_tags);
		return (map_plugin_err(picl_err));
	}
	picl_err = picl_get_next_by_col(tagTable, &tagTable);
	while (picl_err == PICL_SUCCESS) {
		/* check array bounds */
		if (rc_num >= total_tags) {
			free(rc_tags);
			return (FRU_FAILURE);
		}
		/* fill in the array */
		if ((picl_err = picl_get_propval(tagTable,
			(void *)&(rc_tags[rc_num++]),
			sizeof (fru_tag_t))) != PICL_SUCCESS) {
			free(rc_tags);
			return (map_plugin_err(picl_err));
		}
		/* get the next tag */
		picl_err = picl_get_next_by_col(tagTable, &tagTable);
	}

	if (picl_err == PICL_ENDOFLIST) {
		*tags = rc_tags;
		*number = rc_num;
		return (FRU_SUCCESS);
	}
	return (map_plugin_err(picl_err));
}

/* ========================================================================= */
/*
 * From the handle, segment name, tag, and instance of the tag get me:
 * segHdl: The segment handle for this segment.
 * tagHdl: tag property handle in the tag table for this instance "tag"
 */
static fru_errno_t
get_tag_handle(picl_nodehdl_t handle, const char *segment,
		fru_tag_t tag, int instance,
		picl_nodehdl_t *segHdl,
		picl_prophdl_t *tagHdl)
{
	fru_seg_hwdesc_t hw_desc;
	fru_errno_t err;
	picl_prophdl_t tagTable = 0;
	int picl_err = PICL_SUCCESS;
	picl_nodehdl_t tmp_seg;

	fru_tag_t foundTag;

	if ((err = get_segment_node(TREEHDL_TO_PICLHDL(handle), segment,
		&tmp_seg, &hw_desc, IGN_CORRUPT_NO)) != FRU_SUCCESS) {
		return (err);
	}

	foundTag.raw_data = 0;
	if ((picl_err = picl_get_propval_by_name(tmp_seg,
		PICL_PROP_PACKET_TABLE,
		&tagTable, sizeof (tagTable))) != PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	picl_err = picl_get_next_by_col(tagTable, &tagTable);
	while ((picl_err != PICL_ENDOFLIST) &&
		(picl_err == PICL_SUCCESS)) {
		if ((picl_err = picl_get_propval(tagTable, (void *)&foundTag,
			sizeof (foundTag))) != PICL_SUCCESS) {
			return (map_plugin_err(picl_err));
		}
		if ((tags_equal(tag, foundTag) == 1) && (instance-- == 0)) {
			*segHdl = tmp_seg;
			*tagHdl = tagTable;
			return (FRU_SUCCESS);
		}
		picl_err = picl_get_next_by_col(tagTable, &tagTable);
	}

	return (map_plugin_err(picl_err));
}

/* ========================================================================= */
static fru_errno_t
fpt_get_tag_data(fru_treehdl_t handle, const char *seg_name,
		fru_tag_t tag, int instance,
		uint8_t **data, size_t *data_len)
{
	fru_errno_t err = FRU_SUCCESS;
	int picl_err = PICL_SUCCESS;
	uint8_t *buffer;
	int buf_len = 0;

	picl_nodehdl_t seg;
	picl_prophdl_t tagHdl;

	if ((err = get_tag_handle(TREEHDL_TO_PICLHDL(handle), seg_name,
		tag, instance, &seg, &tagHdl)) != FRU_SUCCESS) {
		return (err);
	}

	if ((picl_err = picl_get_next_by_row(tagHdl, &tagHdl))
		!= PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	buf_len = get_payload_length(&tag);
	buffer = malloc(buf_len);
	if (buffer == NULL) {
		return (FRU_FAILURE);
	}

	if ((picl_err = picl_get_propval(tagHdl, buffer, buf_len))
		!= PICL_SUCCESS) {
		free(buffer);
		return (map_plugin_err(picl_err));
	}

	*data = buffer;
	*data_len = buf_len;
	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_set_tag_data(fru_treehdl_t handle, const char *seg_name,
		fru_tag_t tag, int instance,
		uint8_t *data, size_t data_len)
{
	fru_errno_t rc = FRU_SUCCESS;
	int picl_err = PICL_SUCCESS;

	picl_nodehdl_t seg;
	picl_prophdl_t tagHdl;

	if ((rc = get_tag_handle(TREEHDL_TO_PICLHDL(handle), seg_name,
		tag, instance, &seg, &tagHdl)) != FRU_SUCCESS) {
		return (rc);
	}

	if ((picl_err = picl_get_next_by_row(tagHdl, &tagHdl))
		!= PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	if ((picl_err = picl_set_propval(tagHdl, data, data_len))
		!= PICL_SUCCESS) {
		return (map_plugin_err(picl_err));
	}

	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_delete_tag(fru_treehdl_t handle, const char *seg_name, fru_tag_t tag,
		int instance)
{
	fru_errno_t rc = FRU_SUCCESS;
	int picl_err = PICL_SUCCESS;

	picl_nodehdl_t segHdl;
	picl_prophdl_t tagHdl;

	/* get tag handle */
	if ((rc = get_tag_handle(TREEHDL_TO_PICLHDL(handle), seg_name,
		tag, instance, &segHdl, &tagHdl)) != FRU_SUCCESS) {
		return (rc);
	}

	/* set up key */
	tag.raw_data &= FRUDATA_DELETE_TAG_MASK;
	tag.raw_data |= FRUDATA_DELETE_TAG_KEY;

	/* Write back */
	picl_err = picl_set_propval(tagHdl, (void *)&(tag.raw_data),
		sizeof (tag.raw_data));
	return (map_plugin_err(picl_err));
}

/* ========================================================================= */
static fru_errno_t
fpt_for_each_segment(fru_treehdl_t treenode,
			int (*function)(fru_treeseghdl_t segment, void *args),
			void *args)
{
	int		num_segments = 0, status;

	fru_errno_t	saved_status = FRU_SUCCESS;

	picl_nodehdl_t	container = TREEHDL_TO_PICLHDL(treenode),
			section, segment;


	if ((status = update_data_nodes(container)) != FRU_SUCCESS)
		return (status);

	/* process each section */
	for (status = picl_get_propval_by_name(container, PICL_PROP_CHILD,
						&section, sizeof (section));
		status == PICL_SUCCESS;
		status = picl_get_propval_by_name(section, PICL_PROP_PEER,
							&section,
							sizeof (section))) {

		if (cmp_class_name(section, PICL_CLASS_SECTION) != FRU_SUCCESS)
			continue;

		if ((status = picl_get_propval_by_name(section,
							PICL_PROP_NUM_SEGMENTS,
							&num_segments,
							sizeof (num_segments)))
		    == PICL_PROPNOTFOUND) {
			continue;
		} else if (status != PICL_SUCCESS) {
			saved_status = map_plugin_err(status);
			continue;
		} else if (num_segments == 0) {
			continue;
		}

		/* process each segment */
		for (status = picl_get_propval_by_name(section,
							PICL_PROP_CHILD,
							&segment,
							sizeof (segment));
			status == PICL_SUCCESS;
			status = picl_get_propval_by_name(segment,
							PICL_PROP_PEER,
							&segment,
							sizeof (segment))) {

			if (cmp_class_name(segment, PICL_CLASS_SEGMENT)
			    != FRU_SUCCESS) continue;

			if ((status = function(PICLHDL_TO_TREESEGHDL(segment),
						args))
			    != FRU_SUCCESS) return (status);
		}

		if (status != PICL_PROPNOTFOUND)
			saved_status = map_plugin_err(status);
	}

	if (status != PICL_PROPNOTFOUND)
		saved_status = map_plugin_err(status);

	return (saved_status);
}

/* ========================================================================= */
static fru_errno_t
fpt_get_segment_name(fru_treeseghdl_t segment, char **name)
{
	char		*propval;

	int		status;

	picl_prophdl_t	proph = 0;

	picl_propinfo_t	propinfo;


	if ((status = picl_get_propinfo_by_name(TREESEGHDL_TO_PICLHDL(segment),
		PICL_PROP_NAME, &propinfo, &proph))
	    != PICL_SUCCESS)
		return (map_plugin_err(status));

	if (propinfo.size == 0)
		return (FRU_INVALDATASIZE);

	if ((propval = malloc(propinfo.size)) == NULL)
		return (FRU_NOSPACE);

	if ((status = picl_get_propval(proph, propval, propinfo.size))
	    != PICL_SUCCESS) {
		free(propval);
		return (map_plugin_err(status));
	}

	*name = propval;

	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
fpt_for_each_packet(fru_treeseghdl_t treesegment,
			int (*function)(fru_tag_t *tag, uint8_t *payload,
					size_t length,
			void *args),
    void *args)
{
	int		status;

	uint8_t		*payload;

	picl_nodehdl_t	segment = TREESEGHDL_TO_PICLHDL(treesegment);

	picl_prophdl_t	packet, payloadh = 0;

	picl_propinfo_t	propinfo;

	fru_segdesc_t	descriptor;

	fru_tag_t	tag;


	if ((status = picl_get_propval_by_name(segment, PICL_PROP_DESCRIPTOR,
						&descriptor,
						sizeof (descriptor)))
	    != PICL_SUCCESS) return (map_plugin_err(status));

	if (descriptor.field.opaque)
		return (FRU_SUCCESS);

	if (descriptor.field.encrypted && (encrypt_func == NULL))
		return (FRU_SUCCESS);

	if ((status = picl_get_propval_by_name(segment, PICL_PROP_PACKET_TABLE,
						&packet, sizeof (packet)))
	    == PICL_PROPNOTFOUND)
		return (FRU_SUCCESS);
	else if (status != PICL_SUCCESS)
		return (map_plugin_err(status));

	while ((status = picl_get_next_by_col(packet, &packet))
		== PICL_SUCCESS) {
		if (((status = picl_get_propval(packet, &tag, sizeof (tag)))
			!= PICL_SUCCESS) ||
		    ((status = picl_get_next_by_row(packet, &payloadh))
			!= PICL_SUCCESS) ||
		    ((status = picl_get_propinfo(payloadh, &propinfo))
			!= PICL_SUCCESS))
			return (map_plugin_err(status));

		if (propinfo.size > 0) {
			payload = alloca(propinfo.size);
			if ((status = picl_get_propval(payloadh, payload,
							propinfo.size))
			    != PICL_SUCCESS) return (map_plugin_err(status));
		} else {
			payload = NULL;
		}

		if ((descriptor.field.encrypted) &&
		    ((status = encrypt_func(FRU_DECRYPT, payload,
						propinfo.size))
			!= FRU_SUCCESS)) return status;

		if ((status = function(&tag, payload, propinfo.size, args))
		    != FRU_SUCCESS) return (status);
	}

	if (status == PICL_ENDOFLIST)
		return (FRU_SUCCESS);
	else
		return (map_plugin_err(status));
}

/* ========================================================================= */
/* ARGSUSED0 */
static fru_errno_t
initialize(int argc, char **argv)
{
	/* LINTED */
	int rc = PICL_SUCCESS;
	if ((rc = picl_initialize()) != PICL_SUCCESS) {
		return (FRU_FAILURE);
	}

	return (FRU_SUCCESS);
}

/* ========================================================================= */
static fru_errno_t
shutdown(void)
{
	if (picl_shutdown() != PICL_SUCCESS) {
		return (FRU_FAILURE);
	}
	return (FRU_SUCCESS);
}

/* ========================================================================= */
/* object for libfru to link to */
fru_datasource_t data_source =
{
	LIBFRU_DS_VER,
	initialize,
	shutdown,
	fpt_get_root,
	fpt_get_child,
	fpt_get_peer,
	fpt_get_parent,
	fpt_get_name_from_hdl,
	fpt_get_node_type,
	fpt_get_seg_list,
	fpt_get_seg_def,
	fpt_add_seg,
	fpt_delete_seg,
	fpt_for_each_segment,
	fpt_get_segment_name,
	fpt_add_tag_to_seg,
	fpt_get_tag_list,
	fpt_get_tag_data,
	fpt_set_tag_data,
	fpt_delete_tag,
	fpt_for_each_packet
};
