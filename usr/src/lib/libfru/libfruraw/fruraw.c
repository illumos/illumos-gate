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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "fru_access_impl.h"

#include "libfruds.h"
#include "libfrup.h"
#include "fru_access.h"
#include "fruraw.h"


raw_list_t *g_raw = NULL;


/* ARGSUSED */
static raw_list_t *
treehdl_to_rawlist(fru_treehdl_t handle)
{
	return (g_raw);
}


static container_hdl_t
treehdl_to_conthdl(fru_treehdl_t handle)
{
	raw_list_t *ptr;

	ptr = treehdl_to_rawlist(handle);
	if (ptr == NULL) {
		return (-1);
	}

	return (ptr->cont);
}


static fru_errno_t
map_errno(int err)
{
	switch (err) {
	case ENFILE:
	case EEXIST:
		return (FRU_DUPSEG);
	case EAGAIN:
		return (FRU_NOSPACE);
	case EPERM:
		return (FRU_INVALPERM);
	default :
		return (FRU_IOERROR);
	}
}


static raw_list_t *
make_raw(uint8_t *buffer, size_t size, char *cont_type)
{
	raw_list_t *node;

	node = (raw_list_t *)malloc(sizeof (raw_list_t));
	if (node == NULL) {
		return (NULL);
	}

	node->hdl = 0;
	node->raw = buffer;
	node->size = size;
	node->cont_type = strdup(cont_type);
	if (node->cont_type == NULL) {
		free(node);
		return (NULL);
	}
	node->segs = NULL;

	return (node);
}


/*
 * Arguments :
 * 0 - pointer to byte buffer (in)
 * 1 - size of buffer (in)
 * 2 - container type, string (in)
 */
static fru_errno_t
frt_initialize(int num, char **args)
{


	if (num != 3) {
		return (FRU_FAILURE);
	}

	g_raw = make_raw((uint8_t *)args[0], (size_t)args[1], args[2]);
	if (g_raw == NULL) {
		return (FRU_FAILURE);
	}

	g_raw->cont = open_raw_data(g_raw);
	if (g_raw->cont == NULL) {
		return (FRU_FAILURE);
	}

	return (FRU_SUCCESS);
}


static fru_errno_t
frt_shutdown(void)
{
	segment_list_t *lptr, *lptr2;

	(void) fru_close_container(g_raw->cont);
	free(g_raw->cont_type);
	lptr = g_raw->segs;
	while (lptr) {
		lptr2 = lptr;
		lptr = lptr->next;
		free(lptr2);
	}
	g_raw = NULL;

	return (FRU_SUCCESS);
}


static fru_errno_t
frt_get_root(fru_treehdl_t *node)
{
	*node = g_raw->hdl;

	return (FRU_SUCCESS);
}

/* ARGSUSED */
static fru_errno_t
frt_get_peer(fru_treehdl_t sibling, fru_treehdl_t *peer)
{
	return (FRU_NODENOTFOUND);
}
/* ARGSUSED */
static fru_errno_t
frt_get_child(fru_treehdl_t handle, fru_treehdl_t *child)
{
	return (FRU_NODENOTFOUND);
}

/* ARGSUSED */
static fru_errno_t
frt_get_parent(fru_treehdl_t handle, fru_treehdl_t *parent)
{
	return (FRU_NODENOTFOUND);
}

/* ARGSUSED */
static fru_errno_t
frt_get_name_from_hdl(fru_treehdl_t handle, char **name)
{
	*name = strdup("unknown");
	return (FRU_SUCCESS);
}

/* ARGSUSED */
static fru_errno_t
frt_get_node_type(fru_treehdl_t node, fru_node_t *type)
{
	*type = FRU_NODE_CONTAINER;
	return (FRU_SUCCESS);
}



static fru_errno_t
add_segs_for_section(section_t *section, fru_strlist_t *list)
{
	int i = 0;
	segment_t *segs = NULL;
	int acc_err = 0;

	int num_segment = fru_get_num_segments(section->handle, NULL);
	if (num_segment == -1) {
		return (map_errno(errno));
	} else if (num_segment == 0) {
		return (FRU_SUCCESS);
	}

	segs = malloc(sizeof (*segs) * (num_segment));
	if (segs == NULL) {
		return (FRU_FAILURE);
	}

	acc_err = fru_get_segments(section->handle, segs, num_segment, NULL);
	if (acc_err == -1) {
		free(segs);
		return (map_errno(errno));
	}

	list->strs = realloc(list->strs, sizeof (char *)
	    * (list->num + num_segment));

	for (i = 0; i < num_segment; i++) {
		/* ensure NULL terminated. */
		char *tmp = malloc(sizeof (*tmp) * (sizeof (segs[i].name)+1));
		if (tmp == NULL) {
			free(segs);
			return (FRU_FAILURE);
		}
		(void) memcpy(tmp, segs[i].name, sizeof (segs[i].name));
		tmp[sizeof (segs[i].name)] = '\0';

		list->strs[(list->num)++] = tmp;
	}

	free(segs);

	return (FRU_SUCCESS);
}



static fru_errno_t
frt_get_seg_list(fru_treehdl_t handle, fru_strlist_t *list)
{
	fru_strlist_t rc_list;
	fru_errno_t err = FRU_SUCCESS;
	int acc_err = 0;
	int i = 0;
	int num_section = 0;
	section_t *sects = NULL;
	container_hdl_t cont;

	cont = treehdl_to_conthdl(handle);

	num_section = fru_get_num_sections(cont, NULL);
	if (num_section == -1) {
		return (map_errno(errno));
	}

	sects = malloc(sizeof (*sects) * (num_section));
	if (sects == NULL) {
		return (FRU_FAILURE);
	}

	acc_err = fru_get_sections(cont, sects, num_section, NULL);
	if (acc_err == -1) {
		free(sects);
		return (map_errno(errno));
	}

	rc_list.num = 0;
	rc_list.strs = NULL;
	for (i = 0; i < num_section; i++) {
		if ((err = add_segs_for_section(&(sects[i]), &rc_list))
		    != FRU_SUCCESS) {
			fru_destroy_strlist(&rc_list);
			free(sects);
			return (err);
		}
	}

	list->strs = rc_list.strs;
	list->num = rc_list.num;

	return (FRU_SUCCESS);
}


static fru_errno_t
find_seg_in_sect(section_t *sect, const char *seg_name, int *prot_flg,
    segment_t *segment)
{
	int j = 0;
	int acc_err = 0;
	segment_t *segs = NULL;

	int num_seg = fru_get_num_segments(sect->handle, NULL);
	if (num_seg == -1) {
		return (FRU_FAILURE);
	}

	segs = malloc(sizeof (*segs) * (num_seg));
	if (segs == NULL) {
		return (FRU_FAILURE);
	}

	acc_err = fru_get_segments(sect->handle, segs, num_seg, NULL);
	if (acc_err == -1) {
		free(segs);
		return (map_errno(errno));
	}

	for (j = 0; j < num_seg; j++) {
		/* NULL terminate */
		char tmp[SEG_NAME_LEN+1];
		(void) memcpy(tmp, segs[j].name, SEG_NAME_LEN);
		tmp[SEG_NAME_LEN] = '\0';
		if (strcmp(tmp, seg_name) == 0) {
			*segment = segs[j];
			*prot_flg = (sect->protection ? 1 : 0);
			free(segs);
			return (FRU_SUCCESS);
		}
	}

	free(segs);
	return (FRU_INVALSEG);
}


static fru_errno_t
find_segment(fru_treehdl_t handle, const char *seg_name, int *prot_flg,
    segment_t *segment)
{
	int i = 0;
	int acc_err = 0;
	section_t *sect = NULL;
	container_hdl_t cont;
	int num_sect;

	cont = treehdl_to_conthdl(handle);

	num_sect = fru_get_num_sections(cont, NULL);
	if (num_sect == -1) {
		return (map_errno(errno));
	}

	sect = malloc(sizeof (*sect) * (num_sect));
	if (sect == NULL) {
		return (FRU_FAILURE);
	}

	acc_err = fru_get_sections(cont, sect, num_sect, NULL);
	if (acc_err == -1) {
		free(sect);
		return (map_errno(errno));
	}

	for (i = 0; i < num_sect; i++) {
		if (find_seg_in_sect(&(sect[i]), seg_name, prot_flg, segment)
		    == FRU_SUCCESS) {
			free(sect);
			return (FRU_SUCCESS);
		}
	}

	free(sect);
	return (FRU_INVALSEG);
}


static fru_errno_t
frt_get_seg_def(fru_treehdl_t handle, const char *seg_name, fru_segdef_t *def)
{
	fru_errno_t err = FRU_SUCCESS;
	int prot_flg = 0;
	segment_t segment;

	if ((err = find_segment(handle, seg_name, &prot_flg, &segment))
	    != FRU_SUCCESS) {
		return (err);
	}

	(void) memcpy(def->name, segment.name, SEG_NAME_LEN);
	def->name[SEG_NAME_LEN] = '\0';
	def->desc.raw_data = segment.descriptor;
	def->size = segment.length;
	def->address = segment.offset;

	if (prot_flg == 0)
		def->hw_desc.field.read_only = 0;
	else
		def->hw_desc.field.read_only = 1;

	return (FRU_SUCCESS);

}

/* ARGSUSED */
static fru_errno_t
frt_add_seg(fru_treehdl_t handle, fru_segdef_t *def)
{
	/* NOT SUPPORTED */
	return (FRU_NOTSUP);
}

/* ARGSUSED */
static fru_errno_t
frt_delete_seg(fru_treehdl_t handle, const char *seg_name)
{
	/* NOT SUPPORTED */
	return (FRU_NOTSUP);
}

/* ARGSUSED */
static fru_errno_t
frt_for_each_segment(fru_nodehdl_t node,
    int (*function)(fru_seghdl_t hdl, void *args), void *args)
{
	int num_segment;
	int cnt;
	int num_sect;
	int each_seg;
	section_t *sects;
	segment_t *segs;
	segment_list_t *tmp_list;
	int acc_err;
	int status;
	container_hdl_t cont;

	cont = g_raw->cont;

	num_sect = fru_get_num_sections(cont, NULL);
	if (num_sect == -1) {
		return (map_errno(errno));
	}

	sects = malloc((num_sect + 1) * sizeof (section_t));
	if (sects == NULL) {
		return (FRU_FAILURE);
	}
	num_sect = fru_get_sections(cont, sects, num_sect, NULL);
	if (num_sect == -1) {
		free(sects);
		return (map_errno(errno));
	}
	for (cnt = 0; cnt < num_sect; cnt++) {
		num_segment = fru_get_num_segments(sects[cnt].handle, NULL);
		if (num_segment == -1) {
			return (map_errno(errno));
		} else if (num_segment == 0) {
			continue;
		}
		segs = malloc((num_segment + 1) * sizeof (segment_t));
		if (segs == NULL) {
			free(sects);
			return (FRU_FAILURE);
		}
		acc_err = fru_get_segments(sects[cnt].handle, segs,
		    num_segment, NULL);
		if (acc_err == -1) {
			free(sects);
			free(segs);
			return (map_errno(errno));
		}
		for (each_seg = 0; each_seg < num_segment; each_seg++) {
			tmp_list = malloc(sizeof (segment_list_t));
			tmp_list->segment = &segs[each_seg];
			tmp_list->next = NULL;
			if (g_raw->segs == NULL) {
				g_raw->segs = tmp_list;
			} else {
				tmp_list->next = g_raw->segs;
				g_raw->segs = tmp_list;
			}

			if ((status = function(segs[each_seg].handle, args))
			    != FRU_SUCCESS) {
				free(segs);
				free(sects);
				return (status);
			}
		}
		free(segs);
		free(sects);

	}
	return (FRU_SUCCESS);
}


static fru_errno_t
frt_get_segment_name(fru_seghdl_t node, char **name)
{
	int num_sect;
	int acc_err;
	int cnt;
	int num_segment;
	section_t *sects;
	segment_t *segs;
	int each_seg;
	container_hdl_t cont;

	cont = treehdl_to_conthdl(node);

	num_sect = fru_get_num_sections(cont, NULL);
	if (num_sect == -1) {
		return (map_errno(errno));
	}

	sects = malloc(sizeof (*sects) * (num_sect));
	if (sects == NULL) {
		return (FRU_FAILURE);
	}
	acc_err = fru_get_sections(cont, sects, num_sect, NULL);
	if (acc_err == -1) {
		free(sects);
		return (map_errno(errno));
	}

	for (cnt = 0; cnt < num_sect; cnt++) {
		num_segment = fru_get_num_segments(sects[cnt].handle, NULL);
		if (num_segment == -1) {
			free(sects);
			return (map_errno(errno));
		} else if (num_segment == 0) {
			continue;
		}

		segs = malloc(sizeof (*segs) * (num_segment));
		if (segs == NULL) {
			free(sects);
			return (FRU_FAILURE);
		}

		acc_err = fru_get_segments(sects[cnt].handle, segs,
		    num_segment, NULL);
		if (acc_err == -1) {
			free(sects);
			free(segs);
			return (map_errno(errno));
		}

		for (each_seg = 0; each_seg < num_segment; each_seg++) {
			if (segs[each_seg].handle == node) {
				segs[each_seg].name[FRU_SEGNAMELEN] = '\0';
				*name = strdup(segs[each_seg].name);
				free(sects);
				free(segs);
				return (FRU_SUCCESS);
			}
		}
		free(segs);
	}

	return (FRU_FAILURE);
}


/* ARGSUSED */
static fru_errno_t
frt_add_tag_to_seg(fru_treehdl_t handle, const char *seg_name,
    fru_tag_t tag, uint8_t *data, size_t data_len)
{
	/* NOT SUPPORTED */
	return (FRU_NOTSUP);
}


/* ARGSUSED */
static fru_errno_t
frt_get_tag_list(fru_treehdl_t handle, const char *seg_name,
    fru_tag_t **tags, int *number)
{
	/* NOT SUPPORTED */
	return (FRU_NOTSUP);
}


/* ARGSUSED */
static fru_errno_t
frt_get_tag_data(fru_treehdl_t handle, const char *seg_name, fru_tag_t tag,
    int instance, uint8_t **data, size_t *data_len)
{
	/* NOT SUPPORTED */
	return (FRU_NOTSUP);
}


/* ARGSUSED */
static fru_errno_t
frt_set_tag_data(fru_treehdl_t handle, const char *seg_name, fru_tag_t tag,
    int instance, uint8_t *data, size_t data_len)
{
	/* NOT SUPPORTED */
	return (FRU_NOTSUP);
}


/* ARGSUSED */
static fru_errno_t
frt_delete_tag(fru_treehdl_t handle, const char *seg_name, fru_tag_t tag,
    int instance)
{
	/* NOT SUPPORTED */
	return (FRU_NOTSUP);
}


static fru_errno_t
frt_for_each_packet(fru_seghdl_t node, int (*function)(fru_tag_t *tag,
    uint8_t *payload, size_t length, void *args), void *args)
{
	int rc_num;
	int status;
	char *rc_data;
	int i;
	packet_t *packets = NULL;
	segment_list_t *tmp_list;
	fru_segdesc_t *descriptor;

	tmp_list = g_raw->segs;

	/* num of packet */
	rc_num = fru_get_num_packets(node, NULL);
	if (rc_num == -1) {
		return (map_errno(errno));
	} else if (rc_num == 0) {
		return (FRU_SUCCESS);
	}
	while (tmp_list) {
		if (node == tmp_list->segment->handle) {
			break;
		}
		tmp_list = tmp_list->next;
	}
	if (tmp_list) {
		descriptor = (fru_segdesc_t *)&tmp_list->segment->descriptor;
		if (descriptor->field.opaque) {
			return (FRU_SUCCESS);
		}

		if (descriptor->field.encrypted && (encrypt_func == NULL)) {
			return (FRU_SUCCESS);
		}
	}

	packets = malloc(sizeof (*packets) * (rc_num));
	if (packets == NULL) {
		return (FRU_FAILURE);
	}
	/* get all packets */
	if (fru_get_packets(node, packets, rc_num, NULL) == -1) {
		free(packets);
		return (map_errno(errno));
	}

	/* number of tags */
	for (i = 0; i < rc_num; i++) {
		size_t rc_len =
		    get_payload_length((fru_tag_t *)&packets[i].tag);

		rc_data = malloc(sizeof (*rc_data) * (rc_len));
		if (rc_data == NULL) {
			free(packets);
			return (FRU_FAILURE);
		}
		/* get the payload data */
		(void) fru_get_payload(packets[i].handle, (void *)rc_data,
		    rc_len, NULL);

		if (tmp_list) {
			descriptor =
			    (fru_segdesc_t *)&tmp_list->segment->descriptor;

			if ((descriptor->field.encrypted) &&
			    ((status = encrypt_func(FRU_DECRYPT,
			    (void *)rc_data, rc_len))
			    != FRU_SUCCESS)) {
				return (status);
			}
		}
		/* print packet */
		if ((status = function((fru_tag_t *)&packets[i].tag,
		    (uint8_t *)rc_data, rc_len, args)) != FRU_SUCCESS) {
			free(rc_data);
			free(packets);
			return (status);
		}
		free(rc_data);
	}
	return (FRU_SUCCESS);

}


/* object for libfru to link to */
fru_datasource_t data_source =
{
	LIBFRU_DS_VER,
	frt_initialize,
	frt_shutdown,
	frt_get_root,
	frt_get_child,
	frt_get_peer,
	frt_get_parent,
	frt_get_name_from_hdl,
	frt_get_node_type,
	frt_get_seg_list,
	frt_get_seg_def,
	frt_add_seg,
	frt_delete_seg,
	frt_for_each_segment,
	frt_get_segment_name,
	frt_add_tag_to_seg,
	frt_get_tag_list,
	frt_get_tag_data,
	frt_set_tag_data,
	frt_delete_tag,
	frt_for_each_packet
};
