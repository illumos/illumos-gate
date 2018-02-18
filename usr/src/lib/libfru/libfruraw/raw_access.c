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
#include <stdlib.h>
#include <alloca.h>
#include <sys/byteorder.h>
#include "fru_access_impl.h"
#include "fruraw.h"

#pragma init(initialize_raw_access)

static hash_obj_t	*hash_table[TABLE_SIZE];
extern raw_list_t 	*g_raw;

static void
initialize_raw_access(void)
{
	int	count;

	for (count = 0; count < TABLE_SIZE; count++) {
		hash_table[count] = NULL;
	}
}


static hash_obj_t *
lookup_handle_object(handle_t	handle, int object_type)
{
	handle_t index_to_hash;
	hash_obj_t *first_hash_obj;
	hash_obj_t *next_hash_obj;

	index_to_hash = (handle % TABLE_SIZE);

	first_hash_obj = hash_table[index_to_hash];
	for (next_hash_obj = first_hash_obj; next_hash_obj != NULL;
	    next_hash_obj = next_hash_obj->next) {
		if ((handle == next_hash_obj->obj_hdl) &&
		    (object_type == next_hash_obj->object_type)) {
			return (next_hash_obj);
		}
	}
	return (NULL);
}


static void
add_hashobject_to_hashtable(hash_obj_t *hash_obj)
{
	handle_t index_to_hash;
	static	uint64_t handle_count = 0;

	hash_obj->obj_hdl = ++handle_count;	/* store the handle */

	/* where to add ? */
	index_to_hash = ((hash_obj->obj_hdl) % TABLE_SIZE);

	hash_obj->next = hash_table[index_to_hash];
	hash_table[index_to_hash] = hash_obj;	/* hash obj. added */

	if (hash_obj->next != NULL) {
		hash_obj->next->prev = hash_obj;
	}
}


static hash_obj_t *
create_container_hash_object(void)
{
	hash_obj_t *hash_obj;
	container_obj_t *cont_obj;

	cont_obj = malloc(sizeof (container_obj_t));
	if (cont_obj == NULL) {
		return (NULL);
	}

	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		free(cont_obj);
		return (NULL);
	}

	cont_obj->sec_obj_list = NULL;

	hash_obj->object_type = CONTAINER_TYPE;
	hash_obj->u.cont_obj = cont_obj;
	hash_obj->next = NULL;
	hash_obj->prev = NULL;

	return (hash_obj);
}


static hash_obj_t *
create_section_hash_object(void)
{
	hash_obj_t *hash_obj;
	section_obj_t *sec_obj;

	sec_obj	= malloc(sizeof (section_obj_t));
	if (sec_obj == NULL) {
		return (NULL);
	}

	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		free(sec_obj);
		return (NULL);
	}

	sec_obj->next = NULL;
	sec_obj->seg_obj_list = NULL;

	hash_obj->u.sec_obj = sec_obj;
	hash_obj->object_type = SECTION_TYPE;
	hash_obj->next = NULL;
	hash_obj->prev = NULL;

	return (hash_obj);
}


static hash_obj_t *
create_segment_hash_object(void)
{
	hash_obj_t *hash_obj;
	segment_obj_t *seg_obj;

	seg_obj	= malloc(sizeof (segment_obj_t));
	if (seg_obj == NULL) {
		return (NULL);
	}

	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		free(seg_obj);
		return (NULL);
	}

	seg_obj->next = NULL;
	seg_obj->pkt_obj_list = NULL;

	hash_obj->object_type = SEGMENT_TYPE;
	hash_obj->u.seg_obj = seg_obj;
	hash_obj->next = NULL;
	hash_obj->prev = NULL;

	return (hash_obj);
}


static hash_obj_t *
create_packet_hash_object(void)
{
	hash_obj_t *hash_obj;
	packet_obj_t *pkt_obj;

	pkt_obj	= malloc(sizeof (packet_obj_t));
	if (pkt_obj == NULL) {
		return (NULL);
	}

	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		free(pkt_obj);
		return (NULL);
	}

	pkt_obj->next = NULL;

	hash_obj->object_type = PACKET_TYPE;
	hash_obj->u.pkt_obj = pkt_obj;
	hash_obj->next = NULL;
	hash_obj->prev = NULL;

	return (hash_obj);
}



static hash_obj_t *
get_container_hash_object(int	object_type, handle_t	handle)
{
	hash_obj_t	*hash_obj;

	switch (object_type) {
	case CONTAINER_TYPE:
		break;
	case SECTION_TYPE:
		hash_obj = lookup_handle_object(handle, CONTAINER_TYPE);
		if (hash_obj == NULL) {
			return (NULL);
		}
		break;
	case SEGMENT_TYPE:
		hash_obj = lookup_handle_object(handle, SECTION_TYPE);
		if (hash_obj == NULL) {
			return (NULL);
		}
		hash_obj = lookup_handle_object(hash_obj->u.sec_obj->cont_hdl,
		    CONTAINER_TYPE);
		break;
	case PACKET_TYPE:
		break;
	default:
		return (NULL);
	}

	return (hash_obj);
}


static void
add_to_pkt_object_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t *next_hash;

	/* add the packet object in the end of list */
	child_obj->u.pkt_obj->segment_hdl = parent_obj->obj_hdl;

	if (parent_obj->u.seg_obj->pkt_obj_list == NULL) {
		parent_obj->u.seg_obj->pkt_obj_list = child_obj;
		return;
	}

	for (next_hash = parent_obj->u.seg_obj->pkt_obj_list;
	    next_hash->u.pkt_obj->next != NULL;
	    next_hash = next_hash->u.pkt_obj->next) {
		;
	}

	next_hash->u.pkt_obj->next = child_obj;
}


static void
free_pkt_object_list(hash_obj_t	*hash_obj)
{
	hash_obj_t *next_obj;
	hash_obj_t *free_obj;

	next_obj = hash_obj->u.seg_obj->pkt_obj_list;
	while (next_obj != NULL) {
		free_obj = next_obj;
		next_obj = next_obj->u.pkt_obj->next;
		/* if prev is NULL it's the first object in the list */
		if (free_obj->prev == NULL) {
			hash_table[(free_obj->obj_hdl % TABLE_SIZE)] =
			    free_obj->next;
			if (free_obj->next != NULL) {
				free_obj->next->prev = free_obj->prev;
			}
		} else {
			free_obj->prev->next = free_obj->next;
			if (free_obj->next != NULL) {
				free_obj->next->prev = free_obj->prev;
			}
		}

		free(free_obj->u.pkt_obj->payload);
		free(free_obj->u.pkt_obj);
		free(free_obj);
	}

	hash_obj->u.seg_obj->pkt_obj_list = NULL;
}


static void
free_segment_hash(handle_t handle, hash_obj_t *sec_hash)
{
	hash_obj_t *seg_hash;
	hash_obj_t *next_hash;

	seg_hash = sec_hash->u.sec_obj->seg_obj_list;
	if (seg_hash == NULL) {
		return;
	}

	if (seg_hash->obj_hdl == handle) {
		sec_hash->u.sec_obj->seg_obj_list = seg_hash->u.seg_obj->next;
	} else {
		while (seg_hash->obj_hdl != handle) {
			next_hash = seg_hash;
			seg_hash = seg_hash->u.seg_obj->next;
			if (seg_hash == NULL) {
				return;
			}
		}
		next_hash->u.seg_obj->next = seg_hash->u.seg_obj->next;
	}

	if (seg_hash->prev == NULL) {
		hash_table[(seg_hash->obj_hdl % TABLE_SIZE)] = seg_hash->next;
		if (seg_hash->next != NULL) {
			seg_hash->next->prev = NULL;
		}
	} else {
		seg_hash->prev->next = seg_hash->next;
		if (seg_hash->next != NULL) {
			seg_hash->next->prev = seg_hash->prev;
		}
	}

	free_pkt_object_list(seg_hash);
	free(seg_hash->u.seg_obj);
	free(seg_hash);
}



static void
add_to_sec_object_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t *next_hash;

	child_obj->u.sec_obj->cont_hdl = parent_obj->obj_hdl;
	if (parent_obj->u.cont_obj->sec_obj_list == NULL) {
		parent_obj->u.cont_obj->sec_obj_list = child_obj;
		return;
	}

	for (next_hash = parent_obj->u.cont_obj->sec_obj_list;
	    next_hash->u.sec_obj->next != NULL;
	    next_hash = next_hash->u.sec_obj->next) {
		;
	}

	next_hash->u.sec_obj->next = child_obj;
}


static void
add_to_seg_object_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t *next_hash;

	child_obj->u.seg_obj->section_hdl = parent_obj->obj_hdl;
	if (parent_obj->u.sec_obj->seg_obj_list == NULL) {
		parent_obj->u.sec_obj->seg_obj_list = child_obj;
		return;
	}

	for (next_hash = parent_obj->u.sec_obj->seg_obj_list;
	    next_hash->u.seg_obj->next != NULL;
	    next_hash = next_hash->u.seg_obj->next) {
		;
	}

	next_hash->u.seg_obj->next = child_obj;
}


static char *
tokenizer(char *buf, char *separator, char **nextBuf, char *matched)
{
	int i = 0;
	int j = 0;

	for (i = 0; buf[i] != '\0'; i++) {
		for (j = 0; j < strlen(separator); j++) {
			if (buf[i] == separator[j]) {
				buf[i] = '\0';
				*nextBuf = &(buf[i+1]);
				*matched = separator[j];
				return (buf);
			}
		}
	}

	*nextBuf = buf;
	*matched = '\0';
	return (NULL);
}


static void
copy_segment_layout(segment_t *seghdr, void *layout)
{
	segment_layout_t *seg_layout;

	seg_layout = (segment_layout_t *)layout;
	(void) memcpy(seghdr->name, &seg_layout->name, SEG_NAME_LEN);
	seghdr->descriptor = GET_SEGMENT_DESCRIPTOR;
	seghdr->offset = BE_16(seg_layout->offset);
	seghdr->length = BE_16(seg_layout->length);
}


static int
get_container_info(const char *def_file, const char *cont_desc_str,
    container_info_t *cont_info)
{
	char *item;
	char *token;
	char *field;
	char matched;
	char buf[1024];
	int foundIt = 0;
	FILE *file = fopen(def_file, "r");

	if (file == NULL)
		return (-1);

	cont_info->num_sections = 0;

	while (fgets(buf, sizeof (buf), file) != NULL) {
		/* ignore all comments */
		token = tokenizer(buf, "#", &field, &matched);
		/* find the names */
		token = tokenizer(buf, ":", &field, &matched);
		if (token != NULL) {
			token = tokenizer(token, "|", &item, &matched);
			while (token != NULL) {
				if (strcmp(token, cont_desc_str) == 0) {
					foundIt = 1;
					goto found;
				}
				token = tokenizer(item, "|", &item, &matched);
			}
			/* check the last remaining item */
			if ((item != NULL) &&
			    (strcmp(item, cont_desc_str) == 0)) {
				foundIt = 1;
				goto found;
			}
		}
	}

found :
	if (foundIt == 1) {
		token = tokenizer(field, ":", &field, &matched);
		if (token == NULL) {
			(void) fclose(file);
			return (-1);
		}
		cont_info->header_ver = (headerrev_t)atoi(token);

		token = tokenizer(field, ":\n", &field, &matched);
		while (token != NULL) {
			token = tokenizer(token, ",", &item, &matched);
			if (token == NULL) {
				(void) fclose(file);
				return (-1);
			}
			if (atoi(token) == 1) {
				cont_info->section_info[cont_info->
				    num_sections].description.field.read_only
				    = 1;
			} else if (atoi(token) == 0) {
				cont_info->section_info[cont_info->
				    num_sections].description.field.read_only
				    = 0;
			} else {
				(void) fclose(file);
				return (-1);
			}

			token = tokenizer(item, ",", &item, &matched);
			if (token == NULL) {
				(void) fclose(file);
				return (-1);
			}

			cont_info->section_info[cont_info->
			    num_sections].address = atoi(token);
			if (item == NULL) {
				(void) fclose(file);
				return (-1);
			}
			cont_info->section_info[cont_info->num_sections].size =
			    atoi(item);
			(cont_info->num_sections)++;

			token = tokenizer(field, ":\n ", &field, &matched);
		}
	}
	(void) fclose(file);

	return (0);
}


/* ARGSUSED */
int
fru_get_segments(section_hdl_t section, segment_t *segment, int maxseg,
    door_cred_t *cred)
{
	int count;
	hash_obj_t *sec_object;
	hash_obj_t *seg_object;
	section_obj_t *sec_obj;

	sec_object = lookup_handle_object(section, SECTION_TYPE);
	if (sec_object == NULL) {
		return (-1);
	}

	sec_obj	= sec_object->u.sec_obj;
	if (sec_obj == NULL) {
		return (-1);
	}

	if (sec_obj->num_of_segment > maxseg) {
		return (-1);
	}

	seg_object = sec_object->u.sec_obj->seg_obj_list;
	if (seg_object == NULL) {
		return (-1);
	}

	for (count = 0; count < sec_obj->num_of_segment; count++) {

		/* populate segment_t */
		segment->handle = seg_object->obj_hdl;
		(void) memcpy(segment->name,
		    seg_object->u.seg_obj->segment.name, SEG_NAME_LEN);
		segment->descriptor = seg_object->u.seg_obj->segment.descriptor;

		segment->offset	= seg_object->u.seg_obj->segment.offset;
		segment->length	= seg_object->u.seg_obj->segment.length;
		seg_object = seg_object->u.seg_obj->next;
		segment++;
	}
	return (0);
}


static int
raw_memcpy(void *buffer, raw_list_t *rawlist, int offset, int size)
{
	if (offset + size > rawlist->size) {
		size = rawlist->size - offset;
	}

	(void) memcpy(buffer, &rawlist->raw[offset], size);

	return (size);
}


static int
verify_header_crc8(headerrev_t head_ver, unsigned char *bytes, int length)
{
	int crc_offset = 0;
	unsigned char orig_crc8 = 0;
	unsigned char calc_crc8 = 0;

	switch (head_ver) {
		case SECTION_HDR_VER:
			crc_offset = 4;
			break;
		default:
			errno = EINVAL;
			return (0);
	}

	orig_crc8 = bytes[crc_offset];
	bytes[crc_offset] = 0x00; /* clear for calc */
	calc_crc8 = compute_crc8(bytes, length);
	bytes[crc_offset] = orig_crc8; /* restore */

	return (orig_crc8 == calc_crc8);
}


static int
get_section(raw_list_t *rawlist, hash_obj_t *sec_hash, section_t *section)
{
	int retval;
	int size;
	int count;
	uint16_t hdrver;
	hash_obj_t *seg_hash;
	unsigned char *buffer;
	section_obj_t *sec_obj;
	section_layout_t sec_hdr;
	segment_layout_t *seg_hdr;
	segment_layout_t *seg_buf;

	sec_obj	= sec_hash->u.sec_obj;
	if (sec_obj == NULL) {
		return (-1);
	}

	/* populate section_t */
	section->handle = sec_hash->obj_hdl;
	section->offset = sec_obj->section.offset;
	section->length = sec_obj->section.length;
	section->protection = sec_obj->section.protection;
	section->version = sec_obj->section.version;

	/* read section header layout */
	retval = raw_memcpy(&sec_hdr, rawlist, sec_obj->section.offset,
	    sizeof (sec_hdr));

	if (retval != sizeof (sec_hdr)) {
		return (-1);
	}


	hdrver = GET_SECTION_HDR_VERSION;

	if ((sec_hdr.headertag != SECTION_HDR_TAG) &&
	    (hdrver != section->version)) {
		return (-1);
	}

	/* size = section layout + total sizeof segment header */
	size = sizeof (sec_hdr) + ((sec_hdr.segmentcount)
	    * sizeof (segment_layout_t));

	buffer = alloca(size);
	if (buffer == NULL) {
		return (-1);
	}

	/* segment header buffer */
	seg_buf = alloca(size - sizeof (sec_hdr));
	if (seg_buf == NULL) {
		return (-1);
	}

	/* read segment header */
	retval = raw_memcpy(seg_buf, rawlist,
	    sec_obj->section.offset + sizeof (sec_hdr),
	    size - sizeof (sec_hdr));

	if (retval != (size - sizeof (sec_hdr))) {
		return (-1);
	}

	/* copy section header layout */
	(void) memcpy(buffer, &sec_hdr, sizeof (sec_hdr));

	/* copy segment header layout */
	(void) memcpy(buffer + sizeof (sec_hdr), seg_buf, size -
	    sizeof (sec_hdr));

	/* verify crc8 */
	retval = verify_header_crc8(hdrver, buffer, size);
	if (retval != TRUE) {
		return (-1);
	}

	section->version = hdrver;
	sec_obj->section.version = hdrver;

	seg_hdr	= (segment_layout_t *)seg_buf;

	/* bug fix for frutool */
	if (sec_hash->u.sec_obj->seg_obj_list != NULL) {
		return (0);
	} else {
		sec_obj->num_of_segment = 0;
	}
	for (count = 0; count < sec_hdr.segmentcount; count++, seg_hdr++) {

		seg_hash = create_segment_hash_object();
		if (seg_hash == NULL) {
			return (-1);
		}
		add_hashobject_to_hashtable(seg_hash);
		copy_segment_layout(&seg_hash->u.seg_obj->segment, seg_hdr);
		add_to_seg_object_list(sec_hash, seg_hash);
		sec_obj->num_of_segment++;
	}
	return (0);
}

/* ARGSUSED */
int
fru_get_sections(container_hdl_t container, section_t *section, int maxsec,
    door_cred_t *cred)
{
	int count;
	int num_sec = 0;
	hash_obj_t *cont_object;
	hash_obj_t *sec_hash;

	cont_object = lookup_handle_object(container, CONTAINER_TYPE);
	if (cont_object == NULL) {
		return (-1);
	}

	if (cont_object->u.cont_obj->num_of_section > maxsec) {
		return (-1);
	}

	sec_hash = cont_object->u.cont_obj->sec_obj_list;
	if (sec_hash == NULL) {
		return (-1);
	}

	for (count = 0; count < cont_object->u.cont_obj->num_of_section;
	    count++) {
		section->version = -1;
		/* populate section_t */
		if (get_section(g_raw, sec_hash, section) == 0) {
			section++;
			num_sec++;
		}
		sec_hash = sec_hash->u.sec_obj->next;
	}
	return (num_sec);
}


static uint32_t
get_checksum_crc(hash_obj_t *seg_hash, int data_size)
{
	int protection;
	int offset = 0;
	uint32_t crc;
	hash_obj_t *sec_hash;
	hash_obj_t *pkt_hash;
	unsigned char *buffer;

	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
	    SECTION_TYPE);
	if (sec_hash == NULL) {
		return ((uint32_t)-1);
	}

	buffer = alloca(data_size);
	if (buffer == NULL) {
		return ((uint32_t)-1);
	}

	/* traverse the packet object list for all the tags and payload */
	for (pkt_hash = seg_hash->u.seg_obj->pkt_obj_list; pkt_hash != NULL;
	    pkt_hash = pkt_hash->u.pkt_obj->next) {
		(void) memcpy(buffer + offset, &pkt_hash->u.pkt_obj->tag,
		    pkt_hash->u.pkt_obj->tag_size);
		offset += pkt_hash->u.pkt_obj->tag_size;
		(void) memcpy(buffer + offset, pkt_hash->u.pkt_obj->payload,
		    pkt_hash->u.pkt_obj->paylen);
		offset += pkt_hash->u.pkt_obj->paylen;
	}

	protection = sec_hash->u.sec_obj->section.protection;

	if (protection == READ_ONLY_SECTION) { /* read-only section */
		crc = compute_crc32(buffer, data_size);
	} else {		/* read/write section */
		crc = compute_checksum32(buffer, data_size);
	}
	return (crc);	/* computed crc */
}


static int
get_packet(raw_list_t *rawlist, void *buffer, int size, int offset)
{
	int retval;

	retval = raw_memcpy(buffer, rawlist, offset, size);

	if (retval != -1) {
		return (0);
	}
	return (-1);
}


static int
get_packets(hash_obj_t *seg_hash, raw_list_t *rawlist, int offset, int length)
{
	int tag_size;
	int paylen;
	int retval;
	int seg_limit = 0;
	int pktcnt = 0;
	char *data;
	uint32_t crc;
	uint32_t origcrc;
	fru_tag_t tag;
	hash_obj_t *pkt_hash_obj;
	hash_obj_t *sec_hash;
	fru_segdesc_t *segdesc;
	fru_tagtype_t tagtype;
	char *ignore_flag;

	retval = get_packet(rawlist, &tag, sizeof (fru_tag_t), offset);
	if (retval == -1) {
		return (-1);
	}

	/* section hash object */
	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
	    SECTION_TYPE);

	if (sec_hash == NULL) {
		return (-1);
	}

	seg_hash->u.seg_obj->trailer_offset = offset;

	data = (char *)&tag;
	while (data[0] != SEG_TRAILER_TAG) {
		tagtype	= get_tag_type(&tag); /* verify tag type */
		if (tagtype == -1) {
			return (-1);
		}

		tag_size = get_tag_size(tagtype);
		if (tag_size == -1) {
			return (-1);
		}

		seg_limit += tag_size;
		if (seg_limit > length) {
			return (-1);
		}

		paylen = get_payload_length((void *)&tag);
		if (paylen == -1) {
			return (-1);
		}

		seg_limit += paylen;
		if (seg_limit > length) {
			return (-1);
		}
		if ((offset + tag_size + paylen) >
		    (sec_hash->u.sec_obj->section.offset +
		    sec_hash->u.sec_obj->section.length)) {
			return (-1);
		}

		pkt_hash_obj = create_packet_hash_object();
		if (pkt_hash_obj == NULL) {
			return (-1);
		}

		pkt_hash_obj->u.pkt_obj->payload = malloc(paylen);
		if (pkt_hash_obj->u.pkt_obj->payload == NULL) {
			free(pkt_hash_obj);
			return (-1);
		}

		offset += tag_size;

		retval = raw_memcpy(pkt_hash_obj->u.pkt_obj->payload, rawlist,
		    offset, paylen);

		if (retval != paylen) {
			free(pkt_hash_obj->u.pkt_obj->payload);
			free(pkt_hash_obj);
			return (-1);
		}

		/* don't change this */
		pkt_hash_obj->u.pkt_obj->tag.raw_data = 0;
		(void) memcpy(&pkt_hash_obj->u.pkt_obj->tag, &tag, tag_size);
		pkt_hash_obj->u.pkt_obj->paylen = paylen;
		pkt_hash_obj->u.pkt_obj->tag_size = tag_size;
		pkt_hash_obj->u.pkt_obj->payload_offset = offset;

		offset += paylen;

		add_hashobject_to_hashtable(pkt_hash_obj);
		add_to_pkt_object_list(seg_hash, pkt_hash_obj);

		pktcnt++;

		retval = get_packet(rawlist, &tag, sizeof (fru_tag_t),
		    offset);
		if (retval == -1) {
			return (retval);
		}

		data = (char *)&tag;
	}

	segdesc	= (fru_segdesc_t *)&seg_hash->u.seg_obj->segment.descriptor;

	seg_hash->u.seg_obj->trailer_offset = offset;

	if (!segdesc->field.ignore_checksum)  {
		crc = get_checksum_crc(seg_hash, seg_limit);
		offset = seg_hash->u.seg_obj->segment.offset;

		retval = raw_memcpy(&origcrc, rawlist, offset + seg_limit + 1,
		    sizeof (origcrc));

		ignore_flag = getenv(IGNORE_CHECK);
		if (ignore_flag != NULL) {
			return (pktcnt);
		}

		if (retval != sizeof (origcrc)) {
			return (-1);
		}

		origcrc = BE_32(origcrc);
		if (origcrc != crc) {
			seg_hash->u.seg_obj->trailer_offset = offset;
			return (-1);
		}
	}

	return (pktcnt);
}

/* ARGSUSED */
int
fru_get_num_sections(container_hdl_t container, door_cred_t *cred)
{
	hash_obj_t *hash_object;

	hash_object = lookup_handle_object(container, CONTAINER_TYPE);
	if (hash_object == NULL) {
		return (-1);
	}

	return (hash_object->u.cont_obj->num_of_section);
}

/* ARGSUSED */
int
fru_get_num_segments(section_hdl_t section, door_cred_t *cred)
{
	hash_obj_t *sec_object;
	section_obj_t *sec_obj;

	sec_object = lookup_handle_object(section, SECTION_TYPE);
	if (sec_object == NULL) {
		return (-1);
	}

	sec_obj	= sec_object->u.sec_obj;
	if (sec_obj == NULL) {
		return (-1);
	}

	return (sec_obj->num_of_segment);
}

/* ARGSUSED */
int
fru_get_num_packets(segment_hdl_t segment, door_cred_t *cred)
{
	int pktcnt;
	int length;
	uint16_t offset;
	hash_obj_t *cont_hash_obj;
	hash_obj_t *seg_hash;
	hash_obj_t *sec_hash;
	fru_segdesc_t *segdesc;
	segment_obj_t *segment_object;

	seg_hash = lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	segment_object = seg_hash->u.seg_obj;
	if (segment_object == NULL) {
		return (-1);
	}

	segdesc = (fru_segdesc_t *)&segment_object->segment.descriptor;
	if (segdesc->field.opaque) {
		return (0);
	}

	offset = segment_object->segment.offset;
	length = segment_object->segment.length;

	cont_hash_obj = get_container_hash_object(SEGMENT_TYPE,
	    segment_object->section_hdl);

	if (cont_hash_obj == NULL) {
		return (-1);
	}

	if (seg_hash->u.seg_obj->pkt_obj_list != NULL) {
		return (segment_object->num_of_packets);
	}
	/* section hash object */
	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
	    SECTION_TYPE);
	if (sec_hash == NULL) {
		return (-1);
	}

	/* valid segment header b'cos crc8 already validated */
	if (offset < sec_hash->u.sec_obj->section.offset) {
		return (-1);
	}

	segment_object->num_of_packets = 0;

	pktcnt = get_packets(seg_hash, g_raw, offset, length);
	if (pktcnt == -1) {
		free_pkt_object_list(seg_hash);
		seg_hash->u.seg_obj->pkt_obj_list = NULL;
	}

	segment_object->num_of_packets = pktcnt;

	return (segment_object->num_of_packets);
}

/* ARGSUSED */
int
fru_get_packets(segment_hdl_t segment, packet_t *packet, int maxpackets,
    door_cred_t *cred)
{
	int count;
	hash_obj_t *seg_hash_obj;
	hash_obj_t *pkt_hash_obj;

	/* segment hash object */
	seg_hash_obj = lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash_obj == NULL) {
		return (-1);
	}

	if (seg_hash_obj->u.seg_obj->num_of_packets != maxpackets) {
		return (-1);
	}

	pkt_hash_obj = seg_hash_obj->u.seg_obj->pkt_obj_list;
	if (pkt_hash_obj == NULL) {
		return (-1);
	}

	for (count = 0; count < maxpackets; count++, packet++) {
		packet->handle	= pkt_hash_obj->obj_hdl;
		packet->tag = 0;
		(void) memcpy(&packet->tag, &pkt_hash_obj->u.pkt_obj->tag,
		    pkt_hash_obj->u.pkt_obj->tag_size);
		pkt_hash_obj = pkt_hash_obj->u.pkt_obj->next;
	}

	return (0);
}

/* ARGSUSED */
ssize_t
fru_get_payload(packet_hdl_t packet, void *buffer, size_t nbytes,
    door_cred_t *cred)
{
	hash_obj_t *packet_hash_obj;

	/* packet hash object */
	packet_hash_obj	= lookup_handle_object(packet, PACKET_TYPE);
	if (packet_hash_obj == NULL) {
		return (-1);
	}

	/* verify payload length */
	if (nbytes != packet_hash_obj->u.pkt_obj->paylen) {
		return (-1);
	}

	(void) memcpy(buffer, packet_hash_obj->u.pkt_obj->payload, nbytes);
	return (nbytes);
}


container_hdl_t
open_raw_data(raw_list_t *node)
{
	char *cont_conf_file = NULL;
	hash_obj_t *cont_hash_obj;
	hash_obj_t *sec_hash_obj;
	container_info_t cont_info;
	int retval;
	int count;

	cont_hash_obj = create_container_hash_object();
	if (cont_hash_obj == NULL) {
		return (NULL);
	}

	add_hashobject_to_hashtable(cont_hash_obj);

	(void) strncpy(cont_hash_obj->u.cont_obj->device_pathname, "unknown",
	    sizeof (cont_hash_obj->u.cont_obj->device_pathname));

	cont_conf_file = getenv(FRU_CONT_CONF_ENV_VAR);
	if (cont_conf_file == NULL) {
		cont_conf_file = FRU_CONT_CONF_SPARC;
		retval = get_container_info(cont_conf_file, node->cont_type,
		    &cont_info);
		if (retval < 0) {
			cont_conf_file = FRU_CONT_CONF_X86;
			retval = get_container_info(cont_conf_file,
			    node->cont_type, &cont_info);
		}
	} else {
		retval = get_container_info(cont_conf_file, node->cont_type,
		    &cont_info);
	}

	if (retval < 0) {
		return (NULL);
	}

	cont_hash_obj->u.cont_obj->num_of_section = cont_info.num_sections;
	cont_hash_obj->u.cont_obj->sec_obj_list = NULL;

	for (count = 0; count < cont_info.num_sections; count++) {
		sec_hash_obj = create_section_hash_object();
		if (sec_hash_obj == NULL) {
			return (NULL);
		}

		add_hashobject_to_hashtable(sec_hash_obj);

		sec_hash_obj->u.sec_obj->section.offset =
		    cont_info.section_info[count].address;

		sec_hash_obj->u.sec_obj->section.protection =
		    cont_info.section_info[count].description.field.read_only;

		sec_hash_obj->u.sec_obj->section.length =
		    cont_info.section_info[count].size;
		sec_hash_obj->u.sec_obj->section.version =
		    cont_info.header_ver;

		add_to_sec_object_list(cont_hash_obj, sec_hash_obj);
	}

	return (cont_hash_obj->obj_hdl);
}


int
fru_close_container(container_hdl_t container)
{
	hash_obj_t *hash_obj;
	hash_obj_t *prev_hash;
	hash_obj_t *sec_hash_obj;
	handle_t obj_hdl;

	/* lookup for container hash object */
	hash_obj = lookup_handle_object(container, CONTAINER_TYPE);
	if (hash_obj == NULL) {
		return (0);
	}

	/* points to section object list */
	sec_hash_obj = hash_obj->u.cont_obj->sec_obj_list;

	/* traverse section object list */
	while (sec_hash_obj != NULL) {

		/* traverse segment hash object in the section */
		while (sec_hash_obj->u.sec_obj->seg_obj_list != NULL) {
			/* object handle of the segment hash object */
			obj_hdl	=
			    sec_hash_obj->u.sec_obj->seg_obj_list->obj_hdl;
			free_segment_hash(obj_hdl, sec_hash_obj);
		}

		/* going to free section hash object, relink the hash object */
		if (sec_hash_obj->prev == NULL) {
			hash_table[(sec_hash_obj->obj_hdl % TABLE_SIZE)] =
			    sec_hash_obj->next;
			if (sec_hash_obj->next != NULL) {
				sec_hash_obj->next->prev = NULL;
			}
		} else {
			sec_hash_obj->prev->next = sec_hash_obj->next;
			if (sec_hash_obj->next != NULL) {
				sec_hash_obj->next->prev = sec_hash_obj->prev;
			}
		}

		prev_hash = sec_hash_obj;
		sec_hash_obj = sec_hash_obj->u.sec_obj->next;

		free(prev_hash->u.sec_obj); /* free section hash object */
		free(prev_hash); /* free section hash */
	}

	/* free container hash object */
	if (hash_obj->prev == NULL) {
		hash_table[(hash_obj->obj_hdl % TABLE_SIZE)] =
		    hash_obj->next;
		if (hash_obj->next != NULL) {
			hash_obj->next->prev = NULL;
		}
	} else {
		hash_obj->prev->next = hash_obj->next;
		if (hash_obj->next != NULL) {
			hash_obj->next->prev = hash_obj->prev;
		}
	}

	free(hash_obj->u.cont_obj);
	free(hash_obj);

	return (0);
}
