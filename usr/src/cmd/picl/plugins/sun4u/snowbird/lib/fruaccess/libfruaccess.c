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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <picl.h>
#include <limits.h>
#include <alloca.h>
#include <stdarg.h>
#include "smc_if.h"
#include "fru_access_impl.h"

#pragma init(initialize_fruaccess)	/* .init section */

/*
 * This module translates all the frudata plugin requests into platform
 * specific commands and provides information back to frudata plugin.
 */

/*
 * precedence for format.
 * define an ENV variable (SUNW_FRUACCESS_IPMI_PRECEDENCE) to make
 * ipmi format has more precedence than sun format.
 */
static int precedence = SUN_FORMAT;	/* by default */
#define	FRUACCESS_PRECEDENCE	"SUNW_FRUACCESS_IPMI_PRECEDENCE"

extern ssize_t pread_new(int, void  *, size_t,  off_t, format_t *);
extern ssize_t pwrite_new(int, const void *, size_t, off_t, format_t *);
extern int get_manr(format_t *, payload_t *);
extern int is_fru_data_available(int, int, format_t *);
extern picl_errno_t fruaccess_platmod_init_format(uint8_t, format_t *);
extern int fruaccess_platmod_check_chassis();
extern int fruaccess_platmod_check_fru(picl_nodehdl_t parenth);

static container_hdl_t sun_fru_open_container(picl_nodehdl_t);
static int sun_fru_close_container(container_hdl_t);
static int sun_fru_get_num_sections(container_hdl_t, door_cred_t *);
static int sun_fru_get_sections(container_hdl_t, section_t *,
			int, door_cred_t *);
static int sun_fru_get_num_segments(section_hdl_t, door_cred_t *);
static int sun_fru_get_segments(section_hdl_t, segment_t *,
			int, door_cred_t *);
static int sun_fru_add_segment(section_hdl_t, segment_t *,
			section_hdl_t *, door_cred_t *);
static int sun_fru_delete_segment(segment_hdl_t, section_hdl_t *,
			door_cred_t *);
static ssize_t sun_fru_read_segment(segment_hdl_t, void *, size_t,
			door_cred_t *);
static int sun_fru_write_segment(segment_hdl_t, const void *, size_t,
			segment_hdl_t *, door_cred_t *);
static int sun_fru_get_num_packets(segment_hdl_t, door_cred_t *);
static int sun_fru_get_packets(segment_hdl_t, packet_t *,
			int, door_cred_t *);
static ssize_t sun_fru_get_payload(packet_hdl_t, void *, size_t,
			door_cred_t *);
static int sun_fru_update_payload(packet_hdl_t, const void *, size_t,
			packet_hdl_t *, door_cred_t *);
static int sun_fru_append_packet(segment_hdl_t, packet_t *,
			const void *, size_t, segment_hdl_t *,
			door_cred_t *);
static int sun_fru_delete_packet(packet_hdl_t, segment_hdl_t *, door_cred_t *);

static container_hdl_t ipmi_fru_open_container(picl_nodehdl_t);
static int ipmi_fru_close_container(container_hdl_t);
static int ipmi_fru_get_num_sections(container_hdl_t, door_cred_t *);
static int ipmi_fru_get_sections(container_hdl_t, section_t *,
			int, door_cred_t *);
static int ipmi_fru_get_num_segments(section_hdl_t, door_cred_t *);
static int ipmi_fru_get_segments(section_hdl_t, segment_t *,
			int, door_cred_t *);
static int ipmi_fru_add_segment(section_hdl_t, segment_t *,
			section_hdl_t *, door_cred_t *);
static int ipmi_fru_delete_segment(segment_hdl_t, section_hdl_t *,
			door_cred_t *);
static ssize_t ipmi_fru_read_segment(segment_hdl_t, void *, size_t,
			door_cred_t *);
static int ipmi_fru_write_segment(segment_hdl_t, const void *, size_t,
			segment_hdl_t *, door_cred_t *);
static int ipmi_fru_get_num_packets(segment_hdl_t, door_cred_t *);
static int ipmi_fru_get_packets(segment_hdl_t, packet_t *,
			int, door_cred_t *);
static ssize_t ipmi_fru_get_payload(packet_hdl_t, void *, size_t,
			door_cred_t *);
static int ipmi_fru_update_payload(packet_hdl_t, const void *, size_t,
			packet_hdl_t *, door_cred_t *);
static int ipmi_fru_append_packet(segment_hdl_t, packet_t *,
			const void *, size_t, segment_hdl_t *,
			door_cred_t *);
static int ipmi_fru_delete_packet(packet_hdl_t, segment_hdl_t *, door_cred_t *);

typedef struct {
	container_hdl_t (* open_container)(picl_nodehdl_t);
	int (* close_container)(container_hdl_t);
	int (* get_num_sections)(container_hdl_t, door_cred_t *);
	int (* get_sections)(container_hdl_t, section_t *,
			int, door_cred_t *);
	int (* get_num_segments)(section_hdl_t, door_cred_t *);
	int (* get_segments)(section_hdl_t, segment_t *,
			int, door_cred_t *);
	int (* add_segment)(section_hdl_t, segment_t *,
			section_hdl_t *, door_cred_t *);
	int (* delete_segment)(segment_hdl_t, section_hdl_t *,
			door_cred_t *);
	ssize_t (* read_segment)(segment_hdl_t, void *, size_t,
			door_cred_t *);
	int (* write_segment)(segment_hdl_t, const void *, size_t,
			segment_hdl_t *, door_cred_t *);
	int (* get_num_packets)(segment_hdl_t, door_cred_t *);
	int (* get_packets)(segment_hdl_t, packet_t *,
			int, door_cred_t *);
	ssize_t (* get_payload)(packet_hdl_t, void *, size_t,
			door_cred_t *);
	int (* update_payload)(packet_hdl_t, const void *, size_t,
			packet_hdl_t *, door_cred_t *);
	int (* append_packet)(segment_hdl_t, packet_t *,
			const void *, size_t, segment_hdl_t *,
			door_cred_t *);
	int (* delete_packet)(packet_hdl_t, segment_hdl_t *, door_cred_t *);
} fruaccess_func_ptrs_t;

static fruaccess_func_ptrs_t fruaccess_func[2] = {
		{
			ipmi_fru_open_container,
			ipmi_fru_close_container,
			ipmi_fru_get_num_sections,
			ipmi_fru_get_sections,
			ipmi_fru_get_num_segments,
			ipmi_fru_get_segments,
			ipmi_fru_add_segment,
			ipmi_fru_delete_segment,
			ipmi_fru_read_segment,
			ipmi_fru_write_segment,
			ipmi_fru_get_num_packets,
			ipmi_fru_get_packets,
			ipmi_fru_get_payload,
			ipmi_fru_update_payload,
			ipmi_fru_append_packet,
			ipmi_fru_delete_packet,
		},
		{
			sun_fru_open_container,
			sun_fru_close_container,
			sun_fru_get_num_sections,
			sun_fru_get_sections,
			sun_fru_get_num_segments,
			sun_fru_get_segments,
			sun_fru_add_segment,
			sun_fru_delete_segment,
			sun_fru_read_segment,
			sun_fru_write_segment,
			sun_fru_get_num_packets,
			sun_fru_get_packets,
			sun_fru_get_payload,
			sun_fru_update_payload,
			sun_fru_append_packet,
			sun_fru_delete_packet,
		},
	};

static int is_valid_chassis = -1;
static hash_obj_t *hash_table[TABLE_SIZE];

static void
initialize_fruaccess(void)
{
	int	count;
	for (count = 0; count < TABLE_SIZE; count++) {
		hash_table[count] = NULL;
	}

	/* check if ipmi format has precedence */
	if (getenv(FRUACCESS_PRECEDENCE)) {
		precedence = IPMI_FORMAT;
	}
}

/* called to lookup hash object for specified handle in the hash table. */
static hash_obj_t *
lookup_handle_object(handle_t	handle, int object_type)
{
	handle_t	index_to_hash;
	hash_obj_t	*first_hash_obj;
	hash_obj_t	*next_hash_obj;

	index_to_hash	= (handle % TABLE_SIZE);

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

/* called to allocate container hash object */
static hash_obj_t *
create_container_hash_object(void)
{
	hash_obj_t		*hash_obj;
	container_obj_t		*cont_obj;

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

/* called to allocate section hash object */
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

/* called to allocate segment hash object */
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

	seg_obj->next		= NULL;
	seg_obj->pkt_obj_list	= NULL;

	hash_obj->object_type	= SEGMENT_TYPE;
	hash_obj->u.seg_obj	= seg_obj;
	hash_obj->next		= NULL;
	hash_obj->prev		= NULL;

	return (hash_obj);
}

/* called to allocate packet hash object */
static hash_obj_t *
create_packet_hash_object(void)
{
	hash_obj_t		*hash_obj;
	packet_obj_t		*pkt_obj;

	pkt_obj	= malloc(sizeof (packet_obj_t));
	if (pkt_obj == NULL) {
		return (NULL);
	}

	hash_obj = malloc(sizeof (hash_obj_t));
	if (hash_obj == NULL) {
		free(pkt_obj);
		return (NULL);
	}

	pkt_obj->next		= NULL;

	hash_obj->object_type	= PACKET_TYPE;
	hash_obj->u.pkt_obj	= pkt_obj;
	hash_obj->next		= NULL;
	hash_obj->prev		= NULL;

	return (hash_obj);
}

/* called to add allocated hash object into the hash table */
static void
add_hashobject_to_hashtable(hash_obj_t *hash_obj, int object_type)
{
	handle_t		index_to_hash;
	static	uint64_t	handle_count	= 0;

	if (object_type != CONTAINER_TYPE) {
		hash_obj->obj_hdl = ++handle_count;
	}

	/* where to add ? */
	index_to_hash	= ((hash_obj->obj_hdl) % TABLE_SIZE);

	hash_obj->next	= hash_table[index_to_hash];
	hash_table[index_to_hash] = hash_obj;	/* hash obj. added */

	if (hash_obj->next != NULL) {
		hash_obj->next->prev = hash_obj;
	}
}

/* called to add section object list into the section list */
static void
add_to_sec_object_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t	*next_hash;

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

	next_hash->u.sec_obj->next	= child_obj;
}

/* called to add segment object list into segment list */
static void
add_to_seg_object_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t	*next_hash;

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

	next_hash->u.seg_obj->next	= child_obj;
}

/* called to add packet object list into packet list */
static void
add_to_pkt_object_list(hash_obj_t *parent_obj, hash_obj_t *child_obj)
{
	hash_obj_t	*next_hash;

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

/* fill the information, payload in the conatiner */
/*ARGSUSED*/
static int
initialize_ipmi_container(picl_nodehdl_t fru, hash_obj_t *cont_hash_obj)
{
	payload_t manr;
	hash_obj_t *seg_hash_obj, *sec_hash_obj, *pkt_hash_obj;
	format_t format;

	format = cont_hash_obj->u.cont_obj->format;
	/* plug to SMC driver to fetch the data */
	if (get_manr(&format, &manr) != 0) {
		return (-1);
	}

	cont_hash_obj->u.cont_obj->num_of_section =  1;
	cont_hash_obj->u.cont_obj->sec_obj_list = NULL;

	sec_hash_obj = create_section_hash_object();
	if (sec_hash_obj == NULL) {
		return (-1);
	}

	add_hashobject_to_hashtable(sec_hash_obj, SECTION_TYPE);

	/* create fake section info here */
	sec_hash_obj->u.sec_obj->num_of_segment = 1;
	sec_hash_obj->u.sec_obj->section.handle = sec_hash_obj->obj_hdl;
	sec_hash_obj->u.sec_obj->section.offset = 0;
	sec_hash_obj->u.sec_obj->section.protection = READ_ONLY_SECTION;

	sec_hash_obj->u.sec_obj->section.length = STATIC_LENGTH;
	sec_hash_obj->u.sec_obj->section.version = SECTION_HDR_VER;
	add_to_sec_object_list(cont_hash_obj, sec_hash_obj);

	seg_hash_obj = create_segment_hash_object();
	if (seg_hash_obj == NULL) {
		return (-1);
	}

	add_hashobject_to_hashtable(seg_hash_obj, SEGMENT_TYPE);

	seg_hash_obj->u.seg_obj->num_of_packets = 1;
	seg_hash_obj->u.seg_obj->segment.handle = seg_hash_obj->obj_hdl;
	(void) strncpy(seg_hash_obj->u.seg_obj->segment.name,
		SD_SEGMENT_NAME,
		sizeof (seg_hash_obj->u.seg_obj->segment.name));
	seg_hash_obj->u.seg_obj->segment.descriptor = SD_SEGMENT_DESCRIPTOR;
						/* tag + payload */
	seg_hash_obj->u.seg_obj->segment.length = MANR_SIZE +
		SEGMENT_TRAILER_LEN + SEGMENT_CHKSM_LEN;
	add_to_seg_object_list(sec_hash_obj, seg_hash_obj);

	pkt_hash_obj = create_packet_hash_object();
	if (pkt_hash_obj == NULL) {
		return (-1);
	}
	add_hashobject_to_hashtable(pkt_hash_obj, PACKET_TYPE);

	pkt_hash_obj->u.pkt_obj->payload_data = manr;
	if (mk_tag(FRU_F, 0x001, 0x0B7, &pkt_hash_obj->u.pkt_obj->tag) == 4) {
		add_to_pkt_object_list(seg_hash_obj, pkt_hash_obj);
	}
	return (0);
}

/* Look up the container_hdl in the PICL tree. */
static container_hdl_t
ipmi_fru_open_container(picl_nodehdl_t fruh)
{
	int err;
	hash_obj_t		*cont_hash_obj;

	err = ptree_get_propval_by_name(fruh, PICL_PROP_FRUDATA_AVAIL,
		NULL, NULL);
	if (err != PICL_SUCCESS) {
		return (0);
	}

	cont_hash_obj = lookup_handle_object((handle_t)fruh, CONTAINER_TYPE);
	if (cont_hash_obj == NULL) {
		return (0);
	}

	/* initialize the container */
	if (initialize_ipmi_container(fruh, cont_hash_obj) != 0) {
		return (0);
	}
	return (cont_hash_obj->obj_hdl);
}

/*ARGSUSED*/
static int
ipmi_fru_get_num_sections(container_hdl_t container, door_cred_t *cred)
{
	hash_obj_t 	*cont_hash_obj;

	cont_hash_obj = lookup_handle_object((handle_t)container,
		CONTAINER_TYPE);
	if (cont_hash_obj == NULL) {
		return (-1);
	}
	return (cont_hash_obj->u.cont_obj->num_of_section);
}

/*ARGSUSED*/
static int
ipmi_fru_get_sections(container_hdl_t container, section_t *section,
	int max_sections, door_cred_t *cred)
{
	int count;
	hash_obj_t	*cont_object;
	hash_obj_t	*sec_hash;

	cont_object = lookup_handle_object((handle_t)container,
		CONTAINER_TYPE);
	if (cont_object == NULL) {
		return (-1);
	}

	if (cont_object->u.cont_obj->num_of_section > max_sections) {
		return (-1);
	}
	sec_hash = cont_object->u.cont_obj->sec_obj_list;

	for (count = 0; count < cont_object->u.cont_obj->num_of_section &&
		sec_hash != NULL; count++, section++) {
		/* populate section_t */
		section->handle = sec_hash->u.sec_obj->section.handle;
		section->offset = sec_hash->u.sec_obj->section.offset;
		section->length = sec_hash->u.sec_obj->section.length;
		section->protection = sec_hash->u.sec_obj->section.protection;
		section->version = sec_hash->u.sec_obj->section.version;
		sec_hash = sec_hash->u.sec_obj->next;
	}
	return (count);
}

/*ARGSUSED*/
static int
ipmi_fru_get_num_segments(section_hdl_t section, door_cred_t *cred)
{
	hash_obj_t	*sec_object;

	sec_object = lookup_handle_object((handle_t)section, SECTION_TYPE);
	if (sec_object == NULL) {
		return (-1);
	}
	return (sec_object->u.sec_obj->num_of_segment);
}

/*ARGSUSED*/
static int
ipmi_fru_get_segments(section_hdl_t section, segment_t *segment,
	int max_segments, door_cred_t *cred)
{
	int count;
	hash_obj_t	*seg_hash;
	hash_obj_t	*sec_object;

	sec_object = lookup_handle_object((handle_t)section, SECTION_TYPE);
	if (sec_object == NULL) {
		return (-1);
	}

	if (sec_object->u.sec_obj->num_of_segment > max_segments) {
		return (-1);
	}

	seg_hash = sec_object->u.sec_obj->seg_obj_list;

	for (count = 0; count < sec_object->u.sec_obj->num_of_segment &&
		seg_hash != NULL; count++, segment++) {
		/* populate the segment info */
		segment->handle = seg_hash->u.seg_obj->segment.handle;
		(void) memcpy(segment->name, seg_hash->u.seg_obj->segment.name,
			SEG_NAME_LEN);
		segment->descriptor = seg_hash->u.seg_obj->segment.descriptor;
		segment->offset = seg_hash->u.seg_obj->segment.offset;
		segment->length = seg_hash->u.seg_obj->segment.length;
		seg_hash = seg_hash->u.seg_obj->next;
	}
	return (count);
}

/*ARGSUSED*/
static int
ipmi_fru_get_num_packets(segment_hdl_t segment, door_cred_t *cred)
{
	hash_obj_t	*seg_object;

	seg_object = lookup_handle_object((handle_t)segment, SEGMENT_TYPE);
	if (seg_object == NULL) {
		return (-1);
	}
	return (seg_object->u.seg_obj->num_of_packets);
}

/*ARGSUSED*/
static int
ipmi_fru_get_packets(segment_hdl_t segment, packet_t *packet,
		    int max_packets, door_cred_t *cred)
{
	int count;
	hash_obj_t	*pkt_hash;
	hash_obj_t	*seg_object;

	seg_object = lookup_handle_object((handle_t)segment, SEGMENT_TYPE);
	if (seg_object == NULL) {
		return (-1);
	}

	if (seg_object->u.seg_obj->num_of_packets > max_packets) {
		return (-1);
	}

	pkt_hash = seg_object->u.seg_obj->pkt_obj_list;

	for (count = 0; count < seg_object->u.seg_obj->num_of_packets &&
		pkt_hash != NULL; count++, packet++) {
		/* populate the segment info */
		packet->handle = pkt_hash->obj_hdl;
		(void) memcpy(&packet->tag, &pkt_hash->u.pkt_obj->tag, 4);
		pkt_hash = pkt_hash->u.pkt_obj->next;
	}

	return (count);
}

/*ARGSUSED*/
static ssize_t
ipmi_fru_read_segment(segment_hdl_t segment, void *buffer, size_t nbytes,
		door_cred_t *cred)
{
	hash_obj_t	*seg_hash;
	hash_obj_t	*pkt_hash;

	/* segment hash object */
	seg_hash = lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	if (seg_hash->u.seg_obj->segment.length < nbytes) {
		return (-1);
	}

	pkt_hash = seg_hash->u.seg_obj->pkt_obj_list;

	if (pkt_hash == NULL) {
		return (-1);
	}

	(void) memcpy(buffer, &pkt_hash->u.pkt_obj->payload_data,
		sizeof (payload_t));
	return (nbytes);
}

/*ARGSUSED*/
static ssize_t
ipmi_fru_get_payload(packet_hdl_t packet, void *buffer, size_t nbytes,
	door_cred_t *cred)
{
	hash_obj_t	*packet_hash_obj;

	/* size  = size of ManR */
	if (nbytes != MANR_SIZE) {
		return (-1);
	}

	/* packet hash object */
	packet_hash_obj	= lookup_handle_object(packet, PACKET_TYPE);
	if (packet_hash_obj == NULL) {
		return (-1);
	}

	(void) memcpy(buffer, &(packet_hash_obj->u.pkt_obj->payload_data),
		MANR_SIZE);
	return (nbytes);
}

/*ARGSUSED*/
static int
ipmi_fru_add_segment(section_hdl_t section, segment_t *segment,
    section_hdl_t *newsection, door_cred_t *cred)
{
	errno = ENOTSUP;
	return (-1);
}

/*ARGSUSED*/
static int
ipmi_fru_delete_segment(segment_hdl_t segment,
    section_hdl_t *newsection, door_cred_t *cred)
{
	errno = ENOTSUP;
	return (-1);
}


/*ARGSUSED*/
static ssize_t
ipmi_fru_write_segment(segment_hdl_t segment, const void *data,
    size_t nbytes, segment_hdl_t *newsegment, door_cred_t *cred)
{
	errno = ENOTSUP;
	return (-1);
}

/*ARGSUSED*/
static int
ipmi_fru_update_payload(packet_hdl_t packet, const void *data,
    size_t nbytes, packet_hdl_t *newpacket, door_cred_t *cred)
{
	errno = ENOTSUP;
	return (-1);
}

/*ARGSUSED*/
static int
ipmi_fru_append_packet(segment_hdl_t segment, packet_t *packet,
    const void *payload, size_t nbytes, segment_hdl_t *newsegment,
    door_cred_t *cred)
{
	errno = ENOTSUP;
	return (-1);
}

/*ARGSUSED*/
static int
ipmi_fru_delete_packet(packet_hdl_t packet,
    segment_hdl_t *newsegment, door_cred_t *cred)
{
	errno = ENOTSUP;
	return (-1);
}

static void
free_pkt_object_list(hash_obj_t	*hash_obj)
{
	hash_obj_t	*next_obj;
	hash_obj_t	*free_obj;

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

		free(free_obj->u.pkt_obj);
		free(free_obj);
	}

	hash_obj->u.seg_obj->pkt_obj_list = NULL;
}

static void
free_segment_hash(handle_t handle, hash_obj_t *sec_hash)
{
	hash_obj_t	*seg_hash;
	hash_obj_t	*next_hash;

	seg_hash	= sec_hash->u.sec_obj->seg_obj_list;
	if (seg_hash == NULL) {
		return;
	}

	if (seg_hash->obj_hdl == handle) {
		sec_hash->u.sec_obj->seg_obj_list = seg_hash->u.seg_obj->next;
	} else {
		while (seg_hash->obj_hdl != handle) {
			next_hash	= seg_hash;
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

static int
ipmi_fru_close_container(container_hdl_t container)
{
	hash_obj_t	*hash_obj;
	hash_obj_t	*prev_hash;
	hash_obj_t	*sec_hash_obj;
	handle_t	obj_hdl;

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
			hash_table[(sec_hash_obj->obj_hdl % TABLE_SIZE)]
							= sec_hash_obj->next;
			if (sec_hash_obj->next != NULL) {
				sec_hash_obj->next->prev = NULL;
			}
		} else {
			sec_hash_obj->prev->next = sec_hash_obj->next;
			if (sec_hash_obj->next != NULL) {
				sec_hash_obj->next->prev = sec_hash_obj->prev;
			}
		}

		free(sec_hash_obj->u.sec_obj); /* free section hash object */

		prev_hash = sec_hash_obj;

		sec_hash_obj = sec_hash_obj->u.sec_obj->next;

		free(prev_hash); /* free section hash */
	}

	/* free container hash object */
	if (hash_obj->prev == NULL) {
		hash_table[(sec_hash_obj->obj_hdl % TABLE_SIZE)] =
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

/* opens the binary file and returns the file descriptor */
static int
open_file()
{
	int fd;

	if ((fd = open(INPUT_FILE, O_RDWR)) == -1) {
		return (-1);
	}
	return (fd);
}

static void
copy_segment_layout(segment_t	*seghdr, void	*layout)
{
	segment_layout_t	*seg_layout;

	seg_layout	= (segment_layout_t *)layout;
	(void) memcpy(seghdr->name, &seg_layout->name, SEG_NAME_LEN);
	seghdr->descriptor = GET_SEGMENT_DESCRIPTOR;
	seghdr->offset	= seg_layout->offset;
	seghdr->length	= seg_layout->length;
}

static hash_obj_t *
get_container_hash_object(int	object_type, handle_t	handle)
{
	hash_obj_t	*hash_obj;

	switch (object_type) {
	case	CONTAINER_TYPE	:
		break;

	case	SECTION_TYPE	:
		hash_obj = lookup_handle_object(handle, CONTAINER_TYPE);
		if (hash_obj == NULL) {
			return (NULL);
		}
		break;
	case	SEGMENT_TYPE	:
		hash_obj = lookup_handle_object(handle, SECTION_TYPE);
		if (hash_obj == NULL) {
			return (NULL);
		}
		hash_obj = lookup_handle_object(hash_obj->u.sec_obj->cont_hdl,
			CONTAINER_TYPE);
		break;
	case	PACKET_TYPE	:

		hash_obj = lookup_handle_object(handle, SEGMENT_TYPE);
		if (hash_obj == NULL) {
			return (NULL);
		}
		hash_obj = lookup_handle_object(
			hash_obj->u.seg_obj->section_hdl, SECTION_TYPE);
		if (hash_obj == NULL) {
			return (NULL);
		}
		hash_obj = lookup_handle_object(hash_obj->u.sec_obj->cont_hdl,
			CONTAINER_TYPE);
		break;
	default	:
		return (NULL);
	}
	return (hash_obj);
}

static void
sort_offsettbl(int	segcnt, seg_info_t	*offset_tbl)
{
	int		cntx;
	int		cnty;
	seg_info_t	tmp;

	for (cntx = 0; cntx < segcnt+2; cntx++) {
		for (cnty = cntx+1; cnty < segcnt + 2; cnty++) {
			if (offset_tbl[cntx].offset >
					offset_tbl[cnty].offset) {
				(void) memcpy(&tmp, &offset_tbl[cnty],
					sizeof (seg_info_t));
				(void) memcpy(&offset_tbl[cnty],
					&offset_tbl[cntx],
					sizeof (seg_info_t));

				(void) memcpy(&offset_tbl[cntx], &tmp,
					sizeof (seg_info_t));
			}
		}
	}
}

/*
 * Description : move_segment_data() reads the segment data and writes it
 *      back to the new segment offset.
 */

static void
move_segment_data(void *seghdr, int newoffset, container_hdl_t contfd)
{
	int			ret;
	char			*buffer;
	segment_layout_t	*segment;
	format_t		format;
	hash_obj_t		*cont_hash;

	segment	= (segment_layout_t *)seghdr;

	buffer = alloca(segment->length);
	if (buffer == NULL) {
		return;
	}

	cont_hash = lookup_handle_object((handle_t)contfd, CONTAINER_TYPE);
	if (cont_hash == NULL) {
		return;
	}

	format = cont_hash->u.cont_obj->format;

	ret = pread_new(contfd, buffer,
		segment->length, segment->offset, &format);
	if (ret != segment->length) {
		return;
	}

	segment->offset = newoffset;

	ret = pwrite_new(contfd, buffer, segment->length, segment->offset,
		&format);
	if (ret != segment->length) {
		return;
	}
}

/*
 * Description : pack_segment_data() moves the segment data if there is
 *              a hole between two segments.
 */

static void
pack_segment_data(char *seghdr, int segcnt, container_hdl_t contfd,
	seg_info_t *offset_tbl)
{
	int	cnt;
	int	diff;
	int	newoffset;

	for (cnt = segcnt + 1; cnt > 0; cnt--) {
		if (!offset_tbl[cnt - 1].fixed) {
			if (offset_tbl[cnt].offset
				- (offset_tbl[cnt -1 ].offset
					+ offset_tbl[cnt - 1].length) > 0) {

				diff = offset_tbl[cnt].offset -
					(offset_tbl[cnt - 1].offset
					+ offset_tbl[cnt - 1].length);
				newoffset = offset_tbl[cnt - 1].offset
								+ diff;

				move_segment_data(seghdr, newoffset,
					contfd);

				offset_tbl[cnt - 1].offset = newoffset;

				sort_offsettbl(segcnt, offset_tbl);
			}
		}
	}
}

/*
 * Description : build_offset_tbl() builds the offset table by reading all the
 *              segment header. it makes two more entry into the table one for
 *              section size and another with start of the section after the
 *              segment header.
 */

static int
build_offset_tbl(void   *seghdr, int segcnt, int secsize,
						seg_info_t *offset_tbl)
{
	int			cnt;
	fru_segdesc_t		segdesc;
	segment_layout_t	*segment;

	for (cnt = 0; cnt < segcnt; cnt++) {
		segment	= (segment_layout_t *)(seghdr) + cnt;

		(void) memcpy(&segdesc, &segment->descriptor,
			sizeof (uint32_t));
		offset_tbl[cnt].segnum = cnt;
		offset_tbl[cnt].offset = segment->offset;
		offset_tbl[cnt].length = segment->length;
		offset_tbl[cnt].fixed = segdesc.field.fixed;
	}

	/* upper boundary of segment area (lower address bytes) */
	offset_tbl[cnt].segnum = -1;
	offset_tbl[cnt].offset = sizeof (section_layout_t) + ((cnt + 1)
		* sizeof (segment_layout_t));

	offset_tbl[cnt].length = 0;
	offset_tbl[cnt].fixed  = 1;
	/* lower boundary of segment area (higher address bytes) */

	offset_tbl[cnt+1].segnum = -1;
	offset_tbl[cnt+1].offset = secsize;
	offset_tbl[cnt+1].length = 0;
	offset_tbl[cnt+1].fixed = 1;
	return (0);
}

static int
hole_discovery(int bytes, int segcnt, int *totsize, seg_info_t *offset_tbl)
{
	int cnt = 0;

	*totsize = 0;
	for (cnt = segcnt + 1; cnt > 0; cnt--) {
		if (bytes <= offset_tbl[cnt].offset -
			(offset_tbl[cnt - 1].offset +
			offset_tbl[cnt - 1].length)) {
			return (offset_tbl[cnt].offset - bytes);
		}

		*totsize += offset_tbl[cnt].offset -
			(offset_tbl[cnt - 1].offset +
			offset_tbl[cnt - 1].length);
	}
	return (0);
}


/*
 * Description : segment_hdr_present() verify space for new segment header to
 *              be added.
 */

static int
segment_hdr_present(int segoffset, int size, seg_info_t *offset_tbl)
{
	if ((segoffset + size) <= offset_tbl[0].offset)
		return (0);
	else
		return (-1);
}

/*
 * Description : find_offset() is called from fru_add_segment routine to find
 *              a valid offset.
 */

static int
find_offset(char *seghdr, int segcnt, int secsize, int *sectionoffset,
		int segsize, int fix, container_hdl_t contfd)
{
	int		ret;
	int		newoffset;
	int		totsize = 0;
	seg_info_t	*offset_tbl;

	if (segcnt == 0) {
		if (!fix) {	/* if not fixed segment */
			*sectionoffset = secsize - segsize;
		}
		return (0);
	}

	/*
	 * two extra segment info structure are allocated for start of segment
	 * and other end of segment. first segment offset is first available
	 * space and length is 0. second segment offset is is segment length and
	 * offset is 0. build_offset_tbl() explains how upper boundary and lower
	 * boudary segment area are initialized in seg_info_t table.
	 */

	offset_tbl    = malloc((segcnt + 2) * sizeof (seg_info_t));
	if (offset_tbl == NULL) {
		return (-1);
	}

	/* read all the segment header to make offset table */
	ret = build_offset_tbl(seghdr, segcnt, secsize, offset_tbl);
	if (ret != 0) {
		free(offset_tbl);
		return (-1);
	}

	/* sort the table */
	sort_offsettbl(segcnt, offset_tbl);

	/* new segment header offset */
	newoffset = sizeof (section_layout_t) + segcnt *
		sizeof (segment_layout_t);

	/* do? new segment header overlap any existing data */
	ret = segment_hdr_present(newoffset, sizeof (segment_layout_t),
		offset_tbl);
	if (ret != 0) { /* make room for new segment if possible */

	/* look for hole in order to move segment data */
		if (offset_tbl[0].fixed == SEGMENT_FIXED) { /* fixed segment */
			free(offset_tbl);
			return (-1);
		}

		newoffset = hole_discovery(offset_tbl[0].length,
			segcnt, &totsize, offset_tbl);
		if (newoffset != 0) { /* found new offset */
				/* now new offset */
			offset_tbl[0].offset = newoffset;

			/* move the segment data */
			move_segment_data(seghdr, newoffset, contfd);
			/* again sort the offset table */
			sort_offsettbl(segcnt, offset_tbl);
		} else {
			/* pack the existing hole */
			if (totsize > offset_tbl[0].length) {
				pack_segment_data(seghdr, segcnt,
					contfd, offset_tbl);
			} else {
				free(offset_tbl);
				return (-1);
			}
		}
	}

	totsize = 0;
	newoffset = hole_discovery(segsize, segcnt, &totsize, offset_tbl);

	if (newoffset == 0) { /* No hole found */
		if (totsize >= segsize) {
			pack_segment_data(seghdr, segcnt, contfd,
				offset_tbl);
			newoffset = hole_discovery(segsize, segcnt,
				&totsize, offset_tbl);
			if (newoffset != 0) {
				*sectionoffset = newoffset;
				free(offset_tbl);
				return (0);
			}
		}
	} else {
		*sectionoffset = newoffset;
		free(offset_tbl);
		return (0);
	}
	free(offset_tbl);
	return (-1);
}

/*
 * Description :sun_fru_open_container() opens the container associated with
 *		a fru. it's called by data plugin module before creating
 *		container property.  it calls picltree library routine to get
 *		the device path and driver binding name for the fru to get the
 *              corresponding fru name that describe the fru layout.
 *
 * Arguments   :picl_hdl_t      fru
 *              A handle for PICL tree node of class "fru" representing the
 *              FRU with the container to open.
 *
 * Return      :
 *              On Success, a Positive integer container handle. is returned
 *              for use in subsequent fru operations;on error, 0 is returned
 *              and "errno" is set appropriately.
 */
static container_hdl_t
sun_fru_open_container(picl_nodehdl_t fruhdl)
{
	int			count;
	hash_obj_t		*cont_hash_obj;
	hash_obj_t		*sec_hash_obj;

	cont_hash_obj = lookup_handle_object((handle_t)fruhdl, CONTAINER_TYPE);
	if (cont_hash_obj == NULL) {
		return (NULL);
	}

	cont_hash_obj->u.cont_obj->num_of_section = NUM_OF_SECTIONS;
	cont_hash_obj->u.cont_obj->sec_obj_list = NULL;

	for (count = 0; count < NUM_OF_SECTIONS; count++) {
		sec_hash_obj = create_section_hash_object();
		if (sec_hash_obj == NULL) {
			return (NULL);
		}

		add_hashobject_to_hashtable(sec_hash_obj, SECTION_TYPE);

		if (count == 0) {
			sec_hash_obj->u.sec_obj->section.offset =
				DYNAMIC_OFFSET;
			sec_hash_obj->u.sec_obj->section.protection =
				WRITE_SECTION;
			sec_hash_obj->u.sec_obj->section.length =
				DYNAMIC_LENGTH;
		} else {
			sec_hash_obj->u.sec_obj->section.offset = STATIC_OFFSET;
			sec_hash_obj->u.sec_obj->section.protection =
				READ_ONLY_SECTION;
			sec_hash_obj->u.sec_obj->section.length = STATIC_LENGTH;
		}

		sec_hash_obj->u.sec_obj->section.version = SECTION_HDR_VER;

		add_to_sec_object_list(cont_hash_obj, sec_hash_obj);
	}

	return (cont_hash_obj->obj_hdl);
}

static int
verify_header_crc8(headerrev_t head_ver, unsigned char *bytes, int length)
{
	int		crc_offset = 0;
	unsigned char	orig_crc8 = 0;
	unsigned char	calc_crc8 = 0;

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

/*
 * Description	:
 *		sun_fru_get_num_sections() returns number of sections in a
 *		container. it calls get_container_index() to get the container
 *		index number in the container list.
 *
 * Arguments	:
 *		container_hdl_t	: container handle.
 *
 * Return	:
 *		int
 *		On success, returns number of sections in a container.
 *
 */
/*ARGSUSED*/
static int
sun_fru_get_num_sections(container_hdl_t container, door_cred_t *cred)
{
	hash_obj_t		*hash_object;

	hash_object	= lookup_handle_object(container, CONTAINER_TYPE);
	if (hash_object == NULL) {
		return (-1);
	}

	return (hash_object->u.cont_obj->num_of_section);
}

/*
 * called from fru_get_sections()
 */

static void
get_section(int fd, hash_obj_t *sec_hash, section_t *section)
{
	int			retval;
	int			size;
	int			count;
	uint16_t		hdrver;
	hash_obj_t		*seg_hash;
	unsigned char		*buffer;
	section_obj_t		*sec_obj;
	section_layout_t	sec_hdr;
	segment_layout_t	*seg_hdr;
	segment_layout_t	*seg_buf;
	format_t		format;
	hash_obj_t		*cont_hash;

	sec_obj	= sec_hash->u.sec_obj;
	if (sec_obj == NULL) {
		return;
	}

	/* populate section_t */
	section->handle = sec_hash->obj_hdl;
	section->offset = sec_obj->section.offset;
	section->length = sec_obj->section.length;
	section->protection = sec_obj->section.protection;
	section->version = sec_obj->section.version;
	sec_obj->num_of_segment	= 0;

	cont_hash = get_container_hash_object(SEGMENT_TYPE, sec_hash->obj_hdl);
	if (cont_hash == NULL) {
		return;
	}

	format = cont_hash->u.cont_obj->format;

	/* read section header layout */
	retval = pread_new(fd, &sec_hdr, sizeof (sec_hdr),
		sec_obj->section.offset, &format);
	if (retval != sizeof (sec_hdr)) {
		return;
	}

	hdrver	= GET_SECTION_HDR_VERSION;

	if ((sec_hdr.headertag != SECTION_HDR_TAG) &&
		(hdrver != section->version)) {
		return;
	}

	/* size = section layout + total sizeof segment header */
	size = sizeof (sec_hdr) + ((sec_hdr.segmentcount)
		* sizeof (segment_layout_t));
	buffer	= alloca(size);
	if (buffer == NULL) {
		return;
	}

	/* segment header buffer */
	seg_buf = alloca(size - sizeof (sec_hdr));
	if (seg_buf == NULL) {
		return;
	}

	/* read segment header */
	retval = pread_new(fd, seg_buf, size - sizeof (sec_hdr),
		sec_obj->section.offset + sizeof (sec_hdr), &format);
	if (retval != (size - sizeof (sec_hdr))) {
		return;
	}

	/* copy section header layout */
	(void) memcpy(buffer, &sec_hdr, sizeof (sec_hdr));

	/* copy segment header layout */
	(void) memcpy(buffer + sizeof (sec_hdr), seg_buf, size -
		sizeof (sec_hdr));

	/* verify crc8 */
	retval = verify_header_crc8(hdrver, buffer, size);
	if (retval != TRUE) {
		return;
	}

	section->version = hdrver;
	sec_obj->section.version = hdrver;

	seg_hdr	= (segment_layout_t *)seg_buf;

	for (count = 0; count < sec_hdr.segmentcount; count++, seg_hdr++) {
		seg_hash = create_segment_hash_object();
		if (seg_hash == NULL) {
			return;
		}

		add_hashobject_to_hashtable(seg_hash, SEGMENT_TYPE);

		copy_segment_layout(&seg_hash->u.seg_obj->segment, seg_hdr);

		add_to_seg_object_list(sec_hash, seg_hash);

		sec_obj->num_of_segment++;
	}
}

/*
 * Description	:
 *   		sun_fru_get_sections() fills an array of section structures
 *		passed as an argument.
 *
 * Arguments	:
 *		container_hdl_t : container handle(device descriptor).
 *		section_t	: array of section structure.
 *		int		: maximum number of section in a container.
 *
 * Returns	:
 *   		int
 *     		On success,the number of section structures written is returned;
 *     		on error, -1 is returned and "errno" is set appropriately.
 *
 */
/*ARGSUSED*/
static int
sun_fru_get_sections(container_hdl_t container, section_t *section, int maxsec,
	door_cred_t *cred)
{
	int		device_fd;
	int		count;
	hash_obj_t	*cont_object;
	hash_obj_t	*sec_hash;

	cont_object	= lookup_handle_object(container, CONTAINER_TYPE);
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

	device_fd = open_file();

	if (device_fd < 0) {
		return (-1);
	}

	for (count = 0; count < cont_object->u.cont_obj->num_of_section;
		count++, section++) {
		section->version = -1;
		/* populate section_t */
		get_section(device_fd, sec_hash, section);
		sec_hash = sec_hash->u.sec_obj->next;
	}

	(void) close(device_fd);

	return (count);
}

/*
 * Description	:
 * 		sun_fru_get_num_segments() returns the current number of
 *		segments in a section.
 *
 * Arguments	:
 *		section_hdl_t : section header holding section information.
 *
 * Return	:
 * 		int
 *     		On success, the number of segments in the argument section is
 *     		returned; on error -1 is returned.
 */
/*ARGSUSED*/
static int
sun_fru_get_num_segments(section_hdl_t section, door_cred_t *cred)
{
	hash_obj_t	*sec_object;
	section_obj_t	*sec_obj;

	sec_object	= lookup_handle_object(section, SECTION_TYPE);
	if (sec_object == NULL) {
		return (-1);
	}

	sec_obj	= sec_object->u.sec_obj;
	if (sec_obj == NULL) {
		return (-1);
	}

	return (sec_obj->num_of_segment);
}

/*
 * Description	:
 *		sun_fru_get_segments() fills an array of structures
 *		representing the segments in a section.
 *
 * Arguments	:
 *		section_hdl_t : holds section number.
 *		segment_t : on success will hold segment information.
 *		int	: maximum number of segment.
 *
 * Return	:
 *		int
 *		On success, the number of segment structures written is
 *		returned; on errno -1 is returned.
 */
/* ARGSUSED */
static int
sun_fru_get_segments(section_hdl_t section, segment_t *segment, int maxseg,
	door_cred_t *cred)
{
	int		count;
	hash_obj_t	*sec_object;
	hash_obj_t	*seg_object;
	section_obj_t	*sec_obj;

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

	seg_object	= sec_object->u.sec_obj->seg_obj_list;
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

/*
 * Description	:
 *		sun_fru_add_segment() adds a segment to a section.
 *
 * Arguments	:
 *		section_hdl_t section
 *		A handle for the section in which to add the segment.
 *
 *		segment_t *segment
 *		On entry, the "handle" component of "segment" is ignored and the
 *		remaining components specify the parameters of the segment to be
 *		added.  On return, the "handle" component is set to the handle
 *		for the added segment. The segment offset is mandatory for FIXED
 *		segments; otherwise, the offset is advisory.
 *
 * Return	:
 *		int
 *		On success, 0 is returned; on error -1 is returned.
 *
 */
static int
sun_fru_add_segment(section_hdl_t section, segment_t *segment,
	section_hdl_t *newsection, door_cred_t *cred)
{
	int		fd;
	int		retval;
	int		offset;
	int		sec_size;
	int		seg_cnt;
	int		bufsize;
	int		new_seg_offset;
	int		new_seg_length;
	int		fixed_segment;
	char		trailer[]	= { 0x0c, 0x00, 0x00, 0x00, 0x00 };
	hash_obj_t	*cont_hash;
	hash_obj_t	*sec_hash;
	hash_obj_t	*seg_hash;
	fru_segdesc_t	*new_seg_desc;
	unsigned char 	*crcbuf;
	section_layout_t sec_layout;
	segment_layout_t *seg_layout;
	segment_layout_t *segment_buf;
	format_t		format;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	/* section hash */
	sec_hash = lookup_handle_object(section, SECTION_TYPE);
	if (sec_hash == NULL) {
		return (-1);
	}

	/* check for read-only section */
	if (sec_hash->u.sec_obj->section.protection == READ_ONLY_SECTION) {
		errno = EPERM;
		return (-1);
	}

	/* look for duplicate segment */
	seg_hash = sec_hash->u.sec_obj->seg_obj_list;
	while (seg_hash != NULL) {
		if (strncmp(segment->name, seg_hash->u.seg_obj->segment.name,
			SEG_NAME_LEN) == 0) {
			errno = EEXIST;
			return (-1); /* can't add duplicate segment */
		}
		seg_hash = seg_hash->u.seg_obj->next;
	}

	/* get the container hash */
	cont_hash = lookup_handle_object(sec_hash->u.sec_obj->cont_hdl,
		CONTAINER_TYPE);
	if (cont_hash == NULL) {
		return (-1);
	}

	format = cont_hash->u.cont_obj->format;

	/* open the container */
	fd = open_file();
	if (fd < 0) {
		return (-1);
	}

	/* section start here */
	offset	= sec_hash->u.sec_obj->section.offset;

	/* read section header layout */
	retval = pread_new(fd, &sec_layout, sizeof (sec_layout), offset,
		&format);
	if (retval != sizeof (sec_layout)) {
		(void) close(fd);
		return (-1);
	}

	/* check for valid section header */
	if (sec_layout.headertag != SECTION_HDR_TAG) {
		/* write a new one */
		sec_layout.headertag		= SECTION_HDR_TAG;
		sec_layout.headerversion[0]	= SECTION_HDR_VER_BIT0;
		sec_layout.headerversion[1]	= SECTION_HDR_VER_BIT1;
		sec_layout.headerlength		= sizeof (sec_layout);
		sec_layout.segmentcount		= 0;
	}

	/* section size */
	sec_size	= sec_hash->u.sec_obj->section.length;

	/* number of segment in the section */
	seg_cnt	= sec_layout.segmentcount;

	/* total sizeof segment + new segment */
	bufsize	=	sizeof (segment_layout_t) * (seg_cnt + 1);
	segment_buf = alloca(bufsize);
	if (segment_buf == NULL) {
		return (-1);
	}

	/* read entire segment header */
	retval = pread_new(fd, segment_buf,
		(bufsize - sizeof (segment_layout_t)),
		offset + sizeof (section_layout_t), &format);
	if (retval != (bufsize - sizeof (segment_layout_t))) {
		(void) close(fd);
		return (-1);
	}

	new_seg_offset	= segment->offset; /* new segment offset */
	new_seg_length	= segment->length; /* new segment length */

	new_seg_desc	= (fru_segdesc_t *)&segment->descriptor;

	fixed_segment	= new_seg_desc->field.fixed;

	/* get new offset for new segment to be addedd */
	retval = find_offset((char *)segment_buf, seg_cnt, sec_size,
		&new_seg_offset, new_seg_length, fixed_segment, fd);

	if (retval != 0)	{
		(void) close(fd);
		errno = EAGAIN;
		return (-1);
	}

	/* copy new segment data in segment layout */
	seg_layout	= (segment_layout_t *)(segment_buf + seg_cnt);
	(void) memcpy(&seg_layout->name, segment->name, SEG_NAME_LEN);
	(void) memcpy(seg_layout->descriptor, &segment->descriptor,
		sizeof (uint32_t));
	seg_layout->length	= segment->length;
	seg_layout->offset	= new_seg_offset; /* new segment offset */

	sec_layout.segmentcount += 1;

	crcbuf	= alloca(sizeof (section_layout_t) + bufsize);
	if (crcbuf == NULL) {
		(void) close(fd);
		return (-1);
	}

	sec_layout.headercrc8 = 0;
	sec_layout.headerlength += sizeof (segment_layout_t);

	(void) memcpy(crcbuf, (char *)&sec_layout, sizeof (section_layout_t));
	(void) memcpy(crcbuf + sizeof (section_layout_t), segment_buf, bufsize);

	sec_layout.headercrc8 = compute_crc8(crcbuf, bufsize +
		sizeof (section_layout_t));

	/* write section header */
	retval = pwrite_new(fd, &sec_layout, sizeof (section_layout_t),
		offset, &format);
	if (retval != sizeof (section_layout_t)) {
		(void) close(fd);
		return (-1);
	}

	/* write segment header */
	retval = pwrite_new(fd, segment_buf, bufsize, offset +
		sizeof (section_layout_t), &format);
	if (retval != bufsize) {
		(void) close(fd);
		return (-1);
	}

	/* write segment trailer */
	retval = pwrite_new(fd, &trailer, sizeof (trailer), new_seg_offset,
		&format);
	if (retval != sizeof (trailer)) {
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);

	/* create new segment hash object */
	seg_hash	= create_segment_hash_object();
	if (seg_hash == NULL) {
		return (-1);
	}

	add_hashobject_to_hashtable(seg_hash, SEGMENT_TYPE);

	copy_segment_layout(&seg_hash->u.seg_obj->segment, seg_layout);

	add_to_seg_object_list(sec_hash, seg_hash);

	sec_hash->u.sec_obj->num_of_segment += 1;
	seg_hash->u.seg_obj->trailer_offset = new_seg_offset;
	*newsection	= section; /* return the new section handle */
	return (0);
}

/*
 * Description	:
 *		sun_fru_delete_segment() deletes a segment from a section; the
 *		associated container data is not altered.
 *
 * Arguments	: segment_hdl_t	segment handle.
 *		  section_hdl_t	new section handle.
 *
 * Return	:
 *		int
 *		On success, 0 returned; On error -1 is returned.
 */
static int
sun_fru_delete_segment(segment_hdl_t segment, section_hdl_t *newsection,
	door_cred_t *cred)
{
	int			num_of_seg;
	int			bufsize;
	int			count;
	int			retval;
	int			fd;
	int			segnum;
	hash_obj_t		*seg_hash;
	hash_obj_t		*sec_hash;
	hash_obj_t		*cont_hash;
	hash_obj_t		*tmp_hash;
	unsigned char		*buffer;
	fru_segdesc_t		*desc;
	segment_layout_t	*seg_buf;
	section_layout_t	*sec_layout;
	segment_layout_t	*seg_layout;
	segment_layout_t	*next_layout;
	format_t		format;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	seg_hash = lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	desc    = (fru_segdesc_t *)&seg_hash->u.seg_obj->segment.descriptor;
	if (!(desc->field.field_perm & SEGMENT_DELETE)) {
		errno = EPERM;
		return (-1); /* can't delete this segment */
	}

	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
		SECTION_TYPE);
	if (sec_hash == NULL) {
		return (-1);
	}

	if (sec_hash->u.sec_obj->section.protection == READ_ONLY_SECTION) {
		errno = EPERM;
		return (-1);
	}

	num_of_seg	= sec_hash->u.sec_obj->num_of_segment;

	bufsize	= (sizeof (segment_layout_t) * num_of_seg);

	seg_buf	= alloca(bufsize);
	if (seg_buf == NULL) {
		return (-1);
	}

	segnum	= 0;
	for (tmp_hash = sec_hash->u.sec_obj->seg_obj_list; tmp_hash != NULL;
		tmp_hash = tmp_hash->u.seg_obj->next) {
		if (tmp_hash->obj_hdl == segment) {
			break;
		}
		segnum++;
	}

	cont_hash = lookup_handle_object(sec_hash->u.sec_obj->cont_hdl,
		CONTAINER_TYPE);
	if (cont_hash == NULL) {
		return (-1);
	}
	format = cont_hash->u.cont_obj->format;

	fd  = open_file();
	if (fd < 0) {
		return (-1);
	}

	sec_layout	= alloca(sizeof (section_layout_t));
	if (sec_layout == NULL) {
		(void) close(fd);
		return (-1);
	}

	/* read section layout header */
	retval = pread_new(fd, sec_layout, sizeof (section_layout_t),
		sec_hash->u.sec_obj->section.offset, &format);
	if (retval != sizeof (section_layout_t)) {
		(void) close(fd);
		return (-1);
	}

	/* read segment header layout */
	retval = pread_new(fd, seg_buf, bufsize,
		sec_hash->u.sec_obj->section.offset +
		sizeof (section_layout_t), &format);
	if (retval != bufsize) {
		(void) close(fd);
		return (-1);
	}

	seg_layout = (segment_layout_t *)(seg_buf + segnum);
	next_layout	= seg_layout;
	for (count = segnum; count < sec_hash->u.sec_obj->num_of_segment-1;
		count++) {
		next_layout++;
		(void) memcpy(seg_layout, next_layout,
			sizeof (segment_layout_t));
		seg_layout++;
	}

	(void) memset(seg_layout, '\0', sizeof (segment_layout_t));

	sec_layout->headercrc8 = 0;

	sec_layout->headerlength -= sizeof (segment_layout_t);
	sec_layout->segmentcount -= 1;

	buffer = alloca(sec_layout->headerlength);
	if (buffer == NULL) {
		(void) close(fd);
		return (-1);
	}

	(void) memcpy(buffer, sec_layout, sizeof (section_layout_t));
	(void) memcpy(buffer + sizeof (section_layout_t), seg_buf, bufsize
		- sizeof (segment_layout_t));
	sec_layout->headercrc8 = compute_crc8(buffer,
		sec_layout->headerlength);

	/* write section header with update crc8 and header length */
	retval = pwrite_new(fd, sec_layout, sizeof (section_layout_t),
		sec_hash->u.sec_obj->section.offset, &format);
	if (retval != sizeof (section_layout_t)) {
		(void) close(fd);
		return (-1);
	}

	/* write the update segment header */
	retval = pwrite_new(fd, seg_buf, bufsize,
		sec_hash->u.sec_obj->section.offset +
		sizeof (section_layout_t), &format);
	(void) close(fd);
	if (retval != bufsize) {
		return (-1);
	}

	free_segment_hash(segment, sec_hash);

	*newsection	= sec_hash->obj_hdl;
	sec_hash->u.sec_obj->num_of_segment = sec_layout->segmentcount;

	return (0);
}

/*
 * Description	:
 * 		sun_fru_read_segment() reads the raw contents of a segment.
 *
 * Arguments	: segment_hdl_t : segment handle.
 *		 void *	: buffer containing segment data when function returns.
 *		size_t :number of bytes.
 *
 * Return	:
 * 		int
 *		On success, the number of bytes read is returned;
 *
 * Notes	:
 *		Segments containing packets can be read in structured fashion
 *		using the fru_get_packets() and fru_get_payload() primitives;the
 *		entire byte range of a segment can be read using
 *		fru_read_segment().
 */
/*ARGSUSED*/
static ssize_t
sun_fru_read_segment(segment_hdl_t segment, void *buffer, size_t nbytes,
		door_cred_t *cred)
{
	int		fd;
	int		retval;
	hash_obj_t	*seg_hash;
	hash_obj_t	*sec_hash;
	hash_obj_t	*cont_hash;
	format_t	format;

	/* segment hash object */
	seg_hash = lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	/* section hash object */
	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
		SECTION_TYPE);
	if (sec_hash == NULL) {
		return (-1);
	}

	/* container hash object */
	cont_hash = lookup_handle_object(sec_hash->u.sec_obj->cont_hdl,
		CONTAINER_TYPE);
	if (cont_hash == NULL) {
		return (-1);
	}
	format = cont_hash->u.cont_obj->format;

	if (seg_hash->u.seg_obj->segment.length < nbytes) {
		return (-1);
	}

	fd = open_file();
	if (fd < 0) {
		return (-1);
	}

	retval = pread_new(fd, buffer, nbytes,
		seg_hash->u.seg_obj->segment.offset, &format);
	(void) close(fd);
	if (retval != nbytes) {
		return (-1);
	}
	return (nbytes);
}

/*
 * Description	:
 *		sun_fru_write_segment() writes a raw segment.
 *
 * Arguments	: segment_hdl_t :segment handle.
 *		 const void * : data buffer.
 *		 size_t	: number of bytes.
 *		 segment_hdl_t : new segment handle.
 *
 * Returns	:
 *		int
 *		On success, the number of bytes written is returned
 *
 */
/*ARGSUSED*/
static int
sun_fru_write_segment(segment_hdl_t segment, const void *data, size_t nbytes,
	segment_hdl_t *newsegment, door_cred_t *cred)
{
	return (ENOTSUP);
}


static int
get_packet(int device_fd, void *buffer, int size, int offset, format_t *format)
{
	int	retval;

	retval = pread_new(device_fd, (char *)buffer, size, offset, format);
	if (retval != -1) {
		return (0);
	}
	return (-1);
}

static uint32_t
get_checksum_crc(hash_obj_t	*seg_hash, int data_size)
{
	int		protection;
	int		offset = 0;
	uint32_t	crc;
	hash_obj_t	*sec_hash;
	hash_obj_t	*pkt_hash;
	unsigned char	*buffer;

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

	protection	= sec_hash->u.sec_obj->section.protection;

	if (protection == READ_ONLY_SECTION) { /* read-only section */
		crc = compute_crc32(buffer, data_size);
	} else {		/* read/write section */
		crc = compute_checksum32(buffer, data_size);
	}
	return (crc);	/* computed crc */
}

static int
get_packets(hash_obj_t *seg_hash, int device_fd, int offset, int length)
{
	int		tag_size;
	int		paylen;
	int		retval;
	int		seg_limit = 0;
	int		pktcnt	= 0;
	char		*data;
	uint32_t	crc;
	uint32_t	origcrc;
	fru_tag_t	tag;
	hash_obj_t	*pkt_hash_obj;
	fru_segdesc_t	*segdesc;
	fru_tagtype_t	tagtype;
	format_t	format;
	hash_obj_t	*cont_hash;

	cont_hash = get_container_hash_object(PACKET_TYPE, seg_hash->obj_hdl);
	if (cont_hash == NULL) {
		return (NULL);
	}
	format = cont_hash->u.cont_obj->format;

	retval = get_packet(device_fd, &tag, sizeof (fru_tag_t), offset,
		&format);
	if (retval == -1) {
		return (-1);
	}

	seg_hash->u.seg_obj->trailer_offset = offset;

	data	= (char *)&tag;
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
		retval = pread_new(device_fd, pkt_hash_obj->u.pkt_obj->payload,
			paylen, offset, &format);
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

		add_hashobject_to_hashtable(pkt_hash_obj, PACKET_TYPE);
		add_to_pkt_object_list(seg_hash, pkt_hash_obj);

		pktcnt++;

		retval = get_packet(device_fd, &tag, sizeof (fru_tag_t),
			offset, &format);
		if (retval == -1) {
			return (retval);
		}

		data	= (char *)&tag;
	}

	segdesc	= (fru_segdesc_t *)&seg_hash->u.seg_obj->segment.descriptor;

	seg_hash->u.seg_obj->trailer_offset = offset;

	if (!segdesc->field.ignore_checksum)  {
		crc = get_checksum_crc(seg_hash, seg_limit);
		offset	= seg_hash->u.seg_obj->segment.offset;

		retval = pread_new(device_fd, &origcrc, sizeof (origcrc),
			offset + seg_limit + 1, &format);
		if (retval != sizeof (origcrc)) {
			return (-1);
		}

		if (origcrc != crc) {
			seg_hash->u.seg_obj->trailer_offset = offset;
			return (-1);
		}
	}
	return (pktcnt);
}

/*
 * Description	:
 *		sun_fru_get_num_packets() returns the current number of packets
 *		in a segment.
 *
 * Arguments	: segment_hdl_t : segment handle.
 *
 * Return	:
 *		int
 *		On success, the number of packets is returned;
 *		-1 on failure.
 */
/*ARGSUSED*/
static int
sun_fru_get_num_packets(segment_hdl_t segment, door_cred_t *cred)
{
	int		device_fd;
	int		pktcnt;
	int		length;
	uint16_t	offset;
	hash_obj_t	*cont_hash_obj;
	hash_obj_t	*seg_hash;
	fru_segdesc_t	*segdesc;
	segment_obj_t	*segment_object;

	seg_hash	= lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	segment_object	= seg_hash->u.seg_obj;
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

	segment_object->num_of_packets = 0;
	device_fd = open_file();
	if (device_fd < 0) {
		return (-1);
	}

	pktcnt = get_packets(seg_hash, device_fd, offset,
		length);
	if (pktcnt == -1) {
		free_pkt_object_list(seg_hash);
		seg_hash->u.seg_obj->pkt_obj_list = NULL;
	}

	segment_object->num_of_packets = pktcnt;
	(void) close(device_fd);

	return (segment_object->num_of_packets);
}

/*
 * Description	:
 *		sun_fru_get_packets() fills an array of structures
 *		representing the packets in a segment.
 *
 * Arguments	: segment_hdl_t : segment handle.
 *		packet_t	: packet buffer.
 *		int	: maximum number of packets.
 *
 * Return	:
 *		int
 *		On success, the number of packet structures written is returned;
 *		On failure -1 is returned;
 *
 */
/*ARGSUSED*/
static int
sun_fru_get_packets(segment_hdl_t segment, packet_t *packet, int maxpackets,
	door_cred_t *cred)
{
	int		count;
	hash_obj_t	*seg_hash_obj;
	hash_obj_t	*pkt_hash_obj;

	/* segment hash object */
	seg_hash_obj	= lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash_obj == NULL) {
		return (-1);
	}

	if (seg_hash_obj->u.seg_obj->num_of_packets != maxpackets) {
		return (-1);
	}

	pkt_hash_obj	= seg_hash_obj->u.seg_obj->pkt_obj_list;
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

/*
 * Description	:
 *		sun_fru_get_payload() copies the contents of a packet's payload.
 *
 * Arguments	: packet_hdl_t : packet handle.
 *		void *	: payload buffer.
 *		size_t	: sizeof the buffer.
 *
 * Return	:
 *    		int
 *     		On success, the number of bytes copied is returned; On error
 *		-1 returned.
 */
/*ARGSUSED*/
static ssize_t
sun_fru_get_payload(packet_hdl_t packet, void *buffer, size_t nbytes,
	door_cred_t *cred)
{
	hash_obj_t	*packet_hash_obj;

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

/*
 * Description	:
 * 		sun_fru_update_payload() writes the contents of a packet's
 *		payload.
 *
 * Arguments	: packet_hdl_t : packet handle.
 *		const void * : data buffer.
 *		size_t	: buffer size.
 *		packet_hdl_t	: new packet handle.
 *
 * Return	:
 * 		int
 *		On success, 0 is returned; on failure
 *		-1 is returned.
 */
/*ARGSUSED*/
static int
sun_fru_update_payload(packet_hdl_t packet, const void *data, size_t nbytes,
	packet_hdl_t *newpacket, door_cred_t *cred)
{
	int		fd;
	int		segment_offset;
	int		trailer_offset;
	int		retval;
	uint32_t	crc;
	hash_obj_t	*pkt_hash;
	hash_obj_t	*seg_hash;
	hash_obj_t	*sec_hash;
	hash_obj_t	*cont_hash;
	fru_segdesc_t	*desc;
	format_t	format;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	/* packet hash object */
	pkt_hash = lookup_handle_object(packet,	PACKET_TYPE);
	if (pkt_hash == NULL) {
		return (-1);
	}

	/* segment hash object */
	seg_hash = lookup_handle_object(pkt_hash->u.pkt_obj->segment_hdl,
		SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	/* check for write perm. */
	desc    = (fru_segdesc_t *)&seg_hash->u.seg_obj->segment.descriptor;
	if (!(desc->field.field_perm & SEGMENT_WRITE)) {
		errno = EPERM;
		return (-1); /* write not allowed */
	}

	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
		SECTION_TYPE);
	if (sec_hash == NULL) {
		return (-1);
	}

	if (sec_hash->u.sec_obj->section.protection == READ_ONLY_SECTION) {
		errno = EPERM;
		return (-1);		/* read-only section */
	}

	cont_hash = lookup_handle_object(sec_hash->u.sec_obj->cont_hdl,
		CONTAINER_TYPE);
	if (cont_hash == NULL) {
		return (-1);
	}

	format = cont_hash->u.cont_obj->format;

	if (pkt_hash->u.pkt_obj->paylen != nbytes) {
		return (-1);
	}

	(void) memcpy(pkt_hash->u.pkt_obj->payload, (char *)data, nbytes);
	fd	= open_file();
	if (fd < 0) {
		return (-1);
	}

	trailer_offset	= seg_hash->u.seg_obj->trailer_offset;
	segment_offset	= seg_hash->u.seg_obj->segment.offset;

	crc = get_checksum_crc(seg_hash, (trailer_offset - segment_offset));
	retval = pwrite_new(fd, data, nbytes,
		pkt_hash->u.pkt_obj->payload_offset, &format);
	if (retval != nbytes) {
		(void) close(fd);
		return (-1);
	}

	retval = pwrite_new(fd, &crc, sizeof (crc),
		trailer_offset + 1, &format);
	(void) close(fd);
	if (retval != sizeof (crc)) {
		return (-1);
	}
	*newpacket = packet;
	return (0);
}

/*
 * Description	:
 *		sun_fru_append_packet() appends a packet to a segment.
 *
 * Arguments	:
 *		segment_hdl_t segment
 *		A handle for the segment to which the packet will be appended.
 *
 *   		packet_t *packet
 *     		On entry, the "tag" component of "packet" specifies the tag
 *     		value for the added packet; the "handle" component is ignored.
 *     		On return, the "handle" component is set to the handle of the
 *     		appended packet.
 *
 *   		const void *payload
 *     		A pointer to the caller's buffer containing the payload data for
 *     		the appended packet.
 *
 *   		size_t nbytes
 *     		The size of the caller buffer.
 *
 * Return	:
 *   		int
 *     		On success, 0 is returned; on error -1 is returned;
 */
static int
sun_fru_append_packet(segment_hdl_t segment, packet_t *packet,
	const void *payload, size_t nbytes, segment_hdl_t *newsegment,
	door_cred_t *cred)
{
	int		trailer_offset;
	int		tag_size;
	int		fd;
	int		retval;
	char		trailer[] = {0x0c, 0x00, 0x00, 0x00, 0x00};
	uint32_t	crc;
	hash_obj_t	*seg_hash;
	hash_obj_t	*sec_hash;
	hash_obj_t	*pkt_hash;
	hash_obj_t	*cont_hash;
	fru_tagtype_t	tagtype;
	fru_segdesc_t	*desc;
	format_t	format;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	seg_hash = lookup_handle_object(segment, SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	/* check for write perm. */
	desc    = (fru_segdesc_t *)&seg_hash->u.seg_obj->segment.descriptor;
	if (!(desc->field.field_perm & SEGMENT_WRITE)) {
		errno = EPERM;
		return (-1); /* write not allowed */
	}

	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
		SECTION_TYPE);
	if (sec_hash == NULL) {
		return (-1);
	}

	if (sec_hash->u.sec_obj->section.protection == READ_ONLY_SECTION) {
		errno = EPERM;
		return (-1);		/* read-only section */
	}

	trailer_offset	= seg_hash->u.seg_obj->trailer_offset;

	/*
	 * if trailer offset is 0 than parse the segment data to get the trailer
	 * offset to compute the remaining space left in the segment area for
	 * new packet to be added.
	 */
	if (trailer_offset == 0) {
		(void) sun_fru_get_num_packets(segment, cred);
		trailer_offset  = seg_hash->u.seg_obj->trailer_offset;
	}

	tagtype	= get_tag_type((void *)&packet->tag);
	if (tagtype == -1) {
		return (-1);
	}

	tag_size	= get_tag_size(tagtype);
	if (tag_size == -1) {
		return (-1);
	}

	if (seg_hash->u.seg_obj->segment.length >
		((trailer_offset - seg_hash->u.seg_obj->segment.offset) +
			tag_size + nbytes +
			sizeof (char) + sizeof (uint32_t))) {
		/* create new packet hash */
		pkt_hash = create_packet_hash_object();
		if (pkt_hash == NULL) {
			return (-1);
		}

		/* tag initialization */
		(void) memcpy(&pkt_hash->u.pkt_obj->tag, &packet->tag,
			tag_size);
		pkt_hash->u.pkt_obj->tag_size	= tag_size;

		/* payload inititalization */
		pkt_hash->u.pkt_obj->payload	= malloc(nbytes);
		if (pkt_hash->u.pkt_obj->payload == NULL) {
			free(pkt_hash);
			return (-1);
		}

		(void) memcpy(pkt_hash->u.pkt_obj->payload, payload, nbytes);
		pkt_hash->u.pkt_obj->paylen	= nbytes;
		pkt_hash->u.pkt_obj->payload_offset = trailer_offset + tag_size;

		/* add to hash table */
		add_hashobject_to_hashtable(pkt_hash, PACKET_TYPE);

		add_to_pkt_object_list(seg_hash, pkt_hash);

		cont_hash = lookup_handle_object(sec_hash->u.sec_obj->cont_hdl,
			CONTAINER_TYPE);
		if (cont_hash == NULL) {
			return (-1);
		}
		format = cont_hash->u.cont_obj->format;

		fd = open_file();
		if (fd < 0) {
			return (-1);
		}

		/* update the trailer offset  */
		trailer_offset += tag_size + nbytes;

		/* calculate new checksum */
		crc = get_checksum_crc(seg_hash, (trailer_offset -
			seg_hash->u.seg_obj->segment.offset));

		retval = pwrite_new(fd, &packet->tag, tag_size, trailer_offset
			- (tag_size + nbytes), &format);
		if (retval != tag_size) {
			(void) close(fd);
			return (-1);
		}

		retval = pwrite_new(fd, payload, nbytes,
			trailer_offset - nbytes, &format);
		if (retval != nbytes) {
			(void) close(fd);
			return (-1);
		}

		retval = pwrite_new(fd, trailer, sizeof (trailer),
			trailer_offset, &format);
		if (retval != sizeof (trailer)) {
			(void) close(fd);
			return (-1);
		}

		retval = pwrite_new(fd, &crc, sizeof (crc),
			trailer_offset + 1, &format);
		(void) close(fd);
		if (retval != sizeof (crc)) {
			return (-1);
		}

		seg_hash->u.seg_obj->trailer_offset = trailer_offset;
		seg_hash->u.seg_obj->num_of_packets += 1;

		*newsegment	= segment; 	/* return new segment handle */
		return (0);
	} else {
		errno = EAGAIN;
	}

	return (-1);
}

static void
adjust_packets(int	fd, hash_obj_t	*free_obj, hash_obj_t	*object_list)
{
	int		retval;
	uint32_t	new_offset;
	hash_obj_t	*hash_ptr;
	format_t	format;
	hash_obj_t	*hash_obj;

	hash_obj = lookup_handle_object(free_obj->obj_hdl, PACKET_TYPE);
	if (hash_obj == NULL) {
		return;
	}
	hash_obj = get_container_hash_object(PACKET_TYPE,
		hash_obj->u.pkt_obj->segment_hdl);
	if (hash_obj == NULL) {
		return;
	}
	format = hash_obj->u.cont_obj->format;

	new_offset = free_obj->u.pkt_obj->payload_offset
		- free_obj->u.pkt_obj->tag_size;
	for (hash_ptr = object_list; hash_ptr != NULL;
		hash_ptr = hash_ptr->u.pkt_obj->next) {
		retval = pwrite_new(fd, &hash_ptr->u.pkt_obj->tag,
			hash_ptr->u.pkt_obj->tag_size, new_offset, &format);
		if (retval != hash_ptr->u.pkt_obj->tag_size) {
			return;
		}
		new_offset += hash_ptr->u.pkt_obj->tag_size;
		hash_ptr->u.pkt_obj->payload_offset = new_offset;
		retval = pwrite_new(fd, hash_ptr->u.pkt_obj->payload,
			hash_ptr->u.pkt_obj->paylen, new_offset, &format);
		if (retval != hash_ptr->u.pkt_obj->paylen) {
			return;
		}
		new_offset += hash_ptr->u.pkt_obj->paylen;
	}
}

static void
free_packet_object(handle_t	handle, hash_obj_t *seg_hash)
{
	hash_obj_t	*pkt_hash;
	hash_obj_t	*next_hash;

	pkt_hash	= seg_hash->u.seg_obj->pkt_obj_list;
	if (pkt_hash == NULL) {
		return;
	}

	if (pkt_hash->obj_hdl == handle) {
		seg_hash->u.seg_obj->pkt_obj_list = pkt_hash->u.pkt_obj->next;
	} else {
		while (pkt_hash->obj_hdl != handle) {
			next_hash = pkt_hash;
			pkt_hash = pkt_hash->u.pkt_obj->next;
			if (pkt_hash == NULL) {
				return;
			}
		}
		next_hash->u.pkt_obj->next = pkt_hash->u.pkt_obj->next;
	}

	if (pkt_hash->prev == NULL) {
		hash_table[(pkt_hash->obj_hdl % TABLE_SIZE)] = pkt_hash->next;
		if (pkt_hash->next != NULL) {
			pkt_hash->next->prev = NULL;
		}
	} else {
		pkt_hash->prev->next = pkt_hash->next;
		if (pkt_hash->next != NULL) {
			pkt_hash->next->prev = pkt_hash->prev;
		}
	}

	free(pkt_hash->u.pkt_obj->payload);
	free(pkt_hash->u.pkt_obj);
	free(pkt_hash);
}

/*
 * Description	:
 *   		sun_fru_delete_packet() deletes a packet from a segment.
 *
 * Arguments	: packet_hdl_t : packet number to be deleted.
 *		segment_hdl_t : new segment handler.
 *
 * Return	:
 *   		int
 *     		On success, 0 is returned; on error, -1.
 *
 * NOTES
 * 		Packets are adjacent; thus, deleting a packet requires moving
 *   		succeeding packets to compact the resulting hole.
 */
static int
sun_fru_delete_packet(packet_hdl_t packet, segment_hdl_t *newsegment,
	door_cred_t *cred)
{
	int		retval;
	int		fd;
	char		trailer[] = { 0x0c, 0x00, 0x00, 0x00, 0x00};
	uint32_t	crc;
	hash_obj_t	*tmp_obj;
	hash_obj_t	*pkt_hash;
	hash_obj_t	*sec_hash;
	hash_obj_t	*cont_hash;
	hash_obj_t	*prev_obj;
	hash_obj_t	*seg_hash;
	fru_segdesc_t	*desc;
	format_t	format;

	/* check the effective uid of the client */
	if (cred->dc_euid != 0) {
		errno = EPERM;
		return (-1);	/* not a root */
	}

	/* packet hash object */
	pkt_hash = lookup_handle_object(packet, PACKET_TYPE);
	if (pkt_hash == NULL) {
		return (-1);
	}

	/* segment hash object */
	seg_hash = lookup_handle_object(pkt_hash->u.pkt_obj->segment_hdl,
		SEGMENT_TYPE);
	if (seg_hash == NULL) {
		return (-1);
	}

	/* check for write perm. */
	desc    = (fru_segdesc_t *)&seg_hash->u.seg_obj->segment.descriptor;
	if (!(desc->field.field_perm & SEGMENT_WRITE)) {
		errno = EPERM;
		return (-1); /* write not allowed */
	}

	/* section hash object */
	sec_hash = lookup_handle_object(seg_hash->u.seg_obj->section_hdl,
		SECTION_TYPE);
	if (sec_hash == NULL) {
		return (-1);
	}

	if (sec_hash->u.sec_obj->section.protection == READ_ONLY_SECTION) {
		errno = EPERM;
		return (-1); 		/* read-only section */
	}

	prev_obj	= seg_hash->u.seg_obj->pkt_obj_list;
	if (prev_obj == NULL) {
		return (-1);
	}

	/* container hash object */
	cont_hash = lookup_handle_object(sec_hash->u.sec_obj->cont_hdl,
		CONTAINER_TYPE);
	if (cont_hash == NULL) {
		return (-1);
	}

	format = cont_hash->u.cont_obj->format;

	fd = open_file();
	if (fd < 0) {
		return (-1);
	}

	if (prev_obj->obj_hdl == packet) { /* first object to be deleted */
		adjust_packets(fd, prev_obj, prev_obj->u.pkt_obj->next);
		seg_hash->u.seg_obj->trailer_offset -=
			(prev_obj->u.pkt_obj->tag_size
			+ prev_obj->u.pkt_obj->paylen);
		free_packet_object(packet, seg_hash);
	} else {
		for (tmp_obj = prev_obj;
			tmp_obj != NULL; tmp_obj = tmp_obj->u.pkt_obj->next) {
			/* found the object */
			if (tmp_obj->obj_hdl == packet) {
				adjust_packets(fd, tmp_obj,
					tmp_obj->u.pkt_obj->next);
				seg_hash->u.seg_obj->trailer_offset -=
					(tmp_obj->u.pkt_obj->tag_size
					+ tmp_obj->u.pkt_obj->paylen);
				free_packet_object(packet, seg_hash);
			}
		}
	}

	seg_hash->u.seg_obj->num_of_packets -= 1;

	/* calculate checksum */
	crc = get_checksum_crc(seg_hash, (seg_hash->u.seg_obj->trailer_offset
		- seg_hash->u.seg_obj->segment.offset));
	/* write trailer at new offset */
	retval = pwrite_new(fd, &trailer, sizeof (trailer),
		seg_hash->u.seg_obj->trailer_offset, &format);
	if (retval != sizeof (trailer)) {
		(void) close(fd);
		return (-1);
	}

	/* write the checksum value */
	retval = pwrite_new(fd, &crc, sizeof (crc),
		seg_hash->u.seg_obj->trailer_offset + 1, &format);
	(void) close(fd);
	if (retval != sizeof (crc)) {
		return (-1);
	}

	*newsegment = seg_hash->obj_hdl; /* return new segment handle */
	return (0);
}

/*
 * Description :
 *		sun_fru_close_container() removes the association between a
 *		container and its handle. this routines free's up all the
 *		hash object contained under container.
 *
 * Arguments   :
 *		container_hdl_t holds the file descriptor of the fru.
 *
 * Return      :
 *		int
 *		return 0.
 *
 */
/* ARGSUSED */
static int
sun_fru_close_container(container_hdl_t container)
{
	hash_obj_t	*hash_obj;
	hash_obj_t	*prev_hash;
	hash_obj_t	*sec_hash_obj;
	handle_t	obj_hdl;

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
			hash_table[(sec_hash_obj->obj_hdl % TABLE_SIZE)]
							= sec_hash_obj->next;
			if (sec_hash_obj->next != NULL) {
				sec_hash_obj->next->prev = NULL;
			}
		} else {
			sec_hash_obj->prev->next = sec_hash_obj->next;
			if (sec_hash_obj->next != NULL) {
				sec_hash_obj->next->prev = sec_hash_obj->prev;
			}
		}

		free(sec_hash_obj->u.sec_obj); /* free section hash object */

		prev_hash = sec_hash_obj;

		sec_hash_obj = sec_hash_obj->u.sec_obj->next;

		free(prev_hash); /* free section hash */
	}

	/* free container hash object */
	if (hash_obj->prev == NULL) {
		hash_table[(sec_hash_obj->obj_hdl % TABLE_SIZE)] =
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

/*
 * FRU ACCESS API
 */

/*
 * Description :
 *		fru_is_data_available checks if the fruid information
 *		is available or not on a give fru
 *
 * Arguments   :
 *		picl_nodehdl_t  hold picl node handle of the fru.
 *
 * Return      :
 *		int
 *		return 0 - if fruid is not present.
 *		return 1 - if fruid is present.
 */
int
fru_is_data_available(picl_nodehdl_t fruh)
{
	int retval, ret;
	uint8_t slot_no;
	picl_nodehdl_t parenth;
	format_t fru_format;
	hash_obj_t *cont_hash_obj;

	if (is_valid_chassis == -1) {
		if (fruaccess_platmod_check_chassis() == 0) {
			is_valid_chassis = 1;
		} else {
			is_valid_chassis = 0;
		}
	}

	if (!is_valid_chassis) {
		return (0);
	}

	retval = ptree_get_propval_by_name(fruh, PICL_PROP_PARENT,
		&parenth, sizeof (picl_nodehdl_t));
	if (retval != PICL_SUCCESS) {
		return (0);
	}

	if (fruaccess_platmod_check_fru(parenth) != 0) {
		return (0);
	}

	retval = ptree_get_propval_by_name(parenth, PICL_PROP_GEO_ADDR,
		&slot_no, sizeof (uint8_t));
	if (retval != PICL_SUCCESS) {
		return (0);
	}

	if (fruaccess_platmod_init_format(slot_no, &fru_format) !=
		PICL_SUCCESS) {
		return (0);
	}

	ret = is_fru_data_available(precedence, slot_no, &fru_format);
	if (ret && (fru_format.format != NO_FRUDATA)) {
		goto create;
	} else {
		return (0);
	}
create:

	cont_hash_obj = create_container_hash_object();
	if (cont_hash_obj == NULL) {
		return (0);
	}

	cont_hash_obj->obj_hdl = fruh;
	cont_hash_obj->u.cont_obj->format = fru_format;

	/* if both formats are present follow the precedence */
	if (fru_format.format == 0x3) {
		if (precedence == IPMI_FORMAT) {
			cont_hash_obj->u.cont_obj->format.format = IPMI_FORMAT;
		} else {
			cont_hash_obj->u.cont_obj->format.format = SUN_FORMAT;
		}
	}
	add_hashobject_to_hashtable(cont_hash_obj, CONTAINER_TYPE);
	return (1);
}

/*
 * FRU ACCESS API
 */

/*
 * All the routines check the fruid format and redirects the call to
 * to appropriate routines depending on fruid format.
 * All SUN format routines start with sun_ prefix.
 * All IPMI format routines start with ipmi_ prefix.
 */
container_hdl_t
fru_open_container(picl_nodehdl_t fru)
{
	hash_obj_t *hash_obj;
	format_t fru_format;

	hash_obj = lookup_handle_object((handle_t)fru, CONTAINER_TYPE);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;
	return (fruaccess_func[fru_format.format - 1].open_container(fru));
}

int
fru_close_container(container_hdl_t container)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = lookup_handle_object(container, CONTAINER_TYPE);
	if (hash_obj == NULL) {
		return (-1);
	}

	fru_format = hash_obj->u.cont_obj->format;
	ret = fruaccess_func[fru_format.format - 1].close_container(container);
	return (ret);
}

int
fru_get_num_sections(container_hdl_t container, door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = lookup_handle_object(container, CONTAINER_TYPE);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;
	ret = fruaccess_func[fru_format.format - 1].get_num_sections(container,
		cred);
	return (ret);
}

int
fru_get_sections(container_hdl_t container, section_t *section,
	int max_sections, door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = lookup_handle_object(container, CONTAINER_TYPE);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].get_sections(container,
		section, max_sections, cred);
	return (ret);
}

int
fru_get_num_segments(section_hdl_t section, door_cred_t *rarg)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(SEGMENT_TYPE, section);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].get_num_segments(section,
		rarg);
	return (ret);
}

int
fru_get_segments(section_hdl_t section, segment_t *segment,
	int max_segments, door_cred_t *rarg)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(SEGMENT_TYPE, section);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;
	ret = fruaccess_func[fru_format.format - 1].get_segments(section,
		segment, max_segments, rarg);
	return (ret);
}

int
fru_add_segment(section_hdl_t section, segment_t *segment,
	section_hdl_t *newsection, door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(SEGMENT_TYPE, section);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].add_segment(section,
		segment, newsection, cred);
	return (ret);
}

int
fru_delete_segment(segment_hdl_t segment, section_hdl_t *newsection,
	door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(PACKET_TYPE, segment);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;
	ret = fruaccess_func[fru_format.format - 1].delete_segment(segment,
		newsection, cred);
	return (ret);
}

ssize_t
fru_read_segment(segment_hdl_t segment, void *buffer, size_t nbytes,
	door_cred_t *cred)
{
	ssize_t ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(PACKET_TYPE, segment);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;
	ret = fruaccess_func[fru_format.format - 1].read_segment(segment,
		buffer, nbytes, cred);
	return (ret);
}

int
fru_write_segment(segment_hdl_t segment, const void *data, size_t nbytes,
	segment_hdl_t *newsegment, door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(PACKET_TYPE, segment);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].write_segment(segment,
		data, nbytes, newsegment, cred);
	return (ret);
}

int
fru_get_num_packets(segment_hdl_t segment, door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(PACKET_TYPE, segment);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].get_num_packets(segment,
		cred);
	return (ret);
}

int
fru_get_packets(segment_hdl_t segment, packet_t *packet,
	int max_packets, door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(PACKET_TYPE, segment);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].get_packets(segment,
		packet, max_packets, cred);
	return (ret);
}

ssize_t
fru_get_payload(packet_hdl_t packet, void *buffer,
	size_t nbytes, door_cred_t *cred)
{
	ssize_t ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = lookup_handle_object(packet, PACKET_TYPE);
	if (hash_obj == NULL) {
		return (-1);
	}

	hash_obj = get_container_hash_object(PACKET_TYPE,
		hash_obj->u.pkt_obj->segment_hdl);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].get_payload(packet, buffer,
		nbytes, cred);
	return (ret);
}

int
fru_update_payload(packet_hdl_t packet, const void *data, size_t nbytes,
	packet_hdl_t *newpacket, door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = lookup_handle_object(packet, PACKET_TYPE);
	if (hash_obj == NULL) {
		return (-1);
	}

	hash_obj = get_container_hash_object(PACKET_TYPE,
		hash_obj->u.pkt_obj->segment_hdl);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;
	ret = fruaccess_func[fru_format.format - 1].update_payload(packet, data,
		nbytes, newpacket, cred);
	return (ret);
}

int
fru_append_packet(segment_hdl_t segment, packet_t *packet,
	const void *payload, size_t nbytes, segment_hdl_t *newsegment,
	door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = get_container_hash_object(PACKET_TYPE, segment);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].append_packet(segment,
		packet, payload, nbytes, newsegment, cred);
	return (ret);
}

int
fru_delete_packet(packet_hdl_t packet, segment_hdl_t *newsegment,
	door_cred_t *cred)
{
	int ret;
	format_t fru_format;
	hash_obj_t *hash_obj;

	hash_obj = lookup_handle_object(packet, PACKET_TYPE);
	if (hash_obj == NULL) {
		return (-1);
	}

	hash_obj = get_container_hash_object(PACKET_TYPE,
		hash_obj->u.pkt_obj->segment_hdl);
	if (hash_obj == NULL) {
		return (-1);
	}
	fru_format = hash_obj->u.cont_obj->format;

	ret = fruaccess_func[fru_format.format - 1].delete_packet(packet,
		newsegment, cred);
	return (ret);
}
