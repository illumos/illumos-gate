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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _FRU_ACCESS_H
#define	_FRU_ACCESS_H

#include <sys/types.h>
#include <picl.h>
#include <door.h>

#ifdef	__cplusplus
extern "C" {
#endif


#define	SEG_NAME_LEN	2


typedef uint64_t  fru_hdl_t;

typedef fru_hdl_t  container_hdl_t;
typedef fru_hdl_t  section_hdl_t;
typedef fru_hdl_t  segment_hdl_t;
typedef fru_hdl_t  packet_hdl_t;

typedef struct
{
	section_hdl_t	handle;	/*  for use in operations on section  */
	uint32_t	offset;	/*  bytes from container beginning  */
	uint32_t	length;	/*  length of section in bytes  */
	uint32_t	protection; /* non-zero if section is write-protected */
	int32_t		version;	/*  version of section header, or -1 */
}
section_t;

typedef struct
{
	segment_hdl_t	handle;	/*  for operations on segment  */
	char	name[SEG_NAME_LEN];	/*  from container section header  */
	uint32_t	descriptor;	/*  ditto  */
	uint32_t	offset;		/*  ditto  */
	uint32_t	length;		/*  ditto  */
}
segment_t;

typedef uint64_t  tag_t;

typedef struct
{
	packet_hdl_t	handle;	/*  for use in operations on packet  */
	tag_t		tag;
}
packet_t;


container_hdl_t fru_open_container(picl_nodehdl_t fru);

int fru_close_container(container_hdl_t container);
int fru_get_num_sections(container_hdl_t container, door_cred_t *cred);
int fru_get_sections(container_hdl_t container, section_t *section,
				int max_sections, door_cred_t *cred);
int fru_get_num_segments(section_hdl_t section, door_cred_t *rarg);
int fru_get_segments(section_hdl_t section, segment_t *segment,
				int max_segments, door_cred_t *rarg);
int fru_add_segment(section_hdl_t section, segment_t *segment,
			section_hdl_t *newsection, door_cred_t *cred);
int fru_delete_segment(segment_hdl_t segment, section_hdl_t *newsection,
							door_cred_t *cred);
ssize_t fru_read_segment(segment_hdl_t segment, void *buffer, size_t nbytes,
							door_cred_t *cred);
int fru_write_segment(segment_hdl_t segment, const void *data, size_t nbytes,
				segment_hdl_t *newsegment, door_cred_t *cred);
int fru_get_num_packets(segment_hdl_t segment, door_cred_t *cred);
int fru_get_packets(segment_hdl_t segment, packet_t *packet,
			int max_packets, door_cred_t *cred);
ssize_t fru_get_payload(packet_hdl_t packet, void *buffer,
			size_t nbytes, door_cred_t *cred);
int fru_update_payload(packet_hdl_t packet, const void *data, size_t nbytes,
			packet_hdl_t *newpacket, door_cred_t *cred);
int fru_append_packet(segment_hdl_t segment, packet_t *packet,
	const void *payload, size_t nbytes, segment_hdl_t *newsegment,
						door_cred_t *cred);
int fru_delete_packet(packet_hdl_t packet, segment_hdl_t *newsegment,
						door_cred_t *cred);
int fru_is_data_available(picl_nodehdl_t fru);

#ifdef	__cplusplus
}
#endif

#endif /* _FRU_ACCESS_H */
