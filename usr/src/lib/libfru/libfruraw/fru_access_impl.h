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

#ifndef	_FRU_ACCESS_IMPL_H
#define	_FRU_ACCESS_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dial.h>
#include <strings.h>
#include <libdevinfo.h>
#include <sys/systeminfo.h>
#include <sys/byteorder.h>
#include <syslog.h>
#include <errno.h>
#include <libfru.h>
#include <limits.h>
#include <fru_tag.h>
#include <fru_access.h>


/* object types */
typedef	enum {CONTAINER_TYPE, SECTION_TYPE, SEGMENT_TYPE, PACKET_TYPE} object_t;

#define	TABLE_SIZE		64	/* hash table size */


/* section header */
#define	SECTION_HDR_TAG		0x08
#define	SECTION_HDR_VER		0x0001
#define	SECTION_HDR_LENGTH	0x06
#define	SECTION_HDR_CRC8	0x00
#define	SECTION_HDR_VER_BIT0	0x00
#define	SECTION_HDR_VER_BIT1	0x01

#define	READ_ONLY_SECTION	1	/* section is read-only */

#define	GET_SEGMENT_DESCRIPTOR	\
		(BE_16(seg_layout->descriptor[1])| \
		BE_16(seg_layout->descriptor[0] << 16))

#define	GET_SECTION_HDR_VERSION	\
		(sec_hdr.headerversion[1]|sec_hdr.headerversion[0] << 8)

/* Segment Trailer Tag */
#define	SEG_TRAILER_TAG 0x0C

/* defines fixed segment */
#define	SEGMENT_FIXED		1

typedef union {
	uint32_t all_bits;
	struct {
		unsigned read_only : 1;
		unsigned unused : 8;
		unsigned : 8;
		unsigned : 8;
		unsigned : 7;
	} field;
} sectdescbit_t;

typedef enum {
	ENC_STANDARD = 0,	/* proper fruid data */
	ENC_SPD			/* serial presence detect data */
} sectencoding_t;

typedef struct {
	sectdescbit_t	description;
	uint32_t	address; /* for SEEPROMS this is the offset */
	uint32_t	size;
	sectencoding_t	encoding;
} sectioninfo_t;

typedef uint16_t headerrev_t;

#define	MAX_NUMOF_SECTION	2

typedef struct {
	headerrev_t header_ver;
	int num_sections;
	sectioninfo_t section_info[MAX_NUMOF_SECTION];
} container_info_t;


/* section header layout */
typedef struct {
	uint8_t	headertag; /* section header tag */
	uint8_t	headerversion[2]; /* header version (msb) */
	uint8_t	headerlength; /* header length */
	uint8_t	headercrc8; /* crc8 */
	uint8_t	segmentcount; /* total number of segment */
} section_layout_t;

/* segment header layout */
typedef struct  {
	uint16_t	name; 	/* segment name */
	uint16_t	descriptor[2]; /* descriptor (msb) */
	uint16_t	offset; /* segment data offset */
	uint16_t	length; /* segment length */
} segment_layout_t;

/* segment information used in finding new offset for a new segment */
typedef struct {
	int segnum;	/* segment number */
	int offset;	/* segment offset */
	int length;	/* segment length */
	int fixed;	/* fixed or non-fixed segment */
} seg_info_t;

typedef	uint64_t	handle_t;

struct	hash_obj;

/* packet hash object */
typedef	struct {
	handle_t	segment_hdl;	/* segment handle */
	fru_tag_t	tag;
	int		tag_size;
	uint8_t		*payload;
	uint32_t	paylen;
	uint32_t	payload_offset;
	struct hash_obj *next;
} packet_obj_t;

/* segment hash object */
typedef struct {
	handle_t	section_hdl;	/* section handle */
	int		num_of_packets;	/* in a segment */
	int		trailer_offset;
	segment_t	segment;
	struct hash_obj	*pkt_obj_list;	/* packet object list */
	struct hash_obj	*next;
} segment_obj_t;

/* section hash object */
typedef	struct {
	handle_t	cont_hdl;	/* container handle */
	section_t	section;
	sectencoding_t	encoding;	/* standard or needing interpretation */
	int	num_of_segment;		/* in a section */
	struct hash_obj	*seg_obj_list;	/* points to segment objects list */
	struct hash_obj	*next;
} section_obj_t;

/* container hash object */
typedef	struct {
	char	device_pathname[PATH_MAX]; /* device name */
	int	num_of_section;	/* num of section in container */
	struct hash_obj	*sec_obj_list; /* points to section objects list */
} container_obj_t;

/* hash object */
typedef	struct hash_obj {
	int	object_type;
	handle_t obj_hdl;
	union {
		container_obj_t		*cont_obj;
		section_obj_t		*sec_obj;
		segment_obj_t		*seg_obj;
		packet_obj_t		*pkt_obj;
	} u;
	struct hash_obj 	*next;
	struct hash_obj 	*prev;
} hash_obj_t;

unsigned char compute_crc8(unsigned char *bytes, int length);
long compute_crc32(unsigned char *bytes, int length);
long compute_checksum32(unsigned char *bytes, int length);

#ifdef	__cplusplus
}
#endif

#endif /* _FRU_ACCESS_IMPL_H */
