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

#ifndef _FRU_ACCESS_IMPL_H
#define	_FRU_ACCESS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <picl.h>
#include <picltree.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>
#include "picldefs.h"
#include "libfru.h"
#include "fru_tag.h"
#include "fru_access.h"

/* converts slot# to ipmb addr */
#define	IPMB_ADDR(_X)	(((_X) < 10) ? (0xb0 + 2 * ((_X) - 1)) :\
					(0xb0 + 2 * (_X)))
#define	MANR_TAG		0xF80010B7	/* ManR tag */
#define	SEG_NAME_LEN		2

#define	MANR_TIME_LEN		4
#define	MANR_FRUDESCR_LEN	80
#define	MANR_MFRLOC_LEN		64
#define	MANR_PARTNUM_LEN	7
#define	MANR_SERIALNUM_LEN	6
#define	MANR_VENDORNAME_LEN	2
#define	MANR_DASHLVL_LEN	2
#define	MANR_REVLVL_LEN		2
#define	MANR_FRUNAME_LEN	16

#define	NO_FRUDATA	0x0
#define	IPMI_FORMAT	0x1
#define	SUN_FORMAT	0x2

/* These are newly introduced #defines for Snowbird */
#define	INPUT_FILE	"/dev/ctsmc"
#define	NUM_OF_SECTIONS	2
#define	DYNAMIC_OFFSET	0x0
#define	STATIC_OFFSET	0x1800
#define	WRITE_SECTION	0
#define	DYNAMIC_LENGTH	(6 * 1024);	/* 6k bytes */
#define	STATIC_LENGTH	(2 * 1024);	/* 2k bytes */
#define	MANR_SIZE 183	/* MANR record size in bytes */

#define	PICL_SLOT_CPCI		"cpci"
#define	PICL_SLOT_PCI		"pci"
#define	PICL_NODE_CHASSIS	"chassis"
#define	SD_SEGMENT_NAME		"SD"
#define	SD_SEGMENT_DESCRIPTOR	0x00004924
#define	SEGMENT_TRAILER_LEN	1
#define	SEGMENT_CHKSM_LEN	4

/* format structure */
typedef struct {
	int format;
	int sun_lun;		/* this info comes from SDR */
	int sun_device_id;	/* this info comes from SDR */
	uint8_t src;
	uint8_t dest;
} format_t;

/* ManR payload structure */
typedef struct {
	char timestamp[MANR_TIME_LEN];
	char fru_descr[MANR_FRUDESCR_LEN];
	char manufacture_loc[MANR_MFRLOC_LEN];
	char sun_part_no[MANR_PARTNUM_LEN];
	char sun_serial_no[MANR_SERIALNUM_LEN];
	char vendor_name[MANR_VENDORNAME_LEN];		/* JEDEC CODE */
	char inital_hw_dash_lvl[MANR_DASHLVL_LEN];
	char inital_hw_rev_lvl[MANR_REVLVL_LEN];
	char fru_short_name[MANR_FRUNAME_LEN];
} payload_t;
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
		(seg_layout->descriptor[1]|seg_layout->descriptor[0] << 16)

#define	GET_SECTION_HDR_VERSION	\
		(sec_hdr.headerversion[1]|sec_hdr.headerversion[0] << 8)

/* Segment Trailer Tag */
#define	SEG_TRAILER_TAG		0x0C

/* defines fixed segment */
#define	SEGMENT_FIXED		1

#define	DEFAULT_FD		-1
#define	DEFAULT_SEQN		-1
#define	FRUACCESS_MSG_ID	11

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

typedef struct {
	sectdescbit_t	description;
	uint32_t address; /* for SEEPROMS this is the offset */
	uint32_t size;
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
	payload_t	payload_data;	/* reqd for ipmi format */
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
	int	num_of_segment;		/* in a section */
	struct hash_obj	*seg_obj_list;	/* points to segment objects list */
	struct hash_obj	*next;
} section_obj_t;

/* contianer hash object */
typedef	struct {
	char	device_pathname[PATH_MAX]; /* device name */
	int	num_of_section;	/* num of section in container */
	format_t	format;
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

extern unsigned char compute_crc8(unsigned char *bytes, int length);
extern long compute_crc32(unsigned char *bytes, int length);
extern long compute_checksum32(unsigned char *bytes, int length);

#ifdef	__cplusplus
}
#endif

#endif /* _FRU_ACCESS_IMPL_H */
