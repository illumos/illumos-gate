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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SGFRU_H
#define	_SGFRU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * sgfru driver ioctl definitions
 */

#define	FRU_PSEUDO_DEV		"/devices/pseudo/sgfru@0:sgfru"
/* see SCAPP source file FruRegistry.java */
#define	SEG_PROTIGNCKS		(1 << 30)
#define	SEG_PROTOPAQUE		(1 << 29)
#define	SEG_PROTFIXED		(1 << 28)

#ifdef _KERNEL
#define	_SGFRU_KERNEL_OR_FRU
#endif

#ifdef _SGFRU
#define	_SGFRU_KERNEL_OR_FRU
#endif

#ifdef _SGFRU_KERNEL_OR_FRU
#define	SEG_NAME_LEN 2
#endif

/*
 * Generic typedefs and defines.
 *
 * All sgfru ioctls accept either a fru_info_t (a handle and a count),
 * a frup_info_t (which is a fru_info_t plus a pointer to a preallocated
 * data buffer), or an append_info_t (which is a packet_t plus a frup_info_t).
 *
 * The count is always the space allocated for a specific number of items,
 * aka the calloc model.
 */
typedef	int32_t		fru_cnt_t;	/* count for number of objects */
#ifdef _SGFRU_KERNEL_OR_FRU
typedef uint64_t	fru_hdl_t;	/* SC_handle, opaque handle for SCAPP */

typedef fru_hdl_t	container_hdl_t; /* container handle */
typedef fru_hdl_t	section_hdl_t;	/* section handle */
typedef fru_hdl_t	segment_hdl_t;	/* segment handle */
typedef fru_hdl_t	packet_hdl_t;	/* packet handle */

typedef struct {
	section_hdl_t	handle;		/* for use in operations on section */
	uint32_t	offset;		/* bytes from container beginning */
	uint32_t	length;		/*  length of section in bytes */
	uint32_t	protected;	/* non-zero if write-protected */
	int32_t		version;	/* version of section header, or -1 */
} section_t;

typedef struct {
	segment_hdl_t	handle;		/* for use in operations on segment */
	char		name[SEG_NAME_LEN]; /* from container section header */
	uint32_t	descriptor;	/* ditto */
	uint32_t	offset;		/* ditto */
	uint32_t	length;		/* ditto */
} segment_t;

typedef uint64_t  tag_t;

typedef struct {
	packet_hdl_t	handle;		/* for use in operations on packet */
	tag_t		tag;		/* packet tag */
} packet_t;
#endif

typedef struct {
	fru_hdl_t	hdl;		/* generic fru handle */
	fru_cnt_t	cnt;		/* generic fru count */
} fru_info_t;

typedef	fru_info_t	section_info_t;	/* section handle and count */
typedef	fru_info_t	segment_info_t;	/* segment handle and count */
typedef	fru_info_t	packet_info_t;	/* packet handle and count */

typedef struct {
	fru_info_t	fru_info;	/* handle and count */
	void		*frus;		/* pointer to opaque buffer */
} frup_info_t;

#define	fru_hdl		fru_info.hdl
#define	fru_cnt		fru_info.cnt

typedef	frup_info_t	sections_t;	/* section handle, count, pointer */
typedef	frup_info_t	segments_t;	/* segment handle, count, pointer */
typedef	frup_info_t	packets_t;	/* packet handle, count, pointer */
typedef	frup_info_t	payload_t;	/* payload handle, count, pointer */

typedef struct {
	packet_t	packet;		/* packet info */
	payload_t	payload;	/* handle, count, pointer to buffer */
} append_info_t;

#define	payload_hdl	payload.fru_hdl
#define	payload_cnt	payload.fru_cnt
#define	payload_data	payload.frus

#if defined(_SYSCALL32)

typedef struct {
	fru_info_t	fru_info;	/* handle and count */
	caddr32_t	frus;		/* 32 bit pointer to opaque buffer */
} frup32_info_t;

typedef struct {
	packet_t	packet;		/* packet info */
	frup32_info_t	payload;	/* handle, count, 32 bit pointer */
} append32_info_t;

#endif	/* _SYSCALL32 */

/*
 * Request: section_info_t, with container handle
 * Receive: section_info_t, with current section count
 */
#define	SGFRU_GETNUMSECTIONS		0x0001

/*
 * Request: sections_t, with container handle, max count, preallocated buffer
 * Receive: sections_t, with section_t array and actual count
 */
#define	SGFRU_GETSECTIONS		0x0002

/*
 * Request: segment_info_t, with section handle
 * Receive: segment_info_t, with current segment count
 */
#define	SGFRU_GETNUMSEGMENTS		0x0003

/*
 * Request: segments_t, with section handle, max count, preallocated buffer
 * Receive: segments_t, with segment_t array and actual count
 */
#define	SGFRU_GETSEGMENTS		0x0004

/*
 * Request: segments_t, with section handle and segment_t
 * Receive: updated segments_t with section handle and new segment handle
 */
#define	SGFRU_ADDSEGMENT		0x0005

/*
 * Request: segment_info_t, with segment handle
 * Receive: segment_info_t, with updated section handle
 */
#define	SGFRU_DELETESEGMENT		0x0006

/*
 * Request: segments_t, with segment handle, max count, preallocated buffer
 * Receive: segments_t, with segment raw data and actual count
 */
#define	SGFRU_READRAWSEGMENT		0x0007

/*
 * Request: segments_t, with segment handle, max count, data buffer
 * Receive: segments_t, with segment data and actual count
 */
#define	SGFRU_WRITERAWSEGMENT		0x0008

/*
 * Request: packet_info_t, with segment handle
 * Receive: packet_info_t, with current packet count
 */
#define	SGFRU_GETNUMPACKETS		0x0009

/*
 * Request: packet_info_t, with segment handle, max count, preallocated buffer
 * Receive: packet_info_t, with packet array and actual count
 */
#define	SGFRU_GETPACKETS		0x000a

/*
 * Request: append_info_t, with packet_t, segment handle, count and data
 * Receive: updated append_info_t with segment handle and new packet handle
 */
#define	SGFRU_APPENDPACKET		0x000b

/*
 * Request: packet_info_t, with packet handle
 * Receive: packet_info_t, with updated segment handle
 */
#define	SGFRU_DELETEPACKET		0x000c

/*
 * Request: payload_t, with packet handle, max count, and payload data buffer
 * Receive: payload_t, with payload data and actual count
 */
#define	SGFRU_GETPAYLOAD		0x000d

/*
 * Request: payload_t, with packet handle, max count, and payload data buffer
 * Receive: payload_t, with new packet handle and actual count
 */
#define	SGFRU_UPDATEPAYLOAD		0x000e

#ifdef	__cplusplus
}
#endif

#endif	/* _SGFRU_H */
