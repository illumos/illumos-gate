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

#ifndef _DR_MEM_H
#define	_DR_MEM_H

/*
 * Memory DR Control Protocol
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Memory DR Message Header
 */
typedef struct {
	uint32_t	msg_type;	/* message type */
	uint32_t	msg_arg;	/* messages argument */
	uint64_t	req_num;	/* request number */
} dr_mem_hdr_t;

/*
 * Memory command and response messages
 */

#define	DR_MEM_DS_ID		"dr-mem"

#define	DR_MEM_CONFIGURE	(0x4d43)	/* 'MC' configure mem */
#define	DR_MEM_UNCONFIGURE	(0x4d55)	/* 'MU' unconfigure  mem */
#define	DR_MEM_UNCONF_STATUS	(0x4d53)	/* 'MS' get mem unconf status */
#define	DR_MEM_UNCONF_CANCEL	(0x4d4e)	/* 'MN' cancel mem unconf */
#define	DR_MEM_QUERY		(0x4d51)	/* 'MQ' query mem info */

#define	DR_MEM_OK		('o')
#define	DR_MEM_ERROR		('e')

typedef struct {
	uint64_t	addr;		/* mblk base address */
	uint64_t	size;		/* mblk size */
} dr_mem_blk_t;

/*
 * Response Message
 */
typedef struct {
	uint64_t	addr;		/* mblk base address */
	uint64_t	size;		/* mblk size */
	uint32_t	result;		/* result of the operation */
	uint32_t	status;		/* status of the mblk */
	uint32_t	string_off;	/* informational string offset */
	uint32_t	reserved;	/* padding */
} dr_mem_stat_t;

typedef struct {
	uint64_t	addr;		/* query address */
	memquery_t	mq;		/* query results */
} dr_mem_query_t;

/*
 * Result Codes
 */
#define	DR_MEM_RES_OK			0x0	/* operation succeeded */
#define	DR_MEM_RES_FAILURE		0x1	/* operation failed */
#define	DR_MEM_RES_BLOCKED		0x2	/* operation was blocked */
#define	DR_MEM_RES_NOT_IN_MD		0x3	/* memory not defined in MD */
#define	DR_MEM_RES_ESPAN		0x4	/* memory already in use */
#define	DR_MEM_RES_EFAULT		0x5	/* memory access test failed */
#define	DR_MEM_RES_ERESOURCE		0x6	/* resource not available */
#define	DR_MEM_RES_PERM			0x7	/* permanent pages in span */
#define	DR_MEM_RES_EBUSY		0x8	/* memory span busy */
#define	DR_MEM_RES_ENOTVIABLE		0x9	/* VM viability test failed */
#define	DR_MEM_RES_ENOWORK		0xA	/* no pages to unconfigure */
#define	DR_MEM_RES_ECANCELLED		0xB	/* operation cancelled */
#define	DR_MEM_RES_EREFUSED		0xC	/* operation refused */
#define	DR_MEM_RES_EDUP			0xD	/* memory span duplicate */
#define	DR_MEM_RES_EINVAL		0xE	/* invalid argument */

/*
 * Sub-Result Codes
 */
#define	DR_MEM_SRES_NONE		0x0	/* no sub-result */
#define	DR_MEM_SRES_OS_SUSPENDED	0x1	/* blocked due to OS suspend */

/*
 * Status Codes
 */
#define	DR_MEM_STAT_NOT_PRESENT		0x0	/* mblk ID not in MD */
#define	DR_MEM_STAT_UNCONFIGURED	0x1	/* mblk unconfigured */
#define	DR_MEM_STAT_CONFIGURED		0x2	/* mblk configured */

/*
 * Macros to access arrays that follow message header
 */
#define	DR_MEM_HDR(h)		((dr_mem_hdr_t *)(h))
#define	DR_MEM_CMD_MBLKS(h)	((dr_mem_blk_t *)((DR_MEM_HDR(h)) + 1))
#define	DR_MEM_RESP_STATS(h)	((dr_mem_stat_t *)((DR_MEM_HDR(h)) + 1))
#define	DR_MEM_RESP_DEL_STAT(h)	((memdelstat_t *)(DR_MEM_HDR(h) + 1))
#define	DR_MEM_RESP_QUERY(h)	((dr_mem_query_t *)(DR_MEM_HDR(h) + 1))

#ifdef __cplusplus
}
#endif

#endif /* _DR_MEM_H */
