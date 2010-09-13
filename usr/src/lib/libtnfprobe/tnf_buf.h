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
 *	Copyright (c) 1994, by Sun Microsytems, Inc.
 */

#ifndef _TNF_BUF_H
#define	_TNF_BUF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef _KERNEL
#include <sys/tnf_com.h>
#else  /* _KERNEL */
#include <tnf/com.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Size of the file header and forwarding pointer (directory) area combined.
 * Tag and data blocks start this many bytes into the file.
 *
 * The kernel uses a smaller directory area, and uses the saved space
 * as block pool reserved for tag allocations.
 */

#ifdef _KERNEL
#define	TNFW_B_FW_ZONE			0x4000
#define	TNFW_B_TAG_RESERVE		0xc000
#else
#define	TNFW_B_FW_ZONE			0x10000
#define	TNFW_B_TAG_RESERVE		0x8000
#endif
#define	TNFW_B_DATA_BLOCK_BEGIN		(TNFW_B_FW_ZONE + TNFW_B_TAG_RESERVE)

/*
 * CAUTION: do not change integer values of TNF_ALLOC_REUSABLE or
 *		TNF_ALLOC_FIXED
 */
enum tnf_alloc_mode {
	TNF_ALLOC_REUSABLE = 0,
	TNF_ALLOC_FIXED
};

typedef struct {
	tnf_uint32_t		magic;
	tnf_file_header_t	com;
	struct {
		uint_t		hi;
		uint_t		lo[2];
	} next_alloc;
	uint_t			next_tag_alloc;
	uint_t			next_fw_alloc;
} tnf_buf_file_header_t;

typedef struct tnfw_b_pos TNFW_B_POS;

struct tnfw_b_pos {
	tnf_block_header_t 	*tnfw_w_block;
	tnf_block_header_t 	*tnfw_w_uncommitted;
	short 			tnfw_w_write_off;
};

typedef struct {
	boolean_t 		tnfw_w_initialized;
	struct tnfw_b_pos 	tnfw_w_pos;
	struct tnfw_b_pos 	tnfw_w_tag_pos;
	int 			tnfw_w_gen_shift;
	int 			tnfw_w_block_shift;
	pid_t 			tnfw_w_pid;
	u_long 			tnfw_w_block_size;
#ifdef TNFWB_MAY_RELEASE_A_LOCK
	u_long 			tnfw_w_generation;
	boolean_t 		tnfw_w_a_lock_released;
#endif
} TNFW_B_WCB;

typedef enum {
	TNFW_B_OK,
	TNFW_B_NOTCONN,
	TNFW_B_ACKPHT,
	TNFW_B_NO_ALLOC,
	TNFW_B_NO_SPACE,
	TNFW_B_BAD_BLOCK_SIZE,
	TNFW_B_BAD_BLOCK_COUNT,
	TNFW_B_RECORD_TOO_BIG
} TNFW_B_STATUS;

typedef enum {
    TNFW_B_RUNNING = 0,
    TNFW_B_NOBUFFER,
    TNFW_B_FORKED,
    TNFW_B_BROKEN
} TNFW_B_STATE;

/*
 * The STOPPED bit may be or-ed into the state field.
 */
#define	TNFW_B_STOPPED  16
#define	TNFW_B_SET_STOPPED(state)	((state) |= TNFW_B_STOPPED)
#define	TNFW_B_UNSET_STOPPED(state)	((state) &= ~TNFW_B_STOPPED)
#define	TNFW_B_IS_STOPPED(state)	((state) & TNFW_B_STOPPED)


typedef struct {
	TNFW_B_STATE tnf_state;
	volatile char *tnf_buffer;
	int (*tnf_init_callback)(void);
	void (*tnf_fork_callback)(void);
	pid_t tnf_pid;
} TNFW_B_CONTROL;

extern TNFW_B_CONTROL *_tnfw_b_control;

/*
 * structure exported by buffering layer - guaranteed to be filled
 * after tnfw_b_init_buffer is called.
 */
typedef struct {
	char *	fw_file_header;
	char *	fw_block_header;
	char *	fw_root;
} tnf_buf_header_t;

extern tnf_buf_header_t *_tnf_buf_headers_p;

/*
 * External interface
 */

#define	TNFW_B_GIVEBACK(wcb, new_pos)	\
	((wcb)->tnfw_w_pos.tnfw_w_write_off = \
	(((char *)(new_pos) - (char *)((wcb)->tnfw_w_pos.tnfw_w_block) + 7) \
	& ~7), *(int *)(new_pos) = 0)

TNFW_B_STATUS tnfw_b_init_buffer(char *, int, int, boolean_t);
TNFW_B_STATUS tnfw_b_connect(TNFW_B_WCB *, volatile char *);
void * tnfw_b_alloc(TNFW_B_WCB *, size_t, enum tnf_alloc_mode);
TNFW_B_STATUS tnfw_b_xcommit(TNFW_B_WCB *);
TNFW_B_STATUS tnfw_b_xabort(TNFW_B_WCB *);
tnf_uint32_t *tnfw_b_fw_alloc(TNFW_B_WCB *);
void tnfw_b_release_block(TNFW_B_WCB *);

/* Declare lock routines written in assembly language. */
extern int tnfw_b_get_lock(tnf_byte_lock_t *);
extern void tnfw_b_clear_lock(tnf_byte_lock_t *);
extern u_long tnfw_b_atomic_swap(uint_t *, u_long);

#ifdef __cplusplus
}
#endif

#endif /* _TNF_BUF_H */
