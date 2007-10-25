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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_MSGBUF_H
#define	_SMBSRV_MSGBUF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definition and interface for smb_msgbuf buffer management.  The
 * smb_msgbuf interface is typically used to encode or decode SMB
 * data using sprintf/scanf style operations.  It can also be used
 * for general purpose encoding and decoding.
 */

#include <sys/types.h>
#include <smbsrv/smb_i18n.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * When unicode strings are decoded, the resultant UTF-8 strings are
 * stored in dynamically allocated areas, which are held on a linked
 * list anchored at smb_msgbuf.mlist.  The list is deallocated by
 * smb_msgbuf_term.
 */
typedef struct smb_msgbuf_mlist {
    struct smb_msgbuf_mlist *next;
    size_t size;
} smb_msgbuf_mlist_t;

/*
 * smb_smgbuf flags
 *
 * SMB_MSGBUF_UNICODE	When there is a choice between unicode or ascii
 *			formatting, select unicode processing.
 * SMB_MSGBUF_NOTERM	Do not null terminate strings.
 */
#define	SMB_MSGBUF_UNICODE		0x00000001
#define	SMB_MSGBUF_NOTERM		0x00000002

/*
 * base:   points to the beginning of the buffer
 * end:    points to the limit of the buffer.
 * scan:   points to the current offset.
 * max:    holds the number of bytes in the buffer.
 * count:  unused.
 * mlist:  anchors the dynamically allocated memory list.
 * flags:  see SMB_SMGBUF flags.
 */
typedef struct smb_msgbuf {
	uint8_t *base;
	uint8_t *end;
	uint8_t *scan;
	size_t count;
	size_t max;
	smb_msgbuf_mlist_t mlist;
	uint32_t flags;
} smb_msgbuf_t;

/*
 * List of smb_msgbuf_decode and smb_msgbuf_encode return values.
 */
#define	SMB_MSGBUF_SUCCESS		0
#define	SMB_MSGBUF_UNDERFLOW		-1
#define	SMB_MSGBUF_OVERFLOW		SMB_MSGBUF_UNDERFLOW
#define	SMB_MSGBUF_INVALID_FORMAT	-2
#define	SMB_MSGBUF_INVALID_HEADER	-3
#define	SMB_MSGBUF_DATA_ERROR		-4

/*
 * smb_msgbuf_init must be called to associate the smb_msgbuf_t with
 * a buffer before any encode or decode operations may be performed.
 *
 * smb_msgbuf_term must be called to free any dynamically allocated memory
 * that was acquired during encode or decode operations. At this time
 * the only operation that allocates memory is a unicode string decode.
 *
 * If there are no errors, smb_msgbuf_decode and smb_msgbuf_encode return
 * the number of bytes decoded or encoded.  If there is a problem they
 * return -ve error codes.
 */
extern void smb_msgbuf_init(smb_msgbuf_t *, uint8_t *, size_t, uint32_t);
extern void smb_msgbuf_term(smb_msgbuf_t *);
extern int smb_msgbuf_decode(smb_msgbuf_t *, char *, ...);
extern int smb_msgbuf_encode(smb_msgbuf_t *, char *, ...);
extern size_t smb_msgbuf_used(smb_msgbuf_t *);
extern size_t smb_msgbuf_size(smb_msgbuf_t *);
extern uint8_t *smb_msgbuf_base(smb_msgbuf_t *);
extern void smb_msgbuf_word_align(smb_msgbuf_t *);
extern void smb_msgbuf_dword_align(smb_msgbuf_t *);
extern int smb_msgbuf_has_space(smb_msgbuf_t *, size_t);
extern void smb_msgbuf_fset(smb_msgbuf_t *, uint32_t);
extern void smb_msgbuf_fclear(smb_msgbuf_t *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_MSGBUF_H */
