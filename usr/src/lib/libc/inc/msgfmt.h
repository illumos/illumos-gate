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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MSGFMT_H
#define	_MSGFMT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdint.h>
#include <stddef.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Sun MO file format
 */

/*
 *
 *		+-------------------------------+
 *		| (int) middle message id       |
 *		+-------------------------------+
 *		| (int) total # of messages     |
 *		+-------------------------------+
 *		| (int) total msgid length      |
 *		+-------------------------------+
 *		| (int) total msgstr length     |
 *		+-------------------------------+
 *		| (int) size of msg_struct size	|
 *		+-------------------------------+
 *		+-------------------------------+
 *		| (int) less                    |
 *		+-------------------------------+
 *		| (int) more                    |
 *		+-------------------------------+
 *		| (int) msgid offset            |
 *		+-------------------------------+
 *		| (int) msgstr offset           |
 *		+-------------------------------+
 *			................
 *		+-------------------------------+
 *		| (variable str) msgid          |
 *		+-------------------------------+
 *		| (variable str) msgid          |
 *		+-------------------------------+
 *			................
 *		+-------------------------------+
 *		| (variable str) msgid          |
 *		+-------------------------------+
 *		+-------------------------------+
 *		| (variable str) msgstr         |
 *		+-------------------------------+
 *		| (variable str) msgstr         |
 *		+-------------------------------+
 *			................
 *		+-------------------------------+
 *		| (variable str) msgstr         |
 *		+-------------------------------+
 */

struct msg_info {
	int	msg_mid;			/* middle message id */
	int	msg_count;			/* total # of messages */
	int	str_count_msgid;	/* total msgid length */
	int	str_count_msgstr;	/* total msgstr length */
	int	msg_struct_size;	/* size of msg_struct_size */
};

struct msg_struct {
	int	less;				/* index of left leaf */
	int	more;				/* index of right leaf */
	int	msgid_offset;		/* msgid offset */
	int msgstr_offset;		/* msgstr offset */
};

#define	MSG_STRUCT_SIZE		(sizeof (struct msg_struct))

/*
 * The following is the size of the old msg_struct used be defined
 * in usr/src/cmd/msgfmt/msgfmt.c.
 * Old msg_struct contained:
 * struct msg_struct {
 *		char	*msgid;
 *		char	*msgstr;
 *		int	msgid_offset;
 *		int	msgstr_offset;
 *		struct msg_struct	*next;
 * };
 */
#define	OLD_MSG_STRUCT_SIZE	20

#define	LEAFINDICATOR		-99

/*
 *	GNU MO file format
 */

/*
 *
 *             +-----------------------------------------+
 *           0 | (uint32_t) magic number                 |
 *             +-----------------------------------------+
 *           4 | (uint32_t) format revision              |
 *             +-----------------------------------------+
 *           8 | (uint32_t) number of strings            | == N
 *             +-----------------------------------------+
 *          12 | (uint32_t) offset of msgid table        | == O
 *             +-----------------------------------------+
 *          16 | (uint32_t) offset of msgstr table       | == T
 *             +-----------------------------------------+
 *          20 | (uint32_t) size of hashing table        | == S
 *             +-----------------------------------------+
 *          24 | (uint32_t) offset of hashing table      | == H
 *             +-----------------------------------------+
 *             +-----------------------------------------+
 *           O | (uint32_t) length of 0th msgid          |
 *             +-----------------------------------------+
 *         O+4 | (uint32_t) offset of 0th msgid          | == M(0)
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 * O+((N-1)*8) | (uint32_t) length of (N-1)th msgid      |
 *             +-----------------------------------------+
 * O+((N-1)*8) | (uint32_t) offset of (N-1)th msgid      | == M(N-1)
 *       +4    +-----------------------------------------+
 *             +-----------------------------------------+
 *           T | (uint32_t) length of 0th msgstr         |
 *             +-----------------------------------------+
 *         T+4 | (uint32_t) offset of 0th msgstr         | == Q(0)
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 * T+((N-1)*8) | (uint32_t) length of (N-1)th msgstr     |
 *             +-----------------------------------------+
 * T+((N-1)*8) | (uint32_t) offset of (N-1)th msgstr     | == Q(N-1)
 *       +4    +-----------------------------------------+
 *             +-----------------------------------------+
 *           H | (uint32_t) start hashing table          |
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 *   H + S * 4 | (uint32_t) end hashing table            |
 *             +-----------------------------------------+
 *             +-----------------------------------------+
 *        M(0) | NULL terminated 0th msgid string        |
 *             +-----------------------------------------+
 *        M(1) | NULL terminated 1st msgid string        |
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 *      M(N-1) | NULL terminated (N-1)th msgid string    |
 *             +-----------------------------------------+
 *             +-----------------------------------------+
 *        Q(0) | NULL terminated 0th msgstr string       |
 *             +-----------------------------------------+
 *        Q(1) | NULL terminated 1st msgstr string       |
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 *      Q(N-1) | NULL terminated (N-1)th msgstr string   |
 *             +-----------------------------------------+
 */

/*
 *	GNU MO file format (Revision 1)
 */
/*
 *
 *             +-----------------------------------------------+
 *           0 | (uint32_t) magic number                       |
 *             +-----------------------------------------------+
 *           4 | (uint32_t) format revision                    |
 *             +-----------------------------------------------+
 *           8 | (uint32_t) number of strings                  | == N
 *             +-----------------------------------------------+
 *          12 | (uint32_t) offset of msgid table              | == O
 *             +-----------------------------------------------+
 *          16 | (uint32_t) offset of msgstr table             | == T
 *             +-----------------------------------------------+
 *          20 | (uint32_t) size of hashing table              | == S
 *             +-----------------------------------------------+
 *          24 | (uint32_t) offset of hashing table            | == H
 *             +-----------------------------------------------+
 *          32 | (uint32_t) number of dynamic macros           | == M
 *             +-----------------------------------------------+
 *          36 | (uint32_t) offset of dynamic macros           | == P
 *             +-----------------------------------------------+
 *          40 | (uint32_t) number of dynamic strings          | == D
 *             +-----------------------------------------------+
 *          44 | (uint32_t) offset of dynamic msgid tbl        | == A
 *             +-----------------------------------------------+
 *          48 | (uint32_t) offset of dynamic msgstr tbl       | == B
 *             +-----------------------------------------------+
 *             +-----------------------------------------------+
 *           O | (uint32_t) length of 0th msgid                |
 *             +-----------------------------------------------+
 *         O+4 | (uint32_t) offset of 0th msgid                | == M(0)
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 * O+((N-1)*8) | (uint32_t) length of (N-1)th msgid            |
 *             +-----------------------------------------------+
 * O+((N-1)*8) | (uint32_t) offset of (N-1)th msgid            | == M(N-1)
 *       +4    +-----------------------------------------------+
 *             +-----------------------------------------------+
 *           T | (uint32_t) length of 0th msgstr               |
 *             +-----------------------------------------------+
 *         T+4 | (uint32_t) offset of 0th msgstr               | == Q(0)
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 * T+((N-1)*8) | (uint32_t) length of (N-1)th msgstr           |
 *             +-----------------------------------------------+
 * T+((N-1)*8) | (uint32_t) offset of (N-1)th msgstr           | == Q(N-1)
 *       +4    +-----------------------------------------------+
 *             +-----------------------------------------------+
 *           H | (uint32_t) start hashing table                |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *   H + S * 4 | (uint32_t) end hashing table                  |
 *             +-----------------------------------------------+
 *             +-----------------------------------------------+
 *           P | (uint32_t) length of 0th macro                |
 *             +-----------------------------------------------+
 *         P+4 | (uint32_t) offset of 0th macro                | == C(0)
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 * P+((M-1)*8) | (uint32_t) length of (M-1)th macro            |
 *             +-----------------------------------------------+
 * P+((M-1)*8) | (uint32_t) offset of (M-1)th macro            | == C(M-1)
 *       +4    +-----------------------------------------------+
 *             +-----------------------------------------------+
 *           A | (uint32_t) offset of 0th d_msgid              | == L(0)
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 * A+((D-1)*4) | (uint32_t) offset of (D-1)th d_msgid          | == L(D-1)
 *             +-----------------------------------------------+
 *             +-----------------------------------------------+
 *           B | (uint32_t) offset of 0th d_msgstr             | == E(0)
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 * B+((D-1)*4) | (uint32_t) offset of (D-1)th d_msgstr         | == E(D-1)
 *             +-----------------------------------------------+
 *             +-----------------------------------------------+
 *        L(0) | (uint32_t) offset of 0th d_msgid message      | == F(0)
 *             +-----------------------------------------------+
 *      L(0)+4 | (uint32_t) length of 0th fixed substring      |
 *             +-----------------------------------------------+
 *      L(0)+8 | (uint32_t) index to a dynamic macro           |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *     L(0)+4+ | (uint32_t) length of (m-1)th fixed substring  |
 *   ((m-1)*8) +-----------------------------------------------+
 *     L(0)+8+ | (uint32_t) NOMORE_DYNAMIC_STR                 |
 *   ((m-1)*8) +-----------------------------------------------+
 *             +-----------------------------------------------+
 *      L(D-1) | (uint32_t) offset of 0th d_msgid message      | == F(D-1)
 *             +-----------------------------------------------+
 *    L(D-1)+4 | (uint32_t) length of 0th fixed substring      |
 *             +-----------------------------------------------+
 *    L(D-1)+8 | (uint32_t) index to a dynamic macro           |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *    L(D-1)+4 | (uint32_t) length of (m-1)th fixed substring  |
 *   ((m-1)*8) +-----------------------------------------------+
 *    L(D-1)+8 | (uint32_t) NOMORE_DYNAMIC_STR                 |
 *   ((m-1)*8) +-----------------------------------------------+
 *             +-----------------------------------------------+
 *        E(0) | (uint32_t) offset of 0th d_msgstr message     | == G(0)
 *             +-----------------------------------------------+
 *      E(0)+4 | (uint32_t) length of 0th fixed substring      |
 *             +-----------------------------------------------+
 *      E(0)+8 | (uint32_t) index to a dynamic macro           |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *     E(0)+4+ | (uint32_t) length of (m-1)th fixed substring  |
 *   ((m-1)*8) +-----------------------------------------------+
 *     E(0)+8+ | (uint32_t) NOMORE_DYNAMIC_STR                 |
 *   ((m-1)*8) +-----------------------------------------------+
 *             +-----------------------------------------------+
 *      E(D-1) | (uint32_t) offset of 0th d_msgstr message     | == G(D-1)
 *             +-----------------------------------------------+
 *    E(D-1)+4 | (uint32_t) length of 0th fixed substring      |
 *             +-----------------------------------------------+
 *    E(D-1)+8 | (uint32_t) index to a dynamic macro           |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *    E(D-1)+4 | (uint32_t) length of (m-1)th fixed substring  |
 *   ((m-1)*8) +-----------------------------------------------+
 *    E(D-1)+8 | (uint32_t) NOMORE_DYNAMIC_STR                 |
 *   ((m-1)*8) +-----------------------------------------------+
 *             +-----------------------------------------------+
 *        M(0) | NULL terminated 0th msgid string              |
 *             +-----------------------------------------------+
 *        M(1) | NULL terminated 1st msgid string              |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *      M(N-1) | NULL terminated (N-1)th msgid string          |
 *             +-----------------------------------------------+
 *        Q(0) | NULL terminated 0th msgstr string             |
 *             +-----------------------------------------------+
 *        Q(1) | NULL terminated 1st msgstr string             |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *      Q(N-1) | NULL terminated (N-1)th msgstr string         |
 *             +-----------------------------------------------+
 *             +-----------------------------------------------+
 *        C(0) | NULL terminated 0th macro                     |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *      C(M-1) | NULL terminated (M-1)th macro                 |
 *             +-----------------------------------------------+
 *             +-----------------------------------------------+
 *        F(0) | NULL terminated 0th dynamic msgid string      |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *      F(D-1) | NULL terminated (D-1)th dynamic msgid string  |
 *             +-----------------------------------------------+
 *             +-----------------------------------------------+
 *        G(0) | NULL terminated 0th dynamic msgstr string     |
 *             +-----------------------------------------------+
 *             ...............................
 *             +-----------------------------------------------+
 *      G(D-1) | NULL terminated (D-1)th dynamic msgstr string |
 *             +-----------------------------------------------+
 */

#define	GNU_MAGIC			0x950412de
#define	GNU_MAGIC_SWAPPED		0xde120495
#define	GNU_REVISION			0
#define	GNU_REVISION_0_0		0
#define	GNU_REVISION_0_0_SWAPPED	0
#define	GNU_REVISION_0_1		0x00000001
#define	GNU_REVISION_0_1_SWAPPED	0x01000000
#define	GNU_REVISION_1_1		0x00010001
#define	GNU_REVISION_1_1_SWAPPED	0x01000100
#define	NOMORE_DYNAMIC_MACRO		0xffffffff

enum gnu_msgidstr {
	MSGID = 0,
	MSGSTR = 1
};

struct gnu_msg_info {
	uint32_t	magic;
	uint32_t	revision;
	uint32_t	num_of_str;
	uint32_t	off_msgid_tbl;
	uint32_t	off_msgstr_tbl;
	uint32_t	sz_hashtbl;
	uint32_t	off_hashtbl;
};

struct gnu_msg_rev1_info {
	uint32_t	num_of_dynamic_macro;
	uint32_t	off_dynamic_macro;
	uint32_t	num_of_dynamic_str;
	uint32_t	off_dynamic_msgid_tbl;
	uint32_t	off_dynamic_msgstr_tbl;
};

struct gnu_msg_ent {
	uint32_t	len;
	uint32_t	offset;
};

struct gnu_dynamic_ent {
	uint32_t	len;
	uint32_t	idx;
};

struct gnu_dynamic_tbl {
	uint32_t	offset;
	struct gnu_dynamic_ent	entry[1];
};

#ifdef	__cplusplus
}
#endif

#endif /* _MSGFMT_H */
