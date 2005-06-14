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
 * Copyright (c) 1998, 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MSGFMT_H
#define	_MSGFMT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
 *           0 | (unsigned int) magic number             |
 *             +-----------------------------------------+
 *           4 | (unsigned int) format revision          |
 *             +-----------------------------------------+
 *           8 | (unsigned int) number of strings        | == N
 *             +-----------------------------------------+
 *          12 | (unsigned int) offset of msgid table    | == O
 *             +-----------------------------------------+
 *          16 | (unsigned int) offset of msgstr table   | == T
 *             +-----------------------------------------+
 *          20 | (unsigned int) size of hashing table    | == S
 *             +-----------------------------------------+
 *          24 | (unsigned int) offset of hashing table  | == H
 *             +-----------------------------------------+
 *             +-----------------------------------------+
 *           O | (unsigned int) length of 0th msgid      |
 *             +-----------------------------------------+
 *         O+4 | (unsigned int) offset of 0th msgid      | == M(0)
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 * O+((N-1)*8) | (unsigned int) length of (N-1)th msgid  |
 *             +-----------------------------------------+
 * O+((N-1)*8) | (unsigned int) offset of (N-1)th msgid  | == M(N-1)
 *       +4    +-----------------------------------------+
 *           T | (unsigned int) length of 0th msgstr     |
 *             +-----------------------------------------+
 *         T+4 | (unsigned int) offset of 0th msgstr     | == Q(0)
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 * T+((N-1)*8) | (unsigned int) length of (N-1)th msgstr |
 *             +-----------------------------------------+
 * T+((N-1)*8) | (unsigned int) offset of (N-1)th msgstr | == Q(N-1)
 *       +4    +-----------------------------------------+
 *           H | (unsigned int) start hashing table      |
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 *   H + S * 4 | (unsigned int) end hashing table        |
 *             +-----------------------------------------+
 *        M(0) | NULL terminated 0th msgid string        |
 *             +-----------------------------------------+
 *        M(1) | NULL terminated 1st msgid string        |
 *             +-----------------------------------------+
 *             ...............................
 *             +-----------------------------------------+
 *      M(N-1) | NULL terminated (N-1)th msgid string    |
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

#define	GNU_MAGIC	0x950412de
#define	GNU_MAGIC_SWAPPED	0xde120495
#define	GNU_REVISION	0
#define	GNU_REVISION_SWAPPED	0

struct gnu_msg_info {
	unsigned int	magic;
	unsigned int	revision;
	unsigned int	num_of_str;
	unsigned int	off_msgid_tbl;
	unsigned int	off_msgstr_tbl;
	unsigned int	sz_hashtbl;
	unsigned int	off_hashtbl;
};

struct gnu_msg_ent {
	unsigned int	len;
	unsigned int	offset;
};

#ifdef	__cplusplus
}
#endif

#endif /* _MSGFMT_H */
