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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _BUFFER_LIST_H
#define	_BUFFER_LIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

/*
 * List of work buffers that need to be processed
 */
struct buffer_ent {
	uint_t		be_flags;
	int		be_error;		/* last error reported */
	char		*be_name;		/* work buffer path */
	time_t		be_lastprocessed;	/* last time processed */
	struct sharepnt_ent	*be_sharepnt;	/* share point list */
	struct buffer_ent	*be_next;
};

/*
 * List of share points that refer to a given work buffer
 */
struct sharepnt_ent {
	uint_t	se_flags;
	char	*se_name;		/* share point path */
	int	se_state;		/* active or inactive? */
	struct sharepnt_ent *se_next;
};

#define	SE_INTABLE 0x01			/* entry still in file table */

extern int getbuffer_list(struct buffer_ent **, timestruc_t *);
extern int checkbuffer_list(struct buffer_ent **, timestruc_t *);
extern void free_buffer_list(struct buffer_ent **);
extern void remove_buffer_ent(struct buffer_ent **, struct buffer_ent *);
extern void free_buffer_list(struct buffer_ent **);
extern void remove_sharepnt_ent(struct sharepnt_ent **, struct sharepnt_ent *);
#ifdef DEBUG
extern void printbuffer_list(struct buffer_ent *);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _BUFFER_LIST_H */
