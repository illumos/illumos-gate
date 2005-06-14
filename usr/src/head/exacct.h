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

#ifndef	_EXACCT_H
#define	_EXACCT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * exacct item, group, and object definitions as well as structure manipulation
 * and conversion routines are given in sys/exacct.h.
 */
#include <sys/exacct.h>
#include <sys/exacct_catalog.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ea_open positioning options:  passed in via the aflags argument, these flags
 * determine whether the newly opened file is positioned for reading prior to
 * its first record, or after its last.
 */
#define	EO_HEAD		0x0	/* open file positioned at first object */
#define	EO_TAIL		0x1	/* open file positioned at last object */
#define	EO_POSN_MSK	0x1

/*
 * ea_open validation options:  passed in via the aflags argument, these flags
 * specify whether the open operation should validate the header on the input
 * file.  The EO_NO_VALID_HDR is useful in the case that no header is present on
 * the file, but the version and file type checks are omitted, meaning that
 * incompatibilities might not be caught immediately.
 */
#define	EO_VALID_HDR	0x0	/* validate header on opening file */
#define	EO_NO_VALID_HDR	0x2	/* omit header validation */
#define	EO_VALIDATE_MSK	0x2

typedef struct _ea_file {
	void		*ef_opaque_ptr[8];
	offset_t	ef_opaque_off[3];
	int		ef_opaque_int[6];
} ea_file_t;

extern int ea_error(void);
extern int ea_open(ea_file_t *, const char *, const char *, int, int, mode_t);
extern int ea_fdopen(ea_file_t *, int, const char *, int, int);
extern void ea_clear(ea_file_t *);
extern int ea_close(ea_file_t *);
extern int ea_match_object_catalog(ea_object_t *, ea_catalog_t);
extern ea_object_type_t ea_next_object(ea_file_t *, ea_object_t *);
extern ea_object_type_t ea_previous_object(ea_file_t *, ea_object_t *);
extern ea_object_type_t ea_get_object(ea_file_t *, ea_object_t *);
extern ea_object_type_t ea_unpack_object(ea_object_t **, int, void *, size_t);
extern int ea_write_object(ea_file_t *, ea_object_t *);
extern const char *ea_get_creator(ea_file_t *);
extern const char *ea_get_hostname(ea_file_t *);
extern ea_object_t *ea_copy_object(const ea_object_t *);
extern ea_object_t *ea_copy_object_tree(const ea_object_t *);
extern ea_object_t *ea_get_object_tree(ea_file_t *, uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _EXACCT_H */
