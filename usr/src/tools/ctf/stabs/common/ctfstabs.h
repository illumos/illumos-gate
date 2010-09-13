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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CTFSTABS_H
#define	_CTFSTABS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "ctf_headers.h"

/*
 * The file-reading portion of ctfstabs communicates with the type-specific
 * backends (genassym and forth) via the proc_ops_t, one of which is supplied
 * by each backend.
 */
typedef struct proc_ops {
	/*
	 * Called prior to reading the input template.  A return of -1 signals
	 * an error, and will halt processing.
	 */
	int (*po_init)(char *);

	/*
	 * Called for each line in the input file.  If an error is returned,
	 * also signalled by a return of -1, input lines will be skipped, and
	 * this method will not be called, until a blank line is encountered.
	 */
	int (*po_line)(char *);

	/*
	 * Called after all input lines have been processed.
	 */
	int (*po_fini)(void);
} proc_ops_t;

extern proc_ops_t ga_ops;
extern proc_ops_t fth_ops;

extern FILE *out;		/* the output file */
extern ctf_file_t *ctf;		/* the input object file */

extern int parse_warn(char *, ...);
extern ctf_id_t find_type(char *);

#ifdef __cplusplus
}
#endif

#endif /* _CTFSTABS_H */
