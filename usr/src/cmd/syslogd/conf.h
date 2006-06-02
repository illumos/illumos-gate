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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CONF_H
#define	_CONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
	char **cf_dtab;		/* Array of pointers to line data */
	int cf_dsize;		/* Number of allocated lines in dtab */
	int cf_lines;		/* Number of valid lines in dtab */
	int cf_ptr;		/* Current dtab location for read/rewind */
} conf_t;

int conf_open(conf_t *, const char *, char *[]);
void conf_close(conf_t *);
void conf_rewind(conf_t *);
char *conf_read(conf_t *);

extern void logerror(const char *, ...);

#ifdef __cplusplus
}
#endif

#endif	/* _CONF_H */
