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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBDLADM_H
#define	_LIBDLADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/dls.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_attr	dladm_attr_t;

struct dladm_attr {
	char		da_dev[MAXNAMELEN];
	uint_t		da_port;
	uint16_t	da_vid;
};

/* number of attributes per devices in database file */
#define	DLADM_NATTR	3

/*
 * Diagnostic codes. These supplement error messages.
 */
typedef enum {
	DLADM_DIAG_INVALID_LINKNAME	= 1,
	DLADM_DIAG_INVALID_INTFNAME	= 2,
	DLADM_DIAG_CORRUPT_REPOSITORY   = 3,
	DLADM_DIAG_REPOSITORY_OPENFAIL  = 4,
	DLADM_DIAG_REPOSITORY_WRITEFAIL = 5,
	DLADM_DIAG_REPOSITORY_CLOSEFAIL = 6,
	DLADM_DIAG_DEVICE_OPENFAIL	= 7
} dladm_diag_t;

/*
 * Flags recognized by dladm_link()
 */
#define	DLADM_LINK_TEMP		0x01
#define	DLADM_LINK_FORCED	0x02

extern int	dladm_link(const char *, dladm_attr_t *,
    int, const char *, dladm_diag_t *);
extern int	dladm_up(const char *, dladm_diag_t *);
extern int	dladm_unlink(const char *, boolean_t, const char *,
    dladm_diag_t *);
extern int	dladm_down(const char *, dladm_diag_t *);
extern int	dladm_walk(void (*)(void *, const char *), void *);
extern int	dladm_info(const char *, dladm_attr_t *);
extern void	dladm_db_walk(void (*)(void *, const char *,
    dladm_attr_t *), void *);
extern int	dladm_sync(void);
extern const char *dladm_diag(dladm_diag_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_H */
