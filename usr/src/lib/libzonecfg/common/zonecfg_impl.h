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
 *
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _ZONECFG_IMPL_H
#define	_ZONECFG_IMPL_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <zone.h>
#include <sys/uuid.h>

#if !defined(TEXT_DOMAIN)		/* should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it wasn't */
#endif

#define	ZONEADMD_PATH	"/usr/sbin:/usr/bin"

typedef enum {
	PZE_MODIFY = -1,
	PZE_REMOVE = 0,
	PZE_ADD = 1
} zoneent_op_t;

#define	ZONE_STATE_STR_CONFIGURED	"configured"
#define	ZONE_STATE_STR_INCOMPLETE	"incomplete"
#define	ZONE_STATE_STR_INSTALLED	"installed"
#define	ZONE_STATE_STR_READY		"ready"
#define	ZONE_STATE_STR_MOUNTED		"mounted"
#define	ZONE_STATE_STR_RUNNING		"running"
#define	ZONE_STATE_STR_SHUTTING_DOWN	"shutting_down"
#define	ZONE_STATE_STR_DOWN		"down"

/*
 * ":::\n" => 4, no need to count '\0' as ZONENAME_MAX covers that.
 *
 * Note that ZONE_STATE_MAXSTRLEN, MAXPATHLEN, and UUID_PRINTABLE_STRING_LENGTH
 * all include a NUL byte, and this extra count of 2 bytes covers the quotes
 * that may be placed around the path plus one more.
 */
#define	MAX_INDEX_LEN	(ZONENAME_MAX + ZONE_STATE_MAXSTRLEN + MAXPATHLEN + \
			UUID_PRINTABLE_STRING_LENGTH + 3)

#define	ZONE_INDEX_LOCK_DIR	ZONE_SNAPSHOT_ROOT
#define	ZONE_INDEX_LOCK_FILE	"/index.lock"

#define	ZONE_SNAPSHOT_ROOT	ZONES_TMPDIR

extern int putzoneent(struct zoneent *, zoneent_op_t);
extern char *zonecfg_root;

#ifdef	__cplusplus
}
#endif

#endif	/* _ZONECFG_IMPL_H */
