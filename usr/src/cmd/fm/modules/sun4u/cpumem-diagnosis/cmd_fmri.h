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

#ifndef _CMD_FMRI_H
#define	_CMD_FMRI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Each general-purpose state structure is named by an FMRI - the FMRI of the
 * piece of hardware being described.  FMRIs are nvlists, and thus require
 * special handling if they are to be persisted along with the general-purpose
 * buffer.  The cmd_fmri_t manages the FMRI, both in packed (persistable) and
 * unpacked formats.  The packed FMRI is stored in a separate buffer (named by
 * the fmri_packnm member), from which it can be unpacked on restore.
 *
 * Data structures:
 *
 *     ,--------.
 *     |G.P.    |
 *     |buffer  |
 *     |,-------|         ,-------------.
 *     ||fmri_t |   ----> |packed nvlist|
 *     |`-------|         `-------------'
 *     `--------'
 *
 * The buffer for the general purpose buffer is named and stored independently.
 * This subsystem creates and manages the packed nvlist buffer, using a name
 * provided by the caller.
 */

#include <libnvpair.h>
#include <fm/fmd_api.h>
#include <sys/types.h>

#include <cmd_state.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cmd_fmri {
	nvlist_t *fmri_nvl;		/* The unpacked FMRI FMRI */
	char *fmri_packbuf;		/* In-core packed nvlist buffer */
	size_t fmri_packsz;		/* Size of packed nvlist buffer */
	char fmri_packnm[CMD_BUFNMLEN];	/* Persistent buffer name for FMRI */
} cmd_fmri_t;

extern void cmd_fmri_init(fmd_hdl_t *, cmd_fmri_t *, nvlist_t *,
    const char *, ...);
extern void cmd_fmri_fini(fmd_hdl_t *, cmd_fmri_t *, int);

extern void cmd_fmri_restore(fmd_hdl_t *, cmd_fmri_t *);
extern void cmd_fmri_write(fmd_hdl_t *, cmd_fmri_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CMD_FMRI_H */
