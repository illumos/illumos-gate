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

#ifndef	_LIBDLPI_IMPL_H
#define	_LIBDLPI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libdlpi.h>
#include <sys/sysmacros.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum DLPI response size, in bytes.
 */
#define	DLPI_CHUNKSIZE	8192

/*
 * Maximum SAP length, in bytes.
 */
#define	DLPI_SAPLEN_MAX	4

/*
 * Maximum number of modules that can be pushed onto a device stream.
 */
#define	DLPI_MODS_MAX	9

/*
 * Number of elements in 'arr'.
 */
#define	NELEMS(arr)	(sizeof (arr) / sizeof ((arr)[0]))

/*
 * Allocate buffer size for DLPI message, in bytes and set DLPI primitive.
 */
#define	DLPI_MSG_CREATE(dlmsg, dlprimitive) \
	(dlmsg).dlm_msgsz = i_dlpi_getprimsize((dlprimitive)); \
	(dlmsg).dlm_msg = alloca((dlmsg).dlm_msgsz); \
	(dlmsg).dlm_msg->dl_primitive = (dlprimitive);

/*
 * Publicly available DLPI notification types. This list may change if
 * new DLPI notification types are made public. See dlpi(7P).
 *
 */
#define	DLPI_NOTIFICATION_TYPES	(DL_NOTE_LINK_DOWN | DL_NOTE_LINK_UP | \
	DL_NOTE_PHYS_ADDR | DL_NOTE_SDU_SIZE | DL_NOTE_SPEED | \
	DL_NOTE_PROMISC_ON_PHYS | DL_NOTE_PROMISC_OFF_PHYS)

/*
 * Used in a mactype lookup table.
 */
typedef struct dlpi_mactype_s {
	uint_t	dm_mactype;	/* DLPI/Private mactype */
	char 	*dm_desc;	/* Description of mactype */
} dlpi_mactype_t;

/*
 * Used to get the maximum DLPI message buffer size, in bytes.
 */
typedef struct dlpi_primsz {
	t_uscalar_t	dp_prim;	/* store DLPI primitive */
	size_t		dp_primsz;
				/* max. message size, in bytes, for dp_prim */
} dlpi_primsz_t;

/*
 * Used to create DLPI message.
 */
typedef struct dlpi_msg {
	union DL_primitives	*dlm_msg;
					/* store DLPI primitive message */
	size_t			dlm_msgsz;
					/* provide buffer size for dlm_msg */
} dlpi_msg_t;

typedef struct dlpi_notifyent {
	uint_t			dln_notes;
					/* notification types registered */
	dlpi_notifyfunc_t	*dln_fnp;
					/* callback to call */
	void 			*arg;	/* argument to pass to callback */
	uint_t			dln_rm;	/* true if should be removed */
	struct dlpi_notifyent	*dln_next;
} dlpi_notifyent_t;

/*
 * Private libdlpi structure associated with each DLPI handle.
 */
typedef struct dlpi_impl_s {
	int		dli_fd;		/* fd attached to stream */
	int		dli_timeout;	/* timeout for operations, in sec */
	char		dli_linkname[DLPI_LINKNAME_MAX];
					/* full linkname including PPA */
	char		dli_provider[DLPI_LINKNAME_MAX];
					/* only provider name */
	t_uscalar_t	dli_style;	/* style 1 or 2 */
	uint_t		dli_saplen;	/* bound SAP length */
	uint_t		dli_sap;	/* bound SAP value */
	boolean_t 	dli_sapbefore;	/* true if SAP precedes address */
	uint_t		dli_ppa;	/* physical point of attachment */
	uint_t		dli_mod_cnt;	/* number of modules to be pushed */
	uint_t		dli_mod_pushed;	/* number of modules pushed */
	char   		dli_modlist[DLPI_MODS_MAX][DLPI_LINKNAME_MAX];
					/* array of mods */
	uint_t		dli_mactype;	/* mac type */
	uint_t		dli_oflags;	/* flags set at open */
	uint_t		dli_note_processing;
					/* true if notification is being */
					/* processed */
	dlpi_notifyent_t *dli_notifylistp;
					/* list of registered notifications */
} dlpi_impl_t;

#ifdef __cplusplus
}
#endif

#endif /* _LIBDLPI_IMPL_H */
