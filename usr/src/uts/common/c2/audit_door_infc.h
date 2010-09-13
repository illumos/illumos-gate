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
 *
 * defines auditd interface uts/common/c2; project private.
 */

#ifndef	_AUDIT_DOOR_INFC_H
#define	_AUDIT_DOOR_INFC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * door buffer
 */

#define	AU_DBUF_COMPLETE	0	/* buffer is a complete record */
#define	AU_DBUF_FIRST		1	/* first of two or more buffers */
#define	AU_DBUF_MIDDLE		2	/* intermediate of 3 or more bufs */
#define	AU_DBUF_LAST		3	/* last of two or more buffers */
#define	AU_DBUF_NOTIFY		0x8000	/* buffer contains a control message */
#define	AU_DBUF_POLICY		1	/* control msg: audit policy changed */
#define	AU_DBUF_SHUTDOWN	2	/* control msg: going down */

/*
 * control messages from the kernel to auditd
 *
 * POLICY:	the new audit policy mask is in aub_buf at a uint32_t
 */


#define	AU_DMARGIN 8
/*
 * The actual length of buf is based on the dynamic allocation
 * for this structure; any positive value for AU_DMARGIN would do.
 */
typedef struct aub {
	uint32_t	aub_size;
	uint32_t	aub_type;	/* flags AU_DBUF_*	*/
	char		aub_buf[AU_DMARGIN];
} au_dbuf_t;

#define	AU_DBUF_HEADER	offsetof(au_dbuf_t, aub_buf[0])


#ifdef __cplusplus
}
#endif

#endif	/* _AUDIT_DOOR_INFC_H */
