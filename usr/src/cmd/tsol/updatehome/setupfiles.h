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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SETUPFILES_H
#define	_SETUPFILES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <pwd.h>
#include <tsol/label.h>

#define	COPY "/.copy_files"
#define	LINK "/.link_files"
#define	CP "/usr/bin/cp"

#define	DBUG	0x001		/* print debug */
#define	DIAG	0x002		/* print diagnostics */
#define	IGNE	0x004		/* ignore copy/link errors */
#define	REPC	0x008		/* replace existing copies */
#define	REPL	0x010		/* replace existing links */

extern int __setupfiles(const struct passwd *pwd, const m_label_t *, int flags);

#ifdef	__cplusplus
}
#endif

#endif	/* !_SETUPFILES_H */
