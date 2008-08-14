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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	_STRAPP_H
#define	_STRAPP_H

#include <stdarg.h>

extern char	*mms_strpar_undo_escape_sequence(char *);
extern char	*mms_strpar_escape_sequence(char *);
extern char	*mms_strnew(const char *, ...);
extern char	*mms_strapp(char *, const char *, ...);
extern char	*mms_vstrapp(char *, const char *, va_list);
extern char	*mms_strnapp(char *str, int n, char *str2);

#endif /* _STRAPP_H */
