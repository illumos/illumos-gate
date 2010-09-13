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

/* Copyright 1996 Sun Microsystems, Inc. All Rights Reserved. */


#ifndef sea_1_0_i18n_h
#define sea_1_0_i18n_h


#include <sys/param.h>
#include <locale.h>
#include <libintl.h>

#define SEA_LOCALE_PATH	"/opt/SUNWconn/snm/lib/locale"

#define DOMAIN_LGET	"SUNW_SEA_LABELS"
#define DOMAIN_MGET	"SUNW_SEA_MESSAGES"
#define DOMAIN_SGET	"SUNW_SEA_SCHEMAS"
#define DOMAIN_LIBGET	"SUNW_SEA_LIBRARIES"
#define DOMAIN_FGET	"SUNW_SEA_FORMATS"


#define LGET(s)            (char *) dgettext(DOMAIN_LGET,  s)
#define MGET(s)            (char *) dgettext(DOMAIN_MGET,    s)
#define MGET(s)            (char *) dgettext(DOMAIN_MGET,    s)
#define SGET(s)            (char *) dgettext(DOMAIN_SGET, s)
#define LIBGET(s)          (char *) dgettext(DOMAIN_LIBGET,    s)
#define FGET(s)		   (char *) dgettext(DOMAIN_FGET,    s)


#define I18N_KEY           628323

#endif /* sea_1_0_i18n_h*/

