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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "dh_gssapi.h"

static gss_OID_desc  OID = {9, "\053\006\004\001\052\002\032\002\003" };
static char *MODULUS = 	"d4a0ba0250b6fd2ec626e7ef"
			"d637df76c716e22d0944b88b";
static int ROOT = 3;
static int KEYLEN = 192;
static int ALGTYPE = 0;
#define	HEX_KEY_BYTES 48

#include "fakensl.c"

#include "../dh_common/dh_template.c"

#include "../dh_common/dh_nsl_tmpl.c"
