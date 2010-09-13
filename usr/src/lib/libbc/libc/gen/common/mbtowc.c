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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * mbtowc
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint) && defined(SCCSIDS)
static  char *sccsid = "%Z%%M% %I%     %E% SMI";
#endif 

#include <stdlib.h>
#include "codeset.h"
#include "mbextern.h"

#undef	mblen

int
mbtowc(pwc, s, n)
	wchar_t * pwc;
	char *s;
	size_t n;
{
	char *handle;		/* handle */
	int (*p)();
	int ret;

	switch (_code_set_info.code_id) {
	case CODESET_NONE:
#ifdef DEBUG
	printf ("DEFAULT: mbtowc invoked\n");
#endif
		/*
		 * This is a default code set
		 */
		 if (s == NULL)
			return (1);
		 else {
			if (pwc != NULL)
				*pwc = (unsigned char)*s;
			return (1);
		 }
		 break;
	case CODESET_EUC:
#ifdef DEBUG
	printf ("EUC: mbtowc invoked\n");
#endif
		/*
		 * EUC code set
		 */
		 return(_mbtowc_euc(pwc, s, n));
		 break;

	case CODESET_XCCS:
#ifdef DEBUG
	printf ("XCCS: mbtowc invoked\n");
#endif
		/*
		 * XCCS code set
		 */
		return(_mbtowc_xccs(pwc, s, n));
		break;

	case CODESET_ISO2022:
#ifdef DEBUG
	printf ("ISO2022: mbtowc invoked\n");
#endif
		/*
		 * ISO family
		 */
		return(_mbtowc_iso(pwc, s, n));
		break;

	default:
		/*
		 * User defined code set
		 */
		 handle = _ml_open_library();
		 if (handle == (char *)NULL)
			return(ERROR_NO_LIB);	/* No user library */
		 p = (int (*)()) dlsym(handle, "_mbtowc");
		 if (p == (int (*)()) NULL)
			return(ERROR_NO_SYM);
		 ret = (*p)(pwc, s, n);
		 return (ret);
		 break;
	}
	/* NOTREACHED */
}

int mblen(s, n)
register char *s; int n;
{
	int val;

	if (_code_set_info.code_id != CODESET_ISO2022)
		return (mbtowc((wchar_t *)0, s, n));
	else {
		/*
		 * ISO's mbtowc() changes 'states'.
		 */
		_savestates();
		val = mbtowc((wchar_t *)0, s, n);
		_restorestates();
		return (val);
	}
}
