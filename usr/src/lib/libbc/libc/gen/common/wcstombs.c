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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * wcstombs
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint) && defined(SCCSIDS)
static  char *sccsid = "%Z%%M% %I%     %E% SMI";
#endif 

#include <sys/types.h>
#include "codeset.h"
#include "mbextern.h"

size_t
wcstombs(s, pwcs, n)
	char *s;
	wchar_t * pwcs;
	size_t n;
{
	char *handle;		/* handle */
	int (*p)();
	int num = 0;
	int ret;

	switch (_code_set_info.code_id) {
	case CODESET_NONE:
		/*
		 * default code set
		 */
		 while (*pwcs && (num < n)) {
			*s++ = *pwcs++ & 0x00ff;
			num++;
		 }
		 if (num < n)
			*s = 0;
		 return (num);
		 break;
	case CODESET_EUC:
		/*
		 * EUC code set
		 */
		 return(_wcstombs_euc(s, pwcs, n));
		 break;

	case CODESET_XCCS:
		/*
		 * XCCS code set
		 */
		return(_wcstombs_xccs(s, pwcs, n));
		break;

	case CODESET_ISO2022:
		/*
		 * ISO family
		 */
		return(_wcstombs_iso(s, pwcs, n));
		break;

	default:
		/*
		 * User defined code set
		 */
		 handle = _ml_open_library();
		 if (handle == (char *)NULL)
			return(ERROR_NO_LIB);	/* No user library */
		 p = (int (*)()) dlsym(handle, "_wcstombs");
		 if (p == (int (*)()) NULL)
			return(ERROR_NO_SYM);
		 ret = (*p)(s, pwcs, n);
		 return (ret);
		 break;
	}
	/* NOTREACHED */
}
