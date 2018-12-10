/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <dlfcn.h>
#include <link.h>
#include <sys/utsname.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <idn/api.h>
#include <idn/version.h>
#include "ace.h"


void *
_icv_open()
{
	ace_state_t *cd;

	cd = (ace_state_t *)calloc(1, sizeof(ace_state_t));
	if (cd == (ace_state_t *)NULL) {
		errno = ENOMEM;
		return ((void *)-1);
	}

	cd->libidnkit = dlopen(ICV_LIBIDNKITPATH, RTLD_LAZY);
	if (cd->libidnkit == (void *)NULL) {
		free((void *)cd);
		errno = EINVAL;
		return ((void *)-1);
	}

	cd->idn_function = (idn_result_t(*)(int, const char *, char *,
#if defined(ICV_ACE_TO_UTF8)
		size_t))dlsym(cd->libidnkit, "idn_decodename");
#else
		size_t))dlsym(cd->libidnkit, "idn_encodename");
#endif	/* defined(ICV_ACE_TO_UTF8) */
	if (cd->idn_function ==
	    (idn_result_t(*)(int, const char *, char *, size_t))NULL) {
		(void) dlclose(cd->libidnkit);
		free((void *)cd);
		errno = EINVAL;
		return ((void *)-1);
	}

	cd->ib = (uchar_t *)malloc(_SYS_NMLN);
	if (cd->ib == (uchar_t *)NULL) {
		(void) dlclose(cd->libidnkit);
		free((void *)cd);
		errno = ENOMEM;
		return ((void *)-1);
	}

	cd->ob = (uchar_t *)malloc(_SYS_NMLN);
	if (cd->ob == (uchar_t *)NULL) {
		(void) dlclose(cd->libidnkit);
		free((void *)cd->ib);
		free((void *)cd);
		errno = ENOMEM;
		return ((void *)-1);
	}

	cd->ibl = cd->obl = _SYS_NMLN;
	cd->iblconsumed = cd->oblremaining = 0;

	return ((void *)cd);
}


void
_icv_close(ace_state_t *cd)
{
	if (! cd)
		errno = EBADF;
	else {
		(void) dlclose(cd->libidnkit);
		free((void *)cd->ib);
		free((void *)cd->ob);
		free((void *)cd);
	}
}


size_t
_icv_iconv(ace_state_t *cd, char **inbuf, size_t *inbufleft, char **outbuf,
                size_t *outbufleft)
{
	size_t ret_val = 0;
	uchar_t *ib;
	uchar_t *ob;
	uchar_t *ibtail;
	uchar_t *obtail;
	uchar_t *tmps;
	idn_result_t idnres;
	idn_action_t actions;
	int i;


	if (! cd) {
		errno = EBADF;
		return((size_t)-1);
	}

	/*
	 * We need an output buffer in pretty much anycase and so we check it
	 * here and issue E2BIG if there the output buffer isn't supplied
	 * properly.
	 */
	if (!outbuf || !(*outbuf)) {
		errno = E2BIG;
		return ((size_t)-1);
	}

	ob = (uchar_t *)*outbuf;
	obtail = ob + *outbufleft;

	/*
	 * Always flush first any previously remaining output buffer at
	 * the conversion descriptor.
	 */
	for (i = 0; i < cd->oblremaining; i++) {
		if (ob >= obtail) {
			errno = E2BIG;
			cd->oblremaining -= i;
			(void) memmove((void *)cd->ob,
				(const void *)(cd->ob + i), cd->oblremaining);
			ret_val = (size_t)-1;
			goto ICV_ICONV_RETURN_TWO;
		}
		*ob++ = cd->ob[i];
	}
	cd->oblremaining = 0;

#ifdef IDNKIT_VERSION_LIBIDN

	/* IDNkit v2 */

	actions =
		 IDN_RTCONV
		|IDN_PROHCHECK
		|IDN_NFCCHECK
		|IDN_PREFCHECK
		|IDN_COMBCHECK
		|IDN_CTXOLITECHECK
		|IDN_BIDICHECK
		|IDN_LOCALCHECK
		|IDN_IDNCONV
		|IDN_LENCHECK;

# if defined(ICV_ACE_TO_UTF8)
	actions |= IDN_RTCHECK;
# else
	actions |= IDN_MAP;
# endif

#else

	/* IDNkit v1 */
	actions =
		 IDN_DELIMMAP
		|IDN_NAMEPREP
		|IDN_IDNCONV
		|IDN_ASCCHECK;

# if defined(ICV_ACE_TO_UTF8)
	actions |= IDN_RTCHECK;
# else
	actions |= IDN_LOCALMAP;
# endif

#endif

#if !defined(ICV_IDN_ALLOW_UNASSIGNED)
	actions |= IDN_UNASCHECK;
#endif

	/* Process reset request. */
	if (!inbuf || !(*inbuf)) {
		if (cd->iblconsumed > 0) {
			if (cd->iblconsumed >= cd->ibl) {
				cd->ibl += _SYS_NMLN;
				tmps = (uchar_t *)realloc((void *)cd->ib,
							cd->ibl);
				if (tmps == (uchar_t *)NULL) {
					/*
					 * We couldn't allocate any more;
					 * return with realloc()'s errno.
					 */
					cd->ibl -= _SYS_NMLN;
					ret_val = (size_t)-1;
					goto ICV_ICONV_RETURN_TWO;
				}
				cd->ib = tmps;
			}

			*(cd->ib + cd->iblconsumed++) = '\0';

			i = 0;
ICV_ICONV_LOOP_ONE:
			idnres = (*(cd->idn_function))(actions,
			    (const char *)cd->ib, (char *)cd->ob,
				cd->obl);
			switch (idnres) {
			case idn_success:
				break;
			case idn_buffer_overflow:
				if (++i >= 2) {
					errno = EILSEQ;
					ret_val = (size_t)-1;
					goto ICV_ICONV_RETURN_TWO;
				}
				cd->obl += _SYS_NMLN;
				tmps = (uchar_t *)realloc((void *)cd->ob,
							cd->obl);
				if (tmps == (uchar_t *)NULL) {
					/*
					 * We couldn't allocate any more;
					 * return with realloc()'s errno.
					 */
					cd->obl -= _SYS_NMLN;
					ret_val = (size_t)-1;
					goto ICV_ICONV_RETURN_TWO;
				}
				cd->ob = tmps;
				goto ICV_ICONV_LOOP_ONE;
			default:
				/*
				 * Anything else we just treat
				 * as illegal sequence error.
				 */
				errno = EILSEQ;
				ret_val = (size_t)-1;
				goto ICV_ICONV_RETURN_TWO;
			}

			cd->iblconsumed = 0;

			cd->oblremaining = strlen((const char *)cd->ob);
			for (i = 0; i < cd->oblremaining; i++) {
				if (ob >= obtail) {
					errno = E2BIG;
					cd->oblremaining -= i;
					(void) memmove((void *)cd->ob,
					    (const void *)(cd->ob + i),
						cd->oblremaining);
					ret_val = (size_t)-1;
					goto ICV_ICONV_RETURN_TWO;
				}
				*ob++ = cd->ob[i];
			}
			cd->oblremaining = 0;
		}

		ret_val = (size_t)0;
		goto ICV_ICONV_RETURN_TWO;
	}

	ib = (uchar_t *)*inbuf;
	ibtail = ib + *inbufleft;

	while (ib < ibtail) {
		/*
		 * We only use bare minimum single byte space class characters
		 * as delimiters between names.
		 */
		if (isspace(*ib)) {
			if (cd->iblconsumed > 0) {
				if (cd->iblconsumed >= cd->ibl) {
					cd->ibl += _SYS_NMLN;
					tmps = (uchar_t *)realloc(
						(void *)cd->ib, cd->ibl);
					if (tmps == (uchar_t *)NULL) {
						/*
						 * We couldn't allocate any
						 * more; return with
						 * realloc()'s errno.
						 */
						cd->ibl -= _SYS_NMLN;
						ret_val = (size_t)-1;
						break;
					}
					cd->ib = tmps;
				}
				*(cd->ib + cd->iblconsumed) = '\0';
				i = 0;
ICV_ICONV_LOOP:
				idnres = (*(cd->idn_function))(actions,
				    (const char *)cd->ib, (char *)cd->ob,
					cd->obl);
				switch (idnres) {
				case idn_success:
					break;
				case idn_buffer_overflow:
					if (++i >= 2) {
						errno = EILSEQ;
						ret_val = (size_t)-1;
						goto ICV_ICONV_RETURN;
					}
					cd->obl += _SYS_NMLN;
					tmps = (uchar_t *)realloc(
						(void *)cd->ob, cd->obl);
					if (tmps == (uchar_t *)NULL) {
						/*
						 * We couldn't allocate any
						 * more; return with
						 * realloc()'s errno.
						 */
						cd->obl -= _SYS_NMLN;
						ret_val = (size_t)-1;
						goto ICV_ICONV_RETURN;
					}
					cd->ob = tmps;
					goto ICV_ICONV_LOOP;
				default:
					/*
					 * Anything else we just treat
					 * as illegal sequence error.
					 */
					errno = EILSEQ;
					ret_val = (size_t)-1;
					goto ICV_ICONV_RETURN;
				}

				cd->iblconsumed = 0;

				cd->oblremaining = strlen((const char *)cd->ob);
				for (i = 0; i < cd->oblremaining; i++) {
					if (ob >= obtail) {
						errno = E2BIG;
						ret_val = (size_t)-1;
						cd->oblremaining -= i;
						(void) memmove((void *)cd->ob,
						    (const void *)(cd->ob + i),
							cd->oblremaining);
						goto ICV_ICONV_RETURN;
					}
					*ob++ = cd->ob[i];
				}
				cd->oblremaining = 0;
			}
			if (ob >= obtail) {
				errno = E2BIG;
				ret_val = (size_t)-1;
				break;
			}
			*ob++ = *ib++;
		} else {
			if (cd->iblconsumed >= cd->ibl) {
				cd->ibl += _SYS_NMLN;
				tmps = (uchar_t *)realloc((void *)cd->ib,
						cd->ibl);
				if (tmps == (uchar_t *)NULL) {
					/*
					 * We couldn't allocate any more;
					 * return with realloc()'s errno.
					 */
					cd->ibl -= _SYS_NMLN;
					ret_val = (size_t)-1;
					break;
				}
				cd->ib = tmps;
			}
			*(cd->ib + cd->iblconsumed++) = *ib++;
		}
	} /* while (ib < ibtail) */

ICV_ICONV_RETURN:
	*inbuf = (char *)ib;
	*inbufleft = ibtail - ib;
ICV_ICONV_RETURN_TWO:
	*outbuf = (char *)ob;
	*outbufleft = obtail - ob;

	return(ret_val);
}
