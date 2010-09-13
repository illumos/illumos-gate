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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/promif.h>
#include <sys/promimpl.h>

char *
prom_path_gettoken(register char *from, register char *to)
{
	while (*from) {
		switch (*from) {
		case '/':
		case '@':
		case ':':
		case ',':
			*to = '\0';
			return (from);
		default:
			*to++ = *from++;
		}
	}
	*to = '\0';
	return (from);
}

/*
 * Given an OBP pathname, do the best we can to fully expand
 * the OBP pathname, in place in the callers buffer.
 *
 * If we have to complete the addrspec of any component, we can
 * only handle devices that have a maximum of NREGSPECS "reg" specs.
 * We cannot allocate memory inside this function.
 */
void
prom_pathname(char *pathname)
{
	char tmp[OBP_MAXPATHLEN];
	char *from = tmp;
	char *to = pathname;
	char *p;
	cell_t ci[7];
#ifdef PROM_32BIT_ADDRS
	char *opathname = NULL;
#endif /* PROM_32BIT_ADDRS */

	if ((to == (char *)0) || (*to == (char)0))
		return;

#ifdef PROM_32BIT_ADDRS
	if ((uintptr_t)pathname > (uint32_t)-1) {
		opathname = pathname;
		pathname = promplat_alloc(OBP_MAXPATHLEN);
		if (pathname == NULL) {
			return;
		}
		(void) prom_strcpy(pathname, opathname);
		to = pathname;
	}
	if ((uintptr_t)from > (uint32_t)-1) {
		from = promplat_alloc(OBP_MAXPATHLEN);
		if (from == NULL) {
			if (opathname != NULL)
				promplat_free(pathname, OBP_MAXPATHLEN);
			return;
		}
	}
#endif /* PROM_32BIT_ADDRS */

	promif_preprom();

	(void) prom_strcpy(from, to);
	*to = (char)0;

	ci[0] = p1275_ptr2cell("canon");	/* Service name */
	ci[1] = (cell_t)3;			/* #argument cells */
	ci[2] = (cell_t)1;			/* #result cells */
	ci[3] = p1275_ptr2cell(from);		/* Arg1: token */
	ci[4] = p1275_ptr2cell(to);		/* Arg2: buffer address */
	ci[5] = p1275_uint2cell(OBP_MAXPATHLEN); /* Arg3: buffer length */

	(void) p1275_cif_handler(&ci);

	promif_postprom();

#ifdef PROM_32BIT_ADDRS
	if (opathname != NULL) {
		(void) prom_strcpy(opathname, pathname);
		promplat_free(pathname, OBP_MAXPATHLEN);
		to = pathname = opathname;
	}
	if (from != tmp) {
		(void) prom_strcpy(tmp, from);
		promplat_free(from, OBP_MAXPATHLEN);
		from = tmp;
	}
#endif /* PROM_32BIT_ADDRS */

	/*
	 * workaround for bugid 1218110, the prom strips the
	 * options from the input string ... save options at
	 * at the end of the string if the prom didn't.
	 * NB: The workaround only preserves options in the last
	 * component of the string.
	 */

	/*
	 * If there are any options in the last component of the
	 * output, the prom has copied them; No workaround required.
	 */
	if ((p = prom_strrchr(to, '/')) == 0)
		return;
	if ((p = prom_strchr(p, ':')) != 0)
		return;

	/*
	 * If there are no options in the input ... there's
	 * nothing to preserve; return.
	 */
	if ((p = prom_strrchr(from, '/')) == 0)
		p = from;
	if ((p = prom_strchr(p, ':')) == 0)
		return;

	/*
	 * Concatenate the options we found to the end of the output string.
	 */
	(void) prom_strcat(to, p);
}

/*
 * Strip any options strings from an OBP pathname.
 * Output buffer (to) expected to be as large as input buffer (from).
 */
void
prom_strip_options(char *from, char *to)
{
	while (*from != (char)0)  {
		if (*from == ':')  {
			while ((*from != (char)0) && (*from != '/'))
				++from;
		} else
			*to++ = *from++;
	}
	*to = (char)0;
}
