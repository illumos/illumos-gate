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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1985 AT&T
 *      All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.4 */

#include	<stdio.h>
#include	<sys/types.h>		/* EFT abs k16 */
#include	"wish.h"
#include	"typetab.h"
#include	"optabdefs.h"
#include	"partabdefs.h"

extern struct opt_entry	Partab[MAX_TYPES];
extern struct one_part	Parts[MAXPARTS];

char	*get_skip();
char	*tab_parse();

int
read_parts(fp, obj)
FILE	*fp;
char	*obj;
{
	register char	*p;
	char	*tmpstr;
	char	buf[BUFSIZ];
	register int	i;
	struct opt_entry	*partab;
	int openpart;

	partab = Partab + MAX_TYPES - 1;
	openpart = MAXPARTS - MAXOBJPARTS;
	if (get_skip(buf, BUFSIZ, fp) == NULL) {
#ifdef _DEBUG
		_debug(stderr, "No parts\n");
#endif
		return O_FAIL;
	}
	strncpy(partab->objtype, obj, OTYPESIZ);
	tmpstr = NULL;
	p = tab_parse(&tmpstr, buf);
	strncpy(partab->objdisp, tmpstr, OTYPESIZ);
	if (p) {
		p = tab_parse(&tmpstr, p);
		partab->int_class = strtol(tmpstr, 0, 16);
	}
	p = tab_parse(&partab->oeu, p);
	p = tab_parse(&partab->objformat, p);
	p = tab_parse(&partab->objapp, p);
	p = tab_parse(&partab->objprod, p);
	if (p == NULL) {
#ifdef _DEBUG
		_debug(stderr, "Bad def line, '%s'\n", buf);
#endif
		if (tmpstr)
			free(tmpstr);
		return O_FAIL;
	}
	p = tab_parse(&partab->objclass, p);
	if (p) {
		p = tab_parse(&tmpstr, p);
		partab->info_type = strtol(tmpstr, 0, 16);
	}
	else
		partab->info_type = -1;
	if (p) {
		p = tab_parse(&tmpstr, p);
		partab->info_int = strtol(tmpstr, 0, 16);
	}
	p = tab_parse(&partab->info_ext, p);
	partab->part_offset = MAXPARTS - MAXOBJPARTS;
	if (partab->info_type == -1) {
		partab->info_int = 0;
		partab->info_ext = NULL;
	}
	if (get_skip(buf, BUFSIZ, fp) == NULL) {
#ifdef _DEBUG
		_debug(stderr, "No partnum\n");
#endif
		if (tmpstr)
			free(tmpstr);
		return O_FAIL;
	}
	partab->numparts = strtol(buf, &tmpstr, 0);
	if (tmpstr == buf) {
#ifdef _DEBUG
		_debug(stderr, "Bad partnum fld\n");
#endif
		return O_FAIL;
	}
	tmpstr = NULL;
	for (i = 0; i < partab->numparts; i++) {
		if (get_skip(buf, BUFSIZ, fp) == NULL) {
#ifdef _DEBUG
			_debug(stderr, "Missing part\n");
#endif
			if (tmpstr)
				free(tmpstr);
			return O_FAIL;
		}
		p = tab_parse(&tmpstr, buf);
		strncpy(Parts[i + openpart].part_name, tmpstr, PNAMESIZ);
		if (p) {
			p = tab_parse(&tmpstr, p);
			strncpy(Parts[i + openpart].part_template, tmpstr, PNAMESIZ);
		}
		if (p) {
			p = tab_parse(&tmpstr, p);
			Parts[i + openpart].part_flags = strtol(tmpstr, NULL, 16);
		}
		else {
#ifdef _DEBUG
			_debug(stderr, "Bad part num %d '%s'\n", i, buf);
#endif
			if (tmpstr)
				free(tmpstr);
			return O_FAIL;
		}
	}
	if (tmpstr)
		free(tmpstr);
	return O_OK;
}
