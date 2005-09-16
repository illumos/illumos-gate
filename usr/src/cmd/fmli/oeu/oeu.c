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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "io.h"
#include "retcds.h"
#include "parse.h"
#include "smdef.h"
#include "typetab.h"
#include "mail.h"
#include "partabdefs.h"
#include "terror.h"
#include "sizes.h"


#define NOFIELDS 20
#define PARTFIELDS 13
static int look_ahead = 0;
char *uptokwd();
long getnum();
int skipspace();
static int stopit();
extern int skip();       /* >>>> CHANGED FROM "static" <<<< */
static int obj_num();
static int obj_name();
static int obj_type();
static void encrytest();
static int par_count();
static struct parsetab {
	char *testring;
	int (*func)();
} Parsetab[NOFIELDS] = 
	{
		{ "type:",		obj_type },
		{ "application:",	skip },
		{ "format:",		skip },
		{ "product-id:",	skip },
		{ "object-number:",	obj_num },
		{ "count:",		par_count },
		{ "name:",		obj_name },
		{ "cdate:",		skip },
		{ "moddate:",		skip },
		{ "author:",		skip },
		{ "folder:",		skip },
		{ "keywords:",		skip },
		{ "subject:",		skip },
		{ "product-info:",	skip },
		{ "part-type:",		stopit },
		{ "encrypted:",		stopit },
		{ "encryption-test:",	stopit },
		{ "part-encoding:",	stopit },
		{ "encoding-algorithm:",stopit },
		{ "part-length:",	stopit }
};

static int
stopit(fp, p)
FILE *fp;
struct oeh *p;
{
	look_ahead = TRUE;
	return (0);
}
int
#ifndef JUSTCHECK
oeuparse(from, p, unpack) 
#else
oeucheck(from, p, unpack) 
#endif /* JUSTCHECK */
char *from;
struct oeh *p;
int unpack;
{
    struct opt_entry *parts, *obj_to_parts();
    struct one_part *apart, *opt_next_part();
    FILE *fp, *fp2;
    char *enc, *type ,*filename();
    int c, kwd, i		/* , place */;  /* abs: vaiable unused */
    long length;
    char partname[PATHSIZ], fullname[PATHSIZ];
    char buf[STR_SIZE];

    if ((fp = fopen(from, "r")) == NULL) {
	warn(NOPEN, from);
	return(OEH_BAD);
    }
    p->name = p->num = NULL;
    p->encrytest = NULL;
    p->count = 1;
    while ((kwd = nextkwd(fp, buf)) == PDONE);
    if (kwd == EOF) {
	fclose(fp);
	return(OEH_BAD);
    }
    if (strcmp(buf, "version:") && strcmp(buf, "content-version:")) {
	fclose(fp);
	return(OEH_NOT);
    }
    skiptokwd(fp);
    look_ahead = FALSE;
    while ((kwd = nextkwd(fp, buf)) == KEYWORD) { 
	for (i = 0; i < NOFIELDS; i++)
	    if (strcmp(buf, Parsetab[i].testring) == 0) {
		(*(Parsetab[i].func))(fp, p);
		break;
	    }
	if (i == NOFIELDS)
	    skiptokwd(fp);
	if (i > PARTFIELDS)
	    break;
    }
    if (((parts = obj_to_parts(p->num)) == NULL) && ((unpack == NUM_CHECK) || (p->count > 1))) {
	fclose(fp);
	return(OBJ_UNK);
    }
    if ((unpack == NUM_CHECK) && (parts->int_class & CL_OEU)) {
	fclose(fp);
	return(OBJ_OEU);
    }
    if (parts->int_class & CL_OEU)
	parts = NULL;
    if (!look_ahead)
	while ((kwd = nextkwd(fp, buf)) == PDONE);
    if (kwd == EOF) {
	fclose(fp);
	return(OEH_BAD);
    }
    while (kwd == KEYWORD) {
	if (strcmp(buf, "part-type:") == 0) {
	    type = uptokwd(fp);
	    kwd = nextkwd(fp, buf);
	}
	else if (strcmp(buf, "encrypted:") == 0) {
	    skiptokwd(fp);
	    kwd = nextkwd(fp, buf);
	}
	else if (strcmp(buf, "encryption-test:") == 0) {
	    encrytest(fp, p);
	    kwd = nextkwd(fp, buf);
	}
	else if (strcmp(buf, "part-encoding:") == 0) {
	    enc = uptokwd(fp);
	    if (strncmp(enc, "ascii", 5) && strncmp(enc, "binary", 6)) {
		fclose(fp);
		return(ENC_BAD);
	    }
	    kwd = nextkwd(fp, buf);
	}
	else if (strcmp(buf, "encoding-algorithm:") == 0) {
	    char *encod;

	    encod = uptokwd(fp);
	    if (strncmp(encod, "btoa", 4) || strncmp(enc, "binary", 6)) {
		fclose(fp);
		return(ENC_BAD);
	    }
	    kwd = nextkwd(fp, buf);
	}
	else if (strcmp(buf, "part-length:") == 0) {
	    length = getnum(fp, SKIP);
	    if ((unpack == READ_HEADER) || ((unpack == NUM_CHECK) && p->encrytest))
		break;
#ifndef JUSTCHECK
	    if (!parts) {
		if (strcmp(enc, "binary") == 0)
		    rm_atob(fp, p->file);
		else {
		    if ((fp2 = fopen(p->file, "w")) == NULL) {
			warn(NOPEN, p->file);
			fclose(fp);
			return(OEH_BAD);
		    };
		    for (i = 0; (i < length) && ((c = getc(fp)) != EOF); i++)
			putc(c, fp2);
		    fclose(fp2);
		}
		while ((kwd = nextkwd(fp, buf)) == PDONE);
		continue;

	    }
	    if (parts->numparts > 1) {
		if (type)
		    for (apart = opt_next_part(parts), i = 0;
			(i < MAXPARTS) && (strcmp(apart->part_name, type) != 0) &&apart;
			 i++, apart = opt_next_part(NULL));
		if (!type || i == MAXPARTS) {
		    fclose(fp);
		    return(PART_BAD);
		}
	    }
	    else
		apart = opt_next_part(parts);
	    sprintf(partname, apart->part_template, filename(p->file));
	    strcpy(fullname, p->file);
	    strcpy(filename(fullname), partname);
	    if ((apart->part_flags & PRT_BIN) || p->encrytest) {
		rm_atob(fp, fullname);
	    }
	    else {
		if ((fp2 = fopen(fullname, "w")) == NULL) {
		    warn(NOPEN, fullname);
		    fclose(fp);
		    return(OEH_BAD);
		}
		for (i = 0; (i < length) && ((c = getc(fp)) != EOF); i++)
		    putc(c, fp2);
		fclose(fp2);
	    }
	    while ((kwd = nextkwd(fp, buf)) == PDONE);
#endif				/* JUSTCHECK */
	}
	else {
	    skiptokwd(fp);
	    kwd = nextkwd(fp, buf);
	}
    }
    fclose(fp);
    return(0);
}
static void
encrytest(fp, p)
FILE *fp;
struct oeh *p;
{
	p->encrytest = uptokwd(fp);
}
static int
obj_num(fp, p)
FILE *fp;
struct oeh *p;
{
	if (skipspace(fp) == KEYWORD)
		p->num = NULL;
	else
		p->num = uptokwd(fp);
	return(KEYWORD);
}
static int
obj_type(fp, p)
FILE *fp;
struct oeh *p;
{
	if (skipspace(fp) == KEYWORD)
		p->name = NULL;
	else
		p->type = uptokwd(fp);
	return(KEYWORD);
}
static int
obj_name(fp, p)
FILE *fp;
struct oeh *p;
{
	if (skipspace(fp) == KEYWORD)
		p->name = NULL;
	else
		p->name = uptokwd(fp);
	return(KEYWORD);
}
static int
par_count(fp, p)
FILE *fp;
struct oeh *p;
{
	p->count = (int) getnum(fp, SKIP);
	return(KEYWORD);
}
