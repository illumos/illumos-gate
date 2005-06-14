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
 *	All Rights Reserved
 */

#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.5 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "but.h"
#include "wish.h"
#include "sizes.h"
#include "typetab.h"
#include "ifuncdefs.h"
#include "optabdefs.h"
#include "partabdefs.h"

extern size_t strlen();

char *
part_match(name, template)
char *name, *template;
{
    char pre[FILE_NAME_SIZ], suf[FILE_NAME_SIZ];
    char name1[FILE_NAME_SIZ];
    char *p;
    static char retstr[FILE_NAME_SIZ];
    int  matchlen = FILE_NAME_SIZ;
    int len;

    p = pre;

    while (*template && (*template != '%' || *(template+1) == '%')) {
	*p++ = *template++;
    }

    *p = '\0';

    if (*template == '%') {
	if (*(++template) == '.')
	    matchlen = atoi(++template);
	if (matchlen == 0)
	    matchlen = FILE_NAME_SIZ;
	while (*template && *template >= '0' && *template <= '9')
	    template++;
	if (*template == 's') {
	    template++;
	}
    }

    p = suf;

    while (*template && *template != '/')
	*p++ = *template++;

    *p = '\0';

    if (*template == '/') {
	if ((p = strchr(name, '/')) == NULL)
	    return(NULL);
	strncpy(name1, name, name-p);
	name1[name-p] = '\0';
    } else {
	strcpy(name1, name);
    }

    if (*pre)
    {
	if ((int)strlen(name1) < (int)strlen(pre) ||    /* EFT k16 */
	    strncmp(name1, pre, strlen(pre)) != 0)
	{
	    return(NULL);
	}
    }

    if (*suf)
    {
	if (!has_suffix(name1+strlen(pre), suf))
	{
	    return(NULL);
	}
    }
				/* EFT k16.. */
    if ((int)strlen(name1) > matchlen + (int)strlen(pre) + (int)strlen(suf))
    {
	return(NULL);
    }

    strncpy(retstr, name+strlen(pre), 
	    (len=strlen(name)-strlen(pre)-strlen(suf)));
    retstr[len] = '\0';

    if (*template == '/') {
	sprintf(name1, ++template, retstr);
	if (strcmp(++p, name1) != 0)
	    return(NULL);
    }
		
    return(retstr);
}

char *
part_construct(name, template)
char *name, *template;
{
	static char result[FILE_NAME_SIZ];

	sprintf(result, template, name, name);
	return(result);
}

char *
objparent(base, objtype)
char *base;
char *objtype;
{
	struct opt_entry *partab, *obj_to_parts();
	struct one_part *apart, *opt_next_part();

	if ((partab = obj_to_parts(objtype)) == NULL)
		return(NULL);
	apart = opt_next_part(partab);
	return(part_construct(base, apart->part_template));
}
