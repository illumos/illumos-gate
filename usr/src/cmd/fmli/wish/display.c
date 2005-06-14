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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.6 */

#include <stdio.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "typetab.h"
#include "sizes.h"

int
glob_display (path)
char	*path;
{
    char	*vpath;
    char	title[PATHSIZ];
    struct	ott_entry *path_to_ott();
    char	*path_to_vpath();
    char	*bsd_path_to_title();
    struct	ott_entry *ott, *path_to_ott();

    if ((vpath = path_to_vpath(path)) == NULL) {
	if ( access(path,00) )
	    mess_temp(nstrcat(bsd_path_to_title(path,MESS_COLS - 16)," does not exist.",NULL));
	else
	    mess_temp(nstrcat(bsd_path_to_title(path,MESS_COLS - 20)," is not displayable.",NULL));
	return(FAIL);
    }
    ott = path_to_ott(path);
    sprintf(title, "%s/%s", parent(path), ott->dname);
    return(objop("OPEN", "TEXT", "$VMSYS/OBJECTS/Text.disp", vpath,
	bsd_path_to_title(title,MAX_TITLE - 3 - strlen(ott->display)),
	ott->display, NULL));
}
