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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.8 */

#include <stdio.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "typetab.h"
#include "sizes.h"

extern int Vflag;

struct ott_entry *
path_to_ott(path)
char	*path;
{
    register char	*name;
    register struct ott_entry	*entry;
    struct ott_entry	*name_to_ott();
    struct ott_entry	*dname_to_ott();
    char	*filename();
    char	*parent();
    char	*nstrcat();
    char	*path_to_title();

    if (make_current(parent(path)) == O_FAIL) {
	if (Vflag)
	    mess_temp(nstrcat("Could not open folder ",
			      path_to_title(parent(path), NULL, MESS_COLS-22), NULL));
	else
	    mess_temp("Command unknown, please try again");
	return(NULL);
    }
    if ((entry = name_to_ott(name = filename(path))) == NULL &&
	(entry = dname_to_ott(name)) == NULL) {
 /*
  * Backedup the changes to test the valid fmli name
  */
  /*
	if ( strncmp("Text", name, 4) == 0 ||
	     strncmp("Menu", name, 4) == 0 ||
	     strncmp("Form", name, 4) == 0 )    */
  /* Changed the message. Removed the word object  */
	    mess_temp(nstrcat("Could not access ", name, NULL));
  /*
	else
	    mess_temp("Command unknown, please try again");   */
	return(NULL);
    }
    return(entry);
}
