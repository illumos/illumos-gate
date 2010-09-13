/*
 * Copyright 1999 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980, 1986, 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that: (1) source distributions retain this entire copyright
 * notice and comment, and (2) distributions including binaries display
 * the following acknowledgement:  ``This product includes software
 * developed by the University of California, Berkeley and its contributors''
 * in the documentation or other materials provided with the distribution
 * and in all advertising materials mentioning features or use of this
 * software. Neither the name of the University nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/mntent.h>
#include <sys/vnode.h>
#include <pwd.h>
#include "fsck.h"
#include <sys/fs/udf_volume.h>
#include <locale.h>

extern void	errexit(char *, ...);

extern unsigned int largefile_count;

/*
 * Enter inodes into the cache.
 */
struct fileinfo *
cachefile(feblock, len)
	uint32_t feblock;
	uint32_t len;
{
	register struct fileinfo *inp;
	struct fileinfo **inpp;

	inpp = &inphash[feblock % listmax];
	for (inp = *inpp; inp; inp = inp->fe_nexthash) {
		if (inp->fe_block == feblock)
			break;
	}
	if (!inp) {
		if (inpnext >= inplast) {
			inpnext = (struct fileinfo *)calloc(FEGROW + 1,
				sizeof (struct fileinfo));
			if (inpnext == NULL)
				errexit(gettext("Cannot grow inphead list\n"));
			/* Link at extra entry so that we can find them */
			inplast->fe_nexthash = inpnext;
			inplast->fe_block = (uint32_t)-1;
			inplast = &inpnext[FEGROW];
		}
		inp = inpnext++;
		inp->fe_block = feblock;
		inp->fe_len = (uint16_t)len;
		inp->fe_lseen = 1;
		inp->fe_nexthash = *inpp;
		*inpp = inp;
		if (debug) {
		    (void) printf("cacheing %x\n", feblock);
		}
	} else {
		inp->fe_lseen++;
		if (debug) {
		    (void) printf("cache hit %x lcount %d lseen %d\n", feblock,
			inp->fe_lcount, inp->fe_lseen);
		}
	}
	return (inp);
}
