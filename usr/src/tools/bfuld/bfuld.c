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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/mman.h>

#define	ISTRLEN		16
char istr[ISTRLEN + 1]    = "/usr/lib/ld.so.1";
char istretc[ISTRLEN + 1] = "/etc/lib/ld.so.1";
char bstr[ISTRLEN + 1]    = "/tmp/bfulib/bf.1";

#define	ISTRLEN2	12
char istr2[ISTRLEN2 + 1] = "/lib/ld.so.1";
char bstr2[ISTRLEN2 + 1] = "/tmp/bl/bf.1";

#ifdef __sparc

#define	LD64

#define	I64STRLEN	24
char i64str[I64STRLEN + 1] = "/usr/lib/sparcv9/ld.so.1";
char b64str[I64STRLEN + 1] = "/tmp/bfulib/sparcv9/bf.1";

#define	I64STRLEN2	20
char i64str2[I64STRLEN2 + 1] = "/lib/sparcv9/ld.so.1";
char b64str2[I64STRLEN2 + 1] = "/tmp/bl/sparcv9/bf.1";

#endif	/* __sparc */

#ifdef __i386

#define	LD64

#define	I64STRLEN	22
char i64str[I64STRLEN + 1] = "/usr/lib/amd64/ld.so.1";
char b64str[I64STRLEN + 1] = "/tmp/bfulib/amd64/bf.1";

#define	I64STRLEN2	18
char i64str2[I64STRLEN2 + 1] = "/lib/amd64/ld.so.1";
char b64str2[I64STRLEN2 + 1] = "/tmp/bl/amd64/bf.1";

#endif	/* __sparc */

#define	MINSIZE	12	/* MIN of ISTRLEN ISTRLEN2 I64STRLEN I64STRLEN2 */

int
main(int argc, char **argv)
{
	int i, f, fd;
	size_t size;
	char *map;

	for (f = 1; f < argc; f++) {
		boolean_t found = B_FALSE;

		fd = open(argv[f], O_RDWR);
		size = lseek(fd, 0, SEEK_END);
		map = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
		for (i = 0; i < size - MINSIZE - 1; i++) {
			if (i < size - ISTRLEN - 1 &&
			    (bcmp(&map[i], istr, ISTRLEN) == 0 ||
			    bcmp(&map[i], istretc, ISTRLEN) == 0)) {
				bcopy(bstr, &map[i], ISTRLEN);
				found = B_TRUE;
			}
			if (i < size - ISTRLEN2 - 1 &&
			    bcmp(&map[i], istr2, ISTRLEN2) == 0) {
				bcopy(bstr2, &map[i], ISTRLEN2);
				found = B_TRUE;
			}
#ifdef LD64
			if (i < size - I64STRLEN - 1 &&
			    bcmp(&map[i], i64str, I64STRLEN) == 0) {
				bcopy(b64str, &map[i], I64STRLEN);
				found = B_TRUE;
			}
			if (i < size - I64STRLEN2 - 1 &&
			    bcmp(&map[i], i64str2, I64STRLEN2) == 0) {
				bcopy(b64str2, &map[i], I64STRLEN2);
				found = B_TRUE;
			}
#endif
		}
		msync(map, size, MS_SYNC);
		munmap(map, size);
		close(fd);
		if (!found)
			fprintf(stderr, "bfuld: %s: no ld.so.1 found\n",
			    argv[f]);
	}
	return (0);
}
