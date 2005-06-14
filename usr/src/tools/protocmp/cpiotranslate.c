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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * This utility takes a list of arguments specifying directories with
 * packages, and a cpio archive on standard input.  Standard output
 * will have a modified version of the cpio archive with mode, uid,
 * and gid fixed according to the packaging.  Standard error will list
 * the files that don't have corresponding packaging information.
 *
 * This utility supports "ASC" (cpio -c; "070701") type archives only.
 * This is what the mkbfu utility uses.
 *
 * It assumes that the local system architecture and the proto area
 * architecture are the same.  The wrong packages will be used if this
 * is not true.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <archives.h>
#include <string.h>

#include "list.h"
#include "protodir.h"
#include "proto_list.h"
#include "exception_list.h"
#include "stdusers.h"

static const char *myname;

static elem_list list;

#define	MAX_EXCEPT_LIST	5
static const char *except_file[MAX_EXCEPT_LIST];
static int except_count;

static void
usage(void)
{
	(void) fprintf(stderr, "usage: %s [-v] [-e except] pkgdir/list...\n",
	    myname);
	exit(1);
}

int
main(int argc, char **argv)
{
	char buffer[65536];
	elem elt;
	elem *ep;
	int hsize;
	ulong_t mode, filesize, namesize;
	size_t nsize;
	int uid, gid;
	char extra;
	struct stat sb;
	int chr;
	boolean_t trailer_copy;
	int errflg = 0;
	int verbose = 0;
	size_t inoffset;
	boolean_t no_unknowns;

	if ((myname = *argv) == NULL)
		myname = "cpiotranslate";

	while (errflg == 0 && (chr = getopt(argc, argv, "ve:")) != EOF) {
		switch (chr) {
		case 'v':
			verbose++;
			break;
		case 'e':
			if (except_count >= MAX_EXCEPT_LIST)
				errflg++;
			else
				except_file[except_count++] = optarg;
			break;
		default:
			errflg++;
			break;
		}
	}

	if (errflg != 0)
		usage();

	/* Allows selection of previous BFU behavior */
	no_unknowns = getenv("CPIOTRANSLATE_ALL") != NULL;

	init_list(&exception_list, HASH_SIZE);
	while (--except_count >= 0) {
		(void) read_in_exceptions(except_file[except_count], verbose);
	}

	/* Read in all the packaging information */
	init_list(&list, HASH_SIZE);
	while (optind < argc) {
		if (stat(argv[optind], &sb) == -1) {
			perror(argv[optind]);
		} else if (S_ISDIR(sb.st_mode)) {
			(void) read_in_protodir(argv[optind], &list, verbose);
		} else if (S_ISREG(sb.st_mode)) {
			(void) read_in_protolist(argv[optind], &list, verbose);
		} else {
			(void) fprintf(stderr, "%s: %s: bad type of object\n",
			    myname, argv[optind]);
			return (1);
		}

		optind++;
	}

	/* Process the cpio stream, one file at a time. */
	inoffset = 0;
	for (;;) {
		/* Read the next cpio header */
		hsize = fread(buffer, 1, ASCSZ, stdin);
		if (hsize == 0 || (hsize == -1 && feof(stdin))) {
			return (0);
		}
		if (hsize == -1) {
			perror("cpio input");
			break;
		}
		inoffset += hsize;
		if (hsize != ASCSZ) {
			(void) fprintf(stderr,
			    "%s: bad cpio header; only %d bytes\n",
			    myname, hsize);
			break;
		}

		/* Get the data we care about: mode and name sizes */
		if (sscanf(buffer+14, "%8lx%*32s%8lx%*32s%8lx", &mode,
		    &filesize, &namesize) != 3) {
			(void) fprintf(stderr,
			    "%s: bad cpio header; cannot read file size\n",
			    myname);
			if (verbose != 0)
				(void) fprintf(stderr, "Header: '%.*s'\n",
				    hsize, buffer);
			break;
		}

		/* Read in file name; account for padding */
		nsize = ASCSZ + namesize;
		if (namesize <= 1 || nsize >= sizeof (buffer)) {
			(void) fprintf(stderr,
			    "%s: bad cpio header; file name size %lu\n",
			    myname, namesize);
			break;
		}
		if ((nsize & 3) != 0)
			nsize += 4 - (nsize & 3);
		hsize = fread(buffer + ASCSZ, 1, nsize - ASCSZ, stdin);
		if (hsize == -1) {
			if (feof(stdin)) {
				(void) fprintf(stderr,
				    "%s: missing file name\n", myname);
			} else {
				perror("cpio input");
			}
			break;
		}
		inoffset += hsize;
		if (hsize != nsize - ASCSZ) {
			(void) fprintf(stderr, "%s: truncated file name\n",
			    myname);
			break;
		}
		buffer[nsize] = '\0';

#ifdef DEBUG
		if (verbose) {
			(void) fprintf(stderr,
			    "'%s' at offset %d: nlen %lu flen %lu\n",
			    buffer + ASCSZ, inoffset - nsize, namesize,
			    filesize);
		}
#endif

		/* Locate file name in packaging information database */
		(void) strlcpy(elt.name, buffer + ASCSZ, sizeof (elt.name));
		if (nsize == ASCSZ + 14 && filesize == 0 &&
		    strcmp(elt.name, "TRAILER!!!") == 0) {
			trailer_copy = B_TRUE;
			goto skip_update;
		}
		trailer_copy = B_FALSE;
		elt.arch = P_ISA;
		ep = find_elem(&list, &elt, FOLLOW_LINK);
		if (ep == NULL) {
			ep = find_elem_mach(&list, &elt, FOLLOW_LINK);
		}

		if (ep == NULL) {
			/*
			 * If it's on the exception list, remove it
			 * from the archive.  It's not part of the
			 * system.
			 */
			ep = find_elem(&exception_list, &elt, FOLLOW_LINK);
			if (ep != NULL) {
				if (verbose) {
					(void) fprintf(stderr,
					    "%s: %s: removed; exception list\n",
					    myname, elt.name);
				}
				/*
				 * Cannot use fseek here because input
				 * is usually a pipeline.
				 */
				if (filesize & 3)
					filesize += 4 - (filesize & 3);
				while (filesize > 0) {
					nsize = filesize;
					if (nsize > sizeof (buffer))
						nsize = sizeof (buffer);
					hsize = fread(buffer, 1, nsize, stdin);
					if (hsize == -1 && ferror(stdin)) {
						perror("cpio read");
						goto failure;
					}
					if (hsize != -1)
						inoffset += hsize;
					if (hsize != nsize) {
						(void) fprintf(stderr,
						    "%s: cpio file truncated\n",
						    myname);
						goto failure;
					}
					filesize -= hsize;
				}
				continue;
			}
		}

		/*
		 * No mode, user, group on symlinks in the packaging
		 * information.  Leave mode alone and set user and
		 * group to 'root' (0).  This is what a netinstall
		 * would do.
		 */
		if (ep == NULL) {
			uid = 0;
			gid = 3;

			if (!no_unknowns) {
				(void) fprintf(stderr,
				    "%s: %s: no packaging info\n", myname,
				    elt.name);
				goto skip_update;
			}
		} else if (ep->file_type == SYM_LINK_T) {
			uid = gid = 0;
		} else {
			mode = (mode & S_IFMT) | (ep->perm & ~S_IFMT);
			if ((uid = stdfind(ep->owner, usernames)) == -1) {
				(void) fprintf(stderr,
				    "%s: %s: user '%s' unknown\n", myname,
				    elt.name, ep->owner);
				uid = 0;
			}
			if ((gid = stdfind(ep->group, groupnames)) == -1) {
				(void) fprintf(stderr,
				    "%s: %s: group '%s' unknown\n", myname,
				    elt.name, ep->group);
				gid = 3;
			}
		}
		/* save character overwritten by sprintf's NUL terminator. */
		extra = buffer[38];
		/* snprintf not needed; cannot possibly overflow */
		(void) sprintf(buffer + 14, "%08lx%08x%08x", mode, uid, gid);
		/* recover char overwritten with NUL by sprintf above. */
		buffer[38] = extra;

		/* Write out the updated header information */
	skip_update:
		hsize = fwrite(buffer, 1, nsize, stdout);
		if (hsize == -1) {
			perror("cpio output");
			break;
		}
		if (hsize != nsize) {
			(void) fprintf(stderr, "%s: cpio output disk full\n",
			    myname);
			break;
		}

		if (trailer_copy) {
			while ((chr = getchar()) != EOF && chr != '0')
				(void) putchar(chr);
			if (chr == '0')
				(void) ungetc(chr, stdin);
			continue;
		}

		/* Copy the file data */
		while (filesize > 0) {
			if ((nsize = filesize) > sizeof (buffer))
				nsize = sizeof (buffer);
			if (nsize & 3)
				nsize += 4 - (nsize & 3);
			hsize = fread(buffer, 1, nsize, stdin);
			if (hsize == -1 && ferror(stdin)) {
				perror("cpio read");
				goto failure;
			}
			if (hsize != -1)
				inoffset += hsize;
			if (hsize != nsize) {
				(void) fprintf(stderr,
				    "%s: cpio file truncated\n",
				    myname);
				goto failure;
			}
			hsize = fwrite(buffer, 1, nsize, stdout);
			if (hsize == -1) {
				perror("cpio output");
				goto failure;
			}
			if (hsize != nsize) {
				(void) fprintf(stderr,
				    "%s: cpio output disk full\n", myname);
				goto failure;
			}
			if (hsize > filesize)
				break;
			filesize -= hsize;
		}
	}

failure:
	if (verbose != 0) {
		(void) fprintf(stderr, "%s: stopped at offset %u\n",
		    myname, inoffset);
	}

	return (1);
}
