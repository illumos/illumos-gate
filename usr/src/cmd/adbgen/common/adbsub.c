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
 * Copyright (c) 1983-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

/*
 * Subroutines to be called by adbgen2.c, the C program generated
 * by adbgen1.c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

off_t last_off;
int warnings = 1;
int warns = 0;

/*
 * User claims offset is ok.
 * This usually follows call to another script, which we cannot handle.
 */
void
offsetok(void)
{
	last_off = -1;
}

/*
 * Get adb.s dot to the right offset.
 */
void
offset(off_t off)
{
	off_t off_diff;

	if (last_off == -1) {
		last_off = off;
		return;
	}
	off_diff = off - last_off;
	if (off_diff) {
		if (off_diff > 0) {
			if (off_diff > 1) {
				printf("%ld", off_diff);
			}
			printf("+");
		}
		if (off_diff < 0) {
			if (off_diff < -1) {
				printf("%ld", -off_diff);
			}
			printf("-");
		}
	}
	last_off = off;
}

/*
 * Emit the format command, return the size.
 */
int
do_fmt(char *acp)
{
	int rcount, width, sum, i;
	char *cp;

	cp = acp;
	sum = rcount = 0;
	do {
		while (*cp >= '0' && *cp <= '9') {
			rcount = rcount * 10 + *cp++ - '0';
		}
		if (rcount == 0) {
			rcount = 1;
		}
		switch (*cp) {
		case 'e':
		case 'E':
		case 'F':
		case 'g':
		case 'G':
		case 'J':
			width = 8;
			break;
		case 'K':
#ifdef	_LP64
			width = 8;
#else	/* _LP64 */
			width = 4;
#endif	/* _LP64 */
			break;
		case 'X':
		case 'O':
		case 'Q':
		case 'D':
		case 'U':
		case 'f':
		case 'Y':
		case 'p':
		case 'P':
			width = 4;
			break;
		case 'x':
		case 'o':
		case 'q':
		case 'd':
		case 'u':
			width = 2;
			break;
		case 'v':
		case 'V':
		case 'b':
		case 'B':
		case 'c':
		case 'C':
		case '+':
			width = 1;
			break;
		case 'I':
		case 'a':
		case 'A':
		case 't':
		case 'r':
		case 'n':
			width = 0;
			break;
		case '-':
			width = -1;
			break;
		case 's':
		case 'S':
		case 'i':
			if (warnings) {
				fprintf(stderr, "Unknown format size \"%s\", "
				    "assuming zero\n", acp);
				warns++;
			}
			width = 0;
			break;
		default:
			fprintf(stderr, "Unknown format size: %s\n", acp);
			exit(1);
		}
		for (i = 0; i < rcount; i++) {
			(void) putchar(*cp);
		}
		cp++;
		sum += width * rcount;
	} while (*cp);
	return (sum);
}

/*
 * Format struct member, checking size.
 */
void
format(char *name, size_t size, char *fmt)
{
	int fs;

	fs = do_fmt(fmt);
	if (fs != size && warnings) {
		fprintf(stderr,
		    "warning: \"%s\" size is %ld, \"%s\" width is %d\n",
		    name, size, fmt, fs);
		warns++;
	}
	last_off += fs;
}

/*
 * Get the value at offset based on base.
 */
void
indirect(off_t offset, size_t size, char *base, char *member)
{
	if (size == 8 || size == 4) {
		if (offset == 0) {
			printf("*%s", base);
		} else {
			printf("*(%s+0t%ld)", base, offset);
		}
	} else if (size == 2) {
		if (offset == 2) {
			printf("(*%s&0xffff)", base);
		} else {
			printf("(*(%s+0t%ld)&0xffff)", base, offset - 2);
		}
	} else if (size == 1) {
		if (offset == 3) {
			printf("(*%s&0xff)", base);
		} else {
			if ((offset & 0x1) == 0x1) {
				printf("(*(%s+0t%ld)&0xff)", base, offset - 3);
			} else {
				printf("((*(%s+0t%ld)&0xff00)/0x100)",
				    base, offset - 2);
			}
		}
	} else {
		fprintf(stderr, "Indirect size %ld not 1, 2, or 4: %s\n",
		    size, member);
		exit(1);
	}
}
