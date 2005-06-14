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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

#include	<stdio.h>
#include	<fcntl.h>

#define LOOKING		1
#define SKIPPING	2

char *
chgenv(file, name, val)
char	*file;
char	*name;
char	*val;
{
	char	inbuf[BUFSIZ];
	char	outbuf[BUFSIZ];
	register char	*p;
	char	*index;
	register int	c;
	register int	state;
	register FILE	*infp;
	register FILE	*outfp;
	int		len;
	char	*strnsave();
	char	*backslash();
	FILE	*tempfile();

	if ((outfp = tempfile(NULL, "w+")) == NULL)
		return NULL;
	setbuf(outfp, outbuf);
	if (val) {
		fputs(name, outfp);
		putc('=', outfp);
		len = 2 * strlen(val);
		fputs(p = backslash(strnsave(val, len), len), outfp);
		free(p);
		putc('\n', outfp);
	}
	if ((infp = fopen(file, "r+"))) {
		setbuf(infp, inbuf);
		state = LOOKING;
		index = name;
		for (c = getc(infp); c != EOF; c = getc(infp)) {
			if (state == SKIPPING) {
				if (c == '\n') {
					state = LOOKING;
					index = name;
				}
				continue;
			}
			if (state == LOOKING) {
				/* if we are in name */
				if (*index) {
					if (c == *index) {
						index++;
						continue;
					}
				}
				/* found name, look for "=" */
				else if (c == '=') {
					state = SKIPPING;
					continue;
				}
				/* failure, copy line to outfile */
				for (p = name; p < index; p++)
					putc(*p, outfp);
				state = 0;
			}
			if (c == '\n') {
				state = LOOKING;
				index = name;
			}
			putc(c, outfp);
		}
		fclose(infp);
	}
	{
		register int	fd;
		register int	n;

		if ((fd = open(file, O_WRONLY | O_CREAT | O_TRUNC, 0640)) >= 0) {
			fseek(outfp, 0L, 0);
			while ((n = fread(inbuf, 1, sizeof(inbuf), outfp)) > 0)
				write(fd, inbuf, n);
			close(fd);
		}
		else
			val = NULL;
	}
	fclose(outfp);
	return val;
}
