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

/*
 * chargen inetd service - both stream and dgram based.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/sysmacros.h>
#include <ctype.h>
#include <inetsvc.h>


#define	LINESIZE		72
#define	RINGSIZE		128


static	char	ring[RINGSIZE];
static	char	*endring;


static void
initring(void)
{
	unsigned char ch;

	endring = ring;

	for (ch = 0; ch <= RINGSIZE; ++ch) {
		if (isprint(ch))
			*endring++ = ch;
	}
}

static void
chargen_stream(int s, char *argv[])
{
	char	text[LINESIZE+2];
	int	i;
	char	*rp;
	char	*dp;
	char	*rs = ring;

	setproctitle("chargen", s, argv);

	for (;;) {
		if (rs >= endring)
			rs = ring;
		rp = rs++;
		dp = text;
		i = MIN(LINESIZE, endring - rp);
		(void) memmove(dp, rp, i);
		dp += i;
		if ((rp += i) >= endring)
			rp = ring;
		if (i < LINESIZE) {
			i = LINESIZE - i;
			(void) memmove(dp, rp, i);
			dp += i;
			if ((rp += i) >= endring)
				rp = ring;
		}

		*dp++ = '\r';
		*dp++ = '\n';

		if (safe_write(s, text, dp - text) != 0)
			break;
	}
}

/* ARGSUSED3 */
static void
chargen_dg(int s, const struct sockaddr *sap, int sa_size, const void *buf,
    size_t sz)
{
	char		text[LINESIZE+2];
	int		i;
	char		*rp;
	static char 	*rs = ring;

	rp = rs;
	if (rs++ >= endring)
		rs = ring;
	i = MIN(LINESIZE, endring - rp);
	(void) memmove(text, rp, i);
	if ((rp += i) >= endring)
		rp = ring;
	if (i < LINESIZE) {
		(void) memmove(text, rp, i);
		if ((rp += i) >= endring)
			rp = ring;
	}

	text[LINESIZE - 2] = '\r';
	text[LINESIZE - 1] = '\n';

	(void) safe_sendto(s, text, sizeof (text), 0, sap, sa_size);
}

int
main(int argc, char *argv[])
{
	opterr = 0;	/* disable getopt error msgs */

	initring();

	switch (getopt(argc, argv, "ds")) {
	case 'd':
		dg_template(chargen_dg, STDIN_FILENO, NULL, 0);
		break;
	case 's':
		chargen_stream(STDIN_FILENO, argv);
		break;
	default:
		return (1);
	}

	return (0);
}
