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
 * Copyright 2014 Joyent, Inc.
 */

/*
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <err.h>

#include "rcv.h"

static int		icsubstr(char *s1, char *s2);

void 
receipt(struct message *mp)
{
	char	head[LINESIZE];
	char	buf[BUFSIZ];
	FILE	*pp, *fp;
	char	*mail, *s;


	if ((mail = value("sendmail")) == 0)
#ifdef SENDMAIL
		mail = SENDMAIL;
#else
		mail = MAIL;
#endif
	if (icsubstr(hfield("default-options", mp, addone), "/receipt")
	 || icsubstr(hfield(">to", mp, addto), "/receipt")) {
		snprintf(buf, sizeof (buf), "%s %s", mail, skin(nameof(mp)));
		if (pp = npopen(buf, "w")) {
			headline_t *hl;

			if (headline_alloc(&hl) != 0) {
				err(1, "could not allocate memory");
			}

			fp = setinput(mp);
			readline(fp, head);
			if (parse_headline(head, hl) != 0) {
				headline_reset(hl);
			}
			if (custr_len(hl->hl_date) > 0) {
				fprintf(pp, "Original-Date: %s\n",
				    custr_cstr(hl->hl_date));
			}
			if (s = hfield("message-id", mp, addone))
				fprintf(pp, "Original-Message-ID: %s\n", s);
			s = hfield("subject", mp, addone);
			fprintf(pp, "Subject: RR: %s\n", s ? s : "(none)");
			npclose(pp);
			headline_free(hl);
		}
	}
}

static int 
icsubstr(char *s1, char *s2)
{
	char	buf[LINESIZE];

	if (s1 && s2) {
		istrcpy(buf, sizeof (buf), s1);
		return substr(buf, s2) != -1;
	} else
		return 0;
}
