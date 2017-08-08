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
 *
 * nlsrequest(3):
 *
 *		Send service request message to remote listener
 *		on previously established virtual circuit to remote
 *		listener process.
 *
 *		If an error occurrs, t_errno will contain an error code.
 *
 *		Setting the external integer "_nlslog" to any non-zero
 *		value before calling nlsrequest,  will cause nlsrequest
 *		to print debug information on stderr.
 *
 *		client/server process pairs should include their own
 *		initial handshake to insure connectivity.
 *
 *		This version of nlsrequest includes the
 *		service request response message.
 */


#include	<stdio.h>
#include	<ctype.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<string.h>
#include	<stdlib.h>
#include	<sys/tiuser.h>
#include	"listen.h"

extern	int _nlslog;		/* non-zero allows use of stderr	*/
char *_nlsrmsg = (char *)0;
static char _nlsbuf[256];


int
nlsrequest(int fd, char *svc_code)
{
	int	len, err, flags;
	char 	buf[256];
	char	*p;
	int	ret;
	extern  int t_errno;

	t_errno = 0;		/* indicates a 'name' problem	*/
	buf[0] = 0;

	/*
	 * Validate service code
	 */

	if (!svc_code || !strlen(svc_code) ||
	    (strlen(svc_code) >= (size_t)SVC_CODE_SZ)) {
		if (_nlslog) {
			fprintf(stderr,
			    "nlsrequest: invalid service code format\n");
		}
		return (-1);
	}

	/*
	 * send protocol message requesting the service
	 */

	len = sprintf(buf, nls_v2_msg, svc_code) + 1; /* inc trailing null */

	if (t_snd(fd, buf, len, 0) < len) {
		if (_nlslog)
			t_error("t_snd of listener request message failed");
		return (-1);
	}

	p = _nlsbuf;
	len = 0;

	do {
		if (++len > sizeof (_nlsbuf)) {
			if (_nlslog) {
				fprintf(stderr,
				    "nlsrequest: _nlsbuf not large enough\n");
			}
			return (-1);
		}
		if (t_rcv(fd, p, sizeof (char), &flags) != sizeof (char)) {
			if (_nlslog) {
				t_error("t_rcv of listener response msg "
				    "failed");
			}
			return (-1);
		}

	} while (*p++ != '\0');


	if ((p = strtok(_nlsbuf, ":")) == NULL)
		goto parsefail;

	/*
	 * We ignore the version number here as we do not have any use for it.
	 * Previous versions of the code looked at it by calling atoi() on it,
	 * which did not mutate the actual string and did not use it.
	 */

	if ((p = strtok(NULL, ":")) ==  NULL)
		goto parsefail;
	ret = atoi(p);
	_nlsrmsg = p + strlen(p) + 1;
	if (ret && _nlslog)
		fprintf(stderr, "%s\n", _nlsrmsg); /* debug only */
	return (ret);

parsefail:
	if (_nlslog) {
		fprintf(stderr,
		    "nlsrequest: failed parse of response message\n");
	}
	return (-1);
}
