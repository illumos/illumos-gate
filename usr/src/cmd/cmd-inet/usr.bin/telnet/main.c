/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1988, 1990 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1988, 1990 Regents of the University of California.\n"
" All rights reserved.\n";
#endif /* not lint */

#ifndef lint
static char sccsid[] = "@(#)main.c	5.5 (Berkeley) 12/18/92";
#endif /* not lint */

#include <string.h>
#include <sys/types.h>

#include "ring.h"
#include "externs.h"
#include "defines.h"

/* These values need to be the same as defined in libtelnet/kerberos5.c */
/* Either define them in both places, or put in some common header file. */
#define	OPTS_FORWARD_CREDS		0x00000002
#define	OPTS_FORWARDABLE_CREDS		0x00000001

/*
 * This flag is incremented, if any of the
 * Kerberos command line options are used.
 */
int krb5auth_flag = 0;

/*
 * Initialize variables.
 */
int
tninit()
{
	init_terminal();

	init_network();

	if (init_telnet() == 0)
		return (0);

	init_sys();

	return (1);
}

#if	defined(USE_TOS)
#define	TELNET_OPTIONS	"8EKLS:X:acde:fFk:l:n:rt:x"
#else
#define	TELNET_OPTIONS	"8EKLX:acde:fFk:l:n:rt:x"
#endif	/* USE_TOS */

static void
usage()
{
	(void) fprintf(stderr, "Usage: %s %s\n",
		prompt,
		" [-8] [-E] [-K] [-L] [-a] [-c] [-d] [-f/-F] [-r] [-x]"
		"\n\t[-e char] [-k realm] [-l user] [-n tracefile] [-X atype]"
		"\n\t[host-name [port]]");
	exit(1);
}

/*
 * main.  Parse arguments, invoke the protocol or command parser.
 */


int
main(int argc, char *argv[])
{
	int ch;
	char *user;
	extern boolean_t auth_enable_encrypt;
	extern int forward_flags;

	/* Clear out things */
	if (tninit() == 0)
		return (EXIT_FAILURE);

	if (!isatty(fileno(stdin))) {
		setbuf(stdin, NULL);
	}
	if (!isatty(fileno(stdout))) {
		setbuf(stdout, NULL);
	}

	TerminalSaveState();

	if (prompt = strrchr(argv[0], '/'))
		++prompt;
	else
		prompt = argv[0];

	user = NULL;

	rlogin = (strncmp(prompt, "rlog", 4) == 0) ? '~' : _POSIX_VDISABLE;
	autologin = -1;

	while ((ch = getopt(argc, argv, TELNET_OPTIONS)) != EOF) {
		switch (ch) {
		case 'K':
			autologin_set = 1;
			autologin = 0;
			krb5auth_flag++;
			break;
		case 'X':
			auth_disable_name(optarg);
			krb5auth_flag++;
			break;
		case 'a':
			autologin_set = 1;
			autologin = 1;
			krb5auth_flag++;
			break;
		case 'f':
			if (forward_flags & OPTS_FORWARD_CREDS) {
			    (void) fprintf(stderr, gettext(
				"%s: Only one of -f "
				"and -F allowed.\n"), prompt);
			    usage();
			}
			forward_flags |= OPTS_FORWARD_CREDS;
			forward_flag_set = 1;
			krb5auth_flag++;
			break;
		case 'F':
			if (forward_flags & OPTS_FORWARD_CREDS) {
			    (void) fprintf(stderr, gettext(
				"%s: Only one of -f "
				"and -F allowed.\n"), prompt);
			    usage();
			}
			forward_flags |= OPTS_FORWARD_CREDS;
			forward_flags |= OPTS_FORWARDABLE_CREDS;
			forwardable_flag_set = 1;
			forward_flag = 1;
			krb5auth_flag++;
			break;
		case 'k':
			set_krb5_realm(optarg);
			krb5auth_flag++;
			break;
		case 'x':
			if (krb5_privacy_allowed()) {
				encrypt_auto(1);
				decrypt_auto(1);
				wantencryption = B_TRUE;
				autologin = 1;
				autologin_set = 1;
				auth_enable_encrypt = B_TRUE;
				encrypt_flag_set = 1;
				krb5auth_flag++;
			} else {
				(void) fprintf(stderr, gettext(
					"%s: Encryption not supported.\n"),
					prompt);
				exit(1);
			}
			break;

		/* begin common options */
		case '8':
			eight = 3;	/* binary output and input */
			break;
		case 'E':
			escape_valid = B_FALSE;
			rlogin = escape = _POSIX_VDISABLE;
			break;
		case 'L':
			eight |= 2;	/* binary output only */
			break;
#if USE_TOS
		case 'S':
			(void) fprintf(stderr,
			    "%s: Warning: -S ignored, no parsetos() support.\n",
			    prompt);
			break;
#endif /* USE_TOS */
		case 'c':
			skiprc = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'e':
			escape_valid = B_TRUE;
			set_escape_char(optarg);
			break;
		case 'l':
			autologin_set = 1;
			autologin = 1;
			user = optarg;
			break;
		case 'n':
			SetNetTrace(optarg);
			break;
		case 'r':
			rlogin = '~';
			break;
		case 't':
			(void) fprintf(stderr,
			    "%s: Warning: -t ignored, no TN3270 support.\n",
			    prompt);
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}
	if (autologin == -1)
		autologin = (rlogin == _POSIX_VDISABLE) ? 0 : 1;

	argc -= optind;
	argv += optind;

	if (argc) {
		char *args[7], **argp = args;

		if (argc > 2)
			usage();
		*argp++ = prompt;
		if (user) {
			*argp++ = "-l";
			*argp++ = user;
		}
		*argp++ = argv[0];		/* host */
		if (argc > 1)
			*argp++ = argv[1];	/* port */
		*argp = 0;

		if (setjmp(toplevel) != 0)
			Exit(EXIT_SUCCESS);
		if (tn(argp - args, args) == 1)
			return (EXIT_SUCCESS);
		else
			return (EXIT_FAILURE);
	}
	(void) setjmp(toplevel);
	for (;;) {
		command(1, 0, 0);
	}
}
