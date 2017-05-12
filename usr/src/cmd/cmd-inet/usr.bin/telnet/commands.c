/*
 * Copyright (c) 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>

#include <signal.h>
#include <netdb.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <strings.h>

#include <arpa/telnet.h>
#include <arpa/inet.h>

#include "general.h"

#include "ring.h"

#include "externs.h"
#include "defines.h"
#include "types.h"

extern	char *telnet_krb5_realm;
extern	void krb5_profile_get_options(char *, char *,
		profile_options_boolean*);

#include <k5-int.h>
#include <profile/prof_int.h>

profile_options_boolean config_file_options[] = {
	{ "forwardable", &forwardable_flag, 0},
	{ "forward", &forward_flag, 0},
	{ "encrypt", &encrypt_flag, 0 },
	{ "autologin", &autologin, 0 },
	{ NULL, NULL, 0}
};

#include <netinet/ip.h>

/*
 * Number of maximum IPv4 gateways user can specify. This number is limited by
 * the maximum size of the IPv4 options in the IPv4 header.
 */
#define	MAX_GATEWAY	8
/*
 * Number of maximum IPv6 gateways user can specify. This number is limited by
 * the maximum header extension length of the IPv6 routing header.
 */
#define	MAX_GATEWAY6	127
#define	MAXMAX_GATEWAY	MAX(MAX_GATEWAY, MAX_GATEWAY6)

/*
 * Depending on the address resolutions of the target and gateways,
 * we determine which addresses of the target we'll try connecting to.
 */
#define	ALL_ADDRS	0	/* try all addrs of target */
#define	ONLY_V4		1	/* try only IPv4 addrs of target */
#define	ONLY_V6		2	/* try only IPv6 addrs of target */

#if defined(USE_TOS)
int tos = -1;
#endif

char	*hostname;
static char _hostname[MAXHOSTNAMELEN];

static int send_tncmd(void (*func)(), char *, char *);
static void call(int n_ptrs, ...);
static int cmdrc(char *, char *);

typedef struct {
	char	*name;		/* command name */
	char	*help;		/* help string (NULL for no help) */
	int	(*handler)();	/* routine which executes command */
	int	needconnect;	/* Do we need to be connected to execute? */
} Command;

/*
 * storage for IPv6 and/or IPv4 addresses of gateways
 */
struct gateway {
	struct in6_addr	gw_addr6;
	struct in_addr	gw_addr;
};

/*
 * IPv4 source routing option.
 * In order to avoid padding for the alignment of IPv4 addresses, ipsr_addrs
 * is defined as a 2-D array of uint8_t, instead of 1-D array of struct in_addr.
 * If it were defined as "struct in_addr ipsr_addrs[1]", "ipsr_ptr" would be
 * followed by one byte of padding to avoid misaligned struct in_addr.
 */
struct ip_sourceroute {
	uint8_t ipsr_code;
	uint8_t ipsr_len;
	uint8_t ipsr_ptr;
	/* up to 9 IPv4 addresses */
	uint8_t ipsr_addrs[1][sizeof (struct in_addr)];
};

static char *line = NULL;
static unsigned linesize = 0;
static int margc;
static char **margv = NULL;
static unsigned margvlen = 0;
static int doing_rc = 0;   /* .telnetrc file is being read and processed */

static void
Close(int *fd)
{
	if (*fd != -1) {
		(void) close(*fd);
		*fd = -1;
	}
}

static void
Free(char **p)
{
	if (*p != NULL) {
		free(*p);
		*p = NULL;
	}
}

static void
FreeHostnameList(char *list[])
{
	unsigned i;
	for (i = 0; i <= MAXMAX_GATEWAY && list[i] != NULL; i++)
		Free(&list[i]);
}

#define	MARGV_CHUNK_SIZE 8

static void
set_argv(str)
char *str;
{
	if (margc == margvlen) {
		char **newmargv;

		margvlen += MARGV_CHUNK_SIZE;

		if ((newmargv = realloc(margv, margvlen * sizeof (char *)))
			== NULL)
			ExitString("telnet: no space for arguments",
				EXIT_FAILURE);

		margv = newmargv;
	}

	margv[margc] = str;
	if (str != NULL)
		margc++;
}

static void
makeargv()
{
	char *cp, *cp2, c;
	boolean_t shellcmd = B_FALSE;

	margc = 0;
	cp = line;
	if (*cp == '!') {		/* Special case shell escape */
		set_argv("!");		/* No room in string to get this */
		cp++;
		shellcmd = B_TRUE;
	}
	while ((c = *cp) != '\0') {
		register int inquote = 0;
		while (isspace(c))
			c = *++cp;
		if (c == '\0')
			break;
		set_argv(cp);
		/*
		 * For the shell escape, put the rest of the line, less
		 * leading space, into a single argument, breaking out from
		 * the loop to prevent the rest of the line being split up
		 * into smaller arguments.
		 */
		if (shellcmd)
			break;
		for (cp2 = cp; c != '\0'; c = *++cp) {
			if (inquote) {
				if (c == inquote) {
					inquote = 0;
					continue;
				}
			} else {
				if (c == '\\') {
					if ((c = *++cp) == '\0')
						break;
				} else if (c == '"') {
					inquote = '"';
					continue;
				} else if (c == '\'') {
					inquote = '\'';
					continue;
				} else if (isspace(c))
					break;
			}
			*cp2++ = c;
		}
		*cp2 = '\0';
		if (c == '\0')
			break;
		cp++;
	}
	set_argv((char *)NULL);
}

/*
 * Make a character string into a number.
 *
 * Todo:  1.  Could take random integers (12, 0x12, 012, 0b1).
 */

	static int
special(s)
	register char *s;
{
	register char c;
	char b;

	switch (*s) {
	case '^':
		b = *++s;
		if (b == '?') {
		    c = b | 0x40;		/* DEL */
		} else {
		    c = b & 0x1f;
		}
		break;
	default:
		c = *s;
		break;
	}
	return (c);
}

/*
 * Construct a control character sequence
 * for a special character.
 */
	static char *
control(c)
	register cc_t c;
{
	static char buf[5];
	/*
	 * The only way I could get the Sun 3.5 compiler
	 * to shut up about
	 *	if ((unsigned int)c >= 0x80)
	 * was to assign "c" to an unsigned int variable...
	 * Arggg....
	 */
	register unsigned int uic = (unsigned int)c;

	if (uic == 0x7f)
		return ("^?");
	if (c == (cc_t)_POSIX_VDISABLE) {
		return ("off");
	}
	if (uic >= 0x80) {
		buf[0] = '\\';
		buf[1] = ((c>>6)&07) + '0';
		buf[2] = ((c>>3)&07) + '0';
		buf[3] = (c&07) + '0';
		buf[4] = 0;
	} else if (uic >= 0x20) {
		buf[0] = c;
		buf[1] = 0;
	} else {
		buf[0] = '^';
		buf[1] = '@'+c;
		buf[2] = 0;
	}
	return (buf);
}

/*
 * Same as control() except that its only used for escape handling, which uses
 * _POSIX_VDISABLE differently and is aided by the use of the state variable
 * escape_valid.
 */
	static char *
esc_control(c)
	register cc_t c;
{
	static char buf[5];
	/*
	 * The only way I could get the Sun 3.5 compiler
	 * to shut up about
	 *	if ((unsigned int)c >= 0x80)
	 * was to assign "c" to an unsigned int variable...
	 * Arggg....
	 */
	register unsigned int uic = (unsigned int)c;

	if (escape_valid == B_FALSE)
		return ("off");
	if (uic == 0x7f)
		return ("^?");
	if (uic >= 0x80) {
		buf[0] = '\\';
		buf[1] = ((c>>6)&07) + '0';
		buf[2] = ((c>>3)&07) + '0';
		buf[3] = (c&07) + '0';
		buf[4] = 0;
	} else if (uic >= 0x20) {
		buf[0] = c;
		buf[1] = 0;
	} else {
		buf[0] = '^';
		buf[1] = '@'+c;
		buf[2] = 0;
	}
	return (buf);
}

/*
 *	The following are data structures and routines for
 *	the "send" command.
 *
 */

struct sendlist {
	char	*name;		/* How user refers to it (case independent) */
	char	*help;		/* Help information (0 ==> no help) */
	int	needconnect;	/* Need to be connected */
	int	narg;		/* Number of arguments */
	int	(*handler)();	/* Routine to perform (for special ops) */
	int	nbyte;		/* Number of bytes to send this command */
	int	what;		/* Character to be sent (<0 ==> special) */
};


static int send_esc(void);
static int send_help(void);
static int send_docmd(char *);
static int send_dontcmd(char *);
static int send_willcmd(char *);
static int send_wontcmd(char *);

static struct sendlist Sendlist[] = {
	{ "ao",	"Send Telnet Abort output",		1, 0, 0, 2, AO },
	{ "ayt", "Send Telnet 'Are You There'",		1, 0, 0, 2, AYT },
	{ "b", 0,					1, 0, 0, 2, BREAK },
	{ "br", 0,					1, 0, 0, 2, BREAK },
	{ "break", 0,					1, 0, 0, 2, BREAK },
	{ "brk", "Send Telnet Break",			1, 0, 0, 2, BREAK },
	{ "ec",	"Send Telnet Erase Character",		1, 0, 0, 2, EC },
	{ "el",	"Send Telnet Erase Line",		1, 0, 0, 2, EL },
	{ "escape", "Send current escape character",	1, 0, send_esc, 1, 0 },
	{ "ga",	"Send Telnet 'Go Ahead' sequence",	1, 0, 0, 2, GA },
	{ "ip",	"Send Telnet Interrupt Process",	1, 0, 0, 2, IP },
	{ "intp", 0,					1, 0, 0, 2, IP },
	{ "interrupt", 0,				1, 0, 0, 2, IP },
	{ "intr",	0,				1, 0, 0, 2, IP },
	{ "nop", "Send Telnet 'No operation'",		1, 0, 0, 2, NOP },
	{ "eor", "Send Telnet 'End of Record'",		1, 0, 0, 2, EOR },
	{ "abort", "Send Telnet 'Abort Process'",	1, 0, 0, 2, ABORT },
	{ "susp", "Send Telnet 'Suspend Process'",	1, 0, 0, 2, SUSP },
	{ "eof", "Send Telnet End of File Character",	1, 0, 0, 2, xEOF },
	{ "synch", "Perform Telnet 'Synch operation'",	1, 0, dosynch, 2, 0 },
	{ "getstatus", "Send request for STATUS", 1, 0, get_status, 6, 0 },
	{ "?",	"Display send options",			0, 0, send_help, 0, 0 },
	{ "help",	0,				0, 0, send_help, 0, 0 },
	{ "do",	0,				0, 1, send_docmd, 3, 0 },
	{ "dont", 0,				0, 1, send_dontcmd, 3, 0 },
	{ "will", 0,				0, 1, send_willcmd, 3, 0 },
	{ "wont", 0,				0, 1, send_wontcmd, 3, 0 },
	{ 0 }
};

#define	GETSEND(name) ((struct sendlist *)genget(name, (char **)Sendlist, \
				sizeof (struct sendlist)))

static int
sendcmd(argc, argv)
	int  argc;
	char **argv;
{
	int count;	/* how many bytes we are going to need to send */
	int i;
	struct sendlist *s;	/* pointer to current command */
	int success = 0;
	int needconnect = 0;

	if (argc < 2) {
		(void) printf(
		    "need at least one argument for 'send' command\n");
		(void) printf("'send ?' for help\n");
		return (0);
	}
	/*
	 * First, validate all the send arguments.
	 * In addition, we see how much space we are going to need, and
	 * whether or not we will be doing a "SYNCH" operation (which
	 * flushes the network queue).
	 */
	count = 0;
	for (i = 1; i < argc; i++) {
		s = GETSEND(argv[i]);
		if (s == 0) {
			(void) printf("Unknown send argument '%s'\n'send ?' "
			    "for help.\n", argv[i]);
			return (0);
		} else if (Ambiguous(s)) {
			(void) printf("Ambiguous send argument '%s'\n'send ?' "
			    "for help.\n", argv[i]);
			return (0);
		}
		if (i + s->narg >= argc) {
			(void) fprintf(stderr,
			    "Need %d argument%s to 'send %s' "
			    "command.  'send %s ?' for help.\n",
			    s->narg, s->narg == 1 ? "" : "s", s->name, s->name);
			return (0);
		}
		count += s->nbyte;
		if (s->handler == send_help) {
			(void) send_help();
			return (0);
		}

		i += s->narg;
		needconnect += s->needconnect;
	}
	if (!connected && needconnect) {
		(void) printf("?Need to be connected first.\n");
		(void) printf("'send ?' for help\n");
		return (0);
	}
	/* Now, do we have enough room? */
	if (NETROOM() < count) {
		(void) printf("There is not enough room in the buffer "
		    "TO the network\n");
		(void) printf(
		    "to process your request.  Nothing will be done.\n");
		(void) printf("('send synch' will throw away most "
		    "data in the network\n");
		(void) printf("buffer, if this might help.)\n");
		return (0);
	}
	/* OK, they are all OK, now go through again and actually send */
	count = 0;
	for (i = 1; i < argc; i++) {
		if ((s = GETSEND(argv[i])) == 0) {
			(void) fprintf(stderr,
			    "Telnet 'send' error - argument disappeared!\n");
			(void) quit();
			/*NOTREACHED*/
		}
		if (s->handler) {
			count++;
			success += (*s->handler)((s->narg > 0) ? argv[i+1] : 0,
			    (s->narg > 1) ? argv[i+2] : 0);
			i += s->narg;
		} else {
			NET2ADD(IAC, s->what);
			printoption("SENT", IAC, s->what);
		}
	}
	return (count == success);
}

static int
send_esc()
{
	NETADD(escape);
	return (1);
}

static int
send_docmd(name)
	char *name;
{
	return (send_tncmd(send_do, "do", name));
}

static int
send_dontcmd(name)
	char *name;
{
	return (send_tncmd(send_dont, "dont", name));
}

static int
send_willcmd(name)
	char *name;
{
	return (send_tncmd(send_will, "will", name));
}

static int
send_wontcmd(name)
	char *name;
{
	return (send_tncmd(send_wont, "wont", name));
}

int
send_tncmd(func, cmd, name)
	void	(*func)();
	char	*cmd, *name;
{
	char **cpp;
	extern char *telopts[];
	register int val = 0;

	if (isprefix(name, "help") || isprefix(name, "?")) {
		register int col, len;

		(void) printf("Usage: send %s <value|option>\n", cmd);
		(void) printf("\"value\" must be from 0 to 255\n");
		(void) printf("Valid options are:\n\t");

		col = 8;
		for (cpp = telopts; *cpp; cpp++) {
			len = strlen(*cpp) + 3;
			if (col + len > 65) {
				(void) printf("\n\t");
				col = 8;
			}
			(void) printf(" \"%s\"", *cpp);
			col += len;
		}
		(void) printf("\n");
		return (0);
	}
	cpp = (char **)genget(name, telopts, sizeof (char *));
	if (Ambiguous(cpp)) {
		(void) fprintf(stderr,
		    "'%s': ambiguous argument ('send %s ?' for help).\n",
		    name, cmd);
		return (0);
	}
	if (cpp) {
		val = cpp - telopts;
	} else {
		register char *cp = name;

		while (*cp >= '0' && *cp <= '9') {
			val *= 10;
			val += *cp - '0';
			cp++;
		}
		if (*cp != 0) {
			(void) fprintf(stderr,
			    "'%s': unknown argument ('send %s ?' for help).\n",
			    name, cmd);
			return (0);
		} else if (val < 0 || val > 255) {
			(void) fprintf(stderr,
			    "'%s': bad value ('send %s ?' for help).\n",
			    name, cmd);
			return (0);
		}
	}
	if (!connected) {
		(void) printf("?Need to be connected first.\n");
		return (0);
	}
	(*func)(val, 1);
	return (1);
}

static int
send_help()
{
	struct sendlist *s;	/* pointer to current command */
	for (s = Sendlist; s->name; s++) {
		if (s->help)
			(void) printf("%-15s %s\n", s->name, s->help);
	}
	return (0);
}

/*
 * The following are the routines and data structures referred
 * to by the arguments to the "toggle" command.
 */

static int
lclchars()
{
	donelclchars = 1;
	return (1);
}

static int
togdebug()
{
	if (net > 0 &&
	    (SetSockOpt(net, SOL_SOCKET, SO_DEBUG, debug)) < 0) {
		perror("setsockopt (SO_DEBUG)");
	}
	return (1);
}


static int
togcrlf()
{
	if (crlf) {
		(void) printf(
		    "Will send carriage returns as telnet <CR><LF>.\n");
	} else {
		(void) printf(
		    "Will send carriage returns as telnet <CR><NUL>.\n");
	}
	return (1);
}

static int binmode;

static int
togbinary(val)
	int val;
{
	donebinarytoggle = 1;

	if (val >= 0) {
		binmode = val;
	} else {
		if (my_want_state_is_will(TELOPT_BINARY) &&
		    my_want_state_is_do(TELOPT_BINARY)) {
			binmode = 1;
		} else if (my_want_state_is_wont(TELOPT_BINARY) &&
		    my_want_state_is_dont(TELOPT_BINARY)) {
			binmode = 0;
		}
		val = binmode ? 0 : 1;
	}

	if (val == 1) {
		if (my_want_state_is_will(TELOPT_BINARY) &&
		    my_want_state_is_do(TELOPT_BINARY)) {
			(void) printf("Already operating in binary mode "
			    "with remote host.\n");
		} else {
			(void) printf(
			    "Negotiating binary mode with remote host.\n");
			tel_enter_binary(3);
		}
	} else {
		if (my_want_state_is_wont(TELOPT_BINARY) &&
		    my_want_state_is_dont(TELOPT_BINARY)) {
			(void) printf("Already in network ascii mode "
			    "with remote host.\n");
		} else {
			(void) printf("Negotiating network ascii mode "
			    "with remote host.\n");
			tel_leave_binary(3);
		}
	}
	return (1);
}

static int
togrbinary(val)
	int val;
{
	donebinarytoggle = 1;

	if (val == -1)
		val = my_want_state_is_do(TELOPT_BINARY) ? 0 : 1;

	if (val == 1) {
		if (my_want_state_is_do(TELOPT_BINARY)) {
			(void) printf("Already receiving in binary mode.\n");
		} else {
			(void) printf("Negotiating binary mode on input.\n");
			tel_enter_binary(1);
		}
	} else {
		if (my_want_state_is_dont(TELOPT_BINARY)) {
			(void) printf(
			    "Already receiving in network ascii mode.\n");
		} else {
			(void) printf(
			    "Negotiating network ascii mode on input.\n");
			    tel_leave_binary(1);
		}
	}
	return (1);
}

static int
togxbinary(val)
	int val;
{
	donebinarytoggle = 1;

	if (val == -1)
		val = my_want_state_is_will(TELOPT_BINARY) ? 0 : 1;

	if (val == 1) {
		if (my_want_state_is_will(TELOPT_BINARY)) {
			(void) printf("Already transmitting in binary mode.\n");
		} else {
			(void) printf("Negotiating binary mode on output.\n");
			tel_enter_binary(2);
		}
	} else {
		if (my_want_state_is_wont(TELOPT_BINARY)) {
			(void) printf(
			    "Already transmitting in network ascii mode.\n");
		} else {
			(void) printf(
			    "Negotiating network ascii mode on output.\n");
			tel_leave_binary(2);
		}
	}
	return (1);
}


static int togglehelp(void);
extern int auth_togdebug(int);

struct togglelist {
	char	*name;		/* name of toggle */
	char	*help;		/* help message */
	int	(*handler)();	/* routine to do actual setting */
	int	*variable;
	char	*actionexplanation;
};

static struct togglelist Togglelist[] = {
	{ "autoflush",
	"flushing of output when sending interrupt characters",
	    0,
		&autoflush,
		    "flush output when sending interrupt characters" },
	{ "autosynch",
	"automatic sending of interrupt characters in urgent mode",
	    0,
		&autosynch,
		    "send interrupt characters in urgent mode" },
	{ "autologin",
	"automatic sending of login and/or authentication info",
	    0,
		&autologin,
		    "send login name and/or authentication information" },
	{ "authdebug",
	"authentication debugging",
	    auth_togdebug,
		0,
		    "print authentication debugging information" },
	{ "autoencrypt",
	"automatic encryption of data stream",
	    EncryptAutoEnc,
		0,
		    "automatically encrypt output" },
	{ "autodecrypt",
	"automatic decryption of data stream",
	    EncryptAutoDec,
		0,
		    "automatically decrypt input" },
	{ "verbose_encrypt",
	"verbose encryption output",
	    EncryptVerbose,
		0,
		    "print verbose encryption output" },
	{ "encdebug",
	"encryption debugging",
	    EncryptDebug,
		0,
		    "print encryption debugging information" },
	{ "skiprc",
	"don't read ~/.telnetrc file",
	    0,
		&skiprc,
		    "skip reading of ~/.telnetrc file" },
	{ "binary",
	"sending and receiving of binary data",
	    togbinary,
		0,
		    0 },
	{ "inbinary",
	"receiving of binary data",
	    togrbinary,
		0,
		    0 },
	{ "outbinary",
	"sending of binary data",
	    togxbinary,
		0,
		    0 },
	{ "crlf",
	"sending carriage returns as telnet <CR><LF>",
	    togcrlf,
		&crlf,
		    0 },
	{ "crmod",
	"mapping of received carriage returns",
	    0,
		&crmod,
		    "map carriage return on output" },
	{ "localchars",
	"local recognition of certain control characters",
	    lclchars,
		&localchars,
		    "recognize certain control characters" },
	{ " ", "", 0 },		/* empty line */
	{ "debug",
	"debugging",
	    togdebug,
		&debug,
		    "turn on socket level debugging" },
	{ "netdata",
	"printing of hexadecimal network data (debugging)",
	    0,
		&netdata,
		    "print hexadecimal representation of network traffic" },
	{ "prettydump",
	"output of \"netdata\" to user readable format (debugging)",
	    0,
		&prettydump,
		    "print user readable output for \"netdata\"" },
	{ "options",
	"viewing of options processing (debugging)",
	    0,
		&showoptions,
		    "show option processing" },
	{ "termdata",
	"(debugging) toggle printing of hexadecimal terminal data",
	    0,
		&termdata,
		    "print hexadecimal representation of terminal traffic" },
	{ "?",
	0,
	    togglehelp },
	{ "help",
	0,
	    togglehelp },
	{ 0 }
};

static int
togglehelp()
{
	struct togglelist *c;

	for (c = Togglelist; c->name; c++) {
		if (c->help) {
			if (*c->help)
				(void) printf(
					"%-15s toggle %s\n", c->name, c->help);
			else
				(void) printf("\n");
		}
	}
	(void) printf("\n");
	(void) printf("%-15s %s\n", "?", "display help information");
	return (0);
}

static void
settogglehelp(set)
	int set;
{
	struct togglelist *c;

	for (c = Togglelist; c->name; c++) {
		if (c->help) {
			if (*c->help)
				(void) printf("%-15s %s %s\n", c->name,
				    set ? "enable" : "disable", c->help);
			else
				(void) printf("\n");
		}
	}
}

#define	GETTOGGLE(name) (struct togglelist *) \
		genget(name, (char **)Togglelist, sizeof (struct togglelist))

static int
toggle(argc, argv)
	int  argc;
	char *argv[];
{
	int retval = 1;
	char *name;
	struct togglelist *c;

	if (argc < 2) {
		(void) fprintf(stderr,
		    "Need an argument to 'toggle' command.  "
		    "'toggle ?' for help.\n");
		return (0);
	}
	argc--;
	argv++;
	while (argc--) {
		name = *argv++;
		c = GETTOGGLE(name);
		if (Ambiguous(c)) {
			(void) fprintf(stderr, "'%s': ambiguous argument "
			    "('toggle ?' for help).\n", name);
			return (0);
		} else if (c == 0) {
			(void) fprintf(stderr, "'%s': unknown argument "
			    "('toggle ?' for help).\n", name);
			return (0);
		} else {
			if (c->variable) {
				*c->variable = !*c->variable;	/* invert it */
				if (c->actionexplanation) {
			(void) printf("%s %s.\n",
				*c->variable ? "Will" : "Won't",
							c->actionexplanation);
				}
			}
			if (c->handler) {
				retval &= (*c->handler)(-1);
			}
		}
	}
	return (retval);
}

/*
 * The following perform the "set" command.
 */

#ifdef	USE_TERMIO
struct termio new_tc = { 0 };
#endif

struct setlist {
	char *name;		/* name */
	char *help;		/* help information */
	void (*handler)();
	cc_t *charp;		/* where it is located at */
};

static struct setlist Setlist[] = {
#ifdef	KLUDGELINEMODE
	{ "echo",  "character to toggle local echoing on/off", 0, &echoc },
#endif
	{ "escape", "character to escape back to telnet command mode", 0,
	    &escape },
	{ "rlogin", "rlogin escape character", 0, &rlogin },
	{ "tracefile", "file to write trace information to", SetNetTrace,
	    (cc_t *)NetTraceFile},
	{ " ", "" },
	{ " ", "The following need 'localchars' to be toggled true", 0, 0 },
	{ "flushoutput", "character to cause an Abort Output", 0,
	    termFlushCharp },
	{ "interrupt", "character to cause an Interrupt Process", 0,
	    termIntCharp },
	{ "quit", "character to cause an Abort process", 0, termQuitCharp },
	{ "eof", "character to cause an EOF ", 0, termEofCharp },
	{ " ", "" },
	{ " ", "The following are for local editing in linemode", 0, 0 },
	{ "erase", "character to use to erase a character", 0, termEraseCharp },
	{ "kill", "character to use to erase a line", 0, termKillCharp },
	{ "lnext", "character to use for literal next", 0,
	    termLiteralNextCharp },
	{ "susp", "character to cause a Suspend Process", 0, termSuspCharp },
	{ "reprint", "character to use for line reprint", 0, termRprntCharp },
	{ "worderase", "character to use to erase a word", 0, termWerasCharp },
	{ "start",	"character to use for XON", 0, termStartCharp },
	{ "stop",	"character to use for XOFF", 0, termStopCharp },
	{ "forw1",	"alternate end of line character", 0, termForw1Charp },
	{ "forw2",	"alternate end of line character", 0, termForw2Charp },
	{ "ayt",	"alternate AYT character", 0, termAytCharp },
	{ 0 }
};

static struct setlist *
getset(name)
    char *name;
{
	return ((struct setlist *)
	    genget(name, (char **)Setlist, sizeof (struct setlist)));
}

    void
set_escape_char(s)
    char *s;
{
	if (rlogin != _POSIX_VDISABLE) {
		rlogin = (s && *s) ? special(s) : _POSIX_VDISABLE;
		(void) printf("Telnet rlogin escape character is '%s'.\n",
					control(rlogin));
	} else {
		escape = (s && *s) ? special(s) : _POSIX_VDISABLE;
		(void) printf("Telnet escape character is '%s'.\n",
		    esc_control(escape));
	}
}

static int
setcmd(argc, argv)
	int  argc;
	char *argv[];
{
	int value;
	struct setlist *ct;
	struct togglelist *c;

	if (argc < 2 || argc > 3) {
		(void) printf(
			"Format is 'set Name Value'\n'set ?' for help.\n");
		return (0);
	}
	if ((argc == 2) &&
	    (isprefix(argv[1], "?") || isprefix(argv[1], "help"))) {
		for (ct = Setlist; ct->name; ct++)
			(void) printf("%-15s %s\n", ct->name, ct->help);
		(void) printf("\n");
		settogglehelp(1);
		(void) printf("%-15s %s\n", "?", "display help information");
		return (0);
	}

	ct = getset(argv[1]);
	if (ct == 0) {
		c = GETTOGGLE(argv[1]);
		if (c == 0) {
			(void) fprintf(stderr, "'%s': unknown argument "
			    "('set ?' for help).\n", argv[1]);
			return (0);
		} else if (Ambiguous(c)) {
			(void) fprintf(stderr, "'%s': ambiguous argument "
			    "('set ?' for help).\n", argv[1]);
			return (0);
		}
		if (c->variable) {
			if ((argc == 2) || (strcmp("on", argv[2]) == 0))
				*c->variable = 1;
			else if (strcmp("off", argv[2]) == 0)
				*c->variable = 0;
			else {
				(void) printf(
				    "Format is 'set togglename [on|off]'\n"
				    "'set ?' for help.\n");
				return (0);
			}
			if (c->actionexplanation) {
				(void) printf("%s %s.\n",
				    *c->variable? "Will" : "Won't",
				    c->actionexplanation);
			}
		}
		if (c->handler)
			(*c->handler)(1);
	} else if (argc != 3) {
		(void) printf(
			"Format is 'set Name Value'\n'set ?' for help.\n");
		return (0);
	} else if (Ambiguous(ct)) {
		(void) fprintf(stderr,
		    "'%s': ambiguous argument ('set ?' for help).\n", argv[1]);
		return (0);
	} else if (ct->handler) {
		(*ct->handler)(argv[2]);
		(void) printf(
		    "%s set to \"%s\".\n", ct->name, (char *)ct->charp);
	} else {
		if (strcmp("off", argv[2])) {
			value = special(argv[2]);
		} else {
			value = _POSIX_VDISABLE;
		}
		*(ct->charp) = (cc_t)value;
		(void) printf("%s character is '%s'.\n", ct->name,
		    control(*(ct->charp)));
	}
	slc_check();
	return (1);
}

static int
unsetcmd(argc, argv)
	int  argc;
	char *argv[];
{
	struct setlist *ct;
	struct togglelist *c;
	register char *name;

	if (argc < 2) {
		(void) fprintf(stderr, "Need an argument to 'unset' command.  "
		    "'unset ?' for help.\n");
		return (0);
	}
	if (isprefix(argv[1], "?") || isprefix(argv[1], "help")) {
		for (ct = Setlist; ct->name; ct++)
			(void) printf("%-15s %s\n", ct->name, ct->help);
		(void) printf("\n");
		settogglehelp(0);
		(void) printf("%-15s %s\n", "?", "display help information");
		return (0);
	}

	argc--;
	argv++;
	while (argc--) {
		name = *argv++;
		ct = getset(name);
		if (ct == 0) {
			c = GETTOGGLE(name);
			if (c == 0) {
				(void) fprintf(stderr, "'%s': unknown argument "
				    "('unset ?' for help).\n", name);
				return (0);
			} else if (Ambiguous(c)) {
				(void) fprintf(stderr,
				    "'%s': ambiguous argument "
				    "('unset ?' for help).\n", name);
				return (0);
			}
			if (c->variable) {
				*c->variable = 0;
				if (c->actionexplanation) {
					(void) printf("%s %s.\n",
					    *c->variable? "Will" : "Won't",
					    c->actionexplanation);
				}
			}
			if (c->handler)
				(*c->handler)(0);
		} else if (Ambiguous(ct)) {
			(void) fprintf(stderr, "'%s': ambiguous argument "
			    "('unset ?' for help).\n", name);
			return (0);
		} else if (ct->handler) {
			(*ct->handler)(0);
			(void) printf("%s reset to \"%s\".\n", ct->name,
			    (char *)ct->charp);
		} else {
			*(ct->charp) = _POSIX_VDISABLE;
			(void) printf("%s character is '%s'.\n", ct->name,
			    control(*(ct->charp)));
		}
	}
	return (1);
}

/*
 * The following are the data structures and routines for the
 * 'mode' command.
 */
extern int reqd_linemode;

#ifdef	KLUDGELINEMODE
extern int kludgelinemode;

static int
dokludgemode()
{
	kludgelinemode = 1;
	send_wont(TELOPT_LINEMODE, 1);
	send_dont(TELOPT_SGA, 1);
	send_dont(TELOPT_ECHO, 1);
	/*
	 * If processing the .telnetrc file, keep track of linemode and/or
	 * kludgelinemode requests which are processed before initial option
	 * negotiations occur.
	 */
	if (doing_rc)
		reqd_linemode = 1;
	return (1);
}
#endif

static int
dolinemode()
{
#ifdef	KLUDGELINEMODE
	if (kludgelinemode)
		send_dont(TELOPT_SGA, 1);
#endif
	send_will(TELOPT_LINEMODE, 1);
	send_dont(TELOPT_ECHO, 1);

	/*
	 * If processing the .telnetrc file, keep track of linemode and/or
	 * kludgelinemode requests which are processed before initial option
	 * negotiations occur.
	 */
	if (doing_rc)
		reqd_linemode = 1;
	return (1);
}

static int
docharmode()
{
#ifdef	KLUDGELINEMODE
	if (kludgelinemode)
		send_do(TELOPT_SGA, 1);
	else
#endif
		send_wont(TELOPT_LINEMODE, 1);
	send_do(TELOPT_ECHO, 1);
	reqd_linemode = 0;
	return (1);
}

static int
dolmmode(bit, on)
	int bit, on;
{
	unsigned char c;
	extern int linemode;

	if (my_want_state_is_wont(TELOPT_LINEMODE)) {
		(void) printf("?Need to have LINEMODE option enabled first.\n");
		(void) printf("'mode ?' for help.\n");
		return (0);
	}

	if (on)
		c = (linemode | bit);
	else
		c = (linemode & ~bit);
	lm_mode(&c, 1, 1);
	return (1);
}

static int
setmode(bit)
{
	return (dolmmode(bit, 1));
}

static int
clearmode(bit)
{
	return (dolmmode(bit, 0));
}

struct modelist {
	char	*name;		/* command name */
	char	*help;		/* help string */
	int	(*handler)();	/* routine which executes command */
	int	needconnect;	/* Do we need to be connected to execute? */
	int	arg1;
};

static int modehelp();

static struct modelist ModeList[] = {
	{ "character", "Disable LINEMODE option",	docharmode, 1 },
#ifdef	KLUDGELINEMODE
	{ "",	"(or disable obsolete line-by-line mode)", 0 },
#endif
	{ "line",	"Enable LINEMODE option",	dolinemode, 1 },
#ifdef	KLUDGELINEMODE
	{ "",	"(or enable obsolete line-by-line mode)", 0 },
#endif
	{ "", "", 0 },
	{ "",	"These require the LINEMODE option to be enabled", 0 },
	{ "isig",	"Enable signal trapping", setmode, 1, MODE_TRAPSIG },
	{ "+isig",	0,			setmode, 1, MODE_TRAPSIG },
	{ "-isig",	"Disable signal trapping", clearmode, 1, MODE_TRAPSIG },
	{ "edit",	"Enable character editing",	setmode, 1, MODE_EDIT },
	{ "+edit",	0,			setmode, 1, MODE_EDIT },
	{ "-edit",	"Disable character editing", clearmode, 1, MODE_EDIT },
	{ "softtabs",	"Enable tab expansion",	setmode, 1, MODE_SOFT_TAB },
	{ "+softtabs",	0,			setmode, 1, MODE_SOFT_TAB },
	{ "-softtabs",	"Disable tab expansion",
						clearmode, 1, MODE_SOFT_TAB },
	{ "litecho",	"Enable literal character echo",
						setmode, 1, MODE_LIT_ECHO },
	{ "+litecho",	0,			setmode, 1, MODE_LIT_ECHO },
	{ "-litecho",	"Disable literal character echo", clearmode, 1,
		MODE_LIT_ECHO },
	{ "help",	0,			modehelp, 0 },
#ifdef	KLUDGELINEMODE
	{ "kludgeline", 0,				dokludgemode, 1 },
#endif
	{ "", "", 0 },
	{ "?",	"Print help information",	modehelp, 0 },
	{ 0 },
};


static int
modehelp()
{
	struct modelist *mt;

	(void) printf("format is:  'mode Mode', where 'Mode' is one of:\n\n");
	for (mt = ModeList; mt->name; mt++) {
		if (mt->help) {
			if (*mt->help)
				(void) printf("%-15s %s\n", mt->name, mt->help);
			else
				(void) printf("\n");
		}
	}
	return (0);
}

#define	GETMODECMD(name) (struct modelist *) \
		genget(name, (char **)ModeList, sizeof (struct modelist))

static int
modecmd(argc, argv)
	int  argc;
	char *argv[];
{
	struct modelist *mt;

	if (argc != 2) {
		(void) printf("'mode' command requires an argument\n");
		(void) printf("'mode ?' for help.\n");
	} else if ((mt = GETMODECMD(argv[1])) == 0) {
		(void) fprintf(stderr,
		    "Unknown mode '%s' ('mode ?' for help).\n", argv[1]);
	} else if (Ambiguous(mt)) {
		(void) fprintf(stderr,
		    "Ambiguous mode '%s' ('mode ?' for help).\n", argv[1]);
	} else if (mt->needconnect && !connected) {
		(void) printf("?Need to be connected first.\n");
		(void) printf("'mode ?' for help.\n");
	} else if (mt->handler) {
		return (*mt->handler)(mt->arg1);
	}
	return (0);
}

/*
 * The following data structures and routines implement the
 * "display" command.
 */

static int
display(argc, argv)
	int  argc;
	char *argv[];
{
	struct togglelist *tl;
	struct setlist *sl;

#define	dotog(tl)	if (tl->variable && tl->actionexplanation) { \
			    if (*tl->variable) { \
				(void) printf("will"); \
			    } else { \
				(void) printf("won't"); \
			    } \
			    (void) printf(" %s.\n", tl->actionexplanation); \
			}

#define	doset(sl)   if (sl->name && *sl->name != ' ') { \
			if (sl->handler == 0) \
			    (void) printf("%-15s [%s]\n", sl->name, \
			    control(*sl->charp)); \
			else \
			    (void) printf("%-15s \"%s\"\n", sl->name, \
			    (char *)sl->charp); \
		    }

	if (argc == 1) {
		for (tl = Togglelist; tl->name; tl++) {
			dotog(tl);
		}
		(void) printf("\n");
		for (sl = Setlist; sl->name; sl++) {
			doset(sl);
		}
	} else {
		int i;

		for (i = 1; i < argc; i++) {
			sl = getset(argv[i]);
			tl = GETTOGGLE(argv[i]);
			if (Ambiguous(sl) || Ambiguous(tl)) {
				(void) printf(
				    "?Ambiguous argument '%s'.\n", argv[i]);
				return (0);
			} else if (!sl && !tl) {
				(void) printf(
				    "?Unknown argument '%s'.\n", argv[i]);
				return (0);
			} else {
				if (tl) {
					dotog(tl);
				}
				if (sl) {
				    doset(sl);
				}
			}
		}
	}
	optionstatus();
	(void) EncryptStatus();
	return (1);
#undef	doset
#undef	dotog
}

/*
 * The following are the data structures, and many of the routines,
 * relating to command processing.
 */

/*
 * Set the escape character.
 */
	static int
setescape(argc, argv)
	int argc;
	char *argv[];
{
	register char *arg;
	char *buf = NULL;

	if (argc > 2)
		arg = argv[1];
	else {
		(void) printf("new escape character: ");
		if (GetString(&buf, NULL, stdin) == NULL) {
			if (!feof(stdin)) {
				perror("can't set escape character");
				goto setescape_exit;
			}
		}
		arg = buf;
	}
	/* we place no limitations on what escape can be. */
	escape = arg[0];
	(void) printf("Escape character is '%s'.\n", esc_control(escape));
	(void) fflush(stdout);
setescape_exit:
	Free(&buf);
	return (1);
}

/*ARGSUSED*/
static int
togcrmod(argc, argv)
	int argc;
	char *argv[];
{
	crmod = !crmod;
	(void) printf(
	    "%s map carriage return on output.\n", crmod ? "Will" : "Won't");
	(void) fflush(stdout);
	return (1);
}

/*ARGSUSED*/
static int
suspend(argc, argv)
	int argc;
	char *argv[];
{
	setcommandmode();
	{
		unsigned short oldrows, oldcols, newrows, newcols;
		int err;

		err = (TerminalWindowSize(&oldrows, &oldcols) == 0) ? 1 : 0;
		(void) kill(0, SIGTSTP);
		/*
		 * If we didn't get the window size before the SUSPEND, but we
		 * can get them now (?), then send the NAWS to make sure that
		 * we are set up for the right window size.
		 */
		if (TerminalWindowSize(&newrows, &newcols) && connected &&
		    (err || ((oldrows != newrows) || (oldcols != newcols)))) {
			sendnaws();
		}
	}
	/* reget parameters in case they were changed */
	TerminalSaveState();
	setconnmode(0);
	return (1);
}

/*ARGSUSED*/
static int
shell(argc, argv)
	int argc;
	char *argv[];
{
	unsigned short oldrows, oldcols, newrows, newcols;
	int err;

	setcommandmode();

	err = (TerminalWindowSize(&oldrows, &oldcols) == 0) ? 1 : 0;
	switch (vfork()) {
	case -1:
		perror("Fork failed\n");
		break;

	case 0:
		{
		/*
		 * Fire up the shell in the child.
		 */
		register char *shellp, *shellname;

		shellp = getenv("SHELL");
		if (shellp == NULL)
			shellp = "/bin/sh";
		if ((shellname = strrchr(shellp, '/')) == 0)
			shellname = shellp;
		else
			shellname++;
		if (argc > 1)
			(void) execl(shellp, shellname, "-c", argv[1], 0);
		else
			(void) execl(shellp, shellname, 0);
		perror("Execl");
		_exit(EXIT_FAILURE);
		}
	default:
		(void) wait((int *)0);	/* Wait for the shell to complete */

		if (TerminalWindowSize(&newrows, &newcols) && connected &&
		(err || ((oldrows != newrows) || (oldcols != newcols)))) {
			sendnaws();
		}
		break;
	}
	return (1);
}

static int
bye(argc, argv)
	int  argc;	/* Number of arguments */
	char *argv[];	/* arguments */
{
	extern int resettermname;

	if (connected) {
		(void) shutdown(net, 2);
		(void) printf("Connection to %.*s closed.\n", MAXHOSTNAMELEN,
		    hostname);
		Close(&net);
		connected = 0;
		resettermname = 1;
		/* reset options */
		(void) tninit();
	}
	if ((argc != 2) || (strcmp(argv[1], "fromquit") != 0)) {
		longjmp(toplevel, 1);
		/* NOTREACHED */
	}
	return (1);			/* Keep lint, etc., happy */
}

/*VARARGS*/
int
quit()
{
	(void) call(3, bye, "bye", "fromquit");
	Exit(EXIT_SUCCESS);
	/*NOTREACHED*/
	return (1);
}

/*ARGSUSED*/
static int
logout(argc, argv)
	int argc;
	char *argv[];
{
	send_do(TELOPT_LOGOUT, 1);
	(void) netflush();
	return (1);
}


/*
 * The SLC command.
 */

struct slclist {
	char	*name;
	char	*help;
	void	(*handler)();
	int	arg;
};

static void slc_help();

static struct slclist SlcList[] = {
	{ "export",	"Use local special character definitions",
						slc_mode_export,	0 },
	{ "import",	"Use remote special character definitions",
						slc_mode_import,	1 },
	{ "check",	"Verify remote special character definitions",
						slc_mode_import,	0 },
	{ "help",	0,			slc_help,		0 },
	{ "?",	"Print help information",	slc_help,		0 },
	{ 0 },
};

static void
slc_help()
{
	struct slclist *c;

	for (c = SlcList; c->name; c++) {
		if (c->help) {
			if (*c->help)
				(void) printf("%-15s %s\n", c->name, c->help);
			else
				(void) printf("\n");
		}
	}
}

static struct slclist *
getslc(name)
	char *name;
{
	return ((struct slclist *)
	    genget(name, (char **)SlcList, sizeof (struct slclist)));
}

static int
slccmd(argc, argv)
	int  argc;
	char *argv[];
{
	struct slclist *c;

	if (argc != 2) {
		(void) fprintf(stderr,
		    "Need an argument to 'slc' command.  'slc ?' for help.\n");
		return (0);
	}
	c = getslc(argv[1]);
	if (c == 0) {
		(void) fprintf(stderr,
		    "'%s': unknown argument ('slc ?' for help).\n",
		    argv[1]);
		return (0);
	}
	if (Ambiguous(c)) {
		(void) fprintf(stderr,
		    "'%s': ambiguous argument ('slc ?' for help).\n", argv[1]);
		return (0);
	}
	(*c->handler)(c->arg);
	slcstate();
	return (1);
}

/*
 * The ENVIRON command.
 */

struct envlist {
	char	*name;
	char	*help;
	void	(*handler)();
	int	narg;
};

static struct env_lst *env_define(unsigned char *, unsigned char *);
static void env_undefine(unsigned char *);
static void env_export(unsigned char *);
static void env_unexport(unsigned char *);
static void env_send(unsigned char *);
#if defined(OLD_ENVIRON) && defined(ENV_HACK)
static void env_varval(unsigned char *);
#endif
static void env_list(void);

static void env_help(void);

static struct envlist EnvList[] = {
	{ "define",	"Define an environment variable",
						(void (*)())env_define,	2 },
	{ "undefine", "Undefine an environment variable",
						env_undefine,	1 },
	{ "export",	"Mark an environment variable for automatic export",
						env_export,	1 },
	{ "unexport", "Don't mark an environment variable for automatic export",
						env_unexport,	1 },
	{ "send",	"Send an environment variable", env_send,	1 },
	{ "list",	"List the current environment variables",
						env_list,	0 },
#if defined(OLD_ENVIRON) && defined(ENV_HACK)
	{ "varval", "Reverse VAR and VALUE (auto, right, wrong, status)",
						env_varval,    1 },
#endif
	{ "help",	0,			env_help,		0 },
	{ "?",	"Print help information",	env_help,		0 },
	{ 0 },
};

static void
env_help()
{
	struct envlist *c;

	for (c = EnvList; c->name; c++) {
		if (c->help) {
			if (*c->help)
				(void) printf("%-15s %s\n", c->name, c->help);
			else
				(void) printf("\n");
		}
	}
}

static struct envlist *
getenvcmd(name)
    char *name;
{
	return ((struct envlist *)
	    genget(name, (char **)EnvList, sizeof (struct envlist)));
}

static int
env_cmd(argc, argv)
	int  argc;
	char *argv[];
{
	struct envlist *c;

	if (argc < 2) {
		(void) fprintf(stderr,
		    "Need an argument to 'environ' command.  "
		    "'environ ?' for help.\n");
		return (0);
	}
	c = getenvcmd(argv[1]);
	if (c == 0) {
		(void) fprintf(stderr, "'%s': unknown argument "
		    "('environ ?' for help).\n", argv[1]);
		return (0);
	}
	if (Ambiguous(c)) {
		(void) fprintf(stderr, "'%s': ambiguous argument "
		    "('environ ?' for help).\n", argv[1]);
		return (0);
	}
	if (c->narg + 2 != argc) {
		(void) fprintf(stderr,
		    "Need %s%d argument%s to 'environ %s' command.  "
		    "'environ ?' for help.\n",
		    c->narg + 2 < argc ? "only " : "",
		    c->narg, c->narg == 1 ? "" : "s", c->name);
		return (0);
	}
	(*c->handler)(argv[2], argv[3]);
	return (1);
}

struct env_lst {
	struct env_lst *next;	/* pointer to next structure */
	struct env_lst *prev;	/* pointer to previous structure */
	unsigned char *var;	/* pointer to variable name */
	unsigned char *value;	/* pointer to variable value */
	int export;		/* 1 -> export with default list of variables */
	int welldefined;	/* A well defined variable */
};

static struct env_lst envlisthead;

static struct env_lst *
env_find(var)
	unsigned char *var;
{
	register struct env_lst *ep;

	for (ep = envlisthead.next; ep; ep = ep->next) {
		if (strcmp((char *)ep->var, (char *)var) == 0)
			return (ep);
	}
	return (NULL);
}

int
env_init()
{
#ifdef	lint
	char **environ = NULL;
#else	/* lint */
	extern char **environ;
#endif	/* lint */
	char **epp, *cp;
	struct env_lst *ep;

	for (epp = environ; *epp; epp++) {
		if (cp = strchr(*epp, '=')) {
			*cp = '\0';

			ep = env_define((unsigned char *)*epp,
					(unsigned char *)cp+1);
			if (ep == NULL)
				return (0);
			ep->export = 0;
			*cp = '=';
		}
	}
	/*
	 * Special case for DISPLAY variable.  If it is ":0.0" or
	 * "unix:0.0", we have to get rid of "unix" and insert our
	 * hostname.
	 */
	if (((ep = env_find((uchar_t *)"DISPLAY")) != NULL) &&
	    ((*ep->value == ':') ||
	    (strncmp((char *)ep->value, "unix:", 5) == 0))) {
		char hbuf[MAXHOSTNAMELEN];
		char *cp2 = strchr((char *)ep->value, ':');

		if (gethostname(hbuf, MAXHOSTNAMELEN) == -1) {
			perror("telnet: cannot get hostname");
			return (0);
		}
		hbuf[MAXHOSTNAMELEN-1] = '\0';
		cp = malloc(strlen(hbuf) + strlen(cp2) + 1);
		if (cp == NULL) {
			perror("telnet: cannot define DISPLAY variable");
			return (0);
		}
		(void) sprintf((char *)cp, "%s%s", hbuf, cp2);
		free(ep->value);
		ep->value = (unsigned char *)cp;
	}
	/*
	 * If LOGNAME is defined, but USER is not, then add
	 * USER with the value from LOGNAME.  We do this because the "accepted
	 * practice" is to always pass USER on the wire, but SVR4 uses
	 * LOGNAME by default.
	 */
	if ((ep = env_find((uchar_t *)"LOGNAME")) != NULL &&
		env_find((uchar_t *)"USER") == NULL) {
		if (env_define((unsigned char *)"USER", ep->value) != NULL)
			env_unexport((unsigned char *)"USER");
	}
	env_export((unsigned char *)"DISPLAY");
	env_export((unsigned char *)"PRINTER");

	return (1);
}

static struct env_lst *
env_define(var, value)
	unsigned char *var, *value;
{
	unsigned char *tmp_value;
	unsigned char *tmp_var;
	struct env_lst *ep;

	/*
	 * Allocate copies of arguments first, to make cleanup easier
	 * in the case of allocation errors.
	 */
	tmp_var = (unsigned char *)strdup((char *)var);
	if (tmp_var == NULL) {
		perror("telnet: can't copy environment variable name");
		return (NULL);
	}

	tmp_value = (unsigned char *)strdup((char *)value);
	if (tmp_value == NULL) {
		free(tmp_var);
		perror("telnet: can't copy environment variable value");
		return (NULL);
	}

	if (ep = env_find(var)) {
		if (ep->var)
			free(ep->var);
		if (ep->value)
			free(ep->value);
	} else {
		ep = malloc(sizeof (struct env_lst));
		if (ep == NULL) {
			perror("telnet: can't define environment variable");
			free(tmp_var);
			free(tmp_value);
			return (NULL);
		}

		ep->next = envlisthead.next;
		envlisthead.next = ep;
		ep->prev = &envlisthead;
		if (ep->next)
			ep->next->prev = ep;
	}
	ep->welldefined = opt_welldefined((char *)var);
	ep->export = 1;
	ep->var = tmp_var;
	ep->value = tmp_value;

	return (ep);
}

static void
env_undefine(var)
	unsigned char *var;
{
	register struct env_lst *ep;

	if (ep = env_find(var)) {
		ep->prev->next = ep->next;
		if (ep->next)
			ep->next->prev = ep->prev;
		if (ep->var)
			free(ep->var);
		if (ep->value)
			free(ep->value);
		free(ep);
	}
}

static void
env_export(var)
	unsigned char *var;
{
	register struct env_lst *ep;

	if (ep = env_find(var))
		ep->export = 1;
}

static void
env_unexport(var)
	unsigned char *var;
{
	register struct env_lst *ep;

	if (ep = env_find(var))
		ep->export = 0;
}

static void
env_send(var)
	unsigned char *var;
{
	register struct env_lst *ep;

	if (my_state_is_wont(TELOPT_NEW_ENVIRON)
#ifdef	OLD_ENVIRON
	    /* old style */ && my_state_is_wont(TELOPT_OLD_ENVIRON)
#endif
		/* no environ */) {
		(void) fprintf(stderr,
		    "Cannot send '%s': Telnet ENVIRON option not enabled\n",
									var);
		return;
	}
	ep = env_find(var);
	if (ep == 0) {
		(void) fprintf(stderr,
		    "Cannot send '%s': variable not defined\n", var);
		return;
	}
	env_opt_start_info();
	env_opt_add(ep->var);
	env_opt_end(0);
}

static void
env_list()
{
	register struct env_lst *ep;

	for (ep = envlisthead.next; ep; ep = ep->next) {
		(void) printf("%c %-20s %s\n", ep->export ? '*' : ' ',
					ep->var, ep->value);
	}
}

	unsigned char *
env_default(init, welldefined)
	int init;
{
	static struct env_lst *nep = NULL;

	if (init) {
		/* return value is not used */
		nep = &envlisthead;
		return (NULL);
	}
	if (nep) {
		while ((nep = nep->next) != NULL) {
			if (nep->export && (nep->welldefined == welldefined))
				return (nep->var);
		}
	}
	return (NULL);
}

	unsigned char *
env_getvalue(var)
	unsigned char *var;
{
	register struct env_lst *ep;

	if (ep = env_find(var))
		return (ep->value);
	return (NULL);
}

#if defined(OLD_ENVIRON) && defined(ENV_HACK)
static void
env_varval(what)
	unsigned char *what;
{
	extern int old_env_var, old_env_value, env_auto;
	int len = strlen((char *)what);

	if (len == 0)
		goto unknown;

	if (strncasecmp((char *)what, "status", len) == 0) {
		if (env_auto)
			(void) printf("%s%s", "VAR and VALUE are/will be ",
					"determined automatically\n");
		if (old_env_var == OLD_ENV_VAR)
			(void) printf(
			    "VAR and VALUE set to correct definitions\n");
		else
			(void) printf(
			    "VAR and VALUE definitions are reversed\n");
	} else if (strncasecmp((char *)what, "auto", len) == 0) {
		env_auto = 1;
		old_env_var = OLD_ENV_VALUE;
		old_env_value = OLD_ENV_VAR;
	} else if (strncasecmp((char *)what, "right", len) == 0) {
		env_auto = 0;
		old_env_var = OLD_ENV_VAR;
		old_env_value = OLD_ENV_VALUE;
	} else if (strncasecmp((char *)what, "wrong", len) == 0) {
		env_auto = 0;
		old_env_var = OLD_ENV_VALUE;
		old_env_value = OLD_ENV_VAR;
	} else {
unknown:
		(void) printf(
		    "Unknown \"varval\" command. (\"auto\", \"right\", "
		    "\"wrong\", \"status\")\n");
	}
}
#endif	/* OLD_ENVIRON && ENV_HACK */

/*
 * The AUTHENTICATE command.
 */

struct authlist {
	char	*name;
	char	*help;
	int	(*handler)();
	int	narg;
};

extern int auth_enable(char *);
extern int auth_disable(char *);
extern int auth_status(void);

static int auth_help(void);

static struct authlist AuthList[] = {
	{ "status",
	    "Display current status of authentication information",
	    auth_status,	0 },
	{ "disable",
	    "Disable an authentication type ('auth disable ?' for more)",
	    auth_disable,	1 },
	{ "enable",
	    "Enable an authentication type ('auth enable ?' for more)",
	    auth_enable,	1 },
	{ "help",	0,			auth_help,		0 },
	{ "?",	"Print help information",	auth_help,		0 },
	{ 0 },
};

static int
auth_help(void)
{
	struct authlist *c;

	for (c = AuthList; c->name; c++) {
		if (c->help) {
			if (*c->help)
				(void) printf("%-15s %s\n", c->name, c->help);
			else
				(void) printf("\n");
		}
	}
	return (0);
}


static int
auth_cmd(argc, argv)
	int  argc;
	char *argv[];
{
	struct authlist *c;

	if (argc < 2) {
		(void) fprintf(stderr, "Need an argument to 'auth' "
			"command.  'auth ?' for help.\n");
		return (0);
	}

	c = (struct authlist *)
		genget(argv[1], (char **)AuthList, sizeof (struct authlist));
	if (c == 0) {
		(void) fprintf(stderr,
		    "'%s': unknown argument ('auth ?' for help).\n",
		    argv[1]);
		return (0);
	}
	if (Ambiguous(c)) {
		(void) fprintf(stderr,
		    "'%s': ambiguous argument ('auth ?' for help).\n", argv[1]);
		return (0);
	}
	if (c->narg + 2 != argc) {
		(void) fprintf(stderr,
		    "Need %s%d argument%s to 'auth %s' command."
		    " 'auth ?' for help.\n",
		    c->narg + 2 < argc ? "only " : "",
		    c->narg, c->narg == 1 ? "" : "s", c->name);
		return (0);
	}
	return ((*c->handler)(argv[2], argv[3]));
}

/*
 * The FORWARD command.
 */

extern int forward_flags;

struct forwlist {
	char *name;
	char *help;
	int (*handler)();
	int f_flags;
};

static int forw_status(void);
static int forw_set(int);
static int forw_help(void);

static struct forwlist ForwList[] = {
	{"status",
		"Display current status of credential forwarding",
		forw_status, 0},
	{"disable",
		"Disable credential forwarding",
		forw_set, 0},
	{"enable",
		"Enable credential forwarding",
		forw_set, OPTS_FORWARD_CREDS},
	{"forwardable",
		"Enable credential forwarding of "
				"forwardable credentials",
		forw_set, OPTS_FORWARD_CREDS |	OPTS_FORWARDABLE_CREDS},
	{"help",
		0,
		forw_help, 0},
	{"?",
		"Print help information",
		forw_help, 0},
	{0},
};

static int
forw_status(void)
{
	if (forward_flags & OPTS_FORWARD_CREDS) {
		if (forward_flags & OPTS_FORWARDABLE_CREDS)
			(void) printf(gettext(
				"Credential forwarding of "
				"forwardable credentials enabled\n"));
		else
			(void) printf(gettext(
				"Credential forwarding enabled\n"));
	} else
		(void) printf(gettext("Credential forwarding disabled\n"));
	return (0);
}

static int
forw_set(int f_flags)
{
	forward_flags = f_flags;
	return (0);
}

static int
forw_help(void)
{
	struct forwlist *c;

	for (c = ForwList; c->name; c++) {
		if (c->help) {
			if (*c->help)
				(void) printf("%-15s %s\r\n", c->name, c->help);
			else
				(void) printf("\n");
		}
	}
	return (0);
}

static int
forw_cmd(int argc, char *argv[])
{
	struct forwlist *c;

	if (argc < 2) {
		(void) fprintf(stderr, gettext(
			"Need an argument to 'forward' "
			"command.  'forward ?' for help.\n"));
		return (0);
	}
	c = (struct forwlist *)genget(argv[1], (char **)ForwList,
		sizeof (struct forwlist));
	if (c == 0) {
		(void) fprintf(stderr, gettext(
		    "'%s': unknown argument ('forward ?' for help).\n"),
		    argv[1]);
		return (0);
	}
	if (Ambiguous(c)) {
		(void) fprintf(stderr, gettext(
		    "'%s': ambiguous argument ('forward ?' for help).\n"),
		    argv[1]);
		return (0);
	}
	if (argc != 2) {
		(void) fprintf(stderr, gettext(
		    "No arguments needed to 'forward %s' command.  "
		    "'forward ?' for help.\n"), c->name);
		return (0);
	}
	return ((*c->handler) (c->f_flags));
}

/*
 * The ENCRYPT command.
 */

struct encryptlist {
	char	*name;
	char	*help;
	int	(*handler)();
	int	needconnect;
	int	minarg;
	int	maxarg;
};

static int EncryptHelp(void);

static struct encryptlist EncryptList[] = {
	{ "enable", "Enable encryption. ('encrypt enable ?' for more)",
						EncryptEnable, 1, 1, 2 },
	{ "disable", "Disable encryption. ('encrypt disable ?' for more)",
						EncryptDisable, 0, 1, 2 },
	{ "type", "Set encryption type. ('encrypt type ?' for more)",
						EncryptType, 0, 1, 2 },
	{ "start", "Start encryption. ('encrypt start ?' for more)",
						EncryptStart, 1, 0, 1 },
	{ "stop", "Stop encryption. ('encrypt stop ?' for more)",
						EncryptStop, 1, 0, 1 },
	{ "input", "Start encrypting the input stream",
						EncryptStartInput, 1, 0, 0 },
	{ "-input", "Stop encrypting the input stream",
						EncryptStopInput, 1, 0, 0 },
	{ "output", "Start encrypting the output stream",
						EncryptStartOutput, 1, 0, 0 },
	{ "-output", "Stop encrypting the output stream",
						EncryptStopOutput, 1, 0, 0 },

	{ "status",	"Display current status of encryption information",
						EncryptStatus,	0, 0, 0 },
	{ "help",	0,
						EncryptHelp,	0, 0, 0 },
	{ "?",	"Print help information",	EncryptHelp,	0, 0, 0 },
	{ 0 },
};

static int
EncryptHelp(void)
{
	struct encryptlist *c;

	for (c = EncryptList; c->name; c++) {
		if (c->help) {
			if (*c->help)
				(void) printf("%-15s %s\n", c->name, c->help);
			else
				(void) printf("\n");
		}
	}
	return (0);
}

static int
encrypt_cmd(int  argc, char *argv[])
{
	struct encryptlist *c;

	if (argc < 2) {
		(void) fprintf(stderr, gettext(
			"Need an argument to 'encrypt' command.  "
			"'encrypt ?' for help.\n"));
		return (0);
	}

	c = (struct encryptlist *)
	    genget(argv[1], (char **)EncryptList, sizeof (struct encryptlist));
	if (c == 0) {
		(void) fprintf(stderr, gettext(
		    "'%s': unknown argument ('encrypt ?' for help).\n"),
		    argv[1]);
		return (0);
	}
	if (Ambiguous(c)) {
		(void) fprintf(stderr, gettext(
		    "'%s': ambiguous argument ('encrypt ?' for help).\n"),
		    argv[1]);
		return (0);
	}
	argc -= 2;
	if (argc < c->minarg || argc > c->maxarg) {
		if (c->minarg == c->maxarg) {
			(void) fprintf(stderr, gettext("Need %s%d %s "),
			c->minarg < argc ?
			gettext("only ") : "", c->minarg,
			c->minarg == 1 ?
			gettext("argument") : gettext("arguments"));
		} else {
			(void) fprintf(stderr,
			    gettext("Need %s%d-%d arguments "),
			c->maxarg < argc ?
			gettext("only ") : "", c->minarg, c->maxarg);
		}
		(void) fprintf(stderr, gettext(
		    "to 'encrypt %s' command.  'encrypt ?' for help.\n"),
		    c->name);
		return (0);
	}
	if (c->needconnect && !connected) {
		if (!(argc &&
		    (isprefix(argv[2], "help") || isprefix(argv[2], "?")))) {
			(void) printf(
			    gettext("?Need to be connected first.\n"));
			return (0);
		}
	}
	return ((*c->handler)(argc > 0 ? argv[2] : 0,
	    argc > 1 ? argv[3] : 0, argc > 2 ? argv[4] : 0));
}

/*
 * Print status about the connection.
 */
static int
status(int argc, char *argv[])
{
	if (connected) {
		(void) printf("Connected to %s.\n", hostname);
		if ((argc < 2) || strcmp(argv[1], "notmuch")) {
			int mode = getconnmode();

			if (my_want_state_is_will(TELOPT_LINEMODE)) {
				(void) printf(
				    "Operating with LINEMODE option\n");
				(void) printf(
				    "%s line editing\n", (mode&MODE_EDIT) ?
				    "Local" : "No");
				(void) printf("%s catching of signals\n",
				    (mode&MODE_TRAPSIG) ? "Local" : "No");
				slcstate();
#ifdef	KLUDGELINEMODE
			} else if (kludgelinemode &&
			    my_want_state_is_dont(TELOPT_SGA)) {
				(void) printf(
				    "Operating in obsolete linemode\n");
#endif
			} else {
				(void) printf(
					"Operating in single character mode\n");
				if (localchars)
					(void) printf(
					"Catching signals locally\n");
			}
			(void) printf("%s character echo\n", (mode&MODE_ECHO) ?
			    "Local" : "Remote");
			if (my_want_state_is_will(TELOPT_LFLOW))
				(void) printf("%s flow control\n",
				    (mode&MODE_FLOW) ? "Local" : "No");

			encrypt_display();
		}
	} else {
		(void) printf("No connection.\n");
	}
	if (rlogin != _POSIX_VDISABLE)
		(void) printf("Escape character is '%s'.\n", control(rlogin));
	else
		(void) printf(
		    "Escape character is '%s'.\n", esc_control(escape));
	(void) fflush(stdout);
	return (1);
}

/*
 * Parse the user input (cmd_line_input) which should:
 * - start with the target host, or with "@" or "!@" followed by at least one
 *   gateway.
 * - each host (can be literal address or hostname) can be separated by ",",
 *   "@", or ",@".
 * Note that the last host is the target, all the others (if any ) are the
 * gateways.
 *
 * Returns:	-1	if a library call fails, too many gateways, or parse
 *			error
 *		num_gw	otherwise
 * On successful return, hostname_list points to a list of hosts (last one being
 * the target, others gateways), src_rtng_type points to the type of source
 * routing (strict vs. loose)
 */
static int
parse_input(char *cmd_line_input, char **hostname_list, uchar_t *src_rtng_type)
{
	char hname[MAXHOSTNAMELEN + 1];
	char *cp;
	int gw_count;
	int i;

	gw_count = 0;
	cp = cmd_line_input;

	/*
	 * Defining ICMD generates the Itelnet binary, the special version of
	 * telnet which is used with firewall proxy.
	 * If ICMD is defined, parse_input will treat the whole cmd_line_input
	 * as the target host and set the num_gw to 0. Therefore, none of the
	 * source routing related code paths will be executed.
	 */
#ifndef ICMD
	if (*cp == '@') {
		*src_rtng_type = IPOPT_LSRR;
		cp++;
	} else if (*cp == '!') {
		*src_rtng_type = IPOPT_SSRR;

		/* "!" must be followed by '@' */
		if (*(cp + 1) != '@')
			goto parse_error;
		cp += 2;
	} else {
#endif	/* ICMD */
		/* no gateways, just the target */
		hostname_list[0] = strdup(cp);
		if (hostname_list[0] == NULL) {
			perror("telnet: copying host name");
			return (-1);
		}
		return (0);
#ifndef ICMD
	}

	while (*cp != '\0') {
		/*
		 * Identify each gateway separated by ",", "@" or ",@" and
		 * store in hname[].
		 */
		i = 0;
		while (*cp != '@' && *cp != ',' && *cp != '\0') {
			hname[i++] = *cp++;
			if (i > MAXHOSTNAMELEN)
				goto parse_error;
		}
		hname[i] = '\0';

		/*
		 * Two consecutive delimiters which result in a 0 length hname
		 * is a parse error.
		 */
		if (i == 0)
			goto parse_error;

		hostname_list[gw_count] = strdup(hname);
		if (hostname_list[gw_count] == NULL) {
			perror("telnet: copying hostname from list");
			return (-1);
		}

		if (++gw_count > MAXMAX_GATEWAY) {
			(void) fprintf(stderr, "telnet: too many gateways\n");
			return (-1);
		}

		/* Jump over the next delimiter. */
		if (*cp != '\0') {
			/* ...gw1,@gw2... accepted */
			if (*cp == ',' && *(cp + 1) == '@')
				cp += 2;
			else
				cp++;
		}
	}

	/* discount the target */
	gw_count--;

	/* Any input starting with '!@' or '@' must have at least one gateway */
	if (gw_count <= 0)
		goto parse_error;

	return (gw_count);

parse_error:
	(void) printf("Bad source route option: %s\n", cmd_line_input);
	return (-1);
#endif	/* ICMD */
}

/*
 * Resolves the target and gateway addresses, determines what type of addresses
 * (ALL_ADDRS, ONLY_V6, ONLY_V4) telnet will be trying to connect.
 *
 * Returns:	pointer to resolved target	if name resolutions succeed
 *		NULL				if name resolutions fail or
 *						a library function call fails
 *
 * The last host in the hostname_list is the target. After resolving the target,
 * determines for what type of addresses it should try to resolve gateways. It
 * resolves gateway addresses and picks one address for each desired address
 * type and stores in the array pointed by gw_addrsp. Also, this 'type of
 * addresses' is pointed by addr_type argument on successful return.
 */
static struct addrinfo *
resolve_hosts(char **hostname_list, int num_gw, struct gateway **gw_addrsp,
    int *addr_type, const char *portp)
{
	struct gateway *gw_addrs = NULL;
	struct gateway *gw;
	/* whether we already picked an IPv4 address for the current gateway */
	boolean_t got_v4_addr;
	boolean_t got_v6_addr;
	/* whether we need to get an IPv4 address for the current gateway */
	boolean_t need_v4_addr = B_FALSE;
	boolean_t need_v6_addr = B_FALSE;
	int res_failed_at4;	/* save which gateway failed to resolve */
	int res_failed_at6;
	boolean_t is_v4mapped;
	struct in6_addr *v6addrp;
	struct in_addr *v4addrp;
	int error_num;
	int i;
	int rc;
	struct addrinfo *res, *host, *gateway, *addr;
	struct addrinfo hints;

	*addr_type = ALL_ADDRS;

	memset(&hints, 0, sizeof (hints));
	hints.ai_flags = AI_CANONNAME; /* used for config files, diags */
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(hostname_list[num_gw],
	    (portp != NULL) ? portp : "telnet", &hints, &res);
	if (rc != 0) {
		if (hostname_list[num_gw] != NULL &&
		    *hostname_list[num_gw] != '\0')
			(void) fprintf(stderr, "%s: ", hostname_list[num_gw]);
		(void) fprintf(stderr, "%s\n", gai_strerror(rc));
		return (NULL);
	}

	/*
	 * Let's see what type of addresses we got for the target. This
	 * determines what type of addresses we'd like to resolve gateways
	 * later.
	 */
	for (host = res; host != NULL; host = host->ai_next) {
		struct sockaddr_in6 *s6;

		s6 = (struct sockaddr_in6 *)host->ai_addr;

		if (host->ai_addr->sa_family == AF_INET ||
		    IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr))
			need_v4_addr = B_TRUE;
		else
			need_v6_addr = B_TRUE;

		/*
		 * Let's stop after seeing we need both IPv6 and IPv4.
		 */
		if (need_v4_addr && need_v6_addr)
			break;
	}

	if (num_gw > 0) {
		/*
		 * In the prepare_optbuf(), we'll store the IPv4 address of the
		 * target in the last slot of gw_addrs array. Therefore we need
		 * space for num_gw+1 hosts.
		 */
		gw_addrs = calloc(num_gw + 1, sizeof (struct gateway));
		if (gw_addrs == NULL) {
			perror("telnet: calloc");
			freeaddrinfo(res);
			return (NULL);
		}
	}

	/*
	 * Now we'll go through all the gateways and try to resolve them to
	 * the desired address types.
	 */
	gw = gw_addrs;

	/* -1 means 'no address resolution failure yet' */
	res_failed_at4 = -1;
	res_failed_at6 = -1;
	for (i = 0; i < num_gw; i++) {
		rc = getaddrinfo(hostname_list[i], NULL, NULL, &gateway);
		if (rc != 0) {
			if (hostname_list[i] != NULL &&
			    *hostname_list[i] != '\0')
				(void) fprintf(stderr, "%s: ",
				    hostname_list[i]);
			(void) fprintf(stderr, "bad address\n");
			return (NULL);
		}

		/*
		 * Initially we have no address of any type for this gateway.
		 */
		got_v6_addr = B_FALSE;
		got_v4_addr = B_FALSE;

		/*
		 * Let's go through all the addresses of this gateway.
		 * Use the first address which matches the needed family.
		 */
		for (addr = gateway; addr != NULL; addr = addr->ai_next) {
			/*LINTED*/
			v6addrp = &((struct sockaddr_in6 *)addr->ai_addr)->
			    sin6_addr;
			v4addrp = &((struct sockaddr_in *)addr->ai_addr)->
			    sin_addr;

			if (addr->ai_family == AF_INET6)
				is_v4mapped = IN6_IS_ADDR_V4MAPPED(v6addrp);
			else
				is_v4mapped = B_FALSE;

			/*
			 * If we need to determine an IPv4 address and haven't
			 * found one yet and this is a IPv4-mapped IPv6 address,
			 * then bingo!
			 */
			if (need_v4_addr && !got_v4_addr) {
				if (is_v4mapped) {
					IN6_V4MAPPED_TO_INADDR(v6addrp,
					    &gw->gw_addr);
					got_v4_addr = B_TRUE;
				} else if (addr->ai_family = AF_INET) {
					gw->gw_addr = *v4addrp;
					got_v4_addr = B_TRUE;
				}
			}

			if (need_v6_addr && !got_v6_addr &&
			    addr->ai_family == AF_INET6) {
				gw->gw_addr6 = *v6addrp;
				got_v6_addr = B_TRUE;
			}

			/*
			 * Let's stop if we got all what we looked for.
			 */
			if ((!need_v4_addr || got_v4_addr) &&
			    (!need_v6_addr || got_v6_addr))
				break;
		}

		/*
		 * We needed an IPv4 address for this gateway but couldn't
		 * find one.
		 */
		if (need_v4_addr && !got_v4_addr) {
			res_failed_at4 = i;
			/*
			 * Since we couldn't resolve a gateway to IPv4 address
			 * we can't use IPv4 at all. Therefore we no longer
			 * need IPv4 addresses for any of the gateways.
			 */
			need_v4_addr = B_FALSE;
		}

		if (need_v6_addr && !got_v6_addr) {
			res_failed_at6 = i;
			need_v6_addr = B_FALSE;
		}

		/*
		 * If some gateways don't resolve to any of the desired
		 * address types, we fail.
		 */
		if (!need_v4_addr && !need_v6_addr) {
			if (res_failed_at6 != -1) {
				(void) fprintf(stderr,
				    "%s: Host doesn't have any IPv6 address\n",
				    hostname_list[res_failed_at6]);
			}
			if (res_failed_at4 != -1) {
				(void) fprintf(stderr,
				    "%s: Host doesn't have any IPv4 address\n",
				    hostname_list[res_failed_at4]);
			}
			free(gw_addrs);
			return (NULL);
		}

		gw++;
	}

	*gw_addrsp = gw_addrs;

	/*
	 * When we get here, need_v4_addr and need_v6_addr have their final
	 * values based on the name resolution of the target and gateways.
	 */
	if (need_v4_addr && need_v6_addr)
		*addr_type = ALL_ADDRS;
	else if (need_v4_addr && !need_v6_addr)
		*addr_type = ONLY_V4;
	else if (!need_v4_addr && need_v6_addr)
		*addr_type = ONLY_V6;

	return (res);
}


/*
 * Initializes the buffer pointed by opt_bufpp for a IPv4 option of type
 * src_rtng_type using the gateway addresses stored in gw_addrs. If no buffer
 * is passed, it allocates one. If a buffer is passed, checks if it's big
 * enough.
 * On return opt_buf_len points to the buffer length which we need later for the
 * setsockopt() call, and opt_bufpp points to the newly allocated or already
 * passed buffer. Returns B_FALSE if a library function call fails or passed
 * buffer is not big enough, B_TRUE otherwise.
 */
static boolean_t
prepare_optbuf(struct gateway *gw_addrs, int num_gw, char **opt_bufpp,
    size_t *opt_buf_len, struct in_addr *target, uchar_t src_rtng_type)
{
	struct ip_sourceroute *sr_opt;
	size_t needed_buflen;
	int i;

	/*
	 * We have (num_gw + 1) IP addresses in the buffer because the number
	 * of gateway addresses we put in the option buffer includes the target
	 * address.
	 * At the time of setsockopt() call, passed option length needs to be
	 * multiple of 4 bytes. Therefore we need one IPOPT_NOP before (or
	 * after) IPOPT_LSRR.
	 * 1 = preceding 1 byte of IPOPT_NOP
	 * 3 = 1 (code) + 1 (len) + 1 (ptr)
	 */
	needed_buflen = 1 + 3 + (num_gw + 1) * sizeof (struct in_addr);

	if (*opt_bufpp != NULL) {
		/* check if the passed buffer is big enough */
		if (*opt_buf_len < needed_buflen) {
			(void) fprintf(stderr,
			    "telnet: buffer too small for IPv4 source routing "
			    "option\n");
			return (B_FALSE);
		}
	} else {
		*opt_bufpp = malloc(needed_buflen);
		if (*opt_bufpp == NULL) {
			perror("telnet: malloc");
			return (B_FALSE);
		}
	}

	*opt_buf_len = needed_buflen;

	/* final hop is the target */
	gw_addrs[num_gw].gw_addr = *target;

	*opt_bufpp[0] = IPOPT_NOP;
	/* IPOPT_LSRR starts right after IPOPT_NOP */
	sr_opt = (struct ip_sourceroute *)(*opt_bufpp + 1);
	sr_opt->ipsr_code = src_rtng_type;
	/* discount the 1 byte of IPOPT_NOP */
	sr_opt->ipsr_len = needed_buflen - 1;
	sr_opt->ipsr_ptr = IPOPT_MINOFF;

	/* copy the gateways into the optlist */
	for (i = 0; i < num_gw + 1; i++) {
		(void) bcopy(&gw_addrs[i].gw_addr, &sr_opt->ipsr_addrs[i],
		    sizeof (struct in_addr));
	}

	return (B_TRUE);
}

/*
 * Initializes the buffer pointed by opt_bufpp for a IPv6 routing header option
 * using the gateway addresses stored in gw_addrs. If no buffer is passed, it
 * allocates one. If a buffer is passed, checks if it's big enough.
 * On return opt_buf_len points to the buffer length which we need later for the
 * setsockopt() call, and opt_bufpp points to the newly allocated or already
 * passed buffer. Returns B_FALSE if a library function call fails or passed
 * buffer is not big enough, B_TRUE otherwise.
 */
static boolean_t
prepare_optbuf6(struct gateway *gw_addrs, int num_gw, char **opt_bufpp,
    size_t *opt_buf_len)
{
	char *opt_bufp;
	size_t needed_buflen;
	int i;

	needed_buflen = inet6_rth_space(IPV6_RTHDR_TYPE_0, num_gw);

	if (*opt_bufpp != NULL) {
		/* check if the passed buffer is big enough */
		if (*opt_buf_len < needed_buflen) {
			(void) fprintf(stderr,
			    "telnet: buffer too small for IPv6 routing "
			    "header option\n");
			return (B_FALSE);
		}
	} else {
		*opt_bufpp = malloc(needed_buflen);
		if (*opt_bufpp == NULL) {
			perror("telnet: malloc");
			return (B_FALSE);
		}
	}
	*opt_buf_len = needed_buflen;
	opt_bufp = *opt_bufpp;

	/*
	 * Initialize the buffer to be used for IPv6 routing header type 0.
	 */
	if (inet6_rth_init(opt_bufp, needed_buflen, IPV6_RTHDR_TYPE_0,
	    num_gw) == NULL) {
		perror("telnet: inet6_rth_init");
		return (B_FALSE);
	}

	/*
	 * Add gateways one by one.
	 */
	for (i = 0; i < num_gw; i++) {
		if (inet6_rth_add(opt_bufp, &gw_addrs[i].gw_addr6) == -1) {
			perror("telnet: inet6_rth_add");
			return (B_FALSE);
		}
	}

	/* successful operation */
	return (B_TRUE);
}

int
tn(argc, argv)
	int argc;
	char *argv[];
{
	struct addrinfo *host = NULL;
	struct addrinfo *h;
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	struct in6_addr addr6;
	struct in_addr addr;
	void *addrp;
	struct gateway *gw_addrs;
	char *hostname_list[MAXMAX_GATEWAY + 1] = {NULL};
	char *opt_buf6 = NULL;		/* used for IPv6 routing header */
	size_t opt_buf_len6 = 0;
	uchar_t src_rtng_type;		/* type of IPv4 source routing */
	struct servent *sp = 0;
	char *opt_buf = NULL;		/* used for IPv4 source routing */
	size_t opt_buf_len = 0;
	char *cmd;
	char *hostp = NULL;
	char *portp = NULL;
	char *user = NULL;
#ifdef	ICMD
	char *itelnet_host;
	char *real_host;
	unsigned short dest_port;
#endif	/* ICMD */
	/*
	 * The two strings at the end of this function are 24 and 39
	 * characters long (minus the %.*s in the format strings).  Add
	 * one for the null terminator making the longest print string 40.
	 */
	char buf[MAXHOSTNAMELEN+40];
	/*
	 * In the case of ICMD defined, dest_port will contain the real port
	 * we are trying to telnet to, and target_port will contain
	 * "telnet-passthru" port.
	 */
	unsigned short target_port;
	char abuf[INET6_ADDRSTRLEN];
	int num_gw;
	int ret_val;
	boolean_t is_v4mapped;
	/*
	 * Type of addresses we'll try to connect to (ALL_ADDRS, ONLY_V6,
	 * ONLY_V4).
	 */
	int addr_type;

	/* clear the socket address prior to use */
	(void) memset(&sin6, '\0', sizeof (sin6));
	sin6.sin6_family = AF_INET6;

	(void) memset(&sin, '\0', sizeof (sin));
	sin.sin_family = AF_INET;

	if (connected) {
		(void) printf("?Already connected to %s\n", hostname);
		return (0);
	}
#ifdef	ICMD
	itelnet_host = getenv("INTERNET_HOST");
	if (itelnet_host == NULL || itelnet_host[0] == '\0') {
		(void) printf("INTERNET_HOST environment variable undefined\n");
		goto tn_exit;
	}
#endif
	if (argc < 2) {
		(void) printf("(to) ");
		if (GetAndAppendString(&line, &linesize, "open ",
			stdin) == NULL) {
			if (!feof(stdin)) {
				perror("telnet");
				goto tn_exit;
			}
		}
		makeargv();
		argc = margc;
		argv = margv;
	}
	cmd = *argv;
	--argc; ++argv;
	while (argc) {
		if (isprefix(*argv, "help") == 4 || isprefix(*argv, "?") == 1)
			goto usage;
		if (strcmp(*argv, "-l") == 0) {
			--argc; ++argv;
			if (argc == 0)
				goto usage;
			user = *argv++;
			--argc;
			continue;
		}
		if (strcmp(*argv, "-a") == 0) {
			--argc; ++argv;
			autologin = autologin_set = 1;
			continue;
		}
		if (hostp == 0) {
			hostp = *argv++;
			--argc;
			continue;
		}
		if (portp == 0) {
			portp = *argv++;
			--argc;
			/*
			 * Do we treat this like a telnet port or raw?
			 */
			if (*portp == '-') {
				portp++;
				telnetport = 1;
			} else
				telnetport = 0;
			continue;
		}
usage:
		(void) printf(
		    "usage: %s [-l user] [-a] host-name [port]\n", cmd);
		goto tn_exit;
	}
	if (hostp == 0)
		goto usage;

#ifdef ICMD
	/*
	 * For setup phase treat the relay host as the target host.
	 */
	real_host = hostp;
	hostp = itelnet_host;
#endif
	num_gw = parse_input(hostp, hostname_list, &src_rtng_type);
	if (num_gw < 0) {
		goto tn_exit;
	}

	/* Last host in the hostname_list is the target */
	hostp = hostname_list[num_gw];

	host = resolve_hosts(hostname_list, num_gw, &gw_addrs, &addr_type,
	    portp);
	if (host == NULL) {
		goto tn_exit;
	}

	/*
	 * Check if number of gateways is less than max. available
	 */
	if ((addr_type == ALL_ADDRS || addr_type == ONLY_V6) &&
	    num_gw > MAX_GATEWAY6) {
		(void) fprintf(stderr, "telnet: too many IPv6 gateways\n");
		goto tn_exit;
	}

	if ((addr_type == ALL_ADDRS || addr_type == ONLY_V4) &&
	    num_gw > MAX_GATEWAY) {
		(void) fprintf(stderr, "telnet: too many IPv4 gateways\n");
		goto tn_exit;
	}

	/*
	 * If we pass a literal IPv4 address to getaddrinfo(), in the
	 * returned addrinfo structure, hostname is the IPv4-mapped IPv6
	 * address string. We prefer to preserve the literal IPv4 address
	 * string as the hostname.  Also, if the hostname entered by the
	 * user is IPv4-mapped IPv6 address, we'll downgrade it to IPv4
	 * address.
	 */
	if (inet_addr(hostp) != (in_addr_t)-1) {
		/* this is a literal IPv4 address */
		(void) strlcpy(_hostname, hostp, sizeof (_hostname));
	} else if ((inet_pton(AF_INET6, hostp, &addr6) > 0) &&
		    IN6_IS_ADDR_V4MAPPED(&addr6)) {
		/* this is a IPv4-mapped IPv6 address */
		IN6_V4MAPPED_TO_INADDR(&addr6, &addr);
		(void) inet_ntop(AF_INET, &addr, _hostname, sizeof (_hostname));
	} else {
		(void) strlcpy(_hostname, host->ai_canonname,
		    sizeof (_hostname));
	}
	hostname = _hostname;

	if (portp == NULL) {
		telnetport = 1;
	}

	if (host->ai_family == AF_INET) {
		target_port = ((struct sockaddr_in *)(host->ai_addr))->sin_port;
	} else {
		target_port = ((struct sockaddr_in6 *)(host->ai_addr))
		    ->sin6_port;
	}

#ifdef ICMD
	/*
	 * Since we pass the port number as an ascii string to the proxy,
	 *  we need it in host format.
	 */
	dest_port = ntohs(target_port);
	sp = getservbyname("telnet-passthru", "tcp");
	if (sp == 0) {
		(void) fprintf(stderr,
		    "telnet: tcp/telnet-passthru: unknown service\n");
			goto tn_exit;
	}
	target_port = sp->s_port;
#endif
	h = host;

	/*
	 * For IPv6 source routing, we need to initialize option buffer only
	 * once.
	 */
	if (num_gw > 0 && (addr_type == ALL_ADDRS || addr_type == ONLY_V6)) {
		if (!prepare_optbuf6(gw_addrs, num_gw, &opt_buf6,
		    &opt_buf_len6)) {
			goto tn_exit;
		}
	}

	/*
	 * We procure the Kerberos config files options only
	 * if the user has choosen Krb5 authentication.
	 */
	if (krb5auth_flag > 0) {
		krb5_profile_get_options(hostname, telnet_krb5_realm,
			config_file_options);
	}

	if (encrypt_flag) {
		extern boolean_t auth_enable_encrypt;
		if (krb5_privacy_allowed()) {
			encrypt_auto(1);
			decrypt_auto(1);
			wantencryption = B_TRUE;
			autologin = 1;
			auth_enable_encrypt = B_TRUE;
		} else {
			(void) fprintf(stderr, gettext(
			    "%s:Encryption not supported.\n"), prompt);
			exit(1);
			}
	}

	if (forward_flag && forwardable_flag) {
		(void) fprintf(stderr, gettext(
			"Error in krb5 configuration file. "
			"Both forward and forwardable are set.\n"));
		exit(1);
	}
	if (forwardable_flag) {
		forward_flags |= OPTS_FORWARD_CREDS | OPTS_FORWARDABLE_CREDS;
	} else if (forward_flag)
		forward_flags |= OPTS_FORWARD_CREDS;


	do {
		/*
		 * Search for an address of desired type in the IP address list
		 * of the target.
		 */
		while (h != NULL) {
			struct sockaddr_in6 *addr;

			addr = (struct sockaddr_in6 *)h->ai_addr;

			if (h->ai_family == AF_INET6)
				is_v4mapped =
				    IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr);
			else
				is_v4mapped = B_FALSE;

			if (addr_type == ALL_ADDRS ||
			    (addr_type == ONLY_V6 &&
				h->ai_family == AF_INET6) ||
			    (addr_type == ONLY_V4 &&
				(h->ai_family == AF_INET || is_v4mapped)))
				break;

			/* skip undesired typed addresses */
			h = h->ai_next;
		}

		if (h == NULL) {
			fprintf(stderr,
			    "telnet: Unable to connect to remote host");
			goto tn_exit;
		}

		/*
		 * We need to open a socket with a family matching the type of
		 * address we are trying to connect to. This is because we
		 * deal with IPv4 options and IPv6 extension headers.
		 */
		if (h->ai_family == AF_INET) {
			addrp = &((struct sockaddr_in *)(h->ai_addr))->sin_addr;
			((struct sockaddr_in *)(h->ai_addr))->sin_port =
			    target_port;
		} else {
			addrp = &((struct sockaddr_in6 *)(h->ai_addr))
			    ->sin6_addr;
			((struct sockaddr_in6 *)(h->ai_addr))->sin6_port =
			    target_port;
		}

		(void) printf("Trying %s...\n", inet_ntop(h->ai_family,
		    addrp, abuf, sizeof (abuf)));

		net = socket(h->ai_family, SOCK_STREAM, 0);

		if (net < 0) {
			perror("telnet: socket");
			goto tn_exit;
		}
#ifndef ICMD
		if (num_gw > 0) {
			if (h->ai_family == AF_INET || is_v4mapped) {
				if (!prepare_optbuf(gw_addrs, num_gw, &opt_buf,
				    &opt_buf_len, addrp, src_rtng_type)) {
					goto tn_exit;
				}

				if (setsockopt(net, IPPROTO_IP, IP_OPTIONS,
				    opt_buf, opt_buf_len) < 0)
					perror("setsockopt (IP_OPTIONS)");
			} else {
				if (setsockopt(net, IPPROTO_IPV6, IPV6_RTHDR,
				    opt_buf6, opt_buf_len6) < 0)
					perror("setsockopt (IPV6_RTHDR)");
			}
		}
#endif
#if	defined(USE_TOS)
		if (is_v4mapped) {
			if (tos < 0)
				tos = 020;	/* Low Delay bit */
			if (tos &&
			    (setsockopt(net, IPPROTO_IP, IP_TOS,
			    &tos, sizeof (int)) < 0) &&
			    (errno != ENOPROTOOPT))
				perror("telnet: setsockopt (IP_TOS) (ignored)");
		}
#endif	/* defined(USE_TOS) */

		if (debug && SetSockOpt(net, SOL_SOCKET, SO_DEBUG, 1) < 0) {
			perror("setsockopt (SO_DEBUG)");
		}

		ret_val = connect(net, h->ai_addr, h->ai_addrlen);

		/*
		 * If failed, try the next address of the target.
		 */
		if (ret_val < 0) {
			Close(&net);
			if (h->ai_next != NULL) {

				int oerrno = errno;

				(void) fprintf(stderr,
				    "telnet: connect to address %s: ", abuf);
				errno = oerrno;
				perror((char *)0);

				h = h->ai_next;
				continue;
			}
			perror("telnet: Unable to connect to remote host");
			goto tn_exit;
		}
		connected++;
	} while (connected == 0);
	freeaddrinfo(host);
	host = NULL;
#ifdef ICMD
	/*
	 * Do initial protocol to connect to farther end...
	 */
	{
		char buf[1024];
		(void) sprintf(buf, "%s %d\n", real_host, (int)dest_port);
		write(net, buf, strlen(buf));
	}
#endif
	if (cmdrc(hostp, hostname) != 0)
		goto tn_exit;
	FreeHostnameList(hostname_list);
	if (autologin && user == NULL) {
		struct passwd *pw;

		user = getenv("LOGNAME");
		if (user == NULL ||
		    ((pw = getpwnam(user)) != NULL) &&
		    pw->pw_uid != getuid()) {
			if (pw = getpwuid(getuid()))
				user = pw->pw_name;
			else
				user = NULL;
		}
	}

	if (user) {
		if (env_define((unsigned char *)"USER", (unsigned char *)user))
			env_export((unsigned char *)"USER");
		else {
			/* Clean up and exit. */
			Close(&net);
			(void) snprintf(buf, sizeof (buf),
			    "Connection to %.*s closed.\n",
			    MAXHOSTNAMELEN, hostname);
			ExitString(buf, EXIT_FAILURE);

			/* NOTREACHED */
		}
	}
	(void) call(3, status, "status", "notmuch");
	if (setjmp(peerdied) == 0)
		telnet(user);

	Close(&net);

	(void) snprintf(buf, sizeof (buf),
	    "Connection to %.*s closed by foreign host.\n",
	    MAXHOSTNAMELEN, hostname);
	ExitString(buf, EXIT_FAILURE);

	/*NOTREACHED*/

tn_exit:
	FreeHostnameList(hostname_list);
	Close(&net);
	connected = 0;
	if (host != NULL)
		freeaddrinfo(host);
	return (0);
}

#define	HELPINDENT (sizeof ("connect"))

static char openhelp[] = "connect to a site";
static char closehelp[] = "close current connection";
static char logouthelp[] =
	    "forcibly logout remote user and close the connection";
static char quithelp[] = "exit telnet";
static char statushelp[] = "print status information";
static char helphelp[] = "print help information";
static char sendhelp[] =
	    "transmit special characters ('send ?' for more)";
static char sethelp[] =  "set operating parameters ('set ?' for more)";
static char unsethelp[] = "unset operating parameters ('unset ?' for more)";
static char togglestring[] =
	    "toggle operating parameters ('toggle ?' for more)";
static char slchelp[] = "change state of special charaters ('slc ?' for more)";
static char displayhelp[] = "display operating parameters";
static char authhelp[] =
	    "turn on (off) authentication ('auth ?' for more)";
static char forwardhelp[] =
	    "turn on (off) credential forwarding ('forward ?' for more)";
static char encrypthelp[] =
	    "turn on (off) encryption ('encrypt ?' for more)";
static char zhelp[] = "suspend telnet";
static char shellhelp[] = "invoke a subshell";
static char envhelp[] = "change environment variables ('environ ?' for more)";
static char modestring[] =
	    "try to enter line or character mode ('mode ?' for more)";

static int	help();

static Command cmdtab[] = {
	{ "close",	closehelp,	bye,		1 },
	{ "logout",	logouthelp,	logout,		1 },
	{ "display",	displayhelp,	display,	0 },
	{ "mode",	modestring,	modecmd,	0 },
	{ "open",	openhelp,	tn,		0 },
	{ "quit",	quithelp,	quit,		0 },
	{ "send",	sendhelp,	sendcmd,	0 },
	{ "set",	sethelp,	setcmd,		0 },
	{ "unset",	unsethelp,	unsetcmd,	0 },
	{ "status",	statushelp,	status,		0 },
	{ "toggle",	togglestring,	toggle,		0 },
	{ "slc",	slchelp,	slccmd,		0 },
	{ "auth",	authhelp,	auth_cmd,	0 },
	{ "encrypt",	encrypthelp,	encrypt_cmd,	0 },
	{ "forward",	forwardhelp,	forw_cmd,	0 },
	{ "z",		zhelp,		suspend,	0 },
	{ "!",		shellhelp,	shell,		0 },
	{ "environ",	envhelp,	env_cmd,	0 },
	{ "?",		helphelp,	help,		0 },
	0
};


static Command cmdtab2[] = {
	{ "help",	0,		help,		0 },
	{ "escape",	0,		setescape,	0 },
	{ "crmod",	0,		togcrmod,	0 },
	0
};


/*
 * Call routine with argc, argv set from args.
 * Uses /usr/include/stdarg.h
 */
#define	MAXVARGS	100
/*VARARGS1*/
static void
call(int n_ptrs, ...)
{
	va_list ap;
	typedef int (*intrtn_t)();
	intrtn_t routine;
	char *args[MAXVARGS+1];	/* leave 1 for trailing NULL */
	int argno = 0;

	if (n_ptrs > MAXVARGS)
		n_ptrs = MAXVARGS;
	va_start(ap, n_ptrs);

	routine = (va_arg(ap, intrtn_t)); /* extract the routine's name */
	n_ptrs--;

	while (argno < n_ptrs)	/* extract the routine's args */
		args[argno++] = va_arg(ap, char *);
	args[argno] = NULL;	/* NULL terminate for good luck */
	va_end(ap);

	(*routine)(argno, args);
}


static Command *
getcmd(name)
	char *name;
{
	Command *cm;

	if (cm = (Command *) genget(name, (char **)cmdtab, sizeof (Command)))
		return (cm);
	return (Command *) genget(name, (char **)cmdtab2, sizeof (Command));
}

void
command(top, tbuf, cnt)
	int top;
	char *tbuf;
	int cnt;
{
	Command *c;

	setcommandmode();
	if (!top) {
		(void) putchar('\n');
	} else {
		(void) signal(SIGINT, SIG_DFL);
		(void) signal(SIGQUIT, SIG_DFL);
	}
	for (;;) {
		if (rlogin == _POSIX_VDISABLE)
			(void) printf("%s> ", prompt);
		if (tbuf) {
			char *cp;
			if (AllocStringBuffer(&line, &linesize, cnt) == NULL)
				goto command_exit;
			cp = line;
			while (cnt > 0 && (*cp++ = *tbuf++) != '\n')
				cnt--;
			tbuf = 0;
			if (cp == line || *--cp != '\n' || cp == line)
				goto getline;
			*cp = '\0';
			if (rlogin == _POSIX_VDISABLE)
				(void) printf("%s\n", line);
		} else {
getline:
			if (rlogin != _POSIX_VDISABLE)
				(void) printf("%s> ", prompt);
			if (GetString(&line, &linesize, stdin) == NULL) {
				if (!feof(stdin))
					perror("telnet");
				(void) quit();
				/*NOTREACHED*/
				break;
			}
		}
		if (line[0] == 0)
			break;
		makeargv();
		if (margv[0] == 0) {
			break;
		}
		c = getcmd(margv[0]);
		if (Ambiguous(c)) {
			(void) printf("?Ambiguous command\n");
			continue;
		}
		if (c == 0) {
			(void) printf("?Invalid command\n");
			continue;
		}
		if (c->needconnect && !connected) {
			(void) printf("?Need to be connected first.\n");
			continue;
		}
		if ((*c->handler)(margc, margv)) {
			break;
		}
	}
command_exit:
	if (!top) {
		if (!connected) {
			longjmp(toplevel, 1);
			/*NOTREACHED*/
		}
		setconnmode(0);
	}
}

/*
 * Help command.
 */
	static int
help(argc, argv)
	int argc;
	char *argv[];
{
	register Command *c;

	if (argc == 1) {
		(void) printf(
		    "Commands may be abbreviated.  Commands are:\n\n");
		for (c = cmdtab; c->name; c++)
			if (c->help) {
				(void) printf("%-*s\t%s\n", HELPINDENT,
					c->name, c->help);
			}
		(void) printf("<return>\tleave command mode\n");
		return (0);
	}
	while (--argc > 0) {
		register char *arg;
		arg = *++argv;
		c = getcmd(arg);
		if (Ambiguous(c))
			(void) printf("?Ambiguous help command %s\n", arg);
		else if (c == (Command *)0)
			(void) printf("?Invalid help command %s\n", arg);
		else if (c->help) {
			(void) printf("%s\n", c->help);
		} else  {
			(void) printf("No additional help on %s\n", arg);
		}
	}
	return (0);
}

static char *rcname = NULL;
#define	TELNETRC_NAME "telnetrc"
#define	TELNETRC_COMP "/." TELNETRC_NAME

static int
cmdrc(char *m1, char *m2)
{
	Command *c;
	FILE *rcfile = NULL;
	int gotmachine = 0;
	int l1 = strlen(m1);
	int l2 = strlen(m2);
	char m1save[MAXHOSTNAMELEN];
	int ret = 0;
	char def[] = "DEFAULT";

	if (skiprc)
		goto cmdrc_exit;

	doing_rc = 1;

	(void) strlcpy(m1save, m1, sizeof (m1save));
	m1 = m1save;

	if (rcname == NULL) {
		char *homedir;
		unsigned rcbuflen;

		if ((homedir = getenv("HOME")) == NULL)
			homedir = "";

		rcbuflen = strlen(homedir) + strlen(TELNETRC_COMP) + 1;
		if ((rcname = malloc(rcbuflen)) == NULL) {
			perror("telnet: can't process " TELNETRC_NAME);
			ret = 1;
			goto cmdrc_exit;
		}
		(void) strcpy(rcname, homedir);
		(void) strcat(rcname, TELNETRC_COMP);
	}

	if ((rcfile = fopen(rcname, "r")) == NULL)
		goto cmdrc_exit;

	for (;;) {
		if (GetString(&line, &linesize, rcfile) == NULL) {
			if (!feof(rcfile)) {
				perror("telnet: error reading " TELNETRC_NAME);
				ret = 1;
				goto cmdrc_exit;
			}
			break;
		}
		if (line[0] == 0)
			continue;
		if (line[0] == '#')
			continue;
		if (gotmachine) {
			if (!isspace(line[0]))
			gotmachine = 0;
		}
		if (gotmachine == 0) {
			if (isspace(line[0]))
				continue;
			if (strncasecmp(line, m1, l1) == 0)
				(void) strcpy(line, &line[l1]);
			else if (strncasecmp(line, m2, l2) == 0)
				(void) strcpy(line, &line[l2]);
			else if (strncasecmp(line, def, sizeof (def) - 1) == 0)
				(void) strcpy(line, &line[sizeof (def) - 1]);
			else
				continue;
			if (line[0] != ' ' && line[0] != '\t' &&
			    line[0] != '\n')
				continue;
			gotmachine = 1;
		}
		makeargv();
		if (margv[0] == 0)
			continue;
		c = getcmd(margv[0]);
		if (Ambiguous(c)) {
			(void) printf("?Ambiguous command: %s\n", margv[0]);
			continue;
		}
		if (c == 0) {
			(void) printf("?Invalid command: %s\n", margv[0]);
			continue;
		}
		/*
		 * This should never happen...
		 */
		if (c->needconnect && !connected) {
			(void) printf("?Need to be connected first for %s.\n",
			    margv[0]);
			continue;
		}
		(*c->handler)(margc, margv);
	}
cmdrc_exit:
	if (rcfile != NULL)
		(void) fclose(rcfile);
	doing_rc = 0;

	return (ret);
}
