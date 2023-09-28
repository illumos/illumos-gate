/*
 * Copyright 1994-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * usr/src/cmd/cmd-inet/usr.bin/telnet/utilities.c
 */

/*
 * Copyright (c) 1988, 1993
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
 */

#ifndef lint
static char sccsid[] = "@(#)utilities.c	8.1 (Berkeley) 6/6/93";
#endif /* not lint */

#define	TELOPTS
#ifdef	lint
static char *telcmds[] = {0};
static char *slc_names[] = {0};
static char *encrypt_names[] = {0};
static char *enctype_names[] = {0};
#else	/* lint */
#define	TELCMDS
#define	SLC_NAMES
#endif	/* lint */
#include <arpa/telnet.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <errno.h>

#include <ctype.h>

#include "general.h"

#include "ring.h"

#include "defines.h"

#include "externs.h"

FILE	*NetTrace = 0;		/* Not in bss, since needs to stay */
int	prettydump;

/*
 * upcase()
 *
 *	Upcase (in place) the argument.
 */

    void
upcase(argument)
	register char *argument;
{
	register int c;

	while ((c = *argument) != 0) {
		if (islower(c)) {
			*argument = toupper(c);
		}
	argument++;
	}
}

/*
 * SetSockOpt()
 *
 * Compensate for differences in 4.2 and 4.3 systems.
 */

    int
SetSockOpt(fd, level, option, yesno)
    int fd, level, option, yesno;
{
	return (setsockopt(fd, level, option, &yesno, sizeof (yesno)));
}

/*
 * The following are routines used to print out debugging information.
 */

unsigned char NetTraceFile[MAXPATHLEN] = "(standard output)";

    void
SetNetTrace(file)
    register char *file;
{
	if (NetTrace && NetTrace != stdout)
		(void) fclose(NetTrace);
	if (file && (strcmp(file, "-") != 0)) {
		NetTrace = fopen(file, "w");
		if (NetTrace) {
			(void) strcpy((char *)NetTraceFile, file);
			return;
		}
		(void) fprintf(stderr, "Cannot open %s.\n", file);
	}
	NetTrace = stdout;
	(void) strcpy((char *)NetTraceFile, "(standard output)");
}

    void
Dump(direction, buffer, length)
    char direction;
    unsigned char *buffer;
    int length;
{
#define	BYTES_PER_LINE	32
#define	min(x, y)	((x < y) ? x:y)
	unsigned char *pThis;
	int offset;

	offset = 0;

	while (length) {
		/* print one line */
		(void) fprintf(NetTrace, "%c 0x%x\t", direction, offset);
		pThis = buffer;
		if (prettydump) {
			buffer = buffer + min(length, BYTES_PER_LINE/2);
			while (pThis < buffer) {
				(void) fprintf(NetTrace, "%c%.2x",
				    (((*pThis)&0xff) == 0xff) ? '*' : ' ',
				    (*pThis)&0xff);
				pThis++;
			}
			length -= BYTES_PER_LINE/2;
			offset += BYTES_PER_LINE/2;
		} else {
			buffer = buffer + min(length, BYTES_PER_LINE);
			while (pThis < buffer) {
				(void) fprintf(NetTrace, "%.2x", (*pThis)&0xff);
				pThis++;
			}
			length -= BYTES_PER_LINE;
			offset += BYTES_PER_LINE;
		}
		if (NetTrace == stdout) {
			(void) fprintf(NetTrace, "\r\n");
		} else {
			(void) fprintf(NetTrace, "\n");
		}
		if (length < 0) {
			(void) fflush(NetTrace);
			return;
		}
		/* find next unique line */
	}
	(void) fflush(NetTrace);
}


	void
printoption(direction, cmd, option)
	char *direction;
	int cmd, option;
{
	if (!showoptions)
		return;
	if (cmd == IAC) {
		if (TELCMD_OK(option))
			(void) fprintf(NetTrace, "%s IAC %s", direction,
			    TELCMD(option));
		else
			(void) fprintf(NetTrace, "%s IAC %d", direction,
				option);
	} else {
		register char *fmt;
		fmt = (cmd == WILL) ? "WILL" : (cmd == WONT) ? "WONT" :
			(cmd == DO) ? "DO" : (cmd == DONT) ? "DONT" : 0;
		if (fmt) {
		    (void) fprintf(NetTrace, "%s %s ", direction, fmt);
		    if (TELOPT_OK(option))
			(void) fprintf(NetTrace, "%s", TELOPT(option));
		    else if (option == TELOPT_EXOPL)
			(void) fprintf(NetTrace, "EXOPL");
		    else
			(void) fprintf(NetTrace, "%d", option);
		} else
			(void) fprintf(NetTrace, "%s %d %d", direction, cmd,
			    option);
	}
	if (NetTrace == stdout) {
	    (void) fprintf(NetTrace, "\r\n");
	    (void) fflush(NetTrace);
	} else {
	    (void) fprintf(NetTrace, "\n");
	}
}

    void
optionstatus()
{
	register int i;
	extern char will_wont_resp[], do_dont_resp[];

	for (i = 0; i < SUBBUFSIZE; i++) {
		if (do_dont_resp[i]) {
			if (TELOPT_OK(i))
				(void) printf("resp DO_DONT %s: %d\n",
				    TELOPT(i), do_dont_resp[i]);
			else if (TELCMD_OK(i))
				(void) printf("resp DO_DONT %s: %d\n",
				    TELCMD(i), do_dont_resp[i]);
			else
				(void) printf("resp DO_DONT %d: %d\n", i,
				    do_dont_resp[i]);
			if (my_want_state_is_do(i)) {
				if (TELOPT_OK(i))
					(void) printf("want DO   %s\n",
					    TELOPT(i));
				else if (TELCMD_OK(i))
					(void) printf("want DO   %s\n",
						TELCMD(i));
				else
					(void) printf("want DO   %d\n", i);
			} else {
				if (TELOPT_OK(i))
					(void) printf("want DONT %s\n",
					    TELOPT(i));
				else if (TELCMD_OK(i))
					(void) printf("want DONT %s\n",
					    TELCMD(i));
				else
					(void) printf("want DONT %d\n", i);
			}
		} else {
			if (my_state_is_do(i)) {
				if (TELOPT_OK(i))
					(void) printf("     DO   %s\n",
					    TELOPT(i));
				else if (TELCMD_OK(i))
					(void) printf("     DO   %s\n",
					    TELCMD(i));
				else
					(void) printf("     DO   %d\n", i);
			}
		}
		if (will_wont_resp[i]) {
			if (TELOPT_OK(i))
				(void) printf("resp WILL_WONT %s: %d\n",
				    TELOPT(i), will_wont_resp[i]);
			else if (TELCMD_OK(i))
				(void) printf("resp WILL_WONT %s: %d\n",
				    TELCMD(i), will_wont_resp[i]);
			else
				(void) printf("resp WILL_WONT %d: %d\n",
				    i, will_wont_resp[i]);
			if (my_want_state_is_will(i)) {
				if (TELOPT_OK(i))
					(void) printf("want WILL %s\n",
					    TELOPT(i));
				else if (TELCMD_OK(i))
					(void) printf("want WILL %s\n",
					    TELCMD(i));
				else
					(void) printf("want WILL %d\n", i);
			} else {
				if (TELOPT_OK(i))
					(void) printf("want WONT %s\n",
					    TELOPT(i));
				else if (TELCMD_OK(i))
					(void) printf("want WONT %s\n",
					    TELCMD(i));
				else
					(void) printf("want WONT %d\n", i);
			}
		} else {
			if (my_state_is_will(i)) {
				if (TELOPT_OK(i))
					(void) printf("     WILL %s\n",
					    TELOPT(i));
				else if (TELCMD_OK(i))
					(void) printf("     WILL %s\n",
					    TELCMD(i));
				else
					(void) printf("     WILL %d\n", i);
			}
		}
	}

}

    void
printsub(direction, pointer, length)
	char direction;	/* '<' or '>' */
	unsigned char *pointer;	/* where suboption data sits */
	int	  length;	/* length of suboption data */
{
	register int i;
	char buf[512];
	extern int want_status_response;

	if (showoptions || direction == 0 ||
	    (want_status_response && (pointer[0] == TELOPT_STATUS))) {
		if (direction) {
			(void) fprintf(NetTrace, "%s IAC SB ",
				(direction == '<')? "RCVD":"SENT");
			if (length >= 3) {
				register int j;

				i = pointer[length-2];
				j = pointer[length-1];

				if (i != IAC || j != SE) {
					(void) fprintf(NetTrace,
					    "(terminated by ");
					if (TELOPT_OK(i))
						(void) fprintf(NetTrace, "%s ",
						    TELOPT(i));
					else if (TELCMD_OK(i))
						(void) fprintf(NetTrace, "%s ",
						    TELCMD(i));
					else
						(void) fprintf(NetTrace, "%d ",
						    i);
					if (TELOPT_OK(j))
						(void) fprintf(NetTrace, "%s",
						    TELOPT(j));
					else if (TELCMD_OK(j))
						(void) fprintf(NetTrace, "%s",
						    TELCMD(j));
					else
						(void) fprintf(NetTrace, "%d",
						    j);
					(void) fprintf(NetTrace,
					    ", not IAC SE!) ");
				}
			}
			length -= 2;
		}
		if (length < 1) {
			(void) fprintf(NetTrace, "(Empty suboption??\?)");
			if (NetTrace == stdout)
				(void) fflush(NetTrace);
			return;
		}
		switch (pointer[0]) {
		case TELOPT_TTYPE:
			(void) fprintf(NetTrace, "TERMINAL-TYPE ");
			switch (pointer[1]) {
			case TELQUAL_IS:
				(void) fprintf(NetTrace, "IS \"%.*s\"",
				    length-2,
				    (char *)pointer+2);
				break;
			case TELQUAL_SEND:
				(void) fprintf(NetTrace, "SEND");
				break;
			default:
				(void) fprintf(NetTrace,
				    "- unknown qualifier %d (0x%x).",
				    pointer[1], pointer[1]);
			}
			break;
		case TELOPT_TSPEED:
			(void) fprintf(NetTrace, "TERMINAL-SPEED");
			if (length < 2) {
				(void) fprintf(NetTrace,
				    " (empty suboption??\?)");
				break;
			}
			switch (pointer[1]) {
			case TELQUAL_IS:
				(void) fprintf(NetTrace, " IS ");
				(void) fprintf(NetTrace, "%.*s", length-2,
				    (char *)pointer+2);
				break;
			default:
				if (pointer[1] == 1)
					(void) fprintf(NetTrace, " SEND");
				else
					(void) fprintf(NetTrace,
					    " %d (unknown)", pointer[1]);
				for (i = 2; i < length; i++)
					(void) fprintf(NetTrace, " ?%d?",
					    pointer[i]);
				break;
			}
			break;

		case TELOPT_LFLOW:
			(void) fprintf(NetTrace, "TOGGLE-FLOW-CONTROL");
			if (length < 2) {
				(void) fprintf(NetTrace,
				    " (empty suboption??\?)");
				break;
			}
			switch (pointer[1]) {
			case LFLOW_OFF:
				(void) fprintf(NetTrace, " OFF");
				break;
			case LFLOW_ON:
				(void) fprintf(NetTrace, " ON");
				break;
			case LFLOW_RESTART_ANY:
				(void) fprintf(NetTrace, " RESTART-ANY");
				break;
			case LFLOW_RESTART_XON:
				(void) fprintf(NetTrace, " RESTART-XON");
				break;
			default:
				(void) fprintf(NetTrace, " %d (unknown)",
				    pointer[1]);
			}
			for (i = 2; i < length; i++)
				(void) fprintf(NetTrace, " ?%d?",
				    pointer[i]);
			break;

		case TELOPT_NAWS:
			(void) fprintf(NetTrace, "NAWS");
			if (length < 2) {
				(void) fprintf(NetTrace,
				    " (empty suboption??\?)");
				break;
			}
			if (length == 2) {
				(void) fprintf(NetTrace, " ?%d?", pointer[1]);
				break;
			}
			(void) fprintf(NetTrace, " %d %d (%d)",
			    pointer[1], pointer[2],
			    (int)((((unsigned int)pointer[1])<<8)|
			    ((unsigned int)pointer[2])));
			if (length == 4) {
				(void) fprintf(NetTrace, " ?%d?", pointer[3]);
				break;
			}
			(void) fprintf(NetTrace, " %d %d (%d)",
			    pointer[3], pointer[4],
			    (int)((((unsigned int)pointer[3])<<8)|
			    ((unsigned int)pointer[4])));
			for (i = 5; i < length; i++)
				(void) fprintf(NetTrace, " ?%d?", pointer[i]);
			break;

		case TELOPT_AUTHENTICATION:
			(void) fprintf(NetTrace, "AUTHENTICATION");
			if (length < 2) {
				(void) fprintf(NetTrace,
					" (empty suboption??\?)");
				break;
			}
			switch (pointer[1]) {
			case TELQUAL_REPLY:
			case TELQUAL_IS:
				(void) fprintf(NetTrace, " %s ",
				    (pointer[1] == TELQUAL_IS) ?
				    "IS" : "REPLY");
				if (AUTHTYPE_NAME_OK(pointer[2]))
					(void) fprintf(NetTrace, "%s ",
					    AUTHTYPE_NAME(pointer[2]));
				else
					(void) fprintf(NetTrace, "%d ",
						pointer[2]);
				if (length < 3) {
					(void) fprintf(NetTrace,
					    "(partial suboption??\?)");
					break;
				}
				(void) fprintf(NetTrace, "%s|%s",
				    ((pointer[3] & AUTH_WHO_MASK) ==
				    AUTH_WHO_CLIENT) ? "CLIENT" : "SERVER",
				    ((pointer[3] & AUTH_HOW_MASK) ==
				    AUTH_HOW_MUTUAL) ? "MUTUAL" : "ONE-WAY");

				auth_printsub(&pointer[1], length - 1,
				    (uchar_t *)buf, sizeof (buf));
				(void) fprintf(NetTrace, "%s", buf);
				break;

			case TELQUAL_SEND:
				i = 2;
				(void) fprintf(NetTrace, " SEND ");
				while (i < length) {
					if (AUTHTYPE_NAME_OK(pointer[i]))
						(void) fprintf(NetTrace, "%s ",
						    AUTHTYPE_NAME(pointer[i]));
					else
						(void) fprintf(NetTrace, "%d ",
						    pointer[i]);
					if (++i >= length) {
						(void) fprintf(NetTrace,
						    "(partial "
						    "suboption??\?)");
						break;
					}
					(void) fprintf(NetTrace, "%s|%s ",
					    ((pointer[i] & AUTH_WHO_MASK) ==
					    AUTH_WHO_CLIENT) ?
					    "CLIENT" : "SERVER",
					    ((pointer[i] & AUTH_HOW_MASK) ==
					    AUTH_HOW_MUTUAL) ?
					    "MUTUAL" : "ONE-WAY");
					++i;
				}
				break;

			case TELQUAL_NAME:
				i = 2;
				(void) fprintf(NetTrace, " NAME \"");
				while (i < length)
					(void) putc(pointer[i++], NetTrace);
				(void) putc('"', NetTrace);
				break;

			default:
				for (i = 2; i < length; i++)
				(void) fprintf(NetTrace, " ?%d?", pointer[i]);
				break;
			}
			break;

		case TELOPT_ENCRYPT:
			(void) fprintf(NetTrace, "ENCRYPT");
			if (length < 2) {
				(void) fprintf(NetTrace,
				    " (empty suboption??\?)");
				break;
			}
			switch (pointer[1]) {
			case ENCRYPT_START:
				(void) fprintf(NetTrace, " START");
				break;

			case ENCRYPT_END:
				(void) fprintf(NetTrace, " END");
				break;

			case ENCRYPT_REQSTART:
				(void) fprintf(NetTrace, " REQUEST-START");
				break;

			case ENCRYPT_REQEND:
				(void) fprintf(NetTrace, " REQUEST-END");
				break;

			case ENCRYPT_IS:
			case ENCRYPT_REPLY:
				(void) fprintf(NetTrace, " %s ",
				    (pointer[1] == ENCRYPT_IS) ?
				    "IS" : "REPLY");
				if (length < 3) {
					(void) fprintf(NetTrace, " (partial "
					    "suboption??\?)");
					break;
				}
				if (ENCTYPE_NAME_OK(pointer[2]))
					(void) fprintf(NetTrace, "%s ",
					    ENCTYPE_NAME(pointer[2]));
				else
					(void) fprintf(NetTrace,
					    " %d (unknown)", pointer[2]);

				encrypt_printsub(&pointer[1], length - 1,
				    (uchar_t *)buf, sizeof (buf));
				(void) fprintf(NetTrace, "%s", buf);
				break;

			case ENCRYPT_SUPPORT:
				i = 2;
				(void) fprintf(NetTrace, " SUPPORT ");
				while (i < length) {
					if (ENCTYPE_NAME_OK(pointer[i]))
						(void) fprintf(NetTrace, "%s ",
						    ENCTYPE_NAME(pointer[i]));
					else
						(void) fprintf(NetTrace, "%d ",
						    pointer[i]);
					i++;
				}
				break;

			case ENCRYPT_ENC_KEYID:
				(void) fprintf(NetTrace, " ENC_KEYID ");
				goto encommon;

			case ENCRYPT_DEC_KEYID:
				(void) fprintf(NetTrace, " DEC_KEYID ");
				goto encommon;

			default:
				(void) fprintf(NetTrace, " %d (unknown)",
				    pointer[1]);
			encommon:
				for (i = 2; i < length; i++)
					(void) fprintf(NetTrace, " %d",
					    pointer[i]);
				break;
			}
			break;

		case TELOPT_LINEMODE:
			(void) fprintf(NetTrace, "LINEMODE ");
			if (length < 2) {
				(void) fprintf(NetTrace,
				    " (empty suboption??\?)");
				break;
			}
			switch (pointer[1]) {
			case WILL:
				(void) fprintf(NetTrace, "WILL ");
				goto common;
			case WONT:
				(void) fprintf(NetTrace, "WONT ");
				goto common;
			case DO:
				(void) fprintf(NetTrace, "DO ");
				goto common;
			case DONT:
				(void) fprintf(NetTrace, "DONT ");
common:
				if (length < 3) {
					(void) fprintf(NetTrace,
						"(no option??\?)");
					break;
				}
				switch (pointer[2]) {
				case LM_FORWARDMASK:
					(void) fprintf(NetTrace,
					    "Forward Mask");
					for (i = 3; i < length; i++)
						(void) fprintf(NetTrace, " %x",
						    pointer[i]);
					break;
				default:
					(void) fprintf(NetTrace, "%d (unknown)",
					    pointer[2]);
					for (i = 3; i < length; i++)
					(void) fprintf(NetTrace,
					    " %d", pointer[i]);
					break;
				}
				break;

			case LM_SLC:
				(void) fprintf(NetTrace, "SLC");
				for (i = 2; i < length - 2; i += 3) {
					if (SLC_NAME_OK(pointer[i+SLC_FUNC]))
						(void) fprintf(NetTrace, " %s",
						    SLC_NAME(pointer[
						    i+SLC_FUNC]));
					else
						(void) fprintf(NetTrace, " %d",
						    pointer[i+SLC_FUNC]);
					switch (pointer[i+SLC_FLAGS] &
					    SLC_LEVELBITS) {
					case SLC_NOSUPPORT:
						(void) fprintf(NetTrace,
						    " NOSUPPORT");
						break;
					case SLC_CANTCHANGE:
						(void) fprintf(NetTrace,
						    " CANTCHANGE");
						break;
					case SLC_VARIABLE:
						(void) fprintf(NetTrace,
						    " VARIABLE");
						break;
					case SLC_DEFAULT:
						(void) fprintf(NetTrace,
						    " DEFAULT");
						break;
					}
					(void) fprintf(NetTrace, "%s%s%s",
					    pointer[i+SLC_FLAGS]&SLC_ACK ?
						"|ACK" : "",
					    pointer[i+SLC_FLAGS]&SLC_FLUSHIN ?
						"|FLUSHIN" : "",
					    pointer[i+SLC_FLAGS]&SLC_FLUSHOUT ?
						"|FLUSHOUT" : "");
					if (pointer[i+SLC_FLAGS] &
					    ~(SLC_ACK|SLC_FLUSHIN|
					    SLC_FLUSHOUT| SLC_LEVELBITS))
					(void) fprintf(NetTrace, "(0x%x)",
					    pointer[i+SLC_FLAGS]);
					(void) fprintf(NetTrace, " %d;",
					    pointer[i+SLC_VALUE]);
					if ((pointer[i+SLC_VALUE] == IAC) &&
					    (pointer[i+SLC_VALUE+1] == IAC))
						i++;
				}
				for (; i < length; i++)
					(void) fprintf(NetTrace, " ?%d?",
					    pointer[i]);
				break;

			case LM_MODE:
				(void) fprintf(NetTrace, "MODE ");
				if (length < 3) {
					(void) fprintf(NetTrace,
					    "(no mode??\?)");
					break;
				}
				{
					char tbuf[64];
					(void) sprintf(tbuf, "%s%s%s%s%s",
					    pointer[2]&MODE_EDIT ? "|EDIT" : "",
					    pointer[2]&MODE_TRAPSIG ?
					    "|TRAPSIG" : "",
					    pointer[2]&MODE_SOFT_TAB ?
					    "|SOFT_TAB" : "",
					    pointer[2]&MODE_LIT_ECHO ?
					    "|LIT_ECHO" : "",
					    pointer[2]&MODE_ACK ? "|ACK" : "");
					(void) fprintf(NetTrace, "%s", tbuf[1] ?
					    &tbuf[1] : "0");
				}
				if (pointer[2]&~(MODE_MASK))
					(void) fprintf(NetTrace, " (0x%x)",
					    pointer[2]);
				for (i = 3; i < length; i++)
					(void) fprintf(NetTrace, " ?0x%x?",
					    pointer[i]);
				break;
			default:
				(void) fprintf(NetTrace, "%d (unknown)",
				    pointer[1]);
				for (i = 2; i < length; i++)
					(void) fprintf(NetTrace, " %d",
					    pointer[i]);
				}
				break;

		case TELOPT_STATUS: {
				register char *cp;
				register int j, k;

				(void) fprintf(NetTrace, "STATUS");

				switch (pointer[1]) {
				default:
					if (pointer[1] == TELQUAL_SEND)
						(void) fprintf(NetTrace,
						    " SEND");
					else
						(void) fprintf(NetTrace,
						    " %d (unknown)",
						    pointer[1]);
					for (i = 2; i < length; i++)
					(void) fprintf(NetTrace, " ?%d?",
					    pointer[i]);
					break;
				case TELQUAL_IS:
					if (--want_status_response < 0)
						want_status_response = 0;
					if (NetTrace == stdout)
						(void) fprintf(NetTrace,
						    " IS\r\n");
					else
						(void) fprintf(NetTrace,
						    " IS\n");

					for (i = 2; i < length; i++) {
						switch (pointer[i]) {
						case DO:
							cp = "DO";
							goto common2;
						case DONT:
							cp = "DONT";
							goto common2;
						case WILL:
							cp = "WILL";
							goto common2;
						case WONT:
							cp = "WONT";
							goto common2;
common2:
							i++;
							if (TELOPT_OK(
							    (int)pointer[i]))
								(void) fprintf(
								    NetTrace,
								    " %s %s",
								    cp,
								    TELOPT(
								    pointer[
								    i]));
							else
								(void) fprintf(
								    NetTrace,
								    " %s %d",
								    cp,
								    pointer[i]);

							if (NetTrace == stdout)
								(void) fprintf(
								    NetTrace,
								    "\r\n");
							else
								(void) fprintf(
								    NetTrace,
								    "\n");
							break;

						case SB:
							(void) fprintf(NetTrace,
							    " SB ");
							i++;
							j = k = i;
							while (j < length) {
			if (pointer[j] == SE) {
				if (j+1 == length)
					break;
				if (pointer[j+1] == SE)
					j++;
				else
					break;
				}
				pointer[k++] = pointer[j++];
							}
							printsub(0,
							    &pointer[i], k - i);
							if (i < length) {
						(void) fprintf(NetTrace, " SE");
				i = j;
			} else
				i = j - 1;

			if (NetTrace == stdout)
				(void) fprintf(NetTrace, "\r\n");
			else
				(void) fprintf(NetTrace, "\n");

							break;

						default:
							(void) fprintf(NetTrace,
							    " %d", pointer[i]);
							break;
						}
					}
					break;
				}
				break;
			}

		case TELOPT_XDISPLOC:
			(void) fprintf(NetTrace, "X-DISPLAY-LOCATION ");
			switch (pointer[1]) {
			case TELQUAL_IS:
				(void) fprintf(NetTrace, "IS \"%.*s\"",
				    length-2, (char *)pointer+2);
				break;
			case TELQUAL_SEND:
				(void) fprintf(NetTrace, "SEND");
				break;
			default:
				(void) fprintf(NetTrace,
				    "- unknown qualifier %d (0x%x).",
				    pointer[1], pointer[1]);
			}
			break;

		case TELOPT_NEW_ENVIRON:
	    (void) fprintf(NetTrace, "NEW-ENVIRON ");
#ifdef	OLD_ENVIRON
	    goto env_common1;
	case TELOPT_OLD_ENVIRON:
	    (void) fprintf(NetTrace, "OLD-ENVIRON ");
	env_common1:
#endif
	    switch (pointer[1]) {
	    case TELQUAL_IS:
		(void) fprintf(NetTrace, "IS ");
		goto env_common;
	    case TELQUAL_SEND:
		(void) fprintf(NetTrace, "SEND ");
		goto env_common;
	    case TELQUAL_INFO:
		(void) fprintf(NetTrace, "INFO ");
	    env_common:
		{
		    register int noquote = 2;
#if defined(ENV_HACK) && defined(OLD_ENVIRON)
		    extern int old_env_var, old_env_value;
#endif
		    for (i = 2; i < length; i++) {
			switch (pointer[i]) {
			case NEW_ENV_VALUE:
#ifdef OLD_ENVIRON
		    /*	case NEW_ENV_OVAR: */
			    if (pointer[0] == TELOPT_OLD_ENVIRON) {
#ifdef	ENV_HACK
				if (old_env_var == OLD_ENV_VALUE)
					(void) fprintf(NetTrace,
					    "\" (VALUE) " + noquote);
				else
#endif
					(void) fprintf(NetTrace,
					    "\" VAR " + noquote);
			    } else
#endif /* OLD_ENVIRON */
				(void) fprintf(NetTrace, "\" VALUE " + noquote);
			    noquote = 2;
			    break;

			case NEW_ENV_VAR:
#ifdef OLD_ENVIRON
		    /* case OLD_ENV_VALUE: */
			    if (pointer[0] == TELOPT_OLD_ENVIRON) {
#ifdef	ENV_HACK
				if (old_env_value == OLD_ENV_VAR)
					(void) fprintf(NetTrace,
					    "\" (VAR) " + noquote);
				else
#endif
					(void) fprintf(NetTrace,
					    "\" VALUE " + noquote);
			    } else
#endif /* OLD_ENVIRON */
				(void) fprintf(NetTrace, "\" VAR " + noquote);
			    noquote = 2;
			    break;

			case ENV_ESC:
			    (void) fprintf(NetTrace, "\" ESC " + noquote);
			    noquote = 2;
			    break;

			case ENV_USERVAR:
			    (void) fprintf(NetTrace, "\" USERVAR " + noquote);
			    noquote = 2;
			    break;

			default:
			    if (isprint(pointer[i]) && pointer[i] != '"') {
				if (noquote) {
				    (void) putc('"', NetTrace);
				    noquote = 0;
				}
				(void) putc(pointer[i], NetTrace);
			    } else {
				(void) fprintf(NetTrace, "\" %03o " + noquote,
							pointer[i]);
				noquote = 2;
			    }
			    break;
			}
		    }
		    if (!noquote)
			(void) putc('"', NetTrace);
		    break;
		}
	    }
	    break;

	default:
	    if (TELOPT_OK(pointer[0]))
		(void) fprintf(NetTrace, "%s (unknown)", TELOPT(pointer[0]));
	    else
		(void) fprintf(NetTrace, "%d (unknown)", pointer[0]);
	    for (i = 1; i < length; i++)
		(void) fprintf(NetTrace, " %d", pointer[i]);
	    break;
	}
	if (direction) {
	    if (NetTrace == stdout)
		(void) fprintf(NetTrace, "\r\n");
	    else
		(void) fprintf(NetTrace, "\n");
	}
	if (NetTrace == stdout)
	    (void) fflush(NetTrace);
	}
}

/*
 * EmptyTerminal - called to make sure that the terminal buffer is empty.
 *			Note that we consider the buffer to run all the
 *			way to the kernel (thus the select).
 */

static void
EmptyTerminal()
{
	fd_set	o;

	FD_ZERO(&o);

	if (TTYBYTES() == 0) {
		FD_SET(tout, &o);
		/* wait for TTLOWAT */
		(void) select(tout+1, NULL, &o, NULL, NULL);
	} else {
		while (TTYBYTES()) {
			if (ttyflush(0) == -2) {
				/* This will not return. */
				fatal_tty_error("write");
			}
			FD_SET(tout, &o);
			/* wait for TTLOWAT */
			(void) select(tout+1, NULL, &o, NULL, NULL);
		}
	}
}

static void
SetForExit()
{
	setconnmode(0);
	do {
		(void) telrcv();		/* Process any incoming data */
		EmptyTerminal();
	} while (ring_full_count(&netiring));	/* While there is any */
	setcommandmode();
	(void) fflush(stdout);
	(void) fflush(stderr);
	setconnmode(0);
	EmptyTerminal();			/* Flush the path to the tty */
	setcommandmode();
}

void
Exit(returnCode)
	int returnCode;
{
	SetForExit();
	exit(returnCode);
}

void
ExitString(string, returnCode)
	char *string;
	int returnCode;
{
	SetForExit();
	(void) fwrite(string, 1, strlen(string), stderr);
	exit(returnCode);
}

#define	BUFFER_CHUNK_SIZE 64

/* Round up to a multiple of BUFFER_CHUNK_SIZE */
#define	ROUND_CHUNK_SIZE(s) ((((s) + BUFFER_CHUNK_SIZE - 1) / \
		BUFFER_CHUNK_SIZE) * BUFFER_CHUNK_SIZE)

/*
 * Optionally allocate a buffer, and optionally read a string from a stream
 * into the buffer, starting at the given offset.  If the buffer isn't
 * large enough for the given offset, or if buffer space is exhausted
 * when reading the string, the size of the buffer is increased.
 *
 * A buffer can be supplied when the function is called, passing the
 * buffer address via the first argument.  The buffer size can be
 * passed as well, in the second argument.  If the second argument is
 * NULL, the function makes no assumptions about the buffer size.
 * The address of the buffer is returned via the first argument, and the
 * buffer size via the second argument if this is not NULL.
 * These returned values may differ from the supplied values if the buffer
 * was reallocated.
 *
 * If no buffer is to be supplied, specify a buffer address of NULL, via
 * the first argument.
 *
 * If the pointer to the buffer address is NULL, the function just returns
 * NULL, and performs no other processing.
 *
 * If a NULL stream is passed, the function will just make sure the
 * supplied buffer is large enough to hold the supplied offset,
 * reallocating it if is too small or too large.
 *
 * The returned buffer will be a multiple of BUFFER_CHUNK_SIZE in size.
 *
 * The function stops reading from the stream when a newline is read,
 * end of file is reached, or an error occurs.  The newline is not
 * returned in the buffer.  The returned string will be NULL terminated.
 *
 * The function returns the address of the buffer if any characters
 * are read and no error occurred, otherwise it returns NULL.
 *
 * If the function returns NULL, a buffer may have been allocated.  The
 * buffer address will be returned via the first argument, together with
 * the buffer size if the second argument is not NULL.
 *
 */
static char *
GetStringAtOffset(bufp, cbufsiz, off, st)
	char **bufp;
	unsigned int *cbufsiz;
	unsigned int off;
	FILE *st;
{
	unsigned int bufsiz;
	char *buf;
	char *nbuf;
	unsigned int idx = off;

	if (bufp == NULL)
		return (NULL);

	buf = *bufp;

	bufsiz = ROUND_CHUNK_SIZE(off + 1);

	if (buf == NULL || cbufsiz == NULL || *cbufsiz != bufsiz) {
		if ((nbuf = realloc(buf, bufsiz)) == NULL)
			return (NULL);

		buf = nbuf;
		*bufp = buf;
		if (cbufsiz != NULL)
			*cbufsiz = bufsiz;
	}


	if (st == NULL)
		return (buf);

	clearerr(st);
	for (;;) {
		int c = getc(st);

		/* Expand the buffer as needed. */
		if (idx == bufsiz) {
			bufsiz += BUFFER_CHUNK_SIZE;
			if ((nbuf = realloc(buf, bufsiz)) == NULL) {
				/* Discard everything we read. */
				buf[off] = 0;
				buf = NULL;
				break;
			}
			buf = nbuf;
			*bufp = buf;
			if (cbufsiz != NULL)
				*cbufsiz = bufsiz;
		}

		if (c == EOF || c == '\n') {
			buf[idx] = 0;
			if (ferror(st) != 0) {
				/* Retry if interrupted by a signal. */
				if (errno == EINTR) {
					clearerr(st);
					continue;
				}
				buf = NULL;
			} else if (feof(st) != 0) {
				/* No characters transferred? */
				if (off == idx)
					buf = NULL;
			}
			break;
		}
		buf[idx++] = c;
	}
	return (buf);
}

/*
 * Read a string from the supplied stream.  Stop reading when a newline
 * is read, end of file reached, or an error occurs.
 *
 * A buffer can be supplied by specifying the buffer address via the
 * first argument. The buffer size can be passed via the second argument.
 * If the second argument is NULL, the function makes no assumptions
 * about the buffer size. The buffer will be reallocated if it is too
 * small or too large for the returned string.
 *
 * If no buffer is to be supplied, specify a buffer address of NULL,
 * via the first argument.
 *
 * If the first argument is NULL, the function just returns NULL, and
 * performs no other processing.
 *
 * The function returns the address of the buffer if any characters are
 * read and no error occurred.
 *
 * If the function returns NULL, a buffer may have been allocated.  The
 * buffer address and buffer size will be returned via the first argument,
 * and the buffer size via the second argument, if this isn't NULL.
 */
char *
GetString(bufp, bufsiz, st)
	char **bufp;
	unsigned int *bufsiz;
	FILE *st;
{
	return (GetStringAtOffset(bufp, bufsiz, 0, st));
}

/*
 * Allocate a buffer to hold a string of given length.
 *
 * An existing buffer can be reallocated by passing its address and via
 * the first argument.  The buffer size can be passed via the second
 * argument.  If the second argument is NULL, the function makes no
 * assumptions about the buffer size.
 *
 * If no existing buffer is to be supplied, pass a NULL buffer address via
 * the first argument.
 *
 * If the first argument is NULL, the function just returns NULL,
 * and performs no other processing.
 */
char *
AllocStringBuffer(bufp, bufsiz, size)
	char **bufp;
	unsigned int *bufsiz;
	unsigned int size;
{
	return (GetStringAtOffset(bufp, bufsiz, size, (FILE *)NULL));
}

/*
 * This function is similar to GetString(), except that the string read
 * from the stream is appended to the supplied string.
 */
char *
GetAndAppendString(bufp, bufsiz, str, st)
	char **bufp;
	unsigned int *bufsiz;
	char *str;
	FILE *st;
{
	unsigned int off = strlen(str);

	if (GetStringAtOffset(bufp, bufsiz, off, st) == NULL)
		return (NULL);

	return (memcpy(*bufp, str, off));
}
