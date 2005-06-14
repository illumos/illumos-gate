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


#pragma ident	"%Z%%M%	%I%	%E% SMI" 	/* SVr4.0 2.1	*/
/*
    NAME
	copymt - copy mail (f1) to temp (f2)

    SYNOPSIS
	void copymt(FILE *f1, FILE *f2)

    DESCRIPTION
	The mail messages in /var/mail are copied into
	the temp file. The file pointers f1 and f2 point
	to the files, respectively.
*/
#include "mail.h"

void copymt(f1, f2)
register FILE *f1, *f2;
{
	static char pn[] = "copymt";
	long nextadr;
	int n, newline = 1;
	int StartNewMsg = TRUE;
	int ToldUser = FALSE;
	int mesg = 0;
	int ctf = FALSE; 		/* header continuation flag */
	long clen = (long)0;
	int hdr = 0;
	int cflg = 0;			/* found Content-length in header */

	Dout(pn, 0,"entered\n");
	if (!let[1].adr) {
		nlet = nextadr = 0;
		let[0].adr = 0;
		let[0].text = TRUE;	/* until proven otherwise.... */
		let[0].change = ' ';
	} else {
		nextadr = let[nlet].adr;
	}

	while ((n = getline(line, sizeof line, f1)) > 0) {
		if (!newline) {
			goto putout;
		} else if ((hdr = isheader (line, &ctf)) == FALSE) {
			ctf = FALSE;	/* next line can't be cont. */
		}
		if (!hdr && cflg) {	/* nonheader, Content-length seen */
			if (clen < n) {	/* read too much */
				/* NB: this only can happen if the content-length
				 * says a smaller number than what's seen on the
				 * first non-header line.
				 */
				if (let[nlet-1].text == TRUE) {
					let[nlet-1].text = istext((unsigned char*)line,clen);
				    Dout(pn, 0, "1, let[%d].text = %s\n",
					   nlet-1,
					   (let[nlet-1].text ? "TRUE":"FALSE"));
				}
				if (fwrite(line,1,(int)clen,f2) != clen) {
					fclose(f1); fclose(f2);
					errmsg(E_FILE,
						"Write error in copymt()");
					done(0);
				}
				nextadr += clen;
				n -= clen;
				strmove (line, line+clen);
				cflg = 0;
				ctf = FALSE;
				hdr = isheader(line, &ctf);
				goto dohdr;
			}
			/* here, clen >= n */
			if (n == 1 && line[0] == '\n'){	/* leading empty line */
				clen++;		/* cheat */
			}
			nextadr += clen;
			for (;;) {
				if (let[nlet-1].text == TRUE) {
					let[nlet-1].text = istext((unsigned char*)line,n);
				  Dout(pn, 0, "2, let[%d].text = %s\n",
					nlet-1,
					(let[nlet-1].text ? "TRUE" : "FALSE"));
				}
				if (fwrite(line,1,n,f2) != n) {
					fclose(f1); fclose(f2);
					errmsg(E_FILE,
						"Write error in copymt()");
					done(0);
				}
				clen -= n;
				if (clen <= 0) {
					break;
				}
				n = clen < sizeof line ? clen : sizeof line;
				if ((n = fread (line, 1, n, f1)) <= 0) {
				    fprintf(stderr,
		"%c%s:\tYour mailfile was found to be corrupted.\n",
						BELL, program);
				    fprintf(stderr,
					"\t(Unexpected end-of-file).\n");
				    fprintf(stderr,
					"\tMessage #%d may be truncated.%c\n\n",
						nlet, BELL);
					nextadr -= clen;
					clen = 0; /* stop the loop */
				}
			}
			/* All done, go to top for next message */
			cflg = 0;
			StartNewMsg = TRUE;
			continue;
		}

dohdr:
		switch (hdr) {
		case H_FROM:
			if(nlet >= (MAXLET-2)) {
				if (!mesg) {
					fprintf(stderr,"%s: Too many letters, overflowing letters concatenated\n\n",program);
					mesg++;
				}
			} else {
				let[nlet++].adr = nextadr;
				let[nlet].text = TRUE;
				let[nlet].change = ' ';
			}
			Dout(pn, 5, "setting StartNewMsg to FALSE\n");
			StartNewMsg = FALSE;
			ToldUser = FALSE;
			break;
		case H_CLEN:
			if (cflg) {
				break;
			}
			cflg = TRUE;	/* mark for clen processing */
			clen = atol (strpbrk (line, ":")+1);
			break;
		default:
			break;
		}

putout:
		if (nlet == 0) {
			fclose(f1);
			fclose(f2);
			errmsg(E_FILE,"mailfile does not begin with a 'From' line");
			done(0);
		}
		nextadr += n;
		if (let[nlet-1].text == TRUE) {
			let[nlet-1].text = istext((unsigned char*)line,n);
		        Dout(pn, 5,"3, let[%d].text = %s\n",
				nlet-1, (let[nlet-1].text ? "TRUE" : "FALSE"));
		}
		if (fwrite(line,1,n,f2) != n) {
			fclose(f1);
			fclose(f2);
			errmsg(E_FILE,"Write error in copymt()");
			done(0);
		}
		if (line[n-1] == '\n') {
			newline = 1;
			if (n == 1) { /* Blank line. Skip StartNewMsg */
				      /* check below                  */
				continue;
			}
		} else {
			newline = 0;
		}
		if (StartNewMsg == TRUE && ToldUser == FALSE) {
			fprintf(stderr,
			     "%c%s:\tYour mailfile was found to be corrupted\n",
			     BELL, program);
			fprintf(stderr, "\t(Content-length mismatch).\n");
			fprintf(stderr,"\tMessage #%d may be truncated,\n",
			     nlet);
			fprintf(stderr,
			    "\twith another message concatenated to it.%c\n\n",
			    BELL);
			ToldUser = TRUE;
		}
	}

	/*
		last plus 1
	*/
	let[nlet].adr = nextadr;
	let[nlet].change = ' ';
	let[nlet].text = TRUE;
}
