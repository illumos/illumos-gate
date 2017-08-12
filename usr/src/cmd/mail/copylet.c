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
 * Copyright 2017 Gary Mills
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "mail.h"

/*
    NAME
	copylet - copy a given letter to a file pointer

    SYNOPSIS
	int copylet(int letnum, FILE *f, int type)

    DESCRIPTION
	Copylet() will copy the letter "letnum" to the
	given file pointer.

		letnum	-> index into: letter table
		f	-> file pointer to copy file to
		type	-> copy type

	Returns TRUE on a completely successful copy.
*/

int
copylet(int letnum, FILE *f, int type) 
{
	int		pos = ftell(f);
	int		rc  = xxxcopylet(letnum, f, type);

	if (fflush(f) != 0)
		rc = FALSE;
	
	/*
	 * On error, truncate the file to its original position so that a
	 * partial message is not left in the mailbox.
	 */
	if (rc == FALSE)
		ftruncate(fileno(f), pos);

	return(rc);
}

int
xxxcopylet(int letnum, FILE *f, int type) 
{
	static char	pn[] = "copylet";
	char	buf[LSIZE], lastc;
	char	wbuf[LSIZE];
	int	n;
	long	i, k;
	int	num;
	int	rtrncont = 1;	/* True: nondelivery&content included, or regular mail */
	int	suppress = FALSE;
	int	sav_suppress = FALSE; /* Did we suppress previous hdr line? */
	int	print_from_struct = FALSE; /* print from hdrlines struct */
					   /* rather than fgets() buffer */
	int	pushrest = FALSE;
	int	ctf = FALSE;
	int	didafflines = FALSE;	/* Did we already put out any */
					/* H_AFWDFROM lines? */
	int	didrcvlines = FALSE;	/* Did we already put out any */
					/* H_RECEIVED lines? */
	long	clen = -1L;
	int	htype;			/* header type */
	struct hdrs *hptr;

	if (!sending) {
		/* Clear out any saved header info from previous message */
		clr_hinfo();
	}

	fseek(tmpf, let[letnum].adr, 0);
	/* Get size of message as stored into tempfile by copymt() */
	k = let[letnum+1].adr - let[letnum].adr;
	Dout(pn, 1, "(letnum = %d, type = %d), k = %ld\n", letnum, type, k);
	while (k>0) {	/* process header */
		num = ((k < sizeof(buf)) ? k+1 : sizeof(buf));
		if (fgets (buf, num, tmpf) == NULL) {
			return (FALSE);
		}
		if ((n = strlen (buf)) == 0) {
			k = 0;
			break;
		}
		k -= n;
		lastc = buf[n-1];
		if (pushrest) {
			pushrest = (lastc != '\n');
			continue;
		}
		htype = isheader (buf, &ctf);
		Dout(pn, 5, "loop 1: buf = %s, htype= %d/%s\n", buf, htype, header[htype].tag);
		if (htype == H_CLEN) {
			if (!sending) {
				savehdrs(buf,htype);
			}
			if ((hptr = hdrlines[H_CLEN].head) !=
			    (struct hdrs *)NULL) {
				clen = atol (hptr->value);
			}
		}
		if (type == ZAP) {
			if (htype != FALSE) {
				pushrest = (lastc != '\n');
				continue;
			}
			/* end of header.  Print non-blank line and bail. */
			Dout(pn, 5, "ZAP end header; n=%d, buf[0] = %d\n", n, buf[0]);
			if (buf[0] != '\n') {
				if (fwrite(buf,1,n,f) != n) {
					sav_errno = errno;
					return(FALSE);
				}
			} else {
				n = 0;
			}
			break;
		}
		/* Copy From line appropriately */
		if (fwrite(buf,1,n-1,f) != n-1)  {
			sav_errno = errno;
			return(FALSE);
		}
		if (lastc != '\n') {
			if (fwrite(&lastc,1,1,f) != 1) {
				sav_errno = errno;
				return(FALSE);
			}
			continue;
		}
		switch(type) {
			case REMOTE:
				if (fprintf(f, rmtmsg, thissys) < 0)
				{
					sav_errno = errno;
					return(FALSE);
				}
				
				break;

			case TTY:
			case ORDINARY:
			default:
				if (fprintf(f, "\n") < 0)
				{
					sav_errno = errno;
					return(FALSE);
				}
				break;
		}
		if ((error > 0) && (dflag == 1)) {
			Dout(pn, 3, "before gendeliv(), uval = '%s'\n", uval);
			gendeliv(f, dflag, uval);
			if (!(ckdlivopts(H_TCOPY, (int*)0) & RETURN)) {
				rtrncont = 0;
			} else {
				/* Account for content-type info */
				/* of returned msg */
				if (fprintf(f, "%s %s\n", header[H_CTYPE].tag,
				    (let[letnum].text == TRUE ? "text/plain" : "application/octet-stream")) < 0)
				{
					sav_errno = errno;
					return(FALSE);
				}

				/* Compute Content-Length of what's being */
				/* returned... */
				i = k;
				/* Account for H_AFWDFROM, H_AFWDCNT, */
				/* H_TCOPY, or H_RECEIVED lines which may */
				/* be added later */
				if (affcnt > 0) {
					sprintf(wbuf, "%d", affcnt);
					i += (affbytecnt
						+ strlen(header[H_AFWDCNT].tag)
						+ strlen(wbuf) + 2);
				}
				if (orig_tcopy) {
				    if ((hptr = hdrlines[H_TCOPY].head) !=
							(struct hdrs *)NULL) {
				        i +=
					  strlen(hdrlines[H_TCOPY].head->value);
				    }
				}
				if ((hptr = hdrlines[H_RECEIVED].head) !=
							(struct hdrs *)NULL) {
				    i += rcvbytecnt;
				}
				/* Add in strlen of MIME-Version:, */
				/* Content-Length: and Content-Type: */
				/* values for msg being returned... */
				if ((hptr = hdrlines[H_MIMEVERS].head) !=
							(struct hdrs *)NULL) {
				    i += strlen(hdrlines[H_MIMEVERS].head->value);
				}
				if ((hptr = hdrlines[H_CTYPE].head) !=
							(struct hdrs *)NULL) {
				    i += strlen(hdrlines[H_CTYPE].head->value);
				}
				if ((hptr = hdrlines[H_CLEN].head) !=
							(struct hdrs *)NULL) {
				    i += strlen(hdrlines[H_CLEN].head->value);
				}
				if (fprintf(f, "%s %ld\n", header[H_CLEN].tag, i) < 0)
				{
					sav_errno = errno;
					return(FALSE);
				}
			}
			if (fprintf(f, "\n") < 0)
			{
				sav_errno = errno;
				return(FALSE);
			}
		}
		if (fflush(f))
		{
			sav_errno = errno;
			return(FALSE);
		}
		
		break;
	}
	/* if not ZAP, copy balance of header */
	n = 0;
	if ((type != ZAP) && rtrncont)
		while (k>0 || n>0) {
			if ((n > 0) && !suppress) {
				if (print_from_struct == TRUE) {
					if (printhdr (type, htype, hptr, f) < 0) {
						return (FALSE);
					}
				} else {
				    if (sel_disp(type, htype, buf) >= 0) {
					if (fwrite(buf,1,n,f) != n)  {
						sav_errno = errno;
						return(FALSE);
					}
				    }
				}
				if (htype == H_DATE) {
					dumprcv(type, htype,&didrcvlines,&suppress,f);
					dumpaff(type, htype,&didafflines,&suppress,f);
				}
			}
			if (k <= 0) {
				/* Can only get here if k=0 && n>0, which occurs */
				/* in a message with header lines but no content. */
				/* If we haven't already done it, force out any */
				/* H_AFWDFROM or H_RECEIVED lines */
				dumprcv(type, -1,&didrcvlines,&suppress,f);
				dumpaff(type, -1,&didafflines,&suppress,f);
				break;
			}
			num = ((k < sizeof(buf)) ? k+1 : sizeof(buf));
			if (fgets (buf, num, tmpf) == NULL) {
				return (FALSE);
			}
			n = strlen (buf);
			k -= n;
			lastc = buf[n-1];

			if (pushrest) {
				pushrest = (lastc != '\n');
				continue;
			}
			sav_suppress = suppress;
			suppress = FALSE;
			print_from_struct = FALSE;
			htype = isheader (buf, &ctf);
			Dout(pn, 5, "loop 2: buf = %s, htype= %d/%s\n", buf, htype, header[htype].tag);
			/* The following order is defined in the MTA documents. */
			switch (htype) {
			case H_CONT:
			    if (sending) {
				suppress = sav_suppress;
			    }
			    continue;
			case H_TCOPY:
			case H_MIMEVERS:
			case H_CTYPE:
			case H_CLEN:
				if (!sending) {
					savehdrs(buf,htype);
				}
				hptr = hdrlines[htype].head;
				if (htype == H_CLEN) {
					clen = atol (hptr->value);
				}
				/*
				 * Use values saved in hdrlines[] structure
				 * rather than what was read from tmp file.
				 */
				print_from_struct = TRUE;
				/* FALLTHROUGH */
			case H_EOH:
			case H_AFWDFROM:
			case H_AFWDCNT:
			case H_RECEIVED:
				dumprcv(type, htype,&didrcvlines,&suppress,f);
				dumpaff(type, htype,&didafflines,&suppress,f);
				continue;	/* next header line */
			default:
				pushrest = (lastc != '\n');
				continue;	/* next header line */
			case FALSE:	/* end of header */
				break;
			}

			/* Found the blank line after the headers. */
			if (n > 0) {
				if (fwrite(buf,1,n,f) != n)  {
					sav_errno = errno;
					return(FALSE);
				}
			}

			Dout(pn, 3,", let[%d].text = %s\n",
				letnum, (let[letnum].text ? "TRUE" : "FALSE"));

			if ((type == TTY) && (let[letnum].text == FALSE) && !pflg) {
				if (fprintf (f, "\n%s\n", binmsg) < 0)
				{
					sav_errno = errno;
					return(FALSE);
				}
				return (TRUE);
			}

			if (n == 1 && buf[0] == '\n') {
				n = 0;
			}
			break;
		}

	Dout(pn, 1, "header processed, clen/k/n = %ld/%ld/%d\n", clen, k, n);

	if (clen >= 0) {
		if (((clen - n) == k) || ((clen - n) == (k - 1))) {
			k = clen - n;
		} else {
			/* probable content-length mismatch. show it ALL! */
			Dout(pn, 1, "clen conflict. using k = %ld\n", k);
		}
	}

	/* copy balance of message */
	if (rtrncont)
		while (k > 0) {
			num = ((k < sizeof(buf)) ? k : sizeof(buf));
			if ((n = fread (buf, 1, num, tmpf)) <= 0) {
				Dout(pn, 1, "content-length mismatch. return(FALSE)\n");
				return(FALSE);
			}
			k -= n;
			if (fwrite(buf,1,n,f) != n)  {
				sav_errno = errno;
				return(FALSE);
			}
		}

	Dout(pn, 3, "body processed, k=%ld\n", k);

	if (rtrncont && type != ZAP && type != REMOTE) {
		if (fwrite("\n",1,1,f) != 1)  {
			sav_errno = errno;
			return(FALSE);
		}
	}

	return(TRUE);
}
