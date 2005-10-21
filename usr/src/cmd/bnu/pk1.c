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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "uucp.h"

#include "pk.h"
#include <sys/buf.h>

extern void pkfail(), pkzero(), pkoutput(), pkreset(), pkcntl(), pkgetpack();
extern int pksack();
static void pkdata();
static int pkcget();
static void xlatestate(struct pack *, int);
void xlatecntl(int, int);

/*
 * Code added to allow translation of states from numbers to
 * letters, to be done in such a way as to be meaningful to 
 * John Q. Public
 */
struct {
	int state;
	char *msg;
} st_trans[] = {
	DEAD,	"Dead!",
	INITa,	"INIT code a",
	INITb,	"INIT code b",
	LIVE,	"O.K.",
	RXMIT,	"Rcv/Xmit",
	RREJ,	"RREJ?",
	PDEBUG,	"PDEBUG?",
	DRAINO,	"Draino...",
	WAITO,	"Waiting",
	DOWN,	"Link down",
	RCLOSE,	"RCLOSE?",
	BADFRAME,	"Bad frame",
	-1,	"End of the line",
};

extern char _Protocol[];	/* Protocol string with (options) */

#define PKMAXSTMSG 40
int Connodata = 0;		/* Continuous Non Valid Data Count */
int Ntimeout = 0;
#define CONNODATA	20	/* Max Continuous Non Valid Data Count */
#define NTIMEOUT	50	/* This is not currently used, but maybe future */

extern jmp_buf Getjbuf;

/*
 * start initial synchronization.
 */
struct pack *
pkopen(ifn, ofn)
int ifn, ofn;
{
	struct pack *pk;
	char **bp;
	int i;
	int windows = WINDOWS;
	extern int xpacksize, packsize;

	if ((pk = (struct pack *) calloc(1, sizeof (struct pack))) == NULL)
		return(NULL);
	pk->p_ifn = ifn;
	pk->p_ofn = ofn;
	DEBUG(7, "Setting up protocol parameters '%s'\n", _Protocol);
	if ( _Protocol[1] == '(' ) {
	    if (sscanf(_Protocol, "%*c(%d,%d)", &windows, &packsize) == 0)
	    sscanf(_Protocol, "%*c(,%d)", &packsize);
	    windows = ( windows < MINWINDOWS ? WINDOWS :
			( windows > MAXWINDOWS ? WINDOWS : windows ) );
	    packsize = ( packsize < MINPACKSIZE ? PACKSIZE :
			( packsize > MAXPACKSIZE ? PACKSIZE : packsize ) );
	}
	if ( (_Protocol[0] == 'g') && (packsize > OLDPACKSIZE) ) {
	    /*
	     * We reset to OLDPACKSIZE to maintain compatibility
	     * with old limited implementations. Maybe we should
	     * just warn the administrator and continue?
	     */
	    packsize = OLDPACKSIZE;
	}
	pk->p_xsize = pk->p_rsize = xpacksize = packsize;
	pk->p_rwindow = pk->p_swindow = windows;

	/*
	 * allocate input window
	 */
	for (i = 0; i < pk->p_rwindow; i++) {
		if ((bp = (char **) malloc((unsigned) pk->p_xsize)) == NULL)
			break;
		*bp = (char *) pk->p_ipool;
		pk->p_ipool = bp;
	}
	if (i == 0)
		return(NULL);
	pk->p_rwindow = i;

	/*
	 * start synchronization
	 */
	pk->p_msg = pk->p_rmsg = M_INITA;
	pkoutput(pk);

	for (i = 0; i < PKMAXSTMSG; i++) {
		pkgetpack(pk);
		if ((pk->p_state & LIVE) != 0)
			break;
	}
	if (i >= PKMAXSTMSG)
		return(NULL);

	pkreset(pk);
	return(pk);
}

/*
 * input framing and block checking.
 * frame layout for most devices is:
 *	
 *	S|K|X|Y|C|Z|  ... data ... |
 *
 *	where 	S	== initial synch byte
 *		K	== encoded frame size (indexes pksizes[])
 *		X, Y	== block check bytes
 *		C	== control byte
 *		Z	== XOR of header (K^X^Y^C)
 *		data	== 0 or more data bytes
 *
 */
#define GETRIES 10

/*
 * Byte collection.
 */
void
pkgetpack(ipk)
struct pack *ipk;
{
	char *p;
	struct pack *pk;
	struct header *h;
	unsigned short sum;
	int k, tries, ifn, noise;
	char **bp, hdchk;

	pk = ipk;
	/*
	 * If we are known to be DOWN, or if we've received too many garbage
	 * packets or timeouts, give up without a fight.
	 */
	if ((pk->p_state & DOWN) || Connodata > CONNODATA  || Ntimeout > NTIMEOUT)
		pkfail();
	ifn = pk->p_ifn;
	h = &pk->p_ihbuf;

	/*
	 * Attempt no more than GETRIES times to read a packet.  The only valid
	 * exit from this loop is a return.  Break forces a failure.
	 */
	for (tries = 0; tries < GETRIES; tries++) {
		/*
		 * Read header.
		 * First look for SYN.  If more than 3 * packetsize characters
		 * go by w/o a SYN, request a retransmit.
		 */
		p = (caddr_t) h;
		noise = 0;
		for ( ; ; ) {
			if (pkcget(ifn, p, HDRSIZ) != SUCCESS) {
				DEBUG(7,
		"Alarm while looking for SYN -- request RXMIT\n%s", "");
				goto retransmit;
			}
			if (*p == SYN)
				break;		/* got it */
			else {
				char *pp, *pend;

				DEBUG(7, "first char not SYN (%x)\n", *p&0xff);
				if ((pp = memchr(p, SYN, HDRSIZ)) != NULL) {
					pend = p + HDRSIZ;
					while (pp < pend)
						*p++ = *pp++;
					/* Now look for remainder of header */
					if (pkcget(ifn, p, pend - p) !=
					    SUCCESS) {
						DEBUG(7,
		"Alarm while looking for header -- request RXMIT\n%s", "");
						goto retransmit;
					}
					p = (caddr_t) h;
					break;	/* got entire header */
				}
			}
			if ((noise += HDRSIZ) > 3 * pk->p_rsize) {
				DEBUG(7,
			"No SYN in %d characters -- request RXMIT\n", noise);
				goto retransmit;
			}
		}
		/* Validate the header */		
		Connodata++;
		hdchk = p[1] ^ p[2] ^ p[3] ^ p[4];
		sum = ((unsigned) p[2] & 0377) | ((unsigned) p[3] << 8);
		h->sum = sum;
		k = h->ksize;
		if (hdchk != h->ccntl) {
			/* bad header */
			DEBUG(7, "bad header checksum\n%s", "");
			return;
		}

		if (k == 9) {	/* control packet */
			if (((h->sum + h->cntl) & 0xffff) == CHECK) {
				pkcntl(h->cntl, pk);
				xlatestate(pk, 7);
			} else {
				/* bad header */
				DEBUG(7, "bad header (k == 9) 0%o\n", h->cntl&0xff);
				pk->p_state |= BADFRAME;
			}
			return;
		}
		/* data packet */
		if (k && pksizes[k] != pk->p_rsize)
			return;
		pk->p_rpr = h->cntl & MOD8;
		pksack(pk);
		if ((bp = pk->p_ipool) == NULL) {
			DEBUG(7, "bp NULL\n%s", "");
			return;
		}
		pk->p_ipool = (char **) *bp;
		/* Header checks out, go for data */
		if (pkcget(pk->p_ifn, (char *) bp, pk->p_rsize) == SUCCESS) {
			pkdata(h->cntl, h->sum, pk, bp);
			Ntimeout = 0;
			return;
		}
		DEBUG(7, "Alarm while reading data -- request RXMIT\n%s", "");
retransmit:
		/*
		 * Transmission error or excessive noise.  Send a RXMIT
		 * and try again.
		 */
/*
		Retries++;
*/
		pk->p_msg |= pk->p_rmsg;
		if (pk->p_msg == 0)
			pk->p_msg |= M_RR;
		if ((pk->p_state & LIVE) == LIVE)
			pk->p_state |= RXMIT;
		pkoutput(pk);
	}
	DEBUG(7, "pkgetpack failed after %d tries\n", tries);
	pkfail();
}

/*
 * Translate pk->p_state into something printable.
 */
static void
xlatestate(pk, dbglvl)
struct pack *pk;
int dbglvl;
{
	int i;
	char delimc = ' ', msgline[80], *buf = msgline;

	if (Debug < dbglvl)
		return;
	sprintf(buf, "state -");
	buf += strlen(buf);
	for(i = 0; st_trans[i].state != -1; i++) {
		if (pk->p_state&st_trans[i].state){
			sprintf(buf, "%c[%s]", delimc, st_trans[i].msg);
			buf += strlen(buf);
			delimc = '&';
		}
	}
	sprintf(buf, " (0%o)\n", pk->p_state);
	DEBUG(dbglvl, "%s", msgline);
	return;
}

static void
pkdata(c, sum, pk, bp)
struct pack *pk;
unsigned short sum;
char c;
char **bp;
{
	int x;
	int t;
	char m;

	if (pk->p_state & DRAINO || !(pk->p_state & LIVE)) {
		pk->p_msg |= pk->p_rmsg;
		pkoutput(pk);
		goto drop;
	}
	t = next[pk->p_pr];
	for(x=pk->p_pr; x!=t; x = (x-1)&7) {
		if (pk->p_is[x] == 0)
			goto slot;
	}
drop:
	*bp = (char *)pk->p_ipool;
	pk->p_ipool = bp;
	return;

slot:
	m = mask[x];
	pk->p_imap |= m;
	pk->p_is[x] = c;
	pk->p_isum[x] = sum;
	pk->p_ib[x] = (char *)bp;
}

/*
 * Start transmission on output device associated with pk.
 * For asynch devices (t_line==1) framing is
 * imposed.  For devices with framing and crc
 * in the driver (t_line==2) the transfer is
 * passed on to the driver.
 */
void
pkxstart(pk, cntl, x)
struct pack *pk;
int x;
char cntl;
{
	char *p;
	short checkword;
	char hdchk;

	p = (caddr_t) &pk->p_ohbuf;
	*p++ = SYN;
	if (x < 0) {
		*p++ = hdchk = 9;
		checkword = cntl;
	} else {
		*p++ = hdchk = pk->p_lpsize;
		checkword = pk->p_osum[x] ^ (unsigned)(cntl & 0377);
	}
	checkword = CHECK - checkword;
	*p = checkword;
	hdchk ^= *p++;
	*p = checkword>>8;
	hdchk ^= *p++;
	*p = cntl;
	hdchk ^= *p++;
	*p = hdchk;

 /*
  * writes
  */
	if (Debug >= 9)
		xlatecntl(1, cntl);

	p = (caddr_t) & pk->p_ohbuf;
	if (x < 0) {
		if ((*Write)(pk->p_ofn, p, HDRSIZ) != HDRSIZ) {
			DEBUG(4, "pkxstart, write failed, %s\n",
			    strerror(errno));
			logent(strerror(errno), "PKXSTART WRITE");
			pkfail();
			/* NOT REACHED */
		}
	} else {
		char buf[MAXPACKSIZE + HDRSIZ]; 

		memcpy(buf, p, HDRSIZ);
		memcpy(buf+HDRSIZ, pk->p_ob[x], pk->p_xsize);
		if ((*Write)(pk->p_ofn, buf, pk->p_xsize + HDRSIZ) !=
		    pk->p_xsize + HDRSIZ) {
			DEBUG(4, "pkxstart, write failed, %s\n",
			    strerror(errno));
			logent(strerror(errno), "PKXSTART WRITE");
			pkfail();
			/* NOT REACHED */
		}
		Connodata = 0;
	}
	if (pk->p_msg)
		pkoutput(pk);
}

/*
 * get n characters from input
 *	b	-> buffer for characters
 *	fn	-> file descriptor
 *	n	-> requested number of characters
 * return: 
 *	SUCCESS	-> n chars successfully read
 *	FAIL	-> o.w.
 */

static int
pkcget(fn, b, n)
int n;
char *b;
int fn;
{
	int ret;
#ifdef PKSPEEDUP
	extern int linebaudrate;
	int donap = (linebaudrate > 0 && linebaudrate < 4800);
#endif /*  PKSPEEDUP  */

	if (n == 0)
		return(SUCCESS);
	if (setjmp(Getjbuf)) {
		Ntimeout++;
		DEBUG(4, "pkcget: alarm %d\n", Ntimeout);
		return(FAIL);
	}

	(void) alarm( (unsigned) ( 10 + (n >> 7)) );

	for (;;) {
		ret = (*Read)(fn, b, n);
		(void) alarm(0);
		if (ret == 0) {
			DEBUG(4, "pkcget, read failed, EOF\n", 0);
			/*
			 * Device has decided that the connection has no
			 * more data to send.  Any further tries are futile...
			 * (The only other way to get a zero return value
			 * is to read a zero length message from a STREAM.
			 * However, uucp *never* sends zero length messages
			 * over any sort of channel...)
			 */
			pkfail();
			/* NOT REACHED */
		}
		if (ret < 0) {
			DEBUG(4, "pkcget, read failed, %s\n",
			    strerror(errno));
			logent(strerror(errno), "PKCGET READ");
			pkfail();
			/* NOT REACHED */
		}
		if ((n -= ret) <= 0)
			break;
#ifdef PKSPEEDUP
		if (donap) {
#if defined(BSD4_2) || defined(ATTSVR4)
			/* wait for more chars to come in */
			nap((n * HZ * 10) / linebaudrate); /* n char times */
#else
			sleep(1);
#endif
		}
#endif /*  PKSPEEDUP  */
		b += ret;
		(void) alarm( (unsigned) ( 10 + (n >> 7)) );
	}
	(void) alarm(0);
	return(SUCCESS);
}

/*
 * role == 0: receive
 * role == 1: send
 */
void
xlatecntl(role, cntl)
int role;
int cntl;
{
	static char *cntltype[4] = {"CNTL, ", "ALT, ", "DATA, ", "SHORT, "};
	static char *cntlxxx[8] = {"ZERO, ", "CLOSE, ", "RJ, ", "SRJ, ",
				   "RR, ", "INITC, ", "INITB, ", "INITA, "};
	char dbgbuf[128];
	char *ptr;

	ptr = dbgbuf;
	strcpy(ptr, role ? "send " : "recv ");
	ptr += strlen(ptr);

	strcpy(ptr, cntltype[(cntl&0300)>>6]);
	ptr += strlen(ptr);

	if (cntl&0300) {
		/* data packet */
		if (role)
			sprintf(ptr, "loc %o, rem %o\n", (cntl & 070) >> 3, cntl & 7);
		else
			sprintf(ptr, "loc %o, rem %o\n", cntl & 7, (cntl & 070) >> 3);
	} else {
		/* control packet */
		strcpy(ptr, cntlxxx[(cntl&070)>>3]);
		ptr += strlen(ptr);
		sprintf(ptr, "val %o\n", cntl & 7);
	}

	DEBUG(1, dbgbuf, 0);
}
