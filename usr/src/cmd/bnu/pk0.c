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

extern void xlatecntl();
extern void pkcntl(), pkoutput(), pkclose(), pkreset(), pkzero(),
	pkgetpack(), pkxstart();
extern int pkread(), pkwrite(), pksack();
static int pksize(), chksum(), pkaccept();

extern int Connodata;		/* Continuous No Valid Data Count */
extern int xpacksize;

/*
 * receive control messages
 *	c	-> message type fields
 *	pk	-> line control unit
 */
void
pkcntl(c, pk)
int c;
struct pack *pk;
{
	int cntl, val;

	val = c & MOD8;
	cntl = (c>>3) & MOD8;

	if ( ! ISCNTL(c) ) {
		logent("PK0", "not cntl");
		return;
	}

	if (Debug >= 9)
		xlatecntl(0, c);
	switch(cntl) {

	case INITB:
		val++;
		pk->p_xsize = xpacksize = pksizes[val];
		pk->p_lpsize = val;
		pk->p_bits = 1;
		if (pk->p_state & LIVE) {
			pk->p_msg |= M_INITC;
			break;
		}
		pk->p_state |= INITb;
		if ((pk->p_state & INITa)==0) {
			break;
		}
		pk->p_rmsg &= ~M_INITA;
		pk->p_msg |= M_INITC;
		break;

	case INITC:
		if ((pk->p_state&INITab)==INITab) {
			pk->p_state = LIVE;
			pk->p_rmsg &= ~M_INITB;
		} else
			pk->p_msg |= M_INITB;
		if (val)
			pk->p_swindow = val;
		break;
	case INITA:
		if (val==0 && pk->p_state&LIVE) {
			logent("PK0", "alloc change not implemented");
			break;
		}
		if (val) {
			pk->p_state |= INITa;
			pk->p_msg |= M_INITB;
			pk->p_rmsg |= M_INITB;
			pk->p_swindow = val;
		}
		break;
	case RJ:
		pk->p_state |= RXMIT;
		pk->p_msg |= M_RR;
		DEBUG(9, "pkcntl: RJ: Connodata=%d\n", Connodata);
		/* FALLTHRU */
	case RR:
		pk->p_rpr = val;
		(void) pksack(pk);
		break;
	case CLOSE:
		pk->p_state = DOWN+RCLOSE;
		return;
	}
	if (pk->p_msg)
		pkoutput(pk);
}

static int
pkaccept()
{
	struct pack *pk;
	int x,seq;
	char m, cntl, *p, imask, **bp;
	int bad,accept,skip,t,cc;
	unsigned short sum;

	pk = Pk;
	bad = accept = skip = 0;

	/*
	 * wait for input
	 */
	x = next[pk->p_pr];
	while ((imask=pk->p_imap) == 0 && pk->p_rcount==0) {
		pkgetpack(pk);
	}
	pk->p_imap = 0;


	/*
	 * determine input window in m.
	 */
	t = (~(-1<<pk->p_rwindow)) <<x;
	m = t;
	m |= t>>8;


	/*
	 * mark newly accepted input buffers
	 */
	for(x=0; x<8; x++) {

		if ((imask & mask[x]) == 0)
			continue;

		if (((cntl=pk->p_is[x])&0200)==0) {
			bad++;
free:
			bp = (char **)pk->p_ib[x];
			*bp = (char *)pk->p_ipool;
			pk->p_ipool = bp;
			pk->p_is[x] = 0;
			continue;
		}

		pk->p_is[x] = (char) ~(B_COPY+B_MARK);
		sum = (unsigned)chksum(pk->p_ib[x], pk->p_rsize) ^ (unsigned)(cntl&0377);
		sum += pk->p_isum[x];
		if (sum == CHECK) {
			seq = (cntl>>3) & MOD8;
			if (m & mask[seq]) {
				if (pk->p_is[seq] & (B_COPY | B_MARK)) {
				dup:
					pk->p_msg |= M_RR;
					skip++;
					goto free;
				}
				if (x != seq) {
					p = pk->p_ib[x];
					pk->p_ib[x] = pk->p_ib[seq];
					pk->p_is[x] = pk->p_is[seq];
					pk->p_ib[seq] = p;
				}
				pk->p_is[seq] = B_MARK;
				accept++;
				cc = 0;
				if (cntl&B_SHORT) {
					pk->p_is[seq] = B_MARK+B_SHORT;
					p = pk->p_ib[seq];
					cc = (unsigned)*p++ & 0377;
					if (cc & 0200) {
						cc &= 0177;
						cc |= *p << 7;
					}
				}
				pk->p_isum[seq] = pk->p_rsize - cc;
			} else {
				goto dup;
			}
		} else {
			bad++;
			goto free;
		}
	}

	/*
	 * scan window again turning marked buffers into
	 * COPY buffers and looking for missing sequence
	 * numbers.
	 */
	accept = 0;
	for(x=next[pk->p_pr],t= -1; m & mask[x]; x = next[x]) {
		if (pk->p_is[x] & B_MARK)
			pk->p_is[x] |= B_COPY;

		if (pk->p_is[x] & B_COPY) {
			if (t >= 0) {
				bp = (char **)pk->p_ib[x];
				*bp = (char *)pk->p_ipool;
				pk->p_ipool = bp;
				pk->p_is[x] = 0;
				skip++;
			} else 
				accept++;
		} else if (t<0)
			t = x;
	}

	if (bad) {
		pk->p_msg |= M_RJ;
	}

	if (skip) {
		pk->p_msg |= M_RR;
	}

	pk->p_rcount = accept;
	return(accept);
}


int
pkread(ibuf, icount)
char *ibuf;
int icount;
{
	struct pack *pk;
	int x;
	int is,cc,xfr,count;
	char *cp, **bp;

	pk = Pk;
	xfr = 0;
	count = 0;
	while (pkaccept()==0)
		;
	Connodata = 0;		/* accecpted a packet -- good data */


	while (icount) {

		x = next[pk->p_pr];
		is = pk->p_is[x];

		if (is & B_COPY) {
			cc = MIN(pk->p_isum[x], icount);
			if (cc==0 && xfr) {
				break;
			}
			if (is & B_RESID)
				cp = pk->p_rptr;
			else {
				cp = pk->p_ib[x];
				if (is & B_SHORT) {
					if (*cp++ & 0200)
						cp++;
				}
			}
			if (cc)
				memcpy(ibuf, cp, cc);
			ibuf += cc;
			icount -= cc;
			count += cc;
			xfr++;
			pk->p_isum[x] -= cc;
			if (pk->p_isum[x] == 0) {
				pk->p_pr = x;
				bp = (char **)pk->p_ib[x];
				*bp = (char *)pk->p_ipool;
				pk->p_ipool = bp;
				pk->p_is[x] = 0;
				pk->p_rcount--;
				pk->p_msg |= M_RR;
			} else {
				pk->p_rptr = cp+cc;
				pk->p_is[x] |= B_RESID;
			}
			if (cc==0)
				break;
		} else
			break;
	}
	pkoutput(pk);
	return(count);
}

/* return number of bytes writtten */
int
pkwrite(ibuf, icount)
char *ibuf;
int icount;
{
	struct pack *pk;
	int x;
	caddr_t cp;
	int partial;
	int cc, fc, count;

	pk = Pk;
	if (pk->p_state&DOWN || !pk->p_state&LIVE) {
		return(-1);
	}

	count = icount;
	do {
		while (pk->p_xcount>=pk->p_swindow)  {
			pkoutput(pk);
			pkgetpack(pk);
		}
		x = next[pk->p_pscopy];
		while (pk->p_os[x]!=B_NULL)  {
			pkgetpack(pk);
		}
		pk->p_os[x] = B_MARK;
		pk->p_pscopy = x;
		pk->p_xcount++;

		cp = pk->p_ob[x] = (caddr_t) malloc((unsigned) pk->p_xsize);
		partial = 0;
		if ((int)icount < pk->p_xsize) {
			cc = icount;
			fc = pk->p_xsize - cc;
			*cp = fc&0177;
			if (fc > 127) {
				*cp++ |= 0200;
				*cp++ = fc>>7;
			} else
				cp++;
			partial = B_SHORT;
		} else
			cc = pk->p_xsize;
		memcpy(cp, ibuf, cc);
		ibuf += cc;
		icount -= cc;
		pk->p_osum[x] = chksum(pk->p_ob[x], pk->p_xsize);
		pk->p_os[x] = B_READY+partial;
		pkoutput(pk);
	} while (icount);

	return(count);
}

int
pksack(pk)
struct pack *pk;
{
	int x, i;

	i = 0;
	for(x=pk->p_ps; x!=pk->p_rpr; ) {
		x = next[x];
		if (pk->p_os[x]&B_SENT) {
			i++;
			Connodata = 0;
			pk->p_os[x] = B_NULL;
			pk->p_state &= ~WAITO;
			pk->p_xcount--;
			free((char *) pk->p_ob[x]);
			pk->p_ps = x;
		}
	}
	return(i);
}


void
pkoutput(pk)
struct pack *pk;
{
int x;
char bstate;
int i;

	if (pk->p_obusy++) {
		pk->p_obusy--;
		return;
	}


	/*
	 * find seq number and buffer state
	 * of next output packet
	 */
	if (pk->p_state&RXMIT)
		pk->p_nxtps = next[pk->p_rpr];
	x = pk->p_nxtps;
	bstate = pk->p_os[x];


	/*
	 * Send control packet if indicated
	 */
	if (pk->p_msg) {
		if (pk->p_msg & ~M_RR || !(bstate&B_READY) ) {
			x = pk->p_msg;
			for(i=0; i<8; i++) 
				if (x&1)
					break; 
else
				x >>= 1;
			x = i;
			x <<= 3;
			switch(i) {
			case CLOSE:
				break;
			case RJ:
			case RR:
				x += pk->p_pr;
				break;
			case INITB:
				x += pksize(pk->p_rsize);
				break;
			case INITC:
				x += pk->p_rwindow;
				break;
			case INITA:
				x += pk->p_rwindow;
				break;
			}

			pk->p_msg &= ~mask[i];
			pkxstart(pk, x, -1);
			goto out;
		}
	}


	/*
	 * Don't send data packets if line is marked dead.
	 */
	if (pk->p_state&DOWN) {
		goto out;
	}

	/*
	 * Start transmission (or retransmission) of data packets.
	 */
	if (bstate & (B_READY|B_SENT)) {
		char seq;

		bstate |= B_SENT;
		seq = x;
		pk->p_nxtps = next[x];

		x = 0200+pk->p_pr+(seq<<3);
		if (bstate & B_SHORT)
			x |= 0100;
		pkxstart(pk, x, seq);
		pk->p_os[seq] = bstate;
		pk->p_state &= ~RXMIT;
		pk->p_nout++;
		goto out;
	}

	/*
	 * enable timeout if there's nothing to send
	 * and transmission buffers are languishing
	 */
	if (pk->p_xcount) {
		pk->p_timer = 2;
		pk->p_state |= WAITO;
	} else
		pk->p_state &= ~WAITO;
out:
	pk->p_obusy = 0;
}

/*
 * shut down line by ignoring new input
 * letting output drain
 * releasing space
 */
void
pkclose()
{
	struct pack *pk;
	int i;
	int rcheck;
	char **bp;

	pk = Pk;
	pk->p_state |= DRAINO;

	/*
	 * try to flush output
	 */
	i = 0;
	pk->p_timer = 2;
	while (pk->p_xcount && pk->p_state&LIVE) {
		if (pk->p_state&(RCLOSE+DOWN) || ++i > 2)
			break;
		pkoutput(pk);
	}
	pk->p_timer = 0;
	pk->p_state |= DOWN;

	/*
	 * try to exchange CLOSE messages
	 */
	i = 0;
	while ((pk->p_state&RCLOSE)==0 && i<2) {
		pk->p_msg = M_CLOSE;
		pk->p_timer = 2;
		pkoutput(pk);
		i++;
	}

	/*
	 * free space
	 */
	rcheck = 0;
	for (i=0;i<8;i++) {
		if (pk->p_os[i]!=B_NULL) {
			free((char *) pk->p_ob[i]);
			pk->p_xcount--;
		}
		if (pk->p_is[i]!=B_NULL)  {
			free((char *) pk->p_ib[i]);
			rcheck++;
		}
	}
	while (pk->p_ipool != NULL) {
		bp = pk->p_ipool;
		pk->p_ipool = (char **)*bp;
		rcheck++;
		free((char *) bp);
	}
	if (rcheck  != pk->p_rwindow) {
		logent("PK0", "pkclose rcheck != p_rwindow");
	}
	free((char *) pk);
}


void
pkreset(pk)
struct pack *pk;
{

	pk->p_ps = pk->p_pr =  pk->p_rpr = 0;
	pk->p_nxtps = 1;
}

static int
chksum(s,n)
char *s;
int n;
{
	short sum;
	unsigned short t;
	short x;

	sum = -1;
	x = 0;

	do {
		if (sum<0) {
			sum <<= 1;
			sum++;
		} else
			sum <<= 1;
		t = sum;
		sum += (unsigned)*s++ & 0377;
		x += sum^n;
		if ((unsigned short)sum <= t) {
			sum ^= x;
		}
	} while (--n > 0);

	return(sum);
}

static int
pksize(n)
int n;
{
	int k;

	n >>= 5;
	for(k=0; n >>= 1; k++);
	return(k);
}
