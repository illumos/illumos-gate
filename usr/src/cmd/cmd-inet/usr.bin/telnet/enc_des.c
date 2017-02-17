/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * usr/src/cmd/cmd-inet/usr.bin/telnet/enc_des.c
 */

/*
 * Copyright (c) 1991, 1993
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

/*
 * Copyright (C) 1998 by the FundsXpress, INC.
 *
 * All rights reserved.
 *
 * Export of this software from the United States of America may require
 * a specific license from the United States Government.  It is the
 * responsibility of any person or organization contemplating export to
 * obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of FundsXpress. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  FundsXpress makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* based on @(#)enc_des.c	8.1 (Berkeley) 6/4/93 */
/*
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <krb5.h>
#include <stdio.h>
#include <arpa/telnet.h>

#ifdef	__STDC__
#include <stdlib.h>
#endif

#include "externs.h"

extern	boolean_t encrypt_debug_mode;
extern	krb5_context telnet_context;

#define	KEYFLAG_SHIFT	2
#define	SHIFT_VAL(a, b) (KEYFLAG_SHIFT*((a)+((b)*2)))

static	struct _fb {
	Block temp_feed;
	int state[2];		/* state for each direction */
	int keyid[2];		/* keyid for each direction */
	int once;
	unsigned char fb_feed[64];
	boolean_t need_start;
	boolean_t validkey;
	struct stinfo {
		Block		str_output;
		Block		str_feed;
		Block		str_iv;
		unsigned char	str_keybytes[DES_BLOCKSIZE];
		krb5_keyblock	str_key;
		int		str_index;
		int		str_flagshift;
	} streams[2];		/* one for encrypt, one for decrypt */
} des_cfb;

static	void cfb64_stream_iv(Block, struct stinfo *);
static	void cfb64_stream_key(Block, struct stinfo *);

static void
ecb_encrypt(struct stinfo *stp, Block in, Block out)
{
	krb5_error_code code;
	krb5_data din;
	krb5_enc_data dout;

	din.length = DES_BLOCKSIZE;
	din.data = (char *)in;

	dout.ciphertext.length = DES_BLOCKSIZE;
	dout.ciphertext.data = (char *)out;
	/* this is a kerberos enctype, not a telopt enctype */
	dout.enctype = ENCTYPE_UNKNOWN;

	code = krb5_c_encrypt(telnet_context, &stp->str_key, NULL, NULL,
		&din, &dout);
	if (code)
		(void) fprintf(stderr, gettext(
			"Error encrypting stream data (%s)\r\n"), code);
}

void
cfb64_init(void)
{
	register struct _fb *fbp = &des_cfb;

	(void) memset((void *)fbp, 0, sizeof (*fbp));
	fbp->state[0] = des_cfb.state[1] = ENCR_STATE_FAILED;
	fbp->fb_feed[0] = IAC;
	fbp->fb_feed[1] = SB;
	fbp->fb_feed[2] = TELOPT_ENCRYPT;
	fbp->fb_feed[3] = ENCRYPT_IS;

	fbp->fb_feed[4] = TELOPT_ENCTYPE_DES_CFB64;
	fbp->streams[TELNET_DIR_DECRYPT].str_flagshift =
		SHIFT_VAL(0, CFB);
	fbp->streams[TELNET_DIR_ENCRYPT].str_flagshift =
		SHIFT_VAL(1, CFB);
}


/*
 * Returns:
 *	-1: some error.  Negotiation is done, encryption not ready.
 *	 0: Successful, initial negotiation all done.
 *	 1: successful, negotiation not done yet.
 *	 2: Not yet.  Other things (like getting the key from
 *	    Kerberos) have to happen before we can continue.
 */
int
cfb64_start(int dir)
{
	struct _fb *fbp = &des_cfb;
	int x;
	unsigned char *p;
	register int state;

	switch (dir) {
	case TELNET_DIR_DECRYPT:
		/*
		 * This is simply a request to have the other side
		 * start output (our input).  The other side will negotiate an
		 * IV so we need not look for it.
		 */
		state = fbp->state[dir];
		if (state == ENCR_STATE_FAILED)
			state = ENCR_STATE_IN_PROGRESS;
		break;

	case TELNET_DIR_ENCRYPT:
		state = fbp->state[dir];
		if (state == ENCR_STATE_FAILED)
			state = ENCR_STATE_IN_PROGRESS;
		else if ((state & ENCR_STATE_NO_SEND_IV) == 0)
			break;

		if (!fbp->validkey) {
			fbp->need_start = B_TRUE;
			break;
		}
		state &= ~ENCR_STATE_NO_SEND_IV;
		state |= ENCR_STATE_NO_RECV_IV;
		if (encrypt_debug_mode)
			(void) printf(gettext("Creating new feed\r\n"));
		/*
		 * Create a random feed and send it over.
		 */
		{
			krb5_data d;
			krb5_error_code code;

			d.data = (char *)fbp->temp_feed;
			d.length = sizeof (fbp->temp_feed);

			code = krb5_c_random_make_octets(telnet_context, &d);
			if (code != 0)
				return (ENCR_STATE_FAILED);
		}

		p = fbp->fb_feed + 3;
		*p++ = ENCRYPT_IS;
		p++;
		*p++ = FB64_IV;
		for (x = 0; x < sizeof (Block); ++x) {
			if ((*p++ = fbp->temp_feed[x]) == IAC)
				*p++ = IAC;
		}
		*p++ = IAC;
		*p++ = SE;
		printsub('>', &fbp->fb_feed[2], p - &fbp->fb_feed[2]);
		(void) net_write(fbp->fb_feed, p - fbp->fb_feed);
		break;
	default:
		return (ENCR_STATE_FAILED);
	}
	return (fbp->state[dir] = state);
}

/*
 * Returns:
 *	-1: some error.  Negotiation is done, encryption not ready.
 *	 0: Successful, initial negotiation all done.
 *	 1: successful, negotiation not done yet.
 */
int
cfb64_is(unsigned char *data, int cnt)
{
	unsigned char *p;
	struct _fb *fbp = &des_cfb;
	register int state = fbp->state[TELNET_DIR_DECRYPT];

	if (cnt-- < 1)
		goto failure;

	switch (*data++) {
	case FB64_IV:
		if (cnt != sizeof (Block)) {
			if (encrypt_debug_mode)
				(void) printf(gettext(
					"CFB64: initial vector failed "
					"on size\r\n"));
			state = ENCR_STATE_FAILED;
			goto failure;
		}

		if (encrypt_debug_mode)
			(void) printf(gettext(
				"CFB64: initial vector received\r\n"));

		if (encrypt_debug_mode)
			(void) printf(gettext(
				"Initializing Decrypt stream\r\n"));

		cfb64_stream_iv((void *)data,
			&fbp->streams[TELNET_DIR_DECRYPT]);

		p = fbp->fb_feed + 3;
		*p++ = ENCRYPT_REPLY;
		p++;
		*p++ = FB64_IV_OK;
		*p++ = IAC;
		*p++ = SE;
		printsub('>', &fbp->fb_feed[2], p - &fbp->fb_feed[2]);
		(void) net_write(fbp->fb_feed, p - fbp->fb_feed);

		state = fbp->state[TELNET_DIR_DECRYPT] = ENCR_STATE_IN_PROGRESS;
		break;

	default:
		if (encrypt_debug_mode) {
			(void) printf(gettext(
				"Unknown option type: %d\r\n"), *(data-1));
			printd(data, cnt);
			(void) printf("\r\n");
		}
		/* FALL THROUGH */
	failure:
		/*
		 * We failed.  Send an FB64_IV_BAD option
		 * to the other side so it will know that
		 * things failed.
		 */
		p = fbp->fb_feed + 3;
		*p++ = ENCRYPT_REPLY;
		p++;
		*p++ = FB64_IV_BAD;
		*p++ = IAC;
		*p++ = SE;
		printsub('>', &fbp->fb_feed[2], p - &fbp->fb_feed[2]);
		(void) net_write(fbp->fb_feed, p - fbp->fb_feed);

		break;
	}
	return (fbp->state[TELNET_DIR_DECRYPT] = state);
}

/*
 * Returns:
 *	-1: some error.  Negotiation is done, encryption not ready.
 *	 0: Successful, initial negotiation all done.
 *	 1: successful, negotiation not done yet.
 */
int
cfb64_reply(unsigned char *data, int cnt)
{
	struct _fb *fbp = &des_cfb;
	register int state = fbp->state[TELNET_DIR_ENCRYPT];

	if (cnt-- < 1)
		goto failure;

	switch (*data++) {
	case FB64_IV_OK:
		cfb64_stream_iv(fbp->temp_feed,
			&fbp->streams[TELNET_DIR_ENCRYPT]);
		if (state == ENCR_STATE_FAILED)
			state = ENCR_STATE_IN_PROGRESS;
		state &= ~ENCR_STATE_NO_RECV_IV;
		encrypt_send_keyid(TELNET_DIR_ENCRYPT,
			(unsigned char *)"\0", 1, 1);
		break;

	case FB64_IV_BAD:
		(void) memset(fbp->temp_feed, 0, sizeof (Block));
		cfb64_stream_iv(fbp->temp_feed,
			&fbp->streams[TELNET_DIR_ENCRYPT]);
		state = ENCR_STATE_FAILED;
		break;

	default:
		if (encrypt_debug_mode) {
			(void) printf(gettext(
				"Unknown option type: %d\r\n"), data[-1]);
			printd(data, cnt);
			(void) printf("\r\n");
		}
		/* FALL THROUGH */
	failure:
		state = ENCR_STATE_FAILED;
		break;
	}
	return (fbp->state[TELNET_DIR_ENCRYPT] = state);
}

void
cfb64_session(Session_Key *key)
{
	struct _fb *fbp = &des_cfb;

	if (!key || key->type != SK_DES) {
		if (encrypt_debug_mode)
		    (void) printf(gettext(
			"Can't set DES's session key (%d != %d)\r\n"),
			key ? key->type : -1, SK_DES);
		return;
	}

	fbp->validkey = B_TRUE;

	cfb64_stream_key(key->data, &fbp->streams[TELNET_DIR_ENCRYPT]);
	cfb64_stream_key(key->data, &fbp->streams[TELNET_DIR_DECRYPT]);

	/*
	 * Now look to see if cfb64_start() was was waiting for
	 * the key to show up.  If so, go ahead an call it now
	 * that we have the key.
	 */
	if (fbp->need_start) {
		fbp->need_start = B_FALSE;
		(void) cfb64_start(TELNET_DIR_ENCRYPT);
	}
}

/*
 * We only accept a keyid of 0.  If we get a keyid of
 * 0, then mark the state as SUCCESS.
 */
int
cfb64_keyid(dir, kp, lenp)
	int dir, *lenp;
	unsigned char *kp;
{
	struct _fb *fbp = &des_cfb;
	register int state = fbp->state[dir];

	if (*lenp != 1 || (*kp != '\0')) {
		*lenp = 0;
		return (state);
	}

	if (state == ENCR_STATE_FAILED)
		state = ENCR_STATE_IN_PROGRESS;

	state &= ~ENCR_STATE_NO_KEYID;

	return (fbp->state[dir] = state);
}

/*
 * Print ENCRYPT suboptions to NetTrace when "set opt" is used
 */
void
cfb64_printsub(unsigned char *data, int cnt, unsigned char *buf, int buflen)
{
	char lbuf[ENCR_LBUF_BUFSIZ];
	register int i;
	char *cp;
	unsigned char type[] = "CFB64";

	buf[buflen-1] = '\0';		/* make sure it's NULL terminated */
	buflen -= 1;

	switch (data[2]) {
	case FB64_IV:
		(void) snprintf(lbuf, ENCR_LBUF_BUFSIZ, "%s_IV", type);
		cp = lbuf;
		goto common;

	case FB64_IV_OK:
		(void) snprintf(lbuf, ENCR_LBUF_BUFSIZ, "%s_IV_OK", type);
		cp = lbuf;
		goto common;

	case FB64_IV_BAD:
		(void) snprintf(lbuf, ENCR_LBUF_BUFSIZ, "%s_IV_BAD", type);
		cp = lbuf;
		goto common;

	default:
		(void) snprintf(lbuf, ENCR_LBUF_BUFSIZ, " %d (unknown)",
			data[2]);
		cp = lbuf;
	common:
		for (; (buflen > 0) && (*buf = *cp++); buf++)
			buflen--;
		for (i = 3; i < cnt; i++) {
			(void) snprintf(lbuf, ENCR_LBUF_BUFSIZ, " %d", data[i]);
			for (cp = lbuf; (buflen > 0) && (*buf = *cp++); buf++)
				buflen--;
		}
		break;
	}
}


static void
cfb64_stream_iv(Block seed, register struct stinfo *stp)
{
	(void) memcpy((void *)stp->str_iv,	(void *)seed, sizeof (Block));
	(void) memcpy((void *)stp->str_output,	(void *)seed, sizeof (Block));

	stp->str_index = sizeof (Block);
}

void
cfb64_stream_key(Block key, register struct stinfo *stp)
{
	(void) memcpy((void *)stp->str_keybytes, (void *)key, sizeof (Block));
	stp->str_key.length = DES_BLOCKSIZE;
	stp->str_key.contents = stp->str_keybytes;
	/*
	 * the original version of this code uses des ecb mode, but
	 * it only ever does one block at a time.  cbc with a zero iv
	 * is identical
	 */
	/* this is a kerberos enctype, not a telopt enctype */
	stp->str_key.enctype = ENCTYPE_DES_CBC_RAW;

	(void) memcpy((void *)stp->str_output, (void *)stp->str_iv,
	    sizeof (Block));

	stp->str_index = sizeof (Block);
}

/*
 * DES 64 bit Cipher Feedback
 *
 *     key --->+-----+
 *          +->| DES |--+
 *          |  +-----+  |
 *	    |           v
 *  INPUT --(--------->(+)+---> DATA
 *          |             |
 *	    +-------------+
 *
 *
 * Given:
 *	iV: Initial vector, 64 bits (8 bytes) long.
 *	Dn: the nth chunk of 64 bits (8 bytes) of data to encrypt (decrypt).
 *	On: the nth chunk of 64 bits (8 bytes) of encrypted (decrypted) output.
 *
 *	V0 = DES(iV, key)
 *	On = Dn ^ Vn
 *	V(n+1) = DES(On, key)
 */

void
cfb64_encrypt(register unsigned char *s, int c)
{
	register struct stinfo *stp =
		&des_cfb.streams[TELNET_DIR_ENCRYPT];
	register int index;

	index = stp->str_index;
	while (c-- > 0) {
		if (index == sizeof (Block)) {
			Block b;
			ecb_encrypt(stp, stp->str_output, b);
			(void) memcpy((void *)stp->str_feed, (void *)b,
				sizeof (Block));
			index = 0;
		}

		/* On encryption, we store (feed ^ data) which is cypher */
		*s = stp->str_output[index] = (stp->str_feed[index] ^ *s);
		s++;
		index++;
	}
	stp->str_index = index;
}

int
cfb64_decrypt(int data)
{
	register struct stinfo *stp =
		&des_cfb.streams[TELNET_DIR_DECRYPT];
	int index;

	if (data == -1) {
		/*
		 * Back up one byte.  It is assumed that we will
		 * never back up more than one byte.  If we do, this
		 * may or may not work.
		 */
		if (stp->str_index)
			--stp->str_index;
		return (0);
	}

	index = stp->str_index++;
	if (index == sizeof (Block)) {
		Block b;
		ecb_encrypt(stp, stp->str_output, b);
		(void) memcpy((void *)stp->str_feed, (void *)b, sizeof (Block));
		stp->str_index = 1;	/* Next time will be 1 */
		index = 0;		/* But now use 0 */
	}

	/* On decryption we store (data) which is cypher. */
	stp->str_output[index] = data;
	return (data ^ stp->str_feed[index]);
}
