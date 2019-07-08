/*
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * usr/src/cmd/cmd-inet/usr.bin/telnet/encrypt.c
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

/* based on @(#)encrypt.c	8.1 (Berkeley) 6/4/93 */

/*
 * Copyright (C) 1990 by the Massachusetts Institute of Technology
 *
 * Export of this software from the United States of America may
 * require a specific license from the United States Government.
 * It is the responsibility of any person or organization contemplating
 * export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#ifdef	lint
static char *encrypt_names[] = {0};
static char *enctype_names[] = {0};
#else	/* lint */
#define	ENCRYPT_NAMES
#endif	/* lint */
#include <arpa/telnet.h>

#include "externs.h"

#ifdef	__STDC__
#include <stdlib.h>
#endif

/*
 * These functions pointers point to the current routines
 * for encrypting and decrypting data.
 */
void	(*encrypt_output)(uchar_t *, int);
int	(*decrypt_input)(int);
static	void encrypt_start_output(int);
static	void encrypt_send_end(void);
static	void encrypt_send_request_start(void);
static	void encrypt_send_request_end(void);

boolean_t	encrypt_debug_mode = B_FALSE;

static int decrypt_mode = 0;
static int encrypt_mode = 0;
static boolean_t encrypt_verbose = B_FALSE;
static boolean_t autoencrypt = B_FALSE;
static boolean_t autodecrypt = B_FALSE;
static char *Name = "Noname";

#define	typemask(x)	((x) > 0 ? 1 << ((x)-1) : 0)
#define	SUCCESS		0x00
#define	UNKNOWN		gettext("(unknown)")

static int i_support_encrypt = typemask(TELOPT_ENCTYPE_DES_CFB64);
static int i_support_decrypt = typemask(TELOPT_ENCTYPE_DES_CFB64);
static int i_wont_support_encrypt = 0;
static int i_wont_support_decrypt = 0;
#define	I_SUPPORT_ENCRYPT	(i_support_encrypt & ~i_wont_support_encrypt)
#define	I_SUPPORT_DECRYPT	(i_support_decrypt & ~i_wont_support_decrypt)

static int remote_supports_encrypt = 0;
static int remote_supports_decrypt = 0;

static Encryptions encryptions[] = {
	{ "DES_CFB64",	TELOPT_ENCTYPE_DES_CFB64,
			cfb64_encrypt,
			cfb64_decrypt,
			cfb64_init,
			cfb64_start,
			cfb64_is,
			cfb64_reply,
			cfb64_session,
			cfb64_keyid,
			cfb64_printsub },
	{ 0, },
};

static uchar_t str_send[64] = { IAC, SB, TELOPT_ENCRYPT,
	ENCRYPT_SUPPORT };
static uchar_t str_suplen = 0;
static uchar_t str_start[72] = { IAC, SB, TELOPT_ENCRYPT };
static uchar_t str_end[] = { IAC, SB, TELOPT_ENCRYPT, 0, IAC, SE };

static Encryptions *
findencryption(int type)
{
	Encryptions *ep = encryptions;

	if (!(I_SUPPORT_ENCRYPT & remote_supports_decrypt & typemask(type)))
		return (NULL);
	for (; (ep->type != 0) && (ep->type != type); ep++);
	return (ep->type ? ep : NULL);
}

static Encryptions *
finddecryption(int type)
{
	Encryptions *ep = encryptions;

	if (!(I_SUPPORT_DECRYPT & remote_supports_encrypt & typemask(type)))
		return (NULL);
	while (ep->type && ep->type != type)
		++ep;
	return (ep->type ? ep : NULL);
}

#define	MAXKEYLEN 64

static struct key_info {
	uchar_t keyid[MAXKEYLEN];
	int keylen;
	int dir;
	int *modep;
	Encryptions *(*getcrypt)();
} ki[2] = {
	{ { 0 }, 0, TELNET_DIR_ENCRYPT, &encrypt_mode, findencryption },
	{ { 0 }, 0, TELNET_DIR_DECRYPT, &decrypt_mode, finddecryption },
};
#define	KI_ENCRYPT	0
#define	KI_DECRYPT	1

void
encrypt_init(char *name)
{
	Encryptions *ep = encryptions;

	Name = name;
	i_support_encrypt = i_support_decrypt = 0;
	remote_supports_encrypt = remote_supports_decrypt = 0;
	encrypt_mode = 0;
	decrypt_mode = 0;
	encrypt_output = 0;
	decrypt_input = 0;
#ifdef notdef
	encrypt_verbose = !server;
#endif

	str_suplen = 4;

	while (ep->type) {
		if (encrypt_debug_mode)
			(void) printf(gettext(
				">>>%s: I will support %s\r\n"),
				Name, ENCTYPE_NAME(ep->type));
		i_support_encrypt |= typemask(ep->type);
		i_support_decrypt |= typemask(ep->type);
		if ((i_wont_support_decrypt & typemask(ep->type)) == 0)
			if ((str_send[str_suplen++] = ep->type) == IAC)
				str_send[str_suplen++] = IAC;
		if (ep->init)
			(*ep->init)();
		++ep;
	}
	str_send[str_suplen++] = IAC;
	str_send[str_suplen++] = SE;
}

static void
encrypt_list_types(void)
{
	Encryptions *ep = encryptions;

	(void) printf(gettext("Valid encryption types:\n"));
	while (ep->type) {
		(void) printf("\t%s (%d)\r\n",
			ENCTYPE_NAME(ep->type), ep->type);
		++ep;
	}
}

int
EncryptEnable(char *type, char *mode)
{
	if (isprefix(type, "help") || isprefix(type, "?")) {
		(void) printf(gettext(
			"Usage: encrypt enable <type> [input|output]\n"));
		encrypt_list_types();
		return (0);
	}

	if (EncryptType(type, mode))
		return (EncryptStart(mode));

	return (0);
}

int
EncryptDisable(char *type, char *mode)
{
	register Encryptions *ep;
	int ret = 0;

	if (isprefix(type, "help") || isprefix(type, "?")) {
		(void) printf(gettext(
			"Usage: encrypt disable <type> [input|output]\n"));
		encrypt_list_types();
	} else if ((ep = (Encryptions *)genget(type, (char **)encryptions,
						sizeof (Encryptions))) == 0) {
		(void) printf(gettext("%s: invalid encryption type\n"), type);
	} else if (Ambiguous(ep)) {
		(void) printf(gettext("Ambiguous type '%s'\n"), type);
	} else {
		if ((mode == 0) || (isprefix(mode, "input") ? 1 : 0)) {
			if (decrypt_mode == ep->type)
				(void) EncryptStopInput();
			i_wont_support_decrypt |= typemask(ep->type);
			ret = 1;
		}
		if ((mode == 0) || (isprefix(mode, "output"))) {
			if (encrypt_mode == ep->type)
				(void) EncryptStopOutput();
			i_wont_support_encrypt |= typemask(ep->type);
			ret = 1;
		}
		if (ret == 0)
			(void) printf(gettext(
				"%s: invalid encryption mode\n"), mode);
	}
	return (ret);
}

int
EncryptType(char *type, char *mode)
{
	register Encryptions *ep;
	int ret = 0;

	if (isprefix(type, "help") || isprefix(type, "?")) {
		(void) printf(gettext(
			"Usage: encrypt type <type> [input|output]\n"));
		encrypt_list_types();
	} else if ((ep = (Encryptions *)genget(type, (char **)encryptions,
						sizeof (Encryptions))) == 0) {
		(void) printf(gettext("%s: invalid encryption type\n"), type);
	} else if (Ambiguous(ep)) {
		(void) printf(gettext("Ambiguous type '%s'\n"), type);
	} else {
		if ((mode == 0) || isprefix(mode, "input")) {
			decrypt_mode = ep->type;
			i_wont_support_decrypt &= ~typemask(ep->type);
			ret = 1;
		}
		if ((mode == 0) || isprefix(mode, "output")) {
			encrypt_mode = ep->type;
			i_wont_support_encrypt &= ~typemask(ep->type);
			ret = 1;
		}
		if (ret == 0)
			(void) printf(gettext(
				"%s: invalid encryption mode\n"), mode);
	}
	return (ret);
}

int
EncryptStart(char *mode)
{
	register int ret = 0;
	if (mode) {
		if (isprefix(mode, "input"))
			return (EncryptStartInput());
		if (isprefix(mode, "output"))
			return (EncryptStartOutput());
		if (isprefix(mode, "help") || isprefix(mode, "?")) {
			(void) printf(gettext(
				"Usage: encrypt start [input|output]\n"));
			return (0);
		}
		(void) printf(gettext(
			"%s: invalid encryption mode 'encrypt start ?' "
			"for help\n"), mode);
		return (0);
	}
	ret += EncryptStartInput();
	ret += EncryptStartOutput();
	return (ret);
}

int
EncryptStartInput(void)
{
	if (decrypt_mode) {
		encrypt_send_request_start();
		return (1);
	}
	(void) printf(gettext("No previous decryption mode, "
		"decryption not enabled\r\n"));
	return (0);
}

int
EncryptStartOutput(void)
{
	if (encrypt_mode) {
		encrypt_start_output(encrypt_mode);
		return (1);
	}
	(void) printf(gettext("No previous encryption mode, "
		"encryption not enabled\r\n"));
	return (0);
}

int
EncryptStop(char *mode)
{
	int ret = 0;
	if (mode) {
		if (isprefix(mode, "input"))
			return (EncryptStopInput());
		if (isprefix(mode, "output"))
			return (EncryptStopOutput());
		if (isprefix(mode, "help") || isprefix(mode, "?")) {
			(void) printf(gettext(
				"Usage: encrypt stop [input|output]\n"));
			return (0);
		}
		(void) printf(gettext(
			"%s: invalid encryption mode 'encrypt stop ?' "
			"for help\n"), mode);
		return (0);
	}
	ret += EncryptStopInput();
	ret += EncryptStopOutput();
	return (ret);
}

int
EncryptStopInput(void)
{
	encrypt_send_request_end();
	return (1);
}

int
EncryptStopOutput(void)
{
	encrypt_send_end();
	return (1);
}

void
encrypt_display(void)
{
	if (encrypt_output)
		(void) printf(gettext(
			"Currently encrypting output with %s\r\n"),
			ENCTYPE_NAME(encrypt_mode));
	if (decrypt_input)
		(void) printf(gettext(
			"Currently decrypting input with %s\r\n"),
			ENCTYPE_NAME(decrypt_mode));
}

int
EncryptStatus(void)
{
	if (encrypt_output)
		(void) printf(gettext(
			"Currently encrypting output with %s\r\n"),
			ENCTYPE_NAME(encrypt_mode));
	else if (encrypt_mode) {
		(void) printf(gettext("Currently output is clear text.\r\n"));
		(void) printf(gettext("Last encryption mode was %s\r\n"),
			ENCTYPE_NAME(encrypt_mode));
	}
	if (decrypt_input) {
		(void) printf(gettext(
			"Currently decrypting input with %s\r\n"),
			ENCTYPE_NAME(decrypt_mode));
	} else if (decrypt_mode) {
		(void) printf(gettext("Currently input is clear text.\r\n"));
		(void) printf(gettext("Last decryption mode was %s\r\n"),
			ENCTYPE_NAME(decrypt_mode));
	}
	return (1);
}

void
encrypt_send_support(void)
{
	if (str_suplen) {
		/*
		 * If the user has requested that decryption start
		 * immediatly, then send a "REQUEST START" before
		 * we negotiate the type.
		 */
		if (autodecrypt)
			encrypt_send_request_start();
		(void) net_write(str_send, str_suplen);
		printsub('>', &str_send[2], str_suplen - 2);
		str_suplen = 0;
	}
}

int
EncryptDebug(int on)
{
	encrypt_debug_mode = (on < 0) ? !encrypt_debug_mode :
		(on > 0) ? B_TRUE : B_FALSE;
	(void) printf(encrypt_debug_mode ?
		gettext("Encryption debugging enabled\r\n") :
		gettext("Encryption debugging disabled\r\n"));
	return (1);
}

int
EncryptVerbose(int on)
{
	encrypt_verbose = (on < 0) ? !encrypt_verbose :
		(on > 0) ? B_TRUE : B_FALSE;
	(void) printf(encrypt_verbose ?
		gettext("Encryption is verbose\r\n") :
		gettext("Encryption is not verbose\r\n"));
	return (1);
}

int
EncryptAutoEnc(int on)
{
	encrypt_auto(on);
	(void) printf(autoencrypt ?
		gettext("Automatic encryption of output is enabled\r\n") :
		gettext("Automatic encryption of output is disabled\r\n"));
	return (1);
}

int
EncryptAutoDec(int on)
{
	decrypt_auto(on);
	(void) printf(autodecrypt ?
		gettext("Automatic decryption of input is enabled\r\n") :
		gettext("Automatic decryption of input is disabled\r\n"));
	return (1);
}

/*
 * Called when ENCRYPT SUPPORT is received.
 */
void
encrypt_support(uchar_t *typelist, int cnt)
{
	register int type, use_type = 0;
	Encryptions *ep;

	/*
	 * Forget anything the other side has previously told us.
	 */
	remote_supports_decrypt = 0;

	while (cnt-- > 0) {
		type = *typelist++;
		if (encrypt_debug_mode)
			(void) printf(gettext(
				">>>%s: Remote host supports %s (%d)\r\n"),
				Name, ENCTYPE_NAME(type), type);
		if ((type < TELOPT_ENCTYPE_CNT) &&
		    (I_SUPPORT_ENCRYPT & typemask(type))) {
			remote_supports_decrypt |= typemask(type);
			if (use_type == 0)
				use_type = type;
		}
	}
	if (use_type) {
		ep = findencryption(use_type);
		if (!ep)
			return;
		type = ep->start ? (*ep->start)(TELNET_DIR_ENCRYPT) : 0;
		if (encrypt_debug_mode)
			(void) printf(gettext(
				">>>%s: (*ep->start)() returned %d\r\n"),
				Name, type);
		if (type < 0)
			return;
		encrypt_mode = use_type;
		if (type == 0)
			encrypt_start_output(use_type);
	}
}

void
encrypt_is(uchar_t *data, int cnt)
{
	Encryptions *ep;
	register int type, ret;

	if (--cnt < 0)
		return;
	type = *data++;
	if (type < TELOPT_ENCTYPE_CNT)
		remote_supports_encrypt |= typemask(type);
	if (!(ep = finddecryption(type))) {
		if (encrypt_debug_mode)
			(void) printf(gettext(
				">>>%s: Can't find type %s (%d) for "
				"initial negotiation\r\n"), Name,
				ENCTYPE_NAME_OK(type) ?
				ENCTYPE_NAME(type) : UNKNOWN, type);
		return;
	}
	if (!ep->is) {
		if (encrypt_debug_mode)
			(void) printf(gettext(
				">>>%s: No initial negotiation needed "
				"for type %s (%d)\r\n"), Name,
				ENCTYPE_NAME_OK(type) ?
				ENCTYPE_NAME(type) : UNKNOWN, type);
		ret = 0;
	} else {
		ret = (*ep->is)(data, cnt);
		if (encrypt_debug_mode)
			(void) printf(gettext(
				"(*ep->is)(%x, %d) returned %s(%d)\n"),
				data, cnt, (ret < 0) ? "FAIL " :
				(ret == 0) ? "SUCCESS " : "MORE_TO_DO ", ret);
	}
	if (ret < 0) {
		autodecrypt = B_FALSE;
	} else {
		decrypt_mode = type;
		if (ret == 0 && autodecrypt)
			encrypt_send_request_start();
	}
}

void
encrypt_reply(uchar_t *data, int cnt)
{
	Encryptions *ep;
	register int ret, type;

	if (--cnt < 0)
		return;
	type = *data++;
	if (!(ep = findencryption(type))) {
		if (encrypt_debug_mode)
			(void) printf(gettext(
				">>>%s: Can't find type %s (%d) "
				"for initial negotiation\r\n"), Name,
				ENCTYPE_NAME_OK(type) ?
				ENCTYPE_NAME(type) : UNKNOWN, type);
		return;
	}
	if (!ep->reply) {
		if (encrypt_debug_mode)
			(void) printf(gettext(
				">>>%s: No initial negotiation needed "
				"for type %s (%d)\r\n"), Name,
				ENCTYPE_NAME_OK(type) ?
				ENCTYPE_NAME(type) : UNKNOWN, type);
		ret = 0;
	} else {
		ret = (*ep->reply)(data, cnt);
		if (encrypt_debug_mode)
			(void) printf(gettext(
				"(*ep->reply)(%x, %d) returned %s(%d)\n"),
				data, cnt, (ret < 0) ? "FAIL " :
				(ret == 0) ? "SUCCESS " : "MORE_TO_DO ", ret);
	}
	if (encrypt_debug_mode)
		(void) printf(gettext(
			">>>%s: encrypt_reply returned %d\n"), Name, ret);
	if (ret < 0) {
		autoencrypt = B_FALSE;
	} else {
		encrypt_mode = type;
		if (ret == 0 && autoencrypt)
			encrypt_start_output(type);
	}
}

/*
 * Called when a ENCRYPT START command is received.
 */
/* ARGSUSED */
void
encrypt_start(uchar_t *data, int cnt)
{
	Encryptions *ep;

	if (!decrypt_mode) {
		/*
		 * Something is wrong.  We should not get a START
		 * command without having already picked our
		 * decryption scheme.  Send a REQUEST-END to
		 * attempt to clear the channel...
		 */
		(void) printf(gettext("%s: Warning, cannot decrypt "
			"input stream!!!\r\n"), Name);
		encrypt_send_request_end();
		return;
	}

	if (ep = finddecryption(decrypt_mode)) {
		decrypt_input = ep->input;
		if (encrypt_verbose)
			(void) printf(gettext(
			    "[ Input is now decrypted with type %s ]\r\n"),
			    ENCTYPE_NAME(decrypt_mode));
		if (encrypt_debug_mode)
			(void) printf(gettext(
			    ">>>%s: Start to decrypt input with type %s\r\n"),
			    Name, ENCTYPE_NAME(decrypt_mode));
	} else {
		(void) printf(gettext(
			    "%s: Warning, cannot decrypt type %s (%d)!!!\r\n"),
			    Name, ENCTYPE_NAME_OK(decrypt_mode) ?
			    ENCTYPE_NAME(decrypt_mode) : UNKNOWN,
			    decrypt_mode);
		encrypt_send_request_end();
	}
}

void
encrypt_session_key(Session_Key *key)
{
	Encryptions *ep = encryptions;

	while (ep->type) {
		if (ep->session)
			(*ep->session)(key);
#ifdef notdef
		if (!encrypt_output && autoencrypt)
			encrypt_start_output(ep->type);
		if (!decrypt_input && autodecrypt)
			encrypt_send_request_start();
#endif
		++ep;
	}
}

/*
 * Called when ENCRYPT END is received.
 */
void
encrypt_end(void)
{
	decrypt_input = 0;
	if (encrypt_debug_mode)
		(void) printf(gettext(
			">>>%s: Input is back to clear text\r\n"), Name);
	if (encrypt_verbose)
		(void) printf(gettext("[ Input is now clear text ]\r\n"));
}

/*
 * Called when ENCRYPT REQUEST-END is received.
 */
void
encrypt_request_end(void)
{
	encrypt_send_end();
}

/*
 * Called when ENCRYPT REQUEST-START is received.  If we receive
 * this before a type is picked, then that indicates that the
 * other side wants us to start encrypting data as soon as we
 * can.
 */
/* ARGSUSED */
void
encrypt_request_start(uchar_t *data, int cnt)
{
	if (encrypt_mode == 0)
		return;
	encrypt_start_output(encrypt_mode);
}

static	uchar_t str_keyid[(MAXKEYLEN*2)+5] = { IAC, SB, TELOPT_ENCRYPT };
static	void encrypt_keyid(struct key_info *, uchar_t *, int);

void
encrypt_enc_keyid(uchar_t *keyid, int len)
{
	encrypt_keyid(&ki[KI_DECRYPT], keyid, len);
}

void
encrypt_dec_keyid(uchar_t *keyid, int len)
{
	encrypt_keyid(&ki[KI_ENCRYPT], keyid, len);
}

static void
encrypt_keyid(struct key_info *kp, uchar_t *keyid, int len)
{
	Encryptions *ep;
	int dir = kp->dir;
	register int ret = 0;

	if (!(ep = (*kp->getcrypt)(*kp->modep))) {
		if (len == 0)
			return;
		kp->keylen = 0;
	} else if (len == 0) {
		/*
		 * Empty option, indicates a failure.
		 */
		if (kp->keylen == 0)
			return;
		kp->keylen = 0;
		if (ep->keyid)
			(void) (*ep->keyid)(dir, kp->keyid, &kp->keylen);

	} else if ((len != kp->keylen) ||
		(memcmp(keyid, kp->keyid, len) != 0)) {
		/*
		 * Length or contents are different
		 */
		kp->keylen = len;
		(void) memcpy(kp->keyid, keyid, len);
		if (ep->keyid)
			(void) (*ep->keyid)(dir, kp->keyid, &kp->keylen);
	} else {
		if (ep->keyid)
			ret = (*ep->keyid)(dir, kp->keyid, &kp->keylen);
		if ((ret == 0) && (dir == TELNET_DIR_ENCRYPT) && autoencrypt)
			encrypt_start_output(*kp->modep);
		return;
	}

	encrypt_send_keyid(dir, kp->keyid, kp->keylen, 0);
}

void
encrypt_send_keyid(int dir, uchar_t *keyid, int keylen, int saveit)
{
	uchar_t *strp;

	str_keyid[3] = (dir == TELNET_DIR_ENCRYPT)
			? ENCRYPT_ENC_KEYID : ENCRYPT_DEC_KEYID;
	if (saveit) {
		struct key_info *kp = &ki[(dir == TELNET_DIR_ENCRYPT) ? 0 : 1];
		(void) memcpy(kp->keyid, keyid, keylen);
		kp->keylen = keylen;
	}

	for (strp = &str_keyid[4]; keylen > 0; --keylen) {
		if ((*strp++ = *keyid++) == IAC)
			*strp++ = IAC;
	}
	*strp++ = IAC;
	*strp++ = SE;
	(void) net_write(str_keyid, strp - str_keyid);
	printsub('>', &str_keyid[2], strp - str_keyid - 2);
}

void
encrypt_auto(int on)
{
	autoencrypt = (on < 0) ? !autoencrypt :
		(on > 0) ? B_TRUE : B_FALSE;
}

void
decrypt_auto(int on)
{
	autodecrypt = (on < 0) ? !autodecrypt :
		(on > 0) ? B_TRUE : B_FALSE;
}

static void
encrypt_start_output(int type)
{
	Encryptions *ep;
	register uchar_t *p;
	register int i;

	if (!(ep = findencryption(type))) {
		if (encrypt_debug_mode) {
		    (void) printf(gettext(
			">>>%s: Can't encrypt with type %s (%d)\r\n"),
			Name, ENCTYPE_NAME_OK(type) ?
			ENCTYPE_NAME(type) : UNKNOWN, type);
		}
		return;
	}
	if (ep->start) {
		i = (*ep->start)(TELNET_DIR_ENCRYPT);
		if (encrypt_debug_mode) {
		    (void) printf(gettext(
			">>>%s: Encrypt start: %s (%d) %s\r\n"),
			Name, (i < 0) ?
			gettext("failed") :
			gettext("initial negotiation in progress"),
			i, ENCTYPE_NAME(type));
		}
		if (i)
			return;
	}
	p = str_start + 3;
	*p++ = ENCRYPT_START;
	for (i = 0; i < ki[KI_ENCRYPT].keylen; ++i) {
		if ((*p++ = ki[KI_ENCRYPT].keyid[i]) == IAC)
			*p++ = IAC;
	}
	*p++ = IAC;
	*p++ = SE;
	(void) net_write(str_start, p - str_start);
	net_encrypt();
	printsub('>', &str_start[2], p - &str_start[2]);
	/*
	 * If we are already encrypting in some mode, then
	 * encrypt the ring (which includes our request) in
	 * the old mode, mark it all as "clear text" and then
	 * switch to the new mode.
	 */
	encrypt_output = ep->output;
	encrypt_mode = type;
	if (encrypt_debug_mode)
	    (void) printf(gettext(
		">>>%s: Started to encrypt output with type %s\r\n"),
		Name, ENCTYPE_NAME(type));
	if (encrypt_verbose)
	    (void) printf(gettext(
		"[ Output is now encrypted with type %s ]\r\n"),
		ENCTYPE_NAME(type));
}

static void
encrypt_send_end(void)
{
	if (!encrypt_output)
		return;

	str_end[3] = ENCRYPT_END;
	(void) net_write(str_end, sizeof (str_end));
	net_encrypt();
	printsub('>', &str_end[2], sizeof (str_end) - 2);
	/*
	 * Encrypt the output buffer now because it will not be done by
	 * netflush...
	 */
	encrypt_output = 0;
	if (encrypt_debug_mode)
	    (void) printf(gettext(
		">>>%s: Output is back to clear text\r\n"), Name);
	if (encrypt_verbose)
	    (void) printf(gettext("[ Output is now clear text ]\r\n"));
}

static void
encrypt_send_request_start(void)
{
	register uchar_t *p;
	register int i;

	p = &str_start[3];
	*p++ = ENCRYPT_REQSTART;
	for (i = 0; i < ki[KI_DECRYPT].keylen; ++i) {
		if ((*p++ = ki[KI_DECRYPT].keyid[i]) == IAC)
			*p++ = IAC;
	}
	*p++ = IAC;
	*p++ = SE;
	(void) net_write(str_start, p - str_start);
	printsub('>', &str_start[2], p - &str_start[2]);
	if (encrypt_debug_mode)
	    (void) printf(gettext(
		">>>%s: Request input to be encrypted\r\n"), Name);
}

static void
encrypt_send_request_end(void)
{
	str_end[3] = ENCRYPT_REQEND;
	(void) net_write(str_end, sizeof (str_end));
	printsub('>', &str_end[2], sizeof (str_end) - 2);

	if (encrypt_debug_mode)
	    (void) printf(gettext(
		">>>%s: Request input to be clear text\r\n"), Name);
}

boolean_t
encrypt_is_encrypting(void)
{
	return (encrypt_output && decrypt_input ? B_TRUE : B_FALSE);
}

static void
encrypt_gen_printsub(uchar_t *data, int cnt, uchar_t *buf, int buflen)
{
	char lbuf[ENCR_LBUF_BUFSIZ], *cp;

	if (cnt < 2 || buflen < 2)
		return;
	cnt -= 2;
	data += 2;
	buf[buflen-1] = '\0';
	buf[buflen-2] = '*';
	buflen -= 2;
	for (; cnt > 0; cnt--, data++) {
		(void) snprintf(lbuf, ENCR_LBUF_BUFSIZ, " %d", *data);
		for (cp = lbuf; *cp && buflen > 0; --buflen)
			*buf++ = *cp++;
		if (buflen <= 0)
			return;
	}
	*buf = '\0';
}

void
encrypt_printsub(uchar_t *data, int cnt, uchar_t *buf, int buflen)
{
	Encryptions *ep;
	register int type = data[1];

	for (ep = encryptions; ep->type && ep->type != type; ep++)
		;

	if (ep->printsub)
		(*ep->printsub)(data, cnt, buf, buflen);
	else
		encrypt_gen_printsub(data, cnt, buf, buflen);
}
