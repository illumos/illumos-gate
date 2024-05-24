/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2015 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
 * Copyright (c) 2015 Leon Dang
 * Copyright 2020 Joyent, Inc.
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
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * References to the RFB protocol specification refer to:
 * - [1] https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst
 */

#include <err.h>
#include <errno.h>
#include <libidspace.h>
#include <netdb.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <netinet/in.h>
#ifndef NO_OPENSSL
#include <openssl/des.h>
#endif
#include <sys/debug.h>
#include <sys/endian.h>
#include <sys/list.h>
#include <sys/socket.h>
#include <sys/types.h>
#ifndef WITHOUT_CAPSICUM
#include <sysexits.h>
#include <sys/capsicum.h>
#include <capsicum_helpers.h>
#endif

#include "bhyvegc.h"
#include "config.h"
#include "debug.h"
#include "console.h"
#include "rfb.h"
#include "rfb_impl.h"
#include "sockstream.h"

static uint_t rfb_debug = 0;
static list_t rfb_list;
static id_space_t *rfb_idspace;

static bool rfb_sse42;
static pthread_once_t rfb_once = PTHREAD_ONCE_INIT;

extern int raw_stdio;

static void rfb_send_extended_keyevent_update_msg(rfb_client_t *);

static void
rfb_printf(rfb_client_t *c, rfb_loglevel_t level, const char *fmt, ...)
{
	FILE *fp = stdout;
	va_list ap;

	switch (level) {
	case RFB_LOGDEBUG:
		if (rfb_debug == 0)
			return;
		/* FALLTHROUGH */
	case RFB_LOGERR:
		fp = stderr;
		/* FALLTHROUGH */
	case RFB_LOGWARN:
		if (c != NULL)
			(void) fprintf(fp, "rfb%u: ", c->rc_instance);
		else
			(void) fprintf(fp, "rfb: ");
		va_start(ap, fmt);
		(void) vfprintf(fp, fmt, ap);
		va_end(ap);
		if (raw_stdio)
			(void) fprintf(fp, "\r\n");
		else
			(void) fprintf(fp, "\n");
		(void) fflush(fp);
	}
}

static void
rfb_init_once(void)
{
	uint_t cpu_registers[4], ecx;

	do_cpuid(1, cpu_registers);
	ecx = cpu_registers[2];
	rfb_sse42 = (ecx & CPUID2_SSE42) != 0;

	if (rfb_sse42)
		rfb_printf(NULL, RFB_LOGDEBUG, "enabled fast crc32");
	else
		rfb_printf(NULL, RFB_LOGWARN, "no support for fast crc32");

	if (get_config_bool_default("rfb.debug", false))
		rfb_debug = 1;

	list_create(&rfb_list, sizeof (rfb_server_t),
	    offsetof(rfb_server_t, rs_node));

	rfb_idspace = id_space_create("rfb", 0, INT32_MAX);
}

static void
rfb_free_client(rfb_client_t *c)
{
	free(c->rc_crc);
	free(c->rc_crc_tmp);
	free(c->rc_zbuf);
	free(c->rc_gci.data);

	if (c->rc_encodings & RFB_ENCODING_ZLIB)
		(void) deflateEnd(&c->rc_zstream);

	if (c->rc_fd != -1)
		(void) close(c->rc_fd);

	free(c);
}

/*
 * Calculate CRC32 using SSE4.2; Intel or AMD Bulldozer+ CPUs only
 */
static inline uint32_t
fast_crc32(void *buf, int len, uint32_t crcval)
{
	uint32_t q = len / sizeof (uint32_t);
	uint32_t *p = (uint32_t *)buf;

	while (q--) {
		/* BEGIN CSTYLED */
		asm volatile (
		    /* crc32l %ecx,%esi */
		    ".byte 0xf2, 0xf, 0x38, 0xf1, 0xf1;"
		    :"=S" (crcval)
		    :"0" (crcval), "c" (*p)
		);
		/* END CSTYLED */
		p++;
	}

	return (crcval);
}

static void
rfb_send_client_status(rfb_client_t *c, uint32_t status, const char *msg)
{
	rfb_printf(c, RFB_LOGDEBUG, "sending client status %u (%s)",
	    status, msg ? msg : "NULL");

	status = htonl(status);
	(void) stream_write(c->rc_fd, &status, sizeof (status));

	if (msg != NULL && status != 0 && c->rc_cver == RFB_CVER_3_8) {
		char buf[4];

		rfb_printf(c, RFB_LOGWARN, msg);

		be32enc(buf, strlen((char *)msg));
		(void) stream_write(c->rc_fd, buf, 4);
		(void) stream_write(c->rc_fd, msg, strlen((char *)msg));
	}
}

static bool
rfb_handshake_version(rfb_client_t *c)
{
	unsigned char buf[RFB_VERSION_LEN];
	ssize_t l;

	rfb_printf(c, RFB_LOGDEBUG, "handshake version");

	if (stream_write(c->rc_fd, RFB_VERSION, RFB_VERSION_LEN) !=
	    RFB_VERSION_LEN) {
		rfb_printf(c, RFB_LOGWARN, "could not send server version.");
		return (false);
	}

	l = stream_read(c->rc_fd, buf, sizeof (buf));
	if (l <= 0) {
		rfb_printf(c, RFB_LOGWARN, "client version not read");
		return (false);
	} else if (l != RFB_VERSION_LEN) {
		rfb_printf(c, RFB_LOGWARN, "client sent short version - '%.*s'",
		    l, buf);
		return (false);
	}

	rfb_printf(c, RFB_LOGDEBUG, "version handshake, client ver '%.*s'",
	    l - 1, buf);

	if (strncmp(RFB_VERSION, (char *)buf, RFB_VERSION_LEN - 2) != 0) {
		rfb_printf(c, RFB_LOGERR, "bad client version '%.*s'", l, buf);
		return (false);
	}

	switch (buf[RFB_VERSION_LEN - 2]) {
	case '8':
		c->rc_cver = RFB_CVER_3_8;
		break;
	case '7':
		c->rc_cver = RFB_CVER_3_7;
		break;
	case '5':
		/*
		 * From the RFB specification[1], section 7.1.1:
		 * "version 3.5 was wrongly reported by some clients, but this
		 *  should be interpreted by all servers as 3.3."
		 */
	case '3':
		c->rc_cver = RFB_CVER_3_3;
		break;
	default:
		rfb_printf(c, RFB_LOGERR, "unsupported client version '%.*s'",
		    l - 1, buf);
		return (false);
	}

	return (true);
}

static bool
rfb_handshake_auth(rfb_client_t *c)
{
	unsigned char buf[RFBP_SECURITY_VNC_AUTH_LEN];
	int auth_type;

	rfb_printf(c, RFB_LOGDEBUG, "handshake auth");

	auth_type = RFBP_SECURITY_NONE;
#ifndef NO_OPENSSL
	if (c->rc_s->rs_password != NULL)
		auth_type = RFBP_SECURITY_VNC_AUTH;
#endif

	switch (c->rc_cver) {
	case RFB_CVER_3_3:
		/*
		 * RFB specification[1] section 7.1.2:
		 * The server decides the security type and sends a single word.
		 */
		be32enc(buf, auth_type);
		(void) stream_write(c->rc_fd, buf, 4);

		break;

	case RFB_CVER_3_7:
	case RFB_CVER_3_8:
		/* Send list of supported types. */
		buf[0] = 1;	/* list length */
		buf[1] = auth_type;
		(void) stream_write(c->rc_fd, buf, 2);

		/* Read agreed security type. */
		if (stream_read(c->rc_fd, buf, 1) != 1) {
			rfb_printf(c, RFB_LOGWARN,
			    "auth fail, no type from client");
			return (false);
		}

		if (buf[0] != auth_type) {
			rfb_send_client_status(c, 1,
			    "Auth failed: authentication type mismatch");
			return (false);
		}

		break;
	}

	if (auth_type == RFBP_SECURITY_NONE) {
		/*
		 * According to the RFB specification[1], section 7.2.1, for a
		 * security type of 'None', client versions 3.3 and 3.7 expect
		 * to move straight to the ClientInit phase, without the server
		 * sending a response. For version 3.8, a SecurityResult word
		 * needs to be sent indicating success.
		 */
		switch (c->rc_cver) {
		case RFB_CVER_3_3:
		case RFB_CVER_3_7:
			break;
		case RFB_CVER_3_8:
			rfb_send_client_status(c, 0, NULL);
			break;
		}
		return (true);
	}

	/* Perform VNC authentication. */

#ifdef NO_OPENSSL
	rfb_printf(c, RFB_LOGERR,
	    "Auth not supported, no OpenSSL in your system");
	rfb_send_client_status(c, 1, "Auth failed.");
	return (false);
#else
	unsigned char challenge[RFBP_SECURITY_VNC_AUTH_LEN];
	unsigned char keystr[RFBP_SECURITY_VNC_PASSWD_LEN];
	unsigned char crypt_expected[RFBP_SECURITY_VNC_AUTH_LEN];
	DES_key_schedule ks;

	/*
	 * The client encrypts the challenge with DES, using a password
	 * supplied by the user as the key.
	 * To form the key, the password is truncated to eight characters, or
	 * padded with null bytes on the right.
	 * The client then sends the resulting 16-bytes response.
	 */
	(void) strncpy((char *)keystr, c->rc_s->rs_password,
	    RFBP_SECURITY_VNC_PASSWD_LEN);

	/*
	 * VNC clients encrypt the challenge with all the bit fields in each
	 * byte of the password mirrored.
	 * Here we flip each byte of the keystr.
	 */
	for (uint_t i = 0; i < RFBP_SECURITY_VNC_PASSWD_LEN; i++) {
		keystr[i] = (keystr[i] & 0xf0) >> 4 | (keystr[i] & 0x0f) << 4;
		keystr[i] = (keystr[i] & 0xcc) >> 2 | (keystr[i] & 0x33) << 2;
		keystr[i] = (keystr[i] & 0xaa) >> 1 | (keystr[i] & 0x55) << 1;
	}

	/* Initialize a 16-byte random challenge. */
	arc4random_buf(challenge, sizeof (challenge));

	/* Send the challenge to the client. */
	if (stream_write(c->rc_fd, challenge, RFBP_SECURITY_VNC_AUTH_LEN)
	    != RFBP_SECURITY_VNC_AUTH_LEN) {
		rfb_printf(c, RFB_LOGERR,
		    "failed to send challenge to client");
		return (false);
	}

	/* Receive the 16-byte challenge response. */
	if (stream_read(c->rc_fd, buf, RFBP_SECURITY_VNC_AUTH_LEN)
	    != RFBP_SECURITY_VNC_AUTH_LEN) {
		rfb_send_client_status(c, 1, "Challenge response read failed");
		return (false);
	}

	memcpy(crypt_expected, challenge, RFBP_SECURITY_VNC_AUTH_LEN);

	/* Encrypt the Challenge with DES. */
	DES_set_key_unchecked((const_DES_cblock *)keystr, &ks);
	DES_ecb_encrypt((const_DES_cblock *)challenge,
	    (const_DES_cblock *)crypt_expected, &ks, DES_ENCRYPT);
	DES_ecb_encrypt(
	    (const_DES_cblock *)(challenge + RFBP_SECURITY_VNC_PASSWD_LEN),
	    (const_DES_cblock *)(crypt_expected + RFBP_SECURITY_VNC_PASSWD_LEN),
	    &ks, DES_ENCRYPT);

	if (memcmp(crypt_expected, buf, RFBP_SECURITY_VNC_AUTH_LEN) != 0) {
		rfb_send_client_status(c, 1, "Auth failed: Invalid password.");
		return (false);
	}

	rfb_printf(c, RFB_LOGDEBUG, "authentication succeeded");
	rfb_send_client_status(c, 0, NULL);
#endif

	return (true);
}

static bool
rfb_handshake_init_message(rfb_client_t *c)
{
	struct bhyvegc_image *gci;
	char buf[1];
	char *name;

	rfb_printf(c, RFB_LOGDEBUG, "handshake server init");

	/* Read the client init message. */
	if (stream_read(c->rc_fd, buf, 1) != 1) {
		rfb_printf(c, RFB_LOGWARN, "client did not send init");
		return (false);
	}

	if (buf[0] == 0) {
		rfb_client_t *oc;

		rfb_printf(c, RFB_LOGDEBUG,
		    "client requested exclusive access");

		pthread_mutex_lock(&c->rc_s->rs_clientlock);
		c->rc_s->rs_exclusive = true;
		/* Disconnect all other clients. */
		for (oc = list_head(&c->rc_s->rs_clients); oc != NULL;
		    oc = list_next(&c->rc_s->rs_clients, oc)) {
			if (oc != c)
				oc->rc_closing = true;
		}
		pthread_mutex_unlock(&c->rc_s->rs_clientlock);
	} else {
		rfb_printf(c, RFB_LOGDEBUG, "client requested shared access");

		pthread_mutex_lock(&c->rc_s->rs_clientlock);
		if (c->rc_s->rs_exclusive) {
			rfb_printf(c, RFB_LOGWARN,
			    "deny due to existing exclusive session");
			pthread_mutex_unlock(&c->rc_s->rs_clientlock);
			return (false);
		}
		pthread_mutex_unlock(&c->rc_s->rs_clientlock);
	}

	gci = console_get_image();

	c->rc_sinfo.rsi_width = htons(gci->width);
	c->rc_sinfo.rsi_height = htons(gci->height);
	c->rc_width = gci->width;
	c->rc_height = gci->height;

	if (c->rc_s->rs_name != NULL)
		name = (char *)c->rc_s->rs_name;
	else
		name = "bhyve";

	c->rc_sinfo.rsi_namelen = htonl(strlen(name));
	(void) stream_write(c->rc_fd, &c->rc_sinfo, sizeof (c->rc_sinfo));
	(void) stream_write(c->rc_fd, name, strlen(name));

	return (true);
}

static bool
rfb_handshake(rfb_client_t *c)
{
	if (!rfb_handshake_version(c))
		return (false);

	if (!rfb_handshake_auth(c))
		return (false);

	if (!rfb_handshake_init_message(c))
		return (false);

	return (true);
}

static void
rfb_print_pixfmt(rfb_client_t *c, rfb_pixfmt_t *px, rfb_loglevel_t level)
{
	rfb_printf(c, level, "%20s: %u", "bpp", px->rp_bpp);
	rfb_printf(c, level, "%20s: %u", "depth", px->rp_depth);
	rfb_printf(c, level, "%20s: %u", "bigendian", px->rp_bigendian);
	rfb_printf(c, level, "%20s: %u", "truecolour", px->rp_truecolour);
	rfb_printf(c, level, "%20s: %u", "r_max", ntohs(px->rp_r_max));
	rfb_printf(c, level, "%20s: %u", "g_max", ntohs(px->rp_g_max));
	rfb_printf(c, level, "%20s: %u", "b_max", ntohs(px->rp_b_max));
	rfb_printf(c, level, "%20s: %u", "r_shift", px->rp_r_shift);
	rfb_printf(c, level, "%20s: %u", "g_shift", px->rp_g_shift);
	rfb_printf(c, level, "%20s: %u", "b_shift", px->rp_b_shift);
}

static bool
rfb_recv_set_pixel_format(rfb_client_t *c)
{
	rfb_cs_pixfmt_msg_t msg;
	rfb_pixfmt_t *newpx = &msg.rp_pixfmt;
	rfb_pixfmt_t *oldpx = &c->rc_sinfo.rsi_pixfmt;
	rfb_pixfmt_t *spx = &c->rc_s->rs_pixfmt;

	rfb_printf(c, RFB_LOGDEBUG, "received pixel format");

	if (stream_read(c->rc_fd, &msg, sizeof (msg)) != sizeof (msg))
		return (false);

	/*
	 * The client has sent its desired pixel format. The protocol does not
	 * have a mechanism to reject this, we are supposed to just start using
	 * the requested format from the next update.
	 *
	 * At present, we can only support alternative rgb-shift values and
	 * will accept (and ignore) a new depth value.
	 */

	if (oldpx->rp_bpp != newpx->rp_bpp ||
	    oldpx->rp_bigendian != newpx->rp_bigendian ||
	    oldpx->rp_truecolour != newpx->rp_truecolour ||
	    oldpx->rp_r_max != newpx->rp_r_max ||
	    oldpx->rp_g_max != newpx->rp_g_max ||
	    oldpx->rp_b_max != newpx->rp_b_max) {
		rfb_printf(c, RFB_LOGWARN, "unsupported pixfmt from client");
		rfb_print_pixfmt(c, newpx, RFB_LOGWARN);
		return (false);
	}

	rfb_print_pixfmt(c, newpx, RFB_LOGDEBUG);

	/* Check if the new shifts match the server's native values. */
	if (newpx->rp_r_shift != spx->rp_r_shift ||
	    newpx->rp_g_shift != spx->rp_g_shift ||
	    newpx->rp_b_shift != spx->rp_b_shift) {
		c->rc_custom_pixfmt = true;
		rfb_printf(c, RFB_LOGDEBUG, "Using custom pixfmt");
	} else {
		c->rc_custom_pixfmt = false;
		rfb_printf(c, RFB_LOGDEBUG, "Using native pixfmt");
	}

	c->rc_sinfo.rsi_pixfmt = msg.rp_pixfmt;
	c->rc_crc_reset = true;

	return (true);
}

static bool
rfb_recv_set_encodings(rfb_client_t *c)
{
	rfb_cs_encodings_msg_t msg;

	rfb_printf(c, RFB_LOGDEBUG, "received encodings");

	if (stream_read(c->rc_fd, &msg, sizeof (msg)) != sizeof (msg))
		return (false);

	msg.re_numencs = htons(msg.re_numencs);

	rfb_printf(c, RFB_LOGDEBUG, "%d values", msg.re_numencs);

	for (uint_t i = 0; i < msg.re_numencs; i++) {
		uint32_t enc;

		if (stream_read(c->rc_fd, &enc, sizeof (enc)) != sizeof (enc))
			return (false);

		enc = htonl(enc);

		switch (enc) {
		case RFBP_ENCODING_RAW:
			rfb_printf(c, RFB_LOGDEBUG,
			    "client supports raw encoding");
			c->rc_encodings |= RFB_ENCODING_RAW;
			break;
		case RFBP_ENCODING_ZLIB:
			rfb_printf(c, RFB_LOGDEBUG,
			    "client supports zlib encoding");
			if (!(c->rc_encodings & RFB_ENCODING_ZLIB)) {
				if (deflateInit(&c->rc_zstream, Z_BEST_SPEED)
				    != Z_OK) {
					return (false);
				}
				c->rc_encodings |= RFB_ENCODING_ZLIB;
			}
			break;
		case RFBP_ENCODING_RESIZE:
			rfb_printf(c, RFB_LOGDEBUG, "client supports resize");
			c->rc_encodings |= RFB_ENCODING_RESIZE;
			break;
		case RFBP_ENCODING_EXT_KEVENT:
			rfb_printf(c, RFB_LOGDEBUG,
			    "client supports ext key event");
			c->rc_encodings |= RFB_ENCODING_EXT_KEVENT;
			break;
		case RFBP_ENCODING_DESKTOP_NAME:
			rfb_printf(c, RFB_LOGDEBUG,
			    "client supports desktop name");
			c->rc_encodings |= RFB_ENCODING_DESKTOP_NAME;
			break;
		default:
			rfb_printf(c, RFB_LOGDEBUG,
			    "client supports encoding %d", (int32_t)enc);
		}
	}

	return (true);
}

static bool
rfb_recv_update(rfb_client_t *c)
{
	rfb_cs_update_msg_t msg;

	if (stream_read(c->rc_fd, &msg, sizeof (msg)) != sizeof (msg))
		return (false);

	if (!c->rc_keyevent_sent &&
	    (c->rc_encodings & RFB_ENCODING_EXT_KEVENT)) {
		/*
		 * Take this opportunity to tell the client that we
		 * accept QEMU Extended Key Event Pseudo-encoding.
		 */
		c->rc_keyevent_sent = true;
		rfb_send_extended_keyevent_update_msg(c);
	}

	c->rc_pending = true;
	if (msg.rum_incremental == 0) {
		rfb_printf(c, RFB_LOGDEBUG,
		    "client requested full screen update");
		c->rc_send_fullscreen = true;
	}

	return (true);
}

static bool
rfb_recv_key_event(rfb_client_t *c)
{
	rfb_cs_key_event_msg_t msg;

	if (stream_read(c->rc_fd, &msg, sizeof (msg)) != sizeof (msg))
		return (false);

	msg.rke_sym = htonl(msg.rke_sym);

	rfb_printf(c, RFB_LOGDEBUG, "received key %s %x",
	    msg.rke_down == 0 ? "up" : "down", msg.rke_sym);

	console_key_event(msg.rke_down, msg.rke_sym, htonl(0));
	c->rc_input_detected = true;

	return (true);
}

static bool
rfb_recv_pointer_event(rfb_client_t *c)
{
	rfb_cs_pointer_event_msg_t msg;

	if (stream_read(c->rc_fd, &msg, sizeof (msg)) != sizeof (msg))
		return (false);

	msg.rpe_x = htons(msg.rpe_x);
	msg.rpe_y = htons(msg.rpe_y);

	if (rfb_debug > 1) {
		rfb_printf(c, RFB_LOGDEBUG, "received pointer event @ %dx%d",
		    msg.rpe_x, msg.rpe_y);
	}

	console_ptr_event(msg.rpe_button, msg.rpe_x, msg.rpe_y);
	c->rc_input_detected = true;

	return (true);
}

static bool
rfb_recv_cut_text(rfb_client_t *c)
{
	rfb_cs_cut_text_msg_t msg;
	unsigned char buf[32];

	rfb_printf(c, RFB_LOGDEBUG, "received cut text event");

	if (stream_read(c->rc_fd, &msg, sizeof (msg)) != sizeof (msg))
		return (false);

	msg.rct_length = htonl(msg.rct_length);
	rfb_printf(c, RFB_LOGDEBUG, "%u bytes in buffer", msg.rct_length);
	/* Consume the buffer */
	while (msg.rct_length > 0) {
		ssize_t l;

		l = stream_read(c->rc_fd, buf,
		    MIN(sizeof (buf), msg.rct_length));
		if (l <= 0)
			return (false);
		msg.rct_length -= l;
	}

	return (true);
}

static bool
rfb_recv_qemu(rfb_client_t *c)
{
	rfb_cs_qemu_msg_t msg;

	rfb_printf(c, RFB_LOGDEBUG, "received QEMU event");

	if (stream_read(c->rc_fd, &msg, sizeof (msg)) != sizeof (msg))
		return (false);

	switch (msg.rq_subtype) {
	case RFBP_CS_QEMU_KEVENT: {
		rfb_cs_qemu_extended_key_msg_t keymsg;

		if (stream_read(c->rc_fd, &keymsg, sizeof (keymsg)) !=
		    sizeof (keymsg)) {
			return (false);
		}

		keymsg.rqek_sym = htonl(keymsg.rqek_sym);
		keymsg.rqek_code = htonl(keymsg.rqek_code);

		rfb_printf(c, RFB_LOGDEBUG, "QEMU key %s %x / %x",
		    keymsg.rqek_down == 0 ? "up" : "down",
		    keymsg.rqek_sym, keymsg.rqek_code);

		console_key_event((int)keymsg.rqek_down, keymsg.rqek_sym,
		    keymsg.rqek_code);
		c->rc_input_detected = true;
		break;
	}
	default:
		rfb_printf(c, RFB_LOGWARN, "Unknown QEMU event subtype: %d\n",
		    msg.rq_subtype);
		return (false);
	}

	return (true);
}

static bool
rfb_send_update_header(rfb_client_t *c, int numrects)
{
	rfb_server_update_msg_t msg;

	msg.rss_type = RFBP_SC_UPDATE;
	msg.rss_pad = 0;
	msg.rss_numrects = htons(numrects);

	return (stream_write(c->rc_fd, &msg, sizeof (msg)) == sizeof (msg));
}

static void
rfb_send_resize_update_msg(rfb_client_t *c)
{
	rfb_rect_hdr_t rect;

	rfb_printf(c, RFB_LOGDEBUG, "sending screen resize %dx%d",
	    c->rc_width, c->rc_height);

	(void) rfb_send_update_header(c, 1);

	rect.rr_x = htons(0);
	rect.rr_y = htons(0);
	rect.rr_width = htons(c->rc_width);
	rect.rr_height = htons(c->rc_height);
	rect.rr_encoding = htonl(RFBP_ENCODING_RESIZE);

	(void) stream_write(c->rc_fd, &rect, sizeof (rect));
}

static void
rfb_send_extended_keyevent_update_msg(rfb_client_t *c)
{
	rfb_rect_hdr_t rect;

	rfb_printf(c, RFB_LOGDEBUG, "sending extended keyevent update message");

	(void) rfb_send_update_header(c, 1);

	rect.rr_x = htons(0);
	rect.rr_y = htons(0);
	rect.rr_width = htons(c->rc_width);
	rect.rr_height = htons(c->rc_height);
	rect.rr_encoding = htonl(RFBP_ENCODING_EXT_KEVENT);

	(void) stream_write(c->rc_fd, &rect, sizeof (rect));
}

static void
translate_pixels(rfb_client_t *c, struct bhyvegc_image *gci,
    int x1, int y1, int x2, int y2)
{
	rfb_pixfmt_t *px = &c->rc_sinfo.rsi_pixfmt;
	rfb_pixfmt_t *spx = &c->rc_s->rs_pixfmt;
	int w, h;

	w = gci->width;
	h = gci->height;
	VERIFY3S(gci->width, ==, c->rc_gci.width);
	VERIFY3S(gci->height, ==, c->rc_gci.height);

	for (uint_t y = y1; y < h && y < y2; y++) {
		for (uint_t x = x1; x < w && x < x2; x++) {
			uint32_t p;

			p = gci->data[y * w + x];
			c->rc_gci.data[y * w + x] =
			    0xff000000 |
			    ((p >> spx->rp_r_shift) & 0xff) << px->rp_r_shift |
			    ((p >> spx->rp_g_shift) & 0xff) << px->rp_g_shift |
			    ((p >> spx->rp_b_shift) & 0xff) << px->rp_b_shift;
		}
	}
}

static bool
rfb_send_rect(rfb_client_t *c, struct bhyvegc_image *gci,
    int x, int y, int w, int h)
{
	rfb_rect_hdr_t rect;
	unsigned long zlen;
	ssize_t nwrite, total;
	int err;
	uint32_t *p;
	uint8_t *zbufp;

	if (rfb_debug > 1) {
		rfb_printf(c, RFB_LOGDEBUG, "send rect %dx%d %dx%d",
		    x, y, w, h);
	}

	/* Rectangle header. */
	rect.rr_x = htons(x);
	rect.rr_y = htons(y);
	rect.rr_width = htons(w);
	rect.rr_height = htons(h);

	uint32_t *data = gci->data;
	if (c->rc_custom_pixfmt) {
		translate_pixels(c, gci, x, y, x + w, y + h);
		data = c->rc_gci.data;
	}

	h = y + h;
	w *= sizeof (uint32_t);

	if (c->rc_encodings & RFB_ENCODING_ZLIB) {
		zbufp = c->rc_zbuf;
		c->rc_zstream.total_in = 0;
		c->rc_zstream.total_out = 0;
		for (p = &data[y * gci->width + x]; y < h; y++) {
			c->rc_zstream.next_in = (Bytef *)p;
			c->rc_zstream.avail_in = w;
			c->rc_zstream.next_out = (Bytef *)zbufp;
			c->rc_zstream.avail_out = RFB_ZLIB_BUFSZ + 16 -
			    c->rc_zstream.total_out;
			c->rc_zstream.data_type = Z_BINARY;

			/* Compress with zlib. */
			err = deflate(&c->rc_zstream, Z_SYNC_FLUSH);
			if (err != Z_OK) {
				rfb_printf(c, RFB_LOGWARN,
				    "zlib[rect] deflate err: %d", err);
				goto doraw;
			}
			zbufp = c->rc_zbuf + c->rc_zstream.total_out;
			p += gci->width;
		}
		rect.rr_encoding = htonl(RFBP_ENCODING_ZLIB);
		nwrite = stream_write(c->rc_fd, &rect, sizeof (rect));
		if (nwrite <= 0)
			return (false);

		zlen = htonl(c->rc_zstream.total_out);
		nwrite = stream_write(c->rc_fd, &zlen, sizeof (uint32_t));
		if (nwrite <= 0)
			return (false);
		return (stream_write(c->rc_fd, c->rc_zbuf,
		    c->rc_zstream.total_out) == c->rc_zstream.total_out);
	}

doraw:

	total = 0;
	zbufp = c->rc_zbuf;
	for (p = &data[y * gci->width + x]; y < h; y++) {
		memcpy(zbufp, p, w);
		zbufp += w;
		total += w;
		p += gci->width;
	}

	rect.rr_encoding = htonl(RFBP_ENCODING_RAW);
	nwrite = stream_write(c->rc_fd, &rect, sizeof (rect));
	if (nwrite <= 0)
		return (false);

	return (stream_write(c->rc_fd, c->rc_zbuf, total) == total);
}


static bool
rfb_send_all(rfb_client_t *c, struct bhyvegc_image *gci)
{
	rfb_rect_hdr_t rect;
	ssize_t nwrite;
	unsigned long zlen;
	int err;

	rfb_printf(c, RFB_LOGDEBUG, "send entire screen");

	/* Just the one (big) rect. */
	if (!rfb_send_update_header(c, 1))
		return (false);

	rect.rr_x = 0;
	rect.rr_y = 0;
	rect.rr_width = htons(gci->width);
	rect.rr_height = htons(gci->height);

	uint32_t *data = gci->data;
	if (c->rc_custom_pixfmt) {
		translate_pixels(c, gci, 0, 0, gci->width, gci->height);
		data = c->rc_gci.data;
	}

	if (c->rc_encodings & RFB_ENCODING_ZLIB) {
		c->rc_zstream.next_in = (Bytef *)data;
		c->rc_zstream.avail_in = gci->width * gci->height *
		    sizeof (uint32_t);
		c->rc_zstream.next_out = (Bytef *)c->rc_zbuf;
		c->rc_zstream.avail_out = RFB_ZLIB_BUFSZ + 16;
		c->rc_zstream.data_type = Z_BINARY;

		c->rc_zstream.total_in = 0;
		c->rc_zstream.total_out = 0;

		/* Compress with zlib. */
		err = deflate(&c->rc_zstream, Z_SYNC_FLUSH);
		if (err != Z_OK) {
			rfb_printf(c, RFB_LOGWARN, "zlib deflate err: %d", err);
			goto doraw;
		}

		rect.rr_encoding = htonl(RFBP_ENCODING_ZLIB);
		nwrite = stream_write(c->rc_fd, &rect, sizeof (rect));
		if (nwrite <= 0)
			return (false);

		zlen = htonl(c->rc_zstream.total_out);
		nwrite = stream_write(c->rc_fd, &zlen, sizeof (uint32_t));
		if (nwrite <= 0)
			return (false);
		return (stream_write(c->rc_fd, c->rc_zbuf,
		    c->rc_zstream.total_out) == c->rc_zstream.total_out);
	}

doraw:
	rect.rr_encoding = htonl(RFBP_ENCODING_RAW);
	nwrite = stream_write(c->rc_fd, &rect, sizeof (rect));
	if (nwrite <= 0)
		return (false);

	nwrite = gci->width * gci->height * sizeof (uint32_t);
	return (stream_write(c->rc_fd, data, nwrite) == nwrite);
}

static bool
rfb_send_screen(rfb_client_t *c)
{
	struct bhyvegc_image *gci;
	bool retval = true;
	bool sendall = false;
	int xcells, ycells;
	int rem_x, rem_y;
	uint32_t *p, *ncrc, *ocrc;
	uint_t changes, perc, x, y;

	/* Updates require a preceding client update request. */
	if (atomic_exchange(&c->rc_pending, false) == false)
		return (true);

	console_refresh();
	gci = console_get_image();

	/*
	 * It's helpful if the image size or data address does not change
	 * underneath us.
	 */
	pthread_mutex_lock(&gci->mtx);

	/* Check for screen resolution changes. */
	if (c->rc_width != gci->width ||
	    c->rc_height != gci->height) {
		c->rc_width = gci->width;
		c->rc_height = gci->height;
		c->rc_crc_reset = true;
		c->rc_send_fullscreen = true;

		/* If the client supports it, send a resize event. */
		if (c->rc_encodings & RFB_ENCODING_RESIZE) {
			rfb_send_resize_update_msg(c);
			/*
			 * A resize message counts as an update in response to
			 * the client's preceding request so rc->pending does
			 * not need to be reset here.
			 */
			goto done;
		}
	}

	/* Clear old CRC values. */
	if (atomic_exchange(&c->rc_crc_reset, false))
		memset(c->rc_crc, '\0', c->rc_cells * sizeof (uint32_t));

	if (c->rc_custom_pixfmt && (c->rc_gci.data == NULL ||
	    c->rc_gci.width != c->rc_width ||
	    c->rc_gci.height != c->rc_height)) {
		c->rc_gci.data = reallocarray(c->rc_gci.data,
		    c->rc_width * c->rc_height, sizeof (uint32_t));
		if (c->rc_gci.data == NULL) {
			retval = false;
			goto done;
		}
		c->rc_gci.width = c->rc_width;
		c->rc_gci.height = c->rc_height;
	} else if (!c->rc_custom_pixfmt && c->rc_gci.data != NULL) {
		free(c->rc_gci.data);
		c->rc_gci.data = NULL;
	}

	sendall = atomic_exchange(&c->rc_send_fullscreen, false);

	/*
	 * Calculate a checksum for each 32x32 cell. Send all that have
	 * changed since the last scan.
	 */

	xcells = howmany(gci->width, RFB_PIX_PER_CELL);
	ycells = howmany(gci->height, RFB_PIX_PER_CELL);
	rem_x = gci->width & RFB_PIXCELL_MASK;
	rem_y = gci->height & RFB_PIXCELL_MASK;
	if (rem_y == 0)
		rem_y = RFB_PIX_PER_CELL;

	p = gci->data;

	ncrc = c->rc_crc_tmp - xcells;
	ocrc = c->rc_crc - xcells;
	changes = 0;
	memset(c->rc_crc_tmp, '\0', sizeof (uint32_t) * xcells * ycells);
	for (y = 0; y < gci->height; y++) {
		if ((y & RFB_PIXCELL_MASK) == 0) {
			ncrc += xcells;
			ocrc += xcells;
		}

		for (x = 0; x < xcells; x++) {
			uint_t cellwidth;

			if (x == xcells - 1 && rem_x > 0)
				cellwidth = rem_x;
			else
				cellwidth = RFB_PIX_PER_CELL;

			if (rfb_sse42) {
				ncrc[x] = fast_crc32(p,
				    cellwidth * sizeof (uint32_t), ncrc[x]);
			} else {
				ncrc[x] = (uint32_t)crc32(ncrc[x],
				    (Bytef *)p, cellwidth * sizeof (uint32_t));
			}

			p += cellwidth;

			/* check for crc delta if last row in cell. */
			if ((y & RFB_PIXCELL_MASK) == RFB_PIXCELL_MASK ||
			    y == gci->height - 1) {
				if (ocrc[x] != ncrc[x]) {
					ocrc[x] = ncrc[x];
					ncrc[x] = 1;
					changes++;
				} else {
					ncrc[x] = 0;
				}
			}
		}
	}

	perc = (changes * 100) / (xcells * ycells);
	if (rfb_debug > 1 && changes > 0) {
		rfb_printf(c, RFB_LOGDEBUG,
		    "scanned and found %u changed cell(s) - %u%%",
		    changes, perc);
	}

	/*
	 * If there are no changes, don't send an update. Restore the pending
	 * flag since we still owe the client an update.
	 */
	if (!sendall && !changes) {
		c->rc_pending = true;
		goto done;
	}

	/* If there are a lot of changes, send the whole screen. */
	if (perc >= RFB_SENDALL_THRESH)
		sendall = true;

	if (sendall) {
		retval = rfb_send_all(c, gci);
		goto done;
	}

	if (!rfb_send_update_header(c, changes)) {
		retval = false;
		goto done;
	}

	/* Send the changed cells as separate rects. */
	ncrc = c->rc_crc_tmp;
	for (y = 0; y < gci->height; y += RFB_PIX_PER_CELL) {
		/* Previous cell's row. */
		int celly = (y >> RFB_PIXCELL_SHIFT);

		/* Delta check crc to previous set. */
		for (x = 0; x < xcells; x++) {
			uint_t cellwidth;

			if (*ncrc++ == 0)
				continue;

			if (x == xcells - 1 && rem_x > 0)
				cellwidth = rem_x;
			else
				cellwidth = RFB_PIX_PER_CELL;

			if (!rfb_send_rect(c, gci,
			    x * RFB_PIX_PER_CELL, celly * RFB_PIX_PER_CELL,
			    cellwidth, y + RFB_PIX_PER_CELL >= gci->height ?
			    rem_y : RFB_PIX_PER_CELL)) {
				retval = false;
				goto done;
			}
		}
	}

done:
	pthread_mutex_unlock(&gci->mtx);

	return (retval);
}

static void *
rfb_client_rx_thread(void *arg)
{
	rfb_client_t *c = arg;
	unsigned char cmd;
	bool ret = true;

	while (ret && !c->rc_closing && (read(c->rc_fd, &cmd, 1) == 1)) {
		switch (cmd) {
		case RFBP_CS_SET_PIXEL_FORMAT:
			ret = rfb_recv_set_pixel_format(c);
			break;
		case RFBP_CS_SET_ENCODINGS:
			ret = rfb_recv_set_encodings(c);
			break;
		case RFBP_CS_UPDATE_REQUEST:
			ret = rfb_recv_update(c);
			break;
		case RFBP_CS_KEY_EVENT:
			ret = rfb_recv_key_event(c);
			break;
		case RFBP_CS_POINTER_EVENT:
			ret = rfb_recv_pointer_event(c);
			break;
		case RFBP_CS_CUT_TEXT:
			ret = rfb_recv_cut_text(c);
			break;
		case RFBP_CS_QEMU:
			ret = rfb_recv_qemu(c);
			break;
		default:
			rfb_printf(c, RFB_LOGWARN, "unknown cs code %d",
			    cmd & 0xff);
			ret = false;
		}
	}

	rfb_printf(c, RFB_LOGDEBUG, "client rx thread exiting");
	c->rc_closing = true;

	return (NULL);
}

static void *
rfb_client_tx_thread(void *arg)
{
	rfb_client_t *c = arg;
	rfb_server_t *s = c->rc_s;
	char tname[MAXCOMLEN + 1];
	uint_t counter = 0;
	hrtime_t tprev;
	void *status;
	int err;

	(void) snprintf(tname, sizeof (tname), "rfb%u tx", c->rc_instance);
	(void) pthread_set_name_np(c->rc_tx_tid, tname);

	c->rc_sinfo.rsi_pixfmt = c->rc_s->rs_pixfmt;
	c->rc_encodings = RFB_ENCODING_RAW;

	if (!rfb_handshake(c)) {
		rfb_printf(c, RFB_LOGWARN, "handshake failure");
		goto out;
	}

	c->rc_cells = howmany(RFB_MAX_WIDTH * RFB_MAX_HEIGHT, RFB_PIX_PER_CELL);
	if ((c->rc_crc = calloc(c->rc_cells, sizeof (uint32_t))) == NULL ||
	    (c->rc_crc_tmp = calloc(c->rc_cells, sizeof (uint32_t))) == NULL) {
		perror("calloc crc");
		goto out;
	}

	err = pthread_create(&c->rc_rx_tid, NULL, rfb_client_rx_thread, c);
	if (err != 0) {
		perror("pthread_create client rx thread");
		goto out;
	}

	(void) snprintf(tname, sizeof (tname), "rfb%u rx", c->rc_instance);
	(void) pthread_set_name_np(c->rc_rx_tid, tname);

	tprev = gethrtime();

	while (!c->rc_closing) {
		struct timeval tv;
		hrtime_t tnow;
		int64_t tdiff;
		fd_set rfds;
		int err;

		FD_ZERO(&rfds);
		FD_SET(c->rc_fd, &rfds);
		tv.tv_sec = 0;
		tv.tv_usec = RFB_SEL_DELAY_US;

		err = select(c->rc_fd + 1, &rfds, NULL, NULL, &tv);
		if (err < 0)
			break;

		/* Determine if its time to push the screen; ~24hz. */
		tnow = gethrtime();
		tdiff = NSEC2USEC(tnow - tprev);
		if (tdiff >= RFB_SCREEN_POLL_DELAY) {
			bool input;

			tprev = tnow;

			input = atomic_exchange(&c->rc_input_detected, false);
			/*
			 * Refresh the screen on every second trip through the
			 * loop, or if keyboard/mouse input has been detected.
			 */
			if ((++counter & 1) != 0 || input) {
				if (!rfb_send_screen(c))
					break;
			}
		} else {
			(void) usleep(RFB_SCREEN_POLL_DELAY - tdiff);
		}
	}

out:

	rfb_printf(c, RFB_LOGWARN, "disconnected");

	(void) pthread_join(c->rc_rx_tid, &status);
	pthread_mutex_lock(&s->rs_clientlock);
	s->rs_clientcount--;
	list_remove(&s->rs_clients, c);
	if (s->rs_exclusive && s->rs_clientcount == 0)
		s->rs_exclusive = false;
	id_free(rfb_idspace, c->rc_instance);
	pthread_mutex_unlock(&s->rs_clientlock);

	rfb_free_client(c);
	return (NULL);
}

static void
rfb_accept(int sfd, enum ev_type event, void *arg)
{
	rfb_server_t *s = arg;
	rfb_client_t *c = NULL;
	struct sockaddr_storage cliaddr;
	socklen_t len;
	char host[NI_MAXHOST], port[NI_MAXSERV];
	int cfd, err;
	uint_t cc;

	rfb_printf(c, RFB_LOGDEBUG, "incoming connection");

	len = sizeof (cliaddr);
	cfd = accept(sfd, (struct sockaddr *)&cliaddr, &len);
	if (cfd == -1) {
		perror("client accept");
		return;
	}

	*host = *port = '\0';
	if (cliaddr.ss_family == AF_UNIX) {
		rfb_printf(NULL, RFB_LOGDEBUG, "connection on UNIX socket");
		(void) strlcpy(host, "<UNIX>", sizeof (host));
	} else {
		err = getnameinfo((struct sockaddr *)&cliaddr, len,
		    host, sizeof (host), port, sizeof (port),
		    NI_NUMERICHOST | NI_NUMERICSERV);
		if (err != 0) {
			rfb_printf(NULL, RFB_LOGERR, "getnameinfo: %s",
			    gai_strerror(err));
			*host = *port = '\0';
		} else {
			rfb_printf(NULL, RFB_LOGDEBUG, "connection from %s:%s",
			    host, port);
		}
	}

	pthread_mutex_lock(&s->rs_clientlock);
	cc = s->rs_clientcount;
	pthread_mutex_unlock(&s->rs_clientlock);
	if (cc >= RFB_MAX_CLIENTS) {
		rfb_printf(NULL, RFB_LOGERR,
		    "too many clients, closing connection.");
		goto fail;
	}

	if ((c = calloc(1, sizeof (rfb_client_t))) == NULL) {
		perror("calloc client");
		goto fail;
	}

	c->rc_fd = cfd;
	c->rc_s = s;
	c->rc_zbuf = malloc(RFB_ZLIB_BUFSZ + 16);
	if (c->rc_zbuf == NULL)
		goto fail;

	pthread_mutex_lock(&s->rs_clientlock);

	err = pthread_create(&c->rc_tx_tid, NULL, rfb_client_tx_thread, c);
	if (err != 0) {
		perror("pthread_create client tx thread");
		pthread_mutex_unlock(&s->rs_clientlock);
		goto fail;
	}

	s->rs_clientcount++;
	list_insert_tail(&s->rs_clients, c);
	c->rc_instance = id_allocff(rfb_idspace);
	pthread_mutex_unlock(&s->rs_clientlock);

	(void) pthread_detach(c->rc_tx_tid);

	rfb_printf(c, RFB_LOGWARN, "connection from %s", host);

	return;

fail:
	(void) close(cfd);
	free(c);
}

int
rfb_init(char *hostname, int port, int wait, const char *password,
    const char *name)
{
	rfb_server_t *s;
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
#endif

	(void) pthread_once(&rfb_once, rfb_init_once);

	if (rfb_idspace == NULL) {
		rfb_printf(NULL, RFB_LOGERR,
		    "rfb_idspace could not be allocated");
		return (-1);
	}

	if ((s = calloc(1, sizeof (rfb_server_t))) == NULL) {
		perror("calloc");
		return (-1);
	}
	s->rs_fd = -1;
	s->rs_name = name;

	if (password != NULL && strlen(password) > 0)
		s->rs_password = password;

	if (pthread_mutex_init(&s->rs_clientlock, NULL) != 0) {
		perror("pthread_mutex_init");
		free(s);
		return (-1);
	}

	list_create(&s->rs_clients, sizeof (rfb_client_t),
	    offsetof(rfb_client_t, rc_node));

	/* Server pixel format. */
	s->rs_pixfmt.rp_bpp = RFB_PIX_BPP;
	s->rs_pixfmt.rp_depth = RFB_PIX_DEPTH;
	s->rs_pixfmt.rp_bigendian = 0;
	s->rs_pixfmt.rp_truecolour = 1;
	s->rs_pixfmt.rp_r_max = htons(RFB_PIX_RMAX);
	s->rs_pixfmt.rp_g_max = htons(RFB_PIX_GMAX);
	s->rs_pixfmt.rp_b_max = htons(RFB_PIX_BMAX);
	s->rs_pixfmt.rp_r_shift = RFB_PIX_RSHIFT;
	s->rs_pixfmt.rp_g_shift = RFB_PIX_GSHIFT;
	s->rs_pixfmt.rp_b_shift = RFB_PIX_BSHIFT;

	/* UNIX socket. */
	if (port == -1 && hostname != NULL && *hostname == '/') {
		struct sockaddr_un sock;

		s->rs_fd = socket(PF_UNIX, SOCK_STREAM, 0);
		if (s->rs_fd < 0) {
			perror("socket");
			goto fail;
		}

		sock.sun_family = AF_UNIX;
		if (strlcpy(sock.sun_path, hostname, sizeof (sock.sun_path)) >=
		    sizeof (sock.sun_path)) {
			rfb_printf(NULL, RFB_LOGERR,
			    "socket path '%s' too long\n", hostname);
			goto fail;
		}

		(void) unlink(hostname);
		if (bind(s->rs_fd, (struct sockaddr *)&sock,
		    sizeof (sock)) < 0) {
			perror("bind");
			goto fail;
		}
	} else {
		struct addrinfo hints, *ai = NULL;
		char servname[6];
		int e;

		(void) snprintf(servname, sizeof (servname), "%d",
		    port ? port : RFB_DEFAULT_PORT);

		if (hostname == NULL || strlen(hostname) == 0) {
#if defined(INET)
			hostname = "127.0.0.1";
#elif defined(INET6)
			hostname = "[::1]";
#endif
		}

		memset(&hints, '\0', sizeof (hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV | AI_PASSIVE;

		if ((e = getaddrinfo(hostname, servname, &hints, &ai)) != 0) {
			rfb_printf(NULL, RFB_LOGERR, "getaddrinfo: %s",
			    gai_strerror(e));
			goto fail;
		}

		s->rs_fd = socket(ai->ai_family, ai->ai_socktype, 0);
		if (s->rs_fd < 0) {
			perror("socket");
			freeaddrinfo(ai);
			goto fail;
		}

		e = 1;
		(void) setsockopt(s->rs_fd, SOL_SOCKET, SO_REUSEADDR,
		    &e, sizeof (e));

		if (bind(s->rs_fd, ai->ai_addr, ai->ai_addrlen) < 0) {
			perror("bind");
			freeaddrinfo(ai);
			goto fail;
		}
		freeaddrinfo(ai);
	}

	if (listen(s->rs_fd, 5) < 0) {
		perror("listen");
		goto fail;
	}

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_ACCEPT, CAP_EVENT, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(s->rs_fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	s->rs_connevent = mevent_add(s->rs_fd, EVF_READ, rfb_accept, s);
	if (s->rs_connevent == NULL) {
		rfb_printf(NULL, RFB_LOGERR,
		    "Failed to set up rfb connection mevent");
		goto fail;
	}

	list_insert_tail(&rfb_list, s);

	/*
	 * Wait for first connection. Since the mevent thread is
	 * not yet running, we can't rely on normal incoming connection
	 * handling.
	 */
	if (wait != 0) {
		fd_set rfds;
		int e;

		rfb_printf(NULL, RFB_LOGWARN,
		    "holding boot until first client connection");

		for (;;) {
			FD_ZERO(&rfds);
			FD_SET(s->rs_fd, &rfds);

			e = select(s->rs_fd + 1, &rfds, NULL, NULL, NULL);
			if (e < 0 && errno == EINTR)
				continue;
			if (e < 0 || FD_ISSET(s->rs_fd, &rfds))
				break;
		}
		rfb_printf(NULL, RFB_LOGWARN, "continuing boot");
	}

	return (0);

fail:
	if (s->rs_fd != -1)
		VERIFY3S(close(s->rs_fd), ==, 0);
	(void) pthread_mutex_destroy(&s->rs_clientlock);
	list_destroy(&s->rs_clients);
	free(s);
	return (-1);
}
