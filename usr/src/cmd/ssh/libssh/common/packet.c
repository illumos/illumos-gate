/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains code implementing the packet protocol and communication
 * with the other side.  This same code is used both on client and server side.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * SSH2 packet format added by Markus Friedl.
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* $OpenBSD: packet.c,v 1.148 2007/06/07 19:37:34 pvalchev Exp $ */

#include "includes.h"

#include "sys-queue.h"
#include "xmalloc.h"
#include "buffer.h"
#include "packet.h"
#include "bufaux.h"
#include "crc32.h"
#include "getput.h"
#include "compress.h"
#include "deattack.h"
#include "channels.h"
#include "compat.h"
#include "ssh1.h"
#include "ssh2.h"
#include "cipher.h"
#include "kex.h"
#include "mac.h"
#include "log.h"
#include "canohost.h"
#include "misc.h"
#include "ssh.h"
#include "engine.h"

/* PKCS#11 engine */
ENGINE *e;

#ifdef ALTPRIVSEP
static int packet_server = 0;
static int packet_monitor = 0;
#endif /* ALTPRIVSEP */

#ifdef PACKET_DEBUG
#define DBG(x) x
#else
#define DBG(x)
#endif

static void packet_send2(void);

/*
 * This variable contains the file descriptors used for communicating with
 * the other side.  connection_in is used for reading; connection_out for
 * writing.  These can be the same descriptor, in which case it is assumed to
 * be a socket.
 */
static int connection_in = -1;
static int connection_out = -1;

/* Protocol flags for the remote side. */
static u_int remote_protocol_flags = 0;

/* Encryption context for receiving data.  This is only used for decryption. */
static CipherContext receive_context;

/* Encryption context for sending data.  This is only used for encryption. */
static CipherContext send_context;

/* Buffer for raw input data from the socket. */
Buffer input;

/* Buffer for raw output data going to the socket. */
Buffer output;

/* Buffer for the partial outgoing packet being constructed. */
static Buffer outgoing_packet;

/* Buffer for the incoming packet currently being processed. */
static Buffer incoming_packet;

/* Scratch buffer for packet compression/decompression. */
static Buffer compression_buffer;
static int compression_buffer_ready = 0;

/* Flag indicating whether packet compression/decompression is enabled. */
static int packet_compression = 0;

/* default maximum packet size */
int max_packet_size = 32768;

/* Flag indicating whether this module has been initialized. */
static int initialized = 0;

/* Set to true if the connection is interactive. */
static int interactive_mode = 0;

/* Session key information for Encryption and MAC */
Newkeys *newkeys[MODE_MAX];
static struct packet_state {
	u_int32_t seqnr;
	u_int32_t packets;
	u_int64_t blocks;
} p_read, p_send;

static u_int64_t max_blocks_in, max_blocks_out;
static u_int32_t rekey_limit;

/* Session key for protocol v1 */
static u_char ssh1_key[SSH_SESSION_KEY_LENGTH];
static u_int ssh1_keylen;

/* roundup current message to extra_pad bytes */
static u_char extra_pad = 0;

struct packet {
	TAILQ_ENTRY(packet) next;
	u_char type;
	Buffer payload;
};
TAILQ_HEAD(, packet) outgoing;

/*
 * Part of what -f option and ~& escape sequence do in the client is that they
 * will force it to daemonize itself. Due to the fork safety rules inherent in
 * any PKCS#11 environment, if the engine is used we must do a key re-exchange
 * before forking a child to negotiate the new keys. Those keys will be used to
 * inicialize the new crypto contexts. This involves finishing the engine in the
 * parent and reinitializing it again in both processes after fork() returns.
 * This approach also leaves protocol 1 out since it doesn't support rekeying.
 */
int will_daemonize;

#ifdef	PACKET_DEBUG
/* This function dumps data onto stderr. This is for debugging only. */
void
data_dump(void *data, u_int len)
{
	Buffer buf;

	buffer_init(&buf);
	buffer_append(&buf, data, len);
	buffer_dump(&buf);
	buffer_free(&buf);
}
#endif

/*
 * Sets the descriptors used for communication.  Disables encryption until
 * packet_set_encryption_key is called.
 */
void
packet_set_connection(int fd_in, int fd_out)
{
	Cipher *none = cipher_by_name("none");

	if (none == NULL)
		fatal("packet_set_connection: cannot load cipher 'none'");
	connection_in = fd_in;
	connection_out = fd_out;
	cipher_init(&send_context, none, (unsigned char *) "", 0, NULL, 0, CIPHER_ENCRYPT);
	cipher_init(&receive_context, none, (unsigned char *) "", 0, NULL, 0, CIPHER_DECRYPT);
	newkeys[MODE_IN] = newkeys[MODE_OUT] = NULL;
	if (!initialized) {
		initialized = 1;
		buffer_init(&input);
		buffer_init(&output);
		buffer_init(&outgoing_packet);
		buffer_init(&incoming_packet);
		TAILQ_INIT(&outgoing);
	} else {
		buffer_clear(&input);
		buffer_clear(&output);
		buffer_clear(&outgoing_packet);
		buffer_clear(&incoming_packet);
	}

	/*
	 * Prime the cache for get_remote_ipaddr() while we have a
	 * socket on which to do a getpeername().
	 */
	(void) get_remote_ipaddr();

	/* Kludge: arrange the close function to be called from fatal(). */
	fatal_add_cleanup((void (*) (void *)) packet_close, NULL);
}

/* Returns 1 if remote host is connected via socket, 0 if not. */

int
packet_connection_is_on_socket(void)
{
	struct sockaddr_storage from, to;
	socklen_t fromlen, tolen;

	/* filedescriptors in and out are the same, so it's a socket */
	if (connection_in != -1 && connection_in == connection_out)
		return 1;
	fromlen = sizeof(from);
	memset(&from, 0, sizeof(from));
	if (getpeername(connection_in, (struct sockaddr *)&from, &fromlen) < 0)
		return 0;
	tolen = sizeof(to);
	memset(&to, 0, sizeof(to));
	if (getpeername(connection_out, (struct sockaddr *)&to, &tolen) < 0)
		return 0;
	if (fromlen != tolen || memcmp(&from, &to, fromlen) != 0)
		return 0;
	if (from.ss_family != AF_INET && from.ss_family != AF_INET6)
		return 0;
	return 1;
}

/* returns 1 if connection is via ipv4 */

int
packet_connection_is_ipv4(void)
{
	struct sockaddr_storage to;
	socklen_t tolen = sizeof(to);

	memset(&to, 0, sizeof(to));
	if (getsockname(connection_out, (struct sockaddr *)&to, &tolen) < 0)
		return 0;
	if (to.ss_family == AF_INET)
		return 1;
#ifdef IPV4_IN_IPV6
	if (to.ss_family == AF_INET6 && 
	    IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)&to)->sin6_addr))
		return 1;
#endif
	return 0;
}

/* Sets the connection into non-blocking mode. */

void
packet_set_nonblocking(void)
{
	/* Set the socket into non-blocking mode. */
	if (fcntl(connection_in, F_SETFL, O_NONBLOCK) < 0)
		error("fcntl O_NONBLOCK: %.100s", strerror(errno));

	if (connection_out != connection_in) {
		if (fcntl(connection_out, F_SETFL, O_NONBLOCK) < 0)
			error("fcntl O_NONBLOCK: %.100s", strerror(errno));
	}
}

/* Returns the socket used for reading. */

int
packet_get_connection_in(void)
{
	return connection_in;
}

/* Returns the descriptor used for writing. */

int
packet_get_connection_out(void)
{
	return connection_out;
}

/* Closes the connection and clears and frees internal data structures. */

void
packet_close(void)
{
	if (!initialized)
		return;
	initialized = 0;
	if (connection_in == connection_out) {
		shutdown(connection_out, SHUT_RDWR);
		close(connection_out);
	} else {
		close(connection_in);
		close(connection_out);
	}
	buffer_free(&input);
	buffer_free(&output);
	buffer_free(&outgoing_packet);
	buffer_free(&incoming_packet);
	if (compression_buffer_ready) {
		buffer_free(&compression_buffer);
		buffer_compress_uninit();
		compression_buffer_ready = 0;
	}
	cipher_cleanup(&send_context);
	cipher_cleanup(&receive_context);
}

/* Sets remote side protocol flags. */

void
packet_set_protocol_flags(u_int protocol_flags)
{
	remote_protocol_flags = protocol_flags;
}

/* Returns the remote protocol flags set earlier by the above function. */

u_int
packet_get_protocol_flags(void)
{
	return remote_protocol_flags;
}

/*
 * Starts packet compression from the next packet on in both directions.
 * Level is compression level 1 (fastest) - 9 (slow, best) as in gzip.
 */

static void
packet_init_compression(void)
{
	if (compression_buffer_ready == 1)
		return;
	compression_buffer_ready = 1;
	buffer_init(&compression_buffer);
}

void
packet_start_compression(int level)
{
#ifdef ALTPRIVSEP
	/* shouldn't happen! */
	if (packet_monitor)
		fatal("INTERNAL ERROR: The monitor cannot compress.");
#endif /* ALTPRIVSEP */

	if (packet_compression && !compat20)
		fatal("Compression already enabled.");
	packet_compression = 1;
	packet_init_compression();
	buffer_compress_init_send(level);
	buffer_compress_init_recv();
}

/*
 * Causes any further packets to be encrypted using the given key.  The same
 * key is used for both sending and reception.  However, both directions are
 * encrypted independently of each other.
 */

void
packet_set_encryption_key(const u_char *key, u_int keylen,
    int number)
{
	Cipher *cipher = cipher_by_number(number);

	if (cipher == NULL)
		fatal("packet_set_encryption_key: unknown cipher number %d", number);
	if (keylen < 20)
		fatal("packet_set_encryption_key: keylen too small: %d", keylen);
	if (keylen > SSH_SESSION_KEY_LENGTH)
		fatal("packet_set_encryption_key: keylen too big: %d", keylen);
	memcpy(ssh1_key, key, keylen);
	ssh1_keylen = keylen;
	cipher_init(&send_context, cipher, key, keylen, NULL, 0, CIPHER_ENCRYPT);
	cipher_init(&receive_context, cipher, key, keylen, NULL, 0, CIPHER_DECRYPT);
}

u_int
packet_get_encryption_key(u_char *key)
{
	if (key == NULL)
		return (ssh1_keylen);
	memcpy(key, ssh1_key, ssh1_keylen);
	return (ssh1_keylen);
}

/* Start constructing a packet to send. */
void
packet_start(u_char type)
{
	u_char buf[9];
	int len;

	DBG(debug("packet_start[%d]", type));
	len = compat20 ? 6 : 9;
	memset(buf, 0, len - 1);
	buf[len - 1] = type;
	buffer_clear(&outgoing_packet);
	buffer_append(&outgoing_packet, buf, len);
}

/* Append payload. */
void
packet_put_char(int value)
{
	char ch = value;

	buffer_append(&outgoing_packet, &ch, 1);
}

void
packet_put_int(u_int value)
{
	buffer_put_int(&outgoing_packet, value);
}

void
packet_put_string(const void *buf, u_int len)
{
	buffer_put_string(&outgoing_packet, buf, len);
}

void
packet_put_cstring(const char *str)
{
	buffer_put_cstring(&outgoing_packet, str);
}

void
packet_put_ascii_cstring(const char *str)
{
	buffer_put_ascii_cstring(&outgoing_packet, str);
}
void
packet_put_utf8_cstring(const u_char *str)
{
	buffer_put_utf8_cstring(&outgoing_packet, str);
}
#if 0
void
packet_put_ascii_string(const void *buf, u_int len)
{
	buffer_put_ascii_string(&outgoing_packet, buf, len);
}
void
packet_put_utf8_string(const void *buf, u_int len)
{
	buffer_put_utf8_string(&outgoing_packet, buf, len);
}
#endif
void
packet_put_raw(const void *buf, u_int len)
{
	buffer_append(&outgoing_packet, buf, len);
}

void
packet_put_bignum(BIGNUM * value)
{
	buffer_put_bignum(&outgoing_packet, value);
}

void
packet_put_bignum2(BIGNUM * value)
{
	buffer_put_bignum2(&outgoing_packet, value);
}

/*
 * Finalizes and sends the packet.  If the encryption key has been set,
 * encrypts the packet before sending.
 */

static void
packet_send1(void)
{
	u_char buf[8], *cp;
	int i, padding, len;
	u_int checksum;
	u_int32_t rnd = 0;

	/*
	 * If using packet compression, compress the payload of the outgoing
	 * packet.
	 */
	if (packet_compression) {
		buffer_clear(&compression_buffer);
		/* Skip padding. */
		buffer_consume(&outgoing_packet, 8);
		/* padding */
		buffer_append(&compression_buffer, "\0\0\0\0\0\0\0\0", 8);
		buffer_compress(&outgoing_packet, &compression_buffer);
		buffer_clear(&outgoing_packet);
		buffer_append(&outgoing_packet, buffer_ptr(&compression_buffer),
		    buffer_len(&compression_buffer));
	}
	/* Compute packet length without padding (add checksum, remove padding). */
	len = buffer_len(&outgoing_packet) + 4 - 8;

	/* Insert padding. Initialized to zero in packet_start1() */
	padding = 8 - len % 8;
	if (!send_context.plaintext) {
		cp = buffer_ptr(&outgoing_packet);
		for (i = 0; i < padding; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[7 - i] = rnd & 0xff;
			rnd >>= 8;
		}
	}
	buffer_consume(&outgoing_packet, 8 - padding);

	/* Add check bytes. */
	checksum = ssh_crc32(buffer_ptr(&outgoing_packet),
	    buffer_len(&outgoing_packet));
	PUT_32BIT(buf, checksum);
	buffer_append(&outgoing_packet, buf, 4);

#ifdef PACKET_DEBUG
	fprintf(stderr, "packet_send plain: ");
	buffer_dump(&outgoing_packet);
#endif

	/* Append to output. */
	PUT_32BIT(buf, len);
	buffer_append(&output, buf, 4);
	cp = buffer_append_space(&output, buffer_len(&outgoing_packet));
	cipher_crypt(&send_context, cp, buffer_ptr(&outgoing_packet),
	    buffer_len(&outgoing_packet));

#ifdef PACKET_DEBUG
	debug("encrypted output queue now contains (%d bytes):\n",
	    buffer_len(&output));
	buffer_dump(&output);
#endif

	buffer_clear(&outgoing_packet);

	/*
	 * Note that the packet is now only buffered in output.  It won\'t be
	 * actually sent until packet_write_wait or packet_write_poll is
	 * called.
	 */
}

void
set_newkeys(int mode)
{
	Enc *enc;
	Mac *mac;
	Comp *comp;
	CipherContext *cc;
	u_int64_t *max_blocks;
	int crypt_type;

	debug2("set_newkeys: mode %d", mode);

	if (mode == MODE_OUT) {
		cc = &send_context;
		crypt_type = CIPHER_ENCRYPT;
		p_send.packets = p_send.blocks = 0;
		max_blocks = &max_blocks_out;
	} else {
		cc = &receive_context;
		crypt_type = CIPHER_DECRYPT;
		p_read.packets = p_read.blocks = 0;
		max_blocks = &max_blocks_in;
	}

	debug("set_newkeys: setting new keys for '%s' mode",
	    mode == MODE_IN ? "in" : "out");

	if (newkeys[mode] != NULL) {
		cipher_cleanup(cc);
		free_keys(newkeys[mode]);
	}

	newkeys[mode] = kex_get_newkeys(mode);
	if (newkeys[mode] == NULL)
		fatal("newkeys: no keys for mode %d", mode);
	enc  = &newkeys[mode]->enc;
	mac  = &newkeys[mode]->mac;
	comp = &newkeys[mode]->comp;
	if (mac->md != NULL)
		mac->enabled = 1;
#ifdef	PACKET_DEBUG
	debug("new encryption key:\n");
	data_dump(enc->key, enc->key_len);
	debug("new encryption IV:\n");
	data_dump(enc->iv, enc->block_size);
	debug("new MAC key:\n");
	data_dump(mac->key, mac->key_len);
#endif
	cipher_init(cc, enc->cipher, enc->key, enc->key_len,
	    enc->iv, enc->block_size, crypt_type);
	/* Deleting the keys does not gain extra security */
	/* memset(enc->iv,  0, enc->block_size);
	   memset(enc->key, 0, enc->key_len); */
	if (comp->type != 0 && comp->enabled == 0) {
		packet_init_compression();
		if (mode == MODE_OUT)
			buffer_compress_init_send(6);
		else
			buffer_compress_init_recv();
		comp->enabled = 1;
	}

	/*
	 * In accordance to the RFCs listed below we enforce the key
	 * re-exchange for:
	 * 
	 * - every 1GB of transmitted data if the selected cipher block size
	 *   is less than 16 bytes (3DES, Blowfish)
	 * - every 2^(2*B) cipher blocks transmitted (B is block size in bytes)
	 *   if the cipher block size is greater than or equal to 16 bytes (AES)
	 * - and we never send more than 2^32 SSH packets using the same keys.
	 *   The recommendation of 2^31 packets is not enforced here but in
	 *   packet_need_rekeying(). There is also a hard check in
	 *   packet_send2_wrapped() that we don't send more than 2^32 packets.
	 *
	 * Note that if the SSH_BUG_NOREKEY compatibility flag is set then no
	 * automatic rekeying is performed nor do we enforce the 3rd rule.
	 * This means that we can be always forced by the opposite side to never
	 * initiate automatic key re-exchange. This might change in the future.
	 *
	 * The RekeyLimit option keyword may only enforce more frequent key
	 * renegotiation, never less. For more information on key renegotiation,
	 * see:
	 *
	 * - RFC 4253 (SSH Transport Layer Protocol), section "9. Key
	 *   Re-Exchange"
	 * - RFC 4344 (SSH Transport Layer Encryption Modes), sections "3.
	 *   Rekeying" and "6.1 Rekeying Considerations"
	 */
	if (enc->block_size >= 16)
		*max_blocks = (u_int64_t)1 << (enc->block_size * 2);
	else
		*max_blocks = ((u_int64_t)1 << 30) / enc->block_size;

	if (rekey_limit)
		*max_blocks = MIN(*max_blocks, rekey_limit / enc->block_size);
}

void
free_keys(Newkeys *keys)
{
	Enc *enc;
	Mac *mac;
	Comp *comp;

	enc  = &keys->enc;
	mac  = &keys->mac;
	comp = &keys->comp;
	memset(mac->key, 0, mac->key_len);
	xfree(enc->name);
	xfree(enc->iv);
	xfree(enc->key);
	xfree(mac->name);
	xfree(mac->key);
	xfree(comp->name);
	xfree(keys);
}

/*
 * Process SSH2_MSG_NEWKEYS message. If we are using the engine we must have
 * both SSH2_MSG_NEWKEYS processed before we can finish the engine, fork, and
 * reinitialize the crypto contexts. We can't fork before processing the 2nd
 * message otherwise we couldn't encrypt/decrypt that message at all - note that
 * parent's PKCS#11 sessions are useless after the fork and we must process
 * both SSH2_MSG_NEWKEYS messages using the old keys.
 */
void
process_newkeys(int mode)
{
	/* this function is for the client only */
	if (packet_is_server() != 0)
		return;

	if (will_daemonize == FIRST_NEWKEYS_PROCESSED) {
		debug3("both SSH2_MSG_NEWKEYS processed, will daemonize now");
		cipher_cleanup(&send_context);
		cipher_cleanup(&receive_context);
		pkcs11_engine_finish(e);
		if (daemon(1, 1) < 0) {
			fatal("daemon() failed: %.200s",
			    strerror(errno));
		}
		e = pkcs11_engine_load(e != NULL ? 1 : 0);

		set_newkeys(MODE_OUT);
		set_newkeys(MODE_IN);
		will_daemonize = SECOND_NEWKEYS_PROCESSED;
		packet_send2();
	} else {
		if (will_daemonize == DAEMONIZING_REQUESTED)
			will_daemonize = FIRST_NEWKEYS_PROCESSED;
		else
			set_newkeys(mode);
	}
}

/*
 * Finalize packet in SSH2 format (compress, mac, encrypt, enqueue)
 */
static void
packet_send2_wrapped(void)
{
	u_char type, *cp, *macbuf = NULL;
	u_char padlen, pad;
	u_int packet_length = 0;
	u_int i, len;
	u_int32_t rnd = 0;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;
	int block_size;

	if (newkeys[MODE_OUT] != NULL) {
		enc  = &newkeys[MODE_OUT]->enc;
		mac  = &newkeys[MODE_OUT]->mac;
		comp = &newkeys[MODE_OUT]->comp;
	}
	block_size = enc ? enc->block_size : 8;

	cp = buffer_ptr(&outgoing_packet);
	type = cp[5];

#ifdef PACKET_DEBUG
	debug("plain output packet to be processed (%d bytes):\n",
	    buffer_len(&outgoing_packet));
	buffer_dump(&outgoing_packet);
#endif

	if (comp && comp->enabled) {
		len = buffer_len(&outgoing_packet);
		/* skip header, compress only payload */
		buffer_consume(&outgoing_packet, 5);
		buffer_clear(&compression_buffer);
		buffer_compress(&outgoing_packet, &compression_buffer);
		buffer_clear(&outgoing_packet);
		buffer_append(&outgoing_packet, "\0\0\0\0\0", 5);
		buffer_append(&outgoing_packet, buffer_ptr(&compression_buffer),
		    buffer_len(&compression_buffer));
		DBG(debug("compression: raw %d compressed %d", len,
		    buffer_len(&outgoing_packet)));
	}

	/* sizeof (packet_len + pad_len + payload) */
	len = buffer_len(&outgoing_packet);

	/*
	 * calc size of padding, alloc space, get random data,
	 * minimum padding is 4 bytes
	 */
	padlen = block_size - (len % block_size);
	if (padlen < 4)
		padlen += block_size;
	if (extra_pad) {
		/* will wrap if extra_pad+padlen > 255 */
		extra_pad  = roundup(extra_pad, block_size);
		pad = extra_pad - ((len + padlen) % extra_pad);
		debug3("packet_send2: adding %d (len %d padlen %d extra_pad %d)",
		    pad, len, padlen, extra_pad);
		padlen += pad;
		extra_pad = 0;
	}
	cp = buffer_append_space(&outgoing_packet, padlen);
	if (enc && !send_context.plaintext) {
		/* random padding */
		for (i = 0; i < padlen; i++) {
			if (i % 4 == 0)
				rnd = arc4random();
			cp[i] = rnd & 0xff;
			rnd >>= 8;
		}
	} else {
		/* clear padding */
		memset(cp, 0, padlen);
	}
	/* packet_length includes payload, padding and padding length field */
	packet_length = buffer_len(&outgoing_packet) - 4;
	cp = buffer_ptr(&outgoing_packet);
	PUT_32BIT(cp, packet_length);
	cp[4] = padlen;
	DBG(debug("will send %d bytes (includes padlen %d)",
	    packet_length + 4, padlen));

	/* compute MAC over seqnr and packet(length fields, payload, padding) */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, p_send.seqnr,
		    buffer_ptr(&outgoing_packet),
		    buffer_len(&outgoing_packet));
		DBG(debug("done calc MAC out #%d", p_send.seqnr));
	}
	/* encrypt packet and append to output buffer. */
	cp = buffer_append_space(&output, buffer_len(&outgoing_packet));
	cipher_crypt(&send_context, cp, buffer_ptr(&outgoing_packet),
	    buffer_len(&outgoing_packet));
	/* append unencrypted MAC */
	if (mac && mac->enabled)
		buffer_append(&output, (char *)macbuf, mac->mac_len);
#ifdef PACKET_DEBUG
	debug("encrypted output queue now contains (%d bytes):\n",
	    buffer_len(&output));
	buffer_dump(&output);
#endif
	/* increment sequence number for outgoing packets */
	if (++p_send.seqnr == 0)
		log("outgoing seqnr wraps around");

	/*
	 * RFC 4344: 3.1. First Rekeying Recommendation
	 *
	 * "Because of possible information leakage through the MAC tag after a
	 * key exchange, .... an SSH implementation SHOULD NOT send more than
	 * 2**32 packets before rekeying again."
	 *
	 * The code below is a hard check so that we are sure we don't go across
	 * the suggestion. However, since the largest cipher block size we have
	 * (AES) is 16 bytes we can't reach 2^32 SSH packets encrypted with the
	 * same key while performing periodic rekeying.
	 */
	if (++p_send.packets == 0)
		if (!(datafellows & SSH_BUG_NOREKEY))
			fatal("too many packets encrypted with same key");
	p_send.blocks += (packet_length + 4) / block_size;
	buffer_clear(&outgoing_packet);

	if (type == SSH2_MSG_NEWKEYS) {
		/*
		 * set_newkeys(MODE_OUT) in the client. Note that in the
		 * unprivileged child, set_newkeys() for MODE_OUT are set after
		 * SSH2_MSG_NEWKEYS is read from the monitor and forwarded to
		 * the client side.
		 */
		process_newkeys(MODE_OUT);
	}
}

/*
 * Packets we deal with here are plain until we encrypt them in
 * packet_send2_wrapped().
 *
 * As already mentioned in a comment at process_newkeys() function we must not
 * fork() until both SSH2_MSG_NEWKEYS packets were processed. Until this is done
 * we must queue all packets so that they can be encrypted with the new keys and
 * then sent to the other side. However, what can happen here is that we get
 * SSH2_MSG_NEWKEYS after we sent it. In that situation we must call
 * packet_send2() anyway to empty the queue, and set the rekey flag to the
 * finished state. If we didn't do that we would just hang and enqueue data.
 */
static void
packet_send2(void)
{
	static int rekeying = 0;
	struct packet *p;
	u_char type, *cp;

	if (will_daemonize != SECOND_NEWKEYS_PROCESSED) {
		cp = buffer_ptr(&outgoing_packet);
		type = cp[5];

		/* during rekeying we can only send key exchange messages */
		if (rekeying) {
			if (!((type >= SSH2_MSG_TRANSPORT_MIN) &&
			    (type <= SSH2_MSG_TRANSPORT_MAX))) {
				debug("enqueue a plain packet because rekex in "
				    "progress [type %u]", type);
				p = xmalloc(sizeof(*p));
				p->type = type;
				memcpy(&p->payload, &outgoing_packet, sizeof(Buffer));
				buffer_init(&outgoing_packet);
				TAILQ_INSERT_TAIL(&outgoing, p, next);
				return;
			}
		}

		/* rekeying starts with sending KEXINIT */
		if (type == SSH2_MSG_KEXINIT)
			rekeying = 1;

		packet_send2_wrapped();
	}

	/* after rekex is done we can process the queue of plain packets */
	if (will_daemonize == SECOND_NEWKEYS_PROCESSED ||
	    (will_daemonize == NOT_DAEMONIZING && type == SSH2_MSG_NEWKEYS)) {
		rekeying = 0;
		will_daemonize = NOT_DAEMONIZING;
		while ((p = TAILQ_FIRST(&outgoing)) != NULL) {
			type = p->type;
			debug("dequeuing a plain packet since rekex is over "
			    "[type %u]", type);
			buffer_free(&outgoing_packet);
			memcpy(&outgoing_packet, &p->payload, sizeof(Buffer));
			TAILQ_REMOVE(&outgoing, p, next);
			xfree(p);
			packet_send2_wrapped();
		}
	}
}

void
packet_send(void)
{
	if (compat20)
		packet_send2();
	else
		packet_send1();
	DBG(debug("packet_send done"));
}

/*
 * Waits until a packet has been received, and returns its type.  Note that
 * no other data is processed until this returns, so this function should not
 * be used during the interactive session.
 */

int
packet_read_seqnr(u_int32_t *seqnr_p)
{
	int type, len;
	fd_set *setp;
	char buf[8192];
	DBG(debug("packet_read()"));

	setp = (fd_set *)xmalloc(howmany(connection_in+1, NFDBITS) *
	    sizeof(fd_mask));

	/* Since we are blocking, ensure that all written packets have been sent. */
	packet_write_wait();

	/* Stay in the loop until we have received a complete packet. */
	for (;;) {
		/* Try to read a packet from the buffer. */
		type = packet_read_poll_seqnr(seqnr_p);
		if (!compat20 && (
		    type == SSH_SMSG_SUCCESS
		    || type == SSH_SMSG_FAILURE
		    || type == SSH_CMSG_EOF
		    || type == SSH_CMSG_EXIT_CONFIRMATION))
			packet_check_eom();
		/* If we got a packet, return it. */
		if (type != SSH_MSG_NONE) {
			xfree(setp);
			return type;
		}
		/*
		 * Otherwise, wait for some data to arrive, add it to the
		 * buffer, and try again.
		 */
		memset(setp, 0, howmany(connection_in + 1, NFDBITS) *
		    sizeof(fd_mask));
		FD_SET(connection_in, setp);

		/* Wait for some data to arrive. */
		while (select(connection_in + 1, setp, NULL, NULL, NULL) == -1 &&
		    (errno == EAGAIN || errno == EINTR))
			;

		/* Read data from the socket. */
		len = read(connection_in, buf, sizeof(buf));
		if (len == 0) {
			log("Connection closed by %.200s", get_remote_ipaddr());
			fatal_cleanup();
		}
		if (len < 0)
			fatal("Read from socket failed: %.100s", strerror(errno));
		/* Append it to the buffer. */
		packet_process_incoming(buf, len);
	}
	/* NOTREACHED */
}

int
packet_read(void)
{
	return packet_read_seqnr(NULL);
}

/*
 * Waits until a packet has been received, verifies that its type matches
 * that given, and gives a fatal error and exits if there is a mismatch.
 */

void
packet_read_expect(int expected_type)
{
	int type;

	type = packet_read();
	if (type != expected_type)
		packet_disconnect("Protocol error: expected packet type %d, got %d",
		    expected_type, type);
}

/* Checks if a full packet is available in the data received so far via
 * packet_process_incoming.  If so, reads the packet; otherwise returns
 * SSH_MSG_NONE.  This does not wait for data from the connection.
 *
 * SSH_MSG_DISCONNECT is handled specially here.  Also,
 * SSH_MSG_IGNORE messages are skipped by this function and are never returned
 * to higher levels.
 */

static int
packet_read_poll1(void)
{
	u_int len, padded_len;
	u_char *cp, type;
	u_int checksum, stored_checksum;

	/* Check if input size is less than minimum packet size. */
	if (buffer_len(&input) < 4 + 8)
		return SSH_MSG_NONE;
	/* Get length of incoming packet. */
	cp = buffer_ptr(&input);
	len = GET_32BIT(cp);
	if (len < 1 + 2 + 2 || len > 256 * 1024)
		packet_disconnect("Bad packet length %d.", len);
	padded_len = (len + 8) & ~7;

	/* Check if the packet has been entirely received. */
	if (buffer_len(&input) < 4 + padded_len)
		return SSH_MSG_NONE;

	/* The entire packet is in buffer. */

	/* Consume packet length. */
	buffer_consume(&input, 4);

	/*
	 * Cryptographic attack detector for ssh
	 * (C)1998 CORE-SDI, Buenos Aires Argentina
	 * Ariel Futoransky(futo@core-sdi.com)
	 */
	if (!receive_context.plaintext) {
		switch (detect_attack(buffer_ptr(&input), padded_len, NULL)) {
		case DEATTACK_DETECTED:
			packet_disconnect("crc32 compensation attack: "
			    "network attack detected");
			break;
		case DEATTACK_DOS_DETECTED:
			packet_disconnect("deattack denial of "
			    "service detected");
			break;
		}
	}

	/* Decrypt data to incoming_packet. */
	buffer_clear(&incoming_packet);
	cp = buffer_append_space(&incoming_packet, padded_len);
	cipher_crypt(&receive_context, cp, buffer_ptr(&input), padded_len);

	buffer_consume(&input, padded_len);

#ifdef PACKET_DEBUG
	debug("read_poll plain/full:\n");
	buffer_dump(&incoming_packet);
#endif

	/* Compute packet checksum. */
	checksum = ssh_crc32(buffer_ptr(&incoming_packet),
	    buffer_len(&incoming_packet) - 4);

	/* Skip padding. */
	buffer_consume(&incoming_packet, 8 - len % 8);

	/* Test check bytes. */
	if (len != buffer_len(&incoming_packet))
		packet_disconnect("packet_read_poll1: len %d != buffer_len %d.",
		    len, buffer_len(&incoming_packet));

	cp = (u_char *)buffer_ptr(&incoming_packet) + len - 4;
	stored_checksum = GET_32BIT(cp);
	if (checksum != stored_checksum)
		packet_disconnect("Corrupted check bytes on input.");
	buffer_consume_end(&incoming_packet, 4);

	if (packet_compression) {
		buffer_clear(&compression_buffer);
		buffer_uncompress(&incoming_packet, &compression_buffer);
		buffer_clear(&incoming_packet);
		buffer_append(&incoming_packet, buffer_ptr(&compression_buffer),
		    buffer_len(&compression_buffer));
	}
	type = buffer_get_char(&incoming_packet);
	return type;
}

static int
packet_read_poll2(u_int32_t *seqnr_p)
{
	static u_int packet_length = 0;
	u_int padlen, need;
	u_char *macbuf, *cp, type;
	int maclen, block_size;
	Enc *enc   = NULL;
	Mac *mac   = NULL;
	Comp *comp = NULL;

	if (newkeys[MODE_IN] != NULL) {
		enc  = &newkeys[MODE_IN]->enc;
		mac  = &newkeys[MODE_IN]->mac;
		comp = &newkeys[MODE_IN]->comp;
	}
	maclen = mac && mac->enabled ? mac->mac_len : 0;
	block_size = enc ? enc->block_size : 8;

	if (packet_length == 0) {
		/*
		 * check if input size is less than the cipher block size,
		 * decrypt first block and extract length of incoming packet
		 */
		if (buffer_len(&input) < block_size)
			return SSH_MSG_NONE;
#ifdef PACKET_DEBUG
		debug("encrypted data we have in read queue (%d bytes):\n",
		    buffer_len(&input));
		buffer_dump(&input);
#endif
		buffer_clear(&incoming_packet);
		cp = buffer_append_space(&incoming_packet, block_size);
		cipher_crypt(&receive_context, cp, buffer_ptr(&input),
		    block_size);
		cp = buffer_ptr(&incoming_packet);
		packet_length = GET_32BIT(cp);
		if (packet_length < 1 + 4 || packet_length > 256 * 1024) {
			error("bad packet length %d; i/o counters "
			    "%llu/%llu", packet_length,
			    p_read.blocks * block_size,
			    p_send.blocks * block_size);
			error("decrypted %d bytes follows:\n", block_size);
			buffer_dump(&incoming_packet);
			packet_disconnect("Bad packet length %d, i/o counters "
			    "%llu/%llu.", packet_length,
			    p_read.blocks * block_size,
			    p_send.blocks * block_size);
		}
		DBG(debug("input: packet len %u", packet_length + 4));
		buffer_consume(&input, block_size);
	}
	/* we have a partial packet of block_size bytes */
	need = 4 + packet_length - block_size;
	DBG(debug("partial packet %d, still need %d, maclen %d", block_size,
	    need, maclen));
	if (need % block_size != 0)
		fatal("padding error: need %d block %d mod %d",
		    need, block_size, need % block_size);
	/*
	 * check if the entire packet has been received and
	 * decrypt into incoming_packet
	 */
	if (buffer_len(&input) < need + maclen)
		return SSH_MSG_NONE;
#ifdef PACKET_DEBUG
	debug("in read_poll, the encrypted input queue now contains "
	    "(%d bytes):\n", buffer_len(&input));
	buffer_dump(&input);
#endif
	cp = buffer_append_space(&incoming_packet, need);
	cipher_crypt(&receive_context, cp, buffer_ptr(&input), need);
	buffer_consume(&input, need);
	/*
	 * compute MAC over seqnr and packet,
	 * increment sequence number for incoming packet
	 */
	if (mac && mac->enabled) {
		macbuf = mac_compute(mac, p_read.seqnr,
		    buffer_ptr(&incoming_packet),
		    buffer_len(&incoming_packet));
		if (memcmp(macbuf, buffer_ptr(&input), mac->mac_len) != 0)
			packet_disconnect("Corrupted MAC on input.");
		DBG(debug("MAC #%d ok", p_read.seqnr));
		buffer_consume(&input, mac->mac_len);
	}
	if (seqnr_p != NULL)
		*seqnr_p = p_read.seqnr;
	if (++p_read.seqnr == 0)
		log("incoming seqnr wraps around");

	/* see above for the comment on "First Rekeying Recommendation" */
	if (++p_read.packets == 0)
		if (!(datafellows & SSH_BUG_NOREKEY))
			fatal("too many packets with same key");
	p_read.blocks += (packet_length + 4) / block_size;

	/* get padlen */
	cp = buffer_ptr(&incoming_packet);
	padlen = cp[4];
	DBG(debug("input: padlen %d", padlen));
	if (padlen < 4)
		packet_disconnect("Corrupted padlen %d on input.", padlen);

	/* skip packet size + padlen, discard padding */
	buffer_consume(&incoming_packet, 4 + 1);
	buffer_consume_end(&incoming_packet, padlen);

	DBG(debug("input: len before de-compress %d", buffer_len(&incoming_packet)));
	if (comp && comp->enabled) {
		buffer_clear(&compression_buffer);
		buffer_uncompress(&incoming_packet, &compression_buffer);
		buffer_clear(&incoming_packet);
		buffer_append(&incoming_packet, buffer_ptr(&compression_buffer),
		    buffer_len(&compression_buffer));
		DBG(debug("input: len after de-compress %d",
		    buffer_len(&incoming_packet)));
	}
	/*
	 * get packet type, implies consume.
	 * return length of payload (without type field)
	 */
	type = buffer_get_char(&incoming_packet);
	if (type == SSH2_MSG_NEWKEYS) {
		/*
		 * set_newkeys(MODE_IN) in the client because it doesn't have a
		 * dispatch function for SSH2_MSG_NEWKEYS in contrast to the
		 * server processes. Note that in the unprivileged child,
		 * set_newkeys() for MODE_IN are set in dispatch function
		 * altprivsep_rekey() after SSH2_MSG_NEWKEYS packet is received
		 * from the client.
		 */
		process_newkeys(MODE_IN);
	}

#ifdef PACKET_DEBUG
	debug("decrypted input packet [type %d]:\n", type);
	buffer_dump(&incoming_packet);
#endif
	/* reset for next packet */
	packet_length = 0;
	return type;
}

/*
 * This tries to read a packet from the buffer of received data. Note that it
 * doesn't read() anything from the network socket.
 */
int
packet_read_poll_seqnr(u_int32_t *seqnr_p)
{
	u_int reason, seqnr;
	u_char type;
	char *msg;

	for (;;) {
		if (compat20) {
			type = packet_read_poll2(seqnr_p);
			DBG(debug("received packet type %d", type));
			switch (type) {
			case SSH2_MSG_IGNORE:
				break;
			case SSH2_MSG_DEBUG:
				packet_get_char();
				msg = packet_get_string(NULL);
				debug("Remote: %.900s", msg);
				xfree(msg);
				msg = packet_get_string(NULL);
				xfree(msg);
				break;
			case SSH2_MSG_DISCONNECT:
				reason = packet_get_int();
				msg = packet_get_string(NULL);
				log("Received disconnect from %s: %u: %.400s",
				    get_remote_ipaddr(), reason, msg);
				xfree(msg);
				fatal_cleanup();
				break;
			case SSH2_MSG_UNIMPLEMENTED:
				seqnr = packet_get_int();
				debug("Received SSH2_MSG_UNIMPLEMENTED for %u",
				    seqnr);
				break;
			default:
				return type;
				break;
			}
		} else {
			type = packet_read_poll1();
			DBG(debug("received packet type %d", type));
			switch (type) {
			case SSH_MSG_IGNORE:
				break;
			case SSH_MSG_DEBUG:
				msg = packet_get_string(NULL);
				debug("Remote: %.900s", msg);
				xfree(msg);
				break;
			case SSH_MSG_DISCONNECT:
				msg = packet_get_string(NULL);
				log("Received disconnect from %s: %.400s",
				    get_remote_ipaddr(), msg);
				fatal_cleanup();
				xfree(msg);
				break;
			default:
				return type;
				break;
			}
		}
	}
}

int
packet_read_poll(void)
{
	return packet_read_poll_seqnr(NULL);
}

/*
 * Buffers the given amount of input characters.  This is intended to be used
 * together with packet_read_poll.
 */

void
packet_process_incoming(const char *buf, u_int len)
{
	buffer_append(&input, buf, len);
}

/* Returns a character from the packet. */

u_int
packet_get_char(void)
{
	char ch;

	buffer_get(&incoming_packet, &ch, 1);
	return (u_char) ch;
}

/* Returns an integer from the packet data. */

u_int
packet_get_int(void)
{
	return buffer_get_int(&incoming_packet);
}

/*
 * Returns an arbitrary precision integer from the packet data.  The integer
 * must have been initialized before this call.
 */

void
packet_get_bignum(BIGNUM * value)
{
	buffer_get_bignum(&incoming_packet, value);
}

void
packet_get_bignum2(BIGNUM * value)
{
	buffer_get_bignum2(&incoming_packet, value);
}

void *
packet_get_raw(u_int *length_ptr)
{
	u_int bytes = buffer_len(&incoming_packet);

	if (length_ptr != NULL)
		*length_ptr = bytes;
	return buffer_ptr(&incoming_packet);
}

int
packet_remaining(void)
{
	return buffer_len(&incoming_packet);
}

/*
 * Returns a string from the packet data.  The string is allocated using
 * xmalloc; it is the responsibility of the calling program to free it when
 * no longer needed.  The length_ptr argument may be NULL, or point to an
 * integer into which the length of the string is stored.
 */

void *
packet_get_string(u_int *length_ptr)
{
	return buffer_get_string(&incoming_packet, length_ptr);
}
char *
packet_get_ascii_cstring()
{
	return buffer_get_ascii_cstring(&incoming_packet);
}
u_char *
packet_get_utf8_cstring()
{
	return buffer_get_utf8_cstring(&incoming_packet);
}

/*
 * Sends a diagnostic message from the server to the client.  This message
 * can be sent at any time (but not while constructing another message). The
 * message is printed immediately, but only if the client is being executed
 * in verbose mode.  These messages are primarily intended to ease debugging
 * authentication problems.   The length of the formatted message must not
 * exceed 1024 bytes.  This will automatically call packet_write_wait.
 */

void
packet_send_debug(const char *fmt,...)
{
	char buf[1024];
	va_list args;

	if (compat20 && (datafellows & SSH_BUG_DEBUG))
		return;

	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), gettext(fmt), args);
	va_end(args);

#ifdef ALTPRIVSEP
	/* shouldn't happen */
	if (packet_monitor) {
		debug("packet_send_debug: %s", buf);
		return;
	}
#endif /* ALTPRIVSEP */

	if (compat20) {
		packet_start(SSH2_MSG_DEBUG);
		packet_put_char(0);	/* bool: always display */
		packet_put_cstring(buf);
		packet_put_cstring("");
	} else {
		packet_start(SSH_MSG_DEBUG);
		packet_put_cstring(buf);
	}
	packet_send();
	packet_write_wait();
}

/*
 * Logs the error plus constructs and sends a disconnect packet, closes the
 * connection, and exits.  This function never returns. The error message
 * should not contain a newline.  The length of the formatted message must
 * not exceed 1024 bytes.
 */

void
packet_disconnect(const char *fmt,...)
{
	char buf[1024];
	va_list args;
	static int disconnecting = 0;

	if (disconnecting)	/* Guard against recursive invocations. */
		fatal("packet_disconnect called recursively.");
	disconnecting = 1;

	/*
	 * Format the message.  Note that the caller must make sure the
	 * message is of limited size.
	 */
	va_start(args, fmt);
	vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

#ifdef ALTPRIVSEP
	/*
	 * If we packet_disconnect() in the monitor the fatal cleanups will take
	 * care of the child.  See main() in sshd.c.  We don't send the packet
	 * disconnect message here because: a) the child might not be looking
	 * for it and b) because we don't really know if the child is compat20
	 * or not as we lost that information when packet_set_monitor() was
	 * called.
	 */
	if (packet_monitor)
		goto close_stuff;
#endif /* ALTPRIVSEP */

	/* Send the disconnect message to the other side, and wait for it to get sent. */
	if (compat20) {
		packet_start(SSH2_MSG_DISCONNECT);
		packet_put_int(SSH2_DISCONNECT_PROTOCOL_ERROR);
		packet_put_cstring(buf);
		packet_put_cstring("");
	} else {
		packet_start(SSH_MSG_DISCONNECT);
		packet_put_cstring(buf);
	}
	packet_send();
	packet_write_wait();

#ifdef ALTPRIVSEP
close_stuff:
#endif /* ALTPRIVSEP */
	/* Stop listening for connections. */
	channel_close_all();

	/* Close the connection. */
	packet_close();

	/* Display the error locally and exit. */
	log("Disconnecting: %.100s", buf);
	fatal_cleanup();
}

/* Checks if there is any buffered output, and tries to write some of the output. */

void
packet_write_poll(void)
{
	int len = buffer_len(&output);

	if (len > 0) {
		len = write(connection_out, buffer_ptr(&output), len);
		if (len <= 0) {
			if (errno == EAGAIN)
				return;
			else
				fatal("Write failed: %.100s", strerror(errno));
		}
#ifdef PACKET_DEBUG
		debug("in packet_write_poll, %d bytes just sent to the "
		    "remote side", len);
#endif
		buffer_consume(&output, len);
	}
}

/*
 * Calls packet_write_poll repeatedly until all pending output data has been
 * written.
 */

void
packet_write_wait(void)
{
	fd_set *setp;

	setp = (fd_set *)xmalloc(howmany(connection_out + 1, NFDBITS) *
	    sizeof(fd_mask));
	packet_write_poll();
	while (packet_have_data_to_write()) {
		memset(setp, 0, howmany(connection_out + 1, NFDBITS) *
		    sizeof(fd_mask));
		FD_SET(connection_out, setp);
		while (select(connection_out + 1, NULL, setp, NULL, NULL) == -1 &&
		    (errno == EAGAIN || errno == EINTR))
			;
		packet_write_poll();
	}
	xfree(setp);
}

/* Returns true if there is buffered data to write to the connection. */

int
packet_have_data_to_write(void)
{
	return buffer_len(&output) != 0;
}

/* Returns true if there is not too much data to write to the connection. */

int
packet_not_very_much_data_to_write(void)
{
	if (interactive_mode)
		return buffer_len(&output) < 16384;
	else
		return buffer_len(&output) < 128 * 1024;
}

/* Informs that the current session is interactive.  Sets IP flags for that. */

void
packet_set_interactive(int interactive)
{
	static int called = 0;
#if defined(IP_TOS) && !defined(IP_TOS_IS_BROKEN)
	int lowdelay = IPTOS_LOWDELAY;
	int throughput = IPTOS_THROUGHPUT;
#endif

	if (called)
		return;
	called = 1;

	/* Record that we are in interactive mode. */
	interactive_mode = interactive;

	/* Only set socket options if using a socket.  */
	if (!packet_connection_is_on_socket())
		return;
	/*
	 * IPTOS_LOWDELAY and IPTOS_THROUGHPUT are IPv4 only
	 */
	if (interactive) {
		/*
		 * Set IP options for an interactive connection.  Use
		 * IPTOS_LOWDELAY and TCP_NODELAY.
		 */
#if defined(IP_TOS) && !defined(IP_TOS_IS_BROKEN)
		if (packet_connection_is_ipv4()) {
			if (setsockopt(connection_in, IPPROTO_IP, IP_TOS,
			    &lowdelay, sizeof(lowdelay)) < 0)
				error("setsockopt IPTOS_LOWDELAY: %.100s",
				    strerror(errno));
		}
#endif
		set_nodelay(connection_in);
	}
#if defined(IP_TOS) && !defined(IP_TOS_IS_BROKEN)
	else if (packet_connection_is_ipv4()) {
		/*
		 * Set IP options for a non-interactive connection.  Use
		 * IPTOS_THROUGHPUT.
		 */
		if (setsockopt(connection_in, IPPROTO_IP, IP_TOS, &throughput,
		    sizeof(throughput)) < 0)
			error("setsockopt IPTOS_THROUGHPUT: %.100s", strerror(errno));
	}
#endif
}

/* Returns true if the current connection is interactive. */

int
packet_is_interactive(void)
{
	return interactive_mode;
}

int
packet_set_maxsize(int s)
{
	static int called = 0;

	if (called) {
		log("packet_set_maxsize: called twice: old %d new %d",
		    max_packet_size, s);
		return -1;
	}
	if (s < 4 * 1024 || s > 1024 * 1024) {
		log("packet_set_maxsize: bad size %d", s);
		return -1;
	}
	called = 1;
	debug("packet_set_maxsize: setting to %d", s);
	max_packet_size = s;
	return s;
}

/* roundup current message to pad bytes */
void
packet_add_padding(u_char pad)
{
	extra_pad = pad;
}

/*
 * 9.2.  Ignored Data Message
 *
 *   byte      SSH_MSG_IGNORE
 *   string    data
 *
 * All implementations MUST understand (and ignore) this message at any
 * time (after receiving the protocol version). No implementation is
 * required to send them. This message can be used as an additional
 * protection measure against advanced traffic analysis techniques.
 */
void
packet_send_ignore(int nbytes)
{
	u_int32_t rnd = 0;
	int i;

#ifdef ALTPRIVSEP
	/* shouldn't happen -- see packet_set_monitor() */
	if (packet_monitor)
		return;
#endif /* ALTPRIVSEP */

	packet_start(compat20 ? SSH2_MSG_IGNORE : SSH_MSG_IGNORE);
	packet_put_int(nbytes);
	for (i = 0; i < nbytes; i++) {
		if (i % 4 == 0)
			rnd = arc4random();
		packet_put_char((u_char)rnd & 0xff);
		rnd >>= 8;
	}
}

#define MAX_PACKETS	(1U<<31)
int
packet_need_rekeying(void)
{
	if (datafellows & SSH_BUG_NOREKEY)
		return 0;
	return
	    (p_send.packets > MAX_PACKETS) ||
	    (p_read.packets > MAX_PACKETS) ||
	    (max_blocks_out && (p_send.blocks > max_blocks_out)) ||
	    (max_blocks_in  && (p_read.blocks > max_blocks_in));
}

void
packet_set_rekey_limit(u_int32_t bytes)
{
	rekey_limit = bytes;
}

#ifdef ALTPRIVSEP
void
packet_set_server(void)
{
	packet_server = 1;
}

int
packet_is_server(void)
{
	return (packet_server);
}

void
packet_set_monitor(int pipe)
{
	int dup_fd;

	packet_server = 1;
	packet_monitor = 1;

	/*
	 * Awful hack follows.
	 *
	 * For SSHv1 the monitor does not process any SSHv1 packets, only
	 * ALTPRIVSEP packets.  We take advantage of that here to keep changes
	 * to packet.c to a minimum by using the SSHv2 binary packet protocol,
	 * with cipher "none," mac "none" and compression alg "none," as the
	 * basis for the monitor protocol.  And so to force packet.c to treat
	 * packets as SSHv2 we force compat20 == 1 here.
	 *
	 * For completeness and to help future developers catch this we also
	 * force compat20 == 1 in the monitor loop, in serverloop.c.
	 */
	compat20 = 1;

	/*
	 * NOTE:  Assumptions below!
	 *
	 *  - lots of packet.c code assumes that (connection_in ==
	 *  connection_out) -> connection is socket
	 *
	 *  - packet_close() does not shutdown() the connection fildes
	 *  if connection_in != connection_out
	 *
	 *  - other code assumes the connection is a socket if
	 *  connection_in == connection_out
	 */

	if ((dup_fd = dup(pipe)) < 0)
		fatal("Monitor failed to start: %s", strerror(errno));

	/*
	 * make sure that the monitor's child's socket is not shutdown(3SOCKET)
	 * when we packet_close(). Setting connection_out to -1 will take care
	 * of that.
	 */
	if (packet_connection_is_on_socket())
		connection_out = -1;

	/*
	 * Now clean up the state related to the server socket. As a side
	 * effect, we also clean up existing cipher contexts that were
	 * initialized with 'none' cipher in packet_set_connection(). That
	 * function was called in the child server process shortly after the
	 * master SSH process forked. However, all of that is reinialized again
	 * by another packet_set_connection() call right below.
	 */
	packet_close();

	/*
	 * Now make the monitor pipe look like the ssh connection which means
	 * that connection_in and connection_out will be set to the
	 * communication pipe descriptors.
	 */
	packet_set_connection(pipe, dup_fd);
}

/*
 * We temporarily need to set connection_in and connection_out descriptors so
 * that we can make use of existing code that gets the IP address and hostname
 * of the peer to write a login/logout record. It's not nice but we would have
 * to change more code when implementing the PKCS#11 engine support.
 */
void
packet_set_fds(int fd, int restore)
{
	static int stored_fd;

	if (stored_fd == 0 && restore == 0) {
		debug3("packet_set_fds: saving %d, installing %d",
		    connection_in, fd);
		stored_fd = connection_in;
		/* we don't have a socket in inetd mode */
		if (fd != -1)
			connection_in = connection_out = fd;
		return;
	}

	if (restore == 1) {
		debug3("restoring %d to connection_in/out", stored_fd);
		connection_in = connection_out = stored_fd;
	}
}

int
packet_is_monitor(void)
{
	return (packet_monitor);
}
#endif /* ALTPRIVSEP */
