/*-
 * Copyright (c) 2015 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
 * Copyright (c) 2015 Nahanni Systems Inc.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/socket.h>
#include <netinet/in.h>

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bhyvegc.h"
#include "console.h"
#include "rfb.h"

struct rfb_softc {
	int		sfd;
	pthread_t	tid;

	int		width, height;

	bool		enc_raw_ok;
	bool		enc_resize_ok;
};

struct rfb_pixfmt {
	uint8_t		bpp;
	uint8_t		depth;
	uint8_t		bigendian;
	uint8_t		truecolor;
	uint16_t	red_max;
	uint16_t	green_max;
	uint16_t	blue_max;
	uint8_t		red_shift;
	uint8_t		green_shift;
	uint8_t		blue_shift;
	uint8_t		pad[3];
};

struct rfb_srvr_info {
	uint16_t		width;
	uint16_t		height;
	struct rfb_pixfmt	pixfmt;
	uint32_t		namelen;
};

struct rfb_pixfmt_msg {
	uint8_t			type;
	uint8_t			pad[3];
	struct rfb_pixfmt	pixfmt;
};

#define	RFB_ENCODING_RAW		0
#define	RFB_ENCODING_RESIZE		-223

struct rfb_enc_msg {
	uint8_t		type;
	uint8_t		pad;
	uint16_t	numencs;
};

struct rfb_updt_msg {
	uint8_t		type;
	uint8_t		incremental;
	uint16_t	x;
	uint16_t	y;
	uint16_t	width;
	uint16_t	height;
};

struct rfb_key_msg {
	uint8_t		type;
	uint8_t		down;
	uint16_t	pad;
	uint32_t	code;
};

struct rfb_ptr_msg {
	uint8_t		type;
	uint8_t		button;
	uint16_t	x;
	uint16_t	y;
};

struct rfb_srvr_updt_msg {
	uint8_t		type;
	uint8_t		pad;
	uint16_t	numrects;
};

struct rfb_srvr_rect_hdr {
	uint16_t	x;
	uint16_t	y;
	uint16_t	width;
	uint16_t	height;
	uint32_t	encoding;
};

static void
rfb_send_server_init_msg(int cfd)
{
	struct bhyvegc_image *gc_image;
	struct rfb_srvr_info sinfo;
	int len;

	gc_image = console_get_image();

	sinfo.width = ntohs(gc_image->width);
	sinfo.height = ntohs(gc_image->height);
	sinfo.pixfmt.bpp = 32;
	sinfo.pixfmt.depth = 32;
	sinfo.pixfmt.bigendian = 0;
	sinfo.pixfmt.truecolor = 1;
	sinfo.pixfmt.red_max = ntohs(255);
	sinfo.pixfmt.green_max = ntohs(255);
	sinfo.pixfmt.blue_max = ntohs(255);
	sinfo.pixfmt.red_shift = 16;
	sinfo.pixfmt.green_shift = 8;
	sinfo.pixfmt.blue_shift = 0;
	sinfo.namelen = ntohl(strlen("bhyve"));
	len = write(cfd, &sinfo, sizeof(sinfo));
	len = write(cfd, "bhyve", strlen("bhyve"));
}

static void
rfb_send_resize_update_msg(struct rfb_softc *rc, int cfd)
{
	struct rfb_srvr_updt_msg supdt_msg;
        struct rfb_srvr_rect_hdr srect_hdr;

	/* Number of rectangles: 1 */
	supdt_msg.type = 0;
	supdt_msg.pad = 0;
	supdt_msg.numrects = ntohs(1);
	write(cfd, &supdt_msg, sizeof(struct rfb_srvr_updt_msg));

	/* Rectangle header */
	srect_hdr.x = ntohs(0);
	srect_hdr.y = ntohs(0);
	srect_hdr.width = ntohs(rc->width);
	srect_hdr.height = ntohs(rc->height);
	srect_hdr.encoding = ntohl(RFB_ENCODING_RESIZE);
	write(cfd, &srect_hdr, sizeof(struct rfb_srvr_rect_hdr));
}

static void
rfb_recv_set_pixfmt_msg(struct rfb_softc *rc, int cfd)
{
	struct rfb_pixfmt_msg pixfmt_msg;
	int len;

	len = read(cfd, ((void *)&pixfmt_msg) + 1, sizeof(pixfmt_msg) - 1);
}


static void
rfb_recv_set_encodings_msg(struct rfb_softc *rc, int cfd)
{
	struct rfb_enc_msg enc_msg;
	int len, i;
	uint32_t encoding;

	assert((sizeof(enc_msg) - 1) == 3);
	len = read(cfd, ((void *)&enc_msg) + 1, sizeof(enc_msg) - 1);

	for (i = 0; i < ntohs(enc_msg.numencs); i++) {
		len = read(cfd, &encoding, sizeof(encoding));
		switch (ntohl(encoding)) {
		case RFB_ENCODING_RAW:
			rc->enc_raw_ok = true;
			break;
		case RFB_ENCODING_RESIZE:
			rc->enc_resize_ok = true;
			break;
		}
	}
}

static void
rfb_resize_update(struct rfb_softc *rc, int fd)
{
	struct rfb_srvr_updt_msg supdt_msg;
        struct rfb_srvr_rect_hdr srect_hdr;

	/* Number of rectangles: 1 */
	supdt_msg.type = 0;
	supdt_msg.pad = 0;
	supdt_msg.numrects = ntohs(1);
	write(fd, &supdt_msg, sizeof (struct rfb_srvr_updt_msg));

	/* Rectangle header */
	srect_hdr.x = ntohs(0);
	srect_hdr.y = ntohs(0);
	srect_hdr.width = ntohs(rc->width);
	srect_hdr.height = ntohs(rc->height);
	srect_hdr.encoding = ntohl(RFB_ENCODING_RESIZE);
	write(fd, &srect_hdr, sizeof (struct rfb_srvr_rect_hdr));
}

static void
rfb_recv_update_msg(struct rfb_softc *rc, int cfd)
{
	struct rfb_updt_msg updt_msg;
	struct rfb_srvr_updt_msg supdt_msg;
        struct rfb_srvr_rect_hdr srect_hdr;
	struct bhyvegc_image *gc_image;
	int len;

	len = read(cfd, ((void *)&updt_msg) + 1 , sizeof(updt_msg) - 1);

	console_refresh();
	gc_image = console_get_image();

	if (rc->width != gc_image->width || rc->height != gc_image->height) {
		rc->width = gc_image->width;
		rc->height = gc_image->height;
		rfb_send_resize_update_msg(rc, cfd);
	}

	/*
	 * Send the whole thing
	 */
	/* Number of rectangles: 1 */
	supdt_msg.type = 0;
	supdt_msg.pad = 0;
	supdt_msg.numrects = ntohs(1);
	write(cfd, &supdt_msg, sizeof(struct rfb_srvr_updt_msg));

	/* Rectangle header */
	srect_hdr.x = ntohs(0);
	srect_hdr.y = ntohs(0);
	srect_hdr.width = ntohs(gc_image->width);
	srect_hdr.height = ntohs(gc_image->height);
	srect_hdr.encoding = ntohl(0);	/* raw */
	write(cfd, &srect_hdr, sizeof(struct rfb_srvr_rect_hdr));

	write(cfd, gc_image->data, gc_image->width * gc_image->height *
	    sizeof(uint32_t));
}

static void
rfb_recv_key_msg(struct rfb_softc *rc, int cfd)
{
	struct rfb_key_msg key_msg;
	int len;

	len = read(cfd, ((void *)&key_msg) + 1, sizeof(key_msg) - 1);

	console_key_event(key_msg.down, ntohl(key_msg.code));
}

static void
rfb_recv_ptr_msg(struct rfb_softc *rc, int cfd)
{
	struct rfb_ptr_msg ptr_msg;
	int len;

	len = read(cfd, ((void *)&ptr_msg) + 1, sizeof(ptr_msg) - 1);

	console_ptr_event(ptr_msg.button, ntohs(ptr_msg.x), ntohs(ptr_msg.y));
}

void
rfb_handle(struct rfb_softc *rc, int cfd)
{
	const char *vbuf = "RFB 003.008\n";
	unsigned char buf[80];
	int len;
        uint32_t sres;

	/* 1a. Send server version */
	printf("server vers write: (%s), %d bytes\n", vbuf, (int) strlen(vbuf));
	write(cfd, vbuf, strlen(vbuf));

	/* 1b. Read client version */
	len = read(cfd, buf, sizeof(buf));

	/* 2a. Send security type 'none' */
	buf[0] = 1;
	buf[1] = 1; /* none */
	write(cfd, buf, 2);

	/* 2b. Read agreed security type */
	len = read(cfd, buf, 1);

	/* 2c. Write back a status of 0 */
	sres = 0;
	write(cfd, &sres, 4);

	/* 3a. Read client shared-flag byte */
	len = read(cfd, buf, 1);

	/* 4a. Write server-init info */
	rfb_send_server_init_msg(cfd);

        /* Now read in client requests. 1st byte identifies type */
	for (;;) {
		len = read(cfd, buf, 1);
		if (len <= 0) {
			printf("exiting\n");
			break;
		}

		switch (buf[0]) {
		case 0:
			rfb_recv_set_pixfmt_msg(rc, cfd);
			break;
		case 2:
			rfb_recv_set_encodings_msg(rc, cfd);
			break;
		case 3:
			rfb_recv_update_msg(rc, cfd);
			break;
		case 4:
			rfb_recv_key_msg(rc, cfd);
			break;
		case 5:
			rfb_recv_ptr_msg(rc, cfd);
			break;
		default:
			printf("unknown client code!\n");
			exit(1);
		}
	}
}

static void *
rfb_thr(void *arg)
{
	struct rfb_softc *rc;
	sigset_t set;

	int cfd;

	rc = arg;

	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
		perror("pthread_sigmask");
		return (NULL);
	}

	for (;;) {
		cfd = accept(rc->sfd, NULL, NULL);
		rfb_handle(rc, cfd);
	}

	/* NOTREACHED */
	return (NULL);
}

int
rfb_init(int port)
{
	struct rfb_softc *rc;
	struct sockaddr_in sin;
	int on = 1;

	rc = calloc(1, sizeof(struct rfb_softc));

	rc->sfd = socket(AF_INET, SOCK_STREAM, 0);
	if (rc->sfd < 0) {
		perror("socket");
		return (-1);
	}

	setsockopt(rc->sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

#ifdef	__FreeBSD__
	sin.sin_len = sizeof(sin);
#endif
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);
	if (bind(rc->sfd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		perror("bind");
		return (-1);
	}

	if (listen(rc->sfd, 1) < 0) {
		perror("listen");
		return (-1);
	}

	pthread_create(&rc->tid, NULL, rfb_thr, rc);

	return (0);
}
