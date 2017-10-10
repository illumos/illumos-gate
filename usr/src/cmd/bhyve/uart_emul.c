/*-
 * Copyright (c) 2012 NetApp, Inc.
 * Copyright (c) 2013 Neel Natu <neel@freebsd.org>
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: head/usr.sbin/bhyve/uart_emul.c 257293 2013-10-29 00:18:11Z neel $
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
 * Copyright 2015 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD: head/usr.sbin/bhyve/uart_emul.c 257293 2013-10-29 00:18:11Z neel $");

#include <sys/types.h>
#include <dev/ic/ns16550.h>

#ifndef	__FreeBSD__
#include <sys/socket.h>
#include <sys/stat.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <termios.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#ifndef	__FreeBSD__
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#endif

#ifndef	__FreeBSD__
#include <bhyve.h>

#include "bhyverun.h"
#endif
#ifdef	__FreeBSD__
#include "mevent.h"
#endif
#include "uart_emul.h"

#define	COM1_BASE	0x3F8
#define	COM1_IRQ	4
#define	COM2_BASE      	0x2F8
#define COM2_IRQ	3

#define	DEFAULT_RCLK	1843200
#define	DEFAULT_BAUD	9600

#define	FCR_RX_MASK	0xC0

#define	MCR_OUT1	0x04
#define	MCR_OUT2	0x08

#define	MSR_DELTA_MASK	0x0f

#ifndef REG_SCR
#define REG_SCR		com_scr
#endif

#define	FIFOSZ	16

static bool uart_stdio;		/* stdio in use for i/o */
#ifndef	__FreeBSD__
static bool uart_bcons;		/* bhyveconsole in use for i/o */
#endif

static struct {
	int	baseaddr;
	int	irq;
	bool	inuse;
} uart_lres[] = {
	{ COM1_BASE, COM1_IRQ, false},
	{ COM2_BASE, COM2_IRQ, false},
};

#define	UART_NLDEVS	(sizeof(uart_lres) / sizeof(uart_lres[0]))

struct fifo {
	uint8_t	buf[FIFOSZ];
	int	rindex;		/* index to read from */
	int	windex;		/* index to write to */
	int	num;		/* number of characters in the fifo */
	int	size;		/* size of the fifo */
};

struct uart_softc {
	pthread_mutex_t mtx;	/* protects all softc elements */
	uint8_t data;		/* Data register (R/W) */
	uint8_t ier;		/* Interrupt enable register (R/W) */
	uint8_t lcr;		/* Line control register (R/W) */
	uint8_t mcr;		/* Modem control register (R/W) */
	uint8_t lsr;		/* Line status register (R/W) */
	uint8_t msr;		/* Modem status register (R/W) */
	uint8_t fcr;		/* FIFO control register (W) */
	uint8_t scr;		/* Scratch register (R/W) */

	uint8_t dll;		/* Baudrate divisor latch LSB */
	uint8_t dlh;		/* Baudrate divisor latch MSB */

	struct fifo rxfifo;

	bool	opened;
	bool	stdio;
#ifndef	__FreeBSD__
	bool	bcons;
	struct {
		pid_t	clipid;
		int	clifd;		/* console client unix domain socket */
		int	servfd;		/* console server unix domain socket */
	} usc_bcons;
#endif

	bool	thre_int_pending;	/* THRE interrupt pending */

	void	*arg;
	uart_intr_func_t intr_assert;
	uart_intr_func_t intr_deassert;
};

#ifdef	__FreeBSD__
static void uart_drain(int fd, enum ev_type ev, void *arg);
#else
static void uart_tty_drain(struct uart_softc *sc);
static int uart_bcons_drain(struct uart_softc *sc);
#endif

static struct termios tio_orig, tio_new;	/* I/O Terminals */

static void
ttyclose(void)
{

	tcsetattr(STDIN_FILENO, TCSANOW, &tio_orig);
}

static void
ttyopen(void)
{

	tcgetattr(STDIN_FILENO, &tio_orig);

	tio_new = tio_orig;
	cfmakeraw(&tio_new);
	tcsetattr(STDIN_FILENO, TCSANOW, &tio_new);

	atexit(ttyclose);
}

static bool
tty_char_available(void)
{
	fd_set rfds;
	struct timeval tv;

	FD_ZERO(&rfds);
	FD_SET(STDIN_FILENO, &rfds);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	if (select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv) > 0 ) {
		return (true);
	} else {
		return (false);
	}
}

static int
ttyread(void)
{
	char rb;

	if (tty_char_available()) {
		read(STDIN_FILENO, &rb, 1);
		return (rb & 0xff);
	} else {
		return (-1);
	}
}

static void
ttywrite(unsigned char wb)
{

	(void)write(STDIN_FILENO, &wb, 1);
}

#ifndef	__FreeBSD__
static void
bconswrite(struct uart_softc *sc, unsigned char wb)
{
	(void) write(sc->usc_bcons.clifd, &wb, 1);
}
#endif

static void
fifo_reset(struct fifo *fifo, int size)
{
	bzero(fifo, sizeof(struct fifo));
	fifo->size = size;
}

static int
fifo_putchar(struct fifo *fifo, uint8_t ch)
{

	if (fifo->num < fifo->size) {
		fifo->buf[fifo->windex] = ch;
		fifo->windex = (fifo->windex + 1) % fifo->size;
		fifo->num++;
		return (0);
	} else
		return (-1);
}

static int
fifo_getchar(struct fifo *fifo)
{
	int c;

	if (fifo->num > 0) {
		c = fifo->buf[fifo->rindex];
		fifo->rindex = (fifo->rindex + 1) % fifo->size;
		fifo->num--;
		return (c);
	} else
		return (-1);
}

static int
fifo_numchars(struct fifo *fifo)
{

	return (fifo->num);
}

static int
fifo_available(struct fifo *fifo)
{

	return (fifo->num < fifo->size);
}

static void
uart_opentty(struct uart_softc *sc)
{
#ifdef	__FreeBSD__
	struct mevent *mev;
#endif

	assert(!sc->opened && sc->stdio);

	ttyopen();
#ifdef	__FreeBSD__
	mev = mevent_add(STDIN_FILENO, EVF_READ, uart_drain, sc);
	assert(mev);
#endif
}

/*
 * The IIR returns a prioritized interrupt reason:
 * - receive data available
 * - transmit holding register empty
 * - modem status change
 *
 * Return an interrupt reason if one is available.
 */
static int
uart_intr_reason(struct uart_softc *sc)
{

	if ((sc->lsr & LSR_OE) != 0 && (sc->ier & IER_ERLS) != 0)
		return (IIR_RLS);
	else if (fifo_numchars(&sc->rxfifo) > 0 && (sc->ier & IER_ERXRDY) != 0)
		return (IIR_RXTOUT);
	else if (sc->thre_int_pending && (sc->ier & IER_ETXRDY) != 0)
		return (IIR_TXRDY);
	else if ((sc->msr & MSR_DELTA_MASK) != 0 && (sc->ier & IER_EMSC) != 0)
		return (IIR_MLSC);
	else
		return (IIR_NOPEND);
}

static void
uart_reset(struct uart_softc *sc)
{
	uint16_t divisor;

	divisor = DEFAULT_RCLK / DEFAULT_BAUD / 16;
	sc->dll = divisor;
	sc->dlh = divisor >> 16;

	fifo_reset(&sc->rxfifo, 1);	/* no fifo until enabled by software */
}

/*
 * Toggle the COM port's intr pin depending on whether or not we have an
 * interrupt condition to report to the processor.
 */
static void
uart_toggle_intr(struct uart_softc *sc)
{
	uint8_t intr_reason;

	intr_reason = uart_intr_reason(sc);

	if (intr_reason == IIR_NOPEND)
		(*sc->intr_deassert)(sc->arg);
	else
		(*sc->intr_assert)(sc->arg);
}

#ifdef	__FreeBSD__
static void
uart_drain(int fd, enum ev_type ev, void *arg)
{
	struct uart_softc *sc;
	int ch;

	sc = arg;

	assert(fd == STDIN_FILENO);
	assert(ev == EVF_READ);

	/*
	 * This routine is called in the context of the mevent thread
	 * to take out the softc lock to protect against concurrent
	 * access from a vCPU i/o exit
	 */
	pthread_mutex_lock(&sc->mtx);

	if ((sc->mcr & MCR_LOOPBACK) != 0) {
		(void) ttyread();
	} else {
		while (fifo_available(&sc->rxfifo) &&
		       ((ch = ttyread()) != -1)) {
			fifo_putchar(&sc->rxfifo, ch);
		}
		uart_toggle_intr(sc);
	}

	pthread_mutex_unlock(&sc->mtx);
}
#else
static void
uart_tty_drain(struct uart_softc *sc)
{
	int ch;

	/*
	 * Take the softc lock to protect against concurrent
	 * access from a vCPU i/o exit
	 */
	pthread_mutex_lock(&sc->mtx);

	if ((sc->mcr & MCR_LOOPBACK) != 0) {
		(void) ttyread();
	} else {
		while (fifo_available(&sc->rxfifo) &&
		       ((ch = ttyread()) != -1)) {
			fifo_putchar(&sc->rxfifo, ch);
		}
		uart_toggle_intr(sc);
	}

	pthread_mutex_unlock(&sc->mtx);
}

static int
uart_bcons_drain(struct uart_softc *sc)
{
	char ch;
	int nbytes;
	int ret = 0;

	/*
	 * Take the softc lock to protect against concurrent
	 * access from a vCPU i/o exit
	 */
	pthread_mutex_lock(&sc->mtx);

	if ((sc->mcr & MCR_LOOPBACK) != 0) {
		(void) read(sc->usc_bcons.clifd, &ch, 1);
	} else {
		for (;;) {
			nbytes = read(sc->usc_bcons.clifd, &ch, 1);
			if (nbytes == 0) {
				ret = 1;
				break;
			}
			if (nbytes == -1 &&
			    errno != EINTR && errno != EAGAIN) {
				ret = -1;
				break;
			}
			if (nbytes == -1) {
				break;
			}

			if (fifo_available(&sc->rxfifo)) {
				fifo_putchar(&sc->rxfifo, ch);
			}
		}
		uart_toggle_intr(sc);
	}

	pthread_mutex_unlock(&sc->mtx);

	return (ret);
}
#endif

void
uart_write(struct uart_softc *sc, int offset, uint8_t value)
{
	int fifosz;
	uint8_t msr;

	pthread_mutex_lock(&sc->mtx);

	/* Open terminal */
	if (!sc->opened && sc->stdio) {
		uart_opentty(sc);
		sc->opened = true;
	}

	/*
	 * Take care of the special case DLAB accesses first
	 */
	if ((sc->lcr & LCR_DLAB) != 0) {
		if (offset == REG_DLL) {
			sc->dll = value;
			goto done;
		}

		if (offset == REG_DLH) {
			sc->dlh = value;
			goto done;
		}
	}

        switch (offset) {
	case REG_DATA:
		if (sc->mcr & MCR_LOOPBACK) {
			if (fifo_putchar(&sc->rxfifo, value) != 0)
				sc->lsr |= LSR_OE;
		} else if (sc->stdio) {
			ttywrite(value);
#ifndef	__FreeBSD__
		} else if (sc->bcons) {
				bconswrite(sc, value);
#endif
		} /* else drop on floor */
		sc->thre_int_pending = true;
		break;
	case REG_IER:
		/*
		 * Apply mask so that bits 4-7 are 0
		 * Also enables bits 0-3 only if they're 1
		 */
		sc->ier = value & 0x0F;
		break;
		case REG_FCR:
			/*
			 * When moving from FIFO and 16450 mode and vice versa,
			 * the FIFO contents are reset.
			 */
			if ((sc->fcr & FCR_ENABLE) ^ (value & FCR_ENABLE)) {
				fifosz = (value & FCR_ENABLE) ? FIFOSZ : 1;
				fifo_reset(&sc->rxfifo, fifosz);
			}

			/*
			 * The FCR_ENABLE bit must be '1' for the programming
			 * of other FCR bits to be effective.
			 */
			if ((value & FCR_ENABLE) == 0) {
				sc->fcr = 0;
			} else {
				if ((value & FCR_RCV_RST) != 0)
					fifo_reset(&sc->rxfifo, FIFOSZ);

				sc->fcr = value &
					 (FCR_ENABLE | FCR_DMA | FCR_RX_MASK);
			}
			break;
		case REG_LCR:
			sc->lcr = value;
			break;
		case REG_MCR:
			/* Apply mask so that bits 5-7 are 0 */
			sc->mcr = value & 0x1F;

			msr = 0;
			if (sc->mcr & MCR_LOOPBACK) {
				/*
				 * In the loopback mode certain bits from the
				 * MCR are reflected back into MSR
				 */
				if (sc->mcr & MCR_RTS)
					msr |= MSR_CTS;
				if (sc->mcr & MCR_DTR)
					msr |= MSR_DSR;
				if (sc->mcr & MCR_OUT1)
					msr |= MSR_RI;
				if (sc->mcr & MCR_OUT2)
					msr |= MSR_DCD;
			}

			/*
			 * Detect if there has been any change between the
			 * previous and the new value of MSR. If there is
			 * then assert the appropriate MSR delta bit.
			 */
			if ((msr & MSR_CTS) ^ (sc->msr & MSR_CTS))
				sc->msr |= MSR_DCTS;
			if ((msr & MSR_DSR) ^ (sc->msr & MSR_DSR))
				sc->msr |= MSR_DDSR;
			if ((msr & MSR_DCD) ^ (sc->msr & MSR_DCD))
				sc->msr |= MSR_DDCD;
			if ((sc->msr & MSR_RI) != 0 && (msr & MSR_RI) == 0)
				sc->msr |= MSR_TERI;

			/*
			 * Update the value of MSR while retaining the delta
			 * bits.
			 */
			sc->msr &= MSR_DELTA_MASK;
			sc->msr |= msr;
			break;
		case REG_LSR:
			/*
			 * Line status register is not meant to be written to
			 * during normal operation.
			 */
			break;
		case REG_MSR:
			/*
			 * As far as I can tell MSR is a read-only register.
			 */
			break;
		case REG_SCR:
			sc->scr = value;
			break;
		default:
			break;
	}

done:
	uart_toggle_intr(sc);
	pthread_mutex_unlock(&sc->mtx);
}

uint8_t
uart_read(struct uart_softc *sc, int offset)
{
	uint8_t iir, intr_reason, reg;

	pthread_mutex_lock(&sc->mtx);

	/* Open terminal */
	if (!sc->opened && sc->stdio) {
		uart_opentty(sc);
		sc->opened = true;
	}

	/*
	 * Take care of the special case DLAB accesses first
	 */
	if ((sc->lcr & LCR_DLAB) != 0) {
		if (offset == REG_DLL) {
			reg = sc->dll;
			goto done;
		}

		if (offset == REG_DLH) {
			reg = sc->dlh;
			goto done;
		}
	}

	switch (offset) {
	case REG_DATA:
		reg = fifo_getchar(&sc->rxfifo);
		break;
	case REG_IER:
		reg = sc->ier;
		break;
	case REG_IIR:
		iir = (sc->fcr & FCR_ENABLE) ? IIR_FIFO_MASK : 0;

		intr_reason = uart_intr_reason(sc);

		/*
		 * Deal with side effects of reading the IIR register
		 */
		if (intr_reason == IIR_TXRDY)
			sc->thre_int_pending = false;

		iir |= intr_reason;

		reg = iir;
		break;
	case REG_LCR:
		reg = sc->lcr;
		break;
	case REG_MCR:
		reg = sc->mcr;
		break;
	case REG_LSR:
		/* Transmitter is always ready for more data */
		sc->lsr |= LSR_TEMT | LSR_THRE;

		/* Check for new receive data */
		if (fifo_numchars(&sc->rxfifo) > 0)
			sc->lsr |= LSR_RXRDY;
		else
			sc->lsr &= ~LSR_RXRDY;

		reg = sc->lsr;

		/* The LSR_OE bit is cleared on LSR read */
		sc->lsr &= ~LSR_OE;
		break;
	case REG_MSR:
		/*
		 * MSR delta bits are cleared on read
		 */
		reg = sc->msr;
		sc->msr &= ~MSR_DELTA_MASK;
		break;
	case REG_SCR:
		reg = sc->scr;
		break;
	default:
		reg = 0xFF;
		break;
	}

done:
	uart_toggle_intr(sc);
	pthread_mutex_unlock(&sc->mtx);

	return (reg);
}

#ifndef	__FreeBSD__
static void *
uart_tty_thread(void *param)
{
	struct uart_softc *sc = param;
	pollfd_t pollset;

	pollset.fd = STDIN_FILENO;
	pollset.events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;

	for (;;) {
		if (poll(&pollset, 1, -1) < 0) {
			if (errno != EINTR) {
				perror("poll failed");
				break;
			}
			continue;
		}
		uart_tty_drain(sc);
	}

	return (NULL);
}

/*
 * Read the "ident" string from the client's descriptor; this routine also
 * tolerates being called with pid=NULL, for times when you want to "eat"
 * the ident string from a client without saving it.
 */
static int
get_client_ident(int clifd, pid_t *pid)
{
	char buf[BUFSIZ], *bufp;
	size_t buflen = sizeof (buf);
	char c = '\0';
	int i = 0, r;

	/* "eat up the ident string" case, for simplicity */
	if (pid == NULL) {
		while (read(clifd, &c, 1) == 1) {
			if (c == '\n')
				return (0);
		}
	}

	bzero(buf, sizeof (buf));
	while ((buflen > 1) && (r = read(clifd, &c, 1)) == 1) {
		buflen--;
		if (c == '\n')
			break;

		buf[i] = c;
		i++;
	}
	if (r == -1)
		return (-1);

	/*
	 * We've filled the buffer, but still haven't seen \n.  Keep eating
	 * until we find it; we don't expect this to happen, but this is
	 * defensive.
	 */
	if (c != '\n') {
		while ((r = read(clifd, &c, sizeof (c))) > 0)
			if (c == '\n')
				break;
	}

	/*
	 * Parse buffer for message of the form: IDENT <pid>
	 */
	bufp = buf;
	if (strncmp(bufp, "IDENT ", 6) != 0)
		return (-1);
	bufp += 6;
	errno = 0;
	*pid = strtoll(bufp, &bufp, 10);
	if (errno != 0)
		return (-1);

	return (0);
}

static int
uart_bcons_accept_client(struct uart_softc *sc)
{
	int connfd;
	struct sockaddr_un cliaddr;
	socklen_t clilen;
	pid_t pid;

	clilen = sizeof (cliaddr);
	connfd = accept(sc->usc_bcons.servfd,
			(struct sockaddr *)&cliaddr, &clilen);
	if (connfd == -1)
		return (-1);
	if (get_client_ident(connfd, &pid) == -1) {
		(void) shutdown(connfd, SHUT_RDWR);
		(void) close(connfd);
		return (-1);
	}

	if (fcntl(connfd, F_SETFL, O_NONBLOCK) < 0) {
		(void) shutdown(connfd, SHUT_RDWR);
		(void) close(connfd);
		return (-1);
	}
	(void) write(connfd, "OK\n", 3);

	sc->usc_bcons.clipid = pid;
	sc->usc_bcons.clifd = connfd;

	printf("Connection from process ID %lu.\n", pid);

	return (0);
}

static void
uart_bcons_reject_client(struct uart_softc *sc)
{
	int connfd;
	struct sockaddr_un cliaddr;
	socklen_t clilen;
	char nak[MAXPATHLEN];

	clilen = sizeof (cliaddr);
	connfd = accept(sc->usc_bcons.servfd,
			(struct sockaddr *)&cliaddr, &clilen);

	/*
	 * After hear its ident string, tell client to get lost.
	 */
	if (get_client_ident(connfd, NULL) == 0) {
		(void) snprintf(nak, sizeof (nak), "%lu\n",
		    sc->usc_bcons.clipid);
		(void) write(connfd, nak, strlen(nak));
	}
	(void) shutdown(connfd, SHUT_RDWR);
	(void) close(connfd);
}

static int
uart_bcons_client_event(struct uart_softc *sc)
{
	int res;

	res = uart_bcons_drain(sc);
	if (res < 0)
		return (-1);

	if (res > 0) {
		fprintf(stderr, "Closing connection with bhyve console\n");
		(void) shutdown(sc->usc_bcons.clifd, SHUT_RDWR);
		(void) close(sc->usc_bcons.clifd);
		sc->usc_bcons.clifd = -1;
	}

	return (0);
}

static void
uart_bcons_server_event(struct uart_softc *sc)
{
#if notyet
	int clifd;
#endif

	if (sc->usc_bcons.clifd != -1) {
		/* we're already handling a client */
		uart_bcons_reject_client(sc);
		return;
	}

	if (uart_bcons_accept_client(sc) == 0) {
		pthread_mutex_lock(&bcons_wait_lock);
		bcons_connected = B_TRUE;
		pthread_cond_signal(&bcons_wait_done);
		pthread_mutex_unlock(&bcons_wait_lock);
	}
}

static void *
uart_bcons_thread(void *param)
{
	struct uart_softc *sc = param;
	struct pollfd pollfds[2];
	int res;

	/* read from client and write to vm */
	pollfds[0].events = POLLIN | POLLRDNORM | POLLRDBAND |
	    POLLPRI | POLLERR | POLLHUP;

	/* the server socket; watch for events (new connections) */
	pollfds[1].events = pollfds[0].events;

	for (;;) {
		pollfds[0].fd = sc->usc_bcons.clifd;
		pollfds[1].fd = sc->usc_bcons.servfd;
		pollfds[0].revents = pollfds[1].revents = 0;

		res = poll(pollfds,
		    sizeof (pollfds) / sizeof (struct pollfd), -1);

		if (res == -1 && errno != EINTR) {
			perror("poll failed");
			/* we are hosed, close connection */
			break;
		}

		/* event from client side */
		if (pollfds[0].revents) {
			if (pollfds[0].revents &
			    (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) {
				if (uart_bcons_client_event(sc) < 0)
					break;
			} else {
				break;
			}
		}

		/* event from server socket */
		if (pollfds[1].revents) {
			if (pollfds[1].revents & (POLLIN | POLLRDNORM)) {
				uart_bcons_server_event(sc);
			} else {
				break;
			}
		}
	}

	if (sc->usc_bcons.clifd != -1) {
		fprintf(stderr, "Closing connection with bhyve console\n");
		(void) shutdown(sc->usc_bcons.clifd, SHUT_RDWR);
		(void) close(sc->usc_bcons.clifd);
		sc->usc_bcons.clifd = -1;
	}

	return (NULL);
}

static int
init_bcons_sock(void)
{
	int servfd;
	struct sockaddr_un servaddr;

	if (mkdir(BHYVE_TMPDIR, S_IRWXU) < 0 && errno != EEXIST) {
		fprintf(stderr, "bhyve console setup: "
		    "could not mkdir %s", BHYVE_TMPDIR, strerror(errno));
		return (-1);
	}

	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;
	(void) snprintf(servaddr.sun_path, sizeof (servaddr.sun_path),
	    BHYVE_CONS_SOCKPATH, vmname);

	if ((servfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		fprintf(stderr, "bhyve console setup: "
		    "could not create socket\n");
		return (-1);
	}
	(void) unlink(servaddr.sun_path);

	if (bind(servfd, (struct sockaddr *)&servaddr,
	    sizeof (servaddr)) == -1) {
		fprintf(stderr, "bhyve console setup: "
		    "could not bind to socket\n");
		goto out;
        }

        if (listen(servfd, 4) == -1) {
		fprintf(stderr, "bhyve console setup: "
		    "could not listen on socket");
		goto out;
        }
        return (servfd);

out:
	(void) unlink(servaddr.sun_path);
        (void) close(servfd);
        return (-1);
}
#endif

int
uart_legacy_alloc(int which, int *baseaddr, int *irq)
{

	if (which < 0 || which >= UART_NLDEVS || uart_lres[which].inuse)
		return (-1);

	uart_lres[which].inuse = true;
	*baseaddr = uart_lres[which].baseaddr;
	*irq = uart_lres[which].irq;

	return (0);
}

struct uart_softc *
uart_init(uart_intr_func_t intr_assert, uart_intr_func_t intr_deassert,
    void *arg)
{
	struct uart_softc *sc;

	sc = malloc(sizeof(struct uart_softc));
	bzero(sc, sizeof(struct uart_softc));

	sc->arg = arg;
	sc->intr_assert = intr_assert;
	sc->intr_deassert = intr_deassert;

	pthread_mutex_init(&sc->mtx, NULL);

	uart_reset(sc);

	return (sc);
}

int
uart_set_backend(struct uart_softc *sc, const char *opts)
{
#ifndef	__FreeBSD__
	int error;
#endif
	/*
	 * XXX one stdio backend supported at this time.
	 */
	if (opts == NULL)
		return (0);

#ifdef	__FreeBSD__
	if (strcmp("stdio", opts) == 0 && !uart_stdio) {
		sc->stdio = true;
		uart_stdio = true;
		return (0);
#else
	if (strcmp("stdio", opts) == 0 && !uart_stdio && !uart_bcons) {
		sc->stdio = true;
		uart_stdio = true;

		error = pthread_create(NULL, NULL, uart_tty_thread, sc);
		assert(error == 0);

		return (0);
	} else if (strstr(opts, "bcons") != 0 && !uart_stdio && !uart_bcons) {
		sc->bcons = true;
		uart_bcons= true;

		if (strstr(opts, "bcons,wait") != 0) {
			bcons_wait = true;
		}

		sc->usc_bcons.clifd = -1;
		if ((sc->usc_bcons.servfd = init_bcons_sock()) == -1) {
			fprintf(stderr, "bhyve console setup: "
			    "socket initialization failed\n");
			return (-1);
		}
		error = pthread_create(NULL, NULL, uart_bcons_thread, sc);
		assert(error == 0);

		return (0);
#endif
	} else
		return (-1);
}
