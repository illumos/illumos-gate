/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
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
 */

#include <sys/types.h>

#include <machine/vmm.h>

#include <assert.h>
#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <termios.h>
#include <unistd.h>
#ifndef	__FreeBSD__
#include <sys/socket.h>
#include <fcntl.h>
#endif


#include "debug.h"
#include "mevent.h"
#include "uart_backend.h"
#include "uart_emul.h"

struct ttyfd {
	bool	opened;
	int	rfd;		/* fd for reading */
	int	wfd;		/* fd for writing, may be == rfd */
};

#ifndef	__FreeBSD__
struct sockfd {
	bool	sock;
	int	clifd;		/* console client unix domain socket */
	int	servfd;		/* console server unix domain socket */
	struct mevent *servmev;	/* mevent for server socket */
	void (*drain)(int, enum ev_type, void *);
	void *drainarg;
};
#endif

#define	FIFOSZ	16

struct fifo {
	uint8_t	buf[FIFOSZ];
	int	rindex;		/* index to read from */
	int	windex;		/* index to write to */
	int	num;		/* number of characters in the fifo */
	int	size;		/* size of the fifo */
};

struct uart_softc {
	struct ttyfd	tty;
#ifndef	__FreeBSD__
	struct sockfd	usc_sock;
#endif
	struct fifo	rxfifo;
	struct mevent	*mev;
#ifndef	__FreeBSD__
	/* XXX SmartOS - see uart_intr_throttled(). */
	struct mevent	*intr_throttle;
#endif
	pthread_mutex_t mtx;
};

static bool uart_stdio;		/* stdio in use for i/o */
static struct termios tio_stdio_orig;

static void
ttyclose(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &tio_stdio_orig);
}

static void
ttyopen(struct ttyfd *tf)
{
	struct termios orig, new;

	tcgetattr(tf->rfd, &orig);
	new = orig;
	cfmakeraw(&new);
	new.c_cflag |= CLOCAL;
	tcsetattr(tf->rfd, TCSANOW, &new);
	if (uart_stdio) {
		tio_stdio_orig = orig;
		atexit(ttyclose);
	}
	raw_stdio = 1;
}

static int
ttyread(struct ttyfd *tf)
{
	unsigned char rb;

	if (read(tf->rfd, &rb, 1) == 1)
		return (rb);
	else
		return (-1);
}

static void
ttywrite(struct ttyfd *tf, unsigned char wb)
{
	(void)write(tf->wfd, &wb, 1);
}

#ifndef	__FreeBSD__
static void
sockwrite(struct uart_softc *sc, unsigned char wb)
{
	(void) write(sc->usc_sock.clifd, &wb, 1);
}
#endif

static bool
rxfifo_available(struct uart_softc *sc)
{
	return (sc->rxfifo.num < sc->rxfifo.size);
}

int
uart_rxfifo_getchar(struct uart_softc *sc)
{
	struct fifo *fifo;
	int c, error, wasfull;

	wasfull = 0;
	fifo = &sc->rxfifo;
	if (fifo->num > 0) {
		if (!rxfifo_available(sc))
			wasfull = 1;
		c = fifo->buf[fifo->rindex];
		fifo->rindex = (fifo->rindex + 1) % fifo->size;
		fifo->num--;
		if (wasfull) {
			if (sc->tty.opened) {
				error = mevent_enable(sc->mev);
				assert(error == 0);
			}
#ifndef	__FreeBSD__
			if (sc->usc_sock.sock && sc->usc_sock.clifd != -1) {
				error = mevent_enable(sc->mev);
				assert(error == 0);
			}
#endif /* __FreeBSD__ */
		}
		return (c);
	} else
		return (-1);
}

int
uart_rxfifo_numchars(struct uart_softc *sc)
{
	return (sc->rxfifo.num);
}

static int
rxfifo_putchar(struct uart_softc *sc, uint8_t ch)
{
	struct fifo *fifo;
	int error;

	fifo = &sc->rxfifo;

	if (fifo->num < fifo->size) {
		fifo->buf[fifo->windex] = ch;
		fifo->windex = (fifo->windex + 1) % fifo->size;
		fifo->num++;
		if (!rxfifo_available(sc)) {
			if (sc->tty.opened) {
				/*
				 * Disable mevent callback if the FIFO is full.
				 */
				error = mevent_disable(sc->mev);
				assert(error == 0);
			}
#ifndef	__FreeBSD__
			if (sc->usc_sock.sock && sc->usc_sock.clifd != -1) {
				/*
				 * Disable mevent callback if the FIFO is full.
				 */
				error = mevent_disable(sc->mev);
				assert(error == 0);
			}
#endif /* __FreeBSD__ */
		}
		return (0);
	} else
		return (-1);
}

void
uart_rxfifo_drain(struct uart_softc *sc, bool loopback)
{
	int ch;

	if (loopback) {
		(void)ttyread(&sc->tty);
	} else {
		while (rxfifo_available(sc) &&
		    ((ch = ttyread(&sc->tty)) != -1))
			rxfifo_putchar(sc, ch);
	}
}

#ifndef	__FreeBSD__
/*
 * XXX SmartOS -- the functions that implement OS-8556.
 *
 * This checks if we've scheduled our small 1ms delay or not in
 * uart_toggle_intr() in uart_emul.c. If we haven't, we schedule one and
 * enable the interrupt; future callers here will NOT enable the interrupt
 * until the delay has been cleared. See the aforementioned function/file for
 * the motivation behind this.
 */

/*
 * Clear the IIR_RXTOUT timer, allowing uart_rxfifo_sock_drain() to continue
 * processing. Not under sc->mtx protection, so we must acquire and release
 * the lock.
 */
static void
uart_intr_callback(int fd __unused, enum ev_type type __unused, void *param)
{
	struct uart_softc *sc = param;

	pthread_mutex_lock(&sc->mtx);

	mevent_delete(sc->intr_throttle);
	sc->intr_throttle = NULL;

	pthread_mutex_unlock(&sc->mtx);
}

/*
 * Called from the uart_emul interrupt toggler's enable path.  Will actually
 * intr_assert() the interrupt if no existing throttle timer is on the soft
 * state.  Otherwise it just return and nothing happens.
 *
 * NOTE:  We are already under the sc->mtx's protection before being called.
 * (We could ASSERT() this if we wanted to.)
 */
void
uart_intr_throttled(struct uart_softc *sc, void *intr_assert_ptr, void *arg)
{
	uart_intr_func_t intr_assert = (uart_intr_func_t)intr_assert_ptr;

	if (sc->intr_throttle != NULL)
		return;

	intr_assert(arg);
	sc->intr_throttle = mevent_add(1, EVF_TIMER, uart_intr_callback, sc);
}

void
uart_rxfifo_sock_drain(struct uart_softc *sc, bool loopback)
{
	int ch;

	if (loopback) {
		(void) read(sc->usc_sock.clifd, &ch, 1);
	} else {
		bool err_close = false;

		while (rxfifo_available(sc) && sc->intr_throttle == NULL) {
			int res;

			res = read(sc->usc_sock.clifd, &ch, 1);
			if (res == 0) {
				err_close = true;
				break;
			} else if (res == -1) {
				if (errno != EAGAIN && errno != EINTR) {
					err_close = true;
				}
				break;
			}

			rxfifo_putchar(sc, ch);
		}

		if (err_close) {
			(void) fprintf(stderr, "uart: closing client conn\n");
			(void) shutdown(sc->usc_sock.clifd, SHUT_RDWR);
			mevent_delete_close(sc->mev);
			sc->mev = NULL;
			sc->usc_sock.clifd = -1;
		}
	}
}
#endif

int
uart_rxfifo_putchar(struct uart_softc *sc, uint8_t ch, bool loopback)
{
	if (loopback) {
		return (rxfifo_putchar(sc, ch));
	} else if (sc->tty.opened) {
		ttywrite(&sc->tty, ch);
		return (0);
#ifndef	__FreeBSD__
	} else if (sc->usc_sock.sock) {
		sockwrite(sc, ch);
		return (0);
#endif
	} else {
		/* Drop on the floor. */
		return (0);
	}
}

void
uart_rxfifo_reset(struct uart_softc *sc, int size)
{
	char flushbuf[32];
	struct fifo *fifo;
	ssize_t nread;
	int error;

	fifo = &sc->rxfifo;
	bzero(fifo, sizeof(struct fifo));
	fifo->size = size;

	if (sc->tty.opened) {
		/*
		 * Flush any unread input from the tty buffer.
		 */
		while (1) {
			nread = read(sc->tty.rfd, flushbuf, sizeof(flushbuf));
			if (nread != sizeof(flushbuf))
				break;
		}

		/*
		 * Enable mevent to trigger when new characters are available
		 * on the tty fd.
		 */
		error = mevent_enable(sc->mev);
		assert(error == 0);
	}
#ifndef	__FreeBSD__
	if (sc->usc_sock.sock && sc->usc_sock.clifd != -1) {
		/* Flush any unread input from the socket buffer. */
		do {
			nread = read(sc->usc_sock.clifd, flushbuf,
			    sizeof (flushbuf));
		} while (nread == sizeof (flushbuf));

		/* Enable mevent to trigger when new data available on sock */
		error = mevent_enable(sc->mev);
		assert(error == 0);
	}
#endif /* __FreeBSD__ */
}

int
uart_rxfifo_size(struct uart_softc *sc __unused)
{
	return (FIFOSZ);
}

#ifdef BHYVE_SNAPSHOT
int
uart_rxfifo_snapshot(struct uart_softc *sc, struct vm_snapshot_meta *meta)
{
	int ret;

	SNAPSHOT_VAR_OR_LEAVE(sc->rxfifo.rindex, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sc->rxfifo.windex, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sc->rxfifo.num, meta, ret, done);
	SNAPSHOT_VAR_OR_LEAVE(sc->rxfifo.size, meta, ret, done);
	SNAPSHOT_BUF_OR_LEAVE(sc->rxfifo.buf, sizeof(sc->rxfifo.buf),
	    meta, ret, done);

done:
	return (ret);
}
#endif

static int
uart_stdio_backend(struct uart_softc *sc)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
#endif

	if (uart_stdio)
		return (-1);

	sc->tty.rfd = STDIN_FILENO;
	sc->tty.wfd = STDOUT_FILENO;
	sc->tty.opened = true;

	if (fcntl(sc->tty.rfd, F_SETFL, O_NONBLOCK) != 0)
		return (-1);
	if (fcntl(sc->tty.wfd, F_SETFL, O_NONBLOCK) != 0)
		return (-1);

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_IOCTL, CAP_READ);
	if (caph_rights_limit(sc->tty.rfd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(sc->tty.rfd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	uart_stdio = true;

	return (0);
}

static int
uart_tty_backend(struct uart_softc *sc, const char *path)
{
#ifndef WITHOUT_CAPSICUM
	cap_rights_t rights;
	cap_ioctl_t cmds[] = { TIOCGETA, TIOCSETA, TIOCGWINSZ };
#endif
	int fd;

	fd = open(path, O_RDWR | O_NONBLOCK);
	if (fd < 0)
		return (-1);

	if (!isatty(fd)) {
		close(fd);
		return (-1);
	}

	sc->tty.rfd = sc->tty.wfd = fd;
	sc->tty.opened = true;

#ifndef WITHOUT_CAPSICUM
	cap_rights_init(&rights, CAP_EVENT, CAP_IOCTL, CAP_READ, CAP_WRITE);
	if (caph_rights_limit(fd, &rights) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
	if (caph_ioctls_limit(fd, cmds, nitems(cmds)) == -1)
		errx(EX_OSERR, "Unable to apply rights for sandbox");
#endif

	return (0);
}

#ifndef	__FreeBSD__
static void
uart_sock_accept(int fd, enum ev_type ev, void *arg)
{
	struct uart_softc *sc = arg;
	int connfd;

	connfd = accept(sc->usc_sock.servfd, NULL, NULL);
	if (connfd == -1) {
		return;
	}

	/*
	 * Do client connection management under protection of the softc lock
	 * to avoid racing with concurrent UART events.
	 */
	pthread_mutex_lock(&sc->mtx);

	if (sc->usc_sock.clifd != -1) {
		/* we're already handling a client */
		(void) fprintf(stderr, "uart: unexpected client conn\n");
		(void) shutdown(connfd, SHUT_RDWR);
		(void) close(connfd);
	} else {
		if (fcntl(connfd, F_SETFL, O_NONBLOCK) < 0) {
			perror("uart: fcntl(O_NONBLOCK)");
			(void) shutdown(connfd, SHUT_RDWR);
			(void) close(connfd);
		} else {
			sc->usc_sock.clifd = connfd;
			sc->mev = mevent_add(sc->usc_sock.clifd, EVF_READ,
			    sc->usc_sock.drain, sc->usc_sock.drainarg);
		}
	}

	pthread_mutex_unlock(&sc->mtx);
}

static int
init_sock(const char *path)
{
	int servfd;
	struct sockaddr_un servaddr;

	bzero(&servaddr, sizeof (servaddr));
	servaddr.sun_family = AF_UNIX;

	if (strlcpy(servaddr.sun_path, path, sizeof (servaddr.sun_path)) >=
	    sizeof (servaddr.sun_path)) {
		(void) fprintf(stderr, "uart: path '%s' too long\n",
		    path);
		return (-1);
	}

	if ((servfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		(void) fprintf(stderr, "uart: socket() error - %s\n",
		    strerror(errno));
		return (-1);
	}
	(void) unlink(servaddr.sun_path);

	if (bind(servfd, (struct sockaddr *)&servaddr,
	    sizeof (servaddr)) == -1) {
		(void) fprintf(stderr, "uart: bind() error - %s\n",
		    strerror(errno));
		goto out;
	}

	if (listen(servfd, 1) == -1) {
		(void) fprintf(stderr, "uart: listen() error - %s\n",
		    strerror(errno));
		goto out;
	}
	return (servfd);

out:
	(void) unlink(servaddr.sun_path);
	(void) close(servfd);
	return (-1);
}

static int
uart_sock_backend(struct uart_softc *sc, const char *inopts,
    void (*drain)(int, enum ev_type, void *), void *drainarg)
{
	char *opts, *tofree;
	char *opt;
	char *nextopt;
	char *path = NULL;

	if (strncmp(inopts, "socket,", 7) != 0) {
		return (-1);
	}
	if ((opts = strdup(inopts + 7)) == NULL) {
		return (-1);
	}

	tofree = nextopt = opts;
	for (opt = strsep(&nextopt, ","); opt != NULL;
	    opt = strsep(&nextopt, ",")) {
		if (path == NULL && *opt == '/') {
			path = opt;
			continue;
		}
		/*
		 * XXX check for server and client options here.  For now,
		 * everything is a server
		 */
		free(tofree);
		return (-1);
	}

	sc->usc_sock.clifd = -1;
	if ((sc->usc_sock.servfd = init_sock(path)) == -1) {
		free(tofree);
		return (-1);
	}
	sc->usc_sock.sock = true;
	sc->tty.rfd = sc->tty.wfd = -1;
	sc->usc_sock.servmev = mevent_add(sc->usc_sock.servfd, EVF_READ,
	    uart_sock_accept, sc);
	assert(sc->usc_sock.servmev != NULL);

	sc->usc_sock.drain = drain;
	sc->usc_sock.drainarg = drainarg;

	free(tofree);
	return (0);
}
#endif /* not __FreeBSD__ */

struct uart_softc *
uart_init(void)
{
	struct uart_softc *sc = calloc(1, sizeof(struct uart_softc));
	if (sc == NULL)
		return (NULL);

	pthread_mutex_init(&sc->mtx, NULL);

	return (sc);
}

int
uart_tty_open(struct uart_softc *sc, const char *path,
    void (*drain)(int, enum ev_type, void *), void *arg)
{
	int retval;

#ifndef __FreeBSD__
	if (strncmp("socket,", path, 7) == 0)
		return (uart_sock_backend(sc, path, drain, arg));
#endif
	if (strcmp("stdio", path) == 0)
		retval = uart_stdio_backend(sc);
	else
		retval = uart_tty_backend(sc, path);
	if (retval == 0) {
		ttyopen(&sc->tty);
		sc->mev = mevent_add(sc->tty.rfd, EVF_READ, drain, arg);
		assert(sc->mev != NULL);
	}

	return (retval);
}

void
uart_softc_lock(struct uart_softc *sc)
{
	pthread_mutex_lock(&sc->mtx);
}

void
uart_softc_unlock(struct uart_softc *sc)
{
	pthread_mutex_unlock(&sc->mtx);
}
