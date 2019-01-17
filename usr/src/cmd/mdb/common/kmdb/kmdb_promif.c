/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/termios.h>
#include <sys/promif.h>
#ifdef sun4v
#include <sys/promif_impl.h>
#endif
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <kmdb/kmdb_promif_impl.h>
#include <kmdb/kmdb_kdi.h>
#include <kmdb/kmdb_dpi.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb.h>

#define	KMDB_PROM_DEF_CONS_MODE	"9600,n,1,-,-"

#define	KMDB_PROM_READBUF_SIZE	1024

static char kmdb_prom_readbuf[KMDB_PROM_READBUF_SIZE];
static int kmdb_prom_readbuf_head;
static int kmdb_prom_readbuf_tail;

static int
kmdb_prom_getchar(int wait)
{
	struct cons_polledio *pio = mdb.m_pio;
	uintptr_t ischar;
	uintptr_t getchar;
	uintptr_t arg;

	if (pio == NULL || pio->cons_polledio_getchar == NULL) {
		int c;
		while ((c = prom_mayget()) == -1) {
			if (!wait)
				return (-1);
		}
		return (c);
	}

	ischar = (uintptr_t)pio->cons_polledio_ischar;
	getchar = (uintptr_t)pio->cons_polledio_getchar;
	arg = (uintptr_t)pio->cons_polledio_argument;

	if (!wait && ischar != 0 && !kmdb_dpi_call(ischar, 1, &arg))
		return (-1);

	return ((int)kmdb_dpi_call(getchar, 1, &arg));
}

static ssize_t
kmdb_prom_polled_write(caddr_t buf, size_t len)
{
	uintptr_t args[2];
	int i;

	args[0] = (uintptr_t)mdb.m_pio->cons_polledio_argument;

	for (i = 0; i < len; i++) {
		args[1] = *buf++;
		(void) kmdb_dpi_call(
		    (uintptr_t)mdb.m_pio->cons_polledio_putchar, 2, args);
	}

	return (len);
}

static ssize_t
kmdb_prom_reader(caddr_t buf, size_t len, int wait)
{
	int nread = 0;
	int c;

	while (nread < len) {
		if ((c = kmdb_prom_getchar(wait)) == -1)
			break;

		*buf++ = (char)c;
		nread++;
		wait = 0;
	}

	return (nread);
}

static ssize_t
kmdb_prom_writer(caddr_t buf, size_t len)
{
	if (mdb.m_pio != NULL && mdb.m_pio->cons_polledio_putchar != NULL)
		return (kmdb_prom_polled_write(buf, len));

	return (kmdb_prom_obp_writer(buf, len));
}

/*
 * Due to the nature of kmdb, we don't have signals.  This prevents us from
 * receiving asynchronous notification when the user would like to abort active
 * dcmds.  Whereas mdb can simply declare a SIGINT handler, we must
 * occasionally poll the input stream, looking for pending ^C characters.  To
 * give the illusion of asynchronous interrupt delivery, this polling is
 * triggered from several commonly-used functions, such as kmdb_prom_write and
 * the *read and *write target ops.  When an interrupt check is triggered, we
 * read through pending input, looking for interrupt characters.  If we find
 * one, we deliver an interrupt immediately.
 *
 * In a read context, we can deliver the interrupt character directly back to
 * the termio handler rather than raising an interrupt.
 *
 * OBP doesn't have an "unget" facility.  Any character read for interrupt
 * checking is gone forever, unless we save it.  Loss of these characters
 * would prevent us from supporting typeahead.  We like typeahead, so we're
 * going to save characters gathered during interrupt checking.  As with
 * ungetc(3c), however, we can only store a finite number of characters in
 * our typeahead buffer.  Characters read beyond that will be silently dropped
 * after they undergo interrupt processing.
 *
 * The typeahead facility is implemented as a ring buffer, stored in
 * kmdb_prom_readbuf.
 */
static size_t
kmdb_prom_drain_readbuf(void *buf, size_t len)
{
	size_t n, tailread;

	/*
	 * If head > tail, life is easy - we can simply read as much as we need
	 * in one gulp.
	 */
	if (kmdb_prom_readbuf_head > kmdb_prom_readbuf_tail) {
		n = MIN(kmdb_prom_readbuf_head - kmdb_prom_readbuf_tail, len);
		bcopy(kmdb_prom_readbuf + kmdb_prom_readbuf_tail, buf, n);
		kmdb_prom_readbuf_tail += n;
		return (n);

	} else if (kmdb_prom_readbuf_head == kmdb_prom_readbuf_tail) {
		return (0);
	}

	/*
	 * The consumable slots wrap around zero (there are slots from tail to
	 * zero, and from zero to head).  We have to read them in two parts.
	 */
	n = MIN(KMDB_PROM_READBUF_SIZE - kmdb_prom_readbuf_tail, len);
	bcopy(kmdb_prom_readbuf + kmdb_prom_readbuf_tail, buf, n);
	kmdb_prom_readbuf_tail = (kmdb_prom_readbuf_tail + n) %
	    KMDB_PROM_READBUF_SIZE;

	if (n == len) {
		/*
		 * We filled the passed buffer from the first part, so there's
		 * no need to read the second.
		 */
		return (n);
	} else {
		tailread = n;
	}

	n = MIN(kmdb_prom_readbuf_head, len - tailread);
	buf = (void *)((uintptr_t)buf + tailread);
	bcopy(kmdb_prom_readbuf, buf, n);

	kmdb_prom_readbuf_tail = (kmdb_prom_readbuf_tail + n) %
	    KMDB_PROM_READBUF_SIZE;

	return (tailread + n);
}

static void
check_int(char *buf, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (buf[i] == CTRL('c')) {
			kmdb_prom_readbuf_tail = kmdb_prom_readbuf_head;
			if (mdb.m_intr == 0)
				longjmp(mdb.m_frame->f_pcb, MDB_ERR_SIGINT);
			else
				mdb.m_pend++;
		}
	}
}

/*
 * Attempt to refill the ring buffer from the input stream.  This called from
 * two contexts:
 *
 * Direct read: read the input into our buffer until input is exhausted, or the
 * buffer is full.
 *
 * Interrupt check: called 'asynchronously' from the normal read routines; read
 * the input into our buffer until it is exhausted, discarding input if the
 * buffer is full.  In this case we look ahead for any interrupt characters,
 * delivering an interrupt directly if we find one.
 */
static void
kmdb_prom_fill_readbuf(int check_for_int, int wait)
{
	int oldhead, left, n;

	/*
	 * Calculate the number of slots left before we wrap around to the
	 * beginning again.
	 */
	left = KMDB_PROM_READBUF_SIZE - kmdb_prom_readbuf_head;
	if (kmdb_prom_readbuf_tail == 0)
		left--;

	if (kmdb_prom_readbuf_head == kmdb_prom_readbuf_tail ||
	    (kmdb_prom_readbuf_head > kmdb_prom_readbuf_tail && left > 0)) {
		/*
		 * head > tail, so we have to read in two parts - the slots
		 * from head until we wrap back around to zero, and the ones
		 * from zero to tail.  We handle the first part here, and let
		 * the common code handle the second.
		 */
		if ((n = kmdb_prom_reader(kmdb_prom_readbuf +
		    kmdb_prom_readbuf_head, left, wait)) <= 0)
			return;

		oldhead = kmdb_prom_readbuf_head;
		kmdb_prom_readbuf_head = (kmdb_prom_readbuf_head + n) %
		    KMDB_PROM_READBUF_SIZE;

		if (check_for_int)
			check_int(kmdb_prom_readbuf + oldhead, n);

		if (n != left)
			return;
	}

	left = kmdb_prom_readbuf_tail - kmdb_prom_readbuf_head - 1;
	if (left > 0) {
		if ((n = kmdb_prom_reader(kmdb_prom_readbuf +
		    kmdb_prom_readbuf_head, left, wait)) <= 0)
			return;

		oldhead = kmdb_prom_readbuf_head;
		kmdb_prom_readbuf_head = (kmdb_prom_readbuf_head + n) %
		    KMDB_PROM_READBUF_SIZE;

		if (check_for_int)
			check_int(kmdb_prom_readbuf + oldhead, n);

		if (n != left)
			return;
	}

	if (check_for_int) {
		char c;

		while (kmdb_prom_reader(&c, 1, 0) == 1)
			check_int(&c, 1);
	}
}

void
kmdb_prom_check_interrupt(void)
{
	kmdb_prom_fill_readbuf(1, 0);
}

/*
 * OBP reads are always non-blocking.  If there are characters available,
 * we'll return as many as we can.  If nothing is available, we'll spin
 * until one shows up.
 */
ssize_t
kmdb_prom_read(void *buf, size_t len, struct termios *tio)
{
	size_t totread = 0;
	size_t thisread;
	char *c = (char *)buf;
	int wait = 1;

	for (;;) {
		kmdb_prom_fill_readbuf(0, wait);
		thisread = kmdb_prom_drain_readbuf(c, len);
		len -= thisread;
		totread += thisread;
		c += thisread;

		/* wait until something shows up */
		if (totread == 0)
			continue;

		wait = 0;

		/*
		 * We're done if we've exhausted available input or if we've
		 * filled the provided buffer.
		 */
		if (len == 0 || thisread == 0)
			break;
	}

	if (tio->c_iflag & ICRNL) {
		char *cbuf = buf;
		int i;

		for (i = 0; i < totread; i++) {
			if (cbuf[i] == '\r')
				cbuf[i] = '\n';
		}
	}

	if (tio->c_lflag & ECHO)
		(void) kmdb_prom_write(buf, totread, tio);

	return (totread);
}

/*ARGSUSED*/
ssize_t
kmdb_prom_write(const void *bufp, size_t len, struct termios *tio)
{
	caddr_t buf = (caddr_t)bufp;
	size_t left = len;
	char *nl = "\r\n";
	char *c;

	kmdb_prom_check_interrupt();

	if (!(tio->c_oflag & ONLCR))
		return (kmdb_prom_writer(buf, left));

	/* translate every \n into \r\n */
	while ((c = strnchr(buf, '\n', left)) != NULL) {
		if (c != buf) {
			size_t sz = (size_t)(c - buf);
			(void) kmdb_prom_writer(buf, sz);
			left -= sz;
		}

		buf = c + 1;
		left--;

		(void) kmdb_prom_writer(nl, 2);
	}

	if (*buf != '\0')
		(void) kmdb_prom_writer(buf, left);

	return (len);
}

static char *
kmdb_get_ttyio_mode(kmdb_auxv_t *kav, char *devname)
{
	char *modepname, *modepval;

	modepname = mdb_alloc(strlen(devname) + 5 + 1, UM_SLEEP);
	(void) strcpy(modepname, devname);
	(void) strcat(modepname, "-mode");

	modepval = kmdb_prom_get_ddi_prop(kav, modepname);

	strfree(modepname);

	return (modepval);
}

static int
termios_setispeed(struct termios *tip, speed_t s)
{
	if (s > (2 * CBAUD + 1))
		return (-1);

	if ((s << IBSHIFT) > CIBAUD) {
		tip->c_cflag |= CIBAUDEXT;
		s -= ((CIBAUD >> IBSHIFT) + 1);
	} else
		tip->c_cflag &= ~CIBAUDEXT;

	tip->c_cflag = (tip->c_cflag & ~CIBAUD) | ((s << IBSHIFT) & CIBAUD);

	return (0);
}

static int
termios_setospeed(struct termios *tip, speed_t s)
{
	if (s > (2 * CBAUD + 1))
		return (-1);

	if (s > CBAUD) {
		tip->c_cflag |= CBAUDEXT;
		s -= (CBAUD + 1);
	} else
		tip->c_cflag &= ~CBAUDEXT;

	tip->c_cflag = (tip->c_cflag & ~CBAUD) | (s & CBAUD);

	return (0);
}

static int
kmdb_parse_mode(const char *mode, struct termios *tip, int in)
{
	static const uint_t baudmap[] = {
		0, 50, 75, 110, 134, 150, 200, 300, 600, 1200,
		1800, 2400, 4800, 9600, 19200, 38400, 57600,
		76800, 115200, 153600, 230400, 307200, 460800, 921600
	};
	static const uint_t bitsmap[] = { CS6, CS6, CS7, CS8 };
	char *m = strdup(mode);
	char *w;
	int rc = -1;
	speed_t speed;
	int baud, i;

	/*
	 * termios supports different baud rates and flow control types for
	 * input and output, but it requires character width, parity, and stop
	 * bits to be equal in input and output.  obp allows them to be
	 * different, but we're going to (silently) assume that nobody will use
	 * it that way.
	 */

	/* baud rate - see baudmap above */
	if ((w = strtok(m, ",")) == NULL)
		goto parse_mode_bail;

	baud = strtol(w, NULL, 10);
	speed = 0;
	for (i = 0; i < sizeof (baudmap) / sizeof (baudmap[0]); i++) {
		if (baudmap[i] == baud) {
			speed = i;
			break;
		}
	}
	if (speed == 0)
		goto parse_mode_bail;

	if (in == 1)
		(void) termios_setispeed(tip, speed);
	else
		(void) termios_setospeed(tip, speed);

	/* character width (bits) - 5, 6, 7, or 8 */
	if ((w = strtok(NULL, ",")) == NULL || strlen(w) != 1 || *w < '5' ||
	    *w > '8')
		goto parse_mode_bail;
	tip->c_cflag = (tip->c_cflag & ~CSIZE) | bitsmap[*w - '5'];

	/* parity - `n' (none), `e' (even), or `o' (odd) */
	if ((w = strtok(NULL, ",")) == NULL || strlen(w) != 1 ||
	    strchr("neo", *w) == NULL)
		goto parse_mode_bail;

	tip->c_cflag = (tip->c_cflag & ~(PARENB|PARODD));
	switch (*w) {
	case 'n':
		/* nothing */
		break;
	case 'e':
		tip->c_cflag |= PARENB;
		break;
	case 'o':
		tip->c_cflag |= PARENB|PARODD;
		break;
	}

	/*
	 * stop bits - 1, or 2.  obp can, in theory, support 1.5 bits,
	 * but we can't.  how many angels can dance on half of a bit?
	 */
	if ((w = strtok(NULL, ",")) == NULL || strlen(w) != 1 || *w < '1' ||
	    *w > '2')
		goto parse_mode_bail;

	if (*w == '1')
		tip->c_cflag &= ~CSTOPB;
	else
		tip->c_cflag |= CSTOPB;

	/* flow control - `-' (none), `h' (h/w), or `s' (s/w - XON/XOFF) */
	if ((w = strtok(NULL, ",")) == NULL || strlen(w) != 1 ||
	    strchr("-hs", *w) == NULL)
		goto parse_mode_bail;

	tip->c_cflag &= ~(CRTSXOFF|CRTSCTS);
	tip->c_iflag &= ~(IXON|IXANY|IXOFF);

	switch (*w) {
	case 'h':
		tip->c_cflag |= (in == 1 ? CRTSXOFF : CRTSCTS);
		break;

	case 's':
		tip->c_iflag |= (in == 1 ? IXOFF : IXON);
		break;
	}

	rc = 0;

parse_mode_bail:
	strfree(m);

	return (rc);
}

#ifdef __sparc
#define	ATTACHED_TERM_TYPE	"sun"
#else
#define	ATTACHED_TERM_TYPE	"sun-color"
#endif

static void
kmdb_prom_term_init(kmdb_auxv_t *kav, kmdb_promif_t *pif)
{
	const char ccs[NCCS] = { 0x03, 0x1c, 0x08, 0x15, 0x04, 0x00, 0x00,
	    0x00, 0x11, 0x13, 0x1a, 0x19, 0x12, 0x0f, 0x17, 0x16 };
	char *conin = NULL, *conout = NULL;

	if (kmdb_prom_stdout_is_framebuffer(kav))
		pif->pif_oterm = ATTACHED_TERM_TYPE;

	bzero(&pif->pif_tios, sizeof (struct termios));

	/* output device characteristics */
	if ((conout = kmdb_prom_get_ddi_prop(kav, "output-device")) ==
	    NULL || strcmp(conout, "screen") == 0) {
		(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
		    &pif->pif_tios, 0);
	} else if (*conout == '/') {
		/*
		 * We're not going to be able to get characteristics for a
		 * device that's specified as a path, so don't even try.
		 * Conveniently, this allows us to avoid chattering on
		 * Serengetis.
		 */
		(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
		    &pif->pif_tios, 0);
	} else {
		char *mode = kmdb_get_ttyio_mode(kav, conout);

#ifdef __sparc
		/*
		 * Some platforms (Starfire) define a value of `ttya' for
		 * output-device, but neglect to provide a specific property
		 * with the characteristics.  We'll provide a default value.
		 */
		if (mode == NULL && strcmp(conout, "ttya") == 0) {
			(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
			    &pif->pif_tios, 0);
		} else
#endif
		{
			if (mode == NULL || kmdb_parse_mode(mode,
			    &pif->pif_tios, 0) < 0) {
				/*
				 * Either we couldn't retrieve the
				 * characteristics for this console, or they
				 * weren't parseable.  The console hasn't been
				 * set up yet, so we can't warn.  We'll have to
				 * silently fall back to the default
				 * characteristics.
				 */
				(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
				    &pif->pif_tios, 0);
			}
		}

		if (mode != NULL)
			kmdb_prom_free_ddi_prop(mode);
	}

	/* input device characteristics */
	if ((conin = kmdb_prom_get_ddi_prop(kav, "input-device")) == NULL ||
	    strcmp(conin, "keyboard") == 0) {
		(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
		    &pif->pif_tios, 1);
	} else if (*conin == '/') {
		/* See similar case in output-device above */
		(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
		    &pif->pif_tios, 1);
	} else {
		char *mode = kmdb_get_ttyio_mode(kav, conin);

#ifdef __sparc
		/*
		 * Some platforms (Starfire) define a value of `ttya' for
		 * input-device, but neglect to provide a specific property
		 * with the characteristics.  We'll provide a default value.
		 */
		if (mode == NULL && strcmp(conin, "ttya") == 0) {
			(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
			    &pif->pif_tios, 1);
		} else
#endif
		{
			if (mode == NULL || kmdb_parse_mode(mode,
			    &pif->pif_tios, 1) < 0) {
				/*
				 * Either we couldn't retrieve the
				 * characteristics for this console, or they
				 * weren't parseable.  The console hasn't been
				 * set up yet, so we can't warn.  We'll have to
				 * silently fall back to the default
				 * characteristics.
				 */
				(void) kmdb_parse_mode(KMDB_PROM_DEF_CONS_MODE,
				    &pif->pif_tios, 1);
			}
		}

		if (mode != NULL)
			kmdb_prom_free_ddi_prop(mode);
	}

	/* various characteristics of the prom read/write interface */
	pif->pif_tios.c_iflag |= ICRNL;
	pif->pif_tios.c_lflag |= ECHO;
	bcopy(ccs, &pif->pif_tios.c_cc, sizeof (ccs));

	if (conin != NULL)
		kmdb_prom_free_ddi_prop(conin);
	if (conout != NULL)
		kmdb_prom_free_ddi_prop(conout);
}

char *
kmdb_prom_term_type(void)
{
	return (mdb.m_promif->pif_oterm);
}

int
kmdb_prom_term_ctl(int req, void *arg)
{
	switch (req) {
	case TCGETS: {
		struct termios *ti = arg;
		bcopy(&mdb.m_promif->pif_tios, ti, sizeof (struct termios));
		return (0);
	}
	case TIOCGWINSZ:
		/*
		 * When kmdb is used over a serial console, we have no idea how
		 * large the terminal window is.  When we're invoked on a local
		 * console, however, we do, and need to share that information
		 * with the debugger in order to contradict potentially
		 * incorrect sizing information retrieved from the terminfo
		 * database.  One specific case where this happens is with the
		 * Intel console, which is 80x25.  The terminfo entry for
		 * sun-color -- the default terminal type for local Intel
		 * consoles -- was cloned from sun, which has a height of 34
		 * rows.
		 */
		if (mdb.m_promif->pif_oterm != NULL) {
			struct winsize *wsz = arg;
			wsz->ws_row = KMDB_PIF_WINSIZE_ROWS;
			wsz->ws_col = KMDB_PIF_WINSIZE_COLS;
			wsz->ws_xpixel = wsz->ws_ypixel = 0;
			return (0);
		}

		return (set_errno(ENOTSUP));
	default:
		return (set_errno(EINVAL));
	}
}

int
kmdb_prom_vtop(uintptr_t virt, physaddr_t *pap)
{
	physaddr_t pa;
	int rc = kmdb_kdi_vtop(virt, &pa);

#ifdef	__sparc
	if (rc < 0 && errno == EAGAIN)
		rc = kmdb_prom_translate_virt(virt, &pa);
#endif

	if (rc == 0 && pap != NULL)
		*pap = pa;

	return (rc);
}

void
kmdb_prom_debugger_entry(void)
{
	/*
	 * While kmdb_prom_debugger_entry and kmdb_prom_debugger_exit are not
	 * guaranteed to be called an identical number of times (an intentional
	 * debugger fault will cause an additional entry call without a matching
	 * exit call), we must ensure that the polled I/O entry and exit calls
	 * match.
	 */
	if (mdb.m_pio == NULL) {
		mdb.m_pio = kmdb_kdi_get_polled_io();

		if (mdb.m_pio != NULL &&
		    mdb.m_pio->cons_polledio_enter != NULL) {
			(void) kmdb_dpi_call(
			    (uintptr_t)mdb.m_pio->cons_polledio_enter, 1,
			    (uintptr_t *)&mdb.m_pio->cons_polledio_argument);
		}
	}
}

void
kmdb_prom_debugger_exit(void)
{
	if (mdb.m_pio != NULL && mdb.m_pio->cons_polledio_exit != NULL) {
		(void) kmdb_dpi_call((uintptr_t)mdb.m_pio->cons_polledio_exit,
		    1, (uintptr_t *)&mdb.m_pio->cons_polledio_argument);
	}

	mdb.m_pio = NULL;
}

/*
 * The prom_* files use ASSERT, which is #defined as assfail().  We need to
 * redirect that to our assert function. This is also used by the various STAND
 * libraries.
 */
int
kmdb_prom_assfail(const char *assertion, const char *file, int line)
{
	(void) mdb_dassert(assertion, file, line);
	/*NOTREACHED*/
	return (0);
}

/*
 * Begin the initialization of the debugger/PROM interface.  Initialization is
 * performed in two steps due to interlocking dependencies between promif and
 * both the memory allocator and mdb_create.  The first phase is performed
 * before either of the others have been initialized, and thus must neither
 * attempt to allocate memory nor access/write to `mdb'.
 */
void
kmdb_prom_init_begin(char *pgmname, kmdb_auxv_t *kav)
{
#ifdef sun4v
	if (kav->kav_domaining)
		kmdb_prom_init_promif(pgmname, kav);
	else
		prom_init(pgmname, kav->kav_romp);
#else
	prom_init(pgmname, kav->kav_romp);
#endif

	/* Initialize the interrupt ring buffer */
	kmdb_prom_readbuf_head = kmdb_prom_readbuf_tail;

#if defined(__i386) || defined(__amd64)
	kmdb_sysp = kav->kav_romp;
#endif
}

#ifdef sun4v
void
kmdb_prom_init_promif(char *pgmname, kmdb_auxv_t *kav)
{
	ASSERT(kav->kav_domaining);
	cif_init(pgmname, kav->kav_promif_root,
	    kav->kav_promif_in, kav->kav_promif_out,
	    kav->kav_promif_pin, kav->kav_promif_pout,
	    kav->kav_promif_chosennode, kav->kav_promif_optionsnode);
}
#endif

/*
 * Conclude the initialization of the debugger/PROM interface.  Memory
 * allocation and the global `mdb' object are now available.
 */
void
kmdb_prom_init_finish(kmdb_auxv_t *kav)
{
	mdb.m_promif = mdb_zalloc(sizeof (kmdb_promif_t), UM_SLEEP);
	kmdb_prom_term_init(kav, mdb.m_promif);
}
