/*
 * Copyright (c) 1998 Michael Smith (msmith@freebsd.org)
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
 * This code is shared on BIOS and UEFI systems on x86 because
 * we can access io ports on both platforms and the UEFI Serial IO protocol
 * is not giving us reliable port order and we see issues with input.
 */
#include <sys/cdefs.h>

#include <stand.h>
#include <bootstrap.h>
#include <stdbool.h>
#include <machine/cpufunc.h>
#include <dev/ic/ns16550.h>
#include <dev/pci/pcireg.h>
#include "libi386.h"

#define	COMC_TXWAIT	0x40000		/* transmit timeout */
#define	COMC_BPS(x)	(115200 / (x))	/* speed to DLAB divisor */
#define	COMC_DIV2BPS(x)	(115200 / (x))	/* DLAB divisor to speed */

#ifndef	COMSPEED
#define	COMSPEED	9600
#endif

#define	COM_NPORTS	4
#define	COM1_IOADDR	0x3f8
#define	COM2_IOADDR	0x2f8
#define	COM3_IOADDR	0x3e8
#define	COM4_IOADDR	0x2e8

#define	STOP1		0x00
#define	STOP2		0x04

#define	PARODD		0x00
#define	PAREN		0x08
#define	PAREVN		0x10
#define	PARMARK		0x20

#define	BITS5		0x00	/* 5 bits per char */
#define	BITS6		0x01	/* 6 bits per char */
#define	BITS7		0x02	/* 7 bits per char */
#define	BITS8		0x03	/* 8 bits per char */

struct serial {
    int		speed;		/* baud rate */
    uint8_t	lcr;		/* line control */
    uint8_t	ignore_cd;	/* boolean */
    uint8_t	rtsdtr_off;	/* boolean */
    int		ioaddr;
    uint32_t	locator;
};

static void	comc_probe(struct console *);
static int	comc_init(struct console *, int);
static void	comc_putchar(struct console *, int);
static int	comc_getchar(struct console *);
int		comc_getspeed(int);
static int	comc_ischar(struct console *);
static int	comc_ioctl(struct console *, int, void *);
static uint32_t comc_parse_pcidev(const char *);
static int	comc_pcidev_set(struct env_var *, int, const void *);
static int	comc_pcidev_handle(struct console *, uint32_t);
static bool	comc_setup(struct console *);
static char	*comc_asprint_mode(struct serial *);
static int	comc_parse_mode(struct serial *, const char *);
static int	comc_mode_set(struct env_var *, int, const void *);
static int	comc_cd_set(struct env_var *, int, const void *);
static int	comc_rtsdtr_set(struct env_var *, int, const void *);
static void	comc_devinfo(struct console *);

static void
comc_devinfo(struct console *cp)
{
	struct serial *port = cp->c_private;

	printf("\tport %#x", port->ioaddr);
}

static bool
comc_port_is_present(int ioaddr)
{
	/*
	 * Write byte to scratch register and read it out.
	 */
#define	COMC_TEST	0xbb
	outb(ioaddr + com_scr, COMC_TEST);
	return (inb(ioaddr + com_scr) == COMC_TEST);
}

/*
 * Set up list of possible serial consoles.
 * This function is run very early, so we do not expect to
 * run out of memory, and on error, we can not print output.
 */
void
comc_ini(void)
{
	uint_t n = 0, c;
	bool ports[COM_NPORTS];
	struct console **tmp;
	struct console *tty;
	struct serial *port;

	/*
	 * Test the presence of 4 serial devices com1-com4
	 */
	ports[0] = comc_port_is_present(COM1_IOADDR);
	ports[1] = comc_port_is_present(COM2_IOADDR);
	ports[2] = comc_port_is_present(COM3_IOADDR);
	ports[3] = comc_port_is_present(COM4_IOADDR);

	for (uint_t i = 0; i < COM_NPORTS; i++)
		if (ports[i])
			n++;

	if (n == 0)	/* there are no serial ports */
		return;

	c = cons_array_size();
	if (c == 0)
		n++;	/* For NULL pointer */

	tmp = realloc(consoles, (c + n) * sizeof (*consoles));
	if (tmp == NULL)
		return;
	consoles = tmp;
	if (c > 0)
		c--;

	for (uint_t i = 0; i < COM_NPORTS; i++) {
		if (!ports[i])
			continue;
		tty = malloc(sizeof (*tty));
		if (tty == NULL) {
			/* Out of memory?! can not continue */
			consoles[c] = tty;
			return;
		}
		if (asprintf(&tty->c_name, "tty%c", 'a' + i) < 0) {
			free(tty);
			consoles[c] = NULL;
			return;
		}
		if (asprintf(&tty->c_desc, "serial port %c", 'a' + i) < 0) {
			free(tty->c_name);
			free(tty);
			consoles[c] = NULL;
			return;
		}
		tty->c_flags = 0;
		tty->c_probe = comc_probe;
		tty->c_init = comc_init;
		tty->c_out = comc_putchar;
		tty->c_in = comc_getchar;
		tty->c_ready = comc_ischar;
		tty->c_ioctl = comc_ioctl;
		tty->c_devinfo = comc_devinfo;
		port = malloc(sizeof (*port));
		if (port == NULL) {
			free(tty->c_name);
			free(tty->c_desc);
			free(tty);
			consoles[c] = NULL;
			return;
		}
		port->speed = 0;	/* Leave this for comc_probe */
		switch (i) {
		case 0:
			port->ioaddr = COM1_IOADDR;
			break;
		case 1:
			port->ioaddr = COM2_IOADDR;
			break;
		case 2:
			port->ioaddr = COM3_IOADDR;
			break;
		case 3:
			port->ioaddr = COM4_IOADDR;
			break;
		}
		port->speed = comc_getspeed(port->ioaddr);
		port->lcr = BITS8;	/* 8,n,1 */
		port->ignore_cd = 1;	/* ignore cd */
		port->rtsdtr_off = 0;	/* rts-dtr is on */

		tty->c_private = port;
		consoles[c++] = tty;

		/* Reset terminal to initial normal settings with ESC [ 0 m */
		comc_putchar(tty, 0x1b);
		comc_putchar(tty, '[');
		comc_putchar(tty, '0');
		comc_putchar(tty, 'm');
		/* drain input from random data */
		while (comc_getchar(tty) != -1)
			;
	}
	consoles[c] = NULL;
}

static void
comc_probe(struct console *cp)
{
	struct serial *port;
	char name[20];
	char value[20];
	char *env;

	port = cp->c_private;
	if (port->speed != 0)
		return;

	port->speed = COMSPEED;

	/*
	 * Assume that the speed was set by an earlier boot loader if
	 * comconsole is already the preferred console.
	 */
	snprintf(name, sizeof (name), "%s-mode", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		port->speed = comc_getspeed(port->ioaddr);
	}
	env = comc_asprint_mode(port);

	if (env != NULL) {
		unsetenv(name);
		env_setenv(name, EV_VOLATILE, env, comc_mode_set, env_nounset);
		free(env);
	}

	snprintf(name, sizeof (name), "%s-ignore-cd", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->ignore_cd = 1;
		else if (strcmp(env, "false") == 0)
			port->ignore_cd = 0;
	}

	snprintf(value, sizeof (value), "%s",
	    port->ignore_cd? "true" : "false");
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, comc_cd_set, env_nounset);

	snprintf(name, sizeof (name), "%s-rts-dtr-off", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->rtsdtr_off = 1;
		else if (strcmp(env, "false") == 0)
			port->rtsdtr_off = 0;
	}

	snprintf(value, sizeof (value), "%s",
	    port->rtsdtr_off? "true" : "false");
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, comc_rtsdtr_set, env_nounset);

	snprintf(name, sizeof (name), "%s-pcidev", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		port->locator = comc_parse_pcidev(env);
		if (port->locator != 0)
			comc_pcidev_handle(cp, port->locator);
	}

	unsetenv(name);
	env_setenv(name, EV_VOLATILE, env, comc_pcidev_set, env_nounset);

	cp->c_flags = 0;
	if (comc_setup(cp))
		cp->c_flags = C_PRESENTIN | C_PRESENTOUT;
}

static int
comc_init(struct console *cp, int arg __attribute((unused)))
{

	if (comc_setup(cp))
		return (CMD_OK);

	cp->c_flags = 0;
	return (CMD_ERROR);
}

static void
comc_putchar(struct console *cp, int c)
{
	int wait;
	struct serial *sp = cp->c_private;

	for (wait = COMC_TXWAIT; wait > 0; wait--)
		if (inb(sp->ioaddr + com_lsr) & LSR_TXRDY) {
			outb(sp->ioaddr + com_data, (uchar_t)c);
			break;
		}
}

static int
comc_getchar(struct console *cp)
{
	struct serial *sp = cp->c_private;
	return (comc_ischar(cp) ? inb(sp->ioaddr + com_data) : -1);
}

static int
comc_ischar(struct console *cp)
{
	struct serial *sp = cp->c_private;
	return (inb(sp->ioaddr + com_lsr) & LSR_RXRDY);
}

static int
comc_ioctl(struct console *cp __unused, int cmd __unused, void *data __unused)
{
	return (ENOTTY);
}

static char *
comc_asprint_mode(struct serial *sp)
{
	char par, *buf;

	if (sp == NULL)
		return (NULL);

	if ((sp->lcr & (PAREN|PAREVN)) == (PAREN|PAREVN))
		par = 'e';
	else if ((sp->lcr & PAREN) == PAREN)
		par = 'o';
	else
		par = 'n';

	asprintf(&buf, "%d,%d,%c,%d,-", sp->speed,
	    (sp->lcr & BITS8) == BITS8? 8:7,
	    par, (sp->lcr & STOP2) == STOP2? 2:1);
	return (buf);
}

static int
comc_parse_mode(struct serial *sp, const char *value)
{
	unsigned long n;
	int speed;
	int lcr;
	char *ep;

	if (value == NULL || *value == '\0')
		return (CMD_ERROR);

	errno = 0;
	n = strtoul(value, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);
	speed = n;

	ep++;
	errno = 0;
	n = strtoul(ep, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);

	switch (n) {
	case 7: lcr = BITS7;
		break;
	case 8: lcr = BITS8;
		break;
	default:
		return (CMD_ERROR);
	}

	ep++;
	switch (*ep++) {
	case 'n':
		break;
	case 'e': lcr |= PAREN|PAREVN;
		break;
	case 'o': lcr |= PAREN|PARODD;
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '1':
		break;
	case '2': lcr |= STOP2;
		break;
	default:
		return (CMD_ERROR);
	}

	/* handshake is ignored, but we check syntax anyhow */
	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '-':
	case 'h':
	case 's':
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep != '\0')
		return (CMD_ERROR);

	sp->speed = speed;
	sp->lcr = lcr;
	return (CMD_OK);
}

static struct console *
get_console(const char *name)
{
	char port[5];

	(void) strlcpy(port, name, sizeof (port));
	for (uint_t i = 0; consoles[i] != NULL; i++) {
		if (strcmp(port, consoles[i]->c_name) == 0)
			return (consoles[i]);
	}

	printf("No such port: %s\n", port);
	return (NULL);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port, or there is invalid value in mode line.
 */
static int
comc_mode_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	char name[15];

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	/* Do not override serial setup from SPCR */
	snprintf(name, sizeof (name), "%s-spcr-mode", cp->c_name);
	if (getenv(name) == NULL) {
		if (comc_parse_mode(cp->c_private, value) == CMD_ERROR) {
			printf("%s: invalid mode: %s\n", ev->ev_name,
			    (char *)value);
			return (CMD_OK);
		}
		(void) comc_setup(cp);
		env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	}

	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port or invalid value was used.
 */
static int
comc_cd_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	struct serial *sp;

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	sp = cp->c_private;
	if (strcmp(value, "true") == 0) {
		sp->ignore_cd = 1;
	} else if (strcmp(value, "false") == 0) {
		sp->ignore_cd = 0;
	} else {
		printf("%s: invalid value: %s\n", ev->ev_name,
		    (char *)value);
		return (CMD_ERROR);
	}

	(void) comc_setup(cp);

	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port, or invalid value was used.
 */
static int
comc_rtsdtr_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	struct serial *sp;

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	sp = cp->c_private;
	if (strcmp(value, "true") == 0) {
		sp->rtsdtr_off = 1;
	} else if (strcmp(value, "false") == 0) {
		sp->rtsdtr_off = 0;
	} else {
		printf("%s: invalid value: %s\n", ev->ev_name,
		    (char *)value);
		return (CMD_ERROR);
	}

	(void) comc_setup(cp);

	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

/*
 * Input: bus:dev:func[:bar]. If bar is not specified, it is 0x10.
 * Output: bar[24:16] bus[15:8] dev[7:3] func[2:0]
 */
static uint32_t
comc_parse_pcidev(const char *string)
{
#ifdef EFI
	(void) string;
	return (0);
#else
	char *p, *p1;
	uint8_t bus, dev, func, bar;
	uint32_t locator;
	int pres;

	errno = 0;
	pres = strtoul(string, &p, 10);
	if (errno != 0 || p == string || *p != ':' || pres < 0)
		return (0);
	bus = pres;
	p1 = ++p;

	pres = strtoul(p1, &p, 10);
	if (errno != 0 || p == string || *p != ':' || pres < 0)
		return (0);
	dev = pres;
	p1 = ++p;

	pres = strtoul(p1, &p, 10);
	if (errno != 0 || p == string || (*p != ':' && *p != '\0') || pres < 0)
		return (0);
	func = pres;

	if (*p == ':') {
		p1 = ++p;
		pres = strtoul(p1, &p, 10);
		if (errno != 0 || p == string || *p != '\0' || pres <= 0)
			return (0);
		bar = pres;
	} else
		bar = 0x10;

	locator = (bar << 16) | biospci_locator(bus, dev, func);
	return (locator);
#endif
}

static int
comc_pcidev_handle(struct console *cp, uint32_t locator)
{
#ifdef EFI
	(void) cp;
	(void) locator;
	return (CMD_ERROR);
#else
	struct serial *sp = cp->c_private;
	uint32_t port;

	if (biospci_read_config(locator & 0xffff,
	    (locator & 0xff0000) >> 16, 2, &port) == -1) {
		printf("Cannot read bar at 0x%x\n", locator);
		return (CMD_ERROR);
	}
	if (!PCI_BAR_IO(port)) {
		printf("Memory bar at 0x%x\n", locator);
		return (CMD_ERROR);
	}
	port &= PCIM_BAR_IO_BASE;

	(void) comc_setup(cp);

	sp->locator = locator;

	return (CMD_OK);
#endif
}

static int
comc_pcidev_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	struct serial *sp;
	uint32_t locator;
	int error;

	if ((cp = get_console(ev->ev_name)) == NULL)
		return (CMD_ERROR);
	sp = cp->c_private;

	if (value == NULL || (locator = comc_parse_pcidev(value)) <= 0) {
		printf("Invalid pcidev\n");
		return (CMD_ERROR);
	}
	if ((cp->c_flags & (C_ACTIVEIN | C_ACTIVEOUT)) != 0 &&
	    sp->locator != locator) {
		error = comc_pcidev_handle(cp, locator);
		if (error != CMD_OK)
			return (error);
	}
	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);
	return (CMD_OK);
}

/*
 * In case of error, we also reset ACTIVE flags, so the console
 * framefork will try alternate consoles.
 */
static bool
comc_setup(struct console *cp)
{
	struct serial *sp = cp->c_private;
	static int TRY_COUNT = 1000000;
	int tries;

	outb(sp->ioaddr + com_cfcr, CFCR_DLAB | sp->lcr);
	outb(sp->ioaddr + com_dlbl, COMC_BPS(sp->speed) & 0xff);
	outb(sp->ioaddr + com_dlbh, COMC_BPS(sp->speed) >> 8);
	outb(sp->ioaddr + com_cfcr, sp->lcr);
	outb(sp->ioaddr + com_mcr,
	    sp->rtsdtr_off? ~(MCR_RTS | MCR_DTR) : MCR_RTS | MCR_DTR);

	tries = 0;
	do {
		inb(sp->ioaddr + com_data);
	} while (inb(sp->ioaddr + com_lsr) & LSR_RXRDY && ++tries < TRY_COUNT);

	if (tries == TRY_COUNT)
		return (false);
	/* Mark this port usable. */
	cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
	return (true);
}

int
comc_getspeed(int ioaddr)
{
	uint_t	divisor;
	uchar_t	dlbh;
	uchar_t	dlbl;
	uchar_t	cfcr;

	cfcr = inb(ioaddr + com_cfcr);
	outb(ioaddr + com_cfcr, CFCR_DLAB | cfcr);

	dlbl = inb(ioaddr + com_dlbl);
	dlbh = inb(ioaddr + com_dlbh);

	outb(ioaddr + com_cfcr, cfcr);

	divisor = dlbh << 8 | dlbl;

	/* XXX there should be more sanity checking. */
	if (divisor == 0)
		return (COMSPEED);
	return (COMC_DIV2BPS(divisor));
}
