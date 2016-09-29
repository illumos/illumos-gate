/*-
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

#include <sys/cdefs.h>

#include <stand.h>
#include <bootstrap.h>
#include <machine/cpufunc.h>
#include <dev/ic/ns16550.h>
#include <dev/pci/pcireg.h>
#include "libi386.h"

#define COMC_TXWAIT	0x40000		/* transmit timeout */
#define COMC_BPS(x)	(115200 / (x))	/* speed to DLAB divisor */
#define COMC_DIV2BPS(x)	(115200 / (x))	/* DLAB divisor to speed */

#ifndef	COMSPEED
#define COMSPEED	9600
#endif

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

static void	comc_probe(struct console *cp);
static int	comc_init(struct console *cp, int arg);
static void	comc_putchar(struct console *cp, int c);
static int	comc_getchar(struct console *cp);
static int	comc_getspeed(struct serial *sp);
static int	comc_ischar(struct console *cp);
static uint32_t comc_parse_pcidev(const char *string);
static int	comc_pcidev_set(struct env_var *ev, int flags,
		    const void *value);
static int	comc_pcidev_handle(struct console *cp, uint32_t locator);
static void	comc_setup(struct console *cp);
static char	*comc_print_mode(struct serial *sp, char *buf);
static int	comc_parse_mode(struct serial *sp, const char *value);
static int	comc_mode_set(struct env_var *, int, const void *);
static int	comc_cd_set(struct env_var *, int, const void *);
static int	comc_rtsdtr_set(struct env_var *, int, const void *);

struct console ttya = {
    "ttya",
    "serial port a",
    0,
    comc_probe,
    comc_init,
    comc_putchar,
    comc_getchar,
    comc_ischar,
    NULL
};

struct console ttyb = {
    "ttyb",
    "serial port b",
    0,
    comc_probe,
    comc_init,
    comc_putchar,
    comc_getchar,
    comc_ischar,
    NULL
};

struct console ttyc = {
    "ttyc",
    "serial port c",
    0,
    comc_probe,
    comc_init,
    comc_putchar,
    comc_getchar,
    comc_ischar,
    NULL
};

struct console ttyd = {
    "ttyd",
    "serial port d",
    0,
    comc_probe,
    comc_init,
    comc_putchar,
    comc_getchar,
    comc_ischar,
    NULL
};

static void
comc_probe(struct console *cp)
{
    struct serial *port;
    char name[20];
    char value[20];
    char *cons, *env;

    if (cp->private == NULL) {
	cp->private = malloc(sizeof(struct serial));
	port = cp->private;
	port->speed = COMSPEED;

	if (strcmp(cp->c_name, "ttya") == 0)
	    port->ioaddr = COM1_IOADDR;
	else if (strcmp(cp->c_name, "ttyb") == 0)
	    port->ioaddr = COM2_IOADDR;
	else if (strcmp(cp->c_name, "ttyc") == 0)
	    port->ioaddr = COM3_IOADDR;
	else if (strcmp(cp->c_name, "ttyd") == 0)
	    port->ioaddr = COM4_IOADDR;

	port->lcr = BITS8;	/* 8,n,1 */
	port->ignore_cd = 1;	/* ignore cd */
	port->rtsdtr_off = 0;	/* rts-dtr is on */

	/*
	 * Assume that the speed was set by an earlier boot loader if
	 * comconsole is already the preferred console.
	 */
	cons = getenv("console");
	if ((cons != NULL && strcmp(cons, cp->c_name) == 0) ||
	    getenv("boot_multicons") != NULL) {
		port->speed = comc_getspeed(port);
	}

	snprintf(name, 20, "%s-mode", cp->c_name);
	env = getenv(name);

	if (env != NULL) {
		(void) comc_parse_mode(port, env);
	}
	env = comc_print_mode(port, value);

	unsetenv(name);
	env_setenv(name, EV_VOLATILE, env, comc_mode_set, env_nounset);

	snprintf(name, 20, "%s-ignore-cd", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->ignore_cd = 1;
		else if (strcmp(env, "false") == 0)
			port->ignore_cd = 0;
	}

	sprintf(value, "%s", port->ignore_cd? "true":"false");
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, comc_cd_set, env_nounset);

	snprintf(name, 20, "%s-rts-dtr-off", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->rtsdtr_off = 1;
		else if (strcmp(env, "false") == 0)
			port->rtsdtr_off = 0;
	}

	sprintf(value, "%s", port->rtsdtr_off? "true":"false");
	unsetenv(name);
	env_setenv(name, EV_VOLATILE, value, comc_rtsdtr_set, env_nounset);

	snprintf(name, 20, "%s-pcidev", cp->c_name);
	env = getenv(name);
	if (env != NULL) {
	    port->locator = comc_parse_pcidev(env);
	    if (port->locator != 0)
		    comc_pcidev_handle(cp, port->locator);
	}

	unsetenv(name);
	env_setenv(name, EV_VOLATILE, env, comc_pcidev_set, env_nounset);
    }
    comc_setup(cp);
}

static int
comc_init(struct console *cp, int arg __attribute((unused)))
{

    comc_setup(cp);

    if ((cp->c_flags & (C_PRESENTIN | C_PRESENTOUT)) ==
	(C_PRESENTIN | C_PRESENTOUT))
	return (CMD_OK);
    return (CMD_ERROR);
}

static void
comc_putchar(struct console *cp, int c)
{
    int wait;
    struct serial *sp = cp->private;

    for (wait = COMC_TXWAIT; wait > 0; wait--)
        if (inb(sp->ioaddr + com_lsr) & LSR_TXRDY) {
	    outb(sp->ioaddr + com_data, (u_char)c);
	    break;
	}
}

static int
comc_getchar(struct console *cp)
{
    struct serial *sp = cp->private;
    return (comc_ischar(cp) ? inb(sp->ioaddr + com_data) : -1);
}

static int
comc_ischar(struct console *cp)
{
    struct serial *sp = cp->private;
    return (inb(sp->ioaddr + com_lsr) & LSR_RXRDY);
}

static char *
comc_print_mode(struct serial *sp, char *buf)
{
	char par;

	if ((sp->lcr & (PAREN|PAREVN)) == (PAREN|PAREVN))
		par = 'e';
	else if ((sp->lcr & PAREN) == PAREN)
		par = 'o';
	else
		par = 'n';

	sprintf(buf, "%d,%d,%c,%d,-", sp->speed,
	    (sp->lcr & BITS8) == BITS8? 8:7,
	    par, (par & STOP2) == STOP2? 2:1);
	return (buf);
}

static int
comc_parse_mode(struct serial *sp, const char *value)
{
	int n;
	int speed;
	int lcr;
	char *ep;

	n = strtol(value, &ep, 0);
	if (n > 0)
		speed = n;
	else
		return (CMD_ERROR);

	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	n = strtol(ep, &ep, 0);
	switch (n) {
	case 7: lcr = BITS7;
		break;
	case 8: lcr = BITS8;
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

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
get_console(char *name)
{
	struct console *cp = NULL;

	switch(name[3]) {
	case 'a': cp = &ttya;
		break;
	case 'b': cp = &ttyb;
		break;
	case 'c': cp = &ttyc;
		break;
	case 'd': cp = &ttyd;
		break;
	}
	return (cp);
}

static int
comc_mode_set(struct env_var *ev, int flags, const void *value)
{
    struct console *cp;

    if (value == NULL)
	return (CMD_ERROR);

    if ((cp = get_console(ev->ev_name)) == NULL)
	return (CMD_ERROR);

    if (comc_parse_mode(cp->private, value) == CMD_ERROR)
	return (CMD_ERROR);

    comc_setup(cp);

    env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

    return (CMD_OK);
}

static int
comc_cd_set(struct env_var *ev, int flags, const void *value)
{
    struct console *cp;
    struct serial *sp;

    if (value == NULL)
	return (CMD_ERROR);

    if ((cp = get_console(ev->ev_name)) == NULL)
	return (CMD_ERROR);

    sp = cp->private;
    if (strcmp(value, "true") == 0)
	sp->ignore_cd = 1;
    else if (strcmp(value, "false") == 0)
	sp->ignore_cd = 0;
    else
	return (CMD_ERROR);

    comc_setup(cp);

    env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

    return (CMD_OK);
}

static int
comc_rtsdtr_set(struct env_var *ev, int flags, const void *value)
{
    struct console *cp;
    struct serial *sp;

    if (value == NULL)
	return (CMD_ERROR);

    if ((cp = get_console(ev->ev_name)) == NULL)
	return (CMD_ERROR);

    sp = cp->private;
    if (strcmp(value, "true") == 0)
	sp->rtsdtr_off = 1;
    else if (strcmp(value, "false") == 0)
	sp->rtsdtr_off = 0;
    else
	return (CMD_ERROR);

    comc_setup(cp);

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
#ifdef NO_PCI
	(void)string;
	return (0);
#else
	char *p, *p1;
	uint8_t bus, dev, func, bar;
	uint32_t locator;
	int pres;

	pres = strtol(string, &p, 0);
	if (p == string || *p != ':' || pres < 0 )
		return (0);
	bus = pres;
	p1 = ++p;

	pres = strtol(p1, &p, 0);
	if (p == string || *p != ':' || pres < 0 )
		return (0);
	dev = pres;
	p1 = ++p;

	pres = strtol(p1, &p, 0);
	if (p == string || (*p != ':' && *p != '\0') || pres < 0 )
		return (0);
	func = pres;

	if (*p == ':') {
		p1 = ++p;
		pres = strtol(p1, &p, 0);
		if (p == string || *p != '\0' || pres <= 0 )
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
#ifdef NO_PCI
	(void)cp;
	(void)locator;
	return (CMD_ERROR);
#else
	struct serial *sp = cp->private;
	char intbuf[64];
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

	comc_setup(cp);
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
	sp = cp->private;

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

static void
comc_setup(struct console *cp)
{
    struct serial *sp = cp->private;
    static int TRY_COUNT = 1000000;
    int tries;

    if ((cp->c_flags & (C_ACTIVEIN | C_ACTIVEOUT)) == 0)
	return;

    outb(sp->ioaddr + com_cfcr, CFCR_DLAB | sp->lcr);
    outb(sp->ioaddr + com_dlbl, COMC_BPS(sp->speed) & 0xff);
    outb(sp->ioaddr + com_dlbh, COMC_BPS(sp->speed) >> 8);
    outb(sp->ioaddr + com_cfcr, sp->lcr);
    outb(sp->ioaddr + com_mcr,
	sp->rtsdtr_off? ~(MCR_RTS | MCR_DTR):MCR_RTS | MCR_DTR);

    tries = 0;
    do
        inb(sp->ioaddr + com_data);
    while (inb(sp->ioaddr + com_lsr) & LSR_RXRDY && ++tries < TRY_COUNT);

    if (tries < TRY_COUNT) {
	cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
    } else
	cp->c_flags &= ~(C_PRESENTIN | C_PRESENTOUT);
}

static int
comc_getspeed(struct serial *sp)
{
	u_int	divisor;
	u_char	dlbh;
	u_char	dlbl;
	u_char	cfcr;

	cfcr = inb(sp->ioaddr + com_cfcr);
	outb(sp->ioaddr + com_cfcr, CFCR_DLAB | cfcr);

	dlbl = inb(sp->ioaddr + com_dlbl);
	dlbh = inb(sp->ioaddr + com_dlbh);

	outb(sp->ioaddr + com_cfcr, cfcr);

	divisor = dlbh << 8 | dlbl;

	/* XXX there should be more sanity checking. */
	if (divisor == 0)
		return (COMSPEED);
	return (COMC_DIV2BPS(divisor));
}
