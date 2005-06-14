/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/bootsvcs.h>
#include <sys/varargs.h>
#include <sys/promif.h>
#include <sys/salib.h>
#include "serial.h"
#include "chario.h"
#include "vga.h"
#include "console.h"
#include "debug.h"
#include "graphics.h"
#include "bootprop.h"

static int cons_color = CONS_COLOR;
int console = CONS_SCREEN_TEXT;
/* or CONS_SCREEN_GRAPHICS, CONS_TTYA, CONS_TTYB */
static int serial_ischar(void);
static int serial_getchar(void);
static void serial_putchar(int);
static void serial_adjust_prop(void);
static int console_state = 0;

/* Clear the screen and initialize VIDEO, XPOS and YPOS. */
static void
clear_screen(void)
{
	/*
	 * XXX should set vga mode so we don't depend on the
	 * state left by the boot loader
	 */
	vga_clear(cons_color);
	vga_setpos(0, 0);
}

void
text_init(void)
{
	set_videomode(0x3);
	clear_screen();
}

/* Put the character C on the screen. */
static void
screen_putchar(int c)
{
	int row, col;

	vga_getpos(&row, &col);
	switch (c) {
	case '\r':
		vga_setpos(row, 0);
		break;

	case '\b':
		if (col > 0)
			vga_setpos(row, col - 1);
		break;

	case '\n':
		if (row < VGA_TEXT_ROWS - 1)
			vga_setpos(row + 1, col);
		else
			vga_scroll(cons_color);
		break;

	default:
		vga_drawc(c, cons_color);
		if (col < VGA_TEXT_COLS -1)
			vga_setpos(row, col + 1);
		else if (row < VGA_TEXT_ROWS - 1)
			vga_setpos(row + 1, 0);
		else {
			vga_setpos(row, 0);
			vga_scroll(cons_color);
		}
		break;
	}
}

/* serial port stuff */
static int port;

static void
serial_init(void)
{
	extern void mdelay();

	/* initialize only once */
	if (port != 0)
		return;

	/*
	 * wait 2 seconds for serial console redirection to settle
	 * NOTE we only need to wait if BIOS console redirection
	 *	is enabled, but we can't really tell without working
	 *	through a scary Microsoft license.
	 */
	mdelay(2000);

	switch (console) {
	case CONS_TTYA:
		port = 0x3f8;
		break;
	case CONS_TTYB:
		port = 0x2f8;
		break;
	}

	outb(port + ISR, 0x20);
	if (inb(port + ISR) & 0x20) {
		/*
		 * 82510 chip is present
		 */
		outb(port + DAT+7, 0x04);	/* clear status */
		outb(port + ISR, 0x40);  /* set to bank 2 */
		outb(port + MCR, 0x08);  /* IMD */
		outb(port + DAT, 0x21);  /* FMD */
		outb(port + ISR, 0x00);  /* set to bank 0 */
	} else {
		/*
		 * set the UART in FIFO mode if it has FIFO buffers.
		 * use 16550 fifo reset sequence specified in NS
		 * application note. disable fifos until chip is
		 * initialized.
		 */
		outb(port + FIFOR, 0x00);		/* clear */
		outb(port + FIFOR, FIFO_ON);		/* enable */
		outb(port + FIFOR, FIFO_ON|FIFORXFLSH);  /* reset */
		outb(port + FIFOR,
		    FIFO_ON|FIFODMA|FIFOTXFLSH|FIFORXFLSH|0x80);
		if ((inb(port + ISR) & 0xc0) != 0xc0) {
			/*
			 * no fifo buffers so disable fifos.
			 * this is true for 8250's
			 */
			outb(port + FIFOR, 0x00);
		}
	}

	/* disable interrupts */
	outb(port + ICR, 0);

	/* adjust setting based on tty properties */
	serial_adjust_prop();

	/*
	 * Do a full reset to match console behavior.
	 * In verbose mode (-V), we only reset ansi attributes,
	 * leaving existing output on screen.
	 * 0x1B + c - reset everything
	 * 0x1B +
	 *	[ - attribute change (blick, inverse, color, etc.)
	 *	0 - attribute value
	 *	m - terminate escape sequence
	 *
	 */
	if (verbosemode) {
		serial_putchar(0x1B);
		serial_putchar('[');
		serial_putchar('0');
		serial_putchar('m');
	} else {
		serial_putchar(0x1B);
		serial_putchar('c');
	}
}

/* adjust serial port based on properties */
static void
serial_adjust_prop(void)
{
	int plen;
	char propname[20], propval[20];

	(void) snprintf(propname, sizeof (propname), "tty%c-mode",
	    'a' + console - CONS_TTYA);
	plen = bgetproplen(NULL, propname);
	if (plen > 0 && plen <= sizeof (propval)) {
		char *p;
		ulong_t baud;
		uchar_t lcr = 0;

		/* property is of the form: "9600,8,n,1,-" */
		bgetprop(NULL, propname, propval);
		p = strtok(propval, ",");
		if (strcmp(p, "110") == 0)
			baud = ASY110;
		else if (strcmp(p, "150") == 0)
			baud = ASY150;
		else if (strcmp(p, "300") == 0)
			baud = ASY300;
		else if (strcmp(p, "600") == 0)
			baud = ASY600;
		else if (strcmp(p, "1200") == 0)
			baud = ASY1200;
		else if (strcmp(p, "2400") == 0)
			baud = ASY2400;
		else if (strcmp(p, "4800") == 0)
			baud = ASY4800;
		else if (strcmp(p, "19200") == 0)
			baud = ASY19200;
		else if (strcmp(p, "38400") == 0)
			baud = ASY38400;
		else if (strcmp(p, "57600") == 0)
			baud = ASY57600;
		else if (strcmp(p, "115200") == 0)
			baud = ASY115200;
		else
			baud = ASY9600;

		/* set baud */
		outb(port + LCR, DLAB);
		outb(port + DAT+DLL, baud & 0xff);
		outb(port + DAT+DLH, (baud >> 8) & 0xff);

		p = strtok(NULL, ",");
		if (p) {
			switch (*p) {
			case '5':
				lcr |= BITS5;
				break;
			case '6':
				lcr |= BITS6;
				break;
			case '7':
				lcr |= BITS7;
				break;
			case '8':
			default:
				lcr |= BITS8;
				break;
			}
		}

		p = strtok(NULL, ",");
		if (p) {
			switch (*p) {
			case 'n':
				lcr |= PARITY_NONE;
				break;
			case 'o':
				lcr |= PARITY_ODD;
				break;
			case 'e':
			default:
				lcr |= PARITY_EVEN;
				break;
			}
		}

		p = strtok(NULL, ",");
		if (p) {
			switch (*p) {
			case '1':
				/* STOP1 is 0 */
				break;
			default:
				lcr |= STOP2;
				break;
			}
		}

		/* set parity bits */
		outb(port + LCR, lcr);
	}

	(void) snprintf(propname, sizeof (propname),
	    "tty%c-rts-dtr-off", 'a' + console - CONS_TTYA);
	plen = bgetproplen(NULL, propname);
	if (plen > 0 && plen <= sizeof (propval)) {
		char *p;
		uchar_t mcr = DTR | RTS;
		bgetprop(NULL, propname, propval);
		if (propval[0] != 'f' && propval[0] != 'F')
			mcr = 0;
		/* set modem control bits */
		outb(port + MCR, mcr | OUT2);
	}
}

void
console_init(char *bootstr)
{
	char *cons;

	console = CONS_INVALID;

	cons = strstr(bootstr, "console=");
	if (cons) {
		cons += strlen("console=");
		if (strncmp(cons, "ttya", 4) == 0)
			console = CONS_TTYA;
		else if (strncmp(cons, "ttyb", 4) == 0)
			console = CONS_TTYB;
		else if (strncmp(cons, "graphics", 9) == 0)
			console = CONS_SCREEN_GRAPHICS;
		else if (strncmp(cons, "text", 4) == 0)
			console = CONS_SCREEN_TEXT;
	}

	/*
	 * If no console device specified, default to text.
	 * Remember what was specified for second phase.
	 */
	console_state = console;
	if (console == CONS_INVALID)
		console = CONS_SCREEN_TEXT;

	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		/* leave initialization till later, when we know tty mode */
		break;
	case CONS_SCREEN_TEXT:
	default:
		clear_screen();
		kb_init();
		break;
		/*
		 * if console is CONS_SCREEN_GRAPHICS,
		 * initialize it in console_init2()
		 */
	}
}

/*
 * Second phase of possible console redirection,
 * based on input-device & output-device eeprom(1M) properties.
 * Also support a unified "console" property.
 */
void
console_init2(char *inputdev, char *outputdev, char *consoledev)
{
	int cons = CONS_INVALID;

	if (console_state == CONS_INVALID) {

		if (consoledev) {
			if (strcmp(consoledev, "ttya") == 0)
				cons = CONS_TTYA;
			else if (strcmp(consoledev, "ttyb") == 0)
				cons = CONS_TTYB;
			else if (strcmp(consoledev, "text") == 0)
				cons = CONS_SCREEN_TEXT;
			else if (strcmp(consoledev, "graphics") == 0)
				cons = CONS_SCREEN_GRAPHICS;
		}

		if (cons == CONS_INVALID) {
			if (inputdev) {
				if (strcmp(inputdev, "ttya") == 0)
					cons = CONS_TTYA;
				else if (strcmp(inputdev, "ttyb") == 0)
					cons = CONS_TTYB;
			}
			if (outputdev) {
				if (strcmp(outputdev, "ttya") == 0)
					cons = CONS_TTYA;
				else if (strcmp(outputdev, "ttyb") == 0)
					cons = CONS_TTYB;
			}
		}

		if (cons == CONS_INVALID)
			cons = CONS_SCREEN_TEXT;
		console = cons;

		switch (console) {
		case CONS_TTYA:
		case CONS_TTYB:
			if (console_state != CONS_TTYA &&
			    console_state != CONS_TTYB) {
				serial_init();
			}
			break;
		case CONS_SCREEN_TEXT:
			if (console_state != CONS_SCREEN_TEXT) {
				clear_screen();
				kb_init();
			}
			break;
		}
	}

	/* special handling for graphics boot and serial console */
	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		serial_init();
		break;
	case CONS_SCREEN_GRAPHICS:
		if (!graphics_init())
			printf("failed to initialize "
			    "console to graphics mode\n");
		break;
	};
}

static void
serial_putchar(int c)
{
	int checks = 10000;

	while (((inb(port + LSR) & XHRE) == 0) && checks--)
		;
	outb(port + DAT, (char)c);
}

static int
serial_getchar(void)
{
	uchar_t lsr;

	while (serial_ischar() == 0)
		;

	lsr = inb(port + LSR);
	if (lsr & (SERIAL_BREAK | SERIAL_FRAME |
	    SERIAL_PARITY | SERIAL_OVERRUN)) {
		if (lsr & SERIAL_OVERRUN) {
			printf("silo overflow\n");
			return (inb(port + DAT));
		} else {
			/* Toss the garbage */
			(void) inb(port + DAT);
			return (0);
		}
	}
	return (inb(port + DAT));
}

static int
serial_ischar(void)
{
	return (inb(port + LSR) & RCA);
}

static void
_doputchar(int c)
{
	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		serial_putchar(c);
		return;
	case CONS_SCREEN_TEXT:
		screen_putchar(c);
		return;
	case CONS_SCREEN_GRAPHICS:
		if (verbosemode)
			graphics_putchar(c);
	}
}

void
putchar(int c)
{
	static int bhcharpos = 0;

	if (c == '\t') {
			do {
				_doputchar(' ');
			} while (++bhcharpos % 8);
			return;
	} else  if (c == '\n' || c == '\r') {
			bhcharpos = 0;
			_doputchar('\r');
			_doputchar(c);
			return;
	} else if (c == '\b') {
			if (bhcharpos)
				bhcharpos--;
			_doputchar(c);
			return;
	}

	bhcharpos++;
	_doputchar(c);
}


int
getchar(void)
{
	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		return (serial_getchar());
	default:
		return (kb_getchar());
	}
}

int
ischar(void)
{
	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		return (serial_ischar());
	default:
		return (kb_ischar());
	}
}

/*
 * Read from the console (using getchar) into string str,
 * until a carriage return or until n-1 characters are read.
 * Null terminate the string, and return.
 * This all is made complicated by the fact that we must
 * do our own echoing during input.
 * N.B.: Returns the *number of characters in str*.
 */

int
cons_gets(char *str, int n)
{
	int 	c;
	int	t;
	char	*p;

	p = str;
	c = 0;

	while ((t = getchar()) != '\r') {
		putchar(t);
		if (t == '\b') {
			if (c) {
				printf(" \b");
				c--; p--;
			} else
				putchar(' ');
			continue;
		}
		if (c < n - 1) {
			*p++ = t;
			c++;
		}
	}
	putchar('\n');
	*p = '\0';

	return (c);
}

/*PRINTFLIKE1*/
void
printf(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	prom_vprintf(fmt, adx);
	va_end(adx);
}

/* setup boot syscall fields needed by the kernel */
static struct boot_syscalls sc = {
	getchar,
	putchar,
	ischar
};

struct boot_syscalls *sysp = &sc;
