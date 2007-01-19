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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/boot_console.h>

#include "boot_serial.h"
#include "boot_vga.h"

#if defined(_BOOT)
#include "../dboot/dboot_xboot.h"
#include <util/string.h>
#else
#include <sys/bootconf.h>
static char *usbser_buf;
static char *usbser_cur;
#endif

static int cons_color = CONS_COLOR;
int console = CONS_SCREEN_TEXT;
/* or CONS_TTYA, CONS_TTYB */
static int serial_ischar(void);
static int serial_getchar(void);
static void serial_putchar(int);
static void serial_adjust_prop(void);

static char *boot_line = NULL;

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

/* Put the character C on the screen. */
static void
screen_putchar(int c)
{
	int row, col;

	vga_getpos(&row, &col);
	switch (c) {
	case '\t':
		col += 8 - (col % 8);
		if (col == VGA_TEXT_COLS)
			col = 79;
		vga_setpos(row, col);
		break;

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

#if defined(_BOOT)
	/*
	 * Do a full reset to match console behavior.
	 * 0x1B + c - reset everything
	 */
	serial_putchar(0x1B);
	serial_putchar('c');
#endif
}


#define	MATCHES(p, pat)	\
	(strncmp(p, pat, strlen(pat)) == 0 ? (p += strlen(pat), 1) : 0)

#define	SKIP(p, c)				\
	while (*(p) != 0 && *p != (c))		\
		++(p);				\
	if (*(p) == (c))			\
		++(p);

/*
 * find a tty mode property either from cmdline or from boot properties
 */
static char *
get_mode_value(char *name)
{
	char *p;

	/*
	 * when specified on boot line it looks like "name" "="....
	 */
	if (boot_line != NULL) {
		p = strstr(boot_line, name);
		if (p == NULL)
			return (NULL);
		SKIP(p, '=');
		return (p);
	}

#if defined(_BOOT)
	return (NULL);
#else
	/*
	 * if we're running in the full kernel we check the bootenv.rc settings
	 */
	{
		static char propval[20];

		propval[0] = 0;
		if (bootops == NULL || BOP_GETPROPLEN(bootops, name) == 0)
			return (NULL);
		(void) BOP_GETPROP(bootops, name, propval);
		return (propval);
	}
#endif
}

/*
 * adjust serial port based on properties
 * These come either from the cmdline or from boot properties.
 */
static void
serial_adjust_prop(void)
{
	char propname[20];
	char *propval;
	char *p;
	ulong_t baud;
	uchar_t lcr = 0;
	uchar_t mcr = DTR | RTS;

	(void) strcpy(propname, "ttyX-mode");
	propname[3] = 'a' + console - CONS_TTYA;
	propval = get_mode_value(propname);
	if (propval == NULL)
		propval = "9600,8,n,1,-";

	/* property is of the form: "9600,8,n,1,-" */
	p = propval;
	if (MATCHES(p, "110,"))
		baud = ASY110;
	else if (MATCHES(p, "150,"))
		baud = ASY150;
	else if (MATCHES(p, "300,"))
		baud = ASY300;
	else if (MATCHES(p, "600,"))
		baud = ASY600;
	else if (MATCHES(p, "1200,"))
		baud = ASY1200;
	else if (MATCHES(p, "2400,"))
		baud = ASY2400;
	else if (MATCHES(p, "4800,"))
		baud = ASY4800;
	else if (MATCHES(p, "19200,"))
		baud = ASY19200;
	else if (MATCHES(p, "38400,"))
		baud = ASY38400;
	else if (MATCHES(p, "57600,"))
		baud = ASY57600;
	else if (MATCHES(p, "115200,"))
		baud = ASY115200;
	else {
		baud = ASY9600;
		SKIP(p, ',');
	}
	outb(port + LCR, DLAB);
	outb(port + DAT + DLL, baud & 0xff);
	outb(port + DAT + DLH, (baud >> 8) & 0xff);

	switch (*p) {
	case '5':
		lcr |= BITS5;
		++p;
		break;
	case '6':
		lcr |= BITS6;
		++p;
		break;
	case '7':
		lcr |= BITS7;
		++p;
		break;
	case '8':
		++p;
	default:
		lcr |= BITS8;
		break;
	}

	SKIP(p, ',');

	switch (*p) {
	case 'n':
		lcr |= PARITY_NONE;
		++p;
		break;
	case 'o':
		lcr |= PARITY_ODD;
		++p;
		break;
	case 'e':
		++p;
	default:
		lcr |= PARITY_EVEN;
		break;
	}


	SKIP(p, ',');

	switch (*p) {
	case '1':
		/* STOP1 is 0 */
		++p;
		break;
	default:
		lcr |= STOP2;
		break;
	}
	/* set parity bits */
	outb(port + LCR, lcr);

	(void) strcpy(propname, "ttyX-rts-dtr-off");
	propname[3] = 'a' + console - CONS_TTYA;
	propval = get_mode_value(propname);
	if (propval == NULL)
		propval = "false";
	if (propval[0] != 'f' && propval[0] != 'F')
		mcr = 0;
	/* set modem control bits */
	outb(port + MCR, mcr | OUT2);
}

void
bcons_init(char *bootstr)
{
	boot_line = bootstr;
	console = CONS_INVALID;

	if (strstr(bootstr, "console=ttya") != 0)
		console = CONS_TTYA;
	else if (strstr(bootstr, "console=ttyb") != 0)
		console = CONS_TTYB;
	else if (strstr(bootstr, "console=text") != 0)
		console = CONS_SCREEN_TEXT;

	/*
	 * If no console device specified, default to text.
	 * Remember what was specified for second phase.
	 */
	if (console == CONS_INVALID)
		console = CONS_SCREEN_TEXT;

	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		serial_init();
		break;

	case CONS_SCREEN_TEXT:
	default:
#if defined(_BOOT)
		clear_screen();	/* clears the grub screen */
#endif
		kb_init();
		break;
	}
	boot_line = NULL;
}

/*
 * 2nd part of console initialization.
 * In the kernel (ie. fakebop), this can be used only to switch to
 * using a serial port instead of screen based on the contents
 * of the bootenv.rc file.
 */
/*ARGSUSED*/
void
bcons_init2(char *inputdev, char *outputdev, char *consoledev)
{
#if !defined(_BOOT)
	int cons = CONS_INVALID;

	if (consoledev) {
		if (strstr(consoledev, "ttya") != 0)
			cons = CONS_TTYA;
		else if (strstr(consoledev, "ttyb") != 0)
			cons = CONS_TTYB;
		else if (strstr(consoledev, "usb-serial") != 0)
			cons = CONS_USBSER;
	}

	if (cons == CONS_INVALID && inputdev) {
		if (strstr(inputdev, "ttya") != 0)
			cons = CONS_TTYA;
		else if (strstr(inputdev, "ttyb") != 0)
			cons = CONS_TTYB;
		else if (strstr(inputdev, "usb-serial") != 0)
			cons = CONS_USBSER;
	}

	if (cons == CONS_INVALID && outputdev) {
		if (strstr(outputdev, "ttya") != 0)
			cons = CONS_TTYA;
		else if (strstr(outputdev, "ttyb") != 0)
			cons = CONS_TTYB;
		else if (strstr(outputdev, "usb-serial") != 0)
			cons = CONS_USBSER;
	}

	if (cons == CONS_INVALID)
		return;
	if (cons == console)
		return;

	console = cons;
	if (cons == CONS_TTYA || cons == CONS_TTYB) {
		serial_init();
		return;
	}

	/*
	 * USB serial -- we just collect data into a buffer
	 */
	if (cons == CONS_USBSER) {
		extern void *usbser_init(size_t);
		usbser_buf = usbser_cur = usbser_init(MMU_PAGESIZE);
	}
#endif	/* _BOOT */
}

#if !defined(_BOOT)
static void
usbser_putchar(int c)
{
	if (usbser_cur - usbser_buf < MMU_PAGESIZE)
		*usbser_cur++ = c;
}
#endif	/* _BOOT */

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
#if !defined(_BOOT)
	case CONS_USBSER:
		usbser_putchar(c);
		return;
#endif /* _BOOT */
	}
}

void
bcons_putchar(int c)
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

/*
 * kernel character input functions
 */
int
bcons_getchar(void)
{
	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		return (serial_getchar());
	default:
		return (kb_getchar());
	}
}

#if !defined(_BOOT)

int
bcons_ischar(void)
{
	switch (console) {
	case CONS_TTYA:
	case CONS_TTYB:
		return (serial_ischar());
	default:
		return (kb_ischar());
	}
}

#endif /* _BOOT */
