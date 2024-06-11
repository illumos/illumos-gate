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

#include <sys/cdefs.h>

#include <stand.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <bootstrap.h>
#include <stdbool.h>

#include <efi.h>
#include <efilib.h>
#include <efidevp.h>
#include <Protocol/IsaIo.h>
#include <dev/ic/ns16550.h>
#include <uuid.h>

#ifdef MDE_CPU_X64
#include <machine/cpufunc.h>
#endif

EFI_GUID  gEfiIsaIoProtocolGuid = EFI_ISA_IO_PROTOCOL_GUID;

#define	COMC_TXWAIT	0x40000		/* transmit timeout */
#define	COMC_BPS(x)	(115200 / (x))	/* speed to DLAB divisor */
#define	COMC_DIV2BPS(x)	(115200 / (x))	/* DLAB divisor to speed */

#ifndef COMSPEED
#define	COMSPEED	9600
#endif

#define	COM1_IOADDR	0x3f8
#define	COM2_IOADDR	0x2f8
#define	COM3_IOADDR	0x3e8
#define	COM4_IOADDR	0x2e8

#ifdef MDE_CPU_X64
static uint_t io_ports[] = {
	COM1_IOADDR, COM2_IOADDR, COM3_IOADDR, COM4_IOADDR
};
#endif

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

#define	PNP0501		0x501		/* 16550A-compatible COM port */

static void	efi_isa_probe(struct console *);
static int	efi_isa_init(struct console *, int);
static void	efi_isa_putchar(struct console *, int);
static int	efi_isa_getchar(struct console *);
static int	efi_isa_ischar(struct console *);
static int	efi_isa_ioctl(struct console *, int, void *);
static void	efi_isa_devinfo(struct console *);
static bool	efi_isa_setup(struct console *);
static char	*efi_isa_asprint_mode(struct serial *);
static int	efi_isa_parse_mode(struct serial *, const char *);
static int	efi_isa_mode_set(struct env_var *, int, const void *);
static int	efi_isa_cd_set(struct env_var *, int, const void *);
static int	efi_isa_rtsdtr_set(struct env_var *, int, const void *);

extern struct console efi_console;

static bool
efi_isa_port_is_present(struct serial *sp)
{
	EFI_STATUS status;
#define	COMC_TEST	0xbb
	uint8_t test = COMC_TEST;

	/*
	 * Write byte to scratch register and read it out.
	 */
	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_scr, 1, &test);
	test = 0;
	if (status == EFI_SUCCESS) {
		status = sp->io.isa->Io.Read(sp->io.isa,
		    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_scr,
		    1, &test);
	}
	return (test == COMC_TEST);
#undef COMC_TEST
}

static bool
efi_isa_should_append(const char *name, struct serial *port)
{
	EFI_DEVICE_PATH *node, *dev;
	EFI_STATUS status;
	char *buf;
	size_t sz;
	bool rv = true;

	if (port->currdev == NULL)
		return (rv);

	buf = NULL;
	sz = 0;
	status = efi_global_getenv(name, buf, &sz);
	if (status == EFI_BUFFER_TOO_SMALL) {
		buf = malloc(sz);
		if (buf == NULL)
			return (rv);
		status = efi_global_getenv(name, buf, &sz);
	}
	if (EFI_ERROR(status)) {
		free(buf);
		return (rv);
	}

	dev = efi_lookup_devpath(port->currdev);
	if (dev == NULL) {
		free(buf);
		return (rv);
	}

	node = (EFI_DEVICE_PATH *)buf;
	/*
	 * We only need to know if this port is first in list.
	 * This is only important when "os_console" is not set.
	 */
	if (!IsDevicePathEnd(node) && efi_devpath_is_prefix(dev, node))
		rv = false;

	efi_close_devpath(dev);
	free(buf);
	return (rv);
}

static void
efi_isa_setup_env(struct console *tty)
{
	struct serial *port = tty->c_private;
	char name[20];
	char value[20];
	char *env;

	(void) snprintf(name, sizeof (name), "%s-mode", tty->c_name);
	env = getenv(name);
	if (env != NULL)
		(void) efi_isa_parse_mode(port, env);
	env = efi_isa_asprint_mode(port);
	if (env != NULL) {
		(void) unsetenv(name);
		(void) env_setenv(name, EV_VOLATILE, env, efi_isa_mode_set,
		    env_nounset);
		if (port->is_efi_console) {
			(void) snprintf(name, sizeof (name), "%s-spcr-mode",
			    tty->c_name);
			(void) setenv(name, env, 1);
			free(env);

			/* Add us to console list. */
			(void) snprintf(name, sizeof (name), "console");
			env = getenv(name);
			if (env == NULL) {
				(void) setenv(name, tty->c_name, 1);
			} else {
				char *ptr;
				int rv;

				/*
				 * we have "text" already in place,
				 * consult ConOut if we need to add
				 * serial console before or after.
				 */
				if (efi_isa_should_append("ConOut", port))
					rv = asprintf(&ptr, "%s,%s", env,
					    tty->c_name);
				else
					rv = asprintf(&ptr, "%s,%s",
					    tty->c_name, env);
				if (rv > 0) {
					(void) setenv(name, ptr, 1);
					free(ptr);
				} else {
					printf("%s: %s\n", __func__,
					    strerror(ENOMEM));
				}
			}
		} else {
			free(env);
		}
	}

	(void) snprintf(name, sizeof (name), "%s-ignore-cd", tty->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->ignore_cd = 1;
		else if (strcmp(env, "false") == 0)
			port->ignore_cd = 0;
	}

	(void) snprintf(value, sizeof (value), "%s",
	    port->ignore_cd? "true" : "false");
	(void) unsetenv(name);
	(void) env_setenv(name, EV_VOLATILE, value, efi_isa_cd_set,
	    env_nounset);

	(void) snprintf(name, sizeof (name), "%s-rts-dtr-off", tty->c_name);
	env = getenv(name);
	if (env != NULL) {
		if (strcmp(env, "true") == 0)
			port->rtsdtr_off = 1;
		else if (strcmp(env, "false") == 0)
			port->rtsdtr_off = 0;
	}

	(void) snprintf(value, sizeof (value), "%s",
	    port->rtsdtr_off? "true" : "false");
	(void) unsetenv(name);
	(void) env_setenv(name, EV_VOLATILE, value, efi_isa_rtsdtr_set,
	    env_nounset);
}

static void
efi_check_and_set_condev(struct serial *port, const char *name)
{
	EFI_DEVICE_PATH *node, *dev;
	EFI_STATUS status;
	char *buf;
	size_t sz;

	if (port->currdev == NULL)
		return;

	buf = NULL;
	sz = 0;
	status = efi_global_getenv(name, buf, &sz);
	if (status == EFI_BUFFER_TOO_SMALL) {
		buf = malloc(sz);
		if (buf == NULL)
			return;
		status = efi_global_getenv(name, buf, &sz);
	}
	if (EFI_ERROR(status)) {
		free(buf);
		return;
	}

	dev = efi_lookup_devpath(port->currdev);
	if (dev == NULL) {
		free(buf);
		return;
	}

	node = (EFI_DEVICE_PATH *)buf;
	while (!IsDevicePathEnd(node)) {
		/* Sanity check the node before moving to the next node. */
		if (DevicePathNodeLength(node) < sizeof (*node))
			break;

		if (efi_devpath_is_prefix(dev, node)) {
			port->is_efi_console = true;
			break;
		}

		node = efi_devpath_next_instance(node);
	}

	efi_close_devpath(dev);
	free(buf);
}

/*
 * Return number of ports created (0 or 1).
 */
static uint_t
efi_isa_create_port(EFI_HANDLE handle)
{
	struct serial *port;
	EFI_ISA_IO_PROTOCOL *io;
	EFI_STATUS status;

	status = BS->OpenProtocol(handle, &gEfiIsaIoProtocolGuid,
	    (void**)&io, IH, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
	if (EFI_ERROR(status)) {
		return (0);
	}

	/* Is this serial port? */
	if (io->ResourceList->Device.HID != EISA_PNP_ID(PNP0501))
		return (0);

	/* We assume I/O port */
	if (io->ResourceList->ResourceItem->Type != EfiIsaAcpiResourceIo)
		return (0);

	port = calloc(1, sizeof (*port));
	if (port == NULL) {
		return (0);
	}

	/* Set up port descriptor */
	port->ignore_cd = true;
	port->currdev = handle;
	port->ioaddr = 0;
	for (uint_t i = 0; io->ResourceList->ResourceItem[i].Type !=
	    EfiIsaAcpiResourceEndOfList; i++) {
		if (io->ResourceList->ResourceItem[i].Type ==
		    EfiIsaAcpiResourceIo) {
			port->ioaddr =
			    io->ResourceList->ResourceItem[i].StartRange;
			break;
		}
	}
	port->guid = &gEfiIsaIoProtocolGuid;
	port->io.isa = io;
	/* Use 8,n,1 for defaults */
	port->databits = 8;
	port->parity = NoParity;
	port->stopbits = OneStopBit;

	STAILQ_INSERT_TAIL(&serials, port, next);
	return (1);
}

#ifdef MDE_CPU_X64
static EFI_STATUS
efi_isa_create_io(EFI_ISA_IO_PROTOCOL **iop)
{
	EFI_ISA_IO_PROTOCOL *io;

	io = calloc(1, sizeof (*io));
	if (io == NULL) {
		return (EFI_OUT_OF_RESOURCES);
	}
	io->ResourceList = malloc(sizeof (*io->ResourceList));
	if (io->ResourceList == NULL) {
		free(io);
		return (EFI_OUT_OF_RESOURCES);
	}
	io->ResourceList->ResourceItem =
	    calloc(2, sizeof (*io->ResourceList->ResourceItem));
	if (io->ResourceList == NULL) {
		free(io->ResourceList);
		free(io);
		return (EFI_OUT_OF_RESOURCES);
	}

	*iop = io;
	return (EFI_SUCCESS);
}

static EFI_STATUS EFIAPI
_Read(EFI_ISA_IO_PROTOCOL *this __unused,
    EFI_ISA_IO_PROTOCOL_WIDTH Width __unused,
    UINT32 Offset, UINTN Count, VOID *Buffer)
{
	uint8_t *buf = (uint8_t *)Buffer;

	while ((Count--) != 0) {
		*buf++ = inb(Offset);
	}

	return (EFI_SUCCESS);
}

static EFI_STATUS EFIAPI
_Write(EFI_ISA_IO_PROTOCOL *this __unused,
    EFI_ISA_IO_PROTOCOL_WIDTH Width __unused,
    UINT32 Offset, UINTN Count, VOID *Buffer)
{
	uint8_t *buf = (uint8_t *)Buffer;

	while ((Count--) != 0) {
		outb(Offset, *buf++);
	}
	return (EFI_SUCCESS);
}

static EFI_STATUS
efi_isa_create_io_ports(void)
{
	struct serial *port;
	EFI_ISA_IO_PROTOCOL *io;
	EFI_STATUS status = EFI_SUCCESS;

	port = NULL;
	for (uint_t i = 0; i < nitems(io_ports); i++) {
		if (port == NULL) {
			status = efi_isa_create_io(&io);
			if (EFI_ERROR(status))
				return (status);
			io->Io.Read = _Read;
			io->Io.Write = _Write;
			io->ResourceList->Device.HID = EISA_PNP_ID(PNP0501);
			io->ResourceList->ResourceItem[0].Type =
			    EfiIsaAcpiResourceIo;
			io->ResourceList->ResourceItem[1].Type =
			    EfiIsaAcpiResourceEndOfList;

			port = calloc(1, sizeof (*port));
			if (port == NULL) {
				free(io->ResourceList->ResourceItem);
				free(io->ResourceList);
				free(io);
				return (EFI_OUT_OF_RESOURCES);
			}
			/* Set up port descriptor */
			port->io.isa = io;
			/* Use 8,n,1 for defaults */
			port->databits = 8;
			port->parity = NoParity;
			port->stopbits = OneStopBit;
			port->ignore_cd = true;
			port->guid = &gEfiIsaIoProtocolGuid;
		}
		io->ResourceList->Device.UID = i;
		io->ResourceList->ResourceItem[0].StartRange = io_ports[i];
		port->ioaddr = io_ports[i];
		if (efi_isa_port_is_present(port)) {
			STAILQ_INSERT_TAIL(&serials, port, next);
			port = NULL;
		}
	}

	if (port != NULL) {
		free(io->ResourceList->ResourceItem);
		free(io->ResourceList);
		free(io);
		free(port);
	}
	return (status);
}
#endif	/* MDE_CPU_X64 */

/*
 * Get IsaIo protocol handles and build port list for us.
 * returns EFI_SUCCESS or EFI_NOT_FOUND.
 */
static EFI_STATUS
efi_isa_probe_ports(void)
{
	EFI_STATUS status;
	EFI_HANDLE *handles;
	struct serial *port;
	uint_t count, nhandles, index;

	count = 0;
	nhandles = 0;
	handles = NULL;
	status = efi_get_protocol_handles(&gEfiIsaIoProtocolGuid,
	    &nhandles, &handles);
	if (!EFI_ERROR(status)) {
		for (index = 0; index < nhandles; index++) {
			/* skip if we are iodev for serialio port */
			STAILQ_FOREACH(port, &serials, next) {
				if (port->iodev == handles[index])
					break;
			}
			if (port == NULL)
				count += efi_isa_create_port(handles[index]);
		}
		free(handles);
		if (count == 0)
			status = EFI_NOT_FOUND;
	}
	return (status);
}

/*
 * Set up list of possible serial consoles.
 * This function is run very early, so we do not expect to
 * run out of memory, and on error, we can not print output.
 *
 * isaio protocols can include serial ports, parallel ports,
 * keyboard, mouse. We walk protocol handles, create list of
 * serial ports, then create console descriptors.
 */
void
efi_isa_ini(void)
{
	EFI_STATUS status;
	uint_t c, n;
	struct console **tmp;
	struct console *tty;
	struct serial *port;

	status = efi_isa_probe_ports();
#ifdef MDE_CPU_X64
	if (status == EFI_NOT_FOUND) {
		/*
		 * We have no IsaIo serial ports. But, as this implementation
		 * is very similar to one used in BIOS comconsole driver,
		 * and in order to avoid using comconsole as last resort
		 * fallback on x86 platform, we implement fake IsaIo.
		 */
		if (STAILQ_EMPTY(&serials))
			status = efi_isa_create_io_ports();
	}
#endif
	if (EFI_ERROR(status))
		return;

	n = 0;
	/* Count ports we have */
	STAILQ_FOREACH(port, &serials, next) {
		if (uuid_equal((uuid_t *)port->guid,
		    (uuid_t *)&gEfiIsaIoProtocolGuid, NULL) == 1)
			n++;
	}

	if (n == 0)
		return;		/* no serial ports here */

	c = cons_array_size();
	if (c == 0)
		n++;	/* For NULL pointer */

	tmp = realloc(consoles, (c + n) * sizeof (*consoles));
	if (tmp == NULL) {
		return;
	}
	consoles = tmp;
	if (c > 0)
		c--;

	STAILQ_FOREACH(port, &serials, next) {
		char id;

		if (uuid_equal((uuid_t *)port->guid,
		    (uuid_t *)&gEfiIsaIoProtocolGuid, NULL) == 0) {
			continue;
		}

		tty = calloc(1, sizeof (*tty));
		if (tty == NULL) {
			/* Out of memory?! */
			continue;
		}
		switch (port->ioaddr) {
		case 0:	/* bad ioaddr */
			continue;
		case COM1_IOADDR:
			id = 'a';
			break;
		case COM2_IOADDR:
			id = 'b';
			break;
		case COM3_IOADDR:
			id = 'c';
			break;
		case COM4_IOADDR:
			id = 'd';
			break;
		default:
			/*
			 * We should not see this happening, but assigning
			 * this id would let us help to identify unexpected
			 * configuration.
			 */
			id = '0';
		}
		/* Set up serial device descriptor */
		(void) asprintf(&tty->c_name, "tty%c", id);
		(void) asprintf(&tty->c_desc, "serial port %c", id);
		tty->c_flags = C_PRESENTIN | C_PRESENTOUT;
		tty->c_probe = efi_isa_probe;
		tty->c_init = efi_isa_init;
		tty->c_out = efi_isa_putchar;
		tty->c_in = efi_isa_getchar;
		tty->c_ready = efi_isa_ischar;
		tty->c_ioctl = efi_isa_ioctl;
		tty->c_devinfo = efi_isa_devinfo;
		tty->c_private = port;
		consoles[c++] = tty;

		/* Reset terminal to initial normal settings with ESC [ 0 m */
		efi_isa_putchar(tty, 0x1b);
		efi_isa_putchar(tty, '[');
		efi_isa_putchar(tty, '0');
		efi_isa_putchar(tty, 'm');
		/* drain input from random data */
		while (efi_isa_getchar(tty) != -1)
			;
	}
	consoles[c] = NULL;
}

static EFI_STATUS
efi_isa_getspeed(struct serial *sp)
{
	EFI_STATUS status;
	uint_t  divisor;
	uchar_t dlbh;
	uchar_t dlbl;
	uchar_t cfcr;
	uchar_t c;

	status = sp->io.isa->Io.Read(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_cfcr, 1, &cfcr);
	if (EFI_ERROR(status))
		return (status);
	c = CFCR_DLAB | cfcr;
	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_cfcr, 1, &c);
	if (EFI_ERROR(status))
		return (status);

	status = sp->io.isa->Io.Read(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_dlbl, 1, &dlbl);
	if (EFI_ERROR(status))
		return (status);
	status = sp->io.isa->Io.Read(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_dlbh, 1, &dlbh);
	if (EFI_ERROR(status))
		return (status);

	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_cfcr, 1, &cfcr);
	if (EFI_ERROR(status))
		return (status);

	divisor = dlbh << 8 | dlbl;

	if (divisor == 0)
		return (EFI_DEVICE_ERROR);

	sp->baudrate = COMC_DIV2BPS(divisor);
	return (EFI_SUCCESS);
}

static void
efi_isa_probe(struct console *cp)
{
	struct serial *sp = cp->c_private;
	EFI_STATUS status;
	uint8_t lcr;

	if (!efi_isa_port_is_present(sp)) {
		return;
	}

	status = efi_isa_getspeed(sp);
	if (EFI_ERROR(status)) {
		/* Use fallback value. */
		sp->baudrate = COMSPEED;
	}
	status = sp->io.isa->Io.Read(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_lcr,
	    1, &lcr);
	if (EFI_ERROR(status)) {
		return;
	}

	sp->databits = (lcr & BITS8) == BITS8? 8:7;
	sp->stopbits = (lcr & STOP2) == STOP2? TwoStopBits:OneStopBit;
	if ((lcr & (PAREN|PAREVN)) == (PAREN|PAREVN))
		sp->parity = EvenParity;
	else if ((lcr & PAREN) == PAREN)
		sp->parity = OddParity;
	else
		sp->parity = NoParity;

	/* check if we are listed in ConIn */
	efi_check_and_set_condev(sp, "ConIn");
	efi_isa_setup_env(cp);
	if (!efi_isa_setup(cp))
		printf("Failed to set up %s\n", cp->c_name);
}

static int
efi_isa_init(struct console *cp, int arg __unused)
{

	if (efi_isa_setup(cp))
		return (CMD_OK);

	cp->c_flags = 0;
	return (CMD_ERROR);
}

static void
efi_isa_putchar(struct console *cp, int c)
{
	int wait;
	EFI_STATUS status;
	UINTN bufsz = 1;
	char control, cb = c;
	struct serial *sp = cp->c_private;

	for (wait = COMC_TXWAIT; wait > 0; wait--) {
		status = sp->io.isa->Io.Read(sp->io.isa,
		    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_lsr,
		    bufsz, &control);
		if (EFI_ERROR(status))
			continue;

		if ((control & LSR_TXRDY) != LSR_TXRDY)
			continue;

		status = sp->io.isa->Io.Write(sp->io.isa,
		    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT, sp->ioaddr + com_data,
		    bufsz, &cb);
		if (status != EFI_TIMEOUT)
			break;
	}
}

static int
efi_isa_getchar(struct console *cp)
{
	EFI_STATUS status;
	UINTN bufsz = 1;
	char c;
	struct serial *sp = cp->c_private;

	/*
	 * if this device is also used as ConIn, some firmwares
	 * fail to return all input via SIO protocol.
	 */
	if (sp->is_efi_console) {
		return (efi_console.c_in(&efi_console));
	}

	if (!efi_isa_ischar(cp))
		return (-1);

	status = sp->io.isa->Io.Read(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_data, bufsz, &c);
	if (EFI_ERROR(status))
		return (-1);

	return (c);
}

static int
efi_isa_ischar(struct console *cp)
{
	EFI_STATUS status;
	uint8_t control;
	struct serial *sp = cp->c_private;

	/*
	 * if this device is also used as ConIn, some firmwares
	 * fail to return all input via SIO protocol.
	 */
	if (sp->is_efi_console) {
		return (efi_console.c_ready(&efi_console));
	}

	status = sp->io.isa->Io.Read(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_lsr, 1, &control);
	if (EFI_ERROR(status))
		return (0);

	return (control & LSR_RXRDY);
}

static int
efi_isa_ioctl(struct console *cp __unused, int cmd __unused,
    void *data __unused)
{
	return (ENOTTY);
}

static void
efi_isa_devinfo(struct console *cp)
{
	struct serial *port = cp->c_private;
	EFI_DEVICE_PATH *dp;
	CHAR16 *text;

	if (port->currdev != NULL) {
		dp = efi_lookup_devpath(port->currdev);
		if (dp == NULL)
			return;

		text = efi_devpath_name(dp);
		if (text == NULL)
			return;

		printf("\tISA IO device %S", text);
		efi_free_devpath_name(text);
		efi_close_devpath(port->currdev);
		return;
	}

	if (port->ioaddr != 0) {
		printf("\tISA IO port %#x", port->ioaddr);
	}
}

static char *
efi_isa_asprint_mode(struct serial *sp)
{
	char par, *buf, *stop;

	if (sp == NULL)
		return (NULL);

	switch (sp->parity) {
	case NoParity:
		par = 'n';
		break;
	case EvenParity:
		par = 'e';
		break;
	case OddParity:
		par = 'o';
		break;
	case MarkParity:
		par = 'm';
		break;
	case SpaceParity:
		par = 's';
		break;
	default:
		par = 'n';
		break;
	}

	switch (sp->stopbits) {
	case OneStopBit:
		stop = "1";
		break;
	case TwoStopBits:
		stop = "2";
		break;
	case OneFiveStopBits:
		stop = "1.5";
		break;
	default:
		stop = "1";
		break;
	}

	(void) asprintf(&buf, "%ju,%d,%c,%s,-", sp->baudrate,
	    sp->databits, par, stop);
	return (buf);
}

static int
efi_isa_parse_mode(struct serial *sp, const char *value)
{
	unsigned long n;
	uint64_t baudrate;
	uint8_t databits;
	EFI_PARITY_TYPE parity;
	EFI_STOP_BITS_TYPE stopbits;
	char *ep;

	if (value == NULL || *value == '\0')
		return (CMD_ERROR);

	errno = 0;
	n = strtoul(value, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);
	baudrate = n;

	ep++;
	n = strtoul(ep, &ep, 10);
	if (errno != 0 || *ep != ',')
		return (CMD_ERROR);

	switch (n) {
	case 5:
		databits = 5;
		break;
	case 6:
		databits = 6;
		break;
	case 7:
		databits = 7;
		break;
	case 8:
		databits = 8;
		break;
	default:
		return (CMD_ERROR);
	}

	ep++;
	switch (*ep++) {
	case 'n':
		parity = NoParity;
		break;
	case 'e':
		parity = EvenParity;
		break;
	case 'o':
		parity = OddParity;
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
		stopbits = OneStopBit;
		break;
	case '2':
		stopbits = TwoStopBits;
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

	sp->baudrate = baudrate;
	sp->databits = databits;
	sp->parity = parity;
	sp->stopbits = stopbits;
	return (CMD_OK);
}

/*
 * CMD_ERROR will cause set/setenv/setprop command to fail,
 * when used in loader scripts (forth), this will cause processing
 * of boot scripts to fail, rendering bootloading impossible.
 * To prevent such unfortunate situation, we return CMD_OK when
 * there is no such port, or there is invalid value in mode line.
 */
static int
efi_isa_mode_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	char name[15];

	if (value == NULL)
		return (CMD_ERROR);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	/* Do not override serial setup if port is listed in ConIn */
	(void) snprintf(name, sizeof (name), "%s-spcr-mode", cp->c_name);
	if (getenv(name) == NULL) {
		if (efi_isa_parse_mode(cp->c_private, value) == CMD_ERROR) {
			printf("%s: invalid mode: %s\n", ev->ev_name,
			    (char *)value);
			return (CMD_OK);
		}

		(void) efi_isa_setup(cp);
		(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, value,
		    NULL, NULL);
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
efi_isa_cd_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	struct serial *sp;

	if (value == NULL)
		return (CMD_OK);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	sp = cp->c_private;
	if (strcmp(value, "true") == 0) {
		sp->ignore_cd = 1;
	} else if (strcmp(value, "false") == 0) {
		sp->ignore_cd = 0;
	} else {
		printf("%s: invalid value: %s\n", ev->ev_name,
		    (char *)value);
		return (CMD_OK);
	}

	(void) efi_isa_setup(cp);

	(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

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
efi_isa_rtsdtr_set(struct env_var *ev, int flags, const void *value)
{
	struct console *cp;
	struct serial *sp;

	if (value == NULL)
		return (CMD_OK);

	if ((cp = cons_get_console(ev->ev_name)) == NULL)
		return (CMD_OK);

	sp = cp->c_private;
	if (strcmp(value, "true") == 0) {
		sp->rtsdtr_off = 1;
	} else if (strcmp(value, "false") == 0) {
		sp->rtsdtr_off = 0;
	} else {
		printf("%s: invalid value: %s\n", ev->ev_name,
		    (char *)value);
		return (CMD_OK);
	}

	(void) efi_isa_setup(cp);

	(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

/*
 * In case of error, we also reset ACTIVE flags, so the console
 * framefork will try alternate consoles.
 */
static bool
efi_isa_setup(struct console *cp)
{
	EFI_STATUS status;
	uint8_t data, lcr;
	struct serial *sp = cp->c_private;
	uint_t tries, try_count = 1000000;

	if (sp->baudrate == 0)
		return (false);

	switch (sp->databits) {
	case 8:
		lcr = BITS8;
		break;
	case 7:
		lcr = BITS7;
		break;
	case 6:
		lcr = BITS6;
		break;
	case 5:
		lcr = BITS5;
		break;
	default:
		lcr = BITS8;
		break;
	}

	switch (sp->parity) {
	case NoParity:
		break;
	case OddParity:
		lcr |= PAREN|PARODD;
		break;
	case EvenParity:
		lcr |= PAREN|PAREVN;
		break;
	default:
		break;
	}

	switch (sp->stopbits) {
	case OneStopBit:
		break;
	case TwoStopBits:
		lcr |= STOP2;
		break;
	default:
		break;
	}

	data = CFCR_DLAB | lcr;
	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_cfcr, 1, &data);
	if (EFI_ERROR(status))
		return (false);
	data = COMC_BPS(sp->baudrate) & 0xff;
	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_dlbl, 1, &data);
	if (EFI_ERROR(status))
		return (false);
	data = COMC_BPS(sp->baudrate) >> 8;
	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_dlbh, 1, &data);
	if (EFI_ERROR(status))
		return (false);
	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_cfcr, 1, &lcr);
	if (EFI_ERROR(status))
		return (false);
	data = sp->rtsdtr_off? ~(MCR_RTS | MCR_DTR) : MCR_RTS | MCR_DTR;
	status = sp->io.isa->Io.Write(sp->io.isa,
	    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
	    sp->ioaddr + com_mcr, 1, &data);
	if (EFI_ERROR(status))
		return (false);

	tries = 0;
	do {
		status = sp->io.isa->Io.Read(sp->io.isa,
		    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
		    sp->ioaddr + com_data, 1, &data);
		status = sp->io.isa->Io.Read(sp->io.isa,
		    EFI_ISA_ACPI_MEMORY_WIDTH_8_BIT,
		    sp->ioaddr + com_lsr, 1, &data);
	} while (data & LSR_RXRDY && ++tries < try_count);

	if (tries == try_count)
		return (false);

	/* Mark this port usable. */
	cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
	return (true);
}
