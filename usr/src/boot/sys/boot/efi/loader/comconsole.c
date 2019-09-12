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
#include <bootstrap.h>
#include <stdbool.h>

#include <efi.h>
#include <efilib.h>

#include "loader_efi.h"

static EFI_GUID serial = SERIAL_IO_PROTOCOL;

#define	COMC_TXWAIT	0x40000		/* transmit timeout */

#ifndef	COMSPEED
#define	COMSPEED	9600
#endif

#define	PNP0501		0x501		/* 16550A-compatible COM port */

struct serial {
	uint64_t	baudrate;
	uint8_t		databits;
	EFI_PARITY_TYPE	parity;
	EFI_STOP_BITS_TYPE stopbits;
	uint8_t		ignore_cd;	/* boolean */
	uint8_t		rtsdtr_off;	/* boolean */
	int		ioaddr;		/* index in handles array */
	SERIAL_IO_INTERFACE *sio;
};

static void	comc_probe(struct console *);
static int	comc_init(struct console *, int);
static void	comc_putchar(struct console *, int);
static int	comc_getchar(struct console *);
static int	comc_ischar(struct console *);
static int	comc_ioctl(struct console *, int, void *);
static void	comc_devinfo(struct console *);
static bool	comc_setup(struct console *);
static char	*comc_asprint_mode(struct serial *);
static int	comc_parse_mode(struct serial *, const char *);
static int	comc_mode_set(struct env_var *, int, const void *);
static int	comc_cd_set(struct env_var *, int, const void *);
static int	comc_rtsdtr_set(struct env_var *, int, const void *);

struct console ttya = {
	.c_name = "ttya",
	.c_desc = "serial port a",
	.c_flags = 0,
	.c_probe = comc_probe,
	.c_init = comc_init,
	.c_out = comc_putchar,
	.c_in = comc_getchar,
	.c_ready = comc_ischar,
	.c_ioctl = comc_ioctl,
	.c_devinfo = comc_devinfo,
	.c_private = NULL
};

struct console ttyb = {
	.c_name = "ttyb",
	.c_desc = "serial port b",
	.c_flags = 0,
	.c_probe = comc_probe,
	.c_init = comc_init,
	.c_out = comc_putchar,
	.c_in = comc_getchar,
	.c_ready = comc_ischar,
	.c_ioctl = comc_ioctl,
	.c_devinfo = comc_devinfo,
	.c_private = NULL
};

struct console ttyc = {
	.c_name = "ttyc",
	.c_desc = "serial port c",
	.c_flags = 0,
	.c_probe = comc_probe,
	.c_init = comc_init,
	.c_out = comc_putchar,
	.c_in = comc_getchar,
	.c_ready = comc_ischar,
	.c_ioctl = comc_ioctl,
	.c_devinfo = comc_devinfo,
	.c_private = NULL
};

struct console ttyd = {
	.c_name = "ttyd",
	.c_desc = "serial port d",
	.c_flags = 0,
	.c_probe = comc_probe,
	.c_init = comc_init,
	.c_out = comc_putchar,
	.c_in = comc_getchar,
	.c_ready = comc_ischar,
	.c_ioctl = comc_ioctl,
	.c_devinfo = comc_devinfo,
	.c_private = NULL
};

static EFI_STATUS
efi_serial_init(EFI_HANDLE **handlep, int *nhandles)
{
	UINTN bufsz = 0;
	EFI_STATUS status;
	EFI_HANDLE *handles;

	/*
	 * get buffer size
	 */
	*nhandles = 0;
	handles = NULL;
	status = BS->LocateHandle(ByProtocol, &serial, NULL, &bufsz, handles);
	if (status != EFI_BUFFER_TOO_SMALL)
		return (status);

	if ((handles = malloc(bufsz)) == NULL)
		return (ENOMEM);

	*nhandles = (int)(bufsz / sizeof (EFI_HANDLE));
	/*
	 * get handle array
	 */
	status = BS->LocateHandle(ByProtocol, &serial, NULL, &bufsz, handles);
	if (EFI_ERROR(status)) {
		free(handles);
		*nhandles = 0;
	} else
		*handlep = handles;
	return (status);
}

/*
 * Find serial device number from device path.
 * Return -1 if not found.
 */
static int
efi_serial_get_index(EFI_DEVICE_PATH *devpath)
{
	ACPI_HID_DEVICE_PATH  *acpi;

	while (!IsDevicePathEnd(devpath)) {
		if (DevicePathType(devpath) == ACPI_DEVICE_PATH &&
		    DevicePathSubType(devpath) == ACPI_DP) {

			acpi = (ACPI_HID_DEVICE_PATH *)devpath;
			if (acpi->HID == EISA_PNP_ID(PNP0501)) {
				return (acpi->UID);
			}
		}

		devpath = NextDevicePathNode(devpath);
	}
	return (-1);
}

/*
 * The order of handles from LocateHandle() is not known, we need to
 * iterate handles, pick device path for handle, and check the device
 * number.
 */
static EFI_HANDLE
efi_serial_get_handle(int port)
{
	EFI_STATUS status;
	EFI_HANDLE *handles, handle;
	EFI_DEVICE_PATH *devpath;
	int index, nhandles;

	if (port == -1)
		return (NULL);

	handles = NULL;
	nhandles = 0;
	status = efi_serial_init(&handles, &nhandles);
	if (EFI_ERROR(status))
		return (NULL);

	handle = NULL;
	for (index = 0; index < nhandles; index++) {
		devpath = efi_lookup_devpath(handles[index]);
		if (port == efi_serial_get_index(devpath)) {
			handle = (handles[index]);
			break;
		}
	}

	/*
	 * In case we did fail to identify the device by path, use port as
	 * array index. Note, we did check port == -1 above.
	 */
	if (port < nhandles && handle == NULL)
		handle = handles[port];

	free(handles);
	return (handle);
}

static void
comc_probe(struct console *cp)
{
	EFI_STATUS status;
	EFI_HANDLE handle;
	struct serial *port;
	char name[20];
	char value[20];
	char *env;

	/* are we already set up? */
	if (cp->c_private != NULL)
		return;

	cp->c_private = malloc(sizeof (struct serial));
	port = cp->c_private;
	port->baudrate = COMSPEED;

	port->ioaddr = -1;	/* invalid port */
	if (strcmp(cp->c_name, "ttya") == 0)
		port->ioaddr = 0;
	else if (strcmp(cp->c_name, "ttyb") == 0)
		port->ioaddr = 1;
	else if (strcmp(cp->c_name, "ttyc") == 0)
		port->ioaddr = 2;
	else if (strcmp(cp->c_name, "ttyd") == 0)
		port->ioaddr = 3;

	port->databits = 8;		/* 8,n,1 */
	port->parity = NoParity;	/* 8,n,1 */
	port->stopbits = OneStopBit;	/* 8,n,1 */
	port->ignore_cd = 1;		/* ignore cd */
	port->rtsdtr_off = 0;		/* rts-dtr is on */
	port->sio = NULL;

	handle = efi_serial_get_handle(port->ioaddr);

	if (handle != NULL) {
		status = BS->OpenProtocol(handle, &serial,
		    (void**)&port->sio, IH, NULL,
		    EFI_OPEN_PROTOCOL_GET_PROTOCOL);

		if (EFI_ERROR(status))
			port->sio = NULL;
	}

	snprintf(name, sizeof (name), "%s-mode", cp->c_name);
	env = getenv(name);

	if (env != NULL)
		(void) comc_parse_mode(port, env);

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
	EFI_STATUS status;
	UINTN bufsz = 1;
	char cb = c;
	struct serial *sp = cp->c_private;

	if (sp->sio == NULL)
		return;

	for (wait = COMC_TXWAIT; wait > 0; wait--) {
		status = sp->sio->Write(sp->sio, &bufsz, &cb);
		if (status != EFI_TIMEOUT)
			break;
	}
}

static int
comc_getchar(struct console *cp)
{
	EFI_STATUS status;
	UINTN bufsz = 1;
	char c;
	struct serial *sp = cp->c_private;

	if (sp->sio == NULL || !comc_ischar(cp))
		return (-1);

	status = sp->sio->Read(sp->sio, &bufsz, &c);
	if (EFI_ERROR(status) || bufsz == 0)
		return (-1);

	return (c);
}

static int
comc_ischar(struct console *cp)
{
	EFI_STATUS status;
	uint32_t control;
	struct serial *sp = cp->c_private;

	if (sp->sio == NULL)
		return (0);

	status = sp->sio->GetControl(sp->sio, &control);
	if (EFI_ERROR(status))
		return (0);

	return (!(control & EFI_SERIAL_INPUT_BUFFER_EMPTY));
}

static int
comc_ioctl(struct console *cp __unused, int cmd __unused, void *data __unused)
{
	return (ENOTTY);
}

static void
comc_devinfo(struct console *cp)
{
	struct serial *port = cp->c_private;
	EFI_HANDLE handle;
	EFI_DEVICE_PATH *dp;
	CHAR16 *text;

	handle = efi_serial_get_handle(port->ioaddr);
	if (handle == NULL) {
		printf("\tdevice is not present");
		return;
	}

	dp = efi_lookup_devpath(handle);
	if (dp == NULL)
		return;

	text = efi_devpath_name(dp);
	if (text == NULL)
		return;

	printf("\t%S", text);
	efi_free_devpath_name(text);
}

static char *
comc_asprint_mode(struct serial *sp)
{
	char par, *buf;
	char *stop;

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

	asprintf(&buf, "%ju,%d,%c,%s,-", sp->baudrate, sp->databits, par, stop);
	return (buf);
}

static int
comc_parse_mode(struct serial *sp, const char *value)
{
	unsigned long n;
	uint64_t baudrate;
	uint8_t databits = 8;
	int parity = NoParity;
	int stopbits = OneStopBit;
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
	case 5: databits = 5;
		break;
	case 6: databits = 6;
		break;
	case 7: databits = 7;
		break;
	case 8: databits = 8;
		break;
	default:
		return (CMD_ERROR);
	}

	ep++;
	switch (*ep++) {
	case 'n': parity = NoParity;
		break;
	case 'e': parity = EvenParity;
		break;
	case 'o': parity = OddParity;
		break;
	case 'm': parity = MarkParity;
		break;
	case 's': parity = SpaceParity;
		break;
	default:
		return (CMD_ERROR);
	}

	if (*ep == ',')
		ep++;
	else
		return (CMD_ERROR);

	switch (*ep++) {
	case '1': stopbits = OneStopBit;
		if (ep[0] == '.' && ep[1] == '5') {
			ep += 2;
			stopbits = OneFiveStopBits;
		}
		break;
	case '2': stopbits = TwoStopBits;
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

static struct console *
get_console(char *name)
{
	struct console *cp = NULL;

	switch (name[3]) {
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

	if (comc_parse_mode(cp->c_private, value) == CMD_ERROR)
		return (CMD_ERROR);

	(void) comc_setup(cp);

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

	sp = cp->c_private;
	if (strcmp(value, "true") == 0)
		sp->ignore_cd = 1;
	else if (strcmp(value, "false") == 0)
		sp->ignore_cd = 0;
	else
		return (CMD_ERROR);

	(void) comc_setup(cp);

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

	sp = cp->c_private;
	if (strcmp(value, "true") == 0)
		sp->rtsdtr_off = 1;
	else if (strcmp(value, "false") == 0)
		sp->rtsdtr_off = 0;
	else
		return (CMD_ERROR);

	(void) comc_setup(cp);

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
	EFI_STATUS status;
	UINT32 control;
	struct serial *sp = cp->c_private;

	/* port is not usable */
	if (sp->sio == NULL)
		return (false);

	status = sp->sio->Reset(sp->sio);
	if (EFI_ERROR(status))
		return (false);

	status = sp->sio->SetAttributes(sp->sio, sp->baudrate, 0, 0, sp->parity,
	    sp->databits, sp->stopbits);
	if (EFI_ERROR(status))
		return (false);

	status = sp->sio->GetControl(sp->sio, &control);
	if (EFI_ERROR(status))
		return (false);
	if (sp->rtsdtr_off) {
		control &= ~(EFI_SERIAL_REQUEST_TO_SEND |
		    EFI_SERIAL_DATA_TERMINAL_READY);
	} else {
		control |= EFI_SERIAL_REQUEST_TO_SEND;
	}

	(void) sp->sio->SetControl(sp->sio, control);

	/* Mark this port usable. */
	cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
	return (true);
}
