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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Solaris x86 ACPI CA Embedded Controller operation region handler
 */

#include <sys/file.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include <sys/atomic.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/*
 * EC status bits
 * Low to high
 *	Output buffer full?
 *	Input buffer full?
 *	<reserved>
 *	Data register is command byte?
 *	Burst mode enabled?
 *	SCI event?
 *	SMI event?
 *	<reserved>
 */
#define	EC_OBF	(0x01)
#define	EC_IBF	(0x02)
#define	EC_DRC	(0x08)
#define	EC_BME	(0x10)
#define	EC_SCI	(0x20)
#define	EC_SMI	(0x40)

/*
 * EC commands
 */
#define	EC_RD	(0x80)
#define	EC_WR	(0x81)
#define	EC_BE	(0x82)
#define	EC_BD	(0x83)
#define	EC_QR	(0x84)

#define	IO_PORT_DES (0x47)

/*
 * EC softstate
 */
static struct ec_softstate {
	uint8_t	 ec_ok;		/* != 0 if we have ec_base, ec_sc */
	uint16_t ec_base;	/* base of EC I/O port - data */
	uint16_t ec_sc;		/* EC status/command */
	ACPI_HANDLE ec_dev_hdl;	/* EC device handle */
	ACPI_HANDLE ec_gpe_hdl;	/* GPE info */
	ACPI_INTEGER ec_gpe_bit;
	kmutex_t    ec_mutex;	/* serialize access to EC */
} ec;

/* I/O port range descriptor */
typedef struct io_port_des {
	uint8_t type;
	uint8_t decode;
	uint8_t min_base_lo;
	uint8_t min_base_hi;
	uint8_t max_base_lo;
	uint8_t max_base_hi;
	uint8_t align;
	uint8_t len;
} io_port_des_t;

/*
 * Patchable to ignore an ECDT, in case using that
 * causes problems on someone's system.
 */
int ec_ignore_ecdt = 0;

/*
 * Patchable timeout values for EC input-buffer-full-clear
 * and output-buffer-full-set. These are in 10uS units and
 * default to 1 second.
 */
int ibf_clear_timeout = 100000;
int obf_set_timeout = 100000;

/*
 * ACPI CA EC address space handler support functions
 */

/*
 * Busy-wait for IBF to clear
 * return < 0 for time out, 0 for no error
 */
static int
ec_wait_ibf_clear(int sc_addr)
{
	int	cnt;

	cnt = ibf_clear_timeout;
	while (inb(sc_addr) & EC_IBF) {
		if (cnt-- <= 0)
			return (-1);
		drv_usecwait(10);
	}
	return (0);
}

/*
 * Busy-wait for OBF to set
 * return < 0 for time out, 0 for no error
 */
static int
ec_wait_obf_set(int sc_addr)
{
	int	cnt;

	cnt = obf_set_timeout;
	while (!(inb(sc_addr) & EC_OBF)) {
		if (cnt-- <= 0)
			return (-1);
		drv_usecwait(10);
	}
	return (0);
}

/*
 * Only called from ec_handler(), which validates ec_ok
 */
static int
ec_rd(int addr)
{
	int	cnt, rv;
	uint8_t sc;

	mutex_enter(&ec.ec_mutex);
	sc = inb(ec.ec_sc);

#ifdef	DEBUG
	if (sc & EC_IBF) {
		cmn_err(CE_NOTE, "!ec_rd: IBF already set");
	}

	if (sc & EC_OBF) {
		cmn_err(CE_NOTE, "!ec_rd: OBF already set");
	}
#endif

	outb(ec.ec_sc, EC_RD);	/* output a read command */
	if (ec_wait_ibf_clear(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_rd:1: timed-out waiting "
		    "for IBF to clear");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	outb(ec.ec_base, addr);	/* output addr */
	if (ec_wait_ibf_clear(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_rd:2: timed-out waiting "
		    "for IBF to clear");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}
	if (ec_wait_obf_set(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_rd:1: timed-out waiting "
		    "for OBF to set");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	rv = inb(ec.ec_base);
	mutex_exit(&ec.ec_mutex);
	return (rv);
}

/*
 * Only called from ec_handler(), which validates ec_ok
 */
static int
ec_wr(int addr, uint8_t val)
{
	int	cnt;
	uint8_t sc;

	mutex_enter(&ec.ec_mutex);
	sc = inb(ec.ec_sc);

#ifdef	DEBUG
	if (sc & EC_IBF) {
		cmn_err(CE_NOTE, "!ec_wr: IBF already set");
	}

	if (sc & EC_OBF) {
		cmn_err(CE_NOTE, "!ec_wr: OBF already set");
	}
#endif

	outb(ec.ec_sc, EC_WR);	/* output a write command */
	if (ec_wait_ibf_clear(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_wr:1: timed-out waiting "
		    "for IBF to clear");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	outb(ec.ec_base, addr);	/* output addr */
	if (ec_wait_ibf_clear(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_wr:2: timed-out waiting "
		    "for IBF to clear");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	outb(ec.ec_base, val);	/* write data */
	if (ec_wait_ibf_clear(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_wr:3: timed-out waiting "
		    "for IBF to clear");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	mutex_exit(&ec.ec_mutex);
	return (0);
}

/*
 * Only called from ec_gpe_callback(), which validates ec_ok
 */
static int
ec_query(void)
{
	int	cnt, rv;
	uint8_t	sc;

	mutex_enter(&ec.ec_mutex);
	outb(ec.ec_sc, EC_QR);	/* output a query command */
	if (ec_wait_ibf_clear(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_query:1: timed-out waiting "
		    "for IBF to clear");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	if (ec_wait_obf_set(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_query:1: timed-out waiting "
		    "for OBF to set");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	rv = inb(ec.ec_base);
	mutex_exit(&ec.ec_mutex);
	return (rv);
}

/*
 * ACPI CA EC address space handler
 * Requires: ec.ec_sc, ec.ec_base
 */
static ACPI_STATUS
ec_handler(UINT32 func, ACPI_PHYSICAL_ADDRESS addr, UINT32 width,
	UINT64 *val, void *context, void *regcontext)
{
	_NOTE(ARGUNUSED(context, regcontext))
	int i, tw, tmp;

	/* Guard against unexpected invocation */
	if (ec.ec_ok == 0)
		return (AE_ERROR);

	/*
	 * Add safety checks for BIOSes not strictly compliant
	 * with ACPI spec
	 */
	if ((width % 8) != 0) {
		cmn_err(CE_NOTE, "!ec_handler: invalid width %d", width);
		return (AE_BAD_PARAMETER);
	}
	if (val == NULL) {
		cmn_err(CE_NOTE, "!ec_handler: NULL value pointer");
		return (AE_BAD_PARAMETER);
	}

	while (width > 0) {

		/* One UINT64 *val at a time. */
		tw = min(width, 64);

		if (func == ACPI_READ)
			*val = 0;

		/* Do I/O of up to 64 bits */
		for (i = 0; i < tw; i += 8, addr++) {
			switch (func) {
			case ACPI_READ:
				tmp = ec_rd(addr);
				if (tmp < 0)
					return (AE_ERROR);
				*val |= ((UINT64)tmp) << i;
				break;
			case ACPI_WRITE:
				tmp = ((*val) >> i) & 0xFF;
				if (ec_wr(addr, (uint8_t)tmp) < 0)
					return (AE_ERROR);
				break;
			default:
				return (AE_ERROR);
			}
		}
		val++;
		width -= tw;
	}

	return (AE_OK);
}

/*
 * Called via taskq entry enqueued by ec_gpe_handler,
 * which validates ec_ok
 */
static void
ec_gpe_callback(void *ctx)
{
	_NOTE(ARGUNUSED(ctx))
	char		query_str[5];
	int		query;

	if (!(inb(ec.ec_sc) & EC_SCI))
		goto out;

	query = ec_query();
	if (query < 0)
		goto out;

	(void) snprintf(query_str, 5, "_Q%02X", (uint8_t)query);
	(void) AcpiEvaluateObject(ec.ec_dev_hdl, query_str, NULL, NULL);

out:
	AcpiFinishGpe(ec.ec_gpe_hdl, ec.ec_gpe_bit);
}

static UINT32
ec_gpe_handler(ACPI_HANDLE GpeDevice, UINT32 GpeNumber, void *ctx)
{
	_NOTE(ARGUNUSED(GpeDevice))
	_NOTE(ARGUNUSED(GpeNumber))
	_NOTE(ARGUNUSED(ctx))

	/*
	 * With ec_ok==0, we will not install a GPE handler,
	 * so this is just paranoia.  But if this were to
	 * happen somehow, don't add the taskq entry, and
	 * tell the caller we're done with this GPE call.
	 */
	if (ec.ec_ok == 0)
		return (ACPI_REENABLE_GPE);

	AcpiOsExecute(OSL_GPE_HANDLER, ec_gpe_callback, NULL);

	/*
	 * Returning zero tells the ACPI system that we will
	 * handle this event asynchronously.
	 */
	return (0);
}

/*
 * Some systems describe the EC using an "ECDT" (table).
 * If we find one use it (unless ec_ignore_ecdt is set).
 * Modern systems don't provide an ECDT.
 */
static ACPI_STATUS
ec_probe_ecdt(void)
{
	ACPI_TABLE_HEADER *th;
	ACPI_TABLE_ECDT *ecdt;
	ACPI_HANDLE	dev_hdl;
	ACPI_STATUS	status;

	status = AcpiGetTable(ACPI_SIG_ECDT, 1, &th);
#ifndef DEBUG
	if (status == AE_NOT_FOUND)
		return (status);
#endif
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_NOTE, "!acpica: ECDT not found");
		return (status);
	}
	if (ec_ignore_ecdt) {
		/* pretend it was not found */
		cmn_err(CE_NOTE, "!acpica: ECDT ignored");
		return (AE_NOT_FOUND);
	}

	ecdt = (ACPI_TABLE_ECDT *)th;
	if (ecdt->Control.BitWidth != 8 ||
	    ecdt->Data.BitWidth != 8) {
		cmn_err(CE_NOTE, "!acpica: bad ECDT I/O width");
		return (AE_BAD_VALUE);
	}
	status = AcpiGetHandle(NULL, (char *)ecdt->Id, &dev_hdl);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_NOTE, "!acpica: no ECDT device handle");
		return (status);
	}

	/*
	 * Success.  Save info for attach.
	 */
	ec.ec_base = ecdt->Data.Address;
	ec.ec_sc = ecdt->Control.Address;
	ec.ec_dev_hdl = dev_hdl;
	ec.ec_gpe_hdl = NULL;
	ec.ec_gpe_bit = ecdt->Gpe;
	ec.ec_ok = 1;

#ifdef DEBUG
	cmn_err(CE_NOTE, "!acpica:ec_probe_ecdt: success");
#endif
	return (0);
}

/*
 * Called from AcpiWalkDevices() when an EC device is found
 */
static ACPI_STATUS
ec_find(ACPI_HANDLE obj, UINT32 nest, void *context, void **rv)
{
	_NOTE(ARGUNUSED(nest, rv))

	*((ACPI_HANDLE *)context) = obj;
	return (AE_OK);
}

/*
 * Normal way to get the details about the EC,
 * by searching the name space.
 */
static ACPI_STATUS
ec_probe_ns(void)
{
	ACPI_HANDLE dev_hdl;
	ACPI_BUFFER buf, crs;
	ACPI_OBJECT *gpe_obj;
	ACPI_HANDLE gpe_hdl;
	ACPI_INTEGER gpe_bit;
	ACPI_STATUS status;
	int i, io_port_cnt;
	uint16_t ec_sc, ec_base;

	dev_hdl = NULL;
	(void) AcpiGetDevices("PNP0C09", &ec_find, (void *)&dev_hdl, NULL);
	if (dev_hdl == NULL) {
#ifdef DEBUG
		/* Not an error, just no EC on this machine. */
		cmn_err(CE_WARN, "!acpica:ec_probe_ns: "
		    "PNP0C09 not found");
#endif
		return (AE_NOT_FOUND);
	}

	/*
	 * Find ec_base and ec_sc addresses
	 */
	crs.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiEvaluateObjectTyped(dev_hdl, "_CRS", NULL, &crs,
	    ACPI_TYPE_BUFFER);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_WARN, "!acpica:ec_probe_ns: "
		    "_CRS object evaluate failed");
		return (status);
	}

	for (i = 0, io_port_cnt = 0;
	    i < ((ACPI_OBJECT *)crs.Pointer)->Buffer.Length; i++) {
		io_port_des_t *io_port;
		uint8_t *tmp;

		tmp = ((ACPI_OBJECT *)crs.Pointer)->Buffer.Pointer + i;
		if (*tmp != IO_PORT_DES)
			continue;
		io_port = (io_port_des_t *)tmp;
		/*
		 * first port is ec_base and second is ec_sc
		 */
		if (io_port_cnt == 0)
			ec_base = (io_port->min_base_hi << 8) |
			    io_port->min_base_lo;
		if (io_port_cnt == 1)
			ec_sc = (io_port->min_base_hi << 8) |
			    io_port->min_base_lo;

		io_port_cnt++;
		/*
		 * Increment ahead to next struct.
		 */
		i += 7;
	}
	AcpiOsFree(crs.Pointer);
	if (io_port_cnt < 2) {
		cmn_err(CE_WARN, "!acpica:ec_probe_ns: "
		    "_CRS parse failed");
		return (AE_BAD_VALUE);
	}

	/*
	 * Get the GPE info.
	 */
	buf.Length = ACPI_ALLOCATE_BUFFER;
	status = AcpiEvaluateObject(dev_hdl, "_GPE", NULL, &buf);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_WARN, "!acpica:ec_probe_ns: "
		    "_GPE object evaluate");
		return (status);
	}
	gpe_obj = (ACPI_OBJECT *)buf.Pointer;
	/*
	 * process the GPE description
	 */
	switch (gpe_obj->Type) {
	case ACPI_TYPE_INTEGER:
		gpe_hdl = NULL;
		gpe_bit = gpe_obj->Integer.Value;
		break;
	case ACPI_TYPE_PACKAGE:
		if (gpe_obj->Package.Count != 2)
			goto bad_gpe;
		gpe_obj = gpe_obj->Package.Elements;
		if (gpe_obj[1].Type != ACPI_TYPE_INTEGER)
			goto bad_gpe;
		gpe_hdl = gpe_obj[0].Reference.Handle;
		gpe_bit = gpe_obj[1].Integer.Value;
		break;
	bad_gpe:
	default:
		status = AE_BAD_VALUE;
		break;
	}
	AcpiOsFree(buf.Pointer);
	if (ACPI_FAILURE(status)) {
		cmn_err(CE_WARN, "!acpica:ec_probe_ns: "
		    "_GPE parse failed");
		return (status);
	}

	/*
	 * Success.  Save info for attach.
	 */
	ec.ec_base = ec_base;
	ec.ec_sc = ec_sc;
	ec.ec_dev_hdl = dev_hdl;
	ec.ec_gpe_hdl = gpe_hdl;
	ec.ec_gpe_bit = gpe_bit;
	ec.ec_ok = 1;

#ifdef DEBUG
	cmn_err(CE_NOTE, "!acpica:ec_probe_ns: success");
#endif
	return (0);
}

/*
 * Setup the Embedded Controller (EC) address space handler.
 * Entered only if one of the EC probe methods found an EC.
 */
static void
ec_init(void)
{
	ACPI_STATUS rc;
	int x;

	/* paranoia */
	if (ec.ec_ok == 0)
		return;

	/*
	 * Drain the EC data register if something is left over from
	 * legacy mode
	 */
	if (inb(ec.ec_sc) & EC_OBF) {
		x = inb(ec.ec_base);	/* read and discard value */
#ifdef	DEBUG
		cmn_err(CE_NOTE, "!EC had something: 0x%x", x);
#endif
	}

	/*
	 * Install an "EC address space" handler.
	 *
	 * This call does a name space walk under the passed
	 * object looking for child objects with an EC space
	 * region for which to install this handler.  Using
	 * the ROOT object makes sure we find them all.
	 *
	 * XXX: Some systems return an error from this call
	 * after a partial success, i.e. where the NS walk
	 * installs on some nodes and fails on other nodes.
	 * In such cases, disabling the EC and GPE handlers
	 * makes things worse, so just report the error and
	 * leave the EC handler enabled.
	 *
	 * At one point, it seemed that doing this part of
	 * EC setup earlier may help, which is why this is
	 * now a separate function from ec_attach.  Someone
	 * needs to figure our why some systems give us an
	 * error return from this call.  (TODO)
	 */
	rc = AcpiInstallAddressSpaceHandler(ACPI_ROOT_OBJECT,
	    ACPI_ADR_SPACE_EC, &ec_handler, NULL, NULL);
	if (rc != AE_OK) {
		cmn_err(CE_WARN, "!acpica:ec_init: "
		    "install AS handler, rc=0x%x", rc);
		return;
	}
#ifdef DEBUG
	cmn_err(CE_NOTE, "!acpica:ec_init: success");
#endif
}

/*
 * Attach the EC General-Purpose Event (GPE) handler.
 */
static void
ec_attach(void)
{
	ACPI_STATUS rc;

	/*
	 * Guard against call without probe results.
	 */
	if (ec.ec_ok == 0) {
		cmn_err(CE_WARN, "!acpica:ec_attach: "
		    "no EC device found");
		return;
	}

	/*
	 * Install the GPE handler and enable it.
	 */
	rc = AcpiInstallGpeHandler(ec.ec_gpe_hdl, ec.ec_gpe_bit,
	    ACPI_GPE_EDGE_TRIGGERED, ec_gpe_handler, NULL);
	if (rc != AE_OK) {
		cmn_err(CE_WARN, "!acpica:ec_attach: "
		    "install GPE handler, rc=0x%x", rc);
		goto errout;
	}

	rc = AcpiEnableGpe(ec.ec_gpe_hdl, ec.ec_gpe_bit);
	if (rc != AE_OK) {
		cmn_err(CE_WARN, "!acpica:ec_attach: "
		    "enable GPE handler, rc=0x%x", rc);
		goto errout;
	}

#ifdef DEBUG
	cmn_err(CE_NOTE, "!acpica:ec_attach: success");
#endif
	return;

errout:
	AcpiRemoveGpeHandler(ec.ec_gpe_hdl, ec.ec_gpe_bit,
	    ec_gpe_handler);
}

/*
 * System Management Bus Controller (SMBC)
 * These also go through the EC.
 * (not yet supported)
 */
static void
smbus_attach(void)
{
#ifdef	DEBUG
	ACPI_HANDLE obj;

	obj = NULL;
	(void) AcpiGetDevices("ACPI0001", &ec_find, (void *)&obj, NULL);
	if (obj != NULL) {
		cmn_err(CE_NOTE, "!acpica: found an SMBC Version 1.0");
	}

	obj = NULL;
	(void) AcpiGetDevices("ACPI0005", &ec_find, (void *)&obj, NULL);
	if (obj != NULL) {
		cmn_err(CE_NOTE, "!acpica: found an SMBC Version 2.0");
	}
#endif	/* DEBUG */
}

/*
 * Initialize the EC, if present.
 */
void
acpica_ec_init(void)
{
	ACPI_STATUS rc;

	/*
	 * Initialize EC mutex here
	 */
	mutex_init(&ec.ec_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * First search the ACPI tables for an ECDT, and
	 * if not found, search the name space for it.
	 */
	rc = ec_probe_ecdt();
	if (ACPI_FAILURE(rc))
		rc = ec_probe_ns();
	if (ACPI_SUCCESS(rc)) {
		ec_init();
		ec_attach();
	}
	smbus_attach();
}
