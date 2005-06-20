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
/*
 * Solaris x86 ACPI CA Embedded Controller operation region handler
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/file.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/*
 * EC status bits
 */
#define	EC_IBF	(0x02)
#define	EC_OBF	(0x01)
#define	EC_SMI	(0x40)
#define	EC_SCI	(0x20)

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
struct ec_softstate {
	uint16_t ec_base;	/* base of EC I/O port - data */
	uint16_t ec_sc;		/*  EC status/command */
	ACPI_HANDLE ec_obj;	/* handle to ACPI object for EC */
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
 * ACPI CA address space handler interface functions
 */
/*ARGSUSED*/
static ACPI_STATUS
ec_setup(ACPI_HANDLE reg, UINT32 func, void *context, void **ret)
{

	return (AE_OK);
}

static int
ec_rd(int addr)
{
	int	cnt;
	uint8_t sc = inb(ec.ec_sc);

#ifdef	DEBUG
	if (sc & EC_IBF) {
		cmn_err(CE_NOTE, "!ec_rd: IBF already set");
	}

	if (sc & EC_OBF) {
		cmn_err(CE_NOTE, "!ec_rd: OBF already set");
	}
#endif

	outb(ec.ec_sc, EC_RD);	/* output a read command */
	cnt = 0;
	while (inb(ec.ec_sc) & EC_IBF) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_rd:1: timed-out waiting "
			    "for IBF to clear");
			return (-1);
		}
	}

	outb(ec.ec_base, addr);	/* output addr */
	cnt = 0;
	while (inb(ec.ec_sc) & EC_IBF) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_rd:2: timed-out waiting"
			    " for IBF to clear");
			return (-1);
		}
	}

	cnt = 0;
	while (!(inb(ec.ec_sc) & EC_OBF)) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_rd:1: timed-out waiting"
			    " for OBF to set");
			return (-1);
		}
	}

	return (inb(ec.ec_base));
}

static int
ec_wr(int addr, uint8_t *val)
{
	int	cnt;
	uint8_t sc = inb(ec.ec_sc);

#ifdef	DEBUG
	if (sc & EC_IBF) {
		cmn_err(CE_NOTE, "!ec_wr: IBF already set");
	}

	if (sc & EC_OBF) {
		cmn_err(CE_NOTE, "!ec_wr: OBF already set");
	}
#endif

	outb(ec.ec_sc, EC_WR);	/* output a write command */
	cnt = 0;
	while (inb(ec.ec_sc) & EC_IBF) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_wr:1: timed-out waiting "
			    "for IBF to clear");
			return (-1);
		}
	}

	outb(ec.ec_base, addr);	/* output addr */
	cnt = 0;
	while (inb(ec.ec_sc) & EC_IBF) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_wr:2: timed-out waiting"
			    " for IBF to clear");
			return (-1);
		}
	}

	outb(ec.ec_base, *val);	/* write data */
	while (inb(ec.ec_sc) & EC_IBF) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_wr:3: timed-out waiting"
			    " for IBF to clear");
			return (-1);
		}
	}

	return (0);
}

static int
ec_query(void)
{
	int	cnt;
	uint8_t	sc = inb(ec.ec_sc);

	if (!(sc & EC_SCI) || (sc & EC_IBF) || (sc & EC_OBF)) {
		return (-1);
	}

	outb(ec.ec_sc, EC_QR);	/* output a query command */
	cnt = 0;
	while (inb(ec.ec_sc) & EC_IBF) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_query:1: timed-out waiting "
			    "for IBF to clear");
			return (-1);
		}
	}

	cnt = 0;
	while (!(inb(ec.ec_sc) & EC_OBF)) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			cmn_err(CE_NOTE, "!ec_query:1: timed-out waiting"
			    " for OBF to set");
			return (-1);
		}
	}

	return (inb(ec.ec_base));
}

static ACPI_STATUS
ec_handler(UINT32 func, ACPI_PHYSICAL_ADDRESS addr, UINT32 width,
	    ACPI_INTEGER *val, void *context, void *regcontext)
{
	_NOTE(ARGUNUSED(width, context, regcontext))
	int tmp;

	switch (func) {
	case ACPI_READ:
		tmp = ec_rd(addr);
		if (tmp < 0)
			return (AE_ERROR);
		*val = tmp;
		break;
	case ACPI_WRITE:
		if (ec_wr(addr, (uint8_t *)val) < 0)
			return (AE_ERROR);
		break;
	default:
		return (AE_ERROR);
	}

	return (AE_OK);
}


static void
ec_gpe_callback(void *ctx)
{
	_NOTE(ARGUNUSED(ctx))

	char		query_str[5];
	int		query = ec_query();

	if (query >= 0) {
		(void) snprintf(query_str, 5, "_Q%02X", (uint8_t)query);
		(void) AcpiEvaluateObject(ec.ec_obj, query_str, NULL, NULL);
	}

}

static UINT32
ec_gpe_handler(void *ctx)
{
	_NOTE(ARGUNUSED(ctx))

	AcpiOsQueueForExecution(OSD_PRIORITY_GPE, ec_gpe_callback, NULL);
	return (0);
}


/*
 * Called from AcpiWalkDevices() when an EC device is found
 */
static ACPI_STATUS
acpica_install_ec(ACPI_HANDLE obj, UINT32 nest, void *context, void **rv)
{
	_NOTE(ARGUNUSED(nest, context, rv))

	int status, i;
	ACPI_STATUS res;
	ACPI_BUFFER buf, crs;
	ACPI_OBJECT *gpe_obj, *crs_obj;
	ACPI_INTEGER gpe;
	int io_port_cnt;

	/*
	 * Save the one EC object we have
	 */
	ec.ec_obj = obj;

	/*
	 * Find ec_base and ec_sc addresses
	 */
	crs.Length = ACPI_ALLOCATE_BUFFER;
	res = AcpiEvaluateObject(obj, "_CRS", NULL, &crs);
	if (ACPI_FAILURE(res)) {
		cmn_err(CE_WARN, "!acpica_install_ec: _CRS object evaluate"
		    "failed");
		return (AE_OK);
	}
	crs_obj = crs.Pointer;
	if (crs_obj->Type != ACPI_TYPE_BUFFER) {
		cmn_err(CE_WARN, "!acpica_install_ec: not a buffer");
		AcpiOsFree(crs.Pointer);
		return (AE_OK);
	}

	for (i = 0, io_port_cnt = 0; i < crs_obj->Buffer.Length; i++) {
		io_port_des_t *io_port;
		uint8_t *tmp;

		tmp = crs_obj->Buffer.Pointer + i;
		if (*tmp != IO_PORT_DES)
			continue;
		io_port = (io_port_des_t *)tmp;
		/*
		 * Assuming first port is ec_base and second is ec_sc
		 */
		if (io_port_cnt)
			ec.ec_sc = (io_port->min_base_hi << 8) |
			    io_port->min_base_lo;
		else
			ec.ec_base = (io_port->min_base_hi << 8) |
			    io_port->min_base_lo;

		io_port_cnt++;
		/*
		 * Increment ahead to next struct.
		 */
		i += 7;
#if 0
		cmn_err(CE_NOTE, "acpica_install_ec: ec_base = %x ec_sc = %x",
		    ec.ec_base, ec.ec_sc);
#endif
	}
	AcpiOsFree(crs.Pointer);

	/*
	 * Get GPE
	 */
	buf.Length = ACPI_ALLOCATE_BUFFER;
	/*
	 * grab contents of GPE object
	 */
	if (ACPI_FAILURE(AcpiEvaluateObject(obj, "_GPE", NULL, &buf))) {
		cmn_err(CE_WARN, "!acpica_install_ec: _GPE object evaluate"
		    "failed");
		return (AE_OK);
	}
	gpe_obj = buf.Pointer;
	if (gpe_obj->Type != ACPI_TYPE_INTEGER) {
		cmn_err(CE_WARN, "!acpica_install_ec: not an int");
		AcpiOsFree(buf.Pointer);
		return (AE_OK);
	}
	gpe = gpe_obj->Integer.Value;
	AcpiOsFree(buf.Pointer);

	/*
	 * Enable EC GPE
	 */

	if ((status = AcpiInstallGpeHandler(NULL, gpe, ACPI_GPE_EDGE_TRIGGERED,
	    ec_gpe_handler, NULL)) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: failed to install gpe handler status"
		    " = %d", status);
	}

	status = AcpiSetGpeType(NULL, gpe, ACPI_GPE_TYPE_RUNTIME);
	status = AcpiEnableGpe(NULL, gpe, ACPI_NOT_ISR);

	if (AcpiInstallAddressSpaceHandler(obj,
	    ACPI_ADR_SPACE_EC, &ec_handler, &ec_setup, NULL) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: failed to add EC handler\n");
		/* should remove GPE handler here */
	}

	return (AE_OK);
}

#ifdef	DEBUG
/*ARGSUSED*/
static ACPI_STATUS
acpica_install_smbus_v1(ACPI_HANDLE obj, UINT32 nest, void *context, void **rv)
{

	cmn_err(CE_NOTE, "!acpica: found an SMBC Version 1.0\n");
	return (AE_OK);
}

/*ARGSUSED*/
static ACPI_STATUS
acpica_install_smbus_v2(ACPI_HANDLE obj, UINT32 nest, void *context, void **rv)
{

	cmn_err(CE_NOTE, "!acpica: found an SMBC Version 2.0\n");
	return (AE_OK);
}
#endif	/* DEBUG */

#ifdef	NOTYET
static void
prgas(ACPI_GENERIC_ADDRESS *gas)
{
	cmn_err(CE_CONT, "gas: %d %d %d %d %lx",
	    gas->AddressSpaceId, gas->RegisterBitWidth, gas->RegisterBitOffset,
	    gas->AccessWidth, (long)gas->Address);
}

static void
acpica_probe_ecdt()
{
	EC_BOOT_RESOURCES *ecdt;


	if (AcpiGetFirmwareTable("ECDT", 1, ACPI_LOGICAL_ADDRESSING,
				(ACPI_TABLE_HEADER **) &ecdt) != AE_OK) {
		cmn_err(CE_NOTE, "!acpica: ECDT not found\n");
		return;
	}

	cmn_err(CE_NOTE, "EcControl: ");
	prgas(&ecdt->EcControl);

	cmn_err(CE_NOTE, "EcData: ");
	prgas(&ecdt->EcData);
}
#endif	/* NOTYET */

void
acpica_ec_init(void)
{
#ifdef	NOTYET
	/*
	 * Search the ACPI tables for an ECDT; if
	 * found, use it to install an EC handler
	 */
	acpica_probe_ecdt();
#endif	/* NOTYET */

	/*
	 * General model is: use GetDevices callback to install
	 * handler(s) when device is present.
	 */
	(void) AcpiGetDevices("PNP0C09", &acpica_install_ec, NULL, NULL);
#ifdef	DEBUG
	(void) AcpiGetDevices("ACPI0001", &acpica_install_smbus_v1, NULL, NULL);
	(void) AcpiGetDevices("ACPI0005", &acpica_install_smbus_v2, NULL, NULL);
#endif	/* DEBUG */
}
