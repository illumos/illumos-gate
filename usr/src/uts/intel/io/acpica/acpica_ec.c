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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#include <sys/acpi/acpi.h>
#include <sys/acpica.h>

/*
 * Internal prototypes
 */
static int ec_wait_ibf_clear(int sc_addr);
static int ec_wait_obf_set(int sc_addr);

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

static int
ec_wr(int addr, uint8_t *val)
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

	outb(ec.ec_base, *val);	/* write data */
	if (ec_wait_ibf_clear(ec.ec_sc) < 0) {
		cmn_err(CE_NOTE, "!ec_wr:3: timed-out waiting "
		    "for IBF to clear");
		mutex_exit(&ec.ec_mutex);
		return (-1);
	}

	mutex_exit(&ec.ec_mutex);
	return (0);
}

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

static ACPI_STATUS
ec_handler(UINT32 func, ACPI_PHYSICAL_ADDRESS addr, UINT32 width,
	    ACPI_INTEGER *val, void *context, void *regcontext)
{
	_NOTE(ARGUNUSED(context, regcontext))
	int tmp;

	/*
	 * Add safety checks for BIOSes not strictly compliant
	 * with ACPI spec
	 */
	if ((width % 8) != 0) {
		cmn_err(CE_NOTE, "!ec_handler: width %d not multiple of 8",
		    width);
		return (AE_ERROR);
	}

	if (width > 8) {
		cmn_err(CE_NOTE, "!ec_handler: width %d greater than 8", width);
		return (AE_ERROR);
	}

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
	int		query;

	if (!(inb(ec.ec_sc) & EC_SCI))
		return;

	query = ec_query();
	if (query >= 0) {
		(void) snprintf(query_str, 5, "_Q%02X", (uint8_t)query);
		(void) AcpiEvaluateObject(ec.ec_obj, query_str, NULL, NULL);
	}

}

static UINT32
ec_gpe_handler(void *ctx)
{
	_NOTE(ARGUNUSED(ctx))

	AcpiOsExecute(OSL_GPE_HANDLER, ec_gpe_callback, NULL);
	return (0);
}

/*
 * Busy-wait for IBF to clear
 * return < 0 for time out, 0 for no error
 */
static int
ec_wait_ibf_clear(int sc_addr)
{
	int	cnt;

	cnt = 0;
	while (inb(sc_addr) & EC_IBF) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			return (-1);
		}
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

	cnt = 0;
	while (!(inb(sc_addr) & EC_OBF)) {
		cnt += 1;
		drv_usecwait(10);
		if (cnt > 10000) {
			return (-1);
		}
	}
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
	ACPI_BUFFER buf, crs;
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
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(obj, "_CRS", NULL, &crs,
	    ACPI_TYPE_BUFFER))) {
		cmn_err(CE_WARN, "!acpica_install_ec: _CRS object evaluate"
		    "failed");
		return (AE_OK);
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
	}
	AcpiOsFree(crs.Pointer);

	/*
	 * Drain the EC data register if something is left over from
	 * legacy mode
	 */
	if (inb(ec.ec_sc) & EC_OBF) {
#ifndef	DEBUG
		inb(ec.ec_base);	/* read and discard value */
#else
		cmn_err(CE_NOTE, "!EC had something: 0x%x\n", inb(ec.ec_base));
#endif
	}

	/*
	 * Get GPE
	 */
	buf.Length = ACPI_ALLOCATE_BUFFER;
	/*
	 * grab contents of GPE object
	 */
	if (ACPI_FAILURE(AcpiEvaluateObjectTyped(obj, "_GPE", NULL, &buf,
	    ACPI_TYPE_INTEGER))) {
		cmn_err(CE_WARN, "!acpica_install_ec: _GPE object evaluate"
		    "failed");
		return (AE_OK);
	}
	gpe = ((ACPI_OBJECT *)buf.Pointer)->Integer.Value;
	AcpiOsFree(buf.Pointer);

	/*
	 * Initialize EC mutex here
	 */
	mutex_init(&ec.ec_mutex, NULL, MUTEX_DRIVER, NULL);

	if (AcpiInstallAddressSpaceHandler(obj,
	    ACPI_ADR_SPACE_EC, &ec_handler, &ec_setup, NULL) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: failed to add EC handler\n");
		mutex_destroy(&ec.ec_mutex);
		return (AE_ERROR);
	}

	/*
	 * Enable EC GPE
	 */
	if ((status = AcpiInstallGpeHandler(NULL, gpe, ACPI_GPE_EDGE_TRIGGERED,
	    ec_gpe_handler, NULL)) != AE_OK) {
		cmn_err(CE_WARN, "!acpica: failed to install gpe handler status"
		    " = %d", status);
		/*
		 * don't return an error here - GPE won't work but the EC
		 * handler may be OK
		 */
	}

	(void) AcpiSetGpeType(NULL, gpe, ACPI_GPE_TYPE_RUNTIME);
	(void) AcpiEnableGpe(NULL, gpe, ACPI_NOT_ISR);

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


	if (AcpiGetTable("ECDT", 1, (ACPI_TABLE_HEADER **) &ecdt) != AE_OK) {
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
