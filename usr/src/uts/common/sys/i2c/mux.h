/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _SYS_I2C_MUX_H
#define	_SYS_I2C_MUX_H

/*
 * This header should be used by device drivers that implement an I2C mux of
 * some kind, regardless of whether they are controlled in-band with I2C,
 * out-of-band, or through some other means.
 */

#include <sys/devops.h>
#include <sys/stdint.h>
#include <sys/stdbool.h>
#include <sys/i2c/client.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	I2C_MUX_PROVIDER_V0	0
#define	I2C_MUX_PROVIDER	I2C_MUX_PROVIDER_V0

#define	I2C_MUX_PORT_ALL	UINT32_MAX

typedef struct i2c_mux_ops {
	/*
	 * Name the specified port on the mux.
	 */
	bool (*mux_port_name_f)(void *, uint32_t, char *, size_t);
	/*
	 * Enable the specified port. The flags argument is reserved for future
	 * use. Only one segment may be enabled at a time. If one is already
	 * active, this should replace that with the new one.
	 */
	bool (*mux_port_enable_f)(void *, i2c_txn_t *, uint32_t, uint32_t,
	    i2c_error_t *);
	/*
	 * Disable the specified port. The flags argument is reserved for future
	 * use. Today the framework will only ever send I2C_MUX_PORT_ALL. That
	 * is, all ports should be disabled and the device should not send
	 * anything.
	 */
	bool (*mux_port_disable_f)(void *, i2c_txn_t *, uint32_t, uint32_t,
	    i2c_error_t *);
} i2c_mux_ops_t;

typedef struct i2c_mux_regiser {
	uint32_t mr_vers;
	uint32_t mr_nports;
	dev_info_t *mr_dip;
	void *mr_drv;
	const i2c_mux_ops_t *mr_ops;
} i2c_mux_register_t;

typedef struct i2c_mux_hdl i2c_mux_hdl_t;

typedef enum {
	I2C_MUX_REG_E_OK	 = 0,
	I2C_MUX_REG_E_BAD_VERS,
	I2C_MUX_REG_E_BAD_PORTS,
	I2C_MUX_REG_E_BAD_DEVI,
	I2C_MUX_REG_E_BAD_DEVI_BUS,
	I2C_MUX_REG_E_BAD_OPS,
	I2C_MUX_REG_E_UNSUP_DEVI,
	I2C_MUX_REG_E_EXISTS,
	I2C_MUX_REG_E_NEXUS,
	I2C_MUX_REG_E_BUSY
} i2c_mux_reg_error_t;

extern void i2c_mux_mod_init(struct dev_ops *);
extern void i2c_mux_mod_fini(struct dev_ops *);
extern i2c_mux_reg_error_t i2c_mux_register_alloc(uint32_t,
    i2c_mux_register_t **);
extern void i2c_mux_register_free(i2c_mux_register_t *);

extern i2c_mux_reg_error_t i2c_mux_register(const i2c_mux_register_t *,
    i2c_mux_hdl_t **);
extern i2c_mux_reg_error_t i2c_mux_unregister(i2c_mux_hdl_t *);

/*
 * The i2c_mux_port_name_portno() function is a default port naming function
 * that names the port after the port number. The first function is zeros based,
 * the second is 1s based. It is recommended that you match the device datasheet
 * for downstream port/bus naming.
 */
extern bool i2c_mux_port_name_portno(void *, uint32_t, char *, size_t);
extern bool i2c_mux_port_name_portno_1s(void *, uint32_t, char *, size_t);

/*
 * Error functions that muxes can use.
 */
extern bool i2c_io_error(i2c_error_t *, i2c_errno_t, i2c_ctrl_error_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_I2C_MUX_H */
