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

#ifndef _SYS_I2C_CONTROLLER_H
#define	_SYS_I2C_CONTROLLER_H

/*
 * This file contains the definitions that I2C, I3C, and SMBus controller
 * drivers should use to interface with the system's i2c stack.
 */

#include <sys/devops.h>
#include <sys/i2c/i2c.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Current version of the interface expected by the i2c controller provider.
 */
#define	I2C_CTRL_PROVIDER_V0	0
#define	I2C_CTRL_PROVIDER	I2C_CTRL_PROVIDER_V0

typedef struct i2c_prop_info i2c_prop_info_t;

typedef struct i2c_ctrl_ops {
	bool (*i2c_port_name_f)(void *, uint32_t, char *, size_t);
	void (*i2c_io_smbus_f)(void *, uint32_t, smbus_req_t *);
	void (*i2c_io_i2c_f)(void *, uint32_t, i2c_req_t *);
	i2c_errno_t (*i2c_prop_info_f)(void *, i2c_prop_t, i2c_prop_info_t *);
	i2c_errno_t (*i2c_prop_get_f)(void *, i2c_prop_t, void *, size_t);
	i2c_errno_t (*i2c_prop_set_f)(void *, i2c_prop_t, const void *, size_t);
} i2c_ctrl_ops_t;

typedef struct i2c_ctrl_register {
	uint32_t ic_vers;
	i2c_ctrl_type_t ic_type;
	const char *ic_name;
	uint32_t ic_nports;
	dev_info_t *ic_dip;
	void *ic_drv;
	const i2c_ctrl_ops_t *ic_ops;
} i2c_ctrl_register_t;

/*
 * Opaque structures for registration handles.
 */
typedef struct i2c_ctrl_hdl i2c_ctrl_hdl_t;

typedef enum {
	I2C_CTRL_REG_E_OK	= 0,
	I2C_CTRL_REG_E_BAD_VERS,
	I2C_CTRL_REG_E_NULL_ARG,
	I2C_CTRL_REG_E_BAD_OPS,
	I2C_CTRL_REG_E_NEED_PORT_NAME_FUNC,
	I2C_CTRL_REG_E_NEED_PROP_GET_FUNC,
	I2C_CTRL_REG_E_NEED_PROP_INFO_FUNC,
	I2C_CTRL_REG_E_BAD_CTRL_TYPE,
	I2C_CTRL_REG_E_UNSUP_CTRL_TYPE,
	I2C_CTRL_REG_E_BAD_DIP,
	I2C_CTRL_REG_E_BAD_NPORTS,
	I2C_CTRL_REG_E_BAD_NAME,
	I2C_CTRL_REG_E_INTERNAL,
	I2C_CTRL_REG_E_BAD_MOD_TYPE,
	I2C_CTRL_REG_E_NEXUS,
	I2C_CTRL_REG_E_NOT_UNIQUE,
	I2C_CTRL_REG_E_REQ_PROP,
	I2C_CTLR_REG_E_BAD_PROP_VAL
} i2c_ctrl_reg_error_t;

extern void i2c_ctrl_mod_init(struct dev_ops *);
extern void i2c_ctrl_mod_fini(struct dev_ops *);
extern i2c_ctrl_reg_error_t i2c_ctrl_register_alloc(uint32_t,
    i2c_ctrl_register_t **);
extern void i2c_ctrl_register_free(i2c_ctrl_register_t *);

extern i2c_ctrl_reg_error_t i2c_ctrl_register(const i2c_ctrl_register_t *,
    i2c_ctrl_hdl_t **);
extern i2c_ctrl_reg_error_t i2c_ctrl_unregister(i2c_ctrl_hdl_t *);

/*
 * The i2c_ctrl_port_name_portno() function is the default controller port
 * naming function that names the port after the controller. For systems where
 * ther isn't a complex I/O Mux element or some other naming case, this should
 * be what they use.
 */
extern bool i2c_ctrl_port_name_portno(void *, uint32_t, char *, size_t);

/*
 * Various functions that can be called to set the results of I/O commands.
 */
extern void i2c_ctrl_io_success(i2c_error_t *);
extern void i2c_ctrl_io_error(i2c_error_t *, i2c_errno_t, i2c_ctrl_error_t);

/*
 * Property information interfaces.
 */
extern void i2c_prop_info_set_perm(i2c_prop_info_t *, i2c_prop_perm_t);
extern void i2c_prop_info_set_def_u32(i2c_prop_info_t *, uint32_t);
extern void i2c_prop_info_set_range_u32(i2c_prop_info_t *, uint32_t, uint32_t);
extern void i2c_prop_info_set_pos_bit32(i2c_prop_info_t *, uint32_t);

/*
 * Ways for a driver to discover timeout parameters to use.
 */
typedef enum {
	/*
	 * This is the amount of time that a given I/O command should take
	 * before the request is timed out.
	 */
	I2C_CTRL_TO_IO,
	/*
	 * This is the amount of time to busy-wait while polling the controller
	 * for I/O to advance.
	 */
	I2C_CTRL_TO_POLL_CTRL,
	/*
	 * This is the amount of time to wait for the bus to be clear for use
	 * before beginning a transaction.
	 */
	I2C_CTRL_TO_BUS_ACT,
	/*
	 * This is the amount of time to wait for an abort to complete.
	 */
	I2C_CTRL_TO_ABORT
} i2c_ctrl_timeout_t;
extern uint32_t i2c_ctrl_timeout_count(i2c_ctrl_hdl_t *, i2c_ctrl_timeout_t);
extern uint32_t i2c_ctrl_timeout_delay_us(i2c_ctrl_hdl_t *, i2c_ctrl_timeout_t);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_I2C_CONTROLLER_H */
