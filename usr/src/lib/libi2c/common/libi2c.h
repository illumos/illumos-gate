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

#ifndef _LIBI2C_H
#define	_LIBI2C_H

/*
 * This file contains an evolving set of interfaces for dealing with i2c class
 * devices in the system.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <libdevinfo.h>
#include <stdint.h>
#include <sys/i2c/i2c.h>

typedef enum {
	I2C_ERR_OK	= 0,
	/*
	 * Indicates that a command issued to a controller failed for some
	 * reason. The driver's error is available through the i2c_ctrl_err()
	 * function.
	 */
	I2C_ERR_CONTROLLER,
	/*
	 * We were passed an invalid pointer argument for an argument.
	 */
	I2C_ERR_BAD_PTR,
	/*
	 * Indicates that there was a memory allocation error. The system error
	 * contains the specific errno.
	 */
	I2C_ERR_NO_MEM,
	/*
	 * Indicates that an error occurred while trying to use the devinfo
	 * library. The system error is generally populated for this (dependent
	 * on the underlying libdevinfo call).
	 */
	I2C_ERR_LIBDEVINFO,
	/*
	 * Indicates that the devinfo node we were given doesn't correspond to
	 * the correct type of i2c device.
	 */
	I2C_ERR_BAD_DEVI,
	/*
	 * Indicates that an internal error condition occurred.
	 */
	I2C_ERR_INTERNAL,
	/*
	 * Indicates that the caller did not contain sufficient privileges for
	 * a given operation.
	 */
	I2C_ERR_PRIVS,
	/*
	 * Indicates a failure to open a device file.
	 */
	I2C_ERR_OPEN_DEV,
	/*
	 * Indicates that a means of identify a controller, port, or device
	 * (name, instance, etc.) does not match the corresponding I2C entity.
	 * This can also happen when given a path that does not end at the
	 * expected component.
	 */
	I2C_ERR_BAD_CONTROLLER,
	I2C_ERR_BAD_PORT,
	I2C_ERR_BAD_DEVICE,
	/*
	 * Indicates that the address type is invalid or that the address is not
	 * a valid address.
	 */
	I2C_ERR_BAD_ADDR_TYPE,
	I2C_ERR_BAD_ADDR,
	/*
	 * Indicates that the requested address type is not supported by the
	 * controller.
	 */
	I2C_ERR_UNSUP_ADDR_TYPE,
	/*
	 * Indicates that the address could not be used because it is reserved.
	 */
	I2C_ERR_ADDR_RSVD,
	/*
	 * Indicates that the requested address is already in use.
	 */
	I2C_ERR_ADDR_IN_USE,
	/*
	 * Indicates that the requested address does not map to anything known.
	 */
	I2C_ERR_ADDR_UNKNOWN,
	/*
	 * Indicates that the I/O length is outside of the valid range for the
	 * request. The maximum SMBus 2.0 request is 32 bytes and SMBus 3.0 is
	 * 256 bytes. The maximum I2C request is similarly today 256 bytes.
	 */
	I2C_ERR_IO_READ_LEN_RANGE,
	I2C_ERR_IO_WRITE_LEN_RANGE,
	/*
	 * These two indicate general classes of issues with I/O requests. The
	 * first indicates that a given field has not been set. For example, an
	 * address or operation type. The second indicates that the combination
	 * of I/O is not supported. For example, a zero byte read and write.
	 */
	I2C_ERR_IO_REQ_MISSING_FIELDS,
	I2C_ERR_IO_REQ_IO_INVALID,
	/*
	 * Indicates that an I2C or SMBus request was submitted to a controller
	 * that does not support that protocol and the request could not be
	 * translated by the kernel.
	 */
	I2C_ERR_CANT_XLATE_IO_REQ,
	/*
	 * Indicates that the controller or the system does not support the
	 * requested SMBus operation.
	 */
	I2C_ERR_SMBUS_OP_UNSUP,
	/*
	 * Indicates that an attempt to take the controller lock would fail due
	 * to blocking or that a signal was taking, cancelling the operation,
	 * while waiting for the controller lock.
	 */
	I2C_ERR_LOCK_WAIT_SIGNAL,
	I2C_ERR_LOCK_WOULD_BLOCK,
	/*
	 * Indicates that the kernel did not have memory available to allocate
	 * on behalf of the caller.
	 */
	I2C_ERR_NO_KERN_MEM,
	/*
	 * Indicates that a string that is being used for a device name or
	 * compatible array contains illegal characters or is too long.
	 */
	I2C_ERR_BAD_DEV_NAME,
	/*
	 * Indicates that the length of the compatible range is longer than the
	 * system will allow to be set.
	 */
	I2C_ERR_COMPAT_LEN_RANGE,
	/*
	 * Indicates that some of the required fields are missing from a device
	 * add request.
	 */
	I2C_ERR_ADD_DEV_REQ_MISSING_FIELDS,
	/*
	 * Indicates that the I2C nexus had unexpected failures while trying to
	 * manipulate devices.
	 */
	I2C_ERR_NEXUS,
	/*
	 * Indicates that a library handle was used across multiple threads
	 * incorrectly (a handle should only be used by one thread at a time)
	 * and the kernel noted that an operation was already ongoing.
	 */
	I2C_ERR_OP_IN_PROGRESS,
	/*
	 * Indicates that the property is known to the system, but it is
	 * unsupported by the device.
	 */
	I2C_ERR_PROP_UNSUP,
	/*
	 * Indicates that the property name or id is not known to the system.
	 */
	I2C_ERR_BAD_PROP,
	/*
	 * Indicates that the property cannot be set because the controller does
	 * not support setting properties. This is followed by the controller
	 * (or system) indicating that the property is read-only.
	 */
	I2C_ERR_SET_PROP_UNSUP,
	I2C_ERR_PROP_READ_ONLY,
	/*
	 * These indicate that the property buffer is too small and too large
	 * respectively. This only fires on setting a property.
	 */
	I2C_ERR_PROP_BUF_TOO_SMALL,
	I2C_ERR_PROP_BUF_TOO_BIG,
	/*
	 * Indicates that the property value is invalid.
	 */
	I2C_ERR_BAD_PROP_VAL,
	/*
	 * Indicates that there is no default value available.
	 */
	I2C_ERR_NO_PROP_DEF_VAL,
	/*
	 * Indicates that the function used to get a value from a property
	 * didn't match the type of the data.
	 */
	I2C_ERR_PROP_TYPE_MISMATCH,
	/*
	 * Indicates that a user buffer argument is too small for the resulting
	 * string transformation.
	 */
	I2C_ERR_BUF_TOO_SMALL,
} i2c_err_t;

typedef struct i2c_hdl i2c_hdl_t;
typedef struct i2c_ctrl i2c_ctrl_t;
typedef struct i2c_ctrl_iter i2c_ctrl_iter_t;
typedef struct i2c_ctrl_disc i2c_ctrl_disc_t;
typedef struct i2c_prop_info i2c_prop_info_t;
typedef struct i2c_port i2c_port_t;
typedef struct i2c_port_iter i2c_port_iter_t;
typedef struct i2c_port_disc i2c_port_disc_t;
typedef struct i2c_port_map i2c_port_map_t;
typedef struct i2c_dev_iter i2c_dev_iter_t;
typedef struct i2c_dev_disc i2c_dev_disc_t;
typedef struct i2c_dev_info i2c_dev_info_t;
typedef struct i2c_dev_add_req i2c_dev_add_req_t;
typedef struct i2c_mux_iter i2c_mux_iter_t;
typedef struct i2c_mux_disc i2c_mux_disc_t;
typedef struct i2c_io_req i2c_io_req_t;
typedef struct smbus_io_req smbus_io_req_t;

typedef enum i2c_iter {
	I2C_ITER_VALID,
	I2C_ITER_DONE,
	I2C_ITER_ERROR
} i2c_iter_t;

extern i2c_hdl_t *i2c_init(void);
extern void i2c_fini(i2c_hdl_t *);

/*
 * Error Information. Each handle (and objects created from it) has a single
 * error and should only be used from one thread at any given time. An error can
 * be a semantic error or a specific class of I/O error.
 */
extern i2c_err_t i2c_err(i2c_hdl_t *);
extern i2c_ctrl_error_t i2c_ctrl_err(i2c_hdl_t *);
extern int32_t i2c_syserr(i2c_hdl_t *);
extern const char *i2c_errmsg(i2c_hdl_t *);
extern const char *i2c_errtostr(i2c_hdl_t *, i2c_err_t);
extern const char *i2c_ctrl_errtostr(i2c_hdl_t *, i2c_ctrl_error_t);

/*
 * Discover and initialize i2c controllers.
 *
 * Information that is obtained during discovery should only be considered to
 * last as long as you are handling its relative discovery entry point. This
 * includes the devinfo entities.
 */
extern bool i2c_ctrl_discover_init(i2c_hdl_t *, i2c_ctrl_iter_t **);
extern i2c_iter_t i2c_ctrl_discover_step(i2c_ctrl_iter_t *,
    const i2c_ctrl_disc_t **);
extern void i2c_ctrl_discover_fini(i2c_ctrl_iter_t *);
typedef bool (*i2c_ctrl_disc_f)(i2c_hdl_t *, const i2c_ctrl_disc_t *, void *);
extern bool i2c_ctrl_discover(i2c_hdl_t *, i2c_ctrl_disc_f, void *);

extern di_node_t i2c_ctrl_disc_devi(const i2c_ctrl_disc_t *);
extern di_minor_t i2c_ctrl_disc_minor(const i2c_ctrl_disc_t *);

extern bool i2c_ctrl_init(i2c_hdl_t *, di_node_t, i2c_ctrl_t **);
extern bool i2c_ctrl_init_by_path(i2c_hdl_t *, const char *, i2c_ctrl_t **);
extern void i2c_ctrl_fini(i2c_ctrl_t *);
extern i2c_hdl_t *i2c_ctrl_hdl(i2c_ctrl_t *);
extern const char *i2c_ctrl_name(i2c_ctrl_t *);
extern const char *i2c_ctrl_path(i2c_ctrl_t *);
extern int32_t i2c_ctrl_instance(i2c_ctrl_t *);
extern uint32_t i2c_ctrl_nprops(i2c_ctrl_t *);

/*
 * Controller property information. Note, there are no discovery APIs right now
 * as all properties are currently part of the framework. The system will return
 * information about all known properties. If the property is not supported by
 * the controller, then only a subset of information will be valid: the id,
 * type, and name.
 */
extern const char *i2c_prop_info_name(i2c_prop_info_t *);
extern i2c_prop_t i2c_prop_info_id(i2c_prop_info_t *);
extern i2c_prop_type_t i2c_prop_info_type(i2c_prop_info_t *);
extern bool i2c_prop_info_sup(i2c_prop_info_t *);
extern i2c_prop_perm_t i2c_prop_info_perm(i2c_prop_info_t *);
extern bool i2c_prop_info_def_u32(i2c_prop_info_t *, uint32_t *);
extern const i2c_prop_range_t *i2c_prop_info_pos(i2c_prop_info_t *);
extern bool i2c_prop_info(i2c_ctrl_t *, i2c_prop_t, i2c_prop_info_t **);
extern bool i2c_prop_info_by_name(i2c_ctrl_t *, const char *,
    i2c_prop_info_t **);
extern void i2c_prop_info_free(i2c_prop_info_t *);

/*
 * Get and set a property value.
 */
extern bool i2c_prop_get(i2c_ctrl_t *, i2c_prop_t, void *, size_t *);
extern bool i2c_prop_set(i2c_ctrl_t *, i2c_prop_t, const void *, size_t);

/*
 * Port discovery.
 */
extern bool i2c_port_discover_init(i2c_hdl_t *, i2c_port_iter_t **);
extern i2c_iter_t i2c_port_discover_step(i2c_port_iter_t *,
    const i2c_port_disc_t **);
extern void i2c_port_discover_fini(i2c_port_iter_t *);
typedef bool (*i2c_port_disc_f)(i2c_hdl_t *, const i2c_port_disc_t *, void *);
extern bool i2c_port_discover(i2c_hdl_t *, i2c_port_disc_f, void *);

extern di_node_t i2c_port_disc_devi(const i2c_port_disc_t *);
extern const char *i2c_port_disc_path(const i2c_port_disc_t *);

extern bool i2c_port_init(i2c_hdl_t *, di_node_t, i2c_port_t **);
extern bool i2c_port_init_by_path(i2c_hdl_t *, const char *, i2c_port_t **);
extern void i2c_port_fini(i2c_port_t *);
extern const char *i2c_port_name(i2c_port_t *);
extern const char *i2c_port_path(i2c_port_t *);
extern uint32_t i2c_port_portno(i2c_port_t *);
typedef enum {
	I2C_PORT_TYPE_CTRL,
	I2C_PORT_TYPE_MUX
} i2c_port_type_t;
extern i2c_port_type_t i2c_port_type(i2c_port_t *);

/*
 * The port map provides information about all the addresses that are in use
 * from this port's perspective. This is a point in time snapshot that is taken
 * when the function is called. From there, information about a given address
 * can be inquired.
 */
extern bool i2c_port_map_snap(i2c_port_t *, i2c_port_map_t **);
extern void i2c_port_map_free(i2c_port_map_t *);

extern void i2c_port_map_ndevs(const i2c_port_map_t *, uint32_t *, uint32_t *);
extern bool i2c_port_map_addr_info(const i2c_port_map_t *, const i2c_addr_t *,
    uint32_t *, bool *, major_t *);

/*
 * Request to add a device under the given port. This is used to add the
 * specified device into the tree under the given port (whether a controller or
 * mux). This will create a device and attempt to bind a driver to it. It will
 * also be accessible for user access.
 */
extern bool i2c_device_add_req_init(i2c_port_t *, i2c_dev_add_req_t **);
extern void i2c_device_add_req_fini(i2c_dev_add_req_t *);

extern bool i2c_device_add_req_set_addr(i2c_dev_add_req_t *,
    const i2c_addr_t *);
extern bool i2c_device_add_req_set_name(i2c_dev_add_req_t *, const char *);
extern bool i2c_device_add_req_set_compatible(i2c_dev_add_req_t *,
    char *const *, size_t);
extern bool i2c_device_add_req_exec(i2c_dev_add_req_t *);

/*
 * Remove a device, specified by address, that is directly under the given port.
 */
extern bool i2c_device_rem(i2c_port_t *, const i2c_addr_t *);

/*
 * Discover devices.
 *
 * This returns information about devices that are known to the system. It does
 * not go out and attempt to perform I/O to devices or try to infer what a
 * device is based on the results of a scan.
 */
extern bool i2c_device_discover_init(i2c_hdl_t *, i2c_dev_iter_t **);
extern i2c_iter_t i2c_device_discover_step(i2c_dev_iter_t *,
    const i2c_dev_disc_t **);
extern void i2c_device_discover_fini(i2c_dev_iter_t *);
typedef bool (*i2c_dev_disc_f)(i2c_hdl_t *, const i2c_dev_disc_t *, void *);
extern bool i2c_device_discover(i2c_hdl_t *, i2c_dev_disc_f, void *);

extern const char *i2c_device_disc_name(const i2c_dev_disc_t *);
extern const char *i2c_device_disc_path(const i2c_dev_disc_t *);

extern di_node_t i2c_device_disc_devi(const i2c_dev_disc_t *);
extern di_minor_t i2c_device_disc_devctl(const i2c_dev_disc_t *);

/*
 * Get a snapshot of information about a device and its addresses.
 */
extern bool i2c_device_info_snap(i2c_hdl_t *, di_node_t, i2c_dev_info_t **);
extern void i2c_device_info_free(i2c_dev_info_t *);

extern const char *i2c_device_info_path(const i2c_dev_info_t *);
extern const char *i2c_device_info_name(const i2c_dev_info_t *);
extern const char *i2c_device_info_driver(const i2c_dev_info_t *);
extern int i2c_device_info_instance(const i2c_dev_info_t *);
extern uint32_t i2c_device_info_naddrs(const i2c_dev_info_t *);
extern const i2c_addr_t *i2c_device_info_addr(const i2c_dev_info_t *, uint32_t);
extern i2c_addr_source_t i2c_device_info_addr_source(const i2c_dev_info_t *,
    uint32_t);
extern const i2c_addr_t *i2c_device_info_addr_primary(const i2c_dev_info_t *);

/*
 * Discover muxes.
 */
extern bool i2c_mux_discover_init(i2c_hdl_t *, i2c_mux_iter_t **);
extern i2c_iter_t i2c_mux_discover_step(i2c_mux_iter_t *,
    const i2c_mux_disc_t **);
extern void i2c_mux_discover_fini(i2c_mux_iter_t *);
typedef bool (*i2c_mux_disc_f)(i2c_hdl_t *, const i2c_mux_disc_t *, void *);
extern bool i2c_mux_discover(i2c_hdl_t *, i2c_mux_disc_f, void *);

extern const char *i2c_mux_disc_name(const i2c_mux_disc_t *);
extern const char *i2c_mux_disc_path(const i2c_mux_disc_t *);
extern uint32_t i2c_mux_disc_nports(const i2c_mux_disc_t *);
extern di_node_t i2c_mux_disc_devi(const i2c_mux_disc_t *);
extern di_minor_t i2c_mux_disc_devctl(const i2c_mux_disc_t *);

/*
 * Perform I/O on a device from userland. I/O can be specific to a device, in
 * which case an address is not required, or it can be specific to a port. When
 * targeting a port, then an address is required; however, if the port is a port
 * of a multiplexor, then all of the muxes will be implicitly activated to
 * perform that I/O.
 *
 * I/O requests come in two different forms, an I2C style request and an SMBus
 * style request. The system will translate between the two depending on the
 * controllers capabilities.
 */
extern bool i2c_io_req_init(i2c_port_t *, i2c_io_req_t **);
extern void i2c_io_req_fini(i2c_io_req_t *);

extern bool i2c_io_req_set_addr(i2c_io_req_t *, const i2c_addr_t *);
extern bool i2c_io_req_set_transmit_data(i2c_io_req_t *, const void *, size_t);
extern bool i2c_io_req_set_receive_buf(i2c_io_req_t *, void *, size_t);
extern bool i2c_io_req_exec(i2c_io_req_t *);

extern bool smbus_io_req_init(i2c_port_t *, smbus_io_req_t  **);
extern void smbus_io_req_fini(smbus_io_req_t *);

extern bool smbus_io_req_set_addr(smbus_io_req_t *, const i2c_addr_t *);
extern bool smbus_io_req_set_quick_cmd(smbus_io_req_t *, bool);
extern bool smbus_io_req_set_send_byte(smbus_io_req_t *, uint8_t);
extern bool smbus_io_req_set_write_u8(smbus_io_req_t *, uint8_t, uint8_t);
extern bool smbus_io_req_set_write_u16(smbus_io_req_t *, uint8_t, uint16_t);
extern bool smbus_io_req_set_write_u32(smbus_io_req_t *, uint8_t, uint32_t);
extern bool smbus_io_req_set_write_u64(smbus_io_req_t *, uint8_t, uint64_t);
extern bool smbus_io_req_set_write_block(smbus_io_req_t *, uint8_t,
    const void *, size_t, bool);
extern bool smbus_io_req_set_recv_byte(smbus_io_req_t *, uint8_t *);
extern bool smbus_io_req_set_read_u8(smbus_io_req_t *, uint8_t, uint8_t *);
extern bool smbus_io_req_set_read_u16(smbus_io_req_t *, uint8_t, uint16_t *);
extern bool smbus_io_req_set_read_u32(smbus_io_req_t *, uint8_t, uint32_t *);
extern bool smbus_io_req_set_read_u64(smbus_io_req_t *, uint8_t, uint64_t *);
extern bool smbus_io_req_set_read_block_i2c(smbus_io_req_t *, uint8_t, void *,
    size_t);
extern bool smbus_io_req_set_process_call(smbus_io_req_t *, uint8_t, uint16_t,
    uint16_t *);
extern bool smbus_io_req_exec(smbus_io_req_t *);

/*
 * I2C address classification routines. Note, i2c_addr_reserved() only returns
 * true if the address is reserved. If the address is invalid, it will return
 * false as well.
 */
extern bool i2c_addr_reserved(const i2c_addr_t *);

/*
 * Initialize information about a port and device based on the path. If the bool
 * is set to true, then we're allowed to return with just a port and no device
 * information due to the path ending at a port.
 */
extern bool i2c_port_dev_init_by_path(i2c_hdl_t *, const char *, bool,
    i2c_port_t **, i2c_dev_info_t **);

/*
 * Utility functions to parse and transform an i2c_addr_t.
 */
extern bool i2c_addr_parse(i2c_hdl_t *, const char *, i2c_addr_t *);
extern bool i2c_addr_to_string(i2c_hdl_t *, const i2c_addr_t *, char *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBI2C_H */
