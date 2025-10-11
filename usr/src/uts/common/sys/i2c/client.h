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

#ifndef _SYS_I2C_CLIENT_H
#define	_SYS_I2C_CLIENT_H

/*
 * I2C client device driver interface
 */

#include <sys/devops.h>
#include <sys/stdint.h>
#include <sys/stdbool.h>
#include <sys/i2c/i2c.h>
#include <sys/sensors.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct i2c_client i2c_client_t;
typedef struct i2c_reg_hdl i2c_reg_hdl_t;
typedef struct i2c_txn i2c_txn_t;

/*
 * Initialize a new I2C client that refers to the specified dev_info_t's
 * register property to target a specific address. Each client is independent.
 * Note, these calls all assume dip is the caller's dip. If it is not the
 * caller's dip, then the caller must ensure that they have a hold on
 * dev_info_t. Currently, this is not meant to be used as an LDI style
 * interface.
 */
extern i2c_errno_t i2c_client_init(dev_info_t *, uint32_t, i2c_client_t **);
extern void i2c_client_destroy(i2c_client_t *);

/*
 * Some devices may need access to addresses that they don't exclusively own or
 * are missing from their reg[] property. This provides a means to get access to
 * this address. For an exclusive address, no one must have it already. For a
 * shared address, it is claimable if it is free or it is already owned by
 * another instance of the calling driver. Multiple drivers cannot own a shared
 * address. If the address is already in reg[], then this acts just like
 * i2c_client_init().
 */
typedef enum {
	/*
	 * If specified, indicates that the address is shared across multiple
	 * devices. If not specified, this address will be unique to the device.
	 */
	I2C_CLAIM_F_SHARED	= 1 << 0
} i2c_claim_flags_t;

extern i2c_errno_t i2c_client_claim_addr(dev_info_t *, const i2c_addr_t *,
    i2c_claim_flags_t, i2c_client_t **);

/*
 * Obtain the address that corresponds to a client.
 */
extern const i2c_addr_t *i2c_client_addr(i2c_client_t *);

/*
 * There are many times when multiple operations need to be performed on the bus
 * in a row without intervening traffic. Control of the bus is represented by an
 * 'i2c_txn_t'. This is passed along to all I/O operations to indicate and track
 * that the bus is owned. Similarly, this also blocks other operations on the
 * controller / bus such as the getting and setting of properties. These holds
 * are not intended to be long-lived due to the nature of them.
 *
 * Operations are not required to have an explicit hold in this way. If one
 * passes NULL for the 'i2c_txn_t *' argument to any of the I/O functions, then
 * the operation will take and release a bus hold for the duration of its
 * operation as only one request can be active on the bus at any time.
 */

typedef enum {
	I2C_BUS_LOCK_F_NONBLOCK = 1 << 0
} i2c_bus_lock_flags_t;

extern i2c_errno_t i2c_bus_lock(i2c_client_t *, i2c_bus_lock_flags_t,
    i2c_txn_t **);
extern void i2c_bus_unlock(i2c_txn_t *);

/*
 * Current version of the register access structure. The register access
 * functions are intended to be a way to more easily access standard device
 * registers.
 */
#define	I2C_REG_ACC_ATTR_V0	0

typedef struct i2c_reg_acc_attr {
	/*
	 * Specifies the current version of the attribute structure. This should
	 * be I2C_REG_ACC_ATTR_V0.
	 */
	uint16_t i2cacc_version;
	/*
	 * Set as zero for now.
	 */
	uint16_t i2cacc_flags;
	/*
	 * Indicates the length in bytes of the addresses and registers.
	 */
	uint8_t i2cacc_addr_len;
	uint8_t i2cacc_reg_len;
	/*
	 * These are the standard DDI swapping attributes (e.g.
	 * DDI_NEVERSWAP_ACC). These can be left at their default for a 1 byte
	 * value. For 2 byte values this must be set to either to the BE or LE
	 * access.
	 */
	uint8_t i2cacc_addr_endian;
	uint8_t i2cacc_reg_endian;
	/*
	 * The maximum valid address (inclusive) on the device.
	 */
	uint64_t i2cacc_addr_max;
} i2c_reg_acc_attr_t;

extern i2c_errno_t i2c_reg_handle_init(i2c_client_t *,
    const i2c_reg_acc_attr_t *, i2c_reg_hdl_t **);
extern void i2c_reg_handle_destroy(i2c_reg_hdl_t *);

/*
 * Read and write device registers from the requested address. This will read
 * the specified number of registers from the device and assumes that i2c
 * addresses auto-increment. The size is the size of the data buffer. It must be
 * an even multiple of the number of registers that one wishes to read or write.
 */
extern bool i2c_reg_get(i2c_txn_t *, i2c_reg_hdl_t *, uint64_t, void *,
    uint32_t, i2c_error_t *);
extern bool i2c_reg_put(i2c_txn_t *, i2c_reg_hdl_t *, uint64_t, const void *,
    uint32_t, i2c_error_t *);

/*
 * Operations to get at the maximums that a client can read, write, or otherwise
 * perform. Currently we have plumbed through the ones that drivers have needed
 * to date. As most things are encouraged to use the register interface. When
 * they don't they are using small 1-2 byte SMBus read and write APIs that are
 * easy to translate. We should feel free to add ways to get at the underlying
 * controller limits if we find it useful.
 */
extern uint32_t i2c_reg_max_read(i2c_reg_hdl_t *);
extern uint32_t i2c_reg_max_write(i2c_reg_hdl_t *);

/*
 * These are SMBus aliases for devices where that makes sense versus the general
 * register interface. More can be added here based on driver need.
 */
extern bool smbus_client_send_byte(i2c_txn_t *, i2c_client_t *, uint8_t,
    i2c_error_t *);
extern bool smbus_client_write_u8(i2c_txn_t *, i2c_client_t *, uint8_t, uint8_t,
    i2c_error_t *);
extern bool smbus_client_write_u16(i2c_txn_t *, i2c_client_t *, uint8_t,
    uint16_t, i2c_error_t *);
extern bool smbus_client_recv_byte(i2c_txn_t *, i2c_client_t *, uint8_t *,
    i2c_error_t *);
extern bool smbus_client_read_u8(i2c_txn_t *, i2c_client_t *, uint8_t,
    uint8_t *, i2c_error_t *);
extern bool smbus_client_read_u16(i2c_txn_t *, i2c_client_t *, uint8_t,
    uint16_t *, i2c_error_t *);

extern const char *i2c_client_errtostr(i2c_client_t *, i2c_errno_t);
extern const char *i2c_client_ctrl_errtostr(i2c_client_t *, i2c_ctrl_error_t);

/*
 * This is a conveience routine for ksensor creation.
 */
extern int i2c_client_ksensor_create_scalar(i2c_client_t *, uint64_t,
    const ksensor_ops_t *, void *, const char *, id_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SYS_I2C_CLIENT_H */
