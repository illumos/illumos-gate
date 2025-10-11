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

#ifndef _SYS_I2C_IOCTL_H
#define	_SYS_I2C_IOCTL_H

/*
 * Userland i2c requests.
 */

#include <sys/types.h>
#include <sys/i2c/i2c.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This is a private property to aid nexus type discovery.
 */
#define	I2C_NEXUS_TYPE_PROP	"i2c-nexus-type"
#define	I2C_NEXUS_TYPE_PORT	"port"
#define	I2C_NEXUS_TYPE_CTRL	"controller"
#define	I2C_NEXUS_TYPE_MUX	"mux"

/*
 * Base user ioctl type.
 */
#define	UI2C_IOCTL	(('i' << 24) | ('2' << 16) | ('c' << 8))

#define	UI2C_IOCTL_CTRL_NPROPS		(UI2C_IOCTL | 0x00)
typedef struct ui2c_ctrl_nprops {
	uint16_t ucp_nstd;
	uint16_t ucp_npriv;
} ui2c_ctrl_nprops_t;

#define	UI2C_IOCTL_CTRL_PROP_INFO	(UI2C_IOCTL | 0x01)

/*
 * Get information about a property.
 */
typedef struct ui2c_prop_info {
	i2c_error_t upi_error;
	uint32_t upi_prop;
	uint32_t upi_type;
	uint32_t upi_perm;
	uint32_t upi_def_len;
	uint32_t upi_pos_len;
	char upi_name[I2C_PROP_NAME_MAX];
	uint8_t upi_def[I2C_PROP_SIZE_MAX];
	uint8_t upi_pos[I2C_PROP_SIZE_MAX];
} ui2c_prop_info_t;

#define	UI2C_IOCTL_CTRL_PROP_GET	(UI2C_IOCTL | 0x02)
#define	UI2C_IOCTL_CTRL_PROP_SET	(UI2C_IOCTL | 0x03)

/*
 * Get and set a property. up_size is used to indicate how many bytes in
 * up_value are valid on a property set and is filled in on a property get.
 */
typedef struct ui2c_prop {
	i2c_error_t up_error;
	uint32_t up_prop;
	uint32_t up_size;
	uint8_t up_value[I2C_PROP_SIZE_MAX];
} ui2c_prop_t;

/*
 * These ioctls are used to add and remove an i2c device from the system. The
 * device will be added or removed directly under the port that the ioctl is
 * performed upon, this may be a controller or a mux. When adding a device, the
 * address must by unique within the port and any upstream ports. See
 * uts/common/io/i2c/i2cnex/i2cnex_addr.c for more background.
 *
 * When adding a structure, the nvlist is used. When removing it, we just pass
 * an address in using the second structure. The nvlist is due to the assumption
 * that things are going to get more complex eventually and need to include
 * things like properties. Either way, the intent is that this is private to
 * libi2c and it can change.
 */
#define	UI2C_IOCTL_DEVICE_ADD		(UI2C_IOCTL | 0x04)
#define	UI2C_IOCTL_DEVICE_REMOVE	(UI2C_IOCTL | 0x05)

#define	UI2C_IOCTL_NVL_MAX_SIZE	0x4000		/* 16 KiB */
#define	UI2C_IOCTL_NVL_ADDR	"address"	/* uint16_t */
#define	UI2C_IOCTL_NVL_TYPE	"type"		/* uint16_t */
#define	UI2C_IOCTL_NVL_NAME	"name"		/* string */
#define	UI2C_IOCTL_NVL_COMPAT	"compat"	/* string[] (optional) */
#define	UI2C_IOCTL_NVL_NCOMPAT_MAX	32	/* max compat[] length */

typedef struct ui2c_dev {
	i2c_error_t uda_error;
	uintptr_t uda_nvl;
	size_t uda_nvl_len;
} ui2c_dev_add_t;

typedef struct ui2c_dev_rem {
	i2c_error_t udr_error;
	i2c_addr_t udr_addr;
} ui2c_dev_rem_t;

/*
 * These commands are used to issue a request. Today, these can target any port.
 * If the port is downstream of a mux, the mux will be set up appropriately to
 * reach that port. These use the shared i2c_req_t and smbus_req_t found in
 * <sys/i2c/i2c.h>.
 *
 * In the future, we may want to have this work on a device. If we did, it would
 * be the same thing, but constrain the address in question to one that a
 * device actually had from the kernel's perspective.
 */
#define	UI2C_IOCTL_I2C_REQ		(UI2C_IOCTL | 0x06)
#define	UI2C_IOCTL_SMBUS_REQ		(UI2C_IOCTL | 0x07)

/*
 * Get information about a port and the addresses that exist underneath it.
 */
#define	UI2C_IOCTL_PORT_INFO		(UI2C_IOCTL | 0x08)

typedef struct ui2c_port_addr_info {
	bool pai_downstream;
	uint8_t pai_ndevs;
	major_t pai_major;
	uint16_t pai_pad;
} ui2c_port_addr_info_t;

typedef struct ui2c_port_info {
	i2c_error_t upo_error;
	uint32_t upo_portno;
	uint32_t upo_ndevs;
	uint32_t upo_ndevs_ds;
	ui2c_port_addr_info_t upo_7b[1 << 7];
} ui2c_port_info_t;

/*
 * Get information about about a device and the kinds of addresses it uses.
 */
#define	UI2C_IOCTL_DEV_INFO		(UI2C_IOCTL | 0x09)

typedef enum ui2c_dev_flags {
	UI2C_DEV_F_MUX = 1 << 0
} ui2c_dev_flags_t;

typedef struct ui2c_dev_info {
	i2c_error_t udi_error;
	i2c_addr_t udi_primary;
	uint32_t udi_flags;
	uint8_t udi_7b[1 << 7];
} ui2c_dev_info_t;

/*
 * Get information about a mux.
 */
#define	UI2C_IOCTL_MUX_INFO		(UI2C_IOCTL | 0x0a)

typedef struct ui2c_mux_info {
	i2c_error_t umi_error;
	uint32_t umi_nports;
} ui2c_mux_info_t;

#if defined(_KERNEL) && defined(_SYSCALL32)
#pragma pack(4)
typedef struct {
	i2c_error_t uda_error;
	uintptr32_t uda_nvl;
	size32_t uda_nvl_len;
} ui2c_dev_add32_t;

#pragma pack() /* pack(4) */
#endif	/* _KERNEL && _SYSCALL32 */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_I2C_IOCTL_H */
