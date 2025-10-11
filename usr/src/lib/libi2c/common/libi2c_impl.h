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

#ifndef _LIBI2C_IMPL_H
#define	_LIBI2C_IMPL_H

/*
 * Implementation details of libi2c.
 */

#include <locale.h>
#include <libnvpair.h>
#include <libi2c.h>
#include <sys/i2c/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Maximum size of an internal error message.
 */
#define	I2C_ERR_LEN	1024

/*
 * Name of the driver that we expect to be driving an instance of the i2c nexus.
 */
#define	I2C_NEX_DRV	"i2cnex"

typedef struct i2c_err_data {
	i2c_err_t ie_err;
	int32_t ie_syserr;
	i2c_ctrl_error_t ie_ctrl_err;
	char ie_errmsg[I2C_ERR_LEN];
	size_t ie_errlen;
} i2c_err_data_t;

struct i2c_hdl {
	i2c_err_data_t ih_err;
	locale_t ih_c_loc;
	int ih_devfd;
};

struct i2c_ctrl_disc {
	di_node_t icd_devi;
	di_minor_t icd_minor;
};

struct i2c_ctrl_iter {
	i2c_hdl_t *ci_hdl;
	di_node_t ci_root;
	bool ci_done;
	di_node_t ci_cur;
	i2c_ctrl_disc_t ci_disc;
};

struct i2c_ctrl {
	i2c_hdl_t *ctrl_hdl;
	int32_t ctrl_inst;
	char *ctrl_name;
	char *ctrl_path;
	char *ctrl_minor;
	uint16_t ctrl_nstd;
	uint16_t ctrl_npriv;
	int ctrl_fd;
};

struct i2c_port_disc {
	di_node_t pd_devi;
	char pd_path[PATH_MAX];
};

struct i2c_port_iter {
	i2c_hdl_t *pi_hdl;
	bool pi_done;
	di_node_t pi_root;
	uint32_t pi_nalloc;
	uint32_t pi_nports;
	uint32_t pi_curport;
	di_node_t *pi_ports;
	i2c_port_disc_t pi_disc;
};

struct i2c_port {
	i2c_hdl_t *port_hdl;
	int32_t port_inst;
	int port_fd;
	char *port_name;
	char *port_minor;
	char port_path[PATH_MAX];
	ui2c_port_info_t port_info;
	i2c_port_type_t port_type;
};

struct i2c_port_map {
	i2c_hdl_t *pm_hdl;
	ui2c_port_info_t pm_info;
};

struct i2c_io_req {
	i2c_port_t *io_port;
	bool io_addr_valid;
	i2c_addr_t io_addr;
	size_t io_tx_len;
	size_t io_rx_len;
	const void *io_tx_buf;
	void *io_rx_buf;
};

struct smbus_io_req {
	i2c_port_t *sir_port;
	bool sir_addr_valid;
	i2c_addr_t sir_addr;
	bool sir_op_valid;
	smbus_op_t sir_op;
	i2c_req_flags_t sir_flags;
	uint8_t sir_cmd;
	uint64_t sir_write;
	const void *sir_writep;
	size_t sir_wlen;
	void *sir_readp;
	size_t sir_rlen;
};

typedef enum {
	I2C_DEV_ADD_REQ_FIELD_NAME	= 1 << 0,
	I2C_DEV_ADD_REQ_FIELD_ADDR	= 1 << 1
} i2c_dev_add_req_field_t;

struct i2c_dev_add_req {
	i2c_port_t *add_port;
	nvlist_t *add_nvl;
	uint32_t add_need;
};

typedef struct {
	di_minor_t dmi_minor;
	di_node_t dmi_node;
} dev_map_info_t;

typedef struct {
	di_node_t dpi_port;
	bool dpi_scanned;
	bool dpi_7bit_done;
	bool dpi_10bit_done;
	uint16_t dpi_curidx;
	dev_map_info_t dpi_7b[1 << 7];
	dev_map_info_t dpi_10b[1 << 10];
} dev_port_info_t;

struct i2c_dev_disc {
	const dev_map_info_t *idd_map;
	const dev_port_info_t *idd_port;
	char idd_path[PATH_MAX];
};

struct i2c_dev_iter {
	i2c_hdl_t *di_hdl;
	bool di_done;
	i2c_port_iter_t *di_iter;
	const i2c_port_disc_t *di_curport;
	dev_port_info_t di_info;
	i2c_dev_disc_t di_disc;
};

struct i2c_dev_info {
	char *dinfo_name;
	char dinfo_path[PATH_MAX];
	char *dinfo_driver;
	char *dinfo_minor;
	int dinfo_inst;
	uint32_t dinfo_naddrs;
	i2c_addr_t *dinfo_addrs;
	ui2c_dev_info_t dinfo_info;
};

struct i2c_prop_info {
	i2c_hdl_t *pinfo_hdl;
	ui2c_prop_info_t pinfo_info;
	bool pinfo_sup;
};

struct i2c_mux_disc {
	di_node_t md_devi;
	di_minor_t md_minor;
	char md_path[PATH_MAX];
	ui2c_mux_info_t md_info;
};

struct i2c_mux_iter {
	i2c_hdl_t *mi_hdl;
	di_node_t mi_root;
	di_node_t mi_cur;
	bool mi_done;
	i2c_mux_disc_t mi_disc;
};

/*
 * Common success and failure interfaces.
 */
extern bool i2c_error(i2c_hdl_t *, i2c_err_t, int32_t, const char *, ...)
    __PRINTFLIKE(4);
extern bool i2c_success(i2c_hdl_t *);
extern bool i2c_ioctl_syserror(i2c_hdl_t *, int, const char *);
extern bool i2c_ioctl_error(i2c_hdl_t *, const i2c_error_t *, const char *);
extern bool i2c_nvlist_error(i2c_hdl_t *, int, const char *);

/*
 * Common validation routines
 */
extern bool i2c_addr_validate(i2c_hdl_t *, const i2c_addr_t *);
extern bool i2c_name_validate(i2c_hdl_t *, const char *, const char *);

/*
 * Misc. routines.
 */
typedef enum {
	I2C_NODE_T_CTRL,
	I2C_NODE_T_PORT,
	I2C_NODE_T_DEV,
	I2C_NODE_T_MUX,
	I2C_NODE_T_OTHER
} i2c_node_type_t;

extern i2c_node_type_t i2c_node_type(di_node_t);
extern di_minor_t i2c_node_minor(di_node_t);
extern bool i2c_node_is_type(di_node_t, i2c_node_type_t);
extern bool i2c_node_to_path(i2c_hdl_t *, di_node_t, char *, size_t);
extern bool i2c_kernel_address_parse(i2c_hdl_t *, const char *, i2c_addr_t *);
extern bool i2c_reg_to_addr(i2c_hdl_t *, di_node_t, i2c_addr_t *, uint32_t);
extern bool i2c_addr_equal(const i2c_addr_t *, const i2c_addr_t *);

/*
 * Various path lookup routines.
 */
extern di_node_t i2c_path_find_ctrl(di_node_t, const char *);
extern di_node_t i2c_path_find_mux(di_node_t);
extern di_node_t i2c_path_find_port(di_node_t, const char *);
extern di_node_t i2c_path_find_device(i2c_hdl_t *, di_node_t, const char *);
extern bool i2c_path_parse(i2c_hdl_t *, const char *, di_node_t, di_node_t *,
    i2c_node_type_t *, i2c_err_t);

#ifdef __cplusplus
}
#endif

#endif /* _LIBI2C_IMPL_H */
