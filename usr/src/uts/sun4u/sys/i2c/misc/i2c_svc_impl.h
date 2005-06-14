/*
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _I2C_SVC_IMPL_H
#define	_I2C_SVC_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * i2c_transfer_alloc is a wrapper structure that is used
 * to store i2c_transfer_t allocation information so that
 * the caller to i2c_transfer_allocate() can modify the
 * buffer/size fields and i2c_transfer_free() will still
 * be able to recover all buffers.
 */
typedef struct i2c_transfer_alloc {
	i2c_transfer_t		i2cw_i2ct;
	uint32_t		i2cw_size;
} i2c_transfer_alloc_t;

#define	CHDL(client_hdl) ((i2c_client_hdl_impl_t *)(client_hdl))

/*
 * i2c_client_hdl_impl is the real implementation of
 * i2c_client_hdl.
 */
typedef struct i2c_client_hdl_impl {
	dev_info_t	*chdl_dip; /* dip for I2C device */
	struct i2c_nexus_reg *chdl_nexus_reg;
} i2c_client_hdl_impl_t;

/*
 * i2c_nexus_reg_list are the elements of a linked list which
 * tracks all I2C parents.
 */
typedef struct i2c_nexus_reg_list {
	i2c_nexus_reg_t nexus_reg;
	dev_info_t	*dip;
	struct i2c_nexus_reg_list *next;
} i2c_nexus_reg_list_t;

#ifdef	__cplusplus
}
#endif

#endif /* _I2C_SVC_IMPL_H */
