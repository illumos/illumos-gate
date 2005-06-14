
/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _I2C_SVC_H
#define	_I2C_SVC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * I2C interface return values
 */
#define	I2C_SUCCESS	0
#define	I2C_FAILURE	-1
#define	I2C_INCOMPLETE  -2

/*
 * Used for flags in i2c_transfer_alloc()
 */
#define	I2C_SLEEP	0x01
#define	I2C_NOSLEEP	0x02

/*
 * Version for i2c_transfer_t.i2c_version
 */
#define	I2C_XFER_REV	0

/*
 * Version for i2c_svc_t.i2c_nexus_version
 */
#define	I2C_NEXUS_REV	0


/*
 * Valid transfer flags for i2c_transfer.flags
 */
#define	I2C_WR		0x01	/* write */
#define	I2C_RD		0x02	/* read */
#define	I2C_WR_RD	0x04	/* write then read */

/*
 * Developer's note: i2c_transfer_copyout is sensitive to
 * the ordering of i2c_transfer structure fields.  If any fields
 * are changed, make sure to review i2c_transfer_copyout for
 * possible changes.
 *
 * Fields prefixed with 'I' are input fields passed to the
 * i2c_transfer function, while those prefixed with 'O'
 * are returned from the transfer function.
 */
typedef struct i2c_transfer {
	uint16_t		i2c_version; /* I: Set to I2C_XFER_REV_0 */
	uchar_t			*i2c_wbuf;   /* I: pointer to write buffer */
	uchar_t			*i2c_rbuf;   /* I: pointer to read buffer */
	int			i2c_flags;   /* I: description of transfer */
	uint16_t		i2c_wlen;    /* I: length of write buffer */
	uint16_t		i2c_rlen;    /* I: length of read buffer */
	uint16_t		i2c_w_resid; /* O: bytes not written */
	uint16_t		i2c_r_resid; /* O: bytes not read */
	int16_t			i2c_result;  /* O: return value */
} i2c_transfer_t;

typedef struct i2c_client_hdl *i2c_client_hdl_t;

/*
 * i2c_nexus_reg is passed to the I2C services module
 * through the i2c_nexus_register() interface by the nexus
 * driver.  It contains a version plus the pointer to
 * the functions that I2C services calls.
 */
typedef struct i2c_nexus_reg {
	int	i2c_nexus_version; /* set to I2C_NEXUS_REV_0 */
	int	(*i2c_nexus_transfer)(dev_info_t *dip, struct i2c_transfer *);
} i2c_nexus_reg_t;

/*
 * Interfaces for I2C client drivers
 */
int i2c_client_register(dev_info_t *dip, i2c_client_hdl_t *i2c_hdl);
void i2c_client_unregister(i2c_client_hdl_t i2c_hdl);
int i2c_transfer(i2c_client_hdl_t i2c_hdl, i2c_transfer_t *i2c_tran);
int i2c_transfer_alloc(i2c_client_hdl_t i2c_hdl,
			i2c_transfer_t **i2c,
			uint16_t wlen,
			uint16_t rlen,
			uint_t flags);
void i2c_transfer_free(i2c_client_hdl_t i2c_hdl, i2c_transfer_t *i2c);

/*
 * Interfaces for I2C nexus drivers
 */
void i2c_nexus_register(dev_info_t *dip, i2c_nexus_reg_t *nexus_reg);
void i2c_nexus_unregister(dev_info_t *dip);

#ifdef	__cplusplus
}
#endif

#endif /* _I2C_SVC_H */
