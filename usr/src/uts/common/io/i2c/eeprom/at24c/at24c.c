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

/*
 * AT24 series EEPROM device driver.
 *
 * The AT24 series of EEPROMs are a venerable line that cover several different
 * sizes. These all have similar features:
 *
 *  - The EEPROM is organized in terms of pages. The size of a page can be as
 *    small as 8 bytes or as large as 256 bytes.
 *
 *  - Addressing is often a combination of both the device address and a 1 or
 *    2-byte address register. Each register location generally stores a single
 *    byte of data. This means that a 1-byte register covers data locations
 *    [7:0] and the 2-byte, [15:0]. If a device exceeds that, then they start
 *    using additional I2C addresses. Let's look at a few examples:
 *
 *    1) The AT24C01 is a 128 byte device. It uses a 1-byte address. It uses
 *    addr[6:0] to address all of the data. It only uses a single I2C address.
 *
 *    2) The AT24C32 is a 32 KiB device that uses 2-byte addresses. While it
 *    needs a 12-bit address, because it uses a 2-byte address, it only needs to
 *    use a single I2C address.
 *
 *    3) The AT24C08 is an 8 KiB device, which means it needs 1024 data
 *    locations. It uses a single byte address register. Therefore, it specifies
 *    addr[9:8] using the I2C address that refers to the device and addr[7:0]
 *    using the register.
 *
 *    These different cases lead us to using multiple clients to cover a single
 *    device.
 *
 *  - The device supports random reads. These reads can and will increment the
 *    address register internally. This is the primary way that we support
 *    reads.
 *
 *  - The device supports what it calls page writes and single byte writes. The
 *    page writes are more interesting. Effectively a page write is where we
 *    write multiple bytes starting from the address. The device will internally
 *    increment this, but it will roll over when it hits the page boundary.
 *
 *    After a write completes, the device will no longer ack its address until
 *    the write completes. Therefore, we need to end up polling for
 *    completeness.
 *
 *  - With the above we don't employ actual I2C bus exclusion; however, the
 *    driver does use a per-instance mutex to ensure that only one write per
 *    device is going on at a time and that no other reads can interleave that
 *    until the actual polling has completed.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/bitext.h>
#include <sys/sysmacros.h>
#include <sys/i2c/client.h>
#include <eedev.h>

/*
 * The default size in bytes that we use as the maximum amount of I/O that we
 * will perform in one go.
 */
#define	AT24C_MAX_IO	128

/*
 * This is the default time and attempts that we'll wait for a write to
 * complete. Most devices have a 5ms timeout, but some have up to 20ms. We
 * basically will go up to 25ms here. This isn't an absolute delay so we can
 * make sure that if we lose the i2c bus, we still try at least 5 times.
 */
static uint32_t at24c_write_to_count = 5;
static uint32_t at24c_write_delay_us = 5000;

typedef struct at24c_ident {
	const char *ati_name;
	const char *ati_compat;
	size_t ati_size;
	size_t ati_page;
	bool ati_addr16;
} at24c_ident_t;

typedef struct at24c {
	dev_info_t *at_dip;
	kmutex_t at_mutex;
	const at24c_ident_t *at_ident;
	size_t at_naddrs;
	i2c_client_t **at_clients;
	i2c_reg_hdl_t **at_regs;
	eedev_hdl_t *at_eedev;
	uint8_t at_buf[AT24C_MAX_IO];
} at24c_t;

static const at24c_ident_t at24c_idents[] = {
	{
		.ati_name = "at24c01",
		.ati_compat = "atmel,at24c01",
		.ati_size = 128,
		.ati_page = 8,
		.ati_addr16 = false
	}, {
		.ati_name = "at24c02",
		.ati_compat = "atmel,at24c02",
		.ati_size = 256,
		.ati_page = 8,
		.ati_addr16 = false
	}, {
		.ati_name = "at24c04",
		.ati_compat = "atmel,at24c04",
		.ati_size = 512,
		.ati_page = 16,
		.ati_addr16 = false
	}, {
		.ati_name = "at24c08",
		.ati_compat = "atmel,at24c08",
		.ati_size = 1024,
		.ati_page = 16,
		.ati_addr16 = false
	}, {
		.ati_name = "at24c16",
		.ati_compat = "atmel,at24c16",
		.ati_size = 2 * 1024,
		.ati_page = 16,
		.ati_addr16 = false
	}, {
		.ati_name = "at24c32",
		.ati_compat = "atmel,at24c32",
		.ati_size = 4 * 1024,
		.ati_page = 32,
		.ati_addr16 = true
	}, {
		.ati_name = "at24c64",
		.ati_compat = "atmel,at24c64",
		.ati_size = 8 * 1024,
		.ati_page = 32,
		.ati_addr16 = true
	}, {
		.ati_name = "at24c128",
		.ati_compat = "atmel,at24c128",
		.ati_size = 16 * 1024,
		.ati_page = 64,
		.ati_addr16 = true
	}, {
		.ati_name = "at24c256",
		.ati_compat = "atmel,at24c256",
		.ati_size = 32 * 1024,
		.ati_page = 64,
		.ati_addr16 = true
	}, {
		.ati_name = "at24c512",
		.ati_compat = "atmel,at24c512",
		.ati_size = 64 * 1024,
		.ati_page = 128,
		.ati_addr16 = true
	}, {
		.ati_name = "at24c1024",
		.ati_compat = "atmel,at24c1024",
		.ati_size = 128 * 1024,
		.ati_page = 256,
		.ati_addr16 = true
	}
};

/*
 * Take a device page and offset and turn it into the corresponding I2C client.
 * While the device is arranged in terms of pages, it is addressed in terms of
 * bytes. This is then broken into client and the offset in that client based on
 * whether or not we're using 8-bit or 16-bit addressing.
 */
static void
at24c_page_to_addr(at24c_t *at, uint32_t page, uint32_t pageoff,
    uint32_t *clino, uint32_t *addrp)
{
	uint32_t addr = page * at->at_ident->ati_page + pageoff;
	uint32_t addrlen = at->at_ident->ati_addr16 ? 1 << 16 : 1 << 8;
	*clino = addr / addrlen;
	*addrp = addr % addrlen;
	VERIFY3U(*clino, <, at->at_naddrs);
}

static int
at24c_read(void *arg, struct uio *uio, uint32_t page, uint32_t pageoff,
    uint32_t nbytes)
{
	int ret;
	uint32_t idx, reg;
	i2c_error_t err;
	at24c_t *at = arg;

	at24c_page_to_addr(at, page, pageoff, &idx, &reg);
	mutex_enter(&at->at_mutex);
	if (i2c_reg_get(NULL, at->at_regs[idx], reg, at->at_buf, nbytes,
	    &err)) {
		ret = uiomove(at->at_buf, nbytes, UIO_READ, uio);
	} else {
		dev_err(at->at_dip, CE_WARN, "!failed to read %u bytes on "
		    "client %u, addr 0x%x: 0x%x/0x%x", nbytes, idx, reg,
		    err.i2c_error, err.i2c_ctrl);
		ret = EIO;
	}
	mutex_exit(&at->at_mutex);

	return (ret);
}

/*
 * Determine if this error is an address related NACK which means that the
 * device is still busy.
 */
static bool
at24c_poll_nack(const i2c_error_t *err)
{
	if (err->i2c_error != I2C_CORE_E_CONTROLLER) {
		return (false);
	}

	return (err->i2c_ctrl == I2C_CTRL_E_ADDR_NACK ||
	    err->i2c_ctrl == I2C_CTRL_E_NACK);
}

static int
at24c_write(void *arg, struct uio *uio, uint32_t page, uint32_t pageoff,
    uint32_t nbytes)
{
	int ret = EIO;
	uint32_t idx, reg;
	i2c_error_t err;
	at24c_t *at = arg;

	at24c_page_to_addr(at, page, pageoff, &idx, &reg);
	mutex_enter(&at->at_mutex);
	ret = uiomove(at->at_buf, nbytes, UIO_WRITE, uio);
	if (ret != 0) {
		mutex_exit(&at->at_mutex);
		return (ret);
	}

	if (!i2c_reg_put(NULL, at->at_regs[idx], reg, at->at_buf, nbytes,
	    &err)) {
		dev_err(at->at_dip, CE_WARN, "!failed to write %u bytes on "
		    "client %u, addr 0x%x: 0x%x/0x%x", nbytes, idx, reg,
		    err.i2c_error, err.i2c_ctrl);
		goto done;
	}

	/*
	 * Now we must poll waiting to get an ack. We do this by performing a
	 * simple 1 byte read. The Atmel data sheets generally suggested that
	 * this should actually be us looking for an ack to determine what
	 * operation we want to be able to perform. We use a read here as we
	 * don't want to do a quick write and test how well different clones
	 * handle this.
	 */
	for (uint32_t i = 0; i < at24c_write_to_count; i++) {
		uint8_t val;

		delay(drv_usectohz(at24c_write_delay_us));
		if (i2c_reg_get(NULL, at->at_regs[idx], 0, &val, sizeof (val),
		    &err)) {
			ret = 0;
			break;
		}

		if (!at24c_poll_nack(&err)) {
			dev_err(at->at_dip, CE_WARN, "!failed to read after "
			    "write on client %u, addr 0x%x: 0x%x/0x%x", idx,
			    reg, err.i2c_error, err.i2c_ctrl);
			goto done;
		}
	}

	if (ret != 0) {
		dev_err(at->at_dip, CE_WARN, "!timed out waiting for write ack "
		    "on client %u, addr 0x%x: 0x%x/0x%x",  idx, reg,
		    err.i2c_error, err.i2c_ctrl);
	}

done:
	mutex_exit(&at->at_mutex);
	if (ret != 0) {
		uio->uio_resid += nbytes;
		uio->uio_loffset -= nbytes;
	}
	return (ret);
}

static const eedev_ops_t at24c_eedev_ops = {
	.eo_read = at24c_read,
	.eo_write = at24c_write
};

static bool
at24c_ident(at24c_t *at)
{
	const char *bind = ddi_binding_name(at->at_dip);
	const char *name = ddi_node_name(at->at_dip);

	for (size_t i = 0; i < ARRAY_SIZE(at24c_idents); i++) {
		if (strcmp(bind, at24c_idents[i].ati_name) == 0 ||
		    strcmp(bind, at24c_idents[i].ati_compat) == 0 ||
		    strcmp(name, at24c_idents[i].ati_name) == 0 ||
		    strcmp(name, at24c_idents[i].ati_compat) == 0) {
			at->at_ident = &at24c_idents[i];
			return (true);
		}

	}

	dev_err(at->at_dip, CE_WARN, "failed to match against node name %s "
	    "and binding name %s", name, bind);
	return (false);
}

static bool
at24c_i2c_init(at24c_t *at)
{
	i2c_errno_t err;
	uint8_t addrlen = at->at_ident->ati_addr16 ? 16 : 8;

	at->at_naddrs = at->at_ident->ati_size / (1 << addrlen);
	if ((at->at_ident->ati_size % (1 << addrlen)) != 0)
		at->at_naddrs++;
	VERIFY3U(at->at_naddrs, >, 0);
	at->at_clients = kmem_zalloc(at->at_naddrs * sizeof (i2c_client_t *),
	    KM_SLEEP);
	at->at_regs = kmem_zalloc(at->at_naddrs * sizeof (i2c_reg_hdl_t *),
	    KM_SLEEP);

	if ((err = i2c_client_init(at->at_dip, 0, &at->at_clients[0])) !=
	    I2C_CORE_E_OK) {
		dev_err(at->at_dip, CE_WARN, "failed to create i2c client: "
		    "0x%x", err);
		return (false);
	}

	for (size_t i = 1; i < at->at_naddrs; i++) {
		i2c_addr_t addr = *i2c_client_addr((at->at_clients[0]));

		addr.ia_addr += i;
		if ((err = i2c_client_claim_addr(at->at_dip, &addr, 0,
		    &at->at_clients[i])) != I2C_CORE_E_OK) {
			dev_err(at->at_dip, CE_WARN, "failed to claim client "
			    "%zu address 0x%x: 0x%x", i, addr.ia_addr, err);
			return (false);
		}
	}

	i2c_reg_acc_attr_t attr;
	bzero(&attr, sizeof (attr));

	attr.i2cacc_version = I2C_REG_ACC_ATTR_V0;
	if (at->at_ident->ati_addr16) {
		attr.i2cacc_addr_len = 2;
		attr.i2cacc_addr_endian = DDI_STRUCTURE_BE_ACC;
	} else {
		attr.i2cacc_addr_len = 1;
	}
	attr.i2cacc_addr_max = (1 << addrlen) - 1;
	attr.i2cacc_reg_len = 1;

	for (size_t i = 0; i < at->at_naddrs; i++) {
		if ((err = i2c_reg_handle_init(at->at_clients[i], &attr,
		    &at->at_regs[i])) != I2C_CORE_E_OK) {
			dev_err(at->at_dip, CE_WARN, "failed to create "
			    "register handle %zu: %s (0x%x)", i,
			    i2c_client_errtostr(at->at_clients[i], err), err);
			return (false);
		}
	}

	return (true);
}

static bool
at24c_eedev_init(at24c_t *at)
{
	int ret;
	eedev_reg_t reg;

	bzero(&reg, sizeof (reg));
	reg.ereg_vers = EEDEV_REG_VERS0;
	reg.ereg_size = at->at_ident->ati_size;

	/*
	 * The segment here is true for writes, but reads are not quite as
	 * constrained. However, it's simpler for everything if we specify it
	 * tihs way.
	 */
	reg.ereg_seg = at->at_ident->ati_page;
	reg.ereg_read_gran = 1;
	reg.ereg_write_gran = 1;

	/*
	 * The maximum we can read or write will be told to us by the register
	 * client. This takes the address length into account for us. We can
	 * then further constrain this by the maximum desired I/O in the client.
	 * Finally, for writes, we further constrain it so we don't exceed a
	 * single page when writing.
	 */
	reg.ereg_max_read = MIN(i2c_reg_max_read(at->at_regs[0]), AT24C_MAX_IO);
	reg.ereg_max_write = MIN(i2c_reg_max_write(at->at_regs[0]),
	    AT24C_MAX_IO);
	reg.ereg_max_write = MIN(reg.ereg_max_write, at->at_ident->ati_page);
	reg.ereg_dip = at->at_dip;
	reg.ereg_driver = at;
	reg.ereg_ops = &at24c_eedev_ops;

	if ((ret = eedev_create(&reg, &at->at_eedev)) != 0) {
		dev_err(at->at_dip, CE_WARN, "failed to create eedev device: "
		    "%d", ret);
		return (false);
	}

	return (true);
}

static void
at24c_cleanup(at24c_t *at)
{
	eedev_fini(at->at_eedev);
	for (size_t i = 0; i < at->at_naddrs; i++) {
		i2c_reg_handle_destroy(at->at_regs[i]);
		i2c_client_destroy(at->at_clients[i]);
	}

	if (at->at_naddrs > 0) {
		kmem_free(at->at_regs, sizeof (i2c_reg_hdl_t *) *
		    at->at_naddrs);
		kmem_free(at->at_clients, sizeof (i2c_client_t *) *
		    at->at_naddrs);
	}

	mutex_destroy(&at->at_mutex);
	ddi_set_driver_private(at->at_dip, NULL);
	at->at_dip = NULL;
	kmem_free(at, sizeof (at24c_t));
}

static int
at24c_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	at24c_t *at;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	at = kmem_zalloc(sizeof (at24c_t), KM_SLEEP);
	at->at_dip = dip;
	ddi_set_driver_private(dip, at);
	mutex_init(&at->at_mutex, NULL, MUTEX_DRIVER, NULL);

	if (!at24c_ident(at))
		goto cleanup;

	if (!at24c_i2c_init(at))
		goto cleanup;

	if (!at24c_eedev_init(at))
		goto cleanup;

	return (DDI_SUCCESS);

cleanup:
	at24c_cleanup(at);
	return (DDI_FAILURE);
}

static int
at24c_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	at24c_t *at;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	at = ddi_get_driver_private(dip);
	if (at == NULL) {
		dev_err(dip, CE_WARN, "asked to detach, but missing private "
		    "data");
		return (DDI_FAILURE);
	}
	VERIFY3P(at->at_dip, ==, dip);

	at24c_cleanup(at);
	return (DDI_SUCCESS);
}

static struct dev_ops at24c_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = at24c_attach,
	.devo_detach = at24c_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed
};

static struct modldrv at24c_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "SPD5118 driver",
	.drv_dev_ops = &at24c_dev_ops
};

static struct modlinkage at24c_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &at24c_modldrv, NULL }
};


int
_init(void)
{
	return (mod_install(&at24c_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&at24c_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&at24c_modlinkage));
}
