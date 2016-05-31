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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Deimos - cryptographic acceleration based upon Broadcom 582x.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/ioccom.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/kstat.h>
#include <sys/strsun.h>
#include <sys/note.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#include <sys/crypto/dca.h>

/*
 * Core Deimos driver.
 */

static void		dca_enlist2(dca_listnode_t *, dca_listnode_t *,
    kmutex_t *);
static void		dca_rmlist2(dca_listnode_t *node, kmutex_t *);
static dca_listnode_t	*dca_delist2(dca_listnode_t *q, kmutex_t *);
static void		dca_free_context_list(dca_t *dca);
static int		dca_free_context_low(crypto_ctx_t *ctx);
static int		dca_attach(dev_info_t *, ddi_attach_cmd_t);
static int		dca_detach(dev_info_t *, ddi_detach_cmd_t);
static int		dca_suspend(dca_t *);
static int		dca_resume(dca_t *);
static int		dca_init(dca_t *);
static int		dca_reset(dca_t *, int);
static int		dca_initworklist(dca_t *, dca_worklist_t *);
static void		dca_uninit(dca_t *);
static void		dca_initq(dca_listnode_t *);
static void		dca_enqueue(dca_listnode_t *, dca_listnode_t *);
static dca_listnode_t	*dca_dequeue(dca_listnode_t *);
static dca_listnode_t	*dca_unqueue(dca_listnode_t *);
static dca_request_t	*dca_newreq(dca_t *);
static dca_work_t	*dca_getwork(dca_t *, int);
static void		dca_freework(dca_work_t *);
static dca_work_t	*dca_newwork(dca_t *);
static void		dca_destroywork(dca_work_t *);
static void		dca_schedule(dca_t *, int);
static void		dca_reclaim(dca_t *, int);
static uint_t		dca_intr(char *);
static void		dca_failure(dca_t *, ddi_fault_location_t,
			    dca_fma_eclass_t index, uint64_t, int, char *, ...);
static void		dca_jobtimeout(void *);
static int		dca_drain(dca_t *);
static void		dca_undrain(dca_t *);
static void		dca_rejectjobs(dca_t *);

#ifdef	SCHEDDELAY
static void		dca_schedtimeout(void *);
#endif

/*
 * We want these inlined for performance.
 */
#ifndef	DEBUG
#pragma inline(dca_freereq, dca_getreq, dca_freework, dca_getwork)
#pragma inline(dca_enqueue, dca_dequeue, dca_rmqueue, dca_done)
#pragma inline(dca_reverse, dca_length)
#endif

/*
 * Device operations.
 */
static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	nodev,			/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	dca_attach,		/* devo_attach */
	dca_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	NULL,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	ddi_power,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

#define	IDENT		"PCI Crypto Accelerator"
#define	IDENT_SYM	"Crypto Accel Sym 2.0"
#define	IDENT_ASYM	"Crypto Accel Asym 2.0"

/* Space-padded, will be filled in dynamically during registration */
#define	IDENT3	"PCI Crypto Accelerator Mod 2.0"

#define	VENDOR	"Sun Microsystems, Inc."

#define	STALETIME	(30 * SECOND)

#define	crypto_prov_notify	crypto_provider_notification
		/* A 28 char function name doesn't leave much line space */

/*
 * Module linkage.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* drv_modops */
	IDENT,			/* drv_linkinfo */
	&devops,		/* drv_dev_ops */
};

extern struct mod_ops mod_cryptoops;

static struct modlcrypto modlcrypto = {
	&mod_cryptoops,
	IDENT3
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modldrv,		/* ml_linkage */
	&modlcrypto,
	NULL
};

/*
 * CSPI information (entry points, provider info, etc.)
 */

/* Mechanisms for the symmetric cipher provider */
static crypto_mech_info_t dca_mech_info_tab1[] = {
	/* DES-CBC */
	{SUN_CKM_DES_CBC, DES_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT |
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES_KEY_LEN, DES_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES},
	/* 3DES-CBC */
	{SUN_CKM_DES3_CBC, DES3_CBC_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT |
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC,
	    DES3_MIN_KEY_LEN, DES3_MAX_KEY_LEN, CRYPTO_KEYSIZE_UNIT_IN_BYTES}
};

/* Mechanisms for the asymmetric cipher provider */
static crypto_mech_info_t dca_mech_info_tab2[] = {
	/* DSA */
	{SUN_CKM_DSA, DSA_MECH_INFO_TYPE,
	    CRYPTO_FG_SIGN | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_VERIFY_ATOMIC,
	    CRYPTO_BYTES2BITS(DSA_MIN_KEY_LEN),
	    CRYPTO_BYTES2BITS(DSA_MAX_KEY_LEN),
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},

	/* RSA */
	{SUN_CKM_RSA_X_509, RSA_X_509_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_SIGN |
	    CRYPTO_FG_SIGN_RECOVER | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_VERIFY_RECOVER |
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_SIGN_RECOVER_ATOMIC |
	    CRYPTO_FG_VERIFY_ATOMIC | CRYPTO_FG_VERIFY_RECOVER_ATOMIC,
	    CRYPTO_BYTES2BITS(RSA_MIN_KEY_LEN),
	    CRYPTO_BYTES2BITS(RSA_MAX_KEY_LEN),
	    CRYPTO_KEYSIZE_UNIT_IN_BITS},
	{SUN_CKM_RSA_PKCS, RSA_PKCS_MECH_INFO_TYPE,
	    CRYPTO_FG_ENCRYPT | CRYPTO_FG_DECRYPT | CRYPTO_FG_SIGN |
	    CRYPTO_FG_SIGN_RECOVER | CRYPTO_FG_VERIFY |
	    CRYPTO_FG_VERIFY_RECOVER |
	    CRYPTO_FG_ENCRYPT_ATOMIC | CRYPTO_FG_DECRYPT_ATOMIC |
	    CRYPTO_FG_SIGN_ATOMIC | CRYPTO_FG_SIGN_RECOVER_ATOMIC |
	    CRYPTO_FG_VERIFY_ATOMIC | CRYPTO_FG_VERIFY_RECOVER_ATOMIC,
	    CRYPTO_BYTES2BITS(RSA_MIN_KEY_LEN),
	    CRYPTO_BYTES2BITS(RSA_MAX_KEY_LEN),
	    CRYPTO_KEYSIZE_UNIT_IN_BITS}
};

static void dca_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t dca_control_ops = {
	dca_provider_status
};

static int dca_encrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_encrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_encrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int dca_encrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_encrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static int dca_decrypt_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_decrypt(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_decrypt_update(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int dca_decrypt_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_decrypt_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_cipher_ops_t dca_cipher_ops = {
	dca_encrypt_init,
	dca_encrypt,
	dca_encrypt_update,
	dca_encrypt_final,
	dca_encrypt_atomic,
	dca_decrypt_init,
	dca_decrypt,
	dca_decrypt_update,
	dca_decrypt_final,
	dca_decrypt_atomic
};

static int dca_sign_init(crypto_ctx_t *, crypto_mechanism_t *, crypto_key_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_sign(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_sign_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_sign_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_sign_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *, crypto_data_t *,
    crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_sign_recover_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_sign_recover(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_sign_recover_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_sign_ops_t dca_sign_ops = {
	dca_sign_init,
	dca_sign,
	dca_sign_update,
	dca_sign_final,
	dca_sign_atomic,
	dca_sign_recover_init,
	dca_sign_recover,
	dca_sign_recover_atomic
};

static int dca_verify_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_verify(crypto_ctx_t *, crypto_data_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_verify_update(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_verify_final(crypto_ctx_t *, crypto_data_t *,
    crypto_req_handle_t);
static int dca_verify_atomic(crypto_provider_handle_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_verify_recover_init(crypto_ctx_t *, crypto_mechanism_t *,
    crypto_key_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);
static int dca_verify_recover(crypto_ctx_t *, crypto_data_t *,
    crypto_data_t *, crypto_req_handle_t);
static int dca_verify_recover_atomic(crypto_provider_handle_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *, crypto_data_t *,
    crypto_data_t *, crypto_spi_ctx_template_t, crypto_req_handle_t);

static crypto_verify_ops_t dca_verify_ops = {
	dca_verify_init,
	dca_verify,
	dca_verify_update,
	dca_verify_final,
	dca_verify_atomic,
	dca_verify_recover_init,
	dca_verify_recover,
	dca_verify_recover_atomic
};

static int dca_generate_random(crypto_provider_handle_t, crypto_session_id_t,
    uchar_t *, size_t, crypto_req_handle_t);

static crypto_random_number_ops_t dca_random_number_ops = {
	NULL,
	dca_generate_random
};

static int ext_info_sym(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info, crypto_req_handle_t cfreq);
static int ext_info_asym(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info, crypto_req_handle_t cfreq);
static int ext_info_base(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info, crypto_req_handle_t cfreq, char *id);

static crypto_provider_management_ops_t dca_provmanage_ops_1 = {
	ext_info_sym,		/* ext_info */
	NULL,			/* init_token */
	NULL,			/* init_pin */
	NULL			/* set_pin */
};

static crypto_provider_management_ops_t dca_provmanage_ops_2 = {
	ext_info_asym,		/* ext_info */
	NULL,			/* init_token */
	NULL,			/* init_pin */
	NULL			/* set_pin */
};

int dca_free_context(crypto_ctx_t *);

static crypto_ctx_ops_t dca_ctx_ops = {
	NULL,
	dca_free_context
};

/* Operations for the symmetric cipher provider */
static crypto_ops_t dca_crypto_ops1 = {
	&dca_control_ops,
	NULL,				/* digest_ops */
	&dca_cipher_ops,
	NULL,				/* mac_ops */
	NULL,				/* sign_ops */
	NULL,				/* verify_ops */
	NULL,				/* dual_ops */
	NULL,				/* cipher_mac_ops */
	NULL,				/* random_number_ops */
	NULL,				/* session_ops */
	NULL,				/* object_ops */
	NULL,				/* key_ops */
	&dca_provmanage_ops_1,		/* management_ops */
	&dca_ctx_ops
};

/* Operations for the asymmetric cipher provider */
static crypto_ops_t dca_crypto_ops2 = {
	&dca_control_ops,
	NULL,				/* digest_ops */
	&dca_cipher_ops,
	NULL,				/* mac_ops */
	&dca_sign_ops,
	&dca_verify_ops,
	NULL,				/* dual_ops */
	NULL,				/* cipher_mac_ops */
	&dca_random_number_ops,
	NULL,				/* session_ops */
	NULL,				/* object_ops */
	NULL,				/* key_ops */
	&dca_provmanage_ops_2,		/* management_ops */
	&dca_ctx_ops
};

/* Provider information for the symmetric cipher provider */
static crypto_provider_info_t dca_prov_info1 = {
	CRYPTO_SPI_VERSION_1,
	NULL,				/* pi_provider_description */
	CRYPTO_HW_PROVIDER,
	NULL,				/* pi_provider_dev */
	NULL,				/* pi_provider_handle */
	&dca_crypto_ops1,
	sizeof (dca_mech_info_tab1)/sizeof (crypto_mech_info_t),
	dca_mech_info_tab1,
	0,				/* pi_logical_provider_count */
	NULL				/* pi_logical_providers */
};

/* Provider information for the asymmetric cipher provider */
static crypto_provider_info_t dca_prov_info2 = {
	CRYPTO_SPI_VERSION_1,
	NULL,				/* pi_provider_description */
	CRYPTO_HW_PROVIDER,
	NULL,				/* pi_provider_dev */
	NULL,				/* pi_provider_handle */
	&dca_crypto_ops2,
	sizeof (dca_mech_info_tab2)/sizeof (crypto_mech_info_t),
	dca_mech_info_tab2,
	0,				/* pi_logical_provider_count */
	NULL				/* pi_logical_providers */
};

/* Convenience macros */
#define	DCA_SOFTC_FROM_CTX(ctx)	((dca_t *)(ctx)->cc_provider)
#define	DCA_MECH_FROM_CTX(ctx) \
	(((dca_request_t *)(ctx)->cc_provider_private)->dr_ctx.ctx_cm_type)

static int dca_bindchains_one(dca_request_t *reqp, size_t cnt, int dr_offset,
    caddr_t kaddr, ddi_dma_handle_t handle, uint_t flags,
    dca_chain_t *head, int *n_chain);
static uint64_t dca_ena(uint64_t ena);
static caddr_t dca_bufdaddr_out(crypto_data_t *data);
static char *dca_fma_eclass_string(char *model, dca_fma_eclass_t index);
static int dca_check_acc_handle(dca_t *dca, ddi_acc_handle_t handle,
    dca_fma_eclass_t eclass_index);

static void dca_fma_init(dca_t *dca);
static void dca_fma_fini(dca_t *dca);
static int dca_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err,
    const void *impl_data);


static dca_device_t dca_devices[] = {
	/* Broadcom vanilla variants */
	{	0x14e4, 0x5820, "Broadcom 5820" },
	{	0x14e4, 0x5821, "Broadcom 5821" },
	{	0x14e4, 0x5822, "Broadcom 5822" },
	{	0x14e4, 0x5825, "Broadcom 5825" },
	/* Sun specific OEMd variants */
	{	0x108e, 0x5454, "SCA" },
	{	0x108e, 0x5455, "SCA 1000" },
	{	0x108e, 0x5457, "SCA 500" },
	/* subsysid should be 0x5457, but got 0x1 from HW. Assume both here. */
	{	0x108e, 0x1, "SCA 500" },
};

/*
 * Device attributes.
 */
static struct ddi_device_acc_attr dca_regsattr = {
	DDI_DEVICE_ATTR_V1,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC,
	DDI_FLAGERR_ACC
};

static struct ddi_device_acc_attr dca_devattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

#if !defined(i386) && !defined(__i386)
static struct ddi_device_acc_attr dca_bufattr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};
#endif

static struct ddi_dma_attr dca_dmaattr = {
	DMA_ATTR_V0,		/* dma_attr_version */
	0x0,			/* dma_attr_addr_lo */
	0xffffffffUL,		/* dma_attr_addr_hi */
	0x00ffffffUL,		/* dma_attr_count_max */
	0x40,			/* dma_attr_align */
	0x40,			/* dma_attr_burstsizes */
	0x1,			/* dma_attr_minxfer */
	0x00ffffffUL,		/* dma_attr_maxxfer */
	0xffffffffUL,		/* dma_attr_seg */
#if defined(i386) || defined(__i386) || defined(__amd64)
	512,			/* dma_attr_sgllen */
#else
	1,			/* dma_attr_sgllen */
#endif
	1,			/* dma_attr_granular */
	DDI_DMA_FLAGERR		/* dma_attr_flags */
};

static void	*dca_state = NULL;
int	dca_mindma = 2500;

/*
 * FMA eclass string definitions. Note that these string arrays must be
 * consistent with the dca_fma_eclass_t enum.
 */
static char *dca_fma_eclass_sca1000[] = {
	"sca1000.hw.device",
	"sca1000.hw.timeout",
	"sca1000.none"
};

static char *dca_fma_eclass_sca500[] = {
	"sca500.hw.device",
	"sca500.hw.timeout",
	"sca500.none"
};

/*
 * DDI entry points.
 */
int
_init(void)
{
	int rv;

	DBG(NULL, DMOD, "dca: in _init");

	if ((rv = ddi_soft_state_init(&dca_state, sizeof (dca_t), 1)) != 0) {
		/* this should *never* happen! */
		return (rv);
	}

	if ((rv = mod_install(&modlinkage)) != 0) {
		/* cleanup here */
		ddi_soft_state_fini(&dca_state);
		return (rv);
	}

	return (0);
}

int
_fini(void)
{
	int rv;

	DBG(NULL, DMOD, "dca: in _fini");

	if ((rv = mod_remove(&modlinkage)) == 0) {
		/* cleanup here */
		ddi_soft_state_fini(&dca_state);
	}
	return (rv);
}

int
_info(struct modinfo *modinfop)
{
	DBG(NULL, DMOD, "dca: in _info");

	return (mod_info(&modlinkage, modinfop));
}

int
dca_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ddi_acc_handle_t	pci;
	int			instance;
	ddi_iblock_cookie_t	ibc;
	int			intr_added = 0;
	dca_t			*dca;
	ushort_t		venid;
	ushort_t		devid;
	ushort_t		revid;
	ushort_t		subsysid;
	ushort_t		subvenid;
	int			i;
	int			ret;
	char			ID[64];
	static char		*unknowndev = "Unknown device";

#if DEBUG
	/* these are only used for debugging */
	ushort_t		pcicomm;
	ushort_t		pcistat;
	uchar_t			cachelinesz;
	uchar_t			mingnt;
	uchar_t			maxlat;
	uchar_t			lattmr;
#endif

	instance = ddi_get_instance(dip);

	DBG(NULL, DMOD, "dca: in dca_attach() for %d", instance);

	switch (cmd) {
	case DDI_RESUME:
		if ((dca = (dca_t *)ddi_get_driver_private(dip)) == NULL) {
			dca_diperror(dip, "no soft state in detach");
			return (DDI_FAILURE);
		}
		/* assumption: we won't be DDI_DETACHed until we return */
		return (dca_resume(dca));
	case DDI_ATTACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (ddi_slaveonly(dip) == DDI_SUCCESS) {
		dca_diperror(dip, "slot does not support PCI bus-master");
		return (DDI_FAILURE);
	}

	if (ddi_intr_hilevel(dip, 0) != 0) {
		dca_diperror(dip, "hilevel interrupts not supported");
		return (DDI_FAILURE);
	}

	if (pci_config_setup(dip, &pci) != DDI_SUCCESS) {
		dca_diperror(dip, "unable to setup PCI config handle");
		return (DDI_FAILURE);
	}

	/* common PCI attributes */
	venid = pci_config_get16(pci, PCI_VENID);
	devid = pci_config_get16(pci, PCI_DEVID);
	revid = pci_config_get8(pci, PCI_REVID);
	subvenid = pci_config_get16(pci, PCI_SUBVENID);
	subsysid = pci_config_get16(pci, PCI_SUBSYSID);

	/*
	 * Broadcom-specific timings.
	 * We disable these timers/counters since they can cause
	 * incorrect false failures when the bus is just a little
	 * bit slow, or busy.
	 */
	pci_config_put8(pci, PCI_TRDYTO, 0);
	pci_config_put8(pci, PCI_RETRIES, 0);

	/* initialize PCI access settings */
	pci_config_put16(pci, PCI_COMM, PCICOMM_SEE |
	    PCICOMM_PEE | PCICOMM_BME | PCICOMM_MAE);

	/* set up our PCI latency timer */
	pci_config_put8(pci, PCI_LATTMR, 0x40);

#if DEBUG
	/* read registers (for debugging) */
	pcicomm = pci_config_get16(pci, PCI_COMM);
	pcistat = pci_config_get16(pci, PCI_STATUS);
	cachelinesz = pci_config_get8(pci, PCI_CACHELINESZ);
	mingnt = pci_config_get8(pci, PCI_MINGNT);
	maxlat = pci_config_get8(pci, PCI_MAXLAT);
	lattmr = pci_config_get8(pci, PCI_LATTMR);
#endif

	pci_config_teardown(&pci);

	if (ddi_get_iblock_cookie(dip, 0, &ibc) != DDI_SUCCESS) {
		dca_diperror(dip, "unable to get iblock cookie");
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(dca_state, instance) != DDI_SUCCESS) {
		dca_diperror(dip, "unable to allocate soft state");
		return (DDI_FAILURE);
	}

	dca = ddi_get_soft_state(dca_state, instance);
	ASSERT(dca != NULL);
	dca->dca_dip = dip;
	WORKLIST(dca, MCR1)->dwl_prov = NULL;
	WORKLIST(dca, MCR2)->dwl_prov = NULL;
	/* figure pagesize */
	dca->dca_pagesize = ddi_ptob(dip, 1);

	/*
	 * Search for the device in our supported devices table.  This
	 * is here for two reasons.  First, we want to ensure that
	 * only Sun-qualified (and presumably Sun-labeled) devices can
	 * be used with this driver.  Second, some devices have
	 * specific differences.  E.g. the 5821 has support for a
	 * special mode of RC4, deeper queues, power management, and
	 * other changes.  Also, the export versions of some of these
	 * chips don't support RC4 or 3DES, so we catch that here.
	 *
	 * Note that we only look at the upper nibble of the device
	 * id, which is used to distinguish export vs. domestic
	 * versions of the chip.  (The lower nibble is used for
	 * stepping information.)
	 */
	for (i = 0; i < (sizeof (dca_devices) / sizeof (dca_device_t)); i++) {
		/*
		 * Try to match the subsystem information first.
		 */
		if (subvenid && (subvenid == dca_devices[i].dd_vendor_id) &&
		    subsysid && (subsysid == dca_devices[i].dd_device_id)) {
			dca->dca_model = dca_devices[i].dd_model;
			dca->dca_devid = dca_devices[i].dd_device_id;
			break;
		}
		/*
		 * Failing that, try the generic vendor and device id.
		 * Even if we find a match, we keep searching anyway,
		 * since we would prefer to find a match based on the
		 * subsystem ids.
		 */
		if ((venid == dca_devices[i].dd_vendor_id) &&
		    (devid == dca_devices[i].dd_device_id)) {
			dca->dca_model = dca_devices[i].dd_model;
			dca->dca_devid = dca_devices[i].dd_device_id;
		}
	}
	/* try and handle an unrecognized device */
	if (dca->dca_model == NULL) {
		dca->dca_model = unknowndev;
		dca_error(dca, "device not recognized, not supported");
		DBG(dca, DPCI, "i=%d venid=%x devid=%x rev=%d",
		    i, venid, devid, revid);
	}

	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip, "description",
	    dca->dca_model) != DDI_SUCCESS) {
		dca_error(dca, "unable to create description property");
		return (DDI_FAILURE);
	}

	DBG(dca, DPCI, "PCI command=0x%x status=%x cachelinesz=%x",
	    pcicomm, pcistat, cachelinesz);
	DBG(dca, DPCI, "mingnt=0x%x maxlat=0x%x lattmr=0x%x",
	    mingnt, maxlat, lattmr);

	/*
	 * initialize locks, etc.
	 */
	(void) mutex_init(&dca->dca_intrlock, NULL, MUTEX_DRIVER, ibc);

	/* use RNGSHA1 by default */
	if (ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "rngdirect", 0) == 0) {
		dca->dca_flags |= DCA_RNGSHA1;
	}

	/* initialize FMA */
	dca_fma_init(dca);

	/* initialize some key data structures */
	if (dca_init(dca) != DDI_SUCCESS) {
		goto failed;
	}

	/* initialize kstats */
	dca_ksinit(dca);

	/* setup access to registers */
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&dca->dca_regs,
	    0, 0, &dca_regsattr, &dca->dca_regs_handle) != DDI_SUCCESS) {
		dca_error(dca, "unable to map registers");
		goto failed;
	}

	DBG(dca, DCHATTY, "MCR1 = %x", GETCSR(dca, CSR_MCR1));
	DBG(dca, DCHATTY, "CONTROL = %x", GETCSR(dca, CSR_DMACTL));
	DBG(dca, DCHATTY, "STATUS = %x", GETCSR(dca, CSR_DMASTAT));
	DBG(dca, DCHATTY, "DMAEA = %x", GETCSR(dca, CSR_DMAEA));
	DBG(dca, DCHATTY, "MCR2 = %x", GETCSR(dca, CSR_MCR2));

	/* reset the chip */
	if (dca_reset(dca, 0) < 0) {
		goto failed;
	}

	/* initialize the chip */
	PUTCSR(dca, CSR_DMACTL, DMACTL_BE32 | DMACTL_BE64);
	if (dca_check_acc_handle(dca, dca->dca_regs_handle,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
		goto failed;
	}

	/* add the interrupt */
	if (ddi_add_intr(dip, 0, &dca->dca_icookie, NULL, dca_intr,
	    (void *)dca) != DDI_SUCCESS) {
		DBG(dca, DWARN, "ddi_add_intr failed");
		goto failed;
	} else {
		intr_added = 1;
	}

	/* enable interrupts on the device */
	/*
	 * XXX: Note, 5820A1 errata indicates that this may clobber
	 * bits 24 and 23, which affect the speed of the RNG.  Since
	 * we always want to run in full-speed mode, this should be
	 * harmless.
	 */
	if (dca->dca_devid == 0x5825) {
		/* for 5825 - increase the DMA read size */
		SETBIT(dca, CSR_DMACTL,
		    DMACTL_MCR1IE | DMACTL_MCR2IE | DMACTL_EIE | DMACTL_RD256);
	} else {
		SETBIT(dca, CSR_DMACTL,
		    DMACTL_MCR1IE | DMACTL_MCR2IE | DMACTL_EIE);
	}
	if (dca_check_acc_handle(dca, dca->dca_regs_handle,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
		goto failed;
	}

	/* register MCR1 with the crypto framework */
	/* Be careful not to exceed 32 chars */
	(void) sprintf(ID, "%s/%d %s",
	    ddi_driver_name(dip), ddi_get_instance(dip), IDENT_SYM);
	dca_prov_info1.pi_provider_description = ID;
	dca_prov_info1.pi_provider_dev.pd_hw = dip;
	dca_prov_info1.pi_provider_handle = dca;
	if ((ret = crypto_register_provider(&dca_prov_info1,
	    &WORKLIST(dca, MCR1)->dwl_prov)) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
		    "crypto_register_provider() failed (%d) for MCR1", ret);
		goto failed;
	}

	/* register MCR2 with the crypto framework */
	/* Be careful not to exceed 32 chars */
	(void) sprintf(ID, "%s/%d %s",
	    ddi_driver_name(dip), ddi_get_instance(dip), IDENT_ASYM);
	dca_prov_info2.pi_provider_description = ID;
	dca_prov_info2.pi_provider_dev.pd_hw = dip;
	dca_prov_info2.pi_provider_handle = dca;
	if ((ret = crypto_register_provider(&dca_prov_info2,
	    &WORKLIST(dca, MCR2)->dwl_prov)) != CRYPTO_SUCCESS) {
		cmn_err(CE_WARN,
		    "crypto_register_provider() failed (%d) for MCR2", ret);
		goto failed;
	}

	crypto_prov_notify(WORKLIST(dca, MCR1)->dwl_prov,
	    CRYPTO_PROVIDER_READY);
	crypto_prov_notify(WORKLIST(dca, MCR2)->dwl_prov,
	    CRYPTO_PROVIDER_READY);

	/* Initialize the local random number pool for this instance */
	if ((ret = dca_random_init(dca)) != CRYPTO_SUCCESS) {
		goto failed;
	}

	mutex_enter(&dca->dca_intrlock);
	dca->dca_jobtid = timeout(dca_jobtimeout, (void *)dca,
	    drv_usectohz(SECOND));
	mutex_exit(&dca->dca_intrlock);

	ddi_set_driver_private(dip, (caddr_t)dca);

	ddi_report_dev(dip);

	if (ddi_get_devstate(dca->dca_dip) != DDI_DEVSTATE_UP) {
		ddi_fm_service_impact(dca->dca_dip, DDI_SERVICE_RESTORED);
	}

	return (DDI_SUCCESS);

failed:
	/* unregister from the crypto framework */
	if (WORKLIST(dca, MCR1)->dwl_prov != NULL) {
		(void) crypto_unregister_provider(
		    WORKLIST(dca, MCR1)->dwl_prov);
	}
	if (WORKLIST(dca, MCR2)->dwl_prov != NULL) {
		(void) crypto_unregister_provider(
		    WORKLIST(dca, MCR2)->dwl_prov);
	}
	if (intr_added) {
		CLRBIT(dca, CSR_DMACTL,
		    DMACTL_MCR1IE | DMACTL_MCR2IE | DMACTL_EIE);
		/* unregister intr handler */
		ddi_remove_intr(dip, 0, dca->dca_icookie);
	}
	if (dca->dca_regs_handle) {
		ddi_regs_map_free(&dca->dca_regs_handle);
	}
	if (dca->dca_intrstats) {
		kstat_delete(dca->dca_intrstats);
	}
	if (dca->dca_ksp) {
		kstat_delete(dca->dca_ksp);
	}
	dca_uninit(dca);

	/* finalize FMA */
	dca_fma_fini(dca);

	mutex_destroy(&dca->dca_intrlock);
	ddi_soft_state_free(dca_state, instance);
	return (DDI_FAILURE);

}

int
dca_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int		instance;
	dca_t		*dca;
	timeout_id_t	tid;

	instance = ddi_get_instance(dip);

	DBG(NULL, DMOD, "dca: in dca_detach() for %d", instance);

	switch (cmd) {
	case DDI_SUSPEND:
		if ((dca = (dca_t *)ddi_get_driver_private(dip)) == NULL) {
			dca_diperror(dip, "no soft state in detach");
			return (DDI_FAILURE);
		}
		/* assumption: we won't be DDI_DETACHed until we return */
		return (dca_suspend(dca));

	case DDI_DETACH:
		break;
	default:
		return (DDI_FAILURE);
	}

	if ((dca = (dca_t *)ddi_get_driver_private(dip)) == NULL) {
		dca_diperror(dip, "no soft state in detach");
		return (DDI_FAILURE);
	}

	/*
	 * Unregister from kCF.
	 * This needs to be done at the beginning of detach.
	 */
	if (WORKLIST(dca, MCR1)->dwl_prov != NULL) {
		if (crypto_unregister_provider(
		    WORKLIST(dca, MCR1)->dwl_prov) != CRYPTO_SUCCESS) {
			dca_error(dca, "unable to unregister MCR1 from kcf");
			return (DDI_FAILURE);
		}
	}

	if (WORKLIST(dca, MCR2)->dwl_prov != NULL) {
		if (crypto_unregister_provider(
		    WORKLIST(dca, MCR2)->dwl_prov) != CRYPTO_SUCCESS) {
			dca_error(dca, "unable to unregister MCR2 from kcf");
			return (DDI_FAILURE);
		}
	}

	/*
	 * Cleanup the private context list. Once the
	 * crypto_unregister_provider returns, it is safe to do so.
	 */
	dca_free_context_list(dca);

	/* Cleanup the local random number pool */
	dca_random_fini(dca);

	/* send any jobs in the waitq back to kCF */
	dca_rejectjobs(dca);

	/* untimeout the timeouts */
	mutex_enter(&dca->dca_intrlock);
	tid = dca->dca_jobtid;
	dca->dca_jobtid = 0;
	mutex_exit(&dca->dca_intrlock);
	if (tid) {
		(void) untimeout(tid);
	}

	/* disable device interrupts */
	CLRBIT(dca, CSR_DMACTL, DMACTL_MCR1IE | DMACTL_MCR2IE | DMACTL_EIE);

	/* unregister interrupt handlers */
	ddi_remove_intr(dip, 0, dca->dca_icookie);

	/* release our regs handle */
	ddi_regs_map_free(&dca->dca_regs_handle);

	/* toss out kstats */
	if (dca->dca_intrstats) {
		kstat_delete(dca->dca_intrstats);
	}
	if (dca->dca_ksp) {
		kstat_delete(dca->dca_ksp);
	}

	mutex_destroy(&dca->dca_intrlock);
	dca_uninit(dca);

	/* finalize FMA */
	dca_fma_fini(dca);

	ddi_soft_state_free(dca_state, instance);

	return (DDI_SUCCESS);
}

int
dca_resume(dca_t *dca)
{
	ddi_acc_handle_t	pci;

	if (pci_config_setup(dca->dca_dip, &pci) != DDI_SUCCESS) {
		dca_error(dca, "unable to setup PCI config handle");
		return (DDI_FAILURE);
	}

	/*
	 * Reprogram registers in PCI configuration space.
	 */

	/* Broadcom-specific timers -- we disable them. */
	pci_config_put8(pci, PCI_TRDYTO, 0);
	pci_config_put8(pci, PCI_RETRIES, 0);

	/* initialize PCI access settings */
	pci_config_put16(pci, PCI_COMM, PCICOMM_SEE |
	    PCICOMM_PEE | PCICOMM_BME | PCICOMM_MAE);

	/* set up our PCI latency timer */
	pci_config_put8(pci, PCI_LATTMR, 0x40);

	pci_config_teardown(&pci);

	if (dca_reset(dca, 0) < 0) {
		dca_error(dca, "unable to reset device during resume");
		return (DDI_FAILURE);
	}

	/*
	 * Now restore the card-specific CSRs.
	 */

	/* restore endianness settings */
	PUTCSR(dca, CSR_DMACTL, DMACTL_BE32 | DMACTL_BE64);
	if (dca_check_acc_handle(dca, dca->dca_regs_handle,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* restore interrupt enables */
	if (dca->dca_devid == 0x5825) {
		/* for 5825 set 256 byte read size to improve performance */
		SETBIT(dca, CSR_DMACTL,
		    DMACTL_MCR1IE | DMACTL_MCR2IE | DMACTL_EIE | DMACTL_RD256);
	} else {
		SETBIT(dca, CSR_DMACTL,
		    DMACTL_MCR1IE | DMACTL_MCR2IE | DMACTL_EIE);
	}
	if (dca_check_acc_handle(dca, dca->dca_regs_handle,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* resume scheduling jobs on the device */
	dca_undrain(dca);

	return (DDI_SUCCESS);
}

int
dca_suspend(dca_t *dca)
{
	if ((dca_drain(dca)) != 0) {
		return (DDI_FAILURE);
	}
	if (dca_reset(dca, 0) < 0) {
		dca_error(dca, "unable to reset device during suspend");
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Hardware access stuff.
 */
int
dca_reset(dca_t *dca, int failreset)
{
	int i;

	if (dca->dca_regs_handle == NULL) {
		return (-1);
	}

	PUTCSR(dca, CSR_DMACTL, DMACTL_RESET);
	if (!failreset) {
		if (dca_check_acc_handle(dca, dca->dca_regs_handle,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS)
			return (-1);
	}

	/* now wait for a reset */
	for (i = 1; i < 100; i++) {
		uint32_t	dmactl;
		drv_usecwait(100);
		dmactl = GETCSR(dca, CSR_DMACTL);
		if (!failreset) {
			if (dca_check_acc_handle(dca, dca->dca_regs_handle,
			    DCA_FM_ECLASS_NONE) != DDI_SUCCESS)
				return (-1);
		}
		if ((dmactl & DMACTL_RESET) == 0) {
			DBG(dca, DCHATTY, "reset in %d usec", i * 100);
			return (0);
		}
	}
	if (!failreset) {
		dca_failure(dca, DDI_DEVICE_FAULT,
		    DCA_FM_ECLASS_NONE, dca_ena(0), CRYPTO_DEVICE_ERROR,
		    "timeout waiting for reset after %d usec", i * 100);
	}
	return (-1);
}

int
dca_initworklist(dca_t *dca, dca_worklist_t *wlp)
{
	int	i;
	int	reqprealloc = wlp->dwl_hiwater + (MAXWORK * MAXREQSPERMCR);

	/*
	 * Set up work queue.
	 */
	mutex_init(&wlp->dwl_lock, NULL, MUTEX_DRIVER, dca->dca_icookie);
	mutex_init(&wlp->dwl_freereqslock, NULL, MUTEX_DRIVER,
	    dca->dca_icookie);
	mutex_init(&wlp->dwl_freelock, NULL, MUTEX_DRIVER, dca->dca_icookie);
	cv_init(&wlp->dwl_cv, NULL, CV_DRIVER, NULL);

	mutex_enter(&wlp->dwl_lock);

	dca_initq(&wlp->dwl_freereqs);
	dca_initq(&wlp->dwl_waitq);
	dca_initq(&wlp->dwl_freework);
	dca_initq(&wlp->dwl_runq);

	for (i = 0; i < MAXWORK; i++) {
		dca_work_t		*workp;

		if ((workp = dca_newwork(dca)) == NULL) {
			dca_error(dca, "unable to allocate work");
			mutex_exit(&wlp->dwl_lock);
			return (DDI_FAILURE);
		}
		workp->dw_wlp = wlp;
		dca_freework(workp);
	}
	mutex_exit(&wlp->dwl_lock);

	for (i = 0; i < reqprealloc; i++) {
		dca_request_t *reqp;

		if ((reqp = dca_newreq(dca)) == NULL) {
			dca_error(dca, "unable to allocate request");
			return (DDI_FAILURE);
		}
		reqp->dr_dca = dca;
		reqp->dr_wlp = wlp;
		dca_freereq(reqp);
	}
	return (DDI_SUCCESS);
}

int
dca_init(dca_t *dca)
{
	dca_worklist_t		*wlp;

	/* Initialize the private context list and the corresponding lock. */
	mutex_init(&dca->dca_ctx_list_lock, NULL, MUTEX_DRIVER, NULL);
	dca_initq(&dca->dca_ctx_list);

	/*
	 * MCR1 algorithms.
	 */
	wlp = WORKLIST(dca, MCR1);
	(void) sprintf(wlp->dwl_name, "dca%d:mcr1",
	    ddi_get_instance(dca->dca_dip));
	wlp->dwl_lowater = ddi_getprop(DDI_DEV_T_ANY,
	    dca->dca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "mcr1_lowater", MCR1LOWATER);
	wlp->dwl_hiwater = ddi_getprop(DDI_DEV_T_ANY,
	    dca->dca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "mcr1_hiwater", MCR1HIWATER);
	wlp->dwl_reqspermcr = min(ddi_getprop(DDI_DEV_T_ANY,
	    dca->dca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "mcr1_maxreqs", MCR1MAXREQS), MAXREQSPERMCR);
	wlp->dwl_dca = dca;
	wlp->dwl_mcr = MCR1;
	if (dca_initworklist(dca, wlp) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * MCR2 algorithms.
	 */
	wlp = WORKLIST(dca, MCR2);
	(void) sprintf(wlp->dwl_name, "dca%d:mcr2",
	    ddi_get_instance(dca->dca_dip));
	wlp->dwl_lowater = ddi_getprop(DDI_DEV_T_ANY,
	    dca->dca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "mcr2_lowater", MCR2LOWATER);
	wlp->dwl_hiwater = ddi_getprop(DDI_DEV_T_ANY,
	    dca->dca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "mcr2_hiwater", MCR2HIWATER);
	wlp->dwl_reqspermcr = min(ddi_getprop(DDI_DEV_T_ANY,
	    dca->dca_dip, DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "mcr2_maxreqs", MCR2MAXREQS), MAXREQSPERMCR);
	wlp->dwl_dca = dca;
	wlp->dwl_mcr = MCR2;
	if (dca_initworklist(dca, wlp) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Uninitialize worklists.  This routine should only be called when no
 * active jobs (hence DMA mappings) exist.  One way to ensure this is
 * to unregister from kCF before calling this routine.  (This is done
 * e.g. in detach(9e).)
 */
void
dca_uninit(dca_t *dca)
{
	int	mcr;

	mutex_destroy(&dca->dca_ctx_list_lock);

	for (mcr = MCR1; mcr <= MCR2; mcr++) {
		dca_worklist_t	*wlp = WORKLIST(dca, mcr);
		dca_work_t	*workp;
		dca_request_t	*reqp;

		if (dca->dca_regs_handle == NULL) {
			continue;
		}

		mutex_enter(&wlp->dwl_lock);
		while ((workp = dca_getwork(dca, mcr)) != NULL) {
			dca_destroywork(workp);
		}
		mutex_exit(&wlp->dwl_lock);
		while ((reqp = dca_getreq(dca, mcr, 0)) != NULL) {
			dca_destroyreq(reqp);
		}

		mutex_destroy(&wlp->dwl_lock);
		mutex_destroy(&wlp->dwl_freereqslock);
		mutex_destroy(&wlp->dwl_freelock);
		cv_destroy(&wlp->dwl_cv);
		wlp->dwl_prov = NULL;
	}
}

static void
dca_enlist2(dca_listnode_t *q, dca_listnode_t *node, kmutex_t *lock)
{
	if (!q || !node)
		return;

	mutex_enter(lock);
	node->dl_next2 = q;
	node->dl_prev2 = q->dl_prev2;
	node->dl_next2->dl_prev2 = node;
	node->dl_prev2->dl_next2 = node;
	mutex_exit(lock);
}

static void
dca_rmlist2(dca_listnode_t *node, kmutex_t *lock)
{
	if (!node)
		return;

	mutex_enter(lock);
	node->dl_next2->dl_prev2 = node->dl_prev2;
	node->dl_prev2->dl_next2 = node->dl_next2;
	node->dl_next2 = NULL;
	node->dl_prev2 = NULL;
	mutex_exit(lock);
}

static dca_listnode_t *
dca_delist2(dca_listnode_t *q, kmutex_t *lock)
{
	dca_listnode_t *node;

	mutex_enter(lock);
	if ((node = q->dl_next2) == q) {
		mutex_exit(lock);
		return (NULL);
	}

	node->dl_next2->dl_prev2 = node->dl_prev2;
	node->dl_prev2->dl_next2 = node->dl_next2;
	node->dl_next2 = NULL;
	node->dl_prev2 = NULL;
	mutex_exit(lock);

	return (node);
}

void
dca_initq(dca_listnode_t *q)
{
	q->dl_next = q;
	q->dl_prev = q;
	q->dl_next2 = q;
	q->dl_prev2 = q;
}

void
dca_enqueue(dca_listnode_t *q, dca_listnode_t *node)
{
	/*
	 * Enqueue submits at the "tail" of the list, i.e. just
	 * behind the sentinel.
	 */
	node->dl_next = q;
	node->dl_prev = q->dl_prev;
	node->dl_next->dl_prev = node;
	node->dl_prev->dl_next = node;
}

void
dca_rmqueue(dca_listnode_t *node)
{
	node->dl_next->dl_prev = node->dl_prev;
	node->dl_prev->dl_next = node->dl_next;
	node->dl_next = NULL;
	node->dl_prev = NULL;
}

dca_listnode_t *
dca_dequeue(dca_listnode_t *q)
{
	dca_listnode_t *node;
	/*
	 * Dequeue takes from the "head" of the list, i.e. just after
	 * the sentinel.
	 */
	if ((node = q->dl_next) == q) {
		/* queue is empty */
		return (NULL);
	}
	dca_rmqueue(node);
	return (node);
}

/* this is the opposite of dequeue, it takes things off in LIFO order */
dca_listnode_t *
dca_unqueue(dca_listnode_t *q)
{
	dca_listnode_t *node;
	/*
	 * unqueue takes from the "tail" of the list, i.e. just before
	 * the sentinel.
	 */
	if ((node = q->dl_prev) == q) {
		/* queue is empty */
		return (NULL);
	}
	dca_rmqueue(node);
	return (node);
}

dca_listnode_t *
dca_peekqueue(dca_listnode_t *q)
{
	dca_listnode_t *node;

	if ((node = q->dl_next) == q) {
		return (NULL);
	} else {
		return (node);
	}
}

/*
 * Interrupt service routine.
 */
uint_t
dca_intr(char *arg)
{
	dca_t		*dca = (dca_t *)arg;
	uint32_t	status;

	mutex_enter(&dca->dca_intrlock);
	status = GETCSR(dca, CSR_DMASTAT);
	PUTCSR(dca, CSR_DMASTAT, status & DMASTAT_INTERRUPTS);
	if (dca_check_acc_handle(dca, dca->dca_regs_handle,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
		mutex_exit(&dca->dca_intrlock);
		return ((uint_t)DDI_FAILURE);
	}

	DBG(dca, DINTR, "interrupted, status = 0x%x!", status);

	if ((status & DMASTAT_INTERRUPTS) == 0) {
		/* increment spurious interrupt kstat */
		if (dca->dca_intrstats) {
			KIOIP(dca)->intrs[KSTAT_INTR_SPURIOUS]++;
		}
		mutex_exit(&dca->dca_intrlock);
		return (DDI_INTR_UNCLAIMED);
	}

	if (dca->dca_intrstats) {
		KIOIP(dca)->intrs[KSTAT_INTR_HARD]++;
	}
	if (status & DMASTAT_MCR1INT) {
		DBG(dca, DINTR, "MCR1 interrupted");
		mutex_enter(&(WORKLIST(dca, MCR1)->dwl_lock));
		dca_schedule(dca, MCR1);
		dca_reclaim(dca, MCR1);
		mutex_exit(&(WORKLIST(dca, MCR1)->dwl_lock));
	}

	if (status & DMASTAT_MCR2INT) {
		DBG(dca, DINTR, "MCR2 interrupted");
		mutex_enter(&(WORKLIST(dca, MCR2)->dwl_lock));
		dca_schedule(dca, MCR2);
		dca_reclaim(dca, MCR2);
		mutex_exit(&(WORKLIST(dca, MCR2)->dwl_lock));
	}

	if (status & DMASTAT_ERRINT) {
		uint32_t	erraddr;
		erraddr = GETCSR(dca, CSR_DMAEA);
		mutex_exit(&dca->dca_intrlock);

		/*
		 * bit 1 of the error address indicates failure during
		 * read if set, during write otherwise.
		 */
		dca_failure(dca, DDI_DEVICE_FAULT,
		    DCA_FM_ECLASS_HW_DEVICE, dca_ena(0), CRYPTO_DEVICE_ERROR,
		    "DMA master access error %s address 0x%x",
		    erraddr & 0x1 ? "reading" : "writing", erraddr & ~1);
		return (DDI_INTR_CLAIMED);
	}

	mutex_exit(&dca->dca_intrlock);

	return (DDI_INTR_CLAIMED);
}

/*
 * Reverse a string of bytes from s1 into s2.  The reversal happens
 * from the tail of s1.  If len1 < len2, then null bytes will be
 * padded to the end of s2.  If len2 < len1, then (presumably null)
 * bytes will be dropped from the start of s1.
 *
 * The rationale here is that when s1 (source) is shorter, then we
 * are reversing from big-endian ordering, into device ordering, and
 * want to add some extra nulls to the tail (MSB) side of the device.
 *
 * Similarly, when s2 (dest) is shorter, then we are truncating what
 * are presumably null MSB bits from the device.
 *
 * There is an expectation when reversing from the device back into
 * big-endian, that the number of bytes to reverse and the target size
 * will match, and no truncation or padding occurs.
 */
void
dca_reverse(void *s1, void *s2, int len1, int len2)
{
	caddr_t	src, dst;

	if (len1 == 0) {
		if (len2) {
			bzero(s2, len2);
		}
		return;
	}
	src = (caddr_t)s1 + len1 - 1;
	dst = s2;
	while ((src >= (caddr_t)s1) && (len2)) {
		*dst++ = *src--;
		len2--;
	}
	while (len2 > 0) {
		*dst++ = 0;
		len2--;
	}
}

uint16_t
dca_padfull(int num)
{
	if (num <= 512) {
		return (BITS2BYTES(512));
	}
	if (num <= 768) {
		return (BITS2BYTES(768));
	}
	if (num <= 1024) {
		return (BITS2BYTES(1024));
	}
	if (num <= 1536) {
		return (BITS2BYTES(1536));
	}
	if (num <= 2048) {
		return (BITS2BYTES(2048));
	}
	return (0);
}

uint16_t
dca_padhalf(int num)
{
	if (num <= 256) {
		return (BITS2BYTES(256));
	}
	if (num <= 384) {
		return (BITS2BYTES(384));
	}
	if (num <= 512) {
		return (BITS2BYTES(512));
	}
	if (num <= 768) {
		return (BITS2BYTES(768));
	}
	if (num <= 1024) {
		return (BITS2BYTES(1024));
	}
	return (0);
}

dca_work_t *
dca_newwork(dca_t *dca)
{
	dca_work_t		*workp;
	size_t			size;
	ddi_dma_cookie_t	c;
	unsigned		nc;
	int			rv;

	workp = kmem_zalloc(sizeof (dca_work_t), KM_SLEEP);

	rv = ddi_dma_alloc_handle(dca->dca_dip, &dca_dmaattr,
	    DDI_DMA_SLEEP, NULL, &workp->dw_mcr_dmah);
	if (rv != 0) {
		dca_error(dca, "unable to alloc MCR DMA handle");
		dca_destroywork(workp);
		return (NULL);
	}

	rv = ddi_dma_mem_alloc(workp->dw_mcr_dmah,
	    ROUNDUP(MCR_SIZE, dca->dca_pagesize),
	    &dca_devattr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &workp->dw_mcr_kaddr, &size, &workp->dw_mcr_acch);
	if (rv != 0) {
		dca_error(dca, "unable to alloc MCR DMA memory");
		dca_destroywork(workp);
		return (NULL);
	}

	rv = ddi_dma_addr_bind_handle(workp->dw_mcr_dmah, NULL,
	    workp->dw_mcr_kaddr, size, DDI_DMA_CONSISTENT | DDI_DMA_RDWR,
	    DDI_DMA_SLEEP, NULL, &c, &nc);
	if (rv != DDI_DMA_MAPPED) {
		dca_error(dca, "unable to map MCR DMA memory");
		dca_destroywork(workp);
		return (NULL);
	}

	workp->dw_mcr_paddr = c.dmac_address;
	return (workp);
}

void
dca_destroywork(dca_work_t *workp)
{
	if (workp->dw_mcr_paddr) {
		(void) ddi_dma_unbind_handle(workp->dw_mcr_dmah);
	}
	if (workp->dw_mcr_acch) {
		ddi_dma_mem_free(&workp->dw_mcr_acch);
	}
	if (workp->dw_mcr_dmah) {
		ddi_dma_free_handle(&workp->dw_mcr_dmah);
	}
	kmem_free(workp, sizeof (dca_work_t));
}

dca_request_t *
dca_newreq(dca_t *dca)
{
	dca_request_t		*reqp;
	size_t			size;
	ddi_dma_cookie_t	c;
	unsigned		nc;
	int			rv;
	int			n_chain = 0;

	size = (DESC_SIZE * MAXFRAGS) + CTX_MAXLENGTH;

	reqp = kmem_zalloc(sizeof (dca_request_t), KM_SLEEP);

	reqp->dr_dca = dca;

	/*
	 * Setup the DMA region for the context and descriptors.
	 */
	rv = ddi_dma_alloc_handle(dca->dca_dip, &dca_dmaattr, DDI_DMA_SLEEP,
	    NULL, &reqp->dr_ctx_dmah);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "failure allocating request DMA handle");
		dca_destroyreq(reqp);
		return (NULL);
	}

	/* for driver hardening, allocate in whole pages */
	rv = ddi_dma_mem_alloc(reqp->dr_ctx_dmah,
	    ROUNDUP(size, dca->dca_pagesize), &dca_devattr, DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &reqp->dr_ctx_kaddr, &size,
	    &reqp->dr_ctx_acch);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "unable to alloc request DMA memory");
		dca_destroyreq(reqp);
		return (NULL);
	}

	rv = ddi_dma_addr_bind_handle(reqp->dr_ctx_dmah, NULL,
	    reqp->dr_ctx_kaddr, size, DDI_DMA_CONSISTENT | DDI_DMA_WRITE,
	    DDI_DMA_SLEEP, 0, &c, &nc);
	if (rv != DDI_DMA_MAPPED) {
		dca_error(dca, "failed binding request DMA handle");
		dca_destroyreq(reqp);
		return (NULL);
	}
	reqp->dr_ctx_paddr = c.dmac_address;

	reqp->dr_dma_size = size;

	/*
	 * Set up the dma for our scratch/shared buffers.
	 */
	rv = ddi_dma_alloc_handle(dca->dca_dip, &dca_dmaattr,
	    DDI_DMA_SLEEP, NULL, &reqp->dr_ibuf_dmah);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "failure allocating ibuf DMA handle");
		dca_destroyreq(reqp);
		return (NULL);
	}
	rv = ddi_dma_alloc_handle(dca->dca_dip, &dca_dmaattr,
	    DDI_DMA_SLEEP, NULL, &reqp->dr_obuf_dmah);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "failure allocating obuf DMA handle");
		dca_destroyreq(reqp);
		return (NULL);
	}

	rv = ddi_dma_alloc_handle(dca->dca_dip, &dca_dmaattr,
	    DDI_DMA_SLEEP, NULL, &reqp->dr_chain_in_dmah);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "failure allocating chain_in DMA handle");
		dca_destroyreq(reqp);
		return (NULL);
	}

	rv = ddi_dma_alloc_handle(dca->dca_dip, &dca_dmaattr,
	    DDI_DMA_SLEEP, NULL, &reqp->dr_chain_out_dmah);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "failure allocating chain_out DMA handle");
		dca_destroyreq(reqp);
		return (NULL);
	}

	/*
	 * for driver hardening, allocate in whole pages.
	 */
	size = ROUNDUP(MAXPACKET, dca->dca_pagesize);
#if defined(i386) || defined(__i386)
	/*
	 * Use kmem_alloc instead of ddi_dma_mem_alloc here since the latter
	 * may fail on x86 platform if a physically contiguous memory chunk
	 * cannot be found. From initial testing, we did not see performance
	 * degradation as seen on Sparc.
	 */
	if ((reqp->dr_ibuf_kaddr = kmem_alloc(size, KM_SLEEP)) == NULL) {
		dca_error(dca, "unable to alloc request ibuf memory");
		dca_destroyreq(reqp);
		return (NULL);
	}
	if ((reqp->dr_obuf_kaddr = kmem_alloc(size, KM_SLEEP)) == NULL) {
		dca_error(dca, "unable to alloc request obuf memory");
		dca_destroyreq(reqp);
		return (NULL);
	}
#else
	/*
	 * We could kmem_alloc for Sparc too. However, it gives worse
	 * performance when transferring more than one page data. For example,
	 * using 4 threads and 12032 byte data and 3DES on 900MHZ Sparc system,
	 * kmem_alloc uses 80% CPU and ddi_dma_mem_alloc uses 50% CPU for
	 * the same throughput.
	 */
	rv = ddi_dma_mem_alloc(reqp->dr_ibuf_dmah,
	    size, &dca_bufattr,
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &reqp->dr_ibuf_kaddr,
	    &size, &reqp->dr_ibuf_acch);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "unable to alloc request DMA memory");
		dca_destroyreq(reqp);
		return (NULL);
	}

	rv = ddi_dma_mem_alloc(reqp->dr_obuf_dmah,
	    size, &dca_bufattr,
	    DDI_DMA_STREAMING, DDI_DMA_SLEEP, NULL, &reqp->dr_obuf_kaddr,
	    &size, &reqp->dr_obuf_acch);
	if (rv != DDI_SUCCESS) {
		dca_error(dca, "unable to alloc request DMA memory");
		dca_destroyreq(reqp);
		return (NULL);
	}
#endif

	/* Skip the used portion in the context page */
	reqp->dr_offset = CTX_MAXLENGTH;
	if ((rv = dca_bindchains_one(reqp, size, reqp->dr_offset,
	    reqp->dr_ibuf_kaddr, reqp->dr_ibuf_dmah,
	    DDI_DMA_WRITE | DDI_DMA_STREAMING,
	    &reqp->dr_ibuf_head, &n_chain)) != DDI_SUCCESS) {
		(void) dca_destroyreq(reqp);
		return (NULL);
	}
	reqp->dr_ibuf_paddr = reqp->dr_ibuf_head.dc_buffer_paddr;
	/* Skip the space used by the input buffer */
	reqp->dr_offset += DESC_SIZE * n_chain;

	if ((rv = dca_bindchains_one(reqp, size, reqp->dr_offset,
	    reqp->dr_obuf_kaddr, reqp->dr_obuf_dmah,
	    DDI_DMA_READ | DDI_DMA_STREAMING,
	    &reqp->dr_obuf_head, &n_chain)) != DDI_SUCCESS) {
		(void) dca_destroyreq(reqp);
		return (NULL);
	}
	reqp->dr_obuf_paddr = reqp->dr_obuf_head.dc_buffer_paddr;
	/* Skip the space used by the output buffer */
	reqp->dr_offset += DESC_SIZE * n_chain;

	DBG(dca, DCHATTY, "CTX is 0x%p, phys 0x%x, len %d",
	    reqp->dr_ctx_kaddr, reqp->dr_ctx_paddr, CTX_MAXLENGTH);
	return (reqp);
}

void
dca_destroyreq(dca_request_t *reqp)
{
#if defined(i386) || defined(__i386)
	dca_t		*dca = reqp->dr_dca;
	size_t		size = ROUNDUP(MAXPACKET, dca->dca_pagesize);
#endif

	/*
	 * Clean up DMA for the context structure.
	 */
	if (reqp->dr_ctx_paddr) {
		(void) ddi_dma_unbind_handle(reqp->dr_ctx_dmah);
	}

	if (reqp->dr_ctx_acch) {
		ddi_dma_mem_free(&reqp->dr_ctx_acch);
	}

	if (reqp->dr_ctx_dmah) {
		ddi_dma_free_handle(&reqp->dr_ctx_dmah);
	}

	/*
	 * Clean up DMA for the scratch buffer.
	 */
#if defined(i386) || defined(__i386)
	if (reqp->dr_ibuf_dmah) {
		(void) ddi_dma_unbind_handle(reqp->dr_ibuf_dmah);
		ddi_dma_free_handle(&reqp->dr_ibuf_dmah);
	}
	if (reqp->dr_obuf_dmah) {
		(void) ddi_dma_unbind_handle(reqp->dr_obuf_dmah);
		ddi_dma_free_handle(&reqp->dr_obuf_dmah);
	}

	kmem_free(reqp->dr_ibuf_kaddr, size);
	kmem_free(reqp->dr_obuf_kaddr, size);
#else
	if (reqp->dr_ibuf_paddr) {
		(void) ddi_dma_unbind_handle(reqp->dr_ibuf_dmah);
	}
	if (reqp->dr_obuf_paddr) {
		(void) ddi_dma_unbind_handle(reqp->dr_obuf_dmah);
	}

	if (reqp->dr_ibuf_acch) {
		ddi_dma_mem_free(&reqp->dr_ibuf_acch);
	}
	if (reqp->dr_obuf_acch) {
		ddi_dma_mem_free(&reqp->dr_obuf_acch);
	}

	if (reqp->dr_ibuf_dmah) {
		ddi_dma_free_handle(&reqp->dr_ibuf_dmah);
	}
	if (reqp->dr_obuf_dmah) {
		ddi_dma_free_handle(&reqp->dr_obuf_dmah);
	}
#endif
	/*
	 * These two DMA handles should have been unbinded in
	 * dca_unbindchains() function
	 */
	if (reqp->dr_chain_in_dmah) {
		ddi_dma_free_handle(&reqp->dr_chain_in_dmah);
	}
	if (reqp->dr_chain_out_dmah) {
		ddi_dma_free_handle(&reqp->dr_chain_out_dmah);
	}

	kmem_free(reqp, sizeof (dca_request_t));
}

dca_work_t *
dca_getwork(dca_t *dca, int mcr)
{
	dca_worklist_t	*wlp = WORKLIST(dca, mcr);
	dca_work_t	*workp;

	mutex_enter(&wlp->dwl_freelock);
	workp = (dca_work_t *)dca_dequeue(&wlp->dwl_freework);
	mutex_exit(&wlp->dwl_freelock);
	if (workp) {
		int	nreqs;
		bzero(workp->dw_mcr_kaddr, 8);

		/* clear out old requests */
		for (nreqs = 0; nreqs < MAXREQSPERMCR; nreqs++) {
			workp->dw_reqs[nreqs] = NULL;
		}
	}
	return (workp);
}

void
dca_freework(dca_work_t *workp)
{
	mutex_enter(&workp->dw_wlp->dwl_freelock);
	dca_enqueue(&workp->dw_wlp->dwl_freework, (dca_listnode_t *)workp);
	mutex_exit(&workp->dw_wlp->dwl_freelock);
}

dca_request_t *
dca_getreq(dca_t *dca, int mcr, int tryhard)
{
	dca_worklist_t	*wlp = WORKLIST(dca, mcr);
	dca_request_t	*reqp;

	mutex_enter(&wlp->dwl_freereqslock);
	reqp = (dca_request_t *)dca_dequeue(&wlp->dwl_freereqs);
	mutex_exit(&wlp->dwl_freereqslock);
	if (reqp) {
		reqp->dr_flags = 0;
		reqp->dr_callback = NULL;
	} else if (tryhard) {
		/*
		 * failed to get a free one, try an allocation, the hard way.
		 * XXX: Kstat desired here.
		 */
		if ((reqp = dca_newreq(dca)) != NULL) {
			reqp->dr_wlp = wlp;
			reqp->dr_dca = dca;
			reqp->dr_flags = 0;
			reqp->dr_callback = NULL;
		}
	}
	return (reqp);
}

void
dca_freereq(dca_request_t *reqp)
{
	reqp->dr_kcf_req = NULL;
	if (!(reqp->dr_flags & DR_NOCACHE)) {
		mutex_enter(&reqp->dr_wlp->dwl_freereqslock);
		dca_enqueue(&reqp->dr_wlp->dwl_freereqs,
		    (dca_listnode_t *)reqp);
		mutex_exit(&reqp->dr_wlp->dwl_freereqslock);
	}
}

/*
 * Binds user buffers to DMA handles dynamically. On Sparc, a user buffer
 * is mapped to a single physical address. On x86, a user buffer is mapped
 * to multiple physical addresses. These physical addresses are chained
 * using the method specified in Broadcom BCM5820 specification.
 */
int
dca_bindchains(dca_request_t *reqp, size_t incnt, size_t outcnt)
{
	int			rv;
	caddr_t			kaddr;
	uint_t			flags;
	int			n_chain = 0;

	if (reqp->dr_flags & DR_INPLACE) {
		flags = DDI_DMA_RDWR | DDI_DMA_CONSISTENT;
	} else {
		flags = DDI_DMA_WRITE | DDI_DMA_STREAMING;
	}

	/* first the input */
	if (incnt) {
		if ((kaddr = dca_bufdaddr(reqp->dr_in)) == NULL) {
			DBG(NULL, DWARN, "unrecognised crypto data format");
			return (DDI_FAILURE);
		}
		if ((rv = dca_bindchains_one(reqp, incnt, reqp->dr_offset,
		    kaddr, reqp->dr_chain_in_dmah, flags,
		    &reqp->dr_chain_in_head, &n_chain)) != DDI_SUCCESS) {
			(void) dca_unbindchains(reqp);
			return (rv);
		}

		/*
		 * The offset and length are altered by the calling routine
		 * reqp->dr_in->cd_offset += incnt;
		 * reqp->dr_in->cd_length -= incnt;
		 */
		/* Save the first one in the chain for MCR */
		reqp->dr_in_paddr = reqp->dr_chain_in_head.dc_buffer_paddr;
		reqp->dr_in_next = reqp->dr_chain_in_head.dc_next_paddr;
		reqp->dr_in_len = reqp->dr_chain_in_head.dc_buffer_length;
	} else {
		reqp->dr_in_paddr = NULL;
		reqp->dr_in_next = 0;
		reqp->dr_in_len = 0;
	}

	if (reqp->dr_flags & DR_INPLACE) {
		reqp->dr_out_paddr = reqp->dr_in_paddr;
		reqp->dr_out_len = reqp->dr_in_len;
		reqp->dr_out_next = reqp->dr_in_next;
		return (DDI_SUCCESS);
	}

	/* then the output */
	if (outcnt) {
		flags = DDI_DMA_READ | DDI_DMA_STREAMING;
		if ((kaddr = dca_bufdaddr_out(reqp->dr_out)) == NULL) {
			DBG(NULL, DWARN, "unrecognised crypto data format");
			(void) dca_unbindchains(reqp);
			return (DDI_FAILURE);
		}
		rv = dca_bindchains_one(reqp, outcnt, reqp->dr_offset +
		    n_chain * DESC_SIZE, kaddr, reqp->dr_chain_out_dmah,
		    flags, &reqp->dr_chain_out_head, &n_chain);
		if (rv != DDI_SUCCESS) {
			(void) dca_unbindchains(reqp);
			return (DDI_FAILURE);
		}

		/* Save the first one in the chain for MCR */
		reqp->dr_out_paddr = reqp->dr_chain_out_head.dc_buffer_paddr;
		reqp->dr_out_next = reqp->dr_chain_out_head.dc_next_paddr;
		reqp->dr_out_len = reqp->dr_chain_out_head.dc_buffer_length;
	} else {
		reqp->dr_out_paddr = NULL;
		reqp->dr_out_next = 0;
		reqp->dr_out_len = 0;
	}

	return (DDI_SUCCESS);
}

/*
 * Unbind the user buffers from the DMA handles.
 */
int
dca_unbindchains(dca_request_t *reqp)
{
	int rv = DDI_SUCCESS;
	int rv1 = DDI_SUCCESS;

	/* Clear the input chain */
	if (reqp->dr_chain_in_head.dc_buffer_paddr != NULL) {
		(void) ddi_dma_unbind_handle(reqp->dr_chain_in_dmah);
		reqp->dr_chain_in_head.dc_buffer_paddr = 0;
	}

	if (reqp->dr_flags & DR_INPLACE) {
		return (rv);
	}

	/* Clear the output chain */
	if (reqp->dr_chain_out_head.dc_buffer_paddr != NULL) {
		(void) ddi_dma_unbind_handle(reqp->dr_chain_out_dmah);
		reqp->dr_chain_out_head.dc_buffer_paddr = 0;
	}

	return ((rv != DDI_SUCCESS)? rv : rv1);
}

/*
 * Build either input chain or output chain. It is single-item chain for Sparc,
 * and possible mutiple-item chain for x86.
 */
static int
dca_bindchains_one(dca_request_t *reqp, size_t cnt, int dr_offset,
    caddr_t kaddr, ddi_dma_handle_t handle, uint_t flags,
    dca_chain_t *head, int *n_chain)
{
	ddi_dma_cookie_t	c;
	uint_t			nc;
	int			rv;
	caddr_t			chain_kaddr_pre;
	caddr_t			chain_kaddr;
	uint32_t		chain_paddr;
	int 			i;

	/* Advance past the context structure to the starting address */
	chain_paddr = reqp->dr_ctx_paddr + dr_offset;
	chain_kaddr = reqp->dr_ctx_kaddr + dr_offset;

	/*
	 * Bind the kernel address to the DMA handle. On x86, the actual
	 * buffer is mapped into multiple physical addresses. On Sparc,
	 * the actual buffer is mapped into a single address.
	 */
	rv = ddi_dma_addr_bind_handle(handle,
	    NULL, kaddr, cnt, flags, DDI_DMA_DONTWAIT, NULL, &c, &nc);
	if (rv != DDI_DMA_MAPPED) {
		return (DDI_FAILURE);
	}

	(void) ddi_dma_sync(handle, 0, cnt, DDI_DMA_SYNC_FORDEV);
	if ((rv = dca_check_dma_handle(reqp->dr_dca, handle,
	    DCA_FM_ECLASS_NONE)) != DDI_SUCCESS) {
		reqp->destroy = TRUE;
		return (rv);
	}

	*n_chain = nc;

	/* Setup the data buffer chain for DMA transfer */
	chain_kaddr_pre = NULL;
	head->dc_buffer_paddr = 0;
	head->dc_next_paddr = 0;
	head->dc_buffer_length = 0;
	for (i = 0; i < nc; i++) {
		/* PIO */
		PUTDESC32(reqp, chain_kaddr, DESC_BUFADDR, c.dmac_address);
		PUTDESC16(reqp, chain_kaddr, DESC_RSVD, 0);
		PUTDESC16(reqp, chain_kaddr, DESC_LENGTH, c.dmac_size);

		/* Remember the head of the chain */
		if (head->dc_buffer_paddr == 0) {
			head->dc_buffer_paddr = c.dmac_address;
			head->dc_buffer_length = c.dmac_size;
		}

		/* Link to the previous one if one exists */
		if (chain_kaddr_pre) {
			PUTDESC32(reqp, chain_kaddr_pre, DESC_NEXT,
			    chain_paddr);
			if (head->dc_next_paddr == 0)
				head->dc_next_paddr = chain_paddr;
		}
		chain_kaddr_pre = chain_kaddr;

		/* Maintain pointers */
		chain_paddr += DESC_SIZE;
		chain_kaddr += DESC_SIZE;

		/* Retrieve the next cookie if there is one */
		if (i < nc-1)
			ddi_dma_nextcookie(handle, &c);
	}

	/* Set the next pointer in the last entry to NULL */
	PUTDESC32(reqp, chain_kaddr_pre, DESC_NEXT, 0);

	return (DDI_SUCCESS);
}

/*
 * Schedule some work.
 */
int
dca_start(dca_t *dca, dca_request_t *reqp, int mcr, int dosched)
{
	dca_worklist_t	*wlp = WORKLIST(dca, mcr);

	mutex_enter(&wlp->dwl_lock);

	DBG(dca, DCHATTY, "req=%p, in=%p, out=%p, ctx=%p, ibuf=%p, obuf=%p",
	    reqp, reqp->dr_in, reqp->dr_out, reqp->dr_ctx_kaddr,
	    reqp->dr_ibuf_kaddr, reqp->dr_obuf_kaddr);
	DBG(dca, DCHATTY, "ctx paddr = %x, ibuf paddr = %x, obuf paddr = %x",
	    reqp->dr_ctx_paddr, reqp->dr_ibuf_paddr, reqp->dr_obuf_paddr);
	/* sync out the entire context and descriptor chains */
	(void) ddi_dma_sync(reqp->dr_ctx_dmah, 0, 0, DDI_DMA_SYNC_FORDEV);
	if (dca_check_dma_handle(dca, reqp->dr_ctx_dmah,
	    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
		reqp->destroy = TRUE;
		mutex_exit(&wlp->dwl_lock);
		return (CRYPTO_DEVICE_ERROR);
	}

	dca_enqueue(&wlp->dwl_waitq, (dca_listnode_t *)reqp);
	wlp->dwl_count++;
	wlp->dwl_lastsubmit = ddi_get_lbolt();
	reqp->dr_wlp = wlp;

	if ((wlp->dwl_count == wlp->dwl_hiwater) && (wlp->dwl_busy == 0)) {
		/* we are fully loaded now, let kCF know */

		wlp->dwl_flowctl++;
		wlp->dwl_busy = 1;

		crypto_prov_notify(wlp->dwl_prov, CRYPTO_PROVIDER_BUSY);
	}

	if (dosched) {
#ifdef	SCHEDDELAY
		/* possibly wait for more work to arrive */
		if (wlp->dwl_count >= wlp->dwl_reqspermcr) {
			dca_schedule(dca, mcr);
		} else if (!wlp->dwl_schedtid) {
			/* wait 1 msec for more work before doing it */
			wlp->dwl_schedtid = timeout(dca_schedtimeout,
			    (void *)wlp, drv_usectohz(MSEC));
		}
#else
		dca_schedule(dca, mcr);
#endif
	}
	mutex_exit(&wlp->dwl_lock);

	return (CRYPTO_QUEUED);
}

void
dca_schedule(dca_t *dca, int mcr)
{
	dca_worklist_t	*wlp = WORKLIST(dca, mcr);
	int		csr;
	int		full;
	uint32_t	status;

	ASSERT(mutex_owned(&wlp->dwl_lock));
	/*
	 * If the card is draining or has an outstanding failure,
	 * don't schedule any more work on it right now
	 */
	if (wlp->dwl_drain || (dca->dca_flags & DCA_FAILED)) {
		return;
	}

	if (mcr == MCR2) {
		csr = CSR_MCR2;
		full = DMASTAT_MCR2FULL;
	} else {
		csr = CSR_MCR1;
		full = DMASTAT_MCR1FULL;
	}

	for (;;) {
		dca_work_t	*workp;
		uint32_t	offset;
		int		nreqs;

		status = GETCSR(dca, CSR_DMASTAT);
		if (dca_check_acc_handle(dca, dca->dca_regs_handle,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS)
			return;

		if ((status & full) != 0)
			break;

#ifdef	SCHEDDELAY
		/* if there isn't enough to do, don't bother now */
		if ((wlp->dwl_count < wlp->dwl_reqspermcr) &&
		    (ddi_get_lbolt() < (wlp->dwl_lastsubmit +
		    drv_usectohz(MSEC)))) {
			/* wait a bit longer... */
			if (wlp->dwl_schedtid == 0) {
				wlp->dwl_schedtid = timeout(dca_schedtimeout,
				    (void *)wlp, drv_usectohz(MSEC));
			}
			return;
		}
#endif

		/* grab a work structure */
		workp = dca_getwork(dca, mcr);

		if (workp == NULL) {
			/*
			 * There must be work ready to be reclaimed,
			 * in this case, since the chip can only hold
			 * less work outstanding than there are total.
			 */
			dca_reclaim(dca, mcr);
			continue;
		}

		nreqs = 0;
		offset = MCR_CTXADDR;

		while (nreqs < wlp->dwl_reqspermcr) {
			dca_request_t	*reqp;

			reqp = (dca_request_t *)dca_dequeue(&wlp->dwl_waitq);
			if (reqp == NULL) {
				/* nothing left to process */
				break;
			}
			/*
			 * Update flow control.
			 */
			wlp->dwl_count--;
			if ((wlp->dwl_count == wlp->dwl_lowater) &&
			    (wlp->dwl_busy))  {
				wlp->dwl_busy = 0;
				crypto_prov_notify(wlp->dwl_prov,
				    CRYPTO_PROVIDER_READY);
			}

			/*
			 * Context address.
			 */
			PUTMCR32(workp, offset, reqp->dr_ctx_paddr);
			offset += 4;

			/*
			 * Input chain.
			 */
			/* input buffer address */
			PUTMCR32(workp, offset, reqp->dr_in_paddr);
			offset += 4;
			/* next input buffer entry */
			PUTMCR32(workp, offset, reqp->dr_in_next);
			offset += 4;
			/* input buffer length */
			PUTMCR16(workp, offset, reqp->dr_in_len);
			offset += 2;
			/* zero the reserved field */
			PUTMCR16(workp, offset, 0);
			offset += 2;

			/*
			 * Overall length.
			 */
			/* reserved field */
			PUTMCR16(workp, offset, 0);
			offset += 2;
			/* total packet length */
			PUTMCR16(workp, offset, reqp->dr_pkt_length);
			offset += 2;

			/*
			 * Output chain.
			 */
			/* output buffer address */
			PUTMCR32(workp, offset, reqp->dr_out_paddr);
			offset += 4;
			/* next output buffer entry */
			PUTMCR32(workp, offset, reqp->dr_out_next);
			offset += 4;
			/* output buffer length */
			PUTMCR16(workp, offset, reqp->dr_out_len);
			offset += 2;
			/* zero the reserved field */
			PUTMCR16(workp, offset, 0);
			offset += 2;

			/*
			 * Note submission.
			 */
			workp->dw_reqs[nreqs] = reqp;
			nreqs++;
		}

		if (nreqs == 0) {
			/* nothing in the queue! */
			dca_freework(workp);
			return;
		}

		wlp->dwl_submit++;

		PUTMCR16(workp, MCR_FLAGS, 0);
		PUTMCR16(workp, MCR_COUNT, nreqs);

		DBG(dca, DCHATTY,
		    "posting work (phys %x, virt 0x%p) (%d reqs) to MCR%d",
		    workp->dw_mcr_paddr, workp->dw_mcr_kaddr,
		    nreqs, mcr);

		workp->dw_lbolt = ddi_get_lbolt();
		/* Make sure MCR is synced out to device. */
		(void) ddi_dma_sync(workp->dw_mcr_dmah, 0, 0,
		    DDI_DMA_SYNC_FORDEV);
		if (dca_check_dma_handle(dca, workp->dw_mcr_dmah,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			dca_destroywork(workp);
			return;
		}

		PUTCSR(dca, csr, workp->dw_mcr_paddr);
		if (dca_check_acc_handle(dca, dca->dca_regs_handle,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			dca_destroywork(workp);
			return;
		} else {
			dca_enqueue(&wlp->dwl_runq, (dca_listnode_t *)workp);
		}

		DBG(dca, DCHATTY, "posted");
	}
}

/*
 * Reclaim completed work, called in interrupt context.
 */
void
dca_reclaim(dca_t *dca, int mcr)
{
	dca_worklist_t	*wlp = WORKLIST(dca, mcr);
	dca_work_t	*workp;
	ushort_t	flags;
	int		nreclaimed = 0;
	int		i;

	DBG(dca, DRECLAIM, "worklist = 0x%p (MCR%d)", wlp, mcr);
	ASSERT(mutex_owned(&wlp->dwl_lock));
	/*
	 * For each MCR in the submitted (runq), we check to see if
	 * it has been processed.  If so, then we note each individual
	 * job in the MCR, and and do the completion processing for
	 * each of such job.
	 */
	for (;;) {

		workp = (dca_work_t *)dca_peekqueue(&wlp->dwl_runq);
		if (workp == NULL) {
			break;
		}

		/* only sync the MCR flags, since that's all we need */
		(void) ddi_dma_sync(workp->dw_mcr_dmah, 0, 4,
		    DDI_DMA_SYNC_FORKERNEL);
		if (dca_check_dma_handle(dca, workp->dw_mcr_dmah,
		    DCA_FM_ECLASS_NONE) != DDI_SUCCESS) {
			dca_rmqueue((dca_listnode_t *)workp);
			dca_destroywork(workp);
			return;
		}

		flags = GETMCR16(workp, MCR_FLAGS);
		if ((flags & MCRFLAG_FINISHED) == 0) {
			/* chip is still working on it */
			DBG(dca, DRECLAIM,
			    "chip still working on it (MCR%d)", mcr);
			break;
		}

		/* its really for us, so remove it from the queue */
		dca_rmqueue((dca_listnode_t *)workp);

		/* if we were draining, signal on the cv */
		if (wlp->dwl_drain && QEMPTY(&wlp->dwl_runq)) {
			cv_signal(&wlp->dwl_cv);
		}

		/* update statistics, done under the lock */
		for (i = 0; i < wlp->dwl_reqspermcr; i++) {
			dca_request_t *reqp = workp->dw_reqs[i];
			if (reqp == NULL) {
				continue;
			}
			if (reqp->dr_byte_stat >= 0) {
				dca->dca_stats[reqp->dr_byte_stat] +=
				    reqp->dr_pkt_length;
			}
			if (reqp->dr_job_stat >= 0) {
				dca->dca_stats[reqp->dr_job_stat]++;
			}
		}
		mutex_exit(&wlp->dwl_lock);

		for (i = 0; i < wlp->dwl_reqspermcr; i++) {
			dca_request_t *reqp = workp->dw_reqs[i];

			if (reqp == NULL) {
				continue;
			}

			/* Do the callback. */
			workp->dw_reqs[i] = NULL;
			dca_done(reqp, CRYPTO_SUCCESS);

			nreclaimed++;
		}

		/* now we can release the work */
		dca_freework(workp);

		mutex_enter(&wlp->dwl_lock);
	}
	DBG(dca, DRECLAIM, "reclaimed %d cmds", nreclaimed);
}

int
dca_length(crypto_data_t *cdata)
{
	return (cdata->cd_length);
}

/*
 * This is the callback function called from the interrupt when a kCF job
 * completes.  It does some driver-specific things, and then calls the
 * kCF-provided callback.  Finally, it cleans up the state for the work
 * request and drops the reference count to allow for DR.
 */
void
dca_done(dca_request_t *reqp, int err)
{
	uint64_t	ena = 0;

	/* unbind any chains we were using */
	if (dca_unbindchains(reqp) != DDI_SUCCESS) {
		/* DMA failure */
		ena = dca_ena(ena);
		dca_failure(reqp->dr_dca, DDI_DATAPATH_FAULT,
		    DCA_FM_ECLASS_NONE, ena, CRYPTO_DEVICE_ERROR,
		    "fault on buffer DMA handle");
		if (err == CRYPTO_SUCCESS) {
			err = CRYPTO_DEVICE_ERROR;
		}
	}

	if (reqp->dr_callback != NULL) {
		reqp->dr_callback(reqp, err);
	} else {
		dca_freereq(reqp);
	}
}

/*
 * Call this when a failure is detected.  It will reset the chip,
 * log a message, alert kCF, and mark jobs in the runq as failed.
 */
/* ARGSUSED */
void
dca_failure(dca_t *dca, ddi_fault_location_t loc, dca_fma_eclass_t index,
    uint64_t ena, int errno, char *mess, ...)
{
	va_list	ap;
	char	buf[256];
	int	mcr;
	char	*eclass;
	int	have_mutex;

	va_start(ap, mess);
	(void) vsprintf(buf, mess, ap);
	va_end(ap);

	eclass = dca_fma_eclass_string(dca->dca_model, index);

	if (DDI_FM_EREPORT_CAP(dca->fm_capabilities) &&
	    index != DCA_FM_ECLASS_NONE) {
		ddi_fm_ereport_post(dca->dca_dip, eclass, ena,
		    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8,
		    FM_EREPORT_VERS0, NULL);

		/* Report the impact of the failure to the DDI. */
		ddi_fm_service_impact(dca->dca_dip, DDI_SERVICE_LOST);
	} else {
		/* Just log the error string to the message log */
		dca_error(dca, buf);
	}

	/*
	 * Indicate a failure (keeps schedule from running).
	 */
	dca->dca_flags |= DCA_FAILED;

	/*
	 * Reset the chip.  This should also have as a side effect, the
	 * disabling of all interrupts from the device.
	 */
	(void) dca_reset(dca, 1);

	/*
	 * Report the failure to kCF.
	 */
	for (mcr = MCR1; mcr <= MCR2; mcr++) {
		if (WORKLIST(dca, mcr)->dwl_prov) {
			crypto_prov_notify(WORKLIST(dca, mcr)->dwl_prov,
			    CRYPTO_PROVIDER_FAILED);
		}
	}

	/*
	 * Return jobs not sent to hardware back to kCF.
	 */
	dca_rejectjobs(dca);

	/*
	 * From this point on, no new work should be arriving, and the
	 * chip should not be doing any active DMA.
	 */

	/*
	 * Now find all the work submitted to the device and fail
	 * them.
	 */
	for (mcr = MCR1; mcr <= MCR2; mcr++) {
		dca_worklist_t	*wlp;
		int		i;

		wlp = WORKLIST(dca, mcr);

		if (wlp == NULL || wlp->dwl_waitq.dl_prev == NULL) {
			continue;
		}
		for (;;) {
			dca_work_t	*workp;

			have_mutex = mutex_tryenter(&wlp->dwl_lock);
			workp = (dca_work_t *)dca_dequeue(&wlp->dwl_runq);
			if (workp == NULL) {
				if (have_mutex)
					mutex_exit(&wlp->dwl_lock);
				break;
			}
			mutex_exit(&wlp->dwl_lock);

			/*
			 * Free up requests
			 */
			for (i = 0; i < wlp->dwl_reqspermcr; i++) {
				dca_request_t *reqp = workp->dw_reqs[i];
				if (reqp) {
					dca_done(reqp, errno);
					workp->dw_reqs[i] = NULL;
				}
			}

			mutex_enter(&wlp->dwl_lock);
			/*
			 * If waiting to drain, signal on the waiter.
			 */
			if (wlp->dwl_drain && QEMPTY(&wlp->dwl_runq)) {
				cv_signal(&wlp->dwl_cv);
			}

			/*
			 * Return the work and request structures to
			 * the free pool.
			 */
			dca_freework(workp);
			if (have_mutex)
				mutex_exit(&wlp->dwl_lock);
		}
	}

}

#ifdef	SCHEDDELAY
/*
 * Reschedule worklist as needed.
 */
void
dca_schedtimeout(void *arg)
{
	dca_worklist_t	*wlp = (dca_worklist_t *)arg;
	mutex_enter(&wlp->dwl_lock);
	wlp->dwl_schedtid = 0;
	dca_schedule(wlp->dwl_dca, wlp->dwl_mcr);
	mutex_exit(&wlp->dwl_lock);
}
#endif

/*
 * Check for stalled jobs.
 */
void
dca_jobtimeout(void *arg)
{
	int		mcr;
	dca_t		*dca = (dca_t *)arg;
	int		hung = 0;

	for (mcr = MCR1; mcr <= MCR2; mcr++) {
		dca_worklist_t	*wlp = WORKLIST(dca, mcr);
		dca_work_t	*workp;
		clock_t		when;

		mutex_enter(&wlp->dwl_lock);
		when = ddi_get_lbolt();

		workp = (dca_work_t *)dca_peekqueue(&wlp->dwl_runq);
		if (workp == NULL) {
			/* nothing sitting in the queue */
			mutex_exit(&wlp->dwl_lock);
			continue;
		}

		if ((when - workp->dw_lbolt) < drv_usectohz(STALETIME)) {
			/* request has been queued for less than STALETIME */
			mutex_exit(&wlp->dwl_lock);
			continue;
		}

		/* job has been sitting around for over 1 second, badness */
		DBG(dca, DWARN, "stale job (0x%p) found in MCR%d!", workp,
		    mcr);

		/* put it back in the queue, until we reset the chip */
		hung++;
		mutex_exit(&wlp->dwl_lock);
	}

	if (hung) {
		dca_failure(dca, DDI_DEVICE_FAULT,
		    DCA_FM_ECLASS_HW_TIMEOUT, dca_ena(0), CRYPTO_DEVICE_ERROR,
		    "timeout processing job.)");
	}

	/* reschedule ourself */
	mutex_enter(&dca->dca_intrlock);
	if (dca->dca_jobtid == 0) {
		/* timeout has been canceled, prior to DR */
		mutex_exit(&dca->dca_intrlock);
		return;
	}

	/* check again in 1 second */
	dca->dca_jobtid = timeout(dca_jobtimeout, arg,
	    drv_usectohz(SECOND));
	mutex_exit(&dca->dca_intrlock);
}

/*
 * This returns all jobs back to kCF.  It assumes that processing
 * on the worklist has halted.
 */
void
dca_rejectjobs(dca_t *dca)
{
	int mcr;
	int have_mutex;
	for (mcr = MCR1; mcr <= MCR2; mcr++) {
		dca_worklist_t	*wlp = WORKLIST(dca, mcr);
		dca_request_t	*reqp;

		if (wlp == NULL || wlp->dwl_waitq.dl_prev == NULL) {
			continue;
		}
		have_mutex = mutex_tryenter(&wlp->dwl_lock);
		for (;;) {
			reqp = (dca_request_t *)dca_unqueue(&wlp->dwl_waitq);
			if (reqp == NULL) {
				break;
			}
			/* update flow control */
			wlp->dwl_count--;
			if ((wlp->dwl_count == wlp->dwl_lowater) &&
			    (wlp->dwl_busy))  {
				wlp->dwl_busy = 0;
				crypto_prov_notify(wlp->dwl_prov,
				    CRYPTO_PROVIDER_READY);
			}
			mutex_exit(&wlp->dwl_lock);

			(void) dca_unbindchains(reqp);
			reqp->dr_callback(reqp, EAGAIN);
			mutex_enter(&wlp->dwl_lock);
		}
		if (have_mutex)
			mutex_exit(&wlp->dwl_lock);
	}
}

int
dca_drain(dca_t *dca)
{
	int mcr;
	for (mcr = MCR1; mcr <= MCR2; mcr++) {
#ifdef	SCHEDDELAY
		timeout_id_t	tid;
#endif
		dca_worklist_t *wlp = WORKLIST(dca, mcr);

		mutex_enter(&wlp->dwl_lock);
		wlp->dwl_drain = 1;

		/* give it up to a second to drain from the chip */
		if (!QEMPTY(&wlp->dwl_runq)) {
			(void) cv_reltimedwait(&wlp->dwl_cv, &wlp->dwl_lock,
			    drv_usectohz(STALETIME), TR_CLOCK_TICK);

			if (!QEMPTY(&wlp->dwl_runq)) {
				dca_error(dca, "unable to drain device");
				mutex_exit(&wlp->dwl_lock);
				dca_undrain(dca);
				return (EBUSY);
			}
		}

#ifdef	SCHEDDELAY
		tid = wlp->dwl_schedtid;
		mutex_exit(&wlp->dwl_lock);

		/*
		 * untimeout outside the lock -- this is safe because we
		 * have set the drain flag, so dca_schedule() will not
		 * reschedule another timeout
		 */
		if (tid) {
			untimeout(tid);
		}
#else
		mutex_exit(&wlp->dwl_lock);
#endif
	}
	return (0);
}

void
dca_undrain(dca_t *dca)
{
	int	mcr;

	for (mcr = MCR1; mcr <= MCR2; mcr++) {
		dca_worklist_t	*wlp = WORKLIST(dca, mcr);
		mutex_enter(&wlp->dwl_lock);
		wlp->dwl_drain = 0;
		dca_schedule(dca, mcr);
		mutex_exit(&wlp->dwl_lock);
	}
}

/*
 * Duplicate the crypto_data_t structure, but point to the original
 * buffers.
 */
int
dca_dupcrypto(crypto_data_t *input, crypto_data_t *ninput)
{
	ninput->cd_format = input->cd_format;
	ninput->cd_offset = input->cd_offset;
	ninput->cd_length = input->cd_length;
	ninput->cd_miscdata = input->cd_miscdata;

	switch (input->cd_format) {
	case CRYPTO_DATA_RAW:
		ninput->cd_raw.iov_base = input->cd_raw.iov_base;
		ninput->cd_raw.iov_len = input->cd_raw.iov_len;
		break;

	case CRYPTO_DATA_UIO:
		ninput->cd_uio = input->cd_uio;
		break;

	case CRYPTO_DATA_MBLK:
		ninput->cd_mp = input->cd_mp;
		break;

	default:
		DBG(NULL, DWARN,
		    "dca_dupcrypto: unrecognised crypto data format");
		return (CRYPTO_FAILED);
	}

	return (CRYPTO_SUCCESS);
}

/*
 * Performs validation checks on the input and output data structures.
 */
int
dca_verifyio(crypto_data_t *input, crypto_data_t *output)
{
	int	rv = CRYPTO_SUCCESS;

	switch (input->cd_format) {
	case CRYPTO_DATA_RAW:
		break;

	case CRYPTO_DATA_UIO:
		/* we support only kernel buffer */
		if (input->cd_uio->uio_segflg != UIO_SYSSPACE) {
			DBG(NULL, DWARN, "non kernel input uio buffer");
			rv = CRYPTO_ARGUMENTS_BAD;
		}
		break;

	case CRYPTO_DATA_MBLK:
		break;

	default:
		DBG(NULL, DWARN, "unrecognised input crypto data format");
		rv = CRYPTO_ARGUMENTS_BAD;
	}

	switch (output->cd_format) {
	case CRYPTO_DATA_RAW:
		break;

	case CRYPTO_DATA_UIO:
		/* we support only kernel buffer */
		if (output->cd_uio->uio_segflg != UIO_SYSSPACE) {
			DBG(NULL, DWARN, "non kernel output uio buffer");
			rv = CRYPTO_ARGUMENTS_BAD;
		}
		break;

	case CRYPTO_DATA_MBLK:
		break;

	default:
		DBG(NULL, DWARN, "unrecognised output crypto data format");
		rv = CRYPTO_ARGUMENTS_BAD;
	}

	return (rv);
}

/*
 * data: source crypto_data_t struct
 * off:	offset into the source before commencing copy
 * count: the amount of data to copy
 * dest: destination buffer
 */
int
dca_getbufbytes(crypto_data_t *data, size_t off, int count, uchar_t *dest)
{
	int rv = CRYPTO_SUCCESS;
	uio_t *uiop;
	uint_t vec_idx;
	size_t cur_len;
	mblk_t *mp;

	if (count == 0) {
		/* We don't want anything so we're done. */
		return (rv);
	}

	/*
	 * Sanity check that we haven't specified a length greater than the
	 * offset adjusted size of the buffer.
	 */
	if (count > (data->cd_length - off)) {
		return (CRYPTO_DATA_LEN_RANGE);
	}

	/* Add the internal crypto_data offset to the requested offset. */
	off += data->cd_offset;

	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		bcopy(data->cd_raw.iov_base + off, dest, count);
		break;

	case CRYPTO_DATA_UIO:
		/*
		 * Jump to the first iovec containing data to be
		 * processed.
		 */
		uiop = data->cd_uio;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    off >= uiop->uio_iov[vec_idx].iov_len;
		    off -= uiop->uio_iov[vec_idx++].iov_len)
			;
		if (vec_idx == uiop->uio_iovcnt) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && count > 0) {
			cur_len = min(uiop->uio_iov[vec_idx].iov_len -
			    off, count);
			bcopy(uiop->uio_iov[vec_idx].iov_base + off, dest,
			    cur_len);
			count -= cur_len;
			dest += cur_len;
			vec_idx++;
			off = 0;
		}

		if (vec_idx == uiop->uio_iovcnt && count > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed
			 * (requested to digest more data than it provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	case CRYPTO_DATA_MBLK:
		/*
		 * Jump to the first mblk_t containing data to be processed.
		 */
		for (mp = data->cd_mp; mp != NULL && off >= MBLKL(mp);
		    off -= MBLKL(mp), mp = mp->b_cont)
			;
		if (mp == NULL) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now do the processing on the mblk chain.
		 */
		while (mp != NULL && count > 0) {
			cur_len = min(MBLKL(mp) - off, count);
			bcopy((char *)(mp->b_rptr + off), dest, cur_len);
			count -= cur_len;
			dest += cur_len;
			mp = mp->b_cont;
			off = 0;
		}

		if (mp == NULL && count > 0) {
			/*
			 * The end of the mblk was reached but the length
			 * requested could not be processed, (requested to
			 * digest more data than it provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	default:
		DBG(NULL, DWARN, "unrecognised crypto data format");
		rv = CRYPTO_ARGUMENTS_BAD;
	}
	return (rv);
}


/*
 * Performs the input, output or hard scatter/gather checks on the specified
 * crypto_data_t struct. Returns true if the data is scatter/gather in nature
 * ie fails the test.
 */
int
dca_sgcheck(dca_t *dca, crypto_data_t *data, dca_sg_param_t val)
{
	uio_t *uiop;
	mblk_t *mp;
	int rv = FALSE;

	switch (val) {
	case DCA_SG_CONTIG:
		/*
		 * Check for a contiguous data buffer.
		 */
		switch (data->cd_format) {
		case CRYPTO_DATA_RAW:
			/* Contiguous in nature */
			break;

		case CRYPTO_DATA_UIO:
			if (data->cd_uio->uio_iovcnt > 1)
				rv = TRUE;
			break;

		case CRYPTO_DATA_MBLK:
			mp = data->cd_mp;
			if (mp->b_cont != NULL)
				rv = TRUE;
			break;

		default:
			DBG(NULL, DWARN, "unrecognised crypto data format");
		}
		break;

	case DCA_SG_WALIGN:
		/*
		 * Check for a contiguous data buffer that is 32-bit word
		 * aligned and is of word multiples in size.
		 */
		switch (data->cd_format) {
		case CRYPTO_DATA_RAW:
			if ((data->cd_raw.iov_len % sizeof (uint32_t)) ||
			    ((uintptr_t)data->cd_raw.iov_base %
			    sizeof (uint32_t))) {
				rv = TRUE;
			}
			break;

		case CRYPTO_DATA_UIO:
			uiop = data->cd_uio;
			if (uiop->uio_iovcnt > 1) {
				return (TRUE);
			}
			/* So there is only one iovec */
			if ((uiop->uio_iov[0].iov_len % sizeof (uint32_t)) ||
			    ((uintptr_t)uiop->uio_iov[0].iov_base %
			    sizeof (uint32_t))) {
				rv = TRUE;
			}
			break;

		case CRYPTO_DATA_MBLK:
			mp = data->cd_mp;
			if (mp->b_cont != NULL) {
				return (TRUE);
			}
			/* So there is only one mblk in the chain */
			if ((MBLKL(mp) % sizeof (uint32_t)) ||
			    ((uintptr_t)mp->b_rptr % sizeof (uint32_t))) {
				rv = TRUE;
			}
			break;

		default:
			DBG(NULL, DWARN, "unrecognised crypto data format");
		}
		break;

	case DCA_SG_PALIGN:
		/*
		 * Check that the data buffer is page aligned and is of
		 * page multiples in size.
		 */
		switch (data->cd_format) {
		case CRYPTO_DATA_RAW:
			if ((data->cd_length % dca->dca_pagesize) ||
			    ((uintptr_t)data->cd_raw.iov_base %
			    dca->dca_pagesize)) {
				rv = TRUE;
			}
			break;

		case CRYPTO_DATA_UIO:
			uiop = data->cd_uio;
			if ((uiop->uio_iov[0].iov_len % dca->dca_pagesize) ||
			    ((uintptr_t)uiop->uio_iov[0].iov_base %
			    dca->dca_pagesize)) {
				rv = TRUE;
			}
			break;

		case CRYPTO_DATA_MBLK:
			mp = data->cd_mp;
			if ((MBLKL(mp) % dca->dca_pagesize) ||
			    ((uintptr_t)mp->b_rptr % dca->dca_pagesize)) {
				rv = TRUE;
			}
			break;

		default:
			DBG(NULL, DWARN, "unrecognised crypto data format");
		}
		break;

	default:
		DBG(NULL, DWARN, "unrecognised scatter/gather param type");
	}

	return (rv);
}

/*
 * Increments the cd_offset and decrements the cd_length as the data is
 * gathered from the crypto_data_t struct.
 * The data is reverse-copied into the dest buffer if the flag is true.
 */
int
dca_gather(crypto_data_t *in, char *dest, int count, int reverse)
{
	int	rv = CRYPTO_SUCCESS;
	uint_t	vec_idx;
	uio_t	*uiop;
	off_t	off = in->cd_offset;
	size_t	cur_len;
	mblk_t	*mp;

	switch (in->cd_format) {
	case CRYPTO_DATA_RAW:
		if (count > in->cd_length) {
			/*
			 * The caller specified a length greater than the
			 * size of the buffer.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		if (reverse)
			dca_reverse(in->cd_raw.iov_base + off, dest, count,
			    count);
		else
			bcopy(in->cd_raw.iov_base + in->cd_offset, dest, count);
		in->cd_offset += count;
		in->cd_length -= count;
		break;

	case CRYPTO_DATA_UIO:
		/*
		 * Jump to the first iovec containing data to be processed.
		 */
		uiop = in->cd_uio;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    off >= uiop->uio_iov[vec_idx].iov_len;
		    off -= uiop->uio_iov[vec_idx++].iov_len)
			;
		if (vec_idx == uiop->uio_iovcnt) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && count > 0) {
			cur_len = min(uiop->uio_iov[vec_idx].iov_len -
			    off, count);
			count -= cur_len;
			if (reverse) {
				/* Fill the dest buffer from the end */
				dca_reverse(uiop->uio_iov[vec_idx].iov_base +
				    off, dest+count, cur_len, cur_len);
			} else {
				bcopy(uiop->uio_iov[vec_idx].iov_base + off,
				    dest, cur_len);
				dest += cur_len;
			}
			in->cd_offset += cur_len;
			in->cd_length -= cur_len;
			vec_idx++;
			off = 0;
		}

		if (vec_idx == uiop->uio_iovcnt && count > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed
			 * (requested to digest more data than it provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	case CRYPTO_DATA_MBLK:
		/*
		 * Jump to the first mblk_t containing data to be processed.
		 */
		for (mp = in->cd_mp; mp != NULL && off >= MBLKL(mp);
		    off -= MBLKL(mp), mp = mp->b_cont)
			;
		if (mp == NULL) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now do the processing on the mblk chain.
		 */
		while (mp != NULL && count > 0) {
			cur_len = min(MBLKL(mp) - off, count);
			count -= cur_len;
			if (reverse) {
				/* Fill the dest buffer from the end */
				dca_reverse((char *)(mp->b_rptr + off),
				    dest+count, cur_len, cur_len);
			} else {
				bcopy((char *)(mp->b_rptr + off), dest,
				    cur_len);
				dest += cur_len;
			}
			in->cd_offset += cur_len;
			in->cd_length -= cur_len;
			mp = mp->b_cont;
			off = 0;
		}

		if (mp == NULL && count > 0) {
			/*
			 * The end of the mblk was reached but the length
			 * requested could not be processed, (requested to
			 * digest more data than it provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	default:
		DBG(NULL, DWARN, "dca_gather: unrecognised crypto data format");
		rv = CRYPTO_ARGUMENTS_BAD;
	}
	return (rv);
}

/*
 * Increments the cd_offset and decrements the cd_length as the data is
 * gathered from the crypto_data_t struct.
 */
int
dca_resid_gather(crypto_data_t *in, char *resid, int *residlen, char *dest,
    int count)
{
	int	rv = CRYPTO_SUCCESS;
	caddr_t	baddr;
	uint_t	vec_idx;
	uio_t	*uiop;
	off_t	off = in->cd_offset;
	size_t	cur_len;
	mblk_t	*mp;

	/* Process the residual first */
	if (*residlen > 0) {
		uint_t	num = min(count, *residlen);
		bcopy(resid, dest, num);
		*residlen -= num;
		if (*residlen > 0) {
			/*
			 * Requested amount 'count' is less than what's in
			 * the residual, so shuffle any remaining resid to
			 * the front.
			 */
			baddr = resid + num;
			bcopy(baddr, resid, *residlen);
		}
		dest += num;
		count -= num;
	}

	/* Now process what's in the crypto_data_t structs */
	switch (in->cd_format) {
	case CRYPTO_DATA_RAW:
		if (count > in->cd_length) {
			/*
			 * The caller specified a length greater than the
			 * size of the buffer.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		bcopy(in->cd_raw.iov_base + in->cd_offset, dest, count);
		in->cd_offset += count;
		in->cd_length -= count;
		break;

	case CRYPTO_DATA_UIO:
		/*
		 * Jump to the first iovec containing data to be processed.
		 */
		uiop = in->cd_uio;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    off >= uiop->uio_iov[vec_idx].iov_len;
		    off -= uiop->uio_iov[vec_idx++].iov_len)
			;
		if (vec_idx == uiop->uio_iovcnt) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && count > 0) {
			cur_len = min(uiop->uio_iov[vec_idx].iov_len -
			    off, count);
			bcopy(uiop->uio_iov[vec_idx].iov_base + off, dest,
			    cur_len);
			count -= cur_len;
			dest += cur_len;
			in->cd_offset += cur_len;
			in->cd_length -= cur_len;
			vec_idx++;
			off = 0;
		}

		if (vec_idx == uiop->uio_iovcnt && count > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed
			 * (requested to digest more data than it provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	case CRYPTO_DATA_MBLK:
		/*
		 * Jump to the first mblk_t containing data to be processed.
		 */
		for (mp = in->cd_mp; mp != NULL && off >= MBLKL(mp);
		    off -= MBLKL(mp), mp = mp->b_cont)
			;
		if (mp == NULL) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now do the processing on the mblk chain.
		 */
		while (mp != NULL && count > 0) {
			cur_len = min(MBLKL(mp) - off, count);
			bcopy((char *)(mp->b_rptr + off), dest, cur_len);
			count -= cur_len;
			dest += cur_len;
			in->cd_offset += cur_len;
			in->cd_length -= cur_len;
			mp = mp->b_cont;
			off = 0;
		}

		if (mp == NULL && count > 0) {
			/*
			 * The end of the mblk was reached but the length
			 * requested could not be processed, (requested to
			 * digest more data than it provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	default:
		DBG(NULL, DWARN,
		    "dca_resid_gather: unrecognised crypto data format");
		rv = CRYPTO_ARGUMENTS_BAD;
	}
	return (rv);
}

/*
 * Appends the data to the crypto_data_t struct increasing cd_length.
 * cd_offset is left unchanged.
 * Data is reverse-copied if the flag is TRUE.
 */
int
dca_scatter(const char *src, crypto_data_t *out, int count, int reverse)
{
	int	rv = CRYPTO_SUCCESS;
	off_t	offset = out->cd_offset + out->cd_length;
	uint_t	vec_idx;
	uio_t	*uiop;
	size_t	cur_len;
	mblk_t	*mp;

	switch (out->cd_format) {
	case CRYPTO_DATA_RAW:
		if (out->cd_raw.iov_len - offset < count) {
			/* Trying to write out more than space available. */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		if (reverse)
			dca_reverse((void*) src, out->cd_raw.iov_base + offset,
			    count, count);
		else
			bcopy(src, out->cd_raw.iov_base + offset, count);
		out->cd_length += count;
		break;

	case CRYPTO_DATA_UIO:
		/*
		 * Jump to the first iovec that can be written to.
		 */
		uiop = out->cd_uio;
		for (vec_idx = 0; vec_idx < uiop->uio_iovcnt &&
		    offset >= uiop->uio_iov[vec_idx].iov_len;
		    offset -= uiop->uio_iov[vec_idx++].iov_len)
			;
		if (vec_idx == uiop->uio_iovcnt) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now process the iovecs.
		 */
		while (vec_idx < uiop->uio_iovcnt && count > 0) {
			cur_len = min(uiop->uio_iov[vec_idx].iov_len -
			    offset, count);
			count -= cur_len;
			if (reverse) {
				dca_reverse((void*) (src+count),
				    uiop->uio_iov[vec_idx].iov_base +
				    offset, cur_len, cur_len);
			} else {
				bcopy(src, uiop->uio_iov[vec_idx].iov_base +
				    offset, cur_len);
				src += cur_len;
			}
			out->cd_length += cur_len;
			vec_idx++;
			offset = 0;
		}

		if (vec_idx == uiop->uio_iovcnt && count > 0) {
			/*
			 * The end of the specified iovec's was reached but
			 * the length requested could not be processed
			 * (requested to write more data than space provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	case CRYPTO_DATA_MBLK:
		/*
		 * Jump to the first mblk_t that can be written to.
		 */
		for (mp = out->cd_mp; mp != NULL && offset >= MBLKL(mp);
		    offset -= MBLKL(mp), mp = mp->b_cont)
			;
		if (mp == NULL) {
			/*
			 * The caller specified an offset that is larger than
			 * the total size of the buffers it provided.
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}

		/*
		 * Now do the processing on the mblk chain.
		 */
		while (mp != NULL && count > 0) {
			cur_len = min(MBLKL(mp) - offset, count);
			count -= cur_len;
			if (reverse) {
				dca_reverse((void*) (src+count),
				    (char *)(mp->b_rptr + offset), cur_len,
				    cur_len);
			} else {
				bcopy(src, (char *)(mp->b_rptr + offset),
				    cur_len);
				src += cur_len;
			}
			out->cd_length += cur_len;
			mp = mp->b_cont;
			offset = 0;
		}

		if (mp == NULL && count > 0) {
			/*
			 * The end of the mblk was reached but the length
			 * requested could not be processed, (requested to
			 * digest more data than it provided).
			 */
			return (CRYPTO_DATA_LEN_RANGE);
		}
		break;

	default:
		DBG(NULL, DWARN, "unrecognised crypto data format");
		rv = CRYPTO_ARGUMENTS_BAD;
	}
	return (rv);
}

/*
 * Compare two byte arrays in reverse order.
 * Return 0 if they are identical, 1 otherwise.
 */
int
dca_bcmp_reverse(const void *s1, const void *s2, size_t n)
{
	int i;
	caddr_t src, dst;

	if (!n)
		return (0);

	src = ((caddr_t)s1) + n - 1;
	dst = (caddr_t)s2;
	for (i = 0; i < n; i++) {
		if (*src != *dst)
			return (1);
		src--;
		dst++;
	}

	return (0);
}


/*
 * This calculates the size of a bignum in bits, specifically not counting
 * leading zero bits.  This size calculation must be done *before* any
 * endian reversal takes place (i.e. the numbers are in absolute big-endian
 * order.)
 */
int
dca_bitlen(unsigned char *bignum, int bytelen)
{
	unsigned char	msbyte;
	int		i, j;

	for (i = 0; i < bytelen - 1; i++) {
		if (bignum[i] != 0) {
			break;
		}
	}
	msbyte = bignum[i];
	for (j = 8; j > 1; j--) {
		if (msbyte & 0x80) {
			break;
		}
		msbyte <<= 1;
	}
	return ((8 * (bytelen - i - 1)) + j);
}

/*
 * This compares to bignums (in big-endian order).  It ignores leading
 * null bytes.  The result semantics follow bcmp, mempcmp, strcmp, etc.
 */
int
dca_numcmp(caddr_t n1, int n1len, caddr_t n2, int n2len)
{
	while ((n1len > 1) && (*n1 == 0)) {
		n1len--;
		n1++;
	}
	while ((n2len > 1) && (*n2 == 0)) {
		n2len--;
		n2++;
	}
	if (n1len != n2len) {
		return (n1len - n2len);
	}
	while ((n1len > 1) && (*n1 == *n2)) {
		n1++;
		n2++;
		n1len--;
	}
	return ((int)(*(uchar_t *)n1) - (int)(*(uchar_t *)n2));
}

/*
 * Return array of key attributes.
 */
crypto_object_attribute_t *
dca_get_key_attr(crypto_key_t *key)
{
	if ((key->ck_format != CRYPTO_KEY_ATTR_LIST) ||
	    (key->ck_count == 0)) {
		return (NULL);
	}

	return (key->ck_attrs);
}

/*
 * If attribute type exists valp points to it's 32-bit value.
 */
int
dca_attr_lookup_uint32(crypto_object_attribute_t *attrp, uint_t atnum,
    uint64_t atype, uint32_t *valp)
{
	crypto_object_attribute_t	*bap;

	bap = dca_find_attribute(attrp, atnum, atype);
	if (bap == NULL) {
		return (CRYPTO_ATTRIBUTE_TYPE_INVALID);
	}

	*valp = *bap->oa_value;

	return (CRYPTO_SUCCESS);
}

/*
 * If attribute type exists data contains the start address of the value,
 * and numelems contains it's length.
 */
int
dca_attr_lookup_uint8_array(crypto_object_attribute_t *attrp, uint_t atnum,
    uint64_t atype, void **data, unsigned int *numelems)
{
	crypto_object_attribute_t	*bap;

	bap = dca_find_attribute(attrp, atnum, atype);
	if (bap == NULL) {
		return (CRYPTO_ATTRIBUTE_TYPE_INVALID);
	}

	*data = bap->oa_value;
	*numelems = bap->oa_value_len;

	return (CRYPTO_SUCCESS);
}

/*
 * Finds entry of specified name. If it is not found dca_find_attribute returns
 * NULL.
 */
crypto_object_attribute_t *
dca_find_attribute(crypto_object_attribute_t *attrp, uint_t atnum,
    uint64_t atype)
{
	while (atnum) {
		if (attrp->oa_type == atype)
			return (attrp);
		atnum--;
		attrp++;
	}
	return (NULL);
}

/*
 * Return the address of the first data buffer. If the data format is
 * unrecognised return NULL.
 */
caddr_t
dca_bufdaddr(crypto_data_t *data)
{
	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		return (data->cd_raw.iov_base + data->cd_offset);
	case CRYPTO_DATA_UIO:
		return (data->cd_uio->uio_iov[0].iov_base + data->cd_offset);
	case CRYPTO_DATA_MBLK:
		return ((char *)data->cd_mp->b_rptr + data->cd_offset);
	default:
		DBG(NULL, DWARN,
		    "dca_bufdaddr: unrecognised crypto data format");
		return (NULL);
	}
}

static caddr_t
dca_bufdaddr_out(crypto_data_t *data)
{
	size_t offset = data->cd_offset + data->cd_length;

	switch (data->cd_format) {
	case CRYPTO_DATA_RAW:
		return (data->cd_raw.iov_base + offset);
	case CRYPTO_DATA_UIO:
		return (data->cd_uio->uio_iov[0].iov_base + offset);
	case CRYPTO_DATA_MBLK:
		return ((char *)data->cd_mp->b_rptr + offset);
	default:
		DBG(NULL, DWARN,
		    "dca_bufdaddr_out: unrecognised crypto data format");
		return (NULL);
	}
}

/*
 * Control entry points.
 */

/* ARGSUSED */
static void
dca_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*
 * Cipher (encrypt/decrypt) entry points.
 */

/* ARGSUSED */
static int
dca_encrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_encrypt_init: started");

	/* check mechanism */
	switch (mechanism->cm_type) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desctxinit(ctx, mechanism, key, KM_SLEEP,
		    DR_ENCRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desctxinit(ctx, mechanism, key, KM_SLEEP,
		    DR_ENCRYPT | DR_TRIPLE);
		break;
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsainit(ctx, mechanism, key, KM_SLEEP);
		break;
	default:
		cmn_err(CE_WARN, "dca_encrypt_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_encrypt_init: done, err = 0x%x", error);

	if (error == CRYPTO_SUCCESS)
		dca_enlist2(&softc->dca_ctx_list, ctx->cc_provider_private,
		    &softc->dca_ctx_list_lock);

	return (error);
}

/* ARGSUSED */
static int
dca_encrypt(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_encrypt: started");

	/* handle inplace ops */
	if (!ciphertext) {
		dca_request_t *reqp = ctx->cc_provider_private;
		reqp->dr_flags |= DR_INPLACE;
		ciphertext = plaintext;
	}

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3des(ctx, plaintext, ciphertext, req, DR_ENCRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3des(ctx, plaintext, ciphertext, req,
		    DR_ENCRYPT | DR_TRIPLE);
		break;
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsastart(ctx, plaintext, ciphertext, req,
		    DCA_RSA_ENC);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "dca_encrypt: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	if ((error != CRYPTO_QUEUED) && (error != CRYPTO_SUCCESS) &&
	    (error != CRYPTO_BUFFER_TOO_SMALL)) {
		ciphertext->cd_length = 0;
	}

	DBG(softc, DENTRY, "dca_encrypt: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_encrypt_update(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_data_t *ciphertext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_encrypt_update: started");

	/* handle inplace ops */
	if (!ciphertext) {
		dca_request_t *reqp = ctx->cc_provider_private;
		reqp->dr_flags |= DR_INPLACE;
		ciphertext = plaintext;
	}

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desupdate(ctx, plaintext, ciphertext, req,
		    DR_ENCRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desupdate(ctx, plaintext, ciphertext, req,
		    DR_ENCRYPT | DR_TRIPLE);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "dca_encrypt_update: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_encrypt_update: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_encrypt_final(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_encrypt_final: started");

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desfinal(ctx, ciphertext, DR_ENCRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desfinal(ctx, ciphertext, DR_ENCRYPT | DR_TRIPLE);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "dca_encrypt_final: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_encrypt_final: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_encrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *plaintext, crypto_data_t *ciphertext,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc = (dca_t *)provider;

	DBG(softc, DENTRY, "dca_encrypt_atomic: started");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* handle inplace ops */
	if (!ciphertext) {
		ciphertext = plaintext;
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desatomic(provider, session_id, mechanism, key,
		    plaintext, ciphertext, KM_SLEEP, req,
		    DR_ENCRYPT | DR_ATOMIC);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desatomic(provider, session_id, mechanism, key,
		    plaintext, ciphertext, KM_SLEEP, req,
		    DR_ENCRYPT | DR_TRIPLE | DR_ATOMIC);
		break;
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsaatomic(provider, session_id, mechanism, key,
		    plaintext, ciphertext, KM_SLEEP, req, DCA_RSA_ENC);
		break;
	default:
		cmn_err(CE_WARN, "dca_encrypt_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	if ((error != CRYPTO_QUEUED) && (error != CRYPTO_SUCCESS)) {
		ciphertext->cd_length = 0;
	}

	DBG(softc, DENTRY, "dca_encrypt_atomic: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_decrypt_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_decrypt_init: started");

	/* check mechanism */
	switch (mechanism->cm_type) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desctxinit(ctx, mechanism, key, KM_SLEEP,
		    DR_DECRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desctxinit(ctx, mechanism, key, KM_SLEEP,
		    DR_DECRYPT | DR_TRIPLE);
		break;
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsainit(ctx, mechanism, key, KM_SLEEP);
		break;
	default:
		cmn_err(CE_WARN, "dca_decrypt_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_decrypt_init: done, err = 0x%x", error);

	if (error == CRYPTO_SUCCESS)
		dca_enlist2(&softc->dca_ctx_list, ctx->cc_provider_private,
		    &softc->dca_ctx_list_lock);

	return (error);
}

/* ARGSUSED */
static int
dca_decrypt(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_decrypt: started");

	/* handle inplace ops */
	if (!plaintext) {
		dca_request_t *reqp = ctx->cc_provider_private;
		reqp->dr_flags |= DR_INPLACE;
		plaintext = ciphertext;
	}

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3des(ctx, ciphertext, plaintext, req, DR_DECRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3des(ctx, ciphertext, plaintext, req,
		    DR_DECRYPT | DR_TRIPLE);
		break;
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsastart(ctx, ciphertext, plaintext, req,
		    DCA_RSA_DEC);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "dca_decrypt: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	if ((error != CRYPTO_QUEUED) && (error != CRYPTO_SUCCESS) &&
	    (error != CRYPTO_BUFFER_TOO_SMALL)) {
		if (plaintext)
			plaintext->cd_length = 0;
	}

	DBG(softc, DENTRY, "dca_decrypt: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_decrypt_update(crypto_ctx_t *ctx, crypto_data_t *ciphertext,
    crypto_data_t *plaintext, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_decrypt_update: started");

	/* handle inplace ops */
	if (!plaintext) {
		dca_request_t *reqp = ctx->cc_provider_private;
		reqp->dr_flags |= DR_INPLACE;
		plaintext = ciphertext;
	}

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desupdate(ctx, ciphertext, plaintext, req,
		    DR_DECRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desupdate(ctx, ciphertext, plaintext, req,
		    DR_DECRYPT | DR_TRIPLE);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "dca_decrypt_update: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_decrypt_update: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_decrypt_final(crypto_ctx_t *ctx, crypto_data_t *plaintext,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_decrypt_final: started");

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desfinal(ctx, plaintext, DR_DECRYPT);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desfinal(ctx, plaintext, DR_DECRYPT | DR_TRIPLE);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "dca_decrypt_final: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_decrypt_final: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_decrypt_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *ciphertext, crypto_data_t *plaintext,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc = (dca_t *)provider;

	DBG(softc, DENTRY, "dca_decrypt_atomic: started");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* handle inplace ops */
	if (!plaintext) {
		plaintext = ciphertext;
	}

	/* check mechanism */
	switch (mechanism->cm_type) {
	case DES_CBC_MECH_INFO_TYPE:
		error = dca_3desatomic(provider, session_id, mechanism, key,
		    ciphertext, plaintext, KM_SLEEP, req,
		    DR_DECRYPT | DR_ATOMIC);
		break;
	case DES3_CBC_MECH_INFO_TYPE:
		error = dca_3desatomic(provider, session_id, mechanism, key,
		    ciphertext, plaintext, KM_SLEEP, req,
		    DR_DECRYPT | DR_TRIPLE | DR_ATOMIC);
		break;
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsaatomic(provider, session_id, mechanism, key,
		    ciphertext, plaintext, KM_SLEEP, req, DCA_RSA_DEC);
		break;
	default:
		cmn_err(CE_WARN, "dca_decrypt_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	if ((error != CRYPTO_QUEUED) && (error != CRYPTO_SUCCESS)) {
		plaintext->cd_length = 0;
	}

	DBG(softc, DENTRY, "dca_decrypt_atomic: done, err = 0x%x", error);

	return (error);
}

/*
 * Sign entry points.
 */

/* ARGSUSED */
static int
dca_sign_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_sign_init: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsainit(ctx, mechanism, key, KM_SLEEP);
		break;
	case DSA_MECH_INFO_TYPE:
		error = dca_dsainit(ctx, mechanism, key, KM_SLEEP,
		    DCA_DSA_SIGN);
		break;
	default:
		cmn_err(CE_WARN, "dca_sign_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_sign_init: done, err = 0x%x", error);

	if (error == CRYPTO_SUCCESS)
		dca_enlist2(&softc->dca_ctx_list, ctx->cc_provider_private,
		    &softc->dca_ctx_list_lock);

	return (error);
}

static int
dca_sign(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_sign: started\n");

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsastart(ctx, data, signature, req, DCA_RSA_SIGN);
		break;
	case DSA_MECH_INFO_TYPE:
		error = dca_dsa_sign(ctx, data, signature, req);
		break;
	default:
		cmn_err(CE_WARN, "dca_sign: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_sign: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_sign_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int error = CRYPTO_MECHANISM_INVALID;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_sign_update: started\n");

	cmn_err(CE_WARN, "dca_sign_update: unexpected mech type "
	    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));

	DBG(softc, DENTRY, "dca_sign_update: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_sign_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int error = CRYPTO_MECHANISM_INVALID;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_sign_final: started\n");

	cmn_err(CE_WARN, "dca_sign_final: unexpected mech type "
	    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));

	DBG(softc, DENTRY, "dca_sign_final: done, err = 0x%x", error);

	return (error);
}

static int
dca_sign_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc = (dca_t *)provider;

	DBG(softc, DENTRY, "dca_sign_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsaatomic(provider, session_id, mechanism, key,
		    data, signature, KM_SLEEP, req, DCA_RSA_SIGN);
		break;
	case DSA_MECH_INFO_TYPE:
		error = dca_dsaatomic(provider, session_id, mechanism, key,
		    data, signature, KM_SLEEP, req, DCA_DSA_SIGN);
		break;
	default:
		cmn_err(CE_WARN, "dca_sign_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_sign_atomic: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_sign_recover_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_sign_recover_init: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsainit(ctx, mechanism, key, KM_SLEEP);
		break;
	default:
		cmn_err(CE_WARN, "dca_sign_recover_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_sign_recover_init: done, err = 0x%x", error);

	if (error == CRYPTO_SUCCESS)
		dca_enlist2(&softc->dca_ctx_list, ctx->cc_provider_private,
		    &softc->dca_ctx_list_lock);

	return (error);
}

static int
dca_sign_recover(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_data_t *signature, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_sign_recover: started\n");

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsastart(ctx, data, signature, req, DCA_RSA_SIGNR);
		break;
	default:
		cmn_err(CE_WARN, "dca_sign_recover: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_sign_recover: done, err = 0x%x", error);

	return (error);
}

static int
dca_sign_recover_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc = (dca_t *)provider;

	DBG(softc, DENTRY, "dca_sign_recover_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsaatomic(provider, session_id, mechanism, key,
		    data, signature, KM_SLEEP, req, DCA_RSA_SIGNR);
		break;
	default:
		cmn_err(CE_WARN, "dca_sign_recover_atomic: unexpected mech type"
		    " 0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_sign_recover_atomic: done, err = 0x%x", error);

	return (error);
}

/*
 * Verify entry points.
 */

/* ARGSUSED */
static int
dca_verify_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_verify_init: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsainit(ctx, mechanism, key, KM_SLEEP);
		break;
	case DSA_MECH_INFO_TYPE:
		error = dca_dsainit(ctx, mechanism, key, KM_SLEEP,
		    DCA_DSA_VRFY);
		break;
	default:
		cmn_err(CE_WARN, "dca_verify_init: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_verify_init: done, err = 0x%x", error);

	if (error == CRYPTO_SUCCESS)
		dca_enlist2(&softc->dca_ctx_list, ctx->cc_provider_private,
		    &softc->dca_ctx_list_lock);

	return (error);
}

static int
dca_verify(crypto_ctx_t *ctx, crypto_data_t *data, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_verify: started\n");

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsastart(ctx, signature, data, req, DCA_RSA_VRFY);
		break;
	case DSA_MECH_INFO_TYPE:
		error = dca_dsa_verify(ctx, data, signature, req);
		break;
	default:
		cmn_err(CE_WARN, "dca_verify: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_verify: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_verify_update(crypto_ctx_t *ctx, crypto_data_t *data,
    crypto_req_handle_t req)
{
	int error = CRYPTO_MECHANISM_INVALID;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_verify_update: started\n");

	cmn_err(CE_WARN, "dca_verify_update: unexpected mech type "
	    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));

	DBG(softc, DENTRY, "dca_verify_update: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_verify_final(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_req_handle_t req)
{
	int error = CRYPTO_MECHANISM_INVALID;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_verify_final: started\n");

	cmn_err(CE_WARN, "dca_verify_final: unexpected mech type "
	    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));

	DBG(softc, DENTRY, "dca_verify_final: done, err = 0x%x", error);

	return (error);
}

static int
dca_verify_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc = (dca_t *)provider;

	DBG(softc, DENTRY, "dca_verify_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsaatomic(provider, session_id, mechanism, key,
		    signature, data, KM_SLEEP, req, DCA_RSA_VRFY);
		break;
	case DSA_MECH_INFO_TYPE:
		error = dca_dsaatomic(provider, session_id, mechanism, key,
		    data, signature, KM_SLEEP, req, DCA_DSA_VRFY);
		break;
	default:
		cmn_err(CE_WARN, "dca_verify_atomic: unexpected mech type "
		    "0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY, "dca_verify_atomic: done, err = 0x%x", error);

	return (error);
}

/* ARGSUSED */
static int
dca_verify_recover_init(crypto_ctx_t *ctx, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_spi_ctx_template_t ctx_template,
    crypto_req_handle_t req)
{
	int error = CRYPTO_MECHANISM_INVALID;
	dca_t *softc;

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_verify_recover_init: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsainit(ctx, mechanism, key, KM_SLEEP);
		break;
	default:
		cmn_err(CE_WARN, "dca_verify_recover_init: unexpected mech type"
		    " 0x%llx\n", (unsigned long long)mechanism->cm_type);
	}

	DBG(softc, DENTRY, "dca_verify_recover_init: done, err = 0x%x", error);

	if (error == CRYPTO_SUCCESS)
		dca_enlist2(&softc->dca_ctx_list, ctx->cc_provider_private,
		    &softc->dca_ctx_list_lock);

	return (error);
}

static int
dca_verify_recover(crypto_ctx_t *ctx, crypto_data_t *signature,
    crypto_data_t *data, crypto_req_handle_t req)
{
	int error = CRYPTO_MECHANISM_INVALID;
	dca_t *softc;

	if (!ctx || !ctx->cc_provider || !ctx->cc_provider_private)
		return (CRYPTO_OPERATION_NOT_INITIALIZED);

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_verify_recover: started\n");

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsastart(ctx, signature, data, req, DCA_RSA_VRFYR);
		break;
	default:
		cmn_err(CE_WARN, "dca_verify_recover: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
	}

	DBG(softc, DENTRY, "dca_verify_recover: done, err = 0x%x", error);

	return (error);
}

static int
dca_verify_recover_atomic(crypto_provider_handle_t provider,
    crypto_session_id_t session_id, crypto_mechanism_t *mechanism,
    crypto_key_t *key, crypto_data_t *data, crypto_data_t *signature,
    crypto_spi_ctx_template_t ctx_template, crypto_req_handle_t req)
{
	int error = CRYPTO_MECHANISM_INVALID;
	dca_t *softc = (dca_t *)provider;

	DBG(softc, DENTRY, "dca_verify_recover_atomic: started\n");

	if (ctx_template != NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	/* check mechanism */
	switch (mechanism->cm_type) {
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		error = dca_rsaatomic(provider, session_id, mechanism, key,
		    signature, data, KM_SLEEP, req, DCA_RSA_VRFYR);
		break;
	default:
		cmn_err(CE_WARN, "dca_verify_recover_atomic: unexpected mech "
		    "type 0x%llx\n", (unsigned long long)mechanism->cm_type);
		error = CRYPTO_MECHANISM_INVALID;
	}

	DBG(softc, DENTRY,
	    "dca_verify_recover_atomic: done, err = 0x%x", error);

	return (error);
}

/*
 * Random number entry points.
 */

/* ARGSUSED */
static int
dca_generate_random(crypto_provider_handle_t provider,
    crypto_session_id_t session_id,
    uchar_t *buf, size_t len, crypto_req_handle_t req)
{
	int error = CRYPTO_FAILED;
	dca_t *softc = (dca_t *)provider;

	DBG(softc, DENTRY, "dca_generate_random: started");

	error = dca_rng(softc, buf, len, req);

	DBG(softc, DENTRY, "dca_generate_random: done, err = 0x%x", error);

	return (error);
}

/*
 * Context management entry points.
 */

int
dca_free_context(crypto_ctx_t *ctx)
{
	int error = CRYPTO_SUCCESS;
	dca_t *softc;

	softc = DCA_SOFTC_FROM_CTX(ctx);
	DBG(softc, DENTRY, "dca_free_context: entered");

	if (ctx->cc_provider_private == NULL)
		return (error);

	dca_rmlist2(ctx->cc_provider_private, &softc->dca_ctx_list_lock);

	error = dca_free_context_low(ctx);

	DBG(softc, DENTRY, "dca_free_context: done, err = 0x%x", error);

	return (error);
}

static int
dca_free_context_low(crypto_ctx_t *ctx)
{
	int error = CRYPTO_SUCCESS;

	/* check mechanism */
	switch (DCA_MECH_FROM_CTX(ctx)) {
	case DES_CBC_MECH_INFO_TYPE:
	case DES3_CBC_MECH_INFO_TYPE:
		dca_3desctxfree(ctx);
		break;
	case RSA_PKCS_MECH_INFO_TYPE:
	case RSA_X_509_MECH_INFO_TYPE:
		dca_rsactxfree(ctx);
		break;
	case DSA_MECH_INFO_TYPE:
		dca_dsactxfree(ctx);
		break;
	default:
		/* Should never reach here */
		cmn_err(CE_WARN, "dca_free_context_low: unexpected mech type "
		    "0x%llx\n", (unsigned long long)DCA_MECH_FROM_CTX(ctx));
		error = CRYPTO_MECHANISM_INVALID;
	}

	return (error);
}


/* Free any unfreed private context. It is called in detach. */
static void
dca_free_context_list(dca_t *dca)
{
	dca_listnode_t	*node;
	crypto_ctx_t	ctx;

	(void) memset(&ctx, 0, sizeof (ctx));
	ctx.cc_provider = dca;

	while ((node = dca_delist2(&dca->dca_ctx_list,
	    &dca->dca_ctx_list_lock)) != NULL) {
		ctx.cc_provider_private = node;
		(void) dca_free_context_low(&ctx);
	}
}

static int
ext_info_sym(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info, crypto_req_handle_t cfreq)
{
	return (ext_info_base(prov, ext_info, cfreq, IDENT_SYM));
}

static int
ext_info_asym(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info, crypto_req_handle_t cfreq)
{
	int rv;

	rv = ext_info_base(prov, ext_info, cfreq, IDENT_ASYM);
	/* The asymmetric cipher slot supports random */
	ext_info->ei_flags |= CRYPTO_EXTF_RNG;

	return (rv);
}

/* ARGSUSED */
static int
ext_info_base(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info, crypto_req_handle_t cfreq, char *id)
{
	dca_t   *dca = (dca_t *)prov;
	int len;

	/* Label */
	(void) sprintf((char *)ext_info->ei_label, "%s/%d %s",
	    ddi_driver_name(dca->dca_dip), ddi_get_instance(dca->dca_dip), id);
	len = strlen((char *)ext_info->ei_label);
	(void) memset(ext_info->ei_label + len, ' ',
	    CRYPTO_EXT_SIZE_LABEL - len);

	/* Manufacturer ID */
	(void) sprintf((char *)ext_info->ei_manufacturerID, "%s",
	    DCA_MANUFACTURER_ID);
	len = strlen((char *)ext_info->ei_manufacturerID);
	(void) memset(ext_info->ei_manufacturerID + len, ' ',
	    CRYPTO_EXT_SIZE_MANUF - len);

	/* Model */
	(void) sprintf((char *)ext_info->ei_model, dca->dca_model);

	DBG(dca, DWARN, "kCF MODEL: %s", (char *)ext_info->ei_model);

	len = strlen((char *)ext_info->ei_model);
	(void) memset(ext_info->ei_model + len, ' ',
	    CRYPTO_EXT_SIZE_MODEL - len);

	/* Serial Number. Blank for Deimos */
	(void) memset(ext_info->ei_serial_number, ' ', CRYPTO_EXT_SIZE_SERIAL);

	ext_info->ei_flags = CRYPTO_EXTF_WRITE_PROTECTED;

	ext_info->ei_max_session_count = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_max_pin_len = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_min_pin_len = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_total_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_total_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_hardware_version.cv_major = 0;
	ext_info->ei_hardware_version.cv_minor = 0;
	ext_info->ei_firmware_version.cv_major = 0;
	ext_info->ei_firmware_version.cv_minor = 0;

	/* Time. No need to be supplied for token without a clock */
	ext_info->ei_time[0] = '\000';

	return (CRYPTO_SUCCESS);
}

static void
dca_fma_init(dca_t *dca)
{
	ddi_iblock_cookie_t fm_ibc;
	int fm_capabilities = DDI_FM_EREPORT_CAPABLE |
	    DDI_FM_ACCCHK_CAPABLE | DDI_FM_DMACHK_CAPABLE |
	    DDI_FM_ERRCB_CAPABLE;

	/* Read FMA capabilities from dca.conf file (if present) */
	dca->fm_capabilities = ddi_getprop(DDI_DEV_T_ANY, dca->dca_dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
	    fm_capabilities);

	DBG(dca, DWARN, "dca->fm_capabilities = 0x%x", dca->fm_capabilities);

	/* Only register with IO Fault Services if we have some capability */
	if (dca->fm_capabilities) {
		dca_regsattr.devacc_attr_access = DDI_FLAGERR_ACC;
		dca_dmaattr.dma_attr_flags = DDI_DMA_FLAGERR;

		/* Register capabilities with IO Fault Services */
		ddi_fm_init(dca->dca_dip, &dca->fm_capabilities, &fm_ibc);
		DBG(dca, DWARN, "fm_capable() =  0x%x",
		    ddi_fm_capable(dca->dca_dip));

		/*
		 * Initialize pci ereport capabilities if ereport capable
		 */
		if (DDI_FM_EREPORT_CAP(dca->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(dca->fm_capabilities))
			pci_ereport_setup(dca->dca_dip);

		/*
		 * Initialize callback mutex and register error callback if
		 * error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(dca->fm_capabilities)) {
			ddi_fm_handler_register(dca->dca_dip, dca_fm_error_cb,
			    (void *)dca);
		}
	} else {
		/*
		 * These fields have to be cleared of FMA if there are no
		 * FMA capabilities at runtime.
		 */
		dca_regsattr.devacc_attr_access = DDI_DEFAULT_ACC;
		dca_dmaattr.dma_attr_flags = 0;
	}
}


static void
dca_fma_fini(dca_t *dca)
{
	/* Only unregister FMA capabilities if we registered some */
	if (dca->fm_capabilities) {

		/*
		 * Release any resources allocated by pci_ereport_setup()
		 */
		if (DDI_FM_EREPORT_CAP(dca->fm_capabilities) ||
		    DDI_FM_ERRCB_CAP(dca->fm_capabilities)) {
			pci_ereport_teardown(dca->dca_dip);
		}

		/*
		 * Free callback mutex and un-register error callback if
		 * error callback capable.
		 */
		if (DDI_FM_ERRCB_CAP(dca->fm_capabilities)) {
			ddi_fm_handler_unregister(dca->dca_dip);
		}

		/* Unregister from IO Fault Services */
		ddi_fm_fini(dca->dca_dip);
		DBG(dca, DWARN, "fm_capable() = 0x%x",
		    ddi_fm_capable(dca->dca_dip));
	}
}


/*
 * The IO fault service error handling callback function
 */
/*ARGSUSED*/
static int
dca_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	dca_t		*dca = (dca_t *)impl_data;

	pci_ereport_post(dip, err, NULL);
	if (err->fme_status == DDI_FM_FATAL) {
		dca_failure(dca, DDI_DATAPATH_FAULT,
		    DCA_FM_ECLASS_NONE, dca_ena(0), CRYPTO_DEVICE_ERROR,
		    "fault PCI in FMA callback.");
	}
	return (err->fme_status);
}


static int
dca_check_acc_handle(dca_t *dca, ddi_acc_handle_t handle,
    dca_fma_eclass_t eclass_index)
{
	ddi_fm_error_t	de;
	int		version = 0;

	ddi_fm_acc_err_get(handle, &de, version);
	if (de.fme_status != DDI_FM_OK) {
		dca_failure(dca, DDI_DATAPATH_FAULT,
		    eclass_index, fm_ena_increment(de.fme_ena),
		    CRYPTO_DEVICE_ERROR, "");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

int
dca_check_dma_handle(dca_t *dca, ddi_dma_handle_t handle,
    dca_fma_eclass_t eclass_index)
{
	ddi_fm_error_t	de;
	int		version = 0;

	ddi_fm_dma_err_get(handle, &de, version);
	if (de.fme_status != DDI_FM_OK) {
		dca_failure(dca, DDI_DATAPATH_FAULT,
		    eclass_index, fm_ena_increment(de.fme_ena),
		    CRYPTO_DEVICE_ERROR, "");
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static uint64_t
dca_ena(uint64_t ena)
{
	if (ena == 0)
		ena = fm_ena_generate(0, FM_ENA_FMT1);
	else
		ena = fm_ena_increment(ena);
	return (ena);
}

static char *
dca_fma_eclass_string(char *model, dca_fma_eclass_t index)
{
	if (strstr(model, "500"))
		return (dca_fma_eclass_sca500[index]);
	else
		return (dca_fma_eclass_sca1000[index]);
}
