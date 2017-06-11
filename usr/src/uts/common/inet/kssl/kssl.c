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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * The system call and DDI interface for the kernel SSL module
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/model.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <c2/audit.h>
#include <sys/kstat.h>

#include "kssl.h"
#include "ksslimpl.h"

/*
 * DDI entry points.
 */
static int kssl_attach(dev_info_t *, ddi_attach_cmd_t);
static int kssl_detach(dev_info_t *, ddi_detach_cmd_t);
static int kssl_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int kssl_open(dev_t *, int, int, cred_t *);
static int kssl_close(dev_t, int, int, cred_t *);
static int kssl_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int kssl_constructor(void *buf, void *arg, int kmflags);
static void kssl_destructor(void *buf, void *arg);

/*
 * Module linkage.
 */
static struct cb_ops cbops = {
	kssl_open,		/* cb_open */
	kssl_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	kssl_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	kssl_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	kssl_attach,		/* devo_attach */
	kssl_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cbops,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,		/* drv_modops */
	"Kernel SSL Interface",	/* drv_linkinfo */
	&devops,
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modldrv,		/* ml_linkage */
	NULL
};

static dev_info_t *kssl_dip = NULL;

crypto_mechanism_t rsa_x509_mech = {CRYPTO_MECH_INVALID, NULL, 0};
crypto_mechanism_t hmac_md5_mech = {CRYPTO_MECH_INVALID, NULL, 0};
crypto_mechanism_t hmac_sha1_mech = {CRYPTO_MECH_INVALID, NULL, 0};
crypto_call_flag_t kssl_call_flag = CRYPTO_ALWAYS_QUEUE;

KSSLCipherDef cipher_defs[] = { /* indexed by SSL3BulkCipher */
	/* type bsize keysz crypto_mech_type_t */

	{type_stream, 0, 0, CRYPTO_MECH_INVALID},

	/* mech_type to be initialized with CKM_RC4's */
	{type_stream, 0, 16, CRYPTO_MECH_INVALID},

	/* mech_type to be initialized with CKM_DES_CBC's */
	{type_block, 8, 8, CRYPTO_MECH_INVALID},

	/* mech_type to be initialized with CKM_DES3_CBC's */
	{type_block, 8, 24, CRYPTO_MECH_INVALID},

	/* mech_type to be initialized with CKM_AES_CBC with 128-bit key  */
	{type_block, 16, 16, CRYPTO_MECH_INVALID},

	/* mech_type to be initialized with CKM_AES_CBC with 256-bit key  */
	{type_block, 16, 32, CRYPTO_MECH_INVALID},
};

struct kmem_cache *kssl_cache;
static crypto_notify_handle_t prov_update_handle = NULL;

static void kssl_global_init();
static void kssl_global_fini();
static void kssl_init_mechs();
static void kssl_event_callback(uint32_t, void *);

/*
 * DDI entry points.
 */
int
_init(void)
{
	int error;

	kssl_global_init();

	if ((error = mod_install(&modlinkage)) != 0) {
		kssl_global_fini();
		return (error);
	}
	return (0);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);

	if (prov_update_handle != NULL)
		crypto_unnotify_events(prov_update_handle);

	kssl_global_fini();

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
kssl_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = kssl_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
kssl_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		/* we only allow instance 0 to attach */
		return (DDI_FAILURE);
	}

	/* create the minor node */
	if (ddi_create_minor_node(dip, "kssl", S_IFCHR, 0, DDI_PSEUDO, 0) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "kssl_attach: failed creating minor node");
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	kssl_dip = dip;

	return (DDI_SUCCESS);
}

static kstat_t *kssl_ksp = NULL;

static int
kssl_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (kssl_entry_tab_nentries != 0)
		return (DDI_FAILURE);

	kssl_dip = NULL;

	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
kssl_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR)
		return (ENXIO);

	if (kssl_dip == NULL)
		return (ENXIO);

	/* first time here? initialize everything */
	if (rsa_x509_mech.cm_type == CRYPTO_MECH_INVALID) {
		kssl_init_mechs();
		prov_update_handle = crypto_notify_events(
		    kssl_event_callback, CRYPTO_EVENT_MECHS_CHANGED);
	}

	/* exclusive opens are not supported */
	if (flag & FEXCL)
		return (ENOTSUP);

	return (0);
}

/* ARGSUSED */
static int
kssl_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

#define	KSSL_MAX_KEYANDCERTS	80000	/* max 64K plus a little margin */

/* ARGSUSED */
static int
kssl_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *c,
    int *rval)
{
	int error = EINVAL;
	uint32_t auditing = AU_AUDITING();

#define	ARG	((caddr_t)arg)

	if (secpolicy_net_config(c, B_FALSE) != 0) {
		return (EPERM);
	}

	switch (cmd) {
	case KSSL_ADD_ENTRY: {
		uint64_t len;
		uint32_t ck_rv;
		size_t off;
		kssl_params_t *kssl_params;

		off = offsetof(kssl_params_t, kssl_params_size);
		if (copyin(ARG + off, &len, sizeof (len)) != 0) {
			return (EFAULT);
		}

		if (len < sizeof (kssl_params_t) ||
		    len > KSSL_MAX_KEYANDCERTS) {
			return (EINVAL);
		}

		kssl_params = kmem_alloc(len, KM_SLEEP);

		/* Get the whole structure and parameters in one move */
		if (copyin(ARG, kssl_params, len) != 0) {
			kmem_free(kssl_params, len);
			return (EFAULT);
		}
		error = kssl_add_entry(kssl_params);
		if (auditing)
			audit_kssl(KSSL_ADD_ENTRY, kssl_params, error);
		off = offsetof(kssl_params_t, kssl_token) +
		    offsetof(kssl_tokinfo_t, ck_rv);
		ck_rv = kssl_params->kssl_token.ck_rv;
		if (copyout(&ck_rv, ARG + off, sizeof (ck_rv)) != 0) {
			error = EFAULT;
		}

		bzero(kssl_params, len);
		kmem_free(kssl_params, len);
		break;
	}
	case KSSL_DELETE_ENTRY: {
		struct sockaddr_in6 server_addr;

		if (copyin(ARG, &server_addr, sizeof (server_addr)) != 0) {
			return (EFAULT);
		}

		error = kssl_delete_entry(&server_addr);
		if (auditing)
			audit_kssl(KSSL_DELETE_ENTRY, &server_addr, error);
		break;
	}
	}

	return (error);
}

#define	NUM_MECHS	7
static mech_to_cipher_t mech_to_cipher_tab[NUM_MECHS] = {
	{CRYPTO_MECH_INVALID, SUN_CKM_RSA_X_509,
	    {SSL_RSA_WITH_RC4_128_MD5, SSL_RSA_WITH_RC4_128_SHA,
	    SSL_RSA_WITH_DES_CBC_SHA, SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	    TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA,
	    SSL_RSA_WITH_NULL_SHA}},
	{CRYPTO_MECH_INVALID, SUN_CKM_MD5_HMAC, {SSL_RSA_WITH_RC4_128_MD5}},
	{CRYPTO_MECH_INVALID, SUN_CKM_SHA1_HMAC,
	    {SSL_RSA_WITH_RC4_128_SHA, SSL_RSA_WITH_DES_CBC_SHA,
	    SSL_RSA_WITH_3DES_EDE_CBC_SHA, SSL_RSA_WITH_NULL_SHA,
	    TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA}},
	{CRYPTO_MECH_INVALID, SUN_CKM_RC4,
	    {SSL_RSA_WITH_RC4_128_MD5, SSL_RSA_WITH_RC4_128_SHA}},
	{CRYPTO_MECH_INVALID, SUN_CKM_DES_CBC, {SSL_RSA_WITH_DES_CBC_SHA}},
	{CRYPTO_MECH_INVALID, SUN_CKM_DES3_CBC,
	    {SSL_RSA_WITH_3DES_EDE_CBC_SHA}},
	{CRYPTO_MECH_INVALID, SUN_CKM_AES_CBC,
	    {TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA}},
};

static void
kssl_init_mechs()
{
	mech_to_cipher_tab[0].mech = rsa_x509_mech.cm_type =
	    crypto_mech2id(SUN_CKM_RSA_X_509);
	mech_to_cipher_tab[1].mech = hmac_md5_mech.cm_type =
	    crypto_mech2id(SUN_CKM_MD5_HMAC);
	mech_to_cipher_tab[2].mech = hmac_sha1_mech.cm_type =
	    crypto_mech2id(SUN_CKM_SHA1_HMAC);

	mech_to_cipher_tab[3].mech = cipher_defs[cipher_rc4].mech_type =
	    crypto_mech2id(SUN_CKM_RC4);
	mech_to_cipher_tab[4].mech = cipher_defs[cipher_des].mech_type =
	    crypto_mech2id(SUN_CKM_DES_CBC);
	mech_to_cipher_tab[5].mech = cipher_defs[cipher_3des].mech_type =
	    crypto_mech2id(SUN_CKM_DES3_CBC);
	mech_to_cipher_tab[6].mech = cipher_defs[cipher_aes128].mech_type =
	    cipher_defs[cipher_aes256].mech_type =
	    crypto_mech2id(SUN_CKM_AES_CBC);
}

static int
is_in_suites(uint16_t s, uint16_t *sarray)
{
	int i;

	for (i = 0; i < CIPHER_SUITE_COUNT; i++) {
		if (s == sarray[i])
			return (1);
	}

	return (0);
}

static int
is_in_mechlist(char *name, crypto_mech_name_t *mechs, int count)
{
	int i;

	for (i = 0; i < count; i++) {
		if (strncmp(name, mechs[i], CRYPTO_MAX_MECH_NAME) == 0)
			return (1);
	}

	return (0);
}

/*
 * Callback function invoked by the crypto framework when a provider's
 * mechanism is available/unavailable. This callback updates entries in the
 * kssl_entry_tab[] to make changes to the cipher suites of an entry
 * which are affected by the mechanism.
 */
static void
kssl_event_callback(uint32_t event, void *event_arg)
{
	int i, j;
	int cnt, rcnt;
	uint16_t s;
	boolean_t changed;
	crypto_mech_name_t *mechs;
	uint_t mech_count;
	mech_to_cipher_t *mc;
	kssl_entry_t *old;
	kssl_entry_t *new;
	uint16_t tmp_suites[CIPHER_SUITE_COUNT];
	uint16_t dis_list[CIPHER_SUITE_COUNT];
	crypto_notify_event_change_t *prov_change =
	    (crypto_notify_event_change_t *)event_arg;

	/* ignore events for which we didn't register */
	if (event != CRYPTO_EVENT_MECHS_CHANGED) {
		return;
	}

	for (i = 0; i < NUM_MECHS; i++) {
		mc = &(mech_to_cipher_tab[i]);
		if (mc->mech == CRYPTO_MECH_INVALID)
			continue;

		/*
		 * Check if this crypto framework provider mechanism being
		 * added or removed affects us.
		 */
		if (strncmp(mc->name, prov_change->ec_mech_name,
		    CRYPTO_MAX_MECH_NAME) == 0)
			break;
	}

	if (i == NUM_MECHS)
		return;

	mechs = crypto_get_mech_list(&mech_count, KM_SLEEP);
	if (mechs == NULL)
		return;

	mutex_enter(&kssl_tab_mutex);

	for (i = 0; i < kssl_entry_tab_size; i++) {
		if ((old = kssl_entry_tab[i]) == NULL)
			continue;

		cnt = 0;
		rcnt = 0;
		changed = B_FALSE;
		for (j = 0; j < CIPHER_SUITE_COUNT; j++) {
			tmp_suites[j] = CIPHER_NOTSET;
			dis_list[j] = CIPHER_NOTSET;
		}

		/*
		 * We start with the saved cipher suite list for the new entry.
		 * If a mechanism is disabled, resulting in a cipher suite being
		 * disabled now, we take it out from the list for the new entry.
		 * If a mechanism is enabled, resulting in a cipher suite being
		 * enabled now, we don't need to do any thing.
		 */
		if (!is_in_mechlist(mc->name, mechs, mech_count)) {
			for (j = 0; j < CIPHER_SUITE_COUNT; j++) {
				s = mc->kssl_suites[j];
				if (s == 0)
					break;
				if (is_in_suites(s, old->kssl_saved_Suites)) {
					/* Disable this cipher suite */
					if (!is_in_suites(s, dis_list))
						dis_list[cnt++] = s;
				}
			}
		}

		for (j = 0; j < CIPHER_SUITE_COUNT; j++) {
			s = old->kssl_saved_Suites[j];
			if (!is_in_suites(s, dis_list))
				tmp_suites[rcnt] = s;

			if (!changed &&
			    (tmp_suites[rcnt] != old->kssl_cipherSuites[rcnt]))
				changed = B_TRUE;
			rcnt++;
		}

		if (changed) {
			new = kmem_zalloc(sizeof (kssl_entry_t), KM_NOSLEEP);
			if (new == NULL)
				continue;

			*new = *old;		/* Structure copy */
			old->ke_no_freeall = B_TRUE;
			new->ke_refcnt = 0;
			new->kssl_cipherSuites_nentries = rcnt;
			for (j = 0; j < CIPHER_SUITE_COUNT; j++)
				new->kssl_cipherSuites[j] = tmp_suites[j];

			KSSL_ENTRY_REFHOLD(new);
			kssl_entry_tab[i] = new;
			KSSL_ENTRY_REFRELE(old);
		}
	}

	mutex_exit(&kssl_tab_mutex);
	crypto_free_mech_list(mechs, mech_count);
}


kssl_stats_t *kssl_statp;

static void
kssl_global_init()
{
	mutex_init(&kssl_tab_mutex, NULL, MUTEX_DRIVER, NULL);

	kssl_cache = kmem_cache_create("kssl_cache", sizeof (ssl_t),
	    0, kssl_constructor, kssl_destructor, NULL, NULL, NULL, 0);

	if ((kssl_ksp = kstat_create("kssl", 0, "kssl_stats", "crypto",
	    KSTAT_TYPE_NAMED, sizeof (kssl_stats_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT)) != NULL) {
		kssl_statp = kssl_ksp->ks_data;

		kstat_named_init(&kssl_statp->sid_cache_lookups,
		    "kssl_sid_cache_lookups", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->sid_cache_hits,
		    "kssl_sid_cache_hits", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->sid_cached,
		    "kssl_sid_cached", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->sid_uncached,
		    "kssl_sid_uncached", KSTAT_DATA_UINT64);

		kstat_named_init(&kssl_statp->full_handshakes,
		    "kssl_full_handshakes", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->resumed_sessions,
		    "kssl_resumed_sessions", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->fallback_connections,
		    "kssl_fallback_connections", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->proxy_fallback_failed,
		    "kssl_proxy_fallback_failed", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->appdata_record_ins,
		    "kssl_appdata_record_ins", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->appdata_record_outs,
		    "kssl_appdata_record_outs", KSTAT_DATA_UINT64);

		kstat_named_init(&kssl_statp->alloc_fails, "kssl_alloc_fails",
		    KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->fatal_alerts,
		    "kssl_fatal_alerts", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->warning_alerts,
		    "kssl_warning_alerts", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->no_suite_found,
		    "kssl_no_suite_found", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->compute_mac_failure,
		    "kssl_compute_mac_failure", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->verify_mac_failure,
		    "kssl_verify_mac_failure", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->record_decrypt_failure,
		    "kssl_record_decrypt_failure", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->bad_pre_master_secret,
		    "kssl_bad_pre_master_secret", KSTAT_DATA_UINT64);
		kstat_named_init(&kssl_statp->internal_errors,
		    "kssl_internal_errors", KSTAT_DATA_UINT64);

		kstat_install(kssl_ksp);
	};
}

static void
kssl_global_fini(void)
{
	mutex_destroy(&kssl_tab_mutex);

	if (kssl_cache != NULL) {
		kmem_cache_destroy(kssl_cache);
		kssl_cache = NULL;
	}

	if (kssl_ksp != NULL) {
		kstat_delete(kssl_ksp);
		kssl_ksp = NULL;
	}
}

/*ARGSUSED*/
static int
kssl_constructor(void *buf, void *arg, int kmflags)
{
	ssl_t *ssl = buf;

	mutex_init(&ssl->kssl_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ssl->async_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
kssl_destructor(void *buf, void *arg)
{
	ssl_t *ssl = buf;
	mutex_destroy(&ssl->kssl_lock);
	cv_destroy(&ssl->async_cv);
}

/*
 * Handler routine called by the crypto framework when a
 * provider is unregistered or registered. We invalidate the
 * private key handle if our provider is unregistered. We set
 * a flag to reauthenticate if our provider came back.
 */
void
kssl_prov_evnt(uint32_t event, void *event_arg)
{
	int i, rv;
	kssl_entry_t *ep;
	kssl_session_info_t *s;
	crypto_provider_t prov;
	crypto_provider_ext_info_t info;

	if (event != CRYPTO_EVENT_PROVIDER_UNREGISTERED &&
	    event != CRYPTO_EVENT_PROVIDER_REGISTERED)
		return;

	prov = (crypto_provider_t)event_arg;
	if (event == CRYPTO_EVENT_PROVIDER_REGISTERED) {
		rv = crypto_get_provinfo(prov, &info);
		if (rv != CRYPTO_SUCCESS)
			return;
	}

	mutex_enter(&kssl_tab_mutex);

	for (i = 0; i < kssl_entry_tab_size; i++) {
		if ((ep = kssl_entry_tab[i]) == NULL)
			continue;

		s = ep->ke_sessinfo;
		DTRACE_PROBE1(kssl_entry_cycle, kssl_entry_t *, ep);
		switch (event) {
		case CRYPTO_EVENT_PROVIDER_UNREGISTERED:
			if (s->is_valid_handle && s->prov == prov) {
				s->is_valid_handle = B_FALSE;
				crypto_release_provider(s->prov);
			}
			break;

		case CRYPTO_EVENT_PROVIDER_REGISTERED:
			if (s->is_valid_handle)
				break;
			if (bcmp(s->toklabel, info.ei_label,
			    CRYPTO_EXT_SIZE_LABEL) == 0) {
				s->do_reauth = B_TRUE;
			}
			break;
		}
	}

	mutex_exit(&kssl_tab_mutex);
}
