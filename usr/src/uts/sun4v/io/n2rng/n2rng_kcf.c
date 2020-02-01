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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/uio.h>
#include <sys/stream.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/random.h>
#include <sys/crypto/common.h>
#include <sys/crypto/spi.h>
#include <sys/n2rng.h>

#define	IDENT_N2RNG		"SUNW_N2_Random_Number_Generator"

#define	N2RNG_PROVIDER2N2RNG(x)	(((n2rng_provider_private_t *)x)->mp_n2rng)


static void n2rng_provider_status(crypto_provider_handle_t, uint_t *);

static int n2rng_random_number(crypto_provider_handle_t, crypto_session_id_t,
			uchar_t *, size_t, crypto_req_handle_t);

static int ext_info(crypto_provider_handle_t, crypto_provider_ext_info_t *,
			crypto_req_handle_t);

void n2rng_ksinit(n2rng_t *n2rng);
void n2rng_ksdeinit(n2rng_t *n2rng);

static int fips_init(n2rng_t *n2rng);
static void fips_fini(n2rng_t *n2rng);
int fips_random(n2rng_t *n2rng, uint8_t *out, size_t nbytes);


static crypto_control_ops_t n2rng_control_ops = {
	n2rng_provider_status
};


static crypto_random_number_ops_t n2rng_rng_ops = {
	NULL,		/* seed_random */
	n2rng_random_number
};

static crypto_provider_management_ops_t n2rng_extinfo_op = {
	ext_info,	/* ext_info */
	NULL,		/* init_token */
	NULL,		/* init_pin */
	NULL,		/* set_pin */
};

static crypto_ops_t n2rng_ops = {
	&n2rng_control_ops,
	NULL,				/* digest_ops */
	NULL,				/* cipher_ops */
	NULL,				/* mac_ops */
	NULL,				/* sign_ops */
	NULL,				/* verify_ops */
	NULL,				/* dual_ops */
	NULL,				/* cipher_mac_ops */
	&n2rng_rng_ops,			/* rng_ops */
	NULL,				/* session_ops */
	NULL,				/* object_ops */
	NULL,				/* key_ops */
	&n2rng_extinfo_op,		/* management_ops */
	NULL,				/* ctx_ops */
	NULL				/* mech_ops */
};

static crypto_provider_info_t n2rng_prov_info = {
	CRYPTO_SPI_VERSION_2,
	NULL,				/* pi_provider_description */
	CRYPTO_HW_PROVIDER,
	NULL,				/* pi_provider_dev */
	NULL,				/* pi_provider_handle */
	&n2rng_ops,
	0,				/* number of mechanisms */
	NULL,				/* mechanism table */
	0,				/* pi_logical_provider_count */
	NULL				/* pi_logical_providers */
};

static void
strncpy_spacepad(uchar_t *s1, char *s2, int n)
{
	int s2len = strlen(s2);

	(void) strncpy((char *)s1, s2, n);
	if (s2len < n)
		(void) memset(s1 + s2len, ' ', n - s2len);
}

/*ARGSUSED*/
static int
ext_info(crypto_provider_handle_t prov, crypto_provider_ext_info_t *ext_info,
    crypto_req_handle_t cfreq)
{
#define	BUFSZ	64
	n2rng_t	*n2rng = (n2rng_t *)prov;
	char	buf[BUFSZ];

	/* handle info common to logical and hardware provider */

	/* Manufacturer ID */
	strncpy_spacepad(ext_info->ei_manufacturerID, N2RNG_MANUFACTURER_ID,
	    CRYPTO_EXT_SIZE_MANUF);

	/* Model */
	strncpy_spacepad(ext_info->ei_model, "0", CRYPTO_EXT_SIZE_MODEL);

	/* Token flags */
	ext_info->ei_flags = CRYPTO_EXTF_RNG | CRYPTO_EXTF_SO_PIN_LOCKED |
	    CRYPTO_EXTF_WRITE_PROTECTED;

	ext_info->ei_max_session_count = CRYPTO_EFFECTIVELY_INFINITE;
	ext_info->ei_max_pin_len = 0;
	ext_info->ei_min_pin_len = 0;
	ext_info->ei_total_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_total_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_private_memory = CRYPTO_UNAVAILABLE_INFO;

	/* Time. No need to be supplied for token without a clock */
	ext_info->ei_time[0] = '\000';

	/* handle hardware provider specific fields */

	/* Token label */
	(void) snprintf(buf, BUFSZ, "%s/%d SUNW_N2_RNG",
	    ddi_driver_name(n2rng->n_dip),
	    ddi_get_instance(n2rng->n_dip));

	/* Serial number */
	strncpy_spacepad(ext_info->ei_serial_number,
	    "0",
	    CRYPTO_EXT_SIZE_SERIAL);

	/* Version info */
	ext_info->ei_hardware_version.cv_major = 0;
	ext_info->ei_hardware_version.cv_minor = 0;
	ext_info->ei_firmware_version.cv_major = 0;
	ext_info->ei_firmware_version.cv_minor = 0;

	buf[BUFSZ - 1] = '\000';
	/* set the token label */
	strncpy_spacepad(ext_info->ei_label, buf, CRYPTO_EXT_SIZE_LABEL);

#undef	BUFSZ

	return (CRYPTO_SUCCESS);
}

static void
unregister_task(void *targ)
{
	n2rng_t *n2rng = (n2rng_t *)targ;

	/* Unregister provider without checking result */
	(void) n2rng_unregister_provider(n2rng);
}

/*
 * Register with KCF if not already registered
 */
int
n2rng_register_provider(n2rng_t *n2rng)
{
	int	ret;

	if (n2rng_isregistered(n2rng)) {
		DBG0(n2rng, DKCF, "n2rng_kcf: Crypto provider already "
		    "registered");
		return (DDI_SUCCESS);
	} else {
		ret = crypto_register_provider(&n2rng_prov_info,
		    &n2rng->n_prov);
		if (ret == CRYPTO_SUCCESS) {
			DBG0(n2rng, DKCF, "n2rng_kcf: Crypto provider "
			    "registered");
		} else {
			cmn_err(CE_WARN,
			    "crypto_register_provider() failed (%d)", ret);
			n2rng->n_prov = 0;
			return (DDI_FAILURE);
		}
	}
	n2rng_setregistered(n2rng);
	crypto_provider_notification(n2rng->n_prov, CRYPTO_PROVIDER_READY);

	return (DDI_SUCCESS);
}

/*
 * Unregister with KCF if not already registered
 */
int
n2rng_unregister_provider(n2rng_t *n2rng)
{
	if (!n2rng_isregistered(n2rng)) {
		DBG0(n2rng, DKCF, "n2rng_kcf: Crypto provider already "
		    "unregistered");
	} else {
		if (crypto_unregister_provider(n2rng->n_prov) ==
		    CRYPTO_SUCCESS) {
			DBG0(n2rng, DKCF, "n2rng_kcf: Crypto provider "
			    "unregistered");
		} else {
			n2rng_error(n2rng, "unable to unregister from kcf");
			return (DDI_FAILURE);
		}
	}
	n2rng->n_prov = 0;
	n2rng_clrregistered(n2rng);
	return (DDI_SUCCESS);
}


/*
 * Set state to failed for all rngs if in control domain and dispatch a task
 * to unregister from kcf
 */
void
n2rng_failure(n2rng_t *n2rng)
{
	int		rngid;
	rng_entry_t	*rng;

	mutex_enter(&n2rng->n_lock);
	/* Check if error has already been detected */
	if (n2rng_isfailed(n2rng)) {
		mutex_exit(&n2rng->n_lock);
		return;
	}

	cmn_err(CE_WARN, "n2rng: hardware failure detected");
	n2rng_setfailed(n2rng);

	/* Set each rng to failed if running in control domain */
	if (n2rng_iscontrol(n2rng)) {
		for (rngid = 0; rngid < n2rng->n_ctl_data->n_num_rngs;
		    rngid++) {
			rng = &n2rng->n_ctl_data->n_rngs[rngid];
			rng->n_rng_state = CTL_STATE_ERROR;
		}
	}
	mutex_exit(&n2rng->n_lock);

	/* Dispatch task to unregister from kcf */
	if (ddi_taskq_dispatch(n2rng->n_taskq, unregister_task,
	    (void *)n2rng, DDI_SLEEP) !=  DDI_SUCCESS) {
		cmn_err(CE_WARN, "n2rng: ddi_taskq_dispatch() failed");
	}
}

/*
 * Set state to unconfigured for all rngs if in control domain and dispatch a
 * task to unregister from kcf.
 */
void
n2rng_unconfigured(n2rng_t *n2rng)
{
	int		rngid;
	rng_entry_t	*rng;

	mutex_enter(&n2rng->n_lock);
	/* Check if unconfigured state has already been detected */
	if (!n2rng_isconfigured(n2rng)) {
		mutex_exit(&n2rng->n_lock);
		return;
	}

	cmn_err(CE_WARN, "n2rng: no longer generating entropy");
	n2rng_clrconfigured(n2rng);

	/* Set each rng to unconfigured if running in control domain */
	if (n2rng_iscontrol(n2rng)) {
		for (rngid = 0; rngid < n2rng->n_ctl_data->n_num_rngs;
		    rngid++) {
			rng = &n2rng->n_ctl_data->n_rngs[rngid];
			rng->n_rng_state = CTL_STATE_UNCONFIGURED;
		}
	}
	mutex_exit(&n2rng->n_lock);

	/* Dispatch task to unregister from kcf */
	if (ddi_taskq_dispatch(n2rng->n_taskq, unregister_task,
	    (void *)n2rng, DDI_SLEEP) !=  DDI_SUCCESS) {
		cmn_err(CE_WARN, "n2rng: ddi_taskq_dispatch() failed");
	} else {
		/* Schedule a configuration retry */
		n2rng_config_retry(n2rng, RNG_CFG_RETRY_SECS);
	}
}

/*
 * Setup and also register to kCF
 */
int
n2rng_init(n2rng_t *n2rng)
{
	int		ret;
	char		ID[64];
	dev_info_t	*dip;

	dip = n2rng->n_dip;

	/* Initialize data structures if not already done */
	if (!n2rng_isinitialized(n2rng)) {
		/* initialize kstats */
		n2rng_ksinit(n2rng);

		/* initialize the FIPS data and mutexes */
		ret = fips_init(n2rng);
		if (ret) {
			n2rng_ksdeinit(n2rng);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Register with crypto framework if not already registered.
	 * Be careful not to exceed 32 characters.
	 */
	(void) sprintf(ID, "%s/%d %s",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    IDENT_N2RNG);
	n2rng_prov_info.pi_provider_description = ID;
	n2rng_prov_info.pi_provider_dev.pd_hw = dip;
	n2rng_prov_info.pi_provider_handle = n2rng;
	n2rng_setinitialized(n2rng);
	ret = n2rng_register_provider(n2rng);
	if (ret != DDI_SUCCESS) {
		fips_fini(n2rng);
		n2rng_ksdeinit(n2rng);
		n2rng_clrinitialized(n2rng);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Unregister from kCF and cleanup
 */
int
n2rng_uninit(n2rng_t *n2rng)
{
	/* Un-initialize data structures if they exist */
	if (n2rng_isinitialized(n2rng)) {
		/*
		 * Unregister from kCF.
		 * This needs to be done at the beginning of detach.
		 */
		if (n2rng_unregister_provider(n2rng) != DDI_SUCCESS) {
			return (DDI_FAILURE);
		}

		fips_fini(n2rng);

		/* deinitialize kstats */
		n2rng_ksdeinit(n2rng);
		n2rng_clrinitialized(n2rng);
	}

	return (DDI_SUCCESS);
}

/*
 * At this time there are no periodic health checks.  If the health
 * check done at attrach time fails, the driver does not even attach.
 * So there are no failure conditions to report, and this provider is
 * never busy.
 */
/* ARGSUSED */
static void
n2rng_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*ARGSUSED*/
static int
n2rng_random_number(crypto_provider_handle_t provider,
    crypto_session_id_t sess, unsigned char *buf, size_t buflen,
    crypto_req_handle_t cfreq)
{
	n2rng_t		*n2rng = (n2rng_t *)provider;
	int		rv;

	rv = fips_random(n2rng, buf, buflen);

	atomic_add_64(&n2rng->n_stats[DS_RNGBYTES], buflen);
	atomic_inc_64(&n2rng->n_stats[DS_RNGJOBS]);

	return (rv);
}

static int
fips_init(n2rng_t *n2rng)
{
	int		i;
	int		rv;

	n2rng->n_frs.fips_round_robin_j = 0;
	for (i = 0; i < N2RNG_FIPS_INSTANCES; i++) {
		rv = n2rng_fips_random_init(n2rng, &n2rng->n_frs.fipsarray[i]);
		if (rv) {
			/* finalize all the FIPS structures allocated so far */
			for (--i; i >= 0; --i) {
				n2rng_fips_random_fini(
				    &n2rng->n_frs.fipsarray[i]);
			}
			return (rv);
		}
	}
	return (0);
}

static void
fips_fini(n2rng_t *n2rng)
{
	int		i;

	for (i = 0; i < N2RNG_FIPS_INSTANCES; i++) {
		n2rng_fips_random_fini(&n2rng->n_frs.fipsarray[i]);
	}
}
