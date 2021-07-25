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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2021 Jason King
 */

/*
 * TPM 1.2 Driver for the TPMs that follow TIS v1.2
 */

#include <sys/devops.h>		/* used by dev_ops */
#include <sys/conf.h>		/* used by dev_ops,cb_ops */
#include <sys/modctl.h>		/* for _init,_info,_fini,mod_* */
#include <sys/ddi.h>		/* used by all entry points */
#include <sys/sunddi.h>		/* used by all entry points */
#include <sys/cmn_err.h>	/* used for debug outputs */
#include <sys/types.h>		/* used by prop_op, ddi_prop_op */

#include <sys/file.h>		/* used by open, close */
#include <sys/errno.h>		/* used by open,close,read,write */
#include <sys/open.h>		/* used by open,close,read,write */
#include <sys/cred.h>		/* used by open,close,read */
#include <sys/uio.h>		/* used by read */
#include <sys/stat.h>		/* defines S_IFCHR */

#include <sys/byteorder.h>	/* for ntohs, ntohl, htons, htonl */

#ifdef sun4v
#include <sys/hypervisor_api.h>
#include <sys/hsvc.h>
#endif

#include <tss/platform.h>	/* from SUNWtss */
#include <tss/tpm.h>		/* from SUNWtss */

#include "tpm_tis.h"
#include "tpm_ddi.h"
#include "tpm_duration.h"

#define	TPM_HEADER_SIZE 10
typedef enum {
	TPM_TAG_OFFSET = 0,
	TPM_PARAMSIZE_OFFSET = 2,
	TPM_RETURN_OFFSET = 6,
	TPM_COMMAND_CODE_OFFSET = 6,
} TPM_HEADER_OFFSET_T;

/*
 * This is to address some TPMs that does not report the correct duration
 * and timeouts.  In our experience with the production TPMs, we encountered
 * time errors such as GetCapability command from TPM reporting the timeout
 * and durations in milliseconds rather than microseconds.  Some other TPMs
 * report the value 0's
 *
 * Short Duration is based on section 11.3.4 of TIS speciciation, that
 * TPM_GetCapability (short duration) commands should not be longer than 750ms
 * and that section 11.3.7 states that TPM_ContinueSelfTest (medium duration)
 * should not be longer than 1 second.
 */
#define	DEFAULT_SHORT_DURATION	750000
#define	DEFAULT_MEDIUM_DURATION	1000000
#define	DEFAULT_LONG_DURATION	300000000
#define	DEFAULT_TIMEOUT_A	750000
#define	DEFAULT_TIMEOUT_B	2000000
#define	DEFAULT_TIMEOUT_C	750000
#define	DEFAULT_TIMEOUT_D	750000

/*
 * In order to test the 'millisecond bug', we test if DURATIONS and TIMEOUTS
 * are unreasonably low...such as 10 milliseconds (TPM isn't that fast).
 * and 400 milliseconds for long duration
 */
#define	TEN_MILLISECONDS	10000	/* 10 milliseconds */
#define	FOUR_HUNDRED_MILLISECONDS 400000	/* 4 hundred milliseconds */

#define	DEFAULT_LOCALITY 0
/*
 * TPM input/output buffer offsets
 */

typedef enum {
	TPM_CAP_RESPSIZE_OFFSET = 10,
	TPM_CAP_RESP_OFFSET = 14,
} TPM_CAP_RET_OFFSET_T;

typedef enum {
	TPM_CAP_TIMEOUT_A_OFFSET = 14,
	TPM_CAP_TIMEOUT_B_OFFSET = 18,
	TPM_CAP_TIMEOUT_C_OFFSET = 22,
	TPM_CAP_TIMEOUT_D_OFFSET = 26,
} TPM_CAP_TIMEOUT_OFFSET_T;

typedef enum {
	TPM_CAP_DUR_SHORT_OFFSET = 14,
	TPM_CAP_DUR_MEDIUM_OFFSET = 18,
	TPM_CAP_DUR_LONG_OFFSET = 22,
} TPM_CAP_DURATION_OFFSET_T;

#define	TPM_CAP_VERSION_INFO_OFFSET	14
#define	TPM_CAP_VERSION_INFO_SIZE	15

/*
 * Internal TPM command functions
 */
static int itpm_command(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz);
static int tpm_get_timeouts(tpm_state_t *tpm);
static int tpm_get_duration(tpm_state_t *tpm);
static int tpm_get_version(tpm_state_t *tpm);
static int tpm_continue_selftest(tpm_state_t *tpm);

/*
 * Internal TIS related functions
 */
static int tpm_wait_for_stat(tpm_state_t *, uint8_t, clock_t);
static clock_t tpm_get_ordinal_duration(tpm_state_t *, uint8_t);
static int tis_check_active_locality(tpm_state_t *, char);
static int tis_request_locality(tpm_state_t *, char);
static void tis_release_locality(tpm_state_t *, char, int);
static int tis_init(tpm_state_t *);
static uint8_t tis_get_status(tpm_state_t *);
static int tis_send_data(tpm_state_t *, uint8_t *, size_t);
static int tis_recv_data(tpm_state_t *, uint8_t *, size_t);

/* Auxilliary */
static int receive_data(tpm_state_t *, uint8_t *, size_t);
static inline int tpm_io_lock(tpm_state_t *);
static inline void tpm_unlock(tpm_state_t *);
static void tpm_cleanup(dev_info_t *, tpm_state_t *);

/*
 * Sun DDI/DDK entry points
 */

/* Declaration of autoconfig functions */
static int tpm_attach(dev_info_t *, ddi_attach_cmd_t);
static int tpm_detach(dev_info_t *, ddi_detach_cmd_t);
static int tpm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int tpm_quiesce(dev_info_t *);
/* End of autoconfig functions */

/* Declaration of driver entry point functions */
static int tpm_open(dev_t *, int, int, cred_t *);
static int tpm_close(dev_t, int, int, cred_t *);
static int tpm_read(dev_t, struct uio *, cred_t *);
static int tpm_write(dev_t, struct uio *, cred_t *);
/* End of driver entry point functions */

/* cb_ops structure */
static struct cb_ops tpm_cb_ops = {
	tpm_open,
	tpm_close,
	nodev,		/* no strategy - nodev returns ENXIO */
	nodev,		/* no print */
	nodev,		/* no dump */
	tpm_read,
	tpm_write,
	nodev,		/* no ioctl */
	nodev,		/* no devmap */
	nodev,		/* no mmap */
	nodev,		/* no segmap */
	nochpoll,	/* returns ENXIO for non-pollable devices */
	ddi_prop_op,
	NULL,		/* streamtab struc */
	D_MP,		/* compatibility flags */
	CB_REV,		/* cb_ops revision number */
	nodev,		/* no aread */
	nodev		/* no awrite */
};

/* dev_ops structure */
static struct dev_ops tpm_dev_ops = {
	DEVO_REV,
	0,		/* reference count */
	tpm_getinfo,
	nulldev,	/* no identify - nulldev returns 0 */
	nulldev,
	tpm_attach,
	tpm_detach,
	nodev,		/* no reset - nodev returns ENXIO */
	&tpm_cb_ops,
	(struct bus_ops *)NULL,
	nodev,		/* no power */
	tpm_quiesce
};

/* modldrv structure */
static struct modldrv modldrv = {
	&mod_driverops,		/* Type: This is a driver */
	"TPM 1.2 driver",	/* Name of the module. */
	&tpm_dev_ops
};

/* modlinkage structure */
static struct modlinkage tpm_ml = {
	MODREV_1,
	&modldrv,
	NULL
};


#ifdef KCF_TPM_RNG_PROVIDER

#define	IDENT_TPMRNG	"TPM Random Number Generator"

#include <sys/crypto/common.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/spi.h>
/*
 * CSPI information (entry points, provider info, etc.)
 */
static void tpmrng_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t tpmrng_control_ops = {
	tpmrng_provider_status
};

static int tpmrng_seed_random(crypto_provider_handle_t, crypto_session_id_t,
    uchar_t *, size_t, uint_t, uint32_t, crypto_req_handle_t);

static int tpmrng_generate_random(crypto_provider_handle_t,
    crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);

static crypto_random_number_ops_t tpmrng_random_number_ops = {
	tpmrng_seed_random,
	tpmrng_generate_random
};

static int tpmrng_ext_info(crypto_provider_handle_t,
	crypto_provider_ext_info_t *,
	crypto_req_handle_t);

static crypto_provider_management_ops_t tpmrng_extinfo_op = {
	tpmrng_ext_info,
	NULL,
	NULL,
	NULL
};

static int tpmrng_register(tpm_state_t *);
static int tpmrng_unregister(tpm_state_t *);

static crypto_ops_t tpmrng_crypto_ops = {
	&tpmrng_control_ops,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&tpmrng_random_number_ops,
	NULL,
	NULL,
	NULL,
	&tpmrng_extinfo_op,
	NULL,
	NULL
};

static crypto_provider_info_t tpmrng_prov_info = {
	CRYPTO_SPI_VERSION_2,
	"TPM Random Number Provider",
	CRYPTO_HW_PROVIDER,
	NULL,
	NULL,
	&tpmrng_crypto_ops,
	0,
	NULL,
	0,
	NULL
};
#endif /* KCF_TPM_RNG_PROVIDER */

static void *statep = NULL;

/*
 * Inline code to get exclusive lock on the TPM device and to make sure
 * the device is not suspended.  This grabs the primary TPM mutex (pm_mutex)
 * and then checks the suspend status.  If suspended, it will wait until
 * the device is "resumed" before releasing the pm_mutex and continuing.
 */
#define	TPM_EXCLUSIVE_LOCK(tpm)  { \
	mutex_enter(&tpm->pm_mutex); \
	while (tpm->suspended) \
		cv_wait(&tpm->suspend_cv, &tpm->pm_mutex); \
	mutex_exit(&tpm->pm_mutex); }

/*
 * TPM accessor functions
 */
#ifdef sun4v

extern uint64_t
hcall_tpm_get(uint64_t, uint64_t, uint64_t, uint64_t *);

extern uint64_t
hcall_tpm_put(uint64_t, uint64_t, uint64_t, uint64_t);

static inline uint8_t
tpm_get8(tpm_state_t *tpm, unsigned long offset)
{
	uint64_t value;

	ASSERT(tpm != NULL);
	(void) hcall_tpm_get(tpm->locality, offset, sizeof (uint8_t), &value);
	return ((uint8_t)value);
}

static inline uint32_t
tpm_get32(tpm_state_t *tpm, unsigned long offset)
{
	uint64_t value;

	ASSERT(tpm != NULL);
	(void) hcall_tpm_get(tpm->locality, offset, sizeof (uint32_t), &value);
	return ((uint32_t)value);
}

static inline void
tpm_put8(tpm_state_t *tpm, unsigned long offset, uint8_t value)
{
	ASSERT(tpm != NULL);
	(void) hcall_tpm_put(tpm->locality, offset, sizeof (uint8_t), value);
}

#else

static inline uint8_t
tpm_get8(tpm_state_t *tpm, unsigned long offset)
{
	ASSERT(tpm != NULL);

	return (ddi_get8(tpm->handle,
	    (uint8_t *)(TPM_LOCALITY_OFFSET(tpm->locality) |
	    (uintptr_t)tpm->addr + offset)));
}

static inline uint32_t
tpm_get32(tpm_state_t *tpm, unsigned long offset)
{
	ASSERT(tpm != NULL);
	return (ddi_get32(tpm->handle,
	    (uint32_t *)(TPM_LOCALITY_OFFSET(tpm->locality) |
	    (uintptr_t)tpm->addr + offset)));
}

static inline void
tpm_put8(tpm_state_t *tpm, unsigned long offset, uint8_t value)
{
	ASSERT(tpm != NULL);
	ddi_put8(tpm->handle,
	    (uint8_t *)(TPM_LOCALITY_OFFSET(tpm->locality) |
	    (uintptr_t)tpm->addr + offset), value);
}

#endif /* sun4v */

/*
 * TPM commands to get the TPM's properties, e.g.,timeout
 */
/*ARGSUSED*/
static int
tpm_quiesce(dev_info_t *dip)
{
	return (DDI_SUCCESS);
}

static uint32_t
load32(uchar_t *ptr, uint32_t offset)
{
	uint32_t val;
	bcopy(ptr + offset, &val, sizeof (uint32_t));

	return (ntohl(val));
}

/*
 * Get the actual timeouts supported by the TPM by issuing TPM_GetCapability
 * with the subcommand TPM_CAP_PROP_TIS_TIMEOUT
 * TPM_GetCapability (TPM Main Part 3 Rev. 94, pg.38)
 */
static int
tpm_get_timeouts(tpm_state_t *tpm)
{
	int ret;
	uint32_t timeout;   /* in milliseconds */
	uint32_t len;

	/* The buffer size (30) needs room for 4 timeout values (uint32_t) */
	uint8_t buf[30] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 22,	/* paramsize in bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 5,	/* TPM_CAP_Prop */
		0, 0, 0, 4,	/* SUB_CAP size in bytes */
		0, 0, 1, 21	/* TPM_CAP_PROP_TIS_TIMEOUT(0x115) */
	};

	ASSERT(tpm != NULL);

	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: itpm_command failed", __func__);
#endif
		return (DDI_FAILURE);
	}

	/*
	 * Get the length of the returned buffer
	 * Make sure that there are 4 timeout values returned
	 * length of the capability response is stored in data[10-13]
	 * Also the TPM is in network byte order
	 */
	len = load32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len != 4 * sizeof (uint32_t)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: capability response size should be %d"
		    "instead len = %d",
		    __func__, (int)(4 * sizeof (uint32_t)), (int)len);
#endif
		return (DDI_FAILURE);
	}

	/* Get the four timeout's: a,b,c,d (they are 4 bytes long each) */
	timeout = load32(buf, TPM_CAP_TIMEOUT_A_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_A;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_a = drv_usectohz(timeout);

	timeout = load32(buf, TPM_CAP_TIMEOUT_B_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_B;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_b = drv_usectohz(timeout);

	timeout = load32(buf, TPM_CAP_TIMEOUT_C_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_C;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_c = drv_usectohz(timeout);

	timeout = load32(buf, TPM_CAP_TIMEOUT_D_OFFSET);
	if (timeout == 0) {
		timeout = DEFAULT_TIMEOUT_D;
	} else if (timeout < TEN_MILLISECONDS) {
		/* timeout is in millisecond range (should be microseconds) */
		timeout *= 1000;
	}
	tpm->timeout_d = drv_usectohz(timeout);

	return (DDI_SUCCESS);
}

/*
 * Get the actual timeouts supported by the TPM by issuing TPM_GetCapability
 * with the subcommand TPM_CAP_PROP_TIS_DURATION
 * TPM_GetCapability (TPM Main Part 3 Rev. 94, pg.38)
 */
static int
tpm_get_duration(tpm_state_t *tpm)
{
	int ret;
	uint32_t duration;
	uint32_t len;
	uint8_t buf[30] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 22,	/* paramsize in bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 5,	/* TPM_CAP_Prop */
		0, 0, 0, 4,	/* SUB_CAP size in bytes */
		0, 0, 1, 32	/* TPM_CAP_PROP_TIS_DURATION(0x120) */
	};

	ASSERT(tpm != NULL);

	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: itpm_command failed with ret code: 0x%x",
		    __func__, ret);
#endif
		return (DDI_FAILURE);
	}

	/*
	 * Get the length of the returned buffer
	 * Make sure that there are 3 duration values (S,M,L: in that order)
	 * length of the capability response is stored in data[10-13]
	 * Also the TPM is in network byte order
	 */
	len = load32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len != 3 * sizeof (uint32_t)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: capability response should be %d, "
		    "instead, it's %d",
		    __func__, (int)(3 * sizeof (uint32_t)), (int)len);
#endif
		return (DDI_FAILURE);
	}

	duration = load32(buf, TPM_CAP_DUR_SHORT_OFFSET);
	if (duration == 0) {
		duration = DEFAULT_SHORT_DURATION;
	} else if (duration < TEN_MILLISECONDS) {
		duration *= 1000;
	}
	tpm->duration[TPM_SHORT] = drv_usectohz(duration);

	duration = load32(buf, TPM_CAP_DUR_MEDIUM_OFFSET);
	if (duration == 0) {
		duration = DEFAULT_MEDIUM_DURATION;
	} else if (duration < TEN_MILLISECONDS) {
		duration *= 1000;
	}
	tpm->duration[TPM_MEDIUM] = drv_usectohz(duration);

	duration = load32(buf, TPM_CAP_DUR_LONG_OFFSET);
	if (duration == 0) {
		duration = DEFAULT_LONG_DURATION;
	} else if (duration < FOUR_HUNDRED_MILLISECONDS) {
		duration *= 1000;
	}
	tpm->duration[TPM_LONG] = drv_usectohz(duration);

	/* Just make the undefined duration be the same as the LONG */
	tpm->duration[TPM_UNDEFINED] = tpm->duration[TPM_LONG];

	return (DDI_SUCCESS);
}

/*
 * Get the actual timeouts supported by the TPM by issuing TPM_GetCapability
 * with the subcommand TPM_CAP_PROP_TIS_DURATION
 * TPM_GetCapability (TPM Main Part 3 Rev. 94, pg.38)
 */
static int
tpm_get_version(tpm_state_t *tpm)
{
	int ret;
	uint32_t len;
	char vendorId[5];
	/* If this buf is too small, the "vendor specific" data won't fit */
	uint8_t buf[64] = {
		0, 193,		/* TPM_TAG_RQU_COMMAND */
		0, 0, 0, 18,	/* paramsize in bytes */
		0, 0, 0, 101,	/* TPM_ORD_GetCapability */
		0, 0, 0, 0x1A,	/* TPM_CAP_VERSION_VAL */
		0, 0, 0, 0,	/* SUB_CAP size in bytes */
	};

	ASSERT(tpm != NULL);

	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: itpm_command failed with ret code: 0x%x",
		    __func__, ret);
#endif
		return (DDI_FAILURE);
	}

	/*
	 * Get the length of the returned buffer.
	 */
	len = load32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len < TPM_CAP_VERSION_INFO_SIZE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: capability response should be greater"
		    " than %d, instead, it's %d",
		    __func__, TPM_CAP_VERSION_INFO_SIZE, len);
#endif
		return (DDI_FAILURE);
	}

	bcopy(buf + TPM_CAP_VERSION_INFO_OFFSET, &tpm->vers_info,
	    TPM_CAP_VERSION_INFO_SIZE);

	bcopy(tpm->vers_info.tpmVendorID, vendorId,
	    sizeof (tpm->vers_info.tpmVendorID));
	vendorId[4] = '\0';

	cmn_err(CE_NOTE, "!TPM found: Ver %d.%d, Rev %d.%d, "
	    "SpecLevel %d, errataRev %d, VendorId '%s'",
	    tpm->vers_info.version.major,	/* Version */
	    tpm->vers_info.version.minor,
	    tpm->vers_info.version.revMajor,	/* Revision */
	    tpm->vers_info.version.revMinor,
	    (int)ntohs(tpm->vers_info.specLevel),
	    tpm->vers_info.errataRev,
	    vendorId);

	/*
	 * This driver only supports TPM Version 1.2
	 */
	if (tpm->vers_info.version.major != 1 &&
	    tpm->vers_info.version.minor != 2) {
		cmn_err(CE_WARN, "!%s: Unsupported TPM version (%d.%d)",
		    __func__,
		    tpm->vers_info.version.major,		/* Version */
		    tpm->vers_info.version.minor);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * To prevent the TPM from complaining that certain functions are not tested
 * we run this command when the driver attaches.
 * For details see Section 4.2 of TPM Main Part 3 Command Specification
 */
static int
tpm_continue_selftest(tpm_state_t *tpm)
{
	int ret;
	uint8_t buf[10] = {
		0, 193,		/* TPM_TAG_RQU COMMAND */
		0, 0, 0, 10,	/* paramsize in bytes */
		0, 0, 0, 83	/* TPM_ORD_ContinueSelfTest */
	};

	/* Need a longer timeout */
	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: itpm_command failed", __func__);
#endif
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}
/*
 * Auxilary Functions
 */

/*
 * Find out how long we should wait for the TPM command to complete a command
 */
static clock_t
tpm_get_ordinal_duration(tpm_state_t *tpm, uint8_t ordinal)
{
	uint8_t index;

	ASSERT(tpm != NULL);

	/* Default and failure case for IFX */
	/* Is it a TSC_ORDINAL? */
	if (ordinal & TSC_ORDINAL_MASK) {
		if (ordinal >= TSC_ORDINAL_MAX) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!%s: tsc ordinal: %d exceeds MAX: %d",
			    __func__, ordinal, TSC_ORDINAL_MAX);
#endif
			return (0);
		}
		index = tsc_ords_duration[ordinal];
	} else {
		if (ordinal >= TPM_ORDINAL_MAX) {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!%s: ordinal %d exceeds MAX: %d",
			    __func__, ordinal, TPM_ORDINAL_MAX);
#endif
			return (0);
		}
		index = tpm_ords_duration[ordinal];
	}

	if (index > TPM_DURATION_MAX_IDX) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: duration index '%d' is out of bounds",
		    __func__, index);
#endif
		return (0);
	}
	return (tpm->duration[index]);
}

/*
 * Internal TPM Transmit Function:
 * Calls implementation specific sendto and receive
 * The code assumes that the buffer is in network byte order
 */
static int
itpm_command(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int ret;
	uint32_t count;

	ASSERT(tpm != NULL && buf != NULL);

	/* The byte order is network byte order so convert it */
	count = load32(buf, TPM_PARAMSIZE_OFFSET);

	if (count == 0 || (count > bufsiz)) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: invalid byte count value "
		    "(%d > bufsiz %d)", __func__, (int)count, (int)bufsiz);
#endif
		return (DDI_FAILURE);
	}

	/* Send the command */
	ret = tis_send_data(tpm, buf, count);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_send_data failed with error %x",
		    __func__, ret);
#endif
		return (DDI_FAILURE);
	}

	/*
	 * Now receive the data from the tpm
	 * Should at least receive "the common" 10 bytes (TPM_HEADER_SIZE)
	 */
	ret = tis_recv_data(tpm, buf, bufsiz);
	if (ret < TPM_HEADER_SIZE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_recv_data failed", __func__);
#endif
		return (DDI_FAILURE);
	}

	/* Check the return code */
	ret = load32(buf, TPM_RETURN_OFFSET);
	if (ret != TPM_SUCCESS) {
		if (ret == TPM_E_DEACTIVATED)
			cmn_err(CE_WARN, "!%s: TPM is deactivated", __func__);
		else if (ret == TPM_E_DISABLED)
			cmn_err(CE_WARN, "!%s: TPM is disabled", __func__);
		else
			cmn_err(CE_WARN, "!%s: TPM error code 0x%0x",
			    __func__, ret);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Whenever the driver wants to write to the DATA_IO register, it must need
 * to figure out the burstcount.  This is the amount of bytes it can write
 * before having to wait for long LPC bus cycle
 *
 * Returns: 0 if error, burst count if sucess
 */
static uint16_t
tpm_get_burstcount(tpm_state_t *tpm)
{
	clock_t stop;
	uint16_t burstcnt;

	ASSERT(tpm != NULL);

	/*
	 * Spec says timeout should be TIMEOUT_D
	 * burst count is TPM_STS bits 8..23
	 */
	stop = ddi_get_lbolt() + tpm->timeout_d;
	do {
		/*
		 * burstcnt is stored as a little endian value
		 * 'ntohs' doesn't work since the value is not word-aligned
		 */
		burstcnt = tpm_get8(tpm, TPM_STS + 1);
		burstcnt += tpm_get8(tpm, TPM_STS + 2) << 8;

		if (burstcnt)
			return (burstcnt);

		delay(tpm->timeout_poll);
	} while (ddi_get_lbolt() < stop);

	return (0);
}

/*
 * Writing 1 to TPM_STS_CMD_READY bit in TPM_STS will do the following:
 * 1. The TPM will clears IO buffers if any
 * 2. The TPM will enters either Idle or Ready state within TIMEOUT_B
 * (checked in the calling function)
 */
static void
tpm_set_ready(tpm_state_t *tpm)
{
	tpm_put8(tpm, TPM_STS, TPM_STS_CMD_READY);
}

static int
receive_data(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int size = 0;
	int retried = 0;
	uint8_t stsbits;

	/* A number of consecutive bytes that can be written to TPM */
	uint16_t burstcnt;

	ASSERT(tpm != NULL && buf != NULL);
retry:
	while (size < bufsiz && (tpm_wait_for_stat(tpm,
	    (TPM_STS_DATA_AVAIL|TPM_STS_VALID),
	    tpm->timeout_c) == DDI_SUCCESS)) {
		/*
		 * Burstcount should be available within TIMEOUT_D
		 * after STS is set to valid
		 * burstcount is dynamic, so have to get it each time
		 */
		burstcnt = tpm_get_burstcount(tpm);
		for (; burstcnt > 0 && size < bufsiz; burstcnt--) {
			buf[size++] = tpm_get8(tpm, TPM_DATA_FIFO);
		}
	}
	stsbits = tis_get_status(tpm);
	/* check to see if we need to retry (just once) */
	if (size < bufsiz && !(stsbits & TPM_STS_DATA_AVAIL) && retried == 0) {
		/* issue responseRetry (TIS 1.2 pg 54) */
		tpm_put8(tpm, TPM_STS, TPM_STS_RESPONSE_RETRY);
		/* update the retry counter so we only retry once */
		retried++;
		/* reset the size to 0 and reread the entire response */
		size = 0;
		goto retry;
	}
	return (size);
}

/* Receive the data from the TPM */
static int
tis_recv_data(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int ret;
	int size = 0;
	uint32_t expected, status;
	uint32_t cmdresult;

	ASSERT(tpm != NULL && buf != NULL);

	if (bufsiz < TPM_HEADER_SIZE) {
		/* There should be at least tag, paramsize, return code */
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: received data should contain at least "
		    "the header which is %d bytes long",
		    __func__, TPM_HEADER_SIZE);
#endif
		goto OUT;
	}

	/* Read tag(2 bytes), paramsize(4), and result(4) */
	size = receive_data(tpm, buf, TPM_HEADER_SIZE);
	if (size < TPM_HEADER_SIZE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: recv TPM_HEADER failed, size = %d",
		    __func__, size);
#endif
		goto OUT;
	}

	cmdresult = load32(buf, TPM_RETURN_OFFSET);

	/* Get 'paramsize'(4 bytes)--it includes tag and paramsize */
	expected = load32(buf, TPM_PARAMSIZE_OFFSET);
	if (expected > bufsiz) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: paramSize is bigger "
		    "than the requested size: paramSize=%d bufsiz=%d result=%d",
		    __func__, (int)expected, (int)bufsiz, cmdresult);
#endif
		goto OUT;
	}

	/* Read in the rest of the data from the TPM */
	size += receive_data(tpm, (uint8_t *)&buf[TPM_HEADER_SIZE],
	    expected - TPM_HEADER_SIZE);
	if (size < expected) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: received data length (%d) "
		    "is less than expected (%d)", __func__, size, expected);
#endif
		goto OUT;
	}

	/* The TPM MUST set the state to stsValid within TIMEOUT_C */
	ret = tpm_wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c);

	status = tis_get_status(tpm);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: TPM didn't set stsValid after its I/O: "
		    "status = 0x%08X", __func__, status);
#endif
		goto OUT;
	}

	/* There is still more data? */
	if (status & TPM_STS_DATA_AVAIL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: TPM_STS_DATA_AVAIL is set:0x%08X",
		    __func__, status);
#endif
		goto OUT;
	}

	/*
	 * Release the control of the TPM after we are done with it
	 * it...so others can also get a chance to send data
	 */
	tis_release_locality(tpm, tpm->locality, 0);

OUT:
	tpm_set_ready(tpm);
	tis_release_locality(tpm, tpm->locality, 0);
	return (size);
}

/*
 * Send the data (TPM commands) to the Data IO register
 */
static int
tis_send_data(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz)
{
	int ret;
	uint8_t status;
	uint16_t burstcnt;
	uint32_t ordinal;
	size_t count = 0;

	ASSERT(tpm != NULL && buf != NULL);

	if (bufsiz == 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: bufsiz arg is zero", __func__);
#endif
		return (DDI_FAILURE);
	}

	/* Put the TPM in ready state */
	status = tis_get_status(tpm);

	if (!(status & TPM_STS_CMD_READY)) {
		tpm_set_ready(tpm);
		ret = tpm_wait_for_stat(tpm, TPM_STS_CMD_READY, tpm->timeout_b);
		if (ret != DDI_SUCCESS) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: could not put the TPM "
			    "in the command ready state:"
			    "tpm_wait_for_stat returned error",
			    __func__);
#endif
			goto FAIL;
		}
	}

	/*
	 * Now we are ready to send command
	 * TPM's burstcount dictates how many bytes we can write at a time
	 * Burstcount is dynamic if INTF_CAPABILITY for static burstcount is
	 * not set.
	 */
	while (count < bufsiz - 1) {
		burstcnt = tpm_get_burstcount(tpm);
		if (burstcnt == 0) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: tpm_get_burstcnt returned error",
			    __func__);
#endif
			ret = DDI_FAILURE;
			goto FAIL;
		}

		for (; burstcnt > 0 && count < bufsiz - 1; burstcnt--) {
			tpm_put8(tpm, TPM_DATA_FIFO, buf[count]);
			count++;
		}
		/* Wait for TPM to indicate that it is ready for more data */
		ret = tpm_wait_for_stat(tpm,
		    (TPM_STS_VALID | TPM_STS_DATA_EXPECT), tpm->timeout_c);
		if (ret != DDI_SUCCESS) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: TPM didn't enter STS_VALID "
			    "state", __func__);
#endif
			goto FAIL;
		}
	}
	/* We can't exit the loop above unless we wrote bufsiz-1 bytes */

	/* Write last byte */
	tpm_put8(tpm, TPM_DATA_FIFO, buf[count]);
	count++;

	/* Wait for the TPM to enter Valid State */
	ret = tpm_wait_for_stat(tpm, TPM_STS_VALID, tpm->timeout_c);
	if (ret == DDI_FAILURE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tpm didn't enter STS_VALID state",
		    __func__);
#endif
		goto FAIL;
	}

	status = tis_get_status(tpm);
	/* The TPM should NOT be expecing more data at this point */
	if ((status & TPM_STS_DATA_EXPECT) != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: DATA_EXPECT should not be set after "
		    "writing the last byte: status=0x%08X", __func__, status);
#endif
		ret = DDI_FAILURE;
		goto FAIL;
	}

	/*
	 * Final step: Writing TPM_STS_GO to TPM_STS
	 * register will actually send the command.
	 */
	tpm_put8(tpm, TPM_STS, TPM_STS_GO);

	/* Ordinal/Command_code is located in buf[6..9] */
	ordinal = load32(buf, TPM_COMMAND_CODE_OFFSET);

	ret = tpm_wait_for_stat(tpm, TPM_STS_DATA_AVAIL | TPM_STS_VALID,
	    tpm_get_ordinal_duration(tpm, ordinal));
	if (ret == DDI_FAILURE) {
#ifdef DEBUG
		status = tis_get_status(tpm);
		if (!(status & TPM_STS_DATA_AVAIL) ||
		    !(status & TPM_STS_VALID)) {
			cmn_err(CE_WARN, "!%s: TPM not ready or valid "
			    "(ordinal = %d timeout = %ld status = 0x%0x)",
			    __func__, ordinal,
			    tpm_get_ordinal_duration(tpm, ordinal),
			    status);
		} else {
			cmn_err(CE_WARN, "!%s: tpm_wait_for_stat "
			    "(DATA_AVAIL | VALID) failed status = 0x%0X",
			    __func__, status);
		}
#endif
		goto FAIL;
	}
	return (DDI_SUCCESS);

FAIL:
	tpm_set_ready(tpm);
	tis_release_locality(tpm, tpm->locality, 0);
	return (ret);
}

/*
 * Clear XrequestUse and Xactivelocality, where X is the current locality
 */
static void
tis_release_locality(tpm_state_t *tpm, char locality, int force)
{
	ASSERT(tpm != NULL && locality >= 0 && locality < 5);

	if (force ||
	    (tpm_get8(tpm, TPM_ACCESS) &
	    (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) ==
	    (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) {
		/*
		 * Writing 1 to active locality bit in TPM_ACCESS
		 * register reliquishes the control of the locality
		 */
		tpm_put8(tpm, TPM_ACCESS, TPM_ACCESS_ACTIVE_LOCALITY);
	}
}

/*
 * Checks whether the given locality is active
 * Use TPM_ACCESS register and the masks TPM_ACCESS_VALID,TPM_ACTIVE_LOCALITY
 */
static int
tis_check_active_locality(tpm_state_t *tpm, char locality)
{
	uint8_t access_bits;
	uint8_t old_locality;

	ASSERT(tpm != NULL && locality >= 0 && locality < 5);

	old_locality = tpm->locality;
	tpm->locality = locality;

	/* Just check to see if the requested locality works */
	access_bits = tpm_get8(tpm, TPM_ACCESS);
	access_bits &= (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID);

	/* this was just a check, not a request to switch */
	tpm->locality = old_locality;

	if (access_bits == (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID)) {
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

/* Request the TPM to be in the given locality */
static int
tis_request_locality(tpm_state_t *tpm, char locality)
{
	clock_t timeout;
	int ret;

	ASSERT(tpm != NULL && locality >= 0 && locality < 5);

	ret = tis_check_active_locality(tpm, locality);

	if (ret == DDI_SUCCESS) {
		/* Locality is already active */
		tpm->locality = locality;
		return (DDI_SUCCESS);
	}

	tpm_put8(tpm, TPM_ACCESS, TPM_ACCESS_REQUEST_USE);
	timeout = ddi_get_lbolt() + tpm->timeout_a;

	/* Using polling */
	while (tis_check_active_locality(tpm, locality) != DDI_SUCCESS) {
		if (ddi_get_lbolt() >= timeout) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: (interrupt-disabled) "
			    "tis_request_locality timed out (timeout_a = %ld)",
			    __func__, tpm->timeout_a);
#endif
			return (DDI_FAILURE);
		}
		delay(tpm->timeout_poll);
	}

	tpm->locality = locality;
	return (DDI_SUCCESS);
}

/* Read the status register */
static uint8_t
tis_get_status(tpm_state_t *tpm)
{
	return (tpm_get8(tpm, TPM_STS));
}

static int
tpm_wait_for_stat(tpm_state_t *tpm, uint8_t mask, clock_t timeout)
{
	clock_t absolute_timeout = ddi_get_lbolt() + timeout;

	/* Using polling */
	while ((tis_get_status(tpm) & mask) != mask) {
		if (ddi_get_lbolt() >= absolute_timeout) {
			/* Timeout reached */
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: using "
			    "polling - reached timeout (%ld usecs)",
			    __func__, drv_hztousec(timeout));
#endif
			return (DDI_FAILURE);
		}
		delay(tpm->timeout_poll);
	}
	return (DDI_SUCCESS);
}

/*
 * Initialize TPM device
 * 1. Find out supported interrupt capabilities
 * 2. Set up interrupt handler if supported (some BIOSes don't support
 * interrupts for TPMS, in which case we set up polling)
 * 3. Determine timeouts and commands duration
 */
static int
tis_init(tpm_state_t *tpm)
{
	uint32_t intf_caps;
	int ret;

	/*
	 * Temporarily set up timeouts before we get the real timeouts
	 * by issuing TPM_CAP commands (but to issue TPM_CAP commands,
	 * you need TIMEOUTs defined...chicken and egg problem here.
	 * TPM timeouts: Convert the milliseconds to clock cycles
	 */
	tpm->timeout_a = drv_usectohz(TIS_TIMEOUT_A);
	tpm->timeout_b = drv_usectohz(TIS_TIMEOUT_B);
	tpm->timeout_c = drv_usectohz(TIS_TIMEOUT_C);
	tpm->timeout_d = drv_usectohz(TIS_TIMEOUT_D);
	/*
	 * Do the same with the duration (real duration will be filled out
	 * when we call TPM_GetCapability to get the duration values from
	 * the TPM itself).
	 */
	tpm->duration[TPM_SHORT] = drv_usectohz(TPM_DEFAULT_DURATION);
	tpm->duration[TPM_MEDIUM] = drv_usectohz(TPM_DEFAULT_DURATION);
	tpm->duration[TPM_LONG] = drv_usectohz(TPM_DEFAULT_DURATION);
	tpm->duration[TPM_UNDEFINED] = drv_usectohz(TPM_DEFAULT_DURATION);

	/* Find out supported capabilities */
	intf_caps = tpm_get32(tpm, TPM_INTF_CAP);

	/* Upper 3 bytes should always return 0 */
	if (intf_caps & 0x7FFFFF00) {
		cmn_err(CE_WARN, "!%s: bad intf_caps value 0x%0X",
		    __func__, intf_caps);
		return (DDI_FAILURE);
	}

	/* These two interrupts are mandatory */
	if (!(intf_caps & TPM_INTF_INT_LOCALITY_CHANGE_INT)) {
		cmn_err(CE_WARN,
		    "!%s: Mandatory capability Locality Change Int "
		    "not supported", __func__);
		return (DDI_FAILURE);
	}
	if (!(intf_caps & TPM_INTF_INT_DATA_AVAIL_INT)) {
		cmn_err(CE_WARN, "!%s: Mandatory capability Data Available Int "
		    "not supported.", __func__);
		return (DDI_FAILURE);
	}

	/*
	 * Before we start writing anything to TPM's registers,
	 * make sure we are in locality 0
	 */
	ret = tis_request_locality(tpm, DEFAULT_LOCALITY);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: Unable to request locality %d", __func__,
		    DEFAULT_LOCALITY);
		return (DDI_FAILURE);
	} /* Now we can refer to the locality as tpm->locality */

	tpm->timeout_poll = drv_usectohz(TPM_POLLING_TIMEOUT);
	tpm->intr_enabled = 0;

	/* Get the real timeouts from the TPM */
	ret = tpm_get_timeouts(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_get_timeouts error", __func__);
		return (DDI_FAILURE);
	}

	ret = tpm_get_duration(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_get_duration error", __func__);
		return (DDI_FAILURE);
	}

	/* This gets the TPM version information */
	ret = tpm_get_version(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_get_version error", __func__);
		return (DDI_FAILURE);
	}

	/*
	 * Unless the TPM completes the test of its commands,
	 * it can return an error when the untested commands are called
	 */
	ret = tpm_continue_selftest(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "!%s: tpm_continue_selftest error", __func__);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Module Entry points
 */
int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&statep, sizeof (tpm_state_t), 1);
	if (ret) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!ddi_soft_state_init failed: %d", ret);
#endif
		return (ret);
	}
	ret = mod_install(&tpm_ml);
	if (ret != 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!_init: mod_install returned non-zero");
#endif
		ddi_soft_state_fini(&statep);
		return (ret);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	int ret;
	ret = mod_info(&tpm_ml, modinfop);
#ifdef DEBUG
	if (ret == 0)
		cmn_err(CE_WARN, "!mod_info failed: %d", ret);
#endif

	return (ret);
}

int
_fini()
{
	int ret;

	ret = mod_remove(&tpm_ml);
	if (ret != 0)
		return (ret);

	ddi_soft_state_fini(&statep);

	return (ret);
}
/* End of driver configuration functions */

static int
tpm_resume(tpm_state_t *tpm)
{
	mutex_enter(&tpm->pm_mutex);
	if (!tpm->suspended) {
		mutex_exit(&tpm->pm_mutex);
		return (DDI_FAILURE);
	}
	tpm->suspended = 0;
	cv_broadcast(&tpm->suspend_cv);
	mutex_exit(&tpm->pm_mutex);

	return (DDI_SUCCESS);
}

#ifdef sun4v
static uint64_t hsvc_tpm_minor = 0;
static hsvc_info_t hsvc_tpm = {
	HSVC_REV_1, NULL, HSVC_GROUP_TPM, 1, 0, NULL
};
#endif

/*
 * Sun DDI/DDK entry points
 */
static int
tpm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	int instance;
#ifndef sun4v
	int idx, nregs;
#endif
	tpm_state_t *tpm = NULL;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);
	if (instance < 0)
		return (DDI_FAILURE);

	/* Nothing out of ordinary here */
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_soft_state_zalloc(statep, instance) == DDI_SUCCESS) {
			tpm = ddi_get_soft_state(statep, instance);
			if (tpm == NULL) {
#ifdef DEBUG
				cmn_err(CE_WARN,
				    "!%s: cannot get state information.",
				    __func__);
#endif
				return (DDI_FAILURE);
			}
			tpm->dip = dip;
		} else {
#ifdef DEBUG
			cmn_err(CE_WARN,
			    "!%s: cannot allocate state information.",
			    __func__);
#endif
			return (DDI_FAILURE);
		}
		break;
	case DDI_RESUME:
		tpm = ddi_get_soft_state(statep, instance);
		if (tpm == NULL) {
#ifdef DEBUG
			cmn_err(CE_WARN, "!%s: cannot get state information.",
			    __func__);
#endif
			return (DDI_FAILURE);
		}
		return (tpm_resume(tpm));
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: cmd %d is not implemented", __func__,
		    cmd);
#endif
		ret = DDI_FAILURE;
		goto FAIL;
	}

	/* Zeroize the flag, which is used to keep track of what is allocated */
	tpm->flags = 0;

#ifdef sun4v
	ret = hsvc_register(&hsvc_tpm, &hsvc_tpm_minor);
	if (ret != 0) {
		cmn_err(CE_WARN, "!%s: failed to register with "
		    "hypervisor: 0x%0x", __func__, ret);
		goto FAIL;
	}
	tpm->flags |= TPM_HSVC_REGISTERED;
#else
	tpm->accattr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	tpm->accattr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	tpm->accattr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	idx = 0;
	ret = ddi_dev_nregs(tpm->dip, &nregs);
	if (ret != DDI_SUCCESS)
		goto FAIL;

	/*
	 * TPM vendors put the TPM registers in different
	 * slots in their register lists.  They are not always
	 * the 1st set of registers, for instance.
	 * Loop until we find the set that matches the expected
	 * register size (0x5000).
	 */
	for (idx = 0; idx < nregs; idx++) {
		off_t regsize;

		if ((ret = ddi_dev_regsize(tpm->dip, idx, &regsize)) !=
		    DDI_SUCCESS)
			goto FAIL;
		/* The TIS spec says the TPM registers must be 0x5000 bytes */
		if (regsize == 0x5000)
			break;
	}
	if (idx == nregs) {
		ret = DDI_FAILURE;
		goto FAIL;
	}

	ret = ddi_regs_map_setup(tpm->dip, idx, (caddr_t *)&tpm->addr,
	    (offset_t)0, (offset_t)0x5000,
	    &tpm->accattr, &tpm->handle);

	if (ret != DDI_SUCCESS) {
		goto FAIL;
	}
	tpm->flags |= TPM_DIDREGSMAP;
#endif
	/* Enable TPM device according to the TIS specification */
	ret = tis_init(tpm);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_init() failed with error %d",
		    __func__, ret);
#endif

		/* We need to clean up the ddi_regs_map_setup call */
		if (tpm->flags & TPM_DIDREGSMAP) {
			ddi_regs_map_free(&tpm->handle);
			tpm->handle = NULL;
			tpm->flags &= ~TPM_DIDREGSMAP;
		}
		goto FAIL;
	}

	/* Initialize the inter-process lock */
	mutex_init(&tpm->dev_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&tpm->pm_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&tpm->suspend_cv, NULL, CV_DRIVER, NULL);

	/* Set the suspend/resume property */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "pm-hardware-state", "needs-suspend-resume");

	mutex_enter(&tpm->pm_mutex);
	tpm->suspended = 0;
	mutex_exit(&tpm->pm_mutex);

	tpm->flags |= TPM_DID_MUTEX;

	/* Initialize the buffer and the lock associated with it */
	tpm->bufsize = TPM_IO_BUF_SIZE;
	tpm->iobuf = kmem_zalloc((sizeof (uint8_t))*(tpm->bufsize), KM_SLEEP);
	tpm->flags |= TPM_DID_IO_ALLOC;

	mutex_init(&tpm->iobuf_lock, NULL, MUTEX_DRIVER, NULL);
	tpm->flags |= TPM_DID_IO_MUTEX;

	cv_init(&tpm->iobuf_cv, NULL, CV_DRIVER, NULL);
	tpm->flags |= TPM_DID_IO_CV;

	/* Create minor node */
	ret = ddi_create_minor_node(dip, "tpm", S_IFCHR, ddi_get_instance(dip),
	    DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: ddi_create_minor_node failed", __func__);
#endif
		goto FAIL;
	}
	tpm->flags |= TPM_DIDMINOR;

#ifdef KCF_TPM_RNG_PROVIDER
	/* register RNG with kcf */
	if (tpmrng_register(tpm) != DDI_SUCCESS)
		cmn_err(CE_WARN, "!%s: tpm RNG failed to register with kcf",
		    __func__);
#endif

	return (DDI_SUCCESS);
FAIL:
	if (tpm != NULL) {
		tpm_cleanup(dip, tpm);
		ddi_soft_state_free(statep, instance);
		tpm = NULL;
	}

	return (DDI_FAILURE);
}

/*
 * Called by tpm_detach and tpm_attach (only on failure)
 * Free up the resources that are allocated
 */
static void
tpm_cleanup(dev_info_t *dip, tpm_state_t *tpm)
{
	if (tpm == NULL)
		return;

#ifdef KCF_TPM_RNG_PROVIDER
	(void) tpmrng_unregister(tpm);
#endif

#ifdef sun4v
	if (tpm->flags & TPM_HSVC_REGISTERED) {
		(void) hsvc_unregister(&hsvc_tpm);
		tpm->flags &= ~(TPM_HSVC_REGISTERED);
	}
#endif
	if (tpm->flags & TPM_DID_MUTEX) {
		mutex_destroy(&tpm->dev_lock);
		mutex_destroy(&tpm->pm_mutex);
		cv_destroy(&tpm->suspend_cv);
		tpm->flags &= ~(TPM_DID_MUTEX);
	}
	if (tpm->flags & TPM_DID_IO_ALLOC) {
		ASSERT(tpm->iobuf != NULL);
		kmem_free(tpm->iobuf, (sizeof (uint8_t))*(tpm->bufsize));
		tpm->flags &= ~(TPM_DID_IO_ALLOC);
	}
	if (tpm->flags & TPM_DID_IO_MUTEX) {
		mutex_destroy(&tpm->iobuf_lock);
		tpm->flags &= ~(TPM_DID_IO_MUTEX);
	}
	if (tpm->flags & TPM_DID_IO_CV) {
		cv_destroy(&tpm->iobuf_cv);
		tpm->flags &= ~(TPM_DID_IO_CV);
	}
	if (tpm->flags & TPM_DIDREGSMAP) {
		/* Free the mapped addresses */
		if (tpm->handle != NULL)
			ddi_regs_map_free(&tpm->handle);
		tpm->flags &= ~(TPM_DIDREGSMAP);
	}
	if (tpm->flags & TPM_DIDMINOR) {
		/* Remove minor node */
		ddi_remove_minor_node(dip, NULL);
		tpm->flags &= ~(TPM_DIDMINOR);
	}
}

static int
tpm_suspend(tpm_state_t *tpm)
{
	if (tpm == NULL)
		return (DDI_FAILURE);
	mutex_enter(&tpm->pm_mutex);
	if (tpm->suspended) {
		mutex_exit(&tpm->pm_mutex);
		return (DDI_SUCCESS);
	}
	tpm->suspended = 1;
	mutex_exit(&tpm->pm_mutex);

	return (DDI_SUCCESS);
}

static int
tpm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	tpm_state_t *tpm;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);
	if (instance < 0)
		return (DDI_FAILURE);

	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (ENXIO);
	}

	switch (cmd) {
	case DDI_DETACH:
		/* Body is after the switch stmt */
		break;
	case DDI_SUSPEND:
		return (tpm_suspend(tpm));
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: case %d not implemented", __func__, cmd);
#endif
		return (DDI_FAILURE);
	}

	/* Since we are freeing tpm structure, we need to gain the lock */
	tpm_cleanup(dip, tpm);

	/* Free the soft state */
	ddi_soft_state_free(statep, instance);
	tpm = NULL;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
tpm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	int instance;
	tpm_state_t *tpm;

	instance = ddi_get_instance(dip);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (DDI_FAILURE);
	}

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = tpm->dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = 0;
		break;
	default:
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: cmd %d is not implemented", __func__,
		    cmd);
#endif
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*
 * Driver entry points
 */

/*ARGSUSED*/
static int
tpm_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	int instance;
	tpm_state_t *tpm;

	ASSERT(devp != NULL);

	instance = getminor(*devp);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (ENXIO);
	}
	if (otyp != OTYP_CHR) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: otyp(%d) != OTYP_CHR(%d)",
		    __func__, otyp, OTYP_CHR);
#endif
		return (EINVAL);
	}
	TPM_EXCLUSIVE_LOCK(tpm);

	mutex_enter(&tpm->dev_lock);
	if (tpm->dev_held) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: the device is already being used",
		    __func__);
#endif
		mutex_exit(&tpm->dev_lock);
		return (EBUSY);
	}

	/* The device is free so mark it busy */
	tpm->dev_held = 1;
	mutex_exit(&tpm->dev_lock);

	return (0);
}

/*ARGSUSED*/
static int
tpm_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	int instance;
	tpm_state_t *tpm;

	instance = getminor(dev);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (ENXIO);
	}
	if (otyp != OTYP_CHR) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: otyp(%d) != OTYP_CHR(%d)",
		    __func__, otyp, OTYP_CHR);
#endif
		return (EINVAL);
	}
	TPM_EXCLUSIVE_LOCK(tpm);

	ASSERT(tpm->dev_held);

	mutex_enter(&tpm->dev_lock);
	ASSERT(mutex_owned(&tpm->dev_lock));
	tpm->dev_held = 0;
	mutex_exit(&tpm->dev_lock);

	return (0);
}

/*ARGSUSED*/
static int
tpm_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int ret;
	uint32_t size;
	int instance;
	tpm_state_t *tpm;

	instance = getminor(dev);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (ENXIO);
	}
	if (uiop == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: passed in uiop is NULL", __func__);
#endif
		return (EFAULT);
	}

	TPM_EXCLUSIVE_LOCK(tpm);

	/* Receive the data after requiring the lock */
	ret = tpm_io_lock(tpm);

	/* Timeout reached */
	if (ret)
		return (ret);

	if (uiop->uio_resid > tpm->bufsize) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: read_in data is bigger "
		    "than tpm->bufsize:read in:%d, bufsiz:%d",
		    __func__, (int)uiop->uio_resid, (int)tpm->bufsize);
#endif
		ret = EIO;
		goto OUT;
	}

	ret = tis_recv_data(tpm, tpm->iobuf, tpm->bufsize);
	if (ret < TPM_HEADER_SIZE) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_recv_data returned error", __func__);
#endif
		ret = EIO;
		goto OUT;
	}

	size = load32(tpm->iobuf, 2);
	if (ret != size) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_recv_data:"
		    "expected size=%d, actually read=%d",
		    __func__, size, ret);
#endif
		ret = EIO;
		goto OUT;
	}

	/* Send the buffer from the kernel to the userspace */
	ret = uiomove(tpm->iobuf, size, UIO_READ, uiop);
	if (ret) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: uiomove returned error", __func__);
#endif
		goto OUT;
	}

	/* Zeroize the buffer... */
	bzero(tpm->iobuf, tpm->bufsize);
	ret = DDI_SUCCESS;
OUT:
	/* We are done now: wake up the waiting threads */
	tpm_unlock(tpm);

	return (ret);
}

/*ARGSUSED*/
static int
tpm_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int ret;
	size_t len;
	uint32_t size;
	int instance;
	tpm_state_t *tpm;

	instance = getminor(dev);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: stored pointer to tpm state is NULL",
		    __func__);
#endif
		return (ENXIO);
	}

	if (uiop == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: passed in uiop is NULL", __func__);
#endif
		return (EFAULT);
	}

	TPM_EXCLUSIVE_LOCK(tpm);

	len = uiop->uio_resid;
	if (len == 0) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: requested read of len 0", __func__);
#endif
		return (0);
	}

	/* Get the lock for using iobuf */
	ret = tpm_io_lock(tpm);
	/* Timeout Reached */
	if (ret)
		return (ret);

	/* Copy the header and parse the structure to find out the size... */
	ret = uiomove(tpm->iobuf, TPM_HEADER_SIZE, UIO_WRITE, uiop);
	if (ret) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: uiomove returned error"
		    "while getting the the header",
		    __func__);
#endif
		goto OUT;
	}

	/* Get the buffersize from the command buffer structure */
	size = load32(tpm->iobuf, TPM_PARAMSIZE_OFFSET);

	/* Copy the command to the contiguous buffer */
	if (size > tpm->bufsize) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: size %d is greater than "
		    "the tpm input buffer size %d",
		    __func__, (int)size, (int)tpm->bufsize);
#endif
		ret = ENXIO;
		goto OUT;
	}

	/* Copy the buffer from the userspace to kernel */
	ret = uiomove(tpm->iobuf+TPM_HEADER_SIZE, size-TPM_HEADER_SIZE,
	    UIO_WRITE, uiop);

	if (ret) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: uiomove returned error"
		    "while getting the rest of the command", __func__);
#endif
		goto OUT;
	}

	/* Send the command */
	ret = tis_send_data(tpm, tpm->iobuf, size);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!%s: tis_send_data returned error", __func__);
#endif
		ret = EFAULT;
		goto OUT;
	}

	/* Zeroize the buffer... */
	bzero(tpm->iobuf, tpm->bufsize);
	ret = DDI_SUCCESS;
OUT:
	tpm_unlock(tpm);
	return (ret);
}

/*
 * This is to deal with the contentions for the iobuf
 */
static inline int
tpm_io_lock(tpm_state_t *tpm)
{
	int ret;
	clock_t timeout;

	mutex_enter(&tpm->iobuf_lock);
	ASSERT(mutex_owned(&tpm->iobuf_lock));

	timeout = ddi_get_lbolt() + drv_usectohz(TPM_IO_TIMEOUT);

	/* Wait until the iobuf becomes free with the timeout */
	while (tpm->iobuf_inuse) {
		ret = cv_timedwait(&tpm->iobuf_cv, &tpm->iobuf_lock, timeout);
		if (ret <= 0) {
			/* Timeout reached */
			mutex_exit(&tpm->iobuf_lock);
#ifdef DEBUG
			cmn_err(CE_WARN, "!tpm_io_lock:iorequest timed out");
#endif
			return (ETIME);
		}
	}
	tpm->iobuf_inuse = 1;
	mutex_exit(&tpm->iobuf_lock);
	return (0);
}

/*
 * This is to deal with the contentions for the iobuf
 */
static inline void
tpm_unlock(tpm_state_t *tpm)
{
	/* Wake up the waiting threads */
	mutex_enter(&tpm->iobuf_lock);
	ASSERT(tpm->iobuf_inuse == 1 && mutex_owned(&tpm->iobuf_lock));
	tpm->iobuf_inuse = 0;
	cv_broadcast(&tpm->iobuf_cv);
	mutex_exit(&tpm->iobuf_lock);
}

#ifdef KCF_TPM_RNG_PROVIDER
/*
 * Random number generator entry points
 */
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
tpmrng_ext_info(crypto_provider_handle_t prov,
    crypto_provider_ext_info_t *ext_info,
    crypto_req_handle_t cfreq)
{
	tpm_state_t *tpm = (tpm_state_t *)prov;
	char buf[64];

	if (tpm == NULL)
		return (DDI_FAILURE);

	strncpy_spacepad(ext_info->ei_manufacturerID,
	    (char *)tpm->vers_info.tpmVendorID,
	    sizeof (ext_info->ei_manufacturerID));

	strncpy_spacepad(ext_info->ei_model, "0",
	    sizeof (ext_info->ei_model));
	strncpy_spacepad(ext_info->ei_serial_number, "0",
	    sizeof (ext_info->ei_serial_number));

	ext_info->ei_flags = CRYPTO_EXTF_RNG | CRYPTO_EXTF_SO_PIN_LOCKED;
	ext_info->ei_max_session_count = CRYPTO_EFFECTIVELY_INFINITE;
	ext_info->ei_max_pin_len = 0;
	ext_info->ei_min_pin_len = 0;
	ext_info->ei_total_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_total_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ext_info->ei_time[0] = 0;

	ext_info->ei_hardware_version.cv_major = tpm->vers_info.version.major;
	ext_info->ei_hardware_version.cv_minor = tpm->vers_info.version.minor;
	ext_info->ei_firmware_version.cv_major =
	    tpm->vers_info.version.revMajor;
	ext_info->ei_firmware_version.cv_minor =
	    tpm->vers_info.version.revMinor;

	(void) snprintf(buf, sizeof (buf), "tpmrng TPM RNG");

	strncpy_spacepad(ext_info->ei_label, buf,
	    sizeof (ext_info->ei_label));
#undef	BUFSZ
	return (CRYPTO_SUCCESS);

}

static int
tpmrng_register(tpm_state_t *tpm)
{
	int		ret;
	char		ID[64];
	crypto_mech_name_t	*rngmech;

	ASSERT(tpm != NULL);

	(void) snprintf(ID, sizeof (ID), "tpmrng %s", IDENT_TPMRNG);

	tpmrng_prov_info.pi_provider_description = ID;
	tpmrng_prov_info.pi_provider_dev.pd_hw = tpm->dip;
	tpmrng_prov_info.pi_provider_handle = tpm;

	ret = crypto_register_provider(&tpmrng_prov_info, &tpm->n_prov);
	if (ret != CRYPTO_SUCCESS) {
		tpm->n_prov = NULL;
		return (DDI_FAILURE);
	}

	crypto_provider_notification(tpm->n_prov, CRYPTO_PROVIDER_READY);

	rngmech = kmem_zalloc(strlen("random") + 1, KM_SLEEP);
	(void) memcpy(rngmech, "random", 6);
	ret = crypto_load_dev_disabled("tpm", ddi_get_instance(tpm->dip),
	    1, rngmech);
#ifdef DEBUG
	if (ret != CRYPTO_SUCCESS)
		cmn_err(CE_WARN, "!crypto_load_dev_disabled failed (%d)", ret);
#endif
	return (DDI_SUCCESS);
}

static int
tpmrng_unregister(tpm_state_t *tpm)
{
	int ret;
	ASSERT(tpm != NULL);
	if (tpm->n_prov) {
		ret = crypto_unregister_provider(tpm->n_prov);
		tpm->n_prov = NULL;
		if (ret != CRYPTO_SUCCESS)
			return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static void
tpmrng_provider_status(crypto_provider_handle_t provider, uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

/*ARGSUSED*/
static int
tpmrng_seed_random(crypto_provider_handle_t provider, crypto_session_id_t sid,
    uchar_t *buf, size_t len, uint_t entropy_est, uint32_t flags,
    crypto_req_handle_t req)
{
	int ret;
	tpm_state_t *tpm;
	uint32_t len32;
	/* Max length of seed is 256 bytes, add 14 for header. */
	uint8_t cmdbuf[270] = {
		0, 193,		/* TPM_TAG_RQU COMMAND */
		0, 0, 0, 0x0A,	/* paramsize in bytes */
		0, 0, 0, TPM_ORD_StirRandom,
		0, 0, 0, 0	/* number of input bytes (< 256) */
	};
	uint32_t buflen;

	if (len == 0 || len > 255 || buf == NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	tpm = (tpm_state_t *)provider;
	if (tpm == NULL)
		return (CRYPTO_INVALID_CONTEXT);

	/* Acquire lock for exclusive use of TPM */
	TPM_EXCLUSIVE_LOCK(tpm);

	ret = tpm_io_lock(tpm);
	/* Timeout reached */
	if (ret)
		return (CRYPTO_BUSY);

	/* TPM only handles 32 bit length, so truncate if too big. */
	len32 = (uint32_t)len;
	buflen = len32 + 14;

	/* The length must be in network order */
	buflen = htonl(buflen);
	bcopy(&buflen, cmdbuf + 2, sizeof (uint32_t));

	/* Convert it back */
	buflen = ntohl(buflen);

	/* length must be in network order */
	len32 = htonl(len32);
	bcopy(&len32, cmdbuf + 10, sizeof (uint32_t));

	/* convert it back */
	len32 = ntohl(len32);

	bcopy(buf,  cmdbuf + 14, len32);

	ret = itpm_command(tpm, cmdbuf, buflen);
	tpm_unlock(tpm);

	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!tpmrng_seed_random failed");
#endif
		return (CRYPTO_FAILED);
	}

	return (CRYPTO_SUCCESS);
}

/* ARGSUSED */
static int
tpmrng_generate_random(crypto_provider_handle_t provider,
    crypto_session_id_t sid, uchar_t *buf, size_t len, crypto_req_handle_t req)
{
	int ret;
	tpm_state_t *tpm;
	uint8_t hdr[14] = {
		0, 193,		/* TPM_TAG_RQU COMMAND */
		0, 0, 0, 14,	/* paramsize in bytes */
		0, 0, 0, TPM_ORD_GetRandom,
		0, 0, 0, 0
	};
	uint8_t *cmdbuf = NULL;
	uint32_t len32 = (uint32_t)len;
	uint32_t buflen = len32 + sizeof (hdr);

	if (len == 0 || buf == NULL)
		return (CRYPTO_ARGUMENTS_BAD);

	tpm = (tpm_state_t *)provider;
	if (tpm == NULL)
		return (CRYPTO_INVALID_CONTEXT);

	TPM_EXCLUSIVE_LOCK(tpm);

	ret = tpm_io_lock(tpm);
	/* Timeout reached */
	if (ret)
		return (CRYPTO_BUSY);

	cmdbuf = kmem_zalloc(buflen, KM_SLEEP);
	bcopy(hdr, cmdbuf, sizeof (hdr));

	/* Length is written in network byte order */
	len32 = htonl(len32);
	bcopy(&len32, cmdbuf + 10, sizeof (uint32_t));

	ret = itpm_command(tpm, cmdbuf, buflen);
	if (ret != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!tpmrng_generate_random failed");
#endif
		kmem_free(cmdbuf, buflen);
		tpm_unlock(tpm);
		return (CRYPTO_FAILED);
	}

	/* Find out how many bytes were really returned */
	len32 = load32(cmdbuf, 10);

	/* Copy the random bytes back to the callers buffer */
	bcopy(cmdbuf + 14, buf, len32);

	kmem_free(cmdbuf, buflen);
	tpm_unlock(tpm);

	return (CRYPTO_SUCCESS);
}
#endif /* KCF_TPM_RNG_PROVIDER */
