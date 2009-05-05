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

#include <tss/platform.h> 	/* from SUNWtss */
#include <tss/tpm.h> 		/* from SUNWtss */

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
static inline int tpm_lock(tpm_state_t *);
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

static void *statep = NULL;

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
	char *myname = "tpm_get_timeout";

	ASSERT(tpm != NULL);

	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: itpm_command failed", myname);
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
		cmn_err(CE_WARN, "%s: capability response size should be %d"
		    "instead it's %d",
		    myname, (int)(4 * sizeof (uint32_t)), (int)len);
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
tpm_get_duration(tpm_state_t *tpm) {
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
	char *myname = "tpm_get_duration";

	ASSERT(tpm != NULL);

	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: itpm_command failed with ret code: 0x%x",
			myname, ret);
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
		cmn_err(CE_WARN, "%s: capability response should be %d, "
		    "instead, it's %d",
		    myname, (int)(3 * sizeof (uint32_t)), (int)len);
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
tpm_get_version(tpm_state_t *tpm) {
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
	char *myname = "tpm_get_version";

	ASSERT(tpm != NULL);

	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: itpm_command failed with ret code: 0x%x",
			myname, ret);
		return (DDI_FAILURE);
	}

	/*
	 * Get the length of the returned buffer.
	 */
	len = load32(buf, TPM_CAP_RESPSIZE_OFFSET);
	if (len < TPM_CAP_VERSION_INFO_SIZE) {
		cmn_err(CE_WARN, "%s: capability response should be greater"
		    " than %d, instead, it's %d",
		    myname,
		    TPM_CAP_VERSION_INFO_SIZE,
		    len);
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
		cmn_err(CE_WARN, "%s: Unsupported TPM version (%d.%d)",
		    myname,
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
tpm_continue_selftest(tpm_state_t *tpm) {
	int ret;
	uint8_t buf[10] = {
		0, 193,		/* TPM_TAG_RQU COMMAND */
		0, 0, 0, 10,	/* paramsize in bytes */
		0, 0, 0, 83	/* TPM_ORD_ContinueSelfTest */
	};
	char *myname = "tpm_continue_selftest";

	/* Need a longer timeout */
	ret = itpm_command(tpm, buf, sizeof (buf));
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: itpm_command failed", myname);
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
	char *myname = "tpm_get_ordinal_duration";

	ASSERT(tpm != NULL);

	/* Default and failure case for IFX */
	/* Is it a TSC_ORDINAL? */
	if (ordinal & TSC_ORDINAL_MASK) {
		if (ordinal > TSC_ORDINAL_MAX) {
			cmn_err(CE_WARN,
			    "%s: tsc ordinal: %d exceeds MAX: %d",
			    myname, ordinal, TSC_ORDINAL_MAX);
			return (0);
		}
		index = tsc_ords_duration[ordinal];
	} else {
		if (ordinal > TPM_ORDINAL_MAX) {
			cmn_err(CE_WARN,
			    "%s: ordinal %d exceeds MAX: %d",
			    myname, ordinal, TPM_ORDINAL_MAX);
			return (0);
		}
		index = tpm_ords_duration[ordinal];
	}

	if (index > TPM_DURATION_MAX_IDX) {
		cmn_err(CE_WARN, "%s: FATAL:index '%d' is out of bound",
		    myname, index);
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
	char *myname = "itpm_command";

	ASSERT(tpm != NULL && buf != NULL);

	/* The byte order is network byte order so convert it */
	count = load32(buf, TPM_PARAMSIZE_OFFSET);

	if (count == 0) {
		cmn_err(CE_WARN, "%s: count=0, no data? %d", myname,
		    (int)bufsiz);
		return (DDI_FAILURE);
	}
	if (count > bufsiz) {
		cmn_err(CE_WARN, "%s: invalid count value:count:%d > bufsiz %d",
		    myname, (int)count, (int)bufsiz);
		return (DDI_FAILURE);
	}

	/* Send the command */
	ret = tis_send_data(tpm, buf, count);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tis_send_data failed with error %x",
		    myname, ret);
		return (DDI_FAILURE);
	}

	/*
	 * Now receive the data from the tpm
	 * Should at least receive "the common" 10 bytes (TPM_HEADER_SIZE)
	 */
	ret = tis_recv_data(tpm, buf, bufsiz);
	if (ret < TPM_HEADER_SIZE) {
		cmn_err(CE_WARN, "%s: tis_recv_data failed", myname);
		return (DDI_FAILURE);
	}

	/* Check the return code */
	ret = load32(buf, TPM_RETURN_OFFSET);
	if (ret != TPM_SUCCESS) {
		cmn_err(CE_WARN, "%s: command failed with ret code: %x",
		    myname, ret);
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
tpm_get_burstcount(tpm_state_t *tpm) {
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
		burstcnt = ddi_get8(tpm->handle,
		    (uint8_t *)(tpm->addr+
		    TPM_STS_(tpm->locality)+1));
		burstcnt += ddi_get8(tpm->handle,
		    (uint8_t *)(tpm->addr+
		    TPM_STS_(tpm->locality)+2)) << 8;

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
tpm_set_ready(tpm_state_t *tpm) {
	ASSERT(tpm != NULL);

	ddi_put8(tpm->handle,
	    (uint8_t *)(tpm->addr+TPM_STS_(tpm->locality)),
	    TPM_STS_CMD_READY);
}

static int
receive_data(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz) {
	int size = 0;
	int retried = 0;
	uint8_t stsbits;

	/* A number of consecutive bytes that can be written to TPM */
	uint16_t burstcnt;

	ASSERT(tpm != NULL && buf != NULL);
retry:
	while (size < bufsiz &&
		(tpm_wait_for_stat(tpm,
		    (TPM_STS_DATA_AVAIL|TPM_STS_VALID),
		    (ddi_get_lbolt() + tpm->timeout_c)) == DDI_SUCCESS)) {
		/*
		 * Burstcount should be available within TIMEOUT_D
		 * after STS is set to valid
		 * burstcount is dynamic, so have to get it each time
		 */
		burstcnt = tpm_get_burstcount(tpm);
		for (; burstcnt > 0 && size < bufsiz; burstcnt--) {
			buf[size++] = ddi_get8(tpm->handle,
			    (uint8_t *)(tpm->addr +
			    TPM_DATA_FIFO_(tpm->locality)));
		}
	}
	stsbits = tis_get_status(tpm);
	/* check to see if we need to retry (just once) */
	if (size < bufsiz && !(stsbits & TPM_STS_DATA_AVAIL) && retried == 0) {
		/* issue responseRetry (TIS 1.2 pg 54) */
		ddi_put8(tpm->handle,
		    (uint8_t *)(tpm->addr+TPM_STS_(tpm->locality)),
		    TPM_STS_RESPONSE_RETRY);
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
tis_recv_data(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz) {
	int ret;
	int size = 0;
	uint32_t expected, status;
	uint32_t cmdresult;
	char *myname = "tis_recv_data";

	ASSERT(tpm != NULL && buf != NULL);

	if (bufsiz < TPM_HEADER_SIZE) {
		/* There should be at least tag,paramsize,return code */
		cmn_err(CE_WARN, "%s: received data should contain at least "
		    "the header which is %d bytes long",
		    myname, TPM_HEADER_SIZE);
		goto OUT;
	}

	/* Read tag(2 bytes), paramsize(4), and result(4) */
	size = receive_data(tpm, buf, TPM_HEADER_SIZE);
	if (size < TPM_HEADER_SIZE) {
		cmn_err(CE_WARN, "%s: getting the TPM_HEADER failed: size=%d",
		    myname, size);
		goto OUT;
	}

	cmdresult = load32(buf, TPM_RETURN_OFFSET);

	/* Get 'paramsize'(4 bytes)--it includes tag and paramsize */
	expected = load32(buf, TPM_PARAMSIZE_OFFSET);
	if (expected > bufsiz) {
		cmn_err(CE_WARN, "%s: paramSize is bigger "
		    "than the requested size: paramSize=%d bufsiz=%d result=%d",
		    myname, (int)expected, (int)bufsiz, cmdresult);
		goto OUT;
	}

	/* Read in the rest of the data from the TPM */
	size += receive_data(tpm, (uint8_t *)&buf[TPM_HEADER_SIZE],
	    expected - TPM_HEADER_SIZE);
	if (size < expected) {
		cmn_err(CE_WARN, "%s: received data length=%d "
		    "is less than expected = %d", myname, size, expected);
		goto OUT;
	}

	/* The TPM MUST set the state to stsValid within TIMEOUT_C */
	ret = tpm_wait_for_stat(tpm, TPM_STS_VALID,
	    ddi_get_lbolt() + tpm->timeout_c);

	status = tis_get_status(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: TPM didn't set stsValid after its I/O: "
		    "status = 0x%08X", myname, status);
		goto OUT;
	}

	/* There is still more data? */
	if (status & TPM_STS_DATA_AVAIL) {
		cmn_err(CE_WARN, "%s: Status TPM_STS_DATA_AVAIL set:0x%08X",
		    myname, status);
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
tis_send_data(tpm_state_t *tpm, uint8_t *buf, size_t bufsiz) {
	int ret;
	uint8_t status;
	uint16_t burstcnt;
	uint32_t ordinal;
	size_t count = 0;
	char *myname = "tis_send_data";

	ASSERT(tpm != NULL && buf != NULL);

	if (bufsiz == 0) {
		cmn_err(CE_WARN, "%s: passed in argument bufsize is zero",
		    myname);
		return (DDI_FAILURE);
	}

	/* Be in the right locality (aren't we always in locality 0?) */
	if (tis_request_locality(tpm, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tis_request_locality didn't enter "
		    "locality 0", myname);
		return (DDI_FAILURE);
	}

	/* Put the TPM in ready state */
	status = tis_get_status(tpm);

	if (!(status & TPM_STS_CMD_READY)) {
		tpm_set_ready(tpm);
		ret = tpm_wait_for_stat(tpm,
		    TPM_STS_CMD_READY,
		    (ddi_get_lbolt() + tpm->timeout_b));
		if (ret != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: could not put the TPM "
			    "in the command ready state:"
			    "tpm_wait_for_stat returned error",
			    myname);
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
			cmn_err(CE_WARN, "%s: tpm_get_burstcnt returned error",
			    myname);
			ret = DDI_FAILURE;
			goto FAIL;
		}

		for (; burstcnt > 0 && count < bufsiz - 1; burstcnt--) {
			ddi_put8(tpm->handle, (uint8_t *)(tpm->addr+
			    TPM_DATA_FIFO_(tpm->locality)), buf[count]);
			count++;
		}
		/* Wait for TPM to indicate that it is ready for more data */
		ret = tpm_wait_for_stat(tpm,
		    (TPM_STS_VALID | TPM_STS_DATA_EXPECT),
		    (ddi_get_lbolt() + tpm->timeout_c));
		if (ret != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: TPM didn't enter stsvalid "
			    "state after sending the data:", myname);
			goto FAIL;
		}
	}
	/* We can't exit the loop above unless we wrote bufsiz-1 bytes */

	/* Write last byte */
	ddi_put8(tpm->handle, (uint8_t *)(tpm->addr +
	    TPM_DATA_FIFO_(tpm->locality)), buf[count]);
	count++;

	/* Wait for the TPM to enter Valid State */
	ret = tpm_wait_for_stat(tpm,
	    TPM_STS_VALID, (ddi_get_lbolt() + tpm->timeout_c));
	if (ret == DDI_FAILURE) {
		cmn_err(CE_WARN, "%s: tpm didn't enter Valid state", myname);
		goto FAIL;
	}

	status = tis_get_status(tpm);
	/* The TPM should NOT be expecing more data at this point */
	if ((status & TPM_STS_DATA_EXPECT) != 0) {
		cmn_err(CE_WARN, "%s: DATA_EXPECT is set (shouldn't be) after "
		    "writing the last byte: status=0x%08X", myname, status);
		ret = DDI_FAILURE;
		goto FAIL;
	}

	/*
	 * Final step: Writing TPM_STS_GO to TPM_STS
	 * register will actually send the command.
	 */
	ddi_put8(tpm->handle, (uint8_t *)(tpm->addr+TPM_STS_(tpm->locality)),
	    TPM_STS_GO);

	/* Ordinal/Command_code is located in buf[6..9] */
	ordinal = load32(buf, TPM_COMMAND_CODE_OFFSET);

	ret = tpm_wait_for_stat(tpm, TPM_STS_DATA_AVAIL | TPM_STS_VALID,
	    ddi_get_lbolt() + tpm_get_ordinal_duration(tpm, ordinal));
	if (ret == DDI_FAILURE) {
		status = tis_get_status(tpm);
		if (!(status & TPM_STS_DATA_AVAIL) ||
		    !(status & TPM_STS_VALID)) {
			cmn_err(CE_WARN, "%s: TPM not ready or valid "
			    "(ordinal = %d timeout = %ld)",
			    myname, ordinal,
			    tpm_get_ordinal_duration(tpm, ordinal));
		} else {
			cmn_err(CE_WARN, "%s: tpm_wait_for_stat "
			    "(DATA_AVAIL | VALID) failed: STS = 0x%0X",
			    myname, status);
		}
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
tis_release_locality(tpm_state_t *tpm, char locality, int force) {
	ASSERT(tpm != NULL && locality >= 0 && locality < 5);

	if (force ||
	    (ddi_get8(tpm->handle,
		(uchar_t *)(tpm->addr+TPM_ACCESS_(locality)))
	    & (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID))
	    == (TPM_ACCESS_REQUEST_PENDING | TPM_ACCESS_VALID)) {
		/*
		 * Writing 1 to active locality bit in TPM_ACCESS
		 * register reliquishes the control of the locality
		 */
		ddi_put8(tpm->handle,
		    (uint8_t *)(tpm->addr+TPM_ACCESS_(locality)),
		    TPM_ACCESS_ACTIVE_LOCALITY);
	}
}

/*
 * Checks whether the given locality is active
 * Use TPM_ACCESS register and the masks TPM_ACCESS_VALID,TPM_ACTIVE_LOCALITY
 */
static int
tis_check_active_locality(tpm_state_t *tpm, char locality) {
	uint8_t access_bits;

	ASSERT(tpm != NULL && locality >= 0 && locality < 5);

	access_bits = ddi_get8(tpm->handle,
	    (uint8_t *)(tpm->addr+TPM_ACCESS_(locality)));
	access_bits &= (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID);

	if (access_bits == (TPM_ACCESS_ACTIVE_LOCALITY | TPM_ACCESS_VALID))
		return (DDI_SUCCESS);
	else
		return (DDI_FAILURE);
}

/* Request the TPM to be in the given locality */
static int
tis_request_locality(tpm_state_t *tpm, char locality) {
	clock_t timeout;
	int ret;
	char *myname = "tis_request_locality";

	ASSERT(tpm != NULL && locality >= 0 && locality < 5);

	ret = tis_check_active_locality(tpm, locality);

	if (ret == DDI_SUCCESS) {
		/* Locality is already active */
		tpm->locality = locality;
		return (DDI_SUCCESS);
	}

	ddi_put8(tpm->handle, tpm->addr+TPM_ACCESS_(locality),
	    TPM_ACCESS_REQUEST_USE);
	timeout = ddi_get_lbolt() + tpm->timeout_a;

	/* Using polling */
	while (tis_check_active_locality(tpm, locality)
		!= DDI_SUCCESS) {
		if (ddi_get_lbolt() >= timeout) {
			cmn_err(CE_WARN, "%s (interrupt-disabled) "
			    "tis_request_locality timed out",
			    myname);
			return (DDI_FAILURE);
		}
		delay(tpm->timeout_poll);
	}

	tpm->locality = locality;
	return (DDI_SUCCESS);
}

/* Read the status register */
static uint8_t
tis_get_status(tpm_state_t *tpm) {
	return (ddi_get8(tpm->handle,
	    (uint8_t *)(tpm->addr+TPM_STS_(tpm->locality))));
}

static int
tpm_wait_for_stat(tpm_state_t *tpm, uint8_t mask, clock_t absolute_timeout) {
	char *myname = "tpm_wait_for_stat";

	/* Using polling */
	while ((tis_get_status(tpm) & mask) != mask) {
		if (ddi_get_lbolt() >= absolute_timeout) {
			/* Timeout reached */
			cmn_err(CE_WARN, "%s: using "
			    "polling:reached timeout",
			    myname);
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
tis_init(tpm_state_t *tpm) {
	uint32_t intf_caps;
	int ret;
	char *myname = "tis_init";
	uintptr_t aptr = (uintptr_t)tpm->addr;

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
	intf_caps = ddi_get32(tpm->handle,
	    (uint32_t *)(aptr + TPM_INTF_CAP_(0)));

	/* Upper 3 bytes should always return 0 */
	if (intf_caps & 0x7FFFFF00) {
#ifdef DEBUG
		cmn_err(CE_WARN, "%s: bad intf_caps value 0x%0X",
		    myname, intf_caps);
#endif
		return (DDI_FAILURE);
	}

	/* These two interrupts are mandatory */
	if (!(intf_caps & TPM_INTF_INT_LOCALITY_CHANGE_INT)) {
		cmn_err(CE_WARN, "%s: Mandatory capability Locality Change Int "
		    "not supported", myname);
		return (DDI_FAILURE);
	}
	if (!(intf_caps & TPM_INTF_INT_DATA_AVAIL_INT)) {
		cmn_err(CE_WARN, "%s: Mandatory capability Data Available Int "
		    "not supported", myname);
		return (DDI_FAILURE);
	}

	/*
	 * Before we start writing anything to TPM's registers,
	 * make sure we are in locality 0
	 */
	ret = tis_request_locality(tpm, 0);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: Unable to request locality 0", myname);
		return (DDI_FAILURE);
	} /* Now we can refer to the locality as tpm->locality */

	tpm->timeout_poll = drv_usectohz(TPM_POLLING_TIMEOUT);
	tpm->intr_enabled = 0;

	/* Get the real timeouts from the TPM */
	ret = tpm_get_timeouts(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tpm_get_timeouts error", myname);
		return (DDI_FAILURE);
	}

	ret = tpm_get_duration(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tpm_get_duration error", myname);
		return (DDI_FAILURE);
	}

	/* This gets the TPM version information */
	ret = tpm_get_version(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tpm_get_version error", myname);
		return (DDI_FAILURE);
	}

	/*
	 * Unless the TPM completes the test of its commands,
	 * it can return an error when the untested commands are called
	 */
	ret = tpm_continue_selftest(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tpm_continue_selftest error", myname);
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
	if (ret)
		return (ret);

	ret = mod_install(&tpm_ml);
	if (ret != 0) {
		cmn_err(CE_WARN, "_init: mod_install returned non-zero");
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
	if (ret == 0)
		cmn_err(CE_WARN, "mod_info failed: %d", ret);

	return (ret);
}

int
_fini()
{
	int ret;
	ret = mod_remove(&tpm_ml);
	if (ret != 0) {
		return (ret);
	}
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

/*
 * Sun DDI/DDK entry points
 */
static int
tpm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret, idx;
	int instance;
	int nregs;
	char *myname = "tpm_attach";
	tpm_state_t *tpm = NULL;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);

	/* Nothing out of ordinary here */
	switch (cmd) {
	case DDI_ATTACH:
		ret = ddi_soft_state_zalloc(statep, instance);
		if (ret != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s could not allocate tpm_state_t",
			    myname);
			goto FAIL;
		}
		tpm = ddi_get_soft_state(statep, instance);
		tpm->dip = dip;
		break;
	case DDI_RESUME:
		tpm = ddi_get_soft_state(statep, instance);
		if (tpm == NULL) {
			cmn_err(CE_WARN, "%s: tpm_state_t is NULL",
			    myname);
			goto FAIL;
		}
		return (tpm_resume(tpm));
	default:
		cmn_err(CE_WARN, "%s: cmd %d is not implemented", myname, cmd);
		ret = DDI_FAILURE;
		goto FAIL;
	}

	/* Zeroize the flag, which is used to keep track of what is allocated */
	tpm->flags = 0;

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
	if (idx == nregs)
		return (DDI_FAILURE);

	ret = ddi_regs_map_setup(tpm->dip, idx, (caddr_t *)&tpm->addr,
	    (offset_t)0, (offset_t)0x5000,
	    &tpm->accattr, &tpm->handle);

	if (ret != DDI_SUCCESS) {
		goto FAIL;
	}
	tpm->flags |= TPM_DIDREGSMAP;

	/* Enable TPM device according to the TIS specification */
	ret = tis_init(tpm);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tis_init() failed ret: %d",
		    myname, ret);

		/* We need to clean up the ddi_regs_map_setup call */
		ddi_regs_map_free(&tpm->handle);
		tpm->handle = NULL;
		tpm->flags &= ~TPM_DIDREGSMAP;
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
	if (tpm->iobuf == NULL) {
		cmn_err(CE_WARN, "%s: failed to allocate iobuf", myname);
		goto FAIL;
	}
	tpm->flags |= TPM_DID_IO_ALLOC;

	mutex_init(&tpm->iobuf_lock, NULL, MUTEX_DRIVER, NULL);
	tpm->flags |= TPM_DID_IO_MUTEX;

	cv_init(&tpm->iobuf_cv, NULL, CV_DRIVER, NULL);
	tpm->flags |= TPM_DID_IO_CV;

	/* Create minor node */
	ret = ddi_create_minor_node(dip, "tpm", S_IFCHR, ddi_get_instance(dip),
	    DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: ddi_create_minor_node failed", myname);
		goto FAIL;
	}
	tpm->flags |= TPM_DIDMINOR;

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

	if (tpm->flags & TPM_DID_MUTEX) {
		mutex_destroy(&tpm->dev_lock);
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
	char *myname = "tpm_detach";
	int instance;
	tpm_state_t *tpm;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
		cmn_err(CE_WARN, "%s: stored pointer to tpm state is NULL",
		    myname);
		return (ENXIO);
	}

	switch (cmd) {
	case DDI_DETACH:
		/* Body is after the switch stmt */
		break;
	case DDI_SUSPEND:
		return (tpm_suspend(tpm));
	default:
		cmn_err(CE_WARN, "%s: case %d not implemented", myname, cmd);
		return (DDI_FAILURE);
	}

	/* Since we are freeing tpm structure, we need to gain the lock */

	tpm_cleanup(dip, tpm);

	mutex_destroy(&tpm->pm_mutex);
	cv_destroy(&tpm->suspend_cv);

	/* Free the soft state */
	ddi_soft_state_free(statep, instance);
	tpm = NULL;

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
tpm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	char *myname = "tpm_getinfo";
	int instance;
	tpm_state_t *tpm;

	instance = ddi_get_instance(dip);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
		cmn_err(CE_WARN, "%s: stored pointer to tpm state is NULL",
		    myname);
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
		cmn_err(CE_WARN, "%s: cmd %d is not implemented", myname, cmd);
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
	char *myname = "tpm_open";
	int instance;
	tpm_state_t *tpm;

	ASSERT(devp != NULL);

	instance = getminor(*devp);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
		cmn_err(CE_WARN, "%s: stored pointer to tpm state is NULL",
		    myname);
		return (ENXIO);
	}
	if (otyp != OTYP_CHR) {
		cmn_err(CE_WARN, "%s: otyp(%d) != OTYP_CHR(%d)",
		    myname, otyp, OTYP_CHR);
		return (EINVAL);
	}
	mutex_enter(&tpm->pm_mutex);
	while (tpm->suspended)
		cv_wait(&tpm->suspend_cv, &tpm->pm_mutex);
	mutex_exit(&tpm->pm_mutex);

	mutex_enter(&tpm->dev_lock);
	if (tpm->dev_held) {
		cmn_err(CE_WARN, "%s: the device is already being used",
		    myname);
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
	char *myname = "tpm_close";
	int instance;
	tpm_state_t *tpm;

	instance = getminor(dev);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
		cmn_err(CE_WARN, "%s: stored pointer to tpm state is NULL",
		    myname);
		return (ENXIO);
	}
	if (otyp != OTYP_CHR) {
		cmn_err(CE_WARN, "%s: otyp(%d) != OTYP_CHR(%d)",
		    myname, otyp, OTYP_CHR);
		return (EINVAL);
	}
	mutex_enter(&tpm->pm_mutex);
	while (tpm->suspended)
		cv_wait(&tpm->suspend_cv, &tpm->pm_mutex);
	mutex_exit(&tpm->pm_mutex);

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
	char *myname = "tpm_read";
	int instance;
	tpm_state_t *tpm;

	instance = getminor(dev);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
		cmn_err(CE_WARN, "%s: stored pointer to tpm state is NULL",
		    myname);
		return (ENXIO);
	}
	if (uiop == NULL) {
		cmn_err(CE_WARN, "%s: passed in uiop is NULL", myname);
		return (EFAULT);
	}

	mutex_enter(&tpm->pm_mutex);
	while (tpm->suspended)
		cv_wait(&tpm->suspend_cv, &tpm->pm_mutex);
	mutex_exit(&tpm->pm_mutex);

	/* Receive the data after requiring the lock */
	ret = tpm_lock(tpm);

	/* Timeout reached */
	if (ret == ETIME)
		return (ret);

	if (uiop->uio_resid > tpm->bufsize) {
		cmn_err(CE_WARN, "%s: read_in data is bigger "
		    "than tpm->bufsize:read in:%d, bufsiz:%d",
		    myname, (int)uiop->uio_resid, (int)tpm->bufsize);
		ret = EIO;
		goto OUT;
	}

	ret = tis_recv_data(tpm, tpm->iobuf, tpm->bufsize);
	if (ret < TPM_HEADER_SIZE) {
		cmn_err(CE_WARN, "%s: tis_recv_data returned error", myname);
		ret = EIO;
		goto OUT;
	}

	size = load32(tpm->iobuf, 2);
	if (ret != size) {
		cmn_err(CE_WARN, "%s: tis_recv_data:"
		    "expected size=%d, actually read=%d",
		    myname, size, ret);
		ret = EIO;
		goto OUT;
	}

	/* Send the buffer from the kernel to the userspace */
	ret = uiomove(tpm->iobuf, size, UIO_READ, uiop);
	if (ret) {
		cmn_err(CE_WARN, "%s: uiomove returned error", myname);
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
	char *myname = "tpm_write";
	int instance;
	tpm_state_t *tpm;

	instance = getminor(dev);
	if ((tpm = ddi_get_soft_state(statep, instance)) == NULL) {
		cmn_err(CE_WARN, "%s: stored pointer to tpm state is NULL",
		    myname);
		return (ENXIO);
	}

	if (uiop == NULL) {
		cmn_err(CE_WARN, "%s: passed in uiop is NULL", myname);
		return (EFAULT);
	}

	mutex_enter(&tpm->pm_mutex);
	while (tpm->suspended)
		cv_wait(&tpm->suspend_cv, &tpm->pm_mutex);
	mutex_exit(&tpm->pm_mutex);

	len = uiop->uio_resid;
	if (len == 0) {
		cmn_err(CE_WARN, "%s: requested read of len 0", myname);
		return (0);
	}

	/* Get the lock for using iobuf */
	ret = tpm_lock(tpm);
	/* Timeout Reached */
	if (ret == ETIME)
		return (ret);

	/* Copy the header and parse the structure to find out the size... */
	ret = uiomove(tpm->iobuf, TPM_HEADER_SIZE, UIO_WRITE, uiop);
	if (ret) {
		cmn_err(CE_WARN, "%s: uiomove returned error"
		    "while getting the the header",
		    myname);
		goto OUT;
	}

	/* Get the buffersize from the command buffer structure */
	size = load32(tpm->iobuf, TPM_PARAMSIZE_OFFSET);

	/* Copy the command to the contiguous buffer */
	if (size > tpm->bufsize) {
		cmn_err(CE_WARN, "%s: size %d is greater than "
		    "the tpm's input buffer size %d",
		    myname, (int)size, (int)tpm->bufsize);
		ret = ENXIO;
		goto OUT;
	}

	/* Copy the buffer from the userspace to kernel */
	ret = uiomove(tpm->iobuf+TPM_HEADER_SIZE, size-TPM_HEADER_SIZE,
	    UIO_WRITE, uiop);

	if (ret) {
		cmn_err(CE_WARN, "%s: uiomove returned error"
		    "while getting the rest of the command", myname);
		goto OUT;
	}

	/* Send the command */
	ret = tis_send_data(tpm, tpm->iobuf, size);
	if (ret != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s: tis_send_data returned error", myname);
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
tpm_lock(tpm_state_t *tpm)
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
			cmn_err(CE_WARN, "tpm_lock:iorequest timed out");
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
