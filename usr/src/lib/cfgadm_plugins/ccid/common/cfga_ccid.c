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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * CCID cfgadm plugin
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include <sys/usb/clients/ccid/uccid.h>

#define	CFGA_PLUGIN_LIB
#include <config_admin.h>

int cfga_version = CFGA_HSL_V2;

static cfga_err_t
cfga_ccid_error(cfga_err_t err, char **errp, const char *fmt, ...)
{
	va_list ap;

	if (errp == NULL)
		return (err);

	/*
	 * Try to format a string. However because we have to return allocated
	 * memory, if this fails, then we have no error.
	 */
	va_start(ap, fmt);
	(void) vasprintf(errp, fmt, ap);
	va_end(ap);

	return (err);
}

cfga_err_t
cfga_ccid_modify(uccid_cmd_icc_modify_t *modify, const char *ap,
    struct cfga_confirm *confp, struct cfga_msg *msgp, char **errp,
    boolean_t force)
{
	int fd;
	uccid_cmd_status_t ucs;
	uccid_cmd_txn_begin_t begin;
	boolean_t held = B_FALSE;

	/*
	 * Check ap is valid by doing a status request.
	 */
	if ((fd = open(ap, O_RDWR)) < 0) {
		return (cfga_ccid_error(CFGA_LIB_ERROR, errp,
		    "failed to open %s: %s", ap, strerror(errno)));
	}

	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;

	if (ioctl(fd, UCCID_CMD_STATUS, &ucs) != 0) {
		int e = errno;
		if (errno == ENODEV) {
			(void) close(fd);
			return (cfga_ccid_error(CFGA_LIB_ERROR, errp,
			    "ap %s going away", ap));
		}
		(void) close(fd);
		return (cfga_ccid_error(CFGA_ERROR, errp,
		    "ioctl on ap %s failed: %s", ap, strerror(e)));
	}

	/*
	 * Attempt to get a hold. If we cannot obtain a hold, we will not
	 * perform this unless the user has said we should force this.
	 */
	bzero(&begin, sizeof (begin));
	begin.uct_version = UCCID_CURRENT_VERSION;
	begin.uct_flags = UCCID_TXN_DONT_BLOCK;
	if (ioctl(fd, UCCID_CMD_TXN_BEGIN, &begin) != 0) {
		if (errno != EBUSY) {
			int e = errno;
			(void) close(fd);
			return (cfga_ccid_error(CFGA_ERROR, errp, "failed to "
			    "begin ccid transaction on ap %s: %s", ap,
			    strerror(e)));
		}

		/*
		 * If the user didn't force this operation, prompt if we would
		 * interfere.
		 */
		if (!force) {
			int confirm = 0;
			const char *prompt = "CCID slot is held exclusively "
			    "by another program.  Proceeding may interrupt "
			    "their functionality. Continue?";
			if (confp != NULL && confp->appdata_ptr != NULL) {
				confirm = (*confp->confirm)(confp->appdata_ptr,
				    prompt);
			}

			if (confirm == 0) {
				(void) close(fd);
				return (CFGA_NACK);
			}
		}
	} else {
		held = B_TRUE;
	}

	if (ioctl(fd, UCCID_CMD_ICC_MODIFY, modify) != 0) {
		int e = errno;
		(void) close(fd);
		return (cfga_ccid_error(CFGA_ERROR, errp,
		    "failed to modify state on ap %s: %s", ap,
		    strerror(e)));
	}

	if (held) {
		uccid_cmd_txn_end_t end;

		bzero(&end, sizeof (end));
		end.uct_version = UCCID_CURRENT_VERSION;
		end.uct_flags = UCCID_TXN_END_RELEASE;

		if (ioctl(fd, UCCID_CMD_TXN_END, &end) != 0) {
			int e = errno;
			(void) close(fd);
			return (cfga_ccid_error(CFGA_ERROR, errp, "failed to "
			    "end transaction on ap %s: %s", ap,
			    strerror(e)));
		}
	}

	(void) close(fd);
	return (CFGA_OK);

}

cfga_err_t
cfga_change_state(cfga_cmd_t cmd, const char *ap, const char *opts,
    struct cfga_confirm *confp, struct cfga_msg *msgp, char **errp,
    cfga_flags_t flags)
{
	uccid_cmd_icc_modify_t modify;

	if (errp != NULL) {
		*errp = NULL;
	}

	if (ap == NULL) {
		return (cfga_ccid_error(CFGA_APID_NOEXIST, errp, NULL));
	}

	if (opts != NULL) {
		return (cfga_ccid_error(CFGA_ERROR, errp,
		    "hardware specific options are not supported"));
	}

	bzero(&modify, sizeof (modify));
	modify.uci_version = UCCID_CURRENT_VERSION;
	switch (cmd) {
	case CFGA_CMD_CONFIGURE:
		modify.uci_action = UCCID_ICC_POWER_ON;
		break;
	case CFGA_CMD_UNCONFIGURE:
		modify.uci_action = UCCID_ICC_POWER_OFF;
		break;
	default:
		(void) cfga_help(msgp, opts, flags);
		return (CFGA_OPNOTSUPP);
	}

	return (cfga_ccid_modify(&modify, ap, confp, msgp, errp,
	    (flags & CFGA_FLAG_FORCE) != 0));
}

cfga_err_t
cfga_private_func(const char *function, const char *ap, const char *opts,
    struct cfga_confirm *confp, struct cfga_msg *msgp, char **errp,
    cfga_flags_t flags)
{
	uccid_cmd_icc_modify_t modify;

	if (errp != NULL) {
		*errp = NULL;
	}

	if (function == NULL) {
		return (CFGA_ERROR);
	}

	if (ap == NULL) {
		return (cfga_ccid_error(CFGA_APID_NOEXIST, errp, NULL));
	}

	if (opts != NULL) {
		return (cfga_ccid_error(CFGA_ERROR, errp,
		    "hardware specific options are not supported"));
	}

	if (strcmp(function, "warm_reset") != 0) {
		return (CFGA_OPNOTSUPP);
	}

	bzero(&modify, sizeof (modify));
	modify.uci_version = UCCID_CURRENT_VERSION;
	modify.uci_action = UCCID_ICC_WARM_RESET;

	return (cfga_ccid_modify(&modify, ap, confp, msgp, errp,
	    (flags & CFGA_FLAG_FORCE) != 0));
}

/*
 * We don't support the test entry point for CCID.
 */
cfga_err_t
cfga_test(const char *ap, const char *opts, struct cfga_msg *msgp, char **errp,
    cfga_flags_t flags)
{
	(void) cfga_help(msgp, opts, flags);
	return (CFGA_OPNOTSUPP);
}

static void
cfga_ccid_fill_info(const uccid_cmd_status_t *ucs, char *buf, size_t len)
{
	const char *product, *serial, *tran, *prot;
	uint_t bits = CCID_CLASS_F_TPDU_XCHG | CCID_CLASS_F_SHORT_APDU_XCHG |
	    CCID_CLASS_F_EXT_APDU_XCHG;

	if ((ucs->ucs_status & UCCID_STATUS_F_PRODUCT_VALID) != 0) {
		product = ucs->ucs_product;
	} else {
		product = "<unknown>";
	}

	if ((ucs->ucs_status & UCCID_STATUS_F_SERIAL_VALID) != 0) {
		serial = ucs->ucs_serial;
	} else {
		serial = "<unknown>";
	}

	switch (ucs->ucs_class.ccd_dwFeatures & bits) {
	case 0:
		tran = "Character";
		break;
	case CCID_CLASS_F_TPDU_XCHG:
		tran = "TPDU";
		break;
	case CCID_CLASS_F_SHORT_APDU_XCHG:
	case CCID_CLASS_F_EXT_APDU_XCHG:
		tran = "APDU";
		break;
	default:
		tran = "Unknown";
		break;
	}

	if ((ucs->ucs_status & UCCID_STATUS_F_PARAMS_VALID) != 0) {
		switch (ucs->ucs_prot) {
		case UCCID_PROT_T0:
			prot = " (T=0)";
			break;
		case UCCID_PROT_T1:
			prot = " (T=1)";
			break;
		default:
			prot = "<unknown>";
			break;
		}
	} else {
		prot = "<unknown>";
	}

	if ((ucs->ucs_status & UCCID_STATUS_F_CARD_ACTIVE) != 0) {
		(void) snprintf(buf, len, "Product: %s Serial: %s "
		    "Transport: %s Protocol: %s", product, serial,
		    tran, prot);
	} else {
		(void) snprintf(buf, len, "Product: %s Serial: %s ",
		    product, serial);
	}
}

cfga_err_t
cfga_list_ext(const char *ap, struct cfga_list_data **ap_list, int *nlist,
    const char *opts, const char *listopts, char **errp, cfga_flags_t flags)
{
	int fd;
	uccid_cmd_status_t ucs;
	struct cfga_list_data *cld;

	if (errp != NULL) {
		*errp = NULL;
	}

	if (ap == NULL) {
		return (cfga_ccid_error(CFGA_APID_NOEXIST, errp, NULL));
	}

	if (opts != NULL) {
		return (cfga_ccid_error(CFGA_ERROR, errp,
		    "hardware specific options are not supported"));
	}

	if ((fd = open(ap, O_RDWR)) < 0) {
		return (cfga_ccid_error(CFGA_LIB_ERROR, errp,
		    "failed to open %s: %s", ap, strerror(errno)));
	}

	bzero(&ucs, sizeof (ucs));
	ucs.ucs_version = UCCID_CURRENT_VERSION;

	if (ioctl(fd, UCCID_CMD_STATUS, &ucs) != 0) {
		int e = errno;
		(void) close(fd);
		if (e == ENODEV) {
			return (cfga_ccid_error(CFGA_LIB_ERROR, errp,
			    "ap %s going away", ap));
		}
		return (cfga_ccid_error(CFGA_ERROR, errp,
		    "ioctl on ap %s failed: %s", ap, strerror(e)));
	}
	(void) close(fd);

	if ((cld = calloc(1, sizeof (*cld))) == NULL) {
		return (cfga_ccid_error(CFGA_LIB_ERROR, errp, "failed to "
		    "allocate memory for list entry"));
	}

	if (snprintf(cld->ap_log_id, sizeof (cld->ap_log_id), "ccid%d/slot%u",
	    ucs.ucs_instance, ucs.ucs_slot) >= sizeof (cld->ap_log_id)) {
		free(cld);
		return (cfga_ccid_error(CFGA_LIB_ERROR, errp, "ap %s logical id"
		    " was too large", ap));
	}

	if (strlcpy(cld->ap_phys_id, ap, sizeof (cld->ap_phys_id)) >=
	    sizeof (cld->ap_phys_id)) {
		free(cld);
		return (cfga_ccid_error(CFGA_LIB_ERROR, errp,
		    "ap %s physical id was too long", ap));
	}

	cld->ap_class[0] = '\0';

	if ((ucs.ucs_status & UCCID_STATUS_F_CARD_PRESENT) != 0) {
		cld->ap_r_state = CFGA_STAT_CONNECTED;
		if ((ucs.ucs_status & UCCID_STATUS_F_CARD_ACTIVE) != 0) {
			cld->ap_o_state = CFGA_STAT_CONFIGURED;
		} else {
			cld->ap_o_state = CFGA_STAT_UNCONFIGURED;
		}
	} else {
		cld->ap_r_state = CFGA_STAT_EMPTY;
		cld->ap_o_state = CFGA_STAT_UNCONFIGURED;
	}

	/*
	 * We should probably have a way to indicate that there's an error when
	 * the ICC is basically foobar'd. We should also allow the status ioctl
	 * to know that the slot is resetting or something else is going on.
	 */
	if ((ucs.ucs_class.ccd_dwFeatures &
	    (CCID_CLASS_F_SHORT_APDU_XCHG | CCID_CLASS_F_EXT_APDU_XCHG)) == 0) {
		cld->ap_cond = CFGA_COND_UNUSABLE;
	} else {
		cld->ap_cond = CFGA_COND_OK;
	}
	cld->ap_busy = 0;
	cld->ap_status_time = (time_t)-1;
	cfga_ccid_fill_info(&ucs, cld->ap_info, sizeof (cld->ap_info));
	if (strlcpy(cld->ap_type, "icc", sizeof (cld->ap_type)) >=
	    sizeof (cld->ap_type)) {
		free(cld);
		return (cfga_ccid_error(CFGA_LIB_ERROR, errp,
		    "ap %s type overflowed ICC field", ap));
	}

	*ap_list = cld;
	*nlist = 1;
	return (CFGA_OK);
}

cfga_err_t
cfga_help(struct cfga_msg *msgp, const char *opts, cfga_flags_t flags)
{
	(void) (*msgp->message_routine)(msgp, "CCID specific commands:\n");
	(void) (*msgp->message_routine)(msgp,
	    " cfgadm -c [configure|unconfigure] ap_id [ap_id...]\n");
	(void) (*msgp->message_routine)(msgp,
	    " cfgadm -x warm_reset ap_id [ap_id...]\n");

	return (CFGA_OK);
}

int
cfga_ap_id_cmp(const cfga_ap_log_id_t ap_id1, const cfga_ap_log_id_t ap_id2)
{
	return (strcmp(ap_id1, ap_id2));
}
