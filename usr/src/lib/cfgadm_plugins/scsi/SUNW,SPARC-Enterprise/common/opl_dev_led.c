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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <strings.h>
#include <libgen.h>
#include <cfga_scsi.h>
#include <sys/scfd/opcioif.h>


#define	SCF_DRV		"/devices/pseudo/scfd@200:rasctl"
#define	SCFRETRY	3
#define	SCFIOCWAIT	3


#define	OPL_LOCATOR_OPT	0
#define	OPL_LED_OPT	1
#define	OPL_MODE_OPT	2
char *opl_opts[] = {
	"locator",
	"led",
	"mode",
	NULL
};


static scfga_ret_t
opl_get_scf_logical_disk(const apid_t *apidp, char **errstring,
					scfiocgetdiskled_t *scf_disk)
{
	int len;
	char *phys_path;
	char *strptr;

	phys_path  = strdup(apidp->path);
	if (phys_path == NULL) {
		cfga_err(errstring, ENOMEM, ERR_OP_FAILED, 0);
		return (SCFGA_ERR);
	}
	scf_disk->path[0] = '\0';
	if ((strptr = strstr(phys_path, ":")) != NULL) {
		strptr[0] = '\0';
		len = snprintf((char *)scf_disk->path, sizeof (scf_disk->path),
			"%s", (char *)(phys_path));
		if (len >= sizeof (scf_disk->path)) {
			free(phys_path);
			cfga_err(errstring, 0, ERR_OP_FAILED, 0);
			return (SCFGA_ERR);
		}
	} else {
		free(phys_path);
		cfga_err(errstring, 0, ERR_UNKNOWN, 0);
		return (SCFGA_ERR);
	}
	free(phys_path);

	return (SCFGA_OK);
}


/*
 * Open the SCF driver and use the ioctl interface to set or get the status.
 *
 * Returns 0 on success. Returns OP_FAILED on error.
 */
static scfga_ret_t
opl_disk_led_control(apid_t *apidp, char **errstring, struct cfga_msg *msgp,
	int request, scfiocgetdiskled_t *scf_disk)
{
	scfga_ret_t	retval;
	int		scf_fd = -1;
	int		retry = 0;

	/* paranoid check */
	if ((apidp == NULL) || (msgp == NULL) || (scf_disk == NULL)) {
		cfga_err(errstring, 0, ERR_UNKNOWN, 0, 0);
		return (SCFGA_ERR);
	}

	retval = opl_get_scf_logical_disk((const apid_t *)apidp, errstring,
					scf_disk);
	if (retval != SCFGA_OK) {
		/* errstring is set in opl_get_scf_logical_disk */
		return (retval);
	}

	/* Open a file descriptor for the scf driver. */
	scf_fd = open(SCF_DRV, O_RDWR);
	if (scf_fd < 0) {
		cfga_err(errstring, errno, ERRARG_OPEN, SCF_DRV, 0);
		return (SCFGA_LIB_ERR);
	}

	/*
	 * Use the ioctl interface with the SCF driver to get/set the
	 * hdd locator indicator.
	 */
	errno = 0;
	while (ioctl(scf_fd, request, scf_disk) < 0) {
		/* Check Retry Error Number */
		if (errno != EBUSY && errno != EIO) {
			break;
		}

		/* Check Retry Times */
		if (++retry > SCFRETRY) {
			break;
		}
		errno = 0;

		(void) sleep(SCFIOCWAIT);
	}
	(void) close(scf_fd);

	if ((errno != 0) || (retry > SCFRETRY)) {
		cfga_err(errstring, errno, ERR_OP_FAILED, 0, 0);
		return (SCFGA_LIB_ERR);
	}
	return (SCFGA_OK);
}

/*
 * Print the value of the hard disk locator in a human friendly form.
 */
static void
opl_print_locator(apid_t *apidp, struct cfga_msg *msgp, unsigned char led)
{
	led_modeid_t mode = LED_MODE_UNK;

	if ((msgp == NULL) || (msgp->message_routine == NULL)) {
		return;
	}

	cfga_msg(msgp, MSG_LED_HDR, 0);
	switch ((int)led) {
	case SCF_DISK_LED_ON:
		mode = LED_MODE_FAULTED;
		break;

	case SCF_DISK_LED_OFF:
		mode = LED_MODE_OFF;
		break;

	case SCF_DISK_LED_BLINK:
		mode = LED_MODE_ON;
		break;

	default:
		mode = LED_MODE_UNK;
	}
	cfga_led_msg(msgp, apidp, LED_STR_LOCATOR, mode);
}

/*
 * Print the value of the hard disk fault LED in a human friendly form.
 */
static void
opl_print_led(apid_t *apidp, struct cfga_msg *msgp, unsigned char led)
{
	led_modeid_t mode = LED_MODE_UNK;

	if ((msgp == NULL) || (msgp->message_routine == NULL)) {
		return;
	}

	cfga_msg(msgp, MSG_LED_HDR, 0);
	switch ((int)led) {
	case SCF_DISK_LED_ON:
		mode = LED_MODE_ON;
		break;

	case SCF_DISK_LED_OFF:
		mode = LED_MODE_OFF;
		break;

	case SCF_DISK_LED_BLINK:
		mode = LED_MODE_BLINK;
		break;

	default:
		mode = LED_MODE_UNK;
	}
	cfga_led_msg(msgp, apidp, LED_STR_FAULT, mode);
}

static scfga_ret_t
opl_setlocator(
	const char *mode,
	apid_t *apidp,
	char **errstring,
	struct cfga_msg *msgp)
{
	scfga_ret_t retval;
	scfiocgetdiskled_t scf_disk;

	if (strcmp(mode, "on") == 0) {
		scf_disk.led = SCF_DISK_LED_BLINK;
	} else if (strcmp(mode, "off") == 0) {
		scf_disk.led = SCF_DISK_LED_OFF;
	} else {
		cfga_err(errstring, 0, ERRARG_OPT_INVAL, mode, 0);
		return (SCFGA_ERR);
	}

	retval = opl_disk_led_control(apidp, errstring, msgp,
					SCFIOCSETDISKLED, &scf_disk);

	return (retval);
}


static scfga_ret_t
opl_getled(
	int print_switch,
	apid_t *apidp,
	char **errstring,
	struct cfga_msg *msgp)
{
	scfga_ret_t retval;
	scfiocgetdiskled_t scf_disk;

	(void) memset((void *)&scf_disk, 0, sizeof (scf_disk));

	retval = opl_disk_led_control(apidp, errstring, msgp,
				SCFIOCGETDISKLED, &scf_disk);
	if (retval != SCFGA_OK) {
		return (retval);
	}
	if (print_switch == OPL_LED_OPT) {
		opl_print_led(apidp, msgp, scf_disk.led);
	} else {
		opl_print_locator(apidp, msgp, scf_disk.led);
	}

	return (SCFGA_OK);
}


static scfga_ret_t
opl_setled(
	const char *mode,
	apid_t *apidp,
	char **errstring,
	struct cfga_msg *msgp)
{
	scfga_ret_t retval;
	scfiocgetdiskled_t scf_disk;

	(void) memset((void *)&scf_disk, 0, sizeof (scf_disk));

	if (strcmp(mode, "on") == 0) {
		scf_disk.led = SCF_DISK_LED_ON;
	} else if (strcmp(mode, "off") == 0) {
		scf_disk.led = SCF_DISK_LED_OFF;
	} else if (strcmp(mode, "blink") == 0) {
		scf_disk.led = SCF_DISK_LED_BLINK;
	} else {
		cfga_err(errstring, 0, ERRARG_OPT_INVAL, mode, 0);
		return (SCFGA_ERR);
	}

	retval = opl_disk_led_control(apidp, errstring, msgp,
					SCFIOCSETDISKLED, &scf_disk);
	return (retval);
}

/*
 * The func argument is a string in one of the two following forms:
 *	led=LED[,mode=MODE]
 *	locator[=on|off]
 * which can generically be thought of as:
 *	name=value[,name=value]
 * So first, split the function based on the comma into two name-value
 * pairs.
 */
/*ARGSUSED*/
scfga_ret_t
plat_dev_led(
	const char *func,
	scfga_cmd_t cmd,
	apid_t *apidp,
	prompt_t *argsp,
	cfga_flags_t flags,
	char **errstring)
{
	scfga_ret_t retval = SCFGA_ERR;
	char *optptr = (char *)func;
	char *value = NULL;

	int opt_locator = 0;
	int opt_led = 0;
	int opt_mode = 0;
	char *locator_value = NULL;
	char *led_value = NULL;
	char *mode_value = NULL;

	if (func == NULL) {
		return (SCFGA_ERR);
	}

	while (*optptr != '\0') {
		switch (getsubopt(&optptr, opl_opts, &value)) {
		case OPL_LOCATOR_OPT:
			opt_locator++;
			locator_value = value;
			break;
		case OPL_LED_OPT:
			opt_led++;
			led_value = value;
			break;
		case OPL_MODE_OPT:
			opt_mode++;
			mode_value = value;
			break;
		default:
			cfga_err(errstring, 0, ERR_CMD_INVAL, 0);
			return (SCFGA_OPNOTSUPP);
			break;
		}
	}

	if (!opt_locator && !opt_led) {
		cfga_err(errstring, 0, ERR_CMD_INVAL, 0);
		return (SCFGA_ERR);
	}

	if (opt_locator) {
		if ((opt_locator > 1) || opt_led || opt_mode ||
			(strncmp(func, "locator", strlen("locator")) != 0) ||
			(locator_value &&
			(strcmp(locator_value, "blink") == 0))) {
			cfga_err(errstring, 0, ERR_CMD_INVAL, 0);
			return (SCFGA_ERR);
		}

		/* Options are sane so set or get the locator. */
		if (locator_value) {
			retval = opl_setlocator(locator_value, apidp,
				errstring, argsp->msgp);
		} else {
			retval = opl_getled(OPL_LOCATOR_OPT, apidp, errstring,
				argsp->msgp);
		}
	}
	if (opt_led) {
		if ((opt_led > 1) || (opt_mode > 1) || (opt_locator) ||
				(strncmp(func, "led", strlen("led")) != 0) ||
				(!led_value || strcmp(led_value, "fault")) ||
				(opt_mode && !mode_value)) {

			cfga_err(errstring, 0, ERR_CMD_INVAL, 0);
			return (SCFGA_ERR);
		}

		/* options are sane so go ahead and set or get the led */
		if (mode_value != NULL) {
			retval = opl_setled(mode_value, apidp, errstring,
				argsp->msgp);
		} else {
			retval = opl_getled(OPL_LED_OPT, apidp, errstring,
				argsp->msgp);
		}
	}
	return (retval);

}
