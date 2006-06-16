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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/kobj.h>

#include <sys/scfd/scfsys.h>
#include <sys/scfd/scfostoescf.h>

#define	XSCF_DATA_LEN	16
#define	SCF_RETRY_COUNT	10


static int
scf_os_putinfo(uint8_t type, char *datap, uint32_t length)
{
	int	rv, count;

	rv = 0;

	count = SCF_RETRY_COUNT;
	while (count-- > 0) {
		rv = scf_service_putinfo(KEY_ESCF, type, 0, length,
			(void *)datap);
		if (rv == EBUSY) {
			/* 5 sec delay */
			delay(5 * drv_usectohz(1000000));
			continue;
		}
		break;
	};

	return (rv);
}

static int
scf_os_getinfo(uint8_t type, uint32_t transid, char *datap, uint32_t *lengthp)
{
	int	rv, count;

	rv = 0;
	count = SCF_RETRY_COUNT;
	while (count-- > 0) {
		rv = scf_service_getinfo(KEY_ESCF, type, transid, lengthp,
			(void *)datap);
		if (rv == EBUSY) {
			/* 5 sec delay */
			delay(5 * drv_usectohz(1000000));
			continue;
		}
		break;
	};

	return (rv);
}

/*
 * scf_fmem_start()
 *
 * Description: Before starting rename memory,
 * sending the message
 * from OS to XSCF.
 *
 */
int
scf_fmem_start(int s_bd, int t_bd)
{
	char	data[XSCF_DATA_LEN];

	bzero(data, XSCF_DATA_LEN);
	data[0] = (char)s_bd;
	data[1] = (char)t_bd;

	return (scf_os_putinfo(SUB_OS_SEND_PRE_FMEMA,
		data, XSCF_DATA_LEN));
}

/*
 * scf_fmem_end()
 *
 * Description: After doing rename memory, sending the message
 * from OS to XSCF.
 *
 */
int
scf_fmem_end()
{
	char data[XSCF_DATA_LEN];
	int rv;
	uint32_t len;

	bzero(data, XSCF_DATA_LEN);
	len = XSCF_DATA_LEN;
	rv = scf_os_getinfo(SUB_OS_SEND_COMPLETE_FMEMA, 0, data, &len);

	if (rv == 0) {
		/* 0 is OK and everything less than 0 is BAD but TBD */
		if (len > 0)
			rv = (int)data[0];
		else
			rv = -1;
	}
	return (rv);
}

/*
 * scf_fmem_cancel()
 *
 * Description: If the status failed after doing rename memory
 * and check the result, sending the message from OS to XSCF.
 *
 */
int
scf_fmem_cancel()
{
	return (scf_os_putinfo(SUB_OS_SEND_CANCEL_FMEMA, 0, 0));
}

/*
 * scf_get_dimminfo()
 *
 * Description: Get the dimm infomation for a board. This information
 * includes the serial-IDs.
 */
int
scf_get_dimminfo(uint32_t boardnum, void *buf, uint32_t *bufsz)
{
	return (scf_os_getinfo(SUB_OS_RECEIVE_DIMM_INFO, boardnum, buf, bufsz));
}
