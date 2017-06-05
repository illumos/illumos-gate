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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <fstream>
#include "fcntl.h"
#include "Handle.h"
#include "Trace.h"
#include "Exceptions.h"
#include "sun_fc.h"
#include <unistd.h>

#ifdef  __cplusplus
extern "C" {
#endif

void get_random_bytes(HBA_UINT8 *ptr, size_t len) {
	int fd = open("/dev/urandom", O_RDONLY);
	size_t resid = len;
	ssize_t bytes;

	while (resid != 0) {
		bytes = read(fd, ptr, resid);
		ptr += bytes;
		resid -= bytes;
	}
	close (fd);
	return;
}

HBA_STATUS Sun_fcAdapterCreateWWN(HBA_HANDLE handle,
    HBA_UINT32 portindex, HBA_WWN *nwwn, HBA_WWN *pwwn,
    HBA_WWN *OUI, HBA_INT32 method) {
	HBA_UINT8	randombyte[5] = {0};
	HBA_WWN		randomwwn = {0};
	int		index = 0;

        Trace log("Sun_fcAdapterCreateWWN");

        if ((nwwn == NULL) || (pwwn == NULL)) {
                log.userError(
                    "NULL WWN pointer");
                return (HBA_STATUS_ERROR_ARG);
        }
	if (method == HBA_CREATE_WWN_FACTORY) {
		return (HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

        try {
		/* create EUI-64 Mapped WWN */
		if (OUI == NULL) {
			/* if no OUI spec'd, used one of Sun's */
			randomwwn.wwn[index++] = 0x0;
			randomwwn.wwn[index++] = 0x0;
			randomwwn.wwn[index++] = 0x7D;
		} else {
			memcpy(randomwwn.wwn, OUI->wwn, sizeof(HBA_WWN));
			index += 3;
		}
		/* 
		 * for EUI-64 mapped, shift OUI first byte right two bits
		 * then set top two bits to 11
		 */
		randomwwn.wwn[0] = randomwwn.wwn[0] >> 2;
		randomwwn.wwn[0] = randomwwn.wwn[0] | 0xc0;

		/* now create and add 40 random bits */	
		get_random_bytes(randombyte, 5);
		memcpy(randomwwn.wwn+index, randombyte, 5);

		memcpy(nwwn->wwn, randomwwn.wwn, sizeof(HBA_WWN));

		/* toggle lowest bit, to make NWWN and PWWN unique */
		randomwwn.wwn[7] = randomwwn.wwn[7] ^ 1;
		memcpy(pwwn->wwn, randomwwn.wwn, sizeof(HBA_WWN));

                return (HBA_STATUS_OK);
        } catch (HBAException &e) {
                return (e.getErrorCode());
        } catch (...) {
                log.internalError(
                    "Uncaught exception");
                return (HBA_STATUS_ERROR);
        }
}
#ifdef  __cplusplus
}
#endif
