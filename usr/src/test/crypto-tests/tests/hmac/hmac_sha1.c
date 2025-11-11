/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License (), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/crypto/ioctl.h>
#include <sys/sha1.h>

#include "hmac_sha1_data.h"

uint8_t *DATA[] = { DATA0, DATA1, DATA2, DATA3, DATA4, DATA5, DATA6 };

size_t DATALEN[] = {
	sizeof (DATA0), sizeof (DATA1), sizeof (DATA2), sizeof (DATA3),
	sizeof (DATA4), sizeof (DATA5), sizeof (DATA6)
};

uint8_t *KEY[] = { KEY0, KEY1, KEY2, KEY3, KEY4, KEY5, KEY6 };

size_t KEYLEN[] = {
	sizeof (KEY0), sizeof (KEY1), sizeof (KEY2), sizeof (KEY3),
	sizeof (KEY4), sizeof (KEY5), sizeof (KEY6)
};

uint8_t *HMAC[] = { HMAC0, HMAC1, HMAC2, HMAC3, HMAC4, HMAC5, HMAC6 };

char *mechname = SUN_CKM_SHA1_HMAC;
size_t msgcount = 7;
size_t hmac_len = SHA1_DIGEST_LENGTH;
