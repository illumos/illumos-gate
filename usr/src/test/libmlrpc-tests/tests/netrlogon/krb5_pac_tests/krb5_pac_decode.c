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
 * Copyright 2020 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Test the ability to decode PAC data from AD Kerberos tickets.
 */

#include <smbsrv/libmlsvc.h>
#include <stdio.h>
#include <stdlib.h>

#include <util_common.h>

enum KPAC_RC {
	KPC_SUCCESS = 0,
	KPC_ARGC,
	KPC_PAC_FILE,
	KPC_TOKEN_ALLOC,
	KPC_DECODE_PAC
};

int
main(int argc, char *argv[])
{
	char *pac_file;
	uchar_t *pac_buf;
	size_t buflen;
	smb_token_t *token;
	uint32_t status;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <Binary PAC File>\n", argv[0]);
		return (-KPC_ARGC);
	}

	pac_file = argv[1];

	pac_buf = read_buf_from_file(pac_file, &buflen);

	if (pac_buf == NULL) {
		fprintf(stderr, "failed to read pac data\n");
		return (-KPC_PAC_FILE);
	}

	token = calloc(1, sizeof (*token));
	if (token == NULL) {
		fprintf(stderr, "failed to allocate token\n");
		return (-KPC_TOKEN_ALLOC);
	}

	/* Initialize only those bits on which smb_decode_krb5_pac depends */
	(void) smb_lgrp_start();

	status = smb_decode_krb5_pac(token, (char *)pac_buf, buflen);
	if (status != 0) {
		fprintf(stderr, "smb_decode_krb5_pac failed with 0x%x\n",
		    status);
		return (-KPC_DECODE_PAC);
	}

	smb_token_log(token);

	return (KPC_SUCCESS);
}
