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
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/socket.h>
#include <net/pfkeyv2.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define	COOKIE64 0xc0ffee4afee01deaULL
#define	COOKIE32 0x90125
#define	RESERVED 0xc0ffee

/*
 * Exits app on failure.
 */
static void
write_and_read(int s, sadb_msg_t *samsg, uint64_t *readbuf, int readlen,
    char *msgtypestr)
{
	int rc;
	uint8_t msgtype = samsg->sadb_msg_type;
	pid_t pid = samsg->sadb_msg_pid;
	uint8_t seq = samsg->sadb_msg_seq;

	rc = write(s, samsg, SADB_64TO8(samsg->sadb_msg_len));
	if (rc == -1)
		err(-1, "%s write error", msgtypestr);

	/* Yes, parameter re-use, but we're done writing. */
	samsg = (sadb_msg_t *)readbuf;
	do {
		rc = read(s, readbuf, readlen);
		if (rc == -1)
			err(-1, "%s read reply error", msgtypestr);
	} while (samsg->sadb_msg_seq != seq || samsg->sadb_msg_pid != pid ||
	    samsg->sadb_msg_type != msgtype);

	if (samsg->sadb_msg_errno != 0) {
		errno = samsg->sadb_msg_errno;
		err(-1, "%s reply has error (diag = %d)", msgtypestr,
		    samsg->sadb_x_msg_diagnostic);
	}
}

int
main(int argc, char *argv[])
{
	uint32_t spi;
	sadb_ext_t *ext;
	sadb_sa_t *saext;
	sadb_msg_t *samsg;
	sadb_address_t *dstext, *srcext;
	sadb_x_kmc_t *kmcext;
	struct sockaddr_in *sin;
	uint64_t writebuf[20];		/* PF_KEY likes 64-bit alignment. */
	uint64_t readbuf[128];
	uint64_t *extptr, *endptr;
	pid_t pid = getpid();
	boolean_t do_64_test;
	int s;

	if (argc != 2 && argc != 3) {
		(void) fprintf(stderr, "Usage: %s <spi-value> {64}\n",
		    argv[0]);
		exit(-1);
	}
	do_64_test = (argc == 3);

	spi = strtoul(argv[1], NULL, 0);
	if (spi == 0) {
		if (errno != 0) {
			err(-1, "Argument %s is not a parsable number:",
			    argv[1]);
		} else {
			errno = EINVAL;
			err(-1, "Zero SPI not allowed:");
		}
	}

	s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (s == -1)
		err(-1, "socket(PF_KEY)");

	/* Base message. */
	samsg = (sadb_msg_t *)writebuf;
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_UPDATE;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = SADB_SATYPE_AH;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = 1;
	samsg->sadb_msg_pid = pid;
	samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg) + sizeof (*saext) +
	    2 * (sizeof (*dstext) + sizeof (*sin)) + sizeof (*kmcext));

	/* SA extension. Only used to set the SPI. */
	saext = (sadb_sa_t *)(samsg + 1);
	memset(saext, 0, sizeof (*saext));
	saext->sadb_sa_len = SADB_8TO64(sizeof (*saext));
	saext->sadb_sa_exttype = SADB_EXT_SA;
	saext->sadb_sa_spi = htonl(spi);
	saext->sadb_sa_state = SADB_SASTATE_MATURE;

	/* Destination IP, always 127.0.0.1 for this test. */
	dstext = (sadb_address_t *)(saext + 1);
	dstext->sadb_address_len = SADB_8TO64(sizeof (*dstext) + sizeof (*sin));
	dstext->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
	dstext->sadb_address_proto = 0;
	dstext->sadb_address_prefixlen = 0;
	dstext->sadb_address_reserved = 0;
	sin = (struct sockaddr_in *)(dstext + 1);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	/* PF_KEY requires a source address, even if it's a wildcard. */
	srcext = (sadb_address_t *)(sin + 1);
	srcext->sadb_address_len = SADB_8TO64(sizeof (*srcext) + sizeof (*sin));
	srcext->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
	srcext->sadb_address_proto = 0;
	srcext->sadb_address_prefixlen = 0;
	srcext->sadb_address_reserved = 0;
	sin = (struct sockaddr_in *)(srcext + 1);
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = 0;

	/*
	 * KM cookie. Depending, either make it IKEv1, 32-bit, AND store
	 * garbage in the reserved field, or just put a big 64-bit cookie in.
	 */
	kmcext = (sadb_x_kmc_t *)(sin + 1);
	kmcext->sadb_x_kmc_len = SADB_8TO64(sizeof (*kmcext));
	kmcext->sadb_x_kmc_exttype = SADB_X_EXT_KM_COOKIE;
	if (do_64_test) {
		/* 64-bit cookie test.  KINK is non-zero, and non-IKEv1. */
		kmcext->sadb_x_kmc_proto = SADB_X_KMP_KINK;
		kmcext->sadb_x_kmc_cookie64 = COOKIE64;
	} else {
		/* IKEv1 32-bit cookie test. */
		kmcext->sadb_x_kmc_proto = SADB_X_KMP_IKE;
		kmcext->sadb_x_kmc_cookie = COOKIE32;
		kmcext->sadb_x_kmc_reserved = RESERVED;
	}

	write_and_read(s, samsg, readbuf, sizeof (readbuf), "SADB_UPDATE");

	/*
	 * Okay, it worked!  Now let's find the KMC reported back from the
	 * kernel.
	 */
	samsg->sadb_msg_type = SADB_GET;
	samsg->sadb_msg_len -= SADB_8TO64(sizeof (*kmcext));

	/* Everything else in writebuf is good to go. */
	write_and_read(s, samsg, readbuf, sizeof (readbuf), "SADB_GET");

	/* Actually find the KMC extension. (expand for loop for readability) */
	samsg = (sadb_msg_t *)readbuf;
	extptr = (uint64_t *)(samsg + 1);
	endptr = extptr + samsg->sadb_msg_len - SADB_8TO64(sizeof (*samsg));
	ext = (sadb_ext_t *)extptr;

	while ((extptr < endptr) &&
	    (ext->sadb_ext_type != SADB_X_EXT_KM_COOKIE)) {
		extptr += ext->sadb_ext_len;
		ext = (sadb_ext_t *)extptr;
	}

	if (extptr == endptr) {
		(void) fprintf(stderr, "Can't find KMC extension in reply.\n");
		exit(-1);
	}
	kmcext = (sadb_x_kmc_t *)extptr;

	if (do_64_test) {
		if (kmcext->sadb_x_kmc_proto != SADB_X_KMP_KINK ||
		    kmcext->sadb_x_kmc_cookie64 != COOKIE64) {
			(void) fprintf(stderr, "Unexpected 64-bit results: "
			    "KMC received was %d, expecting %d,\n",
			    kmcext->sadb_x_kmc_proto, SADB_X_KMP_KINK);
			(void) fprintf(stderr, "64-bit cookie recevied was "
			    "0x%"PRIx64", expecting 0x%"PRIx64"\n",
			    kmcext->sadb_x_kmc_cookie64, COOKIE64);
			exit(1);
		}
	} else {
		if (kmcext->sadb_x_kmc_proto != SADB_X_KMP_IKE ||
		    kmcext->sadb_x_kmc_cookie != COOKIE32 ||
		    kmcext->sadb_x_kmc_reserved != 0) {
			(void) fprintf(stderr, "Unexpected IKE/32-bit results:"
			    " KMC received was %d, expecting %d,\n",
			    kmcext->sadb_x_kmc_proto, SADB_X_KMP_IKE);
			(void) fprintf(stderr, "32-bit cookie recevied was "
			    "0x%"PRIx32", expecting 0x%"PRIx32"\n",
			    kmcext->sadb_x_kmc_cookie64, COOKIE32);
			(void) fprintf(stderr, "32-bit reserved recevied was "
			    "0x%"PRIx32", expecting 0\n",
			    kmcext->sadb_x_kmc_cookie64);
			exit(1);
		}
	}

	exit(0);
}
