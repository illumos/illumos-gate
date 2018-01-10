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
#include <ipsec_util.h>

#define	COOKIE64 0xc0ffee4afee01deaULL
#define	COOKIE32 0x90125
#define	RESERVED 0xc0ffee

#define	EXIT_SETUP_FAIL -1
#define	EXIT_TEST_FAIL 1
#define	EXIT_SUCCESS 0

/*
 * Exits app on failure.
 */
static void
write_and_read(int s, sadb_msg_t *samsg, uint64_t *readbuf, int readlen,
    int expected, char *msgtypestr)
{
	ssize_t rc;
	uint8_t msgtype = samsg->sadb_msg_type;
	pid_t pid = samsg->sadb_msg_pid;
	uint8_t seq = samsg->sadb_msg_seq;

	rc = write(s, samsg, SADB_64TO8(samsg->sadb_msg_len));
	if (rc == -1)
		err(EXIT_SETUP_FAIL, "%s write error", msgtypestr);

	/* Yes, parameter re-use, but we're done writing. */
	samsg = (sadb_msg_t *)readbuf;
	do {
		rc = read(s, readbuf, readlen);
		if (rc == -1)
			err(EXIT_SETUP_FAIL, "%s read reply error", msgtypestr);
	} while (samsg->sadb_msg_seq != seq || samsg->sadb_msg_pid != pid ||
	    samsg->sadb_msg_type != msgtype);

	if (samsg->sadb_msg_errno != expected) {
		errno = samsg->sadb_msg_errno;
		err(EXIT_SETUP_FAIL, "%s reply has error (diag = %d, %s)",
		    msgtypestr, samsg->sadb_x_msg_diagnostic,
		    keysock_diag(samsg->sadb_x_msg_diagnostic));
	}
}

static void
usage(const char *progname)
{
	(void) fprintf(stderr, "Usage: %s [-e expected_error] [-k kmc_value] "
	    "[-p kmc_proto] <spi-value> [64]\n", progname);
	exit(EXIT_SETUP_FAIL);
}

int
main(int argc, char * const argv[])
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
	const char *cookiestr = NULL;
	uint64_t cookie64 = COOKIE64;
	uint32_t cookie32 = COOKIE32;
	uint32_t reserved = RESERVED;
	uint32_t proto = 0;
	int experr = 0;
	pid_t pid = getpid();
	boolean_t do_64_test;
	int s;
	int c;

	while ((c = getopt(argc, argv, "e:k:p:")) != -1) {
		switch (c) {
		case 'e':
			errno = 0;
			experr = strtol(optarg, NULL, 0);
			if (errno != 0) {
				err(EXIT_SETUP_FAIL,
				    "Expected error value '%s' is not a "
				    "parsable number", optarg);
			}
			break;
		case 'k':
			cookiestr = optarg;
			break;
		case 'p':
			errno = 0;
			proto = strtoul(optarg, NULL, 0);
			if (errno != 0) {
				err(EXIT_SETUP_FAIL,
				    "KMC Protocol value '%s' is not a parsable"
				    " number", optarg);
			}
			break;
		case '?':
			(void) fprintf(stderr, "Invalid option -%c\n", optopt);
			usage(argv[0]);
			break;
		}
	}

	if (argc - optind != 1 && argc - optind != 2)
		usage(argv[0]);

	do_64_test = (argc - optind == 2);

	if (cookiestr != NULL) {
		errno = 0;

		if (do_64_test)
			cookie64 = strtoull(cookiestr, NULL, 0);
		else
			cookie32 = strtoul(cookiestr, NULL, 0);

		if (errno != 0) {
			err(EXIT_SETUP_FAIL,
			    "KMC '%s' is not a parsable number",
			    cookiestr);
		}
	}

	if (proto == 0)
		proto = do_64_test ? SADB_X_KMP_KINK : SADB_X_KMP_IKE;

	errno = 0;	/* Clear for strtoul() call. */
	spi = strtoul(argv[optind], NULL, 0);
	if (spi == 0) {
		if (errno != 0) {
			err(EXIT_SETUP_FAIL,
			    "Argument %s is not a parsable number:", argv[1]);
		} else {
			errno = EINVAL;
			err(EXIT_SETUP_FAIL, "Zero SPI not allowed:");
		}
	}

	s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (s == -1)
		err(EXIT_SETUP_FAIL, "socket(PF_KEY)");

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
		kmcext->sadb_x_kmc_proto = proto;
		kmcext->sadb_x_kmc_cookie64 = cookie64;
	} else {
		/* IKEv1 32-bit cookie test. */
		kmcext->sadb_x_kmc_proto = proto;
		kmcext->sadb_x_kmc_cookie = cookie32;
		kmcext->sadb_x_kmc_reserved = reserved;
	}

	write_and_read(s, samsg, readbuf, sizeof (readbuf), experr,
	    "SADB_UPDATE");

	/* If we expected to fail, we shouldn't try to verify anything */
	if (experr != 0)
		exit(EXIT_SUCCESS);

	/*
	 * Okay, it worked!  Now let's find the KMC reported back from the
	 * kernel.
	 */
	samsg->sadb_msg_type = SADB_GET;
	samsg->sadb_msg_len -= SADB_8TO64(sizeof (*kmcext));

	/* Everything else in writebuf is good to go. */
	write_and_read(s, samsg, readbuf, sizeof (readbuf), 0, "SADB_GET");

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
		exit(EXIT_SETUP_FAIL);
	}
	kmcext = (sadb_x_kmc_t *)extptr;

	if (do_64_test) {
		if (kmcext->sadb_x_kmc_proto != proto ||
		    kmcext->sadb_x_kmc_cookie64 != cookie64) {
			(void) fprintf(stderr, "Unexpected 64-bit results: "
			    "KMC received was %" PRIu32
			    ", expecting %" PRIu32 ",\n",
			    kmcext->sadb_x_kmc_proto, proto);
			(void) fprintf(stderr, "64-bit cookie recevied was "
			    "0x%"PRIx64", expecting 0x%"PRIx64"\n",
			    kmcext->sadb_x_kmc_cookie64, cookie64);
			exit(EXIT_TEST_FAIL);
		}
	} else {
		if (kmcext->sadb_x_kmc_proto != proto ||
		    kmcext->sadb_x_kmc_cookie != cookie32 ||
		    kmcext->sadb_x_kmc_reserved != 0) {
			(void) fprintf(stderr, "Unexpected IKE/32-bit results:"
			    " KMC received was %" PRIu32
			    ", expecting %" PRIu32 ",\n",
			    kmcext->sadb_x_kmc_proto, proto);
			(void) fprintf(stderr, "32-bit cookie recevied was "
			    "0x%"PRIx32", expecting 0x%"PRIx32"\n",
			    kmcext->sadb_x_kmc_cookie64, cookie32);
			(void) fprintf(stderr, "32-bit reserved recevied was "
			    "0x%"PRIx32", expecting 0\n",
			    kmcext->sadb_x_kmc_cookie64);
			exit(EXIT_TEST_FAIL);
		}
	}

	exit(EXIT_SUCCESS);
}
