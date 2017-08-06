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
 * Copyright (c) 2017 Joyent, Inc.
 */

/*
 * Designed to be backgrounded and just killed. Open a PF_KEY socket, do
 * an extended-REGISTER so the kernel will send extended-ACQUIRE messages,
 * and then read-and-discard everything off the socket.
 */

#include <sys/socket.h>
#include <net/pfkeyv2.h>
#include <stdio.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	int s, rc;
	uint64_t buf[1024];	/* PF_KEY likes 64-bit alignment. */
	sadb_msg_t *samsg;
	sadb_x_ereg_t *ereg;
	boolean_t ah_ack, esp_ack;
	pid_t pid = getpid();

	s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
	if (s == -1)
		err(-1, "socket(PF_KEY)");

	/* Base message. */
	samsg = (sadb_msg_t *)buf;
	ereg = (sadb_x_ereg_t *)(samsg + 1);
	samsg->sadb_msg_version = PF_KEY_V2;
	samsg->sadb_msg_type = SADB_REGISTER;
	samsg->sadb_msg_errno = 0;
	samsg->sadb_msg_satype = SADB_SATYPE_UNSPEC;
	samsg->sadb_msg_reserved = 0;
	samsg->sadb_msg_seq = 1;
	samsg->sadb_msg_pid = pid;
	samsg->sadb_msg_len = SADB_8TO64(sizeof (*samsg) + sizeof (*ereg));

	/* extended REGISTER so we can listen for extended ACQUIREs. */
	ereg->sadb_x_ereg_len = SADB_8TO64(sizeof (*ereg));
	ereg->sadb_x_ereg_exttype = SADB_X_EXT_EREG;
	ereg->sadb_x_ereg_satypes[0] = SADB_SATYPE_ESP;
	ereg->sadb_x_ereg_satypes[1] = SADB_SATYPE_AH;
	ereg->sadb_x_ereg_satypes[2] = SADB_SATYPE_UNSPEC;

	rc = write(s, buf, sizeof (*samsg) + sizeof (*ereg));
	if (rc == -1)
		err(-1, "Extended register write error");

	/*
	 * Extended REGISTER expects a regular REGISTER reply for EACH protocol
	 * requested.  In our case, AH and ESP.
	 */
	do {

		do {
			rc = read(s, buf, sizeof (buf));
			if (rc == -1)
				err(-1, "Extended register read error");

		} while (samsg->sadb_msg_seq != 1 ||
		    samsg->sadb_msg_pid != pid ||
		    samsg->sadb_msg_type != SADB_REGISTER);

		if (samsg->sadb_msg_errno != 0) {
			if (samsg->sadb_msg_errno == EPROTONOSUPPORT) {
				warn("Protocol %d not supported.",
				    samsg->sadb_msg_satype);
			} else {
				errno = samsg->sadb_msg_errno;
				err(-1, "Extended REGISTER returned");
			}
		}

		switch (samsg->sadb_msg_satype) {
		case SADB_SATYPE_ESP:
			esp_ack = B_TRUE;
			break;
		case SADB_SATYPE_AH:
			ah_ack = B_TRUE;
			break;
		default:
			err(-1, "Bad satype in extended register ACK %d.",
			    samsg->sadb_msg_satype);
		}
	} while (!esp_ack || !ah_ack);

	/* Expect this loop to never end. This program ends via signal. */
	do {
		rc = read(s, buf, sizeof (buf));
	} while (rc != -1);

	err(-1, "PF_KEY read error");
}
