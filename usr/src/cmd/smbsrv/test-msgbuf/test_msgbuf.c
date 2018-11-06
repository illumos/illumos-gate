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
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Test putting/getting unicode strings in mbchains.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/varargs.h>
#include <smbsrv/smb_kproto.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "test_defs.h"

static char mbsa[] = "A\xef\xbc\xa1.";		// A fwA . (5)
static char mbsp[] = "P\xf0\x9f\x92\xa9.";	// P poop . (6)
static smb_wchar_t wcsa[] = { 'A', 0xff21, '.', 0 };	// (3)
static smb_wchar_t wcsp[] = { 'P', 0xd83d, 0xdca9, '.', 0 }; // (4)

/*
 * Put ASCII string with NULL
 */
static void
msg_put_a0()
{
	uint8_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	rc = smb_msgbuf_encode(&mb, "sw", "one", 42);
	if (rc != 6) {
		printf("Fail: msg_put_a0 encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 6)) {
		printf("Fail: msg_put_a0 cmp:\n");
		hexdump((uchar_t *)temp, 6);
		return;
	}

	printf("Pass: msg_put_a0\n");

out:
	smb_msgbuf_term(&mb);
}

/*
 * Put ASCII string, no NULL
 */
static void
msg_put_a1()
{
	uint8_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	rc = smb_msgbuf_encode(&mb, "4sw", "one.", 42);
	if (rc != 6) {
		printf("Fail: msg_put_a1 encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 6)) {
		printf("Fail: msg_put_a1 cmp:\n");
		hexdump((uchar_t *)temp, 6);
		return;
	}

	printf("Pass: msg_put_a1\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_put_apad()
{
	uint8_t wire[] = { 'o', 'n', 'e', 0, 0 };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	/* Encode with wire length > strlen */
	rc = smb_msgbuf_encode(&mb, "5s", "one");
	if (rc != 5) {
		printf("Fail: msg_put_apad encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 5)) {
		printf("Fail: msg_put_apad cmp:\n");
		hexdump((uchar_t *)temp, 5);
		return;
	}

	printf("Pass: msg_put_apad\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_put_atrunc()
{
	uint8_t wire[] = { 'o', 'n', 'e', 't', };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	/* Encode with wire length < strlen */
	rc = smb_msgbuf_encode(&mb, "4s", "onetwo");
	/* Trunc should put exactly 4 */
	if (rc != 4) {
		printf("Fail: msg_put_atrunc encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 4)) {
		printf("Fail: msg_put_atrunc cmp:\n");
		hexdump((uchar_t *)temp, 4);
		return;
	}

	printf("Pass: msg_put_atrunc\n");

out:
	smb_msgbuf_term(&mb);
}

/*
 * Put unicode string with NULL
 */
static void
msg_put_u0()
{
	uint16_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	rc = smb_msgbuf_encode(&mb, "Uw", "one", 42);
	if (rc != 10) {
		printf("Fail: msg_put_u0 encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 10)) {
		printf("Fail: msg_put_u0 cmp:\n");
		hexdump((uchar_t *)temp, 10);
		return;
	}

	printf("Pass: msg_put_u0\n");

out:
	smb_msgbuf_term(&mb);
}

/*
 * Put unicode string, no NULL
 */
static void
msg_put_u1()
{
	uint16_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	rc = smb_msgbuf_encode(&mb, "8Uw", "one.", 42);
	if (rc != 10) {
		printf("Fail: msg_put_u1 encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 10)) {
		printf("Fail: msg_put_u1 cmp:\n");
		hexdump((uchar_t *)temp, 10);
		return;
	}

	printf("Pass: msg_put_u1\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_put_u3()
{
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	rc = smb_msgbuf_encode(&mb, "U", mbsa);
	if (rc != 8) {
		printf("Fail: msg_put_u3 encode\n");
		goto out;
	}

	if (memcmp(temp, wcsa, 8)) {
		printf("Fail: msg_put_u3 cmp:\n");
		hexdump((uchar_t *)temp, 8);
		return;
	}

	printf("Pass: msg_put_u3\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_put_u4()
{
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	rc = smb_msgbuf_encode(&mb, "U", mbsp);
	if (rc != 10) {
		printf("Fail: msg_put_u4 encode\n");
		goto out;
	}

	if (memcmp(temp, wcsp, 10)) {
		printf("Fail: msg_put_u4 cmp:\n");
		hexdump((uchar_t *)temp, 10);
		return;
	}

	printf("Pass: msg_put_u4\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_put_upad()
{
	uint16_t wire[] = { 'o', 'n', 'e', 0, 0 };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	/* Encode with wire length > strlen */
	rc = smb_msgbuf_encode(&mb, "10U", "one");
	if (rc != 10) {
		printf("Fail: msg_put_upad encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 10)) {
		printf("Fail: msg_put_upad cmp:\n");
		hexdump((uchar_t *)temp, 10);
		return;
	}

	printf("Pass: msg_put_upad\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_put_utrunc()
{
	uint16_t wire[] = { 'o', 'n', 'e', 't' };
	uint8_t temp[32];
	smb_msgbuf_t mb;
	int mbflags = 0;
	int rc;

	smb_msgbuf_init(&mb, temp, sizeof (temp), mbflags);

	/* Encode with wire length < strlen */
	rc = smb_msgbuf_encode(&mb, "8U", "onetwo");
	/* Trunc should put exactly 8 */
	if (rc != 8) {
		printf("Fail: msg_put_utrunc encode\n");
		goto out;
	}

	if (memcmp(temp, wire, 8)) {
		printf("Fail: msg_put_utrunc cmp:\n");
		hexdump((uchar_t *)temp, 8);
		return;
	}

	printf("Pass: msg_put_utrunc\n");

out:
	smb_msgbuf_term(&mb);
}

/*
 * Parse an ascii string.
 */
static void
msg_get_a0()
{
	uint8_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;
	uint16_t w;

	smb_msgbuf_init(&mb, wire, sizeof (wire), mbflags);

	rc = smb_msgbuf_decode(&mb, "sw", &s, &w);
	if (rc != 6) {
		printf("Fail: msg_get_a0 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: msg_get_a0 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: msg_get_a0 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_a0\n");

out:
	smb_msgbuf_term(&mb);
}

/*
 * Parse an ascii string, no NULL
 */
static void
msg_get_a1()
{
	uint8_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;
	uint16_t w;

	smb_msgbuf_init(&mb, wire, sizeof (wire), mbflags);

	rc = smb_msgbuf_decode(&mb, "3s.w", &s, &w);
	if (rc != 6) {
		printf("Fail: msg_get_a1 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: msg_get_a1 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: msg_get_a1 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_a1\n");

out:
	smb_msgbuf_term(&mb);
}

/* parse exactly to end of data */
static void
msg_get_a2()
{
	uint8_t wire[] = { 'o', 'n', 'e' };
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;

	smb_msgbuf_init(&mb, wire, sizeof (wire), mbflags);

	rc = smb_msgbuf_decode(&mb, "3s", &s);
	if (rc != 3) {
		printf("Fail: msg_get_a2 decode\n");
		goto out;
	}
	if (mb.scan != mb.end) {
		printf("Fail: msg_get_a2 wrong pos\n");
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: msg_get_a2 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_a2\n");

out:
	smb_msgbuf_term(&mb);
}

/*
 * Parse a unicode string.
 */
static void
msg_get_u0()
{
	uint16_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;
	uint16_t w;

	smb_msgbuf_init(&mb, (uint8_t *)wire, sizeof (wire), mbflags);

	rc = smb_msgbuf_decode(&mb, "Uw", &s, &w);
	if (rc != 10) {
		printf("Fail: msg_get_u0 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: msg_get_u0 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: msg_get_u0 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_u0\n");

out:
	smb_msgbuf_term(&mb);
}

/*
 * Parse a string that's NOT null terminated.
 */
static void
msg_get_u1()
{
	uint16_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;
	uint16_t w;

	smb_msgbuf_init(&mb, (uint8_t *)wire, sizeof (wire), mbflags);

	rc = smb_msgbuf_decode(&mb, "6U..w", &s, &w);
	if (rc != 10) {
		printf("Fail: msg_get_u1 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: msg_get_u1 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: msg_get_u1 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_u1\n");

out:
	smb_msgbuf_term(&mb);
}

/* parse exactly to end of data */
static void
msg_get_u2()
{
	uint16_t wire[] = { 'o', 'n', 'e' };
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;

	smb_msgbuf_init(&mb, (uint8_t *)wire, sizeof (wire), mbflags);

	rc = smb_msgbuf_decode(&mb, "6U", &s);
	if (rc != 6) {
		printf("Fail: msg_get_u2 decode\n");
		goto out;
	}
	if (mb.scan != mb.end) {
		printf("Fail: msg_get_u2 wrong pos\n");
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: msg_get_u2 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_u2\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_get_u3()
{
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;

	smb_msgbuf_init(&mb, (uint8_t *)wcsa, sizeof (wcsa), mbflags);

	rc = smb_msgbuf_decode(&mb, "#U", sizeof (wcsa), &s);
	if (rc != 8) {
		printf("Fail: msg_get_u3 decode\n");
		goto out;
	}
	if (strcmp(s, mbsa) != 0) {
		printf("Fail: msg_get_u3 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_u3\n");

out:
	smb_msgbuf_term(&mb);
}

static void
msg_get_u4()
{
	smb_msgbuf_t mb;
	int mbflags = 0;
	char *s;
	int rc;

	smb_msgbuf_init(&mb, (uint8_t *)wcsp, sizeof (wcsp), mbflags);

	rc = smb_msgbuf_decode(&mb, "#U", sizeof (wcsp), &s);
	if (rc != 10) {
		printf("Fail: msg_get_u4 decode\n");
		goto out;
	}
	if (strcmp(s, mbsp) != 0) {
		printf("Fail: msg_get_u4 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: msg_get_u4\n");

out:
	smb_msgbuf_term(&mb);
}

void
test_msgbuf()
{

	msg_put_a0();
	msg_put_a1();
	msg_put_apad();
	msg_put_atrunc();

	msg_put_u0();
	msg_put_u1();
	msg_put_u3();
	msg_put_u4();
	msg_put_upad();
	msg_put_utrunc();

	msg_get_a0();
	msg_get_a1();
	msg_get_a2();
	msg_get_u0();
	msg_get_u1();
	msg_get_u2();
	msg_get_u3();
	msg_get_u4();

}
