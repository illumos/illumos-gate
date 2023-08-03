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
 * Copyright 2018-2021 Tintri by DDN, Inc. All rights reserved.
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

smb_session_t test_ssn;
smb_request_t test_sr;

/*
 * Put ASCII string with NULL
 */
static void
mbm_put_a0()
{
	uint8_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	rc = smb_mbc_encodef(mbc, "sw", "one", 42);
	if (rc != 0) {
		printf("Fail: mbm_put_a0 encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 6) {
		printf("Fail: mbm_put_a0 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 6)) {
		printf("Fail: mbm_put_a0 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 6);
		return;
	}

	printf("Pass: mbm_put_a0\n");

out:
	smb_mbc_free(mbc);
}

/*
 * Put ASCII string, no NULL
 */
static void
mbm_put_a1()
{
	uint8_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	rc = smb_mbc_encodef(mbc, "4sw", "one.", 42);
	if (rc != 0) {
		printf("Fail: mbm_put_a1 encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 6) {
		printf("Fail: mbm_put_a1 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 6)) {
		printf("Fail: mbm_put_a1 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 6);
		return;
	}

	printf("Pass: mbm_put_a1\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_apad()
{
	uint8_t wire[] = { 'o', 'n', 'e', 0, 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	/* Encode with wire length > strlen */
	rc = smb_mbc_encodef(mbc, "5s", "one");
	if (rc != 0) {
		printf("Fail: mbm_put_apad encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 5) {
		printf("Fail: mbm_put_apad len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 5)) {
		printf("Fail: mbm_put_apad cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 5);
		return;
	}

	printf("Pass: mbm_put_apad\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_atrunc1()
{
	uint8_t wire[] = { 'o', 'n', 'e', 't', };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	/* Encode with wire length < strlen */
	rc = smb_mbc_encodef(mbc, "4s", "onetwo");
	if (rc != 0) {
		printf("Fail: mbm_put_atrunc1 encode\n");
		goto out;
	}
	/* Trunc should put exactly 4 */
	if (mbc->chain->m_len != 4) {
		printf("Fail: mbm_put_atrunc1 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 4)) {
		printf("Fail: mbm_put_atrunc1 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 4);
		return;
	}

	printf("Pass: mbm_put_atrunc1\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_atrunc2()
{
	uint8_t wire[] = { 'o', 'n', 'e', 't', 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(4);

	/* Encode with wire length < strlen */
	rc = smb_mbc_encodef(mbc, "s", "onetwo");
	if (rc != 1) {
		printf("Fail: mbm_put_atrunc2 encode rc=%d\n", rc);
		goto out;
	}
	/* Trunc should put exactly 4 */
	if (mbc->chain->m_len != 4) {
		printf("Fail: mbm_put_atrunc2 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 5)) {
		printf("Fail: mbm_put_atrunc2 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 4);
		return;
	}

	printf("Pass: mbm_put_atrunc2\n");

out:
	smb_mbc_free(mbc);
}

/*
 * Put unicode string with NULL
 */
static void
mbm_put_u0()
{
	uint16_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	rc = smb_mbc_encodef(mbc, "Uw", "one", 42);
	if (rc != 0) {
		printf("Fail: mbm_put_u0 encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 10) {
		printf("Fail: mbm_put_u0 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 10)) {
		printf("Fail: mbm_put_u0 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 10);
		return;
	}

	printf("Pass: mbm_put_u0\n");

out:
	smb_mbc_free(mbc);
}

/*
 * Put unicode string, no NULL
 */
static void
mbm_put_u1()
{
	uint16_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	rc = smb_mbc_encodef(mbc, "8Uw", "one.", 42);
	if (rc != 0) {
		printf("Fail: mbm_put_u1 encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 10) {
		printf("Fail: mbm_put_u1 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 10)) {
		printf("Fail: mbm_put_u1 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 10);
		return;
	}

	printf("Pass: mbm_put_u1\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_u3()
{
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	rc = smb_mbc_encodef(mbc, "U", mbsa);
	if (rc != 0) {
		printf("Fail: mbm_put_u3 encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 8) {
		printf("Fail: mbm_put_u3 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wcsa, 8)) {
		printf("Fail: mbm_put_u3 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 8);
		return;
	}

	printf("Pass: mbm_put_u3\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_u4()
{
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	rc = smb_mbc_encodef(mbc, "U", mbsp);
	if (rc != 0) {
		printf("Fail: mbm_put_u4 encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 10) {
		printf("Fail: mbm_put_u4 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wcsp, 10)) {
		printf("Fail: mbm_put_u4 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 10);
		return;
	}

	printf("Pass: mbm_put_u4\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_upad()
{
	uint16_t wire[] = { 'o', 'n', 'e', 0, 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	/* Encode with wire length > strlen */
	rc = smb_mbc_encodef(mbc, "10U", "one");
	if (rc != 0) {
		printf("Fail: mbm_put_upad encode\n");
		goto out;
	}
	if (mbc->chain->m_len != 10) {
		printf("Fail: mbm_put_upad len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 10)) {
		printf("Fail: mbm_put_upad cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 10);
		return;
	}

	printf("Pass: mbm_put_upad\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_utrunc1()
{
	uint16_t wire[] = { 'o', 'n', 'e', 't' };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(100);

	/* Encode with wire length < strlen */
	rc = smb_mbc_encodef(mbc, "8U", "onetwo");
	if (rc != 0) {
		printf("Fail: mbm_put_utrunc1 encode\n");
		goto out;
	}
	/* Trunc should put exactly 8 */
	if (mbc->chain->m_len != 8) {
		printf("Fail: mbm_put_utrunc1 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 8)) {
		printf("Fail: mbm_put_utrunc1 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 8);
		return;
	}

	printf("Pass: mbm_put_utrunc1\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_utrunc2()
{
	uint16_t wire[] = { 'o', 'n', 'e', 't', 0 };
	mbuf_chain_t *mbc;
	int rc;

	mbc = smb_mbc_alloc(8);

	/* Encode with wire length < strlen */
	rc = smb_mbc_encodef(mbc, "U", "onetwo");
	if (rc != 1) {
		printf("Fail: mbm_put_utrunc2 encode rc=%d\n", rc);
		goto out;
	}
	/* Trunc should put exactly 8 */
	if (mbc->chain->m_len != 8) {
		printf("Fail: mbm_put_utrunc2 len=%d\n",
		    mbc->chain->m_len);
		return;
	}

	if (memcmp(mbc->chain->m_data, wire, 10)) {
		printf("Fail: mbm_put_utrunc2 cmp:\n");
		hexdump((uchar_t *)mbc->chain->m_data, 8);
		return;
	}

	printf("Pass: mbm_put_utrunc2\n");

out:
	smb_mbc_free(mbc);
}

static void
mbm_put_mbuf1()
{
	uint8_t wire[] = "onetwo";
	mbuf_chain_t mbc, mbc2;
	int rc;

	MBC_INIT(&mbc, 16);
	MBC_INIT(&mbc2, 8);

	rc = smb_mbc_encodef(&mbc, "3s", "one");
	if (rc != 0) {
		printf("Fail: mbm_put_mbuf1 encode 1 rc=%d\n", rc);
		goto out;
	}
	if (mbc.chain_offset != 3) {
		printf("Fail: mbm_put_mbuf1 encode 1 len=%d\n",
		    mbc.chain_offset);
		goto out;
	}

	rc = smb_mbc_encodef(&mbc2, "s", "two");
	if (rc != 0) {
		printf("Fail: mbm_put_mbuf1 encode 2 rc=%d\n", rc);
		goto out;
	}
	if (mbc2.chain_offset != 4) {
		printf("Fail: mbm_put_mbuf1 encode 2 len=%d\n",
		    mbc.chain_offset);
		goto out;
	}

	/* Append */
	rc = smb_mbc_encodef(&mbc, "m", mbc2.chain);
	mbc2.chain = NULL;
	if (rc != 0) {
		printf("Fail: mbm_put_mbuf1 encode 3 rc=%d\n", rc);
		goto out;
	}
	if (mbc.chain_offset != 7) {
		printf("Fail: mbm_put_mbuf1 encode 3 len=%d\n",
		    mbc.chain_offset);
		goto out;
	}

	if (memcmp(mbc.chain->m_data, wire, 7)) {
		printf("Fail: mbm_put_mbuf1 cmp:\n");
		hexdump((uchar_t *)mbc.chain->m_data, 7);
		goto out;
	}

	printf("Pass: mbm_put_mbuf1\n");

out:
	MBC_FLUSH(&mbc);
	MBC_FLUSH(&mbc2);
}

/*
 * Verify m_prepend works
 */
static void
mbm_put_mbuf2()
{
	uint8_t wire[] = "one.two";
	mbuf_chain_t mbc;
	mbuf_t *m;
	int len, rc;

	MBC_INIT(&mbc, 512);

	rc = smb_mbc_encodef(&mbc, "s", "two");
	if (rc != 0) {
		printf("Fail: mbm_put_mbuf2 encode 1 rc=%d\n", rc);
		goto out;
	}
	if (mbc.chain_offset != 4) {
		printf("Fail: mbm_put_mbuf2 encode 1 len=%d\n",
		    mbc.chain_offset);
		goto out;
	}

	/* Prepend.  Should use prepend space, not allocate. */
	m = m_prepend(mbc.chain, 4, M_WAIT);
	if (m != mbc.chain) {
		(void) m_free(m);
		printf("Fail: mbm_put_mbuf2 m_prepend error\n", rc);
		goto out;
	}

	/* Now write into the prepend space. */
	bcopy("one.", m->m_data, 4);

	/* Verify length and content */
	len = MBC_LENGTH(&mbc);
	if (len != 8) {
		printf("Fail: mbm_put_mbuf2 encode 2 len=%d\n",
		    mbc.chain_offset);
		goto out;
	}

	if (memcmp(mbc.chain->m_data, wire, 7)) {
		printf("Fail: mbm_put_mbuf2 cmp:\n");
		hexdump((uchar_t *)mbc.chain->m_data, 7);
		goto out;
	}

	printf("Pass: mbm_put_mbuf2\n");

out:
	MBC_FLUSH(&mbc);
}

/*
 * Check how mbc_marshal_make_room crosses a message boundary
 */
static void
mbm_put_mbuf3()
{
	mbuf_chain_t mbc;
	mbuf_t *m;
	char *p;
	int rc;

	MBC_INIT(&mbc, 16384);

	/*
	 * Encode near the end of the first mbuf
	 * running over into the second.
	 */
	m = mbc.chain;
	mbc.chain_offset = M_TRAILINGSPACE(m) - 4;
	rc = smb_mbc_encodef(&mbc, "s", "one.two");
	if (rc != 0) {
		printf("Fail: mbm_put_mbuf3 encode 1 rc=%d\n", rc);
		goto out;
	}

	/* Verify first segment */
	p = m->m_data + m->m_len - 4;
	if (memcmp(p, "one.", 4)) {
		printf("Fail: mbm_put_mbuf3 cmp1:\n");
		hexdump((uchar_t *)p, 4);
		goto out;
	}

	/* Verify second segment */
	p = m->m_next->m_data;
	if (memcmp(p, "two", 4)) {
		printf("Fail: mbm_put_mbuf3 cmp2:\n");
		hexdump((uchar_t *)p, 4);
		goto out;
	}

	printf("Pass: mbm_put_mbuf3\n");

out:
	MBC_FLUSH(&mbc);
}

/*
 * Parse an ascii string.
 */
static void
mbm_get_a0()
{
	uint8_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	mbuf_chain_t mbc;
	char *s;
	int rc;
	uint16_t w;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wire, sizeof (wire));

	rc = smb_mbc_decodef(&mbc, "%sw", &test_sr, &s, &w);
	if (rc != 0) {
		printf("Fail: mbm_get_a0 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: mbm_get_a0 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: mbm_get_a0 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_a0\n");

out:
	MBC_FLUSH(&mbc);
}

/*
 * Parse an ascii string, no NULL
 */
static void
mbm_get_a1()
{
	uint8_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	mbuf_chain_t mbc;
	char *s;
	int rc;
	uint16_t w;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wire, sizeof (wire));

	rc = smb_mbc_decodef(&mbc, "%3s.w", &test_sr, &s, &w);
	if (rc != 0) {
		printf("Fail: mbm_get_a1 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: mbm_get_a1 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: mbm_get_a1 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_a1\n");

out:
	MBC_FLUSH(&mbc);
}

/* parse exactly to end of data */
static void
mbm_get_a2()
{
	uint8_t wire[] = { 'o', 'n', 'e' };
	mbuf_chain_t mbc;
	char *s;
	int rc;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wire, sizeof (wire));

	rc = smb_mbc_decodef(&mbc, "%3s", &test_sr, &s);
	if (rc != 0) {
		printf("Fail: mbm_get_a2 decode\n");
		goto out;
	}
	if (mbc.chain_offset != 3) {
		printf("Fail: mbm_get_a2 wrong pos\n");
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: mbm_get_a2 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_a2\n");

out:
	MBC_FLUSH(&mbc);
}

/*
 * Parse a unicode string.
 */
static void
mbm_get_u0()
{
	uint16_t wire[] = { 'o', 'n', 'e', 0, 42, 0 };
	mbuf_chain_t mbc;
	char *s;
	int rc;
	uint16_t w;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wire, sizeof (wire));

	rc = smb_mbc_decodef(&mbc, "%Uw", &test_sr, &s, &w);
	if (rc != 0) {
		printf("Fail: mbm_get_u0 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: mbm_get_u0 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: mbm_get_u0 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_u0\n");

out:
	MBC_FLUSH(&mbc);
}

/*
 * Parse a string that's NOT null terminated.
 */
static void
mbm_get_u1()
{
	uint16_t wire[] = { 'o', 'n', 'e', '.', 42, 0 };
	mbuf_chain_t mbc;
	char *s;
	int rc;
	uint16_t w;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wire, sizeof (wire));

	rc = smb_mbc_decodef(&mbc, "%6U..w", &test_sr, &s, &w);
	if (rc != 0) {
		printf("Fail: mbm_get_u1 decode\n");
		goto out;
	}
	/*
	 * Decode a word after the string to make sure we
	 * end up positioned correctly after the string.
	 */
	if (w != 42) {
		printf("Fail: mbm_get_u1 w=%d\n", w);
		return;
	}
	if (strcmp(s, "one") != 0) {
		printf("Fail: mbm_get_u1 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_u1\n");

out:
	MBC_FLUSH(&mbc);
}

/* parse exactly to end of data */
static void
mbm_get_u2()
{
	uint16_t wire[] = { 't', 'w', 'o' };
	mbuf_chain_t mbc;
	char *s;
	int rc;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wire, sizeof (wire));

	rc = smb_mbc_decodef(&mbc, "%6U", &test_sr, &s);
	if (rc != 0) {
		printf("Fail: mbm_get_u2 decode\n");
		goto out;
	}
	if (mbc.chain_offset != 6) {
		printf("Fail: mbm_get_u2 wrong pos\n");
		return;
	}
	if (strcmp(s, "two") != 0) {
		printf("Fail: mbm_get_u2 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_a2\n");

out:
	MBC_FLUSH(&mbc);
}

static void
mbm_get_u3()
{
	mbuf_chain_t mbc;
	char *s;
	int rc;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wcsa, sizeof (wcsa));

	rc = smb_mbc_decodef(&mbc, "%#U", &test_sr, sizeof (wcsa), &s);
	if (rc != 0) {
		printf("Fail: mbm_get_u3 decode\n");
		goto out;
	}
	if (strcmp(s, mbsa) != 0) {
		printf("Fail: mbm_get_u3 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_u3\n");

out:
	MBC_FLUSH(&mbc);
}

static void
mbm_get_u4()
{
	mbuf_chain_t mbc;
	char *s;
	int rc;

	bzero(&mbc, sizeof (mbc));
	MBC_ATTACH_BUF(&mbc, (uchar_t *)wcsp, sizeof (wcsp));

	rc = smb_mbc_decodef(&mbc, "%#U", &test_sr, sizeof (wcsp), &s);
	if (rc != 0) {
		printf("Fail: mbm_get_u4 decode\n");
		goto out;
	}
	if (strcmp(s, mbsp) != 0) {
		printf("Fail: mbm_get_u4 cmp: <%s>\n", s);
		return;
	}

	printf("Pass: mbm_get_u4\n");

out:
	MBC_FLUSH(&mbc);
}

void
test_mbmarshal()
{

	smb_mbc_init();

	test_ssn.dialect = 0x210;	// SMB 2.1
	test_sr.session = &test_ssn;
	test_sr.sr_magic = SMB_REQ_MAGIC;
	smb_srm_init(&test_sr);

	mbm_put_a0();
	mbm_put_a1();
	mbm_put_apad();
	mbm_put_atrunc1();
	mbm_put_atrunc2();

	mbm_put_u0();
	mbm_put_u1();
	mbm_put_u3();
	mbm_put_u4();
	mbm_put_upad();
	mbm_put_utrunc1();
	mbm_put_utrunc2();

	mbm_put_mbuf1();
	mbm_put_mbuf2();
	mbm_put_mbuf3();

	mbm_get_a0();
	mbm_get_a1();
	mbm_get_a2();
	mbm_get_u0();
	mbm_get_u1();
	mbm_get_u2();
	mbm_get_u3();
	mbm_get_u4();

	smb_srm_fini(&test_sr);
	smb_mbc_fini();
}
