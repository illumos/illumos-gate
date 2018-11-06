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
 * Test conversion of strings UTF-8 to/from UTF-16 etc.
 *
 * This tests both 16-bit unicode symbols (UCS-2) and so called
 * "enhanced" unicode symbols such as the "poop emoji" that are
 * above 65535 and encode to four bytes as UTF-8.
 */

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/u8_textprep.h>
#include <smbsrv/string.h>
#include <stdio.h>
#include <string.h>

#include "test_defs.h"

#define	U_FW_A	0xff21		// full-width A (Ａ)
static const char fwA[4] = "\xef\xbc\xa1";

#define	U_POOP	0x1f4a9		// poop emoji (💩)
static const char poop[5] = "\xf0\x9f\x92\xa9";

static char mbsa[] = "A\xef\xbc\xa1.";		// A fwA . (5)
static char mbsp[] = "P\xf0\x9f\x92\xa9.";	// P poop . (6)
static smb_wchar_t wcsa[] = { 'A', U_FW_A, '.', 0 };	// (3)
static smb_wchar_t wcsp[] = { 'P', 0xd83d, 0xdca9, '.', 0 }; // (4)


static void
conv_wctomb()
{
	char mbs[8];
	int len;

	len = smb_wctomb(mbs, U_FW_A);
	if (len != 3) {
		printf("Fail: conv_wctomb fwA ret=%d\n", len);
		return;
	}
	mbs[len] = '\0';
	if (strcmp(mbs, fwA)) {
		printf("Fail: conv_wctomb fwA cmp:\n");
		hexdump((uchar_t *)mbs, len+1);
		return;
	}

	len = smb_wctomb(mbs, U_POOP);
	if (len != 4) {
		printf("Fail: conv_wctomb poop ret=%d\n", len);
		return;
	}
	mbs[len] = '\0';
	if (strcmp(mbs, poop)) {
		printf("Fail: conv_wctomb poop cmp:\n");
		hexdump((uchar_t *)mbs, len+1);
		return;
	}

	/* null wc to mbs should return 1 and put a null */
	len = smb_wctomb(mbs, 0);
	if (len != 1) {
		printf("Fail: conv_wctomb null ret=%d\n", len);
		return;
	}
	if (mbs[0] != '\0') {
		printf("Fail: conv_wctomb null cmp:\n");
		hexdump((uchar_t *)mbs, len+1);
		return;
	}

	printf("Pass: conv_wctomb\n");
}

static void
conv_mbtowc()
{
	uint32_t wch = 0;
	int len;

	/*
	 * The (void *) cast here is to let this build both
	 * before and after an interface change in smb_mbtowc
	 * (uint16_t vs uint32_t)
	 */
	len = smb_mbtowc((void *)&wch, fwA, 4);
	if (len != 3) {
		printf("Fail: conv_mbtowc fwA ret=%d\n", len);
		return;
	}
	if (wch != U_FW_A) {
		printf("Fail: conv_mbtowc fwA cmp: 0x%x\n", wch);
		return;
	}

	len = smb_mbtowc((void *)&wch, poop, 4); // poop emoji
	if (len != 4) {
		printf("Fail: conv_mbtowc poop ret=%d\n", len);
		return;
	}
	if (wch != U_POOP) {
		printf("Fail: conv_mbtowc poop cmp: 0x%x\n", wch);
		return;
	}

	/* null mbs to wc should return 0 (and set wch=0) */
	len = smb_mbtowc((void *)&wch, "", 4);
	if (len != 0) {
		printf("Fail: conv_mbtowc null ret=%d\n", len);
		return;
	}
	if (wch != 0) {
		printf("Fail: conv_mbtowc null cmp: 0x%x\n", wch);
		return;
	}

	printf("Pass: conv_mbtowc\n");
}

static void
conv_wcstombs()
{
	char tmbs[16];
	int len;

	len = smb_wcstombs(tmbs, wcsa, sizeof (tmbs));
	if (len != 5) {
		printf("Fail: conv_wcstombs A ret=%d\n", len);
		return;
	}
	if (strcmp(tmbs, mbsa)) {
		printf("Fail: conv_wcstombs A cmp:\n");
		hexdump((uchar_t *)tmbs, len+2);
		return;
	}

	len = smb_wcstombs(tmbs, wcsp, sizeof (tmbs));
	if (len != 6) {
		printf("Fail: conv_wcstombs f ret=%d\n", len);
		return;
	}
	if (strcmp(tmbs, mbsp)) {
		printf("Fail: conv_wcstombs f cmp:\n");
		hexdump((uchar_t *)tmbs, len+2);
		return;
	}

	printf("Pass: conv_wcstombs\n");
}

static void
conv_mbstowcs()
{
	smb_wchar_t twcs[8];
	uint32_t wch = 0;
	int len;

	len = smb_mbstowcs(twcs, mbsa, sizeof (twcs));
	if (len != 3) {
		printf("Fail: conv_mbstowcs A ret=%d\n", len);
		return;
	}
	if (memcmp(twcs, wcsa, len+2)) {
		printf("Fail: conv_mbstowcs A cmp: 0x%x\n", wch);
		hexdump((uchar_t *)twcs, len+2);
		return;
	}

	len = smb_mbstowcs(twcs, mbsp, sizeof (twcs));
	if (len != 4) {
		printf("Fail: conv_mbstowcs P ret=%d\n", len);
		return;
	}
	if (memcmp(twcs, wcsp, len+2)) {
		printf("Fail: conv_mbstowcs P cmp: 0x%x\n", wch);
		hexdump((uchar_t *)twcs, len+2);
		return;
	}

	printf("Pass: conv_mbstowcs\n");
}

/*
 * An OEM string that will require iconv.
 */
static uchar_t fubar_oem[] = "F\201bar";	// CP850 x81 (ü)
static char fubar_mbs[] = "F\303\274bar";	// UTF8 xC3 xBC


static void
conv_oemtombs()
{
	char tmbs[16];
	int len;

	len = smb_oemtombs(tmbs, (uchar_t *)"foo", 4);
	if (len != 3) {
		printf("Fail: conv_wctomb foo ret=%d\n", len);
		return;
	}
	if (strcmp(tmbs, "foo")) {
		printf("Fail: conv_wctomb foo cmp:\n");
		hexdump((uchar_t *)tmbs, len+1);
		return;
	}

	len = smb_oemtombs(tmbs, fubar_oem, 7);
	if (len != 6) {
		printf("Fail: conv_oemtombs fubar ret=%d\n", len);
		return;
	}
	if (strcmp(tmbs, fubar_mbs)) {
		printf("Fail: conv_oemtombs fubar cmp:\n");
		hexdump((uchar_t *)tmbs, len+1);
		return;
	}

	printf("Pass: conv_oemtombs\n");
}

static void
conv_mbstooem()
{
	uint8_t oemcs[8];
	uint32_t wch = 0;
	int len;

	len = smb_mbstooem(oemcs, "foo", 8);
	if (len != 3) {
		printf("Fail: conv_mbstooem foo ret=%d\n", len);
		return;
	}
	if (memcmp(oemcs, "foo", len+1)) {
		printf("Fail: conv_mbstooem P cmp: 0x%x\n", wch);
		hexdump((uchar_t *)oemcs, len+1);
		return;
	}

	len = smb_mbstooem(oemcs, fubar_mbs, 8);
	if (len != 5) {
		printf("Fail: conv_mbstooem fubar ret=%d\n", len);
		return;
	}
	if (memcmp(oemcs, (char *)fubar_oem, len+1)) {
		printf("Fail: conv_mbstooem fubar cmp: 0x%x\n", wch);
		hexdump((uchar_t *)oemcs, len+1);
		return;
	}

	len = smb_mbstooem(oemcs, mbsp, 8);
	if (len != 3) {
		printf("Fail: conv_mbstooem poop ret=%d\n", len);
		return;
	}
	if (memcmp(oemcs, "P?.", len+1)) {
		printf("Fail: conv_mbstooem poop cmp: 0x%x\n", wch);
		hexdump((uchar_t *)oemcs, len+1);
		return;
	}

	printf("Pass: conv_mbstooem\n");
}

static void
conv_sbequiv_strlen()
{
	int len;

	len = (int)smb_sbequiv_strlen("a");
	if (len != 1) {
		printf("Fail: conv_sbequiv_strlen (a) len=%d\n", len);
		return;
	}

	len = (int)smb_sbequiv_strlen(fubar_mbs);
	if (len != strlen((char *)fubar_oem)) {
		printf("Fail: conv_sbequiv_strlen (fubar) len=%d\n", len);
		return;
	}

	len = (int)smb_sbequiv_strlen(mbsp);
	if (len != 3) {	// "P?."
		printf("Fail: conv_sbequiv_strlen (poop) len=%d\n", len);
		return;
	}

	printf("Pass: conv_sbequiv_strlen\n");
}

static void
conv_wcequiv_strlen()
{
	int len;

	len = (int)smb_wcequiv_strlen("a");
	if (len != 2) {
		printf("Fail: conv_wcequiv_strlen (a) len=%d\n", len);
		return;
	}

	len = (int)smb_wcequiv_strlen(fwA);
	if (len != 2) {
		printf("Fail: conv_wcequiv_strlen (fwA) len=%d\n", len);
		return;
	}

	len = (int)smb_wcequiv_strlen(poop);
	if (len != 4) {
		printf("Fail: conv_wcequiv_strlen (poop) len=%d\n", len);
		return;
	}

	printf("Pass: conv_wcequiv_strlen\n");
}

void
test_conv()
{
	conv_wctomb();
	conv_mbtowc();
	conv_wcstombs();
	conv_mbstowcs();
	conv_oemtombs();
	conv_mbstooem();
	conv_sbequiv_strlen();
	conv_wcequiv_strlen();
}
