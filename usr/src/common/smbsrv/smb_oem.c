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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Support for oem <-> unicode translations.
 */

#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <string.h>
#else
#include <sys/ksynch.h>
#endif /* _KERNEL */

#include <sys/byteorder.h>
#include <smbsrv/alloc.h>
#include <smbsrv/string.h>

/*
 * cpid		The oemcpg_table index for this oempage.
 * value	The conversion values.
 */
typedef struct oempage {
	uint32_t	cpid;
	smb_wchar_t	*value;
} oempage_t;

/*
 * filename	The actual filename contains the codepage.
 * bytesperchar	The codepage uses double or single bytes per char.
 * oempage	The oempage is used to convert Unicode characters to
 *		OEM characters.  Memory needs to be allocated for
 *		the value field of oempage to store the table.
 * ucspage	The unicode page is used to convert OEM characters
 *		to Unicode characters.  Memory needs to be allocated
 *		for the value field of ucspage to store the table.
 * valid	True if the codepage has been initialized.
 */
typedef struct oem_codepage {
	char		*filename;
	uint32_t	bytesperchar;
	oempage_t	oempage;
	oempage_t	ucspage;
	boolean_t	valid;
} oem_codepage_t;

static oem_codepage_t oemcpg_table[] = {
	{"850.cpg",  1, {0, 0},  {0, 0},  0},	/* Multilingual Latin1 */
	{"950.cpg",  2, {1, 0},  {1, 0},  0},	/* Chinese Traditional */
	{"1252.cpg", 1, {2, 0},  {2, 0},  0},	/* MS Latin1 */
	{"949.cpg",  2, {3, 0},  {3, 0},  0},	/* Korean */
	{"936.cpg",  2, {4, 0},  {4, 0},  0},	/* Chinese Simplified */
	{"932.cpg",  2, {5, 0},  {5, 0},  0},	/* Japanese */
	{"852.cpg",  1, {6, 0},  {6, 0},  0},	/* Multilingual Latin2 */
	{"1250.cpg", 1, {7, 0},  {7, 0},  0},	/* MS Latin2 */
	{"1253.cpg", 1, {8, 0},  {8, 0},  0},	/* MS Greek */
	{"737.cpg",  1, {9, 0},  {9, 0},  0},	/* Greek */
	{"1254.cpg", 1, {10, 0}, {10, 0}, 0},	/* MS Turkish */
	{"857.cpg",  1, {11, 0}, {11, 0}, 0},	/* Multilingual Latin5 */
	{"1251.cpg", 1, {12, 0}, {12, 0}, 0},	/* MS Cyrillic */
	{"866.cpg",  1, {13, 0}, {13, 0}, 0},	/* Cyrillic II */
	{"1255.cpg", 1, {14, 0}, {14, 0}, 0},	/* MS Hebrew */
	{"862.cpg",  1, {15, 0}, {15, 0}, 0},	/* Hebrew */
	{"1256.cpg", 1, {16, 0}, {16, 0}, 0},	/* MS Arabic */
	{"720.cpg",  1, {17, 0}, {17, 0}, 0}	/* Arabic */
};

#define	MAX_OEMPAGES	(sizeof (oemcpg_table) / sizeof (oemcpg_table[0]))
#define	MAX_UNICODE_IDX	65536

/*
 * The default SMB OEM codepage for English is codepage 850.
 */
const smb_wchar_t oem_codepage_850[256] = {
	0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
	0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F,
	0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017,
	0x0018, 0x0019, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F,
	0x0020, 0x0021, 0x0022, 0x0023, 0x0024, 0x0025, 0x0026, 0x0027,
	0x0028, 0x0029, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F,
	0x0030, 0x0031, 0x0032, 0x0033, 0x0034, 0x0035, 0x0036, 0x0037,
	0x0038, 0x0039, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F,
	0x0040, 0x0041, 0x0042, 0x0043, 0x0044, 0x0045, 0x0046, 0x0047,
	0x0048, 0x0049, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F,
	0x0050, 0x0051, 0x0052, 0x0053, 0x0054, 0x0055, 0x0056, 0x0057,
	0x0058, 0x0059, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F,
	0x0060, 0x0061, 0x0062, 0x0063, 0x0064, 0x0065, 0x0066, 0x0067,
	0x0068, 0x0069, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F,
	0x0070, 0x0071, 0x0072, 0x0073, 0x0074, 0x0075, 0x0076, 0x0077,
	0x0078, 0x0079, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F,
	0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
	0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
	0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
	0x00FF, 0x00D6, 0x00DC, 0x00F8, 0x00A3, 0x00D8, 0x00D7, 0x0192,
	0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
	0x00BF, 0x00AE, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
	0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x00C1, 0x00C2, 0x00C0,
	0x00A9, 0x2563, 0x2551, 0x2557, 0x255D, 0x00A2, 0x00A5, 0x2510,
	0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x00E3, 0x00C3,
	0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x00A4,
	0x00F0, 0x00D0, 0x00CA, 0x00CB, 0x00C8, 0x0131, 0x00CD, 0x00CE,
	0x00CF, 0x2518, 0x250C, 0x2588, 0x2584, 0x00A6, 0x00CC, 0x2580,
	0x00D3, 0x00DF, 0x00D4, 0x00D2, 0x00F5, 0x00D5, 0x00B5, 0x00FE,
	0x00DE, 0x00DA, 0x00DB, 0x00D9, 0x00FD, 0x00DD, 0x00AF, 0x00B4,
	0x00AD, 0x00B1, 0x2017, 0x00BE, 0x00B6, 0x00A7, 0x00F7, 0x00B8,
	0x00B0, 0x00A8, 0x00B7, 0x00B9, 0x00B3, 0x00B2, 0x25A0, 0x00A0
};

/*
 * The default telnet OEM codepage for English is codepage 1252.
 */
const smb_wchar_t oem_codepage_1252[256] = {
	0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
	0x9, 0x000A, 0x000B, 0x000C, 0x000D, 0x000E, 0x000F, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x001A, 0x001B, 0x001C, 0x001D, 0x001E, 0x001F, 0x20,
	0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	0x29, 0x002A, 0x002B, 0x002C, 0x002D, 0x002E, 0x002F, 0x30,
	0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
	0x39, 0x003A, 0x003B, 0x003C, 0x003D, 0x003E, 0x003F, 0x40,
	0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
	0x49, 0x004A, 0x004B, 0x004C, 0x004D, 0x004E, 0x004F, 0x50,
	0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
	0x59, 0x005A, 0x005B, 0x005C, 0x005D, 0x005E, 0x005F, 0x60,
	0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
	0x69, 0x006A, 0x006B, 0x006C, 0x006D, 0x006E, 0x006F, 0x70,
	0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
	0x79, 0x007A, 0x007B, 0x007C, 0x007D, 0x007E, 0x007F, 0x20AC,
	0x81, 0x201A, 0x192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6,
	0x2030, 0x160, 0x2039, 0x152, 0x8D, 0x017D, 0x8F, 0x90,
	0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC,
	0x2122, 0x161, 0x203A, 0x153, 0x9D, 0x017E, 0x178, 0x00A0,
	0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7, 0x00A8,
	0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF, 0x00B0,
	0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7, 0x00B8,
	0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF, 0x00C0,
	0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7, 0x00C8,
	0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF, 0x00D0,
	0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7, 0x00D8,
	0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF, 0x00E0,
	0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7, 0x00E8,
	0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF, 0x00F0,
	0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7, 0x00F8,
	0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF
};

static oempage_t *oem_get_oempage(uint32_t);
static oempage_t *oem_get_ucspage(uint32_t);
static void oem_codepage_init(uint32_t);
static void oem_codepage_setup(uint32_t);

/*
 * Convert a unicode string to an oem string.
 *
 * The conversion will stop at the end of the unicode string
 * or when (nbytes - 1) oem characters have been stored.
 *
 * The number of converted unicode characters is returned,
 * or 0 on error.
 */
size_t
ucstooem(char *oem, const smb_wchar_t *ucs, size_t nbytes, uint32_t cpid)
{
	oempage_t	*ucspage;
	uint32_t	count = 0;
	smb_wchar_t	oemchar;

	if (ucs == NULL || oem == NULL)
		return (0);

	if ((ucspage = oem_get_ucspage(cpid)) == NULL)
		return (0);

	while (nbytes != 0 && (oemchar = ucspage->value[*ucs]) != 0) {
		if (oemchar & 0xff00 && nbytes >= MTS_MB_CHAR_MAX) {
			*oem++ = oemchar >> 8;
			*oem++ = (char)oemchar;
			nbytes -= 2;
		} else if (nbytes > 1) {
			*oem++ = (char)oemchar;
			nbytes--;
		} else {
			break;
		}

		count++;
		ucs++;
	}

	*oem = '\0';
	return (count);
}

/*
 * Convert an oem string to a unicode string.
 *
 * The conversion will stop at the end of the oem string or
 * when nwchars - 1 have been converted.
 *
 * The number of converted oem chars is returned, or 0 on error.
 * An oem char may be either 1 or 2 bytes.
 */
size_t
oemtoucs(smb_wchar_t *ucs, const char *oem, size_t nwchars, uint32_t cpid)
{
	oempage_t	*oempage;
	size_t		count = nwchars;
	smb_wchar_t	oemchar;

	if (ucs == NULL || oem == NULL)
		return (0);

	if ((oempage = oem_get_oempage(cpid)) == NULL)
		return (0);

	while ((oemchar = (smb_wchar_t)*oem++ & 0xff) != 0) {
		/*
		 * Cannot find one byte oemchar in table.
		 * Must be a lead byte. Try two bytes.
		 */
		if ((oempage->value[oemchar] == 0) && (oemchar != 0)) {
			oemchar = oemchar << 8 | (*oem++ & 0xff);
			if (oempage->value[oemchar] == 0) {
				*ucs = 0;
				break;
			}
		}
#ifdef _BIG_ENDIAN
		*ucs = LE_IN16(&oempage->value[oemchar]);
#else
		*ucs = oempage->value[oemchar];
#endif
		count--;
		ucs++;
	}

	*ucs = 0;
	return (nwchars - count);
}

/*
 * Get a pointer to the oem page for the specific codepage id.
 */
static oempage_t *
oem_get_oempage(uint32_t cpid)
{
	if (cpid >= MAX_OEMPAGES)
		return (NULL);

	if (!oemcpg_table[cpid].valid) {
		oem_codepage_init(cpid);

		if (!oemcpg_table[cpid].valid)
			return (NULL);
	}

	return (&oemcpg_table[cpid].oempage);
}

/*
 * Get a pointer to the ucs page for the specific codepage id.
 */
static oempage_t *
oem_get_ucspage(uint32_t cpid)
{
	if (cpid >= MAX_OEMPAGES)
		return (NULL);

	if (!oemcpg_table[cpid].valid) {
		oem_codepage_init(cpid);

		if (!oemcpg_table[cpid].valid)
			return (NULL);
	}

	return (&oemcpg_table[cpid].ucspage);
}

/*
 * Initialize the oem page in the oem table.
 */
static void
oem_codepage_init(uint32_t cpid)
{
#if !defined(_KERNEL) && !defined(_FAKE_KERNEL)
	static mutex_t mutex;

	(void) mutex_lock(&mutex);
	oem_codepage_setup(cpid);
	(void) mutex_unlock(&mutex);
#else
	static kmutex_t mutex;

	mutex_enter(&mutex);
	oem_codepage_setup(cpid);
	mutex_exit(&mutex);
#endif /* _KERNEL */
}

static void
oem_codepage_setup(uint32_t cpid)
{
	const smb_wchar_t *default_oem_cp;
	oem_codepage_t	*oemcpg;
	uint32_t	bytesperchar;
	uint32_t	max_oem_index;
	int		i;

	switch (cpid) {
	case OEM_CPG_850:
		default_oem_cp = oem_codepage_850;
		break;
	case OEM_CPG_1252:
		default_oem_cp = oem_codepage_1252;
	default:
		return;
	}

	oemcpg = &oemcpg_table[cpid];
	if (oemcpg->valid)
		return;

	/*
	 * max_oem_index will be 256 or 65536 dependent
	 * on the OEM codepage.
	 */
	bytesperchar = oemcpg_table[cpid].bytesperchar;
	max_oem_index = 1 << (bytesperchar * 8);

	oemcpg->oempage.value =
	    MEM_ZALLOC("oem", max_oem_index * sizeof (smb_wchar_t));
	if (oemcpg->oempage.value == NULL)
		return;

	oemcpg->ucspage.value =
	    MEM_ZALLOC("oem", MAX_UNICODE_IDX * sizeof (smb_wchar_t));
	if (oemcpg->ucspage.value == NULL) {
		MEM_FREE("oem", oemcpg->oempage.value);
		oemcpg->oempage.value = NULL;
		return;
	}

	for (i = 0; i < max_oem_index; i++) {
		oemcpg->oempage.value[i] = default_oem_cp[i];
		oemcpg->ucspage.value[default_oem_cp[i]] = (smb_wchar_t)i;
	}

	oemcpg->valid = B_TRUE;
}
