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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support for oem <-> unicode translations.
 */

#ifndef _KERNEL
#include <stdio.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>
#include <string.h>
#endif /* _KERNEL */
#include <smbsrv/alloc.h>
#include <smbsrv/string.h>
#include <smbsrv/oem.h>
#include <sys/byteorder.h>
/*
 * name: Name used to show on the telnet/GUI.
 * filename: The actual filename contains the codepage.
 * doublebytes: The codepage is double or single byte.
 * oempage: The oempage is used to convert Unicode to OEM chars.
 *		Memory needs to be allocated for value field of oempage
 *		to store the entire table.
 * unipage: The unipage is used to convert OEM to Unicode chars.
 *		Memory needs to be allocated for value field of unipage
 *		to store the entire table.
 * valid: This field indicates if the page is valid or not.
 * ref: This ref count is used to keep track of the usage of BOTH
 *		oempage and unipage.
 * Note: If the cpid of the table is changed, please change the
 * codepage_id in oem.h as well.
 */
typedef struct oem_codepage {
	char *filename;
	unsigned int bytesperchar;
	oempage_t oempage;
	oempage_t unicodepage;
	unsigned int valid;
	unsigned int ref;
} oem_codepage_t;

static oem_codepage_t oemcp_table[] = {
	{"850.cpg", 1, {0, 0}, {0, 0}, 0, 0},	/* Multilingual Latin1 */
	{"950.cpg", 2, {1, 0}, {1, 0}, 0, 0},	/* Chinese Traditional */
	{"1252.cpg", 1, {2, 0}, {2, 0}, 0, 0},	/* MS Latin1 */
	{"949.cpg", 2, {3, 0}, {3, 0}, 0, 0},	/* Korean */
	{"936.cpg", 2, {4, 0}, {4, 0}, 0, 0},	/* Chinese Simplified */
	{"932.cpg", 2, {5, 0}, {5, 0}, 0, 0},	/* Japanese */
	{"852.cpg", 1, {6, 0}, {6, 0}, 0, 0},	/* Multilingual Latin2 */
	{"1250.cpg", 1, {7, 0}, {7, 0}, 0, 0},	/* MS Latin2 */
	{"1253.cpg", 1, {8, 0}, {8, 0}, 0, 0},	/* MS Greek */
	{"737.cpg", 1, {9, 0}, {9, 0}, 0, 0},	/* Greek */
	{"1254.cpg", 1, {10, 0}, {10, 0}, 0, 0}, /* MS Turkish */
	{"857.cpg", 1, {11, 0}, {11, 0}, 0, 0},	/* Multilingual Latin5 */
	{"1251.cpg", 1, {12, 0}, {12, 0}, 0, 0}, /* MS Cyrillic */
	{"866.cpg", 1, {13, 0}, {13, 0}, 0, 0},	/* Cyrillic II */
	{"1255.cpg", 1, {14, 0}, {14, 0}, 0, 0}, /* MS Hebrew */
	{"862.cpg", 1, {15, 0}, {15, 0}, 0, 0},	/* Hebrew */
	{"1256.cpg", 1, {16, 0}, {16, 0}, 0, 0}, /* MS Arabic */
	{"720.cpg", 1, {17, 0}, {17, 0}, 0, 0}	/* Arabic */
};

static language lang_table[] = {
	{"Arabic", OEM_CP_IND_720, OEM_CP_IND_1256},
	{"Brazilian", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Chinese Traditional", OEM_CP_IND_950, OEM_CP_IND_950},
	{"Chinese Simplified", OEM_CP_IND_936, OEM_CP_IND_936},
	{"Czech", OEM_CP_IND_852, OEM_CP_IND_1250},
	{"Danish", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Dutch", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"English", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Finnish", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"French", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"German", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Greek", OEM_CP_IND_737, OEM_CP_IND_1253},
	{"Hebrew", OEM_CP_IND_862, OEM_CP_IND_1255},
	{"Hungarian", OEM_CP_IND_852, OEM_CP_IND_1250},
	{"Italian", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Japanese", OEM_CP_IND_932, OEM_CP_IND_932},
	{"Korean", OEM_CP_IND_949, OEM_CP_IND_949},
	{"Norwegian", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Polish", OEM_CP_IND_852, OEM_CP_IND_1250},
	{"Russian", OEM_CP_IND_866, OEM_CP_IND_1251},
	{"Slovak", OEM_CP_IND_852, OEM_CP_IND_1250},
	{"Slovenian", OEM_CP_IND_852, OEM_CP_IND_1250},
	{"Spanish", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Swedish", OEM_CP_IND_850, OEM_CP_IND_1252},
	{"Turkish", OEM_CP_IND_857, OEM_CP_IND_1254}
};



/*
 * The oem_default_smb_cp is the default smb codepage for English.
 * It is actually codepage 850.
 */
mts_wchar_t oem_default_smb_cp[256] = {
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
 * The oem_default_telnet_cp is the default telnet codepage for English.
 * It is actually codepage 1252.
 */
mts_wchar_t oem_default_telnet_cp[256] = {
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


#define	MAX_OEMPAGES (sizeof (oemcp_table) / sizeof (oemcp_table[0]))
#define	MAX_UNI_IDX 65536



/*
 * oem_codepage_bytesperchar
 *
 * This function returns the max bytes per oem char for the specified
 * oem table. This basically shows if the oem codepage is single or
 * double bytes.
 */
static unsigned int
oem_codepage_bytesperchar(unsigned int cpid)
{
	if (cpid >= MAX_OEMPAGES)
		return (0);
	else
		return (oemcp_table[cpid].bytesperchar);
}



/*
 * oem_get_codepage_path
 *
 * This function will get the codepage path.
 */
const char *
oem_get_codepage_path(void)
{
#ifdef PBSHORTCUT /* */
	const char *path = getenv("codepage.oem.directory");
	if (path == 0)
		return ("/");
	else
		return (path);
#else /* PBSHORTCUT */
	return ("/");
#endif /* PBSHORTCUT */
}

/*
 * oem_codepage_init
 *
 * This function will init oem page via the cpid of the oem table.
 * The function oem_codepage_free must be called when the oempage is
 * no longer needed to free up the allocated memory. If the codepage is
 * successfully initialized, zero will be the return value; otherwise
 * -1 will be the return value.
 */
int
oem_codepage_init(unsigned int cpid)
{
#ifndef _KERNEL
	FILE *fp;
	static mutex_t mutex;
	char buf[32];
	char filePath[100];
#endif /* _KERNEL */
	unsigned int max_oem_index;
	const char *codepagePath = oem_get_codepage_path();
	mts_wchar_t *default_oem_cp = 0;
	oem_codepage_t *oemcp;

	/*
	 * The OEM codepages 850 and 1252 are stored in kernel; therefore,
	 * no need for codepagePath to be defined to work.
	 */
	if (cpid >= MAX_OEMPAGES ||
	    (codepagePath == 0 &&
	    cpid != oem_default_smb_cpid && cpid != oem_default_telnet_cpid))
		return (-1);

	max_oem_index = 1 << oem_codepage_bytesperchar(cpid) * 8;
	/*
	 * Use mutex so no two same index can be initialize
	 * at the same time.
	 */
#ifndef _KERNEL
	(void) mutex_lock(&mutex);
#endif /* _KERNEL */

	oemcp = &oemcp_table[cpid];
	if (oemcp->valid) {
		oemcp->valid++;
#ifndef _KERNEL
		(void) mutex_unlock(&mutex);
#endif /* _KERNEL */
		return (0);
	}

	oemcp->oempage.value =
	    MEM_ZALLOC("oem", max_oem_index * sizeof (mts_wchar_t));
	if (oemcp->oempage.value == 0) {
#ifndef _KERNEL
		(void) mutex_unlock(&mutex);
#endif /* _KERNEL */
		return (-1);
	}

	oemcp->unicodepage.value =
	    MEM_ZALLOC("oem", MAX_UNI_IDX * sizeof (mts_wchar_t));
	if (oemcp->unicodepage.value == 0) {
		MEM_FREE("oem", oemcp->oempage.value);
		oemcp->oempage.value = 0;
#ifndef _KERNEL
		(void) mutex_unlock(&mutex);
#endif /* _KERNEL */
		return (-1);
	}

	/*
	 * The default English page is stored in kernel.
	 * Therefore, no need to go to codepage files.
	 */
#ifndef _KERNEL
	if (cpid == oem_default_smb_cpid)
		default_oem_cp = oem_default_smb_cp;
	else if (cpid == oem_default_telnet_cpid)
		default_oem_cp = oem_default_telnet_cp;
	else
		default_oem_cp = 0;
#else /* _KERNEL */
	default_oem_cp = oem_default_smb_cp;
#endif /* _KERNEL */

	if (default_oem_cp) {
		int i;

		for (i = 0; i < max_oem_index; i++) {
			oemcp->oempage.value[i] = default_oem_cp[i];
			oemcp->unicodepage.value[default_oem_cp[i]] =
			    (mts_wchar_t)i;
		}
#ifdef _KERNEL
	}
	/*
	 * XXX This doesn't seem right.  How do we handle the situation
	 * where default_oem_cp == 0 in the kernel?
	 * Is this a PBSHORTCUT?
	 */
#else
	} else {

		/*
		 * The codepage is not one of the default that stores
		 * in the include
		 * file; therefore, we need to read from the file.
		 */
		(void) snprintf(filePath, sizeof (filePath),
		    "%s/%s", codepagePath, oemcp->filename);
		fp = fopen(filePath, "r");

		if (fp == 0) {
			MEM_FREE("oem", oemcp->oempage.value);
			MEM_FREE("oem", oemcp->unicodepage.value);
#ifndef _KERNEL
			(void) mutex_unlock(&mutex);
#endif /* _KERNEL */
			return (-1);
		}

		while (fgets(buf, 32, fp) != 0) {
			char *endptr;
			unsigned int oemval, unival;

			endptr = (char *)strchr(buf, ' ');
			if (endptr == 0) {
				continue;
			}

			oemval = strtol(buf, &endptr, 0);
			unival = strtol(endptr+1, 0, 0);

			if (oemval >= max_oem_index || unival >= MAX_UNI_IDX) {
				continue;
			}

			oemcp->oempage.value[oemval] = unival;
			oemcp->unicodepage.value[unival] = oemval;
		}
		(void) fclose(fp);
	}
#endif /* _KERNEL */

	oemcp->valid = 1;
#ifndef _KERNEL
	(void) mutex_unlock(&mutex);
#endif /* _KERNEL */
	return (0);
}




/*
 * oem_codepage_free
 *
 * This function will clear the valid bit and free the memory
 * allocated to the oem/unipage by oem_codepage_init if the ref count
 * is zero.
 */
void
oem_codepage_free(unsigned int cpid)
{
	oem_codepage_t *oemcp;

	if (cpid >= MAX_OEMPAGES || !oemcp_table[cpid].valid)
		return;

	oemcp = &oemcp_table[cpid];
	oemcp->valid--;

	if (oemcp->ref != 0 || oemcp->valid != 0)
		return;

	if (oemcp->oempage.value != 0) {
		MEM_FREE("oem", oemcp->oempage.value);
		oemcp->oempage.value = 0;
	}

	if (oemcp->unicodepage.value != 0) {
		MEM_FREE("oem", oemcp->unicodepage.value);
		oemcp->unicodepage.value = 0;
	}
}



/*
 * oem_get_oempage
 *
 * This function will return the current oempage and increment
 * the ref count. The function oem_release_page should always
 * be called when finish using the oempage to decrement the
 * ref count.
 */
static oempage_t *
oem_get_oempage(unsigned int cpid)
{
	if (cpid >= MAX_OEMPAGES)
		return (0);

	if (oemcp_table[cpid].valid) {
		oemcp_table[cpid].ref++;
		return (&oemcp_table[cpid].oempage);
	}
	return (0);
}



/*
 * oem_get_unipage
 *
 * This function will return the current unipage and increment
 * the ref count. The function oem_release_page should always
 * be called when finish using the unipage to decrement the
 * ref count.
 */
static oempage_t *
oem_get_unipage(unsigned int cpid)
{
	if (cpid >= MAX_OEMPAGES)
		return (0);

	if (oemcp_table[cpid].valid) {
		oemcp_table[cpid].ref++;
		return (&oemcp_table[cpid].unicodepage);
	}
	return (0);
}



/*
 * oem_release_page
 *
 * This function will decrement the ref count and check the valid
 * bit. It will free the memory allocated for the pages
 * if the
 * valid bit is not set, ref count is zero and the page is not
 * already freed.
 */
static void
oem_release_page(oempage_t *page)
{
	oem_codepage_t *oemcp = &oemcp_table[page->cpid];

	page = 0;

	if (oemcp->ref > 0)
		oemcp->ref--;

	if (oemcp->ref != 0 || oemcp->valid)
		return;

	if (oemcp->oempage.value != 0) {
		MEM_FREE("oem", oemcp->oempage.value);
		oemcp->oempage.value = 0;
	}

	if (oemcp->unicodepage.value != 0) {
		MEM_FREE("oem", oemcp->unicodepage.value);
		oemcp->unicodepage.value = 0;
	}
}



/*
 * unicodestooems
 *
 * Convert unicode string to oem string. The function will stop
 * converting the unicode string when size nbytes - 1 is reached
 * or when there is not enough room to store another unicode.
 * If the function is called when the codepage is not initialized
 * or when the codepage initialize failed, it will return 0.
 * Otherwise, the total # of the converted unicode is returned.
 */
size_t
unicodestooems(
    char *oemstring,
    const mts_wchar_t *unicodestring,
    size_t nbytes,
    unsigned int cpid)
{
	oempage_t *unipage;
	unsigned int count = 0;
	mts_wchar_t oemchar;

	if (cpid >= MAX_OEMPAGES)
		return (0);

	if (unicodestring == 0 || oemstring == 0)
		return (0);

	if ((unipage = oem_get_unipage(cpid)) == 0)
		return (0);

	while ((oemchar = unipage->value[*unicodestring]) != 0) {
		if (oemchar & 0xff00 && nbytes >= MTS_MB_CHAR_MAX) {
			*oemstring++ = oemchar >> 8;
			*oemstring++ = (char)oemchar;
			nbytes -= 2;
		} else if (nbytes > 1) {
			*oemstring++ = (char)oemchar;
			nbytes--;
		} else
			break;

		count++;
		unicodestring++;
	}

	*oemstring = 0;

	oem_release_page(unipage);

	return (count);
}



/*
 * oemstounicodes
 *
 * Convert oem string to unicode string. The function will stop
 * converting the oem string when unicodestring len reaches nwchars - 1.
 * or when there is not enough room to store another oem char.
 * If the function is called when the codepage is not initialized
 * or when the codepage initialize failed, it will return 0.
 * Otherwise, the total # of the converted oem chars is returned.
 * The oem char can be either 1 or 2 bytes.
 */
size_t
oemstounicodes(
    mts_wchar_t *unicodestring,
    const char *oemstring,
    size_t nwchars,
    unsigned int cpid)
{
	oempage_t *oempage;
	size_t count = nwchars;
	mts_wchar_t oemchar;

	if (cpid >= MAX_OEMPAGES)
		return (0);

	if (unicodestring == 0 || oemstring == 0)
		return (0);

	if ((oempage = oem_get_oempage(cpid)) == 0)
		return (0);

	while ((oemchar = (mts_wchar_t)*oemstring++ & 0xff) != 0) {
		/*
		 * Cannot find one byte oemchar in table. Must be
		 * a lead byte. Try two bytes.
		 */

		if ((oempage->value[oemchar] == 0) && (oemchar != 0)) {
			oemchar = oemchar << 8 | (*oemstring++ & 0xff);
			if (oempage->value[oemchar] == 0) {
				*unicodestring = 0;
				break;
			}
		}
#ifdef _BIG_ENDIAN
		*unicodestring = LE_IN16(&oempage->value[oemchar]);
#else
		*unicodestring = oempage->value[oemchar];
#endif
		count--;
		unicodestring++;
	}

	*unicodestring = 0;

	oem_release_page(oempage);

	return (nwchars - count);
}

/*
 * oem_get_lang_table
 *
 * This function returns a pointer to the language table.
 */
language *
oem_get_lang_table(void)
{
	return (lang_table);
}

/*
 * oem_no_of_languages
 *
 * This function returns total languages support in the system.
 */
int
oem_no_of_languages(void)
{
	return (sizeof (lang_table)/sizeof (lang_table[0]));
}


#ifndef _KERNEL
#if 1
/*
 * TESTING Functions
 */
void
oemcp_print(unsigned int cpid)
{
	unsigned int bytesperchar, max_index, i;
	oempage_t *oempage, *unipage;
	unsigned int counter = 0;

	if (cpid >= MAX_OEMPAGES) {
		(void) printf("oemcp cpid %d is invalid\n", cpid);
		return;
	}

	if ((oempage = oem_get_oempage(cpid)) == 0) {
		(void) printf("oemcp of cpid %d is invalid\n", cpid);
		return;
	}

	if ((unipage = oem_get_unipage(cpid)) == 0) {
		(void) printf("unicp of cpid %d is invalid\n", cpid);
		return;
	}

	if ((bytesperchar = oem_codepage_bytesperchar(cpid)) == 0) {
		(void) printf("bytesperchar of cpid %d is not correct\n", cpid);
		return;
	}

	max_index = 1 << bytesperchar * 8;

	(void) printf("OEMPAGE:\n");
	for (i = 0; i < max_index; i++) {
		if ((counter + 1) % 4 == 0 &&
		    (oempage->value[i] != 0 || i == 0)) {
			(void) printf("%x %x\n", i, oempage->value[i]);
			counter++;
		} else if (oempage->value[i] != 0 || i == 0) {
			(void) printf("%x %x, ", i, oempage->value[i]);
			counter++;
		}
	}
	counter = 0;
	(void) printf("\n\nUNIPAGE:\n");
	for (i = 0; i < 65536; i++) {
		if ((counter + 1) % 8 == 0 &&
		    (unipage->value[i] != 0 || i == 0)) {
			(void) printf("%x %x\n", i, unipage->value[i]);
			counter++;
		} else if (unipage->value[i] != 0 || i == 0) {
			(void) printf("%x %x, ", i, unipage->value[i]);
			counter++;
		}
	}
	(void) printf("\n");
	oem_release_page(oempage);
	oem_release_page(unipage);
}



void
oemstringtest(unsigned int cpid)
{
	unsigned char *c, *cbuf;
	unsigned char cbuf1[100] = {0xfe, 0xfd, 0xf2, 0xe9,
		0x63, 0xce, 0xdb, 0x8c, 0x9c, 0x21, 0};
	unsigned char cbuf2[100] = {0xfe, 0xfc, 0x63, 0x81, 0x42,
		0x91, 0x40, 0x24, 0xff, 0x49};
	mts_wchar_t buf[100], *wc;

	if (cpid == 1)
		cbuf = cbuf1;
	else if (cpid == 2)
		cbuf = cbuf2;

	/*
	 * Before oem->uni conversion.
	 */
	(void) printf("Before oem->uni conversion: ");
	for (c = cbuf; *c != 0; c++)
		(void) printf("%x ", *c);
	(void) printf("\n");

	/*
	 * oem->uni conversion
	 */
	(void) oemstounicodes(buf, (const char *)cbuf, 100, cpid);

	/*
	 * After oem->uni conversion.
	 */
	(void) printf("After oem->uni conversion: ");
	for (wc = buf; *wc != 0; wc++)
		(void) printf("%x ", *wc);
	(void) printf("\n");

	/*
	 * uni->oem conversion
	 */
	(void) unicodestooems((char *)cbuf, buf, 100, cpid);

	/*
	 * After uni->oem conversion.
	 */
	(void) printf("After uni->oem conversion: ");
	for (c = cbuf; *c != 0; c++)
		(void) printf("%x ", *c);
	(void) printf("\n");
}
#endif
#endif /* _KERNEL */
