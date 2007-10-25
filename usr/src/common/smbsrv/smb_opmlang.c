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

#include <smbsrv/string.h>
#include <smbsrv/codepage.h>
#include <smbsrv/oem.h>

static unsigned int smb_cpid = NO_OF_OEM_CP_INDS;
static unsigned int telnet_cpid = NO_OF_OEM_CP_INDS;

/*
 * oem_get_smb_cpid
 *
 * This function returns the cpid for current smb codepage.
 */
unsigned int
oem_get_smb_cpid(void)
{
	return (smb_cpid);
}

/*
 * oem_get_telnet_cpid
 *
 * This function returns the cpid for current telnet codepage.
 */
unsigned int
oem_get_telnet_cpid(void)
{
	return (telnet_cpid);
}

/*
 * oem_current_language
 *
 * This function will return the current language setting.
 * The current language is stored in env "codepage.oem.language".
 * If the env does not exist, "None Selected" will be returned.
 */
char *
oem_current_language()
{
#ifdef PBSHORTCUT
	char *p = getenv("codepage.oem.language");

	if (p)
		return (p);
#endif
	return ("None Selected");
}


/*
 * oem_language_set
 *
 * This function will set the oem language and correct
 * env variables.
 */
int
oem_language_set(char *lang_name)
{
	int i;
	language *lang_table = oem_get_lang_table();

	for (i = 0; i < NO_OF_LANGUAGES; i++) {
		if (utf8_strcasecmp(lang_name, lang_table[i].language) == 0) {
			unsigned int oldSmbIndex = smb_cpid;
			unsigned int oldTelnetIndex = telnet_cpid;
			if (oem_codepage_init(lang_table[i].smbIndex) < 0 ||
			    oem_codepage_init(lang_table[i].telnetIndex) < 0) {
				oem_codepage_free(lang_table[i].smbIndex);
				oem_codepage_free(lang_table[i].telnetIndex);
				(void) oem_codepage_init(oem_default_smb_cpid);
				(void) oem_codepage_init(
				    oem_default_telnet_cpid);
				smb_cpid = oem_default_smb_cpid;
				telnet_cpid = oem_default_telnet_cpid;
#ifdef PBSHORTCUT
				setenv("codepage.oem.language",
				    oem_default_language);
#endif
			} else {
				smb_cpid = lang_table[i].smbIndex;
				telnet_cpid = lang_table[i].telnetIndex;
#ifdef PBSHORTCUT
				setenv("codepage.oem.language",
				    lang_table[i].language);
#endif
			}
#ifdef PBSHORTCUT
			saveenv();
#endif

			if (oldSmbIndex < NO_OF_OEM_CP_INDS)
				oem_codepage_free(oldSmbIndex);
			if (oldTelnetIndex < NO_OF_OEM_CP_INDS)
				oem_codepage_free(oldTelnetIndex);
			return (0);
		}
	}

	return (-1);
}
