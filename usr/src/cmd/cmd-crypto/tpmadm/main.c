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
 * Copyright 2018 OmniOS Community Edition (OmniOSce) Association.
 */


#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <libintl.h>
#include <locale.h>

#include <tss/tspi.h>
#include <trousers/trousers.h>
#include "tpmadm.h"

extern cmdtable_t commands[];

static void
print_usage(char *progname, cmdtable_t cmds[])
{
	cmdtable_t *p;

	(void) fprintf(stderr,
	    gettext("usage: %s command args ...\n"), progname);
	(void) fprintf(stderr,
	    gettext("where 'command' is one of the following:\n"));
	for (p = &cmds[0]; p->name != NULL; p++) {
		(void) fprintf(stderr, "\t%s %s\n", p->name, p->args);
	}
}

int
main(int argc, char *argv[])
{
	char *progname;
	cmdtable_t *p;
	cmdfunc_t fptr = NULL;
	int ret;
	TSS_HCONTEXT hContext;
	TSS_HOBJECT hTPM;

	/* Set up for i18n/l10n. */
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D. */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it isn't. */
#endif
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	progname = argv[0];
	argc--;
	argv++;

	if (argc <= 0) {
		print_usage(progname, commands);
		return (ERR_USAGE);
	}

	for (p = &commands[0]; p->name != NULL; p++) {
		if (0 == strcmp(p->name, argv[0])) {
			fptr = p->func;
			break;
		}
	}
	if (fptr == NULL) {
		print_usage(progname, commands);
		return (ERR_USAGE);
	}

	if (tpm_preamble(&hContext, &hTPM))
		return (ERR_FAIL);
	ret = fptr(hContext, hTPM, argc, argv);
	(void) tpm_postamble(hContext);

	return (ret);
}


/*
 * Utility functions
 */

void
print_bytes(BYTE *bytes, size_t len, int formatted)
{
	int i;
	for (i = 0; i < len; i++) {
		(void) printf("%02X ", bytes[i]);
		if (formatted && i % 16 == 7)
			(void) printf("  ");
		if (formatted && i % 16 == 15)
			(void) printf("\n");
	}
	(void) printf("\n");
}


/*
 * TSS convenience functions
 */

void
print_error(TSS_RESULT ret, char *msg)
{
	char *err_string;

	/* Print the standard error string and error code. */
	err_string = Trspi_Error_String(ret);
	(void) fprintf(stderr, "%s: %s (0x%0x)\n", msg, err_string, ret);

	/* For a few special cases, add a more verbose error message. */
	switch (ret) {
	case TPM_E_DEACTIVATED:
	case TPM_E_DISABLED:
		(void) fprintf(stderr,
		    gettext("Enable the TPM and reboot.\n"));
		break;
	case TSP_ERROR(TSS_E_COMM_FAILURE):
		(void) fprintf(stderr,
		    gettext("Make sure the tcsd service "
		    "(svc:/application/security/tcsd) is running.\n"));
		break;
	}
}

int
get_tpm_capability(TSS_HCONTEXT hContext, TSS_HOBJECT hTPM, UINT32 cap,
    UINT32 subcap, void *buf, size_t bufsize)
{
	TSS_RESULT ret;
	UINT32 datalen;
	BYTE *data;

	ret = Tspi_TPM_GetCapability(hTPM, cap, sizeof (subcap),
	    (BYTE *)&subcap, &datalen, &data);
	if (ret) {
		print_error(ret, gettext("Get TPM capability"));
		return (ERR_FAIL);
	}

	if (datalen > bufsize) {
		(void) fprintf(stderr,
		    gettext("Capability 0x%x returned %u bytes "
		    "(expected %u)\n"), cap, datalen, bufsize);
		return (ERR_FAIL);
	}
	bcopy(data, buf, datalen);

	ret = Tspi_Context_FreeMemory(hContext, data);
	if (ret) {
		print_error(ret, gettext("Free capability buffer"));
		return (ERR_FAIL);
	}

	return (0);
}

int
set_policy_options(TSS_HPOLICY hPolicy, TSS_FLAG mode, char *prompt,
    UINT32 secret_len, BYTE *secret)
{
	TSS_RESULT ret;
	BYTE *unicode_prompt;
	UINT32 len;

	ret = Tspi_Policy_SetSecret(hPolicy, mode, secret_len, secret);
	if (ret) {
		print_error(ret, gettext("Set policy secret"));
		return (ERR_FAIL);
	}
	if (prompt != NULL) {
		unicode_prompt = Trspi_Native_To_UNICODE((BYTE *)prompt, &len);
		ret = Tspi_SetAttribData(hPolicy,
		    TSS_TSPATTRIB_POLICY_POPUPSTRING,
		    NULL, len, unicode_prompt);
		if (ret) {
			print_error(ret, gettext("Set policy prompt"));
			return (ERR_FAIL);
		}
	}

	return (0);
}

int
set_object_policy(TSS_HOBJECT handle, TSS_FLAG mode, char *prompt,
    UINT32 secret_len, BYTE *secret)
{
	TSS_HPOLICY hPolicy;
	TSS_RESULT ret;

	ret = Tspi_GetPolicyObject(handle, TSS_POLICY_USAGE, &hPolicy);
	if (ret) {
		print_error(ret, gettext("Get object policy"));
		return (ERR_FAIL);
	}

	return (set_policy_options(hPolicy, mode, prompt, secret_len, secret));
}

int
tpm_preamble(TSS_HCONTEXT *hContext, TSS_HOBJECT *hTPM)
{
	TSS_RESULT ret;

	ret = Tspi_Context_Create(hContext);
	if (ret) {
		print_error(ret, gettext("Create context"));
		return (ERR_FAIL);
	}

	ret = Tspi_Context_Connect(*hContext, NULL);
	if (ret) {
		print_error(ret, gettext("Connect context"));
		(void) Tspi_Context_Close(*hContext);
		return (ERR_FAIL);
	}

	ret = Tspi_Context_GetTpmObject(*hContext, hTPM);
	if (ret) {
		print_error(ret, gettext("Get TPM object"));
		(void) Tspi_Context_Close(*hContext);
		return (ERR_FAIL);
	}
	return (0);
}

int
tpm_postamble(TSS_HCONTEXT hContext)
{
	TSS_RESULT ret;

	ret = Tspi_Context_Close(hContext);
	if (ret) {
		print_error(ret, gettext("Close context"));
		return (ERR_FAIL);
	}
	return (0);
}
