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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * Test connecting to an NFSv4 server with Kerberos auth.
 */

#include <stdlib.h>
#include <strings.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <unistd.h>
#include <gssapi/gssapi_ext.h>

#include "rpcsvc/nfs4_prot.h"

int nfs4_skip_bytes;

int
main(int argc, char *argv[])
{
	CLIENT *client;
	AUTH *auth;
	COMPOUND4args args;
	COMPOUND4res res;
	enum clnt_stat status;
	struct timeval timeout;
	nfs_argop4 arg[1] = {0};
	char *tag = "RPCSEC_GSS test";
	char *host;
	char *ip = NULL;
	char *slp = NULL;
	char svc_name[256];
	ulong_t sleep_time = 0;
	rpc_gss_options_ret_t opt_ret = {0};

	if (argc < 2) {
		fprintf(stderr,
		    "usage: %s [-I IP] hostname <seconds to sleep>\n", argv[0]);
		return (-1);
	}

	if (strcmp(argv[1], "-I") == 0) {
		if (argc < 4) {
			fprintf(stderr, "-I needs an arg\n");
			return (-3);
		}
		ip = argv[2];
		host = argv[3];
		if (argc > 4)
			slp = argv[4];
	} else {
		host = ip = argv[1];
		if (argc > 2)
			slp = argv[2];
	}

	if (slp != NULL) {
		errno = 0;
		sleep_time = strtoul(argv[2], NULL, 0);
		if (errno != 0) {
			perror("failed to convert seconds string");
			return (-2);
		}
	}

	timeout.tv_sec = 30;
	timeout.tv_usec = 0;

	client = clnt_create(ip, NFS4_PROGRAM, NFS_V4, "tcp");
	if (client == NULL) {
		clnt_pcreateerror("test");
		fprintf(stderr, "clnt_create failed\n");
		return (1);
	}

	(void) snprintf(svc_name, sizeof (svc_name), "nfs@%s", host);
	if ((auth = rpc_gss_seccreate(client, svc_name, "kerberos_v5",
	    rpc_gss_svc_none, "default", NULL, &opt_ret)) == NULL) {
		uint32_t disp_major, disp_minor, msg_ctx = 0;
		gss_buffer_desc errstr = {0};
		rpc_gss_error_t rpcerr = {0};

		fprintf(stderr, "creating GSS ctx failed\n");

		rpc_gss_get_error(&rpcerr);
		if (rpcerr.rpc_gss_error != 0) {
			fprintf(stderr, "failed with errno %d\n",
			    rpcerr.system_error);
		}

		if (!GSS_ERROR(opt_ret.major_status)) {
			fprintf(stderr, "no GSS error info\n");
			return (2);
		}

		do {
			disp_major = gss_display_status(&disp_minor,
			    opt_ret.major_status, GSS_C_GSS_CODE,
			    GSS_C_NULL_OID, &msg_ctx, &errstr);
			if (!GSS_ERROR(disp_major) && errstr.length != 0) {
				fprintf(stderr, "major: %s\n", errstr.value);
				(void) gss_release_buffer(&disp_minor, &errstr);
			} else {
				fprintf(stderr,
				    "gss_display_status() failed with "
				    "0x%x:0x%x", disp_major, disp_minor);
			}
		} while (!GSS_ERROR(disp_major) && msg_ctx != 0);

		if (opt_ret.minor_status == 0)
			return (2);

		do {
			disp_major = gss_display_status(&disp_minor,
			    opt_ret.minor_status, GSS_C_MECH_CODE,
			    GSS_C_NULL_OID, &msg_ctx, &errstr);
			if (!GSS_ERROR(disp_major) && errstr.length != 0) {
				fprintf(stderr, "minor: %s\n", errstr.value);
				(void) gss_release_buffer(&disp_minor, &errstr);
			} else {
				fprintf(stderr,
				    "gss_display_status() failed with "
				    "0x%x:0x%x", disp_major, disp_minor);
			}
		} while (!GSS_ERROR(disp_major) && msg_ctx != 0);

		return (2);
	}

	client->cl_auth = auth;

	args.minorversion = 0;
	args.tag.utf8string_len = strlen(tag);
	args.tag.utf8string_val = tag;
	args.argarray.argarray_len = sizeof (arg) / sizeof (nfs_argop4);
	args.argarray.argarray_val = arg;

	arg[0].argop = OP_SETCLIENTID;
	/* leaving arg[0].nfs_argop4_u.opsetclientid as-is */

	bzero(&res, sizeof (res));

	status = clnt_call(client, NFSPROC4_COMPOUND,
	    xdr_COMPOUND4args, (caddr_t)&args,
	    xdr_COMPOUND4res, (caddr_t)&res,
	    timeout);
	if (status != RPC_SUCCESS) {
		clnt_perror(client, "test");
		fprintf(stderr, "clnt_call failed\n");
		return (2);
	}

	if (sleep_time != 0)
		(void) sleep(sleep_time);

	fprintf(stderr, "success!\n");
	return (0);
}
