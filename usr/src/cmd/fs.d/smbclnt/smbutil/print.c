/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * from: Id: print.c,v 1.4 2001/01/28 07:35:01 bp Exp
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libintl.h>

#include <cflib.h>

#include <netsmb/smb_lib.h>

#include "common.h"

static char titlebuf[256];
static char databuf[4096];

static int print_file(smb_ctx_t *, char *, int);

void
print_usage(void)
{
	printf(gettext("usage: smbutil print [connection options] //"
	    "[workgroup;][user[:password]@]"
	    "server/share  {print_file|-}\n"));
	exit(1);
}

int
cmd_print(int argc, char *argv[])
{
	struct smb_ctx *ctx = NULL;
	char *filename;
	int error, opt;
	int file = -1;

	/* last arg is the print file. */
	if (argc < 3)
		print_usage();

	error = smb_ctx_alloc(&ctx);
	if (error)
		goto out;

	error = smb_ctx_scan_argv(ctx, argc-1, argv,
	    SMBL_SHARE, SMBL_SHARE, USE_SPOOLDEV);
	if (error)
		goto out;

	error = smb_ctx_readrc(ctx);
	if (error)
		goto out;

	while ((opt = getopt(argc-1, argv, STDPARAM_OPT)) != EOF) {
		if (opt == '?')
			print_usage();
		error = smb_ctx_opt(ctx, opt, optarg);
		if (error)
			goto out;
	}
	if (optind != argc-2)
		print_usage();
	filename = argv[argc-1];

	if (strcmp(filename, "-") == 0) {
		file = 0;	/* stdin */
		filename = "stdin";
	} else {
		file = open(filename, O_RDONLY, 0);
		if (file < 0) {
			smb_error("could not open file %s\n", errno, filename);
			exit(1);
		}
	}

	/*
	 * Resolve the server address,
	 * setup derived defaults.
	 */
	error = smb_ctx_resolve(ctx);
	if (error)
		goto out;

	/*
	 * Have server + share names, options etc.
	 * Get the session and tree.
	 */
again:
	error = smb_ctx_get_ssn(ctx);
	if (error == EAUTH) {
		int err2 = smb_get_authentication(ctx);
		if (err2 == 0)
			goto again;
	}
	if (error) {
		smb_error(gettext("//%s: login failed"),
		    error, ctx->ct_fullserver);
		goto out;
	}

	error = smb_ctx_get_tree(ctx);
	if (error) {
		smb_error(gettext("//%s/%s: tree connect failed"),
		    error, ctx->ct_fullserver, ctx->ct_origshare);
		goto out;
	}

	/*
	 * Have the printer share connection.
	 * Print the file.
	 */
	snprintf(titlebuf, sizeof (titlebuf), "%s_%s",
	    ctx->ct_user, filename);

	error = print_file(ctx, titlebuf, file);


out:
	/* don't close stdin (file=0) */
	if (file > 0)
		close(file);

	smb_ctx_free(ctx);

	return (error);
}

/*
 * Documentation for OPEN_PRINT_FILE is scarse.
 * It's in a 1996 MS doc. entitled:
 * SMB FILE SHARING PROTOCOL
 *
 * The extra parameters are:
 *   SetupLength: what part of the file is printer setup
 *   Mode: text or graphics (raw data)
 *   IdentifierString:  job title
 */
enum {
	MODE_TEXT = 0,	/* TAB expansion, etc. */
	MODE_GRAPHICS	/* raw data */
};

static int
print_file(smb_ctx_t *ctx, char *title, int file)
{
	off_t offset;
	int error, rcnt, wcnt;
	int setup_len = 0;		/* No printer setup data */
	int mode = MODE_GRAPHICS;	/* treat as raw data */
	int fh = -1;

	error = smb_printer_open(ctx, setup_len, mode, title, &fh);
	if (error) {
		smb_error("could not open print job", error);
		return (error);
	}

	offset = 0;
	for (;;) {
		rcnt = read(file, databuf, sizeof (databuf));
		if (rcnt < 0) {
			error = errno;
			smb_error("error reading input file\n", error);
			break;
		}
		if (rcnt == 0)
			break;

		wcnt = smb_fh_write(ctx, fh, offset, rcnt, databuf);
		if (wcnt < 0) {
			error = errno;
			smb_error("error writing spool file\n", error);
			break;
		}
		if (wcnt != rcnt) {
			smb_error("incomplete write to spool file\n", 0);
			error = EIO;
			break;
		}
		offset += wcnt;
	}

	(void) smb_printer_close(ctx, fh);
	return (error);
}
