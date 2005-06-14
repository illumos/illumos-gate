/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1993, 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%W%	%E% SMI"

#include <sys/types.h>
#include <sys/errno.h>
#include <setjmp.h>
#include <limits.h>
#include <netinet/in.h>
#include <string.h>

#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include <fw.h>
#include <fw_rpc.h>
#include "snoop.h"

extern char *dlc_header;
extern jmp_buf xdr_err;

static char *procnames_short[] = {
	"Null",		/*  0 */
	"INVOKE",	/*  1 */
	"MORE",		/*  2 */
	"KILL",		/*  3 */
};

static char *procnames_long[] = {
	"Null procedure",	/*  0 */
	"Invoke operation",	/*  1 */
	"More data",		/*  2 */
	"Kill operation",	/*  3 */
};

#define	MAXPROC	3

enum Rec_type {
	REC_TYPE_NORM = 0,
	REC_TYPE_EOR = 1,
	REC_TYPE_EOF = 2
};
typedef enum Rec_type Rec_type;

void
interpret_solarnet_fw(
	int flags,
	int type,
	int xid,
	int vers,
	int proc,
	char *data,
	int len)
{
	char *line;
	char buff[CTXTLEN + 1];
	ulong_t thresh;
	char op[CTXTLEN + 1];
	bool_t b;
	Fw_err e;
	Rec_type rt;
	int new_row = 1, row = 0;

	if (proc < 0 || proc > MAXPROC)
		return;

	if (flags & F_SUM) {
		if (setjmp(xdr_err)) {
			return;
		}

		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line,
				"SOLARNET C %s",
				procnames_short[proc]);
			line += strlen(line);

			switch (proc) {
			case FW_INVOKE:
				(void) sprintf(line, " %s",
				    getxdr_string(buff, CTXTLEN));
				line += strlen(line);
				(void) sprintf(line, "/%s",
				    getxdr_string(buff, CTXTLEN));
				line += strlen(line);
				getxdr_string(buff, CTXTLEN);
				if (strlen(buff) != 0) {
					(void) sprintf(line, ".%s", buff);
					line += strlen(line);
				}
				(void) getxdr_string(buff, CTXTLEN);
				thresh = getxdr_u_long();
				if (thresh == ULONG_MAX)
					(void) sprintf(line, " (all)");
				else
					(void) sprintf(line, " %lu", thresh);
				line += strlen(line);
				(void) getxdr_context(buff, CTXTLEN);
				break;
			case FW_MORE:
				(void) getxdr_context(buff, CTXTLEN);
				sscanf(buff, "%*s %*s %s.%*s", op);
				op[strlen(op)-1] = '\0';
				(void) sprintf(line, " %s", op);
				line += strlen(line);
				thresh = getxdr_u_long();
				if (thresh == ULONG_MAX)
					(void) sprintf(line, " (all)");
				else
					(void) sprintf(line, " %lu", thresh);
				line += strlen(line);
				break;
			case FW_KILL:
				(void) getxdr_context(buff, CTXTLEN);
				sscanf(buff, "%*s %*s %s.%*s", op);
				op[strlen(op)-1] = '\0';
				(void) sprintf(line, " %s", op);
				line += strlen(line);
				break;
			default:
				break;
			}

			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "SOLARNET R %s",
			    procnames_short[proc]);
			line += strlen(line);
			b = getxdr_bool();
			if (b) {
				e = getxdr_enum();
				if (e == FW_ERR_FW)
					sprintf(line, " FW");
				else if (e == FW_ERR_OP)
					sprintf(line, " OP");
				else
					sprintf(line, " NOERR");
				line += strlen(line);
				if (e != FW_ERR_NONE) {
					sprintf(line, " %lu", getxdr_u_long());
					line += strlen(line);
					(void) getxdr_bool();
					sprintf(line, " %s",
					    getxdr_string(buff, CTXTLEN));
					line += strlen(line);
				}
			} else {
				sprintf(line, " Success");
				line += strlen(line);
			}
			b = getxdr_bool();
			if (b) {
				sprintf(line, " %lu rows", getxdr_u_long());
				line += strlen(line);
			} else {
				sprintf(line, " (No output)");
				line += strlen(line);
			}
		}
	}

	if ((flags & F_DTAIL)) {
		show_header("SOLARNET:  ", "Solarnet Administration Service",
		    len);
		show_space();
		if (setjmp(xdr_err)) {
			return;
		}
		(void) sprintf(get_line(0, 0), "Proc = %d (%s)", proc,
		    procnames_long[proc]);
		if (type == CALL) {
			switch (proc) {
			case FW_INVOKE:
				(void) showxdr_string(CTXTLEN, "Category: %s");
				(void) showxdr_string(CTXTLEN, "Operation: %s");
				(void) showxdr_string(CTXTLEN, "Version: %s");
				(void) showxdr_string(CTXTLEN, "Locale: %s");
				(void) showxdr_u_long("Threshold: %lu rows");
				(void) showxdr_context("Context: %s");
				b = getxdr_bool();
				if (!b) {
					sprintf(get_line(0, 0),
					    "No input arguments");
					break;
				}
				thresh = showxdr_u_long("Input rows = %lu");
				(void) getxdr_bool();
				do {
					rt = getxdr_enum();
					if (rt == REC_TYPE_NORM) {
						if (new_row) {
							sprintf(get_line(0, 0),
							    "Row %d", ++row);
							new_row = 0;
						}
						(void) getxdr_string(buff,
						    CTXTLEN);
						(void) getxdr_string(op,
						    CTXTLEN);
						sprintf(get_line(0, 0),
						    "\t%s = %s", buff, op);
					} else if (rt == REC_TYPE_EOR) {
						new_row = 1;
					}
				} while (rt != REC_TYPE_EOF);
				break;
			case FW_MORE:
				(void) showxdr_context("Context: %s");
				(void) showxdr_u_long("Threshold: %lu rows");
				break;
			case FW_KILL:
				(void) showxdr_context("Context: %s");
				break;
			default:
				break;
			}
		} else {
			b = getxdr_bool();
			if (b) {
				e = getxdr_enum();
				if (e == FW_ERR_FW) {
					showxdr_u_long(
					    "Framework error code %lu");
				} else if (e == FW_ERR_OP) {
					showxdr_u_long(
					    "Operation error code %lu");
				} else {
					showxdr_u_long("No error %*lu");
				}
				(void) getxdr_bool();
				(void) getxdr_string(buff, CTXTLEN);
				if (e != FW_ERR_NONE) {
					sprintf(get_line(0, 0),
					    "Error message: %s", buff);
				} else {
				}
			} else {
				sprintf(get_line(0, 0),
				    "Operation was successful");
			}
			b = getxdr_bool();
			if (b) {
				showxdr_u_long("Output rows: %lu");
				(void) getxdr_bool();
				do {
					rt = getxdr_enum();
					if (rt == REC_TYPE_NORM) {
						if (new_row) {
							sprintf(get_line(0, 0),
							    "Row %d", ++row);
							new_row = 0;
						}
						(void) getxdr_string(buff,
						    CTXTLEN);
						(void) getxdr_string(op,
						    CTXTLEN);
						sprintf(get_line(0, 0),
						    "\t%s = %s", buff, op);
					} else if (rt == REC_TYPE_EOR) {
						new_row = 1;
					}
				} while (rt != REC_TYPE_EOF);
			} else {
				sprintf(get_line(0, 0), "No output");
			}
		}
		show_trailer();
	}

}
