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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_HELPER_H
#define	_HELPER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAX_ISCSI_NAME_LEN	223
#define	MAX_ADDRESS_LEN		255
#define	MIN_CHAP_SECRET_LEN	12
#define	MAX_CHAP_SECRET_LEN	16
#define	DEFAULT_ISCSI_PORT	3260
#define	DEFAULT_RADIUS_PORT	1812
#define	MAX_CHAP_NAME_LEN   	512

/* forward declarations */
#define	PARSE_ADDR_OK				0
#define	PARSE_ADDR_MISSING_CLOSING_BRACKET	1
#define	PARSE_ADDR_PORT_OUT_OF_RANGE		2
#define	PARSE_TARGET_OK				0
#define	PARSE_TARGET_INVALID_TPGT		1
#define	PARSE_TARGET_INVALID_ADDR		2

typedef enum iSCSINameCheckStatus {
	iSCSINameCheckOK,
	iSCSINameLenZero,
	iSCSINameLenExceededMax,
	iSCSINameUnknownType,
	iSCSINameIqnFormatError,
	iSCSINameEUIFormatError
} iSCSINameCheckStatusType;

typedef struct stat_delta {
	struct stat_delta	*next;
	char			*device;
	size_t			read_cmds,
				write_cmds,
				read_blks,
				write_blks;
} stat_delta_t;

/* helper functions */
int getSecret(char *, int *, int, int);
tgt_node_t *send_data(char *hostname, char *first_str);
int parseAddress(char *address_port_str, uint16_t defaultPort,
    char *address_str, size_t address_str_len,
    uint16_t *port, boolean_t *isIpv6);
char *number_to_scaled_string(
	char *buf,
	unsigned long long number,
	int unit_from,
	int scale);
void stats_load_counts(tgt_node_t *n, stat_delta_t *d);
stat_delta_t *stats_prev_counts(stat_delta_t *cp);
void stats_update_counts(stat_delta_t *p, stat_delta_t *c);
void stats_free();
char *dospace(int n);

#ifdef	__cplusplus
}
#endif

#endif /* _HELPER_H */
