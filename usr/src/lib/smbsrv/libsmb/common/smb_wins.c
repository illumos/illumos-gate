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
 * SMB WINS support functions
 */

#include <strings.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <smbsrv/smbinfo.h>

#include <smbsrv/libsmb.h>

/*
 * smb_wins_iplist
 *
 * Get a string containing a list of comma separated IP addresses
 * and return an array containing numeric equivalent for string IPs.
 *
 * Returns the number of parsed IPs.
 * Return -1 if list is badly formatted.
 * This routine need fix for IPv6
 */
int
smb_wins_iplist(char *list, uint32_t iplist[], int max_naddr)
{
	char *ip, *ctx;
	char *tmp;
	int n = 0;

	if ((list == NULL) || (*list == '\0'))
		return (0);

	if ((tmp = strdup(list)) == NULL)
		return (0);

	ip = strtok_r(tmp, ",", &ctx);
	while (ip && (n < max_naddr)) {
		ip = trim_whitespace(ip);
		if (*ip != 0) {
			if (inet_pton(AF_INET, ip, &iplist[n]) == 1) {
				n++;
			} else {
				return (-1);
			}
		}
		ip = strtok_r(0, ",", &ctx);
	}

	free(tmp);
	return (n);
}

/*
 * smb_wins_is_excluded
 *
 * Check to see if the given IP addr shouldn't be registered in WINS.
 *
 * Returns 1 if it's excluded, 0 if it's not.
 */
boolean_t
smb_wins_is_excluded(in_addr_t ipaddr, ipaddr_t *exclude_list, int nexclude)
{
	int i;

	if (nexclude == 0)
		return (B_FALSE);

	for (i = 0; i < nexclude; i++)
		if (ipaddr == exclude_list[i]) {
			return (B_TRUE);
		}

	return (B_FALSE);
}

/*
 * Build a CSV list of ips to be excluded.
 * This function needs fix for IPv6
 */
void
smb_wins_build_list(char *buf, uint32_t iplist[], int max_naddr)
{
	char ipstr[16];
	int i;

	if (!buf)
		return;

	buf[0] = '\0';
	for (i = 0; i < max_naddr; i++) {
		/* XXX these will be removed */
		/*LINTED*/
		if (iplist[i] == -1)
			continue;

		if (inet_ntop(AF_INET, (const void *)(&iplist[i]), ipstr,
		    sizeof (ipstr)) == 0)
			continue;
		(void) strcat(buf, ipstr);
		(void) strcat(buf, ",");
	}
	buf[strlen(buf)-1] = '\0';
}

/*
 * This function build the new WINS exclude list from
 * configured list + new additions to exclude list
 * It also assumes that the buffers are of enough space.
 */
int
smb_wins_exclude_list(char *config_list, char *exclude_list)
{
	int ccnt, ecnt, already_there;
	int i, j;
	uint32_t ncur_list[SMB_PI_MAX_NETWORKS];
	uint32_t ecur_list[SMB_PI_MAX_NETWORKS];

	ccnt = smb_wins_iplist(config_list, ncur_list, SMB_PI_MAX_NETWORKS);
	if (ccnt < 0)
		return (-1);

	ecnt = smb_wins_iplist(exclude_list, ecur_list, SMB_PI_MAX_NETWORKS);
	if (ecnt < 0)
		return (-1);

	if ((ccnt + ecnt) > SMB_PI_MAX_NETWORKS)
		return (-1);

	for (i = 0; i < ecnt; i++) {
		already_there = 0;
		for (j = 0; j < ccnt; j++) {
			if (ncur_list[j] == ecur_list[i]) {
				already_there = 1;
			}
		}
		if (already_there)
			continue;

		ncur_list[ccnt++] = ecur_list[i];
	}

	smb_wins_build_list(config_list, ncur_list, ccnt);
	return (0);
}

/*
 * This function build the new WINS allow list from
 * configured list - new allowed list
 * It also assumes that the buffers are of enough space.
 */
int
smb_wins_allow_list(char *config_list, char *allow_list)
{
	int ccnt, acnt;
	int i, j;
	uint32_t ncur_list[SMB_PI_MAX_NETWORKS];
	uint32_t acur_list[SMB_PI_MAX_NETWORKS];

	ccnt = smb_wins_iplist(config_list, ncur_list, SMB_PI_MAX_NETWORKS);
	if (ccnt < 0)
		return (-1);

	acnt = smb_wins_iplist(allow_list, acur_list, SMB_PI_MAX_NETWORKS);
	if (acnt < 0)
		return (0);

	for (i = 0; i < acnt; i++) {
		for (j = 0; j < ccnt; j++) {
			if (ncur_list[j] == (in_addr_t)(-1))
				continue;
			if (ncur_list[j] == acur_list[i]) {
				ncur_list[j] = (in_addr_t)(-1);
			}
		}
	}
	smb_wins_build_list(config_list, ncur_list, ccnt);
	return (0);
}
