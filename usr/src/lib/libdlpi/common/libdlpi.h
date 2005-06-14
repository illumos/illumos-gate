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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _LIBDLPI_H
#define	_LIBDLPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/dlpi.h>
#include <net/if.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MAXADDRLEN	64
#define	MAXSAPLEN	64
#define	MAX_MODS	9

typedef struct dlpi_if_attr {
	char	ifname[LIFNAMSIZ];
	int	style;
	int	ppa;
	int	mod_cnt;
	int	mod_pushed;
	boolean_t	style1_failed;
	int	style1_fd;
	char	devname[LIFNAMSIZ + 32]; /* added space for /dev path */
	char	modlist[MAX_MODS][LIFNAMSIZ];
	char	provider[LIFNAMSIZ];
} dlpi_if_attr_t;

extern const char	*dlpi_mac_type(uint_t);

extern int	dlpi_open(const char *);
extern int	dlpi_close(int);
extern int	dlpi_info(int, int, dl_info_ack_t *, union DL_qos_types *,
    union DL_qos_types *, uint8_t *, size_t *, uint8_t *, size_t *);
extern int	dlpi_attach(int, int, uint_t);
extern int	dlpi_detach(int, int);
extern int	dlpi_bind(int, int, uint_t, uint16_t, boolean_t, uint32_t *,
    uint32_t *, uint8_t *, size_t *);
extern int	dlpi_unbind(int, int);
extern int	dlpi_enabmulti(int, int, uint8_t *, size_t);
extern int	dlpi_disabmulti(int, int, uint8_t *, size_t);
extern int	dlpi_promiscon(int, int, uint_t);
extern int	dlpi_promiscoff(int, int, uint_t);
extern int	dlpi_phys_addr(int, int, uint_t, uint8_t *, size_t *);
extern int	dlpi_set_phys_addr(int, int, uint8_t *, size_t);
extern void	dlpi_passive(int, int);

/*
 * dlpi_if_open()
 *   Takes interface name in the following formats
 *   o Specific physical unit (ex. "bge0" or "ce0")
 *   o Tunnels (ex. "ip.tun0" or "ip6.tun0")
 */
extern int	dlpi_if_open(const char *, dlpi_if_attr_t *, boolean_t);
extern int	dlpi_if_parse(const char *, char *, int *);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBDLPI_H */
