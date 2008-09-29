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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBPICLSNMP_H
#define	_LIBPICLSNMP_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Opaque picl snmp handle
 */
typedef void	*picl_snmphdl_t;

/*
 * Exported interfaces
 */
extern picl_snmphdl_t snmp_init(void);
extern void snmp_fini(picl_snmphdl_t);

extern int snmp_reinit(picl_snmphdl_t hdl, int clr_linkreset);
extern void snmp_register_group(picl_snmphdl_t, char *, int, int);

extern int snmp_get_int(picl_snmphdl_t, char *, int, int *, int *);
extern int snmp_get_str(picl_snmphdl_t, char *, int, char **, int *);
extern int snmp_get_bitstr(picl_snmphdl_t, char *, int, uchar_t **,
	    uint_t *, int *);
extern int snmp_get_nextrow(picl_snmphdl_t, char *, int, int *, int *);

extern int snmp_refresh_init(void);
extern void snmp_refresh_fini(void);
extern int snmp_refresh_get_next_expiration(void);
extern int snmp_refresh_get_cycle_hint(int);
extern int snmp_refresh_process_job(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBPICLSNMP_H */
