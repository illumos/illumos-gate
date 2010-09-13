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

#ifndef _SYS_SOCKFS_NL7C_H
#define	_SYS_SOCKFS_NL7C_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>


/*
 * NCA_DEV	NCA device
 *
 * NCA_INET_DEV	TPI device for the INET based transport that NCA will use.
 */
#define	NCA_DEV		"/dev/nca"
#define	NCA_INET_DEV	"/dev/tcp"

/*
 * NL7C (uint64_t)(sotpi_info_t).sti_nl7c_flags:
 */

#define	NL7C_ENABLED	0x00000001 /* NL7C enabled socket */
#define	NL7C_SOPERSIST	0x00000002 /* NL7C socket is persistent */
#define	NL7C_WAITWRITE	0x00000004 /* NL7C waiting first write */
#define	NL7C_AF_NCA	0x00000008 /* NL7C enabled socket via AF_NCA */
#define	NL7C_POLLIN	0x00000010 /* poll() POLLIN prior to read */
#define	NL7C_CLOSE	0x00000020 /* NL7C close needed */

#define	NL7C_SCHEMEPRIV	0xFFFF0000 /* NL7C scheme private state */

#define	NL7C_UNUSED	0xFFFFFFFF00000000 /* Unused bits */

/*
 * Globals ...
 */

extern boolean_t	nl7c_enabled;
extern clock_t		nl7c_uri_ttl;

/*
 * Function prototypes ...
 */

boolean_t	nl7c_process(struct sonode *, boolean_t);
int		nl7c_data(struct sonode *, uio_t *);
void		nl7c_urifree(struct sonode *);
void		nl7c_close(struct sonode *);
boolean_t	nl7c_parse(struct sonode *, boolean_t, boolean_t *);

extern		void *nl7c_lookup_addr(void *, t_uscalar_t);
extern		void *nl7c_add_addr(void *, t_uscalar_t);
extern		void nl7c_listener_addr(void *, struct sonode *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SOCKFS_NL7C_H */
