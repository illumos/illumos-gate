/*
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_SUNW_DST_INIT_H
#define	_SUNW_DST_INIT_H

extern int	sunw_dst_bsafe_init(void);
extern int	sunw_dst_rsaref_init(void);
extern int	sunw_dst_hmac_md5_init(void);
extern int	sunw_dst_eay_dss_init(void);
extern int	sunw_dst_cylink_init(void);

#ifndef	__SUNW_DST_INIT_NODEFINE

#define	dst_bsafe_init		sunw_dst_bsafe_init
#define	dst_rsaref_init		sunw_dst_rsaref_init
#define	dst_hmac_md5_init	sunw_dst_hmac_md5_init
#define	dst_eay_dss_init	sunw_dst_eay_dss_init
#define	dst_cylink_init		sunw_dst_cylink_init

#endif /* __SUNW_DST_INIT_NODEFINE */

#endif	/* _SUNW_DST_INIT_H */
