/*
 * COPYRIGHT 2013 Pluribus Networks Inc.
 *
 * All rights reserved. This copyright notice is Copyright Management
 * Information under 17 USC 1202 and is included to protect this work and
 * deter copyright infringement.  Removal or alteration of this Copyright
 * Management Information without the express written permission from
 * Pluribus Networks Inc is prohibited, and any such unauthorized removal
 * or alteration will be a violation of federal law.
 */
#ifndef	_BHYVE_H
#define	_BHYVE_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	BHYVE_TMPDIR			"/var/run/bhyve"
#define	BHYVE_CONS_SOCKPATH		BHYVE_TMPDIR "/%s.console_sock"

#ifdef	__cplusplus
}
#endif

#endif	/* _BHYVE_H */
