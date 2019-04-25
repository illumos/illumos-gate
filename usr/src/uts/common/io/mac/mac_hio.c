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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * MAC Hybrid I/O related code.
 */

#include <sys/types.h>
#include <sys/sdt.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_soft_ring.h>


/*
 * Return the number of shares supported by the specified MAC.
 */
int
mac_share_capable(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_share_capab.ms_snum);
}


/*
 * Allocate a share to the specified MAC client. Invoked when
 * mac_client_open() is invoked with MAC_OPEN_FLAGS_SHARES_DESIRED set.
 */
void
i_mac_share_alloc(mac_client_impl_t *mcip)
{
	mac_impl_t *mip = mcip->mci_mip;
	int rv;

	i_mac_perim_enter(mip);

	ASSERT(mcip->mci_share == NULL);

	if (mac_share_capable((mac_handle_t)mcip->mci_mip) == 0) {
		DTRACE_PROBE1(i__mac__share__alloc__not__sup,
		    mac_client_impl_t *, mcip);
		i_mac_perim_exit(mip);
		return;
	}

	rv = mip->mi_share_capab.ms_salloc(mip->mi_share_capab.ms_handle,
	    &mcip->mci_share);
	DTRACE_PROBE3(i__mac__share__alloc, mac_client_impl_t *, mcip,
	    int, rv, mac_share_handle_t, mcip->mci_share);

	mcip->mci_state_flags &= ~MCIS_SHARE_BOUND;

	i_mac_perim_exit(mip);
}


/*
 * Free a share previously allocated through i_mac_share_alloc().
 * Safely handles the case when no shares were allocated to the MAC client.
 */
void
i_mac_share_free(mac_client_impl_t *mcip)
{
	mac_impl_t *mip = mcip->mci_mip;

	i_mac_perim_enter(mip);

	/* MAC clients are required to unbind they shares before freeing them */
	ASSERT((mcip->mci_state_flags & MCIS_SHARE_BOUND) == 0);

	if (mcip->mci_share == 0) {
		i_mac_perim_exit(mip);
		return;
	}

	mip->mi_share_capab.ms_sfree(mcip->mci_share);
	i_mac_perim_exit(mip);
}


/*
 * Bind a share. After this operation the rings that were associated
 * with the MAC client are mapped directly into the corresponding
 * guest domain.
 */
int
mac_share_bind(mac_client_handle_t mch, uint64_t cookie, uint64_t *rcookie)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;
	int rv;

	i_mac_perim_enter(mip);

	if (mcip->mci_share == 0) {
		i_mac_perim_exit(mip);
		return (ENOTSUP);
	}

	ASSERT((mcip->mci_state_flags & MCIS_SHARE_BOUND) == 0);

	/*
	 * Temporarly suspend the TX traffic for that client to make sure
	 * there are no in flight packets through a transmit ring
	 * which is being bound to another domain.
	 */
	mac_tx_client_quiesce(mch);

	/*
	 * For the receive path, no traffic will be sent up through
	 * the rings to the IO domain. For TX, we need to ensure
	 * that traffic sent by the MAC client are sent through
	 * the default ring.
	 *
	 * For the transmit path we ensure that packets are sent through the
	 * default ring if the share of the MAC client is bound, see MAC_TX().
	 */

	rv = mip->mi_share_capab.ms_sbind(mcip->mci_share, cookie, rcookie);
	if (rv == 0)
		mcip->mci_state_flags |= MCIS_SHARE_BOUND;

	/*
	 * Resume transmit traffic for the MAC client.
	 */
	mac_tx_client_restart(mch);

	i_mac_perim_exit(mip);

	return (rv);
}


/*
 * Unbind a share.
 */
void
mac_share_unbind(mac_client_handle_t mch)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;

	i_mac_perim_enter(mip);

	if (mcip->mci_share == 0) {
		i_mac_perim_exit(mip);
		return;
	}

	mip->mi_share_capab.ms_sunbind(mcip->mci_share);

	mcip->mci_state_flags &= ~MCIS_SHARE_BOUND;

	/*
	 * If the link state changed while the share was bound, the
	 * soft rings fanout associated with the client would have not
	 * been updated by mac_fanout_recompute(). Do the check here
	 * now that the share has been unbound.
	 */
	mac_fanout_recompute_client(mcip, NULL);

	i_mac_perim_exit(mip);
}
