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
 * Copyright 1999-2002 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * file: snmp_stub.c
 *
 * This file contains the SNMP routines used to retrieve
 * the Mobility Agent's various counter and configurable
 * information.
 */

#include <sys/types.h>
#include <netinet/in.h>

#include <impl.h>
#include <snmp.h>

#include "agent.h"

/* Counters common to all Mobility Agents */
extern CommonCounters commonCounters;

/* Counters maintained by Foreign Agents */
extern ForeignAgentCounters faCounters;

/* Counters maintained by Home Agents */
extern HomeAgentCounters haCounters;


#define	MIP_MOBILE_NODE		0x1
#define	MIP_FOREIGN_AGENT	0x2
#define	MIP_HOME_AGENT		0x4

#define	MIP_ENABLE		1
#define	MIP_DISABLE		2

#define	MIP_ENCAP_IP_IN_IP	0x1
#define	MIP_ENCAP_GRE		0x2
#define	MIP_ENCAP_MIN_ENCAP	0x4
#define	MIP_OTHER		0x8

/*
 * Function: get_mipEntities
 *
 * Arguments:	mipEntities - Pointer to Integer
 *
 * Description:	Returns whether the agent is running
 *		as a Foreign and/or Home agent.
 *
 * Returns: int, 0 if successful
 */
int
get_mipEntities(Integer *mipEntities)
{
	/*
	 * We can only be both Mobility Agents
	 */
	*mipEntities = (MIP_FOREIGN_AGENT | MIP_HOME_AGENT);
	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_mipEnable
 *
 * Arguments:	mipEnable - Pointer to Integer
 *
 * Description: This function is called to determine if
 *		if the Mobile-IP Agent is in the
 *		active mode.
 *
 * Returns: int, 0 if successful
 */
int
get_mipEnable(Integer *mipEnable)
{
	/*
	 * If we get this far, then we are enabled :)
	 */
	*mipEnable = MIP_ENABLE;
	return (SNMP_ERR_NOERROR);
}

/*
 * Function: set_mipEnable
 *
 * Arguments:	pass - The SNMP Pass
 *		mipEnable - Pointer to an Integer
 *
 * Description: This function is called to start the
 *		SNMP Mobile-IP Agent. We do not currently
 *		support this option.
 *
 * Returns: int, 0 if successful
 */
int
set_mipEnable(int pass, Integer *mipEnable)
{
	switch (pass) {
	    case FIRST_PASS:
		/*
		 * Check whether the argument provided was valid to begin with
		 */
		if (*mipEnable != MIP_ENABLE && *mipEnable != MIP_DISABLE) {
		    return (SNMP_ERR_GENERR);
		}
		return (SNMP_ERR_NOERROR);

	    case SECOND_PASS:
		/*
		 * Here is where we allow the value to be changed. We do
		 * not allow this at this time.
		 */
		return (SNMP_ERR_READONLY);
	}

	return (SNMP_ERR_GENERR);
}

/*
 * Function: get_mipEncapsulationSupported
 *
 * Arguments:	mipEncapsulationSupported - Pointer to Integer
 *
 * Description: This function is called to retrieve the
 *		encapsulation types supported by the
 *		agent.
 *
 * Returns: int, 0 if successful
 */
int
get_mipEncapsulationSupported(Integer *mipEncapsulationSupported)
{
	/*
	 * We currently only support IP in IP
	 */
	*mipEncapsulationSupported = MIP_ENCAP_IP_IN_IP;
	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_mipSecTotalViolations
 *
 * Arguments:	mipSecTotalViolations - Pointer to Integer
 *
 * Description: This function is called to retrieve the
 *		number of security violations since start-up.
 *
 * Returns: int, 0 if successful
 */
int
get_mipSecTotalViolations(Integer *mipSecTotalViolations)
{
	/*
	 * TODO: Return the total number of un-authenticated requests
	 */
	*mipSecTotalViolations = haCounters.haMNAuthFailureCnt +
	    haCounters.haFAAuthFailureCnt + faCounters.faMNAuthFailureCnt +
	    faCounters.faHAAuthFailureCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_maAdvertisementsSent
 *
 * Arguments:	maAdvertisementsSent - Pointer to Integer
 *
 * Description: This function is called to retrieve the
 *		number of advertisements transmitted.
 *
 * Returns: int, 0 if successful
 */
int
get_maAdvertisementsSent(Integer *maAdvertisementsSent)
{
	/*
	 * Return the total number of advertisements sent
	 */
	*maAdvertisementsSent = commonCounters.maAdvSentCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_maAdvsSentForSolicitation
 *
 * Arguments:	maAdvsSentForSolicitation - Pointer to Integer
 *
 * Description: This function is called to retrieve the
 *		number of advertisements transmitted as a
 *		result of a solicitation received.
 *
 * Returns: int, 0 if successful
 */
int
get_maAdvsSentForSolicitation(Integer *maAdvsSentForSolicitation)
{
	/*
	 * Return the total number of advertisements we've sent
	 * due to a solicitation.
	 */
	*maAdvsSentForSolicitation =
	    commonCounters.maAdvSentForSolicitationsCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_maSolicitationsReceived
 *
 * Arguments:	maSolicitationsReceived - Pointer to Integer
 *
 * Description: This function is called to retrieve the
 *		number of solicitations received.
 *
 * Returns: int, 0 if successful
 */
int
get_maSolicitationsReceived(Integer *maSolicitationsReceived)
{
	/*
	 * Return the total number of solicitations received.
	 */
	*maSolicitationsReceived = commonCounters.maSolicitationsRecvdCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faIsBusy
 *
 * Arguments:	faIsBusy - Pointer to Integer
 *
 * Description: This function is called to retrieve the
 *		number of times we've advertised the fact
 *		that we were busy.
 *
 * Returns: int, 0 if successful
 */
int
get_faIsBusy(Integer *faIsBusy)
{
	/*
	 * Return the number of times that the foreign agent has
	 * responded as being too busy.
	 */
	*faIsBusy = faCounters.faIsBusyCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faRegistrationRequired
 *
 * Arguments:	faRegistrationRequired - Pointer to Integer
 *
 * Description: This function is called to determine whether
 *		we require registrations to provide service.
 *
 * Returns: int, 0 if successful
 */
int
get_faRegistrationRequired(Integer *faRegistrationRequired)
{
	/*
	 * States whether the Foreign Agent REQUIRES that
	 * all Mobile Nodes register with it. We currently
	 * have no way of enforcing this (short of setting
	 * up a filter on the Foreign Agent).
	 */
	*faRegistrationRequired = _B_FALSE;
	return (SNMP_ERR_NOERROR);
}

/*
 * Function: set_faRegistrationRequired
 *
 * Arguments:	pass - The SNMP Pass
 *		faRegistrationRequired - Pointer to an Integer
 *
 * Description: This function is called to require the agent
 *		to receive a registration in order to provide
 *		service. We do not currently allow this to
 *		be set via SNMP.
 *
 * Returns: int, 0 if successful
 */
int
set_faRegistrationRequired(int pass, Integer *faRegistrationRequired)
{
	switch (pass) {
	case FIRST_PASS:
		/*
		 * Check whether a valid argument was passed.
		 */
		if (*faRegistrationRequired == _B_TRUE ||
		    *faRegistrationRequired == _B_FALSE) {
		    return (SNMP_ERR_NOERROR);
		}
		return (SNMP_ERR_GENERR);

	case SECOND_PASS:
		/*
		 * Sorry, we do not allow this at this time.
		 */
		return (SNMP_ERR_READONLY);
	}

	return (SNMP_ERR_GENERR);
}

/*
 * Function: get_faRegRequestsReceived
 *
 * Arguments:	faRegRequestsReceived - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've received.
 *
 * Returns: int, 0 if successful
 */
int
get_faRegRequestsReceived(Integer *faRegRequestsReceived)
{
	/*
	 * Return the total number of Registration Requests we've
	 * received.
	 */
	*faRegRequestsReceived = faCounters.faRegReqRecvdCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faRegRequestsRelayed
 *
 * Arguments:	faRegRequestsRelayed - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		relayed to a Home Agent.
 *
 * Returns: int, 0 if successful
 */
int
get_faRegRequestsRelayed(Integer *faRegRequestsRelayed)
{
	/*
	 * Return the total number of Registration Requests we've
	 * replayed.
	 */
	*faRegRequestsRelayed = faCounters.faRegReqRelayedCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faReasonUnspecified
 *
 * Arguments:	faReasonUnspecified - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to reason
 *		unspecified.
 *
 * Returns: int, 0 if successful
 */
int
get_faReasonUnspecified(Integer *faReasonUnspecified)
{
	/*
	 * Return the total number of Registration Requests we've
	 * rejected for unspecified reasons (error 64).
	 */
	*faReasonUnspecified = faCounters.faReasonUnspecifiedCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faAdmProhibited
 *
 * Arguments:	faAdmProhibited - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to administratively
 *		prohibited.
 *
 * Returns: int, 0 if successful
 */
int
get_faAdmProhibited(Integer *faAdmProhibited)
{
	/*
	 * Return the total number of Registration Requests we've
	 * rejected for administrative purposes (error 65).
	 */
	*faAdmProhibited = faCounters.faAdmProhibitedCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faInsufficientResource
 *
 * Arguments:	faInsufficientResource - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to insufficient
 *		resources.
 *
 * Returns: int, 0 if successful
 */
int
get_faInsufficientResource(Integer *faInsufficientResource)
{
	/*
	 * Return the total number of Registration Requests we've
	 * rejected due to insufficient resources (error 66).
	 */
	*faInsufficientResource = faCounters.faInsufficientResourceCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faMNAuthenticationFailure
 *
 * Arguments:	faMNAuthenticationFailure - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to MN-FA
 *		Authentication Failure.
 *
 * Returns: int, 0 if successful
 */
int
get_faMNAuthenticationFailure(Integer *faMNAuthenticationFailure)
{
	/*
	 * Return the number of Mobile Node authentication
	 * failures.
	 */
	*faMNAuthenticationFailure = faCounters.faMNAuthFailureCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faRegLifetimeTooLong
 *
 * Arguments:	faRegLifetimeTooLong - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to lifetime
 *		too long.
 *
 * Returns: int, 0 if successful
 */
int
get_faRegLifetimeTooLong(Integer *faRegLifetimeTooLong)
{
	/*
	 * Return the number of failed Registration Requests
	 * due to a lifetime too long.
	 */
	*faRegLifetimeTooLong = faCounters.faRegLifetimeTooLongCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faPoorlyFormedRequests
 *
 * Arguments:	faPoorlyFormedRequests - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to poorly
 *		formed request.
 *
 * Returns: int, 0 if successful
 */
int
get_faPoorlyFormedRequests(Integer *faPoorlyFormedRequests)
{
	/*
	 * Returns the number of poorly formed requests we've
	 * received.
	 */
	*faPoorlyFormedRequests = faCounters.faPoorlyFormedRequestsCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faEncapsulationUnavailable
 *
 * Arguments:	faEncapsulationUnavailable - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to encapsulation
 *		unavailable.
 *
 * Returns: int, 0 if successful
 */
int
get_faEncapsulationUnavailable(Integer *faEncapsulationUnavailable)
{
	/*
	 * Returns the number of times we've rejected a request
	 * due to an unsupported encapsulation.
	 */
	*faEncapsulationUnavailable = faCounters.faEncapUnavailableCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faVJCompressionUnavailable
 *
 * Arguments:	faVJCompressionUnavailable - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to VJ compression
 *		unavailable.
 *
 * Returns: int, 0 if successful
 */
int
get_faVJCompressionUnavailable(Integer *faVJCompressionUnavailable)
{
	/*
	 * Returns the number of times we've returned an error
	 * stating that compression was unavailable.
	 */
	*faVJCompressionUnavailable = faCounters.faVJCompUnavailableCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faHAUnreachable
 *
 * Arguments:	faHAUnreachable - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		failed with the error set to HA
 *		unreachable.
 *
 * Returns: int, 0 if successful
 */
int
get_faHAUnreachable(Integer *faHAUnreachable)
{
	/*
	 * Returns the number of times that we've replied to a
	 * mobile node stating that the home agent was unreachable.
	 */
	*faHAUnreachable = faCounters.faHAUnreachableCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faRegRepliesRecieved
 *
 * Arguments:	faRegRepliesRecieved - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've
 *		received.
 *
 * Returns: int, 0 if successful
 */
int
get_faRegRepliesRecieved(Integer *faRegRepliesRecieved)
{
	/*
	 * Returns the number of Registration Replies we've received.
	 */
	*faRegRepliesRecieved = faCounters.faRegRepliesRecvdCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faRegRepliesRelayed
 *
 * Arguments:	faRegRepliesRelayed - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've
 *		relayed.
 *
 * Returns: int, 0 if successful
 */
int
get_faRegRepliesRelayed(Integer *faRegRepliesRelayed)
{

	/*
	 * Returns the number of Registration Replies we've relayed.
	 */
	*faRegRepliesRelayed = faCounters.faRegRepliesRelayedCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faHAAuthenticationFailure
 *
 * Arguments:	faHAAuthenticationFailure - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've
 *		relayed with the error FA-HA Auth Failure.
 *
 * Returns: int, 0 if successful
 */
int
get_faHAAuthenticationFailure(Integer *faHAAuthenticationFailure)
{
	/*
	 * Returns the number of times that we've encountered an
	 * FA-HA Authentication failure.
	 */
	*faHAAuthenticationFailure = faCounters.faHAAuthFailureCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_faPoorlyFormedReplies
 *
 * Arguments:	faPoorlyFormedReplies - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've
 *		relayed with the error poorly formed reply.
 *
 * Returns: int, 0 if successful
 */
int
get_faPoorlyFormedReplies(Integer *faPoorlyFormedReplies)
{
	/*
	 * Return the number of times that we've received a poorly
	 * formed reply.
	 */
	*faPoorlyFormedReplies = faCounters.faPoorlyFormedRepliesCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haRegistrationAccepted
 *
 * Arguments:	haRegistrationAccepted - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Requests we've
 *		accepted.
 *
 * Returns: int, 0 if successful
 */
int
get_haRegistrationAccepted(Integer *haRegistrationAccepted)
{
	/*
	 * Return the number of Registrations that we've accepted.
	 */
	*haRegistrationAccepted = haCounters.haRegAccepted0Cnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haMultiBindingUnsupported
 *
 * Arguments:	haMultiBindingUnsupported - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to multiple bindings
 *		unsupported.
 *
 * Returns: int, 0 if successful
 */
int
get_haMultiBindingUnsupported(Integer *haMultiBindingUnsupported)
{
	/*
	 * Ret	urn the number of Registrations that we've denied with
	 * code 1.
	 */
	*haMultiBindingUnsupported = haCounters.haRegAccepted1Cnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haReasonUnspecified
 *
 * Arguments:	haReasonUnspecified - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to reason unspecified.
 *
 * Returns: int, 0 if successful
 */
int
get_haReasonUnspecified(Integer *haReasonUnspecified)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 128.
	 */
	*haReasonUnspecified = haCounters.haReasonUnspecifiedCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haAdmProhibited
 *
 * Arguments:	haAdmProhibited - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to administratively
 *		prohibited.
 *
 * Returns: int, 0 if successful
 */
int
get_haAdmProhibited(Integer *haAdmProhibited)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 129.
	 */
	*haAdmProhibited = haCounters.haAdmProhibitedCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haInsufficientResource
 *
 * Arguments:	haInsufficientResource - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to insufficient
 *		resources.
 *
 * Returns: int, 0 if successful
 */
int
get_haInsufficientResource(Integer *haInsufficientResource)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 130.
	 */
	*haInsufficientResource = haCounters.haInsufficientResourceCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haMNAuthenticationFailure
 *
 * Arguments:	haMNAuthenticationFailure - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to MN-HA Authentication
 *		failed.
 *
 * Returns: int, 0 if successful
 */
int
get_haMNAuthenticationFailure(Integer *haMNAuthenticationFailure)
{

	/*
	 * Return the number of Registrations that we've denied with
	 * code 131.
	 */
	*haMNAuthenticationFailure = haCounters.haMNAuthFailureCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haFAAuthenticationFailure
 *
 * Arguments:	haFAAuthenticationFailure - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to FA-HA Authentication
 *		failed.
 *
 * Returns: int, 0 if successful
 */
int
get_haFAAuthenticationFailure(Integer *haFAAuthenticationFailure)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 132.
	 */
	*haFAAuthenticationFailure = haCounters.haFAAuthFailureCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haIDMismatch
 *
 * Arguments:	haIDMismatch - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to ID Mismatch.
 *
 * Returns: int, 0 if successful
 */
int
get_haIDMismatch(Integer *haIDMismatch)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 133.
	 */
	*haIDMismatch = haCounters.haIDMismatchCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haPoorlyFormedRequest
 *
 * Arguments:	haPoorlyFormedRequest - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to poorly formed
 *		request.
 *
 * Returns: int, 0 if successful
 */
int
get_haPoorlyFormedRequest(Integer *haPoorlyFormedRequest)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 134.
	 */
	*haPoorlyFormedRequest = haCounters.haPoorlyFormedRequestsCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haTooManyBindings
 *
 * Arguments:	haTooManyBindings - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to too many bindings.
 *
 * Returns: int, 0 if successful
 */
int
get_haTooManyBindings(Integer *haTooManyBindings)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 135.
	 */
	*haTooManyBindings = haCounters.haTooManyBindingsCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haUnknownHA
 *
 * Arguments:	haUnknownHA - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of Registration Replies we've sent
 *		with the error set to unknown Home Agent.
 *
 * Returns: int, 0 if successful
 */
int
get_haUnknownHA(Integer *haUnknownHA)
{
	/*
	 * Return the number of Registrations that we've denied with
	 * code 136.
	 */
	*haUnknownHA = haCounters.haUnknownHACnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haGratuitiousARPsSent
 *
 * Arguments:	haGratuitiousARPsSent - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of gratuitious ARPs sent.
 *
 * Returns: int, 0 if successful
 */
int
get_haGratuitiousARPsSent(Integer *haGratuitiousARPsSent)
{
	/*
	 * Return the total number of gratuitious ARPs sent
	 */
	*haGratuitiousARPsSent = haCounters.haGratuitousARPsSentCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haProxyARPsSent
 *
 * Arguments:	haProxyARPsSent - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of proxy ARPs sent.
 *
 * Returns: int, 0 if successful
 */
int
get_haProxyARPsSent(Integer *haProxyARPsSent)
{
	/*
	 * Return the total number of proxy ARPs sent
	 */
	*haProxyARPsSent = haCounters.haProxyARPsSentCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haRegRequestsReceived
 *
 * Arguments:	haRegRequestsReceived - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of registration requests received.
 *
 * Returns: int, 0 if successful
 */
int
get_haRegRequestsReceived(Integer *haRegRequestsReceived)
{
	/*
	 * Return the total number of Registration Requests received
	 */
	*haRegRequestsReceived = haCounters.haRegReqRecvdCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haDeRegRequestsReceived
 *
 * Arguments:	haDeRegRequestsReceived - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of deregistration requests received.
 *
 * Returns: int, 0 if successful
 */
int
get_haDeRegRequestsReceived(Integer *haDeRegRequestsReceived)
{
	/*
	 * Return the total number of Deregistration Requests received
	 */
	*haDeRegRequestsReceived = haCounters.haDeRegReqRecvdCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haRegRepliesSent
 *
 * Arguments:	haRegRepliesSent - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of registration replies sent.
 *
 * Returns: int, 0 if successful
 */
int
get_haRegRepliesSent(Integer *haRegRepliesSent)
{
	/*
	 * Return the total number of Registration Replies we've
	 * sent
	 */
	*haRegRepliesSent = haCounters.haRegRepliesSentCnt;

	return (SNMP_ERR_NOERROR);
}

/*
 * Function: get_haDeRegRepliesSent
 *
 * Arguments:	haDeRegRepliesSent - Pointer to Integer
 *
 * Description: This function is called to return the
 *		number of deregistration replies sent.
 *
 * Returns: int, 0 if successful
 */
int
get_haDeRegRepliesSent(Integer *haDeRegRepliesSent)
{
	/*
	 * Return the total number of Registration Replies we've
	 * received
	 */
	*haDeRegRepliesSent = haCounters.haDeRegRepliesSentCnt;

	return (SNMP_ERR_NOERROR);
}

int
get_i_dont_think_so(Integer *bogus)
{
	*bogus = 1;

	return (SNMP_ERR_NOERROR);
}
