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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MIPAGENTSNMP_STUB_H_
#define	_MIPAGENTSNMP_STUB_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _MipSecAssocEntry_t {
	Integer mipSecAlgorithmType;
	Integer mipSecAlgorithmMode;
	String mipSecKey;
	Integer mipSecReplayMethod;
} MipSecAssocEntry_t;

typedef struct _MipSecViolationEntry_t {
	String mipSecViolatorAddress;
	Integer mipSecViolationCounter;
	Integer mipSecRecentViolationSPI;
	Integer mipSecRecentViolationTime;
	Integer mipSecRecentViolationIDLow;
	Integer mipSecRecentViolationIDHigh;
	Integer mipSecRecentViolationReason;
} MipSecViolationEntry_t;

typedef struct _MaAdvConfigEntry_t {
	Integer maAdvMaxRegLifetime;
	Integer maAdvPrefixLengthInclusion;
	String maAdvAddress;
	Integer maAdvMaxInterval;
	Integer maAdvMinInterval;
	Integer maAdvMaxAdvLifetime;
	Integer maAdvResponseSolicitationOnly;
	Integer maAdvStatus;
} MaAdvConfigEntry_t;

typedef struct _FaCOAEntry_t {
	Integer faCOAStatus;
} FaCOAEntry_t;

typedef struct _FaVisitorEntry_t {
	String faVisitorIPAddress;
	String faVisitorHomeAddress;
	String faVisitorHomeAgentAddress;
	Integer faVisitorTimeGranted;
	Integer faVisitorTimeRemaining;
	Integer faVisitorRegFlags;
	Integer faVisitorRegIDLow;
	Integer faVisitorRegIDHigh;
	Integer faVisitorRegIsAccepted;
	Integer faVisitorInIfindex;
	String	faVisitorSlla;
} FaVisitorEntry_t;

typedef struct _HaMobilityBindingEntry_t {
	String haMobilityBindingMN;
	String haMobilityBindingCOA;
	String haMobilityBindingSourceAddress;
	Integer haMobilityBindingRegFlags;
	Integer haMobilityBindingRegIDLow;
	Integer haMobilityBindingRegIDHigh;
	Integer haMobilityBindingTimeGranted;
	Integer haMobilityBindingTimeRemaining;
} HaMobilityBindingEntry_t;

typedef struct _HaCounterEntry_t {
	Integer haServiceRequestsAccepted;
	Integer haServiceRequestsDenied;
	Integer haOverallServiceTime;
	Integer haRecentServiceAcceptedTime;
	Integer haRecentServiceDeniedTime;
	Integer haRecentServiceDeniedCode;
} HaCounterEntry_t;

/*
 * Prototype for functions in mipagentsnmp_stub.c
 */
extern int get_mipEntities(Integer *mipEntities);
extern int get_mipEnable(Integer *mipEnable);
extern int set_mipEnable(int pass, Integer* mipEnable);
extern int get_mipEncapsulationSupported(Integer *mipEncapsulationSupported);

extern int get_mipSecTotalViolations(Integer *mipSecTotalViolations);
extern int get_maAdvertisementsSent(Integer *maAdvertisementsSent);
extern int get_maAdvsSentForSolicitation(Integer *maAdvsSentForSolicitation);
extern int get_maSolicitationsReceived(Integer *maSolicitationsReceived);
extern int get_faIsBusy(Integer *faIsBusy);
extern int get_faRegistrationRequired(Integer *faRegistrationRequired);
extern int set_faRegistrationRequired(int pass,
    Integer *faRegistrationRequired);
extern int get_faRegRequestsReceived(Integer *faRegRequestsReceived);
extern int get_faRegRequestsRelayed(Integer *faRegRequestsRelayed);
extern int get_faReasonUnspecified(Integer *faReasonUnspecified);
extern int get_faAdmProhibited(Integer *faAdmProhibited);
extern int get_faInsufficientResource(Integer *faInsufficientResource);
extern int get_faMNAuthenticationFailure(Integer *faMNAuthenticationFailure);
extern int get_faRegLifetimeTooLong(Integer *faRegLifetimeTooLong);
extern int get_faPoorlyFormedRequests(Integer *faPoorlyFormedRequests);
extern int get_faEncapsulationUnavailable(Integer *faEncapsulationUnavailable);
extern int get_faVJCompressionUnavailable(Integer *faVJCompressionUnavailable);
extern int get_faHAUnreachable(Integer *faHAUnreachable);
extern int get_faRegRepliesRecieved(Integer *faRegRepliesRecieved);
extern int get_faRegRepliesRelayed(Integer *faRegRepliesRelayed);
extern int get_faHAAuthenticationFailure(Integer *faHAAuthenticationFailure);
extern int get_faPoorlyFormedReplies(Integer *faPoorlyFormedReplies);

extern int get_haRegistrationAccepted(Integer *haRegistrationAccepted);
extern int get_haMultiBindingUnsupported(Integer *haMultiBindingUnsupported);
extern int get_haReasonUnspecified(Integer *haReasonUnspecified);
extern int get_haAdmProhibited(Integer *haAdmProhibited);
extern int get_haInsufficientResource(Integer *haInsufficientResource);
extern int get_haMNAuthenticationFailure(Integer *haMNAuthenticationFailure);
extern int get_haFAAuthenticationFailure(Integer *haFAAuthenticationFailure);
extern int get_haIDMismatch(Integer *haIDMismatch);
extern int get_haPoorlyFormedRequest(Integer *haPoorlyFormedRequest);
extern int get_haTooManyBindings(Integer *haTooManyBindings);
extern int get_haUnknownHA(Integer *haUnknownHA);
extern int get_haGratuitiousARPsSent(Integer *haGratuitiousARPsSent);
extern int get_haProxyARPsSent(Integer *haProxyARPsSent);
extern int get_haRegRequestsReceived(Integer *haRegRequestsReceived);
extern int get_haDeRegRequestsReceived(Integer *haDeRegRequestsReceived);
extern int get_haRegRepliesSent(Integer *haRegRepliesSent);
extern int get_haDeRegRepliesSent(Integer *haDeRegRepliesSent);

extern int get_mipSecAssocEntry(int search_type,
    MipSecAssocEntry_t **mipSecAssocEntry_data, IndexType *index);
extern void free_mipSecAssocEntry(MipSecAssocEntry_t *mipSecAssocEntry);

/*
 * Prototype for functions in mipagentsnmp_mipSecViolationEntry.c
 */
extern int get_mipSecViolationEntry(int search_type,
    MipSecViolationEntry_t **mipSecViolationEntry_data, IndexType *index);
extern void free_mipSecViolationEntry(MipSecViolationEntry_t
	*mipSecViolationEntry);


/*
 * Prototype for functions in mipagentsnmp_maAdvConfigEntry.c
 */
extern int get_maAdvConfigEntry(int search_type,
    MaAdvConfigEntry_t **maAdvConfigEntry_data, IndexType *index);
extern void free_maAdvConfigEntry(MaAdvConfigEntry_t *maAdvConfigEntry);


/*
 * Prototype for functions in mipagentsnmp_faCOAEntry.c
 */
extern int get_faCOAEntry(int search_type,
    FaCOAEntry_t **faCOAEntry_data, IndexType *index);
extern void free_faCOAEntry(FaCOAEntry_t *faCOAEntry);


/*
 * Prototype for functions in mipagentsnmp_faVisitorEntry.c
 */
extern int get_faVisitorEntry(int search_type,
    FaVisitorEntry_t **faVisitorEntry_data, IndexType *index);
extern void free_faVisitorEntry(FaVisitorEntry_t *faVisitorEntry);


/*
 * Prototype for functions in mipagentsnmp_haMobilityBindingEntry.c
 */
extern int get_haMobilityBindingEntry(int search_type,
    HaMobilityBindingEntry_t **haMobilityBindingEntry_data, IndexType *index);
extern void free_haMobilityBindingEntry(HaMobilityBindingEntry_t
	*haMobilityBindingEntry);


/*
 * Prototype for functions in mipagentsnmp_haCounterEntry.c
 */
extern int get_haCounterEntry(int search_type,
    HaCounterEntry_t **haCounterEntry_data, IndexType *index);
extern void free_haCounterEntry(HaCounterEntry_t *haCounterEntry);

extern int SSAGetTrapPort();

#ifdef __cplusplus
}
#endif

#endif /* _MIPAGENTSNMP_STUB_H_ */
