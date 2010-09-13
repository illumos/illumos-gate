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

#ifndef	_TGTFCHBAPORT_H
#define	_TGTFCHBAPORT_H



#include <Lockable.h>
#include <HBAPort.h>
#include <Exceptions.h>
#include <string>
#include <hbaapi.h>
#include <sys/fctio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Represents a single HBA port
 */
class TgtFCHBAPort : public HBAPort {
public:
    TgtFCHBAPort(std::string path);
    virtual std::string			getPath()
					    { return path; }
    virtual uint64_t			getNodeWWN()
					    { return nodeWWN; }
    virtual uint64_t			getPortWWN()
					    { return portWWN; }
    virtual HBA_PORTATTRIBUTES		getPortAttributes(
					    uint64_t &stateChange);
    virtual HBA_PORTATTRIBUTES		getDiscoveredAttributes(
					    HBA_UINT32 discoveredport,
					    uint64_t &stateChange);
    virtual HBA_PORTATTRIBUTES		getDiscoveredAttributes(
					    uint64_t wwn,
					    uint64_t &stateChange);
    virtual void			validatePresent();
    virtual void	    getTargetMappings(
				PHBA_FCPTARGETMAPPINGV2 userMappings) {
				throw NotSupportedException(); }
    virtual void	    getRNIDMgmtInfo(PHBA_MGMTINFO info) {
				throw NotSupportedException(); }
    virtual void	    sendCTPassThru(void *requestBuffer,
				HBA_UINT32 requestSize,
				void *responseBuffer,
				HBA_UINT32 *responseSize) {
				throw NotSupportedException(); }
    virtual void	    sendRLS(uint64_t destWWN,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize);
    virtual void	    sendRPL(uint64_t destWWN,
				HBA_UINT32 agent_domain,
				HBA_UINT32 port_index,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) {
				throw NotSupportedException(); }
    virtual void	    sendRPS(uint64_t agentWWN,
				HBA_UINT32 agentDomain,
				uint64_t objectWWN,
				HBA_UINT32 objectPortNum,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) {
				throw NotSupportedException(); }
    virtual void	    sendSRL(uint64_t destWWN,
				HBA_UINT32 agent_domain,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) {
				throw NotSupportedException(); }
    virtual void	    sendLIRR(uint64_t destWWN,
				HBA_UINT8 function,
				HBA_UINT8 type,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) {
				throw NotSupportedException(); }
    virtual void	    sendReportLUNs(uint64_t wwn,
				void *responseBuffer, HBA_UINT32 *responseSize,
				HBA_UINT8 *scsiStatus,
				void *senseBuffer, HBA_UINT32 *senseSize) {
				throw NotSupportedException(); }
    virtual void	    sendScsiInquiry(uint64_t wwn, HBA_UINT64 fcLun,
				HBA_UINT8 cdb1, HBA_UINT8 cdb2,
				void *responseBuffer, HBA_UINT32 *responseSize,
				HBA_UINT8 *scsiStatus, void *senseBuffer,
				HBA_UINT32 *senseSize) {
				throw NotSupportedException(); }
    virtual void	    sendReadCapacity(uint64_t pwwn,
				HBA_UINT64 fcLun, void *responseBuffer,
				HBA_UINT32 *responseSize, HBA_UINT8 *scsiStatus,
				void *senseBuffer, HBA_UINT32 *senseSize) {
				throw NotSupportedException(); }
    virtual void	    sendRNID(uint64_t destwwn, HBA_UINT32 destfcid,
				HBA_UINT32 nodeIdDataFormat, void *pRspBuffer,
				HBA_UINT32 *RspBufferSize) {
				throw NotSupportedException(); }
    virtual void	    setRNID(HBA_MGMTINFO info) {
				throw NotSupportedException(); }
    virtual HBA_PORTNPIVATTRIBUTES	getPortNPIVAttributes(
					    uint64_t &stateChange) {
				throw NotSupportedException(); }
    virtual uint32_t	    createNPIVPort(
				uint64_t vnodewwn,
				uint64_t vportwwn,
				uint32_t vindex) {
				throw NotSupportedException(); }
    virtual uint32_t	    deleteNPIVPort(
				uint64_t vportwwn) {
				throw NotSupportedException(); }

private:
    std::string		    path;
    uint64_t		    portWWN;
    uint64_t		    nodeWWN;
    uint32_t		    instanceNumber;
    int			    controllerNumber;
    static const std::string	FCT_DRIVER_PATH;
    static const int		MAX_FCTIO_MSG_LEN;
    static void transportError(uint32_t fcio_errno, char *message);

	// Wrapper routines to handle error cases
    static void	    fct_ioctl(int cmd, fctio_t *arg);
};

#ifdef	__cplusplus
}
#endif

#endif /* _TGTFCHBAPORT_H */
