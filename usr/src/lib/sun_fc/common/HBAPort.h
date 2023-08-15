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

#ifndef	_HBAPORT_H
#define	_HBAPORT_H



#include "Lockable.h"
#include "HBANPIVPort.h"
#include <string>
#include <map>
#include <vector>
#include <hbaapi.h>
#include <hbaapi-sun.h>

/**
 * @memo	    Represents a single HBA port
 *
 */
class HBAPort : public Lockable {
public:
    HBAPort();
    virtual ~HBAPort() {}
    bool		    operator==(HBAPort &comp);
    virtual void			validatePresent();
    virtual std::string			getPath() = 0;
    virtual uint64_t			getNodeWWN() = 0;
    virtual uint64_t			getPortWWN() = 0;
    virtual HBA_PORTATTRIBUTES		getPortAttributes(
					    uint64_t &stateChange) = 0;
    virtual HBA_PORTATTRIBUTES		getDiscoveredAttributes(
					    HBA_UINT32 discoveredport,
					    uint64_t &stateChange) = 0;
    virtual HBA_PORTATTRIBUTES		getDiscoveredAttributes(
					    uint64_t wwn,
					    uint64_t &stateChange) = 0;
    virtual void	    getTargetMappings(
				PHBA_FCPTARGETMAPPINGV2 userMappings) = 0;
    virtual void	    getRNIDMgmtInfo(PHBA_MGMTINFO info) = 0;
    virtual void	    sendCTPassThru(void *requestBuffer,
				HBA_UINT32 requestSize,
				void *responseBuffer,
				HBA_UINT32 *responseSize) = 0;
    virtual void	    sendRLS(uint64_t destWWN,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) = 0;
    virtual void	    sendRPL(uint64_t destWWN,
				HBA_UINT32 agent_domain,
				HBA_UINT32 port_index,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) = 0;
    virtual void	    sendRPS(uint64_t agentWWN,
				HBA_UINT32 agentDomain,
				uint64_t objectWWN,
				HBA_UINT32 objectPortNum,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) = 0;
    virtual void	    sendSRL(uint64_t destWWN,
				HBA_UINT32 agent_domain,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) = 0;
    virtual void	    sendLIRR(uint64_t destWWN,
				HBA_UINT8 function,
				HBA_UINT8 type,
				void *pRspBuffer,
				HBA_UINT32 *pRspBufferSize) = 0;
    virtual void	    sendReportLUNs(uint64_t wwn,
				void *responseBuffer, HBA_UINT32 *responseSize,
				HBA_UINT8 *scsiStatus,
				void *senseBuffer, HBA_UINT32 *senseSize) = 0;
    virtual void	    sendScsiInquiry(uint64_t wwn, HBA_UINT64 fcLun,
				HBA_UINT8 cdb1, HBA_UINT8 cdb2,
				void *responseBuffer, HBA_UINT32 *responseSize,
				HBA_UINT8 *scsiStatus, void *senseBuffer,
				HBA_UINT32 *senseSize) = 0;
    virtual void	    sendReadCapacity(uint64_t pwwn,
				HBA_UINT64 fcLun, void *responseBuffer,
				HBA_UINT32 *responseSize, HBA_UINT8 *scsiStatus,
				void *senseBuffer, HBA_UINT32 *senseSize) = 0;

    static const int	    RNID_GENERAL_TOPOLOGY_DATA_FORMAT;
    virtual void	    sendRNID(uint64_t destwwn, HBA_UINT32 destfcid,
				HBA_UINT32 nodeIdDataFormat, void *pRspBuffer,
				HBA_UINT32 *RspBufferSize) = 0;
    virtual void	    setRNID(HBA_MGMTINFO info) = 0;

    static const uint8_t	HBA_NPIV_PORT_MAX;
    void			addPort(HBANPIVPort* port);
    HBANPIVPort*		getPort(uint64_t wwn);
    HBANPIVPort*		getPortByIndex(int index);
    virtual HBA_PORTNPIVATTRIBUTES	getPortNPIVAttributes(
					    uint64_t &stateChange) = 0;
    virtual uint32_t			createNPIVPort(
					    uint64_t vnodewwn,
					    uint64_t vportwwn,
					    uint32_t vindex) = 0;
    virtual uint32_t			deleteNPIVPort(
					    uint64_t vportwwn) = 0;
protected:
    void		    convertToShortNames(PHBA_FCPTARGETMAPPINGV2 mappings);
    std::string		    lookupControllerPath(std::string path);
    std::map<uint64_t, HBANPIVPort*>	npivportsByWWN;
    std::vector<HBANPIVPort*>		npivportsByIndex;
};


#endif /* _HBAPORT_H */
