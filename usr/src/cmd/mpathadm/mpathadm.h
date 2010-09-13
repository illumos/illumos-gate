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

#ifndef	_MPATHADM_H
#define	_MPATHADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	LIST					SUBCOMMAND(0)
#define	SHOW					SUBCOMMAND(1)
#define	MODIFY					SUBCOMMAND(2)
#define	ENABLE					SUBCOMMAND(3)
#define	DISABLE					SUBCOMMAND(4)
#define	FAILOVER				SUBCOMMAND(5)
#define	OVERRIDE				SUBCOMMAND(6)
#define	ADD					SUBCOMMAND(7)
#define	REMOVE					SUBCOMMAND(8)


#define	MPATH_SUPPORT				OBJECT(0)
#define	LOGICAL_UNIT				OBJECT(1)
#define	INITIATOR_PORT				OBJECT(2)
#define	PATH					OBJECT(3)

#define	MAX_PLUGINNAME_LEN			256

#define	ERROR_CLI_FAILED			99


int listMpathSupport(int operandLen, char *operand[]);
int showMpathSupport(int operandLen, char *operand[]);
int modifyMpathSupport(int operandLen, char *operand[], cmdOptions_t *options);

int listLogicalUnit(int operandLen, char *operand[], cmdOptions_t *options);
int listIndividualLogicalUnit(MP_OID luOid,
    MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES luProps);
int showLogicalUnit(int operandLen, char *operand[]);
int showIndividualLogicalUnit(MP_OID luOid,
    MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES luProps, MP_PLUGIN_PROPERTIES);
int modifyLogicalUnit(int operandLen, char *operand[], cmdOptions_t *options);
int failoverLogicalUnit(char *operand[]);
boolean_t getLogicalUnitOid(MP_CHAR *luFileName, MP_OID *pluOid);

int listInitiatorPort(int operandLen, char *operand[]);
int listIndividualInitiatorPort(MP_INITIATOR_PORT_PROPERTIES initProps);
int showInitiatorPort(int operandLen, char *operand[]);
int showIndividualInitiatorPort(MP_INITIATOR_PORT_PROPERTIES initProps);

int enablePath(cmdOptions_t *options);
int disablePath(cmdOptions_t *options);
int overridePath(cmdOptions_t *options);

boolean_t getPathOid(cmdOptions_t *options, MP_OID *pPathOid);
MP_LOAD_BALANCE_TYPE getLbValueFromString(char *str);

char *getMpStatusStr(MP_STATUS mpstatus);
void displayArray(MP_CHAR *arrayToDisplay, int arraySize);
void displayWideArray(MP_WCHAR *arrayToDisplay, int arraySize);
char *getPathStateStr(MP_PATH_STATE pathState);
char *getAccessStateStr(MP_ACCESS_STATE_TYPE accessState);
MP_CHAR *getStringArray(MP_CHAR *arrayToDisplay, int arraySize);
boolean_t compareLUName(MP_CHAR *cmpString, MP_CHAR *deviceFileName);
void displayLoadBalanceString(MP_LOAD_BALANCE_TYPE lbVal);
void displayLogicalUnitNameTypeString(MP_LOGICAL_UNIT_NAME_TYPE typeVal);
void displayTransportTypeString(MP_PORT_TRANSPORT_TYPE transportTypeVal);

#ifdef	__cplusplus
}
#endif

#endif /* _MPATHADM_H */
