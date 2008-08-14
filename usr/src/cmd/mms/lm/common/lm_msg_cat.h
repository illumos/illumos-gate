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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef __LM_MSG_CAT_H
#define	__LM_MSG_CAT_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	LM_7000_MSG "message [id [\"IEEE\" \"1244\" \"7000\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"LM was unable to obtain task id from %s command.\"]]"

#define	LM_7001_MSG "message [id [\"IEEE\" \"1244\" \"7001\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"Current state of LM does not allow processing a %s \
command.\"]]"

#define	LM_7002_MSG "message [id [\"IEEE\" \"1244\" \"7002\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"LM received an invalid command - %s.\"]]"

#define	LM_7003_MSG "message [id [\"IEEE\" \"1244\" \"7003\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"LM received a %s command after being told to shutdown, \
command aborted.\"]]"

#define	LM_7004_MSG "message [id [\"IEEE\" \"1244\" \"7004\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"Internal processing error occurred while processing LMPM %s \
command.\"]]"

#define	LM_7005_MSG "message [id [\"IEEE\" \"1244\" \"7005\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"Last LMPM %s command sent to LM contained a syntax error.\"]]"

#define	LM_7006_MSG "message [id [\"IEEE\" \"1244\" \"7006\"] \
arguments [\"ecode\" \"%d\"] \
loctext [\"EN\" \"LM received a signal to shutdown, exit code - %d.\"]]"

#define	LM_7007_MSG "message [id [\"IEEE\" \"1244\" \"7007\"] \
loctext [\"EN\" \"LM is shutting down due to an internal processing error.\"]]"

#define	LM_7008_MSG "message [id [\"IEEE\" \"1244\" \"7008\"] \
loctext [\"EN\" \"\"]]"

#define	LM_7009_MSG "message [id [\"IEEE\" \"1244\" \"7009\"] \
arguments [\"cmd\" \"%s\" \"part\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command has invalid or missing arguments in \
area of %s.\"]]"

#define	LM_7010_MSG "message [id [\"IEEE\" \"1244\" \"7010\"] \
arguments [\"type\" \"%s\" \"name\" \"%s\"] \
loctext [\"EN\" \"LMPM private command contains a unsupport %s-name of %s.\"]]"

#define	LM_7011_MSG "message [id [\"IEEE\" \"1244\" \"7011\"] \
arguments [\"name\" \"%s\" \"value\" \"%s\"] \
loctext [\"EN\" \"LMPM private command's set-name %s has a illegal set-value \
of %s.\"]]"

#define	LM_7012_MSG "message [id [\"IEEE\" \"1244\" \"7012\"] \
arguments [\"type\" \"%s\"] \
loctext [\"EN\" \"This libraries internal configuration is not a supported \
configuration for a library of type %s.\"]]"

#define	LM_7013_MSG "message [id [\"IEEE\" \"1244\" \"7013\"] \
arguments [\"state\" \"%s\"] \
loctext [\"EN\" \"LM state is changing to %s.\"]]"

#define	LM_7014_MSG "message [id [\"IEEE\" \"1244\" \"7014\"] \
loctext [\"EN\" \"LM is active.\"]]"

#define	LM_7015_MSG "message [id [\"IEEE\" \"1244\" \"7015\"] \
loctext [\"EN\" \"LM is deactivated.\"]]"

#define	LM_7016_MSG "message [id [\"IEEE\" \"1244\" \"7016\"] \
loctext [\"EN\" \"LM is exiting.\"]]"

#define	LM_7017_MSG "message [id [\"IEEE\" \"1244\" \"7017\"] \
loctext [\"EN\" \"LM is resetting.\"]]"

#define	LM_7018_MSG "message [id [\"IEEE\" \"1244\" \"7018\"] \
arguments [\"object\" \"%s\"] \
loctext [\"EN\" \"The library object %s or its value is missing.\"]]"

#define	LM_7019_MSG "message [id [\"IEEE\" \"1244\" \"7019\"] \
arguments [\"object\" \"%s\" \"value\" \"%s\"] \
loctext [\"EN\" \"The library object %s is invalidly configured to %s.\"]]"

#define	LM_7020_MSG "message [id [\"IEEE\" \"1244\" \"7020\"] \
arguments [\"type\" \"%s\" \"conn\" \"%s\"] \
loctext [\"EN\" \"Loading a %s library module of connection type %s failed.\"]]"

#define	LM_7021_MSG "message [id [\"IEEE\" \"1244\" \"7021\"] \
loctext [\"EN\" \"LM is shutting down due to mmswcr going away.\"]]"

#define	LM_7022_MSG "message [id [\"IEEE\" \"1244\" \"7022\"] \
loctext [\"EN\" \"LM completed partial reset.\"]]"

#define	LM_7023_MSG "message [id [\"IEEE\" \"1244\" \"7023\"] \
loctext [\"EN\" \"LM encountered a lmpm_parser syntax error on last LMPL \
response from MM.\"]]"

#define	LM_7024_MSG "message [id [\"IEEE\" \"1244\" \"7024\"] \
loctext [\"EN\" \"LM encountered a lmpm_parser syntax error on last input \
from MM, unable to determine if LMPM command or LMPL response.\"]]"

#define	LM_7025_MSG "message [id [\"IEEE\" \"1244\" \"7025\"] \
loctext [\"EN\" \"LM encountered a lmpm_parser no memory error.\"]]"

#define	LM_7026_MSG "message [id [\"IEEE\" \"1244\" \"7026\"] \
loctext [\"EN\" \"LM encountered a unrecoverable lmpm_parser error.\"]]"

#define	LM_7027_MSG "message [id [\"IEEE\" \"1244\" \"7027\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command is being aborted due to the LM going \
inactive or being shutdown.\"]]"


#define	LM_7030_MSG "message [id [\"IEEE\" \"1244\" \"7030\"] \
arguments [\"cmd\" \"%s\" \"lmpl\" \"%s\" \"rsp\" \"%s\"] \
loctext [\"EN\" \"During processing of LMPM %s command, LMPL %s command \
receieved a %s response from MM.\"]]"

#define	LM_7032_MSG "message [id [\"IEEE\" \"1244\" \"7032\"] \
arguments [\"cmd\" \"%s\" \"drive\" \"%s\"] \
loctext [\"EN\" \"During processing of LMPM %s command, LMPL show command \
was not able to obtain serial number for drive %s.\"]]"

#define	LM_7033_MSG "message [id [\"IEEE\" \"1244\" \"7032\"] \
arguments [\"type\" \"%s\" \"a_type\" \"%s\"] \
loctext [\"EN\" \"During activation of library, Library is configured in \
MMS as type %s, ACSLS says library is type %s.\"]]"


#define	LM_7101_MSG "message [id [\"IEEE\" \"1244\" \"7101\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command completed successfully.\"]]"

#define	LM_7102_MSG "message [id [\"IEEE\" \"1244\" \"7102\"] \
arguments [\"cart\" \"%s\" \"drive\" \"%s\"] \
loctext [\"EN\" \"Cartridge %s is mounted in drive %s.\"]]"

#define	LM_7103_MSG "message [id [\"IEEE\" \"1244\" \"7103\"] \
arguments [\"cart\" \"%s\" \"drive\" \"%s\"] \
loctext [\"EN\" \"Cartridge %s unmounted from drive %s.\"]]"

#define	LM_7105_MSG "message [id [\"IEEE\" \"1244\" \"7105\"] \
arguments [\"cmd\" \"%s\" \"type\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command is a NOP for a %s library.\"]]"

#define	LM_7106_MSG "message [id [\"IEEE\" \"1244\" \"7106\"] \
arguments [\"cart\" \"%s\"] \
loctext [\"EN\" \"Cartridge(s) %s injected into library.\"]]"

#define	LM_7107_MSG "message [id [\"IEEE\" \"1244\" \"7107\"] \
arguments [\"cart\" \"%s\"] \
loctext [\"EN\" \"Cartridge(s) %s ejected from library.\"]]"

#define	LM_7108_MSG "message [id [\"IEEE\" \"1244\" \"7108\"] \
arguments [\"port\" \"%s\"] \
loctext [\"EN\" \"Port %s is a valid ACSLS CAP desinator; however, it is \
not physically configured.\"]]"

#define	LM_7109_MSG "message [id [\"IEEE\" \"1244\" \"7109\"] \
loctext[\"EN\" \"There were cartridges in CAP, but none were injected into \
library.\"]]"

#define	LM_7110_MSG "message [id [\"IEEE\" \"1244\" \"7110\"] \
arguments [\"cart\" \"%s\"] \
loctext [\"EN\" \"Cartridge(s) %s were not injected into library.\"]]"

#define	LM_7111_MSG "message [id [\"IEEE\" \"1244\" \"7111\"] \
arguments [\"cart\" \"%s\"] \
loctext [\"EN\" \"Cartridge(s) %s were injected into library; however, \
unable to locate a slot location.\"]]"

#define	LM_7112_MSG "message [id [\"IEEE\" \"1244\" \"7112\"] \
loctext [\"EN\" \"CAP was empty, No cartridges injected into library.\"]]"

#define	LM_7113_MSG "message [id [\"IEEE\" \"1244\" \"7113\"] \
arguments [\"num\" \"%d\"] \
loctext [\"EN\" \"Too many cartridges specified to be ejected from library, \
max CAP size is %d.\"]]"

#define	LM_7114_MSG "message [id [\"IEEE\" \"1244\" \"7114\"] \
arguments [\"cart\" \"%s\"] \
loctext [\"EN\" \"Cartridge(s) %s were not ejected from library.\"]]"

#define	LM_7115_MSG "message [id [\"IEEE\" \"1244\" \"7115\"] \
loctext [\"EN\" \"No cartridges ejected from library.\"]]"

#define	LM_7116_MSG "message [id [\"IEEE\" \"1244\" \"7116\"] \
arguments [\"type\" \"%s\"] \
loctext [\"EN\" \"LMPM scan command does not support the fromslot and toslot \
format for %s libraries.\"]]"

#define	LM_7117_MSG "message [id [\"IEEE\" \"1244\" \"7117\"] \
arguments [\"port\" \"%s\"] \
loctext [\"EN\" \"Port %s is not a valid ACSLS CAP desinator.\"]]"

#define	LM_7118_MSG "message [id [\"IEEE\" \"1244\" \"7118\"] \
arguments [\"carts\" \"%s\"] \
loctext [\"EN\" \"Scan for cartridges %s found cartridges in slots of \
library.\"]]"

#define	LM_7119_MSG "message [id [\"IEEE\" \"1244\" \"7119\"] \
arguments [\"carts\" \"%s\"] \
loctext [\"EN\" \"Scan for cartridges %s did not find cartridges in slots of \
library.\"]]"

#define	LM_7120_MSG "message [id [\"IEEE\" \"1244\" \"7120\"] \
loctext [\"EN\" \"Scan for cartridges did not find any cartridges in slots \
of library.\"]]"

#define	LM_7121_MSG "message [id [\"IEEE\" \"1244\" \"7121\"] \
arguments  [\"geom\" \"%s\"] \
loctext [\"EN\" \"Scan of drive(s) with geometries %s completed\"]]"

#define	LM_7122_MSG "message [id [\"IEEE\" \"1244\" \"7122\"] \
loctext [\"EN\" \"Scan for drives(s) did not find any in library.\"]]"

#define	LM_7123_MSG "message [id [\"IEEE\" \"1244\" \"7123\"] \
arguments  [\"geom\" \"%s\"] \
loctext [\"EN\" \"Scan for drive(s) with geometries %s were not found \
in library.\"]]"

#define	LM_7124_MSG "message [id [\"IEEE\" \"1244\" \"7124\"] \
loctext [\"EN\" \"Scan of entire library completed.\"]]"

#define	LM_7125_MSG "message [id [\"IEEE\" \"1244\" \"7125\"] \
arguments  [\"list\" \"%s\"] \
loctext [\"EN\" \"Scan of drive(s) %s completed\"]]"

#define	LM_7126_MSG "message [id [\"IEEE\" \"1244\" \"7125\"] \
arguments  [\"name\" \"%s\" \"serial\" \"%s\"] \
loctext [\"EN\" \"No ACSLS geometry found for drive %s, serial number - %s.\"]]"


#define	LM_7200_MSG "message [id [\"IEEE\" \"1244\" \"7200\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"state\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, ACSLS command %s returned a \
status of STATUS_LIBRARY_NOT_AVAILABLE, state of ACSLS server - %s.\"]]"

#define	LM_7201_MSG "message [id [\"IEEE\" \"1244\" \"7201\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, ACSLS command %s returned a \
status of STATUS_LIBRARY_NOT_AVAILABLE, state of ACSLS server is \
non-determinable.\"]]"

#define	LM_7202_MSG "message [id [\"IEEE\" \"1244\" \"7202\"] \
arguments [\"state\" \"%s\"] \
loctext [\"EN\" \"Received a STATUS_LIBRARY_NOT_AVAILABLE from ACSLS server, \
state of server - %s, LM state being switched to broken.\"]]"

#define	LM_7203_MSG "message [id [\"IEEE\" \"1244\" \"7203\"] \
arguments [\"status\" \"%s\"] \
loctext [\"EN\" \"Communication problem with ACSLS server, status returned \
from server - %s, LM state being switched to disconnected.\"]]"

#define	LM_7204_MSG "message [id [\"IEEE\" \"1244\" \"7204\"] \
arguments [\"cmd\" \"%s\"] \
loctext [\"EN\" \"Library is currently performing an audit, please \
retry LMPM %s command again.\"]]"

#define	LM_7205_MSG "message [id [\"IEEE\" \"1244\" \"7205\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, MMS does not have permission \
to perform ACSLS command %s.\"]]"

#define	LM_7206_MSG "message [id [\"IEEE\" \"1244\" \"7206\"] \
loctext [\"EN\" \"Received a STATUS_LIBRARY_NOT_AVAILABLE from ACSLS server, \
state of server is non-determinable, LM state being switched to broken.\"]]"

#define	LM_7207_MSG "message [id [\"IEEE\" \"1244\" \"7207\"] \
arguments [\"status\" \"%s\" \"acsls\" \"%s\"] \
loctext [\"EN\" \"Internal problem with ACSLS server, received a %s from \
server for ACSLS command %s, LM state being switched to broken.\"]]"

#define	LM_7208_MSG "message [id [\"IEEE\" \"1244\" \"7208\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, ACSLS command %s returned \
a status of %s.\"]]"

#define	LM_7209_MSG "message [id [\"IEEE\" \"1244\" \"7209\"] \
arguments [\"acsls\" \"%s\"] \
loctext [\"EN\" \"Library component failure, received a \
STATUS_LIBRARY_FAILURE from ACSLS server for ACSLS command %s.\"]]"

#define	LM_7210_MSG "message [id [\"IEEE\" \"1244\" \"7210\"] \
arguments [\"drive\" \"%s\" \"geom\" \"%s\"] \
loctext [\"EN\" \"Drive %s is not accessible, drive state is set to offline. \
Drive's ACSLS geometry is %s.\"]]"

#define	LM_7211_MSG "message [id [\"IEEE\" \"1244\" \"7211\"] \
arguments [\"lsm\" \"%d,%d\"] \
loctext [\"EN\" \"LSM %d,%d is set to offline.\"]]"

#define	LM_7212_MSG "message [id [\"IEEE\" \"1244\" \"7212\"] \
arguments [\"cap\" \"%s\"] \
loctext [\"EN\" \"CAP %s is busy, try again.\"]]"

#define	LM_7213_MSG "message [id [\"IEEE\" \"1244\" \"7213\"] \
arguments [\"cap\" \"%s\"] \
loctext [\"EN\" \"CAP %s is set to automatic mode, \
cannot enter cartridges manually through ACSLS command enter.\"]]"

#define	LM_7214_MSG "message [id [\"IEEE\" \"1244\" \"7214\"] \
arguments [\"cap\" \"%s\" \"acsls\" \"%s\"] \
loctext [\"EN\" \"CAP %s is set to offline, ACSLS command %s cannot \
access CAP.\"]]"

#define	LM_7215_MSG "message [id [\"IEEE\" \"1244\" \"7215\"] \
arguments [\"cmd\" \"%s\" \"drive\" \"%s\" \"cart\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, drive %s is empty. \
Cartridge %s is marked as unusable.\"]]"

#define	LM_7216_MSG "message [id [\"IEEE\" \"1244\" \"7216\"] \
arguments [\"cmd\" \"%s\" \"%s\" \"acs\" \"%d\"] \
loctext [\"EN\" \"LMPM %s command failed, ACS %d is full.\"]]"

#define	LM_7217_MSG "message [id [\"IEEE\" \"1244\" \"7217\"] \
arguments [\"acs\" \"%d\"] \
loctext [\"EN\" \"ACS %d is not a valid ACS desinator on ACSLS server.\"]]"

#define	LM_7218_MSG "message [id [\"IEEE\" \"1244\" \"7218\"] \
arguments [\"lsm\" \"%d,%d\"] \
loctext [\"EN\" \"LSM %d,%d is not a valid LSM desinator on ACSLS server.\"]]"

#define	LM_7219_MSG "message [id [\"IEEE\" \"1244\" \"7219\"] \
arguments [\"drive\" \"%s\" \"geom\" \"%s\"] \
loctext [\"EN\" \"Drive %s was not found in ACSLS library. \
Drive's ACSLS geometry is %s.\"]]"

#define	LM_7220_MSG "message [id [\"IEEE\" \"1244\" \"7220\"] \
arguments [\"cart\" \"%s\" \"drive\" \"%s\" \"geom\" \"%s\"] \
loctext [\"EN\" \"Cartridge %s was not found in drive, drive %s is empty. \
Drive's ACSLS geometry is %s.\"]]"

#define	LM_7221_MSG "message [id [\"IEEE\" \"1244\" \"7221\"] \
arguments [\"acsls\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"Internal ACSLS communication problem on ACSLS server, \
ACSLS command %s received a %s from server.\"]]"

#define	LM_7222_MSG "message [id [\"IEEE\" \"1244\" \"7222\"] \
arguments [\"acsls\" \"%s\"] \
loctext [\"EN\" \"MMS does not have permission to perform ACSLS command %s, \
received a STATUS_COMMAND_ACCESS_DENIED from ACSLS server.\"]]"

#define	LM_7223_MSG "message [id [\"IEEE\" \"1244\" \"7223\"] \
arguments [\"wcart\" \"%s\" \"drive\" \"%s\" \"ecart\" \"%s\"] \
loctext [\"EN\" \"Cartridge %s was actually unmounted from drive %s, \
MMS expected cartridge %s to be in the drive.\"]]"

#define	LM_7225_MSG "message [id [\"IEEE\" \"1244\" \"7225\"] \
arguments [\"cmd\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, Communication error with ACSLS \
server, return status - %s.\"]]"

#define	LM_7226_MSG "message [id [\"IEEE\" \"1244\" \"7226\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, Communication error response from \
ACSLS command %s, return status - %s.\"]]"

#define	LM_7227_MSG "message [id [\"IEEE\" \"1244\" \"7227\"] \
arguments [\"cmd\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, Internal acsls processing error, \
return status - %s.\"]]"

#define	LM_7228_MSG "message [id [\"IEEE\" \"1244\" \"7228\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, Internal ACSLS processing error \
response from ACSLS command %s, return status - %s.\"]]"

#define	LM_7229_MSG "message [id [\"IEEE\" \"1244\" \"7229\"] \
arguments [\"cmd\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, Invalid ACSLS status returned, \
return status - %s.\"]]"

#define	LM_7230_MSG "message [id [\"IEEE\" \"1244\" \"7230\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, Invalid ACSLS response status from \
ACSLS command %s, return status - %s.\"]]"

#define	LM_7231_MSG "message [id [\"IEEE\" \"1244\" \"7231\"] \
loctext [\"EN\" \"LM exceeded threashold of RT_NONE ACSLS response packets, \
LM taken offline.\"]]"

#define	LM_7232_MSG "message [id [\"IEEE\" \"1244\" \"7232\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"status\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, ACSLS command %s received a non \
success response, return status - %s.\"]]"

#define	LM_7233_MSG "message [id [\"IEEE\" \"1244\" \"7233\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"type\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, ACSLS command %s received an \
unexpected return type of %s.\"]]"

#define	LM_7234_MSG "message [id [\"IEEE\" \"1244\" \"7234\"] \
arguments [\"cmd\" \"%s\" \"acsls\" \"%s\" \"state\" \"%s\"] \
loctext [\"EN\" \"LMPM %s command failed, ACSLS command %s received an \
unexpected state in acs_response(), state is %s.\"]]"

#define	LM_7235_MSG "message [id [\"IEEE\" \"1244\" \"7235\"] \
arguments [\"drive\" \"%s\"] \
loctext [\"EN\" \"%s has a missing/incomplete a drive geometry, \
drive will be temorarily disabled, \
offline/online this library and drive to clear \
the error state\"]]"

#ifdef	__cplusplus
}
#endif

#endif /* __LM_MSG_CAT_H */
