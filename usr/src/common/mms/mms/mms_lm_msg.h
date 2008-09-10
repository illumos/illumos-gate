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

#ifndef __MMS_LM_MSG_H
#define	__MMS_LM_MSG_H


#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	LM_MSG
#define	LM_MSG(n, s)
#endif

/* LM Messages 7000-7999 */

#define	LM_7000_MSG 7000
LM_MSG(LM_7000_MSG,
	gettext("LM was unable to obtain task id from $cmd$ command."))

#define	LM_7001_MSG 7001
LM_MSG(LM_7001_MSG, gettext("Current state of LM does not allow processing " \
	"a $cmd$ command."))

#define	LM_7002_MSG 7002
LM_MSG(LM_7002_MSG, gettext("LM received an invalid command - $cmd$."))

#define	LM_7003_MSG 7003
LM_MSG(LM_7003_MSG, gettext("LM received a $cmd$ command after being told " \
	"to shutdown, command aborted."))

#define	LM_7004_MSG 7004
LM_MSG(LM_7004_MSG, gettext("Internal processing error occurred while " \
	"processing LMPM $cmd$ command."))

#define	LM_7005_MSG 7005
LM_MSG(LM_7005_MSG,
	gettext("Last LMPM $cmd$ command sent to LM contained a syntax error."))

#define	LM_7006_MSG 7006
LM_MSG(LM_7006_MSG,
	gettext("LM received a signal to shutdown, exit code - $ecode$."))

#define	LM_7007_MSG 7007
LM_MSG(LM_7007_MSG,
	gettext("LM is shutting down due to an internal processing error."))

#define	LM_7009_MSG 7009
LM_MSG(LM_7009_MSG, gettext("LMPM $cmd$ command has invalid or missing " \
	"arguments in area of $part$."))

#define	LM_7010_MSG 7010
LM_MSG(LM_7010_MSG, gettext("LMPM private command contains a unsupported " \
	"$type$-name of $name$."))

#define	LM_7011_MSG 7011
LM_MSG(LM_7011_MSG, gettext("LMPM private command's set-name $name$ has " \
	"a illegal set-value of $value$."))

#define	LM_7013_MSG 7013
LM_MSG(LM_7013_MSG, gettext("LM state is changing to $state$."))

#define	LM_7014_MSG 7014
LM_MSG(LM_7014_MSG, gettext("LM is active."))

#define	LM_7015_MSG 7015
LM_MSG(LM_7015_MSG, gettext("LM is deactivated."))

#define	LM_7016_MSG 7016
LM_MSG(LM_7016_MSG, gettext("LM is exiting."))

#define	LM_7017_MSG 7017
LM_MSG(LM_7017_MSG, gettext("LM is resetting."))

#define	LM_7018_MSG 7018
LM_MSG(LM_7018_MSG,
	gettext("The library object $object$ or its value is missing."))

#define	LM_7020_MSG 7020
LM_MSG(LM_7020_MSG, gettext("Loading a $type$ library module of connection " \
	"type $conn$ failed."))

#define	LM_7021_MSG 7021
LM_MSG(LM_7021_MSG, gettext("LM is shutting down due to watcher going away."))

#define	LM_7022_MSG 7022
LM_MSG(LM_7022_MSG, gettext("LM completed partial reset."))

#define	LM_7023_MSG 7023
LM_MSG(LM_7023_MSG, gettext("LM encountered a lmpm_parser syntax error " \
	"on last LMPL response from MM."))

#define	LM_7024_MSG 7024
LM_MSG(LM_7024_MSG, gettext("LM encountered a lmpm_parser syntax error on " \
	"last input from MM, unable to determine if LMPM command or LMPL " \
	"response."))

#define	LM_7025_MSG 7025
LM_MSG(LM_7025_MSG, gettext("LM encountered a lmpm_parser no memory error."))

#define	LM_7026_MSG 7026
LM_MSG(LM_7026_MSG,
	gettext("LM encountered a unrecoverable lmpm_parser error."))

#define	LM_7027_MSG 7027
LM_MSG(LM_7027_MSG, gettext("LMPM $cmd$ command is being aborted due to the " \
	"LM going inactive or being shutdown."))

#define	LM_7030_MSG 7030
LM_MSG(LM_7030_MSG, gettext("During processing of LMPM $cmd$ command, " \
	"LMPL $lmpl$ command received a $rsp$ response from MM."))

#define	LM_7032_MSG 7032
LM_MSG(LM_7032_MSG, gettext("During processing of LMPM $cmd$ command, " \
	"LMPL show command was not able to obtain serial number for " \
	"drive $drive$."))

#define	LM_7033_MSG 7033
LM_MSG(LM_7033_MSG, gettext("During activation of library, Library is " \
	"configured in MMS as type $type$, ACSLS says library is " \
	"type $a_type$."))

#define	LM_7101_MSG 7101
LM_MSG(LM_7101_MSG, gettext("LMPM $cmd$ command completed successfully."))

#define	LM_7102_MSG 7102
LM_MSG(LM_7102_MSG, gettext("Cartridge $cart$ is mounted in drive $drive$."))

#define	LM_7103_MSG 7103
LM_MSG(LM_7103_MSG, gettext("Cartridge $cart$ unmounted from drive $drive$."))

#define	LM_7105_MSG 7105
LM_MSG(LM_7105_MSG,
	gettext("LMPM $cmd$ command is a NOP for a $type$ library."))

#define	LM_7106_MSG 7106
LM_MSG(LM_7106_MSG, gettext("Cartridge(s) $cart$ injected into library."))

#define	LM_7107_MSG 7107
LM_MSG(LM_7107_MSG, gettext("Cartridge(s) $cart$ ejected from library."))

#define	LM_7108_MSG 7108
LM_MSG(LM_7108_MSG, gettext("Port $port$ is a valid ACSLS CAP designation; " \
	"however, it is not physically configured."))

#define	LM_7109_MSG 7109
LM_MSG(LM_7109_MSG, gettext("There were cartridges in CAP, but none were " \
	"injected into library."))

#define	LM_7110_MSG 7110
LM_MSG(LM_7110_MSG,
	gettext("Cartridge(s) $cart$ were not injected into library."))

#define	LM_7111_MSG 7111
LM_MSG(LM_7111_MSG, gettext("Cartridge(s) $cart$ were injected into " \
	"library; however, unable to locate a slot location."))

#define	LM_7112_MSG 7112
LM_MSG(LM_7112_MSG,
	gettext("CAP was empty, No cartridges injected into library."))

#define	LM_7113_MSG 7113
LM_MSG(LM_7113_MSG, gettext("Too many cartridges specified to be ejected " \
	"from library, max CAP size is $num$."))

#define	LM_7114_MSG 7114
LM_MSG(LM_7114_MSG,
	gettext("Cartridge(s) $cart$ were not ejected from library."))

#define	LM_7115_MSG 7115
LM_MSG(LM_7115_MSG, gettext("No cartridges ejected from library."))

#define	LM_7116_MSG 7116
LM_MSG(LM_7116_MSG, gettext("LMPM scan command does not support the " \
	"fromslot and toslot format for $type$ libraries."))

#define	LM_7117_MSG 7117
LM_MSG(LM_7117_MSG,
	gettext("Port $port$ is not a valid ACSLS CAP designation."))

#define	LM_7118_MSG 7118
LM_MSG(LM_7118_MSG, gettext("Scan for cartridges $carts$ found cartridges " \
	"in slots of library."))

#define	LM_7119_MSG 7119
LM_MSG(LM_7119_MSG, gettext("Scan for cartridges $carts$ did not find " \
	"cartridges in slots of library."))

#define	LM_7120_MSG 7120
LM_MSG(LM_7120_MSG, gettext("Scan for cartridges did not find any " \
	"cartridges in slots of library."))

#define	LM_7121_MSG 7121
LM_MSG(LM_7121_MSG,
	gettext("Scan of drive(s) with geometries $geom$ completed"))

#define	LM_7122_MSG 7122
LM_MSG(LM_7122_MSG, gettext("Scan for drives(s) did not find any in library."))

#define	LM_7123_MSG 7123
LM_MSG(LM_7123_MSG, gettext("Scan for drive(s) with geometries $geom$ were " \
	"not found in library."))

#define	LM_7124_MSG 7124
LM_MSG(LM_7124_MSG, gettext("Scan of entire library completed."))

#define	LM_7125_MSG 7125
LM_MSG(LM_7125_MSG, gettext("Scan of drive(s) $list$ completed."))

#define	LM_7126_MSG 7126
LM_MSG(LM_7126_MSG, gettext("No ACSLS geometry found for drive $name$, " \
	"serial number - $serial$."))

#define	LM_7200_MSG 7200
LM_MSG(LM_7200_MSG, gettext("LMPM $cmd$ command failed, ACSLS command " \
	"$acsls$ returned a status of STATUS_LIBRARY_NOT_AVAILABLE, " \
	"state of ACSLS server - $state$."))

#define	LM_7201_MSG 7201
LM_MSG(LM_7201_MSG, gettext("LMPM $cmd$ command failed, ACSLS command " \
	"$acsls$ returned a status of STATUS_LIBRARY_NOT_AVAILABLE, " \
	"state of ACSLS server is non-determinable."))

#define	LM_7202_MSG 7202
LM_MSG(LM_7202_MSG, gettext("Received a STATUS_LIBRARY_NOT_AVAILABLE " \
	"from ACSLS server, state of server - \"state\", LM state being " \
	"switched to broken."))

#define	LM_7203_MSG 7203
LM_MSG(LM_7203_MSG, gettext("Communication problem with ACSLS server, " \
	"status returned from server - $status$, LM state being switched " \
	"to disconnected."))

#define	LM_7204_MSG 7204
LM_MSG(LM_7204_MSG, gettext("Library is currently performing an audit, " \
	"please retry LMPM $cmd$ command."))

#define	LM_7205_MSG 7205
LM_MSG(LM_7205_MSG, gettext("LMPM $cmd$ command failed, MMS does not have " \
	"permission to perform ACSLS command $acsls$."))

#define	LM_7206_MSG 7206
LM_MSG(LM_7206_MSG, gettext("Received a STATUS_LIBRARY_NOT_AVAILABLE from " \
	"ACSLS server, state of server is non-determinable, LM state being " \
	"switched to broken."))

#define	LM_7207_MSG 7207
LM_MSG(LM_7207_MSG, gettext("Internal problem with ACSLS server, received " \
	"a $status$ from server for ACSLS command $acsls$, LM state being " \
	"switched to broken."))

#define	LM_7208_MSG 7208
LM_MSG(LM_7208_MSG, gettext("LMPM $cmd$ command failed, ACSLS command " \
	"$acsls$ returned a status of $status$."))

#define	LM_7209_MSG 7209
LM_MSG(LM_7209_MSG, gettext("Library component failure, received a " \
	"STATUS_LIBRARY_FAILURE from ACSLS server for ACSLS command $acsls$."))

#define	LM_7210_MSG 7210
LM_MSG(LM_7210_MSG, gettext("Drive $drive$ is not accessible, drive state " \
	"is set to offline. Drive's ACSLS geometry is $geom$."))

#define	LM_7211_MSG 7211
LM_MSG(LM_7211_MSG, gettext("LSM $lsm$ is set to offline."))

#define	LM_7212_MSG 7212
LM_MSG(LM_7212_MSG, gettext("CAP $cap$ is busy, try again."))

#define	LM_7213_MSG 7213
LM_MSG(LM_7213_MSG, gettext("CAP $cap$ is set to automatic mode, cannot " \
	"enter cartridges manually through ACSLS command enter."))

#define	LM_7214_MSG 7214
LM_MSG(LM_7214_MSG, gettext("CAP $cap$ is set to offline, ACSLS command " \
	"$acsls$ cannot access CAP."))

#define	LM_7215_MSG 7215
LM_MSG(LM_7215_MSG, gettext("LMPM $cmd$ command failed, drive $drive$ " \
	"is empty. Cartridge $cart$ is marked as unusable."))

#define	LM_7216_MSG 7216
LM_MSG(LM_7216_MSG, gettext("LMPM $cmd$ command failed, ACS $acs$ is full."))

#define	LM_7217_MSG 7217
LM_MSG(LM_7217_MSG,
	gettext("ACS $acs$ is not a valid ACS designation on ACSLS server."))

#define	LM_7218_MSG 7218
LM_MSG(LM_7218_MSG,
	gettext("LSM $lsm$ is not a valid LSM designation on ACSLS server."))

#define	LM_7219_MSG 7219
LM_MSG(LM_7219_MSG, gettext("Drive $drive$ was not found in ACSLS library. " \
	"Drive's ACSLS geometry is $geom$."))

#define	LM_7220_MSG 7220
LM_MSG(LM_7220_MSG, gettext("Cartridge $cart$ was not found in drive, " \
	"drive $drive$ is empty. Drive's ACSLS geometry is $geom$."))

#define	LM_7221_MSG 7221
LM_MSG(LM_7221_MSG, gettext("Internal ACSLS communication problem on ACSLS " \
	"server, ACSLS command $acsls$ received a $status$ from server."))

#define	LM_7222_MSG 7222
LM_MSG(LM_7222_MSG, gettext("MMS does not have permission to perform ACSLS " \
	"command $acsls$, received a STATUS_COMMAND_ACCESS_DENIED from " \
	"ACSLS server."))

#define	LM_7223_MSG 7223
LM_MSG(LM_7223_MSG, gettext("Cartridge $wcart$ was actually unmounted from " \
	"drive $drive$, MMS expected cartridge $ecart$ to be in the drive."))

#define	LM_7225_MSG 7225
LM_MSG(LM_7225_MSG, gettext("LMPM $cmd$ command failed, Communication error " \
	"with ACSLS server, return status - $status$."))

#define	LM_7226_MSG 7226
LM_MSG(LM_7226_MSG, gettext("LMPM $cmd$ command failed, Communication error " \
	"response from ACSLS command $acsls$, return status - $status$."))

#define	LM_7227_MSG 7227
LM_MSG(LM_7227_MSG, gettext("LMPM $cmd$ command failed, Internal acsls " \
	"processing error, return status - $status$."))

#define	LM_7228_MSG 7228
LM_MSG(LM_7228_MSG, gettext("LMPM $cmd$ command failed, Internal ACSLS " \
	"processing error response from ACSLS command $acsls$, return " \
	"status - $status$."))

#define	LM_7229_MSG 7229
LM_MSG(LM_7229_MSG, gettext("LMPM $cmd$ command failed, Invalid ACSLS " \
	"status returned, return status - $status$."))

#define	LM_7230_MSG 7230
LM_MSG(LM_7230_MSG, gettext("LMPM $cmd$ command failed, Invalid ACSLS " \
	"response status from ACSLS command $acsls$, return " \
	"status - $status$."))

#define	LM_7232_MSG 7232
LM_MSG(LM_7232_MSG, gettext("LMPM $cmd$ command failed, ACSLS command " \
	"$acsls$ received a non-success response, return status - $status$."))

#define	LM_7233_MSG 7233
LM_MSG(LM_7233_MSG, gettext("LMPM $cmd$ command failed, ACSLS command " \
	"$acsls$ received an unexpected return type of $type$."))

#define	LM_7234_MSG 7234
LM_MSG(LM_7234_MSG, gettext("LMPM $cmd$ command failed, ACSLS command " \
	"$acsls$ received an unexpected state in acs_response(), " \
	"state is $state$."))

#define	LM_7235_MSG 7235
LM_MSG(LM_7235_MSG, gettext("$drive$ has a missing/incomplete drive " \
	"geometry, drive will be temporarily disabled, offline/online this " \
	"library and drive to clear the error state"))

#ifdef	__cplusplus
}
#endif

#endif /* __MMS_LM_MSG_H */
