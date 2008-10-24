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

#ifndef __MMS_MM_MSG_H
#define	__MMS_MM_MSG_H


#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	MM_MSG
#define	MM_MSG(n, s)
#endif

/* MM Operator Messages 1000-1100 */

#define	MM_1000_MSG 1000
MM_MSG(MM_1000_MSG, gettext("operator attended reply message, don't reuse"))

#define	MM_1001_MSG 1001
MM_MSG(MM_1001_MSG, gettext("operator unattended reply message, don't reuse"))


/* MM Messages 5000-5999 */

#define	MM_5000_MSG 5000
MM_MSG(MM_5000_MSG, gettext("Parser error at line $line$, column $col$, " \
	"near token '$token$', error code $code$, $msg$"))

#define	MM_5001_MSG 5001
MM_MSG(MM_5001_MSG, gettext("$msg$"))

#define	MM_5004_MSG 5004
MM_MSG(MM_5004_MSG, gettext("No such CARTRIDGE.CartridgeID $cartid$."))

#define	MM_5005_MSG 5005
MM_MSG(MM_5005_MSG, gettext("No such CARTRIDGE.CartridgePCL $cartpcl$."))

#define	MM_5006_MSG 5006
MM_MSG(MM_5006_MSG,
	gettext("CARTRIDGE.CartridgeID $cartid$ is a mount candidate."))

#define	MM_5007_MSG 5007
MM_MSG(MM_5007_MSG, gettext("Only one library is allowed for the eject " \
	"command. CARTRIDGE.CartridgeID $cartid1$ is in LIBRARY $lib1$ and " \
	"one or more cartridges are in LIBRARY $lib2$."))

#define	MM_5008_MSG 5008
MM_MSG(MM_5008_MSG, gettext("LIBRARY $lib$ doesn't have a configured LM."))

#define	MM_5009_MSG 5009
MM_MSG(MM_5009_MSG, gettext("LIBRARY $lib$ has more than one LM configured."))

#define	MM_5010_MSG 5010
MM_MSG(MM_5010_MSG,
	gettext("SLOT not found for CARTRIDGE.CartridgeID $cartid$."))

#define	MM_5011_MSG 5011
MM_MSG(MM_5011_MSG, gettext("CARTRIDGE.CartridgeID $cartid$ not in SLOT."))

#define	MM_5013_MSG 5013
MM_MSG(MM_5013_MSG, gettext("Ready for client connections."))

#define	MM_5018_MSG 5018
MM_MSG(MM_5018_MSG, gettext("Error Mounting $cartridge$ in $drive$, " \
	"LM error message: $msg_rsp$"))

#define	MM_5019_MSG 5019
MM_MSG(MM_5019_MSG,
	gettext("No error message associated with this class/token"))

#define	MM_5021_MSG 5021
MM_MSG(MM_5021_MSG, gettext("unrecoverable system error, $text$"))

#define	MM_5022_MSG 5022
MM_MSG(MM_5022_MSG, gettext("Drive, $drive$ is temporarily disabled"))

#define	MM_5023_MSG 5023
MM_MSG(MM_5023_MSG, gettext("Drive, $drive$ is permanently disabled"))

#define	MM_5024_MSG 5024
MM_MSG(MM_5024_MSG, gettext("Drive, $drive$ is broken"))

#define	MM_5025_MSG 5025
MM_MSG(MM_5025_MSG, gettext("Drive, $drive$ is not ready, try again later"))

#define	MM_5026_MSG 5026
MM_MSG(MM_5026_MSG,
	gettext("Drive, $drive$ is not accessible from the library"))

#define	MM_5027_MSG 5027
MM_MSG(MM_5027_MSG, gettext("Application $app$ is not the exclusive app " \
	"for drive $drive$."))

#define	MM_5028_MSG 5028
MM_MSG(MM_5028_MSG, gettext("Drive $drive$ is loaded with non-MMS tape."))

#define	MM_5029_MSG 5029
MM_MSG(MM_5029_MSG, gettext("Drive $drive$ is offline."))

#define	MM_5030_MSG 5030
MM_MSG(MM_5030_MSG,
	gettext("Application $app$ does not have access to drive $drive$."))

#define	MM_5031_MSG 5031
MM_MSG(MM_5031_MSG,
	gettext("Drive $drive$ reported as not ready by DM $dm$."))

#define	MM_5032_MSG 5032
MM_MSG(MM_5032_MSG,
	gettext("DM $dm$ for drive $drive$ is not connected to MM."))

#define	MM_5033_MSG 5033
MM_MSG(MM_5033_MSG, gettext("DM $dm$ for drive $drive$ is not connected."))

#define	MM_5034_MSG 5034
MM_MSG(MM_5034_MSG,
	gettext("DM $dm$ for drive $drive$ is currently configuring."))

#define	MM_5035_MSG 5035
MM_MSG(MM_5035_MSG, gettext("DM $dm$ for drive $drive$ is not, " \
	"configured yet, DM may need to be activated."))

#define	MM_5036_MSG 5036
MM_MSG(MM_5036_MSG, gettext("DM $dm$ for drive $drive$ does not support the " \
	"accessmode contained in the accessmode clause."))

#define	MM_5037_MSG 5037
MM_MSG(MM_5037_MSG, gettext("Cartridge $cart$ has not been located in " \
	"the library, if this cartridge has been injected try cpscan."))

#define	MM_5038_MSG 5038
MM_MSG(MM_5038_MSG, gettext("Cartridge $cart$ is currently being used by " \
	"another client"))

#define	MM_5040_MSG 5040
MM_MSG(MM_5040_MSG, gettext("Application $app$ does not have any volumes " \
	"allocated on cartridge $cart$."))

#define	MM_5041_MSG 5041
MM_MSG(MM_5041_MSG, gettext("Library $lib$ is currently offline."))

#define	MM_5042_MSG 5042
MM_MSG(MM_5042_MSG, gettext("Library $lib$ is temporarily disabled."))

#define	MM_5043_MSG 5043
MM_MSG(MM_5043_MSG, gettext("Library $lib$ is permanently disabled."))

#define	MM_5044_MSG 5044
MM_MSG(MM_5044_MSG, gettext("Library $lib$ is broken."))

#define	MM_5045_MSG 5045
MM_MSG(MM_5045_MSG, gettext("LM $lm$ reports the device state as not ready."))

#define	MM_5046_MSG 5046
MM_MSG(MM_5046_MSG,
	gettext("LM $lm$ for library $lib$ is not connected to MM."))

#define	MM_5047_MSG 5047
MM_MSG(MM_5047_MSG, gettext("LM $lm$ for library $lib$ is not activated."))

#define	MM_5048_MSG 5048
MM_MSG(MM_5048_MSG, gettext("LM $lm$ is not connected to library $lib$."))

#define	MM_5049_MSG 5049
MM_MSG(MM_5049_MSG,
	gettext("LM $lm$ for library $lib$ is currently configuring."))

#define	MM_5050_MSG 5050
MM_MSG(MM_5050_MSG, gettext("No DM configured on host $host$."))

#define	MM_5051_MSG 5051
MM_MSG(MM_5051_MSG,
	gettext("Mount type must be one of: SIDE, PARTITION or VOLUME."))

#define	MM_5052_MSG 5052
MM_MSG(MM_5052_MSG, gettext("Could not find any candidate cartridges, " \
	"check match statement and application-cartridge access."))

#define	MM_5053_MSG 5053
MM_MSG(MM_5053_MSG, gettext("Error loading cartridge $cartridge$ in " \
	"drive $drive$, DM error message: $msg_rsp$"))

#define	MM_5054_MSG 5054
MM_MSG(MM_5054_MSG, gettext("Error attaching to handle, cartridge " \
	"$cartridge$ in drive $drive$, DM error message: $msg_rsp$"))

#define	MM_5055_MSG 5055
MM_MSG(MM_5055_MSG, gettext("Device manager communication error, " \
	"LM/DM error message: $msg_rsp$"))

#define	MM_5057_MSG 5057
MM_MSG(MM_5057_MSG, gettext("Library command cannot have both an online " \
	"and offline clause."))

#define	MM_5058_MSG 5058
MM_MSG(MM_5058_MSG, gettext("No matching library exists."))

#define	MM_5059_MSG 5059
MM_MSG(MM_5059_MSG, gettext("Library $lib$ is already online."))

#define	MM_5060_MSG 5060
MM_MSG(MM_5060_MSG, gettext("No matching LM exists."))

#define	MM_5061_MSG 5061
MM_MSG(MM_5061_MSG, gettext("Library $lib$ is already offline."))

#define	MM_5062_MSG 5062
MM_MSG(MM_5062_MSG, gettext("Could not find clause/keyword in command."))

#define	MM_5063_MSG 5063
MM_MSG(MM_5063_MSG, gettext("No matching drive exists."))

#define	MM_5064_MSG 5064
MM_MSG(MM_5064_MSG, gettext("Drive $drive$ is already online."))

#define	MM_5065_MSG 5065
MM_MSG(MM_5065_MSG, gettext("Drive $drive$ has a cartridge mounted."))

#define	MM_5066_MSG 5066
MM_MSG(MM_5066_MSG, gettext("Drive $drive$ is already online."))

#define	MM_5067_MSG 5067
MM_MSG(MM_5067_MSG, gettext("Clause is missing a required argument, $text$"))

#define	MM_5068_MSG 5068
MM_MSG(MM_5068_MSG, gettext("No matching cartridge found for eject."))

#define	MM_5069_MSG 5069
MM_MSG(MM_5069_MSG, gettext("No matching cartridge exists."))

#define	MM_5070_MSG 5070
MM_MSG(MM_5070_MSG, gettext("Too many matching cartridge found."))

#define	MM_5071_MSG 5071
MM_MSG(MM_5071_MSG, gettext("Couldn't find PCL $pcl$ in library."))

#define	MM_5072_MSG 5072
MM_MSG(MM_5072_MSG, gettext("No LM configured for library $lib$."))

#define	MM_5073_MSG 5073
MM_MSG(MM_5073_MSG, gettext("LM $lm$ is not in a ready state."))

#define	MM_5074_MSG 5074
MM_MSG(MM_5074_MSG, gettext("No DM configured."))

#define	MM_5075_MSG 5075
MM_MSG(MM_5075_MSG, gettext("No LM configured."))

#define	MM_5076_MSG 5076
MM_MSG(MM_5076_MSG,
	gettext("Match statement matched more than one device manager."))

#define	MM_5077_MSG 5077
MM_MSG(MM_5077_MSG, gettext("DM $dm$ not connected to MM."))

#define	MM_5078_MSG 5078
MM_MSG(MM_5078_MSG, gettext("LM $lm$ not connected to MM."))

#define	MM_5079_MSG 5079
MM_MSG(MM_5079_MSG, gettext("Couldn't match any current device managers."))

#define	MM_5080_MSG 5080
MM_MSG(MM_5080_MSG,
	gettext("Couldn't use match clause to find any configured LMs."))

#define	MM_5082_MSG 5082
MM_MSG(MM_5082_MSG,
	gettext("Standard privilege client may not use the 'who' clause."))

#define	MM_5083_MSG 5083
MM_MSG(MM_5083_MSG, gettext("Syntax error found parsing the range clause."))

#define	MM_5084_MSG 5084
MM_MSG(MM_5084_MSG, gettext("Error counting new volumns in range."))

#define	MM_5085_MSG 5085
MM_MSG(MM_5085_MSG, gettext("Not enough partitions exist."))

#define	MM_5086_MSG 5086
MM_MSG(MM_5086_MSG,
	gettext("Creation of PARTITION requires an existing CartridgePCL."))

#define	MM_5087_MSG 5087
MM_MSG(MM_5087_MSG,
	gettext("Creation of PARTITION requires an existing LibraryName."))

#define	MM_5088_MSG 5088
MM_MSG(MM_5088_MSG, gettext("Client $client$ does not have cartridge " \
	"group access to PCL $pcl$."))

#define	MM_5089_MSG 5089
MM_MSG(MM_5089_MSG, gettext("Failed to change request state."))

#define	MM_5090_MSG 5090
MM_MSG(MM_5090_MSG, gettext("No matching task found."))

#define	MM_5091_MSG 5091
MM_MSG(MM_5091_MSG, gettext("More than one matching task found."))

#define	MM_5092_MSG 5092
MM_MSG(MM_5092_MSG, gettext("Match returned no results."))

#define	MM_5093_MSG 5093
MM_MSG(MM_5093_MSG, gettext("No matching request found."))

#define	MM_5094_MSG 5094
MM_MSG(MM_5094_MSG, gettext("No drives found for library $lib$."))

#define	MM_5095_MSG 5095
MM_MSG(MM_5095_MSG, gettext("No slot found for cartridge $cart$."))

#define	MM_5096_MSG 5096
MM_MSG(MM_5096_MSG, gettext("Drive $drive$ does not support the shape of " \
	"cartridge $cart$."))

#define	MM_5097_MSG 5097
MM_MSG(MM_5097_MSG, gettext("Drive does not support the cartridge type."))

#define	MM_5098_MSG 5098
MM_MSG(MM_5098_MSG, gettext("DM is still reserved, another client may be " \
	"writing to this tape with DM $dm$."))

#define	MM_5099_MSG 5099
MM_MSG(MM_5099_MSG, gettext("Failed to change $info$."))

#define	MM_5100_MSG 5100
MM_MSG(MM_5100_MSG, gettext("Client not connected."))

#define	MM_5102_MSG 5102
MM_MSG(MM_5102_MSG,
	gettext("Drive $drive$ is currently unloading/loading, retry."))

#define	MM_5103_MSG 5103
MM_MSG(MM_5103_MSG, gettext("DM $dm$ does not support mount point."))

#define	MM_5104_MSG 5104
MM_MSG(MM_5104_MSG, gettext("Requested resources are temporarily unavailable."))

#define	MM_5105_MSG 5105
MM_MSG(MM_5105_MSG, gettext("No valid cartridge/library/drive found."))

#define	MM_5106_MSG 5106
MM_MSG(MM_5106_MSG, gettext("Old password does not match existing password."))

#define	MM_5107_MSG 5107
MM_MSG(MM_5107_MSG,
	gettext("Unable to update hello command password file $file$."))

#define	MM_5108_MSG 5108
MM_MSG(MM_5108_MSG, gettext("Standard privilege client may not modify " \
	"object $object$ attribute $attribute$."))

#define	MM_5109_MSG 5109
MM_MSG(MM_5109_MSG, gettext("Administrator privilege client may not modify " \
	"object $object$ attribute $attribute$."))

#define	MM_5110_MSG 5110
MM_MSG(MM_5110_MSG, gettext("No solutions to this begin-end group, " \
	"one or more mounts cannot complete - $err_text$"))

#ifdef	__cplusplus
}
#endif

#endif	/* __MMS_MM_MSG_H */
