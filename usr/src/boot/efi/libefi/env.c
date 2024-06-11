/*
 * Copyright (c) 2015 Netflix, Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <stand.h>
#include <string.h>
#include <efi.h>
#include <efichar.h>
#include <efilib.h>
#include <eficonsctl.h>
#include <Guid/Acpi.h>
#include <Guid/ConsoleInDevice.h>
#include <Guid/ConsoleOutDevice.h>
#include <Guid/DebugImageInfoTable.h>
#include <Guid/DxeServices.h>
#include <Guid/Fdt.h>
#include <Guid/GlobalVariable.h>
#include <Guid/Gpt.h>
#include <Guid/HobList.h>
#include <Guid/MemoryTypeInformation.h>
#include <Guid/Mps.h>
#include <Guid/MtcVendor.h>
#include <Guid/SmBios.h>
#include <Guid/StandardErrorDevice.h>
#include <Guid/ZeroGuid.h>
#include <Pi/PiStatusCode.h>
#include <Protocol/AbsolutePointer.h>
#include <Protocol/AdapterInformation.h>
#include <Protocol/Arp.h>
#include <Protocol/AtaPassThru.h>
#include <Protocol/Bds.h>
#include <Protocol/BlockIo.h>
#include <Protocol/BlockIo2.h>
#include <Protocol/BusSpecificDriverOverride.h>
#include <Protocol/Capsule.h>
#include <Protocol/ComponentName.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/Cpu.h>
#include <Protocol/CpuIo2.h>
#include <Protocol/DataHub.h>
#include <Protocol/Decompress.h>
#include <Protocol/DeviceIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/DevicePathFromText.h>
#include <Protocol/DevicePathToText.h>
#include <Protocol/DevicePathUtilities.h>
#include <Protocol/Dhcp4.h>
#include <Protocol/Dhcp6.h>
#include <Protocol/DiskInfo.h>
#include <Protocol/DiskIo.h>
#include <Protocol/DiskIo2.h>
#include <Protocol/Dpc.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/DriverConfiguration.h>
#include <Protocol/DriverConfiguration2.h>
#include <Protocol/DriverDiagnostics.h>
#include <Protocol/DriverDiagnostics2.h>
#include <Protocol/DriverFamilyOverride.h>
#include <Protocol/DriverHealth.h>
#include <Protocol/DriverSupportedEfiVersion.h>
#include <Protocol/Ebc.h>
#include <Protocol/EdidActive.h>
#include <Protocol/EdidDiscovered.h>
#include <Pi/PiFirmwareVolume.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <Uefi/UefiInternalFormRepresentation.h>
#include <Protocol/FormBrowser2.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/HiiConfigKeyword.h>
#include <Protocol/HiiConfigRouting.h>
#include <Protocol/HiiFont.h>
#include <Protocol/HiiImage.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/HiiString.h>
#include <Protocol/IdeControllerInit.h>
#include <Protocol/Ip4.h>
#include <Protocol/Ip4Config.h>
#include <Protocol/Ip4Config2.h>
#include <Protocol/Ip6.h>
#include <Protocol/Ip6Config.h>
#include <Protocol/IpSec.h>
#include <Protocol/IpSecConfig.h>
#include <Protocol/IsaAcpi.h>
#include <Protocol/IsaIo.h>
#include <Protocol/Kms.h>
#include <Protocol/Legacy8259.h>
#include <Protocol/LoadFile.h>
#include <Protocol/LoadFile2.h>
#include <Protocol/Metronome.h>
#include <Protocol/MonotonicCounter.h>
#include <Pi/PiMultiPhase.h>
#include <Protocol/MpService.h>
#include <Protocol/Mtftp4.h>
#include <Protocol/Mtftp6.h>
#include <Protocol/NetworkInterfaceIdentifier.h>
#include <Protocol/NvmExpressPassthru.h>
#include <Protocol/PciIo.h>
#include <Protocol/Pcd.h>
#include <Protocol/PciEnumerationComplete.h>
#include <Protocol/PciRootBridgeIo.h>
#include <Protocol/PiPcd.h>
#include <Protocol/PlatformDriverOverride.h>
#include <Protocol/PlatformToDriverConfiguration.h>
#include <Protocol/Print2.h>
#include <Protocol/PxeBaseCode.h>
#include <Protocol/PxeBaseCodeCallBack.h>
#include <Protocol/RealTimeClock.h>
#include <Protocol/ReportStatusCodeHandler.h>
#include <Protocol/Reset.h>
#include <Protocol/Rng.h>
#include <Protocol/Runtime.h>
#include <Protocol/ScsiIo.h>
#include <Protocol/ScsiPassThru.h>
#include <Protocol/ScsiPassThruExt.h>
#include <Protocol/Security.h>
#include <Protocol/Security2.h>
#include <Protocol/SecurityPolicy.h>
#include <Protocol/SerialIo.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/SimplePointer.h>
#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextInEx.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/SmartCardReader.h>
#include <Protocol/StatusCode.h>
#include <Protocol/StorageSecurityCommand.h>
#include <Protocol/Tcg2Protocol.h>
#include <Protocol/Tcp4.h>
#include <Protocol/Tcp6.h>
#include <Protocol/Timer.h>
#include <Protocol/Udp4.h>
#include <Protocol/Udp6.h>
#include <Protocol/UgaDraw.h>
#include <Protocol/UgaIo.h>
#include <Protocol/UnicodeCollation.h>
#include <Protocol/UsbIo.h>
#include <Protocol/Usb2HostController.h>
#include <Protocol/Variable.h>
#include <Protocol/VariableWrite.h>
#include <Protocol/VlanConfig.h>
#include <Protocol/WatchdogTimer.h>
#include <Protocol/IsaAcpi.h>
#include <Protocol/IsaIo.h>
#include <Protocol/SerialIo.h>
#include <Protocol/SuperIo.h>
#include <uuid.h>
#include <stdbool.h>
#include <sys/param.h>
#include "bootstrap.h"
#include "ficl.h"

/*
 * About ENABLE_UPDATES
 *
 * The UEFI variables are identified only by GUID and name, there is no
 * way to (auto)detect the type for the value, so we need to process the
 * variables case by case, as we do learn about them.
 *
 * While showing the variable name and the value is safe, we must not store
 * random values nor allow removing (random) variables.
 *
 * Since we do have stub code to set/unset the variables, I do want to keep
 * it to make the future development a bit easier, but the updates are disabled
 * by default till:
 *	a) the validation and data translation to values is properly implemented
 *	b) We have established which variables we do allow to be updated.
 * Therefore the set/unset code is included only for developers aid.
 */

/* If GUID is not defined elsewhere, define it here. */
EFI_GUID gEfiAbsolutePointerProtocolGuid = EFI_ABSOLUTE_POINTER_PROTOCOL_GUID;
EFI_GUID gEfiAdapterInformationProtocolGuid =
    EFI_ADAPTER_INFORMATION_PROTOCOL_GUID;
EFI_GUID gEfiAtaPassThruProtocolGuid = EFI_ATA_PASS_THRU_PROTOCOL_GUID;
EFI_GUID gEfiBdsArchProtocolGuid = EFI_BDS_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiBusSpecificDriverOverrideProtocolGuid =
    EFI_BUS_SPECIFIC_DRIVER_OVERRIDE_PROTOCOL_GUID;
EFI_GUID gEfiCapsuleArchProtocolGuid = EFI_CAPSULE_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiComponentNameProtocolGuid = EFI_COMPONENT_NAME_PROTOCOL_GUID;
EFI_GUID gEfiComponentName2ProtocolGuid = EFI_COMPONENT_NAME2_PROTOCOL_GUID;
EFI_GUID gEfiCpuArchProtocolGuid = EFI_CPU_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiCpuIo2ProtocolGuid = EFI_CPU_IO2_PROTOCOL_GUID;
EFI_GUID gEfiDataHubProtocolGuid = EFI_DATA_HUB_PROTOCOL_GUID;
EFI_GUID gEfiDebugImageInfoTableGuid = EFI_DEBUG_IMAGE_INFO_TABLE_GUID;
EFI_GUID gEfiDecompressProtocolGuid = EFI_DECOMPRESS_PROTOCOL_GUID;
EFI_GUID gEfiDeviceIoProtocolGuid = EFI_DEVICE_IO_PROTOCOL_GUID;
EFI_GUID gEfiDhcp4ProtocolGuid = EFI_DHCP4_PROTOCOL_GUID;
EFI_GUID gEfiDhcp4ServiceBindingProtocolGuid =
    EFI_DHCP6_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiDhcp6ProtocolGuid = EFI_DHCP4_PROTOCOL_GUID;
EFI_GUID gEfiDhcp6ServiceBindingProtocolGuid =
    EFI_DHCP6_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiDiskInfoProtocolGuid = EFI_DISK_INFO_PROTOCOL_GUID;
EFI_GUID gEfiDiskIoProtocolGuid = EFI_DISK_IO_PROTOCOL_GUID;
EFI_GUID gEfiDiskIo2ProtocolGuid = EFI_DISK_IO2_PROTOCOL_GUID;
EFI_GUID gEfiDpcProtocolGuid = EFI_DPC_PROTOCOL_GUID;
EFI_GUID gEfiDriverConfigurationProtocolGuid =
    EFI_DRIVER_CONFIGURATION_PROTOCOL_GUID;
EFI_GUID gEfiDriverConfiguration2ProtocolGuid =
    EFI_DRIVER_CONFIGURATION2_PROTOCOL_GUID;
EFI_GUID gEfiDriverDiagnosticsProtocolGuid =
    EFI_DRIVER_DIAGNOSTICS_PROTOCOL_GUID;
EFI_GUID gEfiDriverDiagnostics2ProtocolGuid =
    EFI_DRIVER_DIAGNOSTICS2_PROTOCOL_GUID;
EFI_GUID gEfiDriverFamilyOverrideProtocolGuid =
    EFI_DRIVER_FAMILY_OVERRIDE_PROTOCOL_GUID;
EFI_GUID gEfiDriverHealthProtocolGuid =
    EFI_DRIVER_HEALTH_PROTOCOL_GUID;
EFI_GUID gEfiDriverSupportedEfiVersionProtocolGuid =
    EFI_DRIVER_SUPPORTED_EFI_VERSION_PROTOCOL_GUID;
EFI_GUID gEfiDxeServicesTableGuid = DXE_SERVICES_TABLE_GUID;
EFI_GUID gEfiEbcProtocolGuid = EFI_EBC_INTERPRETER_PROTOCOL_GUID;
EFI_GUID gEfiFormBrowser2ProtocolGuid = EFI_FORM_BROWSER2_PROTOCOL_GUID;
EFI_GUID gEfiFirmwareVolumeBlockProtocolGuid =
    EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL_GUID;
EFI_GUID gEfiFirmwareVolumeBlock2ProtocolGuid =
    EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL_GUID;
EFI_GUID gEfiHiiConfigAccessProtocolGuid = EFI_HII_CONFIG_ACCESS_PROTOCOL_GUID;
EFI_GUID gEfiConfigKeywordHandlerProtocolGuid =
    EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL_GUID;
EFI_GUID gEfiHiiConfigRoutingProtocolGuid =
    EFI_HII_CONFIG_ROUTING_PROTOCOL_GUID;
EFI_GUID gEfiHiiFontProtocolGuid = EFI_HII_FONT_PROTOCOL_GUID;
EFI_GUID gEfiHiiImageProtocolGuid = EFI_HII_IMAGE_PROTOCOL_GUID;
EFI_GUID gEfiHiiStringProtocolGuid = EFI_HII_STRING_PROTOCOL_GUID;
EFI_GUID gEfiHiiDatabaseProtocolGuid = EFI_HII_DATABASE_PROTOCOL_GUID;
EFI_GUID gEfiHobListGuid = HOB_LIST_GUID;
EFI_GUID gEfiIdeControllerInitProtocolGuid =
    EFI_IDE_CONTROLLER_INIT_PROTOCOL_GUID;
EFI_GUID gEfiIp4ProtocolGuid = EFI_IP4_PROTOCOL_GUID;
EFI_GUID gEfiIp4ServiceBindingProtocolGuid =
    EFI_IP4_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiIp4ConfigProtocolGuid = EFI_IP4_CONFIG_PROTOCOL_GUID;
EFI_GUID gEfiIp4Config2ProtocolGuid = EFI_IP4_CONFIG2_PROTOCOL_GUID;
EFI_GUID gEfiIp6ProtocolGuid = EFI_IP6_PROTOCOL_GUID;
EFI_GUID gEfiIp6ServiceBindingProtocolGuid =
    EFI_IP6_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiIp6ConfigProtocolGuid = EFI_IP6_CONFIG_PROTOCOL_GUID;
EFI_GUID gEfiIpSecProtocolGuid = EFI_IPSEC_PROTOCOL_GUID;
EFI_GUID gEfiIpSec2ProtocolGuid = EFI_IPSEC2_PROTOCOL_GUID;
EFI_GUID gEfiIpSecConfigProtocolGuid = EFI_IPSEC_CONFIG_PROTOCOL_GUID;
EFI_GUID gEfiIsaAcpiProtocolGuid = EFI_ISA_ACPI_PROTOCOL_GUID;
EFI_GUID gEfiKmsProtocolGuid = EFI_KMS_PROTOCOL_GUID;
EFI_GUID gEfiLegacy8259ProtocolGuid = EFI_LEGACY_8259_PROTOCOL_GUID;
EFI_GUID gEfiLoadFileProtocolGuid = EFI_LOAD_FILE_PROTOCOL_GUID;
EFI_GUID gEfiLoadFile2ProtocolGuid = EFI_LOAD_FILE2_PROTOCOL_GUID;
EFI_GUID gEfiManagedNetworkProtocolGuid = EFI_MANAGED_NETWORK_PROTOCOL_GUID;
EFI_GUID gEfiManagedNetworkServiceBindingProtocolGuid =
    EFI_MANAGED_NETWORK_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiMemoryTypeInformationGuid = EFI_MEMORY_TYPE_INFORMATION_GUID;
EFI_GUID gEfiMetronomeArchProtocolGuid = EFI_METRONOME_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiMonotonicCounterArchProtocolGuid =
    EFI_MONOTONIC_COUNTER_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiMpServiceProtocolGuid = EFI_MP_SERVICES_PROTOCOL_GUID;
EFI_GUID gEfiMpsTableGuid = MPS_TABLE_GUID;
EFI_GUID gEfiMtftp4ProtocolGuid = EFI_MTFTP4_PROTOCOL_GUID;
EFI_GUID gEfiMtftp4ServiceBindingProtocolGuid =
    EFI_MTFTP4_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiMtftp6ProtocolGuid = EFI_MTFTP6_PROTOCOL_GUID;
EFI_GUID gEfiMtftp6ServiceBindingProtocolGuid =
    EFI_MTFTP6_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiNetworkInterfaceIdentifierProtocolGuid =
    EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL_GUID;
EFI_GUID gEfiNetworkInterfaceIdentifierProtocolGuid_31 =
    EFI_NETWORK_INTERFACE_IDENTIFIER_PROTOCOL_GUID_31;
EFI_GUID gEfiNvmExpressPassThruProtocolGuid =
    EFI_NVM_EXPRESS_PASS_THRU_PROTOCOL_GUID;
EFI_GUID gEfiPartTypeLegacyMbrGuid = EFI_PART_TYPE_LEGACY_MBR_GUID;
EFI_GUID gEfiPartTypeSystemPartGuid = EFI_PART_TYPE_EFI_SYSTEM_PART_GUID;
EFI_GUID gEfiPcdProtocolGuid = EFI_PCD_PROTOCOL_GUID;
EFI_GUID gEfiPciEnumerationCompleteProtocolGuid =
    EFI_PCI_ENUMERATION_COMPLETE_GUID;
EFI_GUID gEfiPciRootBridgeIoProtocolGuid =
    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_GUID;
EFI_GUID gEfiPlatformDriverOverrideProtocolGuid =
    EFI_PLATFORM_DRIVER_OVERRIDE_PROTOCOL_GUID;
EFI_GUID gEfiPlatformToDriverConfigurationProtocolGuid =
    EFI_PLATFORM_TO_DRIVER_CONFIGURATION_PROTOCOL_GUID;
EFI_GUID gEfiPrint2SProtocolGuid = EFI_PRINT2_PROTOCOL_GUID;
EFI_GUID gEfiPxeBaseCodeProtocolGuid = EFI_PXE_BASE_CODE_PROTOCOL_GUID;
EFI_GUID gEfiPxeBaseCodeCallbackProtocolGuid =
    EFI_PXE_BASE_CODE_CALLBACK_PROTOCOL_GUID;
EFI_GUID gEfiRealTimeClockArchProtocolGuid =
    EFI_REAL_TIME_CLOCK_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiResetArchProtocolGuid = EFI_RESET_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiRngProtocolGuid = EFI_RNG_PROTOCOL_GUID;
EFI_GUID gEfiRuntimeArchProtocolGuid = EFI_RUNTIME_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiScsiIoProtocolGuid = EFI_SCSI_IO_PROTOCOL_GUID;
EFI_GUID gEfiScsiPassThruProtocolGuid = EFI_SCSI_PASS_THRU_PROTOCOL_GUID;
EFI_GUID gEfiExtScsiPassThruProtocolGuid =
    EFI_EXT_SCSI_PASS_THRU_PROTOCOL_GUID;
EFI_GUID gEfiSecurityArchProtocolGuid = EFI_SECURITY_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiSecurity2ArchProtocolGuid = EFI_SECURITY2_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiSecurityPolicyProtocolGuid = EFI_SECURITY_POLICY_PROTOCOL_GUID;
EFI_GUID gEfiSimpleFileSystemProtocolGuid =
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
EFI_GUID gEfiSimplePointerProtocolGuid = EFI_SIMPLE_POINTER_PROTOCOL_GUID;
EFI_GUID gEfiSmartCardReaderProtocolGuid = EFI_SMART_CARD_READER_PROTOCOL_GUID;
EFI_GUID gEfiStatusCodeRuntimeProtocolGuid =
    EFI_STATUS_CODE_RUNTIME_PROTOCOL_GUID;
EFI_GUID gEfiStorageSecurityCommandProtocolGuid =
    EFI_STORAGE_SECURITY_COMMAND_PROTOCOL_GUID;
EFI_GUID gEfiTcg2ProtocolGuid = EFI_TCG2_PROTOCOL_GUID;
EFI_GUID gEfiTcp4ProtocolGuid = EFI_TCP4_PROTOCOL_GUID;
EFI_GUID gEfiTcp4ServiceBindingProtocolGuid =
    EFI_TCP4_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiTcp6ProtocolGuid = EFI_TCP6_PROTOCOL_GUID;
EFI_GUID gEfiTcp6ServiceBindingProtocolGuid =
    EFI_TCP6_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiTimerArchProtocolGuid = EFI_TIMER_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiUdp4ProtocolGuid = EFI_UDP4_PROTOCOL_GUID;
EFI_GUID gEfiUdp4ServiceBindingProtocolGuid =
    EFI_UDP4_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiUdp6ProtocolGuid = EFI_UDP6_PROTOCOL_GUID;
EFI_GUID gEfiUdp6ServiceBindingProtocolGuid =
    EFI_UDP6_SERVICE_BINDING_PROTOCOL_GUID;
EFI_GUID gEfiUnicodeCollationProtocolGuid = EFI_UNICODE_COLLATION_PROTOCOL_GUID;
EFI_GUID gEfiUnicodeCollation2ProtocolGuid =
    EFI_UNICODE_COLLATION_PROTOCOL2_GUID;
EFI_GUID gEfiUsbIoProtocolGuid = EFI_USB_IO_PROTOCOL_GUID;
EFI_GUID gEfiUsb2HcProtocolGuid = EFI_USB2_HC_PROTOCOL_GUID;
EFI_GUID gEfiVariableArchProtocolGuid = EFI_VARIABLE_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiVariableWriteArchProtocolGuid =
    EFI_VARIABLE_WRITE_ARCH_PROTOCOL_GUID;
EFI_GUID gEfiWatchdogTimerArchProtocolGuid =
    EFI_WATCHDOG_TIMER_ARCH_PROTOCOL_GUID;
EFI_GUID gFdtTableGuid = FDT_TABLE_GUID;
EFI_GUID gLzmaCompress = LZMA_COMPRESS_GUID;
EFI_GUID gMtcVendorGuid = MTC_VENDOR_GUID;
EFI_GUID gPcdProtocolGuid = PCD_PROTOCOL_GUID;

static struct efi_uuid_mapping {
	const char *efi_guid_name;
	EFI_GUID *efi_guid;
} efi_uuid_mapping[] = {
	{ .efi_guid_name = "global",
	    .efi_guid = &gEfiGlobalVariableGuid },
	{ .efi_guid_name = "illumos",
	    .efi_guid = &gillumosBootVarGuid },
	/* EFI Systab entry names. */
	{ .efi_guid_name = "MPS Table",
	    .efi_guid = &gEfiMpsTableGuid },
	{ .efi_guid_name = "ACPI Table",
	    .efi_guid = &gEfiAcpiTableGuid },
	{ .efi_guid_name = "ACPI 2.0 Table",
	    .efi_guid = &gEfiAcpi20TableGuid },
	{ .efi_guid_name = "ATA pass thru",
	    .efi_guid = &gEfiAtaPassThruProtocolGuid },
	{ .efi_guid_name = "SMBIOS Table",
	    .efi_guid = &gEfiSmbiosTableGuid },
	{ .efi_guid_name = "SMBIOS3 Table",
	    .efi_guid = &gEfiSmbios3TableGuid },
	{ .efi_guid_name = "DXE Table",
	    .efi_guid = &gEfiDxeServicesTableGuid },
	{ .efi_guid_name = "HOB List Table",
	    .efi_guid = &gEfiHobListGuid },
	{ .efi_guid_name = EFI_MEMORY_TYPE_INFORMATION_VARIABLE_NAME,
	    .efi_guid = &gEfiMemoryTypeInformationGuid },
	{ .efi_guid_name = "Debug Image Info Table",
	    .efi_guid = &gEfiDebugImageInfoTableGuid },
	{ .efi_guid_name = "FDT Table",
	    .efi_guid = &gFdtTableGuid },
	/*
	 * Protocol names for debug purposes.
	 * Can be removed along with lsefi command.
	 */
	{ .efi_guid_name = "absolute pointer",
	    .efi_guid = &gEfiAbsolutePointerProtocolGuid },
	{ .efi_guid_name = "device path",
	    .efi_guid = &gEfiDevicePathProtocolGuid },
	{ .efi_guid_name = "block io",
	    .efi_guid = &gEfiBlockIoProtocolGuid },
	{ .efi_guid_name = "block io2",
	    .efi_guid = &gEfiBlockIo2ProtocolGuid },
	{ .efi_guid_name = "disk io",
	    .efi_guid = &gEfiDiskIoProtocolGuid },
	{ .efi_guid_name = "disk io2",
	    .efi_guid = &gEfiDiskIo2ProtocolGuid },
	{ .efi_guid_name = "disk info",
	    .efi_guid = &gEfiDiskInfoProtocolGuid },
	{ .efi_guid_name = "simple fs",
	    .efi_guid = &gEfiSimpleFileSystemProtocolGuid },
	{ .efi_guid_name = "load file",
	    .efi_guid = &gEfiLoadFileProtocolGuid },
	{ .efi_guid_name = "load file2",
	    .efi_guid = &gEfiLoadFile2ProtocolGuid },
	{ .efi_guid_name = "device io",
	    .efi_guid = &gEfiDeviceIoProtocolGuid },
	{ .efi_guid_name = "unicode collation",
	    .efi_guid = &gEfiUnicodeCollationProtocolGuid },
	{ .efi_guid_name = "unicode collation2",
	    .efi_guid = &gEfiUnicodeCollation2ProtocolGuid },
	{ .efi_guid_name = "simple network",
	    .efi_guid = &gEfiSimpleNetworkProtocolGuid },
	{ .efi_guid_name = "simple pointer",
	    .efi_guid = &gEfiSimplePointerProtocolGuid },
	{ .efi_guid_name = "simple text output",
	    .efi_guid = &gEfiSimpleTextOutProtocolGuid },
	{ .efi_guid_name = "simple text input",
	    .efi_guid = &gEfiSimpleTextInProtocolGuid },
	{ .efi_guid_name = "simple text ex input",
	    .efi_guid = &gEfiSimpleTextInputExProtocolGuid },
	{ .efi_guid_name = "console control",
	    .efi_guid = &gEfiConsoleControlProtocolGuid },
	{ .efi_guid_name = "stdin",
	    .efi_guid = &gEfiConsoleInDeviceGuid },
	{ .efi_guid_name = "stdout",
	    .efi_guid = &gEfiConsoleOutDeviceGuid },
	{ .efi_guid_name = "stderr",
	    .efi_guid = &gEfiStandardErrorDeviceGuid },
	{ .efi_guid_name = "GOP",
	    .efi_guid = &gEfiGraphicsOutputProtocolGuid },
	{ .efi_guid_name = "UGA draw",
	    .efi_guid = &gEfiUgaDrawProtocolGuid },
	{ .efi_guid_name = "UGA io",
	    .efi_guid = &gEfiUgaIoProtocolGuid },
	{ .efi_guid_name = "PXE base code",
	    .efi_guid = &gEfiPxeBaseCodeProtocolGuid },
	{ .efi_guid_name = "PXE base code callback",
	    .efi_guid = &gEfiPxeBaseCodeCallbackProtocolGuid },
	{ .efi_guid_name = "serial io",
	    .efi_guid = &gEfiSerialIoProtocolGuid },
	{ .efi_guid_name = "serial device type",
	    .efi_guid = &gEfiSerialTerminalDeviceTypeGuid },
	{ .efi_guid_name = "loaded image",
	    .efi_guid = &gEfiLoadedImageProtocolGuid },
	{ .efi_guid_name = "loaded image device path",
	    .efi_guid = &gEfiLoadedImageDevicePathProtocolGuid },
	{ .efi_guid_name = "ISA ACPI",
	    .efi_guid = &gEfiIsaAcpiProtocolGuid },
	{ .efi_guid_name = "ISA io",
	    .efi_guid = &gEfiIsaIoProtocolGuid },
	{ .efi_guid_name = "Super io", .efi_guid = &gEfiSioProtocolGuid },
	{ .efi_guid_name = "IDE controller init",
	    .efi_guid = &gEfiIdeControllerInitProtocolGuid },
	{ .efi_guid_name = "PCI",
	    .efi_guid = &gEfiPciIoProtocolGuid },
	{ .efi_guid_name = "PCI enumeration",
	    .efi_guid = &gEfiPciEnumerationCompleteProtocolGuid },
	{ .efi_guid_name = "PCI root bridge",
	    .efi_guid = &gEfiPciRootBridgeIoProtocolGuid },
	{ .efi_guid_name = "driver binding",
	    .efi_guid = &gEfiDriverBindingProtocolGuid },
	{ .efi_guid_name = "driver configuration",
	    .efi_guid = &gEfiDriverConfigurationProtocolGuid },
	{ .efi_guid_name = "driver configuration2",
	    .efi_guid = &gEfiDriverConfiguration2ProtocolGuid },
	{ .efi_guid_name = "driver diagnostics",
	    .efi_guid = &gEfiDriverDiagnosticsProtocolGuid },
	{ .efi_guid_name = "driver diagnostics2",
	    .efi_guid = &gEfiDriverDiagnostics2ProtocolGuid },
	{ .efi_guid_name = "driver override",
	    .efi_guid = &gEfiPlatformDriverOverrideProtocolGuid },
	{ .efi_guid_name = "bus specific driver override",
	    .efi_guid = &gEfiBusSpecificDriverOverrideProtocolGuid },
	{ .efi_guid_name = "platform to driver configuration",
	    .efi_guid = &gEfiPlatformToDriverConfigurationProtocolGuid },
	{ .efi_guid_name = "driver supported EFI version",
	    .efi_guid = &gEfiDriverSupportedEfiVersionProtocolGuid },
	{ .efi_guid_name = "driver family override",
	    .efi_guid = &gEfiDriverFamilyOverrideProtocolGuid },
	{ .efi_guid_name = "driver health",
	    .efi_guid = &gEfiDriverHealthProtocolGuid },
	{ .efi_guid_name = "adapter information",
	    .efi_guid = &gEfiAdapterInformationProtocolGuid },
	{ .efi_guid_name = "VLAN config",
	    .efi_guid = &gEfiVlanConfigProtocolGuid },
	{ .efi_guid_name = "ARP service binding",
	    .efi_guid = &gEfiArpServiceBindingProtocolGuid },
	{ .efi_guid_name = "ARP",
	    .efi_guid = &gEfiArpProtocolGuid },
	{ .efi_guid_name = "IPv4 service binding",
	    .efi_guid = &gEfiIp4ServiceBindingProtocolGuid },
	{ .efi_guid_name = "IPv4",
	    .efi_guid = &gEfiIp4ProtocolGuid },
	{ .efi_guid_name = "IPv4 config",
	    .efi_guid = &gEfiIp4ConfigProtocolGuid },
	{ .efi_guid_name = "IPv4 config2",
	    .efi_guid = &gEfiIp4Config2ProtocolGuid },
	{ .efi_guid_name = "IPv6 service binding",
	    .efi_guid = &gEfiIp6ServiceBindingProtocolGuid },
	{ .efi_guid_name = "IPv6",
	    .efi_guid = &gEfiIp6ProtocolGuid },
	{ .efi_guid_name = "IPv6 config",
	    .efi_guid = &gEfiIp6ConfigProtocolGuid },
	{ .efi_guid_name = "NVMe pass thru",
	    .efi_guid = &gEfiNvmExpressPassThruProtocolGuid },
	{ .efi_guid_name = "UDPv4",
	    .efi_guid = &gEfiUdp4ProtocolGuid },
	{ .efi_guid_name = "UDPv4 service binding",
	    .efi_guid = &gEfiUdp4ServiceBindingProtocolGuid },
	{ .efi_guid_name = "UDPv6",
	    .efi_guid = &gEfiUdp6ProtocolGuid },
	{ .efi_guid_name = "UDPv6 service binding",
	    .efi_guid = &gEfiUdp6ServiceBindingProtocolGuid },
	{ .efi_guid_name = "TCPv4",
	    .efi_guid = &gEfiTcp4ProtocolGuid },
	{ .efi_guid_name = "TCPv4 service binding",
	    .efi_guid = &gEfiTcp4ServiceBindingProtocolGuid },
	{ .efi_guid_name = "TCPv6",
	    .efi_guid = &gEfiTcp6ProtocolGuid },
	{ .efi_guid_name = "TCPv6 service binding",
	    .efi_guid = &gEfiTcp6ServiceBindingProtocolGuid },
	{ .efi_guid_name = "EFI System partition",
	    .efi_guid = &gEfiPartTypeSystemPartGuid },
	{ .efi_guid_name = "MBR legacy",
	    .efi_guid = &gEfiPartTypeLegacyMbrGuid },
	{ .efi_guid_name = "USB io",
	    .efi_guid = &gEfiUsbIoProtocolGuid },
	{ .efi_guid_name = "USB2 HC",
	    .efi_guid = &gEfiUsb2HcProtocolGuid },
	{ .efi_guid_name = "component name",
	    .efi_guid = &gEfiComponentNameProtocolGuid },
	{ .efi_guid_name = "component name2",
	    .efi_guid = &gEfiComponentName2ProtocolGuid },
	{ .efi_guid_name = "decompress",
	    .efi_guid = &gEfiDecompressProtocolGuid },
	{ .efi_guid_name = "ebc interpreter",
	    .efi_guid = &gEfiEbcProtocolGuid },
	{ .efi_guid_name = "network interface identifier",
	    .efi_guid = &gEfiNetworkInterfaceIdentifierProtocolGuid },
	{ .efi_guid_name = "network interface identifier_31",
	    .efi_guid = &gEfiNetworkInterfaceIdentifierProtocolGuid_31 },
	{ .efi_guid_name = "managed network service binding",
	    .efi_guid = &gEfiManagedNetworkServiceBindingProtocolGuid },
	{ .efi_guid_name = "managed network",
	    .efi_guid = &gEfiManagedNetworkProtocolGuid },
	{ .efi_guid_name = "form browser",
	    .efi_guid = &gEfiFormBrowser2ProtocolGuid },
	{ .efi_guid_name = "HII config access",
	    .efi_guid = &gEfiHiiConfigAccessProtocolGuid },
	{ .efi_guid_name = "HII config keyword handler",
	    .efi_guid = &gEfiConfigKeywordHandlerProtocolGuid },
	{ .efi_guid_name = "HII config routing",
	    .efi_guid = &gEfiHiiConfigRoutingProtocolGuid },
	{ .efi_guid_name = "HII database",
	    .efi_guid = &gEfiHiiDatabaseProtocolGuid },
	{ .efi_guid_name = "HII string",
	    .efi_guid = &gEfiHiiStringProtocolGuid },
	{ .efi_guid_name = "HII image",
	    .efi_guid = &gEfiHiiImageProtocolGuid },
	{ .efi_guid_name = "HII font",
	    .efi_guid = &gEfiHiiFontProtocolGuid },
	{ .efi_guid_name = "MTFTP3 service binding",
	    .efi_guid = &gEfiMtftp4ServiceBindingProtocolGuid },
	{ .efi_guid_name = "MTFTP4",
	    .efi_guid = &gEfiMtftp4ProtocolGuid },
	{ .efi_guid_name = "MTFTP6 service binding",
	    .efi_guid = &gEfiMtftp6ServiceBindingProtocolGuid },
	{ .efi_guid_name = "MTFTP6",
	    .efi_guid = &gEfiMtftp6ProtocolGuid },
	{ .efi_guid_name = "DHCP4 service binding",
	    .efi_guid = &gEfiDhcp4ServiceBindingProtocolGuid },
	{ .efi_guid_name = "DHCP4",
	    .efi_guid = &gEfiDhcp4ProtocolGuid },
	{ .efi_guid_name = "DHCP6 service binding",
	    .efi_guid = &gEfiDhcp6ServiceBindingProtocolGuid },
	{ .efi_guid_name = "DHCP6",
	    .efi_guid = &gEfiDhcp6ProtocolGuid },
	{ .efi_guid_name = "SCSI io",
	    .efi_guid = &gEfiScsiIoProtocolGuid },
	{ .efi_guid_name = "SCSI pass thru",
	    .efi_guid = &gEfiScsiPassThruProtocolGuid },
	{ .efi_guid_name = "SCSI pass thru ext",
	    .efi_guid = &gEfiExtScsiPassThruProtocolGuid },
	{ .efi_guid_name = "Capsule arch",
	    .efi_guid = &gEfiCapsuleArchProtocolGuid },
	{ .efi_guid_name = "monotonic counter arch",
	    .efi_guid = &gEfiMonotonicCounterArchProtocolGuid },
	{ .efi_guid_name = "realtime clock arch",
	    .efi_guid = &gEfiRealTimeClockArchProtocolGuid },
	{ .efi_guid_name = "variable arch",
	    .efi_guid = &gEfiVariableArchProtocolGuid },
	{ .efi_guid_name = "variable write arch",
	    .efi_guid = &gEfiVariableWriteArchProtocolGuid },
	{ .efi_guid_name = "watchdog timer arch",
	    .efi_guid = &gEfiWatchdogTimerArchProtocolGuid },
	{ .efi_guid_name = "BDS arch",
	    .efi_guid = &gEfiBdsArchProtocolGuid },
	{ .efi_guid_name = "metronome arch",
	    .efi_guid = &gEfiMetronomeArchProtocolGuid },
	{ .efi_guid_name = "timer arch",
	    .efi_guid = &gEfiTimerArchProtocolGuid },
	{ .efi_guid_name = "DPC",
	    .efi_guid = &gEfiDpcProtocolGuid },
	{ .efi_guid_name = "print2",
	    .efi_guid = &gEfiPrint2SProtocolGuid },
	{ .efi_guid_name = "device path to text",
	    .efi_guid = &gEfiDevicePathToTextProtocolGuid },
	{ .efi_guid_name = "reset arch",
	    .efi_guid = &gEfiResetArchProtocolGuid },
	{ .efi_guid_name = "CPU arch",
	    .efi_guid = &gEfiCpuArchProtocolGuid },
	{ .efi_guid_name = "CPU IO2",
	    .efi_guid = &gEfiCpuIo2ProtocolGuid },
	{ .efi_guid_name = "Legacy 8259",
	    .efi_guid = &gEfiLegacy8259ProtocolGuid },
	{ .efi_guid_name = "Security arch",
	    .efi_guid = &gEfiSecurityArchProtocolGuid },
	{ .efi_guid_name = "Security2 arch",
	    .efi_guid = &gEfiSecurity2ArchProtocolGuid },
	{ .efi_guid_name = "Security Policy",
	    .efi_guid = &gEfiSecurityPolicyProtocolGuid },
	{ .efi_guid_name = "Runtime arch",
	    .efi_guid = &gEfiRuntimeArchProtocolGuid },
	{ .efi_guid_name = "status code runtime",
	    .efi_guid = &gEfiStatusCodeRuntimeProtocolGuid },
	{ .efi_guid_name = "storage security command",
	    .efi_guid = &gEfiStorageSecurityCommandProtocolGuid },
	{ .efi_guid_name = "data hub",
	    .efi_guid = &gEfiDataHubProtocolGuid },
	{ .efi_guid_name = "PCD",
	    .efi_guid = &gPcdProtocolGuid },
	{ .efi_guid_name = "EFI PCD",
	    .efi_guid = &gEfiPcdProtocolGuid },
	{ .efi_guid_name = "firmware volume block",
	    .efi_guid = &gEfiFirmwareVolumeBlockProtocolGuid },
	{ .efi_guid_name = "firmware volume2",
	    .efi_guid = &gEfiFirmwareVolumeBlock2ProtocolGuid },
	{ .efi_guid_name = "lzma compress",
	    .efi_guid = &gLzmaCompress },
	{ .efi_guid_name = "MP services",
	    .efi_guid = &gEfiMpServiceProtocolGuid },
	{ .efi_guid_name = MTC_VARIABLE_NAME,
	    .efi_guid = &gMtcVendorGuid },
	{ .efi_guid_name = "Active EDID",
	    .efi_guid = &gEfiEdidActiveProtocolGuid },
	{ .efi_guid_name = "Discovered EDID",
	    .efi_guid = &gEfiEdidDiscoveredProtocolGuid },
	{ .efi_guid_name = "key management service",
	    .efi_guid = &gEfiKmsProtocolGuid },
	{ .efi_guid_name = "smart card reader",
	    .efi_guid = &gEfiSmartCardReaderProtocolGuid },
	{ .efi_guid_name = "rng source",
	    .efi_guid = &gEfiRngProtocolGuid },
	{ .efi_guid_name = "IPsec config",
	    .efi_guid = &gEfiIpSecConfigProtocolGuid },
	{ .efi_guid_name = "IPsec",
	    .efi_guid = &gEfiIpSecProtocolGuid },
	{ .efi_guid_name = "IPsec2",
	    .efi_guid = &gEfiIpSec2ProtocolGuid },
	{ .efi_guid_name = "TCG2 tpm",
	    .efi_guid = &gEfiTcg2ProtocolGuid }
};

bool
efi_guid_to_str(const EFI_GUID *guid, char **sp)
{
	uint32_t status;

	uuid_to_string((const uuid_t *)guid, sp, &status);
	return (status == uuid_s_ok ? true : false);
}

bool
efi_str_to_guid(const char *s, EFI_GUID *guid)
{
	uint32_t status;

	uuid_from_string(s, (uuid_t *)guid, &status);
	return (status == uuid_s_ok ? true : false);
}

bool
efi_name_to_guid(const char *name, EFI_GUID *guid)
{
	uint32_t i;

	for (i = 0; i < nitems(efi_uuid_mapping); i++) {
		if (strcasecmp(name, efi_uuid_mapping[i].efi_guid_name) == 0) {
			*guid = *efi_uuid_mapping[i].efi_guid;
			return (true);
		}
	}
	return (efi_str_to_guid(name, guid));
}

bool
efi_guid_to_name(EFI_GUID *guid, char **name)
{
	uint32_t i;
	int rv;

	for (i = 0; i < nitems(efi_uuid_mapping); i++) {
		rv = uuid_equal((uuid_t *)guid,
		    (uuid_t *)efi_uuid_mapping[i].efi_guid, NULL);
		if (rv != 0) {
			*name = strdup(efi_uuid_mapping[i].efi_guid_name);
			if (*name == NULL)
				return (false);
			return (true);
		}
	}
	return (efi_guid_to_str(guid, name));
}

void
efi_init_environment(void)
{
	char var[128];

	snprintf(var, sizeof (var), "%d.%02d", ST->Hdr.Revision >> 16,
	    ST->Hdr.Revision & 0xffff);
	env_setenv("efi-version", EV_VOLATILE, var, env_noset, env_nounset);
}

COMMAND_SET(efishow, "efi-show", "print some or all EFI variables",
    command_efi_show);

static int
efi_print_other_value(uint8_t *data, UINTN datasz)
{
	UINTN i;
	bool is_ascii = true;

	printf(" = ");
	for (i = 0; i < datasz - 1; i++) {
		/*
		 * Quick hack to see if this ascii-ish string is printable
		 * range plus tab, cr and lf.
		 */
		if ((data[i] < 32 || data[i] > 126) &&
		    data[i] != 9 && data[i] != 10 && data[i] != 13) {
			is_ascii = false;
			break;
		}
	}
	if (data[datasz - 1] != '\0')
		is_ascii = false;
	if (is_ascii == true) {
		printf("%s", data);
		if (pager_output("\n"))
			return (CMD_WARN);
	} else {
		if (pager_output("\n"))
			return (CMD_WARN);
		/*
		 * Dump hex bytes grouped by 4.
		 */
		for (i = 0; i < datasz; i++) {
			printf("%02x ", data[i]);
			if ((i + 1) % 4 == 0)
				printf(" ");
			if ((i + 1) % 20 == 0) {
				if (pager_output("\n"))
					return (CMD_WARN);
			}
		}
		if (pager_output("\n"))
			return (CMD_WARN);
	}

	return (CMD_OK);
}

/* This appears to be some sort of UEFI shell alias table. */
static int
efi_print_shell_str(const CHAR16 *varnamearg __unused, uint8_t *data,
    UINTN datasz __unused)
{
	printf(" = %S", (CHAR16 *)data);
	if (pager_output("\n"))
		return (CMD_WARN);
	return (CMD_OK);
}

const char *
efi_memory_type(EFI_MEMORY_TYPE type)
{
	const char *types[] = {
	    "Reserved",
	    "LoaderCode",
	    "LoaderData",
	    "BootServicesCode",
	    "BootServicesData",
	    "RuntimeServicesCode",
	    "RuntimeServicesData",
	    "ConventionalMemory",
	    "UnusableMemory",
	    "ACPIReclaimMemory",
	    "ACPIMemoryNVS",
	    "MemoryMappedIO",
	    "MemoryMappedIOPortSpace",
	    "PalCode",
	    "PersistentMemory"
	};

	switch (type) {
	case EfiReservedMemoryType:
	case EfiLoaderCode:
	case EfiLoaderData:
	case EfiBootServicesCode:
	case EfiBootServicesData:
	case EfiRuntimeServicesCode:
	case EfiRuntimeServicesData:
	case EfiConventionalMemory:
	case EfiUnusableMemory:
	case EfiACPIReclaimMemory:
	case EfiACPIMemoryNVS:
	case EfiMemoryMappedIO:
	case EfiMemoryMappedIOPortSpace:
	case EfiPalCode:
	case EfiPersistentMemory:
		return (types[type]);
	default:
		return ("Unknown");
	}
}

/* Print memory type table. */
static int
efi_print_mem_type(const CHAR16 *varnamearg __unused, uint8_t *data,
    UINTN datasz)
{
	int i, n;
	EFI_MEMORY_TYPE_INFORMATION *ti;

	ti = (EFI_MEMORY_TYPE_INFORMATION *)data;
	if (pager_output(" = \n"))
		return (CMD_WARN);

	n = datasz / sizeof (EFI_MEMORY_TYPE_INFORMATION);
	for (i = 0; i < n && ti[i].NumberOfPages != 0; i++) {
		printf("\t%23s pages: %u", efi_memory_type(ti[i].Type),
		    ti[i].NumberOfPages);
		if (pager_output("\n"))
			return (CMD_WARN);
	}

	return (CMD_OK);
}

/*
 * Print illumos variables.
 * We have LoaderPath and LoaderDev as CHAR16 strings.
 */
static int
efi_print_illumos(const CHAR16 *varnamearg, uint8_t *data,
    UINTN datasz __unused)
{
	int rv = -1;
	char *var = NULL;

	if (ucs2_to_utf8(varnamearg, &var) != 0)
		return (CMD_ERROR);

	if (strcmp("LoaderPath", var) == 0 ||
	    strcmp("LoaderDev", var) == 0) {
		printf(" = ");
		printf("%S", (CHAR16 *)data);

		if (pager_output("\n"))
			rv = CMD_WARN;
		else
			rv = CMD_OK;
	}

	free(var);
	return (rv);
}

/* Print global variables. */
static int
efi_print_global(const CHAR16 *varnamearg, uint8_t *data, UINTN datasz)
{
	int rv = -1;
	char *var = NULL;

	if (ucs2_to_utf8(varnamearg, &var) != 0)
		return (CMD_ERROR);

	if (strcmp("AuditMode", var) == 0) {
		printf(" = ");
		printf("0x%x", *data);	/* 8-bit int */
		goto done;
	}

	if (strcmp("BootOptionSupport", var) == 0) {
		printf(" = ");
		printf("0x%x", *((uint32_t *)data));	/* UINT32 */
		goto done;
	}

	if (strcmp("BootCurrent", var) == 0 ||
	    strcmp("BootNext", var) == 0 ||
	    strcmp("Timeout", var) == 0) {
		printf(" = ");
		printf("%u", *((uint16_t *)data));	/* UINT16 */
		goto done;
	}

	if (strcmp("BootOrder", var) == 0 ||
	    strcmp("DriverOrder", var) == 0) {
		int i;
		UINT16 *u16 = (UINT16 *)data;

		printf(" =");
		for (i = 0; i < datasz / sizeof (UINT16); i++)
			printf(" %u", u16[i]);
		goto done;
	}
	if (strncmp("Boot", var, 4) == 0 ||
	    strncmp("Driver", var, 5) == 0 ||
	    strncmp("SysPrep", var, 7) == 0 ||
	    strncmp("OsRecovery", var, 10) == 0) {
		UINT16 filepathlistlen;
		CHAR16 *text;
		int desclen;
		EFI_DEVICE_PATH *dp;

		data += sizeof (UINT32);
		filepathlistlen = *(uint16_t *)data;
		data += sizeof (UINT16);
		text = (CHAR16 *)data;

		for (desclen = 0; text[desclen] != 0; desclen++)
			;
		if (desclen != 0) {
			/* Add terminating zero and we have CHAR16. */
			desclen = (desclen + 1) * 2;
		}

		printf(" = ");
		printf("%S", text);
		if (filepathlistlen != 0) {
			/* Output pathname from new line. */
			if (pager_output("\n")) {
				rv = CMD_WARN;
				goto done;
			}
			dp = malloc(filepathlistlen);
			if (dp == NULL)
				goto done;

			memcpy(dp, data + desclen, filepathlistlen);
			text = efi_devpath_name(dp);
			if (text != NULL) {
				printf("\t%S", text);
				efi_free_devpath_name(text);
			}
			free(dp);
		}
		goto done;
	}

	if (strcmp("ConIn", var) == 0 ||
	    strcmp("ConInDev", var) == 0 ||
	    strcmp("ConOut", var) == 0 ||
	    strcmp("ConOutDev", var) == 0 ||
	    strcmp("ErrOut", var) == 0 ||
	    strcmp("ErrOutDev", var) == 0) {
		CHAR16 *text;

		printf(" = ");
		text = efi_devpath_name((EFI_DEVICE_PATH *)data);
		if (text != NULL) {
			printf("%S", text);
			efi_free_devpath_name(text);
		}
		goto done;
	}

	if (strcmp("PlatformLang", var) == 0 ||
	    strcmp("PlatformLangCodes", var) == 0 ||
	    strcmp("LangCodes", var) == 0 ||
	    strcmp("Lang", var) == 0) {
		printf(" = ");
		printf("%s", data);	/* ASCII string */
		goto done;
	}

	/*
	 * Feature bitmap from firmware to OS.
	 * Older UEFI provides UINT32, newer UINT64.
	 */
	if (strcmp("OsIndicationsSupported", var) == 0) {
		printf(" = ");
		if (datasz == 4)
			printf("0x%x", *((uint32_t *)data));
		else
			printf("0x%jx", *((uint64_t *)data));
		goto done;
	}

	/* Fallback for anything else. */
	rv = efi_print_other_value(data, datasz);
done:
	if (rv == -1) {
		if (pager_output("\n"))
			rv = CMD_WARN;
		else
			rv = CMD_OK;
	}
	free(var);
	return (rv);
}

static void
efi_print_var_attr(UINT32 attr)
{
	bool comma = false;

	if (attr & EFI_VARIABLE_NON_VOLATILE) {
		printf("NV");
		comma = true;
	}
	if (attr & EFI_VARIABLE_BOOTSERVICE_ACCESS) {
		if (comma == true)
			printf(",");
		printf("BS");
		comma = true;
	}
	if (attr & EFI_VARIABLE_RUNTIME_ACCESS) {
		if (comma == true)
			printf(",");
		printf("RS");
		comma = true;
	}
	if (attr & EFI_VARIABLE_HARDWARE_ERROR_RECORD) {
		if (comma == true)
			printf(",");
		printf("HR");
		comma = true;
	}
	if (attr & EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
		if (comma == true)
			printf(",");
		printf("AT");
		comma = true;
	}
}

static int
efi_print_var(CHAR16 *varnamearg, EFI_GUID *matchguid, int lflag)
{
	UINTN		datasz;
	EFI_STATUS	status;
	UINT32		attr;
	char		*str;
	uint8_t		*data;
	int		rv = CMD_OK;

	str = NULL;
	datasz = 0;
	status = RS->GetVariable(varnamearg, matchguid, &attr, &datasz, NULL);
	if (status != EFI_BUFFER_TOO_SMALL) {
		printf("Can't get the variable: error %#lx\n",
		    DECODE_ERROR(status));
		return (CMD_ERROR);
	}
	data = malloc(datasz);
	if (data == NULL) {
		printf("Out of memory\n");
		return (CMD_ERROR);
	}

	status = RS->GetVariable(varnamearg, matchguid, &attr, &datasz, data);
	if (status != EFI_SUCCESS) {
		printf("Can't get the variable: error %#lx\n",
		    DECODE_ERROR(status));
		free(data);
		return (CMD_ERROR);
	}

	if (efi_guid_to_name(matchguid, &str) == false) {
		rv = CMD_ERROR;
		goto done;
	}
	printf("%s ", str);
	efi_print_var_attr(attr);
	printf(" %S", varnamearg);

	if (lflag == 0) {
		if (strcmp(str, "global") == 0)
			rv = efi_print_global(varnamearg, data, datasz);
		else if (strcmp(str, "illumos") == 0)
			rv = efi_print_illumos(varnamearg, data, datasz);
		else if (strcmp(str,
		    EFI_MEMORY_TYPE_INFORMATION_VARIABLE_NAME) == 0)
			rv = efi_print_mem_type(varnamearg, data, datasz);
		else if (strcmp(str,
		    "47c7b227-c42a-11d2-8e57-00a0c969723b") == 0)
			rv = efi_print_shell_str(varnamearg, data, datasz);
		else if (strcmp(str, MTC_VARIABLE_NAME) == 0) {
			printf(" = ");
			printf("%u", *((uint32_t *)data));	/* UINT32 */
			rv = CMD_OK;
			if (pager_output("\n"))
				rv = CMD_WARN;
		} else
			rv = efi_print_other_value(data, datasz);
	} else if (pager_output("\n"))
		rv =  CMD_WARN;

done:
	free(str);
	free(data);
	return (rv);
}

static int
command_efi_show(int argc, char *argv[])
{
	/*
	 * efi-show [-a]
	 *	print all the env
	 * efi-show -g UUID
	 *	print all the env vars tagged with UUID
	 * efi-show -v var
	 *	search all the env vars and print the ones matching var
	 * efi-show -g UUID -v var
	 * efi-show UUID var
	 *	print all the env vars that match UUID and var
	 */
	/* NB: We assume EFI_GUID is the same as uuid_t */
	int		aflag = 0, gflag = 0, lflag = 0, vflag = 0;
	int		ch, rv;
	unsigned	i;
	EFI_STATUS	status;
	EFI_GUID	varguid = ZERO_GUID;
	EFI_GUID	matchguid = ZERO_GUID;
	CHAR16		*varname;
	CHAR16		*newnm;
	CHAR16		varnamearg[128];
	UINTN		varalloc;
	UINTN		varsz;

	optind = 1;
	optreset = 1;
	opterr = 1;

	while ((ch = getopt(argc, argv, "ag:lv:")) != -1) {
		switch (ch) {
		case 'a':
			aflag = 1;
			break;
		case 'g':
			gflag = 1;
			if (efi_name_to_guid(optarg, &matchguid) == false) {
				printf("uuid %s could not be parsed\n", optarg);
				return (CMD_ERROR);
			}
			break;
		case 'l':
			lflag = 1;
			break;
		case 'v':
			vflag = 1;
			if (strlen(optarg) >= nitems(varnamearg)) {
				printf("Variable %s is longer than %zu "
				    "characters\n", optarg, nitems(varnamearg));
				return (CMD_ERROR);
			}
			cpy8to16(optarg, varnamearg, nitems(varnamearg));
			break;
		default:
			return (CMD_ERROR);
		}
	}

	if (argc == 1)		/* default is -a */
		aflag = 1;

	if (aflag && (gflag || vflag)) {
		printf("-a isn't compatible with -g or -v\n");
		return (CMD_ERROR);
	}

	if (aflag && optind < argc) {
		printf("-a doesn't take any args\n");
		return (CMD_ERROR);
	}

	argc -= optind;
	argv += optind;

	pager_open();
	if (vflag && gflag) {
		rv = efi_print_var(varnamearg, &matchguid, lflag);
		if (rv == CMD_WARN)
			rv = CMD_OK;
		pager_close();
		return (rv);
	}

	if (argc == 2) {
		optarg = argv[0];
		if (strlen(optarg) >= nitems(varnamearg)) {
			printf("Variable %s is longer than %zu characters\n",
			    optarg, nitems(varnamearg));
			pager_close();
			return (CMD_ERROR);
		}
		for (i = 0; i < strlen(optarg); i++)
			varnamearg[i] = optarg[i];
		varnamearg[i] = 0;
		optarg = argv[1];
		if (efi_name_to_guid(optarg, &matchguid) == false) {
			printf("uuid %s could not be parsed\n", optarg);
			pager_close();
			return (CMD_ERROR);
		}
		rv = efi_print_var(varnamearg, &matchguid, lflag);
		if (rv == CMD_WARN)
			rv = CMD_OK;
		pager_close();
		return (rv);
	}

	if (argc > 0) {
		printf("Too many args: %d\n", argc);
		pager_close();
		return (CMD_ERROR);
	}

	/*
	 * Initiate the search -- note the standard takes pain
	 * to specify the initial call must be a poiner to a NULL
	 * character.
	 */
	varalloc = 1024;
	varname = malloc(varalloc);
	if (varname == NULL) {
		printf("Can't allocate memory to get variables\n");
		pager_close();
		return (CMD_ERROR);
	}
	varname[0] = 0;
	while (1) {
		varsz = varalloc;
		status = RS->GetNextVariableName(&varsz, varname, &varguid);
		if (status == EFI_BUFFER_TOO_SMALL) {
			varalloc = varsz;
			newnm = realloc(varname, varalloc);
			if (newnm == NULL) {
				printf("Can't allocate memory to get "
				    "variables\n");
				rv = CMD_ERROR;
				break;
			}
			varname = newnm;
			continue; /* Try again with bigger buffer */
		}
		if (status == EFI_NOT_FOUND) {
			rv = CMD_OK;
			break;
		}
		if (status != EFI_SUCCESS) {
			rv = CMD_ERROR;
			break;
		}

		if (aflag) {
			rv = efi_print_var(varname, &varguid, lflag);
			if (rv != CMD_OK) {
				if (rv == CMD_WARN)
					rv = CMD_OK;
				break;
			}
			continue;
		}
		if (vflag) {
			if (wcscmp(varnamearg, varname) == 0) {
				rv = efi_print_var(varname, &varguid, lflag);
				if (rv != CMD_OK) {
					if (rv == CMD_WARN)
						rv = CMD_OK;
					break;
				}
				continue;
			}
		}
		if (gflag) {
			rv = uuid_equal((uuid_t *)&varguid,
			    (uuid_t *)&matchguid, NULL);
			if (rv != 0) {
				rv = efi_print_var(varname, &varguid, lflag);
				if (rv != CMD_OK) {
					if (rv == CMD_WARN)
						rv = CMD_OK;
					break;
				}
				continue;
			}
		}
	}
	free(varname);
	pager_close();

	return (rv);
}

COMMAND_SET(efiset, "efi-set", "set EFI variables", command_efi_set);

static int
command_efi_set(int argc, char *argv[])
{
	char *uuid, *var, *val;
	CHAR16 wvar[128];
	EFI_GUID guid;
#if defined(ENABLE_UPDATES)
	EFI_STATUS err;
#endif

	if (argc != 4) {
		printf("efi-set uuid var new-value\n");
		return (CMD_ERROR);
	}
	uuid = argv[1];
	var = argv[2];
	val = argv[3];
	if (efi_name_to_guid(uuid, &guid) == false) {
		printf("Invalid uuid %s\n", uuid);
		return (CMD_ERROR);
	}
	cpy8to16(var, wvar, nitems(wvar));
#if defined(ENABLE_UPDATES)
	err = RS->SetVariable(wvar, &guid, EFI_VARIABLE_NON_VOLATILE |
	    EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_BOOTSERVICE_ACCESS,
	    strlen(val) + 1, val);
	if (EFI_ERROR(err)) {
		printf("Failed to set variable: error %lu\n",
		    DECODE_ERROR(err));
		return (CMD_ERROR);
	}
#else
	printf("would set %s %s = %s\n", uuid, var, val);
#endif
	return (CMD_OK);
}

COMMAND_SET(efiunset, "efi-unset", "delete / unset EFI variables",
    command_efi_unset);

static int
command_efi_unset(int argc, char *argv[])
{
	char *uuid, *var;
	CHAR16 wvar[128];
	EFI_GUID guid;
#if defined(ENABLE_UPDATES)
	EFI_STATUS err;
#endif

	if (argc != 3) {
		printf("efi-unset uuid var\n");
		return (CMD_ERROR);
	}
	uuid = argv[1];
	var = argv[2];
	if (efi_name_to_guid(uuid, &guid) == false) {
		printf("Invalid uuid %s\n", uuid);
		return (CMD_ERROR);
	}
	cpy8to16(var, wvar, nitems(wvar));
#if defined(ENABLE_UPDATES)
	err = RS->SetVariable(wvar, &guid, 0, 0, NULL);
	if (EFI_ERROR(err)) {
		printf("Failed to unset variable: error %lu\n",
		    DECODE_ERROR(err));
		return (CMD_ERROR);
	}
#else
	printf("would unset %s %s \n", uuid, var);
#endif
	return (CMD_OK);
}

/*
 * Loader interaction words and extras
 *
 *	efi-setenv  ( value n name n guid n attr -- 0 | -1)
 *	efi-getenv  ( guid n addr n -- addr' n' | -1 )
 *	efi-unsetenv ( name n guid n'' -- )
 */

/*
 * efi-setenv
 *	efi-setenv  ( value n name n guid n attr -- 0 | -1)
 *
 * Set environment variables using the SetVariable EFI runtime service.
 *
 * Value and guid are passed through in binary form (so guid needs to be
 * converted to binary form from its string form). Name is converted from
 * ASCII to CHAR16. Since ficl doesn't have support for internationalization,
 * there's no native CHAR16 interface provided.
 *
 * attr is an int in the bitmask of the following attributes for this variable.
 *
 *	1	Non volatile
 *	2	Boot service access
 *	4	Run time access
 * (corresponding to the same bits in the UEFI spec).
 */
static void
ficlEfiSetenv(ficlVm *pVM)
{
	char	*value = NULL, *guid = NULL;
	CHAR16	*name = NULL;
	int	i;
	char	*namep, *valuep, *guidp;
	int	names, values, guids, attr;
	EFI_STATUS status;
	uuid_t	u;
	uint32_t ustatus;
	char	*error = NULL;
	ficlStack *pStack = ficlVmGetDataStack(pVM);

	FICL_STACK_CHECK(pStack, 6, 0);

	attr = ficlStackPopInteger(pStack);
	guids = ficlStackPopInteger(pStack);
	guidp = (char *)ficlStackPopPointer(pStack);
	names = ficlStackPopInteger(pStack);
	namep = (char *)ficlStackPopPointer(pStack);
	values = ficlStackPopInteger(pStack);
	valuep = (char *)ficlStackPopPointer(pStack);

	guid = ficlMalloc(guids);
	if (guid == NULL)
		goto out;
	memcpy(guid, guidp, guids);
	uuid_from_string(guid, &u, &ustatus);
	if (ustatus != uuid_s_ok) {
		switch (ustatus) {
		case uuid_s_bad_version:
			error = "uuid: bad string";
			break;
		case uuid_s_invalid_string_uuid:
			error = "uuid: invalid string";
			break;
		case uuid_s_no_memory:
			error = "Out of memory";
			break;
		default:
			error = "uuid: Unknown error";
			break;
		}
		ficlStackPushInteger(pStack, -1);
		goto out;
	}

	name = ficlMalloc((names + 1) * sizeof (CHAR16));
	if (name == NULL) {
		error = "Out of memory";
		goto out;
	}
	for (i = 0; i < names; i++)
		name[i] = namep[i];
	name[names] = 0;

	value = ficlMalloc(values + 1);
	if (value == NULL) {
		error = "Out of memory";
		goto out;
	}
	memcpy(value, valuep, values);

	status = RS->SetVariable(name, (EFI_GUID *)&u, attr, values, value);
	if (status == EFI_SUCCESS) {
		ficlStackPushInteger(pStack, 0);
	} else {
		ficlStackPushInteger(pStack, -1);
		error = "Error: SetVariable failed";
	}

out:
	ficlFree(name);
	ficlFree(value);
	ficlFree(guid);
	if (error != NULL)
		ficlVmThrowError(pVM, error);
}

static void
ficlEfiGetenv(ficlVm *pVM)
{
	char	*name, *value;
	char	*namep;
	int	names;

	FICL_STACK_CHECK(ficlVmGetDataStack(pVM), 2, 2);

	names = ficlStackPopInteger(ficlVmGetDataStack(pVM));
	namep = (char *)ficlStackPopPointer(ficlVmGetDataStack(pVM));

	name = ficlMalloc(names+1);
	if (name == NULL)
		ficlVmThrowError(pVM, "Error: out of memory");
	strncpy(name, namep, names);
	name[names] = '\0';

	value = getenv(name);
	ficlFree(name);

	if (value != NULL) {
		ficlStackPushPointer(ficlVmGetDataStack(pVM), value);
		ficlStackPushInteger(ficlVmGetDataStack(pVM), strlen(value));
	} else {
		ficlStackPushInteger(ficlVmGetDataStack(pVM), -1);
	}
}

static void
ficlEfiUnsetenv(ficlVm *pVM)
{
	char	*name;
	char	*namep;
	int	names;

	FICL_STACK_CHECK(ficlVmGetDataStack(pVM), 2, 0);

	names = ficlStackPopInteger(ficlVmGetDataStack(pVM));
	namep = (char *)ficlStackPopPointer(ficlVmGetDataStack(pVM));

	name = ficlMalloc(names+1);
	if (name == NULL)
		ficlVmThrowError(pVM, "Error: out of memory");
	strncpy(name, namep, names);
	name[names] = '\0';

	unsetenv(name);
	ficlFree(name);
}

/*
 * Build platform extensions into the system dictionary
 */
static void
ficlEfiCompilePlatform(ficlSystem *pSys)
{
	ficlDictionary *dp = ficlSystemGetDictionary(pSys);

	FICL_SYSTEM_ASSERT(pSys, dp);

	ficlDictionarySetPrimitive(dp, "efi-setenv", ficlEfiSetenv,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dp, "efi-getenv", ficlEfiGetenv,
	    FICL_WORD_DEFAULT);
	ficlDictionarySetPrimitive(dp, "efi-unsetenv", ficlEfiUnsetenv,
	    FICL_WORD_DEFAULT);
}

FICL_COMPILE_SET(ficlEfiCompilePlatform);
