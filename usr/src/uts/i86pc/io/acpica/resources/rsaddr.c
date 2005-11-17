/*******************************************************************************
 *
 * Module Name: rsaddr - Address resource descriptors (16/32/64)
 *              $Revision: 1.47 $
 *
 ******************************************************************************/

/******************************************************************************
 *
 * 1. Copyright Notice
 *
 * Some or all of this work - Copyright (c) 1999 - 2005, Intel Corp.
 * All rights reserved.
 *
 * 2. License
 *
 * 2.1. This is your license from Intel Corp. under its intellectual property
 * rights.  You may have additional license terms from the party that provided
 * you this software, covering your right to use that party's intellectual
 * property rights.
 *
 * 2.2. Intel grants, free of charge, to any person ("Licensee") obtaining a
 * copy of the source code appearing in this file ("Covered Code") an
 * irrevocable, perpetual, worldwide license under Intel's copyrights in the
 * base code distributed originally by Intel ("Original Intel Code") to copy,
 * make derivatives, distribute, use and display any portion of the Covered
 * Code in any form, with the right to sublicense such rights; and
 *
 * 2.3. Intel grants Licensee a non-exclusive and non-transferable patent
 * license (with the right to sublicense), under only those claims of Intel
 * patents that are infringed by the Original Intel Code, to make, use, sell,
 * offer to sell, and import the Covered Code and derivative works thereof
 * solely to the minimum extent necessary to exercise the above copyright
 * license, and in no event shall the patent license extend to any additions
 * to or modifications of the Original Intel Code.  No other license or right
 * is granted directly or by implication, estoppel or otherwise;
 *
 * The above copyright and patent license is granted only if the following
 * conditions are met:
 *
 * 3. Conditions
 *
 * 3.1. Redistribution of Source with Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification with rights to further distribute source must include
 * the above Copyright Notice, the above License, this list of Conditions,
 * and the following Disclaimer and Export Compliance provision.  In addition,
 * Licensee must cause all Covered Code to which Licensee contributes to
 * contain a file documenting the changes Licensee made to create that Covered
 * Code and the date of any change.  Licensee must include in that file the
 * documentation of any changes made by any predecessor Licensee.  Licensee
 * must include a prominent statement that the modification is derived,
 * directly or indirectly, from Original Intel Code.
 *
 * 3.2. Redistribution of Source with no Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification without rights to further distribute source must
 * include the following Disclaimer and Export Compliance provision in the
 * documentation and/or other materials provided with distribution.  In
 * addition, Licensee may not authorize further sublicense of source of any
 * portion of the Covered Code, and must include terms to the effect that the
 * license from Licensee to its licensee is limited to the intellectual
 * property embodied in the software Licensee provides to its licensee, and
 * not to intellectual property embodied in modifications its licensee may
 * make.
 *
 * 3.3. Redistribution of Executable. Redistribution in executable form of any
 * substantial portion of the Covered Code or modification must reproduce the
 * above Copyright Notice, and the following Disclaimer and Export Compliance
 * provision in the documentation and/or other materials provided with the
 * distribution.
 *
 * 3.4. Intel retains all right, title, and interest in and to the Original
 * Intel Code.
 *
 * 3.5. Neither the name Intel nor any other trademark owned or controlled by
 * Intel shall be used in advertising or otherwise to promote the sale, use or
 * other dealings in products derived from or relating to the Covered Code
 * without prior written authorization from Intel.
 *
 * 4. Disclaimer and Export Compliance
 *
 * 4.1. INTEL MAKES NO WARRANTY OF ANY KIND REGARDING ANY SOFTWARE PROVIDED
 * HERE.  ANY SOFTWARE ORIGINATING FROM INTEL OR DERIVED FROM INTEL SOFTWARE
 * IS PROVIDED "AS IS," AND INTEL WILL NOT PROVIDE ANY SUPPORT,  ASSISTANCE,
 * INSTALLATION, TRAINING OR OTHER SERVICES.  INTEL WILL NOT PROVIDE ANY
 * UPDATES, ENHANCEMENTS OR EXTENSIONS.  INTEL SPECIFICALLY DISCLAIMS ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * 4.2. IN NO EVENT SHALL INTEL HAVE ANY LIABILITY TO LICENSEE, ITS LICENSEES
 * OR ANY OTHER THIRD PARTY, FOR ANY LOST PROFITS, LOST DATA, LOSS OF USE OR
 * COSTS OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, OR FOR ANY INDIRECT,
 * SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THIS AGREEMENT, UNDER ANY
 * CAUSE OF ACTION OR THEORY OF LIABILITY, AND IRRESPECTIVE OF WHETHER INTEL
 * HAS ADVANCE NOTICE OF THE POSSIBILITY OF SUCH DAMAGES.  THESE LIMITATIONS
 * SHALL APPLY NOTWITHSTANDING THE FAILURE OF THE ESSENTIAL PURPOSE OF ANY
 * LIMITED REMEDY.
 *
 * 4.3. Licensee shall not export, either directly or indirectly, any of this
 * software or system incorporating such software without first obtaining any
 * required license or other approval from the U. S. Department of Commerce or
 * any other agency or department of the United States Government.  In the
 * event Licensee exports any such software from the United States or
 * re-exports any such software from a foreign destination, Licensee shall
 * ensure that the distribution and export/re-export of the software is in
 * compliance with all laws, regulations, orders, or other restrictions of the
 * U.S. Export Administration Regulations. Licensee agrees that neither it nor
 * any of its subsidiaries will export/re-export any technical data, process,
 * software, or service, directly or indirectly, to any country for which the
 * United States government or any agency thereof requires an export license,
 * other governmental approval, or letter of assurance, without first obtaining
 * such license, approval or letter.
 *
 *****************************************************************************/

#define __RSADDR_C__

#include "acpi.h"
#include "acresrc.h"

#define _COMPONENT          ACPI_RESOURCES
        ACPI_MODULE_NAME    ("rsaddr")


/* Local prototypes */

static void
AcpiRsDecodeGeneralFlags (
    ACPI_RESOURCE_DATA      *Resource,
    UINT8                   Flags);

static UINT8
AcpiRsEncodeGeneralFlags (
    ACPI_RESOURCE_DATA      *Resource);

static void
AcpiRsDecodeSpecificFlags (
    ACPI_RESOURCE_DATA      *Resource,
    UINT8                   Flags);

static UINT8
AcpiRsEncodeSpecificFlags (
    ACPI_RESOURCE_DATA      *Resource);

static void
AcpiRsSetAddressCommon (
    AML_RESOURCE            *Aml,
    ACPI_RESOURCE           *Resource);

static BOOLEAN
AcpiRsGetAddressCommon (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml);


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDecodeGeneralFlags
 *
 * PARAMETERS:  Resource            - Address resource data struct
 *              Flags               - Raw AML flag byte
 *
 * RETURN:      Decoded flag bits in resource struct
 *
 * DESCRIPTION: Decode a general flag byte to an address resource struct
 *
 ******************************************************************************/

static void
AcpiRsDecodeGeneralFlags (
    ACPI_RESOURCE_DATA      *Resource,
    UINT8                   Flags)
{
    ACPI_FUNCTION_ENTRY ();


    /* Producer / Consumer - flag bit[0] */

    Resource->Address.ProducerConsumer = (UINT32) (Flags & 0x01);

    /* Decode (_DEC) - flag bit[1] */

    Resource->Address.Decode = (UINT32) ((Flags >> 1) & 0x01);

    /* Min Address Fixed (_MIF) - flag bit[2] */

    Resource->Address.MinAddressFixed = (UINT32) ((Flags >> 2) & 0x01);

    /* Max Address Fixed (_MAF) - flag bit[3] */

    Resource->Address.MaxAddressFixed = (UINT32) ((Flags >> 3) & 0x01);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsEncodeGeneralFlags
 *
 * PARAMETERS:  Resource            - Address resource data struct
 *
 * RETURN:      Encoded general flag byte
 *
 * DESCRIPTION: Construct a general flag byte from an address resource struct
 *
 ******************************************************************************/

static UINT8
AcpiRsEncodeGeneralFlags (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    return ((UINT8)

        /* Producer / Consumer - flag bit[0] */

        ((Resource->Address.ProducerConsumer & 0x01) |

        /* Decode (_DEC) - flag bit[1] */

        ((Resource->Address.Decode & 0x01) << 1) |

        /* Min Address Fixed (_MIF) - flag bit[2] */

        ((Resource->Address.MinAddressFixed & 0x01) << 2) |

        /* Max Address Fixed (_MAF) - flag bit[3] */

        ((Resource->Address.MaxAddressFixed & 0x01) << 3))
    );
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsDecodeSpecificFlags
 *
 * PARAMETERS:  Resource            - Address resource data struct
 *              Flags               - Raw AML flag byte
 *
 * RETURN:      Decoded flag bits in attribute struct
 *
 * DESCRIPTION: Decode a type-specific flag byte to an attribute struct.
 *              Type-specific flags are only defined for the Memory and IO
 *              resource types.
 *
 ******************************************************************************/

static void
AcpiRsDecodeSpecificFlags (
    ACPI_RESOURCE_DATA      *Resource,
    UINT8                   Flags)
{
    ACPI_FUNCTION_ENTRY ();


    if (Resource->Address.ResourceType == ACPI_MEMORY_RANGE)
    {
        /* Write Status (_RW) - flag bit[0] */

        Resource->Address.Attribute.Memory.ReadWriteAttribute =
            (UINT16) (Flags & 0x01);

        /* Memory Attributes (_MEM) - flag bits[2:1] */

        Resource->Address.Attribute.Memory.CacheAttribute =
            (UINT16) ((Flags >> 1) & 0x03);
    }
    else if (Resource->Address.ResourceType == ACPI_IO_RANGE)
    {
        /* Ranges (_RNG) - flag bits[1:0] */

        Resource->Address.Attribute.Io.RangeAttribute =
            (UINT16) (Flags & 0x03);

        /* Translations (_TTP and _TRS) - flag bits[5:4] */

        Resource->Address.Attribute.Io.TranslationAttribute =
            (UINT16) ((Flags >> 4) & 0x03);
    }
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsEncodeSpecificFlags
 *
 * PARAMETERS:  Resource            - Address resource data struct
 *
 * RETURN:      Encoded type-specific flag byte
 *
 * DESCRIPTION: Construct a type-specific flag byte from an attribute struct.
 *              Type-specific flags are only defined for the Memory and IO
 *              resource types.
 *
 ******************************************************************************/

static UINT8
AcpiRsEncodeSpecificFlags (
    ACPI_RESOURCE_DATA      *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    if (Resource->Address.ResourceType == ACPI_MEMORY_RANGE)
    {
        return ((UINT8)

            /* Write Status (_RW) - flag bit[0] */

            ((Resource->Address.Attribute.Memory.ReadWriteAttribute & 0x01) |

            /* Memory Attributes (_MEM) - flag bits[2:1] */

            ((Resource->Address.Attribute.Memory.CacheAttribute & 0x03) << 1)));
    }
    else if (Resource->Address.ResourceType == ACPI_IO_RANGE)
    {
        return ((UINT8)

            /* Ranges (_RNG) - flag bits[1:0] */

            ((Resource->Address.Attribute.Io.RangeAttribute & 0x03) |

            /* Translations (_TTP and _TRS) - flag bits[5:4] */

            ((Resource->Address.Attribute.Io.TranslationAttribute & 0x03) << 4)));
    }

    return (0);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetAddressCommon
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              Resource            - Pointer to the internal resource struct
 *
 * RETURN:      None
 *
 * DESCRIPTION: Convert common flag fields from a resource descriptor to an
 *              AML descriptor
 *
 ******************************************************************************/

static void
AcpiRsSetAddressCommon (
    AML_RESOURCE            *Aml,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_ENTRY ();


    /* Set the Resource Type (Memory, Io, BusNumber, etc.) */

    Aml->Address.ResourceType = (UINT8) Resource->Data.Address.ResourceType;

    /* Set the general flags */

    Aml->Address.Flags = AcpiRsEncodeGeneralFlags (&Resource->Data);

    /* Set the type-specific flags */

    Aml->Address.SpecificFlags = AcpiRsEncodeSpecificFlags (&Resource->Data);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetAddressCommon
 *
 * PARAMETERS:  Resource            - Pointer to the internal resource struct
 *              Aml                 - Pointer to the AML resource descriptor
 *
 * RETURN:      TRUE if the ResourceType field is OK, FALSE otherwise
 *
 * DESCRIPTION: Convert common flag fields from a raw AML resource descriptor
 *              to an internal resource descriptor
 *
 ******************************************************************************/

static BOOLEAN
AcpiRsGetAddressCommon (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_ENTRY ();


    /* Validate resource type */

    if ((Aml->Address.ResourceType > 2) && (Aml->Address.ResourceType < 0xC0))
    {
        return (FALSE);
    }

    /* Get the Resource Type (Memory, Io, BusNumber, etc.) */

    Resource->Data.Address.ResourceType = Aml->Address.ResourceType;

    /* Get the General Flags */

    AcpiRsDecodeGeneralFlags (&Resource->Data, Aml->Address.Flags);

    /* Get the Type-Specific Flags */

    AcpiRsDecodeSpecificFlags (&Resource->Data, Aml->Address.SpecificFlags);
    return (TRUE);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetAddress16
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetAddress16 (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetAddress16");


    /* Get the Resource Type, general flags, and type-specific flags */

    if (!AcpiRsGetAddressCommon (Resource, Aml))
    {
        return_ACPI_STATUS (AE_AML_INVALID_RESOURCE_TYPE);
    }

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     */
    AcpiRsMoveData (&Resource->Data.Address16.Granularity,
        &Aml->Address16.Granularity, 5, ACPI_MOVE_TYPE_16_TO_32);

    /* Get the optional ResourceSource (index and string) */

    Resource->Length = 
        ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_ADDRESS16) +

        AcpiRsGetResourceSource (AmlResourceLength,
            sizeof (AML_RESOURCE_ADDRESS16),
            &Resource->Data.Address16.ResourceSource, Aml, NULL);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_ADDRESS16;
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetAddress16
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetAddress16 (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_SIZE               DescriptorLength;


    ACPI_FUNCTION_TRACE ("RsSetAddress16");


    /* Set the Resource Type, General Flags, and Type-Specific Flags */

    AcpiRsSetAddressCommon (Aml, Resource);

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     */
    AcpiRsMoveData (&Aml->Address16.Granularity,
        &Resource->Data.Address16.Granularity, 5, ACPI_MOVE_TYPE_32_TO_16);

    /* Resource Source Index and Resource Source are optional */

    DescriptorLength = AcpiRsSetResourceSource (Aml,
                            sizeof (AML_RESOURCE_ADDRESS16),
                            &Resource->Data.Address16.ResourceSource);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_ADDRESS16, DescriptorLength, Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetAddress32
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetAddress32 (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{

    ACPI_FUNCTION_TRACE ("RsGetAddress32");


    /* Get the Resource Type, general flags, and type-specific flags */

    if (!AcpiRsGetAddressCommon (Resource, (void *) Aml))
    {
        return_ACPI_STATUS (AE_AML_INVALID_RESOURCE_TYPE);
    }

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     */
    AcpiRsMoveData (&Resource->Data.Address32.Granularity,
        &Aml->Address32.Granularity, 5, ACPI_MOVE_TYPE_32_TO_32);

    /* Get the optional ResourceSource (index and string) */

    Resource->Length =
        ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_ADDRESS32) +

        AcpiRsGetResourceSource (AmlResourceLength,
            sizeof (AML_RESOURCE_ADDRESS32),
            &Resource->Data.Address32.ResourceSource, Aml, NULL);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_ADDRESS32;
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetAddress32
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetAddress32 (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_SIZE               DescriptorLength;


    ACPI_FUNCTION_TRACE ("RsSetAddress32");


    /* Set the Resource Type, General Flags, and Type-Specific Flags */

    AcpiRsSetAddressCommon (Aml, Resource);

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     */
    AcpiRsMoveData (&Aml->Address32.Granularity,
        &Resource->Data.Address32.Granularity, 5, ACPI_MOVE_TYPE_32_TO_32);

    /* Resource Source Index and Resource Source are optional */

    DescriptorLength = AcpiRsSetResourceSource (Aml,
                            sizeof (AML_RESOURCE_ADDRESS32),
                            &Resource->Data.Address32.ResourceSource);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_ADDRESS32, DescriptorLength, Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetAddress64
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetAddress64 (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetAddress64");


    /* Get the Resource Type, general Flags, and type-specific Flags */

    if (!AcpiRsGetAddressCommon (Resource, Aml))
    {
        return_ACPI_STATUS (AE_AML_INVALID_RESOURCE_TYPE);
    }

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     */
    AcpiRsMoveData (&Resource->Data.Address64.Granularity,
        &Aml->Address64.Granularity, 5, ACPI_MOVE_TYPE_64_TO_64);

    /* Get the optional ResourceSource (index and string) */

    Resource->Length = 
        ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_ADDRESS64) +

        AcpiRsGetResourceSource (AmlResourceLength,
            sizeof (AML_RESOURCE_ADDRESS64),
            &Resource->Data.Address64.ResourceSource, Aml, NULL);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_ADDRESS64;
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetAddress64
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetAddress64 (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_SIZE               DescriptorLength;


    ACPI_FUNCTION_TRACE ("RsSetAddress64");


    /* Set the Resource Type, General Flags, and Type-Specific Flags */

    AcpiRsSetAddressCommon (Aml, Resource);

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     */
    AcpiRsMoveData (&Aml->Address64.Granularity,
        &Resource->Data.Address64.Granularity, 5, ACPI_MOVE_TYPE_64_TO_64);

    /* Resource Source Index and Resource Source are optional */

    DescriptorLength = AcpiRsSetResourceSource (Aml,
                            sizeof (AML_RESOURCE_ADDRESS64),
                            &Resource->Data.Address64.ResourceSource);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_ADDRESS64, DescriptorLength, Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetExtAddress64
 *
 * PARAMETERS:  Aml                 - Pointer to the AML resource descriptor
 *              AmlResourceLength   - Length of the resource from the AML header
 *              Resource            - Where the internal resource is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert a raw AML resource descriptor to the corresponding
 *              internal resource descriptor, simplifying bitflags and handling
 *              alignment and endian issues if necessary.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsGetExtAddress64 (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{

    ACPI_FUNCTION_TRACE ("RsGetExtAddress64");


    /* Get the Resource Type, general flags, and type-specific flags */

    if (!AcpiRsGetAddressCommon (Resource, Aml))
    {
        return_ACPI_STATUS (AE_AML_INVALID_RESOURCE_TYPE);
    }

    /*
     * Get and validate the Revision ID
     * Note: Only one revision ID is currently supported
     */
    Resource->Data.ExtAddress64.RevisionID = Aml->ExtAddress64.RevisionID;
    if (Aml->ExtAddress64.RevisionID != AML_RESOURCE_EXTENDED_ADDRESS_REVISION)
    {
        return_ACPI_STATUS (AE_SUPPORT);
    }

    /*
     * Get the following contiguous fields from the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     * Type-Specific Attribute
     */
    AcpiRsMoveData (&Resource->Data.ExtAddress64.Granularity,
        &Aml->ExtAddress64.Granularity, 6, ACPI_MOVE_TYPE_64_TO_64);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_EXTENDED_ADDRESS64);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetExtAddress64
 *
 * PARAMETERS:  Resource            - Pointer to the resource descriptor
 *              Aml                 - Where the AML descriptor is returned
 *
 * RETURN:      Status
 *
 * DESCRIPTION: Convert an internal resource descriptor to the corresponding
 *              external AML resource descriptor.
 *
 ******************************************************************************/

ACPI_STATUS
AcpiRsSetExtAddress64 (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetExtAddress64");


    /* Set the Resource Type, General Flags, and Type-Specific Flags */

    AcpiRsSetAddressCommon (Aml, Resource);

    /* Only one Revision ID is currently supported */

    Aml->ExtAddress64.RevisionID = AML_RESOURCE_EXTENDED_ADDRESS_REVISION;
    Aml->ExtAddress64.Reserved = 0;

    /*
     * Set the following contiguous fields in the AML descriptor:
     * Address Granularity
     * Address Range Minimum
     * Address Range Maximum
     * Address Translation Offset
     * Address Length
     * Type-Specific Attribute
     */
    AcpiRsMoveData (&Aml->ExtAddress64.Granularity,
        &Resource->Data.Address64.Granularity, 6, ACPI_MOVE_TYPE_64_TO_64);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_EXTENDED_ADDRESS64,
        sizeof (AML_RESOURCE_EXTENDED_ADDRESS64), Aml);
    return_ACPI_STATUS (AE_OK);
}

