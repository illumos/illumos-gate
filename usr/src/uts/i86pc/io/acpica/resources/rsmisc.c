/*******************************************************************************
 *
 * Module Name: rsmisc - Miscellaneous resource descriptors
 *              $Revision: 1.34 $
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

#define __RSMISC_C__

#include "acpi.h"
#include "acresrc.h"

#define _COMPONENT          ACPI_RESOURCES
        ACPI_MODULE_NAME    ("rsmisc")


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetGenericReg
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
AcpiRsGetGenericReg (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetGenericReg");


    /*
     * Get the following fields from the AML descriptor:
     * Address Space ID
     * Register Bit Width
     * Register Bit Offset
     * Access Size
     * Register Address
     */
    Resource->Data.GenericReg.SpaceId = Aml->GenericReg.AddressSpaceId;
    Resource->Data.GenericReg.BitWidth = Aml->GenericReg.BitWidth;
    Resource->Data.GenericReg.BitOffset = Aml->GenericReg.BitOffset;
    Resource->Data.GenericReg.AccessSize = Aml->GenericReg.AccessSize;
    ACPI_MOVE_64_TO_64 (&Resource->Data.GenericReg.Address,
        &Aml->GenericReg.Address);

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_GENERIC_REGISTER;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_GENERIC_REGISTER);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetGenericReg
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
AcpiRsSetGenericReg (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetGenericReg");


    /*
     * Set the following fields in the AML descriptor:
     * Address Space ID
     * Register Bit Width
     * Register Bit Offset
     * Access Size
     * Register Address
     */
    Aml->GenericReg.AddressSpaceId = (UINT8) Resource->Data.GenericReg.SpaceId;
    Aml->GenericReg.BitWidth = (UINT8) Resource->Data.GenericReg.BitWidth;
    Aml->GenericReg.BitOffset = (UINT8) Resource->Data.GenericReg.BitOffset;
    Aml->GenericReg.AccessSize = (UINT8) Resource->Data.GenericReg.AccessSize;
    ACPI_MOVE_64_TO_64 (&Aml->GenericReg.Address,
        &Resource->Data.GenericReg.Address);

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_GENERIC_REGISTER,
        sizeof (AML_RESOURCE_GENERIC_REGISTER), Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetVendor
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
AcpiRsGetVendor (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    UINT8                   *AmlByteData;


    ACPI_FUNCTION_TRACE ("RsGetVendor");


    /* Determine if this is a large or small vendor specific item */

    if (Aml->LargeHeader.DescriptorType & ACPI_RESOURCE_NAME_LARGE)
    {
        /* Large item, Point to the first vendor byte */

        AmlByteData = ((UINT8 *) Aml) + sizeof (AML_RESOURCE_LARGE_HEADER);
    }
    else
    {
        /* Small item, Point to the first vendor byte */

        AmlByteData = ((UINT8 *) Aml) + sizeof (AML_RESOURCE_SMALL_HEADER);
    }

    /* Copy the vendor-specific bytes */

    ACPI_MEMCPY (Resource->Data.Vendor.ByteData,
        AmlByteData, AmlResourceLength);
    Resource->Data.Vendor.ByteLength = AmlResourceLength;

    /*
     * In order for the StructSize to fall on a 32-bit boundary,
     * calculate the length of the vendor string and expand the
     * StructSize to the next 32-bit boundary.
     */
    Resource->Type = ACPI_RESOURCE_TYPE_VENDOR;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_VENDOR) +
                       ACPI_ROUND_UP_TO_32BITS (AmlResourceLength);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetVendor
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
AcpiRsSetVendor (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    UINT32                  ResourceLength;
    UINT8                   *Source;
    UINT8                   *Destination;


    ACPI_FUNCTION_TRACE ("RsSetVendor");


    ResourceLength = Resource->Data.Vendor.ByteLength;
    Source = ACPI_CAST_PTR (UINT8, Resource->Data.Vendor.ByteData);

    /* Length determines if this is a large or small resource */

    if (ResourceLength > 7)
    {
        /* Large item, get pointer to the data part of the descriptor */

        Destination = ((UINT8 *) Aml) + sizeof (AML_RESOURCE_LARGE_HEADER);

        /* Complete the AML descriptor header */

        AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_VENDOR_LARGE,
            (UINT32) (ResourceLength + sizeof (AML_RESOURCE_LARGE_HEADER)), Aml);
    }
    else
    {
        /* Small item, get pointer to the data part of the descriptor */

        Destination = ((UINT8 *) Aml) + sizeof (AML_RESOURCE_SMALL_HEADER);

        /* Complete the AML descriptor header */

        AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_VENDOR_SMALL,
            (UINT32) (ResourceLength + sizeof (AML_RESOURCE_SMALL_HEADER)), Aml);
    }

    /* Copy the vendor-specific bytes */

    ACPI_MEMCPY (Destination, Source, ResourceLength);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetStartDpf
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
AcpiRsGetStartDpf (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetStartDpf");


    /* Get the flags byte if present */

    if (AmlResourceLength == 1)
    {
        /* Get the Compatibility priority */

        Resource->Data.StartDpf.CompatibilityPriority =
            (Aml->StartDpf.Flags & 0x03);

        if (Resource->Data.StartDpf.CompatibilityPriority >= 3)
        {
            return_ACPI_STATUS (AE_AML_BAD_RESOURCE_VALUE);
        }

        /* Get the Performance/Robustness preference */

        Resource->Data.StartDpf.PerformanceRobustness =
            ((Aml->StartDpf.Flags >> 2) & 0x03);

        if (Resource->Data.StartDpf.PerformanceRobustness >= 3)
        {
            return_ACPI_STATUS (AE_AML_BAD_RESOURCE_VALUE);
        }
    }
    else
    {
        /* StartDependentNoPri(), no flags byte, set defaults */

        Resource->Data.StartDpf.CompatibilityPriority =
            ACPI_ACCEPTABLE_CONFIGURATION;

        Resource->Data.StartDpf.PerformanceRobustness =
            ACPI_ACCEPTABLE_CONFIGURATION;
    }

    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_START_DEPENDENT;
    Resource->Length = ACPI_SIZEOF_RESOURCE (ACPI_RESOURCE_START_DEPENDENT);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetStartDpf
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
AcpiRsSetStartDpf (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetStartDpf");


    /*
     * The descriptor type field is set based upon whether a byte is needed
     * to contain Priority data.
     */
    if (ACPI_ACCEPTABLE_CONFIGURATION ==
            Resource->Data.StartDpf.CompatibilityPriority &&
        ACPI_ACCEPTABLE_CONFIGURATION ==
            Resource->Data.StartDpf.PerformanceRobustness)
    {
        AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_START_DEPENDENT,
            sizeof (AML_RESOURCE_START_DEPENDENT_NOPRIO), Aml);
    }
    else
    {
        AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_START_DEPENDENT,
            sizeof (AML_RESOURCE_START_DEPENDENT), Aml);

        /* Set the Flags byte */

        Aml->StartDpf.Flags = (UINT8)
            (((Resource->Data.StartDpf.PerformanceRobustness & 0x03) << 2) |
              (Resource->Data.StartDpf.CompatibilityPriority & 0x03));
    }
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetEndDpf
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
AcpiRsGetEndDpf (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetEndDpf");


    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_END_DEPENDENT;
    Resource->Length = (UINT32) ACPI_RESOURCE_LENGTH;
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetEndDpf
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
AcpiRsSetEndDpf (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetEndDpf");


    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_END_DEPENDENT,
        sizeof (AML_RESOURCE_END_DEPENDENT), Aml);
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsGetEndTag
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
AcpiRsGetEndTag (
    AML_RESOURCE            *Aml,
    UINT16                  AmlResourceLength,
    ACPI_RESOURCE           *Resource)
{
    ACPI_FUNCTION_TRACE ("RsGetEndTag");


    /* Complete the resource header */

    Resource->Type = ACPI_RESOURCE_TYPE_END_TAG;
    Resource->Length = ACPI_RESOURCE_LENGTH;
    return_ACPI_STATUS (AE_OK);
}


/*******************************************************************************
 *
 * FUNCTION:    AcpiRsSetEndTag
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
AcpiRsSetEndTag (
    ACPI_RESOURCE           *Resource,
    AML_RESOURCE            *Aml)
{
    ACPI_FUNCTION_TRACE ("RsSetEndTag");


    /*
     * Set the Checksum - zero means that the resource data is treated as if
     * the checksum operation succeeded (ACPI Spec 1.0b Section 6.4.2.8)
     */
    Aml->EndTag.Checksum = 0;

    /* Complete the AML descriptor header */

    AcpiRsSetResourceHeader (ACPI_RESOURCE_NAME_END_TAG,
        sizeof (AML_RESOURCE_END_TAG), Aml);
    return_ACPI_STATUS (AE_OK);
}


