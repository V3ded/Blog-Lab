#pragma once

/*
*	Note:
*	If the linker complains, add the following additional dependencies:
*	- $(DDK_LIB_PATH)\fwpkclnt.lib
*	- $(DDK_LIB_PATH)\ndis.lib
*	- $(SDK_LIB_PATH)\uuid.lib
*/

// Network driver headers
#define NDIS630
#include <ndis.h>

// WFP headers
#include <fwpmk.h>
#include <fwpsk.h>
#include <fwpmu.h>

// GUID headers
// https://www.gamedev.net/forums/topic/18905-initguid-an-explanation/
#define INITGUID
#include <guiddef.h>

/*
*	Generate random GUIDs:
*		- a7e76cdd-5b2e-4ffd-a89d-f569911756e7	(Sub-layer GUID)
*		- 8aadb11d-e10e-480d-a669-61dbcc8658e6	(Callout GUID)
*/
DEFINE_GUID(SUB_LAYER_GUID, 0xa7e76cdd, 0x5b2e, 0x4ffd, 0xa8, 0x9d, 0xf5, 0x69, 0x91, 0x17, 0x56, 0xe7);
DEFINE_GUID(CALLOUT_GUID, 0x8aadb11d, 0xe10e, 0x480d, 0xa6, 0x69, 0x61, 0xdb, 0xcc, 0x86, 0x58, 0xe6);

PDEVICE_OBJECT  filterDeviceObject;	// Device object for the filter engine
HANDLE          engineHandle;		// Handle to the filter engine
UINT32		    registerCalloutId;  // Identifier of the added callout
UINT32		    addCalloutId;		// Identifier of the added callout
UINT64		    filterId;			// Identifier of the added filter

NTSTATUS		WfpInit(PDRIVER_OBJECT driverObject);

NTSTATUS		CalloutRegister();
NTSTATUS		CalloutAdd();

VOID			CalloutFilter(const FWPS_INCOMING_VALUES* inFixedValues, const FWPS_INCOMING_METADATA_VALUES* inMetaValues, void* layerData, const void* classifyContext, const FWPS_FILTER* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT* classifyOut);
NTSTATUS		CalloutNotify(FWPS_CALLOUT_NOTIFY_TYPE notifyType, const GUID* filterKey, FWPS_FILTER* filter);

NTSTATUS		SublayerAdd();
NTSTATUS		FilterAdd();

VOID			TermFilterDeviceObject();
VOID			TermCalloutData();
VOID			TermWfpEngine();
VOID			WfpCleanup();