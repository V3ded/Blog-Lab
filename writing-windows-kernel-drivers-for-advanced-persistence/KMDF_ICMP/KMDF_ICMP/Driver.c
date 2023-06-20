#include <ntddk.h>
#include "Trigger.h"

NTSTATUS UnloadDriver(_In_ PDRIVER_OBJECT driverObject) {
	UNREFERENCED_PARAMETER(driverObject);
	
	WfpCleanup();
	KdPrint(("Unloading the driver...\n"));

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(registryPath);

	KdPrint(("Loading the driver...\n"));
	driverObject->DriverUnload = UnloadDriver;

	if (!(NT_SUCCESS(WfpInit(driverObject)))) {
		KdPrint(("Driver failed to load!\n"));
		return STATUS_UNSUCCESSFUL;
	}
	KdPrint(("Driver loaded!\n"));

	return STATUS_SUCCESS;
}