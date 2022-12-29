#include <ntddk.h>

// Exit function
NTSTATUS DriverUnload(_In_ PDRIVER_OBJECT driverObject) {
    UNREFERENCED_PARAMETER(driverObject);       // Parameter not used, mark it as unreferenced

    KdPrint(("Goodbye World!\n"));              // Print 'Goodbye World!' (debug mode only)
    return STATUS_SUCCESS;
}

// Entry function
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath) {
    UNREFERENCED_PARAMETER(registryPath);       // Parameter not used, mark it as unreferenced

    KdPrint(("Hello World!\n"));                // Print 'Hello World!' (debug mode only)
    driverObject->DriverUnload = DriverUnload;  // Map the unload routine to the 'DriverUnload' function

    return STATUS_SUCCESS;
}