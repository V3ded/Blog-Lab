#pragma once

/* Configuration variables */
BYTE PASSWORD[4] = { 0x71, 0x72, 0x73, 0x74 }; // Password used for the network trigger (needs to be EXACTLY 4 bytes)

/* Preprocessor  */
#pragma warning(disable: 4996)					// Ignore depracated function calls - used for ExAllocatePoolWithTag
#define ALLOC_TAG_NAME (ULONG)'TG_1'			// Tag to identify the memory pool