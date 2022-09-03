/*
 Test for the FTL device which writes random data to sequential addresses

 Copyright (c) 2021 - current
 Authors:  Barger M.
*/

#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "./ftl.h"

int main(int argc, char **argv) {
    char *device_name = "nvme0n1";
    struct user_zns_device *my_dev = NULL;
    int status = 0;
    int lba_count = 0;
    char *write_buf = NULL;
    char *read_buf = NULL;

    // Seed RNG
    srand( (unsigned) time(NULL) * getpid());

    // Use argument as device name if one has been passed
    if(argc > 1){
        device_name = argv[1];
    }

    printf("[~] Testing FTL with writes to sequential adresses\n");

    // Open ZNS device and init the ftl
    if ( (status = init_szns_device(device_name, &my_dev)) != 0) {
        printf("[!!] Error: failed to open the szns device, ret 0x%04x \n", status);
        return status;
    }
    assert(my_dev->lba_size_bytes != 0);
    assert(my_dev->capacity_bytes != 0);

    // Fill whole device
    lba_count = my_dev->capacity_bytes / my_dev->lba_size_bytes;

    // Allocate write and read test buffers
    write_buf = (char *) calloc(lba_count, my_dev->lba_size_bytes);
    read_buf  = (char *) calloc(lba_count, my_dev->lba_size_bytes);

    // Generate random bytes for test
    for (size_t byte_idx = 0; byte_idx < lba_count * my_dev->lba_size_bytes; byte_idx++) {
    	write_buf[byte_idx] = rand();
    }

    // Perform writes on the device
    printf("[~] Writing random data to the device ...\n");
    char *curr_buf = write_buf;
    for (size_t lba_idx = 0; lba_idx < lba_count; lba_idx++) {
        if ( (status = szns_write(my_dev, lba_idx * my_dev->lba_size_bytes, curr_buf, my_dev->lba_size_bytes)) != 0) {
            printf("[!!] Error: failed to write to the zns device, ret 0x%04x \n", status);
            free(write_buf);
            free(read_buf);
            return status;
        }

        curr_buf += my_dev->lba_size_bytes;
    }
    printf("[~] Sucessfully wrote random data to the device\n");

    // Perform reads on the device
    printf("[~] Reading written data from the device ...\n");
    curr_buf = read_buf;
    for (size_t lba_idx = 0; lba_idx < lba_count; lba_idx++) {
        if ( (status = szns_read(my_dev, lba_idx * my_dev->lba_size_bytes, curr_buf, my_dev->lba_size_bytes)) != 0) {
            printf("[!!] Error: failed to read from the zns device, ret 0x%04x \n", status);
            free(write_buf);
            free(read_buf);
            return status;
        }

        curr_buf += my_dev->lba_size_bytes;
    }
    printf("[~] Successfully read data from the device\n\n");

    // Compare read data to written data
    printf("[~] Comparing read data to written data...\n");
    for (size_t byte_idx = 0; byte_idx < my_dev->lba_size_bytes; byte_idx++) {
        if (write_buf[byte_idx] != read_buf[byte_idx]) {
            printf("[!] FAILURE: Byte mismatch at position %lu -> Expected: 0x%02hhx | Got: 0x%02hhx\n",
                    byte_idx, write_buf[byte_idx], read_buf[byte_idx]);

            free(write_buf);
            free(read_buf);
            return EXIT_FAILURE;
        }
    }

    printf("[~] SUCCESS: Read data matches written data, sequential read/write test passed.\n");

    free(write_buf);
    free(read_buf);
    return deinit_szns_device(my_dev);
}
