/*
 A simple FTL implementation

 Copyright (c) 2021 - current
 Authors:  Barger M.
*/

#ifndef FTL_H
#define FTL_H

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libnvme.h>

// Percentage of the device allocated to the log
#define LOG_SPACE_PRCNT     ( (size_t) 10 )

// Block IDs for FTL persistency
#define P_PRIV_DATA_LBA     ( (size_t) 0x00 )
#define P_ZONE_MAP_LBA      ( (size_t) 0x01 )
#define P_LOG_MAP_SLBA      ( (size_t) 0x02 )

// DEBUG zone prints on merge
#define DEBUG_ZONE_PRINT 1

/* Structs and enums */

// Struct containing the ZNS device management data
typedef struct user_zns_device {
    uint32_t lba_size_bytes;
    uint64_t capacity_bytes;
    void *_private;
} user_zns_device;

// Possible zone states
typedef enum {
    FTL_ZONE_UNUSED         = 0x00,
    FTL_ZONE_FULL           = 0x01,
    FTL_ZONE_DATA           = 0x02,
    FTL_ZONE_LOG            = 0x04,
    FTL_ZONE_LOG_ACTIVE     = 0x08,
    FTL_ZONE_PERSISTENCY    = 0x10,
} zone_state;

// FTL mapping flags/states
typedef enum mapping_flags {
    FTL_MAP_INVALID     = 0x00,
    FTL_MAP_VALID       = 0x01,
    FTL_MAP_FRESH       = 0x02,
} mapping_flags;

// Log zone mapping
typedef struct {
    uint32_t lba;           // Logical Block Address
    uint32_t pba;           // Physical Block Address
    mapping_flags flags;    // Flags
} log_zone_map;

// Union that represents the mapping of a given zone (data or log)
typedef union {
    uint64_t lzn;	// Data zones are mapped 1:1 physical to logical
    log_zone_map *log;	// Map of log zone mappings
} map;

// Struct describing a zone including its state
typedef struct {
    zone_state state;       // State of the zone
    map mapping;            // Mapping current zone - i.e. data or log
    uint64_t pzn;           // Physical Zone Number
    uint64_t pec;           // Program/Erase cycles
} zone;

// Private FTL data, used to manage the device
typedef struct {
    int fd;                 // fd of the device
    uint32_t nsid;          // Namespace id
    uint64_t nzones;        // Number of zones
    uint64_t zone_size;     // Size of a zone in blocks
    uint32_t log_size;      // Size of the log in zones

    zone *zones;            // Array of zones

    pthread_t gc_tid;           // GC Thread id
    pthread_attr_t gc_tattr;    // GC Thread attributes
    pthread_mutex_t ftl_mutex;  // Mutex for working of ftl data
} ftl_data;


/* Function prototypes */

// Initializes the ZNS device identified by name and returns a control struct
int init_szns_device(char *name, struct user_zns_device **my_dev);

// Reads contiguous data from the device identified by the start address and the size in bytes
int szns_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size);

// Writes data to the device, where address specifies the destination and size the size in bytes
int szns_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size);

// Deinitializes the ZNS device and fress used memory
int deinit_szns_device(struct user_zns_device *my_dev);

#endif // FTL_H
