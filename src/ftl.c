/*
 A simple FTL implementation

 Copyright (c) 2021 - current
 Authors:  Barger M.
*/

#include "ftl.h"

// Magic number to identify FTL persistency data
#define MAGIC_NUM_LEN   ( (size_t) 8 )
const uint8_t magic_num_ftl[MAGIC_NUM_LEN] = {'s', 'f', 't', 'l', '-', 't', 'a', 'r'};

// Emergency GC request
static bool gc_emergency = false;

/* Private function prototypes */

static void print_zones(ftl_data *priv_data);
static bool log_map_set_pba_zid(ftl_data *priv_data, uint64_t lba, uint64_t pba, size_t zid);
static bool log_map_get_pba_zid(ftl_data *priv_data, uint64_t lba, uint64_t *pba, size_t zid);
static bool log_map_get_pba(ftl_data *priv_data, uint64_t lba, uint64_t *pba);
static bool data_map_get_pzn(ftl_data *priv_data, uint64_t lzn, uint64_t *pzn);
static int read_block(struct user_zns_device *my_dev, uint64_t pba, void *buffer);
static int write_block(struct user_zns_device *my_dev, uint64_t pba, void *buffer);
static void log_map_invalidate_th_zid(ftl_data *priv_data, uint64_t lba_limit, size_t zid);
static bool log_find_lowest_addr(ftl_data *priv_data, size_t zid, size_t *entry_idx);
static bool find_zone_with_state_wl(ftl_data *priv_data, zone_state state, size_t *zid);
static bool find_active_log_zone(ftl_data *priv_data, size_t *zid);
static int merge_log_to_data(struct user_zns_device *my_dev, size_t zid);
static void persist_ftl(struct user_zns_device *my_dev);
static bool restore_persisted_ftl(struct user_zns_device *my_dev);
static void *gc_main(void *arg);

/* Function definitions */

// Prints the zones status'
static void print_zones(ftl_data *priv_data) {
    system("clear");
    printf("Zones:\n");
    for(size_t zone_id = 0; zone_id < priv_data->nzones; ++zone_id) {
        printf(" - #%02ld | state: 0x%02x | pzn: 0x%010lx | pec: %4ld", zone_id, priv_data->zones[zone_id].state, priv_data->zones[zone_id].pzn, priv_data->zones[zone_id].pec);
        if (priv_data->zones[zone_id].state == FTL_ZONE_DATA) {
            printf(" | lzn: 0x%010lx", priv_data->zones[zone_id].mapping.lzn);
        } else if (priv_data->zones[zone_id].state & FTL_ZONE_LOG) {
            printf(" | log: @%p", priv_data->zones[zone_id].mapping.log);
        } else if (priv_data->zones[zone_id].state & FTL_ZONE_PERSISTENCY) {
            printf(" | ~persistency~");
        } else {
            printf(" | UNUSED");
        }
        printf("\n");
    }
    fflush(stdout);
}

// Persists the ftl onto the device
static void persist_ftl(struct user_zns_device *my_dev) {
    ftl_data *priv_data = (ftl_data *)my_dev->_private;

    // Write data to disk
    uint8_t *write_buf = (uint8_t *)calloc(1, my_dev->lba_size_bytes);
    if (write_buf == NULL) {
        fprintf(stderr, "[!!] Failed to allocate memory in persistency\n");
        return;
    }

    // Reset persistency zone to enable writing
    nvme_zns_mgmt_send(priv_data->fd, priv_data->nsid, 0, false, NVME_ZNS_ZSA_RESET, 0, NULL);
    priv_data->zones[0].pec++;

    // Write priv_data structure to the first zone
    // After the magic number used to identify persistent data
    memcpy(write_buf, magic_num_ftl, MAGIC_NUM_LEN);
    memcpy(write_buf + MAGIC_NUM_LEN, priv_data, sizeof(ftl_data));
    if (write_block(my_dev, P_PRIV_DATA_LBA, (void *)write_buf) != 0) {
        fprintf(stderr, "[!!] Error writing block for ftl persistency\n");
    }

    // Write the zone map to the device
    memset(write_buf, 0, my_dev->lba_size_bytes);
    memcpy(write_buf, priv_data->zones, sizeof(zone) * priv_data->nzones);
    if (write_block(my_dev, P_ZONE_MAP_LBA, (void *)write_buf) != 0) {
        fprintf(stderr, "[!!] Error writing block for ftl persistency\n");
    }

    // Write the log map(s) to the device
    size_t curr_log_lba = P_LOG_MAP_SLBA;
    for(size_t zone_id = 0; zone_id < priv_data->nzones; zone_id++) { 
        if (priv_data->zones[zone_id].state & FTL_ZONE_LOG) {
            memset(write_buf, 0, my_dev->lba_size_bytes);
            memcpy(write_buf, priv_data->zones[zone_id].mapping.log, priv_data->zone_size * sizeof(log_zone_map));
            if (write_block(my_dev, curr_log_lba, (void *)write_buf) != 0) {
                fprintf(stderr, "[!!] Error writing block for ftl persistency\n");
            }
            
            // Increment lba address for next log map
            curr_log_lba++;
        }
    }

    free(write_buf);
    return;
}

static bool restore_persisted_ftl(struct user_zns_device *my_dev) {
    ftl_data *priv_data = (ftl_data *)my_dev->_private;
    uint8_t *buf = (uint8_t *)calloc(1, my_dev->lba_size_bytes);
    if (nvme_read(priv_data->fd, priv_data->nsid, P_PRIV_DATA_LBA, 0, 0, 0, 0, 0, 0, my_dev->lba_size_bytes, buf, 0, NULL) != 0) {
        free(buf);
        return false;
    }

    if (memcmp(buf, magic_num_ftl, MAGIC_NUM_LEN) == 0) {
        // Restore priv_data
        ftl_data *old_data = (ftl_data *)(buf + MAGIC_NUM_LEN);
        priv_data->nzones = old_data->nzones;
        priv_data->zone_size = old_data->zone_size;
        priv_data->log_size = old_data->log_size;

        // Restore zone data
        priv_data->zones = (zone *)calloc(1, sizeof(zone) * priv_data->nzones);
        if (priv_data->zones == NULL) {
            return false;
        }
        if (nvme_read(priv_data->fd, priv_data->nsid, P_ZONE_MAP_LBA, 0, 0, 0, 0, 0, 0, my_dev->lba_size_bytes, buf, 0, NULL) != 0) {
            free(buf);
            return false;
        }
        memcpy(priv_data->zones, buf, sizeof(zone) * priv_data->nzones);

        // Restore log data
        size_t curr_log_lba = P_LOG_MAP_SLBA;
        for(size_t zone_id = 0; zone_id < priv_data->nzones; zone_id++) { 
            if (priv_data->zones[zone_id].state & FTL_ZONE_LOG) {
                priv_data->zones[zone_id].mapping.log = (log_zone_map *)calloc(1, priv_data->zone_size * sizeof(log_zone_map));
                if (priv_data->zones[zone_id].mapping.log == NULL) {
                    free(priv_data->zones);
                    free(buf);
                    return false;
                }
                if (nvme_read(priv_data->fd, priv_data->nsid, curr_log_lba, 0, 0, 0, 0, 0, 0, my_dev->lba_size_bytes, buf, 0, NULL) != 0) {
                    free(priv_data->zones);
                    free(buf);
                    return false;
                }
                memcpy(priv_data->zones[zone_id].mapping.log, buf, sizeof(log_zone_map) * priv_data->zone_size);
                curr_log_lba++;
            }
        }
        free(buf);

        return true;
    }

    free(buf);
    return false;
}

// Invalidates all entry in the log map for a gNE_FULLa
static void log_map_invalidate_stale_lba(ftl_data *priv_data, uint64_t lba) {
    // Iterate over zones and find log zones
    for(size_t zone_id = 0; zone_id < priv_data->nzones; zone_id++) {
        if (priv_data->zones[zone_id].state & FTL_ZONE_LOG) {
            // Get log mappings for zone
            log_zone_map *log_map = priv_data->zones[zone_id].mapping.log;
            size_t limit = priv_data->zone_size;

            // Look for a matching entry for this lba
            for (size_t i = 0; i < limit; i++) {
                if ((log_map[i].flags & FTL_MAP_VALID) && (log_map[i].lba == lba)) {
                    log_map[i].flags = FTL_MAP_INVALID;
                }
            }
        }
    }
}

// Sets the pba for an entry identified by its lba in the log map of a zone
static bool log_map_set_pba_zid(ftl_data *priv_data, uint64_t lba, uint64_t pba, size_t zid) {
    // Get log mappings for zone
    log_zone_map *log_map = priv_data->zones[zid].mapping.log;
    size_t limit = priv_data->zone_size;

    // Look for a matching entry for this lba
    for (size_t i = 0; i < limit; i++) {
        if ((log_map[i].flags & FTL_MAP_VALID) && (log_map[i].lba == lba)) {
            // Invalidate all otherb mappings for this lba in the log map if they exist
            log_map[i].flags = FTL_MAP_INVALID;
            log_map_invalidate_stale_lba(priv_data, lba);

            // Remap entry
            log_map[i].pba = pba;
            log_map[i].flags = FTL_MAP_VALID;
            return true;
        }
    }

    // If there is none create one
    for (size_t i = 0; i < limit; i++) {
        if (log_map[i].flags == FTL_MAP_INVALID) {
            // Invalidate all other mappings for this lba in the log map if they exist
            log_map_invalidate_stale_lba(priv_data, lba);
            //printf("Mapped 0x%08lx --> 0x%08lx\n", lba, pba);
            //fflush(stdout);
            log_map[i].lba = lba;
            log_map[i].pba = pba;
            log_map[i].flags = FTL_MAP_VALID;
            return true;
        }
    }

    fprintf(stderr, "Failed to access log map\n");
    return false;
}

// Retrieves a pba from an entry matching an lba in the log section of the zone
static bool log_map_get_pba_zid(ftl_data *priv_data, uint64_t lba, uint64_t *pba, size_t zid) {
    // Get log mappings for zone
    log_zone_map *log_map = priv_data->zones[zid].mapping.log;
    size_t limit = priv_data->zone_size;

    // Look for a matching entry for this lba
    for (size_t i = 0; i < limit; i++) {
        if ((log_map[i].flags & FTL_MAP_VALID) && (log_map[i].lba == lba)) {
            *pba = log_map[i].pba;
            return true;
        }
    }

    // No valid entry for that lba in this zone
    return false;
}

// Retrieves a pba from an entry matching an lba in the log
static bool log_map_get_pba(ftl_data *priv_data, uint64_t lba, uint64_t *pba) {
    // Iterate over zones and find log zones
    for(size_t zone_id = 0; zone_id < priv_data->nzones; zone_id++) {
        if (priv_data->zones[zone_id].state & FTL_ZONE_LOG) {
            // Check log mapping of this zone
            if (log_map_get_pba_zid(priv_data, lba, pba, zone_id)) {
                return true;
            }
        }
    }

    return false;
}

// Retrieves a pzn from an entry matching an lzn in the data section
static bool data_map_get_pzn(ftl_data *priv_data, uint64_t lzn, uint64_t *pzn) {
    for(size_t zone_id = 0; zone_id < priv_data->nzones; zone_id++) {
        if (priv_data->zones[zone_id].state == FTL_ZONE_DATA) {
            if (priv_data->zones[zone_id].mapping.lzn == lzn) {
                *pzn = priv_data->zones[zone_id].pzn;
                return true;
            }
        }
    }

    return false;
}

// Reads a single block from the given pba
static int read_block(struct user_zns_device *my_dev, uint64_t pba, void *buffer) {
    ftl_data *priv_data = (ftl_data *)my_dev->_private;
    return nvme_read(priv_data->fd, priv_data->nsid, pba, 0, 0, 0, 0, 0, 0, my_dev->lba_size_bytes, buffer, 0, NULL);
}

// Writes a single block to the given pba
static int write_block(struct user_zns_device *my_dev, uint64_t pba, void *buffer) {
    ftl_data *priv_data = (ftl_data *)my_dev->_private;
    return nvme_write(priv_data->fd, priv_data->nsid, pba, 0, 0, 0, 0, 0, 0, 0, my_dev->lba_size_bytes, buffer, 0, NULL);
}

// Copies the data from a block at pba_r to pba_w
// Invalidates all entries in the log map of a zone with a lba lower than the threshhold
static void log_map_invalidate_th_zid(ftl_data *priv_data, uint64_t lba_limit, size_t zid) {
    // Get log mappings for zone
    log_zone_map *log_map = priv_data->zones[zid].mapping.log;
    size_t limit = priv_data->zone_size;

    // Invalidate entries for a lba lower than the limit
    for (size_t i = 0; i < limit; i++) {
        if ((log_map[i].flags & FTL_MAP_VALID) && (log_map[i].lba < lba_limit)) {
            log_map[i].flags = FTL_MAP_INVALID;
        }
    }
}

// Finds the lowest lba address in a sub log map and returns the corresponding index
static bool log_find_lowest_addr(ftl_data *priv_data, size_t zid, size_t *entry_idx) {
    bool found = false;
    uint64_t curr_addr = 0;

    // Get log mappings for zone
    log_zone_map *log_map = priv_data->zones[zid].mapping.log;
    size_t limit = priv_data->zone_size;

    // Find block with lowest logical address
    for (size_t i = 0; i < limit; i++) {
        if (log_map[i].flags & FTL_MAP_VALID) {
            if (found == false || log_map[i].lba < curr_addr) {
                found = true;
                curr_addr = log_map[i].lba;
                *entry_idx = i;
            }
        }
    }

    return found;
}

// Finds a zone with a given state considering the p/e cycles of the zones
static bool find_zone_with_state_wl(ftl_data *priv_data, zone_state state, size_t *zid) {
    bool found = false;
    uint64_t lowest_pec = 0;

    for(size_t zone_id = 0; zone_id < priv_data->nzones; ++zone_id) {
        //printf("Checking zone %d, state 0x%02x, pec %d | curr lowest: %d\n", zone_id, priv_data->zones[zone_id].state, priv_data->zones[zone_id].pec, lowest_pec);
        if (priv_data->zones[zone_id].state == state) {
            if (found == false || priv_data->zones[zone_id].pec < lowest_pec) {
                found = true;
                *zid = zone_id;
                lowest_pec = priv_data->zones[zone_id].pec;
            }
        }
    }

    if (!found) {
        errno = ENOSPC;
    }
    return found;
}

// Looks for an active log zone and returns the corresponding zone id if successfull
static bool find_active_log_zone(ftl_data *priv_data, size_t *zid) {
    for(size_t zone_id = 0; zone_id < priv_data->nzones; ++zone_id) {
        // Check if the zone is an active log zone
        zone_state zs = priv_data->zones[zone_id].state;
        if (zs == (FTL_ZONE_LOG | FTL_ZONE_LOG_ACTIVE)) {
            *zid = zone_id;
            return true;
        }
    }

    return false;
}

// Merges LOG contents into the DATA parts
static int merge_log_to_data(struct user_zns_device *my_dev, size_t zid) {
    int status = 0;
    ftl_data *priv_data = (ftl_data *)my_dev->_private;
    log_zone_map *log_map = priv_data->zones[zid].mapping.log;

    uint8_t *new_zone = (uint8_t *)calloc(priv_data->zone_size, my_dev->lba_size_bytes);
    if (new_zone == NULL) {
        return ENOMEM;
    }

    // Find lowest entry to determine zone properties for transportation
    size_t start_idx = 0;
    while (log_find_lowest_addr(priv_data, zid, &start_idx)) {
        size_t zone_base = log_map[start_idx].lba - (log_map[start_idx].lba % priv_data->zone_size);
        size_t zone_limit = zone_base + priv_data->zone_size;

        // Calculate offset from zone start
        uint64_t offset = log_map[start_idx].lba;
        if (zone_base != 0) {
            offset %= zone_base;
        }

        // Check if an empty zone exists
        size_t new_zid = 0;
        find_zone_with_state_wl(priv_data, FTL_ZONE_UNUSED, &new_zid);

        // Check if we already have this lba mapped
        bool old_zone = false;
        size_t old_zid = 0;
        for(size_t zone_id = 0; zone_id < priv_data->nzones; ++zone_id) {
            if (priv_data->zones[zone_id].state == FTL_ZONE_DATA) {
                if (priv_data->zones[zone_id].mapping.lzn == zone_base) {
                    old_zid = zone_id;
                    old_zone = true;
                }
            }
        }

        #if DEBUG_ZONE_PRINT
        print_zones(priv_data);
        #endif

        // Iterate over lba's, gather them and copy them to the new zone
        uint8_t *zone_wp = new_zone;
        for (size_t lba = zone_base; lba < zone_limit; lba++) {
            uint64_t pba = 0;
            uint64_t offs = lba - zone_base;

            if (log_map_get_pba(priv_data, lba, &pba)) {
                // Get the entry from the log
                if ( (status = read_block(my_dev, pba, zone_wp)) != 0 ) {
                    fprintf(stderr, "[!!] Error in read_block(): 0x%04x\n", status);
                    exit(status);
                }
            } else {
                if (old_zone) {
                    // Read block from old data zone
                    if ( (status = read_block(my_dev, priv_data->zones[old_zid].pzn + offs, zone_wp)) != 0) {
                        fprintf(stderr, "[!!] Error in copy_block(): 0x%04x\n", status);
                        exit(status);
                    }
                }
            }

            // Move wp forward
            zone_wp += my_dev->lba_size_bytes;
        }

        if (old_zone) {
            // Clean datablock, so that it can be reused immediately
            nvme_zns_mgmt_send(priv_data->fd, priv_data->nsid, priv_data->zones[old_zid].pzn, false, NVME_ZNS_ZSA_RESET, 0, NULL);
            priv_data->zones[old_zid].state = FTL_ZONE_UNUSED;
            priv_data->zones[old_zid].pec++;

            // Reuse data zone if no other zones are free
            new_zid = old_zid;
        }

        // Iterate over lba's and copy the data to the zone
        zone_wp = new_zone;
        for (size_t lba = zone_base; lba < zone_limit; lba++) {
            uint64_t offs = lba - zone_base;
            uint64_t new_pba = priv_data->zones[new_zid].pzn + offs;

            if ( (status = write_block(my_dev, new_pba, zone_wp)) != 0) {
                fprintf(stderr, "[!!] Error in write_block(): 0x%04x\n", status);
                exit(status);
            }

            // Move wp forward
            zone_wp += my_dev->lba_size_bytes;
        }

        // Mark data zone as in use and set lzn
        priv_data->zones[new_zid].state = FTL_ZONE_DATA;
        priv_data->zones[new_zid].mapping.lzn = zone_base;

        // Invalidate entries in log map
        log_map_invalidate_th_zid(priv_data, zone_limit, zid);
    }

    // Free buffer
    free(new_zone);

    // Clean old log zone and mark as unused
    nvme_zns_mgmt_send(priv_data->fd, priv_data->nsid, priv_data->zones[zid].pzn, false, NVME_ZNS_ZSA_RESET, 0, NULL);
    priv_data->zones[zid].state = FTL_ZONE_UNUSED;
    priv_data->zones[zid].pec++;
    free(priv_data->zones[zid].mapping.log);

    // Find a new log zone and allocate/map it
    size_t new_log_zid = 0;
    if (!find_zone_with_state_wl(priv_data, FTL_ZONE_UNUSED, &new_log_zid)) {
        print_zones(priv_data);
        perror("[!!] Failed to reserve new log zone");
        exit(errno);
    }
    priv_data->zones[new_log_zid].state = FTL_ZONE_LOG;
    priv_data->zones[new_log_zid].mapping.log = (log_zone_map *) calloc(1, priv_data->zone_size * sizeof(log_zone_map));
    if (priv_data->zones[new_log_zid].mapping.log == NULL) {
        fprintf(stderr, "[!!] Could not allocate memory for log map\n");
        exit(ENOMEM);
    }
    return EXIT_SUCCESS;
}

// Main function for the gc thread
static void *gc_main(void *arg) {
    struct user_zns_device *my_dev = (struct user_zns_device *) arg;
    ftl_data *priv_data = (ftl_data *) my_dev->_private;

    // Set canceltype so that we can cleanly kill the GC thread
    int status = 0;
    if ( (status = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL)) != 0 ) {
        fprintf(stderr, "[!!] Error in pthread_setcanceltype(): %d\n", status);
    }

    // GC Loop
    while (true) {

        // Check if we have a full log zone to perform a merge
        size_t log_zid = 0;
        if (find_zone_with_state_wl(priv_data, (zone_state) (FTL_ZONE_LOG | FTL_ZONE_FULL), &log_zid)) {
            pthread_mutex_lock(&(priv_data->ftl_mutex));    // CRITICAL BEGIN
            merge_log_to_data(my_dev, log_zid);

            // Check if a gc emergency has been triggered and inform master thread
            if (gc_emergency == true) {
                gc_emergency = false;
            }
            pthread_mutex_unlock(&(priv_data->ftl_mutex));  // CRITICAL END
        }
    }
}

int init_szns_device(char *dev_name, struct user_zns_device **my_dev) {
    int fd = -1;
    uint32_t nsid = -1;
    struct nvme_zone_report zns_report;
    ftl_data *priv_data;
    struct nvme_id_ns id_ns;

    /* Open device and get nsid */
    if ((fd = nvme_open(dev_name)) < 0) {
        perror("Error in nvme_open()");
        return errno;
    }
    if (nvme_get_nsid(fd, (__u32 *)&nsid) != 0) {
        perror("Error in nvme_get_nsid()");
        return errno;
    }
    if (nvme_identify_ns(fd, nsid, &id_ns) != 0) {
        perror("Error in nvme_identify_ns()");
        return errno;
    }

    /* Get zone information */
    if (nvme_zns_mgmt_recv(fd, nsid, 0, NVME_ZNS_ZRA_REPORT_ZONES, 
                NVME_ZNS_ZRAS_REPORT_ALL, 0, sizeof(zns_report), 
                (void *)&zns_report) != 0) {
        perror("Error in nvme_zns_report_zones()");
        return errno;
    }

    // Allocate user_device
    if ((*my_dev = (struct user_zns_device *) calloc(1, sizeof(struct user_zns_device))) == NULL) {
        fprintf(stderr, "Error allocating structure");
        return ENOMEM;
     }

    if ((priv_data = (ftl_data *) calloc(1, sizeof(ftl_data))) == NULL) {
        free(my_dev);
        fprintf(stderr, "Error allocating structure");
        return ENOMEM;
    }
    (*my_dev)->_private = priv_data;

    (*my_dev)->lba_size_bytes = 1 << id_ns.lbaf[(id_ns.flbas & 0xF)].ds;

    priv_data->fd = fd;
    priv_data->nsid = nsid;

    // Check if persistent data is available and restore
    if (restore_persisted_ftl(*my_dev) == true) {
        // Recalculate capacity
        (*my_dev)->capacity_bytes = (priv_data->nzones - (priv_data->log_size + 1)) * priv_data->zone_size * (*my_dev)->lba_size_bytes;
        // Start GC thread
        pthread_attr_init(&(priv_data->gc_tattr));
        pthread_create(&(priv_data)->gc_tid, &(priv_data)->gc_tattr, gc_main, (void *)*my_dev);

        priv_data->ftl_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
        return EXIT_SUCCESS;
    }

    priv_data->nzones = le64_to_cpu(zns_report.nr_zones);
    priv_data->zone_size = id_ns.ncap / priv_data->nzones;

    priv_data->log_size = 1 + (priv_data->nzones / LOG_SPACE_PRCNT);

    // One more zone is reserved as internal buffer space
    (*my_dev)->capacity_bytes = (priv_data->nzones - (priv_data->log_size + 1)) * priv_data->zone_size * (*my_dev)->lba_size_bytes;

    // Allocate space for the zones
    priv_data->zones = (zone *) calloc(1, priv_data->nzones * sizeof(zone));
    if (priv_data->zones == NULL) {
        free((*my_dev)->_private);
        free(my_dev);
        fprintf(stderr, "Error allocating structure");
        return ENOMEM;
    }

    // Iterate over all the zones to initialize their data
    int alloc_status = 0;
    for (size_t zone_id = 0; zone_id < priv_data->nzones; zone_id++) {
        priv_data->zones[zone_id].pzn = priv_data->zone_size * zone_id;
        priv_data->zones[zone_id].pec = 0;

        if (zone_id == 0) {
            priv_data->zones[zone_id].state = FTL_ZONE_PERSISTENCY;
            continue;
        }

        if (zone_id < priv_data->log_size+1) {
            // Mark zone as log zone and allocate memory for the log mapping
            priv_data->zones[zone_id].state = FTL_ZONE_LOG;
            priv_data->zones[zone_id].mapping.log = (log_zone_map *) calloc(1, priv_data->zone_size * sizeof(log_zone_map));

            alloc_status |= (priv_data->zones[zone_id].mapping.log == NULL);
        } else {
            priv_data->zones[zone_id].state = FTL_ZONE_UNUSED;
        }

        // Reset zone (device was not persisted)
        nvme_zns_mgmt_send(priv_data->fd, priv_data->nsid, priv_data->zones[zone_id].pzn, false, NVME_ZNS_ZSA_RESET, 0, NULL);
    }

    // Check allocation status
    if (alloc_status != 0) {
        for (size_t zone_id = 0; zone_id < priv_data->log_size; zone_id++) {
            free(priv_data->zones[zone_id].mapping.log);
        }

        free(priv_data->zones);
        free((*my_dev)->_private);
        free(my_dev);
        fprintf(stderr, "Error allocating memory for log");
        return ENOMEM;
    }

    // Mark first entry as active log zone
    priv_data->zones[1].state = (zone_state) (priv_data->zones[1].state| FTL_ZONE_LOG_ACTIVE);

    // Start GC thread
    pthread_attr_init(&(priv_data->gc_tattr));
    pthread_create(&(priv_data)->gc_tid, &(priv_data)->gc_tattr, gc_main, (void *)*my_dev);

    priv_data->ftl_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    return EXIT_SUCCESS;
}

int szns_read(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    ftl_data *priv_data = (ftl_data *)my_dev->_private;

    // Check if the address is aligned
    if ((address % my_dev->lba_size_bytes) != 0) {
        return EINVAL;
    }
    address /= my_dev->lba_size_bytes;

    memset(buffer, 0, size);
    //printf("Reading 0x%010lx\n", address);
    
    // Lock mutex
    pthread_mutex_lock(&(priv_data->ftl_mutex));

    // Get PBA mapping
    // TODO: Iterate over blocks in request
    uint64_t pba = 0;
    if (log_map_get_pba(priv_data, address, &pba)) {
        pthread_mutex_unlock(&(priv_data->ftl_mutex));
        return read_block(my_dev, pba, buffer);
    } else {
        // Get a data zone mapping if available
        uint64_t offset = address % priv_data->zone_size;
        uint64_t lzn = address - offset;
        uint64_t pzn = 0;
        if (data_map_get_pzn(priv_data, lzn, &pzn)) {
            pthread_mutex_unlock(&(priv_data->ftl_mutex));
            return read_block(my_dev, pzn + offset, buffer);
        }
    }

    // No log mapping found, return given data
    pthread_mutex_unlock(&(priv_data->ftl_mutex));
    //fprintf(stderr, "[!!] No valid mapping found for data, returning nothing\n     Requested address: 0x%010lx\n", address);
    return EXIT_SUCCESS;
}

int szns_write(struct user_zns_device *my_dev, uint64_t address, void *buffer, uint32_t size){
    uint64_t pba = 0;
    ftl_data *priv_data = (ftl_data *)my_dev->_private;
    bool gc_fail = false;

    // Check address and convert it
    if (address % my_dev->lba_size_bytes != 0) {
        return EINVAL;
    }
    address /= my_dev->lba_size_bytes;

    // Lock mutex
    pthread_mutex_lock(&(priv_data->ftl_mutex));

    // Find active log zone
    size_t log_zid = 0;
    if (!find_active_log_zone(priv_data, &log_zid)) {
        fprintf(stderr, "[!!] Could not find an active log zone\n");
        pthread_mutex_unlock(&(priv_data->ftl_mutex));
        exit(ENOSPC);
    }

    // Append to active log zone
    int status = nvme_zns_append(priv_data->fd, priv_data->nsid, 
            priv_data->zones[log_zid].pzn, 0, 0, 0, 0, 0, 
            size, buffer, 0, NULL, (__u64 *)&pba);
    if (status != 0) {
        pthread_mutex_unlock(&(priv_data->ftl_mutex));
        printf("Trying to write to address 0x%06lx\n", address);
        printf("Status: 0x%04x\n", status);
        print_zones(priv_data);
        return status;
    }

    // Update log mapping
    if (!log_map_set_pba_zid(priv_data, address, pba, log_zid)) {
        pthread_mutex_unlock(&(priv_data->ftl_mutex));
        fprintf(stderr, "[!!] Failed to access log map\n");
        exit(-1);
    }

    //printf("Wrote 0x%010lx to 0x%010lx for zid %ld\n", address, pba, log_zid);

new_log_retry:
    // If PBA is at the end of the zone, update zone state and find next log zone
    if (pba != 0 && ((pba % priv_data->zone_size) == (priv_data->zone_size - 1))) {
        // Mark current log zone as full
        priv_data->zones[log_zid].state = (zone_state) (FTL_ZONE_LOG | FTL_ZONE_FULL);

        // Find new log zone and make it active
        size_t new_log_zid = 0;
        if (!find_zone_with_state_wl(priv_data, FTL_ZONE_LOG, &new_log_zid)) {
            // Trigger GC emergency
            if (gc_fail == false) {
                //fprintf(stderr, "[!] Could not find new log zone, triggering emergency GC\n");
                gc_emergency = true;
                gc_fail = true;
                pthread_mutex_unlock(&(priv_data->ftl_mutex));

                while (gc_emergency == true) {
                    // Wait for GC to handle emergency by passing to it
                    sched_yield();
                }

                // Retry searching for a new log zone
                pthread_mutex_lock(&(priv_data->ftl_mutex));
                goto new_log_retry;
            } else {
                // GC could not handle emergency
                pthread_mutex_unlock(&(priv_data->ftl_mutex));
                fprintf(stderr, "[!!] Could not find new log zone with GC help\n");
                exit(ENOSPC);
            }
        }
        // Set new log zone to active
        priv_data->zones[new_log_zid].state = (zone_state) (FTL_ZONE_LOG | FTL_ZONE_LOG_ACTIVE);
    }

    pthread_mutex_unlock(&(priv_data->ftl_mutex));
    return status;
}

int deinit_szns_device(struct user_zns_device *my_dev){
    ftl_data *priv_data = (ftl_data *)my_dev->_private;

    // Safely bring back the GC thread
    int status = 0;
    pthread_mutex_lock(&(priv_data->ftl_mutex));
    if ( (status = pthread_cancel(priv_data->gc_tid)) == 0 ) {
        if (pthread_join(priv_data->gc_tid, NULL) != 0) {
            fprintf(stderr, "[!!] Failed to join GC thread\n");
        }
    } else {
        fprintf(stderr, "[!!] Failed to signal kill to GC thread, error code: %d\n", status);
    }

    // Persist the FTL on the device
    persist_ftl(my_dev);

    // Free the log mapping memory we allocated
    for(size_t zone_id = 0; zone_id < priv_data->nzones; ++zone_id) {
        if (priv_data->zones[zone_id].state & FTL_ZONE_LOG) {
            free(priv_data->zones[zone_id].mapping.log);
        }
    }

    // Free the memory we allocated
    free(priv_data->zones);
    free(priv_data);
    free(my_dev);
    return EXIT_SUCCESS;
}
