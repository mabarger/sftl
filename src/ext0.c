/*
 A simple FS implementation

 Copyright (c) 2021 - current
 Authors:  Barger M.
*/

#include "ext0.h"


// Magic number to identify FS persistency data
#define MAGIC_NUM_LEN   ( (size_t) 8 )
const uint8_t ext0_magic_num[MAGIC_NUM_LEN] = {'e', 'x', 't', '0', '\x75', '\x22', '\x28'};

/* -- Private variables -- */
static ext0_sb *sb = NULL;
static ext0_ft_entry ft[MAX_FD_COUNT];

static struct user_zns_device *my_dev = NULL;
/* -- Private variables -- */

static ext0_inode *_get_inode_by_id(uint32_t inode_id);

static char *_get_file_from_path(char *path) {
    char *fpos = strrchr(path, '/');

    if (fpos == NULL) {
        return NULL;
    }

    // Get file name
    return strdup(fpos+1);
}

static char *_get_dir_from_path(char *path) {
    char *dir = strdup(path);
    char *fpos = strrchr(dir, '/');

    if (fpos == NULL) {
        return NULL;
    }

    // Black out filename
    *fpos = '\x00';
    return dir;
}

static uint32_t _get_free_inode() {
    // Look for unused inode
    for (size_t inode_id = 0; inode_id < sb->inode_cnt; inode_id++) {
        if (bitmap_check(sb->inode_bitmap, inode_id) == false) {
            // Mark found entry as used and return it
            bitmap_set(sb->inode_bitmap, inode_id);
            sb->free_inode_cnt--;
            return inode_id;
        }
    }

    // No free inodes left
    return 0;
}

static uint8_t *_read_block(uint32_t id) {
    uint8_t *buf = (uint8_t *)calloc(1, sb->block_size);
    if (buf) {
        if (szns_read(my_dev, id * sb->block_size, buf, sb->block_size) == 0) {
            return buf;
        }
        free(buf);
    }

    return NULL;
}

static void _log_inode_data_blocks(ext0_inode *inode) {
    fprintf(stderr, "Data block list:\n");
    for (size_t i = 0; i < MAX_IND_BLOCKS; i++) {
        fprintf(stderr, "|- 0x%08x\n", inode->blocks[i]);
        if (inode->blocks[i] != 0) {
            uint32_t *data = (uint32_t *)_read_block(inode->blocks[i]);
            for (size_t j = 0; j < (sb->block_size/sizeof(uint32_t)); j++) {
                fprintf(stderr, "   |- 0x%08x\n", data[j]);
            }
            free(data);
        }
    }
}

static bool _write_block(uint32_t id, uint8_t *buf) {
    return (szns_write(my_dev, id * sb->block_size, buf, sb->block_size) == 0);
}

uint32_t _get_free_block() {
    // Look for unused block
    for (size_t block_id = 0; block_id < sb->block_cnt; block_id++) {
        if (bitmap_check(sb->block_bitmap, block_id) == false) {
            // Mark found entry as used and return it
            // Data blocks start at an offset of sb->first_block
            bitmap_set(sb->block_bitmap, block_id);
            sb->free_block_cnt--;
            return block_id + sb->first_block;
        }
    }

    // No free blocks left
    fprintf(stderr, "[!!] Out of free data blocks\n");
    return 0;
}

static uint32_t _get_block_by_idx(ext0_inode *inode, size_t idx, bool set) {
    uint32_t *sublist = NULL;
    uint32_t block_no = 0;
    size_t list_idx = idx / (sb->block_size / sizeof(uint32_t));
    size_t entry_idx = idx % (sb->block_size / sizeof(uint32_t));

    if (list_idx >= MAX_IND_BLOCKS) {
        fprintf(stderr, "[!!] Out of indirect blocks, file exhausted\n");
        return 0;
    }

    // Check if the wanted entry in the list is allocated
    if (inode->blocks[list_idx] == 0) {
        if (set == false) {
            return 0;
        } else {
            // Allocate and set new entry
            if ( (inode->blocks[list_idx] = _get_free_block()) != 0 ) {
                sublist = (uint32_t *)calloc(1, sb->block_size);
            }
        }
    }

    // Read sublist if it has not been allocated
    if (!sublist) {
        if ( (sublist = (uint32_t *)_read_block(inode->blocks[list_idx])) == NULL) {
            return 0;
        }
    }

    // Set or retrieve new entry
    if (sublist[entry_idx] == 0 && set == true) {
        // Get new data block
        if ( (sublist[entry_idx] = _get_free_block()) == 0 ) {
            free(sublist);
            return 0;
        }

        // Write new sublist back to disk
        if (_write_block(inode->blocks[list_idx], (uint8_t *)sublist) == false) {
            free(sublist);
            return 0;
        }

        block_no = sublist[entry_idx];
    } else {
        block_no = sublist[entry_idx];
    }

    free(sublist);
    return block_no;
}

static void _list_directory(uint32_t inode, size_t indent, bool recursive) {
    if (indent > 8) {
        return;
    }
    ext0_inode *dir_inode = (ext0_inode *)calloc(1, sb->block_size);
    if (dir_inode != NULL) {
        if (szns_read(my_dev, inode * sb->block_size, dir_inode, sb->block_size) == 0) {
            // Read data block and iterate over entries
            uint8_t *data_block = NULL;
            if ( (data_block = _read_block(dir_inode->blocks[0])) == NULL) {
                free(dir_inode);
                return;
            }

            ext0_direntry *curr_entry = (ext0_direntry *) data_block;
            for (size_t i = 0; i < (sb->block_size / sizeof(ext0_direntry)); i++, curr_entry++) {
                if (curr_entry->inode_id == 0) {
                    continue;
                }

                if (strcmp(curr_entry->name, ".") == 0 || strcmp(curr_entry->name, "..") == 0) {
                    continue;
                }

                for(size_t i = 0; i < indent; i++) printf(" ");
                ext0_inode *inode = _get_inode_by_id(curr_entry-> inode_id);
                printf("|- %-22s | %c | 0x%04x | %8d B\n", curr_entry->name, curr_entry->ftype == FTYPE_DIR ? 'd' : 'f',
                                                   curr_entry->inode_id, inode->size);
                free(inode);
                if (recursive && curr_entry->ftype == FTYPE_DIR) {
                    _list_directory(curr_entry->inode_id, indent + 2, recursive);
                }
            }
            free(data_block);
        }
    }

    free(dir_inode);
}

static uint32_t _get_inode_from_direntry(uint32_t dir_inode_id, char *name, uint32_t ftype) {
    ext0_inode *dir_inode = (ext0_inode *)calloc(1, sb->block_size);
    if (dir_inode != NULL) {
        if (szns_read(my_dev, dir_inode_id * sb->block_size, dir_inode, sb->block_size) == 0) {
            // Read data block and iterate over entries
            uint8_t *data_block = NULL;
            if ( (data_block = _read_block(dir_inode->blocks[0])) == NULL) {
                free(dir_inode);
                return 0;
            }

            //printf("Looking for %s, type: %c\n", name, ftype == FTYPE_FILE ? 'f' : ftype == FTYPE_DIR ? 'd' : 'u');
            //printf("Directory entries:\n");
            // Iterate over current data block
            ext0_direntry *curr_entry = (ext0_direntry *) data_block;
            for (size_t entry_id = 0; entry_id < (sb->block_size / sizeof(ext0_direntry)); entry_id++) {
                // Skip stale entries
                if (curr_entry->inode_id == 0) {
                    curr_entry++;
                    continue;
                }

                // If the name matches return the inode id
                if (ftype == FTYPE_IRR) {
                    if (strncmp(curr_entry->name, name, MAX_FNAME_LEN) == 0) {
                        uint32_t inode_id = curr_entry->inode_id;
                        free(dir_inode);
                        free(data_block);
                        return inode_id;
                    }
                } else if ( curr_entry->ftype == ftype && (strncmp(curr_entry->name, name, MAX_FNAME_LEN) == 0) ) {
                    uint32_t inode_id = curr_entry->inode_id;
                    free(dir_inode);
                    free(data_block);
                    return inode_id;
                }

                curr_entry++;
            }

            // Free data block and go to next data block
            free(data_block);
        }
    }

    free(dir_inode);
    return 0;
}

static ext0_inode *_create_inode() {
    ext0_inode *new_inode;
    uint32_t new_inode_id = _get_free_inode();
    if (new_inode_id == 0) {
        return NULL;
    }

    if ( (new_inode = (ext0_inode *)calloc(1, sb->block_size)) == NULL ) {
        return NULL;
    }

    new_inode->uid = new_inode_id;

    return new_inode;
}

static uint32_t _create_file_inode() {
    ext0_inode *new_inode;

    // Create new inode
    if ( (new_inode = _create_inode()) == NULL ) {
        return 0;
    }

    // Allocate new data block for list
    if ((new_inode->blocks[0] = _get_free_block()) == 0) {
        return 0;
    }
    uint8_t *data_list = (uint8_t *)calloc(1, sb->block_size);
    if (data_list) {
        _write_block(new_inode->blocks[0], data_list);
        free(data_list);
    }

    // Write inode to disk
    if (_write_block(new_inode->uid, (uint8_t *)new_inode) == false) {
        free(data_list);
        free(new_inode);
        return 0;
    }

    // Return inode id
    uint32_t new_inode_id = new_inode->uid;
    free(new_inode);
    return new_inode_id;
}

static uint32_t _create_dir_inode(uint32_t parent_inode) {
    ext0_inode *new_inode;

    // Create new inode
    if ( (new_inode = _create_inode()) == NULL ) {
        fprintf(stderr, "[!!] Failed to create new inode\n");
        return 0;
    }

    // Allocate data block in inode for directory entries
    if ((new_inode->blocks[0] = _get_free_block()) != 0) {
        uint8_t *data_block = (uint8_t *)calloc(1, sb->block_size);
        if (data_block != NULL) {
            ext0_direntry *curr_entry = (ext0_direntry *)data_block;

            // Add entry for .
            curr_entry->inode_id = new_inode->uid;
            curr_entry->ftype = FTYPE_DIR;
            strncpy(curr_entry->name, ".", MAX_FNAME_LEN);

            // Add entry for ..
            curr_entry++;
            curr_entry->inode_id = parent_inode;
            curr_entry->ftype = FTYPE_DIR;
            strncpy(curr_entry->name, "..", MAX_FNAME_LEN);

            // Write inode and data block to disk
            new_inode->size = sizeof(ext0_direntry) * 2;
            if (!_write_block(new_inode->uid, (uint8_t *)new_inode) || !_write_block(new_inode->blocks[0], data_block)) {
                fprintf(stderr, "[!!] Failed to write block to disk\n");
                fprintf(stderr, "     Tried to write to address 0x%06x\n", new_inode->uid);
                free(data_block);
                free(new_inode);
                return 0;
            }
            free(data_block);

            // Return inode id
            uint32_t new_inode_id = new_inode->uid;
            free(new_inode);
            return new_inode_id;
        }
    }

    // Failed to allocate data block
    free(new_inode);
    return 0;
}

static int _add_inode_to_dir(uint32_t parent_inode, uint32_t inode_id, char *name, uint32_t ftype) {
    ext0_inode *dir_inode = (ext0_inode *)calloc(1, sb->block_size);
    if (dir_inode != NULL) {
        if (szns_read(my_dev, parent_inode * sb->block_size, dir_inode, sb->block_size) == 0) {
            // Read data block
            uint8_t *data_block = NULL;
            if ( (data_block = _read_block(dir_inode->blocks[0])) == NULL) {
                free(dir_inode);
                return -1;
            }

            // Find empty entry in dir
            ext0_direntry *curr_entry = (ext0_direntry *) data_block;
            for (size_t i = 0; i < (sb->block_size / sizeof(ext0_direntry)); i++, curr_entry++) {
                if (curr_entry->inode_id == 0) {
                    // Add new directory entry
                    curr_entry->inode_id = inode_id;
                    curr_entry->ftype = ftype;
                    strncpy(curr_entry->name, name, MAX_FNAME_LEN);

                    // Write modified data block to disk
                    if (_write_block(dir_inode->blocks[0], data_block) == false) {
                        free(data_block);
                        free(dir_inode);
                        return -1;
                    }
                    free(data_block);
                    break;
                }
            }
        }
    }

    // Update size in inode and write it to disk
    dir_inode->size += sizeof(ext0_direntry);
    if (_write_block(dir_inode->uid, (uint8_t *)dir_inode) == false) {
        free(dir_inode);
        return -1;
    }

    if (dir_inode->size >= sb->block_size) {
        fprintf(stderr, "[!!] Directory exhausted\n");
    }

    free(dir_inode);
    return EXIT_SUCCESS;
}

static uint32_t _get_inode_by_path(char *path) {
    // Go through the tree and check if the path exists
    char *tpath = strdup(path);
    char *curr_elem = strtok(tpath, "/");
    uint32_t dir_inode_id = ROOT_INODE;
    while (curr_elem != NULL) {
        // Check if an entry for the current path element exists in the fs
        uint32_t inode_id = _get_inode_from_direntry(dir_inode_id, curr_elem, FTYPE_IRR);
        if (inode_id == 0) {
            // File does not exist
            free(tpath);
            return 0;
        } else {
            // Entry with this name exists, search inside of it
            dir_inode_id = inode_id;
        }

        // Set next element
        curr_elem = strtok(NULL, "/");
    }

    free(tpath);
    return dir_inode_id;
}

static uint32_t _get_spec_inode_by_path(char *path, uint32_t ftype) {
    // Go through the tree and check if the path exists
    char *tpath = strdup(path);
    char *curr_elem = strtok(tpath, "/");
    uint32_t dir_inode_id = ROOT_INODE;
    while (curr_elem != NULL) {
        char *next_elem = strtok(NULL, "/");
        uint32_t curr_ftype = (next_elem == NULL) ? ftype : FTYPE_DIR;

        // Check if an entry for the current path element exists in the fs
        uint32_t inode_id = _get_inode_from_direntry(dir_inode_id, curr_elem, curr_ftype);
        if (inode_id == 0) {
            // File does not exist
            free(tpath);
            return 0;
        } else {
            // Entry with this name exists, search inside of it
            dir_inode_id = inode_id;
        }

        // Set next element
        curr_elem = next_elem;
    }

    free(tpath);
    return dir_inode_id;
}

static ext0_inode *_get_inode_by_id(uint32_t inode_id) {
    ext0_inode *inode;

    // Read inode from disk
    if ( (inode = (ext0_inode *)_read_block(inode_id)) == NULL) {
        fprintf(stderr, "[!!] Failed to read inode from disk\n");
        return 0;
    }

    return inode;
}

static bool _get_empty_ft_entry(size_t *empty_entry_id) {
    // Iterate through entries and find an empty entry
    for (size_t entry_id = 0; entry_id < MAX_FD_COUNT; entry_id++) {
        if (ft[entry_id].inode == NULL) {
            *empty_entry_id = entry_id;
            return true;
        }
    }

    return false;
}

static bool _get_fd_for_inode(uint32_t inode_id, size_t *ft_idx) {
    // Iterate through entries and find an entry with a matching id
    for (size_t entry_id = 0; entry_id < MAX_FD_COUNT; entry_id++) {
        if ( ft[entry_id].inode && (ft[entry_id].inode-> uid == inode_id)) {
            *ft_idx = entry_id;
            return true;
        }
    }

    return false;
}

static bool _free_block(uint32_t masked_block_id) {
    uint32_t block_id = masked_block_id - sb->first_block;
    if (bitmap_check(sb->block_bitmap, block_id) == true) {
        bitmap_clear(sb->block_bitmap, block_id);
        sb->free_block_cnt++;
        return true;
    }

    // Block was not allocated
    fprintf(stderr, "[!!] Tried to free unallocated block: 0x%06x\n", masked_block_id);
    return false;
}

static bool _free_inode(uint32_t inode_id) {
    if (bitmap_check(sb->inode_bitmap, inode_id)) {
        // Free associated data blocks
        // Get inode
        ext0_inode *inode = _get_inode_by_id(inode_id);
        if (inode == NULL) {
            fprintf(stderr, "[!!] No inode found for given id\n");
            return false;
        }

        // Check if the file contained any data
        if (inode->size != 0) {
            // Iterating over data blocks to free them
            for (size_t block_idx = 0; block_idx < MAX_IND_BLOCKS; block_idx++) {
                // Check for last data block
                if (inode->blocks[block_idx] == 0) {
                    break;
                }

                if (_free_block(inode->blocks[block_idx]) == false) {
                    free(inode);
                    return false;
                }
                inode->blocks[block_idx] = 0;
            }
        }

        // Deallocate the actual inode
        free(inode);
        bitmap_clear(sb->inode_bitmap, inode_id);
        sb->free_inode_cnt++;
        return true;
    }

    // Inode was not allocated
    fprintf(stderr, "[!!] Tried to free unallocated inode\n");
    return false;
}

static bool _modify_file_in_dir(char *file_name, uint32_t dir_inode_id, bool rename, char *new_name) {
    // Get directory inode
    ext0_inode *dir_inode = _get_inode_by_id(dir_inode_id);
    if (dir_inode == NULL) {
        fprintf(stderr, "[!!] No inode found for given id\n");
        return false;
    }

    // Read data block
    uint8_t *data_block = NULL;
    if ( (data_block = _read_block(dir_inode->blocks[0])) == NULL ) {
        free(dir_inode);
        return false;
    }

    // Iterate over entries, find matching entry and update name
    ext0_direntry *curr_entry = (ext0_direntry *) data_block;
    for (size_t i = 0; i < (sb->block_size / sizeof(ext0_direntry)); i++, curr_entry++) {
        if (curr_entry->inode_id == 0) {
            continue;
        }

        if (strcmp(curr_entry->name, file_name) == 0) {
            if (rename == true) {
                // Rename the entry
                strncpy(curr_entry->name, new_name, MAX_FNAME_LEN);
                break;
            } else {
                // Simply invalidate the entry
                curr_entry->inode_id = 0;
                break;
            }
        }
    }

    // Write data block back to disk
    if (_write_block(dir_inode->blocks[0], data_block) == false) {
        free(dir_inode);
        return 0;
    }
    free(data_block);

    // Write inode back to disk
    if (rename == false) {
        // If a deletion has occured adjust the size
        dir_inode->size -= sizeof(ext0_direntry);
    }
    if (_write_block(dir_inode->uid, (uint8_t *)dir_inode) == false) {
        free(dir_inode);
        return 0;
    }
    free(dir_inode);

    // Successfull
    return true;
}

static void _persist_ext0() {
    uint8_t *buf = (uint8_t *)calloc(1, sb->block_size);
    if (buf == NULL) {
        return;
    }

    // Write superblock and bitmaps to disk
    uint8_t *wp = buf;
    memcpy(wp, ext0_magic_num, MAGIC_NUM_LEN); wp += MAGIC_NUM_LEN;
    memcpy(wp, sb, sizeof(ext0_sb)); wp += sizeof(ext0_sb);
    memcpy(wp, sb->inode_bitmap, bitmap_size(sb->inode_cnt)); wp += bitmap_size(sb->inode_cnt);
    memcpy(wp, sb->block_bitmap, bitmap_size(sb->block_cnt)); wp += bitmap_size(sb->block_cnt);
    _write_block(P_SUPERBLCK_LBA, buf);

    //printf("[$] Persisting fs with the following structure:\n");
    //ext0_list_fs(0);

    free(buf);
    return;
}

static bool _restore_ext0() {
    uint8_t *buf = NULL;

    // Read first block and check for magic num
    if ((buf = _read_block(P_SUPERBLCK_LBA)) == NULL) {
        return false;
    }
    if (memcmp(buf, ext0_magic_num, MAGIC_NUM_LEN) == 0) {
        // Restore superblock
        memcpy(sb, buf + MAGIC_NUM_LEN, sizeof(ext0_sb));

        // Restore bitmaps
        sb->inode_bitmap = bitmap_alloc(sb->inode_cnt);
        sb->block_bitmap = bitmap_alloc(sb->block_cnt);
        if ( sb->inode_bitmap == NULL || sb->block_bitmap == NULL ) {
            fprintf(stderr, "[!!] Failed to allocate memory for bitmaps\n");
            free(buf);
            return false;
        }

        uint8_t *rp = buf + MAGIC_NUM_LEN + sizeof(ext0_sb);
        memcpy(sb->inode_bitmap, rp, bitmap_size(sb->inode_cnt)); rp += bitmap_size(sb->inode_cnt);
        memcpy(sb->block_bitmap, rp, bitmap_size(sb->block_cnt)); rp += bitmap_size(sb->block_cnt);
        //fprintf(stderr, "[$] Restored FS with the following structure:\n");
        //ext0_list_fs(0);
        
        free(buf);
        return true;
    }

    free(buf);
    return false;
}

int ext0_init(struct user_zns_device *my_device) {
    my_dev = my_device;
    uint32_t lba_size = my_dev->lba_size_bytes;
    uint32_t block_cnt = my_dev->capacity_bytes / lba_size;

    // Init superblock
    if ( (sb = (ext0_sb *)calloc(1, lba_size)) == NULL ) {
        return ENOMEM;
    }

    // Check if a fs exists on this disk
    sb->block_size = lba_size;
    if (_restore_ext0() == true) {
        sb->mutex = PTHREAD_MUTEX_INITIALIZER;
        return EXIT_SUCCESS;
    }

    // A part of the blocks identified by INODE_RATIO is
    // statically allocated to inodes, the rest to data blocks
    sb->inode_cnt = (block_cnt / INODE_RATIO);
    sb->block_cnt = block_cnt - sb->inode_cnt;
    sb->free_inode_cnt = sb->inode_cnt;
    sb->free_block_cnt = sb->block_cnt;
    sb->first_block = sb->inode_cnt;
    sb->block_size = lba_size;
    sb->inode_bitmap = bitmap_alloc(sb->inode_cnt);
    sb->block_bitmap = bitmap_alloc(sb->block_cnt);

    if ( sb->inode_bitmap == NULL || sb->block_bitmap == NULL ) {
        fprintf(stderr, "[!!] Failed to allocate memory for bitmaps\n");
        goto exit_enomem;
    }

    // First inode is used as a superblock
    bitmap_set(sb->inode_bitmap, 0);
    sb->free_inode_cnt--;

    // Allocate root inode
    if  (_create_dir_inode(ROOT_INODE) == 0) {
        fprintf(stderr, "[!!] Failed to create dir inode for root\n");
        goto exit_enomem;
    }

    // Initialize open file table with zeroes
    memset(ft, 0, sizeof(ext0_ft_entry) * MAX_FD_COUNT);

    // Initialize mutex
    sb->mutex = PTHREAD_MUTEX_INITIALIZER;
    return EXIT_SUCCESS;

exit_enomem:
    fprintf(stderr, "[!!] Failed to allocate memory for FS management\n");
    bitmap_free(sb->inode_bitmap);
    bitmap_free(sb->block_bitmap);
    free(sb);
    exit(ENOMEM);
}

void ext0_deinit() {
    pthread_mutex_destroy(&(sb->mutex));
    _persist_ext0();
    bitmap_free(sb->inode_bitmap);
    bitmap_free(sb->block_bitmap);
    free(sb);
}

int ext0_create_file(char *path, uint32_t ftype) {
    pthread_mutex_lock(&(sb->mutex));
    char *curr_path = strdup(path);
    char *curr_elem = NULL;

    // The path has to start at / (root)
    if (path[0] != '/') {
        pthread_mutex_unlock(&(sb->mutex));
        free(curr_path);
        return EINVAL;
    }

    // Go through the tree and check if the path exists
    curr_elem = strtok(curr_path, "/");
    uint32_t dir_inode_id = ROOT_INODE;
    while (curr_elem != NULL) {
        char *next_elem = strtok(NULL, "/");

        // Check if an entry for the current path element exists in the fs
        uint32_t inode_id = _get_inode_from_direntry(dir_inode_id, curr_elem, FTYPE_IRR);
        bool last_elem = (next_elem == NULL);
        if (inode_id == 0) {
            uint32_t new_inode_id = 0;
            if (last_elem && ftype == FTYPE_FILE) {
                // Create file
                if ( (new_inode_id = _create_file_inode()) == 0 ) {
                    pthread_mutex_unlock(&(sb->mutex));
                    free(curr_path);
                    fprintf(stderr, "[!!] Failed to create new directory inode\n");
                    return ENOSPC;
                }
            } else {
                // Create directory
                if ( (new_inode_id = _create_dir_inode(dir_inode_id)) == 0 ) {
                    pthread_mutex_unlock(&(sb->mutex));
                    free(curr_path);
                    fprintf(stderr, "[!!] Failed to create new directory inode\n");
                    return ENOSPC;
                }
            }
            
            // Add inode to directory
            if (_add_inode_to_dir(dir_inode_id, new_inode_id, curr_elem, ftype) != 0) {
                pthread_mutex_unlock(&(sb->mutex));
                free(curr_path);
                fprintf(stderr, "[!!] Failed to add new inode to directory\n");
                return ENOSPC;
            } 
            dir_inode_id = new_inode_id;
        } else {
            if (next_elem == NULL) {
                // File already exists
                pthread_mutex_unlock(&(sb->mutex));
                free(curr_path);
                return EEXIST;
            }

            // Entry with this name exists, search inside of it
            dir_inode_id = inode_id;
        }

        // Set next element
        curr_elem = next_elem;
    }

    pthread_mutex_unlock(&(sb->mutex));
    free(curr_path);
    return EXIT_SUCCESS;
}

void ext0_list_fs(size_t indent) {
    pthread_mutex_lock(&(sb->mutex));
    _list_directory(ROOT_INODE, indent, true);
    pthread_mutex_unlock(&(sb->mutex));
}

int ext0_open_file(char *path, int *fd) {
    pthread_mutex_lock(&(sb->mutex));
    size_t ft_idx = 0;

    // Check if the file exists
    uint32_t inode_id = _get_inode_by_path(path);
    if (inode_id == 0) {
        // File does not exist
        pthread_mutex_unlock(&(sb->mutex));
        return ENOENT;
    }

    // Allocate an empty ft and use it
    if (_get_empty_ft_entry(&ft_idx)) {
        if ( (ft[ft_idx].inode = (ext0_inode *)_read_block(inode_id)) == NULL) {
            fprintf(stderr, "[!!] Failed to read inode from disk\n");
            pthread_mutex_unlock(&(sb->mutex));
            return -1;
        }
        *fd = (int) ft_idx;
        ft[ft_idx].lock = PTHREAD_MUTEX_INITIALIZER;
        pthread_mutex_unlock(&(sb->mutex));
        return EXIT_SUCCESS;
    }

    // Too many open files
    pthread_mutex_unlock(&(sb->mutex));
    return EMFILE;
}

int ext0_close_file(int fd) {
    pthread_mutex_lock(&(sb->mutex));
    // Check the fd for validity
    if (fd >= MAX_FD_COUNT || ft[fd].inode == NULL) {
        pthread_mutex_unlock(&(sb->mutex));
        return EMFILE;
    }

    // Save inode state to disk
    if (_write_block(ft[fd].inode->uid, (uint8_t *)ft[fd].inode) == false) {
        pthread_mutex_unlock(&(sb->mutex));
        return -1;
    }

    // Free memory
    free(ft[fd].inode);
    ft[fd].inode = NULL;

    // Destroy mutex
    pthread_mutex_destroy(&(ft[fd].lock));

    pthread_mutex_unlock(&(sb->mutex));
    return EXIT_SUCCESS;
}

bool ext0_file_exists(char *path, uint32_t ftype) {
    pthread_mutex_lock(&(sb->mutex));
    // Function returns 0 when no file is at that path
    int inode_id = _get_spec_inode_by_path(path, ftype);
    pthread_mutex_unlock(&(sb->mutex));
    return inode_id != 0;
}

int ext0_lock_file(char *path, int *fd) {
    uint32_t inode_id = 0;
    // Get the inode id
    if ( (inode_id = _get_inode_by_path(path)) == 0) {
        pthread_mutex_unlock(&(sb->mutex));
        return ENOENT;
    }

    // Check if it matches to an open fd
    size_t ft_idx = 0;
    if (_get_fd_for_inode(inode_id, &ft_idx) == false) {
        // If not we open the file
        if (ext0_open_file(path, fd) != 0) {
            pthread_mutex_unlock(&(sb->mutex));
            return EMFILE;
        }
    }

    pthread_mutex_lock(&(ft[ft_idx].lock));
    return EXIT_SUCCESS;
}

int ext0_unlock_file(int fd) {
    pthread_mutex_lock(&(sb->mutex));
    if (fd >= MAX_FD_COUNT || ft[fd].inode == NULL) {
        return EBADF;
    }

    pthread_mutex_unlock(&(ft[fd].lock));
    pthread_mutex_unlock(&(sb->mutex));
    return EXIT_SUCCESS;
}

int ext0_get_children(char *path, std::vector<std::string> *result)  {
    pthread_mutex_lock(&(sb->mutex));
    uint32_t inode_id = 0;
    ext0_inode *inode;

    char *tpath = strdup(path);
    // Get inode id
    if ( (inode_id = _get_inode_by_path(tpath)) == 0) {
        pthread_mutex_unlock(&(sb->mutex));
        free(tpath);
        return ENOENT;
    }

    // Read inode
    if ( (inode = _get_inode_by_id(inode_id)) == 0) {
        pthread_mutex_unlock(&(sb->mutex));
        free(tpath);
        return ENOMEM;
    }

    // Read data block
    uint8_t *data_block = NULL;
    if ( (data_block = _read_block(inode->blocks[0])) == NULL ) {
        pthread_mutex_unlock(&(sb->mutex));
        free(tpath);
        free(inode);
        return ENOMEM;
    }

    // Iterate through data and collect children
    result->clear();
    ext0_direntry *curr_entry = (ext0_direntry *) data_block;
    for (size_t i = 0; i < (sb->block_size / sizeof(ext0_direntry)); i++, curr_entry++) {
        if (curr_entry->inode_id == 0) {
            continue;
        }
        if (strcmp(curr_entry->name, ".") == 0 || strcmp(curr_entry->name, "..") == 0) {
            continue;
        }

        result->push_back(std::string(curr_entry->name));
    }

    pthread_mutex_unlock(&(sb->mutex));
    free(tpath);
    free(data_block);
    free(inode);
    return EXIT_SUCCESS;
}

int ext0_delete_file(char *path, bool is_dir) {
    pthread_mutex_lock(&(sb->mutex));
    uint32_t inode_id = 0;

    // Check if the file exists
    if ( (inode_id = _get_inode_by_path(path)) != 0 ) {
        // Remove entry from directory
        char *dir_path = strdup(path);
        char *file_name = NULL;
        char *fpos = strrchr(dir_path, '/');
    
        if (fpos == NULL) {
            pthread_mutex_unlock(&(sb->mutex));
            free(dir_path);
            fprintf(stderr, "[!!] Invalid path format, no '/' found\n");
            return -1;
        }

        // Extract file name and dir path
        file_name = fpos + 1;
        *fpos = '\x00';

        // Get inode id from directory
        uint32_t dir_inode_id = 0;
        if ( (dir_inode_id = _get_inode_by_path(dir_path)) == 0 ) {
            pthread_mutex_unlock(&(sb->mutex));
            fprintf(stderr, "[!!] Could not match directory to an inode\n");
            return -1;
        }

        // Remove entry from directory
        if (_modify_file_in_dir(file_name, dir_inode_id, false, NULL) == false) {
            pthread_mutex_unlock(&(sb->mutex));
            fprintf(stderr, "[!!] Failed to remove entry from dir\n");
            return -1;
        }
        free(dir_path);

        // Get inode and free data blocks for regular files
        if (is_dir == false) {
            ext0_inode *inode = _get_inode_by_id(inode_id);
            if (inode == 0) {
                pthread_mutex_unlock(&(sb->mutex));
                fprintf(stderr, "[!!] Failed to retrieve inode to be deleted\n");
                return -1;
            }
            for (size_t list_id = 0; list_id < MAX_IND_BLOCKS; list_id++) {
                if (inode->blocks[list_id] != 0) {
                    uint32_t *sublist = NULL;
                    if ( (sublist = (uint32_t *)_read_block(inode->blocks[list_id])) == NULL) {
                        fprintf(stderr, "[!!] Failed to read sublist when deleting file\n");
                        break;
                    }

                    // Free entries in sublist
                    for (size_t entry_id = 0; entry_id < (sb->block_size / sizeof(uint32_t)); entry_id++) {
                        if (sublist[entry_id] != 0) {
                            _free_block(sublist[entry_id]);
                            sublist[entry_id] = 0;
                        } else {
                            break;
                        }
                    }
                    free(sublist);
                } else {
                    // Break if the list is unallocated
                    break;
                }
            }
            free(inode);
        }


        // Free actual inode
        if (_free_inode(inode_id)) {
            pthread_mutex_unlock(&(sb->mutex));
            return EXIT_SUCCESS;
        }

        pthread_mutex_unlock(&(sb->mutex));
        return -1;
    }

    // File does not exist
    pthread_mutex_unlock(&(sb->mutex));
    return ENOENT;
}

int ext0_rename_file(char *old_path, char *new_path) {
    pthread_mutex_lock(&(sb->mutex));
    char *old_dir = _get_dir_from_path(old_path);
    char *new_dir = _get_dir_from_path(new_path);

    // Get inode id of directory
    uint32_t new_dir_inode_id = _get_inode_by_path(new_dir);
    if (new_dir_inode_id == 0) {
        return ENOENT;
    }

    if (strncmp(old_dir, new_dir, MAX_FNAME_LEN) == 0) {
        // If only the name changes we can do it in place
        char *old_fname = _get_file_from_path(old_path);
        char *new_fname = _get_file_from_path(new_path);

        // Rename entry in directory
        if (_modify_file_in_dir(old_fname, new_dir_inode_id, true, new_fname) == false) {
            pthread_mutex_unlock(&(sb->mutex));
            free(old_fname);
            free(new_fname);
            fprintf(stderr, "[!!] Failed to remove entry from dir\n");
            return -1;
        }

        free(old_fname);
        free(new_fname);
    } else {
        // Move file to a different directory
        pthread_mutex_unlock(&(sb->mutex));
        fprintf(stderr, "[!!] Move files between directories not implemented!\n");
        exit(-1);
    }

    pthread_mutex_unlock(&(sb->mutex));
    free(old_dir);
    free(new_dir);
    return EXIT_SUCCESS;
}

int ext0_write_file(int fd, size_t offset, uint8_t *data, size_t size) {
    pthread_mutex_lock(&(sb->mutex));
    size_t block_idx = 0;
    uint8_t *aligned_buf = NULL;

    // Check maximum size
    if (offset + size >= MAX_IND_BLOCKS * sb->block_size * sb->block_size) {
        pthread_mutex_unlock(&(sb->mutex));
        fprintf(stderr, "[!!] Requested size bigger than max file size\n");
        fprintf(stderr, "     Size requested: 0x%06lx\n", offset+size);
        return EFBIG;
    }

    // Check if the fd is valid
    if (fd >= MAX_FD_COUNT || ft[fd].inode == 0) {
        pthread_mutex_unlock(&(sb->mutex));
        return EBADF;
    }

    // Check offset and realign data
    if (offset) {
        // Allocate memory for aligned buffer
        if ( (aligned_buf = (uint8_t *)calloc(1, size + sb->block_size)) == NULL ) {
            pthread_mutex_unlock(&(sb->mutex));
            return ENOMEM;
        }

        // Calculate and read starting data block
        block_idx = offset / sb->block_size;
        uint32_t block = _get_block_by_idx(fd[ft].inode, block_idx, true);
        if (block == 0) {
            pthread_mutex_unlock(&(sb->mutex));
            return EFBIG;
        }
        if (szns_read(my_dev, block * sb->block_size, aligned_buf, sb->block_size) != 0) {
            pthread_mutex_unlock(&(sb->mutex));
            free(aligned_buf);
            fprintf(stderr, "Got block id: 0x%08x\n", block);
            _log_inode_data_blocks(ft[fd].inode);
            fprintf(stderr, "[!!] Failed to read data block\n");
            return -1;
        }

        // Copy data to write to buffer
        memcpy(aligned_buf + (offset % sb->block_size), data, size);

        // Use aligned buffer as data and adjust size values
        data = aligned_buf;
        size += ft[fd].inode->size % sb->block_size;
        ft[fd].inode->size -= (ft[fd].inode->size % sb->block_size);
    }

    // Write data block by block to disk
    while (size) {
        size_t curr_transfer = size < sb->block_size ? size : sb->block_size;

        // Check if we have a data block mapping and if not allocate it
        uint32_t block = _get_block_by_idx(fd[ft].inode, block_idx, true);
        if (block == 0) {
            pthread_mutex_unlock(&(sb->mutex));
            if (offset) free(aligned_buf);
            return EFBIG;
        }

        // Write data to block
        if (szns_write(my_dev, block * sb->block_size, data, curr_transfer) != 0) {
            pthread_mutex_unlock(&(sb->mutex));
            if (offset) free(aligned_buf);
            fprintf(stderr, "[!!] Failed to write data to device\n");
            return -1;
        }

        // Adjust inode size
        ft[fd].inode->size += curr_transfer;

        // Shift write buffer and size
        data += curr_transfer;
        size -= curr_transfer;

        // Switch to next block
        block_idx++;
    }

    // Write inode back to disk to update the status
    if (_write_block(ft[fd].inode->uid, (uint8_t *)ft[fd].inode) == false) {
        pthread_mutex_unlock(&(sb->mutex));
        if (offset) free(aligned_buf);
        fprintf(stderr, "[!!] Failed to write inode to device");
        return -1;
    }

    pthread_mutex_unlock(&(sb->mutex));
    if (offset) free(aligned_buf);
    return EXIT_SUCCESS;
}

int ext0_append(int fd, uint8_t *data, size_t size) {
    // Get the inode associated with the fd
    if (fd >= MAX_FD_COUNT || ft[fd].inode == NULL) {
        return EBADF;
    }

    // Call write at an offset of file size
    return ext0_write_file(fd, ft[fd].inode->size, data, size);
}

int ext0_read_file(int fd, uint8_t *res, size_t *bytes_read, size_t size, size_t offset, bool *eof) {
    pthread_mutex_lock(&(sb->mutex));
    size_t block_idx = 0;
    uint8_t *read_buf = NULL;
    uint8_t *curr_buf = NULL;
    *bytes_read = 0;

    // Get the inode associated with the fd
    if (fd >= MAX_FD_COUNT || ft[fd].inode == NULL) {
        pthread_mutex_unlock(&(sb->mutex));
        return EBADF;
    }

    // Check inode size
    if (ft[fd].inode->size == 0) {
        pthread_mutex_unlock(&(sb->mutex));
        *bytes_read = 0;
        *eof = true;
        return EXIT_SUCCESS;
    }

    // Allocate memory for result
    if ( (read_buf = (uint8_t *) calloc(1, sb->block_size)) == NULL) {
        pthread_mutex_unlock(&(sb->mutex));
        return ENOMEM;
    }
    curr_buf = res;

    // If we start inside the file make a partial read of the first block
    if (offset != 0) {
        block_idx = offset / sb->block_size;
        uint32_t block = _get_block_by_idx(fd[ft].inode, block_idx, false);
        size_t read_size = sb->block_size - (offset % sb->block_size);
        read_size = size < read_size ? size : read_size;
        

        // Check if the block is set
        if (block == 0) {
            *eof = true;
            size = 0;
        } else {
            // Read from datablock
            if (szns_read(my_dev, block * sb->block_size, read_buf, sb->block_size) != 0) {
                pthread_mutex_unlock(&(sb->mutex));
                fprintf(stderr, "[!!] Failed to read from device\n");
                free(read_buf);
                return -1;
            }

            // Align read data in result buffer
            memcpy(curr_buf, read_buf + (offset % sb->block_size), read_size);
            block_idx++;

            size -= read_size;
            curr_buf += read_size;
            *bytes_read += read_size;
        }
    }

    // Read remaining bytes from datablocks
    while(size > 0) {
        size_t curr_size = size < sb->block_size ? size : sb->block_size;
        // Get block id
        uint32_t block = _get_block_by_idx(fd[ft].inode, block_idx, false);
        // Check if the block is set
        if (block == 0) {
            *eof = true;
            break;
        }

        // Read from datablock
        if (szns_read(my_dev, block * sb->block_size, read_buf, sb->block_size) != 0) {
            pthread_mutex_unlock(&(sb->mutex));
            fprintf(stderr, "[!!] Failed to read from device\n");
            free(read_buf);
            return -1;
        }

        // Copy data to result buffer
        memcpy(curr_buf, read_buf, curr_size);
        
        // Update counters
        size -= curr_size;
        curr_buf += curr_size;
        block_idx++;
        *bytes_read += curr_size;
    }

    // Free allocated memory
    free(read_buf);

    // Compute actual number of bytes read
    *bytes_read = (*bytes_read > ft[fd].inode->size) ? ft[fd].inode->size : *bytes_read;
    pthread_mutex_unlock(&(sb->mutex));
    return EXIT_SUCCESS;
}

int ext0_get_file_size(int fd, size_t *res) {
    pthread_mutex_lock(&(sb->mutex));
    if (fd >= MAX_FD_COUNT || ft[fd].inode == NULL) {
        pthread_mutex_unlock(&(sb->mutex));
        return EBADF;
    }

    *res = ft[fd].inode->size;
    pthread_mutex_unlock(&(sb->mutex));
    return EXIT_SUCCESS;
}

int ext0_get_file_size_by_name(char *name, size_t *res) {
    pthread_mutex_lock(&(sb->mutex));
    uint32_t inode_id = _get_inode_by_path(name);
    if (inode_id != 0) {
        ext0_inode *inode = _get_inode_by_id(inode_id);
        if (inode != NULL) {
            *res = inode->size;
            free(inode);
            pthread_mutex_unlock(&(sb->mutex));
            return EXIT_SUCCESS;
        }
    }
    
    pthread_mutex_unlock(&(sb->mutex));
    return ENOENT;
}
