/*
 A simple FS implementation

 Copyright (c) 2021 - current
 Authors:  Barger M.
*/

#ifndef EXT0_H
#define EXT0_H

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "bitmap.h"
#include <zns_device.h>

/* Defines */

#define ROOT_INODE      ( (uint32_t) 1 )    // ID of the / inode
#define INODE_RATIO     ( (size_t) 10 )     // Ratio of data blocks to inodes
#define MAX_IND_BLOCKS  ( (size_t) 512 )    // Maximum indirect/data blocks per inode
#define MAX_FNAME_LEN   ( (size_t) 24 )     // Maximum length of a filename
#define MAX_FD_COUNT    ( (int) 256 )       // Maximum number of fds (open files)

#define FTYPE_FILE      ( (uint32_t) 0 )    // Regular file
#define FTYPE_DIR       ( (uint32_t) 1 )    // Directory
#define FTYPE_IRR       ( (uint32_t) 42 )   // Irrellevant

// Block IDs for FS persistency
#define P_SUPERBLCK_LBA ( (size_t) 0 )

/* Typedefs */

// Superblock
typedef struct ext0_sb {
    uint32_t inode_cnt;         // Number of inodes
    uint32_t block_cnt;         // Number of data blocks
    uint32_t free_inode_cnt;    // Number of free inodes
    uint32_t free_block_cnt;    // Number of free data blocks
    uint32_t first_block;       // Address of the first data block
    uint32_t block_size;        // Size of inodes and data blocks
    bitmap *inode_bitmap;       // Inode allocation bitmap
    bitmap *block_bitmap;       // Data block allocation bitmap
    pthread_mutex_t mutex;      // FS mutex
} ext0_sb;

// Inode
typedef struct ext0_inode {
    uint32_t uid;   // Inode ID
    uint32_t size;  // Size of contained data
    uint32_t blocks[MAX_IND_BLOCKS];
} ext0_inode;

// Directory entry, size is 32 bytes fixed
// Instead of enum we use uint32_t to achieve that
typedef struct ext0_direntry {
    uint32_t inode_id;          // Inode ID of entry
    uint32_t ftype;             // Filetype
    char name[MAX_FNAME_LEN];   // Name
} __attribute__((packed)) ext0_direntry;

// Open File table entry
typedef struct ext0_ft_entry {
    ext0_inode *inode;
    pthread_mutex_t lock;
} ext0_ft_entry;

/* Function Declarations */

// Initialize the ext0 fs
int ext0_init(struct user_zns_device *my_device);

// Deinitialize the ext0 fs
void ext0_deinit();

// Creates a file with the given path if it does not exist
int ext0_create_file(char *path, uint32_t ftype);

// Prints the fs structure with the given indent levels
void ext0_list_fs(size_t indent);

// Opens a file and returns the fd if successfull
int ext0_open_file(char *path, int *fd);

// Closes a file specified by the fd
int ext0_close_file(int fd);

// Checks if a file of a given type exists
bool ext0_file_exists(char *path, uint32_t ftype);

// Locks an open file in the file table and returns the fd
int ext0_lock_file(char *path, int *fd);

// Unlocks an open file in the file table identified by the fd
int ext0_unlock_file(int fd);

// Retrieves the children of a directory and stores them in the provided vector
int ext0_get_children(char *path, std::vector<std::string> *result);

// Deletes a file referred to by a path
int ext0_delete_file(char *path, bool is_dir);

// Renames a file
int ext0_rename_file(char *old_path, char *new_path);

// Write to file at given offset
int ext0_write_file(int fd, size_t offset, uint8_t *data, size_t size);

// Append data to file
int ext0_append(int fd, uint8_t *data, size_t size);

// Read data from file
int ext0_read_file(int fd, uint8_t *res, size_t *bytes_read, size_t size, size_t offset, bool *eof);

// Get file size from an open file
int ext0_get_file_size(int fd, size_t *res);

// Get file size of a file identified by its name
int ext0_get_file_size_by_name(char *name, size_t *res);

// EXT0 header guard
#endif
