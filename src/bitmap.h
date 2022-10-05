#ifndef BITMAP_H
#define BITMAP_H
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>

typedef uint8_t bitmap;

// Allocate a bitmap supporting size bits
bitmap *bitmap_alloc(size_t size);

// Free a bitmap
void bitmap_free(bitmap *bm);

// Set a bit in a bitmap
void bitmap_set(bitmap *bm, size_t idx);

// Clear a bit in a bitmap
void bitmap_clear(bitmap *bm, size_t idx);

// Check if a bit is set in a bitmap
bool bitmap_check(bitmap *bm, size_t idx);

// Calculates the size of the bitmap based on the number of entries
size_t bitmap_size(size_t entries);

// Bitmap header guard
#endif
