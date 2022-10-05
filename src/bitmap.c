#include "bitmap.h"

bitmap *bitmap_alloc(size_t size) {
    size += CHAR_BIT;
    return (bitmap *)calloc(1, size / (CHAR_BIT));
}

void bitmap_free(bitmap *bm) {
    free(bm);
}

void bitmap_set(bitmap *bm, size_t idx) {
    bm[idx / (CHAR_BIT)] |= ( 1 << idx % (CHAR_BIT) );
}

void bitmap_clear(bitmap *bm, size_t idx) {
    bm[idx / (CHAR_BIT)] &= ~( 1 << idx % (CHAR_BIT) );
}

bool bitmap_check(bitmap *bm, size_t idx) {
    return (bm[idx / (CHAR_BIT)] & ( 1 << idx % (CHAR_BIT) ));
}

size_t bitmap_size(size_t entries) {
    return ((entries + CHAR_BIT) / CHAR_BIT);
}
