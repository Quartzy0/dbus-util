#include "vec.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define CHECK_ERROR(expr) { \
    if((expr) != 0) {       \
        fprintf(stderr, #expr " (was non 0): %s", strerror(errno)); \
        return -1;\
    }                            \
}

int
vec_init(struct vec *vec) {
    vec->size = VEC_INITIAL_SIZE;
    vec->el = calloc(VEC_INITIAL_SIZE, sizeof(*vec->el));
    CHECK_ERROR(!vec->el);
    vec->len = 0;
    return 0;
}

int
vec_init_with_size(struct vec *vec, size_t initial) {
    vec->size = initial;
    vec->el = calloc(initial, sizeof(*vec->el));
    CHECK_ERROR(!vec->el);
    vec->len = 0;
    return 0;
}

int
vec_add(struct vec *vec, void *el) {
    if (!vec) return 0;
    if (vec->size <= vec->len + 1) {
        void **realloc_tmp = realloc(vec->el, (vec->size + VEC_SIZE_STEP) * sizeof(*realloc_tmp));
        CHECK_ERROR(!realloc_tmp);
        vec->el = realloc_tmp;
        vec->size += VEC_SIZE_STEP;
    }
    vec->el[vec->len++] = el;
    return 0;
}

int
vec_remove_index(struct vec *vec, size_t index) {
    if (!vec || index >= vec->len) return 1;
    memmove(&vec->el[index], &vec->el[index + 1], sizeof(*vec->el) * (vec->len - index - 1));
    vec->len--;
    return 0;
}

int
vec_remove_element(struct vec *vec, void *el) {
    if (!vec || !el) return 1;
    size_t i;
    for (i = 0; i < vec->len; ++i) {
        if (vec->el[i] == el) break;
    }
    if (i != vec->len) {
        memmove(&vec->el[i], &vec->el[i + 1], sizeof(*vec->el) * (vec->len - i - 1));
        vec->len--;
    }
    return i == vec->len;
}

int
vec_remove_all(struct vec *vec) {
    memset(vec->el, 0, sizeof(*vec->el) * vec->len);
    vec->len = 0;
    return 0;
}

int
vec_free(struct vec *vec) {
    if (!vec) return 0;
    free(vec->el);
    memset(vec, 0, sizeof(*vec));
    return 0;
}