#ifndef   	_MEM_ALLOC_TYPES_H_
#define   	_MEM_ALLOC_TYPES_H_

// set MEM_ALIGNMENT to higher than 1 to consider address padding
#define MEM_ALIGNMENT 1


/* Structure declaration for a free block */
typedef struct mem_free_block{
    int size;
    struct mem_free_block *prev;
    struct mem_free_block *next;
    /* ...*/
} mem_free_block_t;

/* Structure declaration for a used block */
typedef mem_free_block_t mem_used_block_t;

/* Specific metadata for used blocks */
/* typedef struct mem_used_block{ */
/*     int size; */
/*     /\* ...*\/ */
/* } mem_used_block_t; */

#endif
