#include "mem_alloc.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "mem_alloc_types.h"

/* memory */
char memory[MEMORY_SIZE];

/* Pointer to the first free block in the memory */
mem_free_block_t *first_free;
mem_used_block_t *first_allocated;


#define ULONG(x)((long unsigned int)(x))
#define max(x,y) (x>y?x:y)

char *assign_block(mem_free_block_t *node, int size) {
    char* result = (char*) node + sizeof(mem_free_block_t);

    // there's enough space to create metadata for the remaining block
    if (node->size >= size + sizeof(mem_free_block_t)) {
        // must cast node into (void*) (or char*) first so that addition of pointer would increase memory address by 1 for each +1 operation
        // without casting, the increment will be sizeof(mem_free_block_t) bytes for each +1 operation, hence reaching out of bound of memory array soon
        mem_free_block_t *new_block = (mem_free_block_t*) ((char*) node + sizeof(mem_free_block_t) + size);

        new_block->size = node->size - sizeof(mem_free_block_t) - size;
        new_block->prev = node->prev;
        new_block->next = node->next;
        //update of the allocated space
        node->size = size;

        if (new_block->prev == NULL) {
            first_free = new_block;
        } else {
            new_block->prev->next = new_block;
        }

        if (new_block->next != NULL) {
            new_block->next->prev = new_block;
        }
    } else {
        if (node->prev == NULL) {
            first_free = node->next;
            if (node->next != NULL) {
                node->next->prev = NULL;
            }
        } else {
            node->prev->next = node->next;
            if (node->next != NULL) {
                node->next->prev = node->prev;
            }
        }
    }

    return result;
}

/**
 * insert a block to the allocated list
 * maintain that the allocated list is ordered by the address increasingly
 */
void update_allocated_list(mem_free_block_t *block){
    mem_free_block_t *node = first_allocated;

    if (first_allocated == NULL) {
        first_allocated = block;
        block->next = NULL;
        return;
    }

    if (block < first_allocated) {
        block->next = first_allocated;
        first_allocated = block;
        return;
    }

    while (node < block && !(node->next == NULL || node->next > block)) {
        node = node->next;
    }
    block->next = node->next;
    node->next = block;
}

/**
 * get the block with lower address amongst 2 blocks
 * NULL is treated as highest address possible
 */
mem_free_block_t* get_lower_address_block(mem_free_block_t* node1, mem_free_block_t* node2) {
    if (node1 == NULL) {
        return node2;
    }

    if (node2 == NULL) {
        return node1;
    }

    return node1 < node2 ? node1 : node2;
}

/**
 * check for memory consistency by walking through allocated and free list
 * if the total size of block & metadata is not equal to MEMORY_SIZE, yield an error
 */
void check_memory_consistency() {
    mem_free_block_t *free_node = first_free;
    mem_free_block_t *allocated_node = first_allocated;

    mem_free_block_t *node, *next_node;
    int sum = 0;

    node = get_lower_address_block(free_node, allocated_node);
    if (node == NULL) {
        fprintf(stderr, "ERROR: Total memory calculated is 0 != %d, exiting\n", MEMORY_SIZE);
        exit(1);
    }

    do {
        if (node == free_node && free_node != NULL) {
            free_node = free_node->next;
        }
        if (node == allocated_node && allocated_node != NULL) {
            allocated_node = allocated_node->next;
        }

        next_node = get_lower_address_block(free_node, allocated_node);
        if (next_node != NULL) {
            sum += (void*) next_node - (void*) node;
        } else {
            sum += node->size + (int) sizeof(mem_free_block_t);
        }

        node = next_node;
    } while(node != NULL);

    if (sum != MEMORY_SIZE) {
        fprintf(stderr, "ERROR: Total memory calculated is %d != %d, exiting\n", sum, MEMORY_SIZE);
        exit(1);
    }
}


#if defined(FIRST_FIT)

/* code specific to first fit strategy can be inserted here */
char *find_free_block(int size) {
    // TODO what if size <= 0
    char *result = NULL;
    mem_free_block_t *node = first_free;
    mem_free_block_t *memo;

    while(node != NULL) {
        if (node->size >= size) {
            memo = node;
            result = assign_block(node, size);
            break;
        }
        node = node->next;
    }

    if (result == NULL) {
        print_error_alloc(size);
        exit(0);
    }

    update_allocated_list(memo);
    return result;
}

#elif defined(BEST_FIT)

/* code specific to best fit strategy can be inserted here */
char *find_free_block(int size) {
    mem_free_block_t *node = first_free;
    mem_free_block_t *memo = NULL;
    char *addr;

    while (node != NULL) {
        if (node->size >= size && (memo == NULL || node->size < memo->size)) {
            memo = node;
        }
        node = node->next;
    }

    if (memo == NULL) {
        print_error_alloc(size);
        exit(0);
    }

    addr = assign_block(memo, size);
    update_allocated_list(memo);
    return addr;
}

#elif defined(WORST_FIT)

/* code specific to worst fit strategy can be inserted here */
char *find_free_block(int size) {
    mem_free_block_t *node = first_free;
    mem_free_block_t *memo = NULL;
    char *addr;

    while (node != NULL) {
        if (node->size >= size && (memo == NULL || node->size > memo->size)) {
            memo = node;
        }
        node = node->next;
    }

    if (memo == NULL) {
        print_error_alloc(size);
        exit(0);
    }

    addr = assign_block(memo, size);
    update_allocated_list(memo);
    return addr;
}

#endif

void run_at_exit(void)
{
    /* function called when the programs exits */
    /* To be used to display memory leaks informations */
    /* ... */
    if (first_free->size + sizeof(mem_free_block_t) != MEMORY_SIZE) {
        fprintf(stderr, "WARNING: There is some allocated memory that is not made free before exiting.\n");
    }
}



void memory_init(void){

    /* register the function that will be called when the programs exits*/
    atexit(run_at_exit);

    /* .... */
    first_free = (mem_free_block_t*) memory;
    first_free->size = MEMORY_SIZE - sizeof(mem_free_block_t);
    first_free->prev = NULL;
    first_free->next = NULL;
}

char *memory_alloc(int size){

    /* .... */
    check_memory_consistency();
    char *addr = find_free_block(size);
    print_alloc_info(addr, size);
    return addr;

}

/**
 * check if a given address is pointing to the head of a memory block that was allocated before
 */
int is_allocated_pointer(char* addr) {
    mem_used_block_t *prev = NULL;
    mem_used_block_t *node = first_allocated;
    while (node != NULL && ((char*) node + sizeof(mem_free_block_t) != addr)) {
        prev = node;
        node = node->next;
    }
    if (node == NULL) {
        return 0;
    } else {
        if (node == first_allocated) {
            first_allocated = node->next;
        } else {
            prev->next = node->next;
        }
        return 1;
    }
}

void memory_free(char *p){
    check_memory_consistency();
    mem_free_block_t *node = first_free;
    mem_free_block_t *freed = (mem_free_block_t*) (p - sizeof(mem_free_block_t));

    mem_free_block_t *prev_node, *next_node;

    if (!is_allocated_pointer(p)) {
        fprintf(stderr, "WARNING: the provided address [%p] is not associated to an allocated memory block. Failed to free.\n", p);
        return;
    }

    // find the block to be free and bring it back to the list
    // reintegrate a block to the list must preserve the ascending order by address of the list
    if (first_free == NULL) {
        freed->prev = NULL;
        freed->next = NULL;
        first_free = freed;

        prev_node = NULL;
        next_node = NULL;
    } else if (freed < node) {
        freed->prev = NULL;
        node->prev = freed;
        freed->next = node;
        first_free = freed;

        prev_node = NULL;
        next_node = freed->next;
    } else {
        while (node != NULL && !(node->next == NULL || node->next > freed)) {
            node= node->next;
        }

        if (node != NULL) {
            freed->prev = node;
            if(node->next != NULL) {
                node->next->prev = freed;
            }
            freed->next = node->next;
            node->next = freed;

            prev_node = freed->prev;
            next_node = freed->next;
        } else {
            fprintf(stderr, "WARNING: the provided address [%p] is not associated to an allocated memory block. Failed to free.\n", p);
            return;
        }
    }

    // do the merging
    // FIXME assuming that a block is allocated with internal fragmentation,
    // i.e. we got 26 bytes left but the request is for just 24 bytes, the 2 extra bytes isn't big enough for a metadata block,
    // then we free the allocated block immediately next to it, the leftover bytes due to previous internal fragmentation
    // aren't coalerced into the new free block
    if ((char*) freed + freed->size + sizeof(mem_free_block_t) == (char*) next_node) // if next_node is NULL, this condition will always fail
    {
        freed->next = next_node->next;
        if (next_node->next != NULL) {
            next_node->next->prev = freed;
        }
        freed->size += next_node->size + sizeof(mem_free_block_t);
    }

    if (prev_node != NULL && (char*) prev_node + prev_node->size + sizeof(mem_free_block_t) == (char*) freed)
    {
        prev_node->next = freed->next;
        if (freed->next != NULL) {
            next_node->prev = prev_node;
        }
        prev_node->size += freed->size + sizeof(mem_free_block_t);
    }

    print_free_info(p);

}


void print_alloc_info(char *addr, int size){
  if(addr){
      fprintf(stderr, "ALLOC at : %lu (%d byte(s))\n",
              ULONG(addr - memory), size);
  }
  else{
      fprintf(stderr, "Warning, system is out of memory\n");
  }
}


void print_free_info(char *addr){
    if(addr){
        fprintf(stderr, "FREE  at : %lu \n", ULONG(addr - memory));
    }
    else{
        fprintf(stderr, "FREE  at : %lu \n", ULONG(0));
    }
}

void print_error_alloc(int size)
{
    fprintf(stderr, "ALLOC error : can't allocate %d bytes\n", size);
}

void print_info(void) {
  fprintf(stderr, "Memory : [%lu %lu] (%lu bytes)\n", (long unsigned int) memory, (long unsigned int) (memory+MEMORY_SIZE), (long unsigned int) (MEMORY_SIZE));
}


void print_free_blocks(void) {
    mem_free_block_t *current;
    fprintf(stderr, "Begin of free block list :\n");
    for(current = first_free; current != NULL; current = current->next)
        fprintf(stderr, "Free block at address %lu, size %u\n", ULONG((char*)current - memory), current->size);
}

char *heap_base(void) {
  return memory;
}

#ifdef MAIN
int main(int argc, char **argv){

  /* The main can be changed, it is *not* involved in tests */
  memory_init();
  print_info();
  print_free_blocks();
  int i ;
  char *b;
  for( i = 0; i < 10; i++){
    b = memory_alloc(rand()%8);
    memory_free(b);
    print_free_blocks();
  }

  char * a = memory_alloc(15);
  //a=realloc(a, 20);
  memory_free(a);

  print_free_blocks();

  a = memory_alloc(10);
  b = memory_alloc(10);
  *(a+10)='9';
  memory_free(a);
  memory_free(a);
  //fprintf(stderr,"%lu\n",(long unsigned int) (memory_alloc(9)));
  return EXIT_SUCCESS;
}
#endif
