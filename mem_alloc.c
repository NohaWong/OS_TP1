#include "mem_alloc.h"
#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "mem_alloc_types.h"

/* memory */
char memory[MEMORY_SIZE];

/* Pointer to the first free block in the memory */
mem_free_block_t *first_free;


#define ULONG(x)((long unsigned int)(x))
#define max(x,y) (x>y?x:y)

#if defined(FIRST_FIT)

/* code specific to first fit strategy can be inserted here */
char *find_free_block(int size) {
    // TODO what if size <= 0
    char *result = NULL;
    mem_free_block_t *node = first_free;

    while(node != NULL) {
        printf("free mem: %d, trying: %d\n", node->size, size);

        if (node->size >= size) {
            result = (char*) (node + sizeof(mem_free_block_t));

            // there's enough space to create metadata for the remaining block

            if (node->size >= size + sizeof(mem_free_block_t)) {
                // must cast node into (void*) (or char*) first so that addition of pointer would increase memory address by 1 for each +1 operation
                // without casting, the increment will be sizeof(mem_free_block_t) bytes for each +1 operation, hence reaching out of bound of memory array soon
                mem_free_block_t *new_block = (mem_free_block_t*) ((void*) node + sizeof(mem_free_block_t) + size);
                printf("---\n");
                printf("address difference: %lu\n", ULONG((char *) new_block - memory));
                printf("remaining mem: %lu\n", node->size - sizeof(mem_free_block_t) - size);

                new_block->size = node->size - sizeof(mem_free_block_t) - size;
                new_block->next = node->next;
                //update of the allocated space
                node->size = size;

                if (node == first_free) {
                    first_free = new_block;
                }
            }
            else
            {
                if(node == first_free)
                {
                    first_free=node->next;
                }
            }

            break;
        }
        node = node->next;
    }

    if (result == NULL) {
        print_error_alloc(size);
        exit(0);
    }

    return result;
}

#elif defined(BEST_FIT)

/* code specific to best fit strategy can be inserted here */

#elif defined(WORST_FIT)

/* code specific to worst fit strategy can be inserted here */

#endif

void run_at_exit(void)
{
    /* function called when the programs exits */
    /* To be used to display memory leaks informations */
  printf("there's a problem\n");
    /* ... */
}



void memory_init(void){

    /* register the function that will be called when the programs exits*/
    atexit(run_at_exit);

    /* .... */
    first_free = (mem_free_block_t*) memory;
    first_free->size = MEMORY_SIZE - sizeof(mem_free_block_t);
    first_free->next = NULL;
}

char *memory_alloc(int size){

    /* .... */
    return find_free_block(size);

}

void memory_free(char *p){
    mem_free_block_t *node = first_free;
    mem_free_block_t *freed = (mem_free_block_t*) p-sizeof(mem_free_block_t);

    if(freed<node)
    {
      freed->next=node;
      first_free=freed;
      return;
    }
    while(node != NULL && (node->next == NULL || node->next > freed))
    {
      node= node->next;
    }
    
    if(node != NULL)
    {
      freed->next=node->next;
      node->next=freed;
    }
    else
    {

      //bad pointer TO DO after 
      exit(1);
    }
    
    // else
    // {
    //   node->size+=(p - sizeof(mem_free_block_t))->size + sizeof(mem_free_block_t);
    //   if(node + sizeof(mem_free_block_t)+node->size == node->next)
    //   {
    //     node->size+=sizeof(mem_free_block_t)+node->next->size;
    //     node->next=node->next->next;
    //   }
    // }

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
  for( i = 0; i < 10; i++){
    char *b = memory_alloc(rand()%8);
    memory_free(b);
    print_free_blocks();
  }

  char * a = memory_alloc(15);
  //a=realloc(a, 20);
  memory_free(a);

  print_free_blocks();

  a = memory_alloc(10);
  memory_free(a);

  fprintf(stderr,"%lu\n",(long unsigned int) (memory_alloc(9)));
  return EXIT_SUCCESS;
}
#endif
