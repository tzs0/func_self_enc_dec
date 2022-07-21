#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <elf.h>
#include <sys/mman.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <pthread.h>
#include <regex.h>
#include <setjmp.h>
#include <errno.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/user.h>



//#define         __arm__
//#define         __aarch64__
//#define         __i386__
#define         __x86_64__

#define my_printf(fmt, ...) 		printf("[%s %d] "fmt, __func__, __LINE__, ##__VA_ARGS__)

#if defined(__x86_64__) || defined(__aarch64__)
#define ELF_ST_TYPE					ELF64_ST_TYPE
typedef Elf64_Sym                   Elf_Sym;
#define ELFCLASS_BITS 64
#else
#define ELF_ST_TYPE					ELF32_ST_TYPE
typedef ElfW(Sym)                   Elf_Sym;
#define ELFCLASS_BITS 32
#endif

typedef ElfW( Addr )* bloom_el_t;


/* .gnu.hash (GNU hash for string-table) */
typedef struct _gnu_hash_t{
	const uint32_t   *buckets;
	uint32_t          buckets_cnt;
	const uint32_t   *chains;
	uint32_t          symoffset;
	const ElfW(Addr) *bloom;
	uint32_t          bloom_cnt;
	uint32_t          bloom_shift;
} gnu_hash_t;

typedef struct _funcInfo{
  ElfW(Addr) st_value;
  ElfW(Word) st_size;
}funcInfo;

ElfW(Ehdr) ehdr;

static gnu_hash_t gnu_hash = {0};

//For Test
static void print_all(char *str, int len){
  int i;
  for(i=0;i<len;i++)
  {
    if(str[i] == 0)
      printf("");
    else
      printf("%c", str[i]);
  }
}

static uint32_t gnu_hash_func(const uint8_t* name) {
    uint32_t h = 5381;

    for (; *name; name++) {
        h = (h << 5) + h + *name;
    }

    return h;
}

static unsigned elfhash(const char *_name)
{
#if 1		/* GNU hash */
    uint32_t h = 5381;

    while(*_name)
    {
        h += (h << 5) + *_name++;
    }
    return h;
#endif	
	
#if 0	
    const unsigned char *name = (const unsigned char *) _name;
    unsigned h = 0, g;

    while(*name) {
        h = (h << 4) + *name++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
#endif	
}

const Elf_Sym* gnu_lookup(
    const char* strtab,      /* string table */
    const Elf_Sym* symtab,   /* symbol table */
    const uint32_t* hashtab, /* hash table */
    const char* name         /* symbol to look up */
) 
{
    const uint32_t namehash = gnu_hash_func(name);
    my_printf("namehash:%d\n", namehash);

    const uint32_t nbuckets = hashtab[0];
    my_printf("nbuckets:%d\n", nbuckets);
    const uint32_t symoffset = hashtab[1];
    my_printf("symoffset:%d\n", symoffset);
    const uint32_t bloom_size = hashtab[2];
    my_printf("bloom_size:%d\n", bloom_size);
    const uint32_t bloom_shift = hashtab[3];
    my_printf("bloom_shift:%d\n", bloom_shift);
    const bloom_el_t* bloom = (void*)&hashtab[4];
    const uint32_t* buckets = (void*)&bloom[bloom_size];
    const uint32_t* chain = &buckets[nbuckets];

    my_printf("iamhere\n");
    
    size_t word = bloom[(namehash / ELFCLASS_BITS) % bloom_size];
    my_printf("iamhere\n");
    size_t mask = 0
        | (size_t)1 << (namehash % ELFCLASS_BITS)
        | (size_t)1 << ((namehash >> bloom_shift) % ELFCLASS_BITS);
    my_printf("iamhere\n");
    
    /* If at least one bit is not set, a symbol is surely missing. */
    if ((word & mask) != mask) {
        my_printf("((word(%d) & mask(%d) != mask(%d))\n", word,mask,mask);
        return NULL;
    }

    uint32_t symix = buckets[namehash % nbuckets];
    my_printf("iamhere\n");
    if (symix < symoffset) {
        my_printf("symix(%d) < symoffset(%d)\n", symix, symoffset);
        return NULL;
    }

    /* Loop through the chain. */
    while (1) {
        const char* symname = strtab + symtab[symix].st_name;
        my_printf("symname:%s\n", symname);
        const uint32_t hash = chain[symix - symoffset];
        my_printf("hash:%d\n", hash);
        
        if ((namehash|1) == (hash|1) && strcmp(name, symname) == 0) {
            my_printf("Congratulate! Got the symbol!\n");
            return &symtab[symix];
        }

        /* Chain ends with an element with the lowest bit set to 1. */
        if (hash & 1) {
            my_printf("chain ends\n");
            break;
        }

        symix++;
    }

    my_printf("dont find\n");
    return NULL;
}

static ElfW(Off) findTargetSectionAddr(const int fd, const char *secName){
  ElfW(Shdr) shdr;
  char *shstr = NULL;
  int i;
  
  lseek(fd, 0, SEEK_SET);
  if(read(fd, &ehdr, sizeof(ElfW(Ehdr))) != sizeof(ElfW(Ehdr))){
    my_printf("Read ELF header error\n");
    goto _error;
  }
  
  lseek(fd, ehdr.e_shoff + sizeof(ElfW(Shdr)) * ehdr.e_shstrndx, SEEK_SET);
  
  if(read(fd, &shdr, sizeof(ElfW(Shdr))) != sizeof(ElfW(Shdr))){
    my_printf("Read ELF section string table error\n");
    goto _error;
  }
  
  if((shstr = (char *) malloc(shdr.sh_size)) == NULL){
    my_printf("Malloc space for section string table failed\n");
    goto _error;
  }
  
  lseek(fd, shdr.sh_offset, SEEK_SET);
  if(read(fd, shstr, shdr.sh_size) != shdr.sh_size){
    printf(shstr);
    my_printf("Read string table failed\n");
    goto _error;
  }
  
  lseek(fd, ehdr.e_shoff, SEEK_SET);
  for(i = 0; i < ehdr.e_shnum; i++){
    if(read(fd, &shdr, sizeof(ElfW(Shdr))) != sizeof(ElfW(Shdr))){
      my_printf("Find section .text procedure failed\n");
      goto _error;
    }
    if(strcmp(shstr + shdr.sh_name, secName) == 0){
      my_printf("Find section %s, addr = 0x%x\n", secName, shdr.sh_offset);
      break;
    }
  }
  free(shstr);
  return shdr.sh_offset;
_error:
  return -1;
}

static char getTargetFuncInfo(int fd, const char *funcName, funcInfo *info){
  char flag = -1, *dynstr;
  int i;
  ElfW(Sym) funSym;
  ElfW(Phdr) phdr;
  ElfW(Off) dyn_off;
  ElfW(Word) dyn_size, dyn_strsz;  
  ElfW(Dyn) *symtab_dyn;
  ElfW(Dyn) *strtab_dyn;
  ElfW(Addr) dyn_symtab, dyn_strtab, dyn_hash;
  unsigned funHash, nbucket, nchain, funIndex;
  
  lseek(fd, ehdr.e_phoff, SEEK_SET);
  for(i=0;i < ehdr.e_phnum; i++){ /* 遍历所有段找PT_DYNAMIC */
    if(read(fd, &phdr, sizeof(ElfW(Phdr))) != sizeof(ElfW(Phdr))){
      my_printf("Read segment failed\n");
      goto _error;
    }
    if(phdr.p_type ==  PT_DYNAMIC){
      dyn_size = phdr.p_filesz;
      dyn_off = phdr.p_offset;
      flag = 0;
      my_printf("Find section %s, size = 0x%x, addr = 0x%x\n", ".dynamic\n", dyn_size, dyn_off);
      break;
    }
  }
  if(flag){
    my_printf("Find .dynamic failed\n");
    goto _error;
  }
  flag = 0;
  
  //lseek(fd, dyn_off, SEEK_SET);
  int filelen= lseek(fd,0L,SEEK_END); 
  lseek(fd, 0, SEEK_SET);
  void *ptr = mmap(NULL, filelen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  ElfW(Dyn) *p_dyn = (ElfW(Dyn) *)(ptr+dyn_off);
  
  for(i=0;i < dyn_size / sizeof(ElfW(Dyn)); i++, p_dyn++){    
    if(p_dyn->d_tag == DT_SYMTAB){
        dyn_symtab = p_dyn->d_un.d_ptr;
        symtab_dyn = p_dyn;
        flag += 1;
        my_printf("Find .dynsym, addr = 0x%x\n", dyn_symtab);
    }
    if(p_dyn->d_tag == DT_GNU_HASH){ //For Android: DT_HASH
        dyn_hash = p_dyn->d_un.d_ptr;
        flag += 2;
        my_printf("Find .hash, addr = 0x%x DT_GNU_HASH:%d p_dyn->d_tag:%d\n", 
        dyn_hash, DT_GNU_HASH, p_dyn->d_tag);

        my_printf("p_dyn->d_un.d_ptr:%d\n", p_dyn->d_un.d_ptr);             
    }
    if(p_dyn->d_tag == DT_STRTAB){
      dyn_strtab = p_dyn->d_un.d_ptr;
	  strtab_dyn = p_dyn;
      flag += 4;
      my_printf("Find .dynstr, addr = 0x%x\n", dyn_strtab);
    }
    if(p_dyn->d_tag == DT_STRSZ){
      dyn_strsz = p_dyn->d_un.d_val;
      flag += 8;
      my_printf("Find .dynstr size, size = 0x%x\n", dyn_strsz);
    }
  }
  if((flag & 0x0f) != 0x0f){
    my_printf("Find needed .section failed\n");
    goto _error;
  }
  
#if 1 /* GNU hash方式获取指定函数信息 */
    Elf_Sym *sym_gnu = gnu_lookup(ptr+dyn_strtab, ptr+dyn_symtab, ptr+dyn_hash, funcName);
	if(NULL==sym_gnu){
		my_printf("sym_gnu is NULL\n");
		goto _error;			
	}
	
    my_printf("Find: %s, offset = 0x%x, size = 0x%x\n", funcName, sym_gnu->st_value, sym_gnu->st_size);
    info->st_value = sym_gnu->st_value;
    info->st_size = sym_gnu->st_size;
#endif  

	if (ptr != MAP_FAILED) {
		munmap(ptr, filelen);
	}
   
  return 0;
  
_error:
    if(NULL!=dynstr){
        free(dynstr);
    }
      
  return -1;
}


/* 加密指定函数 */
int main(int argc, char **argv){
  char secName[] = ".text";
  char funcName[] = "lib_func0"; /* 加密指定函数 */
  char *content = NULL;
  int fd, i;
  ElfW(Off) secOff;
  funcInfo info;
  
  if(argc < 2){
    my_printf("Usage: enc_func libxxx.so .(section) function\n");
    return -1;
  }
  fd = open(argv[1], O_RDWR);
  if(fd < 0){
    my_printf("open %s failed\n", argv[1]);
    goto _error;
  }
  
  secOff = findTargetSectionAddr(fd, secName);
  if(secOff == -1){
    my_printf("Find section %s failed\n", secName);
    goto _error;
  }
  if(getTargetFuncInfo(fd, funcName, &info) == -1){
    my_printf("Find function %s failed\n", funcName);
    goto _error;
  }
  
  content = (char*) malloc(info.st_size);
  if(content == NULL){
    my_printf("Malloc space failed\n");
    goto _error;
  }
  
  lseek(fd, info.st_value, SEEK_SET);
  if(read(fd, content, info.st_size) != info.st_size){
    my_printf("Malloc space failed\n");
    goto _error;
  }

  my_printf("info.st_value:%d info.st_size:%d\n", info.st_value, info.st_size);
  printf("\n");
  char tmp = 0;
  for(i=0;i<info.st_size -1;i++){
    tmp = ~content[i];
    printf("%d %d %d\n", i, content[i], tmp);
    content[i] = tmp;   
  }
  printf("\n");
  
  lseek(fd, info.st_value, SEEK_SET);
  if(write(fd, content, info.st_size) != info.st_size){
    my_printf("Write modified content to .so failed\n");
    goto _error;
  }
  my_printf("Complete!\n");
  free(content);
  close(fd);
  return 0;
  
_error:
	my_printf("error!!\n");
    if(NULL!=content){
        free(content);
        content = NULL;
    }	
	close(fd);
	return 0;
}

