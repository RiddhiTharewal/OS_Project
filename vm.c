#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"

#include "shmem.h"
#include "spinlock.h"

extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()


//shared memory Structures

//creating a structure of shared memory region which contains: key,shmid,size,address,etc
struct shmpage{
	int key;
	int no_of_pages;
	int shmid;
	int dflag;
	void *phy_addr[32];
	int permission;
	uint size;
	int shm_cpid;
	int shm_lpid;
	int number_of_attaches;
};

//create a structure of shared memory table array of shared memory regions

struct shmtable{
	struct spinlock lock;
	struct shmpage pages[32];
}shmtable;



// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  char *mem;
  uint a;

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for(; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U) < 0){
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if((d = setupkvm()) == 0)
    return 0;
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if(!(*pte & PTE_P))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char*)P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0) {
      kfree(mem);
      goto bad;
    }
  }
  return d;

bad:
  freevm(d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.


void shminit(void){
	struct shmpage *page;
	initlock(&shmtable.lock,"Shared Memory");
	acquire(&shmtable.lock);
	for(page= shmtable.pages;page<&shmtable.pages[32];page++){
		page->key = -1;
		page->no_of_pages = 0;
		page->shmid = -1;
		page->dflag = 0;
		for(int i = 0;i<32;i++){
			page->phy_addr[i] = (void*)0;
		}
		page->permission = 0;
		page->size = 0;
		page->shm_cpid = -1;
		page->shm_lpid = -1;
		page->number_of_attaches = 0;
	}
	release(&shmtable.lock);
	cprintf("Initialized shared memory table");

}


//Shared Memory functions

//shmget
//Flags:IPC_CREAT creates a new segment of the given size which is rounded off to a multiple of page size and assigns a key to the segment which can used later as a identifier.
        //IPC_EXCL creates if segment not present and gives error if present (something like already exits) and fails.

//key is used as identifier

//check if key is present in shmtable and return shmid according to condition
int check_keystatus(int key,int shmflg,int pages_required){
	for(int i = 0; i<32 ; i++){
			if(shmtable.pages[i].key == key){
				if(shmflg == (IPC_CREAT | IPC_EXCL)){
					return -1;
				}
				if(shmtable.pages[i].no_of_pages != pages_required){
					return -1;
				}
				if(shmtable.pages[i].permission == shm_rd || shmtable.pages[i].permission == shm_rdwr){
					if(shmflg == 0 && key!=IPC_PRIVATE)
						return shmtable.pages[i].shmid;
					if(shmflg == IPC_CREAT)
						return shmtable.pages[i].shmid;
				}
				return -1;
			}
	}
	return -2;
}


int shmget(int key, uint size, int shmflg){
	acquire(&shmtable.lock);
	if(size <= 0){
		release(&shmtable.lock);
		return -1;
	}
	int perm = 0;
	if((shmflg & 3) == (int)shm_rd){
		perm = shm_rd;
		shmflg = shmflg^shm_rd;
	}
	else if((shmflg & 3) == shm_rdwr){
		perm = shm_rdwr;
		shmflg = shmflg^shm_rdwr;
	}
	else if((shmflg!=0) || (key == IPC_PRIVATE)){
		release(&shmtable.lock);
		return -1;
	}
	int pages_required = size/PGSIZE + 1;

	if(pages_required>32){
		release(&shmtable.lock);
		return -1;
	}
	int j = check_keystatus(key,shmflg,pages_required);
	if(j != -2){
		release(&shmtable.lock);
		return j;
	}
	int i;
	for(i=0 ; i<32 ; i++)
		if(shmtable.pages[i].key == -1)
			break;
	if(i == 32){
		release(&shmtable.lock);
		return -1;
	}
	if((key!=IPC_PRIVATE) && (shmflg != IPC_CREAT) && (shmflg != (IPC_CREAT | IPC_EXCL))){
		release(&shmtable.lock);
		return -1;
	}

	for(int k = 0; k < pages_required; k++){
		char* getregion = kalloc();
		if(getregion == 0){
			release(&shmtable.lock);
			return -1;
		}
		memset(getregion, 0, PGSIZE);
		shmtable.pages[i].phy_addr[k] = (void*)V2P(getregion);
	}
	shmtable.pages[i].no_of_pages = pages_required;
	shmtable.pages[i].key = key;
	shmtable.pages[i].size = size;
	shmtable.pages[i].permission = perm;
	shmtable.pages[i].shmid = i;
	shmtable.pages[i].shm_cpid = myproc()->pid;
	release(&shmtable.lock);

	return i;	//shmid
}

/*
shmdt
detaches the shared memory located  at the address specified by shmaddr
}*/

int shmdt(void *shmaddr){
	acquire(&shmtable.lock);
	int k;
	int shmid,no_of_pages;
	struct proc *p = myproc();
	void* v_addr = (void*)0;

	for(k = 0; k < 32; k++){
		if(p->pages[k].key != -1 && p->pages[k].v_addr == shmaddr){
			v_addr = p->pages[k].v_addr;
			shmid = p->pages[k].shmid;
			no_of_pages = p->pages[k].no_of_pages;
			break;
		}
	}
	if(v_addr){
		for(int j = 0;j<no_of_pages;j++){
			pte_t* pte = walkpgdir(p->pgdir, (void*)((uint)v_addr + j*PGSIZE), 0);
			if(pte == 0) {
				release(&shmtable.lock);
				return -1;
			}
			*pte = 0;
		}
		p->pages[k].shmid = -1;
		p->pages[k].no_of_pages = 0;
		p->pages[k].key = -1;
		p->pages[k].v_addr = (void*)0;
		p->pages[k].permission = PTE_W | PTE_U;
		if(shmtable.pages[shmid].number_of_attaches > 0){
			shmtable.pages[shmid].number_of_attaches--;
		}
		if(shmtable.pages[shmid].number_of_attaches == 0 && shmtable.pages[shmid].dflag==1){
			for(int j = 0; j < shmtable.pages[k].no_of_pages; j++){
				void *a = (void*)P2V(shmtable.pages[k].phy_addr[j]);
				kfree(a);
				shmtable.pages[k].phy_addr[j] = (void*)0;
			}
			shmtable.pages[k].key = -1;
			shmtable.pages[k].no_of_pages = 0;
			shmtable.pages[k].shmid = -1;
			shmtable.pages[k].dflag = 0;
			shmtable.pages[k].permission = -1;
			shmtable.pages[k].size = 0;
			shmtable.pages[k].shm_lpid = -1;
			shmtable.pages[k].shm_cpid = -1;
			shmtable.pages[k].number_of_attaches = 0;
			release(&shmtable.lock);
			return 0;
		}
		shmtable.pages[shmid].shm_lpid = p->pid;
		release(&shmtable.lock);
		return 0;
	}
	else{
		release(&shmtable.lock);
		return -1;
	}
}
/*shmat
we get shmid from shmget
attaches memory segment identified by shmid to the address space of process
shmaddr provides this address:if null suitable unused address attached
                              else if null attach occurs to address equal to shmaddr
*/
void *shmat(int shmid, void *shmaddr, int shmflg){
	acquire(&shmtable.lock);
	if((shmid < 0 || shmid>32)){
		release(&shmtable.lock);
		return (void*)-1;
	}
	int k = shmtable.pages[shmid].shmid;
	if(k==-1){
		release(&shmtable.lock);
		return (void*)-1;
	}
	void* va = (void*)MAXHEAP;
	void* lva = (void*)(KERNBASE-1);
	int index = -1;
	uint remainder = ((uint)shmaddr -((uint)shmaddr %SHMLBA));	//check
	struct proc *process = myproc();
	if(shmaddr == (void*)0){
		for(int i = 0; i < 32; i++){
			int j;
			index = -1;
			lva = (void*)(KERNBASE-1);
			for(j = 0; j < 32; j++){
				if((process->pages[j].key != -1) && ((uint)process->pages[j].v_addr >= (uint)va) && ((uint)lva >= (uint)process->pages[j].v_addr)){
				lva = process->pages[j].v_addr;
				index = j;
				}
			}
			if(index != -1){
				lva = process->pages[index].v_addr;
				if((uint)va + shmtable.pages[k].no_of_pages*PGSIZE <=  (uint)lva)
					break;
				else
					va = (void*)((uint)lva + process->pages[index].no_of_pages*PGSIZE);
			} else
				break;
		}
	}
	else if((shmaddr != (void*)0) && ((shmaddr >= (void*)KERNBASE) || shmaddr < (void*)MAXHEAP)){
		release(&shmtable.lock);
		return (void*)-1;
	}
	else if((shmaddr != (void*)0) && ((shmflg & SHM_RND) != 0)){
		if(!remainder){
			release(&shmtable.lock);
			return (void*)-1;
		}
		va = (void*)remainder;
	}
	else if((shmaddr != (void*)0) && ((shmflg & SHM_RND) == 0)){
		if(remainder == (uint)shmaddr){
			va = (void*)shmaddr;
		}
	}
	if((uint)va + shmtable.pages[k].no_of_pages*PGSIZE >= KERNBASE){
		release(&shmtable.lock);
		return (void*)-1;
	}
	index = -1;
	for(int i = 0; i<32 ; i++){
		if(process->pages[i].key != -1 && (uint)process->pages[i].v_addr + process->pages[i].no_of_pages*PGSIZE > (uint)va && (uint)va>=(uint)process->pages[i].v_addr){
			index = i;
			break;
		}
	}
	if(index != -1){
		if(shmflg & SHM_REMAP){
			uint seg = (uint)process->pages[index].v_addr;
			if(seg < (uint)va + shmtable.pages[k].no_of_pages*PGSIZE){
				release(&shmtable.lock);
				if(shmdt((void*)seg) == -1){
					return (void*)-1;
				}
				acquire(&shmtable.lock);
			}
		}
		else{
			release(&shmtable.lock);
			return (void*)-1;
		}
	}
	int pflag;
	if(((shmflg & SHM_RDONLY)!=0) && (shmtable.pages[k].permission == shm_rd)){
		pflag = PTE_U;
	}
	else if(((shmflg & SHM_RDONLY)==0) && (shmtable.pages[k].permission == shm_rdwr)){
		pflag = PTE_W | PTE_U;
	}
	else{
		release(&shmtable.lock);
		return (void*)-1;
	}

	for(int j = 0;j<shmtable.pages[k].no_of_pages;j++){
		mappages(process->pgdir, (void*)((uint)va + (j*PGSIZE)), PGSIZE, (uint)shmtable.pages[k].phy_addr[j], pflag);
	}

	index = -1;
	for(int i = 0 ; i<32 ; i++){
		if(process->pages[i].key == -1){
			index = i;
			break;
		}
	}

	if(index == -1){
		release(&shmtable.lock);
		return (void*)-1;
	}
	process->pages[index].shmid = shmid;
	process->pages[index].v_addr = va;
	process->pages[index].key = shmtable.pages[k].key;
	process->pages[index].no_of_pages = shmtable.pages[k].no_of_pages;
	process->pages[index].permission = pflag;
	shmtable.pages[k].number_of_attaches++;
	shmtable.pages[k].shm_lpid = process->pid;

	release(&shmtable.lock);
	return va;
}


/*shmctl
controls the shared memory region corresponding to shmid
cmd: IPC_SET, IPC_RMID
IPC_RMID: destroy segment only after last process detaches it
*/

int shmctl(int shmid, int cmd, void *buf){
	acquire(&shmtable.lock);
	if(shmid<0 || shmid>32){
		return -1;
	}
	int i = shmtable.pages[shmid].shmid;

	if(i != -1){

		if((cmd == IPC_SET) && buf && (((int)buf == shm_rd) || ((int)buf == shm_rdwr))){
			shmtable.pages[i].permission = (int)buf;
			release(&shmtable.lock);
			return 0;
		}
		else if(cmd == IPC_RMID){
			if(shmtable.pages[i].number_of_attaches == 0 ){
				for(int j = 0; j < shmtable.pages[i].no_of_pages; j++){
					void* free_addr = (void*)P2V(shmtable.pages[i].phy_addr[j]);
					kfree(free_addr);
					shmtable.pages[i].phy_addr[j] = (void*)0;
				}
				shmtable.pages[i].no_of_pages = 0;
				shmtable.pages[i].key = -1;
				shmtable.pages[i].shmid = -1;
				shmtable.pages[i].dflag = 0;
				shmtable.pages[i].permission = 0;
				shmtable.pages[i].size = 0;
				shmtable.pages[i].shm_lpid = -1;
				shmtable.pages[i].shm_cpid = -1;
				shmtable.pages[i].number_of_attaches = 0;
				release(&shmtable.lock);
				return 0;
			}
			else{
				shmtable.pages[i].dflag = 1;
				release(&shmtable.lock);
				return 0;
			}
		}
		else{
			release(&shmtable.lock);
			return 0;
		}
	}
	release(&shmtable.lock);
	return -1;
}
