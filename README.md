<h1>Report For Assignment 4</h1>
<h2>Compilation Steps</h2>

```
$ make clean 
$ make qemu SCHEDULER=RR/FCFS/PBS
```
SCHEDULER can be omitted , in which case , the default will be RR.
<h1>Implementation Of The Commands</h1>

<h2>strace</h2>
We have implemented strace system call. 

* We added a new `int` variable `trace_mask` to store the mask given by `strace` system call. 

* We added a syscall with `#define SYS_trace 22` in `syscall.h`. 

* The prototype for the `strace` was added to `syscall.c` as follows : 
```
extern uint64 sys_trace(void);
```

In `syscall.c` : 
* We added the corresponding system call to `syscalls` array (which contains the system calls). 

* The name of the `syscall` was added to the `syscallnames` array. 

* The number of parameters required for the functions of each system calls have been added to the `sysparameters` array. 

* We stored all the possible parameters of the functions in `parameterarr` as follows : 
```
int parameterarr[]={p->trapframe->a0,p->trapframe->a1,p->trapframe->a2,p->trapframe->a3,p->trapframe->a4,p->trapframe->a5};
```
* We added the following piece of code to `syscall` function :-
```
if (num > 0 && num < NELEM(syscalls) && syscalls[num])
  {
    p->trapframe->a0 = syscalls[num]();

    int divisor = 1;

    for(int i = 0 ; i < num ; i++)
    {
      divisor*=2;
    }

    if ((((p->trace_mask)/divisor)&1)==1)
    {
      // printf("mask= %d divisor= %d\n",p->mask,divisor);
      printf("%d: syscall %s ( ",p->pid,syscallnames[num]);

      for (int i = 0; i < sysparameters[num]; i++)
      {
        printf("%d ",parameterarr[i]);
      }
      
      printf(") -> %d\n",p->trapframe->a0);
    }
 }       
```
* In `proc.c` , we have made the following changes to transfer the parent's mask to the child process : 
```
// copy tracemask
  np->trace_mask = p->trace_mask;
```
* In `sysproc.c` , we added the function `uint64 sys_trace(void)` to initialize the mask for the process as follows : 
```
uint64
sys_trace(void)
{
  int a;

  int ret = argint(0,&a);

  if(ret < 0 )
  {
    return -1;
  }

  myproc()->trace_mask = a;

  return 0;
}
```
* We added the following prototype in the `user.h` : 
```
int trace(int);
```
* Add the `trace` as an entry to the `usys.pl` as follows : 
```
entry("trace");
```
* We added the file `strace.c` which contains the interface for the `strace` command: 
```
#include "kernel/types.h"
#include "user/user.h"
#include "kernel/fcntl.h"

int main(int argc,char** argv)
{
    if (argc < 3)
    {
        printf("Atleast 3 parameters required\n");
        exit(1);
    }
    else if (trace(atoi(argv[1]))<0)
    {        
        printf("strace failed\n");
        exit(1);
    }

    char *arr[100];
    for (int i = 2; i < argc; i++)
    {
        arr[i-2]=argv[i];
    }
    
    exec(arr[0],arr);    
    exit(0);
    
}
```


<h2>sigalarm and sigreturn</h2>

We created two system calls `sigalarm` and `sigreturn` that will help to limit the CPU time of a process. 
* First , we gave the numbers 25 and 26 to `sigalarm` and `sigreturn`. 
* We defined two handlers for the `sigalarm` and `sigreturn` routines respectively: 
```
extern uint64 sys_sigalarm(void);
extern uint64 sys_sigreturn(void);
```
This was added in `syscall.c`
* We now defined the interface for the system calls in `user.h` as follows : 
```
int sigalarm(int ticks, void (*handler)());
int sigreturn(void);
```
* We added the system call entries to `usys.pl` as :
```
entry("sigalarm");
entry("sigreturn");
```
* We added some new variables to the `struct proc` as follows : 
```
int is_sigalarm;
int ticks;
int now_ticks;
uint64 handler;
struct trapframe *trapframe_copy;
```
The first variable keeps track of whether or not the alarm has reached. If it has reached , sigreturn will be called. 

The second variable stores the ticks i.e. the time given by the user in the sigalarm system call.

The third variable stores the current ticks that have elapsed since the system call sigalarm was called. When this becomes equal to or exceeds the ticks , we invoke the sigreturn. 

The fourth variable stores the `handler` function details provided in the  sigalarm system call. 

The fifth variable stores the copy of trapframe. This will be useful.

* Initialize the values in the `allocproc()` function as follows : 
```
// Allocates the trapframe_copy
if((p->trapframe_copy = (struct trapframe *)kalloc()) == 0){
    release(&p->lock);
    return 0;
  }

  p->is_sigalarm=0;
  p->ticks=0;
  p->now_ticks=0;
  p->handler=0;
```

* In `freeproc()` , free the `trapframe_copy` if it is allocated.

* Add a function `uint64 sys_sigalarm(void)` as follows : 
```
uint64
sys_sigalarm(void)
{
  int ticks;

  uint64 handler;

  if(argint(0,&ticks) < 0)
  {
    return -1;
  }

  if(argaddr(1,&handler) < 0)
  {
    return -1;
  }

  struct proc* p = myproc();
  
  p->is_sigalarm = 0;
  p->ticks = ticks;
  p->now_ticks = 0;
  p->handler = handler;

  return 0;
}
```
* If the timer expires , we need to redirect back from the handler to the Operating System i.e. generate a trap.
So , we edit the `usertrap()` and `kerneltrap()` by adding following conditions as well when `which_dev == 2` 
as follows : 
```
p->now_ticks+=1;
    if(p->ticks>0&&p->now_ticks>=p->ticks&&!p->is_sigalarm){
      p->now_ticks = 0;
      p->is_sigalarm=1;
      *(p->trapframe_copy)=*(p->trapframe);
      p->trapframe->epc=p->handler;
    }
```

* Design the return routine i.e `uint64 sys_sigreturn(void)` as follows in `sysproc.c` as follows : 
```
uint64
sys_sigreturn(void)
{
  struct proc*p = myproc();

  // Copy kernel
  p->trapframe_copy->kernel_hartid = p->trapframe->kernel_hartid;
  p->trapframe_copy->kernel_satp = p->trapframe->kernel_satp;
  p->trapframe_copy->kernel_sp = p->trapframe->kernel_sp;
  p->trapframe_copy->kernel_trap= p->trapframe->kernel_trap;

  *(p->trapframe) = *(p->trapframe_copy);

  p->is_sigalarm = 0;

  usertrapret();
  return 0;
}
```

<h2>Scheduling Algorithms:</h2>

<h3>Performance Comparisons</h3>

|         Scheduler         | Running Time | Waiting Time   |
| :-----------------------: | :---------:  | :-----------:  |
|        Round Robin        |      28   |      252    |
|  First Come First Serve   |     29    |    127     |
| Priority Based Scheduler  |      28  |       127    |

* The times are obtained in the above table by running each of these scheduling algorithms on a single CPU. 

<h3>First Come , First Serve</h3>

1. We added `ctime` to `struct proc` in `proc.h`. It is added to keep the track of creation of the process. 

2. Initialized the creation time to the `ticks` at that instant in `allocproc()` in `proc.c`. 

3. In `scheduler()` in `proc.c` , we have added the following code : 
```
#elif defined(FCFS)

  struct proc *p_least_time ;
  printf("scheduler: FCFS\n"); // DEBUG
  // struct proc *p_least_time ;
  for (;;)
  {
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();

    // minimum time
    int found = 0;
    int min_ticks = -1;

    for (p = proc; p < &proc[NPROC]; p++)
    {
      acquire(&p->lock);
      // find the process with the least time
      if (p->state == RUNNABLE)
      {
        if (!found)
        {
          min_ticks = p->ctime;
          p_least_time = p;
          found = 1;
          continue;
        }
        if (p->ctime < min_ticks)
        {
          release(&p_least_time->lock);
          min_ticks = p->ctime;
          p_least_time = p;
          continue;
        }
      }

      release(&p->lock);

    }

    if(found >= 1)
    {
      p_least_time->state = RUNNING;
      c->proc = p_least_time;
      swtch(&c->context,&p_least_time->context);

      c->proc = 0;
      release(&p_least_time->lock);
    }
    
  }
```
* We choose the process which is runnable and has the least creation time. This process is then scheduled to the CPU. 


<h3>Priority Based Scheduling</h3>

1. We have implemented a non-preemptive Priority Based Scheduler. The Scheduler will select the <strong>highest priority</strong> process from the process(es) that is/are available in the waiting queue.

2. To achieve this , we have to add some new variables to the  `struct proc` for the process as follows : 
* **ltime :** This variable is an `uint` and stores the lifetime of the process. 
* **stime :** This variable is an `uint` and stores the time for which the process was sleeping.
* **ntime :** This variable is an `uint` and stores the time since it had its last sleep. 
* **rtime :** This variable is an `uint` and stores the time for which the process was running.
* **etime :** This variable is an `uint` and stores the time at which the process has exited after completion.
* **nice :** This variable is an `uint` and stores the niceness value. It is , by default , 5.
* **stp :** This variable is an `uint` and stores the static priority of the process. By default , its value is 60.
* **nrun :** This variable is an `uint` and stores the number of times the process has been run so far or picked by the scheduler. 

The following changes were done after adding these variables to the `struct proc` : 

1. Whenever a process is allocated (`allocproc()`), the variable `stp` is set to 60 , `nice` is set to 5 and `nrun` is set to 0. All `time` variables (except `ctime`) are initialised to 0.
2. Whenever process gets scheduled by the `scheduler()` in `proc.c` , we increment `nrun` , set the `rtime` to 0 and the `ntime` to 0 as well.
3. To remove pre-emptiveness (default of xv6 is `Round Robin` , which is pre-emptive) , we need to modify the `usertrap()` and `kerneltrap()` in `trap.c` by calling `yield()` only when Round Robin(RR) is defined. So , we enclosed it within #ifdef and #endif.

3. To update the time of the process after every clock interrupt (handled by `clockintr()` function), we have created a function named `update_time()` which will update the variables `ltime` , `rtime` , `stime` and `ntime`. This will be called once in the `clockintr()`.

4. We have created a system call `int set_priority(int new_priority, int pid)` that will update the static priority of the process with `pid` to be `new_priority`. It should `yield()` since the new priority can be lower than the priority of the others. 

4. Now we modified the `scheduler()` function in `proc.c` by adding the following code : 

```
#elif defined(PBS)
  //printf("scheduler: PBS\n"); // DEBUG
  struct proc *p_preffered = proc;
  for (;;)
  {
    // Avoid deadlock by ensuring that devices can interrupt.
    intr_on();

    // minimum time
    int found = 0;
    int min_dyp = -1;

    for (p = proc; p < &proc[NPROC]; p++)
    {
      // find the process with the least time
      if (p->state == RUNNABLE)
      {
        if (!found)
        {
          min_dyp = max(0, min(p->stp - p->nice + 5, 100));
          p_preffered = p;
          found = 1;
        }
        if (p->ctime < min_dyp)
        {
          min_dyp = max(0, min(p->stp - p->nice + 5, 100));
          p_preffered = p;
        }
      }

      acquire(&p_preffered->lock);
      if (p_preffered->state == RUNNABLE)
      {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p_preffered->state = RUNNING;
        p_preffered->nrun++;
        c->proc = p_preffered;
        swtch(&c->context, &p_preffered->context);

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;
      }
      release(&p_preffered->lock);
      p_preffered->nice = (10 * p_preffered->ntime) / (p_preffered->ntime + p_preffered->rtime);
    }
  }
```

<h2>Copy-on Write Fork</h2>

We have modified the `fork()` in xv6 so that it does not entirely copy the address of the parent but rather, uses the Copy On Write Method.

The following changes were made to the xv6 code :


1. We modified `uvmcopy()` so that the Parent's physical pages are mapped into the child. Thus , new pages are not allocated for the child process. 
2. By doing so , the parent and child share readable pages but when needed to write , we allocate new pages.

The code for this is as follows : 
```
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa = 0, i;
  uint flags;
  // char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      panic("uvmcopy: pte should exist");
    if((*pte & PTE_V) == 0)
      panic("uvmcopy: page not present");
    
    flags = PTE_FLAGS(*pte);
    pa = PTE2PA(*pte);

    if((flags & PTE_W) != 0){
      flags = (flags &(~PTE_W)) | PTE_C;
      *pte = PA2PTE(pa) | flags;
    }
    if(mappages(new,i,PGSIZE,pa,flags))
    {
      goto err;
    }
    inc_page_ref((void *)pa);
  }
  
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}
```
3. We modify `usertrap()` to deal with page faults.

4. When a page fault occurs , we allocate a new page with `kalloc()` and copy the old page to the new page. We add the new page to  `PTE_W set`.

4. If no process owns the previous page , then we need to free it using `kfree()` if it is a COW page. 

```
int pagefaulthandler(void*va,pagetable_t pagetable)
{
  struct proc* p = myproc();

  if((uint64)va>=MAXVA)
  {
    return -2;
  }

  if((uint64)va>=PGROUNDDOWN(p->trapframe->sp)-PGSIZE&&(uint64)va<=PGROUNDDOWN(p->trapframe->sp))
  {
    return -2;
  }

  uint64 pa;

  va = (void*)PGROUNDDOWN((uint64)va);
  pte_t *pte = walk(pagetable,(uint64)va,0);
  if(!pte)
  {
    return -1;
  }
  
  if(PTE2PA(*pte) == 0)
  {
    return -1;
  }
  pa = PTE2PA(*pte);
  uint flags = PTE_FLAGS(*pte);

  if((flags & PTE_C) == 0)
  {
    return 0;
  }
  flags = (flags|PTE_W)&(~PTE_C);
  char*mem;
  mem = kalloc();
  if(mem==0)
  {
    return -1;
  }
  memmove(mem,(void*)pa,PGSIZE); 
  *pte = PA2PTE(mem)|flags;
  kfree((void*)pa);
  return 0;
}
```
6. The physical page is freed when the last PTE reference to it is no longer available. We keep a reference count of the number of page tables that refer to the page.
   * The reference count is set to 1 when `kalloc()`  allocates it.
   * Reference count is increased when `fork()` causes  child to share the page. 
   * Reference count is decreased when any process drops a page from the page table.  
   * `kfree()` frees the page when its reference count is zero. 
   * To keep the track of reference counts , we have created an array of size `HighestAddress/4096`.

```
struct {
  struct spinlock lock;
  int count[PGROUNDUP(PHYSTOP)>>12];
} page_ref;
```
```
void
kinit()
{
  // Initialize page reference 
  initlock(&page_ref.lock, "page_ref");
  acquire(&page_ref.lock);
  for(int i=0;i<(PGROUNDUP(PHYSTOP)>>12);++i)
  {
    page_ref.count[i]=0;
  }

  release(&page_ref.lock);

  initlock(&kmem.lock, "kmem");
  freerange(end, (void*)PHYSTOP);
}
```
```
void inc_page_ref(void*pa){
  acquire(&page_ref.lock);
  if(page_ref.count[(uint64)pa>>12]<0){
    panic("inc_page_ref");
  }
  page_ref.count[(uint64)pa>>12]+=1;
  release(&page_ref.lock);
}
```
```
void *
kalloc(void)
{
  struct run *r;

  acquire(&kmem.lock);
  r = kmem.freelist;
  if(r)
    kmem.freelist = r->next;
  release(&kmem.lock);

  if(r){
    memset((char*)r, 5, PGSIZE); // fill with junk
    acquire(&page_ref.lock);
  if(page_ref.count[(uint64)r>>12]<0)
  {
    panic("page ref cannot be increased");
  }
  page_ref.count[(uint64)r>>12]++;
  release(&page_ref.lock);
  }
  return (void*)r;
}
```
```
void
kfree(void *pa)
{
  struct run *r;

  if(((uint64)pa % PGSIZE) != 0 || (char*)pa < end || (uint64)pa >= PHYSTOP)
    panic("kfree");

  acquire(&page_ref.lock);
  if(page_ref.count[(uint64)pa>>12]<=0){
    panic("page ref could not be decreased");
  }
  page_ref.count[(uint64)pa>>12]--;
  if(page_ref.count[(uint64)pa>>12]>0){
    release(&page_ref.lock);
    return;
  }
  release(&page_ref.lock);
  // Fill with junk to catch dangling refs.
  memset(pa, 1, PGSIZE);

  r = (struct run*)pa;

  acquire(&kmem.lock);
  r->next = kmem.freelist;
  kmem.freelist = r;
  release(&kmem.lock);
}
```
7. We modified the `copyout()` function to detect page faults when it encounters a COW page.

```
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0,flags;

  pte_t *pte;

  for(;len > 0;)
  {
    va0 = PGROUNDDOWN(dstva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0)
      return -1;

    pte = walk(pagetable,va0,0);

    flags = PTE_FLAGS(*pte);

    if(flags & PTE_C)
    {
      pagefaulthandler((void*)va0,pagetable);
      pa0 = walkaddr(pagetable,va0);
    }

    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}
```
