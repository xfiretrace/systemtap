/* -*- linux-c -*-
 * Common functions for using inode-based uprobes
 * Copyright (C) 2011-2020 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _UPROBES_INODE_C_
#define _UPROBES_INODE_C_

#include <linux/fs.h>
#include <linux/list.h>
#include <linux/namei.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/uprobes.h>

/* STAPIU: SystemTap Inode Uprobes */


// PR13489, inodes-uprobes export kludge
#if !defined(CONFIG_UPROBES)
#error "not to be built without CONFIG_UPROBES"
#endif

#if !defined(STAPCONF_UPROBE_REGISTER_EXPORTED)
// First get the right typeof(name) that's found in uprobes.h
#if defined(STAPCONF_OLD_INODE_UPROBES)
typedef typeof(&register_uprobe) uprobe_register_fn;
#else
typedef typeof(&uprobe_register) uprobe_register_fn;
#endif
// Then define the typecasted call via function pointer
#define uprobe_register (* (uprobe_register_fn)kallsyms_uprobe_register)
#elif defined(STAPCONF_OLD_INODE_UPROBES)
// In this case, just need to map the new name to the old
#define uprobe_register register_uprobe
#endif

#if !defined(STAPCONF_UPROBE_UNREGISTER_EXPORTED)
// First get the right typeof(name) that's found in uprobes.h
#if defined(STAPCONF_OLD_INODE_UPROBES)
typedef typeof(&unregister_uprobe) uprobe_unregister_fn;
#else
typedef typeof(&uprobe_unregister) uprobe_unregister_fn;
#endif
// Then define the typecasted call via function pointer
#define uprobe_unregister (* (uprobe_unregister_fn)kallsyms_uprobe_unregister)
#elif defined(STAPCONF_OLD_INODE_UPROBES)
// In this case, just need to map the new name to the old
#define uprobe_unregister unregister_uprobe
#endif


// uprobes started setting REG_IP itself starting in kernel commit 74e59dfc.
// There's no direct indicator of this, but commit da1816b1 in the same patch
// series defines UPROBE_HANDLER_MASK, so that's a decent trigger for us.
#ifndef UPROBE_HANDLER_MASK
#define STAPIU_NEEDS_REG_IP 1
#if !defined(STAPCONF_UPROBE_GET_SWBP_ADDR_EXPORTED)
// First typedef from the original decl, then #define it as a typecasted call.
typedef typeof(&uprobe_get_swbp_addr) uprobe_get_swbp_addr_fn;
#define uprobe_get_swbp_addr (* (uprobe_get_swbp_addr_fn)kallsyms_uprobe_get_swbp_addr)
#endif
#endif


/* A uprobe attached to a particular inode on behalf of a particular
   consumer.  NB: such a uprobe instance affects all processes that
   map that inode, so it is not tagged or associated with a
   process.  This object is owned by a stapiu_consumer. */
struct stapiu_instance {
  struct list_head instance_list;   // to find other instances e.g. during shutdown

  struct uprobe_consumer kconsumer; // the kernel-side struct for uprobe callbacks etc.
  struct inode *inode;              // refcounted
  unsigned registered_p:1;          // whether the this kconsumer is registered (= armed, live)

  struct stapiu_consumer *sconsumer; // whose instance are we
};


/* A snippet to record the per-process vm where a particular
   executable/solib was mapped.  Used for sdt semaphore setting, and
   for identifying processes of our interest (vs. disinterest) for
   uprobe hits.  This object is owned by a stapiu_consumer.  We use
   the same inode* as the stapiu_instance, and have the same lifespan,
   so don't bother separately refcount it. 
*/
struct stapiu_process {
  struct list_head process_list;    // to find other processes

  struct inode *inode;              // the inode* for solib or executable
  unsigned long relocation;         // the mmap'ed .text address
  unsigned long base;               // the address to apply sdt offsets against
  pid_t tgid;                       // pid
};


/* A consumer is a declaration of a family of uprobes we want to
   place, on one or more IDENTICAL files specified by name or buildid.
   When a matching binaries are found, new stapiu_instances are
   created for it.  Note that uprobes are file-based, not
   process-based.  The files are identical enough that we store only
   one uprobe address, sdt-semaphore offset etc., for the whole lot.

   But we also need some per-process data saved: for sys/sdt.h
   semaphores, on older kernels that don't have semaphore management
   capabilities natively, we need to track all the processes where a
   given binary is mapped, and their base addresses.  That way we can
   incrementally compute the semaphore address across the several
   mmap(2) operations involved in shlib loading.  We also track
   processes because that's how we tell apart a uprobe hit from an
   interesting process subtree (like due to stap -c ...)  from a hit
   on some other process (which we want to ignore) --- but only in
   _stp_target-set mode.
*/
struct stapiu_consumer {
  // NB: task_finder looks for PROCESSES only
  // info to identify the matching exec: pathname/buildid/pid
  struct stap_task_finder_target finder;
  // ... so if we want to probe SHARED LIBRARIES, we need the
  // task_finder to track many processes (not filter on procname /
  // build_id), for which we receive mmap callbacks, then we filter
  // the mmap callbacks against the following fields.
  const char *solib_pathname;
  unsigned long solib_build_id_vaddr;
  const char *solib_build_id;
  int solib_build_id_len;

  // The key by which we can match the _stp_module[] element
  const char *module_name;
  
  struct mutex consumer_lock;
  // a lock to protect lists etc. from iteration/modification; NB: not
  // held during uprobe hits; NB: must be a "sleeping lock" not a
  // "spinning lock"

  // what kind of uprobe and where to put it  
  const unsigned return_p:1;
  loff_t offset; /* the probe offset within the inode */
  loff_t sdt_sem_offset; /* the semaphore offset from process->base */
  // those result in this:
  struct list_head instance_list_head; // the resulting uprobe instances for this consumer

  struct list_head process_list_head; // the processes for this consumer
  spinlock_t process_list_lock; // protect list; used briefly from even atomic contexts
        
  // List of perf counters used by each probe
  // This list is an index into struct stap_perf_probe,
  long perf_counters_dim;
  long *perf_counters;
  void (*perf_read_handler)(long *values);
  
  const struct stap_probe * const probe; // the script-level probe handler metadata: pp(), probe handler function
};




/* The stap-generated probe handler for all inode-uprobes. */
static int
stapiu_probe_handler (struct stapiu_consumer *c, struct pt_regs *regs);

static int
stapiu_probe_prehandler (struct uprobe_consumer *inst, struct pt_regs *regs)
{
  int ret;
  struct stapiu_instance *instance = 
    container_of(inst, struct stapiu_instance, kconsumer);
  struct stapiu_consumer *c = instance->sconsumer;
  
  if (_stp_target) // need we filter by pid at all?
    {
      struct stapiu_process *p, *process = NULL;
      unsigned long flags;

      // First find the related process, set by stapiu_change_plus.
      // NB: This is a linear search performed for every probe hit!
      // This could be an algorithmic problem if the list gets large,
      // but we'll wait until this is demonstratedly a hotspot before
      // optimizing.  NB: on rhel7 sometimes we're invoked from atomic
      // context, so must be careful to use the spinlock, not the
      // mutex.
      spin_lock_irqsave(&c->process_list_lock, flags);
      list_for_each_entry(p, &c->process_list_head, process_list) {
	if (p->tgid == current->tgid) {
	  process = p;
	  break;
	}
      }
      spin_unlock_irqrestore(&c->process_list_lock, flags);
      if (!process) {
        /* We know that we're in -c/-x mode, but this process is not
           in the process hierarchy, so the uprobe should be ignored
           and future hits prevented.  PR15278
        */
#ifdef UPROBE_HANDLER_REMOVE
	/* Once we're past the starting phase, we can be sure that any
	 * processes which are executing code in a mapping have already
	 * been through task_finder.  So if it's not in our list of
	 * target->processes, it can safely get removed.  */
	if (stap_task_finder_complete())
	  return UPROBE_HANDLER_REMOVE;
#endif
	return 0;
      }
    }

#ifdef STAPIU_NEEDS_REG_IP
  /* Make it look like the IP is set as it would in the actual user task
   * before calling the real probe handler.  */
  {
    unsigned long saved_ip = REG_IP(regs);
    SET_REG_IP(regs, uprobe_get_swbp_addr(regs));
#endif

    ret = stapiu_probe_handler(c, regs);

#ifdef STAPIU_NEEDS_REG_IP
    /* Reset IP regs on return, so we don't confuse uprobes.  */
    SET_REG_IP(regs, saved_ip);
  }
#endif
  
  return ret;
}

static int
stapiu_retprobe_prehandler (struct uprobe_consumer *inst,
			    unsigned long func __attribute__((unused)),
			    struct pt_regs *regs)
{
  return stapiu_probe_prehandler(inst, regs);
}



static int
stapiu_register (struct stapiu_instance* inst, struct stapiu_consumer* c)
{
  int ret = 0;

  dbug_uprobes("registering (u%sprobe) at inode-offset "
	       "%lu:%p pidx %zu target filename:%s buildid:%s\n",
	       c->return_p ? "ret" : "",
	       (unsigned long) inst->inode->i_ino,
	       (void*) (uintptr_t) c->offset,
	       c->probe->index,
	       ((char*)c->finder.procname ?: ((char*)c->solib_pathname ?: "")),
               ((char*)c->finder.build_id ?: ((char*)c->solib_build_id ?: "")));

  if (!c->return_p) {
    inst->kconsumer.handler = stapiu_probe_prehandler;
  } else {
#if defined(STAPCONF_INODE_URETPROBES)
    inst->kconsumer.ret_handler = stapiu_retprobe_prehandler;
#else
    ret = EINVAL;
#endif
  }
  if (ret == 0)
    ret = uprobe_register (inst->inode, c->offset, &inst->kconsumer);

  if (ret)
    _stp_warn("probe %s at inode-offset %lu:%p "
	      "registration error [man warning::pass5] (rc %d)",
	      c->probe->pp,
	      (unsigned long) inst->inode->i_ino,
	      (void*) (uintptr_t) c->offset,
	      ret);

  inst->registered_p = (ret ? 0 : 1);
  return ret;
}


static void
stapiu_unregister (struct stapiu_instance* inst, struct stapiu_consumer* c)
{
  dbug_uprobes("unregistering (u%sprobe) at inode-offset "
	       "%lu:%p pidx %zu\n",
      c->return_p ? "ret" : "",
      (unsigned long) inst->inode->i_ino,
      (void*) (uintptr_t) c->offset,
      c->probe->index);

  (void) uprobe_unregister (inst->inode, c->offset, &inst->kconsumer);
  inst->registered_p = 0;
}



/* Read-modify-write a semaphore in an arbitrary task, usually +/- 1.  */
static int
stapiu_write_task_semaphore(struct task_struct* task,
			    unsigned long addr, short delta)
{
    int count, rc = 0;
    unsigned short sdt_semaphore = 0; /* NB: fixed size */
    /* XXX: need to analyze possibility of race condition */
    count = __access_process_vm_noflush(task, addr,
      &sdt_semaphore, sizeof(sdt_semaphore), 0);
    if (count != sizeof(sdt_semaphore))
      rc = 1;
    else {
      sdt_semaphore += delta;
      count = __access_process_vm_noflush(task, addr,
					  &sdt_semaphore, sizeof(sdt_semaphore), 1);
      rc = (count == sizeof(sdt_semaphore)) ? 0 : 1;
    }
    return rc;
}


static void
stapiu_decrement_process_semaphores(struct stapiu_process *p,
				    struct stapiu_consumer *c)
{
    struct task_struct *task;
    rcu_read_lock();
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
    /* We'd like to call find_task_by_pid_ns() here, but it isn't
     * exported.  So, we call what it calls...  */
    task = pid_task(find_pid_ns(p->tgid, &init_pid_ns), PIDTYPE_PID);
#else
    task = find_task_by_pid(p->tgid);
#endif

    /* The task may have exited while we weren't watching.  */
    if (task) {
      /* Holding the rcu read lock makes us atomic, and we
       * can't write userspace memory while atomic (which
       * could pagefault).  So, instead we lock the task
       * structure, then release the rcu read lock. */
      get_task_struct(task);
      rcu_read_unlock();
      
      if (c->sdt_sem_offset) {
	unsigned long addr = p->base + c->sdt_sem_offset;
	stapiu_write_task_semaphore(task, addr, -1);
      }
      put_task_struct(task);
    } else {
      rcu_read_unlock();
    }
}


/* As part of shutdown, we need to decrement the semaphores in every task we've
 * been attached to.  */
static void
stapiu_decrement_semaphores(struct stapiu_consumer *consumers, size_t nconsumers)
{
  size_t i;
  /* NB: no process_list_lock use needed as the task_finder engine is
   * already stopped by now, so no one else will mess with us.  We need
   * to be sleepable for access_process_vm.  */
  for (i = 0; i < nconsumers; ++i) {
    struct stapiu_consumer *c = &consumers[i];
    struct stapiu_process *p;
    int has_semaphores = 0;
    
    if (! c->sdt_sem_offset)
      continue;
    
    list_for_each_entry(p, &c->process_list_head, process_list)
      stapiu_decrement_process_semaphores(p, c);
  }
}


/* Unregister all uprobe consumers of each target inode.  */
static void
stapiu_consumer_unreg(struct stapiu_consumer *c)
{
  struct stapiu_instance *inst, *in2;
  struct stapiu_process *p, *tmp;  

  // no need for locking protection; by the time this cleanup
  // is triggered, no further list modifying ops can also go
  list_for_each_entry_safe(inst, in2, &c->instance_list_head, instance_list) {
    if (inst->registered_p)
      stapiu_unregister(inst, c);
    if (inst->inode)
      iput(inst->inode);
    list_del(&inst->instance_list);
    _stp_kfree(inst);
  }

  // NB: it's hypothetically possible for the same process to show up
  // multiple times in the list.  Don't break after the first.
  list_for_each_entry_safe(p, tmp, &c->process_list_head, process_list) {
    list_del(&p->process_list);
    // no refcount used for the inode field
    _stp_kfree (p);
  }
}


/* Register/unregister a target's uprobe consumers if their associated probe
 * handlers have their conditions enabled/disabled. */
static void
stapiu_consumer_refresh(struct stapiu_consumer *c)
{
  struct stapiu_instance *inst;
  
  mutex_lock(& c->consumer_lock);

  list_for_each_entry(inst, &c->instance_list_head, instance_list) {
    if (inst->registered_p && !c->probe->cond_enabled)
      stapiu_unregister(inst, c);
    else if (!inst->registered_p && c->probe->cond_enabled)
      stapiu_register(inst, c);
  }

  mutex_unlock(& c->consumer_lock);
}


/* Cleanup every target.  */
static void
stapiu_exit(struct stapiu_consumer *consumers, size_t nconsumers)
{
  size_t i;
  stapiu_decrement_semaphores(consumers, nconsumers);
  for (i = 0; i < nconsumers; ++i) {
    struct stapiu_consumer *c = &consumers[i];
    // protect against conceivable stapiu_refresh() at same time
    mutex_lock(& c->consumer_lock);
    stapiu_consumer_unreg(c);
    mutex_unlock(& c->consumer_lock);
    /* NB: task_finder needs no unregister. */
  }
}


/* Initialize every consumer.  */
static int
stapiu_init(struct stapiu_consumer *consumers, size_t nconsumers)
{
  int ret = 0;
  size_t i;
  for (i = 0; i < nconsumers; ++i) {
    struct stapiu_consumer *c = &consumers[i];
    INIT_LIST_HEAD(&c->instance_list_head);
    INIT_LIST_HEAD(&c->process_list_head);
    mutex_init(&c->consumer_lock);
    spin_lock_init(&c->process_list_lock);
    
    dbug_uprobes("registering task-finder for procname:%s buildid:%s\n",
                 ((char*)c->finder.procname ?: ""),
                 ((char*)c->finder.build_id ?: ""));

    ret = stap_register_task_finder_target(&c->finder);
    if (ret != 0) {
      _stp_error("Couldn't register task finder target for file '%s': %d\n",
		 c->finder.procname, ret);
      break;
    }
  }
  return ret;
}


/* Refresh the entire inode-uprobes subsystem.  */
static void
stapiu_refresh(struct stapiu_consumer *consumers, size_t nconsumers)
{
  size_t i;
  
  for (i = 0; i < nconsumers; ++i) {
    struct stapiu_consumer *c = &consumers[i];
    stapiu_consumer_refresh(c);
  }
}


/* Task-finder found a process with a target that we're interested in.
   Time to create a stapiu_instance for this inode/consumer combination. */
static int
stapiu_change_plus(struct stapiu_consumer* c, struct task_struct *task,
		   unsigned long relocation, unsigned long length,
		   unsigned long offset, unsigned long vm_flags,
		   struct inode *inode)
{
  int rc = 0;
  struct stapiu_instance *i;
  struct stapiu_instance *inst = NULL;
  struct stapiu_process *p;
  int j;
  unsigned long flags;

  if (! inode) {
      rc = -EINVAL;
      goto out;
    }

  /* Do the buildid check.  NB: on F29+, offset may not equal
     0 for LOADable "R E" segments, because the read-only .note.*
     stuff may have been loaded earlier, separately.  PR23890. */
  // NB: this is not really necessary for buildid-based probes,
  // which had this verified already.
  rc = _stp_usermodule_check(task, c->module_name,
			     relocation - offset);
  if (rc)
    goto out;

  dbug_uprobes("notified for inode-offset arrival u%sprobe "
	       "%lu:%p pidx %zu target procname:%s buildid:%s\n",
	       c->return_p ? "ret" : "",
	       (unsigned long) inode->i_ino,
	       (void*) (uintptr_t) c->offset,
	       c->probe->index,
	       ((char*)c->finder.procname ?: ((char*)c->solib_pathname ?: "")),
               ((char*)c->finder.build_id ?: ((char*)c->solib_build_id ?: "")));

  /* Check the buildid of the target (if we haven't already). We
   * lock the target so we don't have concurrency issues. */
  mutex_lock(&c->consumer_lock);

  // Check if we already have an instance for this inode.  This is normal:
  // if a different process maps the same solib, or forks into the same
  // executable.  In this case, we must not re-register the same uprobe.
  list_for_each_entry(i, &c->instance_list_head, instance_list) {
    if (i->inode == inode) {
      inst = i;
      break;
    }
  }

  if (!inst) { // new instance; need new uprobe etc.
    inst = _stp_kzalloc(sizeof(struct stapiu_instance));
    if (! inst) {
      rc = -ENOMEM;
      goto out1;
    }

    inst->sconsumer = c; // back link essential; that's how we go from uprobe *handler callback
          
    /* Grab the inode first (to prevent TOCTTOU problems). */
    inst->inode = igrab(inode);
    if (!inst->inode) {
      rc = -EINVAL;
      goto out2;
    }
  
    // Add the inode/instance to the list
    list_add(&inst->instance_list, &c->instance_list_head);

    // Register the actual uprobe if cond_enabled already
    if (c->probe->cond_enabled)
      (void) stapiu_register(inst, c);
  }

  // ... but we may have to do per-process work anyway: perfctr
  // initialization and sdt.h semaphore manipulation!
  
  // Perform perfctr registration if required
  for (j=0; j < c->perf_counters_dim; j++) {
    if ((c->perf_counters)[j] > -1)
      (void) _stp_perf_read_init ((c->perf_counters)[j], task);
  }

  // NB: process_list[] already extended up in stapiu_mmap_found().
  
  rc = 0;
  goto out1;

 out2:
  _stp_kfree(inst);
 out1:
  mutex_unlock(&c->consumer_lock);
 out:
  return rc;
}


/* Task-finder found a writable mapping in our interested target.
 * Increment the semaphore now.  */
static int
stapiu_change_semaphore_plus(struct stapiu_consumer* c, struct task_struct *task,
			     unsigned long relocation, struct inode* inode)
{
  int rc = 0;
  struct stapiu_process *p;
  int any_found;
  unsigned long flags;
  
  if (! c->sdt_sem_offset) // nothing to do
    return 0;

  dbug_uprobes("considering semaphore (u%sprobe) pid %ld inode 0x%lx"
               "pidx %zu\n",
               c->return_p ? "ret" : "",
               (long) task->tgid,
               (unsigned long) inode,
               c->probe->index);
  
  // NB: we mustn't hold a lock while changing the task memory,
  // but we need a lock to protect the process_list from concurrent
  // add/delete.  So hold a spinlock during iteration until the first
  // hit, then unlock & process.  NB: We could in principle have multiple
  // instances of the same process in the list (e.g., if the process
  // somehow maps in the same solib multiple times).  We can't easily
  // both iterate this list (in a spinlock-protected safe way), and
  // relax the spinlock enough to do a safe stapiu_write_task_semaphore()
  // call within the loop.  So we will hit only the first copy in our list.
  any_found = 0;
  spin_lock_irqsave(&c->process_list_lock, flags);
  /* Look through all the consumer's processes and increment semaphores.  */
  list_for_each_entry(p, &c->process_list_head, process_list) {
    unsigned long addr = p->base + c->sdt_sem_offset;
    int rc2;
    if (p->tgid != task->tgid) continue; // skip other processes in the list
    if (p->inode != inode) continue; // skip other inodes

    // unlock list and process write for this entry
    spin_unlock_irqrestore(&c->process_list_lock, flags);
    any_found=1;

    dbug_uprobes("incrementing semaphore (u%sprobe) pid %ld "
                 "pidx %zu address 0x%lx\n",
                 c->return_p ? "ret" : "",
                 (long) task->tgid,
                 c->probe->index,
                 (unsigned long) addr);

    rc2 = stapiu_write_task_semaphore(task, addr, +1);
    if (!rc)
            rc = rc2;
    break; // exit list_for_each loop
  }
  if (! any_found)
    spin_unlock_irqrestore(&c->process_list_lock, flags);
  else
    ; // already unlocked

  return rc;
}


/* Task-finder found a mapping that's now going away.  We don't need to worry
 * about the semaphores, so we can just release the process slot.  */
static int
stapiu_change_minus(struct stapiu_consumer* c, struct task_struct *task,
		    unsigned long addr, unsigned long length)
{
  // We don't need do anything really.
  // A process going away means:
  // - its uprobes will no longer fire: no problem, the uprobe inode
  //   is shared and persistent
  // - its sdt semaphores (if any) will be nonzero: no problem, the
  //   process is dying anyway
  // - the stapiu_consumer's process_list linked list will have a record
  //   of the dead process: well, not great, it'll be cleaned up eventually,
  //   and cleaning it up NOW is tricky - we could use the process_list_lock
  //   to protect the list (as done in stapiu_change_semaphore_plus),
  //   but not our sleepy mutex:
  //
  // [ 1955.410237]  ? stapiu_change_minus+0x38/0xf0 [stap_54a723c01c50d972590a5c901516849_15522]
  // [ 1955.411583]  __mutex_lock+0x35/0x820
  // [ 1955.416858]  ? _raw_spin_unlock+0x1f/0x30
  // [ 1955.419649]  ? utrace_control+0xbe/0x2d0 [stap_54a723c01c50d972590a5c901516849_15522]
  // [ 1955.421702]  stapiu_change_minus+0x38/0xf0 [stap_54a723c01c50d972590a5c901516849_15522]
  // [ 1955.425147]  ? __stp_utrace_task_finder_target_exec+0x74/0xc0 [stap_54a723c01c50d972590a5c901516849_15522]
  // [ 1955.429773]  ? utrace_report_exec+0xdb/0x140 [stap_54a723c01c50d972590a5c901516849_15522]
  // [ 1955.431398]  ? __do_execve_file+0xa05/0xb30
  // [ 1955.432923]  ? do_execve+0x27/0x30
  // [ 1955.436334]  ? __x64_sys_execve+0x27/0x30
  // [ 1955.437700]  ? do_syscall_64+0x5c/0xa0

  // But as an optimization - to avoid having them build up indefinitely,
  // and make semaphore operations go slowly, we will nuke matching entries anyway.
  unsigned long flags;
  struct stapiu_process *p, *tmp;
  unsigned nmatch=0;
  
  spin_lock_irqsave(&c->process_list_lock, flags);
  list_for_each_entry_safe(p, tmp, &c->process_list_head, process_list) {
    // we nuke by matching semaphore address (where ..._semaphore_plus wrote)
    // against the address range being unmapped
    unsigned long semaddr = p->base + c->sdt_sem_offset;
    if (p->tgid != task->tgid) // skip other processes in the list
      continue;
    if (semaddr >= addr && semaddr < addr + length) {
      list_del(&p->process_list);
      _stp_kfree (p);
      nmatch ++;
    }
  }
  spin_unlock_irqrestore(&c->process_list_lock, flags);

  if (nmatch > 0)
    dbug_uprobes("notified for inode-offset departure u%sprobe "
                 "pidx %zu matches:%u procname:%s buildid:%s\n",
                 c->return_p ? "ret" : "",
                 c->probe->index,
                 nmatch,
                 ((char*)c->finder.procname ?: ((char*)c->solib_pathname ?: "")),
                 ((char*)c->finder.build_id ?: ((char*)c->solib_build_id ?: "")));

  return 0;
}


static struct inode *
stapiu_get_task_inode(struct task_struct *task)
{
	struct mm_struct *mm;
	struct file* vm_file;
	struct inode *inode = NULL;

	// Grab the inode associated with the task.
	//
	// Note we're not calling get_task_mm()/mmput() here.  Since
	// we're in the the context of task, the mm should stick
	// around without locking it (and mmput() can sleep).
	mm = task->mm;
	if (! mm) {
		/* If the thread doesn't have a mm_struct, it is
		 * a kernel thread which we need to skip. */
		return NULL;
	}

	vm_file = stap_find_exe_file(mm);
	if (vm_file) {
		if (vm_file->f_path.dentry)
          //inode = vm_file->f_path.dentry->d_inode;
          inode = d_real_inode(vm_file->f_path.dentry);
		fput(vm_file);
	}
	return inode;
}


/* The task_finder_callback we use for ET_EXEC targets. */
static int
stapiu_process_found(struct stap_task_finder_target *tf_target,
		     struct task_struct *task, int register_p, int process_p)
{
  struct stapiu_consumer *c = container_of(tf_target, struct stapiu_consumer, finder);
  
  if (!process_p)
    return 0; /* ignore threads */

  dbug_uprobes("process_found pid=%ld f.p=%s f.b=%s c.p=%s c.b=%s\n",
               (long)task->tgid,
	       ((char*)c->finder.procname ?: ""),
               ((char*)c->finder.build_id ?: ""),
	       ((char*)c->solib_pathname ?: ""),
               ((char*)c->solib_build_id ?: ""));

  /* ET_EXEC events are like shlib events, but with 0 relocation bases */
  if (register_p) {
    int rc = -EINVAL;
    struct inode *inode = stapiu_get_task_inode(task);
    
    if (inode) {
      // Add a stapiu_process record to the consumer, so that
      // the semaphore increment logic will accept this task.
      struct stapiu_process* p;
      unsigned long flags;
      p = _stp_kzalloc(sizeof(struct stapiu_process));
      if (p) {
        p->tgid = task->tgid;
        p->relocation = 0;
        p->inode = inode;
        p->base = 0;
        spin_lock_irqsave (&c->process_list_lock, flags);
        list_add(&p->process_list, &c->process_list_head);
        spin_unlock_irqrestore (&c->process_list_lock, flags);
      } else {
         _stp_warn("out of memory tracking executable in process %ld\n",
                   (long) task->tgid);
      }
            
      rc = stapiu_change_plus(c, task, 0, TASK_SIZE, 0, 0, inode);
      
      stapiu_change_semaphore_plus(c, task, 0, inode);
    }
    return rc;
  } else
    return stapiu_change_minus(c, task, 0, TASK_SIZE);
}


bool
__verify_build_id (struct task_struct *tsk, unsigned long addr,
		   unsigned const char *build_id, int build_id_len);
// defined in task_finder2.c



/* The task_finder_mmap_callback.  These callbacks are NOT
   pre-filtered for buildid or pathname matches (because task_finder
   deals with TASKS only), so we get to do that here.  */
static int
stapiu_mmap_found(struct stap_task_finder_target *tf_target,
		  struct task_struct *task,
		  char *path, struct dentry *dentry,
		  unsigned long addr, unsigned long length,
		  unsigned long offset, unsigned long vm_flags)
{
  struct stapiu_consumer *c =
    container_of(tf_target, struct stapiu_consumer, finder);
  int rc = 0;
  struct stapiu_process* p;
  int known_mapping_p;
  unsigned long flags;
  struct inode *inode;  

  /*
  We need to verify that this file/mmap corresponds to the given stapiu_consumer.
  One could compare (inode) file name, but that won't work with buildid-based
  uprobes.  For those, one cannot just
 
  __verify_build_id(... addr - offset + c->solib_build_id_vaddr ...)
 
  because dlopen()ing a shared library involves multiple mmaps, including
  some at repeating/offset addresses.  See glibc _dl_map_segments() in various
  versions.  So by the fourth call (!) on modern glibc's, we get a VM_WRITE-able
  data segment mapped, but that's at a load/mapping address that is offset by a
  page from the base (file offset=0) mapping.

  e.g. on Fedora 32 / glibc 2.31, with testsuite/libsdt_buildid.so:

  Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000000000 0x0000000000000000 0x0004b8 0x0004b8 R   0x1000
  LOAD           0x001000 0x0000000000001000 0x0000000000001000 0x000161 0x000161 R E 0x1000
  LOAD           0x002000 0x0000000000002000 0x0000000000002000 0x0000cc 0x0000cc R   0x1000
  LOAD           0x002df8 0x0000000000003df8 0x0000000000003df8 0x000232 0x000238 RW  0x1000
  DYNAMIC        0x002e10 0x0000000000003e10 0x0000000000003e10 0x0001d0 0x0001d0 RW  0x8

  strace:
  openat(AT_FDCWD, ".../libsdt_buildid.so", O_RDONLY|O_CLOEXEC) = 3
  mmap(NULL, 16432, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3, 0) = 0x148c764ac000
  mmap(0x148c764ad000, 4096, PROT_READ|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x1000) = 0x148c764ad000
  mmap(0x148c764ae000, 4096, PROT_READ, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x148c764ae000
  mmap(0x148c764af000, 8192, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE, 3, 0x2000) = 0x148c764af000

  Note how the virtual mapping for the fourth mmap (also) maps file-offset 0x2000 at
  vm offset 0x3000.

  So what we do is rely on the name/buildid validation tests being run
  -earlier- in the dlopen/mmap sequence to validate near-future
  mmap()s.  We search the c->process_list[] for a mapping that already
  overlaps the new range, and if so, consider it validated ... whether
  for the solib_pathname or the solib_build_id case.

  This is complicated for startup-time traversal of processes/mmaps,
  where it seems sometimes we get notifications out of temporal sequence.
  */
  
  known_mapping_p = 0;
  spin_lock_irqsave(&c->process_list_lock, flags);
  list_for_each_entry(p, &c->process_list_head, process_list) {
    if (p->tgid != task->tgid) continue;
    if (p->inode != dentry->d_inode) continue;
    known_mapping_p = 1;
    break;
  }
  spin_unlock_irqrestore(&c->process_list_lock, flags);


  // Check if this mapping (solib) is of interest: whether we expect
  // it by buildid or name.
  
  if (! known_mapping_p) {
    /* The file path or build-id must match. The build-id address
     * is calculated using start address of this vma, the file
     * offset of the vma start address and the file offset of
     * the build-id. */
    if (c->solib_pathname && path && strcmp (path, c->solib_pathname))
      return 0;
    if (c->solib_build_id_len > 0 && !__verify_build_id(task,
  						        addr - offset + c->solib_build_id_vaddr,
  						        c->solib_build_id,
						        c->solib_build_id_len))
      return 0;
  }

  // If we made it this far, we have an interesting solib.

  dbug_uprobes("mmap_found pid=%ld path=%s addr=0x%lx length=%lu offset=%lu flags=0x%lx known=%d\n",
               (long) task->tgid, path, addr, length, offset, vm_flags, known_mapping_p);
  
  if (! known_mapping_p) {
    // OK, let's add it.  The first mapping should be a VM_READ mapping
    // of the entire solib file, which will also serve as the apprx.
    // outer bounds of the repeatedly-mapped segments.

#if 0
    // Consider an assumption about the dlopen/mmap sequence
    // If it comes out of sequence, we could get length/base wrong in the stored
    // stapiu_process, which could lead us to miscalculate semaphore addresses.
    //
    // However, this has been observed on task-finder initial-enumeration case,
    // (sdt_misc.exp, where a solib test is already running when stap starts).
    if (offset != 0)
      return 0;
#endif
    
    // Associate this consumer with this process.  If we encounter
    // resource problems here, we don't really have to undo the uprobe
    // registrations etc. already in effect.  It may break correct
    // tracking of process hierarchy in -c/-x operation, but too bad.
    p = _stp_kzalloc(sizeof(struct stapiu_process));
    if (p) {
      p->tgid = task->tgid;
      p->relocation = addr;
      p->inode = dentry->d_inode;
      p->base = addr-offset; // ... in case caught this during the second mmap
      spin_lock_irqsave (&c->process_list_lock, flags);
      list_add(&p->process_list, &c->process_list_head);
      spin_unlock_irqrestore (&c->process_list_lock, flags);
    } else
      _stp_warn("out of memory tracking solib %s in process %ld\n",
                path, (long) task->tgid);
  }
  //use inode_1 in the following function.
  inode = d_real_inode(dentry);
  /* Check non-writable, executable sections for probes. */
  if ((vm_flags & VM_EXEC) && !(vm_flags & VM_WRITE))
    rc = stapiu_change_plus(c, task, addr, length,
			     offset, vm_flags, inode);

  /* Check writeable sections for semaphores.
   * NB: They may have also been executable for the check above,
   *     if we're running a kernel that lacks noexec mappings.
   *     So long as there's no error (rc == 0), we need to look
   *     for semaphores too. 
   */

  if ((rc == 0) && (vm_flags & VM_WRITE))
    rc = stapiu_change_semaphore_plus(c, task, addr, dentry->d_inode);

  return rc;
}


/* The task_finder_munmap_callback */
static int
stapiu_munmap_found(struct stap_task_finder_target *tf_target,
		    struct task_struct *task,
		    unsigned long addr, unsigned long length)
{
  struct stapiu_consumer *c =
    container_of(tf_target, struct stapiu_consumer, finder);

  return stapiu_change_minus(c, task, addr, length);
}


/* The task_finder_callback we use for ET_DYN targets.
 * This just forces an unmap of everything as the process exits. (PR11151)
 */
static int
stapiu_process_munmap(struct stap_task_finder_target *tf_target,
		      struct task_struct *task,
		      int register_p, int process_p)
{
  struct stapiu_consumer *c =
    container_of(tf_target, struct stapiu_consumer, finder);
  
  if (!process_p)
    return 0; /* ignore threads */
  
  /* Covering 0->TASK_SIZE means "unmap everything" */
  if (!register_p)
    return stapiu_change_minus(c, task, 0, TASK_SIZE);
  return 0;
}


#endif /* _UPROBES_INODE_C_ */
