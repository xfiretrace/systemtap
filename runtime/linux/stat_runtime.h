/* -*- linux-c -*-
 * Stat Runtime Functions
 * Copyright (C) 2012 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _LINUX_STAT_RUNTIME_H_
#define _LINUX_STAT_RUNTIME_H_

#define STAT_LOCK(sd)		do {} while (0)
#define STAT_UNLOCK(sd)		do {} while (0)
/* get/put_cpu wrappers.  Unnecessary if caller is already atomic. */
#if defined(CONFIG_PREEMPT_RT_FULL) || defined(CONFIG_PREEMPT_RT)
#define STAT_GET_CPU()		raw_smp_processor_id()
#else
#define STAT_GET_CPU()		smp_processor_id()
#endif
#define STAT_PUT_CPU()		do {} while (0)

#define _stp_stat_get_agg(stat) ((stat)->agg)
#define _stp_stat_per_cpu_ptr(stat, cpu) *per_cpu_ptr((stat)->sd, (cpu))

/** Stat struct. Maps do not need this */
typedef struct _Stat {
	struct _Hist hist;

	/* aggregated data */
	stat_data *agg;

	/* The stat data is per-cpu data.  */
	stat_data **sd;
} *Stat;

static void _stp_stat_free(Stat st);

static Stat _stp_stat_alloc(size_t stat_data_size)
{
	Stat st;
	unsigned int cpu;

	if (stat_data_size < sizeof(stat_data))
		return NULL;

	/* Called from module_init, so user context, may sleep alloc. */
	st = _stp_kmalloc_gfp (sizeof(struct _Stat), STP_ALLOC_SLEEP_FLAGS);
	if (st == NULL)
		return NULL;

	st->agg = _stp_kzalloc_gfp (stat_data_size, STP_ALLOC_SLEEP_FLAGS);
	if (st->agg == NULL) {
		_stp_kfree (st);
		return NULL;
	}

	st->sd = _stp_alloc_percpu (sizeof (stat_data *));
	if (st->sd == NULL) {
		_stp_kfree (st->agg);
		_stp_kfree (st);
		return NULL;
	}

	for_each_online_cpu(cpu) {
		stat_data *sd = _stp_vzalloc_node(stat_data_size,
						  cpu_to_node(cpu));
		if (unlikely(sd == NULL)) {
			_stp_stat_free (st);
			return NULL;
		}
		*per_cpu_ptr(st->sd, cpu) = sd;
	}

	return st;
}

static void _stp_stat_free(Stat st)
{
	if (st) {
		unsigned int cpu;

		for_each_possible_cpu(cpu) {
			stat_data *sd = _stp_stat_per_cpu_ptr(st, cpu);
			if (likely(sd))
				_stp_vfree (sd);
		}
		_stp_free_percpu (st->sd);
		_stp_kfree (st->agg);
		_stp_kfree (st);
	}
}

#endif /* _LINUX_STAT_RUNTIME_H_ */
