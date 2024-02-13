#pragma once

// GADGET_TRACER is used to define a tracer. Currently only one tracer per eBPF object is allowed.
// name is the tracer's name
// map_name is the name of the perf event array or ring buffer maps used to send events to user
// space
// event_type is the name of the structure that describes the event
#define GADGET_TRACER(name, map_name, event_type) \
	const void *gadget_tracer_##name##___##map_name##___##event_type __attribute__((unused)); \
	const struct event_type *__gadget_tracer_type_##name __attribute__((unused));
