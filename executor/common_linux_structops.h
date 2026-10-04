// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// BPF struct_ops carrier -- native loader for syz_bpf_struct_ops_load
// (sys/linux/bpf_struct_ops.txt).
//
// The blob is a load recipe (pkg/structops/recipe.go): the compiled
// object's BTF, one record per callback program (its instructions, the
// struct member it fills, its kfunc call sites by NAME), and the instance
// struct's name.  Everything kernel-image specific is resolved HERE, by
// name against /sys/kernel/btf/vmlinux, because BTF ids differ per kernel
// build: the kfunc ids patched into the call instructions, the struct_ops
// type id each program attaches to, the member index/offset of each
// callback, and the bpf_struct_ops_<name> value type the map carries.
//
// The sequence is what libbpf's struct_ops path does, with raw bpf()
// syscalls and no library (docs/pseudo_syscalls.md):
//
//   BPF_BTF_LOAD            the object's BTF (func_info for each program)
//   BPF_PROG_LOAD   x N     one BPF_PROG_TYPE_STRUCT_OPS program per
//                           callback: attach_btf_id = the struct's vmlinux
//                           id, expected_attach_type = its member index
//   BPF_MAP_CREATE          BPF_MAP_TYPE_STRUCT_OPS, value type
//                           bpf_struct_ops_<name>, BPF_F_LINK
//   BPF_MAP_UPDATE_ELEM     the value: program fds in their callback
//                           slots + the object's scalar instance data
//                           (.flags, .timeout_ms, ...) + a unique .name
//   BPF_LINK_CREATE         the registration (tcp_register_congestion_control,
//                           mptcp_register_scheduler, ...); the link fd is
//                           returned
//
// Registration is ALWAYS through a BPF_F_LINK map + link, whatever section
// the object placed its instance in (.struct_ops or .struct_ops.link; the
// recipe records it, the loader does not act on it).  A plain, link-less
// struct_ops registration takes a reference on its own map
// (bpf_struct_ops_map_update_elem: bpf_map_inc after st_ops->reg) and
// lives until BPF_MAP_DELETE_ELEM, so it would outlive the program and
// accumulate -- every executed program would leave another congestion
// control registered.  Through a link the registration dies with the link
// fd, which the executor's end-of-program fd sweep closes.  Every mainline
// struct_ops that matters here supports links (tcp_congestion_ops since
// 6.3; mptcp_sched_ops, Qdisc_ops, sched_ext_ops were born with them).
//
// The .name is uniquified in the executor (not at generation time) because
// the same program is executed concurrently by several processes during
// triage and a registered name must be unique kernel-wide.
//
// Layout of the bpf attributes below is the UAPI union bpf_attr's
// (include/uapi/linux/bpf.h), declared command by command and passed with
// its own size: the kernel accepts a shorter attr than its own and
// requires nothing past the fields used here.  No kernel header is
// included; constants are the stable UAPI values.

#ifndef EXECUTOR_COMMON_LINUX_STRUCTOPS_H
#define EXECUTOR_COMMON_LINUX_STRUCTOPS_H

#if SYZ_EXECUTOR || __NR_syz_bpf_struct_ops_load
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// --- Recipe format (mirrors pkg/structops/recipe.go; keep in sync).
#define STRUCTOPS_RECIPE_MAGIC 0x53504f53u
#define STRUCTOPS_RECIPE_VERSION 1u
#define STRUCTOPS_REC_BTF 1u
#define STRUCTOPS_REC_INSTANCE 2u
#define STRUCTOPS_REC_PROG 3u
#define STRUCTOPS_REC_SPEC 4u // host-only generative spec; skipped here
#define STRUCTOPS_REC_DATA 5u
#define STRUCTOPS_INSTANCE_FLAG_LINK 1u
#define STRUCTOPS_STRUCT_NAME_LEN 64
#define STRUCTOPS_MEMBER_LEN 32
#define STRUCTOPS_PROG_NAME_LEN 32
#define STRUCTOPS_KFUNC_NAME_LEN 64
#define STRUCTOPS_DATA_LEN (STRUCTOPS_MEMBER_LEN + 16)
#define STRUCTOPS_MAX_PROGS 16
#define STRUCTOPS_MAX_KFUNCS 64
#define STRUCTOPS_MAX_DATA 16

// --- UAPI constants (include/uapi/linux/bpf.h, include/uapi/linux/btf.h).
#define STRUCTOPS_BPF_MAP_CREATE 0
#define STRUCTOPS_BPF_MAP_UPDATE_ELEM 2
#define STRUCTOPS_BPF_PROG_LOAD 5
#define STRUCTOPS_BPF_BTF_LOAD 18
#define STRUCTOPS_BPF_LINK_CREATE 28
#define STRUCTOPS_BPF_OBJ_GET_INFO_BY_FD 15
#define STRUCTOPS_BPF_ENABLE_STATS 32
#define STRUCTOPS_BPF_PROG_INFO_RUN_CNT_OFF 200 // offsetof(struct bpf_prog_info, run_cnt)
#define STRUCTOPS_BPF_PROG_INFO_LEN 232
#define STRUCTOPS_TCP_CONGESTION 13 // setsockopt(IPPROTO_TCP, TCP_CONGESTION)
#define STRUCTOPS_BPF_MAP_TYPE_STRUCT_OPS 26
#define STRUCTOPS_BPF_PROG_TYPE_STRUCT_OPS 27
#define STRUCTOPS_BPF_STRUCT_OPS_ATTACH 44 // enum bpf_attach_type BPF_STRUCT_OPS
#define STRUCTOPS_BPF_F_LINK (1u << 13)
#define STRUCTOPS_BPF_PSEUDO_KFUNC_CALL 2
#define STRUCTOPS_BPF_JMP_CALL 0x85 // BPF_JMP | BPF_CALL

#define STRUCTOPS_BTF_MAGIC 0xeB9F
#define STRUCTOPS_BTF_KIND_INT 1
#define STRUCTOPS_BTF_KIND_PTR 2
#define STRUCTOPS_BTF_KIND_ARRAY 3
#define STRUCTOPS_BTF_KIND_STRUCT 4
#define STRUCTOPS_BTF_KIND_UNION 5
#define STRUCTOPS_BTF_KIND_ENUM 6
#define STRUCTOPS_BTF_KIND_FWD 7
#define STRUCTOPS_BTF_KIND_TYPEDEF 8
#define STRUCTOPS_BTF_KIND_VOLATILE 9
#define STRUCTOPS_BTF_KIND_CONST 10
#define STRUCTOPS_BTF_KIND_RESTRICT 11
#define STRUCTOPS_BTF_KIND_FUNC 12
#define STRUCTOPS_BTF_KIND_FUNC_PROTO 13
#define STRUCTOPS_BTF_KIND_VAR 14
#define STRUCTOPS_BTF_KIND_DATASEC 15
#define STRUCTOPS_BTF_KIND_FLOAT 16
#define STRUCTOPS_BTF_KIND_DECL_TAG 17
#define STRUCTOPS_BTF_KIND_TYPE_TAG 18
#define STRUCTOPS_BTF_KIND_ENUM64 19

#define STRUCTOPS_VMLINUX_BTF "/sys/kernel/btf/vmlinux"
#define STRUCTOPS_LOG_SIZE (1 << 16)

struct structops_bpf_insn {
	uint8 code;
	uint8 regs; // dst_reg:4 | src_reg:4
	short off;
	int imm;
};

struct structops_attr_btf_load {
	uint64 btf;
	uint64 btf_log_buf;
	uint32 btf_size;
	uint32 btf_log_size;
	uint32 btf_log_level;
	uint32 btf_log_true_size;
	uint32 btf_flags;
	uint32 btf_token_fd;
};

struct structops_attr_map_create {
	uint32 map_type;
	uint32 key_size;
	uint32 value_size;
	uint32 max_entries;
	uint32 map_flags;
	uint32 inner_map_fd;
	uint32 numa_node;
	char map_name[16];
	uint32 map_ifindex;
	uint32 btf_fd;
	uint32 btf_key_type_id;
	uint32 btf_value_type_id;
	uint32 btf_vmlinux_value_type_id;
	uint64 map_extra;
	uint32 value_type_btf_obj_fd;
	uint32 map_token_fd;
};

struct structops_attr_prog_load {
	uint32 prog_type;
	uint32 insn_cnt;
	uint64 insns;
	uint64 license;
	uint32 log_level;
	uint32 log_size;
	uint64 log_buf;
	uint32 kern_version;
	uint32 prog_flags;
	char prog_name[16];
	uint32 prog_ifindex;
	uint32 expected_attach_type;
	uint32 prog_btf_fd;
	uint32 func_info_rec_size;
	uint64 func_info;
	uint32 func_info_cnt;
	uint32 line_info_rec_size;
	uint64 line_info;
	uint32 line_info_cnt;
	uint32 attach_btf_id;
	uint32 attach_btf_obj_fd;
	uint32 core_relo_cnt;
	uint64 fd_array;
	uint64 core_relos;
	uint32 core_relo_rec_size;
	uint32 log_true_size;
	uint32 prog_token_fd;
	uint32 fd_array_cnt;
};

struct structops_attr_map_update {
	uint32 map_fd;
	uint32 pad;
	uint64 key;
	uint64 value;
	uint64 flags;
};

struct structops_attr_link_create {
	uint32 map_fd;
	uint32 target_fd;
	uint32 attach_type;
	uint32 flags;
};

struct structops_attr_obj_info {
	uint32 bpf_fd;
	uint32 info_len;
	uint64 info;
};

struct structops_attr_enable_stats {
	uint32 type; // BPF_STATS_RUN_TIME = 0
};

struct structops_bpf_func_info {
	uint32 insn_off;
	uint32 type_id;
};

struct structops_btf_header {
	uint16 magic;
	uint8 version;
	uint8 flags;
	uint32 hdr_len;
	uint32 type_off;
	uint32 type_len;
	uint32 str_off;
	uint32 str_len;
};

struct structops_btf_type {
	uint32 name_off;
	uint32 info; // vlen:16 | unused:8 | kind:5 | unused:2 | kind_flag:1
	uint32 size; // or type
};

struct structops_btf_member {
	uint32 name_off;
	uint32 type;
	uint32 offset; // bit offset (low 24 bits when kind_flag)
};

struct structops_btf_array {
	uint32 type;
	uint32 index_type;
	uint32 nelems;
};

static long structops_bpf(int cmd, void* attr, unsigned size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

// --- vmlinux BTF: mapped once per process, indexed by type id.

struct structops_vmlinux {
	const uint8* data;
	uint32 size;
	const uint8* strs;
	uint32 str_len;
	uint32* offs; // offs[id] = byte offset of type id in data (id >= 1)
	uint32 ntypes; // number of ids including the implicit void (0)
	int state; // 0 = not loaded, 1 = loaded, -1 = failed
};

static struct structops_vmlinux structops_vml;

static uint32 structops_btf_kind(const struct structops_btf_type* t)
{
	return (t->info >> 24) & 0x1f;
}

static uint32 structops_btf_vlen(const struct structops_btf_type* t)
{
	return t->info & 0xffff;
}

// structops_btf_extra returns the size of the kind-specific data following
// a btf_type, or -1 for an unknown kind.
static long structops_btf_extra(uint32 kind, uint32 vlen)
{
	switch (kind) {
	case STRUCTOPS_BTF_KIND_INT:
	case STRUCTOPS_BTF_KIND_VAR:
	case STRUCTOPS_BTF_KIND_DECL_TAG:
		return 4;
	case STRUCTOPS_BTF_KIND_ARRAY:
		return sizeof(struct structops_btf_array);
	case STRUCTOPS_BTF_KIND_STRUCT:
	case STRUCTOPS_BTF_KIND_UNION:
	case STRUCTOPS_BTF_KIND_DATASEC:
	case STRUCTOPS_BTF_KIND_ENUM64:
		return 12L * vlen;
	case STRUCTOPS_BTF_KIND_ENUM:
	case STRUCTOPS_BTF_KIND_FUNC_PROTO:
		return 8L * vlen;
	case STRUCTOPS_BTF_KIND_PTR:
	case STRUCTOPS_BTF_KIND_FWD:
	case STRUCTOPS_BTF_KIND_TYPEDEF:
	case STRUCTOPS_BTF_KIND_VOLATILE:
	case STRUCTOPS_BTF_KIND_CONST:
	case STRUCTOPS_BTF_KIND_RESTRICT:
	case STRUCTOPS_BTF_KIND_FUNC:
	case STRUCTOPS_BTF_KIND_FLOAT:
	case STRUCTOPS_BTF_KIND_TYPE_TAG:
		return 0;
	}
	return -1;
}

static int structops_vmlinux_load(void)
{
	if (structops_vml.state != 0)
		return structops_vml.state == 1 ? 0 : -1;
	structops_vml.state = -1;
	int fd = open(STRUCTOPS_VMLINUX_BTF, O_RDONLY);
	if (fd < 0) {
		debug("structops: open %s failed: %d\n", STRUCTOPS_VMLINUX_BTF, errno);
		return -1;
	}
	struct stat st;
	if (fstat(fd, &st) || st.st_size < (long)sizeof(struct structops_btf_header)) {
		debug("structops: fstat %s failed: %d\n", STRUCTOPS_VMLINUX_BTF, errno);
		close(fd);
		return -1;
	}
	uint32 size = (uint32)st.st_size;
	// The kernel supports mmap of the vmlinux BTF since 6.16; read() is the
	// fallback for older kernels.
	uint8* data = (uint8*)mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		data = (uint8*)malloc(size);
		if (!data) {
			close(fd);
			return -1;
		}
		uint32 got = 0;
		while (got < size) {
			long n = read(fd, data + got, size - got);
			if (n <= 0) {
				debug("structops: read %s failed at %u: %d\n", STRUCTOPS_VMLINUX_BTF, got, errno);
				free(data);
				close(fd);
				return -1;
			}
			got += (uint32)n;
		}
	}
	close(fd);
	const struct structops_btf_header* h = (const struct structops_btf_header*)data;
	if (h->magic != STRUCTOPS_BTF_MAGIC || (uint64)h->hdr_len + h->type_off + h->type_len > size ||
	    (uint64)h->hdr_len + h->str_off + h->str_len > size) {
		debug("structops: %s: bad BTF header\n", STRUCTOPS_VMLINUX_BTF);
		return -1;
	}
	// Index the type table.
	uint32 cap = 1 << 16;
	uint32* offs = (uint32*)malloc(cap * sizeof(uint32));
	if (!offs)
		return -1;
	uint32 n = 1; // id 0 is void
	uint32 pos = h->hdr_len + h->type_off;
	uint32 end = pos + h->type_len;
	while (pos < end) {
		if (end - pos < sizeof(struct structops_btf_type)) {
			debug("structops: %s: truncated type at %u\n", STRUCTOPS_VMLINUX_BTF, pos);
			free(offs);
			return -1;
		}
		const struct structops_btf_type* t = (const struct structops_btf_type*)(data + pos);
		long extra = structops_btf_extra(structops_btf_kind(t), structops_btf_vlen(t));
		if (extra < 0) {
			debug("structops: %s: unknown BTF kind %u at %u\n", STRUCTOPS_VMLINUX_BTF, structops_btf_kind(t), pos);
			free(offs);
			return -1;
		}
		if (n == cap) {
			cap *= 2;
			uint32* grown = (uint32*)realloc(offs, cap * sizeof(uint32));
			if (!grown) {
				free(offs);
				return -1;
			}
			offs = grown;
		}
		offs[n++] = pos;
		pos += sizeof(struct structops_btf_type) + (uint32)extra;
	}
	structops_vml.data = data;
	structops_vml.size = size;
	structops_vml.strs = data + h->hdr_len + h->str_off;
	structops_vml.str_len = h->str_len;
	structops_vml.offs = offs;
	structops_vml.ntypes = n;
	structops_vml.state = 1;
	debug("structops: %s: %u bytes, %u types\n", STRUCTOPS_VMLINUX_BTF, size, n);
	return 0;
}

static const struct structops_btf_type* structops_vml_type(uint32 id)
{
	if (id == 0 || id >= structops_vml.ntypes)
		return NULL;
	return (const struct structops_btf_type*)(structops_vml.data + structops_vml.offs[id]);
}

static const char* structops_vml_str(uint32 off)
{
	if (off >= structops_vml.str_len)
		return "";
	return (const char*)structops_vml.strs + off;
}

// structops_vml_find returns the id of the first vmlinux type with the given
// name and kind, or 0.  A small cache fronts the linear scan: the names a
// load resolves come from a fixed small set (the kfuncs and structs of a
// surface), and the scan is ~150k types.
struct structops_name_cache_entry {
	char name[STRUCTOPS_KFUNC_NAME_LEN];
	uint32 kind;
	uint32 id;
};

#define STRUCTOPS_NAME_CACHE_SIZE 64
static struct structops_name_cache_entry structops_name_cache[STRUCTOPS_NAME_CACHE_SIZE];
static uint32 structops_name_cache_n;

static uint32 structops_vml_find(const char* name, uint32 kind)
{
	uint32 i = 0;
	for (; i < structops_name_cache_n; i++) {
		if (structops_name_cache[i].kind == kind && strcmp(structops_name_cache[i].name, name) == 0)
			return structops_name_cache[i].id;
	}
	uint32 id = 0;
	uint32 cand = 1;
	for (; cand < structops_vml.ntypes; cand++) {
		const struct structops_btf_type* t = structops_vml_type(cand);
		if (structops_btf_kind(t) != kind)
			continue;
		if (strcmp(structops_vml_str(t->name_off), name) == 0) {
			id = cand;
			break;
		}
	}
	if (id && structops_name_cache_n < STRUCTOPS_NAME_CACHE_SIZE && strlen(name) < STRUCTOPS_KFUNC_NAME_LEN) {
		struct structops_name_cache_entry* e = &structops_name_cache[structops_name_cache_n++];
		strcpy(e->name, name);
		e->kind = kind;
		e->id = id;
	}
	return id;
}

// structops_vml_member finds member `name` of struct `sid`; returns its
// index or -1, and its byte offset / type through the out params.
static int structops_vml_member(uint32 sid, const char* name, uint32* byte_off, uint32* type)
{
	const struct structops_btf_type* t = structops_vml_type(sid);
	if (!t || structops_btf_kind(t) != STRUCTOPS_BTF_KIND_STRUCT)
		return -1;
	uint32 vlen = structops_btf_vlen(t);
	int kflag = (t->info >> 31) & 1;
	const struct structops_btf_member* m = (const struct structops_btf_member*)(t + 1);
	uint32 i = 0;
	for (; i < vlen; i++) {
		if (strcmp(structops_vml_str(m[i].name_off), name) != 0)
			continue;
		uint32 bit_off = kflag ? (m[i].offset & 0xffffff) : m[i].offset;
		if (kflag && (m[i].offset >> 24) != 0)
			return -1; // a bitfield cannot be a callback or a name
		*byte_off = bit_off / 8;
		*type = m[i].type;
		return (int)i;
	}
	return -1;
}

// structops_vml_type_size resolves the byte size of a type (through
// modifiers, arrays and pointers); 0 if unknown.
static uint32 structops_vml_type_size(uint32 id)
{
	int depth = 0;
	for (; depth < 32; depth++) {
		const struct structops_btf_type* t = structops_vml_type(id);
		if (!t)
			return 0;
		switch (structops_btf_kind(t)) {
		case STRUCTOPS_BTF_KIND_INT:
		case STRUCTOPS_BTF_KIND_STRUCT:
		case STRUCTOPS_BTF_KIND_UNION:
		case STRUCTOPS_BTF_KIND_ENUM:
		case STRUCTOPS_BTF_KIND_ENUM64:
		case STRUCTOPS_BTF_KIND_FLOAT:
			return t->size;
		case STRUCTOPS_BTF_KIND_PTR:
			return sizeof(void*);
		case STRUCTOPS_BTF_KIND_ARRAY: {
			const struct structops_btf_array* a = (const struct structops_btf_array*)(t + 1);
			return a->nelems * structops_vml_type_size(a->type);
		}
		case STRUCTOPS_BTF_KIND_TYPEDEF:
		case STRUCTOPS_BTF_KIND_VOLATILE:
		case STRUCTOPS_BTF_KIND_CONST:
		case STRUCTOPS_BTF_KIND_RESTRICT:
		case STRUCTOPS_BTF_KIND_TYPE_TAG:
			id = t->size; // the referenced type
			break;
		default:
			return 0;
		}
	}
	return 0;
}

// --- Recipe parsing.

struct structops_recipe_prog {
	const char* member;
	const char* name;
	uint32 func_type_id;
	uint32 nkfunc;
	uint32 ninsn;
	const uint8* kfuncs; // nkfunc x { uint32 insn_idx; char name[64] }
	const uint8* insns; // ninsn x 8
};

// One scalar instance-data member (`.flags`, `.timeout_ms`, ...) the object
// set to a non-zero value; copied into the map value at the member's offset
// in the running kernel's struct.
struct structops_recipe_data {
	const char* member;
	uint32 size;
	uint64 value;
};

struct structops_recipe {
	const uint8* btf;
	uint32 btf_len;
	uint32 flags;
	const char* struct_name;
	uint32 nprogs;
	struct structops_recipe_prog progs[STRUCTOPS_MAX_PROGS];
	uint32 ndata;
	struct structops_recipe_data data[STRUCTOPS_MAX_DATA];
};

static uint32 structops_get32(const uint8* p)
{
	uint32 v;
	memcpy(&v, p, sizeof(v));
	return v;
}

// structops_cstr checks a fixed-width field is NUL-terminated within it.
static const char* structops_cstr(const uint8* p, uint32 width)
{
	if (!memchr(p, 0, width))
		return NULL;
	return (const char*)p;
}

static int structops_parse_recipe(const uint8* blob, uint32 len, struct structops_recipe* r)
{
	memset(r, 0, sizeof(*r));
	if (len < 12 || structops_get32(blob) != STRUCTOPS_RECIPE_MAGIC ||
	    structops_get32(blob + 4) != STRUCTOPS_RECIPE_VERSION) {
		debug("structops: blob is not a load recipe (len %u)\n", len);
		return -1;
	}
	uint32 nrec = structops_get32(blob + 8);
	uint32 pos = 12;
	uint32 i = 0;
	for (; i < nrec; i++) {
		if (len - pos < 8)
			return -1;
		uint32 typ = structops_get32(blob + pos);
		uint32 n = structops_get32(blob + pos + 4);
		pos += 8;
		if (len - pos < n)
			return -1;
		const uint8* p = blob + pos;
		pos += (n + 3) & ~3u;
		if (pos > len)
			pos = len;
		switch (typ) {
		case STRUCTOPS_REC_BTF:
			r->btf = p;
			r->btf_len = n;
			break;
		case STRUCTOPS_REC_INSTANCE:
			if (n != 4 + STRUCTOPS_STRUCT_NAME_LEN)
				return -1;
			r->flags = structops_get32(p);
			r->struct_name = structops_cstr(p + 4, STRUCTOPS_STRUCT_NAME_LEN);
			if (!r->struct_name)
				return -1;
			break;
		case STRUCTOPS_REC_PROG: {
			const uint32 hdr = STRUCTOPS_MEMBER_LEN + STRUCTOPS_PROG_NAME_LEN + 16;
			if (n < hdr || r->nprogs == STRUCTOPS_MAX_PROGS)
				return -1;
			struct structops_recipe_prog* pr = &r->progs[r->nprogs];
			pr->member = structops_cstr(p, STRUCTOPS_MEMBER_LEN);
			pr->name = structops_cstr(p + STRUCTOPS_MEMBER_LEN, STRUCTOPS_PROG_NAME_LEN);
			pr->func_type_id = structops_get32(p + hdr - 16);
			pr->nkfunc = structops_get32(p + hdr - 12);
			pr->ninsn = structops_get32(p + hdr - 8);
			if (!pr->member || !pr->name || pr->nkfunc > STRUCTOPS_MAX_KFUNCS || pr->ninsn == 0 ||
			    pr->ninsn > (1u << 20) ||
			    n != hdr + pr->nkfunc * (4 + STRUCTOPS_KFUNC_NAME_LEN) + pr->ninsn * sizeof(struct structops_bpf_insn))
				return -1;
			pr->kfuncs = p + hdr;
			pr->insns = pr->kfuncs + pr->nkfunc * (4 + STRUCTOPS_KFUNC_NAME_LEN);
			r->nprogs++;
			break;
		}
		case STRUCTOPS_REC_DATA: {
			if (n != STRUCTOPS_DATA_LEN || r->ndata == STRUCTOPS_MAX_DATA)
				return -1;
			struct structops_recipe_data* d = &r->data[r->ndata];
			d->member = structops_cstr(p, STRUCTOPS_MEMBER_LEN);
			d->size = structops_get32(p + STRUCTOPS_MEMBER_LEN);
			memcpy(&d->value, p + STRUCTOPS_MEMBER_LEN + 8, sizeof(d->value));
			if (!d->member || (d->size != 1 && d->size != 2 && d->size != 4 && d->size != 8))
				return -1;
			r->ndata++;
			break;
		}
		case STRUCTOPS_REC_SPEC:
			// The generative spec the host materialized this recipe from
			// (pkg/structops/spec.go); meaningful only host-side.
			break;
		default:
			return -1;
		}
	}
	if (!r->btf || !r->struct_name || r->nprogs == 0)
		return -1;
	return 0;
}

// --- Unique registered name: "sops_" + 10 hex digits of a random 40-bit
// tag fills the 16-byte TCP_CA_NAME_MAX / MPTCP_SCHED_NAME_MAX.  Random
// rather than pid-derived: every executor worker is pid 2 in its own pid
// namespace, and concurrent procs registering the same name fail with
// EEXIST.
static void structops_uniquify_name(char* out, uint32 width)
{
	uint64 tag = 0;
	if (syscall(__NR_getrandom, &tag, sizeof(tag), 0) != (long)sizeof(tag)) {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		tag = ((uint64)ts.tv_sec << 32) ^ (uint64)ts.tv_nsec ^ ((uint64)getpid() << 20);
	}
	tag &= 0xffffffffffull;
	char name[16];
	snprintf(name, sizeof(name), "sops_%010llx", (unsigned long long)tag);
	memset(out, 0, width);
	if (width > sizeof(name))
		width = sizeof(name);
	memcpy(out, name, width);
	out[width - 1] = 0;
}

#if SYZ_EXECUTOR
static char structops_log[STRUCTOPS_LOG_SIZE];

// structops_debug_log prints the tail of a verifier/BTF log through debug().
static void structops_debug_log(const char* what)
{
	size_t n = strlen(structops_log);
	const char* tail = structops_log;
	if (n > 2048)
		tail = structops_log + n - 2048;
	debug("structops: %s log (last %zu of %zu bytes):\n%s\n", what, strlen(tail), n, tail);
}
#endif

// --- Per-surface exercise tail: make the kernel actually call the
// registered callbacks.  A registration alone covers the struct_ops
// machinery and the subsystem's register path; the callbacks (and the
// kfuncs they call) only run when a socket uses the instance.  The name
// is the one this loader just registered (unique per load), handed in by
// the caller -- it is not knowable at generation time.
//
// mptcp_sched_ops: the netns sysctl selects the scheduler for every MPTCP
// socket created afterwards; the program's own syz_mptcp_pair_init /
// drive_traffic calls then run the callbacks with keystone coverage.
//
// tcp_congestion_ops: selected per socket, so the tail opens a loopback
// TCP connection with setsockopt(TCP_CONGESTION, name) on both ends and
// moves a little data each way.  init runs at setsockopt, cong_avoid on
// every ACK in slow start / avoidance, release at close; ssthresh and
// undo_cwnd need loss or an undo and fire only when a program's other
// calls disturb the connection (that is what the fuzzer is for).

#define STRUCTOPS_TCP_CA_CHUNK 4096
#define STRUCTOPS_TCP_CA_CHUNKS 32

// structops_tcp_ca_transfer moves chunks x CHUNK bytes from tx to rx in
// lockstep (each chunk fully received before the next is sent, so nothing
// ever blocks on a full buffer); returns bytes received.
static long structops_tcp_ca_transfer(int tx, int rx, char* buf)
{
	long total = 0;
	int c = 0;
	for (; c < STRUCTOPS_TCP_CA_CHUNKS; c++) {
		if (send(tx, buf, STRUCTOPS_TCP_CA_CHUNK, MSG_NOSIGNAL) != STRUCTOPS_TCP_CA_CHUNK)
			return total;
		long got = 0;
		while (got < STRUCTOPS_TCP_CA_CHUNK) {
			long n = recv(rx, buf, STRUCTOPS_TCP_CA_CHUNK - got, 0);
			if (n <= 0)
				return total;
			got += n;
		}
		total += got;
	}
	return total;
}

static void structops_exercise_tcp_ca(const char* name)
{
	int srv = -1, cli = -1, acc = -1;
	long fwd = 0, back = 0;
	char* buf = (char*)malloc(STRUCTOPS_TCP_CA_CHUNK);
	if (!buf)
		return;
	memset(buf, 0x5a, STRUCTOPS_TCP_CA_CHUNK);
	struct timeval tmo;
	tmo.tv_sec = 1;
	tmo.tv_usec = 0;
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(0x7f000001); // 127.0.0.1
	socklen_t alen = sizeof(addr);
	srv = socket(AF_INET, SOCK_STREAM, 0);
	cli = socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0 || cli < 0)
		goto out;
	// The listener's choice is inherited by the accepted socket, so both
	// directions run under the registered instance.
	if (setsockopt(srv, IPPROTO_TCP, STRUCTOPS_TCP_CONGESTION, name, strlen(name)) ||
	    setsockopt(cli, IPPROTO_TCP, STRUCTOPS_TCP_CONGESTION, name, strlen(name))) {
		debug("structops: setsockopt(TCP_CONGESTION, %s) failed: %d\n", name, errno);
		goto out;
	}
	if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) || listen(srv, 1) ||
	    getsockname(srv, (struct sockaddr*)&addr, &alen) ||
	    connect(cli, (struct sockaddr*)&addr, sizeof(addr))) {
		debug("structops: tcp_ca exercise: loopback setup failed: %d\n", errno);
		goto out;
	}
	acc = accept(srv, NULL, NULL);
	if (acc < 0)
		goto out;
	setsockopt(cli, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
	setsockopt(acc, SOL_SOCKET, SO_RCVTIMEO, &tmo, sizeof(tmo));
	setsockopt(cli, SOL_SOCKET, SO_SNDTIMEO, &tmo, sizeof(tmo));
	setsockopt(acc, SOL_SOCKET, SO_SNDTIMEO, &tmo, sizeof(tmo));
	fwd = structops_tcp_ca_transfer(cli, acc, buf);
	back = structops_tcp_ca_transfer(acc, cli, buf);
	debug("structops: tcp_ca exercise under %s: %ld + %ld bytes over loopback\n", name, fwd, back);
out:
	if (acc >= 0)
		close(acc);
	if (cli >= 0)
		close(cli);
	if (srv >= 0)
		close(srv);
	free(buf);
}

static void structops_exercise(const char* struct_name, const char* name)
{
	if (strcmp(struct_name, "mptcp_sched_ops") == 0) {
		int fd = open("/proc/sys/net/mptcp/scheduler", O_WRONLY);
		if (fd < 0) {
			debug("structops: open /proc/sys/net/mptcp/scheduler failed: %d\n", errno);
			return;
		}
		if (write(fd, name, strlen(name)) < 0) {
			debug("structops: selecting mptcp scheduler %s failed: %d\n", name, errno);
		}
		close(fd);
	} else if (strcmp(struct_name, "tcp_congestion_ops") == 0) {
		structops_exercise_tcp_ca(name);
	}
}

#if SYZ_EXECUTOR
// structops_debug_run_counts reports how many times the kernel ran each
// callback program (bpf_prog_info.run_cnt), the ground truth that the
// exercise tail reached them.  Counting is only on while a
// BPF_ENABLE_STATS fd is open, so the caller opens one before exercising.
static int structops_enable_stats(void)
{
	struct structops_attr_enable_stats attr;
	memset(&attr, 0, sizeof(attr));
	return structops_bpf(STRUCTOPS_BPF_ENABLE_STATS, &attr, sizeof(attr));
}

static void structops_debug_run_counts(const struct structops_recipe* r, const int* prog_fds)
{
	uint32 i = 0;
	for (; i < r->nprogs; i++) {
		uint8 info[STRUCTOPS_BPF_PROG_INFO_LEN];
		memset(info, 0, sizeof(info));
		struct structops_attr_obj_info attr;
		memset(&attr, 0, sizeof(attr));
		attr.bpf_fd = (uint32)prog_fds[i];
		attr.info_len = sizeof(info);
		attr.info = (uint64)(unsigned long)info;
		uint64 run_cnt = 0;
		if (structops_bpf(STRUCTOPS_BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) == 0)
			memcpy(&run_cnt, info + STRUCTOPS_BPF_PROG_INFO_RUN_CNT_OFF, sizeof(run_cnt));
		debug("structops: %s.%s run_cnt=%llu\n", r->struct_name, r->progs[i].member, (unsigned long long)run_cnt);
	}
}
#endif

static long syz_bpf_struct_ops_load(volatile long a0, volatile long a1)
{
	const uint8* blob = (const uint8*)a0;
	uint32 len = (uint32)a1;
	struct structops_recipe r;
	if (structops_parse_recipe(blob, len, &r)) {
		errno = EINVAL;
		return -1;
	}
	if (structops_vmlinux_load()) {
		errno = ENOENT;
		return -1;
	}
	// Resolve the surface against the running kernel.
	uint32 struct_id = structops_vml_find(r.struct_name, STRUCTOPS_BTF_KIND_STRUCT);
	char value_name[STRUCTOPS_STRUCT_NAME_LEN + 16];
	snprintf(value_name, sizeof(value_name), "bpf_struct_ops_%s", r.struct_name);
	uint32 value_id = structops_vml_find(value_name, STRUCTOPS_BTF_KIND_STRUCT);
	uint32 data_off = 0, data_type = 0, name_off = 0, name_type = 0;
	// The registered-name member is `name` on every surface but Qdisc_ops,
	// which calls it `id` (its TCA_KIND string, char[IFNAMSIZ]).
	if (!struct_id || !value_id || structops_vml_member(value_id, "data", &data_off, &data_type) < 0 ||
	    (structops_vml_member(struct_id, "name", &name_off, &name_type) < 0 &&
	     structops_vml_member(struct_id, "id", &name_off, &name_type) < 0)) {
		debug("structops: %s / %s not a struct_ops of this kernel\n", r.struct_name, value_name);
		errno = ENOENT;
		return -1;
	}
	uint32 value_size = structops_vml_type(value_id)->size;
	uint32 name_size = structops_vml_type_size(name_type);
	if (name_size < 2 || data_off + name_off + name_size > value_size) {
		errno = EINVAL;
		return -1;
	}

	int btf_fd = -1, map_fd = -1, ret = -1, err = EINVAL;
	int prog_fds[STRUCTOPS_MAX_PROGS];
	uint32 i = 0;
	for (; i < STRUCTOPS_MAX_PROGS; i++)
		prog_fds[i] = -1;
	struct structops_bpf_insn* insns = NULL;
	uint8* value = NULL;
	uint32 key = 0;
	char name[16];
#if SYZ_EXECUTOR
	int stats_fd = -1;
#endif

	// 1. The object's BTF.
	struct structops_attr_btf_load battr;
	memset(&battr, 0, sizeof(battr));
	battr.btf = (uint64)(unsigned long)r.btf;
	battr.btf_size = r.btf_len;
	btf_fd = structops_bpf(STRUCTOPS_BPF_BTF_LOAD, &battr, sizeof(battr));
	if (btf_fd < 0) {
		err = errno;
#if SYZ_EXECUTOR
		if (flag_debug) {
			battr.btf_log_buf = (uint64)(unsigned long)structops_log;
			battr.btf_log_size = sizeof(structops_log);
			battr.btf_log_level = 1;
			structops_log[0] = 0;
			structops_bpf(STRUCTOPS_BPF_BTF_LOAD, &battr, sizeof(battr));
			structops_debug_log("BTF_LOAD");
		}
#endif
		debug("structops: BTF_LOAD failed: %d\n", err);
		goto out;
	}

	// 2. One program per callback.
	for (i = 0; i < r.nprogs; i++) {
		struct structops_recipe_prog* pr = &r.progs[i];
		uint32 member_off = 0, member_type = 0;
		int member_idx = structops_vml_member(struct_id, pr->member, &member_off, &member_type);
		if (member_idx < 0) {
			debug("structops: %s has no member %s\n", r.struct_name, pr->member);
			err = ENOENT;
			goto out;
		}
		insns = (struct structops_bpf_insn*)malloc(pr->ninsn * sizeof(*insns));
		if (!insns) {
			err = ENOMEM;
			goto out;
		}
		memcpy(insns, pr->insns, pr->ninsn * sizeof(*insns));
		uint32 k = 0;
		for (; k < pr->nkfunc; k++) {
			const uint8* kf = pr->kfuncs + k * (4 + STRUCTOPS_KFUNC_NAME_LEN);
			uint32 idx = structops_get32(kf);
			const char* kname = structops_cstr(kf + 4, STRUCTOPS_KFUNC_NAME_LEN);
			uint32 kid = kname ? structops_vml_find(kname, STRUCTOPS_BTF_KIND_FUNC) : 0;
			if (idx >= pr->ninsn || !kid || insns[idx].code != STRUCTOPS_BPF_JMP_CALL) {
				debug("structops: kfunc %s (insn %u) not resolvable\n", kname ? kname : "?", idx);
				err = ENOENT;
				goto out;
			}
			// Kernel BTF kfunc call: imm = vmlinux BTF id, off = 0 (vmlinux,
			// not a module BTF from fd_array), src_reg = PSEUDO_KFUNC_CALL.
			insns[idx].imm = (int)kid;
			insns[idx].off = 0;
			insns[idx].regs = (uint8)((STRUCTOPS_BPF_PSEUDO_KFUNC_CALL << 4) | (insns[idx].regs & 0xf));
		}
		struct structops_bpf_func_info finfo;
		finfo.insn_off = 0;
		finfo.type_id = pr->func_type_id;
		struct structops_attr_prog_load pattr;
		memset(&pattr, 0, sizeof(pattr));
		pattr.prog_type = STRUCTOPS_BPF_PROG_TYPE_STRUCT_OPS;
		pattr.insn_cnt = pr->ninsn;
		pattr.insns = (uint64)(unsigned long)insns;
		pattr.license = (uint64)(unsigned long)"GPL";
		strncpy(pattr.prog_name, pr->member, sizeof(pattr.prog_name) - 1);
		pattr.expected_attach_type = (uint32)member_idx;
		pattr.attach_btf_id = struct_id;
		pattr.prog_btf_fd = (uint32)btf_fd;
		pattr.func_info_rec_size = sizeof(finfo);
		pattr.func_info = (uint64)(unsigned long)&finfo;
		pattr.func_info_cnt = 1;
		prog_fds[i] = structops_bpf(STRUCTOPS_BPF_PROG_LOAD, &pattr, sizeof(pattr));
		if (prog_fds[i] < 0) {
			err = errno;
#if SYZ_EXECUTOR
			if (flag_debug) {
				pattr.log_buf = (uint64)(unsigned long)structops_log;
				pattr.log_size = sizeof(structops_log);
				pattr.log_level = 1;
				structops_log[0] = 0;
				structops_bpf(STRUCTOPS_BPF_PROG_LOAD, &pattr, sizeof(pattr));
				structops_debug_log("verifier");
			}
#endif
			debug("structops: %s.%s: PROG_LOAD REJECT errno=%d (%u insns)\n", r.struct_name, pr->member, err, pr->ninsn);
			goto out;
		}
		debug("structops: %s.%s: PROG_LOAD ACCEPT fd=%d (%u insns, %u kfuncs)\n", r.struct_name, pr->member, prog_fds[i], pr->ninsn, pr->nkfunc);
		free(insns);
		insns = NULL;
	}

	// 3. The struct_ops map.
	struct structops_attr_map_create mattr;
	memset(&mattr, 0, sizeof(mattr));
	mattr.map_type = STRUCTOPS_BPF_MAP_TYPE_STRUCT_OPS;
	mattr.key_size = sizeof(uint32);
	mattr.value_size = value_size;
	mattr.max_entries = 1;
	mattr.map_flags = STRUCTOPS_BPF_F_LINK;
	mattr.btf_vmlinux_value_type_id = value_id;
	// map_create() insists on the object's BTF fd whenever a vmlinux value
	// type is given (kernel/bpf/syscall.c: "the bpf_prog.o must have BTF to
	// begin with"); without it the map create fails with EINVAL.
	mattr.btf_fd = (uint32)btf_fd;
	strncpy(mattr.map_name, r.struct_name, sizeof(mattr.map_name) - 1);
	map_fd = structops_bpf(STRUCTOPS_BPF_MAP_CREATE, &mattr, sizeof(mattr));
	if (map_fd < 0) {
		err = errno;
		debug("structops: MAP_CREATE(%s, value %u) failed: %d\n", value_name, value_size, err);
		goto out;
	}

	// 4. The value: callback fds in their slots, the object's instance data
	// in theirs, the unique name, rest zero.
	value = (uint8*)calloc(1, value_size);
	if (!value) {
		err = ENOMEM;
		goto out;
	}
	for (i = 0; i < r.nprogs; i++) {
		uint32 member_off = 0, member_type = 0;
		structops_vml_member(struct_id, r.progs[i].member, &member_off, &member_type);
		uint64 fd = (uint64)prog_fds[i];
		memcpy(value + data_off + member_off, &fd, sizeof(fd));
	}
	for (i = 0; i < r.ndata; i++) {
		// The member is resolved by name in THIS kernel's struct and its
		// width must match the object's (a width change is BTF drift the
		// object was not compiled for).  The value travels as a
		// little-endian u64; its low `size` bytes are the member.
		const struct structops_recipe_data* d = &r.data[i];
		uint32 member_off = 0, member_type = 0;
		if (structops_vml_member(struct_id, d->member, &member_off, &member_type) < 0 ||
		    structops_vml_type_size(member_type) != d->size || data_off + member_off + d->size > value_size) {
			debug("structops: %s.%s: instance data member not resolvable (size %u)\n", r.struct_name, d->member, d->size);
			err = ENOENT;
			goto out;
		}
		memcpy(value + data_off + member_off, &d->value, d->size);
		debug("structops: %s.%s = %#llx\n", r.struct_name, d->member, (unsigned long long)d->value);
	}
	structops_uniquify_name(name, name_size > sizeof(name) ? sizeof(name) : name_size);
	memcpy(value + data_off + name_off, name, strlen(name) + 1);
	struct structops_attr_map_update uattr;
	memset(&uattr, 0, sizeof(uattr));
	uattr.map_fd = (uint32)map_fd;
	uattr.key = (uint64)(unsigned long)&key;
	uattr.value = (uint64)(unsigned long)value;
	if (structops_bpf(STRUCTOPS_BPF_MAP_UPDATE_ELEM, &uattr, sizeof(uattr))) {
		err = errno;
		debug("structops: MAP_UPDATE_ELEM(%s as %s) failed: %d\n", r.struct_name, name, err);
		goto out;
	}

	// 5. The registration: the link.  The map fd is dropped; the link
	// holds the map and the map holds the programs.
	struct structops_attr_link_create lattr;
	memset(&lattr, 0, sizeof(lattr));
	lattr.map_fd = (uint32)map_fd;
	lattr.attach_type = STRUCTOPS_BPF_STRUCT_OPS_ATTACH;
	ret = structops_bpf(STRUCTOPS_BPF_LINK_CREATE, &lattr, sizeof(lattr));
	if (ret < 0) {
		err = errno;
		debug("structops: LINK_CREATE(%s as %s) failed: %d\n", r.struct_name, name, err);
		goto out;
	}
	debug("structops: %s registered as %s (%u callbacks), link fd=%d\n", r.struct_name, name, r.nprogs, ret);
#if SYZ_EXECUTOR
	if (flag_debug)
		stats_fd = structops_enable_stats();
#endif
	structops_exercise(r.struct_name, name);
#if SYZ_EXECUTOR
	if (stats_fd >= 0) {
		structops_debug_run_counts(&r, prog_fds);
		close(stats_fd);
	}
#endif
	err = 0;

out:
	free(insns);
	free(value);
	for (i = 0; i < STRUCTOPS_MAX_PROGS; i++) {
		if (prog_fds[i] >= 0)
			close(prog_fds[i]);
	}
	if (map_fd >= 0)
		close(map_fd);
	if (btf_fd >= 0)
		close(btf_fd);
	if (ret < 0)
		errno = err;
	return ret;
}
#endif

#endif // EXECUTOR_COMMON_LINUX_STRUCTOPS_H
