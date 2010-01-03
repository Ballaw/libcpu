/*
 * libcpu: interface.cpp
 *
 * This is the interface to the client.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* project global headers */
#include "libcpu.h"
#include "tag.h"
#include "translate_all.h"
#include "translate_singlestep.h"
#include "translate_singlestep_bb.h"
#include "function.h"
#include "optimize.h"
#include "stat.h"

/* architecture headers */
#include "arch/6502/libcpu_6502.h"
#include "arch/m68k/libcpu_m68k.h"
#include "arch/mips/libcpu_mips.h"
#include "arch/m88k/libcpu_m88k.h"
#include "arch/arm/libcpu_arm.h"

#define IS_LITTLE_ENDIAN(cpu) (((cpu)->info.common_flags & CPU_FLAG_ENDIAN_MASK) == CPU_FLAG_ENDIAN_LITTLE)

static inline bool
is_valid_gpr_size(size_t size)
{
	switch (size) {
		case 0: case 1: case 8: case 16: case 32: case 64:
			return true;
		default:
			return false;
	}
}

static inline bool
is_valid_fpr_size(size_t size)
{
	switch (size) {
		case 0: case 32: case 64: case 80: case 128:
			return true;
		default:
			return false;
	}
}

static inline bool
is_valid_vr_size(size_t size)
{
	switch (size) {
		case 0: case 64: case 128:
			return true;
		default:
			return false;
	}
}

static StructType *
get_struct_reg(cpu_t *cpu)
{
	std::vector<const Type*>type_struct_reg_t_fields;

	uint32_t count, size;
	
	// GPRs
	count = cpu->info.register_count[CPU_REG_GPR];
	size  = cpu->info.register_size[CPU_REG_GPR];
	for (uint32_t n = 0; n < count; n++)
		type_struct_reg_t_fields.push_back(getIntegerType(size));

	// XRs
	count = cpu->info.register_count[CPU_REG_XR];
	size  = cpu->info.register_size[CPU_REG_XR];
	for (uint32_t n = 0; n < count; n++)
		type_struct_reg_t_fields.push_back(getIntegerType(size));

//	type_struct_reg_t_fields.push_back(getIntegerType(cpu->info.address_size)); /* PC */

	return getStructType(type_struct_reg_t_fields, /*isPacked=*/true);
}

static StructType *
get_struct_fp_reg(cpu_t *cpu)
{
	std::vector<const Type*>type_struct_fp_reg_t_fields;

	uint32_t count, size;

	count = cpu->info.register_count[CPU_REG_FPR];
	size  = cpu->info.register_size[CPU_REG_FPR];
	for (uint32_t n = 0; n < count; n++) {
		if (size == 80) {
			if ((cpu->flags & CPU_FLAG_FP80) == 0) {
				/* two 64bits words hold the data */
				type_struct_fp_reg_t_fields.push_back(getIntegerType(64));
				type_struct_fp_reg_t_fields.push_back(getIntegerType(64));
			} else {
				// XXX ensure it is aligned to 16byte boundary!
				type_struct_fp_reg_t_fields.push_back(getFloatType(80));
			}
		} else if (size == 128) {
			if ((cpu->flags & CPU_FLAG_FP128) == 0) {
				/* two 64bits words hold the data */
				type_struct_fp_reg_t_fields.push_back(getIntegerType(64));
				type_struct_fp_reg_t_fields.push_back(getIntegerType(64));
			} else {
				type_struct_fp_reg_t_fields.push_back(getFloatType(128));
			}
		} else {
			type_struct_fp_reg_t_fields.push_back(getFloatType(size));
		}
	}

	return getStructType(type_struct_fp_reg_t_fields, /*isPacked=*/true);
}

static FunctionType *
get_type_func_callout(cpu_t *cpu)
{
	FunctionType *type_func_callout;
	std::vector<const Type*>args;
	PointerType *type_intptr = PointerType::get(cpu->exec_engine->getTargetData()->getIntPtrType(_CTX()), 0);

	args.push_back(type_intptr);	/* intptr *cpu */
	type_func_callout = FunctionType::get(
		getType(VoidTy),	/* Result */
		args,			/* Params */
		false);		      	/* isVarArg */

	return type_func_callout;
}

static FunctionType *
get_type_func_gbb(cpu_t *cpu)
{
	FunctionType *type_func_gbb;
	std::vector<const Type *> args;
	PointerType *type_pstruct_reg_t = PointerType::get(cpu->mod->getTypeByName("struct.reg_t"), 0);
	PointerType *type_pstruct_fp_reg_t = PointerType::get(cpu->mod->getTypeByName("struct.fp_reg_t"), 0);
	args.push_back(type_pstruct_reg_t);	// reg_t *reg
	args.push_back(type_pstruct_fp_reg_t);	// fp_reg_t *fp_reg */
	//	args.push_back(cpu->type_pfunc_callout);	/* (*debug)(...) */
	type_func_gbb = FunctionType::get(getType(VoidTy), args, false);
	return type_func_gbb;
}

static FunctionType *
get_type_func_trampoline(cpu_t *cpu)
{
	PointerType *type_pfunc_gbb = PointerType::get(cpu->mod->getTypeByName("func.gbb"), 0);
	PointerType *type_pstruct_reg_t = PointerType::get(cpu->mod->getTypeByName("struct.reg_t"), 0);
	PointerType *type_pstruct_fp_reg_t = PointerType::get(cpu->mod->getTypeByName("struct.fp_reg_t"), 0);
	PointerType *type_pfunc_callout = PointerType::get(cpu->mod->getTypeByName("func.callout"), 0);

	std::vector<const Type*>args;
	args.push_back(type_pfunc_gbb);			// (*gbb)(...)
	args.push_back(type_pstruct_reg_t);		// reg_t *reg
	args.push_back(type_pstruct_fp_reg_t);		// fp_reg_t *fp_reg
	args.push_back(type_pfunc_callout);		// (*debug)(...)
	return FunctionType::get(getIntegerType(32), args, false);
}

//////////////////////////////////////////////////////////////////////
// cpu_t
//////////////////////////////////////////////////////////////////////

cpu_t *
cpu_new(cpu_arch_t arch, uint32_t flags, uint32_t arch_flags)
{
	cpu_t *cpu;

	llvm::InitializeNativeTarget();

	cpu = (cpu_t*)malloc(sizeof(cpu_t));
	assert(cpu != NULL);
	memset(&cpu->info, 0, sizeof(cpu->info));
	memset(&cpu->rf, 0, sizeof(cpu->rf));

	cpu->info.type = arch;
	cpu->info.name = "noname";
	cpu->info.common_flags = flags;
	cpu->info.arch_flags = arch_flags;

	switch (arch) {
		case CPU_ARCH_6502:
			cpu->f = arch_func_6502;
			break;
		case CPU_ARCH_M68K:
			cpu->f = arch_func_m68k;
			break;
		case CPU_ARCH_MIPS:
			cpu->f = arch_func_mips;
			break;
		case CPU_ARCH_M88K:
			cpu->f = arch_func_m88k;
			break;
		case CPU_ARCH_ARM:
			cpu->f = arch_func_arm;
			break;
		default:
			printf("illegal arch: %d\n", arch);
			exit(1);
	}

	cpu->code_start = 0;
	cpu->code_end = 0;
	cpu->code_entry = 0;
	cpu->tag = NULL;

	cpu->fp = NULL;
	cpu->trampoline = NULL;
	cpu->dispatch = NULL;
	cpu->dispatch_entries = new dispatch_list;

	cpu->flags_optimize = CPU_OPTIMIZE_NONE;
	cpu->flags_debug = CPU_DEBUG_NONE;
	cpu->flags_hint = CPU_HINT_NONE;
	cpu->flags = 0;

	// init the frontend
	cpu->f.init(cpu, &cpu->info, &cpu->rf);

	assert(is_valid_gpr_size(cpu->info.register_size[CPU_REG_GPR]) &&
		"the specified GPR size is not guaranteed to work");
	assert(is_valid_fpr_size(cpu->info.register_size[CPU_REG_FPR]) &&
		"the specified FPR size is not guaranteed to work");
	assert(is_valid_vr_size(cpu->info.register_size[CPU_REG_VR]) &&
		"the specified VR size is not guaranteed to work");
	assert(is_valid_gpr_size(cpu->info.register_size[CPU_REG_XR]) &&
		"the specified XR size is not guaranteed to work");

	uint32_t count = cpu->info.register_count[CPU_REG_GPR];
	if (count != 0) {
		cpu->ptr_gpr = (Value **)calloc(count, sizeof(Value *));
		cpu->in_ptr_gpr = (Value **)calloc(count, sizeof(Value *));
	} else {
		cpu->ptr_gpr = NULL;
		cpu->in_ptr_gpr = NULL;
	}

	count = cpu->info.register_count[CPU_REG_XR];
	if (count != 0) {
		cpu->ptr_xr = (Value **)calloc(count, sizeof(Value *));
		cpu->in_ptr_xr = (Value **)calloc(count, sizeof(Value *));
	} else {
		cpu->ptr_xr = NULL;
		cpu->in_ptr_xr = NULL;
	}

	count = cpu->info.register_count[CPU_REG_FPR];
	if (count != 0) {
		cpu->ptr_fpr = (Value **)calloc(count, sizeof(Value *));
		cpu->in_ptr_fpr = (Value **)calloc(count, sizeof(Value *));
	} else {
		cpu->ptr_fpr = NULL;
		cpu->in_ptr_fpr = NULL;
	}

	// init LLVM
	cpu->mod = new Module(cpu->info.name, _CTX());
	assert(cpu->mod != NULL);
	cpu->exec_engine = EngineBuilder(cpu->mod).create();
	assert(cpu->exec_engine != NULL);

	// check if FP80 and FP128 are supported by this architecture.
	// XXX there is a better way to do this?
	std::string data_layout = cpu->exec_engine->getTargetData()->getStringRepresentation();
	if (data_layout.find("f80") != std::string::npos) {
		log("INFO: FP80 supported.\n");
		cpu->flags |= CPU_FLAG_FP80;
	}
	if (data_layout.find("f128") != std::string::npos) {
		log("INFO: FP128 supported.\n");
		cpu->flags |= CPU_FLAG_FP128;
	}

	// check if we need to swap guest memory.
	if (cpu->exec_engine->getTargetData()->isLittleEndian()
			^ IS_LITTLE_ENDIAN(cpu))
		cpu->flags |= CPU_FLAG_SWAPMEM;

	cpu->timer_total[TIMER_TAG] = 0;
	cpu->timer_total[TIMER_FE] = 0;
	cpu->timer_total[TIMER_BE] = 0;
	cpu->timer_total[TIMER_RUN] = 0;

	// Save cpu-specific types.
	cpu->mod->addTypeName("struct.reg_t", get_struct_reg(cpu));
	cpu->mod->addTypeName("struct.fp_reg_t", get_struct_fp_reg(cpu));
	cpu->mod->addTypeName("func.callout", get_type_func_callout(cpu));
	cpu->mod->addTypeName("func.gbb", get_type_func_gbb(cpu));
	cpu->mod->addTypeName("func.trampoline", get_type_func_trampoline(cpu));

	return cpu;
}

void
cpu_free(cpu_t *cpu)
{
	if (cpu->f.done != NULL)
		cpu->f.done(cpu);
	
	/*XXX:
	  if (cpu->exec_engine != NULL) {
	  XXX:    if (cpu->cur_func != NULL)
	  cpu->exec_engine->freeMachineCodeForFunction(cpu->cur_func);
	  delete cpu->exec_engine;
	  } */
	if (cpu->in_ptr_fpr != NULL)
		free(cpu->in_ptr_fpr);
	if (cpu->ptr_fpr != NULL)
		free(cpu->ptr_fpr);
	if (cpu->in_ptr_xr != NULL)
		free(cpu->in_ptr_xr);
	if (cpu->ptr_xr != NULL)
		free(cpu->ptr_xr);
	if (cpu->in_ptr_gpr != NULL)
		free(cpu->in_ptr_gpr);
	if (cpu->ptr_gpr != NULL)
		free(cpu->ptr_gpr);
	free(cpu);
}

void
cpu_set_ram(cpu_t*cpu, uint8_t *r)
{
	cpu->RAM = r;
}

void
cpu_set_flags_optimize(cpu_t *cpu, uint64_t f)
{
	cpu->flags_optimize = f;
}

void
cpu_set_flags_debug(cpu_t *cpu, uint32_t f)
{
	cpu->flags_debug = f;
}

void
cpu_set_flags_hint(cpu_t *cpu, uint32_t f)
{
	cpu->flags_hint = f;
}

void
cpu_tag(cpu_t *cpu, addr_t pc)
{
	update_timing(cpu, TIMER_TAG, true);
	tag_start(cpu, pc);
	update_timing(cpu, TIMER_TAG, false);
}

static void
cpu_translate_function(cpu_t *cpu)
{
	if (cpu->trampoline == NULL) {
		// First time run. Initialize
		cpu_create_ram(cpu);
		cpu_create_trampoline(cpu);
		cpu_create_dispatch(cpu);
	}

	/* TRANSLATE! */
	update_timing(cpu, TIMER_FE, true);
#if 0
	if (cpu->flags_debug & CPU_DEBUG_SINGLESTEP) {
		bb_start = cpu_translate_singlestep(cpu, bb_ret, bb_trap);
	} else if (cpu->flags_debug & CPU_DEBUG_SINGLESTEP_BB) {
		bb_start = cpu_translate_singlestep_bb(cpu, bb_ret, bb_trap);
	} else {
		bb_start = cpu_translate_all(cpu);
	}
#endif

	cpu_translate_all(cpu);

	update_timing(cpu, TIMER_FE, false);

	/* make sure everything is OK */
	verifyModule(*cpu->mod, PrintMessageAction);

	if (cpu->flags_debug & CPU_DEBUG_PRINT_IR)
		cpu->mod->dump();

	if (cpu->flags_optimize != CPU_OPTIMIZE_NONE) {
		log("*** Optimizing...");
		optimize(cpu);
		log("done.\n");
		if (cpu->flags_debug & CPU_DEBUG_PRINT_IR_OPTIMIZED)
			cpu->mod->dump();
	}

	log("*** Translating...");
	update_timing(cpu, TIMER_BE, true);
	cpu->exec_engine->recompileAndRelinkFunction(cpu->dispatch);
	cpu->fp = cpu->exec_engine->recompileAndRelinkFunction(cpu->trampoline);
	update_timing(cpu, TIMER_BE, false);
	log("done.\n");
}

/* forces ahead of time translation (e.g. for benchmarking the run) */
void
cpu_translate(cpu_t *cpu)
{
	/* on demand translation */
	if (cpu->tags_dirty) {
		cpu_translate_function(cpu);
	}
	cpu->tags_dirty = false;
}

typedef int (*fp_t)(void *f, void *grf, void *frf, debug_function_t fp);

#ifdef __GNUC__
void __attribute__((noinline))
breakpoint() {
asm("nop");
}
#else
void breakpoint() {}
#endif

int
cpu_run(cpu_t *cpu, debug_function_t debug_function)
{
	addr_t pc, orig_pc = 0;
	int ret;
	bool success;
	bool do_translate = true;

	/* try to find the entry in all functions */
	while(true) {
		if (do_translate) {
			cpu_translate(cpu);
			pc = cpu->f.get_pc(cpu, cpu->rf.grf);
		}

		orig_pc = pc;
		success = false;
		fp_t FP = (fp_t)cpu->fp;
		update_timing(cpu, TIMER_RUN, true);
		breakpoint();
		ret = FP(cpu->exec_engine->getPointerToFunction(cpu->dispatch), cpu->rf.grf, cpu->rf.frf, debug_function);
		update_timing(cpu, TIMER_RUN, false);
		pc = cpu->f.get_pc(cpu, cpu->rf.grf);
		if (ret != JIT_RETURN_FUNCNOTFOUND)
			return ret;
		if (!is_inside_code_area(cpu, pc))
			return ret;
		if (pc != orig_pc) {
			success = true;
		}
		if (!success) {
			cpu_tag(cpu, pc);
		}
	}
}
//printf("%d\n", __LINE__);

void
cpu_flush(cpu_t *cpu)
{
  //XXX: dropAllReferences?	cpu->exec_engine->freeMachineCodeForFunction(cpu->cur_func);
  //XXX:	cpu->cur_func->eraseFromParent();

//	delete cpu->mod;
//	cpu->mod = NULL;
}

void
cpu_print_statistics(cpu_t *cpu)
{
	printf("tag = %8lld\n", cpu->timer_total[TIMER_TAG]);
	printf("fe  = %8lld\n", cpu->timer_total[TIMER_FE]);
	printf("be  = %8lld\n", cpu->timer_total[TIMER_BE]);
	printf("run = %8lld\n", cpu->timer_total[TIMER_RUN]);
}
//printf("%s:%d\n", __func__, __LINE__);
