/*
 * libcpu: function.cpp
 *
 * Create the master function and fill it with the helper
 * basic blocks
 */

#include "libcpu.h"
#include "basicblock.h"
#include "function.h"

//////////////////////////////////////////////////////////////////////
// Reg helpers.
//////////////////////////////////////////////////////////////////////

static Value *
get_struct_member_pointer(Value *s, int index, BasicBlock *bb) {
	ConstantInt* const_0 = ConstantInt::get(getType(Int32Ty), 0);
	ConstantInt* const_index = ConstantInt::get(getType(Int32Ty), index);

	SmallVector<Value*, 2> ptr_11_indices;
	ptr_11_indices.push_back(const_0);
	ptr_11_indices.push_back(const_index);
	return (Value*) GetElementPtrInst::Create(s, ptr_11_indices.begin(), ptr_11_indices.end(), "", bb);
}

static void
emit_decode_reg_helper(cpu_t *cpu, uint32_t count, uint32_t width,
	uint32_t offset, Value *rf, Value **in_ptr_r, Value **ptr_r,
	char const *rcname, BasicBlock *bb)
{
#ifdef OPT_LOCAL_REGISTERS
	// decode struct reg and copy the registers into local variables
	for (uint32_t i = 0; i < count; i++) {
		char reg_name[16];
		snprintf(reg_name, sizeof(reg_name), "%s_%u", rcname, i);

		in_ptr_r[i] = get_struct_member_pointer(rf, i + offset, bb);
		ptr_r[i] = new AllocaInst(getIntegerType(width), reg_name, bb);
		LoadInst* v = new LoadInst(in_ptr_r[i], "", false, bb);
		new StoreInst(v, ptr_r[i], false, bb);
	}
#else
	// just decode struct reg
	for (uint32_t i = 0; i < count; i++) 
		ptr_r[i] = get_struct_member_pointer(rf, i + offset, bb);
#endif
}

static inline unsigned
fp_alignment(unsigned width) {
	return ((width == 80 ? 128 : width) >> 3);
}

static void
emit_decode_fp_reg_helper(cpu_t *cpu, uint32_t count, uint32_t width,
	Value **in_ptr_r, Value **ptr_r, BasicBlock *bb)
{
#ifdef OPT_LOCAL_REGISTERS
	// decode struct reg and copy the registers into local variables
	for (uint32_t i = 0; i < count; i++) {
		char reg_name[16];
		if ((width == 80 && (cpu->flags & CPU_FLAG_FP80) == 0) ||
			(width == 128 && (cpu->flags & CPU_FLAG_FP128) == 0)) {
			snprintf(reg_name, sizeof(reg_name), "fpr_%u_0", i);

			in_ptr_r[i*2+0] = get_struct_member_pointer(cpu->ptr_frf, i*2+0, bb);
			ptr_r[i*2+0] = new AllocaInst(getIntegerType(64), 0, 0, reg_name, bb);
			LoadInst* v = new LoadInst(in_ptr_r[i*2+0], "", false, 0, bb);
			new StoreInst(v, ptr_r[i*2+0], false, 0, bb);

			snprintf(reg_name, sizeof(reg_name), "fpr_%u_1", i);

			in_ptr_r[i*2+1] = get_struct_member_pointer(cpu->ptr_frf, i*2+1, bb);
			ptr_r[i*2+1] = new AllocaInst(getIntegerType(64), 0, 0, reg_name, bb);
			v = new LoadInst(in_ptr_r[i*2+1], "", false, 0, bb);
			new StoreInst(v, ptr_r[i*2+1], false, 0, bb);
		} else {
			snprintf(reg_name, sizeof(reg_name), "fpr_%u", i);
			in_ptr_r[i] = get_struct_member_pointer(cpu->ptr_frf, i, bb);
			ptr_r[i] = new AllocaInst(getFloatType(width), 0, fp_alignment(width), reg_name, bb);
			LoadInst* v = new LoadInst(in_ptr_r[i], "", false, fp_alignment(width), bb);
			new StoreInst(v, ptr_r[i], false, fp_alignment(width), bb);
		}
	}
#else
	// just decode struct reg
	for (uint32_t i = 0; i < count; i++) 
		ptr_r[i] = get_struct_member_pointer(cpu->ptr_frf, i, bb);
#endif
}

static void
emit_decode_pc(cpu_t *cpu, BasicBlock *bb)
{
	// PC pointer.
	Type const *intptr_type = cpu->exec_engine->getTargetData()->getIntPtrType(_CTX());
	Constant *v_pc = ConstantInt::get(intptr_type, (uintptr_t)cpu->rf.pc);
	cpu->ptr_PC = ConstantExpr::getIntToPtr(v_pc, PointerType::getUnqual(getIntegerType(cpu->info.address_size)));
	cpu->ptr_PC->setName("pc");
}

static void
emit_decode_reg(cpu_t *cpu, BasicBlock *bb)
{
	// GPRs
	emit_decode_reg_helper(cpu, cpu->info.register_count[CPU_REG_GPR],
		cpu->info.register_size[CPU_REG_GPR], 0, cpu->ptr_grf,
		cpu->in_ptr_gpr, cpu->ptr_gpr, "gpr", bb);

	// XRs
	emit_decode_reg_helper(cpu, cpu->info.register_count[CPU_REG_XR],
		cpu->info.register_size[CPU_REG_XR],
		cpu->info.register_count[CPU_REG_GPR], cpu->ptr_grf,
		cpu->in_ptr_xr, cpu->ptr_xr, "xr", bb);

	// FPRs
	emit_decode_fp_reg_helper(cpu, cpu->info.register_count[CPU_REG_FPR],
		cpu->info.register_size[CPU_REG_FPR], cpu->in_ptr_fpr,
		cpu->ptr_fpr, bb);

	// PC pointer.
	Type const *intptr_type = cpu->exec_engine->getTargetData()->getIntPtrType(_CTX());
	Constant *v_pc = ConstantInt::get(intptr_type, (uintptr_t)cpu->rf.pc);
	cpu->ptr_PC = ConstantExpr::getIntToPtr(v_pc, PointerType::getUnqual(getIntegerType(cpu->info.address_size)));
	cpu->ptr_PC->setName("pc");
	
	// frontend specific part
	if (cpu->f.emit_decode_reg != NULL)
		cpu->f.emit_decode_reg(cpu, bb);
}

static void
spill_reg_state_helper(uint32_t count, Value **in_ptr_r, Value **ptr_r,
	BasicBlock *bb)
{
#ifdef OPT_LOCAL_REGISTERS
	for (uint32_t i = 0; i < count; i++) {
		LoadInst* v = new LoadInst(ptr_r[i], "", false, bb);
		new StoreInst(v, in_ptr_r[i], false, bb);
	}
#endif
}

static void
spill_fp_reg_state_helper(cpu_t *cpu, uint32_t count, uint32_t width,
	Value **in_ptr_r, Value **ptr_r, BasicBlock *bb)
{
#ifdef OPT_LOCAL_REGISTERS
	for (uint32_t i = 0; i < count; i++) {
		if ((width == 80 && (cpu->flags & CPU_FLAG_FP80) == 0) ||
			(width == 128 && (cpu->flags & CPU_FLAG_FP128) == 0)) {
			LoadInst* v = new LoadInst(ptr_r[i*2+0], "", false, 0, bb);
			new StoreInst(v, in_ptr_r[i*2+0], false, 0, bb);

			v = new LoadInst(ptr_r[i*2+1], "", false, 0, bb);
			new StoreInst(v, in_ptr_r[i*2+1], false, 0, bb);
		} else {
			LoadInst* v = new LoadInst(ptr_r[i], "", false,
				fp_alignment(width), bb);
			new StoreInst(v, in_ptr_r[i], false, fp_alignment(width), bb);
		}
	}
#endif
}

void
spill_reg_state(cpu_t *cpu, BasicBlock *bb)
{
	// frontend specific part.
	if (cpu->f.spill_reg_state != NULL)
		cpu->f.spill_reg_state(cpu, bb);

	// GPRs
	spill_reg_state_helper(cpu->info.register_count[CPU_REG_GPR],
		cpu->in_ptr_gpr, cpu->ptr_gpr, bb);

	// XRs
	spill_reg_state_helper(cpu->info.register_count[CPU_REG_XR],
		cpu->in_ptr_xr, cpu->ptr_xr, bb);

	// FPRs
	spill_fp_reg_state_helper(cpu, cpu->info.register_count[CPU_REG_FPR],
		cpu->info.register_size[CPU_REG_FPR], cpu->in_ptr_fpr,
		cpu->ptr_fpr, bb);
}

//////////////////////////////////////////////////////////////////////
// GuestBB functions.
//////////////////////////////////////////////////////////////////////

static BasicBlock *
create_bb_ret(cpu_t *cpu, Function *f, bool spill)
{
	BasicBlock *bb = BasicBlock::Create(_CTX(), "dispatch", f, 0);
	if (spill)
	  spill_reg_state(cpu, bb);
	ReturnInst::Create(_CTX(), bb);
	return bb;
}

static BasicBlock *
create_bb_unwind(cpu_t *cpu, Function *f)
{
	BasicBlock *bb = BasicBlock::Create(_CTX(), "trap", f, 0);
	spill_reg_state(cpu, bb);
	new UnwindInst(_CTX(), bb);
	return bb;
}

#define GBBF_PRFX "GF_"
#define GBBF_SZ 20

static inline void
_pc_to_function_name(addr_t pc, char *sym)
{
	snprintf(sym, GBBF_SZ, GBBF_PRFX"%08llx",
		 (unsigned long long)pc);
}

Function *
cpu_create_guestbb(cpu_t *cpu, addr_t pc)
{
	Function *f;
	char sym[GBBF_SZ];
	const FunctionType *fty = cast_or_null<FunctionType>(cpu->mod->getTypeByName("func.gbb"));

	_pc_to_function_name(pc, sym);
	f = Function::Create(fty, GlobalValue::ExternalLinkage, sym, cpu->mod);
	f->setCallingConv(CallingConv::C);
	return f;
}

Function *
cpu_get_guestbb(cpu_t *cpu, addr_t pc)
{
	char sym[GBBF_SZ];

	_pc_to_function_name(pc, sym);
	
	/* An array map is faster, but we definitely want LLVM
	 * to use the SymbolResolver, so that we can have more power
	 * by implementing a custom one. */
	return cpu->mod->getFunction(sym);
}

Function *
cpu_setup_guestbb(cpu_t *cpu, addr_t pc, BasicBlock **cur_bb, BasicBlock **bb_dispatch, BasicBlock **bb_trap)
{
	Value *v;
	BasicBlock *bb;
	Function::arg_iterator args;
	Function *f = cpu_get_guestbb(cpu, pc);
	bb = BasicBlock::Create(_CTX(), "entry", f, 0);

	args = f->arg_begin();
	cpu->ptr_grf = args++;
	cpu->ptr_grf->setName("ptr_grf");
	cpu->ptr_frf = args++;
	cpu->ptr_frf->setName("ptr_frf");
	
	v = cpu->mod->getGlobalVariable("G_RAM");
	v = GetElementPtrInst::Create(v, ConstantInt::get(getIntegerType(32), 0), "", bb);
	cpu->ptr_RAM = new LoadInst(v, "", false, bb);
	cpu->ptr_RAM->setName("ptr_RAM");

	emit_decode_reg(cpu, bb);
	
	*cur_bb = bb;
	*bb_dispatch = create_bb_ret(cpu, f, true);
	*bb_trap = create_bb_unwind(cpu, f);
	return f;
}

//////////////////////////////////////////////////////////////////////
// Dispatch function.
//////////////////////////////////////////////////////////////////////

Function *
cpu_create_dispatch(cpu_t *cpu)
{
	Function *f;
	const FunctionType *type_func_dispatch = cast_or_null<FunctionType>(cpu->mod->getTypeByName("func.gbb"));

	f = Function::Create(type_func_dispatch, GlobalValue::ExternalLinkage, "dispatch", cpu->mod);
	f->setCallingConv(CallingConv::C);

	cpu->dispatch = f;
	return f;
}

static inline void
_emit_dispatch_call(cpu_t *cpu, Function *f, BasicBlock *bb_dispatch, BasicBlock *bb_target)
{
	std::vector<Value *> params;
	params.push_back(cpu->ptr_grf);
	params.push_back(cpu->ptr_frf);
	//	params.push_back(cpu->ptr_func_debug);
	CallInst *c = CallInst::Create(f, params.begin(), params.end(), "", bb_target);
	c->setTailCall(true);
	BranchInst::Create(bb_dispatch, bb_target);
}

void
cpu_populate_dispatch(cpu_t *cpu)
{
	Value *v_pc;
	SwitchInst *sw;
	BasicBlock *bb_e, *bb, *bb_ret;
	Function *f = cpu->dispatch;
	Function::arg_iterator args = f->arg_begin();
	dispatch_list::const_iterator it = cpu->dispatch_entries->begin();

	cpu->ptr_grf = args++;
	cpu->ptr_grf->setName("grf");
	cpu->ptr_frf = args++;
	cpu->ptr_frf->setName("frf");

	/* Expensive, but we cannot cache the switch instruction
	 * itself because llvm may optimize it away. */
	f->deleteBody();
	bb_e = BasicBlock::Create(_CTX(), "entry", f, 0);
	bb = BasicBlock::Create(_CTX(), "the_big_switch", f, 0);
	BranchInst::Create(bb, bb_e);
	emit_decode_pc(cpu, bb);
	v_pc  = new LoadInst(cpu->ptr_PC, "", false, bb);
	bb_ret = create_bb_ret(cpu, f, false);
	sw = SwitchInst::Create(v_pc, bb_ret, cpu->dispatch_entries->size(), bb);

	for (; it != cpu->dispatch_entries->end(); it++) {
		log("info: adding case: %llx\n", it->pc);
		BasicBlock *target = create_basicblock(cpu, it->pc, cpu->dispatch, BB_TYPE_NORMAL);
		ConstantInt* c = ConstantInt::get(getIntegerType(cpu->info.address_size), it->pc);

		sw->addCase(c, target);
		_emit_dispatch_call(cpu, cpu_get_guestbb(cpu, it->pc), bb, target);
	}
}

//////////////////////////////////////////////////////////////////////
// Global Variables.
//////////////////////////////////////////////////////////////////////

// XXX: We can add more global variables.

void
cpu_create_ram(cpu_t *cpu)
{
	/* Create global RAM variable. */
	PointerType *type_pi8 = PointerType::get(getIntegerType(8), 0);
	Constant *v_RAM = ConstantExpr::getCast(Instruction::IntToPtr, ConstantInt::get(getType(Int64Ty), (uint64_t)(long)cpu->RAM), type_pi8);
	new GlobalVariable(*cpu->mod, type_pi8, false, GlobalValue::ExternalLinkage, v_RAM, "G_RAM");
}

//////////////////////////////////////////////////////////////////////
// Trampoline function.
//////////////////////////////////////////////////////////////////////

Function *
cpu_create_trampoline(cpu_t *cpu)
{
	Function *func;
	AttrListPtr func_PAL;
	const FunctionType *type_func_trampoline = cast_or_null<FunctionType>(cpu->mod->getTypeByName("func.trampoline"));

	// Create trampoline Function 
	func = Function::Create(type_func_trampoline, GlobalValue::ExternalLinkage, "trampoline", cpu->mod);
	func->setCallingConv(CallingConv::C);
	// Add function attributes.
	{
		SmallVector<AttributeWithIndex, 4> Attrs;
		AttributeWithIndex PAWI;
		PAWI.Index = 1U; PAWI.Attrs = 0  | Attribute::NoCapture;
		Attrs.push_back(PAWI);
		PAWI.Index = 4294967295U; PAWI.Attrs = 0  | Attribute::NoUnwind;
		Attrs.push_back(PAWI);
		func_PAL = AttrListPtr::get(Attrs.begin(), Attrs.end());
	}
	func->setAttributes(func_PAL);

	Function::arg_iterator args = func->arg_begin();
	Value *callee = args++;
	callee->setName("callee");
	Value *grf = args++;
	grf->setName("grf");
	Value *frf = args++;
	frf->setName("frf");
	Value *func_debug = args++;
       	func_debug->setName("debug");

	// Invoke function.
	std::vector<Value *> params;
	params.push_back(grf);
	params.push_back(frf);

	// entry basicblock
	BasicBlock *entry = BasicBlock::Create(_CTX(), "entry", func, 0);

	// create exit code
	Value *exit_code = new AllocaInst(getIntegerType(32), "exit_code", entry);
	// assume JIT_RETURN_FUNCNOTFOUND or JIT_RETURN_SINGLESTEP if in in single step.
	new StoreInst(ConstantInt::get(getType(Int32Ty),
					(cpu->flags_debug & (CPU_DEBUG_SINGLESTEP | CPU_DEBUG_SINGLESTEP_BB)) ? JIT_RETURN_SINGLESTEP :
					JIT_RETURN_FUNCNOTFOUND), exit_code, false, 0, entry);

	// create ret basicblock
	BasicBlock *bb_ret = BasicBlock::Create(_CTX(), "ret", func, 0);  
	ReturnInst::Create(_CTX(), new LoadInst(exit_code, "", false, 0, bb_ret), bb_ret);

	// create trap return basicblock
	BasicBlock *bb_trap = BasicBlock::Create(_CTX(), "trap", func, 0);  
	new StoreInst(ConstantInt::get(getType(Int32Ty), JIT_RETURN_TRAP), exit_code, false, 0, bb_trap);
	BranchInst::Create(bb_ret, bb_trap);

	// Invoke function
	InvokeInst::Create(callee, bb_ret, bb_trap, params.begin(), params.end(), "", entry);
	//CallInst::Create(callee, params.begin(), params.end(), "", entry);
	//	BranchInst::Create(bb_ret, entry);


	cpu->trampoline = func;
	return func;
}
