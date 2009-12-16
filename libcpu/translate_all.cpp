/*
 * libcpu: translate_all.cpp
 *
 * This translates all known code by creating basic blocks and
 * filling them with instructions.
 */
#include "libcpu.h"
#include "basicblock.h"
#include "disasm.h"
#include "tag.h"
#include "translate.h"

#if 0
static bool
already_is_an_entry_in_some_function(cpu_t *cpu, addr_t pc)
{
	return get_tag(cpu, pc) & TAG_TRANSLATED
		&& needs_dispatch_entry(cpu, pc);
}
#endif 

#if 1

#define GBBF_PRFX "GF_"
#define GBBF_SZ 20

static inline void
_pc_to_function_name(addr_t pc, char *sym)
{
	snprintf(sym, GBBF_SZ, GBBF_PRFX"%08llx",
		 (unsigned long long)pc);
}

static Function *
guestbb_create_function(cpu_t *cpu, addr_t pc)
{
	Function *f;
	FunctionType *fty;
	std::vector<const Type *> args;
	char sym[GBBF_SZ];
	PointerType *type_pstruct_reg_t = PointerType::get(cpu->mod->getTypeByName("struct.reg_t"), 0);
	PointerType *type_pstruct_fp_reg_t = PointerType::get(cpu->mod->getTypeByName("struct.fp_reg_t"), 0);
	_pc_to_function_name(pc, sym);
	args.push_back(type_pstruct_reg_t);	/* reg_t *reg */
	args.push_back(type_pstruct_fp_reg_t);	/* fp_reg_t *fp_reg */
	//	args.push_back(cpu->type_pfunc_callout);	/* (*debug)(...) */
	fty = FunctionType::get(getType(VoidTy), args, false);
	f = Function::Create(fty, GlobalValue::ExternalLinkage, sym, cpu->mod);
	f->setCallingConv(CallingConv::C);
	return f;
}

static Function *
guestbb_get_function(cpu_t *cpu, addr_t pc)
{
	char sym[GBBF_SZ];

	_pc_to_function_name(pc, sym);
	
	/* An array map is faster, but we definitely want LLVM
	 * to use the SymbolResolver, so that we can have more power
	 * by implementing a custom one. */
	return cpu->mod->getFunction(sym);
}

static BasicBlock *
guestbb_create_bbdispatch(cpu_t *cpu, Function *f)
{
	BasicBlock *bb = BasicBlock::Create(_CTX(), "dispatch", f, 0);
	//	spill_reg_state(cpu, bb);
	ReturnInst::Create(_CTX(), bb);
	return bb;
}

static BasicBlock *
guestbb_create_bbtrap(cpu_t *cpu, Function *f)
{
	BasicBlock *bb = BasicBlock::Create(_CTX(), "trap", f, 0);
	//	spill_reg_state(cpu, bb);
	new UnwindInst(_CTX(), bb);
	return bb;
}

static inline void
_emit_dispatch_call(cpu_t *cpu, Function *f, BasicBlock *bb_dispatch, BasicBlock *bb_trap, BasicBlock *bb_target)
{
	std::vector<Value *> params;
	params.push_back(cpu->ptr_grf);
	params.push_back(cpu->ptr_frf);
	//	params.push_back(cpu->ptr_func_debug);
	CallInst *c = CallInst::Create(f, params.begin(), params.end(), "", bb_target);
	c->setTailCall(true);
	BranchInst::Create(bb_dispatch, bb_target);
	//	InvokeInst::Create(f, bb_dispatch, bb_trap, params.begin(), params.end(), "", bb_target);
}

static inline BasicBlock *
_emit_target_bb(cpu_t *cpu, Function *f, BasicBlock *bb_ret, addr_t pc)
{
	BasicBlock *bb = BasicBlock::Create(_CTX(), "", f, 0);
	emit_store_pc_return(cpu, bb, pc, bb_ret);
	return bb;
}

static inline void
_emit_guestbb_call(cpu_t *cpu, Function *f, bool tail, BasicBlock *bb)
{
	std::vector<Value *> params;
	params.push_back(cpu->ptr_grf);
	params.push_back(cpu->ptr_frf);
	//	params.push_back(cpu->ptr_func_debug);
	CallInst *c = CallInst::Create(f, params.begin(), params.end(), "", bb);
	c->setTailCall(tail);
}

static inline BasicBlock *
emit_target_bb(cpu_t *cpu, Function *f, BasicBlock *bb_ret, addr_t pc)
{
	BasicBlock *bb = BasicBlock::Create(_CTX(), "", f, 0);
	Function *tgtf = guestbb_get_function(cpu, pc);
	if (tgtf == NULL) {
		emit_store_pc_return(cpu, bb, pc, bb_ret);
	} else {
		_emit_guestbb_call(cpu, tgtf, true, bb);
		ReturnInst::Create(_CTX(), bb);
	}
	return bb;
}

bool
emit_guestbb_call(cpu_t *cpu, addr_t pc, bool tail,  BasicBlock *bb)
{
	Function *f = guestbb_get_function(cpu, pc);

	if (f == NULL)
		return false;
	_emit_guestbb_call(cpu, f, tail, bb);
	return true;
}

 BasicBlock *
 cpu_translate_all(cpu_t *cpu, BasicBlock *bb_ret, BasicBlock *bb_trap)
 {
	// find all instructions that need labels and create separate
	// functions to be called from the dispatch basic block.
	addr_t pc;
	int cases = 0;
	BasicBlock* bb_dispatch = BasicBlock::Create(_CTX(), "dispatch", cpu->cur_func, 0);

	for (pc = cpu->code_start; pc < cpu->code_end; pc++) {
		if (needs_dispatch_entry(cpu, pc)) {
			Function *f = guestbb_create_function(cpu, pc);
			BasicBlock *bb_target = create_basicblock(cpu, pc, cpu->cur_func, BB_TYPE_NORMAL);
			_emit_dispatch_call(cpu, f, bb_dispatch, bb_trap, bb_target);
			cases++;
		}
	}
	log("cases: %d\n", cases);

	Value *v_pc = new LoadInst(cpu->ptr_PC, "", false, bb_dispatch);
	SwitchInst* sw = SwitchInst::Create(v_pc, bb_ret, cases, bb_dispatch);

	for (pc = cpu->code_start; pc < cpu->code_end; pc++) {
		if (needs_dispatch_entry(cpu, pc) && !(get_tag(cpu, pc) & TAG_TRANSLATED)) {
			log("info: adding case: %llx\n", pc);
			ConstantInt* c = ConstantInt::get(getIntegerType(cpu->info.address_size), pc);
			BasicBlock *target = (BasicBlock*)lookup_basicblock(cpu, cpu->cur_func, pc, bb_ret, BB_TYPE_NORMAL);
			sw->addCase(c, target);
		}
	}

	// translate all known guest basic blocks.
	bbaddr_map &bb_addr = cpu->func_bb[cpu->cur_func];
	bbaddr_map::const_iterator it;
	for (it = bb_addr.begin(); it != bb_addr.end(); it++) {
		tag_t tag;
		addr_t pc = it->first;
		Function *f = guestbb_get_function(cpu, pc);
		BasicBlock *cur_bb = BasicBlock::Create(_CTX(), "entry", f, 0);
		BasicBlock *bb_target = NULL, *bb_next = NULL, *bb_cont = NULL;

		BasicBlock *gbb_dispatch = guestbb_create_bbdispatch(cpu, f);
		BasicBlock *gbb_trap = guestbb_create_bbtrap(cpu, f);

		{
		  Value *G_RAM = cpu->mod->getGlobalVariable("G_RAM");
		  Value *a = GetElementPtrInst::Create(G_RAM, ConstantInt::get(getIntegerType(32), 0), "", cur_bb);
		  cpu->ptr_RAM = new LoadInst(a, "", false, cur_bb);
		}

		Function::arg_iterator args = f->arg_begin();
		cpu->ptr_grf = args++;
		cpu->ptr_grf->setName("arg_grf");
		cpu->ptr_frf = args++;
		cpu->ptr_frf->setName("arg_frf");

		extern void emit_decode_reg(cpu_t *cpu, BasicBlock *bb);
		emit_decode_reg(cpu, cur_bb);

		if (needs_dispatch_entry(cpu, pc))
			or_tag(cpu, pc, TAG_TRANSLATED);

		do {
			tag_t dummy1;
			disasm_instr(cpu, pc);
			tag = get_tag(cpu, pc);

			/* get address of the following instruction */
			addr_t new_pc, next_pc;
			cpu->f.tag_instr(cpu, pc, &dummy1, &new_pc, &next_pc);

			/* XXX: Implement direct linking! Tail Call is here! */
			/* get target basic block */
			if (tag & (TAG_RET|TAG_CALL|TAG_BRANCH)) 
				bb_target = gbb_dispatch;
			if ((tag & (TAG_CALL|TAG_BRANCH)
			     && new_pc != NEW_PC_NONE))
				bb_target = emit_target_bb(cpu, f, gbb_dispatch, new_pc);
			if (tag & TAG_CONDITIONAL)
				bb_next = emit_target_bb(cpu, f, gbb_dispatch, next_pc);
			bb_cont = translate_instr(cpu, pc, tag, bb_target,
						  gbb_trap, bb_next, cur_bb, f);

			pc = next_pc;
			
		} while (
			/* new basic block starts here (and we haven't translated it yet)*/
			(!is_start_of_basicblock(cpu, pc)) &&
			/* end of code section */ //XXX no: this is whether it's TAG_CODE
			is_code(cpu, pc) &&
			/* last intruction jumped away */
			bb_cont
			);

		/* XXX: Implement bb linking! */
		if (bb_cont) {
			Function *tgtf = guestbb_get_function(cpu, pc);
			if (tgtf == NULL) {
				emit_store_pc_return(cpu, bb_cont, pc, gbb_dispatch);
			} else {
				_emit_guestbb_call(cpu, tgtf, true, bb_cont);
				ReturnInst::Create(_CTX(), bb_cont);
			}
		}
	}
	return bb_dispatch;
}

#else

BasicBlock *
cpu_translate_all(cpu_t *cpu, BasicBlock *bb_ret, BasicBlock *bb_trap)
{
	// find all instructions that need labels and create basic blocks for them
	int bbs = 0;
	addr_t pc;
	pc = cpu->code_start;
	while (pc < cpu->code_end) {
		//log("%04X: %d\n", pc, get_tag(cpu, pc));
		if (is_start_of_basicblock(cpu, pc) && !already_is_an_entry_in_some_function(cpu,pc)) {
			create_basicblock(cpu, pc, cpu->cur_func, BB_TYPE_NORMAL);
			bbs++;
		}
		pc++;
	}
	log("bbs: %d\n", bbs);

	// create dispatch basicblock
	BasicBlock* bb_dispatch = BasicBlock::Create(_CTX(), "dispatch", cpu->cur_func, 0);
	Value *v_pc = new LoadInst(cpu->ptr_PC, "", false, bb_dispatch);
	SwitchInst* sw = SwitchInst::Create(v_pc, bb_ret, bbs /*XXX upper bound, not accurate count!*/, bb_dispatch);

	for (pc = cpu->code_start; pc < cpu->code_end; pc++) {
		if (needs_dispatch_entry(cpu, pc) && !(get_tag(cpu, pc) & TAG_TRANSLATED)) {
			log("info: adding case: %llx\n", pc);
			ConstantInt* c = ConstantInt::get(getIntegerType(cpu->info.address_size), pc);
			BasicBlock *target = (BasicBlock*)lookup_basicblock(cpu, cpu->cur_func, pc, bb_ret, BB_TYPE_NORMAL);
			sw->addCase(c, target);
		}
	}

	// translate basic blocks
	bbaddr_map &bb_addr = cpu->func_bb[cpu->cur_func];
	bbaddr_map::const_iterator it;
	for (it = bb_addr.begin(); it != bb_addr.end(); it++) {
		pc = it->first;
		BasicBlock *cur_bb = it->second;

		tag_t tag;


		if (already_is_an_entry_in_some_function(cpu, pc)) {
		  printf("already_is_an_entry_in_some_function! %llx\n", pc);
			continue;
		}

		if (needs_dispatch_entry(cpu, pc))
			or_tag(cpu, pc, TAG_TRANSLATED);

		log("basicblock: L%08llx\n", (unsigned long long)pc);

		do {
			tag_t dummy1;

			if (LOGGING)
				disasm_instr(cpu, pc);

			tag = get_tag(cpu, pc);

			/* get address of the following instruction */
			addr_t new_pc, next_pc;
			cpu->f.tag_instr(cpu, pc, &dummy1, &new_pc, &next_pc);

			/* get target basic block */
			if (tag & TAG_RET)
				bb_target = bb_dispatch;
			if (tag & (TAG_CALL|TAG_BRANCH)) {
				if (new_pc == NEW_PC_NONE) /* translate_instr() will set PC */
					bb_target = bb_dispatch;
				else
					bb_target = (BasicBlock*)lookup_basicblock(cpu, cpu->cur_func, new_pc, bb_ret, BB_TYPE_NORMAL);
			}
			/* get not-taken basic block */
			if (tag & TAG_CONDITIONAL)
 				bb_next = (BasicBlock*)lookup_basicblock(cpu, cpu->cur_func, next_pc, bb_ret, BB_TYPE_NORMAL);

			bb_cont = translate_instr(cpu, pc, tag, bb_target, bb_trap, bb_next, cur_bb);

			pc = next_pc;
			
		} while (
					/* new basic block starts here (and we haven't translated it yet)*/
					(!is_start_of_basicblock(cpu, pc)) &&
					/* end of code section */ //XXX no: this is whether it's TAG_CODE
					is_code(cpu, pc) &&
					/* last intruction jumped away */
					bb_cont
				);

		/* link with next basic block if there isn't a control flow instr. already */
		if (bb_cont) {
			BasicBlock *target = (BasicBlock*)lookup_basicblock(cpu, cpu->cur_func, pc, bb_ret, BB_TYPE_NORMAL);
			log("info: linking continue $%04llx!\n", (unsigned long long)pc);
			BranchInst::Create(target, bb_cont);
		}
    }

	return bb_dispatch;
}
#endif
