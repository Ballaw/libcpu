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
#include "function.h"
#include "translate.h"

extern void spill_reg_state(cpu_t *cpu, BasicBlock *bb);

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
	Function *tgtf = cpu_get_guestbb(cpu, pc);
	spill_reg_state(cpu, bb);
	if (tgtf == NULL) {
		emit_store_pc_return(cpu, bb, pc, bb_ret);
	} else {
		_emit_guestbb_call(cpu, tgtf, true, bb);
		ReturnInst::Create(_CTX(), bb);
	}
	return bb;
}

void
cpu_translate_all(cpu_t *cpu)
{
	addr_t pc;

	// Add new guest BBs to the dispatch list.
	for (pc = cpu->code_start; pc < cpu->code_end; pc++) {
		if (needs_dispatch_entry(cpu, pc) && !(get_tag(cpu, pc) & TAG_TRANSLATED)) {
			Function *f = cpu_create_guestbb(cpu, pc);
			dispatch_entry_t entry;
			entry.pc = pc;
			entry.func = f;
			cpu->dispatch_entries->push_back(entry);
		}
	}

	cpu_populate_jitmain(cpu);
	cpu_populate_dispatch(cpu);
	
	// translate all new guest basic blocks.
	dispatch_list::const_iterator it = cpu->dispatch_entries->begin();
	for (; it != cpu->dispatch_entries->end(); it++) {
		tag_t tag;
		Function *f;
		addr_t pc = it->pc;
		BasicBlock *cur_bb, *bb_dispatch, *bb_trap;
		BasicBlock *bb_target = NULL, *bb_next = NULL, *bb_cont = NULL;

		if (get_tag(cpu, pc) & TAG_TRANSLATED)
			continue;

		or_tag(cpu, pc, TAG_TRANSLATED);
		f = cpu_setup_guestbb(cpu, pc, &cur_bb, &bb_dispatch, &bb_trap);

		do {
			tag_t dummy1;
			disasm_instr(cpu, pc);
			tag = get_tag(cpu, pc);
			
			/* get address of the following instruction */
			addr_t new_pc, next_pc;
			cpu->f.tag_instr(cpu, pc, &dummy1, &new_pc, &next_pc);
			
			if (tag & (TAG_RET|TAG_CALL|TAG_BRANCH))
				bb_target = bb_dispatch;
			if (tag & (TAG_CALL|TAG_BRANCH)
			    && new_pc != NEW_PC_NONE)
				bb_target = emit_target_bb(cpu, f, bb_dispatch, new_pc);
			if (tag & TAG_CONDITIONAL)
				bb_next = emit_target_bb(cpu, f, bb_dispatch, next_pc);
			bb_cont = translate_instr(cpu, pc, tag, bb_target,
						  bb_trap, bb_next, cur_bb, f);
			
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
			Function *tgtf = cpu_get_guestbb(cpu, pc);
			spill_reg_state(cpu, bb_cont);
			if (tgtf == NULL) {
				emit_store_pc_return(cpu, bb_cont, pc, bb_dispatch);
			} else {
				_emit_guestbb_call(cpu, tgtf, true, bb_cont);
				ReturnInst::Create(_CTX(), bb_cont);
			}
		}
	}
}
