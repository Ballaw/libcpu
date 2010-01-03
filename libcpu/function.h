// Reg Helpers
void spill_reg_state(cpu_t *cpu, BasicBlock *bb);

// GuestBB functions
Function *cpu_create_guestbb(cpu_t *cpu, addr_t pc);
Function *cpu_get_guestbb(cpu_t *cpu, addr_t pc);
Function *cpu_setup_guestbb(cpu_t *cpu, addr_t pc, BasicBlock **cur_bb, BasicBlock **bb_dispatch, BasicBlock **bb_trap);

// Dispatch function
Function *cpu_create_dispatch(cpu_t *cpu);
void cpu_populate_dispatch(cpu_t *cpu);

// Trampoline function
Function *cpu_create_trampoline(cpu_t *cpu);

// Global variables
void cpu_create_ram(cpu_t *ram);
