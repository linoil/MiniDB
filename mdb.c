#define _GNU_SOURCE // Needed for getdelim

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/personality.h>
#include <capstone/capstone.h>
#include <sys/user.h> // For user_regs_struct
#include <signal.h>   // For SIGTRAP and siginfo_t
#define MAX_BP 16 // Define the maximum number of breakpoints
#define MAX_ID 32
// #define INT3 0xCC0xCC
#define RIP 16 // Index for RIP in user_regs_struct

const uint8_t INT3[1] = {0xcc};

struct bp_t {
    uint8_t id;
    bool is_set;   // Flag to indicate if the breakpoint is set
    size_t addr;    // Address of the breakpoint
    uint8_t instr;
};

struct target_t {
    bool run;
    char *cmd;
    pid_t pid;

    struct bp_t breakpoints[MAX_BP];
    struct bp_t *hit_bp;
    uint16_t bp_bitmap;
    int bp_id[MAX_ID];
};

static struct target_t target;
size_t entry_point;
size_t text_section_start;
size_t text_section_end;
bool is_loaded = false;
uint64_t cur_rip;
bool in_syscall = false;


uint8_t id_now = 0;

void print_binary(uint16_t num);

void swbp_init(struct bp_t *bp, size_t addr);
bool swbp_set(struct bp_t *bp);
bool swbp_unset(struct bp_t *bp);

static bool target_sigtrap(siginfo_t info);
bool target_wait_sig();
bool target_set_breakpoint(size_t addr);
bool target_handle_bp();
bool target_find_bp(size_t addr, struct bp_t **bp);
bool get_entry_point(const char *program, size_t *entry, size_t *text_start, size_t *text_end);
bool target_launch(const char *program);
bool target_step();
bool target_cont();
bool target_syscall();
uint64_t target_get_rip();
bool target_set_rip(size_t value);
void disassemble_instr(uint64_t from_addr, int count);


bool mdb_init(const char *path);
char** mdb_parse_cmd(char *line, int *argc);
void mdb_si();
void mdb_cont();
void mdb_info_reg();
void mdb_break(size_t addr);
void mdb_info_break();
void mdb_delete_bp(int id);
void mdb_patch(size_t addr, size_t value, int len);
void mdb_syscall();
void mdb_match_cmd(int argc, char **argv);
void mdb_run();
void mdb_close();

int main(int argc, char *argv[]) {
    if (argc == 2) {
        if (!mdb_init(argv[1])) {
            perror("dbg_init");
            return -1;
        }
    } else {
        target.run = true;
        // printf("** please load a program first.\n");
    }

    mdb_run();
    mdb_close();

    return 0;
}
void print_binary(uint16_t num) {
    for (int i = 15; i >= 0; --i) {
        printf("%d", (num >> i) & 1);
    }
}

void swbp_init(struct bp_t *bp, size_t addr) {
    bp->addr = addr;
    bp->is_set = false;
    bp->id = id_now++;
}

bool swbp_set(struct bp_t *bp) {
    if (bp->is_set)
        return false;
    
    size_t instr = ptrace(PTRACE_PEEKDATA, target.pid, (void *) bp->addr, NULL);
    if (instr == (size_t) -1) {
        perror("ptrace_peek");
        return false;
    }

    bp->instr = instr;
    memcpy(&instr, INT3, sizeof(INT3));
    int ret = ptrace(PTRACE_POKEDATA, target.pid, (void *) bp->addr, instr);
    // int ret = ptrace(PTRACE_POKETEXT, target.pid, (void *) bp->addr, (void *)((bp->addr & ~0xFF) | 0xCC));
    if (ret == -1) {
        perror("ptrace_poke");
        return false;
    }

    // uint64_t rip = target_get_rip();
    // printf("[swbp_set]\n");
    // disassemble_instr(rip, 5);

    bp->is_set = true;
    return true;
}

bool swbp_unset(struct bp_t *bp) {
    if (!bp->is_set)
        return false;

    uint64_t current_memory = ptrace(PTRACE_PEEKDATA, target.pid, (void *) bp->addr, NULL);
    // printf("before: 0x%lx\n", current_memory);
    current_memory = (current_memory & ~(0xff)) | bp->instr;
    // printf("after: 0x%lx\n", current_memory);
    

    // printf("[swbp_unset] addr:%zx\n", bp->addr);
    int ret = ptrace(PTRACE_POKEDATA, target.pid, (void *) bp->addr, current_memory);
    if (ret == -1) {
        perror("ptrace_poke");
        return false;
    }
    // disassemble_instr(bp->addr, 5);

    bp->is_set = false;
    return true;
}

static bool target_sigtrap(siginfo_t info) {
    struct bp_t *bp = NULL; // breakpoints
    size_t addr;

    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, target.pid, 0, &regs);
    // printf("orig_rax: %lld, rax: %lld, rdi: %lld, rip: %llx\n", regs.orig_rax, regs.rax, regs.rdi, regs.rip);
    // disassemble_instr(target_get_rip(), 5);

    switch (info.si_code) { // specific reason why the SIGTRAP signal was generated
    case TRAP_TRACE: // single-step op
        // Handle system call enter/exit
        // struct user_regs_struct regs;
        // ptrace(PTRACE_GETREGS, target.pid, 0, &regs);
        // printf("orig_rax: %lld, rax: %lld, rdi: %lld, rip: %llx\n", regs.orig_rax, regs.rax, regs.rdi, regs.rip);
        return true;
    case TRAP_BRKPT: // bp
    case SI_KERNEL: // kernel-bp
        addr = (size_t) target_get_rip();
        if (addr == (size_t) -1) {
            return false; // error already printed by target_get_rip
        }
        // decrease addr to point to the instr that caused the trap
        addr -= 1;
        printf("** hit a breakpoint at 0x%zx.\n", addr);
        
        // printf("[target_sigtrap] RIP before adjustment: %zx\n", addr);

        if (target_find_bp(addr, &bp)) {
            target.hit_bp = bp;
            if (!swbp_unset(bp)) {
                printf("swbp_unset failed\n");
                return false;
            }
            // printf("[target_sigtrap] Breakpoint found and unset at: %zx\n", addr);
        } else {
            printf("target_find_bp failed for addr: %zx\n", addr);
            return false;
        }

        // set RIP to `addr`
        if (!target_set_rip(addr)) {
            printf("target_set_rip failed\n");
            return false;
        }

        return true;
    case 5:
        if (!in_syscall) {
            // Entering a syscall
            printf("** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip-2);
            in_syscall = true;
        } else {
            // Leaving a syscall
            printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip-2);
            in_syscall = false;
        }
        disassemble_instr(regs.rip-2, 5);
        // struct ptrace_syscall_info syscall_info;
        // ptrace(PTRACE_GET_SYSCALL_INFO, target.pid, sizeof(syscall_info), &syscall_info);
        // if (!in_syscall) {
        //     // Entering a syscall
        //     printf("** enter a syscall(%lld) at 0x%llx.\n", syscall_info.entry.nr, regs.rip);
        //     in_syscall = true;
        // } else {
        //     // Leaving a syscall
        //     printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", syscall_info.entry.nr, syscall_info.exit.rval, regs.rip);
        //     in_syscall = false;
        // }
        return true;
    default:
        // printf("Unknown %d\n", info.si_code);
        return false;
    }
}


bool target_wait_sig() {
    int wstatus;
    /* wait for state changes in the child process with pid = target.pid */
    if (waitpid(target.pid, &wstatus, __WALL) < 0) {
        perror("waitpid");
        return false;
    }

    bool ret = true;
    /* stopped && is stopped by tracer */
    if (WIFSTOPPED(wstatus) && (WSTOPSIG(wstatus) == SIGTRAP)) {
        siginfo_t info;
        memset(&info, 0, sizeof(siginfo_t));
        // retrieves signal information about the SIGTRAP
        ptrace(PTRACE_GETSIGINFO, target.pid, 0, &info);

        switch (info.si_signo) {
        case SIGTRAP:
            // Handle SIGTRAP signal
            target_sigtrap(info);
            break;
        default:
            /* simply ignore these */
            break;
        }
    } else if (WIFEXITED(wstatus)) { /* exited */
        printf("** the target program terminated.\n");
        // printf("[Process %d exited]\n", target.pid);
        target.run = false;
    }

    return ret;
}

bool target_set_breakpoint(size_t addr) {
    // find an available bp slot
    int n = __builtin_ffs(target.bp_bitmap);
    if (n == 0) {
        printf("Only at max 16 breakpoints could be set\n");
        return false;
    }
    n -= 1;
    target.bp_bitmap &= ~(1 << n);

    // Initialize and Set the Breakpoint
    swbp_init(&target.breakpoints[n], addr);
    target.bp_id[target.breakpoints[n].id] = n;
    if (!swbp_set(&target.breakpoints[n]))
        return false;

    // Adds the breakpoint to a hash table using its address key
    // if (!hashtbl_add(&target.tbl, target.breakpoints[n].addr_key, &target.breakpoints[n]))
    //     return false;

    printf("** set a breakpoint at 0x%lx.\n", addr);
    return true;
}

bool target_handle_bp() {
    // printf("[target_handle_bp]\n");
    if (!target.hit_bp) {
        return true;
    }

    // We have to take the bp first to avoid infinite loop
    struct bp_t *hit_bp = target.hit_bp;
    target.hit_bp = NULL;

    uint64_t rip;
    rip = target_get_rip();
    // printf("at %lx\n", (size_t) rip);
    if ((size_t) rip == hit_bp->addr) {
        target_step();
    }

    /* restore the trap instruction before we do cont command */
    if (!swbp_set(hit_bp))
        return false;

    return true;
}

bool target_find_bp(size_t addr, struct bp_t **bp) {
    for (int i = 0; i < MAX_BP; ++i) {
        if (!(target.bp_bitmap & (1 << i)) && target.breakpoints[i].addr == addr) {
            *bp = &target.breakpoints[i];
            return true;   
        }
    }
    return false;
}

bool get_entry_point(const char *program, size_t *entry, size_t *text_start, size_t *text_end) {
    int fd = open(program, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return false;
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("read");
        close(fd);
        return false;
    }

    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        close(fd);
        return false;
    }

    *entry = ehdr.e_entry;

    Elf64_Shdr shdr;
    lseek(fd, ehdr.e_shoff, SEEK_SET);

    for (int i = 0; i < ehdr.e_shnum; i++) {
        if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) {
            perror("read");
            close(fd);
            return false;
        }

        if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR)) {
            *text_start = shdr.sh_addr;
            *text_end = shdr.sh_addr + shdr.sh_size;
            break;
        }
    }

    close(fd);
    return true;
}

bool target_launch(const char *program) {
    pid_t pid = fork();

    if (pid == 0) {
        // Child process: the debugged program
        personality(ADDR_NO_RANDOMIZE);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(program, program, NULL);
    }

    target.pid = pid;
    // Parent process: the debugger
    if (!target_wait_sig())
        return false;

    
    target.hit_bp = NULL;
    target.run = true;
    // /* we should guarantee the initial value of breakpoint array */
    target.bp_bitmap = 0xffff;
    memset(target.breakpoints, 0, sizeof(struct bp_t) * MAX_BP);
    // hashtbl_create(&t->tbl, MAX_BP);

    int options = PTRACE_O_EXITKILL; // ensure that the tracee is killed if it exits
    ptrace(PTRACE_SETOPTIONS, pid, NULL, options);
    // printf("PID(%d)\n", target.pid);
    return true;
}

bool target_step() {
    // printf("[target_step]\n");
    if (!target.run) {
        printf("** the target program terminated.\n");
        return false;
    }

    if (!target_handle_bp())
        return false;

    cur_rip = target_get_rip();
    // printf("[target_step] cur_rip: %zx\n", (size_t) cur_rip);
    ptrace(PTRACE_SINGLESTEP, target.pid, NULL, NULL);
    if (!target_wait_sig()) {
        return false;
    }
    return true;
}

bool target_cont() {
    if (!target.run) {
        printf("** the target program terminated.\n");
        return false;
    }

    if (!target_handle_bp())
        return false;

    ptrace(PTRACE_CONT, target.pid, NULL, NULL);
    if (!target_wait_sig()){
        return false;
    }

    return true;
}

bool target_syscall() {
    // printf("[target_syscall]\n");
    if (!target.run) {
        printf("** the target program terminated.\n");
        return false;
    }

    if (!target_handle_bp())
        return false;
    
    // cur_rip = target_get_rip();
    // printf("[target_syscall] cur_rip: %zx\n", (size_t) cur_rip);
    // Continue the child process and trace system calls
    ptrace(PTRACE_SYSCALL, target.pid, NULL, NULL);
    if (!target_wait_sig()) {
        return false;
    }

    return true;
}

uint64_t target_get_rip() {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, target.pid, NULL, &regs);

    return regs.rip;
}

bool target_set_rip(size_t value) {
    // printf("target_set_reg\n");
    struct user_regs_struct regs;
    // ptrace(PTRACE_GETREGS, target.pid, NULL, &regs);
    if (ptrace(PTRACE_GETREGS, target.pid, NULL, &regs) == -1) {
        perror("ptrace(PTRACE_GETREGS)");
        return false;
    }

    // *(((size_t *) &regs) + idx) = value;
    regs.rip = value;

    // ptrace(PTRACE_SETREGS, target.pid, NULL, &regs);
    if (ptrace(PTRACE_SETREGS, target.pid, NULL, &regs) == -1) {
        perror("ptrace(PTRACE_SETREGS)");
        return false;
    }
    return true;
}

void disassemble_instr(uint64_t from_addr, int count) {
    csh handle;
    cs_insn *insn; // pointer to hold the disassembled instr
    size_t insn_count; // number of disassembled instr
    uint8_t code[40];

    // Read the instructions from memory
    struct bp_t *bp;
    for (int i = 0; i < 40; ++i) {
        code[i] = ptrace(PTRACE_PEEKTEXT, target.pid, from_addr + i, NULL);
        if (code[i] == INT3[0]) {
            target_find_bp(from_addr + i, &bp);
            code[i] = bp->instr;
        }
    }

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Failed to initialize Capstone disassembler\n");
        return;
    }

    // The disassembled instructions are stored in insn, and the number of instructions disassembled is stored in insn_count
    insn_count = cs_disasm(handle, code, sizeof(code), from_addr, count, &insn);
    // for(int i = 0; i < insn_count; i++)
    // {
    //     printf("%d, %p\n", i, insn[i].address);
    // }
    size_t i;
    if (insn_count > 0) {
        size_t offset = 10;
        // iterates over each disassembled instruction
        for (i = 0; i < insn_count && (insn[i].address >= text_section_start && insn[i].address < text_section_end); ++i) {
            printf("      %lx: ", insn[i].address);
            // prints the raw bytes of the instruction in hexadecimal format.
            for (size_t j = 0; j < insn[i].size; j++) {
                printf("%02x ", insn[i].bytes[j]);
            }
            for (size_t j = 0; j < offset-insn[i].size; j++) {
                printf("   ");
            }
            printf("\t%-7s %s\n", insn[i].mnemonic, insn[i].op_str);
        }
        if ((int)i < count) {
            printf("** the address is out of the range of the text section.\n");
        }
        cs_free(insn, insn_count);
    } else {
        fprintf(stderr, "** Failed to disassemble code!\n");
    }

    cs_close(&handle);
}

bool mdb_init(const char *path) {
    if (!get_entry_point(path, &entry_point, &text_section_start, &text_section_end)) {
        return false;
    }

    if (!target_launch(path)) {
        return false;
    }

    is_loaded = true;
    printf("** program '%s' loaded. entry point 0x%lx.\n", path, entry_point);
    mdb_si();

    // Stop at entry point and disassemble instructions
    // disassemble_instr(entry_point, 5);

    return true;
}

char** mdb_parse_cmd(char *line, int *argc) {
    char **argv = NULL;
    char *token = strtok(line, " \n");
    *argc = 0;

    while (token) {
        argv = realloc(argv, sizeof(char *) * (*argc + 1));
        argv[*argc] = token;
        (*argc)++;
        token = strtok(NULL, " \n");
    }

    return argv;
}

void mdb_si() {
    if (!target_step() || !target.run) {
        return;
    }

    disassemble_instr(cur_rip, 5);
    // disassemble_instr(target_get_rip(), 5);
}

void mdb_cont() {
    if (!target_cont() || !target.run) {
        return;
    }
    
    cur_rip = target_get_rip();
    // printf("[mdb_cont] cur_rip: %zx\n", (size_t) cur_rip);
    disassemble_instr(cur_rip, 5);
    // disassemble_instr(target_get_rip(), 5);
}

void mdb_info_reg() {
    struct user_regs_struct regs;

    // if (!target.run) {
    //     printf("The program is not being run.\n");
    //     return;
    // }

    // Retrieve register values
    if (ptrace(PTRACE_GETREGS, target.pid, NULL, &regs) == -1) {
        perror("ptrace");
        return;
    }

    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
}

void mdb_break(size_t addr) {
    target_set_breakpoint(addr);
}

void mdb_info_break() {
    if (target.bp_bitmap == 0xffff) {
        printf("** no breakpoints.\n");
        return;
    }

    // printf("Bitmap: ");
    // print_binary(target.bp_bitmap);
    // printf("\n");

    printf("Num\tAddress\n");
    // for (int i = 0; i < MAX_BP; ++i) {
    //     if (!(target.bp_bitmap & (1 << i))) {
    //         printf("%d\t0x%zx\n", target.breakpoints[i].id, target.breakpoints[i].addr);
    //     }
    // }
    int n;
    for (int id = 0; id < id_now; id++) {
        n = target.bp_id[id];
        if ( n < MAX_BP && !(target.bp_bitmap & (1 << n))) {
            printf("%d\t0x%zx\n", target.breakpoints[n].id, target.breakpoints[n].addr);
        }
    }

    // printf("Bitmap: ");
    // print_binary(target.bp_bitmap);
    // printf("\n");
}

void mdb_delete_bp(int id) {
    if (id < 0 || id >= MAX_ID) {
        printf("** breakpoint %d does not exist.\n", id);
        return;
    }

    int n = target.bp_id[id];

    // printf("Bitmap: ");
    // print_binary(target.bp_bitmap);
    // printf("\n");
    // printf("1<<n: ");
    // print_binary((1 << n));
    // printf("\n");

    if ( n < MAX_BP && !(target.bp_bitmap & (1 << n))) {
        target.bp_bitmap |= (1 << n);
        target.bp_id[id] = MAX_BP+1;
        swbp_unset(&target.breakpoints[n]);
        printf("** delete breakpoint %d.\n", id);
    }
    else {
        printf("** breakpoint %d does not exist.\n", id);
    }
}

void mdb_patch(size_t addr, size_t value, int len) {
    if (len != 1 && len != 2 && len != 4 && len != 8) {
        printf("** invalid length. Must be 1, 2, 4, or 8.\n");
        return;
    }

    // Check if the address has a breakpoint set
    bool was_breakpoint = false;
    struct bp_t *bp = NULL;
    if (target_find_bp(addr, &bp)) {
        was_breakpoint = true;
        swbp_unset(bp);
    }

    // Read the existing data at the address
    size_t data = ptrace(PTRACE_PEEKDATA, target.pid, (void *) addr, NULL);
    if (data == (size_t) -1) {
        perror("ptrace_peek");
        return;
    }

    // Update the data with the new value
    size_t mask = (1UL << (len * 8)) - 1;
    data = (data & ~mask) | (value & mask);

    // Write the updated data back to the target address
    int ret = ptrace(PTRACE_POKEDATA, target.pid, (void *) addr, data);
    if (ret == -1) {
        perror("ptrace_poke");
        return;
    }

    // Re-set the breakpoint if it was originally set
    if (was_breakpoint) {
        swbp_set(bp);
        bp->instr = (data & mask);
    }

    printf("** patch memory at address 0x%lx.\n", addr);
}

void mdb_syscall() {
    if (!target_syscall() || !target.run) {
        return;
    }
    
    cur_rip = target_get_rip();
    // if (target.hit_bp) cur_rip = target_get_rip();
    if (target.hit_bp) disassemble_instr(cur_rip, 5);
    // if (target.hit_bp) disassemble_instr(target_get_rip(), 5);
}




void mdb_match_cmd(int argc, char **argv) {
    if (argc == 0) {
        return;
    }

    if (!is_loaded && strcmp(argv[0], "load") != 0) {
        printf("** please load a program first.\n");
    } else if (strcmp(argv[0], "continue") == 0 || strcmp(argv[0], "c") == 0 || strcmp(argv[0], "cont") == 0) {
        mdb_cont();
    } else if (strcmp(argv[0], "step") == 0 || strcmp(argv[0], "s") == 0 || strcmp(argv[0], "si") == 0) {
        mdb_si();
    } else if (strcmp(argv[0], "load") == 0) {
        if (argc < 2) {
            printf("Usage: load [path to program]\n");
        } else {
            mdb_init(argv[1]);
        }
    } else if (strcmp(argv[0], "info") == 0 && strcmp(argv[1], "reg") == 0) {
        mdb_info_reg();
    } else if (strcmp(argv[0], "break") == 0) {
        if (argc < 2) {
            printf("Usage: break [hex address]\n");
        } else {
            size_t addr;
            sscanf(argv[1], "%lx", &addr);
            mdb_break(addr);
        }
    } else if (strcmp(argv[0], "info") == 0 && strcmp(argv[1], "break") == 0) {
        mdb_info_break();
    } else if (strcmp(argv[0], "exit") == 0) {
        target.run = false;
    } else if (strcmp(argv[0], "delete") == 0) {
        if (argc < 2) {
            printf("Usage: delete [id]\n");
        } else {
            int id;
            sscanf(argv[1], "%d", &id);
            mdb_delete_bp(id);
        }
    } else if (strcmp(argv[0], "patch") == 0) {
        if (argc < 4) {
            printf("Usage: patch [hex address] [hex value] [len]\n");
        } else {
            size_t addr, value;
            int len;
            sscanf(argv[1], "%lx", &addr);
            sscanf(argv[2], "%lx", &value);
            sscanf(argv[3], "%d", &len);
            mdb_patch(addr, value, len);
        }
    } else if (strcmp(argv[0], "syscall") == 0) {
        mdb_syscall();
    } else {
        printf("Unknown command: %s\n", argv[0]);
    }
}

void mdb_run() {
    char line[256]; // Make sure the buffer is large enough
    int argc;
    char **argv;

    while (target.run) {
        printf("(mdb) ");
        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }
        argv = mdb_parse_cmd(line, &argc);
        mdb_match_cmd(argc, argv);
        free(argv);
    }
}

void mdb_close() {
    return;
}