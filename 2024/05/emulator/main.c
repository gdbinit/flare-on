/*
 *  ____ ___      .__
 * |    |   \____ |__| ____  ___________  ____
 * |    |   /    \|  |/ ___\/  _ \_  __ \/    \
 * |    |  /   |  \  \  \__(  <_> )  | \/   |  \
 * |______/|___|  /__|\___  >____/|__|  |___|  /
 *              \/        \/                 \/
 *
 * A Unicorn Emulator to dump the flag from Flare-On 2024 #5 shellcode
 *
 * Created by reverser on 29/09/24.
 * (c) fG!, 2024 - reverser@put.as - https://reverse.put.as
 *
 * Tested with macOS, might build in Linux :P
 *
 */

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <unicorn/unicorn.h>

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define REGISTER_COLOR  ANSI_COLOR_GREEN
#define SEPARATOR_COLOR ANSI_COLOR_BLUE
#define EFLAGS_COLOR    ANSI_COLOR_RED

#define ERROR_MSG(fmt, ...) fprintf(stderr, "[ERROR] " fmt " \n", ## __VA_ARGS__)
#define WARNING_MSG(fmt, ...) fprintf(stderr, "[WARNING] " fmt " \n", ## __VA_ARGS__)
#define OUTPUT_MSG(fmt, ...) fprintf(stdout, fmt " \n", ## __VA_ARGS__)
#define DEBUG_MSG(fmt, ...) fprintf(stdout, "[DEBUG] " fmt "\n", ## __VA_ARGS__)

// the addresses where we will install the code and stack space - since it's PIE code we can run it anywhere we want
#define CODE_ADDRESS    0x10000000
#define CODE_SIZE       2 * 1024 * 1024
#define STACK_ADDRESS   0xBFF00000
#define STACK_SIZE      10 * 1024 * 1024

// redefine this structure because depends on target build arch if we use the system includes
// plus it wasn't portable...
typedef struct x86_thread_state64 {
    uint64_t    __rax;
    uint64_t    __rbx;
    uint64_t    __rcx;
    uint64_t    __rdx;
    uint64_t    __rdi;
    uint64_t    __rsi;
    uint64_t    __rbp;
    uint64_t    __rsp;
    uint64_t    __r8;
    uint64_t    __r9;
    uint64_t    __r10;
    uint64_t    __r11;
    uint64_t    __r12;
    uint64_t    __r13;
    uint64_t    __r14;
    uint64_t    __r15;
    uint64_t    __rip;
    uint64_t    __rflags;
    uint64_t    __cs;
    uint64_t    __fs;
    uint64_t    __gs;
} x86_thread_state64_t;

int
get_x64_registers(uc_engine *uc, x86_thread_state64_t *state)
{
    if (uc == NULL || state == NULL) {
        ERROR_MSG("Invalid arguments.");
        return -1;
    }
    
    int x86_64_regs[] = {
        UC_X86_REG_RIP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSP,
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15, UC_X86_REG_CS, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_EFLAGS
    };
    uint64_t vals[sizeof(x86_64_regs)] = {0};
    void *ptrs[sizeof(x86_64_regs)] = {0};
    
    for (int i = 0; i < sizeof(x86_64_regs); i++) {
        ptrs[i] = &vals[i];
    }
    
    if (uc_reg_read_batch(uc, x86_64_regs, ptrs, sizeof(x86_64_regs)) != UC_ERR_OK) {
        ERROR_MSG("Failed to read x64 general registers.");
        return -1;
    }
    
    state->__rip = vals[0];
    state->__rax = vals[1];
    state->__rbx = vals[2];
    state->__rbp = vals[3];
    state->__rsp = vals[4];
    state->__rdi = vals[5];
    state->__rsi = vals[6];
    state->__rdx = vals[7];
    state->__rcx = vals[8];
    state->__r8  = vals[9];
    state->__r9  = vals[10];
    state->__r10 = vals[11];
    state->__r11 = vals[12];
    state->__r12 = vals[13];
    state->__r13 = vals[14];
    state->__r14 = vals[15];
    state->__r15 = vals[16];
    state->__cs  = vals[17];
    state->__fs  = vals[18];
    state->__cs  = vals[19];
    state->__rflags = vals[20];    
    return 0;
}

void
print_x64_registers(uc_engine *uc)
{
    x86_thread_state64_t thread_state = {0};
    if (get_x64_registers(uc, &thread_state) != 0) {
        ERROR_MSG("Can't retrieve x86_64 registers.");
        return;
    }
    OUTPUT_MSG(SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------[regs]" ANSI_COLOR_RESET);
    fprintf(stdout, REGISTER_COLOR "  RAX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RBX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RBP:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RSP:" ANSI_COLOR_RESET " 0x%016llx  " EFLAGS_COLOR, thread_state.__rax, thread_state.__rbx, thread_state.__rbp, thread_state.__rsp);
    (thread_state.__rflags >> 0xB) & 1 ? printf("O ") : printf("o ");
    (thread_state.__rflags >> 0xA) & 1 ? printf("D ") : printf("d ");
    (thread_state.__rflags >> 0x9) & 1 ? printf("I ") : printf("i ");
    (thread_state.__rflags >> 0x8) & 1 ? printf("T ") : printf("t ");
    (thread_state.__rflags >> 0x7) & 1 ? printf("S ") : printf("s ");
    (thread_state.__rflags >> 0x6) & 1 ? printf("Z ") : printf("z ");
    (thread_state.__rflags >> 0x4) & 1 ? printf("A ") : printf("a ");
    (thread_state.__rflags >> 0x2) & 1 ? printf("P ") : printf("p ");
    (thread_state.__rflags) & 1 ? printf("C ") : printf("c ");
    fprintf(stdout, "\n" ANSI_COLOR_RESET);
    OUTPUT_MSG(REGISTER_COLOR "  RDI:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RSI:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RDX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RCX:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "RIP:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__rdi, thread_state.__rsi, thread_state.__rdx, thread_state.__rcx, thread_state.__rip);
    OUTPUT_MSG(REGISTER_COLOR "  R8 :" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R9 :" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R10:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R11:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R12:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__r8, thread_state.__r9, thread_state.__r10, thread_state.__r11, thread_state.__r12);
    OUTPUT_MSG(REGISTER_COLOR "  R13:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R14:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "R15:" ANSI_COLOR_RESET " 0x%016llx  " REGISTER_COLOR "EFLAGS:" ANSI_COLOR_RESET " 0x%016llx", thread_state.__r13, thread_state.__r14, thread_state.__r15, thread_state.__rflags);
    OUTPUT_MSG(SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------------" ANSI_COLOR_RESET);
}

void 
print_stack(uc_engine *uc) 
{
    uint64_t rsp = 0;
    uc_err err = 0;
    err = uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to read stack register.");
        return;
    }
    uint64_t stack_buf[16] = {0};
    for (int i = 0; i < 16; i++) {
        err = uc_mem_read(uc, rsp, &stack_buf[i], sizeof(uint64_t));
        OUTPUT_MSG("0x%llx | %llx", rsp, stack_buf[i]);
        rsp += sizeof(rsp);
    }
}

// a simple helper function to map and set the initial stack and registers state
int
map_stack_and_initial_registers(uc_engine *uc)
{
    uc_err err = UC_ERR_OK;    
    // map stack area
    err = uc_mem_map(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to allocate Unicorn stack memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }

    unsigned char *zero = calloc(1, STACK_SIZE);
    err = uc_mem_write(uc, STACK_ADDRESS, zero, STACK_SIZE);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to zero stack memory.");
        free(zero);
        uc_close(uc);
        return -1;
    }
    free(zero);

    int x86_64_regs[] = {
        UC_X86_REG_RIP,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP,
        UC_X86_REG_RDI, UC_X86_REG_RSI, UC_X86_REG_RDX, UC_X86_REG_RCX,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
        UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
        UC_X86_REG_R15, UC_X86_REG_CS, UC_X86_REG_FS, UC_X86_REG_GS, UC_X86_REG_EFLAGS
    };
    uint64_t vals[sizeof(x86_64_regs)] = {0};
    void *ptrs[sizeof(x86_64_regs)] = {0};
    for (int i = 0; i < sizeof(x86_64_regs); i++) {
        ptrs[i] = &vals[i];
    }
    err = uc_reg_write_batch(uc, x86_64_regs, ptrs, sizeof(x86_64_regs));
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to initialize all registers: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    // set initial stack pointer halfway the available stack space
    uint64_t r_rsp = STACK_ADDRESS + STACK_SIZE / 2;
    err = uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write initial RSP register: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    DEBUG_MSG("Wrote initial RSP as 0x%llx", r_rsp);
    err = uc_reg_write(uc, UC_X86_REG_RBP, &r_rsp);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write initial RBP register: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    return 0;
}

// helper function to map whatever code we want at the configured address
int
map_shellcode(uc_engine *uc, void *shellcode, size_t shellcode_size)
{
    uc_err err = UC_ERR_OK;
    // allocate Unicorn code area
    err = uc_mem_map(uc, CODE_ADDRESS, CODE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to allocate Unicorn code memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    // map the shellcode
    err = uc_mem_write(uc, CODE_ADDRESS, shellcode, shellcode_size);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write shellcode to Unicorn memory: %s", uc_strerror(err));
        return -1;
    }
    // if we need we can patch code memory here :-)

    DEBUG_MSG("Shellcode code area:");
    char shell_debug[64] = {0};
    uc_mem_read(uc, CODE_ADDRESS, shell_debug, 64);
    for (int i = 0; i < sizeof(shell_debug) ; i++) {
        if (i && i % 16 == 0) { printf("\n"); };
        printf("%02x ", (unsigned char)shell_debug[i]);
    }
    printf("\n");

    return 0;
}

// the code hook can be used to trace every instruction executed
void
unicorn_hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    // DEBUG_MSG("Hit code at 0x%llx", address);
    // just use it to detect when we reach the end
    // we could have stopped everything after the first sendto
    if (address == CODE_ADDRESS + 0xf1f) {
        DEBUG_MSG("End of line!");
        uc_emu_stop(uc);
    }
}

// the hook we use to detect when unmapped memory is hit
// very useful when developing
bool
unicorn_hook_unmapped_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    uint64_t reg_eip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &reg_eip) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read RIP");
        return false;
    }
    DEBUG_MSG("Memory exception at 0x%llx", reg_eip);
    DEBUG_MSG("Unmapped mem hit 0x%llx", address);
    print_x64_registers(uc);
    print_stack(uc);
    return false;
}

// this is the syscall hook
// we use it to inject the right data into memory when necessary
// and to dump the decrypted data before it is "sent" to the socket
bool 
unicorn_hook_syscall(uc_engine *uc, void *user_data)
{
    // OUTPUT_MSG("Syscall hook hit");
    x86_thread_state64_t ts = {0};
    
    if (get_x64_registers(uc, &ts) != 0) {
        ERROR_MSG("Can't retrieve x86_64 registers.");
        return false;
    }
    uc_err err = UC_ERR_OK;
    uint64_t reg_rax = 0;
    if (uc_reg_read(uc, UC_X86_REG_RAX, &reg_rax) != UC_ERR_OK) {
        ERROR_MSG("Failed to read RAX");
        return false;
    }
    // find out which syscall just hit the hook
    switch (reg_rax) {
    case 0:
        DEBUG_MSG("read syscall");
        DEBUG_MSG("Arguments => fd: 0x%llx buf: 0x%llx count: %llu", ts.__rdi, ts.__rsi, ts.__rdx);
        // the buffer data we extracted from the core dump
        // we write it to memory to simulate a succesful read call
        char data[] = {0xa9,0xf6,0x34,0x08,0x42,0x2a,0x9e,0x1c,0x0c,0x03,0xa8,0x08,0x94,0x70,0xbb,0x8d,0xaa,0xdc,0x6d,0x7b,0x24,0xff,0x7f,0x24,0x7c,0xda,0x83,0x9e,0x92,0xf7,0x07,0x1d,0x02,0x63,0x90,0x2e,0xc1,0x58};
        // this is the address of the buffer - we extract it from dumping the arguments above
        if (ts.__rsi == 0xc03fee80) {
            err = uc_mem_write(uc, 0xc03fee80, data, sizeof(data));
            if (err != UC_ERR_OK) {
                ERROR_MSG("Failed to write data memory.");
                return false;            
            }
        }
        OUTPUT_MSG("----------------------------------------------");
        break;
    case 2:
        DEBUG_MSG("open syscall");
        DEBUG_MSG("Arguments => filename: 0x%llx flags: %llu mode: %llu", ts.__rdi, ts.__rsi, ts.__rdx);
        // read contents
        // this will return nothing since we didn't populate memory
        // shellcode doesn't check return values so we don't care
        char filename[1024] = {0};
        if (uc_mem_read(uc, ts.__rdi, filename, 1024) != UC_ERR_OK) {
            ERROR_MSG("Failed to read filename pointer.");
        }
        DEBUG_MSG("Open filename: %s", filename);
        OUTPUT_MSG("----------------------------------------------");
        break;
    case 3:
        DEBUG_MSG("close syscall");
        OUTPUT_MSG("----------------------------------------------");
        break;
    case 41:
        DEBUG_MSG("socket syscall");
        // AF_INET, SOCK_STREAM, TCP
        DEBUG_MSG("Arguments => domain: %llu type: %llu proto: %llu", ts.__rdi, ts.__rsi, ts.__rdx);
        OUTPUT_MSG("----------------------------------------------");
        break;
    case 42: // 0x2a
        DEBUG_MSG("connect syscall");
        DEBUG_MSG("Arguments => sockfd: %llu addr: 0x%llx addrlen: %llu", ts.__rdi, ts.__rsi, ts.__rdx);
        // ts.__rsi pointer
        struct sockaddr_in server_addr;
        if (uc_mem_read(uc, ts.__rsi, &server_addr, sizeof(server_addr)) != UC_ERR_OK) {
            ERROR_MSG("Failed to read addr pointer.");
        }
        char ip_str[INET_ADDRSTRLEN] = {0};
        // extract the ip address
        inet_ntop(AF_INET, &server_addr.sin_addr, ip_str, sizeof(ip_str));
        DEBUG_MSG("IP Address integer: 0x%x", server_addr.sin_addr.s_addr);
        DEBUG_MSG("IP Address: %s", ip_str);
        DEBUG_MSG("Port: %d", ntohs(server_addr.sin_port));
        DEBUG_MSG("Family: %d", server_addr.sin_family);
        OUTPUT_MSG("----------------------------------------------");
        break;
    case 44: // 0x2c
        DEBUG_MSG("sendto syscall");
        DEBUG_MSG("Arguments => sockfd: %llu buf: 0x%llx len: %llu flags: %llu, dst_addr: 0x%llx addrlen: 0x%llx", ts.__rdi, ts.__rsi, ts.__rdx, ts.__r10, ts.__r8, ts.__r9);
        // read the data that is being sent back to the C2
        // this should contain the decrypted data, which is the flag!
        // find the address via checking the arguments above
        char decrypted[1024] = {0};
        if (uc_mem_read(uc, 0xc03fee80, decrypted, 1024) != UC_ERR_OK) {
            ERROR_MSG("Failed to read filename pointer.");
        }
        printf("Contents: %s", decrypted);
        OUTPUT_MSG("----------------------------------------------");
        break;
    case 45: // 0x2d
        DEBUG_MSG("recvfrom syscall");
        DEBUG_MSG("Arguments => sockfd: %llu buf: 0x%llx len: %llu flags: %llu, src_addr: 0x%llx addrlen: 0x%llx", ts.__rdi, ts.__rsi, ts.__rdx, ts.__r10, ts.__r8, ts.__r9);
        // the data extracted from coredump
        // we inject it into memory
        // find the right locations by checking the arguments above
        char key[] = {0x8d,0xec,0x91,0x12,0xeb,0x76,0x0e,0xda,0x7c,0x7d,0x87,0xa4,0x43,0x27,0x1c,0x35,0xd9,0xe0,0xcb,0x87,0x89,0x93,0xb4,0xd9,0x04,0xae,0xf9,0x34,0xfa,0x21,0x66,0xd7};
        char nonce[] = {0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
        // write the key
        if (ts.__rsi == 0xc03fed50) {
            err = uc_mem_write(uc, 0xc03fed50, key, sizeof(key));
            if (err != UC_ERR_OK) {
                ERROR_MSG("Failed to write key memory.");
                return false;
            }
        }
        // write the nonce
        if (ts.__rsi == 0xc03fed70) {
            err = uc_mem_write(uc, 0xc03fed70, nonce, sizeof(nonce));
            if (err != UC_ERR_OK) {
                ERROR_MSG("Failed to write nonce memory.");
                return false;            
            }
        }
        OUTPUT_MSG("----------------------------------------------");
        break;
    case 48:
        DEBUG_MSG("shutdown syscall");
        OUTPUT_MSG("----------------------------------------------");
        break;
    default:
        DEBUG_MSG("Unknown syscall: %lld", reg_rax);
        break;
    }
    return true;
}

int
start_emulation(char *shellcode, size_t shellcode_size)
{
    OUTPUT_MSG("Let's start the partyyyyyyyyyy");
    uc_engine *uc = NULL;        
    uc_err err = UC_ERR_OK;
    err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to open Unicorn: %s.", uc_strerror(err));
        return -1;
    }
    if (map_stack_and_initial_registers(uc) != 0) {
        ERROR_MSG("Failed to map initial stack and registers.");
        uc_close(uc);
        return -1;
    }
    if (map_shellcode(uc, shellcode, shellcode_size) != 0) {
        ERROR_MSG("Failed to map shellcode.");
        uc_close(uc);
        return -1;
    }

    // !!! this shellcode has no arguments !!!

    // code trace hook - can be useful when developing or to step a stop
    uc_hook trace_hook;
    if (uc_hook_add(uc, &trace_hook, UC_HOOK_CODE, unicorn_hook_code, NULL, 1, 0) != UC_ERR_OK) {
        ERROR_MSG("Failed to set code hook");
    }
    // hook to detect unmapped memory issues - useful when developing
    uc_hook mem_hook;
    if (uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_UNMAPPED, unicorn_hook_unmapped_mem, NULL, 1, 0) != UC_ERR_OK) {
        ERROR_MSG("Failed to set memory hook");
    }
    // the syscall hook that we use to inject data and dump the results
    uc_hook syscall_hook;
    if (uc_hook_add(uc, &syscall_hook, UC_HOOK_INSN, unicorn_hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL) != UC_ERR_OK) {
        ERROR_MSG("Failed to set syscall hook");
    }

    DEBUG_MSG("Initial register state:");
    print_x64_registers(uc);
    // print_stack(uc);

    // start the party :-]
    uint64_t start_address = CODE_ADDRESS;
    err = uc_emu_start(uc, start_address, start_address + shellcode_size, 0, 0);
    DEBUG_MSG("Execution return value: %d (%s)", err, uc_strerror(err));    
    uc_close(uc);
    return 0;
}

int 
read_file(char *path, char**buf, size_t *size) 
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        ERROR_MSG("Failed to open %s.", path);
        return 1;
    }
    struct stat fs = {0};
    if (fstat(fd, &fs) < 0) {
        ERROR_MSG("Failed to fstat %s.", path);
        close(fd);
        return 1;
    }
    *buf = calloc(1, fs.st_size);
    if (*buf == NULL) {
        ERROR_MSG("Malloc failure.");
        close(fd);
        return 1;
    }
    if (read(fd, *buf, fs.st_size) != fs.st_size) {
        ERROR_MSG("Failed to read %s.", path);
        free(*buf);
        *buf = NULL;
        close(fd);
        return 1;
    }
    *size = fs.st_size;
    close(fd);
    return 0;
}

void
header(void)
{
    OUTPUT_MSG("________________________");
    OUTPUT_MSG("< Flare-On 2024 Rules! >");
    OUTPUT_MSG("------------------------");
    OUTPUT_MSG("     \\   ^__^");
    OUTPUT_MSG("      \\  (@@)\\_______");
    OUTPUT_MSG("         (__)\\       )\\/\\");
    OUTPUT_MSG("             ||----w |");
    OUTPUT_MSG("             ||     ||");
}

void
help(const char *name)
{
    printf(
           "________________________\n"
           "< Flare-On 2024 Rules! >\n"
           "------------------------\n"
           "     \\   ^__^\n"
           "      \\  (@@)\\_______\n"
           "         (__)\\       )\\/\\\n"
           "             ||----w |\n"
           "             ||     ||\n"
           " (c) fG!, 2024, All rights reserved.\n"
           " reverser@put.as - https://reverse.put.as\n"
           "---[ Usage: ]---\n"
           "%s -s filename\n"
           "-s: shellcode dump to emulate\n"
           "", name);
}

int
main(int argc, const char * argv[])
{
    // required structure for long options
    static struct option long_options[]={
        { "verbose", required_argument, NULL, 'v' },
        { "shellcode", required_argument, NULL, 's' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int option_index = 0;
    int c = 0;

    char *shellcodefile = NULL;
    
    // process command line options
    while ((c = getopt_long (argc, (char * const*)argv, "hvs:", long_options, &option_index)) != -1)
    {
        switch (c)
        {
            case 's':
                shellcodefile = optarg;
                break;
            case 'h':
                help(argv[0]);
                exit(0);
            default:
                break;
        }
    }
    
    if (shellcodefile == NULL) {
        ERROR_MSG("Missing argument!");
        help(argv[0]);
        exit(1);
    }

    char *shellcode = NULL;
    size_t shellcode_size = 0;

    if (read_file(shellcodefile, &shellcode, &shellcode_size)) {
        exit(1);
    }

    header();
    start_emulation(shellcode, shellcode_size);

    return 0;
}
