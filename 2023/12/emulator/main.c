/*
 *  ____ ___      .__
 * |    |   \____ |__| ____  ___________  ____
 * |    |   /    \|  |/ ___\/  _ \_  __ \/    \
 * |    |  /   |  \  \  \__(  <_> )  | \/   |  \
 * |______/|___|  /__|\___  >____/|__|  |___|  /
 *              \/        \/                 \/
 *
 * Flare on #12 Unicorn based emulator
 *
 * A Unicorn Emulator to use analyse Flare On #12 shellcode and retrieve the valid flag
 *
 * Tested on Intel and ARM macOS and Linux
 *
 * Created by reverser on 07/10/23.
 * (c) fG!, 2023 - reverser@put.as - https://reverse.put.as
 *
 * Copyright (c) 2023 Pedro Vilaça
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <unicorn/unicorn.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/stat.h>

// ripped from mach/thread_status.h
// define here to compile anywhere
typedef struct 
{
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;
    uint64_t rdi;
    uint64_t rsi;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t rflags;
    uint64_t cs;
    uint64_t fs;
    uint64_t gs;
} x86_thread_state64_t;

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

/* the addresses where we will install the code and stack space - since it's PIE code we can run it anywhere we want */
#define CODE_ADDRESS                0x0
#define CODE_SIZE                   2 * 1024 * 1024
#define STACK_ADDRESS               0xBFFF0000
#define STACK_SIZE                  2 * 1024 * 1024
#define DATA_ADDRESS                0x20000000
#define DATA_SIZE                   2 * 1024 * 1024

/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

static const unsigned char base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * base64_encode - Base64 encode
 * @src: Data to be encoded
 * @len: Length of the data to be encoded
 * @out_len: Pointer to output length variable, or %NULL if not used
 * Returns: Allocated buffer of out_len bytes of encoded data,
 * or %NULL on failure
 *
 * Caller is responsible for freeing the returned buffer. Returned buffer is
 * nul terminated to make it easier to use as a C string. The nul terminator is
 * not included in out_len.
 */
unsigned char * base64_encode(const unsigned char *src, size_t len,
                  size_t *out_len)
{
    unsigned char *out, *pos;
    const unsigned char *end, *in;
    size_t olen;
    int line_len;

    olen = len * 4 / 3 + 4; /* 3-byte blocks to 4-byte */
    olen += olen / 72; /* line feeds */
    olen++; /* nul termination */
    if (olen < len)
        return NULL; /* integer overflow */
    out = malloc(olen);
    if (out == NULL)
        return NULL;

    end = src + len;
    in = src;
    pos = out;
    line_len = 0;
    while (end - in >= 3) {
        *pos++ = base64_table[in[0] >> 2];
        *pos++ = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = base64_table[((in[1] & 0x0f) << 2) | (in[2] >> 6)];
        *pos++ = base64_table[in[2] & 0x3f];
        in += 3;
        line_len += 4;
        if (line_len >= 72) {
            *pos++ = '\n';
            line_len = 0;
        }
    }

    if (end - in) {
        *pos++ = base64_table[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = base64_table[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = base64_table[((in[0] & 0x03) << 4) |
                          (in[1] >> 4)];
            *pos++ = base64_table[(in[1] & 0x0f) << 2];
        }
        *pos++ = '=';
        line_len += 4;
    }

    if (line_len)
        *pos++ = '\n';

    *pos = '\0';
    if (out_len)
        *out_len = pos - out;
    return out;
}

// next functions are just debugging helpers to retrieve and print the registers

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
    
    state->rip = vals[0];
    state->rax = vals[1];
    state->rbx = vals[2];
    state->rbp = vals[3];
    state->rsp = vals[4];
    state->rdi = vals[5];
    state->rsi = vals[6];
    state->rdx = vals[7];
    state->rcx = vals[8];
    state->r8 = vals[9];
    state->r9 = vals[10];
    state->r10 = vals[11];
    state->r11 = vals[12];
    state->r12 = vals[13];
    state->r13 = vals[14];
    state->r14 = vals[15];
    state->r15 = vals[16];
    state->cs = vals[17];
    state->fs = vals[18];
    state->cs = vals[19];
    state->rflags = vals[20];    
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
    fprintf(stdout, REGISTER_COLOR "  RAX:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "RBX:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "RBP:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "RSP:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " EFLAGS_COLOR, thread_state.rax, thread_state.rbx, thread_state.rbp, thread_state.rsp);
    (thread_state.rflags >> 0xB) & 1 ? printf("O ") : printf("o ");
    (thread_state.rflags >> 0xA) & 1 ? printf("D ") : printf("d ");
    (thread_state.rflags >> 0x9) & 1 ? printf("I ") : printf("i ");
    (thread_state.rflags >> 0x8) & 1 ? printf("T ") : printf("t ");
    (thread_state.rflags >> 0x7) & 1 ? printf("S ") : printf("s ");
    (thread_state.rflags >> 0x6) & 1 ? printf("Z ") : printf("z ");
    (thread_state.rflags >> 0x4) & 1 ? printf("A ") : printf("a ");
    (thread_state.rflags >> 0x2) & 1 ? printf("P ") : printf("p ");
    (thread_state.rflags) & 1 ? printf("C ") : printf("c ");
    fprintf(stdout, "\n" ANSI_COLOR_RESET);
    OUTPUT_MSG(REGISTER_COLOR "  RDI:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "RSI:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "RDX:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "RCX:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "RIP:" ANSI_COLOR_RESET " 0x%016" PRIx64, thread_state.rdi, thread_state.rsi, thread_state.rdx, thread_state.rcx, thread_state.rip);
    OUTPUT_MSG(REGISTER_COLOR "  R8 :" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "R9 :" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "R10:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "R11:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "R12:" ANSI_COLOR_RESET " 0x%016" PRIx64, thread_state.r8, thread_state.r9, thread_state.r10, thread_state.r11, thread_state.r12);
    OUTPUT_MSG(REGISTER_COLOR "  R13:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "R14:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "R15:" ANSI_COLOR_RESET " 0x%016" PRIx64 "  " REGISTER_COLOR "EFLAGS:" ANSI_COLOR_RESET " 0x%016" PRIx64, thread_state.r13, thread_state.r14, thread_state.r15, thread_state.rflags);
    OUTPUT_MSG(SEPARATOR_COLOR "-----------------------------------------------------------------------------------------------------------------------------" ANSI_COLOR_RESET);
}

void print_stack(uc_engine *uc) {
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
        OUTPUT_MSG("0x%" PRIx64 " | %" PRIx64, rsp, stack_buf[i]);
        rsp += sizeof(rsp);
    }
}

/*
 * a simple helper function to map and set the initial stack and registers state
 */
int
map_stack_and_initial_registers(uc_engine *uc)
{
    uc_err err = UC_ERR_OK;
    /* data area */
    err = uc_mem_map(uc, DATA_ADDRESS, DATA_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to allocate Unicorn data memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    
    /* stack area */
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
    
    /* no need to set RIP because emulation will start on value set on uc_emu_start */
    uint64_t r_rsp = STACK_ADDRESS + STACK_SIZE/2;
    err = uc_reg_write(uc, UC_X86_REG_RSP, &r_rsp);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write initial RSP register: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    uint64_t r_rbp = r_rsp;
    err = uc_reg_write(uc, UC_X86_REG_RBP, &r_rbp);

    return 0;
}

/*
 * helper function to map whatever code we want at the configured address
 */
int
map_shellcode(uc_engine *uc, void *shellcode, size_t shellcode_size)
{
    uc_err err = UC_ERR_OK;

    /* allocate Unicorn code area */
    err = uc_mem_map(uc, CODE_ADDRESS, CODE_SIZE, UC_PROT_ALL);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to allocate Unicorn code memory area: %s.", uc_strerror(err));
        uc_close(uc);
        return -1;
    }
    /* map code */
    err = uc_mem_write(uc, CODE_ADDRESS, shellcode, shellcode_size);
    if (err != UC_ERR_OK)
    {
        ERROR_MSG("Failed to write shellcode to Unicorn memory: %s", uc_strerror(err));
        return -1;
    }

    // set the arguments to enter 0xA74 function
    
    // first copy the contents to the right memory locations
    // argv[1] is set at 0FC00h
    // argv[2] is set at 0FE00h
    uint64_t arg1_addr = 0xFC00;
    uint64_t arg2_addr = 0xFE00;
    // we don't really need to pad this with NUL bytes, it can be anything - the base64 values will be different but it will work
    char arg1[48] = "FLARE2023FLARE2023FLARE2023FLARE2023\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    size_t out_len = 0;
    unsigned char *encoded = base64_encode((const unsigned char*)arg1, sizeof(arg1), &out_len);
    printf("Base64: %s\n", encoded);
    // write the first argument to memory    
    err = uc_mem_write(uc, arg1_addr, arg1, sizeof(arg1));
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write arg1 to memory: %s", uc_strerror(err));
        uc_close(uc);
        return -1;
    }

    // CHANGE ME AND REBUILD CODE
    // this is the first iteration where we base64 the (padded) first argument version
    char *arg2 = (char*)encoded;
    
    // now run with the base64 output from above run - find it in "Encrypted Buffer contents" output
    // char arg2[] = "iDtM6z2gGr13aynmevMOeotPM+wjpHrIAGBR/2CXGw+7fQCqb+UojTBRFsZthAx4";
    
    // this is the result that above run gives and it's the right value we need to get the flag
    // if we run this code with this value we pass the verification function and the base64 output is the first base64 we tried
    // so the encryption loop is complete
    // char arg2[]= "zBYpTBUWJvf9MUH4KtcYv7sdUVUPcjOCiU5G5i63bb+LLBZsAmEk9YlNMplv5SiN";
    
    // write second argument to memory location
    err = uc_mem_write(uc, arg2_addr, arg2, strlen(arg2));
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write arg2 to memory.");
        uc_close(uc);
        return -1;
    }

    // now set the pointers in each argument register
    // Note: map_stack_and_initial_registers() clears all registers but it's called before this
    //       so we are ok when writing values to registers here
    uint64_t rdi = arg1_addr;
    uint64_t rsi = arg2_addr;
    err = uc_reg_write(uc, UC_X86_REG_RDI, &rdi);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write arg1 address to RDI: %s", uc_strerror(err));
        uc_close(uc);
        return -1;        
    }
    err = uc_reg_write(uc, UC_X86_REG_RSI, &rsi);
    if (err != UC_ERR_OK) {
        ERROR_MSG("Failed to write arg2 address to RSI: %s", uc_strerror(err));
        uc_close(uc);
        return -1;        
    }
    return 0;
}

/*
 * can be used to trace every instruction executed
 * used to poke around the different payload areas and dump internal state of salsa and other interesting functions
 */
void
unicorn_hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    uc_err err = UC_ERR_OK;
    uint64_t rax = 0;
    uint64_t rsi = 0;
    uint64_t rdi = 0;
    uint64_t rdx = 0;
    uint64_t rbp = 0;
    // DEBUG_MSG("Hit code at 0x%llx", address);
    
    // test if emulation is running ok with strlen(argv[2])
    if (address == 0xAC4) {
        if (uc_reg_read(uc, UC_X86_REG_RAX, &rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RAX");
            uc_emu_stop(uc);
        }
        OUTPUT_MSG("Argument 2 strlen return value is %" PRId64, rax);
        OUTPUT_MSG("-------------------------------");
        // uc_emu_stop(uc);
    }

    // the result of base64 decode call
    if (address == 0xAD8) {
        // the address of the decoded buffer
        if (uc_reg_read(uc, UC_X86_REG_RBP, &rbp) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RBP");
            uc_emu_stop(uc);
        }
        rbp -= 0x40;
        // the return value is the length of the buffer
        if (uc_reg_read(uc, UC_X86_REG_RAX, &rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RAX");
            uc_emu_stop(uc);
        }
        OUTPUT_MSG("[+] Decoded base64 buffer len is %" PRId64, rax);

        char buf[256] = {0};
        err = uc_mem_read(uc, rbp, buf, rax);
        if (err != UC_ERR_OK) {
            ERROR_MSG("Failed to read decode buffer: %s", uc_strerror(err));
            uc_emu_stop(uc);
        }
        OUTPUT_MSG("[+] Base64 Buffer contents:");
        for (int i = 0; i < rax; i++) {
            printf("%02x", (unsigned char)buf[i]);
        }
        printf("\n");
        OUTPUT_MSG("-------------------------------");
    }
    
    // test if we enter the decryption part aka base64 decoded buffer passed the check
    if (address == 0xAEC) {
        OUTPUT_MSG("[+] We arrived to the decryption call safely!");
        OUTPUT_MSG("-------------------------------");
    }

    // check the arguments being passed to decryption
    if (address == 0xAFE) {
        OUTPUT_MSG("Before call to decryption:");
        if (uc_reg_read(uc, UC_X86_REG_RSI, &rsi) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RSI");
            uc_emu_stop(uc);            
        }
        OUTPUT_MSG("Buf len RSI value is 0x%" PRIx64, rsi);
        if (uc_reg_read(uc, UC_X86_REG_RAX, &rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RAX");
            uc_emu_stop(uc);            
        }
        OUTPUT_MSG("[+] RAX value is 0x%" PRIx64, rax);

        if (uc_reg_read(uc, UC_X86_REG_RDX, &rdx) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RDX");
            uc_emu_stop(uc);            
        }
        OUTPUT_MSG("[+] RDX (key) value is 0x%" PRIx64, rdx);
    }

    // after decryption and before enter the 2nd argument validation
    // we can use it to dump the contents
    if (address == 0xB16) {
        if (uc_reg_read(uc, UC_X86_REG_RDI, &rdi) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RDI");
            uc_emu_stop(uc);            
        }
        OUTPUT_MSG("[+] RDI value is 0x%" PRIx64, rdi);

        uint64_t rsi = 0;
        if (uc_reg_read(uc, UC_X86_REG_RSI, &rsi) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RSI");
            uc_emu_stop(uc);            
        }
        OUTPUT_MSG("[+] RSI value is 0x%" PRIx64, rsi);
        char buf[256] = {0};
        err = uc_mem_read(uc, rsi, buf, sizeof(buf));
        if (err != UC_ERR_OK) {
            ERROR_MSG("Failed to read first argument buffer: %s", uc_strerror(err));
            uc_emu_stop(uc);
        }
        printf("[+] Encrypted Buffer contents:\n[+] Binary: ");
        for (int i = 0; i < 48; i++) {
            printf("%02x", (unsigned char)buf[i]);
        }
        printf("\n");

        size_t out_len = 0;
        unsigned char *encoded = base64_encode((const unsigned char*)buf, 48, &out_len);
        printf("[+] Base64: %s\n", encoded);

        OUTPUT_MSG("-------------------------------");
    }
    
    // this is the address after decryption validation where we can verify if 
    // the result is ok or not
    if (address == 0xB1B) {
        if (uc_reg_read(uc, UC_X86_REG_RAX, &rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RAX");
            uc_emu_stop(uc);            
        }
        // OUTPUT_MSG("Second argument validation value is 0x%llx", rax);
        if (rax == 0) {
            OUTPUT_MSG("[-] :( NOPE!");
        } else {
            OUTPUT_MSG("[+] YOU MADE IT!!!!!");
        }
    }

    // inside the salsa
    if (address == 0x555) {
        // check the init key
        // we need rbp
        if (uc_reg_read(uc, UC_X86_REG_RBP, &rbp) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RBP");
            uc_emu_stop(uc);
        }
        rbp -= 0xA0;
        uint32_t keybuf[16] = {0};
        OUTPUT_MSG("sizeof buf: %ld\n", sizeof(keybuf));
        err = uc_mem_read(uc, rbp, keybuf, sizeof(keybuf));
        if (err != UC_ERR_OK) {
            ERROR_MSG("Failed to read decode buffer: %s", uc_strerror(err));
            uc_emu_stop(uc);
        }
        OUTPUT_MSG("Salsa key stream contents:");
        for (int i = 0; i < sizeof(keybuf)/sizeof(*keybuf); i++) {
            printf("%x", (uint32_t)keybuf[i]);
        }
        printf("\n");

        // where the salsa buffer goes
        if (uc_reg_read(uc, UC_X86_REG_RAX, &rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RAX");
            uc_emu_stop(uc);            
        }
        OUTPUT_MSG("Second argument validation value is 0x%" PRIx64, rax);

        OUTPUT_MSG("-------------------------------");
    }

    // this is inside the decryption validation routine
    // when the values are compared so we can dump and verify what is going on
    if (address == 0x8E4) {
        if (uc_reg_read(uc, UC_X86_REG_RDX, &rdx) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RDX");
            uc_emu_stop(uc);            
        }
        if (uc_reg_read(uc, UC_X86_REG_RAX, &rax) != UC_ERR_OK) {
            ERROR_MSG("Failed to read RAX");
            uc_emu_stop(uc);            
        }
        printf("%" PRIx64 " vs %" PRIx64 "\n", rdx, rax);
    }

    // some internal salsa debugging output to verify the key buffer
#if 0
    if (address == 0x55A) {
        char keybuf[64] = {0};
        err = uc_mem_read(uc, rbp, keybuf, sizeof(keybuf));
        if (err != UC_ERR_OK) {
            ERROR_MSG("Failed to read decode buffer: %s", uc_strerror(err));
            uc_emu_stop(uc);
        }
        OUTPUT_MSG("Salsa Key Buffer contents:");
        for (int i = 0; i < sizeof(keybuf); i++) {
            printf("%x", (unsigned char)keybuf[i]);
        }
        printf("\n");
        OUTPUT_MSG("-------------------------------");
    }
#endif

    // stop emulation before encrypting again the function
    if (address == 0xB2B) {
        OUTPUT_MSG("[!] END OF THE LINE!");
        uc_emu_stop(uc);
    }
}

// hook to deal with any memory issues in case something goes beserk
bool
unicorn_hook_unmapped_mem(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
    uint64_t reg_eip = 0;
    if (uc_reg_read(uc, UC_X86_REG_RIP, &reg_eip) != UC_ERR_OK)
    {
        ERROR_MSG("Failed to read RIP");
        return false;
    }
    DEBUG_MSG("Memory exception at 0x%" PRIx64, reg_eip);
    DEBUG_MSG("Unmapped mem hit 0x%" PRIx64, address);
    
    print_x64_registers(uc);
    print_stack(uc);
    return false;
}

/*
 * the function responsible for emulation setup
 * it essentially sets the function parameters inside Unicorn, uses Unicorn to execute the code and recovers the result
 */
int
start_emulation(char *shellcode, size_t shellcode_size)
{
    OUTPUT_MSG("Let's start the partyyyyyyyyyy");
    /*
     * we reset everything for each string - we could probably optimize this
     * (load all the strings and add a stub to call the function or just not restart everything)
     * but why bother - computers are fast, I am lazy, and this is just peanuts code
     */
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
    
    OUTPUT_MSG("----------------------------------------------");
    DEBUG_MSG("Shellcode code area:");
    char shell_debug[64] = {0};
    uc_mem_read(uc, CODE_ADDRESS, shell_debug, 64);
    for (int i = 0; i < sizeof(shell_debug) ; i++) {
        printf("%02x ", (unsigned char)shell_debug[i]);
    }
    printf("\n");
    OUTPUT_MSG("----------------------------------------------");

    /* set Unicorn hooks */
    uc_hook trace_hook;
    if (uc_hook_add(uc, &trace_hook, UC_HOOK_CODE, unicorn_hook_code, NULL, 1, 0) != UC_ERR_OK) {
        ERROR_MSG("Failed to set hook");
    }
    uc_hook mem_hook;
    if (uc_hook_add(uc, &mem_hook, UC_HOOK_MEM_UNMAPPED, unicorn_hook_unmapped_mem, NULL, 1, 0) != UC_ERR_OK) {
        ERROR_MSG("Failed to set hook");
    }

    // some debugging help for initial development - not really required anymore
#if 0
    DEBUG_MSG("Initial register state:");
    print_x64_registers(uc);
#endif

    // start address is fg_03_verify_2nd_arg_0xA74
    uint64_t start_address = CODE_ADDRESS + 0xA74;
    err = uc_emu_start(uc, start_address, CODE_ADDRESS+0x2000, 0, 0);
    DEBUG_MSG("Execution return value: %d (%s)", err, uc_strerror(err));

    // more debugging to check the final register state 
    // we expect RAX == 1 when we get the right value
    // print_x64_registers(uc);
    
    // the end!
    uc_close(uc);
    return 0;
}

void
header(void)
{
    OUTPUT_MSG("___________________________");
    OUTPUT_MSG("< Flare On #12 2023 Rules! >");
    OUTPUT_MSG("---------------------------");
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
           "___________________________\n"
           "< Flare On #12 2023 Rules! >\n"
           "---------------------------\n"
           "     \\   ^__^\n"
           "      \\  (@@)\\_______\n"
           "         (__)\\       )\\/\\\n"
           "             ||----w |\n"
           "             ||     ||\n"
           " (c) fG!, 2023, All rights reserved.\n"
           " reverser@put.as - https://reverse.put.as\n"
           "---[ Usage: ]---\n"
           "%s -s filename\n"
           "-s: shellcode to emulate\n"
           "", name);
}

int read_file(char *path, char**buf, size_t *size) {
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
