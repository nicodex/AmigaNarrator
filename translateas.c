/* clang-format off */
/*
SPDX-FileCopyrightText: 2024 Nico Bendlin <nico @nicode.net>

SPDX-License-Identifier: GPL-3.0-or-later

 */
/* clang-format on */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Defined with absolute path in Makefile,
 * but can somehow get lost/forgotten... */
#ifndef MUSASHI_CNF
#define MUSASHI_CNF "../cpuconf.h"
#endif
#include "Musashi/m68k.h"

/*
 * Check MUSASHI_CNF options.
 *
 * To avoid manually disassembling and handling all executed instructions, the
 * emulation is based on handling only the PC changes (jumps and branches) and
 * the distinction between code and data fetches. Changing this Musashi options
 * would require a completely different implementation of the emulation logic.
 * CPU prefetch emulation should be disabled (not required by the library code,
 * and it would make the handling of the code fetches far more complicated).
 * The emulation is single-module, single-process and single-threaded anyway,
 * there is no need to make things more complicated than absolutely necessary,
 * we do not want to emulate a running AmigaOS. That is also the reason why
 * only the AmigaOS 1.3 variant of the Translator V42 library is supported
 * (v33_translator.library does not use the locale.library for error strings).
 */
#if (M68K_SEPARATE_READS != OPT_ON)
#error "TranslateAs requires separate reads for emulation."
#endif
#if (M68K_MONITOR_PC != OPT_ON)
#error "TranslateAs requires PC changed callbacks for emulation."
#endif
#if (M68K_EMULATE_PREFETCH != OPT_OFF)
#error "TranslateAs emulation does not support enabled prefetch."
#endif

enum { PROGRAM_VERSION_MAJOR = 0, PROGRAM_VERSION_MINOR = 0 };
static char const program_name[] = "translateas";
static char const opt_accent_default[] = ""; /* empty = library default */
static char const opt_lib_path_default[] = "Libs/v33_translator.library";
static char const opt_accent_dir_default[] = "Accents/";
static char const *accent_dir = opt_accent_dir_default;

static enum log_level {
  LOG_NONE = -1,
  LOG_FATAL,
  LOG_ERROR,
  LOG_WARN,
  LOG_INFO,
  LOG_DEBUG,
  LOG_TRACE
} log_level = LOG_INFO;

int main(int, char **);
static void print_help(void);
static void print_version(void);
static int translate(char const *, char const *, char const *);

/****************************************************************************
 * base types
 */

typedef unsigned int m68k_addr_t;
typedef unsigned char m68k_byte_t;
typedef unsigned short m68k_word_t;
typedef unsigned int m68k_long_t;
typedef m68k_long_t m68k_bptr_t;

#define M68K_ADDR_C(c) c##U
#define M68K_LONG_C(c) c##U
#define M68K_BPTR_C(c) c##U

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#define ENUM_TYPE_DECL(t) : t
#else
#define ENUM_TYPE_DECL(t)
#endif

enum ENUM_TYPE_DECL(m68k_addr_t) { M68K_ADDR_NULL = 0 };
enum ENUM_TYPE_DECL(m68k_bptr_t) { M68K_BPTR_NULL = 0 };

#define PRIM68KxBYTE "0x%.2X"
#define PRIM68KxWORD "0x%.4X"
#define PRIM68KxLONG "0x%.8X"
#define PRIM68KxADDR "$%.6X"
#define PRIM68KxBPTR "^%.6X"
#define PRIM68KxSIZE "0x%.4X"
#define PRIM68KxOFFS "%.4X"
/* LVO quick search in <https://d0.se/autodocs> */
#define PRIM68KxLVO "-$%x"

/* BCPL pointer conversion */

#define BADDR(bptr) (m68k_addr_t)((m68k_bptr_t)(bptr) << 2)
#define MKBADDR(addr) (m68k_bptr_t)((m68k_addr_t)(addr) >> 2)

/* big-endian memory access and twos-complement conversion */

static m68k_long_t m68k_get_word(const m68k_byte_t memory[2]) {
  return (((m68k_long_t)(memory[0] & 0xFFU) << 0x08U) |
          ((m68k_long_t)(memory[1] & 0xFFU) << 0x00U));
}

static void m68k_set_word(m68k_byte_t memory[2], m68k_long_t value) {
  memory[0] = (m68k_byte_t)((value >> 0x08U) & 0xFFU);
  memory[1] = (m68k_byte_t)((value >> 0x00U) & 0xFFU);
}

static signed m68k_word_to_signed(m68k_long_t value) {
  return !(value & 0x8000U) ? (signed)(value & 0x7FFFU) : -(signed)((~value & 0x7FFFU) + 0x0001U);
}

static m68k_long_t m68k_get_long(const m68k_byte_t memory[4]) {
  return (
      ((m68k_long_t)(memory[0] & 0xFFU) << 0x18U) | ((m68k_long_t)(memory[1] & 0xFFU) << 0x10U) |
      ((m68k_long_t)(memory[2] & 0xFFU) << 0x08U) | ((m68k_long_t)(memory[3] & 0xFFU) << 0x00U));
}
static void m68k_set_long(m68k_byte_t memory[4], m68k_long_t value) {
  memory[0] = (m68k_byte_t)((value >> 0x18U) & 0xFFU);
  memory[1] = (m68k_byte_t)((value >> 0x10U) & 0xFFU);
  memory[2] = (m68k_byte_t)((value >> 0x08U) & 0xFFU);
  memory[3] = (m68k_byte_t)((value >> 0x00U) & 0xFFU);
}

static signed m68k_long_to_signed(m68k_long_t value) {
  /* NOTE: -0x800000000 == 0x80000000 */
  return !(value & M68K_LONG_C(0x80000000))
             ? (signed)(value & M68K_LONG_C(0x7FFFFFFF))
             : -(signed)((~value & M68K_LONG_C(0x7FFFFFFF)) + M68K_LONG_C(0x00000001));
}

/****************************************************************************
 * logging
 */

static char const *get_log_level_name(enum log_level level) {
  static char const *const level_name[LOG_TRACE - LOG_FATAL + 1] = {"FATAL", "ERROR", "WARN",
                                                                    "INFO",  "DEBUG", "TRACE"};
  if ((LOG_FATAL <= level) && (level <= LOG_TRACE)) {
    return level_name[level - LOG_FATAL];
  }
  if (level <= LOG_NONE) {
    return "NONE";
  }
  return level_name[LOG_TRACE - LOG_FATAL];
}

static void log_vprintf(enum log_level level, char const *format, va_list args) {
  if (level <= log_level) {
    vfprintf(stderr, format, args);
  }
}

static void log_printf(enum log_level level, char const *format, ...) {
  va_list args;
  va_start(args, format);
  log_vprintf(level, format, args);
  va_end(args);
}

/****************************************************************************
 * memory mapping
 */

enum ENUM_TYPE_DECL(m68k_addr_t) {
  /* ColdStart initial SP, STACK_RAM_TOP */
  ZERO_LOCATION = M68K_ADDR_C(0x000000),
  /* ColdStart initial PC, EXEC_LIB_BASE, freeze/return from emulation */
  ABS_EXEC_BASE = M68K_ADDR_C(0x000004),

  /* stack_ram[] */
  STACK_RAM_END = M68K_ADDR_C(0x010000),
  STACK_RAM_TOP = M68K_ADDR_C(0x020000),

  /* loadable module segments */
  LOAD_RAM_BASE = M68K_ADDR_C(0x100000),
  LOAD_RAM_END = M68K_ADDR_C(0x200000),
  /* dynamic memory allocations */
  FAST_RAM_BASE = LOAD_RAM_END,
  FAST_RAM_END = M68K_ADDR_C(0xA00000),

  FAKE_LIB_BASE = M68K_ADDR_C(0xE00000),
  /* exec.library */
  EXEC_LIB_LVO = FAKE_LIB_BASE + 0x0006U, /* align (1 * 6) */
  EXEC_LIB_BASE = EXEC_LIB_LVO + 0x0336U, /* LVO_execPrivate15 (137 * 6) */
  EXEC_LIB_END = EXEC_LIB_BASE + 0x0278U, /* ExecBase.ex_MemHandler */
  /* dos.library */
  DOS_LIB_LVO = EXEC_LIB_END,
  DOS_LIB_BASE = DOS_LIB_LVO + 0x03E4U, /* LVO_SetOwner (166 * 6) */
  DOS_LIB_END = DOS_LIB_BASE + 0x0046U, /* DosLibrary.dl_IntuitionBase */
  /* graphics.library */
  GRAPHICS_LIB_LVO = DOS_LIB_END + 0x0002U,       /* align to ULONG */
  GRAPHICS_LIB_BASE = GRAPHICS_LIB_LVO + 0x0420U, /* LVO_WriteChunkyPixels (176 * 6) */
  GRAPHICS_LIB_END = GRAPHICS_LIB_BASE + 0x0220U, /* GfxBase.HWEmul */
  /* intuition.library */
  INTUITION_LIB_LVO = GRAPHICS_LIB_END,
  INTUITION_LIB_BASE = INTUITION_LIB_LVO + 0x033CU, /* LVO_HelpControl (138 * 6) */
  INTUITION_LIB_END = INTUITION_LIB_BASE + 0x0050U, /* IntuitionBase.Micros */
  FAKE_LIB_END = INTUITION_LIB_END,

  /* struct Process * FindTask(NULL) */
  FAKE_TASK_BASE = M68K_ADDR_C(0xE10000),
  FAKE_TASK_END = FAKE_TASK_BASE + 0x00E4, /* Process.pr_CES */

  /* struct FileHandle *, only one opened file supported */
  FAKE_FILE_HANDLE = M68K_ADDR_C(0xE20000),

  /* struct TextFont * GfxBase.DefaultFont */
  FAKE_DEFAULT_FONT = M68K_ADDR_C(0xE30000),

  /* mapped to input buffer string (requires 32-bit CPU emulation = 68020+) */
  INPUT_STRING_BASE = M68K_ADDR_C(0x01000000)
};

static m68k_byte_t stack_ram[STACK_RAM_TOP - STACK_RAM_END] /* = {0} */;

static m68k_byte_t *access_stack_ram(m68k_addr_t address, m68k_long_t size) {
  if ((STACK_RAM_END <= address) && (address <= STACK_RAM_TOP - size)) {
    return stack_ram + (address - STACK_RAM_END);
  }
  return NULL;
}

static m68k_byte_t *load_ram /* = NULL */;
static m68k_long_t load_ram_size /* = 0 */;

static m68k_byte_t *access_load_ram(m68k_addr_t address, m68k_long_t size) {
  if ((address >= LOAD_RAM_BASE) && (address <= LOAD_RAM_BASE + load_ram_size - size)) {
    return load_ram + (address - LOAD_RAM_BASE);
  }
  return NULL;
}

static void log_fast_ram(enum log_level level, char const *format, ...) {
  va_list args;
  log_printf(level, "fast_ram: ");
  va_start(args, format);
  log_vprintf(level, format, args);
  va_end(args);
}

struct fast_mem_block {
  /* code assumes that the list is sorted by virtual address
   * to allow easier reuse of freed virtual memory blocks */
  struct fast_mem_block *next;
  m68k_addr_t addr;
  m68k_long_t size;
  /* m68k_byte_t data[size]; */
};

static struct fast_mem_block *fast_mem_head /* = NULL */;

static m68k_byte_t *get_fast_mem_block_data(struct fast_mem_block *block) {
  return !block ? NULL : (m68k_byte_t *)(block + 1);
}

static struct fast_mem_block *find_fast_mem_block(m68k_addr_t address) {
  struct fast_mem_block *block;
  for (block = fast_mem_head; block && (block->addr <= address); block = block->next) {
    /* excluding the end (might be next virtual memory block data) */
    if ((block->addr <= address) && (address < (block->addr + block->size))) {
      return block;
    }
  }
  log_fast_ram(LOG_WARN, "no block found for " PRIM68KxADDR "\n", address);
  return NULL;
}

/* note that this function calls exit() on failure and never returns NULL */
static struct fast_mem_block *alloc_fast_mem_block(m68k_long_t size) {
  if (size > (FAST_RAM_END - FAST_RAM_BASE)) {
    log_fast_ram(LOG_FATAL, "RAM space too small\n");
    exit(EXIT_FAILURE);
  } else {
    m68k_long_t const data_size =
        !size ? sizeof(m68k_long_t) : ((size + M68K_LONG_C(0x00000003)) & M68K_LONG_C(0xFFFFFFFC));
    struct fast_mem_block *const new_block =
        calloc(sizeof(struct fast_mem_block) + data_size, sizeof(m68k_byte_t));
    if (!new_block) {
      log_fast_ram(LOG_FATAL, "out of host memory\n");
      exit(EXIT_FAILURE);
    } else {
      struct fast_mem_block *prev_block = fast_mem_head;
      new_block->size = data_size;
      /* empty list or free space before current head */
      if (!prev_block || (FAST_RAM_BASE + data_size <= prev_block->addr)) {
        new_block->addr = FAST_RAM_BASE;
        new_block->next = prev_block;
        fast_mem_head = new_block;
      } else {
        /* find first gap that is large enough */
        for (; prev_block->next; prev_block = prev_block->next) {
          if (data_size <= prev_block->next->addr - prev_block->addr - prev_block->size) {
            break;
          }
        }
        new_block->addr = prev_block->addr + prev_block->size;
        /* We could allow more, since we are neither emulating real
         * Amiga hardware, nor the AmigaOS memory mapping, but...
         * "8 MB Zorro I/II RAM ought to be enough for anybody" ;-) */
        if (new_block->addr + new_block->size > FAST_RAM_END) {
          log_fast_ram(LOG_FATAL, "out of memory\n");
          exit(EXIT_FAILURE);
        }
        new_block->next = prev_block->next;
        prev_block->next = new_block;
        log_fast_ram(LOG_TRACE, "alloc " PRIM68KxADDR "[%d]\n", new_block->addr,
                     m68k_long_to_signed(new_block->size));
      }
      return new_block;
    }
  }
}

static m68k_addr_t alloc_fast_mem_string(char const *str) {
  m68k_long_t const len = strlen(str);
  struct fast_mem_block *const block = alloc_fast_mem_block(len + sizeof(char));
  if (len) {
    memcpy(get_fast_mem_block_data(block), str, len);
  }
  return block->addr;
}

static void free_fast_mem(m68k_addr_t address) {
  /* special handling for the head */
  if (fast_mem_head && (fast_mem_head->addr == address)) {
    struct fast_mem_block *const block = fast_mem_head;
    fast_mem_head = block->next;
    log_fast_ram(LOG_TRACE, "freed " PRIM68KxADDR "[%d]\n", block->addr,
                 m68k_long_to_signed(block->size));
    free(block);
  } else {
    struct fast_mem_block *prev_block;
    for (prev_block = fast_mem_head; prev_block && prev_block->next;
         prev_block = prev_block->next) {
      if (prev_block->next->addr == address) {
        struct fast_mem_block *const block = prev_block->next;
        prev_block->next = block->next;
        log_fast_ram(LOG_TRACE, "freed " PRIM68KxADDR "[" PRIM68KxADDR "]\n", block->addr,
                     block->size);
        free(block);
        return;
      }
    }
  }
  log_fast_ram(LOG_WARN, "no block to free at " PRIM68KxADDR "\n", address);
}

static m68k_byte_t *access_fast_ram(m68k_addr_t address, m68k_long_t size) {
  struct fast_mem_block *const block = find_fast_mem_block(address);
  if (block && (size <= block->size)) {
    m68k_long_t const offset = address - block->addr;
    if (offset + size <= block->size) {
      return get_fast_mem_block_data(block) + offset;
    }
  }
  return NULL;
}

static m68k_byte_t *access_ram(m68k_addr_t address, m68k_long_t size) {
  m68k_byte_t *memory;
  if (!(memory = access_stack_ram(address, size))) {
    if (!(memory = access_load_ram(address, size))) {
      memory = access_fast_ram(address, size);
    }
  }
  return memory;
}

/****************************************************************************
 * emulation
 */

static void log_emulator(enum log_level level, char const *format, ...) {
  va_list args;
  log_printf(level, "emulator: ");
  va_start(args, format);
  log_vprintf(level, format, args);
  va_end(args);
}

enum ENUM_TYPE_DECL(m68k_word_t) {
  OPCODE_RTS = 0x4E75U,
  OPCODE_JMP_ABS_L = 0x4EF9U, /* JMP ABS.L */
  OPCODE_BRA_S_FE = 0x60FEU   /* $0: BRA.S $0 ; freeze, stop emulation */
};

enum ENUM_TYPE_DECL(m68k_long_t) {
  /* struct Node */
  LN_SUCC = 0,
  LN_PRED = LN_SUCC + sizeof(m68k_addr_t),
  LN_TYPE = LN_PRED + sizeof(m68k_addr_t),
  LN_PRI = LN_TYPE + sizeof(m68k_byte_t),
  LN_NAME = LN_PRI + sizeof(m68k_byte_t),
  LN_SIZE = LN_NAME + sizeof(m68k_addr_t)
};

enum ENUM_TYPE_DECL(m68k_long_t) {
  /* struct Library */
  LIB_FLAGS = LN_SIZE,
  LIB_PAD = LIB_FLAGS + sizeof(m68k_byte_t),
  LIB_NEGSIZE = LIB_PAD + sizeof(m68k_byte_t),
  LIB_POSSIZE = LIB_NEGSIZE + sizeof(m68k_word_t),
  LIB_VERSION = LIB_POSSIZE + sizeof(m68k_word_t),
  LIB_REVISION = LIB_VERSION + sizeof(m68k_word_t),
  LIB_IDSTRING = LIB_REVISION + sizeof(m68k_word_t),
  LIB_SUM = LIB_IDSTRING + sizeof(m68k_addr_t),
  LIB_OPENCNT = LIB_SUM + sizeof(m68k_long_t),
  LIB_SIZE = LIB_OPENCNT + sizeof(m68k_word_t)
};

enum ENUM_TYPE_DECL(m68k_long_t) {
  /* struct MinNode */
  MLN_SUCC = 0,
  MLN_PRED = MLN_SUCC + sizeof(m68k_addr_t),
  MLN_SIZE = MLN_PRED + sizeof(m68k_addr_t)
};

enum ENUM_TYPE_DECL(m68k_long_t) {
  /* struct MinList */
  MLH_HEAD = 0,
  MLH_TAIL = MLH_HEAD + sizeof(m68k_addr_t),
  MLH_TAILPRED = MLH_TAIL + sizeof(m68k_addr_t),
  MLH_SIZE = MLH_TAILPRED + sizeof(m68k_addr_t)
};

/* in contrast to the amiga.lib _LVO constants, these LVOs are positive */
#define LVO_INDEX_TO_OFFSET(index) ((index) * LIB_VECTOR_SIZE)
#define LIB_VECTOR_ADDRESS(base, lvo) ((base) - (lvo))

enum ENUM_TYPE_DECL(m68k_long_t) {
  LIB_VECTOR_SIZE = sizeof(m68k_word_t) + sizeof(m68k_addr_t), /* e.g. JMP ABS.L */
  LVO_LibOpen = LVO_INDEX_TO_OFFSET(1),
  LVO_LibClose = LVO_INDEX_TO_OFFSET(2),
  LVO_LibExpunge = LVO_INDEX_TO_OFFSET(3),
  LVO_LibExtFunc = LVO_INDEX_TO_OFFSET(4),
  /* translator.library */
  LVO_Translate = LVO_INDEX_TO_OFFSET(5),
  /* translator.library V42 */
  LVO_TranslateAs = LVO_INDEX_TO_OFFSET(6),
  LVO_LoadAccent = LVO_INDEX_TO_OFFSET(7),
  LVO_SetAccent = LVO_INDEX_TO_OFFSET(8),
  /* exec.library */
  LVO_Alert = LVO_INDEX_TO_OFFSET(18),
  LVO_AllocMem = LVO_INDEX_TO_OFFSET(33),
  LVO_FreeMem = LVO_INDEX_TO_OFFSET(35),
  LVO_AddHead = LVO_INDEX_TO_OFFSET(40),
  LVO_Remove = LVO_INDEX_TO_OFFSET(42),
  LVO_FindTask = LVO_INDEX_TO_OFFSET(49),
  LVO_CloseLibrary = LVO_INDEX_TO_OFFSET(69),
  LVO_RawDoFmt = LVO_INDEX_TO_OFFSET(87),
  LVO_OpenLibrary = LVO_INDEX_TO_OFFSET(92),
  LVO_InitSemaphore = LVO_INDEX_TO_OFFSET(93),
  LVO_ObtainSemaphore = LVO_INDEX_TO_OFFSET(94),
  LVO_ReleaseSemaphore = LVO_INDEX_TO_OFFSET(95),
  LVO_AttemptSemaphore = LVO_INDEX_TO_OFFSET(96),
  LVO_CacheClearU = LVO_INDEX_TO_OFFSET(106),
  /* dos.library */
  LVO_Open = LVO_INDEX_TO_OFFSET(5),
  LVO_Close = LVO_INDEX_TO_OFFSET(6),
  LVO_Read = LVO_INDEX_TO_OFFSET(7),
  LVO_Seek = LVO_INDEX_TO_OFFSET(11),
  /* intuition.library */
  LVO_AutoRequest = LVO_INDEX_TO_OFFSET(58)
};

/* Might get tricky to handle if used inside pc_changed_callback(), see RawDoFmt */
static m68k_long_t call_function(m68k_addr_t func_addr) {
  m68k_addr_t const old_ppc = m68k_get_reg(NULL, M68K_REG_PPC);
  m68k_addr_t const old_pc = m68k_get_reg(NULL, M68K_REG_PC);
  /* do not log per-char sub-calls in exec_RawDoFmt() */
  if (old_pc != LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_RawDoFmt)) {
    log_emulator(LOG_DEBUG, "call (" PRIM68KxADDR "/" PRIM68KxADDR "/" PRIM68KxADDR ")\n", old_ppc,
                 old_pc, func_addr);
  }
  /* push 'freeze' return address, popped by function's RTS */
  {
    m68k_addr_t const new_sp = m68k_get_reg(NULL, M68K_REG_SP) - sizeof(m68k_long_t);
    if (new_sp < STACK_RAM_END) {
      log_emulator(LOG_FATAL, "stack overflow\n");
      exit(EXIT_FAILURE);
    }
    m68k_set_reg(M68K_REG_SP, new_sp);
    m68k_write_memory_32(new_sp, EXEC_LIB_BASE);
  }
  /* execute function until 'freeze' address is reached */
  m68k_set_reg(M68K_REG_PPC, old_pc);
  m68k_set_reg(M68K_REG_PC, func_addr);
  while (m68k_get_reg(NULL, M68K_REG_PC) != EXEC_LIB_BASE) {
    /* m68k_read_immediate_16() calls m68k_end_timeslice() to
     * break/speed-up execution and returns 'freeze' op-code
     * (endless loop at the current PC) for EXEC_LIB_BASE */
    m68k_execute(512);
  }
  {
    /* get result before restoring old (previous) PC,
     * which might trigger other code/call_function(),
     * which might override the result register value */
    m68k_long_t const result = m68k_get_reg(NULL, M68K_REG_D0);
    m68k_set_reg(M68K_REG_PPC, old_ppc);
    if (m68k_get_reg(NULL, M68K_REG_PC) != old_pc) {
      m68k_set_reg(M68K_REG_PC, old_pc);
    }
    return result;
  }
}

static m68k_long_t call_lib_func(m68k_addr_t lib_base, m68k_long_t func_lvo) {
  m68k_long_t result;
  m68k_long_t const max_lvo = m68k_read_memory_16(lib_base + LIB_NEGSIZE);
  m68k_addr_t const old_a6 = m68k_get_reg(NULL, M68K_REG_A6);
  if ((max_lvo < func_lvo) || (func_lvo % LIB_VECTOR_SIZE)) {
    log_printf(LOG_FATAL,
               "call_lib: invalid LVO (" PRIM68KxADDR "," PRIM68KxLVO "/" PRIM68KxLVO ")\n",
               lib_base, max_lvo, func_lvo);
    exit(EXIT_FAILURE);
  }
  if (lib_base != old_a6) {
    m68k_set_reg(M68K_REG_A6, lib_base);
  }
  result = call_function(lib_base - func_lvo);
  if (old_a6 != lib_base) {
    m68k_set_reg(M68K_REG_A6, old_a6);
  }
  return result;
}

/* VOID Alert(
 *   REG(D7) ULONG alertNum),
 * REG(A6) struct ExecBase * SysBase */
static void exec_Alert(m68k_long_t alertNum) {
  log_emulator(LOG_WARN, "exec.library/Alert(" PRIM68KxLONG ")\n", alertNum);
}

/* REG(D0) APTR AllocMem(
 *   REG(D0) ULONG byteSize,
 *   REG(D1) ULONG requirements),
 * REG(A6) struct ExecBase * SysBase */
static m68k_addr_t exec_AllocMem(m68k_long_t byteSize, m68k_long_t requirements) {
  struct fast_mem_block *const block = alloc_fast_mem_block(byteSize);
  log_emulator(LOG_DEBUG, "exec.library/AllocMem(%d," PRIM68KxLONG ")=" PRIM68KxADDR "\n",
               m68k_long_to_signed(byteSize), requirements, block->addr);
  return block->addr;
}

/* REG(D0) VOID FreeMem(
 *   REG(A1) APTR  memoryBlock,
 *   REG(D0) ULONG byteSize),
 * REG(A6) struct ExecBase * SysBase */
static void exec_FreeMem(m68k_addr_t memoryBlock, m68k_long_t byteSize) {
  struct fast_mem_block const *const block = find_fast_mem_block(memoryBlock);
  log_emulator(LOG_DEBUG, "exec.library/FreeMem(" PRIM68KxADDR ",%d)\n", memoryBlock,
               m68k_long_to_signed(byteSize));
  if (block && (block->addr == memoryBlock) && (byteSize <= block->size)) {
    free_fast_mem(block->addr);
  }
}

/* VOID AddHead(
 *   REG(A0) struct List * list,
 *   REG(A1) struct Node * node),
 * REG(A6) struct ExecBase * SysBase */
static void exec_AddHead(m68k_addr_t list, m68k_addr_t node) {
  /* MOVE.L  (A0),D0         ; MLH_HEAD */
  m68k_byte_t *const list_mem = access_ram(list, MLH_SIZE);
  m68k_byte_t *const node_mem = access_ram(node, MLN_SIZE);
  m68k_addr_t const head = m68k_get_long(list_mem + MLH_HEAD);
  m68k_set_reg(M68K_REG_D0, head);
  /* MOVE.L  A1,(A0)         ; MLH_HEAD */
  m68k_set_long(list_mem + MLH_HEAD, node);
  /* MOVEM.L D0/A0,(A1)      ; MLN_SUCC/MLN_PRED */
  m68k_set_long(node_mem + MLN_SUCC, head);
  m68k_set_long(node_mem + MLN_PRED, list);
  /* MOVE.L  D0,A0           ; previous head */
  m68k_set_reg(M68K_REG_A0, head);
  /* MOVE.L  A1,$0004(A0)    ; MLN_PRED */
  m68k_set_long(access_ram(head, MLH_SIZE) + MLN_PRED, node);
}

/* VOID Remove(
 *   REG(A1) struct Node * node),
 * REG(A6) struct ExecBase * SysBase */
static void exec_Remove(m68k_addr_t node) {
  /* MOVE.L  (A1)+,A0        ; MLN_SUCC */
  /* MOVE.L  (A1),A1         ; MLN_PRED */
  m68k_byte_t *const node_mem = access_ram(node, MLN_SIZE);
  m68k_addr_t const succ = m68k_get_long(node_mem + MLN_SUCC);
  m68k_addr_t const pred = m68k_get_long(node_mem + MLN_PRED);
  m68k_set_reg(M68K_REG_A0, succ);
  m68k_set_reg(M68K_REG_A1, succ);
  /* MOVE.L  A0,(A1)         ; MLN_SUCC */
  m68k_set_long(access_ram(pred, MLH_SIZE) + MLN_SUCC, succ);
  /* MOVE.L  A1,$0004(A0)    ; MLN_PRED */
  m68k_set_long(access_ram(succ, MLH_SIZE) + MLN_PRED, pred);
}

/* REG(D0) struct Task * FindTask(
 *   REG(A1) CONST_STRPTR name),
 * REG(A6) struct ExecBase * SysBase */
static m68k_addr_t exec_FindTask(m68k_addr_t name) {
  m68k_addr_t const result = !name ? FAKE_TASK_BASE : M68K_ADDR_NULL;
  log_emulator(LOG_DEBUG, "exec.library/FindTask(" PRIM68KxADDR ")=" PRIM68KxADDR "\n", name,
               result);
  return result;
}

/* VOID CloseLibrary(
 *   REG(A1) struct Library * library),
 * REG(A6) struct ExecBase * SysBase */
static void exec_CloseLibrary(m68k_addr_t library) {
  switch (library) {
  case M68K_ADDR_NULL: {
    log_emulator(LOG_DEBUG, "exec.library/CloseLibrary(NULL)\n");
    return;
  }
  case EXEC_LIB_BASE: {
    log_emulator(LOG_DEBUG, "exec.library/CloseLibrary(SysBase)\n");
    return;
  }
  case DOS_LIB_BASE: {
    log_emulator(LOG_DEBUG, "exec.library/CloseLibrary(DOSBase)\n");
    return;
  }
  case GRAPHICS_LIB_BASE: {
    log_emulator(LOG_DEBUG, "exec.library/CloseLibrary(GfxBase)\n");
    return;
  }
  case INTUITION_LIB_BASE: {
    log_emulator(LOG_DEBUG, "exec.library/CloseLibrary(IntuitionBase)\n");
    return;
  }
  default: {
    log_emulator(LOG_DEBUG, "exec.library/CloseLibrary(" PRIM68KxADDR ")\n", library);
    return;
  }
  }
}

static void call_put_ch_proc(char ch) {
  m68k_set_reg(M68K_REG_D0, ch);
  call_function(m68k_get_reg(NULL, M68K_REG_A2));
}

/* REG(D0) APTR RawDoFmt(
 *   REG(A0) CONST_STRPTR formatString,
 *   REG(A1) APTR         dataStream,
 *   REG(A2) REG(A3) (*   putChProc)(REG(D0), REG(A3)),
 *   REG(A3) APTR         putChData),
 * REG(A6) struct ExecBase * SysBase */
static m68k_addr_t exec_RawDoFmt(m68k_addr_t formatString, m68k_addr_t dataStream,
                                 m68k_addr_t putChProc, m68k_addr_t putChData) {
  /* Error handling missing, I just hope that all the parameters are
   * valid and that only the format tags '%s' and '%ld' are present.
   * Function is only called for formatting the error requester text. */
  char const *format = (char const *)access_ram(formatString, sizeof(char));
  log_emulator(LOG_TRACE, "exec.library/RawDoFmt(\"%s\")\n", format);
  for (; *format; ++format) {
    if ('%' != *format) {
      /* convert ISO/IEC 8859-1 copyright sign to ASCII */
      if ('\xA9' == *format) {
        call_put_ch_proc('(');
        call_put_ch_proc('C');
        call_put_ch_proc(')');
        continue;
      }
      call_put_ch_proc(*format);
      continue;
    }
    if ('%' == *++format) {
      call_put_ch_proc(*format);
      continue;
    }
    if ('s' == *format) {
      m68k_addr_t const addr = m68k_get_long(access_ram(dataStream, sizeof(addr)));
      dataStream += sizeof(m68k_addr_t);
      if (addr) {
        m68k_byte_t const *data = access_ram(addr, sizeof(*data));
        if (data) {
          for (; *data; ++data) {
            call_put_ch_proc(*data);
          }
        }
      }
    } else if (('l' == *format) && ('d' == *++format)) {
      m68k_long_t const data = m68k_get_long(access_ram(dataStream, sizeof(data)));
      dataStream += sizeof(data);
      {
        char str[12];
        char const *str_ch;
        sprintf(str, "%d", m68k_long_to_signed(data));
        for (str_ch = str; *str_ch; ++str_ch) {
          call_put_ch_proc(*str_ch);
        }
      }
    } else {
      log_emulator(LOG_FATAL, "unsupported format string (\"%s\")\n",
                   (char const *)access_ram(formatString, sizeof(char)));
      exit(EXIT_FAILURE);
    }
  }
  call_put_ch_proc('\0');
  m68k_set_reg(M68K_REG_A2, putChProc);
  m68k_set_reg(M68K_REG_A3, putChData);
  return dataStream;
}

/* REG(D0) struct Library * OpenLibrary(
 *   REG(A1) CONST_STRPTR libName,
 *   REG(D0) ULONG        version),
 * REG(A6) struct ExecBase * SysBase */
static m68k_addr_t exec_OpenLibrary(m68k_addr_t libName, m68k_long_t version) {
  m68k_addr_t library = M68K_ADDR_NULL;
  m68k_byte_t const *const lib_name = access_ram(libName, sizeof("intuition.library"));
  if (lib_name) {
    if (!strcmp((char const *)lib_name, "dos.library")) {
      library = DOS_LIB_BASE;
    } else if (!strcmp((char const *)lib_name, "graphics.library")) {
      library = GRAPHICS_LIB_BASE;
    } else if (!strcmp((char const *)lib_name, "intuition.library")) {
      library = INTUITION_LIB_BASE;
    } else {
      log_emulator(LOG_WARN, "library \"%s\" is not emulated\n");
    }
  }
  log_emulator(LOG_DEBUG, "exec.library/OpenLibrary(\"%s\",%d)=" PRIM68KxADDR "\n",
               lib_name ? (char const *)lib_name : "(null)", m68k_long_to_signed(version), library);
  return library;
}

/* VOID InitSemaphore(
 *   REG(A0) struct SignalSemaphore * sigSem),
 * REG(A6) struct ExecBase * SysBase */
static void exec_InitSemaphore(m68k_addr_t sigSem) {
  log_emulator(LOG_DEBUG, "exec.library/InitSemaphore(" PRIM68KxADDR ")\n", sigSem);
}

/* VOID ObtainSemaphore(
 *   REG(A0) struct SignalSemaphore * sigSem),
 * REG(A6) struct ExecBase * SysBase */
static void exec_ObtainSemaphore(m68k_addr_t sigSem) {
  log_emulator(LOG_DEBUG, "exec.library/ObtainSemaphore(" PRIM68KxADDR ")\n", sigSem);
}

/* VOID ReleaseSemaphore(
 *   REG(A0) struct SignalSemaphore * sigSem),
 * REG(A6) struct ExecBase * SysBase */
static void exec_ReleaseSemaphore(m68k_addr_t sigSem) {
  log_emulator(LOG_DEBUG, "exec.library/ReleaseSemaphore(" PRIM68KxADDR ")\n", sigSem);
}

/* REG(D0) ULONG AttemptSemaphore(
 *   REG(A0) struct SignalSemaphore * sigSem),
 * REG(A6) struct ExecBase * SysBase */
static m68k_long_t exec_AttemptSemaphore(m68k_addr_t sigSem) {
  log_emulator(LOG_DEBUG, "exec.library/AttemptSemaphore(" PRIM68KxADDR ")\n", sigSem);
  return TRUE;
}

/* VOID CacheClearU(VOID),
 * REG(A6) struct ExecBase * SysBase */
static void exec_CacheClearU(void) { log_emulator(LOG_DEBUG, "exec.library/CacheClearU()\n"); }

static FILE *opened_file /* = NULL */;

/* REG(D0) BPTR Open(
 *   REG(D1) CONST_STRPTR name,
 *   REG(D2) LONG         accessMode),
 * REG(A6) struct DosLibrary * DOSBase */
static m68k_bptr_t dos_Open(m68k_addr_t name, m68k_long_t accessMode) {
  enum ENUM_TYPE_DECL(m68k_long_t) {
    MODE_READWRITE = M68K_LONG_C(1004),
    MODE_OLDFILE = M68K_LONG_C(1005),
    MODE_NEWFILE = M68K_LONG_C(1006)
  };
  char const *const name_str = (char const *)access_ram(name, sizeof(char));
  log_emulator(LOG_DEBUG, "dos.library/Open(\"%s\",%d)\n", name_str,
               m68k_long_to_signed(accessMode));
  if (opened_file) {
    log_emulator(LOG_FATAL, "FIXME: multiple open files are not implemented\n");
    exit(EXIT_FAILURE);
  } else if (accessMode != MODE_OLDFILE) {
    log_emulator(LOG_FATAL, "FIXME: creating/writing files not implemented\n");
    exit(EXIT_FAILURE);
  }
  if (name_str && *name_str) {
    enum { LIB_ACCENT_PATH_LEN = sizeof("LOCALE:Accents/") - sizeof("") };
    static char const *const LIB_ACCENT_PATH = "LOCALE:Accents/";
    if (!strncmp(name_str, LIB_ACCENT_PATH, LIB_ACCENT_PATH_LEN)) {
      /* accent open request, no fallbacks */
      size_t const dir_len = strlen(accent_dir);
      char *const filename =
          malloc(dir_len + (strlen(name_str) - LIB_ACCENT_PATH_LEN) + sizeof(char));
      if (filename) {
        char const *name_part;
        char *file_part = strcpy(filename, accent_dir) + dir_len;
        for (name_part = name_str + LIB_ACCENT_PATH_LEN; *name_part; ++name_part, ++file_part) {
          if (('A' <= *name_part) && (*name_part <= 'Z')) {
            *file_part = (char)((unsigned char)*name_part + (unsigned char)('a' - 'A'));
          } else {
            *file_part = *name_part;
          }
        }
        *file_part = '\0';
        log_emulator(LOG_INFO, "opening \"%s\"\n", filename);
        opened_file = fopen(filename, "rb");
        free(filename);
        if (opened_file) {
          return MKBADDR(FAKE_FILE_HANDLE);
        }
      }
    } else {
      /* try the name as is ("ENV:Sys/Translator.prefs") */
      log_emulator(LOG_INFO, "opening \"%s\"\n", name_str);
      opened_file = fopen(name_str, "rb");
      if (opened_file) {
        return MKBADDR(FAKE_FILE_HANDLE);
      } else {
        /* find and skip after first ':' ("Sys/Translator.prefs") */
        char const *rel_part = strchr(name_str, ':');
        if (rel_part && *++rel_part) {
          log_emulator(LOG_INFO, "opening \"%s\"\n", rel_part);
          opened_file = fopen(rel_part, "rb");
          if (opened_file) {
            return MKBADDR(FAKE_FILE_HANDLE);
          }
        }
      }
    }
  }
  return M68K_BPTR_NULL;
}

/* REG(D0) LONG Close(
 *   REG(D1) BPTR file),
 * REG(A6) struct DosLibrary * DOSBase */
static m68k_long_t dos_Close(m68k_bptr_t file) {
  log_emulator(LOG_DEBUG, "dos.library/Close(" PRIM68KxBPTR ")\n", file);
  if (MKBADDR(FAKE_FILE_HANDLE) == file) {
    if (!opened_file) {
      log_emulator(LOG_WARN, "opened file is already closed\n");
    } else {
      FILE *const stream = opened_file;
      opened_file = NULL;
      if (!fclose(stream)) {
        return TRUE;
      }
    }
  }
  return FALSE;
}

/* REG(D0) LONG Read(
 *   REG(D1) BPTR file,
 *   REG(D2) APTR buffer,
 *   REG(D3) LONG length),
 * REG(A6) struct DosLibrary * DOSBase */
static m68k_long_t dos_Read(m68k_bptr_t file, m68k_addr_t buffer, m68k_long_t length) {
  FILE *const stream = opened_file;
  m68k_long_t result = M68K_LONG_C(0xFFFFFFFF) /* (m68k_long_t)-1 */;
  if ((MKBADDR(FAKE_FILE_HANDLE) == file) && stream) {
    if (!length) {
      result = length;
    } else if (m68k_long_to_signed(length) > 0) {
      m68k_byte_t *const memory = access_ram(buffer, length);
      if (memory) {
        size_t const read = fread(memory, sizeof(*memory), length, stream);
        if (read || feof(stream)) {
          result = read;
        }
      }
    }
  }
  log_emulator(LOG_DEBUG, "dos.library/Read(" PRIM68KxBPTR "," PRIM68KxADDR ",%d)=%d\n", file,
               buffer, m68k_long_to_signed(length), m68k_long_to_signed(result));
  return result;
}

/* REG(D0) LONG Seek(
 *   REG(D1) BPTR file,
 *   REG(D2) LONG position,
 *   REG(D3) LONG offset),
 * REG(A6) struct DosLibrary * DOSBase */
static m68k_long_t dos_Seek(m68k_bptr_t file, m68k_long_t position, m68k_long_t offset) {
  enum ENUM_TYPE_DECL(m68k_long_t) {
    OFFSET_CURRENT = M68K_LONG_C(0x00000000),
    OFFSET_END = M68K_LONG_C(0x00000001) /*,
    OFFSET_BEGINNING = M68K_LONG_C(0xFFFFFFFF) */
  };
  FILE *const stream = opened_file;
  int const origin = (offset == OFFSET_CURRENT) ? SEEK_CUR
                     : (offset == OFFSET_END)   ? SEEK_END
                                                : SEEK_SET;
  m68k_long_t result = M68K_LONG_C(0xFFFFFFFF) /* (m68k_long_t)-1 */;
  /* C binary streams are not required to support SEEK_END,
   * but your stdlib and (file)system supports it, right? */
  if ((MKBADDR(FAKE_FILE_HANDLE) == file) && stream) {
    /* dos.library/Seek() returns the previous position */
    long int const pos = ftell(stream);
    if ((0L <= pos) && (pos <= 0x7FFFFFFFL) &&
        !fseek(stream, m68k_long_to_signed(position), origin)) {
      result = (m68k_long_t)(pos & 0x7FFFFFFFL);
    }
  }
  log_emulator(LOG_DEBUG, "dos.library/Seek(" PRIM68KxBPTR ",%d,%d)=%d\n", file,
               m68k_long_to_signed(position), m68k_long_to_signed(offset),
               m68k_long_to_signed(result));
  return result;
}

/* REG(D0) BOOL AutoRequest(
 *   REG(A0) struct Window *          window,
 *   REG(A1) CONST struct IntuiText * body,
 *   REG(A2) CONST struct IntuiText * posText,
 *   REG(A3) CONST struct IntuiText * negText,
 *   REG(D0) ULONG                    pFlag,
 *   REG(D1) ULONG                    nFlag,
 *   REG(D2) ULONG                    width,
 *   REG(D3) ULONG                    height),
 * REG(A6) struct IntuitionBase * IntuitionBase */
static m68k_long_t intuition_AutoRequest(m68k_addr_t window, m68k_addr_t body, m68k_addr_t posText,
                                         m68k_addr_t negText, m68k_long_t pFlag, m68k_long_t nFlag,
                                         m68k_long_t width, m68k_long_t height) {
  static char const *const error_format = "translate: [error] %s\n";
  (void)window;
  (void)posText;
  (void)negText;
  (void)pFlag;
  (void)nFlag;
  (void)width;
  (void)height;
  log_printf(LOG_WARN, error_format, "");
  while (body) {
    m68k_byte_t const *const text = access_ram(body, 0x0014U /* sizeof(struct IntuiText) */);
    if (!text) {
      break;
    }
    body = m68k_get_long(text + 0x0010U /* IntuiText.NextText */);
    log_printf(LOG_FATAL, error_format,
               (char const *)access_ram(m68k_get_long(text + 0x000CU /* IntuiText.IText */),
                                        sizeof(char)));
  }
  log_printf(LOG_WARN, error_format, "");
  return TRUE;
}

static void pc_changed_callback(m68k_addr_t new_pc) {
  m68k_addr_t const old_pc = m68k_get_reg(NULL, M68K_REG_PPC);
  log_emulator(LOG_TRACE, "PC changed (" PRIM68KxADDR "/" PRIM68KxADDR ")\n", old_pc, new_pc);
  switch (new_pc) {
  case ZERO_LOCATION: {
    /* m68k_pulse_reset() or call_execute() return */
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_CacheClearU): {
    exec_CacheClearU();
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_AttemptSemaphore): {
    m68k_set_reg(M68K_REG_D0, exec_AttemptSemaphore(m68k_get_reg(NULL, M68K_REG_A0)));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_ReleaseSemaphore): {
    exec_ReleaseSemaphore(m68k_get_reg(NULL, M68K_REG_A0));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_ObtainSemaphore): {
    exec_ObtainSemaphore(m68k_get_reg(NULL, M68K_REG_A0));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_InitSemaphore): {
    exec_InitSemaphore(m68k_get_reg(NULL, M68K_REG_A0));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_OpenLibrary): {
    m68k_set_reg(M68K_REG_D0, exec_OpenLibrary(m68k_get_reg(NULL, M68K_REG_A1),
                                               m68k_get_reg(NULL, M68K_REG_D0)));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_RawDoFmt): {
    static int in_RawDoFmt = 0;
    if (!in_RawDoFmt) {
      ++in_RawDoFmt;
      m68k_set_reg(M68K_REG_D0,
                   exec_RawDoFmt(m68k_get_reg(NULL, M68K_REG_A0), m68k_get_reg(NULL, M68K_REG_A1),
                                 m68k_get_reg(NULL, M68K_REG_A2), m68k_get_reg(NULL, M68K_REG_A3)));
      --in_RawDoFmt;
    }
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_CloseLibrary): {
    exec_CloseLibrary(m68k_get_reg(NULL, M68K_REG_A1));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_FindTask): {
    m68k_set_reg(M68K_REG_D0, exec_FindTask(m68k_get_reg(NULL, M68K_REG_A1)));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_Remove): {
    exec_Remove(m68k_get_reg(NULL, M68K_REG_A1));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_AddHead): {
    exec_AddHead(m68k_get_reg(NULL, M68K_REG_A0), m68k_get_reg(NULL, M68K_REG_A1));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_FreeMem): {
    exec_FreeMem(m68k_get_reg(NULL, M68K_REG_A1), m68k_get_reg(NULL, M68K_REG_D0));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_AllocMem): {
    m68k_set_reg(M68K_REG_D0,
                 exec_AllocMem(m68k_get_reg(NULL, M68K_REG_D0), m68k_get_reg(NULL, M68K_REG_D1)));
    break;
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_Alert): {
    exec_Alert(m68k_get_reg(NULL, M68K_REG_D7));
    break;
  }
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Seek): {
    m68k_set_reg(M68K_REG_D0,
                 dos_Seek(m68k_get_reg(NULL, M68K_REG_D1), m68k_get_reg(NULL, M68K_REG_D2),
                          m68k_get_reg(NULL, M68K_REG_D3)));
    break;
  }
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Read): {
    m68k_set_reg(M68K_REG_D0,
                 dos_Read(m68k_get_reg(NULL, M68K_REG_D1), m68k_get_reg(NULL, M68K_REG_D2),
                          m68k_get_reg(NULL, M68K_REG_D3)));
    break;
  }
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Close): {
    m68k_set_reg(M68K_REG_D0, dos_Close(m68k_get_reg(NULL, M68K_REG_D1)));
    break;
  }
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Open): {
    m68k_set_reg(M68K_REG_D0,
                 dos_Open(m68k_get_reg(NULL, M68K_REG_D1), m68k_get_reg(NULL, M68K_REG_D2)));
    break;
  }
  case LIB_VECTOR_ADDRESS(INTUITION_LIB_BASE, LVO_AutoRequest): {
    m68k_set_reg(
        M68K_REG_D0,
        intuition_AutoRequest(m68k_get_reg(NULL, M68K_REG_A0), m68k_get_reg(NULL, M68K_REG_A1),
                              m68k_get_reg(NULL, M68K_REG_A2), m68k_get_reg(NULL, M68K_REG_A3),
                              m68k_get_reg(NULL, M68K_REG_D0), m68k_get_reg(NULL, M68K_REG_D1),
                              m68k_get_reg(NULL, M68K_REG_D2), m68k_get_reg(NULL, M68K_REG_D3)));
    break;
  }
  default: {
    if (new_pc == old_pc) {
      if (new_pc != EXEC_LIB_BASE) {
        log_emulator(LOG_FATAL, "freeze at " PRIM68KxADDR "\n", new_pc);
        exit(EXIT_FAILURE);
      }
    }
  }
  }
}

static m68k_long_t fixme_read(char const *func_name, m68k_addr_t address) {
  if ((EXEC_LIB_LVO <= address) && (address < EXEC_LIB_END)) {
    if (address < EXEC_LIB_BASE) {
      log_emulator(LOG_FATAL, "FIXME: %s(exec.library/" PRIM68KxLVO ")\n", func_name,
                   EXEC_LIB_BASE - address);
    } else {
      log_emulator(LOG_FATAL, "FIXME: %s(ExeBase->" PRIM68KxSIZE ")\n", func_name,
                   address - EXEC_LIB_BASE);
    }
  } else if ((DOS_LIB_LVO <= address) && (address < DOS_LIB_END)) {
    if (address < DOS_LIB_BASE) {
      log_emulator(LOG_FATAL, "FIXME: %s(dos.library/" PRIM68KxLVO ")\n", func_name,
                   DOS_LIB_BASE - address);
    } else {
      log_emulator(LOG_FATAL, "FIXME: %s(DosLibrary->" PRIM68KxSIZE ")\n", func_name,
                   address - DOS_LIB_BASE);
    }
  } else if ((GRAPHICS_LIB_LVO <= address) && (address < GRAPHICS_LIB_END)) {
    if (address < GRAPHICS_LIB_BASE) {
      log_emulator(LOG_FATAL, "FIXME: %s(graphics.library/" PRIM68KxLVO ")\n", func_name,
                   GRAPHICS_LIB_BASE - address);
    } else {
      log_emulator(LOG_FATAL, "FIXME: %s(GfxBase->" PRIM68KxSIZE ")\n", func_name,
                   address - GRAPHICS_LIB_BASE);
    }
  } else if ((INTUITION_LIB_LVO <= address) && (address < INTUITION_LIB_END)) {
    if (address < INTUITION_LIB_BASE) {
      log_emulator(LOG_FATAL, "FIXME: %s(intuition.library/" PRIM68KxLVO ")\n", func_name,
                   INTUITION_LIB_BASE - address);
    } else {
      log_emulator(LOG_FATAL, "FIXME: %s(IntuitionBase->" PRIM68KxSIZE ")\n", func_name,
                   address - INTUITION_LIB_BASE);
    }
  } else if ((FAKE_TASK_BASE <= address) && (address < FAKE_TASK_END)) {
    log_emulator(LOG_FATAL, "FIXME: %s(Process->" PRIM68KxSIZE ")\n", func_name,
                 address - FAKE_TASK_BASE);
  } else if ((FAKE_FILE_HANDLE <= address) && (address < FAKE_FILE_HANDLE + 0x002CU)) {
    log_emulator(LOG_FATAL, "FIXME: %s(FileHandle->" PRIM68KxSIZE ")\n", func_name,
                 address - FAKE_FILE_HANDLE);
  } else if ((FAKE_DEFAULT_FONT <= address) && (address < FAKE_DEFAULT_FONT + 0x0034U)) {
    log_emulator(LOG_FATAL, "FIXME: %s(TextFont->" PRIM68KxSIZE ")\n", func_name,
                 address - FAKE_DEFAULT_FONT);
  } else {
    log_emulator(LOG_FATAL, "FIXME: %s(" PRIM68KxADDR ")\n", func_name, address);
  }
  exit(EXIT_FAILURE);
}

m68k_long_t m68k_read_immediate_16(m68k_addr_t address) {
  switch (address) {
  case ZERO_LOCATION: {
    log_emulator(LOG_FATAL, "FIXME: M68K_EMULATE_PREFETCH enabled?\n");
    exit(EXIT_FAILURE);
  }
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_CacheClearU):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_AttemptSemaphore):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_ReleaseSemaphore):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_ObtainSemaphore):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_InitSemaphore):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_OpenLibrary):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_RawDoFmt):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_CloseLibrary):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_FindTask):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_Remove):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_AddHead):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_FreeMem):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_AllocMem):
  case LIB_VECTOR_ADDRESS(EXEC_LIB_BASE, LVO_Alert): {
    return OPCODE_RTS;
  }
  case EXEC_LIB_BASE: {
    /* freeze and leave call_execute() */
    m68k_end_timeslice();
    return OPCODE_BRA_S_FE;
  }
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Seek):
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Read):
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Close):
  case LIB_VECTOR_ADDRESS(DOS_LIB_BASE, LVO_Open): {
    return OPCODE_RTS;
  }
  case LIB_VECTOR_ADDRESS(INTUITION_LIB_BASE, LVO_AutoRequest): {
    return OPCODE_RTS;
  }
  default: {
    m68k_byte_t const *memory; /* stack excluded */
    if (!(memory = access_load_ram(address, sizeof(m68k_word_t)))) {
      memory = access_fast_ram(address, sizeof(m68k_word_t));
    }
    if (memory) {
      return m68k_get_word(memory);
    }
    break;
  }
  }
  return fixme_read("m68k_read_immediate_16", address);
}

m68k_long_t m68k_read_immediate_32(m68k_addr_t address) {
  switch (address) {
  case ZERO_LOCATION: {
    return STACK_RAM_TOP;
  }
  case ABS_EXEC_BASE: {
    return EXEC_LIB_BASE;
  }
  default: {
    m68k_byte_t const *memory; /* stack excluded */
    if (!(memory = access_load_ram(address, sizeof(m68k_long_t)))) {
      memory = access_fast_ram(address, sizeof(m68k_long_t));
    }
    if (memory) {
      return m68k_get_long(memory);
    }
    break;
  }
  }
  return fixme_read("m68k_read_immediate_32", address);
}

static m68k_byte_t const *input_string /* = NULL */;
static m68k_long_t input_string_len /* = 0 */;

m68k_long_t m68k_read_memory_8(m68k_addr_t address) {
  switch (address) {
  case FAKE_TASK_BASE + LN_TYPE: {
    return 13; /* NT_PROCESS */
  }
  default: {
    if ((INPUT_STRING_BASE <= address) && (address < INPUT_STRING_BASE + input_string_len)) {
      return input_string[address - INPUT_STRING_BASE];
    } else {
      m68k_byte_t const *const memory = access_ram(address, sizeof(m68k_byte_t));
      if (memory) {
        return *memory;
      }
    }
    break;
  }
  }
  return fixme_read("m68k_read_memory_8", address);
}

m68k_long_t m68k_read_memory_16(m68k_addr_t address) {
  switch (address) {
  case EXEC_LIB_BASE + LIB_VERSION: {
    return 35 /* not AmigaOS 2.x (avoid CacheClearU call) */;
  }
  case FAKE_DEFAULT_FONT + 0x0014U /* TextFont.tf_YSize */: {
    return 8;
  }
  case FAKE_DEFAULT_FONT + 0x0018U /* TextFont.tf_XSize */: {
    return 4;
  }
  default: {
    m68k_byte_t const *const memory = access_ram(address, sizeof(m68k_word_t));
    if (memory) {
      return m68k_get_word(memory);
    }
    break;
  }
  }
  return fixme_read("m68k_read_memory_16", address);
}

m68k_long_t m68k_read_memory_32(m68k_addr_t address) {
  switch (address) {
  case ABS_EXEC_BASE: {
    return EXEC_LIB_BASE;
  }
  case GRAPHICS_LIB_BASE + 0x009AU /* GfxBase.DefaultFont */: {
    return FAKE_DEFAULT_FONT;
  }
  default: {
    m68k_byte_t const *const memory = access_ram(address, sizeof(m68k_long_t));
    if (memory) {
      return m68k_get_long(memory);
    }
  }
  }
  return fixme_read("m68k_read_memory_32", address);
}

m68k_long_t m68k_read_pcrelative_8(m68k_addr_t address) {
  return fixme_read("m68k_read_pcrelative_8", address);
}

m68k_long_t m68k_read_pcrelative_16(m68k_addr_t address) {
  return fixme_read("m68k_read_pcrelative_16", address);
}

m68k_long_t m68k_read_pcrelative_32(m68k_addr_t address) {
  return fixme_read("m68k_read_pcrelative_32", address);
}

m68k_long_t m68k_read_disassembler_8(m68k_addr_t address) {
  return fixme_read("m68k_read_disassembler_8", address);
}

m68k_long_t m68k_read_disassembler_16(m68k_addr_t address) {
  return fixme_read("m68k_read_disassembler_16", address);
}

m68k_long_t m68k_read_disassembler_32(m68k_addr_t address) {
  return fixme_read("m68k_read_disassembler_32", address);
}

static void fixme_write(char const *callback, m68k_addr_t address, m68k_long_t value) {
  log_printf(LOG_FATAL, "FIXME: %s(" PRIM68KxADDR "," PRIM68KxLONG ")\n", callback, address, value);
  exit(EXIT_FAILURE);
}

void m68k_write_memory_8(m68k_addr_t address, m68k_long_t value) {
  m68k_byte_t *const memory = access_ram(address, sizeof(m68k_byte_t));
  if (memory) {
    *memory = (m68k_byte_t)(value & 0xFFU);
    return;
  }
  fixme_write("m68k_write_memory_8", address, value);
}

void m68k_write_memory_16(m68k_addr_t address, m68k_long_t value) {
  m68k_byte_t *const memory = access_ram(address, sizeof(m68k_word_t));
  if (memory) {
    m68k_set_word(memory, value);
    return;
  }
  fixme_write("m68k_write_memory_16", address, value);
}

void m68k_write_memory_32(m68k_addr_t address, m68k_long_t value) {
  m68k_byte_t *const memory = access_ram(address, sizeof(m68k_long_t));
  if (memory) {
    m68k_set_long(memory, value);
    return;
  }
  fixme_write("m68k_write_memory_32", address, value);
}

void m68k_write_memory_32_pd(m68k_addr_t address, m68k_long_t value) {
  fixme_write("m68k_write_memory_32_pd", address, value);
}

/****************************************************************************
 * segment loading
 */

enum {
  /* a seg_list is basically an AllocVec-ed linked list
   * struct {
   *     ULONG seg_size; // in bytes
   *     BPTR  seg_next; // <- seg_list *
   *     UBYTE seg_data[seg_size - 8U];
   * };
   */
  SEG_LIST_SIZE = sizeof(m68k_long_t) + sizeof(m68k_bptr_t)
};

static void log_load_seg(enum log_level level, char const *format, ...) {
  va_list args;
  log_printf(level, "load_seg: ");
  va_start(args, format);
  log_vprintf(level, format, args);
  va_end(args);
}

static void load_error(FILE **stream, char const *format, ...) {
  va_list args;
  log_printf(LOG_FATAL, "load_seg: ");
  va_start(args, format);
  log_vprintf(LOG_FATAL, format, args);
  va_end(args);
  if (*stream) {
    (fclose(*stream), *stream = NULL);
  }
  if (load_ram != NULL) {
    (free(load_ram), load_ram = NULL);
  }
  exit(EXIT_FAILURE);
}

static m68k_long_t load_long(FILE **stream, char const *name) {
  m68k_byte_t buffer[4];
  if (fread(buffer, sizeof(*buffer), ARRAY_LENGTH(buffer), *stream) == ARRAY_LENGTH(buffer)) {
    m68k_long_t const value = m68k_get_long(buffer);
    log_printf(LOG_TRACE, "load_long: " PRIM68KxLONG " %s\n", value, name);
    return value;
  }
  load_error(stream, "error on reading %s\n", name);
  return 0;
}

static m68k_bptr_t load_seg(char const *filename) {
  enum { MAX_HUNK_COUNT = 8 };
  enum ENUM_TYPE_DECL(m68k_long_t) {
    HUNK_CODE = M68K_LONG_C(0x000003E9),
    HUNK_DATA = M68K_LONG_C(0x000003EA),
    HUNK_BSS = M68K_LONG_C(0x000003EB),
    HUNK_RELOC32 = M68K_LONG_C(0x000003EC),
    HUNK_END = M68K_LONG_C(0x000003F2),
    HUNK_HEADER = M68K_LONG_C(0x000003F3),
    HUNK_SIZE_MASK = M68K_LONG_C(0x3FFFFFFF),
    HUNK_TYPE_MASK = M68K_LONG_C(0x3FFFFFFF)
  };
  FILE *stream;
  m68k_long_t hunk_count, hunk_index, hunk_value;
  m68k_long_t hunk_size[MAX_HUNK_COUNT];     /* runtime size in bytes */
  m68k_addr_t hunk_addr[MAX_HUNK_COUNT + 1]; /* {load RAM addr..., 0} */

  if (!(stream = fopen(filename, "rb"))) {
    int const ec = errno;
    load_error(&stream, "failed to open \"%s\" (%d) %s\n", filename, ec, strerror(ec));
  }
  log_load_seg(LOG_INFO, "loading \"%s\"\n", filename);
  if ((load_long(&stream, "hunk header ID") != HUNK_HEADER) ||
      (load_long(&stream, "hunk header string count") != 0)) {
    load_error(&stream, "\"%s\" is not a loadable hunk file\n", filename);
  }
  hunk_count = load_long(&stream, "hunk header table size");
  hunk_index = load_long(&stream, "hunk header first hunk");
  hunk_value = load_long(&stream, "hunk header last hunk");
  log_load_seg(LOG_DEBUG, "hunk count %d (%d..%d)\n", m68k_long_to_signed(hunk_count),
               m68k_long_to_signed(hunk_index), m68k_long_to_signed(hunk_value));
  if (!hunk_count || (MAX_HUNK_COUNT < hunk_count) || hunk_index ||
      (hunk_value != hunk_count - 1)) {
    load_error(&stream, "unsupported hunk file \"%s\"\n", filename);
  }

  load_ram_size = 0;
  for (hunk_index = 0; hunk_index < hunk_count; ++hunk_index) {
    load_ram_size += SEG_LIST_SIZE;
    hunk_addr[hunk_index] = LOAD_RAM_BASE + load_ram_size;
    log_load_seg(LOG_DEBUG, "hunk %d addr " PRIM68KxADDR "\n", m68k_long_to_signed(hunk_index),
                 hunk_addr[hunk_index]);

    hunk_value = load_long(&stream, "hunk size") & HUNK_SIZE_MASK;
    log_load_seg(LOG_TRACE, "hunk %d blen " PRIM68KxBPTR "\n", hunk_index, hunk_value);
    if (hunk_value > ((SEG_LIST_SIZE + (LOAD_RAM_END - LOAD_RAM_BASE)) >> 2)) {
      load_error(&stream, "load RAM space too small for hunk %d\n",
                 m68k_long_to_signed(hunk_index));
    }
    hunk_size[hunk_index] = hunk_value << 2;
    log_load_seg(LOG_DEBUG, "hunk %d size " PRIM68KxSIZE "\n", m68k_long_to_signed(hunk_index),
                 hunk_size[hunk_index]);
    load_ram_size += hunk_size[hunk_index];
    if (load_ram_size > (LOAD_RAM_END - LOAD_RAM_BASE)) {
      load_error(&stream, "load RAM space overflow on hunk %d\n", m68k_long_to_signed(hunk_index));
    }
  }
  hunk_addr[hunk_count] = sizeof(m68k_long_t); /* tricky, seg_next of NULL */

  if (!(load_ram = calloc(load_ram_size, sizeof(*load_ram)))) {
    load_error(&stream, "failed to allocate load RAM (%d bytes)\n",
               m68k_long_to_signed(load_ram_size));
  }
  for (hunk_index = 0; hunk_index < hunk_count; ++hunk_index) {
    m68k_long_t const hunk_type = load_long(&stream, "hunk type") & HUNK_TYPE_MASK;
    m68k_byte_t *const hunk_data = load_ram + (hunk_addr[hunk_index] - LOAD_RAM_BASE);
    log_load_seg(LOG_TRACE, "hunk %d type " PRIM68KxLONG "\n", m68k_long_to_signed(hunk_index),
                 hunk_type);
    m68k_set_long(hunk_data - 8, SEG_LIST_SIZE + hunk_size[hunk_index]);   /* seg_size */
    m68k_set_long(hunk_data - 4, MKBADDR(hunk_addr[hunk_index + 1]) - 1U); /* seg_next */

    switch (hunk_type) {
    case HUNK_CODE:
    case HUNK_DATA: {
      hunk_value = (load_long(&stream, "CODE/DATA size") & HUNK_SIZE_MASK) << 2;
      log_load_seg(LOG_DEBUG, "hunk %d size " PRIM68KxSIZE "\n", m68k_long_to_signed(hunk_index),
                   hunk_value);
      if (hunk_value > hunk_size[hunk_index]) {
        load_error(&stream, "CODE/DATA overflow in hunk %d\n", m68k_long_to_signed(hunk_index));
      } else if (hunk_value &&
                 (hunk_value != fread(hunk_data, sizeof(*hunk_data), hunk_value, stream))) {
        load_error(&stream, "failed to read CODE/DATA hunk %d\n", m68k_long_to_signed(hunk_index));
      }
      break;
    }
    case HUNK_BSS: {
      hunk_value = (load_long(&stream, "BSS size") & HUNK_SIZE_MASK) << 2;
      log_load_seg(LOG_DEBUG, "hunk %d size " PRIM68KxSIZE "\n", m68k_long_to_signed(hunk_index),
                   hunk_value);
      if (hunk_value > hunk_size[hunk_index]) {
        load_error(&stream, "BSS overflow in hunk %d\n", m68k_long_to_signed(hunk_index));
      }
      break;
    }
    default: {
      load_error(&stream, "unsupported type " PRIM68KxLONG " in hunk %d\n", hunk_type,
                 m68k_long_to_signed(hunk_index));
    }
    }

    while (HUNK_END != (hunk_value = load_long(&stream, "sub hunk type"))) {
      switch (hunk_value) {
      case HUNK_RELOC32: {
        m68k_long_t fixup_count;
        switch (hunk_type) {
        case HUNK_BSS: {
          load_error(&stream, "BSS should not be relocatable\n");
        }
        }
        while (fixup_count = load_long(&stream, "fixup count"), fixup_count) {
          if ((hunk_value = load_long(&stream, "fixup hunk")) < hunk_count) {
            m68k_addr_t const fixup_base = hunk_addr[hunk_value];
            m68k_long_t const fixup_size = hunk_size[hunk_value];
            log_load_seg(LOG_TRACE, "hunk %d reloc %d:" PRIM68KxOFFS "\n",
                         m68k_long_to_signed(hunk_index), m68k_long_to_signed(hunk_value),
                         fixup_base);
            do {
              if ((hunk_value = load_long(&stream, "fixup offset"),
                   (hunk_value < hunk_size[hunk_index])) &&
                  (hunk_value + sizeof(m68k_long_t) <= hunk_size[hunk_index])) {
                m68k_byte_t *const fixup_data = hunk_data + hunk_value;
                m68k_long_t const fixup_value = m68k_get_long(fixup_data);
                log_load_seg(LOG_TRACE, "hunk %d:" PRIM68KxOFFS ": " PRIM68KxADDR "\n",
                             m68k_long_to_signed(hunk_index), hunk_value, fixup_value);
                /* lower or _equal_ to allow end reference (e.g. rt_EndSkip) */
                if (fixup_value <= fixup_size) {
                  m68k_set_long(fixup_data, fixup_base + fixup_value);
                } else {
                  load_error(&stream, "invalid fixup target " PRIM68KxADDR "\n", fixup_value);
                }
              } else {
                load_error(&stream, "invalid fixup offset " PRIM68KxOFFS "\n", hunk_value);
              }
            } while (--fixup_count);
          } else {
            load_error(&stream, "invalid fixup hunk %d\n", m68k_long_to_signed(hunk_value));
          }
        }
        break;
      }
      default: {
        load_error(&stream, "unsupported sub type " PRIM68KxLONG " in hunk %d\n", hunk_value,
                   m68k_long_to_signed(hunk_index));
      }
      }
    }
  }

  fclose(stream);
  return MKBADDR(hunk_addr[0] - sizeof(m68k_bptr_t)); /* -> seg_next */
}

/****************************************************************************
 * resident loading
 */

enum ENUM_TYPE_DECL(m68k_word_t) { RTC_MATCHWORD = 0x4AFCU };
enum ENUM_TYPE_DECL(m68k_long_t) {
  /* struct Resident */
  RT_MATCHWORD = 0,
  RT_MATCHTAG = RT_MATCHWORD + sizeof(m68k_word_t),
  RT_ENDSKIP = RT_MATCHTAG + sizeof(m68k_addr_t),
  RT_FLAGS = RT_ENDSKIP + sizeof(m68k_addr_t),
  RT_VERSION = RT_FLAGS + sizeof(m68k_byte_t),
  RT_TYPE = RT_VERSION + sizeof(m68k_byte_t),
  RT_PRI = RT_TYPE + sizeof(m68k_byte_t),
  RT_NAME = RT_PRI + sizeof(m68k_byte_t),
  RT_IDSTRING = RT_NAME + sizeof(m68k_addr_t),
  RT_INIT = RT_IDSTRING + sizeof(m68k_addr_t),
  RT_SIZE = RT_INIT + sizeof(m68k_addr_t),
};

enum ENUM_TYPE_DECL(m68k_byte_t) {
  /* RT_FLAGS */
  RTF_COLDSTART = (m68k_byte_t)(1 << 0),
  RTF_SINGLETASK = (m68k_byte_t)(1 << 1),
  RTF_AFTERDOS = (m68k_byte_t)(1 << 2),
  RTF_AUTOINIT = (m68k_byte_t)(1 << 7)
};

enum ENUM_TYPE_DECL(m68k_long_t) {
  /* struct InitTable */
  IT_DATASIZE = 0,
  IT_FUNCTABLE = IT_DATASIZE + sizeof(m68k_long_t),
  IT_DATAINIT = IT_FUNCTABLE + sizeof(m68k_addr_t),
  IT_INITFUNC = IT_DATAINIT + sizeof(m68k_addr_t),
  IT_SIZE = IT_INITFUNC + sizeof(m68k_addr_t)
};

static int get_seg_list_offset(m68k_bptr_t seg_list, m68k_addr_t address, m68k_long_t *seg_num,
                               m68k_long_t *seg_off) {
  m68k_addr_t seg_addr;
  for (seg_addr = BADDR(seg_list), *seg_num = 0;
       seg_addr && (address >= seg_addr + sizeof(m68k_bptr_t));
       seg_addr = BADDR(m68k_read_immediate_32(seg_addr)), ++*seg_num) {
    m68k_long_t const seg_size = m68k_read_immediate_32(seg_addr - sizeof(m68k_long_t));
    /* includes end-of-segment */
    if (address <= seg_addr + (seg_size - sizeof(m68k_bptr_t))) {
      *seg_off = address - (seg_addr + sizeof(m68k_bptr_t));
      return TRUE;
    }
  }
  *seg_num = M68K_LONG_C(0xFFFFFFFF) /* (m68k_long_t)-1 */;
  *seg_off = M68K_LONG_C(0xFFFFFFFF) /* (m68k_long_t)-1 */;
  return FALSE;
}

static void log_find_res(enum log_level level, char const *format, ...) {
  va_list args;
  log_printf(level, "find_res: ");
  va_start(args, format);
  log_vprintf(level, format, args);
  va_end(args);
}

static m68k_addr_t find_res(m68k_bptr_t seg_list) {
  m68k_addr_t seg_addr;
  for (seg_addr = BADDR(seg_list); seg_addr; seg_addr = BADDR(m68k_read_immediate_32(seg_addr))) {
    m68k_addr_t data_addr;
    m68k_long_t data_size = m68k_read_immediate_32(seg_addr - sizeof(m68k_bptr_t)) - SEG_LIST_SIZE;
    for (data_addr = seg_addr + sizeof(m68k_bptr_t); data_size >= RT_SIZE;
         data_addr += sizeof(m68k_word_t), data_size -= sizeof(m68k_word_t)) {
      m68k_byte_t const *const data_mem = access_load_ram(data_addr, RT_SIZE);
      if (data_mem && (RTC_MATCHWORD == m68k_get_word(data_mem + RT_MATCHWORD))) {
        m68k_addr_t const match_tag = m68k_get_long(data_mem + RT_MATCHTAG);
        m68k_byte_t const res_flags = data_mem[RT_FLAGS];
        m68k_addr_t const init_addr = m68k_get_long(data_mem + RT_INIT);
        log_find_res(LOG_DEBUG, "rt_MatchWord @ " PRIM68KxADDR "\n", data_addr);
        log_find_res(LOG_DEBUG, "rt_MatchTag  = " PRIM68KxADDR "\n", match_tag);
        log_find_res(LOG_DEBUG, "rt_EndSkip   = " PRIM68KxADDR "\n",
                     m68k_get_long(data_mem + RT_ENDSKIP));
        log_find_res(LOG_DEBUG, "rt_Flags     = " PRIM68KxBYTE "\n", res_flags);
        log_find_res(LOG_DEBUG, "rt_Name      = " PRIM68KxADDR "\n",
                     m68k_get_long(data_mem + RT_NAME));
        log_find_res(LOG_DEBUG, "rt_IdString  = " PRIM68KxADDR "\n",
                     m68k_get_long(data_mem + RT_IDSTRING));
        log_find_res(LOG_DEBUG, "rt_Init      = " PRIM68KxADDR "\n", init_addr);
        if (match_tag == data_addr) {
          if (!init_addr ||
              access_load_ram(init_addr,
                              (res_flags & RTF_AUTOINIT) ? IT_SIZE : sizeof(m68k_word_t))) {
            return match_tag;
          }
        }
      }
    }
  }
  return M68K_ADDR_NULL;
}

static void log_init_res(enum log_level level, char const *format, ...) {
  va_list args;
  log_printf(level, "init_res: ");
  va_start(args, format);
  log_vprintf(level, format, args);
  va_end(args);
}

static m68k_long_t get_func_table_length(m68k_addr_t func_table) {
  m68k_long_t count = 0;
  m68k_addr_t address = func_table;
  m68k_byte_t const *memory = access_load_ram(address, sizeof(m68k_long_t));
  if (memory != NULL) {
    m68k_long_t value = m68k_get_long(memory);
    address += sizeof(m68k_long_t);
    if (M68K_LONG_C(0xFFFF0000) == (M68K_LONG_C(0xFFFF0000) & value)) {
      /* relative WORD offsets: -1,*,-1 */
      for (value &= 0xFFFFU; value < 0xFFFFU; ++count, value = m68k_get_word(memory)) {
        memory = access_load_ram(address, sizeof(m68k_word_t));
        address += sizeof(m68k_word_t);
        if (!memory) {
          return 0;
        }
      }
    } else {
      /* absolute ULONG addresses: *,-1 */
      do {
        ++count;
        memory = access_load_ram(address, sizeof(m68k_long_t));
        address += sizeof(m68k_long_t);
        if (NULL == memory) {
          return 0;
        }
        value = m68k_get_long(memory);
      } while (value != M68K_LONG_C(0xFFFFFFFF));
    }
  }
  return count;
}

static m68k_long_t init_res_func_table(m68k_addr_t func_table, m68k_long_t func_count,
                                       m68k_byte_t *res_base, m68k_bptr_t seg_list) {
  m68k_long_t count = func_count ? func_count : get_func_table_length(func_table);
  m68k_byte_t const *table = access_load_ram(func_table, count * sizeof(m68k_word_t));
  if (count && table) {
    m68k_long_t value = m68k_get_long(table);
    table += sizeof(m68k_long_t);
    if (M68K_LONG_C(0xFFFF0000) == (M68K_LONG_C(0xFFFF0000) & value)) {
      m68k_long_t i;
      value &= 0xFFFFU;
      for (i = 0; i < count; ++i, value = m68k_get_word(table), table += sizeof(m68k_word_t)) {
        signed const offset = m68k_word_to_signed(value);
        m68k_long_t const address = (m68k_long_t)((signed)func_table + offset);
        {
          m68k_long_t seg_num, seg_off;
          get_seg_list_offset(seg_list, address, &seg_num, &seg_off);
          log_init_res(LOG_DEBUG, "rel func[-%d] at %d:" PRIM68KxOFFS "\n",
                       m68k_long_to_signed(i) + 1, m68k_long_to_signed(seg_num), seg_off);
        }
        res_base -= sizeof(m68k_addr_t);
        m68k_set_long(res_base, address);
        res_base -= sizeof(m68k_word_t);
        m68k_set_word(res_base, OPCODE_JMP_ABS_L);
      }
    } else {
      m68k_long_t i;
      for (i = 0; i < count; value = m68k_get_long(table), table += sizeof(m68k_long_t), ++i) {
        {
          m68k_long_t seg_num, seg_off;
          get_seg_list_offset(seg_list, value, &seg_num, &seg_off);
          log_init_res(LOG_TRACE, "abs func[-%d] at %d:" PRIM68KxOFFS "\n",
                       m68k_long_to_signed(i) + 1, m68k_long_to_signed(seg_num), seg_off);
        }
        res_base -= sizeof(m68k_addr_t);
        m68k_set_long(res_base, value);
        res_base -= sizeof(m68k_word_t);
        m68k_set_word(res_base, OPCODE_JMP_ABS_L);
      }
    }
  }
  return count * LIB_VECTOR_SIZE;
}

static m68k_addr_t init_res(m68k_addr_t tag_addr, m68k_bptr_t seg_list) {
  m68k_byte_t const *const res_tag = access_load_ram(tag_addr, RT_SIZE);
  if (res_tag) {
    m68k_byte_t const res_flags = res_tag[RT_FLAGS];
    m68k_byte_t const *const init_table =
        access_load_ram(m68k_get_long(res_tag + RT_INIT), IT_SIZE);
    if (!(res_flags & RTF_AUTOINIT) || !init_table) {
      /* manual library initialization is not implemented/supported */
      log_init_res(LOG_ERROR, "unsupported ressource (not AUTOINIT)\n");
    } else if (res_tag[RT_TYPE] != 9 /* NT_LIBRARY */) {
      log_init_res(LOG_ERROR, "unsupported ressource (no library)\n");
    } else {
      m68k_long_t const pos_size = m68k_get_long(init_table + IT_DATASIZE);
      m68k_addr_t const func_table = m68k_get_long(init_table + IT_FUNCTABLE);
      m68k_addr_t const data_init = m68k_get_long(init_table + IT_DATAINIT);
      m68k_addr_t const init_func = m68k_get_long(init_table + IT_INITFUNC);
      m68k_long_t const func_count = get_func_table_length(func_table);
      if (data_init) {
        log_init_res(LOG_WARN, "FIXME: AUTOINIT data init ignored)\n");
      }
      if (func_count < LVO_Translate / LIB_VECTOR_SIZE) {
        log_init_res(LOG_ERROR, "too few functions (no Translate)\n");
      } else if (pos_size < LIB_SIZE) {
        log_init_res(LOG_ERROR, "invalid data size (no Library)\n");
      } else {
        m68k_long_t const neg_size = func_count * LIB_VECTOR_SIZE;
        struct fast_mem_block *const block = alloc_fast_mem_block(neg_size + pos_size);
        m68k_addr_t const res_addr = block->addr + neg_size;
        m68k_byte_t *const res_base = get_fast_mem_block_data(block) + neg_size;
        /* initialize function table */
        init_res_func_table(func_table, func_count, res_base, seg_list);
        /* initialize struct Library */
        res_base[LN_TYPE] = res_tag[RT_TYPE];
        res_base[LN_PRI] = res_tag[RT_PRI];
        m68k_set_long(res_base + LN_NAME, m68k_get_long(res_tag + RT_NAME));
        m68k_set_word(res_base + LIB_NEGSIZE, neg_size);
        m68k_set_word(res_base + LIB_POSSIZE, pos_size);
        m68k_set_word(res_base + LIB_VERSION, res_tag[RT_VERSION]);
        m68k_set_long(res_base + LIB_IDSTRING, m68k_get_long(res_tag + RT_IDSTRING));
        if (init_func) {
          /* REG(D0) struct Library * LibInit(
           *   REG(D0) struct Library * libBase,
           *   REG(A0) BPTR             segList),
           * REG(A6) struct ExecBase * SysBase */
          m68k_long_t const old_a6 = m68k_get_reg(NULL, M68K_REG_A6);
          {
            m68k_long_t seg_num, seg_off;
            get_seg_list_offset(seg_list, init_func, &seg_num, &seg_off);
            log_init_res(LOG_INFO,
                         "calling LibInit(" PRIM68KxADDR "," PRIM68KxBPTR ") at %d:" PRIM68KxOFFS
                         "\n",
                         res_addr, seg_list, m68k_long_to_signed(seg_num), seg_off);
          }
          m68k_set_reg(M68K_REG_D0, res_addr);
          m68k_set_reg(M68K_REG_A0, seg_list);
          m68k_set_reg(M68K_REG_A6, EXEC_LIB_BASE);
          if (call_function(init_func) != res_addr) {
            log_init_res(LOG_FATAL,
                         "LibInit(" PRIM68KxADDR "," PRIM68KxBPTR ") returned " PRIM68KxADDR "\n",
                         res_addr, seg_list, m68k_get_reg(NULL, M68K_REG_D0));
            exit(EXIT_FAILURE);
          }
          m68k_set_reg(M68K_REG_A6, old_a6);
        }
        return res_addr;
      }
    }
  }
  return M68K_ADDR_NULL;
}

/****************************************************************************
 * TranslateAs (SetAccent/Translate)
 */

static void log_translate(enum log_level level, char const *format, ...) {
  va_list args;
  log_printf(level, "translate: ");
  va_start(args, format);
  log_vprintf(level, format, args);
  va_end(args);
}

static m68k_addr_t translate_open(char const *lib_path) {
  m68k_bptr_t const seg_list = load_seg(lib_path);
  if (!seg_list) {
    log_load_seg(LOG_ERROR, "failed to load \"%s\"\n", lib_path);
  } else {
    m68k_addr_t const tag_addr = find_res(seg_list);
    if (!tag_addr) {
      /* fallback (calling seg_list + 4) is not implemented/supported */
      log_find_res(LOG_ERROR, "unsupported library (no Resident struct)\n");
    } else {
      m68k_addr_t res_base;
      {
        m68k_long_t seg_num, seg_off;
        get_seg_list_offset(seg_list, tag_addr, &seg_num, &seg_off);
        log_find_res(LOG_INFO, "Resident struct found at %d:" PRIM68KxOFFS "\n",
                     m68k_long_to_signed(seg_num), seg_off);
      }
      /* we need a 32-bit CPU (68020+) because the input string
       * address mapping is above the 24-bit limit (0x00FFFFFF) */
      log_emulator(LOG_DEBUG, "Musashi init\n");
      m68k_init();
      m68k_set_cpu_type(M68K_CPU_TYPE_68020);
      m68k_set_pc_changed_callback(pc_changed_callback);
      m68k_pulse_reset();
      /* init library */
      log_init_res(LOG_INFO, "calling InitResident(" PRIM68KxADDR "," PRIM68KxBPTR ")\n", tag_addr,
                   seg_list);
      res_base = init_res(tag_addr, seg_list);
      if (!res_base) {
        log_init_res(LOG_FATAL, "InitResident(" PRIM68KxADDR "," PRIM68KxBPTR ") failed\n",
                     tag_addr, seg_list);
      } else {
        m68k_addr_t lib_base;
        log_printf(LOG_INFO, "open_lib: calling LibOpen(" PRIM68KxADDR ")\n", res_base);
        /* REG(D0) struct Library * LibOpen(VOID),
         * REG(A6) struct Library * libBase */
        lib_base = call_lib_func(res_base, LVO_LibOpen);
        if (!lib_base) {
          log_printf(LOG_ERROR, "open_lib: LibOpen(" PRIM68KxADDR ") failed\n", res_base);
        } else {
          return lib_base;
        }
      }
    }
  }
  return M68K_ADDR_NULL;
}

static int translate_init(m68k_addr_t lib_base, char const *accent) {
  /* REG(D0) LONG SetAccent(
   *   REG(A0) CONST_STRPTR name),
   * REG(A6) struct Library * TranslatorBase */
  if (accent && *accent) {
    m68k_long_t success;
    m68k_addr_t basename;
    log_translate(LOG_INFO, "calling SetAccent(\"%s\")\n", accent);
    basename = alloc_fast_mem_string(accent);
    m68k_set_reg(M68K_REG_A0, basename);
    success = call_lib_func(lib_base, LVO_SetAccent);
    free_fast_mem(basename);
    if (!success) {
      log_translate(LOG_ERROR, "SetAccent(\"%s\") failed\n", accent);
      return FALSE;
    }
  }
  return TRUE;
}

static m68k_long_t translate_text(m68k_addr_t lib_base, struct fast_mem_block *output) {
  /* REG(D0) LONG Translate(
   *   REG(A0) CONST_STRPTR inputString,
   *   REG(D0) LONG         inputLength,
   *   REG(A1) STRPTR       outputBuffer,
   *   REG(D1) LONG         bufferSize),
   * REG(A6) struct Library * TranslatorBase */
  log_translate(LOG_INFO, "calling Translate(%d)\n", m68k_long_to_signed(input_string_len));
  m68k_set_reg(M68K_REG_A0, INPUT_STRING_BASE);
  m68k_set_reg(M68K_REG_D0, input_string_len);
  m68k_set_reg(M68K_REG_A1, output->addr);
  m68k_set_reg(M68K_REG_D1, output->size - 1);
  return call_lib_func(lib_base, LVO_Translate);
}

static int translate(char const *lib_path, char const *accent, char const *text) {
  m68k_addr_t lib_base = translate_open(lib_path);
  if (lib_base && translate_init(lib_base, accent)) {
    struct fast_mem_block *output = alloc_fast_mem_block(0x1000);
    char *const output_str = (char *)get_fast_mem_block_data(output);
    input_string = (m68k_byte_t const *)text;
    input_string_len = strlen(text);
    for (;;) {
      signed offset = -m68k_long_to_signed(translate_text(lib_base, output));
      if (offset < 0) {
        log_translate(LOG_ERROR, "Translate(failed) with error code %d\n", -offset);
        break;
      }

      if (!*output_str) {
        log_translate(LOG_WARN, "Translate() output is empty\n");
      } else {
        printf("%s", output_str);
      }
      if (0 == offset) {
        /*FIXME: "./narrator -" requires a newline and only translates first line */
        printf("\n");
        return EXIT_SUCCESS;
      }

      if (input_string_len <= (m68k_long_t)(unsigned)offset) {
        log_translate(LOG_ERROR, "Translate() input overflow\n");
        break;
      }
      *output_str = '\0';
      input_string += offset;
      input_string_len -= (m68k_long_t)(unsigned)offset;
    }
  }
  return EXIT_FAILURE;
}

/****************************************************************************
 * program entry point
 */

static void opt_error(char const *format, ...) {
  va_list args;
  log_printf(LOG_FATAL, "%s: ", program_name);
  va_start(args, format);
  log_vprintf(LOG_FATAL, format, args);
  va_end(args);
  exit(EXIT_FAILURE);
}

static void print_help(void) {
  log_printf(LOG_INFO, "\n");
  log_printf(LOG_NONE, "Usage: %s [-command|options...] [--] [accent] text\n", program_name);
  log_printf(LOG_INFO, "\n"
                       "Arguments:\n"
                       "\n");
  log_printf(LOG_INFO,
             "  accent  [optional] base name of the *.accent file that\n"
             "          will be loaded before translation.\n"
             "          (defaults to \"%s\")\n"
             "          \n"
             "          Please note that the relative part of the accent\n"
             "          filename is always converted to lowercase when opened.\n"
             "          If your host file system is case-sensitive,\n"
             "          the *.accent filenames must also be lowercase.\n"
             "          \n"
             "          If the accent argument is an empty string,\n"
             "          SetAccent() is not called before Translate()\n"
             "          and the default accent of the library is used\n"
             "          ('american' for the V42 translator.library).\n"
             "\n",
             opt_accent_default);
  log_printf(LOG_INFO,
             "  text    [required] string that will be converted to\n"
             "          phonemes for use with the Amiga Narrator device,\n"
             "          and output to stdout (infos/errors go to stderr).\n"
             "          \n"
             "          This tool does neither map nor convert any characters,\n"
             "          and just passes it as-is to the library functions.\n"
             "          Use tools like '%s' to convert the input string\n"
             "          (ISO-8859-1 is close to the Amiga character set).\n"
             "          \n"
             "          The well-known '-' alias for reading from stdin\n"
             "          is not supported. This project is open source,\n"
             "          you are very welcome to implement this feature.\n"
             "\n",
             "iconv");
  log_printf(LOG_INFO, "Commands:\n"
                       "\n"
                       "  -h, --help      display this help and exit\n"
                       "  -V, --version   print program version and exit\n"
                       "\n");
  log_printf(LOG_INFO,
             "Options:\n"
             "\n"
             "  -d, --accent_dir[=]DIR  *.accent filepath prefix\n"
             "                          (defaults to '%s')\n"
             "  -l, --lib_path[=]PATH   translator.library filepath\n"
             "                          (defaults to '%s')\n"
             "  -s, --silent            disable stderr log (level %s=%d))\n"
             "  -q, --quiet             decrease stderr log level\n"
             "  -v, --verbose           increase stderr log level\n"
             "                          (%s=%d..%s=%d, currently %s=%d)\n"
             "      --                  end of options\n"
             "\n",
             opt_accent_dir_default, opt_lib_path_default, get_log_level_name(LOG_NONE), LOG_NONE,
             get_log_level_name(LOG_FATAL), LOG_FATAL, get_log_level_name(LOG_TRACE), LOG_TRACE,
             get_log_level_name(log_level), log_level);
}

static void print_version(void) {
  log_printf(LOG_NONE, "%s (AmigaNarrator) %d.%d\n", program_name, PROGRAM_VERSION_MAJOR,
             PROGRAM_VERSION_MINOR);
  log_printf(LOG_INFO,
             "Copyright (C) 2024 Nico Bendlin <nico@nicode.net>.\n"
             "License GPLv3+: GNU GPL version 3 or later"
             " <https://gnu.org/licenses/gpl.html>.\n"
             "This is free software:"
             " you are free to change and redistribute it.\n"
             "There is NO WARRANTY, to the extent permitted by law.\n"
             "\n"
             "%s uses Musashi <https://github.com/kstenerud/Musashi>\n",
             program_name);
}

int main(int argc, char **argv) {
  /* options */
  char const *lib_path = opt_lib_path_default;
  char const *accent = opt_accent_default;
  for (--argc, ++argv; (argc > 0) && ('-' == **argv); --argc, ++argv) {
    char sarg[2];
    char *arg = *argv + 1;
    if ('\0' == *arg) {
      opt_error("reading text from stdin (-) is not supported\n");
    }
    if ('-' == *arg) {
      if ('\0' == *++arg) {
        --argc, ++argv;
        break;
      }
      if (0 == strcmp(arg, "help")) {
        *sarg = 'h';
      } else if (0 == strcmp(arg, "version")) {
        *sarg = 'V';
      } else if (0 == strcmp(arg, "silent")) {
        *sarg = 's';
      } else if (0 == strcmp(arg, "quiet")) {
        *sarg = 'q';
      } else if (0 == strcmp(arg, "verbose")) {
        *sarg = 'v';
      } else if (0 == strncmp(arg, "accent_dir", 10)) {
        *sarg = 'd';
        if (arg[10] != '\0') {
          if (arg[10] != '=') {
            opt_error("unknown option --%s\n", arg);
          }
          arg = &arg[10 + 1];
          if (('"' == *arg) && (arg[1] != '\0')) {
            size_t const end = strlen(arg) - 1;
            if ('"' == arg[end]) {
              arg[end] = '\0';
              ++arg;
            }
          }
          accent_dir = arg;
          continue;
        }
      } else if (0 == strncmp(arg, "lib_path", 8)) {
        *sarg = 'l';
        if (arg[8] != '\0') {
          if (arg[8] != '=') {
            opt_error("unknown option --%s\n", arg);
          }
          arg = &arg[8 + 1];
          if (('"' == *arg) && (arg[1] != '\0')) {
            size_t const end = strlen(arg) - 1;
            if ('"' == arg[end]) {
              arg[end] = '\0';
              ++arg;
            }
          }
          if ('\0' == *arg) {
            opt_error("lib_path argument missing\n");
          }
          lib_path = arg;
          continue;
        }
      } else {
        opt_error("unknown option --%s\n", arg);
      }
      sarg[1] = '\0';
      arg = sarg;
    }
    for (; *arg != '\0'; ++arg) {
      switch (*arg) {
      case 'h': {
        return print_help(), EXIT_SUCCESS;
      }
      case 'V': {
        return print_version(), EXIT_SUCCESS;
      }
      case 's': {
        log_level = LOG_NONE;
        break;
      }
      case 'q': {
        if (log_level > LOG_NONE) {
          log_level = (enum log_level)((int)log_level - 1);
        }
        break;
      }
      case 'v': {
        if (log_level < LOG_TRACE) {
          log_level = (enum log_level)((int)log_level + 1);
        }
        break;
      }
      case 'd': {
        if (arg[1] != '\0') {
          opt_error("-d (accent_dir) must be last short option\n");
        }
        accent_dir = (--argc, *++argv);
        break;
      }
      case 'l': {
        if (arg[1] != '\0') {
          opt_error("-l (lib_path) must be last short option\n");
        }
        lib_path = (--argc, *++argv);
        break;
      }
      default: {
        opt_error("invalid option -%c\n", *arg);
      }
      }
    }
  }
  /* arguments */
  if (argc >= 2) {
    accent = (--argc, *argv++);
  }
  if (argc > 1) {
    opt_error("too many arguments (see --help)\n");
  } else if (argc < 1) {
    opt_error("text argument missing (see --help)\n");
  } else if (!*argv || !**argv) {
    log_printf(LOG_WARN, "%s: text is empty, skipping translation\n", program_name);
    return EXIT_SUCCESS;
  } else {
    return translate(lib_path, accent, *argv);
  }
  opt_error("invalid arguments (see --help )\n");
  return EXIT_FAILURE;
}
