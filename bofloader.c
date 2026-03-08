

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <windows.h>

/* ───────────────────────────────────────────────────────────────────────────
 *  Big-endian stream reader
 * ─────────────────────────────────────────────────────────────────────────── */

typedef struct
{
    const uint8_t *cursor;
    uint32_t       remaining;
} be_stream_t;

static void stream_init(be_stream_t *s, const uint8_t *data, uint32_t len)
{
    s->cursor    = data;
    s->remaining = len;
}

static uint32_t stream_read_be32(be_stream_t *s)
{
    if (s->remaining < 4)
        return 0;
    uint32_t v = (s->cursor[0] << 24) | (s->cursor[1] << 16)
               | (s->cursor[2] <<  8) |  s->cursor[3];
    s->cursor    += 4;
    s->remaining -= 4;
    return v;
}

static const uint8_t *stream_read_bytes(be_stream_t *s, uint32_t len)
{
    if (s->remaining < len)
        return NULL;
    const uint8_t *out = s->cursor;
    s->cursor    += len;
    s->remaining -= len;
    return out;
}

static const uint8_t *stream_read_len_prefixed(be_stream_t *s, uint32_t *out_len)
{
    uint32_t len = stream_read_be32(s);
    if (out_len)
        *out_len = len;
    return stream_read_bytes(s, len);
}

/* ───────────────────────────────────────────────────────────────────────────
 *  Types
 * ─────────────────────────────────────────────────────────────────────────── */

typedef struct
{
    const uint8_t *src;
    uint32_t       size;
    uint8_t       *dest;
} section_t;

typedef struct
{
    uint32_t    entry_offset;
    section_t   text;
    section_t   sec2;
    section_t   sec3;
    section_t   sec4;
    section_t   sec5;
    section_t   reloc;
    section_t   args;
    uint8_t    *bss;
    uint32_t    bss_size;
    uint8_t   **func_table;
    size_t      func_table_size;
    uint16_t    alloc_type;
    uint8_t    *base;
} loader_ctx_t;

/* ───────────────────────────────────────────────────────────────────────────
 *  Helpers
 * ─────────────────────────────────────────────────────────────────────────── */

static size_t align16(size_t v)
{
    return (v + 15u) & ~((size_t)15u);
}

static uint8_t **reserve_func_slot(uint8_t **table, size_t table_slots, uintptr_t target)
{
    printf("[*] Reserving function slot for target %p\n", (void *)target);
    for (size_t i = 0; i < table_slots; ++i)
    {
        if (table[i] == (uint8_t *)target)
        {
            printf("[*] Found existing function slot %u for %p\n", (unsigned int)i, (void *)target);
            return &table[i];
        }
    }
    for (size_t i = 0; i < table_slots; ++i)
    {
        if (table[i] == NULL)
        {
            table[i] = (uint8_t *)target;
            printf("[*] Assigned new function slot %u for %p\n", (unsigned int)i, (void *)target);
            return &table[i];
        }
    }
    printf("[*] Failed to reserve function slot for %p\n", (void *)target);
    return NULL;
}

/* ───────────────────────────────────────────────────────────────────────────
 *  Dummy Beacon API stubs
 *
 *  Slot layout matches the order InitializeBeaconApiTable writes at runtime
 *  (same order as the DECLSPEC_IMPORT list in beacon.h).
 *
 *  Signature: 4 pointer-width params covers every Beacon API on x64
 *  (register args RCX/RDX/R8/R9).  APIs that pass extra args on the stack
 *  (e.g. BeaconInjectProcess) just ignore them.  Return intptr_t so that
 *  returning 0 works as both NULL and integer 0.
 * ─────────────────────────────────────────────────────────────────────────── */

#define BEACON_STUB(SLOT, NAME)                                                  \
    static intptr_t stub_##NAME(void *a0, void *a1, void *a2, void *a3)         \
    {                                                                            \
        (void)a0; (void)a1; (void)a2; (void)a3;                                 \
        printf("[Beacon API %d] %s called!\n", SLOT, #NAME);                    \
        return 0;                                                                \
    }

/* Data API */
BEACON_STUB( 0, BeaconDataParse)
BEACON_STUB( 1, BeaconDataInt)
BEACON_STUB( 2, BeaconDataShort)
BEACON_STUB( 3, BeaconDataLength)
BEACON_STUB( 4, BeaconDataExtract)

/* Format API */
BEACON_STUB( 5, BeaconFormatAlloc)
BEACON_STUB( 6, BeaconFormatReset)
BEACON_STUB( 7, BeaconFormatFree)
BEACON_STUB( 8, BeaconFormatAppend)
BEACON_STUB( 9, BeaconFormatPrintf)
BEACON_STUB(10, BeaconFormatToString)
BEACON_STUB(11, BeaconFormatInt)

/* Output API */
static intptr_t stub_BeaconPrintf(void *a0, void *a1, ...)
{
    (void)a0; /* type – ignored, we just print to stdout */
    char *fmt = (char *)a1;
    if (!fmt) return 0;
    va_list va;
    va_start(va, a1);
    vprintf(fmt, va);
    va_end(va);
    return 0;
}
BEACON_STUB(13, BeaconOutput)

/* Token API */
BEACON_STUB(14, BeaconUseToken)
BEACON_STUB(15, BeaconRevertToken)
BEACON_STUB(16, BeaconIsAdmin)

/* Spawn+Inject API */
BEACON_STUB(17, BeaconGetSpawnTo)
BEACON_STUB(18, BeaconInjectProcess)
BEACON_STUB(19, BeaconInjectTemporaryProcess)
BEACON_STUB(20, BeaconCleanupProcess)

/* Utility */
BEACON_STUB(21, toWideChar)

#define BEACON_API_COUNT 22

typedef intptr_t (*beacon_stub_t)(void *, void *, void *, void *);

static void init_dummy_beacon_table(uint8_t **table, size_t table_size)
{
    static const beacon_stub_t stubs[BEACON_API_COUNT] = {
        stub_BeaconDataParse,               /* 0  */
        stub_BeaconDataInt,                 /* 1  */
        stub_BeaconDataShort,               /* 2  */
        stub_BeaconDataLength,              /* 3  */
        stub_BeaconDataExtract,             /* 4  */
        stub_BeaconFormatAlloc,             /* 5  */
        stub_BeaconFormatReset,             /* 6  */
        stub_BeaconFormatFree,              /* 7  */
        stub_BeaconFormatAppend,            /* 8  */
        stub_BeaconFormatPrintf,            /* 9  */
        stub_BeaconFormatToString,          /* 10 */
        stub_BeaconFormatInt,               /* 11 */
        stub_BeaconPrintf,                  /* 12 */
        stub_BeaconOutput,                  /* 13 */
        stub_BeaconUseToken,                /* 14 */
        stub_BeaconRevertToken,             /* 15 */
        stub_BeaconIsAdmin,                 /* 16 */
        stub_BeaconGetSpawnTo,              /* 17 */
        stub_BeaconInjectProcess,           /* 18 */
        stub_BeaconInjectTemporaryProcess,  /* 19 */
        stub_BeaconCleanupProcess,          /* 20 */
        stub_toWideChar,                    /* 21 */
    };

    printf("[*] Populating dummy Beacon API table (%zu slots available)\n", table_size);
    for (size_t i = 0; i < BEACON_API_COUNT; i++)
    {
        if (i < table_size)
        {
            table[i] = (uint8_t *)stubs[i];
            printf("[*]  [%02zu] = %p (dummy)\n", i, (void *)stubs[i]);
        }
    }
}

/* ───────────────────────────────────────────────────────────────────────────
 *  Relocation
 * ─────────────────────────────────────────────────────────────────────────── */

static int apply_reloc(const uint8_t *rec, uintptr_t section_base,
                       uintptr_t reloc_base, uintptr_t target_base, int addend)
{
    uint16_t type   = *(const uint16_t *)(rec + 4);
    uint32_t offset = *(const uint32_t *)(rec + 8);

    printf("[*] Applying reloc type %u offset 0x%x target %p addend %d\n",
           (unsigned int)type, (unsigned int)offset, (void *)target_base, addend);

    if ((uint16_t)(type - 4) <= 5)
    {
        uint32_t  *patch = (uint32_t *)(section_base + offset);
        uintptr_t  value = target_base + addend + *patch;
        uintptr_t  rip   = reloc_base  + offset + type;
        *patch = (uint32_t)(value - rip);
        return 1;
    }

    if (type == 1)
    {
        uint64_t *patch = (uint64_t *)(reloc_base + offset);
        *patch += target_base + addend;
        return 1;
    }

    if (type == 3)
    {
        uint32_t  *patch = (uint32_t *)(reloc_base + offset);
        uintptr_t  where = (uintptr_t)patch;
        *patch += (uint32_t)(target_base - where + addend - 4);
        return 1;
    }

    printf("[*] Unsupported reloc type %u at offset 0x%x\n",
           (unsigned int)type, (unsigned int)offset);
    return 0;
}

static int apply_relocations(loader_ctx_t *ctx)
{
    be_stream_t s;
    stream_init(&s, ctx->reloc.src, ctx->reloc.size);

    printf("[*] Applying relocations (%u bytes)\n", (unsigned int)ctx->reloc.size);

    while (s.remaining >= 16)
    {
        const uint8_t *rec = stream_read_bytes(&s, 16);
        if (!rec)
            return 0;

        uint32_t base = *(const uint32_t *)rec;
        uint16_t sym  = *(const uint16_t *)(rec + 6);

        printf("[*] Reloc record base %u sym %u\n", (unsigned int)base, (unsigned int)sym);

        uintptr_t reloc_section = 0;
        uintptr_t reloc_base    = 0;

        if (base == 1026) // text
        {
            reloc_section = (uintptr_t)ctx->text.dest;
            reloc_base    = (uintptr_t)ctx->base;
        }
        else if (base == 1025)
        {
            reloc_section = (uintptr_t)ctx->sec3.dest;
            reloc_base    = reloc_section;
        }
        else if (base == 1030) // sec5
        {
            reloc_section = (uintptr_t)ctx->sec5.dest;
            reloc_base    = reloc_section;
        }
        else
        {
            printf("[*] Unknown reloc base %u\n", (unsigned int)base);
            return 0;
        }

        uintptr_t target = 0;
        int addend       = *(const uint32_t *)(rec + 12);

        if (sym == 1028)
        {
            printf("[*] Relocations end marker reached\n");
            return 1;
        }

        switch (sym)
        {
        case 1024:
            target = (uintptr_t)ctx->sec2.dest;
            break;
        case 1025:
            target = (uintptr_t)ctx->sec3.dest;
            break;
        case 1026:
            target = (uintptr_t)ctx->base;
            break;
        case 1027:
        {
            uint32_t    len1 = 0, len2 = 0;
            const char *dll  = (const char *)stream_read_len_prefixed(&s, &len1);
            const char *name = (const char *)stream_read_len_prefixed(&s, &len2);
            if (!dll || !name)
                return 0;
            HMODULE mod = GetModuleHandleA(dll);
            if (!mod)
                mod = LoadLibraryA(dll);
            FARPROC proc = mod ? GetProcAddress(mod, name) : NULL;
            if (!proc)
                return 0;
            printf("[*] Resolved import %s!%s to %p\n", dll, name, (void *)proc);
            uint8_t **slot = reserve_func_slot(ctx->func_table, ctx->func_table_size, (uintptr_t)proc);
            if (!slot)
                return 0;
            target = (uintptr_t)slot;
            break;
        }
        case 1029:
            target = (uintptr_t)ctx->sec4.dest;
            break;
        case 1031:
            target = (uintptr_t)ctx->bss;
            break;
        default:
            if (sym >= ctx->func_table_size)
            {
                printf("[*] Reloc sym %u exceeds func table slots\n", (unsigned int)sym);
                return 0;
            }
            target = (uintptr_t)(ctx->func_table + sym);
            break;
        }

        if (!apply_reloc(rec, reloc_section, reloc_base, target, addend))
            return 0;
    }

    return 1;
}

/* ───────────────────────────────────────────────────────────────────────────
 *  Image preparation
 * ─────────────────────────────────────────────────────────────────────────── */

// Scan the relocation stream to figure out how many func_table slots are needed.
static size_t count_slots_needed(loader_ctx_t *ctx)
{
    be_stream_t s;
    stream_init(&s, ctx->reloc.src, ctx->reloc.size);

    size_t count   = 0;
    size_t max_idx = 0;

    while (s.remaining >= 16)
    {
        const uint8_t *rec = stream_read_bytes(&s, 16);
        if (!rec) break;

        uint16_t sym = *(const uint16_t *)(rec + 6);

        if (sym == 1027) // import record -- has two trailing length-prefixed strings
        {
            uint32_t len = 0;
            stream_read_len_prefixed(&s, &len); // dll name
            stream_read_len_prefixed(&s, &len); // symbol name
            count++;
        }
        else if (sym == 1028) // end marker
        {
            break;
        }
        else if (sym >= 1024 && sym <= 1031)
        {
            // other well-known section symbols, skip
        }
        else
        {
            if (sym > max_idx) max_idx = sym;
        }
    }

    size_t needed = count;
    if (max_idx + 1 > needed) needed = max_idx + 1;

    // Reserve at least 128 base slots (Beacon's internal usage) plus the
    // import count on top, matching hook.c's sizing logic.
    size_t reserved = (max_idx + 1 > 128) ? (max_idx + 1) : 128;
    return reserved + count;
}

static int prepare_image(loader_ctx_t *ctx, const uint8_t *data, uint32_t len)
{
    be_stream_t s;
    stream_init(&s, data, len);

    printf("[*] Preparing image from buffer (%u bytes)\n", (unsigned int)len);

    ctx->bss_size     = stream_read_be32(&s);
    ctx->text.src     = stream_read_len_prefixed(&s, &ctx->text.size);
    ctx->sec2.src     = stream_read_len_prefixed(&s, &ctx->sec2.size);
    ctx->sec3.src     = stream_read_len_prefixed(&s, &ctx->sec3.size);
    ctx->sec4.src     = stream_read_len_prefixed(&s, &ctx->sec4.size);
    ctx->sec5.src     = stream_read_len_prefixed(&s, &ctx->sec5.size);
    ctx->reloc.src    = stream_read_len_prefixed(&s, &ctx->reloc.size);
    ctx->entry_offset = stream_read_be32(&s);
    ctx->args.src     = stream_read_len_prefixed(&s, &ctx->args.size);

    printf("[*] Sections: text=%u sec2=%u sec3=%u sec4=%u sec5=%u bss=%u reloc=%u args=%u entry=0x%x\n",
           (unsigned int)ctx->text.size,  (unsigned int)ctx->sec2.size,
           (unsigned int)ctx->sec3.size,  (unsigned int)ctx->sec4.size,
           (unsigned int)ctx->sec5.size,  (unsigned int)ctx->bss_size,
           (unsigned int)ctx->reloc.size, (unsigned int)ctx->args.size,
           (unsigned int)ctx->entry_offset);

    if (!ctx->text.src || !ctx->reloc.src)
        return 0;

    // Compute offsets (relative to base, fixed up after VirtualAlloc).
    size_t total = 0;
    total = align16(total);
    ctx->text.dest = (uint8_t *)(uintptr_t)total;
    total += ctx->text.size;
    total = align16(total);
    ctx->sec2.dest = (uint8_t *)(uintptr_t)total;
    total += ctx->sec2.size;
    total = align16(total);
    ctx->sec3.dest = (uint8_t *)(uintptr_t)total;
    total += ctx->sec3.size;
    total = align16(total);
    ctx->sec4.dest = (uint8_t *)(uintptr_t)total;
    total += ctx->sec4.size;
    total = align16(total);
    ctx->sec5.dest = (uint8_t *)(uintptr_t)total;
    total += ctx->sec5.size;
    total = align16(total);
    ctx->bss       = (uint8_t *)(uintptr_t)total;
    total += ctx->bss_size;
    total = align16(total);

    // Dynamic function table -- sized by scanning relocations.
    ctx->func_table_size = count_slots_needed(ctx);
    ctx->func_table      = (uint8_t **)malloc(ctx->func_table_size * sizeof(void *));
    if (!ctx->func_table)
        return 0;
    memset(ctx->func_table, 0, ctx->func_table_size * sizeof(void *));

    ctx->base = (uint8_t *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ctx->base)
        return 0;

    printf("[*] Allocated image base %p size 0x%x\n", (void *)ctx->base, (unsigned int)total);

    // Fix up destination pointers to actual addresses.
    ctx->text.dest += (uintptr_t)ctx->base;
    ctx->sec2.dest += (uintptr_t)ctx->base;
    ctx->sec3.dest += (uintptr_t)ctx->base;
    ctx->sec4.dest += (uintptr_t)ctx->base;
    ctx->sec5.dest += (uintptr_t)ctx->base;
    ctx->bss       += (uintptr_t)ctx->base;

    memcpy(ctx->text.dest, ctx->text.src, ctx->text.size);
    memcpy(ctx->sec2.dest, ctx->sec2.src ? ctx->sec2.src : (const uint8_t *)"", ctx->sec2.size);
    if (ctx->sec3.size)
        memcpy(ctx->sec3.dest, ctx->sec3.src, ctx->sec3.size);
    if (ctx->sec4.size)
        memcpy(ctx->sec4.dest, ctx->sec4.src, ctx->sec4.size);
    if (ctx->sec5.size)
        memcpy(ctx->sec5.dest, ctx->sec5.src, ctx->sec5.size);
    if (ctx->bss_size)
        memset(ctx->bss, 0, ctx->bss_size);

    if (ctx->args.size)
    {
        ctx->args.dest = (uint8_t *)malloc(ctx->args.size);
        memcpy(ctx->args.dest, ctx->args.src, ctx->args.size);
        printf("[*] Copied args to %p (%u bytes)\n", (void *)ctx->args.dest, (unsigned int)ctx->args.size);
    }

    ctx->alloc_type = 2; // already executable, skip VirtualProtect later
    printf("[*] Allocated function table %p (dynamic, %zu slots)\n", (void *)ctx->func_table, ctx->func_table_size);
    return 1;
}

static void free_image(loader_ctx_t *ctx)
{
    printf("[*] Freeing image resources\n");
    if (ctx->base)
        VirtualFree(ctx->base, 0, MEM_RELEASE);
    if (ctx->args.dest)
        free(ctx->args.dest);
    if (ctx->func_table)
        free(ctx->func_table);
}

/* ───────────────────────────────────────────────────────────────────────────
 *  BOFLoader
 * ─────────────────────────────────────────────────────────────────────────── */

static int BOFLoader(const uint8_t *data, uint32_t len)
{
    loader_ctx_t ctx = {0};

    printf("\n\n[*] BOFLoader start\n");

    if (!prepare_image(&ctx, data, len))
    {
        printf("[*] BOFLoader prepare_image failed\n");
        return 0;
    }

    // Populate function table with dummy Beacon API stubs (replaces the
    // InitializeBeaconApiTable call that hook.c makes into the mapped DLL).
    if (ctx.func_table != NULL)
    {
        printf("[*] Beacon init: populating dummy API stubs into func_table=%p\n",
               (void *)ctx.func_table);
        init_dummy_beacon_table(ctx.func_table, ctx.func_table_size);

        printf("[*] Beacon table after dummy init:\n");
        for (size_t i = 0; i < ctx.func_table_size; i++)
        {
            if (ctx.func_table[i] != NULL)
                printf("[*]  [%02zu] = %p\n", i, (void *)ctx.func_table[i]);
        }
    }
    else
    {
        printf("[*] Beacon init skipped: func_table is NULL\n");
    }

    int ok = apply_relocations(&ctx);
    if (ok)
    {
        uint8_t *entry = ctx.base + ctx.entry_offset;
        DWORD oldProt  = 0;
        if (ctx.alloc_type == 2 || VirtualProtect(ctx.base, ctx.text.size, PAGE_EXECUTE_READWRITE, &oldProt))
        {
            printf("[*] Jumping to entry %p (args %p len %u)\n",
                   (void *)entry, (void *)ctx.args.dest, (unsigned int)ctx.args.size);
            void (*entry_fn)(uint64_t, uint32_t) = (void (*)(uint64_t, uint32_t))entry;
            entry_fn((uint64_t)ctx.args.dest, ctx.args.size);
        }
        else
        {
            ok = 0;
        }
    }

    printf("[*] BOFLoader finished with %s\n", ok ? "success" : "failure");
    free_image(&ctx);
    return ok;
}

/* ───────────────────────────────────────────────────────────────────────────
 *  main  (from main.c)
 * ─────────────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    const char *filename = "bof.blob"; // default filename
    
    if (argc >= 2)
    {
        filename = argv[1];
    }
    else
    {
        printf("Usage: %s <bof_file>\n", argv[0]);
        printf("Using default file: %s\n", filename);
    }

    // Read BOF blob from file
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        printf("Failed to open %s\n", filename);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *bof_buffer = (uint8_t *)malloc(file_size);
    if (!bof_buffer)
    {
        printf("Failed to allocate memory\n");
        fclose(f);
        return 1;
    }

    size_t read_size = fread(bof_buffer, 1, file_size, f);
    fclose(f);

    if (read_size != (size_t)file_size)
    {
        printf("Failed to read %s\n", filename);
        free(bof_buffer);
        return 1;
    }

    printf("Loading BOF-like payload from %s (size %zu bytes)...\n", filename, file_size);
    int ok = BOFLoader(bof_buffer, (uint32_t)file_size);
    printf("Execution %s.\n", ok ? "succeeded" : "failed");
    free(bof_buffer);
    return ok ? 0 : 1;
}