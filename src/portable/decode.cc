#include "nias/decode.hh"

#include <Zydis/Zydis.h>

#include <cstring>

namespace nias {

namespace {

bool init_decoder(ZydisDecoder& dec) noexcept {
    return ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64,
                                         ZYDIS_STACK_WIDTH_64));
}

}  // namespace

DecodeInfo decode_at(const std::uint8_t* code, std::size_t avail,
                     std::uint64_t /*runtime_addr*/) noexcept {
    DecodeInfo di;
    if (code == nullptr || avail == 0) {
        return di;
    }

    ZydisDecoder dec;
    if (!init_decoder(dec)) {
        return di;
    }

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code, avail, &insn, ops))) {
        return di;
    }

    di.valid = true;
    di.length = insn.length;

    if (const char* m = ZydisMnemonicGetString(insn.mnemonic)) {
        std::strncpy(di.mnemonic, m, sizeof(di.mnemonic) - 1);
    }

    switch (insn.meta.category) {
        case ZYDIS_CATEGORY_CALL:
            di.is_branch = di.is_call = true;
            break;
        case ZYDIS_CATEGORY_RET:
            di.is_branch = di.is_ret = true;
            break;
        case ZYDIS_CATEGORY_COND_BR:
        case ZYDIS_CATEGORY_UNCOND_BR:
            di.is_branch = true;
            break;
        default:
            break;
    }

    for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
        const ZydisDecodedOperand& op = ops[i];
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) {
            continue;
        }
        if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) {
            di.reads_memory = true;
        }
        if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
            di.writes_memory = true;
        }
        if (di.mem_base_reg < 0 && op.mem.base != ZYDIS_REGISTER_NONE) {
            di.mem_base_reg = static_cast<std::int32_t>(op.mem.base);
        }
    }

    return di;
}

std::uint32_t scan_prologue_alloc(const std::uint8_t* fn_start,
                                  std::size_t avail) noexcept {
    if (fn_start == nullptr || avail == 0) {
        return 0;
    }
    ZydisDecoder dec;
    if (!init_decoder(dec)) {
        return 0;
    }

    std::uint32_t total = 0;
    std::size_t off = 0;
    for (int steps = 0; steps < 32 && off < avail; ++steps) {
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, fn_start + off,
                                                 avail - off, &insn, ops))) {
            break;
        }
        if (insn.mnemonic == ZYDIS_MNEMONIC_PUSH) {
            total += 8;
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_SUB && insn.operand_count >= 2 &&
                   ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   ops[0].reg.value == ZYDIS_REGISTER_RSP &&
                   ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            total += static_cast<std::uint32_t>(ops[1].imm.value.u);
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_MOV ||
                   insn.mnemonic == ZYDIS_MNEMONIC_LEA) {
            // Register spill into the frame; part of the prologue, no extra alloc.
        } else {
            break;  // first instruction that isn't a recognizable prologue step
        }
        off += insn.length;
    }
    return total;
}

std::optional<std::size_t> find_function_start(const std::uint8_t* buf,
                                               std::size_t size,
                                               std::size_t rip_off,
                                               std::size_t max_lookback) noexcept {
    if (buf == nullptr || rip_off == 0 || rip_off > size) {
        return std::nullopt;
    }
    const std::size_t lo = rip_off > max_lookback ? rip_off - max_lookback : 0;
    for (std::size_t i = rip_off; i > lo;) {
        --i;
        if (buf[i] == 0xCC) {
            return i + 1;  // first byte after the int3 padding run
        }
    }
    return std::nullopt;
}

}  // namespace nias
