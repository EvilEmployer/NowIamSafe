#include "nias/record.hh"

#include <cstddef>
#include <cstring>

namespace nias {

namespace {
constexpr std::size_t kHeaderBytes = offsetof(FaultRecord, frames);
}

std::size_t record_size(const FaultRecord& r) noexcept {
    std::size_t fc = r.frame_count;
    if (fc > kMaxFrames) {
        fc = kMaxFrames;
    }
    return kHeaderBytes + fc * sizeof(FaultRecord::Frame);
}

std::size_t encode(const FaultRecord& r, std::span<std::uint8_t> out) noexcept {
    if (r.frame_count > kMaxFrames) {
        return 0;
    }
    const std::size_t sz = record_size(r);
    if (out.size() < sz) {
        return 0;
    }
    // The header and frame array are contiguous in a packed struct, so the
    // compact form is just the first `sz` bytes.
    std::memcpy(out.data(), &r, sz);
    return sz;
}

bool decode(std::span<const std::uint8_t> in, FaultRecord& out) noexcept {
    if (in.size() < kHeaderBytes) {
        return false;
    }
    FaultRecord tmp{};
    std::memcpy(&tmp, in.data(), kHeaderBytes);
    if (tmp.magic != kRecordMagic || tmp.version != kRecordVersion) {
        return false;
    }
    if (tmp.frame_count > kMaxFrames) {
        return false;
    }
    const std::size_t sz = kHeaderBytes + tmp.frame_count * sizeof(FaultRecord::Frame);
    if (in.size() < sz) {
        return false;
    }
    std::memcpy(tmp.frames, in.data() + kHeaderBytes,
                tmp.frame_count * sizeof(FaultRecord::Frame));
    out = tmp;
    return true;
}

}  // namespace nias
