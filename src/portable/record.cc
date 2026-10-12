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

std::size_t encode(const FaultRecord& r, std::uint8_t* out,
                   std::size_t cap) noexcept {
    if (r.frame_count > kMaxFrames) {
        return 0;
    }
    const std::size_t sz = record_size(r);
    if (cap < sz) {
        return 0;
    }
    // The header and frame array are contiguous in a packed struct, so the
    // compact form is just the first `sz` bytes.
    std::memcpy(out, &r, sz);
    return sz;
}

bool decode(const std::uint8_t* in, std::size_t len, FaultRecord& out) noexcept {
    if (in == nullptr || len < kHeaderBytes) {
        return false;
    }
    FaultRecord tmp{};
    std::memcpy(&tmp, in, kHeaderBytes);
    if (tmp.magic != kRecordMagic || tmp.version != kRecordVersion) {
        return false;
    }
    if (tmp.frame_count > kMaxFrames) {
        return false;
    }
    const std::size_t sz = kHeaderBytes + tmp.frame_count * sizeof(FaultRecord::Frame);
    if (len < sz) {
        return false;
    }
    std::memcpy(tmp.frames, in + kHeaderBytes,
                tmp.frame_count * sizeof(FaultRecord::Frame));
    out = tmp;
    return true;
}

}  // namespace nias
