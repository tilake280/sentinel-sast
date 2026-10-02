// The worker's version, in one place. It goes into the startup banner, the
// SARIF tool descriptor, the triage User-Agent and every published scan result,
// and those drifting apart is how a result ends up attributed to the wrong
// ruleset.

#pragma once

#include <string_view>

namespace sentinel {

inline constexpr std::string_view kVersion = "0.3.0";

}  // namespace sentinel
