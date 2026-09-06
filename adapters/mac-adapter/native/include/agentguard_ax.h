#ifndef AGENTGUARD_AX_H
#define AGENTGUARD_AX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Accessibility bridge status codes. */
enum {
  AG_AX_OK = 0,
  AG_AX_DENIED = 1,
  AG_AX_ERROR = 2,
  AG_AX_UNSUPPORTED = 3
};

/** Probe Accessibility TCC (AXIsProcessTrusted). */
int agentguard_ax_probe(void);

/** 仅由用户点击授权入口调用；请求系统将当前 App 加入辅助功能授权流程。 */
int agentguard_ax_request_permission(void);

/**
 * Snapshot the frontmost app's AX tree as UTF-8 JSON (AxSnapshot shape).
 * On success returns AG_AX_OK and sets *out_json to a malloc'd C string;
 * caller must free with agentguard_ax_string_free.
 */
int agentguard_ax_frontmost_json(char **out_json);

/** Free a string returned by agentguard_ax_frontmost_json. */
void agentguard_ax_string_free(char *s);

/** Caller-owned copy of the last error (may be empty); release with string_free. */
char *agentguard_ax_last_error_copy(void);

/**
 * Start observing the frontmost app's AX tree for change notifications (E3).
 * Registers an AXObserver on the run loop; each notification bumps an internal
 * counter that Rust polls via agentguard_ax_observe_take. Returns AG_AX_OK on
 * success, AG_AX_DENIED without Accessibility, AG_AX_ERROR otherwise.
 */
int agentguard_ax_observe_start(uint64_t generation);

/** Take and zero notifications only when `generation` is still active. */
unsigned long long agentguard_ax_observe_take(uint64_t generation);

/** Stop only the matching generation; a stale worker cannot stop its successor. */
void agentguard_ax_observe_stop(uint64_t generation);

#ifdef __cplusplus
}
#endif

#endif /* AGENTGUARD_AX_H */
