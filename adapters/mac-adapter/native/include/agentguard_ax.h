#ifndef AGENTGUARD_AX_H
#define AGENTGUARD_AX_H

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

/**
 * Snapshot the frontmost app's AX tree as UTF-8 JSON (AxSnapshot shape).
 * On success returns AG_AX_OK and sets *out_json to a malloc'd C string;
 * caller must free with agentguard_ax_string_free.
 */
int agentguard_ax_frontmost_json(char **out_json);

/** Free a string returned by agentguard_ax_frontmost_json. */
void agentguard_ax_string_free(char *s);

/** Human-readable last error (static buffer; may be empty). */
const char *agentguard_ax_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* AGENTGUARD_AX_H */
