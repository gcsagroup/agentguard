// AgentGuard Accessibility (AXUIElement) bridge.
// Builds a depth-limited JSON tree matching Rust AxSnapshot.

#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Foundation/Foundation.h>

#include "agentguard_ax.h"

static NSString *gAxLastError = nil;

static void ag_ax_set_error(NSString *msg) {
  gAxLastError = [msg copy];
}

const char *agentguard_ax_last_error(void) {
  if (gAxLastError == nil) {
    return "";
  }
  return [gAxLastError UTF8String];
}

void agentguard_ax_string_free(char *s) {
  if (s) {
    free(s);
  }
}

int agentguard_ax_probe(void) {
  if (!AXIsProcessTrusted()) {
    ag_ax_set_error(@"Accessibility permission not granted");
    return AG_AX_DENIED;
  }
  ag_ax_set_error(@"");
  return AG_AX_OK;
}

static NSString *ag_ax_string_attr(AXUIElementRef el, CFStringRef attr) {
  CFTypeRef value = NULL;
  if (AXUIElementCopyAttributeValue(el, attr, &value) != kAXErrorSuccess || value == NULL) {
    return @"";
  }
  NSString *out = @"";
  if (CFGetTypeID(value) == CFStringGetTypeID()) {
    out = [(__bridge NSString *)value copy];
  } else if (CFGetTypeID(value) == CFNumberGetTypeID()) {
    out = [(__bridge NSNumber *)value stringValue];
  } else if (CFGetTypeID(value) == CFAttributedStringGetTypeID()) {
    out = [[(__bridge NSAttributedString *)value string] copy];
  }
  CFRelease(value);
  return out ?: @"";
}

static NSDictionary *ag_ax_bounds(AXUIElementRef el) {
  float x = 0, y = 0, w = 0, h = 0;
  CFTypeRef posRef = NULL;
  CFTypeRef sizeRef = NULL;
  if (AXUIElementCopyAttributeValue(el, kAXPositionAttribute, &posRef) == kAXErrorSuccess &&
      posRef != NULL) {
    CGPoint pt = CGPointZero;
    if (AXValueGetValue((AXValueRef)posRef, kAXValueTypeCGPoint, &pt)) {
      x = (float)pt.x;
      y = (float)pt.y;
    }
    CFRelease(posRef);
  }
  if (AXUIElementCopyAttributeValue(el, kAXSizeAttribute, &sizeRef) == kAXErrorSuccess &&
      sizeRef != NULL) {
    CGSize sz = CGSizeZero;
    if (AXValueGetValue((AXValueRef)sizeRef, kAXValueTypeCGSize, &sz)) {
      w = (float)sz.width;
      h = (float)sz.height;
    }
    CFRelease(sizeRef);
  }
  return @{
    @"x" : @(x),
    @"y" : @(y),
    @"width" : @(w),
    @"height" : @(h),
  };
}

static NSDictionary *ag_ax_node(AXUIElementRef el, int depth, int max_depth, NSUInteger *budget) {
  if (el == NULL || depth > max_depth || *budget == 0) {
    return nil;
  }
  (*budget)--;

  NSString *role = ag_ax_string_attr(el, kAXRoleAttribute);
  NSString *title = ag_ax_string_attr(el, kAXTitleAttribute);
  if (title.length == 0) {
    title = ag_ax_string_attr(el, kAXDescriptionAttribute);
  }
  if (title.length == 0) {
    title = ag_ax_string_attr(el, kAXPlaceholderValueAttribute);
  }
  NSString *value = ag_ax_string_attr(el, kAXValueAttribute);

  NSMutableArray *children = [NSMutableArray array];
  if (depth < max_depth && *budget > 0) {
    CFTypeRef kidsRef = NULL;
    if (AXUIElementCopyAttributeValue(el, kAXChildrenAttribute, &kidsRef) == kAXErrorSuccess &&
        kidsRef != NULL && CFGetTypeID(kidsRef) == CFArrayGetTypeID()) {
      CFArrayRef kids = (CFArrayRef)kidsRef;
      CFIndex count = CFArrayGetCount(kids);
      // Cap fan-out per node to keep snapshots bounded.
      CFIndex limit = count > 40 ? 40 : count;
      for (CFIndex i = 0; i < limit && *budget > 0; i++) {
        AXUIElementRef child = (AXUIElementRef)CFArrayGetValueAtIndex(kids, i);
        NSDictionary *c = ag_ax_node(child, depth + 1, max_depth, budget);
        if (c != nil) {
          [children addObject:c];
        }
      }
      CFRelease(kidsRef);
    }
  }

  return @{
    @"role" : role ?: @"",
    @"title" : title ?: @"",
    @"value" : value ?: @"",
    @"children" : children,
    @"bounds" : ag_ax_bounds(el),
  };
}

int agentguard_ax_frontmost_json(char **out_json) {
  if (out_json == NULL) {
    return AG_AX_ERROR;
  }
  *out_json = NULL;

  if (!AXIsProcessTrusted()) {
    ag_ax_set_error(@"Accessibility permission not granted");
    return AG_AX_DENIED;
  }

  NSRunningApplication *front = [[NSWorkspace sharedWorkspace] frontmostApplication];
  if (front == nil) {
    ag_ax_set_error(@"No frontmost application");
    return AG_AX_ERROR;
  }

  pid_t pid = front.processIdentifier;
  AXUIElementRef appEl = AXUIElementCreateApplication(pid);
  if (appEl == NULL) {
    ag_ax_set_error(@"AXUIElementCreateApplication failed");
    return AG_AX_ERROR;
  }

  // Prefer focused window; fall back to app root.
  AXUIElementRef root = NULL;
  CFTypeRef winRef = NULL;
  if (AXUIElementCopyAttributeValue(appEl, kAXFocusedWindowAttribute, &winRef) == kAXErrorSuccess &&
      winRef != NULL) {
    root = (AXUIElementRef)winRef;
  } else {
    root = appEl;
    CFRetain(root);
  }

  NSUInteger budget = 220;
  NSDictionary *tree = ag_ax_node(root, 0, 10, &budget);
  CFRelease(root);
  CFRelease(appEl);

  if (tree == nil) {
    ag_ax_set_error(@"Failed to walk AX tree");
    return AG_AX_ERROR;
  }

  NSString *appName = front.localizedName ?: front.bundleIdentifier ?: @"Unknown";
  NSDictionary *snap = @{
    @"source_app" : appName,
    @"root" : tree,
  };

  NSError *err = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:snap options:0 error:&err];
  if (data == nil) {
    ag_ax_set_error(err.localizedDescription ?: @"JSON serialization failed");
    return AG_AX_ERROR;
  }

  NSUInteger len = data.length;
  char *buf = (char *)malloc(len + 1);
  if (buf == NULL) {
    ag_ax_set_error(@"Out of memory");
    return AG_AX_ERROR;
  }
  memcpy(buf, data.bytes, len);
  buf[len] = '\0';
  *out_json = buf;
  ag_ax_set_error(@"");
  return AG_AX_OK;
}

// ---- AXObserver 推送(E3)。变化时推通知,Rust 侧轮询计数(agentguard_ax_observe_take)。 ----

#include <stdatomic.h>

static AXObserverRef gAxObserver = NULL;
static AXUIElementRef gAxObservedApp = NULL;
static _Atomic(unsigned long long) gAxNotifyCount = 0;

static void ag_ax_observer_cb(AXObserverRef observer, AXUIElementRef element,
                              CFStringRef notification, void *refcon) {
  (void)observer;
  (void)element;
  (void)notification;
  (void)refcon;
  // 只累加计数:Rust 侧的合并器(ax_push.rs)负责去抖与延迟上限。这里保持尽量薄。
  atomic_fetch_add(&gAxNotifyCount, 1ULL);
}

void agentguard_ax_observe_stop(void) {
  if (gAxObserver != NULL) {
    CFRunLoopRemoveSource(CFRunLoopGetCurrent(),
                          AXObserverGetRunLoopSource(gAxObserver),
                          kCFRunLoopDefaultMode);
    CFRelease(gAxObserver);
    gAxObserver = NULL;
  }
  if (gAxObservedApp != NULL) {
    CFRelease(gAxObservedApp);
    gAxObservedApp = NULL;
  }
}

int agentguard_ax_observe_start(void) {
  if (!AXIsProcessTrusted()) {
    ag_ax_set_error(@"Accessibility permission not granted");
    return AG_AX_DENIED;
  }
  agentguard_ax_observe_stop(); // 幂等重启:先卸掉旧的。

  NSRunningApplication *front = [[NSWorkspace sharedWorkspace] frontmostApplication];
  if (front == nil) {
    ag_ax_set_error(@"no frontmost application");
    return AG_AX_ERROR;
  }
  pid_t pid = front.processIdentifier;

  AXObserverRef obs = NULL;
  if (AXObserverCreate(pid, ag_ax_observer_cb, &obs) != kAXErrorSuccess || obs == NULL) {
    ag_ax_set_error(@"AXObserverCreate failed");
    return AG_AX_ERROR;
  }
  AXUIElementRef app = AXUIElementCreateApplication(pid);
  CFStringRef notes[] = {
      kAXValueChangedNotification,          kAXFocusedUIElementChangedNotification,
      kAXWindowCreatedNotification,         kAXTitleChangedNotification,
      kAXUIElementDestroyedNotification,    kAXMainWindowChangedNotification,
  };
  for (size_t i = 0; i < sizeof(notes) / sizeof(notes[0]); i++) {
    // best-effort:某些元素不支持某些通知,逐条失败忽略——少注册一类只会更保守(那类变化
    // 靠兜底轮询兜),不会漏成"以为在推其实没推"。
    AXObserverAddNotification(obs, app, notes[i], NULL);
  }
  CFRunLoopAddSource(CFRunLoopGetCurrent(), AXObserverGetRunLoopSource(obs),
                     kCFRunLoopDefaultMode);
  gAxObserver = obs;
  gAxObservedApp = app;
  atomic_store(&gAxNotifyCount, 0ULL);
  ag_ax_set_error(@"");
  return AG_AX_OK;
}

unsigned long long agentguard_ax_observe_take(void) {
  return atomic_exchange(&gAxNotifyCount, 0ULL);
}
