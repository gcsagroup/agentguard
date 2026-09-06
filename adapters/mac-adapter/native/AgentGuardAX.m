// AgentGuard Accessibility (AXUIElement) bridge.
// Builds a depth-limited JSON tree matching Rust AxSnapshot.

#import <AppKit/AppKit.h>
#import <ApplicationServices/ApplicationServices.h>
#import <Foundation/Foundation.h>

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "agentguard_ax.h"

int agentguard_ax_request_permission(void) {
  @autoreleasepool {
    NSDictionary *options = @{(__bridge NSString *)kAXTrustedCheckOptionPrompt: @YES};
    return AXIsProcessTrustedWithOptions((__bridge CFDictionaryRef)options)
               ? AG_AX_OK
               : AG_AX_DENIED;
  }
}

// 单次 AX 消息不能无限等目标进程；整棵树还另有总预算，避免 220 个节点把许多合法的
// 单次上限串成几十秒。Rust 外层仍有独立墙钟 timeout，三层边界互不替代。
static const float kAGAXMessageTimeoutSeconds = 0.25f;
static const uint64_t kAGAXSnapshotBudgetNs = 1500ULL * 1000ULL * 1000ULL;

typedef struct {
  uint64_t deadline_ns;
  BOOL timed_out;
} AGAXWalkContext;

static uint64_t ag_ax_monotonic_ns(void) {
  struct timespec now = {0, 0};
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return 0;
  }
  return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static BOOL ag_ax_set_global_messaging_timeout(void) {
  AXUIElementRef system_wide = AXUIElementCreateSystemWide();
  if (system_wide == NULL) {
    return NO;
  }
  AXError error = AXUIElementSetMessagingTimeout(
      system_wide, kAGAXMessageTimeoutSeconds);
  CFRelease(system_wide);
  return error == kAXErrorSuccess;
}

static BOOL ag_ax_deadline_exceeded(AGAXWalkContext *context) {
  if (context == NULL || context->timed_out) {
    return context != NULL && context->timed_out;
  }
  uint64_t now = ag_ax_monotonic_ns();
  if (now != 0 && now >= context->deadline_ns) {
    context->timed_out = YES;
    return YES;
  }
  return NO;
}

static AXError ag_ax_copy_attr(AGAXWalkContext *context, AXUIElementRef element,
                               CFStringRef attribute, CFTypeRef *out_value) {
  if (out_value == NULL) {
    return kAXErrorIllegalArgument;
  }
  *out_value = NULL;
  if (ag_ax_deadline_exceeded(context)) {
    return kAXErrorCannotComplete;
  }
  AXError error =
      AXUIElementCopyAttributeValue(element, attribute, out_value);
  if (error == kAXErrorCannotComplete || ag_ax_deadline_exceeded(context)) {
    context->timed_out = YES;
    if (*out_value != NULL) {
      CFRelease(*out_value);
      *out_value = NULL;
    }
    return kAXErrorCannotComplete;
  }
  return error;
}

static NSString *gAxLastError = nil;
static pthread_mutex_t gAxErrorLock = PTHREAD_MUTEX_INITIALIZER;

static void ag_ax_set_error(NSString *msg) {
  pthread_mutex_lock(&gAxErrorLock);
  gAxLastError = [msg copy];
  pthread_mutex_unlock(&gAxErrorLock);
}

char *agentguard_ax_last_error_copy(void) {
  @autoreleasepool {
    pthread_mutex_lock(&gAxErrorLock);
    const char *utf8 = gAxLastError == nil ? "" : [gAxLastError UTF8String];
    char *copy = strdup(utf8 == NULL ? "" : utf8);
    pthread_mutex_unlock(&gAxErrorLock);
    return copy;
  }
}

void agentguard_ax_string_free(char *s) {
  if (s) {
    free(s);
  }
}

static int ag_ax_probe_impl(void) {
  if (!AXIsProcessTrusted()) {
    ag_ax_set_error(@"Accessibility permission not granted");
    return AG_AX_DENIED;
  }
  ag_ax_set_error(@"");
  return AG_AX_OK;
}

int agentguard_ax_probe(void) {
  @autoreleasepool {
    return ag_ax_probe_impl();
  }
}

static NSString *ag_ax_string_attr(AGAXWalkContext *context,
                                   AXUIElementRef el, CFStringRef attr) {
  CFTypeRef value = NULL;
  if (ag_ax_copy_attr(context, el, attr, &value) != kAXErrorSuccess ||
      value == NULL) {
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

static NSDictionary *ag_ax_bounds(AGAXWalkContext *context, AXUIElementRef el) {
  float x = 0, y = 0, w = 0, h = 0;
  CFTypeRef posRef = NULL;
  CFTypeRef sizeRef = NULL;
  if (ag_ax_copy_attr(context, el, kAXPositionAttribute, &posRef) ==
          kAXErrorSuccess &&
      posRef != NULL) {
    CGPoint pt = CGPointZero;
    if (AXValueGetValue((AXValueRef)posRef, kAXValueTypeCGPoint, &pt)) {
      x = (float)pt.x;
      y = (float)pt.y;
    }
    CFRelease(posRef);
  }
  if (ag_ax_copy_attr(context, el, kAXSizeAttribute, &sizeRef) ==
          kAXErrorSuccess &&
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

static NSDictionary *ag_ax_node(AGAXWalkContext *context, AXUIElementRef el,
                                int depth, int max_depth,
                                NSUInteger *budget) {
  if (el == NULL || depth > max_depth || *budget == 0 ||
      ag_ax_deadline_exceeded(context)) {
    return nil;
  }
  (*budget)--;

  NSString *role = ag_ax_string_attr(context, el, kAXRoleAttribute);
  NSString *title = ag_ax_string_attr(context, el, kAXTitleAttribute);
  if (title.length == 0) {
    title = ag_ax_string_attr(context, el, kAXDescriptionAttribute);
  }
  if (title.length == 0) {
    title = ag_ax_string_attr(context, el, kAXPlaceholderValueAttribute);
  }
  NSString *value = ag_ax_string_attr(context, el, kAXValueAttribute);
  if (context->timed_out) {
    return nil;
  }

  NSMutableArray *children = [NSMutableArray array];
  if (depth < max_depth && *budget > 0) {
    CFTypeRef kidsRef = NULL;
    if (ag_ax_copy_attr(context, el, kAXChildrenAttribute, &kidsRef) ==
            kAXErrorSuccess &&
        kidsRef != NULL && CFGetTypeID(kidsRef) == CFArrayGetTypeID()) {
      CFArrayRef kids = (CFArrayRef)kidsRef;
      CFIndex count = CFArrayGetCount(kids);
      // Cap fan-out per node to keep snapshots bounded.
      CFIndex limit = count > 40 ? 40 : count;
      for (CFIndex i = 0; i < limit && *budget > 0; i++) {
        if (ag_ax_deadline_exceeded(context)) {
          break;
        }
        AXUIElementRef child = (AXUIElementRef)CFArrayGetValueAtIndex(kids, i);
        NSDictionary *c =
            ag_ax_node(context, child, depth + 1, max_depth, budget);
        if (c != nil) {
          [children addObject:c];
        }
      }
      CFRelease(kidsRef);
    }
  }
  if (context->timed_out) {
    return nil;
  }

  NSDictionary *bounds = ag_ax_bounds(context, el);
  if (context->timed_out) {
    return nil;
  }

  return @{
    @"role" : role ?: @"",
    @"title" : title ?: @"",
    @"value" : value ?: @"",
    @"children" : children,
    @"bounds" : bounds,
  };
}

static int ag_ax_frontmost_json_impl(char **out_json) {
  if (out_json == NULL) {
    return AG_AX_ERROR;
  }
  *out_json = NULL;

  if (!AXIsProcessTrusted()) {
    ag_ax_set_error(@"Accessibility permission not granted");
    return AG_AX_DENIED;
  }
  if (!ag_ax_set_global_messaging_timeout()) {
    ag_ax_set_error(@"Failed to set global AX messaging timeout");
    return AG_AX_ERROR;
  }

  uint64_t started_ns = ag_ax_monotonic_ns();
  AGAXWalkContext context = {
      .deadline_ns = started_ns == 0 ? UINT64_MAX
                                     : started_ns + kAGAXSnapshotBudgetNs,
      .timed_out = NO,
  };

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
  if (ag_ax_copy_attr(&context, appEl, kAXFocusedWindowAttribute, &winRef) ==
          kAXErrorSuccess &&
      winRef != NULL) {
    root = (AXUIElementRef)winRef;
  } else {
    root = appEl;
    CFRetain(root);
  }

  NSUInteger budget = 220;
  NSDictionary *tree = ag_ax_node(&context, root, 0, 10, &budget);
  CFRelease(root);
  CFRelease(appEl);

  if (context.timed_out) {
    ag_ax_set_error(@"AX snapshot timed out");
    return AG_AX_ERROR;
  }
  if (tree == nil) {
    ag_ax_set_error(@"Failed to walk AX tree");
    return AG_AX_ERROR;
  }

  NSString *appName = front.localizedName ?: front.bundleIdentifier ?: @"Unknown";
  // source_pid:让 Rust 侧能认出"前台就是 AgentGuard 自己"并跳过——守卫的仪表盘树里天生
  // 有演示威胁按钮的文字,交给规则引擎只会对着镜子告警(Windows 真机验收 2026-09-02 的
  // OVL-010 就是这样来的)。判断放在 Rust(可测),这里只如实带上 pid。
  NSDictionary *snap = @{
    @"source_app" : appName,
    @"source_pid" : @((unsigned int)pid),
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

int agentguard_ax_frontmost_json(char **out_json) {
  @autoreleasepool {
    return ag_ax_frontmost_json_impl(out_json);
  }
}

// ---- AXObserver 推送(E3)。变化时推通知,Rust 侧轮询计数(agentguard_ax_observe_take)。 ----

static AXObserverRef gAxObserver = NULL;
static AXUIElementRef gAxObservedApp = NULL;
static pid_t gAxObservedPid = -1;
static pthread_mutex_t gAxCallbackLock = PTHREAD_MUTEX_INITIALIZER;
static unsigned long long gAxNotifyCount = 0;
static uint64_t gAxGeneration = 0;

static uint64_t ag_ax_generation(void) {
  pthread_mutex_lock(&gAxCallbackLock);
  uint64_t generation = gAxGeneration;
  pthread_mutex_unlock(&gAxCallbackLock);
  return generation;
}

static void ag_ax_observer_cb(AXObserverRef observer, AXUIElementRef element,
                              CFStringRef notification, void *refcon) {
  (void)observer;
  (void)element;
  (void)notification;
  uint64_t callback_generation = (uint64_t)(uintptr_t)refcon;
  // stop/start 之间已经排进主 run loop 的旧 callback 可能在新 observer 启动后才执行。
  // refcon 固定在注册代际；不匹配就丢弃，不能把旧通知记到新会话的全局计数。
  pthread_mutex_lock(&gAxCallbackLock);
  if (callback_generation != 0 && gAxGeneration == callback_generation) {
    // 校验和计数必须是一个临界区。否则 stop/start 可能发生在二者之间，旧 callback 会把
    // 新代际的全局计数错误加一。
    gAxNotifyCount += 1ULL;
  }
  pthread_mutex_unlock(&gAxCallbackLock);
}

static void ag_ax_observe_stop_unchecked(void) {
  // 先失效代际再拆 source。已经排队或正在进入的 callback 从这一刻起只能 no-op。
  pthread_mutex_lock(&gAxCallbackLock);
  gAxGeneration = 0;
  gAxNotifyCount = 0ULL;
  pthread_mutex_unlock(&gAxCallbackLock);
  if (gAxObserver != NULL) {
    CFRunLoopRemoveSource(CFRunLoopGetMain(),
                          AXObserverGetRunLoopSource(gAxObserver),
                          kCFRunLoopDefaultMode);
    CFRelease(gAxObserver);
    gAxObserver = NULL;
  }
  if (gAxObservedApp != NULL) {
    CFRelease(gAxObservedApp);
    gAxObservedApp = NULL;
  }
  gAxObservedPid = -1;
}

void agentguard_ax_observe_stop(uint64_t generation) {
  if (generation == 0 || ag_ax_generation() != generation) {
    return;
  }
  ag_ax_observe_stop_unchecked();
}

static int ag_ax_observe_start_impl(uint64_t generation) {
  if (generation == 0) {
    ag_ax_set_error(@"AXObserver generation must be non-zero");
    return AG_AX_ERROR;
  }
  if (!AXIsProcessTrusted()) {
    ag_ax_set_error(@"Accessibility permission not granted");
    return AG_AX_DENIED;
  }
  if (!ag_ax_set_global_messaging_timeout()) {
    ag_ax_set_error(@"Failed to set global AX messaging timeout");
    return AG_AX_ERROR;
  }
  NSRunningApplication *front = [[NSWorkspace sharedWorkspace] frontmostApplication];
  if (front == nil) {
    ag_ax_set_error(@"no frontmost application");
    return AG_AX_ERROR;
  }
  pid_t pid = front.processIdentifier;
  // 驱动循环会定期调用 start 来跟随前台应用。PID 没变就保留现有 observer，避免
  // 每个 tick 都拆装 run-loop source；切换应用时才真正重绑。
  if (gAxObserver != NULL && gAxObservedPid == pid &&
      ag_ax_generation() == generation) {
    ag_ax_set_error(@"");
    return AG_AX_OK;
  }
  ag_ax_observe_stop_unchecked();

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
    AXObserverAddNotification(obs, app, notes[i],
                              (void *)(uintptr_t)generation);
  }
  // observer 可能从 Rust 后台驱动线程启动；source 必须挂到真正持续运行的主线程
  // run loop，不能挂到没有 run loop 的调用线程。
  gAxObserver = obs;
  gAxObservedApp = app;
  gAxObservedPid = pid;
  pthread_mutex_lock(&gAxCallbackLock);
  gAxNotifyCount = 0ULL;
  gAxGeneration = generation;
  pthread_mutex_unlock(&gAxCallbackLock);
  CFRunLoopAddSource(CFRunLoopGetMain(), AXObserverGetRunLoopSource(obs),
                     kCFRunLoopDefaultMode);
  CFRunLoopWakeUp(CFRunLoopGetMain());
  ag_ax_set_error(@"");
  return AG_AX_OK;
}

int agentguard_ax_observe_start(uint64_t generation) {
  @autoreleasepool {
    return ag_ax_observe_start_impl(generation);
  }
}

unsigned long long agentguard_ax_observe_take(uint64_t generation) {
  pthread_mutex_lock(&gAxCallbackLock);
  unsigned long long count = 0ULL;
  if (generation != 0 && gAxGeneration == generation) {
    count = gAxNotifyCount;
    gAxNotifyCount = 0ULL;
  }
  pthread_mutex_unlock(&gAxCallbackLock);
  return count;
}
