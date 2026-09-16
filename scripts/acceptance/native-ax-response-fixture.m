// 仅供本机 AX 故障验收的合成窗口；不读用户数据、不请求权限、不执行外部动作。
// 编译及固定夹具路径见 docs/native-ax-recovery-022-2026-09-16.zh.md。
#import <AppKit/AppKit.h>

@interface AXResponseFixture : NSObject <NSApplicationDelegate>
@property(strong) NSWindow *window;
@property(strong) NSTextField *status;
@property(strong) NSButton *pauseButton;
@property(strong) NSString *logPath;
@end

@implementation AXResponseFixture
- (void)record:(NSString *)event {
  NSDictionary *entry = @{
    @"event": event,
    @"epoch_ms": @((long long)(NSDate.date.timeIntervalSince1970 * 1000)),
    @"uptime": @(NSProcessInfo.processInfo.systemUptime),
    @"pid": @(NSProcessInfo.processInfo.processIdentifier),
    @"active": @(NSApp.active),
  };
  NSData *json = [NSJSONSerialization dataWithJSONObject:entry options:0 error:nil];
  FILE *file = fopen(self.logPath.fileSystemRepresentation, "a");
  if (file) {
    fwrite(json.bytes, 1, json.length, file);
    fputc('\n', file);
    fclose(file);
  }
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
  (void)notification;
  self.logPath = [NSBundle.mainBundle.bundlePath.stringByDeletingLastPathComponent
      stringByAppendingPathComponent:@"ax-response-fixture.jsonl"];
  self.window = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 600, 240)
      styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
      backing:NSBackingStoreBuffered defer:NO];
  self.window.title = @"窗口响应验收夹具 · Ver 1.0 (001)";
  self.status = [NSTextField labelWithString:@"窗口正常响应 · 合成文字 AX-READY-022"];
  self.status.frame = NSMakeRect(24, 158, 552, 44);
  self.status.font = [NSFont systemFontOfSize:20];
  [self.window.contentView addSubview:self.status];
  NSTextField *hint = [NSTextField labelWithString:@"只暂停本窗口，45 秒后自动恢复。不会修改系统权限。"];
  hint.frame = NSMakeRect(24, 115, 552, 28);
  [self.window.contentView addSubview:hint];
  self.pauseButton = [NSButton buttonWithTitle:@"3 秒后暂停响应 45 秒" target:self action:@selector(pause:)];
  self.pauseButton.frame = NSMakeRect(24, 40, 260, 46);
  [self.window.contentView addSubview:self.pauseButton];
  NSMenu *menu = [[NSMenu alloc] init];
  NSMenuItem *root = [[NSMenuItem alloc] init];
  [menu addItem:root];
  NSMenu *appMenu = [[NSMenu alloc] init];
  [appMenu addItemWithTitle:@"退出窗口验收夹具" action:@selector(terminate:) keyEquivalent:@"q"];
  root.submenu = appMenu;
  NSApp.mainMenu = menu;
  [self.window center];
  [self.window makeKeyAndOrderFront:nil];
  [self record:@"launched"];
}

- (void)pause:(id)sender {
  (void)sender;
  self.pauseButton.enabled = NO;
  self.status.stringValue = @"已安排本窗口暂停，随后自动恢复 · AX-PAUSE-022";
  [self record:@"pause_scheduled"];
  dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
    [self record:@"main_thread_pause_begin"];
    // 故意阻塞目标窗口的真实 AppKit 主线程，使跨进程 AX 请求超时；不伪造守卫返回值。
    [NSThread sleepForTimeInterval:45];
    self.status.stringValue = @"窗口已恢复响应 · 合成文字 AX-RECOVERED-022";
    self.pauseButton.enabled = YES;
    [self record:@"main_thread_pause_end"];
  });
}

- (void)applicationDidBecomeActive:(NSNotification *)notification {
  (void)notification;
  [self record:@"became_active"];
}
- (void)applicationDidResignActive:(NSNotification *)notification {
  (void)notification;
  [self record:@"resigned_active"];
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)sender {
  (void)sender;
  return YES;
}
- (void)applicationWillTerminate:(NSNotification *)notification {
  (void)notification;
  [self record:@"terminated"];
}
@end

int main(void) {
  @autoreleasepool {
    NSApplication *app = NSApplication.sharedApplication;
    AXResponseFixture *delegate = [[AXResponseFixture alloc] init];
    app.delegate = delegate;
    [app setActivationPolicy:NSApplicationActivationPolicyRegular];
    [app run];
  }
  return 0;
}
