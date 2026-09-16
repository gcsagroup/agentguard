// AGD-030 原生 API 实验：只处理验收脚本创建的合成资料，不接入产品执行或授权。
#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

static NSDictionary *readProbe(NSString *path) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return @{ @"opened": @NO, @"errno": @(errno) };
    char bytes[256]; ssize_t count = read(fd, bytes, sizeof(bytes)); int error = count < 0 ? errno : 0;
    close(fd);
    return @{ @"opened": @YES, @"errno": @(error), @"bytes": @(MAX(count, 0)),
              @"text": count > 0 ? [[NSString alloc] initWithBytes:bytes length:(NSUInteger)count encoding:NSUTF8StringEncoding] ?: @"" : @"" };
}

static NSDictionary *writeProbe(NSString *path) {
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return @{ @"opened": @NO, @"errno": @(errno) };
    const char *text = "NATIVE_BOOKMARK_OUTPUT";
    ssize_t count = write(fd, text, strlen(text)); int error = count < 0 ? errno : 0;
    close(fd);
    return @{ @"opened": @YES, @"errno": @(error), @"bytes": @(MAX(count, 0)) };
}

static NSDictionary *snapshot(NSDictionary *input) {
    return @{ @"inside_read": readProbe(input[@"inside_file"]),
              @"outside_read": readProbe(input[@"outside_file"]),
              @"symlink_read": readProbe(input[@"symlink_file"]),
              @"hardlink_read": readProbe(input[@"hardlink_file"]),
              @"inside_write": writeProbe(input[@"inside_output"]),
              @"outside_write": writeProbe(input[@"outside_output"]) };
}

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        if (argc != 2) return 2;
        NSMutableData *data = [NSMutableData data];
        NSFileHandle *inputHandle = [NSFileHandle fileHandleWithStandardInput];
        while (data.length <= 65536) {
            NSData *part = [inputHandle readDataOfLength:MIN(4096, 65537 - data.length)];
            if (part.length == 0) break;
            [data appendData:part];
        }
        if (data.length > 65536) return 2;
        NSError *error = nil;
        NSDictionary *input = [NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        if (![input isKindOfClass:NSDictionary.class]) return 2;
        for (NSString *key in @[@"workspace", @"inside_file", @"outside_file", @"symlink_file", @"hardlink_file", @"inside_output", @"outside_output"]) {
            if (![input[key] isKindOfClass:NSString.class] || ![input[key] isAbsolutePath]) return 2;
        }
        NSString *mode = [NSString stringWithUTF8String:argv[1]];
        NSMutableDictionary *result = [@{ @"pid": @(getpid()), @"mode": mode, @"home": NSHomeDirectory() } mutableCopy];
        if ([mode isEqualToString:@"broker"]) {
            NSURL *url = [NSURL fileURLWithPath:input[@"workspace"] isDirectory:YES];
            NSURLBookmarkCreationOptions options = [input[@"without_scope"] boolValue] ? NSURLBookmarkCreationWithoutImplicitSecurityScope : 0;
            NSData *bookmark = [url bookmarkDataWithOptions:options includingResourceValuesForKeys:nil relativeToURL:nil error:&error];
            result[@"bookmark"] = bookmark ? [bookmark base64EncodedStringWithOptions:0] : @"";
            result[@"created"] = @(bookmark != nil);
            result[@"baseline"] = snapshot(input);
        } else if ([mode isEqualToString:@"worker"]) {
            if (![input[@"bookmark"] isKindOfClass:NSString.class]) return 2;
            result[@"before"] = snapshot(input);
            NSData *bookmark = [[NSData alloc] initWithBase64EncodedString:input[@"bookmark"] options:0];
            BOOL stale = NO;
            NSURL *url = bookmark ? [NSURL URLByResolvingBookmarkData:bookmark
                options:NSURLBookmarkResolutionWithoutUI | NSURLBookmarkResolutionWithoutMounting | NSURLBookmarkResolutionWithoutImplicitStartAccessing
                relativeToURL:nil bookmarkDataIsStale:&stale error:&error] : nil;
            result[@"resolved"] = @(url != nil); result[@"stale"] = @(stale);
            result[@"resolved_path"] = url.path ?: @"";
            // 这是 API 行为实验，单独测量 stale 与临时作用域；不把它当作产品授权。
            BOOL started = url && [url startAccessingSecurityScopedResource];
            result[@"started"] = @(started);
            result[@"active"] = snapshot(input);
            // stop 撤回路径访问，不应被误当成撤销已有文件描述符。
            int held = started ? open([input[@"inside_file"] fileSystemRepresentation], O_RDONLY | O_CLOEXEC) : -1;
            if (started) [url stopAccessingSecurityScopedResource];
            result[@"after_stop"] = snapshot(input);
            char bytes[256];
            ssize_t count = held >= 0 ? read(held, bytes, sizeof(bytes)) : -1;
            result[@"held_fd_after_stop_bytes"] = @(count);
            if (held >= 0) close(held);
        } else return 2;
        if (error) result[@"error"] = @{ @"domain": error.domain, @"code": @(error.code), @"message": error.localizedDescription };
        NSData *output = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:NULL];
        [[NSFileHandle fileHandleWithStandardOutput] writeData:output];
        return 0;
    }
}
