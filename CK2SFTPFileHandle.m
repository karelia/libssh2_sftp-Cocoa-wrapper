//
//  CK2SFTPFileHandle.m
//  Sandvox
//
//  Created by Mike Abdullah on 03/07/2011.
//  Copyright © 2011 Karelia Software
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
//

#import "CK2SFTPFileHandle.h"

#import "CK2SFTPSession.h"


@implementation CK2SFTPFileHandle

- (id)initWithSFTPHandle:(LIBSSH2_SFTP_HANDLE *)handle session:(CK2SFTPSession *)session path:(NSString *)path;
{
    NSParameterAssert(handle);
    
    if (self = [self init])
    {
        _handle = handle;
        _session = [session retain];
        _path = [path copy];
    }
    
    return self;
}

- (void)closeFile; { [self closeFile:NULL]; }

- (BOOL)closeFile:(NSError **)error;
{
    BOOL result = YES;
    if (_handle)
    {
        result = (libssh2_sftp_close(_handle) == 0);
        
        if (result)
        {
            _handle = NULL;
            [_session release]; _session = nil;
        }
        else if (error)
        {
            *error = [_session performSelector:@selector(sessionErrorWithPath:) withObject:_path];
        }
    }
    
    return result;
}

- (void)dealloc;
{
    [self closeFile];
    [_session release]; _session = nil; // just in case closing failed
    
    [_path release];
    
    [super dealloc];
}

- (void)writeData:(NSData *)data;
{
    NSError *error;
    if (![self writeData:data error:&error])
    {
        [NSException raise:NSFileHandleOperationException format:@"%@", [error localizedDescription]];
    }
}

- (BOOL)writeData:(NSData *)data error:(NSError **)error;
{
    NSUInteger offset = 0;
    NSUInteger remainder = [data length];
    
    while (remainder)
    {
        const void *bytes = [data bytes];
        
        NSInteger written = [self write:bytes+offset maxLength:remainder error:error];
        if (written < 0) return NO;
        
        offset+=written;
        remainder-=written;
    }
    
    return YES;
}

- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length error:(NSError **)error;
{
    NSInteger result = [self write:buffer maxLength:length];
    if (result < 0 && error)
    {
        *error = [_session performSelector:@selector(sessionErrorWithPath:) withObject:_path];
    }
    
    return result;
}

- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length;
{
    return libssh2_sftp_write(_handle, (const char *)buffer, length);
}

@end
