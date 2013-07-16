//
//  CK2SFTPFileHandle.h
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

#import <Foundation/Foundation.h>

#include <libssh2_sftp.h>


@class CK2SFTPSession;


@interface CK2SFTPFileHandle : NSFileHandle
{
  @private
    LIBSSH2_SFTP_HANDLE *_handle;
    CK2SFTPSession      *_session;
    NSString            *_path;
}

// Session reference & path are not compulsary, but without you won't get decent error information
- (id)initWithSFTPHandle:(LIBSSH2_SFTP_HANDLE *)handle session:(CK2SFTPSession *)session path:(NSString *)path;

- (BOOL)closeFile:(NSError **)error;

- (BOOL)writeData:(NSData *)data error:(NSError **)error;
- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length error:(NSError **)error;
- (NSInteger)write:(const uint8_t *)buffer maxLength:(NSUInteger)length;

@end
