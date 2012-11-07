//
//  PNDOAuth1Credential.m
//  PNDOAuth1Client
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "PNDOAuth1Credential.h"
#import "PNDOAuth1Client.h"

@implementation PNDOAuth1Credential

@dynamic token, secret;
@dynamic verifier, callbackConfirmed, userEmailIsVerified;
@dynamic domain, hostedDomain, iconURLString, language, mobile;

+ (id)storeWithServiceName:(NSString *)name username:(NSString *)username responseObject:(id)data {
	return [self storeWithServiceName: name username: username contents: @{
			@"token" : [data valueForKey: PNDOAuthTokenKey],
			@"secret": [data valueForKey: PNDOAuthTokenSecretKey]
			} userInfo: @{
			@"verifier": [data valueForKey: PNDOAuthVerifierKey],
			@"callbackConfirmed": [data valueForKey: PNDOAuthCallbackConfirmedKey],
			@"userEmailIsVerified": [data valueForKey: PNDOAuthUserEmailIsVerifiedKey],
			}];
}

#pragma mark -

+ (NSSet *)keyPathsForValuesAffectingContents {
    return [NSSet setWithObjects: @"token", @"secret", nil];
}

+ (NSSet *)keyPathsForValuesAffectingUserInfo {
	return [NSSet setWithObjects: @"verifier", @"callbackConfirmed", @"userEmail", @"userEmailIsVerified", nil];
}

+ (NSSet *)keyPathsForValuesAffectingTransientProperties {
	return [NSSet setWithObjects: @"domain", @"hostedDomain", @"iconURLString", @"language", @"mobile", nil];
}

- (BOOL)hasToken {
	return !!self.token.length;
}

- (Class)mutableClass {
	return [PNDMutableOAuth1Credential class];
}

- (void)setToken:(NSString *)token {
	BOOL shouldFire = (!self.hasToken && token.length) || (!token.length && self.hasToken);
	if (shouldFire)
		[self willChangeValueForKey: @"hasToken"];
	[self setValue: token forUndefinedKey: @"token"];
	if (shouldFire)
		[self didChangeValueForKey: @"hasToken"];
}

@end

@implementation PNDMutableOAuth1Credential

@dynamic token, secret;
@dynamic verifier, callbackConfirmed, userEmailIsVerified;
@dynamic domain, hostedDomain, iconURLString, language, mobile;

@end