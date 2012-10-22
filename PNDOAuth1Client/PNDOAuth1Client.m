//
//  PNDOAuth1Client.m
//  PNDOAuth1Client
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "PNDOAuth1Client.h"
#import "AFHTTPRequestOperation.h"
#import <objc/runtime.h>
#import <CommonCrypto/CommonHMAC.h>
#import "PNDOAuth1Credential.h"

NSString *const PNDOAuthErrorDomain = @"PNDOAuthError";
NSString *const PNDOAuthErrorMissingPropertyKey = @"PNDOAuthMissingProperty";

NSString *const PNDOAuthTokenFetchWillStartNotification = @"PNDOAuthTokenWillFetch";
NSString *const PNDOAuthTokenFetchDidSucceedNotification = @"PNDOAuthTokenDidFetch";
NSString *const PNDOAuthTokenFetchDidFailNotification = @"PNDOAuthTokenFailedFetch";

NSString *const PNDOAuthTokenFetchTypeKey = @"PNDOAuthFetchType";
NSString *const PNDOAuthTokenFetchErrorKey = @"PNDOAuthFetchError";

NSString *const PNDOAuthTokenFetchTypeRequest = @"request";
NSString *const PNDOAuthTokenFetchTypeAccess = @"access";
NSString *const PNDOAuthTokenFetchTypeUserInfo = @"userInfo";

NSString *const PNDOAuthUserWillSignInNotification = @"PNDOAuthUserWillSignIn";
NSString *const PNDOAuthUserDidSignInNotification = @"PNDOAuthUserDidSignIn";
NSString *const PNDOAuthUserCancelledSigningInNotification = @"PNDOAuthUserCancelledSigningIn";

NSString *const PNDOAuthNetworkLostNotification = @"PNDOAuthNetworkLost";
NSString *const PNDOAuthNetworkFoundNotification = @"PNDOAuthNetworkFound";

// standard OAuth keys
NSString *const PNDOAuthConsumerKey          = @"oauth_consumer_key";
NSString *const PNDOAuthTokenKey             = @"oauth_token";
NSString *const PNDOAuthCallbackKey          = @"oauth_callback";
NSString *const PNDOAuthCallbackConfirmedKey = @"oauth_callback_confirmed";
NSString *const PNDOAuthTokenSecretKey       = @"oauth_token_secret";
NSString *const PNDOAuthSignatureMethodKey   = @"oauth_signature_method";
NSString *const PNDOAuthSignatureKey         = @"oauth_signature";
NSString *const PNDOAuthTimestampKey         = @"oauth_timestamp";
NSString *const PNDOAuthNonceKey             = @"oauth_nonce";
NSString *const PNDOAuthVerifierKey          = @"oauth_verifier";
NSString *const PNDOAuthVersionKey           = @"oauth_version";

// GetRequestToken extensions
NSString *const PNDOAuthDisplayNameKey       = @"xoauth_displayname";
NSString *const PNDOAuthScopeKey             = @"scope";

// AuthorizeToken extensions
NSString *const PNDOAuthDomainKey            = @"domain";
NSString *const PNDOAuthHostedDomainKey      = @"hd";
NSString *const PNDOAuthIconURLKey           = @"iconUrl";
NSString *const PNDOAuthLanguageKey          = @"hl";
NSString *const PNDOAuthMobileKey            = @"btmpl";

// additional persistent keys
NSString *const PNDOAuthServiceProviderKey        = @"serviceProvider";
NSString *const PNDOAuthUserEmailKey              = @"email";
NSString *const PNDOAuthUserEmailIsVerifiedKey    = @"isVerified";

extern NSString *AFQueryStringFromParametersWithEncoding(NSDictionary *parameters, NSStringEncoding stringEncoding);

static NSString *const PNDOAuthSignatureMethodName[] = {
	@"PLAINTEXT",
    @"HMAC-SHA1",
};

static NSString *PNDOAuthSignatureNameForMethod(PNDOAuthSignatureMethod method) {
	return PNDOAuthSignatureMethodName[method];
}

#pragma mark AFNetworking helper

@interface AFQueryStringPair : NSObject
@property (readwrite, nonatomic, retain) id field;
@property (readwrite, nonatomic, retain) id value;

- (id)initWithField:(id)field value:(id)value;

- (NSString *)URLEncodedStringValueWithEncoding:(NSStringEncoding)stringEncoding;

@end

#pragma mark - Utility Functions

static NSString *PNDOAuthEncodeParameter(NSString *string) {
	// http://oauth.net/core/1.0a/#encoding_parameters
	if (!string)
		return nil;

	CFStringRef leaveUnescaped = CFSTR("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-._~");
	CFStringRef forceEscaped =  CFSTR("%!$&'()*+,/:;=?@");
	return (__bridge_transfer NSString *)CFURLCreateStringByAddingPercentEscapes(NULL, (__bridge CFStringRef)string, leaveUnescaped, forceEscaped, kCFStringEncodingUTF8);
}

static NSString *PNDOAuthDecodeParameter(NSString *string) {
	return [string stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
}

static NSString *PNDOAuthJoinParameters(NSDictionary *params, NSString *joiner, BOOL shouldQuote, BOOL shouldSort) {
	// create a string by joining the supplied param objects
	NSArray *keys = shouldSort ? [params.allKeys sortedArrayUsingSelector: @selector(compare:)] : params.allKeys;

	NSMutableString *string = [NSMutableString string];
	[keys enumerateObjectsUsingBlock:^(NSString *key, NSUInteger idx, BOOL *stop) {
		[string appendFormat: (shouldQuote ? @"%@=\"%@\"" : @"%@=%@"), PNDOAuthEncodeParameter(key), PNDOAuthEncodeParameter(params[key])];

		if (idx < keys.count - 1) {
			[string appendString: joiner];
		}
	}];
	return string;
}

static NSString *PNDOAuthNormalizeRequestURLString(NSURLRequest *request) {
	// http://oauth.net/core/1.0a/#anchor13

	NSURL *url = [[request URL] absoluteURL];

	NSString *scheme = [[url scheme] lowercaseString];
	NSString *host = [[url host] lowercaseString];
	int port = [[url port] intValue];

	// NSURL's path method has an unfortunate side-effect of unescaping the path,
	// but CFURLCopyPath does not
	NSString *path = (__bridge_transfer NSString *)CFURLCopyPath((CFURLRef)url);

	// include only non-standard ports for http or https
	NSString *portStr;
	if (port == 0
		|| ([scheme isEqual:@"http"] && port == 80)
		|| ([scheme isEqual:@"https"] && port == 443)) {
		portStr = @"";
	} else {
		portStr = [NSString stringWithFormat:@":%u", port];
	}

	if ([path length] == 0) {
		path = @"/";
	}

	return [NSString stringWithFormat:@"%@://%@%@%@", scheme, host, portStr, path];
}

static NSDictionary *PNDOAuthDictionaryFromResponse(NSString *responseStr) {
	// build a dictionary from a response string of the form
	// "foo=cat&bar=dog".  Missing or empty values are considered
	// empty strings; keys and values are percent-decoded.
	if (!responseStr.length) return nil;

	NSMutableDictionary *responseDict = [NSMutableDictionary dictionary];
	NSScanner *scanner = [NSScanner scannerWithString: responseStr];

	while (![scanner isAtEnd]) {
		NSString *key = nil;

		if ([scanner scanUpToString:@"=" intoString:&key]) {
			// if there's an "=", then scan the value, too, if any
			NSString *value = @"";
			if ([scanner scanString:@"=" intoString:nil]) {
				// scan the rest of the string
				[scanner scanUpToString:@"&" intoString:&value];
				[scanner scanString:@"&" intoString:NULL];
			}
			NSString *plainKey = PNDOAuthDecodeParameter(key);
			NSString *plainValue = PNDOAuthDecodeParameter(value);
			responseDict[plainKey] = plainValue;
		}
	}

	return responseDict;
}

static NSString *PNDOAuthBase64Encode(NSData *data) {
	// Cyrus Najmabadi elegent little encoder from
	// http://www.cocoadev.com/index.pl?BaseSixtyFour
	if (data == nil) return nil;

	const uint8_t* input = [data bytes];
	NSUInteger length = [data length];

	NSUInteger bufferSize = ((length + 2) / 3) * 4;
	NSMutableData* buffer = [NSMutableData dataWithLength:bufferSize];

	uint8_t* output = [buffer mutableBytes];

	static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	for (NSUInteger i = 0; i < length; i += 3) {
		NSInteger value = 0;
		for (NSUInteger j = i; j < (i + 3); j++) {
			value <<= 8;

			if (j < length) {
				value |= (0xFF & input[j]);
			}
		}

		NSInteger idx = (i / 3) * 4;
		output[idx + 0] =                    table[(value >> 18) & 0x3F];
		output[idx + 1] =                    table[(value >> 12) & 0x3F];
		output[idx + 2] = (i + 1) < length ? table[(value >> 6)  & 0x3F] : '=';
		output[idx + 3] = (i + 2) < length ? table[(value >> 0)  & 0x3F] : '=';
	}

	return [[NSString alloc] initWithData:buffer encoding:NSASCIIStringEncoding];
}

static NSString *PNDOAuthCreateHMACSHA1Hash(NSString *consumerSecret, NSString *tokenSecret, NSString *body) {
	NSString *encodedConsumerSecret = PNDOAuthEncodeParameter(consumerSecret);
	NSString *encodedTokenSecret = PNDOAuthEncodeParameter(tokenSecret);
	NSString *key = [NSString stringWithFormat:@"%@&%@", encodedConsumerSecret ?: @"", encodedTokenSecret ?: @""];
	NSMutableData *sigData = [NSMutableData dataWithLength:CC_SHA1_DIGEST_LENGTH];
	CCHmac(kCCHmacAlgSHA1, key.UTF8String, key.length, body.UTF8String, body.length, sigData.mutableBytes);
	return PNDOAuthBase64Encode(sigData);
}

static void PNDOAuthAddQueryStringToParams(NSMutableDictionary *dict, NSString *query) {
	// make param objects from the query parameters, and add them
	// to the supplied array
	// look for a query like foo=cat&bar=dog
	if (query.length) {
		// the standard test cases insist that + in the query string
		// be encoded as " " - http://wiki.oauth.net/TestCases
		query = [query stringByReplacingOccurrencesOfString:@"+" withString:@" "];
		[dict addEntriesFromDictionary: PNDOAuthDictionaryFromResponse(query)];
	}
}

static void PNDOAuthAddBodyFromRequestToParams(NSMutableDictionary *dict, NSURLRequest *request) {
	// add non-GET form parameters to the array of param objects
	NSString *method = [request HTTPMethod];
	if (method != nil && ![method isEqual:@"GET"]) {
		NSString *type = [request valueForHTTPHeaderField:@"Content-Type"];
		if ([type hasPrefix:@"application/x-www-form-urlencoded"]) {
			NSData *data = [request HTTPBody];
			if ([data length] > 0) {
				NSString *str = [[NSString alloc] initWithData:data
													  encoding:NSUTF8StringEncoding];
				if ([str length] > 0) {
					PNDOAuthAddQueryStringToParams(dict, str);
				}
			}
		}
	}
}

static NSString *PNDOAuthTimestamp(void) {
	NSTimeInterval timeInterval = [[NSDate date] timeIntervalSince1970];
	return [NSString stringWithFormat:@"%qu", (unsigned long long)timeInterval];
}

static NSString *PNDOAuthNonce(void) {
	// make a random 64-bit number
	return [[NSUUID UUID] UUIDString];
}

static NSString *PNDOAuthCreateSignature(NSURLRequest *request, NSDictionary *params, PNDOAuthSignatureMethod signatureMethod, NSString *consumerSecret, NSString *tokenSecret) {
	// construct signature base string per
	// http://oauth.net/core/1.0a/#signing_process
	NSString *requestURLStr = PNDOAuthNormalizeRequestURLString(request);
	NSString *method = [[request HTTPMethod] uppercaseString];
	if (!method.length) {
		method = @"GET";
	}

	// the signature params exclude the signature
	NSMutableDictionary *signatureParams = [params mutableCopy];

	// add request query parameters
	PNDOAuthAddQueryStringToParams(signatureParams, request.URL.query);

	// add parameters from the POST body, if any
	if (request.HTTPMethod && ![request.HTTPMethod isEqual:@"GET"]) {
		NSString *type = [request valueForHTTPHeaderField:@"Content-Type"];
		if ([type hasPrefix:@"application/x-www-form-urlencoded"]) {
			NSString *str = [[NSString alloc] initWithData: request.HTTPBody encoding: NSUTF8StringEncoding];
			PNDOAuthAddQueryStringToParams(signatureParams, str);
		}
	}

	NSString *paramStr = PNDOAuthJoinParameters(signatureParams, @"&", NO, YES);

	// the base string includes the method, normalized request URL, and params
	NSString *requestURLStrEnc = PNDOAuthEncodeParameter(requestURLStr);
	NSString *paramStrEnc = PNDOAuthEncodeParameter(paramStr);

	NSString *sigBaseString = [NSString stringWithFormat:@"%@&%@&%@", method, requestURLStrEnc, paramStrEnc];

	switch (signatureMethod) {
		case PNDOAuthSignatureMethodHMAC_SHA1:
			return PNDOAuthCreateHMACSHA1Hash(consumerSecret, tokenSecret, sigBaseString);
			break;
		default:
			return [NSString stringWithFormat: @"%@&%@", consumerSecret, tokenSecret];
			break;
	}
}

#pragma mark -

@interface PNDOAuth1Client ()

@property (nonatomic, strong) PNDMutableOAuth1Credential *credential;
@property (nonatomic, strong) id <PNDOAuth1LogInController> loginController;

@end

@implementation PNDOAuth1Client

- (id)initWithBaseURL:(NSURL *)url credential:(PNDMutableOAuth1Credential *)credential {
	NSParameterAssert(credential);
	if ((self = [super initWithBaseURL: url])) {
		self.credential = credential;
	}
	return self;
}

- (id)initWithBaseURL:(NSURL *)url serviceName:(NSString *)serviceName {
	return [self initWithBaseURL: url credential: [[PNDMutableOAuth1Credential alloc] initWithServiceName: serviceName]];
}

- (id)initWithBaseURL:(NSURL *)url serviceName:(NSString *)serviceName keychainIdentifier: (NSString *)identifier {
	if (!identifier) return [self initWithBaseURL: url serviceName: serviceName];
	return [self initWithBaseURL: url credential: [PNDMutableOAuth1Credential findStoreForServiceName: serviceName identifier: identifier] ?: [[PNDMutableOAuth1Credential alloc] initWithServiceName: serviceName identifier: identifier]];
}

- (id)initWithBaseURL:(NSURL *)url serviceName:(NSString *)serviceName username: (NSString *)username {
	return [self initWithBaseURL: url credential: [PNDMutableOAuth1Credential findStoreForServiceName: serviceName username: username] ?: [[PNDMutableOAuth1Credential alloc] initWithServiceName: serviceName]];
}

#pragma mark - NSCoding

- (void)encodeWithCoder:(NSCoder *)aCoder {
	[super encodeWithCoder: aCoder];
	
	[aCoder encodeObject: [NSKeyedArchiver archivedDataWithRootObject: self.credential] forKey: @"credential"];
	
	[aCoder encodeObject: self.consumerKey forKey: @"consumerKey"];
	[aCoder encodeObject: self.consumerSecret forKey: @"consumerSecret"];
	[aCoder encodeInteger: self.signatureMethod forKey: @"signatureMethod"];

	[aCoder encodeObject: self.scope forKey: @"scope"];
	[aCoder encodeObject: self.callback forKey: @"callback"];
	[aCoder encodeObject: self.realm forKey: @"realm"];
	[aCoder encodeObject: self.displayName forKey: @"displayName"];

	[aCoder encodeObject: self.requestTokenURL forKey: @"requestTokenURL"];
	[aCoder encodeObject: self.authorizationURL forKey: @"authorizationURL"];
	[aCoder encodeObject: self.accessTokenURL forKey: @"accessTokenURL"];
}

- (id)initWithCoder:(NSCoder *)aDecoder {
	if ((self = [super initWithCoder: aDecoder])) {
		self.credential = [NSKeyedUnarchiver unarchiveObjectWithData: [aDecoder decodeObjectForKey: @"credential"]];

		self.consumerKey = [aDecoder decodeObjectForKey: @"consumerKey"];
		self.consumerSecret = [aDecoder decodeObjectForKey: @"consumerSecret"];
		self.signatureMethod = [aDecoder decodeIntegerForKey: @"signatureMethod"];

		self.scope = [aDecoder decodeObjectForKey: @"scope"];
		self.callback = [aDecoder decodeObjectForKey: @"callback"];
		self.realm = [aDecoder decodeObjectForKey: @"realm"];
		self.displayName = [aDecoder decodeObjectForKey: @"displayName"];

		self.requestTokenURL = [aDecoder decodeObjectForKey: @"requestTokenURL"];
		self.authorizationURL = [aDecoder decodeObjectForKey: @"authorizationURL"];
		self.accessTokenURL = [aDecoder decodeObjectForKey: @"accessTokenURL"];
	}
	return self;
}

#pragma mark - AFHTTPClient

- (NSMutableURLRequest *)requestWithMethod:(NSString *)method path:(NSString *)path parameters:(NSDictionary *)parameters {
	NSMutableURLRequest *request = [super requestWithMethod:method path:path parameters:parameters];
	request.timeoutInterval = 20;
	request.HTTPShouldHandleCookies = NO;

	if (self.canAuthorize) {
		[self addResourceTokenHeaderToRequest:request];
	}

	return request;
}

#pragma mark - Actions

- (void)reset {
	[self.credential evict];
}

#pragma mark - Utility maps

+ (NSDictionary *)parameterPropertyMap {
	return @{
	PNDOAuthConsumerKey: @"consumerKey",
	PNDOAuthSignatureMethodKey: @"signatureMethodString",
	PNDOAuthVersionKey: @"version",
	PNDOAuthCallbackKey: @"callback",
	PNDOAuthDisplayNameKey: @"displayName",
	PNDOAuthScopeKey: @"scope",
	PNDOAuthTokenKey: @"credential.token",
	PNDOAuthHostedDomainKey: @"credential.hostedDomain",
	PNDOAuthDomainKey: @"credential.domain",
	PNDOAuthIconURLKey: @"credential.iconURLString",
	PNDOAuthLanguageKey: @"credential.language",
	PNDOAuthMobileKey: @"credential.mobile",
	PNDOAuthVerifierKey: @"credential.verifier",
	PNDOAuthServiceProviderKey: @"credential.serviceName",
	PNDOAuthUserEmailKey: @"credential.username",
	PNDOAuthUserEmailIsVerifiedKey: @"credential.userEmailIsVerified",
	PNDOAuthTokenSecretKey: @"credential.secret",
	PNDOAuthCallbackConfirmedKey: @"credential.callbackConfirmed",
	};
}

+ (NSArray *)tokenRequestKeys {
	// keys for obtaining a request token http://oauth.net/core/1.0a/#auth_step1
	return @[ PNDOAuthConsumerKey, PNDOAuthSignatureMethodKey,
	PNDOAuthSignatureKey, PNDOAuthTimestampKey, PNDOAuthNonceKey,
	PNDOAuthVersionKey, PNDOAuthCallbackKey, PNDOAuthDisplayNameKey,
	PNDOAuthScopeKey ];
}

+ (NSArray *)tokenAuthorizeKeys {
	// keys for opening the authorize page http://oauth.net/core/1.0a/#auth_step2
	return @[ PNDOAuthTokenKey, PNDOAuthDomainKey, PNDOAuthHostedDomainKey,
	PNDOAuthLanguageKey, PNDOAuthMobileKey, PNDOAuthScopeKey ];
}

+ (NSArray *)tokenAccessKeys {
	// keys for obtaining an access token http://oauth.net/core/1.0a/#auth_step3
	return @[ PNDOAuthConsumerKey, PNDOAuthTokenKey, PNDOAuthSignatureMethodKey,
	PNDOAuthSignatureKey, PNDOAuthTimestampKey, PNDOAuthNonceKey,
	PNDOAuthVersionKey, PNDOAuthVerifierKey ];
}

+ (NSArray *)tokenResourceKeys {
	// keys for accessing protected resource http://oauth.net/core/1.0a/#anchor12
	return @[ PNDOAuthConsumerKey, PNDOAuthTokenKey, PNDOAuthSignatureMethodKey,
	PNDOAuthSignatureKey, PNDOAuthTimestampKey, PNDOAuthNonceKey,
	PNDOAuthVersionKey ];
}

+ (NSArray *)persistenceKeys {
	// keys that we save into the keychain
	return @[ PNDOAuthTokenKey, PNDOAuthTokenSecretKey,
	PNDOAuthCallbackConfirmedKey, PNDOAuthVerifierKey, PNDOAuthServiceProviderKey,
	PNDOAuthUserEmailKey, PNDOAuthUserEmailIsVerifiedKey ];
}

#pragma mark - Parameter getters

- (NSDictionary *)paramsForRequest:(NSURLRequest *)request keys:(NSArray *)keys {
	// this is the magic routine that collects the parameters for the specified
	// keys, and signs them
	NSMutableDictionary *params = [NSMutableDictionary dictionary];

	// go through all of our local properties first
	NSDictionary *map = self.class.parameterPropertyMap;
	[map enumerateKeysAndObjectsUsingBlock:^(NSString *key, NSString *localKey, BOOL *stop) {
		if (![keys containsObject: key]) return;
		NSString *value = [self valueForKeyPath: localKey];
		if (value.length) params[key] = value;
	}];

	// add nonce if wanted
	if ([keys containsObject: PNDOAuthNonceKey]) {
		params[PNDOAuthNonceKey] = PNDOAuthNonce();
	}

	// add timestamp if wanted
	if ([keys containsObject: PNDOAuthTimestampKey]) {
		params[PNDOAuthTimestampKey] = PNDOAuthTimestamp();
	}

	// finally, compute the signature, if requested; the params
	// must be complete for this
	if ([keys containsObject: PNDOAuthSignatureKey]) {
		NSString *value = PNDOAuthCreateSignature(request, params, self.signatureMethod, self.consumerSecret, self.credential.secret);
		params[PNDOAuthSignatureKey] = value;
	}

	return params;
}

- (void)addParams:(NSDictionary *)params toRequest:(NSMutableURLRequest *)request {
	NSString *paramStr = PNDOAuthJoinParameters(params, @"&", NO, NO);
	NSURL *oldURL = [request URL];
	NSString *query = [oldURL query];
	if ([query length] > 0) {
		query = [query stringByAppendingFormat:@"&%@", paramStr];
	} else {
		query = paramStr;
	}

	NSString *oldPort = oldURL.port.stringValue;
	NSString *portStr = oldPort.length ? [@":" stringByAppendingString: oldPort] : @"";

	NSString *qMark = [query length] > 0 ? @"?" : @"";
	NSString *newURLStr = [NSString stringWithFormat:@"%@://%@%@%@%@%@",
						   [oldURL scheme], [oldURL host], portStr,
						   [oldURL path], qMark, query];

	[request setURL:[NSURL URLWithString:newURLStr]];
}

- (void)addParamsToRequest:(NSMutableURLRequest *)request forKeys:(NSArray *)keys {
	// For the specified keys, add the keys and values to the request URL.
	[self addParams: [self paramsForRequest: request keys: keys] toRequest: request];
}

- (void)addAuthorizationHeaderToRequest:(NSMutableURLRequest *)request forKeys:(NSArray *)keys {
	// make all the parameters, including a signature for all
	NSDictionary *params = [self paramsForRequest: request keys: keys];

	// split the params into "oauth_" params which go into the Auth header
	// and others which get added to the query
	NSMutableDictionary *oauthParams = [NSMutableDictionary dictionary];
	NSMutableDictionary *extendedParams = [NSMutableDictionary dictionary];

	for (NSString *param in params) {
		BOOL hasPrefix = [param hasPrefix:@"oauth_"];
		if (hasPrefix) {
			oauthParams[param] = params[param];
		} else {
			extendedParams[param] = params[param];
		}
	}

	NSString *paramStr = PNDOAuthJoinParameters(oauthParams, @", ", YES, NO);

	// include the realm string, if any, in the auth header
	// http://oauth.net/core/1.0a/#auth_header
	NSString *realmParam = @"";
	NSString *realm = [self realm];
	if ([realm length] > 0) {
		NSString *encodedVal = PNDOAuthEncodeParameter(realm);
		realmParam = [NSString stringWithFormat:@"realm=\"%@\", ", encodedVal];
	}

	// set the parameters for "oauth_" keys and the realm
	// in the authorization header
	NSString *authHdr = [NSString stringWithFormat:@"OAuth %@%@",
						 realmParam, paramStr];
	[request setValue:authHdr forHTTPHeaderField:@"Authorization"];

	// add any other params as URL query parameters
	if ([extendedParams count] > 0) {
		[self addParams:extendedParams toRequest:request];
	}
}

#pragma - Signing

- (void)addRequestTokenHeaderToRequest:(NSMutableURLRequest *)request {
	// add request token params to the request's header
	[self addAuthorizationHeaderToRequest: request forKeys: self.class.tokenRequestKeys];
}

- (void)addRequestTokenParamsToRequest:(NSMutableURLRequest *)request {
	// add request token params to the request URL (not to the header)
	[self addParamsToRequest: request forKeys: self.class.tokenRequestKeys];
}

- (void)addAuthorizeTokenHeaderToRequest:(NSMutableURLRequest *)request {
	// add authorize token params to the request's header
	[self addAuthorizationHeaderToRequest: request forKeys: self.class.tokenAuthorizeKeys];
}

- (void)addAuthorizeTokenParamsToRequest:(NSMutableURLRequest *)request {
	// add authorize token params to the request URL (not to the header)
	[self addParamsToRequest: request forKeys: self.class.tokenAuthorizeKeys];
}

- (void)addAccessTokenHeaderToRequest:(NSMutableURLRequest *)request {
	// add access token params to the request's header
	[self addAuthorizationHeaderToRequest: request forKeys: self.class.tokenAccessKeys];
}

- (void)addAccessTokenParamsToRequest:(NSMutableURLRequest *)request {
	// add access token params to the request URL (not to the header)
	[self addParamsToRequest: request forKeys: self.class.tokenAccessKeys];
}

- (void)addResourceTokenHeaderToRequest:(NSMutableURLRequest *)request {
	// add resource access token params to the request's header
	[self addAuthorizationHeaderToRequest: request forKeys: self.class.tokenResourceKeys];
}

- (void)addResourceTokenParamsToRequest:(NSMutableURLRequest *)request {
	// add resource access token params to the request URL (not to the header)
	[self addParamsToRequest: request forKeys: self.class.tokenResourceKeys];
}

#pragma mark - Settings

- (void)setAuthenticationKeysForResponseDictionary:(NSDictionary *)dict {
	NSArray *persistenceKeys = self.class.persistenceKeys;
	NSDictionary *parameterPropertyMap = self.class.parameterPropertyMap;
	[dict enumerateKeysAndObjectsUsingBlock:^(NSString *key, id value, BOOL *stop) {
		if ([persistenceKeys containsObject: key])
		{
			[self setValue: value forKeyPath: parameterPropertyMap[key]];
		}
	}];
}

- (void)setAuthenticationKeysForResponseData:(NSData *)data {
	NSString *responseStr = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	NSDictionary *responseDict = PNDOAuthDictionaryFromResponse(responseStr);
	[self setAuthenticationKeysForResponseDictionary: responseDict];
}

- (void)setAuthenticationKeysForResponseString:(NSString *)str {
	NSDictionary *responseDict = PNDOAuthDictionaryFromResponse(str);
	[self setAuthenticationKeysForResponseDictionary: responseDict];
}

#pragma mark - Accessors

- (NSString *)signatureMethodString {
	return PNDOAuthSignatureNameForMethod(self.signatureMethod);
}

- (NSString *)keychainIdentifier {
	return self.credential.identifier;
}

- (NSString *)userEmail {
	return self.credential.userEmail;
}

- (BOOL)userEmailIsVerified {
	return [self.credential.userEmailIsVerified boolValue];
}

- (BOOL)canAuthorize {
	return self.credential.hasToken;
}

- (NSString *)version {
	return @"1.0";
}

- (NSString *)displayName {
	if (_displayName.length) return _displayName;
	
    NSString *displayName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleDisplayName"];
    if (!displayName.length) {
		displayName = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleName"];
		if (!displayName.length) {
			displayName = [[[NSBundle mainBundle] executablePath] lastPathComponent];
		}
    }
	return displayName;
}

#pragma mark - Signing in

- (void)startSigningInWithController:(id <PNDOAuth1LogInController>)controller success:(void(^)(void))success failure:(void(^)(NSError *err))failure {
	[self getRequestTokenAtPath: self.requestTokenURL.absoluteString success:^(NSDictionary *response) {
		[self setAuthenticationKeysForResponseDictionary: response];
		[self startWebRequestAtPath: self.authorizationURL.absoluteString withController: controller success:^(NSDictionary *response){
			[self setAuthenticationKeysForResponseDictionary: response];
			[self getAccessTokenAtPath: self.accessTokenURL.absoluteString success:^(NSDictionary *response) {
				[self setAuthenticationKeysForResponseDictionary: response];
				if (success) success();
			} failure: failure];
		} failure: failure];
	} failure: failure];
}

- (void)cancelSigningIn {
	NSString *requestTokenPath = self.requestTokenURL.absoluteString;
	NSString *authorizationPath = self.authorizationURL.absoluteString;
	NSString *accessTokenPath = self.requestTokenURL.absoluteString;

	for (NSOperation *operation in [self.operationQueue operations]) {
        if (![operation isKindOfClass:[AFHTTPRequestOperation class]]) {
            continue;
        }

		NSString *URLString = [[[(AFHTTPRequestOperation *)operation request] URL] absoluteString];
        if ([URLString hasPrefix: requestTokenPath] || [URLString hasPrefix: authorizationPath] || [URLString hasPrefix: accessTokenPath]) {
            [operation cancel];
        }
    }
	[self.loginController dismiss];
	[self reset];
}

#pragma mark - Authorization requests

- (void)getRequestTokenAtPath:(NSString *)requestTokenPath success:(void(^)(NSDictionary *response))success failure:(void(^)(NSError *err))failure {
	NSParameterAssert(success);
	NSMutableURLRequest *request = [super requestWithMethod: @"GET" path: requestTokenPath parameters: nil];
	request.HTTPShouldHandleCookies = NO;
	[self addRequestTokenHeaderToRequest: request];
	NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

	AFHTTPRequestOperation *op = [[AFHTTPRequestOperation alloc] initWithRequest: request];
	[op setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
		[nc postNotificationName: PNDOAuthTokenFetchDidSucceedNotification object: self userInfo: @{ PNDOAuthTokenFetchTypeKey : PNDOAuthTokenFetchTypeRequest }];
		success(PNDOAuthDictionaryFromResponse(operation.responseString));
	} failure:^(AFHTTPRequestOperation *operation, NSError *error) {
		NSDictionary *userInfo = @{
			PNDOAuthTokenFetchTypeKey: PNDOAuthTokenFetchTypeRequest,
			PNDOAuthTokenFetchErrorKey: error
		};

		[nc postNotificationName: PNDOAuthTokenFetchDidFailNotification object: self userInfo: userInfo];

		if (failure) {
			NSError *newError = [NSError errorWithDomain: PNDOAuthErrorDomain code: PNDOAuthTokenFetchFailedError userInfo: userInfo];
			failure(newError);
		}
	}];
	[self enqueueHTTPRequestOperation: op];
	[nc postNotificationName: PNDOAuthTokenFetchWillStartNotification object: self userInfo: @{ PNDOAuthTokenFetchTypeKey : PNDOAuthTokenFetchTypeRequest }];
}

- (void)startWebRequestAtPath:(NSString *)authorizationPath withController:(id <PNDOAuth1LogInController>)controller success:(void(^)(NSDictionary *response))success failure:(void(^)(NSError *err))failure {
	NSParameterAssert(success);
	NSString *token = self.credential.token;
	if (token.length) {
		NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
		[nc postNotificationName: PNDOAuthUserWillSignInNotification object: self];

		self.loginController = controller;

		controller.successHandler = ^(NSString *responseStr){
			[nc postNotificationName: PNDOAuthUserDidSignInNotification object: self];
			success(PNDOAuthDictionaryFromResponse(responseStr));
		};

		controller.cancelledHandler = ^{
			[nc postNotificationName: PNDOAuthUserCancelledSigningInNotification object: self];
			if (failure) failure([NSError errorWithDomain: PNDOAuthErrorDomain code: PNDOAuthCancelledError userInfo: nil]);
		};

		controller.redirectHandler = ^(NSURLRequest *request){
			if (!self.callback.length)
				return NO;

			NSURL *callbackURL = [NSURL URLWithString: self.callback];
			return (BOOL)([callbackURL.host isEqual: request.URL.host] && [callbackURL.path isEqual: request.URL.path]);
		};
		
		[controller present];
		
		NSMutableURLRequest *request = [super requestWithMethod: @"GET" path: authorizationPath parameters: nil];
		request.HTTPShouldHandleCookies = NO;
		[self addAuthorizeTokenParamsToRequest:request];
		[controller loadURLRequest: request];
	} else {
		failure([NSError errorWithDomain: PNDOAuthErrorDomain code: PNDOAuthMissingPropertyError userInfo: @{ PNDOAuthErrorMissingPropertyKey : PNDOAuthTokenKey }]);
	}
}

- (void)getAccessTokenAtPath:(NSString *)accessTokenPath success:(void(^)(NSDictionary *response))success failure:(void(^)(NSError *err))failure {
	NSParameterAssert(success);
	NSMutableURLRequest *request = [super requestWithMethod: @"POST" path: accessTokenPath parameters: nil];
	request.HTTPShouldHandleCookies = NO;
	[self addAccessTokenHeaderToRequest: request];
	NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];

	AFHTTPRequestOperation *op = [[AFHTTPRequestOperation alloc] initWithRequest: request];
	[op setCompletionBlockWithSuccess:^(AFHTTPRequestOperation *operation, id responseObject) {
		[nc postNotificationName: PNDOAuthTokenFetchDidSucceedNotification object: self userInfo: @{ PNDOAuthTokenFetchTypeKey : PNDOAuthTokenFetchTypeAccess }];
		success(PNDOAuthDictionaryFromResponse(operation.responseString));
	} failure:^(AFHTTPRequestOperation *operation, NSError *error) {
		NSDictionary *userInfo = @{
			PNDOAuthTokenFetchTypeKey: PNDOAuthTokenFetchTypeAccess,
			PNDOAuthTokenFetchErrorKey: error
		};

		[nc postNotificationName: PNDOAuthTokenFetchDidFailNotification object: self userInfo: userInfo];

		if (failure) {
			NSError *newError = [NSError errorWithDomain: PNDOAuthErrorDomain code: PNDOAuthTokenFetchFailedError userInfo: userInfo];
			failure(newError);
		}
	}];
	[self enqueueHTTPRequestOperation: op];
	[nc postNotificationName: PNDOAuthTokenFetchWillStartNotification object: self userInfo: @{ PNDOAuthTokenFetchTypeKey : PNDOAuthTokenFetchTypeAccess }];
}

@end