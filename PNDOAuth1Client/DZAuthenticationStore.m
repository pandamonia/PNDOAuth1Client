//
//  DZAuthenticationStore.m
//  PNDOAuth1Client
//
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "DZAuthenticationStore.h"
#import <objc/runtime.h>

static NSString *const DZAuthenticationStoreUserDefaultsKey = @"DZAuthenticationStoreLibrary";

static inline BOOL DZClassIsMutable(Class cls) {
	return ([NSStringFromClass(cls) rangeOfString: @"Mutable"].location != NSNotFound) || class_conformsToProtocol(cls, @protocol(DZMutableAuthenticationStore));
}

@interface DZAuthenticationStore ()

@property (nonatomic, strong) NSDictionary *baseQuery;

@end

@implementation DZAuthenticationStore

@synthesize username = _username, userInfo = _userInfo, transientProperties = _transientProperties;

#pragma mark - Automatic KVC properties

static SEL getterForProperty(objc_property_t property)
{
	if (!property)
		return NULL;
	
	SEL getter = NULL;
    
	char *getterName = property_copyAttributeValue(property, "G");
	if (getterName)
		getter = sel_getUid(getterName);
	else
		getter = sel_getUid(property_getName(property));
	free(getterName);
	
	return getter;
}

static SEL setterForProperty(objc_property_t property)
{
	if (!property)
		return NULL;
	
	SEL setter = NULL;
    
	char *setterName = property_copyAttributeValue(property, "S");
	if (setterName)
		setter = sel_getUid(setterName);
	else {
		NSString *propertyName = @(property_getName(property));
		unichar firstChar = [propertyName characterAtIndex: 0];
		NSString *coda = [propertyName substringFromIndex: 1];
		setter = NSSelectorFromString([NSString stringWithFormat: @"set%c%@:", toupper(firstChar), coda]);
	}
	free(setterName);
	
	return setter;
}

static NSString *propertyNameForAccessor(Class cls, SEL selector) {
    if (!cls || !selector)
        return nil;
    
    NSString *propertyName = NSStringFromSelector(selector);
    if ([propertyName hasPrefix: @"set"])
    {
        unichar firstChar = [propertyName characterAtIndex: 3];
        NSString *coda = [propertyName substringWithRange: NSMakeRange(4, propertyName.length - 5)]; // -5 to remove trailing ':'
        propertyName = [NSString stringWithFormat: @"%c%@", tolower(firstChar), coda];
    }
    
    if (!class_getProperty(cls, propertyName.UTF8String))
    {
        // It's not a simple -xBlock/setXBlock: pair
        
        // If selector ends in ':', it's a setter.
        const BOOL isSetter = [NSStringFromSelector(selector) hasSuffix: @":"];
        const char *key = (isSetter ? "S" : "G");
        
        unsigned int i, count;
        objc_property_t *properties = class_copyPropertyList(cls, &count);
        
        for (i = 0; i < count; ++i)
        {
            objc_property_t property = properties[i];
            
            char *accessorName = property_copyAttributeValue(property, key);
            SEL accessor = sel_getUid(accessorName);
            if (sel_isEqual(selector, accessor))
            {
                propertyName = @(property_getName(property));
                break; // from for-loop
            }
            
            free(accessorName);
        }
        
        free(properties);
    }
    
    return propertyName;
}

static id getValueImplementation(NSObject *self, SEL _cmd) {
	return [self valueForUndefinedKey: propertyNameForAccessor([self class], _cmd)];
}

static void setValueImplementation(NSObject *self, SEL _cmd, id value) {
	[self setValue: value forUndefinedKey: propertyNameForAccessor([self class], _cmd)];
}

+ (BOOL)resolveInstanceMethod:(SEL)sel {
	NSString *propertyName = propertyNameForAccessor(self, sel);
	objc_property_t property = class_getProperty(self, propertyName.UTF8String);
	
	if (sel_isEqual(sel, getterForProperty(property))) {
		class_addMethod(self, sel, (IMP)getValueImplementation, "@@:");
	}
	
	char *readonly = property_copyAttributeValue(property, "R");
	BOOL isMutable = DZClassIsMutable(self);
	if (!isMutable && !readonly && sel_isEqual(sel, setterForProperty(property))) {
		class_addMethod(self, sel, imp_implementationWithBlock(^(NSObject *self, id value){
			[self setValue: value forUndefinedKey: propertyName];
		}), "v@:@");
	}
	free(readonly);
	
	return [super resolveInstanceMethod: sel];
}

#pragma mark Private

+ (id)dz_storeWithServiceName:(NSString *)name identifier:(NSString *)identifier username:(NSString *)username userInfo:(NSDictionary *)userInfo {
	DZAuthenticationStore *ret = [[[self class] alloc] initWithServiceName: name identifier: identifier];
	ret->_username = [username copy];
	ret->_userInfo = [userInfo copy];
	return ret;
}

- (void)dz_sharedInit {
	self.baseQuery = @{
	(__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
	(__bridge id)kSecAttrLabel: [NSString stringWithFormat: @"%@.%@", [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleIdentifier"], self.serviceName],
	(__bridge id)kSecAttrAccount: self.identifier,
	(__bridge id)kSecAttrService: self.serviceName
	};
}

- (Class)mutableClass {
	return [DZMutableAuthenticationStore class];
}

#pragma mark Initializers

+ (id)storeWithServiceName:(NSString *)name username:(NSString *)username contents:(id <NSCoding, NSObject>)contents userInfo:(NSDictionary *)userInfo {
	DZAuthenticationStore *ret = [[[self class] alloc] initWithServiceName: name];
	ret->_username = [username copy];
	ret->_userInfo = [userInfo copy];
	[ret setContents: contents];
	return ret;
}

- (id)init {
	[self doesNotRecognizeSelector: _cmd];
	return nil;
}

- (id)initWithServiceName:(NSString *)serviceName {
	return [self initWithServiceName: serviceName identifier: [[NSUUID UUID] UUIDString]];
}

- (id)initWithServiceName:(NSString *)serviceName identifier:(NSString *)identifier {
    if ((self = [super init])) {
		_serviceName = serviceName.length ? serviceName : [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleName"];
		_identifier = identifier;
		_transientProperties = [NSMutableDictionary dictionary];
		
		[self dz_sharedInit];

		NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];

		NSMutableDictionary *authStore = [[defaults dictionaryForKey: DZAuthenticationStoreUserDefaultsKey] mutableCopy] ?: [NSMutableDictionary dictionary];
		NSMutableArray *serviceStore = [authStore[serviceName] mutableCopy] ?: [NSMutableArray array];

		if (![serviceStore containsObject: self.identifier]) {
			[serviceStore addObject: self.identifier];

			authStore[serviceName] = serviceStore;

			[defaults setObject: authStore forKey: DZAuthenticationStoreUserDefaultsKey];
			[defaults synchronize];
		}
    }
    return self;
}

- (id)initWithAuthenticationStore:(DZAuthenticationStore *)store {
	if ((self = [self initWithServiceName: store.serviceName])) {
		_username = [store.username copy];
		_userInfo = [store.userInfo copy];
		_transientProperties = [store.transientProperties mutableCopy];
		self.contents = store.contents;
	}
	return self;
}

#pragma mark NS<Mutable>Copying

- (id)copyWithZone:(NSZone *)zone {
	if ([self conformsToProtocol: @protocol(DZMutableAuthenticationStore)]) {
		Class immutableSuperclass = [self class];
		while (DZClassIsMutable(immutableSuperclass) && immutableSuperclass != [DZAuthenticationStore class]) {
			immutableSuperclass = [immutableSuperclass superclass];
		}
		return [[immutableSuperclass alloc] initWithAuthenticationStore: self];
	} else {
		return self;
	}
}

- (id)mutableCopyWithZone:(NSZone *)zone {
	Class mutableClass = [self conformsToProtocol: @protocol(DZMutableAuthenticationStore)] ? [self class] : [self mutableClass];
	return [[mutableClass alloc] initWithAuthenticationStore: self];
}

#pragma mark NSCoding

+ (BOOL)supportsSecureCoding {
	return YES;
}

- (id)initWithCoder:(NSCoder *)aDecoder {
    if ((self = [super init])) {
		_serviceName = [[aDecoder decodeObjectOfClass: [NSString class] forKey: @"serviceName"] copy];
		_identifier = [[aDecoder decodeObjectOfClass: [NSString class] forKey: @"identifier"] copy];
		_username = [[aDecoder decodeObjectOfClass: [NSString class] forKey: @"username"] copy];
		_userInfo = [[aDecoder decodeObjectOfClass: [NSString class] forKey: @"userInfo"] copy];
		_transientProperties = [[aDecoder decodeObjectOfClass: [NSDictionary class] forKey: @"transientProperties"] copy] ?: [NSMutableDictionary dictionary];
		[self dz_sharedInit];
	}
	return self;
}

- (void) encodeWithCoder:(NSCoder *)aCoder {
	[aCoder encodeObject: self.serviceName forKey: @"serviceName"];
	[aCoder encodeObject: self.username forKey: @"username"];
	[aCoder encodeObject: self.userInfo forKey: @"userInfo"];
    [aCoder encodeObject: self.identifier forKey: @"identifier"];
    [aCoder encodeObject: self.transientProperties forKey: @"transientProperties"];
}

#pragma mark Properties

- (void) setUsername:(NSString *)username {
	if ([_username isEqual: username])
		return;
	
	_username = [username copy];
	
	if (!self.identifier)
		return;
	
	id contents = self.contents;
	
	if (!contents)
		return;
	
	[self setContents: contents];
}

- (void) setUserInfo:(NSDictionary *)userInfo {
	if ([_userInfo isEqualToDictionary: userInfo])
		return;
	
	_userInfo = [userInfo copy];
	
	if (!self.identifier)
		return;
	
	id contents = self.contents;
	
	if (!contents)
		return;
	
	[self setContents: contents];
}

- (void)setContents:(id<NSObject,NSCoding>)contents {
    CFMutableDictionaryRef query = (__bridge_retained CFMutableDictionaryRef)[self.baseQuery mutableCopy];
	
	NSMutableDictionary *userInfo = [self.username.length ? @{ @"username": self.username } : @{} mutableCopy];
	[userInfo addEntriesFromDictionary:self.userInfo];
	NSData *userInfoData = [NSJSONSerialization dataWithJSONObject: userInfo options: 0 error: NULL];
	
    NSData *data = nil;
	
	if (contents) {
		if ([contents isKindOfClass:[NSString class]])
			data = [(NSString *)contents dataUsingEncoding: NSUTF8StringEncoding];
		else if ([NSJSONSerialization isValidJSONObject:contents])
			data = [NSJSONSerialization dataWithJSONObject: contents options: 0 error: NULL];
	}

    if (data.length) {
        id existingContents = self.contents;
        if (!existingContents) {
			CFDictionarySetValue(query, kSecAttrGeneric, (__bridge CFDataRef)userInfoData);
			CFDictionarySetValue(query, kSecValueData, (__bridge CFDataRef)data);
            OSStatus status = SecItemAdd(query, NULL);
            NSAssert(status == noErr, @"Error executing query on keychain.");
        } else {
			CFDictionaryRef updateQuery = (__bridge_retained CFDictionaryRef)@{ (__bridge id)kSecValueData : data, (__bridge id)kSecAttrGeneric : userInfoData };
            SecItemUpdate(query, updateQuery);
			
			CFRelease(updateQuery);
        }
    } else {
        SecItemDelete(query);
    }
	
	CFRelease(query);
}

- (id<NSCoding>)contents {
    CFMutableDictionaryRef query = (__bridge_retained CFMutableDictionaryRef)[self.baseQuery mutableCopy];
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);
    CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
	CFRelease(query);
    
    if (status != noErr)
        return nil;
    
    NSData *data = (__bridge_transfer NSData *)result;
    id ret = nil;
    if (!(ret = [NSJSONSerialization JSONObjectWithData: data options: 0 error: NULL])) {
		ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	}
    return ret;
}

- (void)evict {
	[self setContents: nil];
}

#pragma mark Basic KVC

- (id)valueForUndefinedKey:(NSString *)key {
	NSSet *userInfoKeys = [[self class] keyPathsForValuesAffectingValueForKey: @"userInfo"];
	NSSet *contentsKeys = [[self class] keyPathsForValuesAffectingValueForKey: @"contents"];
	NSSet *transientsKeys = [[self class] keyPathsForValuesAffectingValueForKey: @"transientProperties"];
	
	if ([contentsKeys containsObject: key]) {
		if (contentsKeys.count > 1) {
			return self.contents[key];
		} else {
			return self.contents;
		}
	} else if ([userInfoKeys containsObject: key]) {
		return self.userInfo[key];
	} else if ([transientsKeys containsObject: key]) {
		return self.transientProperties[key];
	} else {
		return [super valueForUndefinedKey: key];
	}
}

- (void)setValue:(id)value forUndefinedKey:(NSString *)key {
	BOOL isMutable = ([NSStringFromClass([self class]) rangeOfString:@"Mutable"].location != NSNotFound);
	
	NSSet *userInfoKeys = [[self class] keyPathsForValuesAffectingValueForKey: @"userInfo"];
	NSSet *contentsKeys = [[self class] keyPathsForValuesAffectingValueForKey: @"contents"];
	NSSet *transientsKeys = [[self class] keyPathsForValuesAffectingValueForKey: @"transientProperties"];

	if (isMutable && [contentsKeys containsObject: key]) {
		if (contentsKeys.count > 1) {
			NSMutableDictionary *userInfo = [(NSDictionary *)self.contents mutableCopy] ?: [NSMutableDictionary dictionary];
			userInfo[key] = value;
			self.contents = userInfo;
		} else {
			self.contents = value;
		}
	} else if (isMutable && [userInfoKeys containsObject: key]) {
		NSMutableDictionary *userInfo = [self.userInfo mutableCopy] ?: [NSMutableDictionary dictionary];
		userInfo[key] = value;
		self.userInfo = userInfo;
	} else if (isMutable && [transientsKeys containsObject: key]) {
		NSMutableDictionary *dict = (id)self.transientProperties;
		dict[key] = value;
	} else {
		[super setValue: value forUndefinedKey: key];
	}
}

@end

@implementation DZMutableAuthenticationStore



@end

@implementation DZAuthenticationStore (DZAuthenticationStoreFactory)

+ (NSSet *)findStoresForService:(NSString *)serviceName {
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
	
	NSDictionary *authStore = [defaults dictionaryForKey: DZAuthenticationStoreUserDefaultsKey];
	if (!authStore.count)
		return nil;

	NSArray *storesForService = authStore[serviceName];
	NSMutableSet *set = [NSMutableSet setWithCapacity: storesForService.count];
	[storesForService enumerateObjectsUsingBlock:^(NSString *identifier, NSUInteger idx, BOOL *stop) {
		[set addObject: [[self class] findStoreForServiceName: serviceName identifier: identifier]];
	}];
	return set;
}

+ (instancetype)findStoreForServiceName:(NSString *)serviceName identifier:(NSString *)unique {
	if (!serviceName.length || !unique.length)
		return nil;
	
	NSDictionary *query = [@{
						   (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
						   (__bridge id)kSecAttrService: serviceName,
						   (__bridge id)kSecAttrLabel: [NSString stringWithFormat: @"%@.%@", [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleIdentifier"], serviceName],
						   (__bridge id)kSecAttrAccount: unique,
						   (__bridge id)kSecReturnAttributes: @YES,
						   (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitOne
						   } mutableCopy];
	CFDictionaryRef attributes = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&attributes);
    
    if (status != noErr)
        return nil;
	
	NSDictionary *match = (__bridge_transfer NSDictionary *)attributes;
	NSData *userInfoData = match[(__bridge id)kSecAttrGeneric];
	
	NSMutableDictionary *userInfo = [[NSJSONSerialization JSONObjectWithData: userInfoData options: 0 error: NULL] mutableCopy];
	NSString *username = userInfo[@"username"];
	[userInfo removeObjectForKey: @"username"];
	
	return [self dz_storeWithServiceName: serviceName identifier: unique username: username userInfo: userInfo];
}

+ (instancetype)findStoreForServiceName:(NSString *)serviceName username:(NSString *)username {
	if (!serviceName.length || !username.length)
		return nil;
	
	NSUserDefaults *defaults = [NSUserDefaults standardUserDefaults];
	
	NSDictionary *authStore = [defaults dictionaryForKey: DZAuthenticationStoreUserDefaultsKey];
	if (!authStore.count)
		return nil;
	
	__block id ret = nil;
	
	[authStore[serviceName] enumerateObjectsUsingBlock:^(NSString *identifier, NSUInteger idx, BOOL *stop) {
		DZAuthenticationStore *store = [[self class] findStoreForServiceName: serviceName identifier: identifier];

		if ([store.username isEqualToString: username]) {
			*stop = YES;
			ret = store;
		}
	}];
	
	return ret;
}

@end