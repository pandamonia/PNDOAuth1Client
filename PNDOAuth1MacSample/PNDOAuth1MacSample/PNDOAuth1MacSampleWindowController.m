//
//  PNDOAuth1MacSampleWindowController.m
//  PNDOAuth1Client Mac Sample
//
//  Copyright (c) 2010 Google Inc.
//  Copyright (c) 2012 Pandamonia LLC.
//  Licensed under Apache 2.0. See LICENSE.
//

#import "PNDOAuth1MacSampleWindowController.h"
#import "PNDOAuth1Client.h"
#import "PNDOAuthLoginWindowController.h"

@interface PNDOAuth1MacSampleWindowController ()

@property (nonatomic, strong) PNDOAuth1Client *client;
@property (nonatomic, strong) PNDOAuthLoginWindowController *loginWindowController;
@property (nonatomic, readonly, getter = isSignedIn) BOOL signedIn;

@end

@implementation PNDOAuth1MacSampleWindowController

static NSString *const kTwitterServiceName = @"Twitter";
static NSString *const kTwitterKeychainItemName = @"OAuth Sample: Twitter";
static NSString *const kTwitterUserDefaultsItemName = @"Twitter User Name";

- (void)displayErrorThatTheCodeNeedsATwitterConsumerKeyAndSecret {
	NSBeginAlertSheet(@"Error", nil, nil, nil, self.window,
					  self, NULL, NULL, NULL,
					  @"The sample code requires a valid Twitter consumer key"
					  " and consumer secret to sign in to Twitter");
}

- (void)awakeFromNib
{
    [super awakeFromNib];
    
	NSString *myConsumerKey = @"7rvkfLjImxMCPotmKNyA";
	NSString *myConsumerSecret = @"CAB13fbdjFdldU9UUXOyND4DtPSHV7QLuei5aTm0JU";

	if ([myConsumerKey length] == 0 || [myConsumerSecret length] == 0) {
		[self displayErrorThatTheCodeNeedsATwitterConsumerKeyAndSecret];
		return;
	}

	NSString *scope = @"http://api.twitter.com/";
	NSURL *URLBase = [NSURL URLWithString: scope];
	NSString *identifier = [[NSUserDefaults standardUserDefaults] stringForKey: kTwitterUserDefaultsItemName];
	PNDOAuth1Client *client = [[PNDOAuth1Client alloc] initWithBaseURL: URLBase serviceName: kTwitterServiceName keychainIdentifier: identifier];
	client.scope = scope;
	client.consumerKey = myConsumerKey;
	client.consumerSecret = myConsumerSecret;
	client.signatureMethod = PNDOAuthSignatureMethodHMAC_SHA1;
	client.callback = @"http://dzzy.us/oauth_twitter_logged_in";
	client.requestTokenURL = [NSURL URLWithString:@"http://twitter.com/oauth/request_token"];
	client.accessTokenURL = [NSURL URLWithString:@"http://twitter.com/oauth/access_token"];
	client.authorizationURL = [NSURL URLWithString:@"http://twitter.com/oauth/authorize"];

	NSNotificationCenter *nc = [NSNotificationCenter defaultCenter];
	[nc addObserver: self selector: @selector(signInFetchStateChanged:) name: PNDOAuthTokenFetchWillStartNotification object: client];
	[nc addObserver: self selector: @selector(signInFetchStateChanged:) name: PNDOAuthTokenFetchDidSucceedNotification object: client];
	[nc addObserver: self selector: @selector(signInFetchStateChanged:) name: PNDOAuthTokenFetchDidFailNotification object: client];
	[nc addObserver: self selector: @selector(signInNetworkLost:) name: PNDOAuthNetworkLostNotification object: client];

	self.client = client;

	[self updateUI];
}

#pragma mark -

- (BOOL)isSignedIn {
	return self.client.canAuthorize;
}

- (IBAction)signInOutClicked:(id)sender {
	if (![self isSignedIn]) {
		// sign in
		[self signInToTwitter];
	} else {
		// sign out
		[self signOut];
	}
	[self updateUI];
}

- (void)signOut {
	// remove the stored Twitter authentication from the keychain, if any
	[[NSUserDefaults standardUserDefaults] removeObjectForKey: kTwitterUserDefaultsItemName];
	[self.client resetAuthenticationState];
	[self updateUI];
}

- (void)signInToTwitter {
	[self signOut];

	self.loginWindowController = [PNDOAuthLoginWindowController new];
	[self.client startSigningInWithController: self.loginWindowController success:^{
		if ([self.client saveAuthenticationState]) {
			[[NSUserDefaults standardUserDefaults] setObject: self.client.keychainIdentifier forKey: kTwitterUserDefaultsItemName];
		}
		[self doAnAuthenticatedAPIFetch];
		[self updateUI];
	} failure:^(NSError *error) {
		NSLog(@"Authentication error: %@", error);
		NSData *responseData = [error userInfo][@"data"]; // kGTMHTTPFetcherStatusDataKey
		if ([responseData length] > 0) {
			// show the body of the server's authentication failure response
			NSString *str = [[NSString alloc] initWithData:responseData
												  encoding:NSUTF8StringEncoding];
			NSLog(@"%@", str);
		}

		[self.client resetAuthenticationState];
		[self updateUI];
	}];
}

#pragma mark -

- (void)doAnAuthenticatedAPIFetch {
	// Twitter status feed
	[self.client getPath: @"1/statuses/home_timeline.json" parameters: nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
		// API fetch succeeded
		NSLog(@"API response: %@", operation.responseString);
	} failure:^(AFHTTPRequestOperation *operation, NSError *error) {
		// fetch failed
		NSLog(@"API fetch error: %@", error);
	}];
}

#pragma mark -

- (void)signInFetchStateChanged:(NSNotification *)note {
	// this just lets the user know something is happening during the
	// sign-in sequence's "invisible" fetches to obtain tokens
	//
	// the type of token obtained is available as
	//   note.userInfo[PNDOAuthTokenFetchTypeKey]
	if ([note.name isEqual: PNDOAuthTokenFetchWillStartNotification]) {
		[self.spinner startAnimation:self];
	} else {
		[self.spinner stopAnimation:self];
	}
}

- (void)signInNetworkLost:(NSNotification *)note {
	// the network dropped for 30 seconds
	//
	// we could alert the user and wait for notification that the network has
	// has returned, or just cancel the sign-in sheet, as shown here.
	[self.client cancelSigningIn];
}

- (void)updateUI {
	// update the text showing the signed-in state and the button title
	if (self.signedIn) {
		// signed in
		BOOL hasToken = self.client.canAuthorize;
		NSString *email = self.client.userEmail;
		BOOL isVerified = self.client.userEmailVerified;

		if (!isVerified) {
			// email address is not verified
			//
			// The email address is listed with the account info on the server, but
			// has not been confirmed as belonging to the owner of this account.
			email = [email stringByAppendingString:@" (unverified)"];
		}

		[self.tokenField setStringValue:(hasToken ? @"YES" : @"NO")];
		[self.usernameField setStringValue:(email != nil ? email : @"")];
		[self.signInOutButton setTitle:@"Sign Out"];
	} else {
		// signed out
		[self.usernameField setStringValue:@"-Not signed in-"];
		[self.tokenField setStringValue:@"NO"];
		[self.signInOutButton setTitle:@"Sign In..."];
	}
}


@end
