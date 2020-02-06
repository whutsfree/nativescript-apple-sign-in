import { device } from "tns-core-modules/platform";
import { ios as iOSUtils } from "tns-core-modules/utils/utils";
import { SignInWithAppleCredentials, SignInWithAppleOptions, SignInWithAppleState } from "./index";
import jsArrayToNSArray = iOSUtils.collections.jsArrayToNSArray;

declare function __nslog(message: string): void;

function logLocal(message) {
    console.log(message);
    // __nslog("CONSOLE LOG: " + message);
}

let FileSystemAccess = require('tns-core-modules/file-system/file-system-access').FileSystemAccess;
let controller: any /* ASAuthorizationController */;
let resolveCallback = null;
let rejectCallback = null;

declare const ASAuthorizationAppleIDProvider, ASAuthorizationController, ASAuthorizationControllerDelegate,
    ASAuthorizationScopeEmail, ASAuthorizationScopeFullName: any;

export function isSignInWithAppleSupported(): boolean {
  return parseInt(device.osVersion) >= 13;
}

export function getSignInWithAppleState(user: string): Promise<SignInWithAppleState> {
  return new Promise<any>((resolve, reject) => {
    if (!user) {
      reject("The 'user' parameter is mandatory");
      return;
    }

    if (!isSignInWithAppleSupported()) {
      reject("Not supported");
      return;
    }

    const provider = ASAuthorizationAppleIDProvider.new();
    provider.getCredentialStateForUserIDCompletion(user, (state: any /* enum: ASAuthorizationAppleIDProviderCredentialState */, error: NSError) => {
      if (error) {
        reject(error.localizedDescription);
        return;
      }

      if (state === 1) { // ASAuthorizationAppleIDProviderCredential.Authorized
        resolve("AUTHORIZED");
      } else if (state === 2) { // ASAuthorizationAppleIDProviderCredential.NotFound
        resolve("NOTFOUND");
      } else if (state === 3) { // ASAuthorizationAppleIDProviderCredential.Revoked
        resolve("REVOKED");
      } else {
        // this prolly means a state was added so we need to add it to the plugin
        reject("Invalid state for getSignInWithAppleState: " + state + ", please report an issue at he plugin repo!");
      }
    });
  });
}

export function signInWithApple(options?: SignInWithAppleOptions): Promise<SignInWithAppleCredentials> {
    logLocal("Attempt signInWithApple");
  return new Promise<any>((resolve, reject) => {
    if (!isSignInWithAppleSupported()) {
      reject("Not supported");
      return;
    }

    const provider = ASAuthorizationAppleIDProvider.new();
    const request = provider.createRequest();

    if (options && options.user) {
      request.user = options.user;
    }

    if (options && options.scopes) {
      const nsArray = NSMutableArray.new();
      options.scopes.forEach(s => {
        if (s === "EMAIL") {
          nsArray.addObject(ASAuthorizationScopeEmail);
        } else if (s === "FULLNAME") {
          nsArray.addObject(ASAuthorizationScopeFullName);
        } else {
          logLocal("Unsupported scope: " + s + ", use either EMAIL or FULLNAME");
        }
      });
      request.requestedScopes = nsArray;
    }

    controller = ASAuthorizationController.alloc().initWithAuthorizationRequests(jsArrayToNSArray([request]));
    resolveCallback = resolve;
    rejectCallback = reject;
    controller.delegate = getSignInDelegate();
      logLocal("Delegate ready");
    controller.performRequests();
      logLocal("Perform requests...");
  });
}

let _delegateInstance = null;
function getSignInDelegate() {
    if (!_delegateInstance) {
        class MyAppleSignInDelegate extends NSObject /* implements ASAuthorizationControllerDelegate */ {
            static ObjCProtocols = [ASAuthorizationControllerDelegate];

            constructor() {
                super();
                logLocal("Construct Apple Sign In Delegate");
            }

            authorizationControllerDidCompleteWithAuthorization(controller: any /* ASAuthorizationController */, authorization: any /* ASAuthorization */): void {
                logLocal("authorizationControllerDidCompleteWithAuthorization");

                const loadData = (): { name?: string, email?: string } => {
                    let fsa = new FileSystemAccess();
                    let fileName = fsa.getDocumentsFolderPath() + "/appleSignIn.db";
                    if (!fsa.fileExists(fileName)) {
                        return {};
                    }

                    let data;
                    try {
                        let textData = fsa.readText(fileName);
                        data = JSON.parse(textData);
                        return data;
                    }
                    catch (err) {
                        logLocal("error reading storage, Error: " + err);
                    }
                    return {};
                };

                const saveData = (data: { email: string, name: string }) => {
                    let fsa = new FileSystemAccess();
                    let fileName = fsa.getDocumentsFolderPath() + "/appleSignIn.db";
                    const existingData = loadData();
                    try {
                        if (!data.email) data.email = existingData.email;
                        if (!data.name) data.name = existingData.name;
                        fsa.writeText(fileName, JSON.stringify(data));
                    } catch (err) {
                        // This should never happen on normal data, but if they tried to put non JS stuff it won't serialize
                        logLocal("unable to write storage, error: " + err);
                    }
                };


                logLocal(">>> credential.state: " + authorization.credential.state); // string

                // These require a scope
                // logLocal(">>> credential.fullName: " + authorization.credential.fullName); // NSPersonNameComponents (familyName, etc)
                // logLocal(">>> credential.email: " + authorization.credential.email); // string

                // logLocal(">>> credential.realUserStatus: " + authorization.credential.realUserStatus); // enum

                // TODO return granted scopes

                const authorizationCode = NSString.alloc().initWithDataEncoding(authorization.credential.authorizationCode, NSUTF8StringEncoding);
                const identityToken = NSString.alloc().initWithDataEncoding(authorization.credential.identityToken, NSUTF8StringEncoding);
                const fullName = authorization.credential.fullName;
                const firstName = fullName.givenName;
                const lastName = fullName.familyName;
                let email = authorization.credential.email;
                let name = null;
                if (firstName && lastName) {
                    name = firstName + " " + lastName;
                } else if (firstName) {
                    name = firstName;
                } else if (lastName) {
                    name = lastName;
                }

                if (name || email) {
                    // save for re-use if needed
                    saveData({name, email});
                }

                if (!name || !email) {
                    const data = loadData();
                    // retrieve last save data
                    if (!name) name = data.name;
                    if (!email) email = data.email;
                }

                resolveCallback(<SignInWithAppleCredentials>{
                    user: authorization.credential.user,
                    authorizationCode: "" + authorizationCode,
                    identityToken: "" + identityToken,
                    fullName: name,
                    email: email
                    // scopes: authorization.credential.authorizedScopes // nsarray<asauthorizationscope>
                });
            }

            authorizationControllerDidCompleteWithError(controller: any /* ASAuthorizationController */, error: NSError): void {
                logLocal("authorizationControllerDidCompleteWithError");

                rejectCallback(error.localizedDescription);
            }
        }

        _delegateInstance = new MyAppleSignInDelegate();
    }

    return _delegateInstance;
}
