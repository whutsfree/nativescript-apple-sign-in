import { device } from "tns-core-modules/platform";
import { ios as iOSUtils } from "tns-core-modules/utils/utils";
import { SignInWithAppleCredentials, SignInWithAppleOptions, SignInWithAppleState } from "./index";
import jsArrayToNSArray = iOSUtils.collections.jsArrayToNSArray;

let FileSystemAccess = require('tns-core-modules/file-system/file-system-access').FileSystemAccess;
let controller: any /* ASAuthorizationController */;
let delegate: ASAuthorizationControllerDelegateImpl;

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
          console.log("Unsupported scope: " + s + ", use either EMAIL or FULLNAME");
        }
      });
      request.requestedScopes = nsArray;
    }

    controller = ASAuthorizationController.alloc().initWithAuthorizationRequests(jsArrayToNSArray([request]));
    controller.delegate = delegate = ASAuthorizationControllerDelegateImpl.createWithPromise(resolve, reject);
    controller.performRequests();
  });
}

class ASAuthorizationControllerDelegateImpl extends NSObject /* implements ASAuthorizationControllerDelegate */ {
  public static ObjCProtocols = [];
  private resolve;
  private reject;

  public static new(): ASAuthorizationControllerDelegateImpl {
    try {
      ASAuthorizationControllerDelegateImpl.ObjCProtocols.push(ASAuthorizationControllerDelegate);
      return <ASAuthorizationControllerDelegateImpl>super.new();
    } catch (ignore) {
      console.log("Apple Sign In not supported on this device - it requires iOS 13+. Tip: use 'isSignInWithAppleSupported' before calling 'signInWithApple'.");
      return null;
    }
  }

  public static createWithPromise(resolve, reject): ASAuthorizationControllerDelegateImpl {
    const delegate = <ASAuthorizationControllerDelegateImpl>ASAuthorizationControllerDelegateImpl.new();
    if (delegate === null) {
      reject("Not supported");
    } else {
      delegate.resolve = resolve;
      delegate.reject = reject;
    }
    return delegate;
  }

  authorizationControllerDidCompleteWithAuthorization(controller: any /* ASAuthorizationController */, authorization: any /* ASAuthorization */): void {
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
              console.log("error reading storage, Error: ", err);
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
              console.log("unable to write storage, error: ", err);
          }
      };


    console.log(">>> credential.state: " + authorization.credential.state); // string

    // These require a scope
    // console.log(">>> credential.fullName: " + authorization.credential.fullName); // NSPersonNameComponents (familyName, etc)
    // console.log(">>> credential.email: " + authorization.credential.email); // string

    // console.log(">>> credential.realUserStatus: " + authorization.credential.realUserStatus); // enum

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

    this.resolve(<SignInWithAppleCredentials>{
      user: authorization.credential.user,
      authorizationCode: "" + authorizationCode,
      identityToken: "" + identityToken,
      fullName: name,
      email: email
      // scopes: authorization.credential.authorizedScopes // nsarray<asauthorizationscope>
    });
  }

  authorizationControllerDidCompleteWithError(controller: any /* ASAuthorizationController */, error: NSError): void {
    this.reject(error.localizedDescription);
  }
}
