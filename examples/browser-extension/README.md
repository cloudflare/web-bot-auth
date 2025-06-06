# web-bot-auth Browser extension

![GitHub License](https://img.shields.io/github/license/cloudflareresearch/web-bot-auth)
![GitHub Release](https://img.shields.io/github/v/release/cloudflareresearch/web-bot-auth)

Chrome browser extension adding HTTP Message Signature on all outgoing requests as defined by [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421). Specification is in [draft-meunier-web-bot-auth-architecture](https://thibmeu.github.io/http-message-signatures-directory/draft-meunier-web-bot-auth-architecture.html).

## Tables of Content

- [Features](#features)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## Features

- Chrome Manifest v3 extension
- RFC 9421 compatible `Signature` header
- CRX extension server

## Usage

Compile the code of the extension:

```shell
npm run build:chrome
```

Bundle and sign the Chrome extension:

```shell
npm run bundle:chrome
```

This command creates the folder `dist` with both the unpacked and packed (.crx) Chrome extension.

## Installing Extension from Sources

This extension requires the [webRequestBlocking](https://developer.chrome.com/docs/extensions/reference/api/webRequest) permission, which in turn requires of an [Enterprise policy](https://support.google.com/chrome/a/answer/187202?hl=en) to be configured on Chrome.

Follow these steps to configure Chrome with such a policy and force it to install the extension locally.
First, run in another terminal:

```shell
npm run start:config
```

This starts a server at http://localhost:8000 for installing extension locally.

Then, copy the policy file in the correspondent system path:

On Linux:

```shell
mkdir -p /etc/opt/chrome/policies/managed
cp policy/policy.json /etc/opt/chrome/policies/managed/policy.json
```

On MacOS:

```shell
mkdir -p /Library/Managed\ Preferences/
cp policy/com.google.Chrome.managed.plist /Library/Managed\ Preferences/
```

You can confirm the policy is installed by navigating to [chrome://policy/](chrome://policy/) and make sure to reload the policies.

## Security Considerations

This software has not been audited. Please use at your sole discretion.

## License

This project is under the Apache 2.0 license.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you shall be Apache 2.0 licensed as above, without any additional terms or conditions.
