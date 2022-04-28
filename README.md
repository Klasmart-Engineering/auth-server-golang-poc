# Auth Server GoLang PoC
This codebase is a proof of concept for implementing auth-server (also known as auth-backend) using the GoLang programming language. The goal of this is to provide a basis for experimentation, so that it can be compared and benchmarked against the existing Node.js implementation. The case for doing this is described in the following RFC: [RFC-2022-04-21](https://calmisland.atlassian.net/wiki/spaces/ARCH/pages/2653356155/RFC-2022-04-21). This README documents the progress made, and outlines any known caveats.

## Behaviours
The behaviour of the existing Node.js app has been deduced by examining the codebase, and experimenting with browsers / Postman etc. It was sadly not possible to discuss this directly with the team responsible for the auth server. There may be some discrepancy in the finer detail of the behaviour, however, it should mirror the existing version for a basic use-case. There are some differences which are known:
- CORS is applied to all routes, whereas Node.js version applies this selectively. This is due to limitation in the default GoLang Mutex, however, there are others available which will fulfill this functionality (e.g. [gorrilla-mux](https://github.com/gorilla/mux))
- Different status codes. We have tried to follow a more strict and comprehensive set of codes. For example, routes which only respond to POST, respond with "MethodNotAllowed" if a GET or POST request is received. Various error scenarios are usually either "BadRequest" or "InternalServerError" whichever was more appropriate
- Only supports Azure B2C, not AMS. This was done to keep the code more simple, and on the assumption that AMS will be phased out in favour of Azure B2C
- Limited support for environment variables. Currently, not all env vars (notable those relating to keys and secrets) are supported, and many are set to defaults which are mostly useful for debugging
- No support for shared secret encryption. Although the current version supports this, only public/private key encryption seems to be in use, and so this was not covered in the PoC
- No support for passphrase locked private keys

## Stubs and placeholder data
The current version makes a call out the User Service's database. In order to avoid the need for a db setup in testing a "DummyDBConnector" struct has been created, using a defined "DBConnector interface" - the dummy connector simply replies "true" to validate the user ID. Currently, this is implemented in both the unit tests and the main code. Obviously this needs to be replaced with an actual DB connector and the interface should be expanded to accommodate it. The interface will still be needed so that the dummy connector can still be used in unit tests.

There is also a pair of RSA keys (in `test/rsa_keys.go`). These were generated specifically for this project, and are not used elsewhere. These are intended to be used in unit tests to avoid the need for access to live RSA keys. However, they are currently used in the main code base as well. This should be factored out when the env vars are fully implemented.

## Unit tests
A basic set of nit tests have been created to cover most functions, for at least the happy path. There is a lot of scope to improve the tests and coverage. Testing the Azure B2C token validation is particular tricky as it is hard to do so without a) providing a valid token (which can only be created by Azure), and b) calling to the Azure JWK endpoint to get the key. It might make sense to refactor the functions so that a test can generate a token and JWK key which mimics the Azure setup.

To run the full suite of tests with coverage report:
```
cd /path/to/auth-server-golang-poc
go test -v -cover ./...
```

## Dockerfile
The Dockerfile is in the root directory, and uses multi-step build. The final output only needs the compiled binary, so on a standard alpine base it is ~14Mb in size. The container has also been configured to run the application as a non-root user.