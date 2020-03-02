[![Gitpod Ready-to-Code](https://img.shields.io/badge/Gitpod-Ready--to--Code-blue?logo=gitpod)](https://gitpod.io/#https://github.com/kopertop/lambda-jwt) 

Lambda API Gateway support for JSON Web Tokens
==============================================

API Gateway custom Lambda function for JSON Web Token: https://jwt.io/introduction/

Changed original to use library nJWt.

To Generate your own private key
--------------------------------
Save secret key string in file `secret.key`.

Upload to AWS
-------------

Log into the AWS console and create an empty "jwtAuthorize" function using Node.js.

Run

```
npm install
grunt deploy --account-id=<your account id>
```

Tie this function to your AWS API Gateway
-----------------------------------------

Go to the AWS console and choose your API gateway. Under "Resources" choose "Custom Authorizers".
Create a new authorizer with the identityToken source of `method.request.header.Authorization`
and a Token validation expression of `Bearer [^\.]+\.[^\.]+\.[^\.]+` and associate it with your newly
created jwtAuthorizer Lambda function.
