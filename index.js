/**
 * Lambda function to support JWT.
 * Used for authenticating API requests for API Gateway
 * as a custom authorizor:
 *
 * @see https://jwt.io/introduction/
 * @see http://docs.aws.amazon.com/apigateway/latest/developerguide/use-custom-authorizer.html
 * @author Chris Moyer <cmoyer@aci.info>
 */
var nJwt = require('njwt');
var fs = require('fs');
var secretKey = fs.readFileSync('secret.key'); // Put secret key in it, txt format

function generatePolicyDocument(principalId, effect, resource) {
	var authResponse = {};
	authResponse.principalId = principalId;
	if (effect && resource) {
		var policyDocument = {};
		policyDocument.Version = '2012-10-17'; // default version
		policyDocument.Statement = [];
		var statementOne = {};
		statementOne.Action = 'execute-api:Invoke'; // default action
		statementOne.Effect = effect;
		statementOne.Resource = resource;
		policyDocument.Statement[0] = statementOne;
		authResponse.policyDocument = policyDocument;
	}
	return authResponse;
}

/**
 * Handle requests from API Gateway
 * "event" is an object with an "authorizationToken"
 */
exports.handler = function jwtHandler(event, context){
	var token = event.authorizationToken.split(' ');
	if(token[0] === 'Bearer'){
		// Token-based re-authorization
		// Verify
        nJwt.verify(token[1], secretKey, 'HS512', function (err, verifiedJwt) {
            if (err) {
                console.log('Verification Failure', err); // Token has expired, has been tampered with, etc
                context.fail('Unauthorized');
            } else if (verifiedJwt && verifiedJwt.body && verifiedJwt.body.id){
                console.log('LOGIN', verifiedJwt);// Will contain the header and body
                context.succeed(generatePolicyDocument(verifiedJwt.body.id, 'Allow', event.methodArn));
            } else {
                console.log('Invalid User', verifiedJwt);
                context.fail('Unauthorized');
			}
        });
	} else {
		// Require a "Bearer" token
		console.log('Wrong token type', token[0]);
		context.fail('Unauthorized');
	}
};
