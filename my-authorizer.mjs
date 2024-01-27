import jwt from 'jsonwebtoken';

class TokenManager {
    #JWT_SECRET;                            // private attribute
    constructor() {
        this.#JWT_SECRET = 'JUSTASECREC-35';
    }
    createToken (data) {
        if(!data) return false;
        try {
            return jwt.sign({
                exp: Math.floor(Date.now() / 1000) + (60 * 60),
                data: DUMMY_USER
            }, this.#JWT_SECRET);
        } catch(err) {
            return false;
        }
    } 
    validateToken (token){
        if(!token) return false;
        try {
            return jwt.verify(token, this.#JWT_SECRET);
        } catch(err) {
            return false;
        }
    }
};

const DUMMY_USER = {            // this is a dummy user information & will pass this data post authorization to backend or origin request as a context request
    id: 270120241803,
    email: 'johndoe@gmail.com',
    name: 'John Doe'
};

export const handler =  async function(event, context, callback) {
    let tm = new TokenManager();
    
    let token = tm.createToken(DUMMY_USER);                  // to generate a new token
    console.log(token);
    
    let tokenResponse = tm.validateToken(getAuthToken(event));  // validating the token
    
    if(!tokenResponse)
       callback(null, generatePolicy('user', 'Deny', event.methodArn)); // unauthorized 

    callback(null, generatePolicy('user', 'Allow', event.methodArn, DUMMY_USER));   // authorized
};

let getAuthToken = (event) => {                     // returns the token from the request header
    try{
        let token = event.headers.Authorization.split('Bearer')[1].trim();
        return token;
    } catch(err) {
       return null;
    }
};

let generatePolicy = (principalId, effect, resource, authData = null) => {       // a function that creates policy
    var authResponse = {};
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; 
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    authResponse.context = authData;
    return authResponse;
};
