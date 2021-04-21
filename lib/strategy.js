const passport = require('passport');
const helpers = require('./helpers.js');
const jwksClient = require('jwks-rsa');
const assert = require('assert');
const axios = require('axios');
const util = require('util');
const jwt = require('jsonwebtoken');

/**
 * 
 * @param {object} options - Options for Cloudflare Access
 *      teamName: String containing the name of the Cloudflare team
 *      teamDomainName: String containing the full team domain name, if not specified uses template `${teamName}.cloudflareaccess.com`
 *      tokenHeader: String containing the header to look for the token, if not specified uses the default header
 *      tokenCookie: String containing the cookie to look for the token, if not specified uses the default cookie name
 *      jwksUri: String containing the JWKS endpoint to retrieve the latest signing keys - if not specified, it is generated from teamName
 *      identityUri: String containing the identity endpoint to retrieve the user identity from. If not specified, it is generated from teamName
 *      issuer: String containing the token issuer, if not specified, it is generated from teamName
 *      audience: String containing the audience from the JWT. It is verified if verifyAudience is true.
 * 
 *      verifyAudience: Boolean to specificy if audience has to be verified. Defaults to true.
 *      verifyIssuer: Boolean to specificy if issuer has to be verified. Defaults to true.
 * @param {Function} verify  - Callback following verification
 */

function CloudflareStrategy(options, verify) {
    passport.Strategy.call(this);

    const defaultOptions = helpers.getDefaults(options.teamName);

    this._options = Object.assign({}, defaultOptions, options);

    this.name = 'cloudflare';

    this._verify = verify;
    this._passReqToCallback = !!options.passReqToCallback;

    this.jwks = jwksClient(this._options.jwksOpts);
}


CloudflareStrategy.prototype.getIdentity = async function(token) {
    const self = this;

    const response = await axios.get(self._options.identityUri, {
        headers: {
            Cookie: `${self._options.tokenCookie}=${token}`
        }
    });

    return response.data;
}

CloudflareStrategy.prototype.verifyToken = async function(token) {
    const self = this;

    // Use the cached-jwks client to get the signing key
    const signingKeyFunc = helpers.getSigningKey(self.jwks);

    const payload = await util.promisify(jwt.verify)(token, signingKeyFunc, {
        issuer: self._options.issuer,
        audience: self._options.audience
    });

    const identity = await self.getIdentity(token);
    const groups = identity.groups ? identity.groups.map(g => g.name) : null;

    assert.strictEqual(identity.email, payload.email);

    return {
        payload,
        identity,
        groups
    }
}

CloudflareStrategy.prototype.authenticate = function(req, options) {
    var self = this;

    // Fetch the token from the header or cookie
    const token = helpers.extractToken(
        req, 
        self._options.tokenCookie,
        self._options.tokenHeader
    );

    // Function to handle response from user callback
    const authencationDone = function (err, user, info) {
        if (err) {
            return self.error(err)
        } else if (!user) {
            return self.fail(info)
        } else {
            return self.success(user, info)
        }
    }

    // Verify the token
    try {
        self.verifyToken(token)
        .then(result => {
            if (self._passReqToCallback) {
                self._verify(req, result, authencationDone)
            } else {
                self._verify(result, authencationDone)
            }
        })
    } catch (err) {
        return self.fail(err)
    }
}

module.exports = CloudflareStrategy