// Extract JWT token from Cookie or Header
// Ensure that Cookie hasn't expired
function extractToken(req, cookieName, headerName) {
    let payload;

    if (cookieName) payload = req.cookies.get(cookieName);
    if (headerName && !payload) payload = req.get(headerName);

    if (!payload) console.error('Could not find authentication token.')
    else {
        return payload
    }
}

// Get signing key
function getSigningKey(jwks) {
    return function(tokenHeader, done) {
        jwks.getSigningKey(tokenHeader.kid, function(err, key) {
            if(err) done(err);

            const signingKey = key.publicKey || key.rsaPublicKey;
            done(null, signingKey)
        })
    }
}

function getDefaults(teamName) {
    
    const teamDomainName = `${teamName}.cloudflareaccess.com`;
    const issuer = `https://${teamDomainName}`;
    const identityUri = `https://${teamDomainName}/cdn-cgi/access/get-identity`;
    const jwksUri = `https://${teamDomainName}/cdn-cgi/access/certs`;

    return {
        teamDomainName,
        identityUri,
        issuer,
        
        tokenHeader: 'Cf-Access-Jwt-Assertion',
        tokenCookie: 'CF_Authorization',
    
        verifyAudience: true,
        verifyIssuer: true,
        
        jwksOpts: {
            jwksUri,
            cache: true
        }
    };
}

module.exports = {
    getDefaults,
    getSigningKey,
    extractToken,
}