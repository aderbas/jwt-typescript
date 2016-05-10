/**
 */
var JWT = (function () {
    function JWT() {
        // offset secounds for date expiration
        this._offsetSeconds = 0;
        // base64 dictionary
        this.b64c = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        // base64url dictionary
        this.b64u = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        // base64 pad helper
        this.b64pad = '=';
    }
    /**
     * base64_charIndex
     * Internal helper to translate a base64 character to its integer index.
     */
    JWT.prototype.base64_charIndex = function (c) {
        if (c == "+")
            return 62;
        if (c == "/")
            return 63;
        return this.b64u.indexOf(c);
    };
    /**
     * base64_decode
     * Decode a base64 or base64url string to a JavaScript string.
     * Input is assumed to be a base64/base64url encoded UTF-8 string.
     * Returned result is a JavaScript (UCS-2) string.
     */
    JWT.prototype.base64Decode = function (data) {
        var dst = "";
        var i = 0, a, b, c, d, z;
        var len = data.length;
        for (; i < len - 3; i += 4) {
            a = this.base64_charIndex(data.charAt(i + 0));
            b = this.base64_charIndex(data.charAt(i + 1));
            c = this.base64_charIndex(data.charAt(i + 2));
            d = this.base64_charIndex(data.charAt(i + 3));
            dst += String.fromCharCode((a << 2) | b >>> 4);
            if (data.charAt(i + 2) != this.b64pad) {
                dst += String.fromCharCode(((b << 4) & 0xF0) | ((c >>> 2) & 0x0F));
            }
            if (data.charAt(i + 3) != this.b64pad) {
                dst += String.fromCharCode(((c << 6) & 0xC0) | d);
            }
        }
        return decodeURIComponent(dst);
    };
    /**
     * Decode token, except if token is expired
     * @param token - string jwt
     */
    JWT.prototype.decodeToken = function (token) {
        var parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('JWT must have 3 parts');
        }
        var decoded = this.base64Decode(parts[1]);
        if (!decoded) {
            throw new Error('Cannot decode the token');
        }
        decoded = JSON.parse(decoded);
        if (typeof decoded.exp === "undefined") {
            throw new Error('Cannot decode the token, date exp is invalid.');
        }
        // check date of token
        var date = new Date(0);
        date.setUTCSeconds(decoded.exp);
        var offsetSeconds = this._offsetSeconds || 0;
        if (!(date.valueOf() > (new Date().valueOf() + (offsetSeconds * 1000)))) {
            throw new Error('Token expired.');
        }
        return decoded;
    };
    /**
     * Get token expiration date
     * @param token - string jwt
     * @return Date
     */
    JWT.prototype.getTokenExpirationDate = function (token) {
        var decoded;
        decoded = this.decodeToken(token);
        if (typeof decoded.exp === "undefined") {
            return null;
        }
        var date = new Date(0); // The 0 here is the key, which sets the date to the epoch
        date.setUTCSeconds(decoded.exp);
        return date;
    };
    /**
     * Check if toke is expired
     * @param token - string jwt
     * @return boolean - true if expired
     */
    JWT.prototype.isTokenExpired = function (token, offsetSeconds) {
        var date = this.getTokenExpirationDate(token);
        offsetSeconds = offsetSeconds || this._offsetSeconds;
        if (date === null) {
            return false;
        }
        // Token expired?
        return !(date.valueOf() > (new Date().valueOf() + (offsetSeconds * 1000)));
    };
    return JWT;
}());
