"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ZitadelIntrospectionStrategy = void 0;
const axios_1 = __importDefault(require("axios"));
const jose_1 = require("jose");
const node_rsa_1 = __importDefault(require("node-rsa"));
const openid_client_1 = require("openid-client");
const passport_1 = require("passport");
class ZitadelIntrospectionStrategy extends passport_1.Strategy {
    constructor(options) {
        super();
        this.options = options;
        this.name = 'zitadel-introspection';
    }
    get clientId() {
        if (this.options.authorization.type === 'basic') {
            return this.options.authorization.clientId;
        }
        return this.options.authorization.profile.clientId;
    }
    async authenticate(req) {
        var _a, _b, _c, _d, _e;
        if (!((_a = req.headers) === null || _a === void 0 ? void 0 : _a.authorization) || ((_c = (_b = req.headers) === null || _b === void 0 ? void 0 : _b.authorization) === null || _c === void 0 ? void 0 : _c.toLowerCase().startsWith('bearer ')) === false) {
            this.fail({ message: 'No bearer token found in authorization header' });
            return;
        }
        (_d = this.introspect) !== null && _d !== void 0 ? _d : (this.introspect = await this.getIntrospecter());
        const token = req.headers.authorization.substring(7);
        try {
            const result = await this.introspect(token);
            if (!result.active) {
                this.fail({ message: 'Token is not active' });
                return;
            }
            this.success(result);
        }
        catch (e) {
            ((_e = this.error) !== null && _e !== void 0 ? _e : console.error)(e);
        }
    }
    async getIntrospecter() {
        var _a;
        const issuer = await openid_client_1.Issuer.discover((_a = this.options.discoveryEndpoint) !== null && _a !== void 0 ? _a : this.options.authority);
        const introspectionEndpoint = issuer.metadata['introspection_endpoint'];
        let jwt = '';
        let lastCreated = 0;
        const getPayload = async (token) => {
            var _a;
            if (this.options.authorization.type === 'basic') {
                return { token };
            }
            // check if the last created time is older than 60 minutes, if so, create a new jwt.
            if (lastCreated < Date.now() - 60 * 60 * 1000) {
                const rsa = new node_rsa_1.default(this.options.authorization.profile.key, (_a = this.options.authorization.profile.format) !== null && _a !== void 0 ? _a : 'pkcs8');
                const key = await (0, jose_1.importPKCS8)(rsa.exportKey('pkcs8-private-pem'), 'RSA256');
                jwt = await new jose_1.SignJWT({
                    iss: this.clientId,
                    sub: this.clientId,
                    aud: this.options.authority,
                })
                    .setIssuedAt()
                    .setExpirationTime('1h')
                    .setProtectedHeader({
                    alg: 'RS256',
                    kid: this.options.authorization.profile.keyId,
                })
                    .sign(key);
                lastCreated = Date.now();
            }
            return {
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                client_assertion: jwt,
                token,
            };
        };
        return async (token) => {
            const payload = await getPayload(token);
            const response = await axios_1.default.post(introspectionEndpoint, new URLSearchParams(payload), {
                auth: this.options.authorization.type === 'basic'
                    ? {
                        username: this.options.authorization.clientId,
                        password: this.options.authorization.clientSecret,
                    }
                    : undefined,
            });
            return response.data;
        };
    }
}
exports.ZitadelIntrospectionStrategy = ZitadelIntrospectionStrategy;
