import { Request } from 'express';
import { ParamsDictionary } from 'express-serve-static-core';
import NodeRSA from 'node-rsa';
import { Strategy } from 'passport';
import { ParsedQs } from 'qs';
type ZitadelJwtProfile = {
    type: 'application';
    keyId: string;
    key: string;
    appId: string;
    clientId: string;
    format: NodeRSA.Format;
};
type EndpointAuthoriztaion = {
    type: 'basic';
    clientId: string;
    clientSecret: string;
} | {
    type: 'jwt-profile';
    profile: ZitadelJwtProfile;
};
export type ZitadelIntrospectionOptions = {
    authority: string;
    authorization: EndpointAuthoriztaion;
    discoveryEndpoint?: string;
};
export declare class ZitadelIntrospectionStrategy extends Strategy {
    private readonly options;
    name: string;
    private introspect?;
    constructor(options: ZitadelIntrospectionOptions);
    private get clientId();
    authenticate(req: Request<ParamsDictionary, unknown, unknown, ParsedQs, Record<string, any>>): Promise<void>;
    private getIntrospecter;
}
export {};
