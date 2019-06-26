"use strict";
const { ServiceBroker } = require("moleculer");
const { AclMiddleware } = require("../index");
const { AclAggregate } = require("../index");
const { Acl } = require("../index");
const { AclMixin } = require("../index");

const fs = require("fs");
process.env.JWT_SECRET = fs.readFileSync("dev/private.pem");

const timestamp = Date.now();

const Service = {
    name: "service",
    mixins: [AclMixin],
    actions: {
        get: {
            async handler(ctx) {
                if (!ctx) throw new Error("missing context");
                if (!await this.isAuthorized({ ctx: ctx, ressource: {}, action: "read" })) throw new Error("not authorized");
                return true;
            }
        }
    }
};

describe("Test service", () => {

    let broker, acl, aggregate, service;
    
    beforeAll(() => {
    });
    
    afterAll(async () => {
    });
    
    describe("Test create service", () => {
        it("it should start the broker", async () => {
            broker = new ServiceBroker({
                logger: console,
                logLevel: "debug", //"info"
                middlewares: [AclMiddleware]
            });
            aggregate = await broker.createService(AclAggregate, Object.assign({
                settings: { 
                    uri: process.env.NEO4J_URI || "bolt://localhost:7687",
                    user: "neo4j",
                    password: "neo4j"
                }
            }));
            acl = await broker.createService(Acl, Object.assign({
                settings: { 
                    uri: process.env.NEO4J_URI || "bolt://localhost:7687",
                    user: "neo4j",
                    password: "neo4j"
                }
            }));
            service = await broker.createService(Service);
            await broker.start();
            expect(acl).toBeDefined();
            expect(aggregate).toBeDefined();
            expect(service).toBeDefined();
        });

        
    });

    describe("Build test data", () => {

        let opts, token;
        
        it("it should add a group with a member", async () => {
            let params = {
                event: "groups.user.joined",
                payload: {
                    groupId: "G-" + timestamp,
                    userId: "U-" + timestamp,
                    role: "admin"
                },
                version: "1",
                uid: "UID-" + timestamp,
                timestamp: timestamp 
            };
            return broker.call("acl.aggregate.eachEvent", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(true);
            });
        });
        
        it("it should add a second group with a member", async () => {
            let params = {
                event: "groups.user.joined",
                payload: {
                    groupId: "G2-" + timestamp,
                    userId: "U2-" + timestamp,
                    role: "member"
                },
                version: "1",
                uid: "UID-" + timestamp,
                timestamp: timestamp 
            };
            return broker.call("acl.aggregate.eachEvent", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(true);
            });
        });

        it("it should give unrestricted access to a member", async () => {
            opts = { meta: { user: { id: `U-${timestamp}` , email: `U-${timestamp}@host.com` } } };
            let params = {
                forGroupId: "G-" + timestamp
            };
            return broker.call("acl.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
                token = res.token;
            });
        });
        
        it("it should add a grant for second group", async () => {
            opts = { meta: { user: { id: `U-${timestamp}` , email: `U-${timestamp}@host.com` }, acl: { accessToken: token } } };
            let exp;
            exp = "@@ ";
            exp += "~F user.id[..string]; > acl.result[string]:= 'decline'; > acl.rule[number]:= 0";
            exp += "@ user.id :: '" + "U2-" + timestamp + "' => acl.result := 'allow'; acl.rule := 1";
            exp += "@@";            
            let params = {
                forGroupId: "G2-" + timestamp,
                ruleset: exp
            };
            return broker.call("acl.addGrant", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res[0].ruleset).toEqual(exp);
            });
        });
        
    });

    describe("Test all together", () => {
        
        let opts, token;
        
        it("it should give unrestricted access to a member", async () => {
            opts = { meta: { user: { id: `U-${timestamp}` , email: `U-${timestamp}@host.com` } } };
            let params = {
                forGroupId: "G-" + timestamp
            };
            return broker.call("acl.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
                token = res.token;
            });
        });

        it("it should allow access with unrestricted token", async () => {
            opts = { meta: { user: { id: `U-${timestamp}` , email: `U-${timestamp}@host.com` }, acl: { accessToken: token } } };
            let params;
            return broker.call("service.get", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(true);
            });
        });

        it("it should give restricted access to a member", async () => {
            opts = { meta: { user: { id: `U2-${timestamp}` , email: `U2-${timestamp}@host.com` } } };
            let params = {
                forGroupId: "G-" + timestamp
            };
            return broker.call("acl.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
                token = res.token;
            });
        });

        it("it should allow access by rule 1", async () => {
            opts = { meta: { user: { id: `U2-${timestamp}` , email: `U2-${timestamp}@host.com` }, acl: { accessToken: token } } };
            let params;
            return broker.call("service.get", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(true);
            });
        });
        
        
    });
    
    describe("Test stop broker", () => {
        it("should stop the broker", async () => {
            expect.assertions(1);
            await broker.stop();
            expect(broker).toBeDefined();
        });
    });
        
});