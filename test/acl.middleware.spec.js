"use strict";
const { ServiceBroker } = require("moleculer");
const { AclMiddleware } = require("../index");
const { AclAggregate } = require("../index");
const { Acl } = require("../index");
// const { AclMixin } = require("../index");

const fs = require("fs");
process.env.JWT_SECRET = fs.readFileSync("dev/private.pem");

const timestamp = Date.now();

const Service = {
    name: "service",
    // mixins: [AclMixin],
    actions: {
        get: {
            acl: "before",
            async handler(ctx) {
                if (!ctx) throw new Error("missing context");
                // if (!await this.isAuthorized({ ctx: ctx, ressource: {}, action: "read" })) throw new Error("not authorized");
                return true;
            }
        },
        get2: {
            acl: "after",
            async handler(ctx) {
                if (!ctx) throw new Error("missing context");
                // if (!await this.isAuthorized({ ctx: ctx, ressource: {}, action: "read" })) throw new Error("not authorized");
                return { test: { a: "yes" } };
            }
        },
        get3: {
            acl: "core",
            async handler(ctx) {
                if (!ctx) throw new Error("missing context");
                return { test: { core: "yes" } };
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
                middlewares: [AclMiddleware({service: "acl"})]
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
            exp += "@ user.id :: '" + "U2-" + timestamp + "' && environment.action.name :: 'service.get' => acl.result := 'allow'; acl.rule := 1";
            exp += "@ user.id :: '" + "U2-" + timestamp + "' && result.test.a :: 'yes' => acl.result := 'allow'; acl.rule := 2";
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

        it("it should add a core group with a member", async () => {
            let params = {
                event: "groups.user.joined",
                payload: {
                    groupId: "G3-" + timestamp,
                    userId: "U3-" + timestamp,
                    role: "member",
                    core: true
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

        it("it should deny access for core group", async () => {
            opts = { meta: { user: { id: `U-${timestamp}` , email: `U-${timestamp}@host.com` }, acl: { accessToken: token } } };
            let params;
            return broker.call("service.get3", params, opts)
                .then(res => {
                    console.log(res);
                })
                .catch(err => {
                    expect(err.message).toEqual("access not authorized");
                });
            // expect(async () => { await broker.call("service.get3", params, opts); }).toThrow("access not authorized");
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
        
        it("it should allow access by rule 2", async () => {
            opts = { meta: { user: { id: `U2-${timestamp}` , email: `U2-${timestamp}@host.com` }, acl: { accessToken: token } } };
            let params;
            return broker.call("service.get2", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual({"test": {"a": "yes"}});
            });
        });

        it("it should give unrestricted access to a member of core group", async () => {
            opts = { meta: { user: { id: `U3-${timestamp}` , email: `U3-${timestamp}@host.com` } } };
            let params = {
                forGroupId: "G3-" + timestamp
            };
            return broker.call("acl.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
                token = res.token;
            });
        });

        
        it("it should allow access for core group", async () => {
            opts = { meta: { user: { id: `U3-${timestamp}` , email: `U3-${timestamp}@host.com` }, acl: { accessToken: token } } };
            let params;
            return broker.call("service.get3", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual({"test": {"core": "yes"}});
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