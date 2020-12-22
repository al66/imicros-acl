"use strict";
const { ServiceBroker } = require("moleculer");
const { AclAggregate } = require("../index");
const { Acl } = require("../index");
const { Compiler } = require("imicros-rules-compiler");

const timestamp = Date.now();

const fs = require("fs");
process.env.JWT_SECRET = fs.readFileSync("dev/private.pem");

let exp1; 
exp1 = "@@ ";
exp1 += "~F user.groups.name[..string]; > result.acl[string]:= 'decline'; > result.rule[number]:= 0";
exp1 += "@ user.groups.name :: 'admin','guests' => result.acl := 'allow'; result.rule := 1";
exp1 += "@ user.groups.name :: 'others','members' => result.acl := 'allow'; result.rule := 2";
exp1 += "@@";

describe("Test service", () => {

    let broker, acl, aggregate, opts;
    beforeAll(() => {
    });
    
    afterAll(async () => {
    });
    
    describe("Test create service", () => {

        it("it should start the broker", async () => {
            broker = new ServiceBroker({
                logger: console,
                logLevel: "debug" //"info"
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
            await broker.start();
            expect(aggregate).toBeDefined();
            expect(acl).toBeDefined();
        });

    });
    
    describe("Build test data", () => {

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
        
        it("it should add a third group with a member", async () => {
            let params = {
                event: "groups.user.joined",
                payload: {
                    groupId: "G3-" + timestamp,
                    userId: "U3-" + timestamp,
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
        
        it("it should add a group account", async () => {
            let params = {
                event: "account.created",
                payload: {
                    accountId: "A1-" + timestamp,
                    groupId: "G-" + timestamp
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
    
    describe("Test grants", () => {

        beforeEach(() => {
            opts = { meta: { user: { id: `U-${timestamp}` , email: `U-${timestamp}@host.com` }, acl: { ownerId: `G-${timestamp}` } } };
        });
        
        it("it should add a grant for second group", async () => {
            let exp = exp1;
            let params = {
                forGroupId: "G2-" + timestamp,
                ruleset: exp
            };
            return broker.call("acl.addGrant", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res[0].ruleset).toEqual(exp);
            });
        });

        it("it should add a grant for third group", async () => {
            let exp = exp1;
            let params = {
                forGroupId: "G3-" + timestamp,
                ruleset: exp
            };
            return broker.call("acl.addGrant", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res[0].ruleset).toEqual(exp);
            });
        });

        it("it should remove grant for third group again", async () => {
            let params = {
                forGroupId: "G3-" + timestamp
            };
            return broker.call("acl.removeGrant", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual([]);
            });
        });

        
    });
        
    describe("Test access", () => {
        
        let token;
        
        beforeEach(() => {
            opts = { meta: { user: { id: `U-${timestamp}` , email: `U-${timestamp}@host.com` } } };
        });
        
        it("it should give unrestricted access to a member", async () => {
            let params = {
                forGroupId: "G-" + timestamp
            };
            return broker.call("acl.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
                token = res.token;
            });
        });

        it("it should give no access", async () => {
            opts = { meta: { user: { id: `U3-${timestamp}` , email: `U3-${timestamp}@host.com` } } };
            let params = {
                forGroupId: "G2-" + timestamp
            };
            return broker.call("acl.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).not.toBeDefined();
            });
        });

        it("it should verify the token", async () => {
            let params = {
                token: token
            };
            return broker.call("acl.verify", params, opts).then(res => {
                expect(res.acl).toBeDefined();
                expect(res.acl.unrestricted).toEqual(true);
                expect(res.acl.ownerId).toEqual("G-" + timestamp);
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

        it("it should verify the token and return grant function as string", async () => {
            opts = { meta: { user: { id: `U2-${timestamp}` , email: `U2-${timestamp}@host.com` } } };
            let exp = exp1;
            let params = {
                token: token
            };
            return broker.call("acl.verify", params, opts).then(async res => {
                expect(res.acl).toBeDefined();
                expect(res.acl.unrestricted).not.toBeDefined();
                expect(res.acl.ownerId).toEqual("G-" + timestamp);
                expect(res.acl.grants).toHaveLength(1);
                expect(res.acl.grants[0].function).toEqual(await Compiler.compile(exp));
            });
        });

        it("it should give unrestricted access to an group account", async () => {
            opts = {
                meta: {
                    serviceToken: "xy",
                    accountId: "A1-" + timestamp
                }
            };
            let params = {
                forGroupId: "G-" + timestamp
            };
            return broker.call("acl.requestAccess", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res.token).toBeDefined();
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