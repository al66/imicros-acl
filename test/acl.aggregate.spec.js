"use strict";
const { ServiceBroker } = require("moleculer");
const { AclAggregate } = require("../index");

const timestamp = Date.now();

describe("Test service", () => {

    let broker, aggregate, opts;
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
            await broker.start();
            expect(aggregate).toBeDefined();
        });

    });
    
    describe("Test aggregate service", () => {

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

        it("it should add a new member to second group", async () => {
            let params = {
                event: "groups.user.joined",
                payload: {
                    groupId: "G2-" + timestamp,
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

        it("it should remove a member from second group", async () => {
            let params = {
                event: "groups.user.left",
                payload: {
                    groupId: "G2-" + timestamp,
                    userId: "U3-" + timestamp
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

        it("it should add a new member to second group", async () => {
            let params = {
                event: "groups.user.joined",
                payload: {
                    groupId: "G2-" + timestamp,
                    userId: "U4-" + timestamp,
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

        it("it should delete a user", async () => {
            let params = {
                event: "users.deleted",
                payload: {
                    userId: "U4-" + timestamp
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

        it("it should delete a group", async () => {
            let params = {
                event: "groups.deleted",
                payload: {
                    groupId: "G2-" + timestamp
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

        it("it should add a core group with a member", async () => {
            let params = {
                event: "groups.user.joined",
                payload: {
                    groupId: "GC-" + timestamp,
                    userId: "UC-" + timestamp,
                    role: "admin",
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

        it("it should delete the core group user", async () => {
            let params = {
                event: "users.deleted",
                payload: {
                    userId: "UC-" + timestamp
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

        it("it should delete the core group", async () => {
            let params = {
                event: "groups.deleted",
                payload: {
                    groupId: "GC-" + timestamp
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
    
    describe("Test stop broker", () => {
        it("should stop the broker", async () => {
            expect.assertions(1);
            await broker.stop();
            expect(broker).toBeDefined();
        });
    });
    
});