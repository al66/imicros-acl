"use strict";
const { ServiceBroker } = require("moleculer");
const { Aggregate } = require("../index");

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
            aggregate = await broker.createService(Aggregate, Object.assign({
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

    });
    
    describe("Test stop broker", () => {
        it("should stop the broker", async () => {
            expect.assertions(1);
            await broker.stop();
            expect(broker).toBeDefined();
        });
    });
    
});