"use strict";
const { ServiceBroker } = require("moleculer");
const { AclMixin } = require("../index");
const { Compiler } = require("imicros-rules-compiler");

const timestamp = Date.now();

const Store = {
    name: "Store",
    settings: {
        acl: {
            service: "ACL"
        }
    },
    mixins: [AclMixin],
    actions: {
        add: {
            async handler(ctx) {
                let res = {
                    id: ctx.params.resId,
                    attrib1: "Attribut 1",
                    attrib2: "Attribut 2",
                    attrib3: "Attribut 3"
                };
                this.logger.info("Store.add called", ctx.meta );
                if (!await this.isAuthorized({ ctx: ctx, ressource: res, action: "create" })) throw new Error("not authorized");
                return ctx.params.resId;
            }
        },
        get: {
            async handler(ctx) {
                this.logger.info("Store.get called", ctx.meta );
                let res = {
                    id: ctx.params.resId,
                    attrib1: "Attribut 1",
                    attrib2: "Attribut 2",
                    attrib3: "Attribut 3"
                };
                if (!await this.isAuthorized({ ctx: ctx, ressource: res, action: "read" })) throw new Error("not authorized");
                return ctx.params.resId;
            }
        },
        remove: {
            async handler(ctx) {
                this.logger.info("Store.remove called", ctx.meta );
                let res = {
                    id: ctx.params.resId,
                    attrib1: "Attribut 1",
                    attrib2: "Attribut 2",
                    attrib3: "Attribut 3"
                };
                if (!await this.isAuthorized({ ctx: ctx, ressource: res, action: "delete" })) throw new Error("not authorized");
                return true;
            }
        }
    }
};

describe("Test mixin service", () => {

    let broker, store, opts;
    beforeAll(() => {
    });
    
    afterAll(async () => {
    });
    
    describe("Test create service", () => {

        it("it should start the broker", async () => {
            broker = new ServiceBroker({
                logger: console,
                logLevel: "info" //"debug"
            });
            store = await broker.createService(Store, Object.assign({}));
            await broker.start();
            expect(store).toBeDefined();
        });

    });

    describe("Test acl.mixin ", () => {

        beforeEach(() => {
            opts = { meta: { user: { id: `1-${timestamp}` , email: `1-${timestamp}@host.com` } } };
        });

        it("it should allow action create", () => {
            opts.meta.acl = { owner: `g-${timestamp}`, role: "member", unrestricted: true };
            let params = {
                resId: "R-" + timestamp
            };
            return broker.call("Store.add", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(params.resId);
            });
        });
        
        it("it should allow action read", () => {
            opts.meta.acl = { owner: `g-${timestamp}`, role: "member", unrestricted: true };
            let params = {
                resId: "R-" + timestamp
            };
            return broker.call("Store.get", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(params.resId);
            });
        });
        
        it("it should throw authorization error", async () => {
            opts.meta.acl = { owner: `g-${timestamp}`, grants: [], restricted: true };
            let params = {
                resId: "R-" + timestamp
            };
            await expect(broker.call("Store.get", params, opts)).rejects.toThrow("not authorized");
        });
        
        it("it should allow action read", async () => {
            let exp;
            exp = "@@ ";
            exp += "~F user.email[..string]; > acl.result[string]:= 'decline'; > acl.rule[number]:= 0";
            exp += "@ user.email :: '" + `1-${timestamp}@host.com` + "' => acl.result := 'allow'; acl.rule := 1";
            exp += "@@";
            let strFunction =await Compiler.compile(exp);
            let grant = {
                id: "xyz",
                function: new Function(strFunction)()
            };
            opts.meta.acl = { owner: `g-${timestamp}`, grants: [grant], restricted: true };
            let params = {
                resId: "R-" + timestamp
            };
            return broker.call("Store.get", params, opts).then(res => {
                expect(res).toBeDefined();
                expect(res).toEqual(params.resId);
            });
        });
        
        it("it should throw authorization error", async () => {
            let exp;
            exp = "@@ ";
            exp += "~F user.email[..string]; > acl.result[string]:= 'decline'; > acl.rule[number]:= 0";
            exp += "@ user.email :: '" + `2-${timestamp}@host.com` + "' => acl.result := 'allow'; acl.rule := 1";
            exp += "@@";
            let strFunction =await Compiler.compile(exp);
            let grant = {
                id: "xyz",
                function: new Function(strFunction)()
            };
            opts.meta.acl = { owner: `g-${timestamp}`, grants: [grant], restricted: true };
            let params = {
                resId: "R-" + timestamp
            };
            await expect(broker.call("Store.get", params, opts)).rejects.toThrow("not authorized");
        });
        
        it("it should allow action delete", () => {
            opts.meta.acl = { owner: `g-${timestamp}`, role: "member", unrestricted: true };
            let params = {
                resId: "R-" + timestamp
            };
            return broker.call("Store.remove", params, opts).then(res => {
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