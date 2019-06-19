"use strict";

const { ServiceBroker } = require("moleculer");
const { Compiler } = require("imicros-rules-compiler");

const ACL = {
    name: "ACL",
    actions: {
        getGrant: {
            async handler(ctx) {
                if (ctx.params) ctx.meta = null;
                
                let exp;
                // Define rule set
                exp = "@@ ";
                exp += "~F user.groups.name[..string]; > result.acl[string]:= 'decline'; > result.rule[number]:= 0";
                exp += "@ user.groups.name :: 'admin','guests' => result.acl := 'allow'; result.rule := 1";
                exp += "@ user.groups.name :: 'others','members' => result.acl := 'allow'; result.rule := 2";
                exp += "@@";
                let func = await Compiler.compile(exp);
                
                return { func: func };
            } 
        }
    }
};

const Service = {
    name: "client",
    dependencies: ["ACL"],
    actions: {
        test: {
            async handler(ctx) {
                let result = await ctx.call("ACL.getGrant");
                this.logger.info("Called ACL successful");
                if (result.func) {
                    //this.logger.info("Received function:", result.func);
                    // For execution create a function from the string...
                    let f = new Function(result.func)();
                    let calc = f({user: { groups: { name: ["guests"] } }});
                    this.logger.info("Calculated result:", calc);
                } else {
                    this.logger.info("Received:", result);
                } 
            }
        }
    }
};

let aclBroker = new ServiceBroker({
    nodeID: "ACL-master",
    transporter: "nats://192.168.2.124:4222",
    logger: console,
    logLevel: "info" //"debug"
});
aclBroker.createService(ACL);
aclBroker.start()
.then(async () => {
    let broker = new ServiceBroker({
        nodeID: "ACL-client",
        transporter: "nats://192.168.2.124:4222",
        logger: console,
        logLevel: "info" //"debug"
    });
    broker.createService(Service);
    broker.start()
    .then(async () => {
        //await console.log("Started");
        await broker.call("client.test");
    })
    .then(async () => {
        await broker.stop(); 
        await aclBroker.stop(); 
    });

});
