/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

module.exports = ({aclService}) => { return {
    
    // wrap local action - call acl 
    localAction(next, action) {
        return async function(ctx) {
            if (ctx.meta.acl) {
                let token = ctx.meta.acl.accessToken;
                ctx.meta.acl = null;
                
                if (token) {
                    let params = { token: token }, opt = { meta: ctx.meta };
                    try {
                        ctx.broker.logger.debug("call acl service to verify token", { params: params , meta: opt.meta });
                        let result = await ctx.call(aclService+".verify",params,opt);
                        if (result.acl && result.acl.grants) {
                            ctx.broker.logger.debug("convert grant functions received", { count: result.acl.grants.length});
                            for (let i=0; i<result.acl.grants.length; i++) {
                                result.acl.grants[i].function = new Function(result.acl.grants[i].function)();
                                if (result.acl.grants[i].function && {}.toString.call(result.acl.grants[i].function) !== "[object Function]") {
                                    ctx.broker.logger.error("unvalid grant function received");
                                    throw new Error("unvalid ruleset");
                                }
                            }
                        }
                        ctx.meta.acl = result.acl;
                        ctx.broker.logger.debug("access token verified and acl data set", { acl: ctx.meta.acl });
                    } catch (err) {
                        ctx.broker.logger.debug("Failed to verify access token");
                    }
                }
            }
            ctx.broker.logger.debug("call wrapped action", { action: action.name });
            return next(ctx);
        };
    },
    
    // After broker started
    async started(broker) {
        
        // wait for acl service
        await broker.waitForServices(["acl"]);
        //await broker.waitForServices([this.imicros.dependencies]);

    }

};};