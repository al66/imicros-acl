/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

const _ = require("lodash");

module.exports = ({service}) => { 
    
    /*
    function getOwnerId({ctx, abort = false}) {
        let ownerId = _.get(ctx.meta,"acl.ownerId",null);
        if (!ownerId && abort) throw new Error("access not authorized");
        return ownerId;
    }
    */
        
    function getEnvironment(ctx) {
        let timestamp = Date.now(); 
        return {
            timestamp: timestamp,
            date: new Date(timestamp).toLocaleDateString(),
            day: new Date(timestamp).getDay(),
            time: new Date(timestamp).toLocaleTimeString(),
            action: ctx.action,
            meta: ctx.meta
        };
    }
    
    /**
	    * isAuthorized
	    */    
    function isAuthorized( { ctx = null, result = {}, abort = false } = {} ) { 
        let acl = _.get(ctx,"meta.acl",null);
        let user = _.get(ctx,"meta.user",null);
        let { meta: { service = null } } = ctx;
        let environment = getEnvironment(ctx);
            
        // not authenticated
        if (!user && !service) {
            ctx.broker.logger.debug("not authorized access", { user, service, action: ctx.action } );
            if (abort) throw new Error("access not authorized (not authenticated)");
            return false;
        }
        
        // no access at all
        if (!acl) {
            ctx.broker.logger.debug("not authorized access", { user, service, action: ctx.action } );
            if (abort) throw new Error("access not authorized");
            return false;
        }
            
        // unrestricted access
        if ( acl.unrestricted ) {
            return true;
        // restricted access - check grant
        } else if (acl.restricted) {
            if ( !acl.grants || !Array.isArray(acl.grants) ) {
                ctx.broker.logger.debug("restricted access - but no grants set");
                if (abort) throw new Error("access not authorized");
                return false;
            }
            ctx.broker.logger.debug("restricted access - check grants", { count: acl.grants.length });
            for (let i=0; i<acl.grants.length; i++ ) {
                ctx.broker.logger.debug("check grant", { id: acl.grants[i].id, user: user, action: ctx.action.name, params: ctx.params, result: result, environment: environment  });

                // call grant function with { user, action, params, result, environment }
                let check = acl.grants[i].function({user: user, action: ctx.action.name, params: ctx.params, result: result, environment: environment });
                ctx.broker.logger.debug("check grant result", { result: check });
                if (check.acl.result === "allow") {
                    ctx.broker.logger.debug("access granted",{ rule: check.acl.rule });
                    return true;
                }
            } 
            ctx.broker.logger.debug("restricted access - not granted");
            if (abort) throw new Error("access not authorized");
            return false;
        }
        // access token not verified - no access
        if (abort) throw new Error("access not authorized");
        return false;
    }
        
    
    
    /**
     * Expose middleware
     */    
    return {
    
        // wrap local action - call acl 
        localAction(next, action) {
            return async function(ctx) {
                // get acl
                if (action.acl) {
                    if (ctx.meta.acl && ( !ctx.meta.acl.nodeID || ctx.meta.acl.nodeID !== ctx.broker.nodeID )) {
                        let token = ctx.meta.acl.accessToken;
                        ctx.meta.acl = null;

                        if (token) {
                            let params = { token: token }, opt = { meta: ctx.meta };
                            try {
                                ctx.broker.logger.debug("call acl service to verify token", { params: params , meta: opt.meta });
                                let result = await ctx.call(service+".verify",params,opt);
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
                                ctx.meta.acl.accessToken = token;
                                ctx.meta.acl.nodeID = ctx.broker.nodeID;
                                ctx.broker.logger.debug("access token verified and acl data set", { acl: ctx.meta.acl });
                            } catch (err) {
                                ctx.broker.logger.debug("Failed to verify access token");
                            }
                        }
                    }
                }

                if (action.acl == "core" && (!ctx.meta.acl || ctx.meta.acl.core !== true)) {
                    ctx.broker.logger.debug("access to core function rejected", { acl: ctx.meta.acl, action });
                    throw new Error("access not authorized");
                }
                
                // short path for usage in services
                ctx.meta.ownerId = _.get(ctx.meta,"acl.ownerId", null);

                // acl check before call based on action and parameters or after call based on the result
                ctx.broker.logger.debug("call wrapped action", { action: action.name, acl: action.acl });
                if (action.acl === "before" || action.acl === "always"  || action.acl === true ) {
                    isAuthorized( { ctx: ctx, action: action.name, params: ctx.params, abort: true } );
                }
                
                if (action.acl === "after" || action.acl === "always") {
                    const res = await next(ctx);
                    isAuthorized( { ctx: ctx, action: action.name, params: ctx.params, result: res, abort: true } );
                    return res;
                } else {
                    return next(ctx);
                }
            };
        },

        // After broker started
        async started(broker) {

            // wait for acl service
            await broker.waitForServices([service]);

        }
    };
};