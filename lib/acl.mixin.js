/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

module.exports = {

    /**
     * Methods
     */
    methods: {
        
        async isAuthorized ( { ctx = null, ressource = {}, action = "", abort = false } = {} ) { 
            let acl = ctx?.meta?.acl ?? null;
            let user = ctx?.meta?.user ?? null;
            let service = ctx?.meta?.service ?? null;
            let environment = this.getEnvironment(ctx);
            
            // not authenticated
            if (!user && !service) {
                ctx.broker.logger.debug("not authorized access", { user, service, action: ctx.action } );
                if (abort) throw new Error("access not authorized (not authenticated)");
                return false;
            }
            
            // no access at all
            if (!acl) {
                this.logger.debug("not authorized access", { user: user.userId, service, action: action } );
                if (abort) throw new Error("access not authorized");
                return false;
            }
            
            // unrestricted access
            if ( acl.unrestricted ) {
                return true;
            // restricted access - check grant
            } else if (acl.restricted) {
                if ( !acl.grants || !Array.isArray(acl.grants) ) {
                    this.logger.debug("restricted access - but no grants set");
                    if (abort) throw new Error("access not authorized");
                    return false;
                }
                this.logger.debug("restricted access - check grants", { count: acl.grants.length });
                for (let i=0; i<acl.grants.length; i++ ) {
                    this.logger.debug("check grant", { id: acl.grants[i].id });

                    // call grant function with { user, ressource, action, environment }
                    let result = acl.grants[i].function({user: user, ressource: ressource, action: action, environment: environment });
                    this.logger.debug("check grant result", { result: result });
                    if (result.acl.result === "allow") {
                        this.logger.debug("access granted",{ rule: result.acl.rule });
                        return true;
                    }
                } 
                this.logger.debug("restricted access - not granted");
                if (abort) throw new Error("access not authorized");
                return false;
            }
            // access token not verified - no access
            if (abort) throw new Error("access not authorized");
            return false;
        },
        
        getOwnerId({ctx, abort = false}) {
            let ownerId = ctx?.meta?.acl?.ownerId ?? null;
            if (!ownerId && abort) throw new Error("access not authorized");
            return ownerId;
        },
        
        getEnvironment(ctx) {
            let timestamp = Date.now(); 
            return {
                timestamp: timestamp,
                date: new Date(timestamp).toLocaleDateString(),
                day: new Date(timestamp).getDay(),
                time: new Date(timestamp).toLocaleTimeString(),
                action: ctx.action.name,
                params: ctx.params,
                meta: ctx.meta
            };
        }
        
    }

};