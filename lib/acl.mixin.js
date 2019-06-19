/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

module.exports = {

    /**
     * Service settings
     */
    settings: {},

    /**
     * Service metadata
     */
    metadata: {},

    /**
     * Methods
     */
    methods: {
        
        async isAuthorized ( { ctx = null, ressource = {}, action = "" } = {} ) { 
            if ( !ctx || !ctx.meta || !ctx.meta.acl ) return false;
            let acl = ctx.meta.acl;
            if ( acl.unrestricted ) {
                return true;
            } else {
                if ( !acl.grants || !Array.isArray(acl.grants) ) return false;
                this.logger.debug("restricted access - check grants", { count: acl.grants.length });
                for (let i=0; i<acl.grants.length; i++ ) {
                    this.logger.debug("check grant", { id: acl.grants[i].id });
                    let result = acl.grants[i].function({user: ctx.meta.user, ressource: ressource, action: action});
                    this.logger.debug("check grant result", { result: result });
                    if (result.acl.result === "allow") {
                        this.logger.debug("access granted",{ rule: result.acl.rule });
                        return true;
                    }
                } 
            }
            this.logger.debug("restricted access without grant");
            return false;
        },
        
    },

    /**
     * Service created lifecycle event handler
     */
    created() {},

    /**
     * Service started lifecycle event handler
     */
    async started() {},

    /**
     * Service stopped lifecycle event handler
     */
    async stopped() {}

};