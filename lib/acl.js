/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

const dbMixin = require("./db.neo4j");
const objectMapper =  require("object-mapper");
const jwt 			= require("jsonwebtoken");
const { Compiler } = require("imicros-rules-compiler");

/** Actions */
// action requestAccess { forGroupId } => { token }
// action verify { token } => { acl }
// action addGrant { forGroupId, rulesetId } => { result } only for group admins
// action removeGrant { forGroupId } => { result } only for group admins

// to be done
// action addDeny { forGroupId, rulesetId } => { result } only for group admins
// action removeDeny { forGroupId } => { result } only for group admins

// enhancements ?
//?? action useStore { storeId, rulesetId } => { storeId }
//?? Set an attributes ruleset to map the grant attributes from the original ressource ?? 

module.exports = {
    name: "acl",
    mixins: [dbMixin],
    
    /**
     * Service settings
     */
    settings: {},
    
    /**
     * Service metadata
     */
    metadata: {},

    /**
     * Service dependencies
     */
    //dependencies: [],	

    /**
     * Actions
     */
    actions: {

        /**
         * requestAccess
         * 
         * @actions
         * @param {String} forGroupId
         * 
         * @returns {String} token
         */
        requestAccess: {
            params: {
                forGroupId: { type: "string" }
            },
            async handler(ctx) {
                let user = this.isAuthenticated (ctx.meta);
                let params = {
                    groupId: ctx.params.forGroupId,
                    userId: user.id
                };
                // Is user member of the group?
                let statement = "MATCH (g:Group { uid: {groupId} })<-[r:MEMBER_OF]-(u:User  { uid: {userId} }) ";
                statement += "RETURN g.uid AS id, r.role AS role, g.core AS core;";
                let result = await this.run(statement, params);
                // TODO: no result, if neo is down....
                if (result[0]) {
                    let payload = {
                        ownerId: params.groupId,
                        role: result[0].role,
                        core: result[0].core,
                        unrestricted: true
                    };
                    //let options = { issuer: ..., audience: ... };
                    let options = { subject: user.id };
                    return { token: jwt.sign(payload, this.JWT_SECRET,options) };
                }
                
                // Is access granted for calling service
                if (ctx.meta.serviceToken && ctx.meta.ownerId) {
                    // TODO - verify service token
                    // TODO - check for grant
                    // TODO - emit access token for service
                    let payload = {
                        ownerId: params.groupId,
                        unrestricted: true
                    };
                    //let options = { issuer: ..., audience: ... };
                    let options = { subject: user.id };
                    return { token: jwt.sign(payload, this.JWT_SECRET,options) };
                }
                
                // Is access granted for a group, where user is member?
                statement = "MATCH (g:Group { uid: {groupId} })-[gt:GRANT]->(:Group)<-[:MEMBER_OF]-(u:User  { uid: {userId} }) ";
                statement += "RETURN g.uid AS id;";
                this.logger.debug("request grants", { statement: statement, params: params });
                result = await this.run(statement, params);
                if (result[0]) {
                    let payload = {
                        ownerId: params.groupId,
                        grant: true
                    };
                    //let options = { issuer: ..., audience: ... };
                    let options = { subject: user.id };
                    return { token: jwt.sign(payload, this.JWT_SECRET,options) };
                }
                // no access
                this.logger.debug("no access");
                return {};
            }
        },        

        /**
         * verify
         * 
         * @actions
         * @param {String} token
         * 
         * @returns {Object} acl
         */
        verify: {
            params: {
                token: { type: "string" }
            },
            async handler(ctx) {
                let user = this.isAuthenticated (ctx.meta);
                this.logger.debug("verify token", { token: ctx.params.token, user: user });
                let acl = jwt.verify(ctx.params.token, this.JWT_SECRET, { subject: user.id });
                this.logger.debug("token sucessfully verified", { payload: acl });
                
                if (acl.unrestricted) return { 
                    acl: { 
                        accessToken: ctx.params.token,
                        ownerId: acl.ownerId,
                        role: acl.role,
                        core: acl.core,
                        unrestricted: true
                    }
                };

                // get acl rules
                let params = {
                    groupId: acl.ownerId,
                    userId: acl.sub
                };
                let statement = "MATCH (g:Group { uid: {groupId} })-[gt:GRANT]->(:Group)<-[:MEMBER_OF]-(u:User  { uid: {userId} }) ";
                statement += "RETURN g.uid AS id, gt.function AS function;";
                let result = await this.run(statement, params);
                if (result && result[0]) {
                    return { 
                        acl: {
                            accessToken: ctx.params.token,
                            ownerId: acl.ownerId,
                            grants: result,
                            denies: [],
                            restricted: true
                        } 
                    };
                }
                return { acl: {} };
            }
        },        

        /**
         * Grant access fo another group
         * 
         * @actions
         * @param {String} forGroupId group id access will be granted for
         * @param {String} ruleset 
         * 
         * @returns {Object} result
         */
        addGrant: {
            params: {
                forGroupId: { type: "string" },
                ruleset: { type: "string" }
            },
            async handler(ctx) {
                let user = this.isAuthenticated (ctx.meta);
                if (!ctx.meta.acl.ownerId) throw new Error("No group access");
                
                // check, if ruleset can be compiled and the result is a valid function
                let func = await Compiler.compile(ctx.params.ruleset);
                let f = new Function(func)();
                if (f && {}.toString.call(f) !== "[object Function]") throw new Error("unvalid ruleset");
                
                let params = {
                    byGroupId: ctx.meta.acl.ownerId || "-",
                    forGroupId: ctx.params.forGroupId,
                    adminId: user.id,  
                    adminRole: this.roles.admin,
                    ruleset: ctx.params.ruleset,
                    function: func
                };
                let statement;
                statement = "MATCH (g:Group { uid: {byGroupId} })<-[:MEMBER_OF { role: {adminRole} }]-(:User { uid: {adminId} }) ";
                statement += "MATCH (e:Group { uid: {forGroupId} }) ";
                statement += "MERGE (g)-[a:GRANT]->(e) ";
                statement += "SET a.ruleset={ruleset}, a.function={function} ";
                statement += "RETURN g.uid AS byGroupId, e.uid AS forGroupId, a.ruleset AS ruleset;";
                return this.run(statement, params);
            }
        },        
        
        /**
         * removeGrant
         * 
         * @actions
         * @param {String} forGroupId group id access will be removed for
         * 
         * @returns [] ruleset
         */
        removeGrant: {
            params: {
                forGroupId: { type: "string" }
            },
            async handler(ctx) {
                let user = this.isAuthenticated (ctx.meta);
                if (!ctx.meta.acl.ownerId) throw new Error("No group access");
                
                let params = {
                    byGroupId: ctx.meta.acl.ownerId || "-",
                    forGroupId: ctx.params.forGroupId,
                    adminId: user.id,  
                    adminRole: this.roles.admin
                };
                let statement;
                statement = "MATCH (g:Group { uid: {byGroupId} })<-[:MEMBER_OF { role: {adminRole} }]-(:User { uid: {adminId} }) ";
                statement += "MATCH (g)-[a:GRANT]->(e:Group { uid: {forGroupId} }) ";
                statement += "DELETE a;";
                return this.run(statement, params);
            }
        }        
    },
    
    /**
     * Events
     */
    events: {},

    /**
     * Methods
     */
    methods: {
        
        /**
         * Check User
         * 
         * @param {Object} meta data of call 
         * 
         * @returns {Object} user entity
         */
        isAuthenticated (meta) {
            // Prepared enhancement: individual maps via settings 
            // from : to
            let map = {
                "user.id": "id",        // from meta.user.id to user.id
                "user.email": "email"   // from meta.user.email to user.email
            };
            let user = objectMapper(meta, map);
            if (!user || !user.id || !user.email ) {
                this.logger.debug("user not authenticated", { meta: meta });
                throw new Error("not authenticated" );
            }
            return user;
        }
        
    },
    
    /**
     * Service created lifecycle event handler
     */
    created() {
        
        this.JWT_SECRET = process.env.JWT_SECRET;
        if (!this.JWT_SECRET) throw new Error("Missing jwt secret - service can't be started");

        this.roles = {
            admin : this.settings.adminRole || "admin",
            default : this.settings.defaultRole || "member",
        };
        
    },

    /**
     * Service started lifecycle event handler
     */
    started() {},

    /**
     * Service stopped lifecycle event handler
     */
    stopped() {}
    
};