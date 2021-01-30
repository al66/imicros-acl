/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

const dbMixin = require("./db.neo4j");
const jwt 			= require("jsonwebtoken");
const { Compiler } = require("imicros-rules-compiler");

const jwtIssuer = "imicros.acl";

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
            async handler({ params, meta: { user = {} }}) {

                // Is user member of the group?
                if (user.id) {

                    let queryParams = {
                        groupId: params.forGroupId,
                        userId: user.id
                    };
                    let statement = "MATCH (g:Group { uid: {groupId} })<-[r:MEMBER_OF]-(u:User  { uid: {userId} }) ";
                    statement += "RETURN g.uid AS id, r.role AS role, g.core AS core;";
                    let result = await this.run(statement, queryParams);
                    // TODO: no result, if neo is down....
                    if (result[0]) {
                        let payload = {
                            ownerId: queryParams.groupId,
                            userId: user.id,
                            role: result[0].role,
                            core: result[0].core,
                            unrestricted: true
                        };
                        //let options = { issuer: ..., audience: ... };
                        let options = { issuer: this.jwtIssuer, subject: queryParams.groupId };
                        return { token: jwt.sign(payload, this.JWT_SECRET,options) };
                    }
                
                }
                
                // Is access granted for a group, where user is member?
                if (user.id) {
                    let queryParams = {
                        groupId: params.forGroupId,
                        userId: user.id
                    };
                    let statement = "MATCH (g:Group { uid: {groupId} })-[gt:GRANT]->(:Group)<-[:MEMBER_OF]-(u:User  { uid: {userId} }) ";
                    statement += "RETURN g.uid AS id;";
                    this.logger.debug("request grants", { statement, queryParams });
                    let result = await this.run(statement, queryParams);
                    if (result[0]) {
                        let payload = {
                            ownerId: queryParams.groupId,
                            userId: user.id,
                            restricted: true,
                            grant: true
                        };
                        //let options = { issuer: ..., audience: ... };
                        let options = { issuer: this.jwtIssuer, subject: queryParams.groupId };
                        return { token: jwt.sign(payload, this.JWT_SECRET,options) };
                    }
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
            visibility: "public",
            params: {
                token: { type: "string" }
            },
            async handler({ params: { token }, meta: { user = {}, service = {} }, broker = {} }) {
                this.logger.debug("verify token", { token });
                let acl = jwt.verify(token, this.JWT_SECRET, { });
                this.logger.debug("token sucessfully verified", { acl });
                // user access
                if ( acl.userId) {
                    if (acl.userId !== user.id) throw new Error("Token not valid");
                    // unrestricted access
                    if (acl.unrestricted) return { 
                        acl: {
                            nodeID: broker.nodeID,
                            accessToken: token,
                            ownerId: acl.ownerId,
                            role: acl.role,
                            core: acl.core,
                            unrestricted: true
                        }
                    };
                    // restricted access - get acl rules
                    let params = {
                        groupId: acl.ownerId,
                        userId: acl.userId
                    };
                    let statement = "MATCH (g:Group { uid: {groupId} })-[gt:GRANT]->(:Group)<-[:MEMBER_OF]-(u:User  { uid: {userId} }) ";
                    statement += "RETURN g.uid AS id, gt.function AS function;";
                    let result = await this.run(statement, params);
                    if (result && result[0]) {
                        return { 
                            acl: {
                                nodeID: broker.nodeID,
                                accessToken: token,
                                ownerId: acl.ownerId,
                                grants: result,
                                denies: [],
                                restricted: true
                            } 
                        };
                    } else {
                        this.logger.debug("missing grants", statement, params, result);
                        throw new Error("Restricted access - missing grants");
                    }
                }
                // service access
                if (acl.serviceId) {
                    if (acl.serviceId !== service.serviceId) throw new Error("Token not valid");
                    return { 
                        acl: { 
                            nodeID: broker.nodeID,
                            accessToken: token,
                            ownerId: acl.ownerId,
                            role: acl.role,
                            core: acl.core,
                            unrestricted: acl.unrestricted
                        }
                    };
                    
                }
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
            acl: "before",
            params: {
                forGroupId: { type: "string" },
                ruleset: { type: "string" }
            },
            async handler({ params, meta: { user = {}, acl = {} }}) {
                // let user = this.isAuthenticated (ctx.meta);
                if (!acl.ownerId) throw new Error("No group access");
                
                // check, if ruleset can be compiled and the result is a valid function
                let func = await Compiler.compile(params.ruleset);
                let f = new Function(func)();
                if (f && {}.toString.call(f) !== "[object Function]") throw new Error("unvalid ruleset");
                
                let queryParams = {
                    byGroupId: acl.ownerId || "-",
                    forGroupId: params.forGroupId,
                    adminId: user.id,  
                    adminRole: this.roles.admin,
                    ruleset: params.ruleset,
                    function: func
                };
                let statement;
                statement = "MATCH (g:Group { uid: {byGroupId} })<-[:MEMBER_OF { role: {adminRole} }]-(:User { uid: {adminId} }) ";
                statement += "MATCH (e:Group { uid: {forGroupId} }) ";
                statement += "MERGE (g)-[a:GRANT]->(e) ";
                statement += "SET a.ruleset={ruleset}, a.function={function} ";
                statement += "RETURN g.uid AS byGroupId, e.uid AS forGroupId, a.ruleset AS ruleset;";
                return this.run(statement, queryParams);
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
            acl: "before",
            params: {
                forGroupId: { type: "string" }
            },
            async handler({ params, meta: { user = {}, acl = {} }}) {
                // let user = this.isAuthenticated (ctx.meta);
                if (!acl.ownerId) throw new Error("No group access");
                
                let queryParams = {
                    byGroupId: acl.ownerId || "-",
                    forGroupId: params.forGroupId,
                    adminId: user.id,  
                    adminRole: this.roles.admin
                };
                let statement;
                statement = "MATCH (g:Group { uid: {byGroupId} })<-[:MEMBER_OF { role: {adminRole} }]-(:User { uid: {adminId} }) ";
                statement += "MATCH (g)-[a:GRANT]->(e:Group { uid: {forGroupId} }) ";
                statement += "DELETE a;";
                return this.run(statement, queryParams);
            }
        },
      
        /**
         * grantAccess
         * 
         * @actions
         * 
         * @returns {Object} {} || { token }
         */
        //TODO: replace meta.service.serviceId by meta.service.serviceToken
        //TODO: call agents.verify with serviceToken and retrieve serviceId
        grantAccess: {
            visibility: "public",
            acl: "before",
            async handler({ meta: { acl: { ownerId = null }, service: { serviceToken = null }}}) {
                if (!ownerId || !serviceToken) return {};

                const { serviceId } = await this.verifyServiceToken ({ serviceToken });
                if (!serviceId) return {};

                // build grant token
                let payload = {
                    type: "grant_token",
                    ownerId,
                    serviceId,
                    role: "member",
                    core: false,
                    unrestricted: true
                };
                //let options = { issuer: ..., audience: ... };
                let options = { issuer: this.jwtIssuer, subject: serviceId };
                return { token: jwt.sign(payload, this.JWT_SECRET,options) };
            }
        },

        /**
         * exchangeToken
         * 
         * @actions
         * @param {String} token
         * 
         * @returns {Object} {} || { token }
         */
        //TODO: replace meta.service.serviceId by meta.service.serviceToken
        //TODO: call agents.verify with serviceToken and retrieve serviceId
        exchangeToken: {
            visibility: "public",
            params: {
                token: { type: "string" }
            },
            async handler({ params, meta: { service: { serviceToken = null }}}) {
                if (!serviceToken) return {};

                const { serviceId } = await this.verifyServiceToken ({ serviceToken });
                if (!serviceId) return {};

                try {
                    let grant = jwt.verify(params.token, this.JWT_SECRET, { subject: serviceId });
                    if (grant.type !== "grant_token") throw new Error("wrong token type", grant.type);
                    // build access token
                    let payload = {
                        type: "access_token",
                        ownerId: grant.ownerId,
                        serviceId,
                        role: grant.role,
                        core: false,
                        unrestricted: grant.unrestricted
                    };
                    //let options = { issuer: ..., audience: ... };
                    let options = { issuer: this.jwtIssuer, subject: grant.ownerId, expiresIn: 60 };
                    return { token: jwt.sign(payload, this.JWT_SECRET,options) };
                } catch (err) {
                    this.logger.debug("Unvalid grant token", err);
                    return {};
                }
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
        
        async verifyServiceToken ({ serviceToken }) {
            const { serviceId = null } = await this.broker.call(`${this.services.agents}.verify`, { serviceToken });
            return { serviceId };
        }

        /**
         * Check User
         * 
         * @param {Object} meta data of call 
         * 
         * @returns {Object} user entity
         */
        /*
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
                // throw new Error("not authenticated" );
                return null;
            }
            return user;
        }
        */
        
    },
    
    /**
     * Service created lifecycle event handler
     */
    created() {
        
        this.JWT_SECRET = process.env.JWT_SECRET;
        if (!this.JWT_SECRET) throw new Error("Missing jwt secret - service can't be started");

        this.jwtIssuer = jwtIssuer;
        
        this.services = {
            agents: this.settings?.services?.agents ?? "agents"
        };

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