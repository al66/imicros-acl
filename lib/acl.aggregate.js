/**
 * @license MIT, imicros.de (c) 2019 Andreas Leinen
 */
"use strict";

const dbMixin = require("./db.neo4j");

/** Actions */
// action eachEvent { event } => {}

module.exports = {
    name: "acl.aggregate",
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
        eachEvent: {
            params: {
                event: { type: "string" },
                payload: { type: "any" },
                version: { type: "string" },
                uid: { type: "string" },
                timestamp: { type: "number" }
            },
            async handler(ctx) {
                switch (ctx.params.event) {
                    case "groups.user.joined":
                        if ( !ctx.params.payload.groupId || !ctx.params.payload.userId || !ctx.params.payload.role ) return false;
                        await this.addMember({ groupId: ctx.params.payload.groupId, userId: ctx.params.payload.userId, role:ctx.params.payload.role });
                        break;
                    case "groups.user.removed":
                    case "groups.user.left":
                        if ( !ctx.params.payload.groupId || !ctx.params.payload.userId ) return false;
                        await this.removeMember({ groupId: ctx.params.payload.groupId, userId: ctx.params.payload.userId });
                        break;
                    case "groups.deleted":
                        if ( !ctx.params.payload.groupId ) return false;
                        await this.removeGroup({ groupId: ctx.params.payload.groupId });
                        break;
                    case "users.deleted":
                        if ( !ctx.params.payload.userId ) return false;
                        await this.removeUser({ userId: ctx.params.payload.userId });
                        break;
                }
                this.logger.debug(`Event ${ctx.params.event} sucessfull processed`, { uid: ctx.params.uid, timestamp: ctx.params.timestamp });
                return true;
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
        
        async addMember({ groupId, userId, role } = {}) {
            let params = {
                groupId: groupId,
                userId: userId,
                role: role
            };
            let statement = "MERGE (u:User { uid: {userId} }) ";
            statement += "MERGE (g:Group { uid: {groupId} }) ";
            statement += "MERGE (u)-[r:MEMBER_OF]->(g) ";
            statement += "SET r.role={role};";
            await this.run(statement, params);
            this.logger.debug(`Member ${userId} added to group ${groupId}`, { userId: userId, groupId: groupId, role: role });
            return true;
        },
        
        async removeMember({ groupId, userId } = {}) {
            let params = {
                groupId: groupId,
                userId: userId
            };
            let statement = "MATCH (u:User { uid: {userId} })-[r:MEMBER_OF]->(g:Group { uid: {groupId} }) ";
            statement += "DELETE r ";
            statement += ";";
            await this.run(statement, params);                    
            this.logger.debug(`Member ${userId} removed group ${groupId}`, { userId: userId, groupId: groupId });
            return true;
        },
        
        async removeGroup({ groupId } = {}) {
            let params = {
                groupId: groupId
            };
            let statement = "MATCH (g:Group { uid: {groupId} }) ";
            statement += "DELETE g ";
            statement += ";";
            await this.run(statement, params);                    
            this.logger.debug(`Group ${groupId} removed`, { groupId: groupId });
            return true;
        },
        
        async removeUser({ userId } = {}) {
            let params = {
                userId: userId
            };
            let statement = "MATCH (u:User { uid: {userId} }) ";
            statement += "DELETE u ";
            statement += ";";
            await this.run(statement, params);                    
            this.logger.debug(`User ${userId} removed`, { userId: userId });
            return true;
        }
    },
    
    /**
     * Service created lifecycle event handler
     */
    created() {},

    /**
     * Service started lifecycle event handler
     */
    started() {},

    /**
     * Service stopped lifecycle event handler
     */
    stopped() {}
    
};