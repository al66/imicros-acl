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
            async handler({ params: { event, payload = {}, version, uid, timestamp} }) {
                switch (event) {
                    case "groups.user.joined":
                        if ( !payload.groupId || !payload.userId || !payload.role ) return false;
                        await this.addMember({ groupId: payload.groupId, userId: payload.userId, role: payload.role, core: payload.core });
                        break;
                    case "groups.user.removed":
                    case "groups.user.left":
                        if ( !payload.groupId || !payload.userId ) return false;
                        await this.removeMember({ groupId: payload.groupId, userId: payload.userId });
                        break;
                    case "groups.deleted":
                        if ( !payload.groupId ) return false;
                        await this.removeGroup({ groupId: payload.groupId });
                        break;
                    case "users.deleted":
                        if ( !payload.userId ) return false;
                        await this.removeUser({ userId: payload.userId });
                        break;
                }
                this.logger.debug(`Event ${event} sucessfull processed`, { version, uid, timestamp });
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
        
        async addMember({ groupId, userId, role, core } = {}) {
            let params = {
                groupId,
                userId,
                role
            };
            let statement = "MERGE (u:User { uid: $userId }) ";
            statement += "MERGE (g:Group { uid: $groupId }) ";
            if (core) statement += "ON CREATE SET g.core = true ";
            statement += "MERGE (u)-[r:MEMBER_OF]->(g) ";
            statement += "SET r.role=$role;";
            await this.run(statement, params);
            this.logger.debug(`Member ${userId} added to group ${groupId}`, { userId, groupId, role });
            return true;
        },
        
        async removeMember({ groupId, userId } = {}) {
            let params = {
                groupId,
                userId
            };
            let statement = "MATCH (u:User { uid: $userId })-[r:MEMBER_OF]->(g:Group { uid: $groupId }) ";
            statement += "DELETE r ";
            statement += ";";
            await this.run(statement, params);                    
            this.logger.debug(`Member ${userId} removed group ${groupId}`, { userId, groupId });
            return true;
        },
        
        async removeGroup({ groupId } = {}) {
            let params = {
                groupId
            };
            let statement = "MATCH (g:Group { uid: $groupId }) ";
            statement += "DETACH DELETE g ";
            statement += ";";
            await this.run(statement, params);                    
            this.logger.debug(`Group ${groupId} removed`, { groupId });
            return true;
        },
        
        async removeUser({ userId } = {}) {
            let params = {
                userId
            };
            let statement = "MATCH (u:User { uid: $userId }) ";
            statement += "DETACH DELETE u ";
            statement += ";";
            await this.run(statement, params);                    
            this.logger.debug(`User ${userId} removed`, { userId });
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