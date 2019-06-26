# imicros-acl
[![Build Status](https://travis-ci.org/al66/imicros-acl.svg?branch=master)](https://travis-ci.org/al66/imicros-acl)
[![Coverage Status](https://coveralls.io/repos/github/al66/imicros-acl/badge.svg?branch=master)](https://coveralls.io/github/al66/imicros-acl?branch=master)

## Installation
```
$ npm install imicros-acl --save
```
## Dependencies
Requires 
-  a running [Neo4j](https://neo4j.com/) instance - refer to [example](#Docker).
-  imicros-groups service for managing the groups

## Preconditions
The service expects user id and email to be set in ctx.meta data as follows:
```
ctx.meta.user = {
    id: 'unique ID of the user (number or string)',
    email: 'user@test.org'
}
```
Otherwise the service throws <code>not authenticated</code> error.

## Usage acl
```
const { Acl } = require("imicros-acl");
```
```
await broker.createService(Acl, Object.assign({
                settings: { 
                    uri: process.env.NEO4J_URI || "bolt://localhost:7687",
                    user: process.env.NEO4J_USER || "neo4j",
                    password: process.env.NEO4J_PASSSWORD || "neo4j"
                }
            }));
```

### Actions
- requestAccess { forGroupId } => { token }
- verify { token } => { acl }
- addGrant { forGroupId, ruleset } => { result } only for group admins
- removeGrant { forGroupId } => { result } only for group admins

### Rulesets
For ruleset language refer to imicros-rules-compiler.

The ruleset is called with the parameters
- user: ctx.meta.user
- ressource: parameter of call isAuthorized
- action: parameter of call isAuthorized

### Authorization logic
To get access for ressources of a group, an access token must be requested by calling <code>acl.requestAccess</code>.
If the authenticated user in <code>ctx.meta.user.id</code> is member of the requested group <code>forGroupId</code> a token with unrestricted access is issued.
If the authenticated user in <code>ctx.meta.user.id</code> is member of a group where grants are assigned to the requested group <code>forGroupId</code> a token with restricted access is issued.
If the authenticated user in <code>ctx.meta.user.id</code> is neither a member nor a grant to one of his groups is assigned, no access token will be issued.

The retrieved access token must be delivered in the service call context under <code>ctx.meta.acl.accessToken</code>.
This token is verified by the broker middleware.

The final authorization check is made in the mixin method <code>isAuthorized</code>.
In case of restricted access the grant rulesets are called. If no grant solves to <code>acl.result = 'allow'</code> the access is denied.

## Usage acl mixin
```
const { AclMixin } = require("imicros-acl");
```
```
const Service = {
    name: "AnyService",
    settings: {
        acl: {
            service: "acl"  // name of the acl service  
        }
    },
    mixins: [AclMixin],
    actions: {
      ...
```
### Check authorization
```
// call method of acl mixin
await this.isAuthorized({ 
    ctx: ctx,               // context from action handler
    ressource: res,         // JSON representation of the ressource - attributes can be used in grant rules
    action: 'read'          // name of the called action or a specific command like read,write,update'
});
```
The original called action is also available in grant rules under <code>environment.action</code>.
## Usage acl middleware
```
const { AclMiddleware } = require("imicros-acl");
```
```
broker = new ServiceBroker({
    logger: console,
    logLevel: "info",
    middlewares: [AclMiddleware]
});

```
The middleware wraps localAction and verifies a given accesstoken in <code>ctx.meta.acl.accessToken</code> by calling service <code>acl.verify</code>.
If successful verified further acl parameter are set which are used by <code>isAuthorized</code> method of the mixin.

## Docker
### Neo4j - example docker-compose file
```
version: '3'

services:

    neo4j:
        image: neo4j
        container_name: neo4j
    
        # only necessary for access neo4j directly via webinterface 
        ports:
        - "7474:7474"
        - "7687:7687"
        
        #environment:
        #  NEO4J_AUTH: 'none'
        
        volumes:
        - ./data:/data
```
