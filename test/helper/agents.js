const { v4: uuid } = require("uuid");

const serviceId = uuid();

const Token = {
    serviceToken: "this is the service token"
};

// mock service agents
const Agents = {
    // name: "v1.agents",
    name: "agents",
    actions: {
        verify: {
            params: {
                serviceToken: { type: "string" }
            },
            async handler({ params: { serviceToken }}) {
                this.logger.info("agents.verify called", { serviceToken } );
                if (serviceToken) {
                    this.logger.info("agents.verify returned", { serviceId } );
                    return { serviceId }; 
                }
                return false;
            }
        }
    }
};

module.exports = {
    serviceId,
    Token,
    Agents
};
