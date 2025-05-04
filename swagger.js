const swaggerJsdoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');

const options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Payment App API',
            version: '1.0.0',
            description: 'API documentation for Payment Application',
        },
        servers: [
            {
                url: 'https://localhost:5000/api/v1',
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
            schemas: {
                User: {
                    type: 'object',
                    properties: {
                        _id: {
                            type: 'string',
                            description: 'User ID'
                        },
                        email: {
                            type: 'string',
                            description: 'User email'
                        },
                        name: {
                            type: 'string',
                            description: 'User name'
                        },
                        avatar: {
                            type: 'string',
                            description: 'URL to user avatar'
                        },
                        role: {
                            type: 'string',
                            enum: ['user', 'admin', 'superadmin'],
                            description: 'User role'
                        },
                        isActive: {
                            type: 'boolean',
                            description: 'Account active status'
                        },
                        createdAt: {
                            type: 'string',
                            format: 'date-time',
                            description: 'Account creation date'
                        }
                    }
                },
                Transaction: {
                    type: 'object',
                    properties: {
                        _id: {
                            type: 'string',
                            description: 'Transaction ID'
                        },
                        paymentIntentId: {
                            type: 'string',
                            description: 'Stripe payment intent ID'
                        },
                        userId: {
                            type: 'string',
                            description: 'User ID who made the transaction'
                        },
                        amount: {
                            type: 'number',
                            description: 'Transaction amount in cents'
                        },
                        currency: {
                            type: 'string',
                            description: 'Currency code (e.g., usd)'
                        },
                        status: {
                            type: 'string',
                            description: 'Transaction status'
                        },
                        description: {
                            type: 'string',
                            description: 'Transaction description'
                        },
                        metadata: {
                            type: 'object',
                            description: 'Additional transaction metadata'
                        },
                        createdAt: {
                            type: 'string',
                            format: 'date-time',
                            description: 'Transaction creation date'
                        }
                    }
                }
            }
        },
        security: [{
            bearerAuth: []
        }],
    },
    apis: ['./server.js'], // files containing annotations
};

const specs = swaggerJsdoc(options);

module.exports = (app) => {
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(specs));
};