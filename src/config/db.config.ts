import { MongoClient } from 'mongodb';

import { config } from './environment.config';
import { logger } from '@/utils/logger.utils';

let client: MongoClient;

export const connectDB = async () =>
{
    try {
        client = new MongoClient(config.mongodb.uri!);
        await client.connect();
        logger.info('MongoDB connected successfully');
    } catch (error) {
        logger.error('MongoDB connection error:', error);
        process.exit(1);
    }
};

export const getDB = () =>
{
    if (!client) {
        throw new Error('Database not initialized');
    }
    return client.db();
};
