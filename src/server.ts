import 'tsconfig-paths/register';
import { config } from './config/environment.config';
import app from './app';
import { connectDB } from './config/db.config';
import { logger } from './utils/logger.utils';


const startServer = async () =>
{
    try {
        // Connect to MongoDB
        await connectDB();

        app.listen(config.port, () =>
        {
            logger.info(`Server running on port ${config.port} in ${config.nodeEnv} mode`);
        });
    } catch (error) {
        logger.error('Failed to start server:', error);
        process.exit(1);
    }
};

startServer();
