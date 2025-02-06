import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';


import routes from './routes';
import { config } from './config/environment.config';
import { logger } from './utils/logger.utils';
import { errorHandler } from './middlewares/error.middleware';

const app: Application = express();

// Security middleware
app.use(helmet());
app.use(cors());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: config.rateLimit.window * 60 * 1000,
    max: config.rateLimit.max
});
app.use(limiter);

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req: Request, _res: Response, next: NextFunction) =>
{
    logger.info(`${req.method} ${req.url}`);
    next();
});

// Routes
app.use('/api/v1', routes);

// Error handling
app.use(errorHandler);

export default app;
