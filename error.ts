import logger from '../config/logger.ts';
import { Prisma } from '../generated/prisma/index.js';
import ApiError from '../utils/ApiError.ts';
import { ErrorRequestHandler } from 'express';
import httpStatus from 'http-status';

export const errorConverter: ErrorRequestHandler = (err, req, res, next) => {
    let error = err;
    if (!(error instanceof ApiError)) {
        const statusCode =
            error.statusCode || error instanceof Prisma.PrismaClientKnownRequestError
                ? httpStatus.BAD_REQUEST
                : httpStatus.INTERNAL_SERVER_ERROR;
        const message = error.message || httpStatus[statusCode];
        error = new ApiError(statusCode, message, false, err.stack);
    }
    next(error);
};

// eslint-disable-next-line @typescript-eslint/no-unused-vars
export const errorHandler: ErrorRequestHandler = (err, req, res, next) => {
    let { statusCode, message } = err;
    if (process.env.ENV === 'prod' && !err.isOperational) {
        statusCode = httpStatus.INTERNAL_SERVER_ERROR;
        message = httpStatus[httpStatus.INTERNAL_SERVER_ERROR];
    }

    res.locals.errorMessage = err.message;
    const response = {
        code: statusCode,
        message,
        ...(process.env.ENV !== 'prod' && { stack: err.stack })
    };

    logger.error(err);

    res.status(statusCode).send(response);
};
