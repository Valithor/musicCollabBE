import { Request, Response } from 'express';
import { Session } from "express-session";
import { Redis } from "ioredis";
import { createUserLoader } from './utils/createUserLoader';
import { createUserRoomLoader } from './utils/createUserRoomLoader';

export type MyContext = {
    req: Request &  { session?: Session & { userId?: number } };
    redis: Redis;
    payload?: { userId: number };
    res: Response;
    userLoader: ReturnType<typeof createUserLoader>;
    userRoomLoader: ReturnType<typeof createUserRoomLoader>;
}

export type Tracks = {
    track: any;
    trackId: any;
}