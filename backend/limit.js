import rateLimit from "express-rate-limit";
export const authLimiter = rateLimit({ windowMs: 60_000, max: 30, standardHeaders: true });
