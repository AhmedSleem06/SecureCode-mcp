import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';

const prisma = new PrismaClient();

export async function searchUsers(req: Request, res: Response) {
    const q = req.query.q as string;
    const results = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE name LIKE '%${q}%'`);
    res.json(results);
}
