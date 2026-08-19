import { PrismaClient } from '@prisma/client';
import { Request, Response } from 'express';

const prisma = new PrismaClient();

export async function searchUsers(req: Request, res: Response) {
    const q = req.query.q as string;
    const results = await prisma.user.findMany({
        where: { name: { contains: q } },
    });
    res.json(results);
}
