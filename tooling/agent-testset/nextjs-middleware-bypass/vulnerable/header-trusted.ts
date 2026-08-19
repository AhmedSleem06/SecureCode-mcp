import { NextRequest, NextResponse } from 'next/server';

export function middleware(req: NextRequest) {
    const authHeader = req.headers.get('x-authenticated');
    if (authHeader === 'true') {
        return NextResponse.next();
    }
    return NextResponse.redirect(new URL('/login', req.url));
}

export const config = {
    matcher: ['/api/:path*'],
};
