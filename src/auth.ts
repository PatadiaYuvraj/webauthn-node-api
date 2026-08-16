import jwt from "jsonwebtoken";

import {
    Request,
    Response,
    NextFunction
} from "express";


/*
|--------------------------------------------------------------------------
| JWT Configuration
|--------------------------------------------------------------------------
*/

const JWT_SECRET =
    process.env.JWT_SECRET ||
    "mini-user-api-secret-change-this";


/*
|--------------------------------------------------------------------------
| Auth User
|--------------------------------------------------------------------------
*/

export interface AuthUser {

    userId: number;

    tunnelId: string;

    isSuperAdmin: boolean;

}


/*
|--------------------------------------------------------------------------
| Auth Request
|--------------------------------------------------------------------------
*/

export interface AuthRequest
    extends Request {

    user?: AuthUser;

}


/*
|--------------------------------------------------------------------------
| JWT Payload
|--------------------------------------------------------------------------
*/

export interface JwtPayload {

    userId: number;

    tunnelId: string;

    isSuperAdmin: boolean;

}


/*
|--------------------------------------------------------------------------
| Create JWT
|--------------------------------------------------------------------------
*/

export function createToken(

    userId: number,

    tunnelId: string,

    isSuperAdmin: boolean

): string {

    const payload: JwtPayload = {

        userId,

        tunnelId,

        isSuperAdmin

    };


    return jwt.sign(

        payload,

        JWT_SECRET,

        {

            expiresIn: "1h"

        }

    );

}


/*
|--------------------------------------------------------------------------
| Verify JWT
|--------------------------------------------------------------------------
*/

export function verifyToken(
    token: string
): JwtPayload | null {

    try {

        return jwt.verify(

            token,

            JWT_SECRET

        ) as JwtPayload;

    } catch {

        return null;

    }

}


/*
|--------------------------------------------------------------------------
| Authentication Middleware
|--------------------------------------------------------------------------
*/

export function authenticate(

    req: AuthRequest,

    res: Response,

    next: NextFunction

): void {

    const authorization =
        req.headers.authorization;


    /*
    |--------------------------------------------------------------------------
    | Authorization Header
    |--------------------------------------------------------------------------
    */

    if (!authorization) {

        res.status(401).json({

            success: false,

            message:
                "Authorization token required"

        });

        return;

    }


    /*
    |--------------------------------------------------------------------------
    | Bearer Token
    |--------------------------------------------------------------------------
    */

    const parts =
        authorization.split(" ");


    if (

        parts.length !== 2 ||

        parts[0] !== "Bearer" ||

        !parts[1]

    ) {

        res.status(401).json({

            success: false,

            message:
                "Invalid authorization format"

        });

        return;

    }


    const token =
        parts[1];


    /*
    |--------------------------------------------------------------------------
    | Verify JWT
    |--------------------------------------------------------------------------
    */

    const decoded =
        verifyToken(
            token
        );


    if (!decoded) {

        res.status(401).json({

            success: false,

            message:
                "Invalid or expired token"

        });

        return;

    }


    /*
    |--------------------------------------------------------------------------
    | Attach User To Request
    |--------------------------------------------------------------------------
    */

    req.user = {

        userId:
            decoded.userId,

        tunnelId:
            decoded.tunnelId,

        isSuperAdmin:
            decoded.isSuperAdmin

    };


    next();

}