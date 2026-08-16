import express, {
    Request,
    Response
} from "express";

import bcrypt from "bcryptjs";
import crypto from "crypto";
import path from "path";
import cors from "cors";
import fs from "fs/promises";

import {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} from "@simplewebauthn/server";

import {
    isoUint8Array
} from "@simplewebauthn/server/helpers";

import type {
    RegistrationResponseJSON,
    AuthenticationResponseJSON,
    WebAuthnCredential
} from "@simplewebauthn/server";

import {
    getUsers,
    saveUsers,
    initializeStorage,
    initializeUserStorage,
    getProducts,
    saveProducts,
    Product
} from "./storage";

import {
    authenticate,
    AuthRequest,
    createToken
} from "./auth";


/*
|--------------------------------------------------------------------------
| App
|--------------------------------------------------------------------------
*/

const app = express();


/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
*/

const PORT = 3000;

const RP_NAME = "Mini User API";

/*
| localhost is valid for development.
|
| Production example:
|
| RP_ID = "example.com"
| ORIGIN = "https://example.com"
|
*/

const RP_ID = "localhost";

const ORIGIN = "http://localhost:3000";


/*
|--------------------------------------------------------------------------
| Super Admin
|--------------------------------------------------------------------------
*/

const SUPER_ADMIN_EMAIL =
    "superadmin@example.com";

const SUPER_ADMIN_PASSWORD =
    "SuperAdmin@123";


/*
|--------------------------------------------------------------------------
| Passkey Storage
|--------------------------------------------------------------------------
|
| We keep passkeys and WebAuthn challenges in JSON files for this
| learning project.
|
*/

const DATA_DIR =
    path.join(
        process.cwd(),
        "data"
    );

const PASSKEY_FILE =
    path.join(
        DATA_DIR,
        "passkeys.json"
    );

const CHALLENGE_FILE =
    path.join(
        DATA_DIR,
        "passkey-challenges.json"
    );


/*
|--------------------------------------------------------------------------
| Passkey Types
|--------------------------------------------------------------------------
*/

interface StoredPasskey {
    id: string;

    userId: number;

    publicKey: string;

    counter: number;

    transports?: string[];

    createdAt: string;

    deviceName?: string;
}


interface StoredChallenge {
    id: string;

    type:
    | "registration"
    | "authentication";

    userId?: number;

    challenge: string;

    createdAt: string;
}


/*
|--------------------------------------------------------------------------
| Middleware
|--------------------------------------------------------------------------
*/

app.use(
    cors({
        origin: true,
        credentials: true
    })
);

app.use(
    express.json()
);

app.use(
    express.static(
        path.join(
            process.cwd(),
            "public"
        )
    )
);


/*
|--------------------------------------------------------------------------
| Passkey Storage Helpers
|--------------------------------------------------------------------------
*/

async function initializePasskeyStorage(): Promise<void> {

    await fs.mkdir(
        DATA_DIR,
        {
            recursive: true
        }
    );


    try {

        await fs.access(
            PASSKEY_FILE
        );

    } catch {

        await fs.writeFile(
            PASSKEY_FILE,
            "[]",
            "utf-8"
        );

    }


    try {

        await fs.access(
            CHALLENGE_FILE
        );

    } catch {

        await fs.writeFile(
            CHALLENGE_FILE,
            "[]",
            "utf-8"
        );

    }

}


async function getPasskeys(): Promise<StoredPasskey[]> {

    await initializePasskeyStorage();

    const data =
        await fs.readFile(
            PASSKEY_FILE,
            "utf-8"
        );

    return JSON.parse(
        data
    );
}


async function savePasskeys(
    passkeys: StoredPasskey[]
): Promise<void> {

    await initializePasskeyStorage();

    await fs.writeFile(
        PASSKEY_FILE,

        JSON.stringify(
            passkeys,
            null,
            2
        ),

        "utf-8"
    );

}


async function getChallenges(): Promise<StoredChallenge[]> {

    await initializePasskeyStorage();

    const data =
        await fs.readFile(
            CHALLENGE_FILE,
            "utf-8"
        );

    return JSON.parse(
        data
    );
}


async function saveChallenges(
    challenges: StoredChallenge[]
): Promise<void> {

    await initializePasskeyStorage();

    await fs.writeFile(
        CHALLENGE_FILE,

        JSON.stringify(
            challenges,
            null,
            2
        ),

        "utf-8"
    );

}


/*
|--------------------------------------------------------------------------
| Create Challenge Record
|--------------------------------------------------------------------------
*/

async function createChallenge(
    type:
        | "registration"
        | "authentication",

    challenge: string,

    userId?: number
): Promise<string> {

    const challenges =
        await getChallenges();


    /*
    | Remove challenges older than 5 minutes.
    */

    const now =
        Date.now();

    const validChallenges =
        challenges.filter(
            item =>

                now -
                new Date(
                    item.createdAt
                ).getTime()
                <
                5 * 60 * 1000
        );


    const id =
        crypto
            .randomBytes(32)
            .toString("hex");


    validChallenges.push({

        id,

        type,

        userId,

        challenge,

        createdAt:
            new Date()
                .toISOString()

    });


    await saveChallenges(
        validChallenges
    );


    return id;
}


/*
|--------------------------------------------------------------------------
| Get Challenge
|--------------------------------------------------------------------------
*/

async function getChallenge(
    id: string,

    type:
        | "registration"
        | "authentication"
): Promise<StoredChallenge | null> {

    const challenges =
        await getChallenges();


    const challenge =
        challenges.find(
            item =>

                item.id === id &&
                item.type === type
        );


    return challenge ?? null;
}


/*
|--------------------------------------------------------------------------
| Delete Challenge
|--------------------------------------------------------------------------
*/

async function deleteChallenge(
    id: string
): Promise<void> {

    const challenges =
        await getChallenges();


    await saveChallenges(

        challenges.filter(
            item =>
                item.id !== id
        )

    );

}


/*
|--------------------------------------------------------------------------
| Create Super Admin
|--------------------------------------------------------------------------
*/

async function initializeSuperAdmin(): Promise<void> {

    const users =
        await getUsers();


    const existingAdmin =
        users.find(
            user =>
                user.isSuperAdmin === true
        );


    if (existingAdmin) {

        return;

    }


    const passwordHash =
        await bcrypt.hash(
            SUPER_ADMIN_PASSWORD,
            12
        );


    const superAdmin = {

        id: 1,

        name:
            "Super Admin",

        email:
            SUPER_ADMIN_EMAIL,

        password:
            passwordHash,

        tunnelId:
            "superadmin",

        isSuperAdmin:
            true,

        createdAt:
            new Date()
                .toISOString()

    };


    /*
    |--------------------------------------------------------------------------
    | Shift existing IDs
    |--------------------------------------------------------------------------
    */

    const updatedUsers =
        users.map(
            user => ({

                ...user,

                id:
                    user.id + 1,

                isSuperAdmin:
                    user.isSuperAdmin ??
                    false

            })
        );


    updatedUsers.unshift(
        superAdmin
    );


    await saveUsers(
        updatedUsers
    );


    await initializeUserStorage(
        "superadmin"
    );


    console.log(
        "Super Admin created"
    );

}


/*
|--------------------------------------------------------------------------
| Home
|--------------------------------------------------------------------------
*/

app.get(
    "/",
    (
        req: Request,
        res: Response
    ) => {

        res.json({

            success: true,

            message:
                "Mini User API is running"

        });

    }
);


/*
|--------------------------------------------------------------------------
| Register
|--------------------------------------------------------------------------
*/

app.post(
    "/api/register",
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const {
                name,
                email,
                password
            } = req.body;


            if (
                !name ||
                !email ||
                !password
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Name, email and password are required"

                });

                return;

            }


            if (
                typeof password !== "string" ||
                password.length < 6
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Password must contain at least 6 characters"

                });

                return;

            }


            const normalizedEmail =
                String(
                    email
                ).toLowerCase();


            if (
                normalizedEmail ===
                SUPER_ADMIN_EMAIL
            ) {

                res.status(403).json({

                    success: false,

                    message:
                        "Super Admin cannot register"

                });

                return;

            }


            const users =
                await getUsers();


            const existingUser =
                users.find(
                    user =>
                        user.email
                            .toLowerCase() ===
                        normalizedEmail
                );


            if (existingUser) {

                res.status(409).json({

                    success: false,

                    message:
                        "Email already registered"

                });

                return;

            }


            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );


            const tunnelId =
                crypto
                    .randomBytes(12)
                    .toString("hex");


            const highestId =
                users.reduce(

                    (
                        max,
                        user
                    ) =>

                        Math.max(
                            max,
                            user.id
                        ),

                    0

                );


            const now =
                new Date()
                    .toISOString();


            const user = {

                id:
                    highestId + 1,

                name:
                    String(name),

                email:
                    normalizedEmail,

                password:
                    passwordHash,

                tunnelId,

                isSuperAdmin:
                    false,

                createdAt:
                    now

            };


            users.push(
                user
            );


            await saveUsers(
                users
            );


            await initializeUserStorage(
                tunnelId
            );


            res.status(201).json({

                success: true,

                message:
                    "Registration successful",

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    email:
                        user.email,

                    tunnelId:
                        user.tunnelId,

                    isSuperAdmin:
                        false,

                    createdAt:
                        user.createdAt

                }

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Registration failed"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Password Login
|--------------------------------------------------------------------------
*/

app.post(
    "/api/login",
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const {
                email,
                password
            } = req.body;


            if (
                !email ||
                !password
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Email and password are required"

                });

                return;

            }


            const users =
                await getUsers();


            const normalizedEmail =
                String(
                    email
                ).toLowerCase();


            const user =
                users.find(
                    user =>
                        user.email
                            .toLowerCase() ===
                        normalizedEmail
                );


            if (!user) {

                res.status(401).json({

                    success: false,

                    message:
                        "Invalid email or password"

                });

                return;

            }


            const passwordValid =
                await bcrypt.compare(

                    String(password),

                    user.password

                );


            if (!passwordValid) {

                res.status(401).json({

                    success: false,

                    message:
                        "Invalid email or password"

                });

                return;

            }


            await initializeUserStorage(
                user.tunnelId
            );


            const token =
                createToken(

                    user.id,

                    user.tunnelId,

                    user.isSuperAdmin

                );


            res.json({

                success: true,

                message:
                    "Login successful",

                token,

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    email:
                        user.email,

                    tunnelId:
                        user.tunnelId,

                    isSuperAdmin:
                        user.isSuperAdmin,

                    createdAt:
                        user.createdAt

                }

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Login failed"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| PASSKEY
|--------------------------------------------------------------------------
|
| 1. Registration options
| 2. Registration verification
| 3. Authentication options
| 4. Authentication verification
|
*/


/*
|--------------------------------------------------------------------------
| Passkey Registration Options
|--------------------------------------------------------------------------
*/

app.post(
    "/api/passkey/register/options",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            const users =
                await getUsers();


            const user =
                users.find(
                    user =>
                        user.id ===
                        req.user!.userId
                );


            if (!user) {

                res.status(404).json({

                    success: false,

                    message:
                        "User not found"

                });

                return;

            }


            const passkeys =
                await getPasskeys();


            const userPasskeys =
                passkeys.filter(
                    passkey =>
                        passkey.userId ===
                        user.id
                );


            /*
            | SimpleWebAuthn requires a non-PII user ID.
            | Numeric internal user ID is suitable.
            */

            const userID =
                isoUint8Array
                    .fromUTF8String(
                        String(user.id)
                    );


            const options =
                await generateRegistrationOptions({

                    rpName:
                        RP_NAME,

                    rpID:
                        RP_ID,

                    userID,

                    userName:
                        user.email,

                    userDisplayName:
                        user.name,

                    attestationType:
                        "none",

                    excludeCredentials:
                        userPasskeys.map(
                            passkey => ({

                                id:
                                    passkey.id,

                                transports:
                                    passkey.transports as any

                            })
                        ),

                    authenticatorSelection: {

                        residentKey:
                            "required",

                        userVerification:
                            "required"

                    }

                });


            /*
            | Store challenge server-side.
            */

            const challengeId =
                await createChallenge(

                    "registration",

                    options.challenge,

                    user.id

                );


            res.json({

                success: true,

                challengeId,

                options

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to generate passkey registration options"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Passkey Registration Verification
|--------------------------------------------------------------------------
*/

app.post(
    "/api/passkey/register/verify",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            const {
                challengeId,
                response
            } = req.body as {

                challengeId:
                string;

                response:
                RegistrationResponseJSON;

            };


            if (
                !challengeId ||
                !response
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "challengeId and response are required"

                });

                return;

            }


            const challenge =
                await getChallenge(

                    challengeId,

                    "registration"

                );


            if (!challenge) {

                res.status(400).json({

                    success: false,

                    message:
                        "Invalid or expired challenge"

                });

                return;

            }


            if (
                challenge.userId !==
                req.user!.userId
            ) {

                res.status(403).json({

                    success: false,

                    message:
                        "Challenge does not belong to this user"

                });

                return;

            }


            const verification =
                await verifyRegistrationResponse({

                    response,

                    expectedChallenge:
                        challenge.challenge,

                    expectedOrigin:
                        ORIGIN,

                    expectedRPID:
                        RP_ID,

                    requireUserVerification:
                        true

                });


            await deleteChallenge(
                challengeId
            );


            if (
                !verification.verified ||
                !verification.registrationInfo
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Passkey registration failed"

                });

                return;

            }


            const {
                credential,
                credentialDeviceType,
                credentialBackedUp
            } =
                verification.registrationInfo;


            const passkeys =
                await getPasskeys();


            const existingPasskey =
                passkeys.find(
                    passkey =>
                        passkey.id ===
                        credential.id
                );


            if (existingPasskey) {

                res.status(409).json({

                    success: false,

                    message:
                        "Passkey already registered"

                });

                return;

            }


            const storedPasskey:
                StoredPasskey = {

                id:
                    credential.id,

                userId:
                    req.user!.userId,

                publicKey:
                    Buffer.from(
                        credential.publicKey
                    ).toString(
                        "base64"
                    ),

                counter:
                    Number(
                        credential.counter
                    ),

                transports:
                    response.response
                        .transports,

                createdAt:
                    new Date()
                        .toISOString()

            };


            passkeys.push(
                storedPasskey
            );


            await savePasskeys(
                passkeys
            );


            res.json({

                success: true,

                verified: true,

                message:
                    "Passkey registered successfully",

                credentialDeviceType,

                credentialBackedUp

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(400).json({

                success: false,

                message:
                    "Passkey registration failed"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Passkey Authentication Options
|--------------------------------------------------------------------------
|
| This route does NOT use authenticate because the user is not logged in.
|
*/

app.post(
    "/api/passkey/login/options",
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const options =
                await generateAuthenticationOptions({

                    rpID:
                        RP_ID,

                    userVerification:
                        "required"

                });


            const challengeId =
                await createChallenge(

                    "authentication",

                    options.challenge

                );


            res.json({

                success: true,

                challengeId,

                options

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to generate passkey login options"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Passkey Authentication Verification
|--------------------------------------------------------------------------
*/

app.post(
    "/api/passkey/login/verify",
    async (
        req: Request,
        res: Response
    ) => {

        try {

            const {
                challengeId,
                response
            } = req.body as {

                challengeId:
                string;

                response:
                AuthenticationResponseJSON;

            };


            if (
                !challengeId ||
                !response
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "challengeId and response are required"

                });

                return;

            }


            const challenge =
                await getChallenge(

                    challengeId,

                    "authentication"

                );


            if (!challenge) {

                res.status(400).json({

                    success: false,

                    message:
                        "Invalid or expired challenge"

                });

                return;

            }


            /*
            | Find passkey by credential ID.
            */

            const passkeys =
                await getPasskeys();


            const passkey =
                passkeys.find(
                    item =>
                        item.id ===
                        response.id
                );


            if (!passkey) {

                await deleteChallenge(
                    challengeId
                );


                res.status(401).json({

                    success: false,

                    message:
                        "Passkey not found"

                });

                return;

            }


            const credential:
                WebAuthnCredential = {

                id:
                    passkey.id,

                publicKey:
                    new Uint8Array(

                        Buffer.from(
                            passkey.publicKey,
                            "base64"
                        )

                    ),

                counter:
                    passkey.counter,

                transports:
                    passkey.transports as any

            };


            const verification =
                await verifyAuthenticationResponse({

                    response,

                    expectedChallenge:
                        challenge.challenge,

                    expectedOrigin:
                        ORIGIN,

                    expectedRPID:
                        RP_ID,

                    credential,

                    requireUserVerification:
                        true

                });


            await deleteChallenge(
                challengeId
            );


            if (
                !verification.verified
            ) {

                res.status(401).json({

                    success: false,

                    message:
                        "Passkey authentication failed"

                });

                return;

            }


            /*
            |--------------------------------------------------------------------------
            | Update WebAuthn counter
            |--------------------------------------------------------------------------
            */

            passkey.counter =
                verification
                    .authenticationInfo
                    .newCounter;


            await savePasskeys(
                passkeys
            );


            /*
            |--------------------------------------------------------------------------
            | Find Application User
            |--------------------------------------------------------------------------
            */

            const users =
                await getUsers();


            const user =
                users.find(
                    user =>
                        user.id ===
                        passkey.userId
                );


            if (!user) {

                res.status(401).json({

                    success: false,

                    message:
                        "User associated with passkey not found"

                });

                return;

            }


            await initializeUserStorage(
                user.tunnelId
            );


            /*
            |--------------------------------------------------------------------------
            | Create Existing JWT
            |--------------------------------------------------------------------------
            */

            const token =
                createToken(

                    user.id,

                    user.tunnelId,

                    user.isSuperAdmin

                );


            res.json({

                success: true,

                message:
                    "Passkey login successful",

                token,

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    email:
                        user.email,

                    tunnelId:
                        user.tunnelId,

                    isSuperAdmin:
                        user.isSuperAdmin,

                    createdAt:
                        user.createdAt

                }

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(401).json({

                success: false,

                message:
                    "Passkey authentication failed"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| List My Passkeys
|--------------------------------------------------------------------------
*/

app.get(
    "/api/passkeys",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            const passkeys =
                await getPasskeys();


            const userPasskeys =
                passkeys
                    .filter(
                        passkey =>
                            passkey.userId ===
                            req.user!.userId
                    )
                    .map(
                        passkey => ({

                            id:
                                passkey.id,

                            createdAt:
                                passkey.createdAt,

                            deviceName:
                                passkey.deviceName ??
                                null,

                            transports:
                                passkey.transports ??
                                []

                        })
                    );


            res.json({

                success: true,

                passkeys:
                    userPasskeys

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to get passkeys"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Delete My Passkey
|--------------------------------------------------------------------------
*/

app.delete(
    "/api/passkeys/:id",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            const passkeyId =
                req.params.id;


            const passkeys =
                await getPasskeys();


            const passkey =
                passkeys.find(
                    item =>
                        item.id ===
                        passkeyId &&
                        item.userId ===
                        req.user!.userId
                );


            if (!passkey) {

                res.status(404).json({

                    success: false,

                    message:
                        "Passkey not found"

                });

                return;

            }


            const updatedPasskeys =
                passkeys.filter(
                    item =>
                        !(
                            item.id ===
                            passkeyId &&
                            item.userId ===
                            req.user!.userId
                        )
                );


            await savePasskeys(
                updatedPasskeys
            );


            res.json({

                success: true,

                message:
                    "Passkey deleted successfully"

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to delete passkey"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/

app.post(
    "/api/logout",
    authenticate,
    (
        req: AuthRequest,
        res: Response
    ) => {

        res.json({

            success: true,

            message:
                "Logout successful"

        });

    }
);


/*
|--------------------------------------------------------------------------
| Current User
|--------------------------------------------------------------------------
*/

app.get(
    "/api/me",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            const users =
                await getUsers();


            const user =
                users.find(
                    user =>
                        user.id ===
                        req.user!.userId
                );


            if (!user) {

                res.status(404).json({

                    success: false,

                    message:
                        "User not found"

                });

                return;

            }


            res.json({

                success: true,

                user: {

                    id:
                        user.id,

                    name:
                        user.name,

                    email:
                        user.email,

                    tunnelId:
                        user.tunnelId,

                    isSuperAdmin:
                        user.isSuperAdmin,

                    createdAt:
                        user.createdAt

                }

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to get user"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Create Product
|--------------------------------------------------------------------------
*/

app.post(
    "/api/products",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            if (
                req.user!.isSuperAdmin
            ) {

                res.status(403).json({

                    success: false,

                    message:
                        "Super Admin cannot create products"

                });

                return;

            }


            const {
                name,
                price
            } = req.body;


            if (
                !name ||
                price === undefined
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Product name and price are required"

                });

                return;

            }


            const numericPrice =
                Number(price);


            if (
                !Number.isFinite(
                    numericPrice
                ) ||
                numericPrice < 0
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Invalid product price"

                });

                return;

            }


            const tunnelId =
                req.user!.tunnelId;


            const products =
                await getProducts(
                    tunnelId
                );


            const highestProductId =
                products.reduce(

                    (
                        max,
                        product
                    ) =>

                        Math.max(
                            max,
                            product.id
                        ),

                    0

                );


            const now =
                new Date()
                    .toISOString();


            const product:
                Product = {

                id:
                    highestProductId + 1,

                name:
                    String(name),

                price:
                    numericPrice,

                createdAt:
                    now,

                updatedAt:
                    now,

                deletedAt:
                    null

            };


            products.push(
                product
            );


            await saveProducts(
                tunnelId,
                products
            );


            res.status(201).json({

                success: true,

                message:
                    "Product created successfully",

                product

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to create product"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Get My Active Products
|--------------------------------------------------------------------------
*/

app.get(
    "/api/products",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            if (
                req.user!.isSuperAdmin
            ) {

                res.status(403).json({

                    success: false,

                    message:
                        "Use the admin products endpoint"

                });

                return;

            }


            const products =
                await getProducts(
                    req.user!.tunnelId
                );


            const activeProducts =
                products.filter(
                    product =>
                        product.deletedAt ===
                        null
                );


            res.json({

                success: true,

                products:
                    activeProducts

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to get products"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Update Product
|--------------------------------------------------------------------------
*/

app.put(
    "/api/products/:id",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            if (
                req.user!.isSuperAdmin
            ) {

                res.status(403).json({

                    success: false,

                    message:
                        "Super Admin cannot update products"

                });

                return;

            }


            const productId =
                Number(
                    req.params.id
                );


            if (
                !Number.isInteger(
                    productId
                )
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Invalid product ID"

                });

                return;

            }


            const {
                name,
                price
            } = req.body;


            const products =
                await getProducts(
                    req.user!.tunnelId
                );


            const product =
                products.find(
                    product =>
                        product.id ===
                        productId
                );


            if (!product) {

                res.status(404).json({

                    success: false,

                    message:
                        "Product not found"

                });

                return;

            }


            if (
                product.deletedAt !==
                null
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Deleted product cannot be updated"

                });

                return;

            }


            if (
                name !== undefined
            ) {

                if (
                    String(name)
                        .trim()
                        .length === 0
                ) {

                    res.status(400).json({

                        success: false,

                        message:
                            "Product name cannot be empty"

                    });

                    return;

                }


                product.name =
                    String(name);

            }


            if (
                price !== undefined
            ) {

                const numericPrice =
                    Number(price);


                if (
                    !Number.isFinite(
                        numericPrice
                    ) ||
                    numericPrice < 0
                ) {

                    res.status(400).json({

                        success: false,

                        message:
                            "Invalid product price"

                    });

                    return;

                }


                product.price =
                    numericPrice;

            }


            product.updatedAt =
                new Date()
                    .toISOString();


            await saveProducts(

                req.user!.tunnelId,

                products

            );


            res.json({

                success: true,

                message:
                    "Product updated successfully",

                product

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to update product"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Soft Delete Product
|--------------------------------------------------------------------------
*/

app.delete(
    "/api/products/:id",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            if (
                req.user!.isSuperAdmin
            ) {

                res.status(403).json({

                    success: false,

                    message:
                        "Super Admin cannot delete products"

                });

                return;

            }


            const productId =
                Number(
                    req.params.id
                );


            const products =
                await getProducts(
                    req.user!.tunnelId
                );


            const product =
                products.find(
                    product =>
                        product.id ===
                        productId
                );


            if (!product) {

                res.status(404).json({

                    success: false,

                    message:
                        "Product not found"

                });

                return;

            }


            if (
                product.deletedAt !==
                null
            ) {

                res.status(400).json({

                    success: false,

                    message:
                        "Product already deleted"

                });

                return;

            }


            const now =
                new Date()
                    .toISOString();


            product.deletedAt =
                now;


            product.updatedAt =
                now;


            await saveProducts(

                req.user!.tunnelId,

                products

            );


            res.json({

                success: true,

                message:
                    "Product deleted successfully",

                product

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to delete product"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| Super Admin - All Products
|--------------------------------------------------------------------------
*/

app.get(
    "/api/admin/products",
    authenticate,
    async (
        req: AuthRequest,
        res: Response
    ) => {

        try {

            if (
                !req.user!.isSuperAdmin
            ) {

                res.status(403).json({

                    success: false,

                    message:
                        "Super Admin access required"

                });

                return;

            }


            const users =
                await getUsers();


            const allProducts:
                any[] = [];


            for (
                const user of users
            ) {

                if (
                    user.isSuperAdmin
                ) {

                    continue;

                }


                const products =
                    await getProducts(
                        user.tunnelId
                    );


                for (
                    const product of products
                ) {

                    allProducts.push({

                        productId:
                            product.id,

                        productName:
                            product.name,

                        price:
                            product.price,

                        createdAt:
                            product.createdAt,

                        updatedAt:
                            product.updatedAt,

                        deletedAt:
                            product.deletedAt,

                        status:
                            product.deletedAt ===
                                null
                                ? "active"
                                : "deleted",

                        userId:
                            user.id,

                        userName:
                            user.name,

                        userEmail:
                            user.email,

                        tunnelId:
                            user.tunnelId

                    });

                }

            }


            allProducts.sort(

                (
                    a,
                    b
                ) =>

                    new Date(
                        b.updatedAt
                    ).getTime()
                    -
                    new Date(
                        a.updatedAt
                    ).getTime()

            );


            res.json({

                success: true,

                total:
                    allProducts.length,

                products:
                    allProducts

            });


        } catch (error) {

            console.error(
                error
            );


            res.status(500).json({

                success: false,

                message:
                    "Failed to get all products"

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| 404
|--------------------------------------------------------------------------
*/

app.use(

    (
        req: Request,
        res: Response
    ) => {

        res.status(404).json({

            success: false,

            message:
                "Route not found",

            path:
                req.originalUrl

        });

    }

);


/*
|--------------------------------------------------------------------------
| Start Server
|--------------------------------------------------------------------------
*/

async function startServer(): Promise<void> {

    try {

        await initializeStorage();

        await initializePasskeyStorage();

        await initializeSuperAdmin();


        app.listen(

            PORT,

            () => {

                console.log("");

                console.log(
                    "======================================"
                );

                console.log(
                    `Server running at http://localhost:${PORT}`
                );

                console.log(
                    "======================================"
                );

                console.log("");

                console.log(
                    "Super Admin Credentials"
                );

                console.log(
                    `Email: ${SUPER_ADMIN_EMAIL}`
                );

                console.log(
                    `Password: ${SUPER_ADMIN_PASSWORD}`
                );

                console.log("");

            }

        );


    } catch (error) {

        console.error(
            "Server startup failed:",
            error
        );

        process.exit(1);

    }

}


startServer();