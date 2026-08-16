import {
    mkdir,
    readFile,
    writeFile
} from "fs/promises";

import path from "path";


const DATA_DIR =
    path.join(
        process.cwd(),
        "data"
    );


const USERS_FILE =
    path.join(
        DATA_DIR,
        "users.json"
    );


export interface User {

    id: number;

    name: string;

    email: string;

    password: string;

    tunnelId: string;

    isSuperAdmin: boolean;

    createdAt: string;

}


export interface Product {

    id: number;

    name: string;

    price: number;

    createdAt: string;

    updatedAt: string;

    deletedAt: string | null;

}


/*
|--------------------------------------------------------------------------
| Initialize Main Storage
|--------------------------------------------------------------------------
*/

export async function initializeStorage(): Promise<void> {

    await mkdir(
        DATA_DIR,
        {
            recursive: true
        }
    );


    try {

        await readFile(
            USERS_FILE,
            "utf-8"
        );

    } catch {

        await writeFile(
            USERS_FILE,
            "[]",
            "utf-8"
        );

    }

}


/*
|--------------------------------------------------------------------------
| Users
|--------------------------------------------------------------------------
*/

export async function getUsers(): Promise<User[]> {

    const data =
        await readFile(
            USERS_FILE,
            "utf-8"
        );


    return JSON.parse(data);

}


export async function saveUsers(
    users: User[]
): Promise<void> {

    await writeFile(

        USERS_FILE,

        JSON.stringify(
            users,
            null,
            4
        ),

        "utf-8"

    );

}


/*
|--------------------------------------------------------------------------
| User Directory
|--------------------------------------------------------------------------
*/

export function getUserDirectory(
    tunnelId: string
): string {

    return path.join(
        DATA_DIR,
        tunnelId
    );

}


/*
|--------------------------------------------------------------------------
| Products File
|--------------------------------------------------------------------------
*/

export function getProductsFile(
    tunnelId: string
): string {

    return path.join(

        getUserDirectory(
            tunnelId
        ),

        "products.json"

    );

}


/*
|--------------------------------------------------------------------------
| Initialize User Storage
|--------------------------------------------------------------------------
*/

export async function initializeUserStorage(
    tunnelId: string
): Promise<void> {

    const userDirectory =
        getUserDirectory(
            tunnelId
        );


    await mkdir(
        userDirectory,
        {
            recursive: true
        }
    );


    const productsFile =
        getProductsFile(
            tunnelId
        );


    try {

        await readFile(
            productsFile,
            "utf-8"
        );

    } catch {

        await writeFile(
            productsFile,
            "[]",
            "utf-8"
        );

    }

}


/*
|--------------------------------------------------------------------------
| Get Products
|--------------------------------------------------------------------------
*/

export async function getProducts(
    tunnelId: string
): Promise<Product[]> {

    const productsFile =
        getProductsFile(
            tunnelId
        );


    try {

        const data =
            await readFile(
                productsFile,
                "utf-8"
            );


        return JSON.parse(data);

    } catch {

        await initializeUserStorage(
            tunnelId
        );


        return [];

    }

}


/*
|--------------------------------------------------------------------------
| Save Products
|--------------------------------------------------------------------------
*/

export async function saveProducts(
    tunnelId: string,
    products: Product[]
): Promise<void> {

    await initializeUserStorage(
        tunnelId
    );


    await writeFile(

        getProductsFile(
            tunnelId
        ),

        JSON.stringify(
            products,
            null,
            4
        ),

        "utf-8"

    );

}