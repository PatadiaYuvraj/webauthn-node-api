import fs from "fs/promises";
import path from "path";

export interface Passkey {
    credentialID: string;
    userId: number;
    publicKey: string;
    counter: number;
    transports?: string[];
}

const DATA_DIR = path.join(process.cwd(), "data");
const PASSKEY_FILE = path.join(DATA_DIR, "passkeys.json");

export async function initializePasskeyStorage(): Promise<void> {
    await fs.mkdir(DATA_DIR, { recursive: true });

    try {
        await fs.access(PASSKEY_FILE);
    } catch {
        await fs.writeFile(
            PASSKEY_FILE,
            "[]",
            "utf-8"
        );
    }
}

export async function getPasskeys(): Promise<Passkey[]> {
    await initializePasskeyStorage();

    const data = await fs.readFile(
        PASSKEY_FILE,
        "utf-8"
    );

    return JSON.parse(data);
}

export async function savePasskeys(
    passkeys: Passkey[]
): Promise<void> {
    await initializePasskeyStorage();

    await fs.writeFile(
        PASSKEY_FILE,
        JSON.stringify(passkeys, null, 2),
        "utf-8"
    );
}