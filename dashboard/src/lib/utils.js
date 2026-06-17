import {clsx} from "clsx";
import {twMerge} from "tailwind-merge"

export function cn(...inputs) {
    return twMerge(clsx(inputs));
}

export const ERR_SERVER_CONNECTION = "Could not connect to the server";
