"use client";

import { useSyncExternalStore } from "react";

const SUBSCRIBE_NOOP = (): (() => void) => () => undefined;
const GET_MOUNTED_SNAPSHOT = (): boolean => true;
const GET_MOUNTED_SERVER_SNAPSHOT = (): boolean => false;

export function useIsMounted(): boolean {
  return useSyncExternalStore(
    SUBSCRIBE_NOOP,
    GET_MOUNTED_SNAPSHOT,
    GET_MOUNTED_SERVER_SNAPSHOT,
  );
}
