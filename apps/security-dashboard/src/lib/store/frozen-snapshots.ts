export const EMPTY_SNAPSHOT = Object.freeze([]) as readonly never[];

export function asMutableSnapshot<T>(snapshot: readonly T[]): T[] {
  return snapshot as T[];
}
