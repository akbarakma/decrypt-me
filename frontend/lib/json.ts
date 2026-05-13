export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };

export type JsonParseResult =
  | {
      ok: true;
      value: JsonValue;
      formatted: string;
    }
  | {
      ok: false;
    };

export function parseJsonResult(text: string): JsonParseResult {
  try {
    const value = JSON.parse(text) as JsonValue;
    return {
      ok: true,
      value,
      formatted: JSON.stringify(value, null, 2)
    };
  } catch {
    return { ok: false };
  }
}
