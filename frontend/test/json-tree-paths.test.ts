import { expect, it } from "vitest";

function childPath(parent: string, segment: string): string {
  return parent + "/" + JSON.stringify(segment);
}

it("disambiguates dotted-key vs nested-object paths", () => {
  const dotted = childPath("$", "a.b");
  const nestedA = childPath("$", "a");
  const nested = childPath(nestedA, "b");

  expect(dotted).not.toBe(nested);
});

it("disambiguates space, slash, and quote keys", () => {
  expect(childPath("$", "a b")).not.toBe(childPath("$", "a/b"));
  expect(childPath("$", "a\"b")).not.toBe(childPath("$", "ab"));
});
