import { expect, test } from "bun:test";

test("public TypeScript source uses type aliases rather than interfaces", async () => {
  const glob = new Bun.Glob("src/**/*.ts");
  for await (const path of glob.scan(".")) {
    const source = await Bun.file(path).text();
    expect(source).not.toMatch(/\b(?:export\s+)?interface\s+[A-Za-z_$]/u);
  }
});
