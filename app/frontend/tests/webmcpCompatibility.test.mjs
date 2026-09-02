import assert from "node:assert/strict";
import test from "node:test";

import { listExistingWebMcpTools } from "../src/webmcpCompatibility.ts";

const tools = ["existing_tool", { name: "structured_tool" }];

test("accepts a synchronous getTools result", async () => {
  assert.deepEqual(await listExistingWebMcpTools(() => tools), tools);
});

test("accepts an asynchronous getTools result", async () => {
  assert.deepEqual(await listExistingWebMcpTools(async () => tools), tools);
});

test("falls back to an empty list when getTools is unavailable", async () => {
  assert.deepEqual(await listExistingWebMcpTools(), []);
});

test("falls back to an empty list when getTools throws", async () => {
  assert.deepEqual(await listExistingWebMcpTools(() => {
    throw new TypeError("browser implementation failure");
  }), []);
});

test("falls back to an empty list when getTools rejects", async () => {
  assert.deepEqual(await listExistingWebMcpTools(
    () => Promise.reject(new TypeError("browser implementation failure")),
  ), []);
});
