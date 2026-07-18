import { callProvider, AiConfig } from "../src/ai/provider";
let last: any = {};
(global as any).fetch = async (url: string, opts: any) => {
  last = { url, headers: opts.headers, body: JSON.parse(opts.body) };
  const anth = String(url).includes("/v1/messages");
  return { ok: true, json: async () => anth ? { content: [{ type: "text", text: "ok" }] } : { choices: [{ message: { content: "ok" } }] } } as any;
};
const base = { maxTokens: 512, azureApiVersion: "2024-06-01" };
const cases: AiConfig[] = [
  { provider: "anthropic", model: "claude-opus-4-8", baseUrl: "https://api.anthropic.com", ...base },
  { provider: "openai", model: "gpt-4o", baseUrl: "https://api.openai.com/v1", ...base },
  { provider: "azure", model: "my-deploy", baseUrl: "https://acme.openai.azure.com", ...base },
  { provider: "ollama", model: "llama3.1", baseUrl: "http://localhost:11434/v1", ...base },
];
(async () => {
  for (const c of cases) {
    const key = c.provider === "ollama" ? "" : "KEY123";
    await callProvider(c, key, "sys", "user");
    const h = last.headers;
    const auth = h["authorization"] || h["x-api-key"] || h["api-key"] || "(none)";
    console.log(`${c.provider.padEnd(10)} -> ${last.url}`);
    console.log(`${" ".repeat(13)} auth: ${auth}`);
  }
})();
