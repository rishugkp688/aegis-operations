export type ListedWebMcpTool = string | { name?: string };

export type GetWebMcpTools = () =>
  | ListedWebMcpTool[]
  | PromiseLike<ListedWebMcpTool[]>;

/**
 * WebMCP implementations have exposed getTools() as both a synchronous list
 * and a Promise. Normalize either shape and keep an optional/failed discovery
 * call from preventing registration of this application's tools.
 */
export async function listExistingWebMcpTools(
  getTools?: GetWebMcpTools,
): Promise<ListedWebMcpTool[]> {
  try {
    return await Promise.resolve(getTools?.() ?? []);
  } catch {
    return [];
  }
}
