#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";
import { v4 as uuidv4 } from "uuid";

interface ScanResult {
  id: string;
  target: string;
  progress: number;
  status: "pending" | "running" | "completed" | "failed" | "canceled";
  findings: any[];
  process?: any;
}

const MAX_CONCURRENT_SCANS = 5;
const scans: { [id: string]: ScanResult } = {};

const server = new Server(
  {
    name: "nuclei-server",
    version: "0.1.0",
  },
  {
    capabilities: {
      resources: {},
      tools: {},
    },
  }
);

server.setRequestHandler(ListResourcesRequestSchema, async () => {
  return {
    resources: Object.values(scans).map((scan) => ({
      uri: `scan:///${scan.id}`,
      mimeType: "application/json",
      name: `Scan ${scan.id} - ${scan.target}`,
      description: `Scan results for ${scan.target}`,
    })),
  };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const scanId = request.params.uri?.split("/").pop()?.trim();
  if (!scanId || !scans[scanId]) {
    throw new Error(`Invalid or missing scan ID: ${scanId}`);
  }
  const scan = scans[scanId];

  return {
    contents: [
      {
        uri: request.params.uri,
        mimeType: "application/json",
        text: JSON.stringify(scan, null, 2),
      },
    ],
  };
});

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "start_scan",
        description: "Start a new nuclei scan",
        inputSchema: {
          type: "object",
          properties: {
            target: { type: "string", description: "Target URL or IP address" },
            template: { type: "string", description: "Template to use for scanning" },
            rateLimit: { type: "number", description: "Rate limit per second" },
            templatesDir: { type: "string", description: "Directory with templates" },
            severity: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
            timeout: { type: "number", description: "Timeout in seconds" },
            concurrency: { type: "number", description: "Concurrent requests" },
            proxyUrl: {
              type: "string",
              description: "Proxy URL (e.g., socks5://127.0.0.1:1080)"
            },
            proxyType: {
              type: "string",
              enum: ["http", "socks5"]
            },
          },
          required: ["target"],
        },
      },
      {
        name: "cancel_scan",
        description: "Cancel a running scan",
        inputSchema: {
          type: "object",
          properties: {
            scanId: { type: "string", description: "Scan ID to cancel" },
          },
          required: ["scanId"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === "start_scan") {
    const activeScans = Object.values(scans).filter(
      (scan) => scan.status === "running"
    ).length;
    if (activeScans >= MAX_CONCURRENT_SCANS) {
      return {
        content: [
          {
            type: "text",
            text: `Reached maximum concurrent scans (${MAX_CONCURRENT_SCANS}), please try again later`,
          },
        ],
        isError: true,
      };
    }

    const { target, template, rateLimit, templatesDir, severity, timeout, concurrency, proxyUrl, proxyType } =
      request.params.arguments as {
        target: string;
        template?: string;
        rateLimit?: number;
        templatesDir?: string;
        severity?: string;
        timeout?: number;
        concurrency?: number;
        proxyUrl?: string;
        proxyType?: string;
      };

    const scanId = uuidv4();
    scans[scanId] = {
      id: scanId,
      target,
      status: "pending",
      progress: 0,
      findings: [],
    };

    let command = `nuclei -u ${target} ${severity ? `-severity ${severity}` : ""} ${
      template ? `-t ${template}` : ""
    } ${rateLimit ? `-rl ${rateLimit}` : ""} ${templatesDir ? `-templates ${templatesDir}` : ""} ${
      timeout ? `-timeout ${timeout}` : ""
    } ${concurrency ? `-c ${concurrency}` : ""} -json`;

    if (proxyUrl && proxyType) {
      if (proxyType === "socks5") {
        command += ` -proxy-socks-url ${proxyUrl}`;
      } else {
        command += ` -proxy-url ${proxyUrl}`;
      }
    }

    try {
      scans[scanId].status = "running";

      const process = spawn(command, {
        shell: true,
        stdio: ["pipe", "pipe", "pipe"],
      });

      let output = "";
      process.stdout.on("data", (data) => {
        output += data.toString();
        scans[scanId].progress = Math.min(100, Math.round((output.split("\n").length / 100) * 100));
      });

      process.on("close", () => {
        scans[scanId].progress = 100;
        const findings = output
          .split("\n")
          .filter(Boolean)
          .map((line) => {
            try {
              return JSON.parse(line);
            } catch {
              return null;
            }
          })
          .filter(Boolean);

        scans[scanId].findings = findings;
        scans[scanId].status = "completed";
      });

      scans[scanId].process = process;

      return {
        content: [
          {
            type: "text",
            text: `Scan ${scanId} started`,
          },
        ],
      };
    } catch (error) {
      scans[scanId].status = "failed";
      return {
        content: [
          {
            type: "text",
            text: `Scan ${scanId} failed: ${error instanceof Error ? error.message : "Unknown error"}`,
          },
        ],
        isError: true,
      };
    }
  }

  if (request.params.name === "cancel_scan") {
    const { scanId } = request.params.arguments as { scanId: string };

    const scan = scans[scanId];
    if (!scan) {
      return { content: [{ type: "text", text: `Scan ${scanId} not found` }], isError: true };
    }

    if (scan.status !== "running" || !scan.process) {
      return { content: [{ type: "text", text: `Scan ${scanId} is not running` }], isError: true };
    }

    scan.process.kill();
    scans[scanId].progress = 0;
    scan.status = "canceled";

    return { content: [{ type: "text", text: `Scan ${scanId} has been canceled` }] };
  }

  throw new Error("Unknown tool");
});

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("Server error:", error);
  Object.values(scans).forEach((scan) => scan.process?.kill());
  process.exit(1);
});
