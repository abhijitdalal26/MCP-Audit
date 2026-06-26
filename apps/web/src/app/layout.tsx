import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "MCPAudit — MCP Security Scanner",
  description:
    "51 security checks for your MCP server config. Find hardcoded secrets, supply chain attacks, privilege escalation, and prompt injection — mapped to OWASP MCP Top 10. Results in seconds.",
  openGraph: {
    title: "MCPAudit — MCP Security Scanner",
    description:
      "Paste your claude_desktop_config.json and get a full security audit in seconds. 51 checks, OWASP MCP Top 10, SARIF + AI-BOM output.",
    type: "website",
    url: "https://mcpaudit.app",
    siteName: "MCPAudit",
  },
  twitter: {
    card: "summary_large_image",
    title: "MCPAudit — MCP Security Scanner",
    description:
      "51 security checks for your MCP config. Secrets, supply chain, privilege escalation, prompt injection — free, no account required.",
  },
  metadataBase: new URL("https://mcpaudit.app"),
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className={inter.className}>{children}</body>
    </html>
  )
}
